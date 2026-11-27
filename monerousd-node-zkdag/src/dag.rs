// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The GHOSTDAG block-DAG store.
//!
//! There is NO linear "longest chain": ordering is by `(blue_work, id)` over the selected-parent
//! tree, with the GHOSTDAG k-cluster coloring (see [`crate::ghostdag`]) giving each block a true
//! blue-score / blue-work. The store maintains, incrementally as blocks arrive, each block's
//! selected parent, blue_score, blue_work, topological order, and the live tip set.
//!
//! Consensus parameters (DAG width, k, spacing, …) live in a governance-tunable [`ChainParams`]
//! the store holds — they are runtime values on-chain governance can retune with no restart, not
//! compile-time constants.
//!
//! Why this shape makes "every node produces" true by construction: a producer builds its next
//! block on [`Dag::tips`] — a set it holds in memory — and references those parents by id. It
//! never re-fetches a parent's full body to build a template. So a validium / instant-synced node
//! (headers + accumulator, but not full history) is a first-class producer, and killing all-but-one
//! node cannot stall the DAG.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::block::{Block, BlockHeader, BlockId};
use crate::params::ChainParams;

/// Errors from adding a block. Every one rejects the OFFENDING block only — the DAG keeps
/// advancing on all other blocks (no-halts by construction).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DagError {
    /// The block is already present (idempotent reject; gossip re-delivery is harmless).
    #[error("block {0} already in the DAG")]
    Duplicate(BlockId),
    /// A referenced parent is not yet known. The caller should buffer + retry once it arrives.
    #[error("parent {0} not found (a block may only extend parents already in the DAG)")]
    MissingParent(BlockId),
    /// A second parentless block was offered after genesis was already set.
    #[error("genesis is already set; a second parentless block is not allowed")]
    SecondGenesis,
    /// ⛔ DB-282 — after an anchor (a DSYNC adopt or a checkpoint resume) the block has NO parent in this node's
    /// settled structure: it is built only on history the certified state already counts (or on a side branch that
    /// stale), so it is not new structure here. Benign — never `Invalid`, never buffered, nothing applied.
    #[error("block {0} has no parent in the settled structure above this node's anchor — it is history here")]
    BelowSettledBase(BlockId),
    /// ⛔ DB-282 — after an anchor the block names settled structure AND a block this node holds only as pre-anchor
    /// history: a LATE MERGE of blocks whose ancestry this node cannot place (its `bounded_past` stops at the anchor),
    /// so its GHOSTDAG data would differ from a full node's. Refused like history, and the caller marks the node for a
    /// certified re-anchor — the one door that brings the merge with the chain's own blue data.
    #[error("block {0} merges pre-anchor history into settled structure — only a certified re-anchor places it here")]
    MergesPreAnchorHistory(BlockId),
    /// ⛔ DB-361 (DB-274 P1) — KASPA'S BOUNDED MERGE DEPTH, a consensus validity rule: the block's mergeset holds a
    /// block whose selected chain meets the block's own selected chain only below `blue_score − merge_depth_cap`.
    /// A function of the block's past alone, so every node refuses it. Invalid, never buffered, never applied.
    #[error("block {0} merges a block below its merge depth (Kaspa's bounded merge depth)")]
    ViolatesMergeDepth(BlockId),
}

/// DB-361 — the bounded-merge-depth verdict on a mergeset ([`Dag::merge_depth_verdict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDepthVerdict {
    /// Every merged block meets the block's selected chain at or above its merge-depth floor.
    Within,
    /// A merged block's selected chain reaches below the floor without meeting the block's chain.
    Violates,
    /// A walk left this node's held DAG (a jumper's anchor) before deciding. Never read as `Within`.
    Unevaluable,
}

/// Per-block DAG metadata maintained incrementally.
/// One difficulty/median-time sample of a selected-chain block: `(timestamp, work, blue_score)`. The
/// blue score is what makes the difficulty rule DAG-WIDE (2026-09-18): the number of blue blocks between
/// two chain points is their blue-score difference, so a window's block count includes every sibling
/// the chain merged — Kaspa's rule, borrowed: difficulty targets the DAG's block rate, not one chain's
/// spacing, so adding producers raises the work and never the mesh-wide block rate.
pub type DaaSample = (u64, u128, u64);

/// SPEED L6 — how many selected-chain blocks the fold reads the chain's spacing over, and the fewest it trusts.
pub const FOLD_RATE_WINDOW: u64 = 32;
pub const FOLD_RATE_MIN: u64 = 8;
/// SPEED L6 — the least depth the fold ever stands at: a record's chain block and one chain block above it.
pub const FOLD_DEPTH_MIN: u64 = 2;
/// ⛔ A-F85 — the most blue levels the depth rule folds above the newest final block while finality is live: HALF the fold's
/// undo journal (`SPINE_RING_LEN` steps; a blue level is at least one fold step), so a reorg of every non-final step still
/// fits it with a half-journal margin. Derived from the journal, never tuned.
pub const NON_FINAL_FOLD_REACH: u64 = (crate::params::SPINE_RING_LEN as u64) / 2;
/// ⛔ A-F85 — finality is read as STALLED (and the depth rule folds alone, as before the cap) once the newest final block's stamp
/// stands this many DAA windows of chain time under the tip's.
/// ⭐ speed5 2026-11-17 (docs/FINALITY-OVERLAY-SPEC-20261117.md §4 interim): TWO windows (≈ 234 s at the 1,953 ms target), was ten
/// (≈ 19.5 min). MEASURED (2-node rig, finality trace): a split stretch of votes leaves the agreed heights above the capped fold,
/// where G2b cannot judge them, so finality stands still and only this bound lifts the cap — at ten windows payments were not
/// spendable for ≈ 20 min. Healthy finality on the same rig lags 7–26 s (4–19 levels), far under two windows, so a live committee
/// never trips it. cons: during a stall past two windows the depth rule folds as before the cap, with A-F85's reorg risk for that
/// time; the cycle itself is closed by §4 (seats frozen at the final checkpoint), not by this bound.
pub const FINALITY_STALL_DAA_WINDOWS: u64 = 2;
/// ⭐ THE PRODUCTION RELAY FLOOR (moved here from `node_runtime` by the node split, lane dcash 2026-11-11: the fold depth below
/// reads it, and the producer reads it as `node_runtime::PRODUCTION_RELAY_FLOOR_MS`; one definition, two readers).
/// THE PRODUCTION RELAY FLOOR — the least time a node leaves between its own blocks, whatever the mesh target
/// says (see `fair_share_spacing_ms`). DERIVED from the transport's own cadence, not tuned: one Tor relay
/// round is announce + pull + deliver = 3 onion legs (~600 ms each) + a 29 KB block at ~150 B/ms + the
/// ~170 ms post-graft apply ≈ 2.2 s, and a peer's tip must be able to arrive AND be built on before this
/// node's next block, i.e. two rounds ≈ 4.3 s. MEASURED in netsim (Tor leg 600 ms, 3 seeds): a pair is one
/// chain in 100% of samples at 4 s per node, 67–100% at 3 s, 75–100% at 2.5 s, 8–17% at ≤ 2 s. Two
/// producers below this floor each select their own lineage for good (Q13 step 3 / DB-326). Ordinary onion
/// latency, not a cap: with ≥ 8 live peers the share `target × seats` exceeds it and the mesh sits at the
/// governance target. Public so the band-throughput lag gate (`nf_sparse`, DB-353 §11) reads THIS value.
/// ⛔ DB-412 (2026-10-07): the floor is the MEAN of a memoryless gap (`NodeRuntime::production_due`), never a fixed
/// period — the "100% at 4 s" above was a pair that happened to start in phase; half a spacing out of phase on the same
/// wire, two fixed-period producers never cross lineages at all.
/// ⭐ 2026-11-03 — THE FLOOR FOLLOWS THE BLOCK IT RELAYS. The derivation above was made for a 29 KB block; it stayed 4 s while a
/// block grew to 1,064,395 B (lane stable-c2, the joined ledger proof), and the mesh's production then sat at the edge of what
/// a joiner can pull: 0.33 blocks/s × 1.06 MB ≈ 350 KB/s against four bulk lanes at ~100 KB/s ≈ 400 KB/s per peer (MEASURED real
/// lanes 104 KB/s; the fast journey's T1.6 flaked 2/2 → 0/3 with 15-17 certified jumps vs 3-4, bisected to df74bb6, the commit that
/// made a simulated block weigh a real block). The same formula, today's numbers: 3 legs × 600 ms + bytes / (4 lanes × 100 B/ms)
/// + 170 ms apply = one round; two rounds = the floor. A real pair is prover-limited far above this (~28 s per node), so a real
/// node's pace does not change; when the block shrinks, the floor falls with it. cons: a sim mesh at the floor runs at half its old
/// block rate, which is the rate its relay can actually carry.
///
/// THE CONSTANTS LIVE IN ONE DEPENDENCY-FREE FILE, `chain_timing.rs` (re-exported here), so the SAT schedule reads the same
/// target the DAA does (`sat_schedule::SCHEDULE_TARGET_SPACING_MS` = this target, model-checked in `kani-proofs` on the same
/// file). The measured frame (`chain_timing::RELAY_BLOCK_BYTES`):
/// The measured wire size of a real block. Was 1,064,395 B (a joined-ledger block, stable-c2 9675dac, 2026-11-03) — stale
/// by 11-16: a quiet rig on main 3cc49818 measured a median whole-block frame of 783,344 B. ⭐ V2 (speed5, 2026-11-16):
/// MEASURED on real nodes (main d74d3617, the tree-ledger note statement and no tag statement; scratchpad/net/own_rate.py over
/// the nodes' own relay-round records and logged frame sizes, 16 whole-block fetches, rig ~/.usdmd-localnet-speed5v2): median
/// frame 644,046 B. ⭐ V2 step 2 (speed5, 2026-11-16, main 7d357574, the ledger proof 369,545 → 154,167 B, the member statement
/// gone): MEASURED on real nodes by the same lines `own_rate.py` reads (`[wire-roundtrip] … the wire frame is N byte(s)`), the
/// verifier's three-node rig ~/.usdmd-localnet-queue-verify over its cash lap: 525 frames, median 390,544 B; blocks carrying a
/// ledger proof (520) min 275,150 / median 394,646 / mean 366,591 / p90 461,560 / max 844,318 B; the 5 without one ~101 KB.
/// So the frame is NOT one constant shape (an earlier line here said it was; the measure refutes it): it varies with what a
/// block carries. ⛔ THE SMALLER FRAME IS NOT TAKEN INTO THE TARGET, AND WHY (MEASURED 2026-11-16, `scratchpad/net/pace.py`, the
/// mesh model reading this source): at the 390,544 B frame the derived target would be 1,953 ms, and the mesh FALLS BEHIND at
/// 1,000 and 3,000 producers; at today's 644,046 B (3,221 ms) it falls behind at 3,000; at 1,064,395 B (5,322 ms) it keeps up at
/// every size. What fails is not bandwidth — frames take 64–69 % of a node's download at all three — but liveness: a crowd of
/// producers starting at once goes 139–265 s without a block at EVERY target, and the halt line is one DAA window, 60 × target
/// (117 s at 1,953 ms, 193 s at 3,221 ms, 319 s at 5,322 ms). So past ~1,000 producers the target's floor is set by that start-up
/// stall, not by the frame; the frame's fall is spent once the stall itself is shortened (finding row A-F84, the next speed
/// piece). The constant was held at the 644,046 B frame until the stall was fixed. ⭐ FIXED (speed5, 2026-11-17, A-F84): the
/// pace rule is AIMD (`node_runtime::next_pace_milli`: additive increase of a node's rate under the target, multiplicative
/// decrease over it); MEASURED in the same model at the 390,544 B frame (1,953 ms): every size keeps up — 2, 13, 14, 100,
/// 1,000 at once (longest block-free stretch 38 s), 3,000 at once (100 s), 1,000 joining in 60 s (71 s), against the 117 s
/// halt line — so the frame is now the measured median and the target 1,953 ms. RE-MEASURED (speed5, 2026-11-17, main
/// c321c1bc + A-F92, a quiet two-node rig over 20 min plus one payment, the same `[wire-roundtrip]` lines): 435 frames, min
/// 101,358 / median 448,353 / p90 457,997 / max 801,180 B — 15 % over the frame the target was laid on. `pace` at the
/// compiled 1,953 ms target with that frame (a scratch tree differing only in `RELAY_BLOCK_BYTES`): PASS at every size —
/// frames 15–73 % of a download, 3,000 at once 109 s without a block against the 117 s halt line (the thinnest margin).
pub use crate::chain_timing::PRODUCTION_RELAY_FLOOR_MS;
/// The measured frame the derived rates are laid on (read by the pins that hold the RULE, never a literal).
#[must_use]
pub const fn relay_block_bytes() -> u64 {
    crate::chain_timing::RELAY_BLOCK_BYTES
}

/// ⭐⭐⭐ THE MESH'S BLOCK-RATE TARGET FITS THE NETWORK IT RUNS ON — finding A-F60, the UNBOUNDED NODES pillar (user 2026-11-15:
/// "a chain that stops as nodes join is not a blockchain at all. the chain must be able to grow infinitely").
///
/// THE DEFECT. The target was 500 ms (2 blocks/s), set when a block was 29 KB. Every node holds every block, and a block now
/// carries a ≈ 1.06 MB proof frame of CONSTANT shape (the cover is a privacy constant, so an empty block weighs what a full one
/// does). The DAA (Kaspa's rule, `miner::adaptive_work_checked`) does its job and holds the WHOLE mesh at the target however
/// many producers join, so as nodes join the frames reach 2 × 1.06 MB = 2.1 MB/s into every node against ≈ 400–800 KB/s of Tor:
/// MEASURED BY ARITHMETIC AND BY THE MESH MODEL (`scratchpad/speedmodel/mesh_sim.py`, the code's own production, DAA and relay
/// rules on a simulated clock, 2 to 3,000 nodes): with few nodes the prover throttles each producer below the target, and at
/// ≈ 13 producing nodes the frames take every node's whole download; at 32 a node held 46 % of the blocks with a 98-minute
/// backlog that only grew. A chain that stops as nodes join.
///
/// THE RULE (BORROWED: Bitcoin's 10 minutes for 1 MB over the 2009 internet; Kaspa's 10 blocks/s for 125 KB blocks — the target
/// block rate × the block's bytes is what every node must carry, so it is sized to the network): the mesh may spend HALF of a
/// node's reference intake on frames, the other half staying for payments and small rounds:
///   target = ⌈ RELAY_BLOCK_BYTES / (½ × RELAY_LANES × RELAY_LANE_BYTES_PER_MS) ⌉ (= ⌈ 1,064,395 / 200 ⌉ = 5,322 ms when
///   written; ⌈ 644,046 / 200 ⌉ = 3,221 ms today, `chain_timing::RELAY_BLOCK_BYTES` being the one source),
/// the SAME transport constants the relay floor above is derived from (one derivation, no tuned number). When a block's frame
/// shrinks (one proof per level, docs/SPEED-MAX-PROGRAM §15), `RELAY_BLOCK_BYTES` falls and the target falls with it toward the
/// 500 ms the chain was meant to run at. Governance can never set a target below it (`ChainParams::governance_set_target_spacing_ms`).
///
/// SCALE: f(fixed constants) — the bytes every node takes in per second are ≈ 200 KB/s at 2, 13, 100 or 10,000 producing nodes;
/// adding nodes raises the DAA's work, never the block rate (the model: 1,000 nodes joining in 60 s, every node holds every block,
/// worst queue wait 102 s, then steady at the target). AI RESISTANT: (a) consensus — the DAA is a rule every node checks, so a
/// flood of blocks costs the flooder the work, never the network its bandwidth.
/// cons: fewer, fuller blocks — a block every ≈ 5.3 s mesh-wide instead of every 0.5 s (the real 2-node chain made one every
/// ≈ 7.7 s, so a small network sees no change); every time-meaning constant is derived from this one (`params::blocks_for_ms`),
/// so a day, a week, an unbonding window and the 4-year halving keep their meaning in time.
pub use crate::chain_timing::MESH_TARGET_SPACING_MS;
/// SPEED L6 — the time the fold depth stands for: two relay rounds of a whole block. The SAME derived constant a producer
/// spaces its own blocks by ([`PRODUCTION_RELAY_FLOOR_MS`]: legs + bytes / lane rate + apply, twice), so the
/// two rules can never disagree about how long a block takes to cross the network.
pub const FOLD_SETTLE_MS: u64 = PRODUCTION_RELAY_FLOOR_MS;

/// SPEED L6 — the fold depth for a chain whose parameter is `param` and whose measured selected-chain spacing is
/// `step_ms`: the steps that cover [`FOLD_SETTLE_MS`], never under [`FOLD_DEPTH_MIN`] and never over `param`. No measure,
/// or a parameter already at or under the minimum (a fixture folding at the tip): the parameter. Pure, pinned directly.
#[must_use]
pub fn fold_depth_for(param: u64, step_ms: Option<u64>) -> u64 {
    let Some(step) = step_ms else { return param };
    if param <= FOLD_DEPTH_MIN {
        return param;
    }
    FOLD_SETTLE_MS.div_ceil(step.max(1)).clamp(FOLD_DEPTH_MIN, param)
}

#[derive(Clone, Debug)]
pub struct BlockNode {
    pub header: BlockHeader,
    pub tx_ids: Vec<crate::hash::Hash32>,
    /// Blocks that reference this one as a parent.
    pub children: Vec<BlockId>,
    /// GHOSTDAG selected parent = the parent maximizing `(blue_work, id)`. `None` for genesis.
    pub selected_parent: Option<BlockId>,
    /// GHOSTDAG blue-score = `blue_score(sp) + |mergeset_blues|` (genesis = 0). The canonical
    /// DAG "height" used for ordering + finality depth.
    pub blue_score: u64,
    /// Accumulated PoUW work of the blue set = `blue_work(sp) + Σ work(mergeset_blues)`.
    pub blue_work: u128,
    /// Selected-parent chain length (genesis = 0).
    pub selected_chain_len: u64,
    /// Topological insertion order. Blocks are added only after their parents, so this is a valid
    /// topological order (parents always have a smaller `topo_order` than their children).
    pub topo_order: u64,
    /// ⛔ DB-282 — IS THIS BLOCK IN THE STRUCTURE THIS NODE SETTLED ON? `true` on a DAG that never installed an
    /// anchor (a from-genesis node settles everything it admits). Once an anchor lands (a DSYNC adopt or a checkpoint
    /// resume — `Dag::add_anchor`), it is `true` only for the anchor, the certified carry (`add_carried_block`), the
    /// fold-named shells (`add_wanted_shell`) and every block admitted after them; every block held BEFORE the anchor
    /// and every folded ancestor placeholder is `false` — history the certified state already counts. `add_block`
    /// reads it: a block with any unsettled parent is refused (Kaspa's `check_pruning_violation`, strict).
    pub settled: bool,
    /// ⭐ A-F114 phase 2 — the block's ADMITTED tags (its lane minus the fold's losers and unadmitted tags), recorded by the
    /// fold step right before the record takes its position, where the record fold steps the canonical tag chain
    /// (`canon_chain::record_step`). Held only while
    /// the window holds this entry (`keep_depth`). O1-FOOTPRINT-REVIEWED: at most a block's tags (~256 × 32 B) per entry of
    /// a constant window, shared by `Arc`, never a history.
    pub chain_tags: Option<std::sync::Arc<Vec<[u8; 32]>>>,
}

/// The GHOSTDAG block-DAG.
pub struct Dag {
    blocks: HashMap<BlockId, BlockNode>,
    tips: HashSet<BlockId>,
    /// ⛔ DB-282 — TRUE once this DAG installed an anchor (`add_anchor`): from then on `add_block` admits a block
    /// only when EVERY parent is `settled`. FALSE on a from-genesis DAG, which refuses nothing on this rule.
    settled_base: bool,
    genesis: Option<BlockId>,
    topo_counter: u64,
    params: ChainParams,
    /// ⛔⛔⛔ THE SELECTED CHAIN, INDEXED BY DEPTH — so "is this block an ancestor of the tip?" is ONE lookup.
    ///
    /// `selected_chain[d]` is the block at depth `d` of the current virtual selected chain, so a block's own
    /// `selected_chain_len` addresses it directly. Answering ancestry by WALKING selected parents is
    /// O(selected-depth): it costs more at height 10^6 than at height 10, which is O(chain) and banned at
    /// every layer — and it sat on the live tx-ingest path, so every spend paid it.
    ///
    /// This is shape (2) of the architecture: write the fact down once, then ONE indexed read whose cost does
    /// not depend on how far back it reaches.
    selected_chain: Vec<BlockId>,
    /// ⛔ THE HELD BLOCKS WITH NO SELECTED-PARENT LINK (non-genesis), kept at the ONE insert site, the relink and the ONE prune
    /// (lane stable 2026-11-02). A block can enter before its parents (a carried ancestor, an adopt's anchor, a shell) or be
    /// handed no selected parent by its door; the LIVE DAG leaves it so (a live relink at every insert was MEASURED to break
    /// joining: fast journey seeds 0x5/0x8, the fresh node never reached one chain — `[fold-conflict]` re-anchor loop; relink
    /// off, both joined), and a checkpoint carries this set (`Node::export_snapshot` v65 `dag_unlinked`) so the restore's relink
    /// links exactly what the live DAG had linked (`relink_selected_parents_except`) — before, it linked everything, and the
    /// restart census read `relay` CHANGED (stable/b5.log: a block at blue score 644 off the live index, on the restored one).
    /// O1-FOOTPRINT-REVIEWED: a subset of `blocks`, pruned with it — bounded by the held span, never f(height).
    unlinked: HashSet<BlockId>,
    /// O1-FOOTPRINT-REVIEWED: bounded by daa_sample_len samples per anchor and at most a handful of anchors
    /// (the fold root of the last resume or jump) — the (timestamp, work) pairs of the selected chain BELOW an
    /// anchor, so the difficulty and median-time walks see a full window on a DAG that starts at the anchor.
    /// Dropped with the anchor when the horizon prunes it.
    window_below: HashMap<BlockId, Vec<DaaSample>>,
    /// TEST ONLY: (keep margin, prune slack) in place of the constants, so a pin can pass the horizon in
    /// a hundred blocks instead of eight thousand.
    #[cfg(test)]
    prune_override: Option<(u64, u64)>,
    /// ⛔ THE FOLD ANCHOR IS NEVER PRUNED (2026-10-27, db270 ×2 / the restart class). The checkpoint anchors at the fold
    /// root (`Node::export_snapshot` → `fold_anchor_block`, then `dag.get(&tip)?`): a sweep that evicted it made the
    /// shutdown save return None, the resume fell back to an older periodic checkpoint, and nine held blocks were gone
    /// (MEASURED watch-20261027-081821.log.2: `[persist] ⛔ shutdown save: export_snapshot returned None`, then
    /// `[block-window] 9 block(s) the checkpoint did not count … are no longer held`). The node pins the anchor's blue
    /// score here as the fold advances; the sweep keeps every block at or above it. BORROWED: Kaspa's pruning point
    /// never passes the point the node's state is derived from. cons: when the fold lags the tip by more than
    /// `keep_depth`, the DAG holds the lag's blocks too — bounded by the fold lag, which the fold-stuck pins measure.
    prune_floor: Option<u64>,
    /// THE RECORD-ADDRESS INVERSION, WRITTEN DOWN ONCE INSTEAD OF SCANNED PER CALL.
    ///
    /// A DA record is NAMED by the block it belongs to: `Node::da_record_id_for_block` folds the block id
    /// down to [`Dag::record_key`] — the low 56 bits of its first eight bytes — and multiplies by the
    /// per-height stride. Going the other way ("which block does address A belong to?") had no index, so
    /// `Node::block_for_record_addr` inverted it with `dag().block_ids().into_iter().find(..)`: a fresh
    /// `Vec<BlockId>` of EVERY block the DAG holds, allocated and linearly scanned, PER CALL.
    ///
    /// MEASURED 2026-09-06, one in-process run of
    /// `mesh_runtime_scenarios::rolling_restart_pair_heals_fold_block_wants_and_missing_records`: the
    /// canonical fold resolves records ONE AT A TIME (`da_record_notes` per record), and once the
    /// 2026-09-05 restore fix asked the header arm of `regenerate_idle_record` FIRST, that inversion
    /// became UNCONDITIONAL rather than a last resort. `[record-regen]` printed 2,479 lines at 1-in-256
    /// sampling — ~633,000 regenerations, each paying a full DAG scan — and the pin did not terminate
    /// inside a 25-minute alarm. A fold over N records was doing N full DAG scans: O(chain squared) per
    /// pass. This is the SECOND site of that class; the first was fixed 2026-09-05.
    ///
    /// SOUND under a key collision. 56 bits do not name a block uniquely, and the scan this replaces
    /// silently returned whichever colliding block `HashMap` iteration reached first — a different answer
    /// on different nodes for a question consensus reads (`block_declares_no_notes` decides whether a row
    /// IS an idle record). The tally makes the ambiguity VISIBLE and the answer fail-closed: two blocks
    /// under one key means [`Self::block_for_record_key`] claims NOTHING, which is exactly how every
    /// caller already treats "not a block this node holds".
    ///
    /// SHAPE 1 (write it down, then look it up), the same architecture as [`Self::selected_chain`] above.
    /// NO NEW GROWTH CLASS: one entry per DISTINCT record key among `self.blocks`, built and torn down
    /// WITH that map — every insert goes through [`Self::insert_block`] and the prune sweep rebuilds it
    /// from the survivors — so it cannot hold an entry whose block is gone, nor outgrow the map it mirrors.
    /// BOUND, stated plainly: at most `DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK + 2*merge_depth_cap +
    /// daa_sample_len` entries — one per surviving block of the constant recent span
    /// [`Self::prune_below_horizon`] keeps, never f(height).
    record_key_index: HashMap<u64, (BlockId, u32)>,
    /// ⭐ DB-430 — THE HELD BLOCKS IN RECEIVE ORDER (`topo_order` → id), kept at the ONE insert site and the ONE prune, so
    /// "the newest N blocks this node received" ([`Self::newest_received`]) is N reads from the end instead of a sort of the
    /// whole held DAG. MEASURED (p14-sample-grow/-join, P14 high leg, heights ~5–19 k): `batch_have_ids` collected, filtered
    /// and sorted every held block per block-lane ask — 15.5–16 % of all CPU at height, ~15× its cost at 1 k.
    /// O1-FOOTPRINT-REVIEWED: one entry per held block, the bound of `blocks` itself (keep_depth + the prune constants).
    by_receive: BTreeMap<u64, BlockId>,
    /// Steps taken by the last ancestry answer. Purely diagnostic, and the evidence a test can assert on:
    /// a counter flat across wildly different chain lengths is what proves O(1) — never a wall-clock.
    last_ancestry_steps: std::cell::Cell<u64>,
    /// ⛔ U-SHELL (2026-11-27) — each tip the template refused for the merge depth, with the head it was refused against. A refusal
    /// stands while the head only EXTENDS that one along the selected chain: the merge-depth floor only rises with the chain, so a
    /// block below it stays below, and a block merging it is refused at the door. MEASURED why (live origin, `[template-parents]`):
    /// 76 of 77 tips refused for the merge depth, each costing a GHOSTDAG pass and a merge-depth walk on every template.
    /// CACHE-ONLY: a miss runs the full check. O1-FOOTPRINT-REVIEWED: at most one entry a tip; pruned to the live tips each call.
    merge_refused: std::cell::RefCell<HashMap<BlockId, BlockId>>,
    /// ⭐⭐⭐ THE FINALITY FLOOR — the block the bonded quorum finalized, and the ONLY input finality has
    /// into consensus. `None` = fork choice is exactly work-only, byte for byte what it was before.
    ///
    /// WHY THIS FIELD EXISTS. MonerousD is bicameral by design: miners produce (the work chamber),
    /// bonded validators finalize (the bond chamber), and `governance.rs` already requires 2/3 of BOTH
    /// chambers to enact a parameter change. But CONSENSUS was work-only — [`Self::order_key`] is
    /// `(blue_work, id)` with no finality input — so the bond chamber governed the parameters and had
    /// no say whatever over the canonical chain. A validator set could finalize a block and then watch
    /// a heavier branch that abandoned it become the head. This field is the missing half.
    ///
    /// IT BOUNDS **SELECT** ONLY — never PRODUCE, never ACCEPT. See [`Self::selected_tip`].
    finality_floor: Option<BlockId>,
    /// ⭐ THE CERTIFIED ANCHOR AS A FORK-CHOICE FLOOR — the last DSYNC adopt's (or checkpoint resume's) anchor
    /// ([`Self::add_anchor_weighed`]). BORROWED: Kaspa's pruning point — a node synced from it follows only its future.
    /// MEASURED 2026-11-08 (eclipse.py on four real nodes): a node that adopted the honest bundle (a freeze point ≥ 32 blocks
    /// under the honest tip, vouchers above it) still held a side branch its anchor's own mergeset had settled; a peer kept
    /// extending that branch while the honest blocks above the anchor waited for their parents, so the branch outweighed the
    /// anchor, became head, the fold rewound below the anchor and went stale, and the node re-adopted the same bundle —
    /// 11 times in 1,500 s, victim 92 against honest 151. Read only by [`Self::finality_admits`], as the finality floor is.
    anchor_floor: Option<BlockId>,
    /// ⛔⛔ LIVE-FOLD W1 (lane livefold, 2026-11-25; docs/LIVE-FOLD-WEDGE-DEEP-AUDIT-20261125.md) — BLOCKS WHOSE BODY NO PEER
    /// SERVED. A block the node's fold waited on as a SHELL past the body reach (`UNFOLDED_BODY_REACH_LEVELS`, the A-F63 verdict)
    /// with no body anywhere it can reach. `withheld_future` is each such block and every held block with it in its PAST
    /// (filled by a children walk once, then by [`Self::insert_block`] for each new block naming a member as a parent).
    /// A block of `withheld_future` is never head and never merged ([`Self::availability_admits`]): its state cannot be applied
    /// by this node, so a chain through it cannot fold here. The node builds from the heaviest available block instead and the
    /// fold, then finality, move on. MEASURED why (the live origin, build 995bab3d, 2026-11-25 04:00): the fold waited at blue
    /// score 3785 on the shell at 3786 (credit set and evidence missing, no held body) while the chain grew to 12,597; the
    /// re-anchor took the one reachable peer's bundle, which certified the same 3785 (it waits on the same shell), so the
    /// wait came back; finality 0 all day (votes are judged only near the fold cursor).
    /// BORROWED: Kaspa — a block whose body is not validated is not UTXO-valid and is never a virtual parent; Bitcoin — a node
    /// never extends a chain whose blocks it has not fully validated.
    /// Cleared for a block when its body lands ([`Self::clear_withheld`]): an available body makes its chain eligible again and
    /// ordinary fork choice returns to it if it is heavier.
    /// SCALE: both sets hold only blocks this DAG holds (pruned with them) — a constant of the retention window.
    /// AI RESISTANT: (b) code; a peer that withholds a body gains nothing: its block and everything built on it lose the head.
    withheld: HashSet<BlockId>,
    withheld_future: HashSet<BlockId>,
}

/// ⛔ KASPA'S INVARIANT, KEPT (2026-11-09): a block may merge only what every honest node still holds WHOLE. Kaspa keeps its
/// pruning depth above its merge depth; here the span every node serves whole is [`crate::block_window::WHOLE_KEEP`] (64 blue
/// scores — a peer further behind adopts a bundle), while `merge_depth_cap` (3,600) let a block merge a side chain 3,600 deep
/// whose bodies no peer held. MEASURED (eclipse.py, 900 s eclipse, four real nodes): the rejoining node merged its 66-block
/// side chain; the honest nodes could not fetch it ("block-part pull … notfound" from every peer), so either they never placed
/// the merge and the network split (fold 158 against 168), or they grafted its shells and the heaviest node's fold waited on a
/// body nobody serves. A blue-score bound for [`Dag::merge_depth_verdict`] only — `merge_depth_cap` stays the BLOCK COUNT the
/// past scan and the rings are sized by (AGENTS.md §6: two coordinate spaces, one name; lowering it truncated GHOSTDAG's past
/// and split a joiner's level arrays from its origin's — `db265`, `AnchorArray`). 48 = `WHOLE_KEEP` less one freeze interval
/// (16). A deeper side chain is refused block by block (DB-361), so its producer's template rebuilds on the chain everyone
/// holds. cons: a node that produced alone for more than 48 blue scores (~10 min at today's ~5 blocks a minute) has those
/// blocks orphaned when it reconnects, as Bitcoin orphans a minority chain.
/// How many blue scores below the tip a block keeps its proofs. A proof is about 870 KB of a 880 KB block, so this one constant
/// sets the block window's (`block_window`)'s disk use: 64 x 0.88 MB is 56 MB, with the proofless span adding about 20 KB per block. It also bounds how deep a
/// fold reorg can refold from this store; the deepest measured on real nodes since cd64e664 is one record.
pub const WHOLE_KEEP: u64 = 64;
/// (Moved here from `block_window` by the node split, lane dcash 2026-11-11.)
pub const MERGEABLE_DEPTH: u64 = WHOLE_KEEP - 16;

impl Dag {
    pub fn new() -> Self {
        Self::with_params(ChainParams::default())
    }

    /// A DAG with an explicit (e.g. governance-set) parameter set.
    pub fn with_params(params: ChainParams) -> Self {
        Dag {
            blocks: HashMap::new(),
            tips: HashSet::new(),
            settled_base: false,
            genesis: None,
            topo_counter: 0,
            selected_chain: Vec::new(),
            unlinked: HashSet::new(),
            window_below: HashMap::new(),
            #[cfg(test)]
            prune_override: None,
            prune_floor: None,
            record_key_index: HashMap::new(),
            by_receive: BTreeMap::new(),
            last_ancestry_steps: std::cell::Cell::new(0),
            merge_refused: std::cell::RefCell::new(HashMap::new()),
            // No quorum has been heard yet ⇒ no bound. A fresh DAG selects tips exactly as before.
            finality_floor: None,
            anchor_floor: None,
            withheld: HashSet::new(),
            withheld_future: HashSet::new(),
            params,
        }
    }

    /// `1` = no withheld block is in this block's past (it may be head, or be merged); `0` = it is, or it is one (W1).
    pub fn availability_admits(&self, id: &BlockId) -> u8 {
        u8::from(!self.withheld_future.contains(id))
    }

    /// W1: mark `id` as a block whose body no peer served, and every held block with it in its past. `true` iff newly marked.
    /// One walk of `id`'s future over child edges, bounded by the held window.
    pub fn mark_withheld(&mut self, id: BlockId) -> bool {
        if !self.blocks.contains_key(&id) || !self.withheld.insert(id) {
            return false;
        }
        let mut stack = vec![id];
        while let Some(b) = stack.pop() {
            if !self.withheld_future.insert(b) {
                continue;
            }
            if let Some(n) = self.blocks.get(&b) {
                stack.extend(n.children.iter().copied());
            }
        }
        self.refresh_selected_chain_index();
        true
    }

    /// W1: `id`'s body landed — its chain is eligible again. The future set is re-derived from the blocks still marked.
    pub fn clear_withheld(&mut self, id: &BlockId) -> bool {
        if !self.withheld.remove(id) {
            return false;
        }
        let still: Vec<BlockId> = self.withheld.drain().collect();
        self.withheld_future.clear();
        for w in still {
            self.mark_withheld(w);
        }
        self.refresh_selected_chain_index();
        true
    }

    /// W1: the blocks marked withheld (a count for the operator's log and the RPC).
    pub fn withheld_count(&self) -> usize {
        self.withheld.len()
    }

    /// W-FOLD-1b: is `id` itself marked withheld?
    #[must_use]
    pub fn is_withheld(&self, id: &BlockId) -> bool {
        self.withheld.contains(id)
    }

    /// The active, governance-tunable consensus parameters.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// Install a governance-approved parameter update (no restart; takes effect next block).
    pub fn set_params(&mut self, params: ChainParams) {
        self.params = params;
    }

    /// Fixed margin the prune horizon keeps BELOW the governance-derived depth, so a block that is
    /// merely near the horizon is never dropped out from under a walk that is still using it.
    /// Named (not a literal) because [`Self::record_key_index`] cites it as its bound and the
    /// store-bound standard is that a bound can be NAMED.
    pub const DAG_PRUNE_KEEP_MARGIN: u64 = 256;
    /// Overflow slack before the prune sweep runs at all — what amortizes the sweep to O(1) per block.
    /// Together with `DAG_PRUNE_KEEP_MARGIN` and the live `merge_depth_cap` / `daa_sample_len` params it
    /// is the whole bound on `self.blocks`, and therefore on every index that mirrors it.
    pub const DAG_PRUNE_SLACK: u64 = 512;

    /// ⭐ THE ONE PLACE A BLOCK ENTERS THE STORE — so an index of the store cannot be forgotten.
    ///
    /// Five call sites insert blocks (produce, anchor, graft, wanted shell, adopted tip). Each one
    /// maintaining [`Self::record_key_index`] by hand is the drift trap this crate has paid for before
    /// ("two copies of this would drift and the drift would only show up as a spend that will not
    /// verify"). A sixth insert site added later gets the index for free.
    fn insert_block(&mut self, id: BlockId, node: BlockNode) {
        self.note_record_key(id);
        if let Some(old) = self.blocks.get(&id) {
            self.by_receive.remove(&old.topo_order); // a re-insert re-files the id at its new receive position
        }
        self.by_receive.insert(node.topo_order, id);
        if node.selected_parent.is_none() && !node.header.is_genesis() {
            self.unlinked.insert(id);
        } else {
            self.unlinked.remove(&id);
        }
        // W1: a block naming a block of a withheld future as a parent has that block in its past
        if !self.withheld_future.is_empty() && node.header.parents.iter().any(|p| self.withheld_future.contains(p)) {
            self.withheld_future.insert(id);
        }
        self.blocks.insert(id, node);
    }

    /// ⭐ DB-430 — the held blocks, NEWEST RECEIVED FIRST (descending `topo_order`): a walk that stops after the few it needs
    /// costs those few, never the held DAG.
    pub fn newest_received(&self) -> impl Iterator<Item = &BlockId> + '_ {
        self.by_receive.values().rev()
    }

    /// ⭐ ONE ENCODING for the record-address key. `Node::da_record_id_for_block` multiplies this by the
    /// per-height stride to name a record; [`Self::block_for_record_key`] inverts it. Both used to spell
    /// the mask out themselves — two copies of a consensus encoding, which is exactly the drift this crate
    /// bans. It is the low 56 bits of the id's first eight bytes, little-endian.
    pub fn record_key(id: &BlockId) -> u64 {
        let mut h = [0u8; 8];
        h.copy_from_slice(&id.as_bytes()[..8]);
        u64::from_le_bytes(h) & 0x00ff_ffff_ffff_ffff
    }

    /// The block a record key names, in ONE indexed read — the inversion of [`Self::record_key`].
    ///
    /// `None` means this node cannot name one block for the key: it holds none, or it holds two that
    /// collide. Fail-closed on the collision is deliberate — see [`Self::record_key_index`]. Cost is
    /// f(nothing): a single hash lookup, whatever the DAG holds and however long the chain is.
    pub fn block_for_record_key(&self, key: u64) -> Option<BlockId> {
        match self.record_key_index.get(&key) {
            Some((id, 1)) => Some(*id),
            _ => None, // absent, or ambiguous — claim nothing
        }
    }

    /// File a newly-inserted block under its record key. Idempotent per id is NOT assumed: every caller
    /// checks `blocks.contains_key(&id)` and returns early on a duplicate, so a given id is filed once.
    fn note_record_key(&mut self, id: BlockId) {
        let e = self.record_key_index.entry(Self::record_key(&id)).or_insert((id, 0));
        e.1 = e.1.saturating_add(1);
    }

    /// Rebuild the index from the blocks that survived a prune. Only the prune sweep calls this, under the
    /// same overflow gate, so its cost is one pass over the surviving set that sweep bounds to fixed
    /// constants (`DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK + 2*merge_depth_cap + daa_sample_len`) —
    /// f(those constants), never f(height).
    fn rebuild_record_key_index(&mut self) {
        self.record_key_index.clear();
        let ids: Vec<BlockId> = self.blocks.keys().copied().collect();
        for id in ids {
            self.note_record_key(id);
        }
    }

    /// The index's own census: `(distinct record keys filed, total blocks filed under them)`. The second
    /// number equals `self.blocks.len()` whenever the index is in step with the store — the invariant the
    /// agreement pins assert — and `Node::da_entry_census_named` lists the first so this map can never
    /// grow unobserved. Cost is two map-length reads; the map itself is bounded by the SAME retention rule
    /// as the block store it mirrors (`prune_below_horizon` keeps DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK
    /// + 2*merge_depth_cap + daa_sample_len surviving blocks — f(fixed constants and governance params),
    /// never f(height or note count)).
    pub fn record_key_index_census(&self) -> (usize, usize) {
        (
            self.record_key_index.len(),
            self.record_key_index.values().map(|(_, c)| *c as usize).sum(),
        )
    }

    pub fn contains(&self, id: &BlockId) -> bool {
        self.blocks.contains_key(id)
    }

    pub fn get(&self, id: &BlockId) -> Option<&BlockNode> {
        self.blocks.get(id)
    }

    /// Every block id this DAG holds. Used to find which blocks are missing a ledger record, so the backfill
    /// can fetch them BY ID the way a transparent chain fetches by hash.
    ///
    /// ⭐ IN ONE ORDER — ascending id — never the map's (lane stable 2026-11-01). `blocks` is a `HashMap` whose iteration order
    /// is a per-instance random seed, so every caller that took "the first k" (the backfill's by-block-id ask names the first
    /// four missing blocks; its hashed host follows from those bytes) chose differently on two nodes holding the same DAG and
    /// in two runs of one seed. MEASURED (stable/c4.log, the reinstall replay calibration with a bulk-lane trace): the
    /// joiner's kind-1 ask at 153.65 s named the same four ids in two orders, hashed to node 1 in one run and node 0 in the
    /// other, and the runs parted from there. BORROWED: Bitcoin Core walks `mapBlockIndex` through ordered structures
    /// wherever the order is observable. cons: one sort of the held ids per call — N log N over the bounded window
    /// (≈ 7.5 k ids × 13 compares ≈ 0.1 ms at keep_depth), no state.
    pub fn block_ids(&self) -> Vec<BlockId> {
        let mut ids: Vec<BlockId> = self.blocks.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// ⭐⭐⭐ THE DAG'S OWN RESIDENT BYTES — so the no-growth census can SEE this store.
    ///
    /// ⛔⛔⛔ THE CENSUS DID NOT COVER THE DAG AT ALL. `Node::da_entry_census_named` lists the `da_*` maps
    /// and `unspent_path_nodes`, and its totals came to ~5 MB while a live producing node held 300-490 MB.
    /// A growth axis outside the instrument is a growth axis nobody can attribute — which is exactly the
    /// failure mode that let a per-record map grow unobserved before this census existed. MEASURED
    /// 2026-09-16 on a live node: `blocks_in_memory` is EXACTLY `height + 1` at every sample, held until
    /// `prune_below_horizon` first fires at `2*merge_depth_cap + daa_sample_len + 256 + 512` = 8,028
    /// blocks, so this store's steady-state size is a protocol constant — but a LARGE one, and it was
    /// invisible.
    ///
    /// Summed from the real vectors rather than from a per-node constant: `tx_ids` and `children` are the
    /// two variable-width fields, and a written-down "bytes per block" would drift the moment either
    /// changes (the §AG lesson: no hand-written width near a measurement).
    #[must_use]
    pub fn census_bytes(&self) -> usize {
        let per_node = core::mem::size_of::<BlockNode>();
        self.blocks
            .values()
            .map(|n| {
                per_node
                    + n.tx_ids.len() * core::mem::size_of::<crate::hash::Hash32>()
                    + n.children.len() * core::mem::size_of::<BlockId>()
            })
            .sum::<usize>()
            + self.selected_chain.len() * core::mem::size_of::<BlockId>()
            + self
                .window_below
                .values()
                .map(|v| v.len() * core::mem::size_of::<(u64, u128)>())
                .sum::<usize>()
            + self.record_key_index.len() * (core::mem::size_of::<u64>() + core::mem::size_of::<(BlockId, u32)>())
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The DETERMINISTIC canonical order over every block in the DAG — the sequence EVERY honest node computes
    /// identically, regardless of the order blocks arrived. A width>1 GHOSTDAG has thousands of raw topological
    /// orderings; this pins the ONE the ledger uses to resolve conflicts (which of two concurrent spends of a note
    /// is effective). Key = [`Self::order_key`] = `(blue_work, id)` ascending — the SAME key
    /// [`Self::selected_tip`] / [`Self::add_anchor`] use for the selected chain. This unification is
    /// CONSENSUS-CRITICAL for value conservation: the effective-ledger winner (first spender of a nullifier in this
    /// order) MUST be the block that lands on the canonical selected chain whose frontier is adopted — else, under
    /// variable difficulty (`blue_work` and `blue_score` can order two concurrent blocks differently), the resolver
    /// could prune a spend whose OUTPUTS the canonical frontier still carries → inflation. `blue_work` accumulates
    /// strictly from parent to child (a descendant's exceeds every ancestor's), so this respects ancestor-before-
    /// descendant; two CONCURRENT blocks (each other's anticone) are tie-broken by `id` (content hash —
    /// deterministic, node-independent). NOT `topo_order` (the RECEIVE-order counter, node-divergent) and NOT
    /// `blue_score` (the depth counter — correct for the finality horizon, WRONG here). Substrate for
    /// [`crate::consensus::resolve_nullifier_conflicts`].
    pub fn canonical_order(&self) -> Vec<BlockId> {
        let mut ids: Vec<BlockId> = self.blocks.keys().copied().collect();
        ids.sort_by_key(|id| self.order_key(id));
        ids
    }

    /// The real nullifiers (`tx.nullifiers`) each block spends, resolved via `nfs_of` (which the caller backs with
    /// whatever it holds — mempool txs / a recorded per-block map), returned in this DAG's [`Self::canonical_order`].
    /// The pairing a node feeds [`crate::consensus::resolve_nullifier_conflicts`] to get the pruned double-spends.
    pub fn canonical_block_nullifiers(
        &self,
        nfs_of: impl Fn(&BlockId) -> Vec<[u8; 32]>,
    ) -> Vec<(BlockId, Vec<[u8; 32]>)> {
        self.canonical_order()
            .into_iter()
            .map(|id| {
                let nfs = nfs_of(&id);
                (id, nfs)
            })
            .collect()
    }

    pub fn genesis(&self) -> Option<BlockId> {
        self.genesis
    }

    /// A BLOCK LOCATOR over this node's selected chain — the ids at exponentially spaced depths
    /// from the tip (tip, tip-1, tip-2, tip-4, tip-8, …) plus genesis, newest first.
    ///
    /// BORROWED-FROM: Bitcoin Core `CBlockLocator` / `CChain::GetLocator` (chain.cpp) —
    /// github.com/bitcoin/bitcoin — the dense-then-doubling height sampling a peer uses to find
    /// the fork point in O(log height) ids. DELIBERATE-DEVIATION: this is a GHOSTDAG, so the
    /// samples walk the virtual SELECTED-parent spine (`selected_chain`), not a single-parent
    /// height index, and the block-lane serve that consumes it descends MERGE parents — but the
    /// locator SHAPE and its use (the serve stops at the first id it holds = the common ancestor,
    /// serving only what is above) is Bitcoin's. Fork-correct because block IDENTITY, never score,
    /// decides shared history; bounded to O(log height) ids off the bounded `selected_chain`
    /// index this struct already maintains; stores nothing.
    /// The newest `k` blocks of the selected chain, tip first — the DENSE part of the batch locator
    /// (DB-65b): a peer that holds any of them excludes that block's whole past cone, so this node's own
    /// recent chain is never served back to it. Reads the chain vector only.
    pub fn selected_chain_tail(&self, k: usize) -> Vec<BlockId> {
        self.selected_chain.iter().rev().take(k).copied().collect()
    }

    /// The selected-chain blocks just ABOVE `hint`, highest first, up to `k` — empty when `hint` is not on
    /// the chain. DB-67: the batch locator's dense band. The peer's last page named the highest block of
    /// this chain it held; the next ask names the `k` blocks above it, so the peer's anchor becomes exact
    /// and none of this node's own blocks between two exponential samples is served back to it.
    pub fn selected_chain_band_above(&self, hint: &BlockId, k: usize) -> Vec<BlockId> {
        let Some(i) = self.selected_chain.iter().rposition(|id| id == hint) else {
            return Vec::new();
        };
        let hi = (i + k).min(self.selected_chain.len().saturating_sub(1));
        (i + 1..=hi).rev().map(|j| self.selected_chain[j]).collect()
    }

    pub fn block_locator(&self) -> Vec<BlockId> {
        let mut out = Vec::new();
        let len = self.selected_chain.len();
        if len > 0 {
            let mut step: usize = 1;
            let mut d = len - 1;
            loop {
                out.push(self.selected_chain[d]);
                if d == 0 {
                    break;
                }
                if out.len() >= 4 {
                    step = step.saturating_mul(2);
                }
                d = d.saturating_sub(step);
            }
        }
        if let Some(g) = self.genesis {
            if out.last() != Some(&g) {
                out.push(g);
            }
        }
        out
    }

    /// ⭐ THE HONEST LIVE-DAG VIEW — the newest `count` blocks THIS node's RAM DAG actually holds,
    /// as pure consensus-public structure: `(id, parents, blue_score, timestamp, on_selected_chain)`.
    ///
    /// ROOT-LAYER: the DAG structure is PRODUCED here — `Dag` is the only owner of the parent edges,
    /// blue scores and the selected chain; every reader (RPC, sovereign proxy, explorer scene) is a
    /// projection of this struct. Serving the view from anywhere else means re-deriving or faking
    /// consensus facts, which is exactly what broke.
    /// MEASURED: 2026-08-25 on-screen click-through — the Live DAG overlay 404'd inside the wallet
    /// (`/dagview.html` resolved at the site root) and its RPC target was a retired clearnet host the
    /// CSP blocks, so the scene drew 0 blocks; after this accessor + the same-origin proxy the scene
    /// draws the node's real held blocks with real parent edges.
    /// MUST-STAY-GREEN: every existing Dag test (ordering, ancestry O(1) counter, prune-horizon
    /// soundness) — this is a read-only projection; it mutates nothing.
    ///
    /// Every field here is data every verifying node must already hold to run GHOSTDAG: block ids,
    /// parent edges, blue scores, header timestamps, selected-chain membership — the same facts
    /// consensus gossip already publishes to every peer. No amount, no value, no real count, no
    /// which-item: the per-block payload stays the constant cover shape and is not touched here.
    /// `count` is a SERVE PAGE (display width), never a reach bound: the RAM DAG holds only its
    /// recent span by design (the O(1) node prunes below its horizon), and this serves newest-first
    /// from what is held. cons: none — one sort over the held set (bounded by the DAG's own O(1)
    /// retention), no state, no growth term.
    ///
    /// ⛔ NEWEST BY THE CHAIN'S OWN ORDER, NEVER BY ARRIVAL (DB-402 R1, 2026-10-06). This sorted by `topo_order` — the
    /// RECEIVE counter — so two nodes holding the same DAG listed different blocks first and, past `count`, served a
    /// different SET of "newest" blocks. MEASURED by the replicated-state census (censusdiff-205229): `relay DIFFERS`
    /// 5413/5413 B, first difference at byte 7 — n0 listed its own score-63 block first, n1 its own. It also handed
    /// every caller of the public `/dag_recent` route this node's arrival order: network-timing metadata about where the
    /// node sits in the mesh (DIGITAL CASH: zero ordering/timing metadata). The order is now GHOSTDAG's (Kaspa): blue
    /// work, then block id — a function of the DAG, the same page on every node holding it.
    /// cons: none — the same one sort over the held set, on a different key.
    pub fn dag_recent_view(
        &self,
        count: usize,
    ) -> Vec<(BlockId, Vec<BlockId>, u64, u64, bool)> {
        let mut ids: Vec<BlockId> = self.blocks.keys().copied().collect();
        ids.sort_by_key(|id| (self.blocks[id].blue_work, *id));
        ids.iter()
            .rev()
            .take(count)
            .map(|id| {
                let n = &self.blocks[id];
                let on_selected = self
                    .selected_chain
                    .get(n.selected_chain_len as usize)
                    .map(|c| c == id)
                    .unwrap_or(false);
                (
                    *id,
                    n.header.parents.clone(),
                    n.blue_score,
                    n.header.timestamp,
                    on_selected,
                )
            })
            .collect()
    }

    /// The current tips (blocks with no children) — exactly the parents a new block references.
    /// In ascending id order, never the set's hash order (see [`Self::block_ids`]): ≤ the DAG width, one small sort.
    pub fn tips(&self) -> Vec<BlockId> {
        let mut tips: Vec<BlockId> = self.tips.iter().copied().collect();
        tips.sort_unstable();
        tips
    }

    /// The virtual selected tip = the tip maximizing `(blue_work, id)`: the head of the selected
    /// chain, i.e. the frontier a wallet/consumer treats as current.
    ///
    /// ⭐⭐⭐ FINALITY-BOUNDED FORK CHOICE — the ONE shared site where the bond chamber binds the chain.
    ///
    /// Work still ORDERS the candidates; finality only decides which tips RANK as candidates at all. A
    /// tip that does not descend from [`Self::finality_floor`] loses to one that does **even when it
    /// carries more accumulated work** — that is precisely the reorg a 2/3-bonded quorum ruled out.
    ///
    /// WHY THIS EXISTS. MonerousD is bicameral by design: miners produce (the work chamber), bonded
    /// validators finalize (the bond chamber), and `governance.rs` already needs 2/3 of BOTH chambers to
    /// enact a parameter change. But CONSENSUS was work-only — [`Self::order_key`] is `(blue_work, id)`
    /// with no finality input — so the bond chamber governed the parameters and had no say whatever over
    /// the canonical chain. This is the missing half of that design, not a new idea bolted on.
    ///
    /// **IT BOUNDS SELECT, NEVER PRODUCE AND NEVER ACCEPT.** The bound is a LEXICOGRAPHIC EXTENSION of
    /// the ordering key, not a filter with a rescue arm — see [`Self::finality_bounded_order_key`]. That
    /// shape is why it is structurally incapable of stopping the chain:
    ///  1. NO-OP WITHOUT A QUORUM. `finality_floor` is `None` until the bonded set first crosses 2/3, so
    ///     at `finalized_height == 0` — a lone node, a fresh chain, a set with zero validators, a mesh
    ///     whose whole quorum is offline — every tip ranks alike and this is byte-for-byte its old self.
    ///     Production never consults it; a node with zero reachable peers extends its own chain forever.
    ///  2. NO-OP WHEN THE FLOOR IS NOT HELD. If the floor block is not in `self.blocks` (pruned below the
    ///     horizon, or a peer finalized something we never received) there is nothing to measure descent
    ///     against, so the bound stands down rather than guessing. Standing down is right HERE and
    ///     nowhere else: this code's whole job is to REFUSE A CHOICE, and a refusal it cannot justify
    ///     from its own state is not a refusal it may make.
    ///  3. IT CANNOT REMOVE THE LAST CANDIDATE. Because admissibility is the HIGH-ORDER FIELD of a sort
    ///     key rather than a filter, "no tip descends from the floor" makes every tip rank 0 and work
    ///     decides among them — identical to the old behaviour. There is no arm to delete, and no future
    ///     edit can turn this into an empty-set stall without deleting the key itself.
    ///
    /// The DSYNC trust root binds it too (2026-11-08): [`Self::add_anchor`] installs the anchor as a floor of its own
    /// ([`Self::anchor_floor`]), and a quorum floor outside the anchor's future stands down, so an anchor never ranks 0
    /// alone. Whether a bundle's chain contains the quorum's floor stays a question for the bundle's certificate.
    ///
    /// PRECEDENT (borrow the proven shape, do not invent one): Ethereum's fork choice runs LMD-GHOST
    /// *starting at the justified/finalized checkpoint*, so a branch abandoning the finalized checkpoint
    /// is never head — while proposers keep proposing and low participation costs finality (the
    /// inactivity leak), never block flow. Same verb split as here: SELECT is bounded, PRODUCE is not.
    ///
    /// ⛔ A-F40 + A-F54 (lane goods, 2026-11-13) — WHEN A MERGE CONSUMED THE LAST TIP THAT KEEPS THE FINALIZED BLOCK, THE HEAD
    /// STAYS ON THE HEAVIEST BLOCK THAT KEEPS IT. Point 3 above let work decide among tips that all leave the floor, so one block
    /// naming the head as a MERGED parent under a heavier branch (built by a node that has not heard the votes yet) carried
    /// every head off a block the bonded quorum finalized (A-F40, adversarial probe A). The first fix (74222c1f) answered it
    /// in the TEMPLATE, building on the finality floor itself; floors differ between nodes while votes travel, so nodes built
    /// on the finalized block, below every fold cursor, and the chain HALTED (A-F54, MEASURED on one binary with the arm behind
    /// a switch: arm on = pay FAIL twice, [fold-stuck] 415/411/389; arm off = pay PASS 394 s, 159/159/125). Now the HEAD keeps
    /// the floor: in that state only, it is the heaviest block that keeps it ([`Self::heaviest_admissible_below_tips`],
    /// normally the block just consumed, above the fold), and the template builds there. While any tip keeps the floor the
    /// rule is exactly point 1. The floor itself always keeps the floor, so a head always exists.
    /// SCALE: the walk runs only in that state and visits only blocks above the floor's depth, inside the window the DAG holds;
    /// constant in height and in the bonded set. PROTECTED BY: (b) ordinary code, the same rule on every node.
    /// BORROWED: Ethereum's LMD-GHOST runs from the finalized checkpoint (a branch abandoning it is never head); Kaspa's virtual
    /// block selects among blocks that keep the finality point.
    pub fn selected_tip(&self) -> Option<BlockId> {
        let best = self.tips.iter().copied().max_by_key(|id| self.finality_bounded_order_key(id))?;
        if self.head_admits(&best) {
            return Some(best);
        }
        Some(self.heaviest_admissible_below_tips().unwrap_or(best))
    }

    /// The heaviest block that keeps the finality floor, found by walking parents down from the tips and stopping at the
    /// first admitting block on each path (its ancestors are lighter) and at the floor's own depth (nothing at or below it
    /// but the floor itself can keep the floor).
    // O1-INFINITY-REVIEWED: the walk visits only blocks above the finality floor's depth within the DAG's held (pruned) window, a constant of the window, never of height
    fn heaviest_admissible_below_tips(&self) -> Option<BlockId> {
        // G4: the stop reads BLUE SCORE, the coordinate every node shares, never `selected_chain_len` (an adopt seeds it from
        // its anchor's blue score, so one DAG holds several origins); a block whose selected chain runs through the floor
        // has a strictly higher blue score than the floor, so nothing at or below it but the floor can keep the floor.
        let floor_depth = [self.finality_floor, self.anchor_floor]
            .iter()
            .flatten()
            .filter_map(|f| self.blocks.get(f).map(|n| n.blue_score))
            .max()
            // W1: with no floor, a withheld future alone sends the walk down — it stops at the first available block on each path
            .or_else(|| (!self.withheld_future.is_empty()).then_some(0))?;
        let mut stack: Vec<BlockId> = self.tips.iter().copied().collect();
        let mut seen: HashSet<BlockId> = HashSet::new();
        let mut best: Option<BlockId> = None;
        while let Some(b) = stack.pop() {
            if !seen.insert(b) {
                continue;
            }
            let Some(n) = self.blocks.get(&b) else { continue };
            if self.head_admits(&b) {
                if best.map_or(true, |x| self.order_key(&b) > self.order_key(&x)) {
                    best = Some(b);
                }
                continue;
            }
            if n.blue_score <= floor_depth {
                continue;
            }
            stack.extend(n.header.parents.iter().copied());
        }
        best
    }

    /// [`Self::order_key`] with the finality verdict prepended as the HIGH-ORDER field:
    /// `(admissible, blue_work, id)`.
    ///
    /// One key, three properties, no branches to get wrong: an admissible tip outranks an inadmissible
    /// one at ANY work; among equally-admissible tips the comparison is exactly the old `(blue_work, id)`;
    /// and when nothing is admissible every tip carries the same leading 0, so work decides and the node
    /// always has a head. Deliberately NOT folded into `order_key` itself — that key also drives
    /// [`Self::canonical_order`], which resolves nullifier conflicts and MUST stay node-independent, and
    /// the finality verdict is node-local (it depends on what this node has heard and still holds).
    fn finality_bounded_order_key(&self, id: &BlockId) -> (u8, u8, u128, BlockId) {
        let (work, tie) = self.order_key(id);
        (self.finality_admits(id), self.availability_admits(id), work, tie)
    }

    /// A block may be head: it keeps the finality and anchor floors and no withheld block is in its past (W1). The finality
    /// field stays the higher-order one: a quorum finalized a block whose body its signers held.
    fn head_admits(&self, id: &BlockId) -> bool {
        self.finality_admits(id) == 1 && self.availability_admits(id) == 1
    }

    /// Test-only triage of the head and its positional index: the selected tip, the floor, the index length, the unlinked
    /// blocks (no selected parent, not genesis), and for the three heaviest blocks their admissibility, depth and whether
    /// the index names them at that depth.
    #[cfg(test)]
    pub fn head_probe(&self) -> String {
        let short = |id: &BlockId| id.as_bytes()[..4].iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut heavy: Vec<BlockId> = self.blocks.keys().copied().collect();
        heavy.sort_by_key(|id| (self.blocks[id].blue_work, *id));
        let top: Vec<String> = heavy
            .iter()
            .rev()
            .take(3)
            .map(|id| {
                let n = &self.blocks[id];
                format!(
                    "{} admits {} depth {} indexed {} sp {} tip {}",
                    short(id),
                    self.finality_admits(id),
                    n.selected_chain_len,
                    self.selected_chain.get(n.selected_chain_len as usize) == Some(id),
                    n.selected_parent.is_some(),
                    self.tips.contains(id)
                )
            })
            .collect();
        let unlinked = self.blocks.iter().filter(|(id, n)| n.selected_parent.is_none() && Some(**id) != self.genesis).count();
        format!(
            "tips {} · selected {:?} · floor {:?} held {} · index len {} · unlinked {} · top {:?}",
            self.tips.len(),
            self.selected_tip().map(|t| (short(&t), self.blocks[&t].selected_chain_len)),
            self.finality_floor.map(|f| short(&f)),
            self.finality_floor.is_some_and(|f| self.blocks.contains_key(&f)),
            self.selected_chain.len(),
            unlinked,
            top
        )
    }

    /// `1` = this tip may be head; `0` = it abandons finalized history. `1` whenever there is no floor to
    /// apply, so the unbounded chain and the un-finalized chain both rank uniformly.
    /// Two floors bound it, each only while held: the certified anchor ([`Self::anchor_floor`]) and the quorum's
    /// finality floor. A finality floor outside the anchor's future is older history the adopt superseded (the anchor
    /// has no local ancestry, so nothing above it could descend from that floor), and stands down.
    pub fn finality_admits(&self, id: &BlockId) -> u8 {
        let anchor = self.anchor_floor.filter(|a| self.blocks.contains_key(a));
        let floor = self
            .finality_floor
            .filter(|f| self.blocks.contains_key(f)) // (2) floor pruned or never received — nothing to measure against
            .filter(|f| anchor.map_or(true, |a| self.descends_from_finality_floor(f, &a)));
        // (1) no quorum has ever crossed 2/3 and no anchor installed: every tip ranks alike
        u8::from(
            anchor.map_or(true, |a| self.descends_from_finality_floor(id, &a))
                && floor.map_or(true, |f| self.descends_from_finality_floor(id, &f)),
        )
    }

    /// Install the block a 2/3 bonded quorum finalized as the [`Self::finality_floor`], or clear it.
    ///
    /// The caller is the node's finality overlay ([`crate::validator::FinalityTracker::finalized_block`]),
    /// which only ever hands over a block THIS node accepted and whose claimed height its ingress matched
    /// against this DAG — so the floor is never a height a peer merely asserted. Monotonicity lives in the
    /// tracker (`finalized_height` never regresses), not here: this stays a plain setter so a restart, a
    /// re-import, or a test can put the DAG in a known state.
    pub fn set_finality_floor(&mut self, floor: Option<BlockId>) {
        if self.finality_floor != floor {
            self.finality_floor = floor;
            self.refresh_selected_chain_index(); // the floor is an input of `selected_tip` (see `head_inputs_changed`)
        }
    }

    /// The currently installed finality floor, if any.
    pub fn finality_floor(&self) -> Option<BlockId> {
        self.finality_floor
    }

    /// ⭐ A-F115 — release the anchor floor a RESUME installed (`Node::boot`, right after the checkpoint and its block window
    /// are back): this node's own checkpoint tip is a cache, not a chain authority, so the fork choice returns to weight and
    /// the quorum's floor. Only the boot calls it, before any network door has run, so the floor it releases can only be the
    /// resume's own. `true` when a floor was released. A certified adopt later installs its floor again through
    /// [`Self::add_anchor_weighed`].
    pub fn release_resume_floor(&mut self) -> bool {
        if self.anchor_floor.is_none() {
            return false;
        }
        let boundary_before = self.window_boundary();
        self.anchor_floor = None;
        self.head_inputs_changed(boundary_before);
        true
    }

    /// ⭐⭐⭐ SYMMETRIC FINALITY TARGETS (2026-09-18). Runs 39/40 on two real producers measured a FROZEN
    /// finality (finalized [1, 0] while the tips passed 200) with the vote target "the selected-chain block
    /// at blue score h": under Tor latency (1–3 s) longer than the block period each producer's newest
    /// block is always its heaviest tip, so every validator's virtual selected chain is ITS OWN blocks and
    /// two validators name a different block at every height; one vote per height (the equivocation
    /// rule) then makes a split height dead forever. The target must be a function of the BLOCK SET
    /// alone: for each blue score in `h_lo..=h_hi`, the blocks at exactly that score inside `tip`'s past,
    /// ids ascending (the caller takes the first, or one bonded peers already voted). Validators holding
    /// the same level compute the same list; the settle depth is what gives a level's siblings time to
    /// arrive and be merged under the tip. Safety untouched: one vote per height, ≥2/3 on ONE block, and
    /// the block is in the voter's own tip's past (a floor it already extends).
    /// cons: one parent walk over the levels from `h_lo` up to the tip — f(h_hi − h_lo + settle), never
    /// f(history); nothing is expanded below `h_lo`.
    pub fn finality_vote_candidates(&self, tip: &BlockId, h_lo: u64, h_hi: u64) -> Vec<(u64, Vec<BlockId>)> {
        let mut levels: std::collections::BTreeMap<u64, Vec<BlockId>> = std::collections::BTreeMap::new();
        let mut seen: HashSet<BlockId> = HashSet::new();
        let mut stack = vec![*tip];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(n) = self.blocks.get(&id) else { continue };
            if n.blue_score < h_lo {
                continue;
            }
            if n.blue_score <= h_hi {
                levels.entry(n.blue_score).or_default().push(id);
            }
            if n.blue_score > h_lo {
                stack.extend(n.header.parents.iter().copied());
            }
        }
        levels
            .into_iter()
            .map(|(h, mut ids)| {
                ids.sort_unstable();
                (h, ids)
            })
            .collect()
    }

    /// Does `tip` descend from the finality floor along the selected-parent chain?
    ///
    /// Walks selected parents from `tip` and STOPS the moment the walk reaches the floor's own depth — so
    /// the cost is exactly the depth gap `tip.selected_chain_len - floor.selected_chain_len`, never the
    /// chain length. The protocol's own cadence sets that gap: `main.rs` votes a stride-aligned checkpoint
    /// `FINALITY_SETTLE` below the tip, so it is a handful of blocks, and it is capped in every case by
    /// the prune horizon since a walk that leaves `self.blocks` ends immediately.
    ///
    /// CONSERVATIVE BY CHOICE. This asks about the SELECTED chain, so a tip that merged the floor only as
    /// a non-selected parent answers `false`. That direction is the safe one: a wrong `false` costs one
    /// candidate, and if it costs the LAST candidate every tip ranks 0 and work decides — the error
    /// degrades to the old behaviour and can never stall the node.
    /// ⭐ A-F86 — whether `anc` lies on `tip`'s SELECTED CHAIN (or is `tip`): the one ancestry finality is judged by.
    pub fn selected_chain_through(&self, tip: &BlockId, anc: &BlockId) -> bool {
        self.descends_from_finality_floor(tip, anc)
    }

    /// ⛔⛔ G4 (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md G4) — THE WALK CROSSES AN ANCHOR AND STOPS BY
    /// BLUE SCORE. Two defects made every joiner's finality stop for good once it re-anchored above its finalized block:
    /// (1) an anchor enters with `selected_parent: None` (a sync trust root, `add_anchor_weighed`), so a walk from above it
    /// ended there and answered "not a descendant" for every floor below it; (2) the stop rule read `selected_chain_len`,
    /// which an adopt seeds from the anchor's blue score (its ORIGIN, `add_anchor`'s doc) and a carried block whose
    /// selected parent is not held falls back to its blue score, so one DAG holds chain lengths from several origins and a
    /// jump between them read as "a different branch" (charter §6: two coordinate spaces under one name). MEASURED (netsim
    /// launch, main 4e899429, scratchpad r5_join.log): every joiner ended with finality at its pre-re-anchor height (n2 26,
    /// n3 74, n4 99, n5 115) against the seeds' 211, while on node 0's chain; A-F86 refused 402 / 563 / 212 / 368 quorums
    /// as "does not extend the finalized block at" exactly those heights, and the certificate re-ask returned the same.
    /// Now the walk steps through a trust root by its heaviest held parent (`walk_parent`, J2's rule for the merge-depth
    /// walk: the carry holds the anchor's whole past down to the merge depth with blue data A-F97 checks), and stops when
    /// the blue score — the one coordinate every node computes alike and the carry certifies — reaches the floor's and the
    /// block is not the floor. Blue score falls strictly along a selected-parent edge (the selected parent is blue in its
    /// child's mergeset), so the stop is exact: a block at or below the floor's blue score that is not the floor cannot
    /// have it as a selected-chain ancestor.
    /// BORROWED: rusty-kaspa's reachability over the pruning point (the pruning point's past is held and ordered by its
    /// GHOSTDAG data, never by a local counter).
    /// AI RESISTANT: (b) code; a peer gains nothing — it cannot place a block whose blue data the carry or A-F97 refuses,
    /// and a wrong `false` here still only delays finality (never finalizes a block off the chain).
    /// SCALE: at most the blue-score gap in steps, each a scan of ≤ dag_width parents only at a trust root; nothing grows
    /// with nodes, items or height.
    /// cons: a walk below an anchor whose true selected parent is NOT held follows the heaviest held one; that parent's
    /// chain can only reach the floor if the floor is in the anchor's past, which the certified carry already binds.
    fn descends_from_finality_floor(&self, tip: &BlockId, floor: &BlockId) -> bool {
        let Some(floor_score) = self.blocks.get(floor).map(|n| n.blue_score) else {
            return false;
        };
        let mut cur = Some(*tip);
        while let Some(c) = cur {
            if c == *floor {
                return true;
            }
            let Some(n) = self.blocks.get(&c) else {
                return false; // walked past the pruned span — cannot prove descent, claim nothing
            };
            if n.blue_score <= floor_score {
                return false; // at or below the floor's blue score and not the floor => a different branch
            }
            cur = self.walk_parent(n);
        }
        false
    }

    /// Ordering key for selected-parent / selected-tip choice: `(blue_work, id)`. The id
    /// tie-break makes the choice deterministic across all nodes (consensus-critical). Used by the
    /// GHOSTDAG + consensus modules too, hence crate-visible.
    /// The canonical order key, exposed so the LEDGER can number its records by consensus order instead of
    /// by the order this node happened to receive blocks.
    ///
    /// Record ordinals were a local append counter, so two mining nodes that hold the SAME blocks numbered
    /// them differently — measured live: 7 of 7 sampled ordinals named different blocks on two peered nodes,
    /// including ordinal 100. A wallet's account bucket records a note's ORDINAL, so on the recipient's node
    /// that ordinal addressed a DIFFERENT block and the payment settled while staying invisible to its owner.
    /// This key is deterministic and node-independent (`blue_work`, tie-broken by content hash), which is
    /// exactly what a record ordinal has to be.
    /// v31: the (timestamp, work) samples of the selected chain below `anchor`, newest first — what a
    /// difficulty or median-time walk continues into when it reaches an anchor.
    /// Every block this DAG holds in `id`'s past (parents, transitively; `id` itself excluded). Bounded by
    /// the DAG's own size — the pruning horizon — and walked once per adopt, never per query.
    pub fn past_of(&self, id: &BlockId) -> Vec<BlockId> {
        let mut seen: std::collections::HashSet<BlockId> = std::collections::HashSet::new();
        let mut stack: Vec<BlockId> = self.blocks.get(id).map(|n| n.header.parents.clone()).unwrap_or_default();
        while let Some(p) = stack.pop() {
            if !seen.insert(p) {
                continue;
            }
            if let Some(n) = self.blocks.get(&p) {
                stack.extend(n.header.parents.iter().copied());
            }
        }
        seen.into_iter().collect()
    }

    /// ⛔ DB-282 — SETTLE WHAT THIS NODE HOLDS GAP-FREE BELOW ITS ANCHOR. `add_anchor` marks every block held before it
    /// as history. That is exact for a JUMPER whose pre-adopt blocks are an ISLAND the anchor's past never reaches (the
    /// anchor links no parent it lacks), and wrong for held structure that DOES reach down from the anchor: a restored
    /// node's re-installed window span (its own history, re-linked below its checkpoint anchor) and a jumper that
    /// crawled right up to the anchor. Such blocks lie inside `bounded_past(sp)` of every block this node will score,
    /// so their GHOSTDAG is computed exactly as a full node computes it, and a peer's block built on them is new
    /// structure here. Only HELD blocks are marked (an absent parent id stays absent). One walk over the held past,
    /// once per adopt or restore. Returns how many blocks it settled.
    pub fn settle_connected_past(&mut self, anchor: &BlockId) -> usize {
        let mut settled = 0usize;
        for id in self.past_of(anchor) {
            if let Some(n) = self.blocks.get_mut(&id) {
                if !n.settled {
                    n.settled = true;
                    settled += 1;
                }
            }
        }
        settled
    }

    /// G1d (lane a 2026-10-23) — SETTLE EVERY HELD BLOCK: each tip and its held past. The resume of a node that ADOPTED
    /// NOTHING — every block it holds is its own history, and its live process holds every one settled (a block added
    /// through `add`/`add_carried_block` is settled; only `add_ancestor_anchor` installs `settled: false`). One walk over
    /// the held span per tip, once per restore. Returns how many blocks it settled.
    pub fn settle_held_span(&mut self) -> usize {
        let mut settled = 0usize;
        for tip in self.tips() {
            for id in std::iter::once(tip).chain(self.past_of(&tip)) {
                if let Some(n) = self.blocks.get_mut(&id) {
                    if !n.settled {
                        n.settled = true;
                        settled += 1;
                    }
                }
            }
        }
        settled
    }

    /// Every block this DAG holds in `id`'s future (children, transitively; `id` itself excluded).
    pub fn descendants_of(&self, id: &BlockId) -> Vec<BlockId> {
        let mut seen: std::collections::HashSet<BlockId> = std::collections::HashSet::new();
        let mut stack: Vec<BlockId> = self.blocks.get(id).map(|n| n.children.clone()).unwrap_or_default();
        while let Some(c) = stack.pop() {
            if !seen.insert(c) {
                continue;
            }
            if let Some(n) = self.blocks.get(&c) {
                stack.extend(n.children.iter().copied());
            }
        }
        seen.into_iter().collect()
    }

    pub fn window_below(&self, anchor: &BlockId) -> Option<&[DaaSample]> {
        self.window_below.get(anchor).map(|v| v.as_slice())
    }
    pub fn set_window_below(&mut self, anchor: BlockId, samples: Vec<DaaSample>) {
        let cap = self.params.daa_sample_len.max(self.params.mtp_sample_len as u64) as usize;
        let mut s = samples;
        s.truncate(cap);
        self.window_below.insert(anchor, s);
    }

    /// The canonical record fold depth this DAG runs with (see `ChainParams::record_fold_depth`): the DEEPEST the fold ever
    /// waits. The depth in force below a given tip is [`Self::fold_depth_at`].
    pub fn record_fold_depth(&self) -> u64 {
        self.params.record_fold_depth
    }

    /// ⭐ SPEED L6 (docs/CHAIN-SPEED-SPEC-20261109.md §6.2) — the mean spacing, in ms, of the selected chain below `tip`: the
    /// span of the header timestamps of its last [`FOLD_RATE_WINDOW`] chain blocks over the steps between them. `None`
    /// while fewer than [`FOLD_RATE_MIN`] are held (a young chain). A function of the DAG alone — the walk and the carried
    /// window are the ones `consensus::median_time_past` reads — so every node with this tip reads the same spacing.
    /// BORROWED: Kaspa's and Bitcoin's difficulty windows (the chain's rate read off its own header timestamps).
    /// cons: one walk of at most FOLD_RATE_WINDOW selected parents per fold pass; no state.
    pub fn chain_step_ms(&self, tip: &BlockId) -> Option<u64> {
        let (mut lo, mut hi, mut n) = (u64::MAX, 0u64, 0u64);
        let mut cur = Some(*tip);
        while let Some(c) = cur {
            if n >= FOLD_RATE_WINDOW {
                break;
            }
            let Some(node) = self.get(&c) else { break };
            let t = node.header.timestamp;
            (lo, hi, n) = (lo.min(t), hi.max(t), n + 1);
            cur = node.selected_parent;
            if cur.is_none() {
                // an anchor: continue into the window it carried, as the median-time walk does
                if let Some(w) = self.window_below(&c) {
                    for (t, _, _) in w.iter() {
                        if n >= FOLD_RATE_WINDOW {
                            break;
                        }
                        (lo, hi, n) = (lo.min(*t), hi.max(*t), n + 1);
                    }
                }
            }
        }
        (n >= FOLD_RATE_MIN).then(|| hi.saturating_sub(lo) / (n - 1))
    }

    /// ⭐ SPEED L6 — THE FOLD DEPTH IN FORCE BELOW `tip`: enough selected-chain steps to cover [`FOLD_SETTLE_MS`] (two
    /// relay rounds) at the chain's own measured spacing, never fewer than [`FOLD_DEPTH_MIN`] and NEVER MORE than the
    /// chain parameter `record_fold_depth` (today's depth). So it only ever makes the fold shallower than today, and
    /// only where the chain's spacing already covers the relay time the depth stands for.
    /// ROOT-LAYER: the one depth the fold root is cut at (`Node::fold_canonical_records_inner`, `Node::fold_position`).
    ///   Every other reader of the parameter wants the DEEPEST the fold can wait (the unbond window, the verify cache,
    ///   `FINALITY_SEAT_ACTIVATION_DELAY`) and keeps reading it.
    /// MEASURED: `scratchpad/net/goals.tsv` 2026-11-04, real nodes — "spendable" grew 17.7 s per extra fold level (depth 8
    ///   → 32) against a predicted 17.9 s, one chain step per level; at depth 4 and a 16 s step that is 72 s of a 104 s
    ///   payment (rig -s, 2026-11-09). The parameter's own comment: the depth stands for the relay time and "must then
    ///   grow with the rate" — written as 4 blocks it is ~65 s on that rig and 3–4 s at the 500 ms target.
    /// A parameter of 0 (a fixture folding at the tip) stays 0. A young chain (no measured spacing) uses the parameter.
    /// A record never UNFOLDS because this depth changed: `fold_canonical_records_inner` returns without rewinding while
    /// its cursor stands ahead of the root on the selected chain.
    /// Timestamps are the producers' own (bounded below by median-time-past and above by the header door's clock rule): a
    /// producer that skews them moves this depth between FOLD_DEPTH_MIN and the parameter, i.e. the fold is as early as
    /// the slowest honest reading or as late as today — never a lost or created note ("spendable is not final").
    /// cons: 0 B. On a slow chain the fold stands FOLD_DEPTH_MIN steps deep instead of 4, so a selected-chain flip deeper
    ///   than that rewinds records a depth-4 fold would not yet have folded (measured by `flips.py` on real nodes).
    /// MUST-STAY-GREEN: the canonical-fold pins (they run at 1 s steps, where this is the parameter), the two-node
    ///   determinism pin `speed_l6_*`, and on real nodes pay / change / burst with no dropped payment.
    pub fn fold_depth_at(&self, tip: &BlockId) -> u64 {
        fold_depth_for(self.params.record_fold_depth, self.chain_step_ms(tip))
    }

    /// ⭐ A BLOCK SETTLES WHEN IT IS FINAL — THE FOLD ROOT (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11.8, §11.13; lane speed
    /// screened it in speed3 fc561073, lane goodshalt made it the rule, 2026-11-15). The fold applies `tip`'s selected chain
    /// up to the highest block of it that is `final_block` or lies on `final_block`'s own selected chain (so it is certainly
    /// in the final block's past), while that final block is at most `delay` levels below the tip (the seat-activation
    /// delay: a cursor further behind could never judge the votes that would move it). Otherwise, with nothing final or
    /// finality further behind, the root is the depth rule's, `depth` levels below the tip, exactly as before this rule
    /// (SAFE-FALLBACK: settlement never waits on a committee; a chain with no bonded voters folds as it always did).
    /// Returns the root and whether finality (true) or the depth rule (false) set it; `None` only when `tip` is not held.
    ///
    /// WHY (MEASURED 2026-11-15, lane goodshalt, three real nodes on 1edf67bb, 40 min): with the root four levels below the
    /// tip (`fold_depth_at`) every node rewound its fold 35 to 38 times (1 to 14 records each). Each rewind voids band proofs
    /// in flight, re-folds received notes (A-F53) and voids the frozen join bundles that restart a stopped fold (A-F56,
    /// `State`). The fork choice floors at the block this node has seen final (`sync_finality_floor_into_dag`, A-F37/A-F54),
    /// so the selected chain never leaves it: nothing at or below this root can be rewound. What is folded is unchanged (the
    /// chain's blocks in canonical order); only WHEN a node folds moves, and that is already local.
    /// The final block's level is its own blue score, never a finality height (§6: two coordinate spaces, one name).
    /// SCALE: one walk of at most `delay` selected-chain levels from the tip and one from the final block; no state; no term
    /// in the bonded set or height. AI RESISTANT: (a) the finality it reads is two thirds of bond's ML-DSA signatures every
    /// node verifies; (b) the distance is a constant of the chain's parameters.
    /// BORROWED: apply at commit (Tendermint); the finalized checkpoint as the settled state (Ethereum, Casper FFG).
    /// cons: while finality lags the depth rule, money settles up to `delay − depth` levels later (lane speed's screen
    /// measured spendable 76 s against 262 s, because rewinds no longer cost re-proofs); none in bytes or state.
    pub fn fold_root_by_finality(&self, tip: &BlockId, final_block: Option<BlockId>, delay: u64, depth: u64) -> Option<(BlockId, bool)> {
        let tip_blue = self.blocks.get(tip)?.blue_score;
        let deep_blue = tip_blue.saturating_sub(delay);
        let final_blue = final_block.and_then(|f| self.blocks.get(&f)).map(|n| n.blue_score);
        if let Some(final_blue) = final_blue.filter(|b| *b >= deep_blue) {
            // the final block's own selected chain down to the deep level: the final block may be a sibling the tip's
            // chain merged, and then the highest selected-chain block the two share is what is certainly in its past
            let mut final_chain: HashSet<BlockId> = HashSet::new();
            let mut at = final_block;
            while let Some(id) = at {
                let Some(n) = self.blocks.get(&id) else { break };
                final_chain.insert(id);
                if n.blue_score <= deep_blue {
                    break;
                }
                at = n.selected_parent;
            }
            let mut at = *tip;
            while let Some(n) = self.blocks.get(&at) {
                if n.blue_score < deep_blue {
                    break;
                }
                if n.blue_score <= final_blue && final_chain.contains(&at) {
                    return Some((at, true));
                }
                match n.selected_parent {
                    Some(p) => at = p,
                    None => break,
                }
            }
        }
        // the depth rule: `depth` selected-chain levels below the tip (genesis bounds the walk)
        let mut root = *tip;
        for _ in 0..depth {
            match self.blocks.get(&root).and_then(|n| n.selected_parent) {
                Some(p) => root = p,
                None => break,
            }
        }
        // ⛔⛔ A-F85 (lane speed5, 2026-11-16) — WHILE FINALITY IS LIVE BUT LATE, THE DEPTH RULE NEVER FOLDS MORE THAN THE FOLD
        // CAN UNDO. The fold undoes only `NON_FINAL_FOLD_REACH`'s journal (`SPINE_RING_LEN` steps, `Node::rewind_window_floor`)
        // while the DAG merges a late block up to `merge_depth_cap` (3,600) deep; this branch ran whenever the final block was
        // more than `delay` levels down and folded to `depth` (2) under the tip however far that stood above it. MEASURED
        // (verifier rig, main 7d357574, ~/.usdmd-localnet-queue-verify/n0/node.log:15250-15312): blocks seen final ~100 s after
        // their stamp, the fold 2 levels under the tip, a late heavier branch rewound 70 non-final steps past the 64-step
        // peg journal ('a rewind reached below the peg ledger's fold journal'), the node stopped folding for good and the
        // cash checks read "the chain STOPPED". So with a final block on record the root is walked down until at most
        // `NON_FINAL_FOLD_REACH` blue levels stand above the newest final block: every non-final step the fold applies can
        // be rewound, and nothing at or under the final block is rewound (the fork choice floors there). BORROWED: Kaspa's
        // invariant — what the DAG may still reorganise, the node can undo.
        // ASSUMPTION, named (AI RESISTANT (b)): a committee that stops voting for good must not hold settlement for ever
        // (SAFE-FALLBACK: settlement never waits on a committee). When the newest final block's stamp stands more than
        // `FINALITY_STALL_DAA_WINDOWS` DAA windows of chain time under the tip's, finality is read as stalled and the depth
        // rule folds as it did before this cap, with the reorg risk it had then; with no final block at all, likewise.
        // SCALE: one more walk of at most the cap's levels; no state, no bytes; constant in the bonded set and height.
        // cons: while finality is live but lags more than 32 levels, money settles when finality catches up instead of at
        // the depth rule (spendable later by that lag; production is untouched); after the stall bound the old risk returns.
        if let Some(fb) = final_blue {
            let stamp = |id: &BlockId| self.blocks.get(id).map_or(0, |n| n.header.timestamp);
            let window_ms = self.params.daa_sample_len.saturating_mul(self.params.target_spacing_ms);
            let stalled = final_block.is_some_and(|f| {
                stamp(tip).saturating_sub(stamp(&f)) > FINALITY_STALL_DAA_WINDOWS.saturating_mul(window_ms)
            });
            if !stalled {
                while let Some(n) = self.blocks.get(&root) {
                    if n.blue_score <= fb.saturating_add(NON_FINAL_FOLD_REACH) {
                        break;
                    }
                    match n.selected_parent {
                        Some(p) => root = p,
                        None => break,
                    }
                }
            }
        }
        Some((root, false))
    }

    pub fn canonical_order_key(&self, id: &BlockId) -> (u128, BlockId) {
        self.order_key(id)
    }

    /// ⭐⭐ A BLOCK'S OWN SELECTED PARENT: the heaviest of `parents` by [`Self::order_key`] — the ONE choice every reader of
    /// a block's parent-derived consensus fields makes: the DAA figure the contextual door expects
    /// (`consensus::validate_contextual`), the shell door's work check, and the template that must satisfy both
    /// (`miner::build_template_reserving`). Node-independent by construction — never [`Self::selected_tip`], whose key leads
    /// with THIS node's finality verdict. BORROWED-FROM Kaspa: a block's GHOSTDAG selected parent is the max-blue-work
    /// parent, and the DAA window (`calc_block_bits`) is read from that block's own GHOSTDAG data, so producer and validator
    /// compute one figure. MEASURED why (link 63, night/perf-load-20261020-230237-n8.log): the template read the work from
    /// the finality-bounded selected tip while building on the plain-heaviest tip, and its own graft refused it —
    /// `WrongWork { expected: 11, got: 12 }` ×72 against 89 blocks kept in the load window.
    /// cons: none — one pass over the parents, the same pass each caller ran inline.
    pub fn selected_parent_of(&self, parents: &[BlockId]) -> Option<BlockId> {
        parents.iter().copied().max_by(|a, b| self.order_key(a).cmp(&self.order_key(b)))
    }

    pub fn order_key(&self, id: &BlockId) -> (u128, BlockId) {
        let bw = self.blocks.get(id).map(|n| n.blue_work).unwrap_or(0);
        (bw, *id)
    }

    /// ⛔⛔ A-F94 (lane speed5, 2026-11-17; docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J2) — THE PARENT A MERGE-DEPTH WALK CLIMBS TO.
    /// A block admitted here carries its GHOSTDAG selected parent. A placeholder (a carried ancestor, `add_ancestor_anchor`, or the
    /// anchor itself) is installed with none, so the walk stopped there and read Unevaluable — and `add_block` refuses an
    /// unevaluable walk as `MergesPreAnchorHistory`. With `MERGEABLE_DEPTH` 48 and a served anchor 40-112 levels deep, every block
    /// in the first ~48 levels above a joiner's anchor that merged a side block meeting the chain below the anchor was refused
    /// (netsim main 84181ee0: 39 refusals, all four joiners stopped at fold 190). A placeholder's parent is the one GHOSTDAG
    /// itself selects: the heaviest held parent by `(blue_work, id)` (`ghostdag_data`'s rule). That is exact whenever the true
    /// selected parent is held; the bundle carries the anchor's past down to `MERGEABLE_DEPTH + ghostdag_k + 1` levels under it
    /// (`Node::carry_for`), and a selected parent is at most `ghostdag_k + 1` levels under its child, so every parent
    /// a walk follows above its floor is held. A walk that reaches a held block below the floor still returns Violates first.
    /// A from-genesis DAG has one block with no selected parent (genesis, no parents): unchanged.
    /// BORROWED: Kaspa ships the pruning point's nearby past with its GHOSTDAG data so the merge-depth rule is evaluable.
    /// AI RESISTANT: (b) — the walk reads only held blocks whose blue data the certified carry binds (A-F97 checks it on placement).
    /// SCALE: one scan of a block's parents (≤ dag_width) per step; the walk's bound is unchanged.
    fn walk_parent(&self, n: &BlockNode) -> Option<BlockId> {
        n.selected_parent.or_else(|| {
            n.header
                .parents
                .iter()
                .filter(|p| self.blocks.contains_key(p))
                .max_by(|a, b| self.order_key(a).cmp(&self.order_key(b)))
                .copied()
        })
    }

    /// Every block a GHOSTDAG step merges, blues then reds (the selected parent is among the blues).
    fn mergeset_of(gd: &crate::ghostdag::GhostdagData) -> Vec<BlockId> {
        gd.mergeset_blues.iter().chain(gd.mergeset_reds.iter()).copied().collect()
    }

    /// ⭐⭐⭐ DB-361 (DB-274 P1) — KASPA'S BOUNDED MERGE DEPTH, the ONE verdict every door reads.
    ///
    /// BORROWED-FROM rusty-kaspa `check_bounded_merge_depth`: every block B merges must lie in the future of B's
    /// merge-depth root (B's selected-chain ancestor `merge_depth_cap` blue score down). Reachability is decided by
    /// SELECTED-CHAIN INTERSECTION: walk each merged m's selected parents until the walk lands on B's selected
    /// chain (then R(B) ∈ past(m): Within) or drops below the floor `T = blue_score − merge_depth_cap` (Violates).
    /// The walk ends because `blue_score` falls strictly along every selected-parent edge (the selected parent is
    /// always blue in its child's mergeset). Stricter than Kaspa only when m's chain runs BESIDE B's for more than
    /// the depth while m's past reaches B's chain through non-selected edges — a deep two-chain race, refused on
    /// every node alike (DB-361 §2, §8(a)).
    ///
    /// DETERMINISTIC: a function of B's past (`blue_score`, selected-parent pointers) and the governance
    /// `merge_depth_cap`, never of this node's tip or arrival order. BOUNDED: B's chain is extended lazily only to
    /// the lowest level a walk reaches, and every block on a walk that ended Within is memoised for the rest of this
    /// check, so a check visits each block of B's past with score ≥ T at most once: ≤ merge_depth_cap × dag_width
    /// lookups, constant in height. Transient: the two sets die with the call.
    /// cons: 0 B on the wire and on disk; honest blocks meet the chain within a few lookups (µs); a hostile block
    /// costs ≤ 3,600 × 32 ≈ 115 k map lookups (~5 ms), each paid for by the grind the header door verified first.
    pub fn merge_depth_verdict(
        &self,
        selected_parent: &BlockId,
        mergeset: Vec<BlockId>,
        blue_score: u64,
    ) -> MergeDepthVerdict {
        let floor = blue_score.saturating_sub((self.params.merge_depth_cap as u64).min(MERGEABLE_DEPTH));
        if floor == 0 {
            return MergeDepthVerdict::Within; // every block's score is ≥ 0: nothing can sit below the floor
        }
        let mut chain: HashSet<BlockId> = HashSet::new();
        let mut chain_next: Option<BlockId> = Some(*selected_parent);
        let mut chain_low: u64 = u64::MAX;
        let mut within: HashSet<BlockId> = HashSet::new();
        for m in mergeset {
            if m == *selected_parent {
                continue;
            }
            let mut walked: Vec<BlockId> = Vec::new();
            let mut x = m;
            loop {
                if within.contains(&x) {
                    break;
                }
                let Some(xn) = self.blocks.get(&x) else {
                    return MergeDepthVerdict::Unevaluable;
                };
                if xn.blue_score < floor {
                    return MergeDepthVerdict::Violates;
                }
                while chain_low > xn.blue_score {
                    let Some(c) = chain_next else { break };
                    let Some(cn) = self.blocks.get(&c) else {
                        return MergeDepthVerdict::Unevaluable;
                    };
                    chain.insert(c);
                    chain_low = cn.blue_score;
                    chain_next = self.walk_parent(cn);
                }
                if chain.contains(&x) {
                    break;
                }
                walked.push(x);
                match self.walk_parent(xn) {
                    Some(p) => x = p,
                    None => return MergeDepthVerdict::Unevaluable, // a held block whose ancestry this node lacks
                }
            }
            within.extend(walked);
        }
        MergeDepthVerdict::Within
    }

    /// ⭐ DB-361 — THE TEMPLATE'S PARENTS, borrowed from rusty-kaspa `pick_virtual_parents`: the selected tip, plus
    /// every other tip whose merge keeps the new block inside its merge depth. A violating tip is dropped ALONE —
    /// never the whole set — so one attacker tip kept alive past the depth cannot collapse honest templates to one
    /// parent (DB-361 §8(b)). The final set is re-checked because each merged sibling raises the new block's blue
    /// score and with it the floor; while it fails, the lightest remaining sibling is dropped. `[selected tip]` alone
    /// is always valid (its mergeset is the selected parent), so production never waits on this rule.
    /// cons: ≤ (tips + tips) GHOSTDAG passes per template, once per produced block; 0 B anywhere.
    /// A-F37 + A-F54 (lane goods, 2026-11-13): the selected parent is the head this node SELECTS ([`Self::selected_tip`]:
    /// keeps the finalized block, then work; when a merge consumed the last tip keeping it, the heaviest block that does),
    /// never the plain-heaviest tip and never the finality floor itself (building on the floor put blocks below every fold
    /// cursor and halted the chain, A-F54). A sibling is merged when it is lighter than the head (GHOSTDAG takes the
    /// heaviest parent as the selected parent, so a heavier one would carry the block off the head) and inside the merge
    /// depth, whether or not its own chain keeps the floor (A-F58: a lighter non-floor sibling left unmerged is a tip
    /// forever, and its notes never fold).
    pub fn template_parents(&self) -> Vec<BlockId> {
        let mut tips = self.tips();
        tips.sort_by(|a, b| self.finality_bounded_order_key(b).cmp(&self.finality_bounded_order_key(a)));
        let Some(sp) = self.selected_tip() else {
            return tips;
        };
        // A-F54: `sp` already is the heaviest block that keeps the floor when no tip does
        // ([`Self::selected_tip`] walks down from the tips), so no second walk is needed here.
        // Main's interim fix (95f090db, lane af54fix) scanned every held block and ran a
        // selected-chain walk for each one: up to blocks × depth lookups per template.
        // The walk from the tips stops at the first block that keeps the floor, so it visits
        // only the blocks above that head. It also gives every other reader of `selected_tip`
        // the same head.
        // BORROWED: Ethereum's fork choice starts at the justified checkpoint; Kaspa's
        // pick_virtual_parents replaces tips past the pruning point with ancestors on the
        // canonical chain.
        let sp_key = self.order_key(&sp);
        let within = |parents: &[BlockId]| {
            let gd = self.ghostdag_data(parents);
            self.merge_depth_verdict(&gd.selected_parent, Self::mergeset_of(&gd), gd.blue_score)
                == MergeDepthVerdict::Within
        };
        let mut chosen: Vec<BlockId> = vec![sp];
        // ⛔ A-F58 (lane af58, 2026-11-13): a sibling is merged when it is LIGHTER than the head by GHOSTDAG's own key and
        // inside the merge depth — WHETHER OR NOT its own chain keeps the finality floor. The `finality_admits(t) > 0` filter
        // that stood here left every tip of a branch that forked before the votes finalized a block on the other branch a
        // tip forever (veil rig: tips 30 → 95): no template merged it, its blocks never folded, and the notes they carried
        // never arrived (record 185526021433325320 folded once at ordinal 28, left the spine at a reorg, asked for 1,610
        // times by its owner's wallet in 50 min). Merging it keeps finality: being lighter, it is never the new block's
        // selected parent, so the selected chain stays on the head (which keeps the floor) and past(F) is untouched; the
        // sibling's blocks join the merge set AFTER F. BORROWED: Kaspa merges the finality point's anticone within the merge
        // depth (only a selected chain may never leave the finality point); rusty-kaspa `pick_virtual_parents` drops a tip
        // for the merge-depth bound alone. A heavier sibling stays out (`order_key(t) < sp_key`, A-F54's guard).
        // W1: a tip with a withheld block in its past is never merged — its mergeset would carry that block into this one
        // ⛔ U-SHELL (2026-11-27, docs/UX-DEEP-AUDIT-20261126.md): the live origin's template walked 77 tips (4,141 samples of a 30 s
        // `sample`, all GHOSTDAG); which rule each tip fails is counted here, once a minute, before any fix is written.
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts of public tips; no id, note or peer.
        let (mut unavailable, mut heavier, mut outside) = (0usize, 0usize, 0usize);
        // ⛔ U-SHELL: a tip refused for the merge depth against `sp0` is refused again without the walk while the head is `sp0` or
        // extends it along the selected chain (O(1) each: `is_ancestor_of_selected_tip`); a reorg to another branch checks it afresh
        let still_refused = |t: &BlockId| -> bool {
            self.merge_refused.borrow().get(t).is_some_and(|sp0| {
                *sp0 == sp
                    || (self.is_ancestor_of_selected_tip(sp0)
                        && self.is_ancestor_of_selected_tip(&sp)
                        && self.blocks.get(sp0).zip(self.blocks.get(&sp)).is_some_and(|(a, b)| a.blue_score <= b.blue_score))
            })
        };
        self.merge_refused.borrow_mut().retain(|t, _| tips.contains(t));
        for t in tips.iter().filter(|t| **t != sp) {
            if self.availability_admits(t) != 1 {
                unavailable += 1;
                continue;
            }
            if self.order_key(t) >= sp_key {
                heavier += 1;
                continue;
            }
            if still_refused(t) {
                outside += 1;
                continue;
            }
            if within(&[sp, *t]) {
                chosen.push(*t);
                self.merge_refused.borrow_mut().remove(t);
            } else {
                outside += 1;
                self.merge_refused.borrow_mut().insert(*t, sp);
            }
        }
        let first_choice = chosen.len();
        while chosen.len() > 1 && !within(&chosen) {
            chosen.pop(); // tips are heaviest-first, so the lightest sibling goes first
        }
        {
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if now.saturating_sub(LAST.load(std::sync::atomic::Ordering::Relaxed)) >= 60 {
                LAST.store(now, std::sync::atomic::Ordering::Relaxed);
                eprintln!(
                    "[template-parents] {} tip(s): {unavailable} unavailable (W1), {heavier} heavier than the head, {outside} outside the merge depth, {} chosen then {} kept",
                    tips.len(),
                    first_choice,
                    chosen.len()
                );
            }
        }
        chosen
    }

    /// Add a block. Validates all parents exist, runs GHOSTDAG to derive its selected parent +
    /// blue_score + blue_work, wires child edges, and updates the tip set. Rejects the bad block
    /// only (never halts). Idempotent on a duplicate.
    pub fn add_block(&mut self, block: Block) -> Result<BlockId, DagError> {
        let id = block.id();
        let boundary_before = self.window_boundary();
        if self.blocks.contains_key(&id) {
            return Err(DagError::Duplicate(id));
        }
        let header = block.header;

        let (selected_parent, blue_work, blue_score, chain_len) = if header.is_genesis() {
            if self.genesis.is_some() {
                return Err(DagError::SecondGenesis);
            }
            (None, 0u128, 0u64, 0u64)
        } else {
            for p in &header.parents {
                if !self.blocks.contains_key(p) {
                    return Err(DagError::MissingParent(*p));
                }
            }
            // ⛔⛔⛔ DB-282 — A BLOCK BUILT ONLY ON HISTORY THIS NODE SETTLED IS NOT NEW STRUCTURE HERE.
            // BORROWED-FROM Kaspa `check_pruning_violation` (a new block must stand in the future of the pruning point;
            // for a node that installed an anchor, the anchor is that point), made STRICTER because this DAG still HOLDS
            // blocks below its point where Kaspa's store has pruned them: EVERY parent must be settled. With "any", a
            // block naming {a settled tip, an island block} passes, and this node's mergeset BFS walks the island — a
            // full node sees those blocks inside past(sp) and excludes them, so GHOSTDAG would still diverge here
            // (review by lane-db224-carriage, 2026-09-27). Every block in the anchor's past has all its parents in that
            // past, so it is refused EXACTLY, with no blue-score approximation. MEASURED gate Q6 (n2.log): ~70 of the origin's old blocks, delivered after the
            // jump by an inventory made before it, grafted onto the jumper's crawl island; each graft applied the block
            // in one act (A_tip folded a leaf the certified A_tip already counts, record written, chain objects, bonds,
            // directory and letters applied) and the jumper's next block merged the island, scoring +32 (= ghostdag_k)
            // on every later block. Checked BEFORE the GHOSTDAG walk and before any mutation: a refusal costs one pass
            // over the parents (≤ dag_width) and changes nothing.
            // cons: a block naming ANY parent this node holds only as history (a block of its own pre-anchor side
            // structure, or a stale block the carry did not bring) is refused here while a from-genesis node takes it;
            // the chain that builds on it parks here and this node re-anchors by DSYNC, whose carry then brings that
            // block as settled structure (fail-closed on the stale item, no halt). Without the rule the same block
            // made this node's GHOSTDAG diverge (+k) — the DB-267 late-merge class, which a merge-depth consensus rule
            // closes for every node.
            if self.settled_base {
                let settled = header
                    .parents
                    .iter()
                    .filter(|p| self.blocks.get(p).map_or(false, |n| n.settled))
                    .count();
                if settled == 0 {
                    // pure history: a re-served block from inside the settled past (or a side branch that stale)
                    // A-F94 diag (lane speed5, 2026-11-17): how the refused block stands against this node's settled base —
                    // its parents' blue scores and whether the DAG holds each, and the newest settled block's score. Public
                    // chain structure only (scores and counts; no id). DIGITAL-CASH-PRIVACY-REVIEWED.
                    let parent_scores: Vec<String> = header
                        .parents
                        .iter()
                        .map(|p| self.blocks.get(p).map_or_else(|| "absent".to_string(), |n| n.blue_score.to_string()))
                        .collect();
                    let settled_top = self.blocks.values().filter(|n| n.settled).map(|n| n.blue_score).max().unwrap_or(0);
                    eprintln!(
                        "[settled-base] refused a block whose {} parent(s) are all history: parent blue scores {:?}; the newest settled block is at {} ({} held)",
                        header.parents.len(),
                        parent_scores,
                        settled_top,
                        self.blocks.len()
                    );
                    return Err(DagError::BelowSettledBase(id));
                }
                if settled < header.parents.len() {
                    // a late merge of pre-anchor history into the chain this node follows
                    // A-F94 diag (lane speed5, 2026-11-17): which parent is history and how it was placed — its blue score, whether
                    // it is a placeholder with no selected parent (an ancestor shell or the anchor) and whether its past reaches the
                    // newest anchor floor. Public chain structure only (scores, flags; no id). DIGITAL-CASH-PRIVACY-REVIEWED.
                    let floor_score = self.anchor_floor.and_then(|a| self.blocks.get(&a)).map(|n| n.blue_score);
                    let parents: Vec<String> = header
                        .parents
                        .iter()
                        .map(|p| match self.blocks.get(p) {
                            None => "absent".to_string(),
                            Some(n) => format!(
                                "{}{}{}",
                                n.blue_score,
                                if n.settled { "/settled" } else { "/HISTORY" },
                                if n.selected_parent.is_none() { "/placeholder" } else { "" }
                            ),
                        })
                        .collect();
                    eprintln!(
                        "[settled-base] refused a merge of history: parents {parents:?}; anchor floor at {floor_score:?} ({} held)",
                        self.blocks.len()
                    );
                    return Err(DagError::MergesPreAnchorHistory(id));
                }
            }
            let gd = self.ghostdag_data(&header.parents);
            // ⛔ DB-361 — THE BOUNDED MERGE DEPTH, a VALIDITY rule on every node (Kaspa `check_bounded_merge_depth`).
            // MUST: the caller verified this block's proof-of-work BEFORE this insert (`Node::header_door_refusal`
            // runs the grind on every path into `add_block`), so the walk below — ≤ merge_depth_cap × dag_width
            // lookups on a hostile block — is paid for by a full grind each time. An unevaluable walk (a jumper
            // whose held DAG stops at its anchor) is refused as pre-anchor history, which re-anchors the node:
            // fail-closed on the item, never read as admitted.
            match self.merge_depth_verdict(&gd.selected_parent, Self::mergeset_of(&gd), gd.blue_score) {
                MergeDepthVerdict::Within => {}
                MergeDepthVerdict::Violates => return Err(DagError::ViolatesMergeDepth(id)),
                MergeDepthVerdict::Unevaluable => return Err(DagError::MergesPreAnchorHistory(id)),
            }
            let cl = self.blocks[&gd.selected_parent].selected_chain_len + 1;
            (Some(gd.selected_parent), gd.blue_work, gd.blue_score, cl)
        };

        // Wire child edges; a referenced parent is no longer a tip.
        for p in &header.parents {
            if let Some(pn) = self.blocks.get_mut(p) {
                pn.children.push(id);
            }
            self.tips.remove(p);
        }

        let topo_order = self.topo_counter;
        self.topo_counter += 1;
        let is_gen = header.is_genesis();
        let node = BlockNode {
            header,
            tx_ids: block.tx_ids,
            children: Vec::new(),
            selected_parent,
            blue_score,
            blue_work,
            selected_chain_len: chain_len,
            topo_order,
            // admitted by the rule above (or no anchor was ever installed)
            settled: true,
            chain_tags: None,
        };
        if is_gen {
            self.genesis = Some(id);
        }
        self.insert_block(id, node);
        self.tips.insert(id);
        self.head_inputs_changed(boundary_before);
        Ok(id)
    }

    /// Graft a #29 DSYNC-adopted peer TIP as a first-class DAG anchor (the mergeset-graft that lets two
    /// independent producers CONVERGE on one shared tip, not just track height). The decider proof —
    /// verified BEFORE this call ([`crate::sync::adopt_sync_bundle`]) — certifies the peer's chain up to
    /// `block` is valid, so the anchor is a TRUST ROOT: it is installed WITHOUT replaying its ancestry
    /// (that is the whole point of O(1) instant-sync). It carries the CERTIFIED `blue_work`/`blue_score`.
    /// We reorg onto it ONLY if it strictly outranks our current selected tip by the GHOSTDAG
    /// `(blue_work, id)` key — so the LIGHTER of two peers follows the HEAVIER chain and the heavier one
    /// ignores the lighter (no adopt ping-pong). On a win it becomes the sole selected tip, so our next
    /// produced block builds ON the peer's tip → the peer grafts it → the DAGs converge. Returns whether
    /// we reorged. Idempotent / no-op when we already hold the tip or ours is heavier.
    /// v31: a FOLDED ancestor placeholder — a block at or below the fold root that a carried block names as a
    /// parent, or one of the selected-chain window headers below the fold root (the DAA and MTP samples).
    /// Inserted with its real blue work/score and linked to `selected_parent` when that block is present, so
    /// the difficulty and median-time walks see a complete window and GHOSTDAG can place its children. Never
    /// made a tip. Idempotent.
    pub fn add_ancestor_anchor(
        &mut self,
        header: BlockHeader,
        tx_ids: Vec<crate::hash::Hash32>,
        blue_work: u128,
        blue_score: u64,
        selected_parent: Option<BlockId>,
    ) -> bool {
        let id = header.id();
        if self.blocks.contains_key(&id) {
            return false;
        }
        let sp = selected_parent.filter(|p| self.blocks.contains_key(p));
        let topo_order = self.topo_counter;
        self.topo_counter += 1;
        let chain_len = sp
            .and_then(|p| self.blocks.get(&p).map(|n| n.selected_chain_len + 1))
            .unwrap_or(blue_score);
        if let Some(p) = sp {
            if let Some(pn) = self.blocks.get_mut(&p) {
                pn.children.push(id);
            }
        }
        self.insert_block(
            id,
            BlockNode {
                header,
                tx_ids,
                children: Vec::new(),
                selected_parent: sp,
                blue_score,
                blue_work,
                selected_chain_len: chain_len,
                topo_order,
                // DB-282: a folded ancestor sits at or below the fold root — history the carried state counts
                settled: false,
                chain_tags: None,
            },
        );
        true
    }

    /// v31: a CARRIED unfolded block — a block above the fold root that a checkpoint or a DSYNC bundle brought
    /// with the blue data its producer computed. Every parent must already be present (the carry lists the
    /// folded ancestors first); the selected parent is the heaviest present parent, children are linked, the
    /// tips move forward. No difficulty recomputation: the block's own proof-of-work was verified on ingest
    /// and its blue data is bound into the certified bundle / the node's own checkpoint.
    pub fn add_carried_block(&mut self, block: Block, blue_work: u128, blue_score: u64) -> bool {
        let id = block.id();
        let boundary_before = self.window_boundary();
        if let Some(held) = self.blocks.get_mut(&id) {
            // DB-282: the carry certifies this block as structure above the anchor even when this node already held
            // it (a side block it crawled before the adopt) — its children are new structure, not history.
            held.settled = true;
            return false;
        }
        if block.header.parents.iter().any(|p| !self.blocks.contains_key(p)) {
            return false;
        }
        // ⛔ DB-361 §8(c) — THE CERTIFICATE BINDS FOLD + WORK, NOT GHOSTDAG VALIDITY, so a carried block is held to
        // the merge-depth rule wherever this node can evaluate it (a violating block in a served carry is a chain no
        // honest node built: refused). The exemption is NARROW: only a walk that leaves this node's held DAG is
        // admitted, and only because a carried block sits AT OR BELOW the certified tip, its identity fixed by that
        // tip's parent hashes — the DB-282 residual, never a pass. DB-360's top-up (above the certified tip) must
        // enter through `add_block`, which carries the full rule.
        if !block.header.is_genesis() {
            let gd = self.ghostdag_data(&block.header.parents);
            if self.merge_depth_verdict(&gd.selected_parent, Self::mergeset_of(&gd), blue_score)
                == MergeDepthVerdict::Violates
            {
                return false;
            }
            // ⛔⛔ A-F97 (lane speed5, 2026-11-17) — THE SERVER'S BLUE FIGURES ARE CHECKED, NEVER TAKEN. A header commits its own
            // `work`, never its blue score or blue work, and the certificate binds fold + work, not GHOSTDAG (above), so a hostile
            // bundle server could state any figures for a carried block: an inflated side block becomes the selected parent of
            // every honest block that merges it on this node alone, which then scores the chain unlike its peers (a one-node
            // fork-choice split). Now: where this node's view of the block's past is EXACT
            // ([`Dag::ghostdag_view_is_exact`]: every block both walks reach is held), the figures must EQUAL its own GHOSTDAG;
            // where it is not (the carry stands on ancestor shells whose own parents are absent), they must lie inside what
            // GHOSTDAG can produce from the selected parent: blue score sp + 1 ..= sp + k + 1 (the mergeset holds at most k + 1
            // blues, sp among them) and blue work ≥ sp's blue work + sp's own header work (sp is always blue).
            // REFUSES: a stated figure off by one wherever the view is exact; a score jump past k + 1 anywhere.
            // AI RESISTANT: (a)-shaped where exact (the statement is recomputed from committed headers); (b) where not — the
            //   residual is a work figure inflated inside the bound on a block whose past this node cannot see, bounded by
            //   the anchor floor (a tip outside the anchor's future never leads, `finality_bounded_order_key`) and repaired
            //   at the next re-anchor. NAMED, not closed: an inexact view's blue WORK has no upper bound without the
            //   absent blocks' headers.
            // SCALE: one extra walk of ≤ merge_depth_cap lookups per carried block (the walk ghostdag_data already makes).
            // cons: none on the wire or on disk; an honest server's figures are the full node's, so nothing honest is refused.
            let Some(spn) = self.blocks.get(&gd.selected_parent) else { return false };
            let k = self.params.ghostdag_k;
            let stated_ok = if self.ghostdag_view_is_exact(&block.header.parents, &gd.selected_parent) {
                (gd.blue_score, gd.blue_work) == (blue_score, blue_work)
            } else {
                blue_score > spn.blue_score
                    && blue_score <= spn.blue_score.saturating_add(k.saturating_add(1))
                    && blue_work >= spn.blue_work.saturating_add(spn.header.work)
            };
            if !stated_ok {
                eprintln!(
                    "[carry] A-F97: refused a carried block whose stated blue figures are not what GHOSTDAG gives here \
                     (stated score {blue_score}, this node's {}; selected parent at {})",
                    gd.blue_score, spn.blue_score
                );
                return false;
            }
        }
        let sp = block
            .header
            .parents
            .iter()
            .copied()
            .max_by(|a, b| self.order_key(a).cmp(&self.order_key(b)));
        let topo_order = self.topo_counter;
        self.topo_counter += 1;
        let chain_len = sp
            .and_then(|p| self.blocks.get(&p).map(|n| n.selected_chain_len + 1))
            .unwrap_or(blue_score);
        for p in &block.header.parents {
            if let Some(pn) = self.blocks.get_mut(p) {
                pn.children.push(id);
            }
            self.tips.remove(p);
        }
        self.insert_block(
            id,
            BlockNode {
                header: block.header,
                tx_ids: block.tx_ids,
                children: Vec::new(),
                selected_parent: sp,
                blue_score,
                blue_work,
                selected_chain_len: chain_len,
                topo_order,
                // DB-282: the certified carry is the structure above the anchor
                settled: true,
                chain_tags: None,
            },
        );
        self.tips.insert(id);
        self.head_inputs_changed(boundary_before);
        true
    }

    /// C1's by-id BLOCK fill (the 7u8 block lane): graft a fold-named block from its
    /// id-authenticated shell — header + tx_ids, the exact halves a `BlockNode` retains, served by
    /// any peer whose DAG holds the id. The caller (`Node::graft_wanted_block_shell`) has already
    /// verified the shell hashes to an id THIS node derived from admitted chain structure (a held
    /// block's parent list, walked by the canonical fold's mergeset pass), so these header bytes
    /// ARE that block's — the same header every verifying node admitted when it was gossiped. The
    /// witness halves (pow proof, notes, sidecar sets) are not retained by ANY node once folded
    /// (no-growth), so the shell is the complete servable truth for a folded block — the same
    /// trust class as `add_ancestor_anchor`'s certified carry headers.
    ///
    /// GHOSTDAG data is COMPUTED from the present parents exactly as `add_block` computes it —
    /// never served, never trusted — so a shell cannot claim weight. Every parent must be present
    /// (the block-lane page is retried parents-first; what cannot place is re-asked). Child edges
    /// are wired BOTH directions: blocks already present that name this id as a parent (they
    /// arrived first — a DSYNC anchor, a fold carry, a resume) get their back-link here, and the
    /// shell joins `tips` ONLY when nothing present references it — a mid-DAG hole must never
    /// resurrect as a tip a producer would try to merge again (an ancestor in a parent list is a
    /// consensus violation on every other node).
    ///
    /// Footprint: ONE `BlockNode` into the same `blocks` map every graft path writes, kept bounded
    /// by `prune_below_horizon` (called at the end of this fn, exactly as in `add_block`) over the
    /// fixed pruning horizon — a protocol constant, no term in height or history. The child scan
    /// reads that same bounded map once per shell graft (a heal event, never steady state) and
    /// stores nothing.
    pub fn add_wanted_shell(&mut self, block: Block) -> bool {
        let id = block.id();
        let boundary_before = self.window_boundary();
        if self.blocks.contains_key(&id) {
            return false;
        }
        if block.header.is_genesis() {
            return false; // genesis is constructed, never fetched
        }
        if block
            .header
            .parents
            .iter()
            .any(|p| !self.blocks.contains_key(p))
        {
            return false; // parents-first: the page loop retries, the lane re-asks
        }
        let gd = self.ghostdag_data(&block.header.parents);
        let chain_len = self.blocks[&gd.selected_parent].selected_chain_len + 1;
        // Present blocks that already name this id as a parent: their forward edge was unwireable
        // when THEY landed (this block was absent), so wire it now — and their existence proves
        // this block is interior, never a tip.
        let kids: Vec<BlockId> = self
            .blocks
            .iter()
            .filter(|(_, n)| n.header.parents.contains(&id))
            .map(|(k, _)| *k)
            .collect();
        let referenced = !kids.is_empty();
        // ⛔ DB-361 — a shell no held block names becomes a TIP: it is a new block in effect and carries the
        // merge-depth rule like `add_block`. A shell held blocks already name is an interior hole of structure that
        // entered only through the certified carry (`add_block` refuses a missing parent), so it is that history.
        if !referenced
            && self.merge_depth_verdict(&gd.selected_parent, Self::mergeset_of(&gd), gd.blue_score)
                == MergeDepthVerdict::Violates
        {
            return false;
        }
        let parents = block.header.parents.clone();
        let topo_order = self.topo_counter;
        self.topo_counter += 1;
        self.insert_block(
            id,
            BlockNode {
                header: block.header,
                tx_ids: block.tx_ids,
                children: kids,
                selected_parent: Some(gd.selected_parent),
                blue_score: gd.blue_score,
                blue_work: gd.blue_work,
                selected_chain_len: chain_len,
                topo_order,
                // DB-282: the shell door admits only ids the canonical fold derived from ADMITTED structure (a held
                // block's parent list), so a shell is part of what this node follows, never re-served history. The
                // door keeps its own admission (parents present); it is not a second graft path for old blocks.
                settled: true,
                chain_tags: None,
            },
        );
        // Wire the parent-side child edges (mutating entries that already exist — no new store).
        for p in &parents {
            if let Some(pn) = self.blocks.get_mut(p) {
                pn.children.push(id);
            }
            self.tips.remove(p);
        }
        if !referenced {
            self.tips.insert(id);
        }
        // ⭐⭐ SELF-HEAL SH1 (lane selfheal, 2026-11-25; scratchpad/scope/build/self-heal.tsv) — A HEADER-ONLY TIP IS NEVER BUILT ON.
        // A shell that nothing references here is a TIP this node holds no body for; extending it is what put 9,451 blocks on
        // a body nobody served (A-F138: `produce.rs` "healed as SHELLS … producing anyway"). It is marked like a withheld block
        // at once (never head, never merged) and the mark clears when its body lands (`fill_shell_body_preverified`); the
        // template builds on the heaviest block whose body is held. A shell UNDER blocks already held (`referenced`, the DB-4
        // heal of a gap) keeps W1's reach rule: its body normally arrives within seconds, and dropping the chain above it at once
        // would move the head below a chain this node already follows.
        // BORROWED: Kaspa's block status — a header-only block is never a virtual parent. AI RESISTANT (b): a peer that serves
        // headers without bodies gains nothing — its headers are never extended. SCALE: one mark a shell tip; nothing grows.
        if !referenced {
            self.mark_withheld(id);
        }
        self.head_inputs_changed(boundary_before);
        true
    }

    /// `selected_chain_len` is the anchor's DEPTH ON THE SELECTED CHAIN — the coordinate the positional index
    /// (`selected_chain`) addresses — never its blue score (AGENTS.md §6: two coordinate spaces under one name). On a
    /// width > 1 DAG a block's blue score counts merged blues too, so it is LARGER than its chain depth; installing the
    /// anchor at its blue score put it at one depth and the window re-entered below it at others (G1g-vi). A resume
    /// passes the depth its own checkpoint recorded (`NodeSnapshot::height`); a DSYNC adopt carries no anchor depth and
    /// passes the anchor's blue score as this node's ORIGIN — the index is positional relative to the tip, so only the
    /// span's coherence (`rederive_selected_chain_lens`) decides which block is on the chain. A depth above the blue
    /// score cannot exist (every selected-chain block is a blue in the anchor's past) and is refused like a lost weight.
    pub fn add_anchor(&mut self, block: Block, blue_work: u128, blue_score: u64, selected_chain_len: u64) -> bool {
        self.add_anchor_weighed(block, blue_work, blue_work, blue_score, selected_chain_len)
    }

    /// [`Self::add_anchor`] with the chain it stands for weighed apart from the anchor's own `blue_work`. A bundle from a fork this node does
    /// not hold is anchored tens of blocks below its tip, so the anchor's weight alone lost to this node's own tip even when the serving chain
    /// was heavier: the adopt installed the certified state while this DAG kept following its own fork, and the fold stopped with "the
    /// selected chain forked below this node's anchor" (MEASURED 2026-11-07, heal.py: anchor 109 against our tip 152, the serving tip 160).
    /// `chain_work` decides only whether the anchor wins; the anchor is stored with its own `blue_work`.
    pub fn add_anchor_weighed(&mut self, block: Block, blue_work: u128, chain_work: u128, blue_score: u64, selected_chain_len: u64) -> bool {
        let id = block.id();
        let boundary_before = self.window_boundary();
        if selected_chain_len > blue_score {
            return false;
        }
        if let Some(held) = self.blocks.get(&id) {
            // ⛔⛔ A-F80 (lane af58, 2026-11-16) — A RE-ANCHOR TO A BLOCK THIS DAG ALREADY HOLDS STILL RE-ANCHORS. The early
            // `return false` here made the adopt of a held anchor a no-op for the head: the node installed the certified state at
            // the anchor (`Node::adopt_sync_bundle`), its DAG kept following a head outside the anchor's future, the fold read
            // "the selected chain moved below this node's adopted floor", went stale and asked again — for ever, since the next
            // bundle's anchor was held too. MEASURED (af58's rig, 5b6d9720, net/evidence-af80-20261116/n0-node.log:3495-9526):
            // a restarted validator re-anchored 23 times, its head always its own a59f3313 (height 33, blue_work 129) while the
            // adopted anchors stood at 145..177 ("anchor in its past false · tips 2"). That the anchor was HELD in that run is
            // READ from "re-anchor adopt at blue_work N (ours N)", not yet logged by the door (the A-F80 diagnostic now does).
            // Same rule as a new anchor: only when it wins by the SAME weight test, and only when the head is not already in
            // its future (then nothing changes: `false`, as before). It becomes the floor (`anchor_floor`, so a tip outside its
            // future never outranks one inside it), and a tip when nothing held stands above it — a held block with children
            // already has a tip in its future, and the tip set never names a block that has children.
            // ROOT-LAYER: the one anchor door (adopt and resume both enter here).
            // BORROWED: Kaspa's pruning-point move — the new pruning point is the floor whether or not its block was already held.
            // AI RESISTANT: (a)+(b): the anchor reached here only through the join door's certificate (adopt) or this node's own
            //   snapshot (resume); a peer gains nothing it could not gain with a fresh anchor, which this door already installs.
            // SCALE: one descent walk inside the held window (`descends_from_finality_floor`), O(window), never of height or nodes.
            // cons: none beyond that walk, once per adopt of a held anchor.
            let head = self.selected_tip();
            let in_future = head.is_some_and(|h| h == id || self.descends_from_finality_floor(&h, &id));
            let wins = match head {
                Some(cur) => (chain_work, id) > (self.blocks[&cur].blue_work, cur),
                None => true,
            };
            if in_future || !wins {
                return false; // already the head's base, or our chain is at least as heavy
            }
            let leaf = held.children.is_empty();
            self.anchor_floor = Some(id);
            if leaf {
                self.tips.insert(id);
            }
            self.head_inputs_changed(boundary_before);
            return true;
        }
        let wins = match self.selected_tip() {
            Some(cur) => (chain_work, id) > (self.blocks[&cur].blue_work, cur),
            None => true,
        };
        if !wins {
            return false; // our chain is at least as heavy — do NOT follow the lighter adopted tip
        }
        // ⛔ DB-282 — THE ANCHOR IS THIS NODE'S SETTLED BASE FROM HERE ON. Every block held before it is either in its
        // past (the certified state counts it) or a side structure this node no longer follows; none is a parent a new
        // block may stand on ALONE. One pass over the held span (bounded by the DAG's constant keep window), once per
        // adopt or resume. A DAG that holds the anchor already never reaches here (`contains_key` above), so no block
        // in the anchor's future can be marked: an admitted descendant would have needed the anchor first.
        // ⛔⛔ A-F94 (lane speed5, 2026-11-17) — ONLY THE FIRST ANCHOR TURNS HELD BLOCKS INTO HISTORY. Before a node's first anchor
        // its DAG may be a crawl island (blocks admitted with no settled base, their blue data computed over a partial past), so
        // every one becomes history. After it, a block is `settled` only because it was carried or admitted with EVERY parent
        // settled (the rule above), so its blue data is exactly what a full node computes, and a later anchor cannot make it
        // less exact. Resetting it on every re-anchor turned the joiner's own admitted structure (side blocks at the tip's
        // level) into history: the next honest block merging one was refused `BelowSettledBase` / `MergesPreAnchorHistory`,
        // the joiner re-anchored onto another shallow fold root and lost its structure again. MEASURED (launch simulator, 2
        // seeds + 4 joiners): 8-11 re-adopts per joiner, refused parents at blue 173 against a settled top of 168-177, joiners
        // stopped at folds 191-195 against the seeds' 234; four patches of which blocks to settle left it in place.
        // ROOT-LAYER: the one anchor door (adopt and resume enter here). BORROWED: Kaspa moves the pruning point without
        // re-validating the headers it already holds above it.
        // AI RESISTANT: (a)/(b) — a settled block is one this node admitted by its own exact rule or one a certified carry
        //   bound; a peer gains nothing from a re-anchor that it could not gain from the first.
        // SCALE: removes a pass over the held window per re-anchor; nothing grows.
        // cons: none — a settled block keeps the flag the rule above gave it; islands are still turned to history once.
        if !self.settled_base {
            for n in self.blocks.values_mut() {
                n.settled = false;
            }
        }
        self.settled_base = true;
        let topo_order = self.topo_counter;
        self.topo_counter += 1;
        self.insert_block(
            id,
            BlockNode {
                header: block.header,
                tx_ids: block.tx_ids,
                children: Vec::new(),
                // Anchor: ancestry is certified by the decider proof, never replayed. `None` selected
                // parent marks it as a sync trust-root (a produced child references it as a real parent).
                selected_parent: None,
                blue_score,
                blue_work,
                selected_chain_len,
                topo_order,
                settled: true,
                chain_tags: None,
            },
        );
        // Reorg to the heavier adopted chain: it is now the SOLE selected tip. Our old (lighter) tips are
        // superseded; the block we produce next builds on this anchor and grafts on the peer → convergence. From here a
        // tip outside the anchor's future never outranks one inside it ([`Self::anchor_floor`]); a heavier certified
        // bundle re-anchors through this same door.
        self.tips.clear();
        self.tips.insert(id);
        self.anchor_floor = Some(id);
        self.head_inputs_changed(boundary_before);
        true
    }

    /// No-growth (O(1) DAG store): drop the DAG metadata for blocks buried deeper than a bounded
    /// pruning horizon below the selected tip, so `self.blocks` stays a CONSTANT-size recent window
    /// instead of the whole chain. This closes the "node slowly eats memory on every block" blowup:
    /// `add_block`/`add_anchor` used to insert one `BlockNode` per block and NEVER evict, so the map
    /// grew O(chain) at 1 block/s forever (a direct no-growth / O(1) violation).
    ///
    /// It is SOUND because GHOSTDAG never needs a pruned block: a new block's parents are current
    /// tips, and the mergeset / k-cluster coloring / DAA / MTP walks all stay within
    /// `merge_depth_cap` of the tip. Certified ancestry below the horizon lives in the O(1) frontier
    /// + decider (#106 frontier-persist / #29 DSYNC), never in this in-memory map; full block BODIES
    /// for serving live in the LMDB store, not here. Genesis and every live tip are ALWAYS kept.
    ///
    /// Horizon = `merge_depth_cap*2 + daa_sample_len + margin` blocks, derived from the LIVE governance
    /// params so it self-adjusts to a width / merge-depth retune with no restart. The sweep runs only
    /// once the window overflows a slack, so it is amortized O(1) per block — never an O(n) per-block
    /// scan (the fast-pillar way to bound memory).
    /// The span this DAG keeps below its tip, in blue score: `merge_depth_cap*2 + daa_sample_len + margin`,
    /// from the LIVE params. ONE definition, read by the in-memory prune, the on-disk block window
    /// (`crate::block_window`) and the restore that re-installs the window — so every node with the same
    /// params keeps the same span (Kaspa's pruning depth: a function of the params, never of one node).
    pub fn keep_depth(&self) -> u64 {
        (self.params.merge_depth_cap as u64)
            .saturating_mul(2)
            .saturating_add(self.params.daa_sample_len)
            .saturating_add(self.prune_keep_margin())
    }

    fn prune_keep_margin(&self) -> u64 {
        #[cfg(test)]
        if let Some((m, _)) = self.prune_override {
            return m;
        }
        Self::DAG_PRUNE_KEEP_MARGIN
    }

    fn prune_slack(&self) -> u64 {
        #[cfg(test)]
        if let Some((_, s)) = self.prune_override {
            return s;
        }
        Self::DAG_PRUNE_SLACK
    }

    #[cfg(test)]
    pub fn override_prune_bounds_for_test(&mut self, margin: u64, slack: u64) {
        self.prune_override = Some((margin, slack));
    }

    /// The horizon in blue score — the selected tip's score less `keep_depth` (0 near genesis). A block
    /// below it is outside the span every node keeps; the block window deletes it and the header door
    /// refuses to merge below the merge depth (see `Node::header_door_refusal`).
    pub fn horizon_blue_score(&self) -> u64 {
        match self.selected_tip() {
            Some(t) => self.blocks[&t].blue_score.saturating_sub(self.keep_depth()),
            None => 0,
        }
    }

    /// Re-link every non-genesis block whose `selected_parent` is unset but whose parents are all held —
    /// the checkpoint's anchor and the carried ancestors, once the block window has re-installed the span
    /// below them at restore. The selected parent is the parent with the highest order key, exactly the
    /// rule `add_block` applies to a live block; the selected-chain index is refreshed after. Runs once per
    /// restore over the held span (bounded by `keep_depth + DAG_PRUNE_SLACK`), never per block.
    pub fn relink_selected_parents(&mut self) -> usize {
        self.relink_selected_parents_except(&HashSet::new())
    }

    /// The held blocks with no selected-parent link, as the live DAG holds them (a checkpoint carries them: v65 `dag_unlinked`).
    pub fn unlinked_ids(&self) -> Vec<BlockId> {
        let mut v: Vec<BlockId> = self.unlinked.iter().copied().collect();
        v.sort_unstable();
        v
    }

    /// [`Self::relink_selected_parents`] leaving `keep` unlinked (a restore keeps what its live process held unlinked).
    pub fn relink_selected_parents_except(&mut self, keep: &HashSet<BlockId>) -> usize {
        // the unlinked set IS every held non-genesis block with no selected parent; ascending id, so every node relinks in
        // one order (cc9f167: HashMap order made two nodes walk differently)
        let mut candidates: Vec<BlockId> = self
            .unlinked
            .iter()
            .copied()
            .filter(|id| !keep.contains(id))
            .filter(|id| self.blocks.get(id).is_some_and(|n| n.header.parents.iter().all(|p| self.blocks.contains_key(p))))
            .collect();
        candidates.sort_unstable();
        let mut relinked = 0usize;
        for id in candidates {
            let Some(sp) = self
                .blocks
                .get(&id)
                .map(|n| n.header.parents.clone())
                .and_then(|ps| ps.into_iter().max_by(|a, b| self.order_key(a).cmp(&self.order_key(b))))
            else {
                continue;
            };
            if let Some(n) = self.blocks.get_mut(&id) {
                n.selected_parent = Some(sp);
            }
            self.unlinked.remove(&id);
            if let Some(pn) = self.blocks.get_mut(&sp) {
                if !pn.children.contains(&id) {
                    pn.children.push(id);
                }
            }
            relinked += 1;
        }
        if relinked > 0 {
            // ⛔ A FULL REBUILD, NOT THE INCREMENTAL REFRESH (2026-09-22 01:00, live joiner). A restore admits the
            // anchor first: `refresh_selected_chain_index` sizes the index to the anchor's depth, FILLS it with the
            // anchor id as a placeholder and stops at the anchor's missing parent. The window then re-enters the
            // span below and this relink restores the anchor's link — but every later block extends the index
            // incrementally and the placeholders below the anchor are never revisited. MEASURED: the joiner's
            // locator named 24 dense ids + the anchor + genesis ("1 of 33 locator id(s) held" on the origin, "asker's
            // past 1 block(s) above the floor", candidates 5,746), so every page restarted at the window floor with
            // blocks the asker already held, and its tip stayed frozen for 30 minutes. The relinked chain is walked
            // whole here — once per restore, bounded by the held span.
            self.rebuild_selected_chain_index();
        }
        relinked
    }

    /// The block window's QUANTIZED cut: `floor(horizon / keep_depth) * keep_depth` — the boundary the nullifier fold base
    /// steps on and the window deletes below (`Node::drain_folded_unfolded_blocks`). ONE definition, read by both, so the
    /// DAG's sweep and the window's cut can never name two different boundaries.
    pub fn window_boundary(&self) -> u64 {
        let span = self.keep_depth().max(1);
        (self.horizon_blue_score() / span).saturating_mul(span)
    }

    /// ⛔ G1 (lane b 2026-10-24, F2-red-found-20261024 "DAG prune len-gated") — THE SWEEP ALSO RUNS WHEN THE WINDOW'S
    /// BOUNDARY STEPS. Gated on length alone, the DAG kept blocks below the window's cut between sweeps (MEASURED,
    /// prune-2.log: live DAG 16 with scores 34, 35 under a window cut at 36), and a restart — which rebuilds the span from
    /// the window — could not hold them: two processes on one datadir, two DAGs. Sweeping once per boundary step as well
    /// keeps every held non-genesis, non-tip block at or above the window's cut, so the window covers the DAG and the
    /// restore rebuilds it whole. The cut is still the raw horizon (≥ the boundary), so the held span is the one the length
    /// gate already allowed. cons: none on any growth axis (the bound is unchanged); one extra sweep per `keep_depth` blue
    /// scores (one pass over the held span every 7,516 scores at the default params — amortized O(1) per block).
    /// The blue score the sweep must keep (see `prune_floor`); `None` lifts it.
    /// A-F114 phase 1: record the term `id` added to `A_tip` (its accept fold), on its window entry.
    pub fn set_chain_tags(&mut self, id: &BlockId, tags: std::sync::Arc<Vec<[u8; 32]>>) {
        if let Some(n) = self.blocks.get_mut(id) {
            n.chain_tags = Some(tags);
        }
    }

    pub fn set_prune_floor(&mut self, floor: Option<u64>) {
        self.prune_floor = floor;
    }

    /// ⛔ THE HEAD INDEX FOLLOWS EVERY CHANGE TO WHAT `selected_tip()` READS (lane stable 2026-11-02). `selected_tip` reads the
    /// tips, their work and the finality verdict — and the verdict reads whether the floor block is still HELD, so the prune
    /// sweep can move the head by dropping the floor (`finality_admits` (2)). `add_carried_block` and `add_anchor` changed the
    /// tips with no refresh, the other doors refreshed BEFORE the sweep, and `set_finality_floor` never did (probe C), so the
    /// positional index (`selected_chain`: `is_ancestor_of_selected_tip`, the tx-settlement predicate, and the relay view's
    /// on-chain flag) went on naming the abandoned head. MEASURED (launch tail, the reinstalled joiner at 1,800 s,
    /// `[restart-head]`): selected tip `68692d8a` at depth 792 with an index of length 792 — unindexed — while its restart's
    /// full rebuild indexed it (restart census `relay` CHANGED). Every head-moving mutation now ends here: refresh, sweep,
    /// refresh again (the second is the O(1) "already correct" read unless the sweep moved the head).
    /// cons: none — one O(1) index check per inserted block; a reorg walk only when the head really moved.
    fn head_inputs_changed(&mut self, boundary_before: u64) {
        self.refresh_selected_chain_index();
        self.prune_below_horizon(boundary_before);
        self.refresh_selected_chain_index();
    }

    fn prune_below_horizon(&mut self, boundary_before: u64) {
        let keep_depth = self.keep_depth();
        let boundary_stepped = self.window_boundary() > boundary_before;
        if (self.blocks.len() as u64) <= keep_depth + self.prune_slack() && !boundary_stepped {
            return; // neither past the slack nor across a window step — the sweep runs a constant number of times per block
        }
        let mut horizon = self.horizon_blue_score();
        if let Some(f) = self.prune_floor {
            horizon = horizon.min(f); // the fold anchor and everything above it stay (see `prune_floor`)
        }
        if horizon == 0 {
            return; // still within the first keep_depth blocks of genesis
        }
        let genesis = self.genesis;
        let tips = &self.tips;
        // Keep genesis, every live tip, and every block within `keep_depth` of the tip; drop the
        // rest. A kept block's children are strictly higher-scored (also kept), so no kept block is
        // left pointing at a pruned child; a kept block's selected_parent may fall just below the
        // horizon, which the ancestry walk tolerates (it stops at the first missing link).
        self.blocks
            .retain(|id, n| n.blue_score >= horizon || Some(*id) == genesis || tips.contains(id));
        let blocks = &self.blocks;
        self.by_receive.retain(|_, id| blocks.contains_key(id)); // DB-430: the receive index mirrors the store exactly
        self.unlinked.retain(|id| blocks.contains_key(id));
        self.withheld.retain(|id| blocks.contains_key(id)); // W1: the marks are pruned with their blocks
        self.withheld_future.retain(|id| blocks.contains_key(id));
        // An index entry may not outlive its block: rebuild the record-key index from the span that
        // SURVIVED. Rebuilding (rather than deleting per dropped id) is also what re-resolves a key whose
        // ambiguity the prune just removed. Same class as the retain it follows — one pass over a
        // span bounded by the fixed constants `keep_depth + DAG_PRUNE_SLACK`, run only behind the same
        // overflow test that gates this sweep, so the cost is f(those constants), never f(height).
        self.rebuild_record_key_index();
    }

    /// Re-point [`Self::selected_chain`] at the current virtual selected tip.
    ///
    /// The overwhelmingly common case is the tip advancing by ONE block, which is a single `push` — O(1). A
    /// reorg rewrites only the SUFFIX that actually diverged (it stops at the first depth already holding the
    /// right block), so the work is the size of the disagreement, never the length of the chain. Nothing here
    /// scales with height.
    /// Rebuild the selected-chain index by walking `selected_parent` links from the tip — no shortcuts, no
    /// placeholders trusted. Cost: the held span, once (a restore's relink; never per block).
    pub fn rebuild_selected_chain_index(&mut self) {
        self.selected_chain.clear();
        self.rederive_selected_chain_lens();
        let Some(tip) = self.selected_tip() else { return };
        let mut cur = Some(tip);
        let mut chain: Vec<BlockId> = Vec::new();
        while let Some(c) = cur {
            chain.push(c);
            cur = self.blocks.get(&c).and_then(|n| self.walk_parent(n)); // J20: through a trust-root anchor, as the refresh walks
        }
        chain.reverse();
        // the index is positional by depth: pad below the lowest linked block with that block so
        // `selected_chain[depth(tip)] == tip` still holds for the incremental refresh
        let depth = self.blocks.get(&tip).map(|n| n.selected_chain_len as usize).unwrap_or(0);
        if chain.len() < depth + 1 {
            let pad = chain[0];
            let mut padded = vec![pad; depth + 1 - chain.len()];
            padded.extend(chain);
            chain = padded;
        } else if chain.len() > depth + 1 {
            let extra = chain.len() - (depth + 1);
            chain.drain(0..extra);
        }
        self.selected_chain = chain;
    }

    /// ⭐ G1g-vi (lane a 2026-10-23) — ONE DEPTH COORDINATE ACROSS THE HELD SPAN. A block whose selected parent is not
    /// held when it enters (the window's lowest block at a resume, a carried ancestor) falls back to its BLUE SCORE as
    /// its depth, so after the restore relinks the span the window's blocks sat at blue-score depths and the anchor
    /// above them at its checkpointed depth: `selected_chain[n.selected_chain_len] == id` failed for every block below
    /// the anchor, and the restarted node named them off the selected chain where the live process named them on it
    /// (restart census `relay`, g1gv-restart-census-2-20261023.log, both nodes). Every depth is re-derived here from ONE
    /// fixed point — the selected tip, whose depth descends from the anchor's: down its held selected-parent walk each
    /// block is one less than its child, and every other held block whose selected parent is held is one more than that
    /// parent (ascending blue work is a topological order). Blocks whose selected parent is not held keep their depth.
    /// Cost: the held span, once, inside the full index rebuild (a restore's relink) — never per block.
    fn rederive_selected_chain_lens(&mut self) {
        let Some(tip) = self.selected_tip() else { return };
        let Some(tip_len) = self.blocks.get(&tip).map(|n| n.selected_chain_len) else { return };
        let mut on_chain: HashSet<BlockId> = HashSet::new();
        let mut cur = Some(tip);
        let mut len = tip_len;
        while let Some(c) = cur {
            let Some(n) = self.blocks.get_mut(&c) else { break };
            if !on_chain.insert(c) {
                break;
            }
            n.selected_chain_len = len;
            len = len.saturating_sub(1);
            let here = n.clone();
            cur = self.walk_parent(&here); // J20: through a trust-root anchor, as the refresh walks
        }
        let mut rest: Vec<(u128, BlockId)> = self
            .blocks
            .iter()
            .filter(|(id, _)| !on_chain.contains(*id))
            .map(|(id, n)| (n.blue_work, *id))
            .collect();
        rest.sort();
        for (_, id) in rest {
            let Some(sp) = self.blocks.get(&id).and_then(|n| n.selected_parent) else { continue };
            let Some(sp_len) = self.blocks.get(&sp).map(|n| n.selected_chain_len) else { continue };
            if let Some(n) = self.blocks.get_mut(&id) {
                n.selected_chain_len = sp_len + 1;
            }
        }
    }

    fn refresh_selected_chain_index(&mut self) {
        let Some(tip) = self.selected_tip() else {
            self.selected_chain.clear();
            return;
        };
        let depth = match self.blocks.get(&tip) {
            Some(n) => n.selected_chain_len as usize,
            None => return,
        };
        // Fast path: the new tip extends what we already have.
        if self.selected_chain.len() == depth && depth > 0 {
            if let Some(n) = self.blocks.get(&tip) {
                if n.selected_parent == self.selected_chain.last().copied() {
                    self.selected_chain.push(tip);
                    return;
                }
            }
        }
        if self.selected_chain.len() == depth + 1 && self.selected_chain.get(depth) == Some(&tip) {
            return; // already correct
        }
        // Reorg / first block: rewrite only the diverged suffix.
        if self.selected_chain.len() < depth + 1 {
            self.selected_chain.resize(depth + 1, tip);
        } else {
            self.selected_chain.truncate(depth + 1);
        }
        let mut cur = Some(tip);
        let mut d = depth as i64;
        let mut lowest = tip;
        while let Some(c) = cur {
            if d < 0 {
                break;
            }
            // J20: a PADDED entry (the same id repeated at the depth below — the fill a walk that ended in a gap left) is not an
            // agreement: the carried past may be held now, so the walk goes on through it and fills it with the real chain.
            let padded_below = d > 0 && self.selected_chain[(d - 1) as usize] == c;
            if self.selected_chain[d as usize] == c && (d as usize) < depth && !padded_below {
                break; // this depth already agrees — everything below it does too
            }
            self.selected_chain[d as usize] = c;
            // ⛔⛔ J20 (lane speed5, 2026-11-18, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J20) — THE INDEX CROSSES AN ANCHOR, AND THE DEPTH IT
            // WRITES IS THE BLOCK'S. An anchor enters with no selected parent (a sync trust root), so this walk ended there and
            // every chain block a joiner holds under its anchor read "not on the selected chain" (the relay view's flag, and
            // `is_ancestor_of_selected_tip`, the tx-settlement predicate). MEASURED (replica census, main ac55b638 + J19): the same
            // 261 blocks with the same blue data on all three nodes, the on-chain flag true on both seeds and false on the joiner
            // for the chain blocks at blue scores 40-47. The walk steps through a trust root by its heaviest held parent (G4's
            // `walk_parent`; the carry holds the anchor's past with blue data A-F97 checks), and the block's `selected_chain_len`
            // is set to the depth it fills, so one coordinate names it whichever origin its length was first written from.
            // AI RESISTANT: (b) code; nothing admitted or refused — an index of blocks this node already holds and verified.
            // SCALE: the walk's own steps (the diverged suffix, or the held span once after an anchor); nothing grows.
            // cons: one write per walked block (the same walk already writes the index entry).
            if let Some(n) = self.blocks.get_mut(&c) {
                n.selected_chain_len = d as u64;
            }
            lowest = c;
            cur = self.blocks.get(&c).and_then(|n| self.walk_parent(n));
            d -= 1;
        }
        // ⛔ THE WALK LEFT THE HELD DAG — a selected parent this node does not hold: a DSYNC anchor (`add_anchor`, whose
        // ancestry is certified, never held) or the gap a certified jump leaves below it. Every depth below the lowest
        // linked block is UNKNOWN on this node, and it is padded with that block exactly as the full rebuild
        // (`rebuild_selected_chain_index`) pads, so no entry left by the PREVIOUS chain answers for the new one.
        // ROOT-LAYER: this is the one writer of the index every O(1) ancestry read takes (`is_ancestor_of_selected_tip` —
        // the live tx-settlement predicate — and `dag_recent_view`'s on-chain flag); a reader-side check would leave the
        // stale entries in place for the others.
        // MEASURED sim-20261008-011738 (fast journey T1.6, the joiner took the DB-99 certified jump to height 530 after
        // grafting to ~score 310): at t=1020 s n2 named d531e145 (born n0 t=590 s) at blue score 302 while n0 named
        // 2154c682 — identical GHOSTDAG data for both siblings on both nodes, n2's head chain walked down only to its
        // anchor, and the depths below kept the branch n2 had selected BEFORE the jump (equal blue work, the id
        // tie-break). Pin: `two_nodes_adopting_one_anchor_name_one_head_chain_whatever_either_held_before` (RED before).
        // MUST-STAY-GREEN: probes B and C, the finality-bound pins, the block-locator pins, the fast + ecosystem journeys.
        // cons: one O(depth) fill when a head's walk ends in a gap (32 B × depth, once per anchor install or gap reorg —
        // the same order as the `resize` above); never on the one-block fast path.
        if cur.is_none() && d >= 0 {
            for e in &mut self.selected_chain[..=d as usize] {
                *e = lowest;
            }
        }
    }

    /// Steps the last ancestry answer took. O(1) means this is the SAME number at height 10 and 10^6.
    pub fn last_ancestry_steps(&self) -> u64 {
        self.last_ancestry_steps.get()
    }

    /// ⭐ Is `a` an ancestor of the CURRENT virtual selected tip, along the selected-parent chain? **O(1).**
    ///
    /// This is the question the live tx-ingest path actually asks (`blk == tip || ancestor(blk, tip)`), and it
    /// used to be answered by walking every selected parent from the tip back — O(selected-depth), i.e. a cost
    /// that grows forever with the chain, on the path every single spend takes.
    ///
    /// The indexed answer is exact rather than approximate: the tip is on the selected chain by definition, so
    /// `a` is an ancestor of it iff `a` sits at its own depth in that chain. Two map reads, no walk, identical
    /// work at any height.
    pub fn is_ancestor_of_selected_tip(&self, a: &BlockId) -> bool {
        self.last_ancestry_steps.set(0);
        let Some(node) = self.blocks.get(a) else {
            return false;
        };
        self.last_ancestry_steps.set(1);
        let d = node.selected_chain_len as usize;
        matches!(self.selected_chain.get(d), Some(at_depth) if at_depth == a)
    }

    /// G13 — which of `targets` are `from` itself or lie in its past (parents, transitively): Kaspa's "merged" question, the
    /// one a mempool asks before returning a block's txs. One backward walk that never descends below the oldest target's
    /// `topo_order` (a parent is always older than its child, so no path to a target passes below it): it visits only the
    /// blocks inserted since the oldest target, never the DAG's history, and stops once every target is found.
    pub fn which_in_past_of(&self, from: &BlockId, targets: &[BlockId]) -> std::collections::HashSet<BlockId> {
        let want: std::collections::HashSet<BlockId> = targets.iter().copied().collect();
        let floor = targets.iter().filter_map(|t| self.blocks.get(t)).map(|n| n.topo_order).min();
        let mut found = std::collections::HashSet::new();
        let Some(floor) = floor else {
            return found;
        };
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![*from];
        while let Some(b) = stack.pop() {
            if found.len() == want.len() {
                break;
            }
            if !seen.insert(b) {
                continue;
            }
            let Some(n) = self.blocks.get(&b) else { continue };
            if n.topo_order < floor {
                continue;
            }
            if want.contains(&b) {
                found.insert(b);
            }
            stack.extend(n.header.parents.iter().copied());
        }
        found
    }

    /// Is `a` an ancestor of `b` along the selected-parent chain? Correct, and O(selected-depth) — used only by
    /// tests and off-hot-path callers. The LIVE ingest path asks about the TIP and uses the O(1)
    /// [`Self::is_ancestor_of_selected_tip`] above instead.
    pub fn is_selected_chain_ancestor(&self, a: &BlockId, b: &BlockId) -> bool {
        let mut cur = Some(*b);
        while let Some(c) = cur {
            if c == *a {
                return true;
            }
            cur = self.blocks.get(&c).and_then(|n| n.selected_parent);
        }
        false
    }
}

impl Default for Dag {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader, BlockId};
    use crate::hash::Hash32;
    use crate::params::ChainParams;

    // A distinct-per-nonce header (nonce differentiates otherwise-identical blocks => distinct id).
    fn hdr(parents: Vec<BlockId>, nonce: u64) -> BlockHeader {
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
            timestamp: nonce,
            nonce,
            work: 100, // a real, uniform per-block work for the test; production sets it via the DAA
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::ZERO,
            frontier_root: Hash32::ZERO,
            nullifier_root: Hash32::ZERO,
            sparse_root: Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::ZERO,
            account_root: Hash32::ZERO,
        }
    }
    fn blk(parents: Vec<BlockId>, nonce: u64) -> Block {
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: hdr(parents, nonce),
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
        }
    }
    // Variable per-block DAA work — lets a test drive `blue_work` and `blue_score` APART (a short heavy
    // chain vs a long light one), the exact condition under which the two keys can order tips differently.
    fn blk_w(parents: Vec<BlockId>, nonce: u64, work: u128) -> Block {
        let mut h = hdr(parents, nonce);
        h.work = work;
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: h,
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
        }
    }

    /// ⭐ SPEED L6 — THE FOLD DEPTH COVERS TWO RELAY ROUNDS AT THE CHAIN'S OWN SPACING, BETWEEN `FOLD_DEPTH_MIN` AND THE
    /// PARAMETER. The rule is pinned at each boundary, against hostile spacings (timestamps bunched to 0 or 1 ms can only
    /// reach the parameter, today's depth; an hour-long spacing can only reach the minimum), and the measure is pinned as
    /// a function of the DAG: a young chain has none, a chain block's spacing is its header timestamps', and a block OFF
    /// the selected chain — whatever its timestamp — does not move it.
    /// TWO-PARTY-REVIEWED: both readings here are one DAG's. The cross-node claim (two nodes with the same DAG cut the same
    /// fold root at every ordinal) is the same function applied to the same DAG, exercised on real nodes by pay / change /
    /// double-spend with the lever on (`scratchpad/speed/screen.py`), where a differing root would show as a fold conflict.
    #[test]
    fn speed_l6_the_fold_depth_covers_two_relay_rounds_at_the_chains_own_spacing_and_never_exceeds_the_parameter() {
        let t = FOLD_SETTLE_MS;
        assert_eq!(fold_depth_for(4, None), 4, "no measured spacing: the parameter");
        assert_eq!(fold_depth_for(0, Some(1)), 0, "a fixture folding at the tip stays at the tip");
        assert_eq!(fold_depth_for(1, Some(3_600_000)), 1, "a parameter under the minimum is kept");
        assert_eq!(fold_depth_for(4, Some(3_600_000)), FOLD_DEPTH_MIN, "⛔ a very slow chain folded shallower than the minimum");
        assert_eq!(fold_depth_for(4, Some(t)), FOLD_DEPTH_MIN, "one step already covers the settle time: the minimum");
        assert_eq!(fold_depth_for(4, Some(t / 2)), 2, "two steps cover it exactly");
        assert_eq!(fold_depth_for(4, Some(t / 2 - 1)), 3, "⛔ two steps one millisecond short of the settle time were taken as enough");
        assert_eq!(fold_depth_for(4, Some(t / 3 - 1)), 4);
        assert_eq!(fold_depth_for(4, Some(1)), 4, "⛔ bunched timestamps pushed the depth past the parameter");
        assert_eq!(fold_depth_for(4, Some(0)), 4, "⛔ a zero spacing pushed the depth past the parameter");
        assert_eq!(fold_depth_for(32, Some(500)), t.div_ceil(500), "a deeper parameter lets the depth grow with the rate");
        assert_eq!(fold_depth_for(8, Some(500)), 8, "…and never past the parameter");

        // the measure: a chain block every 5,000 ms (a header's timestamp is its nonce in this fixture)
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let mut chain = vec![g];
        for i in 1..=6u64 {
            chain.push(dag.add_block(blk(vec![*chain.last().unwrap()], 5_000 * i)).unwrap());
        }
        assert_eq!(dag.chain_step_ms(chain.last().unwrap()), None, "seven chain blocks are not yet a measure");
        chain.push(dag.add_block(blk(vec![*chain.last().unwrap()], 5_000 * 7)).unwrap());
        assert_eq!(dag.chain_step_ms(chain.last().unwrap()), Some(5_000), "eight chain blocks, 5,000 ms apart");
        for i in 8..=40u64 {
            chain.push(dag.add_block(blk(vec![*chain.last().unwrap()], 5_000 * i)).unwrap());
        }
        let tip = *chain.last().unwrap();
        assert_eq!(dag.chain_step_ms(&tip), Some(5_000), "the last 32 chain blocks, 5,000 ms apart");
        assert_eq!(fold_depth_for(4, dag.chain_step_ms(&tip)), 2, "9,260 ms at 5,000 ms a step is two steps");
        // a block off the selected chain, with a timestamp a year away, moves nothing
        let _side = dag.add_block(blk(vec![chain[10]], 31_536_000_000)).unwrap();
        assert_eq!(dag.chain_step_ms(&tip), Some(5_000), "⛔ a block off the selected chain moved the chain's measured spacing");
        // one chain block stamped a minute late stretches the mean by 60 s over 31 steps and no further; the depth it
        // yields stays within the two bounds
        let late = dag.add_block(blk(vec![tip], 5_000 * 41 + 60_000)).unwrap();
        let skewed = dag.chain_step_ms(&late).expect("a measure");
        assert_eq!(skewed, (5_000 * 31 + 60_000) / 31, "the span over the steps");
        assert!((FOLD_DEPTH_MIN..=4).contains(&fold_depth_for(4, Some(skewed))));
    }

    #[test]
    fn genesis_then_width2_merge_true_blue_score() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        assert_eq!(dag.genesis(), Some(g));
        assert_eq!(dag.tips(), vec![g]);
        assert_eq!(dag.get(&g).unwrap().blue_score, 0);
        assert_eq!(dag.get(&g).unwrap().blue_work, 0);

        let a = dag.add_block(blk(vec![g], 1)).unwrap();
        let b = dag.add_block(blk(vec![g], 2)).unwrap();
        assert_ne!(a, b);
        let mut tips = dag.tips();
        tips.sort();
        let mut ab = vec![a, b];
        ab.sort();
        assert_eq!(tips, ab, "both parallel blocks are tips");
        assert_eq!(dag.get(&a).unwrap().blue_score, 1);
        assert_eq!(dag.get(&a).unwrap().blue_work, 100);
        assert_eq!(dag.get(&a).unwrap().selected_chain_len, 1);

        let c = dag.add_block(blk(vec![a, b], 3)).unwrap();
        assert_eq!(dag.tips(), vec![c], "c merges both => sole tip");
        assert_eq!(dag.selected_tip(), Some(c));
        assert_eq!(dag.get(&c).unwrap().blue_score, 3);
        assert_eq!(dag.get(&c).unwrap().blue_work, 300);
        assert_eq!(dag.get(&c).unwrap().selected_chain_len, 2);

        assert!(dag.is_selected_chain_ancestor(&g, &c));
        assert!(!dag.is_selected_chain_ancestor(&c, &g));
        let expect_sp = if a > b { a } else { b };
        assert_eq!(dag.get(&c).unwrap().selected_parent, Some(expect_sp));
    }

    // #152 SOUNDNESS: the effective-ledger canonical order MUST agree with the adopted selected chain,
    // EVEN under variable difficulty where `blue_work` (accumulated work) and `blue_score` (blue-block
    // COUNT) order two concurrent tips OPPOSITELY. If they disagreed, the nullifier/output resolver could
    // prune a spend whose OUTPUTS the wholesale-adopted selected-tip frontier still carries → inflation.
    // canonical_order now keys on `order_key` = `(blue_work, id)`, the SAME key selected_tip/add_anchor use.
    #[test]
    fn canonical_order_agrees_with_selected_tip_under_variable_difficulty() {
        let mut dag = Dag::new();
        // Genesis carries work 1 (real headers always have positive PoUW work) — so `blue_work` is STRICTLY
        // monotone ancestor→descendant (a block's blue_work sums its blue ANCESTORS' work incl. genesis's,
        // excluding its own), which is what keeps `(blue_work, id)` a valid topological order.
        let g = dag.add_block(blk_w(vec![], 0, 1)).unwrap();
        // Chain P: THREE light blocks (work 1 each) → blue_score 3, blue_work 3.
        let p1 = dag.add_block(blk_w(vec![g], 1, 1)).unwrap();
        let p2 = dag.add_block(blk_w(vec![p1], 2, 1)).unwrap();
        let p3 = dag.add_block(blk_w(vec![p2], 3, 1)).unwrap();
        // Chain Q: TWO heavy blocks (work 100 each), concurrent with P → blue_score 2, blue_work 101.
        let q1 = dag.add_block(blk_w(vec![g], 4, 100)).unwrap();
        let q2 = dag.add_block(blk_w(vec![q1], 5, 100)).unwrap();

        // The two keys order the tips OPPOSITELY — the variable-difficulty divergence that made the
        // old `(blue_score,id)` canonical_order unsound: MORE blocks but LESS work vs FEWER but HEAVIER.
        assert!(
            dag.get(&p3).unwrap().blue_score > dag.get(&q2).unwrap().blue_score,
            "p3 has MORE blue blocks (higher blue_score)"
        );
        assert!(
            dag.get(&p3).unwrap().blue_work < dag.get(&q2).unwrap().blue_work,
            "but q2 has MORE accumulated WORK (higher blue_work)"
        );

        // selected_tip follows blue_work (heaviest chain) = q2: the frontier a node ADOPTS is q2's chain.
        assert_eq!(dag.selected_tip(), Some(q2));
        // THE INVARIANT the unification pins: the LAST block in canonical_order == selected_tip. Under the
        // OLD (blue_score,id) key the last would be p3 ≠ q2 — the resolver would disagree with the adopted
        // chain. Now they agree, so a pruned (non-selected) block's outputs are never in the adopted frontier.
        let order = dag.canonical_order();
        assert_eq!(
            order.last().copied(),
            Some(q2),
            "effective-ledger canonical head == adopted selected tip (consistent under variable difficulty)"
        );
        // Ancestor-before-descendant still holds (blue_work is strictly monotone along a chain).
        assert_eq!(
            order.first().copied(),
            Some(g),
            "genesis first (lowest blue_work)"
        );
        let pos = |x: &BlockId| order.iter().position(|y| y == x).unwrap();
        assert!(
            pos(&g) < pos(&p1) && pos(&p1) < pos(&p2) && pos(&p2) < pos(&p3),
            "P chain: ancestor before descendant"
        );
        assert!(
            pos(&g) < pos(&q1) && pos(&q1) < pos(&q2),
            "Q chain: ancestor before descendant"
        );
    }

    #[test]
    fn k_cluster_colors_beyond_k_red() {
        // A clique of (k+2) mutually-parallel blocks on genesis: the max k-cluster is (k+1) blue,
        // so exactly one must be colored red. k is the active governance-tunable value.
        let k = ChainParams::default().ghostdag_k;
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let n = k + 2;
        let mut parallel = Vec::new();
        for i in 1..=n {
            parallel.push(dag.add_block(blk(vec![g], i)).unwrap());
        }
        let gd = dag.ghostdag_data(&parallel);
        assert_eq!(
            gd.mergeset_blues.len() as u64,
            k + 1,
            "a clique of k+2 admits exactly k+1 blues"
        );
        assert_eq!(gd.mergeset_reds.len(), 1, "exactly one block is red");
        assert_eq!(gd.blue_score, 1 + (k + 1));
    }

    #[test]
    fn dag_width_32_full_level_grafts_merges_and_canonical_orders() {
        // ⭐ DAG-WIDTH-32 CARDINAL (user 2026-07-20: "the dag width is 32 by default; we will never have below 32").
        // A FULL width-32 level — 32 mutually-parallel blocks off a common tip — must all graft + be live tips, the
        // virtual block over them must color ALL 32 (mergeset width 32), a merge block must reference all 32, and the
        // canonical order must be a DETERMINISTIC total order over every block. This proves the width-32 envelope the
        // 500ms cadence + per-block nullifier re-derive rely on: a 32-wide mergeset never inflates the per-block
        // advance (each block advances the acc by its OWN 256, independent of how many parents it merges).
        assert_eq!(
            ChainParams::default().dag_width,
            32,
            "the DAG width default + floor is 32"
        );
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let mut level: Vec<BlockId> = Vec::new();
        for i in 1..=32u64 {
            level.push(dag.add_block(blk(vec![g], i)).unwrap());
        }
        assert_eq!(level.len(), 32, "all 32 width-32 siblings graft");
        let mut tips = dag.tips();
        tips.sort();
        let mut want = level.clone();
        want.sort();
        assert_eq!(
            tips, want,
            "the full width-32 level are all live parallel tips (none pruned/serialized)"
        );
        // The virtual block over the 32-wide level colors ALL 32 (blues + reds) — full width admitted, not capped.
        let gd = dag.ghostdag_data(&level);
        assert_eq!(
            gd.mergeset_blues.len() + gd.mergeset_reds.len(),
            32,
            "the virtual block over the width-32 level colors every one of the 32 (full width, no cap below 32)"
        );
        // A merge block referencing all 32 parents grafts (the parent set admits width 32).
        let merge = dag.add_block(blk(level.clone(), 1000)).unwrap();
        let order = dag.canonical_order();
        assert_eq!(
            order.len(),
            34,
            "canonical order totals every block (genesis + 32 + merge) at width 32"
        );
        assert_eq!(order[0], g, "genesis orders first");
        assert_eq!(*order.last().unwrap(), merge, "the merge tip orders last");
        assert_eq!(
            dag.canonical_order(),
            order,
            "canonical order is DETERMINISTIC (receive-independent) over the full width-32 level"
        );
    }

    #[test]
    fn rejects_duplicate_missing_parent_and_second_genesis() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        assert_eq!(
            dag.add_block(blk(vec![], 0)).unwrap_err(),
            DagError::Duplicate(g)
        );
        assert!(matches!(
            dag.add_block(blk(vec![], 9)).unwrap_err(),
            DagError::SecondGenesis
        ));
        let fake = Hash32::hash(b"nonexistent-parent");
        assert_eq!(
            dag.add_block(blk(vec![fake], 5)).unwrap_err(),
            DagError::MissingParent(fake)
        );
    }

    /// DB-361 fixture: genesis, a 10-block main chain c1..c10 (score 1..10), and the ids.
    fn db361_chain(dag: &mut Dag) -> (BlockId, Vec<BlockId>) {
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let mut c = vec![g];
        for i in 1..=10u64 {
            let next = dag.add_block(blk(vec![*c.last().unwrap()], i)).unwrap();
            c.push(next);
        }
        (g, c)
    }

    fn db361_params(merge_depth: usize) -> ChainParams {
        let mut p = ChainParams::default();
        p.merge_depth_cap = merge_depth;
        p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
        p
    }

    /// ⛔ DB-361 PIN 1 — a block that merges a side block forked below its merge depth is INVALID on every node,
    /// whatever order the node received the side block in. CALIBRATION: the SAME construction under the release
    /// depth (3,600, which this 12-score chain cannot reach) is admitted — only the depth decides.
    #[test]
    fn db361_a_block_merging_a_side_block_below_its_merge_depth_is_refused_on_every_node() {
        for side_first in [true, false] {
            let mut dag = Dag::with_params(db361_params(5));
            let g = dag.add_block(blk(vec![], 0)).unwrap();
            let side = blk(vec![g], 1_000); // forked at genesis: score 1
            let side_id = side.id();
            if side_first {
                dag.add_block(side.clone()).unwrap();
            }
            let mut tip = g;
            for i in 1..=10u64 {
                tip = dag.add_block(blk(vec![tip], i)).unwrap();
            }
            if !side_first {
                dag.add_block(side.clone()).unwrap();
            }
            let late = blk(vec![tip, side_id], 2_000); // score 12, floor 7; the side block's chain meets at 0
            let late_id = late.id();
            match dag.add_block(late) {
                Err(DagError::ViolatesMergeDepth(id)) => assert_eq!(id, late_id, "the refusal names the block"),
                other => panic!("⛔ DB-361: a late merge below the merge depth was not refused (side_first={side_first}): {other:?}"),
            }
            assert!(dag.get(&late_id).is_none(), "⛔ DB-361: the refused block is held");
            assert!(dag.template_parents().iter().all(|p| *p != side_id), "⛔ DB-361: the template still merges it");
        }
        // CALIBRATION — the attack is armed: the same late merge under the release depth is admitted.
        let mut open = Dag::with_params(db361_params(crate::params::MERGE_DEPTH_CAP_DEFAULT));
        let g = open.add_block(blk(vec![], 0)).unwrap();
        let side = open.add_block(blk(vec![g], 1_000)).unwrap();
        let mut tip = g;
        for i in 1..=10u64 {
            tip = open.add_block(blk(vec![tip], i)).unwrap();
        }
        assert!(open.add_block(blk(vec![tip, side], 2_000)).is_ok(), "calibration: within the release depth it is admitted");
    }

    /// DB-361 PIN 2 — the boundary: a side block whose chain meets at the floor is admitted, one below is refused.
    #[test]
    fn db361_a_side_block_meeting_the_chain_at_the_floor_is_admitted_and_one_below_is_refused() {
        let mut dag = Dag::with_params(db361_params(5));
        let (_g, c) = db361_chain(&mut dag);
        // A merging block on c10 plus one sibling has score 12, so its floor is 7.
        let at_floor = dag.add_block(blk(vec![c[7]], 3_000)).unwrap(); // meets the chain at c7 (score 7)
        let below = dag.add_block(blk(vec![c[6]], 3_001)).unwrap(); // meets the chain at c6 (score 6)
        assert!(dag.add_block(blk(vec![c[10], at_floor], 3_002)).is_ok(), "⛔ DB-361: a merge AT the floor was refused");
        let mut dag2 = Dag::with_params(db361_params(5));
        let (_g2, c2) = db361_chain(&mut dag2);
        let below2 = dag2.add_block(blk(vec![c2[6]], 3_001)).unwrap();
        assert_eq!(below, below2, "premise: the same block on both DAGs");
        assert!(
            matches!(dag2.add_block(blk(vec![c2[10], below2], 3_003)), Err(DagError::ViolatesMergeDepth(_))),
            "⛔ DB-361: a merge one below the floor was admitted"
        );
    }

    /// ⛔ DB-361 PIN 3 (§8(b)) — the template drops ONLY the violating tip and keeps every valid sibling; the block it
    /// builds is admitted by a second DAG. Dropping the whole set would let one attacker tip collapse DAG width to 1.
    #[test]
    fn db361_the_template_drops_only_the_violating_tip_and_a_second_dag_admits_its_block() {
        let build = || {
            let mut dag = Dag::with_params(db361_params(5));
            let (g, c) = db361_chain(&mut dag);
            let bad = dag.add_block(blk(vec![g], 4_000)).unwrap(); // forked at genesis: violates from c10
            let good_a = dag.add_block(blk(vec![c[9]], 4_001)).unwrap(); // sibling of c10
            let good_b = dag.add_block(blk(vec![c[8]], 4_002)).unwrap(); // forked at c8
            (dag, c[10], bad, good_a, good_b)
        };
        let (dag, tip, bad, good_a, good_b) = build();
        let parents = dag.template_parents();
        // c10 and good_a tie on blue work (both one block on c9), so the id decides which one is selected.
        let selected = dag.selected_tip().expect("a selected tip");
        assert_eq!(parents.first(), Some(&selected), "the selected tip leads the template");
        assert!(!parents.contains(&bad), "⛔ DB-361: the violating tip was merged");
        assert!(
            [tip, good_a, good_b].iter().all(|t| parents.contains(t)),
            "⛔ DB-361 §8(b): a valid sibling was dropped with the violating tip ({parents:?})"
        );
        let (mut peer, ..) = build();
        assert!(peer.add_block(blk(parents, 4_100)).is_ok(), "⛔ DB-361: a second DAG refused the template's block");
        // CALIBRATION: every tip as a parent (the pre-DB-361 template) builds a block every node now refuses.
        let (mut peer2, ..) = build();
        let all = dag.tips();
        assert!(all.contains(&bad), "premise: the violating block is a tip");
        assert!(matches!(peer2.add_block(blk(all, 4_101)), Err(DagError::ViolatesMergeDepth(_))));
    }

    /// A bundle from a heavier fork whose anchor alone weighs less than this node's tip: weighed by its chain, the anchor wins, the old
    /// fork's tips are dropped and the anchor is the head; weighed by the anchor alone (the old rule, `add_anchor`) it loses and this DAG
    /// keeps following its own fork, the heal.py stall of 2026-11-07.
    #[test]
    fn a_heavier_forks_anchor_wins_by_its_chain_not_its_own_weight() {
        let build = || {
            let mut dag = Dag::new();
            let mut p = dag.add_block(blk(vec![], 0)).unwrap();
            for i in 1..6u64 {
                p = dag.add_block(blk(vec![p], i)).unwrap();
            }
            let ours = dag.get(&p).map(|n| n.blue_work).unwrap();
            (dag, p, ours)
        };
        let (mut weighed, own_tip, ours) = build();
        let anchor = blk(vec![Hash32::hash(b"heavier-fork-parent")], 900);
        let a = anchor.id();
        assert!(weighed.add_anchor_weighed(anchor.clone(), ours - 1, ours + 1, 3, 3), "the heavier chain's anchor installs");
        assert_eq!(weighed.selected_tip(), Some(a), "the anchor is the head");
        assert!(!weighed.tips().contains(&own_tip), "the old fork's tip is no longer followed");
        assert_eq!(weighed.get(&a).map(|n| n.blue_work), Some(ours - 1), "the anchor keeps its own weight");
        // CALIBRATION: by the anchor's weight alone it loses, and the old fork stays the head.
        let (mut alone, own_tip, ours) = build();
        assert!(!alone.add_anchor(anchor, ours - 1, 3, 3), "by its own weight the anchor loses");
        assert_eq!(alone.selected_tip(), Some(own_tip));
    }

    /// A-F80: a certified anchor this DAG ALREADY HOLDS on a side branch re-anchors the head exactly as a fresh one does — and a
    /// lighter one, or one the head already stands on, changes nothing. CALIBRATION: before the fix the held anchor returned
    /// `false` at once and the head stayed on its own branch (the 23-re-anchor loop of evidence-af80-20261116).
    #[test]
    fn af80_a_held_anchor_off_the_heads_chain_re_anchors_the_head() {
        // g → c1 → c2 → c3 is this node's own branch (the head); s1 = blk([c1], 40) is the peer's block, held on a side branch
        let build = || {
            let mut dag = Dag::new();
            let g = dag.add_block(blk(vec![], 0)).unwrap();
            let c1 = dag.add_block(blk(vec![g], 1)).unwrap();
            let c2 = dag.add_block(blk(vec![c1], 2)).unwrap();
            let c3 = dag.add_block(blk(vec![c2], 3)).unwrap();
            let s1 = dag.add_block(blk(vec![c1], 40)).unwrap();
            let ours = dag.get(&c3).map(|n| n.blue_work).unwrap();
            (dag, c1, c3, s1, ours)
        };
        // a held LEAF anchor that wins by the chain it stands for becomes the head
        let (mut dag, c1, own, s1, ours) = build();
        assert_eq!(dag.selected_tip(), Some(own), "premise: the head is this node's own branch");
        assert!(dag.add_anchor_weighed(blk(vec![c1], 40), 1, ours + 1, 2, 2), "⛔ A-F80: the held anchor did not re-anchor");
        assert_eq!(dag.selected_tip(), Some(s1), "⛔ A-F80: the head stayed off the certified anchor's chain");
        // a held anchor WITH a child: the head is the tip in its future, and the anchor is never put in the tip set
        let (mut dag, c1, _, s1, ours) = build();
        let s2 = dag.add_block(blk(vec![s1], 41)).unwrap();
        assert!(dag.add_anchor_weighed(blk(vec![c1], 40), 1, ours + 1, 2, 2));
        assert_eq!(dag.selected_tip(), Some(s2), "the head is the held tip above the anchor");
        assert!(!dag.tips().contains(&s1), "a block with children is never a tip");
        // CALIBRATION: lighter by its chain, the held anchor changes nothing
        let (mut dag, c1, own, _, ours) = build();
        assert!(!dag.add_anchor_weighed(blk(vec![c1], 40), 1, ours - 1, 2, 2), "a lighter held anchor installs nothing");
        assert_eq!(dag.selected_tip(), Some(own));
        // and an anchor the head already stands on changes nothing
        let (mut dag, c1, own, _, _) = build();
        let g = dag.get(&c1).and_then(|n| n.selected_parent).unwrap();
        assert!(!dag.add_anchor_weighed(blk(vec![g], 1), 1, u128::MAX, 1, 1), "the head's own base changes nothing");
        assert_eq!(dag.selected_tip(), Some(own));
    }

    /// The eclipse loop (eclipse.py, 2026-11-08): after an adopt, a side branch the anchor's own mergeset settled is extended
    /// by a peer and outweighs the anchor before the honest blocks above it arrive. The head stays in the anchor's future.
    /// CALIBRATION: the side tip carries more work than the anchor, so a work-only choice (the old rule) made it the head.
    #[test]
    fn after_an_adopt_a_heavier_side_branch_outside_the_anchors_future_is_never_head() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let c1 = dag.add_block(blk(vec![g], 1)).unwrap();
        let c2 = dag.add_block(blk(vec![c1], 2)).unwrap();
        let c3 = dag.add_block(blk(vec![c2], 3)).unwrap();
        let s1 = dag.add_block(blk(vec![c1], 4)).unwrap(); // a side block the anchor merges
        let ours = dag.get(&dag.selected_tip().unwrap()).map(|n| n.blue_work).unwrap();
        let anchor = blk(vec![c3, s1], 5);
        let a = anchor.id();
        assert!(dag.add_anchor_weighed(anchor, 1, ours + 1, 4, 4), "the certified anchor installs");
        dag.settle_connected_past(&a);
        let mut side = s1;
        for i in 0..6u64 {
            side = dag.add_block(blk(vec![side], 10 + i)).expect("the settled side branch keeps growing");
        }
        let side_work = dag.get(&side).map(|n| n.blue_work).unwrap();
        assert!(side_work > 1, "CALIBRATION: the side tip outweighs the anchor, so work alone would make it head");
        assert_eq!(dag.selected_tip(), Some(a), "⛔ a tip outside the anchor's future became head");
        let y = dag.add_block(blk(vec![a], 30)).expect("a block on the anchor");
        assert_eq!(dag.selected_tip(), Some(y), "the anchor's future leads, whatever the side branch weighs");
    }

    /// DB-361 PIN 4 — a walk that leaves a jumper's held DAG is NEVER read as admitted: the block is refused as
    /// pre-anchor history (the caller re-anchors). CALIBRATION: under the release depth the floor is 0 and it enters.
    #[test]
    fn db361_a_walk_that_leaves_a_jumpers_held_dag_refuses_as_pre_anchor_history_never_admits() {
        let jumper = |depth: usize| {
            let mut dag = Dag::with_params(db361_params(depth));
            dag.add_block(blk(vec![], 0)).unwrap();
            let deep = hdr(vec![Hash32::hash(b"db361-absent-a")], 60);
            let deep_id = deep.id();
            // blue scores under `MERGEABLE_DEPTH`, so the release depth's floor is 0 (the calibration below)
            assert!(dag.add_ancestor_anchor(deep, vec![], 500_000, 30, None), "a carried ancestor installs");
            let anchor = blk(vec![Hash32::hash(b"db361-absent-x")], 77);
            let x = anchor.id();
            assert!(dag.add_anchor(anchor, 1_000_000, 40, 40), "the anchor installs");
            let side = blk(vec![deep_id], 61);
            let side_id = side.id();
            assert!(dag.add_carried_block(side, 510_000, 31), "a carried side block on the ancestor installs");
            let y = dag.add_block(blk(vec![x], 62)).expect("a block on the anchor");
            (dag, y, side_id)
        };
        let (mut dag, y, side) = jumper(20);
        let merge = blk(vec![y, side], 63);
        let merge_id = merge.id();
        assert!(
            matches!(dag.add_block(merge), Err(DagError::MergesPreAnchorHistory(id)) if id == merge_id),
            "⛔ DB-361: a walk this node could not finish was read as admitted"
        );
        let (mut open, y, side) = jumper(crate::params::MERGE_DEPTH_CAP_DEFAULT);
        assert!(open.add_block(blk(vec![y, side], 63)).is_ok(), "calibration: a zero floor admits it");
    }

    #[test]
    fn dag_store_is_bounded_no_growth_under_long_production() {
        // The blowup this guards: `add_block` used to keep every block forever, so the store grew
        // O(chain). Shrink the horizon (tiny merge_depth_cap) so the test overflows it cheaply:
        // keep_depth = merge_depth_cap*2 + daa_sample_len + 256 = 4 + 1 + 256 = 261; sweep at >261+512.
        let mut p = ChainParams::default();
        p.merge_depth_cap = 2;
        p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
        p.daa_sample_len = 1;
        let mut dag = Dag::with_params(p);
        let mut tip = dag.add_block(blk(vec![], 0)).unwrap();
        for i in 1..=2000u64 {
            tip = dag.add_block(blk(vec![tip], i)).unwrap();
        }
        // MEMORY IS BOUNDED: after 2001 blocks the store holds a constant recent window, not all
        // history (would be 2001 without pruning).
        assert!(
            dag.len() < 800,
            "dag store must stay bounded, got {}",
            dag.len()
        );
        assert!(
            dag.len() > 200,
            "but must keep a real recent window, got {}",
            dag.len()
        );
        // CONSENSUS STILL WORKS on the recent window: the tip resolves + carries the true blue-score.
        assert_eq!(dag.selected_tip(), Some(tip));
        assert_eq!(dag.get(&tip).unwrap().blue_score, 2000);
        assert!(
            dag.genesis().is_some(),
            "genesis pointer retained (O(1) insurance)"
        );
        // PRODUCTION IS UNINTERRUPTED: a new block still builds on the live tip after pruning.
        let next = dag.add_block(blk(vec![tip], 9999)).unwrap();
        assert_eq!(dag.get(&next).unwrap().blue_score, 2001);
    }

    /// Build the exact adversarial shape the finality bound exists for, on a FRESH dag each time:
    /// an honest selected chain `g -> a -> b -> c` at uniform work, and a rival branch `g -> x1 -> x2`
    /// forking at genesis, so `x2` does NOT descend from `b`.
    ///
    /// The rival's WEIGHT sits on `x1`, not on the tip: `blue_work` sums a block's blue ANCESTORS'
    /// work and EXCLUDES its own (see `canonical_order_agrees_with_selected_tip_under_variable_difficulty`),
    /// so a single heavy fork block would carry none of its own weight into the comparison. Two blocks
    /// is the minimum shape that actually makes the abandoning tip heavier. Returns `(dag, b, c, x2)`.
    fn honest_chain_and_a_heavier_abandoning_rival() -> (Dag, BlockId, BlockId, BlockId) {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 1)).unwrap();
        let a = dag.add_block(blk(vec![g], 2)).unwrap();
        let b = dag.add_block(blk(vec![a], 3)).unwrap();
        let c = dag.add_block(blk(vec![b], 4)).unwrap();
        let x1 = dag.add_block(blk_w(vec![g], 5, 10_000)).unwrap();
        let x2 = dag.add_block(blk(vec![x1], 6)).unwrap();
        assert!(
            dag.get(&x2).unwrap().blue_work > dag.get(&c).unwrap().blue_work,
            "fixture must actually be work-heavier, else the pin proves nothing"
        );
        (dag, b, c, x2)
    }

    /// ⭐ THE PIN: with a finalized block installed, fork choice refuses a WORK-HEAVIER tip that
    /// abandons it — and it refuses identically on TWO independent parties holding the same blocks.
    #[test]
    fn finality_bound_refuses_a_work_heavier_tip_that_abandons_a_finalized_block_on_both_parties() {
        for party in ["party-A", "party-B"] {
            let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();

            // BEFORE the quorum is heard, work alone decides and the heavier rival IS the head.
            assert_eq!(
                dag.selected_tip(),
                Some(x),
                "{party}: work-only fork choice must pick the heavier rival — otherwise this pin is not testing the bound"
            );

            // The bonded quorum finalizes `b`.
            dag.set_finality_floor(Some(b));

            assert_eq!(
                dag.selected_tip(),
                Some(c),
                "{party}: a tip that abandons the finalized block must not be head, however heavy"
            );
            // ACCEPTANCE IS UNTOUCHED — the refused branch is still stored, still a tip, still relayable.
            assert!(dag.get(&x).is_some(), "{party}: the block is still accepted");
            assert!(dag.tips().contains(&x), "{party}: it is still a tip");
            // PRODUCTION IS UNTOUCHED — the chain keeps extending on the bounded head.
            let d = dag.add_block(blk(vec![c], 6)).unwrap();
            assert_eq!(dag.selected_tip(), Some(d), "{party}: production continues");
        }
    }

    /// ⭐ THE NO-OP PIN. At `finalized_height 0` no quorum has ever crossed 2/3, so the floor is `None`
    /// and fork choice is EXACTLY its old work-only self — the heavier rival is head. Same for a floor
    /// this node does not hold (pruned below the horizon, or finalized by a peer from blocks we lack):
    /// the bound cannot justify a refusal from its own state, so it makes none.
    #[test]
    fn the_finality_bound_is_an_exact_no_op_with_no_quorum_and_with_an_unheld_floor() {
        let (mut dag, _b, _c, x) = honest_chain_and_a_heavier_abandoning_rival();

        assert_eq!(dag.finality_floor(), None, "a fresh DAG has heard no quorum");
        assert_eq!(
            dag.selected_tip(),
            Some(x),
            "at finalized_height 0 the bound must be a NO-OP"
        );

        let never_seen = Hash32::hash(b"a block this node has never received");
        assert!(dag.get(&never_seen).is_none());
        dag.set_finality_floor(Some(never_seen));
        assert_eq!(
            dag.selected_tip(),
            Some(x),
            "a floor we do not hold is no floor at all — never a refusal we cannot justify"
        );
    }

    /// ⭐ THE LIVENESS PIN — the property that makes this bound legal under the chain-halts-are-impossible
    /// pillar. A node with NO peers, NO validators and NO votes produces exactly as before; and even with a
    /// floor armed whose branch it has entirely lost, it ALWAYS has a head and keeps extending. The bound
    /// orders the candidates that exist; it can never remove the last one.
    #[test]
    fn production_continues_with_zero_peers_and_the_bound_never_leaves_the_node_headless() {
        // A lone producer: no peers, no bonded validators, so no floor is ever installed.
        let mut dag = Dag::new();
        let mut tip = dag.add_block(blk(vec![], 1)).unwrap();
        for n in 2..40u64 {
            tip = dag.add_block(blk(vec![tip], n)).unwrap();
            assert_eq!(
                dag.selected_tip(),
                Some(tip),
                "a node with zero reachable peers must keep extending its own chain"
            );
        }
        assert_eq!(dag.finality_floor(), None);

        // Now arm a floor on a branch NO tip descends from: every tip ranks alike, so work decides and
        // the node still has a head — and still produces.
        let orphan_floor = {
            let mut other = Dag::new();
            let og = other.add_block(blk(vec![], 777)).unwrap();
            other.add_block(blk(vec![og], 778)).unwrap()
        };
        let mut dag2 = Dag::new();
        let g2 = dag2.add_block(blk(vec![], 1)).unwrap();
        let t2 = dag2.add_block(blk(vec![g2], 2)).unwrap();
        dag2.set_finality_floor(Some(orphan_floor));
        assert_eq!(
            dag2.selected_tip(),
            Some(t2),
            "an unreachable floor must never leave the node without a head"
        );
        let t3 = dag2.add_block(blk(vec![t2], 3)).unwrap();
        assert_eq!(dag2.selected_tip(), Some(t3), "and production continues");
    }

    /// ADVERSARIAL-REVIEW PROBE A — the production path, not a hand-picked parent.
    /// `miner::build_template` sets `parents = dag.tips()` (miner.rs:246): EVERY tip, including the
    /// abandoning one. The pin above builds `blk(vec![c], _)`, a single hand-picked parent no producer
    /// ever chooses. This probe reproduces what the miner actually does.
    #[test]
    fn probe_a_the_bound_dies_on_the_next_honestly_produced_block() {
        let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
        dag.set_finality_floor(Some(b));
        assert_eq!(dag.selected_tip(), Some(c), "setup: the bound holds before production");
        assert!(dag.is_selected_chain_ancestor(&b, &c), "setup: the finalized block is on the head chain");

        // THE REAL TEMPLATE: parents = every current tip.
        let parents = dag.tips();
        assert!(parents.contains(&x) && parents.contains(&c), "setup: both tips are template parents");
        let n = dag.add_block(blk(parents, 4242)).unwrap();

        // GHOSTDAG picks the merged block's SELECTED PARENT with the UNBOUNDED order_key, so it takes the
        // heavier abandoning branch; and the admissible tip was consumed as a parent, so nothing admissible
        // is left to outrank it.
        assert_eq!(
            dag.get(&n).unwrap().selected_parent,
            Some(x),
            "PROBE A: the honest merged block's selected parent is the ABANDONING branch"
        );
        // CLOSED (A-F40 + A-F54, lane goods 2026-11-13): the probe's block still abandons the floor, but it no longer carries
        // the head with it — the head stays on the heaviest block that keeps the finalized block (c, the block it consumed).
        assert!(!dag.is_selected_chain_ancestor(&b, &n), "CALIBRATION: the probe's block itself abandons the finalized block");
        assert_eq!(dag.selected_tip(), Some(c), "⛔ PROBE A (A-F40): one honestly produced block carried the head off the finalized block");
        assert!(
            dag.is_selected_chain_ancestor(&b, &dag.selected_tip().unwrap()),
            "⛔ PROBE A (A-F40): the head left the finalized block while the floor is armed"
        );
        assert_eq!(dag.finality_floor(), Some(b), "the floor is still installed and it holds");
    }

    /// ADVERSARIAL-REVIEW PROBE B — the DSYNC adopt door bypasses the bound outright.
    /// `add_anchor` compares against `selected_tip()` and then CLEARS `tips`, so the anchor is the sole
    /// candidate and ranks alone; admissibility never enters.
    #[test]
    fn probe_b_add_anchor_installs_a_head_that_abandons_the_finalized_block() {
        let (mut dag, b, c, _x) = honest_chain_and_a_heavier_abandoning_rival();
        dag.set_finality_floor(Some(b));
        assert_eq!(dag.selected_tip(), Some(c), "setup: the bound holds");

        // A DSYNC-adopted peer tip with NO local ancestry and a certified heavier weight.
        let anchor = blk(vec![], 777_777);
        let anchor_id = anchor.id();
        assert!(dag.add_anchor(anchor, 1_000_000, 99, 99), "the adopt door takes it");

        assert_eq!(dag.selected_tip(), Some(anchor_id), "PROBE B: the anchor is head");
        assert!(
            !dag.is_selected_chain_ancestor(&b, &anchor_id),
            "PROBE B REFUTATION: the DSYNC adopt door installs a peer's head that abandons the finalized block"
        );
    }

    /// ⭐ TWO NODES THAT ADOPT ONE CERTIFIED ANCHOR NAME ONE HEAD CHAIN (link 30). MEASURED sim-20261008-011738 T1.6: after
    /// the DSYNC jump door installed a certified anchor whose ancestry the joiner does not hold, the incremental refresh
    /// rewrote the O(1) ancestry index only down to the anchor; every depth below kept the chain the joiner had selected
    /// BEFORE the jump, so it named a block of an abandoned branch at a settled height its peer named differently, and
    /// `is_ancestor_of_selected_tip` (the live tx-settlement predicate) answered TRUE for it. Party A held a chain before
    /// the jump; party B is a fresh node that adopts the SAME anchor and extends it with the SAME child. Both index arms are
    /// held — an anchor ABOVE A's held chain (`resize`) and one BELOW A's tip (`truncate`) — and A's answers also agree
    /// with its own full rebuild (the walk-from-the-head oracle).
    #[test]
    fn two_nodes_adopting_one_anchor_name_one_head_chain_whatever_either_held_before() {
        let named = |d: &Dag| -> Vec<BlockId> {
            let mut v: Vec<BlockId> = d.dag_recent_view(64).into_iter().filter(|r| r.4).map(|r| r.0).collect();
            v.sort();
            v
        };
        for (arm, anchor_score) in [("resize", 99u64), ("truncate", 2u64)] {
            // party A: a chain held before the jump
            let mut a_dag = Dag::new();
            let g = a_dag.add_block(blk(vec![], 1)).unwrap();
            let a = a_dag.add_block(blk(vec![g], 2)).unwrap();
            let b = a_dag.add_block(blk(vec![a], 3)).unwrap();
            let c = a_dag.add_block(blk(vec![b], 4)).unwrap();
            for id in [a, b, c] {
                assert!(a_dag.is_ancestor_of_selected_tip(&id), "{arm} CALIBRATION: before the jump A's chain is indexed");
            }
            // party B: a fresh node with nothing before the jump
            let mut b_dag = Dag::new();
            let anchor = blk(vec![], 777_777);
            let anchor_id = anchor.id();
            for (who, d) in [("A", &mut a_dag), ("B", &mut b_dag)] {
                assert!(d.add_anchor(anchor.clone(), 1_000_000, anchor_score, anchor_score), "{arm}: {who}'s adopt door takes the anchor");
                assert_eq!(d.selected_tip(), Some(anchor_id), "{arm}: the anchor is {who}'s head");
            }
            let child_a = a_dag.add_block(blk(vec![anchor_id], 8)).unwrap();
            let child_b = b_dag.add_block(blk(vec![anchor_id], 8)).unwrap();
            assert_eq!(child_a, child_b, "{arm}: one child block on both nodes");
            assert_eq!(a_dag.selected_tip(), b_dag.selected_tip(), "{arm}: one head on both nodes");
            assert_eq!(
                named(&a_dag),
                named(&b_dag),
                "⛔ {arm}: two nodes that adopted the same anchor name different head chains — A still names a block it held \
                 before the jump"
            );
            assert!(named(&b_dag).contains(&anchor_id) && named(&b_dag).contains(&child_b), "{arm} CALIBRATION: B names its chain");
            for (name, id) in [("a", a), ("b", b), ("c", c)] {
                assert!(
                    !a_dag.is_ancestor_of_selected_tip(&id),
                    "⛔ {arm}: {name}, a block A held BEFORE the jump, is still answered as an ancestor of the head"
                );
            }
            for id in [anchor_id, child_a] {
                assert_eq!(a_dag.is_ancestor_of_selected_tip(&id), b_dag.is_ancestor_of_selected_tip(&id), "⛔ {arm}: A and B disagree");
            }
            let ids = [g, a, b, c, anchor_id, child_a];
            let incremental: Vec<bool> = ids.iter().map(|id| a_dag.is_ancestor_of_selected_tip(id)).collect();
            let view = named(&a_dag);
            a_dag.rebuild_selected_chain_index();
            let rebuilt: Vec<bool> = ids.iter().map(|id| a_dag.is_ancestor_of_selected_tip(id)).collect();
            assert_eq!(incremental, rebuilt, "⛔ {arm}: A's incremental index disagrees with its full rebuild");
            assert_eq!(view, named(&a_dag), "⛔ {arm}: A's live view disagrees with its full rebuild's");
        }
    }

    /// ⭐ (lane stable 2026-11-02, `Dag::unlinked`) — A RESTORE LINKS EXACTLY WHAT THE LIVE DAG LINKED. A block that entered
    /// before its parent stays unlinked on the live DAG when the parent arrives (a live relink broke joining — see `unlinked`);
    /// the restore's relink, handed the live unlinked set, leaves it so, and the control relink without it links it.
    #[test]
    fn a_restore_links_exactly_what_the_live_dag_linked() {
        let mut full = Dag::new();
        let g = full.add_block(blk(vec![], 0)).unwrap();
        let a = full.add_block(blk(vec![g], 1)).unwrap();
        let b = full.add_block(blk(vec![a], 2)).unwrap();
        let (na, nb) = (full.get(&a).unwrap().clone(), full.get(&b).unwrap().clone());
        let mut d = Dag::new();
        assert_eq!(d.add_block(blk(vec![], 0)).unwrap(), g, "PRECONDITION: one genesis");
        assert!(d.add_ancestor_anchor(nb.header.clone(), nb.tx_ids.clone(), nb.blue_work, nb.blue_score, None));
        assert!(d.add_ancestor_anchor(na.header.clone(), na.tx_ids.clone(), na.blue_work, na.blue_score, Some(g)));
        assert!(d.get(&b).unwrap().selected_parent.is_none(), "⛔ the live DAG relinked a block when its parent arrived");
        assert_eq!(d.unlinked_ids(), vec![b], "the live unlinked set names it");
        let keep: HashSet<BlockId> = d.unlinked_ids().into_iter().collect();
        assert_eq!(d.relink_selected_parents_except(&keep), 0, "⛔ a restore linked what its live process held unlinked");
        assert_eq!(d.relink_selected_parents(), 1, "CONTROL: the unconditional relink links it");
        assert_eq!(d.get(&b).unwrap().selected_parent, Some(a));
        assert!(d.unlinked_ids().is_empty(), "the set follows the link");
    }

    /// ADVERSARIAL-REVIEW PROBE C (closed lane stable 2026-11-02, `Dag::head_inputs_changed`) — `set_finality_floor` moved the
    /// head WITHOUT refreshing `selected_chain`, the O(1) index `is_ancestor_of_selected_tip` reads, so the live
    /// tx-settlement predicate answered against the ABANDONED chain. The floor now refreshes the index: the head chain is
    /// reported, the abandoned branch is not, on TWO independently built parties.
    #[test]
    fn probe_c_set_finality_floor_moves_the_o1_ancestry_index_with_the_head() {
        for party in ["party-A", "party-B"] {
            let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
            dag.set_finality_floor(Some(b));
            assert_eq!(dag.selected_tip(), Some(c), "{party}: fork choice says the head is c");
            assert!(dag.is_ancestor_of_selected_tip(&b), "⛔ {party}: the finalized block is not on the head chain by the O(1) index");
            assert!(dag.is_ancestor_of_selected_tip(&c), "⛔ {party}: the head itself is not reported on its own chain");
            let x1 = dag.get(&x).unwrap().selected_parent.expect("x has a selected parent");
            assert!(!dag.is_ancestor_of_selected_tip(&x1), "⛔ {party}: the index still reports the ABANDONED branch as the head chain");
            // and the index equals its own full rebuild
            let incremental: Vec<bool> = [b, c, x, x1].iter().map(|id| dag.is_ancestor_of_selected_tip(id)).collect();
            dag.rebuild_selected_chain_index();
            let rebuilt: Vec<bool> = [b, c, x, x1].iter().map(|id| dag.is_ancestor_of_selected_tip(id)).collect();
            assert_eq!(incremental, rebuilt, "⛔ {party}: the incremental index ≠ its full rebuild");
        }
    }

    /// ADVERSARIAL-REVIEW PROBE D — the bound BREAKS the canonical_order/selected_tip unification that
    /// `canonical_order`'s own doc (dag.rs:258-274) calls "CONSENSUS-CRITICAL for value conservation":
    /// "the effective-ledger winner (first spender of a nullifier in this order) MUST be the block that
    /// lands on the canonical selected chain whose frontier is adopted — else ... the resolver could
    /// prune a spend whose OUTPUTS the canonical frontier still carries → inflation". `selected_tip` is
    /// now keyed on `(admissible, blue_work, id)` while `canonical_order` stayed `(blue_work, id)`, so
    /// the two keys disagree exactly when the bound bites. Run on two independent parties (each a peer
    /// of the other, holding the same blocks) so the disagreement is not one object wearing two hats.
    ///
    /// REFERENCE-CHECKED: Kaspa rusty-kaspa GHOSTDAG (virtual selected parent + blue-work ordering) —
    /// github.com/kaspanet/rusty-kaspa. This probe INTRODUCES no ordering and no counter: it only reads
    /// the two orderings this tree already computes and asserts they still agree.
    #[test]
    fn probe_d_the_bound_splits_the_two_orderings_this_tree_already_computes() {
        for party in ["party-A", "party-B"] {
            let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
            assert_eq!(
                dag.canonical_order().last().copied(),
                dag.selected_tip(),
                "{party}: unbounded, the unification the ledger relies on holds"
            );
            dag.set_finality_floor(Some(b));
            assert_eq!(dag.canonical_order().last().copied(), Some(x), "{party}: canonical_order is still work-only");
            assert_eq!(dag.selected_tip(), Some(c), "{party}: but the adopted head is the bounded one");
            assert_ne!(
                dag.canonical_order().last().copied(),
                dag.selected_tip(),
                "{party} PROBE D REFUTATION: with the floor armed the nullifier resolver's order and the \
                 adopted frontier name DIFFERENT canonical chains — the split canonical_order's own doc \
                 calls consensus-critical for value conservation"
            );
        }
    }

    /// ⭐⭐⭐ SYMMETRIC FINALITY TARGET (2026-09-18, runs 39/40). Two producers under Tor latency longer
    /// than the block period: each node's newest block merges the peer's block from TWO steps back, so at
    /// any instant each node lacks the peer's last two blocks and its own chain is its heaviest tip. The
    /// old target ("the selected-chain block at blue score h") then names a different block on each node
    /// at (nearly) every level — the calibration below — so with one vote per height no level reaches
    /// 2/2 and finality froze at 1 on real nodes. The symmetric target names the same block on both.
    #[test]
    fn finality_vote_target_agrees_across_two_producers_where_the_selected_chain_target_never_does() {
        let k = 12usize;
        let mut full = Dag::new();
        let g = full.add_block(blk(vec![], 0)).unwrap();
        let (mut a, mut b): (Vec<BlockId>, Vec<BlockId>) = (vec![g], vec![g]);
        let (mut a_blocks, mut b_blocks): (Vec<Block>, Vec<Block>) = (Vec::new(), Vec::new());
        for i in 1..=k {
            let pa = if i >= 3 { vec![a[i - 1], b[i - 2]] } else { vec![a[i - 1]] };
            let pb = if i >= 3 { vec![b[i - 1], a[i - 2]] } else { vec![b[i - 1]] };
            let (ba, bb) = (blk(pa, 1000 + i as u64), blk(pb, 2000 + i as u64));
            a.push(full.add_block(ba.clone()).unwrap());
            b.push(full.add_block(bb.clone()).unwrap());
            a_blocks.push(ba);
            b_blocks.push(bb);
        }
        // n0 holds every a and the b's up to k-2; n1 the mirror. Topological insertion on each.
        let mut n0 = Dag::new();
        let mut n1 = Dag::new();
        n0.add_block(blk(vec![], 0)).unwrap();
        n1.add_block(blk(vec![], 0)).unwrap();
        for i in 1..=k {
            n0.add_block(a_blocks[i - 1].clone()).unwrap();
            n1.add_block(b_blocks[i - 1].clone()).unwrap();
            if i <= k - 2 {
                n0.add_block(b_blocks[i - 1].clone()).unwrap();
                n1.add_block(a_blocks[i - 1].clone()).unwrap();
            }
        }
        let (t0, t1) = (n0.selected_tip().unwrap(), n1.selected_tip().unwrap());
        assert_eq!(t0, a[k], "n0's heaviest tip is its own newest block");
        assert_eq!(t1, b[k], "n1's heaviest tip is its own newest block");
        let bs0 = n0.get(&t0).unwrap().blue_score;
        let bs1 = n1.get(&t1).unwrap().blue_score;
        let h_hi = bs0.min(bs1) - 4;
        let c0: std::collections::BTreeMap<u64, BlockId> =
            n0.finality_vote_candidates(&t0, 1, h_hi).into_iter().map(|(h, ids)| (h, ids[0])).collect();
        let c1: std::collections::BTreeMap<u64, BlockId> =
            n1.finality_vote_candidates(&t1, 1, h_hi).into_iter().map(|(h, ids)| (h, ids[0])).collect();
        let common: Vec<u64> = c0.keys().filter(|h| c1.contains_key(h)).copied().collect();
        assert!(common.len() >= 4, "too few common levels to say anything: {common:?}");
        for h in &common {
            assert_eq!(c0[h], c1[h], "the symmetric target must name ONE block at level {h}");
        }
        // CALIBRATION: the selected-chain target on the same two views disagrees on the same levels.
        let sp_at = |d: &Dag, tip: BlockId, h: u64| -> BlockId {
            let mut cur = tip;
            loop {
                let n = d.get(&cur).unwrap();
                if n.blue_score <= h {
                    return cur;
                }
                cur = n.selected_parent.unwrap();
            }
        };
        let splits = common.iter().filter(|h| sp_at(&n0, t0, **h) != sp_at(&n1, t1, **h)).count();
        assert!(
            splits * 4 >= common.len() * 3,
            "the old rule was supposed to split on this shape: {splits} of {} levels differ",
            common.len()
        );
    }

    /// ⛔ A-F94 — A RE-ANCHOR KEEPS THE STRUCTURE THIS NODE ADMITTED AFTER ITS FIRST ANCHOR; ONLY THE FIRST ONE TURNS AN ISLAND
    /// INTO HISTORY. RED on the old door (every anchor reset every flag): the side block admitted on the first anchor became
    /// history at the second, and the honest block built on it was refused `BelowSettledBase` — the joiner re-anchored for ever.
    #[test]
    fn af94_a_re_anchor_keeps_admitted_structure_and_the_first_anchor_still_makes_an_island_history() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 1)).unwrap();
        let island = dag.add_block(blk(vec![g], 2)).unwrap();
        let first = blk(vec![Hash32::hash(b"af94-absent-first")], 70);
        let x = first.id();
        assert!(dag.add_anchor(first, 1_000_000, 90, 90), "the first anchor installs");
        let side = dag.add_block(blk(vec![x], 3)).expect("a side block on the first anchor");
        let _main = dag.add_block(blk(vec![x], 4)).expect("a chain block on the first anchor");
        // A heavier certified anchor that does not hold `side` in its past (a later fold root of the serving chain).
        let second = blk(vec![Hash32::hash(b"af94-absent-second")], 71);
        assert!(dag.add_anchor(second, 2_000_000, 95, 95), "the re-anchor installs");
        assert!(
            dag.add_block(blk(vec![side], 5)).is_ok(),
            "⛔ A-F94: a re-anchor turned admitted structure into history, so the honest block on it was refused"
        );
        assert!(
            matches!(dag.add_block(blk(vec![island], 6)), Err(DagError::BelowSettledBase(_))),
            "⛔ DB-282: the pre-anchor island stopped being history after a re-anchor"
        );
    }

    /// ⛔ DB-282 — AFTER AN ANCHOR, A BLOCK WITH NO PARENT IN THE SETTLED STRUCTURE IS REFUSED BEFORE IT TOUCHES THE DAG.
    ///
    /// Kaspa's `check_pruning_violation`: a new block must have at least one parent in the future of (or equal to) the
    /// pruning point. A DSYNC anchor is that point for the node that installed it — every block in its past is already
    /// counted by the certified state, so a block built only on that past is history, never new structure. Parity
    /// with a from-genesis DAG is part of the pin: without an anchor nothing is refused.
    #[test]
    fn db282_after_an_anchor_a_block_built_only_on_the_settled_past_is_refused_and_one_on_the_anchor_is_admitted() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 1)).unwrap();
        let a1 = dag.add_block(blk(vec![g], 2)).unwrap();
        let a2 = dag.add_block(blk(vec![a1], 3)).unwrap();
        // CALIBRATION: a from-genesis DAG has no settled floor — a block on the old chain is admitted.
        let mut control = Dag::new();
        let cg = control.add_block(blk(vec![], 1)).unwrap();
        let c1 = control.add_block(blk(vec![cg], 2)).unwrap();
        assert!(control.add_block(blk(vec![c1], 40)).is_ok(), "calibration: no anchor, no floor, nothing refused");

        // A peer's certified tip, installed with no local ancestry and a heavier certified weight.
        let anchor = blk(vec![Hash32::hash(b"db282-absent-parent")], 77);
        let x = anchor.id();
        assert!(dag.add_anchor(anchor, 1_000_000, 90, 90), "the anchor installs");
        let blocks_before = dag.len();

        // TAMPER: a block built ONLY on the pre-anchor chain (what a re-served old block is).
        let stale = blk(vec![a2], 4);
        let stale_id = stale.id();
        match dag.add_block(stale) {
            Err(DagError::BelowSettledBase(id)) => assert_eq!(id, stale_id, "the refusal names the block"),
            other => panic!("⛔ DB-282: a block built only on the settled past entered the DAG: {other:?}"),
        }
        assert!(dag.get(&stale_id).is_none(), "⛔ DB-282: the refused block is held");
        assert!(!dag.tips().contains(&stale_id), "⛔ DB-282: the refused block is a tip");
        assert_eq!(dag.len(), blocks_before, "a refusal mutates nothing");

        // A block on the anchor is new structure: admitted, and settled for its own children.
        let on_anchor = dag.add_block(blk(vec![x], 5)).expect("a block on the anchor is admitted");
        assert!(dag.add_block(blk(vec![on_anchor], 6)).is_ok(), "its child is admitted");
        // TAMPER (review, lane-db224-carriage): a block naming a settled tip AND a held pre-anchor block. Under "any
        // parent settled" it passed, and this node's mergeset BFS walked the pre-anchor chain — outside
        // `bounded_past(sp)`, which stops at the anchor — so it scored the block up to k higher than a full node,
        // which sees that chain inside past(sp). EVERY parent must be settled.
        let mixed = blk(vec![a2, on_anchor], 7);
        let mixed_id = mixed.id();
        assert!(
            matches!(dag.add_block(mixed), Err(DagError::MergesPreAnchorHistory(id)) if id == mixed_id),
            "⛔ DB-282: a block naming a pre-anchor parent beside a settled one entered the DAG, or was not named as the \
             late merge the caller re-anchors on"
        );

        // A GAP-FREE past is placeable: an anchor whose parent this DAG holds settles everything it reaches.
        let mut joined = Dag::new();
        let jg = joined.add_block(blk(vec![], 1)).unwrap();
        let j1 = joined.add_block(blk(vec![jg], 2)).unwrap();
        let j2 = joined.add_block(blk(vec![j1], 3)).unwrap();
        let met = blk(vec![j2], 50);
        let met_id = met.id();
        assert!(joined.add_anchor(met, 1_000_000, 90, 90), "an anchor on a held parent installs");
        assert!(
            matches!(joined.add_block(blk(vec![j2], 51)), Err(DagError::BelowSettledBase(_))),
            "calibration: before the settle, the held past is history like any pre-anchor block"
        );
        assert_eq!(joined.settle_connected_past(&met_id), 3, "the anchor's held past (j2, j1, genesis) settles");
        assert!(joined.add_block(blk(vec![j2], 52)).is_ok(), "a block on the connected past is admitted");
        // …while the island DAG above (anchor on an ABSENT parent) settles nothing: its old chain stays history.
        assert_eq!(dag.settle_connected_past(&x), 0, "an island across a gap is never reached from the anchor");

        // A CARRIED block (certified structure) is settled even when its parents are pre-anchor blocks.
        let carried = blk(vec![a1], 8);
        let carried_id = carried.id();
        // A-F97: the carry states the figures GHOSTDAG gives (an honest server's); this DAG holds a1's whole past, so they are
        // checked exactly. TAMPER: the same block with its blue score off by one is refused and leaves nothing behind.
        let gd = dag.ghostdag_data(&[a1]);
        assert!(
            !dag.add_carried_block(carried.clone(), gd.blue_work, gd.blue_score + 1),
            "⛔ A-F97: a carried block with a stated blue score this node can recompute exactly, off by one, was placed"
        );
        assert!(dag.get(&carried_id).is_none(), "a refused carry leaves no block behind");
        assert!(
            !dag.add_carried_block(carried.clone(), gd.blue_work + 1_000_000, gd.blue_score),
            "⛔ A-F97: a carried block with inflated blue work, where this node sees its whole past, was placed"
        );
        assert!(dag.add_carried_block(carried, gd.blue_work, gd.blue_score), "the carry installs");
        assert!(dag.add_block(blk(vec![carried_id], 9)).is_ok(), "a block on a carried block is admitted");
    }

    /// ⭐ A-F37 PIN (RED-first): a block template builds on the FINALITY-RESPECTING head, not the
    /// plain-heaviest tip. BORROWED: Ethereum proposers build on the fork-choice head; Kaspa virtual
    /// parents never leave the finality point. The fix is one line: template_parents sorts by
    /// finality_bounded_order_key instead of order_key.
    #[test]
    fn af37_a_template_builds_on_the_finality_respecting_head_not_the_plain_heaviest_tip() {
        let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
        dag.set_finality_floor(Some(b));
        assert_eq!(dag.selected_tip(), Some(c), "setup: the finality head is c");
        assert!(dag.get(&x).unwrap().blue_work > dag.get(&c).unwrap().blue_work, "setup: x is heavier");

        let parents = dag.template_parents();
        assert_eq!(
            parents[0], c,
            "⛔ A-F37: template_parents[0] must be the finality-respecting head (c), not the \
             plain-heaviest tip (x) — a template built on the abandoning branch halts the fold"
        );

        let n = dag.add_block(blk(parents, 4242)).unwrap();
        assert!(
            dag.is_selected_chain_ancestor(&b, &n),
            "⛔ A-F37: the honestly-produced block does not keep the finalized block on its \
             selected chain — the template ignored finality"
        );
        assert_eq!(dag.selected_tip(), Some(n), "production continues on the admissible chain");
    }

    /// ⭐ A-F40 PIN (RED-first): after a foreign block merges the admissible head from a heavier
    /// branch, the NEXT template still builds on an admissible parent. The foreign block itself is
    /// inadmissible (its selected chain goes through the abandoning branch), but template_parents
    /// must not follow it.
    #[test]
    fn af40_after_a_merge_that_consumes_the_admissible_head_the_next_template_keeps_finality() {
        let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
        dag.set_finality_floor(Some(b));
        assert_eq!(dag.selected_tip(), Some(c), "setup: the finality head is c");

        // A foreign block arrives: selected parent = x (heavy, inadmissible), merged parent = c (admissible head).
        let foreign = dag.add_block(blk(vec![x, c], 9999)).unwrap();
        assert_eq!(
            dag.get(&foreign).unwrap().selected_parent,
            Some(x),
            "setup: GHOSTDAG picks x as selected parent (heavier)"
        );
        assert!(!dag.is_selected_chain_ancestor(&b, &foreign),
            "setup: the foreign block does not keep finality (its selected chain goes through x)");

        // c is no longer a tip (it was consumed as a parent). The foreign block is a tip but inadmissible.
        assert!(!dag.tips().contains(&c), "setup: c was consumed");
        assert!(dag.tips().contains(&foreign), "setup: foreign is a tip");

        // A-F40 + A-F54: with no admissible tip, the HEAD stays on the heaviest block that keeps the floor (c, the block just
        // consumed), and the template builds on it — never on the finality floor b itself, which sits below every node's fold
        // cursor (the 74222c1f arm that built on b halted the chain on real nodes, A-F54).
        assert_eq!(dag.selected_tip(), Some(c), "⛔ A-F40: one merge carried the head off the finalized block");
        let parents = dag.template_parents();
        assert_eq!(parents.first().copied(), Some(c), "⛔ A-F54: the template does not build on the heaviest block that keeps the floor");
        assert!(!parents.contains(&b) || b == c, "⛔ A-F54: the template builds on the finality floor itself, below the fold");
        let n = dag.add_block(blk(parents, 5555)).unwrap();
        assert_eq!(dag.selected_tip(), Some(n), "A-F40: the chain goes on above the finalized block");
        assert!(
            dag.is_selected_chain_ancestor(&b, &n),
            "⛔ A-F40: the new block does not keep finality"
        );

        // The critical property: an honest template that builds ON the admissible head (before the
        // foreign block arrives) keeps finality. Test that path too.
        let (mut dag2, b2, c2, _x2) = honest_chain_and_a_heavier_abandoning_rival();
        dag2.set_finality_floor(Some(b2));
        let parents2 = dag2.template_parents();
        assert_eq!(parents2[0], c2, "before the foreign merge, the template builds on c");
        let honest = dag2.add_block(blk(parents2, 7777)).unwrap();
        assert!(
            dag2.is_selected_chain_ancestor(&b2, &honest),
            "⛔ A-F40: the honest template's block does not keep finality — it built on the \
             abandoning branch instead of the admissible head"
        );
    }

    /// ⛔ A-F58 PIN (RED-first): a LIGHTER sibling in the finalized block's anticone is MERGED by the next template, so its
    /// records fold and the notes it carries arrive. MEASURED (lane veil rig, main bc4fc829, three real nodes, 2026-11-13):
    /// the record of block seq 185526021433325320 folded once at ordinal 28 on every node, left the spine at "[fold-reorg]
    /// … 4 record(s) from ordinal 27", and never folded again; its owner's wallet asked for it 1,610 times over 50 min
    /// ("has not folded on the node yet"), the DAG's tips grew 30 → 95, and every note in those blocks stayed unspendable
    /// (A-F53's shape). The cause was `template_parents`' sibling filter `finality_admits(t) > 0`: a tip whose own selected
    /// chain does not pass through the finalized block — every tip of a branch that forked before the votes finalized a
    /// block on the other branch — was never merged by any template, so it stayed a tip forever and nothing below it folded.
    /// Merging it is safe: the template's selected parent stays the finality-respecting head because the sibling is
    /// LIGHTER (GHOSTDAG takes the heaviest parent), so the new block's past(F) is untouched; the sibling only joins the
    /// new block's merge set, after F (Kaspa merges a finality point's anticone within the merge depth; only a selected
    /// chain may never leave it). CONTROL: a HEAVIER sibling that abandons the floor is still never merged (A-F54's guard),
    /// and every new block keeps the finalized block on its selected chain. MEASURED RED before the fix (lane names,
    /// 22:21): "⛔ A-F58 (party-A): the template does not merge a lighter sibling in the finalized block's anticone".
    /// TWO-PARTY-REVIEWED: two DAGs fed the same blocks derive the same template and the same merge; the cross-node proof is
    /// the real-node rows (funding on a fresh rig of three: pay, names, nft, tap) re-run on this build.
    #[test]
    fn af58_a_lighter_sibling_in_the_finalized_blocks_anticone_is_merged_and_never_stranded() {
        for party in ["party-A", "party-B"] {
            let mut dag = Dag::new();
            let g = dag.add_block(blk(vec![], 1)).unwrap();
            let a = dag.add_block(blk(vec![g], 2)).unwrap();
            let f = dag.add_block(blk(vec![a], 3)).unwrap(); // finalized by the votes
            let f2 = dag.add_block(blk(vec![f], 4)).unwrap();
            let f3 = dag.add_block(blk(vec![f2], 5)).unwrap(); // the finality-respecting head
            let s = dag.add_block(blk(vec![a], 6)).unwrap(); // another producer's block, forked before f
            dag.set_finality_floor(Some(f));
            assert_eq!(dag.selected_tip(), Some(f3), "{party} setup: the head keeps the floor");
            assert_eq!(dag.finality_admits(&s), 0, "{party} CALIBRATION: the sibling's own chain does not pass through f");
            assert!(dag.tips().contains(&s), "{party} setup: the sibling is a tip");
            assert!(
                dag.get(&s).unwrap().blue_work < dag.get(&f3).unwrap().blue_work,
                "{party} setup: the sibling is lighter than the head"
            );
            let parents = dag.template_parents();
            assert_eq!(parents.first().copied(), Some(f3), "{party}: the template still builds on the head");
            assert!(
                parents.contains(&s),
                "⛔ A-F58 ({party}): the template does not merge a lighter sibling in the finalized block's anticone — it stays a \
                 tip forever and the records (and notes) of its branch never fold"
            );
            let n = dag.add_block(blk(parents, 7)).unwrap();
            assert_eq!(dag.get(&n).unwrap().selected_parent, Some(f3), "{party}: the merge keeps the head as selected parent");
            assert!(dag.is_selected_chain_ancestor(&f, &n), "⛔ {party}: the new block does not keep the finalized block");
            assert!(!dag.tips().contains(&s), "⛔ {party}: the sibling is still a tip after the merge");
            assert_eq!(dag.tips(), vec![n], "{party}: one tip remains — nothing is stranded");

            // CONTROL (A-F54's guard stays): a HEAVIER sibling that abandons the floor is never merged.
            let h1 = dag.add_block(blk_w(vec![a], 8, 1_000_000_000)).unwrap();
            assert!(dag.get(&h1).unwrap().blue_work > dag.get(&n).unwrap().blue_work, "{party} setup: heavier");
            assert_eq!(dag.finality_admits(&h1), 0, "{party} setup: it abandons the floor");
            let parents = dag.template_parents();
            assert!(!parents.contains(&h1), "⛔ {party}: a heavier sibling that abandons the floor was merged (A-F54)");
            let m = dag.add_block(blk(parents, 9)).unwrap();
            assert!(dag.is_selected_chain_ancestor(&f, &m), "⛔ {party}: the control block left the finalized block");
        }
    }


    /// ⭐⭐ LIVE-FOLD W1 PIN — A WITHHELD BLOCK AND EVERY BLOCK BUILT ON IT LEAVE THE HEAD, AND RETURN WHEN ITS BODY LANDS. A heavy
    /// branch g → a → x → y1 → y2 → y3 and a light one a → z: before the mark the head is y3 (heavier). With x marked withheld the
    /// head is z (the heaviest available block), the template never merges a withheld-future tip, a new block on y3 is withheld
    /// on arrival; when x's body lands (`clear_withheld`) the head is the heavy branch again.
    #[test]
    fn w1_a_withheld_block_and_its_future_leave_the_head_and_return_when_its_body_lands() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let a = dag.add_block(blk(vec![g], 1)).unwrap();
        let x = dag.add_block(blk(vec![a], 2)).unwrap();
        let y1 = dag.add_block(blk(vec![x], 3)).unwrap();
        let y2 = dag.add_block(blk(vec![y1], 4)).unwrap();
        let y3 = dag.add_block(blk(vec![y2], 5)).unwrap();
        let z = dag.add_block(blk(vec![a], 6)).unwrap();
        assert_eq!(dag.selected_tip(), Some(y3), "CALIBRATION: the heavy branch leads before the mark");
        assert!(dag.mark_withheld(x), "the first mark is new");
        assert!(!dag.mark_withheld(x), "a second mark is not");
        assert_eq!(dag.selected_tip(), Some(z), "⛔ W1: a chain through a withheld block stayed head");
        assert!(!dag.template_parents().iter().any(|p| [x, y1, y2, y3].contains(p)), "⛔ W1: the template merged a withheld future");
        let y4 = dag.add_block(blk(vec![y3], 7)).unwrap();
        assert_eq!(dag.availability_admits(&y4), 0, "⛔ W1: a block built on a withheld future was admitted as available");
        assert_eq!(dag.selected_tip(), Some(z), "⛔ W1: the withheld branch took the head back by growing");
        let z2 = dag.add_block(blk(dag.template_parents(), 8)).unwrap();
        assert_eq!(dag.availability_admits(&z2), 1, "⛔ W1: a block on the available chain read withheld");
        assert_eq!(dag.selected_tip(), Some(z2), "⛔ W1: the available chain does not extend");
        assert!(dag.clear_withheld(&x), "the body landing clears the mark");
        assert_eq!(dag.availability_admits(&y4), 1, "⛔ W1: the future stayed withheld after the body landed");
        assert_eq!(dag.selected_tip(), Some(y4), "⛔ W1: fork choice did not return to the heavier chain once its body landed");
    }

    /// ⭐⭐ SELF-HEAL SH1 PIN — A HEADER-ONLY TIP IS NEVER BUILT ON: g → a → b whole, then a shell s on b (a header this node holds no
    /// body for, nothing above it) is grafted by the heal door; the head stays b and the template never names s; when s's body lands
    /// (`clear_withheld`) s is head. A shell under a block already held (referenced) is not marked (W1's reach rule keeps it).
    #[test]
    fn sh1_a_header_only_tip_is_never_built_on_until_its_body_lands() {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0)).unwrap();
        let a = dag.add_block(blk(vec![g], 1)).unwrap();
        let b = dag.add_block(blk(vec![a], 2)).unwrap();
        let s = blk(vec![b], 3);
        let sid = s.id();
        assert!(dag.add_wanted_shell(s), "PRECONDITION: the heal door grafts the shell");
        assert_eq!(dag.availability_admits(&sid), 0, "⛔ SH1: a header-only tip was admitted as available");
        assert_eq!(dag.selected_tip(), Some(b), "⛔ SH1: a header-only tip became head");
        assert!(!dag.template_parents().contains(&sid), "⛔ SH1: the template built on a header-only tip");
        assert!(dag.clear_withheld(&sid), "the body landing clears the mark");
        assert_eq!(dag.selected_tip(), Some(sid), "⛔ SH1: the shell did not lead once its body landed");
    }

}

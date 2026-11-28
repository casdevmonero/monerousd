// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE AUTHORITY MANIFEST — WHICH OF THIS NODE'S STATE IS THE CHAIN'S, AND WHICH IS ITS OWN.**
//!
//! user 2026-09-08: *"i see a lot of the errors are the known error of local node state being seen as
//! truth when it is not supposed to be."*
//!
//! That reading is correct, and it is the single most useful thing said about this defect set. SEVEN
//! of the holes found or registered are ONE CLASS, not seven bugs:
//!
//! | hole | how local state became truth |
//! |---|---|
//! | D-32 | the root was DERIVED from the node's own stored bytes, then used as authority over them |
//! | D-36 | the joiner KEPT its own genesis root; the arbiter was "does OUR root replay from OUR ledger" |
//! | D-35 | a block recorded locally and never folded — the local view drifted from the chain |
//! | E-7  | the DEX burn was LOCAL and never travelled; the lot paid out twice |
//! | D-01 | the victim derives ITS work from its own DAG and takes the challenger's from the wire |
//! | item 5 | a collateral ratio set by an RPC route, treated as authoritative |
//! | D-29 | a local verify (`accept_bundle`) treated as evidence about a chain it never read |
//!
//! The cardinal already exists ([[project_local_decides_consensus_sweep]], [[feedback_always_trustless]])
//! and the holes kept appearing anyway — because "is this field the chain's or mine?" was answered
//! per-site, from memory, by whoever was editing. This file answers it ONCE, for every field, in a
//! place a test can read.
//!
//! ⛔ WHY A MANIFEST AND NOT MORE HAND-PICKED CHECKS. `I-CP` compares eight surfaces against a
//! chain-only replay, and those eight were CHOSEN — which is exactly where a gap hides. `struct Node`
//! has 142 fields. A hole in any of the other 134 is invisible to a hand-picked list, and no amount of
//! adding more surfaces one at a time ever proves there are none left.
//!
//! ── THE RATCHET ──────────────────────────────────────────────────────────────────────────────────
//! Two properties, both enforced by the test below:
//!   1. **NO NEW GAP.** Every field of `struct Node` must appear here. A field added to the node
//!      without a classification FAILS the build — so this cannot silently regrow.
//!   2. **THE BACKLOG ONLY SHRINKS.** `MAX_UNCLASSIFIED` is a ceiling that may be lowered and never
//!      raised. It is honest about the 94 fields not yet decided rather than pretending to a coverage
//!      that does not exist.
//!
//! A field is `ChainDerived` if a node fed ONLY BLOCKS must reach the same value — those belong under
//! `Sim::cold_peer_verdict`. It is `LocalCache` if it is legitimately this node's own: a pool, a
//! buffer, an instrument counter, a serve cache. The distinction is the whole class: a `LocalCache`
//! that some door treats as authority is the next D-32.

/// What decides a field's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// The CHAIN decides it. A node fed only blocks must reach the same value, so it belongs in the
    /// cold-peer comparison. If a door reads it as authority, that is correct.
    ChainDerived,
    /// This NODE decides it, legitimately — a pool, a buffer, a cache, a counter, an instrument.
    /// ⛔ A door that treats one of these as authority over a peer is the D-32 shape.
    LocalCache,
    /// NOT YET DECIDED. Counted, capped, and allowed to shrink only. Every entry here is a field
    /// whose authority nobody has ruled on, which means nobody can say whether a door reading it is
    /// reading the chain or reading itself.
    Unclassified,
}

/// Every field of `struct Node`, with who decides it.
pub const AUTHORITY_MANIFEST: &[(&str, Authority)] = &[
    // ── THE PoUW WITNESSES a node happens to still hold for its tip and its fold anchor. LocalCache and
    // not ChainDerived, deliberately: the witness itself is chain data (it rides the block body), but
    // WHETHER THIS NODE STILL HAS IT is a property of what this node retained, not of the chain. That is
    // exactly what `PowWitness::NotServable` exists to say — a node rebuilding a block from retained
    // headers cannot produce one, and a cold peer replaying the chain would legitimately hold neither.
    ("tip_pow_witness", Authority::LocalCache),
    ("anchor_pow_witness", Authority::LocalCache),
    // ── THE RUNNING WHOLE-CHAIN CERTIFICATE and the position it last certified. LocalCache: the object
    // is this node's OWN artifact — two honest nodes at the identical chain position hold different
    // bytes (different proving randomness), so a cold-peer comparison would be wrong to demand equality.
    // ⭐ Its CONTENT is not trusted for being local: a certificate is checked by `verify_whole_chain_cert`
    // against a summary the reader recomputes from the state it is about to install, never by comparison.
    // `certified_blue_work` is bookkeeping about this node's own proving progress and nothing else.
    // ── RECORDS THIS NODE IS PROBING FOR AVAILABILITY. LocalCache, and emphatically so: WHICH records
    // a node is sampling and WHICH pieces it drew are functions of its own private seed and of what it
    // happens to be missing, not of the chain. Two honest nodes at the identical chain position hold
    // different entries here BY DESIGN — that divergence is the security property (a producer that could
    // predict the draw would withhold everything else), so a cold-peer comparison demanding equality
    // would be demanding the opposite of what makes sampling work.
    ("da_sample_pending", Authority::LocalCache),
    ("chain_cert", Authority::LocalCache),
    // DSYNC-SERVE-OFF-LOCK: the served join bundle's wire, rebuilt from `join_frozen` (its source) at most once a minute
    ("join_serve_cache", Authority::LocalCache),
    ("certified_blue_work", Authority::LocalCache),
    // LIVE-GROWTH (8dc7281d): the deep-fork sweep's call counter — a cadence (`node.rs` `DEEP_FORK_SWEEP_EVERY`), counted from this
    // process's own passes, never chain state. MEASURED (testnet gate 20261127-145549, join's replica census): 3/3/2 across three
    // nodes, a joiner having booted later; unclassified, the census read it as a chain-derived field that differed.
    ("deep_fork_sweep_n", Authority::LocalCache),
    // Z2 (lane funds 2026-10-27): a test-only override of the measured mesh size — this node's own knob, never a chain value.
    ("mesh_size_override_for_test", Authority::LocalCache),
    ("relay", Authority::ChainDerived),
    ("mempool", Authority::LocalCache),
    ("validators", Authority::ChainDerived),
    ("finality", Authority::ChainDerived),
    // ⛔ RECLASSIFIED 2026-09-24, and the reclassification is the FIX, not a relabel. This field holds
    // proposals and vote tallies this node has heard by GOSSIP. It was declared ChainDerived while
    // `Node::enact_param` retuned the LIVE `ChainParams` from a local tally — a node authoring a RULE
    // change, which is stronger than authoring a value change. That path is gone: production now calls
    // `evaluate_param_enactment`, which is read-only, and a rule change may only arrive CARRIED BY A
    // BLOCK (`docs/DB154-COMMITTED-NULLIFIER-ROOT.md`).
    //
    // LOCAL-BY-DESIGN: what remains is one node's view of gossiped evidence — genuinely its own, like a
    // mempool. It decides nothing, so two nodes holding different tallies is not a divergence in
    // anything the chain depends on.
    ("governance", Authority::LocalCache),
    ("sites", Authority::LocalCache),
    // `names` and `pending_dir` were fields here (LocalCache): the unpaid sign-up lane's own registry and its staging list.
    // Both left the node with that lane (audit F15, 584b69cb: an entry reaches the directory only as a paid object the
    // fold applies), and their rows stayed behind until this census named them.
    ("directory", Authority::ChainDerived),
    ("order_book", Authority::ChainDerived),
    ("letter_acc", Authority::ChainDerived),
    ("dir_refill_target", Authority::LocalCache),
    ("spine_recent_roots", Authority::LocalCache),
    ("observed", Authority::LocalCache),
    // J19 (lane speed5, 2026-11-18): how many certified bundles THIS node adopted — its own history by definition (a joiner
    // adopted, a replayer never did), read by no verdict; measured DIFFERS 1/1/1 B in the replica census on a joiner.
    ("dsync_adopts", Authority::LocalCache), // its own doc: CACHE-ONLY, this node's knowledge of votes it verified; every STATE reader keeps `finality`
    ("lock_book", Authority::LocalCache), // its own doc: CACHE-ONLY, a count for this node's own wallet page; no fold, block door or pool rule reads it
    ("lock_early", Authority::LocalCache), // verified locks this node cannot count yet, a bounded ring; relearned from gossip
    ("lock_door_tally", Authority::LocalCache), // its own doc: CACHE-ONLY, a readout for this node's operator; no rule reads it
    ("seen_final_path", Authority::LocalCache), // where this node keeps a figure across its own restart (a path); `None` on every test node
    ("carried_ring_commits", Authority::LocalCache), // one adopt's carried history, held until this node's own replay rebuilds its ring and takes it
    ("member_ring_commits", Authority::LocalCache), // §RF-3: the ring's commit per step, same reach and rules as the ring
    // Fields landed 10/22–10/24 without a ruling (census red on fb663c0), each by its own doc comment:
    ("pooled_votes", Authority::LocalCache), // G2: "a cache of the pool, never state" — the carried tally is compared
    ("deferred_votes", Authority::LocalCache), // "process-local by shape"; the tally it feeds IS compared
    ("fold_landing_blue", Authority::LocalCache), // the applying step's merge-set blue, `None` between steps
    ("dsync_covered", Authority::LocalCache), // adopt bookkeeping drained at the ingest door; rides the checkpoint
    ("own_record_path", Authority::LocalCache), // "a path, never state"
    ("reward_recipient_file", Authority::LocalCache), // "a path, never state"
    ("clues", Authority::LocalCache),
    ("peer_dir", Authority::LocalCache),
    ("site_verifier", Authority::LocalCache),
    ("finality_verifier", Authority::LocalCache),
    ("decider_verifier", Authority::LocalCache),
    ("synced", Authority::LocalCache),
    ("last_served_block", Authority::LocalCache),
    ("da_mem", Authority::ChainDerived),
    ("da_wanted", Authority::LocalCache),
    ("sidecar_cursor", Authority::LocalCache),
    ("sidecar_refill", Authority::LocalCache),
    ("sidecar_ask_starved", Authority::LocalCache),
    ("da_wanted_ids", Authority::LocalCache),
    // DB-203/209 (2026-09-25): the ordinals whose rows this node found unjustifiable, with a refusal count,
    // bounded by DA_POISON_TRACKED_MAX. What THIS node could not verify is a property of what it holds, not
    // of the chain — a cold peer fed the same blocks may hold none of them.
    ("da_poisoned_ordinals", Authority::LocalCache),
    // DB-221's `nf_recent` is deleted (DB-353 P2'): the band door's `spent_since` answers its question.
    // DB-226: whether THIS node's accumulator missed a tag the chain settled — a fact about this node's own
    // absorb history (no view, a foreign shard), never read as the chain's state or a peer's.
    ("sparse_acc_stale", Authority::LocalCache),
    ("da_want_seed_cursor", Authority::LocalCache),
    ("da_want_seed_target", Authority::LocalCache),
    ("note_body_want_cursor", Authority::LocalCache),
    ("da_ladder_mem", Authority::ChainDerived),
    ("wanted_ladder", Authority::LocalCache),
    ("own_validator_id", Authority::LocalCache),
    ("da_tags_mem", Authority::ChainDerived),
    ("da_targets_mem", Authority::ChainDerived),
    ("da_ord_mem", Authority::ChainDerived),
    ("da_leafstart_mem", Authority::ChainDerived),
    ("da_ord_rev_mem", Authority::ChainDerived),
    ("da_ord_top", Authority::ChainDerived),
    ("da_macc_rev_mem", Authority::ChainDerived),
    ("da_macc_fwd_mem", Authority::ChainDerived),
    ("da_macc_first", Authority::ChainDerived),
    ("served_membership_acc", Authority::ChainDerived),
    ("da_reads", Authority::LocalCache),
    ("nf_fold_seq", Authority::ChainDerived),
    // `nf_fold_pending` retired (DB-353 §13.5 item 2): the parked-fold stash could never unlock.
    ("pending_fold_evictions", Authority::LocalCache),
    ("wanted_ordinals", Authority::LocalCache),
    ("bucket_ask_last_ms", Authority::LocalCache),
    ("wanted_buckets", Authority::LocalCache),
    // ⛔ J20 (lane speed5, 2026-11-18, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J18/J20): THIS NODE'S starting point, not chain state.
    // READ: no verdict reads it — spend admission checks the live nullifier root only (`nf_absent_by_reconstructed_tip`, fold.rs,
    // "which BASE did you fold from? … deleted"); its readers are the snapshot, its own advance, and the wallet route (rpc_http.rs
    // `/nf_fold_inputs`), where the wallet folds base ⊕ span to THIS node's A_tip — the certified accumulator every node agrees on.
    // A DSYNC joiner installs its adopt-instant base (node/sync.rs), so honest nodes differ (replica census, main ac55b638 + J19:
    // 98 / 98 / 97 B). Making it a function of the chain needs a bound span on the join wire (a network upgrade): recorded as J18.
    ("nf_fold_base", Authority::LocalCache),
    // ⭐ THE PREVIOUS certified fold base, kept for the ONE-BLOCK HORIZON RACE. `nf_fold_base` advances as
    // each block crosses `Dag::horizon_blue_score` — a value every node derives from the same DAG — so a
    // carrier built moments before the step names the base this field holds, and the gate accepts either.
    // Same authority as the field it shadows, and held back from `cold_peer_verdict` for the same stated
    // reason: a DSYNC-jumped node installs its adopted accumulator here, so two honest nodes legitimately
    // hold different values (see the exemption list below).
    ("nf_base_prev", Authority::LocalCache), // J20: the starting point's previous value — the same ruling as `nf_fold_base` above
    // ── Declared 2026-09-22. Each verdict read from the field's writers in `node.rs`.
    // This node's OWN record of which blocks it holds without their data — `insert` on a local miss,
    // `retain` as they arrive. DB-162: it is the set that answers "what am I still missing", and its
    // own doc says it is EMPTY on a healthy mesh. Nothing else reads it as a chain fact.
    ("payload_gap", Authority::LocalCache),
    // The blue score of the CERTIFIED anchor: written from the certified bundle (`anchor_score_from_bundle`) and from
    // the DAG's own node for the common ancestor. LocalCache WITH `certified_anchor` (lane funds 2026-10-27, DB-402 §3:
    // "its own certificate bytes … stays LocalCache with its reason"): the anchor is where THIS node's certification
    // begins — a jumper holds the bundle's anchor, the origin that folded the same chain from genesis holds none.
    // MEASURED (mesh_schedule_search seed 2, final-harness-23.log): party 1 jumped to party 0's bundle and held 7,
    // party 0 held 0, both held ONE spine root and every ordinal above it — the chain value the score was standing in
    // for, compared directly by `cold_peer_verdict` (spine root, `da_ord_mem`, `da_ord_top`). A cold peer replaying the
    // chain holds 0 by construction, which is the manifest's own test for LocalCache.
    ("certified_anchor_score", Authority::LocalCache),
    // A handle to the on-disk window store (`BlockWindow::open(dir)`). Its CONTENT mirrors chain blocks
    // above the DAG horizon, but the store is this node's own bounded cache of them — the pruning
    // formula's local copy, re-installed at restart, never a value the chain decides.
    ("block_window", Authority::LocalCache),
    // A dedup latch for the last shard mesh this node announced, compared and overwritten in place.
    ("last_shard_mesh", Authority::LocalCache),
    // This node's own outbound queue of payout events for its custody lane.
    ("payout_events", Authority::LocalCache),
    ("defi_events", Authority::LocalCache),
    ("defi_intake", Authority::LocalCache),
    // §BR-12 F13 — the serve-side ring of recent contract-state transitions a follower catches up from: what this node
    // filed since it started (its depth is this process's history), never consulted by consensus — the root is the peg's.
    ("contract_leaf_ring", Authority::LocalCache),
    // IonSwap pools: this node's own copy of the contract-state tree and the pool rows. Its owner's sentence: "CACHE-ONLY:
    // it is used only while its tree's root is the ledger's, every settlement formed from it is recomputed by every node
    // against that node's own root, and it un-folds with the fold." The chain's fact is `peg.contract_state_root`.
    ("ion_cache", Authority::LocalCache),
    // The pool leaves the fold step being folded has written so far (what a later settlement of the same step is brought
    // forward over): emptied when a step's objects begin, a function of the block being folded, read by nothing else.
    ("ion_step_writes", Authority::LocalCache),
    // DB-122 F6, and LOCAL BY DEFINITION: it is set from THIS node's own Bitcoin source showing fewer
    // coins than the ledger's reserve. Two honest nodes watching different sources may legitimately
    // differ, which is exactly why it may only refuse this node's own signature and never the chain.
    ("reserve_solvency_hold", Authority::LocalCache),
    // §19.5a: the same F6 hold for Monero's ledger, set from THIS custodian's own Monero wallet balance — local by definition.
    ("xmr_reserve_solvency_hold", Authority::LocalCache),
    // A bounded ring of custody leaf members this node has seen announced.
    ("custody_leaf_ring", Authority::LocalCache),
    // DB-121x. Its own writer doc is explicit: "CACHE-ONLY: a mirror of the custodians' wallets' own
    // state, re-learned from their announcements after a restart; nothing here is decided for the chain."
    ("xmr_custody_ring", Authority::LocalCache),
    // The DSOL token registry was a field here (`dsol_registry`, ChainDerived). A-F31 (2026-11-11): it was chain state the
    // fold wrote and no rewind restored, so it moved INTO the journaled ledger (`peg`, `PegLedger::dsol_tokens`), which is
    // declared below. Its cold-peer comparison is untouched: `cold_peer_verdict` reads `Node::dsol_registry_root()`.
    // D-43c: a memo of deletions applied during THIS node's own sync window (a jump or restart
    // heal), cleared when it owes nothing — never read as the chain's state, only as "what I already
    // applied"; a cold peer owes nothing and holds none.
    ("pending_tags", Authority::LocalCache),
    ("pending_credit_notes", Authority::LocalCache),
    // ⭐ §BA — the framed objects that justify this node's staged credits. `LocalCache` like its note
    // sibling above and for the identical reason: it is a STAGING lane, drained into the very next block
    // this node produces, and nothing reads it as truth. Once the block carries it, the JUSTIFICATION is
    // chain-derived — every peer re-runs `admissible` + `carried_note_payloads` on the carried bytes —
    // which is exactly the direction this manifest exists to keep straight.
    ("pending_credit_justifiers", Authority::LocalCache),
    // §CE diagnostic — a pure counter of how many times the cover-conf accumulator advanced. `LocalCache`
    // because nothing reads it as truth: it exists so a convergence report can say whether two nodes
    // differed on a VALUE or on a COUNT, which is what separated a content bug from a route bug.
    ("nf_conf_advances", Authority::LocalCache),
    // D-43 re-entrancy latch for the deferred-deletion drain. `LocalCache`: it guards a call depth, holds
    // no chain fact, and nothing reads it as truth.
    // D-43 edge-triggered print latch for the root-drift refusal. `LocalCache`: it throttles a log line
    // and holds no chain fact.
    ("account_buckets", Authority::ChainDerived),
    ("account_acc", Authority::ChainDerived),
    ("membership_tip_prev", Authority::ChainDerived),
    ("membership_tip_root", Authority::ChainDerived),
    // 2026-10-04: record addresses are a 56-bit fold of the BLOCK ID (`Dag::record_key`), so the highest and lowest this
    // node wrote are a function of which records it holds — a DSYNC joiner holds none from before its anchor, by design.
    // The cursors bound this node's own serve walks; the chain does not decide them (d47 / d49 / d50 measured it).
    ("da_top", Authority::LocalCache),
    ("da_base", Authority::LocalCache),
    ("pending_bucket", Authority::LocalCache),
    ("note_target_addr", Authority::LocalCache),
    ("targets_claimed_total", Authority::LocalCache),
    ("inflight_tx_ids", Authority::LocalCache),
    // lane agg / lane bundle (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12-§14): what THIS node took on to prove — the payments
    // pushed to it, the bundles over them, and whether it runs a worker. No peer holds or reads them; a restart drops them and
    // each payment's origin pushes it again. (A-F76's census half: `agg_held` was excluded with no ruling here.)
    ("agg_held", Authority::LocalCache),
    ("agg_bundles", Authority::LocalCache),
    ("bundle_worker", Authority::LocalCache),
    ("wanted_record_ids", Authority::LocalCache),
    ("wanted_block_slots", Authority::LocalCache),
    ("freshly_filed_buckets", Authority::LocalCache),
    ("da_secret", Authority::LocalCache),
    ("served_seq", Authority::ChainDerived),
    ("fold_chain_tip", Authority::LocalCache),
    ("spine_stale", Authority::LocalCache),
    ("fold_reorgs", Authority::LocalCache),
    ("certified_anchor", Authority::LocalCache),
    ("certified_prefix_len", Authority::Unclassified),
    ("fold_waits", Authority::LocalCache),
    // ⭐ DB-163/DB-164 WEDGE DETECTION — every one of these is LOCAL BY CONSTRUCTION, and that is the
    // right answer rather than a convenient one. They measure THIS node's own inability to make progress:
    // which block ITS fold is waiting on, how many of ITS passes did nothing, how long ITS record wants
    // have gone unanswered. Two honest nodes holding the same blocks SHOULD differ here — one may be
    // wedged while the other is not, which is exactly the state these exist to surface. A field that
    // measures a node's own health is not a claim about the chain, and declaring it ChainDerived would
    // make `cold_peer_verdict` report every healthy mesh as divergent.
    ("fold_wait_on", Authority::LocalCache),
    ("fold_no_progress_passes", Authority::LocalCache),
    ("fold_progress_since_len", Authority::LocalCache),
    ("da_want_stall_passes", Authority::LocalCache),
    ("record_ask_nonce", Authority::LocalCache),
    ("da_want_fingerprint", Authority::LocalCache),
    ("da_want_stall_since_ms", Authority::LocalCache),
    ("row_hint_mismatches", Authority::LocalCache),
    ("unfolded_blocks", Authority::LocalCache),
    // ⛔ DB-358 — the fold-time respend journal: this node's record of its own fold decisions, kept for a rewind. (The
    // arrival-time `respend_memos` and `respend_claims` are deleted from the struct — the canonical fold decides.)
    ("respend_journal", Authority::LocalCache),
    // the locator tags that left a record with its stripped notes, beside the journal's notes, for the same rewind
    ("respend_tag_journal", Authority::LocalCache),
    // Declared 2026-11-09 (the census named them undeclared). Each is THIS node's operation, never a chain fact a peer reads
    // as truth: its own view of the mix network while Tor is down; its own pushed txs awaiting an echo and the wallet
    // publications it pushes; a counter; a span read cache; the join-proof material it keeps to prove its OWN fold to a
    // joiner (the joiner verifies it, never trusts it) with its batch buffer and frozen bundles; and the private-sharding
    // evidence, shard fetches and band copaths it gathers as a prover. A cold replayer rebuilds none of them from blocks.
    ("band_mix", Authority::LocalCache),
    ("own_unechoed", Authority::LocalCache),
    ("wallet_publications", Authority::LocalCache),
    ("orphans_absent_parent", Authority::LocalCache),
    ("nf_span_cache", Authority::LocalCache),
    ("join", Authority::LocalCache),
    ("join_step_buf", Authority::LocalCache),
    ("join_frozen", Authority::LocalCache),
    ("join_last_freeze", Authority::LocalCache),
    ("nf_evidence_cache", Authority::LocalCache),
    ("nf_shard_fetch", Authority::LocalCache),
    ("nf_band_gathered", Authority::LocalCache),
    ("nf_band_wants", Authority::LocalCache),
    ("respend_reach", Authority::LocalCache),
    ("folded_floor", Authority::LocalCache),
    ("payment_receipts", Authority::LocalCache),
    ("note_clues", Authority::LocalCache),
    ("note_clue_fifo", Authority::LocalCache),
    ("bond_locked", Authority::ChainDerived),
    ("bond_height", Authority::ChainDerived),
    // ⭐ DB-274 P2 (§8.7), ruled 2026-09-30 (lane-db224-carriage, on lane-wallet's attribution). `unbonding` is the
    // bond class's own state, applied at the canonical fold and carried by the checkpoint and the certified bundle
    // (bound in `sync_binding`), so a node fed only blocks reaches it: ChainDerived, and COMPARED (`Sim::cold_peer_verdict`,
    // `unbonding_census`). The journal and its floor are this node's record of its own fold steps kept for a rewind — the
    // `respend_journal` / `folded_floor` ruling: LocalCache.
    ("unbonding", Authority::ChainDerived),
    ("bond_fold_journal", Authority::LocalCache),
    ("bond_journal_floor", Authority::LocalCache),
    // DB-274 (dir_set, 2026-10-04): the directory's fold journal — before-images for the rewind, the same class as the
    // bond class's journal above (the directory ITSELF is `ChainDerived`, compared by `census_cmp!(dir_acc)`).
    ("dir_fold_journal", Authority::LocalCache),
    ("dir_journal_floor", Authority::LocalCache),
    // Audit F15 / F16 (2026-11-10/11), each by its own doc comment. `dir_open_step`: the before-images of the paid
    // entries the block BEING FOLDED has applied so far; closed into `dir_fold_journal` when the block's record takes
    // its position, or un-done if the fold is refused. It never outlives one block's fold, and what it journals (the
    // directory) is `ChainDerived` and compared by `census_cmp!(dir_acc)`.
    ("dir_open_step", Authority::LocalCache),
    // `dir_refill_stage` / `dir_refill_stage_acc`: the entries a joiner has been SERVED toward the certified directory
    // word and their running fold, kept apart from the directory until the whole sequence folds to that word (then
    // adopted, or dropped whole). Nothing reads them as the directory; a restart loses them and the refill asks again.
    ("dir_refill_stage", Authority::LocalCache),
    ("dir_refill_stage_acc", Authority::LocalCache),
    // A-F38: `dir_refill_held` / `dir_refill_held_closed`: the directory writes this node's own fold made while a
    // refill was owed, held in fold order and replayed through the apply gate when the certified sequence is in place.
    // Nothing reads them as the directory; what they become (the directory) is `ChainDerived` and compared by
    // `census_cmp!(dir_acc)`. A restart loses them with the owed word.
    ("dir_refill_held", Authority::LocalCache),
    ("dir_refill_held_closed", Authority::LocalCache),
    // ⭐ DB-353 (landing 1 + part (a)), ruled 2026-09-30: the band door is READ BY NOTHING THAT DECIDES A SPEND until
    // landing 2 — the `sparse_work` ruling, LocalCache. Landing 2 (docs/DB-353-BAND-DOOR-SPEC.md §13) makes the band the
    // set a spend is judged against and carries it in the certified bundle (P5); it is re-ruled ChainDerived THERE, with a
    // cold-peer comparison of `band_root_at` over the steps both parties applied (a pointer waiting on a body it lacks is
    // local timing, never a different band).
    ("band_door", Authority::LocalCache),
    // DB-353 §11.13: the prover's overlay of noted steps beyond the pointer — a wrong cursor yields refused proofs, never
    // a band; rebuilt from the view and the pending sets.
    ("band_cursor", Authority::LocalCache),
    // DB-353 P7: a count of steps THIS node applied since it started — its own progress, never the chain's state.
    ("band_steps_applied", Authority::LocalCache),
    // ⭐ DB-223 Q2, ruled 2026-09-30: `completed_windows` is a ring with the anchor ring's reach, purge and adopt rules — the
    // `spine_recent_roots` ruling; `window_index` is the serving-tier path-refresh index whose HELD shards the holder
    // policy picks per node (a wallet verifies what it is served against the ring digest); `public_id` is this node's own
    // onion peer id. All three: this node's, LocalCache.
    ("completed_windows", Authority::LocalCache),
    ("window_index", Authority::LocalCache),
    ("public_id", Authority::LocalCache),
    ("spend_frontier", Authority::ChainDerived),
    ("root_history", Authority::ChainDerived),
    ("nf_rebuild_failed_at", Authority::LocalCache),
    ("carrier_slot", Authority::LocalCache),
    ("pending_block_nullifiers", Authority::LocalCache),
    ("mined_tx_nfs", Authority::LocalCache),
    ("evicted_by_block", Authority::LocalCache),
    // DB-389: the fold's verdict on a HELD block's carried objects — kept only for blocks in `evicted_by_block`, so WHICH
    // blocks have an entry is a property of what THIS node pooled and evicted; a cold peer that never pooled those txs holds
    // none. The verdict itself is the fold's (chain) answer; the map is this node's pool bookkeeping. LocalCache.
    ("fold_verdicts", Authority::LocalCache),
    // lane a 2026-10-22 (G7, the manifest completeness pin): five fields added since the last ruling, each this NODE's.
    // Two are test knobs (`*_for_test`), the rest are caches or observations the restart census lists as VOLATILE / NODE_LOCAL.
    ("band_autoprove_for_test", Authority::LocalCache),
    ("template_double_for_test", Authority::LocalCache),
    // lane a 2026-10-26: §RF-3's test knob (e34470f) — whether THIS test node lays its ledger real or as the bound double.
    // `#[cfg(test)]`, armed per mesh; no block carries it and a node binary has no such field. LocalCache.
    ("real_ledger_for_test", Authority::LocalCache),
    ("band_benched", Authority::LocalCache),
    ("note_backfill_cursor", Authority::LocalCache),
    ("span_close_landing", Authority::LocalCache),
    ("reorg_heal_fired", Authority::LocalCache),
    ("da_stale_row_refusals", Authority::LocalCache),
    ("note_body_target", Authority::LocalCache),
    ("note_body_acc_before", Authority::LocalCache),
    ("note_body_acc_target", Authority::LocalCache),
    ("roots_run_closed_target", Authority::LocalCache),
    ("roots_run_spine_before", Authority::LocalCache),
    ("roots_run_spine_target", Authority::LocalCache),
    ("roots_run_cursor", Authority::LocalCache),
    ("roots_run_windows", Authority::LocalCache),
    ("roots_run_origin_windows", Authority::LocalCache),
    ("sparse_acc", Authority::ChainDerived),
    ("sparse_work", Authority::LocalCache),
    ("nf_blocks", Authority::ChainDerived),
    ("nf_leaves", Authority::ChainDerived),
    ("nf_unspent_acc", Authority::ChainDerived),
    ("nf_cover_conf_acc", Authority::ChainDerived),
    ("peg", Authority::ChainDerived),
    ("custodian_opening_seal", Authority::LocalCache),
    // The peg-in attestation lane's working state (`crate::peg_attest`): proposals this node saw or
    // authored with the signatures gathered so far, the deltas of objects it published and no block has
    // carried yet, and where recent mints landed for the wallet's poll. Every one of them is an
    // instrument of THIS node's gathering — the chain decides the mint (`peg`), never these.
    ("peg_attest_pending", Authority::LocalCache),
    ("peg_in_published", Authority::LocalCache),
    ("peg_out_published", Authority::LocalCache),
    ("peg_minted_heights", Authority::LocalCache),
    // This node's own signed seat REQUEST, kept so it can be re-pooled after a jump (§DB) — the
    // validator set itself is chain-derived (`validators`); this is the request, never the seat.
    ("own_membership_bond", Authority::LocalCache),
    // The peg-OUT attestation lane's working state — the mirror of `peg_attest_pending`: proposals seen
    // or authored with the signatures gathered so far. An instrument of gathering; the chain decides.
    ("peg_out_attest_pending", Authority::LocalCache),
    // Where this custodian persists its own sealed opening between runs (§CZ-b): a path, no state.
    ("custody_opening_path", Authority::LocalCache),
    ("custodian_opening_history", Authority::LocalCache),
    // §BR-3 17.6 (stakers' half): this custodian's sealed opening of the stakers' pool paid-out total, and its rewind
    // history — the mirror of `custodian_opening_seal`; the chain decides the commitment (`peg`), never these.
    ("custodian_paid_seal", Authority::LocalCache),
    ("custodian_paid_history", Authority::LocalCache),
    // §BR-9a: this custodian's own epoch seed shares, captured from each `Class::EpochKeyDeal` the fold applies — its private
    // key material, the mirror of a share sealed to it on the chain. The chain decides the epoch key (`peg.epoch_keys`);
    // no door reads these as authority over a peer, and no other node can hold them.
    ("epoch_seed_shares", Authority::LocalCache),
    ("unapplied_shell_floor", Authority::LocalCache),
    ("unapplied_shell_ceiling", Authority::LocalCache),
    ("unapplied_shell_count", Authority::LocalCache),
    ("applied_one_time_ids", Authority::LocalCache),
    ("wrapped_opening_seals", Authority::LocalCache),
    ("miner_seed", Authority::LocalCache),
    // ⭐ SATOSHI §8.1 — WHO this node's rewards are sealed to (the operator wallet's public scan key, a reward-only locator key
    // and the next clue index). The operator's own payout destination: two honest nodes hold different recipients, and the
    // chain decides only whether a reward is VALID (the issuance door), never whose it is. LocalCache.
    ("reward_recipient", Authority::LocalCache),
    ("l2_state_root", Authority::ChainDerived),
    ("settlement_verifier", Authority::LocalCache),
    ("fee_seed", Authority::LocalCache),
    ("fee_mlkem_pub", Authority::LocalCache),
    ("fee_mlkem_sec", Authority::LocalCache),
    ("pow_miner", Authority::LocalCache),
    ("persist_path", Authority::LocalCache),
    // ⛔ `params` WAS HERE AND THE FIELD IS NOW GONE (2026-09-09). It was a SECOND copy of the
    // consensus rules — written once at construction, never by `set_params` — and the two gates that
    // read it (the orphan-depth width, and the UNBOND LOCK on bonded collateral) kept enforcing the
    // rules the node booted with while every peer moved on. Classifying it `ChainDerived` was correct
    // and did not save it: the class says where the truth LIVES, not that a given read goes there.
    // The rules now have exactly one reader, `Node::params()`, which reads the DAG. Pinned by
    // `the_chain_rules_have_exactly_one_reader_never_a_second_local_copy` below.
    // ── DB-115 (2026-09-20): NINE FIELDS THAT HAD NEVER BEEN CLASSIFIED. The gate was red on all of them,
    // and the classification is the point, not the green: every one is LocalCache, and each says WHY in the
    // terms this manifest cares about — "would two honest nodes at the identical chain position hold the
    // same bytes?" Where the answer is no, the field is this node's own and may never be read as truth.
    //
    // WHOLE BLOCK BODIES THIS NODE HAPPENS TO STILL HOLD — the `tip_pow_witness` reasoning exactly. The
    // bodies are chain data, but WHETHER THIS NODE RETAINED ONE is a property of its own ring, not of the
    // chain: `body_ring` evicts oldest-first at BODY_RING_DEPTH and `anchor_block_full` keeps exactly one.
    // A cold peer replaying the same chain would legitimately hold neither, and both are re-pullable.
    ("anchor_block_full", Authority::LocalCache),
    // ARRIVAL BUFFERS — what reached THIS node and in what order. `unapplied_shell_ids` is the shells it has
    // not applied yet; `parked_votes` is votes that landed before the block they name (stride-1 voting, run
    // 30). Two honest nodes differ here purely by network timing, and both drain as the missing piece lands.
    ("unapplied_shell_ids", Authority::LocalCache),
    ("parked_votes", Authority::LocalCache),
    // THIS NODE'S OWN KEY MATERIAL. `custodian_identity` pairs its bonded id with the ML-KEM-768 decryption
    // key that opens the sealed delta THE BLOCK CARRIES. The id is chain-derived (a bond seat), but the
    // secret half is this process's alone and must never be compared against a peer. `wrapped_opening_path`
    // is a filesystem path, not state at all.
    ("custodian_identity", Authority::LocalCache),
    ("wrapped_opening_path", Authority::LocalCache),
    // GATHERING AND IN-FLIGHT PUBLISH STATE. `peg_requests` holds the peg requests this node is working;
    // `wrapped_published` holds wrapped mints it published that no block has carried yet. Both are
    // instruments of getting a transition ONTO the chain — the ledger moves only at the block door, on
    // every node alike. ⭐ DB-113 is the standing warning attached to this class: the redeem twin of these
    // maps had an oldest-first eviction that deleted a node's own in-flight work, and the fix was to retain
    // every UNRESOLVED entry at any age and retire only what the chain had settled.
    ("peg_requests", Authority::LocalCache),
    // §BR-3 17.5 (2026-10-29): the custody signature books of the repayment and pot-fill lanes — gathering caches; the chain
    // decides only through the framed TheftRepayment / PotFill objects a block carries (each verified against the node's own
    // ledger at the fold).
    ("theft_repay_book", Authority::LocalCache),
    ("pot_book", Authority::LocalCache),
    // §BR-4 B4-3 (2026-10-29): the unit-close lane's custody signature book — a gathering cache; the chain decides only through
    // the framed UnitClose a block carries (verified against the node's own ledger at the fold).
    ("unit_close_book", Authority::LocalCache),
    // §BR-2 (2026-10-28): the depositor sweep authorizations this custodian staged from the sealed requests it acted on — a
    // pass-through of a chain object's sealed leg into the custodian's own propose call; the request re-stages it after a
    // restart (`custodian_act_on_request`), and every attestor judges the authorization carried in the leg itself.
    ("deposit_sweeps", Authority::LocalCache),
    ("wrapped_published", Authority::LocalCache),
    // A WALL-CLOCK STAMP for autosave pacing. Local by definition; nothing reads it as truth about anything.
    ("last_autosave", Authority::LocalCache),
    // ── NINE FIELDS ADDED 9/25–9/27 WITH NO RULING. Both manifest pins were red on them (lane-db224-carriage,
    // 2026-09-27; measured on the q14 and q15 fuzz runs). Each is ruled here from the field's own doc in node.rs. An
    // owner who reads its field differently re-rules it.
    // Fold REWIND AIDS (DB-268). A ring of this node's own spine frontiers at its last 64 fold steps, and the certified
    // base its last adopt or restart installed. WHICH frontiers a node holds depends on where it adopted and how far it
    // has folded since. A cold peer at the same tip holds a different ring. The spine itself is compared elsewhere.
    ("spine_recent_frontiers", Authority::LocalCache),
    // §19.4: the frontier this node's fold stood at on its newest epoch anchor — what its OWN wallet's claim leg is proven
    // against. A cache: the anchors themselves are chain state (`peg.epoch_anchors`); a restart refills this at the next one.
    ("epoch_anchor_frontier", Authority::LocalCache),
    // §19.5b: this custodian's rewind ring for its Monero-ledger opening (the native ring's twin) — its private witness.
    ("xmr_opening_history", Authority::LocalCache),
    ("fold_checkpoint", Authority::LocalCache),
    // A PUBLICATION QUEUE (DB-266): caught conflicting votes waiting to be paired and published as evidence. The
    // slashing it leads to moves only when a block carries the evidence. Its doc says: "A publication queue, not state."
    ("pending_equivocations", Authority::LocalCache),
    // FOLD BOOKKEEPING of this node's own A_tip progress. DB-270's per-block fold-base generation stamps, for blocks not
    // yet in the window. DB-246's ring of the last blocks THIS node folded, reset whenever the accumulator is replaced
    // wholesale. Both follow this node's adopt and fold history, not the chain alone.
    ("nf_unfolded_gen", Authority::LocalCache),
    // G2g-r2a: an adopt's fetch queue toward the certified base — the base it switches to is `nf_fold_base` (ChainDerived).
    ("nf_fold_base_pending", Authority::LocalCache),
    ("nf_recent_folds", Authority::LocalCache),
    // A DERIVATION CACHE (DB-248): this node's own roots for the open roots run, derived once per run and dropped with
    // the span.
    ("roots_run_own_cache", Authority::LocalCache),
    // A GOSSIP CACHE (DB-240): the current epoch's price quotes. The mark it feeds rides a block, and a restart
    // re-gathers the quotes.
    ("quote_book", Authority::LocalCache),
    // THE OPERATOR'S OWN PRICE SOURCE (DB-240): what this validator quotes, set from its own configuration. A quote is one
    // signed input to a mark the CHAIN tallies at ≥ 2/3 of bond; the source never decides a price by itself.
    ("relay_answers", Authority::LocalCache),
    // LIQUIDATION §10 — the CUSTODIAN's private openings of the pool words (live and per closed epoch) and the file they
    // persist to: a custodian secret, exactly like `custodian_opening_seal`; the chain holds only the commitments, which
    // the `pools` / `pool_closes` peg fields carry and the peg comparison checks.
    ("pool_openings", Authority::LocalCache),
    ("pool_close_openings", Authority::LocalCache),
    ("pool_opening_path", Authority::LocalCache),
    // LIQUIDATION §10.2 (4) — a GOSSIP CACHE of bonded custodians' liquidation signatures, gathered against this node's
    // own state; the liquidation it feeds rides a block and the door re-tallies it there.
    ("liquidation_book", Authority::LocalCache),
    // SAFE AT SCALE, stage three — GOSSIP CACHES of custodians' signatures, gathered against this node's own chain:
    // the key lane's (a take or a retire of a vault's custody key) and the cost lane's (a foreign fee a vault's
    // custody paid). The objects they feed ride a block and the ledger's doors re-tally them there.
    ("vault_key_book", Authority::LocalCache),
    ("reserve_cost_book", Authority::LocalCache),
    ("vault_merge_book", Authority::LocalCache),
    // spec §3g.1: the rebalance lane's gossip book and relay ring — signatures over statements each node forms from its own chain;
    // every step it gathers for rides a block (`Class::VaultRebalance`).
    ("rebalance_book", Authority::LocalCache),
    ("rebalance_relayed", Authority::LocalCache),
    // SAFE AT SCALE, stage three — this custodian's own view of where ITS Bitcoin source shows coins (by custody leaf):
    // a reading of a foreign chain that decides only what this custodian signs; the chain's key record is `PegLedger::vault_keys`.
    ("vault_key_coin_view", Authority::LocalCache),
    // …and of whether ITS current Monero wallet holds the whole reserve its opening counts (the same kind of reading).
    ("xmr_reserve_whole", Authority::LocalCache),
    // DB-274 P4b — the fold's before-image journal of the peg ledger and its floor: an UNDO log for a fold reorg, never
    // read as the chain's state (the ledger it restores is the chain-derived one).
    ("objects_fold_journal", Authority::LocalCache),
    ("objects_journal_floor", Authority::LocalCache),
    // A-F42 (lane vaults, 2026-11-11) — the validator rows an objects fold step wrote (a delegation, a yield claim), as they
    // stood before it: an UNDO log the step's own bond journal takes (`bond_step_at_fold`) and a rewind restores, scoped to
    // one fold step and empty between steps; never read as the chain's set (the set it restores is the chain-derived one).
    ("objects_vids_before", Authority::LocalCache),
    // (DB-290's `sparse_pivot_tail` / `sparse_pivot_expired` and DB-316c's `sparse_pivot_candidate` are deleted from the
    // struct.)
    // DB-339 part 3 (lane-db224-carriage): the ids of the blocks this node applied before its pivot, captured at restore so
    // a warm can heal from its own copies. A heal installs only on an exact root match, so nothing reads it as truth.
    ("pivot_span", Authority::LocalCache),
    // DB-332: this node's own OLI serve index, rebuilt off-lock from data it serves — a serve cache.
    ("oli_serve_cache", Authority::LocalCache),
    // DB-335: which chain objects THIS node built and pooled, and when it last re-sent each — relay bookkeeping; an
    // entry leaves with its transaction, and no door reads it as evidence that anything happened.
    ("own_publications", Authority::LocalCache),
    // DB-310b: which ladder spans a PEER served (the untrusted writer) — provenance over `da_ladder_mem`, so the span
    // close never treats them as authorities.
    ("da_ladder_adopted", Authority::LocalCache),
];

/// The ceiling on `Unclassified` entries. **MAY BE LOWERED, NEVER RAISED.**
///
/// Lowering it is the work: decide a field's authority, move it to `ChainDerived` (and add it to
/// `Sim::cold_peer_verdict`) or to `LocalCache`, then drop this number. Raising it would mean a new
/// field arrived unclassified, which is the gap this file exists to close.
pub const MAX_UNCLASSIFIED: usize = 4;

/// The `ChainDerived` fields `Sim::cold_peer_verdict` ACTUALLY COMPARES today.
///
/// ⛔⛔⛔ THE GAP THIS EXISTS TO MEASURE. Declaring a field `ChainDerived` is a claim: *a node fed only
/// blocks must reach this same value.* Nothing enforces that claim until something COMPARES it against
/// a chain-only replay. A field declared chain-derived and never compared is WORSE than an
/// unclassified one, because it reads as covered.
///
/// This is the honest link between the manifest and the oracle. The number it produces —
/// `ChainDerived` minus these — is the real remaining surface of the "local state read as truth"
/// class, and it only shrinks.
pub const COLD_PEER_COVERED: &[&str] = &[
    "da_leafstart_mem",
    "da_macc_rev_mem",
    // ⭐ 2026-09-24: unblocked by `Sim::new_folding_at_tip` — the fold depth was why these were always
    // empty. Compared as one sorted coordinate set by `cold_peer_verdict`.
    "da_macc_fwd_mem",
    "order_book",
    "letter_acc",
    "directory",
    "validators",
    "peg",
    // batch 2 — added with their comparisons and refutations together, 2026-09-08
    "account_acc",
    "spend_frontier",
    "nf_cover_conf_acc",
    "da_ord_mem",
    "da_ord_top",
    // batch 3 — the spend gate's own inputs and the rules every gate is measured against
    "nf_leaves",
    "nf_blocks",
    "membership_tip_root",
    "membership_tip_prev",
    "l2_state_root",
    // batch 4 — added with their comparison in `cold_peer_verdict` together, 2026-09-22
    // (`certified_anchor_score` left this list 2026-10-27 with its LocalCache ruling above)
    // `dsol_registry` was compared here as a Node FIELD; the field moved into `peg` (A-F31, 2026-11-11). The comparison
    // itself still runs in `cold_peer_verdict` through `dsol_registry_root()`, so the registry divergence check is not
    // weakened by the move, only re-addressed (the `params` precedent below).
    // `params` was compared here as a Node FIELD; the field is deleted. The comparison itself is
    // untouched and still runs in `cold_peer_verdict` — it reads `params()`, the accessor — so the
    // chain-rules divergence check is not weakened by the deletion, only re-addressed.
    // batch 4 — the serve position and the finality height
    "served_seq",
    "finality",
    // already compared by the verdict's own tail and by `nullifier_root()`, recorded here so the
    // coverage count matches what the code actually does rather than what was last remembered
    "nf_unspent_acc",
    // ── batch 5, 2026-09-09 — the chain itself, the record-space bounds, the anchor sets, the bonds
    // and the per-record sidecar stores. Each landed WITH its comparison in `Sim::cold_peer_verdict`
    // and its refutation in `harness::fuzz::selfproof`, and each refutation asserts the mutation
    // actually moved the projection before asserting the detector fired.
    "relay",
    "nf_fold_seq",
    "root_history",
    "account_buckets",
    "bond_locked",
    "bond_height",
    // DB-274 P2: compared by `census_cmp!(unbonding_census)` in `Sim::cold_peer_verdict` (2026-09-30).
    "unbonding",
    "da_tags_mem",
    "da_ord_rev_mem",
    // ALREADY compared before this batch and simply not recorded: `membership_tip()` returns
    // `(membership_tip_prev, membership_tip_root, served_membership_acc)` and the batch-3 comparison
    // reads the whole tuple, so the served-prefix accumulator has been under the oracle all along.
    // Recorded now with its own refutation, for the same reason `unspent_note_root` was: a manifest
    // that understates the code is as untrustworthy as one that overstates it.
    "served_membership_acc",
];

/// The ceiling on `ChainDerived` fields NOT yet compared against a chain-only replay.
///
/// PAST-CHATS-CHECKED / prior art: this is the same shrink-only ratchet as `MAX_UNCLASSIFIED` above
/// and as the tree's existing `store_bound_manifest_tests` bound manifest — a declared backlog that a
/// test holds and that may only be lowered. Not a new mechanism, the established one applied to a
/// second question.
///
/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT, taken 2026-09-09 from this file:
///     49 fields declared `ChainDerived` − 35 named in `COLD_PEER_COVERED` = 14 not yet compared.
/// (44 at 6 covered; 39 at 11; 33; 29; now 14 as batch 5 lands with its refutations. Batch 5 moved
/// FIFTEEN fields; the declared total fell 50 -> 49 on the same day because the `params` FIELD was
/// deleted outright — its comparison still runs, reading the accessor — so the backlog is 14 either
/// way. The arithmetic is written out because a ceiling that does not reconcile with the two lists
/// above it is exactly the drift this file exists to prevent.)
/// It is written down rather than computed so that ADDING a chain-derived field cannot silently raise
/// the backlog: a new declaration pushes the live count past this ceiling and fails.
///
/// **MAY BE LOWERED, NEVER RAISED.** Lowering it is the work: add the field to
/// `Sim::cold_peer_verdict`, add its refutation to `harness::fuzz::selfproof`, then drop this number.
///
/// ─────────────────────────────────────────────────────────────────────────────────────────────────
/// 2026-09-11 (D-41 class): `da_nf_mem` (compared) and `da_nacc_rev_mem` (held back) are DELETED
/// outright — the per-block DA-nf shard had three key spaces and the acc->seq index existed only to
/// let the spend gate sweep it; the gate now admits at the live accumulator alone. 49 → 47 declared,
/// 35 → 34 compared, backlog 14 → 13.
///
/// ⛔⛔⛔ THE REMAINING 13 ARE NOT "NOT DONE YET" — NINE OF THEM WERE MEASURED AND FOUND *NOT*
/// DERIVABLE FROM THE CHAIN. That is a finding about the CLASSIFICATION, not about the backlog, and
/// it is written here because a wrong ruling is worse than an honest "not yet". Measured 2026-09-09
/// by reading each candidate projection on a live party AND on a chain-only replay across six
/// schedules (baseline, restart seam, jump seam, three-party out-of-order, receive/spend/forget/forge,
/// drop-then-burst):
///
/// * `blocks_note_applied` (DELETED 2026-10-22, DB-402 R1 — it had no reader; the ask resume point is the NODE_LOCAL
///   `note_backfill_cursor`, the debt is the by-id set `payload_gap`) — **DIFFERED ON EVERY HONEST SCHEDULE.** Read
///   cold=4/18/32/18/8/14 against party0=2/3/16/15/7/10: a backfill CURSOR ("how far my walk has got"), not chain state.
/// * `sparse_acc` — DIFFERS on 3 of the 6. ⛔⛔⛔ THIS EXEMPTION IS A **TRACKED DEFECT (DB-154)**, NOT A
///   LEGITIMATE DIFFERENCE, AND CALLING IT ONE IS HOW IT SURVIVED. The field is declared `ChainDerived`
///   because that is its CONTRACT; production does not currently honour it.
///
///   Production advances `sparse_acc` as a RUNNING LOCAL ACCUMULATOR over the order blocks ARRIVE. Two
///   devices on a GHOSTDAG mesh never share that order, so the value islands — MEASURED 2026-08-14:
///   *"A folded 47 blocks, B folded 2 with 32 parked, `nf_root_agree=false` — while `nf_acc_agree=TRUE`
///   on the very same pair."* `nullifier_root()` was moved off it in response, onto the A_tip SUM.
///
///   ⛔ THAT IS THE LOCAL-STATE-AS-TRUTH CLASS THIS WHOLE MANIFEST EXISTS FOR. The test for a legitimate
///   cache is "state is a FUNCTION OF THE CHAIN": two nodes holding the same blocks compute the same
///   value. An arrival-ordered accumulator fails it by construction — it caches no chain value, it IS a
///   private opinion. And the nullifier set is the SPEND AUTHORITY, so a gate consulting it can admit on
///   one node and refuse on another with the disagreement never travelling: the 2026-09-03 DEX
///   double-payout shape at mesh level ([[feedback_local_node_deciding_truth_trap]]).
///
///   ⛔ TWO QUANTITIES, AND CONFLATING THEM IS WHAT KEEPS DB-154 SHUT (I did it once, 2026-09-24):
///     • SET of nullifiers → tree root: ORDER-FREE. Measured, `nf_sparse::set_determined_root_tests` —
///       three permutations agree and adding a tag moves it. `fold_sparse` places a tag where its own
///       BITS say, so insertion touches only that tag's own path and cannot move a copath.
///     • running LOCAL accumulator over ARRIVAL order: ORDER-DEPENDENT. This is what islanded.
///   So a committed Merkle root IS reachable — as a function of the block's OWN PAST (selected parent's
///   committed root + its mergeset), never of arrival order. Pinned:
///   `nf_sparse::db154_block_past_root_tests` and `nf_sparse::fold_block_tags_into_root`.
///   Design + build order: `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`.
///
///   THIS ENTRY MOVES OUT OF THE EXEMPTION LIST WHEN DB-154 LANDS — it is not permitted to settle here.
/// * `da_mem`, `da_ladder_mem` — retention is a LOCAL decision. `drop_record_bytes_if_unreferenced`
///   is gated on `record_is_wanted` (this node's want set) and releases any row it can regenerate;
///   `release_unreferenced_ladder_spans` keeps only what the live position references. CONTENT
///   chain-derived, RETENTION not.
/// * `nf_base_prev` — the previous `nf_fold_base`, written by the same two writers (the horizon step and
///   the DSYNC adopt). It inherits its sibling's exemption exactly: a jumped node installs its adopted
///   accumulator here too, so honest nodes differ.
/// * `nf_fold_base`, `da_macc_first` — both are installed BY A DSYNC ADOPT (`letter_acc_covered` was deleted 2026-09-11, D-49b)
///   and are, in the fields' own words, what "a jumped node cannot recompute from history". Two
///   honest nodes legitimately hold different values.
/// * `governance` — **NO BLOCK FOLD EXISTS.** The only writers are `Node::propose_param` and
///   `Node::vote_param` (RPC/gossip); nothing applies a governance set from a block. That is the
///   `POST /register_wrapped_asset` shape exactly — kill-list item 5 — at a second door.
///
/// The other four (`da_targets_mem`, `da_leafstart_mem`, `da_macc_fwd_mem`, `da_macc_rev_mem`) are
/// believed chain-derived and are held back for a MECHANICAL reason, stated so
/// nobody re-tries it blind: they are empty on every harness schedule, so the only way to build a
/// violating state is to write a row into the map directly — which O(1) guard class K denies, with no
/// escape marker. Every production door that fills them also moves a field compared EARLIER in the
/// verdict (`da_ord_mem` / the record space), so the mutation is answered by the wrong comparison and
/// the new one never executes — a green proving nothing. They need a driver that makes the CHAIN
/// populate them.
pub const MAX_UNCHECKED_CHAIN_DERIVED: usize = 7;

/// ⛔⛔⛔ WHY A `ChainDerived` FIELD IS NOT COMPARED — AND THE TWO ANSWERS MEAN OPPOSITE THINGS.
///
/// ROOT-LAYER: the INCORRECT-DESIGN guard. `MAX_UNCHECKED_CHAIN_DERIVED` counts uncompared fields and
/// ratchets them down, which is right — but it puts two completely different states in one bucket:
///
///   * a comparison NOBODY HAS WRITTEN YET, over a field whose writers already honour the contract. A
///     backlog item. Writing the comparison is expected to PASS.
///   * a field where PRODUCTION VIOLATES THE DECLARED CONTRACT — it is advanced from a LOCAL-ONLY input,
///     so two honest nodes holding the same blocks hold different values. Writing the comparison would
///     FAIL. That is a defect, not a backlog item.
///
/// ⛔ THE SECOND HIDING INSIDE THE FIRST IS HOW THIS CLASS SURVIVES, MEASURED ON THIS REPO: `sparse_acc`
/// is advanced as a running local accumulator over the order blocks ARRIVE (2026-08-14: *"A folded 47
/// blocks, B folded 2 with 32 parked, `nf_root_agree=false` — while `nf_acc_agree=TRUE` on the very same
/// pair"*). The response was to route `nullifier_root()` AROUND the broken field onto the A_tip SUM, and
/// to excuse the field in PROSE as "legitimately differs". Prose closed the question. A sum cannot express
/// non-membership, and DB-160 — a live double spend — is the direct consequence.
///
/// So: every uncompared `ChainDerived` field must SAY which it is, a contract violation must carry the
/// defect id tracking its fix, and violations ratchet on their OWN ceiling. Broken can never be counted
/// as to-do again.
///
/// ⭐ THE GENERAL RULE THIS ENCODES, which applies to every layer and not just this manifest: **a value
/// the chain's correctness depends on must be a function of the chain.** The test is not "did a node
/// verify it" but "would two honest nodes holding the same blocks compute the same value". A value
/// derived from arrival order, local timing, the local peer set or a local secret fails that by
/// construction — it caches no chain value, it IS a private opinion, and a gate consulting it can admit
/// on one node and refuse on another with the disagreement never travelling. That is the 2026-09-03 DEX
/// double-payout shape ([[feedback_local_node_deciding_truth_trap]]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uncompared {
    /// The comparison is not written yet; the field's writers already honour the contract.
    NotYetWritten,
    /// ⛔ Production violates the declared contract. Carries the defect id that tracks the fix.
    ContractViolated(&'static str),
}

/// Every `ChainDerived` field not named in [`COLD_PEER_COVERED`], with WHY.
///
/// ⛔ DERIVED, NOT A HAND LIST: `every_uncompared_chain_derived_field_says_why` computes the uncompared
/// set from the manifest itself and requires an entry here for each — a field cannot be silently
/// uncompared, and a stale entry for a field that IS compared fails too.
pub const UNCOMPARED_REASONS: &[(&str, Uncompared)] = &[
    // ⛔ THE ONE KNOWN CONTRACT VIOLATION. Advanced by ARRIVAL ORDER; see the exemption note above and
    // `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`. The fix is a root committed over the block's OWN PAST.
    ("sparse_acc", Uncompared::ContractViolated("DB-154")),
    // Installed by a DSYNC adopt — "what a jumped node cannot recompute from history". Two honest nodes
    // legitimately hold different values, so the comparison is not merely unwritten, it is not the right
    // instrument; these are the jump-base family and are tracked with the base that moves them.
    ("nf_fold_base", Uncompared::NotYetWritten),
    ("nf_base_prev", Uncompared::NotYetWritten),
    ("da_macc_first", Uncompared::NotYetWritten),
    // Believed chain-derived, held back for a MECHANICAL reason: empty on every harness schedule, so the
    // only way to build a violating state is a direct map write, which O(1) guard class K denies.
    ("da_targets_mem", Uncompared::NotYetWritten),
    ("da_mem", Uncompared::NotYetWritten),
    ("da_ladder_mem", Uncompared::NotYetWritten),
];

/// ⛔ HOW MANY `ChainDerived` FIELDS PRODUCTION IS KNOWN TO VIOLATE. **May be LOWERED, never raised.**
///
/// This is the number that matters. `MAX_UNCHECKED_CHAIN_DERIVED` can fall while this stays put — that
/// is progress on the backlog and none on the defects. Raising this means a new field has been allowed
/// to compute a consensus-relevant value from a local-only input, which is the class that produced
/// DB-160.
pub const MAX_CONTRACT_VIOLATIONS: usize = 1;

#[cfg(test)]
mod manifest {
    use super::*;

    /// Parse the field names of `struct Node` straight out of the source.
    ///
    /// ⭐ SOURCE-ABSENCE TECHNIQUE (the capability calibration row D-6 says the harness lacks). Some
    /// defects are an ABSENCE — a missing bound, a missing classification — and an absence has no
    /// runtime handle to observe. Reading the source is how an absence becomes assertable at all.
    fn node_fields() -> Vec<String> {
        let src = include_str!("../../node.rs");
        let start = src.find("pub struct Node {").expect("struct Node exists");
        let mut depth = 0usize;
        let mut end = start;
        for (k, ch) in src[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for line in src[start..end].lines() {
            let t = line.trim_start();
            if line.len() - t.len() != 4 || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            let t = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
            if let Some(colon) = t.find(':') {
                let name = t[..colon].trim();
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    out.push(name.to_string());
                }
            }
        }
        out
    }

    /// ⛔⛔⛔ NO FIELD OF THIS NODE MAY EXIST WITHOUT AN ANSWER TO "WHOSE STATE IS THIS?"
    #[test]
    fn every_node_field_declares_whose_state_it_is() {
        let fields = node_fields();
        assert!(
            fields.len() > 100,
            "the source parse found only {} fields — `struct Node`'s shape changed and this test is \
             reading the wrong thing. Fix the parse; a manifest checked against nothing is worse than \
             no manifest.",
            fields.len()
        );

        let missing: Vec<&String> = fields
            .iter()
            .filter(|f| !AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ {} FIELD(S) ADDED TO `struct Node` WITH NO AUTHORITY DECLARED: {missing:?}\n\n\
             Every field must say whether the CHAIN decides it or this NODE does. That question is the \
             single largest defect class in this project — D-32, D-35, D-36, E-7, D-01, D-29 and the \
             `register_wrapped_asset` hole are all one shape: local state read as truth. Add the field \
             to AUTHORITY_MANIFEST as `ChainDerived` (and add it to `Sim::cold_peer_verdict`) or as \
             `LocalCache`. If you genuinely do not know yet, `Unclassified` is honest — but it is \
             capped, so you may have to decide one of the others first.",
            missing.len()
        );

        let stale: Vec<&str> = AUTHORITY_MANIFEST
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !fields.iter().any(|f| f.as_str() == *n))
            .collect();
        assert!(
            stale.is_empty(),
            "⛔ the manifest names {} field(s) that no longer exist: {stale:?}. A manifest that drifts \
             from the struct is a list nobody can trust — delete them.",
            stale.len()
        );
    }

    /// ⭐⭐ THE MANIFEST CHECK ITSELF IS REFUTED — it must be able to SEE an unclassified field.
    ///
    /// A manifest test that cannot detect a missing entry is the same failure as a detector that
    /// cannot fire: it reports green forever while the gap it exists to close reopens. So the lookup
    /// is exercised on a synthetic field list containing a name the manifest does not carry, and
    /// required to find it.
    ///
    /// The negative half matters equally: the REAL field list must come back fully covered, or the
    /// positive result above would just mean the manifest is empty.
    #[test]
    fn the_manifest_check_detects_a_field_it_does_not_carry() {
        let missing_in: Vec<String> = vec![
            "relay".to_string(),
            "a_field_nobody_classified".to_string(),
        ];
        let found: Vec<&String> = missing_in
            .iter()
            .filter(|f| !AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "⛔ THE MANIFEST CHECK IS BLIND: handed a field list containing a name the manifest does \
             NOT carry, it reported {found:?}. Then a field can be added to `struct Node` with no \
             ruling on whose state it is and nothing objects — which is exactly how local state \
             becomes truth at some future door."
        );
        assert_eq!(
            found[0], "a_field_nobody_classified",
            "the check must name the UNCOVERED field, not an arbitrary one"
        );

        // NEGATIVE HALF — the real struct must come back fully covered, or the above proves nothing.
        let real = node_fields();
        let uncovered = real
            .iter()
            .filter(|f| !AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .count();
        assert_eq!(
            uncovered, 0,
            "{uncovered} real field(s) are uncovered — see the sibling test for the list"
        );
    }

    /// ⛔⛔⛔ A FIELD DECLARED "THE CHAIN'S" MUST EVENTUALLY BE COMPARED AGAINST THE CHAIN.
    ///
    /// `ChainDerived` is a CLAIM — *a node fed only blocks reaches this same value* — and a claim
    /// nothing checks is exactly the shape of every hole in this class. `I-CP` compares eight
    /// surfaces; the manifest declares 50 fields chain-derived. The difference is the honest remaining
    /// surface of "local state read as truth", and this keeps it visible and shrink-only.
    #[test]
    fn every_chain_derived_field_is_or_will_be_compared_against_a_chain_only_replay() {
        let declared: Vec<&str> = AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == Authority::ChainDerived)
            .map(|(n, _)| *n)
            .collect();
        let unchecked: Vec<&&str> = declared
            .iter()
            .filter(|n| !COLD_PEER_COVERED.contains(n))
            .collect();
        println!(
            "[authority] {} declared chain-derived · {} compared by cold-peer · {} NOT YET COMPARED (ceiling {})",
            declared.len(),
            COLD_PEER_COVERED.len(),
            unchecked.len(),
            MAX_UNCHECKED_CHAIN_DERIVED
        );

        // Every covered name must actually BE a chain-derived field, or the count flatters itself.
        for name in COLD_PEER_COVERED {
            assert!(
                declared.contains(name),
                "⛔ `{name}` is listed as compared by the cold-peer verdict but is NOT declared \
                 ChainDerived in the manifest. Either the comparison is checking something the node \
                 legitimately owns (and will report phantom findings), or the manifest is wrong. Both \
                 are worse than the gap this test measures."
            );
        }

        assert!(
            unchecked.len() <= MAX_UNCHECKED_CHAIN_DERIVED,
            "⛔ THE UNCHECKED CHAIN-DERIVED SURFACE GREW: {} fields are declared to be the CHAIN's and \
             are never compared against a chain-only replay, against a ceiling of {}. Every one is a \
             field where a node could hold a value no block produced and nothing would notice — which \
             is D-32, D-35, D-36, E-7 and the `register_wrapped_asset` hole, all over again. This \
             number may be LOWERED and never raised.\n\nNot yet compared: {unchecked:?}",
            unchecked.len(),
            MAX_UNCHECKED_CHAIN_DERIVED
        );
    }

    /// ⛔⛔⛔ IS A TIP-FOLDING SCHEDULE THE DRIVER THE HELD-BACK MAPS NEED?
    ///
    /// Four `ChainDerived` fields sit in `UNCOMPARED_REASONS` for a MECHANICAL reason, stated in this
    /// file: *"they are empty on every harness schedule, so the only way to build a violating state is to
    /// write a row into the map directly — which O(1) guard class K denies … They need a driver that
    /// makes the CHAIN populate them."*
    ///
    /// ⭐ THE LIKELY REASON THEY WERE ALWAYS EMPTY: they fill in `da_store_membership_acc`, which runs
    /// when a record takes an ORDINAL — i.e. when records FOLD. Every `Sim` party used the production
    /// `record_fold_depth` (32), so a short schedule folds nothing and the maps never fill. That is the
    /// same blindness `live_leaves` had (2026-09-24), from the same cause.
    ///
    /// `Sim::new_folding_at_tip` (added 2026-09-24) builds parties at depth 0. This test reports whether
    /// that is enough — it is the CALIBRATION that must pass before the four can be moved into
    /// `cold_peer_verdict`, and it fails loudly if the driver still does not exist, rather than leaving
    /// the next reader to re-derive the question.
    #[test]
    fn a_tip_folding_schedule_populates_the_per_ordinal_maps_the_verdict_cannot_yet_compare() {
        use crate::consensus_scenarios::{Act, Sim};
        let mut sim = Sim::new_folding_at_tip(2, 0x5eed_1234_5678_9abc);
        for _ in 0..6 {
            sim.drain();
            let _ = sim.step_checked(Act::Receive(0));
            sim.drain();
            let _ = sim.step_checked(Act::Produce(0, 1));
            sim.drain();
        }
        let (fwd, rev, leafstart, targets) = sim.parties[0].per_ordinal_map_sizes_for_test();
        println!(
            "[authority] tip-folding driver: da_macc_fwd_mem={fwd} da_macc_rev_mem={rev} \
             da_leafstart_mem={leafstart} da_targets_mem={targets}"
        );
        assert!(
            fwd > 0 && rev > 0,
            "⛔ EVEN A TIP-FOLDING SCHEDULE LEAVES THE MEMBERSHIP-ACC MAPS EMPTY (fwd={fwd}, rev={rev}). \
             Then the fold depth was NOT why they are empty, and the four fields stay uncomparable for a \
             reason nobody has found yet — which is worse than the gap, because the stated reason in this \
             file would be wrong. Find the real driver before moving them into the verdict."
        );
        assert!(
            leafstart > 0,
            "⛔ `da_leafstart_mem` is still empty (fwd={fwd}), so a record's leaf offset — what a note's \
             copath needs — is never written down on this schedule"
        );
    }

    /// ⛔⛔⛔ NOBODY INSTALLS THE RULES FROM A LOCAL DECISION — derived from the source, not a hand list.
    ///
    /// ROOT-LAYER: `Node::set_params` is THE rules installer — it writes the DAG's copy AND the
    /// mempool's, so every gate in the node is measured against what it wrote. A caller that reaches it
    /// from a LOCAL verdict makes this node run rules no block ever carried, and a rules divergence is
    /// worse than a state divergence: every gate agrees with itself perfectly against a different
    /// yardstick.
    ///
    /// MEASURED 2026-09-24: `Node::enact_param` called it on a governance tally computed from gossiped
    /// votes plus this node's own `total_bond()`. It never fired only because the one caller passed
    /// `miner_total = 0` and `Proposal::passes` requires `total > 0` — an ACCIDENT, not a gate. Fixed by
    /// making enactment read-only; a rule change must be carried by a block.
    ///
    /// This test parses `node.rs` for every `set_params(` call OUTSIDE `#[cfg(test)]` code and requires
    /// each to be one of the known-safe shapes. Adding a new production caller fails until it is either
    /// block-driven or justified here — which is the ratchet, stated as a set rather than a count.
    #[test]
    fn nothing_installs_the_chain_rules_from_a_local_decision() {
        let src = include_str!("../../node.rs");
        // The two lines INSIDE `set_params` itself (it writes the DAG and the mempool), and the restart
        // resume, which restores a persisted snapshot and now NAMES any difference from the network
        // defaults (`[params-resume]`) because no block has ever carried a parameter change.
        const KNOWN: &[&str] = &[
            "self.relay.dag_mut().set_params(params.clone());",
            "self.mempool.set_params(params);",
            "self.set_params(snap.params);",
        ];
        let mut offenders: Vec<(usize, String)> = Vec::new();
        let mut in_test = false;
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            // A crude but honest test-scope tracker: every test helper in this file carries the
            // attribute on its own line, and the `mod tests` block does too.
            if t.starts_with("#[cfg(test)]") || t.starts_with("#[test]") {
                in_test = true;
            }
            if !t.contains("set_params(") || t.starts_with("//") || t.starts_with("///") {
                continue;
            }
            if t.contains("fn set_params") {
                continue;
            }
            if in_test || KNOWN.iter().any(|k| t.contains(k)) {
                continue;
            }
            offenders.push((i + 1, t.to_string()));
        }
        assert!(
            offenders.is_empty(),
            "⛔⛔⛔ A NEW PRODUCTION CALLER INSTALLS THE CHAIN RULES: {offenders:?}\n\n             `set_params` writes the DAG's copy of `ChainParams` AND the mempool's, so it decides what \
             every gate in this node measures against. Reaching it from a LOCAL verdict — a gossip tally, \
             a timer, this node's own view of the validator set — makes this node run rules no block ever \
             carried. That is a RULES divergence, and it is worse than a state divergence because every \
             gate agrees with itself perfectly against the wrong yardstick.\n\n             A rule change is a CHAIN OBJECT: the block carries the enacted change and applying the block \
             installs it, at the same height, on every node. See \
             `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`. If this caller genuinely is block-driven, add its \
             exact line to KNOWN with the block path named."
        );
    }

    /// ⛔⛔⛔ THE INCORRECT-DESIGN GUARD: every uncompared `ChainDerived` field must SAY WHY, and a
    /// contract VIOLATION may never be counted as a backlog item.
    ///
    /// DERIVED, NOT A HAND LIST — the uncompared set is computed from the manifest, so a field cannot be
    /// silently uncompared and a stale reason for a field that IS now compared fails too.
    #[test]
    fn every_uncompared_chain_derived_field_says_why() {
        let declared: Vec<&str> = AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == Authority::ChainDerived)
            .map(|(n, _)| *n)
            .collect();
        let uncompared: Vec<&str> = declared
            .iter()
            .copied()
            .filter(|n| !COLD_PEER_COVERED.contains(n))
            .collect();

        let missing: Vec<&str> = uncompared
            .iter()
            .copied()
            .filter(|n| !UNCOMPARED_REASONS.iter().any(|(m, _)| m == n))
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ {} CHAIN-DERIVED FIELD(S) ARE NOT COMPARED AND DO NOT SAY WHY: {missing:?}\n\n             Two states hide in that silence and they need opposite work: a comparison nobody has WRITTEN \
             yet (a backlog item, expected to pass), or a field where production VIOLATES the contract — \
             advanced from a local-only input, so two honest nodes holding the same blocks hold different \
             values, and writing the comparison would FAIL. Add an `UNCOMPARED_REASONS` entry saying \
             which. A contract violation must name the defect id tracking its fix.",
            missing.len()
        );

        let stale: Vec<&str> = UNCOMPARED_REASONS
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !uncompared.contains(n))
            .collect();
        assert!(
            stale.is_empty(),
            "⛔ {stale:?} carry an UNCOMPARED_REASONS entry but are no longer uncompared chain-derived \
             fields. A stale exemption is how a closed question stays closed — delete the entry (and if a \
             violation was fixed, LOWER `MAX_CONTRACT_VIOLATIONS`)."
        );

        for (name, why) in UNCOMPARED_REASONS {
            if let Uncompared::ContractViolated(id) = why {
                assert!(
                    !id.is_empty(),
                    "⛔ `{name}` is declared a CONTRACT VIOLATION with no defect id. An unticketed \
                     violation is prose, and prose is exactly what let `sparse_acc` sit excused while \
                     DB-160 opened underneath it."
                );
            }
        }

        let violations: Vec<&str> = UNCOMPARED_REASONS
            .iter()
            .filter(|(_, w)| matches!(w, Uncompared::ContractViolated(_)))
            .map(|(n, _)| *n)
            .collect();
        println!(
            "[authority] {} uncompared · {} are CONTRACT VIOLATIONS {violations:?} (ceiling {})",
            uncompared.len(),
            violations.len(),
            MAX_CONTRACT_VIOLATIONS
        );
        assert!(
            violations.len() <= MAX_CONTRACT_VIOLATIONS,
            "⛔⛔⛔ THE KNOWN-BROKEN SURFACE GREW: {} field(s) declared to be the CHAIN's are advanced by \
             production from a LOCAL-ONLY input, against a ceiling of {}. {violations:?}\n\n             A value the chain's correctness depends on must be a FUNCTION OF THE CHAIN — the test is not \
             'did a node verify it' but 'would two honest nodes holding the same blocks compute the same \
             value'. Arrival order, local timing, the local peer set and local secrets all fail it, and a \
             gate consulting such a value admits on one node while refusing on another with the \
             disagreement never travelling. This number may be LOWERED and never raised.",
            violations.len(),
            MAX_CONTRACT_VIOLATIONS
        );
    }

    /// ⛔⛔ THE RATCHET — the undecided backlog may only shrink.
    #[test]
    fn the_unclassified_backlog_only_shrinks() {
        let n = AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == Authority::Unclassified)
            .count();
        println!(
            "[authority] {} chain-derived · {} local cache · {} UNCLASSIFIED (ceiling {})",
            AUTHORITY_MANIFEST.iter().filter(|(_, a)| *a == Authority::ChainDerived).count(),
            AUTHORITY_MANIFEST.iter().filter(|(_, a)| *a == Authority::LocalCache).count(),
            n,
            MAX_UNCLASSIFIED
        );
        assert!(
            n <= MAX_UNCLASSIFIED,
            "⛔ THE UNDECIDED BACKLOG GREW: {n} unclassified fields against a ceiling of {}. This \
             number may be LOWERED and never raised — a field arriving without a ruling on whose state \
             it is is exactly how local state becomes truth at some future door.",
            MAX_UNCLASSIFIED
        );
    }

    /// ⭐⭐⭐ THERE IS EXACTLY ONE WAY TO ASK WHAT THE CONSENSUS RULES ARE.
    ///
    /// `Node` used to carry its own `params: ChainParams` field ALONGSIDE the DAG's copy. It was
    /// written once, at construction, and never again — `set_params`, the governance install, writes
    /// `self.relay.dag_mut()` and `self.mempool`. `Node::params()` reads the DAG's copy, so the
    /// eighteen call sites that went through the accessor correctly saw a governance update. The two
    /// that read the raw FIELD did not, and went on judging against the rules the node booted with:
    ///
    ///   * the orphan-depth gate in `settle_or_return_evicted_txs` (`dag_width`), whose own comment
    ///     records what a wrong verdict there cost last time — a SETTLED payment returned to the pool
    ///     and re-mined, 2306 bytes stored 7x on the sender and 8x on the receiver; and
    ///   * the UNBOND LOCK in the validator exit path (`stake_lock_blocks`), which is COLLATERAL: a
    ///     node whose governance raised the lock would still release on the old, shorter one, returning
    ///     a bonded note to the spendable served index while every peer still held that bond locked.
    ///     Two nodes then disagree about whether an unbond is legal.
    ///
    /// ⛔ THIS IS THE §F SHAPE EXACTLY — *local state read as truth* — and note what made it survive:
    /// nothing was WRONG at any single read. `self.params.stake_lock_blocks` is a perfectly ordinary
    /// line. It was wrong only in relation to a second copy that moved without it, which is invisible
    /// from the read site. That is why the fix is deletion rather than assignment: keeping the field
    /// and also writing it in `set_params` would work today and rot again the first time someone adds
    /// a third writer. With ONE source, a governance update cannot reach some gates and miss others.
    ///
    /// Measured 2026-09-09: 2 raw reads before the fix, 0 after. This test would have FAILED before it.
    #[test]
    fn the_chain_rules_have_exactly_one_reader_never_a_second_local_copy() {
        let src = include_str!("../../node.rs");

        // Field ACCESS (`self.params.x`), not the accessor (`self.params()`). The dot after `params`
        // is what separates them.
        let raw: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("self.params."))
            .map(|l| l.trim())
            .collect();

        // Non-vacuity: this assertion is only meaningful if the accessor is genuinely in wide use. If
        // `params()` had no callers either, "zero raw reads" would be true of a file that simply never
        // asks for the rules, and this test would pass while proving nothing.
        let via_accessor = src.matches("self.params()").count();
        assert!(
            via_accessor >= 10,
            "⛔ THE CONTROL FAILED, NOT THE RATCHET: only {via_accessor} reads go through `params()`.              Zero raw field reads means nothing if nobody is reading the rules at all — check whether              the accessor was renamed before trusting the count below."
        );

        assert!(
            raw.is_empty(),
            "⛔⛔ A SECOND COPY OF THE CONSENSUS RULES IS BEING READ AGAIN. {} raw `self.params.` \
             read(s) in node.rs:\n    {}\n\nThe `params` field was DELETED on 2026-09-09 precisely \
             so this could not recur. `set_params` installs a governance update into the DAG and the \
             mempool ONLY; anything reading a local copy keeps enforcing the rules this node booted \
             with. The last time that happened it was the UNBOND LOCK, and the node would have \
             returned bonded collateral to the spendable index while its peers still held it locked. \
             Read `self.params()` — it reads the DAG, which is where a governance update actually \
             lands. Do NOT reintroduce the field and write it in `set_params` too: that works until \
             the next writer forgets, which is how this arrived the first time.",
            raw.len(),
            raw.join("\n    ")
        );
    }
}

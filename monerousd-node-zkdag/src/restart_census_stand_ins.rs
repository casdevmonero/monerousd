//! ⭐ THE RESTART CENSUS — STAND-INS for the `Node` fields whose types cannot be printed (`restart_census_fields.rs` holds
//! them as `None`). Each is either compared through what stands for it (its serialized form, its DAG view, its root) or
//! declared VOLATILE with the reason it is process-local by design. `the_restart_census_names_every_node_field` refuses a
//! `None` field named in neither list, so a new unprintable field can never slip out of the census.
use super::restart_census_fields::canonical_debug;
use super::Node;

/// Process-local by design: re-created by every boot (`Node::boot` re-installs the verifiers), or a cache / work buffer
/// whose loss costs time, never state. (field, reason)
pub(crate) const VOLATILE: [(&str, &str); 49] = [
    ("floor_final", "the no-reorg floor: recomputed from the resumed selected chain (monotone from there)"),
    ("work_final", "FINALITY BY WORK: the final block, recomputed from the resumed selected chain (monotone from there)"),
    // IonSwap pools (lane goods 2026-11-12; the restart census read "ion_step_writes: before 8 B → after 7 B" on lane goods6
    // b6dde8a5): the pool leaves THIS fold step wrote, so a second pool's settlement of the same step is brought forward over
    // them (`IonSettleTx::brought_forward`). Reset at the start of every fold step (`objects_decide_at_fold`) and read only
    // for its own step (`ion_step_writes_of` answers nothing for another), so between steps it is the last step's scratch,
    // which no later step reads: a restart between steps loses nothing a fold will ask for.
    ("ion_step_writes", "the pool leaves the fold step IN PROGRESS wrote: reset at every step's start and read only for its own step"),
    // SPEED L7 (lane speed 2026-11-10; goods measured the hole on main b44fbfb9: "observed: unprintable and neither stood
    // in for nor declared"). Two parts, attributed to their writers before it was listed (AGENTS.md §9.5):
    //   the OPEN TALLY is the signatures THIS node verified at its vote door before any block carried them — arrival order
    //   of gossip, the twin of `pooled_votes` and `parked_votes` below; a restarted node hears them again
    //   (`maybe_ask_finality_certs`), and the votes a block CARRIED are tallied into `finality`, which IS compared;
    //   the FINALIZED PAIR (height, block) is kept by the live driver in one 48-byte record and re-installed bound to the
    //   held block (`restore_seen_final_from`, called by serve.rs and main.rs, never by `Node::boot`), measured across a
    //   restart by `node::pins::speed_l7_the_seen_final_figure_survives_a_restart_and_a_bad_record_installs_nothing`.
    // What a lost tally costs: the fork-choice floor and the wallet's "final" reading are the carried figure again
    // (`user_final_height` is the higher of the two), which is the rule every node ran before L7. Time, never state.
    // cons: none — a declaration; no write, no state, no file beyond the 48 B record L7 already keeps.
    ("observed", "SPEED L7: the seen-final tally — signatures THIS node verified before a block carried them (gossip arrival order, the twin of `pooled_votes`); its finalized pair is kept in the 48-byte seen-final record by the live driver and re-installed bound to the held block; without it the node reads the carried `finality`, which IS compared"),
    ("fold_reorgs", "G2d (lane a 2026-10-23): a count of the fold rewinds THIS process performed (`fold_reorgs_for_test`, its only reader, is test-only); history of one process, decides nothing"),
    // G1e-iii SERVE CACHES, lane a 2026-10-23 (g1eiv-restart-census-20261023.log:2470/2552/2553/2582: each CHANGED on both
    // nodes at every restart). Each is a serve cache its own doc names transient; each reader's tolerance of the empty
    // cache is MEASURED across the production resume by the pin
    // `node::pins::a_node_booted_from_the_same_files_serves_without_its_serve_caches_and_every_reader_tolerates_the_absence`.
    // cons: none — four declarations of caches already process-local by design; no write, no state, no file.
    ("note_clues", "G1e-iii: the BOUNDED, front-evicted OMR clue serve cache (its doc: 'NOT persisted consensus state … on restart it refills FORWARD from the tx stream'); its readers tolerate the absence by construction — the locator index reads the tags from the replicated DA shard, never from this cache (the cache-independence gate `the_locator_index_survives_a_wiped_clue_cache_because_tags_ride_the_da_shard`), `note_clue` answers None and the wallet decap-scans (the clue is an acceleration hint), and a re-gossiped tx re-fills it (the pool is VOLATILE for the same reason)"),
    ("note_clue_fifo", "G1e-iii: the eviction order of `note_clues` above — empty exactly when it is"),
    ("last_served_block", "G1e-iii: the relay slice of the ONE block this node recorded last, overwritten on each record (its doc: 'TRANSIENT DA RELAY … never persisted to disk'); its one reader `note_leaves_hex` (the explorer's full-tree view of `/get_pq_output_tree`; the wallet's light path omits it) serves the next recorded block, and that block's notes stay served from its DA record (`da_record_notes`), which the restart keeps"),
    // G1g-ii THE KIND-8 RANGE-ASK CURSOR, lane a 2026-10-23 (g1g-restart-census-20261023.log: note_backfill_cursor CHANGED node1
    // 2 → 1 B, node0 1 → 1 B). A COUNT of applied blocks read as the ordinal FLOOR of a range walk (DB-431); the live relay tick
    // itself resets it to 0 at every tip (`NodeRuntime`: `applied >= tip_h`), and the census rows refute every derivation from
    // held state (node0's live value sat below `da_ord_top` + 1, node1's above it) — no restore reproduces it and a persisted
    // sawtooth buys nothing. WHAT the lane asks is decided by the restored index and want sets (`owes_record_bytes`,
    // `record_row_top`: `range_ask_bound`'s two terms); every reader's tolerance of the zero floor is MEASURED across the
    // production resume, and the restart shown equal to the live tip-reset, by
    // `node::pins::a_node_booted_from_the_same_files_holds_a_zero_record_cursor_and_asks_exactly_what_the_live_process_asks`.
    // cons: none — a declaration of a value the live process itself zeroes; no write, no state, no file.
    ("note_backfill_cursor", "G1g-ii: the kind-8 range-ask floor, a count the live relay tick resets to 0 at every tip; the lane's question (owes_record_bytes, record_row_top) is answered by the restored index, measured identical live / tip-reset / booted"),
    // G1g-x THE PAYLOAD WANT WALK'S RESUME POINTER, lane a 2026-10-23 (g1gx-restart-census-20261023.log: 41/43 → 0 on both
    // nodes, after the DACHUNK misparse that had parked an ADDRESS 0xE000000400000000 here was routed to its own judge).
    ("note_body_want_cursor", "G1g-x: the payload want walk's resume pointer — clamped UP to note_backfill_cursor (VOLATILE, the live tip-reset) at every call and WRAPPED back to it at note_body_target every pass, so a boot at 0 is the walk's own wrap; the ordinals it asks are derived from note_payload_debt and the restored index"),
    // G1 per-process identity class, lane a 2026-10-22 (g1-finality-harness-20261022.log:3438–3809: each CHANGED at every
    // restart of both nodes; each attributed to its writers before it was listed — AGENTS.md §9.5). The fourth of the class,
    // `reward_recipient`, was a VALUE defect and is FIXED (`Node::restore_or_persist_reward_recipient`), not listed.
    // cons: none — three declarations of fields that are already process-local; no write, no state, no file: f(fixed
    // constants), never f(history).
    // G1g-iv (lane a 2026-10-23): `public_id` LEFT this list — every peer persists this node's record across its restart
    // (addrman), so the mesh counted it as a prover while it alone forgot; it now rides `BootFiles::own_record`
    // (`Node::enable_own_record_persist`), pinned by `node::pins::a_node_booted_from_the_same_files_holds_the_public_id_the_live_process_announced`.
    ("own_membership_bond", "THIS node's own signed seat request, kept to re-pool it (its doc) — its outbox, like `own_publications`: every boot that asks for a seat signs a FRESH request (`request_own_seat_at_boot`, DB-437: main.rs under MONEROUSD_VALIDATOR_BOND, serve.rs, the simulator's validator daemons — over a fresh `fresh_seat_nonce`), and a boot whose seat the chain already holds asks nothing (`is_seated`) and keeps none; the seat the chain holds is compared in `validators`"),
    ("da_secret", "the DA idle-cover secret, a fresh CSPRNG draw per process BY DESIGN (`da_secret_value`, user 2026-07-29: a persistent secret is a cross-reboot LINKAGE handle; a restart only re-randomizes the served cover/PIR shapes and wallets re-derive against the node's current epoch seed)"),
    ("own_publications", "G2 (2026-10-22): the re-send marks on THIS node's own pooled publications — a map over `mempool` ids (VOLATILE, the same reason: the pool is process-local by Bitcoin's shape, and `own_publications_due` drops a mark whose tx left the pool); a vote every node pools made it non-empty at every restart"),
    ("evicted_by_block", "G2 (2026-10-22): the pooled txs a grafted block carried, parked to RETURN to the pool if that block loses the selected chain — the pool's twin (its rows ARE pool entries, VOLATILE above); after a restart the sender re-announces, as for the pool itself; a carried vote put rows here at every restart"),
    ("deferred_votes", "G2b (2026-10-22): the verified carried finality votes THIS node's fold cursor cannot judge yet (a vote at h waits until the cursor reaches h − FINALITY_SEAT_ACTIVATION_DELAY, then `judge_deferred_votes` tallies it) — a function of the chain AND this node's fold position; the tally it feeds, `finality`, IS compared"),
    ("fold_landing_blue", "G2b (2026-10-22): the chain-block height of the fold step IN PROGRESS, None between steps (`fold_canonical_records` clears it on every return); a census runs between steps, so it reads None on every node"),
    // G1 (lane b 2026-10-24): the joiner restart census read parked_votes 6.6 MB → 2 B (joiner-restart-revert-ledger.log:
    // 32925) — a full PARKED_VOTES_MAX queue of gossiped votes whose blocks the joiner never held. It is the vote pool's
    // ORPHANAGE (Bitcoin Core txorphanage: never persisted); the votes the chain CARRIES are tallied into `finality`.
    ("parked_votes", "G1 (lane b 2026-10-24): verified finality votes for blocks THIS node does not hold yet, waiting to re-enter the vote door at graft (`take_parked_votes_for_held_blocks`) — the pool's orphanage (Bitcoin Core's txorphanage is not persisted either): it only decides what THIS node pools, a vote is counted only when a block carries it (`finality`, compared), and a lost one reaches the chain through every other holder's pool"),
    ("pooled_votes", "G2 (2026-10-22): an index by (height, voter) of the finality votes in THIS node's pool — a cache of `mempool` (VOLATILE, the same reason), re-filled by the next vote door call and pruned to what the pool holds; the votes the chain CARRIED are compared in `finality`"),
    ("band_benched", "DB-404: this node's observation of which provers let a pointer lease lapse — re-judged within one lease after a restart"),
    // G1g-v (lane a 2026-10-23): the CLOCK those leases are measured in — a count of the band steps THIS process applied
    // (`band_drain`), read only by the bench expiry (`until > band_steps_applied`) and the runtime's own bp cursor
    // (`band_bp_applied`); the boot re-applies the ring's steps (G1e-iv) and counts them from 0, so with `band_benched`
    // reset the leases and their clock restart together (measured 1 B → 1 B on both nodes, g1giv-restart-census-20261023.log).
    ("band_steps_applied", "G1g-v: the per-process clock of `band_benched` (steps THIS process applied); both readers are per-process"),
    ("mempool", "pending transactions are process-local (Bitcoin's shape): the sender re-announces; T1.4 proves a post-restart send"),
    ("pending_tags", "G1g-ix: the locator tags of THIS node's own pooled txs and staged credits, waiting for its next produced block — the twin of `mempool` (VOLATILE, the same reason: the sender re-announces the tx with its clue) and of `pending_credit_notes`; a block's CARRIED tags are filed at its record (`file_block_carried_tags`), never staged here, and the filed index is compared in `da_tags_mem`"),
    ("oli_serve_cache", "a serve cache, rebuilt on demand"),
    ("pow_miner", "the PoW kernel's allocation"),
    ("persist_path", "the datadir handle — Node::boot sets it from the same BootFiles"),
    ("site_verifier", "re-installed by Node::boot"),
    ("finality_verifier", "re-installed by Node::boot"),
    ("settlement_verifier", "the default RefuseAllSettlement on every boot (fail-closed)"),
    ("band_cursor", "a LocalCache over the view: reset whenever the view is replaced; a wrong cursor yields proofs every door refuses"),
    ("da_reads", "a test diagnostic counter of serve touches"),
    ("nf_conf_advances", "a pure counter for route diagnosis (its doc: 'nothing reads it as truth')"),
    ("fold_no_progress_passes", "a stall counter, cleared by the next fold that folds something"),
    ("fold_progress_since_len", "the chain length a no-progress streak began at, recorded again by the next streak"),
    ("da_want_fingerprint", "a fingerprint of the current want set, recomputed from it"),
    ("da_want_seed_cursor", "a want cursor: a restarted node re-derives its wants from the missing set"),
    // A WANT IN FLIGHT AT THE RESTART INSTANT (lane a 2026-10-23, sim-20261023-082851.log:71143: node 0 restarted holding one
    // fold record want, stalled 25 sweeps; the restarted node wrote that record 31 lines later). The by-id want set's ONLY
    // writer is the fold (`want_held_block_record`, 4 sites in `fold_canonical_records_inner`), which re-wants every record it
    // waits on at its next pass over the unfolded blocks the checkpoint carries — Bitcoin's shape: blocks in flight
    // (`mapBlocksInFlight`) and their stall timers are not persisted; a restart re-requests what the chain still needs.
    // NOT DECLARED, MEASURED: `restart_census_every_field_survives_a_production_restart` asserts every id wanted before a
    // restart is held or wanted again after it.
    ("wanted_record_ids", "the fold's by-id want set: re-derived by its next pass over the unfolded blocks (asserted by the restart census)"),
    ("da_want_stall_passes", "a stall counter over the want set, cleared when the set changes (the twin of fold_no_progress_passes)"),
    ("record_ask_nonce", "the by-id ask's per-process nonce (decoy draw); a new process starts at 0, as the process-wide static it replaced did"),
    ("da_want_stall_since_ms", "the wall-clock start of the current stall run, 0 = not stalled; restarts with the re-derived want set"),
    // THE SAME CLASS ON THE BLOCK LANE (lane a 2026-10-23, sim-20261023-094616.log:72727: node 1 restarted holding one
    // by-id block want, 213 → 192 B). Writers: the fold's C1 waits (2 sites in `fold_canonical_records_inner`, re-run every
    // pass), a page shell's missing parent, a buffered orphan's missing parent, an evicted orphan child — each derives the id
    // from what the node still lacks. Bitcoin: `mapBlocksInFlight` is not persisted. MEASURED by the restart census.
    ("wanted_block_slots", "the fold's by-id block want slots: re-derived from what the node lacks (asserted by the restart census)"),
    // A BLOCK TEMPLATE IN FLIGHT AT THE RESTART INSTANT (lane a 2026-10-23, watch-20261023-110845.log.7:5188: node 0 restarted
    // between `produce_template` and `graft_mined_own`, inflight_tx_ids 5376 → 2 B, pending_block_nullifiers 37596 → 2 B —
    // armed once G4 4c1c47f let carried spends reach a template). Both are the produce→graft scratch of ONE off-lock mine;
    // the block being mined dies with the process and the next template is built fresh. Bitcoin: a getblocktemplate is not
    // persisted. The txs stay pooled until graft, so the VALUE law is MEASURED by the restart census: every tx a template
    // held before the restart is carried by a block the node holds, or still pooled by some node, after it.
    ("inflight_tx_ids", "the in-flight template's tx ids: rebuilt by the next template (each tx asserted carried or pooled by the restart census)"),
    // lane agg — THE PAYMENTS HELD FOR AGGREGATION (docs/LEVEL-AGGREGATE-SPEC-20261115.md §10). The pool holding their
    // aggregated forms is itself not persisted, and the origin of each keeps its own copy and pushes it again after its echo
    // window (`NodeRuntime::own_push_tick`), so a restart loses no payment. Bitcoin: mapOrphanTransactions is not persisted.
    ("agg_held", "the payments this node holds for its own blocks' aggregates: dropped with the pool; their origins re-push them"),
    // §14 THE BUNDLE RELAY — the bundles over held payments: each is a root over members `agg_held` holds, so it goes with them
    // and their origins re-push them (the bundle is re-proved from the leaves of whoever holds them next).
    ("agg_bundles", "the bundles over this node's held payments: dropped with agg_held; their origins re-push the payments"),
    ("bundle_worker", "whether this process runs a bundle worker: set again by the runtime at every start"),
    ("pending_block_nullifiers", "the in-flight template's padded nullifier set: produce→graft scratch, rebuilt by the next template"),
    ("span_close_landing", "DB-440: a measurement cache of where the certified span close lands — the first landing walk after a boot re-measures it; it decides nothing the walk would not"),
    ("last_autosave", "the autosave timer"),
    ("last_shard_mesh", "the mesh size the shard policy was last derived for — a derivation cache"),
    ("miner_seed", "drawn fresh per process by design (reward::new_node_miner_seed); a node's rewards go to the provisioned recipient file, not to this seed"),
];

/// ⭐⭐⭐ DB-402 R1 — fields the replicated-state census does not compare across nodes, beside the `LocalCache` rows of
/// `harness::fuzz::authority::AUTHORITY_MANIFEST` (the ONE ruling of whose state a field is, each with its reason there;
/// verdict `LOCAL_CACHE`). DEFAULT = REPLICATED: a field is here only when the answer to *"must another node holding the
/// same chain agree on this byte-for-byte?"* is NO, and the reason says why. Never add a field to turn a DIFFERS row green
/// — a DIFFERS on a replicated field is a node standing on local truth (DB-401: the order book). An entry naming no `Node`
/// field, or a field the manifest rules `ChainDerived`, is refused by the completeness pin (`served_fold_count` sat here
/// as "diagnostic" while `/membership_roots` bounds its walk by it, 2026-10-27).
pub(crate) const NODE_LOCAL: &[(&str, &str)] = &[
    // A-F118 (lane speed5r, 2026-11-22): the record index through which THIS node's canonical ring FILE is current — written
    // by its own saver thread after a write succeeded, lowered by a rewind (its doc, `Node::canon_saved_top`); a function of
    // when this node saved, never of the chain (MEASURED replica census main bb4b7d46: 186 vs 180 on two replayers)
    ("canon_saved_top", "this node's own disk saver's cursor: how far its ring file is written, by its own saver thread"),
    // process-local by design (each is also VOLATILE across a restart, with the same reason)
    ("mempool", "pending transactions are per-node until a block carries them (Bitcoin's shape)"),
    ("oli_serve_cache", "a serve cache, rebuilt on demand"),
    ("pow_miner", "the PoW kernel's allocation"),
    ("persist_path", "this node's datadir"),
    ("site_verifier", "a verifier object installed by Node::boot; holds no chain state"),
    ("finality_verifier", "a verifier object installed by Node::boot; holds no chain state"),
    ("settlement_verifier", "a verifier object installed by Node::boot; holds no chain state"),
    ("band_cursor", "a LocalCache over this node's view"),
    ("fold_reorgs", "G2d (lane a 2026-10-23): how many times THIS node's selected chain moved below its fold root — its own arrival history (fast-eco: 2 vs 3 on one chain); read only by tests (`fold_reorgs_for_test`)"),
    ("band_steps_applied", "G2d (lane a 2026-10-23): the per-process clock of `band_benched` (NODE_LOCAL above) — steps THIS process applied since boot; read only by the bench expiry, P7's progress probe and the runtime's own bp cursor, all per-process (fast-eco: 571 vs 1100 on one chain)"),
    ("band_benched", "DB-404: the leases THIS node waited out — each node benches only the provers it saw lapse (ownership only, never P7's turn set)"),
    ("da_reads", "a diagnostic counter of this node's serve touches"),
    ("nf_conf_advances", "a counter for route diagnosis (its doc: 'nothing reads it as truth')"),
    ("fold_no_progress_passes", "this node's stall counter"),
    ("fold_progress_since_len", "where this node's stall streak began"),
    ("da_want_fingerprint", "a fingerprint of this node's want set"),
    ("da_want_seed_cursor", "this node's want cursor"),
    ("wanted_record_ids", "the records THIS node's fold waits on — what it lacks, not what the chain holds"),
    ("da_want_stall_passes", "this node's stall counter over its own want set"),
    ("record_ask_nonce", "this node's own ask nonce: how many by-id asks THIS process has sent"),
    ("da_want_stall_since_ms", "when this node's own want set stalled"),
    ("wanted_block_slots", "the blocks THIS node lacks and asks for by id — what it lacks, not what the chain holds"),
    ("inflight_tx_ids", "the template THIS node is mining — its own producer scratch until a block carries it"),
    ("agg_held", "the payments pushed to THIS node that it holds for its own blocks — what this node took on, not what the chain holds"),
    ("agg_bundles", "§14: the bundles THIS node proved or took over the payments it holds — its own work in flight, not what the chain holds"),
    ("bundle_worker", "§14: whether THIS process runs a bundle worker — a process fact"),
    ("pending_block_nullifiers", "the padded set of the template THIS node is mining — its own producer scratch"),
    ("span_close_landing", "DB-440: written only by a span-close walk THIS node ran (a jumper's; a node that never jumped never walks)"),
    ("last_autosave", "this node's autosave timer"),
    ("last_shard_mesh", "the mesh size this node last derived its shard policy for (a derivation cache)"),
    ("miner_seed", "drawn per process by design (reward::new_node_miner_seed)"),
    // this node's own identity and keys — per-entity by the DECENTRALIZATION cardinal, never shared
    ("public_id", "this node's own identity"),
    ("own_validator_id", "this node's own validator identity"),
    ("da_secret", "this node's own secret"),
    ("fee_seed", "this node's own fee key seed (per-entity value key)"),
    ("fee_mlkem_pub", "this node's own fee key (per-entity value key)"),
    ("fee_mlkem_sec", "this node's own fee key (per-entity value key)"),
    ("reward_recipient", "this node's provisioned reward recipient (per-entity)"),
    ("own_publications", "what THIS node published (its own outbox), not what the chain holds"),
    ("deferred_votes", "G2b (2026-10-22): the carried finality votes THIS node's fold cursor cannot judge yet — the pool's twin on the fold side (process position, like `mempool`); the votes it judges land in `finality`, which IS compared"),
    ("fold_landing_blue", "G2b (2026-10-22): the fold step in progress, None between steps on every node"),
    ("parked_votes", "G1 (lane b 2026-10-24): the votes THIS node holds for blocks it has not seen yet — what gossip reached it before the block (arrival order, like `mempool`); the votes the chain carried are tallied into `finality`, which IS compared"),
    ("pooled_votes", "G2 (2026-10-22): the finality votes in THIS node's pool, by (height, voter) — the pool's twin (arrival order, like `mempool`); the votes the chain carried are tallied into `finality`, which IS compared"),
    ("peer_dir", "the peers this node knows (Bitcoin addrman: per-node by design)"),
    // DB-402 R1 triage (link 6, censusdiff-205229: each read DIFFERS, its first difference printed)
    ("custody_opening_path", "the filesystem path of this node's own opening file in its own datadir (…/node-0/custody-opening-30000.bin vs …/node-1/…-30001.bin) — a path, never state"),
    ("own_record_path", "G1g-iv: the filesystem path of this node's own announced-record file in its own datadir — a path, never state"),
    ("wrapped_opening_path", "the filesystem path of this node's own wrapped-opening file in its own datadir — a path, never state"),
    ("pool_opening_path", "the filesystem path of this node's own pool-opening file in its own datadir — a path, never state"),
    ("reward_recipient_file", "G1 (lane a 2026-10-22): the filesystem path of this node's own reward recipient file in its own datadir (`BootFiles::reward_recipient`) — a path, never state"),
    ("last_served_block", "the relay slice of the LAST block this node recorded, overwritten on each arrival (persist.rs: 'a non-authoritative serve-cache'); which block was last depends on arrival order, like the mempool"),
    ("note_body_want_cursor", "this node's ask cursor (where its next payload ask resumes) — the twin of da_want_seed_cursor; the records it asks for are compared in their own fields"),
    ("note_backfill_cursor", "this node's kind-8 range-ask resume point — advanced by every record it applied and JUMPED to a served page's covered_upto on the node that paged (DB-402 R1: 41 vs 45 on one chain while it shared blocks_note_applied's name); the records it walks toward are compared in the DA fields (da_mem, da_ord_mem); the per-block counter blocks_note_applied that shared its name was deleted 2026-10-22"),
    // DB-402 R1 triage, lane a 2026-10-22 (watch-20261022-131112.log.node, pin lane: 10 DIFFERS on a6ede51; each attributed
    // to its writers before it was listed — AGENTS.md §9.5). What the CHAIN carries for each is compared in its own field.
    ("own_membership_bond", "THIS node's own signed seat request, kept to re-pool it (its doc) — its outbox, like own_publications; the seat the chain holds is compared in `validators`"),
    ("chain_cert", "this node's own running recursive proof of the chain it holds, stepped at ITS proving cadence when it builds a bundle (`install_cert_step`; its doc: 'the proving cadence an engineering choice instead of a consensus parameter'); a joiner VERIFIES a certificate against the bundle's chain_acc, never compares two nodes' proofs — the chain it proves is compared in the DAG fields (n0 certified to blue work 305, n1 to 301, the same chain)"),
    ("certified_blue_work", "the position this node's own certificate last certified — the cursor of `chain_cert` above"),
    ("note_clues", "a serve-cache of the OMR clue BYTES that reached THIS node's doors (/submit_pq_tx, tx gossip, its own produced reward); the chain carries only `index_key(clue)` in Block::oli_tags, which is filed in `da_tags_mem` (compared, SAME) — no node can derive another's clue bytes, and a wallet missing one decap-scans (its doc: 'an acceleration hint, never a correctness requirement')"),
    ("note_clue_fifo", "the eviction order of `note_clues` above"),
    ("pending_tags", "locator tags STAGED on this node (a tx it accepted, a block it ingested) and awaiting the record loop that drains them into `da_tags_mem` — the mempool's twin, per node until the block's record files them; a late tag lands through `attach_tag_to_recorded_block`. The FILED index is compared in `da_tags_mem` (SAME)"),
    ("evicted_by_block", "the pooled txs a grafted block evicted from THIS node's mempool, held until the block's fate on the selected chain is decided and then dropped (settled) or RETURNED TO THIS NODE'S POOL (`settle_or_return_evicted_txs`) — the mempool's twin: a node that never pooled the tx holds no entry by construction (pin lane: n0 {} vs n1 one block's one tx — the credit n1's fixture pooled). Its one other reader, `objects_decide_at_fold`, uses it only to file a fold verdict FOR THE HELD TXS (`fold_verdicts`, the return-to-pool decision), never to decide the fold itself; what the chain settled is compared in the DAG and fold fields"),
    ("fold_verdicts", "the fold's verdict FOR THE TXS THIS NODE HELD in `evicted_by_block` above (its doc: a held tx whose object the fold refused returns to the pool) — filed only for a block that has an `evicted_by_block` entry here (`objects_decide_at_fold`: `judged_for_held`), so a node that never pooled the tx files none (pin lane g2-bna-20261022.log:4160: n0 {} vs n1 {one block: []}); the fold's outcome itself is compared in the fold and DAG fields"),
    ("mined_tx_nfs", "the graft's per-tx record of the real nullifiers of the block txs THIS node had POOLED (`spent_by_an_unfolded_block` arm (b): 'filled from THIS node's pool at graft'); a node that never pooled a tx holds no entry by construction (a block carries tx ids and a lane of real+cover tags, never which tag is real). The replicated spent fact is the block's own lane (arm (a), `nullifier_proof.padded_tags`, compared in `unfolded_blocks`) and the canonical fold-point set; a missing entry fails OPEN only at this node's pool door and CLOSED at the fold (the loser is refused), so no value moves on it"),
];

/// ⭐ DB-402 R1 — fields whose ITEMS are replicated but whose ORDER is this node's arrival order by design, and no reader
/// takes the order as truth. The replicated-state census compares them as SETS (`multiset_digest`, verdict `SAME-SET`): a
/// missing, extra or changed item still reads DIFFERS — only the order is forgiven, and only for the reason given here.
/// Each entry answers: who reads the order, and why arrival order is the right one for them.
pub(crate) const UNORDERED: &[(&str, &str)] = &[
    // `unfolded_blocks` (a holding buffer appended in arrival order: the fold walks the DAG's merge sets, the served carry
    // is sorted by (blue score, id) in carry_for, and nf_fold_inputs pages it by position — censusdiff-205229: n0 listed
    // its own height-1 block first, n1 its own) is since 2026-10-22 compared through its STAND-IN, which sorts by id and
    // renders each block's ONE wire encoding — so its order needs no forgiving here.
    // `nf_recent_folds` left VOLATILE 2026-10-26 (a resume rebuilds it from the restored span, rebuild_recent_folds_from_span)
    // and this list 2026-10-25: the ring is now held and evicted by the canonical order key
    // (blue work, id), so its ORDER is a function of the chain too and the census compares it exactly.
];

/// ⭐ §POLES (lane a 2026-10-25) — fields holding ZERO-KNOWLEDGE PROOF BYTES, which the replicated-state census compares by
/// STATEMENT (`census_field_render_statement`, verdict `SAME-STATEMENT`): every proven fact — block, transition, roots,
/// counts — must agree exactly; only the randomized proof bytes are left out, and only for the reason given here. Any other
/// difference still reads DIFFERS. The restart census (one node across its own restart) keeps comparing the exact bytes.
pub(crate) const BY_STATEMENT: &[(&str, &str)] = &[(
    "band_door",
    "its held band-step proofs (applied_proofs, verified, solicited, parked) are WHIR zero-knowledge proofs, randomized per \
     run, and a lapsed owner's step is re-proven by its one deterministic backup (DB-454): two honest nodes may each apply \
     a different verifying proof of the same step. Every statement field and the band, root and journal stay compared",
)];

/// DB-402 R2: the fields compared through a stand-in (below) instead of their own `{:?}` — the derived census skips their
/// digest (`node_field_census(&STOOD_IN)`), so a huge or order-unstable rendering is never computed for nothing. The
/// completeness pin requires `restart_census_stand_ins()` to name exactly these.
pub(crate) const STOOD_IN: [&str; 22] = [
    "relay",
    "peg",
    "directory",
    "objects_fold_journal",
    "validators",
    "finality",
    "governance",
    "sites",
    "clues",
    "peer_dir",
    "chain_cert",
    "block_window",
    "sparse_work",
    "decider_verifier",
    "unfolded_blocks",
    "anchor_block_full",
    // §POLES spec 5: the rewind journals by their effective window (`Node::rewind_window_floor`), a function of the tip
    "spine_recent_frontiers",
    "respend_reach",
    "respend_journal",
    "objects_journal_floor",
    // A-F118: the switch's window by its JUDGED records (`CanonRecent::judge_floor`, the newest CANON_RECENT_RECORDS by index);
    // the serve margin below them is held by a node that replayed and not by a joiner, by design (U2), and no verdict reads it
    "canon_recent",
    // the texts list (`restart_census_stand_in_texts`) names da_mem LAST; the completeness pin compares the two as one
    // ordered list (f2b4a72 added it at the front here — RED on main since, g2-finality-harness-2-20261022.log:3001)
    "da_mem",
];

/// A block by its ONE wire encoding (postcard, the relay's), as the blake3 hex of those bytes; a block that does not
/// serialize renders as its error text, which is compared — and differs — like any other value.
fn wire_digest(b: &crate::block::Block) -> String {
    match postcard::to_allocvec(b) {
        Ok(bytes) => blake3::hash(&bytes).to_hex().to_string(),
        Err(e) => format!("unserializable: {e}"),
    }
}

impl Node {
    /// Test-only triage: the DAG blocks a checkpoint written now would not bring back — neither the anchor nor genesis, nor
    /// carried (unfolded or ancestor), nor in the block window the restore re-installs from, nor a v64 shell — each as (score above the
    /// anchor, in the folded floor, in the unfolded buffer).
    #[cfg(test)]
    pub(crate) fn dag_blocks_a_checkpoint_drops(&self) -> Vec<(i64, bool, bool)> {
        let dag = self.relay.dag();
        let carry = self.checkpoint_carry();
        let mut kept: std::collections::HashSet<crate::block::BlockId> =
            carry.unfolded.iter().chain(carry.ancestors.iter()).map(|(b, _, _)| b.id()).collect();
        kept.extend(self.fold_anchor_block());
        kept.extend(dag.genesis());
        kept.extend(self.block_window.ascending().into_iter().map(|(_, id)| id));
        kept.extend(self.dag_shells(&carry).into_iter().map(|(b, _, _, _)| b.id())); // v64: carried as shells
        let anchor = self.fold_anchor_block().and_then(|a| dag.get(&a).map(|n| n.blue_score)).unwrap_or(0) as i64;
        let unfolded: std::collections::HashSet<crate::block::BlockId> = self.unfolded_blocks.iter().map(|b| b.id()).collect();
        let mut out: Vec<(i64, bool, bool)> = dag
            .block_ids()
            .into_iter()
            .filter(|id| !kept.contains(id))
            .filter_map(|id| dag.get(&id).map(|n| (n.blue_score as i64 - anchor, self.folded_floor.contains(&id), unfolded.contains(&id))))
            .collect();
        out.sort_unstable();
        out
    }

    /// Test-only triage: the `folded_floor` ids this node holds in neither its DAG nor its block window (the restore keeps a
    /// held floor id only when it holds the block), and the `nf_unfolded_gen` stamps on blocks that are not unfolded.
    #[cfg(test)]
    pub(crate) fn floor_and_stamp_probe(&self) -> (usize, usize, usize, Vec<(String, Vec<String>)>) {
        let dag = self.relay.dag();
        let unheld = self.folded_floor.iter().filter(|id| dag.get(id).is_none() && !self.block_window.contains(id)).count();
        let unfolded: std::collections::HashSet<crate::block::BlockId> = self.unfolded_blocks.iter().map(|b| b.id()).collect();
        let off = self.nf_unfolded_gen.keys().filter(|id| !unfolded.contains(*id)).count();
        // the DAG blocks whose parents this live DAG does not hold, with each such parent (window-held or not)
        let dangling: Vec<(String, Vec<String>)> = dag
            .block_ids()
            .into_iter()
            .filter(|id| Some(*id) != dag.genesis())
            .filter_map(|id| {
                let n = dag.get(&id)?;
                let gone: Vec<String> = n
                    .header
                    .parents
                    .iter()
                    .filter(|p| dag.get(p).is_none())
                    .map(|p| format!("{}{}", &p.to_hex()[..8], if self.block_window.contains(p) { "(w)" } else { "" }))
                    .collect();
                (!gone.is_empty()).then(|| (format!("{}@{}{}", &id.to_hex()[..8], n.blue_score, if unfolded.contains(&id) { "u" } else { "" }), gone))
            })
            .collect();
        (unheld, off, self.nf_unfolded_gen.len(), dangling)
    }

    /// Test-only triage: the byteless ordinal rows of real records (carried since v63 as `coordinate_rows`) and how many rows
    /// the node holds in all.
    #[cfg(test)]
    pub(crate) fn uncarried_ordinal_rows(&self) -> (usize, usize) {
        let dropped = self
            .da_ord_mem
            .keys()
            .filter(|rid| !self.da_mem.contains_key(*rid))
            .filter(|rid| self.row_has_real_reference(**rid) || !self.block_declares_no_notes(**rid))
            .count();
        (dropped, self.da_ord_mem.len())
    }

    /// §POLES spec 5 — a rewind journal's entries inside the effective window (ordinal ≥ `rewind_window_floor`), oldest
    /// first: the ONE helper every journal's census render reads.
    fn rewind_window<'a, T>(&self, journal: &'a std::collections::VecDeque<T>, ordinal: impl Fn(&T) -> u64) -> Vec<&'a T> {
        let floor = self.rewind_window_floor();
        journal.iter().filter(|e| ordinal(e) >= floor).collect()
    }

    /// The unprintable fields compared through what stands for them: each stand-in's canonical digest.
    pub(crate) fn restart_census_stand_ins(&self) -> Vec<(&'static str, (u64, usize))> {
        self.restart_census_stand_in_texts().into_iter().map(|(n, s)| (n, canonical_debug(&s))).collect()
    }

    /// DB-402 R1 triage: field `name` rendered into `out` exactly as the censuses digest it — its stand-in's text when
    /// `STOOD_IN` names it, else its own `{:?}`. `false` when it renders to nothing (no such field, or unprintable).
    pub(crate) fn census_field_render(&self, name: &str, out: &mut dyn std::fmt::Write) -> bool {
        if STOOD_IN.contains(&name) {
            return match self.restart_census_stand_in_texts().into_iter().find(|(n, _)| *n == name) {
                Some((_, s)) => out.write_str(&s).is_ok(),
                None => false,
            };
        }
        self.node_field_render(name, out)
    }

    /// A [`BY_STATEMENT`] field rendered by statement (its proof bytes cleared) for the replicated-state census; `false`
    /// for a field not on that list.
    pub(crate) fn census_field_render_statement(&self, name: &str, out: &mut dyn std::fmt::Write) -> bool {
        match name {
            "band_door" => out.write_str(&self.band_door.statement_view()).is_ok(),
            _ => false,
        }
    }

    /// Each stand-in's text (what the censuses digest in its field's slot). A serialization error is the text itself
    /// (`unserializable: …`), so it is compared — and differs — like any other value.
    fn restart_census_stand_in_texts(&self) -> Vec<(&'static str, String)> {
        let j = |v: serde_json::Result<String>| match v {
            Ok(s) => s,
            Err(e) => format!("unserializable: {e}"),
        };
        let d = |s: String| s;
        vec![
            // J19 (lane speed5, 2026-11-18): the span every node keeps BY RULE — the blocks at or above the horizon
            // (`Dag::horizon_blue_score`: "a block below it is outside the span every node keeps"). The prune is lazy (it runs past
            // `prune_slack` or on a boundary step) and a joiner also keeps its anchor's past (`prune_floor`), so the held count and
            // anything below the horizon are this node's cache. MEASURED (replica census, main 624311e7 + F6): `relay` DIFFERS
            // 19,256 / 19,256 / 19,295 B with the selected chains equal.
            ("relay", d({
                let dag = self.relay.dag();
                let horizon = dag.horizon_blue_score();
                format!("{:?}", dag.dag_recent_view(1 << 16).into_iter().filter(|v| v.2 >= horizon).collect::<Vec<_>>())
            })),
            ("peg", j(serde_json::to_string(&self.peg))),
            ("directory", j(serde_json::to_string(&self.directory))),
            ("objects_fold_journal", j(serde_json::to_string(&self.rewind_window(&self.objects_fold_journal, |e| e.0)))),
            // T3/T2 (2026-11-03): the custody KEY TABLE rides the stand-in — a restart that keeps only the SAT seats' keys
            // (what the checkpoint carried before `seated_kem_eks`) reads DIFFERS here, never only at a refused stake.
            ("validators", d(format!("{:?}", (self.validators.len(), self.validators.total_bond(), self.validators.total_finality_weight(), self.validators.takeover_figures(), self.validators.seat_activations(), {
                let kems = self.validators.seated_kem_eks();
                let mut h = blake3::Hasher::new();
                for (id, ek) in &kems {
                    h.update(id);
                    h.update(&(ek.len() as u64).to_le_bytes());
                    h.update(ek);
                }
                (kems.len(), *h.finalize().as_bytes())
            })))),
            // ⛔ A-F106 part 2 (lane speed5, 2026-11-19): the open tally is compared once finality RUNS (A-F100's overlay rule,
            // net/double_spend.py). Where finality never moved (finalized 0: a chain whose founding seat no node holds), the open
            // tally is every vote since genesis that no certificate ever used, and a bundle joiner holds only the votes carried
            // in bodies above its anchor — MEASURED replica census on e53cce79: finalized 0 on all three, tally (242, 122) on both
            // replayers against (221, 114) on the joiner, the census's last DIFFERS. Once finality runs, the tally holds open
            // heights only (above finalized) and is compared as before; the finalized height and block are compared always.
            ("finality", d(if self.finality.finalized_height() == 0 {
                format!("{:?}", (self.finality.finalized_height(), self.finality.finalized_block()))
            } else {
                format!("{:?}", (self.finality.finalized_height(), self.finality.finalized_block(), self.finality.tally_rows()))
            })),
            ("governance", d(format!("{:?}", self.governance.len()))),
            ("sites", d(format!("{:?}", self.sites.roots()))),
            ("clues", d(format!("{:?}", (self.clues.len(), self.clues.content_digest())))),
            ("peer_dir", d(format!("{:?}", self.peer_dir.len()))),
            ("chain_cert", d(format!("{:?}", (self.chain_cert.acc(), self.chain_cert.work())))),
            ("block_window", d(format!("{:?}", self.block_window_census()))),
            // the nullifier VIEW by what it holds — its root, spent-leaf count and shard policy — never by presence alone
            // (MEASURED 2026-10-06: a presence-only stand-in would read a view whose root no longer matches as unchanged)
            ("sparse_work", d(format!("{:?}", self.sparse_work.as_ref().map(|v| (v.root_bytes(), v.spent_leaf_count(), v.shard_policy()))))),
            ("decider_verifier", d(String::from("installed by Node::boot (presence is asserted by the adopt pins)"))),
            // ⭐ DB-402 R1 (lane a 2026-10-22) — THE BLOCK-HOLDING FIELDS ARE COMPARED BY THE BLOCK'S ONE WIRE ENCODING.
            // `Block::output_notes` is `#[serde(skip)]` (DB-165): never on the wire, REHYDRATED by each node from the tx
            // bodies it holds and checked against `note_commitments` — so the in-memory `{:?}` of a held block differs
            // between a node that rehydrated it and one that did not (MEASURED pin lane, g2-census-20261022.log:
            // anchor_block_full n0 `output_notes: [210, …]` vs n1 `output_notes: []`, every wire field identical). One
            // consensus object has ONE encoding: the stand-in renders each held block as (id, blake3 of its postcard wire
            // bytes), the set sorted by id; a block that does not serialize renders as its error text and so differs. The
            // note BYTES a node holds for a block are compared in their own field (`da_mem`, the DA record); a block
            // missing, extra or changed on either node still reads DIFFERS here.
            ("unfolded_blocks", d({
                let mut v: Vec<(String, String)> =
                    self.unfolded_blocks.iter().map(|b| (format!("{:?}", b.id()), wire_digest(b.block()))).collect();
                v.sort();
                format!("{:?}", (v.len(), v))
            })),
            ("anchor_block_full", d(format!(
                "{:?}",
                self.anchor_block_full.as_ref().map(|b| (format!("{:?}", b.id()), wire_digest(b)))
            ))),
            // ⭐ DB-402 R1 (lane a 2026-10-22) — THE RECORD STORE IS COMPARED BY WHAT THE CHAIN FIXES: its rows that carry
            // content. A row holding exactly its address's public idle seed and no letters is COVER a node regenerates
            // from the address at serve (`regenerate_idle_record`) and releases as cache when cold
            // (`sweep_cold_idle_rows`: no ordinal row, block not held, nothing wants it — every 256 ordinals, per node).
            // MEASURED g2-provenance-harness-2-20261022.log: the one DIFFERS left in `da_mem` was the genesis ledger
            // seed record 74223561543428028 held by n0 and swept by n1 — identical bytes, one node's cache policy. Every
            // row with a real note or a letter column is compared whole, provenance bool included: a real record
            // missing, extra, changed or unbound on either node still reads DIFFERS.
            // ⛔ §POLES spec 5 — the rewind journals keep `REWIND_RETAIN` entries so a retreat can be re-folded, but what
            // they mean is the window at the tip: the census compares that window (and the floor it implies), never the
            // slack a node's own fold history left below it.
            ("spine_recent_frontiers", d(format!("{:?}", self.rewind_window(&self.spine_recent_frontiers, |e| e.0)))),
            ("respend_reach", d(format!("{:?}", self.rewind_window(&self.respend_reach, |e| e.0)))),
            ("respend_journal", d({
                let reach: std::collections::BTreeSet<_> =
                    self.rewind_window(&self.respend_reach, |e| e.0).into_iter().map(|(_, id)| *id).collect();
                let kept: std::collections::BTreeMap<_, _> =
                    self.respend_journal.iter().filter(|(id, _)| reach.contains(*id)).collect();
                format!("{kept:?}")
            })),
            ("objects_journal_floor", d(format!("{:?}", self.objects_journal_floor.max(self.rewind_window_floor())))),
            ("canon_recent", d(format!(
                "{:?}",
                self.canon_recent.range(self.canon_recent.judge_floor(), crate::canon_chain::CANON_RECENT_RECORDS)
            ))),
            ("da_mem", d({
                let kept: std::collections::BTreeMap<&u64, &(Vec<Vec<u8>>, Vec<u8>, bool, crate::cover::CoverKey)> = self
                    .da_mem
                    .iter()
                    .filter(|(addr, row)| {
                        !(row.1.is_empty()
                            && row.0.len() == 1
                            && row.0[0][..] == crate::cover::public_idle_seed_note(**addr)[..])
                    })
                    .collect();
                format!("{:?}", kept)
            })),
        ]
    }
}

#[cfg(test)]
mod tests {
    /// The census's comparison is ARMED: a map rebuilt in another insertion order reads the same, a list in another order and a
    /// changed value read different.
    #[test]
    fn the_canonical_digest_ignores_map_order_and_catches_a_changed_value() {
        use super::super::restart_census_fields::canonical_debug_of;
        let a: std::collections::HashMap<u64, u64> = (0..200).map(|i| (i, i * 3)).collect();
        let mut b: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        for i in (0..200).rev() {
            b.insert(i, i * 3);
        }
        assert_eq!(canonical_debug_of(&a), canonical_debug_of(&b), "a rebuilt map must read the same");
        assert_ne!(canonical_debug_of(&vec![1, 2, 3]).0, canonical_debug_of(&vec![3, 2, 1]).0, "a list keeps its order");
        b.insert(7, 0);
        assert_ne!(canonical_debug_of(&a).0, canonical_debug_of(&b).0, "a changed value must read different");
        let s1: std::collections::HashSet<String> = ["x, y".to_string(), "z".to_string()].into_iter().collect();
        let s2: std::collections::HashSet<String> = ["x".to_string(), "y, z".to_string()].into_iter().collect();
        assert_ne!(canonical_debug_of(&s1).0, canonical_debug_of(&s2).0, "a comma inside a string is not an item boundary");
    }

    /// The first-difference instrument is ARMED: it names the exact byte two long renderings part at (inside a later chunk, at a
    /// chunk boundary, and where one is a strict prefix of the other), with the field name before it, and refuses to invent a
    /// difference between identical renderings.
    #[test]
    fn the_first_difference_instrument_names_where_two_renderings_part() {
        use super::super::restart_census_fields::first_difference;
        #[derive(Debug)]
        struct Row {
            id: u64,
            seq: Vec<u64>,
        }
        let a: Vec<Row> = (0..400).map(|i| Row { id: i, seq: vec![i; 3] }).collect();
        let mut b: Vec<Row> = (0..400).map(|i| Row { id: i, seq: vec![i; 3] }).collect();
        b[333].seq[1] = 9;
        let at = |x: &Vec<Row>, y: &Vec<Row>| {
            let r = |side: bool, out: &mut dyn std::fmt::Write| out.write_fmt(format_args!("{:?}", if side { y } else { x })).is_ok();
            first_difference(&r, 24)
        };
        let (sa, sb) = (format!("{a:?}"), format!("{b:?}"));
        let want = sa.bytes().zip(sb.bytes()).position(|(x, y)| x != y).expect("CALIBRATION: the renderings differ");
        assert!(want > 8192, "CALIBRATION: the difference lies past the first two chunks ({want})");
        let (p, la, lb, ca, cb) = at(&a, &b).expect("a difference is found");
        assert_eq!((p, la, lb), (want, sa.len(), sb.len()), "the exact byte and both lengths");
        assert!(ca.contains("seq:") && ca.contains("333") && cb.contains(", 9,"), "the context names the field and both values:\n{ca}\n{cb}");
        let mut c: Vec<Row> = (0..400).map(|i| Row { id: i, seq: vec![i; 3] }).collect();
        c.truncate(399);
        let (p, ..) = at(&c, &a).expect("a strict prefix parts where it ends");
        assert_eq!(p, format!("{c:?}").len() - 1, "the shorter rendering parts at its closing bracket");
        assert!(at(&a, &(0..400).map(|i| Row { id: i, seq: vec![i; 3] }).collect()).is_err(), "identical renderings: no difference");
        // a difference deep inside one long map entry (its key lies further back than the captured context) names the key
        let m1: std::collections::BTreeMap<u64, Vec<u64>> = (0..10u64).map(|k| (k * 1_000_003, vec![k; 4000])).collect();
        let mut m2 = m1.clone();
        if let Some(v) = m2.get_mut(&7_000_021) {
            v[3900] = 1;
        }
        let r = |side: bool, out: &mut dyn std::fmt::Write| out.write_fmt(format_args!("{:?}", if side { &m2 } else { &m1 })).is_ok();
        let (_, _, _, ca, cb) = first_difference(&r, 24).expect("the maps differ");
        assert!(
            ca.contains("7000021") && cb.contains("7000021"),
            "the key of the entry the difference sits in is named although it lies past the captured context:\n{ca}\n{cb}"
        );
        // the order-only probe: the same rows reversed read equal, a changed row does not
        use super::super::restart_census_fields::{canonical_debug_of, multiset_digest};
        let ms = |x: &Vec<Row>| multiset_digest(&|out| out.write_fmt(format_args!("{x:?}")).is_ok());
        let rev: Vec<Row> = (0..400).rev().map(|i| Row { id: i, seq: vec![i; 3] }).collect();
        assert_ne!(canonical_debug_of(&a).0, canonical_debug_of(&rev).0, "CALIBRATION: the canonical digest keeps list order");
        assert_eq!(ms(&a), ms(&rev), "the same rows in another order are ORDER-ONLY");
        assert_ne!(ms(&a), ms(&b), "a changed value is CONTENT");
    }

    /// ⭐⭐⭐ DB-402 R3 — THE WIRE-LOSS CENSUS over the whole tree (`scripts/wire_loss_census.py`): no conversion fn (`of`, `from`,
    /// `into_*`, `to_*`, `wire*`, `decode*`, `encode*`) may set a field its source type carries to an empty literal, unless
    /// `DECLARED_DROPS` says why the receiver must not have it. The structs and the conversions are DISCOVERED from the source,
    /// so a conversion written tomorrow is in the census the day it exists (DB-401: `OrderWire::of` wrote the maker's bind as
    /// `Vec::new()`, and every book but the poster's held the offer hollow). CALIBRATION: DB-401's own text fires.
    #[test]
    fn the_wire_loss_census_finds_no_undeclared_drop_and_fires_on_db401() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/wire_loss_census.py");
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let run = |extra: &[&str]| -> (bool, String) {
            let o = std::process::Command::new("python3")
                .arg(script)
                .args(["--root", root])
                .args(extra)
                .output()
                .expect("python3 runs the wire-loss census");
            (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned())
        };
        // DB-401's text (c560219 `OrderWire::of`): the bind written empty although the order it converts carried it.
        const DB401: &str = "impl OrderWire {\n    pub fn of(o: &RestingOrder) -> OrderWire {\n        OrderWire {\n            \
                             lot: o.terms.lot,\n            membership_carrier: Vec::new(),\n            membership_tip: Vec::new(),\n        \
                             }\n    }\n}\n";
        let (ok, out) = run(&["--text", DB401]);
        assert!(
            !ok && out.contains("RestingOrder.membership_carrier dropped") && out.contains("RestingOrder.membership_tip dropped"),
            "⛔ CALIBRATION FAILED: the wire-loss census does not fire on DB-401's own text:\n{out}"
        );
        let (ok, out) = run(&[]);
        assert!(
            ok,
            "⛔ a conversion drops a field its source carries (DB-401's class) — carry it, or declare it in DECLARED_DROPS with why \
             the receiver must not have it:\n{out}"
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! persist — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// How stale a spend proof may be before the node stops reconstructing and asks for a fresh one.
    /// This bounds PROOF age only — never note age. A note from any height stays spendable; a wallet whose
    /// proof has aged simply rebuilds it (one O(1) fold step on a synced wallet) and the spend proceeds.
    /// Sized so an honest wallet always fits: blocks land ~2/s, so this is ~a minute of slack.
    /// O1-INFINITY-REVIEWED: a FIXED constant — the reconstruction scan is f(this constant), never f(chain
    /// height) or f(spent-set total), so per-spend verify cost is flat at any chain size.
    /// Start a node seeded with genesis, using the default (governance-tunable) parameters.
    pub fn new(genesis: Block) -> Result<Self, DagError> {
        Self::with_params(genesis, ChainParams::default())
    }

    /// Start a node with an explicit parameter set (both the DAG and mempool share it).
    pub fn with_params(genesis: Block, params: ChainParams) -> Result<Self, DagError> {
        let mut dag = Dag::with_params(params.clone());
        dag.add_block(genesis)?;
        let genesis_commit = params.genesis_parity_commit.clone();
        let net_prefix_len = params.net_prefix_len;
        // A node binary draws a fresh seed; a TEST build's is reproducible so the cert cache can hit (see the fn).
        let miner_seed = crate::reward::new_node_miner_seed();
        // PER-NODE fee key material (decentralization): a fee seed bound to THIS node's miner seed + its own
        // ML-KEM-768 fee keypair, used to derive a real per-epoch PQ stealth fee address. Never shared.
        let fee_seed = {
            let mut v = Vec::from(&b"MUSD-fee-seed-v1"[..]);
            v.extend_from_slice(&miner_seed);
            *Hash32::hash(&v).as_bytes()
        };
        let (fee_mlkem_pub, fee_mlkem_sec) = crate::pqkem::keypair();
        let mut node = Node {
            relay: BlockRelay::from_dag(dag),
            mempool: Mempool::with_params(params),
            oli_serve_cache: std::sync::Arc::new(OliServeCell {
                state: std::sync::Mutex::new(OliServeCache { built: None, building: None }),
                landed: std::sync::Condvar::new(),
                published_to: std::sync::atomic::AtomicU64::new(u64::MAX),
            }),
            own_publications: std::collections::BTreeMap::new(),
            validators: ValidatorSet::new(),
            finality: FinalityTracker::new(),
            observed: FinalityTracker::new(),
            lock_book: std::collections::BTreeMap::new(),
            lock_early: std::collections::VecDeque::new(),
            lock_door_tally: [0; locks::LOCK_DOOR_KINDS],
            seen_final_path: None,
            governance: Governance::new(),
            sites: SiteRegistry::new(),
            directory: crate::directory::Directory::new(),
            order_book: crate::order_book::OrderBook::new(),
            letter_acc: crate::letter::letter_acc_genesis(),
            dir_refill_target: None,
            dir_refill_stage: Vec::new(),
            dir_refill_stage_acc: crate::directory::dir_acc_genesis(),
            dir_refill_held: Vec::new(),
            dir_refill_held_closed: 0,
            // Correction 7 stage 3: empty until the live fold fills it — a cold ring keeps the
            // record-spine split detector quiet, never wrong (the unspent ring's own cold contract).
            spine_recent_roots: std::collections::VecDeque::new(),
            member_ring_commits: std::collections::VecDeque::new(),
            carried_ring_commits: None,
            completed_windows: std::collections::VecDeque::new(),
            window_index: crate::window_index::WindowIndex::new(),
            public_id: None,
            band_mix: None,
            own_unechoed: std::collections::HashMap::new(),
            dsync_adopts: 0,
            wallet_publications: std::collections::HashSet::new(),
            orphans_absent_parent: 0,
            spine_recent_frontiers: std::collections::VecDeque::new(),
            epoch_anchor_frontier: None,
            fold_checkpoint: None,
            clues: crate::clue_registry::ClueRegistry::new(),
            peer_dir: crate::peer_directory::PeerDirectory::new(),
            site_verifier: Box::new(UnpinnedVerifier),
            finality_verifier: Box::new(UnpinnedVerifier),
            decider_verifier: Box::new(UnverifiedDecider),
            synced: None,
            last_served_block: Vec::new(),
            da_mem: std::collections::BTreeMap::new(),
            da_wanted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            // ⛔⛔⛔ THE CURSOR'S FLOOR IS 1 — ORDINAL 0 IS GENESIS AND OWES NO SIDECAR, EVER.
            //
            // The cursor names the first ordinal whose sidecars this node still owes itself, and
            // genesis contributes NO leaves and has NO record row (`fold_canonical_records`: "a record
            // at ordinal k occupies leaves [(k-1)·256, k·256)"), so position 0 is covered BY
            // CONSTRUCTION on every node that ever existed. Starting at 0 made the certified position
            // (which counts one past the last record ordinal, genesis position included) exceed the
            // cursor's reachable range by exactly the genesis slot:
            // MEASURED `a_resumed_ingester_comes_back_ready_and_follows_the_producers_next_blocks`:
            // "ready=true gaps=4" on a resumed node holding all 3 records — backlog 4 = certified 4
            // minus a cursor pinned at 0 because `sidecar_cursor_advance_through(1)` refuses to start
            // anywhere but the cursor and no row exists (or ever will) at ordinal 0.
            sidecar_cursor: 1,
            sidecar_refill: false,
            sidecar_ask_starved: std::cell::Cell::new(0),
            da_wanted_ids: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            da_want_seed_cursor: std::cell::RefCell::new(0),
            da_want_seed_target: std::cell::Cell::new(0),
            note_body_want_cursor: std::cell::RefCell::new(0),
            da_ladder_mem: std::collections::HashMap::new(),
            da_ladder_adopted: std::collections::HashSet::new(),
            tip_pow_witness: None,
            anchor_pow_witness: None,
            wanted_ladder: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            own_validator_id: None,
            da_tags_mem: std::collections::BTreeMap::new(),
            da_targets_mem: std::collections::HashMap::new(),
            da_ord_mem: std::collections::HashMap::new(),
            da_leafstart_mem: std::collections::HashMap::new(),
            da_ord_rev_mem: std::collections::HashMap::new(),
            da_ord_top: 0,
            da_macc_rev_mem: std::collections::HashMap::new(),
            da_macc_fwd_mem: std::collections::HashMap::new(),
            da_macc_first: None,
            served_membership_acc: usdm_decider::poseidon2_compress::zero_digest(),
            da_reads: std::sync::atomic::AtomicU64::new(0),
            nf_fold_seq: 0,
            pending_fold_evictions: Vec::new(),
            wanted_ordinals: std::collections::BTreeSet::new(),
            bucket_ask_last_ms: std::cell::Cell::new(0),
            wanted_buckets: std::collections::BTreeMap::new(),
            // MUST EQUAL THE A_TIP GENESIS — same number, one definition. A second literal here made the
            // absence gate REFUSE HONEST SPENDS (tip matched, base did not). See nf_unspent_acc_genesis.
            nf_fold_base: (Self::nf_unspent_acc_genesis(), 0),
            nf_base_prev: Self::nf_unspent_acc_genesis(),
            payload_gap: std::collections::BTreeMap::new(),
            pending_tags: std::collections::HashMap::new(),
            pending_credit_notes: Vec::new(),
            pending_equivocations: Vec::new(),
            pooled_votes: std::collections::BTreeMap::new(),
            deferred_votes: std::collections::BTreeMap::new(),
            fold_landing_blue: None,
            pending_credit_justifiers: Vec::new(),
            account_buckets: std::collections::HashMap::new(),
            payment_receipts: Vec::new(),
            account_acc: crate::hash::Hash32::ZERO,
            membership_tip_prev: usdm_decider::poseidon2_compress::zero_digest(),
            membership_tip_root: usdm_decider::poseidon2_compress::zero_digest(),
            da_top: 0,
            da_base: u64::MAX,
            pending_bucket: std::collections::HashMap::new(),
            note_target_addr: std::collections::HashMap::new(),
            targets_claimed_total: 0,
            inflight_tx_ids: Vec::new(),
            agg_held: std::collections::HashMap::new(),
            agg_bundles: Vec::new(),
            bundle_worker: false,
            wanted_record_ids: std::collections::BTreeSet::new(),
            wanted_block_slots: [None; crate::protocol::TX_REQ_FIXED_COUNT],
            freshly_filed_buckets: Vec::new(),
            da_secret: std::sync::OnceLock::new(),
            served_seq: 0,
            fold_chain_tip: None,
            deep_fork_sweep_n: 0,
            da_sample_pending: std::collections::BTreeMap::new(),
            chain_cert: usdm_decider::whole_chain_cert::WholeChainCert::new(),
            certified_blue_work: 0,
            spine_stale: false,
            fold_reorgs: 0,
            certified_anchor: None,
            certified_anchor_score: 0,
            certified_prefix_len: 0,
            fold_waits: 0,
            fold_wait_on: None,
            fold_wait_since_len: 0,
            fold_no_progress_passes: 0,
            fold_progress_since_len: 0,
            da_want_stall_passes: 0,
            record_ask_nonce: std::sync::atomic::AtomicU64::new(0),
            da_want_fingerprint: 0,
            da_want_stall_since_ms: 0,
            row_hint_mismatches: 0,
            unfolded_blocks: Vec::new(),
            nf_span_cache: std::sync::Mutex::new((std::collections::HashMap::new(), std::time::Instant::now())),
            contract_leaf_ring: std::collections::VecDeque::new(),
            ion_cache: crate::node::objects::ion_pool::IonCache::default(),
            ion_step_writes: (0, Vec::new()),
            respend_journal: std::collections::HashMap::new(),
            respend_tag_journal: std::collections::HashMap::new(),
            respend_reach: std::collections::VecDeque::new(),
            nf_unfolded_gen: std::collections::HashMap::new(),
            nf_fold_base_pending: None,
            block_window: crate::block_window::BlockWindow::in_memory(),
            folded_floor: std::collections::HashSet::new(),
            note_clues: std::collections::HashMap::new(),
            note_clue_fifo: std::collections::VecDeque::new(),
            bond_locked: std::collections::HashMap::new(),
            unbonding: std::collections::BTreeMap::new(),
            bond_fold_journal: std::collections::VecDeque::new(),
            objects_vids_before: Vec::new(),
            objects_fold_journal: std::collections::VecDeque::new(),
            objects_journal_floor: 0,
            bond_journal_floor: 0,
            dir_fold_journal: std::collections::VecDeque::new(),
            dir_open_step: None,
            dir_journal_floor: 0,
            // W5: fixed-root from the first instant under the constant chain (a boot never starts in proof mode)
            band_door: {
                let mut d = crate::nf_sparse::BandDoor::new(Self::SPINE_RING_LEN);
                d.set_fixed_root(crate::canon_chain::canon_live());
                d
            },
            #[cfg(test)]
            band_autoprove_for_test: false,
            mesh_size_override_for_test: None,
            #[cfg(test)]
            template_double_for_test: false,
            #[cfg(test)]
            real_ledger_for_test: false,
            band_cursor: crate::nf_sparse::BandCursor::new(),
            band_steps_applied: 0,
            band_benched: std::collections::BTreeMap::new(),
            bond_height: std::collections::HashMap::new(),
            spend_frontier: crate::spend_frontier::PoseidonSpendFrontier::new(),
            root_history: crate::spend_frontier::PoseidonSpendFrontier::new(),
            nf_rebuild_failed_at: None,
            carrier_slot: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_shard_mesh: u32::MAX, // never derived yet — the first tick always derives
            pending_block_nullifiers: Vec::new(),
            mined_tx_nfs: std::collections::HashMap::new(),
            evicted_by_block: std::collections::HashMap::new(),
            fold_verdicts: std::collections::HashMap::new(),
            note_backfill_cursor: 0,
            reorg_heal_fired: false,
            da_stale_row_refusals: 0,
            da_poisoned_ordinals: std::collections::BTreeMap::new(),
            nf_recent_folds: crate::nf_sparse::RecentFoldBlocks::default(),
            dsync_covered: std::collections::BTreeMap::new(),
            sparse_acc_stale: false,
            pivot_span: Vec::new(),
            note_body_target: 0,
            note_body_acc_before: usdm_decider::poseidon2_compress::zero_digest(),
            note_body_acc_target: usdm_decider::poseidon2_compress::zero_digest(),
            span_close_landing: std::cell::Cell::new(None),
            roots_run_closed_target: usdm_decider::poseidon2_compress::zero_digest(),
            roots_run_own_cache: None,
            roots_run_spine_before: crate::spend_frontier::PoseidonSpendFrontier::new(),
            roots_run_spine_target: crate::spend_frontier::PoseidonSpendFrontier::new(),
            roots_run_cursor: crate::spend_frontier::PoseidonSpendFrontier::new(),
            roots_run_windows: crate::window_index::WindowIndex::new(),
            roots_run_origin_windows: crate::window_index::WindowIndex::new(),
            sparse_acc: crate::nf_sparse::SparseNfAcc::new(),
            join: Default::default(),
            join_step_buf: Vec::new(),
            join_frozen: Default::default(),
            join_last_freeze: 0,
            nf_evidence_cache: std::collections::HashMap::new(),
            nf_shard_fetch: std::collections::HashMap::new(),
            nf_band_gathered: std::collections::HashMap::new(),
            nf_band_wants: Vec::new(),
            sparse_work: (!crate::canon_chain::canon_live()).then(crate::nf_sparse::RefSparseNf::initial_view), // A-F114 U1: no spent set under the constant chain; // re-built under the shard policy by `new_sparse_work` once the identity is set
            nf_blocks: 0, // genesis has applied no nullifier blocks
            nf_leaves: 0,
            // ⭐⭐⭐ A_TIP GENESIS = f(NETWORK), DOMAIN-SEPARATED — never the all-zero seed.
            //
            // Two defects closed at the source rather than papered over at the read:
            //  1) ALL-ZERO COLLIDED WITH THE "UNSET" SENTINEL. `nullifier_root()` projects this accumulator, so
            //     a `usdm_decider::poseidon2_compress::zero_digest()` seed made a fresh node's committed root THIRTY-TWO ZERO BYTES — the exact
            //     encoding this codebase uses for "absent" (e.g. the `state.sparse_root != [0u8; 32]` adopt
            //     check). MEASURED: a verifier grafted NOTHING, `nf_fold_seq() == 0` where 4 was expected.
            //  2) CROSS-NETWORK COLLISION. A count-free accumulator seeded identically on every network lets a
            //     testnet root equal a mainnet root at the same block SET. Seeding from the network id binds the
            //     accumulator to its chain, so a foreign root can never be mistaken for a local one
            //     ([[feedback_ecosystem_chain_aware]] [[feedback_chains_nondeterministic_network_ids]]).
            //
            // FIXED HERE, NOT AT THE PROJECTION. Hashing inside `nullifier_root()` also removes the zero, but
            // that value is NOT only the reported root — `nullifier_seed_root()` feeds `block_pre` at produce
            // while ingest reads the committed `header.nullifier_root`, so projecting moved ONE side of the fold
            // algebra and broke convergence outright (MEASURED: a_nf_blocks=4 vs b_nf_blocks=49,
            // nf_acc_agree=false, where the raw seed gave 6/6 and agreement). Moving the BASE moves both sides
            // identically, which is why the genesis seed is the correct layer for this.
            //
            // Same shape as `unspent_note_root` below, which already seeds from `process_network_id()`.
            nf_unspent_acc: Self::nf_unspent_acc_genesis(),
            canon_c: crate::canon_chain::genesis(),
            canon_recent: crate::canon_chain::CanonRecent::default(),
            canon_missing: 0,
            canon_index: 0,
            canon_decoy_seq: 0,
            canon_fill: None,
            canon_rewind: std::collections::VecDeque::new(),
            canon_saved_top: std::sync::Arc::new(crate::canon_chain::CanonSaved::default()),
            canon_resume_rewind: None,
            work_final: None,
            floor_final: None,
            db471_failed_anchor: None,
            canon_bounty_seq: 0,
            canon_theft_seq: 0,
            canon_held_wrappers: Vec::new(),
            release_book: std::collections::BTreeMap::new(),
            release_own_pending: Vec::new(),

            // Deterministic genesis seed for the confidential real-spend-blob accumulator (same on every node).
            // Early-chain residual: until the first real spend folds in, this is a known constant, so a zero-spend
            // block before ANY spend is still recomputable — negligible in steady state (documented follow-on).
            nf_cover_conf_acc: *Hash32::hash(b"MUSD-nf-cover-conf-acc-genesis-v1").as_bytes(),
            nf_conf_advances: 0,
            // 150% over-collateralization (the Buy-USDm reserve default); the LIVE governance ratio still gates
            // the mint via `authorize_mint`, this is the peg-ledger's own solvency floor. `genesis` (not `new`)
            // seeds the confidential-solvency pair to commitment-to-ZERO under the well-known genesis blinds, so
            // the FIRST peg-in on a fresh chain has a real OLD commitment to prove against (a raw `[0;4]` matches
            // no `solvency_commit_256` output ⇒ the first mint would be unprovable). See `PegLedger::genesis`.
            peg: crate::peg::PegLedger::genesis(15_000),
            // Seed the custodian opening to the genesis (zero-value) opening under the genesis blinds — matches the
            // zero-state digests `PegLedger::genesis` seeds, so the FIRST orchestrated mint proves from it.
            custodian_opening_seal: seal_opening(
                0,
                crate::peg::GENESIS_PEG_RESERVE_BLIND,
                0,
                crate::peg::GENESIS_PEG_MINTED_BLIND,
            ),
            peg_attest_pending: std::collections::BTreeMap::new(),
            custodian_identity: None,
            payout_events: std::collections::VecDeque::new(),
            defi_events: std::collections::VecDeque::new(),
            defi_intake: std::collections::VecDeque::new(),
            reserve_solvency_hold: false,
            xmr_reserve_solvency_hold: false,
            custody_leaf_ring: std::collections::VecDeque::new(),
            xmr_custody_ring: std::collections::VecDeque::new(),
            custodian_opening_history: std::collections::VecDeque::new(),
            xmr_opening_history: std::collections::VecDeque::new(),
            // §BR-3 17.6: the stakers' pool paid-out opening starts at the public genesis (zero under its genesis blind)
            custodian_paid_seal: super::seal_paid(0, crate::peg::GENESIS_STAKE_PAID_BLIND),
            custodian_paid_history: std::collections::VecDeque::new(),
            epoch_seed_shares: std::collections::BTreeMap::new(),
            unapplied_shell_floor: None,
            unapplied_shell_ceiling: 0,
            unapplied_shell_count: 0,
            unapplied_shell_ids: std::collections::VecDeque::new(),
            anchor_block_full: None,
            parked_votes: std::collections::VecDeque::new(),
            applied_one_time_ids: std::collections::VecDeque::new(),
            peg_in_published: std::collections::BTreeMap::new(),
            deposit_sweeps: std::collections::VecDeque::new(),
            peg_out_published: std::collections::BTreeMap::new(),
            peg_minted_heights: std::collections::BTreeMap::new(),
            own_membership_bond: None,
            peg_out_attest_pending: std::collections::BTreeMap::new(),
            custody_opening_path: None,
            own_record_path: None,
            reward_recipient_file: None,
            peg_requests: std::collections::BTreeMap::new(),
            wrapped_published: std::collections::BTreeMap::new(),
            wrapped_opening_path: None,
            pool_opening_path: None,
            // Per-wrapped-asset openings are seeded lazily on registration (genesis zero-value opening) — none exist
            // until governance registers a wrapped asset, so start empty.
            // Monero's ledger is born at genesis (`PegLedger::genesis`), so its genesis opening is too
            wrapped_opening_seals: std::collections::HashMap::from([(
                crate::peg::XMR_PEG_ASSET_ID,
                genesis_opening_seal(crate::peg::XMR_PEG_ASSET_ID),
            )]),
            pool_openings: std::collections::HashMap::new(),
            pool_close_openings: std::collections::HashMap::new(),
            liquidation_book: std::collections::BTreeMap::new(),
            vault_key_book: std::collections::BTreeMap::new(),
            reserve_cost_book: std::collections::BTreeMap::new(),
            vault_merge_book: std::collections::BTreeMap::new(),
            rebalance_book: std::collections::BTreeMap::new(),
            rebalance_relayed: std::collections::VecDeque::new(),
            vault_key_coin_view: None,
            xmr_reserve_whole: None,
            theft_repay_book: std::collections::BTreeMap::new(),
            pot_book: std::collections::BTreeMap::new(),
            unit_close_book: std::collections::BTreeMap::new(),
            quote_book: crate::price_quote::QuoteBook::default(),
            relay_answers: Vec::new(),
            reward_recipient: Self::initial_reward_recipient(&miner_seed),
            miner_seed,
            l2_state_root: [0u8; 32],
            settlement_verifier: Box::new(crate::settlement::RefuseAllSettlement),
            fee_seed,
            fee_mlkem_pub,
            fee_mlkem_sec,
            // #73 PoUW: PQ-PoUW miner+verifier keyed to this node's per-node coinbase secrets ([u8;32] is
            // Copy, so &miner_seed here is fine after the field move above).
            pow_miner: crate::pow::PowMiner::new(),
            persist_path: None, // opt-in via `enable_persist` (the serve loop); tests run non-persistent
            last_autosave: None,
        };
        // ⭐ THE FOUNDING SEATS (user 2026-11-04): a genesis fact like the launch's book, on every node before its first block, so custody, the price mark and the
        // bridge exist from the first block. A restored node reads its own validator set over this one.
        let founders = crate::defi_launch::genesis_seats();
        if !crate::validator::seat_founders(&mut node.validators, &founders) {
            eprintln!("[defi-launch] ⛔ the validator set refused a founding seat");
        }
        for (vid, _, seat, _) in founders {
            node.lock_bond_note(vid, seat.locked_note, 0);
        }
        // ⭐ §18.14: a chain that launched its pools holds their two coin ledgers from its first block
        if !crate::defi_launch::genesis_seats().is_empty() {
            for id in crate::peg::COIN_LEDGERS {
                node.register_wrapped_asset(id, crate::peg::COIN_RATIO_BPS);
            }
        }
        // GENESIS = DETERMINISTIC PER-NETWORK CONSTANT, NO COMMIT (user 2026-07-13). `genesis_commit` is now PURELY
        // the per-network id prefix (`network_genesis_prefix`) with ZERO per-device input, and `net_prefix_len`
        // equals its full length — so the aligned region past the prefix is ALWAYS empty and genesis records NO
        // state. That is what makes two FRESH devices on the same network build a BYTE-IDENTICAL genesis and
        // converge (a device can never diverge from a fresh one). The generic guard below is kept fail-safe: were
        // an aligned region ever supplied, it would flow the SAME ordinary note path.
        let payload: &[u8] = if genesis_commit.len() > net_prefix_len {
            &genesis_commit[net_prefix_len..]
        } else {
            &[]
        };
        // GENESIS GETS A LEDGER RECORD LIKE EVERY OTHER BLOCK — unconditionally, payload or not.
        //
        // Skipping it left genesis in every node's DAG with no record, so `blocks_missing_ledger_records`
        // returned it forever and the by-id backfill spun on it: measured 1,242 consecutive unserved requests,
        // every one for record id 7305956828534032, while the peer holding 3,470 records had none for it. The
        // gap could never close because the block it kept asking for was one NO node had ever recorded.
        //
        // It is also the same distinguishability rule: a block without a record is identifiable by that
        // absence. Genesis is not an exception to "every block has a record".
        // Genesis's ledger record is written in `enable_persist`, NOT here. At construction `persist_path` is
        // still None, so a record written now goes to the in-memory shard and never reaches disk — measured:
        // `[da] STORE genesis rid=7305956828534032 reals=1 dir=None`. Worse, that phantom write claimed sub=0
        // for the id, so the later real write was pushed to sub=1 and the genesis record id stayed empty
        // forever. One write, once persistence exists.
        if !payload.is_empty() {
            node.record_note_payload_for(node.relay.dag().genesis(), 0, payload, None); // §20.2: the public genesis record takes the idle key
        }
        // ⛔ DO NOT FOLD THE GENESIS RECORD HERE. Tried 2026-09-04 and MEASURED the cost: folding it at
        // construction appends its 256-leaf cover shape to the spend frontier, so the accumulator starts
        // one record higher than every existing node's (`persist_restart_resumes_state…` read 768 leaves
        // where two records must give 512), and a node resumed beyond genesis then certified a funded note
        // ABSENT. The initial accumulator is chain identity — it cannot move to tidy up an ordinal.
        // Genesis's record is written where it always was, by `enable_persist` (see `ensure_genesis_record`),
        // and the fold starts at 1 when that row exists, 0 when it does not.

        Ok(node)
    }

    /// Every known dialable peer record. The auto-peer loop (re-)dials these on boot + on each fresh adopt, so a
    /// node re-forms the mesh from its persisted + gossiped view among whoever is alive — no single bootstrap
    /// node is a point of failure once a node has joined even once.
    /// Tell the peer directory THIS node's own owner id, so its own announcement is never filed as a peer.
    ///
    /// MEASURED 2026-08-01: `announce_peer` adopts the node's OWN record, so the node became its own peer and
    /// the dialer then tried to rendezvous with its own onion — impossible, and every attempt burned circuits
    /// on the guards it needed to publish its service. A node started with NO seed peers still reported
    /// `writers_held 1` and logged `[arti] dial <its own .onion> failed`.
    pub fn set_self_peer_owner(&mut self, owner: [u8; 32]) {
        self.peer_dir.set_self_owner(owner);
    }

    /// Enable on-disk persistence of the peer directory at `path` (the serve loop wires this at startup, before
    /// the mesh spins up), loading any previously-learned peers so a restarted node immediately re-dials them —
    /// the pinned seed is never needed a second time.
    pub fn enable_peer_persist(&mut self, path: std::path::PathBuf) {
        self.peer_dir.enable_persist(path);
    }

    /// ⭐ THE CHAIN-DEFINED ORDINAL-0 ROOT — the genesis record's root, derived from the genesis block id
    /// alone (an EMPTY record's fixed 256-leaf shape seeded by genesis's canonical record address).
    /// Identical on every node of this chain, at any time, from O(1) state — never a stored row, and
    /// provably not the all-zero sentinel (pinned). Its transition is the identity: genesis folds nothing.
    pub fn genesis_membership_record_root(&self) -> Option<crate::spend_frontier::Digest4> {
        let g = self.relay.dag().genesis()?;
        let rid = Self::da_record_id_for_block(&g, 0);
        // ONE encoding with the record write's own empty-block law (`record_note_payload_inner`: an empty
        // block records ONE `public_idle_seed_note(seq)`, seq-derived and identical on every node), so
        // this constant equals what any node derives from the genesis record's actual bytes. Read-only
        // derivation from public chain structure — nothing moves and nothing needs publishing.
        let seed = crate::cover::public_idle_seed_note(rid);
        Some(Self::fold_leaves_to_root(&Self::block_leaves_from_notes(
            &seed, rid, &crate::cover::idle_cover_key(rid),
        )))
    }


    /// Re-register the FILED index (`note_target_addr`) from a record's persisted targets blob — the wire
    /// shape `cm ‖ bucket ‖ ek_len ‖ ek` per target (the same offsets `account_target_wire` parses).
    /// First writer wins: a target already filed (by the live path, or an earlier row) keeps its address.
    /// Bounded by the blob: one lookup per target the record consumed.
    pub(super) fn register_filed_targets_from_blob(&mut self, rid: u64, blob: &[u8]) {
        let mut off = 0usize;
        while off + 66 <= blob.len() {
            let ek_len = u16::from_le_bytes([blob[off + 64], blob[off + 65]]) as usize;
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&blob[off..off + 32]);
            if !self.note_target_addr.contains_key(&cm) {
                self.note_target_addr.insert(cm, rid);
            }
            off += 66 + ek_len;
        }
    }

    /// ⭐ THE TAGS RESUME WITH THE CHAIN — re-derived from the whole blocks the on-disk block window holds (Bitcoin Core's
    /// `-reindex`: indexes are a function of the block files; the window is the owner-approved Kaspa pruning-window store).
    ///
    /// `da_tags_mem` is the sole source of the OLI locator index (`oli_klog_entries`) and is RAM-only, so after a restart
    /// the index held nothing. MEASURED 2026-10-06 (simulator `sim-fast-11`, T1.4): every index build after the rolling
    /// restart read 0 tags (epochs 128…320; epoch 64, before it, read 2), no wallet could locate a note that landed before
    /// the restart, and W1's own 22.0 change stayed "pending change" forever — the live gate's "custody 0.0".
    ///
    /// §9.6 — this door admits bytes from the node's own block window into the tag sidecar:
    /// 1. PoW — n/a: no block enters the DAG; each block is one this node already holds — in its DAG or as a window body
    ///    (same id, read back whole).
    /// 2. Proof — the carried list must reproduce the block's own `header.oli_tags_root` (`da_sidecar_root_of`), the bind
    ///    every producer seals and every ingest checks; the block read back must hash to the id the DAG names.
    /// 3. Conservation — a tag moves no value: a locator key beside a note, read only to find positions.
    /// 4. Replay — first write wins per slot (`file_tags_at_fixed_slots`), so a second resume is a no-op.
    /// 5. Bounded — one window read per folded real-note record; the window is the DAG's own span (fixed params).
    /// 6. Parity — the door it parallels is the ingest carry (`[oli-carry]`, every delivery): the TAG_REC length check and
    ///    the carried-cm-must-be-a-record-note match. This door runs both, and ADDS the header-root bind and the id check.
    /// cons: one block-file read per folded real-note record at resume (bounded by the window; ~21 KB each). Tags placed
    /// without a carrying block (a late clue, the fold's unbond release) are not in any block and are not re-derived here.
    /// Returns `(records re-tagged, tags filed, window blocks refused)`.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: counts only in the log line; tags are written beside records this node holds.
    pub(crate) fn restore_tags_from_block_window(&mut self) -> (usize, usize, usize) {
        // ⛔ G1 (lane b 2026-10-24): every block this node HOLDS — its DAG and the window's bodies the DAG never held (a
        // joiner's fold-span bodies of the adopted past, now left out of the restored DAG as the live process leaves them).
        // Walking the DAG alone dropped their records' tags across the restart (joiner restart census `da_tags_mem` 66,560 →
        // 43,089 B, joiner-restart-bo3.log). Same bind for both: the body read back must hash to the id and its header must
        // bind the list, and the record must already be held and folded.
        let mut ids: Vec<crate::block::BlockId> = self.relay.dag().block_ids();
        let held: std::collections::HashSet<crate::block::BlockId> = ids.iter().copied().collect();
        ids.extend(self.block_window.ascending().into_iter().map(|(_, id)| id).filter(|id| !held.contains(id)));
        let (mut records, mut tags, mut refused) = (0usize, 0usize, 0usize);
        for id in ids {
            let Some(seq) = self.record_addr_for_block(&id) else { continue };
            if !self.da_ord_mem.contains_key(&seq) {
                continue; // not folded: the record loop files its tags when it folds
            }
            let Some(blk) = self.block_window.get(&id) else { continue };
            let Some(carried) = Self::window_block_carried_tags(&blk, &id) else {
                refused += 1;
                continue;
            };
            if carried.is_empty() {
                continue;
            }
            if let Some((_, added)) = self.file_tags_at_fixed_slots(seq, carried) {
                records += usize::from(added > 0);
                tags += added;
            }
        }
        eprintln!(
            "[resume] OLI locator tags re-derived from the block window: {tags} tag(s) on {records} record(s), {refused} window \
             block(s) refused (not the DAG's id or not their header's tag root)"
        ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts only.
        (records, tags, refused)
    }

    /// ⭐⭐⭐ THE HEADER HALF OF HEADERS-FIRST — admit a RUN of block roots by folding it to a value we
    /// already trust, so fetched bodies finally have something to be checked against.
    ///
    /// MEASURED, and this is the defect it closes: after a DSYNC adopt the body fetch worked — peers answered
    /// — and every single record was refused, `[da-fetch] 0/1 peer record(s) verified against roots we hold`,
    /// with the 118-block gap never shrinking. `accept_fetched_record` checks a body against
    /// `da_block_root_at_ordinal`, but a node that JUMPED consensus never received the skipped blocks'
    /// headers, so it holds no root for them and the check fails closed forever. Body without header is
    /// unverifiable by construction; that is exactly why Kaspa ships the header chain FIRST.
    ///
    /// Our header equivalent is the block ROOT, and we do not need to trust the sender for it either. The
    /// membership accumulator is a fold over block roots, and the adopt already carries a CERTIFIED
    /// accumulator. So a served run of roots is admissible iff folding it from the accumulator we hold
    /// reproduces that certified value: one wrong, missing, extra or reordered root cannot land on it. The
    /// run is then written down, and the bodies that follow verify against those roots as normal.
    ///
    /// Trustless: no root is believed because a peer sent it — the run is believed because it folds to a value
    /// this node already certified. Nothing partial is stored, so a truncated or poisoned run advances zero.
    /// Open a roots-run span: the spine this node holds on its own (`before`) and the certified spine it
    /// must reach (`target`). The fold cursor restarts at `before`. Called at a DSYNC adopt and at a
    /// resume that is short of rows.
    pub(crate) fn open_roots_run_span(
        &mut self,
        before: crate::spend_frontier::PoseidonSpendFrontier,
        target: crate::spend_frontier::PoseidonSpendFrontier,
    ) {
        self.roots_run_origin_windows = self.origin_windows_the_target_merges(&before, &target); // DB-429
        self.roots_run_cursor = before.clone();
        self.roots_run_spine_before = before;
        self.roots_run_spine_target = target;
        self.roots_run_windows = crate::window_index::WindowIndex::new(); // DB-418: a new span stages its own windows
    }

    /// ⭐ DB-223 / DB-274 P3 — reinstall the anchor ring a checkpoint's fold record carried, ONLY when it describes the
    /// spine this node just restored: dense ascending ordinals, within the reach, and its newest root equal to the
    /// restored spine's own root. Anything else installs nothing (the live fold refills it; a spend whose anchor
    /// predates the restart then waits, never passes on a ring this node cannot vouch for). Returns whether it installed.
    pub(crate) fn install_anchor_ring(&mut self, ring: &[(u64, crate::spend_frontier::Digest4)]) -> bool {
        let Some((_, newest)) = ring.last() else {
            return false;
        };
        let dense = ring.windows(2).all(|w| w[1].0 == w[0].0.saturating_add(1));
        if !dense || ring.len() > self.anchor_ring_len() || *newest != self.spend_frontier.root() {
            // which check refused it, so one run names its own cause (MEASURED 2026-11-10, round 22: an adopt refused a
            // 227-entry ring with no reason given and the fold then waited 806 passes). DIGITAL-CASH-PRIVACY-REVIEWED:
            // ordinals and counts of the public spine; no root, note, tag, amount, key or owner.
            eprintln!(
                "[anchor-ring] ⛔ the checkpoint's ring does not describe the restored spine ({} entries, ordinals {}..{}; dense {dense}; \
                 within reach {}; newest root is this spine's {}; this spine holds {} record(s)) — not installed; the held-record \
                 replay rebuilds this node's own ring",
                ring.len(),
                ring.first().map_or(0, |(o, _)| *o),
                ring.last().map_or(0, |(o, _)| *o),
                ring.len() <= self.anchor_ring_len(),
                *newest == self.spend_frontier.root(),
                self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64
            );
            return false;
        }
        self.spine_recent_roots = ring.iter().copied().collect();
        true
    }

    /// §RF-3 — install a carried history (checkpoint or certified bundle) AFTER its anchor ring was installed: only a
    /// dense history within reach whose newest entry is the ring's newest step AND equals the commit this node computes
    /// from the ring it now holds. Anything else installs nothing (the live fold refills it; a header naming an older ring
    /// then waits, never passes). Returns whether it installed.
    pub(crate) fn install_member_ring_commits(&mut self, commits: &[(u64, crate::hash::Hash32)]) -> bool {
        let dense = commits.windows(2).all(|w| w[1].0 == w[0].0.saturating_add(1));
        let newest_ok = commits.last().is_some_and(|(k, c)| {
            self.spine_recent_roots.back().map(|(o, _)| *o) == Some(*k) && self.current_member_ring_commit() == Some(*c)
        });
        if !dense || !newest_ok || commits.len() > self.anchor_ring_len() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count of public spine ring commits; no note, tag, amount, key or owner.
            eprintln!(
                "[member-ring] ⛔ the carried ring-commit history does not describe the installed ring ({} entries) — not installed; the live fold refills it",
                commits.len()
            );
            return false;
        }
        self.member_ring_commits = commits.iter().copied().collect();
        true
    }

    /// Record this node's PUBLIC peer id (its announced onion record's) for the shard holder rule.
    pub fn set_public_id(&mut self, id: String) {
        self.public_id = Some(id);
    }

    /// ⭐ G1g-iv (lane a 2026-10-23) — bind this node's own announced record to `path` and restore the PUBLIC id it carries.
    /// `public_id` was declared VOLATILE ("a node not yet announced is not yet a prover"), but every PEER persists this node's
    /// record across its restart (Bitcoin addrman's peers.dat), so the mesh kept counting the restarted node as a prover while
    /// the node alone forgot itself: `band_provers` lost one member and the band door's solicit window `W = M` read 2 → 1 on
    /// both nodes (g1giii-restart-census-2-20261023.log). A turn set must be a function every node computes alike (DB-404), so
    /// the node's own record rides its files: decoded exactly, verified like a peers.dat line (`PeerGossip::verify`: onion-only
    /// address, ML-DSA self-signature) and OWNED by this node's own key (`own_validator_id` — the key every announce door signs
    /// with: main.rs, serve.rs, the simulator), else nothing is restored and the process boots unannounced as before. The
    /// directory's self owner is restored with it, so a restarted node never files itself (DB-355). Returns whether restored.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: this node's own PUBLIC record, gossiped in clear to every peer and already persisted
    /// by every peer — never a note, amount, key, owner or commitment. O1-INFINITY-REVIEWED: one signed record (≈ 4 KB).
    /// cons: one bounded file read per boot.
    pub fn enable_own_record_persist(&mut self, path: std::path::PathBuf) -> bool {
        self.own_record_path = Some(path.clone());
        let Ok(bytes) = std::fs::read(&path) else { return false };
        let Some(g) = crate::chain_object::decode_exact::<crate::peer_directory::PeerGossip>(&bytes) else { return false };
        let Some(owner) = g.verify() else { return false };
        if self.own_validator_id != Some(owner) {
            return false; // a stranger's record never names this node's identity
        }
        self.peer_dir.set_self_owner(owner);
        self.public_id = Some(g.record.peer_id);
        true
    }

    /// ⛔ DB-358 increment 2 — resume the respend state a checkpoint carried. It runs BEFORE the carry graft folds
    /// anything (`restore_from_disk`). A carry longer than the reach ring keeps only its newest steps, the same bound
    /// the live ring holds.
    pub(super) fn install_respend_carry(&mut self, c: &crate::respend::RespendCarry) {
        self.respend_journal = c
            .journal
            .iter()
            .map(|(id, addr, revoked)| {
                (Hash32(*id), (*addr, revoked.iter().map(|(i, n)| (*i as usize, n.clone())).collect()))
            })
            .collect();
        let skip = c.reach.len().saturating_sub(Self::REWIND_RETAIN);
        self.respend_reach = c.reach.iter().skip(skip).map(|(o, id)| (*o, Hash32(*id))).collect();
    }

    /// ⭐ DB-274 P2 (§8.7) — put back everything ONE fold step changed: each touched validator's before-state, the
    /// set's scalars, and the notes it released (taken back off the end of its record row, where it appended them).
    pub(super) fn restore_bond_fold_step(&mut self, step: BondFoldStep) {
        for v in step.vids {
            self.validators.set_vid_state(v.vid, v.set);
            match v.locked {
                Some(n) => {
                    self.bond_locked.insert(v.vid, n);
                }
                None => {
                    self.bond_locked.remove(&v.vid);
                }
            }
            match v.height {
                Some(h) => {
                    self.bond_height.insert(v.vid, h);
                }
                None => {
                    self.bond_height.remove(&v.vid);
                }
            }
            match v.unbonding {
                Some(u) => {
                    self.unbonding.insert(v.vid, u);
                }
                None => {
                    self.unbonding.remove(&v.vid);
                }
            }
        }
        self.validators.set_scalars(step.burned, step.commit);
        if step.pushed > 0 {
            if let Some(row) = self.da_mem.get_mut(&step.row) {
                let keep = row.0.len().saturating_sub(step.pushed);
                row.0.truncate(keep);
            }
        }
    }

    /// ⭐ THE ONE WHOLESALE WRITE OF THE VIEW. Every site that replaces or drops `sparse_work` (a reshard, a warm's install,
    /// a rebuild, an adopt, a restore, a rewind the view could not follow) goes through here, so the prover's cursor —
    /// an overlay ON the view — is never left describing a tree that is gone (a stale cursor yields proofs every door
    /// refuses). The band drain's incremental advance is not wholesale and does not come here.
    pub(super) fn set_sparse_work(&mut self, view: Option<crate::nf_sparse::RefSparseNf>) {
        // ⭐ A-F114 U1 — under the constant chain no node holds the spent set: every wholesale write installs nothing, so no
        // warm, restore, adopt or rebuild can bring the O(spent) tree back (docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md U1).
        let view = if crate::canon_chain::canon_live() { None } else { view };
        // DIGITAL-CASH-PRIVACY-REVIEWED: shard counts of this node's own view; no tag, root, amount or owner.
        eprintln!("[nf-share] view installed: {:?} (shard bits, shards held)", view.as_ref().map(crate::nf_sparse::RefSparseNf::shard_policy));
        self.sparse_work = view;
        self.band_cursor = crate::nf_sparse::BandCursor::new();
        // ⛔ A NEW VIEW IS A NEW INPUT TO THE SHARD POLICY (lane b 2026-10-24, T2): `maybe_reshard_nullifier_view` memoises on
        // the mesh size alone, so a pivot warm install of a COMPLETE sharded view `(8, 256)` after the memo was set kept that
        // representation for the life of the process, while a restart (memo `u32::MAX`) re-filed it to `(0, 0)` on its first
        // tick — the joiner restart census read `sparse_work` shard_policy (8, 256) → (0, 0), last_shard_mesh 3 → MAX
        // (joiner-restart-r2.log). Every install re-arms the memo here, the one writer of the view.
        // cons: one O(2^s) policy derivation on the tick after an install (installs are rare; never per block).
        self.last_shard_mesh = u32::MAX;
    }

    /// ⭐⭐⭐ DB-290 (A''): INSTALL A PIVOT WARM THE WORKER BUILT AND CHECKED OFF THIS NODE'S LOCK.
    ///
    /// `h` exists only if its scratch reached `set(R)` EXACTLY (`PivotWarm::into_healed` checks the root against the
    /// pivot) and then re-took `tail[..synced]`.
    ///
    /// ⭐ DB-353 landing 2 (§13.5 wholesale table) — the door re-checks what can have changed since the worker started:
    /// - the node still holds no view;
    /// - the warm's target `R` is still placeable in this node's band journal within the tail bound;
    /// - `synced` is within the band tail since `R`.
    ///
    /// Then the tree is BROUGHT FORWARD: `tail[synced..]` — the admitted tags the band applied after `R` that the worker
    /// had not yet synced, in fold order, from this node's own door journal — are inserted, and the result is admitted as
    /// the view ONLY if its root is the band root NOW. A warm that started earlier is therefore never discarded because
    /// the band moved (the livelock the RAM tail left behind under P1: every drained step restarted the warm), and a tree
    /// that does not reach the proven band root installs nothing.
    pub fn install_healed_pivot(&mut self, h: crate::nf_sparse::HealedPivot) -> bool {
        let (mut tree, pivot, synced) = h.into_parts();
        let tail = if self.sparse_work.is_none() && self.sparse_pivot_placeable(pivot) {
            self.sparse_pivot_tail_since(pivot, 0)
        } else {
            None
        };
        let Some(rest) = tail.filter(|t| synced <= t.len()).map(|t| t[synced..].to_vec()) else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a state name only; no tag, root, amount or owner.
            eprintln!(
                "[sparse-pivot] ⛔ a healed warm arrived for a target this node can no longer bring forward (a view is \
                 held, or the target left the band journal's reach) — discarded; the next warm targets the live band root"
            );
            return false;
        };
        // The ONE insert the warm's own tree takes (its pages and its healed tail go in the same way): a sharded scratch
        // (`PivotWarm::new` builds every shard owned) advances by the batch walk.
        // MEASURED 2026-09-30 (`db353_a_warm_started_…`): a per-tag `insert_and_witness` over this tree left a root off
        // the band while an independently rebuilt set equalled it (expected == J band == S band == S view).
        let _ = tree.advance_block_rooted(&rest);
        let band_now = crate::spend_frontier::leaf_to_cm_bytes(self.band_door.band_root());
        if tree.root_bytes() != band_now {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed phrase and a count; no tag, root, amount or owner.
            eprintln!(
                "[sparse-pivot] ⛔ a healed warm brought forward by {} band tag(s) does not reach the band root — not \
                 installed; the next warm starts over",
                rest.len()
            );
            return false;
        }
        let Some(acc) = crate::nf_sparse::SparseNfAcc::adopt_merkle_root(band_now) else {
            return false;
        };
        self.set_sparse_work(Some(tree));
        self.sparse_acc = acc;
        self.sparse_acc_stale = false;
        self.pivot_span = Vec::new(); // DB-339 part 3: the view is installed; the span has done its work
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts over a PUBLIC replicated set; no tag, amount or owner.
        eprintln!(
            "[sparse-pivot] ✅ the copath source is warm against the band root: {synced} tag(s) synced off-lock, {} brought \
             forward from the band journal",
            rest.len()
        );
        true
    }

    /// ⭐ T2 real lane (lane b 2026-10-23) — THE CHECKPOINT'S RESTING BOOK RE-ENTERS THROUGH ITS ONE DOOR. MEASURED why: the
    /// real journey's leg 3 restarted all three nodes with one order on node 1's book (sim-20261023-053354.log :15980) and the
    /// taker read "no resting orders for this pair right now" (:19294) — the book was RAM-only and no resume replayed the
    /// post block. Every wire goes through `decode_exact` + `post_order` at the restored tip height, exactly as the gossip arm
    /// and the carried `Class::OrderPost` apply do (Bitcoin Core's mempool.dat reload re-validates every entry).
    /// §9.6: (1) PoW — none; the entry was admitted through a door that checked its carriage. (2) Proof — the maker half
    /// re-verifies in `OrderBook::post`. (3) Value — the book moves none; a fill is decided at the fill door. (4) Replay —
    /// `Duplicate` (this book) and `MakerSpent` (the restored spent view). (5) Work — one decode + one verify per entry, the
    /// entries bounded by what the book held. (6) Parity — the gossip arm's `decode_exact` + `post_order`, nothing skipped.
    /// Returns (rested, refused).
    pub(super) fn restore_resting_orders(&mut self, wires: Vec<Vec<u8>>) -> (usize, usize) {
        let (mut rested, mut refused) = (0usize, 0usize);
        for bytes in wires {
            match crate::chain_object::decode_exact::<crate::order_book::OrderWire>(&bytes)
                .map(|w| self.post_order(w.into_order()))
            {
                Some(Ok(_)) => rested += 1,
                _ => refused += 1,
            }
        }
        if rested + refused > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two counts of this node's own book at boot; no order, maker or amount.
            eprintln!("[order-book] resumed {rested} resting order(s) from the checkpoint; {refused} refused at the post door");
        }
        (rested, refused)
    }

    /// Read the live peg reserve ledger (per-asset reserve, minted USDm, solvency).
    /// ⭐ REGISTER A DSOL ASSET into this node's registry accumulator; returns the new registry root.
    /// Called from the graft-side asset door, so every node that grafts the creation reaches the same root.
    pub fn register_dsol_asset(&mut self, c: &crate::dsol::DsolContract) -> [u8; 32] {
        self.peg.dsol_tokens_mut().register(c);
        self.peg.dsol_tokens().root_bytes()
    }

    /// The executor's opening advances when the block carrying ITS peg-out grafts — the peg-out twin of
    /// `advance_custodian_opening_from_delta`, guarded the same way (the advanced opening must open the
    /// commitments the ledger just moved to). Custodians that only ATTESTED a peg-out do not hold its delta
    /// yet: the peg-out attestation lane is the peg-in lane's next brick.
    /// §CZ-b — persist this custodian's sealed opening beside its keys, and load the one a previous run
    /// left. The seal is the same form the RAM copy has (a fixed-domain keystream over the four limbs),
    /// so the file is protected exactly as `validator-<port>.key` is: by the custodian's own disk. A
    /// custodian may know its totals (#75); no one else reads this file. Returns whether a persisted
    /// opening was loaded. Bounded: one file of OPENING_SEAL_BYTES.
    /// CHAIN-PUBLISH-REVIEWED: the opening is this custodian's PRIVATE witness to chain commitments, never
    /// chain state; loading it publishes nothing and moves no ledger.
    /// Both files go through the custody keystore (sealed at rest only if the operator opted in).
    /// ⛔ LIVENESS FIRST (user 2026-09-28): a file that EXISTS but is LOCKED (sealed, passphrase missing or wrong) never
    /// stops the node. The custodian runs this process WITHOUT persisting its openings (no path is set, so nothing
    /// writes the genesis opening over the locked witness), and says so. Its attestations refuse on the missing
    /// opening, which fails closed on the item, never on the chain.
    /// O1-INFINITY-REVIEWED: this custodian's OWN private witness, one file of OPENING_SEAL_BYTES plus one row per
    /// wrapped asset registered; not chain state. The reads existed before; only the at-rest form changes.
    pub fn enable_custody_opening_persist(&mut self, path: std::path::PathBuf) -> bool {
        let mut locked = false;
        let mut open = |p: &std::path::Path| match crate::keystore::read_key_file(p) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                eprintln!("[custody] ⛔ this custodian's opening file is LOCKED ({e}); it is left untouched and not persisted this run");
                locked = true;
                None
            }
        };
        let opened = open(&path);
        let wrapped_path = path.with_extension("wrapped.bin");
        let opened_wrapped = open(&wrapped_path);
        let pool_path = path.with_extension("pool.bin");
        let opened_pool = open(&pool_path);
        let history_path = path.with_extension("history.bin");
        let opened_history = open(&history_path);
        let paid_path = path.with_extension("paid.bin");
        let opened_paid = open(&paid_path);
        let shares_path = path.with_extension("epochshares.bin");
        let opened_shares = open(&shares_path);
        if locked {
            return false;
        }
        // §BR-9a: this custodian's epoch seed shares ride their own sibling file. DOOR: only 33-byte shares, at most the held
        // epochs' bound — a tampered or oversize row is dropped, never installed.
        if let Some(bytes) = opened_shares {
            type Shares = Vec<(u64, Vec<([u8; 32], Vec<u8>)>)>;
            if let Some(rows) = crate::chain_object::decode_exact::<Shares>(&bytes) {
                for (epoch, dealers) in rows.into_iter().take(crate::epoch_deal_tx::DEAL_LEAD_EPOCHS as usize + 2) {
                    let kept: std::collections::BTreeMap<[u8; 32], Vec<u8>> = dealers
                        .into_iter()
                        .filter(|(_, s)| s.len() == crate::epoch_deal_tx::SHARE_BYTES)
                        .take(crate::peg_attest::PEG_ATTEST_SEALED_MAX)
                        .collect();
                    self.epoch_seed_shares.insert(epoch, kept);
                }
            }
        }
        // LIQUIDATION §10: the pool openings ride their own sibling file; a restarted custodian resumes them.
        if let Some(bytes) = opened_pool {
            if let Some((live, closed)) = crate::chain_object::decode_exact::<PoolOpeningsFile>(&bytes) {
                self.pool_openings.extend(live);
                self.pool_close_openings.extend(closed);
            }
        }
        self.pool_opening_path = Some(pool_path);
        let loaded = match opened {
            Some(bytes) if bytes.len() == OPENING_SEAL_BYTES => {
                // G1g: the loaded opening is the one HELD; recording it here gave a boot a ring entry the live
                // process never held (restart census 2 → 921 B, g1eiii-restart-census-20261023.log:2579).
                self.custodian_opening_seal = bytes;
                true
            }
            _ => false,
        };
        // G1g: the rewind ring (DB-5) rides the seal's sibling file; a restarted custodian holds the rewind targets the
        // live process held. DOOR: a row is admitted only if its stored commitments are the ones its own seal opens
        // (re-derived here, never trusted), its seal is OPENING_SEAL_BYTES, and the file holds at most the ring's bound
        // (the newest rows kept) — a tampered, oversize or foreign row is dropped, never installed.
        if loaded {
            if let Some(bytes) = opened_history {
                if let Some(rows) = crate::chain_object::decode_exact::<Vec<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, Vec<u8>)>>(&bytes) {
                    let mut ring: std::collections::VecDeque<_> = rows
                        .into_iter()
                        .filter(|(r, m, seal)| seal.len() == OPENING_SEAL_BYTES && Self::opening_commits(seal) == (*r, *m))
                        .collect();
                    while ring.len() > crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX {
                        ring.pop_front();
                    }
                    self.custodian_opening_history = ring;
                }
            }
        }
        // §BR-3 17.6: the stakers' pool paid-out opening and its ring ride their own sibling file; each row's commitment is
        // re-derived from its seal at the door.
        if let Some(bytes) = opened_paid {
            if let Some((seal, rows)) = crate::chain_object::decode_exact::<(Vec<u8>, Vec<(crate::spend_frontier::Digest4, Vec<u8>)>)>(&bytes) {
                if seal.len() == OPENING_SEAL_BYTES {
                    self.custodian_paid_seal = seal;
                }
                let mut ring: std::collections::VecDeque<_> = rows
                    .into_iter()
                    .filter(|(c, s)| s.len() == OPENING_SEAL_BYTES && Self::paid_commit_of(s) == *c)
                    .collect();
                while ring.len() > crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX {
                    ring.pop_front();
                }
                self.custodian_paid_history = ring;
            }
        }
        // DB-77: the wrapped openings ride a sibling file; loaded rows REPLACE the genesis seeds
        // `register_wrapped_asset` planted at boot (a restarted custodian keeps minting wrapped assets).
        if let Some(bytes) = opened_wrapped {
            if let Some(rows) = crate::chain_object::decode_exact::<Vec<(u32, Vec<u8>)>>(&bytes) {
                for (asset_id, seal) in rows {
                    if seal.len() == OPENING_SEAL_BYTES {
                        self.wrapped_opening_seals.insert(asset_id, seal);
                    }
                }
            }
        }
        // §19.5b: the Monero opening's rewind ring — each row's commitments re-derived from its seal at the door
        if let Ok(bytes) = crate::keystore::read_key_file(&wrapped_path.with_extension("xmrhistory.bin")) {
            type Ring = Vec<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, Vec<u8>)>;
            if let Some(rows) = crate::chain_object::decode_exact::<Ring>(&bytes) {
                self.xmr_opening_history = rows
                    .into_iter()
                    .filter(|(_, _, seal)| seal.len() == OPENING_SEAL_BYTES)
                    .map(|(_, _, seal)| {
                        let (r, m) = Self::opening_commits(&seal);
                        (r, m, seal)
                    })
                    .take(crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX)
                    .collect();
            }
        }
        self.wrapped_opening_path = Some(wrapped_path);
        self.custody_opening_path = Some(path);
        if !loaded {
            self.persist_custody_opening();
        }
        self.persist_wrapped_openings();
        loaded
    }

    /// LIQUIDATION §10 — persist this custodian's pool openings (every writer of `pool_openings` / `pool_close_openings`
    /// calls this after it writes). Bounded: one row per registered PSM plus one per pool close.
    pub(super) fn persist_pool_openings(&self) {
        if let Some(p) = self.pool_opening_path.as_ref() {
            let mut live: Vec<(u32, PoolOpening)> = self.pool_openings.iter().map(|(k, v)| (*k, *v)).collect();
            live.sort_by_key(|(k, _)| *k);
            let mut closed: Vec<((u32, u64), PoolOpening)> = self.pool_close_openings.iter().map(|(k, v)| (*k, *v)).collect();
            closed.sort_by_key(|(k, _)| *k);
            match postcard::to_stdvec(&(live, closed)) {
                Ok(bytes) => {
                    if let Err(e) = crate::keystore::write_key_file(p, &bytes) {
                        eprintln!("[pool] ⛔ could not persist this custodian's pool openings: {e}");
                    }
                }
                Err(e) => eprintln!("[pool] ⛔ could not encode this custodian's pool openings: {e}"),
            }
        }
    }

    pub(super) fn persist_custody_opening(&self) {
        if let Some(p) = self.custody_opening_path.as_ref() {
            if let Err(e) = crate::keystore::write_key_file(p, &self.custodian_opening_seal) {
                eprintln!("[custody] ⛔ could not persist this custodian's opening: {e}");
            }
            // G1g: the rewind ring (DB-5) beside the seal — bounded CUSTODY_OPENING_HISTORY_MAX rows, the same private
            // witness at rest (keystore-sealed if the operator opted in); never chain state.
            // §BR-3 17.6: the stakers' pool paid-out opening and its ring beside it
            let paid: (Vec<u8>, Vec<(crate::spend_frontier::Digest4, Vec<u8>)>) =
                (self.custodian_paid_seal.clone(), self.custodian_paid_history.iter().cloned().collect());
            match postcard::to_stdvec(&paid) {
                Ok(bytes) => {
                    if let Err(e) = crate::keystore::write_key_file(&p.with_extension("paid.bin"), &bytes) {
                        eprintln!("[custody] ⛔ could not persist this custodian's stakers' pool opening: {e}");
                    }
                }
                Err(e) => eprintln!("[custody] ⛔ could not encode this custodian's stakers' pool opening: {e}"),
            }
            let rows: Vec<&(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, Vec<u8>)> =
                self.custodian_opening_history.iter().collect();
            match postcard::to_stdvec(&rows) {
                Ok(bytes) => {
                    if let Err(e) = crate::keystore::write_key_file(&p.with_extension("history.bin"), &bytes) {
                        eprintln!("[custody] ⛔ could not persist this custodian's opening rewind ring: {e}");
                    }
                }
                Err(e) => eprintln!("[custody] ⛔ could not encode this custodian's opening rewind ring: {e}"),
            }
        }
    }

    /// The ONE writer of this custodian's opening: sets it, records it in the rewind ring, persists it.
    /// CHAIN-PUBLISH-REVIEWED: the custodian's PRIVATE opening — a local secret that mirrors chain state
    /// this node applied or adopted; it authors nothing and travels nowhere.
    /// The node's OWN custodian identity (its bonded signer id + its ML-KEM decryption key), so a mint or
    /// burn the BLOCK carries is opened for THIS custodian at apply time — on any ingest door, whatever the
    /// gossip lane's pending slot did. MEASURED run 68 (2026-09-18): the attesting custodian applied the
    /// mint block but its opening never advanced (no slot at apply time) and every redeem it executed was
    /// refused at the reserve-release gate; the proposer's advanced. Local state is a cache; the block is
    /// the truth. CHAIN-PUBLISH-REVIEWED: this is the node's own key material, not chain state.
    pub fn set_custodian_identity(&mut self, my_id: [u8; 32], kem_dk: Vec<u8>) {
        self.custodian_identity = Some((my_id, kem_dk));
    }

    /// ⭐ §BR-9a — CAPTURE this custodian's share of a deal the fold just applied: open the share sealed to it, keep it only
    /// if it matches the dealer's signed commitment, persist. The instant of application is the only time it can be
    /// captured (a deal's bytes are not kept). A share that does not open or does not match is not kept; the dealer is
    /// named at the epoch's release (§19.1 item 2).
    /// CHAIN-PUBLISH-REVIEWED: the custodian's PRIVATE key material, mirrored from a share sealed to it on the chain; it
    /// authors nothing and travels nowhere.
    pub(crate) fn capture_epoch_share(&mut self, t: &crate::epoch_deal_tx::EpochKeyDealTx) {
        let Some((my_id, dk)) = self.bonded_custodian_identity() else { return };
        let Some(s) = t.shares.iter().find(|s| s.to == *my_id) else { return };
        let opened = crate::epoch_deal_tx::open_share(dk, &s.sealed)
            .filter(|plain| crate::epoch_deal_tx::share_commit(&t.vid, t.epoch, my_id, plain) == s.commit);
        let Some(plain) = opened else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line — no dealer, epoch or share.
            eprintln!("[custody] ⛔ an epoch deal's share sealed to this custodian does not open under its commitment — not kept");
            return;
        };
        self.epoch_seed_shares.entry(t.epoch).or_default().insert(t.vid, plain.to_vec());
        self.persist_epoch_seed_shares();
    }

    /// ⭐ §BR-9a, §19 item 6 — ERASE this custodian's shares of every epoch before `epoch` (zeroed, then dropped), persist.
    pub(crate) fn erase_epoch_seed_shares_before(&mut self, epoch: u64) {
        let keep = self.epoch_seed_shares.split_off(&epoch);
        let gone = std::mem::replace(&mut self.epoch_seed_shares, keep);
        if gone.is_empty() {
            return;
        }
        for mut dealers in gone.into_values() {
            for share in dealers.values_mut() {
                share.fill(0);
                std::hint::black_box(&share);
            }
        }
        self.persist_epoch_seed_shares();
    }

    /// The custodian's epoch shares, in the order the loader reads them.
    #[must_use]
    pub fn epoch_seed_shares(&self) -> &std::collections::BTreeMap<u64, std::collections::BTreeMap<[u8; 32], Vec<u8>>> {
        &self.epoch_seed_shares
    }

    fn persist_epoch_seed_shares(&self) {
        let Some(p) = self.custody_opening_path.as_ref() else { return };
        let rows: Vec<(u64, Vec<([u8; 32], Vec<u8>)>)> =
            self.epoch_seed_shares.iter().map(|(e, d)| (*e, d.iter().map(|(k, v)| (*k, v.clone())).collect())).collect();
        match postcard::to_stdvec(&rows) {
            Ok(bytes) => {
                if let Err(e) = crate::keystore::write_key_file(&p.with_extension("epochshares.bin"), &bytes) {
                    eprintln!("[custody] ⛔ could not persist this custodian's epoch shares: {e}");
                }
            }
            Err(e) => eprintln!("[custody] ⛔ could not encode this custodian's epoch shares: {e}"),
        }
    }
    /// ⭐ §BR-3 17.6 — the ONE writer of the stakers' pool paid-out opening: ring the one left and the one held, persist.
    pub(super) fn set_custodian_paid_seal(&mut self, seal: Vec<u8>) {
        for s in [self.custodian_paid_seal.clone(), seal.clone()] {
            if s.is_empty() {
                continue;
            }
            let c = Self::paid_commit_of(&s);
            if !self.custodian_paid_history.iter().any(|(h, _)| *h == c) {
                self.custodian_paid_history.push_back((c, s));
            }
        }
        while self.custodian_paid_history.len() > crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX {
            self.custodian_paid_history.pop_front();
        }
        self.custodian_paid_seal = seal;
        self.persist_custody_opening();
    }

    pub(super) fn set_custodian_opening_seal(&mut self, seal: Vec<u8>) {
        self.record_opening_in_history(); // the opening being LEFT — the one a jump may rewind to
        self.custodian_opening_seal = seal;
        self.record_opening_in_history(); // the one now held
        self.persist_custody_opening();
    }

    pub fn register_wrapped_asset_attested(
        &mut self,
        epoch_id: u64,
        asset_id: u32,
        prev_ratio_bps: u32,
        ratio_bps: u32,
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
    ) -> crate::peg::PegOutcome {
        let outcome = self.peg.register_wrapped_asset_attested(
            epoch_id,
            asset_id,
            prev_ratio_bps,
            ratio_bps,
            &self.validators,
            verifier,
            attestors,
        );
        // ⛔ REGISTRATION IS TWO FACTS, NOT ONE. The peg door sets the ratio; the node ALSO holds this
        // asset's private opening seal, and `execute_wrapped_mint` refuses (`BadRequest`) for an asset whose
        // seal it lacks. Calling only the peg door left the ledger registered and the node unable to mint —
        // MEASURED as `{"minted":false,"outcome":"BAD_REQUEST"}` on the wrapped-mint route once the RPC
        // stopped registering locally. So the authorised registration goes through the SAME node-level
        // function every other caller uses, which seeds both. It is idempotent: the entry is `or_insert_with`
        // and the peg re-register only re-applies the ratio the door just authorised.
        if outcome == crate::peg::PegOutcome::WrappedAssetRegistered {
            self.register_wrapped_asset(asset_id, ratio_bps);
        }
        outcome
    }


    // CHAIN-PUBLISH-REVIEWED: the apply half, driven by the PegIn chain object at graft — the publish
    // half is `Node::peg_in_confidential`, which frames the object and admits it through `ingest_tx`.

    // CHAIN-PUBLISH-REVIEWED: the apply half, driven by the PegOut chain object at graft — the publish
    // half is `Node::execute_peg_out_burn_verified`, which frames the object and admits it.

    // CHAIN-PUBLISH-REVIEWED: the apply half, driven by the stake object at its block's canonical fold — the publish half
    // is `Node::execute_stake`, which frames the object and pools it.
    /// DB-77: every writer of a wrapped opening goes through here so the seal is persisted (§CZ-b for wrapped).
    pub(super) fn set_wrapped_opening_seal(&mut self, asset_id: u32, seal: Vec<u8>) {
        let xmr = asset_id == crate::peg::XMR_PEG_ASSET_ID;
        if xmr {
            self.record_xmr_opening_in_history(); // §19.5b: the opening being LEFT — the one a jump may rewind to
        }
        self.wrapped_opening_seals.insert(asset_id, seal);
        if xmr {
            self.record_xmr_opening_in_history(); // the one now held
        }
        self.persist_wrapped_openings();
    }

    /// §19.5b — push this custodian's current Monero-ledger opening onto its rewind ring (deduped, bounded).
    fn record_xmr_opening_in_history(&mut self) {
        let Some(seal) = self.wrapped_opening_seals.get(&crate::peg::XMR_PEG_ASSET_ID).cloned() else { return };
        let (r, m) = Self::opening_commits(&seal);
        if self.xmr_opening_history.iter().any(|(hr, hm, _)| *hr == r && *hm == m) {
            return;
        }
        self.xmr_opening_history.push_back((r, m, seal));
        while self.xmr_opening_history.len() > crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX {
            self.xmr_opening_history.pop_front();
        }
    }

    pub(super) fn persist_wrapped_openings(&self) {
        if let Some(p) = self.wrapped_opening_path.as_ref() {
            let mut rows: Vec<(u32, Vec<u8>)> =
                self.wrapped_opening_seals.iter().map(|(k, v)| (*k, v.clone())).collect();
            rows.sort_by_key(|(k, _)| *k);
            let bytes = postcard::to_allocvec(&rows).unwrap_or_default();
            if let Err(e) = crate::keystore::write_key_file(p, &bytes) {
                eprintln!("[custody] ⛔ could not persist this custodian's wrapped openings: {e}");
            }
            // §19.5b: the Monero opening's rewind ring beside them
            let ring: Vec<&(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, Vec<u8>)> = self.xmr_opening_history.iter().collect();
            match postcard::to_stdvec(&ring) {
                Ok(bytes) => {
                    if let Err(e) = crate::keystore::write_key_file(&p.with_extension("xmrhistory.bin"), &bytes) {
                        eprintln!("[custody] ⛔ could not persist this custodian's Monero opening rewind ring: {e}");
                    }
                }
                Err(e) => eprintln!("[custody] ⛔ could not encode this custodian's Monero opening rewind ring: {e}"),
            }
        }
    }

    /// DB-77: register the KEM encapsulation key a bonded custodian seals deltas and requests to (the chain
    /// path is `apply_membership_seat`; this is the direct writer tests and tools use).
    pub fn register_custody_kem(&mut self, id: [u8; 32], kem_ek: Vec<u8>) {
        self.validators.register_custody_kem(id, kem_ek);
    }
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // DB-77 — THE CUSTODIAL REQUEST LANE (node side). See `peg_attest::PegRequest` for the design and
    // the borrowed shape (tBTC reveal / THORChain observe→sign→publish / Liquid peg-out tx).
    // ═══════════════════════════════════════════════════════════════════════════════════════════

    pub fn register_wrapped_asset(&mut self, asset_id: u32, ratio_bps: u32) {
        self.peg.register_wrapped_asset(asset_id, ratio_bps);
        if !self.wrapped_opening_seals.contains_key(&asset_id) {
            self.set_wrapped_opening_seal(asset_id, genesis_opening_seal(asset_id));
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed Unbond object, judged
    // by every grafting node from its own bytes.
    pub fn params(&self) -> &ChainParams {
        self.relay.dag().params()
    }

    /// Install a governance-approved parameter update (no restart) into both the DAG and mempool.
    pub fn set_params(&mut self, params: ChainParams) {
        self.relay.dag_mut().set_params(params.clone());
        self.mempool.set_params(params);
    }

    /// Install a (re)provisioned recipient — the `/provision_reward_recipient` route's second half, after the file is written.
    pub fn set_reward_recipient(&mut self, rc: Option<crate::satoshi::RewardRecipient>) {
        self.reward_recipient = rc;
    }
    /// Register a bonded validator's bridge-custody points (its share of the reserve key-aggregate). The reserve is
    /// the LIVE bonded set's aggregate, so the founding validator is a 1-of-1 reserve on day 1 (deposits work) and
    /// it grows to t-of-n as more bond — decentralization by construction.
    pub fn register_validator_custody(&mut self, id: [u8; 32], secp33: Vec<u8>, ed32: [u8; 32]) {
        self.validators.register_custody(id, secp33, ed32);
    }

    /// DB-121x: record a bonded set's Monero custody wallet address (from ≥k signed announcements, or this node's
    /// own final wallet). CACHE-ONLY: a mirror of the custodians' wallets' own state, re-learned from their
    /// announcements after a restart; nothing here is decided for the chain.
    pub fn set_xmr_custody_address(&mut self, set_id: [u8; 32], address: String) {
        if self.xmr_custody_ring.iter().any(|(s, a)| *s == set_id && *a == address) {
            return;
        }
        self.xmr_custody_ring.retain(|(s, _)| *s != set_id);
        self.xmr_custody_ring.push_back((set_id, address));
        // SAFE AT SCALE: past the ring's depth the oldest wallet that is NOT a current vault's leaves — a node must know
        // every current vault's deposit address, so those are never evicted. Bounded by the ring's depth or the vaults of
        // the bonded set, whichever is larger; never by history. On a one-vault chain: the oldest entry leaves, as it did.
        let live = self.custody_set_ids();
        while self.xmr_custody_ring.len() > CUSTODY_SET_RING_DEPTH {
            let Some(oldest) = self.xmr_custody_ring.iter().position(|(s, _)| !live.contains(s)) else { break };
            self.xmr_custody_ring.remove(oldest);
        }
    }

    /// DB-122 F6: the payout lane's verdict on solvency, from this node's own source. Loud on every change.
    /// CACHE-ONLY: an observation of the foreign chain (coins seen vs the ledger's reserve); it gates only this
    /// node's own attestation of NEW issuance, never a chain transition and never a redemption.
    pub fn set_reserve_solvency_hold(&mut self, hold: bool) {
        if hold != self.reserve_solvency_hold {
            if hold {
                eprintln!("[reserve] ⛔ SOLVENCY HOLD — this node's Bitcoin source shows fewer matured coins than the ledger's committed reserve; NEW ISSUANCE is refused until they are seen (redemptions continue)");
            } else {
                eprintln!("[reserve] solvency hold lifted — the coins the ledger commits to are seen again");
            }
        }
        self.reserve_solvency_hold = hold;
    }

    /// DB-122 F6 for Monero's ledger: the Monero custody lane's verdict, from the custody wallet's own balance. Loud on every
    /// change. CACHE-ONLY: an observation of the foreign chain; it gates only this node's attestation of NEW Monero issuance.
    pub fn set_xmr_reserve_solvency_hold(&mut self, hold: bool) {
        if hold != self.xmr_reserve_solvency_hold {
            if hold {
                eprintln!("[reserve] ⛔ MONERO SOLVENCY HOLD — the custody wallet holds less than Monero's committed reserve; NEW Monero issuance is refused until it is seen (redemptions continue)");
            } else {
                eprintln!("[reserve] Monero solvency hold lifted — the custody wallet holds the reserve again");
            }
        }
        self.xmr_reserve_solvency_hold = hold;
    }

    /// Install the PQ verifier that authenticates finality votes (the ML-DSA verifier from the PQ
    /// dep). Until one is set, votes are rejected fail-closed.
    /// The vote identity the wallet must bond onto (see `own_validator_id`).
    pub fn set_own_validator_id(&mut self, id: [u8; 32]) {
        self.own_validator_id = Some(id);
    }
    pub fn set_finality_verifier(&mut self, verifier: Box<dyn PqVerifier + Send>) {
        self.finality_verifier = verifier;
    }

    /// ⭐ G1 (lane a 2026-10-22) — RE-INSTALL THE FINALIZED CHECKPOINT THE FOLD RECORD CARRIES (`FoldRecord::finalized`),
    /// bound to the chain this node resumed: only when the DAG holds the block AT that height (the binding every carried
    /// vote passes, `finality_vote_binds_to_dag`, after `install_block_window_span` re-linked this node's own history) and
    /// only above what the restored bodies' carried votes already re-tallied (monotone, like a live finalization). A height
    /// the block does not sit at, or a block this node does not hold, installs nothing — the tally then stands where the
    /// window's carried votes put it. The floor follows into the DAG as after every record.
    /// Privacy: a height only; no block id, key or amount is printed.
    pub(super) fn install_persisted_finality(&mut self, persisted: Option<(u64, [u8; 32])>) {
        let Some((height, id)) = persisted else { return };
        let block = Hash32(id);
        if !self.finality_vote_binds_to_dag(&block, height) {
            eprintln!(
                "[persist] ⛔ the checkpoint's finalized height {height} names a block this node does not hold at that height — \
                 not installed; finality stands where the restored carried votes put it"
            );
            return;
        }
        if self.finality.install_finalized_checkpoint(height, block) {
            self.sync_finality_floor_into_dag();
            eprintln!("[persist] finalized checkpoint RESUMED at height {height} (bound to the held block)");
        }
    }

    /// Publish (or update) the caller's PUBLIC clue key for the oblivious cold-restore path. Authenticated by an
    /// ML-DSA signature over `clue_register_msg(clue_pk)`; the slot is keyed by `H(pubkey)` = the address spend
    /// tag `b`, so only the address owner can set their OWN clue key. Returns `None` on a bad signature
    /// (fail-closed), else `Some(changed)` where `changed` = the clue key was NEW/DIFFERENT (so the gossip layer
    /// re-broadcasts only a real change, loop-free). The clue key is PUBLIC (it only lets a sender TAG a note).
    pub fn register_clue(&mut self, pubkey: &[u8], clue_pk: Vec<u8>, sig: &[u8]) -> Option<bool> {
        use crate::pqauth::PqVerifier;
        if !crate::pqauth::MlDsaVerifier.verify(
            pubkey,
            &crate::pqauth::clue_register_msg(&clue_pk),
            sig,
        ) {
            return None;
        }
        let owner = crate::pqauth::pubkey_id(pubkey);
        Some(self.clues.adopt(
            owner,
            crate::clue_registry::ClueGossip {
                pubkey: pubkey.to_vec(),
                clue_pk,
                sig: sig.to_vec(),
            },
        ))
    }

    /// Install the PQ signature verifier used to authenticate site publishes (the ML-DSA verifier
    /// from the PQ dep). Until one is set, publishes are rejected fail-closed.
    pub fn set_site_verifier(&mut self, verifier: Box<dyn PqVerifier + Send>) {
        self.site_verifier = verifier;
    }

    /// Install the O(1) decider verifier used to instant-sync (the pure-Rust `WhirDecider`).
    /// Until one is set, sync bundles are rejected fail-closed (the default [`UnverifiedDecider`]).
    pub fn set_decider_verifier(&mut self, verifier: Box<dyn ConsensusVerifier + Send>) {
        self.decider_verifier = verifier;
    }

    /// ⭐⭐⭐ THE ONE BOOT — every way a node starts (the daemon, the in-process wallet node, the journey simulator) runs
    /// exactly this sequence, so a restart anywhere is the production restart: the block window, the checkpoint resume
    /// (with its verified nf-view, record and witness-window caches), the boot retention sweep, the @username registry,
    /// the on-chain directory, the production verifiers, this node's identity, and its custody opening.
    /// A corrupt or foreign checkpoint is REFUSED (never wiped) — the caller decides how to die (the daemon exits 97).
    /// cons: none — the same calls, in the daemon's order, from one site.
    pub fn boot(&mut self, files: &crate::persist::BootFiles, validator_id: [u8; 32]) -> Result<BootReport, String> {
        // ⛔⛔ G1 (lane a 2026-10-22) — THE VERIFIERS STAND BEFORE THE RESTORE. The resume's carry graft is a graft door
        // (`graft_unfolded_carry` → `remember_unfolded_block`): it re-tallies every carried finality vote the restored
        // bodies hold through the ONE verified door. Installed AFTER `enable_persist`, the restore ran under the fail-closed
        // default verifier and refused every carried vote as unauthenticated, so a restarted node resumed with an EMPTY
        // tally (MEASURED: 77 × "[vote-apply] refused: … the signature is not the key-holder's" around the two restarts and
        // the restart census `finality` CHANGED 41 → 17 B, scratchpad/night/g2-finality-harness-3-20261022.log:3192–3370,
        // :3696). Door parity (AGENTS.md §9.6 (6)): the resume graft runs with the verifiers the runtime door runs with —
        // Bitcoin Core brings its verification context up before it loads the chainstate.
        self.set_site_verifier(Box::new(crate::pqauth::MlDsaVerifier));
        self.set_finality_verifier(Box::new(crate::pqauth::MlDsaVerifier));
        self.set_own_validator_id(validator_id);
        self.set_decider_verifier(Box::new(crate::whir_decider::WhirDecider));
        self.enable_block_window(files.window.clone());
        let resumed = self.enable_persist(files.snapshot.clone())?;
        let mut report = BootReport { resumed, ..BootReport::default() };
        if resumed {
            report.swept = self.sweep_unreferenced_record_bytes();
            report.window = self.block_window_census();
            // ⭐ A RESUME IS NOT A CHAIN AUTHORITY (A-F115, lane speed5r, 2026-11-22). The resume re-installs this node's OWN
            // checkpoint tip through the one anchor door (`restore_snapshot` → `Dag::add_anchor`), which makes it the
            // fork-choice floor (`Dag::finality_admits`: a tip whose SELECTED chain does not pass through the floor never
            // ranks as head). With two producers that tip is often this node's own last block, which the network's
            // heavier chain MERGES as a member rather than taking as its selected parent: the resumed node then refused
            // every heavier tip for ever and folded its own fork alone. MEASURED (testnet gate, main f1c02f5f, `restart`
            // FAIL): node 1's fold stood at 215 with 26 blocks unfolded while node 0's reached 238, both DAGs holding the
            // same 96 recent blocks, the payment node 0 applied never reaching node 1's wallet. The window below the anchor
            // is re-entered with its selected-parent links (`[block-window] … re-entered`), so the resumed DAG weighs
            // every branch by itself: the floor this node's own disk installed is released, and only a CERTIFIED adopt
            // (the join door's verified work and vouchers) or a 2/3 quorum floors the fork choice. BORROWED: Bitcoin
            // Core's restart — a node's own chainstate is a cache, the heaviest valid chain decides
            // (`ActivateBestChain` after load). AI RESISTANT: (b) ordinary fork choice, the same rule on every node; a
            // peer gains nothing it could not gain by producing the heavier chain, which every node follows anyway.
            // cons: none on the wire or in state; a restarted node may now reorg below its own checkpoint, which is what
            // the fold rewind exists for.
            let released = self.relay.dag_mut().release_resume_floor();
            if released {
                eprintln!("[resume] the checkpoint's own tip is no longer a fork-choice floor: the heaviest chain decides");
            }
        }
        // MonerousD Veil: where this node's site store would live (one file beside where the names file was). Nothing is opened
        // or created here; the store opens when a site is first hosted or browsed.
        crate::veil::host_at(files.names.with_file_name("veil.slab"));
        // D4: where this node keeps the ring of applied calls' sealed storage blobs (one file of a constant size, opened at
        // the first call it folds or the first reader that asks).
        crate::contract_blobs::log_at(files.names.with_file_name("call-blobs.ring"));
        // the sites this node holds: each signed publish is read back and goes through the publish door again
        // (its signature is verified there), so the site registry is rebuilt from signed records, never trusted
        // from the file
        for bytes in crate::veil::stored_publishes() {
            if let Some(g) = crate::site::SiteGossip::from_wire(&bytes) {
                let _ = self.publish_site(g.publish, &g.pubkey, &g.sig);
            }
        }
        report.directory_records = self.enable_dir_persist(files.directory.clone());
        // G1g-iii (lane a 2026-10-23): the peers this node learned (Bitcoin addrman's peers.dat) ride the ONE boot door. The
        // daemon alone wired the file (main.rs, after the boot), so the simulator and the in-process node booted with an
        // empty directory (restart census g1giii-restart-census-20261023.log: peer_dir 1 → 0 peers, both nodes) and the
        // band door's solicit window, derived from it below, fell 2 → 1. cons: one ≤ MAX_PEERS file read per boot.
        self.enable_peer_persist(files.peers.clone());
        // G1g-iv (lane a 2026-10-23): this node's own announced record rides the boot too, so the prover set below counts
        // the node itself exactly as every peer's persisted directory does (restart census g1giii-restart-census-2: band_door
        // `solicit_cap:2` → `solicit_cap:1`, both nodes). cons: one bounded file read per boot.
        report.own_record = self.enable_own_record_persist(files.own_record.clone());
        // G1g-iii (lane a 2026-10-23): the band door's solicit window `W = M` is a function of the mesh target and the
        // provers this node knows (`band_set_solicit_window`, re-read by the relay every tick) — set here from the restored
        // peer directory, so a booted door never holds the constructor's mesh-wide default until its first tick (restart
        // census g1gii-restart-census-20261023.log: band_door `solicit_cap:2` → `solicit_cap:7`, both nodes).
        // cons: none — one owner-count computation per boot.
        let provers = self.band_provers().len().max(1);
        self.band_set_solicit_window(provers);
        report.custody_opening = self.enable_custody_opening_persist(files.custody_opening.clone());
        report.fee_key = self.restore_or_persist_fee_key(&files.fee_key);
        report.reward_recipient = self.restore_or_persist_reward_recipient(&files.reward_recipient);
        Ok(report)
    }

    /// ⭐ THE REWARD RECIPIENT IS ONE FUNCTION OF THE DATADIR, NEVER OF THE PROCESS (G1 restart census; readiness T2/R3,
    /// lane a 2026-10-22). Who this node's SAT rewards are sealed to is the file its operator's wallet provisioned
    /// (`/provision_reward_recipient` → `satoshi::provision_reward_recipient_at`, the same path `BootFiles::reward_recipient`
    /// names), and the `"sat"` locator counter is persisted there in place by `advance_reward_index`. Before this a TEST build
    /// derived the recipient from the per-process miner seed (`initial_reward_recipient`) and never read the file, so a
    /// simulated restart sealed every later reward to a recipient the first process's operator wallet never held and the
    /// counter restarted at 0 (MEASURED: the restart census `reward_recipient CHANGED` at every restart of both nodes,
    /// scratchpad/night/g1-finality-harness-20261022.log:3610, :3809; the pin
    /// `a_reward_recipient_booted_from_the_same_files_is_the_same_recipient_with_its_counter_and_a_truncated_file_is_refused`
    /// RED). The daemon already read the file at construction; this is the ONE door every boot path runs, the simulator's
    /// included (TESTNET == PRODUCTION: the simulator exercises the file the daemon reads).
    ///
    /// Borrowed shape: the fee key door (`restore_or_persist_fee_key`) / Bitcoin Core's wallet file — a persisted file every
    /// later process reads, through the custody keystore (sealed at rest iff the operator opted in). A file present and
    /// well-formed is INSTALLED (returns `true`); no file — a node binary has no recipient until its wallet provisions one,
    /// while a test node drew one from its reproducible miner seed — persists the recipient this process holds, if any, so
    /// the next process booted from these files seals to the same one (`false`). A file that exists but cannot be opened
    /// (sealed, passphrase missing or wrong) or does not decode is NEVER overwritten (the keystore's clobber rule, the
    /// no-wipe cardinal) and the process keeps the recipient it holds — said as ⛔ at every boot.
    /// O1-INFINITY-REVIEWED: one fixed-size file (1,260 B); a key and a counter, never chain state.
    /// NEW-DOOR CHECKLIST (§9.6): not an ingress of chain objects — a local file this node's wallet wrote under its own
    /// datadir; (3) a forged file only changes WHO this node's own rewards are sealed to (no value is created or
    /// duplicated: the reward note is laid once, to one recipient); (4) nothing to replay; (5) one bounded file read, and
    /// the decode refuses any length but the fixed one; (6) parity with the fee key door: same keystore, same clobber rule,
    /// same first-boot persist.
    pub fn restore_or_persist_reward_recipient(&mut self, path: &std::path::Path) -> bool {
        self.reward_recipient_file = Some(path.to_path_buf());
        match crate::keystore::read_key_file(path) {
            Ok(bytes) => {
                if let Some(rc) = crate::satoshi::RewardRecipient::decode(&bytes) {
                    self.reward_recipient = Some(rc);
                    return true;
                }
                eprintln!(
                    "[sat-reward] ⛔ {} is not a reward recipient file and is NOT overwritten: this process lays rewards to the \
                     recipient it holds (none until its wallet provisions one) — move the file aside deliberately",
                    path.display()
                );
                return false;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("[sat-reward] ⛔ {e}: the persisted reward recipient was not installed");
                return false;
            }
        }
        if let Some(rc) = self.reward_recipient.as_ref() {
            if let Err(e) = crate::keystore::write_key_file(path, &rc.encode()) {
                eprintln!("[sat-reward] ⛔ could not persist this node's reward recipient: {e}");
            }
        }
        false
    }

    /// ⭐ THE FEE KEY IS ONE FUNCTION OF THE DATADIR, NEVER OF THE PROCESS (G1 restart census; readiness R3, lane a
    /// 2026-10-22). Before this, `fee_seed` was derived from the per-process `miner_seed` and `fee_mlkem_pub/sec` were drawn
    /// fresh by `with_params`, so a restarted node published a DIFFERENT epoch fee address within the same epoch and every
    /// fee a wallet had paid to the old one was sealed to a key no process would hold again (MEASURED: the restart census
    /// `fee_seed/fee_mlkem_pub/fee_mlkem_sec CHANGED` at every restart of the launch journey, f1-launch5-20261022-1649.log;
    /// the pin `a_fee_address_a_wallet_paid_this_epoch_is_still_the_nodes_after_a_restart` RED).
    ///
    /// Borrowed shape: Bitcoin Core's wallet seed — drawn once, persisted, every later process derives the same keys —
    /// through the custody keystore exactly as the validator vote key (`validator::load_or_create_node_vote_key`): sealed
    /// at rest iff the operator opted in, owner-only and atomic otherwise. File: `fee_seed (32) ‖ pk_len u32 LE ‖ ML-KEM-768
    /// pk ‖ sk`. The first boot persists the key this process drew; every later boot installs the persisted one. Returns
    /// `true` iff a persisted key was installed.
    ///
    /// A file that exists but cannot be opened (sealed, passphrase missing or wrong) or does not parse is NEVER
    /// overwritten (the keystore's clobber rule, the no-wipe cardinal) and the process keeps the key it drew — said as ⛔ at
    /// every boot, because every fee paid to that key dies with the process (the pre-fix behaviour, now named, never silent).
    /// O1-INFINITY-REVIEWED: one fixed-size key file (32 + 4 + 1,184 + 2,400 B); a key, never chain state.
    /// NEW-DOOR CHECKLIST (§9.6): not an ingress of chain objects — a local file this node wrote under its own datadir;
    /// (3) a forged file installs a key that only changes THIS node's own fee address (a wallet pays whatever address the
    /// node publishes; no value is created or duplicated); (4) nothing to replay; (5) one bounded file read, and the pair
    /// must round-trip an encapsulation before it is installed; (6) parity with the validator key door: same keystore,
    /// same clobber rule, same first-boot persist.
    pub fn restore_or_persist_fee_key(&mut self, path: &std::path::Path) -> bool {
        match crate::keystore::read_key_file(path) {
            Ok(bytes) => {
                if let Some((seed, pk, sk)) = Self::parse_fee_key_file(&bytes) {
                    self.fee_seed = seed;
                    self.fee_mlkem_pub = pk;
                    self.fee_mlkem_sec = sk;
                    return true;
                }
                eprintln!(
                    "[fee-key] ⛔ {} is not a fee key file and is NOT overwritten: this process's fee address dies with it — \
                     move the file aside deliberately",
                    path.display()
                );
                return false;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("[fee-key] ⛔ {e}: this process's fee address dies with it");
                return false;
            }
        }
        let bytes = Self::encode_fee_key_file(&self.fee_seed, &self.fee_mlkem_pub, &self.fee_mlkem_sec);
        if let Err(e) = crate::keystore::write_key_file(path, &bytes) {
            eprintln!("[fee-key] ⛔ could not persist this node's fee key: {e}");
        }
        false
    }

    /// Enable local-disk checkpointing at `path` and IMMEDIATELY restore from it if a valid checkpoint exists,
    /// so the serve loop boots straight into the node's last committed state (a restart RESUMES, never restarts
    /// from an empty chain). After this, every committed block auto-saves the O(1) resumable checkpoint.
    /// Returns `true` iff a checkpoint was found and restored.
    pub fn enable_persist(&mut self, path: std::path::PathBuf) -> Result<bool, String> {
        self.persist_path = Some(PersistTarget {
            path: path.clone(),
            save_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let outcome = self.restore_from_disk();
        let restored = outcome == RestoreOutcome::Restored;
        if restored {
            let _ = self.restore_nf_view(&path); // DB-397 fix A: verified against the resumed acc root, or ignored
            let _ = self.restore_da_records(&path); // DB-397 fix A part 2: each record against its block's header root
            // A-F32: the unfolded bodies the checkpoint carried without their notes take them from the rows just restored.
            // cons: none — nothing is written to disk or to state; a serde-skipped RAM field is set on blocks this node
            // already holds (the unfolded set, bounded by protocol constants), once per boot.
            let completed = self.complete_held_bodies_from_records();
            if completed > 0 {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a count of this node's own held blocks; no note, tag, amount or owner.
                eprintln!("[persist] {completed} held unfolded block(s) took their notes back from this node's own record");
            }
            let _ = self.refile_held_rows_into_index(); // G1e: the filed-note index is derived from the rows just restored
            let _ = self.restore_mined_tx_nfs(&path); // G1: each per-tx nullifier row against the lane of the block naming it
            // The OLI index after a restart is the index before it (T1.4). Writes NOTHING to disk; it re-fills in RAM the
            // 17 B tags the node held before it stopped (same count, so cons: none on state), reading one ~21 KB window
            // block per folded real-note record — f(the window's fixed span), never f(history).
            // O1-INFINITY-REVIEWED: no authority is read back — roots, frontier and fold state come from the checkpoint as
            // before; this re-derives a FINDABILITY index from the owner-approved block window (block_window.rs, Kaspa's
            // pruning-window store), each list bound by its block's header `oli_tags_root`; bounded by the window's span.
            let _ = self.restore_tags_from_block_window();
            let _ = self.restore_window_index(&path); // T1.7: every window folded before the stop, bound to the spine
            let anchor = crate::persist::load_window_anchor(&path);
            let _ = self.rebuild_windows_from_records(anchor); // the witness windows a wallet needs, from the records held
            self.restore_canon(&path); // A-F114 phase 1: the canonical accumulator and the record MMR
        }
        // ⛔⛔⛔ CORRUPT-LOAD REFUSES, NEVER WIPES (the no-regenesis cardinal, enforced at the exact
        // site it was violated). A snapshot FILE exists but no decode door accepted it ⇒ this binary
        // and this checkpoint disagree — the ONLY safe outcomes are "fix the binary" or "operator
        // moves the file aside deliberately". Booting fresh here minted a rival chain whose first
        // save OVERWROTE both nodes' 26k-block checkpoints (measured 2026-08-25, my own deploy).
        // A process that cannot read its own custody must not run beside it.
        if !restored && crate::persist::snapshot_file_exists(&path) {
            // Two DISTINCT refusals share this exit, and the operator must be told which one fired.
            //
            // WHAT PRODUCES the condition: `restore_from_disk` itself — the enum is minted at the ONE
            // decode site, alongside the decode, precisely so this block never re-derives it (the old
            // bool forced either a second full-file decode here or a wrong message; the v29 chain gate
            // made "cannot decode" a FALSE diagnosis for a pre-fork file, which decodes perfectly and
            // belongs to another chain). CAN IT BE DELETED: no — the two causes demand opposite operator
            // actions (a corrupt file is a restore-from-peer problem; a foreign-chain checkpoint is a
            // deliberate migration/reset decision), so collapsing them re-creates the misdiagnosis this
            // exists to end. WHY IT STAYS: the message is the only thing a bricked node leaves behind.
            let diagnosis = if outcome == RestoreOutcome::RefusedForeign {
                "this binary DECODED it but REFUSED to resume it — see the refusal above (a valid \
                 checkpoint for a chain this binary does not implement, NOT a corrupt file)"
            } else {
                "this binary cannot decode it (corrupt file, or a layout no frozen door covers)"
            };
            let why = format!(
                "REFUSING TO START: a snapshot exists at {} and {diagnosis}. Booting fresh would \
                 re-genesis a rival chain and overwrite real custody. Fix the binary or move the file \
                 aside DELIBERATELY, then restart.",
                path.display()
            );
            eprintln!("[persist] ⛔⛔⛔ {why}");
            // The CALLER decides how to stop: the daemon exits 97 (`main.rs`); the in-process node hands
            // the refusal to the wallet as an error (`serve.rs`). MEASURED 2026-09-17: the iPhone wallet
            // died at launch with exit 97 on a months-old snapshot and nothing on screen — a library
            // door must never end the host process.
            return Err(why);
        }
        // GENESIS GETS ITS LEDGER RECORD HERE, not at construction. `persist_path` is None while the node is
        // being built, so a record written then lands in memory and never reaches disk — genesis stayed absent
        // from the ledger on every restart. The by-id backfill then asked for it forever: measured 1,242
        // consecutive unserved requests, every one for record id 7305956828534032, from a peer holding 3,470
        // other records. A gap can only close if some node actually has the block.
        match self.relay.dag().genesis() {
            Some(g) => {
                let rid = Self::da_record_id_for_block(&g, 0);
                let had = self.da_holds(rid);
                // ⛔ THE ROW MUST EXIST EVEN WHEN THE PAYLOAD ALREADY DID. Genesis IS position 0 on every
                // persisted node — the same block, the same record, the same row everywhere — and roots
                // runs, pages and the fold's base all read it. MEASURED 2026-09-04: `da_addr_at_ordinal(0)`
                // returned None on a producer, the resume pin "genesis is ordinal 0 on the producer"
                // failed, and a roots run served an empty span.
                //
                // ⛔⛔⛔ v32 (item 9): ONE door. A duplicate write+FOLD lived here beside the
                // `ensure_genesis_record` call below — the fold appended genesis's 256-leaf cover shape to
                // the spend frontier, and the fold-order law then refused the first real record forever on
                // a had=false boot (measured: `[item9] persisted had=false boot: count=256 served_seq=1`,
                // then `[fold-order] ⛔ ordinal 1 would append at leaf 256 but its ordinal places it at
                // 0`). Genesis contributes NO leaves and NO accumulator step — its spine contribution is
                // defined by the CHAIN (nothing), not produced by persistence. `ensure_genesis_record`
                // writes the bytes + the row, exactly once, and folds NOTHING.
                self.ensure_genesis_record();
                // DIGITAL-CASH-PRIVACY-REVIEWED: a block id and its record id — already-public chain
                // structure. This states whether genesis reached the ledger, which is the fact two silent
                // failed attempts could not distinguish from "the call never ran".
                eprintln!(
                    // the whole genesis id (public: it names the network), so an operator reads which run a node is on
                    "[da] genesis ledger record: genesis={} rid={rid} had={had} now={}",
                    g.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    self.da_holds(rid)
                );
                // ⭐⭐⭐ STATE THE LEDGER POSITION AT BOOT — "was the gap already there at t=0?"
                //
                // `served_seq = note_frontier_count() / 256` is the count of blocks this node has FOLDED,
                // while `blue_score` is the DAG height. All session a constant offset between them
                // ("the record gap") has driven five hypotheses, every one refuted by measurement:
                // duplicate re-delivery (0 hits), per-block sub-record ids (still `serving 0 of 1`), the
                // producer dropping its own block (fixed, gap unchanged), a hole at the accept path (the
                // `[ledger-hole]` probe fired 0 times), and the DSYNC adopt gap (a FRESH SOLO node with no
                // peer and nothing to adopt showed gap 112,501 anyway).
                //
                // Each of those cost a live run because the ONE number that separates "created at startup"
                // from "leaking during operation" was never printed. In steady state the two counters advance
                // in lockstep (+54/+54 measured), so if the offset already exists here it was never a leak at
                // all. Print it once, at the only moment that answers the question.
                // DIGITAL-CASH-PRIVACY-REVIEWED: two chain-progress counters, both already public via
                // /get_info. Never a note, amount, key, owner or ordering.
                let boot_score = self
                    .relay
                    .dag()
                    .selected_tip()
                    .and_then(|t| self.relay.dag().get(&t).map(|n| n.blue_score))
                    .unwrap_or(0);
                eprintln!(
                    "[da] BOOT ledger position: blue_score={} served_seq={} gap={}",
                    boot_score,
                    self.served_seq,
                    boot_score.saturating_sub(self.served_seq)
                );
            }
            None => eprintln!(
                "[da] genesis ledger record SKIPPED — dag has no genesis at persist-enable"
            ),
        }
        Ok(restored)
    }

    /// The enabled checkpoint path (None on non-persistent test nodes). The runtime uses it to anchor the
    /// join-mesh-or-nothing `.mesh-joined` marker next to the snapshot (see [`crate::persist::mesh_joined_marker`]).
    pub fn persist_path(&self) -> Option<&std::path::PathBuf> {
        self.persist_path.as_ref().map(|t| &t.path)
    }

    /// Enable disk-persistence for the ON-CHAIN directory projection (@usernames, group handles, profiles):
    /// LOAD the on-disk copy now (restart-proof) and auto-save on every applied entry. Same cardinal as
    /// [`Self::enable_persist`] — blocks older than the ladder span never replay on an O(1) node, so
    /// without this every registration before the last restart would vanish from resolve. Count restored.
    pub fn enable_dir_persist(&mut self, path: std::path::PathBuf) -> usize {
        self.directory = crate::directory::Directory::open(path);
        if self.directory.refill_was_owed() {
            // ⭐ A-F38 (the restart half): this node stopped while a certified refill of its directory was owed. The owed
            // word, the staged entries and what its fold held since the adopt were in memory only, so the file just read
            // is an emptied or half-refilled directory and nothing this node holds can complete it. It is stale exactly
            // as after a rewind below the directory's journal: folding stops and the next certified bundle re-anchors
            // the node, whose adopt arms a whole new refill (and clears the marker when it lands).
            self.mark_spine_stale(
                "a directory refill was owed when this node stopped — its directory is not the chain's until a certified bundle refills it",
            );
        }
        self.directory.total()
    }

    /// Reload the checkpoint from the configured path (if any). `false` if no path, no file, or a guard rejects it.
    pub fn restore_from_disk(&mut self) -> RestoreOutcome {
        // Same single #106 boot checkpoint read as always — one `load` per process start, before and
        // after this change. Only the RETURN TYPE widened (bool → three-outcome enum) so the exit-97
        // site can name WHICH refusal fired without decoding the file a second time.
        let Some(checkpoint) = self.persist_path.as_ref().map(|t| t.path.clone()) else {
            return RestoreOutcome::NoFile;
        };
        match crate::persist::load_with_fold(&checkpoint) {
            Some((snap, fold)) => self.derive_resumed(snap, fold),
            None => RestoreOutcome::Undecodable,
        }
    }

    /// v47 (G1d) — re-enter the DA samples that were in flight at the checkpoint. Each goes through `begin_da_sample` (bound,
    /// plan re-derived from this node's secret) only when this node holds the record's block, that header's
    /// `output_notes_root` IS the held root, and the record bytes are still absent; the proved pieces keep only members of
    /// the plan. A forged or stale entry installs nothing. Returns how many re-entered.
    ///
    /// v49 (G1-DA): the PLAN rides too. `da_sampling_secret` folds `miner_seed`, which is drawn fresh per process by design,
    /// so a re-derived plan is a different draw and every proved piece was dropped (pin
    /// `a_node_booted_from_the_same_files_resumes_the_da_sample_the_live_process_had_in_flight`: plan and proved piece
    /// differed live vs booted). The carried plan is installed only when well-formed ([`Self::da_plan_is_wellformed`]);
    /// otherwise the slot keeps the fresh draw. It is this node's own private draw, read back from its own files.
    pub(super) fn restore_da_samples(&mut self, held: Vec<(u64, Hash32, Vec<u64>, Vec<u64>, u64)>) -> usize {
        let mut entered = 0usize;
        for (addr, root, plan, verified, asked_at_ms) in held {
            let header_root = self
                .block_for_record_addr(addr)
                .and_then(|b| self.relay.dag().get(&b).map(|n| n.header.output_notes_root));
            if header_root != Some(root) || root == Hash32::hash(&[]) || self.da_record_notes(addr).is_some() {
                continue;
            }
            if !self.begin_da_sample(addr, root, Self::da_record_chunk_count()) {
                continue;
            }
            // CHAIN-CARRIES-REVIEWED: node-local DA availability probe state (no chain transition, no value) — the slot
            // was just created by `begin_da_sample` from the accepted header's root; this only restores its progress.
            if let Some(st) = self.da_sample_pending.get_mut(&addr) {
                if Self::da_plan_is_wellformed(&plan) {
                    st.want = plan.iter().map(|i| *i as usize).collect();
                }
                let want = st.want.clone();
                st.verified = verified.into_iter().map(|i| i as usize).filter(|i| want.contains(i)).collect();
                st.asked_at_ms = asked_at_ms;
                entered += 1;
            }
        }
        entered
    }

    /// Name the on-disk block window (`crate::block_window`, `persist::window_dir`). Called BEFORE
    /// `enable_persist`, so the restore can re-install the span the window holds.
    pub fn enable_block_window(&mut self, dir: std::path::PathBuf) {
        self.block_window = crate::block_window::BlockWindow::open(dir);
    }

    /// RESTORE THE SPAN (Kaspa reopens its block store; Bitcoin its block index): every block the window
    /// holds that the restored DAG does not — the blocks below the checkpoint's anchor — re-enters the DAG
    /// as an ancestor with the blue data it had, parents first, and is marked folded (its record is in the
    /// checkpoint's state, exactly like a carried ancestor). Then the anchor and the carried ancestors are
    /// re-linked to their selected parents so the selected chain reaches down through the span. After this
    /// the resumed node spans what its peers span: a peer's block that names any parent in the span grafts
    /// instead of parking, and the page lanes serve from the same store they served from before the
    /// restart. MEASURED 2026-09-21 19:13 (live pair, before): 38 and 34 blocks held, none shared above
    /// genesis. Cost: one pass over the window (bounded by the DAG's constant span), once per restart.
    ///
    /// ⛔ G1 (lane b 2026-10-24) — ONLY WHAT THE LIVE DAG HELD. `span` is the checkpoint's [`Self::dag_window_span`]: the live
    /// DAG's floor and the window ids at or above it the DAG did not hold (a joiner's fold-span bodies of the adopted past,
    /// `place_fold_span_body`, never enter its DAG). An entry below the floor or listed stays a window body. MEASURED before
    /// (joiner-restart-f4probe.log): the joiner's DAG 321 → 588 blocks across the restart, the 267 bodies re-installed.
    /// `None` (a pre-v53 file) installs every entry the DAG lacks, as before.
    ///
    /// ⛔ v64 (lane stable 2026-11-02) — AND THE DAG SHELLS NO OTHER FIELD BROUGHT BACK (`Node::dag_shells`), re-entered the same
    /// way, lowest score first, BEFORE the relink, so the restored DAG is the live one; the held `folded_floor` (v47) then
    /// re-marks the floor ones. §9.6 (a restore path reading this node's own checkpoint):
    /// (1) PoW — not re-checked, as for the window entries beside it and the carried ancestors (`graft_unfolded_carry`): each
    ///     is a block this node's live DAG held, which entered through a door that checked it; a shell is placed, never applied.
    /// (2) Proof — the shell's id is `H(header)` (it re-enters under the id the live DAG held); no body, nothing to verify.
    /// (3) Value — none: `add_ancestor_anchor` places a header with its blue data; no record, note or object is applied (the
    ///     checkpoint's state already counts each one — every unfolded block rides `fold_carry`, never here).
    /// (4) Replay — an id the DAG already holds is skipped (`add_ancestor_anchor` refuses it), so a second resume is a no-op.
    /// (5) Bounded — the list is the live DAG's own blocks, bounded by its prune span (`keep_depth` + slack).
    /// (6) Parity — the window entries this function installs: same insert, same relink, same index rebuild; the floor mark
    ///     comes from the held floor instead of being assumed (a shell above the floor stays unmarked, as it was held).
    /// v64 — re-enter the checkpoint's DAG shells (`Node::dag_shells`), lowest score first, each under the selected parent the
    /// live DAG held; an id already held is skipped. Returns how many entered. The §9.6 answers are on
    /// [`Self::install_block_window_span`], which this shares its insert with.
    pub(super) fn install_dag_shells(&mut self, shells: Vec<(crate::block::Block, u128, u64, Option<[u8; 32]>)>) -> usize {
        let mut shells = shells;
        shells.sort_by_key(|(b, _, bs, _)| (*bs, b.id()));
        let mut installed = 0usize;
        for (shell, bw, bs, sp) in shells {
            let sp = sp.map(crate::hash::Hash32);
            if self.relay.dag_mut().add_ancestor_anchor(shell.header, shell.tx_ids, bw, bs, sp) {
                installed += 1;
            }
        }
        installed
    }

    pub(super) fn install_block_window_span(
        &mut self,
        span: Option<(u64, Vec<[u8; 32]>)>,
        shells: Vec<(crate::block::Block, u128, u64, Option<[u8; 32]>)>,
        // v65: the ids the live DAG held unlinked — `None` at an adopt: relink all, as before
        unlinked: Option<Vec<[u8; 32]>>,
    ) {
        let mut installed = 0usize;
        let (floor, off) = match span {
            Some((f, ids)) => (f, ids.into_iter().collect::<std::collections::HashSet<[u8; 32]>>()),
            None => (0, std::collections::HashSet::new()),
        };
        for (score, id) in self.block_window.ascending() {
            if self.relay.dag().get(&id).is_some() || score < floor || off.contains(id.as_bytes()) {
                continue;
            }
            let Some(e) = self.block_window.entry(&id) else {
                continue;
            };
            let sp = e.selected_parent.map(crate::hash::Hash32);
            if self.relay.dag_mut().add_ancestor_anchor(e.block.header, e.block.tx_ids, e.blue_work, e.blue_score, sp) {
                self.folded_floor.insert(id);
                installed += 1;
            }
        }
        installed += self.install_dag_shells(shells);
        // v65: link exactly what the live DAG had linked — the blocks it held unlinked stay unlinked
        let relinked = match unlinked {
            Some(unlinked) => {
                let keep: std::collections::HashSet<crate::block::BlockId> = unlinked.into_iter().map(crate::hash::Hash32).collect();
                self.relay.dag_mut().relink_selected_parents_except(&keep)
            }
            None => self.relay.dag_mut().relink_selected_parents(),
        };
        if installed > 0 {
            // the chain index below the anchor is placeholders until the relinked span is walked whole
            // (see `Dag::rebuild_selected_chain_index`); the relink rebuilds it when it restored a link,
            // and a span whose links were all known at insert time needs the same walk
            self.relay.dag_mut().rebuild_selected_chain_index();
        }
        if installed > 0 || relinked > 0 {
            eprintln!(
                "[block-window] {installed} block(s) re-entered the DAG below the checkpoint's anchor from the \
                 window; {relinked} selected-parent link(s) restored — this node spans what its peers span"
            );
        }
    }

    /// Install a resumable checkpoint into this node. Guarded by schema + genesis-parity: because genesis
    /// identity is a deterministic per-network constant, a node and its own datadir's snapshot share it by
    /// construction, so a same-network restart simply RESUMES its persisted chain (Bitcoin-datadir semantics:
    /// the datadir IS the chain; nobody hands bitcoind its genesis on every launch). A snapshot whose genesis
    /// identity differs — a different NETWORK, or any chain this node is not on — is REFUSED (anti chain-split:
    /// never load another chain's state). The tip is re-installed via the SAME [`crate::dag::Dag::add_anchor`]
    /// path used to adopt a #29 DSYNC peer tip (no parent history required — phone-safe), then the final
    /// value-state is installed VERBATIM (never replayed, so no peg op is re-applied and no value is
    /// recomputed). Returns `true` on a successful restore.
    pub fn restore_snapshot(&mut self, snap: crate::persist::NodeSnapshot) -> bool {
        matches!(self.derive_replicated(ReplicaBase::PersistedVerbatim(snap)), ReplayOutcome::Restored(true))
    }

    /// [`Self::restore_snapshot`]; `fold_carry` false leaves the carry placed but unfolded — the checkpoint resume
    /// folds once, after it has installed the folded floor and the window span the fold's walk reads.
    pub(super) fn restore_snapshot_folding(&mut self, mut snap: crate::persist::NodeSnapshot, fold_carry: bool) -> bool {
        if snap.schema != crate::persist::SNAPSHOT_SCHEMA {
            return false;
        }
        // GENESIS-PARITY RESUME: genesis identity is a deterministic per-network constant, so this node and its
        // own datadir's snapshot compute it identically by construction. Resume iff they are byte-identical; a
        // snapshot whose genesis identity differs — a different NETWORK, or any chain this node is not on — is
        // REFUSED (anti chain-split: never load another chain's state). Fail-closed; the node stays on its own
        // genesis, /get_info `chain_id` unchanged across the restart.
        if snap.genesis_commit != self.params().genesis_parity_commit {
            return false;
        }
        // ⛔⛔⛔ CHAIN-IDENTITY RESUME (v29) — the anti-chain-split check the resume path never really had.
        //
        // ROOT-LAYER: the comparison above is where a snapshot's chain identity is DECIDED, and the value it
        // decides on is produced by `params.genesis_parity_commit` — a per-network PREFIX that is an INPUT to
        // genesis derivation. A value that feeds genesis cannot also witness what came out of it, so no edit
        // at the reading site could ever make it fork-aware. The fix is to give this gate a value that IS
        // produced by consensus hashing (the genesis BLOCK ID, stamped at write time in `export_snapshot`)
        // and compare that. Same gate, a value that can actually move.
        //
        // MEASURED: 2026-08-26 — binding `amm_set_root` into `BlockHeader::preimage` moved EVERY block id
        // in-tree (the live daemons reported `chain_id fc6a3623…` at heights 153,765/154,824 while the
        // in-tree binary derived a different genesis, with `genesis_commit` byte-identical across the
        // fork), and the frozen-door repair meant such files now DECODE — the exact moment a cross-fork
        // tip would silently resume. The pool AMM was then retired at source the same day (user ruling)
        // and the preimage binding reverted, so NO deployed fork exists any more — but the gate stays,
        // because the next consensus-hash change re-creates the same danger and this is the check that
        // sees it.
        //
        // THE ZERO CASE: a pre-v29 file carries no `chain_id` and reads back all-zero. That is not a
        // foreign chain — it is a file from an era when every deployed binary shared today's id rules
        // (the only preimage change ever made was retired without deploying), so it is resumable, and
        // refusing it would orphan real custody (the upgrade-custody law). It resumes, with a log line
        // naming the fact; its next save stamps the id and all future restarts take the strict path.
        // Every v29+ file carries a REAL id, so any future fork is caught by the non-zero compare.
        //
        // MUST-STAY-GREEN: `persist::real_v27_fixture_tests` (the three REAL live snapshots must decode,
        // migrate AND resume through this gate), the v25/v26/v27 door migrations, and every same-chain
        // restart test — a node restarting on its OWN v29 datadir stamps and reads the same genesis id.
        //
        // cons: none. TIME = one 32-byte compare plus an O(1) `dag().genesis()` read (a stored `Option`
        // field, not a search), executed ONCE per process start — not per block, per record or per note:
        // f(fixed constants), never f(history). SIZE = the 32 B accounted on `NodeSnapshot::chain_id`.
        //
        // The prints name only GENESIS IDS — deterministic per-network constants every node derives
        // independently and already serves as `chain_id` on /get_info. No balance, note, nullifier,
        // address or height is named here.
        let own_genesis = match self.relay.dag().genesis() {
            Some(g) => *g.as_bytes(),
            None => [0u8; 32],
        };
        if snap.chain_id == [0u8; 32] {
            eprintln!(
                "[persist] chain-identity: pre-v29 checkpoint (no stamped chain id) — RESUMING under the                  unforked historical id rules; the next save stamps {} and future restarts compare strictly.",
                crate::hash::Hash32(own_genesis),
            );
        } else if snap.chain_id != own_genesis {
            eprintln!(
                "[persist] ⛔⛔⛔ REFUSING A FOREIGN-CHAIN CHECKPOINT — it names a different genesis block                  than this binary derives.
                 [persist]   checkpoint chain_id: {}
                 [persist]   this binary's genesis: {}
                 [persist]   The checkpoint decoded CLEANLY — it is not corrupt, it belongs to another                  chain. Resuming it would install a tip whose id-space this binary does not share. To join                  the chain this binary implements, move the snapshot file aside DELIBERATELY and restart;                  to keep serving the old chain, run the binary that produced it.",
                crate::hash::Hash32(snap.chain_id),
                crate::hash::Hash32(own_genesis),
            );
            return false;
        }
        let tip_id = snap.tip_block.id();
        // ⛔ RECORD THE TIP HERE — the restore path's OWN record site, not inside `add_anchor`.
        //
        // I first put this recording inside `add_anchor` itself. That was wrong: `add_anchor` runs for
        // genesis and for the instant_sync adopt too, and instant_sync ALREADY records its tip
        // (`record_note_payload_for` at the adopt site), so recording again in `add_anchor` DOUBLE-recorded
        // every adopted block. MEASURED: `served_seq` ran to 33,636 against a 7,575-block DAG — a 4x
        // over-count that corrupts the frontier coordinate a recipient's copath resolves against, so the note
        // settled but the recipient's wallet read 0. The record belongs at each CALLER that owns a payload,
        // once — restore_snapshot is one such caller and records here; add_anchor stays a pure DAG insert.
        // ⛔⛔⛔ THE RESUMED TIP IS NEVER RE-RECORDED HERE — it is restored (circulating) or FETCHED.
        //
        // ROOT-LAYER: this was the one site that WROTE a ledger record from a snapshot instead of from
        // the chain. A tip whose block carried real notes is a circulating record and comes back through
        // the restore loop below with its persisted ordinal, so `da_load` hit and this never ran. The
        // only tip that reached it was a seed-only (empty) block — and re-recording THAT regenerates a
        // FRESH random seed note (`fresh_seed_note` is high-entropy by design: identical bytes exist
        // only because the producer wrote them once and they travel in the record), so the resumed node
        // manufactured a record no peer holds. Worse, it ran BEFORE the ordinal ceiling is rebuilt from
        // the restored rows (below), so the write landed at ORDINAL 0 — the genesis record's slot.
        // MEASURED: gate 31 (scratch musd-ecocheck-xObm0A, frozen 28b764ea), n1 after `[term]`:
        // "[record-write] seq=253689959268021556 ordinal=0" (the same seq was ordinal=68 before the
        // kill), then "[record-miss] addr 268630260899752944 [genesis] maps to ordinal 70 … NEITHER key
        // holds bytes", "[copath-coord] … truly does not hold it", "[da-fetch] 0/1 peer record(s)
        // verified" forever, n1's unspent root moved 62d83896→203e7df3→106bbfa→26cc5138→30c7c572 on a
        // chain with ONE real note while the untouched n2 stayed on the true root 14648235 and REVERTed
        // 181 times chasing n1's advertised phantoms. After: the resumed node's ledger holds exactly the
        // rows the snapshot carried, every missing ordinal (this tip included) is a by-ordinal want the
        // peer backfill answers with the bytes the mesh actually holds, and the ordinal space stays the
        // mesh's. MUST-STAY-GREEN: the persist door tests (real v27/v29 bytes resume on two nodes
        // identically), the READY→READY resume test, a_restarted_node_never_resurrects_a_spent_note…,
        // the DA seed-regen two-party tests. `add_anchor` stays a pure DAG insert, as before.
        // (The tip's own row is checked AFTER the circulating rows are restored below — checking it
        // here, before `da_mem` is refilled, is what made `da_load` miss on EVERY restart.)
        let tip_rid = Self::da_record_id_for_block(&tip_id, 0);
        // The node's OWN tip, from its OWN disk, rebuilt from a header the DAG retained — see
        // `admit_anchor_block_witnessed` for why the witness is `NotServable` here and `Required` on
        // every network door.
        //
        // ⭐ DB-135b (2026-09-21): KEEP THE ANCHOR'S OWN WITNESS ACROSS THE RESTART. The snapshot's anchor
        // carries the 32-byte PoUW witness `export_snapshot` found for it, and the admission below keeps
        // the block as header + tx ids only — so the witness left with it, and the resumed node served a
        // bundle whose anchor had `pow_proof` EMPTY. MEASURED on the live pair (19:13): both nodes refused
        // each other's bundle "anchor block: no witness carried", each stuck on its own resumed branch.
        // ROOT-LAYER: the two witness slots and the kept anchor body are what `pow_witness_for` and
        // `build_sync_bundle` read; they are filled here from bytes the snapshot already carries, so the
        // next save (`export_snapshot` → `pow_witness_for`) carries the witness forward again.
        // MUST-STAY-GREEN: every same-chain restart pin and `family_d_door_audit_tests` (a witness-less
        // anchor from a NETWORK door is refused exactly as before — nothing here touches a network door).
        // cons: none — one 32-byte witness in two fixed slots and one anchor body per restart; nothing per
        // block, nothing per record, no growth on any axis.
        let anchor_witness = snap.tip_block.pow_proof.clone();
        // ⭐ G1g-v (lane a 2026-10-23): THE KEPT ANCHOR BODY IS THE CHECKPOINT'S WHOLE COPY (`anchor_body`, v45), never the
        // header + tx-id shell `tip_block` is: the shell in this slot read as the anchor's body on every restart (same id,
        // a different wire digest — restart census g1giv-restart-census-20261023.log, both nodes) and `build_sync_bundle`
        // served it as the anchor's whole body once the window had pruned the anchor. Installed only under the restored
        // tip's id and with its witness; otherwise `None`, and both readers fall to the witness slots below and the
        // bundle's own header-only arm (which names the anchor's gap). The witness still rides the two slots.
        let anchor_body = snap.anchor_body.take().filter(|b| b.id() == tip_id && !b.pow_proof.is_empty());
        // ⭐ G1g-vi (lane a 2026-10-23): the anchor re-enters at the DEPTH the live process held it at (`height` is the
        // exported `selected_chain_len`), never at its blue score — see `Dag::add_anchor`.
        self.admit_anchor_block_witnessed(
            snap.tip_block,
            snap.blue_work,
            snap.blue_score,
            snap.height,
            PowWitness::NotServable,
        );
        if !anchor_witness.is_empty() {
            self.tip_pow_witness = Some((tip_id, anchor_witness.clone()));
            self.anchor_pow_witness = Some((tip_id, anchor_witness));
        }
        self.anchor_block_full = anchor_body;
        // ⭐ G1f (lane a 2026-10-23) — THE RUNNING WHOLE-CHAIN CERTIFICATE RESUMES, VERIFIED. `chain_cert` had writers at the
        // off-lock step install (`install_cert_step`) and the adopt (`inherit`, above) and NO restore site, so every restart
        // dropped it to the construction value: the restart census read chain_cert 95 → 29 B and certified_blue_work 3 → 1 B
        // on both nodes (g1e-b-restart-census-20261022.log:2507+), and the next bundle build re-proved the BASE step from the
        // genesis proof — a certificate that then attested only the delta since the restart, under a tip whose declared work
        // the whole chain had earned. THE DOOR: the checkpoint's certificate installs only through
        // `WholeChainCert::inherit` — the exact verify a DSYNC adopter runs on a served bundle (the step at the release door,
        // its io block against the four public values); a step that does not decode or verify installs nothing. THE CURSOR
        // IS DERIVED, never read from a file: the adopt gate binds a served certificate's proven work to the bundle's
        // declared `blue_work` (`sync.rs`, "cert.work != bundle.blue_work" is refused) and `install_cert_step` sets the
        // cursor to the stepped tip's `blue_work` whose delta the step just folded, so cursor == proven work holds for every
        // honest node by induction from `(0, 0)` (MEASURED: work 48, cursor 48 at the stepped tip,
        // g1f-chain-cert-red2-20261023.log:1589). The checkpoint's own `blue_work` is the FOLD ANCHOR's, below the stepped
        // tip, so it bounds nothing here (MEASURED: an anchor bound refused the honest certificate,
        // g1f-chain-cert-green2-20261023.log:1575: proven 48, declared anchor work 16). Fail-closed on the item only: a refused certificate leaves the
        // construction value, the node still resumes and the next bundle build steps from genesis as a never-stepped node
        // does — never a halt. cons: one certificate verify per boot (~220 ms measured at T = 2^14) and ≈178 KB more per
        // checkpoint write, both constant in height.
        if let Some(wire) = snap.chain_cert.take() {
            // The refusal names PUBLIC values only (decodes, the claimed proven work — what a bundle serves anyway).
            let decoded = wire.to_proof();
            match decoded.as_ref().and_then(usdm_decider::whole_chain_cert::WholeChainCert::inherit) {
                Some(cert) => {
                    self.certified_blue_work = cert.work();
                    self.chain_cert = cert;
                }
                None => eprintln!(
                    "[restore] ⛔ G1f: the checkpoint's whole-chain certificate installs nothing (decodes {}, claimed proven work {:?}) \
                     — the construction certificate stands and the next bundle steps from genesis",
                    decoded.is_some(),
                    decoded.as_ref().map(|p| p.work)
                ),
            }
        }
        // G1e-iv: the spine's rewind ring resumes ONLY when its newest entry IS the frontier this same file carries
        // (same fold ordinal, root and leaf count), ascending and within the ring bound — else nothing installs.
        if !snap.spine_frontiers.is_empty() {
            let k = snap.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
            let ring = std::mem::take(&mut snap.spine_frontiers);
            let ascending = ring.windows(2).all(|w| w[0].0 < w[1].0);
            let top_is_frontier = ring.last().is_some_and(|(o, f, _, rh)| {
                *o == k
                    && f.count() == snap.spend_frontier.count()
                    && f.root() == snap.spend_frontier.root()
                    && rh.count() == snap.root_history.count()
                    && rh.root() == snap.root_history.root()
            });
            // G2a: every entry's anchor spine holds one anchor per record through its ordinal
            let anchors_lawful = ring.iter().all(|(o, _, _, rh)| rh.count() == *o);
            if ascending && ring.len() <= Self::REWIND_RETAIN && top_is_frontier && anchors_lawful {
                self.spine_recent_frontiers = ring.into();
            } else {
                eprintln!(
                    "[restore] ⛔ G1e-iv: the checkpoint's rewind ring installs nothing ({} entries; its newest entry is not the \
                     frontier the file carries) — the ring stays empty, as before v43",
                    ring.len()
                );
            }
        }
        // note_index REMOVED (no-growth): the node keeps no note set — a resumed node relays only new blocks;
        // earlier notes are peer-sampled (#27 DAS). The frontier roots below carry the note commitment.
        // note_clues NOT restored (no-growth brick 3): the OMR clue cache is a transient bounded serve-cache, so it
        // stays empty on resume and refills FORWARD from the tx stream; evicted/absent clues are peer-DA or the
        // wallet decap-scans. It is DA/acceleration data, never consensus — nothing money-critical depends on it.
        self.bond_locked = snap.bond_locked;
        self.bond_height = snap.bond_height;
        // v25 — RESUME THE FINALITY QUORUM with the value that backs it. Before this, every restart
        // emptied `validators`, the node rejected all finality votes at `bond_of(voter)==0`, and
        // finalized_height froze until a fresh bond landed (MEASURED 2026-08-22, see persist.rs v25).
        self.validators.import_state(
            snap.bonded_validators,
            snap.slashed_validators,
            snap.slashed_bond_burned,
            snap.validator_bond_commit,
            snap.validator_custody,
        );
        self.validators.import_finality_state(snap.finality_validators.clone()); // SATOSHI §6
        // G2b: the activation heights and departed rows resume with the seats they describe
        self.validators.import_seat_activations(
            snap.custody_seat_active_from,
            snap.finality_seat_active_from,
            snap.departed_custody_seats,
            snap.departed_finality_seats,
        );
        self.validators.import_seat_words(snap.seat_words.clone()); // v55 §BR-3 17.3
        // v66 (T3/T2): the custody key table the checkpoint held, after the seats it names (`import_kem_eks` keeps only seated ids)
        self.validators.import_kem_eks(snap.validator_kem_eks.clone());
        // v67 (SAFE AT SCALE): each custodian's custody seat, after the seats and their activation heights
        self.validators.import_custody_seats(snap.custody_seat_numbers.clone());
        self.spend_frontier = snap.spend_frontier;
        // v47 (G1d): the rewind base EXACTLY AS HELD (DB-268 — the base a certified adopt set), never the resume point
        // re-derived: a node that adopted nothing holds `None` and rewinds from its own per-ordinal roots, which restore with
        // it. Installed only when its shape is consistent (a whole number of records, at or below the restored frontier).
        {
            let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
            let top = self.spend_frontier.count() / rec;
            self.fold_checkpoint =
                snap.fold_checkpoint.take().filter(|(k, ck, rh)| ck.count() == k.saturating_mul(rec) && rh.count() == *k && *k <= top);
        }
        // Resume the root-history accumulator (O(DEPTH) peaks) so a wallet's frozen receipt anchor stays provable
        // across a node restart — never rebuilt from history (no-growth); stays in lockstep with spend_frontier.
        self.root_history = snap.root_history;
            // ⛔⛔⛔ DA ROWS RESTORE UNCONDITIONALLY — hoisted OUT of the `unspent_note_root != genesis`
            // block on 2026-09-02. A node whose accumulator was still at genesis (no receive folded yet)
            // restored NONE of its ledger rows at resume, then seeded wants for its OWN records; the
            // peer answered `hold 0` and both sides sat mutually holed after a rolling restart. The
            // record set is the LEDGER; its restore must not depend on the accumulator's state.
            // Pinned by idle_record_presence_across_restart_tests.
            // §20.2: the saved cover keys, by record
            let snap_keys: std::collections::BTreeMap<u64, crate::cover::CoverKey> = snap.record_cover_keys.iter().copied().collect();
            let provisional: std::collections::HashSet<u64> = snap.provisional_records.iter().copied().collect();
            if !snap.circulating_records.is_empty() {
                let mut restored = 0usize;
                for (rid, ord, notes_blob, targets) in &snap.circulating_records {
                    let reals: Vec<Vec<u8>> = notes_blob
                        .chunks(crate::cover::PQ_NOTE_BYTES)
                        .filter(|c| c.len() == crate::cover::PQ_NOTE_BYTES)
                        .map(|c| c.to_vec())
                        .collect();
                    // A COORDINATE-ONLY ROW (empty bytes) restores its ORDINAL and nothing else (2026-09-22): the seed
                    // bytes are a pure function of the address and regenerate at read time through the header and
                    // reference checks (`regenerate_idle_record`), which is also what keeps a restore from ever
                    // fabricating a real record's row. Materializing them here re-created the DB-141 growth in RAM.
                    if reals.is_empty() {
                        if *ord != u64::MAX {
                            self.da_ord_mem.entry(*rid).or_insert(*ord);
                            self.da_ord_rev_mem.entry(*ord).or_insert(*rid);
                            self.da_ord_top = self.da_ord_top.max(*ord);
                        }
                        // the seed row is re-materialized so a peer's by-id want for it is answered after the
                        // restart (`idle_records_survive_sweep_export_and_restore`: "hold 0" strands the peer);
                        // BOUNDED: coordinates are the ladder-bounded ordinal set (≤ DA_LADDER_SPAN), and the
                        // ordinal pruner retires these rows as they go cold exactly like any written row
                        self.da_mem
                            .entry(*rid)
                            .or_insert((vec![crate::cover::public_idle_seed_note(*rid).to_vec()], Vec::new(), true, crate::cover::idle_cover_key(*rid)));
                        self.da_top = self.da_top.max(rid.saturating_add(1));
                        self.da_base = self.da_base.min(*rid);
                        restored += 1;
                        continue;
                    }
                    // PROVENANCE AS HELD (v63): a row carried by `snap` is this node's own ledger returning through
                    // the snapshot door, chain-bound exactly when it was bound before the save. A row the snapshot
                    // names provisional (a peer's page this node never bound) comes back provisional — never an
                    // authority by way of a restart. The resumed node still re-proves its unspent state by folding
                    // this ledger to the certified root before it serves anything.
                    let key = snap_keys.get(rid).copied().unwrap_or_else(|| crate::cover::idle_cover_key(*rid));
                    self.da_mem.entry(*rid).or_insert((reals, Vec::new(), !provisional.contains(rid), key));
                    if !targets.is_empty() {
                        self.da_targets_mem
                            .entry(*rid)
                            .or_insert_with(|| targets.clone());
                        // The snapshot carries the record's consumed targets; the FILED index must be
                        // re-registered from them, or `da_recv_wire` cannot re-derive a pre-restart receive
                        // and every heal refold on the resumed node lands on the wrong root (gate 36).
                        self.register_filed_targets_from_blob(*rid, targets);
                    }
                    if *ord != u64::MAX {
                        self.da_ord_mem.entry(*rid).or_insert(*ord);
                        self.da_ord_rev_mem.entry(*ord).or_insert(*rid);
                        // ⛔⛔⛔ REBUILD THE ORDINAL CEILING WITH THE ORDINALS. `da_ord_top` is written by
                        // `da_store_ordinal` at record-write time and was never restored here, so every
                        // resumed node answered `da_record_ordinal_top() == 1` regardless of how many
                        // records it restored — and `span_closes_to_target` uses that value as its
                        // ceiling, refusing every span past ordinal 1 as "ran past the known ordinal
                        // space". A restarted node could therefore never verify a by-id record it
                        // fetched: it re-asked forever — the live pair's "asks 32 by id every tick".
                        //
                        // ROOT-LAYER: the ceiling is PRODUCED here, where the ordinal maps are refilled;
                        // `da_store_ordinal` is the write-time producer of the same invariant and this is
                        // its resume-time twin. Reading `da_ord_rev_mem.keys().max()` at every consumer
                        // would be the read-layer patch. MEASURED: before → producer ordinal_top=2,
                        // resumed ordinal_top=1 in 8 of 8 runs (da_seed_regen_tests); after → equal.
                        // MUST-STAY-GREEN: the persist door tests (real v27/v29 bytes resume on two nodes
                        // identically), the READY→READY resume test, and every restore that carried no
                        // ordinals (`ord == u64::MAX` rows leave the ceiling untouched, as before).
                        // cons: none — one max over the loop already running; nothing persisted, no walk.
                        self.da_ord_top = self.da_ord_top.max(*ord);
                    }
                    // Rebuild the bucket index this record's targets name — the ledger is the
                    // authority, the index is derived state, and it died with the process (measured
                    // 2026-08-18: same seed, same node, bucket went from filed to empty across a
                    // restart while the note stayed on chain). fold_acc=false: the restored
                    // account_acc already includes these folds. Exactly-once via the refile core;
                    // fixed target shape per record, resume-only.
                    if !targets.is_empty() {
                        self.refile_account_targets_at(*rid, targets, false);
                    }
                    restored += 1;
                }
                eprintln!(
                    "[uns-resume] restored {restored} circulating-note record(s) from the snapshot — \
                     membership proofs and seed-restore decap survive the restart for every live note."
                );
            }
            for (rid, _) in &snap.coordinate_rows {
                if let Some(key) = snap_keys.get(rid) {
                    self.install_stripped_row(*rid, *key, !provisional.contains(rid));
                }
            }
            // v63: a real record's ordinal row whose bytes this node had not yet fetched — its coordinate only (the bytes
            // stay wanted by id; `regenerate_idle_record` answers nothing for a block that does not declare itself idle)
            for (rid, ord) in &snap.coordinate_rows {
                self.install_coordinate_row(*rid, *ord);
            }
        // ⭐ G1e-ii (lane a 2026-10-23) — THE MEMBERSHIP-STEP INDEX RESUMES THROUGH ONE DOOR. `da_macc_fwd_mem` / `_rev_mem` /
        // `da_macc_first` / `da_leafstart_mem` had writers at the fold (`record_note_payload_inner`, `da_store_ordinal`) and the
        // reorg memo (`derive_membership_acc_through`) and NO restore site, so every restart emptied them while the rows they
        // index were restored above (restart census g1f-restart-census-20261023.log:2930–2933, both nodes) and
        // `da_ordinal_at_membership_acc` read None — "forged" — for every accumulator this node served before the restart.
        // The door: the entry at the highest ordinal must equal the frontier accumulator the SAME file carries
        // (`snap.membership_acc`, installed as `served_membership_acc` below) — an index that does not stand on the frontier it
        // claims installs nothing, first and leaf starts included, and the node resumes exactly as before v42.
        // ⛔ OR THE INDEX RE-FOLDS FROM THE ROWS JUST RESTORED (lane stable 2026-11-02). A DSYNC joiner that RE-ANCHORED (its
        // spine went stale; the certified bundle replaced it) holds the index of its own prefix below the re-anchor while its
        // frontier is the re-anchored one, so the top never equals it until the new span closes — and the door refused it.
        // MEASURED (launch tail, n2 restarted at 1,800 s just after a re-anchor to 820, stable/b4.log): "G1e-ii … installs
        // nothing (163 entries …)", then "carried ladder span 0 … does not land (held there: false; macc first None)" — the
        // ladder restore anchors on this index — and restart census `da_macc_*` 18,508 → 2 B, `da_ladder_mem` 117,931 → 2 B,
        // `da_tags_mem`, `roots_run_origin_windows` … lost. Moved below the row restore so the second arm can judge it: the index
        // installs when it is contiguous from its first ordinal and every entry is `step(previous, root)` with `root` derived
        // from the record row this node holds at that ordinal, from the accumulator it knows below the first one (genesis at
        // ordinal 0, or `da_macc_first`'s). A forged, reordered or unrooted entry still installs nothing.
        // cons: at boot only, on the second arm — one record-root derive and one Poseidon2 step per entry (≤ the index's own
        // bound); nothing on the steady-state path.
        if !snap.da_macc_steps.is_empty() {
            let top = snap.da_macc_steps.iter().max_by_key(|(o, _)| *o).map(|(_, a)| *a);
            let refolds = || -> bool {
                let mut steps = snap.da_macc_steps.clone();
                steps.sort_unstable_by_key(|(o, _)| *o);
                let Some(&(first, _)) = steps.first() else { return false };
                let mut prev = if first == 1 {
                    Self::MEMBERSHIP_GENESIS_ACC
                } else {
                    match snap.da_macc_first {
                        Some((f, a)) if f == first => a,
                        _ => return false,
                    }
                };
                let mut next = first;
                for (o, a) in steps {
                    let Some(root) = (o == next).then(|| self.da_block_root_at_ordinal_derive(o)).flatten() else { return false };
                    prev = usdm_decider::note_membership_air::note_membership_step_new_acc(prev, root);
                    if prev != a {
                        return false;
                    }
                    next += 1;
                }
                true
            };
            if top == Some(snap.membership_acc) || refolds() {
                for (o, a) in std::mem::take(&mut snap.da_macc_steps) {
                    self.da_macc_fwd_mem.insert(o, a);
                    self.da_macc_rev_mem.insert(a, o);
                }
                self.da_macc_first = snap.da_macc_first.take();
                for (addr, leaf_start) in std::mem::take(&mut snap.da_leaf_starts) {
                    self.da_leafstart_mem.insert(addr, leaf_start);
                }
            } else {
                eprintln!(
                    "[restore] ⛔ G1e-ii: the checkpoint's membership-step index installs nothing ({} entries; its top accumulator is not \
                     the frontier's, and it does not re-fold from the rows this node holds) — the index stays empty, as before v42",
                    snap.da_macc_steps.len()
                );
            }
        }
            // v64: the tags of rows no window block re-derives, merged per slot (first write wins, as every tag filer)
            // DIGITAL-CASH-PRIVACY-REVIEWED: the node's own locator tags read back from its own datadir; nothing logged.
            for (rid, tags) in std::mem::take(&mut snap.unwindowed_tags) {
                let mut merged = self.da_load_tags(rid);
                // ⛔ A-F118: the ONE merge rule (`da::merge_slot_tag`), as every tag filer
                let reals = self.da_load(rid).map_or(0, |r| r.len());
                let mut changed = false;
                for (slot, k) in tags {
                    changed |= crate::node::da::merge_slot_tag(&mut merged, slot, k, (slot as usize) < reals) != crate::node::da::TagMerge::Kept;
                }
                if changed {
                    self.da_store_tags(rid, &merged);
                }
            }
        // ⭐⭐⭐ RE-ESTABLISH THE RANGE CURSOR FROM THE PERSISTED WATERMARK, CLAMPED TO WHAT THIS FILE
        // CERTIFIES — NEVER FROM THE SPINE (v33, the readiness-cursor closure; reviewer's must_fix #1).
        //
        // The cursor is "one past the highest position whose unspent-set sidecars this node has proven
        // held/served". The previous re-establishment took the RESTORED SPINE as that proof — but the
        // spine is ADOPTABLE WITHOUT ROWS: a #29 DSYNC jump installs the peer's certified spine in O(1)
        // (the adopt arm above `open_roots_run_span`) while this node holds ZERO rows of the jumped
        // span, and `export_snapshot` persists that spine verbatim. So a jumped node's restart CANCELLED
        // its debt: MEASURED 2026-09-06 (red pin `a_restart_of_a_jumped_node_must_not_cancel_its_
        // sidecar_debt`): 40 rowless certified positions, verdict 32, backlog 0, cursor 41 — READY on a
        // node whose sidecar pages serve holes, the stranded-fold class the readiness verdict exists to
        // refuse. The spine proves the span is CERTIFIED, never that this node held or served its rows.
        //
        // WHAT REPLACES IT — belt and braces:
        //   (a) the v33 snapshot carries the cursor itself (`NodeSnapshot::sidecar_cursor`): the live
        //       node's own honest ledger of the debt line, saved beside the spine it was honest against.
        //       A jumped node's save carries its LOW cursor, so its restart resumes owing the span.
        //   (b) the persisted value is CLAMPED to evidence at load — never above one past what this same
        //       file certifies (nothing beyond the certified position exists to have been served). Within
        //       one honest save the pair is consistent by construction, so the clamp only ever bites a
        //       corrupt or forged field; the snapshot is LOCAL cache, state is a function of the chain.
        //   (c) a LEGACY file (pre-v33, field = 0) resumes at the EVIDENCE FLOOR: the retention floor
        //       (certified − DA_LADDER_SPAN — ordinals below it were released by design and are proven
        //       by ladder rung folds, the same floor `sidecar_named_hole_count` tracks) and then only
        //       contiguous HELD rows advance it. A legacy complete node re-proves its last span by
        //       paging once (bounded, drains); a legacy jumped node's debt is COUNTED, never cancelled.
        //
        // The earlier defect this block was born for stays fixed by (a): a healthy restart's watermark
        // is its own saved cursor, so a spent-out ordinal in the restored rows no longer freezes the
        // walk (MEASURED 2026-09-06 live gate runs: sidecar_gap 91→154 / 861→1258 growing with height
        // on a healed restarted node — that regression class is covered by the persisted value, not by
        // trusting the spine).
        //
        // MUST-STAY-GREEN: the two rolling-restart pins, the resume pins (a complete snapshot still
        // resumes with zero backlog — its saved cursor IS past its top; a spine-less resume keeps the
        // old cursor and claims nothing — the clamp and the maxes never lower a live value), the heal
        // REVERT's deliberate rewind to 1 + refill (untouched — it runs after resume and re-pages
        // through the same advance sites). cons: one min, three maxes and a walk over rows present in
        // RAM, once per resume — f(circulating records), never f(history).
        let spine_proven =
            self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        let certified_at_save = snap.served_seq.max(spine_proven);
        if snap.sidecar_cursor > 0 {
            let clamped = snap.sidecar_cursor.min(certified_at_save.saturating_add(1));
            self.sidecar_cursor = self.sidecar_cursor.max(clamped).max(1);
        } else {
            let floor = certified_at_save
                .saturating_sub(Self::DA_LADDER_SPAN)
                .max(1);
            self.sidecar_cursor = self.sidecar_cursor.max(floor);
        }
        while self.da_ord_rev_mem.contains_key(&self.sidecar_cursor) {
            self.sidecar_cursor = self.sidecar_cursor.saturating_add(1);
        }
        // A tip whose row the snapshot did NOT carry (an autosave that predates the last record) is a
        // by-id WANT — counted by `missing_record_count`, so the node reads holed (advertises no root,
        // the roll gate refuses) until the mesh's bytes land at the mesh's ordinal through the ordinary
        // by-id backfill. Never re-recorded locally: see the note above the anchor insert.
        if !self.da_holds(tip_rid) {
            self.wanted_record_ids.insert(tip_rid);
            eprintln!(
                "[persist] resumed tip has no ledger row in this snapshot — registered a by-id want for \
                 it (the mesh's bytes at the mesh's ordinal); this node is holed until it lands"
            );
        }
        // v26 MAIL CUSTODY: merge each filed letters column back onto its row (creating the row shell if
        // its notes were spent away — mail outlives value movements). WHY the keep-live-if-non-empty
        // branch is correct (not a skip-because-seen): TWO legitimate writers exist for a row's letters
        // column — this snapshot merge (the PAST, captured at the previous shutdown) and the live ingest
        // lane `apply_letter_set` (the PRESENT, which may have filed newer letters for the same rid
        // between boot and this merge). The live fill is a superset-or-equal for that rid; overwriting it
        // with the older snapshot bytes would DROP mail that arrived after the save. Neither writer is
        // deletable: without the snapshot side restarts lose mail (the measured disappearing-messages
        // class this field exists for); without the live side no new mail files.
        if !snap.letter_columns.is_empty() {
            let mut mail_rows = 0usize;
            for (rid, letters) in &snap.letter_columns {
                if letters.is_empty() {
                    continue;
                }
                if !self.da_mem.contains_key(rid) {
                    // A LETTERS-ONLY row carries no money column at all, so its provenance decides
                    // nothing: with no note bytes it can never be a record's body and can never be an
                    // authority. `false` is the honest value.
                    let rows = &mut self.da_mem;
                    rows.insert(*rid, (Vec::new(), letters.clone(), false, crate::cover::idle_cover_key(*rid)));
                    mail_rows += 1;
                } else if let Some(row) = self.da_mem.get_mut(rid) {
                    if row.1.is_empty() {
                        row.1 = letters.clone();
                        mail_rows += 1;
                    }
                }
            }
            eprintln!(
                "[uns-resume] restored the filed mail column on {mail_rows} record(s) — letters survive \
                 the restart (permanent unless the user deletes)."
            );
        }
        self.nf_fold_seq = snap.nf_fold_seq;
        self.account_acc = crate::hash::Hash32(snap.account_acc);
        // …and restores it into the maintained accumulator, so resume and live folding are one series.
        self.served_membership_acc = snap.membership_acc;
        // G1c (lane a 2026-10-22): THE TIP TRANSITION RIDES BESIDE THE ACCUMULATOR IT FOLDS TO. `membership_tip_prev` /
        // `membership_tip_root` had one live writer (the record fold) and no restore site, so a restarted node served
        // `(0, 0, acc)` over `/get_membership_acc` and in every bundle's `SyncState.membership_tip` until its next fold
        // (restart census CHANGED 101 B → 24 B on every restart, g2b-census-harness-20261022.log:3906+). BOUND, never
        // trusted: the pair installs only when it folds to the carried accumulator — the same step the live fold took
        // (`note_membership_step_new_acc`); a planted pair installs nothing and the construction zeros stand (the
        // status quo, fail-closed on the bad item). Zero/zero = never folded. One hash, once per resume.
        {
            let zero = usdm_decider::poseidon2_compress::zero_digest();
            let (p, r) = (snap.membership_tip_prev, snap.membership_tip_root);
            if p == zero && r == zero {
                // never folded: the construction value stands
            } else if usdm_decider::note_membership_air::note_membership_step_new_acc(p, r) == snap.membership_acc {
                self.membership_tip_prev = p;
                self.membership_tip_root = r;
            } else {
                eprintln!(
                    "[uns-resume] ⛔ the checkpoint's membership tip transition does not fold to its accumulator — refused; \
                     the next fold publishes a real one"
                );
            }
        }
        // Restore the DA frontier, never shrinking one this process already reached (a resume must not lose
        // ground a live node has already covered).
        // Restore the recorded position FIRST — the backfill seed below reads it to know what is missing.
        // Never shrink one this process already reached.
        self.served_seq = self.served_seq.max(snap.served_seq);
        // v31: the fold continues from the checkpoint's anchor (a v30 file carries no cursor: its spine
        // folded every record through its tip in arrival order, so the tip IS its fold root).
        // ⛔⛔⛔ A RESUME MUST NOT CLAIM A FOLD POSITION IT CANNOT SUPPORT. This DELETES a silent rescue.
        //
        // Substituting the tip for an absent cursor is correct for a v30 file — that spine folded every
        // record through its tip in arrival order, so the tip genuinely IS its fold root. But it fired for
        // ANY snapshot whose cursor is absent, including a v31 node that had folded NOTHING (the field is
        // `serde(default)`, and every legacy door writes `fold_chain_tip: None` as well). Such a node
        // resumed asserting it had folded everything through its tip — a claim it could not support, made
        // silently, which is exactly the shape the no-rescue rule exists to stop.
        //
        // The claim is also unrecoverable, because the canonical fold only ever walks UP from the cursor
        // (`fold_canonical_records` descends `record_fold_depth` from the tip and folds forward). Every
        // block below a cursor that was never really reached is skipped PERMANENTLY — not re-visited, not
        // wanted, not asked for, so nothing can heal it.
        //
        // MEASURED 2026-09-04, `recorded_case_04` (`both-restart-with-blocks-still-in-flight`): the
        // restarted party holds `None` for early blocks its peer folded at low ordinals —
        // `[(0, Some(2), None), (1, Some(3), None), (2, Some(4), None), (3, Some(5), None),
        //   (4, Some(1), None), (5, Some(9), None)]` — and it reports `gap=0/1` with `ask_wanted=false`,
        // i.e. it does not even know they are missing. Ordinals 1-5 sit far below its restored cursor.
        //
        // THE DISCRIMINATOR IS THE NODE'S OWN EVIDENCE, not the file's version: the restored spine. A node
        // that folded records has leaves in `spend_frontier` (restored above); a node that folded nothing
        // has an empty one and resumes from its floor, so the fold covers the chain from the bottom. v30
        // behaviour is unchanged (those files carry a full spine); only the unsupported claim goes.
        //
        // ROOT-LAYER: the cursor is INSTALLED here. Teaching the fold to look below its cursor, or seeding
        // wants for the skipped span, would each be patching a reader of a position this line got wrong —
        // and neither could tell a genuine cursor from a fabricated one.
        // MUST-STAY-GREEN: the v27/v29/v30 persist-door resumes (real bytes, two nodes, identical), the
        // READY→READY resume pin, and every restore that carries a real cursor (unchanged: a present
        // `snap.fold_chain_tip` still wins).
        // cons: none — one count read on an already-restored field; no new state, no extra work per block.
        // ⛔ REVERTED 2026-09-04 UNDER THE WORSE-RESULT RULE — the diagnosis above stands, this remedy
        // does not. Resuming from the floor when the spine is empty broke FOUR resume pins
        // (`both_parties_resume_knowing_their_record_ordinal_top…`,
        // `a_resumed_ingester_comes_back_ready_and_follows_the_producers_next_blocks`,
        // `a_resumed_node_never_re_records_its_seed_only_tip_and_backfills_it_from_the_peer`,
        // `a_resumed_node_short_of_a_row_asks_for_the_roots_run_before_the_bytes_and_then_verifies_them`)
        // and moved no recorded case (7/3 before, 7/3 after). Those pins depend on a resumed node
        // standing AT its tip, so cursor-at-the-floor is not a drop-in for the substitution.
        //
        // WHAT THE NEXT ATTEMPT SHOULD DO INSTEAD, so this is not rediscovered: the false claim is real,
        // but the repair belongs where the skipped span becomes VISIBLE, not in the cursor's value. A
        // resumed node standing at its tip should NAME the ordinals below it that it holds no row for —
        // `sidecar_ask_from` already prefers the lowest `wanted_ordinals` entry below the cursor, so the
        // ask machinery is in place and nothing seeds it. Seed those wants at resume and the fold heals
        // through the existing page lane, with the cursor left exactly where the pins expect it.
        // ⛔ LANDED 2026-09-04 — the narrow form the note above asked for, aimed at the case that is
        // MEASURED rather than the whole substitution.
        //
        // `fold_schedule_fuzz::restarts_interleaved_with_undelivered_blocks_never_split_the_record_space`,
        // seed 1: after a restart, party 0 reports `served_seq = 3` while party 1 reports 4, on the SAME
        // tip, with the SAME ordinals filed (`[####]` on both) and the record at ordinal 3 HELD in bytes
        // on both. Party 0 was not missing anything — the substitution had set its cursor to its TIP, whose
        // own record it had never folded, so `fold_canonical_records` returned 0 at its first line
        // (`if Some(root) == self.fold_chain_tip`) forever. A node that holds every byte it needs and
        // still never folds them is not slow, it is stuck, and nothing above it can tell.
        //
        // THE CURSOR IS NOW DERIVED FROM THIS NODE'S OWN EVIDENCE when the file carries none: walk down the
        // selected chain from the tip to the first block whose record this node has ACTUALLY folded. That
        // block is the highest position it can support, which is the only honest answer.
        //
        // Two properties keep this narrow, and they are why it is not the reverted attempt:
        //   • A v30 file folded every record through its tip, so the walk stops on the FIRST block and the
        //     cursor is `tip_id` — byte-identical to the old behaviour, at zero extra cost.
        //   • A node that folded NOTHING keeps the old substitution. Resuming such a node from the floor is
        //     what broke four resume pins last time (see the note above); its unsupported claim is real but
        //     it is a different case from this one, and it is not repaired by guessing again here.
        // ⛔ C4 (derived-ordinal stage 2): A RESUME NEVER SELF-CERTIFIES ITS NUMBERING — the L4 close.
        //
        // ROOT-LAYER: this resume is where the post-restart fold AUTHORITY is PRODUCED — the cursor,
        // its stamped row, `certified_anchor` and `certified_prefix_len` (whose ordinal-space arm in
        // `folded_prefix_boundary` treats every covered row as settled prefix). Before this change the
        // walk stopped at `block_record_folded` — a watermark that counts rows ADOPTED from a peer's
        // pages — and the tail below then certified `served_seq` wholesale, so a pre-restart FORKED
        // numbering resumed as if certified and the level peer refused its rows forever (the measured
        // red class: every sidecar row refused via the local-claim arm, nothing re-anchors a level
        // pair). The walk now stops only at a block whose ordinal this node's OWN EVIDENCE says it
        // actually folded — the membership-step index (`da_macc_fwd_mem`, one entry per ordinal this
        // node folded: the discriminator the old [fold-skip] diagnostic documented), or, on a fresh
        // restore where that index died with the process, the restored spine's own top (a row equal
        // to exactly the position the restored leaves reach) — NEVER a bare adopted row's say-so.
        // The cursor stays AT the tip-walk result — cursor-at-floor is not reintroduced.
        // MEASURED: 2026-09-05 (previous implementer's diagnosis, this task's design doc) — p0 folded
        // rid 238810 at ordinal 48 while p1 folded it at ordinal 9 on the SAME selected tip, every
        // sidecar row refused; and fold_schedule_fuzz seed 1's restarted party 0 resumed served_seq 3
        // against its peer's 4 on the same tip, its cursor at a tip whose own record it never folded.
        // MUST-STAY-GREEN: the canonical_record_fold suite (incl. the resumed-from-checkpoint and
        // rewind pins), fold_schedule_fuzz, the four certify-absence pins,
        // two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal, the item9 leaf-law pin,
        // the graft/strand landing pins, a_staged_credit_rides_the_next_block_and_lands_in_the_
        // unspent_set.
        // cons: none — nothing new is persisted or retained; one count read plus one map read per
        // walked block (the walk is bounded by the chain segment above the last folded block, exactly
        // as before); no term in height, blocks or notes.
        let spine_supported =
            self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        self.fold_chain_tip = match snap.fold_chain_tip.map(crate::hash::Hash32) {
            Some(c) => Some(c),
            None if self.served_seq > 0 => {
                let mut cur = Some(tip_id);
                while let Some(b) = cur {
                    if self.relay.dag().genesis() == Some(b) {
                        break; // the fold's floor — folded by definition, the same stop as before
                    }
                    let rid = Self::da_record_id_for_block(&b, 0);
                    let actually_folded = self.da_ord_mem.get(&rid).map_or(false, |o| {
                        self.da_macc_fwd_mem.contains_key(o) || (*o > 0 && *o == spine_supported)
                    });
                    if actually_folded {
                        break; // the highest block whose record this node's own evidence supports
                    }
                    cur = self.relay.dag().get(&b).and_then(|n| n.selected_parent);
                }
                cur.or(Some(tip_id))
            }
            // ⭐ DB-402 (lane stable 2026-10-30): a checkpoint that folded NOTHING resumes folding nothing — the live node
            // held `None` there, and naming the tip would call an unfolded block the fold root. MEASURED (stable/a4.log,
            // launch tail): node 1 restarted at t = 0 s changed `fold_chain_tip` 4 B → 25 B (None → the tip).
            None => None,
        };
        self.sync_prune_floor(); // the resumed anchor is pinned before any graft can sweep it
        // The cursor resumes WITH its position (see `fold_chain_ordinal`): without the row the fold has to
        // infer where it stands, and every inference disagreed with the peer by one.
        if snap.fold_chain_ordinal > 0 {
            if let Some(c) = self.fold_chain_tip {
                let rid = Self::da_record_id_for_block(&c, 0);
                if !self.da_ord_mem.contains_key(&rid) {
                    self.da_store_ordinal(rid, snap.fold_chain_ordinal);
                }
            }
        }
        // ⛔ C4 tail: the resumed rows above are UNCERTIFIED HINTS — the restored spine is the only
        // authority this node holds, so the claim is CHECKED against it and the certified prefix is
        // capped at what the spine actually supports.
        //   • A cursor row ABOVE the spine's own top is a claim the spine cannot back — fail closed
        //     (`spine_stale`; the certified re-anchor lane settles it), never resume it as truth.
        //     A row AT or BELOW the top stays: a snapshot saved mid-batch legitimately holds a
        //     cursor below already-materialised records, and staling those honest resumes would
        //     regress the four resume pins (the reverted cursor-at-floor remedy taught exactly that).
        //   • `certified_prefix_len` = one past the restored spine's own top (the same "one past the
        //     last certified ordinal" convention the adopt path stores) — never `served_seq`'s
        //     unexamined say-so, which counted rows a peer's pages merely filed.
        // cons: none — one map read and two assignments, once per resume; nothing persisted.
        let cursor_row = match self.fold_chain_tip {
            Some(c) => self
                .da_ord_mem
                .get(&Self::da_record_id_for_block(&c, 0))
                .copied(),
            None => None,
        };
        if let Some(claimed) = cursor_row {
            if claimed > spine_supported {
                eprintln!(
                    "[uns-resume] ⛔ the resumed cursor claims position {claimed} but the restored \
                     spine supports only {spine_supported} — an unsupported claim never resumes as \
                     certified"
                );
                self.mark_spine_stale(
                    "the resumed fold cursor claims a position the restored spine does not reach — \
                     only the next certified bundle can re-anchor this node",
                );
            }
        }
        match snap.certified_anchor_row {
            // v44 (G1g-iii, lane a 2026-10-23): the triple the live process held, verbatim (Ethereum STF — a restart
            // restores state, it never re-derives it). MEASURED before v44 (g1gii-restart-census-20261023.log): the live
            // process held `None` / 0 / 0 after folding its own chain from genesis, the restarted one `Some(fold tip)` /
            // its score / spine top + 1 — a different fork floor and walk floor on the same chain. The C4 cap stays: a
            // prefix the restored spine cannot back fails closed on THIS node's certification (stale, no anchor), never
            // on chain progress. Pin: `node::pins::a_node_booted_from_the_same_files_holds_the_certified_anchor_the_live_process_held`.
            Some((anchor, score, prefix_len)) if prefix_len <= spine_supported.saturating_add(1) => {
                self.certified_anchor = anchor.map(crate::hash::Hash32);
                self.certified_anchor_score = score;
                self.certified_prefix_len = prefix_len;
            }
            Some((_, _, prefix_len)) => {
                eprintln!(
                    "[uns-resume] ⛔ the checkpoint's certified prefix {prefix_len} exceeds what the restored spine \
                     supports ({spine_supported}) — no anchor resumes as certified"
                );
                self.mark_spine_stale(
                    "the checkpoint's certified prefix exceeds the restored spine — only the next certified bundle can \
                     re-anchor this node",
                );
                self.certified_anchor = None;
                self.certified_anchor_score = 0;
                self.certified_prefix_len = 0;
            }
            None => {
                // a pre-v44 checkpoint: the derivation it was written for
                self.certified_anchor = self.fold_chain_tip;
                self.certified_anchor_score = self
                    .fold_chain_tip
                    .and_then(|c| self.relay.dag().get(&c).map(|n| n.blue_score))
                    .unwrap_or(0);
                self.certified_prefix_len = if spine_supported == 0 { 0 } else { spine_supported.saturating_add(1) };
            }
        }
        // ⛔⛔ DB-424 (2) — THE OPEN BATCH'S SLOT MARKERS COME BACK WITH THE SPINE THAT HOLDS THEIR LEAVES.
        //
        // A checkpoint saved mid-batch holds records ABOVE its cursor whose leaves are already in the restored spine (the
        // C4 note above). The resumed walk of the waiting chain block counts each such member only when C2's state 1 sees
        // it VERIFIED IN ITS SLOT — row, `da_leafstart_mem`, spine — and `da_leafstart_mem` had ONE writer, the live
        // fold's commit, so the restore left it empty: the member fell to state 3, its row was dropped and its re-fold
        // refused at the leaf law forever (the seed 0x6 T3 wedge; pin
        // `a_node_checkpointed_mid_batch_resumes_the_batch_at_its_peers_ordinals`). The marker is the leaf law itself —
        // a record at ordinal o occupies leaves (o-1)·width.. — and the restored spine is the authority that those leaves
        // are present (`spine_supported`). Only the open batch is stamped: rows strictly above the resumed cursor, at or
        // below the spine's top, held as that ordinal's unique occupant (`adopt_sidecar_row` never overwrites one) — the
        // rows this node's own fold committed after its cursor's batch. Below the cursor the walk never asks (prefix).
        // cons: none — one pass over the retained rows (the ladder-bounded set the restore just refilled), at most one
        // merge set of map inserts, once per resume; the markers were held before the restart.
        if !self.spine_stale {
            if let Some(cursor) = cursor_row {
                let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                let open: Vec<(u64, u64)> = self
                    .da_ord_rev_mem
                    .iter()
                    .filter(|(o, rid)| **o > cursor && **o <= spine_supported && self.da_ord_mem.get(*rid) == Some(*o))
                    .map(|(o, rid)| (*rid, o.saturating_sub(1).saturating_mul(width)))
                    .collect();
                for (rid, leaf_start) in open {
                    self.da_leafstart_mem.entry(rid).or_insert(leaf_start);
                }
            }
        }
        // v31: the certified spent-state accumulator resumes with the checkpoint (a v30 file carries the
        // genesis value; the first DSYNC adopt or produced block moves it, exactly as before).
        if snap.nf_unspent_acc != usdm_decider::poseidon2_compress::zero_digest() {
            self.nf_unspent_acc = snap.nf_unspent_acc;
            // DB-246: the ring is cleared with the sum it described; a resume rebuilds it from the restored span
            // (`rebuild_recent_folds_from_span`, after the carry graft).
            self.nf_recent_folds.reset();
        }
        // D-45: the letter accumulator resumes with the checkpoint (a pre-D-45 file carries zero: the
        // genesis seed, as before). Restored BEFORE the fold carry is re-grafted below, so the re-applied
        // blocks above the fold root fold on top of the persisted sum exactly as they did live, and the
        // covered score keeps a block already in the sum from folding twice.
        if snap.letter_acc != [0u8; 32] {
            self.letter_acc = snap.letter_acc;
        }
        // v31: the blocks above the fold root and the folded parents they name come back with the checkpoint;
        // re-grafted through the full ingest gates, the DAG reaches the tip and the canonical fold continues.
        // v64: the DAG blocks no other field brings back re-enter FIRST — a carried block's parent can be one of them (a DAG
        // block this node held neither folded nor unfolded: a header awaiting its record), and placed after the carry it
        // stranded that block. MEASURED (launch tail, the joiner restarted mid catch-up at 1,800 s, b3/v1.log): "[fold-carry]
        // ⛔ carried block d7616f18 could not be placed (a parent is missing)" ×2, then 64 restart-census fields CHANGED.
        // The window entries and the relink still run in `install_block_window_span` once the floor is installed.
        let shells = std::mem::take(&mut snap.dag_shells);
        self.install_dag_shells(shells);
        if !snap.fold_carry.is_empty() {
            let carry = std::mem::take(&mut snap.fold_carry);
            if fold_carry {
                self.graft_unfolded_carry(carry);
            } else {
                self.place_unfolded_carry(carry);
            }
            // DB-270: a CHECKPOINT's carry is this node's own in-flight set — A_tip (restored above) counts it — so it is
            // stamped a member under the window's persisted generation. (A DSYNC bundle's carry is NOT stamped: it is the
            // origin's, inside the adopted past the certified base already counts.) The restart arm of the span (the base
            // itself is not in the checkpoint) is DB-270 R4.
            let gen = self.block_window.base_gen();
            for b in &self.unfolded_blocks {
                self.nf_unfolded_gen.insert(b.id(), gen);
            }
        }
        self.da_top = self.da_top.max(snap.da_top);
        if snap.da_base > 0 {
            self.da_base = self.da_base.min(snap.da_base);
        }
        // ⭐⭐⭐ ARM THE RESUME RESEED WALK AS A FIRST-CLASS GATE TERM (2026-09-07, forged-cursor
        // cancellation close — the root shape, not the clamp). The v33 cursor clamp bounds a
        // corrupt or forged persisted `sidecar_cursor` to certified+1 — but bounding is an
        // OPTIMIZATION, not the soundness: with the backlog term forged to 0, only the seeder
        // below's TX_REQ_FIXED_COUNT holes were ever named, `has_wanted_records()` closed the
        // moment they healed (ALL its terms were cursor- or list-derived), and the rolling reseed
        // — the one cursor-INDEPENDENT lane that names every rowless position — became
        // UNREACHABLE. MEASURED (red pin
        // `a_forged_snapshot_cursor_must_not_cancel_the_resume_reseed`): 8 rowless certified
        // positions permanently unnamed, gate open=false, backlog 0, cursor 42. The snapshot is
        // LOCAL CACHE; state is a function of the chain — no single persisted field may silence
        // the heal.
        //
        // So: seed the reseed cursor at the retention floor and, if ANY tracked-span position is
        // rowless RIGHT NOW, arm the completion target at the resumed top. The ask gate stays open
        // until the reseed's cursor covers that top (the reseed itself disarms the target), so the
        // walk names every rowless tracked-span position exactly once regardless of the persisted
        // watermark, and the gate may close only when the walk is complete AND the range authority
        // reads zero. A holeless resume proves its span in this one scan and arms nothing — a
        // complete snapshot still resumes with the gate closed and zero backlog.
        // cons: one scan bounded by the FIXED protocol constant DA_LADDER_SPAN (the tip span, from
        // the retention floor), once per resume — f(fixed constants), never f(history). One u64 of
        // new state.
        {
            let top = self.served_seq;
            let floor = top.saturating_sub(Self::DA_LADDER_SPAN).max(1);
            let holed = (floor..top).any(|o| self.da_addr_at_ordinal(o).is_none());
            if holed {
                *self.da_want_seed_cursor.borrow_mut() = floor;
                self.da_want_seed_target.set(top);
            } else {
                *self.da_want_seed_cursor.borrow_mut() = top;
                self.da_want_seed_target.set(0);
            }
        }
        // ⛔⛔⛔ A RESUMED NODE HELD NO RECORDS AND NEVER ASKED FOR ANY. IT BLINDED EVERY WALLET ON IT.
        //
        // `da_mem`/`da_targets_mem` are RAM by design — "the DA is the ledger" means records live on the
        // NETWORK and a restarted node refetches them. Nothing asked, so a resumed node served an EMPTY
        // history while reporting the full chain height.
        //
        // MEASURED 2026-08-12, live pair, chain at height 54,000, wallet holding 47,000.00 across 4+ notes:
        //   [detect-why] ZERO candidates: bucket held 0 entr(ies) at cursor 3019 (served RECORD seq 2635)
        // The node served only the 2,635 records written since ITS OWN boot; the wallet's notes sit at record
        // 180,736. Its balance read empty, no scan could complete, every send refused. An owned note that
        // disappears because a node restarted is fund loss.
        //
        // ⛔ AND THE FIRST VERSION OF THIS WAS WRONG — kept as the reason it is written this way. It seeded
        // wants across `da_base..da_top`, which are record ADDRESSES: block-derived hashes, not a dense
        // range. It logged `record range 324..288219509009725589` and asked for 32 addresses that do not
        // exist. The dense coordinate is the ORDINAL, and `da_wanted` is exactly the by-ordinal want-set the
        // runtime already turns into a `NotesReq` every tick.
        //
        // Seed that set from ordinal 0 forward. A record already held is skipped, a returned record enters
        // only through `accept_fetched_record` (checked against a block root this node holds), and the set is
        // served TX_REQ_FIXED_COUNT at a time and drains as asks go out — so this widens what we ASK for,
        // never what we believe, and adds no unbounded state.
        //
        // cons: none — no new storage, no new request path, nothing refused; a node that already holds its
        // records seeds nothing.
        {
            let mut seeded = 0usize;
            let mut ord = 0u64;
            while ord < self.served_seq && seeded < crate::protocol::TX_REQ_FIXED_COUNT {
                if self.da_addr_at_ordinal(ord).is_none() {
                    self.da_wanted.borrow_mut().insert(ord);
                    seeded += 1;
                }
                ord = ord.saturating_add(1);
            }
            if seeded > 0 {
                // Ordinal COUNTS only — already public via /get_info; never a note, amount, key or owner.
                eprintln!(
                    "[da-resume] resumed missing records below served ordinal {} — seeded {seeded} by-ORDINAL \
                     peer want(s). Without this a restarted node serves an EMPTY history and every wallet on \
                     it loses sight of its notes.",
                    self.served_seq
                );
            }
        }
        // The anchor RELAY (`recent_root_history`) is NOT restored — it is a transient serve-cache (not persisted),
        // so it stays empty and refills FORWARD as new blocks arrive. A wallet stays spendable across the restart
        // without it: its note copath is frozen against its receipt anchor at receipt ([[project_root_history_retires_window]]),
        // and any peer serves the constant `root_history_from` broadcast for a wallet still building its copath.
        // `snap.stake_frontier` is RETIRED (2026-10-04) and not restored: the node holds no stake frontier.
        // nullifier_imt (the full O(spends) tree) is NOT restored (no-growth brick 2) — it stays empty. A resumed
        // node is a treeless VERIFIER: every re-spend is caught by the O(1) `nullifier_acc` root below via the
        // spend's mandatory carried witness (`nullifier_witnesses_gate`), no stored set consulted. A node that will
        // PRODUCE first calls `rebuild_nullifier_tree` to reconstruct its working tree from the replicated nullifier
        // stream (verified: the rebuilt root == this acc root).
        // Resume the O(1) nullifier CONSENSUS commitment (root+count) — constant-size, self-verifying; a re-spend
        // after restart is checked against THIS root (the sole double-spend authority).
        self.nf_blocks = snap.nf_blocks;
        self.nf_leaves = snap.nf_leaves;
        // SPARSE CUTOVER — RESUME the header-committed consensus accumulator (never reboot it at genesis). The
        // working tree is left cold and re-warmed on demand by `ensure_sparse_work` from the replicated stream,
        // self-verifying against this root: UNBOUNDED, no window, no age-out — every past spend stays spent.
        // ⛔ A RESTORED root that is not a canonical digest is a PRE-FORK or corrupt checkpoint (§AG);
        // the snapshot doors already refuse those, and this is the same law one layer in.
        // ⭐ RESUME THE DSOL REGISTRY. Refused rather than repaired if the parts do not describe their own
        // count: an accumulator that does not match its count answers membership questions wrongly, and a
        // wrong answer here refuses honest mints or admits unregistered ones.
        match crate::dsol::DsolRegistry::from_parts(snap.dsol_registry_count, &snap.dsol_registry_peaks) {
            Some(r) => *self.peg.dsol_tokens_mut() = r,
            None => {
                if snap.dsol_registry_count != 0 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a count of PUBLIC creations and a peak count.
                    eprintln!(
                        "[dsol] ⛔ REFUSED a checkpointed token registry whose {} peak(s) do not describe                          its count of {} — resuming EMPTY, which refuses mints rather than admitting                          unregistered ones, and the creations replay from the chain",
                        snap.dsol_registry_peaks.len(),
                        snap.dsol_registry_count
                    );
                }
            }
        }
        // ⛔ DB-321: a checkpoint written while this node could not VOUCH for its root carries ZERO (`vouched_sparse_root`):
        // its accumulator was a pivot whose tail lived in RAM only, and restoring that pivot without the tail left a warm
        // no honest stream could reach. A vouched root is complete for what the checkpoint applied, so its tail is empty.
        match (snap.sparse_acc_root != [0u8; 32])
            .then(|| crate::nf_sparse::SparseNfAcc::adopt_merkle_root(snap.sparse_acc_root))
            .flatten()
        {
            Some(a) => {
                self.sparse_acc = a;
            }
            None => self.forget_unvouched_sparse_root(),
        }
        self.set_sparse_work(None);
        // DB-226: a restored root is NOT known complete — a snapshot written while this node was viewless holds
        // the frozen subset, and the flag is not persisted. The restored node has no view, so the first block it
        // applies would set this anyway; setting it here closes the gap before that block. It clears at the
        // next certified adopt.
        self.sparse_acc_stale = true;
        self.nf_cover_conf_acc = snap.nf_cover_conf_acc;
        self.join = snap.join.clone();
        self.join_install_history();
        self.load_frozen_join_bundles();
        // A-F31: the token registry rides the snapshot beside the ledger (`dsol_registry_*`, restored above), so it is kept
        // across the ledger's own restore: the ledger's serialized form does not carry it.
        let tokens = std::mem::take(self.peg.dsol_tokens_mut());
        self.peg = snap.peg;
        *self.peg.dsol_tokens_mut() = tokens;
        // §19.4: the frontier at the newest epoch anchor is a cache of the rewind ring restored above — refilled from it
        // here, so a cash-out claim built right after a restart proves at once (`Node::refill_epoch_anchor_frontier`)
        self.refill_epoch_anchor_frontier();
        // IonSwap pools: this node's own cache of the contract tree and the pool rows resumes only if it is the tree
        // under the ledger root just restored (checked whole, `IonCache::install`); otherwise the node holds none
        if let Some(file) = snap.ion_cache.take() {
            let _ = self.ion_cache.install_file(self.peg.contract_state_root(), file);
        }
        self.l2_state_root = snap.l2_state_root;
        // Resume the GOVERNANCE-ACTIVE consensus params (block spacing / VDF heartbeat / DAG width / economic
        // bands): a governance retune enacted before the restart persists, instead of reverting to the code
        // default. snap.params carries the same genesis identity (the parity guard above already matched), so
        // this never changes the node's genesis / chain_id — it only restores the tuned values.
        // ⛔⛔⛔ THE LAST DOOR A LOCALLY-RETUNED RULE COULD COME BACK THROUGH — SO IT SAYS SO.
        //
        // Governance can no longer retune live params (`evaluate_param_enactment` is read-only; a rule
        // change must be carried by a block — see `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`). But a
        // snapshot written by an OLDER binary could carry values that WERE retuned locally, and adopting
        // them silently would reinstate the rules divergence across a restart: this node would run rules
        // no block ever carried, and every gate on it would agree with itself against that yardstick.
        //
        // The comparison is against the network's code defaults, which is what the chain says today
        // because no param object exists yet. Adopt either way — refusing to boot would be a chain halt,
        // and the pillars forbid one — but NEVER silently.
        {
            let defaults = crate::params::ChainParams::default();
            if snap.params.dag_width != defaults.dag_width
                || snap.params.mint_ratio_bps != defaults.mint_ratio_bps
                || snap.params.stake_lock_blocks != defaults.stake_lock_blocks
                || snap.params.withdraw_fee_min_bps != defaults.withdraw_fee_min_bps
                || snap.params.withdraw_fee_max_bps != defaults.withdraw_fee_max_bps
            {
                // DIGITAL-CASH-PRIVACY-REVIEWED: public consensus PARAMETERS only — never a tag, amount,
                // key or owner.
                eprintln!(
                    "[params-resume] ⛔ this snapshot carries CONSENSUS PARAMETERS that differ from the \
                     network defaults (dag_width {} vs {}, mint_ratio_bps {} vs {}, stake_lock_blocks {} \
                     vs {}, withdraw band {}..{} vs {}..{}). No block has ever carried a parameter change, \
                     so a difference here can only have come from a LOCAL retune by an older binary — \
                     this node may be running rules its peers do not. Adopting them (refusing to boot \
                     would be a chain halt), and saying so.",
                    snap.params.dag_width, defaults.dag_width,
                    snap.params.mint_ratio_bps, defaults.mint_ratio_bps,
                    snap.params.stake_lock_blocks, defaults.stake_lock_blocks,
                    snap.params.withdraw_fee_min_bps, snap.params.withdraw_fee_max_bps,
                    defaults.withdraw_fee_min_bps, defaults.withdraw_fee_max_bps,
                );
            }
        }
        self.set_params(snap.params);
        // ⛔⛔⛔ THE LAST leaves/256 DERIVATION OF `served_seq` IS DELETED. BOTH ITS PREMISES ARE FALSE.
        //
        // It read: "every record appended EXACTLY 256 leaves, so served_seq = leaf_count / 256 — no
        // separately-persisted field". Neither holds any more. The block x256 cover fill is RETIRED, so a
        // record appends its REAL note count; and `served_seq` IS persisted now (schema v23), restored a few
        // lines above. Running after that restore, this line clobbered the true value on every resume.
        //
        // MEASURED 2026-08-12, live node, across a restart:
        //   served_seq before 4,212  ->  after 148
        // while `[da-resume] resumed missing records below served ordinal 4212` proves the snapshot had been
        // read correctly. The node then believed it held almost nothing, served an empty history, and every
        // wallet on it went blind — which is how a note becomes unspendable because a node restarted.
        //
        // The restored value stands. `served_seq` counts RECORDS WRITTEN and has exactly one other writer:
        // the record path, which increments it. No derivation, no retired constant, one writer.
        // cons: none — the counter now means the one thing its name says, at any chain height.
        // v47 (G1d): the synced state EXACTLY AS HELD — `None` on a node that adopted nothing. Until v47 this built a fresh
        // `SyncState` at every resume (restart census: 4 B → ~18 KB on both nodes), so a resumed node reported a jump it never
        // made; its production readers are the diagnostics (`spine_state`, `/status` `jumped`).
        self.synced = snap.synced.take();
        let held_ladder = std::mem::take(&mut snap.ladder_spans);
        let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        let span = snap.body_catchup.as_ref().filter(|c| c.roots_run_spine_target.count() > 0).map(|c| {
            let closed = c.roots_run_closed_target == c.roots_run_spine_target.root() || c.roots_run_cursor.same_state(&c.roots_run_spine_target);
            // an OPEN span's roots are judged up to its cursor (the fold its partial runs reached), a closed one's to its target
            let end = if closed { Some(c.roots_run_spine_target.clone()) } else { (c.roots_run_cursor.count() > c.roots_run_spine_before.count()).then(|| c.roots_run_cursor.clone()) };
            (c.roots_run_spine_before.count() / rec + 1, c.roots_run_spine_target.count() / rec, end.map(|e| (c.roots_run_spine_before.clone(), e)))
        });
        self.restore_ladder_spans(held_ladder, span);
        if let Some(c) = snap.body_catchup.take() {
            self.restore_body_catchup(c);
        }
        true
    }

    /// v52 (G2g-r2d) — re-install the DSYNC body catch-up a checkpoint carried. Until v52 a restart dropped it (joiner restart
    /// census: note_body_target, note_body_acc_*, roots_run_closed_target/spine_*/cursor all CHANGED), so a joiner that
    /// restarted mid catch-up forgot the certified span it still owed. The two ends are installed as held — the same trust as
    /// the v47 `synced` they came from. Shape-checked (`before ≤ cursor ≤ target` in leaves, whole records); a malformed
    /// carry installs nothing. An OPEN span restarts its cursor at `before` through `open_roots_run_span`: its partial run
    /// blobs were RAM-only, so its runs are re-asked from the origin and folded against the certified target again — the
    /// refused-run arm's own reset. A CLOSED span is installed closed (its roots are re-fetched on demand via `wanted_ladder`).
    /// cons: none in RAM (the same fields the live node holds); ≈ 3 × 2 KB frontiers + 104 B per checkpoint while set.
    /// v52 (G2g-r2d) — re-install the ladder span blobs a checkpoint carried. The roots a DSYNC joiner's roots-run door wrote
    /// into its LIVE (unsealed) span were RAM-only: a restart lost them (joiner restart census: da_ladder_mem 32,500 B → 2 B),
    /// and the restored closed span could then never re-ask them. NEW-DOOR CHECKLIST (a restore path, own disk): (1) no PoW —
    /// roots, not blocks; (2) every non-zero slot is re-judged by the check that admitted it live: a whole blob outside the
    /// span through `adopt_ladder_span` itself (rung to rung); the roots of the carried CLOSED roots-run span (`closed`:
    /// its spine before → target) must cover its ordinals contiguously and refold `before` onto `target` exactly — the
    /// roots-run door's closing comparison; any other run of non-zero slots must fold from the node's own accumulator at
    /// its first ordinal − 1 onto its own accumulator at its last. A non-canonical slot, an unknown rung or a fold that lands
    /// elsewhere refuses the WHOLE blob; an OPEN span's slots are provisional (the refused-run arm removes them whole): a blob
    /// holding them installs only when they refold the span's `before` onto its carried cursor exactly (v64), still provisional; (3) creates no value — roots only verify records; (4) a span index already held is
    /// skipped; (5) work ≤ one Poseidon2 step per slot, blobs bounded by the release keep set at save; (6) parity with
    /// `adopt_ladder_span` and `accept_fetched_root_run`: the same decoder, folds and comparisons, nothing weaker.
    /// cons: ≤ 128 KB per held span per checkpoint (normally the one live span), never f(height).
    pub(super) fn restore_ladder_spans(
        &mut self,
        held: Vec<(u64, Vec<u8>, bool)>,
        span: Option<(u64, u64, Option<(crate::spend_frontier::PoseidonSpendFrontier, crate::spend_frontier::PoseidonSpendFrontier)>)>,
    ) -> usize {
        let slot = Self::LADDER_SLOT_BYTES;
        let full = (Self::DA_LADDER_SPAN as usize) * slot;
        let zero = usdm_decider::poseidon2_compress::zero_digest();
        let (lo, hi) = span.as_ref().map_or((1, 0), |(l, h, _)| (*l, *h));
        let mut span_roots: std::collections::BTreeMap<u64, crate::spend_frontier::Digest4> = std::collections::BTreeMap::new();
        let mut staged: Vec<(u64, Vec<u8>, bool)> = Vec::new();
        let mut installed = 0usize;
        'span: for (sp, blob, adopted) in held {
            if blob.is_empty() || blob.len() % slot != 0 || blob.len() > full || self.da_ladder_mem.contains_key(&sp) {
                continue;
            }
            let start = sp * Self::DA_LADDER_SPAN;
            let mut decoded = Vec::with_capacity(blob.len() / slot);
            for (i, chunk) in blob.chunks_exact(slot).enumerate() {
                let Some(root) = Self::ladder_slot_decode(chunk) else {
                    eprintln!("[persist] ⛔ carried ladder span {sp}: slot {i} is not a canonical digest — not installed");
                    continue 'span;
                };
                decoded.push(root);
            }
            let in_span = |o: u64| o >= lo && o <= hi;
            let touches_span = decoded.iter().enumerate().any(|(i, r)| *r != zero && in_span(start + i as u64));
            if blob.len() == full && !touches_span && self.adopt_ladder_span(sp, &blob) {
                if !adopted {
                    self.da_ladder_adopted.remove(&sp);
                }
                installed += 1;
                continue;
            }
            let mut acc: Option<crate::spend_frontier::Digest4> = None; // Some while inside a run outside the span
            let mut pending: Vec<(u64, crate::spend_frontier::Digest4)> = Vec::new();
            for (i, root) in decoded.iter().enumerate() {
                let o = start + i as u64;
                if *root == zero || in_span(o) {
                    if let Some(a) = acc.take() {
                        match self.da_membership_acc_at_ordinal(o - 1) {
                            Some(held) if held == a => {}
                            // ⭐ A RUN THAT MEETS THE SPAN WHERE THIS NODE HOLDS NO ACCUMULATOR FOLDS ON THROUGH IT (lane stable
                            // 2026-11-01). The span's roots continue the SAME membership chain, so the run is judged at the first
                            // ordinal this node does hold — a DSYNC joiner holds the accumulator just below its fold base
                            // (`da_macc_first`) and none below it. MEASURED (stable/c9.log, the launch tail's reinstalled n2
                            // restart): "a run ending at ordinal 78 does not land on this node's accumulator" — no row at 78 to
                            // compare with, so the joiner's carried span 0 (104,238 B) was dropped at every restart with its
                            // roots-run cursor and tag rows. Sound as before: landing on a held accumulator further on still
                            // needs every root in between to be the chain's (a Poseidon2 collision otherwise), and the span's
                            // own closing check (`span_ok`) still decides whether a blob touching it installs.
                            None if in_span(o) && *root != zero => {
                                acc = Some(usdm_decider::note_membership_air::note_membership_step_new_acc(a, *root));
                                pending.push((o, *root));
                                continue;
                            }
                            _ => {
                                eprintln!("[persist] ⛔ carried ladder span {sp}: a run ending at ordinal {} does not land on this node's accumulator — not installed", o - 1);
                                continue 'span;
                            }
                        }
                    }
                    if *root != zero {
                        pending.push((o, *root));
                    }
                    continue;
                }
                let from = match acc {
                    Some(a) => a,
                    None if o == 0 => zero,
                    None => match self.da_membership_acc_at_ordinal(o - 1) {
                        Some(a) => a,
                        None => {
                            eprintln!("[persist] ⛔ carried ladder span {sp}: no accumulator at ordinal {} to anchor the run at {o} — not installed", o - 1);
                            continue 'span;
                        }
                    },
                };
                acc = Some(usdm_decider::note_membership_air::note_membership_step_new_acc(from, *root));
            }
            if let Some(a) = acc {
                let last = start + decoded.len() as u64 - 1;
                if self.da_membership_acc_at_ordinal(last) != Some(a) {
                    let first_real = decoded.iter().position(|r| *r != zero).map(|i| start + i as u64);
                    eprintln!(
                        "[persist] ⛔ carried ladder span {sp}: the run ending at ordinal {last} does not land on this node's accumulator \
                         (held there: {}; span {lo}..={hi}; first non-zero slot {first_real:?}; macc first {:?}) — not installed",
                        self.da_membership_acc_at_ordinal(last).is_some(),
                        self.da_macc_first.map(|(o, _)| o)
                    );
                    continue;
                }
            }
            if decoded.iter().all(|r| *r == zero) {
                continue;
            }
            span_roots.extend(pending);
            staged.push((sp, blob, adopted));
        }
        // The carried span's roots, judged together exactly as their runs were: contiguous from `lo` and refolding the spine
        // before onto `end` — a CLOSED span's certified target (its closing comparison), an OPEN span's cursor (the fold its
        // partial runs reached, `accept_fetched_root_run`'s provisional arm).
        // ⛔ AN OPEN SPAN'S ROOTS COME BACK PROVISIONAL, AS THE LIVE PROCESS HELD THEM (lane stable 2026-11-02). They were dropped
        // and the run re-opened at its origin: MEASURED (launch tail, the reinstalled joiner restarted mid roots-run at 1,800 s)
        // restart census `da_ladder_mem` 111,665 → 2 B and `roots_run_cursor` moved back — the whole run re-asked. Sound as live:
        // the roots install only when they refold the carried `before` onto the carried cursor exactly (one wrong, missing or
        // reordered root lands elsewhere), they stay invisible to root readers while the span is open, and the span's closure
        // still judges every one of them against the certified target (a refused closure removes the span blobs whole).
        // cons: none — the bytes the checkpoint already carried; one Poseidon2 frontier append per carried root at boot.
        let span_ok = match &span {
            Some((_, _, Some((before, end)))) if !span_roots.is_empty() => {
                let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                let mut f = before.clone();
                let mut next = lo;
                let mut ok = true;
                for (o, r) in span_roots.iter() {
                    if *o != next || !f.append_subtree(Self::RECORD_SUBTREE_LEVEL, *r) {
                        ok = false;
                        break;
                    }
                    next += 1;
                }
                ok && next == end.count() / rec + 1 && next <= hi + 1 && f.same_state(end)
            }
            _ => false,
        };
        if !span_roots.is_empty() && !span_ok {
            eprintln!(
                "[persist] ⛔ the carried roots of the roots-run span do not reproduce its certified spine (or the span is open) — \
                 {} root(s) not installed; the span re-opens and its run is re-asked",
                span_roots.len()
            );
        }
        for (sp, blob, adopted) in staged {
            let touches_span = blob
                .chunks_exact(slot)
                .enumerate()
                .any(|(i, c)| in_range(sp * Self::DA_LADDER_SPAN + i as u64, lo, hi) && Self::ladder_slot_decode(c) != Some(zero));
            if touches_span && !span_ok {
                continue;
            }
            self.da_ladder_mem.insert(sp, blob);
            if adopted {
                self.da_ladder_adopted.insert(sp);
            }
            installed += 1;
        }
        fn in_range(o: u64, lo: u64, hi: u64) -> bool {
            o >= lo && o <= hi
        }
        installed
    }

    pub(super) fn restore_body_catchup(&mut self, c: crate::persist::BodyCatchupCarry) -> bool {
        let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        let (b, t, k) = (c.roots_run_spine_before.count(), c.roots_run_spine_target.count(), c.roots_run_cursor.count());
        if b > k || k > t || b % rec != 0 || k % rec != 0 || t % rec != 0 {
            eprintln!("[persist] ⛔ the carried body catch-up is malformed (leaf counts {b}/{k}/{t}) — nothing installed");
            return false;
        }
        self.note_body_target = c.note_body_target;
        self.note_body_acc_before = c.note_body_acc_before;
        self.note_body_acc_target = c.note_body_acc_target;
        if t == 0 {
            return true;
        }
        let closed = c.roots_run_closed_target == c.roots_run_spine_target.root() || c.roots_run_cursor.same_state(&c.roots_run_spine_target);
        // A closed span's roots must be derivable after the restore (its blob re-verified by `restore_ladder_spans`), else
        // nothing could re-open it (`before` would be its own target) — it re-opens at its origin instead.
        // The span's roots live in the ladder (the derive path answers for ordinals this node never held, so it proves nothing
        // here). A closed span longer than the held ladder spans re-asks its run once (cons: 32 B per record of the span).
        let roots_held = t / rec <= b / rec || self.ladder_root_if_held(t / rec).is_some(); // records live at ordinals 1..=count
        if closed && roots_held {
            self.roots_run_spine_before = c.roots_run_spine_before;
            self.roots_run_spine_target = c.roots_run_spine_target;
            self.roots_run_cursor = c.roots_run_cursor;
            self.roots_run_closed_target = c.roots_run_closed_target;
        } else {
            // Re-opened: the carried close marker must not name this span's target (that alone reads as closed).
            self.roots_run_closed_target = if c.roots_run_closed_target == c.roots_run_spine_target.root() {
                usdm_decider::poseidon2_compress::zero_digest()
            } else {
                c.roots_run_closed_target
            };
            self.open_roots_run_span(c.roots_run_spine_before.clone(), c.roots_run_spine_target);
            // An OPEN span whose partial runs' roots came back (`restore_ladder_spans` refolded them onto this cursor) resumes
            // at its cursor with their windows staged again, exactly as the live runs left it; else it restarts at `before`.
            if !closed && k > b {
                let roots: Option<Vec<crate::spend_frontier::Digest4>> = (b / rec + 1..=k / rec).map(|o| self.ladder_root_if_held(o)).collect();
                if let Some(roots) = roots {
                    let mut f = c.roots_run_spine_before.clone();
                    if roots.iter().all(|r| f.append_subtree(Self::RECORD_SUBTREE_LEVEL, *r)) && f.same_state(&c.roots_run_cursor) {
                        self.stage_root_run_windows(&c.roots_run_spine_before, &roots);
                        self.roots_run_cursor = c.roots_run_cursor;
                    }
                }
            }
        }
        true
    }

    /// Persist the current checkpoint if persistence is enabled. Serializes on-thread (cheap) then writes on a
    /// DETACHED thread so disk IO never blocks block production or the RPC (FAST/liveness pillar — a save failure
    /// is logged, never fatal). Called at each block-commit choke point.
    /// SYNCHRONOUS save for the SHUTDOWN path: build the snapshot and write it IN-LINE, bypassing the
    /// coalescing skip. MEASURED 2026-08-13 (the roll-survival acceptance run): a change note minted ~40s
    /// before a clean kill was ABSENT from the restored snapshot — `autosave`'s block-commit cadence plus
    /// its in-flight coalescing leaves a window where the last blocks' records die with the process, which
    /// is exactly the five-times-measured roll-loss class. A TERM-time blocking save closes the window for
    /// every clean shutdown. cons: shutdown blocks for one serialize+write (~ms at supply scale); a hard
    /// kill (-9/power loss) still falls back to the last autosave — mesh replication covers that case.
    /// ⭐⭐⭐ DB-397 fix A — write the view's spent tags beside the snapshot (see `persist::save_nf_view`).
    pub(crate) fn persist_nf_view(&self, snapshot: &std::path::PathBuf) {
        if let Some(view) = self.sparse_work.as_ref() {
            if crate::persist::save_nf_view(snapshot, &view.leaves_sorted()).is_err() {
                eprintln!("[persist] ⛔ the nullifier view cache was not written beside the snapshot");
            }
        }
        self.persist_da_records(snapshot);
        self.persist_mined_tx_nfs(snapshot); // G1: the graft's per-tx nullifier record, chain-bound on resume
        self.persist_window_anchor(snapshot);
        self.persist_window_index(snapshot);
        self.persist_canon(snapshot);
    }

    /// A-F114 phase 2: the canonical tag chain and its recent window beside the snapshot, in the same capture.
    pub(crate) fn persist_canon(&self, snapshot: &std::path::PathBuf) {
        if !crate::canon_chain::canon_live() {
            return; // off until the network upgrade: nothing written on today's chain
        }
        // W8: never a ring for a snapshot the rollback rule refused (the weight `export_snapshot` writes: the selected tip's)
        // O1-INFINITY-REVIEWED: one read of the in-memory watermark; the ring written (or not) is the same one ring file.
        let weight = self.selected_tip().and_then(|t| self.relay.dag().get(&t)).map(|n| (n.blue_score, n.selected_chain_len));
        if weight.is_some_and(|(b, h)| crate::persist::save_would_be_refused(snapshot, b, h)) {
            eprintln!("[persist] W8: the snapshot was refused as a rollback — the canonical ring is not written past it either");
            return;
        }
        // A-F114 U5: the same ring file every checkpoint writes (the slots since the last write, then the head)
        if let Some((head, slots, saved, epoch, top)) = self.capture_canon_ring() {
            match crate::persist::save_canon_ring(snapshot, &head, &slots) {
                Ok(()) => saved.landed(epoch, top), // A-F139: never undoes a rewind that landed during the write
                Err(_) => eprintln!("[persist] ⛔ the canonical chain was not written beside the snapshot"),
            }
        }
    }

    /// A-F114 phase 2: resume the canonical tag chain and its window from their sidecar.
    pub(crate) fn restore_canon(&mut self, snapshot: &std::path::PathBuf) {
        if !crate::canon_chain::canon_live() {
            return;
        }
        if self.restore_canon_ring(snapshot) {
            return; // A-F114 U5: the ring file every checkpoint writes
        }
        match crate::persist::load_canon(snapshot) {
            Some((_, _, _, _, _, Some(fill), _)) => {
                // A-F114 U2: the pull was under way — it resumes from the vouched state it was pulling toward
                self.adopt_certified_canon(fill);
                eprintln!("[resume] canonical tag chain: a window pull to record {} resumes", fill.index);
            }
            Some((index, c, recent, missing, (decoy_seq, bounty_seq, theft_seq), None, rewind)) => {
                self.canon_rewind = rewind.into_iter().take(Self::REWIND_RETAIN).collect();
                self.canon_theft_seq = theft_seq;
                self.canon_index = index;
                self.canon_decoy_seq = decoy_seq;
                self.canon_bounty_seq = bounty_seq;
                self.canon_c = c;
                self.canon_recent = crate::canon_chain::CanonRecent::default();
                for (i, e, tags, leaves, score) in recent {
                    self.canon_recent.push(i, e, std::sync::Arc::new(tags), std::sync::Arc::new(leaves), score);
                }
                self.canon_missing = missing;
                // DIGITAL-CASH-PRIVACY-REVIEWED: counts and the chain's own record index only.
                eprintln!("[resume] canonical tag chain at record index {index} ({} recent records, {missing} missing)", self.canon_recent.len());
            }
            None => eprintln!("[resume] canonical tag chain: no sidecar — it starts at the upgrade height (a header commitment adopts it later)"),
        }
    }

    pub(crate) fn persist_mined_tx_nfs(&self, snapshot: &std::path::PathBuf) {
        if crate::persist::save_mined_tx_nfs(snapshot, &self.mined_tx_nfs_rows_to_persist()).is_err() {
            eprintln!("[persist] ⛔ the mined-tx nullifier cache was not written beside the snapshot");
        }
    }

    /// G1 — on resume, re-install the cached per-tx nullifier rows through the chain's bind (`persist::save_mined_tx_nfs`):
    /// a row installs only when a block the DAG holds names its tx and that block is held WHOLE with every cached tag in
    /// its lane; a row no held block names, a row its block's lane does not carry, and a row whose naming blocks are all
    /// header shells are dropped. Returns (rows read, rows installed).
    pub(crate) fn restore_mined_tx_nfs(&mut self, snapshot: &std::path::PathBuf) -> (usize, usize) {
        let Some(rows) = crate::persist::load_mined_tx_nfs(snapshot) else { return (0, 0) };
        let total = rows.len();
        let (mut installed, mut unnamed, mut shells, mut refused) = (0usize, 0usize, 0usize, 0usize);
        for (txb, nfs) in rows {
            let tx_id = Hash32(txb);
            let named: Vec<crate::block::BlockId> = {
                let dag = self.relay.dag();
                dag.block_ids().into_iter().filter(|id| dag.get(id).is_some_and(|n| n.tx_ids.contains(&tx_id))).collect()
            };
            if named.is_empty() {
                unnamed += 1;
                continue;
            }
            // the lane of a block held whole: every cached tag must be in it (a shell has no lane and verifies nothing)
            let lanes: Vec<&[[u8; 32]]> = self
                .unfolded_blocks
                .iter()
                .filter(|b| named.contains(&b.id()) && !b.nullifier_proof.padded_tags.is_empty())
                .map(|b| b.nullifier_proof.padded_tags.as_slice())
                .collect();
            if lanes.is_empty() {
                shells += 1;
                continue;
            }
            if nfs.is_empty() || !lanes.iter().any(|lane| nfs.iter().all(|nf| lane.contains(nf))) {
                refused += 1;
                continue;
            }
            self.mined_tx_nfs.entry(tx_id).or_insert(nfs);
            installed += 1;
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts over this node's own cached rows; no tag, tx id or block.
        eprintln!(
            "[persist] mined-tx nullifier cache: {total} cached row(s), {installed} RESUMED against the lane of the block that names \
             them, {unnamed} named by no held block, {shells} named only by header shells, {refused} not in their block's lane"
        );
        (total, installed)
    }

    /// T1.7 — the window-index files a fold or rewind changed since the last checkpoint (see `persist::save_window_files`).
    pub(crate) fn persist_window_index(&self, snapshot: &std::path::PathBuf) {
        let failed = crate::persist::save_window_files(snapshot, &self.window_index.take_dirty_files());
        if !failed.is_empty() {
            eprintln!("[persist] ⛔ {} window-index file(s) not written beside the snapshot; the next checkpoint retries", failed.len());
            crate::window_index::WindowIndex::return_files(&self.window_index.dirty_handle(), failed);
        }
    }

    /// ⭐ T1.7 — RESUME THE WINDOW INDEX from its files beside the snapshot, keeping ONLY the windows bound by hashes to the
    /// restored spine (`WindowIndex::bound_to`): a stale, foreign or tampered file contributes nothing that is not the
    /// chain's. Files whose bound content differs from what is on disk are rewritten at the next checkpoint. Returns
    /// (windows read, windows kept). Runs before `rebuild_windows_from_records`, which merges the replayed tail on top.
    pub(crate) fn restore_window_index(&mut self, snapshot: &std::path::PathBuf) -> (usize, usize) {
        let t0 = std::time::Instant::now();
        let mut index = crate::persist::load_window_index(snapshot);
        index.forget_changes(); // read from its files: nothing differs from them yet
        let (read, kept) = index.retain_bound_to(&self.spend_frontier); // DB-418: the one binding step (resume + adopt)
        self.window_index = index;
        eprintln!(
            "[resume] window index: {kept} of {read} cached window(s) bound to the restored spine, in {} ms",
            t0.elapsed().as_millis()
        ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts only.
        (read, kept)
    }

    /// The window anchor, written beside the snapshot (see `rebuild_windows_from_records`).
    pub(crate) fn persist_window_anchor(&self, snapshot: &std::path::PathBuf) {
        if let Some((ordinal, peaks)) = self.window_anchor() {
            if crate::persist::save_window_anchor(snapshot, ordinal, &peaks).is_err() {
                eprintln!("[persist] ⛔ the window anchor was not written beside the snapshot");
            }
        }
    }

    pub(crate) fn persist_da_records(&self, snapshot: &std::path::PathBuf) {
        let rows = self.committed_real_records();
        if crate::persist::save_da_records(snapshot, &rows).is_err() {
            eprintln!("[persist] ⛔ the real-note record cache was not written beside the snapshot");
        }
    }

    pub(crate) fn restore_da_records(&mut self, snapshot: &std::path::PathBuf) -> usize {
        let Some(rows) = crate::persist::load_da_records(snapshot) else { return 0 };
        let total = rows.len();
        let mut installed = 0usize;
        let mut refused = 0usize;
        let mut held = 0usize;
        for (seq, idb, reals, key) in rows {
            let id = crate::hash::Hash32(idb);
            let Some(root) = self.relay.dag().get(&id).map(|n| n.header.output_notes_root) else {
                refused += 1;
                continue; // the DAG names no such block — not the chain's record
            };
            // "held" means the row already holds THESE bytes (its notes root is the block's). MEASURED 2026-10-05 21:26
            // (gate12 step 3): the snapshot restore regenerates a placeholder row for every block before the cache is read,
            // so every cached record read "already held" (9 of 9) and no real note was ever re-installed — a placeholder
            // row is replaced, a row that already carries the block's bytes is left alone.
            if self.da_load(seq).is_some_and(|r| !r.is_empty() && crate::block::da_notes_root_of(&r.concat()) == root) {
                held += 1;
                continue;
            }
            let flat: Vec<u8> = reals.iter().flatten().copied().collect();
            if crate::block::da_notes_root_of(&flat) != root {
                refused += 1;
                continue; // not the chain's bytes for this block — refused, the heal lane fetches the body
            }
            self.da_store(seq, &reals, key);
            if let Some(row) = self.da_mem.get_mut(&seq) {
                row.2 = true;
            }
            installed += 1;
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts over this node's own cached records; no note, tag, amount or owner.
        eprintln!("[persist] real-note record cache: {total} cached, {installed} RESUMED against their block roots, {refused} refused, {held} already held");
        installed
    }

    /// ⭐⭐⭐ DB-397 fix A — on resume, re-insert the cached tags through the TRUSTLESS rebuild: installed only when the
    /// rebuilt root equals the resumed O(1) acc root (chain-bound, C1); otherwise ignored and the peer warm runs as before.
    pub(crate) fn restore_nf_view(&mut self, snapshot: &std::path::PathBuf) -> bool {
        // ⭐ A-F114 U1 — under the constant chain this whole path returns before any file is opened: no spent set is held.
        // O1-INFINITY-REVIEWED: this line REMOVES a read — under the switch the boot reads nothing here and holds nothing (zero bytes at any height).
        if crate::canon_chain::canon_live() {
            return false;
        }
        if self.sparse_work.is_some() {
            return false;
        }
        let Some(tags) = crate::persist::load_nf_view(snapshot) else { return false };
        // ⭐ PRIVATE SHARDING §2.4: every node resumes from the band: its cached tags come back shard by shard, each only if it folds to its
        // entry, and `nf_share_tick` fetches what is missing. Never decided by who this node knows yet: at boot it knows nobody, and
        // deciding from that once threw away every cached tag (MEASURED 2026-11-06, two real nodes). The band door is the authority,
        // so a stale cache costs a fetch and never installs a wrong set.
        if !self.band_door.is_stale() {
            let mut view = crate::nf_sparse::RefSparseNf::from_band(self.band_door.band());
            let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
            // ⛔⛔ A-F101 (lane speed5, 2026-11-18, docs/LIVE-BAND-STALL-DEEP-AUDIT-20261118.md L1) — THE CACHE IS CARRIED UP TO THE BAND
            // BEFORE ITS SHARDS ARE CHECKED. The view advances step by step on its own, so the tags a checkpoint captured can stand
            // a few band steps behind the door the same checkpoint restores; every shard spent into between the two then fails
            // `add_shard`'s fold check and was dropped. A spent set only grows, so the tags the journal's steps admitted (all
            // that lie between the cache and the door, within the journal's reach) are added first; each shard is still held only
            // if it folds to its band entry, exactly as before. MEASURED (live testnet origin, 2026-11-18 16:55): "spent-set view
            // cache: RESUMED at the band root: 97 shard(s) held from 525518 cached tag(s)" — the node came back partial, its band
            // worker then sat "waiting on holders for the pointer step's copaths" (no peer holds a view), the band stopped at step
            // 5,428, and the fold, the join bundle (5,436 against a tip of 8,866) and finality (5,445) all stopped behind it.
            // AI RESISTANT: (a) — `add_shard` keeps a shard only if its tags fold to the band entry every node agrees on; a tag
            //   added here that the chain did not spend makes its shard fail, never pass.
            // SCALE: the journal's reach (lag_cap steps × 256 tags) added to a set, once per resume; nothing grows.
            // cons: one pass over the journal's admitted tags (≤ ~16 k) per resume.
            let mut tags = tags;
            {
                let mut have: std::collections::HashSet<[u8; 32]> = tags.iter().copied().collect();
                let before = tags.len();
                for t in self.band_door.journal_admitted() {
                    if have.insert(*t) {
                        tags.push(*t);
                    }
                }
                // DIGITAL-CASH-PRIVACY-REVIEWED: counts only; no tag, root, amount or owner.
                eprintln!("[persist] spent-set view cache: {} tag(s) cached, {} more carried from the band journal", before, tags.len() - before);
            }
            let mut by_shard: std::collections::BTreeMap<u32, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
            for t in &tags {
                by_shard.entry(crate::nf_sparse::nf_shard(t, bits)).or_default().push(*t);
            }
            for s in 0..1u32 << bits {
                let _ = view.add_shard(s, by_shard.get(&s).map_or(&[], Vec::as_slice));
            }
            // A-F101 L6–L10 (docs/LIVE-BAND-STALL-DEEP-AUDIT-20261118.md): rebuilding a shard the cache lacks from the held blocks was
            // MEASURED to fold 0 of 256 band entries on the live origin's files — the fold's DB-367 leave-outs are not recorded in the
            // blocks — so a missing shard is fetched from a holder (`nf_share_tick`), and every node without a budget holds every
            // shard (`nf_wanted_shards`), so a holder exists while any such node runs.
            // The view stands on the band's root, so the accumulator follows the band, through the one function that moves it.
            self.view_follow_band_root();
            self.sparse_acc_stale = false;
            self.pivot_span = Vec::new();
            let held = view.owned_shards().len();
            self.set_sparse_work(Some(view));
            eprintln!("[persist] spent-set view cache: RESUMED at the band root: {held} shard(s) held from {} cached tag(s)", tags.len());
            return true;
        }
        let ok = self.rebuild_nullifier_tree(&tags);
        // ⛔ MEASURED LIVE 2026-10-05 20:05 (both nodes, every /get_nf_copath): the snapshot restore marks the accumulator
        // STALE (`sparse_acc_stale = true`: the resumed root is unvouched until a view stands at the band root), and the
        // resumed view above installed without vouching for it — so `authority_verdict` downgraded EVERY unspent verdict
        // to Unprovable, every wallet read its notes "pending verification", and the chain had no movable funds. The
        // peer-warm install (`install_healed_pivot`) vouches only when the installed tree stands AT THE BAND ROOT; the
        // resume does exactly that, or it keeps nothing (a view not at the band root is one no copath should come from).
        if ok {
            let band_now = crate::spend_frontier::leaf_to_cm_bytes(self.band_door.band_root());
            let at_band = self.sparse_work.as_ref().is_some_and(|t| t.root_bytes() == band_now);
            if at_band {
                self.sparse_acc_stale = false;
                self.pivot_span = Vec::new();
            } else {
                self.set_sparse_work(None);
                eprintln!(
                    "[persist] nullifier view cache: rebuilt to the resumed acc root but NOT at the band root — not installed; \
                     the peer warm brings the view to the band"
                );
                return false;
            }
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a verdict and a count over this node's own cached set; no tag, root or owner.
        eprintln!(
            "[persist] nullifier view cache: {} ({} cached tag(s))",
            if ok { "RESUMED — the rebuilt root is the chain's acc root; no peer warm needed" } else { "REFUSED — the rebuilt root is not the resumed acc root; the peer warm rebuilds it" },
            tags.len()
        );
        ok
    }

    pub fn persist_blocking(&self) {
        // Every arm prints — a silent branch here cost a diagnosis cycle (TERM fired, save skipped, zero
        // lines; "handler dead" and "save silently declined" were indistinguishable). cons: none.
        let Some(path) = self.persist_path.as_ref().map(|t| t.path.clone()) else {
            eprintln!("[persist] shutdown save SKIPPED: persistence not enabled on this node");
            return;
        };
        // ⛔ G1 (lane a 2026-10-22): THE SHUTDOWN CHECKPOINT IS WRITTEN AFTER ANY AUTOSAVE IN FLIGHT, NEVER BESIDE IT. The
        // graft-time autosave writes on its own thread; this write ran at once beside it, and both renamed the SAME
        // `snap.tmp` into place — the loser's rename found no file (MEASURED g1-minednfs-node-green-2-20261022.log:
        // "shutdown snapshot FAILED: No such file or directory" while the autosave's older checkpoint resumed), so a clean
        // shutdown's newest state and every sibling cache it alone writes were lost. `save_inner` now names each writer's
        // temp file uniquely (no rename can lose), and this write waits — bounded — for the in-flight autosave so the
        // last checkpoint on disk is the newest. cons: at most 10 s added to a shutdown that caught an autosave mid-write.
        if let Some(flag) = self.persist_path.as_ref().map(|t| std::sync::Arc::clone(&t.save_in_flight)) {
            let waited = std::time::Instant::now();
            while flag.load(std::sync::atomic::Ordering::Acquire) && waited.elapsed() < std::time::Duration::from_secs(10) {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if flag.load(std::sync::atomic::Ordering::Acquire) {
                eprintln!("[persist] ⛔ an autosave was still in flight after 10 s; the shutdown checkpoint is written beside it");
            }
        }
        match self.export_snapshot() {
            Some(snap) => {
                let (fold, unlink) = self.capture_fold_record();
                match crate::persist::save_with_fold(&path, &snap, &fold) {
                    Ok(true) => {
                        crate::block_window::BlockWindow::flush_unlinks(&unlink);
                        self.persist_nf_view(&path); // DB-397 fix A: the view beside the snapshot it belongs to
                        eprintln!("[persist] shutdown snapshot WRITTEN (blocking) — circulating records + map saved")
                    }
                    Ok(false) => {
                        self.return_unlinks(unlink);
                        eprintln!("[persist] ⛔ shutdown snapshot REFUSED by the monotone-persist guard (see above)")
                    }
                    Err(e) => {
                        self.return_unlinks(unlink);
                        eprintln!("[persist] ⛔ shutdown snapshot FAILED: {e}")
                    }
                }
            }
            None => eprintln!("[persist] ⛔ shutdown save: export_snapshot returned None (no selected tip?)"),
        }
    }

    /// DB-243: adopt a certificate stepped OFF the lock — only if the live certificate is still the one the job
    /// cloned. A certificate that moved meanwhile (a synchronous build stepped it) is newer than the job's base,
    /// so the job's result is an older branch of it and is refused rather than written over it.
    pub fn install_cert_step(
        &mut self,
        cert: usdm_decider::whole_chain_cert::WholeChainCert,
        blue_work: u128,
        acc_before: &[u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
    ) -> bool {
        if self.chain_cert.acc() != *acc_before {
            return false;
        }
        self.chain_cert = cert;
        self.certified_blue_work = blue_work;
        true
    }

}

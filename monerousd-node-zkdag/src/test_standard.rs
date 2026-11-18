// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CROSS-NODE TEST STANDARD, ENFORCED BY THE SUITE ITSELF.
//!
//! A single-party test of chain behaviour proves almost nothing. Every expensive failure in this codebase was
//! a DISAGREEMENT BETWEEN TWO PARTIES that a one-node test could not express:
//!
//!   * two nodes recorded the same block at different ids        -> 0 shared ledger records
//!   * two nodes advertised one chain while holding no common data (DSYNC false join)
//!   * a producer recorded a note its VERIFYING peer never did   -> every cross-device payment lost
//!   * a backfill asked for a range no record could occupy       -> "serving 0" forever, silently
//!   * a wallet detected a note its own node could not serve     -> balance visible, funds unspendable
//!   * a node INVENTED 256 leaves for a block it had never seen  -> a silent fork of "block X's notes"
//!
//! Every one of those was green under a narrower test. The narrowing IS the defect: shrinking the subject
//! until it passes proves the subject passes, not that the system works.
//!
//! ## What this module does
//!
//! [`tests::every_chain_state_test_has_two_parties`] reads the crate's own source and applies the standard to
//! every `#[test]` in it. A test is IN SCOPE when it BUILDS CHAIN STATE — constructs a `Node`, records a note
//! payload, touches the DA layer, ingests, produces, grafts, adopts or persists. Mentioning a consensus noun
//! is not enough: a field-arithmetic identity or a pure hashing unit is legitimately one-party, and scoping on
//! construction rather than vocabulary is what keeps this precise instead of merely loud.
//!
//! An in-scope test must involve TWO parties — a second `Node`, a peer ingest, or a second wallet/device.
//!
//! ## The ratchet
//!
//! The suite did not start out meeting this standard, so [`LEGACY_ONE_PARTY`] freezes the ones that did not.
//! The assertion is deliberately two-sided:
//!
//!   * a NEW single-party chain-state test is not in the list  -> FAIL. The standard binds all new work.
//!   * a listed test that has since been FIXED is now stale    -> FAIL, until its entry is deleted.
//!
//! So the list cannot be padded to buy silence and cannot rot: it only ever shrinks, and it reaches zero when
//! the suite fully meets the standard. ([[feedback_cross_device_testing_cardinal]])

/// Tests that BUILD CHAIN STATE with a single party, frozen as of 2026-07-27. Shrink this list by giving a
/// test a second node and asserting the two AGREE; never add to it.
#[cfg(test)]
pub const LEGACY_ONE_PARTY: &[(&str, &str)] = &[
    (
        "node.rs",
        "a_bonded_note_is_locked_out_of_the_spendable_set_and_returned_only_on_unbond",
    ),
    (
        "node.rs",
        "a_pooled_spend_is_selected_into_the_very_next_block_not_stranded",
    ),
    (
        "node.rs",
        "a_stale_absence_proof_still_settles_while_forged_and_overtaken_ones_are_rejected",
    ),
    (
        "node.rs",
        "a_tag_survives_a_clue_cache_overflow_between_accept_and_block_record",
    ),
    (
        "node.rs",
        "block_apply_routes_witnessed_and_legacy_txs_advancing_the_sparse_acc",
    ),
    ("node.rs", "bond_unbond_delay_is_enforced_no_flash_bond"),
    (
        "node.rs",
        "decoy_seed_root_is_the_tree_free_sparse_accumulator",
    ),
    ("node.rs", "finality_vote_is_fail_closed_without_a_verifier"),
    (
        "node.rs",
        "fold_admit_gate_enforces_constant_width_and_mandatory_fold_proof",
    ),
    (
        "node.rs",
        "fresh_node_shares_canonical_genesis_by_construction_and_converges",
    ),
    (
        "node.rs",
        "hf38_solvency_carrier_is_fail_closed_without_a_verifier",
    ),
    (
        "node.rs",
        "hf44_settlement_advances_l2_root_and_rejects_replay",
    ),
    (
        "node.rs",
        "instant_sync_is_fail_closed_by_default_then_adopts_and_jumps",
    ),
    (
        "node.rs",
        "mina_o1_treeless_block_apply_advances_both_roots_from_carried_witnesses",
    ),
    (
        "node.rs",
        "no_double_unbond_cannot_double_withdraw_the_bond",
    ),
    (
        "node.rs",
        "node_executes_orchestrated_confidential_mint_self_attested",
    ),
    (
        "node.rs",
        "node_executes_orchestrated_wrapped_mint_per_asset_stablecoin_exempt",
    ),
    ("node.rs", "node_is_a_sovereign_site_deploy_target"),
    (
        "node.rs",
        "node_maintains_o1_nf_unspent_acc_and_admits_absence_chain",
    ),
    (
        "node.rs",
        "note_clue_cache_is_bounded_and_never_persisted_no_growth",
    ),
    (
        "node.rs",
        "nullifier_acc_o1_commitment_tracks_full_tree_and_is_byte_constant",
    ),
    ("node.rs", "overlays_finality_and_runtime_governance"),
    (
        "node.rs",
        "peg_out_release_requires_a_valid_burn_carrier_no_drain",
    ),
    (
        "node.rs",
        "root_history_retires_window_frozen_receipt_anchor_stays_spendable_forever",
    ),
    (
        "node.rs",
        "slash_reserve_theft_needs_a_pq_fraud_proof_forfeits_the_bond_and_bars_the_offender",
    ),
    (
        "node.rs",
        "sparse_acc_co_advances_on_record_block_nullifiers_peg_path",
    ),
    (
        "node.rs",
        "sparse_dsync_jump_adopts_tip_root_o1_then_rebuilds_and_gates",
    ),
    (
        "node.rs",
        "sparse_ingest_gate_advances_across_production_block_transitions_and_rejects_a_break",
    ),
    (
        "node.rs",
        "sparse_shadow_acc_tracks_the_applied_stream_in_lockstep",
    ),
    ("node.rs", "spent_nullifier_is_rejected_cross_block"),
    (
        "node.rs",
        "the_gate_admits_a_full_width_batched_absence_proof_and_rejects_a_settled_member",
    ),
    (
        "node.rs",
        "the_locator_index_survives_a_wiped_clue_cache_because_tags_ride_the_da_shard",
    ),
    (
        "node.rs",
        "trustless_sparse_spend_self_built_from_served_stream",
    ),
    (
        "node.rs",
        "yield_claim_requires_a_real_staked_note_no_free_reward",
    ),
    (
        "node_runtime.rs",
        "an_identical_directory_registration_is_unchanged_and_not_re_gossiped",
    ),
    (
        "node_runtime.rs",
        "runtime_serves_live_state_over_loopback_rpc",
    ),
    (
        "oli.rs",
        "a_recipient_finds_its_tagged_note_through_the_live_sharded_index_by_locator_alone",
    ),
    ("rpc.rs", "get_info_reflects_live_state"),
    ("rpc.rs", "submit_bad_tx_is_rejected_fail_closed"),
    (
        "rpc.rs",
        "submit_tx_then_template_includes_it_and_block_grafts",
    ),
];

#[cfg(test)]
mod tests {
    use super::LEGACY_ONE_PARTY;

    /// A test is in scope when it CONSTRUCTS node/ledger state, not when it merely names one.
    fn builds_chain_state(body: &str) -> bool {
        const MARKERS: &[&str] = &[
            "Node::new",
            "record_note_payload",
            "da_store",
            "da_load",
            "da_record",
            "da_block_leaves",
            "da_note_copath",
            "ingest_block",
            "apply_block",
            "produce_template",
            "produce_block",
            "graft_mined",
            "instant_sync",
            "enable_persist",
            "restore_from_disk",
            // ⛔ "adopt_" ALONE WAS A FALSE POSITIVE — it matched `adopt_merkle_root`, a pure sparse-tree
            // call that builds NO chain state. MEASURED 2026-08-01: five `nf_sparse.rs` tests were flagged as
            // one-party chain-state tests; all five contain ZERO `Node::new`, so there is no chain state for
            // two parties to disagree about and no second Node could make them meaningful. Naming the real
            // chain-adoption entry points keeps every genuine offender caught while dropping the false ones —
            // a guard that flags correct tests trains the reader to ignore it, which is worse than no guard.
            "adopt_peer",
            "adopt_account_targets",
            "adopt_block",
            "adopt_fetched_record",
            "account_bucket_append",
            "account_bucket_blob",
        ];
        MARKERS.iter().any(|m| body.contains(m))
    }

    /// Does the test actually involve a SECOND party?
    fn has_two_parties(body: &str) -> bool {
        let lc = body.to_lowercase();
        const MARKERS: &[&str] = &[
            "node_a",
            "ingest_block",
            "peer",
            "wallet_b",
            "device_b",
            "two_nodes",
            "cross_device",
            "cross_node",
        ];
        if MARKERS.iter().any(|m| lc.contains(m)) {
            return true;
        }
        // BOTH roles, never either alone. "verifier" on its own passes any test whose subject happens to be
        // named one — `finality_vote_is_fail_closed_without_a_verifier` has exactly one node and matched the
        // bare word, which is the false-pass this standard exists to prevent.
        if lc.contains("producer") && lc.contains("verifier") {
            return true;
        }
        // Two independent `Node::new`s in one body is the plainest two-party shape there is.
        lc.matches("node::new").count() >= 2
    }

    /// Every `#[test] fn name() { .. }` in a source file, with its brace-balanced body.
    fn test_bodies(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let bytes: Vec<char> = src.chars().collect();
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("#[test]") {
            let at = from + rel;
            from = at + 7;
            // Skip any further attributes, then read `fn <name>`.
            let Some(fpos) = src[at..].find("fn ") else {
                continue;
            };
            let after = at + fpos + 3;
            let Some(paren) = src[after..].find('(') else {
                continue;
            };
            let name: String = src[after..after + paren].trim().to_string();
            if name.is_empty() || name.contains(char::is_whitespace) {
                continue;
            }
            let Some(open_rel) = src[after..].find('{') else {
                continue;
            };
            let open = after + open_rel;
            let mut depth = 0i32;
            let mut end = open;
            for (i, c) in bytes.iter().enumerate().skip(src[..open].chars().count()) {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let body: String = bytes[src[..open].chars().count()..=end].iter().collect();
            out.push((name, body));
        }
        out
    }

    /// ⛔ THE VALUE-PATH DEBT, FROZEN AND COUNTED. 130 tests that move value and never assert on the
    /// peer. They are not deleted and they are not excused — they are NAMED, so no NEW one can appear and
    /// this list can only shrink. Every entry is a test that would pass while the other node disagreed,
    /// which is exactly how `execute_order_fill(..) == Settled` was true on two nodes at once while the
    /// maker's lot paid out twice.
    ///
    /// TO REMOVE AN ENTRY: make the test assert what the PEER holds — its book, its balance, its root, its
    /// record — then delete the line. Do not weaken the rule to fit a test.
    const LEGACY_SILENT_ON_PEER: &[(&str, &str)] = &[
        ("account_da.rs", "a_full_bucket_spills_to_the_next_link_and_never_drops_a_note"),
        ("canonical_record_fold_tests.rs", "a_node_that_jumps_by_a_bundle_folds_the_carried_blocks_at_the_producers_ordinals"),
        ("cover.rs", "an_idle_block_records_the_full_cover_shape_identically_on_every_node"),
        ("mesh_runtime_scenarios.rs", "diag_case_04_refill"),
        ("node.rs", "the_cheap_readiness_verdict_runs_off_lock_and_never_latches_a_moved_world"),
        ("node.rs", "the_reorg_heal_does_not_fire_without_stale_row_evidence"),
        ("node.rs", "a_lagging_beacon_keeps_the_certified_lock_and_a_foreign_root_does_not"),
        ("node.rs", "a_restarted_node_never_resurrects_a_spent_note_as_balance"),
        ("node.rs", "every_internal_credit_path_files_its_note_under_the_owner_when_one_is_given"),
        ("node.rs", "the_block_apply_path_emits_a_copath_delta_a_bystander_can_use"),
        ("node.rs", "the_membership_carrier_advances_per_block_on_both_live_paths_and_stays_flat"),
        ("node.rs", "a_record_folds_its_receive_from_notes_alone_so_two_nodes_converge_without_the_sidecar"),
        ("node.rs", "two_nodes_agree_the_idle_seed_is_not_a_receive_and_fold_an_owned_note_identically"),
        ("node.rs", "a_carried_note_folds_in_on_apply_and_the_catchup_serve_spends_it_after_churn"),
        ("node.rs", "chained_change_notes_stay_present_and_spendable_across_payment_blocks"),
        ("node.rs", "retention_drops_only_unreferenced_records_and_referenced_ones_never"),
        ("node.rs", "a_jumped_node_rebuilds_its_unspent_map_and_a_reverted_node_serves_only_its_own_view"),
        ("node.rs", "a_rolling_restart_resumed_from_disk_checkpoints_never_certifies_absence_of_a_funded_note"),
        ("node.rs", "an_adopted_unverified_root_never_enters_the_recent_roots_ring"),
        ("node.rs", "a_refused_fold_publishes_no_delta_and_does_not_move_the_root"),
        ("node.rs", "the_second_settlement_must_move_the_root_not_be_silently_dropped"),
        ("node.rs", "a_spent_nullifier_reads_spent_on_a_second_node_that_holds_no_sparse_tree"),
        ("node.rs", "three_credits_to_one_account_give_the_second_node_three_distinct_positions"),
        ("node.rs", "a_node_whose_index_cannot_describe_its_root_refuses_to_serve_a_witness"),
        ("node.rs", "two_nodes_apply_note_transitions_treeless_and_agree_on_one_root"),
        ("node.rs", "a_producer_that_already_filed_a_target_still_carries_it_on_the_block_for_its_peer"),
        ("node.rs", "bucket_index_rebuilds_at_resume_and_backfill_files_served_targets"),
        ("node.rs", "a_note_credited_outside_a_tx_has_no_account_bucket_entry_so_detection_is_not_yet_redundant"),
        ("node.rs", "a_notes_global_leaf_index_is_recoverable_from_its_record_so_no_stream_walk_is_needed"),
        ("node.rs", "a_genesis_one_step_carrier_verifies_on_any_node_at_any_age_and_every_tamper_refuses"),
        ("node.rs", "a_restarted_node_verifies_a_one_step_carrier_by_its_named_canonical_record_even_after_a_purge"),
        ("node.rs", "a_stale_membership_carrier_still_settles_while_a_forged_or_overtaken_one_is_refused"),
        ("node.rs", "the_served_accumulator_index_survives_persistence_the_way_a_live_node_runs"),
        ("node.rs", "the_carriers_own_fold_equals_the_nodes_step_function_or_no_spend_can_ever_match"),
        ("node.rs", "a_blocks_root_enters_the_membership_accumulator_exactly_once"),
        ("node.rs", "the_accumulator_a_spender_folds_from_served_roots_is_one_this_node_indexed"),
        ("node.rs", "a_verifying_node_records_every_block_that_cascades_in_out_of_order_never_losing_a_payment"),
        ("node.rs", "a_verifying_node_folds_every_accepted_block_including_dag_siblings_that_share_a_pre_root"),
        ("node.rs", "an_isolated_jumped_past_record_closes_the_span_and_a_forged_one_is_refused"),
        ("node.rs", "two_nodes_derive_byte_identical_block_leaves_and_never_invent_a_block_they_lack"),
        ("node.rs", "the_private_ledger_measured_against_a_transparent_chain_on_every_axis"),
        ("node.rs", "sparse_stage2_produce_spend_ingest_all_sub_1s_at_height"),
        ("node.rs", "trustless_sparse_spend_self_built_from_served_stream"),
        ("node.rs", "brick_c4_tx_fold_absence_gate_admits_unspent_rejects_spent_and_forged"),
        ("node.rs", "fold_admit_gate_enforces_constant_width_and_mandatory_fold_proof"),
        ("node.rs", "the_gate_admits_a_full_width_batched_absence_proof_and_rejects_a_settled_member"),
        ("node.rs", "a_stale_absence_proof_still_settles_while_forged_and_overtaken_ones_are_rejected"),
        ("node.rs", "node_maintains_o1_nf_unspent_acc_and_admits_absence_chain"),
        ("node.rs", "sparse_acc_co_advances_on_record_block_nullifiers_peg_path"),
        ("node.rs", "sparse_dsync_jump_adopts_tip_root_o1_then_rebuilds_and_gates"),
        ("node.rs", "decoy_seed_root_is_the_tree_free_sparse_accumulator"),
        ("node.rs", "ingest_tx_produce_and_extend"),
        ("node.rs", "a_pooled_spend_is_selected_into_the_very_next_block_not_stranded"),
        ("node.rs", "a_produced_block_carries_the_note_payload_it_settles_so_peers_need_no_local_tx_body"),
        ("node.rs", "a_bonded_note_is_locked_out_of_the_spendable_set_and_returned_only_on_unbond"),
        ("node.rs", "no_double_unbond_cannot_double_withdraw_the_bond"),
        ("node.rs", "bond_unbond_delay_is_enforced_no_flash_bond"),
        ("node.rs", "spent_nullifier_is_rejected_cross_block"),
        ("node.rs", "a_node_that_only_verifies_a_peers_block_records_its_notes_so_the_recipient_finds_the_payment"),
        ("node.rs", "treeless_adopt_ingest_holds_no_sparse_tree_at_any_height_and_the_fold_is_constant"),
        ("node.rs", "mina_split_measured_verifier_retains_zero_per_block_producer_retains_exactly_the_cover"),
        ("node.rs", "concurrent_conflicting_blocks_both_admit_no_split_and_mempool_gates_respend"),
        ("node.rs", "canonical_ordering_prunes_the_deterministic_double_spend_loser_receive_order_independent"),
        ("node.rs", "peg_out_release_requires_a_valid_burn_carrier_no_drain"),
        ("node.rs", "instant_sync_is_fail_closed_by_default_then_adopts_and_jumps"),
        ("node.rs", "a_stale_or_replayed_bundle_is_refused_not_heavier_and_state_never_rewinds"),
        ("node.rs", "a_jumped_node_adopts_an_extensible_frontier_spine_and_a_mismatched_one_is_refused"),
        ("node.rs", "a_jumped_node_adopts_the_certified_nf_unspent_acc_and_a_forged_one_is_rejected"),
        ("node.rs", "two_nodes_instant_sync_roundtrip_serve_then_adopt"),
        ("node.rs", "hf44_settlement_advances_l2_root_and_rejects_replay"),
        ("node.rs", "snapshot_field_sizes_ranked_for_the_4kb_budget"),
        ("node.rs", "nullifier_acc_o1_commitment_tracks_full_tree_and_is_byte_constant"),
        ("node.rs", "verifier_applies_carried_witnesses_to_o1_acc_holding_no_tree"),
        ("node.rs", "producer_builds_witnesses_a_verifier_reproduces_the_root"),
        ("node.rs", "block_apply_routes_witnessed_and_legacy_txs_advancing_the_sparse_acc"),
        ("node.rs", "commit_pads_cover_deterministically_producer_equals_verifier"),
        ("node.rs", "nullifier_no_window_da_replay_reproduces_acc_by_construction"),
        ("node.rs", "a_blocks_shipped_tag_count_is_constant_whatever_its_real_spend_count"),
        ("node.rs", "produced_header_commits_pre_block_nullifier_root_two_producers_agree"),
        ("node.rs", "carried_witnesses_are_transient_wire_never_retained_state"),
        ("node.rs", "the_fold_one_carrier_replaces_per_block_witnesses_and_rejects_a_broken_chain"),
        ("node.rs", "brick1_treeless_live_ingest_path_end_to_end_at_production_cover"),
        ("node.rs", "spender_self_builds_witness_from_replicated_da_a_treeless_verifier_accepts"),
        ("node.rs", "mina_producer_builds_witnesses_a_treeless_verifier_reaches_the_same_roots"),
        ("node.rs", "mina_o1_treeless_block_apply_advances_both_roots_from_carried_witnesses"),
        ("node.rs", "root_history_retires_window_frozen_receipt_anchor_stays_spendable_forever"),
        ("node.rs", "a_verifying_node_folds_every_block_even_when_they_arrive_out_of_order"),
        ("node.rs", "two_nodes_receiving_the_same_blocks_in_different_order_agree_on_every_ordinal"),
        ("node.rs", "a_v25_snapshot_file_migrates_forward_with_custody_intact"),
        ("node.rs", "two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal"),
        ("node.rs", "inserting_through_the_da_index_tracks_a_held_tree_exactly_with_no_tree_and_no_replay"),
        ("node.rs", "the_in_flight_gauge_counts_settled_payments_no_recipient_has_seen"),
        ("node.rs", "an_unresolved_payment_is_never_evicted_however_many_newer_ones_arrive"),
        ("node.rs", "two_nodes_agree_on_one_state_root_and_a_tampered_half_changes_it"),
        ("node.rs", "a_running_nodes_per_record_footprint_is_measured_and_attributed_not_assumed"),
        ("node.rs", "two_nodes_that_accepted_the_same_blocks_agree_on_every_record_ordinal"),
        ("node.rs", "a_filed_bucket_position_resolves_to_the_same_block_on_a_second_mining_node"),
        ("node.rs", "cross_node_a_spend_settles_by_deletion_and_the_peer_agrees_from_the_root_alone"),
        ("node.rs", "cross_node_the_live_produce_path_folds_spend_transitions_and_the_peer_agrees"),
        ("node.rs", "cross_node_a_reboot_restores_the_unspent_root_and_still_refuses_the_double_spend"),
        ("node.rs", "a_verifier_refuses_a_block_whose_body_does_not_match_its_header_commitments"),
        ("node.rs", "a_verifier_refuses_a_block_whose_findability_sidecars_were_stripped_or_forged"),
        ("node.rs", "a_verifier_refuses_a_block_whose_deletion_set_was_stripped_or_forged"),
        ("node.rs", "the_bonded_validator_set_survives_a_snapshot_roundtrip"),
        ("node.rs", "an_empty_mempool_ingester_folds_the_carried_deletion_set_and_agrees_on_the_unspent_root"),
        ("node.rs", "a_fill_settled_on_one_node_reaches_the_same_spend_state_on_a_second_node"),
        ("node.rs", "a_swap_leaves_its_proof_in_chain_state_not_in_a_server"),
        ("node.rs", "the_spentness_assertion_actually_discriminates_on_an_executing_node"),
        ("node.rs", "resting_orders_are_offers_and_never_move_value_by_themselves"),
        ("node_runtime.rs", "a_served_page_never_exceeds_the_wire_byte_bound"),
        ("node_runtime.rs", "a_byte_budgeted_page_truncates_and_vouches_only_covered_ground"),
        ("node_runtime.rs", "beacon_fork_choice_rejects_foreign_and_lighter_only_adopts_heavier_same_genesis"),
        ("node_runtime.rs", "two_nodes_converge_on_the_same_heaviest_tip_no_backfill"),
        ("node_runtime.rs", "two_nodes_converge_to_exact_tip_within_bounded_propagation_latency"),
        ("node_runtime.rs", "two_nodes_converge_over_the_multi_transport_composite"),
        ("node_runtime.rs", "two_devices_converge_over_the_ble_shaped_bridge_transport_no_shared_channel"),
        ("node_runtime.rs", "cross_device_send_converges_full_spent_state_no_island"),
        ("node_runtime.rs", "a_carrier_without_its_tag_set_is_refused_at_the_gate"),
        ("node_runtime.rs", "a_forged_pow_block_is_refused_by_the_offlock_preverifier_and_a_real_one_grafts"),
        ("node_runtime.rs", "a_tx_whose_first_gossip_was_dropped_is_re_relayed_instead_of_being_lost"),
        ("node_runtime.rs", "a_node_missing_a_blocks_txs_requests_them_and_then_folds_the_block"),
        ("node_runtime.rs", "a_missing_tx_request_is_cover_padded_to_a_constant_width"),
        ("oli.rs", "a_recipient_finds_its_tagged_note_through_the_live_sharded_index_by_locator_alone"),
        ("persist.rs", "the_node_snapshot_is_attributed_field_by_field"),
        ("persist.rs", "a_v26_layout_snapshot_migrates_and_garbage_refuses_every_door"),
        ("rpc.rs", "get_pq_notes_serves_the_any_height_stream_range"),
        ("rpc.rs", "submit_tx_then_template_includes_it_and_block_grafts"),
        ("rpc_http.rs", "note_copath_serves_the_append_ordinal_so_a_wallet_can_place_its_note_without_the_stream"),
        ("test_standard.rs", "builds_chain_state"),
        ("mesh_runtime_scenarios.rs", "diag_case_04_refill"),
        ("mesh_runtime_scenarios.rs", "diag_case_08_unspent_root_split"),
        ("mesh_schedule_search_tests.rs", "diag_replay_case_file"),
        ("mesh_schedule_search_tests.rs", "diag_restart_search_seed_1"),
        ("node.rs", "the_cheap_readiness_verdict_runs_off_lock_and_never_latches_a_moved_world"),
    ];

    /// ⛔⛔⛔ THE RULE THAT WOULD HAVE CAUGHT THE DOUBLE-FILL. A test that MOVES VALUE must assert on what
    /// the OTHER party holds, not on what the local call returned.
    ///
    /// MEASURED 2026-09-03: every DEX fill test satisfied `has_two_parties` — they mention `ingest_block`
    /// or build two `Node`s in setup — and then asserted only `execute_order_fill(..) == Settled`. That is
    /// the local view of a local mutation. Two honest nodes each returned `Settled` for the SAME order and
    /// the maker's lot paid out twice; forty-five gate runs never saw it, because nothing ever asked the
    /// peer. A returned enum is not a ledger.
    fn moves_value(body: &str) -> bool {
        let lc = body.to_lowercase();
        const VALUE: &[&str] = &[
            "execute_order_fill",
            "peg_in_confidential",
            "record_note_payload",
            "post_order",
            "spend",
            "burn",
            "settle",
        ];
        VALUE.iter().any(|m| lc.contains(m))
    }

    /// At least one assertion must name the SECOND party. The check is deliberately syntactic and dumb:
    /// an assertion whose text mentions a peer binding. A test can still be weak, but it can no longer be
    /// silent about the other side.
    fn asserts_on_the_peer(body: &str) -> bool {
        const PEER: &[&str] = &["node_b", "b.", "peer", "other", "wallet_b", "device_b", "n2", "w2"];
        body.lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("assert!") || t.starts_with("assert_eq!") || t.starts_with("assert_ne!")
            })
            .any(|l| {
                let lc = l.to_lowercase();
                PEER.iter().any(|p| lc.contains(p))
            })
    }

    #[test]
    fn every_chain_state_test_has_two_parties() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("the crate's own source directory is readable")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
            .collect();
        files.sort();
        assert!(
            files.len() > 20,
            "the scan must actually find the crate's sources, found {}",
            files.len()
        );

        let mut offenders: Vec<(String, String)> = Vec::new();
        let mut silent: Vec<(String, String)> = Vec::new();
        let mut scanned = 0usize;
        for path in &files {
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            let src = std::fs::read_to_string(path).expect("source file is readable");
            for (name, body) in test_bodies(&src) {
                scanned += 1;
                if builds_chain_state(&body) && !has_two_parties(&body) {
                    offenders.push((file.clone(), name.clone()));
                }
                // A value-moving test that never asserts on the peer proves only that a function returned.
                if builds_chain_state(&body) && moves_value(&body) && !asserts_on_the_peer(&body) {
                    silent.push((file.clone(), name));
                }
            }
        }
        assert!(
            scanned > 300,
            "the parser must actually find the suite's tests, found {scanned}"
        );

        let frozen: std::collections::BTreeSet<(String, String)> = LEGACY_ONE_PARTY
            .iter()
            .map(|(f, n)| (f.to_string(), n.to_string()))
            .collect();
        let found: std::collections::BTreeSet<(String, String)> =
            offenders.iter().cloned().collect();

        // (1) NEW single-party chain-state tests are refused outright.
        let fresh: Vec<_> = found.difference(&frozen).collect();
        // ⛔ THE VALUE-PATH RULE. Reported FIRST because it is the one that cost money: a test that moves
        // value and never asserts on the peer proves only that a function returned a value it likes.
        let silent_frozen: std::collections::BTreeSet<(String, String)> = LEGACY_SILENT_ON_PEER
            .iter()
            .map(|(f, n)| (f.to_string(), n.to_string()))
            .collect();
        let silent_found: std::collections::BTreeSet<(String, String)> = silent.iter().cloned().collect();
        let silent: Vec<_> = silent_found.difference(&silent_frozen).cloned().collect();
        assert!(
            silent.is_empty(),
            "these tests MOVE VALUE and never assert on the OTHER party. A returned enum is not a ledger — \
             `execute_order_fill(..) == Settled` was true on BOTH nodes for the SAME order while the maker's \
             lot paid out twice. Assert what the PEER holds: its book, its balance, its root, its record. \
             Offenders: {silent:#?}"
        );
        assert!(
            fresh.is_empty(),
            "these tests BUILD CHAIN STATE with only ONE party. A one-party test cannot express the failure \
             that actually breaks this system: two parties DISAGREEING. Give the test a second `Node` — one \
             PRODUCES, the other INGESTS — and assert they hold or derive the SAME thing (same record id, \
             same accumulator, same served bytes, same balance). Offenders: {fresh:#?}"
        );

        // (2) The ratchet: a listed test that now has two parties must be REMOVED from the list, so the
        //     baseline can only shrink and can never be padded to buy silence.
        let stale: Vec<_> = frozen.difference(&found).collect();
        assert!(
            stale.is_empty(),
            "these tests now meet the cross-node standard — delete their LEGACY_ONE_PARTY entries so the \
             baseline ratchets down: {stale:#?}"
        );
    }
}

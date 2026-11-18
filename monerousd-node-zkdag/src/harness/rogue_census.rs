// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE ROGUE-ROLE CENSUS — every chain-object class × every attack, as a mechanical list.
//!
//! User 2026-10-03: *"we have to be the first to audit this like a professional external reviewer who ask 'how can i break
//! this?'"*, and (the RAM-light readiness plan) *"no blind spots"*. This week's holes were all one shape: a role we
//! assumed honest lies, and a peer believes it.
//! - DB-223: a spend of a note that never existed.
//! - DB-368: a carried fill with never-existed inputs, or a substituted payout.
//! - The second mint of one asset (refused, pinned).
//! - The PoolDeposit of a never-existing note (refused, pinned).
//!
//! THE CENSUS. For every [`Class`] (read from the decoder, so a new class appears here the day it is added) and every
//! attack in [`ATTACKS`], exactly one [`Cell`]:
//! - [`Cell::Pinned`] names the test that drives the attack through a PEER and asserts the peer refuses it;
//! - [`Cell::NotApplicable`] says why the attack has no target in this class;
//! - [`Cell::Open`] says what is not yet pinned.
//!
//! The tests below FAIL when a class lacks a cell, or a pinned cell names a test that does not exist. The open cells are
//! the honest work list ([`open_cells`]).
//!
//! The ATTACKS, as a rogue PRODUCER, RELAY, WALLET or CUSTODIAN would mount them:
//! - `forge`: an object whose inputs or authority never existed (an invented note, an unsigned or under-signed
//!   attestation, a proof over a statement the chain never held);
//! - `strip`: a required part removed (a bind, a lane tag, an owner clue, a carrier);
//! - `substitute`: a field swapped for one the proof or signature never covered (a payout note, a snapshot, an
//!   owner, an amount);
//! - `replay`: a settled object carried again (the same bytes, or a fresh wrapper around the same one-time right).
//! - `burn` (2026-10-03, the DESTRUCTION side): an object, refused or forged, that names a VICTIM's id — a note's
//!   nullifier, a deposit's or a position's one-time id, an issuance or seat right — so a peer retires the id its owner
//!   never authorised. Every retirement enters the spent set through ONE door (DB-367 `Node::lane_justified`: a proven
//!   transition's tags, or an ADMISSIBLE object's `chain_object::object_own_nullifiers`), so a class with no arm there
//!   retires nothing of its own — checked against the source by [`destruction_universe_gaps`], never declared. This replaced
//!   the hand-written §BB row `Block::del_set`, which named a field the Z-build deleted on 2026-09-22.

use crate::chain_object::Class;

/// The attacks every class is censused against.
pub const ATTACKS: [&str; 5] = ["forge", "strip", "substitute", "replay", "burn"];

/// The prefix of every `burn` cell that is NotApplicable because the class retires no id of its own — the one claim
/// [`destruction_universe_gaps`] checks against `chain_object::object_own_nullifiers`.
pub const RETIRES_NOTHING: &str = "retires no id of its own";

/// One census cell.
#[derive(Debug, Clone, Copy)]
pub enum Cell {
    /// The test (by name) that mounts this attack and asserts a PEER refuses it.
    Pinned(&'static str),
    /// Why this attack has no target in this class.
    NotApplicable(&'static str),
    /// What is not yet pinned.
    Open(&'static str),
}

/// `(class name as `{:?}` prints it, attack, cell)`. Cells are Pinned only where the named test was read and found to
/// mount exactly that attack through a peer. Everything else is Open until it is.
pub const CELLS: &[(&str, &str, Cell)] = &[
    // ── OrderFill (DB-368, 2026-10-03) ──
    ("OrderFill", "forge", Cell::Pinned("a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_rogue_producer_carries_it")),
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): real inputs on both chains, binds stripped, refused at the fold
    // (DB-368 MembershipRefused); CONTROL: the honest fill then settles on both nodes, each note exactly once.
    ("OrderFill", "strip", Cell::Pinned("a_fill_over_real_inputs_stripped_of_its_membership_binds_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    ("OrderFill", "substitute", Cell::Pinned("a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_rogue_producer_carries_it")),
    ("OrderFill", "replay", Cell::Pinned("an_order_fill_settles_once_and_a_replay_is_refused_as_already_filled")),
    // ── OrderPost ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): each judged on the peer's BOOK, CONTROL: the honest offer then rides
    // a block and rests on both nodes.
    ("OrderPost", "forge", Cell::Pinned("a_forged_offer_carried_by_a_rogue_producer_rests_in_no_peer_book")),
    ("OrderPost", "strip", Cell::Pinned("an_offer_stripped_of_its_payout_owner_carried_by_a_rogue_producer_rests_in_no_peer_book")),
    ("OrderPost", "substitute", Cell::Pinned("an_offer_whose_payout_note_was_swapped_carried_by_a_rogue_producer_rests_in_no_peer_book")),
    // RED 2026-10-04 15:55 (a filled order re-rested 1/1 from a re-carried post) → GREEN 16:32 after lane-consensus DB-384
    // (`post_order` refuses `MakerSpent`): live re-carry 1/1 (Duplicate), after the fill 0/0.
    ("OrderPost", "replay", Cell::Pinned("a_re_carried_offer_rests_once_while_live_and_never_again_after_its_fill_on_the_peer")),
    // ── BridgeCredit ──
    ("BridgeCredit", "forge", Cell::Pinned("a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body")),
    // 2026-10-04 (lane-harness): strip = the existing two-arm pin (arm 2: the stripped credit staged past the rogue's own
    // assembly door on MAINNET, the peer holds nothing; arm 1: the attested one lands) — read and first recorded GREEN;
    // substitute = `rogue_role_pins.rs` (the note swapped under the attestation; the honest credit then lands once).
    ("BridgeCredit", "strip", Cell::Pinned("an_attested_mainnet_credit_lands_on_the_peer_at_graft_and_an_unattested_one_does_not")),
    ("BridgeCredit", "substitute", Cell::Pinned("a_credit_whose_note_was_swapped_under_its_attestation_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    ("BridgeCredit", "replay", Cell::Pinned("many_replays_of_one_credit_sum_to_exactly_one_mint_on_the_peer")),
    // ── AssetCreate ──
    // A creation is unsigned BY DESIGN (the creator field names who may mint; the mint is the authority): the forge cell
    // asks what a forged creation buys — the rogue's own mint of it is refused, the named creator's mint lands once.
    ("AssetCreate", "forge", Cell::Pinned("a_creation_laid_by_a_rogue_naming_a_victim_creator_gives_the_rogue_no_issuance_on_the_peer")),
    // 2026-10-04 (lane-harness): judged on the peer's DSOL registry root.
    ("AssetCreate", "strip", Cell::Pinned("a_creation_stripped_of_its_bytecode_carried_by_a_rogue_producer_registers_nothing_on_the_peer")),
    ("AssetCreate", "substitute", Cell::Pinned("a_creation_claiming_an_id_that_is_not_its_descriptors_carried_by_a_rogue_producer_registers_nothing_on_the_peer")),
    // RED 2026-10-04 17:46 (a re-carried creation appended a duplicate registry leaf) → GREEN 18:22 after lane-consensus
    // DB-388 (a creation retires `one_time_id_nf(ONE_TIME_ASSET_CREATE, asset_id)`; the graft apply skips an object whose
    // own ids it does not retire).
    ("AssetCreate", "replay", Cell::Pinned("a_creation_re_carried_by_a_rogue_producer_moves_no_peer_registry_and_grants_no_second_issuance")),
    // ── AssetMint ──
    ("AssetMint", "forge", Cell::Pinned("a_mint_for_an_asset_that_was_never_created_is_refused_and_the_registered_one_is_not")),
    ("AssetMint", "strip", Cell::Pinned("an_asset_mint_stripped_of_its_issuance_right_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    ("AssetMint", "substitute", Cell::Pinned("a_mint_whose_carrier_does_not_open_the_note_is_not_authorised")),
    ("AssetMint", "replay", Cell::Pinned("a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer")),
    // ── Liquidation ──
    ("Liquidation", "forge", Cell::Pinned("a_healthy_psm_or_a_forged_liquidation_moves_nothing")),
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): a DUE liquidation (PSM marked under 125 %, 900 in the pool) framed by
    // the custodian; rogue blocks judged on the peer's PSM commitments + pool words; CONTROL: the honest close lands on both.
    ("Liquidation", "strip", Cell::Pinned("a_liquidation_stripped_of_its_attestations_carried_by_a_rogue_producer_moves_no_peer_psm")),
    ("Liquidation", "substitute", Cell::Pinned("a_liquidation_whose_legs_were_swapped_under_its_attestation_carried_by_a_rogue_producer_moves_no_peer_psm")),
    ("Liquidation", "replay", Cell::Pinned("a_liquidation_re_carried_by_a_rogue_producer_closes_the_position_once_on_the_peer")),
    // ── WrappedAssetRegister ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): judged on the peer's registry ratio; CONTROL: the bonded quorum's
    // registration then lands on both nodes. The substitute arm swaps 150 % → 100 % (the over-issue direction).
    ("WrappedAssetRegister", "forge", Cell::Pinned("an_under_attested_wrapped_asset_registration_carried_by_a_rogue_producer_registers_nothing_on_the_peer")),
    ("WrappedAssetRegister", "strip", Cell::Pinned("a_wrapped_asset_registration_stripped_of_its_attestations_carried_by_a_rogue_producer_registers_nothing_on_the_peer")),
    ("WrappedAssetRegister", "substitute", Cell::Pinned("a_wrapped_asset_registration_whose_ratio_was_swapped_under_the_quorum_carried_by_a_rogue_producer_registers_nothing_on_the_peer")),
    ("WrappedAssetRegister", "replay", Cell::Pinned("a_wrapped_asset_registration_re_carried_by_a_rogue_producer_does_not_roll_back_the_peer_ratio")),
    // ── WrappedMint ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): judged on the peer's peg ledger + records; CONTROL: the honest
    // attested mint then lands on both nodes, its note in exactly one record each.
    ("WrappedMint", "forge", Cell::Pinned("an_under_attested_wrapped_mint_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    ("WrappedMint", "strip", Cell::Pinned("a_wrapped_mint_stripped_of_its_attestations_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    ("WrappedMint", "substitute", Cell::Pinned("a_wrapped_mint_whose_note_was_swapped_under_the_quorum_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    // The rogue-side record count this arm first measured is the DB-379 class, pinned on its own (red, filed):
    // `db379_a_late_sibling_re_carrying_a_mint_leaves_its_note_unstripped_on_the_node_that_folded_past_it`.
    ("WrappedMint", "replay", Cell::Pinned("a_wrapped_mint_re_carried_by_a_rogue_producer_mints_once_on_the_peer")),
    // ── AssetSpend ──
    ("AssetSpend", "forge", Cell::Pinned("a_peer_does_not_credit_an_asset_transfer_whose_input_never_existed")),
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): a wrapped note minted to a holder and its transfer published; rogue
    // blocks judged on the peer's records; CONTROL: the honest transfer then lands on both nodes, each output once. The
    // replay cell is the BLOCK path: a second, fully valid transfer of the spent note carried by a rogue producer.
    ("AssetSpend", "strip", Cell::Pinned("an_asset_transfer_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    ("AssetSpend", "substitute", Cell::Pinned("an_asset_transfer_whose_output_was_swapped_under_its_carrier_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    ("AssetSpend", "replay", Cell::Pinned("a_second_transfer_of_a_spent_asset_note_carried_by_a_rogue_producer_credits_nothing_on_the_peer")),
    // ── Unbond ──
    ("Unbond", "forge", Cell::Pinned("an_unbond_not_signed_by_the_bonds_owner_carried_by_a_rogue_producer_releases_nothing_on_the_peer")),
    ("Unbond", "strip", Cell::Pinned("an_unbond_whose_owner_clue_was_stripped_replaced_or_repointed_is_refused")),
    ("Unbond", "substitute", Cell::Pinned("an_unbond_whose_owner_clue_was_stripped_replaced_or_repointed_is_refused")),
    ("Unbond", "replay", Cell::Pinned("no_double_unbond_cannot_double_withdraw_the_bond")),
    // ── PegIn ──
    // 2026-10-04: four two-party pins, a rogue producer's block judged by the peer, each with a CONTROL that the honest
    // mint still lands on both nodes afterwards (the DB-377 burn class the forge arm found).
    ("PegIn", "forge", Cell::Pinned("an_under_attested_peg_in_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    ("PegIn", "strip", Cell::Pinned("a_peg_in_stripped_of_its_attestations_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    ("PegIn", "substitute", Cell::Pinned("a_peg_in_whose_recipient_was_swapped_under_the_quorum_carried_by_a_rogue_producer_mints_nothing_on_the_peer")),
    ("PegIn", "replay", Cell::Pinned("a_peg_in_re_carried_by_a_rogue_producer_mints_once_on_the_peer")),
    // ── PegOut ──
    // 2026-10-04: the forge / strip / replay arms are GREEN inside `a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block`
    // (rogue producer blocks judged on D and C). Its CONTROL was RED as DB-379 ("a block landing below a moving fold cursor
    // is never folded") until 2026-10-22, when a per-node DAG measurement (`[db379-measure]`, scratchpad/night/
    // db379-measure-20261022.log:1823) showed the honest block was a lighter SIDE TIP no block had merged — the fixture never
    // laid the mesh's merging block. With that block laid, D applies the burn from it (db379-mesh-20261022.log:1875): GREEN.
    ("PegOut", "forge", Cell::Pinned("a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block")),
    ("PegOut", "strip", Cell::Pinned("a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block")),
    ("PegOut", "substitute", Cell::Pinned("a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block")),
    ("PegOut", "replay", Cell::Pinned("a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block")),
    // ── YieldClaim ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): a real stake laid at e1, its claim published at e1+365 and judged
    // in its epoch on the peer's records + committed supply; CONTROL: the honest claim then lands on both nodes once.
    ("YieldClaim", "forge", Cell::Pinned("a_yield_claim_whose_stake_carrier_proves_nothing_carried_by_a_rogue_producer_pays_no_reward_on_the_peer")),
    ("YieldClaim", "strip", Cell::Pinned("a_yield_claim_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_pays_no_reward_on_the_peer")),
    ("YieldClaim", "substitute", Cell::Pinned("a_yield_claim_whose_reward_note_was_swapped_carried_by_a_rogue_producer_pays_no_reward_on_the_peer")),
    ("YieldClaim", "replay", Cell::Pinned("a_yield_claim_re_carried_by_a_rogue_producer_pays_its_reward_once_on_the_peer")),
    // ── MembershipBond ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): the rogue pools the object past its own door and lays it on the
    // BOND lane; judged on the peer's validator set; CONTROL: the validator's own signed request then seats on both nodes.
    ("MembershipBond", "forge", Cell::Pinned("a_seat_not_signed_by_its_key_carried_by_a_rogue_producer_seats_no_one_on_the_peer")),
    ("MembershipBond", "strip", Cell::Pinned("a_seat_carried_without_its_one_shot_right_by_a_rogue_producer_seats_no_one_on_the_peer")),
    ("MembershipBond", "substitute", Cell::Pinned("a_seat_whose_custody_key_was_swapped_after_signing_carried_by_a_rogue_producer_seats_no_one_on_the_peer")),
    ("MembershipBond", "replay", Cell::Pinned("a_seat_request_re_carried_by_a_rogue_producer_seats_once_on_the_peer")),
    // ── PriceMark ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): judged on the peer's standing mark; CONTROL: the bonded quorum's
    // mark then lands on both nodes. Replay = a stale epoch-1 mark after epoch 2 (the strictly monotone epoch holds).
    ("PriceMark", "forge", Cell::Pinned("an_under_attested_price_mark_carried_by_a_rogue_producer_moves_no_peer_price")),
    ("PriceMark", "strip", Cell::Pinned("a_price_mark_stripped_of_its_quotes_carried_by_a_rogue_producer_moves_no_peer_price")),
    ("PriceMark", "substitute", Cell::Pinned("a_price_mark_whose_price_was_swapped_under_its_signature_carried_by_a_rogue_producer_moves_no_peer_price")),
    ("PriceMark", "replay", Cell::Pinned("a_stale_price_mark_re_carried_by_a_rogue_producer_does_not_roll_back_the_peer_price")),
    // ── Equivocation ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): judged on the peer's bonds; CONTROL: genuine evidence then slashes
    // the validator on both nodes at the fold.
    ("Equivocation", "forge", Cell::Pinned("equivocation_evidence_not_signed_by_the_accused_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("Equivocation", "strip", Cell::NotApplicable("the evidence is two signatures; a stripped one is not evidence (decode refuses)")),
    ("Equivocation", "substitute", Cell::Pinned("two_votes_at_different_heights_presented_as_equivocation_by_a_rogue_producer_slash_no_one_on_the_peer")),
    ("Equivocation", "replay", Cell::Pinned("equivocation_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer")),
    // ── FinalityVote (G2, lane a 2026-10-22) ──
    // judged on the peer's `(finalized_height, finalized_block)`: a rogue bond lane carrying a vote whose signature was
    // flipped (forge), a vote for the block at a height it does not sit at (substitute), and the honest vote carried twice
    // (replay) each move the peer's finality by nothing; CONTROL: the honest carried vote finalizes on both nodes alike.
    ("FinalityVote", "forge", Cell::Pinned("two_nodes_holding_the_same_blocks_read_the_same_finality_whichever_of_them_heard_the_votes")),
    ("FinalityVote", "strip", Cell::NotApplicable("the vote is one signature over one (block, height); a stripped one is not a vote (decode refuses exact ML-DSA-65 widths)")),
    ("FinalityVote", "substitute", Cell::Pinned("two_nodes_holding_the_same_blocks_read_the_same_finality_whichever_of_them_heard_the_votes")),
    ("FinalityVote", "replay", Cell::Pinned("two_nodes_holding_the_same_blocks_read_the_same_finality_whichever_of_them_heard_the_votes")),
    // ── BondTransition ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): a real welded bond; the rogue (which pooled the honest bond via
    // gossip) lays its own block and tampers the bond lane. MEASURED batch 10: every tampered lane seats 0 weight on the
    // peer (the attack arms HOLD), but forge/strip/burn are RED on their CONTROL — EVICTION BY INCLUSION: the peer drops the
    // honest pooled bond at graft (node.rs ~31517-31536 `evicted_by_block`) and returns it only when the block loses the
    // selected chain, so a canonical block whose object the fold REFUSED censors the pending tx (filed; lane-consensus).
    // 2026-10-07 (cf22f61, user-delegated: VALIDATOR BONDS ARE SAT-ONLY, `Node::USDM_BOND_RETIRED`): the four per-tamper pins
    // above were deleted with the class they attacked (DB-389's eviction-by-inclusion control went GREEN e61d2c2 first). The
    // one pin left mounts the STRONGEST form — a rogue producer lays a USDm bond WITH its proven welded statement, the full
    // pre-ruling shape — and asserts the peer (and the rogue itself) seats 0 finality weight and no seat; a forged, stripped,
    // substituted or re-carried statement can seat no more than the proven one. 2026-10-22 (lane a): each cell re-pointed
    // from a name that existed nowhere (`a_bond_re_carried_by_a_rogue_producer_seats_its_weight_once_on_the_peer`).
    ("BondTransition", "forge", Cell::Pinned("a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer")),
    ("BondTransition", "strip", Cell::Pinned("a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer")),
    ("BondTransition", "substitute", Cell::Pinned("a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer")),
    ("BondTransition", "replay", Cell::Pinned("a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer")),
    // ── SatoshiReward (2026-10-22, lane a; the class entered the decoder 2026-10-07 with no cells — the census self-test
    //    was red for 15 days) ── `satoshi_pins.rs`: the peer fed only blocks judges a rogue producer's block at the fold door
    //    `apply_sat_reward_at_fold` (first reward only; the carrying block's parent key; the opening recomputes the note at the
    //    schedule's amount; the 21,000,000 SAT cap).
    ("SatoshiReward", "forge", Cell::Pinned("a_rogue_reward_at_a_wrong_key_with_a_forged_carrier_doubled_or_replayed_mints_nothing_extra_on_the_peer")),
    ("SatoshiReward", "strip", Cell::Open("a reward carried WITHOUT its 32-byte opening (B4: the object is note + opening + clue) in a rogue block: the forged-carrier arm of `a_rogue_reward_at_a_wrong_key…` drives an opening that does not recompute the note through the same door (`credit_is_authorised`), and an undecodable object is stripped at the fold — a cell that removes the opening outright and asserts the PEER mints nothing is not yet mounted")),
    ("SatoshiReward", "substitute", Cell::Pinned("db393_b4_a_relay_that_swaps_a_rewards_opening_breaks_the_block_on_the_peer")),
    ("SatoshiReward", "replay", Cell::Pinned("a_rogue_reward_at_a_wrong_key_with_a_forged_carrier_doubled_or_replayed_mints_nothing_extra_on_the_peer")),
    // ── SatBond (2026-10-22, lane a) ── `satoshi_pins.rs`: a custody bond built from a mining reward; `objects_decide_at_fold`
    //    decides it on the peer (the weld, the seat's signature, the single-seat rule of the set). The moved-weight,
    //    stranger-signature and USDm-carrier arms of the forge pin are judged at the fold's own authorisation door
    //    (`weld_is_authorised` / `is_authorised`, the door `objects_decide_at_fold` asks); its second-seat arm is a rogue-pooled,
    //    rogue-laid block judged on BOTH nodes' custody weight.
    ("SatBond", "forge", Cell::Pinned("a_sat_bond_with_a_moved_weight_a_usdm_carrier_a_strangers_signature_or_a_second_seat_seats_nothing_on_the_peer")),
    ("SatBond", "strip", Cell::Open("a FIRST SAT bond carried without its weld or its locked note in a rogue block, judged on the peer's custody weight: `a_rebond_with_a_phantom_locked_input_an_unseated_key_a_strangers_signature_a_stripped_leg_or_a_replay_seats_nothing` strips the RE-BOND leg at the verifier; the rogue-block strip of a first bond is not yet mounted")),
    ("SatBond", "substitute", Cell::Pinned("a_rebond_that_lowers_custody_weight_is_refused_at_every_door_and_the_old_weight_stays_seated")),
    ("SatBond", "replay", Cell::Pinned("a_sat_bond_with_a_moved_weight_a_usdm_carrier_a_strangers_signature_or_a_second_seat_seats_nothing_on_the_peer")),
    // ── ReserveTheft ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): bond-lane rogue blocks judged on the peer's bonds past the fold;
    // CONTROL: the honest ≥ 2/3 evidence then slashes the real thief on both nodes.
    ("ReserveTheft", "forge", Cell::Pinned("theft_evidence_against_an_innocent_custodian_below_the_quorum_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("ReserveTheft", "strip", Cell::Pinned("theft_evidence_stripped_of_its_certificate_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("ReserveTheft", "substitute", Cell::Pinned("a_genuine_theft_certificate_retargeted_at_an_honest_custodian_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("ReserveTheft", "replay", Cell::Pinned("theft_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer")),
    // ── PoolDeposit (2026-10-03) ──
    ("PoolDeposit", "forge", Cell::Pinned("a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool")),
    ("PoolDeposit", "strip", Cell::Pinned("a_pool_deposit_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_moves_no_peer_pool")),
    ("PoolDeposit", "substitute", Cell::Pinned("a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool")),
    ("PoolDeposit", "replay", Cell::Pinned("a_pool_deposit_re_carried_by_a_rogue_producer_moves_the_peer_pool_once")),
    // ── PoolWithdraw (2026-10-03) ──
    // 2026-10-04 (lane-harness, `rogue_role_pins.rs`): the receipt deposited and landed, its withdrawal published; rogue
    // blocks judged on the peer's records + pool words; CONTROL: the honest withdrawal then lands on both nodes once.
    ("PoolWithdraw", "forge", Cell::Pinned("a_pool_withdrawal_with_a_forged_withdraw_leg_carried_by_a_rogue_producer_moves_no_peer_pool")),
    ("PoolWithdraw", "strip", Cell::Pinned("a_pool_withdrawal_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_moves_no_peer_pool")),
    ("PoolWithdraw", "substitute", Cell::Pinned("a_pool_withdrawal_whose_output_note_was_swapped_carried_by_a_rogue_producer_moves_no_peer_pool")),
    ("PoolWithdraw", "replay", Cell::Pinned("a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool")),
    // ── BURN — every class (2026-10-03). A retiring class's cell is Pinned only where the named test carries a refused
    //    or forged object naming a victim's id and asserts the PEER still lets the owner use it.
    ("PegIn", "burn", Cell::Pinned("db367_a_refused_peg_in_naming_a_deposit_does_not_stop_its_real_mint_on_a_peer")),
    ("OrderFill", "burn", Cell::Pinned("a_refused_fill_naming_a_victim_makers_lot_carried_by_a_rogue_producer_does_not_stop_the_real_fill_on_the_peer")),
    ("PegOut", "burn", Cell::Open("a refused peg-out naming a victim's USDm nullifier: the note must stay spendable on a peer — not pinned")),
    ("YieldClaim", "burn", Cell::Pinned("a_refused_yield_claim_naming_a_victims_stake_does_not_stop_its_real_claim_on_the_peer")),
    ("PoolDeposit", "burn", Cell::Pinned("a_refused_pool_deposit_naming_a_victims_note_does_not_stop_its_real_deposit_on_the_peer")),
    ("PoolWithdraw", "burn", Cell::Pinned("a_refused_pool_withdrawal_naming_a_victims_receipt_does_not_stop_its_real_withdrawal_on_the_peer")),
    ("WrappedMint", "burn", Cell::Pinned("a_refused_wrapped_mint_naming_a_deposit_does_not_stop_its_real_mint_on_the_peer")),
    ("Liquidation", "burn", Cell::Pinned("a_refused_liquidation_naming_a_position_does_not_stop_its_real_close_on_the_peer")),
    // ── TheftRepayment (§BR-3 17.5, 2026-10-29): every attack mounted on the PEER before the block in `br3175_repay` (each
    // refuter pin runs it): stripped attestations, a header whose split / pool burn / seize amount was substituted, a flipped
    // leg — each refused with nothing moved; then the honest repayment applies and its replay is refused. FORGE: a node that
    // booked no theft refuses the repayment a theft-holding node verifies. BURN: the object retires only its own repay_id,
    // a function of the state it moves, and the refused tampers did not stop the real one.
    ("TheftRepayment", "forge", Cell::Pinned("br3175_a_repayment_for_a_theft_that_never_folded_is_refused")),
    ("TheftRepayment", "strip", Cell::Pinned("br3175_a_theft_past_the_pot_and_buffer_is_absorbed_by_the_stability_pool_on_both_nodes")),
    ("TheftRepayment", "substitute", Cell::Pinned("br3175_a_theft_past_the_pot_and_buffer_is_absorbed_by_the_stability_pool_on_both_nodes")),
    ("TheftRepayment", "replay", Cell::Pinned("br3175_a_theft_past_the_pot_and_buffer_is_absorbed_by_the_stability_pool_on_both_nodes")),
    ("TheftRepayment", "burn", Cell::Pinned("br3175_a_theft_past_the_pot_and_buffer_is_absorbed_by_the_stability_pool_on_both_nodes")),
    // ── PotFill (§BR-3 17.5 layer 1, 2026-10-29): mounted on the PEER before the block — the custody half stripped, more SAT
    // than the burn pays for at the floor, a flipped retire leg — each refused with nothing moved; then the honest fill
    // applies on both nodes and its replay is refused (the burn's nullifier, refused by the spent set).
    ("PotFill", "forge", Cell::Pinned("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes")),
    ("PotFill", "strip", Cell::Pinned("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes")),
    ("PotFill", "substitute", Cell::Pinned("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes")),
    ("PotFill", "replay", Cell::Pinned("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes")),
    ("PotFill", "burn", Cell::Pinned("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes")),
    // ── DecoyBatch / DecoyReturn (§BR-8 B8-a, 2026-10-29): mounted on the PEER before each block — a third of the weight, a
    // decoy naming an unbonded validator, an amount the signers never signed, a return at an unbooked outpoint — each refused
    // with nothing opened or closed; a rogue third-weight batch through a block books nothing and the honest one still books;
    // the booked batch's replay is refused.
    ("DecoyBatch", "forge", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyBatch", "strip", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyBatch", "substitute", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyBatch", "replay", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyBatch", "burn", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyReturn", "forge", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyReturn", "strip", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyReturn", "substitute", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyReturn", "replay", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    ("DecoyReturn", "burn", Cell::Pinned("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes")),
    // ── UnitOpen (§BR-4 B4-2, 2026-10-29): mounted on the PEER before the block — a rewritten band, the custody signatures
    // stripped, a substituted unit note, a day the carrying block is not — each refused with nothing moved; the honest unit
    // opens on both nodes and its replay is refused (both deposit ids spent).
    ("UnitOpen", "forge", Cell::Pinned("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused")),
    ("UnitOpen", "strip", Cell::Pinned("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused")),
    ("UnitOpen", "substitute", Cell::Pinned("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused")),
    ("UnitOpen", "replay", Cell::Pinned("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused")),
    ("UnitOpen", "burn", Cell::Pinned("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused")),
    // ── UnitClose (§BR-4 B4-3, 2026-10-29): mounted on the PEER before the block — the burns lifted onto another ticket, the
    // custody half stripped, a debt one atomic short, a flipped release leg — each refused with nothing moved; the honest close
    // applies on both nodes and its replay is refused (both nullifiers spent).
    ("UnitClose", "forge", Cell::Pinned("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces")),
    ("UnitClose", "strip", Cell::Pinned("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces")),
    ("UnitClose", "substitute", Cell::Pinned("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces")),
    ("UnitClose", "replay", Cell::Pinned("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces")),
    ("UnitClose", "burn", Cell::Pinned("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces")),
    // ── §BR-15 (2026-11-02): the four DeFi classes, each attack mounted through a peer in ONE two-node journey — a settlement at
    // a tick above the rule's (forge), an over-claim and a claim stripped of its member leg (substitute, strip), the claim
    // replayed (replay), the order's burn retired once and its batch expired into a refund (burn).
    ("DefiOrder", "forge", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiOrder", "strip", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiOrder", "substitute", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiOrder", "replay", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiOrder", "burn", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiSettle", "forge", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiSettle", "strip", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiSettle", "substitute", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiSettle", "replay", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiSettle", "burn", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiExpire", "forge", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiExpire", "strip", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiExpire", "substitute", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiExpire", "replay", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiExpire", "burn", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiClaim", "forge", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiClaim", "strip", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiClaim", "substitute", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiClaim", "replay", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    ("DefiClaim", "burn", Cell::Pinned("br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes")),
    // §BR-15 §18.11 — the custody handover: a dealing of shares its commitment does not hold (forge), an acceptance whose new
    // pool is not its combination (substitute), a second dealing or acceptance for a filled slot (replay), a dealing without
    // its proof (strip), an order or settlement while the pool is frozen (burn: nothing moves) — each refused.
    ("DefiHandover", "forge", Cell::Pinned("br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles")),
    ("DefiHandover", "strip", Cell::Pinned("br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles")),
    ("DefiHandover", "substitute", Cell::Pinned("br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles")),
    ("DefiHandover", "replay", Cell::Pinned("br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles")),
    // §BR-15 §18.12 — the batch's slots: a slot whose proof or leg fails (forge), a slot stripped of its leg (strip), a claim
    // slot minting more than its fill (substitute), a nullifier twice or a second slots object (replay), a lone order or
    // claim outside slots (burn: refused at every door) — each refused.
    ("DefiSlots", "forge", Cell::Pinned("br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused")),
    ("DefiSlots", "strip", Cell::Pinned("br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused")),
    ("DefiSlots", "substitute", Cell::Pinned("br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused")),
    ("DefiSlots", "replay", Cell::Pinned("br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused")),
    ("DefiSlots", "burn", Cell::Pinned("br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused")),
    ("DefiHandover", "burn", Cell::Pinned("br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles")),
    ("AssetMint", "burn", Cell::Pinned("a_refused_asset_mint_naming_an_issuance_right_does_not_stop_the_creators_real_mint_on_the_peer")),
    ("AssetSpend", "burn", Cell::Pinned("a_refused_asset_transfer_naming_a_holders_note_does_not_stop_its_real_transfer_on_the_peer")),
    // RED 2026-10-04 15:56 / 16:09 (a refused, stranger-signed seat / unbond burned the real request's right — collateral
    // hostage) → GREEN 16:32 after lane-consensus DB-385 (`object_own_nullifiers` names no right for a request the named
    // key did not sign): the real seat and the real unbond land on both nodes.
    ("MembershipBond", "burn", Cell::Pinned("a_refused_seat_naming_a_validators_seat_right_does_not_stop_its_real_seat_on_the_peer")),
    ("Unbond", "burn", Cell::Pinned("a_refused_unbond_naming_a_validators_unbond_right_does_not_stop_its_real_unbond_on_the_peer")),
    // RED 2026-10-04 15:30 (0/0 rest: raw-lane retirement) → GREEN 16:09 after lane-consensus DB-383 (both retire sites
    // filter by the lane-justified tags): the order rests 1/1 and the lot still fills on both nodes.
    ("OrderPost", "burn", Cell::Pinned("a_rogue_producer_naming_a_makers_lot_tag_in_its_lane_does_not_cancel_the_resting_order_on_the_peer")),
    // 2026-10-07 (cf22f61): the USDm bond class is retired with its burn pin; it has no `object_own_nullifiers` arm, so a block
    // naming a victim's id in its lane under this class retires nothing of its own (checked against the source below).
    ("BondTransition", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm): validator bonds are SAT-only (`Node::USDM_BOND_RETIRED`), a USDm bond seats nothing whatever it carries")),
    // SATOSHI (2026-10-22, lane a): both classes RETIRE ids of their own (`object_own_nullifiers` arms: the reward's own
    // nullifier `satoshi::reward_nf`; a bond's locked-note nullifier and change clue), so neither burn cell may be NotApplicable.
    // ── SatDelegation (§BR-3 17.3, 2026-10-29): the conversion's own pins are `br3_*` in node::pins; the peer-level rogue cells
    // are named OPEN until mounted.
    ("SatDelegation", "forge", Cell::Pinned("a_delegation_minting_more_than_it_burns_carried_by_a_rogue_producer_moves_no_seat_on_the_peer")),
    ("SatDelegation", "strip", Cell::Pinned("a_delegation_stripped_of_its_burn_carrier_carried_by_a_rogue_producer_moves_no_seat_on_the_peer")),
    ("SatDelegation", "substitute", Cell::Pinned("a_delegation_whose_minted_note_was_swapped_carried_by_a_rogue_producer_moves_no_seat_on_the_peer")),
    ("SatDelegation", "replay", Cell::Pinned("a_delegation_re_carried_by_a_rogue_producer_raises_the_seat_once_on_the_peer")),
    // ── ReleaseAttestation (§BR-10, 2026-10-29): its own pins are `br10_*`; the peer-level rogue cells are open.
    ("ReleaseAttestation", "forge", Cell::Pinned("a_release_attestation_by_an_outsider_carried_by_a_rogue_producer_enters_no_peer_registry")),
    ("ReleaseAttestation", "strip", Cell::Pinned("a_release_attestation_stripped_of_its_signature_carried_by_a_rogue_producer_enters_no_peer_registry")),
    ("ReleaseAttestation", "substitute", Cell::Pinned("a_release_attestation_whose_hash_was_changed_carried_by_a_rogue_producer_enters_no_peer_registry")),
    ("ReleaseAttestation", "replay", Cell::Pinned("a_release_attestation_re_carried_by_a_rogue_producer_does_not_roll_back_the_peers_registry")),
    ("ReleaseAttestation", "burn", Cell::Pinned("a_refused_release_attestation_naming_a_builders_id_does_not_stop_its_real_attestation_on_the_peer")),
    // ── DeploymentSignal (§BR-10, 2026-10-29): its own pins are `br10_*`; the peer-level rogue cells are open.
    ("DeploymentSignal", "forge", Cell::Pinned("a_deployment_signal_signed_by_another_key_carried_by_a_rogue_producer_counts_nothing_on_the_peer")),
    ("DeploymentSignal", "strip", Cell::Pinned("a_deployment_signal_stripped_of_its_signature_carried_by_a_rogue_producer_counts_nothing_on_the_peer")),
    ("DeploymentSignal", "substitute", Cell::Pinned("a_deployment_signal_whose_bits_were_changed_carried_by_a_rogue_producer_counts_nothing_on_the_peer")),
    ("DeploymentSignal", "replay", Cell::Pinned("a_deployment_signal_re_carried_by_a_rogue_producer_counts_once_on_the_peer")),
    ("DeploymentSignal", "burn", Cell::Pinned("a_refused_deployment_signal_naming_a_validators_window_does_not_stop_its_real_signal_on_the_peer")),
    // ── EpochKeyDeal (§BR-9a, 2026-10-29): pinned the day the class landed; its own pins are `br9a_*`.
    ("EpochKeyDeal", "forge", Cell::Pinned("an_epoch_key_deal_signed_by_another_key_carried_by_a_rogue_producer_sums_nothing_on_the_peer")),
    ("EpochKeyDeal", "strip", Cell::Pinned("an_epoch_key_deal_stripped_of_its_signature_carried_by_a_rogue_producer_sums_nothing_on_the_peer")),
    ("EpochKeyDeal", "substitute", Cell::Pinned("an_epoch_key_deal_whose_public_part_was_changed_carried_by_a_rogue_producer_sums_nothing_on_the_peer")),
    ("EpochKeyDeal", "replay", Cell::Pinned("an_epoch_key_deal_re_carried_by_a_rogue_producer_sums_once_on_the_peer")),
    ("EpochKeyDeal", "burn", Cell::Pinned("a_refused_epoch_key_deal_naming_a_custodians_epoch_does_not_stop_its_real_deal_on_the_peer")),
    // ── EpochKeyFraud (§BR-9a, 2026-10-29): pinned the day the class landed, in rogue_role_pins (the bond lane's home).
    ("EpochKeyFraud", "forge", Cell::Pinned("epoch_key_fraud_evidence_against_an_honest_dealer_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("EpochKeyFraud", "strip", Cell::Pinned("epoch_key_fraud_evidence_stripped_of_a_share_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("EpochKeyFraud", "substitute", Cell::Pinned("epoch_key_fraud_evidence_with_a_substituted_share_carried_by_a_rogue_producer_slashes_no_one_on_the_peer")),
    ("EpochKeyFraud", "replay", Cell::Pinned("epoch_key_fraud_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer")),
    ("EpochKeyFraud", "burn", Cell::NotApplicable("its destruction is a SLASH of the convicted dealer's bond, not a retired id: it retires no id of its own (no `object_own_nullifiers` arm), and a convicted dealer is barred by the slashed set")),
    // ── SatSetAside (§BR-13, 2026-10-29): its own pins are `br13_*` in node::pins; the peer-level rogue cells are open.
    // ── BountyPayout (§BR-10 / spec §8.4, 2026-10-29): pinned the day the class landed
    ("BountyPayout", "forge", Cell::Pinned("a_bounty_signed_by_a_third_of_custody_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BountyPayout", "strip", Cell::Pinned("a_bounty_stripped_of_its_attestors_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BountyPayout", "substitute", Cell::Pinned("a_bounty_whose_note_was_swapped_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BountyPayout", "replay", Cell::Pinned("a_bounty_re_carried_by_a_rogue_producer_is_paid_once_on_the_peer")),
    ("BountyPayout", "burn", Cell::Pinned("a_refused_bounty_naming_a_real_nonce_does_not_stop_the_real_bounty_on_the_peer")),
    // ── DsolDeploy / DsolCall / DsolFeeUpdate (§BR-12, 2026-11-02: found by the bisect as a regression of 6654ce5) ──
    // ── DirEntry (audit F15; cells added 2026-11-11, the day the census named them) ──
    ("DirEntry", "forge", Cell::Pinned("dir_rogue_an_entry_signed_by_another_key_carried_by_a_rogue_producer_writes_nothing_on_the_peer")),
    ("DirEntry", "strip", Cell::Pinned("dir_rogue_an_entry_stripped_of_its_fee_carrier_carried_by_a_rogue_producer_writes_nothing_on_the_peer")),
    ("DirEntry", "substitute", Cell::Pinned("dir_rogue_an_entry_whose_change_was_swapped_carried_by_a_rogue_producer_writes_nothing_on_the_peer")),
    ("DirEntry", "replay", Cell::Pinned("dir_rogue_an_entry_re_carried_by_a_rogue_producer_applies_once_on_the_peer")),
    ("DirEntry", "burn", Cell::Pinned("dir_rogue_a_refused_entry_naming_the_payers_fee_note_does_not_stop_its_real_entry_on_the_peer")),
    // ── IonOrder, IonSettle (IonSwap pools; cells filed 2026-11-11, the day the classes were added) ── ONE pin
    // (`ion_pool_tx/node_tests.rs`) lays each false object in a rogue producer's block, one block each, and judges every
    // one on what the PEER holds afterwards: its contract-state root, its pending orders, its layer word, its pool row,
    // and that no note the false object carried sits in a record. Orders: a note that never existed under a lifted
    // membership (forge), the leg removed (strip), another floor under the proven leg with the seller's nullifier on
    // the lane (substitute, burn: the seller's real order then publishes). Settlements: a row the pool never had with
    // the payouts that row computes (forge, a lying prover), the buyer's payout note swapped for a thief's (substitute),
    // one payout note fewer (strip), the landed settlement and a stale one carried again (replay); burn: a settlement
    // retires only the id of its own bytes, so a false one names nobody's id, and the true one lands after all of them.
    ("IonOrder", "forge", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonOrder", "strip", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonOrder", "substitute", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonOrder", "replay", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonOrder", "burn", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonSettle", "forge", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonSettle", "strip", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonSettle", "substitute", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonSettle", "replay", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("IonSettle", "burn", Cell::Pinned("ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land")),
    ("DsolDeploy", "forge", Cell::Pinned("dsol_rogue_a_deploy_signed_by_another_key_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolDeploy", "strip", Cell::Pinned("dsol_rogue_a_deploy_stripped_of_its_fee_carrier_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolDeploy", "substitute", Cell::Pinned("dsol_rogue_a_deploy_whose_change_was_swapped_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolDeploy", "replay", Cell::Pinned("dsol_rogue_a_deploy_re_carried_by_a_rogue_producer_applies_once_on_the_peer")),
    ("DsolDeploy", "burn", Cell::Pinned("dsol_rogue_a_refused_deploy_naming_the_deployers_fee_note_does_not_stop_its_real_deploy_on_the_peer")),
    ("DsolCall", "forge", Cell::Pinned("dsol_rogue_a_call_signed_by_another_key_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolCall", "strip", Cell::Pinned("dsol_rogue_a_call_stripped_of_its_proof_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolCall", "substitute", Cell::Pinned("dsol_rogue_a_call_whose_publisher_note_was_swapped_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolCall", "replay", Cell::Pinned("dsol_rogue_a_call_re_carried_by_a_rogue_producer_applies_once_on_the_peer")),
    ("DsolCall", "burn", Cell::Pinned("dsol_rogue_a_refused_call_naming_the_callers_fee_note_does_not_stop_its_real_call_on_the_peer")),
    ("DsolFeeUpdate", "forge", Cell::Pinned("dsol_rogue_a_fee_cut_signed_by_a_non_deployer_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolFeeUpdate", "strip", Cell::Pinned("dsol_rogue_a_fee_cut_stripped_of_its_signature_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolFeeUpdate", "substitute", Cell::Pinned("dsol_rogue_a_fee_cut_whose_storage_root_was_swapped_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("DsolFeeUpdate", "replay", Cell::Pinned("dsol_rogue_a_fee_cut_re_carried_by_a_rogue_producer_applies_once_on_the_peer")),
    ("DsolFeeUpdate", "burn", Cell::Pinned("dsol_rogue_a_refused_fee_cut_naming_its_one_time_id_does_not_stop_the_deployers_cut_on_the_peer")),
    ("SatSetAside", "forge", Cell::Pinned("a_set_aside_over_the_bound_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("SatSetAside", "strip", Cell::Pinned("a_set_aside_stripped_of_its_carrier_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("SatSetAside", "substitute", Cell::Pinned("a_set_aside_whose_note_was_swapped_carried_by_a_rogue_producer_applies_nothing_on_the_peer")),
    ("SatSetAside", "replay", Cell::Pinned("a_set_aside_re_carried_by_a_rogue_producer_applies_once_on_the_peer")),
    ("SatSetAside", "burn", Cell::Pinned("a_refused_set_aside_naming_its_nullifier_does_not_stop_the_canonical_set_aside_on_the_peer")),
    // ── BondYieldClaim (§BR-3 17.6, 2026-10-29): its own pins are `br3_*` in node::pins; the peer-level rogue cells are open.
    ("BondYieldClaim", "forge", Cell::Pinned("a_bond_yield_claim_above_the_yield_owed_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BondYieldClaim", "strip", Cell::Pinned("a_bond_yield_claim_stripped_of_its_signature_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BondYieldClaim", "substitute", Cell::Pinned("a_bond_yield_claim_whose_note_was_swapped_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("BondYieldClaim", "replay", Cell::Pinned("a_bond_yield_claim_re_carried_by_a_rogue_producer_pays_once_on_the_peer")),
    ("BondYieldClaim", "burn", Cell::Pinned("a_refused_bond_yield_claim_naming_a_victims_index_does_not_stop_its_real_claim_on_the_peer")),
    ("SatDelegation", "burn", Cell::Pinned("a_refused_delegation_naming_a_victims_note_does_not_stop_its_real_delegation_on_the_peer")),
    // ── MinerPayout (§BR-11, 2026-10-28, lane funds-br14): the class entered the decoder with the miner pool; its ledger door
    // (`apply_miner_payout_at_fold` → `PegLedger::pay_miner_payout`) is pinned by `br11_every_block_of_a_quarter_pays_the_rate_
    // and_the_pool_conserves` (amount above/below the rate, another quarter, an uncoverable payout — refused, nothing moved) and
    // the object's own binding by `br11_a_payout_opens_its_own_note_and_a_tampered_one_is_refused`. The PEER-level rogue cells
    // (a rogue block carrying the tampered object, judged on a peer) are not yet mounted — each named OPEN.
    ("MinerPayout", "forge", Cell::Pinned("a_miner_payout_above_the_quarters_rate_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("MinerPayout", "strip", Cell::Pinned("a_miner_payout_stripped_of_its_owner_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("MinerPayout", "substitute", Cell::Pinned("a_miner_payout_whose_note_was_swapped_carried_by_a_rogue_producer_pays_nothing_on_the_peer")),
    ("MinerPayout", "replay", Cell::Pinned("a_miner_payout_re_carried_by_a_rogue_producer_is_paid_once_on_the_peer")),
    ("MinerPayout", "burn", Cell::Pinned("a_refused_miner_payout_naming_a_victims_note_does_not_stop_its_real_payout_on_the_peer")),
    ("SatoshiReward", "burn", Cell::Open("a refused reward whose lane names a VICTIM's nullifier, judged on the peer: the arm retires `satoshi::reward_nf`, derived from the reward's own key and index — whether a rogue can point it at another owner's note, and that the owner still spends on the peer, is not yet mounted")),
    ("SatBond", "burn", Cell::Open("a refused, stranger-signed SAT bond or re-bond naming V's locked or change note, carried by a rogue block: `a_stranger_signed_rebond_owns_no_nullifier_and_vs_own_owns_both` proves the ONE shared site (`object_own_nullifiers`) names no right for it; the peer-level pin (V's real bond still lands on the peer) is not yet mounted")),
    ("Equivocation", "burn", Cell::NotApplicable("its destruction is a SLASH of the accused's bond, not a retired id: an innocent's bond burned IS this class's forge cell")),
    ("FinalityVote", "burn", Cell::NotApplicable("retires no id of its own: a vote moves the finality floor, never a note, a bond or a one-shot right")),
    ("ReserveTheft", "burn", Cell::NotApplicable("its destruction is a SLASH of the accused custodian's bond, not a retired id: an innocent's bond burned IS this class's forge cell")),
    ("BridgeCredit", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm): its replay is refused by the credit ledger, not the spent set")),
    // 2026-10-04 18:0x: DB-388 (lane-consensus, in source) gives a creation a one-time id of its asset id in
    // `object_own_nullifiers`, so the class now RETIRES an id and its burn cell is live: a lane-only rogue block naming that
    // id (no creation) must not stop the honest creation registering on a peer. Pin written when DB-388 lands.
    ("AssetCreate", "burn", Cell::Pinned("a_rogue_producer_naming_a_creations_one_time_id_does_not_stop_its_real_creation_on_the_peer")),
    ("WrappedAssetRegister", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm)")),
    // SAFE AT SCALE — the custody vault merge (2026-11-10), every attack mounted on the PEER before the honest block: a
    // merge signed by one vault's quorum alone (forge), a merge with a sum proof removed (strip), a receiving pair that is
    // not the sum the proofs state (substitute), the settled merge carried again (replay) — each refused, the peer's
    // ledgers unmoved.
    ("VaultMerge", "forge", Cell::Pinned("safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultMerge", "strip", Cell::Pinned("safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultMerge", "substitute", Cell::Pinned("safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultMerge", "replay", Cell::Pinned("safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused")),
    // SAFE AT SCALE — the reserve cost (2026-11-10), every attack on the PEER's own ledger before the honest object: a
    // cost signed by another vault's quorum or under two thirds of its own (forge), a cost past the floor with its bound
    // proof removed (strip), a reserve after that is not the difference, or a fee the proof never named (substitute), the
    // booked cost carried again (replay: the pair it names moved; the lane's one-time id is the spent set's) — each refused.
    ("ReserveCost", "forge", Cell::Pinned("safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum")),
    ("ReserveCost", "strip", Cell::Pinned("safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum")),
    ("ReserveCost", "substitute", Cell::Pinned("safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum")),
    ("ReserveCost", "replay", Cell::Pinned("safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum")),
    ("ReserveCost", "burn", Cell::Pinned("safe_at_scale_a_forged_reserve_cost_naming_a_real_sweep_does_not_stop_its_honest_booking_on_the_peer")),
    ("VaultMerge", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm): its replay is refused by the pairs it names, which its own apply moves")),
    // SAFE AT SCALE, stage three — the rebalance (2026-11-12; spec §3g), every attack mounted on the PEER before the
    // honest block: a move signed by one vault's quorum alone, or by the two with no bound proof (forge); a move with a
    // sum proof removed (strip); a receiver that gains more than the giver gives — the two sides not sharing the part —
    // or a bound over the receiver's old totals (substitute); the settled move carried again (replay) — each refused,
    // the peer's ledgers unmoved.
    ("VaultRebalance", "forge", Cell::Pinned("safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultRebalance", "strip", Cell::Pinned("safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultRebalance", "substitute", Cell::Pinned("safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultRebalance", "replay", Cell::Pinned("safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused")),
    ("VaultRebalance", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm): its replay is refused by the pairs it names, which its own apply moves")),
    // SAFE AT SCALE, stage three — the custody key record (2026-11-11), every attack mounted on the PEER before the
    // honest block: a take signed by under two thirds of the vault, or by another vault's quorum (forge); a take or a
    // retire with its signatures removed (strip: the decode refuses an object with none); a take whose member list is
    // not the chain's — a stranger added, a leaver kept — or a retire of the current key or inside the address window
    // (substitute); the settled take or retire carried again (replay) — each refused, the peer's record unmoved, and
    // the leaver's collateral still held.
    ("VaultKey", "forge", Cell::Pinned("safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node")),
    ("VaultKey", "strip", Cell::Pinned("safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node")),
    ("VaultKey", "substitute", Cell::Pinned("safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node")),
    ("VaultKey", "replay", Cell::Pinned("safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node")),
    ("VaultKey", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm): its replay is refused by the record's pre-state its statement binds, which its own apply moves")),
    ("PriceMark", "burn", Cell::NotApplicable("retires no id of its own (no `object_own_nullifiers` arm)")),
];

/// The classes `chain_object::object_own_nullifiers` names an arm for — read out of the SOURCE TEXT (a census of the
/// code, never node state), so the burn universe cannot fall behind the code; the same reading
/// `value_creation::classes_that_carry_notes` does for notes.
#[must_use]
pub fn classes_that_retire_ids(src: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Some(start) = src.find("pub fn object_own_nullifiers") else { return out };
    let end = src[start..].find("\npub fn ").map_or(src.len(), |i| start + i);
    let body = &src[start..end];
    let mut rest = body;
    while let Some(i) = rest.find("Class::") {
        rest = &rest[i + 7..];
        let name: String = rest.chars().take_while(char::is_ascii_alphanumeric).collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// The burn universe against the code: a class with an `object_own_nullifiers` arm whose burn cell says it retires
/// nothing, and a retiring class whose burn cell is NotApplicable on any other ground, are both wrong — either way a
/// destruction door would read as covered. The source is the crate's own `chain_object.rs`, read as TEXT for this
/// census; an unreadable source is a gap, never silence.
#[must_use]
pub fn destruction_universe_gaps() -> Vec<String> {
    let Ok(src) = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/chain_object.rs")) else {
        return vec!["src/chain_object.rs could not be read, so the burn universe is UNCHECKED".to_string()];
    };
    destruction_gaps_against(&classes_that_retire_ids(&src), CELLS)
}

/// [`destruction_universe_gaps`] over a given retiring set and cell list (the calibration pin plants both).
fn destruction_gaps_against(retiring: &std::collections::BTreeSet<String>, cells: &[(&str, &str, Cell)]) -> Vec<String> {
    let mut gaps = Vec::new();
    if retiring.len() < 5 {
        gaps.push(format!("the retirement reader found only {} class(es) — a reader that finds nothing is green and worthless", retiring.len()));
    }
    for (class, attack, cell) in cells.iter().filter(|(_, a, _)| *a == "burn") {
        let says_nothing = matches!(cell, Cell::NotApplicable(why) if why.starts_with(RETIRES_NOTHING));
        if says_nothing && retiring.contains(*class) {
            gaps.push(format!("{class} × {attack}: the cell says it retires nothing, but `object_own_nullifiers` has an arm for it"));
        }
        if retiring.contains(*class) && matches!(cell, Cell::NotApplicable(_)) && !says_nothing {
            gaps.push(format!("{class} × {attack}: a retiring class's burn cell cannot be NotApplicable"));
        }
    }
    gaps
}

/// The cells still open: `(class, attack, what is missing)`.
#[must_use]
pub fn open_cells() -> Vec<(&'static str, &'static str, &'static str)> {
    CELLS
        .iter()
        .filter_map(|(c, a, cell)| match cell {
            Cell::Open(why) => Some((*c, *a, *why)),
            _ => None,
        })
        .collect()
}

/// Whether every class × attack has exactly one cell; the missing and the duplicated, by name.
#[must_use]
pub fn coverage_gaps() -> Vec<String> {
    let mut gaps = Vec::new();
    for class in Class::all() {
        let name = format!("{class:?}");
        for attack in ATTACKS {
            let n = CELLS.iter().filter(|(c, a, _)| *c == name && *a == attack).count();
            if n != 1 {
                gaps.push(format!("{name} × {attack}: {n} cell(s)"));
            }
        }
    }
    // the destruction side: every class whose CARRIED object retires ids at the fold (DB-367 `lane_justified`) has a
    // burn cell that does not claim otherwise
    gaps.extend(destruction_universe_gaps());
    gaps
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::{coverage_gaps, open_cells, Cell, CELLS};

    /// Every class the decoder knows has exactly one cell per attack — a class added tomorrow fails here until it is
    /// censused.
    #[test]
    fn every_chain_class_has_exactly_one_cell_for_every_attack() {
        let gaps = coverage_gaps();
        let open = open_cells();
        eprintln!(
            "[rogue-census] {} cell(s): {} pinned, {} not applicable, {} OPEN",
            CELLS.len(),
            CELLS.iter().filter(|(_, _, c)| matches!(c, Cell::Pinned(_))).count(),
            CELLS.iter().filter(|(_, _, c)| matches!(c, Cell::NotApplicable(_))).count(),
            open.len()
        );
        assert!(gaps.is_empty(), "⛔ the rogue-role census does not cover the chain's classes: {gaps:?}");
    }

    /// A pinned cell names a test that EXISTS in the tree, through the register's one reader (a renamed or deleted pin
    /// cannot keep counting).
    #[test]
    fn every_pinned_cell_names_a_test_that_exists() {
        let exists = crate::harness::e2e_claims::claimed_pins_that_exist();
        let missing: Vec<&str> = CELLS
            .iter()
            .filter_map(|(_, _, c)| match c {
                Cell::Pinned(p) if !exists(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert!(missing.is_empty(), "⛔ census cells name pins that do not exist: {missing:?}");
    }

    /// ⭐ THE DESTRUCTION UNIVERSE IS READ FROM THE RETIREMENT DOOR, AND THE CHECK FIRES. The reader finds the classes
    /// the code retires ids for (calibration: four with measured histories); the census agrees with the source today;
    /// and a planted lie — a retiring class whose `burn` cell claims it retires nothing, or a retiring class marked
    /// NotApplicable on another ground — is reported, so an empty gap list is not vacuous.
    #[test]
    fn the_destruction_universe_matches_the_retirement_door_and_a_planted_lie_is_caught() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/chain_object.rs")).unwrap();
        let retiring = super::classes_that_retire_ids(&src);
        for known in ["PegIn", "OrderFill", "AssetMint", "Liquidation"] {
            assert!(retiring.contains(known), "calibration: the reader must see `{known}` (found {retiring:?})");
        }
        let today = super::destruction_universe_gaps();
        assert!(today.is_empty(), "the census disagrees with the code: {today:?}");
        let planted: &[(&str, &str, Cell)] = &[
            ("PegIn", "burn", Cell::NotApplicable("retires no id of its own (planted lie)")),
            ("OrderFill", "burn", Cell::NotApplicable("a slash, not an id (planted)")),
            ("PriceMark", "burn", Cell::NotApplicable("retires no id of its own")),
        ];
        let gaps = super::destruction_gaps_against(&retiring, planted);
        assert_eq!(gaps.len(), 2, "both planted lies are reported and the honest row is not: {gaps:?}");
        eprintln!("[rogue-census] destruction universe: {} retiring class(es) {retiring:?}; planted lies caught: {}", retiring.len(), gaps.len());
    }
}

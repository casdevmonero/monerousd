// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE END-TO-END CLAIM GATE — "IT WORKS" MUST MEAN A REAL USER CAN MOVE THEIR MONEY.
//!
//! ⛔⛔⛔ WHY THIS EXISTS, IN THE USER'S OWN WORDS: *"you said all asset types were spendable but you/the
//! harness never checked the whole process to verify that spends of all asset types actually worked."*
//! They were right, and the record shows exactly how the claim was manufactured:
//!
//! * `dsol::tests::all_asset_types_unlimited_no_growth_and_trustless` registers 6,000 asset DESCRIPTORS
//!   across six kinds and asserts the registry's count and peak count. It is a correct and valuable
//!   no-growth measurement. **It never mints, never holds, never SPENDS, and never involves a second
//!   node** — yet its NAME claims every asset type works, and that is where the confidence came from.
//! * §AK was recorded as "assets CLOSED — the transfer object exists and both halves of its gate are
//!   enforced". Also true, also not the claim a user cares about. Measured later the same day: **no
//!   honest transfer could satisfy both gates at once** (§AO, a note had two identities) and **no live
//!   node can publish one** (§AQ, the node cannot fabricate a spender's witness).
//!
//! ⭐⭐⭐ THE STANDARD THIS GATE ENFORCES: **a unit test that a carrier verifies is not evidence that a
//! user can spend.** For every kind of value a person can hold on this chain, there must be a pin that
//! carries it along the WHOLE path and ends by asserting what a SECOND PARTY holds. Anything less is
//! declared `Unproven` with the blocker named, and the list may only ever shrink.
//!
//! ⛔ AND A PIN MAY NOT PROVE ITS CLAIM OVER AN EMPTY STATE. MEASURED the day this was written:
//! `note_witness::tests::e2e_node_serve_to_witness_book_matches_consensus_root` — the wallet's own
//! front↔back parity pin — compared the wallet's book root to the node's root while the node served ZERO
//! notes. Two empty trees are equal. The pin read green and proved nothing for months, because the wallet
//! had not compiled since §AG so its suite never ran.
//!
//! WHAT THIS IS NOT: it does not replace the seam census (`harness::seam`), which asks whether production
//! CALLS a subsystem. A class can be fully wired and still be unspendable — §AO and §AQ both were.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Can a real user actually move this kind of value, end to end, with a peer as the witness?
#[derive(Clone, Copy, Debug)]
pub enum Moved {
    /// ⭐⭐⭐ THE STRONGEST CLAIM: the named pin drives ≥2 REAL `usdmd-node` PROCESSES over their real
    /// RPC, peered over the real onion transport, and the SECOND PROCESS'S OWN SOCKET reported the
    /// outcome. Certified by `RealMesh::start` appearing in the pin's body — a thing an in-process
    /// fixture cannot fake, because it spawns an operating-system process.
    RealNodes(&'static str),
    /// The named pin carries this value the whole way and asserts on a SECOND PARTY — but IN PROCESS,
    /// against a simulated transport.
    ///
    /// ⛔ THIS IS WEAKER THAN IT READS, AND THE WEAKNESS COST US THREE TURNS ON 2026-09-16. A local
    /// mutation and a chain object look IDENTICAL when the second party shares your address space, which
    /// is the exact defect class this register exists to catch. Worse, a fixture that simply forgot to
    /// put its inputs on chain refuses for a FIXTURE reason and reads as a CHAIN verdict. Every entry
    /// here is a candidate for promotion to `RealNodes`; none of them is finished.
    CrossNode(&'static str),
    /// Nothing proves a user can move this yet. The reason names the BLOCKER, never the intention.
    Unproven(&'static str),
    /// ⭐⭐⭐ DB-197 — THIS ENTRY MOVES NO VALUE OF ITS OWN, so "can a user move it" is the wrong
    /// question to ask about it. The `&str` names the class that DOES carry the value.
    ///
    /// ⛔ WHY THIS VARIANT EXISTS, AND WHY IT IS NOT A WAY TO RAISE THE NUMBER. `OrderPost`'s own entry
    /// says it: *"A resting offer moves no value by itself — it is the FILL that pays… Kept in the
    /// register so nobody reads its absence as coverage."* Both halves of that are right, and together
    /// they made the criterion IMPOSSIBLE: `Unproven` is the only variant that keeps an entry visible,
    /// and every `Unproven` counts against *"value classes a user can move AT ALL"*, so the target of 22
    /// could never be reached no matter what anyone built. A criterion that cannot be met is not a
    /// standard — it is permanent red for a reason that is not a defect, and a permanent red is the
    /// thing this module says gets muted within a day.
    ///
    /// ⛔ THE BAR FOR USING IT IS DELIBERATELY NARROW: the entry's OWN text must state that it carries no
    /// value. It is NOT for a class whose value is carried by another path — `ble_tap_pay` looks like
    /// that case and is NOT one, because its entry refuses exactly that shortcut: *"THREE proven halves
    /// are not a proven journey — that addition is exactly how §AK was filed CLOSED while assets were
    /// unspendable twice over."* A journey with an unproven JOIN stays `Unproven`.
    NoValueOfItsOwn(&'static str),
}

/// ⛔ EVERY KIND OF VALUE A PERSON CAN HOLD. Shrink-only in the `Unproven` direction.
///
/// ⭐ The class list is DERIVED from `chain_object::Class` and `dsol::DsolKind` at test time, read from
/// the filesystem — never from this hand-written table. A register whose input is hand-maintained is
/// blind exactly where somebody forgot to add something, which is the failure it exists to catch.
pub const VALUE_CLASSES: &[(&str, Moved)] = &[
    // ── THE BASIC CHAIN ACTIONS — what a person does every day, and the first thing that must be safe.
    //
    // ⭐ THESE ARE NOT `chain_object::Class` VARIANTS, and they belong here anyway. "Is my money safe?"
    // is not only a question about value CLASSES; a send that cannot be received, a balance that does not
    // survive a restart, and a joining node that inherits the wrong spent-state each lose funds just as
    // completely as an unspendable asset. The register would be answering a narrower question than the
    // one people actually ask if it listed only what the enum happens to name.
    (
        "native_send",
        // ⭐ CRITERION 2 (2026-09-26): MEASURED GREEN on two real `usdmd-node` processes by `a_payment_sent_through_one_real_process_is_spendable_through_the_other`.
        // The in-process proof it replaces stays in the tree: `node_runtime::tests::cross_device_send_converges_full_spent_state_no_island`.
        Moved::RealNodes("a_payment_sent_through_one_real_process_is_spendable_through_the_other"),
    ),
    (
        "restart_persistence",
        // ⭐ RE-PROMOTED 2026-09-25 (DB-194). The deleted pin's replacement is written and green:
        // `da_seed_regen_tests::a_peer_that_restarts_still_holds_the_spent_state_it_grafted`. It is the
        // PEER that restarts — a producer remembering its own work proves nothing about the chain; the
        // failure that loses money is a RECEIVER coming back having lost the spent set, which would
        // re-admit a nullifier the chain already settled. The witness is the CONSENSUS nullifier root
        // (the order-free A_tip projection), not a local balance readout, and a third node that never
        // saw the block is carried as a control so the assertions cannot be vacuous.
        // ⭐ PROMOTED 2026-09-27 ([slotR2]): MEASURED GREEN on two real `usdmd-node` processes (node 821ef964,
        // harness dd25e12b, load1 18-29) by `a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin`
        // — one run, so it is a pass, not a rate. The in-process proof it replaces stays in the tree:
        // `da_seed_regen_tests::tests::a_peer_that_restarts_still_holds_the_spent_state_it_grafted`.
        Moved::RealNodes("a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin"),
    ),
    (
        "dsync_join",
        // ⭐ CRITERION 2 (2026-09-28): MEASURED GREEN on two real `usdmd-node` processes (node c3aa0a59, DB-346's warm
        // certificate in): the restarted joiner ADOPTED a peer's certified bundle and jumped past LIVE_CATCH_UP_DEPTH, then both
        // processes agreed at common positions. slotB18m2b rc=0 1001s: the restarted joiner's first and only join was 'adopted a peer's #29 DSYNC bundle', 1 adopt jumping 824 blocks (> depth 600), then h0=h1=1048 with 0 divergences at common positions
        // The in-process roundtrip stays in the tree: `two_nodes_instant_sync_roundtrip_serve_then_adopt`.
        // ⛔ DEMOTED 2026-10-03 (honest register): the claim certified a journey by its BODY, not by its result. Today BOTH
        // this real journey and its in-process roundtrip are RED and listed in `scratchpad/known-reds.txt` (pre-existing,
        // attributed in d3036df's round), and the journey's DSYNC certificate prove needs ~7 GB per node (DB-371), which a
        // 16 GB machine cannot hold twice. A row counts again when the journey passes on a build not older than the landed code.
        Moved::Unproven(
            "DSYNC join regressed: two_real_nodes_join_by_dsync… and two_nodes_instant_sync_roundtrip_serve_then_adopt are both \
             RED (known-reds, 2026-10-03); the certificate prove they need breaks phone-class RAM (DB-371)",
        ),
    ),
    (
        "jumped_node_spent_state",
        // ⭐ RE-PROMOTED 2026-09-25 (DB-194b) — AND THE OLD REASON WAS SIMPLY WRONG. It said "no
        // replacement exists in the tree". One does, it is green, and it is stronger than the claim:
        // `two_nodes_instant_sync_roundtrip_serve_then_adopt` has a fresh B adopt A's certified bundle
        // and then asserts B inherited A's spent state on THREE surfaces — `nullifier_root()`,
        // `nullifier_count()` and `sparse_acc.root_bytes()` — each with a non-vacuity arm proving A's
        // value had advanced past the empty root first, so B could only have it from the proof-bound
        // bundle. [[feedback_stale_note_guard]]: DEFAULT TO DONE and verify the live tree; a blocker
        // note is a past snapshot, and this one outlived the thing it described.
        // ⭐ CRITERION 2 (2026-09-28): MEASURED GREEN on two real `usdmd-node` processes (node 7948ed52, DB-346's warm
        // certificate in): after a DSYNC jump past LIVE_CATCH_UP_DEPTH the joiner's SPARSE nullifier view became present and
        // matched its accumulator, and the pair agreed at an equal tip set and fold count (the third surface of the in-process pin). MEASURED slotB20view2 (node-M3 7948ed52, harness 0dc04444, 762 s): a DSYNC jump of 831 blocks; the joiner's nullifier view present+matching after 180.2 s (a young chain; the warm is O(tags), so this is not criterion 7's 
        // The in-process roundtrip stays in the tree: `two_nodes_instant_sync_roundtrip_serve_then_adopt`.
        // ⛔ DEMOTED 2026-10-03 (honest register): this real journey and the in-process roundtrip it leans on are both RED and in
        // `scratchpad/known-reds.txt`; MEASURED 2026-10-03 the re-run reaped this journey after nine silent minutes.
        Moved::Unproven(
            "jumped-node spent state regressed: a_real_node_that_jumped_by_dsync_warms… and \
             two_nodes_instant_sync_roundtrip_serve_then_adopt are both RED (known-reds, 2026-10-03); DB-371 blocks the real run",
        ),
    ),
    (
        "OrderFill",
        // ⛔ DEMOTED 2026-09-17 BY A REAL-NODE MEASUREMENT, not by a doubt. Two real `usdmd-node`
        // processes, real onion peering: the order rested on node0 while its tx was refused
        // (`InvalidProof`), and the fill was refused at the burn gate on BOTH — `32 input(s) carried NO
        // absence proof`. The node is RIGHT; the in-process pin passed only because it plants its inputs
        // with `carry_notes_in_a_block_for_test`, a test-only door no user has. See
        // `two_real_nodes_peer_and_a_settlement_whose_inputs_the_chain_never_held_is_refused_by_both`.
        // ⭐⭐ DB-224 (2026-09-26) — PROMOTED IN PROCESS on a journey whose inputs a REAL route funded, run GREEN
        // (58.8 s). The funding:
        //   * the maker's USDm lot is a bridge credit PUBLISHED as a transaction (the faucet's own wrapper),
        //     crediting exactly the lot its note commits to;
        //   * the taker's input is a real WRAPPED MINT whose carrier proves the taker's own note.
        // Both ride blocks at the PRODUCTION record depth (32), and each membership bind is built from the
        // settling node's own served record: nothing is planted. A settles; C pools the gossiped settlement
        // and produces; B, fed only the wire, retires the order and refuses the replay at its pool and its
        // DEX door; no payout ciphertext rides the wire; C records the maker's payout exactly once.
        // ⭐ CRITERION 2 (2026-09-28): the real-node refusal above is ANSWERED — MEASURED GREEN on two real `usdmd-node`
        // processes (node 7948ed52). The maker's USDm lot is a real faucet drip (a BridgeCredit chain object)
        // sealed to the maker's own ML-KEM key; the taker pays with the first mint of a token created through the DSOL
        // route; both membership binds come from process 0's own served record; the order rests through process 0 and
        // reaches the other process's book; the fill SETTLES through process 0; the other process, which never saw the
        // submit, retires the order and places the maker's payout and the taker's payout and change; and the SAME fill
        // resubmitted is refused on BOTH with 409 ORDER_ALREADY_FILLED — the maker input's nullifier reads SPENT in that
        // process's view OR is claimed by its pool (the reply does not say which, so neither is claimed here). MEASURED [slotB22fill] 05:32-05:41 on node 7948ed52 / harness 2b59040e: process 0 answered the fill after 14.7 s of 503 holds; process 1 retired the order and placed the maker payout, taker payout and change after 78.7 s; replay HTTP 409 ORDER_ALREADY_FILLED on process 1 and process 0; 1 passed in 5
        // ⛔ NOT what this proves: a WALLET taking from the book. DB-349: the wallet's fill body used keys the door never
        // read (fixed, phase 1) and the door's step 4 needs the maker slot's owner, which no public order may carry —
        // phase 2 needs a BOUND maker clue (DB-351). The client here is the harness, holding both notes' keys.
        // The in-process pin stays in the tree: `db224_a_fill_whose_inputs_a_real_chain_funded_settles_on_a_peer_fed_only_the_wire`.
        // ⛔ 2026-10-03 AUDIT: this journey had been RED at its faucet drip (`NO_LOCATOR`, a bare key) while this row cited
        // it — a claim resting on a proof that no longer ran. Fixed (7c5ed8a: a findable receive address, the lot on the
        // grid) and RE-MEASURED GREEN 05:52–05:59 on a daemon built from the DB-368 tree (cb9ff4f: a carried fill is judged
        // by the one fill rule at its fold), same build on both processes.
        // DB-368's own pin: `dex_cross_party_scenarios::a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_
        // rogue_producer_carries_it`.
        Moved::RealNodes("a_fill_settled_through_one_real_process_retires_the_order_on_the_other_and_a_replay_is_refused_by_both"),
    ),
    (
        "AssetSpend",
        // ⭐⭐⭐ DB-216 (2026-09-25) — PROMOTED. A holder MOVES an asset and a second party proves it:
        // A creates and mints (DB-200/201), then publishes a transfer carrying BOTH real carriers — the
        // validity carrier over the minted note's own opening and the one-step membership carrier built
        // from the record B derived from the block, bound by `leaf_commit` — produces, and B grafts. B's
        // spent set moves and equals A's, B's record for the transfer block holds both outputs, and a
        // SECOND spend of the same note (new outputs, new bytes, same nullifier) is refused on B and on A.
        // Identical bytes would be refused by the settled-object set alone; different bytes can only be
        // refused by the spent set. The pin files no account targets (owners None), so recipient DISCOVERY on the
        // second node is not what it asserts — on real processes either.
        // ⭐ CRITERION 2 (2026-09-28): MEASURED GREEN on two real `usdmd-node` processes (node c3aa0a59). Process 1
        // admits the asset's first mint; process 0 — which learned the minted note only from that block — serves the note's
        // record address and in-record copath from its OWN record (the client refolds it); the transfer, built exactly as the
        // in-process pin builds it, publishes through process 0; process 1, which never saw the submit, places BOTH outputs;
        // and a second spend of the same note (new outputs, new bytes, same nullifier) is refused on BOTH processes with the
        // spent set's own reason ("the note is already spent"). CONTROL: neither process placed the outputs before the
        // transfer existed. MEASURED slotB21spend (harness 7d4bb9a5, 567 s): mint PUBLISHED on process 1 after 7.7 s of 503 holds; transfer PUBLISHED through process 0 after 8.1 s; both outputs placed on process 1 after 3.1 s; the second spend answered HTTP 422 ASSET_SPEND_REFUSED 'the n
        // The in-process pin stays in the tree: `a_published_asset_transfer_travels_to_a_second_node_and_a_second_spend_is_refused`.
        Moved::RealNodes("a_transfer_published_through_one_real_process_is_retired_by_the_other_and_a_second_spend_is_refused_by_both"),
    ),
    (
        "AssetCreate",
        // ⭐ DB-200 — PROVEN TO TRAVEL.
        // `asset_tx::a_published_asset_creation_travels_to_a_second_node_in_a_block`: A publishes the
        // creation, A produces ONE block, B grafts THAT BLOCK and is never handed the descriptor, and B's
        // `token_registry_root()` moves off empty and EQUALS A's. ⛔ WHAT HAD TO BE FIXED FIRST WAS NOT A
        // MISSING TEST. The admission door refused every creation unless `genesis_mint_allowance != 0`, and
        // that allowance is non-zero for exactly ONE genesis identity (the testnet prefix) — so no asset
        // could be created on mainnet at all. It is the USDm OPEN-MINT bound, and a creation mints no value:
        // its only note is the issue right `H(domain ‖ asset_id)`, and the block binding refuses a creation
        // carrying any other note. DB-200 removed it; the creator ML-DSA signature, the in-circuit asset-tag
        // binding and registry membership all still gate the MINT, so nothing that decides supply was
        // touched. ⛔ IN PROCESS, NOT REAL NODES: two `Node` structs in one address space, the exact weakness
        // this variant's own doc warns about. Promotion to `RealNodes` is unfinished work.
        // ⛔ DB-218: this slot held the prose above, so the pin-existence census could not find it and
        // the class was counted on the variant alone. It now names the pin exactly.
        // ⭐ CRITERION 2 (2026-09-26): MEASURED GREEN on two real `usdmd-node` processes by `a_real_second_node_registers_an_asset_it_only_saw_in_a_block`.
        // The in-process proof it replaces stays in the tree: `a_published_asset_creation_travels_to_a_second_node_in_a_block`.
        Moved::RealNodes("a_real_second_node_registers_an_asset_it_only_saw_in_a_block"),
    ),
    (
        "DirEntry",
        // Audit F15 (2026-11-10): a paid directory entry (a @username, a group handle, a profile, a handover) spends its
        // owner's USDm note: the entry's price is burned into the four fee pools and the rest returns as change.
        // `db274_two_nodes_that_apply_two_registrations_of_one_name_in_opposite_orders_hold_one_directory`: two PAID
        // claims of one name are carried by sibling blocks to two nodes that graft them in opposite orders; both nodes
        // resolve the name to ONE owner, hold one directory accumulator and EQUAL fee pools (both fees spent on both).
        // ⛔ IN PROCESS. The real-node proof is not a Rust pin and so cannot be named here: `scratchpad/net/names.py`,
        // `dir_priced.py` and the pay-by-name row (three real processes; the loser of a race reads its balance from a
        // cold restore of its seed), each recorded in `scratchpad/net/results.tsv` per build.
        Moved::CrossNode("db274_two_nodes_that_apply_two_registrations_of_one_name_in_opposite_orders_hold_one_directory"),
    ),
    (
        "IonOrder",
        // IonSwap pools (2026-11-11): an order burns its inputs (USDm, a token, or a pool's share note) and joins the
        // ledger's pending list. `a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes`: every order is built
        // with the welded spends a wallet builds, published at node A's door, carried in A's block and judged on node B
        // from the block alone; after every step both nodes hold one pending list, one layer word, one contract-state
        // root. ⛔ IN PROCESS. The real-node proof is `scratchpad/net/pool.py` (the wallet harness places the orders
        // through one process and reads its position from another), recorded per build in `scratchpad/net/results.tsv`.
        Moved::CrossNode("a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes"),
    ),
    (
        "IonSettle",
        // IonSwap pools (2026-11-11): a settlement pays a pool's pending orders. The same pin: node A forms each
        // settlement, its block carries it, node B recomputes it from its own ledger; both nodes then hold the same row
        // and every payout note in a folded record, and the provider's REMOVAL spends the share note the first
        // settlement paid it and holds its tokens and its USDm again on both nodes. ⛔ IN PROCESS (see `IonOrder`).
        Moved::CrossNode("a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes"),
    ),
    (
        "AssetMint",
        // ⭐ DB-201 — PROVEN TO TRAVEL.
        // `asset_tx::a_published_asset_mint_travels_to_a_second_node_in_a_block`: A creates the asset and
        // produces; B grafts that block; A then mints with a REAL WHIR carrier
        // (`prove_asset_mint_validity_bytes`), a real ML-DSA-65 signature by the keypair whose `pubkey_id`
        // the asset id derives from, and a registry membership path SELF-BUILT from the public creation
        // stream; A produces; B grafts THAT BLOCK and is never handed the mint. B's `nullifier_root()` moves
        // and EQUALS A's — B absorbed the retired ISSUANCE RIGHT from block bytes alone, which is what makes
        // an asset mintable once per right rather than repeatedly. ⛔ THE FIRST RED WAS THE PIN'S, NOT THE
        // CHAIN'S, and it is recorded because it would have become a false defect report: the note frontier
        // does NOT move for one mint note — `note_frontier_root()` advances only when a WHOLE 256-leaf record
        // folds (`record_note_payload_for` is the sole production appender), so asserting it read as 'the
        // mint did not travel' while the mint had travelled perfectly. The SPENT SET is the observable a mint
        // must move. The in-process proof stays in the tree (two `Node` structs in one address space).
        // ⭐ CRITERION 2 (2026-09-28): MEASURED GREEN on two real `usdmd-node` processes (matched set M1, node 426d64a8):
        // one process published the first mint and the OTHER refused a second mint of the same right from block
        // bytes alone (ASSET_MINT_REFUSED, "this asset has already been issued"):
        // slotB15 rc=0 390s: 1 passed; process 1 first mint PUBLISHED; process 0 second mint HTTP 422 ASSET_MINT_REFUSED already issued
        // ⛔ DEMOTED to CrossNode 2026-10-03 (honest register): RE-MEASURED RED twice on today's build. Process 0's ROUTE answered
        // "PUBLISHED" to the second mint (its canonical spent set could not yet say Spent: on real processes it is fed by
        // band proofs, the DB-371 prove work). The CHAIN still refuses it. Both are pinned in process on two nodes:
        // - `asset_tx::tests::a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer` (9aaa448): the fold's
        //   first-spender rule revokes the second note on the peer, and BOTH nodes' publishers refuse it (right = Spent).
        // It returns to RealNodes when this journey passes on a build not older than the landed code.
        Moved::CrossNode("a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer"),
    ),
    (
        "WrappedMint",
        // ⛔ THE ⭐ "PROVEN 2026-09-16" BANNER THAT STOOD HERE WAS REMOVED 2026-09-25: it described a pin
        // the Z-build then DELETED, and it sat directly above a `Moved::Unproven` value it contradicted.
        // A reader skimming the comment would have taken this class as covered.
        // [[feedback_code_hygiene_pillar]]: comments track the CURRENT model.
        //
        // ⭐ WHAT *IS* GREEN, so whoever re-proves this does not rebuild it: 
        // `chain_action_carriage_tests::a_wrapped_mint_carries_its_peg_transition_to_a_node_fed_only_the_chain`
        // drives `POST /wrapped_mint_execute`, has A produce, and a node fed ONLY the chain ends with the
        // same PEG STATE. That is the peg transition travelling — NOT this class's claim.
        //
        // WHAT THIS ROW ASKS FOR is the HOLDER journey: B must HOLD the minted note and then SPEND it, with
        // the two controls the Z-build's deleted pin carried (B must not hold the note before the block
        // carries it; neither party may hold the spend's output before the spend is published).
        // ⭐⭐ PROMOTED 2026-09-26 (DB-224 round), ON THE HOLDER JOURNEY THIS ROW ASKS FOR — WITH ITS TWO CONTROLS.
        // The old text said "no replacement exists in the tree"; one did: DB-219's
        // `a_wrapped_note_minted_to_a_holder_is_moved_and_a_node_fed_only_blocks_retires_it`. It lacked both
        // controls this row names, so DB-224 added them to that pin and it ran GREEN with them (the binary
        // that ran carries both control strings, built after the edit): (1) B does NOT hold the wrapped note
        // before any block carried it, then holds it from the mint block alone; (2) neither party holds the
        // transfer's outputs before the transfer is published, then B holds both from the transfer block; B's
        // spent set equals A's, and a second spend of the same note is refused on B and on A. ⛔ IN PROCESS,
        // NOT REAL NODES — the block is handed over as a struct, so B's note comes with it; across the real
        // wire a peer that never pooled the mint gets the note's PAYLOAD from the record lane (DB-224's wire pin
        // shows the peg transition itself travelling without it).
        // ⭐⭐⭐ CRITERION 2 (2026-09-28): MEASURED GREEN ON TWO REAL `usdmd-node` PROCESSES — M7, one snapshot of the live
        // tree (node f12258b5, harness f9f84999, EXIT 0 in 423 s). A REAL regtest Bitcoin Core deposit (0.02 BTC, mined
        // under 2 blocks), each operator's own price source for the asset, the custodian quorum's wrapped mint (done
        // after 40.5 s); process 1 places both of the holder's transfer outputs from the block alone 6.0 s after process
        // 0 took the transfer; a second spend of the wrapped note is refused on BOTH processes (HTTP 422
        // ASSET_SPEND_REFUSED "the note is already spent"). The in-process pin above stays as the fed-only-blocks proof.
        // (The one earlier real run, on M5, islanded its DSYNC joiner under heavy machine contention; this rerun on a
        // quiet machine passed — measured, not assumed.)
        Moved::RealNodes("a_wrapped_note_minted_against_a_real_bitcoin_deposit_is_moved_and_the_other_process_retires_it"),
    ),
    (
        "BridgeCredit",
        // ⭐⭐⭐ PROVEN 2026-09-16 — and the blocker had been gone for some time. The pin was `#[ignore]`d
        // with a SPEC reason ("fails until a bridge credit is a transaction any producer can include") and
        // stayed ignored AFTER that landed, because it exercised `record_note_payload` — the raw staging
        // call — instead of `bridge_credit_tx`, which every real deposit route already publishes through.
        // An `#[ignore]` with a SPEC reason is a promise to re-measure when the spec lands; nothing re-read
        // it, so a closed hole read as an open one. Pointed at the real door, it is green on the first run:
        // A accepts and never mines, B produces, both hold the deposit
        // (`a_bridge_credit_reaches_the_network_without_the_accepting_node_producing`, in process).
        // ⭐⭐⭐ ON REAL NODE PROCESSES (DB-224, 2026-09-26, 156 s): two real `usdmd-node` processes (sha16
        // 02873a6bae045f10). The drip is POSTed to process 0 (`published:true`, a BridgeCredit chain object),
        // and a real wallet whose ONLY node URL is process 1 reads 2,500,000,000 atomic SPENDABLE after
        // 27.5 s, with a CONTROL of 0 before the drip. So the credit crossed to the other process in a block
        // and that process applied and serves it. Two processes on one machine: not a scale claim.
        Moved::RealNodes("a_bridge_credit_posted_to_one_real_process_is_spendable_through_the_other"),
    ),
    (
        "YieldClaim",
        // ⛔ DB-237 (2026-09-26, read in code): no chain could harvest (rate 0), and one that could would have harvested
        // unstaked value (the stake bound nothing; a fresh principal re-harvested).
        // ⭐⭐⭐ DB-237 CLOSED (2026-10-02): the claim spends a hidden-tag STAKED note (a USDm note cannot earn: the gate
        // forces Δ = 0), pays exactly `floor(v · rate · Δ / D)` at the chain's GOVERNANCE rate
        // (`ChainParams::stake_reward_apr_bps`, checked at the fold), re-stakes the principal from the block's own epoch
        // (no interval paid twice), and mints the reward into the committed supply through the yield supply step (the
        // reserve's surplus backs it). MEASURED in process on two nodes: the reward note (50 = 1000 · 5 % · 1 year) and
        // the re-staked principal on BOTH, one committed supply, the custodian's opening advanced by exactly the reward;
        // a claim outside its epoch and a replay refused on both.
        Moved::CrossNode("db237_a_private_stake_and_its_claim_travel_to_a_peer_with_one_supply"),
    ),
    (
        "MembershipBond",
        // ⭐ §CW/§CY — a validator SEAT as a chain object, free while the reserve is zero, no founding
        // keys. "Movable" means: a seat published on one real node lands on a SECOND real node's
        // validator set from the block alone, and both derive the SAME set. MEASURED GREEN on two real
        // `usdmd-node` processes over onion peering, 2026-09-17 (runs 2, 4, 5, 6, 7 of the seat journey):
        // `node0 validators=2 (holds node1: true) · node1 validators=2 (holds node0: true)` within
        // seconds of the mesh forming. The first run measured `validators=0` on both — the seat rode the
        // block and `BASE_BOND_FLOOR=2000` refused it silently (§CY).
        // ⭐ RE-POINTED 2026-09-26 ON A FRESH MEASUREMENT. The journey above also runs a peg mint, and DB-240
        // makes that mint unattestable on today's tree (no price mark exists), so a seat proof must not ride
        // it. The seat-only pin below PASSED on two real processes (node sha16 8277d2fe, the gate-N build):
        // `[seat-real] after 15.5s seats: process 0=Some(2) process 1=Some(2)`, each read from its own socket.
        Moved::RealNodes("two_real_processes_each_hold_the_seat_the_other_published"),
    ),
    (
        "PegOut",
        // ⭐⭐⭐ PROVEN IN PROCESS 2026-09-17 (§DB item 3) — a REAL USDm note minted through the peg-in lane
        // is burned by its owner; the redeem quorum is GATHERED over the peg-out attestation lane (B
        // verifies the burn evidence and re-derives the commitments from its own opening before it
        // signs); A publishes with the 2-of-2 quorum, A's own block applies the burn, and a THIRD node
        // that never pooled the transaction releases the reserve AND deletes the note from the block
        // alone (the §BB burn bind the pin caught on its first run). Refutations in the same pin: the
        // executor alone is below threshold and moves nothing; a sealed release larger than the burn
        // carrier proves is refused by the custodian; a weightless key counts for nothing; the replay
        // after settlement is refused. Real-node certification still needs the seat journey's redeem
        // arm (the wallet-side burn witness) — `Moved::RealNodes` only then.
        // ⭐ CRITERION 2 (2026-09-27): MEASURED GREEN on two real `usdmd-node` processes by [slotB11] (node 426d64a8) and a
        // real regtest Bitcoin Core: a second real wallet on the OTHER daemon burned its USDm, both custodians signed the payout, and the BTC ARRIVED at the redeemer's address in Core's own wallet (the wallet-side burn witness this row asked for):
        // slotB16 rc=0 516s on matched set M1: 1 passed; a real wallet bought USDm with a BTC deposit on a 2-of-2 quorum, paid a second real wallet on the other node, which redeemed it and the BTC arrived from a real regtest Bitco
        // The in-process proof stays in the tree: `a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block`.
        Moved::RealNodes("a_real_wallet_deposits_real_bitcoin_mints_redeems_and_the_btc_arrives_from_a_real_bitcoin_core"),
    ),
    (
        "PriceMark",
        // DB-124's price mark is a real chain object — a ≥2/3 bond-weighted median of attested quotes,
        // without which the peg counted one atomic unit of ANY asset as one USDm and 1 XMR could mint
        // ~6.67 BILLION. Its gate is enforced and its unit tests are adversarial (a minority cannot move the
        // median, an unattested quote is refused). ⛔ 'The object exists and its gate is enforced' was NOT
        // movability — §AK was recorded exactly that way — so this row stayed Unproven until a pin carried a
        // mark to a PEER and showed that peer pricing a mint by it, which is what DB-224's pin below does.
        // ⭐⭐⭐ DB-224 (2026-09-26) — PROVEN TO TRAVEL, AND ACROSS THE WIRE, NOT ONLY IN PROCESS. A admits a
        // mark and produces; B — whose pool NEVER held the mark — is handed the block through its own
        // postcard codec (the bytes a real peer receives: `credit_set` rides in carriage form, `output_notes`
        // does not travel) and ends holding A's mark and PRICING by it: the largest mint the priced deposit
        // covers is covered, one unit more is refused, and the CONTROL shows B refusing to count the deposit
        // at all before the block. RED before DB-224 even in process (the DB-220 calibration pin
        // `a_price_mark_travels_in_a_block_and_the_peer_prices_a_mint_by_it`): `rehydrate_block_body` rebuilt
        // the set from B's empty pool and installed nothing. ⛔ IN PROCESS, NOT REAL NODES: two `Node`
        // structs, the wire modelled by the block's own codec.
        // ⛔⛔ DB-240 (2026-09-26) — DEMOTED BY ITS OWN PROMOTER, THE SAME DAY. The pin proves the CONSENSUS half
        // (a mark travels and a peer prices by it), but the pin BUILDS the mark itself: no production code
        // publishes one (every `price_mark_tx::as_pq_tx` / `PriceQuote` construction is in a test, and there
        // is no validator price feed, no route, no quote gathering). A class nothing in production can
        // publish is not movable AT ALL. And the absence is not idle: DB-124 makes `attest_peg_in` refuse
        // every unpriced mint, so with no mark there is no peg-in on a production chain.
        // ⭐ §21 (2026-10-30): the hand-set source named below is DELETED — each bonded validator now quotes what its own
        // sample of the onion price relays agrees on (`price_relay`), and `harness::flash_price` pins that no production line
        // reads a typed price. The entries below are the dated record of how the publisher was first measured.
        // ⭐⭐ DB-240 BUILT (2026-09-26 04:29) — THE PUBLISHER EXISTS AND ITS PIN IS GREEN. `src/price_quote.rs`
        // plus an additive node.rs seam, a runtime tick block and a `WireMsg::PriceQuote` arm. Each bonded
        // validator signs its OWN observation (`MONEROUSD_PRICE_QUOTES`, no default), quotes gather in a
        // bounded current-epoch book, and at >=2/3 of bonded weight — the door's own tally — any node
        // publishes the mark through `as_pq_tx` → `ingest_tx`. The pin runs that production publisher:
        //   * three equal validators;
        //   * B hears 1/3 and does not publish;
        //   * A hears 2/3 and publishes exactly once;
        //   * B applies A's mark from the wire block alone.
        // ⛔ Operator configuration is now the only thing between a chain and its marks; no live node has it
        // set yet. In process: `RealNodes` needs a run with quotes configured on each validator.
        // ⭐ CRITERION 2 (2026-09-26): MEASURED GREEN on two real `usdmd-node` processes by `two_real_validators_price_an_asset_and_both_processes_apply_the_same_mark`.
        // The in-process proof it replaces stays in the tree: `db240_a_price_quorum_gathered_over_the_lane_publishes_one_mark_a_peer_applies_from_the_wire`.
        Moved::RealNodes("two_real_validators_price_an_asset_and_both_processes_apply_the_same_mark"),
    ),
    (
        "PegIn",
        // ⭐⭐⭐ PROVEN IN PROCESS 2026-09-17 (§CZ/§DA) — the executor's mint is verify-only at execute
        // (`ConfidentialPublished`, nothing moves), the 2-of-2 quorum is GATHERED over the peg-in
        // attestation lane, A's OWN block applies the mint, B applies it from the block, and a THIRD
        // node that never pooled the transaction holds the deposit as minted and the note as spendable
        // from the block's carried credit set alone; the forged statement and the weightless key are
        // refused, the replay after settlement is refused, and the second mint (B's) travels back.
        // ⭐⭐⭐ ON REAL NODES (seat journey run 12, 2026-09-17, `usdmd_journey_seat_*`, 396 s): two real
        // `usdmd-node` processes over Tor — seats on both in 0.4 s; ARM 2 `node0 mint -> minted:true,
        // credited:true, mint_height:35, ALREADY_MINTED` (a 2-of-2 quorum gathered over the mesh);
        // ARM 3a the executor's replay refused; ARM 3b `node1 asked for the SAME deposit ->
        // minted:true, credited:true, mint_height:53, ALREADY_MINTED` after 23.9 s from the block
        // alone (no second mint published); ARM 4 node1 minted a fresh deposit with node0's
        // attestation (`mint_height:89`). Run 11 the day's earlier attempt failed ARM 3b under an
        // asymmetric Tor link (node1 ~340 blocks behind, the ~10 MB fold-band bundle never crossing)
        // — the mesh-catch-up class is filed (§DB-4/DB-5, the bundle band), not certified by this.
        // ⛔⛔ DB-240 (2026-09-26) — DEMOTED: THE PROOF ABOVE PREDATES THE RULE THAT NOW REFUSES IT. DB-124
        // (after 9/21) made `attest_peg_in` refuse any mint not covered by a >=2/3-attested price mark, and
        // no production code publishes one. MEASURED on today's tree: the in-process proof
        // `a_two_of_two_custody_quorum_gathers_its_attestations_over_the_lane_and_both_can_execute` panics at
        // "B attests the honest proposal" with `[peg-attest] ⛔ not signing: the mint is not covered by the
        // deposit's PRICED value … (no >=2/3 attested price mark)`, and so do the three other dd-lane mint
        // pins. The real-node journey's mint arm reaches the same refusal (it injects deposits, never a mark).
        // ⭐⭐ RE-MEASURED 2026-09-26 06:00 WITH A MARK ON CHAIN — CrossNode on its own in-process proof, GREEN.
        //   * DB-240 built the production publisher.
        //   * The dd fixture (`dd_price_asset`) prices asset 0 on both custodians through the graft door every node
        //     runs (`mark_price_attested`: the ≥2/3 tally and the median), with the bonded keys signing exactly
        //     the production reporter's quote.
        //   * With that, the pin passes end to end: B attests over the lane, A executes verify-only, A's block
        //     applies the mint, and a THIRD node that never pooled the peg-in applies it from the block's carried
        //     credit set.
        //   * The same fixture turned four more DB-124 reds green.
        // ⛔ NOT RealNodes: the 9/17 real-node proof predates DB-124, and a real run needs operators to configure
        // `MONEROUSD_PRICE_QUOTES` (the real PriceMark pin is the next step).
        // ⭐ CRITERION 2 (2026-09-27): MEASURED GREEN on two real `usdmd-node` processes by [slotB11] (node 426d64a8) and a
        // real regtest Bitcoin Core: a real 30 BTC regtest deposit to the custody reserve MINTED through the 2-of-2 quorum, priced by a mark each daemon's own reporter published from its operator source (MONEROUSD_PRICE_QUOTES):
        // slotB16 rc=0 516s on matched set M1: 1 passed; a real wallet bought USDm with a BTC deposit on a 2-of-2 quorum, paid a second real wallet on the other node, which redeemed it and the BTC arrived from a real regtest Bitco
        // The in-process proof stays in the tree: `a_two_of_two_custody_quorum_gathers_its_attestations_over_the_lane_and_both_can_execute`.
        Moved::RealNodes("a_real_wallet_deposits_real_bitcoin_mints_redeems_and_the_btc_arrives_from_a_real_bitcoin_core"),
    ),
    (
        "OrderPost",
        // ⭐ DB-197: re-filed from `Unproven` to `NoValueOfItsOwn` — the text is unchanged and still
        // true; what changes is that it no longer counts against a criterion asking whether a user can
        // MOVE it. It stays in the register, exactly as its own reason asks, so nobody reads its absence
        // as coverage.
        Moved::NoValueOfItsOwn(
            "A resting offer moves no value by itself — it is the FILL that pays, and that is OrderFill \
             above. Kept in the register so nobody reads its absence as coverage.",
        ),
    ),
    (
        "Liquidation",
        // ⭐ LIQUIDATION §10 v2 (2026-10-02) — the v1 re-mark door is DELETED (it lowered the supply with the notes still
        // out, and its own red-team pins measured a free seizure and a liability erasure). The v2 door verifies five welded
        // WHIR legs: the amount rule at the chain's mark, the pool burn, the pool step, the supply retire, the reserve
        // seizure. Journey, in process: `a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool`
        // (a real peg-in, a real pool deposit, the mark falls, A's custodian opening BUILDS the object — `build_liquidation`
        // — A frames it — `publish_liquidation` — and B, fed the block, holds one peg and one pool and refuses the replay).
        // ⭐ §10.2 (4) THE AUTOMATIC TRIGGER (2026-10-02): every bonded custodian derives the due liquidation from the chain's
        // mark and its own opening (`Node::due_liquidation`), signs it on its own (`own_liquidation_sigs`, the runtime's
        // price cadence), gossips it (`WireMsg::LiquidationSig`, gathered against each receiver's OWN state), and the
        // first custodian holding ≥2/3 proves the legs on a worker thread and frames (`NodeRuntime::liquidation_tick`).
        // The pin drives that exact sequence on two parties. Not yet promoted to RealNodes: no two-process run yet.
        Moved::CrossNode("a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool"),
    ),
    (
        "VaultMerge",
        // SAFE AT SCALE (2026-11-10): a thinned custody vault's ledgers are summed into another vault's by a block-carried
        // object both vaults' quorums sign; a peer fed only the block reaches the same pairs, and each forgery mounted on
        // the peer first is refused. In-process parties (two nodes); not yet a real-process run.
        Moved::CrossNode("safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused"),
    ),
    (
        "VaultRebalance",
        // SAFE AT SCALE, stage three (2026-11-12; spec §3g.1): part of one custody vault's ledger is carved into its slot
        // by the giver's quorum and taken by the receiver's under its bound proof (or taken back by the giver), each a
        // block-carried object; a peer fed only the blocks reaches the same pairs and slot, and each forgery mounted on
        // the peer first is refused. In-process nodes; not yet a real-process run.
        Moved::CrossNode("safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused"),
    ),
    (
        "VaultKey",
        // SAFE AT SCALE, stage three (2026-11-11): a vault's members take the key of their set and later retire the one
        // it replaced, by block-carried objects their own quorum signs; a peer fed only the blocks holds the same key
        // record, and a custodian that left gets its collateral back on that peer only once no alive key names it.
        // In-process nodes; not yet a real-process run (the custody lanes that publish it are the next step).
        Moved::CrossNode("safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node"),
    ),
    (
        "ReserveCost",
        // SAFE AT SCALE (2026-11-10): a vault's reserve falls by a public foreign fee under a proof and its own quorum; a
        // peer's own ledger judges and applies the same bytes. Two ledger parties; not yet carried by a block between
        // nodes (the sweep lanes that publish it are the next stage).
        Moved::CrossNode("safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum"),
    ),
    (
        "WrappedAssetRegister",
        // ⭐ CRITERION 2 (2026-09-26): MEASURED GREEN on two real `usdmd-node` processes by `two_real_validators_register_a_wrapped_asset_and_both_processes_apply_the_ratio`.
        // The in-process proof it replaces stays in the tree: `a_second_node_derives_the_ratio_from_the_block_object_and_refuses_a_forged_one`.
        Moved::RealNodes("two_real_validators_register_a_wrapped_asset_and_both_processes_apply_the_ratio"),
    ),
    (
        "stake_note",
        // ⛔ DB-237 (2026-09-26, read in code): a stake did not travel (a producer-only stake frontier) and bound nothing.
        // ⭐⭐⭐ DB-237 CLOSED (2026-10-02): a staked note is a HIDDEN-TAG note (`whir_rec_block::stake_tag(e0)` inside the
        // commitment), created by the ONE stake gate (stake / claim / unstake, wire-identical), carried by a block as a
        // chain object and applied at its fold on every node. MEASURED in process on two nodes: the staked note recorded
        // on the producer AND a peer fed only the blocks.
        Moved::CrossNode("db237_a_private_stake_and_its_claim_travel_to_a_peer_with_one_supply"),
    ),
    (
        "PoolDeposit",
        // ⭐ LIQUIDATION SPEC §10 (2026-10-02): a USDm holder moves value into a PSM's stability pool and holds a RECEIPT
        // note keyed to the pool's snapshot. MEASURED in process on two nodes: the receipt and the change on the executing
        // custodian AND a peer fed only the blocks, one pool (T advanced by the hidden deposit), the custodian's pool
        // opening advanced by exactly the deposit; a receipt keyed to an invented snapshot refused at the fold. The
        // receipt's WITHDRAWAL (the compounded USDm + the collateral gain) is the next object (§10.2 increment 2).
        Moved::CrossNode("a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool"),
    ),
    (
        "PoolWithdraw",
        // ⭐ LIQUIDATION SPEC §10.2 (2026-10-02): the receipt's holder withdraws the compounded USDm (the receipt's snapshot,
        // value and key hidden, §10.4). MEASURED in process on two nodes, the SAME journey pin: the 600 deposited comes
        // back as a USDm note on the executor AND a peer fed only the blocks, one pool (T back to 0), the custodian's opening
        // retired by exactly 600; a second withdrawal of the same receipt refused. Increment 2 requires a zero gain (no
        // liquidation can exist yet); the gain leg lands with the liquidation object.
        Moved::CrossNode("a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool"),
    ),
    (
        "bond_note",
        // ⛔⛔ DB-257 (2026-09-26): the pin this row cited, `an_unbond_must_travel_to_a_peer_or_the_weight_and_the_
        // bond_exist_twice`, admits its validator with `admit_validator` and locks NO note. It proves the WEIGHT
        // travels (the `Unbond` row keeps it for that). It never ran the bonded note's return. When that path
        // was driven (DB-257 pin 2), the returned note reached the producer only (A=true B=false), and a second
        // pin measured the door admitting a still-bonded note with NO unbond: the collateral left and the weight
        // stayed. Both are fixed. The row now cites the pin where an honest unbond's block carries the returned
        // note, B records it from that block, and the pair's membership accumulators agree.
        // ⛔⛔ DB-345 (2026-09-28, history): NO USER COULD BOND A NOTE. The only production path that locks a note is the USDm
        // bond (DB-313), and every door refused it (`validator::USDM_BOND_PAUSED`, deleted 10/02). Slot B19 MEASURED a validator-set
        // split on two real processes: node0 0, node1 300,000,000 after 421.8 s. The cited pin builds its bond with
        // `admit_validator`, not through any door, so it proves the RETURN mechanism, not a class a user can move. The row
        // stays Unproven while the pause holds, exactly like `stake_note` under DB-327. It is lifted by DB-274 (canonical
        // fold apply, §7's nine refutations answered) or DB-223 (membership in the block proof). The in-process return
        // pin stays in the tree: `db257_an_honest_unbond_returns_its_bonded_note_on_every_node_and_the_pair_agrees`.
        // ⭐ DB-345 LIFTED (2026-10-02): the pause is DELETED. A user's bond travels the production path: a real note carried
        // in a block and folded, the welded bond carrier, the one-step membership carrier over that record, the statement
        // signed by the vid's own key, the pool through the submit door's path, laid with its bond transition, and the
        // weight derived at each node's FOLD under the `MemberDoor::Fold` door (the named record folded before the bond's
        // block: one verdict on every node). MEASURED in process: 300,000,000 on the producer, on an in-order peer and on
        // a peer fed the bond block before its input's block (one fold pass). The note's RETURN is db257's pin. Promote to
        // `RealNodes` with the gate's bond step on two processes.
        // ⛔⛔⛔ RETIRED 2026-10-07 — VALIDATOR BONDS ARE SAT-ONLY (`Node::USDM_BOND_RETIRED`; the user's design question,
        // decided on architecture: a USDm bond is a claim on the reserve it would secure, DB-391, and two bond assets need a
        // price to add). No door admits a NEW USDm bond and no fold seats one; a seat that already exists keeps its unbond
        // and its note's return (db257, DB-409). The claim this row now carries is that the class moves NOTHING on any node:
        // a rogue producer lays a real USDm bond WITH its proven statement and neither the peer nor the rogue seats it.
        Moved::CrossNode("a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer"),
    ),
    // ⭐ THE REGISTER CAUGHT THIS CLASS THE MOMENT IT EXISTED. I added `Class::Unbond` and the
    // completeness test refused the suite until it was declared — which is precisely the failure mode it
    // was built for: a new value-bearing class added and left silently unproven.
    (
        "ble_tap_pay",
        // ⭐ CRITERION 2 (2026-09-27): THE JOIN, MEASURED GREEN on two real `usdmd-node` processes by
        // `a_charge_carried_over_the_tap_protocol_is_paid_and_the_merchants_node_holds_it` (node 09e531b0, harness
        // 25d29ffe, [tapjoin2] 08:31–08:37). The merchant's wallet on process B began a tap for its own address. The
        // payer's wallet on process A ran the payer half. Every tap crossing (ML-KEM key, ciphertext, the charge
        // sealed under their session, framed at the tap MTU by `moneropay_ble::tap_*`, the radio's own steps) was
        // RELAYED byte for byte between the two live wallet processes, which share nothing else. The payer opened
        // the charge and paid it with the ordinary send (admitted in 24.4 s). The merchant's spendable balance, read
        // through ITS OWN process, reached the charged 50,000,000 atomic after 30.9 s.
        // ⭐ RE-CERTIFIED IN ITS DB-319 FORM (2026-09-27 17:12–17:19; node 93c2fbf7, harness 187563e5, 424.8 s): that
        // first run paid with an ordinary send, a sibling of the path a user takes. DB-319 found that the real path
        // paid every tap twice (the radio call paid unverified, then the UI's verify→pay paid again) and paid an
        // UNSIGNED float. The pin now presents the ONE signed charge (`wallet_pos_charge`'s builder), opens it to
        // the payer gate's VERIFIED view, and pays through `tappay` = `wallet_pos_pay`: the gate again, then
        // exactly the signed atomic amount, in 0.3 s. The merchant's own process read 50,000,000 atomic after 46.4 s.
        // NOT CLAIMED, and still open: (1) the radio's physical layer (advertising, GATT, RSSI range). The frames
        // crossed by relay; the iPhone⇄Mac radio crossing is proven on hardware separately. (2) The node-TRANSPORT
        // half, for offline settlement over BLE fragments, is still UNPINNED: its §AZ pin
        // `a_spend_settles_on_both_devices_when_the_only_link_is_ble_fragments` was deleted 2026-09-22, and only
        // `ble_pump_ferries_whole_cells_between_two_node_transports_over_a_simulated_fragment_link` remains (cells
        // cross, no node joins). The payment here travelled the ordinary onion transport.
        // ⛔ DEMOTED 2026-10-03 (honest register): RE-MEASURED RED on today's build with a FRESH wallet harness (built from
        // 9ce19ed): "the payer's real wallet could not pay the opened charge (121.3s): this charge has expired — ask the merchant
        // to re-present it". The pay that took 0.3 s on 9/27 now outlives the charge. That is a real regression on the user's
        // path, and it is also against the sub-second PERFORMANCE pillar. With a stale (Sep 28) wallet it had failed
        // "MEMBERSHIP_PROOF_INVALID" instead.
        Moved::Unproven(
            "tap-to-pay regressed: the real wallet's pay took 121 s and the signed charge expired first (2026-10-03, fresh \
             wallet 9ce19ed); the pay path must finish inside the charge's validity window",
        ),
    ),
    (
        "Unbond",
        // ⭐ CRITERION 2 (2026-09-26): MEASURED GREEN on two real `usdmd-node` processes by `a_seat_unbonded_through_one_real_process_leaves_the_validator_set_of_both`.
        // The in-process proof it replaces stays in the tree: `an_unbond_must_travel_to_a_peer_or_the_weight_and_the_bond_exist_twice`.
        Moved::RealNodes("a_seat_unbonded_through_one_real_process_leaves_the_validator_set_of_both"),
    ),
    (
        "Equivocation",
        // ⭐ DB-266 CLOSED (2026-09-27): both vote doors QUEUE the conflicting cert (no local slash), the runtime pairs it
        // with the first cert it remembered and publishes the evidence, and every grafting node slashes from the block.
        // The apply-half pin `db266_equivocation_evidence_carried_by_a_block_slashes_the_validator_on_every_node` stays.
        // ⭐ CRITERION 2 (2026-09-27): MEASURED GREEN on two real `usdmd-node` processes (node 1f4bb815): a watchtower
        // reported process 0's double-sign to process 1 ONLY (`/report_equivocation`, DB-334) and BOTH slashed it:
        // [slotB12] 01:02 two real usdmd-node processes: CONTROL both held 2 seats; process 1 alone was sent the double-sign via /report_equivocation; after 3.0s process 0=Some(1) process 1=Some(1) (the never-t
        // The in-process proof stays in the tree: `db266_an_equivocation_seen_by_one_node_slashes_the_validator_on_every_node`.
        Moved::RealNodes("two_real_processes_slash_a_validator_whose_equivocation_one_of_them_was_told_of"),
    ),
    (
        "ReserveTheft",
        // ⛔ DB-274 P4b (§8.15, 2026-09-30): a reserve theft's evidence BURNS BONDS, so it is value-bearing like
        // `Equivocation`. It replaces `/slash_reserve_theft`'s LOCAL slash, which moved one node's validator set.
        // - The state it writes (bonds, the slashed set, the burned figure, unbonding) is ChainDerived and already
        //   compared by the authority book (`validator_bonds`, `validator_slashed`, `validator_slashed_burned`,
        //   `validator_total_bond`).
        // - The in-process pin `db274_p4b_the_reserve_theft_slash_travels_the_mesh_and_never_mutates_at_the_socket`
        //   carries the object in a block to a peer that never heard the route; it stays in the tree.
        // - ⭐ CRITERION 2, MEASURED GREEN 2026-09-30 09:31 on two real `usdmd-node` processes: the watchtower reported
        //   process 0's theft (both seats signing the v2 statement + offender) to process 1 ONLY through
        //   `/slash_reserve_theft`; "[theft-real] after 108.5s seats: process 0=Some(1) process 1=Some(1)" — the
        //   peer process that was never told slashed too. 1 passed in 403.2 s.
        Moved::RealNodes("two_real_processes_slash_a_reserve_thief_that_one_of_them_was_told_of"),
    ),
    (
        "SatoshiReward",
        // ⭐ SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md, 2026-10-05): the per-block mining reward, sealed to the operator wallet's
        // scan key. MEASURED in process on two nodes: the producer AND a peer fed only the blocks credit exactly the scheduled
        // reward; a reward at a wrong key, forged, doubled or replayed mints nothing extra on the peer (satoshi_pins).
        Moved::CrossNode("a_produced_block_mints_exactly_its_scheduled_sat_reward_on_the_producer_and_a_peer_fed_only_blocks"),
    ),
    (
        "SatBond",
        // ⭐ SATOSHI §8 — THE validator bond since 2026-10-07 (bonds are SAT-only, `Node::USDM_BOND_RETIRED`): a mining reward
        // locked as custody + finality weight. MEASURED in process on two nodes: the bond built from a reward seats its weight
        // on the producer and the peer (and a USDm carrier seats none); tampers seat nothing (satoshi_pins).
        Moved::CrossNode("a_sat_bond_built_from_a_mining_reward_seats_custody_weight_on_the_producer_and_the_peer_and_usdm_seats_none"),
    ),
    (
        "BondTransition",
        // DB-313 §3 (Class 17, 2026-09-28): the PRODUCER'S aggregate proof over every USDm bond a block carries. It
        // rides `bond_set` beside the bonds it states. The value a user moves is the bond itself (`MembershipBond`,
        // `Unbond`); this object only proves them. The register-completeness pin caught the row missing.
        Moved::NoValueOfItsOwn(
            "a block-level statement proving the block's bonds (note_transition::BondTransition); it carries no note \
             of its own and no pool door admits one, so the value it concerns is counted on MembershipBond / Unbond",
        ),
    ),
    // ── THE CLASSES THIS REGISTER DID NOT LIST (audit, lane goods, 2026-11-11): its completeness test stood RED on main for
    //    25 classes. Each row names the two-node pin the rogue-role census already holds for the class, and only where
    //    that pin was read GREEN in the filing lane's own run; a class whose pin was red or not run says so as its blocker.
    (
        "DsolDeploy",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("dsol_rogue_a_deploy_re_carried_by_a_rogue_producer_applies_once_on_the_peer"),
    ),
    (
        "DsolCall",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("dsol_rogue_a_call_re_carried_by_a_rogue_producer_applies_once_on_the_peer"),
    ),
    (
        "DsolFeeUpdate",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("dsol_rogue_a_fee_cut_re_carried_by_a_rogue_producer_applies_once_on_the_peer"),
    ),
    (
        "FinalityVote",
        Moved::NoValueOfItsOwn("a finality vote moves no note and no balance: it raises the height under which fork choice refuses a reorg. What a person holds moves by the spend and object classes, each with its own entry here"),
    ),
    (
        "MinerPayout",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("a_miner_payout_re_carried_by_a_rogue_producer_is_paid_once_on_the_peer"),
    ),
    (
        "SatDelegation",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("a_delegation_re_carried_by_a_rogue_producer_raises_the_seat_once_on_the_peer"),
    ),
    (
        "BondYieldClaim",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("a_bond_yield_claim_re_carried_by_a_rogue_producer_pays_once_on_the_peer"),
    ),
    (
        "BountyPayout",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("a_bounty_re_carried_by_a_rogue_producer_is_paid_once_on_the_peer"),
    ),
    (
        "SatSetAside",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("a_set_aside_re_carried_by_a_rogue_producer_applies_once_on_the_peer"),
    ),
    (
        "DeploymentSignal",
        Moved::NoValueOfItsOwn("a validator's signal for a protocol version: it counts toward an activation and moves no note, bond or balance. The value a version's rules then move is carried by the classes those rules govern"),
    ),
    (
        "ReleaseAttestation",
        Moved::NoValueOfItsOwn("a builder's attestation of a release's digest, kept in the release registry: it moves no note, bond or balance. A wallet reads it to judge an update; the value at stake moves by the spend classes"),
    ),
    (
        "EpochKeyDeal",
        Moved::NoValueOfItsOwn("a custodian's dealing of an epoch key share (public commitments and sealed shares): it moves no note or balance. The orders that epoch key later opens carry the value (DefiOrder, DefiSlots)"),
    ),
    (
        "EpochKeyFraud",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("epoch_key_fraud_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer"),
    ),
    (
        "TheftRepayment",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br3175_a_theft_past_the_pot_and_buffer_is_absorbed_by_the_stability_pool_on_both_nodes"),
    ),
    (
        "PotFill",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br3175_the_pot_sells_at_the_floor_and_retires_its_proceeds_on_both_nodes"),
    ),
    (
        "DecoyBatch",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes"),
    ),
    (
        "DecoyReturn",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br8_decoys_are_booked_returned_and_an_unreturned_decoy_is_slashed_on_both_nodes"),
    ),
    (
        "UnitOpen",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br4_a_debt_unit_opens_on_both_nodes_at_its_own_110_percent_and_a_thin_or_misbanded_unit_is_refused"),
    ),
    (
        "UnitClose",
        // the rogue-role census's REPLAY cell for this class: carried to a peer, it applies there once, and the peer's own
        // state is asserted. ⛔ IN PROCESS (two nodes in one address space); green in lane goods' run of 2026-11-11.
        Moved::CrossNode("br4_a_debt_unit_closes_on_both_nodes_and_its_collateral_is_booked_for_release_in_ladder_pieces"),
    ),
    (
        "DefiOrder",
        Moved::Unproven("its two-node pin `br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes` is RED on lane goods' tree over main 9486d6f0 (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
    (
        "DefiSettle",
        Moved::Unproven("its two-node pin `br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes` is RED on lane goods' tree over main 9486d6f0 (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
    (
        "DefiExpire",
        Moved::Unproven("its two-node pin `br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes` is RED on lane goods' tree over main 9486d6f0 (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
    (
        "DefiClaim",
        Moved::Unproven("its two-node pin `br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes` is RED on lane goods' tree over main 9486d6f0 (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
    (
        "DefiHandover",
        Moved::Unproven("its two-node pin `br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles` was not run green by the lane that filed this row (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
    (
        "DefiSlots",
        Moved::Unproven("its two-node pin `br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused` was not run green by the lane that filed this row (2026-11-11): until it is green nothing here shows this class reaching a peer"),
    ),
];

fn src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &PathBuf, out: &mut Vec<(String, String)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                if let Ok(t) = fs::read_to_string(&p) {
                    out.push((p.to_string_lossy().into_owned(), t));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&src_root(), &mut out);
    out
}

/// The body of `fn <name>(` through its matching closing brace, from anywhere in the tree.
/// ⭐⭐⭐ DB-218 — THE ONE READER THAT DECIDES WHETHER A CLAIM'S PIN EXISTS, shared by the register's own
/// completeness test AND the readiness criterion that counts proven classes.
///
/// ⛔ MEASURED 2026-09-25: `every_movable_claim_names_a_pin_that_exists` went RED on two entries whose
/// payload was PROSE rather than a test name (AssetCreate, AssetMint), while criterion 1 counted both as
/// proven — because the count read only the VARIANT and never asked whether the named pin exists. That is
/// DB-196's class (a criterion reading green while the census behind it is red) on the value-class row.
/// With ONE reader, a claim naming no real pin cannot be counted, by construction.
#[must_use]
pub(crate) fn claimed_pins_that_exist() -> impl Fn(&str) -> bool {
    let files = source_files();
    move |pin: &str| test_body(pin, &files).is_some()
}

/// ⛔⛔⛔ THE JOURNEY LEDGER (user 2026-10-03: "weve already tested most of our register on real nodes already but since the
/// register didnt track passing youve been going in circles"). `scratchpad/lane_run.sh` appends one row per real-node
/// journey RUN, chronologically: `ts ⇥ journey ⇥ HEAD ⇥ daemon_built_unix ⇥ wallet_built_unix ⇥ PASS|FAIL ⇥ source`.
/// `source` is `run` (lane_run recorded it), or `backfill` (a pass the register's own MEASURED line documents, entered
/// once on 2026-10-03 from that line's date and build).
pub const JOURNEY_PASS_LEDGER: &str = "scratchpad/journey-passes.tsv";

/// ⛔⛔⛔ A REAL-NODE ROW COUNTS WHILE ITS MOST RECENT RECORDED RUN PASSED.
///
/// MEASURED 2026-10-03: `Moved::RealNodes` was certified by the pin's BODY (it spawns the real binary), never by its RESULT.
/// - The OrderFill row cited a journey that failed at its faucet drip for days.
/// - Tap-to-pay regressed from 0.3 s to 121 s unseen.
/// - Earlier passes were also never COUNTED as evidence, so every round re-argued rows that had been proven.
///
/// THE RULE: the LATEST recorded run of a row's journey decides. A failed re-run demotes the row automatically, and a later
/// pass restores it. Every run is on binaries no older than the landed code: the harness refuses a stale node or wallet
/// binary (`real_node_journey::binary_predates_landed_sources`). Fail-closed: no ledger, or no run, means the row does not
/// count.
#[must_use]
pub(crate) fn real_node_pins_whose_latest_run_passed() -> impl Fn(&str) -> bool {
    let ledger = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|r| r.join(JOURNEY_PASS_LEDGER))
        .and_then(|p| fs::read_to_string(p).ok());
    // The LATEST verdict per journey (rows are appended in time order, so the last one wins).
    let mut latest: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for line in ledger.as_deref().map(str::lines).into_iter().flatten() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 {
            continue;
        }
        match f[5] {
            "PASS" => latest.insert(f[1].to_string(), true),
            "FAIL" => latest.insert(f[1].to_string(), false),
            _ => None,
        };
    }
    move |pin: &str| latest.get(pin).copied().unwrap_or(false)
}

/// The journeys whose LATEST ledger row is a PASS entered by backfill (a documented pass, not yet re-run since the ledger
/// began). They count, and they are the first the nightly batch re-verifies. The report names them so a backfilled row
/// is never mistaken for a fresh measurement.
#[must_use]
pub(crate) fn real_node_pins_counting_on_backfill() -> Vec<String> {
    let ledger = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|r| r.join(JOURNEY_PASS_LEDGER))
        .and_then(|p| fs::read_to_string(p).ok());
    let mut latest: std::collections::BTreeMap<String, (String, String)> = std::collections::BTreeMap::new();
    for line in ledger.as_deref().map(str::lines).into_iter().flatten() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() >= 7 && (f[5] == "PASS" || f[5] == "FAIL") {
            latest.insert(f[1].to_string(), (f[5].to_string(), f[6].to_string()));
        }
    }
    latest.into_iter().filter(|(_, (v, s))| v == "PASS" && s == "backfill").map(|(j, _)| j).collect()
}

/// Does this pin START REAL NODES? See [`with_direct_helpers`].
fn starts_real_mesh(body: &str, files: &[(String, String)]) -> bool {
    with_direct_helpers(body, files).contains("RealMesh::start")
}

/// ONE reading of what a pin does, for every register check: its own body PLUS the bodies of the local helpers it
/// calls directly. It follows exactly one level, so a claim cannot be laundered through a chain of wrappers.
/// MEASURED 2026-09-28: the peg pins `a_real_wallet_deposits_real_bitcoin_…` delegate their whole journey to
/// `wallet_money_path_on_real_nodes` (the mesh at its line 2142, the peg doors and the second-party asserts inside it).
/// Three checks read the literal body alone and reported them as in-process, faucet-only and one-party. Each check
/// asked the right question of the wrong text.
fn with_direct_helpers(body: &str, files: &[(String, String)]) -> String {
    let mut text = body.to_string();
    // Every `ident(` the body calls, taken from the text: an identifier run ending right before a '('.
    let b = body.as_bytes();
    let mut called: Vec<&str> = Vec::new();
    for (i, &c) in b.iter().enumerate() {
        if c != b'(' {
            continue;
        }
        let end = i;
        let mut start = i;
        while start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_') {
            start -= 1;
        }
        if start < end {
            called.push(&body[start..end]);
        }
    }
    called.sort_unstable();
    called.dedup();
    for helper in called
        .into_iter()
        .filter(|f| f.chars().next().is_some_and(|c| c.is_ascii_lowercase()))
        .filter_map(|f| test_body(f, files))
    {
        text.push('\n');
        text.push_str(&helper);
    }
    text
}

/// A REAL-PROCESS pin's second party: it starts real processes (`RealMesh::start`) and reads a process by an index that
/// is not a hard-coded `0` (`.get(1, …)`, or `.get(i, …)` in a loop over every process). The in-process vocabulary above
/// (`let mut b`, `b.ingest_block(`) never matches a real pin, so every one of them was flagged one-party.
/// MEASURED 2026-09-28: the restart, fill and equivocation pins each read process 1 or every process, and were
/// reported as having no second party.
fn reads_a_second_real_process(text: &str) -> bool {
    if !text.contains("RealMesh::start(") {
        return false;
    }
    let handle = "mesh.";
    let mut rest = text;
    while let Some(at) = rest.find(handle) {
        let after = &rest[at + handle.len()..];
        let ident_len = after.bytes().take_while(|c| c.is_ascii_alphanumeric() || *c == b'_').count();
        if let Some(args) = after[ident_len..].strip_prefix('(') {
            let first = args.trim_start();
            let arg: String = first.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !arg.is_empty() && arg != "0" && (arg == "1" || arg.chars().all(|c| c.is_ascii_lowercase() || c == '_')) {
                return true;
            }
        }
        rest = &after[ident_len..];
    }
    false
}

fn test_body(name: &str, files: &[(String, String)]) -> Option<String> {
    // ⭐ A REGISTER ENTRY NAMES A PIN THE WAY A HUMAN WOULD (`module::tests::the_pin`), and the file holds
    // only `fn the_pin(`. Taking the last segment is what makes the two agree — and this gate caught its
    // OWN first two claims as "pin does not exist" because of it, which is the behaviour you want from a
    // standard: it fails on its author before it fails on anyone else.
    let bare = name.rsplit("::").next().unwrap_or(name);
    let needle = format!("fn {bare}(");
    for (_, txt) in files {
        let Some(at) = txt.find(&needle) else { continue };
        let Some(open) = txt[at..].find('{').map(|k| at + k) else { continue };
        let b = txt.as_bytes();
        let mut depth = 0i32;
        let mut p = open;
        while p < b.len() {
            match b[p] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(txt[open..=p].to_string());
                    }
                }
                _ => {}
            }
            p += 1;
        }
    }
    None
}

/// Every `Class` variant declared in `chain_object.rs` — read from the file, never hand-listed.
fn declared_chain_classes(files: &[(String, String)]) -> Vec<String> {
    let Some((_, txt)) = files.iter().find(|(p, _)| p.ends_with("/chain_object.rs")) else {
        return Vec::new();
    };
    let Some(at) = txt.find("pub enum Class {") else { return Vec::new() };
    let tail = &txt[at..];
    let end = tail.find("\n}").unwrap_or(tail.len());
    tail[..end]
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.starts_with("//") || t.starts_with('/') {
                return None;
            }
            let name: String = t.chars().take_while(|c| c.is_alphanumeric()).collect();
            (!name.is_empty() && name.chars().next()?.is_uppercase()).then_some(name)
        })
        .collect()
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// ⭐ THE REGISTER'S INPUT IS THE CODE, NOT THIS FILE. A new value-bearing class cannot be added to
    /// the chain and left silently unproven.
    #[test]
    fn every_value_bearing_chain_class_is_in_the_register() {
        let files = source_files();
        let classes = declared_chain_classes(&files);
        assert!(
            classes.len() >= 8,
            "the Class enum was not parsed ({} found) — the register's input is broken, so its verdicts \
             are worthless",
            classes.len()
        );
        let missing: Vec<&String> = classes
            .iter()
            .filter(|c| !VALUE_CLASSES.iter().any(|(n, _)| n == &c.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ CHAIN OBJECT CLASS(ES) WITH NO ENTRY IN THE END-TO-END REGISTER: {missing:?}. Every kind \
             of value a user can hold must declare whether a REAL USER CAN MOVE IT. Add each with a \
             `Moved::CrossNode(pin)` naming the pin that carries it to a peer, or `Moved::Unproven(why)` \
             naming the blocker. ⛔ 'the object exists and its gate is enforced' is not movability — §AK \
             was recorded exactly that way and assets turned out to be unspendable twice over."
        );
    }

    /// ⛔ A CLAIM MUST NAME A PIN THAT EXISTS. A register entry pointing at a test that was renamed or
    /// deleted is a claim with nothing behind it, and it reads identically to a real one.
    #[test]
    fn every_movable_claim_names_a_pin_that_exists() {
        let files = source_files();
        let missing: Vec<&str> = VALUE_CLASSES
            .iter()
            .filter_map(|(_, m)| match m {
                Moved::RealNodes(pin) | Moved::CrossNode(pin) => {
                    test_body(pin, &files).is_none().then_some(*pin)
                }
                // DB-197: neither names a pin, so neither can have a MISSING one.
                Moved::Unproven(_) | Moved::NoValueOfItsOwn(_) => None,
            })
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ THESE PINS ARE CLAIMED AS PROOF AND DO NOT EXIST: {missing:?}. Either the test was \
             renamed (update the register) or the claim was never true."
        );
    }

    /// ⭐⭐ THE CROSS-NODE CARDINAL, AS FAR AS READING SOURCE TEXT CAN TAKE IT.
    ///
    /// ⛔⛔⛔ BE CLEAR ABOUT WHAT THIS GATE IS: it greps each pin's BODY for the substring `"assert"`
    /// beside a peer-ish name. It never RUNS the pin, never starts a node, and cannot see whether the
    /// "second party" is a separate process or another struct in the same address space. It catches a
    /// pin that forgot to assert at all. It CANNOT catch a pin whose second party shares its memory,
    /// which is the shape that let the maker's lot pay out twice, and it CANNOT catch a fixture that
    /// refuses because its own setup is incomplete — measured 2026-09-16, three turns spent re-closing
    /// a closed item on a fixture's refusal. **`Moved::RealNodes` is the variant that answers those two,
    /// and it is answered by `RealMesh::start` spawning a real process.**
    ///
    /// MEASURED 2026-09-03 and never to be repeated: two honest nodes each self-verified the SAME DEX
    /// fill, both were right to accept it, and the maker's lot paid out TWICE — because the burn was a
    /// local mutation and never travelled. **A test that asserts on what a call RETURNS proves nothing.**
    #[test]
    fn a_pin_that_claims_a_user_can_move_value_asserts_on_a_second_party() {
        let files = source_files();
        let mut weak: Vec<(&str, &str)> = Vec::new();
        for (class, m) in VALUE_CLASSES {
            let (Moved::CrossNode(pin) | Moved::RealNodes(pin)) = m else { continue };
            let Some(body) = test_body(pin, &files).map(|b| with_direct_helpers(&b, &files)) else { continue };
            // A second party appears under one of the names this tree uses for one, and the pin must
            // ASSERT — a pin that merely builds a peer proves nothing about what the peer holds.
            // DB-218: `b.ingest_block(` — a SECOND node grafting the block — is this tree's canonical
            // cross-node shape (`let (mut a, mut b) = …`), and the list missed it: the AssetCreate/AssetMint
            // pins assert on B's own roots after exactly that call and were flagged as having no peer the
            // moment DB-218 made their pin names resolvable.
            let has_peer = ["peer", "verifier", "joiner", "b.node", "let mut b ", "party()", "second", "b.ingest_block("]
                .iter()
                .any(|k| body.contains(k))
                || reads_a_second_real_process(&body);
            let asserts = body.contains("assert");
            if !(has_peer && asserts) {
                weak.push((class, pin));
            }
        }
        assert!(
            weak.is_empty(),
            "⛔⛔⛔ THESE PINS CLAIM A USER CAN MOVE VALUE WITHOUT A SECOND PARTY WITNESSING IT: \
             {weak:?}. Self-verification is not consensus — it decides whether a node ACCEPTS a \
             transition, never whether it HAPPENED. Assert what the PEER holds."
        );
    }

    /// ⛔ SHRINK-ONLY, BOTH WAYS. An `Unproven` must name its blocker, and one that gets proven must be
    /// re-declared so the register cannot go stale in the good direction either.
    #[test]
    fn every_unproven_class_names_its_blocker() {
        let thin: Vec<&str> = VALUE_CLASSES
            .iter()
            .filter_map(|(n, m)| match m {
                // DB-197: a `NoValueOfItsOwn` filing is held to the SAME bar. "It carries no value" is
                // a claim about the chain and must say WHY and WHAT carries it instead, or it becomes a
                // way to retire an entry by asserting it does not matter.
                Moved::Unproven(why) | Moved::NoValueOfItsOwn(why) => (why.len() < 80).then_some(*n),
                Moved::CrossNode(_) | Moved::RealNodes(_) => None,
            })
            .collect();
        assert!(
            thin.is_empty(),
            "⛔ {thin:?} are declared unproven without naming the blocker. The reason is the whole value \
             of the filing — 'not done yet' tells the next reader nothing about what to fix."
        );
    }

    /// ⭐⭐⭐ A `RealNodes` CLAIM MUST ACTUALLY SPAWN THE REAL BINARY. This is the one certification in
    /// the register that an in-process fixture cannot imitate: `RealMesh::start` forks an
    /// operating-system process running `target/release/usdmd-node` and will not return until every node
    /// has published an onion and can see a peer that is not itself.
    ///
    /// ⛔ Without this gate `RealNodes` would be a stronger-sounding label on the same text check, which
    /// is how the register got into trouble in the first place.
    #[test]
    fn a_real_node_claim_names_a_pin_that_spawns_the_real_binary() {
        let files = source_files();
        let fake: Vec<(&str, &str)> = VALUE_CLASSES
            .iter()
            .filter_map(|(class, m)| {
                let Moved::RealNodes(pin) = m else { return None };
                let body = test_body(pin, &files)?;
                (!starts_real_mesh(&body, &files)).then_some((*class, *pin))
            })
            .collect();
        assert!(
            fake.is_empty(),
            "⛔⛔⛔ THESE CLAIM THE FUNCTIONAL TIER WITHOUT STARTING A REAL NODE: {fake:?}. \
             `Moved::RealNodes` means ≥2 real `usdmd-node` processes over real sockets. A pin that does \
             not call `RealMesh::start` is an in-process fixture wearing the stronger label — declare it \
             `Moved::CrossNode` or make it real."
        );
    }

    /// ⛔⛔⛔ A FAUCET GREEN IS NOT PEG-IN EVIDENCE, AND THE REGISTER MUST NOT LET ONE COUNT AS THE OTHER.
    ///
    /// The `/faucet/drip` route is the only way this tree can put a spendable note in a party's hands on
    /// a real chain, so every journey that needs funded parties will reach for it. That makes it exactly
    /// the shape §CU was about, one level up: **a path that SHARES plumbing with the real path, read as
    /// proof of the real path.** What the two genuinely share is note sealing/opening, the DA
    /// record → block → peer serve, and the published-not-settled lifecycle. What they do not share is
    /// every place the peg's fund-loss risk actually lives — verified against the live code 2026-09-17:
    ///
    /// | `Class::PegIn` requires                                  | `/faucet/drip`            |
    /// |----------------------------------------------------------|---------------------------|
    /// | `deposit_id` replay key (`confidential_deposit_ids`)      | a different key space     |
    /// | `new_reserve_commit` / `new_minted_commit`                | never touched             |
    /// | a ≥2/3 bonded quorum attesting the amount                 | `attestors: Vec::new()`   |
    /// | `mint_authorized` + the bond backstop                     | absent                    |
    /// | the `peg_in_confidential_msg` domain                      | a different domain        |
    /// | the BTC/XMR watcher, confirmations, foreign reorgs        | bypassed entirely         |
    /// | solvency: minted ≤ reserves                               | mints from nothing        |
    ///
    /// ⭐ And the faucet answers `403 TESTNET_ONLY` in production, so it is one of the few deliberate
    /// breaks from testnet/mainnet parity — a code path a real user's money never travels.
    ///
    /// **The peg's signature fund-loss shape — the same BTC deposit minting twice through two doors —
    /// cannot be exhibited by a faucet at all, because there is no deposit.** So a peg class may only
    /// claim proof from a pin that drives a peg door.
    #[test]
    fn a_peg_class_may_not_claim_proof_from_a_pin_that_only_drives_the_faucet() {
        // The peg's OWN doors: the two RPC routes, the two block doors, and — since the attestation lanes
        // (2026-09-17) — the executor and custodian doors a lane pin drives directly (`execute_*` is what
        // the route calls; `propose_*`/`attest_*` are the quorum's halves). A faucet drip touches none.
        const PEG_DOORS: [&str; 12] = [
            "/peg_in_confidential",
            "/peg_in_execute",
            "apply_peg_out_attested",
            "/peg_out_execute",
            "apply_chain_peg_in",
            "apply_chain_peg_out",
            "execute_peg_in",
            "execute_peg_out_burn_verified",
            "propose_peg_in",
            "propose_peg_out",
            "attest_peg_in",
            "attest_peg_out",
        ];
        let files = source_files();
        let borrowed: Vec<(&str, &str)> = VALUE_CLASSES
            .iter()
            .filter_map(|(class, m)| {
                if !matches!(*class, "PegIn" | "PegOut") {
                    return None;
                }
                let (Moved::CrossNode(pin) | Moved::RealNodes(pin)) = m else {
                    return None;
                };
                let body = with_direct_helpers(&test_body(pin, &files)?, &files);
                let drives_a_peg_door = PEG_DOORS.iter().any(|d| body.contains(d));
                (!drives_a_peg_door).then_some((*class, *pin))
            })
            .collect();
        assert!(
            borrowed.is_empty(),
            "⛔⛔⛔ THESE PEG CLASSES CLAIM PROOF FROM A PIN THAT NEVER TOUCHES A PEG DOOR: {borrowed:?}. \
             Funding a party with the faucet and watching the note arrive proves the note plumbing — it \
             proves nothing about deposit replay, reserve solvency, the bonded attestation, or the \
             foreign-chain watcher, which is where every way a peg loses money lives. Point the claim at \
             a pin that drives the peg's own door, or leave the class `Moved::Unproven`."
        );
    }

    /// ⛔ SHRINK-ONLY IN THE RIGHT DIRECTION, AND NOT VACUOUS WHILE THE COUNT IS STILL ZERO.
    ///
    /// Two halves, because either alone would be a lie today:
    /// 1. **The rig must be exercised.** At least one pin in the tree must actually call
    ///    `RealMesh::start`. A functional tier nobody runs decays into a directory, and then the next
    ///    person reads the in-process register as if it were a chain verdict — which is precisely the
    ///    §CU failure this whole module was built to end.
    /// 2. **The promoted count may only grow.** `FLOOR` is 0 right now and that is the honest number:
    ///    the first journey MEASURED that no value class survives a real-node round trip yet, because
    ///    the rig cannot fund a party on a real chain. Raise `FLOOR` the moment one is promoted — and
    ///    never lower it, because a class does not stop needing real-process proof when its pin gets
    ///    inconvenient.
    #[test]
    fn the_functional_tier_is_exercised_and_never_shrinks() {
        const FLOOR: usize = 0;
        let files = source_files();
        let rig_users = files
            .iter()
            .filter(|(_, src)| src.contains("RealMesh::start"))
            .count();
        assert!(
            rig_users >= 2,
            "⛔ THE FUNCTIONAL TIER IS NOT BEING RUN. `RealMesh::start` appears in {rig_users} file(s) \
             (its own definition counts as one), so no journey drives a real node. Every claim in this \
             register is then an in-process claim, and an in-process claim cannot tell a chain that \
             refuses from a fixture that forgot its setup — measured 2026-09-16, three turns."
        );
        let real = VALUE_CLASSES
            .iter()
            .filter(|(_, m)| matches!(m, Moved::RealNodes(_)))
            .count();
        assert!(
            real >= FLOOR,
            "⛔ THE FUNCTIONAL TIER SHRANK: {real} classes are proven against real node processes, and \
             {FLOOR} were. If a journey was removed, say why in the kill list first."
        );
    }

    /// The register, printed. A standing answer to "what can a real user actually do with their money?"
    #[test]
    fn report_which_value_classes_a_real_user_can_actually_move() {
        let files = source_files();
        let mut real: BTreeMap<&str, &str> = BTreeMap::new();
        let mut by: BTreeMap<&str, &str> = BTreeMap::new();
        let (mut ok, mut no) = (0usize, 0usize);
        // DB-197: entries that carry no value of their own, counted apart from both.
        let mut none_of_its_own = 0usize;
        for (n, m) in VALUE_CLASSES {
            match m {
                Moved::RealNodes(p) => {
                    ok += 1;
                    real.insert(n, p);
                }
                Moved::CrossNode(p) => {
                    ok += 1;
                    by.insert(n, p);
                }
                Moved::Unproven(_) => no += 1,
                // DB-197: counted APART from both. Reporting it PROVEN would claim a movability nobody
                // demonstrated; reporting it UNPROVEN would ask "can a user move this" of a thing that
                // moves nothing, which is what made the criterion unreachable.
                Moved::NoValueOfItsOwn(_) => none_of_its_own += 1,
            }
        }
        eprintln!(
            "[e2e] {} of {} value-MOVING classes are PROVEN movable end-to-end by a real user; {} are \
             NOT ({} further entr(y/ies) carry no value of their own and are excluded from the \
             denominator — they stay listed so their absence is never read as coverage)",
            ok,
            VALUE_CLASSES.len() - none_of_its_own,
            no,
            none_of_its_own
        );
        // ⛔ THE SPLIT IS THE POINT. A single "proven" count hid the difference between a claim tested
        // against real processes and a claim tested against a fixture, and that difference is where a
        // day of re-closing closed work came from.
        eprintln!(
            "[e2e] TIER: {} proven against REAL NODE PROCESSES · {} proven IN PROCESS ONLY · {} unproven",
            real.len(),
            by.len(),
            no
        );
        for (c, p) in &real {
            let n = test_body(p, &files).map(|b| b.lines().count()).unwrap_or(0);
            eprintln!("[e2e]   ⭐ REAL NODES  {c}  ->  {p} ({n} lines)");
        }
        for (c, p) in &by {
            let n = test_body(p, &files).map(|b| b.lines().count()).unwrap_or(0);
            eprintln!("[e2e]   ✅ in-process  {c}  ->  {p} ({n} lines)");
        }
        for (c, m) in VALUE_CLASSES {
            if let Moved::Unproven(_) = m {
                eprintln!("[e2e]   ⛔ {c}");
            }
        }
    }
}

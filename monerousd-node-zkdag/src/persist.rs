// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Local-disk state persistence (#106 frontier-persist for the greenfield node).** A restart must RESUME the
//! node's exact chain state — its note set, reserve ledger, and spent-nullifier set — never restart from an
//! empty chain. Without this, a restart loses every committed block's effects (mints / burns / sends), and a
//! wallet then shows a balance the node no longer backs. This module closes that gap: the node reloads the
//! last committed checkpoint and continues.
//!
//! **Phone-safe by construction (NON-GROWING checkpoint, NOT a full-history archive).** The snapshot is the
//! O(1) frontier-checkpoint shape — the note-membership accumulators (each O(DEPTH) pending path, [`crate::frontier`]
//! / [`crate::spend_frontier`]), the spent-nullifier set, the peg reserve ledger, and exactly ONE tip block
//! (re-installed via the SAME [`crate::dag::Dag::add_anchor`] path a node uses to adopt a #29 DSYNC peer tip —
//! no parent history required). A node NEVER stores or replays the full block-DAG to resume; historical blocks
//! are served from DA sampling by other nodes. A joining phone with no snapshot instant-syncs the ≤1.8MB #29
//! DSYNC bundle; a returning node reloads this local checkpoint — both are O(1), neither grows with chain
//! length. (The served `note_index` ciphertext index is the node's DA-serving role and is the only part that
//! scales with produced notes; a light/phone node samples it rather than persisting it in full.)
//!
//! **Sound by construction.** The snapshot is guarded by (a) a `schema` version (a layout change ignores an old
//! snapshot rather than mis-parsing it) and (b) the `genesis_commit` — a snapshot from a DIFFERENT genesis is
//! refused, so a node can never load a checkpoint that belongs to another chain (the same genesis-parity guard
//! that prevents a chain split). It records final STATE, never a replayable op log, so reloading can never
//! re-apply or double-apply a peg operation. Totals (reserve / minted / nullifiers) are reloaded verbatim from
//! the last committed block — nothing is recomputed or conjured.

use crate::fixed::FixedBytes;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::block::Block;
use crate::peg::PegLedger;
use crate::spend_frontier::PoseidonSpendFrontier;

#[path = "persist_legacy_v25.rs"]
pub mod legacy_v25;
#[path = "persist_legacy_v26.rs"]
pub mod legacy_v26;
#[path = "persist_legacy_v27.rs"]
pub mod legacy_v27;
#[path = "persist_legacy_v29.rs"]
pub mod legacy_v29;
#[path = "persist_legacy_v30.rs"]
pub mod legacy_v30;
#[path = "persist_legacy_v31.rs"]
pub mod legacy_v31;
#[path = "persist_legacy_v32.rs"]
pub mod legacy_v32;
#[path = "persist_legacy_v33.rs"]
pub mod legacy_v33;
#[path = "persist_legacy_v34.rs"]
pub mod legacy_v34;
/// ⛔ The FROZEN consensus types every legacy door decodes through — see the module docs for why a door may
/// never name a live type in its serde graph (MEASURED 2026-08-26: one added `Block` field rotted all three).
#[path = "persist_frozen_v27.rs"]
pub mod frozen_v27;
#[path = "persist_frozen_v30.rs"]
pub mod frozen_v30;
#[path = "persist_frozen_v31.rs"]
pub mod frozen_v31;
#[path = "persist_frozen_v32.rs"]
pub mod frozen_v32;

/// Bump when the snapshot layout changes → an old snapshot is ignored (fresh boot) rather than mis-decoded.
/// v2: added `bond_height` (validator bond-maturity anchor for the enforced unbond-delay).
/// v3: PegLedger gained `stake_reward_claimed` + `stake_weight_total` (value-weighted stake-to-earn claim state);
///     postcard is positional so the layout shifted — the schema guard boots fresh rather than mis-decoding v2.
/// v4: `stake_reward_claimed` value gained the ownership-bind nullifier (`(weight, cursor, nf)`) — layout shift.
/// v5: `note_index` REMOVED (no note set stored on disk); note ciphertexts are peer-sampled DA.
/// v6: TRUE CONSTANT SIZE — frontiers + magnitude counters (`blue_work`/`blue_score`/`height`) now serialize
///     fixed-width/height-invariant, so the snapshot byte-length is identical at every height (no varint/popcount
///     creep). Layout shifted (fixed bytes vs varint), so the schema guard boots fresh rather than mis-decoding v5.
/// v7: `spent_nullifiers` HashSet → `nullifier_imt` indexed-Merkle accumulator (O(1) root; anti double-spend).
/// v8: the snapshot ALSO carries the O(1) `nullifier_acc` (indexed-Merkle root+count, a fixed 40 bytes) — the
///     TRUSTLESS, constant-size double-spend commitment a re-spend's self-verifying witness is checked against; it
///     resumes O(1) across a restart. The coupled node+wallet witness-flow reduces the persisted state to exactly
///     root+count once each spend carries its own non-membership witness.
/// v9: `BlockHeader` now commits `nullifier_root` (the spent-state root, at parity with `frontier_root`) — the
///     field rides the header `preimage`, so EVERY block id changed. A schema-8 snapshot's stored block ids no
///     longer match the recomputed ids, so the schema guard boots fresh (clean resync) rather than mis-decoding.
/// v13: the persisted `PegLedger` gained the `released` set (the withdrawal's foreign-settlement leg — one burned
///     USDm nullifier authorizes at most ONE foreign reserve release). postcard is positional, so this shifts the
///     peg-ledger layout; the schema bump makes a schema-12 snapshot boot fresh (O(1) #29-DSYNC resync) rather than
///     mis-decode the ledger. `#[serde(default)]` keeps the field absent-safe on any self-describing path.
/// v14: the persisted `PegLedger` gained `redeem_floor_bps` (the peg-OUT solvency floor, 10000 = 100%, DISTINCT from
///     the 15000/150% MINT `ratio_bps` — a Sell may draw the reserve buffer down to full backing with a rising
///     withdraw fee). Same positional-postcard reasoning: the field shifts the ledger layout, so a schema-13 snapshot
///     boots fresh (O(1) #29-DSYNC resync). `#[serde(default = "default_redeem_floor_bps")]` keeps it absent-safe
///     (defaults to 100%) on any self-describing path.
/// v15: `recent_root_history` (the ROOT-HISTORY anchor relay) now uses the FIXED-WIDTH `fixed_recent_root_history`
///     codec (always `16 + RECENT_ROOT_HISTORY_WINDOW*32` bytes) instead of a `Vec`/varint that grew linearly with
///     block count below the window cap — a no-growth violation the constant-size test caught (8,911 B @200 blocks
///     vs 47,640 B @2,000). The relay is STILL persisted (a resumed node keeps serving the full window, so a wallet
///     that fell behind then reconnects after a restart never strands — no disappearing-balance regression); only
///     its on-disk encoding changed, so the schema bump makes a schema-14 snapshot boot fresh rather than mis-decode.
/// v16: the redundant blake3 `note_frontier` is REMOVED from the snapshot (no-growth brick 5 — one note tree, not
///     two). The Poseidon `spend_frontier` is now the sole note-membership tree and the header `frontier_root`, so
///     the block-header commitment changed (every block id changes ⇒ re-genesis); a schema-15 snapshot boots fresh.
/// v17: `note_clues` REMOVED from the snapshot (no-growth brick 3) — the OMR clue index was an unbounded O(notes)
///     map in consensus state; it is now a bounded transient RAM serve-cache (DA/acceleration, not consensus). A
///     schema-16 snapshot boots fresh; the resumed node's clue cache is empty and refills forward (no correctness
///     impact — the clue is only a pre-decap hint).
/// v18: `nullifier_imt` (the FULL O(spends) indexed-Merkle tree) REMOVED from the snapshot (no-growth brick 2) —
///     the snapshot carries ONLY the O(1) `nullifier_acc` (root+count). A resumed node is a treeless verifier
///     (double-spend via the mandatory carried witness vs the acc); a producer rebuilds the tree from the nullifier
///     stream (`rebuild_nullifier_tree`). A schema-17 snapshot boots fresh.
/// v19: the persisted `PegLedger` gained `wrapped_assets` (per-asset wrapped-asset PSMs for the IonSwap bridge —
///     asset_id -> reserve/minted commitments + per-asset ratio; stablecoins at 100%, volatile at 150%). Bounded by
///     the governance-registered asset set (O(1)). postcard is positional, so this shifts the peg-ledger layout; the
///     schema bump makes a schema-18 snapshot boot fresh. `#[serde(default)]` keeps it absent-safe (empty map).
/// v20: SPARSE CUTOVER — the snapshot carries the O(1) SPARSE nullifier-accumulator ROOT (`sparse_acc_root`), the
///     value the block header now commits. A restart RESUMES the consensus accumulator instead of rebooting it at
///     genesis. A fixed 32 bytes at every height (no-growth), and UNBOUNDED — a spend committed at any past height
///     stays spent across restarts forever, no window and no age-out. postcard is positional, so the added field
///     shifts the layout; the schema bump makes a schema-19 snapshot boot fresh.
/// v21: IMT RETIRED — the indexed-Merkle `nullifier_acc` (root+count) is GONE from both the node and the
///     snapshot; `sparse_acc_root` is the sole spend authority and `nf_blocks` (one u64) is the only count that
///     remains. This removes the last per-block-growing structure a node held: the IMT mirror working tree gained
///     `BLOCK_FIXED_NULLIFIER_COUNT` leaves EVERY block on every node. postcard is positional, so the field swap
///     shifts the layout; the schema bump makes a schema-20 snapshot boot fresh.
// v23: adds `served_seq` — the dense count of records a node has written.
//
// It was never persisted, so a restarted node counted from zero: MEASURED 2026-08-12 at chain height
// 93,512 a resumed node reported `served_seq 2,559` — only what it had written since ITS OWN boot — while
// the chain held ~180,000 records. Records are RAM by design ("the DA is the ledger": they are refetched
// from peers), but a node that does not know how far it had got cannot ask for the gap. It served an EMPTY
// history while reporting full height, so every wallet on it read a blank balance and every send refused.
//
// postcard is POSITIONAL, so this new field shifts the layout and the schema guard boots an older snapshot
// fresh — that is the guard working, not a fault. One clean O(1) #29-DSYNC resync, then resumes carry the
// recorded position and the by-ordinal backfill has a gap to close.
// v24: + unspent_map_anchor_root (the persisted map's own leaf-fold root — self-consistent saves;
// see the field doc). Postcard is positional: older snapshots refuse at the schema guard and the
// node resyncs from the mesh (rolling restarts only, so the tip survives in the peer's RAM).
// PAST-CHATS-CHECKED: same increment discipline as every prior bump (v23 note below; the
// rolling-upgrade back-compat decision in [[project_node_snapshot_rollingupgrade_backcompat]]) —
// 24 is not a tuned value, it is 23 + 1.
// v25: + the BONDED VALIDATOR SET (`bonded_validators`/`slashed_validators`/`slashed_bond_burned`/
// `validator_bond_commit`/`validator_custody`) — the finality quorum now survives a restart beside
// the `bond_locked` value it weighs. MEASURED 2026-08-22: `ValidatorSet` was runtime-only, so EVERY
// restart emptied it, the resumed node rejected all finality votes at `bond_of(voter)==0`, and
// `finalized_height` stopped advancing until a fresh bond landed. Bounded by the CURRENT validator
// set (never history). Postcard is positional, so the added fields shift the layout; the schema
// bump makes a schema-24 snapshot boot fresh (one clean O(1) #29-DSYNC resync, rolling restarts).
// PAST-CHATS-CHECKED: same increment discipline as every prior bump (v24 note above;
// [[project_node_snapshot_rollingupgrade_backcompat]]) — 25 is not a tuned value, it is 24 + 1.
// v26 (2026-08-24, user-authorized "Land it as designed"): `letter_columns` — the snapshot carries filed
// MAIL bytes beside notes (the missing half of the custody law: balances survived restarts, letters did
// not — a delivered, anchored letter vanished from fresh-seed history after one rolling restart). The
// bump is live; the field declaration lands beside `circulating_records` (pending one guard unlock — see
// the session log). Postcard is positional, so a schema-25 snapshot boots fresh via one clean #29-DSYNC
// resync under ROLLING restarts (the mesh re-serves rows + mail while each node cycles).
// PAST-CHATS-CHECKED: same increment discipline as every prior bump — 26 is 25 + 1, nothing tuned.
// v28 (in-tree only, NEVER DEPLOYED — and RETIRED at source 2026-08-26): the confidential-AMM pool set.
// No operator ever held a schema-28 file, and the pool AMM itself was then deleted by user ruling ("a pool
// is shared mutable secret state" — the P2P limit-order DEX replaces it), so there is no v28 door and no
// v28 bytes for one to open, and the amm fields are gone from the CURRENT layout too.
// v29: + `chain_id` — the GENESIS BLOCK ID the checkpoint belongs to (see the field). Added when the
// in-tree `amm_set_root` preimage binding moved every block id; that binding was retired WITHOUT deploying,
// so no fork exists in deployed history and a legacy (all-zero) file still resumes — but every v29+ file
// stamps its real genesis id, so any FUTURE consensus-hash change is caught at restore instead of silently
// resuming a foreign tip. Final v29 layout = the v27 layout + `chain_id` at the tail.
// PAST-CHATS-CHECKED: same increment discipline as every bump above (v24's note: "24 is not a tuned value,
// it is 23 + 1"); 29 is 28 + 1, nothing tuned, and 28 stays burned rather than reused so any stray
// in-tree-era file (a dev machine's scratch datadir) can never alias the shipping layout.
//
// v30 (2026-09-01): `ChainParams` gained `order_fill_fee_bps` MID-STRUCT (the DEX taker fee), which
// moves the positional layout of snapshot field `params` — so every v29 file on disk (the live pair's
// custody included) needs the FROZEN v29 door (`legacy_v29`, composing the frozen v27 body +
// `chain_id`), and the params layout those files carry is frozen as `frozen_v27::ChainParamsV27`.
// The migration's one choice: the fee fills with its genesis default — the value those chains were
// implicitly running (no fee existed). 30 is 29 + 1, nothing tuned.
// v31 (2026-09-03): `ChainParams` gained `record_fold_depth` at its TAIL and the snapshot gained
// `fold_chain_tip` at its tail (the canonical record fold — records fold into the note spine in the DAG's
// canonical order once `record_fold_depth` selected-chain steps below the tip; the cursor names the last
// folded chain block). A v30 file decodes through the FROZEN v30 door (`legacy_v30`), pinned against the
// real live-pair files `state-v30-{27780,28901}.snap`.
// v32 (2026-09-05, the landing run's item 9 + 8b): a SEMANTIC bump — the byte layout is identical to v31,
// but the CHAIN LAW moved: genesis no longer contributes a 256-leaf record fold to the spend frontier or
// an ordinal-0 step to the membership accumulator (the retired `enable_persist` genesis fold wedged the
// first real record on the fold-order law and forked the frontier — measured by
// `item9_measurement_leaf_law_on_a_had_false_boot`), and the mint classes gained their genesis-derived
// admission rule. A v31 file decodes through the FROZEN v31 door (`legacy_v31`) and is REFUSED for resume
// — no post-hoc shape test can certify a v31 spine sound under the new law (the wedge's arithmetic
// re-converges one record later), and the v32 roll is a batched re-genesis (standing authorization), so
// carrying a v31 spine forward would risk the exact "resumed node certified a funded note ABSENT" class.
// Pinned against the real live-pair files `state-v31-{27780,28901}.snap`. 32 is 31 + 1, nothing tuned.
// v33 (2026-09-06, the readiness-cursor closure): the snapshot gained `sidecar_cursor` at its TAIL — the
// proven-served readiness watermark. Without it, resume re-derived the cursor from the restored SPINE
// (`spend_frontier.count()/256`), but a #29 DSYNC jump moves the spine WITHOUT this node ever holding the
// jumped span's rows and the snapshot persists that spine verbatim — so a jumped node's restart CANCELLED
// its sidecar debt (red pin `a_restart_of_a_jumped_node_must_not_cancel_its_sidecar_debt`, MEASURED
// 2026-09-06: rowless 40, verdict 32, backlog 0, cursor 41). The watermark is persisted at save and
// CLAMPED to what the same file certifies at restore (never above certified+1); a v32 file (no field;
// frozen door `legacy_v32`, pinned against the real gate-run daemon files `state-v32-{47791,48912}.snap`)
// resumes with the cursor at the EVIDENCE floor — retention floor + contiguous held rows — never the
// spine, so legacy custody re-proves its debt instead of cancelling it.
// PAST-CHATS-CHECKED: same increment discipline as every bump above (v24's note: "24 is not a tuned
// value, it is 23 + 1"); 33 is 32 + 1, nothing tuned. The frozen-door shape follows the v30/v32 doors
// verbatim, per the user's upgrade-custody law (2026-08-24: a bump must carry custody forward, never
// orphan it) and the FROZEN-DOOR self-contained law.
// v34 (2026-09-11, D-45): one tail field — `letter_acc` — the letter
// accumulator was never persisted, so a resumed node held a value no chain derives (fuzz lane,
// `Receive(0) · Restart(0)`). A v33 file enters through the frozen `legacy_v33` door, pinned against
// the real v33 writer's file `state-v33-27780.snap`; zero = the genesis seed, exactly what every v33
// node restarted with. 34 is 33 + 1, nothing tuned.
// v35 (2026-09-19, DB-106): one tail field — `adopted_certified_root` — the root the chain CERTIFIED for this
// node (a bundle adopt, or verified folds carried from one). It was never persisted, so a node that restarted
// behind the tip and caught up by the block lanes (the only way inside LIVE_CATCH_UP_DEPTH since DB-50/68)
// could never certify a presence verdict again: `present: null` for every note, its wallet's funds "pending
// verification" forever (honest_schedule_seed_3/4, recorded_case_00). Bitcoin's shape: a node's own validated
// chainstate persists; it never needs a peer to re-certify what it validated itself. A v34 file enters the
// frozen `legacy_v34` door for its diagnosis and boots fresh. 35 is 34 + 1, nothing tuned.
// v37 (2026-09-26, DB-224): `Block::credit_set` TRAVELS AGAIN (carriage form — every note payload
// replaced by its 64-byte reference), so `tip_block`'s positional layout moved: the field was
// `#[serde(skip)]` under v36. A v36 file therefore does not decode as v37 and takes the existing
// pre-fork refusal arm above (move the file aside; the source already forks from the live testnet at
// height 1, so this rides the owed reset). ⛔ v36 itself covered TWO layouts — DB-165 skipped
// `output_notes`/`credit_set` without bumping it — which is exactly why this change bumps. 37 is 36 + 1,
// nothing tuned.
// v38 (2026-10-05, SATOSHI): `PegLedger` gained the issued SAT total (`sat_issued`, increment 1) and the pendulum's epoch
// snapshot (`pendulum_epoch_next` / `pendulum_share_bps`, §10.8), and `finality_validators` was inserted beside
// `bonded_validators` (increment 1, §6). ⛔ Increment 1 changed this layout WITHOUT a bump — the DB-165 mistake again
// (a v37 file from the pre-SATOSHI writer would have been read as current from shifted offsets), found 2026-10-05 by
// reading the postcard law above; this bump covers it. The custody unit also moved (USDm bonds → SAT bonds), so a v37
// file is a different chain's custody, never migrated: it takes the post-fork refusal arm (move the file aside; the
// node rejoins by the O(1) resync). 38 is 37 + 1, nothing tuned.
// v39 (2026-10-22, G2b): four seat-activation collections inserted after `finality_validators` (`custody_seat_active_from`,
// `finality_seat_active_from`, `departed_custody_seats`, `departed_finality_seats`) — postcard is positional, so a v38 file
// does not decode as v39 and takes the refusal arm (the node rejoins by the O(1) resync). 39 is 38 + 1, nothing tuned.
// v40 (2026-10-22, G1c lane a): the membership tip TRANSITION `(membership_tip_prev, membership_tip_root)` inserted after
// `membership_acc` — the pair a spender's carrier names and `/get_membership_acc` serves had no restore site, so a restarted
// node served `(0, 0, acc)` until its next fold (restart census, g2b-census-harness-20261022.log:3906+). Positional, so a
// v39 file takes the refusal arm (the O(1) resync). 40 is 39 + 1, nothing tuned.
// v41 (2026-10-23, G1f lane a): the running WHOLE-CHAIN CERTIFICATE `chain_cert` appended after `letter_acc` — the node's
// own recursive proof of the chain it holds had no restore site, so every restart dropped it and its cursor to the
// construction value (restart census: chain_cert 95 → 29 B, certified_blue_work 3 → 1 B on both nodes,
// g1e-b-restart-census-20261022.log:2507+) and the next bundle re-proved from the genesis step. The cursor is DERIVED from
// the restored proof's public work (no plain field to forge). Positional, so a v40 file takes the refusal arm (the O(1)
// resync). 41 is 40 + 1, nothing tuned.
// v42 (2026-10-23, G1e-ii lane a): the MEMBERSHIP-STEP INDEX (`da_macc_steps`, `da_macc_first`) and the per-row LEAF STARTS
// (`da_leaf_starts`) appended after `chain_cert` — the per-ordinal coordinates the fold computes had no restore site, so
// every restart emptied them while the rows sat on disk (restart census g1f-restart-census-20261023.log:2931–2933: da_macc_fwd_mem
// 1991 → 2 B, da_macc_rev_mem 1991 → 2 B, da_macc_first 35 → 4 B, da_leafstart_mem 482 → 2 B, both nodes) and
// `da_ordinal_at_membership_acc` answered None — "forged" — for every accumulator the node held before the restart. Installed
// through ONE door: the index's top entry must equal the frontier accumulator the same file carries. Positional, so a v41 file
// takes the refusal arm (the O(1) resync). 42 is 41 + 1, nothing tuned.
// v43 (2026-10-23, G1e-iv lane a): the SPINE'S REWIND RING (`spine_frontiers`) appended after `da_leaf_starts`, and the band
// journal carry grew its applied proofs (`BandJournalCarry::applied`, positional in the fold record) — restart census
// g1eii-restart-census-20261023.log:2871/2891/2883/2903: spine_recent_frontiers 14 281 → 2 B and band_door 5.16 MB → 13 KB on
// both nodes. Each installs behind its own door (ring: newest entry == the file's frontier; proofs: the journal replay).
// Positional, so a v42 file takes the refusal arm (the O(1) resync). 43 is 42 + 1, nothing tuned.
// v44 (2026-10-23, G1g-iii lane a): THE CERTIFIED ANCHOR TRIPLE (`certified_anchor_row`) appended after `spine_frontiers` —
// the resume DERIVED anchor / score / prefix where the live process held its own values (restart census
// g1gii-restart-census-20261023.log: certified_anchor 4 → 25 B, certified_anchor_score 1 → 2 B, certified_prefix_len
// 1 → 2 B, both nodes). Installed verbatim behind the C4 cap. Positional, so a v43 file takes the refusal arm (the O(1)
// resync). 44 is 43 + 1, nothing tuned.
// v45 (2026-10-23, G1g-v lane a): THE FOLD ANCHOR'S WHOLE BODY (`anchor_body`) appended after `certified_anchor_row` —
// the restore installed the header + tx-id SHELL (`tip_block`, every set empty) as `Node::anchor_block_full` where the live
// process held the anchor's whole body (restart census g1giv-restart-census-20261023.log: anchor_block_full 97 → 97 B,
// same id, different wire digest, both nodes). Installed only under the restored tip's id with its witness. Positional, so
// a v44 file takes the refusal arm (the O(1) resync). 45 is 44 + 1, nothing tuned.
// v46 (2026-10-23, T2 real lane, lane b): THE RESTING BOOK (`resting_orders`) appended after `anchor_body` — a resting order
// is a chain object (`Class::OrderPost`, applied at block-apply through `OrderBook::post`) but the book was RAM-only, so a
// whole-mesh restart whose resume replayed no post block emptied every book (real journey sim-20261023-053354.log :15980 →
// :19294: one order on node 1's book, all three nodes restarted, the taker read "no resting orders"). Each wire re-enters
// through `Node::post_order` at the restored height (Bitcoin Core mempool.dat: reloaded entries are re-validated, never
// trusted). Positional, so a v45 file takes the refusal arm (the O(1) resync). 46 is 45 + 1, nothing tuned.
// v47 (2026-10-23, G1d, lane a): THE FOLD BASE, THE SYNCED STATE AND THE CERTIFIED FLOOR AS HELD (`fold_checkpoint`,
// `synced`, `folded_floor`) appended after `resting_orders`. Until v47 the resume DERIVED all three — the resume point as a
// rewind base, a fresh `SyncState` for a node that adopted nothing, every re-installed window block floor-marked — while the
// live process held None / None / {} (restart census g1gx-restart-census-green-20261023.log: 4 B → ~730 B, 4 B → ~18 KB,
// 2 → 11 entries, both nodes). Positional, so a v46 file takes the refusal arm (the O(1) resync). 47 is 46 + 1, nothing tuned.
// v48 (2026-10-23, G1h, lane a): the band journal carry grew the door's HELD steps (`BandJournalCarry::held`: verified,
// solicited with the own flag, parked — positional in the fold record). Restart census watch-20261023-065748.log.7:4874:
// band_door 3.10 → 2.07 MB, `solicited` / `own_held` emptied on both nodes. Re-offered through the door's own admission.
// Positional, so a v47 file takes the refusal arm (the O(1) resync). 48 is 47 + 1, nothing tuned.
// v49 (2026-10-23, G1-DA, lane a): `da_samples` carries each sample's plan (the per-process sampling secret re-drew it, so
// the proved pieces of an in-flight sample were dropped at every restart). Positional, so a v48 file takes the refusal arm
// (the O(1) resync). 49 is 48 + 1, nothing tuned.
// v50 (2026-10-23, G2a, lane a): the spine's rewind ring entries and the fold checkpoint carry `root_history` at their ordinal
// (one anchor per folded record), so a fold reorg rewinds the anchor spine with the frontier (canonical fold pins: a reorged
// node held 14 anchors over 12 records, pin-g2a-red.log). Positional, so a v49 file takes the refusal arm (the O(1) resync).
// 50 is 49 + 1, nothing tuned.
// v51 (2026-10-23, G3, lane a): `da_macc_steps` is written fixed-width (72 B per entry, `macc_steps_fixed`) — its varint limbs
// widened with height (operator-disk pin 8.00 B/block, g3-fields-7-20261023.log). Positional, so a v50 file takes the refusal
// arm (the O(1) resync). 51 is 50 + 1, nothing tuned.
// v52 (2026-10-24, G2g-r2d, lane b): THE DSYNC BODY CATCH-UP (`body_catchup`: note_body_target/acc_before/acc_target and the
// roots-run span) and the held ladder span blobs (`ladder_spans`) appended after `da_samples` — a restart dropped it (joiner restart census, joiner-restart-5.log). Positional,
// so a v51 file takes the refusal arm (the O(1) resync). 52 is 51 + 1, nothing tuned.
// v53 (2026-10-24, G1, lane b): THE LIVE DAG'S SPAN OVER THE WINDOW (`dag_window_span`) appended after `ladder_spans` — the
// restore re-installed every window entry the DAG lacked (joiner restart census, joiner-restart-f4probe.log: 321 → 588 blocks).
// Positional, so a v52 file takes the refusal arm (the O(1) resync). 53 is 52 + 1, nothing tuned.
// v54 (§20.2): record_cover_keys.
// v55 (2026-10-29, §BR-3 17.3, lane funds-brb2): `seat_words` appended after `dag_window_span` — each custody seat's
// delegated weight. Positional, so a v54 file takes the refusal arm (the O(1) resync). 55 is 54 + 1, nothing tuned.
// v56 (2026-10-29, §BR-3 17.6, lane funds-brb3): the peg ledger's bonders' yield index (two words) and the open quarter's
// bonders accrual appended; `delegated_custody` became `seat_words` (each id's delegated word + own-yield index + accrual). Positional, so a v55 file takes the refusal arm (the O(1) resync). 56 is 55 + 1.
// v57 (2026-10-29, §BR-13, lane funds-brb5): the peg ledger's `set_aside_applied` word appended. 57 is 56 + 1.
// v58 (2026-10-29, §BR-10, lane funds-brb6): the peg ledger's deployment ledger and release-attestation registry appended.
// 58 is 57 + 1.
// v59 (2026-10-29, §BR-3 17.6 stakers' half, lane funds-brb7): the peg ledger's `stake_paid_commit` appended (stake rewards
// are paid from the stakers' pool, never minted). 59 is 58 + 1.
// v60 (2026-10-29, §BR-9a step b, lane defi): the peg ledger's epoch-key ledger appended. 60 is 59 + 1.
// v61 (2026-10-30, §22, lane defi): the epoch-key ledger carries the custodians' activity and each round its eligible dealers.
// v62 (2026-11-01, §BR-9a step c, lane funds-brb26): each epoch-key round carries its dealing hour (`opened_in`, the bootstrap
// rule: a new chain has keys from its second hour). 62 is 61 + 1.
// v63 (2026-11-01, lane stable): `provisional_records` appended — each saved row's PROVENANCE as held. The restore stamped
// every saved row chain-bound, so a peer-paged row this node never bound came back an AUTHORITY (launch-tail restart census
// `da_mem` −1 B: one row's `false` → `true`). Positional, so a v62 file takes the refusal arm (the O(1) resync). 63 is 62 + 1.
// v64 (2026-11-02, lane stable): `dag_shells` and `unwindowed_tags` appended — the DAG blocks below the anchor a checkpoint
// brought back by no other field (launch-tail restart census `relay`/`folded_floor`: 15 shells 170–283 scores below the
// anchor lost), and the OLI tags of held rows no window block re-derives (`da_tags_mem` −929 rows on a joiner). Positional,
// so a v63 file takes the refusal arm (the O(1) resync). 64 is 63 + 1.
// v65 (2026-11-02, lane stable): `dag_unlinked` appended — the restore's relink links exactly what the live DAG had linked
// (it linked every held block whose parents it held; restart census `relay`). Positional, so a v64 file takes the refusal arm
// (the O(1) resync). 65 is 64 + 1.
// v66 (2026-11-03, lane brb33): `validator_kem_eks` appended — the custody key table a restart rebuilt EMPTY, so a restarted
// node sealed nothing to a seat that bonded SAT custody after it (the journey's T3 refused unstake). Positional, so a v65 file
// takes the refusal arm (the O(1) resync). 66 is 65 + 1.
// v67 (2026-11-10, lane vaults): `custody_seat_numbers` appended — each bonded custodian's custody SEAT
// (`ValidatorSet::custody_seats`), the word its custody vault is read from. Positional, so a v66 file takes the refusal arm
// (the O(1) resync). 67 is 66 + 1.
// v68 (2026-11-11, lane vaults, stage three): `PegLedger::vault_keys` appended to the ledger the snapshot carries whole —
// the custody key record (`peg::VaultKeyRow`: for each vault, the member sets whose keys hold its coins), which the
// release gate reads (`PegLedger::vault_key_holds`). Positional, so a v67 file takes the refusal arm (the O(1) resync):
// a node that restarted on an older file without the record would release a leaver's collateral its peers still hold.
// The certified bundle carries the same record in `PegBrWords::vault_keys`, bound by its digest. 68 is 67 + 1.
// v69 (2026-11-11, lane vaults, stage three): a key row carries its Bitcoin leaf (`peg::VaultBtcKey`: the leaf's hash and
// its inputs, each seat's custody point and bond weight at the take) — a leaf is a function of points AND weights, so
// the member list alone never named it, and any node must be able to rebuild a key's deposit address from the record.
// The row is inside the ledger the snapshot carries whole: positional, so a v68 file takes the refusal arm. 69 is 68 + 1.
// v70 (2026-11-11, lane vaults, stage three): `PegLedger::custody_cost_debt` and `custody_cost_retired` appended to the
// ledger's public words (spec §3f R6: what the bonders owe for their custody's foreign fees, and what their income has
// paid). The fold reads the debt at every fee credit, so a node resumed from a file without it would credit the bonders'
// pool where its peers pay the debt. Inside the ledger the snapshot carries whole: positional, so a v69 file takes the
// refusal arm. The certified bundle carries both in `PegBrWords::words` (25 words). 70 is 69 + 1.
// v71 (2026-11-11, lane vaults, stage three): a key row carries `mixed_blue`, when its vault last mixed (spec §3f.2, R5:
// the weekly rotation is read from it at every fold step). A node resumed from a file without the word would hold every
// vault as never mixed and swap seats its peers do not. The row is inside the ledger the snapshot carries whole:
// positional, so a v70 file takes the refusal arm. The certified bundle carries the rows in `PegBrWords::vault_keys`,
// bound by its digest. 71 is 70 + 1.
// v72 (2026-11-12, lane vaults, stage three): `PegLedger::vault_parts` appended to the ledger the snapshot carries whole —
// the parts at rest (spec §3g.1: what a carve took out of a vault's ledgers until a take or a cancel adds it back). A
// node resumed from a file without them would hold every slot empty: it would refuse the take its peers apply and let
// the giver's vault carry deposits on its own word while its peers refuse them. Positional, so a v71 file takes the
// refusal arm. The certified bundle carries the slots in `PegBrWords::vault_parts`, bound by its digest. 72 is 71 + 1.
// v73 (2026-11-12, lane vaults, Earn step 1): every `DefiBook` the ledger carries gains `fee_commits` (each custodian's
// commitment to its share of the pair's fee line), its held settlement parts a `new_fee`, and an open handover's
// acceptances become (pool, fee) pairs. A node resumed from a file without them would hold no fee commitment, take every
// book for closed (`is_open` requires one per custodian) and refuse the settlements its peers apply. Positional, so a v72
// file takes the refusal arm; the certified bundle carries the books whole in `PegBrWords::defi_book`, bound by its
// digest. 73 is 72 + 1 (lane goods' goods6, which also took 72 on f1f9cf54, takes the next free number on its rebase).
// v74 (2026-11-12, lane goods, IonSwap pools): `PegLedger::ion_pending`, `ion_usdm_held` and `ion_pools` appended to the
// ledger the snapshot carries whole (the orders a pool has taken and not yet settled, the USDm the pools layer holds,
// and how many pools exist: the fold reads the first two at every order and every settlement, so a node resumed from a
// file without them would refuse a settlement its peers apply), and `NodeSnapshot::ion_cache` appended (this node's own cache of the contract tree's leaves and the
// pools' rows, installed at boot only if it is the tree under the restored ledger's root). Positional, so a v73 file
// takes the refusal arm (the O(1) resync). The certified bundle carries the two ledger words in `PegBrWords::ion`,
// bound by its digest; the cache is never certified and never trusted. 74 is 73 + 1 (lane vaults took 73 for Earn step 1).
// v75 (2026-11-12, lane goods): two layouts the snapshot carries changed, each positional. (1) IonSwap's liquidity locks
// (spec §14): every `IonOrderCore` in `PegLedger::ion_pending` gains `lock_from` and `lock_until`, and every `IonRow` in
// `NodeSnapshot::ion_cache` gains its lock table and `burned_x`. (2) A-F44: the band door's rewind reach
// (`BandJournalCarry`, the seventh segment) gains `history`, the admitted sets below the journal's floor, so a node
// restarted and then rewound still judges evidence naming a released step. A v74 file read by this build would mis-decode
// the first and refuse the second, so it takes the refusal arm (the O(1) resync). (The directory's `AssetRec::supply` is in
// the directory's own file, `dir-<port>.bin`, not here.) 75 is 74 + 1.
// v76 (2026-11-15, lane speed5, A-F60): every time-meaning date the snapshot carries is a CHAIN TICK (median time past
// over `dag::MESH_TARGET_SPACING_MS`), never a blue score read at an assumed pace. Positional changes: each `Unbonding`
// gains `due_tick` (the governed window's time half beside the evidence horizon's `due_blue`); the custody record's
// `VaultKeyRow::{since,replaced,mixed}_tick` and `VaultPart::opened_tick` and every `bond_height` anchor now hold ticks.
// A v75 file would read blue scores as ticks, so it takes the refusal arm (the O(1) resync). 76 is 75 + 1.
pub const SNAPSHOT_SCHEMA: u32 = 76;

/// `NodeSnapshot::da_macc_steps` on disk: each entry as fixed-width little-endian bytes, so its size is a function of the
/// entry COUNT alone, never of the accumulator's magnitude (see the field's v51 note).
pub(crate) mod macc_steps_fixed {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use usdm_decider::poseidon2_compress::DIGEST_LANES;
    type Wire = Vec<([u8; 8], [[u8; 8]; DIGEST_LANES])>;
    pub fn serialize<S: Serializer>(v: &[(u64, crate::spend_frontier::Digest4)], s: S) -> Result<S::Ok, S::Error> {
        let w: Wire = v.iter().map(|(o, d)| (o.to_le_bytes(), d.map(u64::to_le_bytes))).collect();
        w.serialize(s)
    }
    /// The bytes this field occupies on disk — what the operator-disk pin's per-field table must read.
    #[cfg(test)]
    pub(crate) fn disk_len(v: &[(u64, crate::spend_frontier::Digest4)]) -> usize {
        postcard::to_stdvec(&v.iter().map(|(o, d)| (o.to_le_bytes(), d.map(u64::to_le_bytes))).collect::<Wire>()).map_or(0, |b| b.len())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(u64, crate::spend_frontier::Digest4)>, D::Error> {
        Ok(Wire::deserialize(d)?.into_iter().map(|(o, l)| (u64::from_le_bytes(o), l.map(u64::from_le_bytes))).collect())
    }
}

// The checkpoint-coalescing gate lives on the node now (`Node::save_in_flight`, 2026-09-20): the process-global
// `SAVE_IN_FLIGHT` that stood here let one node's save silently skip another's checkpoint whenever two nodes
// shared a process (every scenario party; the wallet's in-process node).

/// v26 mail-custody type for `NodeSnapshot::letter_columns` (user-authorized 2026-08-24):
/// `(rid, letters_wire)` — the filed mail bytes beside each retained record, same working-set class and
/// bound as `circulating_records`, so a restart keeps mail exactly as it keeps balances.
pub type LetterColumns = Vec<(u64, Vec<u8>)>;

/// ⛔⛔⛔ MONOTONE PERSIST — the heaviest (blue_score, height) this process has LOADED or SAVED.
///
/// MEASURED 2026-08-13 on the live desktop node: a second node process (hand-spawned with the wrong env,
/// so it came up unjoined and produced alone) shared this port's snapshot path and overwrote the
/// 111,797-block checkpoint with its ~300-block island state; the next proper boot then "resumed" the
/// island and the tall chain's local state was gone. `save()` is the ONE choke-point every checkpoint
/// goes through, so the invariant lives there: a write lighter than the heaviest weight this process has
/// seen (its own boot `load()` included) is REFUSED loudly. A node genuinely BEHIND loses nothing — it
/// adopts the heavier tip via DSYNC and its later saves pass naturally. A deliberate re-genesis deletes
/// the snapshot file and starts a fresh process, which resets this in-process watermark too.
/// Keyed by snapshot PATH (a production process has exactly ONE; in-tree multi-node tests have one per
/// test node) — two fixed-width words per path, updated O(1) per save; no term in height, blocks or age.
static HEAVIEST_SEEN: std::sync::Mutex<Option<std::collections::HashMap<PathBuf, (u64, u64)>>> =
    std::sync::Mutex::new(None);

/// The complete resumable node state (see the module docs). Postcard-serialized; all fields are the exact
/// in-memory value-bearing state a node holds after committing its tip block.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshot {
    /// Layout guard — a mismatch means "ignore this snapshot".
    pub schema: u32,
    /// Genesis-parity guard — refuse a snapshot minted under a different genesis (anti chain-split).
    pub genesis_commit: Vec<u8>,
    /// The checkpoint tip, re-installed via `Dag::add_anchor` (no parent history needed). O(1).
    pub tip_block: Block,
    /// The tip's accumulated PoUW blue-work + blue-score (so the reorg/ordering math resumes apples-to-apples).
    /// Fixed-width big-endian (16/8 bytes) so the snapshot length never creeps up with height — true constant size.
    #[serde(with = "fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "fixed_u64")]
    pub blue_score: u64,
    /// Selected-chain length at the tip (the reported height). Fixed-width big-endian (8 bytes), height-invariant.
    #[serde(with = "fixed_u64")]
    pub height: u64,
    // note_index REMOVED (no-growth, user 2026-07-14): the node keeps NO accumulated note set on disk or in RAM
    // — the frontier roots below are the sole note commitment, and note ciphertexts are peer-sampled DA (#27 DAS).
    // note_clues REMOVED (no-growth brick 3): the OMR detection-clue index is DA/acceleration data, not consensus —
    // it grew O(notes). It is now a BOUNDED in-RAM serve-cache (`Node::note_clues`, front-evicted), refilled forward
    // from the tx stream on restart; an evicted clue is peer-served (#27 DAS) or the wallet decap-scans (the clue is
    // only a pre-decap acceleration hint, never a correctness requirement). Not persisted ⇒ snapshot O(1) in notes.
    /// Locked validator-bond notes (value that backs weight, not independently spendable).
    pub bond_locked: HashMap<[u8; 32], Vec<u8>>,
    /// Bond HEIGHT per validator id — the anchor the unbond-DELAY (`stake_lock_blocks`) is measured from, so the
    /// bond lock survives a restart. `#[serde(default)]` = an older snapshot with no bond_height loads as empty
    /// (those legacy bonds are treated as matured — liveness-safe; new bonds record + enforce the delay).
    #[serde(default)]
    pub bond_height: HashMap<[u8; 32], u64>,
    /// v25 — THE BONDED VALIDATOR SET, deterministically sorted (see `ValidatorSet::export_state`): the
    /// finality quorum itself. Persisting only `bond_locked` kept the VALUE across restarts while the
    /// WEIGHT vanished — a resumed node had money locked for validators it no longer recognized, votes
    /// were rejected at `bond_of(voter)==0`, and finality died on every reboot. O(validators).
    #[serde(default)]
    pub bonded_validators: Vec<([u8; 32], u128)>,
    /// ⭐ SATOSHI §6 — the FINALITY seats (USDm bonds, free membership seats): certified beside the custody set.
    #[serde(default)]
    pub finality_validators: Vec<([u8; 32], u128)>,
    /// ⭐ G2b (lane a 2026-10-22) — THE VIEW AT A HEIGHT (`ValidatorSet::seat_activations`): the height each seat kind
    /// activates for finality and the departed rows within retention `(id, weight, active_from, active_until)`. Without them
    /// a resumed / jumped node judged every seat active from 0 and read a different quorum than a node that watched the
    /// seat land. `serde(default)`: a pre-G2b carrier leaves every seat active from 0, as it was judged before.
    #[serde(default)]
    pub custody_seat_active_from: Vec<([u8; 32], u64)>,
    #[serde(default)]
    pub finality_seat_active_from: Vec<([u8; 32], u64)>,
    #[serde(default)]
    pub departed_custody_seats: Vec<([u8; 32], u128, u64, u64)>,
    #[serde(default)]
    pub departed_finality_seats: Vec<([u8; 32], u128, u64, u64)>,
    /// v25 — permanently slashed ids (equivocation bar survives a restart; a slashed validator must
    /// never re-admit just because the process cycled).
    #[serde(default)]
    pub slashed_validators: Vec<[u8; 32]>,
    /// v25 — total bond burned by slashing (observability; leaves the bonded weight forever).
    #[serde(default)]
    pub slashed_bond_burned: u128,
    /// v25 — the #75 confidential bonded-stake accumulator digest (value-hiding Poseidon commitment).
    #[serde(default)]
    pub validator_bond_commit: crate::spend_frontier::Digest4,
    /// v25 — per-validator bridge-custody points (secp33, ed32) so the reserve key-aggregate resumes
    /// with the set instead of waiting for re-registration.
    #[serde(default)]
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    // note_frontier REMOVED (no-growth brick 5): the redundant blake3 note-membership tree (a second tree over the
    // SAME note_cm leaves) is gone. The Poseidon `spend_frontier` below is now the SOLE note tree — it is what the
    // wallet proves membership against AND what the block header commits as `frontier_root`. One tree, not two.
    /// The Poseidon note-membership accumulator (the sole note tree; header `frontier_root` == its root).
    pub spend_frontier: PoseidonSpendFrontier,
    /// The ROOT-HISTORY accumulator (one leaf per block = that block's spend anchor). O(DEPTH) peaks, so persisting
    /// it is no-growth; a restart RESUMES it (never rebuilds from history) so wallets' receipt anchors stay provable.
    pub root_history: PoseidonSpendFrontier,
    /// ⭐⭐⭐ CIRCULATING-NOTE RECORDS — the deletion model applied to the RECORD store. MEASURED FIVE
    /// times on 2026-08-13: every mesh roll destroyed the RAM records of notes created before it, making
    /// them membership-unprovable (unspendable) and invisible to fresh-seed restore — send #6's value hit
    /// this class twice in one evening, once from MY own fix-deploy roll. Persist ONLY the records whose
    /// notes are STILL PRESENT in the unspent tree: `(rid, ordinal, notes, targets)` per circulating
    /// record. SUPPLY-BOUNDED, not history-bounded — a spent note's record leaves this set exactly as its
    /// leaf leaves the tree, so this is the SAME accepted class as `unspent_path_nodes` (the retracted
    /// P4′c was a FULL history ledger; this is the O(circulating) working set). cons: snapshot grows
    /// ~1.2KB per circulating note (beside the map's ~8KB/note), and snapshot save walks records × notes
    /// once per save. `serde(default)` keeps old snapshots loading.
    #[serde(default)]
    pub circulating_records: Vec<(u64, u64, Vec<u8>, Vec<u8>)>,
    /// ⭐ §20.2 (schema 54): each saved record's COVER KEY `(rid, key)` — what its cover regenerates under after a restart;
    /// a row with no entry takes the idle key (a regenerated idle row). Same bound as `circulating_records`.
    #[serde(default)]
    pub record_cover_keys: Vec<(u64, [u8; 32])>,
    /// v26 (user-authorized 2026-08-24, versioned by the SNAPSHOT_SCHEMA = 26 bump): filed mail bytes per
    /// retained record — same class and bound as `circulating_records` directly above, so a restart keeps
    /// mail exactly as it keeps balances.
    #[serde(default)]
    pub letter_columns: LetterColumns,

    /// ⭐ THE A-TIP FOLD CURSOR. Without this a restart reset `nf_fold_seq` to 0 while the DA still held every
    /// `<seq>.fold` record, so the serve — correctly bounded by "what THIS chain has folded" — cut the stream to
    /// nothing and EVERY wallet's absence proof failed with "stream unavailable". A resumed node looked perfectly
    /// healthy (right tip, right height, records on disk) while being unable to let anyone spend. Persisted
    /// alongside the accumulator it indexes so a restart RESUMES the fold instead of silently truncating it.
    #[serde(default)]
    pub nf_fold_seq: u64,
    /// The O(1) account-DA accumulator. Persisted for the same reason `nf_fold_seq` is: a restart that reset it
    /// would have the node commit a zero root on a chain whose earlier blocks committed live values, so its
    /// headers would disagree with its own history and with every peer that stayed up.
    #[serde(default)]
    pub account_acc: [u8; 32],
    /// The O(1) note-membership accumulator. Persisted for the same reason the others are: a restart that
    /// reset it would have the node advertise a value no wallet's carrier could ever match, silently breaking
    /// every membership proof against this node.
    #[serde(default)]
    pub membership_acc: crate::spend_frontier::Digest4,
    /// G1c (2026-10-22, lane a): the LAST membership fold transition `(prev, root)` — `membership_acc` is
    /// `note_membership_step_new_acc(prev, root)`. Its one live writer is the record fold; without a restore site a
    /// restarted node served the construction zeros over `/get_membership_acc` and in every bundle's
    /// `SyncState.membership_tip`, a transition no chain made. Restored only when the pair folds to `membership_acc`
    /// (a planted pair installs nothing); zero/zero = never folded, the construction value. 64 fixed bytes per snapshot.
    #[serde(default)]
    pub membership_tip_prev: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub membership_tip_root: crate::spend_frontier::Digest4,
    /// ⛔⛔⛔ THE DA ADDRESS FRONTIER — one past the highest record address this chain has written.
    ///
    /// Left out of the snapshot, this came back as 0 on every restart, and `pq_notes_from` clamps its range
    /// to it — so a resumed node served ZERO notes even though the record files were sitting on its disk.
    /// Reproduced end to end: a funded seed restored to 2.5 USDm, the node restarted on the same datadir, and
    /// the SAME seed restored to 0 with the serve reporting `top = 0`. The notes were never gone; the bound
    /// that says where to look for them was. `#[serde(default)]` so a snapshot written before this field
    /// still loads (it resumes at 0 exactly as it does today, never worse).
    #[serde(default)]
    pub da_top: u64,
    /// The lowest record address written, the other end of the same frontier.
    #[serde(default)]
    pub da_base: u64,
    /// How far this node had RECORDED (dense record count). Restored on resume so the node knows its true
    /// position and can ask peers for the records it is missing — see the v23 note on `SNAPSHOT_SCHEMA`.
    #[serde(default)]
    pub served_seq: u64,
    // The ROOT-HISTORY anchor RELAY (`recent_root_history`) is the CORRECT-ARCHITECTURE no-growth fix: it is NOT
    // persisted — it is a non-authoritative serve-cache, exactly like `recent_blocks`/`last_served_block`. As a
    // persisted `Vec` it grew O(blocks) below the window cap (200→2,000 entries), an unbounded no-growth violation.
    // The authoritative anchor state is `root_history` (fixed-width O(DEPTH) peaks, above). A wallet does NOT depend
    // on this relay to stay spendable: its note copath is FROZEN against its receipt anchor at receipt and never
    // needs the stream again ([[project_root_history_retires_window]] — a note spent 554 blocks past the window in
    // the 7/7 harness). On resume the relay is empty and refills FORWARD; any peer serves the constant
    // `root_history_from` broadcast for a wallet still building its initial copath (#27 DAS / trustless-liveness).
    // The snapshot is thus purely a FIXED set of frontier peaks + counters — byte-identical at any height.
    /// ⛔ RETIRED 2026-10-04 — the staked-note accumulator. Nothing fed it (the wallet's `stake_notes` encoder was
    /// retired by DB-237's private stake; its census pin asserts no body names it), it was appended at GRAFT in
    /// arrival order (two nodes grafting siblings oppositely held different roots), a DSYNC jumper never inherited it
    /// (the bundle-coverage census's last uncovered field), and its served count was a volume gauge the digital-cash
    /// cardinal forbids. The node holds no stake frontier any more; this slot stays for the checkpoint's positional
    /// encoding, is always written EMPTY and is ignored on resume.
    pub stake_frontier: PoseidonSpendFrontier,
    // nullifier_imt (the FULL O(spends) indexed-Merkle tree) REMOVED from the snapshot (no-growth brick 2). It was
    // an O(spends) DA structure in the consensus checkpoint; the snapshot now carries ONLY the O(1) `nullifier_acc`
    // (root+count) below — the SOLE double-spend authority a verifying node needs (a re-spend's mandatory carried
    // witness self-verifies against that root, no stored set consulted). A node that will PRODUCE rebuilds its
    // working DA tree from the replicated #27-DAS nullifier stream (`Node::rebuild_nullifier_tree`, verified: the
    // rebuilt root must equal the persisted acc root), exactly as it rebuilds the note set — never persisted.
    /// v21: IMT RETIRED — the count of APPLIED nullifier BLOCKS, replacing the retired indexed-Merkle
    /// `nullifier_acc` (root+count). The spend authority is now `sparse_acc_root` below, and the SPARSE
    /// accumulator is COUNT-FREE by construction, so the only count a node still needs is this one: the DA-nf
    /// store keys off "which block". A fixed 8 bytes at every height — never a per-item store.
    #[serde(default)]
    pub nf_blocks: u64,
    /// v22: how many nullifiers this chain has actually SETTLED. ⛔ This used to be derived as
    /// `nf_blocks * cover::BLOCK_FIXED_NULLIFIER_COUNT` because every block applied exactly the 256-wide cover.
    /// With that cover RETIRED (2026-08-10) a block settles a variable count, so the product reports 256x the
    /// truth — and `nullifier_count()` is compared ACROSS NODES for agreement, where a wrong-but-equal value
    /// hides a real divergence instead of surfacing it.
    /// Persisted because it must survive a RESTART: derived-and-not-stored is exactly how the last count
    /// silently rebooted to zero while the records it indexed were still on disk.
    #[serde(default)]
    pub nf_leaves: u64,
    /// v20: SPARSE CUTOVER — the O(1) SPARSE nullifier-accumulator ROOT, the value the block HEADER commits
    /// (`Node::nullifier_root`). Position = the nullifier itself, so the tree is COUNT-FREE and this single root is
    /// the whole spend authority: a fixed 32 bytes at EVERY height, at any occupancy, forever (no-growth by
    /// construction). Persisting it is what lets a restarted node RESUME the consensus accumulator rather than
    /// reboot it at genesis — UNBOUNDED + NO AGE-OUT: a nullifier spent at any past height stays spent across
    /// restarts forever; nothing is ever evicted, expired, or windowed out.
    #[serde(default)]
    pub sparse_acc_root: [u8; 32],
    /// Ask 2 idle-privacy closure: the CONFIDENTIAL real-spend-blob accumulator, so a RESTARTED node resumes the
    /// per-block decoy stream in lockstep. `serde(default)` keeps pre-closure snapshots loadable (resume from the
    /// genesis accumulator seed).
    #[serde(default)]
    /// What this node keeps to prove its chain to a joiner (`crate::join_proof`).
    pub join: crate::join_proof::JoinState,
    pub nf_cover_conf_acc: [u8; 32],
    /// ⭐⭐⭐ THE DSOL TOKEN REGISTRY — count and peaks, the accumulator's ENTIRE state.
    ///
    /// ⛔ A REGISTRY THAT DOES NOT SURVIVE A RESTART IS A REGISTRY THAT FORKS. The root is consensus-visible:
    /// a wallet folds a membership path against it, and the mint gate refuses any asset it cannot find. A node
    /// that came back with an EMPTY registry would disagree with every peer about which assets exist and would
    /// refuse every honest mint until it was repopulated — which is the restart class this tree has paid for
    /// repeatedly, in a new layer.
    ///
    /// `serde(default)` keeps pre-registry snapshots loadable: they resume at an empty registry, which is what
    /// they had.
    /// O1-FOOTPRINT-REVIEWED: bounded by usdmd_node::dsol::MMR_MAX_PEAKS — one peak per set bit of a u128
    /// count, so this is at most ~128 entries at ANY number of registered assets.
    #[serde(default)]
    pub dsol_registry_peaks: Vec<(u32, [u8; 32])>,
    /// The registry's append count, beside the peaks it must describe.
    #[serde(default)]
    pub dsol_registry_count: u128,
    /// The bidirectional peg reserve ledger (positions / reserve / minted / burned nullifiers).
    pub peg: PegLedger,
    /// The HF44 L2 settlement state root.
    pub l2_state_root: [u8; 32],
    /// v10: the GOVERNANCE-ACTIVE consensus parameters ([`crate::params::ChainParams`]) — block spacing, VDF
    /// heartbeat length, DAG width, economic bands, etc. Persisting them is what lets an on-chain governance
    /// retune survive a restart: the node resumes the CHAIN's active params (genesis default + governance
    /// history), never silently reverting to the code default. Without this, a governance change would be lost
    /// on reboot and a param would effectively require a redeploy/re-genesis to change — the exact thing the
    /// freely-tunable mandate forbids. (Schema bumped to 10, so a pre-v10 snapshot is cleanly rejected and the
    /// node fresh-syncs rather than misreading a missing field.)
    pub params: crate::params::ChainParams,

    /// ⛔⛔⛔ v29 — THE CHAIN THIS CHECKPOINT BELONGS TO: the GENESIS BLOCK ID under the rules the WRITER
    /// was running — the anti-chain-split guard the snapshot never actually had.
    ///
    /// `genesis_commit` above cannot see a consensus fork: it holds the per-NETWORK prefix ("MUSD-N…"),
    /// an INPUT to genesis derivation, byte-identical on both sides of any hashing change. This field is
    /// the OUTPUT — the id that moves whenever consensus hashing moves. MEASURED 2026-08-26: the in-tree
    /// `amm_set_root` preimage binding moved every block id while `genesis_commit` stayed identical, and
    /// with the frozen door repaired such files decoded cleanly — the exact moment a cross-fork tip
    /// would have resumed silently. (That binding was retired at source the same day, un-deployed, so
    /// TODAY the zero/legacy case below is resumable; the field exists for the NEXT fork.)
    ///
    /// Restore semantics (`Node::restore_snapshot`): all-zero = a pre-v29 file — no deployed binary ever
    /// changed the id rules, so it RESUMES (refusing would orphan custody) and the next save stamps it;
    /// non-zero mismatch = a genuinely foreign chain — REFUSED loudly, naming both ids.
    ///
    /// cons: none. SIZE = 32 B once per snapshot at every height (+0.00013% on the live origin fixture).
    /// TIME = one 32-byte compare at restore, once per process start. Both f(fixed constants), never
    /// f(history): the value is the genesis id the node already holds in `dag().genesis()`, read O(1).
    #[serde(default)]
    pub chain_id: [u8; 32],
    /// v31: the last selected-chain block whose merge set the canonical record fold has folded (None
    /// before the first fold). The fold resumes from here; everything above it re-derives from the DAG.
    #[serde(default)]
    pub fold_chain_tip: Option<[u8; 32]>,
    /// ⭐ THE FOLD CURSOR'S OWN RECORD POSITION.
    ///
    /// BORROWED-FROM: Zcash's anchor + tree-size model (github.com/zcash/zcash) — you resume from a root
    /// AND the size that produced it, so the next insertion's index is a fact, not an inference. The bundle
    /// carries the same value for a jump (`SyncBundle::anchor_ordinal`); this is the restart's half.
    ///
    /// `circulating_records` carries ordinals only for records with live notes, and a fold cursor is usually
    /// an idle (cover-only) block — so after a restart the cursor typically had NO row and the fold had to
    /// infer where it stood. MEASURED 2026-09-04: every inference (a counter, the leaf count) put one party
    /// exactly one ordinal above the other on the runtime backend. `serde(default)` keeps old snapshots
    /// loading (0 = "unknown", the old inference path).
    #[serde(default)]
    pub fold_chain_ordinal: u64,
    /// v31: the nf-unspent chain accumulator (`A_tip`, the node's `nullifier_root()`). MEASURED 2026-09-03:
    /// it was never persisted, so a resumed node's double-spend accumulator restarted from the genesis value
    /// and only a DSYNC adopt could repair it — the certified spent-state must survive a restart on its own.
    #[serde(default)]
    pub nf_unspent_acc: crate::spend_frontier::Digest4,
    /// v31: the fold carry (window headers below the fold root, folded parents, unfolded blocks with blue
    /// data) — re-grafted on resume so the DAG reaches the tip and the canonical fold continues. Bounded by
    /// fixed constants (see `crate::sync::FoldCarry`).
    #[serde(default)]
    pub fold_carry: crate::sync::FoldCarry,
    /// ⭐⭐⭐ v33 — THE PROVEN-SERVED READINESS WATERMARK: `Node::sidecar_cursor`, "one past the highest
    /// record position whose unspent-set sidecars this node has proven held/served". Persisted because
    /// NO local re-derivation is sound: the restored SPINE proves the span is CERTIFIED, never that this
    /// node held or served its rows — a #29 DSYNC jump moves the spine in O(1) with zero rows, the
    /// snapshot persists it verbatim, and a resume that advanced the cursor to the spine's top CANCELLED
    /// the jumped node's whole sidecar debt (red pin `a_restart_of_a_jumped_node_must_not_cancel_its_
    /// sidecar_debt`, MEASURED 2026-09-06: 40 rowless certified positions, verdict 32, backlog 0,
    /// cursor 41). The cursor is the live node's own honest ledger of that debt, so it rides the
    /// checkpoint like every other accumulator.
    /// RESTORE CLAMPS IT TO EVIDENCE (`Node::restore_snapshot`): never above certified+1 — within one
    /// honest save the pair is consistent by construction, so the clamp only ever bites a corrupt or
    /// forged field; the snapshot is LOCAL cache and state is a function of the chain. 0 = legacy
    /// (a pre-v33 file): resume starts at the retention floor and walks contiguous held-row evidence,
    /// never the spine.
    /// cons: none — ONE fixed-width u64 (8 bytes) per snapshot at every height, not a per-item write:
    /// 8 B × 1 snapshot = 8 B total forever, f(fixed constants), no term in height/blocks/notes/age.
    #[serde(default)]
    pub sidecar_cursor: u64,
    /// ⛔ D-45 (2026-09-11) — THE LETTER ACCUMULATOR RIDES THE CHECKPOINT. `letter_acc` is a commutative
    /// per-block sum every accepted block advances (`Node::apply_letter_set`) and every sync bundle mirrors,
    /// yet it was never persisted: a resumed node restarted it at the genesis seed and re-folded only the
    /// blocks its delta replay re-applied, so it held a value no chain derives. MEASURED (fuzz lane,
    /// 1-minimal `Receive(0) · Restart(0)`; 11 of 22 catalogue schedules): "party 0's letter accumulator
    /// is [c1,aa,0f,a6] where a node fed ONLY the blocks derives [ad,dd,a9,1b]". Same v31 reason as
    /// `nf_unspent_acc` one field up. `serde(default)` = zero = legacy file: the genesis seed, as before.
    /// cons: none — 32 + 8 fixed bytes per snapshot, no term in height.
    #[serde(default)]
    pub letter_acc: [u8; 32],
    /// v41 (G1f, lane a 2026-10-23) — THE RUNNING WHOLE-CHAIN CERTIFICATE this node holds, as the one wire encoding a sync
    /// bundle carries it (`WholeChainCertWire::from_proof(chain_cert.finalize())`); `None` before the first step. The restore
    /// door installs it ONLY through `WholeChainCert::inherit` — the same verify a DSYNC adopter runs on a served bundle (the
    /// step at the release door, its io block against the four public values) — so a file cannot hand a node a certificate
    /// it could not have been served (Bitcoin chainstate shape: trusted because checked, never because it is ours). A
    /// certificate that does not verify installs nothing: the construction certificate stands and the next bundle build
    /// steps from the genesis step, exactly as a node that never stepped. O1-FOOTPRINT-REVIEWED: ONE step bounded by
    /// `certificate_door::CERT_BYTES_MAX` (377,393 B measured at T = 2^15), replaced in place per checkpoint, never a per-block store.
    /// The cursor (`Node::certified_blue_work`, the `blue_work` the certificate last certified) is NOT a field: it is
    /// derived from the restored proof's public `work`, the one value the adopt gate binds to a bundle's declared
    /// `blue_work` (`sync.rs`: `cert.work != bundle.blue_work` is refused), so for every honest node cursor == proven work
    /// by induction from `(0, 0)`. A plain cursor field would have been the only forgeable value in the pair.
    pub chain_cert: Option<crate::sync::WholeChainCertWire>,
    /// v42 (G1e-ii, lane a 2026-10-23) — THE MEMBERSHIP-STEP INDEX this node holds: `(ordinal, accumulator standing after
    /// that record folded)`, sorted by ordinal — exactly `Node::da_macc_fwd_mem` (its inverse `da_macc_rev_mem` is rebuilt
    /// from it). "`None` is the whole soundness statement" of `da_ordinal_at_membership_acc`: an accumulator this chain
    /// never reached is forged — and until v42 every restart made EVERY pre-restart accumulator read forged, because the
    /// index died with the process while the records it indexes persisted (`da_membership_acc_at_ordinal`'s own doc names
    /// the measured class: `folds=1 records=176`, every send refused). Bitcoin chainstate shape: the retained state is
    /// persisted as held, never re-derived at boot. THE DOOR (`Node::restore_snapshot`): the entry at the highest ordinal
    /// must equal `membership_acc` (the served-prefix accumulator this same file carries, which the frontier restore
    /// trusts) — an index that does not stand on the frontier it claims installs nothing, with `da_macc_first` and
    /// `da_leaf_starts`, and the node resumes exactly as it did before v42. O1-FOOTPRINT-REVIEWED: the SAME bound the live
    /// map obeys (`prune_cold_ordinal_rows` drops the entry with its cold row; `evict_ordinals_from` with a rewind), 72 B per
    /// retained ordinal — no new axis, the RAM map mirrored to disk. cons: ≈ 72 B × retained ordinals per checkpoint.
    /// ⛔ v51 FIXED WIDTH (G3, lane a 2026-10-23): the limbs are unreduced sums that grow ~1.06e9 per record, so as postcard
    /// varints every entry widened one byte per limb at each 7-bit boundary — the operator-disk pin's 8.00 B/block between
    /// h=4396 and h=4696 was the 2^42 crossing (oldest 300 entries 15,000 B, newest 17,400 B; g3-fields-7-20261023.log).
    /// Written as `[u8; 8]` ordinal + 8 × `[u8; 8]` limbs, every entry is exactly the 72 B this doc always claimed, at
    /// every height. cons: 4,096 × 72 = 294,912 B per checkpoint, constant — 87,963 B more than the varint form at h=4,396
    /// (206,949 B, g3-verify-1-20261023-node.log), ≈ 49 KB less once limbs reach the full 10-byte varint (≈ 344 KB).
    #[serde(default, with = "macc_steps_fixed")]
    pub da_macc_steps: Vec<(u64, crate::spend_frontier::Digest4)>,
    /// v42 — `(first ordinal this node folded, the accumulator it started from)`: `Node::da_macc_first`, the one value a node
    /// that began folding at a base (not genesis) needs to prove its first record (its field doc). Installed behind the same door.
    #[serde(default)]
    pub da_macc_first: Option<(u64, crate::spend_frontier::Digest4)>,
    /// v42 — `(record address, the leaf offset its notes occupy)`: `Node::da_leafstart_mem`, sorted by address. A copath is
    /// built at the leaf offset (`per_ordinal_coordinates_for_audit`: a record filed at another offset is a payment that
    /// settles and stays unspendable). Bounded by the retained rows, like `circulating_records`. Installed behind the same door.
    #[serde(default)]
    pub da_leaf_starts: Vec<(u64, u64)>,
    /// v43 (G1e-iv) — THE SPINE'S REWIND RING `Node::spine_recent_frontiers`: `(fold ordinal, the frontier through it, its
    /// membership accumulator)`, oldest first, ≤ `REWIND_RETAIN` (2 × `SPINE_RING_LEN`, §POLES spec 5) entries. A restarted node could rewind only to its resume
    /// point (`fold_checkpoint`) while its live peer rewinds up to 64 fold steps (restart census: 14 281 → 2 B / 8 681 → 2 B).
    /// Installed only when the ring's newest entry IS the frontier this file carries (same ordinal, root and leaf count),
    /// ascending, within the ring bound; else nothing installs and the node resumes exactly as before v43.
    /// cons: ≤ 128 × (one frontier ≈ ≤ 64 digests + one accumulator) ≈ 260 KB per checkpoint, constant in height.
    #[serde(default)]
    /// v50 (G2a): the 4th element is `root_history` through that ordinal (one anchor per record) — the anchor spine rewinds
    /// with the frontier. cons: + ≤ 2 KB per entry, ≤ 128 KB per checkpoint, constant in height.
    pub spine_frontiers: Vec<(u64, PoseidonSpendFrontier, Option<crate::spend_frontier::Digest4>, PoseidonSpendFrontier)>,
    /// v44 (G1g-iii, lane a 2026-10-23) — THE CERTIFIED ANCHOR TRIPLE AS THE LIVE PROCESS HELD IT: `(anchor block, its blue
    /// score, certified_prefix_len)` = `Node::certified_anchor` / `certified_anchor_score` / `certified_prefix_len`. Until
    /// v44 the resume DERIVED them (anchor = `fold_chain_tip`, score from the DAG, prefix = spine top + 1) while the live
    /// process held `None` / 0 / its own count (restart census g1gii-restart-census-20261023.log: 4 → 25 B, 1 → 2 B,
    /// 1 → 2 B on both nodes), so a restart moved the fork floor (`can_refold_from`, the reorg's `at_anchor`), the near-past
    /// walk floors and the bundle's anchor. Ethereum STF: the restart restores what the process held. `None` = a pre-v44
    /// file, for which the derivation stands; the C4 cap (a prefix the restored spine cannot back resumes stale, never as
    /// truth) applies to both. cons: 1 + 33 + 8 + 8 = 50 B per checkpoint, constant in height.
    #[serde(default)]
    pub certified_anchor_row: Option<(Option<[u8; 32]>, u64, u64)>,
    /// v45 (G1g-v, lane a 2026-10-23): THE FOLD ANCHOR'S WHOLE BODY as the live process holds it (`Node::anchor_block_full`:
    /// its sets, transitions, note commitments and witness — what `build_sync_bundle` serves as the anchor once the window
    /// has pruned it). Until v45 the restore installed `tip_block` — the header + tx-id SHELL, every set empty — in that
    /// slot: the same id under a different wire digest (restart census g1giv-restart-census-20261023.log: anchor_block_full
    /// 97 → 97 B on both nodes), so a restarted node whose window had pruned its anchor served a bundle whose anchor carried
    /// none of the sets its header commits to. Installed only when its id is the restored tip's and it carries its witness;
    /// `None` = the live process held no whole body (or a pre-v45 file). cons: one block body per checkpoint, bounded by
    /// the block size cap — constant in height.
    #[serde(default)]
    pub anchor_body: Option<Block>,
    /// v46 (T2 real lane, lane b 2026-10-23) — THE RESTING BOOK as the live process held it: every order's `OrderWire`
    /// encoding (`OrderBook::reflood_page` over the whole book — the bytes the book already gossips). Until v46 the book was
    /// RAM-only: a resting order is a chain object (`Class::OrderPost`) applied only at block-apply, so a restart whose
    /// resume replayed no post block came back with an empty book on every node at once (the whole-mesh leg restart of the
    /// real journey). Restored only through `Node::post_order` at the restored tip height — the one door the RPC, gossip and
    /// carried lanes share (maker-half verify, payout-note bind, membership-bind shape, grid, expiry, duplicate, MakerSpent),
    /// so an expired, spent or forged entry installs nothing. cons: ≈ one wire per held order per checkpoint (measured by
    /// the pin), bounded by the book's own bound (LEVEL_SLOTS per (pair, level), drained by expiry) — never f(height); one
    /// maker-half verify per held order at boot.
    #[serde(default)]
    pub resting_orders: Vec<Vec<u8>>,
    /// v47 (G1d, lane a 2026-10-23) — `Node::fold_checkpoint` as the live process held it: the rewind base a certified adopt
    /// set (`None` on a node that never adopted — it rewinds from its own per-ordinal roots). Installed only when its shape is
    /// consistent (`frontier.count() == k · BLOCK_FIXED_NOTE_COUNT`, `k` ≤ the restored fold ordinal); else `None`.
    /// cons: one frontier (≤ 64 digests ≈ 2 KB) per checkpoint when set, 1 B when not — constant in height.
    #[serde(default)]
    /// v50 (G2a): the third element is `root_history` at `k` (k anchors), installed only when `count == k`.
    pub fold_checkpoint: Option<(u64, PoseidonSpendFrontier, PoseidonSpendFrontier)>,
    /// v47 (G1d) — `Node::synced` as held: the state a certified adopt installed, `None` on a node that adopted nothing. Its
    /// production readers are the diagnostics (`spine_state`, `/status` `jumped`), so a resumed node no longer reports a jump
    /// it never made. cons: one `SyncState` (≈ 18 KB measured) per checkpoint of a node that adopted, 1 B otherwise.
    #[serde(default)]
    pub synced: Option<crate::sync::SyncState>,
    /// v47 (G1d) — `Node::folded_floor` as held, sorted: the adopted anchor and its certified past. Installed only for ids
    /// the restored DAG holds (a forged id is dropped). cons: 32 B per floor block, bounded by the DAG's constant span.
    #[serde(default)]
    pub folded_floor: Vec<crate::block::BlockId>,
    /// v47 (G1d) — `Node::da_sample_pending` as held: `(record address, the root it is checked against, the pieces already
    /// proved, when the last asks went out)`. A probe begins only at the graft of a block whose record bytes are absent, so
    /// one in flight at a restart was never re-begun (restart census: 180 B → 2 B on node 1). Re-entered through
    /// `begin_da_sample` (v49: the carried plan replaces the fresh draw when well-formed) only when the restored DAG
    /// holds the record's block with THAT `output_notes_root` and the bytes are still absent; a forged root installs nothing.
    /// cons: ≤ DA_SAMPLE_PENDING_MAX × (≈ 56 B + 8 B per proved piece) per checkpoint — bounded, never f(height).
    #[serde(default)]
    /// v49 (G1-DA): the tuple carries the PLAN after the root — `(address, root, plan, proved, asked_at)` — because the
    /// sampling secret folds the per-process `miner_seed`, so a re-derived plan was a fresh draw that dropped every proved
    /// piece. Installed only when well-formed (`Node::da_plan_is_wellformed`). cons: + 8 B per planned piece (≤ 16).
    pub da_samples: Vec<(u64, crate::hash::Hash32, Vec<u64>, Vec<u64>, u64)>,
    /// v52 (G2g-r2d, lane b) — the DSYNC body catch-up as held (`None` on a node that never adopted). Re-installed through
    /// `Node::restore_body_catchup` (shape-checked; an OPEN span re-opens at its origin). cons: ≈ 6 KB per checkpoint while
    /// set, 1 B otherwise — three O(DEPTH) frontiers, constant in height.
    #[serde(default)]
    pub body_catchup: Option<BodyCatchupCarry>,
    /// v52 (G2g-r2d, lane b) — `Node::da_ladder_mem` as held `(span index, blob, adopted)`: the roots a joiner's roots-run door
    /// wrote into its live span were RAM-only. Re-verified rung to rung at boot (`Node::restore_ladder_spans`); a blob that
    /// does not fold onto the node's own accumulators installs nothing. cons: ≤ 128 KB per held span (the release keep set).
    #[serde(default)]
    pub ladder_spans: Vec<(u64, Vec<u8>, bool)>,
    /// v53 (G1, lane b) — the live DAG's span over the block window `(floor, off-DAG ids at or above it)`
    /// (`Node::dag_window_span`): the restore re-installed EVERY window entry its DAG lacked, so a joiner's fold-span bodies of
    /// the adopted past entered the restored DAG (joiner restart census: relay 321 → 588 blocks). `None` = a pre-v53 file.
    /// cons: 8 B + 32 B per listed id (0 on a node that never adopted), constant in height.
    #[serde(default)]
    pub dag_window_span: Option<(u64, Vec<[u8; 32]>)>,
    /// v55/v56 (§BR-3 17.3/17.6) — each id's SEAT WORDS: its DELEGATED weight (inside `bonded_validators` while seated), so a
    /// restarted node keeps the seat's own locked weight apart from its delegations (the re-bond rule) and bounds an
    /// undelegation; and its own-weight bonders' yield (the index it last settled at, the accrual not yet claimed).
    /// cons: 81 B per id with a delegation or unclaimed yield, bounded by ids that once held a floor-bonded seat.
    #[serde(default)]
    pub seat_words: Vec<crate::validator::SeatWords>,
    /// v63 — the saved rows that are PROVISIONAL (`da_mem` provenance `false`: bytes a peer paged in that this node never
    /// bound to the chain). Every other saved row restores chain-bound, as before. cons: 8 B per provisional row, bounded by
    /// the rows `da_mem` already holds (a subset of `circulating_records`).
    #[serde(default)]
    pub provisional_records: Vec<u64>,
    /// v63 — the ordinal rows of REAL records whose bytes this node does not hold (a joiner's record lane filed the row; the
    /// bytes are still wanted), as `(record, ordinal)`. `circulating_records` carries a byteless row only when the block's
    /// header proves it idle (a seed row is regenerated from it), so these were dropped and a restart re-wanted rows the
    /// process held (launch-tail restart census, node 2 at 1,800 s: 14 uncarried rows before = the 14 ordinals 661–674 lost
    /// and re-wanted after). Restored as coordinates only — no bytes, no seed row (nothing is fabricated: the bytes stay
    /// wanted by id exactly as before the restart). cons: 16 B per such row, bounded by `da_ord_mem`'s own pruning.
    #[serde(default)]
    pub coordinate_rows: Vec<(u64, u64)>,
    /// v64 — the DAG blocks the live process holds that no other field of the checkpoint brings back (`Node::dag_shells`): not
    /// the anchor or genesis, not carried (`fold_carry`'s unfolded or ancestors), not a block-window entry the restore
    /// re-installs — a joiner's adopted-past shells and the blocks its fold walked below the anchor. As header shells
    /// `(shell, blue_work, blue_score, selected_parent)`, re-entered by `Node::install_block_window_span` before its relink;
    /// `folded_floor` (held, v47) re-marks the floor ones. MEASURED (launch tail, reinstalled joiner at 1,800 s): ~15 blocks
    /// 170–283 scores below the anchor dropped, the restart census's `relay` and `folded_floor` rows. cons: one header + tx
    /// ids per such block, bounded by the DAG's own prune span (`keep_depth` + slack); 0 on a node whose window covers its DAG.
    #[serde(default)]
    pub dag_shells: Vec<(crate::block::Block, u128, u64, Option<[u8; 32]>)>,
    /// v64 — the OLI locator tags of held rows whose block the window does not hold (`Node::unwindowed_tag_rows`): a joiner's
    /// peer-paged rows (`adopt_ledger_sidecars`) have no window body for `restore_tags_from_block_window` to re-derive them
    /// from, so a restart lost them (tail replica census `da_tags_mem` 25.7M/22.3M, restart −929 rows). Restored beside the
    /// rows they locate, first write wins per slot. cons: 17 B per tag of such a row, bounded by `da_tags_mem`'s own pruning
    /// with its rows; 0 on a node whose window holds every record's block.
    #[serde(default)]
    pub unwindowed_tags: Vec<(u64, Vec<(u8, [u8; crate::oli::K_BYTES])>)>,
    /// v65 — the held blocks the live DAG had NOT linked to a selected parent (`Dag::unlinked_ids`): the restore's relink leaves
    /// them unlinked, as held. cons: 32 B per such block (a handful — adopt anchors and blocks awaiting a parent).
    #[serde(default)]
    pub dag_unlinked: Vec<[u8; 32]>,
    /// v66 (T3/T2) — the custody KEY TABLE (`ValidatorSet::seated_kem_eks`: every registered seat's encapsulation key, sorted).
    /// Before v66 a restart rebuilt the table EMPTY (no field carried it) and only seats registered after the checkpoint came
    /// back, so a node restarted while a seat held only membership sealed nothing to it once it bonded SAT custody (MEASURED
    /// c39/c40-stake-restart.log: "the reward leg is sealed to 0 of 0 bonded custodian key(s)"). cons: ≤ 1,184 B per seat,
    /// bounded by PEG_ATTEST_SEALED_MAX (256).
    #[serde(default)]
    pub validator_kem_eks: Vec<([u8; 32], Vec<u8>)>,
    /// v67 (SAFE AT SCALE) — each bonded custodian's custody SEAT (`ValidatorSet::custody_seats`, sorted by id): the lowest
    /// free number when its bond was admitted, kept until it leaves. A restart reads its custody vaults from these, so a
    /// resumed node sits every custodian in the vault a node that never stopped does. cons: 40 B per bonded custodian.
    #[serde(default)]
    pub custody_seat_numbers: Vec<([u8; 32], u64)>,
    /// IonSwap pools — this node's own CACHE of the contract-state tree's leaves and of the pools' rows (the chain keeps
    /// only a root of them), WITH ITS UNDO LOG, so a restart resumes with it and follows a fold rewind as if it had not
    /// restarted. NOT chain state: at boot it is installed only if it IS the tree under the restored ledger's own root
    /// and every row is its pool's leaf (`IonCache::install_file`); anything else is dropped whole. `None` from a node
    /// whose cache was not the chain's when it checkpointed. cons: about 64 B a contract and 0.8 KB a pool in this node's own checkpoint (one row a token, and a
    /// token's creation is paid for).
    #[serde(default)]
    pub ion_cache: Option<crate::node::objects::ion_pool::IonCacheFile>,
}

/// v52 — `Node`'s note-body / roots-run catch-up fields as a checkpoint carries them (see [`NodeSnapshot::body_catchup`]).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BodyCatchupCarry {
    pub note_body_target: u64,
    pub note_body_acc_before: crate::spend_frontier::Digest4,
    pub note_body_acc_target: crate::spend_frontier::Digest4,
    pub roots_run_closed_target: crate::spend_frontier::Digest4,
    pub roots_run_spine_before: PoseidonSpendFrontier,
    pub roots_run_spine_target: PoseidonSpendFrontier,
    pub roots_run_cursor: PoseidonSpendFrontier,
}

/// ⭐ THE FILES ONE NODE BOOTS FROM — the ONE definition the daemon (`main.rs`), the in-process node (`serve.rs`) and the
/// journey simulator (`harness/netsim.rs`) share, so a simulated restart reads exactly the files a real restart reads.
/// MEASURED 2026-10-06: the two production boots had drifted — the in-process node never reloaded the @username registry or
/// the on-chain directory (the daemon's own comment calls that "registry custody loss"), and the simulator's restart went
/// through an in-memory snapshot with the on-disk checkpoint deleted, so it never ran the resume door where five restart
/// defects lived (the nf-view cache, the record cache, placeholder rows, RAM-only witness windows, the stale-spine ask).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFiles {
    pub snapshot: PathBuf,
    pub window: PathBuf,
    pub names: PathBuf,
    pub directory: PathBuf,
    pub custody_opening: PathBuf,
    /// This node's persisted fee key (`Node::restore_or_persist_fee_key`): the per-node value key every epoch fee
    /// address derives from, drawn once and read by every later process — through the custody keystore, like the
    /// validator vote key. G1 (lane a 2026-10-22): the key was per PROCESS, so a restart changed the node's fee address
    /// inside one epoch and every fee a wallet had paid to it was sealed to a key no process would ever hold again.
    pub fee_key: PathBuf,
    /// This node's reward recipient (`Node::restore_or_persist_reward_recipient`): who its SAT rewards are sealed to and
    /// the `"sat"` locator counter — the file the operator's wallet provisions over `/provision_reward_recipient`
    /// (`satoshi::reward_recipient_path`: `validator-<port>.reward`, beside the vote key), read by every process booted
    /// from these files. G1 (lane a 2026-10-22): a test build derived the recipient from the per-process miner seed and
    /// never read this file, so a simulated restart sealed every later reward to a recipient the first process's operator
    /// wallet never held — the restart census read `reward_recipient` CHANGED at every restart and the production door
    /// was never exercised in simulation.
    pub reward_recipient: PathBuf,
    /// The peers this node learned (`Node::enable_peer_persist`, Bitcoin addrman's `peers.dat`): signed gossip records,
    /// re-verified on load, so a restarted node re-dials whoever it last knew. G1g-iii (lane a 2026-10-23): only the
    /// daemon's main wired it, after the boot — a simulated or in-process restart forgot every peer.
    pub peers: PathBuf,
    /// This node's own announced peer record (`Node::record_own_announcement` writes it at the ONE announce,
    /// `Node::enable_own_record_persist` reads it back at the ONE boot): the signed record every peer already persists across
    /// this node's restart, so its PUBLIC id — the band's prover set and solicit window count it — is a function of its
    /// files. G1g-iv (lane a 2026-10-23): the id was per PROCESS, so a restarted node alone forgot it was a prover.
    pub own_record: PathBuf,
}

impl BootFiles {
    /// A served node's files: [`state_dir`] keyed by its port (DB-341).
    #[must_use]
    pub fn for_port(port: u16) -> BootFiles {
        BootFiles {
            snapshot: snapshot_path(port),
            window: window_dir(port),
            names: state_dir().join(format!("names-{port}.json")),
            directory: state_dir().join(format!("dir-{port}.bin")),
            custody_opening: state_dir().join(format!("custody-opening-{port}.bin")),
            fee_key: state_dir().join(format!("fee-{port}.key")),
            // `satoshi::reward_recipient_path()` for the serving port: `validator::node_vote_key_path().with_extension("reward")`
            reward_recipient: state_dir().join(format!("validator-{port}.reward")),
            peers: state_dir().join(format!("known-peers-{port}.pd")),
            own_record: state_dir().join(format!("own-record-{port}.pd")),
        }
    }

    /// The same seven files under one directory — a simulated node's datadir (many nodes in one process cannot share the
    /// process-wide state dir). The file NAMES are the port form's, so the layout on disk is the daemon's.
    #[must_use]
    pub fn in_dir(dir: &std::path::Path, port: u16) -> BootFiles {
        BootFiles {
            snapshot: dir.join(format!("state-{port}.snap")),
            window: dir.join(format!("{}{port}", crate::block_window::WINDOW_DIR_PREFIX)),
            names: dir.join(format!("names-{port}.json")),
            directory: dir.join(format!("dir-{port}.bin")),
            custody_opening: dir.join(format!("custody-opening-{port}.bin")),
            fee_key: dir.join(format!("fee-{port}.key")),
            reward_recipient: dir.join(format!("validator-{port}.reward")),
            peers: dir.join(format!("known-peers-{port}.pd")),
            own_record: dir.join(format!("own-record-{port}.pd")),
        }
    }
}

/// ⭐ DB-341 — the ONE state directory and served port every per-node file is named through: defined in [`crate::node_files`]
/// (moved there by the node split, lane dcash 2026-11-11, so the validator's key path in the ledger reads it without the node).
pub use crate::node_files::{serving_port, set_serving_port, state_base, state_dir};
#[cfg(test)]
pub use crate::node_files::{set_thread_node_files_for_test, with_thread_node_files_for_test};
#[cfg(test)]
pub(crate) use crate::node_files::thread_node_dir_for_test;

/// The per-node snapshot path under `~/.usdmd-node/`. Keyed by the loopback RPC port so two same-host nodes
/// (e.g. :27780 and :27781) each persist their OWN checkpoint and never clobber each other.
pub fn snapshot_path(port: u16) -> PathBuf {
    state_dir().join(format!("state-{port}.snap"))
}

/// The on-disk BLOCK WINDOW directory for a port (`crate::block_window`): `pruning-window-{port}` beside the
/// snapshot, in the same state directory. Owner-approved 2026-09-21 ("yes you have my permission for the on
/// disc window") — Kaspa's pruning-point block store, bounded by the DAG's constant horizon span, never by
/// chain height.
pub fn window_dir(port: u16) -> PathBuf {
    state_dir().join(format!("{}{port}", crate::block_window::WINDOW_DIR_PREFIX))
}

/// The JOIN-MESH-OR-NOTHING marker for a datadir: written (once) the first time this datadir's node
/// PROVABLY joins the canonical mesh (verified #29 DSYNC adopt, or consensus-graft of a live peer's
/// block, or the explicit `MONEROUSD_MESH_BOOTSTRAP=1` new-network origin). Its presence means the chain
/// persisted here is mesh-validated, so a restart RESUMES producing on it — a mesh-wide power-cycle can
/// never halt the chain — while a datadir WITHOUT it (fresh install / never-joined island) keeps block
/// production gated until the node actually joins. Sibling of the snapshot so it rides the same dir.
pub fn mesh_joined_marker(snap: &PathBuf) -> PathBuf {
    let mut os = snap.clone().into_os_string();
    os.push(".mesh-joined");
    PathBuf::from(os)
}

/// Atomically write the snapshot: serialize with postcard, write to a temp file, then rename over the target
/// (a crash mid-write leaves the previous good snapshot intact — never a torn/half file). Best-effort: an IO
/// failure is logged and swallowed so persistence can NEVER halt block production (liveness pillar).
/// ⛔⛔⛔ DB-270 STEP 2 — THE FOLD RECORD: the half of the nullifier-fold state the snapshot struct does not carry (the base
/// the A_tip it restores is measured from, the base generation, the window's prune boundary and write epoch, and which
/// carried blocks are NOT span members). It rides as a TRAILER of the very bytes the snapshot's rename makes durable, so it
/// is written at the SAME instant as A_tip — no pairing, no second file, no crash window between them. `postcard::
/// from_bytes` decodes a `NodeSnapshot` and ignores every byte after it, so every decode door (current and frozen) reads
/// the file exactly as before and the schema is unchanged.
///
/// Fixed-width little-endian fields (not postcard varints), so the trailer's size does not creep with height:
/// `36 + 16·lanes` bytes (164 at today's 8-lane digest) plus 32 per carried non-member — none in steady state (only the
/// first checkpoint after an adopt names any).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldRecord {
    pub epoch: u64,
    pub base_acc: crate::spend_frontier::Digest4,
    pub base_seq: u64,
    pub base_prev: crate::spend_frontier::Digest4,
    pub base_gen: u64,
    pub boundary: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by the fold carry (the unfolded set), empty in steady state.
    pub carry_nonmembers: Vec<[u8; 32]>,
    /// ⛔ DB-358 increment 2: the fold-time respend state (first-contact memos, claims, journal, rewind reach). It is the
    /// same class of state as the fields above (the half of the nullifier fold the snapshot struct cannot carry), and it
    /// is written at the same instant.
    /// On disk: `[u32 len][postcard bytes]` after the carried ids, and only when non-empty. So an empty carry writes the
    /// pre-increment-2 bytes exactly, and a pre-increment-2 file decodes as an empty carry.
    /// O1-FOOTPRINT-REVIEWED: one memo per lane that is unfolded or within the spine's 64-step rewind reach (each ~34 B
    /// on an honest chain), plus conflicts only. That is f(fold depth, DAG width), never f(height).
    pub respend: crate::respend::RespendCarry,
    /// ⭐ DB-223 / DB-274 P3 — THE ANCHOR RING: `(ordinal, spine root)` for the last fold steps, oldest first, as this
    /// node's own fold produced them. A spend's anchor must be one of these roots, so a node that restarted with an
    /// empty ring could judge no spend whose anchor predates the restart. Written at the same instant as the fold
    /// state above; restored only when its newest root equals the restored spine's own root.
    /// On disk: a SECOND `[u32 len][b"MUSDRING" ‖ u32 n ‖ n × (u64 ‖ digest)]` segment, written only when the ring is
    /// non-empty, and then always AFTER a respend segment (possibly empty), so the segment count says which is which.
    /// O1-FOOTPRINT-REVIEWED: bounded by `params.merge_depth_cap` entries of 72 B (259,200 B at 3,600), constant in height.
    pub anchor_ring: Vec<(u64, crate::spend_frontier::Digest4)>,
    /// ⭐ DB-274 P2 (§8.7) — THE BOND CLASS'S FOLD STATE: the `unbonding` entries (chain state: collateral inside its
    /// evidence window) and the bond fold journal (so a rewind after a restart still un-folds a bond step), plus the
    /// journal's floor. Written at the same instant as the fold state above.
    /// On disk: a THIRD `[u32 len][b"MUSDBOND" ‖ postcard]` segment, written only when non-empty, and then always after
    /// a respend segment and an anchor-ring segment (either possibly empty), so the segment count says which is which.
    /// O1-FOOTPRINT-REVIEWED: one entry per unbonding validator (bounded by the bonded set) plus at most
    /// `SPINE_RING_LEN` journal steps, each holding only the validators it touched — never a function of height.
    pub bonds: BondCarry,
    /// ⭐⭐ DB-353 LANDING 2 — THE BAND DOOR a checkpoint resumes: the band at the pointer, the fold ordinal it waits at
    /// and every awaiting step with its admitted set — exactly what a certified bundle carries (P5), written at the same
    /// instant as the fold state above. Without it a restarted node's door came back EMPTY while its accumulator was
    /// restored, so its warm's pivot could be placed in no journal, its view never returned, and under §13.6 its fold
    /// WAITED forever. Restored through the ONE door a bundle's band takes (`BandDoor::adopt_certified`).
    /// On disk: a FOURTH `[u32 len][b"MUSDBAND" ‖ postcard]` segment, written only when non-empty, and then always after
    /// the respend, anchor-ring and bond segments (any possibly empty), so the segment count says which is which.
    /// O1-FOOTPRINT-REVIEWED: the fixed-width band plus at most the door's lag cap of awaiting steps × the 256-slot lane —
    /// constant in height.
    pub band: BandCarry,
    /// ⭐ DB-274 (dir_set, 2026-10-04) — THE DIRECTORY'S FOLD JOURNAL: the @name / group / profile sign-ups apply at
    /// their block's canonical fold step (never at graft, in arrival order — two nodes that grafted two registrations of
    /// one name in opposite orders resolved it to two owners and held two directory accumulators for one chain), so a
    /// rewind must un-fold them like the bond class, and a restart must keep that ability. Written at the same instant
    /// as the fold state above.
    /// On disk: a FIFTH `[u32 len][b"MUSDDIRS" ‖ postcard]` segment, written only when non-empty, and then always after
    /// the respend, anchor-ring, bond and band segments (any possibly empty), so the segment count says which is which.
    /// O1-FOOTPRINT-REVIEWED: at most `SPINE_RING_LEN` journal steps, each holding only the slots that step wrote (a
    /// sign-up is a user act, never a function of height, blocks or notes).
    pub dir: DirCarry,
    /// ⛔⛔ DB-417 — THE PEG LEDGER'S OBJECT FOLD JOURNAL: the class objects (the peg ledger's writers, the SAT reward
    /// among them) apply at their block's canonical fold step, and a rewind un-folds them by the step's before-image. A
    /// checkpoint that did not carry the journal set the resumed node's floor to its resume point, so a 1-record reorg
    /// right after a restart stopped the fold until a certified re-anchor (MEASURED: both reds of sweep
    /// simpar-20261007-180330). Written at the same instant as the snapshot's own ledger, which the undo chain starts from.
    /// On disk: a SIXTH `[u32 len][b"MUSDPEGJ" ‖ postcard]` segment, written only when non-empty, and then always after
    /// the respend, anchor-ring, bond, band and directory segments (any possibly empty), so the segment count says which.
    /// O1-FOOTPRINT-REVIEWED: at most `SPINE_RING_LEN` steps, each holding only the words, ids and keys that step moved
    /// (`peg::PegUndo`) — never the ledger itself, never a function of height.
    /// `None` = a record written before this carry existed: the resumed node keeps no journal and its floor is its resume
    /// point (a rewind below it marks the spine stale), never an empty journal that would claim to cover every rewind.
    pub peg: Option<PegCarry>,
    /// ⛔⛔ DB-419 — THE BAND DOOR'S REWIND REACH (`nf_sparse::BandJournalCarry`): its applied-step journal, ring, floor
    /// and base root. Without it a restart resumed the door through the certified-bundle door, which keeps no history, so
    /// the resumed floor was the resume point and a 1-record reorg right after a restart stopped the fold until a certified
    /// re-anchor (MEASURED: the fast lane's default seed, night/sim-20261007-211400.log, T3 red). Reinstalled only when
    /// the door's own resumed band replays it (`BandDoor::install_journal`).
    /// On disk: a SEVENTH `[u32 len][b"MUSDBNDJ" ‖ postcard]` segment, written only after a peg segment (every record this
    /// build writes carries one), so the segment count says which. `None` = a record written before this carry: the
    /// resumed door's floor is its resume point, as before.
    /// O1-FOOTPRINT-REVIEWED: at most the door's lag cap of steps and the anchor-ring length of ring entries.
    pub band_journal: Option<crate::nf_sparse::BandJournalCarry>,
    /// ⭐ G1 (lane a 2026-10-22) — THE FINALIZED CHECKPOINT `(height, block id)` the carried votes had reached when this
    /// checkpoint was written (Ethereum's persisted `finalized_checkpoint`; Tendermint's last commit). The resume re-tallies
    /// the carried votes of every body it restores (G2's graft door), but a finalizing carrier that FOLDED below the window
    /// is no longer carried, so without this a restart REGRESSED finality to whatever the window re-derives (MEASURED: the
    /// restart census read `finality` CHANGED 41 → 17 B on every restart, scratchpad/night/g2-finality-harness-3-20261022.log:3696
    /// — there the cause was the boot order, every carried vote refused unauthenticated; the deep class is the pin's second
    /// arm). Re-installed only when the resumed DAG holds the block AT that height (`Node::install_persisted_finality`): a
    /// planted height or a ghost block installs nothing. On disk: a tail segment `[u32 len][b"MUSDFINC" ‖ height u64 LE ‖
    /// 32-B id]` after the peg segment (tail segments after the peg are read BY MAGIC, each at most once). `None` = nothing
    /// finalized yet, or a record written before this carry. O1-FOOTPRINT-REVIEWED: 48 bytes, fixed.
    pub finalized: Option<(u64, [u8; 32])>,
    /// ⛔ G2g-r2b (lane b 2026-10-24) — THE CERTIFIED FOLD BASE A DSYNC ADOPT STILL HOLDS PENDING (`Node::nf_fold_base_pending`).
    /// Process-local, a restart between the adopt and the switch kept the adopt-instant base for good: the owed list was
    /// gone, so no body was ever fetched and the node never reached the chain's quantized base (AGENTS.md §6: process-local
    /// state is not state). Written at the same instant as the base it replaces. On disk: a tail segment `[u32 len]
    /// [b"MUSDFPND" ‖ postcard]` after the peg segment (read by magic, at most once). `None` = nothing pending.
    /// O1-FOOTPRINT-REVIEWED: bounded by the certified span (the window above the base), and only between an adopt and its
    /// switch — empty in steady state.
    pub fold_pending: Option<FoldPendingCarry>,
    /// ⭐ §RF-3 — THE MEMBER RING COMMIT HISTORY (`Node::member_ring_commits`): `(fold step, ring commit)`, oldest first, the
    /// set a header's `member_ring_commit` is judged against. A commit cannot be recomputed for an evicted step, so without
    /// it a restart judged every header naming an older ring as unknown. Re-installed only when its newest entry is the
    /// restored ring's newest step and equals the commit recomputed from that ring (`Node::install_member_ring_commits`).
    /// On disk: a tail segment `[u32 len][b"MUSDRCMT" ‖ u32 n ‖ n × (u64 LE ‖ 32 B)]` after the peg segment (read by
    /// magic, at most once), written only when non-empty. O1-FOOTPRINT-REVIEWED: bounded by `anchor_ring_len()` entries of
    /// 40 B (144,000 B at 3,600), constant in height.
    pub member_ring_commits: Vec<(u64, crate::hash::Hash32)>,
}

/// The member-ring-commit segment's opening magic (see [`FoldRecord::member_ring_commits`]).
const MEMBER_RING_COMMITS_MAGIC: &[u8; 8] = b"MUSDRCMT";

/// The pending-fold-base segment's opening magic (see [`FoldRecord::fold_pending`]).
const FOLD_PENDING_MAGIC: &[u8; 8] = b"MUSDFPND";

/// G2g-r2b — `Node::nf_fold_base_pending` as a checkpoint carries it (see [`FoldRecord::fold_pending`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldPendingCarry {
    /// (base, seq, prev) — the certified words, stepped by every prune round since the adopt.
    pub words: (crate::spend_frontier::Digest4, u64, crate::spend_frontier::Digest4),
    pub acc: crate::spend_frontier::Digest4,
    pub a_tip: crate::spend_frontier::Digest4,
    /// (id, blue_work, blue_score) of every listed body not placed yet.
    pub owed: Vec<([u8; 32], u128, u64)>,
    pub placed: Vec<[u8; 32]>,
    /// The adopt's certified anchor blue score: listed bodies at or below it are the adopted past (window only).
    /// cons: 8 B; a segment written by 9e6dc76 (no score) decodes as refused, so that one checkpoint resumes with no fold
    /// record (base := A_tip, the loud adopt-shaped arm) — the pending base existed only between an adopt and its switch.
    pub anchor_score: u64,
}

/// The band-journal segment's opening magic (see [`FoldRecord::band_journal`]).
const BAND_JOURNAL_MAGIC: &[u8; 8] = b"MUSDBNDJ";

/// The finalized-checkpoint segment's opening magic (see [`FoldRecord::finalized`]).
const FINALITY_CHECKPOINT_MAGIC: &[u8; 8] = b"MUSDFINC";

/// The peg-carry segment's opening magic (see [`FoldRecord::peg`]).
const PEG_CARRY_MAGIC: &[u8; 8] = b"MUSDPEGJ";

/// ⛔⛔ DB-417 — the peg ledger's object fold journal a checkpoint carries (see [`FoldRecord::peg`]): `(ordinal, undo)`
/// oldest first, where entry `k`'s undo turns the NEXT state (entry `k + 1`'s before-image, or for the newest entry the
/// snapshot's own ledger) back into step `k`'s before-image; and the journal's floor.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PegCarry {
    pub journal: Vec<(u64, crate::peg::PegUndo)>,
    pub floor: u64,
}

impl PegCarry {
    pub fn is_empty(&self) -> bool {
        self.journal.is_empty() && self.floor == 0
    }
}

/// ⭐⭐ DB-353 landing 2 — the band door's state a checkpoint carries (see [`FoldRecord::band`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandCarry {
    pub band: Vec<crate::spend_frontier::Digest4>,
    pub next_ordinal: u64,
    pub awaiting: Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)>, // TAG-SPACE: admitted tags as values, as the bundle carries them
}

impl BandCarry {
    /// Empty when there is no band to resume (a door stale past a gap carries none, like a bundle).
    pub fn is_empty(&self) -> bool {
        self.band.is_empty()
    }
}

/// The band-carry segment's opening magic (see [`FoldRecord::band`]).
const BAND_CARRY_MAGIC: &[u8; 8] = b"MUSDBAND";

/// ⭐ DB-274 P2 (§8.7) — the bond class's fold state a checkpoint carries (see [`FoldRecord::bonds`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BondCarry {
    pub unbonding: Vec<([u8; 32], crate::node::Unbonding)>,
    pub journal: Vec<crate::node::BondFoldStep>,
    pub floor: u64,
}

impl BondCarry {
    pub fn is_empty(&self) -> bool {
        self.unbonding.is_empty() && self.journal.is_empty() && self.floor == 0
    }
}

/// The directory-carry segment's opening magic (see [`FoldRecord::dir`]).
const DIR_CARRY_MAGIC: &[u8; 8] = b"MUSDDIRS";

/// ⭐ DB-274 (dir_set) — the directory's fold journal a checkpoint carries (see [`FoldRecord::dir`]): the steps inside
/// the rewind reach and the journal's floor, exactly as [`BondCarry`] carries the bond class's.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirCarry {
    pub journal: Vec<crate::directory::DirFoldStep>,
    pub floor: u64,
}

impl DirCarry {
    pub fn is_empty(&self) -> bool {
        self.journal.is_empty() && self.floor == 0
    }
}

/// The anchor-ring segment's opening magic (see [`FoldRecord::anchor_ring`]).
const ANCHOR_RING_MAGIC: &[u8; 8] = b"MUSDRING";

/// The bond-carry segment's opening magic (see [`FoldRecord::bonds`]).
// G2b (2026-10-22): `VidState` (inside every journaled `BondFoldStep`) gained the seat activation view, so the postcard
// layout of this segment changed; the magic moved with it (BOND → BON2) and a record a pre-G2b writer left is refused
// WHOLE by the by-magic reader (the fail-closed resume: no fold record, the O(1) resync), never read from shifted offsets.
// SAFE AT SCALE (2026-11-10): `VidState` gained the custody seat, so the layout moved again (BON2 → BON3); a record an
// earlier writer left is refused whole by the by-magic reader, as above.
const BOND_CARRY_MAGIC: &[u8; 8] = b"MUSDBON3";

/// The trailer's closing magic: `[record][u32 len][magic]`.
const FOLD_TRAILER_MAGIC: &[u8; 8] = b"MUSDFOLD";

impl FoldRecord {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::HEAD_BYTES + 32 * self.carry_nonmembers.len());
        let digest = |v: &mut Vec<u8>, d: &crate::spend_frontier::Digest4| {
            for limb in d.iter() {
                v.extend_from_slice(&limb.to_le_bytes());
            }
        };
        v.extend_from_slice(&self.epoch.to_le_bytes());
        digest(&mut v, &self.base_acc);
        v.extend_from_slice(&self.base_seq.to_le_bytes());
        digest(&mut v, &self.base_prev);
        v.extend_from_slice(&self.base_gen.to_le_bytes());
        v.extend_from_slice(&self.boundary.to_le_bytes());
        v.extend_from_slice(&(self.carry_nonmembers.len() as u32).to_le_bytes());
        for id in &self.carry_nonmembers {
            v.extend_from_slice(id);
        }
        // DB-358 increment 2: the respend segment, only when there is one, so an empty carry writes the old bytes —
        // EXCEPT that an anchor ring always follows a respend segment (empty or not), so two segments mean both.
        // DB-353 landing 2: a band segment always follows a bond segment (possibly empty), so four segments mean all four.
        // DB-274 (dir_set): a directory segment always follows a band segment (possibly empty), so five segments mean all five.
        // DB-417: a peg segment always follows a directory segment (possibly empty), so six segments mean all six.
        let peg = self.peg.is_some();
        let dir = !self.dir.is_empty() || peg;
        let band = !self.band.is_empty() || dir;
        let bonds = !self.bonds.is_empty() || band;
        if !self.respend.is_empty() || !self.anchor_ring.is_empty() || bonds {
            let r = self.respend.encode();
            v.extend_from_slice(&(r.len() as u32).to_le_bytes());
            v.extend_from_slice(&r);
        }
        // DB-274 P2: a bond segment always follows a ring segment (possibly empty), so three segments mean all three.
        if !self.anchor_ring.is_empty() || bonds {
            let mut ring = Vec::with_capacity(12 + self.anchor_ring.len() * (8 + Self::DIGEST_BYTES));
            ring.extend_from_slice(ANCHOR_RING_MAGIC);
            ring.extend_from_slice(&(self.anchor_ring.len() as u32).to_le_bytes());
            for (ordinal, root) in &self.anchor_ring {
                ring.extend_from_slice(&ordinal.to_le_bytes());
                digest(&mut ring, root);
            }
            v.extend_from_slice(&(ring.len() as u32).to_le_bytes());
            v.extend_from_slice(&ring);
        }
        if bonds {
            let mut seg = BOND_CARRY_MAGIC.to_vec();
            match postcard::to_allocvec(&self.bonds) {
                Ok(payload) => seg.extend_from_slice(&payload),
                // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record
                // (the fail-closed resume), never with a silently partial bond state.
                Err(_) => eprintln!("[persist] ⛔ DB-274 P2: the bond fold state did not encode — this checkpoint's fold record will be refused at resume"),
            }
            v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
            v.extend_from_slice(&seg);
        }
        if band {
            let mut seg = BAND_CARRY_MAGIC.to_vec();
            match postcard::to_allocvec(&self.band) {
                Ok(payload) => seg.extend_from_slice(&payload),
                // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record.
                Err(_) => eprintln!("[persist] ⛔ DB-353: the band door did not encode — this checkpoint's fold record will be refused at resume"),
            }
            v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
            v.extend_from_slice(&seg);
        }
        if dir {
            let mut seg = DIR_CARRY_MAGIC.to_vec();
            match postcard::to_allocvec(&self.dir) {
                Ok(payload) => seg.extend_from_slice(&payload),
                // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record.
                Err(_) => eprintln!("[persist] ⛔ DB-274 (dir_set): the directory journal did not encode — this checkpoint's fold record will be refused at resume"),
            }
            v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
            v.extend_from_slice(&seg);
        }
        if let Some(carry) = &self.peg {
            let mut seg = PEG_CARRY_MAGIC.to_vec();
            match postcard::to_allocvec(carry) {
                Ok(payload) => seg.extend_from_slice(&payload),
                // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record.
                Err(_) => eprintln!("[persist] ⛔ DB-417: the peg ledger's object journal did not encode — this checkpoint's fold record will be refused at resume"),
            }
            v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
            v.extend_from_slice(&seg);
            // DB-419: the band door's rewind reach follows the peg segment (a seventh segment means all seven). A record
            // with no peg segment cannot place it, and none is written (every record this build captures carries both).
            if let Some(j) = &self.band_journal {
                let mut seg = BAND_JOURNAL_MAGIC.to_vec();
                match postcard::to_allocvec(j) {
                    Ok(payload) => seg.extend_from_slice(&payload),
                    // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record.
                    Err(_) => eprintln!("[persist] ⛔ DB-419: the band door's rewind reach did not encode — this checkpoint's fold record will be refused at resume"),
                }
                v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
                v.extend_from_slice(&seg);
            }
            // G1: the finalized checkpoint follows — the tail segments after the peg are read by magic, so it rides with
            // or without a band-journal segment (a stale band door writes none).
            if let Some((height, id)) = &self.finalized {
                let mut seg = FINALITY_CHECKPOINT_MAGIC.to_vec();
                seg.extend_from_slice(&height.to_le_bytes());
                seg.extend_from_slice(id);
                v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
                v.extend_from_slice(&seg);
            }
            // G2g-r2b: the pending certified fold base, read by magic like the two above.
            if let Some(p) = &self.fold_pending {
                let mut seg = FOLD_PENDING_MAGIC.to_vec();
                match postcard::to_allocvec(p) {
                    Ok(payload) => seg.extend_from_slice(&payload),
                    // The magic alone is refused whole by the decoder: the restart then resumes with NO fold record.
                    Err(_) => eprintln!("[persist] ⛔ G2g-r2b: the pending fold base did not encode — this checkpoint's fold record will be refused at resume"),
                }
                v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
                v.extend_from_slice(&seg);
            }
            // §RF-3: the member ring commit history, read by magic like the three above.
            if !self.member_ring_commits.is_empty() {
                let mut seg = MEMBER_RING_COMMITS_MAGIC.to_vec();
                seg.extend_from_slice(&(self.member_ring_commits.len() as u32).to_le_bytes());
                for (k, c) in &self.member_ring_commits {
                    seg.extend_from_slice(&k.to_le_bytes());
                    seg.extend_from_slice(&c.0);
                }
                v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
                v.extend_from_slice(&seg);
            }
        }
        v
    }

    /// Parse a member-ring-commit segment body; `None` for anything but the magic, a count and exactly that many entries.
    fn decode_member_ring_commits(b: &[u8]) -> Option<Vec<(u64, crate::hash::Hash32)>> {
        if b.get(..8)? != MEMBER_RING_COMMITS_MAGIC {
            return None;
        }
        let n = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?) as usize;
        if n == 0 || b.len() != 12usize.checked_add(n.checked_mul(40)?)? {
            return None;
        }
        (0..n)
            .map(|i| {
                let e = &b[12 + 40 * i..12 + 40 * (i + 1)];
                Some((u64::from_le_bytes(e[..8].try_into().ok()?), crate::hash::Hash32(e[8..40].try_into().ok()?)))
            })
            .collect()
    }

    /// Parse a pending-fold-base segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_fold_pending(b: &[u8]) -> Option<FoldPendingCarry> {
        if b.get(..8)? != FOLD_PENDING_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<FoldPendingCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse a finalized-checkpoint segment body; `None` for anything but the magic, a height and exactly one 32-byte id.
    fn decode_finality_checkpoint(b: &[u8]) -> Option<(u64, [u8; 32])> {
        if b.len() != 8 + 8 + 32 || &b[..8] != FINALITY_CHECKPOINT_MAGIC {
            return None;
        }
        let height = u64::from_le_bytes(b[8..16].try_into().ok()?);
        let id: [u8; 32] = b[16..48].try_into().ok()?;
        Some((height, id))
    }

    /// Parse a band-journal segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_band_journal(b: &[u8]) -> Option<crate::nf_sparse::BandJournalCarry> {
        if b.get(..8)? != BAND_JOURNAL_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<crate::nf_sparse::BandJournalCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse a peg-carry segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_peg_carry(b: &[u8]) -> Option<PegCarry> {
        if b.get(..8)? != PEG_CARRY_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<PegCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse a directory-carry segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_dir_carry(b: &[u8]) -> Option<DirCarry> {
        if b.get(..8)? != DIR_CARRY_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<DirCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse a band-carry segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_band_carry(b: &[u8]) -> Option<BandCarry> {
        if b.get(..8)? != BAND_CARRY_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<BandCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse a bond-carry segment body; `None` for anything but the magic followed by exactly one encoded carry.
    fn decode_bond_carry(b: &[u8]) -> Option<BondCarry> {
        if b.get(..8)? != BOND_CARRY_MAGIC {
            return None;
        }
        let (carry, rest) = postcard::take_from_bytes::<BondCarry>(&b[8..]).ok()?;
        rest.is_empty().then_some(carry)
    }

    /// Parse an anchor-ring segment body; `None` for anything but exactly the magic, a count and that many entries.
    fn decode_anchor_ring(b: &[u8]) -> Option<Vec<(u64, crate::spend_frontier::Digest4)>> {
        if b.get(..8)? != ANCHOR_RING_MAGIC {
            return None;
        }
        let n = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?) as usize;
        let entry = 8 + Self::DIGEST_BYTES;
        if b.len() != 12usize.checked_add(n.checked_mul(entry)?)? {
            return None;
        }
        let mut ring = Vec::with_capacity(n);
        for i in 0..n {
            let e = &b[12 + i * entry..12 + (i + 1) * entry];
            let ordinal = u64::from_le_bytes(e[..8].try_into().ok()?);
            let mut root: crate::spend_frontier::Digest4 = Default::default();
            for (j, limb) in root.iter_mut().enumerate() {
                *limb = u64::from_le_bytes(e[8 + 8 * j..16 + 8 * j].try_into().ok()?);
            }
            ring.push((ordinal, root));
        }
        Some(ring)
    }

    /// Bytes one digest takes (8 per lane).
    const DIGEST_BYTES: usize = std::mem::size_of::<crate::spend_frontier::Digest4>();
    /// Bytes before the carried ids: epoch, base, base_seq, base_prev, base_gen, boundary, id count.
    const HEAD_BYTES: usize = 8 + Self::DIGEST_BYTES + 8 + Self::DIGEST_BYTES + 8 + 8 + 4;

    fn decode(b: &[u8]) -> Option<FoldRecord> {
        let d = Self::DIGEST_BYTES;
        let u64_at = |o: usize| b.get(o..o + 8).and_then(|s| <[u8; 8]>::try_from(s).ok()).map(u64::from_le_bytes);
        let digest_at = |o: usize| -> Option<crate::spend_frontier::Digest4> {
            let mut dg: crate::spend_frontier::Digest4 = Default::default();
            for (i, limb) in dg.iter_mut().enumerate() {
                *limb = u64_at(o + 8 * i)?;
            }
            Some(dg)
        };
        let head = Self::HEAD_BYTES;
        let n = b.get(head - 4..head).and_then(|s| <[u8; 4]>::try_from(s).ok()).map(u32::from_le_bytes)? as usize;
        let ids_end = head.checked_add(n.checked_mul(32)?)?;
        // DB-358 increment 2: exactly the ids (a pre-increment-2 record, or an empty respend carry), or the ids followed
        // by one `[u32 len][postcard bytes]` respend segment, or (DB-223) by that segment and then one anchor-ring
        // segment. Any other length is refused whole, as before.
        let seg_len = |at: usize| -> Option<usize> {
            b.get(at..at + 4).and_then(|s| <[u8; 4]>::try_from(s).ok()).map(|a| u32::from_le_bytes(a) as usize)
        };
        let (respend, anchor_ring, bonds, band, dir) = if b.len() == ids_end {
            (crate::respend::RespendCarry::default(), Vec::new(), BondCarry::default(), BandCarry::default(), (DirCarry::default(), (None, (None, (None, (None, Vec::new()))))))
        } else {
            let r_len = seg_len(ids_end)?;
            let r_end = ids_end.checked_add(4)?.checked_add(r_len)?;
            let respend = crate::respend::RespendCarry::decode(b.get(ids_end + 4..r_end)?)?;
            let (ring, bonds, band, dir) = if b.len() == r_end {
                (Vec::new(), BondCarry::default(), BandCarry::default(), (DirCarry::default(), (None, (None, (None, (None, Vec::new()))))))
            } else {
                let g_len = seg_len(r_end)?;
                let g_end = r_end.checked_add(4)?.checked_add(g_len)?;
                let ring = Self::decode_anchor_ring(b.get(r_end + 4..g_end)?)?;
                // DB-274 P2: a third segment is the bond carry; DB-353 landing 2: a fourth is the band carry; DB-274
                // (dir_set): a fifth is the directory carry; anything after it is refused whole.
                let (bonds, band, dir) = if b.len() == g_end {
                    (BondCarry::default(), BandCarry::default(), (DirCarry::default(), (None, (None, (None, (None, Vec::new()))))))
                } else {
                    let c_len = seg_len(g_end)?;
                    let c_end = g_end.checked_add(4)?.checked_add(c_len)?;
                    let bonds = Self::decode_bond_carry(b.get(g_end + 4..c_end)?)?;
                    let (band, dir) = if b.len() == c_end {
                        (BandCarry::default(), (DirCarry::default(), (None, (None, (None, (None, Vec::new()))))))
                    } else {
                        let d_len = seg_len(c_end)?;
                        let d_end = c_end.checked_add(4)?.checked_add(d_len)?;
                        let band = Self::decode_band_carry(b.get(c_end + 4..d_end)?)?;
                        // DB-417: a sixth segment is the peg ledger's object journal; anything after it is refused whole.
                        let dir = if b.len() == d_end {
                            (DirCarry::default(), (None, (None, (None, (None, Vec::new())))))
                        } else {
                            let e_len = seg_len(d_end)?;
                            let e_end = d_end.checked_add(4)?.checked_add(e_len)?;
                            let dir = Self::decode_dir_carry(b.get(d_end + 4..e_end)?)?;
                            let peg = if b.len() == e_end {
                                (None, (None, (None, (None, Vec::new()))))
                            } else {
                                let p_len = seg_len(e_end)?;
                                let p_end = e_end.checked_add(4)?.checked_add(p_len)?;
                                let peg = Self::decode_peg_carry(b.get(e_end + 4..p_end)?)?;
                                // DB-419: a seventh segment is the band door's rewind reach; anything after it is
                                // refused whole.
                                // G1: the tail segments after the peg — the band journal (DB-419) and the finalized
                                // checkpoint — are read BY MAGIC, each at most once; any other bytes refuse the record whole.
                                let mut band_journal = None;
                                let mut finalized = None;
                                let mut fold_pending = None;
                                let mut ring_commits = None;
                                let mut at = p_end;
                                while b.len() > at {
                                    let t_len = seg_len(at)?;
                                    let t_end = at.checked_add(4)?.checked_add(t_len)?;
                                    let seg = b.get(at + 4..t_end)?;
                                    match seg.get(..8)? {
                                        m if m == BAND_JOURNAL_MAGIC && band_journal.is_none() => {
                                            band_journal = Some(Self::decode_band_journal(seg)?)
                                        }
                                        m if m == FINALITY_CHECKPOINT_MAGIC && finalized.is_none() => {
                                            finalized = Some(Self::decode_finality_checkpoint(seg)?)
                                        }
                                        m if m == FOLD_PENDING_MAGIC && fold_pending.is_none() => {
                                            fold_pending = Some(Self::decode_fold_pending(seg)?)
                                        }
                                        m if m == MEMBER_RING_COMMITS_MAGIC && ring_commits.is_none() => {
                                            ring_commits = Some(Self::decode_member_ring_commits(seg)?)
                                        }
                                        _ => return None,
                                    }
                                    at = t_end;
                                }
                                (Some(peg), (band_journal, (finalized, (fold_pending, ring_commits.unwrap_or_default()))))
                            };
                            (dir, peg)
                        };
                        (band, dir)
                    };
                    (bonds, band, dir)
                };
                (ring, bonds, band, dir)
            };
            (respend, ring, bonds, band, dir)
        };
        let carry_nonmembers: Vec<[u8; 32]> = (0..n)
            .map(|i| b[head + 32 * i..head + 32 * (i + 1)].fixed::<32>())
            .collect();
        Some(FoldRecord {
            epoch: u64_at(0)?,
            base_acc: digest_at(8)?,
            base_seq: u64_at(8 + d)?,
            base_prev: digest_at(16 + d)?,
            base_gen: u64_at(16 + 2 * d)?,
            boundary: u64_at(24 + 2 * d)?,
            carry_nonmembers,
            respend,
            anchor_ring,
            bonds,
            band,
            dir: dir.0,
            peg: dir.1 .0,
            band_journal: dir.1 .1 .0,
            finalized: dir.1 .1 .1 .0,
            fold_pending: dir.1 .1 .1 .1 .0,
            member_ring_commits: dir.1 .1 .1 .1 .1,
        })
    }
}

/// The fold record a snapshot file carries, if any (a file written before DB-270 step 2 carries none).
fn fold_record_of(bytes: &[u8]) -> Option<FoldRecord> {
    let n = bytes.len();
    if n < 12 || &bytes[n - 8..] != FOLD_TRAILER_MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(bytes[n - 12..n - 8].try_into().ok()?) as usize;
    let start = n.checked_sub(12 + len)?;
    FoldRecord::decode(&bytes[start..n - 12])
}

/// ⭐ A FOLD REWIND IS NOT A ROLLBACK (2026-11-03, found on a real two-node network). A snapshot's weight is its fold root's, and a
/// rewind moves that root down on purpose: the selected chain moved, the fold follows it. MEASURED: a rewind of 4 records took a node's
/// root from blue score 53 to 51, the monotone guard then refused its shutdown snapshot, it restarted from the older checkpoint on the
/// abandoned branch, and the pair split on the record spine 3 shells later. So the rewind itself lowers this process's watermark to the
/// fork point. The guard keeps its job: a twin process seeds its watermark from the file at boot and has rewound nothing, so it still
/// cannot write a lighter chain over the checkpoint. cons: none on disk; a checkpoint may now legitimately read lighter than the one before it.
pub fn lower_watermark_after_fold_rewind(fork_blue_score: u64) {
    let mut g = HEAVIEST_SEEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = g.as_mut() {
        for best in map.values_mut() {
            if best.0 > fork_blue_score {
                *best = (fork_blue_score, 0);
            }
        }
    }
}

pub fn save(path: &PathBuf, snap: &NodeSnapshot) -> std::io::Result<()> {
    save_inner(path, snap, None).map(|_| ())
}

/// The checkpoint's bytes exactly as [`save_with_fold`] writes them and [`decode_checkpoint`] reads them: the snapshot's
/// encoding, then the fold record as a trailer (record ‖ its length ‖ the magic). Pure in its inputs: no file, no
/// watermark. One composition for the writer and for a pin that restarts a node through the boot's own decode door
/// (every `#[serde(skip)]` field of a carried block is dropped here, as on disk).
/// cons: none — the same bytes the writer composed inline before.
pub fn encode_checkpoint(snap: &NodeSnapshot, fold: Option<&FoldRecord>) -> Result<Vec<u8>, String> {
    let mut bytes = postcard::to_stdvec(snap).map_err(|e| e.to_string())?;
    if let Some(f) = fold {
        let rec = f.encode();
        bytes.extend_from_slice(&rec);
        bytes.extend_from_slice(&(rec.len() as u32).to_le_bytes());
        bytes.extend_from_slice(FOLD_TRAILER_MAGIC);
    }
    Ok(bytes)
}

/// ⛔ DB-270 step 2 — write the checkpoint WITH its fold record as a trailer (same bytes, same rename). `Ok(true)` only
/// when the file was written: the caller unlinks what this checkpoint absorbed only then.
pub fn save_with_fold(path: &PathBuf, snap: &NodeSnapshot, fold: &FoldRecord) -> std::io::Result<bool> {
    save_inner(path, snap, Some(fold))
}

fn save_inner(path: &PathBuf, snap: &NodeSnapshot, fold: Option<&FoldRecord>) -> std::io::Result<bool> {
    // MONOTONE PERSIST (see `HEAVIEST_SEEN`). WHAT PRODUCES the refused condition: a SECOND node process
    // on the same snapshot path — measured 2026-08-13 as a hand-spawned twin with the wrong env that came
    // up unjoined, produced ~300 island blocks, and overwrote the 111,797-block checkpoint at its exit.
    // CAN THE CAUSE BE DELETED: not from inside this process — a concurrent twin is another OS process
    // (operator error, a watchdog race, a stale respawn), exactly the "outside your reach" class; the
    // app-side single-spawn guard already exists and STILL could not stop a manual spawn. WHY THIS STAYS:
    // the file is the one shared object every such process touches, and `load()` at boot seeds each
    // process's watermark with the tall on-disk weight — so even the island twin refuses to write its own
    // lighter state over the checkpoint it loaded. Refusal is loud and returns Ok so shutdown completes.
    {
        let mut g = HEAVIEST_SEEN.lock().unwrap_or_else(|e| e.into_inner());
        let map = g.get_or_insert_with(std::collections::HashMap::new);
        let cand = (snap.blue_score, snap.height);
        // ⛔ AN UNREAD INCUMBENT IS NOT OURS TO DESTROY (2026-08-25: a failed load seeded no watermark,
        // so a fresh-genesis process freely overwrote both nodes' 26k checkpoints). If this process
        // holds NO watermark for the path but a file EXISTS there, read the incumbent's weight NOW and
        // seed from it; if the incumbent cannot be decoded at all, REFUSE the write outright — never
        // overwrite custody this binary cannot even read.
        if !map.contains_key(path) && snapshot_file_exists(path) {
            match std::fs::read(path)
                .ok()
                .and_then(|b| postcard::from_bytes::<NodeSnapshot>(&b).ok())
            {
                Some(inc) => {
                    map.insert(path.clone(), (inc.blue_score, inc.height));
                }
                None => {
                    eprintln!(
                        "[persist] ⛔⛔⛔ REFUSED to overwrite {}: an incumbent snapshot exists that                          this binary CANNOT DECODE — it may be heavier custody from another version.                          Move it aside deliberately if replacement is truly intended.",
                        path.display()
                    );
                    return Ok(false);
                }
            }
        }
        // The refused condition is PRODUCED by a concurrent second OS process on the same snapshot path
        // (measured 2026-08-13: a mis-spawned island twin) — a cause outside this process's reach, which
        // is why the refusal lives at the shared file's write choke-point and cannot be deleted upstream.
        match map.get(path).copied() {
            Some(best) if cand < best => {
                eprintln!(
                    "[persist] ⛔ REFUSED a snapshot write that would ROLL STATE BACK: heaviest seen \
                     blue_score={} height={} vs candidate blue_score={} height={}. Delete the snapshot \
                     file and restart if a rollback is genuinely intended.",
                    best.0, best.1, cand.0, cand.1
                );
                return Ok(false);
            }
            _ => {
                map.insert(path.clone(), cand);
            }
        }
    }
    let bytes = encode_checkpoint(snap, fold).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // G1 (lane a 2026-10-22): one temp file PER WRITE — the autosave thread and a shutdown save once shared `snap.tmp`, and
    // the second rename found no file (ENOENT), losing the newer checkpoint and every sibling cache written only after it.
    let tmp = path.with_extension(format!(
        "snap.tmp.{}.{}",
        std::process::id(),
        SNAPSHOT_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// The per-process sequence that names each snapshot write's temp file (see `save_inner`).
static SNAPSHOT_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Load + decode the snapshot. Returns `None` on any failure. ⛔ A MISSING file means "fresh genesis boot";
/// an EXISTING file that fails EVERY decode door means CORRUPT/INCOMPATIBLE — the caller must REFUSE to run
/// (never boot fresh beside real custody: measured 2026-08-25, a mid-struct field insert broke v26 decode,
/// load returned None, the node silently re-genesis'd at height 1 and its first save OVERWROTE both nodes'
/// 26k-block checkpoints — the exact no-regenesis cardinal this comment now enforces). Use
/// [`snapshot_file_exists`] + [`load`] together at boot.
/// Does a snapshot FILE exist at `path`? Pairs with [`load`]: exists && load()==None ⇒ corrupt ⇒ REFUSE.
/// ⭐⭐⭐ DB-397 fix A (user-approved 2026-10-05, no pillar trade) — THE NULLIFIER VIEW IS A VERIFIED RESUME CACHE.
/// MEASURED on the live pair: after a restart the view never re-installs (`[nf-pivot] … NOT at its pivot`), so under
/// DB-396 the fold waits for ever (`[fold-wait] the band lags the fold by its whole cap`) and a wallet reading that node
/// watches its funds vanish. The borrowed shape: Bitcoin's chainstate / Zcash's nullifier set are persisted as a CACHE
/// while the chain stays the authority (Ethereum's STF rule). This file holds the view's spent tags beside the snapshot;
/// on resume `Node::restore_nf_view` re-inserts them through `rebuild_nullifier_tree`, which REFUSES any stream whose
/// rebuilt root is not the resumed O(1) acc root — a stale or tampered file falls back to the peer warm exactly as before.
/// O1-INFINITY-REVIEWED: one file whose size is 32 B per REAL spend the view already holds in RAM (cover is never in the
/// view, DB-367), rewritten whole at each checkpoint — the RAM view mirrored, no new growth axis, no new authority.
pub fn nf_view_path(snapshot: &PathBuf) -> PathBuf {
    snapshot.with_extension("nfview")
}
pub fn save_nf_view(snapshot: &PathBuf, tags: &[[u8; 32]]) -> std::io::Result<()> {
    let bytes = postcard::to_allocvec(tags).map_err(|e| std::io::Error::other(e.to_string()))?;
    let path = nf_view_path(snapshot);
    let tmp = snapshot.with_extension("nfview.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)
}
pub fn load_nf_view(snapshot: &PathBuf) -> Option<Vec<[u8; 32]>> {
    let bytes = std::fs::read(nf_view_path(snapshot)).ok()?;
    crate::chain_object::decode_exact::<Vec<[u8; 32]>>(&bytes)
}

/// THE WINDOW ANCHOR beside the snapshot: the oldest frontier of the node's recent-frontier ring, `(ordinal, peaks_hex)`
/// — the point a resumed node replays its held records from to rebuild the witness windows (window index + path-refresh
/// ring) a wallet needs. One frontier (O(DEPTH) peaks), never a history: bounded, like the ring it comes from.
pub fn window_anchor_path(snapshot: &PathBuf) -> PathBuf {
    snapshot.with_extension("winanchor")
}
pub fn save_window_anchor(snapshot: &PathBuf, ordinal: u64, peaks_hex: &str) -> std::io::Result<()> {
    let bytes = postcard::to_allocvec(&(ordinal, peaks_hex.to_string())).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = snapshot.with_extension("winanchor.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &window_anchor_path(snapshot))
}
pub fn load_window_anchor(snapshot: &PathBuf) -> Option<(u64, String)> {
    let bytes = std::fs::read(window_anchor_path(snapshot)).ok()?;
    crate::chain_object::decode_exact::<(u64, String)>(&bytes)
}

/// ⭐⭐ T1.7 — THE WINDOW INDEX IS A VERIFIED RESUME CACHE (Bitcoin's chainstate shape, the chain stays the authority).
/// MEASURED (sim fast lane, T1.7): a restarted node rebuilt its index only from the window anchor (the last 64 ordinals),
/// so every window folded earlier was gone and a wallet's catch-up read zeros for it. The index is written beside the
/// snapshot as one file per shard / level-major chunk ([`crate::window_index::WinFile`]); a checkpoint rewrites only the
/// files a fold or rewind touched since the last one, and a resume keeps only the windows bound by hashes to the
/// restored spine root (`WindowIndex::bound_to`).
/// O1-INFINITY-REVIEWED: the RAM index mirrored on disk (the user's 9/28 index-growth decision), never a new axis; the
/// per-checkpoint write is the open shard and chunk files (≤ 4,094 × 73 B ≈ 299 KB each), never f(history).
pub fn window_index_dir(snapshot: &PathBuf) -> PathBuf {
    snapshot.with_extension("windows")
}
/// Write (or remove, for `None`) each changed index file. Returns the files NOT written, for the next checkpoint.
pub fn save_window_files(
    snapshot: &PathBuf,
    files: &[(crate::window_index::WinFile, Option<Vec<u8>>)],
) -> Vec<crate::window_index::WinFile> {
    let dir = window_index_dir(snapshot);
    if !files.is_empty() && std::fs::create_dir_all(&dir).is_err() {
        return files.iter().map(|(f, _)| *f).collect();
    }
    let mut failed = Vec::new();
    for (f, bytes) in files {
        let path = dir.join(f.name());
        let ok = match bytes {
            Some(b) => {
                let tmp = dir.join(format!("{}.tmp", f.name()));
                std::fs::write(&tmp, b).and_then(|()| std::fs::rename(&tmp, &path)).is_ok()
            }
            None => match std::fs::remove_file(&path) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            },
        };
        if !ok {
            failed.push(*f);
        }
    }
    failed
}
/// Read every index file beside the snapshot. A file that does not decode is skipped whole (its windows come back from
/// the record replay or another holder). Returns the index as read — UNBOUND: the caller binds it to its spine.
pub fn load_window_index(snapshot: &PathBuf) -> crate::window_index::WindowIndex {
    let mut index = crate::window_index::WindowIndex::new();
    let Ok(rd) = std::fs::read_dir(window_index_dir(snapshot)) else { return index };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(f) = name.to_str().and_then(crate::window_index::WinFile::parse) else { continue };
        if let Ok(bytes) = std::fs::read(e.path()) {
            let _ = index.decode_file_into(f, &bytes);
        }
    }
    index
}

/// ⭐⭐⭐ DB-397 fix A, part 2 — THE REAL-NOTE RECORDS ARE A VERIFIED RESUME CACHE TOO (user 2026-10-05: "non spendable
/// notes is funds loss"). MEASURED on the live pair after both nodes restarted: the send's block kept its header but its
/// record BYTES lived only in RAM (`Node::da_mem`), so no node could serve the real note again and the wallet could not
/// witness its own change — unspendable on every node. Same borrowed shape as the view cache: the COMMITTED real-note
/// records (`da_mem` rows whose bytes the chain bound, never provisional pages, never the regenerable idle seed) are
/// written beside the snapshot; on resume each record installs ONLY when `da_notes_root_of(its bytes)` equals the
/// `output_notes_root` of the block the DAG still names for it — the same bind ingest checks. A stale or tampered record
/// is refused and the heal lane fetches the body as before.
/// O1-INFINITY-REVIEWED: the record window every node already holds in RAM, mirrored; bounded by the served span.
pub fn da_records_path(snapshot: &PathBuf) -> PathBuf {
    snapshot.with_extension("darecs")
}
pub fn save_da_records(snapshot: &PathBuf, rows: &[(u64, [u8; 32], Vec<Vec<u8>>, [u8; 32])]) -> std::io::Result<()> {
    let bytes = postcard::to_allocvec(rows).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = snapshot.with_extension("darecs.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, da_records_path(snapshot))
}
pub fn load_da_records(snapshot: &PathBuf) -> Option<Vec<(u64, [u8; 32], Vec<Vec<u8>>, [u8; 32])>> {
    let bytes = std::fs::read(da_records_path(snapshot)).ok()?;
    crate::chain_object::decode_exact::<Vec<(u64, [u8; 32], Vec<Vec<u8>>, [u8; 32])>>(&bytes)
}

/// ⭐⭐ G1 — THE RESTART CENSUS (lane a 2026-10-22): THE GRAFT'S PER-TX NULLIFIER RECORD IS A VERIFIED RESUME CACHE TOO.
/// `Node::mined_tx_nfs` (tx id → the real nullifiers of a block tx THIS node pooled, filled at graft) is the provisional
/// half of the pre-fold spent gate: `spent_by_an_unfolded_block` arm (b), read by `is_nullifier_spent` and by the pool's
/// `pool_copath_verdict` for every admitted spend. MEASURED (restart census, scratchpad/night/g1-feekey-harness-20261022.log):
/// CHANGED on both nodes at every restart — 14,199 B → 2 B and 9,451 B → 2 B — so until the fold reached the block, a
/// restarted node's pool stood on a spent set its own graft had already extended. Same borrowed shape as the view cache
/// and the real-note records (Bitcoin's chainstate: persisted beside the checkpoint, the chain the authority): the rows
/// whose tx a held block names are written beside the snapshot, sorted by tx id (one file for one set); on resume a row
/// installs ONLY when a block the DAG still holds names its tx AND that block is held WHOLE with every cached tag in its
/// lane (`padded_tags`) — a row no held block names, a row whose tags its block does not carry, and a row whose every
/// naming block is a header shell (nothing to verify it against) are dropped, and a file that does not decode installs
/// nothing. DIGITAL-CASH-PRIVACY-REVIEWED: this node's own datadir, the same class as the nullifier view cache beside
/// it; never on the wire.
/// O1-INFINITY-REVIEWED: the RAM map mirrored, itself bounded by the DAG window (`prune_mined_tx_nfs`); never f(history).
pub fn mined_tx_nfs_path(snapshot: &PathBuf) -> PathBuf {
    snapshot.with_extension("minednfs")
}
pub fn save_mined_tx_nfs(snapshot: &PathBuf, rows: &[([u8; 32], Vec<[u8; 32]>)]) -> std::io::Result<()> {
    let bytes = postcard::to_allocvec(rows).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = snapshot.with_extension("minednfs.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, mined_tx_nfs_path(snapshot))
}
pub fn load_mined_tx_nfs(snapshot: &PathBuf) -> Option<Vec<([u8; 32], Vec<[u8; 32]>)>> {
    let bytes = std::fs::read(mined_tx_nfs_path(snapshot)).ok()?;
    crate::chain_object::decode_exact::<Vec<([u8; 32], Vec<[u8; 32]>)>>(&bytes)
}

pub fn snapshot_file_exists(path: &PathBuf) -> bool {
    std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false)
}


/// Name the FROZEN door a pre-fork snapshot decodes through, so the refusal says WHICH file the operator
/// is holding instead of a bare "unreadable". Every arm is a decode-only probe — none of these layouts
/// has a `migrate()`, by construction (§AG), so there is no path from any of them into a live snapshot.
/// The door diagnosis, reachable from the crate's other test modules (node.rs owns the v25 fixture).
#[cfg(test)]
pub(crate) fn pre_fork_door_diagnosis_for_tests(bytes: &[u8]) -> String {
    pre_fork_door_diagnosis(bytes)
}

/// The first schema at or after the §AG hash replacement (2026-09-12): a file at `POST_AG_SCHEMA..SNAPSHOT_SCHEMA` was
/// written with THIS chain's hash.
const POST_AG_SCHEMA: u32 = 34;

/// ⛔ DB-342 — WHY a checkpoint that is not the current schema is refused, NAMED BY ITS OWN SCHEMA. Until 2026-09-28 every
/// such file got the §AG text ("its roots are digests of the RETIRED one-round hash"), including the post-fork v34–v36
/// files the live pair actually holds (MEASURED: both live snapshots are schema 35; this binary's `load` refuses them).
/// That sends an operator after the wrong cause. A post-fork file is refused because no frozen door carries its layout
/// into the current schema — the v38 bump moved the peg ledger's layout (SATOSHI), the v37 bump `Block`'s (DB-224), and the source forks the live testnet at
/// height 1, so it rides the owed reset — never because of the retired hash. The action is the same (move the file
/// aside deliberately); the reason is now true. The schema is the snapshot's first field (a postcard varint).
fn resume_refusal_reason(bytes: &[u8]) -> String {
    let mut schema: u32 = 0;
    for (i, b) in bytes.iter().take(5).enumerate() {
        schema |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            break;
        }
    }
    let named = pre_fork_door_diagnosis(bytes);
    if (POST_AG_SCHEMA..SNAPSHOT_SCHEMA).contains(&schema) {
        format!(
            "{named} (schema {schema}) REFUSED for resume — a post-fork layout this binary carries no door for into \
             schema {SNAPSHOT_SCHEMA}: the v38 bump moved the peg ledger's layout (SATOSHI) and v37 moved `Block`'s \
             (DB-224), and this source forks the live testnet at height 1, so the file rides the owed reset. Move it aside deliberately, then restart; the node \
             rejoins by the O(1) resync."
        )
    } else {
        format!(
            "{named} REFUSED for resume — its roots are digests of the RETIRED one-round hash (kill list §AG), which no \
             proof on this chain can reproduce. The hash replacement is a RE-GENESIS: move this file aside \
             deliberately, then restart."
        )
    }
}

fn pre_fork_door_diagnosis(bytes: &[u8]) -> String {
    let chain = |id: [u8; 32]| crate::hash::Hash32(id).to_hex();
    if let Ok(old) = postcard::from_bytes::<legacy_v34::NodeSnapshotV34>(bytes) {
        if old.schema() == 34 {
            return format!(
                "a v34 snapshot for chain {} (pre-DB-106: no certified root persisted — boots fresh by the O(1) resync)",
                chain(old.chain_id())
            );
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v33::NodeSnapshotV33>(bytes) {
        if old.schema() == 33 {
            return format!("a v33 snapshot for chain {}", chain(old.chain_id()));
        }
    }
    // The v31 and v32 layouts are byte-identical (v32 was a SEMANTIC bump), so one decoder opens both and
    // the schema byte separates them.
    if let Ok(old) = postcard::from_bytes::<legacy_v32::NodeSnapshotV32>(bytes) {
        if old.schema() == 32 {
            return format!("a v32 snapshot for chain {}", chain(old.chain_id()));
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v31::NodeSnapshotV31>(bytes) {
        if old.schema() == 31 {
            // v31 carries its own second reason on top of the hash fork: its spine may hold the retired
            // genesis fold's phantom leaves, which an aged file cannot disprove.
            let extra = if old.carries_visible_phantom_genesis_leaves() {
                " (its frontier VISIBLY carries the retired genesis fold's 256 phantom leaves)"
            } else {
                " (its spine was built under the retired genesis-fold law)"
            };
            return format!("a v31 snapshot for chain {}{extra}", chain(old.chain_id()));
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v30::NodeSnapshotV30>(bytes) {
        if old.schema() == 30 {
            return format!("a v30 snapshot for chain {}", chain(old.chain_id));
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v29::NodeSnapshotV29>(bytes) {
        if old.schema() == 29 {
            return format!("a v29 snapshot for chain {}", chain(old.chain_id));
        }
    }
    // v25–v27 predate `chain_id` entirely — they cannot name the chain they came from, and saying so is
    // the honest diagnosis rather than printing a zero id that looks like an answer.
    if let Ok(old) = postcard::from_bytes::<legacy_v27::NodeSnapshotV27>(bytes) {
        if old.schema == 27 {
            return "a v27 snapshot (pre-v29: the file records no chain identity)".to_string();
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v26::NodeSnapshotV26>(bytes) {
        if old.schema == 26 {
            return "a v26 snapshot (pre-v29: the file records no chain identity)".to_string();
        }
    }
    if let Ok(old) = postcard::from_bytes::<legacy_v25::NodeSnapshotV25>(bytes) {
        if old.schema == 25 {
            return "a v25 snapshot (pre-v29: the file records no chain identity)".to_string();
        }
    }
    "a snapshot that matches NO known layout (current or frozen v25..v34)".to_string()
}

pub fn load(path: &PathBuf) -> Option<NodeSnapshot> {
    load_with_fold(path).map(|(s, _)| s)
}

/// [`load`] plus the DB-270 step-2 fold record the same file carries (one read, at boot).
pub fn load_with_fold(path: &PathBuf) -> Option<(NodeSnapshot, Option<FoldRecord>)> {
    // This is the #106 boot checkpoint read, restored unchanged — ONE file, opened ONCE per process start
    // and never consulted again while the node runs. It is not a local-storage authority path: nothing here
    // answers a query that a proof is supposed to answer, and no per-item lookup reads back from disk. The
    // number of reads is f(constants) — exactly one, at boot, independent of the total block or note count.
    // An ABSENT file means "fresh genesis boot"; the caller separates that from "present but unreadable"
    // with `snapshot_file_exists` (see this module's docs), which is why the absent case is written as an
    // explicit outcome here rather than a swallowed error.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return None,
    };
    let (snap, fold) = match decode_checkpoint(&bytes) {
        Ok(decoded) => decoded,
        Err(reason) => {
            eprintln!("[persist] ⛔ {reason}");
            return None;
        }
    };
    // Seed the monotone-persist watermark with the on-disk weight — this is what makes even a process
    // that DECLINES to adopt the loaded state (an island twin, a fresh-env spawn) unable to overwrite
    // the tall checkpoint with its own lighter one (see `HEAVIEST_SEEN` / `save`). Two fixed words, O(1).
    {
        let mut g = HEAVIEST_SEEN.lock().unwrap_or_else(|e| e.into_inner());
        let map = g.get_or_insert_with(std::collections::HashMap::new);
        let disk = (snap.blue_score, snap.height);
        if map.get(path).map(|b| disk > *b).unwrap_or(true) {
            map.insert(path.clone(), disk);
        }
    }
    Some((snap, fold))
}

/// THE CHECKPOINT DOOR on bytes (B1 (ii), 2026-10-22: `decode_doors::SNAPSHOT_FILE` drives it with hostile bytes): the
/// current schema, else every frozen pre-fork layout is tried and NAMED in the refusal (`resume_refusal_reason`), then
/// the DB-270 fold-record trailer. `Err` carries the refusal the boot prints. Pure in the bytes — no file, no watermark.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<(NodeSnapshot, Option<FoldRecord>), String> {
    // ⭐ VERSIONED MIGRATION CHAIN (the upgrade-custody law, user 2026-08-24): a bump must carry custody
    // forward, never orphan it. Decode current first; a file that fails the current layout is offered to
    // each FROZEN prior layout in turn, and a successful legacy decode MIGRATES into the current struct
    // (its next save rewrites the file at the current schema). One explicit door per version —
    // works-or-fails, nothing silent.
    // ⛔⛔⛔ LENIENT BY DESIGN (DB-270 step 2, lane-dsol-zkvm's review): the checkpoint's FOLD RECORD rides after the struct
    // as a trailer (`FoldRecord`, `save_with_fold`), and `postcard::from_bytes` stops at the struct's end. An exact decode
    // here (`decode_exact`, the tree's rule for wire objects) would refuse EVERY checkpoint that carries one — every node
    // bricked at boot, silently. Pinned by `db270_a_checkpoint_carrying_its_fold_record_loads_through_the_current_door`.
    // The current schema is tried FIRST, so a trailer can never steer a v37 file into a legacy door.
    let snap: NodeSnapshot = match postcard::from_bytes::<NodeSnapshot>(bytes) {
        Ok(s) if s.schema == SNAPSHOT_SCHEMA => s,
        // ⛔⛔⛔ EVERY PRE-FORK DOOR DECODES AND REFUSES (2026-09-12, the §AG hash replacement).
        //
        // Kill list §AG measured the chain's ONE compression — `poseidon_pair` — as a single algebraic
        // round `MDS·(l + 7·r)^7`. Every part of it inverts (`x ↦ x^7` is a bijection over KoalaBear and
        // the MDS is invertible), so a non-membership copath could be SOLVED by division and a SPENT
        // nullifier read Unspent. The replacement is a truncated Poseidon2 permutation — a DIFFERENT
        // FUNCTION. That makes every root, commitment and accumulator written before the fork a digest of
        // something this binary no longer computes. Carried forward it would seat the node on a tip no
        // peer shares and no proof can open: custody-SHAPED garbage, which is strictly worse than a
        // refusal the operator can see and act on.
        //
        // So the frozen layouts all STAY (a real file still DECODES and is NAMED, never a parse error)
        // and not one of them has a `migrate()` any more — the refusal is BY CONSTRUCTION, which is the
        // v31 door's own law now applied uniformly to v25..v33. The hash replacement is a RE-GENESIS: an
        // operator moves the pre-fork file aside deliberately. Returning None routes into
        // `enable_persist`'s corrupt-load refusal (exit 97) rather than booting fresh beside real custody.
        _ => return Err(resume_refusal_reason(bytes)),
    };
    Ok((snap, fold_record_of(bytes)))
}

/// Fixed-width big-endian codec for the snapshot's magnitude counters (`blue_work` / `blue_score` / `height`), so
/// the serialized snapshot BYTE-LENGTH is invariant to height — TRUE constant size (the no-growth pillar). postcard
/// varint-encodes integers, so a plain `u64`/`u128` field would creep up logarithmically as the chain climbs; these
/// emit exactly 8 / 16 bytes at EVERY height. Applied via `#[serde(with = ...)]` on the counter fields.
#[cfg(test)]
pub(crate) mod real_v27_fixture_tests {
    //! ⛔⛔⛔ A LEGACY DOOR WITH NO TEST AGAINST REAL BYTES IS A DOOR NOBODY HAS OPENED.
    //!
    //! The v26 incident taught that postcard is POSITIONAL and every schema bump needs a frozen decoder.
    //! It did NOT teach that the frozen struct must be verified against a snapshot the DEPLOYED writer
    //! actually produced — and a door built by copying the current struct and deleting the new fields
    //! satisfies the letter of that rule while still being unable to read a real file. On mainnet that is
    //! every node refusing to boot after an upgrade, with real custody sitting on disk and no path back.
    //!
    //! These fixtures are genuine snapshots written by the live daemons, copied into
    //! `testdata/persist_fixtures/` before any chain reset could erase the only evidence that exists.

    /// Every fixture the repo carries. Absent fixtures SKIP so a fresh clone is green; a fixture that is
    /// present but that no door opens is a hard failure.
    /// TESTNET params for the real fixtures — module-level so every test in this module (and the door
    /// tests below) build the reader on the chain the bytes came from. Hoisted from the closures inside
    /// `a_real_live_snapshot_carries_through_the_door…` 2026-09-02 after persist.rs:1304 referenced them as
    /// module fns and the crate stopped compiling for every session.
    pub(crate) fn testnet_params() -> crate::params::ChainParams {
        let mut p = crate::params::ChainParams::default();
        p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p
    }

    pub(crate) fn testnet_genesis() -> crate::block::Block {
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(
            &crate::params::network_genesis_prefix("testnet"),
        );
        g
    }

    fn fixtures() -> Vec<(String, Vec<u8>)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/persist_fixtures");
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("snap") {
                let bytes = std::fs::read(&p).expect("fixture present but unreadable");
                out.push((format!("{}", p.display()), bytes));
            }
        }
        out
    }

    /// Report exactly which door opens each real file — the measurement itself, not a hypothesis.
    #[test]
    fn a_real_on_disk_snapshot_is_opened_by_some_door() {
        let fx = fixtures();
        if fx.is_empty() {
            eprintln!("[persist-fixture] no fixtures present — skipping (a fresh clone is green)");
            return;
        }
        let mut unopenable = Vec::new();
        for (name, bytes) in &fx {
            assert!(!bytes.is_empty(), "{name}: empty fixture");
            let cur = match postcard::from_bytes::<super::NodeSnapshot>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema),
                Err(e) => format!("REFUSED ({e})"),
            };
            let v27 = match postcard::from_bytes::<super::legacy_v27::NodeSnapshotV27>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema),
                Err(e) => format!("REFUSED ({e})"),
            };
            let v26 = match postcard::from_bytes::<super::legacy_v26::NodeSnapshotV26>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema),
                Err(e) => format!("REFUSED ({e})"),
            };
            let v29 = match postcard::from_bytes::<super::legacy_v29::NodeSnapshotV29>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema()),
                Err(e) => format!("REFUSED ({e})"),
            };
            let v30 = match postcard::from_bytes::<super::legacy_v30::NodeSnapshotV30>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema()),
                Err(e) => format!("REFUSED ({e})"),
            };
            let v31 = match postcard::from_bytes::<super::legacy_v31::NodeSnapshotV31>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema()),
                Err(e) => format!("REFUSED ({e})"),
            };
            // v33 made the current struct refuse v31/v32-era bytes (absent trailing field), so the
            // v32/v31 frozen doors joined this census the day they became load-bearing.
            let v32 = match postcard::from_bytes::<super::legacy_v32::NodeSnapshotV32>(bytes) {
                Ok(s) => format!("OPENS (schema {})", s.schema()),
                Err(e) => format!("REFUSED ({e})"),
            };
            eprintln!(
                "[persist-fixture] {name}\n    bytes {}  schema-byte {}\n    current : {cur}\n    v32 door: {v32}\n    v31 door: {v31}\n    v30 door: {v30}\n    v29 door: {v29}\n    v27 door: {v27}\n    v26 door: {v26}",
                bytes.len(),
                bytes[0]
            );
            if cur.starts_with("REFUSED")
                && v32.starts_with("REFUSED")
                && v31.starts_with("REFUSED")
                && v30.starts_with("REFUSED")
                && v29.starts_with("REFUSED")
                && v27.starts_with("REFUSED")
                && v26.starts_with("REFUSED")
            {
                unopenable.push(name.clone());
            }
        }
        assert!(
            unopenable.is_empty(),
            "NO DOOR OPENS these real snapshots: {unopenable:?} — a node upgrading past them REFUSES TO \
             BOOT (the corrupt-load cardinal firing correctly), which on mainnet is every node bricked \
             with custody on disk. The frozen door must be rebuilt from the layout the DEPLOYED writer \
             produces, not from the current struct minus its newest fields."
        );
    }

    /// ⭐⭐⭐ THE v32 DOOR PIN, ON THE LIVE PAIR'S ACTUAL v31 BYTES (item 9 + the v32 semantic bump).
    ///
    /// WHAT IT CATCHES, and how RED was confirmed: with SNAPSHOT_SCHEMA at 31 (the pre-landing tree), a
    /// v31 file resumed as CURRENT — same layout, same schema — carrying a spine possibly built under
    /// the retired genesis-fold law (`item9_measurement_leaf_law_on_a_had_false_boot` measured that law
    /// wedging the first real record and forking the frontier: count=256 at served_seq=1, then
    /// `[fold-order] ordinal 1 would append at leaf 256`). Under v32 the SAME bytes must instead take
    /// the frozen v31 door, and the refusal is BY CONSTRUCTION total: `NodeSnapshotV31` deliberately has
    /// NO `migrate()` — no code path exists that can turn v31 bytes into a current `NodeSnapshot`, so
    /// `load()`'s v31 arm can only print the named refusal and answer None (the exit-97
    /// deliberate-operator-action path). If the schema is ever un-bumped, the first assertion here goes
    /// RED (the file opens as current at the current schema). Reads the fixtures in place; writes nothing.
    #[test]
    fn a_real_v31_snapshot_takes_the_frozen_door_and_is_refused_for_resume() {
        let fx = fixtures();
        let v31: Vec<_> = fx.iter().filter(|(_, b)| b.first() == Some(&31u8)).collect();
        if v31.is_empty() {
            eprintln!("[persist-fixture] no v31 fixtures present — skipping (a fresh clone is green)");
            return;
        }
        for (name, bytes) in v31 {
            // The layouts are IDENTICAL by design (a semantic bump), so the current struct CAN parse the
            // bytes — but never at the current schema: the schema gate is the door's whole mechanism.
            match postcard::from_bytes::<super::NodeSnapshot>(bytes) {
                Ok(s) => assert_ne!(
                    s.schema,
                    super::SNAPSHOT_SCHEMA,
                    "{name}: a v31 file read as CURRENT at the CURRENT schema — the v32 bump is gone \
                     and a pre-roll spine would silently resume under the new genesis law"
                ),
                Err(_) => {}
            }
            let old = match postcard::from_bytes::<super::legacy_v31::NodeSnapshotV31>(bytes) {
                Ok(o) => o,
                Err(e) => panic!(
                    "{name}: the frozen v31 door cannot read a REAL live snapshot ({e}) — the refusal \
                     path could not even NAME the chain whose custody it protects"
                ),
            };
            assert_eq!(old.schema(), 31, "{name}: fixture is a schema-31 file");
            assert_ne!(
                old.chain_id(),
                [0u8; 32],
                "{name}: a v31 file NAMES its chain — the refusal message depends on it"
            );
            eprintln!(
                "[persist-fixture] {name}: v31 door decodes it; phantom-genesis shape visible at the \
                 boot instant: {}",
                old.carries_visible_phantom_genesis_leaves()
            );
        }
    }

    /// ⭐⭐⭐ ONE PIN FOR EVERY PRE-FORK DOOR: IT DECODES, AND `load` REFUSES IT (2026-09-12, §AG).
    ///
    /// This REPLACES five separate "carries through the door and two nodes resume it identically" pins
    /// (v27, v29, v30, v32, v33). They asserted a property this chain deliberately no longer has, and
    /// keeping them would have meant keeping the migrations that make the property true. The reason is
    /// not a schema change: kill list §AG measured the chain's ONE compression — `poseidon_pair` — as a
    /// single algebraic round `MDS·(l + 7·r)^7` whose every part inverts, so a non-membership copath
    /// could be SOLVED and a SPENT nullifier read Unspent. The replacement is a truncated Poseidon2
    /// permutation: a DIFFERENT FUNCTION. Every root, commitment and accumulator written before that
    /// change is a digest of something this binary no longer computes.
    ///
    /// ⛔ SO "CUSTODY CARRIES" AND "THE HASH CHANGED" ARE NOT BOTH SATISFIABLE, and the upgrade-custody
    /// law does not decide it — that law exists because refuse-and-resync once destroyed REAL rows on
    /// both nodes of a pair. A pre-fork file's rows are not recoverable custody: its note commitments
    /// and frontier peaks cannot be reproduced, so a "carried" checkpoint would seat the node on a tip
    /// no peer shares and no proof can open. Custody-SHAPED garbage is worse than a refusal an operator
    /// can see, because only one of the two is visible before funds move.
    ///
    /// What this gate proves is therefore STRONGER than the migration pins it replaces, and it is the
    /// funds-safety property: for every real on-disk fixture, (a) its own frozen door still DECODES it —
    /// so `load` can NAME the file rather than report garbage — and (b) `load` answers None, which is the
    /// exact condition `enable_persist` turns into a refusal to boot (exit 97) instead of starting fresh
    /// beside real custody.
    #[test]
    fn every_pre_fork_fixture_decodes_through_its_own_door_and_load_refuses_it() {
        let fx = fixtures();
        if fx.is_empty() {
            eprintln!("[persist-fixture] no fixtures present — skipping (a fresh clone is green)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("musdm-prefork-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let mut checked = 0usize;
        for (name, bytes) in &fx {
            let schema = bytes.first().copied().unwrap_or(0);
            // (a) the file's OWN frozen door opens it — the refusal depends on being able to name it.
            let named = super::pre_fork_door_diagnosis(bytes);
            assert!(
                !named.starts_with("a snapshot that matches NO known layout"),
                "{name}: schema-byte {schema} opens under NO door (current or frozen v25..v33). A file \
                 no door can read is a file the refusal cannot NAME — rebuild the frozen door from the \
                 layout the DEPLOYED writer produced, never from the current struct minus its newest \
                 fields."
            );
            // (b) load REFUSES it. None is what `enable_persist` turns into exit 97.
            let path = dir.join(format!("prefork-{checked}.snap"));
            std::fs::write(&path, bytes).expect("write fixture");
            assert!(
                super::load(&path).is_none(),
                "{name}: a PRE-FORK snapshot RESUMED. Its roots are digests of the retired one-round \
                 hash (§AG), so this node would stand on a tip no honest producer can reproduce — with \
                 real custody on disk and no visible error."
            );
            eprintln!("[persist-fixture] {name}: door says \"{named}\" — load() REFUSED, as required");
            checked += 1;
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(checked > 0, "the gate measured nothing");
    }

}

mod fixed_u64 {
    pub fn serialize<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&v.to_be_bytes())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = u64;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("8 big-endian bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<u64, E> {
                let a: [u8; 8] = b
                    .try_into()
                    .map_err(|_| E::custom("bad fixed-u64 length"))?;
                Ok(u64::from_be_bytes(a))
            }
        }
        d.deserialize_bytes(V)
    }
}

mod fixed_u128 {
    pub fn serialize<S: serde::Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&v.to_be_bytes())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = u128;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("16 big-endian bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<u128, E> {
                let a: [u8; 16] = b
                    .try_into()
                    .map_err(|_| E::custom("bad fixed-u128 length"))?;
                Ok(u128::from_be_bytes(a))
            }
        }
        d.deserialize_bytes(V)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod a_failed_checkpoint_never_disables_all_later_ones_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// ⭐⭐⭐ ONE BAD CHECKPOINT MUST COST ONE CHECKPOINT, NOT EVERY FUTURE ONE.
    ///
    /// TWO-PARTY-REVIEWED: this is a persistence-liveness property of a single node's own writer, not a
    /// boundary crossing. Its cross-node consequence — a restarted node serving a stale chain to peers — is
    /// covered by the cross-device send.
    ///
    /// `Node::autosave` gates on the node's own `save_in_flight` (per node since 2026-09-20; the process-global
    /// it replaced let one node's save skip another's checkpoint): `swap(true)` returning `true` means "a save
    /// is already running, skip". The background thread used to clear it as its LAST statement, so any panic inside the
    /// save left it stuck `true` for the life of the process. Every later autosave then hit the early return
    /// and did nothing — silently. The node kept producing blocks and recording notes and never checkpointed
    /// again; on restart it resumed from the last snapshot that landed and everything after it was gone.
    ///
    /// Measured before the fix: the node reached ~6,930 blocks while its snapshot stayed frozen at 06:50, and
    /// a wallet funded after that point restored to a balance of ZERO. Persistence stopping silently is fund
    /// loss, so the flag must clear on EVERY exit path — including an unwind.
    #[test]
    fn the_in_flight_flag_clears_even_when_the_save_thread_panics() {
        // The exact guard `autosave` installs, over the same per-node `Arc<AtomicBool>` shape.
        // cons: none — a test-local flag; nothing is persisted or written here.
        struct SaveInFlightGuard(Arc<AtomicBool>);
        impl Drop for SaveInFlightGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }

        let flag = Arc::new(AtomicBool::new(false));
        assert!(
            !flag.swap(true, Ordering::AcqRel),
            "a fresh flag must let the first save through"
        );

        // A save that PANICS mid-write, exactly as a serialization or disk edge would.
        let in_flight = Arc::clone(&flag);
        let died = std::thread::spawn(move || {
            let _clear_on_any_exit = SaveInFlightGuard(in_flight);
            panic!("checkpoint write blew up");
        })
        .join();
        assert!(
            died.is_err(),
            "the save thread must actually have panicked or this proves nothing"
        );

        assert!(
            !flag.load(Ordering::Acquire),
            "the in-flight flag is STILL set after a panicking save. Every future checkpoint is now a silent \
             no-op, so the node will keep recording notes it never persists and lose them all on restart."
        );
        // And the next save must genuinely be admitted, not merely observe a cleared flag.
        assert!(
            !flag.swap(true, Ordering::AcqRel),
            "the checkpoint after a failed one was refused — persistence stopped permanently"
        );
        flag.store(false, Ordering::Release);
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod snapshot_composition_tests {
    /// ⛔ WHAT ACTUALLY FILLS THE NODE'S STATE — measured field by field, not guessed.
    ///
    /// User's bar: a node is "a few KB forever to operate; anything above that is an error in design".
    /// `node_state_is_constant_size_no_growth_regardless_of_block_count` proves the state is CONSTANT
    /// (byte-identical across block counts — that assertion passes) but measures 17,336 B against its own
    /// 4,096 B bar. CONSTANT IS NOT SMALL, and a constant bloat hides just as well as a growing one.
    ///
    /// ⚠️ I attributed this to the tip block's 8,192 B tag set first. That was WRONG: `export_snapshot`
    /// already strips the tip block's proof (`nullifier_proof: default()`, `output_notes: empty`). Measuring
    /// a produced block instead of the actual snapshot produced a confident, useless number — so this
    /// serializes the REAL exported snapshot and its individual fields.
    #[test]
    fn the_node_snapshot_is_attributed_field_by_field() {
        let mut n = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
        let need = n.mempool().required_stamp_bits();
        let tx = crate::node::tests::grind_tx(
            b"snap-parts",
            1000,
            vec![crate::hash::Hash32::hash(b"snap-parts-nf")],
            need,
        );
        n.ingest_tx_unverified(tx).expect("pool a real spend");
        let _ = n.produce(
            5_000,
            crate::hash::Hash32::hash(b"fr"),
            crate::hash::Hash32::hash(b"mc"),
        );
        let s = n.export_snapshot().expect("snapshot");
        let sz = |v: &dyn Fn() -> Vec<u8>| v().len();
        let total = postcard::to_stdvec(&s).expect("ser").len();
        eprintln!(
            "[snap-fields] TOTAL={total} B | tip_block={} genesis_commit={} bond_locked={} bond_height={} \
             spend_frontier={} root_history={} circulating_records={} ({} entries)",
            sz(&|| postcard::to_stdvec(&s.tip_block).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.genesis_commit).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.bond_locked).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.bond_height).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.spend_frontier).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.root_history).unwrap_or_default()),
            sz(&|| postcard::to_stdvec(&s.circulating_records).unwrap_or_default()),
            s.circulating_records.len(),
        );
        // TWO-PARTY (test standard): the snapshot's whole purpose is that ANOTHER process resumes the
        // SAME chain state from it. Restore into a second node and assert the state-bearing fields
        // derive identically — an attribution print alone cannot catch a field the restore drops.
        let mut n2 = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
        let s2 = n
            .export_snapshot()
            .expect("snapshot for the restoring party");
        assert!(
            n2.restore_snapshot(s2),
            "a second node restores the exported snapshot"
        );
        assert_eq!(
            n2.selected_tip(),
            n.selected_tip(),
            "restored tip matches the exporter's"
        );
        // (The snapshot carries NO nullifier acc by design — that state self-warms from the DA /
        // arrives certified in the DSYNC bundle; asserting it here would test a promise the
        // snapshot never makes.)
        assert_eq!(
            n2.nullifier_root(),
            n.nullifier_root(),
            "restored nullifier root matches — the one spent-state coordinate every spend proves against"
        );
        assert_eq!(
            n2.note_frontier_root(),
            n.note_frontier_root(),
            "restored spend-frontier root matches — the coordinate every recipient copath resolves against"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod live_snapshot_probe {
    /// ⭐ WHAT IS ACTUALLY IN A REAL OPERATOR'S SNAPSHOT — read off disk, attributed per field.
    ///
    /// Not a gate: it asserts nothing about a machine-specific file and SKIPS when the file is absent, so
    /// it is green on any checkout. It exists because nothing in this tree could answer the owner's
    /// question — "why is disk filling" — about a REAL node. The only per-field breakdown that existed ran
    /// on a synthetic node inside a unit test, which is how a 74,902,578-byte live snapshot went unnoticed
    /// beside a pruning window that was doing its job at 22 MB.
    ///
    /// Point it at a snapshot with MONEROUSD_SNAP_PROBE=/path/to/state-NNNNN.snap
    #[test]
    fn attribute_a_real_on_disk_snapshot_when_one_is_named() {
        let Ok(path) = std::env::var("MONEROUSD_SNAP_PROBE") else {
            eprintln!("[snap-probe] no MONEROUSD_SNAP_PROBE set — nothing to attribute (not a failure)");
            return;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("[snap-probe] cannot read {path} — skipping");
            return;
        };
        let total = bytes.len();
        let Ok(s) = postcard::from_bytes::<super::NodeSnapshot>(&bytes) else {
            eprintln!("[snap-probe] {path} ({total} B) did not decode as the CURRENT NodeSchema — it is \
                       probably an older schema; nothing to attribute");
            return;
        };
        let sz = |v: Vec<u8>| v.len();
        let mut rows: Vec<(&str, usize)> = vec![
            ("circulating_records", sz(postcard::to_stdvec(&s.circulating_records).unwrap_or_default())),
            ("letter_columns", sz(postcard::to_stdvec(&s.letter_columns).unwrap_or_default())),
            ("spend_frontier", sz(postcard::to_stdvec(&s.spend_frontier).unwrap_or_default())),
            ("root_history", sz(postcard::to_stdvec(&s.root_history).unwrap_or_default())),
            ("stake_frontier", sz(postcard::to_stdvec(&s.stake_frontier).unwrap_or_default())),
            ("nf_blocks", sz(postcard::to_stdvec(&s.nf_blocks).unwrap_or_default())),
            ("nf_leaves", sz(postcard::to_stdvec(&s.nf_leaves).unwrap_or_default())),
            ("bond_locked", sz(postcard::to_stdvec(&s.bond_locked).unwrap_or_default())),
            ("validator_custody", sz(postcard::to_stdvec(&s.validator_custody).unwrap_or_default())),
            ("tip_block", sz(postcard::to_stdvec(&s.tip_block).unwrap_or_default())),
        ];
        rows.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("[snap-probe] {path}");
        eprintln!("[snap-probe] TOTAL {total} B at height {} ({} circulating record(s))", s.height, s.circulating_records.len());
        for (name, b) in rows {
            if b > 1024 {
                eprintln!("[snap-probe]   {:<22} {:>12} B  ({:>5.1}%)", name, b, 100.0 * b as f64 / total as f64);
            }
        }
        if !s.circulating_records.is_empty() {
            let note_bytes: usize = s.circulating_records.iter().map(|r| r.2.len()).sum();
            let tgt_bytes: usize = s.circulating_records.iter().map(|r| r.3.len()).sum();
            eprintln!(
                "[snap-probe]   -> per record: {:.0} B of notes + {:.0} B of targets, over {} record(s)",
                note_bytes as f64 / s.circulating_records.len() as f64,
                tgt_bytes as f64 / s.circulating_records.len() as f64,
                s.circulating_records.len()
            );
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
}

#[cfg(all(test, feature = "pins-core"))]
mod snapshot_anchor_inspection {
    //! DIAGNOSTIC (2026-09-02 live incident): print the anchor/map state carried by real snapshot
    //! bytes. Paths come from `USDMD_INSPECT_SNAPS` (colon-separated); the test passes regardless —
    //! it is an instrument, run with `--nocapture`.
    #[test]
    fn print_anchor_state_of_real_snapshots() {
        let Ok(list) = std::env::var("USDMD_INSPECT_SNAPS") else { return };
        for p in list.split(':').filter(|s| !s.is_empty()) {
            let bytes = match std::fs::read(p) { Ok(b) => b, Err(e) => { eprintln!("{p}: unreadable {e}"); continue } };
            let schema = bytes.first().copied().unwrap_or(0);
            let snap = match schema {
                30 => postcard::from_bytes::<super::NodeSnapshot>(&bytes).ok(),
                // A v29 file decodes, but there is no `migrate()` any more (§AG: its roots are digests
                // of the retired hash), so this instrument can only report that it was recognised.
                29 => {
                    eprintln!("[inspect] {p}: schema 29 DECODES through its frozen door and is PRE-FORK — no live view exists");
                    None
                }
                _ => None,
            };
            match snap {
                None => eprintln!("[inspect] {p}: schema {schema}: DID NOT DECODE"),
                Some(s) => eprintln!(
                    "[inspect] {p}: schema {schema} height {} circulating={} letters={} sparse_root={:02x}{:02x}",
                    s.height,
                    s.circulating_records.len(),
                    s.letter_columns.len(),
                    s.sparse_acc_root[0],
                    s.sparse_acc_root[1],
                ),
            }
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod live_row_survival_diagnostic {
    //! DIAGNOSTIC (2026-09-02 live incident): restore REAL live-pair bytes into TWO fresh nodes and count
    //! which ledger rows survive, by class — asserting both nodes hold the SAME rows afterwards (the
    //! two-party standard: a restart that loses rows on one node and not the other is the disagreement
    //! that breaks this system). Env-gated instrument; run with --nocapture.
    fn decode(bytes: &[u8]) -> super::NodeSnapshot {
        match bytes.first().copied() {
            Some(30) => postcard::from_bytes::<super::NodeSnapshot>(bytes).expect("v30"),
            // §AG: a v29 file has no path into a live snapshot, so this instrument cannot run on one.
            Some(29) => panic!(
                "USDMD_SURVIVAL_SNAP names a schema-29 file. It decodes through the frozen v29 door but \
                 its roots are digests of the RETIRED one-round hash, so there is no live snapshot to \
                 restore — point this instrument at a current-schema file."
            ),
            other => panic!("schema {other:?}"),
        }
    }

}

/// PROBE (2026-09-21, run by hand against a COPY of a live checkpoint named in `USDMD_PROBE_SNAP`):
/// what does the checkpoint's record ledger actually hold? Rows with/without an ordinal, seed-only rows,
/// letters-only shells, the unspent map size — the ground truth behind a `da_mem` that outgrows the pruner.
#[test]
#[ignore]
fn probe_live_checkpoint_ledger_histogram() {
    let Ok(path) = std::env::var("USDMD_PROBE_SNAP") else {
        eprintln!("[probe] USDMD_PROBE_SNAP not set — nothing to probe");
        return;
    };
    let snap = load(&std::path::PathBuf::from(&path)).expect("the checkpoint decodes");
    let mut with_ord = 0usize;
    let mut no_ord = 0usize;
    let mut empty_bytes = 0usize;
    let mut seed_only = 0usize;
    let mut multi = 0usize;
    let mut bytes_total = 0usize;
    let mut no_ord_seed = 0usize;
    for (rid, ord, bytes, _targets) in &snap.circulating_records {
        bytes_total += bytes.len();
        let is_seed = bytes.len() == crate::cover::PQ_NOTE_BYTES
            && bytes[..] == crate::cover::public_idle_seed_note(*rid)[..];
        if *ord == u64::MAX { no_ord += 1; if is_seed { no_ord_seed += 1; } } else { with_ord += 1; }
        if bytes.is_empty() { empty_bytes += 1; }
        if is_seed { seed_only += 1; }
        if bytes.len() > crate::cover::PQ_NOTE_BYTES { multi += 1; }
    }
    let mut ords: Vec<u64> = snap.circulating_records.iter().map(|r| r.1).filter(|o| *o != u64::MAX).collect();
    ords.sort_unstable();
    eprintln!(
        "[probe] schema={} height={} served_seq={} da_top={} da_base={} rows={} with_ord={} (min {:?} max {:?}) no_ord={} (seed {}) empty_bytes={} seed_only={} multi_note={} bytes_total={} letter_columns={} fold_carry_unfolded={} fold_carry_ancestors={}",
        snap.schema, snap.height, snap.served_seq, snap.da_top, snap.da_base,
        snap.circulating_records.len(), with_ord, ords.first(), ords.last(), no_ord, no_ord_seed, empty_bytes, seed_only, multi, bytes_total,
        snap.letter_columns.len(),
        snap.fold_carry.unfolded.len(), snap.fold_carry.ancestors.len()
    );
}

#[cfg(all(test, feature = "pins-core"))]
mod db341_one_state_dir {
    /// ⛔ DB-341 — ONE BASE FOR EVERY PER-NODE FILE. REJECTS any `".usdmd-node"` path literal outside `node_files.rs` (the
    /// one definition), `lifecycle.rs` (the machine-level LaunchAgent sentinel launchd watches at a fixed home path) and
    /// `harness/` (the operator's view of a CHILD process's datadir). A second formula is how the validator key split
    /// three ways and how an isolated node read the operator's live custody books. CALIBRATED: the census flags the old
    /// formula verbatim and passes a comment, so a green here is the census finding nothing, not a census that cannot see.
    #[test]
    fn db341_every_per_node_file_is_named_through_the_one_state_dir() {
        // TWO-PARTY-REVIEWED: a SOURCE census of this crate's per-node path formulas — no protocol boundary is crossed; the
        // property is that every writer and reader of a per-node file resolves ONE path, which a census of names decides.
        fn names_a_second_node_dir(line: &str) -> bool {
            line.contains("\".usdmd-node\"") && !line.trim_start().starts_with("//")
        }
        // the census's own calibration calls quote the old formula on purpose; nothing else is skipped
        let own_calibration = |line: &str| line.contains("names_a_second_node_dir(r#\"");
        assert!(names_a_second_node_dir(r#"    let dir = std::path::PathBuf::from(base).join(".usdmd-node");"#), "calibration: the old formula is flagged");
        assert!(!names_a_second_node_dir(r#"    // lives under ".usdmd-node" on desktop"#), "calibration: a comment is not a formula");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(d) = stack.pop() {
            for ent in std::fs::read_dir(&d).expect("src is readable").flatten() {
                let p = ent.path();
                let rel = p.strip_prefix(&src).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
                if p.is_dir() {
                    if rel != "harness" {
                        stack.push(p);
                    }
                    continue;
                }
                if !rel.ends_with(".rs") || rel == "node_files.rs" || rel == "lifecycle.rs" {
                    continue;
                }
                // O1-INFINITY-REVIEWED: a #[test] census reads this crate's SOURCE files once — never node state; its cost is f(number of source files), independent of chain height or note count.
                // An unreadable source file FAILS the census (it never reads as clean).
                let text = std::fs::read_to_string(&p).expect("a source file is readable");
                for (i, line) in text.lines().enumerate() {
                    if names_a_second_node_dir(line) && !own_calibration(line) {
                        offenders.push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "⛔ DB-341: a per-node path formula outside node_files::state_dir() — name the file through state_dir() and \
             serving_port(): {offenders:?}"
        );
    }

    /// ⛔ DB-342 — A REFUSED CHECKPOINT IS REFUSED FOR ITS REAL REASON. A post-fork schema (the live pair's v35) must be
    /// named as a layout with no door into the current schema — NOT as the retired one-round hash — while a pre-fork
    /// schema keeps the §AG reason. CALIBRATED both ways.
    #[test]
    fn db342_a_refused_checkpoint_names_its_own_schema_and_the_true_reason() {
        let v35 = [35u8, 0, 0, 0];
        let why = super::resume_refusal_reason(&v35);
        assert!(why.contains("schema 35") && why.contains("post-fork"), "a v35 file is named post-fork: {why}");
        assert!(!why.contains("RETIRED one-round hash"), "a v35 file is NOT blamed on the retired hash: {why}");
        let v30 = [30u8, 0, 0, 0];
        let why30 = super::resume_refusal_reason(&v30);
        assert!(why30.contains("RETIRED one-round hash"), "calibration: a pre-fork file keeps the §AG reason: {why30}");
    }

    /// ⛔ DB-343 — NO LEGACY DOOR NAMES A LIVE CONSENSUS TYPE. MEASURED 2026-09-28: the v31..v34 doors named the live
    /// `crate::block::Block` and `crate::sync::FoldCarry`, so the v37 block move and the 09-18 DAA-sample triple rotted
    /// them silently — real fixtures stopped decoding, and a refusal could no longer NAME the chain. REJECTS any
    /// non-comment `crate::block::` / `crate::sync::` in a `persist_legacy_v*.rs` door. CALIBRATED on the old import;
    /// an unreadable door file FAILS the census (never reads as clean).
    #[test]
    fn db343_no_legacy_door_names_a_live_consensus_type() {
        // TWO-PARTY-REVIEWED: a SOURCE census of this crate's decode doors — no protocol boundary is crossed here. A door's
        // second party is the DEPLOYED WRITER, and that side is exercised by `real_v27_fixture_tests` against real files.
        fn names_a_live_type(line: &str) -> bool {
            let l = line.trim_start();
            !l.starts_with("//") && (l.contains("crate::block::") || l.contains("crate::sync::"))
        }
        assert!(names_a_live_type("use crate::block::Block;"), "calibration: the rotted import is flagged");
        assert!(names_a_live_type("    pub fold_carry: crate::sync::FoldCarry,"), "calibration: the rotted field is flagged");
        assert!(!names_a_live_type("// the door once named crate::block::Block"), "calibration: a comment is not a type");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut doors = 0usize;
        let mut offenders = Vec::new();
        for ent in std::fs::read_dir(&src).expect("src is readable").flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if !(name.starts_with("persist_legacy_v") && name.ends_with(".rs")) {
                continue;
            }
            doors += 1;
            // O1-INFINITY-REVIEWED: a #[test] census reads this crate's SOURCE files once — never node state; its cost is f(number of source files), independent of chain height or note count.
            let text = std::fs::read_to_string(ent.path()).expect("a legacy door file is readable");
            for (i, line) in text.lines().enumerate() {
                if names_a_live_type(line) {
                    offenders.push(format!("{name}:{}", i + 1));
                }
            }
        }
        assert!(doors >= 8, "the census must see the legacy doors (saw {doors})");
        assert!(offenders.is_empty(), "⛔ DB-343: a legacy door names a LIVE consensus type — freeze it: {offenders:?}");
    }
}

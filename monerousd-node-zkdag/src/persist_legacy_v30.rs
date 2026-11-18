// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v30 SNAPSHOT DOOR — the layout every schema-30 writer (binary cc3e5c96, the 2026-09-02
//! gate-certified deploy; the live pair's custody on disk on 2026-09-03) put on disk. v31 exists
//! because `ChainParams` gained `record_fold_depth` at its tail (the canonical record fold) and the
//! snapshot gained `fold_chain_tip` at its tail — so a v31 binary can no longer decode a v30 file
//! through the live structs, and without this door the next deploy would refuse to start BOTH live
//! nodes with real custody on disk (the measured 8/26 blocker class).
//!
//! The v30 layout is EXACTLY the frozen v27 body with `ChainParams` at its v30 layout (v27 params +
//! `order_fill_fee_bps` mid-struct, the v30 change) and `chain_id` appended (the v29 change). Every type
//! in this serde graph is FROZEN (`BlockV27`, `ChainParamsV30`) or has not changed its layout since the
//! v27 freeze (the frontier, peg ledger and letter columns — pinned by the real-file door tests).
//! Decode-only; nothing serializes from this type in production. cons: none — transient inside
//! `load`, no new disk/RAM/wire/time term.
//!
//! Upgrade-custody law (user 2026-08-24): a bump must carry custody forward, never orphan it.
//! Frozen-door self-contained law (2026-08-26): the byte contract lives in frozen types; verified by
//! `a_real_v30_snapshot_carries_through_the_v30_door_and_two_nodes_resume_it_identically` against
//! the REAL files `testdata/persist_fixtures/state-v30-{27780,28901}.snap`.

use std::collections::HashMap;

use crate::persist::frozen_v27::BlockV27;
// The accumulators are FROZEN types too (2026-09-07): the v30 writer (cc3e5c96, 2026-09-02) was a
// depth-32 build; `SPEND_TREE_DEPTH` moved 32 → 64 on 9/4 and the live frontier wire form moved with
// it (1,064 → 2,088 bytes), rotting this door against its own real fixtures.
use crate::persist::frozen_v27::PoseidonSpendFrontierV27;

use super::LetterColumns;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV30 {
    /// Layout guard — a mismatch means "ignore this snapshot".
    pub schema: u32,
    /// Genesis-parity guard — refuse a snapshot minted under a different genesis (anti chain-split).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    pub genesis_commit: Vec<u8>,
    /// The checkpoint tip, re-installed via `Dag::add_anchor` (no parent history needed). O(1).
    pub tip_block: BlockV27,
    /// The tip's accumulated PoUW blue-work + blue-score (so the reorg/ordering math resumes apples-to-apples).
    /// Fixed-width big-endian (16/8 bytes) so the snapshot length never creeps up with height — true constant size.
    #[serde(with = "super::fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "super::fixed_u64")]
    pub blue_score: u64,
    /// Selected-chain length at the tip (the reported height). Fixed-width big-endian (8 bytes), height-invariant.
    #[serde(with = "super::fixed_u64")]
    pub height: u64,
    // note_index REMOVED (no-growth, user 2026-07-14): the node keeps NO accumulated note set on disk or in RAM
    // — the frontier roots below are the sole note commitment, and note ciphertexts are peer-sampled DA (#27 DAS).
    // note_clues REMOVED (no-growth brick 3): the OMR detection-clue index is DA/acceleration data, not consensus —
    // it grew O(notes). It is now a BOUNDED in-RAM serve-cache (`Node::note_clues`, front-evicted), refilled forward
    // from the tx stream on restart; an evicted clue is peer-served (#27 DAS) or the wallet decap-scans (the clue is
    // only a pre-decap acceleration hint, never a correctness requirement). Not persisted ⇒ snapshot O(1) in notes.
    /// Locked validator-bond notes (value that backs weight, not independently spendable).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    pub bond_locked: HashMap<[u8; 32], Vec<u8>>,
    /// Bond HEIGHT per validator id — the anchor the unbond-DELAY (`stake_lock_blocks`) is measured from, so the
    /// bond lock survives a restart. `#[serde(default)]` = an older snapshot with no bond_height loads as empty
    /// (those legacy bonds are treated as matured — liveness-safe; new bonds record + enforce the delay).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub bond_height: HashMap<[u8; 32], u64>,
    /// v25 — THE BONDED VALIDATOR SET, deterministically sorted (see `ValidatorSet::export_state`): the
    /// finality quorum itself. Persisting only `bond_locked` kept the VALUE across restarts while the
    /// WEIGHT vanished — a resumed node had money locked for validators it no longer recognized, votes
    /// were rejected at `bond_of(voter)==0`, and finality died on every reboot. O(validators).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub bonded_validators: Vec<([u8; 32], u128)>,
    /// v25 — permanently slashed ids (equivocation bar survives a restart; a slashed validator must
    /// never re-admit just because the process cycled).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub slashed_validators: Vec<[u8; 32]>,
    /// v25 — total bond burned by slashing (observability; leaves the bonded weight forever).
    #[serde(default)]
    pub slashed_bond_burned: u128,
    /// v25 — the #75 confidential bonded-stake accumulator digest (value-hiding Poseidon commitment).
    #[serde(default)]
    pub validator_bond_commit: [u64; 4],
    /// v25 — per-validator bridge-custody points (secp33, ed32) so the reserve key-aggregate resumes
    /// with the set instead of waiting for re-registration.
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    // note_frontier REMOVED (no-growth brick 5): the redundant blake3 note-membership tree (a second tree over the
    // SAME note_cm leaves) is gone. The Poseidon `spend_frontier` below is now the SOLE note tree — it is what the
    // wallet proves membership against AND what the block header commits as `frontier_root`. One tree, not two.
    /// The Poseidon note-membership accumulator (the sole note tree; header `frontier_root` == its root),
    /// at the depth-32 writer's frozen wire shape.
    pub spend_frontier: PoseidonSpendFrontierV27,
    /// The ROOT-HISTORY accumulator (one leaf per block = that block's spend anchor). O(DEPTH) peaks, so persisting
    /// it is no-growth; a restart RESUMES it (never rebuilds from history) so wallets' receipt anchors stay provable.
    pub root_history: PoseidonSpendFrontierV27,
    /// ⭐⭐⭐ THE UNSPENT-NOTE ROOT — the deletion model's entire state, and it MUST survive a restart.
    ///
    /// Without this a reboot silently resets the root to the empty chain, which would make every already-spent
    /// note look unspent again: a restart would re-open every double-spend the chain had already closed. That
    /// is fund creation, not a hygiene nit, so it rides the snapshot beside `spend_frontier`.
    ///
    /// `serde(default)` so a schema-21 snapshot still loads and simply starts from the empty-chain root.
    ///
    /// O1-DEFINITION-REVIEWED: BY CONSTRUCTION — 4 u64 limbs, f(the Poseidon field width). No history
    /// quantity (height, blocks, notes, spends, age) appears in it, so this field is the same size at block
    /// 2,000 and block 2,000,000.
    #[serde(default)]
    pub unspent_note_root: [u64; 4],
    /// ⭐⭐⭐ THE UNSPENT MAP ITSELF — the deletion model's WORKING state, persisted beside the root it
    /// reproduces. WHY (measured TWICE on 2026-08-13): the map's rebuild inputs (recv/del sidecars) are
    /// RAM-only, so a full-mesh restart loses them everywhere, replay reads `0 receives, 0 deletions`,
    /// the certified root can never be reproduced, `history_complete` stays false and catch-up serve +
    /// sends BRICK mesh-wide — this forced one authorized re-genesis and then recurred on the fresh chain
    /// the same day. Persisting the map makes a restart SELF-SUFFICIENT: load, verify it reproduces
    /// `unspent_note_root` (fail-closed: mismatch → discard and rebuild as before), serve immediately.
    ///
    /// O1-DEFINITION-REVIEWED: bounded by CIRCULATING SUPPLY × tree depth — the deletion model's own
    /// state class ("state = circulating supply, not history"), the exact map every node already holds
    /// in RAM; a spent note's nodes are REMOVED. No height/blocks/age term. cons: snapshot grows
    /// f(circulating notes) (~8KB per live note at depth 256; ~100KB at today's 13 notes) — the disk
    /// mirror of accepted RAM state, never a second axis.
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub unspent_path_nodes: Vec<((usize, [u8; 32]), [u64; 4])>,
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
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub circulating_records: Vec<(u64, u64, Vec<u8>, Vec<u8>)>,
    /// v26 (user-authorized 2026-08-24, versioned by the SNAPSHOT_SCHEMA = 26 bump): filed mail bytes per
    /// retained record — same class and bound as `circulating_records` directly above, so a restart keeps
    /// mail exactly as it keeps balances.
    #[serde(default)]
    pub letter_columns: LetterColumns,

    /// ⭐⭐⭐ THE PERSISTED MAP'S OWN LEAF-FOLD ROOT, computed AT SAVE from exactly the leaves stored
    /// in `unspent_path_nodes` — self-consistent BY CONSTRUCTION whatever era the save caught.
    ///
    /// Without it, resume verified the persisted leaves against the LIVE `unspent_note_root`, and a
    /// save taken while the map was mid-heal (stale leaves, advanced root) produced a pair that can
    /// never verify: MEASURED 2026-08-22 on the live pair, EVERY boot printed "[uns-resume] ⛔
    /// persisted unspent map did NOT reproduce the persisted root — DISCARDED" on BOTH nodes, so
    /// `last_self_verified_root` stayed zero, the ladder-era heal had no anchor, and past ordinal
    /// DA_LADDER_SPAN the node could never become READY again after a restart.
    ///
    /// Zero = legacy (resume verifies against the live root exactly as before). Non-zero = resume
    /// verifies the map against THIS root (true by construction for any honest save; a corrupted
    /// snapshot still fails the fold and is discarded), installs it as the self-verified anchor,
    /// and the anchor heal folds forward to the live tip before serving.
    #[serde(default)]
    pub unspent_map_anchor_root: [u64; 4],
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
    pub membership_acc: [u64; 4],
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
    /// The staked-note accumulator, at the depth-32 writer's frozen wire shape (a fixed 1,064-byte
    /// blob at every height — f(the frozen depth constant only)).
    pub stake_frontier: PoseidonSpendFrontierV27,
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
    pub nf_cover_conf_acc: [u8; 32],
    /// The bidirectional peg reserve ledger (positions / reserve / minted / burned nullifiers).
    pub peg: crate::persist::frozen_v32::PegLedgerV32,
    /// The HF44 L2 settlement state root.
    pub l2_state_root: [u8; 32],
    /// v10: the GOVERNANCE-ACTIVE consensus parameters, FROZEN at this schema's layout (`ChainParamsV27`
    /// — the live type gained a mid-struct field 2026-09-01, the exact rot a live import invites) — VDF
    /// heartbeat length, DAG width, economic bands, etc. Persisting them is what lets an on-chain governance
    /// retune survive a restart: the node resumes the CHAIN's active params (genesis default + governance
    /// history), never silently reverting to the code default. Without this, a governance change would be lost
    /// on reboot and a param would effectively require a redeploy/re-genesis to change — the exact thing the
    /// freely-tunable mandate forbids. (Schema bumped to 10, so a pre-v10 snapshot is cleanly rejected and the
    /// node fresh-syncs rather than misreading a missing field.)
    pub params: crate::persist::frozen_v30::ChainParamsV30,

    /// v27 (user cardinal 2026-08-25, the resurrected-balance custody fix): each retained record's
    /// DELETION SIDECAR (`del_cms` wire bytes) rides the snapshot beside the note bytes it deletes from.
    /// Without this, a restart lost every historic deletion the ladder no longer replays — the post-boot
    /// heal then rebuilt an unspent lineage WITHOUT them and every previously-SPENT note resurfaced as
    /// spendable balance (measured live: a spent 5.0 drip re-entered two wallets wrong-high while the
    /// nullifier gate still refused re-spends — view broken, conservation display broken). Same
    /// supply-bounded custody class as `circulating_records` directly above: a record leaves this set as
    /// its notes leave circulation. `serde(default)` keeps v26 snapshots loading (they migrate forward
    /// with empty sidecars once; the fix is complete from the FIRST save after this deploy).
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    #[serde(default)]
    pub deletion_sidecars: Vec<(u64, Vec<u8>)>,
    /// v29: the genesis block id this checkpoint belongs to (see persist.rs).
    #[serde(default)]
    pub chain_id: [u8; 32],
}

impl NodeSnapshotV30 {
    pub fn schema(&self) -> u32 {
        self.schema
    }

    // ⛔⛔⛔ THERE IS DELIBERATELY NO `migrate()` — THE REFUSAL IS BY CONSTRUCTION (2026-09-12, §AG).
    // Every root, commitment and accumulator in a pre-fork file is a digest of the RETIRED one-round
    // `MDS·(l + 7·r)^7`, which kill list §AG measured as INVERTIBLE and which this chain replaced with a
    // truncated Poseidon2 permutation. A migrated snapshot would seat the node on a root that no honest
    // producer can ever reproduce and no proof can open: a tip no peer shares. That is strictly worse
    // than refusing, because it looks like custody. The layout above stays FROZEN so a real file still
    // DECODES and earns a NAMED refusal in `persist::load` instead of a parse error — but no code path
    // exists that can turn these bytes into a current `NodeSnapshot`. Same law as the v31 door.
}

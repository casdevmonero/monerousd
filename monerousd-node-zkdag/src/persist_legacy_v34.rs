// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! THE FROZEN v34 SNAPSHOT (2026-09-19, DB-106): the layout the deployed v34 writer wrote, kept whole so the
//! resume door can NAME a v34 file it refuses ("a v34 snapshot for chain …") instead of "unreadable". v35 adds
//! one tail field — `adopted_certified_root` — so a v34 file boots fresh by the O(1) DSYNC resync. Decode-only,
//! transient inside `load`; never a live store on a running node.
#![allow(dead_code)]
use super::*;
// ⛔ DB-343: a door names only FROZEN types (MEASURED 2026-09-28: this door named the LIVE `Block`, so the v37 layout
// move (DB-224) rotted it and the real fixtures stopped decoding). The v34 cut (2026-09-11) wrote the schema-27
// block layout `BlockV27` freezes; v34-era writers after 09-13 (DaNotesRoot, NoteTransition, NoCoinbase) wrote layouts
// no door carries, and are refused by schema with the post-fork reason (DB-342).
use crate::persist::frozen_v27::BlockV27 as Block;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV34 {
    pub schema: u32,
    pub genesis_commit: Vec<u8>,
    pub tip_block: Block,
    #[serde(with = "fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "fixed_u64")]
    pub blue_score: u64,
    #[serde(with = "fixed_u64")]
    pub height: u64,
    // note_index REMOVED (no-growth, user 2026-07-14): the node keeps NO accumulated note set on disk or in RAM
    // — the frontier roots below are the sole note commitment, and note ciphertexts are peer-sampled DA (#27 DAS).
    // note_clues REMOVED (no-growth brick 3): the OMR detection-clue index is DA/acceleration data, not consensus —
    // it grew O(notes). It is now a BOUNDED in-RAM serve-cache (`Node::note_clues`, front-evicted), refilled forward
    // from the tx stream on restart; an evicted clue is peer-served (#27 DAS) or the wallet decap-scans (the clue is
    // only a pre-decap acceleration hint, never a correctness requirement). Not persisted ⇒ snapshot O(1) in notes.
    pub bond_locked: HashMap<[u8; 32], Vec<u8>>,
    #[serde(default)]
    pub bond_height: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub bonded_validators: Vec<([u8; 32], u128)>,
    #[serde(default)]
    pub slashed_validators: Vec<[u8; 32]>,
    #[serde(default)]
    pub slashed_bond_burned: u128,
    #[serde(default)]
    pub validator_bond_commit: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    // note_frontier REMOVED (no-growth brick 5): the redundant blake3 note-membership tree (a second tree over the
    // SAME note_cm leaves) is gone. The Poseidon `spend_frontier` below is now the SOLE note tree — it is what the
    // wallet proves membership against AND what the block header commits as `frontier_root`. One tree, not two.
    pub spend_frontier: PoseidonSpendFrontier,
    pub root_history: PoseidonSpendFrontier,
    #[serde(default)]
    pub unspent_note_root: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub unspent_path_nodes: Vec<((usize, [u8; 32]), crate::spend_frontier::Digest4)>,
    #[serde(default)]
    pub circulating_records: Vec<(u64, u64, Vec<u8>, Vec<u8>)>,
    #[serde(default)]
    pub letter_columns: LetterColumns,

    #[serde(default)]
    pub unspent_map_anchor_root: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub nf_fold_seq: u64,
    #[serde(default)]
    pub account_acc: [u8; 32],
    #[serde(default)]
    pub membership_acc: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub da_top: u64,
    #[serde(default)]
    pub da_base: u64,
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
    pub stake_frontier: PoseidonSpendFrontier,
    // nullifier_imt (the FULL O(spends) indexed-Merkle tree) REMOVED from the snapshot (no-growth brick 2). It was
    // an O(spends) DA structure in the consensus checkpoint; the snapshot now carries ONLY the O(1) `nullifier_acc`
    // (root+count) below — the SOLE double-spend authority a verifying node needs (a re-spend's mandatory carried
    // witness self-verifies against that root, no stored set consulted). A node that will PRODUCE rebuilds its
    // working DA tree from the replicated #27-DAS nullifier stream (`Node::rebuild_nullifier_tree`, verified: the
    // rebuilt root must equal the persisted acc root), exactly as it rebuilds the note set — never persisted.
    #[serde(default)]
    pub nf_blocks: u64,
    #[serde(default)]
    pub nf_leaves: u64,
    #[serde(default)]
    pub sparse_acc_root: [u8; 32],
    #[serde(default)]
    pub nf_cover_conf_acc: [u8; 32],
    pub peg: PegLedger,
    pub l2_state_root: [u8; 32],
    pub params: crate::params::ChainParams,

    #[serde(default)]
    pub deletion_sidecars: Vec<(u64, Vec<u8>)>,
    #[serde(default)]
    pub chain_id: [u8; 32],
    #[serde(default)]
    pub fold_chain_tip: Option<[u8; 32]>,
    #[serde(default)]
    pub fold_chain_ordinal: u64,
    #[serde(default)]
    pub nf_unspent_acc: crate::spend_frontier::Digest4,
    #[serde(default)]
    pub fold_carry: crate::persist::frozen_v32::FoldCarryV32,
    #[serde(default)]
    pub sidecar_cursor: u64,
    #[serde(default)]
    pub letter_acc: [u8; 32],
}


impl NodeSnapshotV34 {
    pub fn schema(&self) -> u32 {
        self.schema
    }
    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v33 SNAPSHOT DOOR — the layout every schema-33 writer put on disk (the 2026-09-06 v33
//! roll: v32 + the tail field `sidecar_cursor`; fixture `testdata/persist_fixtures/state-v33-27780.snap`
//! is a real file written through `Node::export_snapshot` + `persist::save` by the deployed v33 writer
//! before the v34 bump). v34 adds ONE tail field to `NodeSnapshot` — `letter_acc` (D-45: the letter accumulator was never persisted, so a resumed node held a
//! value no chain derives) — and postcard refuses an absent trailing field, so a v33 file can only
//! enter through this frozen decoder.
//!
//! THE MIGRATION IS CUSTODY-PRESERVING: every v33 field carries across unchanged; the new field is
//! zero = "the genesis seed", which is exactly the value every v33 node restarted with. The
//! `params` graph composes through the frozen `ChainParamsV32`: `crate::params::ChainParams` has not
//! changed since the v32 freeze (24 fields, byte-identical layout; params.rs untouched since
//! 2026-09-06 15:03, before the v33 roll), which the real-file door test pins.
//!
//! Decode-only; nothing serializes from this type and nothing is retained — every field is a transient
//! copy inside `load`, bounded by the deployed v33 writer's own file and dropped after `migrate`.
//! cons: none — no disk/RAM/wire/time term survives.

use std::collections::HashMap;

// ⛔ DB-343: a door names only FROZEN types (MEASURED 2026-09-28: this door named the LIVE `Block`, so the v37 layout
// move (DB-224) rotted it and the real fixtures stopped decoding). The v31–v34 writers (2026-08-26..09-13) wrote
// the schema-27 block layout, which `BlockV27` freezes.
use crate::persist::frozen_v27::BlockV27 as Block;
// ⛔ THE FROZEN PRE-§AG ACCUMULATOR, NOT THE LIVE ONE (2026-09-12). This door named
// `crate::spend_frontier::PoseidonSpendFrontier` until §AG moved the digest from four 64-bit limbs to
// eight 31-bit lanes and the live decoder began refusing every pre-fork slot as non-canonical. A door
// that cannot DECODE cannot NAME what it refuses, and "unreadable" is what a corrupt disk looks like.
// The frozen-door law says a door is SELF-CONTAINED; this is that law applied to the accumulator.
use crate::persist::frozen_v32::PoseidonSpendFrontierV32 as PoseidonSpendFrontier;

use super::LetterColumns;

// Deployed v33 writer's own field shapes — decode-only, transient inside `load`, dropped with the
// migrated value; none of these is ever a live store on a running node.
type BondLockedV33 = HashMap<[u8; 32], Vec<u8>>;
type BondHeightV33 = HashMap<[u8; 32], u64>;
type BondedValidatorsV33 = Vec<([u8; 32], u128)>;
type SlashedValidatorsV33 = Vec<[u8; 32]>;
type ValidatorCustodyV33 = Vec<([u8; 32], Vec<u8>, [u8; 32])>;
type UnspentPathNodesV33 = Vec<((usize, [u8; 32]), [u64; 4])>;
type CirculatingRecordsV33 = Vec<(u64, u64, Vec<u8>, Vec<u8>)>;
type DeletionSidecarsV33 = Vec<(u64, Vec<u8>)>;
type GenesisCommitBytesV33 = Vec<u8>;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV33 {
    pub schema: u32,
    pub genesis_commit: GenesisCommitBytesV33,
    pub tip_block: Block,
    #[serde(with = "super::fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "super::fixed_u64")]
    pub blue_score: u64,
    #[serde(with = "super::fixed_u64")]
    pub height: u64,
    pub bond_locked: BondLockedV33,
    #[serde(default)]
    pub bond_height: BondHeightV33,
    #[serde(default)]
    pub bonded_validators: BondedValidatorsV33,
    #[serde(default)]
    pub slashed_validators: SlashedValidatorsV33,
    #[serde(default)]
    pub slashed_bond_burned: u128,
    #[serde(default)]
    pub validator_bond_commit: [u64; 4],
    #[serde(default)]
    pub validator_custody: ValidatorCustodyV33,
    pub spend_frontier: PoseidonSpendFrontier,
    pub root_history: PoseidonSpendFrontier,
    #[serde(default)]
    pub unspent_note_root: [u64; 4],
    #[serde(default)]
    pub unspent_path_nodes: UnspentPathNodesV33,
    #[serde(default)]
    pub circulating_records: CirculatingRecordsV33,
    #[serde(default)]
    pub letter_columns: LetterColumns,
    #[serde(default)]
    pub unspent_map_anchor_root: [u64; 4],
    #[serde(default)]
    pub nf_fold_seq: u64,
    #[serde(default)]
    pub account_acc: [u8; 32],
    #[serde(default)]
    pub membership_acc: [u64; 4],
    #[serde(default)]
    pub da_top: u64,
    #[serde(default)]
    pub da_base: u64,
    #[serde(default)]
    pub served_seq: u64,
    pub stake_frontier: PoseidonSpendFrontier,
    #[serde(default)]
    pub nf_blocks: u64,
    #[serde(default)]
    pub nf_leaves: u64,
    #[serde(default)]
    pub sparse_acc_root: [u8; 32],
    #[serde(default)]
    pub nf_cover_conf_acc: [u8; 32],
    pub peg: crate::persist::frozen_v32::PegLedgerV32,
    pub l2_state_root: [u8; 32],
    pub params: crate::persist::frozen_v32::ChainParamsV32,
    #[serde(default)]
    pub deletion_sidecars: DeletionSidecarsV33,
    #[serde(default)]
    pub chain_id: [u8; 32],
    #[serde(default)]
    pub fold_chain_tip: Option<[u8; 32]>,
    #[serde(default)]
    pub fold_chain_ordinal: u64,
    #[serde(default)]
    pub nf_unspent_acc: [u64; 4],
    #[serde(default)]
    pub fold_carry: crate::persist::frozen_v32::FoldCarryV32,
    #[serde(default)]
    pub sidecar_cursor: u64,
}

impl NodeSnapshotV33 {
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// The chain this file names — readable so the migration log can say WHOSE custody is carried.
    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
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

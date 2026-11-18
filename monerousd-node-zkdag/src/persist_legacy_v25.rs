// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! FROZEN v25 snapshot layout + the versioned MIGRATION into the current schema.
//!
//! ⭐ THE UPGRADE-CUSTODY LAW (user cardinal 2026-08-24, learned the hard way): a schema bump must
//! MIGRATE custody fields forward, never orphan them. Refuse-and-resync alone destroyed real rows on
//! BOTH nodes of the pair simultaneously (each cycled onto v26 within minutes, so neither could
//! re-serve the other's v25-era rows — a fauceted balance read zero after the upgrade). This module
//! freezes the exact v25 layout so a v25 file DECODES, and `migrate_v25` carries every field into the
//! current [`super::NodeSnapshot`] (the new `letter_columns` starts empty — mail custody begins at
//! v26). The pattern for every future bump: freeze the outgoing layout HERE, extend `load`'s
//! migration chain, ship. This is an explicit versioned migration — one door, works-or-fails.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::persist::frozen_v27::BlockV27;
// The accumulators and params are FROZEN types too (2026-09-07, same freeze as the v26–v30 doors):
// every schema-25 writer was a depth-32 build; `SPEND_TREE_DEPTH` moved 32 → 64 on 9/4 and the live
// frontier wire form moved with it (1,064 → 2,088 bytes), and the live `ChainParams` later gained
// `record_fold_depth` at its tail (the v30 bump) — a live import here would misread every real v25 file.
use crate::persist::frozen_v27::{ChainParamsV27, PoseidonSpendFrontierV27};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV25 {
    pub schema: u32,
    pub genesis_commit: Vec<u8>,
    pub tip_block: BlockV27,
    #[serde(with = "super::fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "super::fixed_u64")]
    pub blue_score: u64,
    #[serde(with = "super::fixed_u64")]
    pub height: u64,
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
    pub validator_bond_commit: [u64; 4],
    #[serde(default)]
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    pub spend_frontier: PoseidonSpendFrontierV27,
    pub root_history: PoseidonSpendFrontierV27,
    #[serde(default)]
    pub unspent_note_root: [u64; 4],
    #[serde(default)]
    pub unspent_path_nodes: Vec<((usize, [u8; 32]), [u64; 4])>,
    #[serde(default)]
    pub circulating_records: Vec<(u64, u64, Vec<u8>, Vec<u8>)>,
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
    pub stake_frontier: PoseidonSpendFrontierV27,
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
    pub params: ChainParamsV27,
}

impl NodeSnapshotV25 {
    // ⛔⛔⛔ THERE IS DELIBERATELY NO `migrate()` — THE REFUSAL IS BY CONSTRUCTION (2026-09-12, §AG).
    // Every root, commitment and accumulator in a pre-fork file is a digest of the RETIRED one-round
    // `MDS·(l + 7·r)^7`, which kill list §AG measured as INVERTIBLE and which this chain replaced with a
    // truncated Poseidon2 permutation. A migrated snapshot would seat the node on a root that no honest
    // producer can ever reproduce and no proof can open: a tip no peer shares. That is strictly worse
    // than refusing, because it looks like custody. The layout above stays FROZEN so a real file still
    // DECODES and earns a NAMED refusal in `persist::load` instead of a parse error — but no code path
    // exists that can turn these bytes into a current `NodeSnapshot`. Same law as the v31 door.
}


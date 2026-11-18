// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v31 SNAPSHOT DOOR — the layout every schema-31 writer (the live pair's custody on disk as of
//! 2026-09-05, build 81578d55d825e09d) put on disk. The v32 bump is SEMANTIC, not positional (item 9 of
//! the 2026-09-05 landing run): the byte layout is identical to v32, but a v31 file's spine and
//! accumulator series may have been built under the RETIRED genesis-fold law — `enable_persist` folded
//! genesis's 256-leaf record into the spend frontier and stored an ordinal-0 accumulator step, both of
//! which no v32 node derives. Measured, `item9_measurement_leaf_law_on_a_had_false_boot`:
//!     [item9] persisted had=false boot: count=256 served_seq=1
//!     [fold-order] ⛔ ordinal 1 would append at leaf 256 but its ordinal places it at 0 — Refused
//! after which record 1's leaves were silently SKIPPED while 2.. folded at shifted positions — a spine
//! no v32 node can reach, with the arithmetic RE-CONVERGING (count == (served_seq−1)·256 again one
//! record later), so no post-hoc shape test can certify a v31 spine sound. A detector that passes aged
//! poisoned files would be an assertion that cannot fail.
//!
//! THE DOOR'S VERDICT IS THEREFORE UNIFORM AND HONEST: a v31 file DECODES (its bytes and chain identity
//! are readable and named) and is REFUSED for resume — fail-closed, loudly, with the operator's next
//! step stated. This is the no-regenesis cardinal doing its job, not a wipe: the v32 roll is a BATCHED
//! RE-GENESIS (standing authorization), and no v31 file is a valid subject of the v32 accumulator law.
//!
//! Every type in this serde graph other than the frozen `ChainParamsV31` is a live type whose layout has
//! not moved since the v31 freeze (pinned by the real-file door test against
//! `testdata/persist_fixtures/state-v31-{27780,28901}.snap`). Decode-only; nothing serializes from this
//! type and nothing is retained — every field is a transient copy inside `load`, bounded by the deployed
//! v31 writer's own file and dropped with the verdict. cons: none — no disk/RAM/wire/time term survives.

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

// Deployed v31 writer's own field shapes — decode-only, transient inside `load`, dropped with the
// verdict; none of these is ever a live store on a running node.
type BondLockedV31 = HashMap<[u8; 32], Vec<u8>>;
type BondHeightV31 = HashMap<[u8; 32], u64>;
type BondedValidatorsV31 = Vec<([u8; 32], u128)>;
type SlashedValidatorsV31 = Vec<[u8; 32]>;
type ValidatorCustodyV31 = Vec<([u8; 32], Vec<u8>, [u8; 32])>;
type UnspentPathNodesV31 = Vec<((usize, [u8; 32]), [u64; 4])>;
type CirculatingRecordsV31 = Vec<(u64, u64, Vec<u8>, Vec<u8>)>;
type DeletionSidecarsV31 = Vec<(u64, Vec<u8>)>;
type GenesisCommitBytesV31 = Vec<u8>;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV31 {
    pub schema: u32,
    pub genesis_commit: GenesisCommitBytesV31,
    pub tip_block: Block,
    #[serde(with = "super::fixed_u128")]
    pub blue_work: u128,
    #[serde(with = "super::fixed_u64")]
    pub blue_score: u64,
    #[serde(with = "super::fixed_u64")]
    pub height: u64,
    pub bond_locked: BondLockedV31,
    #[serde(default)]
    pub bond_height: BondHeightV31,
    #[serde(default)]
    pub bonded_validators: BondedValidatorsV31,
    #[serde(default)]
    pub slashed_validators: SlashedValidatorsV31,
    #[serde(default)]
    pub slashed_bond_burned: u128,
    #[serde(default)]
    pub validator_bond_commit: [u64; 4],
    #[serde(default)]
    pub validator_custody: ValidatorCustodyV31,
    pub spend_frontier: PoseidonSpendFrontier,
    pub root_history: PoseidonSpendFrontier,
    #[serde(default)]
    pub unspent_note_root: [u64; 4],
    #[serde(default)]
    pub unspent_path_nodes: UnspentPathNodesV31,
    #[serde(default)]
    pub circulating_records: CirculatingRecordsV31,
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
    pub params: crate::persist::frozen_v31::ChainParamsV31,
    #[serde(default)]
    pub deletion_sidecars: DeletionSidecarsV31,
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
}

impl NodeSnapshotV31 {
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// The boot-instant shape of the retired genesis-fold law, where it is still visible: genesis's
    /// 256-leaf record IS the spine's only content (count == served_seq·256 with served_seq > 0). Aged
    /// files re-converge to the healthy arithmetic while carrying the wrong LEAVES (record 1's skipped,
    /// genesis's substituted), which is exactly why this is DIAGNOSTIC ONLY — it names the refusal more
    /// precisely when it fires, and its silence certifies nothing. The door refuses every v31 file
    /// either way.
    pub fn carries_visible_phantom_genesis_leaves(&self) -> bool {
        let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        self.served_seq > 0 && self.spend_frontier.count == self.served_seq.saturating_mul(rec)
    }

    /// The chain this file names — readable so the refusal can say WHOSE custody is being protected.
    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
}

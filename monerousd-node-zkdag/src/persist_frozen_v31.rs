// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v31 CONSENSUS PARAMETERS — the `ChainParams` layout every schema-31 writer (the live pair's
//! custody on disk as of 2026-09-05, build 81578d55d825e09d) serialized. v32 exists NOT because this
//! layout moved (it is byte-identical to the v32 layout) but because the CHAIN LAW moved (item 9, the
//! 2026-09-05 landing run): genesis no longer contributes a 256-leaf record fold to the spend frontier
//! or an ordinal-0 step to the membership accumulator, so a v31 file's spine and acc series may have
//! been built under a law no v32 node runs. The schema gate is the ONE mechanism that versions on-disk
//! state SEMANTICS, so the bump routes every v31 file through an explicit door. Decode-only; nothing
//! serializes from this type, nothing is retained: every field is a transient copy inside `load`,
//! bounded by the deployed v31 writer's own file and dropped with the verdict.
//! cons: none — no disk/RAM/wire/time term survives the call.

/// The deployed v31 writer's genesis identity bytes — decode-only, transient inside `load`.
type GenesisCommitBytesV31 = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainParamsV31 {
    pub dag_width: usize,
    pub ghostdag_k: u64,
    pub merge_depth_cap: usize,
    pub target_spacing_ms: u64,
    pub daa_sample_len: u64,
    pub mtp_sample_len: usize,
    pub max_ts_drift_ms: u64,
    pub max_block_weight: u64,
    pub max_tx_weight: u32,
    pub pow_stamp_base_bits: u32,
    pub pow_stamp_max_bits: u32,
    pub max_pool_weight: u64,
    pub vdf_steps: u64,
    pub genesis_parity_commit: GenesisCommitBytesV31,
    pub net_prefix_len: usize,
    pub mint_ratio_bps: u32,
    pub stake_lock_blocks: u64,
    pub stake_reward_apr_bps: u32,
    pub reward_epoch_blocks: u64,
    pub validator_reward_share_bps: u32,
    pub order_fill_fee_bps: u64,
    pub withdraw_fee_min_bps: u32,
    pub withdraw_fee_max_bps: u32,
    pub record_fold_depth: u64,
}

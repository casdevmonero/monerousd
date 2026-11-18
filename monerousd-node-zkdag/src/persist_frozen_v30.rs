// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v30 CONSENSUS PARAMETERS — the `ChainParams` layout every schema-30 writer (binary
//! cc3e5c96, the 2026-09-02 gate-certified deploy, the live pair's custody on disk) serialized.
//! v31 exists because `ChainParams` gained `record_fold_depth` at its TAIL on 2026-09-03 (the
//! canonical record fold: records fold into the note spine only once their block is this many
//! selected-chain steps below the tip, in the DAG's canonical order), so a v31 binary can no longer
//! decode a v30 `params` through the live struct. Decode-only; nothing serializes from this type.
//! cons: none — transient inside `load`, no disk/RAM/wire/time term.

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainParamsV30 {
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
    /// O1-FOOTPRINT-REVIEWED: bounded by the deployed v30 writer (decode-only frozen door: a transient copy inside `load`, dropped after `migrate`; never grows, never serialized)
    pub genesis_parity_commit: Vec<u8>,
    pub net_prefix_len: usize,
    pub mint_ratio_bps: u32,
    pub stake_lock_blocks: u64,
    pub stake_reward_apr_bps: u32,
    pub reward_epoch_blocks: u64,
    pub validator_reward_share_bps: u32,
    pub order_fill_fee_bps: u64,
    pub withdraw_fee_min_bps: u32,
    pub withdraw_fee_max_bps: u32,
}

impl ChainParamsV30 {
    pub fn into_live(self) -> crate::params::ChainParams {
        crate::params::ChainParams {
            dag_width: self.dag_width,
            ghostdag_k: self.ghostdag_k,
            merge_depth_cap: self.merge_depth_cap,
            target_spacing_ms: self.target_spacing_ms,
            daa_sample_len: self.daa_sample_len,
            mtp_sample_len: self.mtp_sample_len,
            max_ts_drift_ms: self.max_ts_drift_ms,
            max_block_weight: self.max_block_weight,
            max_tx_weight: self.max_tx_weight,
            pow_stamp_base_bits: self.pow_stamp_base_bits,
            pow_stamp_max_bits: self.pow_stamp_max_bits,
            max_pool_weight: self.max_pool_weight,
            vdf_steps: self.vdf_steps,
            genesis_parity_commit: self.genesis_parity_commit,
            net_prefix_len: self.net_prefix_len,
            mint_ratio_bps: self.mint_ratio_bps,
            stake_lock_blocks: self.stake_lock_blocks,
            miner_quarter_keys: crate::params::MINER_QUARTER_KEYS_DEFAULT, // §BR-11: a frozen format predates the quarter
            unbonding_blocks: crate::params::UNBONDING_BLOCKS_DEFAULT, // §BR-3: a frozen format predates the window
            surplus_buffer_cap_atomic: crate::params::SURPLUS_BUFFER_CAP_DEFAULT, // §BR-3 17.6: a frozen format predates the buffer target
            stake_reward_apr_bps: self.stake_reward_apr_bps,
            reward_epoch_blocks: self.reward_epoch_blocks,
            validator_reward_share_bps: self.validator_reward_share_bps,
            order_fill_fee_bps: self.order_fill_fee_bps,
            withdraw_fee_min_bps: self.withdraw_fee_min_bps,
            withdraw_fee_max_bps: self.withdraw_fee_max_bps,
            // New in v31: the canonical record fold depth starts at its protocol default.
            record_fold_depth: crate::params::RECORD_FOLD_DEPTH_DEFAULT,
        }
    }
}

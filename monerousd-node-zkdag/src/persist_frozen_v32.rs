// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ FROZEN v32 CONSENSUS PARAMETERS — the `ChainParams` layout every schema-32 writer (the
//! 2026-09-06 gate-run daemons; fixtures `state-v32-{47791,48912}.snap` are their real files)
//! serialized. Byte-identical to the v31 params layout at the freeze instant, and frozen HERE, in
//! its own module, because the frozen-door law is that a door is SELF-CONTAINED: if the live
//! `ChainParams` moves tomorrow, this decoder must keep reading yesterday's bytes unchanged.
//! v33 exists because `NodeSnapshot` gained `sidecar_cursor` at its TAIL (the proven-served
//! readiness watermark — see persist.rs's schema history); postcard refuses an absent trailing
//! field (the v26 incident's measurement), so a v32 file can only enter through this frozen
//! layout. Decode-only; nothing serializes from this type — every field is a transient copy
//! inside `load`, bounded by the deployed v32 writer's own file and dropped after `migrate`.
//! cons: none — no disk/RAM/wire/time term survives the call.

/// The deployed v32 writer's genesis identity bytes — decode-only, transient inside `load`.
type GenesisCommitBytesV32 = Vec<u8>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainParamsV32 {
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
    pub genesis_parity_commit: GenesisCommitBytesV32,
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

impl ChainParamsV32 {
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
            record_fold_depth: self.record_fold_depth,
        }
    }
}

#[cfg(test)]
impl ChainParamsV32 {
    /// TEST-ONLY projection from the live params — used once to write the v33 fixture through the frozen
    /// v33 door layout. The live `ChainParams` and this layout are field-for-field identical (24 fields).
    pub(crate) fn from_live_for_fixture(p: &crate::params::ChainParams) -> Self {
        ChainParamsV32 {
            dag_width: p.dag_width.clone(),
            ghostdag_k: p.ghostdag_k.clone(),
            merge_depth_cap: p.merge_depth_cap.clone(),
            target_spacing_ms: p.target_spacing_ms.clone(),
            daa_sample_len: p.daa_sample_len.clone(),
            mtp_sample_len: p.mtp_sample_len.clone(),
            max_ts_drift_ms: p.max_ts_drift_ms.clone(),
            max_block_weight: p.max_block_weight.clone(),
            max_tx_weight: p.max_tx_weight.clone(),
            pow_stamp_base_bits: p.pow_stamp_base_bits.clone(),
            pow_stamp_max_bits: p.pow_stamp_max_bits.clone(),
            max_pool_weight: p.max_pool_weight.clone(),
            vdf_steps: p.vdf_steps.clone(),
            genesis_parity_commit: p.genesis_parity_commit.clone(),
            net_prefix_len: p.net_prefix_len.clone(),
            mint_ratio_bps: p.mint_ratio_bps.clone(),
            stake_lock_blocks: p.stake_lock_blocks.clone(),
            stake_reward_apr_bps: p.stake_reward_apr_bps.clone(),
            reward_epoch_blocks: p.reward_epoch_blocks.clone(),
            validator_reward_share_bps: p.validator_reward_share_bps.clone(),
            order_fill_fee_bps: p.order_fill_fee_bps.clone(),
            withdraw_fee_min_bps: p.withdraw_fee_min_bps.clone(),
            withdraw_fee_max_bps: p.withdraw_fee_max_bps.clone(),
            record_fold_depth: p.record_fold_depth.clone(),
        }
    }
}

/// ⛔ FROZEN v32-ERA `PegLedger` — the layout every schema-25..33 writer put on disk. On 2026-09-08 the
/// liquidation door appended two fields to the live `PegLedger` (`reserve_hwm_commit`, `liquidated`) and
/// one to `WrappedAsset` (`reserve_hwm_commit`); postcard has no field tags, so `serde(default)` is a
/// no-op on a shorter file, and every legacy door that named the LIVE type stopped opening real files —
/// MEASURED 2026-09-11: all seven real-fixture door pins red with "Hit the end of buffer" on
/// `state-v32-48912.snap`. That is the exact rot the frozen-door law names ("a door may never name a
/// live type in its serde graph"), so the peg graph is frozen here the way `ChainParamsV32` is.
///
/// Decode-only, transient inside `load`, dropped after `migrate` — the same idiom as the door field
/// shapes above; nothing here is a live store on a running node. `From` impls in `peg.rs` (where the
/// live fields are visible) fill the three post-freeze fields with their genesis values — a zero
/// commitment and no liquidations — exactly what every pre-2026-09-08 node held.
type PegSpentBurnsV32 = std::collections::HashSet<[u8; 32]>;
type PegDepositIdsV32 = std::collections::HashSet<[u8; 32]>;
type PegReleasedV32 = std::collections::HashSet<[u8; 32]>;
type PegWrappedAssetsV32 = std::collections::BTreeMap<u32, WrappedAssetV32>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedAssetV32 {
    pub reserve_commit: [u64; 4],
    pub minted_commit: [u64; 4],
    pub ratio_bps: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PegLedgerV32 {
    pub reserve_commit: [u64; 4],
    pub minted_commit: [u64; 4],
    pub spent_burns: PegSpentBurnsV32,
    #[serde(default)]
    pub confidential_deposit_ids: PegDepositIdsV32,
    pub ratio_bps: u32,
    #[serde(default)]
    pub yield_rate_bps: u32,
    #[serde(default = "crate::peg::default_redeem_floor_bps")]
    pub redeem_floor_bps: u32,
    #[serde(default)]
    pub released: PegReleasedV32,
    #[serde(default)]
    pub wrapped_assets: PegWrappedAssetsV32,
}

// ── FROZEN PRE-§AG ACCUMULATOR WIRE SHAPE (2026-09-12) ───────────────────────────────────────────────
//
// ⛔⛔⛔ THE v31/v32/v33 DOORS USED THE **LIVE** `PoseidonSpendFrontier`, AND THAT BROKE THEM.
//
// The frozen-door law is that a door is SELF-CONTAINED — this file's own header says it about
// `ChainParams`. The three newest doors nevertheless named the live accumulator type, which was
// harmless only for as long as its wire form never moved. It moved on 2026-09-12: kill list §AG
// replaced the chain's compression, the digest went from four 64-bit limbs to eight 31-bit lanes, and
// the live decoder now reads each 32-byte slot as a canonical 8-lane digest and REFUSES anything else.
// A real v31/v32/v33 file's slots are four little-endian `kb_reduce`d u64s, so they stop decoding —
// and a door that cannot decode cannot NAME what it is refusing. The operator would see "unreadable"
// for a checkpoint that is merely pre-fork, which is indistinguishable from a corrupt disk.
//
// So the pre-§AG wire shape is frozen HERE, where it cannot move again: depth 64 (the 2026-09-04
// death-date fix), four 64-bit LE limbs per slot, 8 + 65x32 = 2,088 bytes at every count. Decode-only,
// exactly like everything else in this module — there is no `into_live`, because a peak here is a
// digest of the retired one-round hash and nothing on this chain can reproduce it.

/// The pre-§AG spend-tree depth. A DEPTH constant IS a wire contract (kill list, 2026-09-07), so the
/// door carries its own rather than reading the live one.
pub const SPEND_TREE_DEPTH_PRE_AG: usize = 64;

/// `8-byte BE count + (DEPTH+1) x 32-byte slots`, the byte length every v31/v32/v33 writer emitted.
pub const SPEND_FRONTIER_WIRE_LEN_PRE_AG: usize = 8 + (SPEND_TREE_DEPTH_PRE_AG + 1) * 32;

/// The MMR peak set, one slot per level. ⭐ A `Box<[T]>` RATHER THAN A `Vec`, ON PURPOSE: it has no
/// `push` and no `reserve`, so the store cannot grow after construction — the bound is enforced by the
/// TYPE instead of asserted in a comment (the move this tree settled on 2026-09-12 for exactly this
/// conflict). Its one constructor fills `SPEND_TREE_DEPTH_PRE_AG + 1` slots and nothing else can add one.
type PreAgPeaks = Box<[Option<[u64; 4]>]>;

/// The accumulator as a pre-§AG writer stored it: MMR peaks of FOUR 64-bit limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonSpendFrontierV32 {
    pub peaks: PreAgPeaks,
    pub count: u64,
}

impl<'de> serde::Deserialize<'de> for PoseidonSpendFrontierV32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PoseidonSpendFrontierV32;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("fixed-width pre-AG PoseidonSpendFrontier bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                if b.len() != SPEND_FRONTIER_WIRE_LEN_PRE_AG {
                    return Err(E::custom("bad pre-AG PoseidonSpendFrontier wire length"));
                }
                let mut c = [0u8; 8];
                c.copy_from_slice(&b[..8]);
                let count = u64::from_be_bytes(c);
                Ok(PoseidonSpendFrontierV32::frozen_era(count, |l| {
                    let off = 8 + l * 32;
                    let mut d = [0u64; 4];
                    for (i, limb) in d.iter_mut().enumerate() {
                        let mut w = [0u8; 8];
                        w.copy_from_slice(&b[off + i * 8..off + i * 8 + 8]);
                        *limb = u64::from_le_bytes(w);
                    }
                    d
                }))
            }
        }
        deserializer.deserialize_bytes(V)
    }
}

impl serde::Serialize for PoseidonSpendFrontierV32 {
    /// The encode half, so a test can state a genuine pre-§AG file byte for byte instead of deriving it
    /// from a live value that has already moved.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; SPEND_FRONTIER_WIRE_LEN_PRE_AG];
        buf[..8].copy_from_slice(&self.count.to_be_bytes());
        for (l, slot) in self.peaks.iter().enumerate().take(SPEND_TREE_DEPTH_PRE_AG + 1) {
            if let Some(d) = slot {
                let off = 8 + l * 32;
                for (i, limb) in d.iter().enumerate() {
                    buf[off + i * 8..off + i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
                }
            }
        }
        serializer.serialize_bytes(&buf)
    }
}

impl PoseidonSpendFrontierV32 {
    /// Build a pre-§AG-era accumulator directly from the old writer's own `(count, peaks)` content —
    /// the ONLY constructor, which is what fixes the peak count at `DEPTH + 1` for every instance.
    /// There is no `from_live`: a live peak is a digest of a function this era never ran.
    pub fn frozen_era(count: u64, peak_at: impl Fn(usize) -> [u64; 4]) -> Self {
        let peaks: PreAgPeaks = (0..=SPEND_TREE_DEPTH_PRE_AG)
            .map(|l| {
                // Level 64 would need exactly 2^64 leaves — unrepresentable in a u64 count, so that
                // slot is always empty and `count >> 64` (a shift overflow) never runs.
                ((l as u32) < u64::BITS && (count >> l) & 1 == 1).then(|| peak_at(l))
            })
            .collect();
        PoseidonSpendFrontierV32 { peaks, count }
    }
}

/// ⛔ DB-343 — `crate::sync::FoldCarry` FROZEN as the v31..v34 writers laid it out (2026-09-03..09-18): each DAA sample was
/// a `(u64, u128)` PAIR (the live `dag::DaaSample` is a `(u64, u128, u64)` triple since 2026-09-18, DagDaa) and every
/// carried block was the schema-27 layout (`BlockV27`). MEASURED 2026-09-28: the doors named the LIVE `FoldCarry`, so a
/// real v31..v33 file whose carry held any window or block stopped decoding (`state-v31-28901` failed where
/// `state-v31-27780`, whose carry was empty, opened) — content-dependent rot, the class a frozen door exists to prevent.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldCarryV32 {
    pub window: Vec<(u64, u128)>,
    pub ancestors: Vec<(crate::persist::frozen_v27::BlockV27, u128, u64)>,
    pub ancestor_windows: Vec<([u8; 32], Vec<(u64, u128)>)>,
    pub unfolded: Vec<(crate::persist::frozen_v27::BlockV27, u128, u64)>,
}

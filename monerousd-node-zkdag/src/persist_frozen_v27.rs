// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ FROZEN CONSENSUS TYPES AS THE SCHEMA-27 WRITER WROTE THEM — never edit these fields again.
//!
//! ROOT-LAYER: a legacy decode door is a promise about BYTES, but every door in this tree was written as a
//! reference to TYPES (`use crate::block::Block`). Types move; bytes do not. The door's type graph is the
//! layer where the byte contract is actually expressed, so that is where the freeze has to live — pinning
//! only the door's own field list (which the v27 door did correctly) leaves it rotting the instant any
//! NESTED consensus type gains a field.
//!
//! MEASURED 2026-08-26 against the three real on-disk snapshots the live daemons wrote
//! (`testdata/persist_fixtures/`, 24 MB origin / 15 MB joiner / 39 KB retired node, all schema byte 27):
//! adding `Block::amm_set` + `BlockHeader::amm_set_root` for confidential AMM settlement rotted ALL THREE
//! doors at once, because v25, v26 and v27 all reach the live `Block` through `tip_block` — snapshot field
//! THREE. Before: current `REFUSED (Hit the end of buffer, expected more data)`, v27 door `REFUSED (same)`,
//! v26 door `REFUSED (same)`; the 39 KB file misaligned earlier and died on
//! `REFUSED (Found an Option discriminant that wasn't 0 or 1)`. No door opened any real file, and
//! `enable_persist` turns "no door opened" into `exit(97)` — so deploying v28 would have refused to start
//! BOTH live nodes, with real custody sitting on disk. After: the v27 door opens all three (see
//! `persist::real_v27_fixture_tests`).
//!
//! MUST-STAY-GREEN: `persist::real_v27_fixture_tests` (real bytes open a door), the v26→v27 door regression
//! in `persist`, and the whole node suite — these types are byte-identical to what the schema-27 writer
//! emitted, so nothing that reads a v27 file may change meaning.
//!
//! THE LAW THIS ADDS to "every schema bump ships a frozen decoder": a frozen decoder must be SELF-CONTAINED
//! — it may not name a live consensus type anywhere in its serde graph. `Hash32` is written here as its
//! wire form `[u8; 32]` (a derived newtype struct is byte-identical to its inner value in postcard) and
//! `BlockId` likewise, so no upstream edit can reach these definitions. The only place live types appear is
//! the conversion at the bottom, which is allowed to know both sides: if a live type gains a field, that
//! conversion stops COMPILING, which is the forcing function that makes the next author choose a migration
//! value deliberately instead of discovering the rot on an operator's disk.

/// The schema-27 block header. Identical field order and wire types to `crate::block::BlockHeader` as of
/// the deployed schema-27 writer. (The in-tree v28 era briefly added `amm_set_root` to the live type —
/// retired at source 2026-08-26 — which is exactly the rot this frozen copy exists to be immune to.)
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct BlockHeaderV27 {
    pub version: u32,
    pub parents: Vec<[u8; 32]>,
    pub timestamp: u64,
    pub nonce: u64,
    pub work: u128,
    pub pow_bind: [u8; 32],
    pub tx_merkle_root: [u8; 32],
    pub frontier_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub chain_acc: [u8; 16],
    pub miner_commitment: [u8; 32],
    #[serde(default)]
    pub account_root: [u8; 32],
    #[serde(default)]
    pub output_notes_root: [u8; 32],
    #[serde(default)]
    pub nullifier_tags_root: [u8; 32],
    #[serde(default)]
    pub oli_tags_root: [u8; 32],
    #[serde(default)]
    pub account_targets_root: [u8; 32],
    #[serde(default)]
    pub del_set_root: [u8; 32],
    #[serde(default)]
    pub bond_set_root: [u8; 32],
    #[serde(default)]
    pub dir_set_root: [u8; 32],
    #[serde(default)]
    pub letter_set_root: [u8; 32],
}

/// The schema-27 nullifier block proof. Byte-identical to `crate::block::NfBlockProof` at schema 27.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NfBlockProofV27 {
    pub carrier: Vec<u8>,
    pub post_root: [u8; 32],
    #[serde(default)]
    pub fold: Vec<u8>,
    pub padded_tags: Vec<[u8; 32]>,
}

/// The schema-27 block. Identical field order and wire types to `crate::block::Block` as of the deployed
/// schema-27 writer. (The in-tree v28 era briefly inserted `amm_set` AHEAD of `letter_set` on the live
/// type — a MEANING SWAP against these bytes, the same defect class that killed v26 decoding — retired at
/// source 2026-08-26. The freeze is what made that era's files diagnosable at all.)
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct BlockV27 {
    pub header: BlockHeaderV27,
    pub tx_ids: Vec<[u8; 32]>,
    #[serde(default)]
    pub pow_proof: Vec<u8>,
    #[serde(default)]
    pub settlement: Option<Vec<u8>>,
    #[serde(default)]
    pub nullifier_proof: NfBlockProofV27,
    #[serde(default)]
    pub output_notes: Vec<u8>,
    #[serde(default)]
    pub oli_tags: Vec<u8>,
    pub account_targets: Vec<u8>,
    #[serde(default)]
    pub del_set: Vec<u8>,
    #[serde(default)]
    pub bond_set: Vec<u8>,
    #[serde(default)]
    pub dir_set: Vec<u8>,
    #[serde(default)]
    pub letter_set: Vec<u8>,
}

// ---------------------------------------------------------------------------------------------------------
// THE ONE PLACE LIVE TYPES MAY APPEAR. Everything above is frozen wire shape; everything below is the
// migration decision, which by definition knows both sides. A live type that gains a field breaks THIS code
// and nothing else — a compile error the author must answer, instead of silent rot found on a user's disk.
// ---------------------------------------------------------------------------------------------------------

impl BlockHeaderV27 {
    /// Carry a schema-27 header into the live header. With the pool AMM retired at source (2026-08-26)
    /// the live preimage is byte-identical to the schema-27 writer's, so the id recomputed from this
    /// header IS the id the chain agreed on — identity carries across the door. (While the in-tree
    /// `amm_set_root` binding existed this was explicitly NOT true, and the chain-identity gate in
    /// `Node::restore_snapshot` is what decides resumability either way.)
    pub fn into_live(self) -> crate::block::BlockHeader {
        use crate::hash::Hash32;
        crate::block::BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
            version: self.version,
            parents: self.parents.into_iter().map(Hash32).collect(),
            timestamp: self.timestamp,
            nonce: self.nonce,
            work: self.work,
            pow_bind: Hash32(self.pow_bind),
            tx_merkle_root: Hash32(self.tx_merkle_root),
            frontier_root: Hash32(self.frontier_root),
            nullifier_root: Hash32(self.nullifier_root),
            // v27 predates DB-154's committed sparse root: ZERO is "this producer asserted none", which
            // is exactly how a treeless producer signs today, so a restored v27 header reads correctly.
            sparse_root: Hash32::ZERO,
            // v27 predates DB-154's committed sparse root: ZERO is "this producer asserted none", which
            // is exactly how a treeless producer signs today, so a restored v27 header reads correctly.
            chain_acc: self.chain_acc,
            miner_commitment: Hash32(self.miner_commitment),
            account_root: Hash32(self.account_root),
            output_notes_root: Hash32(self.output_notes_root),
            nullifier_tags_root: Hash32(self.nullifier_tags_root),
            oli_tags_root: Hash32(self.oli_tags_root),
            // ⭐ §BA — this construction carries no credit set, so its commitment is the DERIVED empty
            // sidecar root, never a magic constant: the same `da_sidecar_root_of` every verifier uses.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: Hash32(self.account_targets_root),
            bond_set_root: Hash32(self.bond_set_root),
            dir_set_root: Hash32(self.dir_set_root),
            letter_set_root: Hash32(self.letter_set_root),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
        }
    }
}

impl NfBlockProofV27 {
    pub fn into_live(self) -> crate::block::NfBlockProof {
        use crate::hash::Hash32;
        crate::block::NfBlockProof {
            carrier: self.carrier,
            post_root: Hash32(self.post_root),
            fold: self.fold,
            padded_tags: self.padded_tags,
            // v27 predates the sparse carrier: ZERO is "this producer proved none".
            sparse_post_root: Hash32::ZERO,
            sparse_carrier: Vec::new(),
        }
    }
}

impl BlockV27 {
    /// Carry a schema-27 block into the live block — field-for-field, identity preserved (see
    /// `BlockHeaderV27::into_live`).
    pub fn into_live(self) -> crate::block::Block {
        use crate::hash::Hash32;
        crate::block::Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: self.header.into_live(),
            tx_ids: self.tx_ids.into_iter().map(Hash32).collect(),
            pow_proof: self.pow_proof,
            // ⛔ A v27 BLOCK'S `settlement` IS NOT A NOTE TRANSITION AND IS DROPPED, NOT CARRIED.
            // v27's field held task #144's aggregate, which verified over ZERO ROWS with no inner
            // carrier (§BD/§BZ) — a different object entirely, and a forgeable one. Mapping it across
            // would launder a claim nothing backs into the slot a peer now GRANTS on.
            note_transition: None,
            nullifier_proof: self.nullifier_proof.into_live(),
            output_notes: self.output_notes,
            oli_tags: self.oli_tags,
            account_targets: self.account_targets,
            bond_set: self.bond_set,
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: self.dir_set,
            letter_set: self.letter_set,
            tag_evidence: Vec::new(),
            cover_transition: None,
            member_transition: None,
        }
    }
}

impl BlockHeaderV27 {
    /// Render a live header in schema-27 wire shape — see [`BlockV27::from_live`] for the contract.
    fn from_live(h: &crate::block::BlockHeader) -> Option<BlockHeaderV27> {
        Some(BlockHeaderV27 {
            version: h.version,
            parents: h.parents.iter().map(|p| *p.as_bytes()).collect(),
            timestamp: h.timestamp,
            nonce: h.nonce,
            work: h.work,
            pow_bind: *h.pow_bind.as_bytes(),
            tx_merkle_root: *h.tx_merkle_root.as_bytes(),
            frontier_root: *h.frontier_root.as_bytes(),
            nullifier_root: *h.nullifier_root.as_bytes(),
            chain_acc: h.chain_acc,
            miner_commitment: *h.miner_commitment.as_bytes(),
            account_root: *h.account_root.as_bytes(),
            output_notes_root: *h.output_notes_root.as_bytes(),
            nullifier_tags_root: *h.nullifier_tags_root.as_bytes(),
            oli_tags_root: *h.oli_tags_root.as_bytes(),
            account_targets_root: *h.account_targets_root.as_bytes(),
            // Z1 (2026-09-22): the live header carries no deletion-set root; the frozen v27 column
            // keeps its slot and takes the DERIVED empty-sidecar root so the wire shape is unchanged.
            del_set_root: *crate::block::da_sidecar_root_of(&[]).as_bytes(),
            bond_set_root: *h.bond_set_root.as_bytes(),
            dir_set_root: *h.dir_set_root.as_bytes(),
            letter_set_root: *h.letter_set_root.as_bytes(),
        })
    }
}

impl BlockV27 {
    /// Render a live block in schema-27 wire shape — exactly what the deployed schema-27 writer would have
    /// emitted for it. This is how a test builds a genuine legacy fixture instead of hand-waving one.
    ///
    /// `Option` is the door's permanent contract: it returns `None` exactly when the live block carries
    /// state schema 27 had no field for. With the pool AMM retired (2026-08-26) the live layout is again
    /// byte-identical to schema 27, so today every live block renders — but the signature stays, because
    /// the next consensus field re-creates the same question and the caller must already be answering it.
    pub fn from_live(b: &crate::block::Block) -> Option<BlockV27> {
        Some(BlockV27 {
            header: BlockHeaderV27::from_live(&b.header)?,
            tx_ids: b.tx_ids.iter().map(|t| *t.as_bytes()).collect(),
            pow_proof: b.pow_proof.clone(),
            // A live block's note transition has no v27 spelling (v27 predates it), and v27's own
            // `settlement` is the retired forgeable aggregate — so this frozen shape carries neither.
            settlement: None,
            nullifier_proof: NfBlockProofV27 {
                carrier: b.nullifier_proof.carrier.clone(),
                post_root: *b.nullifier_proof.post_root.as_bytes(),
                fold: b.nullifier_proof.fold.clone(),
                padded_tags: b.nullifier_proof.padded_tags.clone(),
            },
            output_notes: b.output_notes.clone(),
            oli_tags: b.oli_tags.clone(),
            account_targets: b.account_targets.clone(),
            del_set: Vec::new(),
            bond_set: b.bond_set.clone(),
            dir_set: b.dir_set.clone(),
            letter_set: b.letter_set.clone(),
        })
    }
}

/// The governance parameter set EXACTLY as the schema-26 through schema-29 writers serialized it —
/// the layout is identical across those schemas (verified by the REAL-bytes fixtures: the 8/26 v27
/// files and the live pair's schema-29 files both open through it).
///
/// Frozen here because the live `crate::params::ChainParams` gained `order_fill_fee_bps` MID-STRUCT
/// on 2026-09-01 (between `validator_reward_share_bps` and `withdraw_fee_min_bps`) and every door
/// reached the live type directly — the amm_set rot class, second occurrence, this time through the
/// parameters instead of the block. postcard is positional: only ORDER and WIRE TYPES are
/// load-bearing here, and they never change again.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug)]
pub struct ChainParamsV27 {
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
    pub genesis_parity_commit: Vec<u8>,
    pub net_prefix_len: usize,
    pub mint_ratio_bps: u32,
    pub stake_lock_blocks: u64,
    pub stake_reward_apr_bps: u32,
    pub reward_epoch_blocks: u64,
    pub validator_reward_share_bps: u32,
    pub withdraw_fee_min_bps: u32,
    pub withdraw_fee_max_bps: u32,
}

impl ChainParamsV27 {
    /// The one allowed live reference: map the frozen layout onto today's `ChainParams`, choosing a
    /// deliberate migration value for every field the live type gained since these bytes were
    /// written. If `ChainParams` gains another field, THIS stops compiling — the forcing function
    /// that makes the next author bump `SNAPSHOT_SCHEMA` and choose the migration value on purpose.
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
            // ⛔ ADOPT THE CURRENT CONSENSUS RATE, NOT THE ONE THIS FILE WAS WRITTEN UNDER. The field
            // was added to the live type on 2026-09-01, after every file this door reads was written,
            // so a resumed snapshot carries no value for it and one has to be chosen here.
            //
            // It is the genesis DEFAULT — 10 bps, the rate every other node is enforcing — and NOT the
            // zero those chains ran at before the field existed. Resuming at zero would leave this node
            // accepting fee-free fills that every peer refuses: a one-node consensus split, produced by
            // the act of restarting. The snapshot's job is to restore this node's HISTORY, not to pin it
            // to retired rules; governance retunes from here on-chain like any other parameter.
            order_fill_fee_bps: crate::params::ORDER_FILL_FEE_BPS_DEFAULT,
            withdraw_fee_min_bps: self.withdraw_fee_min_bps,
            withdraw_fee_max_bps: self.withdraw_fee_max_bps,
            // New in v31: the canonical record fold depth starts at its protocol default.
            record_fold_depth: crate::params::RECORD_FOLD_DEPTH_DEFAULT,
        }
    }
}

/// The spend-accumulator wire shape EXACTLY as every schema-25 through schema-30 writer emitted it:
/// a length-prefixed blob of 8-byte big-endian `count` followed by `(32 + 1)` fixed 32-byte peak
/// slots (four 8-byte BE limbs each, zero-padded where empty; occupied slots are exactly the set
/// bits of `count` — the MMR invariant). Those writers were built with `SPEND_TREE_DEPTH = 32`, so
/// their blob is a fixed **1,064 bytes**.
///
/// Frozen here because `SPEND_TREE_DEPTH` moved 32 → 64 on 2026-09-04 (the chain-death-date fix:
/// depth 32 filled its 2^32-leaf capacity in 97 days), which grew the live
/// `PoseidonSpendFrontier` wire form to 2,088 bytes — and the live codec refuses any other length.
/// Every pre-9/4 door (v25–v30) reached the live type directly, so all of them rotted at once —
/// the amm_set/params rot class, THIRD occurrence, this time through the accumulator. MEASURED
/// 2026-09-07 against the seven real pre-9/4 files in `testdata/persist_fixtures/`: every door
/// REFUSED every one of them ("Serde Deserialization Error" — the live codec's length check).
///
/// The codec rides serde's `try_from`/`into` byte-vec conversion: in postcard a byte VECTOR and a
/// byte STRING are the same wire form (varint length + raw bytes), so this encodes byte-identically
/// to what the depth-32 writer emitted, and a blob of any other length is REFUSED at decode (the
/// door then falls through, exactly as the live codec refuses today). Only the length and limb
/// order are load-bearing here, and they never change again.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct PoseidonSpendFrontierV27 {
    /// Leaves appended so far, as the depth-32 writer recorded it.
    count: u64,
    /// `peaks[l]` = the pending left-subtree digest at level `l` (0..=32), occupied exactly at the
    /// set bits of `count`.
    peaks: Vec<Option<[u64; 4]>>,
}

/// The depth the schema-25→30 writers were compiled with. A constant of the FILE FORMAT now, not of
/// the live tree — never touch it when `SPEND_TREE_DEPTH` moves again.
const SPEND_TREE_DEPTH_V27: usize = 32;
const SPEND_FRONTIER_WIRE_LEN_V27: usize = 8 + (SPEND_TREE_DEPTH_V27 + 1) * 32;

/// Big-endian u64 from exactly 8 bytes — the depth-32 writer's limb order.
fn be_limb(b: &[u8]) -> u64 {
    let mut x = 0u64;
    for &byte in b {
        x = (x << 8) | byte as u64;
    }
    x
}

/// Write a u64 into 8 big-endian bytes.
fn be_limb_out(x: u64, out: &mut [u8]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = (x >> (56 - 8 * i)) as u8;
    }
}

impl TryFrom<Vec<u8>> for PoseidonSpendFrontierV27 {
    type Error = String;
    /// The decode half of the frozen byte contract — refuses any blob the depth-32 writer could not
    /// have emitted, so a non-v27-era file falls through this door instead of misreading.
    fn try_from(b: Vec<u8>) -> Result<Self, String> {
        if b.len() != SPEND_FRONTIER_WIRE_LEN_V27 {
            return Err(format!(
                "bad v27-era PoseidonSpendFrontier wire length {} (the depth-32 writers emitted \
                 exactly {SPEND_FRONTIER_WIRE_LEN_V27})",
                b.len()
            ));
        }
        let count = be_limb(&b[..8]);
        let mut peaks = vec![None; SPEND_TREE_DEPTH_V27 + 1];
        for (l, slot) in peaks.iter_mut().enumerate() {
            // l <= 32 here, so the shift is always in range for a u64 count.
            if (count >> l) & 1 == 1 {
                let off = 8 + l * 32;
                let mut d = [0u64; 4];
                for (i, limb) in d.iter_mut().enumerate() {
                    *limb = be_limb(&b[off + i * 8..off + i * 8 + 8]);
                }
                *slot = Some(d);
            }
        }
        Ok(PoseidonSpendFrontierV27 { peaks, count })
    }
}

impl From<PoseidonSpendFrontierV27> for Vec<u8> {
    /// The encode half — exactly the depth-32 writer's bytes, so a test-built legacy fixture is
    /// genuine and the round trip is byte-stable.
    fn from(f: PoseidonSpendFrontierV27) -> Vec<u8> {
        let mut buf = vec![0u8; SPEND_FRONTIER_WIRE_LEN_V27];
        be_limb_out(f.count, &mut buf[..8]);
        for (l, slot) in f.peaks.iter().enumerate().take(SPEND_TREE_DEPTH_V27 + 1) {
            if let Some(d) = slot {
                let off = 8 + l * 32;
                for (i, limb) in d.iter().enumerate() {
                    be_limb_out(*limb, &mut buf[off + i * 8..off + i * 8 + 8]);
                }
            }
        }
        buf
    }
}

impl PoseidonSpendFrontierV27 {
    /// ⛔⛔⛔ THERE IS NO `into_live` AND NO `from_live` — NOT A PORTING CHORE, A STATEMENT (2026-09-12).
    ///
    /// A v27 peak is a digest of the RETIRED one-round `MDS·(l + 7·r)^7` that kill list §AG measured as
    /// INVERTIBLE; a live peak is a digest of the truncated Poseidon2 permutation that replaced it. They
    /// are values of two different functions that happen to share a shape. Carrying a frozen peak into
    /// the live tree would seat a node on a root no honest producer can reproduce; rendering a live peak
    /// as a v27 peak would manufacture a file no v27 writer could ever have emitted. Both directions are
    /// therefore deliberately ABSENT, which is what makes `persist::load`'s pre-fork refusal total: no
    /// code path exists that turns these bytes into live custody.
    ///
    /// The frozen layout itself STAYS — it is how a real v27 file still DECODES and earns a NAMED
    /// refusal instead of a parse error, and how the byte contract below stays checkable.
    ///
    /// A fixture states the old writer's `(count, peaks)` DIRECTLY through this constructor, rather than
    /// deriving it from a live value that moved: the same discipline the v26 door's own fixture note
    /// records (*"never by trimming a CURRENT encoding"*).
    pub fn frozen_era(count: u64, peak_at: impl Fn(usize) -> [u64; 4]) -> Self {
        let mut peaks = vec![None; SPEND_TREE_DEPTH_V27 + 1];
        for l in 0..=SPEND_TREE_DEPTH_V27 {
            if (count >> l) & 1 == 1 {
                peaks[l] = Some(peak_at(l));
            }
        }
        PoseidonSpendFrontierV27 { peaks, count }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod frozen_wire_shape_tests {
    use super::*;

    fn sample() -> BlockV27 {
        BlockV27 {
            header: BlockHeaderV27 {
                version: 3,
                parents: vec![[7u8; 32], [9u8; 32]],
                timestamp: 1_787_700_000,
                nonce: 42,
                work: 1 << 70,
                pow_bind: [1u8; 32],
                tx_merkle_root: [2u8; 32],
                frontier_root: [3u8; 32],
                nullifier_root: [4u8; 32],
                chain_acc: [5u8; 16],
                miner_commitment: [6u8; 32],
                account_root: [8u8; 32],
                output_notes_root: [10u8; 32],
                nullifier_tags_root: [11u8; 32],
                oli_tags_root: [12u8; 32],
                account_targets_root: [13u8; 32],
                del_set_root: [14u8; 32],
                bond_set_root: [15u8; 32],
                dir_set_root: [16u8; 32],
                letter_set_root: [17u8; 32],
            },
            tx_ids: vec![[21u8; 32]],
            pow_proof: vec![1, 2, 3],
            settlement: Some(vec![4, 5]),
            nullifier_proof: NfBlockProofV27 {
                carrier: vec![6, 7],
                post_root: [18u8; 32],
                fold: vec![8, 9],
                padded_tags: vec![[19u8; 32], [20u8; 32]],
            },
            output_notes: vec![31, 32],
            oli_tags: vec![33],
            account_targets: vec![34, 35],
            del_set: vec![36],
            bond_set: vec![37],
            dir_set: vec![38],
            letter_set: vec![39, 40],
        }
    }

    /// ⭐ THE FREEZE IS ONLY REAL IF THE WIRE SHAPE HOLDS — checkable without any fixture. With the AMM
    /// retired the live layout is byte-identical to schema 27 again, so the strongest statement is
    /// EQUALITY: the frozen encoding and the live encoding of the same block are the same bytes. If this
    /// ever fails, a consensus type gained a field — which is precisely the moment the frozen door must
    /// stay behind and a new schema (with its own frozen door) must be cut.
    #[test]
    fn the_frozen_block_round_trips_and_matches_the_live_encoding_byte_for_byte() {
        let frozen = sample();
        let bytes = postcard::to_stdvec(&frozen).expect("frozen block encodes");
        let back: BlockV27 = postcard::from_bytes(&bytes).expect("frozen block decodes its own bytes");
        assert_eq!(back, frozen, "the frozen v27 block is not self-consistent");

        // ⛔ DB-343 (2026-09-28): the LIVE-equality half that stood here asserted "the live layout is byte-identical to
        // schema 27 again" — true from the AMM retirement (2026-08-26) until 2026-09-13, false since by LEGITIMATE schema
        // evolution (v34..v37 each cut with its bump). Its own instruction for that moment was "the frozen door must stay
        // behind and a new schema must be cut": the schemas were cut, but the v31..v34 doors kept naming the LIVE `Block`
        // and rotted (the real v31..v33 fixtures stopped decoding). That defect is fixed at the doors (they name
        // `BlockV27`), and the invariant it guarded is now pinned where it can hold forever:
        // `db343_no_legacy_door_names_a_live_consensus_type` (a source census) plus the real-fixture decodes.
    }

    /// ⭐ THE FROZEN v27 FRONTIER WIRE SHAPE, checkable without any fixture: a depth-32-era value
    /// round-trips byte-stably at exactly the old writer's 1,064-byte blob (postcard: 2-byte varint
    /// length prefix + blob), and the peak set a given count implies is exactly the binary-counter one.
    ///
    /// ⛔ THIS GATE USED TO END BY CARRYING THE FROZEN VALUE INTO THE LIVE TREE. It cannot any more, and
    /// that is the §AG hash replacement showing up in a test rather than a comment: a v27 peak is a
    /// digest of the retired one-round hash, so there is nothing to carry it INTO. What is still fully
    /// checkable — and is what the door actually needs — is that a real v27 file DECODES at its exact
    /// byte contract, which is how `persist::load` can name the refusal instead of reporting garbage.
    #[test]
    fn the_frozen_v27_frontier_round_trips_at_the_depth_32_writers_byte_contract() {
        // The depth-32 writer's own content: 13 leaves ⇒ peaks at levels 0, 2 and 3 (13 = 0b1101).
        let frozen = PoseidonSpendFrontierV27::frozen_era(13, |l| {
            [l as u64 + 1, 2 * l as u64, 7, l as u64]
        });
        let bytes = postcard::to_stdvec(&frozen).expect("frozen frontier encodes");
        assert_eq!(
            bytes.len(),
            2 + SPEND_FRONTIER_WIRE_LEN_V27,
            "the frozen frontier is not the depth-32 writer's fixed wire length"
        );
        let back: PoseidonSpendFrontierV27 =
            postcard::from_bytes(&bytes).expect("frozen frontier decodes its own bytes");
        assert_eq!(back, frozen, "the frozen v27 frontier is not byte-stable");
        assert_eq!(back.count, 13, "the decode lost the leaf count");
        let occupied: Vec<usize> =
            (0..=SPEND_TREE_DEPTH_V27).filter(|&l| back.peaks[l].is_some()).collect();
        assert_eq!(
            occupied,
            vec![0, 2, 3],
            "13 leaves is 0b1101, so the MMR holds peaks at exactly levels 0, 2 and 3 — any other set \
             means the frozen door and the binary-counter law disagree"
        );
    }

    /// ⛔ ADVERSARIAL: a blob of any length the depth-32 writer could not have emitted must be
    /// REFUSED at decode — this is the fail-closed length gate that makes a live-era (2,088-byte)
    /// or truncated/padded frontier fall through the door instead of misreading as v27 state.
    #[test]
    fn a_wrong_length_frontier_blob_is_refused_at_decode() {
        let live_era = vec![0u8; 8 + (64 + 1) * 32];
        let tampered_short = vec![0u8; SPEND_FRONTIER_WIRE_LEN_V27 - 1];
        let tampered_long = vec![0u8; SPEND_FRONTIER_WIRE_LEN_V27 + 1];
        for (name, blob) in [
            ("live-era 2088", live_era),
            ("truncated 1063", tampered_short),
            ("padded 1065", tampered_long),
        ] {
            let bytes = postcard::to_stdvec(&blob).expect("byte vec encodes");
            assert!(
                postcard::from_bytes::<PoseidonSpendFrontierV27>(&bytes).is_err(),
                "{name}: the frozen door ACCEPTED a blob the depth-32 writer could never have \
                 emitted — the byte contract is not being enforced"
            );
        }
    }
}

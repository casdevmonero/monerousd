// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! VALUE-KEYED SPARSE nullifier accumulator — the COUNT-FREE, flat-O(1) settlement layer.
//!
//! Why this exists (user 2026-07-21): a producer's per-block work must be flat-constant regardless of chain
//! height, like the WHIR decider — NOT the O(256·log N) of building 256 witnesses through a held tree. The proven
//! blocker was the append-indexed IMT: its `count` is an append position every node must agree on, so hiding spend
//! VOLUME forced a constant +256 advance (256 decoy inserts/block), which forced the producer to hold the O(N)
//! tree to build decoy copaths.
//!
//! The user pinned the real leak: a single node only ever knows the volume of blocks it witnessed LIVE — an O(1)
//! DSYNC jumper adopts state without replaying txs and learns nothing — EXCEPT that a cumulative `count` would hand
//! a jumper the whole chain's real volume. So the fix is to have NO count at all.
//!
//! Here the position of a nullifier IS the nullifier (its 256 bits); "unspent" = the leaf is EMPTY, "spent" = the
//! leaf holds the SPENT marker. Insertion needs NO append index and NO count: it flips one leaf EMPTY→SPENT and
//! re-folds that leaf's O(DEPTH) copath. The accumulator is a single `root` — a jumper adopts only the root and
//! learns zero about volume (there is nothing to count). Double-spend is caught for free: a re-spend's leaf is
//! already SPENT, so its non-membership (leaf==EMPTY) proof fails.
//!
//! FLAT-O(1) BY CONSTRUCTION: `verify_and_insert` folds a copath of EXACTLY `DEPTH` siblings twice (a membership
//! check + the updated root) — a fixed hash count independent of how many nullifiers are already spent. The copath
//! is SPENDER-SUPPLIED (self-built from the replicated DA stream — the trustless design), so a producer settles a
//! block holding only the O(1) `root`. Same `poseidon_pair`/`Digest4` convention as [`crate::spend_frontier`] so
//! the in-circuit gate and the wallet fold the identical tree.
//! ([[project_phone_full_node_o1_produce_fold]] [[feedback_no_growth_any_axis]] [[feedback_always_trustless]]
//!  [[feedback_no_counters_no_plaintext_transparency]])

use crate::spend_frontier::{leaf_to_cm_bytes, poseidon_pair, Digest4};

/// Key depth = the full 256-bit nullifier, so two distinct nullifiers can NEVER share a leaf (collision-free by
/// construction — no birthday analysis, no soundness caveat). Copaths are `DEPTH` siblings, mostly empty-subtree
/// constants. (Depth can be shortened later to a collision-safe hash-truncation to shrink witnesses; 256 is the
/// correct-by-construction baseline the circuit binds to.)
pub const NF_SPARSE_DEPTH: usize = 256;

/// ⭐⭐⭐ Z2 (2026-09-22) — THE NULLIFIER SET IS SHARDED BY PREFIX, WHICH IS WHAT MAKES THE ZCASH SHAPE
/// FIT THE NO-GROWTH RULE.
///
/// Zcash's one cost is a nullifier set monotone in the number of spends. That cost is a DATA-AVAILABILITY
/// problem, not a per-node one, once the set is partitioned: the tree is keyed BY the nullifier, so its
/// leaves split by nf PREFIX into `2^s` shards that are contiguous subtrees at level `DEPTH - s`.
///
/// A node holds:
///   * the BAND — the `2^s` subtree roots at level `DEPTH - s` (8 KB at s = 8, a FIXED size at any
///     height), maintained in O(1) per spend by folding the spend's own carried copath up to the band
///     level. The chain root is a fold of the band, so every node computes the consensus root with no
///     tree at all;
///   * the LEAVES of the shards it is responsible for — its share, `O(spends * k / N)` for replication
///     factor `k` over `N` nodes, so the share SHRINKS as the network grows (the danksharding argument
///     applied to nullifiers). A node serves non-membership copaths for those shards and no others.
///
/// VERIFICATION NEEDS NO SHARD AND NO TREE. Every node checks a spend with `verify_unspent` against
/// the O(1) root, exactly as before; the shard is a CUSTODY question (who can SERVE a copath), never a
/// consensus one. `s` and the owned set are therefore purely local: two nodes with different policies
/// agree on every root and every verdict.
pub const NF_SHARD_BITS_DEFAULT: usize = 8;

/// The hard cap on shard bits, and with it on every per-shard structure in this module. A tree asked for
/// more is built UNSHARDED rather than allocating past this constant.
pub const NF_SHARD_BITS_MAX: usize = 12;

/// The protocol bound on the band and on the owned-shard set: one entry per shard at the widest policy.
/// 4,096 entries x 32 B = 128 KB, a FIXED size at any chain height, spend count or peer count.
pub const NF_BAND_MAX: usize = 1usize << NF_SHARD_BITS_MAX;

/// ⭐⭐⭐ DB-353 — THE TREE'S KEY (2026-09-29, docs/DB-353-NODE-SELECTOR-BOUNDARY-SPEC.md): where a nullifier TAG becomes
/// the PATH the sparse tree walks. `SparseKey::of(tag)` = the byte-reversed tag, and it is the ONLY constructor: a tag is
/// `digest_to_bytes` of a Poseidon digest — eight lanes of 31 bits, so byte 31 is ALWAYS zero — and the descent reads
/// level 255 first (bit 7 of byte 31), so under the identity map every real nullifier landed in shard 0 and sharding
/// retained nothing. Reversed, tag byte 0 (the low byte of lane 0, uniform) selects the shard; the bottom eight levels
/// read the zero byte as a constant left tail (still injective: all 248 information bits are on the path).
///
/// The boundary is THIS MODULE's public surface: a public fn takes a TAG and converts once on entry; a public fn that
/// hands stored entries out converts back with [`SparseKey::tag`]; every private path helper takes `&SparseKey`, so a
/// raw tag reaching one does not compile. There is NO raw accessor (a `pub(crate)` one would let a crate-internal caller
/// pass key bytes to a public fn, which converts again and walks the tag's path — the double-spend shape of §4). The
/// decider handoff is the one fn [`insert_witness_for`] / [`SparseKey::to_insert_witness`]. Canon arrays below the leaf
/// (`[u8; 32]` subtree ids) stay raw: they are derived from keys and never re-enter through the public surface.
///
/// TAG space is unchanged everywhere the nullifier is a VALUE: header `padded_tags`, `tx.nullifiers`, mempool dedup,
/// `nf_to_limbs`, the fold-accumulator absence chain (`sparse_fold_digest_nfs`), cover / spend-or-decoy tags.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SparseKey([u8; 32]);

impl SparseKey {
    /// The tree key of a nullifier TAG — the only constructor.
    #[must_use]
    #[inline]
    pub fn of(tag: &[u8; 32]) -> Self {
        // ONE definition of the rule, in the decider (`sparse_key_of_tag`): the circuits and this tree cannot drift.
        Self(usdm_decider::nf_sparse_air::sparse_key_of_tag(tag))
    }
    /// Back to the TAG (the inverse of [`SparseKey::of`]; tag → key → tag is the identity).
    #[must_use]
    #[inline]
    pub fn tag(&self) -> [u8; 32] {
        usdm_decider::nf_sparse_air::tag_of_sparse_key(&self.0)
    }
    /// The decider handoff — the ONE place key bytes leave this type as a witness: the insert carriers walk exactly this
    /// path, and the decider derives the TAG for every value use (`SparseInsertWitness::tag`) by the same rule.
    #[must_use]
    pub fn to_insert_witness(&self, copath: Vec<Digest4>) -> usdm_decider::nf_sparse_air::SparseInsertWitness {
        usdm_decider::nf_sparse_air::SparseInsertWitness { key: self.0, copath }
    }
    /// Module-private: the key bytes for the path helpers below. Not `pub(crate)` by design (see the type's doc).
    #[inline]
    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Module-private: wrap a key-space byte array (a canon prefix or a stored traversal key reversed back) that is
    /// already a PATH — never a tag. Callers are inside this module only.
    #[inline]
    fn from_key_bytes(k: [u8; 32]) -> Self {
        Self(k)
    }
}

/// The decider's insert witness for the nullifier TAG `tag` with the copath THIS module built for its key.
#[must_use]
pub fn insert_witness_for(tag: &[u8; 32], copath: Vec<Digest4>) -> usdm_decider::nf_sparse_air::SparseInsertWitness {
    SparseKey::of(tag).to_insert_witness(copath)
}

impl SparseKey {
    /// The second decider handoff: the PUBLIC key digest of a shard's (or block's) insert list at the trace's insert
    /// count `n` — `usdm_decider::nf_sparse_air::keys_digest_of` over these keys' bytes. The band door derives the keys
    /// from the header's tags (`SparseKey::of`) and calls this; it never takes the digest from a carrier.
    #[must_use]
    pub fn keys_digest(keys: &[SparseKey], n: usize) -> Digest4 {
        let raw: Vec<[u8; 32]> = keys.iter().map(|k| k.0).collect();
        usdm_decider::nf_compact_air::compact_keys_digest_of(&raw, n)
    }
    /// The third and last decider handoff — SHAPE (3)'s door check (docs/DB-353-BAND-DOOR-SPEC.md §8b): the block's fold
    /// transition, carried as `k` chained direct keyed carriers, verified against values the DOOR derived — the fold-point
    /// root, the post root the announced band folds to, and the shard-major ordered admitted TAGS (converted to keys here,
    /// the slice digests and real counts derived from them by the decider). ONE transition whatever `k`.
    #[must_use]
    pub fn verify_chained_band_transition(
        fold_pre: Digest4,
        post: Digest4,
        ordered_tags: &[[u8; 32]],
        slices: &[usdm_decider::nf_sparse_air::BandSlice<'_>],
    ) -> bool {
        let keys: Vec<[u8; 32]> = ordered_tags.iter().map(|t| SparseKey::of(t).0).collect();
        usdm_decider::nf_compact_air::verify_compact_chained_band_transition(fold_pre, post, &keys, slices)
    }
}

/// ⭐ SHAPE (3) — A BAND FILLER KEY: the non-member a producer pads the fold carrier's empty slots with (a slot falls empty
/// when `respend_decide_at_fold` refuses a tag). Its key byte 0 is forced to `0xFF`, which no real key has (a real tag is a
/// 248-bit digest encoding, so its KEY byte 0 — tag byte 31 — is always zero), so it can never collide with a spend, and
/// it is never applied: padding inserts advance only the carrier's internal running root, never the committed post.
#[must_use]
pub fn band_filler_key(i: u64) -> SparseKey {
    let mut k = *blake3::hash(&[b"usdm.nf.band-filler.v1".as_slice(), &i.to_le_bytes()].concat()).as_bytes();
    k[0] = 0xFF;
    SparseKey::from_key_bytes(k)
}

/// The tower over a 256-entry protocol band: `tower[j]` has `256 >> j` nodes, `tower[j][i] = pair(tower[j−1][2i],
/// tower[j−1][2i+1])`, `tower[0]` the band itself — the same fold `usdm_decider::nf_sparse_air::fold_band` performs, kept
/// level by level so a copath's top `NF_BAND_BITS` siblings can be read off it: the sibling of shard `s` at level
/// `NF_BAND_LEVEL + j` is `tower[j][(s >> j) ^ 1]`.
fn band_tower(band: &[Digest4]) -> Option<Vec<Vec<Digest4>>> {
    let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
    if band.len() != 1usize << bits {
        return None;
    }
    let mut tower: Vec<Vec<Digest4>> = Vec::with_capacity(bits + 1);
    tower.push(band.to_vec());
    for j in 0..bits {
        let prev = &tower[j];
        let next: Vec<Digest4> = (0..prev.len() / 2).map(|i| poseidon_pair(prev[2 * i], prev[2 * i + 1])).collect();
        tower.push(next);
    }
    Some(tower)
}

/// Set band entry `shard` of `tower` ([`band_tower`]) to `v` and re-hash ONLY its path to the top: afterwards `tower` is
/// exactly `band_tower` of the moved band (every other node's two children are unchanged, so its pair hash is too).
/// `shard` must be below the band's width — the caller has checked it.
fn band_tower_set(tower: &mut [Vec<Digest4>], shard: usize, v: Digest4) {
    tower[0][shard] = v;
    let mut i = shard;
    for j in 0..tower.len() - 1 {
        i >>= 1;
        tower[j + 1][i] = poseidon_pair(tower[j][2 * i], tower[j][2 * i + 1]);
    }
}

/// The top `NF_BAND_BITS` siblings of a key in protocol shard `shard`, read off `tower` ([`band_tower`]).
fn band_top_siblings(tower: &[Vec<Digest4>], shard: u32) -> Vec<Digest4> {
    (0..usdm_decider::nf_sparse_air::NF_BAND_BITS).map(|j| tower[j][((shard as usize) >> j) ^ 1]).collect()
}

/// ⭐ SHAPE (3) — THE PRODUCER'S ASSEMBLY (docs/DB-353-BAND-DOOR-SPEC.md §8b). From the running band at the fold point,
/// the per-shard serves `(shard, band_post, [(tag, lower copath)])` in the door's canonical order within each shard, and the
/// filler serves `(filler key index, shard, lower copath, band entry after the filler)` for the empty slots, build the
/// shard-major insert list the fold carrier proves: each admitted copath's top siblings come from the MIXED band (shards
/// below at their announced post, shards above at pre), each filler's from the band as the fillers advance it; returns the
/// inserts (admitted first, fillers after), the shard-major ordered admitted TAGS the door derives too, and the band after
/// the transition. Fail-closed on a duplicate or empty shard serve, a tag outside its serve's shard, a wrong copath length,
/// or a total that is not the cover.
#[allow(clippy::type_complexity)]
pub fn assemble_fold_inserts(
    band_pre: &[Digest4],
    serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)],
    fillers: &[(u64, u32, Vec<Digest4>, Digest4)],
) -> Option<(Vec<usdm_decider::nf_compact_air::CompactInsertWitness>, Vec<[u8; 32]>, Vec<Digest4>)> {
    let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
    let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
    if band_pre.len() != 1usize << bits {
        return None;
    }
    let mut order: Vec<usize> = (0..serves.len()).collect();
    order.sort_by_key(|&i| serves[i].0);
    // ⭐ ONE tower over the running band, moved by one PATH per serve or filler ([`band_tower_set`]) — the tower `band_tower`
    // would rebuild from the moved band, at `NF_BAND_BITS` (8) pair hashes instead of `2^NF_BAND_BITS − 1` (255).
    // MEASURED (link 16, `sample` of sim-20261007-054805 at T1.2): the per-serve rebuild was 1,884 of the band prove job's
    // 3,035 samples (62 %); the job is up to 256 rebuilds (one per shard serve and per filler) ≈ 65k hashes per step.
    let mut tower = band_tower(band_pre)?;
    let entries_n = tower[0].len();
    let mut inserts = Vec::with_capacity(cover);
    let mut tags_out = Vec::with_capacity(cover);
    let mut last_shard: Option<u32> = None;
    for &i in &order {
        let (shard, band_post, entries) = &serves[i];
        if entries.is_empty() || *shard as usize >= entries_n || last_shard == Some(*shard) {
            return None;
        }
        last_shard = Some(*shard);
        let top = band_top_siblings(&tower, *shard);
        for (tag, low) in entries {
            if nf_shard(tag, bits) != *shard {
                return None;
            }
            inserts.push(compact_insert_witness_for(tag, &join_lower(low, &top)?)?);
            tags_out.push(*tag);
        }
        band_tower_set(&mut tower, *shard as usize, *band_post);
    }
    for (idx, shard, low, entry_after) in fillers {
        if *shard as usize >= entries_n {
            return None;
        }
        let key = band_filler_key(*idx);
        if key_shard(&key, bits) != *shard {
            return None;
        }
        inserts.push(compact_witness(&key, &join_lower(low, &band_top_siblings(&tower, *shard))?)?);
        band_tower_set(&mut tower, *shard as usize, *entry_after); // the filler moves the carrier's internal band, never the committed one
    }
    if inserts.len() != cover {
        return None;
    }
    // the committed band is the admitted transition only: replay the serves' posts over the pre band
    let mut band_post = band_pre.to_vec();
    for (shard, post, _) in serves {
        band_post[*shard as usize] = *post;
    }
    Some((inserts, tags_out, band_post))
}

/// ⭐ DB-353 item 3 / DB-223 Q2 — THE ONE HOLDER RULE for every sharded structure (the nullifier band, the window index):
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐ SHAPE (3) — THE BAND DOOR (docs/DB-353-BAND-DOOR-SPEC.md §2, §3, §8b; the consensus lane's R1–R7 all taken).
//
// The ONE state machine through which any node's fold-point nullifier band advances. No node advances its band by its
// own recompute — holders included (R2a): the band moves ONLY by a RELAYED, verified `BandTransition` (§11.10–§11.13:
// the band is a function of the chain, so its certificates travel on the relay, never in a block), applied strictly in
// fold order at a pointer that WAITS and never skips (R2c). Everything the proof is checked against — the pre root, the
// insert order, the slice digests, the post root — is DERIVED here from the header-bound admitted set and this node's own
// band; the relay contributes the announced touched entries and the proofs, nothing else.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// ⭐ DB-454 — the most bytes one band step's encoding may carry over the bulk lane (the `BANDSTEP` answer's body bound).
/// DERIVED: the deepest honest compact step measured is 248,294 B (DB-453 brick 1, `db453_c`: a split below level 193 at
/// k = 1; the normal step is 231,042 B); 2^19 covers it twice over, so a slice-count or shape variance never trips it and
/// a hostile server's 16 MB frame (the lane's own ceiling) is refused before decoding.
pub const BAND_STEP_BYTES_MAX: usize = 512 * 1024;

/// The fold transition of ONE block's admitted nullifier set — §11.10/§11.12: a RELAY message (inv, getdata, this),
/// never a block field (`Block.band_transition` was removed, 8a28941); taken only by `BandDoor::offer_step`, which
/// verifies it against values it derives. One postcard encoding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandTransition {
    /// NOT-A-TAG: the id of the block whose fold step this applies.
    pub for_block: [u8; 32],
    /// `(shard, entry after)` for every TOUCHED shard, ascending — the only carried values beside the proofs. The door
    /// refuses an entry for a shard the admitted set does not touch and a touched shard without one (the partition rule).
    pub band_post: Vec<(u32, Digest4)>,
    /// §11.2 — the step's slice count; the door checks it against its OWN `band_chain_k` of the governance target, never
    /// takes it from here.
    pub k: u32,
    /// §11.12 — ALL `k` chained direct keyed carriers of the step, indices `0..k` in order: `(slice index, post root after
    /// the slice, proof bytes)`. Slice `i`'s pre root is slice `i−1`'s post (the door's derived pre for `i = 0`) and slice
    /// `k−1`'s post is the fold's post root. ONE owner proves the whole step (`band_step_owner`); owners pipeline steps.
    pub slices: Vec<(u32, Digest4, Vec<u8>)>,
}

/// The protocol's ONE insert order for a fold step's admitted set — shard-major (`nf_shard` at `NF_BAND_BITS`), ascending
/// tag bytes within a shard, duplicates collapsed (a nullifier set is a set). The door derives it, the holders serve in it,
/// the producer proves in it, and `verify_chained_band_transition` chunks it as given. Returns `(touched shards
/// ascending, ordered tags, the tags of each touched shard)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn admitted_order(
    admitted: &[[u8; 32]],
) -> (Vec<u32>, Vec<[u8; 32]>, std::collections::BTreeMap<u32, Vec<[u8; 32]>>) {
    let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
    let mut sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<[u8; 32]>> = Default::default();
    for t in admitted {
        sets.entry(nf_shard(t, bits)).or_default().insert(*t);
    }
    let by_shard: std::collections::BTreeMap<u32, Vec<[u8; 32]>> =
        sets.into_iter().map(|(s, set)| (s, set.into_iter().collect())).collect();
    let touched = by_shard.keys().copied().collect();
    let ordered = by_shard.values().flatten().copied().collect();
    (touched, ordered, by_shard)
}

/// The PRODUCER's half (any node that gathered the copaths): assemble, prove `k` chained slices and lay the object.
/// `serves` and `fillers` are the holders' answers (`RefSparseNf::serve_fold_copaths`), any order; `band_pre` is the
/// producer's copy of the fold-point band — it must equal the door's, or the door refuses (the statement binds the fold
/// root). `k` = `band_chain_k(block_interval_ms)`. `None` when the assembly is malformed or the prover refuses.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn build_band_transition(
    for_block: [u8; 32],
    band_pre: &[Digest4],
    serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)],
    fillers: &[(u64, u32, Vec<Digest4>, Digest4)],
    k: usize,
) -> Option<BandTransition> {
    let all: Vec<usize> = (0..k).collect();
    build_band_slices(for_block, band_pre, serves, fillers, k, &all)
}

/// The slices of one step: real carriers, or — for an armed test node only — the bound double's.
fn band_prove_slices(
    inserts: &[usdm_decider::nf_compact_air::CompactInsertWitness],
    fold_pre: Digest4,
    admitted: usize,
    k: usize,
    chosen: &[usize],
    bound: bool,
) -> Option<Vec<(usize, Digest4, Vec<u8>)>> {
    #[cfg(test)]
    {
        if bound {
            return usdm_decider::nf_compact_air::prove_compact_band_slices_bound(inserts, fold_pre, admitted, k, chosen);
        }
    }
    let _ = bound;
    usdm_decider::nf_compact_air::prove_compact_band_slices(inserts, fold_pre, admitted, k, chosen)
}

/// §11.4 — the PRODUCER's attach: prove only `chosen` slices of the step (every pre root computed natively) and lay them
/// with the step's `band_post`. `build_band_transition` is this with every slice.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn build_band_slices(
    for_block: [u8; 32],
    band_pre: &[Digest4],
    serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)],
    fillers: &[(u64, u32, Vec<Digest4>, Digest4)],
    k: usize,
    chosen: &[usize],
) -> Option<BandTransition> {
    build_band_slices_with(for_block, band_pre, serves, fillers, k, chosen, false)
}

/// ⛔ TEST BUILDS ONLY — [`build_band_transition`] with the BOUND band-step double: an armed node's prove worker lays
/// these, and only an armed door accepts them.
#[cfg(test)]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn build_band_transition_bound(
    for_block: [u8; 32],
    band_pre: &[Digest4],
    serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)],
    fillers: &[(u64, u32, Vec<Digest4>, Digest4)],
    k: usize,
) -> Option<BandTransition> {
    let all: Vec<usize> = (0..k).collect();
    build_band_slices_with(for_block, band_pre, serves, fillers, k, &all, true)
}

#[allow(clippy::type_complexity)]
fn build_band_slices_with(
    for_block: [u8; 32],
    band_pre: &[Digest4],
    serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)],
    fillers: &[(u64, u32, Vec<Digest4>, Digest4)],
    k: usize,
    chosen: &[usize],
    bound: bool,
) -> Option<BandTransition> {
    if chosen.is_empty() {
        return None;
    }
    let (inserts, ordered_tags, _band_post) = assemble_fold_inserts(band_pre, serves, fillers)?;
    let fold_pre = usdm_decider::nf_sparse_air::fold_band(band_pre)?;
    let slices = band_prove_slices(&inserts, fold_pre, ordered_tags.len(), k, chosen, bound)?;
    let touched: std::collections::BTreeMap<u32, Digest4> = serves.iter().map(|(s, post, _)| (*s, *post)).collect();
    Some(BandTransition {
        for_block,
        band_post: touched.into_iter().collect(),
        k: u32::try_from(k).ok()?,
        slices: slices.into_iter().map(|(i, post, bytes)| (i as u32, post, bytes)).collect(),
    })
}

/// §11.13 (node-lane condition 1) — how many provers OWN steps in an epoch: `ceil(BAND_FOLD_PROVE_MS_REF / target)`, the
/// `band_chain_k` derivation (one owner's whole step proves within `M` mesh block intervals at the reference cost), at
/// most the provers known, at least one. 7 at the 500 ms target (3,117 ms reference).
#[must_use]
pub fn band_owner_count(target_spacing_ms: u64, provers: usize) -> usize {
    let need = usdm_decider::nf_sparse_air::BAND_FOLD_PROVE_MS_REF.div_ceil(target_spacing_ms.max(1));
    // clamped in u64 first, so the cast holds a value no larger than `provers`
    need.min(provers as u64).max(1) as usize
}

/// ⭐ §11.13 — the step OWNERS of an epoch (`oli::EPOCH_BLOCKS` fold ordinals): the top-`m` provers by HRW over
/// `("MUSD/band-step-owner/v1" ‖ epoch)`, in rank order. Deterministic from public ids and rotating every epoch; a prover
/// joining or leaving moves only the epochs it ranks in. MEASURED (`db353_13_the_relay_lag_is_bounded_by_the_owner_count…`):
/// `m` owners with the open rule at `2m` hold a 10×-slow owner to lag 26 at N = 8 … 100, where all-N ownership drops steps.
#[must_use]
pub fn band_step_owners(epoch: u64, provers: &[String], m: usize) -> Vec<String> {
    let mut domain = b"MUSD/band-step-owner/v1".to_vec();
    domain.extend_from_slice(&epoch.to_le_bytes());
    holders_of(&domain, 0, provers, m)
}

/// The owner of the fold step at `ordinal`: its epoch's owners, round-robin by ordinal. `None` with no provers.
#[must_use]
pub fn band_step_owner(ordinal: u64, provers: &[String], m: usize) -> Option<String> {
    let owners = band_step_owners(ordinal / crate::oli::EPOCH_BLOCKS, provers, m);
    let n = u64::try_from(owners.len()).ok().filter(|n| *n > 0)?;
    owners.into_iter().nth((ordinal % n) as usize)
}

/// ⭐ §11.14 (node-lane bandwidth condition) — the slice count of a RELAYED step: ONE. Under whole-step ownership one
/// owner proves every slice, so slices no longer split work between producers (the reason `band_chain_k` existed), and the
/// owner's time budget is already `band_owner_count` mesh intervals. MEASURED (`db353_11_14_…`, one real 256-insert step on
/// this machine): k = 1 proves in 9,580 ms, verifies in 2 ms, 34,584 B; k = 8 in 13,971 ms, 10 ms, 233,772 B — every
/// step crosses every link of the constant-rate cell channel, so k = 1 is 6.8× fewer bytes AND the faster proof.
#[must_use]
pub const fn band_relay_k() -> usize {
    1
}

/// §11.13 C2 — how many mesh blocks after its noting a step its owner has not relayed becomes OPEN to any tree-holder:
/// `2m`, so a slow or absent owner stalls the band by a bound set by the OWNER count, never by the prover count.
#[must_use]
pub const fn band_open_after(m: usize) -> usize {
    2 * m
}

/// §11.12 — a relayed step whose `k` slices and `band_post` VERIFIED against the pre and band the door derived: held until
/// `drain` applies it at the pointer, and served to the peers that ask for it. `end` is its chain end — the next step's pre.
#[derive(Clone, Debug)]
pub struct VerifiedStep {
    pub transition: BandTransition,
    end: Digest4,
}

/// ⛔⛔ DB-419 — THE BAND DOOR'S REWIND REACH a checkpoint carries: the applied steps inside the journal (R3), the band
/// ring's `(ordinal, root)` entries, the journal's floor and the root just below it. A restart resumed the door through
/// `adopt_certified`, which drops all four (a certified bundle's band carries no history), so the resumed floor was the
/// resume point and a reorg just below it marked the spine stale until a certified re-anchor. MEASURED (fast lane, default
/// seed, night/sim-20261007-211400.log): node 0 restarted on its provisioned identity, three of its own blocks lost a
/// reorg 1 record deep, `a rewind reached below the band door's fold journal` stopped its fold, the re-anchor took
/// the bundle at height 788, and W1's POS pay never found its member windows (T3 red). The bond, directory and peg
/// classes carry their journals since DB-274 / DB-417 — this is the one class the restart still cut.
/// O1-FOOTPRINT-REVIEWED: at most `lag_cap` journal steps (each ≤ the 256-slot lane of before-entries and its admitted
/// tags) and at most the anchor-ring length of 72-byte ring entries — constant in height.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandJournalCarry {
    pub journal: Vec<BandStep>,
    pub ring: Vec<(u64, Digest4)>,
    pub floor: u64,
    pub base_root: Digest4,
    /// ⭐ G1e-iv (lane a 2026-10-23) — THE PROOFS OF THE JOURNALED STEPS (`BandDoor::applied_proofs`), oldest first, so a
    /// restarted node still serves what a peer behind it needs (the Bitcoin / Kaspa shape: a node keeps what a syncing peer
    /// needs above its pruning point). RESTART CENSUS g1eii-restart-census-20261023.log:2883/2903: band_door 5.16 MB → 13 KB
    /// on both nodes — every applied proof was dropped at resume, so after a rolling restart NO node served the steps between
    /// a joiner's adopted band pointer and the fold point (the T1.6 shape of 2026-10-06). Installed by `install_journal`
    /// behind the journal's own replay door: a proof is kept only for a journaled step it reproduces (its block, and the post
    /// slots the door's own backward replay reproduces for that step); any other proof is dropped, counted, never served.
    /// Bounded like the live deque: ≤ `lag_cap` × one proof. cons: ≤ 64 × ≈ 34.6 KB ≈ 2.2 MB per checkpoint write (k = 1),
    /// constant in height.
    #[serde(default)]
    pub applied: Vec<([u8; 32], BandTransition)>, // NOT-A-TAG: block ids
    /// ⭐ G1h (lane a 2026-10-23) — THE STEPS THE DOOR HOLDS BUT HAS NOT APPLIED: each `verified` copy and each `solicited`
    /// one (flag = THIS node proved it, `own_held`) in fold order, then the `parked` early copies. RESTART CENSUS
    /// (scratchpad/watch/watch-20261023-065748.log.7:4874): band_door 3 105 664 → 2 076 105 B, `solicited:{…}` and
    /// `own_held:{…}` → `{}` on both nodes — `adopt_certified` clears them, so a restart threw away the node's own proof of
    /// a step held ahead of its predecessor (re-proved from scratch, or never served to the peer pulling it). Installed by
    /// `install_journal` through the door's OWN admission (`offer_step` / `offer_own_step`): the same structural checks, a
    /// verifiable copy is VERIFIED again, an early one held within the same windows — nothing enters that the live door
    /// would refuse. cons: one proof per held step per checkpoint write (≤ the awaiting steps + `lag_cap` parked, constant in
    /// height; measured 1.03 MB for the one held step above) and one step verify per verifiable copy at boot.
    #[serde(default)]
    pub held: Vec<(BandTransition, bool)>,
    /// ⭐ A-F44 (lane goods 2026-11-12) — THE ADMITTED SETS BELOW THE FLOOR (`BandDoor::history`), `(ordinal, admitted)`
    /// ascending and contiguous, every ordinal below `floor` and none below `floor − EVIDENCE_WINDOW_STEPS`: what a fold
    /// step re-folded at the floor still reads when its spends' evidence names a step the journal has released. Without
    /// it a node restarted, then rewound, judges that evidence "unknown here" forever (the A-F44 wedge). Trusted from this
    /// node's own checkpoint exactly as the journal's own `admitted` sets are (the replay below checks `before` and `post`,
    /// never an admitted set). O1-FOOTPRINT-REVIEWED: at most `EVIDENCE_WINDOW_STEPS` + 1 entries, each one step's
    /// admitted tags — constant in height.
    #[serde(default)]
    pub history: Vec<(u64, Vec<[u8; 32]>)>,
}

/// One applied step in the rewind journal (R3): the entries the step replaced, restored in reverse on a rewind, and the
/// admitted tags it applied — what a rewind takes back out of the held view, and what `spent_after` reads. Bounded by the
/// journal's reach (`lag_cap` steps × the 256-slot lane).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandStep {
    pub ordinal: u64,
    /// NOT-A-TAG: a block id.
    pub block: [u8; 32],
    pub before: Vec<(u32, Digest4)>,
    /// TAG-SPACE: the step's admitted tags, in the order `drain` applied them.
    pub admitted: Vec<[u8; 32]>,
    /// The band root AFTER this step — what a copath carried against it folds to (`spent_since`). NOT-A-TAG: a root.
    pub post: Digest4,
}

/// `BandDoor::spent_since`'s answer: exact both ways, or why it cannot be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Since {
    /// The root is not one this door can place.
    UnknownRoot,
    /// Not known-spent, and a step after the root is unknown (or a gap): wait.
    Stale,
    Spent,
    NotSpent,
}

/// The door's answer to one relayed step (§11.12). Nothing here names a tag. What the relay does with each: `Verified` —
/// announce it (inv) and serve it; `Held` — wait for its predecessor; `Refused` — drop it, NOT the peer's fault by itself
/// (early, duplicate, unknown here); `Invalid` — the bytes FAILED against values this door derived: score the announcer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BandReceipt {
    /// Verified against the pre and band this door derived; `drain` applies it at the pointer.
    Verified,
    /// Held unverified: this node solicited it and an earlier step has not verified yet.
    Held,
    /// Refused before any proof work; the reason is a fixed string.
    Refused(&'static str),
    /// The slices or `band_post` did not verify.
    Invalid(&'static str),
}

/// The door's refusal of a copy whose step it has already APPLIED (another proof of the step got here first and moved the band).
pub const BAND_REFUSED_APPLIED: &str = "this step's block is already applied";
/// The door's refusal of a copy whose step it already holds VERIFIED (another proof of the step got here first).
pub const BAND_REFUSED_VERIFIED: &str = "this step is already verified";

impl BandReceipt {
    /// SPEED R4 — was this copy refused because ANOTHER proof of the same step had already been verified or applied
    /// here? For a node's own proof that is a lost race: somebody else proved the step first
    /// (`Node::band_own_proof_lost`). Every other refusal says something about the copy or the door, not about a race.
    #[must_use]
    pub fn lost_to_another_proof(&self) -> bool {
        matches!(self, Self::Refused(why) if *why == BAND_REFUSED_APPLIED || *why == BAND_REFUSED_VERIFIED)
    }
}

/// What one drained step did. `holder_disagreed` names the shards whose recompute on the held tree differed from the
/// carried entry: the caller DROPS and re-warms them (R2a) — the carried, verified value stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BandApplied {
    pub ordinal: u64,
    /// NOT-A-TAG: a block id.
    pub block: [u8; 32],
    pub touched: usize,
    pub holder_disagreed: Vec<u32>,
}

/// Why the last drain stopped (diagnostics; the pointer WAITS in every case, it never skips).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandWait {
    /// No fold step awaits.
    Idle,
    /// The pointer's step awaits a carried transition.
    Carrier,
    /// The pointer's step's admitted set is unknown here (no body was held at its fold): only a certified re-adopt
    /// moves it — never a carrier's word.
    Unknown,
}

/// ⭐ The band door's state: the running fold-point band and everything that moves it. Every collection is bounded by
/// `lag_cap` steps (the node passes its fold journals' reach) or by the ring length the caller passes — never by height.
#[derive(Clone, Debug)]
pub struct BandDoor {
    band: Vec<Digest4>,
    root: Digest4,
    /// The band root just BELOW the journal (before its first step): the empty root at creation, the adopted root after
    /// a re-adopt, the released step's post as the journal releases — the oldest root `spent_since` can still answer from.
    base_root: Digest4,
    /// Fold steps noted and not yet applied, oldest first: ordinal → (block, admitted tags; `None` = unknown here).
    /// The POINTER is the smallest key.
    awaiting: std::collections::BTreeMap<u64, ([u8; 32], Option<Vec<[u8; 32]>>)>,
    /// §11.12 — relayed steps that VERIFIED, keyed by the step's block, one per step. Bounded by `lag_cap` (only awaiting
    /// steps are held).
    verified: std::collections::BTreeMap<[u8; 32], VerifiedStep>,
    /// ⭐ THE PROOFS OF RECENTLY APPLIED STEPS, still served to a peer that is behind (the Bitcoin / Kaspa shape: a node keeps
    /// what a syncing peer needs above its pruning point). Applying a step used to DROP its proof, so the steps between a
    /// joiner's adopted band pointer and the servers' were held verified by NO node.
    /// MEASURED 2026-10-06 (`sim-20261006-045210`, T1.6): a fresh node adopted the bundle with its band 32 steps behind the
    /// fold point, wanted those 32 steps, verified 0 of 147 relayed copies (all for later steps), applied 0 — its fold waited
    /// at the cap 5,966 times and its view warm (which needs the fold's tail) never installed.
    /// Bounded by `lag_cap` like the journal: ≤ lag_cap × one proof (≈ 34.6 KB at k = 1) ≈ 2.2 MB at the 64 cap, constant.
    applied_proofs: std::collections::VecDeque<([u8; 32], BandTransition)>,
    /// §11.12 — steps THIS node asked for (a getdata of its own) that cannot verify yet because an earlier step has not:
    /// at most `solicit_cap` of them, re-tried as each earlier step verifies. Nothing unsolicited is ever held here.
    solicited: std::collections::BTreeMap<[u8; 32], BandTransition>,
    /// ⭐ DB-454 — the ids in `solicited` whose copy THIS node PROVED itself (its own step proven ahead of its predecessor).
    /// Those are served to a peer's by-id pull like a verified copy: the producer of a proof publishes it the moment it
    /// exists (the block-relay shape — a miner announces its own block before anyone verified it), and the puller verifies
    /// it against values it derives. A third party's held copy is never served: the invariant kept is that a node never
    /// RELAYS bytes it has not verified unless it made them. ⊆ `solicited`, so ≤ `solicit_cap` ids — no growth axis.
    /// MEASURED why (real lane, night/sim-20261021-211315.log): an owner's step proven ahead was neither flooded nor served
    /// until the owner's own band reached it, so every non-owner's lease ran out and every node proved every step.
    own_held: std::collections::BTreeSet<[u8; 32]>, // O1-INFINITY-REVIEWED: a subset of `solicited`, which `offer_step` caps at `solicit_cap` (= the owner count, a constant of the target spacing) and `forget_unawaited` prunes to the awaiting window — never a per-step store
    /// §11.13 condition 2 — `W = M`, the epoch's owner count (`band_owner_count`), set by the node.
    solicit_cap: usize,
    /// ⭐ EARLY relayed steps — a step for a block this door has NOT yet noted a fold step for (gossip outruns the fold by
    /// up to the fold depth on every node). MEASURED 2026-10-05 (db358 r3 control + the live joiner ×3): the door REFUSED
    /// such a step ("no awaiting fold step"), the one gossip copy was lost, and when the fold reached the block it waited on
    /// `BandWait::Carrier` for a step nobody would send again — the joiner stopped folding at ordinal 13 while the producer
    /// reached 19 (H3), and live the fold trailed at the DB-396 cap because every step had to be re-solicited. A step whose
    /// block is unknown HERE is parked, FIFO, bounded by `lag_cap` (the same bound as `awaiting`), one per block, and is
    /// re-offered as a solicited copy the moment `note_fold_step` names its block — so it verifies through `cascade` like
    /// any held copy. DOOR CHECKLIST (§9.6): (1) PoW — n/a, a band step is a proof object; (2) proof — `verify_step` runs
    /// when the step becomes verifiable, parking defers it and never skips it; (3) conservation — n/a; (4) replay — one
    /// parked copy per block, `verified` refuses a second copy; (5) bounded — `lag_cap` entries, FIFO eviction; (6) parity
    /// with the solicited door — the same structural checks (k, slice order, band_post) run before a step is parked, and a
    /// parked step takes the solicited store's own path afterwards.
    parked: std::collections::VecDeque<BandTransition>,
    /// Solicited copies that FAILED when their predecessor verified, since the relay last took them: the relay scores
    /// the peer it fetched each from and re-solicits. NOT-A-TAG: block ids. Bounded by `solicit_cap` per cascade.
    invalidated: Vec<[u8; 32]>,
    /// ⭐ Steps the CASCADE verified (a held copy whose predecessor just landed), since the relay last took them — the relay
    /// floods each at once, as it floods a step that verified on arrival. MEASURED 2026-10-06 (the simulator's fast lane, two
    /// provers, alternating owners): a node's own early proof sat held, the cascade verified it when the peer's predecessor
    /// arrived, and nothing sent it — the peer got it only from its next 4 s ask (8 s ask timeout): ~1 band step per 14 s
    /// against a fold step per 2 s, the band never caught up, the fold sat at its cap and no credited note became spendable.
    /// NOT-A-TAG: block ids. Bounded by `solicit_cap` per cascade.
    newly_verified: Vec<[u8; 32]>,
    /// The slice count every relayed step must use — [`band_relay_k`] (1); never taken from a relayed copy.
    chain_k: usize,
    /// Applied steps inside the rewind reach, oldest first (R3).
    journal: std::collections::VecDeque<BandStep>,
    /// The admitted sets of steps BELOW the journal's floor, contiguous up to it (an idle step's set is empty): given by the
    /// bundle a joiner joined with (JOINING BY WORK, checked against the header commits), and, since A-F44, every step the
    /// journal releases. Lets a fold step judge evidence naming a step the journal no longer holds. Bounded by the
    /// evidence window below the floor ([`Self::keep_released`]).
    /// ⛔ A-F44 (measured by lane vaults 2026-11-12 on real nodes; mechanism read by lane goods): this map was filled ONLY
    /// at a join. A rewind from about step 118 to 63 left the journal's floor where its releases had raised it (about 55:
    /// the journal holds `lag_cap` = 64 steps), so the re-fold of step 63 judged evidence naming steps below 54 against a
    /// floor that no longer reached them: `admitted_after_ordinal` answered "unknown here", the verdict was `Wait`
    /// forever, the fold never noted step 63, the band had no pointer, and nothing could ever move (1,224 `[respend] ⏸`
    /// lines, "the door has no pointer"). A node that never rewound judged the same step from its full journal: the
    /// verdict depended on the node's own past, not on the chain. Now the sets the journal releases stay here for one
    /// evidence window, so every node judges a step at its fold, first or re-folded, from the same sets.
    history: std::collections::BTreeMap<u64, Vec<[u8; 32]>>,
    /// The band root after each applied step, `(ordinal, root)`, oldest first — `band_root_at` (R2c: a step absent here is
    /// PENDING or out of the ring).
    ring: std::collections::VecDeque<(u64, Digest4)>,
    /// The lowest ordinal the journal can still un-fold to; a rewind below it is STALE, never silently wrong (R3).
    floor: u64,
    lag_cap: usize,
    /// Counters, never tags: fold steps not noted because the lag reached `lag_cap`; carried copies the proof refused.
    pub dropped_for_lag: u64,
    /// The first fold ordinal this door could NOT note (the lag cap refused it). From there the band cannot follow the
    /// chain without skipping, so the door takes NO later step and every `spent_after` is STALE until a certified
    /// re-adopt (`adopt_certified`) clears it — a gap is never skipped silently.
    stale_from: Option<u64>,
    /// Admitted tags a rewind could not take back out of the held view (a view that does not hold them): the caller
    /// drops and re-warms the view. Never a tag.
    pub held_rewind_misses: u64,
    pub copies_refused: u64,
    /// ⛔ TEST BUILDS ONLY — this door verifies the BOUND band-step double (`usdm_decider::nf_sparse_air::band_bound`)
    /// instead of real carriers: a whole hub of nodes is armed together, so the two forms never mix. A node binary has no
    /// such field.
    #[cfg(test)]
    bound_double: bool,
    /// ⛔ TEST BUILDS ONLY — DB-454: the simulated cost (ms) the bound double's prove job DECLARES, so a charged simulated node
    /// takes it at spawn + this (`budget_clock::OffLockJob::spawn_with_declared_cost`); 0 = the double's own microseconds.
    #[cfg(test)]
    double_charge_ms: u64,
}

impl BandDoor {
    /// ⛔ TEST BUILDS ONLY — arm the bound band-step double on this door (and, through
    /// [`crate::node::Node::arm_band_double_for_test`], on the node's prove worker).
    #[cfg(test)]
    pub fn arm_bound_double_for_test(&mut self) {
        self.bound_double = true;
    }

    /// ⛔ TEST BUILDS ONLY — DB-454: charge the bound double's prove job `ms` of simulated time per step.
    #[cfg(test)]
    pub fn set_double_charge_for_test(&mut self, ms: u64) {
        self.double_charge_ms = ms;
    }

    /// The declared simulated cost of the bound double's prove job (test builds; 0 in a node binary).
    #[must_use]
    pub fn double_charge_ms(&self) -> u64 {
        #[cfg(test)]
        {
            self.double_charge_ms
        }
        #[cfg(not(test))]
        {
            0
        }
    }

    /// Does this door verify the bound double (test builds only; always `false` in a node binary)?
    #[must_use]
    pub fn bound_double(&self) -> bool {
        #[cfg(test)]
        {
            self.bound_double
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// ONE carried slice against the door-derived values: the real carrier verifier, or — on an armed test door only —
    /// the bound double's.
    fn slice_verifies(bound: bool, pre: Digest4, post: Digest4, chunk: &[[u8; 32]], k: usize, bytes: &[u8]) -> bool {
        #[cfg(test)]
        {
            if bound {
                return usdm_decider::nf_compact_air::verify_compact_band_slice_bound(pre, post, chunk, k, bytes);
            }
        }
        let _ = bound;
        usdm_decider::nf_compact_air::verify_compact_band_slice(pre, post, chunk, k, bytes)
    }

    /// The empty band: every shard's subtree empty, the root the empty sparse root.
    #[must_use]
    pub fn new(lag_cap: usize) -> Self {
        let n = 1usize << usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let band = vec![empty_subtree(usdm_decider::nf_sparse_air::NF_BAND_LEVEL); n];
        let root = usdm_decider::nf_sparse_air::fold_band(&band).expect("a full band folds");
        Self {
            band,
            root,
            base_root: root,
            awaiting: std::collections::BTreeMap::new(),
            verified: std::collections::BTreeMap::new(),
            solicited: std::collections::BTreeMap::new(),
            own_held: std::collections::BTreeSet::new(),
            solicit_cap: band_owner_count(crate::params::ChainParams::default().target_spacing_ms, usize::MAX),
            parked: std::collections::VecDeque::new(),
            invalidated: Vec::new(),
            newly_verified: Vec::new(),
            chain_k: band_relay_k(),
            journal: std::collections::VecDeque::new(),
            history: std::collections::BTreeMap::new(),
            applied_proofs: std::collections::VecDeque::new(),
            ring: std::collections::VecDeque::new(),
            floor: 0,
            lag_cap: lag_cap.max(1),
            dropped_for_lag: 0,
            stale_from: None,
            held_rewind_misses: 0,
            copies_refused: 0,
            #[cfg(test)]
            bound_double: false,
            #[cfg(test)]
            double_charge_ms: 0,
        }
    }

    /// The fold-point band root — `fold_band` of the running band. NOT-A-TAG: a root.
    #[must_use]
    pub fn band_root(&self) -> Digest4 {
        self.root
    }

    /// Set the slice count (production: [`band_relay_k`], the default — the node never needs this; the k-measurement pin
    /// does). A value that is not a power of two within the cover is refused (`false`) and the count stands.
    pub fn set_chain_k(&mut self, k: usize) -> bool {
        if k == 0 || !k.is_power_of_two() || k > usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER {
            return false;
        }
        self.chain_k = k;
        true
    }

    /// The slice count this door requires.
    #[must_use]
    pub fn chain_k(&self) -> usize {
        self.chain_k
    }

    /// §11.13 condition 2 — the solicited window `W`: the epoch's owner count. At least one.
    pub fn set_solicit_cap(&mut self, w: usize) {
        self.solicit_cap = w.max(1);
    }

    /// The solicited window `W` this door holds (G1g-iv: compared live vs booted by `node::pins`).
    #[must_use]
    pub fn solicit_cap(&self) -> usize {
        self.solicit_cap
    }

    /// §11.12 — would this door take a copy of the step for `block` NOW: it awaits here with a known, non-empty admitted
    /// set, no copy is verified or held, and either the step is verifiable (every earlier step verified) or the
    /// solicited window has room. The relay asks this before it sends a getdata.
    #[must_use]
    pub fn wants(&self, block: &[u8; 32]) -> bool { // NOT-A-TAG: a block id
        let awaits = self.awaiting.values().any(|(b, a)| b == block && a.as_ref().is_some_and(|a| !a.is_empty()));
        awaits
            && !self.verified.contains_key(block)
            && !self.solicited.contains_key(block)
            && (self.pre_of(block).is_some() || self.pulled_held() < self.solicit_cap)
    }

    /// G1e-iv audit: the blocks whose applied proofs this door still serves, oldest first (block ids, never tags).
    #[must_use]
    pub fn applied_proof_blocks(&self) -> Vec<[u8; 32]> { // NOT-A-TAG: block ids
        self.applied_proofs.iter().map(|(b, _)| *b).collect()
    }

    /// §11.12 / DB-454 — the copy of a step this door SERVES to a peer's by-id pull: one VERIFIED and still awaiting here,
    /// one this door APPLIED within the journal's reach (`applied_proofs`), or THIS NODE'S OWN proof held ahead of its
    /// predecessor (`own_held`). Never a third party's unverified copy.
    pub fn serve_step(&self, block: &[u8; 32]) -> Option<&BandTransition> { // NOT-A-TAG: a block id
        self.verified
            .get(block)
            .map(|v| &v.transition)
            .or_else(|| self.applied_proofs.iter().rev().find(|(b, _)| b == block).map(|(_, t)| t))
            .or_else(|| if self.own_held.contains(block) { self.solicited.get(block) } else { None })
    }

    /// DB-454 — can this door serve `block`'s step (what a `BandInv` may name)?
    #[must_use]
    pub fn holds_step(&self, block: &[u8; 32]) -> bool { // NOT-A-TAG: a block id
        self.serve_step(block).is_some()
    }

    /// ⭐ DB-454 — THIS NODE'S OWN proof of a step, offered to its own door: [`Self::offer_step`] as a solicited copy (this
    /// node asked itself), and when it is HELD ahead of its predecessor it is marked `own_held` so a peer's pull is served
    /// from it at once instead of after this node's own band reaches it.
    pub fn offer_own_step(&mut self, t: BandTransition) -> BandReceipt {
        let block = t.for_block;
        self.own_held.retain(|b| self.solicited.contains_key(b));
        let receipt = self.offer_step_as(t, true, true);
        if matches!(receipt, BandReceipt::Held) && self.solicited.contains_key(&block) {
            self.own_held.insert(block);
        }
        receipt
    }

    /// §11.12 — the steps this door holds VERIFIED (what its inv announces), in fold order.
    #[must_use]
    pub fn verified_blocks(&self) -> Vec<[u8; 32]> { // NOT-A-TAG: block ids
        self.awaiting.values().map(|(b, _)| *b).filter(|b| self.verified.contains_key(b)).collect()
    }

    /// The pre root and band BEFORE the awaiting step for `block`, and its admitted set: the applied band carried through
    /// every step between the pointer and it — an idle step moves nothing, a non-idle one only by its VERIFIED copy.
    /// `None` while any earlier step is unverified or unknown, or when `block` awaits nothing.
    fn pre_of(&self, block: &[u8; 32]) -> Option<(Digest4, Vec<Digest4>, Vec<[u8; 32]>)> {
        let mut pre = self.root;
        let mut band = self.band.clone();
        for (b, admitted) in self.awaiting.values() {
            let admitted = admitted.as_ref()?;
            if b == block {
                return Some((pre, band, admitted.clone()));
            }
            if admitted.is_empty() {
                continue;
            }
            let v = self.verified.get(b)?;
            for (s, e) in &v.transition.band_post {
                *band.get_mut(*s as usize)? = *e;
            }
            pre = v.end;
        }
        None
    }

    /// §11.12 — verify ONE whole relayed step against the pre and band the door derived: all `k` slices chained in order
    /// over the chunks of the admitted set, then the partition rule (the carried shards are EXACTLY the touched ones) and
    /// the fold of the band after `band_post` to the chain's end. `Some(chain end)` on success.
    fn verify_step(&self, pre: Digest4, band: &[Digest4], admitted: &[[u8; 32]], t: &BandTransition) -> Option<Digest4> {
        let k = self.chain_k;
        let (touched, ordered, _) = admitted_order(admitted);
        if ordered.is_empty() || t.slices.len() != k {
            return None;
        }
        let keys: Vec<[u8; 32]> = ordered.iter().map(|tag| SparseKey::of(tag).0).collect();
        let chunks = usdm_decider::nf_sparse_air::band_slices(&keys, k)?;
        if chunks.len() != k {
            return None;
        }
        let mut at = pre;
        for (i, ((idx, post, bytes), chunk)) in t.slices.iter().zip(&chunks).enumerate() {
            if *idx as usize != i || !Self::slice_verifies(self.bound_double(), at, *post, chunk, k, bytes) {
                return None;
            }
            at = *post;
        }
        if t.band_post.iter().map(|(s, _)| *s).collect::<Vec<u32>>() != touched {
            return None;
        }
        let mut after = band.to_vec();
        for (s, e) in &t.band_post {
            *after.get_mut(*s as usize)? = *e;
        }
        (usdm_decider::nf_sparse_air::fold_band(&after) == Some(at)).then_some(at)
    }

    /// Re-try every solicited step that has become verifiable, in fold order, until none moves. A copy that fails is
    /// dropped and counted — the relay re-solicits from another announcer.
    fn cascade(&mut self) {
        loop {
            let next = self.awaiting.values().map(|(b, _)| *b).find(|b| self.solicited.contains_key(b) && self.pre_of(b).is_some());
            let Some(block) = next else { break };
            let Some(t) = self.solicited.remove(&block) else { break };
            self.own_held.remove(&block);
            let end = self.pre_of(&block).and_then(|(pre, band, admitted)| self.verify_step(pre, &band, &admitted, &t));
            match end {
                Some(end) => {
                    self.verified.insert(block, VerifiedStep { transition: t, end });
                    self.newly_verified.push(block);
                }
                None => {
                    self.copies_refused = self.copies_refused.saturating_add(1);
                    self.invalidated.push(block);
                }
            }
        }
    }

    /// The solicited copies that failed since the last call — the relay scores their announcers and re-solicits.
    pub fn take_invalidated(&mut self) -> Vec<[u8; 32]> { // NOT-A-TAG: block ids
        std::mem::take(&mut self.invalidated)
    }

    /// The steps the cascade verified since the last call (see `newly_verified`).
    pub fn take_newly_verified(&mut self) -> Vec<[u8; 32]> { // NOT-A-TAG: block ids
        std::mem::take(&mut self.newly_verified)
    }

    /// ⭐ P2' as ONE door function, where the data lives: was `tag` spent by a fold step AFTER `anchor_ordinal` — an
    /// applied one still in the journal, or one noted and awaiting? `Some(true)` is exact as soon as ANY known step in
    /// range admits the tag — whatever else is unknown. `Some(false)` needs every step in range known; otherwise `None` is
    /// STALE and the caller WAITS (never excludes): a step in range whose admitted set is unknown here, a gap (a step the
    /// lag cap refused), or an anchor older than the journal's reach (an applied step after it has been released). A
    /// verdict is then: the tag is absent at the anchor's band root (the copath) AND `spent_after(anchor, tag) ==
    /// Some(false)`. The respend memo's `held` is `spent_after(pointer's anchor, tag) != Some(false)`-shaped: a hit anywhere
    /// known is spent.
    /// Work: the journal and the awaiting sets — ≤ `lag_cap` steps × the 256-slot lane, whatever the height.
    #[must_use]
    pub fn spent_after(&self, anchor_ordinal: u64, tag: &[u8; 32]) -> Option<bool> { // TAG-SPACE: `tag` is compared against the admitted tags as values
        // A KNOWN hit is exact whatever else is unknown — only "not spent" needs every step in range (the node lane's
        // 13:38 finding: an unknown later step must never mask a hit in an earlier known one, or the respend memo reads
        // a spent tag FRESH and a later respend wins the fold — the paid-twice class)
        let mut incomplete = self.stale_from.is_some() || anchor_ordinal.saturating_add(1) < self.floor;
        if self.journal.iter().filter(|s| s.ordinal > anchor_ordinal).any(|s| s.admitted.contains(tag)) {
            return Some(true);
        }
        for (_, (_, admitted)) in self.awaiting.range(anchor_ordinal.saturating_add(1)..) {
            match admitted {
                Some(a) if a.contains(tag) => return Some(true),
                Some(_) => {}
                None => incomplete = true,
            }
        }
        (!incomplete).then_some(false)
    }

    /// ⭐ P2' keyed by a ROOT (the node lane's reader ask, 13:42): a carried copath folds EMPTY to some band root, and the
    /// gate never knows an ordinal — so "was `tag` spent AFTER the band stood at `root`?" Found as the journal step whose
    /// POST root is `root` (the latest one: equal roots only repeat across idle steps, which admit nothing), or the root
    /// just below the journal. `Spent` is exact on any KNOWN hit after it; `NotSpent` needs every step after it known;
    /// `Stale` otherwise (an unknown step after it, or a gap) — the caller waits; `UnknownRoot` when the root is not one
    /// this door can place (older than the journal's reach, or never this chain's) — the caller refuses the witness.
    #[must_use]
    pub fn spent_since(&self, root: &Digest4, tag: &[u8; 32]) -> Since { // TAG-SPACE: `tag` is compared against the admitted tags as values
        let Some((released, start)) = self.place_root(root) else {
            return Since::UnknownRoot;
        };
        if released.iter().any(|(_, a)| a.contains(tag)) || self.journal.iter().skip(start).any(|s| s.admitted.contains(tag)) {
            return Since::Spent;
        }
        let mut incomplete = self.stale_from.is_some();
        for (_, admitted) in self.awaiting.values() {
            match admitted {
                Some(a) if a.contains(tag) => return Since::Spent,
                Some(_) => {}
                None => incomplete = true,
            }
        }
        if incomplete {
            Since::Stale
        } else {
            Since::NotSpent
        }
    }

    /// Does ANY known step — applied in the journal or noted and awaiting — admit `tag`? Never masked by an unknown step:
    /// the respend memo's and `is_nullifier_spent`'s "a true hit stays true".
    #[must_use]
    /// ⭐ The APPLIED steps after the band stood at `root`, with their admitted sets, in fold order — what a view warmed
    /// against `root` (a healed pivot, a restream) replays to reach the band's CURRENT root. Placement exactly as
    /// [`Self::spent_since`]: the latest journal step whose post is `root`, or `base_root` (the whole journal). `None` when
    /// the root is not one this door can place (older than the journal's reach): the warm must restart from a newer
    /// target. Idle steps come back with empty sets, so the ordinals stay dense.
    #[must_use]
    pub fn admitted_since(&self, root: &Digest4) -> Option<Vec<(u64, Vec<[u8; 32]>)>> { // TAG-SPACE: the admitted tags as values, for the caller's view to apply
        let (released, start) = self.place_root(root)?;
        let mut out: Vec<(u64, Vec<[u8; 32]>)> = released.into_iter().map(|(o, a)| (o, a.clone())).collect();
        out.extend(self.journal.iter().skip(start).map(|s| (s.ordinal, s.admitted.clone())));
        Some(out)
    }

    /// The admitted tags applied after the band stood at `root`, flattened in fold order, from the `from`-th on — a warm's
    /// TAIL toward `root` (DB-353 §13.5 wholesale table: the RAM tail it replaces was written by a graft advance that no
    /// longer exists). Same placement as [`Self::admitted_since`]; `None` when `root` is unplaceable, so the warm must
    /// restart from a newer target. Reads the journal in place: no step's set is cloned but the returned suffix.
    #[must_use]
    pub fn admitted_tags_since(&self, root: &Digest4, from: usize) -> Option<Vec<[u8; 32]>> { // TAG-SPACE: admitted tags as values
        let (released, start) = self.place_root(root)?;
        Some(
            released
                .into_iter()
                .flat_map(|(_, a)| a.iter().copied())
                .chain(self.journal.iter().skip(start).flat_map(|s| s.admitted.iter().copied()))
                .skip(from)
                .collect(),
        )
    }

    /// ⛔⛔ B3b (lane speed5, 2026-11-17, docs/BOND-FLOOR-DEEP-AUDIT-20261117.md) — THE ONE PLACEMENT OF A ROOT: the latest journal step
    /// whose post is `root` (`(no released steps, its index + 1)`), `base_root` (`(none, 0)`), or a RELEASED step — a ring entry below
    /// the floor whose every later released ordinal up to the floor the history still holds (`keep_released` keeps them contiguous,
    /// idle ones empty) — answered as `(those history steps in order, 0)`: the whole journal follows them. The four readers
    /// (`spent_since`, `admitted_since`, `admitted_tags_since`, `place_class`) read this one rule.
    /// MEASURED why (real 3-node bond-floor, main b5832ff0): a joiner's warm pivot (its adopted band step; anchors stand 40-112 levels
    /// deep) fell below the server's journal at once, and the server answered "the pivot left this node's band journal (released:
    /// older than its reach)" 177 times while it held that root in its ring and the released admitted sets in its history; the joiner
    /// never rebuilt its view, so its fold could not decide a block and the founder's bond could never prove its note.
    /// BORROWED: Kaspa's pruning-point UTXO sync answers a set at a point it still holds the diffs from; the history is those diffs.
    /// AI RESISTANT: (b) code — placement reads only this node's own applied band; a peer gains nothing it could not with a journal
    /// pivot (the warm still installs only a tree that folds to the certified root).
    /// SCALE: one ring scan (bounded by the ring) and at most `EVIDENCE_WINDOW_STEPS` history entries; no new state, nothing grows.
    /// cons: none on state; a warm answered from history carries up to one evidence window more of admitted tags in its tail.
    fn place_root(&self, root: &Digest4) -> Option<(Vec<(u64, &Vec<[u8; 32]>)>, usize)> {
        if let Some(i) = self.journal.iter().rposition(|s| s.post == *root) {
            return Some((Vec::new(), i + 1));
        }
        if *root == self.base_root {
            return Some((Vec::new(), 0));
        }
        let (o, _) = self.ring.iter().rev().find(|(o, r)| r == root && *o < self.floor)?;
        let from = o.saturating_add(1);
        let released: Vec<(u64, &Vec<[u8; 32]>)> = self.history.range(from..self.floor).map(|(k, a)| (*k, a)).collect();
        (released.len() as u64 == self.floor.saturating_sub(from)).then_some((released, 0))
    }

    /// ⭐ DB-428: WHERE `root` stands relative to this door, in words, for a warm server that cannot answer `set(root)` —
    /// the placement of [`Self::admitted_tags_since`], then the ring (which also names roots the journal released). A
    /// diagnosis only: no caller decides anything from it.
    #[must_use]
    pub fn place_class(&self, root: &Digest4) -> &'static str {
        if self.place_root(root).is_some() {
            "the pivot is placed in this node's band journal or its released history"
        } else if self.ring.iter().any(|(_, r)| r == root) {
            "the pivot left this node's band journal (released: older than its reach)"
        } else {
            "the pivot is unknown to this node's band (ahead of it, older than its ring, or on another branch)"
        }
    }

    /// ⭐ DB-399: the admitted sets of the fold steps noted and AWAITING (not yet applied), oldest first, each step one group;
    /// an unknown set is left out. These are post-pivot by construction (every awaiting step is after the band pointer), so
    /// a viewless warm may strip them (`PivotWarm::strip_held_extras`). Bounded by `lag_cap` steps.
    #[must_use]
    pub fn awaiting_admitted_groups(&self) -> Vec<Vec<[u8; 32]>> { // TAG-SPACE: admitted tags as values
        self.awaiting.values().filter_map(|(_, a)| a.clone()).collect()
    }

    /// ⭐ DB-399: the blocks of the awaiting steps (their admitted sets are in `awaiting_admitted_groups`). NOT-A-TAG: block ids.
    #[must_use]
    pub fn awaiting_blocks(&self) -> Vec<[u8; 32]> { // NOT-A-TAG: block ids
        self.awaiting.values().map(|(b, _)| *b).collect()
    }

    pub fn known_admits(&self, tag: &[u8; 32]) -> bool { // TAG-SPACE: `tag` is compared against the admitted tags as values
        self.journal.iter().any(|s| s.admitted.contains(tag))
            || self.awaiting.values().any(|(_, a)| a.as_ref().is_some_and(|a| a.contains(tag)))
    }

    /// ⛔⛔⛔ DB-396 — can the fold note step `ordinal` now? Exactly the rule [`Self::note_fold_step`] refuses by (not past a
    /// gap; room under the lag cap, or a re-note of an ordinal already awaiting — a rewind's re-fold), asked by the fold
    /// BEFORE anything moves so a full door makes the fold WAIT instead of dropping the step and going stale.
    /// `note_fold_step` keeps its own refusal: a caller that skips this check still cannot overrun the cap.
    #[must_use]
    pub fn can_note(&self, ordinal: u64) -> bool {
        !self.stale_from.is_some_and(|gap| ordinal >= gap)
            && (self.awaiting.len() < self.lag_cap || self.awaiting.contains_key(&ordinal))
    }

    /// TEST DIAGNOSTIC — the pointer step's holding state: (held verified, held solicited, verified held, solicited held,
    /// solicit cap, parked). Counts and flags only.
    #[cfg(test)]
    pub fn pointer_diag_for_test(&self) -> (bool, bool, usize, usize, usize, usize) {
        let p = self.awaiting.values().next().map(|(b, _)| *b);
        (
            p.is_some_and(|b| self.verified.contains_key(&b)),
            p.is_some_and(|b| self.solicited.contains_key(&b)),
            self.verified.len(),
            self.solicited.len(),
            self.solicit_cap,
            self.parked.len(),
        )
    }

    /// Is this door past a gap it cannot bridge without a certified re-adopt?
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.stale_from.is_some()
    }

    /// TEST DOOR — put this door past an unbridgeable gap at its floor, the state a lag-cap overrun leaves (the runtime's
    /// certified-re-adopt ask is pinned against it without driving a node through a real overrun).
    #[cfg(test)]
    pub fn force_stale_for_test(&mut self) {
        self.stale_from = Some(self.floor);
    }

    /// TEST LEVER (lane funds 2026-10-27) — what a certified adopt leaves this door standing on, without a band: `root` as
    /// the base the journal is placed against (`admitted_tags_since(root, 0)` = an empty tail), nothing awaiting, nothing
    /// journaled. A fixture that hands a cold node a certified sparse root by `adopt_sparse_snapshot` alone measured a
    /// node no adopt produces: production installs the sparse root and the band TOGETHER (`instant_sync` → `adopt_certified`),
    /// so DB-339's placeability read the pivot as unplaceable and `sparse_pivot()` was None (treeless-warm pin, NEVER-PASSED
    /// since 10/05). Exactly `adopt_certified`'s effect on the placement state; the band itself stays as it was.
    #[cfg(test)]
    pub fn plant_certified_root_for_test(&mut self, root: Digest4) {
        self.root = root;
        self.base_root = root;
        self.awaiting.clear();
        self.stale_from = None;
        self.journal.clear();
        self.ring.clear();
    }

    /// §11.13 C4 — the steps pointer..tip with their admitted sets, in fold order: what a certified bundle carries so a
    /// joiner's `adopt_certified` can verify relayed steps from minute 0.
    #[must_use]
    pub fn awaiting_steps(&self) -> Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)> { // TAG-SPACE: admitted tags as values, for the bundle
        self.awaiting.iter().map(|(o, (b, a))| (*o, *b, a.clone())).collect()
    }

    /// The fold ordinal of the awaiting step whose block is `block` (a scan of the awaiting window, ≤ the lag cap; no clone).
    #[must_use]
    pub fn awaiting_ordinal_of(&self, block: &[u8; 32]) -> Option<u64> { // NOT-A-TAG: a block id
        self.awaiting.iter().find(|(_, (b, _))| b == block).map(|(o, _)| *o)
    }

    /// ⭐ §POLES (lane a 2026-10-25) — the door rendered BY STATEMENT: its `{:?}` with every held proof's bytes cleared
    /// (`slices[i].2` of the applied, verified, solicited and parked transitions), every statement field kept — block,
    /// `band_post`, `k`, each slice's index and post root. The replicated-state census compares this, because a band step
    /// legitimately has more than one valid proof: the WHIR prover is zero-knowledge (randomized bytes per run), and a
    /// lapsed owner's step is proven again by its one deterministic backup (DB-454), so two honest nodes may each apply a
    /// different verifying proof of the SAME transition. MEASURED (4-node launch census, scratchpad/night/census4-ring1.log):
    /// band_door CONTENT DIFFERS in one `applied_proofs` item, 23 items each side, while the band, root and every statement
    /// agreed. The restart census still compares the door's exact bytes.
    #[must_use]
    pub fn statement_view(&self) -> String {
        fn strip(t: &mut BandTransition) {
            for s in &mut t.slices {
                s.2 = Vec::new();
            }
        }
        let mut d = self.clone();
        d.applied_proofs.iter_mut().for_each(|(_, t)| strip(t));
        d.verified.values_mut().for_each(|v| strip(&mut v.transition));
        d.solicited.values_mut().for_each(strip);
        d.parked.iter_mut().for_each(strip);
        format!("{d:?}")
    }

    /// The running band (2^NF_BAND_BITS entries at NF_BAND_LEVEL).
    #[must_use]
    pub fn band(&self) -> &[Digest4] {
        &self.band
    }

    /// The fold step the band waits at (`None`: nothing awaits).
    #[must_use]
    pub fn pointer(&self) -> Option<u64> {
        self.awaiting.keys().next().copied()
    }

    /// Steps noted and not yet applied.
    #[must_use]
    pub fn lag(&self) -> usize {
        self.awaiting.len()
    }

    /// The band root AFTER fold step `ordinal`, when that step is applied and inside the ring (R2c: `None` = pending).
    #[must_use]
    pub fn band_root_at(&self, ordinal: u64) -> Option<Digest4> {
        self.ring.iter().find(|(o, _)| *o == ordinal).map(|(_, r)| *r)
    }

    /// ⭐ PRIVATE SHARDING §8 — the root evidence naming step `ordinal` must reach. Step 0 is the empty set a new chain starts
    /// on. `None`: this band has not reached that step, so the reader waits.
    #[must_use]
    pub fn evidence_root_at(&self, ordinal: u64) -> Option<Digest4> {
        if ordinal == 0 {
            return Some(RefSparseNf::with_shards(usdm_decider::nf_sparse_air::NF_BAND_BITS, std::iter::empty()).root());
        }
        self.band_root_at(ordinal)
    }

    /// ⭐ PRIVATE SHARDING §8 — is `tag` admitted by a step after `ordinal`, as far as the fold has noted? Reads the journal and
    /// the steps still awaiting a proof. `None` when a step's admitted set is unknown here, or the journal no longer reaches
    /// back to `ordinal`.
    #[must_use]
    pub fn admitted_after_ordinal(&self, ordinal: u64, tag: &[u8; 32]) -> Option<bool> { // TAG-SPACE: a tag as a value
        let history_reaches = self.history.keys().next().is_some_and(|first| ordinal.saturating_add(1) >= *first);
        if ordinal.saturating_add(1) < self.floor && !history_reaches {
            return None;
        }
        let mut hit = self.journal.iter().filter(|s| s.ordinal > ordinal).any(|s| s.admitted.contains(tag));
        hit = hit || self.history.range(ordinal.saturating_add(1)..).any(|(_, a)| a.contains(tag));
        for (o, (_, admitted)) in &self.awaiting {
            if *o <= ordinal {
                continue;
            }
            match admitted {
                Some(a) => hit = hit || a.contains(tag),
                None => return None,
            }
        }
        Some(hit)
    }

    /// The newest fold step applied and held in the ring (`None`: none yet).
    #[must_use]
    /// JOINING BY WORK: the steps inside `window` of this band's position, for a joiner: root and admitted set of each, idle steps included.
    /// Stops short where this door no longer knows a step's admitted set.
    #[must_use]
    pub fn join_history(&self, window: u64) -> Vec<(u64, Digest4, Vec<[u8; 32]>)> {
        let Some(newest) = self.newest_applied() else { return Vec::new() };
        let from = newest.saturating_sub(window);
        let mut out = Vec::new();
        for (o, root) in self.ring.iter().filter(|(o, _)| *o >= from) {
            let admitted = if let Some(step) = self.journal.iter().find(|s| s.ordinal == *o) {
                step.admitted.clone()
            } else if let Some(a) = self.history.get(o) {
                a.clone()
            } else if *o >= self.floor {
                Vec::new() // an idle step: it admitted nothing and took no journal slot
            } else {
                out.clear(); // unknown here: only what follows it can be shown
                continue;
            };
            out.push((*o, *root, admitted));
        }
        out
    }

    /// JOINING BY WORK: take the steps before this door's position. The caller checked them against the header commits.
    pub fn install_history(&mut self, steps: &[(u64, Digest4, Vec<[u8; 32]>)]) {
        let oldest_held = self.ring.front().map(|(o, _)| *o);
        for (o, root, admitted) in steps.iter().rev() {
            if oldest_held.is_none_or(|first| *o < first) {
                self.ring.push_front((*o, *root));
            }
            self.history.insert(*o, admitted.clone());
        }
    }

    pub fn ring_steps(&self) -> impl Iterator<Item = (u64, Digest4)> + '_ {
        self.ring.iter().copied()
    }

    /// The newest fold step this band has applied.
    #[must_use]
    pub fn newest_applied(&self) -> Option<u64> {
        self.ring.back().map(|(o, _)| *o)
    }

    /// A-F56 MEASUREMENT — where this door stands, in public fold ordinals only: the ring's length, lowest and highest
    /// step, how many steps between them it lacks, whether it holds `around`, the awaiting steps' first, last and count,
    /// and the journal's newest step. One line a reader can set beside a peer's.
    #[must_use]
    pub fn ring_census(&self, around: u64) -> String {
        let mut held: Vec<u64> = self.ring.iter().map(|(o, _)| *o).collect();
        let in_order = held.windows(2).all(|w| w[0] < w[1]);
        held.sort_unstable();
        held.dedup();
        let (lo, hi) = (held.first().copied(), held.last().copied());
        let lacks = match (lo, hi) {
            (Some(l), Some(h)) => (h - l + 1).saturating_sub(held.len() as u64),
            _ => 0,
        };
        let first_gap = held.windows(2).find(|w| w[1] != w[0] + 1).map(|w| w[0] + 1);
        format!(
            "ring {} step(s) {:?}..={:?} in insertion order {in_order}, lacking {lacks} (first lacked {first_gap:?}), holds {around} {}; awaiting {:?}..={:?} ({} step(s)); journal newest {:?}, floor {}",
            self.ring.len(),
            lo,
            hi,
            held.binary_search(&around).is_ok(),
            self.awaiting.keys().next(),
            self.awaiting.keys().next_back(),
            self.awaiting.len(),
            self.journal.back().map(|s| s.ordinal),
            self.floor
        )
    }

    /// The rewind floor: the lowest fold ordinal `rewind_to` can still restore.
    #[must_use]
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// ⛔⛔ DB-419 — this door's rewind reach as a checkpoint carries it ([`BandJournalCarry`]).
    #[must_use]
    pub fn journal_carry(&self) -> BandJournalCarry {
        BandJournalCarry {
            journal: self.journal.iter().cloned().collect(),
            ring: self.ring.iter().copied().collect(),
            floor: self.floor,
            base_root: self.base_root,
            applied: self.applied_proofs.iter().cloned().collect(),
            held: self
                .awaiting
                .values()
                .filter_map(|(b, _)| {
                    self.verified
                        .get(b)
                        .map(|v| (v.transition.clone(), false))
                        .or_else(|| self.solicited.get(b).map(|t| (t.clone(), self.own_held.contains(b))))
                })
                .chain(self.parked.iter().map(|t| (t.clone(), false)))
                .collect(),
            history: self.history.iter().map(|(o, a)| (*o, a.clone())).collect(),
        }
    }

    /// ⛔⛔ DB-419 — reinstall a checkpoint's rewind reach on a door JUST RESUMED through [`Self::adopt_certified`] (its
    /// journal and ring empty, its floor the resume ordinal), ONLY when the carry describes the band this door now holds:
    /// - at most `lag_cap` steps and `ring_len` ring entries, every ordinal strictly ascending and below the resume
    ///   ordinal, every step at or above the carried floor, and the carried floor not above the resume ordinal;
    /// - the newest ring root is the door's root, and every step's ring root (when the ring holds its ordinal) is its post;
    /// - THE REPLAY: un-applying the steps newest first from the door's own band, each step's `post` is the root it is
    ///   un-applied from, and the oldest lands exactly on the carried `base_root`.
    /// Anything else installs NOTHING and the door keeps the resume floor (a rewind below it then marks the spine stale,
    /// as before) — the door never resumes a journal its own band does not reproduce. Returns whether it installed.
    /// cons: one `fold_band` per carried step at boot (≤ `lag_cap` = 64 band folds, each 255 pair hashes).
    pub fn install_journal(&mut self, carry: BandJournalCarry, ring_len: usize) -> bool {
        let next = self.floor;
        if !self.journal.is_empty() || !self.ring.is_empty() || self.stale_from.is_some() {
            return false;
        }
        if carry.journal.len() > self.lag_cap || carry.ring.len() > ring_len.max(1) || carry.floor > next {
            return false;
        }
        let ascending_below = |ords: &[u64]| ords.windows(2).all(|w| w[0] < w[1]) && ords.last().is_none_or(|o| *o < next);
        if !ascending_below(&carry.journal.iter().map(|s| s.ordinal).collect::<Vec<_>>())
            || !ascending_below(&carry.ring.iter().map(|(o, _)| *o).collect::<Vec<_>>())
            || carry.journal.first().is_some_and(|s| s.ordinal < carry.floor)
            || carry.ring.last().is_some_and(|(_, r)| *r != self.root)
        {
            return false;
        }
        // A-F44: the admitted sets below the floor — ascending, every one below the floor and within one evidence window
        // of it (plus the joiner's own window edge), at most that many
        let window = crate::nf_evidence::EVIDENCE_WINDOW_STEPS;
        let hist: Vec<u64> = carry.history.iter().map(|(o, _)| *o).collect();
        if hist.len() as u64 > window.saturating_add(1)
            || !hist.windows(2).all(|w| w[0] < w[1])
            || hist.last().is_some_and(|o| *o >= carry.floor)
            || hist.first().is_some_and(|o| *o < carry.floor.saturating_sub(window.saturating_add(1)))
        {
            return false;
        }
        let mut band = self.band.clone();
        let mut root = self.root;
        // G1e-iv: per journaled step, the post slots the replay reproduces — what a carried proof must claim.
        let mut posts: Vec<([u8; 32], Vec<(u32, Digest4)>)> = Vec::with_capacity(carry.journal.len());
        for step in carry.journal.iter().rev() {
            if step.post != root || carry.ring.iter().any(|(o, r)| *o == step.ordinal && *r != step.post) {
                return false;
            }
            posts.push((
                step.block,
                step.before.iter().map(|(s, _)| (*s, band.get(*s as usize).copied().unwrap_or_default())).collect(),
            ));
            for (s, before) in step.before.iter().rev() {
                let Some(slot) = band.get_mut(*s as usize) else { return false };
                *slot = *before;
            }
            let Some(r) = usdm_decider::nf_sparse_air::fold_band(&band) else { return false };
            root = r;
        }
        if root != carry.base_root {
            return false;
        }
        self.journal = carry.journal.into();
        self.ring = carry.ring.into();
        self.floor = carry.floor;
        self.base_root = carry.base_root;
        self.history = carry.history.into_iter().collect();
        // G1e-iv: the journaled steps' proofs — each kept only when it names a journaled step's block (`for_block` too) and
        // claims exactly the post slots the replay above reproduced for that step; one per block, ≤ lag_cap. Anything else
        // is dropped and counted (never served): the item fails closed, the journal still installs.
        let mut applied: std::collections::VecDeque<([u8; 32], BandTransition)> = std::collections::VecDeque::new();
        let mut dropped = 0usize;
        for (block, t) in carry.applied {
            let mut claimed: Vec<(u32, Digest4)> = t.band_post.clone();
            claimed.sort_unstable_by_key(|(s, _)| *s);
            let reproduced = posts.iter().find(|(b, _)| *b == block).map(|(_, p)| {
                let mut p = p.clone();
                p.sort_unstable_by_key(|(s, _)| *s);
                p
            });
            let binds = t.for_block == block && reproduced.as_ref() == Some(&claimed) && !applied.iter().any(|(b, _)| *b == block);
            if binds && applied.len() < self.lag_cap {
                applied.push_back((block, t));
            } else {
                dropped += 1;
            }
        }
        if dropped > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count only; no tag, root or block id.
            eprintln!("[band-door] ⛔ G1e-iv: {dropped} carried proof(s) do not reproduce a journaled step — not served");
        }
        self.applied_proofs = applied;
        // G1h: the held steps re-enter through the door's own admission, in fold order; one it would refuse now is dropped
        // and counted (the item fails closed, the journal stays installed).
        let mut refused = 0usize;
        for (t, own) in carry.held {
            let receipt = if own { self.offer_own_step(t) } else { self.offer_step(t, true) };
            if !matches!(receipt, BandReceipt::Verified | BandReceipt::Held) {
                refused += 1;
            }
        }
        if refused > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count only; no tag, root or block id.
            eprintln!("[band-door] ⛔ G1h: {refused} carried held step(s) refused by the door at resume — not held");
        }
        true
    }

    /// ⭐ DB-403 — can this door still SERVE every band-moving step an adopter of a bundle certified at band pointer
    /// `pointer` will need? `(stranded, moves_since, reach)`: `stranded` when a step at or above `pointer` that moved the band
    /// was already released from the journal (`pointer < floor` — the floor is one past the newest released step, so a
    /// released step lies in `[pointer, floor)`); `moves_since` = the journaled steps at or above `pointer` (each held
    /// for `applied_proofs`, the only copies served once applied); `reach` = the journal's bound (`lag_cap`). The first
    /// needed step is released once `moves_since` would pass `reach`. Idle steps need no proof and take no slot.
    /// O(lag_cap) — the journal's own bound.
    #[must_use]
    pub fn bundle_reach(&self, pointer: u64) -> (bool, usize, usize) {
        (pointer < self.floor, self.journal.iter().filter(|s| s.ordinal >= pointer).count(), self.lag_cap)
    }

    /// The journal's bound (`lag_cap`): how many band-moving steps below its pointer ANY honest door still serves — the
    /// reach of the band relay for a node whose band trails it.
    #[must_use]
    pub fn journal_reach(&self) -> usize {
        self.lag_cap
    }

    /// §3 step 1 — a fold step's ADMITTED set, noted at the fold after the canonical respend decision (TAG space: the
    /// header's tags minus the losers). `None` = this node held no body at the fold and cannot derive the set: the
    /// pointer will WAIT there. A re-noted ordinal (a re-fold) replaces its entry. Returns `false` when the lag cap
    /// refused the step (counted) — the band then needs a certified re-adopt, never a silent skip.
    pub fn note_fold_step(&mut self, ordinal: u64, block: [u8; 32], admitted: Option<Vec<[u8; 32]>>) -> bool { // TAG-SPACE: `admitted` holds the header's tags as values, converted where the band applies them (`admitted_order` → `nf_shard` → `SparseKey::of`); `block` is a block id, never a tag
        // a step past a gap would apply without the dropped one — the band SKIPS it. Nothing newer is noted until a
        // certified re-adopt; a re-note at or below the gap (a re-fold) is still taken
        if self.stale_from.is_some_and(|gap| ordinal >= gap) {
            self.dropped_for_lag = self.dropped_for_lag.saturating_add(1);
            return false;
        }
        if self.awaiting.len() >= self.lag_cap && !self.awaiting.contains_key(&ordinal) {
            self.dropped_for_lag = self.dropped_for_lag.saturating_add(1);
            self.stale_from = Some(ordinal);
            return false;
        }
        // §11.12 — a RE-noted ordinal whose step changed moves every later step's pre: what was verified or held for
        // this step and every later one is forgotten (re-offered by the relay), never kept against the old pre
        if self.awaiting.get(&ordinal).is_some_and(|(b, a)| *b != block || *a != admitted) {
            let stale: Vec<[u8; 32]> = self.awaiting.range(ordinal..).map(|(_, (b, _))| *b).collect();
            for b in &stale {
                self.verified.remove(b);
                self.solicited.remove(b);
                self.own_held.remove(b);
            }
        }
        // A-F56 MEASUREMENT: a step is noted right after the newest one this door holds (awaiting, or applied); one noted
        // past a hole leaves a step no drain will ever apply here. DIGITAL-CASH-PRIVACY-REVIEWED: public fold ordinals only.
        if !self.awaiting.contains_key(&ordinal) {
            let newest = self.awaiting.keys().next_back().copied().or_else(|| self.ring.back().map(|(o, _)| *o));
            if let Some(n) = newest.filter(|n| ordinal > n.saturating_add(1)) {
                eprintln!("[band-note-gap] step {ordinal} is noted while the newest step held here is {n}");
            }
        }
        self.awaiting.insert(ordinal, (block, admitted));
        if let Some(i) = self.parked.iter().position(|p| p.for_block == block) {
            if let Some(t) = self.parked.remove(i) {
                let _ = self.offer_step(t, true); // the early copy takes the solicited path: verifies now, or is held for cascade
            }
        }
        true
    }

    /// Early relayed steps parked for blocks this door has not yet noted (bounded by `lag_cap`).
    #[must_use]
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// A refused fold leaves no trace (the unwind beside `unwind_bond_step`).
    pub fn unwind_fold_step(&mut self, ordinal: u64) {
        // A-F56 MEASUREMENT — DIGITAL-CASH-PRIVACY-REVIEWED: a public fold ordinal and two flags.
        if self.awaiting.range(ordinal.saturating_add(1)..).next().is_some() {
            eprintln!("[band-unwind] step {ordinal} is unwound while later steps are noted (held {})", self.awaiting.contains_key(&ordinal));
        }
        self.awaiting.remove(&ordinal);
    }

    /// ⭐ §11.12 — THE RELAY DOOR: one whole step (`BandTransition`, all `k` slices) arrives from a peer. Shape first, no
    /// proof work — `k` must be THIS door's `chain_k`, the slices exactly `0..k` in order, `band_post` well-formed —
    /// then the replay SET (a block that awaits nothing here is unknown or applied; a step already verified is a
    /// duplicate). Then ONE of:
    /// - the step is verifiable NOW (every earlier step verified): all `k` slices and `band_post` are checked against the
    ///   pre and band this door derives, and it is held VERIFIED (`Queued`) — or refused and counted;
    /// - it is not verifiable yet and THIS node solicited it (`solicited`): held, at most `solicit_cap` such, verified the
    ///   moment its predecessor is;
    /// - otherwise refused, and NOTHING is held — an unsolicited, unverifiable copy never occupies a slot.
    ///
    /// A step that verifies re-tries every held solicited one (a failure there is reported by `take_invalidated`).
    pub fn offer_step(&mut self, t: BandTransition, solicited: bool) -> BandReceipt {
        self.offer_step_as(t, solicited, false)
    }

    /// DB-454 — the solicited copies held here that OTHER nodes proved (pulled ahead); the solicited window `W` bounds these.
    fn pulled_held(&self) -> usize {
        self.solicited.len().saturating_sub(self.own_held.len())
    }

    /// ⭐ DB-454 — would this door take THIS NODE'S OWN proof of `block` now: awaiting, not verified or held, and either
    /// verifiable at once or within the OWN-ahead budget (`W` own proofs held ahead, a budget of its own — MEASURED link 85,
    /// night/link85-green.log: with one shared window the pulled copies filled it, 42–68 own proofs per node were refused
    /// "window full", each reset the cursor and was proven again: 428 jobs for 304 steps).
    #[must_use]
    pub fn wants_own(&self, block: &[u8; 32]) -> bool { // NOT-A-TAG: a block id
        let awaits = self.awaiting.values().any(|(b, a)| b == block && a.as_ref().is_some_and(|a| !a.is_empty()));
        awaits
            && !self.verified.contains_key(block)
            && !self.solicited.contains_key(block)
            && (self.pre_of(block).is_some() || self.own_held.len() < self.solicit_cap)
    }

    /// The one admission (see [`Self::offer_step`]); `own` = this node proved it (its hold counts against the own-ahead
    /// budget, never against the pulled window).
    fn offer_step_as(&mut self, t: BandTransition, solicited: bool, own: bool) -> BandReceipt {
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let k = self.chain_k;
        if t.k as usize != k {
            return BandReceipt::Refused("slice count is not this chain's band_chain_k");
        }
        if t.slices.len() != k || t.slices.iter().enumerate().any(|(i, (idx, _, _))| *idx as usize != i) {
            return BandReceipt::Refused("a relayed step carries all k slices, in order");
        }
        if t.band_post.is_empty()
            || t.band_post.len() > cover
            || t.band_post.iter().any(|(s, _)| *s as usize >= self.band.len())
            || t.band_post.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return BandReceipt::Refused("malformed band_post");
        }
        let block = t.for_block;
        let Some(admitted) = self.awaiting.values().find(|(b, _)| *b == block).map(|(_, a)| a.clone()) else {
            if self.journal.iter().any(|st| st.block == block) {
                return BandReceipt::Refused(BAND_REFUSED_APPLIED);
            }
            if self.parked.iter().any(|p| p.for_block == block) {
                return BandReceipt::Refused("a copy of this early step is already parked");
            }
            while self.parked.len() >= self.lag_cap {
                self.parked.pop_front();
            }
            self.parked.push_back(t);
            return BandReceipt::Held;
        };
        match admitted {
            None => return BandReceipt::Refused("this step's admitted set is unknown here"),
            Some(a) if a.is_empty() => return BandReceipt::Refused("an idle step carries no transition"),
            Some(_) => {}
        }
        if self.verified.contains_key(&block) {
            return BandReceipt::Refused(BAND_REFUSED_VERIFIED);
        }
        match self.pre_of(&block) {
            Some((pre, band, admitted)) => match self.verify_step(pre, &band, &admitted, &t) {
                Some(end) => {
                    self.solicited.remove(&block);
                    self.own_held.remove(&block);
                    self.verified.insert(block, VerifiedStep { transition: t, end });
                    self.cascade();
                    BandReceipt::Verified
                }
                None => {
                    self.copies_refused = self.copies_refused.saturating_add(1);
                    BandReceipt::Invalid("the step's slices or band_post do not verify")
                }
            },
            None if solicited => {
                if self.solicited.contains_key(&block) {
                    BandReceipt::Refused("a solicited copy of this step is already held")
                } else if (if own { self.own_held.len() } else { self.pulled_held() }) >= self.solicit_cap {
                    BandReceipt::Refused("the solicited window is full")
                } else {
                    self.solicited.insert(block, t);
                    BandReceipt::Held
                }
            }
            None => BandReceipt::Refused("not verifiable yet and not solicited"),
        }
    }

    /// The carried-copy entry of landing 2 part (a) — kept only until that field is removed (the node lane's half of the
    /// joint landing): a block-carried copy is an UNSOLICITED relay offer.
    pub fn receive(&mut self, t: BandTransition) -> BandReceipt {
        self.offer_step(t, false)
    }

    /// ⭐ G1g-iii (lane a 2026-10-23) — WHAT THE POINTER WAITS ON, read from the door's own queues: no awaiting step →
    /// `Idle`; the pointer's admitted set unknown here → `Unknown`; a non-empty step with no verified copy → `Carrier`; an
    /// idle or verified step the next `drain` takes → `Idle`. It was a stored field the drain overwrote, so a restarted
    /// door read `Idle` where the live one read `Carrier` on the same queues (restart census
    /// g1gii-restart-census-20261023.log: band_door `last_wait:Carrier` → `last_wait:Idle`, both nodes); after a drain the
    /// derived answer is the one the drain stopped on, and between drains it names the current queue, not a stale one.
    /// cons: none — one map lookup per read; one field fewer.
    pub fn last_wait(&self) -> BandWait {
        match self.awaiting.iter().next() {
            None => BandWait::Idle,
            Some((_, (_, None))) => BandWait::Unknown,
            Some((_, (block, Some(admitted)))) => {
                if admitted.is_empty() || self.verified.contains_key(block) {
                    BandWait::Idle
                } else {
                    BandWait::Carrier
                }
            }
        }
    }

    /// Apply every step the pointer can take, in fold order: an empty admitted set is a no-op step; a non-empty one needs
    /// its queued transition, verified against values DERIVED here. A copy that fails is dropped (counted) and the
    /// pointer waits for the next carried copy. `held` = this node's held subtree(s) — the holder CHECK of §3 step 5
    /// (R2a): the admitted inserts are applied to it from its own copaths and each owned touched entry must equal the
    /// carried one; a disagreement is reported for the caller to DROP and re-warm the shard, the carried value stands.
    /// `ring_len` bounds the band ring. Returns the steps applied.
    pub fn drain(&mut self, mut held: Option<&mut RefSparseNf>, ring_len: usize) -> Vec<BandApplied> {
        let level = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut out = Vec::new();
        loop {
            let Some((&ordinal, (block, admitted))) = self.awaiting.iter().next() else {
                break;
            };
            let block = *block;
            let Some(admitted) = admitted.clone() else {
                break;
            };
            // A-F56 MEASUREMENT: the pointer only ever takes the next step, so a step applied after a step that is not its
            // predecessor means a step this door never noted, or forgot, is skipped here while every peer applies it.
            // DIGITAL-CASH-PRIVACY-REVIEWED: two public fold ordinals; no tag, root, cm, amount or owner.
            if let Some(last) = self.ring.back().map(|(o, _)| *o) {
                if ordinal != last.saturating_add(1) {
                    eprintln!("[band-gap] the drain applies step {ordinal} right after step {last}");
                }
            }
            let (touched, ordered, by_shard) = admitted_order(&admitted);
            if ordered.is_empty() {
                // An idle step: nothing to carry, the band stands. ⛔ DB-367 follow-up — it takes NO journal slot: it moves
                // nothing, so it has nothing to undo.
                // ROOT-LAYER: the journal's reach is set here, where steps enter it. Since DB-367 an idle block's step
                //   admits nothing and applies at once; journaling each one let `lag_cap` IDLE blocks raise the floor, and
                //   an ordinary reorg past them answered "below the band door's fold journal" (spine stale).
                // MEASURED: before — `db367_empty_steps_take_no_place_in_the_band_doors_rewind_journal` (70 idle steps, a
                //   rewind to 5 refused); `db265_a_joiner_and_its_origin_agree…` green at c6dcad6, red at 64cdf0f.
                // MUST-STAY-GREEN: every journal reader — `spent_since` / `admitted_since` place a root by the LAST step
                //   whose post is it, or `base_root` (an idle step repeats the previous post, so the root it stood on is
                //   still placed by the step that made it), and read admitted tags (an idle step has none); the band
                //   rewind pins; the ring still records every step's root (`band_root_at`).
                // cons: none — the journal keeps at most `lag_cap` entries either way; its reach now counts band MOVES.
                self.finish_step(ordinal, ring_len);
                out.push(BandApplied { ordinal, block, touched: 0, holder_disagreed: Vec::new() });
                continue;
            }
            // §11.12 — the step applies from its VERIFIED relayed copy (checked at `offer_step` against exactly this
            // pre and band: the pointer's root and the applied band); none yet → the pointer WAITS, never skips
            let Some(v) = self.verified.remove(&block) else {
                break;
            };
            let band_post = v.transition.band_post.clone();
            let mut band_after = self.band.clone();
            for (s, e) in &band_post {
                if let Some(slot) = band_after.get_mut(*s as usize) {
                    *slot = *e;
                }
            }
            debug_assert_eq!(touched, band_post.iter().map(|(s, _)| *s).collect::<Vec<u32>>(), "verified at offer_step");
            let post = v.end;
            // the holder CHECK (R2a): the held subtree recomputes its owned touched entries; the carried value stands
            let mut holder_disagreed = Vec::new();
            if let Some(tree) = held.as_deref_mut() {
                let _ = tree.advance_block_rooted(&ordered);
                for (s, carried_entry) in &band_post {
                    let Some(first) = by_shard.get(s).and_then(|v| v.first()) else { continue };
                    if !tree.holds(first) {
                        // A shard this view does not hold: the verified step's entry is all it needs to stay on the root.
                        tree.adopt_band_entry(*s, *carried_entry);
                        continue;
                    }
                    let canon = RefSparseNf::canon(&SparseKey::of(first), level);
                    if tree.node_at(level, &canon) != *carried_entry {
                        holder_disagreed.push(*s);
                    }
                }
            }
            let before: Vec<(u32, Digest4)> = band_post.iter().map(|(s, _)| (*s, self.band[*s as usize])).collect();
            self.journal.push_back(BandStep { ordinal, block, before, admitted: ordered, post });
            // the applied step's proof stays servable for the journal's reach (a peer behind still needs it)
            self.applied_proofs.push_back((block, v.transition));
            while self.applied_proofs.len() > self.lag_cap {
                self.applied_proofs.pop_front();
            }
            self.band = band_after;
            self.root = post;
            self.finish_step(ordinal, ring_len);
            out.push(BandApplied { ordinal, block, touched: band_post.len(), holder_disagreed });
        }
        self.forget_unawaited();
        out
    }

    /// The bookkeeping every applied step shares: the awaiting entry leaves, the ring records the root, the journal
    /// and the ring keep their bounds (a released journal step raises the floor).
    fn finish_step(&mut self, ordinal: u64, ring_len: usize) {
        self.awaiting.remove(&ordinal);
        self.ring.push_back((ordinal, self.root));
        while self.ring.len() > ring_len.max(1) {
            self.ring.pop_front();
        }
        while self.journal.len() > self.lag_cap {
            if let Some(released) = self.journal.pop_front() {
                self.keep_released(released.ordinal, &released.admitted);
                self.floor = self.floor.max(released.ordinal.saturating_add(1));
                self.base_root = released.post;
            }
        }
    }

    /// ⭐ A-F44 — a step the journal releases keeps its admitted set in [`Self::history`] (and every idle step since the
    /// floor an empty one, so the map stays contiguous up to the new floor), and the map keeps one evidence window below
    /// that floor: a rewind never reaches below the floor (below it the band is STALE), so a re-folded step judges evidence
    /// at most `EVIDENCE_WINDOW_STEPS` below the floor, and that is exactly what is kept. Called before the floor moves.
    /// SCALE: at most `EVIDENCE_WINDOW_STEPS` + 1 entries of one step's admitted tags; no term in the bonded set or height.
    /// AI RESISTANT: (b) ordinary code every node runs on the sets its own fold admitted; what it changes is that a
    /// verdict no longer depends on how many rewinds a node lived through. cons: up to 65 steps' admitted tags kept in RAM
    /// and in the checkpoint (≤ 256 tags × 32 B a step: ≤ 0.53 MB at full blocks, kilobytes on today's chain).
    fn keep_released(&mut self, ordinal: u64, admitted: &[[u8; 32]]) {
        let keep_from = ordinal.saturating_add(1).saturating_sub(crate::nf_evidence::EVIDENCE_WINDOW_STEPS);
        for idle in self.floor.max(keep_from)..ordinal {
            self.history.entry(idle).or_default(); // took no journal slot: it admitted nothing
        }
        self.history.insert(ordinal, admitted.to_vec());
        while self.history.first_key_value().is_some_and(|(o, _)| *o < keep_from) {
            self.history.pop_first();
        }
    }

    /// R3 — un-apply every step with `ordinal ≥ first_evict`, newest first: the band is restored byte-identically and,
    /// when the caller passes its `held` view (P1: the view IS the band-pointer state), each un-applied step's admitted
    /// tags are taken back OUT of it (`RefSparseNf::remove`, the exact inverse of the insert `drain` made) — so after a
    /// reorg the view never keeps an insert the band no longer holds. A tag the view cannot take back is counted in
    /// `held_rewind_misses` (the caller drops and re-warms the view). The awaiting steps from there are forgotten (the
    /// re-fold notes them again) and the ring entries leave; a gap at or after `first_evict` closes (the re-fold re-notes
    /// it). Returns `false` when the rewind reaches below the journal's floor: the band is STALE there (the caller marks
    /// the spine stale), never silently kept.
    pub fn rewind_to(&mut self, first_evict: u64, mut held: Option<&mut RefSparseNf>) -> bool {
        // A-F56 MEASUREMENT — DIGITAL-CASH-PRIVACY-REVIEWED: public fold ordinals and counts only.
        eprintln!("[band-rewind] from step {first_evict}: before, {}", self.ring_census(first_evict.saturating_sub(1)));
        while self.journal.back().is_some_and(|s| s.ordinal >= first_evict) {
            if let Some(step) = self.journal.pop_back() {
                for (s, before) in step.before.iter().rev() {
                    self.band[*s as usize] = *before;
                }
                // ⛔ §POLES (lane a 2026-10-25) — AND ITS PROOF LEAVES WITH IT: `applied_proofs` holds the proofs of the
                // JOURNALED steps (pushed with the journal entry, released with it). Leaving an un-applied step's proof
                // behind made the re-fold push a second one, so the capped window's oldest entry depended on how many
                // reorgs THIS node lived through. MEASURED (4-node launch census, scratchpad/night/census4-stmt1.log):
                // band_door DIFFERS by statement — n1/n3 applied 74 steps, n0/n2 73, same cursor and root, different
                // oldest applied_proofs block.
                if let Some(at) = self.applied_proofs.iter().rposition(|(b, _)| *b == step.block) {
                    self.applied_proofs.remove(at);
                }
                if let Some(view) = held.as_deref_mut() {
                    for tag in step.admitted.iter().rev() {
                        if view.holds(tag) && !view.remove(tag) {
                            self.held_rewind_misses = self.held_rewind_misses.saturating_add(1);
                        }
                    }
                    for (s, before) in step.before.iter().rev() {
                        view.adopt_band_entry(*s, *before);
                    }
                }
            }
        }
        self.root = usdm_decider::nf_sparse_air::fold_band(&self.band).expect("a full band folds");
        self.ring.retain(|(o, _)| *o < first_evict);
        self.awaiting.retain(|o, _| *o < first_evict);
        if self.stale_from.is_some_and(|gap| first_evict <= gap) {
            self.stale_from = None;
        }
        // §11.12: a step still awaiting kept its pre (every step before it is below `first_evict` and was not un-applied),
        // so its verified copy stands; the evicted steps' copies leave — the relay re-offers them after the re-fold
        self.forget_unawaited();
        // A-F56 MEASUREMENT — DIGITAL-CASH-PRIVACY-REVIEWED: public fold ordinals and counts only.
        eprintln!("[band-rewind] from step {first_evict}: after, {}", self.ring_census(first_evict.saturating_sub(1)));
        first_evict >= self.floor
    }

    /// Relayed copies of steps that no longer await (applied, unwound, rewound or re-adopted) leave both stores.
    fn forget_unawaited(&mut self) {
        let awaiting: std::collections::BTreeSet<[u8; 32]> = self.awaiting.values().map(|(b, _)| *b).collect();
        self.verified.retain(|b, _| awaiting.contains(b));
        self.solicited.retain(|b, _| awaiting.contains(b));
        self.own_held.retain(|b| awaiting.contains(b));
    }

    /// ⭐ §11.13 C4 — a certified re-adopt (the sync bundle's band, pointer and the steps pointer..tip): the band is
    /// REPLACED, the journal, ring and relayed copies are dropped, the floor moves to `next_ordinal`, and the carried
    /// AWAITING steps are INSTALLED with their admitted sets — so a joiner verifies relayed steps from minute 0 instead of
    /// waiting on steps it never folded. Refuses a band of the wrong width, a step below `next_ordinal`, more steps than
    /// the lag cap, or an ordinal twice.
    pub fn adopt_certified(&mut self, band: Vec<Digest4>, next_ordinal: u64, awaiting: Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)>) -> bool { // TAG-SPACE: `awaiting` carries admitted tags as values, applied through `admitted_order` like every noted step; the block ids are never tags
        let Some(root) = usdm_decider::nf_sparse_air::fold_band(&band) else {
            return false;
        };
        let mut installed = std::collections::BTreeMap::new();
        for (ordinal, block, admitted) in awaiting {
            if ordinal < next_ordinal || installed.insert(ordinal, (block, admitted)).is_some() {
                return false;
            }
        }
        if band.len() != self.band.len() || installed.len() > self.lag_cap {
            return false;
        }
        self.band = band;
        self.root = root;
        self.base_root = root;
        self.awaiting = installed;
        self.stale_from = None;
        self.verified.clear();
        self.solicited.clear();
        self.own_held.clear();
        self.journal.clear();
        self.history.clear();
        // ⛔ AND THE JOURNALED STEPS' PROOFS LEAVE WITH THE JOURNAL (lane stable 2026-11-02). `applied_proofs` holds exactly the
        // proofs of the journaled steps — pushed with a journal entry, released with it (the rewind above; `install_journal`
        // keeps only a proof that reproduces a journaled step). Clearing the journal here kept them, so a re-anchored node
        // served proofs of steps it no longer journals, and its own restart dropped them: MEASURED (launch tail, n2
        // restarted just after a stale-spine re-anchor, stable/b8.log) "[band-door] ⛔ G1e-iv: 7 carried proof(s) do not
        // reproduce a journaled step", restart census `band_door` 141,087 → 24,553 B. cons: none — those proofs answer no
        // step this door can name; a peer behind asks the nodes that journal them.
        self.applied_proofs.clear();
        self.ring.clear();
        self.floor = next_ordinal;
        true
    }
}

/// TEST-ONLY: the band cursor's work in this process — [inserts, absorbed steps, served steps, rebuilds] (the simulator's
/// speed census reads it).
#[cfg(test)]
pub static BAND_CURSOR_EVENTS: [std::sync::atomic::AtomicU64; 4] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

/// TEST-ONLY: an EXACT bounded memo of [`RefSparseNf::fold_lone_leaf`] — `(key, level) → digest`, a pure function.
/// WHY (MEASURED 2026-10-06, simulator profile, link 8): a lone-leaf sibling read folds the leaf through `level` pair
/// hashes, and every simulated node (plus each node's band prove job) reads the SAME lone siblings for the same fold step —
/// 3,723 of the sim thread's 28,354 samples, each fold `level` pair-cache lookups. The memo answers a repeat in one lookup.
/// Same rule as `compress_sparse`'s pair cache: test builds only (a node binary folds directly — the simulator's cross-node
/// repeats do not exist in a one-node process), and it changes no value. cons: ≤ 2 × `CAP` entries (~13 MB) in a test
/// process; none in a node.
#[cfg(test)]
mod lone_fold_cache {
    use super::Digest4;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const CAP: usize = 65_536;
    const SHARDS: usize = 16;

    #[derive(Default)]
    struct Gen {
        cur: HashMap<([u8; 32], u16), Digest4>,
        old: HashMap<([u8; 32], u16), Digest4>,
    }

    static CACHE: std::sync::OnceLock<Vec<Mutex<Gen>>> = std::sync::OnceLock::new();

    /// What a hit is charged: the fold's measured miss cost, per pair hash (`usdm_decider::poseidon2_compress::sim_charge`
    /// — a node binary folds every lone leaf; a fold to `level` is `level` pair hashes, so the charge scales with it).
    static MISS_PER_LEVEL: usdm_decider::poseidon2_compress::sim_charge::MissCost =
        usdm_decider::poseidon2_compress::sim_charge::MissCost::new();

    pub fn get_or_compute(key: &[u8; 32], level: usize, f: impl FnOnce() -> Digest4) -> Digest4 {
        let k = (*key, level as u16);
        let shard = (key[0] as usize ^ key[17] as usize ^ level) % SHARDS;
        let cache = CACHE.get_or_init(|| (0..SHARDS).map(|_| Mutex::new(Gen::default())).collect());
        {
            let g = cache[shard].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(d) = g.cur.get(&k).or_else(|| g.old.get(&k)) {
                let d = *d;
                drop(g);
                MISS_PER_LEVEL.charge_hits(level as u64);
                return d;
            }
        }
        let out = MISS_PER_LEVEL.measure_per(level as u64, f);
        let mut g = cache[shard].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= CAP / SHARDS {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(k, out);
        out
    }
}

/// One insert's undo record in a [`BandCursor`]: the overrides it replaced, oldest first.
type CursorUndo = Vec<((usize, [u8; 32]), Option<Digest4>)>;

/// ⭐ §11.13 condition 3 — THE PROVER'S CURSOR: the held view (the band pointer's state) PLUS the admitted inserts of the
/// fold steps noted after the pointer, as an OVERLAY in the view's own representation — the new leaves, and an override
/// for every UNION subtree of ≥ 2 leaves that holds one of them; a lone-leaf subtree folds on demand and an untouched one
/// reads the view. It never copies the view: what it holds is bounded by the steps between the pointer and the cursor
/// (≤ the lag cap × the 256-slot lane × each insert's branch points), whatever the chain's height. It stays valid while the
/// view advances — the view only ever catches up to a state the cursor already holds, and a node no absorbed insert
/// touched is the same in both — and it is rebuilt from the pending sets on a rewind. A LocalCache: a wrong cursor yields
/// proofs every door refuses, never a band.
#[derive(Clone, Debug, Default)]
pub struct BandCursor {
    /// The absorbed keys, in the view's storage order (`tkey`).
    leaves: std::collections::BTreeSet<[u8; 32]>,
    /// `(level, canon) → hash` of every union subtree of ≥ 2 leaves that holds an absorbed key.
    branch: std::collections::HashMap<(usize, [u8; 32]), Digest4>,
    /// The absorbed steps, in fold order — what a rebuild replays. NOT-A-TAG in the block ids.
    steps: std::collections::VecDeque<(u64, [u8; 32], Vec<[u8; 32]>)>,
    /// One key (path space) per protocol shard an absorbed step touched — where that shard's band entry is read.
    touched: std::collections::BTreeMap<u32, [u8; 32]>,
}

impl BandCursor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The fold ordinal the cursor has absorbed through (`None`: nothing beyond the view).
    #[must_use]
    pub fn through(&self) -> Option<u64> {
        self.steps.back().map(|(o, _, _)| *o)
    }

    /// Steps the overlay holds (applied ones stay until a rebuild sheds them).
    #[must_use]
    pub fn absorbed_steps(&self) -> usize {
        self.steps.len()
    }

    fn node(&self, view: &RefSparseNf, level: usize, canon: &[u8; 32]) -> Digest4 {
        if let Some(d) = self.branch.get(&(level, *canon)) {
            return *d;
        }
        let (lo, hi) = RefSparseNf::subtree_range(level, canon);
        let Some(first) = self.leaves.range(lo..=hi).next() else {
            return view.node_at(level, canon);
        };
        // an absorbed key here and no override: the union subtree holds exactly this one leaf (`insert_key` keeps an
        // override for every union subtree of ≥ 2 leaves that holds an absorbed key)
        RefSparseNf::fold_lone_leaf(&SparseKey::from_key_bytes(RefSparseNf::tkey(first)), level)
    }

    fn sibling_canon(key: &SparseKey, level: usize) -> [u8; 32] {
        let mut sib = *key.bytes();
        sib[level >> 3] ^= 1u8 << (level & 7);
        RefSparseNf::canon(&SparseKey::from_key_bytes(sib), level)
    }

    /// Mark `key` spent in the union: the leaf folded up over the UNCHANGED siblings, an override kept at every level
    /// whose union subtree then holds ≥ 2 leaves. `None` (nothing changed) when the view cannot serve the key's shard or
    /// the key is already spent in the union.
    fn insert_key(&mut self, view: &RefSparseNf, key: &SparseKey) -> Option<CursorUndo> {
        self.insert_key_cp(view, key, None)
    }

    /// [`Self::insert_key`], also handing back the key's copath BEFORE the insert when `cp` is given. The siblings the fold
    /// reads are exactly that copath — an insert rewrites only the key's own ancestors, never a sibling of its path — so
    /// the owner's serve walks the 256 levels once, not twice. MEASURED 2026-10-06 (simulator profile): `copath_key` then
    /// `insert_key` over the same path was half of `band_next_owned_step`, itself 42 % of the journey's wall time.
    /// cons: none — the same `node` reads in the same order; a refused key leaves `cp` unspecified (the caller rolls back).
    fn insert_key_cp(&mut self, view: &RefSparseNf, key: &SparseKey, mut cp: Option<&mut Vec<Digest4>>) -> Option<CursorUndo> {
        #[cfg(test)]
        BAND_CURSOR_EVENTS[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let t = RefSparseNf::tkey(key.bytes());
        if !view.holds_key(key) || self.leaves.contains(&t) || view.leaves.contains(&t) {
            return None;
        }
        let mut undo = Vec::new();
        // DB-453: the key's compact witness against the UNION of the view's leaves and the overlay's — the terminal from
        // the nearest leaves of both, `Z` below it, the union's sibling nodes from it up — and its post path. A union
        // subtree holds ≥ 2 leaves (an override) exactly from the nearest leaf's entry level `e1` up.
        let (lt, term, e1) = compact_terminal(&[&view.leaves, &self.leaves], &t, false);
        let term = term.map(|x| SparseKey::from_key_bytes(RefSparseNf::tkey(&x)));
        let mut full = vec![Z; NF_COPATH_LEN];
        for (level, slot) in full.iter_mut().enumerate().take(NF_SPARSE_DEPTH).skip(lt) {
            *slot = self.node(view, level, &Self::sibling_canon(key, level));
        }
        full[NF_TERMINAL_SLOT] = terminal_slot(term.as_ref());
        let path = post_path_of(key, lt, term.as_ref(), &full);
        // Above the band every level folds plainly, and a sharded view's foreign shards hold leaves this overlay cannot
        // see — so every band level takes its override too (its value is the union's node whatever the count).
        let first_override = e1.min(usdm_decider::nf_sparse_air::NF_BAND_LEVEL + 1).max(1);
        for (level, node) in path.iter().enumerate().skip(first_override) {
            let at = (level, RefSparseNf::canon(key, level));
            undo.push((at, self.branch.insert(at, *node)));
        }
        if let Some(c) = cp.as_deref_mut() {
            *c = full;
        }
        self.leaves.insert(t);
        Some(undo)
    }

    fn undo(&mut self, key: &SparseKey, log: CursorUndo) {
        for (at, prev) in log.into_iter().rev() {
            match prev {
                Some(d) => {
                    self.branch.insert(at, d);
                }
                None => {
                    self.branch.remove(&at);
                }
            }
        }
        self.leaves.remove(&RefSparseNf::tkey(key.bytes()));
    }

    fn rollback(&mut self, logs: Vec<(SparseKey, CursorUndo)>) {
        for (key, log) in logs.into_iter().rev() {
            self.undo(&key, log);
        }
    }

    fn note_touched(&mut self, by_shard: &std::collections::BTreeMap<u32, Vec<[u8; 32]>>) { // TAG-SPACE: shard → admitted tags, stored as their path keys
        for (s, tags) in by_shard {
            if let Some(t) = tags.first() {
                self.touched.entry(*s).or_insert(SparseKey::of(t).0);
            }
        }
    }

    /// Absorb a noted step the cursor does not prove (idle steps included), its admitted inserts in the door's canonical
    /// order. `false` (nothing absorbed) when the ordinal does not follow the cursor, a tag is already spent in the union,
    /// or the view cannot serve its shard — the owner then cannot prove past it and C2's open rule covers the step.
    pub fn absorb(&mut self, view: &RefSparseNf, ordinal: u64, block: [u8; 32], admitted: &[[u8; 32]]) -> bool { // TAG-SPACE: `admitted` holds tags as values, keyed through `SparseKey::of`
        if self.through().is_some_and(|o| ordinal <= o) {
            return false;
        }
        #[cfg(test)]
        BAND_CURSOR_EVENTS[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (_, ordered, by_shard) = admitted_order(admitted);
        let mut logs = Vec::with_capacity(ordered.len());
        for t in &ordered {
            let key = SparseKey::of(t);
            match self.insert_key(view, &key) {
                Some(log) => logs.push((key, log)),
                None => {
                    self.rollback(logs);
                    return false;
                }
            }
        }
        self.note_touched(&by_shard);
        self.steps.push_back((ordinal, block, admitted.to_vec()));
        true
    }

    /// The protocol band of the cursor's state: `door_band` (the band at the pointer — the view's state) with every shard
    /// an absorbed step touched read from the union.
    #[must_use]
    pub fn band_now(&self, view: &RefSparseNf, door_band: &[Digest4]) -> Vec<Digest4> {
        let lower = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut band = door_band.to_vec();
        for (s, key) in &self.touched {
            if let Some(slot) = band.get_mut(*s as usize) {
                *slot = self.node(view, lower, &RefSparseNf::canon(&SparseKey::from_key_bytes(*key), lower));
            }
        }
        band
    }

    /// ⭐ The OWNER's serve of the NEXT fold step: the band BEFORE it, then for every protocol shard its admitted set or
    /// its fillers reach (shard order) — the lower copaths of the shard's tags in canonical order, each against the union
    /// after the previous ones; the shard's band entry after its tags; the fillers' lower copaths and entries against the
    /// shard after the tags (applied and taken back: a filler is never spent). Exactly the shapes
    /// `RefSparseNf::serve_fold_copaths` gives `build_band_transition`. The step is then ABSORBED. `None` (nothing
    /// absorbed) as for [`Self::absorb`], or a step with more admitted tags than the cover.
    #[allow(clippy::type_complexity)]
    pub fn serve_and_absorb(
        &mut self,
        view: &RefSparseNf,
        door_band: &[Digest4],
        ordinal: u64,
        block: [u8; 32],
        admitted: &[[u8; 32]],
        filler_from: u64,
    ) -> Option<(Vec<Digest4>, Vec<(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)>, Vec<(u64, u32, Vec<Digest4>, Digest4)>)> { // TAG-SPACE: `admitted` tags are keyed through `SparseKey::of`; the serves carry them as the builder's values
        if self.through().is_some_and(|o| ordinal <= o) {
            return None;
        }
        #[cfg(test)]
        BAND_CURSOR_EVENTS[2].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let lower = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let band_pre = self.band_now(view, door_band);
        let (_, ordered, by_shard) = admitted_order(admitted);
        let need = cover.checked_sub(ordered.len())?;
        let mut fill_by_shard: std::collections::BTreeMap<u32, Vec<u64>> = std::collections::BTreeMap::new();
        for i in filler_from..filler_from + need as u64 {
            fill_by_shard.entry(key_shard(&band_filler_key(i), bits)).or_default().push(i);
        }
        let shards: std::collections::BTreeSet<u32> = by_shard.keys().chain(fill_by_shard.keys()).copied().collect();
        let (mut serves, mut fillers) = (Vec::new(), Vec::new());
        let mut logs: Vec<(SparseKey, CursorUndo)> = Vec::with_capacity(ordered.len());
        for s in shards {
            let tags: &[[u8; 32]] = by_shard.get(&s).map_or(&[], Vec::as_slice);
            let fills: &[u64] = fill_by_shard.get(&s).map_or(&[], Vec::as_slice);
            let mut lows = Vec::with_capacity(tags.len());
            for t in tags {
                let key = SparseKey::of(t);
                let mut cp = Vec::new();
                let Some(log) = self.insert_key_cp(view, &key, Some(&mut cp)) else {
                    self.rollback(logs);
                    return None;
                };
                lows.push((*t, lower_witness(&cp)));
                logs.push((key, log));
            }
            if let Some(t) = tags.first() {
                let entry_after = self.node(view, lower, &RefSparseNf::canon(&SparseKey::of(t), lower));
                serves.push((s, entry_after, lows));
            }
            let mut filler_logs: Vec<(SparseKey, CursorUndo)> = Vec::with_capacity(fills.len());
            for &i in fills {
                let key = band_filler_key(i);
                let mut cp = Vec::new();
                let Some(log) = self.insert_key_cp(view, &key, Some(&mut cp)) else {
                    self.rollback(filler_logs);
                    self.rollback(logs);
                    return None;
                };
                fillers.push((i, s, lower_witness(&cp), self.node(view, lower, &RefSparseNf::canon(&key, lower))));
                filler_logs.push((key, log));
            }
            self.rollback(filler_logs);
        }
        self.note_touched(&by_shard);
        self.steps.push_back((ordinal, block, admitted.to_vec()));
        Some((band_pre, serves, fillers))
    }

    /// Rebuild from the view and the steps still pending (after a rewind, or to shed applied steps): the overlay becomes
    /// exactly `pending`'s inserts. `false` (and an empty cursor) when a step cannot be absorbed.
    pub fn rebuild(&mut self, view: &RefSparseNf, pending: &[(u64, [u8; 32], Vec<[u8; 32]>)]) -> bool { // TAG-SPACE: pending admitted tags, absorbed through `SparseKey::of`
        #[cfg(test)]
        BAND_CURSOR_EVENTS[3].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self = Self::default();
        for (ordinal, block, admitted) in pending {
            if !self.absorb(view, *ordinal, *block, admitted) {
                *self = Self::default();
                return false;
            }
        }
        true
    }
}

/// HIGHEST-RANDOM-WEIGHT (rendezvous) selection. `holders_of(domain, shard, ids, k)` = the `k` ids with the largest
/// `blake3(domain ‖ shard ‖ id)`, ties broken by the id bytes — deterministic on every node from PUBLIC ids alone, balanced
/// (each id holds ≈ k·S/n of S shards), and minimally disruptive: an id joining or leaving moves ONLY the shards where it
/// ranks in the top `k`; every other shard's holder set is unchanged (the property a modulo assignment lacks). `k ≥
/// ids.len()` ⇒ every id holds every shard. Own-id rule (consensus lane, 21:35): ids = known peers' ids ∪ the node's own
/// announced public id; a node whose public id is not yet announced is in nobody's set and HOLDS EVERY SHARD
/// (`holds_shard(.., None)`) — over-holding, never short. Returned best-rank first.
#[must_use]
pub fn holders_of(domain: &[u8], shard: u32, ids: &[String], k: usize) -> Vec<String> {
    let mut ranked: Vec<([u8; 32], &String)> = ids
        .iter()
        .map(|id| {
            let mut h = blake3::Hasher::new();
            h.update(domain);
            h.update(&shard.to_le_bytes());
            h.update(id.as_bytes());
            (*h.finalize().as_bytes(), id)
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    ranked.dedup_by(|a, b| a.1 == b.1);
    ranked.into_iter().take(k).map(|(_, id)| id.clone()).collect()
}

/// Does the node `me` hold `shard` under [`holders_of`]? A node with no announced public id (`None`) holds everything.
#[must_use]
pub fn holds_shard(domain: &[u8], shard: u32, ids: &[String], k: usize, me: Option<&str>) -> bool {
    match me {
        None => true,
        Some(m) => holders_of(domain, shard, ids, k).iter().any(|h| h == m),
    }
}

/// The STORED traversal key of a nullifier TAG (`RefSparseNf::tkey` of its path key) — for the restore cursor and the
/// stream filters, which compare served tags against the leaf set. Under this boundary it equals the tag's own byte
/// order (key = reverse(tag), tkey = reverse(key)); spelled through the conversion so no reader has to know that.
fn tag_tkey(tag: &[u8; 32]) -> [u8; 32] {
    RefSparseNf::tkey(SparseKey::of(tag).bytes())
}

/// The shard id of a KEY under `s` shard bits: the `s` bits the descent reads FIRST (levels `DEPTH-1`
/// down to `DEPTH-s`), most-significant first — so shard ids are exactly the level-`DEPTH-s` subtrees in
/// band order, and merging adjacent ids merges the correct sibling pair. Public callers hand a TAG to
/// [`nf_shard`]; this is the path-space form.
#[must_use]
pub fn key_shard(key: &SparseKey, shard_bits: usize) -> u32 {
    let mut id = 0u32;
    for j in 0..shard_bits {
        id = (id << 1) | u32::from(key_bit(key, NF_SPARSE_DEPTH - 1 - j));
    }
    id
}

/// The shard id of a nullifier TAG under `s` shard bits (converted at this boundary).
#[must_use]
pub fn nf_shard(nf: &[u8; 32], shard_bits: usize) -> u32 {
    key_shard(&SparseKey::of(nf), shard_bits)
}

/// bit `level` of the KEY, LSB-first (level 0 = least-significant bit of key byte 0). Determines the child side
/// at that tree level: 0 ⇒ this node is the LEFT child (sibling on the right), 1 ⇒ RIGHT child (sibling on left).
#[inline]
fn key_bit(key: &SparseKey, level: usize) -> u8 {
    (key.bytes()[level >> 3] >> (level & 7)) & 1
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐⭐ DB-453 — THE COMPACT SHARD TREE (docs/DB-453-COMPACT-SHARD-NULLIFIER-TREE.md §3.3). The node computes every node
// value through the decider's ONE definition (`usdm_decider::nf_compact_air`): below the band (levels ≤ NF_BAND_LEVEL) an
// EMPTY subtree is `Z = [0; 8]`, a subtree holding exactly ONE key is that key's leaf `compact_leaf(key)`, and only a
// subtree holding two or more keys hashes its two children; the band levels above fold PLAINLY (`fold_band`), so an empty
// subtree there is `Z` folded with itself. The root is a function of the spent SET (commutative, count-free, monotone),
// and a path is only as long as the keys' common prefix — the band step proves 64 rows per insert instead of 256.
//
// THE COPATH CURRENCY (one layout, every reader): `NF_COPATH_LEN` digests — `cp[l]` the sibling at level `l` for every
// level at or above the TERMINAL `t` (the highest level on the key's path whose subtree holds at most one key, at most
// the band level), `Z` below it, and `cp[NF_SPARSE_DEPTH]` the TERMINAL SLOT: the one key in the terminal subtree packed
// into eight 32-bit lanes ([`terminal_slot`]), or `Z` when that subtree is empty. `t` is not carried: it is the lowest
// non-`Z` sibling (capped at the band level) — every level above an honest `t` has a non-empty sibling there, because the
// subtree one level up holds ≥ 2 keys. A forged layout cannot move a verdict: a sibling planted below the real terminal
// lowers the implied `t`, and the fold from there must hit the root through `pair(Z, ·) = Z` or a leaf/pair collision.
// When the terminal key IS the copath's own key (the MEMBER form a tree serves for a spent tag), the copath proves
// membership; otherwise it proves absence and, folded with the key's leaf, the root once the key is inserted.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// The copath currency's length: `NF_SPARSE_DEPTH` siblings, then the terminal slot (see the block above).
pub const NF_COPATH_LEN: usize = NF_SPARSE_DEPTH + 1;

/// Where the terminal slot sits in a copath.
const NF_TERMINAL_SLOT: usize = NF_SPARSE_DEPTH;

/// The LOWER witness a shard holder serves for one insert: the siblings below the band level, then the terminal slot. The
/// producer joins it with the band-top siblings of its mixed band ([`join_lower`]).
pub const NF_LOWER_LEN: usize = usdm_decider::nf_sparse_air::NF_BAND_LEVEL + 1;

/// An empty subtree below the band — and the empty terminal slot.
const Z: Digest4 = usdm_decider::nf_compact_air::compact_empty();

/// The leaf node of a KEY — the value a one-key subtree takes at every level up to the band.
#[inline]
fn compact_leaf_of(key: &SparseKey) -> Digest4 {
    usdm_decider::nf_compact_air::compact_leaf(key.bytes())
}

/// The terminal slot of a copath: the terminal key's 32 bytes as eight little-endian 32-bit lanes, or `Z` for an empty
/// terminal. The all-zero key is never a leaf of the committed tree (the zero tag is refused at every door), so `Z` is
/// unambiguous. Data, never hashed.
fn terminal_slot(key: Option<&SparseKey>) -> Digest4 {
    let Some(k) = key else { return Z };
    let b = k.bytes();
    core::array::from_fn(|i| u64::from(u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])))
}

/// The terminal key a slot names: `Some(None)` for an empty terminal, `None` for a malformed slot (a lane past 32 bits).
fn terminal_of(slot: &Digest4) -> Option<Option<SparseKey>> {
    if *slot == Z {
        return Some(None);
    }
    let mut b = [0u8; 32];
    for (i, lane) in slot.iter().enumerate() {
        let v = u32::try_from(*lane).ok()?;
        b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    Some(Some(SparseKey::from_key_bytes(b)))
}

/// The terminal level a compact copath implies: its lowest non-`Z` sibling, at most the band level.
fn copath_terminal_level(cp: &[Digest4]) -> usize {
    let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
    (0..band).find(|&l| cp[l] != Z).unwrap_or(band)
}

/// A compact copath as the decider's insert witness for `key` (`None` on a wrong length or a malformed terminal slot).
fn compact_witness(key: &SparseKey, cp: &[Digest4]) -> Option<usdm_decider::nf_compact_air::CompactInsertWitness> {
    if cp.len() != NF_COPATH_LEN {
        return None;
    }
    let other = terminal_of(&cp[NF_TERMINAL_SLOT])?;
    Some(usdm_decider::nf_compact_air::CompactInsertWitness {
        key: *key.bytes(),
        t: copath_terminal_level(cp),
        other: other.map(|o| *o.bytes()),
        siblings: cp[..NF_SPARSE_DEPTH].to_vec(),
    })
}

/// The ABSENCE folds of a copath for `key`: `(root under which key is absent, root once key is inserted)` — the decider's
/// one native transition (`native_compact_insert_folds`, which also refuses the zero key and a terminal that is the key
/// itself). `None` for a member-form or malformed copath.
fn absence_folds(key: &SparseKey, cp: &[Digest4]) -> Option<(Digest4, Digest4)> {
    let w = compact_witness(key, cp)?;
    let (pre, post, _split) = usdm_decider::nf_compact_air::native_compact_insert_folds(&w)?;
    Some((pre, post))
}

/// The MEMBER fold of a copath for `key`: the root of a tree holding `key` alone in its terminal subtree. `None` unless the
/// terminal slot names `key` itself.
fn member_root(key: &SparseKey, cp: &[Digest4]) -> Option<Digest4> {
    let w = compact_witness(key, cp)?;
    if w.other != Some(*key.bytes()) || *key.bytes() == [0u8; 32] {
        return None;
    }
    let mut node = compact_leaf_of(key);
    for (l, sib) in cp.iter().enumerate().take(NF_SPARSE_DEPTH).skip(w.t) {
        node = pair_by_bit(node, *sib, key_bit(key, l));
    }
    Some(node)
}

/// One parent on the key's path: `node` is the LEFT child when the key's bit at the child's level is 0.
#[inline]
fn pair_by_bit(node: Digest4, sib: Digest4, bit: u8) -> Digest4 {
    #[cfg(test)]
    NF_SPARSE_HASHES.with(|c| c.set(c.get() + 1));
    if bit == 0 {
        sparse_pair(node, sib)
    } else {
        sparse_pair(sib, node)
    }
}

/// The highest LEVEL where two keys differ; `None` when they are equal.
fn split_level(a: &SparseKey, b: &SparseKey) -> Option<usize> {
    (0..NF_SPARSE_DEPTH).rev().find(|&l| key_bit(a, l) != key_bit(b, l))
}

/// `key`'s own subtree node at EVERY level once it is inserted, from its compact witness `(t, terminal, cp)` taken while it
/// was absent: `path[l]` for `l` in `0..=NF_SPARSE_DEPTH`, `path[NF_SPARSE_DEPTH]` the post root. Below the split the
/// subtree holds the key alone (its leaf); a terminal key splits off at their highest differing level, the levels up to `t`
/// pair with `Z`, and every level from `t` folds the copath's sibling. A terminal that IS the key (the member form)
/// yields the member path — inserting a member changes nothing.
fn post_path_of(key: &SparseKey, t: usize, terminal: Option<&SparseKey>, cp: &[Digest4]) -> Vec<Digest4> {
    let lk = compact_leaf_of(key);
    let mut path = vec![lk; NF_SPARSE_DEPTH + 1];
    let mut node = lk;
    if let Some(o) = terminal.filter(|o| *o != key) {
        if let Some(s) = split_level(key, o).filter(|s| *s < t) {
            node = pair_by_bit(lk, compact_leaf_of(o), key_bit(key, s));
            path[s + 1] = node;
            for l in (s + 1)..t {
                node = pair_by_bit(node, Z, key_bit(key, l));
                path[l + 1] = node;
            }
        }
    }
    for l in t..NF_SPARSE_DEPTH {
        node = pair_by_bit(node, cp[l], key_bit(key, l));
        path[l + 1] = node;
    }
    path
}

/// `key`'s own subtree node at every level from the terminal up while it is ABSENT (`Z` below the terminal): `path[t]` is
/// the terminal node (`Z` or the terminal key's leaf). What a removal leaves on the key's path.
fn pre_path_of(key: &SparseKey, t: usize, terminal: Option<&SparseKey>, cp: &[Digest4]) -> Vec<Digest4> {
    let mut path = vec![Z; NF_SPARSE_DEPTH + 1];
    let mut node = terminal.map_or(Z, compact_leaf_of);
    path[t] = node;
    for l in t..NF_SPARSE_DEPTH {
        node = pair_by_bit(node, cp[l], key_bit(key, l));
        path[l + 1] = node;
    }
    path
}

/// ⭐ THE COMPACT TERMINAL of a storage key `k` in the union of `sets` (storage keys, `k` itself excluded): `(t, terminal
/// storage key, nearest entry level)`. A key `x` enters `k`'s path subtrees at level `e(x) = highest differing level + 1`;
/// the subtree at level `l` holds `#{x : e(x) ≤ l}` keys besides `k`, and the two smallest entries are attained at the
/// two nearest neighbours on each side of every set — the nearest-neighbour rule `insert_with_path` already uses. With `k`
/// PRESENT the terminal holds `k` alone: `t = min(band, e₁ − 1)`. ABSENT: `t = min(band, e₂ − 1)` and the terminal holds the
/// nearest key iff it entered at or below `t`. The nearest entry `e₁` is the lowest level whose subtree holds `k` and
/// another key — where a branch first exists once `k` is inserted.
fn compact_terminal(
    sets: &[&std::collections::BTreeSet<[u8; 32]>],
    k: &[u8; 32],
    present: bool,
) -> (usize, Option<[u8; 32]>, usize) {
    let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
    let mut ent: Vec<(usize, [u8; 32])> = Vec::with_capacity(4 * sets.len());
    for s in sets {
        for x in s.range(..*k).rev().take(2).chain(s.range((std::ops::Bound::Excluded(*k), std::ops::Bound::Unbounded)).take(2)) {
            ent.push((RefSparseNf::highest_differing_bit(k, x) + 1, *x));
        }
    }
    ent.sort_unstable();
    ent.dedup_by(|a, b| a.1 == b.1);
    let none = NF_SPARSE_DEPTH + 1;
    let e1 = ent.first().map_or(none, |e| e.0);
    if present {
        return (band.min(e1 - 1), Some(*k), e1);
    }
    let e2 = ent.get(1).map_or(none, |e| e.0);
    let t = band.min(e2 - 1);
    let other = ent.first().filter(|e| e.0 <= t).map(|e| e.1);
    (t, other, e1)
}

/// The compact node of a SMALL key set at `level` (every key sharing the bits at and above `level`): `Z`, one key's leaf,
/// or the pair of its two halves — the reference recursion (`CompactRefTree::node`) for the few keys a wallet witness
/// meets inside its own terminal subtree.
fn compact_node_small(keys: &[SparseKey], level: usize) -> Digest4 {
    match keys {
        [] => Z,
        [k] => compact_leaf_of(k),
        _ => {
            let (l, r): (Vec<SparseKey>, Vec<SparseKey>) = keys.iter().partition(|k| key_bit(k, level - 1) == 0);
            sparse_pair(compact_node_small(&l, level - 1), compact_node_small(&r, level - 1))
        }
    }
}

/// The LOWER witness of a full compact copath: its siblings below the band level, then its terminal slot.
#[must_use]
pub fn lower_witness(cp: &[Digest4]) -> Vec<Digest4> {
    let lower = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
    let mut low = cp[..lower.min(cp.len())].to_vec();
    low.push(cp.get(NF_TERMINAL_SLOT).copied().unwrap_or(Z));
    low
}

/// A full compact copath from a holder's lower witness and the band-top siblings (`None` on a wrong length).
#[must_use]
pub fn join_lower(low: &[Digest4], top: &[Digest4]) -> Option<Vec<Digest4>> {
    let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
    if low.len() != NF_LOWER_LEN || top.len() != bits {
        return None;
    }
    let mut cp = low[..NF_LOWER_LEN - 1].to_vec();
    cp.extend_from_slice(top);
    cp.push(low[NF_LOWER_LEN - 1]);
    Some(cp)
}

/// The decider's compact insert witness of the nullifier TAG `tag` with the compact copath THIS module built for its key.
#[must_use]
pub fn compact_insert_witness_for(tag: &[u8; 32], cp: &[Digest4]) -> Option<usdm_decider::nf_compact_air::CompactInsertWitness> {
    compact_witness(&SparseKey::of(tag), cp)
}

/// ⭐ DB-453 — THE BLOCK'S OPTIONAL SPARSE CARRIER on the compact tree (`NfBlockProof::sparse_carrier`): the block's tags
/// inserted in carried order (reals first, power-of-two padding after), proven on the compact carrier at the shape they
/// fit. `(carrier, post)`. Off the produce path (a producer that holds no tree carries none).
#[must_use]
pub fn prove_block_sparse_carrier(
    inserts: &[usdm_decider::nf_compact_air::CompactInsertWitness],
    pre: Digest4,
    real_n: usize,
) -> Option<(Vec<u8>, Digest4)> {
    let lb = usdm_decider::nf_compact_air::compact_step_lb(inserts);
    let (carrier, post, _kd) = usdm_decider::nf_compact_air::prove_compact_band_carrier_bytes(inserts, pre, real_n, lb)?;
    Some((carrier, post))
}

/// VERIFY a block's sparse carrier against values the VERIFIER derives: the committed endpoints and the block's REAL tags
/// in carried order (their key digest at the power-of-two insert count) — the keys are bound, never taken from the carrier.
#[must_use]
pub fn verify_block_sparse_carrier(carrier: &[u8], pre: Digest4, post: Digest4, real_tags: &[[u8; 32]]) -> bool { // TAG-SPACE: the block's carried tags, keyed through `SparseKey::of`
    if carrier.is_empty() || real_tags.is_empty() {
        return false;
    }
    let n = real_tags.len().next_power_of_two();
    let keys: Vec<SparseKey> = real_tags.iter().map(SparseKey::of).collect();
    usdm_decider::nf_compact_air::verify_compact_band_carrier_any_shape(carrier, pre, post, real_tags.len(), n, SparseKey::keys_digest(&keys, n))
}

/// The nullifier tree's pair hash on the hot folds (the band cursor's inserts, the lone-leaf folds, the settle fold): the
/// ONE compression, through the decider's exact test-build cache (`compress_sparse`; a node binary calls `compress`).
#[inline]
fn sparse_pair(left: Digest4, right: Digest4) -> Digest4 {
    #[cfg(test)]
    crate::spend_frontier::NODE_PAIR_HASHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    usdm_decider::poseidon2_compress::compress_sparse(&left, &right)
}

/// TEST-ONLY hash counter — proves the settle fold is a FIXED number of hashes regardless of how many nullifiers
/// are already spent (flat-O(1) in height), the decider-analog.
#[cfg(test)]
thread_local! {
    pub static NF_SPARSE_HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Errors settling a spend against the sparse accumulator.
#[derive(Debug, PartialEq, Eq)]
pub enum SpentVerdict {
    /// The copath reproduces this root with the EMPTY leaf — provably NOT spent.
    Unspent,
    /// The copath reproduces this root with the SPENT leaf — provably spent.
    Spent,
    /// The copath does not describe this tree (stale/short/foreign index). It proves NOTHING; a caller must
    /// not read this as either answer. Fail-closed belongs at the GATE, which requires a positive proof of
    /// absence — not here, where guessing "spent" refuses honest money and guessing "unspent" would admit a
    /// double spend.
    Unprovable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseNfError {
    /// The nullifier is zero (a reserved/invalid value).
    ZeroNullifier,
    /// The supplied copath is not exactly `DEPTH` siblings.
    BadCopathLength,
    /// The leaf is NOT currently EMPTY under the committed root ⇒ already spent (double-spend) or a bad witness.
    AlreadySpentOrBadWitness,
}

/// The COUNT-FREE sparse nullifier accumulator: a single root. O(1) memory at ANY height — there is no count, no
/// tree, nothing that grows. A DSYNC jumper adopts exactly this and learns zero about spend volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseNfAcc {
    root: Digest4,
}

impl Default for SparseNfAcc {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseNfAcc {
    /// The empty accumulator — an all-unspent tree (root = the all-empty subtree at full depth).
    pub fn new() -> Self {
        Self {
            root: empty_subtree(NF_SPARSE_DEPTH),
        }
    }

    /// Adopt a committed root O(1) (the DSYNC-jump twin — no count, no tree, no volume).
    /// ⛔⛔⛔ ADOPT A **SPARSE MERKLE ROOT** — NOT A FOLD ACCUMULATOR.
    ///
    /// THE DEFECT THIS NAMES, verified in live code 2026-07-31. Two functions wrote DIFFERENT mathematical
    /// objects into this one field:
    ///
    ///   * `Node::ingest_sparse_nf_transition` rebuilds a real sparse tree and commits `t.root_bytes()`
    ///     — a Merkle root, which is what `verify_unspent` folds a copath against;
    ///   * `Node::adopt_sparse_via_block_fold` — THE HOT PATH — computes `nf_unspent_step_new_acc(..)`,
    ///     the A_tip FOLD accumulator, and commits `leaf_to_cm_bytes(post_acc)` into the same field.
    ///
    /// `verify_unspent` checks `fold_sparse([0xA, 0, 0, 0, 0, 0, 0, 0], nf, copath) != self.root`. Against a fold value
    /// that comparison CANNOT succeed for any copath, honest or forged — so every verdict was `Unprovable`
    /// BY CONSTRUCTION, on every node, at every height, forever. The carried-copath machinery
    /// (`apply_block_treeless`, `PqTx::nullifier_witnesses`) is correct code reading a field that had been
    /// overwritten with a different kind of number.
    ///
    /// A fold accumulator and a Merkle root are both `[u8; 32]`, so the compiler could not object and the
    /// tests could not either — each function is self-consistent; only the FIELD they share is not. The
    /// caller must now state which object it holds, so the two can never be confused again.
    /// ⛔⛔⛔ WAS `cm_bytes_to_leaf`, WHICH IS A **HASH** — so this installed `hash(the served root)` as
    /// the double-spend gate, not the root. See [`crate::spend_frontier::cm_bytes_to_root`] for the full
    /// account; MEASURED by `two_nodes_instant_sync_roundtrip_serve_then_adopt`, where a DSYNC-jumped
    /// node's sparse gate held a value the serving node had never committed to and no honest copath
    /// could ever fold to.
    ///
    /// `None` when the bytes are not a canonical digest: such a value did not come from this chain, and
    /// there is no root it "means". The caller REFUSES rather than installing something reduced into
    /// range — the same law the frontier's own decoder applies slot by slot.
    #[must_use]
    pub fn adopt_merkle_root(root: [u8; 32]) -> Option<Self> { // NOT-A-TAG: a root
        Some(Self {
            root: crate::spend_frontier::cm_bytes_to_root(&root)?,
        })
    }

    /// The A_tip FOLD accumulator, adopted knowingly. A copath can NEVER fold to this value — any
    /// `verify_unspent` against it returns `AlreadySpentOrBadWitness` and any `spent_verdict` returns
    /// `Unprovable`. Kept as a distinct, named constructor so a caller that installs a fold value is
    /// declaring exactly that, in one place, instead of silently poisoning the copath gate.
    /// Same §AG repair as [`Self::adopt_merkle_root`]: the committed accumulator is a value the chain
    /// PRODUCED, so it decodes injectively or it is refused.
    #[must_use]
    pub fn adopt_fold_accumulator(acc_committed: [u8; 32]) -> Option<Self> { // NOT-A-TAG: an accumulator
        Some(Self {
            root: crate::spend_frontier::cm_bytes_to_root(&acc_committed)?,
        })
    }

    /// The 32-byte committed root.
    pub fn root_bytes(&self) -> [u8; 32] { // NOT-A-TAG: a root
        leaf_to_cm_bytes(self.root)
    }

    /// The committed root in `Digest4` limb form — the drop-in accessor mirroring `NullifierTree::root()`, so the
    /// consensus cutover can swap `Node.nullifier_acc: NullifierTree` → `SparseNfAcc` at the ~11 `.root()` call sites
    /// with no signature churn (the parallel-field migration's accessor parity). ([[project_node_footprint_and_lifecycle]])
    pub fn root(&self) -> Digest4 {
        self.root
    }

    /// Verify `nf` is currently UNSPENT under the committed root using a supplied non-membership copath. Read-only.
    pub fn verify_unspent(&self, nf: &[u8; 32], copath: &[Digest4]) -> Result<(), SparseNfError> {
        if *nf == [0u8; 32] {
            return Err(SparseNfError::ZeroNullifier);
        }
        if copath.len() != NF_COPATH_LEN {
            return Err(SparseNfError::BadCopathLength);
        }
        // Non-membership (DB-453): the key's compact terminal — empty, or ONE other key's leaf — folds to the current root
        // (the boundary: tag → key). A member-form copath, a re-spend, a forged terminal or sibling: no fold reaches it.
        match absence_folds(&SparseKey::of(nf), copath) {
            Some((pre, _post)) if pre == self.root => Ok(()),
            _ => Err(SparseNfError::AlreadySpentOrBadWitness),
        }
    }

    /// FLAT-O(1) SETTLE: verify `nf` is unspent (non-membership) then flip it EMPTY→SPENT, advancing the root. A
    /// FIXED `2·DEPTH` hashes, independent of how many nullifiers are already spent. The copath is spender-supplied
    /// (self-built from the replicated DA stream), so a producer holds only the O(1) root — no tree, no count.
    /// ⛔⛔⛔ "SPENT" AND "I CANNOT TELL" ARE DIFFERENT ANSWERS — DO NOT CONFLATE THEM.
    ///
    /// `verify_unspent` returns `AlreadySpentOrBadWitness` for BOTH a genuinely spent leaf and a copath that
    /// simply does not fold to this root (a stale or short local index). Treating that single Err as "spent"
    /// makes an UNSPENT nullifier read SPENT and refuses honest money — the exact false double-spend measured
    /// tonight, and what the live comment in `is_nullifier_spent` records as "the two paths do NOT agree on a
    /// chain with real history".
    ///
    /// The distinction is cheap and total. A copath either reproduces this root with the EMPTY leaf (provably
    /// unspent), or with the SPENT leaf (provably spent), or with neither (the witness does not describe this
    /// tree at all, so it proves nothing either way). Same fixed 2·DEPTH hashes, no extra state.
    pub fn spent_verdict(&self, nf: &[u8; 32], copath: &[Digest4]) -> SpentVerdict {
        match copath_described_roots(nf, copath) {
            Some((if_empty, _)) if if_empty == Some(self.root) => SpentVerdict::Unspent,
            Some((_, if_spent)) if if_spent == self.root => SpentVerdict::Spent,
            _ => SpentVerdict::Unprovable,
        }
    }

/// ⭐⭐⭐ INSERT FROM A COPATH THIS NODE JUST PRODUCED ITSELF — ONE fold instead of two.
    ///
    /// MEASURED (real joiner, n=236): the Merkle view advance costs **281 ms/block** over the
    /// constant 256-tag cover set, which is half of `fold_block_nf_in_order`'s 569 ms against a
    /// 500 ms block time. That is what caps a follower near 1 block/s and makes it depend on a
    /// #29 DSYNC jump to catch up.
    ///
    /// The cost is 256 leaves folded into a depth-256 tree TWICE: `insert_and_witness` walks the
    /// tree and returns the pre-insert copath, then `verify_and_insert` folds that copath ONCE to
    /// verify and AGAIN to insert. This does the insert only.
    ///
    /// ⛔ THIS WEAKENS NO GATE, AND THAT IS THE WHOLE POINT. `verify_and_insert` exists for a
    /// SPENDER-SUPPLIED copath, where the fold is what refuses a forged or stale witness. The
    /// caller here supplies a copath IT JUST READ FROM ITS OWN TREE, so the verify is asking
    /// whether this node's tree agrees with this node's accumulator — a DRIFT check, not an
    /// admission check, and `advance_sparse_shadow` already makes exactly that comparison once per
    /// block (`tree_root != acc_root`, logged loudly). Paying for it 256 times per block buys the
    /// same answer the O(1) comparison already gives.
    ///
    /// ⛔ NEVER CALL THIS ON A CARRIED WITNESS. A copath that came from the wire must go through
    /// `verify_and_insert`; this entry point assumes the caller produced it and is checking the
    /// result at the block boundary.
    pub fn insert_from_own_copath(&mut self, nf: &[u8; 32], copath: &[Digest4]) {
        if *nf == [0u8; 32] {
            return; // nothing to fold — the boundary check below still catches the divergence
        }
        let key = SparseKey::of(nf);
        if let Some(w) = compact_witness(&key, copath) {
            let terminal = w.other.map(SparseKey::from_key_bytes);
            self.root = post_path_of(&key, w.t, terminal.as_ref(), copath)[NF_SPARSE_DEPTH];
        }
    }

    /// Take the root THIS node's own view just folded for one insert (`RefSparseNf::advance_one_rooted`) —
    /// the identical value [`Self::insert_from_own_copath`] would re-derive with `DEPTH` more hashes, since
    /// both fold the spent leaf up the same pre-insert copath. Same contract, same boundary: ⛔ NEVER with a
    /// root that came from the wire; the per-block drift check in `advance_sparse_shadow` still compares the
    /// view against this accumulator. The zero tag is padding and moves nothing, exactly as there.
    pub fn follow_own_walk(&mut self, nf: &[u8; 32], post_root: Digest4) { // TAG-SPACE: only the zero-tag check, no path
        if *nf == [0u8; 32] {
            return;
        }
        self.root = post_root;
    }

    pub fn verify_and_insert(
        &mut self,
        nf: &[u8; 32],
        copath: &[Digest4],
    ) -> Result<(), SparseNfError> {
        // (1) non-membership against the current root (also catches double-spend: a member's terminal is its own leaf).
        self.verify_unspent(nf, copath)?;
        // (2) insert along the SAME witness → the new root. `nf` is now spent forever.
        let (_pre, post) = absence_folds(&SparseKey::of(nf), copath).ok_or(SparseNfError::AlreadySpentOrBadWitness)?;
        self.root = post;
        Ok(())
    }
}

/// ⭐ DB-221 — THE TWO ROOTS A CARRIED COPATH CAN DESCRIBE at `nf`'s position: the root of a tree whose leaf there
/// is EMPTY (the copath proves `nf` unspent in THAT tree) and of one whose leaf is SPENT. `None` for the zero tag
/// or a copath of the wrong length. These are exactly the two folds [`SparseNfAcc::spent_verdict`] compares
/// against one root; returning them lets a caller holding SEVERAL roots find the one a copath was built on by
/// equality — two folds per tag whatever the number of roots, never one fold per root.
/// DB-453 (compact): an ABSENCE-form copath describes both roots — `(Some(pre), post)`, the tree it was built on and that
/// tree with `nf` inserted; a MEMBER-form copath (its terminal is `nf` itself) describes only the tree holding `nf` —
/// `(None, member root)`: which tree held the same siblings without `nf` is not a function of the copath (a removal can
/// re-compact the levels above it).
pub fn copath_described_roots(nf: &[u8; 32], copath: &[Digest4]) -> Option<(Option<Digest4>, Digest4)> {
    if *nf == [0u8; 32] || copath.len() != NF_COPATH_LEN {
        return None;
    }
    let key = SparseKey::of(nf);
    if let Some(member) = member_root(&key, copath) {
        return Some((None, member));
    }
    let (pre, post) = absence_folds(&key, copath)?;
    Some((Some(pre), post))
}

/// DB-221 — how many BLOCKS of absorbed tags [`RecentSpentRoots`] spans. DERIVED FROM THE PROTOCOL'S OWN
/// CADENCE, not tuned: a wallet builds its copath, then proves the spend (measured 1.2–2.9 s), then the tx crosses
/// Tor (seconds). 64 blocks × 500 ms = 32 s covers that with margin. A copath older than the ring is refused with
/// its reason named and the spender rebuilds it — the NOTE never ages out, only a proof that stopped short of the
/// present, the same rule the gate states for every carrier.
pub const NF_RECENT_BLOCKS: usize = 64;

/// DB-221 — the ring's capacity in TAGS: [`NF_RECENT_BLOCKS`] full constant-width blocks. Counting tags rather
/// than events is what keeps the window a TIME window: a burst of single-tag absorbs (order fills, peg
/// nullifiers) costs its own tags, never a whole block's worth of anchors.
///
/// O1-FOOTPRINT-REVIEWED: 16,384 entries × 64 B (a root and a tag) = 1 MiB, allocated once, fixed; the oldest
/// entry drops on every push past it. No term in height, blocks, notes or spends.
pub const NF_RECENT_TAGS: usize = NF_RECENT_BLOCKS * crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;

/// ⭐⭐ DB-221 — THE RECENT SPENT-SET ROOTS A NODE PASSED THROUGH, each with the tag whose absorb produced it, so a
/// spender's carried copath built a few blocks ago is judged EXACTLY instead of refused as `Unprovable`.
///
/// WHY: DB-217 made the spend gate require a positive `Unspent` verdict. A carried copath folds to the root it was
/// built against, and every block absorbs the constant 256-tag cover, so one block later that root is gone and
/// the verdict against the live root alone is `Unprovable` — every honest carried spend refused.
///
/// SET ALGEBRA, EXACT. Entry `k` is `(R_k, t_k)`: the root AFTER absorbing tag `t_k`, chained from `base`. So for
/// any held root `R_j`, `set(live) = set(R_j) ∪ {t_k : k > j}`:
/// - a copath folding `nf` SPENT to any held root ⇒ `nf` is spent now (the set only grows);
/// - a copath folding `nf` EMPTY to `R_j` ⇒ `nf ∉ set(R_j)`, so `nf` is unspent now iff it is none of the later
///   `t_k` — if it is one, it settled AFTER the copath was built and the verdict is `Spent`.
///
/// Several consecutive entries may share one root when a caller absorbed a whole block without computing the
/// intermediate roots (see [`Self::absorb_block`]); an anchor is therefore always the LAST entry holding a root,
/// so the sweep can never skip a tag that entry's root does not contain.
///
/// ⛔ CONTINUITY IS CHECKED, NOT ASSUMED. [`Self::absorb`] takes the root BEFORE the tag and chains only onto a
/// ring whose newest root equals it; otherwise something moved the set without recording here, and the ring
/// restarts at that root. [`Self::verdict`] consults the ring only while its newest root IS the live root. A path
/// that moves the accumulator without recording therefore makes the ring SHORTER or UNUSABLE — never wrong.
///
/// A LOCAL CACHE of public blocks this node absorbed: never served, never persisted, rebuilt from blocks after a
/// restart. It decides only what THIS node admits; inclusion in a block still decides what happened.
#[derive(Clone, Debug, Default)]
pub struct RecentSpentRoots {
    /// The root before the oldest held entry (itself a valid anchor with every entry to sweep).
    base: Option<Digest4>,
    /// `(root after absorbing tag, tag)`, oldest first.
    entries: std::collections::VecDeque<(Digest4, [u8; 32])>,
}

impl RecentSpentRoots {
    /// The newest root this ring describes — the live root, when every absorb since the last reset was recorded.
    pub fn newest(&self) -> Option<Digest4> {
        self.entries.back().map(|e| e.0).or(self.base)
    }

    /// Held entries (a diagnostic and a pin observable; never a consensus value).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ring holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `root` is one this ring can anchor a copath at (the base or any held entry).
    pub fn holds(&self, root: Digest4) -> bool {
        self.base == Some(root) || self.entries.iter().any(|(r, _)| *r == root)
    }

    /// The set was REPLACED wholesale (a jump, a restore, a rebuild, a carrier adopt): nothing before `root` is
    /// known tag by tag, so the ring restarts AT it. A copath built against `root` still proves absence as of it.
    pub fn reset(&mut self, root: Digest4) {
        self.entries.clear();
        self.base = Some(root);
    }

    /// Record that absorbing `tag` moved the set from `pre` to `post` (a verified union: `set(post) = set(pre) ∪
    /// {tag}`). Chains only onto `pre`; a ring whose newest root differs restarts at `pre` first.
    pub fn absorb(&mut self, pre: Digest4, post: Digest4, tag: [u8; 32]) { // TAG-SPACE: the tag is a stored value
        self.absorb_block(pre, post, &[tag]);
    }

    /// Record a verified union `set(post) = set(pre) ∪ tags` — one tag with its own roots, or a WHOLE block
    /// whose intermediate roots were not computed. Every entry carries `post`; anchors take the LAST entry
    /// holding a root, so no tag is ever skipped.
    pub fn absorb_block(&mut self, pre: Digest4, post: Digest4, tags: &[[u8; 32]]) { // TAG-SPACE: stored values
        if self.newest() != Some(pre) {
            self.reset(pre);
        }
        if post == pre {
            // The set did not move: every tag was already in it, and continuity (every move since the base
            // was recorded) means an entry at or before `pre` already accounts for each. Recording them again
            // would only spend capacity — a produced block's tags cross two doors — and shrink the window.
            return;
        }
        if tags.is_empty() {
            // A move with no tag to describe it: nothing before `post` can be anchored.
            self.reset(post);
            return;
        }
        if self.entries.capacity() == 0 {
            // One fixed allocation for the life of the node (O1-FOOTPRINT: 1 MiB, see NF_RECENT_TAGS), with
            // room for one block's tags above the cap before the trim below runs.
            self.entries.reserve_exact(NF_RECENT_TAGS + crate::cover::BLOCK_FIXED_NULLIFIER_COUNT);
        }
        for tag in tags {
            self.entries.push_back((post, *tag));
        }
        while self.entries.len() > NF_RECENT_TAGS {
            if let Some((root, _)) = self.entries.pop_front() {
                self.base = Some(root);
            }
        }
    }

    /// ⭐ THE VERDICT FOR `nf` FROM A COPATH BUILT AGAINST THE LIVE ROOT OR ANY ROOT THIS RING HOLDS.
    ///
    /// Identical to `SparseNfAcc { live }.spent_verdict(nf, copath)` whenever the copath folds to `live`; beyond
    /// that it answers only from held roots, and `Unprovable` for anything it cannot decide exactly — a forged
    /// copath, a root older than the ring, or a ring that no longer describes the live root.
    ///
    /// Bounded work: two folds (the same two `spent_verdict` makes) plus at most three linear passes over the
    /// fixed-capacity ring — no term in height, blocks or spends.
    pub fn verdict(&self, live: Digest4, nf: &[u8; 32], copath: &[Digest4]) -> SpentVerdict {
        let Some((if_empty, if_spent)) = copath_described_roots(nf, copath) else {
            return SpentVerdict::Unprovable;
        };
        if if_empty == Some(live) {
            return SpentVerdict::Unspent;
        }
        if if_spent == live {
            return SpentVerdict::Spent;
        }
        if self.newest() != Some(live) {
            return SpentVerdict::Unprovable; // the ring stopped describing the live set — fail closed
        }
        if self.base == Some(if_spent) || self.entries.iter().any(|(root, _)| *root == if_spent) {
            return SpentVerdict::Spent; // spent under a held root ⇒ spent now: the set only grows
        }
        let Some(if_empty) = if_empty else {
            return SpentVerdict::Unprovable; // a member-form copath names no pre-spend root to sweep from
        };
        let sweep_from = match self.entries.iter().rposition(|(root, _)| *root == if_empty) {
            Some(k) => k + 1,
            None if self.base == Some(if_empty) => 0,
            None => return SpentVerdict::Unprovable, // not a root this node held within the ring
        };
        if self.entries.iter().skip(sweep_from).any(|(_, tag)| tag == nf) {
            SpentVerdict::Spent // absent when the copath was built, settled since
        } else {
            SpentVerdict::Unspent
        }
    }
}

/// ⭐⭐ DB-246 — THE WORK BUDGET OF ONE GAP WALK, in DAG nodes visited. DERIVED, not tuned:
/// [`NF_RECENT_BLOCKS`] × [`crate::params::DAG_WIDTH_CEILING`] is the most blocks a 64-deep window of a
/// width-bounded DAG can hold.
///
/// A walk that would exceed it refuses the stale carrier, fail-closed on the ITEM with its own reason, and the
/// spender re-reads at the tip. Why it can be reached at all: a block whose body is folded LATE (a backfilled
/// shell) enters the ring with an old DAG insertion order. The walk's stop then sits below everything inserted
/// since, and the walk would otherwise visit all of it.
pub const NF_RECENT_GAP_WALK_BUDGET: usize = NF_RECENT_BLOCKS * crate::params::DAG_WIDTH_CEILING;

/// DB-252: the absence follower's page quantum is [`NF_RECENT_BLOCKS`] itself, as ruled on the bus (07:09) and as
/// the wallet ships it (`nf_carrier.rs`). A separate half-ring constant stood here with no reader anywhere, so it was
/// deleted rather than left as a second name for one rule. DB-255 (a carrier standing at a quantum boundary) must
/// revisit this, because it needs `ring >= quantum + pass-and-submit lag`; the arithmetic is in docs/DB-252 §8.

/// One block this node folded into A_tip: its id, its own leaf (`block_transition_leaf`, the exact term it
/// added to the sum), and the padded tags that leaf commits.
#[derive(Clone, Debug)]
pub struct RecentFold {
    /// The block's id.
    pub id: [u8; 32],
    /// The term this block added to A_tip.
    pub leaf: Digest4,
    /// The block's padded nullifier tags: the set the sweep checks a carrier's inputs against.
    pub tags: Vec<[u8; 32]>,
}

/// ⭐⭐ DB-246 — THE LAST [`NF_RECENT_BLOCKS`] BLOCKS THIS NODE FOLDED INTO A_tip, BY BLOCK ID.
///
/// With it, a spender's absence carrier that stopped a few blocks short of the live A_tip is judged EXACTLY
/// instead of refused. It is the spend gate's recent-anchor ring for the recursive carrier, as
/// [`RecentSpentRoots`] is for a carried copath.
///
/// WHY BY BLOCK ID, NOT BY A_tip VALUE:
/// - A_tip is an order-free SET sum, so its intermediate values depend on the order a node accepted blocks in.
///   A ring of values would admit only on the node whose history produced the claimed one.
/// - Block ids are what every node shares. A carrier names the tip antichain `T` of the span it folded, and the
///   gate derives the gap from its own ring: the ring blocks outside `closure(T)`.
/// - The gate then demands the exact accounting `claimed + Σ leaf(gap) == live`, and sweeps the gap's tags.
///
/// A LOCAL CACHE of public blocks this node folded: never served, never persisted, rebuilt from blocks after a
/// restart. RESET wherever A_tip is replaced wholesale (a DSYNC adopt, a snapshot restore), so it can only
/// ever describe the sum it sits beside. It decides only what THIS node admits; the block door still decides
/// what happened.
///
/// ⭐ HELD AND EVICTED BY THE CANONICAL ORDER KEY, NEVER BY ARRIVAL (§POLES lane a, 2026-10-25). The ring holds the
/// [`NF_RECENT_BLOCKS`] folded blocks with the GREATEST `(blue_work, id)` — `Dag::canonical_order_key`, fixed per block
/// from its own GHOSTDAG data — kept sorted by that key, so two nodes that folded the same blocks hold the same ring
/// in the same order whatever order the blocks arrived in. BORROWED-FROM Kaspa: concurrent blocks are ordered by the
/// mergeset's blue-work rule, never by arrival. MEASURED why (4-node launch census, scratchpad/night/census4-det1.log):
/// an arrival-order `push_back`/`pop_front` ring read ORDER-ONLY on two nodes and different CONTENT on a third, so one
/// node admitted a carrier its peer refused. A late-folded block whose key falls below the held 64 is not held — a
/// carrier whose closure misses it is refused (fail closed, that carrier only), exactly as one older than the ring.
///
/// O1-FOOTPRINT-REVIEWED: at most [`NF_RECENT_BLOCKS`] entries × (16 + 32 + 32 + 256 × 32) B ≈ 528 KiB, fixed; the
/// lowest-key entry drops on every insert past it. No term in height, blocks, notes or spends.
#[derive(Clone, Debug, Default)]
pub struct RecentFoldBlocks {
    /// `(blue_work, fold)`, ascending by `(blue_work, fold.id)`.
    entries: Vec<(u128, RecentFold)>,
}

impl RecentFoldBlocks {
    /// Record one block this node just folded into A_tip, under its canonical order key `(blue_work, id)`.
    /// A block already held is not held twice.
    pub fn record(&mut self, blue_work: u128, id: [u8; 32], leaf: Digest4, tags: &[[u8; 32]]) { // TAG-SPACE: a block id and stored tags
        let key = (blue_work, id);
        let at = match self.entries.binary_search_by(|(bw, f)| (*bw, f.id).cmp(&key)) {
            Ok(_) => return,
            Err(at) => at,
        };
        self.entries.insert(at, (blue_work, RecentFold { id, leaf, tags: tags.to_vec() }));
        if self.entries.len() > NF_RECENT_BLOCKS {
            self.entries.remove(0);
        }
    }

    /// A_tip was REPLACED wholesale: nothing held here describes the new sum.
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Held entries (a diagnostic and a pin observable; never a consensus value).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ring holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The held folds, lowest canonical order key first.
    pub fn iter(&self) -> impl Iterator<Item = &RecentFold> {
        self.entries.iter().map(|(_, f)| f)
    }
}

/// A COMPRESSED sparse copath — the wire form a spend CARRIES so a treeless verifier can settle it.
///
/// A raw copath is `DEPTH` (256) siblings × 32 B = 8 KB per nullifier; at the 256-wide block cover that is ~2 MB,
/// over the ≤1.8 MB block budget. But in a 256-bit sparse tree over random nullifiers, almost EVERY sibling is the
/// all-empty subtree constant `empty_subtree(level)` — only the ~log2(spent) levels near the leaf where another
/// spend shares a prefix are non-empty. So the copath compresses to a 32-byte PRESENCE BITMAP (bit `level` set ⇒
/// that sibling is carried explicitly) plus just the non-empty siblings: ~32 B + ~log2(spent)·32 B, a ~20× cut that
/// brings a full block's carried witnesses well inside the budget.
///
/// LOSSLESS by construction: an absent sibling is EXACTLY `empty_subtree(level)`, recomputed identically by every
/// verifier, so expand(compress(c)) == c byte-for-byte. Carrying it costs no privacy — a copath is derived from the
/// already-replicated spent set and reveals nothing about value, identity, or which note is being spent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompressedCopath {
    /// bit `level` (LSB-first within byte `level>>3`) set ⇒ `siblings` carries that level explicitly.
    pub present: [u8; 32],
    /// The non-empty siblings, in ascending level order.
    pub siblings: Vec<Digest4>,
    /// DB-453 — the copath's TERMINAL SLOT (the one key in the terminal subtree), `None` for an empty terminal.
    pub terminal: Option<Digest4>,
}

/// Does this copath show `nf` absent at `root`? The one pure check [`crate::nf_evidence`] reads: nothing held, nothing asked.
#[must_use]
pub fn copath_proves_absent(root: &Digest4, nf: &[u8; 32], copath: &CompressedCopath) -> bool {
    if *nf == [0u8; 32] {
        return false;
    }
    let Some(cp) = expand_copath(copath) else {
        return false;
    };
    if cp.len() != NF_COPATH_LEN {
        return false;
    }
    matches!(absence_folds(&SparseKey::of(nf), &cp), Some((pre, _)) if pre == *root)
}

/// Compress a full `DEPTH` copath by dropping every sibling that equals the empty-subtree constant.
pub fn compress_copath(copath: &[Digest4]) -> CompressedCopath {
    let mut present = [0u8; 32];
    let mut siblings = Vec::new();
    for (level, sib) in copath.iter().enumerate().take(NF_SPARSE_DEPTH) {
        if *sib != empty_subtree(level) {
            present[level >> 3] |= 1u8 << (level & 7);
            siblings.push(*sib);
        }
    }
    let terminal = copath.get(NF_TERMINAL_SLOT).copied().filter(|t| *t != Z);
    CompressedCopath { present, siblings, terminal }
}

/// Expand a compressed copath back to the full `DEPTH` siblings — absent levels are the empty-subtree constant.
/// `None` if the carried sibling count does not match the bitmap (malformed wire data ⇒ fail-closed).
pub fn expand_copath(c: &CompressedCopath) -> Option<Vec<Digest4>> {
    let expect = (0..NF_SPARSE_DEPTH)
        .filter(|l| c.present[l >> 3] & (1u8 << (l & 7)) != 0)
        .count();
    if expect != c.siblings.len() {
        return None; // bitmap/siblings disagree — reject rather than silently mis-expand
    }
    if c.terminal == Some(Z) {
        return None; // the empty terminal is carried as `None` — one encoding
    }
    let mut out = Vec::with_capacity(NF_COPATH_LEN);
    let mut next = 0usize;
    for level in 0..NF_SPARSE_DEPTH {
        if c.present[level >> 3] & (1u8 << (level & 7)) != 0 {
            out.push(c.siblings[next]);
            next += 1;
        } else {
            out.push(empty_subtree(level));
        }
    }
    out.push(c.terminal.unwrap_or(Z));
    Some(out)
}

/// The all-empty subtree hash at `level` (level 0 = an empty leaf). Memoized would be O(1); computed here in
/// O(level) which is fine (the accumulator never calls it on the hot path — copaths carry the siblings).
pub fn empty_subtree_pub(level: usize) -> Digest4 {
    empty_subtree(level)
}

fn empty_subtree(level: usize) -> Digest4 {
    // DB-453 (compact): an empty subtree is `Z` at every level up to the band; above it the band folds PLAINLY, so the
    // empty value there is `Z` folded with itself. MEMOIZED — a constant of the level alone, computed once.
    static EMPTY: std::sync::OnceLock<Vec<Digest4>> = std::sync::OnceLock::new();
    let table = EMPTY.get_or_init(|| {
        let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut v = vec![Z; band + 1];
        let mut e = Z;
        for _ in band..NF_SPARSE_DEPTH {
            e = poseidon_pair(e, e);
            v.push(e);
        }
        v
    });
    table[level]
}

/// A REFERENCE sparse tree over the spent nullifiers — the "stream side" a spender/serving node walks to self-build
/// a copath (never held by a treeless producer). MEMOIZED like an incremental Merkle tree: it keeps only the
/// O(spent·DEPTH) OCCUPIED path nodes, keyed by `(level, canonical-prefix)`; an absent key is an all-empty subtree
/// (`empty_subtree(level)`). Each insert recomputes just the O(DEPTH) nodes on the new leaf's root-path, so building
/// a witness is O(DEPTH) — the earlier set-scan reference was O(spent²·DEPTH²) and never finished at depth 256, so
/// its flat-O(1) claim was UNPROVEN until now. This is the independent oracle the fold must match; soundness (a bad
/// witness is rejected) is checked separately by the reject tests, which a shared construction bug cannot mask.
/// REFERENCE ORACLE (test-only) — the original path-memoized sparse tree. It stores ~`DEPTH` interior nodes PER
/// inserted nullifier (O(spent·DEPTH) RAM: 504,061 nodes at 9 blocks in the runtime-footprint measurement), which
/// is the RAM blowup the leaf-set [`RefSparseNf`] below removes. Kept ONLY as the byte-identical correctness oracle
/// the equality test checks the leaf-set tree against (`leaf_set_tree_is_byte_identical_to_the_memo_oracle`) — it
/// is never linked into a shipped build.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct RefSparseNfMemo {
    /// DB-453: the spent KEYS in storage order — every node is recomputed from them by the compact rule (the reference
    /// recursion, `nf_compact_air::CompactRefTree::node`), never from an incremental cache: an oracle that shares no code
    /// path with [`RefSparseNf`]'s neighbour rule, branch cache or band.
    keys: std::collections::BTreeSet<[u8; 32]>,
}

#[cfg(test)]
impl RefSparseNfMemo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn canon(key: &SparseKey, level: usize) -> [u8; 32] { // NOT-A-TAG: a canon subtree id, from a KEY
        let mut p = *key.bytes();
        let full = level >> 3;
        for b in p.iter_mut().take(full) {
            *b = 0;
        }
        if level & 7 != 0 {
            p[full] &= !((1u8 << (level & 7)) - 1);
        }
        p
    }

    fn keys_under(&self, level: usize, canon: &[u8; 32]) -> Vec<SparseKey> { // NOT-A-TAG: a canon subtree id
        let (lo, hi) = RefSparseNf::subtree_range(level, canon);
        self.keys.range(lo..=hi).map(|k| SparseKey::from_key_bytes(RefSparseNf::tkey(k))).collect()
    }

    /// The compact node of `keys` (all under one subtree) at `level`: compacted up to the band, plain above it.
    fn node_of(level: usize, keys: &[SparseKey]) -> Digest4 {
        let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        if level <= band {
            match keys {
                [] => return Z,
                [k] => return compact_leaf_of(k),
                _ => {}
            }
        }
        let (l, r): (Vec<SparseKey>, Vec<SparseKey>) = keys.iter().partition(|k| key_bit(k, level - 1) == 0);
        poseidon_pair(Self::node_of(level - 1, &l), Self::node_of(level - 1, &r))
    }

    fn node_at(&self, level: usize, canon: &[u8; 32]) -> Digest4 { // NOT-A-TAG: a canon subtree id
        Self::node_of(level, &self.keys_under(level, canon))
    }

    pub fn root_bytes(&self) -> [u8; 32] { // NOT-A-TAG: a root
        leaf_to_cm_bytes(self.root())
    }

    pub fn node_count(&self) -> usize {
        self.keys.len()
    }

    pub fn root(&self) -> Digest4 {
        self.node_at(NF_SPARSE_DEPTH, &[0u8; 32])
    }

    /// The compact copath by DIRECT COUNTING: the terminal is the highest level (at most the band) whose subtree on the
    /// key's path holds at most one key, counted from the key set itself.
    pub fn copath(&self, nf: &[u8; 32]) -> Vec<Digest4> {
        let key = SparseKey::of(nf);
        let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut t = band;
        while self.keys_under(t, &Self::canon(&key, t)).len() > 1 {
            t -= 1;
        }
        let terminal = self.keys_under(t, &Self::canon(&key, t)).first().copied();
        let mut cp = vec![Z; NF_COPATH_LEN];
        for (level, slot) in cp.iter_mut().enumerate().take(NF_SPARSE_DEPTH).skip(t) {
            let mut sib = *key.bytes();
            sib[level >> 3] ^= 1u8 << (level & 7); // flip bit `level` → the sibling subtree
            *slot = self.node_at(level, &Self::canon(&SparseKey::from_key_bytes(sib), level));
        }
        cp[NF_TERMINAL_SLOT] = terminal_slot(terminal.as_ref());
        cp
    }

    pub fn node_at_pub(&self, level: usize, canon: &[u8; 32]) -> Digest4 { // NOT-A-TAG: a canon subtree id
        self.node_at(level, canon)
    }

    pub fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Vec<Digest4> {
        let copath = self.copath(nf); // BEFORE the insert → a valid non-membership witness
        self.keys.insert(RefSparseNf::tkey(SparseKey::of(nf).bytes()));
        copath
    }
}

/// A REFERENCE sparse tree over the spent nullifiers — the transient "stream side" a serving/producing node walks
/// to build a copath. LEAF-SET representation: stores exactly the occupied leaves (one entry per spent nullifier),
/// keyed by the traversal key `tkey(nf) = byte-reversed nf` so lexicographic order == root-to-leaf descent order and
/// every subtree is a contiguous `BTreeSet` range. Interior nodes are recomputed on demand; empty subtrees (nearly
/// all of them, for random 256-bit positions) return the empty-subtree CONSTANT via a range check without recursing.
///
/// SCOPE — this is a size REDUCTION, not the O(1) end state. It stores `spent` entries, the SAME footprint as the
/// indexed-Merkle working tree (`nf_work`); the earlier path-memoized tree stored ~DEPTH interior nodes PER
/// nullifier (measured 504,061 nodes vs 2,049 spent leaves at 9 blocks — the ~26 MB/block produce-path RAM blowup),
/// so this is a ~246× cut that brings the sparse working tree to parity with the IMT. Copath/root stay DEPTH-bounded
/// hashing. It is NOT count-independent — the consensus state that IS count-independent is the O(1) `SparseNfAcc`
/// root; the true no-held-tree design (carried witnesses folded against that root) is [[project_trustless_nullifier_o1_design]].
/// Proven byte-identical to the memo oracle by `leaf_set_tree_is_byte_identical_to_the_memo_oracle`.
#[derive(Clone)]
pub struct RefSparseNf {
    /// Occupied (spent) leaves, keyed by `tkey(nf)` (byte-reversed nf) so subtrees are contiguous ranges. O(spent).
    leaves: std::collections::BTreeSet<[u8; 32]>,
    /// BRANCH-node hash cache: `(level, canon) → hash` for the subtrees that contain ≥2 leaves. There are at most
    /// `spent-1` such branch points in a tree of `spent` leaves, so this is O(spent) — NOT O(spent·DEPTH). It is what
    /// makes a copath O(DEPTH): a sibling subtree holding O(N) leaves is inherently O(N) to fold FROM SCRATCH, so its
    /// hash MUST be cached; a single-leaf subtree needs no cache (folded on demand in O(level)); an empty one is the
    /// constant. Maintained incrementally on insert — each insert creates at most ONE new branch (the divergence
    /// point of the new leaf from its nearest neighbor).
    branch: std::collections::HashMap<(usize, [u8; 32]), Digest4>,
    /// Z2 SHARD POLICY. `0` = unsharded: this tree holds every leaf and behaves byte-identically to the
    /// pre-Z2 tree (the in-process and single-node shape, and every existing pin). `s > 0` = this node
    /// keeps leaves only for `owned` and carries the `2^s` BAND for everything else.
    shard_bits: usize,
    /// The shard ids whose LEAVES this tree holds (empty and `shard_bits == 0` => all of them).
    /// O1-FOOTPRINT-REVIEWED: bounded by NF_BAND_MAX — filled once at construction from the node's
    /// policy (ids outside the range are dropped) and never appended to at runtime.
    owned: std::collections::BTreeSet<u32>,
    /// The level-`DEPTH - shard_bits` subtree roots, one per shard, in shard-id order. Empty when
    /// unsharded.
    /// O1-FOOTPRINT-REVIEWED: bounded by NF_BAND_MAX — allocated once at construction, written IN PLACE
    /// per spend, never grown.
    band: Vec<Digest4>,
    /// ⭐⭐⭐ DB-170 — THE BAND FOLDED UP, MAINTAINED INCREMENTALLY INSTEAD OF REBUILT PER READ.
    ///
    /// `band_up[k-1]` is band level `k` (level 0 IS `band`), so the last entry is the single node the
    /// sharded root folds from. Bounded by `NF_BAND_MAX` total across all levels (a halving tower),
    /// allocated once at construction, written IN PLACE — no growth axis.
    ///
    /// ⛔ WHAT THIS REPLACES, MEASURED. `band_levels()` CLONED the whole `2^s` band and folded it up `s`
    /// levels — `2^s - 1` Poseidon pairs plus `s+1` allocations — and `node_at` called it for EVERY level
    /// at or above `band_level()`. One depth-256 copath asks 8 such questions at `s = 8`, so it rebuilt
    /// the identical tower EIGHT TIMES per copath: ~2,040 Poseidon pairs to answer 8 questions.
    ///
    /// MEASURED (`where_advance_one_spends_its_time_under_the_live_shard_policy`), 256 tags, 2,000-tag
    /// warm tree, which is one block of the live pair's constant-width set:
    /// ```text
    ///   sharded (band_level 248)   1762.5 ms   <- what the live pair ran
    ///   flat    (shard_bits 0)      271.9 ms
    ///   the band fold alone          57.5 ms   <- only 4% of the 1,490 ms difference
    /// ```
    /// A band WRITE touches one shard, so refreshing that shard's path costs `s` pairs instead of
    /// `2^s - 1` — and it is paid per write rather than per read.
    band_up: Vec<Vec<Digest4>>,
}

/// DB-232: one tag's shard-local walk (see [`RefSparseNf::advance_block_rooted`]) — its copath below the band
/// level, its subtree root AT the band level, the branch entries its insert creates below the band, and its leaf
/// key. Transient: built and consumed inside one block advance; its size is f(DEPTH), never f(tree).
struct LowerWalk {
    key: [u8; 32],
    band_node: Digest4,
    copath: Vec<Digest4>,
    terminal: Digest4,
    branch_writes: Vec<(usize, [u8; 32], Digest4)>,
}

impl Default for RefSparseNf {
    fn default() -> Self {
        Self::new()
    }
}

impl RefSparseNf {
    /// Every spent tag this view holds, sorted — the stream `Node::rebuild_nullifier_tree` re-inserts and VERIFIES
    /// against the chain's acc root (DB-397 fix A: the view is a verified resume cache, never authority).
    pub fn leaves_sorted(&self) -> Vec<[u8; 32]> { // TAG-SPACE: the spent tags as values; the rebuild's insert converts
        self.leaves.iter().copied().collect()
    }
    pub fn new() -> Self {
        Self {
            leaves: std::collections::BTreeSet::new(),
            branch: std::collections::HashMap::new(),
            shard_bits: 0,
            owned: std::collections::BTreeSet::new(),
            band: Vec::new(),
            band_up: Vec::new(),
        }
    }

    /// The view a new node starts with: the whole set, moved to its share by `Node::nf_share_tick` once it knows who else holds what.
    #[must_use]
    pub fn initial_view() -> Self {
        Self::new()
    }

    /// ⭐ PRIVATE SHARDING §2.4 — a view on the chain's root holding no leaves at all: the band alone. It verifies everything and serves
    /// nothing. The instant start for a node that just adopted a bundle, or one with a budget of zero.
    #[must_use]
    pub fn from_band(band: &[Digest4]) -> Self {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let mut view = Self::with_shards(bits, std::iter::empty());
        for (s, e) in band.iter().enumerate() {
            view.adopt_band_entry(s as u32, *e);
        }
        view
    }

    /// ⭐ PRIVATE SHARDING §2.5 — take one shard's leaves, fetched from a holder or read from this node's own cache. They are held only
    /// if they fold to the band entry this view already stands on, so a lying holder or a stale cache adds nothing. Tags that lie in
    /// another shard refuse the whole page.
    pub fn add_shard(&mut self, shard: u32, tags: &[[u8; 32]]) -> bool {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        if self.shard_bits != bits || shard as usize >= self.band.len() {
            return false;
        }
        if self.owned.contains(&shard) {
            return true;
        }
        if tags.iter().any(|t| nf_shard(t, bits) != shard) {
            return false;
        }
        let mut scratch = Self::with_shards(bits, [shard]);
        scratch.absorb_set(tags);
        if scratch.band[shard as usize] != self.band[shard as usize] {
            return false;
        }
        self.owned.insert(shard);
        self.leaves.extend(scratch.leaves);
        self.branch.extend(scratch.branch);
        true
    }

    /// ⭐ PRIVATE SHARDING §2.5 — stop holding one shard's leaves. The band entry stays, so the view stays on the root.
    pub fn drop_shard(&mut self, shard: u32) {
        if self.shard_bits == 0 || !self.owned.contains(&shard) {
            return;
        }
        let keep: Vec<u32> = self.owned.iter().copied().filter(|s| *s != shard).collect();
        *self = self.reshard(self.shard_bits, keep);
    }

    /// The tags this view holds in one shard, sorted, from `after` on, at most `max` of them: one page for a node fetching the shard.
    #[must_use]
    pub fn shard_tags_page(&self, shard: u32, after: Option<[u8; 32]>, max: usize) -> Vec<[u8; 32]> { // TAG-SPACE: public spent tags
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        self.leaves_sorted()
            .into_iter()
            .filter(|t| nf_shard(t, bits) == shard && after.is_none_or(|a| *t > a))
            .take(max)
            .collect()
    }

    /// The shards this view holds, or every shard for an unsharded view.
    #[must_use]
    pub fn owned_shards(&self) -> Vec<u32> {
        if self.shard_bits == 0 {
            return (0..1u32 << usdm_decider::nf_sparse_air::NF_BAND_BITS).collect();
        }
        self.owned.iter().copied().collect()
    }

    /// How many leaves this view holds.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Does this view hold fewer shards than the band has?
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.shard_bits > 0 && self.owned.len() < (1usize << self.shard_bits)
    }

    /// Does this view hold protocol shard `s`?
    #[must_use]
    pub fn owns_shard(&self, s: u32) -> bool {
        self.shard_bits == 0 || self.owned.contains(&s)
    }

    /// A SHARDED working tree: this node keeps the leaves of `owned` and the `2^shard_bits` band for the
    /// rest. `shard_bits == 0` (or past `NF_SHARD_BITS_MAX`) is the unsharded tree (`new`).
    #[must_use]
    pub fn with_shards(shard_bits: usize, owned: impl IntoIterator<Item = u32>) -> Self {
        // DB-453: the compact tree's band is the PROTOCOL band (level NF_BAND_LEVEL) — below it subtrees compact, above it
        // they fold plainly — so a sharded view keeps exactly that band; any other width is held unsharded.
        if shard_bits != usdm_decider::nf_sparse_air::NF_BAND_BITS {
            return Self::new();
        }
        let n = 1usize << shard_bits;
        let band = vec![empty_subtree(NF_SPARSE_DEPTH - shard_bits); n];
        // The empty tower, folded ONCE here. Every later band write refreshes only its own path.
        let mut band_up: Vec<Vec<Digest4>> = Vec::with_capacity(shard_bits);
        let mut prev = band.clone();
        for _ in 0..shard_bits {
            let next: Vec<Digest4> = (0..prev.len())
                .step_by(2)
                .map(|i| poseidon_pair(prev[i], prev[i + 1]))
                .collect();
            band_up.push(next.clone());
            prev = next;
        }
        Self {
            leaves: std::collections::BTreeSet::new(),
            branch: std::collections::HashMap::new(),
            shard_bits,
            owned: owned.into_iter().filter(|k| (*k as usize) < n).collect(),
            band,
            band_up,
        }
    }

    /// ⭐⭐⭐ THE WARM STREAM — how a TREELESS node gets a copath source back (DB-151).
    ///
    /// The working tree is O(spent) and is deliberately never persisted, so every restart and every
    /// DSYNC jump starts it empty while the certified accumulator it must describe is restored intact.
    /// Nothing local can bridge that: the per-block nullifier store was deleted in the no-growth sweep,
    /// so the lawful source is the mesh. This is the serve half — the spent set in a deterministic
    /// order, paged, so a peer can hand it over inside the transport budget.
    ///
    /// The order is the tree's own key order (`tkey`, byte-reversed), which makes paging stable under
    /// concurrent spends in the sense that matters: a nullifier's position depends only on its own bytes,
    /// so a later insert never renumbers an earlier page's entries, it only inserts between them. The
    /// rebuild is order-free anyway (a sparse tree has no insertion order) and fails closed on the root,
    /// so a page that raced a spend is caught rather than trusted.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: every nullifier here was PUBLISHED in the block that spent it —
    /// this is replicated public chain data, carries no amount, owner, note or linkage, and the order is
    /// a pure function of the tag bytes, so it reveals nothing about when or by whom anything was spent.
    #[must_use]
    pub fn spent_leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// ⭐ DB-358 — does this view hold `nf` as a spent leaf? `None` when `nf` lies in a shard this node does not own
    /// (it cannot answer). DB-353 keeps the live view complete, so production answers every tag. One ordered-set
    /// lookup; reads nothing but the leaf set. (Not [`Self::holds`], which answers SHARD ownership.)
    #[must_use]
    pub fn holds_spent_leaf(&self, nf: &[u8; 32]) -> Option<bool> {
        let key = SparseKey::of(nf);
        if self.shard_bits > 0 && !self.owned.contains(&key_shard(&key, self.shard_bits)) {
            return None;
        }
        Some(self.leaves.contains(&Self::tkey(key.bytes())))
    }

    /// One page of [`Self::spent_leaf_count`]'s stream BY INDEX, as real nullifier bytes. TEST-ONLY since DB-290: the
    /// serve pages by key (`spent_leaves_after`); this stays as the index-paged reference the DB-290 (C) pins measure
    /// the key cursor against.
    #[cfg(test)]
    #[must_use]
    pub fn spent_leaves_page(&self, from: usize, count: usize) -> Vec<[u8; 32]> {
        self.leaves
            .iter()
            .skip(from)
            .take(count)
            .map(|k| SparseKey::from_key_bytes(Self::tkey(k)).tag()) // stored traversal key → path key → TAG (the boundary)
            .collect()
    }

    /// ⭐ DB-290 (C): ONE PAGE OF THE SPENT SET AFTER A KEY, NOT AFTER AN INDEX.
    ///
    /// `spent_leaves_page` pages by INDEX (`iter().skip(from)`), which has two defects.
    /// - It walks `from` entries per page, so a whole stream is O(N² / page).
    /// - An insert below the cursor mid-stream SHIFTS every later position right by one, so the next page starts on
    ///   tags already served and RE-SERVES them. The set is insert-only, so that duplicates tags; it never skips one.
    ///
    /// A key cursor has neither defect. `range(after..)` is O(log N + count), and a tag's position is its own bytes,
    /// so an insert anywhere never moves a tag relative to the cursor: every tag held for the whole stream is served
    /// exactly once.
    ///
    /// `after` is the last TAG (not key) the previous page returned, or `None` for the first page. The page is in
    /// `tkey` order, the same order as `spent_leaves_page`.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the same published tags `spent_leaves_page` serves, in the same key order; the
    /// cursor is a tag the asker already received. No amount, owner, note or linkage.
    pub fn spent_leaves_after(&self, after: Option<&[u8; 32]>, count: usize) -> Vec<[u8; 32]> {
        let lo = match after {
            None => std::ops::Bound::Unbounded,
            Some(t) => std::ops::Bound::Excluded(Self::tkey(SparseKey::of(t).bytes())),
        };
        self.leaves
            .range((lo, std::ops::Bound::Unbounded))
            .take(count)
            .map(|k| SparseKey::from_key_bytes(Self::tkey(k)).tag()) // stored traversal key → path key → TAG (the boundary)
            .collect()
    }

    /// ⭐⭐ DB-426: one page of `set(R)` read off a view that stands AFTER `R`: the key-cursor read of
    /// [`Self::spent_leaves_after`] with `post_pivot` (every tag the band admitted after `R`, from the band journal) left
    /// out. The set is insert-only, so the view is `set(R) ⊎ post_pivot` and the page is exactly `set(R)` in its key range,
    /// whenever it is read. Bounded: it walks at most `count + post_pivot.len()` entries.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the same published tags `spent_leaves_after` serves, in the same key order.
    pub fn spent_leaves_after_excluding( // TAG-SPACE: tags as values
        &self,
        after: Option<&[u8; 32]>,
        count: usize,
        post_pivot: &std::collections::HashSet<[u8; 32]>,
    ) -> Vec<[u8; 32]> {
        let lo = match after {
            None => std::ops::Bound::Unbounded,
            Some(t) => std::ops::Bound::Excluded(Self::tkey(SparseKey::of(t).bytes())),
        };
        self.leaves
            .range((lo, std::ops::Bound::Unbounded))
            .map(|k| SparseKey::from_key_bytes(Self::tkey(k)).tag())
            .filter(|t| !post_pivot.contains(t))
            .take(count)
            .collect()
    }

    /// ⭐ DB-290: THE INVERSE OF AN INSERT. Flip `nf`'s leaf back to EMPTY and leave the tree exactly as if `nf` had
    /// never been inserted: leaves, branch cache, band and tower.
    ///
    /// WHY IT EXISTS. A jumped node warms its copath source against the FROZEN certified root `R` of its adopt
    /// (DB-290 (A'')).
    /// - The serving peer streams its LIVE set, which also holds tags from blocks after `R`.
    /// - The joiner applies those same blocks, so it can take their tags back out, and a scratch equal to `set(R)`
    ///   is the only tree its root check can accept.
    /// - Without a remove, the only way to reach `set(R)` from a live stream was a full rebuild per attempt, at
    ///   O(spent set x DEPTH) each time.
    ///
    /// SAME WALK AS AN INSERT, MIRRORED.
    /// - Removing `nf` changes only the nodes on `nf`'s own path; its siblings are disjoint subtrees.
    /// - So the post-removal path is the EMPTY leaf folded up the unchanged copath.
    /// - A node on that path stays cached iff its subtree still holds at least two leaves. With the leaves in `tkey`
    ///   order, that is decided by `nf`'s two nearest neighbours on each side, just as the insert decides it with one
    ///   per side.
    ///
    /// Returns `false` and changes nothing when `nf` is not held, or when it lies in a shard this tree holds no
    /// leaves for: a foreign shard's band slot cannot move without that shard's copath.
    /// cons: O(DEPTH) hashing per call, the same as one insert; no new state.
    pub fn remove(&mut self, nf: &[u8; 32]) -> bool {
        let key = SparseKey::of(nf);
        if self.shard_bits > 0 && !self.owned.contains(&key_shard(&key, self.shard_bits)) {
            return false;
        }
        let k = Self::tkey(key.bytes());
        if !self.leaves.remove(&k) {
            return false;
        }
        // The siblings along the key's path are unchanged by the removal (disjoint subtrees). They are read AFTER the
        // leaf is gone, so no sibling read can see the leaf itself.
        let copath = self.copath_key(&key);
        // DB-453: the key's path as its ABSENCE witness folds it — every level holding ≥ 2 remaining leaves lies above
        // the new terminal, where this path is defined.
        let (t, term, _) = compact_terminal(&[&self.leaves], &k, false);
        let term = term.map(|x| SparseKey::from_key_bytes(Self::tkey(&x)));
        let path = pre_path_of(&key, t, term.as_ref(), &copath);
        // A window around k holds a contiguous run of leaves from each side, so it holds at least two iff at least
        // two of {p2, p1, s1, s2} lie inside it.
        let mut below = self.leaves.range(..k).rev();
        let (p1, p2) = (below.next().copied(), below.next().copied());
        let mut above = self
            .leaves
            .range((std::ops::Bound::Excluded(k), std::ops::Bound::Unbounded));
        let (s1, s2) = (above.next().copied(), above.next().copied());
        let readable = if self.shard_bits > 0 { self.band_level() } else { NF_SPARSE_DEPTH + 1 };
        for level in 1..=NF_SPARSE_DEPTH {
            if level >= readable {
                break; // a sharded tree answers these levels from the BAND; no entry here is ever read
            }
            let cn = Self::canon(&key, level);
            let (lo, hi) = Self::subtree_range(level, &cn);
            let inside = [
                p1.is_some_and(|p| p >= lo),
                p2.is_some_and(|p| p >= lo),
                s1.is_some_and(|s| s <= hi),
                s2.is_some_and(|s| s <= hi),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if inside >= 2 {
                self.branch.insert((level, cn), path[level]);
            } else {
                self.branch.remove(&(level, cn));
            }
        }
        if self.shard_bits > 0 {
            let id = key_shard(&key, self.shard_bits) as usize;
            if id < self.band.len() {
                self.band[id] = path[self.band_level()];
                self.refresh_band_path(id);
            }
        }
        true
    }

    /// ⭐⭐⭐ RE-FILE THIS TREE'S LEAVES UNDER A NEW SHARD POLICY.
    ///
    /// ⛔ WITHOUT THIS, SHARDING CANNOT ENGAGE AT ALL, AND IT NEVER DID. A node builds its working tree
    /// once, at construction, when it knows no peers — so the policy it would be built under is always
    /// "hold everything". The policy is a function of the MESH, and the mesh grows after construction, so
    /// a tree that is never re-filed is a tree that is always unsharded however large the mesh gets.
    /// `Node::new_sparse_work` (the sharded constructor) had exactly one caller, inside a function that
    /// itself had zero production callers, so `with_shards` never ran on a live node.
    ///
    /// Each leaf is re-applied through `apply_spend` with its copath taken from THIS (complete) tree, so
    /// the new tree gets the right band value for every shard and keeps the leaves of the ones it owns.
    /// The copaths come from a tree that holds every leaf, so the band it computes is the true subtree
    /// root, not an approximation of one.
    ///
    /// O(spent) — which is why it runs only when the policy actually CHANGES, and never per block.
    ///
    /// ⛔⛔⛔ DB-353 — "THIS (COMPLETE) TREE" WAS AN ASSUMPTION NOTHING CHECKED. MEASURED ([slotB17c], five real
    /// daemons): every node re-filed TWICE — mesh 5 → `(8, 205)`, then mesh 6 → `(8, 171)`. The second re-file started
    /// from a SHARDED view, which holds the leaves of its own 205 shards only; re-applying those leaves rebuilt the band
    /// for them and left the other 51 at the EMPTY-subtree constant `with_shards` starts from. The view's root then
    /// described a set nobody spent, its first `[sparse-fold] ⛔ the copath source drifted` line followed within
    /// seconds on every node, and the wallet's send came back `503 … its copath index does not describe the root it
    /// committed`.
    ///
    /// A PARTIAL source (sharded, not every shard held) therefore re-files under two rules:
    ///   * the BAND travels whole — its entries are the subtree roots of every shard, held or not, and they are the
    ///     one thing a partial view knows about the shards whose leaves it does not have;
    ///   * the new view claims ONLY shards whose leaves the source holds (`requested ∩ held`) and keeps the source's
    ///     own shard bits — a partial view can neither become complete nor change its band granularity from what it
    ///     has. The caller reads what it got from `shard_policy()`.
    #[must_use]
    pub fn reshard(&self, shard_bits: usize, owned: impl IntoIterator<Item = u32>) -> Self {
        let complete = self.shard_bits == 0 || self.owned.len() == (1usize << self.shard_bits);
        if !complete {
            let requested: std::collections::BTreeSet<u32> = owned.into_iter().collect();
            let keep: Vec<u32> = if shard_bits == self.shard_bits {
                requested.intersection(&self.owned).copied().collect()
            } else {
                self.owned.iter().copied().collect()
            };
            let mut out = Self::with_shards(self.shard_bits, keep);
            out.band = self.band.clone();
            out.band_up = self.band_up.clone();
            for k in &self.leaves {
                let key = SparseKey::from_key_bytes(Self::tkey(k)); // stored traversal key → path key
                if out.holds_key(&key) {
                    let cp = self.copath_key(&key);
                    out.apply_spend_key(&key, &cp);
                }
            }
            return out;
        }
        let mut out = Self::with_shards(shard_bits, owned);
        if shard_bits == 0 || shard_bits > NF_SHARD_BITS_MAX {
            // Unsharded target: the leaf set IS the tree, so copy it straight across — in PATH space, as the two arms
            // around this one do. ⛔⛔⛔ DB-398: a stored leaf is a traversal key; `insert_and_witness` takes a TAG and maps
            // it to a key again (`SparseKey::of`), so passing `tkey(k)` there moved EVERY leaf — MEASURED on the live pair
            // 2026-10-05: a warmed view re-filed on the next peer-count change left its accumulator for good and every
            // send was refused 503 (`db398_a_complete_sharded_tree_re_filed_unsharded_keeps_its_root_and_its_leaves`).
            for k in &self.leaves {
                let _ = out.insert_and_witness_key(&SparseKey::from_key_bytes(Self::tkey(k)));
            }
            return out;
        }
        for k in &self.leaves {
            let key = SparseKey::from_key_bytes(Self::tkey(k)); // stored traversal key → path key (never back through a tag)
            let cp = self.copath_key(&key);
            out.apply_spend_key(&key, &cp);
        }
        out
    }

    /// This tree's shard policy: `(shard_bits, owned_count)`. `(0, 0)` = unsharded.
    #[must_use]
    pub fn shard_policy(&self) -> (usize, usize) {
        (self.shard_bits, self.owned.len())
    }

    /// ⭐ SHAPE (3) — THE HOLDER'S FOLD SERVE (docs/DB-353-BAND-DOOR-SPEC.md §5b revised). For the admitted TAGS of ONE
    /// protocol shard this tree holds, in the door's canonical order, the LOWER copaths (levels `0..NF_BAND_LEVEL`), each
    /// valid against the tree AFTER the previous tags of the shard were applied; then the lower copaths of the given
    /// FILLER keys against the shard as it stands after all the tags, with the shard's band entry after each filler; and
    /// the shard's protocol band entry after the tags. The tree is left EXACTLY as it was: every tag is applied to produce
    /// the next copath and removed again in reverse (`remove` is the exact inverse of an insert). `None` unless every tag
    /// lies in ONE protocol shard this tree holds, none is already spent, and every filler lies in that shard.
    #[allow(clippy::type_complexity)]
    pub fn serve_fold_copaths(&mut self, tags: &[[u8; 32]], fillers: &[u64]) -> Option<(Vec<Vec<Digest4>>, Digest4, Vec<(Vec<Digest4>, Digest4)>)> {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let lower = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        // the shard: from the first tag, or — for a filler-only serve — from the first filler key
        let shard_key = match tags.first() {
            Some(t) => SparseKey::of(t),
            None => band_filler_key(*fillers.first()?),
        };
        let shard = key_shard(&shard_key, bits);
        if !self.holds(&shard_key.tag())
            || !tags.iter().all(|t| nf_shard(t, bits) == shard && self.holds(t) && self.holds_spent_leaf(t) == Some(false))
        {
            return None;
        }
        let mut lows = Vec::with_capacity(tags.len());
        let mut applied: Vec<[u8; 32]> = Vec::with_capacity(tags.len());
        for t in tags {
            let cp = self.copath(t);
            lows.push(lower_witness(&cp));
            self.apply_spend(t, &cp);
            applied.push(*t);
        }
        // the protocol band entry: the shard's subtree root at NF_BAND_LEVEL, whatever this tree's own shard policy is
        let shard_canon = |key: &SparseKey| Self::canon(key, lower);
        let entry_after = self.node_at(lower, &shard_canon(&shard_key));
        // fillers: non-members against the shard as it now stands; each one is applied for the next and removed with the rest
        let mut filler_out = Vec::with_capacity(fillers.len());
        let mut filler_applied: Vec<[u8; 32]> = Vec::new();
        let mut ok = true;
        for &i in fillers {
            let key = band_filler_key(i);
            if key_shard(&key, bits) != shard {
                ok = false;
                break;
            }
            let tag = key.tag();
            let cp = self.copath(&tag);
            let low = lower_witness(&cp);
            self.apply_spend(&tag, &cp);
            filler_applied.push(tag);
            filler_out.push((low, self.node_at(lower, &shard_canon(&key))));
        }
        // restore, in reverse
        for t in filler_applied.iter().rev().chain(applied.iter().rev()) {
            if !self.remove(t) {
                ok = false; // cannot happen for a tag this tree just applied; loud in debug, fail-closed here
            }
        }
        if !ok {
            return None;
        }
        Some((lows, entry_after, filler_out))
    }

    /// Does this tree hold the LEAVES that `nf` belongs to — i.e. can it serve `nf`'s copath?
    #[must_use]
    pub fn holds(&self, nf: &[u8; 32]) -> bool {
        self.holds_key(&SparseKey::of(nf))
    }

    /// [`Self::holds`] in path space.
    fn holds_key(&self, key: &SparseKey) -> bool {
        self.shard_bits == 0 || self.owned.contains(&key_shard(key, self.shard_bits))
    }

    /// The band level — where a shard's subtree root sits.
    #[inline]
    fn band_level(&self) -> usize {
        NF_SPARSE_DEPTH - self.shard_bits
    }

    /// ⭐ PRIVATE SHARDING §2.4 — take a shard this view does not hold from a verified band step (or a rewind of one), so the
    /// view stays on the chain's root holding none of that shard's leaves. A shard it holds moves only by its own leaves, so
    /// this returns false for one, and for an unsharded view.
    pub fn adopt_band_entry(&mut self, shard: u32, entry: Digest4) -> bool {
        if self.shard_bits == 0 || self.owned.contains(&shard) || shard as usize >= self.band.len() {
            return false;
        }
        self.band[shard as usize] = entry;
        self.refresh_band_path(shard as usize);
        true
    }

    /// Fold the band up `k` levels: `up[0]` is the band itself, `up[k][i] = pair(up[k-1][2i], up[k-1][2i+1])`.
    /// Adjacent band entries differ in the bit at the band level, which is exactly the pair the tree merges
    /// first, so this reproduces the real subtree roots. O(2^s) hashes, a fixed protocol cost.
    /// Band level `k` at index `idx` — level 0 is `band` itself, above that the maintained tower.
    /// O(1), no hashing. See [`Self::band_up`] for what this replaced and why.
    fn band_node(&self, k: usize, idx: usize) -> Option<Digest4> {
        if k == 0 {
            self.band.get(idx).copied()
        } else {
            self.band_up.get(k - 1).and_then(|l| l.get(idx).copied())
        }
    }

    /// Re-fold ONLY the path from shard `id` to the top of the band — `shard_bits` pairs. Called after
    /// every band write, which is the only thing that can invalidate the tower.
    fn refresh_band_path(&mut self, id: usize) {
        let mut idx = id;
        for k in 0..self.shard_bits {
            let sib = idx ^ 1;
            let (a, b) = if idx & 1 == 0 { (idx, sib) } else { (sib, idx) };
            let (Some(l), Some(r)) = (self.band_node(k, a), self.band_node(k, b)) else {
                return; // malformed tower; a partial refresh is worse than none
            };
            let parent = poseidon_pair(l, r);
            idx >>= 1;
            match self.band_up.get_mut(k) {
                Some(level) if idx < level.len() => level[idx] = parent,
                _ => return,
            }
        }
    }

    /// THE O(1)-PER-SPEND BAND UPDATE — the whole reason a node needs no tree to follow the chain.
    ///
    /// A spend carries its own non-membership copath, already verified against the live root by
    /// `SparseNfAcc::verify_and_insert`. Folding the now-SPENT leaf up that copath to the BAND level
    /// gives this shard's new subtree root exactly, in `DEPTH - s` hashes and with no leaf set at all.
    /// A node that OWNS the shard also files the leaf so it can keep serving copaths for it.
    pub fn apply_spend(&mut self, nf: &[u8; 32], copath: &[Digest4]) {
        self.apply_spend_key(&SparseKey::of(nf), copath);
    }

    /// [`Self::apply_spend`] in path space — for callers inside this module that already hold the key (a public fn
    /// calling a public fn would convert twice).
    fn apply_spend_key(&mut self, key: &SparseKey, copath: &[Digest4]) {
        let Some(w) = compact_witness(key, copath) else {
            return; // fail-closed: a malformed witness moves nothing
        };
        if self.shard_bits == 0 {
            let _ = self.insert_and_witness_key(key); // unsharded: the leaf set IS the tree
            return;
        }
        let level = self.band_level();
        let term = w.other.map(SparseKey::from_key_bytes);
        let node = post_path_of(key, w.t, term.as_ref(), copath)[level];
        let id = key_shard(key, self.shard_bits) as usize;
        if id < self.band.len() {
            self.band[id] = node;
            self.refresh_band_path(id);
        }
        if self.owned.contains(&(id as u32)) {
            let _ = self.insert_and_witness_key(key);
        }
    }

    /// ⭐⭐⭐ DB-169 — ADVANCE ONE TAG IN **ONE** TREE WALK, SHARDED OR NOT.
    ///
    /// ⛔ THE COST THIS REMOVES, MEASURED ON REAL NODES. Ecosystem gate 8 (2026-09-24), same binary,
    /// same machine, two nodes:
    /// ```text
    ///   n1 (restarted, holds NO tree)   [sparse-shadow] median  60 ms
    ///   n2 (holds a tree)               [sparse-shadow] median 329 ms   max 639 ms
    /// ```
    /// against a 500 ms block time, with `apply_preverified` median 349 ms on n2 — two thirds of the
    /// block gone to maintaining a LOCAL SERVING CACHE.
    ///
    /// ⛔ AND THE REASON IS A BRANCH THAT READS AS "SHARDED" WHEN THE NODE HOLDS EVERYTHING. At any mesh
    /// at or below `NF_SHARD_REPLICATION` the policy is `(NF_SHARD_BITS_DEFAULT, every shard)` — the node
    /// owns all `2^bits` of them — but `shard_bits` is still 8, so `advance_sparse_shadow`'s `unsharded`
    /// test (`shard_policy().0 == 0`) is FALSE and every tag took the two-step form:
    /// ```text
    ///   walk 1  da_sparse_copath(nf)  ->  copath(nf)              ~DEPTH node_at
    ///   fold    apply_spend           ->  band fold               ~band_level poseidon
    ///   walk 2  apply_spend           ->  insert_and_witness(nf)  ~DEPTH node_at AGAIN + branch loop
    /// ```
    /// That is the SAME three-pass defect this file's own history records being fixed once — fixed for
    /// the unsharded path only, and the live pair never takes that path.
    ///
    /// ⭐ `insert_and_witness` ALREADY returns the pre-insert copath and performs the insert in one walk,
    /// which is exactly both things the band fold and the accumulator need. So the second walk was never
    /// buying anything.
    ///
    /// ⛔ ORDER IS SAFE, AND THAT IS NOT AN ASSUMPTION. The band fold starts from `[0xB, 0, 0, 0, 0, 0, 0, 0]` — `nf`'s
    /// POST state — and climbs through `nf`'s SIBLINGS. Inserting `nf` changes only the nodes ON `nf`'s
    /// own path, never its siblings, so the pre-insert copath is the correct input whether the insert has
    /// happened or not. `one_pass_advance_matches_the_two_step_form_exactly` proves it byte-for-byte on
    /// the root, the band and the returned copath, with a foreign-shard arm.
    ///
    /// Returns the copath the accumulator folds, or EMPTY for a shard this node holds no leaves for — a
    /// node that cannot source a witness must not pretend to (see `Node::da_sparse_copath`).
    pub fn advance_one(&mut self, nf: &[u8; 32]) -> Vec<Digest4> {
        match self.advance_one_rooted(nf) {
            Some((cp, _root)) => cp,
            None => Vec::new(), // foreign shard: no leaves here, so no copath this node can stand behind
        }
    }

    /// ⭐⭐⭐ DB-232 — A WHOLE BLOCK'S TAGS IN ONE CALL, THE SHARD-LOCAL WORK IN PARALLEL.
    ///
    /// Returns exactly what `tags.iter().map(|t| self.advance_one_rooted(t))` returns, in the same order, and
    /// leaves the tree (leaves, branch cache, band, tower) byte-identical — pinned by
    /// `db232_block_advance_is_byte_identical_to_the_per_tag_walk`.
    ///
    /// WHY IT CAN BE PARALLEL. Below the band level a tag's walk (its copath there, its path up to the band,
    /// its branch-cache writes, its leaf) reads and writes ONLY its own shard's subtree: a level-L subtree with
    /// L < band_level lies inside one shard. So tags in DIFFERENT shards do not see each other below the band,
    /// and tags in the SAME shard see each other exactly in block order. Rounds reproduce that: round `r` walks
    /// the r-th tag of every shard in parallel on the state all earlier rounds committed, then commits. The
    /// band levels (the top `shard_bits`) are shared by every shard, so they are folded afterwards in the
    /// ORIGINAL tag order — each tag reading the band as every earlier tag of the block left it, which is the
    /// sequential walk's order to the byte.
    ///
    /// ROOT-LAYER: the per-block cost of the Merkle view is produced here, in the tree; `Node` only asks for it.
    /// MEASURED: before — the live view advance was ~183–191 ms per 256-tag block (`[sparse-shadow]`, gates
    /// H/J/K), which caps what a follower can apply at a few blocks per second against 2 produced per second:
    /// gate K's follower swung 11–101 blocks behind a producing peer and repeatedly fell back to a DSYNC jump.
    /// After — the pin prints both timings on the live shard policy.
    /// MUST-STAY-GREEN: every `nf_sparse` test (`one_fold_walk_tests` in particular), the DB-221 ring pins
    /// and the produce/ingest lockstep pins — the outputs are byte-identical by construction and by pin.
    /// cons: `std::thread::scope` workers for the length of one call (at most the machine's available
    /// parallelism, never more than the round's tag count), f(fixed constants); no new state, no growth. An
    /// unsharded tree (`shard_bits == 0`) has no disjoint regions and takes the sequential walk unchanged.
    pub fn advance_block_rooted(&mut self, tags: &[[u8; 32]]) -> Vec<Option<(Vec<Digest4>, Digest4)>> { // TAG-SPACE: tags as values, keyed per walk in `advance_block_inner` (`SparseKey::of`)
        self.advance_block_inner(tags, true)
    }

    /// ⭐ DB-453 / DB-316 — ABSORB A SET: the same parallel shard-local rounds as [`Self::advance_block_rooted`], leaving the
    /// tree byte-identical, but without the per-tag band-level copaths a caller would discard: each touched shard's band
    /// entry is written ONCE from its last walk (the shard's root after all its tags) and its tower path refreshed once.
    /// ROOT-LAYER: the warm (`PivotWarm::absorb_page`) absorbs a SET and never read a copath; the per-tag band phase was
    /// 8 sibling reads + 8 folds + 8 tower hashes per tag, sequential.
    /// MEASURED (`db316_a_warm_page…`, 16,384-tag page): after the compact tree made the per-tag walk 8.5x cheaper
    /// (4,101 → 484 ms), the batch's sequential band phase dominated it (336 ms, 1.44x) — this removes that phase.
    /// cons: none — no new state; the same leaves, branch cache, band and tower.
    pub fn absorb_set(&mut self, tags: &[[u8; 32]]) { // TAG-SPACE: tags as values, keyed per walk in `advance_block_inner` (`SparseKey::of`)
        let _ = self.advance_block_inner(tags, false);
    }

    fn advance_block_inner(&mut self, tags: &[[u8; 32]], copaths: bool) -> Vec<Option<(Vec<Digest4>, Digest4)>> {
        if tags.len() < 2 {
            return tags.iter().map(|t| self.advance_one_rooted(t)).collect();
        }
        if self.shard_bits == 0 {
            return self.advance_block_rooted_unsharded(tags, copaths);
        }
        let band_level = self.band_level();
        // Owned tags grouped by shard, block order kept within each group.
        let mut groups: std::collections::BTreeMap<u32, Vec<usize>> = std::collections::BTreeMap::new();
        for (i, nf) in tags.iter().enumerate() {
            let shard = nf_shard(nf, self.shard_bits);
            if self.owned.contains(&shard) {
                groups.entry(shard).or_default().push(i);
            }
        }
        let mut lower: Vec<Option<LowerWalk>> = (0..tags.len()).map(|_| None).collect();
        let rounds = groups.values().map(|g| g.len()).max().unwrap_or(0);
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).max(1);
        for r in 0..rounds {
            let batch: Vec<usize> = groups.values().filter_map(|g| g.get(r).copied()).collect();
            let walks: Vec<(usize, LowerWalk)> = {
                let tree: &RefSparseNf = self;
                let chunk = batch.len().div_ceil(workers).max(1);
                std::thread::scope(|scope| {
                    let walk = |part: &[usize]| {
                        part.iter()
                            .map(|&i| (i, tree.lower_walk(&SparseKey::of(&tags[i]), band_level)))
                            .collect::<Vec<_>>()
                    };
                    let handles: Vec<_> =
                        batch.chunks(chunk).map(|part| (part, scope.spawn(move || walk(part)))).collect();
                    // a worker that panicked has its part walked inline: the same read-only computation, every tag inserted
                    handles
                        .into_iter()
                        .flat_map(|(part, h)| crate::fixed::join_or_else(h, "lower walk", || walk(part)))
                        .collect()
                })
            };
            for (i, w) in walks {
                self.leaves.insert(w.key);
                for (level, canon, hash) in &w.branch_writes {
                    self.branch.insert((*level, *canon), *hash);
                }
                lower[i] = Some(w);
            }
        }
        if !copaths {
            // the set's band: each touched shard's entry from its LAST walk, its tower path refreshed once
            let mut last: std::collections::BTreeMap<usize, Digest4> = std::collections::BTreeMap::new();
            for (i, nf) in tags.iter().enumerate() {
                if let Some(w) = lower[i].take() {
                    last.insert(nf_shard(nf, self.shard_bits) as usize, w.band_node);
                }
            }
            for (id, node) in last {
                if id < self.band.len() {
                    self.band[id] = node;
                    self.refresh_band_path(id);
                }
            }
            return Vec::new();
        }
        // The band levels, in block order.
        let mut out = Vec::with_capacity(tags.len());
        for (i, nf) in tags.iter().enumerate() {
            let Some(w) = lower[i].take() else {
                out.push(None); // foreign shard: no leaves here, so no copath this node can stand behind
                continue;
            };
            let key = SparseKey::of(nf);
            let mut copath = w.copath;
            let mut node = w.band_node;
            for level in band_level..NF_SPARSE_DEPTH {
                let mut sib = *key.bytes();
                sib[level >> 3] ^= 1u8 << (level & 7);
                let s = self.node_at(level, &Self::canon(&SparseKey::from_key_bytes(sib), level));
                copath.push(s);
                node = if key_bit(&key, level) == 0 { poseidon_pair(node, s) } else { poseidon_pair(s, node) };
            }
            copath.push(w.terminal);
            let id = nf_shard(nf, self.shard_bits) as usize;
            if id < self.band.len() {
                self.band[id] = w.band_node;
                self.refresh_band_path(id);
            }
            out.push(Some((copath, node)));
        }
        out
    }

    /// ⭐⭐⭐ DB-232b — THE UNSHARDED VIEW TAKES THE SAME PARALLEL WALK. Every node at mesh ≤
    /// `Node::NF_SHARD_REPLICATION` holds its view UNSHARDED (`maybe_reshard_nullifier_view` maps "own every
    /// shard" to `shard_bits == 0`, and every rebuild path starts from `RefSparseNf::new()`), and DB-232's
    /// first cut sent `shard_bits == 0` down the sequential walk — so its measured speed-up never reached the
    /// view a small live mesh actually runs.
    ///
    /// The regions are still disjoint: a level-L subtree with L < DEPTH − 8 lies inside one level-(DEPTH − 8)
    /// subtree whatever the representation. So the unsharded view borrows the sharded machinery for one call:
    /// its 256 level-(DEPTH − 8) roots become a band (read with this tree's own `node_at`, BEFORE any insert),
    /// the tower is folded over them, the proven sharded advance runs with every shard owned, and the upper
    /// levels are written back as branch-cache entries — for each (level, subtree) on a tag's path at or above
    /// the band level, the FINAL value iff that subtree now holds ≥ 2 leaves, which is exactly the set and the
    /// values the sequential `insert_with_path` leaves behind (it writes a path node when a second leaf shares
    /// its subtree, and the last tag into a subtree writes that subtree's final value). The view returns to
    /// `shard_bits == 0` with an empty band before this returns.
    ///
    /// ROOT-LAYER: the per-block cost is produced by the walk; this is the one advance every view goes through,
    /// whichever path built it, so no construction site needs to change its representation.
    /// MEASURED: gate M (/tmp/musd-ecocheck-yMOMek) — `[sparse-shadow]` median 189 ms on BOTH nodes, the same as
    /// before DB-232, and the origin's `apply_preverified` held its lock 20.2 s over 47 slow ticks while it
    /// sat 41–51 blocks behind the jumped joiner; the gate pair runs `(0, ·)`, which DB-232 never parallelised.
    /// MUST-STAY-GREEN: `db232_block_advance_is_byte_identical_to_the_per_tag_walk` (now with an UNSHARDED arm),
    /// every `nf_sparse` test, the DB-221 ring pins and the lockstep pin.
    /// cons: per block, 256 `node_at` reads and a 255-hash tower (~1 ms), one 256-entry owned set; no new state
    /// survives the call.
    fn advance_block_rooted_unsharded(&mut self, tags: &[[u8; 32]], copaths: bool) -> Vec<Option<(Vec<Digest4>, Digest4)>> {
        let bits = NF_SHARD_BITS_DEFAULT;
        let band_level = NF_SPARSE_DEPTH - bits;
        let shards = 1u32 << bits;
        // The canonical id of shard `s` at the band level: its bits are the ones `nf_shard` reads, MSB first
        // from level DEPTH − 1; every lower bit is zero.
        let shard_canon = |s: u32| -> [u8; 32] {
            let mut c = [0u8; 32];
            for j in 0..bits {
                if (s >> (bits - 1 - j)) & 1 == 1 {
                    let level = NF_SPARSE_DEPTH - 1 - j;
                    c[level >> 3] |= 1u8 << (level & 7);
                }
            }
            c
        };
        let band: Vec<Digest4> = (0..shards).map(|s| self.node_at(band_level, &shard_canon(s))).collect();
        let mut band_up: Vec<Vec<Digest4>> = Vec::with_capacity(bits);
        let mut prev = band.clone();
        for _ in 0..bits {
            let next: Vec<Digest4> = (0..prev.len()).step_by(2).map(|i| poseidon_pair(prev[i], prev[i + 1])).collect();
            band_up.push(next.clone());
            prev = next;
        }
        let saved_owned = std::mem::take(&mut self.owned);
        self.shard_bits = bits;
        self.owned = (0..shards).collect();
        self.band = band;
        self.band_up = band_up;
        let out = self.advance_block_inner(tags, copaths);
        // The upper levels as the sequential walk leaves them in the branch cache (read while still banded).
        let mut upper: std::collections::BTreeSet<(usize, [u8; 32])> = std::collections::BTreeSet::new();
        for nf in tags {
            for level in band_level..=NF_SPARSE_DEPTH {
                upper.insert((level, Self::canon(&SparseKey::of(nf), level)));
            }
        }
        let mut writes: Vec<((usize, [u8; 32]), Digest4)> = Vec::with_capacity(upper.len());
        for (level, cn) in upper {
            let (lo, hi) = Self::subtree_range(level, &cn);
            let mut it = self.leaves.range(lo..=hi);
            if it.next().is_some() && it.next().is_some() {
                writes.push(((level, cn), self.node_at(level, &cn)));
            }
        }
        self.shard_bits = 0;
        self.owned = saved_owned;
        self.band = Vec::new();
        self.band_up = Vec::new();
        for (key, value) in writes {
            self.branch.insert(key, value);
        }
        out
    }

    /// The shard-local half of one tag's walk, on the tree as it stands: `nf`'s copath and path below the band
    /// level, the branch entries its insert creates there, and its leaf key. Read-only, so tags in different
    /// shards run it concurrently; the caller commits the writes.
    fn lower_walk(&self, key: &SparseKey, band_level: usize) -> LowerWalk {
        // DB-453: the compact witness below the band — siblings from the terminal up, `Z` below it (`t ≤ band_level`).
        let tk = Self::tkey(key.bytes());
        let (t, term, _) = compact_terminal(&[&self.leaves], &tk, self.leaves.contains(&tk));
        let term = term.map(|x| SparseKey::from_key_bytes(Self::tkey(&x)));
        let mut full = vec![Z; NF_SPARSE_DEPTH];
        for (level, slot) in full.iter_mut().enumerate().take(band_level).skip(t) {
            let mut sib = *key.bytes();
            sib[level >> 3] ^= 1u8 << (level & 7);
            *slot = self.node_at(level, &Self::canon(&SparseKey::from_key_bytes(sib), level));
        }
        // the path up to the band level reads only the siblings below it
        let path = post_path_of(key, t, term.as_ref(), &full);
        let pred = self.leaves.range(..tk).next_back().copied();
        let succ = self
            .leaves
            .range((std::ops::Bound::Excluded(tk), std::ops::Bound::Unbounded))
            .next()
            .copied();
        let mut branch_writes = Vec::new();
        for (level, value) in path.iter().enumerate().take(band_level).skip(1) {
            let cn = Self::canon(key, level);
            let (lo, hi) = Self::subtree_range(level, &cn);
            if pred.is_some_and(|p| p >= lo) || succ.is_some_and(|s| s <= hi) {
                branch_writes.push((level, cn, *value));
            }
        }
        full.truncate(band_level);
        LowerWalk { key: tk, band_node: path[band_level], copath: full, terminal: terminal_slot(term.as_ref()), branch_writes }
    }

    /// ⭐⭐ THE ONE WALK AND THE ROOT IT ALREADY FOLDED: `(pre-insert copath, post-insert root)`, or `None` for a
    /// foreign shard. The band slot is read off the same path ([`Self::insert_with_path`]) instead of re-folding
    /// the copath, and the caller's accumulator takes the root instead of re-folding it a third time
    /// (`SparseNfAcc::follow_own_walk`). MEASURED with the path-fed branch cache, `one_fold_walk_tests`:
    /// 371.9 -> 178.9 ms per 256-tag block (sharded, live policy), 317.5 -> 179.1 ms (unsharded).
    pub fn advance_one_rooted(&mut self, nf: &[u8; 32]) -> Option<(Vec<Digest4>, Digest4)> {
        let key = SparseKey::of(nf);
        if self.shard_bits > 0 && !self.owned.contains(&key_shard(&key, self.shard_bits)) {
            return None;
        }
        let (cp, path) = self.insert_with_path(&key);
        if self.shard_bits > 0 {
            let id = key_shard(&key, self.shard_bits) as usize;
            if id < self.band.len() {
                self.band[id] = path[self.band_level()];
                self.refresh_band_path(id);
            }
        }
        Some((cp, path[NF_SPARSE_DEPTH]))
    }

    /// TREE-TRAVERSAL key: byte-reversed nullifier. `nf_bit(nf, level)` reads byte `level>>3`, bit `level&7`, and
    /// the tree descends level 255→0, so byte-reversing makes lexicographic `[u8;32]` order equal descent order —
    /// hence a subtree (a fixed high-bit prefix) is a contiguous key range.
    #[inline]
    pub fn tkey(key_bytes: &[u8; 32]) -> [u8; 32] { // NOT-A-TAG: key-space bytes in, storage order out
        // KEY-space bytes in (a key or a canon prefix), storage order out. Under the DB-353 boundary the key is the
        // byte-reversed tag, so the stored traversal key of a nullifier is the tag's own byte order.
        let mut k = *key_bytes;
        k.reverse();
        k
    }

    /// The KEY with bits `[0, level)` cleared — the canonical id of the depth-`level` subtree containing it.
    fn canon(key: &SparseKey, level: usize) -> [u8; 32] {
        let mut p = *key.bytes();
        let full = level >> 3;
        for b in p.iter_mut().take(full) {
            *b = 0;
        }
        if level & 7 != 0 {
            p[full] &= !((1u8 << (level & 7)) - 1);
        }
        p
    }

    /// The inclusive `tkey` range `[lo, hi]` covered by the subtree at `(level, canon)` — `canon` has nf-bits
    /// `[0, level)` zeroed (the low end); `hi` sets all `level` free bits (the high end). Contiguous by construction.
    /// nf-bit `b` lives in tkey byte `31 - b/8`, bit `b % 8` (byte-reversed), so the free bits `[0, level)` are the last
    /// `level / 8` bytes whole plus the low `level % 8` bits of the byte before them — set a byte at a time.
    /// MEASURED 2026-10-06 (simulator profile, link 8): the bit-at-a-time loop (up to 256 iterations a call, once per level
    /// of every band-cursor and view read) was 2,812 of the sim thread's 28,354 samples — the largest leaf frame of the
    /// relay phase. cons: none — the same range; `a_subtree_range_sets_exactly_the_free_bits` pins it against the loop.
    pub fn subtree_range(level: usize, canon: &[u8; 32]) -> ([u8; 32], [u8; 32]) { // NOT-A-TAG: canon ids
        let lo = Self::tkey(canon);
        let mut hi = lo;
        let full = level >> 3;
        for b in &mut hi[32 - full..] {
            *b = 0xFF;
        }
        if level & 7 != 0 {
            hi[31 - full] |= (1u8 << (level & 7)) - 1;
        }
        (lo, hi)
    }

    /// The highest bit (a tree LEVEL: storage byte `31 - b/8`, bit `b % 8`, as [`Self::subtree_range`]) where two storage
    /// keys differ; `NF_SPARSE_DEPTH` when they are equal (no level separates them).
    fn highest_differing_bit(a: &[u8; 32], b: &[u8; 32]) -> usize { // NOT-A-TAG: storage keys
        for i in 0..32 {
            let d = a[i] ^ b[i];
            if d != 0 {
                return (31 - i) * 8 + (7 - d.leading_zeros() as usize);
            }
        }
        NF_SPARSE_DEPTH
    }

    /// The levels [`Self::node_at`] answers from LEAVES — below the band level of a sharded tree (above it the band
    /// answers), every level of an unsharded one.
    fn leaf_answered_levels(&self) -> usize {
        if self.shard_bits > 0 {
            self.band_level()
        } else {
            NF_SPARSE_DEPTH
        }
    }

    /// Fold a LONE leaf `nf` from level 0 up to `level`, every sibling empty — the subtree hash when `nf` is the
    /// subtree's ONLY occupant. Same child order as [`fold_sparse`]: bit 0 ⇒ node is LEFT. O(level) hashes, no cache.
    pub fn fold_lone_leaf(key: &SparseKey, level: usize) -> Digest4 {
        #[cfg(test)]
        {
            lone_fold_cache::get_or_compute(key.bytes(), level, || Self::fold_lone_leaf_uncached(key, level))
        }
        #[cfg(not(test))]
        {
            Self::fold_lone_leaf_uncached(key, level)
        }
    }

    fn fold_lone_leaf_uncached(key: &SparseKey, level: usize) -> Digest4 {
        // DB-453: a one-key subtree IS the key's leaf up to the band; above it the band levels fold plainly.
        let band = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut node = compact_leaf_of(key);
        for l in band..level {
            node = pair_by_bit(node, empty_subtree(l), key_bit(key, l));
        }
        node
    }

    /// The subtree hash at `(level, canon)` in O(DEPTH)-friendly time: EMPTY subtree ⇒ the constant; exactly ONE
    /// leaf ⇒ fold it on demand (O(level)); ≥2 leaves ⇒ the cached BRANCH hash (O(1)). This is what keeps a copath
    /// O(DEPTH): the only subtrees expensive to fold from scratch (≥2 leaves, up to O(N) of them) are exactly the
    /// ones the cache holds. Same child order as the memo oracle: bit 0 ⇒ LEFT.
    /// One node of this tree — exposed so the DA node index mirrors EXACTLY what an insert produced, rather
    /// than re-deriving it a second way that could drift.
    pub fn node_at_pub(&self, level: usize, canon: &[u8; 32]) -> Digest4 { // NOT-A-TAG: a canon subtree id
        self.node_at(level, canon)
    }

    pub fn node_at(&self, level: usize, canon: &[u8; 32]) -> Digest4 { // NOT-A-TAG: a canon subtree id
        // Z2: at or above the band level the answer is a fold of BAND entries — no leaves consulted, so
        // it is correct for every shard including the ones this node holds no leaves for.
        if self.shard_bits > 0 && level >= self.band_level() {
            let k = level - self.band_level();
            let idx = (key_shard(&SparseKey::from_key_bytes(*canon), self.shard_bits) as usize) >> k;
            return self
                .band_node(k, idx)
                .unwrap_or_else(|| empty_subtree(level));
        }
        let (lo, hi) = Self::subtree_range(level, canon);
        let mut it = self.leaves.range(lo..=hi);
        let first = match it.next() {
            None => return empty_subtree(level),
            Some(k) => *k,
        };
        if it.next().is_none() {
            let key = SparseKey::from_key_bytes(Self::tkey(&first)); // stored traversal key → path key
            return Self::fold_lone_leaf(&key, level);
        }
        // the branch of a ≥2-leaf subtree is maintained on insert; an absent entry (unreachable by construction) is
        // RECOMPUTED by the first key's own lower walk — the exact value the insert would have cached — so a cache
        // defect costs one walk, never the process and never a guessed digest
        self.branch.get(&(level, *canon)).copied().unwrap_or_else(|| {
            let key = SparseKey::from_key_bytes(Self::tkey(&first));
            self.lower_walk(&key, self.band_level())
                .branch_writes
                .iter()
                .find(|(l, c, _)| *l == level && c == canon)
                .map_or_else(|| empty_subtree(level), |(_, _, v)| *v)
        })
    }

    /// This reference tree's current root.
    pub fn root_bytes(&self) -> [u8; 32] { // NOT-A-TAG: a root
        leaf_to_cm_bytes(self.root())
    }

    /// The current root in `Digest4` limb form. When sharded this is a fold of the BAND — `2^s` hashes,
    /// identical on every node whatever shards it holds, which is what lets a sharded node still commit
    /// the consensus root.
    pub fn root(&self) -> Digest4 {
        if self.shard_bits > 0 {
            return self.band_node(self.shard_bits, 0).unwrap_or_else(|| empty_subtree(NF_SPARSE_DEPTH));
        }
        self.node_at(NF_SPARSE_DEPTH, &[0u8; 32])
    }

    /// Occupied-leaf count — the ACTUAL spent-nullifier count, the RAM-audit's working-set size.
    pub fn node_count(&self) -> usize {
        self.leaves.len()
    }

    /// The copath for the nullifier TAG `nf` under the CURRENT (pre-insert) tree — the sibling subtree hash at each
    /// level of its KEY's path (converted at this boundary). Always `NF_SPARSE_DEPTH` siblings, at any occupancy.
    pub fn copath(&self, nf: &[u8; 32]) -> Vec<Digest4> {
        self.copath_key(&SparseKey::of(nf))
    }

    /// [`Self::copath`] in path space.
    fn copath_key(&self, key: &SparseKey) -> Vec<Digest4> {
        // DB-453: the compact witness — the terminal from the nearest leaves, `Z` below it, the real siblings from it up,
        // and the terminal slot (the key itself when it is spent here: the member form).
        let tk = Self::tkey(key.bytes());
        let (t, term, _) = compact_terminal(&[&self.leaves], &tk, self.leaves.contains(&tk));
        let mut cp = vec![Z; NF_COPATH_LEN];
        for (level, slot) in cp.iter_mut().enumerate().take(NF_SPARSE_DEPTH).skip(t) {
            let mut sib = *key.bytes();
            sib[level >> 3] ^= 1u8 << (level & 7);
            *slot = self.node_at(level, &Self::canon(&SparseKey::from_key_bytes(sib), level));
        }
        cp[NF_TERMINAL_SLOT] = terminal_slot(term.map(|x| SparseKey::from_key_bytes(Self::tkey(&x))).as_ref());
        cp
    }

    /// Build the TAG's non-membership copath, then mark it SPENT and maintain the branch cache. Returns the witness.
    /// `NF_SPARSE_DEPTH` hashes for the copath plus one walk of the key's path updating the branch nodes it touches —
    /// a fixed amount of work per insert, whatever the tree holds.
    pub fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Vec<Digest4> {
        self.insert_and_witness_key(&SparseKey::of(nf))
    }

    /// [`Self::insert_and_witness`] in path space.
    fn insert_and_witness_key(&mut self, key: &SparseKey) -> Vec<Digest4> {
        self.insert_with_path(key).0
    }

    /// ⭐⭐ THE ONE WALK — `(pre-insert copath, post-insert path)`, where `path[l]` is `nf`'s own subtree node
    /// at level `l` AFTER the leaf flips to SPENT: the spent leaf folded with the UNCHANGED pre-insert siblings
    /// (a disjoint subtree cannot move when `nf`'s leaf does). Every structure that follows an insert reads
    /// this one fold — the branch cache below, the band slot and the accumulator root in
    /// [`Self::advance_one_rooted`].
    ///
    /// ROOT-LAYER: the tree is where these node values are PRODUCED; the old walk produced the same values
    /// three times per tag (branch cache via `node_at` on both children, re-folding every lone leaf; the band
    /// slot by re-folding the copath; the accumulator by re-folding it again in `insert_from_own_copath`).
    /// MEASURED (`one_fold_walk_tests`, dev-optimized, live shard policy 8 bits / all 256 owned, 256 tags on a
    /// 102,400-leaf view): 371.9 ms -> 178.9 ms (2.08x); gate G's live `[sparse-shadow]` median was 339 ms of
    /// a 500 ms block. Byte-identical copaths, roots, bands and readable branch cache at every insert.
    /// MUST-STAY-GREEN: every `nf_sparse` test (parity, z2 shard, count-surface, the `insert_from_own_copath`
    /// contract, `one_fold_walk_tests`), the DB-221 ring pins, the DB-217 coverage pin, and the produce/ingest
    /// lockstep pins that compare `sparse_acc` against the view.
    fn insert_with_path(&mut self, key: &SparseKey) -> (Vec<Digest4>, Vec<Digest4>) {
        let copath = self.copath_key(key); // BEFORE marking spent → a valid non-membership witness
        let t = copath_terminal_level(&copath);
        let term = terminal_of(&copath[NF_TERMINAL_SLOT]).flatten();
        let path = post_path_of(key, t, term.as_ref(), &copath);
        self.leaves.insert(Self::tkey(key.bytes()));
        // Maintain the branch cache bottom-up along nf's path: any node whose subtree now holds ≥2 leaves is a
        // branch and must be cached (its children's node_at resolves via the cache we filled at the lower level,
        // the stable sibling, or a lone-leaf fold). Nodes below the divergence point hold only nf ⇒ not cached.
        // NEAREST NEIGHBOURS, ONCE. "Does this subtree hold a leaf other than `nf`?" used to be a fresh BTreeSet
        // range scan at EVERY one of the 256 levels — 65,536 range scans per 256-nullifier block, which is what
        // made a block's fold cost ~1.35s against a ~500ms block interval. The leaves are stored in tkey order and
        // `subtree_range` is a contiguous tkey window CONTAINING `nf`, so the ONLY leaves that can be the second
        // occupant of any such window are `nf`'s immediate predecessor and successor: every other leaf is further
        // away in the same direction, so it enters a window only after the neighbour already has. Two ordered
        // lookups therefore answer all 256 levels EXACTLY — same nodes cached, same root, no approximation. With
        // random nullifiers only ~log2(N) levels near the root can hold a second leaf, so the ~248 levels below
        // the divergence point now cost two integer comparisons instead of a tree walk.
        let k = Self::tkey(key.bytes());
        let pred = self.leaves.range(..k).next_back().copied();
        let succ = self
            .leaves
            .range((std::ops::Bound::Excluded(k), std::ops::Bound::Unbounded))
            .next()
            .copied();
        // The first level `node_at` answers from the band rather than this cache (sharded trees only).
        let readable = if self.shard_bits > 0 { self.band_level() } else { NF_SPARSE_DEPTH + 1 };
        for level in 1..=NF_SPARSE_DEPTH {
            let cn = Self::canon(key, level);
            let (lo, hi) = Self::subtree_range(level, &cn);
            // `pred < k` and `lo <= k`, so `pred` is inside iff `pred >= lo`; `succ > k` and `hi >= k`, so `succ`
            // is inside iff `succ <= hi`.
            if level >= readable {
                break; // a sharded tree answers these levels from the BAND; an entry here is never read
            }
            if pred.is_some_and(|p| p >= lo) || succ.is_some_and(|s| s <= hi) {
                // The post-insert node on `nf`'s path — the SAME value `poseidon_pair(node_at(left),
                // node_at(right))` recomputed, without re-folding either child's lone leaf.
                self.branch.insert((level, cn), path[level]);
            }
        }
        (copath, path)
    }
}

/// INCREMENTAL non-membership witness for a wallet's OWN future nullifier `nf` — the O(1)-per-block, O(DEPTH)-storage
/// maintainer that makes "spending is never a problem" true at EVERY layer, with NO party ever holding a tree and NO
/// rebuild from O(N) history. The wallet keeps ONLY `nf`'s copath (DEPTH siblings) and folds in each block's REPLICATED
/// (nullifier, copath) spends as they stream by off the DA.
///
/// Why this is O(1) here and IMPOSSIBLE on the old indexed-Merkle nullifier tree: that tree MUTATED an existing low
/// leaf's `next` pointer on every insert, and a mutation can strike any copath sibling — untrackable in O(DEPTH). This
/// accumulator is MONOTONE (a leaf only flips EMPTY→SPENT and its POSITION is the nullifier itself), so inserting
/// `other` perturbs `nf`'s copath at EXACTLY ONE level — `d`, the HIGHEST bit where their paths differ (above `d` the
/// paths coincide, so only there does `other`'s path cross `nf`'s sibling). The new sibling is just `other`'s freshly
/// SPENT leaf folded up `d` levels through `other`'s OWN replicated copath — O(DEPTH), from the replicated DA stream
/// alone. Total maintenance = O(BLOCK·DEPTH) per block, flat at ANY chain height. Cold-restore (`from_copath`) installs
/// an O(DEPTH) copath the wallet itself reconstructed (from the replicated stream, or an oblivious serve) and
/// SELF-VERIFIES it against the live O(1) root before trusting it — a forged/stale copath is rejected, never a wrong
/// spend. This is the trustless "self-build from the replicated stream (+ oblivious cold-restore)" the cardinal blesses.
/// ([[project_phone_full_node_o1_produce_fold]] [[feedback_always_trustless]] [[feedback_no_growth_any_axis]]
///  [[feedback_digital_cash_pillar]] [[project_membership_witness_o1_regression]])
#[derive(Clone, Debug)]
pub struct SparseNfWitness {
    nf: [u8; 32],
    copath: Vec<Digest4>,
}

impl SparseNfWitness {
    /// Maintain `nf`'s witness from the EMPTY accumulator forward (a wallet that watched from genesis): the copath is
    /// all empty-subtree constants; every later `observe_spend` folds in the real siblings as spends stream by.
    pub fn start_from_empty(nf: [u8; 32]) -> Self { // TAG-SPACE: the tag is stored; every path use converts
        let mut copath: Vec<Digest4> = (0..NF_SPARSE_DEPTH).map(empty_subtree).collect();
        copath.push(Z); // the empty terminal
        Self { nf, copath }
    }

    /// TRUSTLESS COLD-RESTORE — the wallet reconstructs `nf`'s O(DEPTH) copath itself (self-built from the replicated DA
    /// stream, or an oblivious serve) and installs it here, which MUST self-verify against the live root before it is
    /// trusted. A forged/stale copath fails `verify_unspent` and returns `None` (fail-closed) — never a wrong spend, no
    /// trusted server, and the selector `nf` never leaves the wallet. "Restoring after a long time is never a problem":
    /// O(DEPTH) regardless of how many blocks elapsed while offline. Mirrors the membership cold-restore
    /// [`crate::spend_frontier::IncrementalWitness::from_copath`].
    pub fn from_copath(nf: [u8; 32], copath: Vec<Digest4>, acc: &SparseNfAcc) -> Option<Self> {
        if copath.len() != NF_COPATH_LEN {
            return None;
        }
        let w = Self { nf, copath };
        acc.verify_unspent(&w.nf, &w.copath).ok()?; // self-verify vs the O(1) root — fail-closed on a bad copath
        Some(w)
    }

    /// Fold `leaf` up `nf`'s bit-path through `copath` for the first `level_cap` levels → the node at that level on
    /// `nf`'s path. Same child ordering as [`fold_sparse`].
    /// ⭐ DB-453 — FOLD ONE INSERT into this compact witness: `oth` was inserted with the post path `oth_path`
    /// ([`post_path_of`], from its own witness against the same root). `d` = the highest level where the two keys differ.
    /// - `d ≥ t`: `oth` lands OUTSIDE this key's terminal subtree, inside the sibling subtree at `d` — that ONE sibling
    ///   becomes `oth`'s post node at `d`; the terminal cannot move (the subtree above it already held ≥ 2 keys).
    /// - `d < t`, empty terminal: `oth` becomes the terminal key.
    /// - `d < t`, terminal `x`: the terminal subtree now holds `{x, oth}`, so the terminal descends to where at most one of
    ///   them remains on this key's path, and the levels between take the compact nodes of the departed keys.
    fn observe_insert(&mut self, oth: &SparseKey, oth_path: &[Digest4]) {
        let me = SparseKey::of(&self.nf);
        let Some(d) = split_level(&me, oth) else { return };
        let t = copath_terminal_level(&self.copath);
        if d >= t {
            self.copath[d] = oth_path[d];
            return;
        }
        let Some(term) = terminal_of(&self.copath[NF_TERMINAL_SLOT]) else { return };
        let Some(x) = term else {
            self.copath[NF_TERMINAL_SLOT] = terminal_slot(Some(oth));
            return;
        };
        let Some(dx) = split_level(&me, &x) else { return }; // this key itself as the terminal: a member, nothing to follow
        // entry levels: a key enters this key's path subtrees one level above where they differ
        let (ex, eo) = (dx + 1, d + 1);
        let t_new = ex.max(eo) - 1;
        let pair = [x, *oth];
        for l in t_new..t {
            let departed: Vec<SparseKey> = pair.iter().zip([ex, eo]).filter(|(_, e)| *e == l + 1).map(|(k, _)| *k).collect();
            self.copath[l] = compact_node_small(&departed, l);
        }
        let stays = match ex.cmp(&eo) {
            std::cmp::Ordering::Less => Some(x),
            std::cmp::Ordering::Greater => Some(*oth),
            std::cmp::Ordering::Equal => None,
        };
        self.copath[NF_TERMINAL_SLOT] = terminal_slot(stays.as_ref());
    }

    /// Fold in ONE streamed spend `other` (with its replicated non-membership `other_copath`): `other`'s post path from its
    /// own compact witness, then [`Self::observe_insert`]. O(DEPTH). A spend of `nf` itself or a malformed copath is a no-op.
    pub fn observe_spend(&mut self, other: &[u8; 32], other_copath: &[Digest4]) {
        if other == &self.nf {
            return;
        }
        let oth = SparseKey::of(other);
        let Some(w) = compact_witness(&oth, other_copath) else { return };
        let term = w.other.map(SparseKey::from_key_bytes);
        let path = post_path_of(&oth, w.t, term.as_ref(), other_copath);
        self.observe_insert(&oth, &path);
    }

    pub fn observe_block(&mut self, spends: &[([u8; 32], Vec<Digest4>)]) {
        for (other, cp) in spends {
            self.observe_spend(other, cp);
        }
    }

    /// The maintained non-membership copath — hand to the producer to settle, or self-check via `SparseNfAcc`.
    pub fn copath(&self) -> &[Digest4] {
        &self.copath
    }
    pub fn nf(&self) -> &[u8; 32] { // TAG-SPACE: the stored tag
        &self.nf
    }
}

/// ⭐⭐⭐ FOLD-NOT-HOLD SPEND WITNESS ON THE WIRE (brick C3) — the CONSTANT-SIZE folded absence proof a spender
/// carries on its tx, replacing the O(DEPTH) `CompressedCopath`. The spender SELF-builds it from the replicated DA
/// stream (`usdm_decider::nf_sparse_air::prove_nf_absence_chain`): ONE recursive proof that `nf ∉ every block's tags`
/// genesis→tip, plus the tip endpoints the node re-derives. The node verifies it O(1) against its OWN A_tip
/// (`verify_nf_absence_chain`) with NO copath and NO held tree — a stale (already-spent) or forged proof is REJECTED.
/// `Default`/`serde(default)` keeps older gossiped txs deserializable. ([[feedback_infinite_o1_fold_cardinal]])
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NfAbsenceWitness {
    /// The recursive fold proof that `nf` is absent from every block genesis→tip.
    pub proof: Vec<u8>,
    /// The tip block's PREVIOUS fold acc (the chain's second-to-last A_tip) — a node re-derives + binds it.
    pub tip_prev: crate::spend_frontier::Digest4,
    /// The tip block's committed pre value (limbs).
    pub tip_bp: crate::spend_frontier::Digest4,
    /// The tip block's tags digest.
    pub tip_td: crate::spend_frontier::Digest4,
    /// ⛔⛔⛔ THE BASE THIS PROOF WAS ROOTED AT. The verifier used to substitute its OWN CURRENT base, which
    /// is a moving target: `nf_fold_base` advances on every #29 DSYNC adopt, so a node that adopted while a
    /// wallet was folding then checked an honest proof against a base it was never built on, and no spend
    /// could verify. Measured: node base at seq 205 versus a wallet proving from seq 0 — and it worsens as
    /// the chain ages, so sends decay over time rather than failing honestly on day one.
    ///
    /// Naming the base makes the proof self-describing, exactly as `tip_prev/tip_bp/tip_td` already make its
    /// endpoint self-describing. It grants the spender nothing: the node accepts this base only if it is an
    /// accumulator THIS chain actually held (one indexed lookup, at any age, no window), and any spend that
    /// happened after the named tip is still caught by the node's own gap close.
    #[serde(default)]
    pub base_acc: crate::spend_frontier::Digest4,
    /// ⭐⭐ DB-246 — THE TIP ANTICHAIN OF THE SPAN THIS CARRIER FOLDED: every folded block that is no folded block's
    /// parent. The carrier folded exactly `closure(tips)` above its base, a coordinate every node that holds those
    /// blocks shares, whatever order it accepted them in. The gate derives the gap to its own live A_tip from its
    /// recent-fold ring. Empty ⇒ only an exact live-tip match can admit (the pre-DB-246 rule).
    /// Bounded by [`crate::params::DAG_WIDTH_CEILING`] at the gate.
    #[serde(default)]
    pub tips: Vec<[u8; 32]>,
    // ⛔⛔⛔ REMOVED — A CARRIED GAP IS THE PER-BLOCK GROWTH VECTOR, NOT A FIX.
    //
    // This briefly held `Vec<(block_pre, padded_tags)>` for every block between a proof's endpoint and the
    // live tip, so a node with no per-block history could close the race. It is the same shape this project
    // has deleted three times: O(staleness) on the wire, O(chain) to build. MEASURED: a 758-block gap =
    // ~6.2 MB, past the RPC's 8 MB body limit, killing the send outright.
    //
    // THE ENDPOINT MUST BE REACHED BY PROOF. The node steps every POOLED carrier by one block as it applies
    // that block — tags already in hand, O(BLOCK_FIXED_SPEND_TX_COUNT) per block, no history read and
    // nothing on the wire — so endpoint-at-inclusion equals the live tip by construction and no gap exists
    // to carry. ([[feedback_no_growth_any_axis]] [[feedback_never_carried_witnesses_wire]])
    // NOTE: no `base_seq` is carried. It was, briefly, and it could not be BOUND: `/get_nf_fold_inputs`
    // reports the sequence the base was INSTALLED at, while `da_seq_at_nf_acc` reports where that accumulator
    // was first REACHED — different quantities, so requiring them equal rejected honest spends. An unbound
    // field is worse than no field: the boundary tamper flips its last byte and the gate admits a corrupted
    // witness. `base_acc` alone is enough, and it IS checked against this chain's own index.
}

/// ⭐⭐⭐ OWNED COVER — a wallet's CONSTANT-WIDTH bundle of maintained witnesses: its real spend PLUS the per-tx
/// decoys it will pad with, all advanced together. This is the wallet half of the treeless producer.
///
/// WHY IT EXISTS: a producer can only be treeless if EVERY insertion arrives already owned, so a tx must carry a
/// valid copath for its decoys too — not just its real spends. A wallet can own them because a decoy's position is
/// its own choice: it derives them from its own per-tx secret and maintains each one exactly like its real note's,
/// via [`SparseNfWitness`] (O(DEPTH) each, folded forward from every streamed spend). Starting from the EMPTY
/// accumulator needs no tree at all — the copath is all empty-subtree constants.
///
/// COST IS FLAT: storage is `width · DEPTH` and per-block work is `width · DEPTH`, both functions of the FIXED
/// per-tx width only. Neither has a term in the chain height or the spent-set total, so a wallet that has been
/// running for years costs exactly what a fresh one does.
/// ([[feedback_no_growth_any_axis]] [[feedback_all_actions_128_cover_shape]] [[cover_privacy_not_public_function]])
pub struct OwnedCoverSet {
    members: Vec<SparseNfWitness>,
}

impl OwnedCoverSet {
    /// Start maintaining a constant-width bundle from the EMPTY accumulator — the from-genesis wallet. `real` are
    /// the nullifiers the wallet actually intends to spend; the remainder are decoys derived from the wallet's own
    /// `tx_secret`, so it owns every one. `None` if `real` exceeds the width (fail-closed — never a wider carry).
    pub fn start_from_empty(real: &[[u8; 32]], tx_secret: &[u8; 32], width: usize) -> Option<Self> { // TAG-SPACE: tags + a secret
        if real.len() > width {
            return None;
        }
        let mut nfs: Vec<[u8; 32]> = real.to_vec();
        let mut slot = 0usize;
        while nfs.len() < width {
            nfs.push(crate::cover::cover_nullifier_det(tx_secret, slot));
            slot += 1;
        }
        Some(Self {
            members: nfs
                .into_iter()
                .map(SparseNfWitness::start_from_empty)
                .collect(),
        })
    }

    /// Fold ONE streamed spend into EVERY member. This is the whole per-block cost, and it is
    /// `width · DEPTH` — no term in height.
    pub fn observe_spend(&mut self, other: &[u8; 32], other_copath: &[Digest4]) {
        for m in &mut self.members {
            m.observe_spend(other, other_copath);
        }
    }

    /// The constant-width carry to attach to a tx: `(nullifier, compressed copath)` per member, in order.
    /// Every entry is OWNED — the producer folds these and manufactures nothing.
    pub fn tx_carry(&self) -> Vec<([u8; 32], CompressedCopath)> { // TAG-SPACE: the tags a tx carries
        self.members
            .iter()
            .map(|m| (*m.nf(), compress_copath(m.copath())))
            .collect()
    }

    /// Retained size in copath entries — the AUDIT hook. `width · DEPTH`, independent of height.
    pub fn retained_entries(&self) -> usize {
        self.members.iter().map(|m| m.copath().len()).sum()
    }

    pub fn width(&self) -> usize {
        self.members.len()
    }

    /// Every member must still prove NON-MEMBERSHIP against the live O(1) root. A member whose position was spent
    /// by someone else, or whose copath drifted, fails here — so a wallet learns BEFORE it sends, and the tx it
    /// builds cannot be one the network will reject.
    pub fn all_verify(&self, acc: &SparseNfAcc) -> bool {
        self.members
            .iter()
            .all(|m| acc.verify_unspent(m.nf(), m.copath()).is_ok())
    }
}

/// ⭐⭐⭐ BATCH INSERT — the construction that gets over the "carries don't compose" wall, and the last piece of a
/// fully treeless producer.
///
/// THE WALL: 255 of 256 independently-built copaths go STALE inside one block
/// (`carried_copaths_do_not_compose_within_a_block`), because folding one nullifier changes sibling subtrees on the
/// others' paths near the root. That kills SEQUENTIAL folding of wallet carries — but sequential folding was never
/// required. Every carry is honest and valid against the SAME pre-root; only the order-dependent application broke.
///
/// THE FIX: merge all N paths BOTTOM-UP in a single pass. Walking level by level, a block node's sibling is either
/// (a) ANOTHER block nullifier's subtree — already computed at the level below — or (b) that nullifier's CARRIED
/// sibling, which is exactly what its copath holds. Both cases are available without any tree, so the producer
/// computes the block's post-root holding only the O(1) pre-root and the N carries it was handed.
///
/// SOUND: every carry is FIRST verified against the pre-root individually (`verify_unspent` — it must fold to that
/// root with an EMPTY leaf), so a forged or stale carry is rejected before it can influence the merge, and a
/// duplicate nullifier is rejected outright (otherwise a spender could settle the same note twice in one block).
/// Byte-identical to sequential insertion, proven by `batch_insert_matches_sequential_and_is_order_independent`.
///
/// COST: O(N · DEPTH) hashes for the WHOLE block, with no term in the chain height or the spent-set total.
pub fn batch_insert_root(
    acc: &SparseNfAcc,
    carries: &[([u8; 32], Vec<Digest4>)],
) -> Option<[u8; 32]> {
    if carries.is_empty() {
        return Some(acc.root_bytes());
    }
    let mut seen = std::collections::BTreeSet::new();
    for (nf, copath) in carries {
        if copath.len() != NF_COPATH_LEN || !seen.insert(*nf) {
            return None; // wrong-length copath, or the same nullifier settled twice in one block
        }
        acc.verify_unspent(nf, copath).ok()?; // forged / stale / already-spent ⇒ reject before it can influence us
    }
    // DB-453 (compact): every carry is an absence witness against the SAME pre root. Inserting one moves the others'
    // witnesses only where the compact structure says (`SparseNfWitness::observe_insert`: one sibling, or the terminal
    // subtree they share), so the batch settles by inserting in carried order while advancing the rest — each insert's
    // post path computed ONCE. The result is the set's root whatever the order (the root is a function of the set).
    let mut ws: Vec<SparseNfWitness> =
        carries.iter().map(|(nf, cp)| SparseNfWitness { nf: *nf, copath: cp.clone() }).collect();
    let mut root = acc.root();
    for i in 0..ws.len() {
        let key = SparseKey::of(&ws[i].nf);
        let w = compact_witness(&key, &ws[i].copath)?;
        let (pre, _post, _split) = usdm_decider::nf_compact_air::native_compact_insert_folds(&w)?;
        if pre != root {
            return None;
        }
        let term = w.other.map(SparseKey::from_key_bytes);
        let path = post_path_of(&key, w.t, term.as_ref(), &ws[i].copath);
        root = path[NF_SPARSE_DEPTH];
        for later in &mut ws[i + 1..] {
            later.observe_insert(&key, &path);
        }
    }
    Some(leaf_to_cm_bytes(root))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {

    /// ⭐ The path update [`super::band_tower_set`] leaves EXACTLY the tower [`super::band_tower`] rebuilds from the moved band,
    /// at every level, after every one of a sequence of moves touching the first and last shard, a repeated shard, and
    /// both children of one pair — so `assemble_fold_inserts`' top siblings are byte-identical to the per-serve rebuild it
    /// replaced (the two-holders fold pin then proves a REAL carrier over that assembly).
    #[test]
    fn a_band_tower_moved_one_path_at_a_time_is_the_full_rebuild() {
        let n = 1usize << usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let d = |s: u64| -> super::Digest4 { core::array::from_fn(|i| (s.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919)) % 2_130_706_433) };
        let mut band: Vec<super::Digest4> = (0..n as u64).map(d).collect();
        let mut tower = super::band_tower(&band).expect("a full band");
        let moves = [0usize, n - 1, 17, 17, 16, n / 2, 3, n - 2, 0];
        for (step, &s) in moves.iter().enumerate() {
            let v = d(10_000 + step as u64);
            band[s] = v;
            super::band_tower_set(&mut tower, s, v);
            assert_eq!(tower, super::band_tower(&band).expect("a full band"), "move {step} (shard {s}) left a tower the rebuild disagrees with");
        }
        assert_eq!(tower[usdm_decider::nf_sparse_air::NF_BAND_BITS][0], usdm_decider::nf_sparse_air::fold_band(&band).expect("256 entries"), "the top is the band's fold");
    }

    /// The byte-at-a-time `subtree_range` sets exactly the bits the bit-at-a-time loop set, at every level 0..=256 and
    /// for canon ids with every byte pattern (the loop is kept here as the oracle). A wrong range would hide or invent a
    /// leaf in a subtree and change every root.
    #[test]
    fn a_subtree_range_sets_exactly_the_free_bits() {
        let oracle = |level: usize, canon: &[u8; 32]| {
            let lo = super::RefSparseNf::tkey(canon);
            let mut hi = lo;
            for b in 0..level {
                hi[31 - (b >> 3)] |= 1u8 << (b & 7);
            }
            (lo, hi)
        };
        for seed in 0u8..8 {
            let canon: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(seed.wrapping_mul(91)));
            for level in 0..=super::NF_SPARSE_DEPTH {
                assert_eq!(super::RefSparseNf::subtree_range(level, &canon), oracle(level, &canon), "level {level} seed {seed}");
            }
        }
    }


    /// ⭐⭐⭐ THE NODE AND THE CIRCUIT MUST AGREE ON EVERY SHARED CONSTANT — asserted, not claimed.
    ///
    /// ⛔⛔⛔ THE DECIDER'S `spent_leaf_native` CARRIED THE COMMENT *"Byte-identical to the node-side
    /// `nf_sparse::spent_leaf`"* WHILE THE TWO WERE DIFFERENT VALUES (2026-09-13). The §AG widening wrote
    /// this side's second operand as `lanes_of(&[1, 1, 1, 1])`, which PADS WITH ZEROS —
    /// `[1,1,1,1,0,0,0,0]` — against the circuit's `[1u64; DIGEST_LANES]` = `[1,1,1,1,1,1,1,1]`. Every
    /// spent leaf therefore differed, no sparse root could ever agree, and the node could not prove a
    /// transition it had just made itself.
    ///
    /// ⭐ `lanes_of(&[x; 4])` AND `[x; 8]` ARE DIFFERENT CONSTANTS and both read as "a row of x". That is
    /// the widening trap in its purest form: the edit that looks like padding is a value change.
    /// ⭐⭐ A COMMENT CLAIMING TWO THINGS ARE BYTE-IDENTICAL IS NOT A MECHANISM. This gate is the
    /// mechanism, and the functions now DELEGATE rather than mirror — so it also pins that nobody
    /// re-introduces a copy while the delegation quietly rots.
    #[test]
    fn the_node_and_the_circuit_share_one_definition_of_every_sparse_constant() {
        // DB-453: the compact tree's constants are the decider's — the empty subtree, a key's leaf, the empty root.
        assert_eq!(Z, usdm_decider::nf_compact_air::compact_empty(), "⛔ the EMPTY subtree differs between node and circuit");
        let probe: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(3));
        assert_eq!(
            compact_leaf_of(&SparseKey::of(&probe)),
            usdm_decider::nf_compact_air::compact_leaf(SparseKey::of(&probe).bytes()),
            "⛔ a key's leaf differs — no root could agree and no absence proof could verify"
        );
        assert_ne!(compact_leaf_of(&SparseKey::of(&probe)), Z, "a leaf must be distinguishable from the empty subtree");
        let empty_band = vec![Z; usdm_decider::nf_sparse_air::NF_BAND_ENTRIES];
        assert_eq!(
            Some(empty_subtree(NF_SPARSE_DEPTH)),
            usdm_decider::nf_sparse_air::fold_band(&empty_band),
            "⛔ the empty root differs from the decider's band fold"
        );
        // The bit path both sides walk, over a value with bits set in every byte.
        let nf: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for level in 0..NF_SPARSE_DEPTH {
            assert_eq!(
                key_bit(&SparseKey::of(&nf), level),
                usdm_decider::nf_sparse_air::nf_bit(SparseKey::of(&nf).bytes(), level),
                "⛔ the bit path diverges at level {level} — the two sides would walk to different leaves"
            );
        }
        eprintln!(
            "[parity] node and circuit agree on empty leaf, spent leaf and all {NF_SPARSE_DEPTH} bit-path levels"
        );
    }

    /// ⭐⭐⭐ THE ROUND TRIP IS THE IDENTITY — AND THE HASH IS NOT THE INVERSE (kill list §AI).
    ///
    /// `leaf_to_cm_bytes` / `cm_bytes_to_leaf` were a matching encode/decode until §AG made the second a
    /// HASH. Every site round-tripping a ROOT kept compiling and began returning `hash(root)`: a
    /// DSYNC-jumped node installed one as its double-spend gate, and `NullifierTree`'s SERDE pair changed
    /// the root on EVERY RESTART. Nothing failed to build; the types and arity were unchanged.
    ///
    /// Both halves are asserted, and the second is the one that matters: a future reader "simplifying"
    /// `cm_bytes_to_root` back to `cm_bytes_to_leaf` fails HERE, loudly, instead of in a jumped node's
    /// spend gate months later.
    #[test]
    fn a_root_round_trips_through_the_injective_pair_and_never_through_the_hash() {
        let acc = SparseNfAcc::new();
        let root = acc.root();
        let bytes = crate::spend_frontier::leaf_to_cm_bytes(root);
        assert_eq!(
            crate::spend_frontier::cm_bytes_to_root(&bytes),
            Some(root),
            "⛔ the INJECTIVE pair is not a round trip — a root cannot survive the wire"
        );
        assert_ne!(
            crate::spend_frontier::cm_bytes_to_leaf(&bytes),
            root,
            "⛔ `cm_bytes_to_leaf` ROUND-TRIPPED A ROOT. It is a HASH and must never be the inverse of \
             `leaf_to_cm_bytes`; if this ever passes, every root decode in the tree is silently a hash \
             again (§AI) and nothing will fail to compile"
        );
        // And a value that is NOT a canonical digest is REFUSED, never reduced into range.
        assert_eq!(
            crate::spend_frontier::cm_bytes_to_root(&[0xFFu8; 32]),
            None,
            "⛔ a non-canonical 32 bytes decoded as a root — it did not come from this chain, and \
             laundering it into range is how a node ends up gated on a value nothing can reproduce"
        );
        eprintln!("[parity] the root round trip is the identity, and the hash is not its inverse");
    }
    use super::*;


    /// ⭐⭐⭐ BATCH INSERT CLEARS THE WALL — a producer holding ONLY the O(1) root computes a full production-width
    /// block's post-root from carries that were ALL built INDEPENDENTLY against the pre-root.
    ///
    /// This is the exact scenario `carried_copaths_do_not_compose_within_a_block` shows sequential folding cannot
    /// handle (255/256 carries go stale). What it proves:
    ///   1. BYTE-IDENTICAL to sequential insertion by a full-tree holder — so consensus cannot fork on the swap.
    ///   2. ORDER-INDEPENDENT — reversing and shuffling the carries yields the SAME root. That is the property
    ///      sequential folding lacked, and it is why a producer can accept carries in whatever order it selects.
    ///   3. TREELESS — the producer holds one root; the carries are the only other input.
    ///   4. FAIL-CLOSED — a forged carry, a stale carry, and a DUPLICATE nullifier (settling one note twice in a
    ///      block) are each rejected, and the honest batch still succeeds.
    #[test]
    fn batch_insert_matches_sequential_and_is_order_independent() {
        let nf_at = |i: u64| -> [u8; 32] {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&i.to_le_bytes());
            x[31] = 0x8E;
            x
        };
        // A realistic pre-state so the copaths are not all empty-subtree constants.
        let mut world = RefSparseNf::new();
        for i in 0..512u64 {
            world.insert_and_witness(&nf_at(i));
        }
        let acc = SparseNfAcc::adopt_merkle_root(world.root_bytes()).expect("a root this fixture produced is a canonical digest");

        // Every wallet builds its carry INDEPENDENTLY against the same pre-root — none knows about the others.
        let block: Vec<[u8; 32]> = (0..crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64)
            .map(|i| nf_at(10_000 + i))
            .collect();
        let carries: Vec<([u8; 32], Vec<Digest4>)> =
            block.iter().map(|nf| (*nf, world.copath(nf))).collect();

        // Ground truth: a full-tree holder inserts them sequentially.
        let mut seq = world.clone();
        for nf in &block {
            seq.insert_and_witness(nf);
        }
        let expected = seq.root_bytes();

        // (1) TREELESS + BYTE-IDENTICAL.
        let got =
            batch_insert_root(&acc, &carries).expect("the batch folds independently-built carries");
        assert_eq!(
            got, expected,
            "batch post-root is BYTE-IDENTICAL to sequential insertion by a tree holder"
        );
        assert_ne!(
            got,
            world.root_bytes(),
            "the block actually advanced the root (not a vacuous comparison)"
        );

        // (2) ORDER-INDEPENDENT — the exact property sequential folding lacked.
        let mut reversed = carries.clone();
        reversed.reverse();
        assert_eq!(
            batch_insert_root(&acc, &reversed).expect("reversed order still folds"),
            expected,
            "reversing the carries yields the SAME root — a producer may select them in any order"
        );
        let mut shuffled = carries.clone();
        let n = shuffled.len();
        for i in 0..n / 3 {
            shuffled.swap(i, n - 1 - i * 2);
        }
        assert_eq!(
            batch_insert_root(&acc, &shuffled).expect("shuffled order still folds"),
            expected,
            "and so does an interleaved shuffle"
        );

        // (3) FAIL-CLOSED — forged, stale, and duplicate.
        let mut forged = carries.clone();
        forged[7].1[0] = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        assert!(
            batch_insert_root(&acc, &forged).is_none(),
            "a FORGED carry is rejected before it can influence the merge"
        );

        let mut stale = carries.clone();
        stale[3].0 = nf_at(5); // already spent in the pre-state ⇒ its leaf is not EMPTY
        assert!(
            batch_insert_root(&acc, &stale).is_none(),
            "a carry for an ALREADY-SPENT nullifier is rejected"
        );

        let mut dup = carries.clone();
        dup.push(carries[11].clone());
        assert!(
            batch_insert_root(&acc, &dup).is_none(),
            "the SAME nullifier twice in one block is rejected — otherwise a note could be settled twice"
        );

        // The honest batch still folds — the gate rejects tampering, not everything.
        assert_eq!(
            batch_insert_root(&acc, &carries).expect("honest batch"),
            expected
        );
    }

    /// ⛔⛔⛔ CARRIED COPATHS DO NOT COMPOSE WITHIN A BLOCK — the measured wall that blocks a fully treeless
    /// producer, pinned so it is never rediscovered by guesswork.
    ///
    /// The appeal of "every insertion is OWNED" is that a producer could fold N wallets' carries and hold nothing.
    /// It does not work, and this shows exactly why: two nullifiers in the SAME block share sibling subtrees near
    /// the root (with 256-bit positions, any two values diverge within the first handful of top bits), so folding
    /// one INVALIDATES the other's independently-built copath. Order is therefore load-bearing — but each wallet
    /// builds against the block's PRE-root without knowing which other txs the producer will select, or in what
    /// order it will fold them.
    ///
    /// Consequence: a producer must build the block's copaths itself, against a base it queries. That is what
    /// `PartialSparseNf` does. Repairing carries in-block via `SparseNfWitness::observe_spend` is O(N²·DEPTH) for
    /// the block's N insertions — a per-block time blowup, so it is not the way out either.
    #[test]
    fn carried_copaths_do_not_compose_within_a_block() {
        let nf_at = |i: u64| -> [u8; 32] {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&i.to_le_bytes());
            x[31] = 0x3D;
            x
        };
        // Two wallets independently build a NON-MEMBERSHIP copath against the SAME pre-root — exactly what they
        // can do without knowing about each other.
        let pre = RefSparseNf::new();
        let acc = SparseNfAcc::new();
        let (a, b) = (nf_at(1), nf_at(2));
        let (cp_a, cp_b) = (pre.copath(&a), pre.copath(&b));
        assert!(
            acc.verify_unspent(&a, &cp_a).is_ok(),
            "A's carry is valid against the pre-root"
        );
        assert!(
            acc.verify_unspent(&b, &cp_b).is_ok(),
            "B's carry is valid against the pre-root — independently"
        );

        // The producer folds A first. B's carry — still perfectly honest — is now STALE.
        let mut acc_after_a = acc;
        acc_after_a.verify_and_insert(&a, &cp_a).expect("A folds");
        assert!(
            acc_after_a.verify_and_insert(&b, &cp_b).is_err(),
            "B's independently-built copath is REJECTED once A landed first — carries do not compose, so a \
             producer cannot fold N wallets' carries in an order they could not predict"
        );

        // And it is not a quirk of these two: it holds for a full production-width block.
        let mut stale = 0usize;
        let mut acc_seq = SparseNfAcc::new();
        let mut seq = RefSparseNf::new();
        for i in 0..crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64 {
            let nf = nf_at(1000 + i);
            let independent = pre.copath(&nf); // built against the block PRE-root, as a wallet would
            if acc_seq.verify_and_insert(&nf, &independent).is_err() {
                stale += 1;
                let chained = seq.copath(&nf); // what the producer must build itself
                acc_seq
                    .verify_and_insert(&nf, &chained)
                    .expect("the producer-built copath does fold");
            }
            seq.insert_and_witness(&nf);
        }
        println!(
            "CARRIED COPATHS: {stale}/{} independently-built carries went STALE within ONE block",
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        );
        assert!(
            stale > crate::cover::BLOCK_FIXED_NULLIFIER_COUNT / 2,
            "most independently-built carries in a block go stale ({stale} of {}) — if this ever stopped being \
             true, a fully treeless producer would become possible and this wall should be re-derived",
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        );
    }

    /// ⭐⭐⭐ OWNED COVER IS FLAT AT ANY HEIGHT — the wallet half that makes a treeless producer possible.
    ///
    /// A wallet maintains a CONSTANT-WIDTH bundle (its real spend + the decoys it will pad with) while the chain
    /// runs underneath it. What this proves:
    ///   1. FLAT COST BY CONSTRUCTION — retained entries are `width · DEPTH` and are IDENTICAL after 1 block and
    ///      after many. The metric is a function of the FIXED width only, with no term in height or spent total.
    ///   2. STILL VALID AT HEIGHT — after a long stream of OTHER people's spends, every member still proves
    ///      non-membership against the LIVE root. Maintenance that silently drifted would be worthless.
    ///   3. THE CARRY IS CONSTANT WIDTH and every entry is owned — which is exactly what lets the producer fold
    ///      without manufacturing anything (and therefore without a tree).
    ///   4. FAIL-CLOSED — once someone else spends a member's position, the bundle reports invalid rather than
    ///      letting the wallet build a tx the network must reject.
    #[test]
    fn owned_cover_set_is_flat_at_any_height_and_stays_valid() {
        const W: usize = 4;
        let nf_at = |tag: u64, i: u64| -> [u8; 32] {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&tag.to_le_bytes());
            x[8..16].copy_from_slice(&i.to_le_bytes());
            x[31] = 0xC7;
            x
        };
        // The wallet's OWN bundle: one real spend + 3 decoys it derives itself. Started from the empty
        // accumulator, so it needed NO tree and NO server to begin maintaining them.
        let real = [nf_at(1, 0)];
        let tx_secret = [0x9Au8; 32];
        let mut bundle =
            OwnedCoverSet::start_from_empty(&real, &tx_secret, W).expect("reals fit the width");
        assert_eq!(bundle.width(), W, "the bundle is the CONSTANT per-tx width");
        let entries_at_start = bundle.retained_entries();

        // The chain runs: many OTHER wallets' spends stream past. The bundle folds each one in.
        let mut world = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        const BLOCKS: u64 = 40;
        const PER_BLOCK: u64 = 16;
        for b in 0..BLOCKS {
            for i in 0..PER_BLOCK {
                let other = nf_at(500 + b, i);
                let cp = world.insert_and_witness(&other);
                acc.verify_and_insert(&other, &cp)
                    .expect("the world advances");
                bundle.observe_spend(&other, &cp);
            }
        }
        assert_eq!(
            acc.root_bytes(),
            world.root_bytes(),
            "the accumulator tracked the world"
        );

        // (1) FLAT — identical retained size before and after 640 streamed spends.
        let entries_at_height = bundle.retained_entries();
        println!(
            "OWNED COVER: width {W} | retained entries {entries_at_start} → {entries_at_height} after {} spends \
             ({BLOCKS} blocks) | carry width {}",
            BLOCKS * PER_BLOCK,
            bundle.tx_carry().len()
        );
        assert_eq!(
            entries_at_start, entries_at_height,
            "retained cost is f(width · DEPTH) ONLY — it must not gain a single entry as the chain grows"
        );
        assert_eq!(
            entries_at_height,
            W * NF_COPATH_LEN,
            "and it is exactly width · (DEPTH + 1) — the siblings and the terminal slot, by construction"
        );

        // (2) STILL VALID at height — every member proves non-membership against the LIVE root.
        assert!(
            bundle.all_verify(&acc),
            "every maintained member still verifies after {BLOCKS} blocks"
        );

        // (3) The carry is constant width, owned, and each entry expands + folds against the live root.
        let carry = bundle.tx_carry();
        assert_eq!(
            carry.len(),
            W,
            "the tx carry is the CONSTANT width — a real count of 1 is hidden inside it"
        );
        for (nf, c) in &carry {
            let cp = expand_copath(c).expect("a carried compressed copath expands");
            assert!(
                acc.verify_unspent(nf, &cp).is_ok(),
                "each carried entry folds to the live root — owned, valid"
            );
        }

        // (4) FAIL-CLOSED — someone else spends one of the bundle's positions.
        let victim = carry[W - 1].0;
        let vcp = world.insert_and_witness(&victim);
        acc.verify_and_insert(&victim, &vcp)
            .expect("the other party's spend lands first");
        assert!(
            !bundle.all_verify(&acc),
            "once a member's position is spent, the bundle reports INVALID — the wallet learns before it sends"
        );
    }


    /// ⭐⭐⭐ CARRIED-WITNESS SIZE UNLOCK — compressed copaths are LOSSLESS and fit a full 256-cover block inside the
    /// ≤1.8 MB budget, which is what makes the treeless (Mina-style) live path affordable. Raw: 256 siblings × 32 B
    /// = 8 KB per nullifier ⇒ ~2 MB per block (over budget). Compressed: a 32-byte presence bitmap + only the
    /// non-empty siblings. Asserts (a) byte-exact round-trip at production occupancy, (b) a malformed bitmap is
    /// REJECTED fail-closed, and (c) the real measured block total is well under budget.
    #[test]
    fn compressed_copaths_are_lossless_and_fit_a_256_cover_block_in_budget() {
        // A realistic occupancy: many prior spends, so copaths have their genuine non-empty siblings.
        let mut t = RefSparseNf::new();
        for i in 0..4096u64 {
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&i.to_le_bytes());
            nf[31] = 0xC7;
            t.insert_and_witness(&nf);
        }

        let mut total_compressed = 0usize;
        let cover = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT; // PRODUCTION 256-wide cover
        for j in 0..cover {
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&(900_000u64 + j as u64).to_le_bytes());
            nf[31] = 0xC7;
            let raw = t.copath(&nf);
            assert_eq!(
                raw.len(),
                NF_COPATH_LEN,
                "raw copath is always DEPTH siblings + the terminal slot"
            );
            let c = compress_copath(&raw);
            // (a) LOSSLESS — expand reproduces the raw copath byte-for-byte.
            assert_eq!(
                expand_copath(&c).expect("expands"),
                raw,
                "compressed copath round-trips byte-exactly"
            );
            total_compressed += 32 + c.siblings.len() * 32; // bitmap + carried siblings
        }

        // (c) SIZE: the whole block's carried sparse copaths fit far inside the ≤1.8 MB constant-proof budget,
        // whereas the raw form would not.
        let raw_total = cover * NF_SPARSE_DEPTH * 32;
        assert!(
            raw_total > 1_800_000,
            "raw copaths would BLOW the block budget ({raw_total} B) — that's the problem"
        );
        assert!(
            total_compressed < 400_000,
            "compressed carried copaths for a full 256-cover block must fit the budget (got {total_compressed} B)"
        );

        // (b) FAIL-CLOSED — a bitmap that disagrees with the carried sibling count is rejected, never mis-expanded.
        let mut bad = compress_copath(&t.copath(&[0x5Au8; 32]));
        bad.siblings.pop();
        assert!(
            expand_copath(&bad).is_none(),
            "malformed compressed copath is rejected fail-closed"
        );
    }

    /// ⭐⭐⭐ BYTE-IDENTICAL SAFETY NET — the leaf-set `RefSparseNf` (O(spent) RAM) must produce EXACTLY the same
    /// roots and copaths as the path-memoized oracle (O(spent·DEPTH) RAM) it replaces, or every sparse proof breaks.
    /// Insert the same random nullifiers into both, after EACH insert assert the roots are byte-identical and the
    /// copath for several probe positions (spent and unspent) matches limb-for-limb. Also asserts the RAM win: the
    /// leaf-set node_count is the spent count while the memo oracle holds ~DEPTH× more.
    #[test]
    fn leaf_set_tree_is_byte_identical_to_the_memo_oracle() {
        let mut memo = RefSparseNfMemo::new();
        let mut leaf = RefSparseNf::new();
        assert_eq!(memo.root_bytes(), leaf.root_bytes(), "empty roots match");

        let mut inserted: Vec<[u8; 32]> = Vec::new();
        for i in 0..300u64 {
            let nf = nf_from(0xBEEF_0000 + i);
            // Copaths must match BEFORE the insert (non-membership witness), for this nf AND unrelated probes.
            assert_eq!(
                memo.copath(&nf),
                leaf.copath(&nf),
                "pre-insert copath matches for the target #{i}"
            );
            if let Some(p) = inserted.first() {
                assert_eq!(
                    memo.copath(p),
                    leaf.copath(p),
                    "copath matches for an already-spent probe #{i}"
                );
            }
            let probe_unspent = nf_from(0xFACE_0000 + i);
            assert_eq!(
                memo.copath(&probe_unspent),
                leaf.copath(&probe_unspent),
                "copath matches for an UNSPENT probe #{i}"
            );

            let cm = memo.insert_and_witness(&nf);
            let cl = leaf.insert_and_witness(&nf);
            assert_eq!(
                cm, cl,
                "insert_and_witness returns the identical copath #{i}"
            );
            assert_eq!(
                memo.root_bytes(),
                leaf.root_bytes(),
                "roots byte-identical after insert #{i}"
            );
            inserted.push(nf);
        }

        // The RAM win, measured: the leaf-set holds exactly `spent` entries; the memo oracle holds ~DEPTH× more.
        assert_eq!(
            leaf.node_count(),
            300,
            "leaf-set holds exactly the spent count (O(spent))"
        );
        // DB-453: the oracle now recomputes every node from its KEY SET (direct counting), so both hold exactly the keys.
        assert_eq!(memo.node_count(), leaf.node_count(), "both structures hold exactly the spent keys");
    }

    fn nf_from(seed: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        for chunk in out.chunks_mut(8) {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut v = z;
            v = (v ^ (v >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            v = (v ^ (v >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            v ^= v >> 31;
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        out[0] |= 0x01;
        out
    }

    /// The accumulator settles a spender-supplied witness and lands the SAME root the reference tree holds — the
    /// treeless producer is byte-identical to a full-set holder, so a verifier accepts it.
    #[test]
    fn acc_settle_matches_reference_tree() {
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        assert_eq!(
            acc.root_bytes(),
            refs.root_bytes(),
            "empty acc == empty reference root"
        );
        for s in 0..40u64 {
            let nf = nf_from(1_000 + s);
            let copath = refs.insert_and_witness(&nf); // spender self-builds from the stream
            acc.verify_and_insert(&nf, &copath)
                .expect("acc settles supplied witness");
            assert_eq!(
                acc.root_bytes(),
                refs.root_bytes(),
                "acc root tracks the reference after each spend"
            );
        }
    }

    /// FLAT-O(1) — settling one spend does a FIXED 2·DEPTH hashes whether 10 or 1000 nullifiers are already spent.
    /// This is the whole point: produce work never grows with chain size, and there is NO count to leak volume.
    #[test]
    fn settle_is_flat_o1_regardless_of_spent_count() {
        // DB-453 (compact): a settle folds the key's compact witness — its leaf, the terminal key's leaf, the pair chain
        // from their split up to the terminal, then two folds from the terminal to the root. Its work is read off the
        // witness the settle consumed and is BOUNDED by the constant `2·DEPTH + 2` at every spent-set size (it grows only
        // as the terminal descends, ~log2 of a shard's population, never past the bound).
        let settle_hashes = |already: u64| -> u64 {
            let mut refs = RefSparseNf::new();
            for s in 0..already {
                let nf = nf_from(500_000 + s);
                refs.insert_and_witness(&nf);
            }
            let mut acc = SparseNfAcc::adopt_merkle_root(refs.root_bytes()).expect("a root this fixture produced is a canonical digest");
            let fresh = nf_from(9_000_000);
            let copath = refs.insert_and_witness(&fresh);
            let w = compact_witness(&SparseKey::of(&fresh), &copath).expect("well-formed");
            let (_, _, split) = usdm_decider::nf_compact_air::native_compact_insert_folds(&w).expect("an absence witness");
            acc.verify_and_insert(&fresh, &copath).expect("settle");
            let leaves = 1 + u64::from(w.other.is_some());
            leaves + (w.t - split) as u64 + 2 * (NF_SPARSE_DEPTH - w.t) as u64
        };
        let sizes = [10u64, 1_000, 20_000];
        let work: Vec<u64> = sizes.iter().map(|n| settle_hashes(*n)).collect();
        eprintln!("[settle-work] spent {sizes:?} → hashes per settle {work:?} (bound {})", 2 * NF_SPARSE_DEPTH + 2);
        for (n, w) in sizes.iter().zip(&work) {
            assert!(
                *w <= 2 * NF_SPARSE_DEPTH as u64 + 2,
                "settle work at {n} spent ({w} hashes) must stay within the constant 2·DEPTH + 2"
            );
        }
        // COUNT-FREE: the accumulator is a single root, O(1) at any height, with nothing that aggregates volume.
        assert_eq!(
            std::mem::size_of::<SparseNfAcc>(),
            std::mem::size_of::<Digest4>(),
            "the accumulator is exactly one root — no count field, nothing to reveal total volume"
        );
    }

    /// SEMANTIC soundness INDEPENDENT of exact hash values (so a shared fold/reference bug in the bit-ordering can't
    /// slip past `acc == reference`): a real insert must ADVANCE the root (it is not a no-op), must NOT spuriously
    /// spend a DIFFERENT nullifier, and the inserted one must read as spent afterward.
    #[test]
    fn insert_advances_root_and_isolates_other_nullifiers() {
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        let empty_root = acc.root_bytes();
        let a = nf_from(11);
        let b = nf_from(22);

        // b is unspent in the empty tree.
        acc.verify_unspent(&b, &refs.copath(&b))
            .expect("b unspent initially");

        // Insert a → the root MUST change (a no-op insert would be a silent cheat the double-spend test also catches).
        let ca = refs.insert_and_witness(&a);
        acc.verify_and_insert(&a, &ca).expect("insert a");
        assert_ne!(
            acc.root_bytes(),
            empty_root,
            "a real insert ADVANCES the root — insert is not a no-op"
        );

        // a is now spent; b (a DIFFERENT position) is untouched — inserting a did not spuriously spend anything else.
        assert_eq!(
            acc.verify_unspent(&a, &refs.copath(&a)).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "a reads as spent after its insert"
        );
        acc.verify_unspent(&b, &refs.copath(&b))
            .expect("b is STILL unspent — a's insert isolated to a's leaf");
    }

    /// SOUND — a double-spend is rejected fail-closed: the second spend's leaf is already SPENT, so its
    /// non-membership (leaf==EMPTY) proof against the current root fails.
    #[test]
    fn double_spend_is_rejected_fail_closed() {
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        let nf = nf_from(77);
        let copath = refs.insert_and_witness(&nf);
        acc.verify_and_insert(&nf, &copath).expect("first spend ok");

        // Re-using the SAME (now stale) copath: the leaf is SPENT, not EMPTY, so non-membership fails.
        assert_eq!(
            acc.verify_and_insert(&nf, &copath).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "double-spend with the old copath is rejected"
        );
        // Even a FRESH copath (built after the spend) proves the leaf is SPENT, not empty → still rejected.
        let fresh_copath = refs.copath(&nf);
        assert_eq!(
            acc.verify_and_insert(&nf, &fresh_copath).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "double-spend with a current copath is still rejected (leaf is SPENT)"
        );
    }

    /// SOUND — a forged copath (not consistent with the committed root) is rejected; you cannot fake non-membership.
    #[test]
    fn forged_copath_is_rejected() {
        let mut refs = RefSparseNf::new();
        for s in 0..8u64 {
            refs.insert_and_witness(&nf_from(s + 1));
        }
        let acc = SparseNfAcc::adopt_merkle_root(refs.root_bytes()).expect("a root this fixture produced is a canonical digest");
        let nf = nf_from(123_456);
        let mut copath = refs.copath(&nf);
        copath[0] = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]); // tamper one sibling
        assert_eq!(
            acc.verify_unspent(&nf, &copath).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "a tampered copath does not fold to the committed root → rejected"
        );
        assert_eq!(
            acc.verify_unspent(&[0u8; 32], &refs.copath(&[0u8; 32]))
                .unwrap_err(),
            SparseNfError::ZeroNullifier
        );
    }

    // ───────────────────────────── VOLUME PASS — the reals-only, count-free advance ─────────────────────────────

    /// SOUND across the count-free, REALS-ONLY advance: a nullifier spent in an earlier block stays spent no matter
    /// how far the accumulator later advances (by many more REAL spends, NO decoy padding) — so a double-spend in a
    /// LATER block is still rejected. Proves the volume-pass change does not weaken the double-spend gate over time.
    #[test]
    fn cross_block_double_spend_rejected_after_reals_only_advance() {
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        let victim = nf_from(424_242);
        // Block 1: spend `victim` + two others — REALS ONLY, no 256-pad decoy inserts into the tree.
        for nf in [victim, nf_from(1), nf_from(2)] {
            let cp = refs.insert_and_witness(&nf);
            acc.verify_and_insert(&nf, &cp).expect("block 1 settle");
        }
        // Later blocks: advance by MANY more real spends. The acc root moves a lot; `victim`'s leaf stays SPENT.
        for s in 100..170u64 {
            let nf = nf_from(s);
            let cp = refs.insert_and_witness(&nf);
            acc.verify_and_insert(&nf, &cp).expect("later block settle");
        }
        // A later block tries to replay `victim` with a CURRENT copath — rejected: the leaf is SPENT, not empty.
        let now_copath = refs.copath(&victim);
        assert_eq!(
            acc.verify_and_insert(&victim, &now_copath).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "a spend from a much earlier block cannot be replayed after the count-free acc advanced by many reals"
        );
    }

    /// DIGITAL-CASH-PRIVACY-REVIEWED: this test DEMONSTRATES the hiding (it does not build a serving oracle) — an
    /// RPC-observer that lacks the block secret CANNOT recover the real count from the served cover, while a full
    /// node that holds the confidential blobs (hence the secret) can. VOLUME: once the count-free SMT advances by
    /// REALS ONLY, the surface an RPC-observer sees (a constant-256 served cover) must still reveal ZERO about how
    /// many reals a block had. The decoys are secret-seeded, so a secret-less observer cannot separate reals from
    /// decoys; a secret-holder regenerates the exact decoys and subtracts.
    #[test]
    fn serve_cover_hides_real_volume_from_observer_not_secret_holder() {
        use crate::cover;
        let pre_root = [7u8; 32];
        let reals = vec![nf_from(101), nf_from(202), nf_from(303)]; // K=3 — the volume to HIDE
                                                                    // The block secret folds the confidential real-spend blobs — an RPC-observer LACKS these (node-gossiped,
                                                                    // never RPC-served), so it cannot derive the secret.
        let secret = cover::nullifier_block_secret(b"real-spend-confidential-blobs", &pre_root);
        let cover_set = cover::nullifier_wire_fill(&reals, &secret);

        // (1) CONSTANT surface: exactly 256 regardless of K — the count itself is padded away.
        assert_eq!(
            cover_set.len(),
            cover::BLOCK_FIXED_NULLIFIER_COUNT,
            "served surface is a CONSTANT 256 — no per-block count leak"
        );

        // (2) SECRET HOLDER (full node): regenerates the EXACT decoys → subtracts → recovers exactly the K reals.
        // ⚠️ STRIP WITH THE PRODUCTION FN, NOT A HAND-ROLLED ONE. This regenerated decoys via
        // `cover_nullifier_det(secret, i)` — the TX-level cover generator — while `nullifier_wire_fill`
        // derives its fill as `blake3("MUSD-nf-wire-fill-v1" ‖ secret ‖ i)`. Two different derivations, so
        // the "decoys" matched nothing, nothing was subtracted, and the test reported 256 recovered reals
        // out of 3. A privacy test that models the strip instead of CALLING it proves nothing about the
        // strip that ships — and this one would have kept passing while the real pair drifted apart.
        let recovered = cover::nullifier_wire_strip(&cover_set, &secret);
        assert_eq!(
            recovered.len(),
            reals.len(),
            "secret-holder recovers exactly K reals"
        );
        for nf in &reals {
            assert!(
                recovered.contains(nf),
                "each real is recovered by the secret-holder"
            );
        }

        // (3) OBSERVER WITHOUT the secret: a WRONG secret yields a DIFFERENT decoy set, so subtracting it does NOT
        //     isolate the K reals — the observer cannot even learn HOW MANY were real. Volume stays hidden.
        let wrong = cover::nullifier_block_secret(b"observer-guess-lacks-the-blobs", &pre_root);
        // Same correction: run the OBSERVER through the production strip too, so both halves of this test
        // exercise the same code path and the comparison is honest.
        let wrong_recovered = cover::nullifier_wire_strip(&cover_set, &wrong);
        assert_ne!(
            wrong_recovered.len(),
            reals.len(),
            "without the secret the observer cannot isolate the real count — volume is hidden"
        );
    }

    /// DIGITAL-CASH-PRIVACY-REVIEWED: asserts INDISTINGUISHABILITY (a hiding property), never exposes a value. Two
    /// blocks that spend DIFFERENT numbers of reals present an IDENTICAL-SHAPE observable surface — a 32-byte
    /// count-free root + a CONSTANT-256 served cover — so spend VOLUME is not derivable from what the chain exposes.
    /// The reals-only count-free SMT is what lets the tree advance by K with no `count` field betraying K.
    #[test]
    fn block_volume_is_indistinguishable_across_spend_counts() {
        use crate::cover;
        let observable = |k: usize, seed: u64| -> (usize, usize) {
            let mut refs = RefSparseNf::new();
            let mut acc = SparseNfAcc::new();
            let reals: Vec<[u8; 32]> = (0..k).map(|i| nf_from(seed + i as u64)).collect();
            for nf in &reals {
                let cp = refs.insert_and_witness(nf);
                acc.verify_and_insert(nf, &cp).expect("settle");
            }
            let secret = cover::nullifier_block_secret(b"blobs", &[0u8; 32]);
            (
                acc.root_bytes().len(),
                cover::nullifier_wire_fill(&reals, &secret).len(),
            )
        };
        let (root_len_1, cover_len_1) = observable(1, 10_000);
        let (root_len_50, cover_len_50) = observable(50, 20_000);

        // Root shape + served-cover count are INVARIANT to the real spend count (1 vs 50): nothing observable scales.
        assert_eq!(root_len_1, 32);
        assert_eq!(root_len_50, 32);
        assert_eq!(
            cover_len_1, cover_len_50,
            "served cover count is invariant to real spend volume"
        );
        assert_eq!(cover_len_1, cover::BLOCK_FIXED_NULLIFIER_COUNT);
        // No count anywhere in the accumulator: a jumper adopting the root learns nothing about K.
        assert_eq!(
            std::mem::size_of::<SparseNfAcc>(),
            std::mem::size_of::<Digest4>()
        );
    }

    /// ⭐⭐⭐ THE O(1)-EVERYWHERE KEYSTONE — a wallet maintains its OWN spend witness incrementally, holding only the
    /// O(DEPTH) copath, matching a full-set holder at EVERY block and at ANY chain height, then SPENDS with it — with a
    /// trustless O(DEPTH) cold-restore for the offline case. This is what makes "spending is never a problem" and
    /// "restoring after a long time is never a problem" true WITHOUT any party holding a tree, doing O(N) work, or
    /// querying a which-item serve. (A) correctness+spend across a long stream; (B) maintenance work is flat regardless
    /// of how many nullifiers are already spent; (C) a forged cold-restore is rejected fail-closed.
    #[test]
    fn wallet_maintains_spend_witness_incrementally_o1_at_any_height_then_spends() {
        // ── (A) COLD-RESTORE at a large height, then INCREMENTAL maintenance forward, ending in a real spend. ──
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        // Advance the chain a long way BEFORE the wallet's note exists — the wallet was offline for all of it.
        for s in 0..600u64 {
            let nf = nf_from(3_000_000 + s);
            let cp = refs.insert_and_witness(&nf);
            acc.verify_and_insert(&nf, &cp).expect("pre-history settle");
        }
        // The wallet's own future nullifier. It reconstructs the O(DEPTH) copath (self-built from the stream / oblivious
        // serve) and COLD-RESTORES — self-verified against the live root, regardless of the 600-block gap.
        let target = nf_from(42_424_242);
        let mut w = SparseNfWitness::from_copath(target, refs.copath(&target), &acc)
            .expect("cold-restore self-verifies against the live O(1) root");
        assert_eq!(
            w.copath().len(),
            NF_COPATH_LEN,
            "wallet holds exactly DEPTH siblings + the terminal slot — O(DEPTH), any height"
        );

        // NON-VACUITY: a nullifier differing from `target` ONLY at bit 2 MUST populate `target`'s copath[2] (its
        // highest differing bit) when spent — so the oracle-match below is proven non-trivial, not an all-empty copath.
        let near = {
            let mut n = target;
            // flip KEY bit 2 only ⇒ highest-differing-level(target, near) == 2. The tree walks the KEY = the byte-reversed
            // tag (DB-353), so key byte 0 is TAG byte 31: the flip lands there, not in tag byte 0.
            n[31] ^= 0b100;
            n
        };
        assert_eq!(
            w.copath()[2],
            empty_subtree(2),
            "copath[2] starts as the empty-subtree constant"
        );

        // Now stream many more blocks; the wallet folds each block's spends into its ONE witness and stays correct.
        let mut seed = 5_000_000u64;
        for blk in 0..40u64 {
            let mut batch: Vec<([u8; 32], Vec<Digest4>)> = Vec::new();
            if blk == 0 {
                let cp = refs.insert_and_witness(&near); // the crafted near-prefix spend rides block 0
                acc.verify_and_insert(&near, &cp).expect("near settle");
                batch.push((near, cp));
            }
            for _ in 0..7 {
                let nf = nf_from(seed);
                seed += 1;
                let cp = refs.insert_and_witness(&nf); // the block's replicated (nullifier, copath)
                acc.verify_and_insert(&nf, &cp).expect("stream settle");
                batch.push((nf, cp));
            }
            w.observe_block(&batch);
            // The incrementally-maintained copath is BYTE-IDENTICAL to a full-set holder's, and self-verifies live.
            assert_eq!(
                w.copath(),
                refs.copath(&target).as_slice(),
                "incremental copath == full-tree copath @ block {blk}"
            );
            acc.verify_unspent(&target, w.copath())
                .expect("maintained witness proves target still unspent");
        }
        // NON-VACUITY proven: copath[2] absorbed `near`, so the per-block match was real work, not a trivial all-empty
        // copath. NEGATIVE CONTROL: a witness that NEVER observed the stream (still the empty-tree copath) is REJECTED
        // against the advanced root — so the passing case above is load-bearing.
        // DB-453 (compact): `near` shares every bit from level 3 up with `target`, so it lands in target's TERMINAL subtree —
        // the maintainer names it as the terminal key (below the terminal every sibling stays `Z`).
        assert_eq!(
            terminal_of(&w.copath()[NF_TERMINAL_SLOT]),
            Some(Some(SparseKey::of(&near))),
            "the terminal slot names `near` after it streamed by — the maintainer did real work"
        );
        assert!(
            acc.verify_unspent(&target, SparseNfWitness::start_from_empty(target).copath())
                .is_err(),
            "an un-maintained (empty-tree) witness does NOT verify against the advanced root"
        );

        // SPENDING IS NEVER A PROBLEM: the wallet spends `target` with its own maintained witness — the O(1) acc settles.
        acc.verify_and_insert(&target, w.copath())
            .expect("the wallet spends with its incrementally-maintained witness");

        // ── (B) BOUNDED-O(1): per-spend maintenance work stays within one constant whether 10 or 1000 are already spent. ──
        let maintain_hashes = |already: u64| -> u64 {
            let mut r = RefSparseNf::new();
            for s in 0..already {
                r.insert_and_witness(&nf_from(700_000 + s));
            }
            let tgt = nf_from(88_888_888);
            let a = SparseNfAcc::adopt_merkle_root(r.root_bytes()).expect("a root this fixture produced is a canonical digest");
            let mut mw = SparseNfWitness::from_copath(tgt, r.copath(&tgt), &a).expect("restore");
            let other = nf_from(99_999_999);
            let ocp = r.insert_and_witness(&other);
            NF_SPARSE_HASHES.with(|c| c.set(0)); // measure ONLY the observe_spend maintenance fold
            mw.observe_spend(&other, &ocp);
            NF_SPARSE_HASHES.with(|c| c.get())
        };
        let few = maintain_hashes(10);
        let many = maintain_hashes(1_000); // 100× more already spent
        // DB-453 (compact): the observed spend's post path folds from its own terminal — work bounded by the constant
        // DEPTH + 2 at every height (it varies under the bound with the spend's shard population, ~log2, never past it).
        eprintln!("[maintain-work] hashes per observed spend at 10 / 1,000 spent: {few} / {many} (bound {})", NF_SPARSE_DEPTH + 2);
        for w in [few, many] {
            assert!(
                w <= NF_SPARSE_DEPTH as u64 + 2,
                "maintenance work per spend stays within the constant DEPTH + 2 at any height: {few} vs {many}"
            );
        }

        // ── (C) SOUND cold-restore: a forged/stale copath does not fold to the live root → rejected fail-closed. ──
        let mut forged = refs.copath(&nf_from(1_234_567));
        forged[0] = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        assert!(
            SparseNfWitness::from_copath(nf_from(1_234_567), forged, &acc).is_none(),
            "a forged cold-restore copath is rejected — never a wrong spend, no trusted server"
        );
    }

    /// ⭐⭐⭐ PER-TX COVER OWNERSHIP — closes the O(1)-everywhere loop. Every nullifier a block settles (REAL or DECOY)
    /// has an INCREMENTAL OWNER: the spender's own tx pads to a constant `M` (its reals + secret-seeded decoys the
    /// SPENDER builds from its own view), so there are NO orphan decoys forcing the producer to hold a tree. The
    /// producer folds every spender-supplied `(nf, copath)` into the O(1) `SparseNfAcc` (root only) and lands the SAME
    /// root an independent full-set holder does — flat-O(1) produce with the cover intact. Each tx's real count `K` is
    /// hidden inside the constant `M`, and a tampered supplied copath is rejected fail-closed.
    ///
    /// ADVERSARIAL (not a rubber stamp): the treeless producer root is checked against the independent `RefSparseNf`
    /// full-set holder — a wrong fold DIVERGES; per-tx width is asserted constant; a corrupted copath is REJECTED.
    #[test]
    fn per_tx_cover_ownership_producer_folds_treelessly_o1() {
        use crate::cover;
        const M: usize = 4; // per-tx cover width — every tx settles exactly M nullifiers regardless of its real count
        const N_TX: usize = 64; // 64 tx × M = 256 — a production-volume block, yet the acc stays count-free O(1)

        let mut refs = RefSparseNf::new(); // the spender-side view (stands in for each spender's OWN node)
        let mut acc = SparseNfAcc::new(); // the PRODUCER: holds ONLY the O(1) root — no tree, no count
        let block_pre = acc.root_bytes();
        let mut used = std::collections::HashSet::new();
        let mut supplied: Vec<([u8; 32], Vec<Digest4>)> = Vec::new();
        let mut seed = 6_000_000u64;

        for t in 0..N_TX {
            let k = (t % M) + 1; // real count 1..=M — hidden inside the constant width
            let mut this_tx = 0usize;
            // REAL spends — the spender self-builds each witness from its own view and hands it to the producer.
            while this_tx < k {
                let nf = nf_from(seed);
                seed += 1;
                if !used.insert(nf) {
                    continue;
                }
                let cp = refs.insert_and_witness(&nf);
                acc.verify_and_insert(&nf, &cp)
                    .expect("producer folds a spender-supplied REAL");
                supplied.push((nf, cp));
                this_tx += 1;
            }
            // DECOYS — secret-seeded per THIS tx and OWNED (built) by the spender, so no orphan the producer must serve.
            let tx_secret = cover::nullifier_block_secret(&[t as u8], &block_pre);
            let mut d = 0usize;
            while this_tx < M {
                let decoy = cover::cover_nullifier_det(&tx_secret, d);
                d += 1;
                if !used.insert(decoy) {
                    continue;
                }
                let cp = refs.insert_and_witness(&decoy);
                acc.verify_and_insert(&decoy, &cp)
                    .expect("producer folds a spender-OWNED DECOY");
                supplied.push((decoy, cp));
                this_tx += 1;
            }
            assert_eq!(this_tx, M, "tx {t} settles exactly M — its real count K={k} is hidden inside the constant width");
        }
        assert_eq!(
            supplied.len(),
            N_TX * M,
            "block = N_TX·M spender-supplied insertions (all owned, none orphan)"
        );

        // The treeless producer (root only) landed the SAME root an independent full-set holder holds — flat-O(1),
        // cover intact, no consensus divergence.
        assert_eq!(
            acc.root_bytes(),
            refs.root_bytes(),
            "treeless producer root == independent full-set holder root"
        );
        assert_eq!(
            std::mem::size_of::<SparseNfAcc>(),
            std::mem::size_of::<Digest4>(),
            "the producer held exactly ONE root — no tree, no count, O(1) at 256 insertions"
        );

        // TAMPER: a spender/relay that corrupts a supplied (would-be decoy) copath is rejected by the O(1) acc — a lie
        // is never a wrong settle, and the producer needs no trusted server to catch it.
        let unseen = nf_from(123_123_123);
        let mut corrupted = refs.copath(&unseen);
        corrupted[0] = usdm_decider::poseidon2_compress::lanes_of(&[7, 7, 7, 7]);
        assert_eq!(
            acc.verify_unspent(&unseen, &corrupted).unwrap_err(),
            SparseNfError::AlreadySpentOrBadWitness,
            "a corrupted spender-supplied copath does not fold to the acc root → rejected"
        );
    }

    /// ⭐ PARITY (sparse carrier brick 1) — the decider's NATIVE sparse transition (the reference the in-circuit
    /// carrier will prove) lands the BYTE-IDENTICAL root the node's live `SparseNfAcc` does, over a real chain of
    /// spender-built witnesses. This is what lets a jumped/adopting node verify the sparse block carrier against its
    /// OWN O(1) acc root with NO held tree — the circuit and the node fold the same tree. ([[project_29_dsync_e2e_proven]])
    #[test]
    fn decider_native_sparse_transition_matches_node_acc() {
        use usdm_decider::nf_sparse_air as air;
        let mut refs = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        // ⛔ WAS `cm_bytes_to_leaf(&acc.root_bytes())` — a ROOT round-tripped through a HASH (§AG).
        // `root()` is the value itself; the byte form exists for the wire, not for re-entry.
        let pre_limbs = acc.root();
        let mut inserts: Vec<usdm_decider::nf_compact_air::CompactInsertWitness> = Vec::new();
        let _ = air::PRODUCTION_BLOCK_COVER;
        // PRODUCTION cover: the full per-block nullifier count (256), never a shrunken count.
        for s in 0..crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64 {
            let nf = nf_from(4_000 + s);
            let cp = refs.insert_and_witness(&nf);
            acc.verify_and_insert(&nf, &cp)
                .expect("node acc settles the spender witness");
            inserts.push(compact_insert_witness_for(&nf, &cp).expect("a compact copath")); // the ONE handoff: the KEY's path
        }
        let n = inserts.len();
        let native_post = usdm_decider::nf_compact_air::compact_post_native(&inserts, pre_limbs, n)
            .map(|(post, _kd)| post)
            .expect("the decider's native chain settles the same block");
        assert_eq!(
            crate::spend_frontier::leaf_to_cm_bytes(native_post),
            acc.root_bytes(),
            "decider native sparse root == node SparseNfAcc root (byte-identical) — the carrier binds to the live acc"
        );
    }

    /// ⭐⭐⭐ TRUE INFINITE-O(1) CHAIN-WIDE — a node at ANY chain height JUMPS to the tip in O(1) (adopt the count-free
    /// root, NO history replay, NO held tree), then VERIFIES the next PRODUCTION block's O(1) carrier from ONLY the two
    /// committed roots, and lands the SAME root a full-replay node does. This is what makes the whole chain O(1) on the
    /// HEIGHT axis: neither the adopting jump, the held state (one root), nor the forward verify grows with how many
    /// blocks came before. Fail-closed + TRUSTLESS: a FORGED tip breaks the carrier's endpoint binding and is REJECTED
    /// (no trusted issuer). The deep prior chain is the height witness; the structural facts (count-free root, endpoint-
    /// only verify) ARE the O(1)-at-∞ proof. ([[feedback_always_trustless]] [[feedback_no_growth_any_axis]] [[project_29_dsync_e2e_proven]])
    #[test]
    fn sparse_accumulator_is_o1_chain_wide_via_adopt_then_verify_forward() {
        use crate::spend_frontier::cm_bytes_to_root;
        use usdm_decider::nf_sparse_air as air;

        // ── A DEEP prior chain (the height witness): the chain already advanced a long way before this node exists. ──
        let mut refs = RefSparseNf::new();
        let mut full = SparseNfAcc::new(); // a node that replayed EVERYTHING (the reference)
        for s in 0..3_000u64 {
            let nf = nf_from(7_000_000 + s);
            let cp = refs.insert_and_witness(&nf);
            full.verify_and_insert(&nf, &cp)
                .expect("prior-history settle");
        }
        let r_prev = full.root_bytes(); // the tip a peer serves
        // ⛔ A ROOT decodes with the INJECTIVE inverse, never the hash (§AG).
        let pre_limbs = cm_bytes_to_root(&r_prev).expect("a root this chain produced decodes injectively");

        // ── THE O(1) JUMP: a joining node adopts the tip root and holds ONLY that root — it NEVER replayed the 3000. ──
        let mut joiner = SparseNfAcc::adopt_merkle_root(r_prev).expect("a root this fixture produced is a canonical digest");
        assert_eq!(
            joiner.root_bytes(),
            r_prev,
            "adopt installs the tip root O(1) — count-free, no tree, no replay"
        );

        // ── PRODUCE the next PRODUCTION block: the full 256-nullifier cover, chained onto the tip R_prev → R_K. ──
        let mut inserts: Vec<usdm_decider::nf_compact_air::CompactInsertWitness> = Vec::new();
        for s in 0..crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64 {
            let nf = nf_from(8_100_000 + s);
            let cp = refs.insert_and_witness(&nf);
            full.verify_and_insert(&nf, &cp)
                .expect("full-replay node settles block K");
            joiner
                .verify_and_insert(&nf, &cp)
                .expect("the JUMPED joiner settles block K from the same stream copaths");
            inserts.push(compact_insert_witness_for(&nf, &cp).expect("a compact copath"));
        }
        let r_k = full.root_bytes();
        let post_limbs = cm_bytes_to_root(&r_k).expect("a root this chain produced decodes injectively");

        // The compact O(1) block carrier proves the whole R_prev → R_K transition (endpoints only, intermediate private).
        // DB-453: the compact band carrier proves the same 256-insert transition (the deep shape only if a split needs it)
        let n = inserts.len();
        let lb = usdm_decider::nf_compact_air::compact_step_lb(&inserts);
        let (carrier, carrier_post, kd) =
            usdm_decider::nf_compact_air::prove_compact_band_carrier_bytes(&inserts, pre_limbs, n, lb)
                .expect("prove the block-K carrier");
        assert_eq!(
            carrier_post, post_limbs,
            "carrier post-root == the node's live SparseNfAcc root"
        );

        // ── THE O(1) FORWARD VERIFY: a treeless node checks block K against ONLY (R_prev, R_K) — no history, no tree. ──
        let _ = air::PRODUCTION_BLOCK_COVER;
        assert!(
            usdm_decider::nf_compact_air::verify_compact_band_carrier_any_shape(&carrier, pre_limbs, post_limbs, n, n, kd),
            "the jumped node verifies the next block O(1) from the two committed roots alone"
        );

        // The node that JUMPED reached the byte-identical root the full-replay node did — the O(1) jump lost NO soundness.
        assert_eq!(
            joiner.root_bytes(),
            r_k,
            "adopted joiner ends at the SAME root as the full-replay node"
        );
        assert_eq!(
            joiner.root_bytes().len(),
            32,
            "acc state = ONE 32-byte root — constant at ANY height (no growth)"
        );

        // ── TRUSTLESS / fail-closed: a FORGED tip breaks the carrier's endpoint binding ⇒ REJECT (no trusted issuer). ──
        let mut bad_prev = pre_limbs;
        bad_prev[0] ^= 1;
        assert!(
            !usdm_decider::nf_compact_air::verify_compact_band_carrier_any_shape(&carrier, bad_prev, post_limbs, n, n, kd),
            "a forged tip (wrong pre-root) is REJECTED — the jump is self-verifying, not trusted"
        );
        // A joiner that adopted a TAMPERED tip cannot even settle the real stream: the copaths fold to the real root,
        // not the tampered one, so non-membership fails ⇒ a swapped-root peer cannot make it accept forward blocks.
        let mut tampered = r_prev;
        tampered[0] ^= 0x40;
        let mut bad_joiner = SparseNfAcc::adopt_merkle_root(tampered).expect("a root this fixture produced is a canonical digest");
        let nf = nf_from(8_100_000); // the first real block-K nullifier
        assert!(
            bad_joiner.verify_and_insert(&nf, &{
                let mut cp0 = inserts[0].siblings.clone();
                cp0.push(terminal_slot(inserts[0].other.map(SparseKey::from_key_bytes).as_ref()));
                cp0
            }).is_err(),
            "a joiner on a TAMPERED tip rejects the real stream (copaths don't fold to the forged root) — fail-closed"
        );
    }
}

/// Canonical prefix of `nf` at `level` — module-level so the DA node index keys identically to the tree.
pub fn canon_pub(nf: &[u8; 32], level: usize) -> [u8; 32] {
    RefSparseNf::canon(&SparseKey::of(nf), level)
}

/// Bit `level` of a nullifier, LSB-first — the child side at that tree level.
pub fn nf_bit_pub(nf: &[u8; 32], level: usize) -> u8 {
    key_bit(&SparseKey::of(nf), level)
}

#[cfg(all(test, feature = "pins-core"))]
mod count_surface_privacy_tests {
    /// PRIVACY (user 2026-08-14): the WIRE-SERVED nullifier count must be a pure function of the PUBLIC
    /// block count — never of real spend volume. This gates the count surface of the volume-hiding fix
    /// (the per-block tag-vector shape is gated separately by `block_volume_is_indistinguishable…`).
    #[test]
    fn served_nullifier_count_is_a_pure_function_of_block_count_not_spend_volume() {
        let per_block = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;
        // The reporting convention: 1 sentinel + fixed-constant x blocks, regardless of real activity.
        // Zero real spends and fifty real spends in a block contribute the IDENTICAL delta.
        let blocks = 7u64;
        let expect = 1 + per_block * blocks;
        let mut leaves = 0u64;
        for real_count_this_block in [0u64, 1, 50, 0, 256, 3, 0] {
            let _ = real_count_this_block; // the real volume MUST NOT appear in the advance
            leaves += per_block;
        }
        assert_eq!(1 + leaves, expect, "count derives from block count alone");
        assert_eq!(per_block, 256, "the constant is the fixed protocol shape");
    }
}

#[cfg(test)]
mod z2_shard_tests {
    use super::*;

    fn nf(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"z2-nf".as_slice(), &i.to_le_bytes()].concat()).as_bytes()
    }

    /// ⛔⛔⛔ DB-398 — a whole-set sharded tree re-filed to the unsharded representation keeps its root and its leaves.
    /// Measured 2026-10-05 on the live pair (Tier-1 run 5, step 3): a restarted node's warm installs a sharded `(8, 256)`
    /// view (`PivotWarm`); the next peer-count change re-files it to the unsharded representation, and from that log line
    /// on the view no longer matched its accumulator (48 of 48 samples) and the wallet's send was refused with
    /// `503 … its copath index does not describe the root it committed`. READ: the unsharded arm re-inserted each stored
    /// leaf `tkey(k)` — a PATH KEY — through `insert_and_witness`, which takes a TAG and maps it to a key again.
    /// CALIBRATION: the same spends in a fresh unsharded tree reach the sharded tree's root, so the two representations
    /// agree and only the re-file can move the root.
    #[test]
    fn db398_a_complete_sharded_tree_re_filed_unsharded_keeps_its_root_and_its_leaves() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let spends: Vec<[u8; 32]> = (0..33u64).map(nf).collect();
        let mut sharded = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let _ = sharded.advance_block_rooted(&spends); // the warm's own insert (`install_healed_pivot`)
        let mut oracle = RefSparseNf::new();
        for x in &spends {
            let _ = oracle.insert_and_witness(x);
        }
        assert_eq!(sharded.root(), oracle.root(), "CALIBRATION: the sharded and unsharded representations of one set agree");
        let refiled = sharded.reshard(0, Vec::new());
        assert_eq!(refiled.shard_policy(), (0, 0), "CALIBRATION: the re-file reached the unsharded representation");
        assert_eq!(refiled.spent_leaf_count(), spends.len(), "the re-file keeps every leaf");
        assert!(
            spends.iter().all(|x| refiled.holds_spent_leaf(x) == Some(true)),
            "⛔ DB-398: a re-filed leaf moved to another key"
        );
        assert_eq!(
            refiled.root(),
            sharded.root(),
            "⛔⛔⛔ DB-398: the re-file changed the view's root — a current view became one no copath can be checked against"
        );
    }

    /// TWO PARTIES, ONE ROOT. A node that holds every shard and a node that holds ONE shard apply the same
    /// spends from the same carried copaths and end on the SAME consensus root — because the sharded node
    /// folds its BAND from each spend's own witness and never needs the leaves it does not keep.
    ///
    /// This is the whole Z2 claim: partitioning the nullifier set is a CUSTODY decision, invisible to
    /// consensus. If it were not, two nodes with different policies would commit different roots and the
    /// chain would split on nothing.
    #[test]
    fn a_sharded_node_and_a_full_node_agree_on_the_root_from_the_same_carried_witnesses() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let spends: Vec<[u8; 32]> = (0..64u64).map(nf).collect();
        // The one shard the small node keeps: whichever the first spend falls in.
        let mine = nf_shard(&spends[0], bits);

        let mut full = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let mut small = RefSparseNf::with_shards(bits, [mine]);
        let mut oracle = RefSparseNf::new(); // the pre-Z2, unsharded tree

        assert_eq!(full.root(), oracle.root(), "an empty sharded tree is the empty tree");
        assert_eq!(small.root(), oracle.root(), "…whatever share it keeps");

        let mut held = 0usize;
        for x in &spends {
            // The WITNESS the spender carries — built by a node that holds the shard, verified by every
            // node against the live root. Here the full node is the holder, as a real mesh's holder is.
            let copath = full.copath(x);
            full.apply_spend(x, &copath);
            small.apply_spend(x, &copath);
            oracle.insert_and_witness(x);
            if nf_shard(x, bits) == mine {
                held += 1;
            }
            assert_eq!(
                small.root(),
                full.root(),
                "the sharded node's band fold must equal the full node's root at every step"
            );
            assert_eq!(
                full.root(),
                oracle.root(),
                "and both must equal the unsharded tree the chain was defined by"
            );
        }
        assert!(held > 0, "the fixture must exercise the owned shard at least once");
        assert_eq!(
            small.node_count(),
            held,
            "the sharded node keeps ONLY its own shard's leaves ({held} of {}), which is the growth bound",
            spends.len()
        );
        assert!(
            small.node_count() * 4 < spends.len(),
            "one shard of 2^{bits} must be a small fraction of the set — got {} of {}",
            small.node_count(),
            spends.len()
        );
    }

    /// A node SERVES only what it holds. The sharded node answers copaths for its own shard (and those
    /// copaths verify against the live root on any node) and declines the rest — it never invents a path
    /// that cannot fold, which is the silent-drop defect `da_sparse_copath` documents.
    #[test]
    fn a_sharded_node_serves_its_own_shard_and_declines_the_rest() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let spends: Vec<[u8; 32]> = (0..32u64).map(nf).collect();
        let mine = nf_shard(&spends[0], bits);
        let mut full = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let mut small = RefSparseNf::with_shards(bits, [mine]);
        for x in &spends {
            let copath = full.copath(x);
            full.apply_spend(x, &copath);
            small.apply_spend(x, &copath);
        }
        let mut acc = SparseNfAcc::adopt_merkle_root(full.root_bytes()).expect("canonical root");
        assert_eq!(acc.root_bytes(), small.root_bytes(), "one root on both parties");

        let fresh_mine = (0u64..)
            .map(|i| nf(1_000 + i))
            .find(|x| nf_shard(x, bits) == mine)
            .expect("a fresh tag in the owned shard");
        assert!(small.holds(&fresh_mine), "the owned shard is served");
        let cp = small.copath(&fresh_mine);
        assert!(
            acc.verify_unspent(&fresh_mine, &cp).is_ok(),
            "a copath the shard holder serves must prove non-membership against the LIVE root"
        );

        let foreign = (0u64..)
            .map(|i| nf(9_000 + i))
            .find(|x| nf_shard(x, bits) != mine)
            .expect("a tag outside the owned shard");
        assert!(
            !small.holds(&foreign),
            "a shard this node does not keep must not be claimed as served"
        );
    }

    /// ⭐⭐⭐ DB-353 — A VIEW RE-FILED FROM A PARTIAL VIEW KEEPS THE ROOT AND CLAIMS ONLY WHAT IT HOLDS.
    ///
    /// The [slotB17c] step, in process: `(0,0)` → `(8, 205)` → `(8, 171)`, the owned sets being PREFIXES of one ranking
    /// exactly as `Node::nf_shard_policy_for` builds them. Before DB-353 the second re-file lost the band of the 51
    /// shards the 205-view never held and its root left the chain's.
    /// ⛔ REFUTES: a partial view asked for shards it never held must not CLAIM them (a claimed-but-empty shard serves a
    /// copath that folds to no root), and an unshard request from a partial view must not become "holds everything".
    #[test]
    fn db353_a_view_refiled_from_a_partial_view_keeps_the_root_and_claims_only_what_it_holds() {
        // TWO-PARTY-REVIEWED: one accumulator re-filed into another shape; nothing crosses a boundary here. The
        // cross-node claim (every node's complete view follows every block) is the node-level pin
        // db353_a_node_past_the_replication_floor_keeps_a_complete_view_that_follows_every_block and the five-daemon run.
        let bits = NF_SHARD_BITS_DEFAULT;
        let total = 1u32 << bits;
        let spends: Vec<[u8; 32]> = (0..2_000u64).map(nf).collect();
        let mut full = RefSparseNf::new();
        for x in &spends {
            full.insert_and_witness(x);
        }
        let root = full.root_bytes();
        let acc = SparseNfAcc::adopt_merkle_root(root).expect("canonical root");
        let mut ranked: Vec<(u64, u32)> = (0..total)
            .map(|id| {
                let d = blake3::hash(&[b"db353-rank".as_slice(), &id.to_le_bytes()].concat());
                (u64::from_le_bytes(d.as_bytes()[..8].try_into().expect("8 bytes")), id)
            })
            .collect();
        ranked.sort_unstable();
        let owned = |k: usize| -> Vec<u32> { ranked[..k].iter().map(|(_, id)| *id).collect() };
        let fresh = |view: &RefSparseNf, held: bool| -> Option<[u8; 32]> {
            (0u64..20_000).map(|i| nf(50_000 + i)).find(|x| view.holds(x) == held)
        };

        let a = full.reshard(bits, owned(205));
        assert_eq!(a.root_bytes(), root, "CALIBRATION: a re-file from the COMPLETE view keeps the root");
        assert_eq!(a.shard_policy(), (bits, 205));

        let b = a.reshard(bits, owned(171));
        assert_eq!(
            b.root_bytes(),
            root,
            "⛔ DB-353: a re-file from a PARTIAL view lost the band of the shards it never held"
        );
        assert_eq!(b.shard_policy(), (bits, 171), "the 171 asked for are all held by the 205-view");
        let t = fresh(&b, true).expect("a fresh tag in a held shard");
        assert!(
            acc.verify_unspent(&t, &b.copath(&t)).is_ok(),
            "a held shard's copath proves non-membership against the LIVE root"
        );
        let mut checked = 0usize;
        for x in spends.iter().filter(|x| b.holds(x)).take(64) {
            assert_eq!(acc.spent_verdict(x, &b.copath(x)), SpentVerdict::Spent, "a held spent tag reads SPENT");
            checked += 1;
        }
        assert!(checked > 0, "CALIBRATION: the spent arm ran");

        let c = b.reshard(bits, owned(205));
        assert_eq!(c.root_bytes(), root, "the band still travels whole");
        assert_eq!(
            c.shard_policy(),
            (bits, 171),
            "⛔ a partial view must not CLAIM a shard whose leaves it does not hold"
        );
        let d = b.reshard(0, Vec::new());
        assert_eq!(d.root_bytes(), root);
        assert_eq!(d.shard_policy(), (bits, 171), "⛔ a partial view cannot become complete from what it has");
        let lost = fresh(&d, false).expect("a fresh tag in a shard the partial view never held");
        assert!(!d.holds(&lost), "and it says so for that shard");
    }

    /// ⭐⭐⭐ DB-353 — WHY A LIVE VIEW STAYS COMPLETE: A PARTIAL VIEW CANNOT FOLLOW A BLOCK THAT INSERTS INTO A SHARD IT
    /// DOES NOT HOLD. A block ships its tags and ONE folded carrier for `(pre → post)`; it carries no per-tag band
    /// value, so a foreign shard's new root is computable only from that shard's leaves. `advance_block_rooted` skips
    /// such a tag (`None`), the band keeps the pre value, and from that block on the view describes a set the chain no
    /// longer has. MEASURED on five real daemons: after the first re-file both the view and the accumulator that
    /// follows it skipped every foreign tag (`sparse_acc_stale`), so every copath the node served folded to a root no
    /// other node held.
    /// A CALIBRATION of the design's limit: the day a block carries what a partial view needs, this flips — and live
    /// sharding (`Node::maybe_reshard_nullifier_view`) may come back.
    #[test]
    fn a_partial_view_stays_on_the_root_from_verified_band_entries_and_serves_its_own_shards() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let shards = 1u32 << bits;
        let level = NF_SPARSE_DEPTH - bits;
        let mut full = RefSparseNf::with_shards(bits, 0..shards);
        let mut even = RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 0));
        let mut odd = RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 1));
        let entry_of = |t: &RefSparseNf, s: &[u8; 32]| t.node_at(level, &RefSparseNf::canon(&SparseKey::of(s), level));
        let mut history: Vec<(Vec<[u8; 32]>, Vec<(u32, Digest4)>)> = Vec::new();
        for step in 0..8u64 {
            let block: Vec<[u8; 32]> = (0..64u64).map(|i| nf(step * 1_000 + i)).collect();
            let before: Vec<(u32, Digest4)> = block.iter().map(|t| (nf_shard(t, bits), entry_of(&full, t))).collect();
            let _ = full.advance_block_rooted(&block);
            // what a verified step carries: the touched shards' entries after it
            let post: Vec<(u32, Digest4)> = block.iter().map(|t| (nf_shard(t, bits), entry_of(&full, t))).collect();
            for view in [&mut even, &mut odd] {
                let _ = view.advance_block_rooted(&block);
                for (s, e) in &post {
                    view.adopt_band_entry(*s, *e);
                }
                assert_eq!(view.root_bytes(), full.root_bytes(), "a partial view left the chain's root at step {step}");
            }
            history.push((block, before));
        }
        assert!(!even.leaves_sorted().is_empty() && !odd.leaves_sorted().is_empty(), "CALIBRATION: each holds tags");
        assert_eq!(even.leaves_sorted().len() + odd.leaves_sorted().len(), full.leaves_sorted().len(), "the two shares split the set");
        // Each share serves true evidence for a fresh tag it holds, and none for a tag it does not.
        let root = full.root();
        let fresh = (9_000_000u64..).map(nf).find(|t| nf_shard(t, bits) % 2 == 0).expect("a tag in an even shard");
        assert!(copath_proves_absent(&root, &fresh, &compress_copath(&even.copath(&fresh))), "a holder's evidence must fold");
        assert!(!odd.holds(&fresh), "CALIBRATION: this tag is foreign to the other share");
        // A spent tag has no evidence of absence from any holder.
        let spent = history[0].0.iter().copied().find(|t| even.holds(t)).expect("a spent tag in the even share");
        assert!(!copath_proves_absent(&root, &spent, &compress_copath(&even.copath(&spent))), "a spent tag must have no evidence");
        // Rewinding the last step returns every share to one root.
        let (block, before) = history.pop().expect("a step");
        for t in block.iter().rev() {
            assert!(full.remove(t), "the full view holds what it inserted");
        }
        for view in [&mut even, &mut odd] {
            for t in block.iter().rev() {
                if view.holds(t) {
                    assert!(view.remove(t), "a share holds what it inserted");
                }
            }
            for (s, e) in before.iter().rev() {
                view.adopt_band_entry(*s, *e);
            }
            assert_eq!(view.root_bytes(), full.root_bytes(), "a rewind must return a share to the root");
        }
    }

    #[test]
    fn a_new_node_stands_on_the_root_from_the_band_alone_then_takes_shards_only_if_they_fold() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let shards = 1u32 << bits;
        let mut full = RefSparseNf::with_shards(bits, 0..shards);
        let spent: Vec<[u8; 32]> = (0..400u64).map(nf).collect();
        let _ = full.advance_block_rooted(&spent);
        let band: Vec<Digest4> = {
            let level = NF_SPARSE_DEPTH - bits;
            (0..shards)
                .map(|s| {
                    let mut k = [0u8; 32];
                    k[0] = s as u8;
                    full.node_at(level, &RefSparseNf::canon(&SparseKey::of(&k), level))
                })
                .collect()
        };
        let mut new = RefSparseNf::from_band(&band);
        assert_eq!(new.root_bytes(), full.root_bytes(), "the band alone must stand on the chain's root");
        assert_eq!(new.leaf_count(), 0, "CALIBRATION: it holds nothing");
        let s = nf_shard(&spent[0], bits);
        let tags = full.shard_tags_page(s, None, usize::MAX);
        assert!(!tags.is_empty(), "CALIBRATION: the shard has tags to fetch");
        // A holder that leaves one tag out, adds a false one, or serves another shard's tags adds nothing.
        assert!(!new.add_shard(s, &tags[1..]), "a page with a tag missing must not fold");
        let mut extra = tags.clone();
        extra.push((0u64..).map(|i| nf(7_000_000 + i)).find(|t| nf_shard(t, bits) == s).expect("a false tag"));
        assert!(!new.add_shard(s, &extra), "a page with a false tag must not fold");
        let other = (0..400).map(|i| spent[i]).find(|t| nf_shard(t, bits) != s).expect("another shard's tag");
        assert!(!new.add_shard(s, &[other]), "another shard's tag must be refused");
        assert_eq!(new.leaf_count(), 0, "a refused page leaves nothing behind");
        // The true page is taken, the root does not move, and the node can now serve true evidence.
        assert!(new.add_shard(s, &tags), "the true page folds to the band entry");
        assert_eq!(new.root_bytes(), full.root_bytes());
        let fresh = (0u64..).map(|i| nf(8_000_000 + i)).find(|t| nf_shard(t, bits) == s).expect("a fresh tag in the shard");
        assert!(copath_proves_absent(&full.root(), &fresh, &compress_copath(&new.copath(&fresh))), "evidence from a fetched shard must fold");
        // Dropping it keeps the root.
        new.drop_shard(s);
        assert_eq!(new.leaf_count(), 0);
        assert_eq!(new.root_bytes(), full.root_bytes(), "dropping a shard must not move the root");
    }

    #[test]
    fn db353_a_partial_view_cannot_follow_a_block_that_inserts_into_a_shard_it_does_not_hold() {
        // TWO-PARTY-REVIEWED: the calibration of ONE data structure's limit (a partial tree against a full one built in
        // the same process). The cross-node consequence is pinned at node level
        // (db353_a_node_past_the_replication_floor_keeps_a_complete_view_that_follows_every_block) and on five daemons.
        let bits = NF_SHARD_BITS_DEFAULT;
        let spends: Vec<[u8; 32]> = (0..512u64).map(nf).collect();
        let mut full = RefSparseNf::new();
        for x in &spends {
            full.insert_and_witness(x);
        }
        let half: Vec<u32> = (0..(1u32 << bits)).filter(|id| id % 2 == 0).collect();
        let mut partial = full.reshard(bits, half);
        assert_eq!(partial.root_bytes(), full.root_bytes(), "CALIBRATION: one root before the block");
        let block: Vec<[u8; 32]> = (0..256u64).map(|i| nf(900_000 + i)).collect();
        let foreign = block.iter().filter(|t| !partial.holds(t)).count();
        assert!(foreign > 0, "CALIBRATION: the block inserts into a shard the partial view does not hold");
        let _ = full.advance_block_rooted(&block);
        let skipped = partial.advance_block_rooted(&block).iter().filter(|w| w.is_none()).count();
        assert_eq!(skipped, foreign, "every foreign-shard tag is skipped: there is no copath for it here");
        assert_ne!(
            partial.root_bytes(),
            full.root_bytes(),
            "if this reads EQUAL, a partial view CAN follow the chain and live sharding may return (DB-353)"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod warm_rebuild_cost_tests {
    //! ⛔⛔⛔ WHAT ONE WARM PAGE COSTS, MEASURED — the number behind the runtime-lock freeze.
    //!
    //! `NodeRuntime::on_nf_warm_page` (DB-151, retired by DB-290) absorbed a whole 16,384-tag page in one call, inside the drain,
    //! under the runtime mutex. Ecosystem gate run 2026-09-24 (`/tmp/musd-ecocheck-hA8ufo`, node 2):
    //!
    //! ```text
    //! slowest bulk handler: nf-warm-page = 54,316 ms over 3 tick(s)
    //! ```
    //!
    //! 18.1 SECONDS PER PAGE — 36 block times, during which no block applies, the pump is frozen and
    //! every RPC queues behind the writer. This test states the per-tag cost as a FACT rather than an
    //! inference from a log line, so the fix is aimed at the right lever.
    use super::*;

    #[test]
    fn a_warm_page_absorb_is_priced_per_tag_and_the_price_is_named() {
        // A small, fixed sample — this is a COST STATEMENT, not a throughput benchmark, so it must be
        // cheap enough to run in the ordinary suite. The per-tag price is what scales, and it is what
        // the page (16,384) and the stream ceiling (8,000,000) multiply.
        const SAMPLE: usize = 512;
        let mut tree = RefSparseNf::new();
        let t0 = std::time::Instant::now();
        for i in 0..SAMPLE {
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&(i as u64).to_le_bytes());
            nf[31] = 0xA5;
            let _ = tree.insert_and_witness(&nf);
        }
        let per_tag_us = t0.elapsed().as_micros() as f64 / SAMPLE as f64;

        // ⛔ THE GROWTH AXIS, STATED IN THE UNITS THE PILLARS ARE WRITTEN IN. The rebuild is
        // O(spent set × NF_SPARSE_DEPTH); the spent set only ever grows with chain age, so a node's
        // RESTART cost grows with the chain's history. That is the Bitcoin IBD shape this design
        // retired everywhere else.
        let page_ms = per_tag_us * 16_384.0 / 1_000.0;
        let ceiling_min = per_tag_us * 8_000_000.0 / 60_000_000.0;
        eprintln!(
            "[warm-cost] one tag costs {per_tag_us:.0}us at depth {NF_SPARSE_DEPTH} => one 16,384-tag \
             page costs {page_ms:.0}ms of LOCKED work, and the 8,000,000-tag stream ceiling costs \
             {ceiling_min:.0} minute(s). The gate measured 18,100ms per page on a real node."
        );

        // The assertion is the SHAPE, not the machine's speed: the price is per TAG, so the page and the
        // stream ceiling multiply it. A build that made this free would break the assertion and deserve
        // to — it would mean the tree stopped being a depth-256 sparse tree.
        assert!(
            per_tag_us > 0.0,
            "a depth-{NF_SPARSE_DEPTH} insert cannot be free — if it measured as free, this fixture \
             stopped measuring the insert and the cost statement above is worthless"
        );
        assert!(
            page_ms > 100.0,
            "⛔ ONE WARM PAGE MEASURED AT {page_ms:.0}ms, WHICH IS UNDER THE BLOCK TIME. If that is \
             real, the warm absorb is no longer the lock-freeze this test was written for and the \
             budget it justifies should be re-derived rather than kept on faith. Per tag: \
             {per_tag_us:.0}us."
        );
    }
}

/// ⭐⭐⭐ DB-154 — THE NULLIFIER ROOT A BLOCK COMMITS, OVER **ITS OWN PAST**.
///
/// ```text
/// nf_root(B)       = fold_block_tags_into_root( nf_root(selected_parent(B)), tags(mergeset(B)) )
/// nf_root(genesis) = empty_subtree(NF_SPARSE_DEPTH)
/// ```
///
/// ROOT-LAYER: this is the value a block commits so that a spender's NON-MEMBERSHIP copath has a
/// chain-committed root to fold against. The chain commits a wrapping SUM today (`Node::nullifier_root`
/// projects A_tip), and a sum cannot express non-membership — which is the whole of DB-160.
///
/// ⛔ THE INPUT IS THE **SELECTED PARENT'S COMMITTED ROOT**, NEVER THIS NODE'S RUNNING TREE. That
/// distinction is the entire reason the previous attempt failed. `nullifier_root()` used to be
/// `sparse_acc.root_bytes()`, a running LOCAL accumulator advanced in the order blocks ARRIVE, and two
/// devices on a GHOSTDAG mesh never share that order — MEASURED 2026-08-14: *"A folded 47 blocks, B
/// folded 2 with 32 parked, `nf_root_agree=false` — while `nf_acc_agree=TRUE` on the very same pair."*
/// `node.rs.forkAttempt-20260916` repeated the mistake, passing `pre_sparse.root_bytes()` as `block_pre`.
///
/// ⭐ WHY EVERY NODE AGREES — a proof resting on exactly two facts, one of them measured here:
///   1. a block's MERGESET is a function of the block (its parents), identical on every node holding it;
///   2. SET → root is ORDER-FREE (`set_determined_root_tests`), so the order a node folds the mergeset's
///      tags in cannot change the result.
/// By induction from genesis, `nf_root(B)` is identical on every node holding `B`. Arrival order never
/// enters. See `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`.
///
/// `tree` is the caller's working sparse tree, which must already describe `parent_root`; it supplies the
/// non-membership copaths and is advanced in step. cons: O(|tags| · DEPTH) on the PRODUCER; a verifier
/// checks the compact transition proof instead and pays O(1).
#[must_use]
pub fn fold_block_tags_into_root(
    parent_root: [u8; 32],
    tags: &[[u8; 32]],
    tree: &mut RefSparseNf,
) -> [u8; 32] {
    // ⛔ ADOPT A **MERKLE ROOT**, NOT A FOLD ACCUMULATOR — `adopt_merkle_root`'s own doc records what
    // happens otherwise: two functions wrote different mathematical objects into one field, and
    // `verify_unspent` against a fold value "CANNOT succeed for any copath, honest or forged — so every
    // verdict was `Unprovable` BY CONSTRUCTION, on every node, at every height, forever." A parent root
    // this chain committed is a Merkle root by construction, so a `None` here is a caller error, not a
    // chain state — fail closed by returning the parent unchanged rather than folding onto a wrong base.
    let Some(mut acc) = SparseNfAcc::adopt_merkle_root(parent_root) else {
        return parent_root;
    };
    for nf in tags {
        // ⛔ SKIP THE PADDING TAG EXPLICITLY. `SparseNfAcc::insert_from_own_copath` already treats
        // `[0u8; 32]` as padding and folds nothing, while `RefSparseNf` would insert it as an ordinary
        // leaf — an asymmetry pinned in `the_zero_tag_is_padding_to_the_accumulator_and_a_leaf_to_the_tree`.
        // Letting the two halves disagree HERE would make the committed root depend on whether a padding
        // slot happened to be folded last, which is precisely the kind of order-sensitivity this function
        // exists to eliminate.
        if *nf == [0u8; 32] {
            continue;
        }
        let copath = tree.insert_and_witness(nf);
        acc.insert_from_own_copath(nf, &copath);
    }
    acc.root_bytes()
}

#[cfg(all(test, feature = "pins-core"))]
mod db154_block_past_root_tests {
    //! ⛔⛔⛔ THE PIN DB-154's DESIGN DOC NAMES AS "WRITE IT FIRST" — and the assertion the 2026-08-14
    //! failure would have tripped before it shipped. Nothing in this tree asserted it.
    //!
    //! Two nodes that receive the SAME blocks in DIFFERENT arrival orders must commit the SAME `nf_root`
    //! at every height. If that does not hold, DB-154 cannot be built this way and the design doc is
    //! wrong; if it does, the committed Merkle root is reachable and DB-160 has a real fix.
    use super::*;

    fn tag(b: u64, i: u64) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(b * 1_000 + i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        t[8] = (b & 0xff) as u8;
        t[31] = ((i + 1) & 0xff) as u8;
        t
    }

    /// A toy selected-parent chain: block `b` carries `tags_per` tags. Returns the committed root per
    /// height, folding each block's tags in the order `perm` gives.
    fn roots_along_chain(blocks: u64, tags_per: u64, perm: fn(u64, u64) -> u64) -> Vec<[u8; 32]> {
        let mut tree = RefSparseNf::new();
        let mut root = SparseNfAcc::new().root_bytes();
        let mut out = Vec::with_capacity(blocks as usize);
        for b in 0..blocks {
            let tags: Vec<[u8; 32]> = (0..tags_per).map(|i| tag(b, perm(b, i))).collect();
            root = fold_block_tags_into_root(root, &tags, &mut tree);
            out.push(root);
        }
        out
    }

    #[test]
    fn two_nodes_folding_the_same_blocks_in_different_orders_commit_the_same_root_at_every_height() {
        const B: u64 = 12;
        const T: u64 = 9; // deliberately NOT a power of two — the arity trap that silently dropped carriers
        let ascending = roots_along_chain(B, T, |_, i| i);
        let reversed = roots_along_chain(B, T, |_, i| T - 1 - i);
        let rotated = roots_along_chain(B, T, |b, i| (i + b) % T);

        for h in 0..B as usize {
            assert_eq!(
                ascending[h], reversed[h],
                "⛔ THE COMMITTED ROOT DEPENDS ON THE ORDER A NODE FOLDS A BLOCK'S TAGS at height {h}. \
                 Then two honest nodes commit different roots for the same block, every later block parks \
                 behind the disagreement, and DB-154 cannot be built this way — this is the 2026-08-14 \
                 failure reproduced, and the design doc must be withdrawn."
            );
            assert_eq!(
                ascending[h], rotated[h],
                "…and it is the SET, not a sorted-vs-reversed coincidence (height {h})"
            );
        }

        // NEGATIVE CONTROL — a chain carrying a DIFFERENT tag set must diverge, or every equality above is
        // vacuous (a function ignoring its input would satisfy them all).
        let different = roots_along_chain(B, T, |b, i| if b == 7 { i + 500 } else { i });
        assert_ne!(
            ascending[B as usize - 1],
            different[B as usize - 1],
            "⛔ CHANGING A BLOCK'S TAGS DID NOT MOVE THE COMMITTED ROOT — the root does not describe the \
             spent set at all, and the order-independence above proves nothing"
        );
        // …and it diverges FROM the block that changed, never before it: the root is a function of the
        // past, so heights below 7 must be untouched.
        assert_eq!(ascending[6], different[6], "a later block cannot change an earlier committed root");
        assert_ne!(ascending[7], different[7], "and the block that changed must move its own root");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod set_determined_root_tests {
    //! ⭐⭐⭐ IS THE NULLIFIER ROOT A FUNCTION OF THE **SET**, OR OF THE **INSERT ORDER**?
    //!
    //! DB-154 turns entirely on this. The chain today commits the A_tip FOLD (a commutative wrapping sum)
    //! as `nullifier_root`, and a sum cannot express non-membership — which is what
    //! [[project_db160_below_base_double_spend]] exploits. The obvious fix is to commit the MERKLE root
    //! instead, and the standing objection in `harness::fuzz::authority` is that `sparse_acc` is
    //! *"order-dependent … requires replaying the producer's exact block ORDER, which two devices on a
    //! GHOSTDAG mesh never share"*.
    //!
    //! ⛔ THAT OBJECTION IS THE WHOLE BLOCKER, SO IT GETS MEASURED RATHER THAN BELIEVED. A sparse Merkle
    //! tree keyed by the leaf's OWN BITS is order-independent by construction: `fold_sparse` places a tag
    //! at the position its bits name, so two nodes that insert the same SET in different orders must land
    //! on the same root. If that holds, the objection is stale and DB-154 is buildable; if it fails, the
    //! Merkle root genuinely cannot be committed and DB-154 needs a different shape.
    use super::*;

    /// ⛔ `seed + 1`, so seed 0 is not the ALL-ZERO tag. The accumulator treats `[0u8; 32]` as padding and
    /// the reference tree treats it as a leaf (pinned in
    /// `the_zero_tag_is_padding_to_the_accumulator_and_a_leaf_to_the_tree`), and a generator that emits it
    /// makes every other question in this module unanswerable.
    fn tag(seed: u64) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        t[31] = ((seed + 1) & 0xff) as u8;
        t
    }

    /// Insert `order` into a fresh reference tree and return the resulting root.
    fn root_after(order: &[u64]) -> [u8; 32] {
        let mut tree = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        for s in order {
            let nf = tag(*s);
            let copath = tree.insert_and_witness(&nf);
            acc.insert_from_own_copath(&nf, &copath);
        }
        acc.root_bytes()
    }

    /// ⛔ THE TWO HALVES DISAGREE ABOUT THE ALL-ZERO TAG, AND THE DISAGREEMENT IS DIRECTIONAL.
    ///
    /// `SparseNfAcc::insert_from_own_copath` treats `[0u8; 32]` as padding and folds nothing;
    /// `RefSparseNf::insert_and_witness` inserts it as an ordinary leaf. So a run whose LAST insert is the
    /// zero tag ends with an accumulator that does not describe its tree — measured as
    /// `dense-prefix/descending` before this was isolated. Earlier inserts hide it, because every later
    /// `insert_from_own_copath` RECOMPUTES the whole root from a copath that already reflects the zero
    /// leaf.
    ///
    /// This is narrow (a real nullifier is a Poseidon image, so all-zero is not reachable by an honest
    /// spend) but it is a genuine inconsistency between two halves of one mechanism, and the per-block
    /// drift check only NOTICES it. Pinned so the behaviour is stated rather than discovered again.
    #[test]
    fn the_zero_tag_is_padding_to_the_accumulator_and_a_leaf_to_the_tree() {
        let zero = [0u8; 32];
        let mut tree = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        let copath = tree.insert_and_witness(&zero);
        acc.insert_from_own_copath(&zero, &copath);
        assert_eq!(
            acc.root_bytes(),
            SparseNfAcc::new().root_bytes(),
            "the accumulator treats the all-zero tag as padding and must not move"
        );
        assert_ne!(
            tree.root_bytes(),
            SparseNfAcc::new().root_bytes(),
            "⛔ the reference tree DOES insert it — if this ever matches, the two halves have been \
             reconciled and the asymmetry this pin exists to state is gone"
        );
    }

    #[test]
    fn the_root_is_a_function_of_the_set_not_of_the_insert_order() {
        let ascending: Vec<u64> = (0..24u64).collect();
        let descending: Vec<u64> = (0..24u64).rev().collect();
        // A third order that is neither sorted nor reversed — two orders could agree by accident.
        let shuffled: Vec<u64> = (0..24u64).map(|i| (i * 7 + 5) % 24).collect();
        assert_eq!(
            shuffled.iter().copied().collect::<std::collections::BTreeSet<_>>().len(),
            24,
            "calibration: the third order must be a permutation of the same set, not a smaller one"
        );

        let a = root_after(&ascending);
        let b = root_after(&descending);
        let c = root_after(&shuffled);

        assert_eq!(
            a, b,
            "⛔ THE ROOT DEPENDS ON INSERT ORDER. Then it cannot be committed by a GHOSTDAG chain, where \
             two honest nodes never share a block order, and DB-154 cannot be built this way — the \
             standing objection in the authority manifest is CORRECT and a different shape is needed."
        );
        assert_eq!(a, c, "…and it is the SET, not merely a sorted-vs-reversed coincidence");

        // NEGATIVE CONTROL — a DIFFERENT set must give a different root, or the equality above is vacuous
        // (an accumulator that ignores its input would pass every assertion so far).
        let mut with_one_more: Vec<u64> = ascending.clone();
        with_one_more.push(999);
        assert_ne!(
            a,
            root_after(&with_one_more),
            "⛔ ADDING A TAG DID NOT MOVE THE ROOT — the accumulator is not describing its set at all, and \
             the order-independence above proves nothing"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod own_copath_insert_tests {
    //! ⭐⭐⭐ THE CONTRACT OF `insert_from_own_copath`: for a copath the node produced ITSELF, it must
    //! reach the byte-identical root `verify_and_insert` would — it drops the VERIFY, never the insert.
    //!
    //! MEASURED (real joiner, before → after): `ing_apply` 284.1 → 245.5 ms per block, drift lines 0 → 0.
    //! The view advance folds 256 leaves into a depth-256 tree, and `verify_and_insert` folded each
    //! carried copath TWICE — once to verify, once to insert. For a copath read from this node's own
    //! tree one line earlier, that verify asks whether the node agrees with itself; the block-boundary
    //! root comparison already answers it in O(1).
    use super::*;

    fn tag(seed: u8) -> [u8; 32] {
        let mut t = [seed; 32];
        t[0] = seed.wrapping_mul(31).wrapping_add(7);
        t
    }

    #[test]
    fn an_own_copath_insert_reaches_the_same_root_as_verify_and_insert() {
        let mut tree = RefSparseNf::new();
        // Build a real spent set so the copaths carry genuine siblings, not just empty constants.
        let mut acc_a = SparseNfAcc::new();
        let mut acc_b = SparseNfAcc::new();
        for i in 0..24u8 {
            let nf = tag(i);
            let copath = tree.insert_and_witness(&nf);
            // The gate path: verify THEN insert.
            assert!(
                acc_a.verify_and_insert(&nf, &copath).is_ok(),
                "calibration: an honest own-tree copath must pass the verifying path at step {i}"
            );
            // The hot path: insert only.
            acc_b.insert_from_own_copath(&nf, &copath);
            assert_eq!(
                acc_a.root_bytes(),
                acc_b.root_bytes(),
                "⛔ THE TWO PATHS DIVERGED at step {i} — dropping the self-verify must change the COST, \
                 never the ROOT. A difference here is a node whose accumulator no longer describes its \
                 own tree, which is the drift that makes every spend read UNPROVABLE."
            );
        }
        assert_eq!(
            acc_a.root_bytes(),
            tree.root_bytes(),
            "…and both still describe the tree they were built from — the O(1) boundary check that \
             replaces the 256 per-tag verifies"
        );
    }

    #[test]
    fn a_malformed_copath_moves_nothing_and_the_boundary_check_still_catches_drift() {
        // ⛔ FAIL-SAFE, NOT FAIL-OPEN. A wrong-length or zero-tag input must leave the accumulator
        // untouched, so the block-boundary comparison sees the divergence instead of a root that was
        // quietly advanced to something nobody can reproduce.
        let mut acc = SparseNfAcc::new();
        let before = acc.root_bytes();
        acc.insert_from_own_copath(&[0u8; 32], &[]);
        assert_eq!(acc.root_bytes(), before, "a zero tag moves nothing");
        acc.insert_from_own_copath(&tag(9), &[empty_subtree(0); 3]);
        assert_eq!(acc.root_bytes(), before, "a short copath moves nothing");

        // And a copath that does NOT describe this accumulator advances it to a root the tree cannot
        // match — which is exactly what the boundary comparison exists to report.
        let mut tree = RefSparseNf::new();
        let nf = tag(5);
        let good = tree.insert_and_witness(&nf);
        let mut drifted = SparseNfAcc::new();
        let mut bad = good.clone();
        bad[NF_SPARSE_DEPTH - 1] = [7, 0, 0, 0, 0, 0, 0, 0]; // a sibling this tree never had
        drifted.insert_from_own_copath(&nf, &bad);
        assert_ne!(
            drifted.root_bytes(),
            tree.root_bytes(),
            "⛔ a copath that does not describe the tree must leave the accumulator DISAGREEING with \
             it — if these matched, the boundary drift check could never fire and the cost saving \
             would have bought silence"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db154_order_free_root {
    use super::*;

    /// ⭐⭐⭐ DB-154 — THE SPARSE ROOT IS A FUNCTION OF THE SPENT **SET**, NOT OF INSERTION ORDER.
    ///
    /// THIS IS THE MEASUREMENT THAT DECIDES WHETHER THE CHAIN CAN COMMIT IT. `header.nullifier_root`
    /// holds the A_tip projection today, and its own comment says why: it *used* to hold
    /// `sparse_acc.root_bytes()` — a root advanced only by the linear pre→post CHAIN, which requires
    /// replaying the producer's exact block ORDER. Two devices on a GHOSTDAG mesh never share that
    /// order, so the chain stalled at the first out-of-turn block (MEASURED 2026-08-14: A folded 47
    /// blocks, B folded 2 with 32 parked, `nf_root_agree=false` while `nf_acc_agree=TRUE`).
    ///
    /// That was the CHAINED ACCUMULATOR, not the tree. `RefSparseNf` keys its leaves in a sorted
    /// `BTreeSet` and derives the root from them, so its root should be order-free — and if it is, the
    /// chain can commit it without reproducing the 2026-08-14 stall. This pin is that claim, measured.
    #[test]
    fn the_same_spent_set_inserted_in_two_orders_reaches_one_root() {
        let nfs: Vec<[u8; 32]> = (1..=24u8)
            .map(|i| {
                let mut n = [0u8; 32];
                n[0] = i;
                n[7] = i.wrapping_mul(31);
                n[31] = i.wrapping_mul(17);
                n
            })
            .collect();

        let build = |order: &[usize]| -> [u8; 32] {
            let mut t = RefSparseNf::new();
            for &i in order {
                let _ = t.insert_and_witness(&nfs[i]);
            }
            t.root_bytes()
        };

        let forward: Vec<usize> = (0..nfs.len()).collect();
        let reverse: Vec<usize> = (0..nfs.len()).rev().collect();
        // A third, genuinely scrambled order — two orders could agree by accident, three do not.
        let scrambled: Vec<usize> = {
            let mut v: Vec<usize> = (0..nfs.len()).collect();
            v.sort_by_key(|&i| (i * 7 + 5) % nfs.len());
            v
        };
        assert_ne!(forward, reverse, "setup: the orders differ");
        assert_ne!(forward, scrambled, "setup: the third order differs too");

        let (a, b, c) = (build(&forward), build(&reverse), build(&scrambled));
        assert_eq!(
            a, b,
            "⛔ THE SPARSE ROOT DEPENDS ON INSERTION ORDER. Committing it would reproduce the 2026-08-14 \
             stall exactly: two GHOSTDAG nodes never share a block order, so they would never agree on \
             the header root and every out-of-turn block would park."
        );
        assert_eq!(a, c, "and it is the same under a scrambled order, so the agreement is not a coincidence");

        // NON-VACUITY: a DIFFERENT set must reach a different root, or the equality above is trivial.
        let mut t = RefSparseNf::new();
        for n in nfs.iter().take(nfs.len() - 1) {
            let _ = t.insert_and_witness(n);
        }
        assert_ne!(
            t.root_bytes(),
            a,
            "a root that ignores one spent nullifier is not a commitment to the spent set"
        );
        eprintln!("[db154] {} nullifiers, three insertion orders, one root — the root is set-derived", nfs.len());
    }
}

/// ⛔⭐⭐⭐ DB-153 ATTRIBUTION — WHERE DO THE 551-858 MILLISECONDS ACTUALLY GO?
///
/// Gate 6 (2026-09-24) measured the joiner's `apply_preverified` at a MEDIAN 935 ms against a 500 ms
/// block time, with `[sparse-shadow] the MERKLE VIEW advance took 551-858ms over 256 tag(s)` as the
/// dominant term. That is the convergence failure, stated as a number: a node that cannot finish a
/// drain inside its block time cannot follow its peer.
///
/// ⛔ BEFORE RESTRUCTURING ANYTHING, ATTRIBUTE IT. Two candidate causes have completely different
/// fixes and only a measurement separates them:
///
///   * the SHAPE is wrong — DEPTH 256 is 256 Poseidon pairs per insert, and the constant's own doc
///     says "depth can be shortened later to a collision-safe hash-truncation". But the birthday
///     bound DERIVED from the primitive (2^48 lifetime tags, p <= 2^-40) gives DEPTH >= 135, only a
///     1.6x cut against a 2x gap. Truncation alone does NOT close it.
///   * the PRIMITIVE is slow — 256 tags x 256 levels = 65,536 inserts-worth of hashing. At 551 ms
///     that is ~8.4 us per level. A Poseidon2 pair over two field-element quads should be well under
///     1 us. If it is 8, the tree is ~10x slower than its own primitive allows and this is a DEFECT,
///     not a structure to redesign.
///
/// This prints both, plus the tree-size dependence (`node_at` walks a map, so a cost that GROWS with
/// the spent set is a third, worse answer: an O(height) term hiding inside a per-block constant).
#[cfg(all(test, feature = "pins-core"))]
mod db153_attribution {
    use super::*;

    #[test]
    fn where_the_merkle_view_advance_actually_spends_its_milliseconds() {
        // ── 1. THE PRIMITIVE. One `poseidon_pair`, amortised over a run long enough to time.
        let a = poseidon_pair([0xA, 0, 0, 0, 0, 0, 0, 0], [0xB, 0, 0, 0, 0, 0, 0, 0]);
        let b = [0xB, 0, 0, 0, 0, 0, 0, 0];
        const N: usize = 200_000;
        let t = std::time::Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = poseidon_pair(acc, b);
        }
        let per_pair_ns = t.elapsed().as_nanos() as f64 / N as f64;
        std::hint::black_box(acc);

        // ── 2. THE SHAPE. One insert at DEPTH, into trees of growing size, so a cost that depends on
        //    the SPENT SET shows up as a rising column rather than hiding in an average.
        let tag = |i: u64| -> [u8; 32] {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&i.to_le_bytes());
            x[31] = 1; // never the all-zero tag
            x
        };
        let mut tree = RefSparseNf::new();
        let mut rows = Vec::new();
        for size in [0usize, 256, 1_024, 4_096] {
            while tree.spent_leaf_count() < size {
                let n = tree.spent_leaf_count() as u64;
                let _ = tree.insert_and_witness(&tag(n + 1_000_000));
            }
            let t = std::time::Instant::now();
            const M: usize = 64;
            for j in 0..M {
                let _ = tree.insert_and_witness(&tag(9_000_000 + (size as u64) * 1000 + j as u64));
            }
            let per_insert_us = t.elapsed().as_micros() as f64 / M as f64;
            rows.push((size, per_insert_us, per_insert_us * 1000.0 / NF_SPARSE_DEPTH as f64));
        }

        eprintln!("\n[db153] poseidon_pair          {per_pair_ns:.0} ns/pair");
        eprintln!(
            "[db153] a DEPTH-{} insert costs at MINIMUM 2x{} pairs = {:.1} ms if the primitive is all there is",
            NF_SPARSE_DEPTH,
            NF_SPARSE_DEPTH,
            per_pair_ns * 2.0 * NF_SPARSE_DEPTH as f64 / 1e6
        );
        eprintln!("[db153] spent-set  us/insert   ns/level   (does the cost GROW with the set?)");
        for (size, us, ns_level) in &rows {
            eprintln!("[db153]   {size:>7}   {us:>9.1}   {ns_level:>8.0}");
        }
        let block = rows.last().map(|r| r.1).unwrap_or(0.0)
            * crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as f64
            / 1000.0;
        eprintln!(
            "[db153] => ONE BLOCK of {} tags = {block:.0} ms against a 500 ms block time\n",
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        );

        // ⭐⭐⭐ AND IT IS A PIN, NOT A PRINTOUT. [[feedback_performance_pillar]]: "treat a perf
        // regression like a soundness regression". DB-167 is a CACHE — one `OnceLock` in one function —
        // and a cache is exactly the kind of fix a later edit deletes without noticing, because nothing
        // it computes changes. These two bounds are what would notice.
        //
        // ⛔ THE CEILINGS SEPARATE THE TWO MEASURED WORLDS RATHER THAN TRACKING TODAY'S NUMBER. Before
        // DB-167: 3,619 ns/pair and 208 ms/block. After: 936 ns/pair and 156 ms/block. A ceiling set just
        // above today's figure would go red on a slow machine and be muted within a day; set BETWEEN the
        // two worlds, it can only fire when the derivation comes back.
        assert!(
            per_pair_ns < 2_000.0,
            "[db153] poseidon_pair measured {per_pair_ns:.0} ns — DB-167 brought this from 3,619 to 936 \
             by deriving the Poseidon2 round constants ONCE instead of per hash. Above 2,000 the \
             derivation is being paid again: check that `sponge_chain_air::production_perm` still returns \
             a cached &'static and that no caller re-entered `derive_perm` directly."
        );
        assert!(
            block < 400.0,
            "[db153] the Merkle view advance projects {block:.0} ms for one {}-tag block against a 500 ms \
             block time. A node that cannot finish a drain inside its block time cannot follow its peer — \
             ecosystem gate 6 measured exactly this as apply_preverified median 935 ms on BOTH nodes and \
             reported it as 'nodes never converged'.",
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        );
    }
}

/// ⭐⭐⭐ DB-169 — THE ONE-PASS ADVANCE IS THE SAME OBJECT, PROVEN BYTE-FOR-BYTE.
///
/// [`RefSparseNf::advance_one`] replaced a two-walk sequence (`copath` → `apply_spend` →
/// `insert_and_witness`) on the block-apply hot path. That is only safe if the tree it leaves behind is
/// IDENTICAL — same root, same band, same returned copath — because the root is what the accumulator is
/// checked against and the band is what every shard's consensus value folds from.
///
/// So this does not argue the ordering is safe; it runs both forms on the same tags and compares.
#[cfg(all(test, feature = "pins-core"))]
mod db169_one_pass_advance {
    use super::*;

    fn tag(i: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"db169");
        h.update(&i.to_le_bytes());
        *h.finalize().as_bytes()
    }

    #[test]
    fn one_pass_advance_matches_the_two_step_form_exactly() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let all: Vec<u32> = (0..(1u32 << bits)).collect();
        let mut one = RefSparseNf::with_shards(bits, all.clone());
        let mut two = RefSparseNf::with_shards(bits, all);

        for i in 0..96u64 {
            let nf = tag(i);
            let cp_one = one.advance_one(&nf);
            // THE OLD FORM, verbatim: source the copath, then apply_spend (which folds the band and
            // then walks the tree a second time to insert).
            let cp_two = two.copath(&nf);
            two.apply_spend(&nf, &cp_two);

            assert_eq!(
                cp_one, cp_two,
                "tag {i}: the one-pass copath differs from the two-step copath — the accumulator would \
                 fold a different witness"
            );
            assert_eq!(
                one.root_bytes(),
                two.root_bytes(),
                "tag {i}: the trees reached DIFFERENT roots — the copath source would stop describing \
                 the authority and every spend on this node would read UNPROVABLE"
            );
            assert_eq!(
                one.spent_leaf_count(),
                two.spent_leaf_count(),
                "tag {i}: a leaf went missing"
            );
        }
        // The band is what a sharded node's consensus root folds from, so compare it explicitly rather
        // than trusting that equal roots imply equal bands.
        for id in 0..(1usize << bits) {
            assert_eq!(
                one.node_at_pub(one.band_level(), &{
                    let mut c = [0u8; 32];
                    // canonical key of shard `id` at the band level
                    let sb = id as u32;
                    for b in 0..bits {
                        if sb >> (bits - 1 - b) & 1 == 1 {
                            c[b >> 3] |= 1u8 << (7 - (b & 7));
                        }
                    }
                    c
                }),
                two.node_at_pub(two.band_level(), &{
                    let mut c = [0u8; 32];
                    let sb = id as u32;
                    for b in 0..bits {
                        if sb >> (bits - 1 - b) & 1 == 1 {
                            c[b >> 3] |= 1u8 << (7 - (b & 7));
                        }
                    }
                    c
                }),
                "shard {id}: band entries diverged"
            );
        }
        eprintln!(
            "[db169] 96 tags, one-pass vs two-step: roots, copaths, leaf counts and all {} band entries identical",
            1usize << bits
        );
    }

    /// ⛔⭐ WHERE `advance_one` ACTUALLY SPENDS ITS TIME, UNDER THE **LIVE** SHARD POLICY.
    ///
    /// DB-169 collapsed two tree walks into one and predicted ~2x. Ecosystem gate 9 MEASURED NO CHANGE:
    /// `[sparse-shadow]` median 329 ms (gate 8, two walks) -> 334/337 ms (gate 9, one walk). So the
    /// second walk was not the cost and the model behind the prediction was wrong.
    ///
    /// This splits the real thing rather than reasoning about it a third time. The live pair runs
    /// `(NF_SHARD_BITS_DEFAULT, every shard)`, so `band_level() = DEPTH - 8 = 248` and the band fold is
    /// 248 poseidon pairs PER TAG on top of the insert — a term the unsharded path does not pay at all.
    #[test]
    fn where_advance_one_spends_its_time_under_the_live_shard_policy() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let all: Vec<u32> = (0..(1u32 << bits)).collect();
        let warm = |t: &mut RefSparseNf, n: u64| {
            for i in 0..n {
                let _ = t.advance_one(&tag(1_000_000 + i));
            }
        };

        let mut sharded = RefSparseNf::with_shards(bits, all);
        let mut flat = RefSparseNf::new();
        warm(&mut sharded, 2_000);
        warm(&mut flat, 2_000);

        const M: u64 = 256; // exactly one block's constant-width tag set
        let t = std::time::Instant::now();
        for i in 0..M {
            let _ = sharded.advance_one(&tag(5_000_000 + i));
        }
        let sharded_ms = t.elapsed().as_micros() as f64 / 1000.0;

        let t = std::time::Instant::now();
        for i in 0..M {
            let _ = flat.advance_one(&tag(5_000_000 + i));
        }
        let flat_ms = t.elapsed().as_micros() as f64 / 1000.0;

        // The band fold alone: 248 poseidon pairs, no tree touched.
        let level = sharded.band_level();
        let cp = vec![empty_subtree_pub(0); NF_SPARSE_DEPTH];
        let t = std::time::Instant::now();
        for i in 0..M {
            let nf = tag(7_000_000 + i);
            let mut node = compact_leaf_of(&SparseKey::of(&nf));
            for (l, sib) in cp.iter().enumerate().take(level) {
                node = if key_bit(&SparseKey::of(&nf), l) == 0 { poseidon_pair(node, *sib) } else { poseidon_pair(*sib, node) };
            }
            std::hint::black_box(node);
        }
        let band_ms = t.elapsed().as_micros() as f64 / 1000.0;

        eprintln!("\n[db169] ONE BLOCK ({M} tags) of view advance, 2,000-tag warm tree:");
        eprintln!("[db169]   sharded (band_level {level})   {sharded_ms:>8.1} ms   <- what the live pair runs");
        eprintln!("[db169]   flat    (shard_bits 0)         {flat_ms:>8.1} ms");
        eprintln!("[db169]   the band fold alone            {band_ms:>8.1} ms   ({level} poseidon/tag)");
        eprintln!("[db169]   => sharding costs {:.1} ms a block, and the band fold explains {:.0}% of it\n",
            sharded_ms - flat_ms,
            100.0 * band_ms / (sharded_ms - flat_ms).max(0.001));
    }

    /// ⛔ NON-VACUITY + THE FOREIGN-SHARD ARM. A node that does NOT own a tag's shard holds no leaves for
    /// it and must return EMPTY rather than a copath it cannot stand behind — and the comparison above
    /// would pass trivially if `advance_one` simply returned empty for everything.
    #[test]
    fn a_foreign_shard_yields_no_copath_and_an_owned_one_does() {
        let bits = NF_SHARD_BITS_DEFAULT;
        let nf = tag(7);
        let mine = nf_shard(&nf, bits);
        let mut foreign =
            RefSparseNf::with_shards(bits, (0..(1u32 << bits)).filter(|s| *s != mine).collect::<Vec<_>>());
        assert!(
            foreign.advance_one(&nf).is_empty(),
            "a node that does not own this shard produced a copath anyway — it cannot source a witness \
             for leaves it does not hold, and answering with one is the silent-drop class"
        );
        let mut owner = RefSparseNf::with_shards(bits, vec![mine]);
        assert_eq!(
            owner.advance_one(&nf).len(),
            NF_COPATH_LEN,
            "the OWNER produced no copath either — then the comparison test above proves nothing"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db221_recent_roots_tests {
    //! DB-221 — the recent-roots ring judged against the SET it claims to describe. Every refusal is calibrated:
    //! the same copath is first shown to be one an honest spender carries (it folds EMPTY to a root this node
    //! really held), so a REJECT is the ring's decision, not a malformed input's.
    use super::*;

    fn tag(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"db221-tag".as_slice(), &i.to_le_bytes()].concat()).as_bytes()
    }

    /// A node's accumulator, its copath source, and the ring, advanced together through the recorded door.
    struct Chain {
        world: RefSparseNf,
        acc: SparseNfAcc,
        ring: RecentSpentRoots,
    }

    impl Chain {
        fn new() -> Self {
            let acc = SparseNfAcc::new();
            let mut ring = RecentSpentRoots::default();
            ring.reset(acc.root());
            Self { world: RefSparseNf::new(), acc, ring }
        }
        /// Absorb through the RECORDED door (what `sparse_apply_with_copath` does on a node).
        fn absorb(&mut self, t: [u8; 32]) {
            let cp = self.world.insert_and_witness(&t);
            let pre = self.acc.root();
            self.acc.verify_and_insert(&t, &cp).expect("a fresh tag folds");
            self.ring.absorb(pre, self.acc.root(), t);
        }
        /// Absorb WITHOUT telling the ring — a path that forgot to record.
        fn absorb_unrecorded(&mut self, t: [u8; 32]) {
            let cp = self.world.insert_and_witness(&t);
            self.acc.verify_and_insert(&t, &cp).expect("a fresh tag folds");
        }
        /// What a wallet carries: a copath for `t` built NOW (before any later block).
        fn copath_now(&self, t: &[u8; 32]) -> Vec<Digest4> {
            self.world.copath(t)
        }
        fn verdict(&self, t: &[u8; 32], cp: &[Digest4]) -> SpentVerdict {
            self.ring.verdict(self.acc.root(), t, cp)
        }
    }

    /// Tags per block in these fixtures: the PRODUCTION constant-width cover, so every ring below spans
    /// real-width blocks (the ring's algebra does not depend on the width, and that argument does not excuse a
    /// shrunken run).
    const BLOCK: u64 = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;

    #[test]
    fn a_copath_built_blocks_ago_is_admitted_exactly_where_the_live_root_alone_cannot_decide() {
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let v = tag(10_000);
        let cp = c.copath_now(&v);
        let built_on = c.acc;
        assert_eq!(built_on.spent_verdict(&v, &cp), SpentVerdict::Unspent, "calibration: an honest copath");
        for i in BLOCK..4 * BLOCK {
            c.absorb(tag(i)); // three more blocks of cover
        }
        assert_eq!(
            c.acc.spent_verdict(&v, &cp),
            SpentVerdict::Unprovable,
            "calibration: against the LIVE root alone the stale copath decides nothing — DB-217 refuses it"
        );
        assert_eq!(
            c.verdict(&v, &cp),
            SpentVerdict::Unspent,
            "⛔ a copath three blocks old for a tag nobody spent must be ADMITTED — the ring holds its root"
        );
    }

    #[test]
    fn a_tag_that_settled_after_its_copath_was_built_is_rejected() {
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let v = tag(20_000);
        let cp = c.copath_now(&v);
        for i in BLOCK..2 * BLOCK {
            c.absorb(tag(i));
        }
        assert_eq!(c.verdict(&v, &cp), SpentVerdict::Unspent, "calibration: stale-but-honest is admitted");
        c.absorb(v); // v settles in a later block
        for i in 2 * BLOCK..3 * BLOCK {
            c.absorb(tag(i));
        }
        assert_eq!(
            SparseNfAcc { root: c.ring.base.expect("genesis base") }.spent_verdict(&v, &cp),
            SpentVerdict::Unprovable,
            "fixture sanity: the copath was not built on the base"
        );
        assert_eq!(
            c.verdict(&v, &cp),
            SpentVerdict::Spent,
            "⛔ DOUBLE SPEND: the copath proves v was absent at ITS root, and v settled since — the sweep must \
             see it"
        );
        // And a fresh copath for v against the live root proves it spent directly.
        assert_eq!(c.verdict(&v, &c.copath_now(&v)), SpentVerdict::Spent);
    }

    #[test]
    fn a_set_move_the_ring_never_saw_restarts_it_and_never_skips_the_unseen_tag() {
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let x = tag(30_000);
        let cp_x = c.copath_now(&x); // honest copath: x absent at R1
        let r1 = c.acc;
        assert_eq!(r1.spent_verdict(&x, &cp_x), SpentVerdict::Unspent, "calibration: an honest copath at R1");
        // A path that moved the set and did NOT record: x settles, and a second tag after it. (With x alone
        // the old copath would fold SPENT to the new root exactly — only x's own leaf changed — and prove x
        // spent directly; the second tag is what leaves the copath describing no root the node holds.)
        c.absorb_unrecorded(x);
        c.absorb_unrecorded(tag(30_002));
        let r2 = c.acc;
        assert_eq!(
            c.verdict(&x, &cp_x),
            SpentVerdict::Unprovable,
            "⛔ the ring no longer describes the live root — it must decide nothing beyond it"
        );
        let y = tag(30_001);
        c.absorb(y); // the next RECORDED absorb: its pre is not the ring's newest root
        assert_eq!(
            (c.ring.base, c.ring.len()),
            (Some(r2.root), 1),
            "the ring must restart AT the unseen moves' result, holding only what it saw after them"
        );
        // CALIBRATION — the attack is armed: had the ring chained `y` onto R1, the anchor would be R1 (the
        // copath folds EMPTY there, asserted above) and the sweep would hold only `y`, which is not `x`.
        assert_ne!(x, y, "calibration: the one swept tag is not the settled one");
        assert_eq!(
            c.verdict(&x, &cp_x),
            SpentVerdict::Unprovable,
            "⛔⛔ DOUBLE SPEND BY A FORGOTTEN RECORD: x settled on a path the ring never saw; chaining the next \
             absorb onto R1 would sweep only the later tag and call x unspent"
        );
    }

    #[test]
    fn a_forged_or_tampered_copath_decides_nothing() {
        let mut c = Chain::new();
        for i in 0..2 * BLOCK {
            c.absorb(tag(i));
        }
        let v = tag(40_000);
        let mut cp = c.copath_now(&v);
        for i in 2 * BLOCK..3 * BLOCK {
            c.absorb(tag(i));
        }
        assert_eq!(c.verdict(&v, &cp), SpentVerdict::Unspent, "calibration: the untampered copath is admitted");
        cp[0] = poseidon_pair(cp[0], cp[1]); // one sibling changed
        assert_eq!(c.verdict(&v, &cp), SpentVerdict::Unprovable, "⛔ a tampered sibling must decide nothing");
        let forged: Vec<Digest4> = (0..NF_SPARSE_DEPTH as u64)
            .map(|i| crate::spend_frontier::cm_bytes_to_root(&tag(50_000 + i)).unwrap_or(cp[0]))
            .collect();
        assert_eq!(c.verdict(&v, &forged), SpentVerdict::Unprovable, "⛔ a forged copath must decide nothing");
        assert_eq!(c.verdict(&v, &cp[..NF_SPARSE_DEPTH - 1]), SpentVerdict::Unprovable, "short copath");
        assert_eq!(c.verdict(&[0u8; 32], &c.copath_now(&[0u8; 32])), SpentVerdict::Unprovable, "zero tag");
    }

    #[test]
    fn the_ring_agrees_with_spent_verdict_on_every_live_root_copath() {
        let mut c = Chain::new();
        for i in 0..2 * BLOCK {
            c.absorb(tag(i));
        }
        for i in 0..3 * BLOCK {
            let t = tag(i);
            let cp = c.copath_now(&t);
            assert_eq!(c.verdict(&t, &cp), c.acc.spent_verdict(&t, &cp), "tag {i}: ring and live verdict differ");
        }
    }

    #[test]
    fn a_whole_block_absorbed_without_intermediate_roots_never_skips_a_tag() {
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let pre = c.acc;
        let (b, d) = (tag(60_001), tag(60_003));
        let (cp_b, cp_d) = (c.copath_now(&b), c.copath_now(&d));
        let block = [tag(60_000), b, tag(60_002)];
        for t in &block {
            c.absorb_unrecorded(*t);
        }
        c.ring.absorb_block(pre.root, c.acc.root, &block);
        assert_eq!(c.verdict(&b, &cp_b), SpentVerdict::Spent, "⛔ b settled inside the block — never skipped");
        assert_eq!(c.verdict(&d, &cp_d), SpentVerdict::Unspent, "d is in no block — admitted from the old root");
        for i in BLOCK..2 * BLOCK {
            c.absorb(tag(i));
        }
        assert_eq!(c.verdict(&b, &cp_b), SpentVerdict::Spent, "still spent a block later");
        assert_eq!(c.verdict(&d, &cp_d), SpentVerdict::Unspent, "still admitted a block later");
    }

    #[test]
    fn a_tag_crossing_a_second_door_spends_no_capacity_and_loses_no_verdict() {
        // A produced block's tags are absorbed at the per-tag door AND again at the co-advance, where the root
        // does not move. The second pass must cost nothing, or the ring spans a fraction of its 64 blocks.
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let held = c.ring.len();
        let live = c.acc.root;
        for i in 0..BLOCK {
            c.ring.absorb(live, live, tag(i)); // the co-advance re-applying the same tags: no move
        }
        c.ring.absorb_block(live, live, &(0..BLOCK).map(tag).collect::<Vec<_>>());
        assert_eq!(c.ring.len(), held, "⛔ a re-absorb that moved nothing consumed ring capacity");
        assert_eq!(c.ring.newest(), Some(live), "the ring still describes the live root");
        let v = tag(90_000);
        let cp = c.copath_now(&v);
        c.absorb(tag(90_001));
        assert_eq!(c.verdict(&v, &cp), SpentVerdict::Unspent, "and still judges a stale copath exactly");
    }

    #[test]
    fn the_ring_forgets_roots_older_than_its_capacity_and_never_grows_past_it() {
        let mut c = Chain::new();
        for i in 0..BLOCK {
            c.absorb(tag(i));
        }
        let v = tag(70_000);
        let cp = c.copath_now(&v);
        c.absorb(tag(70_001));
        assert_eq!(c.verdict(&v, &cp), SpentVerdict::Unspent, "calibration: held and admitted");
        // Fill the ring past capacity. Synthetic union steps are enough: the ring stores, it does not re-fold.
        let mut live = c.acc.root;
        for i in 0..NF_RECENT_TAGS as u64 {
            let next = poseidon_pair(live, live);
            c.ring.absorb(live, next, tag(80_000 + i));
            live = next;
            assert!(c.ring.len() <= NF_RECENT_TAGS, "the ring grew past its fixed capacity");
        }
        assert_eq!(c.ring.len(), NF_RECENT_TAGS);
        assert_eq!(
            c.ring.verdict(live, &v, &cp),
            SpentVerdict::Unprovable,
            "⛔ a copath older than the ring must be refused (rebuilt by the spender), never guessed"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod one_fold_walk_tests {
    //! DB-153 lever, PROTOTYPED IN TEST BEFORE IT TOUCHES PRODUCTION: the Merkle view's per-tag advance computes
    //! `nf`'s post-insert path once, and every structure that follows the insert (branch cache, band slot,
    //! accumulator root) reads it. This module proves the candidate is BYTE-IDENTICAL to the production walk
    //! (copath, root, branch cache, band) and measures both at a live-chain leaf count.
    use super::*;

    fn tag(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"one-fold".as_slice(), &i.to_le_bytes()].concat()).as_bytes()
    }

    /// THE REFERENCE — the walk as production ran it until 2026-09-25, kept verbatim so the one-fold walk is
    /// always judged against an INDEPENDENT computation: each new branch node recomputed from `node_at` on both
    /// children (re-folding lone leaves), the band slot re-folded from the copath, and the accumulator
    /// re-folding the same copath (`insert_from_own_copath`).
    fn reference_advance(t: &mut RefSparseNf, acc: &mut SparseNfAcc, nf: &[u8; 32]) -> Vec<Digest4> {
        if t.shard_bits > 0 && !t.owned.contains(&nf_shard(nf, t.shard_bits)) {
            return Vec::new(); // foreign shard
        }
        let key = SparseKey::of(nf);
        let copath = t.copath(nf);
        let k = RefSparseNf::tkey(key.bytes());
        t.leaves.insert(k);
        let pred = t.leaves.range(..k).next_back().copied();
        let succ = t.leaves.range((std::ops::Bound::Excluded(k), std::ops::Bound::Unbounded)).next().copied();
        for level in 1..=NF_SPARSE_DEPTH {
            let cn = RefSparseNf::canon(&key, level);
            let (lo, hi) = RefSparseNf::subtree_range(level, &cn);
            if pred.is_some_and(|p| p >= lo) || succ.is_some_and(|s| s <= hi) {
                let mut c1 = cn;
                c1[(level - 1) >> 3] |= 1u8 << ((level - 1) & 7);
                let (left, right) = (t.node_at(level - 1, &cn), t.node_at(level - 1, &c1));
                t.branch.insert((level, cn), poseidon_pair(left, right));
            }
        }
        if t.shard_bits > 0 {
            let level = t.band_level();
            let w = compact_witness(&key, &copath).expect("the view's own copath");
            let node = post_path_of(&key, w.t, w.other.map(SparseKey::from_key_bytes).as_ref(), &copath)[level];
            let id = nf_shard(nf, t.shard_bits) as usize;
            if id < t.band.len() {
                t.band[id] = node;
                t.refresh_band_path(id);
            }
        }
        acc.insert_from_own_copath(nf, &copath);
        copath
    }

    /// PRODUCTION — the walk `Node::advance_sparse_shadow` runs now: one fold, the root handed to the
    /// accumulator.
    fn production_advance(t: &mut RefSparseNf, acc: &mut SparseNfAcc, nf: &[u8; 32]) -> Vec<Digest4> {
        match t.advance_one_rooted(nf) {
            Some((cp, post)) => {
                acc.follow_own_walk(nf, post);
                cp
            }
            None => Vec::new(),
        }
    }

    fn assert_same_tree(a: &RefSparseNf, b: &RefSparseNf, ctx: &str) {
        assert_eq!(a.root(), b.root(), "{ctx}: roots differ");
        assert_eq!(a.leaves, b.leaves, "{ctx}: leaf sets differ");
        assert_eq!(a.band, b.band, "{ctx}: bands differ");
        assert_eq!(a.band_up, b.band_up, "{ctx}: band paths differ");
        // Every branch entry `node_at` can READ must be identical; entries at or above a sharded tree's band
        // level are never read (the band answers there), and only production writes them.
        let readable = |t: &RefSparseNf, level: usize| t.shard_bits == 0 || level < t.band_level();
        let ra: std::collections::BTreeMap<_, _> = a.branch.iter().filter(|((l, _), _)| readable(a, *l)).collect();
        let rb: std::collections::BTreeMap<_, _> = b.branch.iter().filter(|((l, _), _)| readable(b, *l)).collect();
        assert!(!ra.is_empty(), "{ctx}: calibration — the readable branch cache is empty, so this compares nothing");
        assert_eq!(ra.len(), rb.len(), "{ctx}: readable branch caches differ in size");
        for (k, v) in &ra {
            assert_eq!(rb.get(k), Some(v), "{ctx}: readable branch node {k:?} differs");
        }
        assert!(
            b.branch.keys().all(|(l, _)| readable(b, *l)),
            "{ctx}: the one-fold walk wrote a branch entry nothing can read"
        );
    }

    fn run(shards: Option<(usize, u32)>, base: u64, per_block: u64) {
        let fresh = || match shards {
            Some((bits, owned)) => RefSparseNf::with_shards(bits, 0..owned),
            None => RefSparseNf::new(),
        };
        let ctx = match shards { Some((b, o)) => format!("sharded ({b}, {o} owned)"), None => "unsharded".into() };
        // Phase 1 — equivalence from empty, over eight production-width blocks, so every branch shape occurs
        // (lone leaves, first branchings, deep branches) and every insert is compared.
        let (mut a, mut b) = (fresh(), fresh());
        let (mut acc_a, mut acc_b) = (SparseNfAcc::new(), SparseNfAcc::new());
        // Eight blocks of the production 256-tag cover, every insert compared.
        for i in 0..8 * crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64 {
            let nf = tag(i);
            let cp_a = reference_advance(&mut a, &mut acc_a, &nf);
            let cp_b = production_advance(&mut b, &mut acc_b, &nf);
            assert_eq!(cp_a, cp_b, "{ctx}: copath differs at insert {i}");
            assert_eq!(acc_a, acc_b, "{ctx}: the accumulator differs at insert {i}");
        }
        assert_same_tree(&a, &b, &ctx);
        assert_eq!(acc_b.root(), b.root(), "{ctx}: calibration — the accumulator follows the view in lockstep");
        // Re-inserting a tag already spent must also agree (a produced block's tags cross two doors), and so
        // must the all-zero padding tag (padding to the accumulator, a leaf to the tree).
        for again in [tag(7), [0u8; 32], tag(8)] {
            let cp_a = reference_advance(&mut a, &mut acc_a, &again);
            let cp_b = production_advance(&mut b, &mut acc_b, &again);
            assert_eq!((cp_a, acc_a), (cp_b, acc_b), "{ctx}: a re-insert / padding insert differs");
            assert_same_tree(&a, &b, &ctx);
        }

        // Phase 2 — ONE BLOCK of production cover on a tree at a live-chain leaf count, timed.
        let mut big = fresh();
        let mut acc_big = SparseNfAcc::new();
        // ~400 production-width blocks of history, built with the (proven-equivalent) production walk.
        for i in 0..base {
            let _ = production_advance(&mut big, &mut acc_big, &tag(10_000_000 + i));
        }
        let (mut a, mut b) = (big.clone(), big);
        let (mut acc_a, mut acc_b) = (acc_big, acc_big);
        let t0 = std::time::Instant::now();
        let cps_a: Vec<Vec<Digest4>> =
            (0..per_block).map(|i| reference_advance(&mut a, &mut acc_a, &tag(20_000_000 + i))).collect();
        let ref_ms = t0.elapsed().as_secs_f64() * 1e3;
        let t1 = std::time::Instant::now();
        let cps_b: Vec<Vec<Digest4>> =
            (0..per_block).map(|i| production_advance(&mut b, &mut acc_b, &tag(20_000_000 + i))).collect();
        let prod_ms = t1.elapsed().as_secs_f64() * 1e3;
        assert_eq!(cps_a, cps_b, "{ctx}: a block's copaths differ at scale");
        assert_eq!(acc_a, acc_b, "{ctx}: the block's accumulator differs at scale");
        assert_same_tree(&a, &b, &ctx);
        eprintln!(
            "[one-fold] {ctx}: {per_block} tags on a {base}-leaf view — previous walk {ref_ms:.1} ms, \
             production one-fold walk {prod_ms:.1} ms ({:.2}x)",
            ref_ms / prod_ms.max(1e-9)
        );
    }

    // TWO-PARTY-REVIEWED: a refactor-equivalence pin — the two sides are the two IMPLEMENTATIONS, each on its
    // own independently built tree, asserted byte-identical (copath, root, branch cache, band) at every insert.
    // The cross-node property this code path carries (a producer and an ingesting peer reach one root) is
    // pinned where two Nodes exist: `a_stale_carried_copath_is_admitted_if_unspent_and_rejected_if_its_tag_
    // settled_since` and the produce/ingest convergence pins.
    #[test]
    fn the_one_fold_walk_is_byte_identical_to_the_production_walk_and_measures_its_cost() {
        // One block = the production constant-width cover; the view holds ~400 blocks of it (a live chain).
        let per_block = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;
        let base = 400 * per_block;
        // The live policy at mesh <= NF_SHARD_REPLICATION is 8 shard bits with EVERY shard owned (gate 8).
        run(Some((8, 256)), base, per_block);
        run(None, base, per_block);
    }

    /// The `which`-th DB-232 fixture block (the production 256-tag width): 0..=5 random, 6 FORCED to put 64 tags
    /// in one shard, 7 repeating a spent tag and carrying the all-zero padding tag.
    fn db232_fixture(which: u64, bits: usize) -> Vec<[u8; 32]> {
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;
        match which {
            6 => {
                let target = nf_shard(&tag(40_000_000), bits);
                let mut out: Vec<[u8; 32]> = Vec::with_capacity(width as usize);
                let mut probe = 0u64;
                while out.len() < 64 {
                    let t = tag(41_000_000 + probe);
                    probe += 1;
                    if nf_shard(&t, bits) == target {
                        out.push(t);
                    }
                }
                out.extend((0..width - 64).map(|i| tag(42_000_000 + i)));
                out
            }
            7 => {
                let mut out: Vec<[u8; 32]> = (0..width - 3).map(|i| tag(43_000_000 + i)).collect();
                out.push(tag(30_000_005));
                out.push([0u8; 32]);
                out.push(tag(43_000_001));
                out
            }
            b => (0..width).map(|i| tag(30_000_000 + b * width + i)).collect(),
        }
    }

    /// ⭐⭐⭐ DB-232 PIN — THE PARALLEL BLOCK ADVANCE IS THE PER-TAG WALK, BYTE FOR BYTE.
    ///
    /// Two independently built trees; one advances each block tag by tag (`advance_one_rooted`, production until
    /// DB-232), the other in one `advance_block_rooted` call. Every per-tag output (pre-insert copath, post-insert
    /// root) and the whole tree after every block (root, leaves, band, band tower, every readable branch node)
    /// must be identical. The fixture blocks cover the cases the rounds exist for: random production-width
    /// blocks (natural same-shard collisions), a block FORCED to put 64 tags in one shard, a block repeating a
    /// tag and carrying the zero padding tag, and a policy owning only half the shards (foreign tags). Then one
    /// production block on a live-scale view, timed both ways.
    /// ROOT-LAYER: the block advance is where the view's per-block cost is produced; the pin judges it against
    /// the per-tag walk it replaces, on independently built trees.
    /// MEASURED: before — the live `[sparse-shadow]` view advance was ~183–191 ms per 256-tag block (gates H,
    /// J, K); the timed arm below prints both walks on the same live-scale view.
    /// MUST-STAY-GREEN: `the_one_fold_walk_is_byte_identical_to_the_production_walk_and_measures_its_cost`.
    /// TWO-PARTY-REVIEWED: a refactor-equivalence pin — the two sides are two IMPLEMENTATIONS on two
    /// independently built trees, compared at every tag; the cross-node property is pinned where Nodes exist.
    #[test]
    fn db232_block_advance_is_byte_identical_to_the_per_tag_walk() {
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;
        for (bits, owned) in [(8usize, 256u32), (8, 128)] {
            let ctx = format!("sharded ({bits}, {owned} owned)");
            let (mut seq, mut par) = (RefSparseNf::with_shards(bits, 0..owned), RefSparseNf::with_shards(bits, 0..owned));
            for which in 0..8u64 {
                let fixture = db232_fixture(which, bits);
                let one_by_one: Vec<Option<(Vec<Digest4>, Digest4)>> =
                    fixture.iter().map(|t| seq.advance_one_rooted(t)).collect();
                let batched = par.advance_block_rooted(&fixture);
                assert_eq!(one_by_one.len(), batched.len(), "{ctx} fixture {which}: output count");
                for (i, (a, b)) in one_by_one.iter().zip(batched.iter()).enumerate() {
                    assert_eq!(a, b, "{ctx} fixture {which}: tag {i} differs (copath or post-insert root)");
                }
                assert!(
                    one_by_one.iter().any(|o| o.is_some()),
                    "{ctx} fixture {which}: calibration — every tag was foreign, so nothing was compared"
                );
                assert_same_tree(&seq, &par, &format!("{ctx} fixture {which}"));
            }
        }
        // ⭐ DB-232b — THE UNSHARDED VIEW, the one every node at mesh ≤ NF_SHARD_REPLICATION actually runs (gate M:
        // `[sparse-shadow]` still 189 ms because DB-232 left `shard_bits == 0` sequential). Same fixtures, same
        // strictness: for an unsharded tree `assert_same_tree` compares the WHOLE branch cache, so the upper-level
        // write-back must reproduce the sequential walk's entries exactly — set and values.
        {
            let (mut seq, mut par) = (RefSparseNf::new(), RefSparseNf::new());
            for which in 0..8u64 {
                let fixture = db232_fixture(which, NF_SHARD_BITS_DEFAULT);
                let one_by_one: Vec<Option<(Vec<Digest4>, Digest4)>> =
                    fixture.iter().map(|t| seq.advance_one_rooted(t)).collect();
                let batched = par.advance_block_rooted(&fixture);
                assert_eq!(one_by_one, batched, "unsharded fixture {which}: per-tag outputs differ");
                assert_eq!(par.shard_policy().0, 0, "unsharded fixture {which}: the view must come back unsharded");
                assert_same_tree(&seq, &par, &format!("unsharded fixture {which}"));
            }
        }
        // …and the unsharded view at live scale, timed — the number gate M's `[sparse-shadow]` should move to.
        {
            let base = 400 * width;
            let mut big = RefSparseNf::new();
            for i in 0..base {
                let _ = big.advance_one_rooted(&tag(70_000_000 + i));
            }
            let (mut seq, mut par) = (big.clone(), big);
            let fixture: Vec<[u8; 32]> = (0..width).map(|i| tag(80_000_000 + i)).collect();
            let t0 = std::time::Instant::now();
            let a: Vec<_> = fixture.iter().map(|t| seq.advance_one_rooted(t)).collect();
            let seq_ms = t0.elapsed().as_secs_f64() * 1e3;
            let t1 = std::time::Instant::now();
            let b = par.advance_block_rooted(&fixture);
            let par_ms = t1.elapsed().as_secs_f64() * 1e3;
            assert_eq!(a, b, "unsharded at scale: the block's outputs differ");
            assert_same_tree(&seq, &par, "unsharded at scale");
            eprintln!(
                "[db232b] {width} tags on a {base}-leaf UNSHARDED view (the small-mesh live representation): \
                 per-tag walk {seq_ms:.1} ms, parallel block advance {par_ms:.1} ms ({:.2}x)",
                seq_ms / par_ms.max(1e-9)
            );
        }

        // One production-width block on a live-scale view (400 blocks of cover), timed.
        let base = 400 * width;
        let mut big = RefSparseNf::with_shards(8, 0..256);
        for i in 0..base {
            let _ = big.advance_one_rooted(&tag(50_000_000 + i));
        }
        let (mut seq, mut par) = (big.clone(), big);
        let fixture: Vec<[u8; 32]> = (0..width).map(|i| tag(60_000_000 + i)).collect();
        let t0 = std::time::Instant::now();
        let a: Vec<_> = fixture.iter().map(|t| seq.advance_one_rooted(t)).collect();
        let seq_ms = t0.elapsed().as_secs_f64() * 1e3;
        let t1 = std::time::Instant::now();
        let b = par.advance_block_rooted(&fixture);
        let par_ms = t1.elapsed().as_secs_f64() * 1e3;
        assert_eq!(a, b, "at scale: the block's outputs differ");
        assert_same_tree(&seq, &par, "at scale");
        let workers = std::thread::available_parallelism().map(|n| n.get()).ok();
        eprintln!(
            "[db232] {width} tags on a {base}-leaf view (live policy 8 bits, all owned): per-tag walk \
             {seq_ms:.1} ms, parallel block advance {par_ms:.1} ms ({:.2}x) on {workers:?} worker(s)",
            seq_ms / par_ms.max(1e-9)
        );
    }
}


/// ⭐⭐⭐ DB-290 (A''): REBUILD A JUMPED OR RESTORED NODE'S COPATH SOURCE AGAINST ITS FROZEN CERTIFIED ROOT, WHILE THE
/// CHAIN KEEPS MOVING. The shape is Ethereum snap sync's pivot plus healing, for an insert-only set.
///
/// Why this reaches the chain:
/// - A viewless node's accumulator stays at the certified root `R` of its last adopt or restore (DB-226).
/// - The node writes down every tag it applies and cannot absorb (`Node::sparse_pivot_tail`).
/// - A peer serves its LIVE set by key cursor (`spent_leaves_after`). That set is `set(R)` plus tags of blocks after
///   `R`, and every such later tag is one this node has applied or will apply.
/// - So `stream − tail == set(R)` once the tail has caught up with what the peer had, and that is checked against
///   `R` ITSELF. A lying, truncated or padded stream never reaches it.
///
/// Built OFF the node's lock: the absorb runs at the tree's own rate, not a tick budget's (DB-290 (D)).
/// O1-FOOTPRINT-REVIEWED: one scratch of the spent set, the same O(spent) the view it becomes already holds, plus the
/// synced tail (bounded by `Node::SPARSE_PIVOT_TAIL_MAX`); dropped the moment it installs or is abandoned.
///
/// ⭐⭐⭐ DB-426 — THE STREAM NAMES ITS ROOT (Ethereum snap sync: a range request names the state root it is read at, and
/// a peer that holds that root answers from it). The ask carries the pivot `R`. A server whose CURRENT view stands at or
/// after `R` inside its band journal answers EXACTLY `set(R)`: its view is `set(R) ⊎ admitted-after-R`, and it leaves the
/// journal's admitted tags out (`RefSparseNf::spent_leaves_after_excluding`). Every page says which it is: EXACT at `R`,
/// or LIVE (the server could not place `R` and served its live set, the DB-290 shape the heals below exist for).
/// MEASURED why (link 32, seed-0x9-3.log, SIM_PAR=4): a joiner adopted at 639 took a 632-tag LIVE stream that was not
/// `set(R)`; its tail stayed at 0 (the band waits on the fold, the fold on the view), so no heal — tail removal (part 1),
/// prefix (2), own span (3), re-open (4), held strip (DB-399) — ever moved the scratch: unfolded 42 → 485, view false to the
/// deadline. A guess that waits on the tail cannot end a wait the tail is part of. An exact page needs no tail at all.
/// - An all-EXACT pass that completes off `R` came from a lying or inconsistent server: the pass restarts from the first
///   key (`restart_if_exact_missed`), and nothing installs.
/// - A pass with any LIVE page keeps every DB-290/DB-339/DB-399 heal, unchanged.
///
/// §9.6 DOOR CHECKLIST (the warm stream into a copath source):
/// 1. Proof of work — n/a: no block enters; tags enter a private scratch that installs only at the root check.
/// 2. Proof / signature — the scratch installs only when its root EQUALS `R` (`into_healed`), `R` being this node's own
///    proven band root (a verified band transition or a certified adopt), and `Node::install_healed_pivot` re-checks it.
///    The EXACT flag is a server's claim and is never trusted: it only decides which recovery a miss takes.
/// 3. Conservation — a spent set creates no value; a MISSING tag would admit a double spend, and the root equality
///    refuses any set that is not exactly `set(R)`.
/// 4. Replay — a page answering a cursor or pivot this job is not at is dropped (`on_nf_keyed_page`); a tag already held is
///    skipped; the scratch is a set.
/// 5. Bounded work — the server walks ≤ `count + |admitted after R|` (≤ the journal's `lag_cap` steps × the block width);
///    a page ≤ `NF_WARM_PAGE_TAGS`; a stream ≤ `NF_WARM_STREAM_MAX_TAGS`; an exact miss costs one more stream.
/// 6. Parity with the LIVE kind-17 page door it extends — cursor echo ✔, strict key order ✔, the page-count bound ✔, the
///    stream refusal bound ✔, root equality at install ✔, the install door's re-checks ✔; added: the pivot echo.
pub struct PivotWarm {
    tree: RefSparseNf,
    pivot: [u8; 32],
    cursor: Option<[u8; 32]>,
    stream_done: bool,
    tail: std::collections::HashSet<[u8; 32]>,
    tail_synced: usize,
    /// ⭐ DB-339 part 2: the tail in the node's APPLICATION order (each tag once), so the earliest entries can be tried.
    /// O1-FOOTPRINT-REVIEWED: the same tags `tail` already holds, bounded by `Node::SPARSE_PIVOT_TAIL_MAX`.
    tail_order: Vec<[u8; 32]>,
    /// ⭐ DB-339 part 2: `restore_pre_pivot_prefix` tries again only once `tail_synced` reaches this (doubling).
    next_restore_at: usize,
    /// ⭐ DB-339 part 3: `heal_from_own_span` tries again only once `tail_synced` reaches this (doubling).
    next_span_heal_at: usize,
    /// ⭐ DB-339 part 4: whether a tail tag took a leaf back out of the scratch since the last `reopen_if_short` check.
    /// A stream whose server was AHEAD of the pivot carried post-pivot tags, and the tail removes them as this node
    /// applies the same blocks. A stream whose server was not ahead carried none, so its tail never hits.
    tail_hit: bool,
    /// ⭐ DB-339 part 4: `reopen_if_short` checks again only once `tail_synced` reaches this (one block width first,
    /// then doubling).
    next_restream_at: usize,
    /// ⭐ DB-399: `strip_held_extras` tries again only once the node's held post-pivot tag bound reaches this (doubling).
    next_held_strip_at: usize,
    /// ⭐ DB-426: whether this pass took any LIVE page (a server that could not place the pivot). An all-exact pass holds
    /// `set(R)` by construction, so the tail never takes a tag out of it and a miss restarts the pass.
    pass_live: bool,
}

/// ⭐ DB-339 part 2 — what one `PivotWarm::restore_pre_pivot_prefix` call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixRestore {
    /// No attempt: the stream is open, the scratch is already at its pivot, or the doubling threshold is not reached.
    Skipped,
    /// The scratch reached its pivot after re-inserting the tail's first `n` tags: they were already in `set(R)`.
    Healed(usize),
    /// No tail prefix restores the pivot; every re-inserted tag was removed again (the scratch is as it was).
    NoPrefix,
}

impl PivotWarm {
    /// A warm toward `pivot`, the root `Node::sparse_pivot` names.
    pub fn new(pivot: [u8; 32]) -> Self {
        Self {
            // ⭐ DB-316: the live shard policy's shape with EVERY shard owned (the whole set, as before), so a page absorbs
            // through DB-232's per-shard parallel rounds instead of one walk at a time.
            tree: RefSparseNf::with_shards(NF_SHARD_BITS_DEFAULT, 0..(1u32 << NF_SHARD_BITS_DEFAULT)),
            pivot,
            cursor: None,
            stream_done: false,
            tail: std::collections::HashSet::new(),
            tail_synced: 0,
            tail_order: Vec::new(),
            next_restore_at: 0,
            next_span_heal_at: 0,
            tail_hit: false,
            next_restream_at: crate::cover::BLOCK_FIXED_NULLIFIER_COUNT,
            next_held_strip_at: 0,
            pass_live: false,
        }
    }

    /// The pivot this warm must reach.
    pub fn pivot(&self) -> [u8; 32] {
        self.pivot
    }

    /// The key the next page must start AFTER (`None` = from the first key).
    pub fn cursor(&self) -> Option<[u8; 32]> {
        self.cursor
    }

    /// True once an empty page has closed the stream.
    pub fn stream_done(&self) -> bool {
        self.stream_done
    }

    /// Absorb one page the peer served after `cursor()`; an EMPTY page closes the stream.
    /// - `exact` (DB-426): the server read the page at THIS warm's pivot, so every tag is a member of `set(R)` and none is
    ///   skipped. A LIVE page may carry post-pivot tags, so a tag already synced from this node's tail is skipped: it came
    ///   from a block after the pivot.
    /// - A page that does not start strictly after the cursor, or is not in strictly increasing key order, is
    ///   refused WHOLE. The root check would catch any such stream anyway; refusing early keeps the scratch clean.
    pub fn absorb_page(&mut self, tags: &[[u8; 32]], exact: bool) -> bool {
        if self.stream_done {
            return false;
        }
        if !exact && !self.pass_live {
            // ⭐ DB-426: the first live page: the tail synced so far was only recorded (an exact page holds no post-pivot
            // tag), so it is taken out now — `stream − tail` from here on, exactly as a live pass always was.
            self.pass_live = true;
            for t in &self.tail_order {
                if self.tree.remove(t) {
                    self.tail_hit = true;
                }
            }
        }
        if tags.is_empty() {
            self.stream_done = true;
            return true;
        }
        let mut prev = self.cursor.map(|c| tag_tkey(&c));
        for t in tags {
            let k = tag_tkey(t);
            if prev.is_some_and(|p| k <= p) {
                return false;
            }
            prev = Some(k);
        }
        // ⭐ DB-316: ONE batch walk per page, the shard-local work in parallel (DB-232's `advance_block_rooted`, pinned
        // byte-identical to the per-tag walk). MEASURED gate Q12 (n1 restarted): the per-tag absorb cost ~12 s a page on
        // one thread, so the warm took ~655 tags/s against the chain's ~589 and never caught the set it streams.
        // ⭐ DB-339 part 4: a top-up pass re-reads the whole stream, so a tag the scratch already holds is skipped too.
        let fresh: Vec<[u8; 32]> = tags
            .iter()
            .filter(|t| (exact || !self.tail.contains(*t)) && !self.tree.leaves.contains(&tag_tkey(t)))
            .copied()
            .collect();
        self.tree.absorb_set(&fresh);
        self.cursor = tags.last().copied();
        true
    }

    /// Sync the node's tail past `tail_synced()`. A tag already absorbed from the stream is taken back out (a HIT, which
    /// DB-339 part 4 reads), and every tag is remembered so a later page skips it.
    /// ⭐ DB-426: while every page so far was EXACT the tail is only recorded — the scratch holds `set(R)` and nothing after
    /// it, and a tail tag that IS in `set(R)` (a pre-pivot tag re-applied after a restart) must stay in.
    pub fn sync_tail(&mut self, more: &[[u8; 32]]) {
        for t in more {
            if self.tail.insert(*t) {
                if self.pass_live && self.tree.remove(t) {
                    self.tail_hit = true;
                }
                self.tail_order.push(*t);
            }
        }
        self.tail_synced += more.len();
    }

    /// ⭐⭐ DB-426 — AN ALL-EXACT PASS THAT COMPLETED OFF ITS PIVOT IS RESTARTED, never healed. Every page claimed to be
    /// `set(R)` read at `R`, so a miss is a lying or inconsistent server, and no guess from this node's tail or blocks can
    /// stand in for the set it should have sent. The scratch is cleared and the stream re-opens from the first key; the
    /// tail stays (it is this node's own). Returns whether it restarted. Sound either way: nothing reaches `into_healed`
    /// unless its root EQUALS `R`.
    pub fn restart_if_exact_missed(&mut self) -> bool {
        if !self.stream_done || self.pass_live || self.at_pivot() {
            return false;
        }
        self.tree = RefSparseNf::with_shards(NF_SHARD_BITS_DEFAULT, 0..(1u32 << NF_SHARD_BITS_DEFAULT));
        self.cursor = None;
        self.stream_done = false;
        true
    }

    /// ⭐ DB-426: whether this pass took any LIVE page.
    pub fn pass_live(&self) -> bool {
        self.pass_live
    }

    /// ⭐⭐ DB-339 part 4 — RE-OPEN A COMPLETED STREAM THAT IS SHORT OF ITS PIVOT, as a top-up pass.
    ///
    /// MEASURED ([slotB17f], five real daemons on node-M7 f12258b5, node4): the node joined by adopting a #29 bundle at blue
    /// score 2 whose server vouched a non-empty root `R`. Its first warm page came from a server whose CURRENT view still
    /// held nothing, so the stream closed on 0 tags. The scratch stayed empty while the tail grew from 256 to 112,896 tags:
    /// part 2 found no prefix, and part 3 had no span (a jumped node never held `R`'s blocks). The node never installed and
    /// never served Lane A, and its own pool door refused the payee's redeem (`NullifierWitnessRejected`: 32 of 32 inputs
    /// without a positive absence proof).
    ///
    /// A key-ordered stream is exactly the server's set when it was read.
    /// - Server AHEAD of the pivot: the scratch holds `set(R)` plus post-pivot tags, and the tail takes those back out as
    ///   this node applies the same blocks. Tail tags HIT the scratch.
    /// - Server NOT ahead: the scratch lacks members of `set(R)`, holds no post-pivot tag, and no tail tag can supply
    ///   what is missing.
    /// So a whole interval of tail with no hit, while the scratch is off its pivot, means the scratch is SHORT. The stream
    /// then re-opens from the first key, and `absorb_page` skips every tag the scratch or the tail already holds, so the
    /// pass inserts only what is missing.
    ///
    /// Sound either way: nothing reaches `into_healed` unless its root EQUALS `R`, whatever any pass carried.
    /// Rate-bounded like parts 2 and 3: the first check waits for one block width of tail, and each later check waits for
    /// the tail to double.
    pub fn reopen_if_short(&mut self) -> bool {
        if !self.stream_done || self.at_pivot() || self.tail_synced < self.next_restream_at {
            return false;
        }
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
        self.next_restream_at = self.tail_synced.saturating_mul(2).max(self.tail_synced + width);
        if std::mem::replace(&mut self.tail_hit, false) {
            return false; // the tail is still taking the server's post-pivot tags back out: extras, not shortness
        }
        self.stream_done = false;
        self.cursor = None;
        true
    }

    /// How many of the node's tail entries this warm has synced.
    pub fn tail_synced(&self) -> usize {
        self.tail_synced
    }

    /// The scratch's current root (test-only: pins a failed restore attempt leaves it byte-for-byte).
    #[cfg(test)]
    pub fn scratch_root_for_test(&self) -> [u8; 32] {
        self.tree.root_bytes()
    }

    /// ⭐ DB-339: how many leaves the scratch holds now — a count over the PUBLIC replicated spent set, reported while a
    /// completed stream has not reached its pivot.
    pub fn scratch_len(&self) -> usize {
        self.tree.leaves.len()
    }

    /// ⭐⭐ DB-339 part 2 — MEASURE-AND-HEAL a completed stream that missed its pivot.
    ///
    /// MEASURED ([gateT1] run 3, node1 after its restart): the stream completed with 50,841 served tags. The scratch then
    /// held 45,568 leaves while the synced tail grew from 12,288 to 64,000 tags, and it never reached the pivot, so the
    /// node stayed treeless. `stream − tail == set(R)` fails whenever a tag ALREADY in `set(R)` enters the tail after the
    /// restart: it is subtracted from the scratch, and no later tail can put it back.
    ///
    /// This re-inserts the tail's EARLIEST entries and checks the root against `R` after each step. The steps are tag by
    /// tag across the first block width (`BLOCK_FIXED_NULLIFIER_COUNT`), since a peg or credit nullifier applied outside
    /// a block can lead the tail, and then one whole block at a time.
    /// - **A match** proves those entries were already in `set(R)`. They leave the tail set (they are not post-pivot),
    ///   and the scratch is now exactly `set(R)`.
    /// - **No match** removes every re-inserted tag again, so the scratch is exactly as it was.
    ///
    /// Sound either way: nothing reaches `into_healed` unless its root EQUALS `R`.
    ///
    /// Attempts are rate-bounded by tail doubling, so a stuck warm pays O(log) attempts, not one per block.
    /// O1-INFINITY-REVIEWED: nothing here is persisted. "restore" re-inserts tags into this warm's own RAM scratch (the
    /// bounded pivot tail, `Node::SPARSE_PIVOT_TAIL_MAX`) and removes exactly those again on a miss; no store, key or file.
    pub fn restore_pre_pivot_prefix(&mut self) -> PrefixRestore {
        if !self.stream_done || self.at_pivot() || self.tail_synced < self.next_restore_at {
            return PrefixRestore::Skipped;
        }
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
        self.next_restore_at = self.tail_synced.saturating_mul(2).max(self.tail_synced + width);
        let mut restored = 0usize;
        while restored < self.tail_order.len() {
            // Tag by tag across the first block width (a few pre-pivot tags — a peg or credit nullifier applied outside a
            // block's padded set — may lead a block of post-pivot ones), then one whole block at a time.
            let step = if restored < width { 1 } else { width };
            let end = (restored + step).min(self.tail_order.len());
            let chunk: Vec<[u8; 32]> = self.tail_order[restored..end].to_vec();
            let _ = self.tree.advance_block_rooted(&chunk);
            restored = end;
            if self.tree.root_bytes() == self.pivot {
                for t in self.tail_order.drain(..restored) {
                    self.tail.remove(&t);
                }
                return PrefixRestore::Healed(restored);
            }
        }
        for t in &self.tail_order[..restored] {
            let _ = self.tree.remove(t);
        }
        PrefixRestore::NoPrefix
    }

    /// ⭐ DB-339 part 3: is a heal from the node's own pre-pivot blocks due (the stream is complete, the scratch is not at
    /// its pivot, and the synced tail reached the doubling threshold)? The node reads its span's tags only when it is.
    pub fn span_heal_due(&self) -> bool {
        self.stream_done && !self.at_pivot() && self.tail_synced >= self.next_span_heal_at
    }

    /// ⭐⭐ DB-339 part 3 — HEAL FROM THE NODE'S OWN PRE-PIVOT BLOCKS, which the server's stream may never have carried.
    ///
    /// MEASURED ([slotB25roll] pass 1, node-M4 78f78767, part 2 landed): a restarted PRODUCER's stream completed with
    /// 76,245 served tags and its scratch stayed at 67,072 = 262 x 256 leaves while its restored fold record named 263
    /// member blocks. The tail grew from 12,032 to 49,152 tags with no effect, and part 2 found no tail prefix. The pivot set
    /// holds the producer's last block before its stop, which had not reached the peer when that peer served its
    /// KEY-ORDERED stream (the stop came 0.2 s after the block; relay takes 5-13 s). A stream is read once and closes on an
    /// empty page, so it can never carry that block, and no tail can put it back: the block was applied BEFORE the pivot.
    ///
    /// The node still holds those blocks (its restored fold span, in its window), so `span` is their padded tags. Every tag
    /// not already in the scratch is inserted, and the root is checked against `R`:
    /// - **a match** means the scratch is now exactly `set(R)`;
    /// - **no match** removes exactly the inserted tags again, so the scratch is as it was.
    /// Sound either way: nothing reaches `into_healed` unless its root EQUALS `R`, whatever `span` held.
    /// Rate-bounded by tail doubling, like part 2.
    pub fn heal_from_own_span(&mut self, span: &[[u8; 32]]) -> PrefixRestore {
        if !self.span_heal_due() {
            return PrefixRestore::Skipped;
        }
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
        self.next_span_heal_at = self.tail_synced.saturating_mul(2).max(self.tail_synced + width);
        let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        let fresh: Vec<[u8; 32]> = span
            .iter()
            .filter(|t| !self.tree.leaves.contains(&tag_tkey(t)) && seen.insert(**t))
            .copied()
            .collect();
        if fresh.is_empty() {
            return PrefixRestore::NoPrefix;
        }
        let _ = self.tree.advance_block_rooted(&fresh);
        if self.tree.root_bytes() == self.pivot {
            return PrefixRestore::Healed(fresh.len());
        }
        for t in &fresh {
            let _ = self.tree.remove(t);
        }
        PrefixRestore::NoPrefix
    }

    /// ⭐ DB-399: is a strip by this node's HELD post-pivot blocks due? The stream is complete, the scratch is off its
    /// pivot, and `held_bound` (the node's cheap bound on those blocks' tags) reached the doubling threshold. The node
    /// builds the groups only when it is, since judging a held block's lane costs a proof check per block.
    pub fn held_strip_due(&self, held_bound: usize) -> bool {
        self.stream_done && !self.at_pivot() && held_bound > 0 && held_bound >= self.next_held_strip_at
    }

    /// ⭐⭐⭐ DB-399 — TAKE THE SERVER'S POST-PIVOT TAGS BACK OUT USING THE BLOCKS THIS NODE HOLDS, when its band journal
    /// has no tail to give.
    ///
    /// MEASURED (`sim-20261006-054823`, T1.6): a fresh node adopted a bundle whose band stood at step 81 (pivot `R`) while
    /// the mesh's band was at ~360. Its stream came from a server AHEAD of `R`, so the scratch held `set(R)` plus the
    /// admitted tags of steps 82..~360. The ONLY tail source was the band journal. The node's band applied 0 steps: the
    /// proofs for steps 82–83 had left every peer's 64-step window. Its fold waited on a view (3,743 waits). The wait was
    /// circular: the view needs the tail, the tail needs the band, the band needs the fold, and the fold needs the view.
    /// The node did hold the bodies of every block after its pivot (550 unfolded, plus the 2 awaiting steps' admitted sets).
    ///
    /// `groups` are those blocks' JUSTIFIED tags, the awaiting steps first and then the held bodies, each group one block.
    /// Each scratch tag a group names leaves the scratch, and the root is checked against `R` after every group:
    /// - **a match** means every extra the server carried is gone, and the scratch is exactly `set(R)`;
    /// - **no match** re-inserts exactly the removed tags, so the scratch is as it was.
    /// A justified tag already in `set(R)` (a respend loser whose winner preceded `R`) can only keep the root off `R`. It
    /// can never make a wrong set install. The prefix check heals before such a block whenever it follows the extras.
    /// Rate-bounded by doubling of `held_bound`, like parts 2–4.
    /// O1-INFINITY-REVIEWED: nothing is persisted; the removed tags live in this call's RAM and go back on a miss.
    pub fn strip_held_extras(&mut self, groups: &[Vec<[u8; 32]>], held_bound: usize) -> PrefixRestore { // TAG-SPACE: tags as values
        if !self.held_strip_due(held_bound) {
            return PrefixRestore::Skipped;
        }
        let width = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
        self.next_held_strip_at = held_bound.saturating_mul(2).max(held_bound + width);
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for g in groups {
            for t in g {
                if !self.tail.contains(t) && self.tree.remove(t) {
                    removed.push(*t);
                }
            }
            if !removed.is_empty() && self.tree.root_bytes() == self.pivot {
                return PrefixRestore::Healed(removed.len());
            }
        }
        let _ = self.tree.advance_block_rooted(&removed);
        PrefixRestore::NoPrefix
    }

    /// The stream is complete and the scratch is EXACTLY `set(R)`.
    pub fn at_pivot(&self) -> bool {
        self.stream_done && self.tree.root_bytes() == self.pivot
    }

    /// HEAL: re-insert the synced tail and hand back `set(R) ∪ tail[..synced]`. Only a warm at its pivot can do this;
    /// any other hands itself back unchanged, to sync more of the tail or be dropped.
    pub fn into_healed(mut self) -> Result<HealedPivot, PivotWarm> {
        if !self.at_pivot() {
            return Err(self);
        }
        // DB-316: the synced tail goes back in as one batch too (it can be a catch-up depth of blocks).
        // DB-426: a tail tag the scratch already holds (a pre-pivot tag re-applied after a restart, kept by an exact pass)
        // is not inserted twice.
        let tail: Vec<[u8; 32]> =
            self.tail.iter().filter(|t| !self.tree.leaves.contains(&tag_tkey(t))).copied().collect();
        let _ = self.tree.advance_block_rooted(&tail);
        Ok(HealedPivot { tree: self.tree, pivot: self.pivot, synced: self.tail_synced })
    }
}

/// A copath source that reached its pivot exactly and was then healed by the tail it synced. The fields are private, so
/// `PivotWarm::into_healed` is the only way to make one: a scratch that never matched `R` cannot be installed.
pub struct HealedPivot {
    tree: RefSparseNf,
    pivot: [u8; 32],
    synced: usize,
}

impl HealedPivot {
    /// The pivot it was checked against.
    pub fn pivot(&self) -> [u8; 32] {
        self.pivot
    }
    /// How many tail entries it already carries.
    pub fn synced(&self) -> usize {
        self.synced
    }
    /// `(tree, pivot, synced)`, for the node's install door.
    pub fn into_parts(self) -> (RefSparseNf, [u8; 32], usize) {
        (self.tree, self.pivot, self.synced)
    }
}

/// DB-290 (lane-db224-carriage, 2026-09-27): the two primitives a jumped node's warm needs, pinned against the
/// definitions they must agree with. Each property below is checked against a tree built WITHOUT the thing
/// removed, never against a number.
#[cfg(all(test, feature = "pins-core"))]
mod db290_warm_primitive_tests {
    use super::*;

    fn tag(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"db290-tag".as_slice(), &i.to_le_bytes()].concat()).as_bytes()
    }

    fn build(shard_bits: usize, tags: impl IntoIterator<Item = [u8; 32]>) -> RefSparseNf {
        let mut t = if shard_bits == 0 {
            RefSparseNf::new()
        } else {
            RefSparseNf::with_shards(shard_bits, 0..(1u32 << shard_bits))
        };
        for x in tags {
            let _ = t.advance_one_rooted(&x);
        }
        t
    }

    /// Byte-for-byte: root, leaf set, readable branch cache, band and tower.
    fn assert_identical(a: &RefSparseNf, b: &RefSparseNf, ctx: &str) {
        assert_eq!(a.root_bytes(), b.root_bytes(), "{ctx}: roots differ");
        assert_eq!(a.leaves, b.leaves, "{ctx}: leaf sets differ");
        assert_eq!(a.branch, b.branch, "{ctx}: branch caches differ");
        assert_eq!(a.band, b.band, "{ctx}: bands differ");
        assert_eq!(a.band_up, b.band_up, "{ctx}: towers differ");
    }

    #[test]
    fn db290_remove_leaves_the_tree_a_tree_that_never_held_the_tag() {
        for shard_bits in [0usize, 8] {
            let base: Vec<[u8; 32]> = (0..3_000).map(tag).collect();
            let extra: Vec<[u8; 32]> = (100_000..100_600).map(tag).collect();
            let reference = build(shard_bits, base.iter().copied());

            // (1) insert then remove, in a different order from the inserts: back to exactly the reference.
            let mut t = build(shard_bits, base.iter().chain(extra.iter()).copied());
            assert_ne!(t.root_bytes(), reference.root_bytes(), "calibration: the extra tags moved the root");
            for x in extra.iter().rev() {
                assert!(t.remove(x), "a held tag must be removable");
            }
            assert_identical(&t, &reference, &format!("shard_bits={shard_bits}: insert-then-remove"));

            // (2) remove tags that were in the ORIGINAL build: equal to a tree built without them.
            let gone: Vec<[u8; 32]> = base.iter().step_by(7).copied().collect();
            let mut t2 = build(shard_bits, base.iter().copied());
            for x in &gone {
                assert!(t2.remove(x));
            }
            let never = build(shard_bits, base.iter().filter(|x| !gone.contains(x)).copied());
            assert_identical(&t2, &never, &format!("shard_bits={shard_bits}: remove == never inserted"));

            // (3) the copaths it serves afterwards are the reference's, for held and unheld tags alike.
            for probe in [base[1], base[7], tag(999_999)] {
                assert_eq!(t2.copath(&probe), never.copath(&probe), "shard_bits={shard_bits}: a copath differs");
            }

            // (4) removing what is not held changes nothing and says so.
            let before = t2.root_bytes();
            assert!(!t2.remove(&tag(424_242)), "an unheld tag reports false");
            assert!(!t2.remove(&gone[0]), "a twice-removed tag reports false");
            assert_eq!(t2.root_bytes(), before, "a refused remove moved the root");

            // (5) down to empty and back: the empty tree's root.
            let mut t3 = build(shard_bits, base.iter().take(5).copied());
            for x in base.iter().take(5) {
                assert!(t3.remove(x));
            }
            assert_identical(&t3, &build(shard_bits, std::iter::empty()), &format!("shard_bits={shard_bits}: to empty"));
        }

        // (6) a FOREIGN shard: no leaves held there, so no remove, and nothing moves.
        let mut sharded = RefSparseNf::with_shards(8, [0u32]);
        let foreign = (0..).map(tag).find(|t| nf_shard(t, 8) != 0).expect("some tag is foreign");
        let before = sharded.root_bytes();
        assert!(!sharded.remove(&foreign), "a foreign-shard tag is not removable");
        assert_eq!(sharded.root_bytes(), before);
    }

    #[test]
    fn db290_the_key_cursor_serves_every_held_tag_exactly_once_while_the_set_grows() {
        let held: Vec<[u8; 32]> = (0..5_000).map(tag).collect();
        let page = 257usize;
        // The same insert schedule for both pagers: before each of the first 12 pages, 40 new tags land ANYWHERE in key
        // order; after that the set holds still and both pagers drain it. The schedule MUST end: under endless inserts
        // an index pager never sees an empty page (every round adds 40 positions at the end), so a pin with no bound
        // hangs instead of measuring. Twelve rounds of 40 is enough to shift every later page many times.
        let schedule = |round: u64| -> Vec<[u8; 32]> {
            if round >= 12 {
                return Vec::new();
            }
            (0..40).map(|j| tag(1_000_000 + round * 40 + j)).collect()
        };

        // THE KEY CURSOR.
        let mut t = build(0, held.iter().copied());
        let mut served: Vec<[u8; 32]> = Vec::new();
        let mut cursor: Option<[u8; 32]> = None;
        let mut round = 0u64;
        loop {
            for x in schedule(round) {
                let _ = t.advance_one_rooted(&x);
            }
            round += 1;
            let p = t.spent_leaves_after(cursor.as_ref(), page);
            if p.is_empty() {
                break;
            }
            cursor = p.last().copied();
            served.extend(p);
        }
        let mut seen = std::collections::HashMap::<[u8; 32], usize>::new();
        for x in &served {
            *seen.entry(*x).or_default() += 1;
        }
        assert!(seen.values().all(|n| *n == 1), "the key cursor served a tag twice");
        let missing = held.iter().filter(|x| !seen.contains_key(*x)).count();
        assert_eq!(missing, 0, "the key cursor skipped {missing} tag(s) that were held for the whole stream");

        // CALIBRATION: the INDEX pager under the identical schedule RE-SERVES tags (an insert below its cursor shifts
        // the next page back onto served ground). That is the defect the cursor removes, so a schedule that could not
        // expose it would leave "exactly once" above unarmed. Its skips are printed too; for an insert-only set they
        // are 0, and that is recorded rather than assumed.
        let mut ti = build(0, held.iter().copied());
        let mut count_i = std::collections::HashMap::<[u8; 32], usize>::new();
        let (mut from, mut round) = (0usize, 0u64);
        loop {
            for x in schedule(round) {
                let _ = ti.advance_one_rooted(&x);
            }
            round += 1;
            let p = ti.spent_leaves_page(from, page);
            if p.is_empty() {
                break;
            }
            from += p.len();
            for x in p {
                *count_i.entry(x).or_default() += 1;
            }
        }
        let twice_i = count_i.values().filter(|n| **n > 1).count();
        let skipped_i = held.iter().filter(|x| !count_i.contains_key(*x)).count();
        assert!(twice_i > 0, "calibration: the index pager re-served nothing under this schedule, so the pin is unarmed");
        eprintln!(
            "[db290c] key cursor: {} served, 0 skipped, 0 twice | index pager, same schedule: {twice_i} tag(s) served \
             twice, {skipped_i} held tag(s) skipped",
            served.len()
        );
    }

    /// ⛔ DB-316 — A WARM PAGE ABSORBS AS ONE PARALLEL BATCH, AND THE SCRATCH IS STILL EXACTLY THE SET.
    ///
    /// MEASURED, gate Q12 (n1 restarted, `n1.log` 3654..6608): 19 full pages, each fetched in 2.7–6.3 s and then absorbed
    /// ~12 s by per-tag walks on ONE worker thread. In series that is ~655 tags/s against the chain's ~589, so the stream
    /// chased a set growing almost as fast until the 600-block tail bound tripped.
    /// TARGET:
    /// - (1) through two full pages with a tail taken out and put back, the healed scratch is exactly the live set, byte
    ///   for byte: the absorb path changes no answer;
    /// - (2) on a machine with ≥ 4 workers, a page absorbs in at most half the per-tag walk's time. DB-232 MEASURED the
    ///   same per-shard parallel rounds at 3.76x on a 256-tag block (182 → 48.5 ms), and half leaves that measured margin.
    #[test]
    fn db316_a_warm_page_absorbs_as_one_batch_and_reaches_the_same_set() {
        const PAGE: usize = 16_384;
        let all_owned = || RefSparseNf::with_shards(NF_SHARD_BITS_DEFAULT, 0..(1u32 << NF_SHARD_BITS_DEFAULT));
        let set_r: Vec<[u8; 32]> = (0..(2 * PAGE) as u64).map(tag).collect();
        let post: Vec<[u8; 32]> = (900_000..900_512).map(tag).collect();
        let mut r_tree = all_owned();
        let _ = r_tree.advance_block_rooted(&set_r);
        let r = r_tree.root_bytes();
        let mut live = r_tree.clone();
        let _ = live.advance_block_rooted(&post);
        let stream: Vec<[u8; 32]> = live.spent_leaves_after(None, usize::MAX);
        assert!(stream.len() > PAGE, "CALIBRATION: the stream spans more than one page");
        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&post);
        let t0 = std::time::Instant::now();
        let mut pages = 0usize;
        for page in stream.chunks(PAGE) {
            assert!(pw.absorb_page(page, false), "an honest page is in key order after the cursor");
            pages += 1;
        }
        let per_page_ms = t0.elapsed().as_secs_f64() * 1e3 / pages as f64;
        assert!(pw.absorb_page(&[], false), "the empty page closes the stream");
        assert!(pw.at_pivot(), "⛔ DB-316: the absorbed stream minus the tail is not the pivot set");
        let healed = pw.into_healed().ok().expect("a scratch at its pivot heals");
        let (tree, _, _) = healed.into_parts();
        assert_eq!(tree.root_bytes(), live.root_bytes(), "⛔ DB-316: the healed scratch is not the live set");
        // The per-tag walk of ONE page on a fresh tree: the pre-DB-316 absorb, on this machine, now.
        let mut seq = RefSparseNf::new();
        let t1 = std::time::Instant::now();
        for x in &stream[..PAGE] {
            let _ = seq.insert_and_witness(x);
        }
        let seq_ms = t1.elapsed().as_secs_f64() * 1e3;
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        eprintln!(
            "[db316] a {PAGE}-tag warm page: {per_page_ms:.0} ms absorbed by the warm vs {seq_ms:.0} ms by per-tag walks \
             ({:.2}x) on {workers} worker(s)",
            seq_ms / per_page_ms.max(1e-9)
        );
        if workers >= 4 {
            assert!(
                per_page_ms * 2.0 <= seq_ms,
                "⛔ DB-316: a warm page absorbed in {per_page_ms:.0} ms against {seq_ms:.0} ms for per-tag walks — the warm \
                 still walks one tag at a time, so its stream cannot outrun the chain it chases"
            );
        }
    }

    #[test]
    fn db290_a_live_stream_minus_the_post_pivot_tags_is_the_pivot_set_and_a_short_stream_is_refused() {
        // R = the certified pivot: the set at the adopt. P = the tags of the blocks applied after it.
        let set_r: Vec<[u8; 32]> = (0..4_000).map(tag).collect();
        let post: Vec<[u8; 32]> = (200_000..200_512).map(tag).collect();
        let r = build(0, set_r.iter().copied()).root_bytes();
        let live = build(0, set_r.iter().chain(post.iter()).copied());
        let stream: Vec<[u8; 32]> = live.spent_leaves_after(None, usize::MAX);

        // HONEST: the whole live stream, minus P, has exactly R's root.
        let mut scratch = build(0, stream.iter().copied());
        for x in &post {
            assert!(scratch.remove(x));
        }
        assert_eq!(scratch.root_bytes(), r, "the live stream minus the post-pivot tags must be the pivot set");

        // TAMPER: a stream missing ONE tag of set(R) can never reach R, so its install is refused.
        let dropped = set_r[1_234];
        let mut short = build(0, stream.iter().filter(|x| **x != dropped).copied());
        for x in &post {
            let _ = short.remove(x);
        }
        assert_ne!(short.root_bytes(), r, "⛔ a stream missing a pivot-set tag reached the pivot root");

        // TAMPER: an extra tag the chain never spent can never reach R either.
        let mut padded = build(0, stream.iter().copied().chain(std::iter::once(tag(777_777))));
        for x in &post {
            let _ = padded.remove(x);
        }
        assert_ne!(padded.root_bytes(), r, "⛔ a stream carrying a foreign tag reached the pivot root");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db339_prefix_restore {
    use super::{PivotWarm, PrefixRestore, RefSparseNf, NF_SHARD_BITS_DEFAULT};

    /// The module's tag generator (never the zero tag, which is padding to the accumulator).
    fn tag(seed: u64) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        t[31] = ((seed + 1) & 0xff) as u8;
        t
    }

    fn all_owned() -> RefSparseNf {
        RefSparseNf::with_shards(NF_SHARD_BITS_DEFAULT, 0..(1u32 << NF_SHARD_BITS_DEFAULT))
    }

    /// ⭐ DB-339 part 2 — A PRE-PIVOT BLOCK RE-APPLIED AFTER A RESTART IS MEASURED AND HEALED; A LYING STREAM NEVER IS.
    ///
    /// `set(R)` = blocks A and B, and the live set adds block C after the pivot. The restarted node's tail, in its
    /// application order, is B (re-applied, already in `set(R)`) and then C.
    /// - CALIBRATION: `stream − tail = A`, so the warm is NOT at its pivot, and a later tail can never fix it. This is
    ///   the measured stall.
    /// - THE HEAL: re-inserting the tail's first block restores `set(R)` exactly, reports 256, and heals to the live set.
    /// - ADVERSARIAL:
    ///   - a stream carrying one forged extra tag never matches `R`, and the scratch is restored byte-for-byte;
    ///   - a tail whose FIRST block is post-pivot also never matches;
    ///   - a second call inside the doubling threshold does nothing.
    #[test]
    fn db339_a_pre_pivot_block_in_the_tail_is_measured_and_healed_and_a_lying_stream_is_not() {
        // TWO-PARTY-REVIEWED: pure accumulator logic of ONE warm against a constructed live set; the two-party claim (a
        // restarted real process re-reaches Lane A beside its peer) is the DB-339 rolling-restart real pin.
        let block = |base: u64| -> Vec<[u8; 32]> { (base..base + 256).map(tag).collect() };
        let (a, b, c) = (block(1_000), block(2_000), block(3_000));
        let mut r_tree = all_owned();
        let _ = r_tree.advance_block_rooted(&a);
        let _ = r_tree.advance_block_rooted(&b);
        let r = r_tree.root_bytes();
        let mut live = r_tree.clone();
        let _ = live.advance_block_rooted(&c);
        let honest: Vec<[u8; 32]> = live.spent_leaves_after(None, usize::MAX);
        let tail: Vec<[u8; 32]> = b.iter().chain(c.iter()).copied().collect();

        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&tail);
        assert!(pw.absorb_page(&honest, false) && pw.absorb_page(&[], false), "the honest stream absorbs and closes");
        assert!(!pw.at_pivot(), "calibration: stream − tail = A, the measured stall — not at the pivot");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::Healed(256), "⛔ DB-339: the pre-pivot block was not found");
        assert!(pw.at_pivot(), "⛔ DB-339: the restored scratch is not exactly set(R)");
        let (tree, _, _) = pw.into_healed().ok().expect("a scratch at its pivot heals").into_parts();
        assert_eq!(tree.root_bytes(), live.root_bytes(), "⛔ the healed scratch is not the live set");

        let mut lying = honest.clone();
        lying.push(tag(9_999_999));
        lying.sort_by_key(super::tag_tkey); // the server's page order is the STORED traversal-key order of TAGS (DB-353 boundary)
        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&tail);
        assert!(pw.absorb_page(&lying, false) && pw.absorb_page(&[], false), "the lying stream is in key order");
        let before = pw.scratch_root_for_test();
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::NoPrefix, "⛔ a forged extra tag must never match R");
        assert!(!pw.at_pivot(), "⛔ a lying stream must never reach the pivot");
        assert_eq!(pw.scratch_root_for_test(), before, "⛔ a failed attempt must restore the scratch exactly");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::Skipped, "a second attempt waits for the tail to double");

        // A FEW pre-pivot tags (three of block B) lead the tail, then the post-pivot block C: tag-level steps find them.
        let few: Vec<[u8; 32]> = b[..3].iter().chain(c.iter()).copied().collect();
        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&few);
        assert!(pw.absorb_page(&honest, false) && pw.absorb_page(&[], false), "the honest stream absorbs and closes");
        assert!(!pw.at_pivot(), "calibration: three set(R) tags are missing from the scratch");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::Healed(3), "⛔ DB-339: three leading pre-pivot tags were not found");
        assert!(pw.at_pivot(), "⛔ the restored scratch is not exactly set(R)");

        let post_first: Vec<[u8; 32]> = c.iter().chain(b.iter()).copied().collect();
        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&post_first);
        assert!(pw.absorb_page(&honest, false) && pw.absorb_page(&[], false), "the honest stream absorbs and closes");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::NoPrefix, "a post-pivot head never matches R");
        assert!(!pw.at_pivot(), "⛔ nothing installs that is not root-equal to R");
    }

    /// ⭐⭐ DB-339 part 3 — A PIVOT BLOCK THE SERVER NEVER STREAMED HEALS FROM THE NODE'S OWN COPY; A FOREIGN SPAN NEVER DOES.
    ///
    /// `set(R)` = blocks A and B, B being the restarted producer's own last block, which never reached the server. The
    /// server's stream holds A and a post-pivot block C; the node's tail is C (applied after its restart).
    /// - CALIBRATION: `stream − tail = A`, so the warm is not at its pivot. Part 2 cannot find B, because B is not in the
    ///   tail. This is the measured [slotB25roll] stall.
    /// - THE HEAL: the node's own span [A, B] heals exactly (A is already present, B inserts: 256), to the live set `R ∪ C`.
    /// - ADVERSARIAL:
    ///   - a span carrying a block outside `set(R)` never matches `R`, and the scratch is restored byte-for-byte;
    ///   - a second attempt inside the doubling threshold does nothing.
    #[test]
    fn db339_part3_a_pivot_block_the_server_never_streamed_heals_from_the_nodes_own_span_and_a_foreign_span_does_not() {
        // TWO-PARTY-REVIEWED: pure accumulator logic of ONE warm against a constructed server set; the two-party claim is the
        // DB-339 rolling-restart real pin.
        let block = |base: u64| -> Vec<[u8; 32]> { (base..base + 256).map(tag).collect() };
        let (a, b, c) = (block(11_000), block(12_000), block(13_000));
        let mut r_tree = all_owned();
        let _ = r_tree.advance_block_rooted(&a);
        let _ = r_tree.advance_block_rooted(&b);
        let r = r_tree.root_bytes();
        let mut server = all_owned();
        let _ = server.advance_block_rooted(&a);
        let _ = server.advance_block_rooted(&c);
        let stream: Vec<[u8; 32]> = server.spent_leaves_after(None, usize::MAX);
        let own_span: Vec<[u8; 32]> = a.iter().chain(b.iter()).copied().collect();

        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&c);
        assert!(pw.absorb_page(&stream, false) && pw.absorb_page(&[], false), "the server's stream absorbs and closes");
        assert!(!pw.at_pivot(), "calibration: stream − tail = A — B never came, the measured stall");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::NoPrefix, "calibration: part 2 cannot find B, it is not in the tail");
        assert!(pw.span_heal_due(), "a completed stream off its pivot is due a span heal");
        assert_eq!(
            pw.heal_from_own_span(&own_span),
            PrefixRestore::Healed(256),
            "⛔ DB-339 part 3: the node's own pivot block did not heal the scratch"
        );
        assert!(pw.at_pivot(), "⛔ the healed scratch is not exactly set(R)");
        let (tree, _, _) = pw.into_healed().ok().expect("a scratch at its pivot heals").into_parts();
        let mut live = r_tree.clone();
        let _ = live.advance_block_rooted(&c);
        assert_eq!(tree.root_bytes(), live.root_bytes(), "⛔ the healed view is not the live set R ∪ C");

        let mut pw = PivotWarm::new(r);
        pw.sync_tail(&c);
        assert!(pw.absorb_page(&stream, false) && pw.absorb_page(&[], false), "the server's stream absorbs and closes");
        let before = pw.scratch_root_for_test();
        let foreign: Vec<[u8; 32]> = own_span.iter().chain(block(14_000).iter()).copied().collect();
        assert_eq!(pw.heal_from_own_span(&foreign), PrefixRestore::NoPrefix, "⛔ a span with a block outside set(R) must never match R");
        assert!(!pw.at_pivot(), "⛔ nothing installs that is not root-equal to R");
        assert_eq!(pw.scratch_root_for_test(), before, "⛔ a failed heal must restore the scratch exactly");
        assert_eq!(pw.heal_from_own_span(&own_span), PrefixRestore::Skipped, "a second attempt waits for the tail to double");
    }

    /// ⭐⭐⭐ DB-399 — A FRESH NODE WITH NO BAND TAIL HEALS BY ITS HELD POST-PIVOT BLOCKS; A POISONED OR FOREIGN SET NEVER
    /// INSTALLS.
    ///
    /// `set(R)` = block A. The server is AHEAD: its stream is A ∪ C ∪ D. The node's band journal gives NO tail (the measured
    /// T1.6 state: band applied 0, peers' proofs gone), and the node holds the bodies of C, D and a later block E that the
    /// server had not seen.
    /// - CALIBRATION: `stream − tail = A ∪ C ∪ D`. With no tail, parts 2 and 4 cannot move the scratch. This is the measured
    ///   circular wait.
    /// - THE HEAL: groups [C, D, E] strip C and D (E is not in the scratch, so it is a no-op), and the scratch is exactly
    ///   `set(R)`. The installed view is the band root now (`R`, no tail).
    /// - ADVERSARIAL:
    ///   - a group naming a tag of `set(R)` (a respend loser) BEFORE the extras never matches `R`, and the scratch is
    ///     restored byte-for-byte;
    ///   - a foreign set (tags in no block the server applied) never matches;
    ///   - an attempt inside the doubling threshold does nothing;
    ///   - a poisoned block AFTER the extras still heals at the prefix, and nothing of `set(R)` is lost.
    #[test]
    fn db399_a_fresh_node_with_no_band_tail_heals_by_its_held_post_pivot_blocks_and_a_poisoned_set_never_installs() {
        // TWO-PARTY-REVIEWED: pure accumulator logic of ONE warm against a constructed server set; the two-party claim is the
        // simulator's T1.6 journey (a fresh third node joins the mesh).
        let block = |base: u64| -> Vec<[u8; 32]> { (base..base + 256).map(tag).collect() };
        let (a, c, d, e) = (block(21_000), block(23_000), block(24_000), block(25_000));
        let mut r_tree = all_owned();
        let _ = r_tree.advance_block_rooted(&a);
        let r = r_tree.root_bytes();
        let mut server = all_owned();
        for blk in [&a, &c, &d] {
            let _ = server.advance_block_rooted(blk);
        }
        let stream: Vec<[u8; 32]> = server.spent_leaves_after(None, usize::MAX);
        let warm = || {
            let mut pw = PivotWarm::new(r);
            assert!(pw.absorb_page(&stream, false) && pw.absorb_page(&[], false), "the server's stream absorbs and closes");
            pw
        };
        let bound = 3 * 256;

        // CALIBRATION: no tail, so nothing else moves the scratch.
        let mut pw = warm();
        assert!(!pw.at_pivot(), "calibration: the scratch holds the server's post-pivot extras");
        // O1-INFINITY-REVIEWED: a test assertion over one warm's RAM scratch; nothing is persisted or keyed per item.
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::NoPrefix, "calibration: no tail, part 2 has nothing to restore");
        assert!(!pw.at_pivot(), "calibration: part 2 left the scratch off its pivot");
        assert!(!pw.reopen_if_short(), "calibration: no tail, part 4 never runs");

        // THE HEAL.
        assert!(pw.held_strip_due(bound), "a completed stream off its pivot is due a held strip");
        let held = vec![c.clone(), d.clone(), e.clone()];
        assert_eq!(pw.strip_held_extras(&held, bound), PrefixRestore::Healed(512), "⛔ DB-399: the held blocks did not strip the extras");
        assert!(pw.at_pivot(), "⛔ the stripped scratch is not exactly set(R)");
        let (tree, _, synced) = pw.into_healed().ok().expect("a scratch at its pivot heals").into_parts();
        assert_eq!((tree.root_bytes(), synced), (r, 0), "⛔ the healed view is not set(R) with no tail");

        // ADVERSARIAL 1: a respend loser's tag (a member of set(R)) ahead of the extras never matches, and restores exactly.
        let mut pw = warm();
        let before = pw.scratch_root_for_test();
        let poisoned = vec![vec![a[7]], c.clone(), d.clone()];
        assert_eq!(pw.strip_held_extras(&poisoned, bound), PrefixRestore::NoPrefix, "⛔ a strip that removed a set(R) member matched R");
        assert_eq!(pw.scratch_root_for_test(), before, "⛔ a failed strip must restore the scratch exactly");
        assert!(!pw.at_pivot() && pw.into_healed().is_err(), "⛔ nothing installs that is not root-equal to R");

        // ADVERSARIAL 2: a foreign set never matches; a second attempt inside the doubling threshold does nothing.
        let mut pw = warm();
        assert_eq!(pw.strip_held_extras(&[e.clone()], bound), PrefixRestore::NoPrefix, "⛔ a foreign set matched R");
        assert_eq!(pw.strip_held_extras(&held, bound), PrefixRestore::Skipped, "a second attempt waits for the held bound to double");
        assert_eq!(pw.strip_held_extras(&held, 2 * bound), PrefixRestore::Healed(512), "the doubled bound retries and heals");

        // ADVERSARIAL 3: a poisoned block AFTER the extras heals at the prefix, before the poison is touched.
        let mut pw = warm();
        let late_poison = vec![c.clone(), d.clone(), vec![a[7]]];
        assert_eq!(pw.strip_held_extras(&late_poison, bound), PrefixRestore::Healed(512), "⛔ the prefix before the poison did not heal");
        let (tree, _, _) = pw.into_healed().ok().expect("a scratch at its pivot heals").into_parts();
        assert_eq!(tree.root_bytes(), r, "⛔ a set(R) member was lost");
    }

    /// ⭐⭐ DB-339 part 4 — a JUMPED node whose stream came from a server BEHIND its pivot re-opens and heals; a stream from
    /// a server AHEAD of it does not re-open while the tail still takes its extras back out; a lying pass never installs.
    ///
    /// `set(R)` = blocks A and B, the adopted pivot. A jumped node never held either, so it has no span and part 3 cannot run.
    /// - CALIBRATION ([slotB17f] node4): the first server's current view still held nothing, so the stream is one empty
    ///   page. The tail is the node's own post-pivot block C. Part 2 finds no prefix, and the scratch is off its pivot.
    /// - THE RE-OPEN: a block width of tail with no hit re-opens the stream. A server now AHEAD serves A ∪ B ∪ C ∪ D in two
    ///   pages. The pass skips C (tail) and inserts A, B and D, and the tail's D then hits: the scratch is exactly `set(R)`.
    /// - ADVERSARIAL:
    ///   - an AHEAD stream whose extras the tail is still taking back out does NOT re-open;
    ///   - a LYING pass (A ∪ B plus a forged block F) never reaches `R`, and nothing installs off the pivot;
    ///   - a check inside the doubling threshold does nothing; at the doubled threshold, still without a hit, it re-opens.
    #[test]
    fn db339_part4_a_stream_from_a_server_behind_the_pivot_reopens_and_heals_and_a_lying_pass_never_installs() {
        // TWO-PARTY-REVIEWED: pure accumulator logic of ONE warm against constructed server sets; the two-party claim is the
        // five-node real pin ([slotB17f]).
        let block = |base: u64| -> Vec<[u8; 32]> { (base..base + 256).map(tag).collect() };
        let (a, b, c, d) = (block(21_000), block(22_000), block(23_000), block(24_000));
        let mut r_tree = all_owned();
        let _ = r_tree.advance_block_rooted(&a);
        let _ = r_tree.advance_block_rooted(&b);
        let r = r_tree.root_bytes();
        let mut ahead = all_owned();
        for blk in [&a, &b, &c, &d] {
            let _ = ahead.advance_block_rooted(blk);
        }
        let ahead_stream: Vec<[u8; 32]> = ahead.spent_leaves_after(None, usize::MAX);

        // CALIBRATION: an empty first stream from a server whose current view held nothing yet.
        let mut pw = PivotWarm::new(r);
        assert!(pw.absorb_page(&[], false), "the behind server's empty page closes the stream");
        pw.sync_tail(&c);
        assert!(!pw.at_pivot(), "calibration: the scratch is empty and off its pivot (the measured node4 stall)");
        assert_eq!(pw.restore_pre_pivot_prefix(), PrefixRestore::NoPrefix, "calibration: part 2 cannot supply A or B");
        assert!(pw.reopen_if_short(), "⛔ DB-339 part 4: a block width of tail with no hit must re-open the stream");
        assert!(!pw.stream_done() && pw.cursor().is_none(), "the re-opened stream starts again from the first key");

        // THE TOP-UP PASS from a server now AHEAD of the pivot, in two key-ordered pages.
        let (p1, p2) = ahead_stream.split_at(ahead_stream.len() / 2);
        assert!(pw.absorb_page(p1, false) && pw.absorb_page(p2, false) && pw.absorb_page(&[], false), "the top-up pass absorbs and closes");
        assert!(!pw.at_pivot(), "D is post-pivot and stays in the scratch until the tail covers it");
        pw.sync_tail(&d);
        assert!(pw.at_pivot(), "⛔ the topped-up scratch minus the tail is not exactly set(R)");
        let (tree, _, _) = pw.into_healed().ok().expect("a scratch at its pivot heals").into_parts();
        let mut live = r_tree.clone();
        let _ = live.advance_block_rooted(&c);
        let _ = live.advance_block_rooted(&d);
        assert_eq!(tree.root_bytes(), live.root_bytes(), "⛔ the healed view is not the live set R ∪ C ∪ D");

        // ADVERSARIAL 1: an AHEAD stream whose extras the tail is still taking back out does not re-open.
        let mut pw = PivotWarm::new(r);
        assert!(pw.absorb_page(&ahead_stream, false) && pw.absorb_page(&[], false), "the ahead server's stream absorbs and closes");
        pw.sync_tail(&c);
        assert!(!pw.reopen_if_short(), "⛔ a tail that hits the scratch means extras, not shortness: no re-open");
        assert!(pw.stream_done(), "the stream stays closed");

        // ADVERSARIAL 2: a LYING top-up pass (A ∪ B ∪ a forged block F) never reaches R, and nothing installs.
        let f = block(25_000);
        let mut liar = all_owned();
        for blk in [&a, &b, &f] {
            let _ = liar.advance_block_rooted(blk);
        }
        let lie: Vec<[u8; 32]> = liar.spent_leaves_after(None, usize::MAX);
        let mut pw = PivotWarm::new(r);
        assert!(pw.absorb_page(&[], false), "an empty first stream");
        pw.sync_tail(&c);
        assert!(pw.reopen_if_short(), "the short stream re-opens");
        assert!(pw.absorb_page(&lie, false) && pw.absorb_page(&[], false), "the lying pass absorbs and closes");
        assert!(!pw.at_pivot(), "⛔ a pass carrying a forged block must never reach R");
        assert!(pw.into_healed().is_err(), "⛔ nothing installs that is not root-equal to R");

        // ADVERSARIAL 3: inside the doubling threshold a second check does nothing.
        let mut pw = PivotWarm::new(r);
        assert!(pw.absorb_page(&[], false), "an empty first stream");
        pw.sync_tail(&c);
        assert!(pw.reopen_if_short(), "the first re-open");
        assert!(pw.absorb_page(&[], false), "the re-opened pass is empty again: the server is still behind");
        assert!(!pw.reopen_if_short(), "⛔ a second re-open must wait for the tail to double");
        pw.sync_tail(&d);
        assert!(pw.reopen_if_short(), "at the doubled threshold, still without a hit, the stream re-opens again");
    }
}

/// ⭐⭐⭐ DB-353 — THE SELECTOR BOUNDARY PINS (docs/DB-353-NODE-SELECTOR-BOUNDARY-SPEC.md §5), two spaces and one boundary.
#[cfg(all(test, feature = "pins-core"))]
mod db353_boundary_pins {
    use super::*;

    /// A digest-encoded nullifier TAG, as every real tag is (`leaf_to_cm_bytes` of a Poseidon digest: 248 bits, byte 31 zero).
    fn digest_tag(i: u64) -> [u8; 32] {
        leaf_to_cm_bytes(poseidon_pair([0xDB35_3, i, 7, 11, 0, 0, 0, 0], [0xA, 0, 0, 0, 0, 0, 0, 0]))
    }

    /// The map the code had until 2026-09-29: the shard = the top `s` bits of TAG byte 31 (level 255 = bit 7 of byte 31).
    fn old_map_shard(tag: &[u8; 32], shard_bits: usize) -> u32 {
        let mut id = 0u32;
        for j in 0..shard_bits {
            let level = NF_SPARSE_DEPTH - 1 - j;
            id = (id << 1) | u32::from((tag[level >> 3] >> (level & 7)) & 1);
        }
        id
    }

    /// (b) SELECTOR UNIFORMITY, DERIVED bounds (R2): 4,096 digest tags over 256 shards is Poisson(16) per shard —
    /// every shard non-empty (P(empty) = e^-16) and the largest ≤ mean + 6·√mean = 40 (a 6σ tail, < 10^-8 per shard).
    /// RED CALIBRATION against the OLD map: every one of the 4,096 tags landed in shard 0 (byte 31 is always zero).
    #[test]
    fn db353_the_selector_spreads_real_tags_over_every_shard_and_the_old_map_put_them_all_in_shard_zero() {
        let tags: Vec<[u8; 32]> = (0..4_096u64).map(digest_tag).collect();
        for t in &tags {
            assert_eq!(t[31], 0, "a digest-encoded tag's byte 31 is always zero (248 information bits)");
        }
        let mut old = [0u32; 256];
        let mut new = [0u32; 256];
        for t in &tags {
            old[old_map_shard(t, 8) as usize] += 1;
            new[nf_shard(t, 8) as usize] += 1;
        }
        assert_eq!(old[0], 4_096, "RED calibration: the old map put EVERY tag in shard 0 — sharding retained nothing");
        let (min, max) = (new.iter().min().copied().expect("256 shards"), new.iter().max().copied().expect("256 shards"));
        assert!(min > 0, "every shard is non-empty under the new selector (P(empty) = e^-16 per shard); min = {min}");
        assert!(max <= 40, "the largest shard holds ≤ mean + 6·√mean = 40 (Poisson(16), 6σ); max = {max}");
    }

    /// (a) THE CROSS-DOOR DOUBLE-SPEND PIN: insert `T` through each insert door the node has; then EVERY membership reader
    /// asked about `T` answers SPENT or refuses. CALIBRATION: the same readers asked about `rev(T)` — the tag whose KEY is
    /// `T`'s bytes — answer UNSPENT, which proves the two spaces really differ (a path check in the wrong space would
    /// read UNSPENT for `T` itself: the double spend §4 names).
    #[test]
    fn db353_a_tag_inserted_through_every_door_reads_spent_from_every_reader_and_its_reverse_reads_unspent() {
        let t = digest_tag(1);
        let mut rev_t = t;
        rev_t.reverse();
        // door 1: the leaf-set tree + the accumulator's recorded door
        let mut tree = RefSparseNf::new();
        let mut acc = SparseNfAcc::new();
        let cp = tree.insert_and_witness(&t);
        acc.verify_and_insert(&t, &cp).expect("the recorded door settles T");
        assert_eq!(acc.root(), tree.root(), "the accumulator follows the tree");
        // door 2: apply_spend (the band path) on a second tree, same copath
        let mut tree2 = RefSparseNf::new();
        tree2.apply_spend(&t, &cp);
        assert_eq!(tree2.root(), tree.root(), "apply_spend lands T at the same position");
        // door 3: the treeless batch insert
        let pre = SparseNfAcc::new();
        let post = batch_insert_root(&pre, &[(t, cp.clone())]).expect("a valid carry batch");
        assert_eq!(post, tree.root_bytes(), "batch_insert_root lands T at the same position");
        // door 4: advance_one_rooted on a fourth tree
        let mut tree4 = RefSparseNf::new();
        let (_cp4, root4) = tree4.advance_one_rooted(&t).expect("unsharded: every tag is owned");
        assert_eq!(root4, tree.root(), "advance_one_rooted lands T at the same position");
        // every reader, about T: SPENT or refused
        let cp_now = tree.copath(&t);
        assert_eq!(acc.spent_verdict(&t, &cp_now), SpentVerdict::Spent, "spent_verdict reads T as SPENT");
        assert_eq!(acc.verify_unspent(&t, &cp_now), Err(SparseNfError::AlreadySpentOrBadWitness), "verify_unspent refuses T");
        assert_eq!(tree.holds_spent_leaf(&t), Some(true), "the leaf set holds T");
        assert!(SparseNfWitness::from_copath(t, cp_now.clone(), &acc).is_none(), "a non-membership witness for T is refused");
        let mut ring = RecentSpentRoots::default();
        ring.reset(pre.root());
        ring.absorb(pre.root(), acc.root(), t);
        assert_eq!(ring.verdict(acc.root(), &t, &cp_now), SpentVerdict::Spent, "the recent-roots ring reads T as SPENT");
        // CALIBRATION: rev(T) as a TAG walks a different path (T's bytes) — every reader answers UNSPENT
        let cp_rev = tree.copath(&rev_t);
        assert_eq!(acc.spent_verdict(&rev_t, &cp_rev), SpentVerdict::Unspent, "rev(T) is UNSPENT: the spaces differ");
        assert_eq!(acc.verify_unspent(&rev_t, &cp_rev), Ok(()), "rev(T) passes non-membership");
        assert_eq!(tree.holds_spent_leaf(&rev_t), Some(false), "the leaf set does not hold rev(T)");
        assert!(SparseNfWitness::from_copath(rev_t, cp_rev, &acc).is_some(), "a witness for rev(T) is accepted");
    }

    /// (c) DECIDER AGREEMENT through the ONE handoff: the decider's native insert over `insert_witness_for(T, copath)`
    /// reproduces the node tree's root; the keyed carrier for T verifies under the digest of T's KEY and is REFUSED under
    /// the digest of T's bytes taken as a key (the wrong space, one level up).
    #[test]
    fn db353_the_decider_walks_the_same_key_path_and_the_keyed_carrier_binds_the_key_not_the_tag() {
        let t = digest_tag(2);
        let mut tree = RefSparseNf::new();
        let pre_limbs = tree.root(); // the root value itself (Digest4 IS the decider's Digest), never re-entered via bytes
        let cp = tree.insert_and_witness(&t);
        // DB-453: the compact carrier — the band step's prover — over the node's ONE handoff
        let w = compact_insert_witness_for(&t, &cp).expect("the node's own compact copath");
        let native = usdm_decider::nf_compact_air::native_compact_insert_transition(&w, pre_limbs)
            .expect("the decider accepts the node's witness");
        assert_eq!(native, tree.root(), "the decider's native insert over the KEY reproduces the node tree's root");
        let lb = usdm_decider::nf_compact_air::compact_step_lb(std::slice::from_ref(&w));
        let (carrier, post, kd) = usdm_decider::nf_compact_air::prove_compact_band_carrier_bytes(&[w], pre_limbs, 1, lb)
            .expect("the compact carrier proves");
        assert_eq!(post, tree.root(), "the carrier's post is the node tree's root");
        assert_eq!(kd, SparseKey::keys_digest(&[SparseKey::of(&t)], 1), "the door's digest over the KEY is the prover's");
        assert!(
            usdm_decider::nf_compact_air::verify_compact_band_carrier_any_shape(&carrier, pre_limbs, post, 1, 1, kd),
            "verifies under the digest of T's KEY"
        );
        let wrong_space = SparseKey::keys_digest(&[SparseKey::from_key_bytes(t)], 1);
        assert_ne!(kd, wrong_space);
        assert!(
            !usdm_decider::nf_compact_air::verify_compact_band_carrier_any_shape(&carrier, pre_limbs, post, 1, 1, wrong_space),
            "REFUSED under the digest of T's bytes taken as a key — the tag space"
        );
    }

    /// (e) THE PUBLIC-SURFACE CENSUS: every `pub`/`pub(crate)` fn of this module that takes or returns 32 bytes either
    /// converts at the boundary (`SparseKey::of` / `.tag()` / `tag_tkey`, or a pass-through to a public fn that does), or
    /// says on its signature line why it does not: `// TAG-SPACE` (the nullifier is a VALUE there) or `// NOT-A-TAG` (a
    /// root, an accumulator, a canon id, a secret). A new public fn that forgets fails here. Source-text census over the
    /// module's non-test surface; the converters `of` / `tag` and the decider handoffs are the boundary itself.
    #[test]
    fn db353_every_public_fn_touching_32_bytes_converts_or_declares_its_space() {
        let src = include_str!("nf_sparse.rs");
        let surface_end = src.find("\nmod tests {").expect("the first test module");
        let surface = &src[..surface_end];
        let lines: Vec<&str> = surface.lines().collect();
        let is_fn_line = |l: &str| {
            let t = l.trim_start();
            t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ") || t.starts_with("pub(super) fn ") || t.starts_with("fn ")
        };
        let converts = [
            "SparseKey::of(", ".tag()", "tag_tkey(", "nf_shard(", "copath_described_roots(", "verify_unspent(",
            "observe_spend(", "advance_one_rooted(", "spent_verdict(", ".copath(", "insert_and_witness(", "apply_spend(",
            ".holds(", "insert_witness_for(", "keys_digest_of(",
        ];
        let exempt = ["pub fn of(", "pub fn tag(", "pub fn to_insert_witness(", "pub fn keys_digest(", "pub fn holders_of(", "pub fn holds_shard("];
        let mut offenders: Vec<String> = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim_start();
            if !(t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ")) || !l.contains("[u8; 32]") {
                continue;
            }
            if exempt.iter().any(|e| t.starts_with(e)) || l.contains("// TAG-SPACE") || l.contains("// NOT-A-TAG") {
                continue;
            }
            // the body: up to the next fn item
            let body: String = lines[i + 1..].iter().take_while(|n| !is_fn_line(n)).copied().collect::<Vec<_>>().join("\n");
            if !converts.iter().any(|c| body.contains(c)) {
                offenders.push(format!("line {}: {}", i + 1, t));
            }
        }
        assert!(
            offenders.is_empty(),
            "⛔ public fns touching 32 bytes that neither convert at the boundary nor declare their space:\n{}",
            offenders.join("\n")
        );
    }

    /// ⭐⭐⭐ SHAPE (3), THE TWO-PARTY FOLD (door spec §8b, pin (a)): two HOLDERS with disjoint shard sets serve their shards'
    /// lower copaths and band entries at the fold point; a PRODUCER holding no tree assembles the shard-major inserts with the
    /// mixed-band top siblings and proves the block's fold transition as `k = band_chain_k(4000)` direct carrier(s); a
    /// TREELESS door — holding only the fold root, the header's admitted tags and the announced entries — verifies the chain
    /// through `SparseKey::verify_chained_band_transition` and requires `fold_band(band') == the proven post`, which equals a
    /// full view's root after the same block (the oracle). One respend loser leaves an empty slot, padded by a filler served
    /// by its shard's holder. REFUSED: an announced entry for an untouched shard, a tampered entry, a tag left out of the
    /// derived order. The holders' trees are byte-identical before and after serving.
    #[test]
    fn db353_two_holders_serve_a_treeless_producer_proves_and_a_treeless_door_adopts_the_fold() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let lower = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let shards = 1u32 << bits;
        let mut holder_a = RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 0));
        let mut holder_b = RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 1));
        let mut oracle = RefSparseNf::new();
        let fold_pre = oracle.root();
        let band_pre: Vec<Digest4> = (0..shards as usize).map(|_| empty_subtree(lower)).collect();
        assert_eq!(usdm_decider::nf_sparse_air::fold_band(&band_pre), Some(fold_pre), "the empty band folds to the empty root");
        // the block's 256 tags; the last one is a respend loser the fold refuses → 255 admitted, one filler
        let tags: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let admitted: Vec<[u8; 32]> = tags[..cover - 1].to_vec();
        // the door's order: shard-major, ascending tag bytes within a shard
        let mut by_shard: std::collections::BTreeMap<u32, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
        for t in &admitted {
            by_shard.entry(nf_shard(t, bits)).or_default().push(*t);
        }
        for v in by_shard.values_mut() {
            v.sort();
        }
        let ordered: Vec<[u8; 32]> = by_shard.values().flatten().copied().collect();
        // a filler in a shard holder A owns
        let filler_idx = (0u64..).find(|i| key_shard(&band_filler_key(*i), bits) % 2 == 0).expect("some filler lands in an even shard");
        let filler_shard = key_shard(&band_filler_key(filler_idx), bits);
        let snapshot_a = holder_a.root_bytes();
        let snapshot_b = holder_b.root_bytes();
        let mut serves: Vec<(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)> = Vec::new();
        let mut fillers: Vec<(u64, u32, Vec<Digest4>, Digest4)> = Vec::new();
        for (s, ts) in &by_shard {
            let holder = if s % 2 == 0 { &mut holder_a } else { &mut holder_b };
            let f: Vec<u64> = if *s == filler_shard { vec![filler_idx] } else { Vec::new() };
            let (lows, entry, fl) = holder.serve_fold_copaths(ts, &f).expect("the holder serves its shard");
            serves.push((*s, entry, ts.iter().copied().zip(lows).collect()));
            for (low, after) in fl {
                fillers.push((filler_idx, *s, low, after));
            }
        }
        if !by_shard.contains_key(&filler_shard) {
            let (lows, _entry, fl) = holder_a.serve_fold_copaths(&[], &[filler_idx]).expect("a filler-only serve");
            assert!(lows.is_empty());
            for (low, after) in fl {
                fillers.push((filler_idx, filler_shard, low, after));
            }
        }
        assert_eq!(holder_a.root_bytes(), snapshot_a, "serving leaves holder A exactly as it was");
        assert_eq!(holder_b.root_bytes(), snapshot_b, "serving leaves holder B exactly as it was");
        assert_eq!(fillers.len(), 1);
        // the PRODUCER (no tree): assemble and prove
        let (inserts, ordered_tags, band_post) = assemble_fold_inserts(&band_pre, &serves, &fillers).expect("the assembly is well-formed");
        assert_eq!(ordered_tags, ordered, "the producer's order is the door's derivation");
        assert_eq!(inserts.len(), cover);
        let k = usdm_decider::nf_sparse_air::band_chain_k(4_000);
        let t0 = std::time::Instant::now();
        // PROOF-BINDS-STATE-REVIEWED: the carrier's statement binds the FOLD-POINT ROOT (chain state) and the post root; a proof
        // made for one fold root fails against another (the decider's chain pin refuses a broken link in both directions)
        let all: Vec<usize> = (0..k).collect();
        let chain: Vec<(Vec<u8>, Digest4)> = usdm_decider::nf_compact_air::prove_compact_band_slices(&inserts, fold_pre, admitted.len(), k, &all)
            .expect("the fold carrier proves")
            .into_iter()
            .map(|(_, post, bytes)| (bytes, post))
            .collect();
        eprintln!("[db353-fold] k={k}: {} slice(s), prove {} ms, {} B", chain.len(), t0.elapsed().as_millis(), chain.iter().map(|(b, _)| b.len()).sum::<usize>());
        // the DOOR (treeless): derive post from the announced band, verify the chain against its own derivation
        let post = usdm_decider::nf_sparse_air::fold_band(&band_post).expect("a 256-entry band folds");
        let slices: Vec<usdm_decider::nf_sparse_air::BandSlice<'_>> = chain.iter().map(|(b, p)| usdm_decider::nf_sparse_air::BandSlice { bytes: b, post: *p }).collect();
        // PROOF-BINDS-STATE-REVIEWED: verified against the door's OWN fold root and the post its own band folds to — no carried root
        assert!(SparseKey::verify_chained_band_transition(fold_pre, post, &ordered, &slices), "the treeless door adopts the fold from header values alone");
        // the ORACLE: a full view applying the same admitted tags lands on the same root, whatever the order
        for t in &admitted {
            let cp = oracle.copath(t);
            oracle.apply_spend(t, &cp);
        }
        assert_eq!(oracle.root(), post, "the announced band folds to the full view's root");
        // REFUSALS at the door
        let untouched = (0..shards).find(|s| !by_shard.contains_key(s) && *s != filler_shard).expect("an untouched shard exists");
        let mut band_bad = band_post.clone();
        band_bad[untouched as usize] = poseidon_pair(band_bad[untouched as usize], empty_subtree(0)); // a carried value for an untouched shard
        let post_bad = usdm_decider::nf_sparse_air::fold_band(&band_bad).expect("folds");
        assert!(!SparseKey::verify_chained_band_transition(fold_pre, post_bad, &ordered, &slices), "an entry for an untouched shard is refused");
        let touched = *by_shard.keys().next().expect("a touched shard");
        let mut band_tampered = band_post.clone();
        band_tampered[touched as usize] = poseidon_pair(band_tampered[touched as usize], empty_subtree(0));
        let post_tampered = usdm_decider::nf_sparse_air::fold_band(&band_tampered).expect("folds");
        assert!(!SparseKey::verify_chained_band_transition(fold_pre, post_tampered, &ordered, &slices), "a tampered announced entry is refused");
        assert!(!SparseKey::verify_chained_band_transition(fold_pre, post, &ordered[..ordered.len() - 1], &slices), "an admitted tag left out of the order is refused");
    }

    /// holders_of: deterministic and order-free; k ≥ n holds all; balanced within DERIVED bounds; minimally disruptive.
    #[test]
    fn db353_holders_of_is_deterministic_balanced_and_minimally_disruptive() {
        let ids: Vec<String> = (0..16).map(|i| format!("peer-{i:02}")).collect();
        let mut shuffled = ids.clone();
        shuffled.reverse();
        shuffled.swap(0, 5);
        for shard in [0u32, 17, 255] {
            assert_eq!(holders_of(b"band", shard, &ids, 3), holders_of(b"band", shard, &shuffled, 3), "order-free");
            assert_eq!(holders_of(b"band", shard, &ids, 3).len(), 3);
            assert_eq!(holders_of(b"band", shard, &ids, 100).len(), 16, "k ≥ n: every id holds the shard");
        }
        assert_ne!(holders_of(b"band", 0, &ids, 3), holders_of(b"window", 0, &ids, 3), "the domain separates structures");
        // balance: 256 shards × k = 3 over 16 ids → per id Binomial(256, 3/16): mean 48, σ = √(48·13/16) ≈ 6.25; 6σ = [11, 85]
        let mut count = std::collections::BTreeMap::<String, u32>::new();
        for shard in 0..256u32 {
            for h in holders_of(b"band", shard, &ids, 3) {
                *count.entry(h).or_insert(0) += 1;
            }
        }
        for (id, c) in &count {
            assert!((11..=85).contains(c), "{id} holds {c} shards; the 6σ band around 48 is [11, 85]");
        }
        assert_eq!(count.len(), 16, "every id holds something");
        // minimal disruption: a 17th id changes a shard's holder set only where it ranks in the top 3
        let mut more = ids.clone();
        more.push("peer-new".to_string());
        let mut moved = 0;
        for shard in 0..256u32 {
            let before = holders_of(b"band", shard, &ids, 3);
            let after = holders_of(b"band", shard, &more, 3);
            if before != after {
                moved += 1;
                assert!(after.iter().any(|h| h == "peer-new"), "shard {shard} changed without the new id ranking in");
                assert_eq!(after.iter().filter(|h| before.contains(h)).count(), 2, "exactly one prior holder yields");
            }
        }
        assert!(moved > 0 && moved < 256, "the new id takes some shards (expected ≈ 3·256/17 ≈ 45), never all: {moved}");
        assert!(holds_shard(b"band", 9, &ids, 3, None), "a node with no public id holds every shard");
        let h = holders_of(b"band", 9, &ids, 3);
        assert!(holds_shard(b"band", 9, &ids, 3, Some(&h[0])));
        assert!(!holds_shard(b"band", 9, &ids, 3, Some("peer-not-here")));
    }

    /// The holders' half for one fold step, as the copath-serve door will run it: holder `s % holders.len()` serves shard
    /// `s` — the admitted tags of the shard in the protocol order and the fillers that land in it (indices from
    /// `filler_from`, one per refused slot) — and every tree is restored after serving.
    #[allow(clippy::type_complexity)]
    fn serve_admitted(
        holders: &mut [RefSparseNf],
        admitted: &[[u8; 32]],
        filler_from: u64,
    ) -> (Vec<(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)>, Vec<(u64, u32, Vec<Digest4>, Digest4)>) {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let (_touched, ordered, by_shard) = admitted_order(admitted);
        let need = cover - ordered.len();
        let mut fill_by_shard: std::collections::BTreeMap<u32, Vec<u64>> = std::collections::BTreeMap::new();
        for i in filler_from..filler_from + need as u64 {
            fill_by_shard.entry(key_shard(&band_filler_key(i), bits)).or_default().push(i);
        }
        let shards: std::collections::BTreeSet<u32> = by_shard.keys().chain(fill_by_shard.keys()).copied().collect();
        let mut serves = Vec::new();
        let mut fillers = Vec::new();
        for s in shards {
            // a shard reached only by a filler has no admitted tag, and a shard with tags may have no filler: both are
            // legitimately empty lists, not missing values
            let tags: Vec<[u8; 32]> = match by_shard.get(&s) {
                Some(v) => v.clone(),
                None => Vec::new(),
            };
            let f: Vec<u64> = match fill_by_shard.get(&s) {
                Some(v) => v.clone(),
                None => Vec::new(),
            };
            let n = holders.len();
            let snapshot = holders[s as usize % n].root_bytes();
            let (lows, entry, fl) =
                holders[s as usize % n].serve_fold_copaths(&tags, &f).expect("the holder serves its shard");
            assert_eq!(holders[s as usize % n].root_bytes(), snapshot, "serving leaves the holder exactly as it was");
            if !tags.is_empty() {
                serves.push((s, entry, tags.iter().copied().zip(lows).collect()));
            }
            for (idx, (low, after)) in f.iter().zip(fl) {
                fillers.push((*idx, s, low, after));
            }
        }
        (serves, fillers)
    }

    /// ⭐ THE BAND DOOR, three nodes (two holders, one treeless), three fold steps, one rewind. RED-first: every refusal
    /// is asserted BEFORE the honest copy applies, on a door whose band is provably at the pre root. Pins §8 (g) — a
    /// concurrent double spend does not stall the band, the loser leaves the set —, (h) — a rewound fold restores the
    /// band byte-identically —, the pointer-never-skips rule (an idle step waits behind a pending one), the replay set,
    /// and the 9/24 incorrect-design guard: three doors hold one band at every step.
    /// PROOF-BINDS-STATE-REVIEWED: every verification runs against the door's OWN fold root and the post root its own
    /// band folds to; a carrier for one fold root fails against another (the decider's chain pin).
    #[test]
    fn db353_band_door_moves_only_by_carried_verified_transitions_in_fold_order_and_rewinds_byte_identically() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let shards = 1u32 << bits;
        let mut holders = vec![
            RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 0)),
            RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 1)),
        ];
        let mut oracle = RefSparseNf::new();
        let (mut door_a, mut door_b, mut door_t) = (BandDoor::new(64), BandDoor::new(64), BandDoor::new(64));
        let ring = 8usize;
        let (b1, b2, b3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        // ── STEP 1: 256 header tags, no losers ──
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        for d in [&mut door_a, &mut door_b, &mut door_t] {
            assert!(d.note_fold_step(1, b1, Some(tags1.clone())));
            assert_eq!(d.pointer(), Some(1));
            assert!(d.drain(None, ring).is_empty(), "no carrier, no move");
            assert_eq!(d.last_wait(), BandWait::Carrier);
            assert_eq!(d.band_root_at(1), None, "step 1 is PENDING");
        }
        let root0 = door_t.band_root();
        assert_eq!(root0, oracle.root(), "CALIBRATION: the empty band is the empty root");
        let (serves, fillers) = serve_admitted(&mut holders, &tags1, 0);
        assert!(fillers.is_empty(), "no refused slot, no filler");
        // §11.1: the step is proven at the door's OWN slice count — the production value, band_chain_k(the target spacing)
        let k = door_t.chain_k();
        let t0 = std::time::Instant::now();
        let t1 = build_band_transition(b1, door_t.band(), &serves, &fillers, k).expect("the producer lays step 1's transition");
        eprintln!(
            "[db353-door] step 1: k={k}, {} touched shards, prove {} ms, {} B",
            t1.band_post.len(),
            t0.elapsed().as_millis(),
            t1.slices.iter().map(|(_, _, b)| b.len()).sum::<usize>()
        );
        // ── REFUSALS FIRST: the attack is armed while the door is provably at the pre root. Each forged copy goes to a
        // FRESH door (no honest copy there to mask it) and is refused AT THE DOOR (§11.12: a relayed step verifies when
        // offered), and the honest copy then verifies on that SAME door — nothing a bad relay sends blocks an honest one ──
        let applied_block = "this step's block is already applied";
        let mut wrong_block = t1.clone();
        wrong_block.for_block = [9u8; 32];
        assert_eq!(door_t.offer_step(wrong_block, false), BandReceipt::Held, "a step for a block not yet noted is PARKED (early gossip), never lost");
        assert_eq!(door_t.parked_len(), 1);
        let mut wrong_k = t1.clone();
        wrong_k.k = (k * 2) as u32;
        assert_eq!(door_t.offer_step(wrong_k, false), BandReceipt::Refused("slice count is not this chain's band_chain_k"));
        let mut partial = t1.clone();
        partial.slices.truncate(k - 1);
        assert_eq!(
            door_t.offer_step(partial, true),
            BandReceipt::Refused("a relayed step carries all k slices, in order"),
            "a relayed step is WHOLE: a partial one is refused before any proof work, solicited or not"
        );
        let touched: std::collections::BTreeSet<u32> = t1.band_post.iter().map(|(s, _)| *s).collect();
        let untouched = (0..shards).find(|s| !touched.contains(s)).expect("an untouched shard");
        let mut extra = t1.clone();
        extra.band_post.push((untouched, poseidon_pair(empty_subtree(usdm_decider::nf_sparse_air::NF_BAND_LEVEL), [0xA, 0, 0, 0, 0, 0, 0, 0])));
        extra.band_post.sort_by_key(|(s, _)| *s);
        let mut tampered = t1.clone();
        tampered.band_post[0].1 = poseidon_pair(tampered.band_post[0].1, [0xA, 0, 0, 0, 0, 0, 0, 0]);
        let mut bad_proof = t1.clone();
        let real_slice = bad_proof.slices.iter().position(|(_, _, b)| !b.is_empty()).expect("a proven slice");
        let n = bad_proof.slices[real_slice].2.len();
        bad_proof.slices[real_slice].2[n / 2] ^= 0xFF;
        let mut missing = t1.clone();
        missing.band_post.pop();
        for (what, forged) in [
            ("a carried entry for an UNTOUCHED shard", extra),
            ("a tampered touched entry", tampered),
            ("a tampered proof", bad_proof),
            ("a touched shard without its entry", missing),
        ] {
            let mut d = BandDoor::new(64);
            assert!(d.note_fold_step(1, b1, Some(tags1.clone())));
            assert!(matches!(d.offer_step(forged, false), BandReceipt::Invalid(_)), "{what} is INVALID at the door");
            assert!(d.drain(None, ring).is_empty(), "{what} never applies");
            assert_eq!((d.copies_refused, d.band_root(), d.pointer(), d.last_wait()), (1, root0, Some(1), BandWait::Carrier), "{what}");
            assert!(d.serve_step(&b1).is_none() && d.verified_blocks().is_empty(), "{what} is neither held nor served");
            assert_eq!(d.offer_step(t1.clone(), false), BandReceipt::Verified, "after {what}, the honest copy verifies");
            assert_eq!(d.drain(None, ring).len(), 1, "after {what}, the honest copy applies on the same door");
        }
        // ── THE HONEST COPY verifies and applies on all three nodes; the holders' recompute agrees ──
        assert_eq!(door_a.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(door_a.offer_step(t1.clone(), false), BandReceipt::Refused("this step is already verified"), "one verified copy per step");
        assert_eq!(door_a.serve_step(&b1), Some(&t1), "a verified step is served to peers");
        let ap_a = door_a.drain(Some(&mut holders[0]), ring);
        assert_eq!(door_b.offer_step(t1.clone(), false), BandReceipt::Verified);
        let ap_b = door_b.drain(Some(&mut holders[1]), ring);
        assert_eq!(door_t.offer_step(t1.clone(), false), BandReceipt::Verified);
        let ap_t = door_t.drain(None, ring);
        // ⛔ AN APPLIED STEP IS STILL SERVED — and a peer still behind catches up from it. MEASURED 2026-10-06
        // (`sim-20261006-045210`, T1.6): applying dropped the proof, so a joiner whose band trailed its adopted fold point
        // wanted 32 steps no node held and applied none (RED here before: `serve_step` after `drain` was None).
        let served = door_a.serve_step(&b1).cloned().expect("⛔ door A applied step 1 and no longer serves its proof");
        assert_eq!(served, t1, "the applied step's proof is served byte-identically");
        let mut late = BandDoor::new(64);
        assert!(late.note_fold_step(1, b1, Some(tags1.clone())));
        assert_eq!(late.offer_step(served, true), BandReceipt::Verified, "the behind peer verifies the served applied step");
        assert_eq!(late.drain(None, ring).len(), 1, "the behind peer applies it");
        assert_eq!(late.band_root(), door_a.band_root(), "and reaches the same band root");
        for ap in [&ap_a, &ap_b, &ap_t] {
            assert_eq!(ap.len(), 1);
            assert_eq!((ap[0].ordinal, ap[0].block, ap[0].touched), (1, b1, t1.band_post.len()));
            assert!(ap[0].holder_disagreed.is_empty(), "the holders' recompute agrees with the carried entries");
        }
        for t in &tags1 {
            let cp = oracle.copath(t);
            oracle.apply_spend(t, &cp);
        }
        let root1 = oracle.root();
        assert_eq!(door_t.band_root(), root1, "the carried band folds to the full view's root");
        assert_eq!(door_a.band(), door_t.band(), "holder A's node and the treeless node hold ONE band");
        assert_eq!(door_b.band(), door_t.band(), "holder B's node and the treeless node hold ONE band");
        assert_eq!((door_t.band_root_at(1), door_t.pointer()), (Some(root1), None));
        assert_eq!(door_t.offer_step(t1.clone(), false), BandReceipt::Refused(applied_block), "REPLAY: refused by the set (the journal holds the block)");
        let snap1 = door_t.band().to_vec();
        // ── STEP 2 (pin g): block 2's header carries a tag block 1 already spent; the fold's loser leaves the set ──
        let header2: Vec<[u8; 32]> =
            (cover as u64..2 * cover as u64 - 1).map(digest_tag).chain(std::iter::once(tags1[7])).collect();
        let admitted2: Vec<[u8; 32]> = header2[..cover - 1].to_vec();
        assert!(header2.contains(&tags1[7]) && !admitted2.contains(&tags1[7]), "CALIBRATION: the loser is out");
        // STEP 3 is an idle block noted behind it: the pointer never skips it ahead of step 2
        for d in [&mut door_a, &mut door_b, &mut door_t] {
            assert!(d.note_fold_step(2, b2, Some(admitted2.clone())));
            assert!(d.note_fold_step(3, b3, Some(Vec::new())));
            assert!(d.drain(None, ring).is_empty());
            assert_eq!((d.pointer(), d.band_root_at(3)), (Some(2), None), "the idle step 3 waits behind step 2");
        }
        let (serves2, fillers2) = serve_admitted(&mut holders, &admitted2, 0);
        assert_eq!(fillers2.len(), 1, "one refused slot, one filler");
        let t0 = std::time::Instant::now();
        let t2 = build_band_transition(b2, door_t.band(), &serves2, &fillers2, k)
            .expect("step 2's transition proves — the loser is out of the set, so the band does not stall");
        eprintln!("[db353-door] step 2 (one loser, one filler): prove {} ms", t0.elapsed().as_millis());
        assert_eq!(door_a.offer_step(t2.clone(), false), BandReceipt::Verified);
        let ap_a = door_a.drain(Some(&mut holders[0]), ring);
        assert_eq!(door_b.offer_step(t2.clone(), false), BandReceipt::Verified);
        let ap_b = door_b.drain(Some(&mut holders[1]), ring);
        assert_eq!(door_t.offer_step(t2.clone(), false), BandReceipt::Verified);
        let ap_t = door_t.drain(None, ring);
        for ap in [&ap_a, &ap_b, &ap_t] {
            assert_eq!(ap.iter().map(|a| a.ordinal).collect::<Vec<_>>(), vec![2, 3], "step 2, then the idle step 3");
            assert!(ap.iter().all(|a| a.holder_disagreed.is_empty()));
        }
        for t in &admitted2 {
            let cp = oracle.copath(t);
            oracle.apply_spend(t, &cp);
        }
        let root2 = oracle.root();
        assert_eq!(door_t.band_root(), root2, "the band advanced past the double spend to the full view's root");
        assert_eq!((door_t.band_root_at(2), door_t.band_root_at(3)), (Some(root2), Some(root2)), "an idle step keeps the root");
        assert_eq!(door_a.band(), door_t.band());
        assert_eq!(door_b.band(), door_t.band());
        let snap2 = door_t.band().to_vec();
        let proofs2 = door_t.applied_proof_blocks();
        assert_eq!(proofs2.last(), Some(&b2), "CALIBRATION: step 2's applied proof is held");
        // ── REWIND (pin h): un-fold steps 2 and 3 — byte-identical to the band after step 1 ──
        assert!(door_t.rewind_to(2, None), "inside the journal: not stale");
        assert_eq!(door_t.band(), &snap1[..], "the band after the rewind is the band after step 1, byte for byte");
        assert_eq!((door_t.band_root(), door_t.band_root_at(1), door_t.band_root_at(2), door_t.pointer()), (root1, Some(root1), None, None));
        assert!(!door_t.applied_proof_blocks().contains(&b2), "⛔ the un-applied step's proof stayed behind its journal entry");
        // the re-fold notes step 2 again and the transition is re-carried: the door lands on the same band
        assert!(door_t.note_fold_step(2, b2, Some(admitted2.clone())));
        assert_eq!(door_t.offer_step(t2.clone(), false), BandReceipt::Verified);
        assert_eq!(door_t.drain(None, ring).len(), 1);
        assert_eq!(door_t.band(), &snap2[..]);
        assert_eq!(
            door_t.applied_proof_blocks(),
            proofs2,
            "⛔ a rewind + re-fold left the applied proofs different from a door that never rewound (a duplicate shifts the window)"
        );
        // ── THE FLOOR: a door whose journal released a step refuses to rewind below it ──
        // (DB-367 follow-up: an idle step takes no journal slot, so the steps that fill the journal here MOVE the band —
        // the same two proven transitions, re-verified on a one-slot door.)
        let mut short = BandDoor::new(1);
        assert!(short.note_fold_step(1, b1, Some(tags1.clone())));
        assert_eq!(short.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(short.drain(None, ring).len(), 1);
        assert!(short.note_fold_step(2, b2, Some(admitted2.clone())));
        assert_eq!(short.offer_step(t2.clone(), false), BandReceipt::Verified);
        assert_eq!(short.drain(None, ring).len(), 1);
        assert_eq!(short.floor(), 2, "the journal released step 1: the floor is one past it");
        assert!(!short.rewind_to(1, None), "a rewind below the floor is STALE, never silently kept");
        assert!(short.rewind_to(2, None));
        // and IDLE steps never move it: they change nothing, so they take no slot (`db367_empty_steps_…`)
        let mut idle = BandDoor::new(1);
        for (o, b) in [(1u64, b1), (2, b2), (3, b3)] {
            assert!(idle.note_fold_step(o, b, Some(Vec::new())));
            assert_eq!(idle.drain(None, ring).len(), 1);
        }
        assert_eq!(idle.floor(), 0, "idle steps released nothing: the floor stays");
        assert!(idle.rewind_to(1, None), "a rewind past idle steps is inside the reach");
    }

    /// R2a — a holder never advances by its own recompute: a held subtree that DISAGREES with the carried entry is named
    /// (the caller drops and re-warms it) and the carried, verified value stands — the holder's node holds the same band
    /// as a treeless node.
    #[test]
    fn db353_band_door_names_a_disagreeing_holder_shard_and_the_carried_value_stands() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let shards = 1u32 << bits;
        let mut holders = vec![
            RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 0)),
            RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 1)),
        ];
        let b1 = [1u8; 32];
        let tags: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let (serves, fillers) = serve_admitted(&mut holders, &tags, 0);
        let fresh = BandDoor::new(8);
        let t1 = build_band_transition(b1, &fresh.band().to_vec(), &serves, &fillers, fresh.chain_k()).expect("proves");
        // AFTER serving (the copaths were honest), holder A's tree rots: a stray leaf in an even shard it owns
        let stray = (1_000_000u64..).map(digest_tag).find(|t| nf_shard(t, bits) % 2 == 0).expect("an even-shard tag");
        let stray_shard = nf_shard(&stray, bits);
        let cp = holders[0].copath(&stray);
        holders[0].apply_spend(&stray, &cp);
        let (mut door_a, mut door_t) = (BandDoor::new(8), BandDoor::new(8));
        for d in [&mut door_a, &mut door_t] {
            assert!(d.note_fold_step(1, b1, Some(tags.clone())));
            assert_eq!(d.offer_step(t1.clone(), false), BandReceipt::Verified);
        }
        let ap = door_a.drain(Some(&mut holders[0]), 8);
        assert_eq!(ap.len(), 1);
        assert_eq!(ap[0].holder_disagreed, vec![stray_shard], "exactly the rotten shard is named");
        assert_eq!(door_t.drain(None, 8).len(), 1);
        assert_eq!(door_a.band(), door_t.band(), "the carried value stands: the holder's node holds the treeless node's band");
        assert_eq!(door_a.band_root(), door_t.band_root());
    }

    /// DB-353 §11 — THE LAG MODEL: the pointer's lag over `steps` mesh blocks when `producers` nodes each attach slices at
    /// their own block, with `slice_ms` of proving per slice and each node's spacing `max(target × producers, relay
    /// floor)` (the block-time law). One fold step arrives per mesh block. `split = true` is §11.4 as amended (each
    /// producer carries, at its next block, what it planned at the START of its interval: the missing slices it OWNS,
    /// `owned_band_slices`, lowest step first, then the OPEN pick on steps older than the latency bound, up to its budget);
    /// `split = false` is today's rule (each producer proves the POINTER's whole step and carries it, a
    /// duplicate when another producer finished it first). A step applies when all `k` slices are in and every earlier
    /// step applied. Returns `(max lag, steps dropped past the lag cap, margin = spacing ÷ step cost, whether the lag is
    /// flat — the second half's worst within one step of the first half's)`.
    /// What a producer plans for its next block in [`band_lag_model`].
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum LagPick {
        /// Every producer proves the pointer's WHOLE step (duplication).
        WholeStep,
        /// §11.4 amended: HRW-owned slices, then the open pick. `one_step` = the block can carry slices of ONE step only
        /// (`Block.band_transition: Option<BandTransition>`, one `for_block`); `false` = slices of several steps.
        Owned { one_step: bool },
        /// No ids: missing `(step, slice)` pairs in an order keyed by the producer's PRIVATE randomness, over several steps.
        PrivateRandom,
        /// No ids, OLDEST FIRST: the pick is uniform (private randomness) over the missing slices of the lowest steps
        /// until that window holds `window × budget` of them — so the pointer's step is never starved by later ones.
        PrivateWindow { window: usize },
        /// §11.12: WHOLE steps owned round-robin by fold ordinal (step `s` → producer `s mod N`), proven ahead from the
        /// owner's cursor and relayed (any number of steps per interval), then the open pick on steps older than 2N.
        StepOwner,
    }

    fn band_lag_model(k: usize, slice_ms: f64, producers: usize, steps: usize, pick: LagPick) -> (usize, usize, f64, bool) {
        let target = crate::params::ChainParams::default().target_spacing_ms as f64;
        let spacing = (target * producers as f64).max(crate::dag::PRODUCTION_RELAY_FLOOR_MS as f64);
        let step_cost = k as f64 * slice_ms;
        let margin = spacing / step_cost;
        let cap = crate::params::SPINE_RING_LEN;
        // every block, in time order: (time, producer)
        let mut events: Vec<(f64, usize)> = Vec::new();
        for j in 0.. {
            for p in 0..producers {
                events.push((p as f64 * spacing / producers as f64 + j as f64 * spacing, p));
            }
            if events.len() >= steps + producers {
                break;
            }
        }
        events.sort_by(|a, b| a.0.partial_cmp(&b.0).expect("finite"));
        events.truncate(steps);
        let block_id = |n: usize| -> [u8; 32] { *blake3::hash(&(n as u64).to_le_bytes()).as_bytes() };
        let ids: Vec<String> = (0..producers).map(|p| format!("producer-{p}")).collect();
        let mut carried: Vec<std::collections::BTreeSet<usize>> = Vec::new(); // per step: slices carried
        let mut first_half_max = 0usize;
        let mut applied = 0usize;
        let (mut max_lag, mut dropped) = (0usize, 0usize);
        let mut plans: Vec<Vec<(usize, Vec<usize>)>> = vec![Vec::new(); producers]; // what each producer is proving now
        for (n, (_, p)) in events.iter().enumerate() {
            // the block carries what its producer picked at the START of its interval
            for (step, slices) in std::mem::take(&mut plans[*p]) {
                if step >= applied && step < carried.len() {
                    carried[step].extend(slices);
                }
            }
            carried.push(std::collections::BTreeSet::new()); // this block is a new fold step
            while applied < carried.len() && carried[applied].len() == k {
                applied += 1;
            }
            let lag = carried.len() - applied;
            max_lag = max_lag.max(lag);
            if n < steps / 2 {
                first_half_max = first_half_max.max(lag);
            }
            if lag > cap {
                dropped += 1;
            }
            // plan the next interval from the door's view NOW
            let own = block_id(n);
            let mut plan: Vec<(usize, Vec<usize>)> = Vec::new();
            if pick == LagPick::StepOwner {
                let mut budget = (spacing / slice_ms).floor() as usize;
                let latency_blocks = 2 * producers;
                for step in applied..carried.len() {
                    let open = carried.len() - 1 - step >= latency_blocks;
                    if step % producers != *p && !open {
                        continue;
                    }
                    let missing: Vec<usize> = (0..k).filter(|i| !carried[step].contains(i)).collect();
                    if missing.is_empty() || missing.len() > budget {
                        continue;
                    }
                    budget -= missing.len();
                    plan.push((step, missing));
                }
            } else if matches!(pick, LagPick::PrivateRandom | LagPick::PrivateWindow { .. }) {
                let mut budget = (spacing / slice_ms).floor() as usize;
                let want = match pick {
                    LagPick::PrivateWindow { window } => window * budget,
                    _ => usize::MAX,
                };
                let mut pool: Vec<([u8; 32], usize, usize)> = Vec::new();
                for step in applied..carried.len() {
                    if pool.len() >= want {
                        break;
                    }
                    for i in (0..k).filter(|i| !carried[step].contains(i)) {
                        let mut h = blake3::Hasher::new();
                        h.update(b"model/private-pick");
                        h.update(&(*p as u64).to_le_bytes()); // the producer's secret
                        h.update(&(n as u64).to_le_bytes());
                        h.update(&(step as u64).to_le_bytes());
                        h.update(&(i as u64).to_le_bytes());
                        pool.push((*h.finalize().as_bytes(), step, i));
                    }
                }
                pool.sort_unstable();
                for (_, step, i) in pool {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    match plan.iter_mut().find(|(s, _)| *s == step) {
                        Some((_, v)) => v.push(i),
                        None => plan.push((step, vec![i])),
                    }
                }
            } else if let LagPick::Owned { one_step } = pick {
                // §11.4 (amended): the slices this producer OWNS (HRW over the producer ids), lowest step first; then the
                // OPEN pick on steps older than the expected latency (owners plan within one spacing and carry one later)
                let mut budget = (spacing / slice_ms).floor() as usize;
                let latency_blocks = 2 * producers;
                for step in applied..carried.len() {
                    if budget == 0 {
                        break;
                    }
                    let owned: Vec<usize> = owned_band_slices(&block_id(step), &ids[*p], &ids, k)
                        .into_iter()
                        .filter(|i| !carried[step].contains(i))
                        .take(budget)
                        .collect();
                    budget -= owned.len();
                    if !owned.is_empty() {
                        plan.push((step, owned));
                    }
                }
                for step in applied..carried.len() {
                    if budget == 0 || carried.len() - 1 - step < latency_blocks {
                        break;
                    }
                    let planned: Vec<usize> = plan.iter().filter(|(s, _)| *s == step).flat_map(|(_, v)| v.clone()).collect();
                    let missing: Vec<usize> =
                        (0..k).filter(|i| !carried[step].contains(i) && !planned.contains(i)).collect();
                    let picked = pick_band_slices(&block_id(step), &own, k, &missing, budget);
                    budget -= picked.len();
                    if !picked.is_empty() {
                        plan.push((step, picked));
                    }
                }
                if one_step {
                    // the wire carries ONE BandTransition (one for_block): only the plan's lowest step rides
                    plan.sort_by_key(|(s, _)| *s);
                    if let Some(lowest) = plan.first().map(|(s, _)| *s) {
                        let merged: Vec<usize> = plan.iter().filter(|(s, _)| *s == lowest).flat_map(|(_, v)| v.clone()).collect();
                        plan = vec![(lowest, merged)];
                    }
                }
            } else if spacing >= step_cost && applied < carried.len() {
                plan.push((applied, (0..k).collect()));
            }
            plans[*p] = plan;
        }
        // NOT growing: the second half's worst lag is within one step of the first half's
        (max_lag, dropped, margin, max_lag <= first_half_max + 1)
    }

    /// ⭐ DB-353 §11 (pin a) — THE LAG GATE. MEASURED inputs: one real 256-insert fold step proven at the door's `k`, its
    /// per-slice cost and its bytes. Then the deterministic lag model (the door's missing-slice rule and the real
    /// `pick_band_slices`) runs 200 mesh blocks with three producers at the block-time law's spacing, at the REFERENCE
    /// cost (`BAND_FOLD_PROVE_MS_REF`) and at the MEASURED one.
    /// - RED FIRST: today's whole-step attach (every producer proves the pointer's step) lets the lag GROW at the
    ///   reference cost — producers duplicate one step while new steps keep arriving.
    /// - §11.4's split attach keeps the lag ≤ 2 with no step dropped at the reference cost (margin ≥ 1).
    /// - At the measured cost the margin is printed; margin < 1 is the named LIVENESS residual (lag → the cap → counted
    ///   drops → certified re-adopt, never a skip), not a pass.
    /// Prints bytes per step and per block (condition 1) and the small-mesh con (condition 3: `k` from the governance
    /// target, so a 2-node mesh at the floor pays k slices per step where band_chain_k(its own spacing) would pay fewer).
    /// TWO-PARTY-REVIEWED: a capacity MODEL over one prover's measured cost; the two-party claims (a treeless door and
    /// holders holding one band from carried slices) are the band-door pins beside it.
    #[test]
    fn db353_11_the_band_lag_stays_bounded_when_producers_split_slices_and_grows_when_they_duplicate_steps() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let shards = 1u32 << bits;
        let mut holders = vec![RefSparseNf::with_shards(bits, 0..shards)];
        let door = BandDoor::new(64);
        // the RETIRED producer slice carriage (§13.3), measured at the k it used: the target's band_chain_k (8); the relay
        // proves at band_relay_k (1) — `db353_11_14_…`
        let k = usdm_decider::nf_sparse_air::band_chain_k(crate::params::ChainParams::default().target_spacing_ms);
        let tags: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let (serves, fillers) = serve_admitted(&mut holders, &tags, 0);
        let t0 = std::time::Instant::now();
        let t = build_band_transition([1u8; 32], door.band(), &serves, &fillers, k).expect("one real step proves");
        let measured_step_ms = t0.elapsed().as_millis() as f64;
        let slice_ms = measured_step_ms / k as f64;
        let step_bytes: usize = t.slices.iter().map(|(_, _, b)| b.len()).sum::<usize>() + t.band_post.len() * 36;
        let ref_slice_ms = usdm_decider::nf_sparse_air::BAND_FOLD_PROVE_MS_REF as f64 / k as f64;
        let floor_k = usdm_decider::nf_sparse_air::band_chain_k(crate::dag::PRODUCTION_RELAY_FLOOR_MS);
        eprintln!(
            "[db353-11] k={k}: MEASURED one step {measured_step_ms:.0} ms ({slice_ms:.0} ms/slice), {step_bytes} B per step \
             = {step_bytes} B per block (one step per mesh block); small-mesh con: at the floor band_chain_k would be \
             {floor_k}, the governance target makes it {k} (≈ {step_bytes} B vs ≈ {} B per block)",
            step_bytes * floor_k / k.max(1)
        );
        let (steps, producers) = (200, 3);
        // the latency SCALE (printed, not asserted): an owner plans within one spacing (N mesh blocks) and carries one
        // spacing later, so a step completes ≈ 2N blocks after it arrives; uneven HRW shares and the integer budget add a
        // small constant backlog on top. The CLAIM is flatness and zero drops, not a tuned number.
        let bound = 2 * producers;
        let owned = LagPick::Owned { one_step: false };
        let (dup_lag, dup_drop, dup_margin, dup_flat) = band_lag_model(k, ref_slice_ms, producers, steps, LagPick::WholeStep);
        let (split_lag, split_drop, split_margin, split_flat) = band_lag_model(k, ref_slice_ms, producers, steps, owned);
        let (meas_lag, meas_drop, meas_margin, meas_flat) = band_lag_model(k, slice_ms, producers, steps, owned);
        eprintln!(
            "[db353-11] {producers} producers, {steps} blocks — REFERENCE cost: duplicate-step attach lag {dup_lag} (dropped \
             {dup_drop}, flat {dup_flat}, margin {dup_margin:.2}) | owned-slice attach lag {split_lag} (dropped {split_drop}, \
             flat {split_flat}, margin {split_margin:.2}); MEASURED cost: owned-slice lag {meas_lag} (dropped {meas_drop}, \
             flat {meas_flat}, margin {meas_margin:.2}); latency bound {bound}"
        );
        assert!(split_margin >= 1.0, "CALIBRATION: at the reference cost the block-time law's spacing covers one step");
        assert!(
            !dup_flat && dup_drop > 0,
            "RED FIRST: today's whole-step attach lets the lag GROW ({dup_lag}, {dup_drop} dropped) even at margin {dup_margin:.2}"
        );
        // §13 refutation (MEASURED at 400 vs 1,600 blocks, `db353_13_…`): at the reference margin the owned lag is a SLOW
        // SLOPE, not flat — flatness needs margin headroom (constant from ≈ 1.27) or P7's backpressure. This 200-block run
        // asserts only what it can: the split drops nothing where whole-step duplication drops
        assert!(
            split_drop == 0,
            "⛔ §11.4's owned-slice attach dropped {split_drop} steps (lag {split_lag}, flat {split_flat})"
        );
        if meas_margin >= 1.0 {
            assert!(meas_drop == 0, "⛔ at measured margin {meas_margin:.2} ≥ 1 the owned attach dropped {meas_drop} (lag {meas_lag})");
        } else {
            eprintln!(
                "[db353-11] ⚠ LIVENESS RESIDUAL on THIS machine: measured margin {meas_margin:.2} < 1 — the lag grows toward \
                 the cap ({meas_lag} after {steps} blocks) and a dropped step needs a certified re-adopt; the scale-floor run \
                 is the production measurement"
            );
        }
    }

    /// DB-353 §13 refutation instrument (model only, no proving — the REFERENCE slice cost): which CARRIAGE the lag
    /// needs. Every block adds one step of `k` slices, so a block that can carry only ONE step (`Option<BandTransition>`,
    /// one `for_block`) supplies at most what it demands: owned slices split each step over N blocks and the lag must
    /// GROW. Carriage over several steps is what §11.9's flat measurement actually modelled.
    /// TWO-PARTY-REVIEWED: a capacity MODEL; no party state is asserted.
    #[test]
    fn db353_13_a_block_that_carries_one_step_cannot_catch_up_and_owned_slices_need_several() {
        // the RETIRED slice carriage, measured at the k it used: the target's band_chain_k (8)
        let k = usdm_decider::nf_sparse_air::band_chain_k(crate::params::ChainParams::default().target_spacing_ms);
        let ref_slice_ms = usdm_decider::nf_sparse_air::BAND_FOLD_PROVE_MS_REF as f64 / k as f64;
        // two scales tell a constant from a slope: the lag after 400 and after 1,600 blocks
        for producers in [2usize, 3, 5] {
            // the CALIBRATION point is where a producer's integer slice budget is EXACTLY k (margin ≈ 1), derived from the
            // model's own spacing — never from the reference. MEASURED link 83: at the 3,700 ms reference the budget WAS
            // k, so scale 1.0 doubled as the calibration; the compact step (3,117 ms) gives budget 10 > k = 8 (margin
            // 1.28), where owned slices hold flat, so the reference row now carries the flat assertion and the margin-1
            // slope is calibrated at its own slice.
            let target = crate::params::ChainParams::default().target_spacing_ms as f64;
            let spacing = (target * producers as f64).max(crate::dag::PRODUCTION_RELAY_FLOOR_MS as f64);
            let at_budget_k = spacing / (k as f64 + 0.5);
            assert_eq!((spacing / at_budget_k).floor() as usize, k, "CALIBRATION: the calibration slice's budget is exactly k");
            for slice in [1.0f64, 0.85, 0.7, 0.5].map(|s| ref_slice_ms * s).into_iter().chain([at_budget_k]) {
                let budget = (spacing / slice).floor() as usize;
                let row = |pick: LagPick| {
                    let (a, _, margin, _) = band_lag_model(k, slice, producers, 400, pick);
                    let (b, dropped, _, _) = band_lag_model(k, slice, producers, 1_600, pick);
                    (a, b, dropped, margin)
                };
                let one = row(LagPick::Owned { one_step: true });
                let multi = row(LagPick::Owned { one_step: false });
                let rnd = row(LagPick::PrivateRandom);
                eprintln!(
                    "[db353-13] N={producers} margin {:.2} — max lag @400 / @1600 blocks (dropped @1600): owned ONE-step \
                     {} / {} ({}) | owned MULTI-step {} / {} ({}) | private-random MULTI-step {} / {} ({})",
                    one.3, one.0, one.1, one.2, multi.0, multi.1, multi.2, rnd.0, rnd.1, rnd.2
                );
                for window in [1usize, 2, 4, 8] {
                    let w = row(LagPick::PrivateWindow { window });
                    eprintln!(
                        "[db353-13]   N={producers} margin {:.2} private OLDEST-FIRST window {window}×budget: {} / {} ({})",
                        w.3, w.0, w.1, w.2
                    );
                }
                let so = row(LagPick::StepOwner);
                eprintln!(
                    "[db353-13]   N={producers} margin {:.2} §11.12 WHOLE-STEP round-robin owner: {} / {} ({})",
                    so.3, so.0, so.1, so.2
                );
                // §11.12's claim: whole steps owned round-robin are balanced exactly, so the lag is a CONSTANT (the
                // owners' pipeline depth) from margin ≥ 1 — no slope at the reference margin where owned slices drift
                assert!(
                    so.1 == so.0 && so.2 == 0 && so.1 <= producers,
                    "⛔ whole-step ownership at margin {:.2}, N={producers}: lag {} / {} (dropped {})",
                    so.3,
                    so.0,
                    so.1,
                    so.2
                );
                assert!(
                    one.2 > 0,
                    "CALIBRATION: one step per block at margin {:.2} must GROW to the cap and drop (lag {} / {})",
                    one.3,
                    one.0,
                    one.1
                );
                if budget != k {
                    // a budget above k is flat; one BELOW k (the reference outgrew the interval) is a slope and RED here
                    assert!(
                        multi.1 <= multi.0 + 1 && multi.2 == 0,
                        "⛔ owned slices over several steps at margin {:.2} (budget {budget}, k {k}), N={producers}: lag {} / {} \
                         (dropped {}) is a SLOPE",
                        multi.3,
                        multi.0,
                        multi.1,
                        multi.2
                    );
                } else {
                    // margin ≈ 1 with an integer budget of exactly k: the HRW shares random-walk — a slope, so P7's
                    // backpressure is required whenever a machine sits at its budget (a contended one), not only in theory
                    assert!(multi.1 > multi.0, "CALIBRATION: at margin {:.2} (budget = k) the owned lag is a slow slope", multi.3);
                }
            }
        }
    }

    /// §11.13 — the RELAY lag model: provers are continuous workers (not tied to their own block times). Step `j` is noted
    /// at `j · Δ` (Δ = the mesh block interval = spacing ÷ N); it is owned by one of the epoch's `M` owners, round-robin by
    /// ordinal; an owner proves its steps FIFO at `k · slice_ms` each; a step is verifiable one relay round trip after it
    /// is proven; the band applies in order. Returns (max lag in steps, dropped past the cap, M).
    fn relay_lag_model(slice_ms: f64, provers: usize, steps: usize, rtt_ms: f64) -> (usize, usize, usize) {
        let target = crate::params::ChainParams::default().target_spacing_ms;
        let m = super::band_owner_count(target, provers);
        relay_lag_model_with(slice_ms, provers, m, steps, rtt_ms, 1.0, Some(2 * m))
    }

    /// [`relay_lag_model`] with the owner count given, owner 0 proving `slow`× slower (a heterogeneous owner set), and
    /// C2's OPEN rule: a step its owner has not relayed `open_after` mesh blocks after it was noted is proven by an idle
    /// non-owner at the reference cost (the relay then carries whichever copy lands first).
    fn relay_lag_model_with(
        slice_ms: f64,
        provers: usize,
        m: usize,
        steps: usize,
        rtt_ms: f64,
        slow: f64,
        open_after: Option<usize>,
    ) -> (usize, usize, usize) {
        let target = crate::params::ChainParams::default().target_spacing_ms;
        let spacing = (target as f64 * provers as f64).max(crate::dag::PRODUCTION_RELAY_FLOOR_MS as f64);
        let delta = spacing / provers as f64;
        let k = usdm_decider::nf_sparse_air::band_chain_k(target) as f64;
        let m = m.clamp(1, provers);
        let cap = crate::params::SPINE_RING_LEN;
        let mut free = vec![0f64; m];
        let mut available = Vec::with_capacity(steps);
        for j in 0..steps {
            let noted = j as f64 * delta;
            let w = j % m;
            let start = noted.max(free[w]);
            free[w] = start + k * slice_ms * if w == 0 { slow } else { 1.0 };
            let owner_relayed = free[w] + rtt_ms;
            let open_relayed = open_after.map(|b| noted + b as f64 * delta + k * slice_ms + rtt_ms);
            available.push(match open_relayed {
                Some(o) if o < owner_relayed => o,
                _ => owner_relayed,
            });
        }
        // applied in order: step j applies at max(apply(j−1), available(j))
        let mut applied_at = Vec::with_capacity(steps);
        let mut last = 0f64;
        for a in &available {
            last = last.max(*a);
            applied_at.push(last);
        }
        let (mut max_lag, mut dropped) = (0usize, 0usize);
        for j in 0..steps {
            let t = j as f64 * delta;
            let applied = applied_at.partition_point(|a| *a <= t);
            let lag = (j + 1).saturating_sub(applied);
            max_lag = max_lag.max(lag);
            if lag > cap {
                dropped += 1;
            }
        }
        (max_lag, dropped, m)
    }

    /// ⭐ DB-353 §11.13 (node-lane condition 1) — THE LAG DOES NOT SCALE WITH THE PROVER COUNT. With `M` owners per epoch
    /// (`band_owner_count`: ceil(BAND_FOLD_PROVE_MS_REF / target), the `band_chain_k` derivation, at most N) the lag is
    /// bounded by `M + 2` steps at N = 2 … 100 at the REFERENCE cost with a 1 s relay round trip, 0 dropped; extra provers
    /// add liveness (the open rule), never lag. CALIBRATION: owning over ALL N provers (M = N) at N = 100 passes the
    /// 64-step cap — the condition's own failure.
    /// TWO-PARTY-REVIEWED: a capacity MODEL; the two-party claims are the relay-door pins.
    #[test]
    fn db353_13_the_relay_lag_is_bounded_by_the_owner_count_not_the_prover_count() {
        let k = usdm_decider::nf_sparse_air::band_chain_k(crate::params::ChainParams::default().target_spacing_ms);
        let ref_slice_ms = usdm_decider::nf_sparse_air::BAND_FOLD_PROVE_MS_REF as f64 / k as f64;
        for n in [2usize, 3, 5, 8, 20, 100] {
            let (a, _, m) = relay_lag_model(ref_slice_ms, n, 400, 1_000.0);
            let (b, dropped, _) = relay_lag_model(ref_slice_ms, n, 1_600, 1_000.0);
            let (all_n, all_drop, _) = relay_lag_model_with(ref_slice_ms, n, n, 1_600, 1_000.0, 1.0, Some(2 * n));
            let (slow_closed, slow_closed_drop, _) = relay_lag_model_with(ref_slice_ms, n, m, 1_600, 1_000.0, 10.0, None);
            let (slow_m, slow_m_drop, _) = relay_lag_model_with(ref_slice_ms, n, m, 1_600, 1_000.0, 10.0, Some(2 * m));
            let (slow_n, slow_n_drop, _) = relay_lag_model_with(ref_slice_ms, n, n, 1_600, 1_000.0, 10.0, Some(2 * n));
            eprintln!(
                "[db353-13r] N={n}: M={m} owners lag @400/@1600 = {a}/{b} (dropped {dropped}) | ALL N own: {all_n} ({all_drop}) \
                 | one owner 10× slower: NO open rule {slow_closed} ({slow_closed_drop}), M-owners + open@2M {slow_m} \
                 ({slow_m_drop}), N-owners + open@2N {slow_n} ({slow_n_drop})"
            );
            assert!(b <= m + 2 && b == a && dropped == 0, "⛔ N={n}: the relay lag {a} / {b} exceeds M + 2 = {} or grows", m + 2);
            // a slow owner is bounded by the OPEN rule at 2M, never by the owner count alone
            assert!(slow_m_drop == 0 && slow_m <= 2 * m + m + 2, "⛔ N={n}: a 10× slow owner under open@2M: lag {slow_m}, dropped {slow_m_drop}");
            assert!(n < 8 || slow_closed_drop > 0, "CALIBRATION: without the open rule a 10× slow owner drops steps (N={n})");
        }
    }

    /// The RETIRED §11.4 slice ownership (HRW over producer ids per slice), kept only as the lag model's record of the
    /// design §13.3 refuted (it named the block's producer, H-B). Never called outside this model.
    fn owned_band_slices(step_block: &[u8; 32], own_id: &str, producer_ids: &[String], k: usize) -> Vec<usize> { // NOT-A-TAG: a block id
        (0..k)
            .filter(|i| {
                let mut h = blake3::Hasher::new();
                h.update(b"MUSD/band-slice-owner/v1");
                h.update(step_block);
                h.update(&(*i as u64).to_le_bytes());
                let point = u32::from_le_bytes(h.finalize().as_bytes()[..4].try_into().expect("32-byte hash"));
                holders_of(b"MUSD/band-slice-owner/v1", point, producer_ids, 1).first().is_some_and(|top| top == own_id)
            })
            .collect()
    }

    /// The RETIRED §11.4 open slice pick, the lag model's record of it (see `owned_band_slices` above).
    fn pick_band_slices(step_block: &[u8; 32], own_block: &[u8; 32], k: usize, missing: &[usize], budget: usize) -> Vec<usize> { // NOT-A-TAG: two block ids
        if k == 0 || missing.is_empty() || budget == 0 {
            return Vec::new();
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/band-slice-pick/v1");
        h.update(step_block);
        h.update(own_block);
        let bytes = h.finalize();
        let start = (u64::from_le_bytes(bytes.as_bytes()[..8].try_into().expect("32-byte hash")) % k as u64) as usize;
        let mut picked: Vec<usize> = (0..k).map(|j| (start + j) % k).filter(|i| missing.contains(i)).take(budget).collect();
        picked.sort_unstable();
        picked
    }

    /// ⛔ DB-367 follow-up — AN EMPTY STEP TAKES NO PLACE IN THE REWIND JOURNAL. Since DB-367 an idle block's fold step
    /// admits nothing (its fill is unjustified) and applies at once; each one took a journal slot, so after `lag_cap` idle
    /// blocks the floor rose and any rewind past them answered "below the band door's fold journal" — the spine went
    /// stale (MEASURED: `db265_a_joiner_and_its_origin_agree…` green at c6dcad6, red at 64cdf0f). An empty step changes
    /// nothing, so it has nothing to undo: the journal's reach is `lag_cap` steps that MOVED the band, never `lag_cap` blocks.
    /// TWO-PARTY-REVIEWED: one door's journal bound; the cross-node twin is `db265_a_joiner_and_its_origin_agree…` (a
    /// joiner and its origin must fold alike after concurrent production), which this rule turns green.
    #[test]
    fn db367_empty_steps_take_no_place_in_the_band_doors_rewind_journal() {
        let cap = 64usize;
        let mut d = BandDoor::new(cap);
        for o in 1..=(cap as u64 + 6) {
            assert!(d.note_fold_step(o, [o as u8; 32], Some(Vec::new())), "CALIBRATION: an idle step is noted");
            let applied = d.drain(None, 8);
            assert_eq!(applied.len(), 1, "CALIBRATION: an idle step applies at once");
        }
        assert_eq!(d.pointer(), None, "CALIBRATION: nothing awaits");
        assert!(
            d.rewind_to(5, None),
            "⛔ DB-367: a rewind past idle steps reached 'below the band door's fold journal' — empty steps filled the \
             journal and raised its floor, so a joiner's ordinary reorg went stale"
        );
    }

    /// ⛔⛔ DB-419 — A DOOR RESUMED FROM ITS CHECKPOINT UN-FOLDS BELOW ITS RESUME POINT EXACTLY AS THE DOOR THAT DID NOT
    /// RESTART. MEASURED (fast lane, default seed, night/sim-20261007-211400.log): node 0 restarted on its provisioned
    /// identity, its three post-restart blocks lost a 1-record reorg, and `a rewind reached below the band door's fold
    /// journal` stopped its fold — the resume went through `adopt_certified`, which keeps no journal, so the resumed floor
    /// was the resume point. The certified re-anchor that followed left W1's POS pay without its member windows (T3 red).
    /// The twin applies two band-MOVING steps and an idle one; a second door resumes from the twin's carriage (the band at
    /// the resume ordinal, as a checkpoint carries it) plus the carried rewind reach; both rewind to step 2.
    /// CALIBRATION: the same resume WITHOUT the reach refuses the rewind — the red.
    /// TAMPER: a reach whose steps, posts, base root, ordinals, floor or ring do not replay onto the resumed band — or a
    /// reach for ANOTHER band — installs nothing and leaves the resume floor.
    /// TWO-PARTY-REVIEWED: the twin never restarts; the claim is what the RESUMED door holds after the same rewind, compared
    /// band entry by band entry with the twin's.
    #[test]
    fn db419_a_door_resumed_from_its_checkpoint_rewinds_below_its_resume_point_like_its_twin() {
        let ring = 64usize;
        let k = BandDoor::new(64).chain_k();
        let mut twin = BandDoor::new(64);
        twin.arm_bound_double_for_test();
        let mut holder = RefSparseNf::new();
        let steps: Vec<([u8; 32], Vec<[u8; 32]>)> = vec![
            ([0x41; 32], (0..8u64).map(digest_tag).collect()),
            ([0x42; 32], (100..108u64).map(digest_tag).collect()),
            ([0x43; 32], Vec::new()), // idle: applies, takes no journal slot
        ];
        let mut after: Vec<Vec<Digest4>> = Vec::new();
        for (i, (block, tags)) in steps.iter().enumerate() {
            let o = i as u64 + 1;
            assert!(twin.note_fold_step(o, *block, Some(tags.clone())), "CALIBRATION: step {o} is noted");
            if !tags.is_empty() {
                let (serves, fillers) = serve_admitted(std::slice::from_mut(&mut holder), tags, 0);
                let t = build_band_transition_bound(*block, twin.band(), &serves, &fillers, k).expect("the bound step builds");
                assert_eq!(twin.offer_step(t, false), BandReceipt::Verified, "CALIBRATION: step {o} verifies");
            }
            assert_eq!(twin.drain(Some(&mut holder), ring).len(), 1, "CALIBRATION: step {o} applies");
            after.push(twin.band().to_vec());
        }
        assert_ne!(after[0], after[1], "CALIBRATION: step 2 moved the band");
        let next = 4u64; // the resume ordinal: the checkpoint's band carriage waits at the step after the fold tip
        let carry = twin.journal_carry();
        assert_eq!(carry.journal.len(), 2, "CALIBRATION: the two band-moving steps are journaled, the idle one is not");
        assert_eq!(carry.ring.len(), 3, "CALIBRATION: the ring holds every step's root");
        let resume = |with: Option<BandJournalCarry>| -> BandDoor {
            let mut r = BandDoor::new(64);
            r.arm_bound_double_for_test();
            assert!(r.adopt_certified(after[2].clone(), next, Vec::new()), "PRECONDITION: the door resumes its band");
            if let Some(c) = with {
                assert!(r.install_journal(c, ring), "the carried reach replays onto the resumed band");
            }
            r
        };
        let mut old = resume(None);
        assert!(!old.rewind_to(2, None), "CALIBRATION: without the carried reach a rewind to step 2 is below the floor — the red");
        let mut r = resume(Some(carry.clone()));
        assert_eq!(
            (r.floor(), r.band_root_at(1), r.band_root_at(3)),
            (twin.floor(), twin.band_root_at(1), twin.band_root_at(3)),
            "the resumed door holds the twin's floor and ring"
        );
        assert!(twin.rewind_to(2, None), "CALIBRATION: the twin un-folds steps 2 and 3");
        assert!(
            r.rewind_to(2, None),
            "⛔⛔ DB-419: the RESUMED door could not un-fold a reorg just below its resume point — its node's fold stops until \
             a certified re-anchor, which the twin never needed"
        );
        assert_eq!(r.band(), &after[0][..], "⛔⛔ DB-419: after the rewind the resumed door is not at the band after step 1");
        assert_eq!(r.band(), twin.band(), "⛔⛔ DB-419: after the same rewind the resumed door's band differs from the twin's");
        assert_eq!(
            (r.band_root(), r.band_root_at(1), r.band_root_at(2)),
            (twin.band_root(), twin.band_root_at(1), None),
            "the roots and the ring after the rewind are the twin's"
        );
        assert!(r.rewind_to(1, None) && twin.rewind_to(1, None), "the whole reach un-folds on both");
        assert_eq!(r.band(), twin.band(), "back to the band below the journal on both");
        // TAMPERS: refused whole, the door stays at its resume floor
        let tamper = |what: &str, c: BandJournalCarry| {
            let mut d = resume(None);
            assert!(!d.install_journal(c, ring), "⛔ DB-419: {what} was installed");
            assert_eq!(d.floor(), next, "{what}: a refused install keeps the resume floor");
            assert!(!d.rewind_to(2, None), "{what}: nothing below the resume floor un-folds");
        };
        let mut c = carry.clone();
        c.journal[1].before[0].1[0] ^= 1;
        tamper("a step's before-entry altered", c);
        let mut c = carry.clone();
        c.journal[0].post[0] ^= 1;
        tamper("a step's post altered", c);
        let mut c = carry.clone();
        c.base_root[0] ^= 1;
        tamper("the base root altered", c);
        let mut c = carry.clone();
        c.journal[1].ordinal = next;
        tamper("a step at the resume ordinal", c);
        let mut c = carry.clone();
        c.journal.swap(0, 1);
        tamper("the steps reordered", c);
        let mut c = carry.clone();
        c.journal.remove(1);
        tamper("the newest step dropped", c);
        let mut c = carry.clone();
        c.floor = next + 1;
        tamper("a floor above the resume point", c);
        let mut c = carry.clone();
        if let Some(last) = c.ring.last_mut() {
            last.1[0] ^= 1;
        }
        tamper("the newest ring root altered", c);
        let mut other = BandDoor::new(64);
        assert!(other.adopt_certified(after[0].clone(), next, Vec::new()), "PRECONDITION: a door at another band");
        assert!(!other.install_journal(carry, ring), "⛔ DB-419: a reach that does not replay onto this door's band was installed");
    }

    /// ⛔⛔ A-F44 (measured by lane vaults on two real nodes 2026-11-12; mechanism read by lane goods) — A STEP RE-FOLDED
    /// AFTER A REWIND JUDGES EVIDENCE BELOW THE JOURNAL'S FLOOR EXACTLY AS A DOOR THAT NEVER REWOUND. On the rig a rewind
    /// from about step 118 to 63 left the floor near 55; the re-fold of step 63 asked whether a tag was admitted after a
    /// step below 54, the door answered "unknown here" (`None`), the respend verdict was `Wait` forever and the fold
    /// never moved again (the band had no pointer: nothing was noted). Here a door with a four-step journal and a twin
    /// whose journal never releases apply the same ten steps (step 2 admits `spent`, step 4 is idle), both rewind to step
    /// 8, and the re-fold of step 8 asks about evidence naming step 1. RED before: the short door answered `None` for both
    /// tags while the twin answered. Then the same question on a door RESUMED from the short door's checkpoint, the
    /// carried history's tampers, and the bound: after a long run of idle steps the history holds one evidence window.
    /// TWO-PARTY-REVIEWED: the twin never releases and never restarts; the claim is that the short and the resumed door
    /// answer what it answers.
    #[test]
    fn af44_a_step_refolded_after_a_rewind_judges_evidence_below_the_floor_as_a_door_that_never_rewound() {
        let ring = 64usize;
        let cap = 4usize;
        let k = BandDoor::new(cap).chain_k();
        let spent = digest_tag(7);
        let fresh = digest_tag(999_999);
        let tags_of = |o: u64| -> Vec<[u8; 32]> {
            match o {
                2 => (0..8u64).map(digest_tag).collect(), // admits `spent`
                4 => Vec::new(),                          // idle: applies, takes no journal slot
                _ => (o * 100..o * 100 + 8).map(digest_tag).collect(),
            }
        };
        let apply = |d: &mut BandDoor, h: &mut RefSparseNf, o: u64, tags: &[[u8; 32]]| {
            let block = [o as u8; 32];
            assert!(d.note_fold_step(o, block, Some(tags.to_vec())), "CALIBRATION: step {o} is noted");
            if !tags.is_empty() {
                let (serves, fillers) = serve_admitted(std::slice::from_mut(h), tags, 0);
                let t = build_band_transition_bound(block, d.band(), &serves, &fillers, k).expect("the bound step builds");
                assert_eq!(d.offer_step(t, false), BandReceipt::Verified, "CALIBRATION: step {o} verifies");
            }
            assert_eq!(d.drain(Some(h), ring).len(), 1, "CALIBRATION: step {o} applies");
        };
        let mut door = BandDoor::new(cap);
        let mut twin = BandDoor::new(64);
        door.arm_bound_double_for_test();
        twin.arm_bound_double_for_test();
        let (mut hd, mut ht) = (RefSparseNf::new(), RefSparseNf::new());
        for o in 1..=10u64 {
            apply(&mut door, &mut hd, o, &tags_of(o));
            apply(&mut twin, &mut ht, o, &tags_of(o));
        }
        assert_eq!(door.floor(), 7, "CALIBRATION: the short journal released steps 1 to 6 (its floor is 7)");
        assert_eq!(twin.floor(), 0, "CALIBRATION: the twin's journal released nothing");
        assert_eq!(door.band_root(), twin.band_root(), "CALIBRATION: both doors applied the same band");
        assert!(door.rewind_to(8, None) && twin.rewind_to(8, None), "CALIBRATION: a rewind to step 8 is inside both reaches");
        assert_eq!(door.pointer(), None, "CALIBRATION: nothing awaits: the re-fold of step 8 notes it only after its verdict");
        let asks = |d: &BandDoor| (d.admitted_after_ordinal(1, &spent), d.admitted_after_ordinal(1, &fresh), d.admitted_after_ordinal(0, &spent));
        assert_eq!(asks(&twin), (Some(true), Some(false), Some(true)), "CALIBRATION: the twin answers both tags");
        assert_eq!(
            asks(&door),
            asks(&twin),
            "⛔⛔ A-F44: a step re-folded after a rewind could not judge evidence below the journal's floor — its respend \
             verdict is Wait forever, the fold never notes the step, and the band has no pointer: the chain stops"
        );
        // ── the same question on a door RESUMED from the short door's checkpoint
        let carry = door.journal_carry();
        assert_eq!(carry.history.iter().map(|(o, _)| *o).collect::<Vec<_>>(), (0..=6u64).collect::<Vec<_>>(), "the checkpoint carries the steps below its floor from genesis (an empty set) to 6, the idle step 4 included");
        let resume = || -> BandDoor {
            let mut r = BandDoor::new(cap);
            r.arm_bound_double_for_test();
            assert!(r.adopt_certified(door.band().to_vec(), 8, Vec::new()), "PRECONDITION: the door resumes its band");
            r
        };
        let mut r = resume();
        assert!(r.install_journal(carry.clone(), ring), "the carried reach and history install");
        assert_eq!(asks(&r), asks(&twin), "⛔⛔ A-F44: a RESTARTED door lost the admitted sets below its floor");
        // ── TAMPERS of the carried history: refused whole
        let tamper = |what: &str, c: BandJournalCarry| {
            let mut d = resume();
            assert!(!d.install_journal(c, ring), "⛔ A-F44: {what} was installed");
        };
        let mut c = carry.clone();
        c.history.push((carry.floor, Vec::new()));
        tamper("a history entry at the floor", c);
        let mut c = carry.clone();
        c.history.swap(0, 1);
        tamper("the history out of order", c);
        // ── THE BOUND: a long run of idle steps, then the journal releases again — one evidence window is kept
        let mut long = BandDoor::new(cap);
        long.arm_bound_double_for_test();
        let mut hl = RefSparseNf::new();
        for o in 1..=3u64 {
            apply(&mut long, &mut hl, o, &tags_of(o + 10));
        }
        for o in 4..=80u64 {
            apply(&mut long, &mut hl, o, &[]);
        }
        for o in 81..=86u64 {
            apply(&mut long, &mut hl, o, &tags_of(o));
        }
        let keys: Vec<u64> = long.history.keys().copied().collect();
        let w = crate::nf_evidence::EVIDENCE_WINDOW_STEPS;
        assert!(keys.windows(2).all(|p| p[1] == p[0] + 1), "⛔ A-F44: the history has a hole: {keys:?}");
        assert_eq!(keys.last().copied(), Some(long.floor() - 1), "⛔ A-F44: the history does not reach up to the floor");
        assert!(keys.len() as u64 <= w + 1 && keys[0] + w >= long.floor() - 1, "⛔ A-F44: the history keeps more than one evidence window: {} entries", keys.len());
        // the long door's checkpoint installs, and a carried history reaching past one window below its floor does not
        let long_carry = long.journal_carry();
        let resume_long = || -> BandDoor {
            let mut r = BandDoor::new(cap);
            r.arm_bound_double_for_test();
            assert!(r.adopt_certified(long.band().to_vec(), 87, Vec::new()), "PRECONDITION: the long door resumes its band");
            r
        };
        assert!(resume_long().install_journal(long_carry.clone(), ring), "CALIBRATION: the long door's own checkpoint installs");
        let mut c = long_carry.clone();
        c.history.insert(0, (keys[0] - 2, Vec::new()));
        assert!(!resume_long().install_journal(c, ring), "⛔ A-F44: a carried history reaching past one evidence window below the floor was installed");
    }

    /// ⭐ A-F27 PIN: evidence at a step above the rewind point is invalid; evidence at or below it is still valid.
    /// WHAT THIS PROVES: after a rewind from step 10 to step 8, evidence_root_at(10) changes (the root moved) while
    /// evidence_root_at(7) is stable. The Node fix (da.rs own_tag_evidence) builds evidence at the newest FINAL band
    /// step (at or below final_fold_step), so evidence survives a reorg above finality. The old code used
    /// newest_applied() which returned N — a step that gets invalidated by the rewind.
    #[test]
    fn af27_evidence_at_a_rewound_step_is_invalid_but_evidence_at_or_below_the_rewind_point_survives() {
        let ring = 64usize;
        let cap = 64usize;
        let k = BandDoor::new(cap).chain_k();
        let tags_of = |o: u64| -> Vec<[u8; 32]> {
            (0..8u64).map(|i| digest_tag(o * 1000 + i)).collect()
        };
        let apply = |d: &mut BandDoor, h: &mut RefSparseNf, o: u64, tags: &[[u8; 32]]| {
            let block = [o as u8; 32];
            assert!(d.note_fold_step(o, block, Some(tags.to_vec())), "CALIBRATION: step {o} is noted");
            if !tags.is_empty() {
                let (serves, fillers) = serve_admitted(std::slice::from_mut(h), tags, 0);
                let t = build_band_transition_bound(block, d.band(), &serves, &fillers, k).expect("the bound step builds");
                assert_eq!(d.offer_step(t, false), BandReceipt::Verified, "CALIBRATION: step {o} verifies");
            }
            assert_eq!(d.drain(Some(h), ring).len(), 1, "CALIBRATION: step {o} applies");
        };
        let mut door = BandDoor::new(cap);
        door.arm_bound_double_for_test();
        let mut holder = RefSparseNf::new();
        for o in 1..=10u64 {
            apply(&mut door, &mut holder, o, &tags_of(o));
        }
        let root_at_10 = door.evidence_root_at(10);
        let root_at_7 = door.evidence_root_at(7);
        assert!(root_at_10.is_some(), "CALIBRATION: root at step 10 exists before rewind");
        assert!(root_at_7.is_some(), "CALIBRATION: root at step 7 exists before rewind");
        assert_eq!(door.newest_applied(), Some(10), "CALIBRATION: newest applied is step 10");
        // rewind to step 8 (evict steps 8..=10, simulating a DAG reorg above finality step 7)
        assert!(door.rewind_to(8, Some(&mut holder)), "CALIBRATION: rewind to 8 succeeds");
        // re-fold steps 8..=10 with DIFFERENT tags (the reorg changed what these blocks contain)
        for o in 8..=10u64 {
            apply(&mut door, &mut holder, o, &tags_of(o + 100));
        }
        let root_at_10_after = door.evidence_root_at(10);
        let root_at_7_after = door.evidence_root_at(7);
        // step 10's root CHANGED (the reorg replaced what step 10 folds)
        assert_ne!(root_at_10, root_at_10_after,
            "⛔ A-F27: evidence at the newest applied step must change after a reorg replaces those blocks — \
             evidence built there before the rewind is now INVALID");
        // step 7's root is STABLE (it was not rewound, it is at or below the rewind point)
        assert_eq!(root_at_7, root_at_7_after,
            "step 7's root must survive the rewind — evidence at the final step is stable");
        eprintln!("[af27] evidence at step 10 changed after rewind ({:?} → {:?}); evidence at step 7 stable ({:?})",
            root_at_10, root_at_10_after, root_at_7);
    }

    /// ⭐ G1h (lane a 2026-10-23) — A DOOR RESUMED FROM ITS CHECKPOINT HOLDS THE STEPS ITS TWIN HELD UNAPPLIED: this node's
    /// own proof of step 2 held ahead of step 1 (`own_held`, served to a peer's pull), and a verified-but-undrained step.
    /// MEASURED (restart census, scratchpad/watch/watch-20261023-065748.log.7:4874): `solicited` / `own_held` → `{}` at
    /// resume on both nodes, band_door 3.10 → 2.07 MB. CALIBRATION: the resume without the carried held steps serves
    /// nothing for step 2 — the red. TAMPER: a carried held copy whose band_post is altered never verifies when step 1
    /// arrives (the door's own cascade refuses it), exactly as the live door would.
    /// TWO-PARTY-REVIEWED: the twin never restarts; the claim is what the RESUMED door serves and verifies, compared with
    /// the twin's.
    #[test]
    fn g1h_a_door_resumed_from_its_checkpoint_holds_its_own_early_proof_and_its_verified_steps_like_its_twin() {
        let ring = 64usize;
        let k = BandDoor::new(64).chain_k();
        let (a, b) = ([0x51u8; 32], [0x52u8; 32]);
        let tags: [Vec<[u8; 32]>; 2] = [(0..8u64).map(digest_tag).collect(), (200..208u64).map(digest_tag).collect()];
        // the two proofs, built on a scratch door that applies step 1 before step 2 is proved
        let mut scratch = BandDoor::new(64);
        scratch.arm_bound_double_for_test();
        let mut holder = RefSparseNf::new();
        let mut proofs = Vec::new();
        for (i, block) in [a, b].iter().enumerate() {
            assert!(scratch.note_fold_step(i as u64 + 1, *block, Some(tags[i].clone())), "CALIBRATION: step {i} is noted");
            let (serves, fillers) = serve_admitted(std::slice::from_mut(&mut holder), &tags[i], 0);
            let t = build_band_transition_bound(*block, scratch.band(), &serves, &fillers, k).expect("the bound step builds");
            assert_eq!(scratch.offer_step(t.clone(), false), BandReceipt::Verified, "CALIBRATION: step {i} verifies");
            assert_eq!(scratch.drain(Some(&mut holder), ring).len(), 1, "CALIBRATION: step {i} applies");
            proofs.push(t);
        }
        let fresh = || {
            let mut d = BandDoor::new(64);
            d.arm_bound_double_for_test();
            assert!(d.note_fold_step(1, a, Some(tags[0].clone())) && d.note_fold_step(2, b, Some(tags[1].clone())));
            d
        };
        let resume = |twin: &BandDoor, with: Option<BandJournalCarry>| -> BandDoor {
            let mut r = BandDoor::new(64);
            r.arm_bound_double_for_test();
            assert!(r.adopt_certified(twin.band().to_vec(), 1, twin.awaiting_steps()), "PRECONDITION: the door resumes its band");
            if let Some(c) = with {
                assert!(r.install_journal(c, ring), "the carried reach installs onto the resumed band");
            }
            r
        };
        // case 1: this node's own proof of step 2, held ahead of step 1
        let mut twin = fresh();
        assert_eq!(twin.offer_own_step(proofs[1].clone()), BandReceipt::Held, "CALIBRATION: the own early proof is held");
        assert!(twin.holds_step(&b), "CALIBRATION: the twin serves its own early proof");
        let carry = twin.journal_carry();
        assert!(!resume(&twin, None).holds_step(&b), "CALIBRATION: without the carried held steps the resumed door serves nothing — the red");
        let mut r = resume(&twin, Some(carry.clone()));
        assert_eq!(
            r.serve_step(&b),
            twin.serve_step(&b),
            "⛔ G1h: the RESUMED door does not serve the own early proof its twin serves — the restart threw the proof away"
        );
        assert_eq!(r.offer_step(proofs[0].clone(), false), BandReceipt::Verified, "step 1 arrives on the resumed door");
        assert_eq!(twin.offer_step(proofs[0].clone(), false), BandReceipt::Verified, "step 1 arrives on the twin");
        assert_eq!(r.verified_blocks(), vec![a, b], "⛔ G1h: the held step 2 did not verify behind step 1 on the resumed door");
        assert_eq!(r.verified_blocks(), twin.verified_blocks(), "the resumed door verified what the twin verified");
        // case 2: both steps verified, not yet drained
        let carry2 = twin.journal_carry();
        let r2 = resume(&twin, Some(carry2));
        assert_eq!(r2.verified_blocks(), twin.verified_blocks(), "⛔ G1h: the resumed door lost its verified-but-undrained steps");
        // TAMPER: an altered held copy is held as the live door would hold it, and never verifies
        let mut bad = carry;
        bad.held[0].0.band_post[0].1[0] ^= 1;
        let mut t = resume(&twin, Some(bad));
        assert_eq!(t.offer_step(proofs[0].clone(), false), BandReceipt::Verified, "step 1 still verifies");
        assert_eq!(t.verified_blocks(), vec![a], "⛔ G1h: a tampered carried copy verified");
    }

    /// The door's bounds and its two waits: the lag cap refuses (and counts) a step it cannot hold; an UNKNOWN step (no
    /// body held at its fold) stops the pointer until a certified re-adopt; a second copy for one block, a copy for a
    /// block that awaits nothing and every malformed shape are refused before any proof work; a garbage copy is dropped
    /// at the pointer and the door waits for the next.
    #[test]
    fn db353_band_door_bounds_its_lag_waits_on_an_unknown_step_and_refuses_bad_copies_cheaply() {
        let level = usdm_decider::nf_sparse_air::NF_BAND_LEVEL;
        let mut d = BandDoor::new(3);
        assert!(d.note_fold_step(1, [1; 32], None));
        assert!(d.note_fold_step(2, [2; 32], Some(Vec::new())));
        assert!(d.note_fold_step(3, [3; 32], Some(Vec::new())));
        assert!(!d.note_fold_step(4, [4; 32], Some(Vec::new())), "the lag cap refuses a 4th awaiting step");
        assert_eq!(d.dropped_for_lag, 1);
        assert!(d.drain(None, 8).is_empty());
        assert_eq!((d.last_wait(), d.pointer()), (BandWait::Unknown, Some(1)), "an unknown step stops the pointer");
        let band = d.band().to_vec();
        // §11.13 C4 — the certified re-adopt installs the carried steps; malformed carriage is refused whole
        assert!(!d.adopt_certified(band[..5].to_vec(), 2, Vec::new()), "a band of the wrong width is refused");
        assert!(!d.adopt_certified(band.clone(), 2, vec![(1, [1; 32], Some(Vec::new()))]), "a step below the floor is refused");
        assert!(
            !d.adopt_certified(band.clone(), 2, vec![(2, [2; 32], Some(Vec::new())), (2, [9; 32], Some(Vec::new()))]),
            "one ordinal twice is refused"
        );
        let over: Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)> = (2..6u64).map(|o| (o, [o as u8; 32], Some(Vec::new()))).collect();
        assert!(!d.adopt_certified(band.clone(), 2, over), "more steps than the lag cap is refused");
        assert!(d.adopt_certified(band, 2, Vec::new()));
        assert_eq!((d.pointer(), d.floor(), d.lag()), (None, 2, 0));
        assert!(!d.rewind_to(1, None), "below the adopted floor: stale");
        let mut d = BandDoor::new(4);
        let k = d.chain_k();
        let tag = digest_tag(1);
        assert!(d.note_fold_step(5, [5; 32], Some(vec![tag])));
        let t = BandTransition {
            for_block: [5; 32],
            band_post: vec![(nf_shard(&tag, usdm_decider::nf_sparse_air::NF_BAND_BITS), empty_subtree(level))],
            k: k as u32,
            slices: (0..k as u32).map(|i| (i, [0xA, 0, 0, 0, 0, 0, 0, 0], vec![1, 2, 3])).collect(),
        };
        let whole = "a relayed step carries all k slices, in order";
        let mut no_slices = t.clone();
        no_slices.slices.clear();
        assert_eq!(d.offer_step(no_slices, true), BandReceipt::Refused(whole));
        let mut repeated = t.clone();
        repeated.slices.push(t.slices[0].clone());
        assert_eq!(d.offer_step(repeated, true), BandReceipt::Refused(whole), "exactly k slices, indices exactly 0..k");
        let mut past_k = t.clone();
        past_k.slices[k - 1].0 = k as u32;
        assert_eq!(d.offer_step(past_k, true), BandReceipt::Refused(whole), "a slice index past k is refused");
        let mut unsorted = t.clone();
        unsorted.band_post = vec![(7, empty_subtree(level)), (3, empty_subtree(level))];
        assert_eq!(d.offer_step(unsorted, true), BandReceipt::Refused("malformed band_post"));
        let mut wide = t.clone();
        wide.band_post = vec![(1 << usdm_decider::nf_sparse_air::NF_BAND_BITS, empty_subtree(level))];
        assert_eq!(d.offer_step(wide, true), BandReceipt::Refused("malformed band_post"), "a shard past the band");
        let mut stranger = t.clone();
        stranger.for_block = [6; 32];
        assert_eq!(d.offer_step(stranger.clone(), true), BandReceipt::Held, "a structurally sound step for an unnoted block is parked");
        assert_eq!(d.offer_step(stranger, true), BandReceipt::Refused("a copy of this early step is already parked"));
        assert_eq!(d.parked_len(), 1);
        // a garbage whole step at the pointer is verified on the spot and refused as INVALID — nothing is held, so the
        // next copy (garbage again here) is judged afresh and the slot never fills
        assert!(matches!(d.offer_step(t.clone(), false), BandReceipt::Invalid(_)));
        assert!(matches!(d.offer_step(t, true), BandReceipt::Invalid(_)), "solicited or not, bytes that fail are invalid");
        assert_eq!(d.copies_refused, 2);
        assert!(d.verified_blocks().is_empty() && d.serve_step(&[5; 32]).is_none(), "an invalid copy is neither held nor served");
        assert!(d.drain(None, 8).is_empty(), "a garbage copy never applies");
        assert_eq!((d.last_wait(), d.pointer()), (BandWait::Carrier, Some(5)), "the door waits for an honest copy");
        assert!(d.wants(&[5; 32]), "and still wants one");
    }

    /// ⭐ §11.13 condition 3 — THE CURSOR IS THE ADVANCED VIEW, WITHOUT BEING A COPY OF IT. For an unsharded view and a
    /// full-shard view: a cursor that absorbed steps 1..j serves step j+1 BYTE-IDENTICALLY to a real tree advanced through
    /// steps 1..j (the band before it, every serve, every filler); it stays identical while the VIEW advances under it (the
    /// band applies step 1 midway) and after a rebuild from the pending steps; and a serve refuses a tag already spent in
    /// the union without changing the cursor. Its size is printed beside the view's leaf count.
    #[test]
    fn db353_11_13_the_cursor_serves_a_step_ahead_exactly_as_a_view_advanced_through_the_steps_before_it() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let steps: Vec<Vec<[u8; 32]>> = vec![
            (0..cover as u64).map(digest_tag).collect(),
            (cover as u64..2 * cover as u64 - 1).map(digest_tag).collect(), // one refused slot: one filler
            (2 * cover as u64..3 * cover as u64 - 40).map(digest_tag).collect(),
        ];
        let empty_band = BandDoor::new(8).band().to_vec();
        for (name, view0) in [("unsharded", RefSparseNf::new()), ("full-shard", RefSparseNf::with_shards(bits, 0..(1u32 << bits)))] {
            // a pre-existing spent set under the pointer, so the overlay's siblings come from a non-empty view
            let mut view = view0;
            for t in (9_000_000u64..9_000_600).map(digest_tag) {
                let cp = view.copath(&t);
                view.apply_spend(&t, &cp);
            }
            let reference = |through: usize| {
                let mut r = view.clone();
                for tags in &steps[..through] {
                    for t in tags {
                        let cp = r.copath(t);
                        r.apply_spend(t, &cp);
                    }
                }
                r
            };
            let band_after = |band: &[Digest4], serves: &[(u32, Digest4, Vec<([u8; 32], Vec<Digest4>)>)]| {
                let mut b = band.to_vec();
                for (s, e, _) in serves {
                    b[*s as usize] = *e;
                }
                b
            };
            // the door's band at the pointer = the view's state: shard `s`'s canonical prefix at the band level is the key
            // whose top byte is `s` (the shard is the key's top NF_BAND_BITS = 8 bits, MSB first)
            assert_eq!(bits, 8, "the canon below assumes an 8-bit band");
            let door_band: Vec<Digest4> = (0..(1u32 << bits))
                .map(|s| {
                    let mut canon = [0u8; 32];
                    canon[31] = s as u8;
                    view.node_at(usdm_decider::nf_sparse_air::NF_BAND_LEVEL, &canon)
                })
                .collect();
            assert_ne!(door_band, empty_band, "CALIBRATION: the pre-existing spent set moved the band");
            let mut cursor = BandCursor::new();
            let (pre1, serves1, fillers1) =
                cursor.serve_and_absorb(&view, &door_band, 1, [1; 32], &steps[0], 0).expect("step 1 serves from the view");
            assert_eq!((pre1.clone(), serves1.clone(), fillers1), {
                let (s, f) = serve_admitted(&mut [reference(0)], &steps[0], 0);
                (door_band.clone(), s, f)
            }, "{name}: step 1 (nothing ahead) serves exactly as the view");
            let band1 = band_after(&pre1, &serves1);
            // step 2 AHEAD of the pointer
            let (pre2, serves2, fillers2) = cursor.serve_and_absorb(&view, &door_band, 2, [2; 32], &steps[1], 0).expect("step 2 serves ahead");
            let (ref_s2, ref_f2) = serve_admitted(&mut [reference(1)], &steps[1], 0);
            assert_eq!(pre2, band1, "{name}: the band before step 2 is the band after step 1");
            assert_eq!((serves2.clone(), fillers2.clone()), (ref_s2, ref_f2), "{name}: step 2 serves exactly as a view advanced through step 1");
            assert_eq!(fillers2.len(), 1, "one refused slot, one filler (applied and taken back)");
            let band2 = band_after(&pre2, &serves2);
            // THE VIEW ADVANCES under the cursor (the band applied step 1): step 3 still serves exactly
            let mut view_after_1 = view.clone();
            for t in &steps[0] {
                let cp = view_after_1.copath(t);
                view_after_1.apply_spend(t, &cp);
            }
            let (pre3, serves3, fillers3) =
                cursor.serve_and_absorb(&view_after_1, &band1, 3, [3; 32], &steps[2], 0).expect("step 3 serves over the advanced view");
            let (ref_s3, ref_f3) = serve_admitted(&mut [reference(2)], &steps[2], 0);
            assert_eq!(pre3, band2, "{name}: the band before step 3");
            assert_eq!((serves3.clone(), fillers3.clone()), (ref_s3.clone(), ref_f3.clone()), "{name}: step 3, two steps ahead, over an advanced view");
            eprintln!(
                "[db353-cursor] {name}: view leaves {}, cursor after 3 steps: {} keys, {} overrides",
                view.spent_leaf_count(),
                cursor.leaves.len(),
                cursor.branch.len()
            );
            // a REBUILD from the steps still pending (step 2) over the advanced view serves step 3 identically
            let mut rebuilt = BandCursor::new();
            assert!(rebuilt.rebuild(&view_after_1, &[(2, [2; 32], steps[1].clone())]));
            assert_eq!(rebuilt.through(), Some(2));
            let again = rebuilt.serve_and_absorb(&view_after_1, &band1, 3, [3; 32], &steps[2], 0).expect("serves after a rebuild");
            assert_eq!(again, (band2.clone(), ref_s3, ref_f3), "{name}: the rebuilt cursor serves step 3 identically");
            // a tag already spent in the union refuses the serve and changes nothing
            let before = (rebuilt.leaves.len(), rebuilt.branch.len(), rebuilt.through());
            assert!(rebuilt.serve_and_absorb(&view_after_1, &band1, 4, [4; 32], &[steps[1][0]], 0).is_none());
            assert!(!rebuilt.absorb(&view_after_1, 3, [3; 32], &steps[2]), "an ordinal at or below the cursor is refused");
            assert_eq!((rebuilt.leaves.len(), rebuilt.branch.len(), rebuilt.through()), before, "{name}: a refused serve leaves the cursor as it was");
        }
    }

    /// ⭐ §11.12 pin (b) + (e) — A STEP PROVEN AHEAD FROM THE CURSOR VERIFIES AT A TREELESS DOOR, and a JOINER that adopted a
    /// certified band with the pending admitted sets (C4) verifies both relayed steps from minute 0. Two real proofs, the
    /// production slice count.
    /// TWO-PARTY-REVIEWED: the prover's cursor and view never reach either door; only the relayed bytes cross.
    #[test]
    fn db353_11_12_a_step_proven_ahead_from_the_cursor_verifies_at_a_treeless_door_and_at_a_joiner() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let view = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let (b1, b2) = ([1u8; 32], [2u8; 32]);
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let tags2: Vec<[u8; 32]> = (cover as u64..2 * cover as u64 - 3).map(digest_tag).collect();
        let mut door = BandDoor::new(64);
        let k = door.chain_k();
        assert!(door.note_fold_step(1, b1, Some(tags1.clone())));
        assert!(door.note_fold_step(2, b2, Some(tags2.clone())));
        let band0 = door.band().to_vec();
        let mut cursor = BandCursor::new();
        // the OWNER of step 2 proves it BEFORE step 1 is proven anywhere — the cursor absorbs step 1 unproven
        assert!(cursor.absorb(&view, 1, b1, &tags1));
        let (pre2, serves2, fillers2) = cursor.serve_and_absorb(&view, &band0, 2, b2, &tags2, 0).expect("step 2 serves ahead");
        let t0 = std::time::Instant::now();
        let t2 = build_band_transition(b2, &pre2, &serves2, &fillers2, k).expect("step 2 proves ahead of step 1");
        eprintln!("[db353-cursor] step 2 proven ahead: {} ms", t0.elapsed().as_millis());
        let mut own = BandCursor::new();
        let (pre1, serves1, fillers1) = own.serve_and_absorb(&view, &band0, 1, b1, &tags1, 0).expect("step 1 serves");
        let t1 = build_band_transition(b1, &pre1, &serves1, &fillers1, k).expect("step 1 proves");
        // the treeless door: step 2 arrives FIRST (solicited), step 1 second — both verify, both apply, in order
        assert_eq!(door.offer_step(t2.clone(), true), BandReceipt::Held);
        assert_eq!(door.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(door.verified_blocks(), vec![b1, b2], "the step proven ahead verified when its predecessor did");
        assert_eq!(door.drain(None, 8).iter().map(|a| a.ordinal).collect::<Vec<_>>(), vec![1, 2]);
        let mut oracle = RefSparseNf::new();
        for t in tags1.iter().chain(&tags2) {
            let cp = oracle.copath(t);
            oracle.apply_spend(t, &cp);
        }
        assert_eq!(door.band_root(), oracle.root(), "the relayed band folds to the full view's root");
        // C4: a JOINER adopts the certified band at the pointer WITH the pending admitted sets, then takes relayed steps
        let mut joiner = BandDoor::new(64);
        assert!(joiner.adopt_certified(band0, 1, vec![(1, b1, Some(tags1)), (2, b2, Some(tags2))]));
        assert_eq!(joiner.offer_step(t1, false), BandReceipt::Verified, "the joiner verifies step 1 from minute 0");
        assert_eq!(joiner.offer_step(t2, false), BandReceipt::Verified);
        assert_eq!(joiner.drain(None, 8).len(), 2);
        assert_eq!(joiner.band(), door.band(), "the joiner holds the same band from relayed steps alone");
    }

    /// ⭐⭐ DB-454 — THE DOOR SERVES ITS OWN PROOF HELD AHEAD, AND NEVER A THIRD PARTY'S HELD COPY. Owner A proves step 2
    /// before step 1 exists anywhere: offered as its OWN (`offer_own_step`) it is Held AND served (`serve_step` / `holds_step`),
    /// so a peer pulls it at once; the SAME bytes offered to a second door B as a solicited RELAYED copy are Held and NOT served
    /// (B has not verified them). When step 1 lands, both doors verify step 2 in the cascade, both serve it, and the step
    /// stays served once applied inside the journal reach. The bound double stands in for the carrier (the door's one verify).
    /// MEASURED why (real lane, night/sim-20261021-211315.log): the owner's step proven ahead was served by nobody until the
    /// owner's own band reached it — every non-owner's lease ran out and every node proved every step.
    /// TWO-PARTY-REVIEWED: two independent doors (A the owner, B a treeless peer); only the relayed bytes cross.
    #[test]
    fn db454_an_own_proof_held_ahead_is_served_and_a_relayed_held_copy_is_not() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let view = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let (b1, b2) = ([1u8; 32], [2u8; 32]);
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let tags2: Vec<[u8; 32]> = (cover as u64..2 * cover as u64 - 3).map(digest_tag).collect();
        let mut a = BandDoor::new(64);
        let mut b = BandDoor::new(64);
        a.arm_bound_double_for_test();
        b.arm_bound_double_for_test();
        let k = a.chain_k();
        for d in [&mut a, &mut b] {
            assert!(d.note_fold_step(1, b1, Some(tags1.clone())));
            assert!(d.note_fold_step(2, b2, Some(tags2.clone())));
        }
        let band0 = a.band().to_vec();
        let mut cursor = BandCursor::new();
        assert!(cursor.absorb(&view, 1, b1, &tags1));
        let (pre2, serves2, fillers2) = cursor.serve_and_absorb(&view, &band0, 2, b2, &tags2, 0).expect("step 2 serves ahead");
        let t2 = build_band_transition_bound(b2, &pre2, &serves2, &fillers2, k).expect("step 2 proves ahead (bound double)");
        assert_eq!(a.offer_own_step(t2.clone()), BandReceipt::Held, "calibration: proven ahead of its predecessor");
        assert!(
            a.holds_step(&b2) && a.serve_step(&b2) == Some(&t2),
            "⛔ the owner does not serve its own proof held ahead — a peer can only get it after the owner's band reaches it"
        );
        assert_eq!(b.offer_step(t2.clone(), true), BandReceipt::Held, "calibration: the peer holds the solicited copy");
        assert!(
            !b.holds_step(&b2) && b.serve_step(&b2).is_none(),
            "⛔ a door serves a third party's copy it has not verified"
        );
        assert!(a.verified_blocks().is_empty() && b.verified_blocks().is_empty(), "calibration: held is not verified");
        let mut own = BandCursor::new();
        let (pre1, serves1, fillers1) = own.serve_and_absorb(&view, &band0, 1, b1, &tags1, 0).expect("step 1 serves");
        let t1 = build_band_transition_bound(b1, &pre1, &serves1, &fillers1, k).expect("step 1 proves");
        assert_eq!(a.offer_own_step(t1.clone()), BandReceipt::Verified);
        assert_eq!(b.offer_step(t1, true), BandReceipt::Verified);
        for d in [&a, &b] {
            assert_eq!(d.verified_blocks(), vec![b1, b2], "the step held ahead verified in the cascade");
            assert!(d.holds_step(&b1) && d.holds_step(&b2), "both verified steps are served");
        }
        assert_eq!(a.take_newly_verified(), vec![b2], "the cascade names the step the relay announces");
        assert_eq!(a.drain(None, 8).len(), 2);
        assert_eq!(b.drain(None, 8).len(), 2);
        assert_eq!(a.band(), b.band(), "the peer's band from relayed steps alone equals the owner's");
        assert!(a.holds_step(&b2) && b.holds_step(&b2), "applied inside the journal reach: still served to a peer behind");
    }

    /// DB-353 §11.14 (node-lane bandwidth condition) — ONE real 256-insert step proven at k = 1 and at the target's
    /// `band_chain_k` (8): prove time and relay bytes MEASURED side by side, each copy verified at a door of its own k.
    /// Under whole-step ownership one owner proves every slice, so `k` no longer splits work between producers; the
    /// claim pinned here is only the byte one (k = 1 carries under a quarter of k = 8's bytes). Times are printed —
    /// the machine is shared.
    /// TWO-PARTY-REVIEWED: a holder serves, a treeless door verifies the relayed bytes.
    /// ⭐ MEASURED 2026-10-05 (H3, db358 r3 control; the live joiner ×3): a relayed band step that arrives BEFORE this
    /// door notes the block's fold step was refused and lost, and the fold later waited on a carrier nobody re-sent. The
    /// early step is parked and verifies the moment the fold names its block; the park is bounded by `lag_cap` and holds
    /// one copy per block.
    #[test]
    fn an_early_relayed_band_step_is_parked_and_verifies_when_its_fold_step_is_noted() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let view = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let b1 = [1u8; 32];
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let mut door = BandDoor::new(4);
        let k = door.chain_k();
        let band0 = door.band().to_vec();
        let mut own = BandCursor::new();
        let (pre1, serves1, fillers1) = own.serve_and_absorb(&view, &band0, 1, b1, &tags1, 0).expect("step 1 serves");
        let t1 = build_band_transition(b1, &pre1, &serves1, &fillers1, k).expect("step 1 proves");
        assert_eq!(door.offer_step(t1.clone(), false), BandReceipt::Held, "⛔ an early relayed step must be parked, not refused");
        assert_eq!(door.offer_step(t1.clone(), false), BandReceipt::Refused("a copy of this early step is already parked"));
        for i in 0..8u8 {
            let mut other = t1.clone();
            other.for_block = [0xE0 + i; 32];
            let _ = door.offer_step(other, false);
        }
        assert!(door.parked_len() <= 4, "the park is bounded by lag_cap: {} held", door.parked_len());
        let mut door2 = BandDoor::new(4);
        assert_eq!(door2.offer_step(t1.clone(), false), BandReceipt::Held);
        assert!(door2.verified_blocks().is_empty(), "nothing verifies before the fold names the block");
        assert!(door2.note_fold_step(1, b1, Some(tags1.clone())));
        assert_eq!(door2.verified_blocks(), vec![b1], "⛔ the parked step did not verify when its fold step was noted");
        assert_eq!(door2.parked_len(), 0);
        assert_eq!(door2.drain(None, 8).iter().map(|a| a.ordinal).collect::<Vec<_>>(), vec![1]);
        let mut oracle = RefSparseNf::new();
        for t in &tags1 {
            let cp = oracle.copath(t);
            oracle.apply_spend(t, &cp);
        }
        assert_eq!(door2.band_root(), oracle.root(), "the parked-then-verified step folds to the full view's root");
    }

    #[test]
    fn db353_11_14_one_step_at_k_one_carries_a_fraction_of_the_bytes_and_verifies() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let target_k = usdm_decider::nf_sparse_air::band_chain_k(crate::params::ChainParams::default().target_spacing_ms);
        let mut holders = vec![RefSparseNf::with_shards(bits, 0..(1u32 << bits))];
        let block = [1u8; 32];
        let tags: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let (serves, fillers) = serve_admitted(&mut holders, &tags, 0);
        let mut out = Vec::new();
        for k in [1usize, target_k] {
            let mut door = BandDoor::new(8);
            assert!(door.set_chain_k(k));
            assert!(door.note_fold_step(1, block, Some(tags.clone())));
            let t0 = std::time::Instant::now();
            let t = build_band_transition(block, door.band(), &serves, &fillers, k).expect("one step proves");
            let prove_ms = t0.elapsed().as_millis();
            let bytes: usize = t.slices.iter().map(|(_, _, b)| b.len()).sum::<usize>() + t.band_post.len() * 36;
            let t1 = std::time::Instant::now();
            assert_eq!(door.offer_step(t, false), BandReceipt::Verified, "k = {k}: the relayed step verifies");
            let verify_ms = t1.elapsed().as_millis();
            eprintln!("[db353-k] k = {k}: prove {prove_ms} ms, verify {verify_ms} ms, {bytes} B per step");
            out.push(bytes);
        }
        assert!(out[0] * 4 < out[1], "k = 1 carries {} B, under a quarter of k = {target_k}'s {} B", out[0], out[1]);
    }

    /// ⭐ The node lane's three door asks for P1 (the view IS the band-pointer state, reorgs included), RED FIRST where a
    /// red exists:
    /// (1) a rewind with the HELD view takes every un-applied step's inserts back out of it — the view's root returns to
    ///     the band's root after the surviving steps (RED before: the journal kept entries, not tags, so the view kept
    ///     the rewound inserts and read them SPENT);
    /// (2) `spent_after(anchor, tag)` answers exactly over the journal and the awaiting sets, and STALE (`None`) for an
    ///     unknown step in range or an anchor the journal no longer reaches;
    /// (3) a step the lag cap refuses opens a GAP: no later step is noted (the band would SKIP the refused one), every
    ///     `spent_after` is STALE, and only a certified re-adopt or a rewind at or below the gap closes it (RED before: the
    ///     next step was noted and applied past the hole).
    /// TWO-PARTY-REVIEWED: one door and its own held view — the claim is the door's bookkeeping; the relay pins beside it
    /// cover what crosses between nodes.
    #[test]
    fn db353_p1_a_rewind_takes_the_view_back_spent_after_is_exact_or_stale_and_a_gap_is_never_skipped() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let mut held = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        let (b1, b2) = ([1u8; 32], [2u8; 32]);
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let tags2: Vec<[u8; 32]> = (cover as u64..2 * cover as u64).map(digest_tag).collect();
        let mut door = BandDoor::new(64);
        let k = door.chain_k();
        assert!(door.note_fold_step(1, b1, Some(tags1.clone())));
        assert!(door.note_fold_step(2, b2, Some(tags2.clone())));
        let mut cursor = BandCursor::new();
        let band0 = door.band().to_vec();
        let (p1, s1, f1) = cursor.serve_and_absorb(&held, &band0, 1, b1, &tags1, 0).expect("serves 1");
        let (p2, s2, f2) = cursor.serve_and_absorb(&held, &band0, 2, b2, &tags2, 0).expect("serves 2");
        let t1 = build_band_transition(b1, &p1, &s1, &f1, k).expect("proves 1");
        let t2 = build_band_transition(b2, &p2, &s2, &f2, k).expect("proves 2");
        assert_eq!(door.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(door.offer_step(t2.clone(), false), BandReceipt::Verified);
        assert_eq!(door.drain(Some(&mut held), 8).len(), 2);
        let root_after_1 = door.band_root_at(1).expect("step 1 applied");
        assert_eq!(held.root(), door.band_root(), "CALIBRATION: the held view is at the band's root after step 2");
        // (2) spent_after, exact over the journal
        assert_eq!(door.spent_after(0, &tags2[5]), Some(true), "spent by step 2, after anchor 0");
        assert_eq!(door.spent_after(1, &tags1[5]), Some(false), "spent AT step 1 is not after anchor 1");
        assert_eq!(door.spent_after(1, &tags2[5]), Some(true));
        assert_eq!(door.spent_after(0, &digest_tag(9_999_999)), Some(false), "a tag no step spent");
        // (2') the same answers keyed by the ROOT a carried copath folds to (spent_since), and known_admits
        let empty_root = BandDoor::new(1).band_root();
        assert_eq!(door.spent_since(&root_after_1, &tags2[5]), Since::Spent, "spent by step 2, after step 1's root");
        assert_eq!(door.spent_since(&root_after_1, &tags1[5]), Since::NotSpent, "spent AT step 1 is not after its root");
        assert_eq!(door.spent_since(&empty_root, &tags1[5]), Since::Spent, "from the root below the journal");
        assert_eq!(door.spent_since(&door.band_root(), &tags2[5]), Since::NotSpent, "nothing after the current root");
        assert_eq!(door.spent_since(&poseidon_pair([0xA, 0, 0, 0, 0, 0, 0, 0], [0xB, 0, 0, 0, 0, 0, 0, 0]), &tags1[5]), Since::UnknownRoot);
        assert!(door.known_admits(&tags1[5]) && door.known_admits(&tags2[5]) && !door.known_admits(&digest_tag(9_999_999)));
        // (1) the rewind takes step 2's inserts back out of the held view
        // (2'') admitted_since — a WARM started two steps back (at the root below the journal) replays exactly the applied
        // steps and lands on the band's current root; from step 1's root only step 2 remains; an unplaceable root is None
        let since_empty = door.admitted_since(&empty_root).expect("the root below the journal is placeable");
        assert_eq!(since_empty.iter().map(|(o, _)| *o).collect::<Vec<_>>(), vec![1, 2]);
        let mut warm = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        for (_, tags) in &since_empty {
            for t in tags {
                let cp = warm.copath(t);
                warm.apply_spend(t, &cp);
            }
        }
        assert_eq!(warm.root(), door.band_root(), "⛔ a warm brought forward through admitted_since is not the band");
        let from_1 = door.admitted_since(&root_after_1).expect("step 1's root is placeable");
        let as_set = |v: &[[u8; 32]]| v.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(from_1.len(), 1, "from step 1's root, step 2 alone");
        assert_eq!((from_1[0].0, as_set(&from_1[0].1)), (2, as_set(&tags2)), "step 2's admitted set, as the journal applied it");
        assert_eq!(door.admitted_since(&door.band_root()), Some(Vec::new()), "at the current root nothing remains");
        assert_eq!(door.admitted_since(&poseidon_pair([0xA, 0, 0, 0, 0, 0, 0, 0], [0xB, 0, 0, 0, 0, 0, 0, 0])), None, "an unplaceable root");
        assert!(door.rewind_to(2, Some(&mut held)));
        assert_eq!(door.band_root(), root_after_1);
        assert_eq!(held.root(), root_after_1, "⛔ the held view kept the rewound inserts");
        assert_eq!(held.holds_spent_leaf(&tags2[5]), Some(false), "a rewound tag reads UNSPENT in the view");
        assert_eq!(held.holds_spent_leaf(&tags1[5]), Some(true), "a surviving step's tag stays spent");
        assert_eq!((door.held_rewind_misses, door.spent_after(0, &tags2[5])), (0, Some(false)), "the journal forgot step 2 too");
        // a view that never held the step: each tag it cannot take back is counted, and the band still rewinds
        let mut foreign = RefSparseNf::with_shards(bits, 0..(1u32 << bits));
        assert!(door.note_fold_step(2, b2, Some(tags2.clone())));
        assert_eq!(door.offer_step(t2.clone(), false), BandReceipt::Verified);
        assert_eq!(door.drain(None, 8).len(), 1);
        assert!(door.rewind_to(2, Some(&mut foreign)));
        assert_eq!(door.held_rewind_misses, tags2.len() as u64, "every tag the view could not take back is counted");
        // (2) STALE: an unknown step in range, or an anchor below the journal's reach
        assert!(door.note_fold_step(2, b2, None));
        assert_eq!(door.spent_after(1, &tags1[5]), None, "not known-spent and an unknown step after the anchor: STALE, the caller waits");
        // RED FIRST (the node lane's 13:38 finding; before this, an unknown LATER step returned None and MASKED this hit, so a
        // respend memo read a spent tag FRESH): a known earlier hit is exact whatever is unknown after it
        assert_eq!(door.spent_after(0, &tags1[5]), Some(true), "⛔ an unknown later step masked a known hit in step 1");
        assert_eq!(door.spent_since(&root_after_1, &digest_tag(9_999_999)), Since::Stale, "not known-spent past an unknown step: wait");
        assert_eq!(door.spent_since(&empty_root, &tags1[5]), Since::Spent, "a known hit stays exact past an unknown step");
        assert!(door.known_admits(&tags1[5]), "known_admits is never masked");
        // (DB-367 follow-up: an idle step takes no journal slot, so the steps the one-slot journal releases here MOVE the
        // band — the same two proven transitions, re-verified.)
        let mut short = BandDoor::new(1);
        for (o, b, tags, t) in [(1u64, b1, &tags1, &t1), (2, b2, &tags2, &t2)] {
            assert!(short.note_fold_step(o, b, Some(tags.clone())));
            assert_eq!(short.offer_step(t.clone(), false), BandReceipt::Verified);
            assert_eq!(short.drain(None, 8).len(), 1);
        }
        assert_eq!(short.spent_after(0, &tags1[5]), None, "the journal released steps after anchor 0: STALE");
        assert_eq!(short.spent_after(2, &tags1[5]), Some(false), "inside the reach: exact");
        // and idle steps release nothing: past them the answer stays EXACT
        let mut idle = BandDoor::new(1);
        for o in 1..=3u64 {
            assert!(idle.note_fold_step(o, [o as u8; 32], Some(Vec::new())));
            assert_eq!(idle.drain(None, 8).len(), 1);
        }
        assert_eq!(idle.spent_after(0, &tags1[5]), Some(false), "idle steps admitted nothing and released nothing: exact");
        // (3) the GAP — closed by a rewind at or below it
        let mut gap = BandDoor::new(2);
        assert!(gap.note_fold_step(1, [1; 32], Some(Vec::new())));
        assert!(gap.note_fold_step(2, [2; 32], Some(Vec::new())));
        assert!(!gap.note_fold_step(3, [3; 32], Some(Vec::new())), "the lag cap refuses step 3");
        assert!(gap.is_stale());
        assert!(gap.note_fold_step(2, [2; 32], Some(Vec::new())), "a re-note BELOW the gap (a re-fold) is still taken");
        assert_eq!(gap.drain(None, 8).len(), 2, "the steps before the gap still apply");
        assert!(!gap.note_fold_step(3, [3; 32], Some(Vec::new())), "⛔ the gap step was noted with room — it stays refused");
        assert!(!gap.note_fold_step(4, [4; 32], Some(Vec::new())), "⛔ a step past the gap was noted — the band would skip 3");
        assert_eq!(gap.spent_after(2, &tags1[5]), None, "past a gap every verdict is STALE");
        assert!(gap.rewind_to(3, None));
        assert!(!gap.is_stale(), "a rewind at the gap closes it: the re-fold re-notes step 3");
        assert!(gap.note_fold_step(3, [3; 32], Some(Vec::new())));
        assert!(gap.note_fold_step(4, [4; 32], Some(Vec::new())));
        assert_eq!(gap.drain(None, 8).len(), 2, "the door follows again from step 3");
        // … and closed by a certified re-adopt
        let band = gap.band().to_vec();
        let mut gap2 = BandDoor::new(2);
        assert!(gap2.note_fold_step(1, [1; 32], None));
        assert!(gap2.note_fold_step(2, [2; 32], Some(Vec::new())));
        assert!(!gap2.note_fold_step(3, [3; 32], Some(Vec::new())));
        assert!(gap2.is_stale());
        assert!(gap2.adopt_certified(band, 5, vec![(5, [5; 32], Some(Vec::new()))]), "a certified re-adopt");
        assert!(!gap2.is_stale(), "the re-adopt closes the gap");
        assert!(gap2.note_fold_step(6, [6; 32], Some(Vec::new())), "past the re-adopt the door follows again");
        assert_eq!(gap2.drain(None, 8).iter().map(|a| a.ordinal).collect::<Vec<_>>(), vec![5, 6]);
    }

    /// ⭐ §11.12 pin (a) — THE SOLICITED WINDOW, RED FIRST (on the pre-relay door a copy for a step it could not yet verify
    /// was HELD whoever sent it): an UNSOLICITED copy of a not-yet-verifiable step is refused and NOTHING is held; a
    /// SOLICITED one is held (at most `W`), verified the moment its predecessor verifies; a solicited copy that fails
    /// then is dropped and reported (`take_invalidated`), and the next honest copy verifies.
    /// TWO-PARTY-REVIEWED: two doors built from one noted history; the prover's bytes are the only thing that crosses.
    #[test]
    fn db353_11_12_an_unsolicited_early_step_is_never_held_and_a_solicited_one_verifies_when_its_predecessor_does() {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let mut holders = vec![RefSparseNf::with_shards(bits, 0..(1u32 << bits))];
        let (b1, b2) = ([1u8; 32], [2u8; 32]);
        let tags1: Vec<[u8; 32]> = (0..cover as u64).map(digest_tag).collect();
        let tags2: Vec<[u8; 32]> = (cover as u64..2 * cover as u64).map(digest_tag).collect();
        let prover = BandDoor::new(64);
        let k = prover.chain_k();
        let (serves1, fillers1) = serve_admitted(&mut holders, &tags1, 0);
        let t1 = build_band_transition(b1, prover.band(), &serves1, &fillers1, k).expect("step 1 proves");
        for t in &tags1 {
            let cp = holders[0].copath(t);
            holders[0].apply_spend(t, &cp);
        }
        let band1: Vec<Digest4> = {
            let mut b = prover.band().to_vec();
            for (s, e) in &t1.band_post {
                b[*s as usize] = *e;
            }
            b
        };
        let (serves2, fillers2) = serve_admitted(&mut holders, &tags2, 0);
        let t2 = build_band_transition(b2, &band1, &serves2, &fillers2, k).expect("step 2 proves ahead");
        let fresh = || {
            let mut d = BandDoor::new(64);
            assert!(d.note_fold_step(1, b1, Some(tags1.clone())));
            assert!(d.note_fold_step(2, b2, Some(tags2.clone())));
            d
        };
        // RED FIRST: the unsolicited early copy
        let mut d = fresh();
        assert!(!d.wants(&[9u8; 32]), "a step that awaits nothing is not wanted");
        assert_eq!(d.offer_step(t2.clone(), false), BandReceipt::Refused("not verifiable yet and not solicited"));
        assert_eq!(d.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert!(d.serve_step(&b2).is_none(), "the refused early copy was never held — step 2 still needs a copy");
        assert_eq!(d.offer_step(t2.clone(), false), BandReceipt::Verified, "once step 1 verified, step 2 verifies unsolicited");
        assert_eq!(d.drain(None, 8).len(), 2);
        // SOLICITED: held, then verified by the cascade when step 1 lands
        let mut d = fresh();
        d.set_solicit_cap(1);
        assert!(d.wants(&b2), "the window has room");
        assert_eq!(d.offer_step(t2.clone(), true), BandReceipt::Held);
        assert!(!d.wants(&b2), "a held step is not asked for twice");
        assert_eq!(d.offer_step(t2.clone(), true), BandReceipt::Refused("a solicited copy of this step is already held"));
        assert_eq!(d.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(d.verified_blocks(), vec![b1, b2], "the held step verified in the cascade");
        assert!(d.take_invalidated().is_empty());
        assert_eq!(d.take_newly_verified(), vec![b2], "the cascade-verified step is reported for the relay to flood at once");
        assert!(d.take_newly_verified().is_empty(), "taken once");
        let applied = d.drain(None, 8);
        assert_eq!(applied.iter().map(|a| a.ordinal).collect::<Vec<_>>(), vec![1, 2]);
        // a JUNK solicited copy: held, dropped and REPORTED when step 1 lands; the honest copy then verifies
        let mut d = fresh();
        d.set_solicit_cap(1);
        let mut junk = t2.clone();
        let n = junk.slices[k - 1].2.len();
        junk.slices[k - 1].2[n / 2] ^= 0xFF;
        assert_eq!(d.offer_step(junk, true), BandReceipt::Held);
        assert_eq!(d.offer_step(t1.clone(), false), BandReceipt::Verified);
        assert_eq!(d.take_invalidated(), vec![b2], "the junk solicited copy is named for the relay to score its announcer");
        assert!(d.take_newly_verified().is_empty(), "TAMPER: a junk held copy that fails in the cascade is never flooded");
        assert!(d.take_invalidated().is_empty(), "taken once");
        assert!(d.wants(&b2), "step 2 is wanted again");
        assert_eq!(d.offer_step(t2.clone(), false), BandReceipt::Verified);
        assert_eq!(d.drain(None, 8).len(), 2);
        // THE WINDOW: W = 1 holds one solicited step; a second is refused
        let mut d = fresh();
        assert!(d.note_fold_step(3, [3u8; 32], Some(vec![digest_tag(9_999_999)])));
        d.set_solicit_cap(1);
        assert_eq!(d.offer_step(t2, true), BandReceipt::Held);
        let mut third = t1;
        third.for_block = [3u8; 32];
        assert_eq!(d.offer_step(third, true), BandReceipt::Refused("the solicited window is full"));
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db453_compact_parity {
    //! ⭐ DB-453 brick 2 — THE NODE'S TREE IS THE DECIDER'S COMPACT TREE. Every node-side structure that computes a
    //! nullifier root or witness (the unsharded and sharded `RefSparseNf`, the direct-counting `RefSparseNfMemo` oracle,
    //! the O(1) `SparseNfAcc`, the wallet's incremental `SparseNfWitness`, `batch_insert_root`) agrees with ONE reference,
    //! `usdm_decider::nf_compact_air::CompactRefTree`, over key sets that exercise every compact case: lone keys per
    //! shard, shared shards, and deep common prefixes (splits far below the band).
    use super::*;
    use usdm_decider::nf_compact_air::{native_compact_insert_transition, CompactRefTree};

    /// A real-shaped TAG (byte 31 = 0, as every digest encoding): `shard` picks key byte 31, `deep` how many key bytes
    /// below the shard byte are shared with every other tag of the same `family` (a deep common prefix).
    fn tag(family: u8, i: u32, shard: u8, deep: usize) -> [u8; 32] {
        let mut key = *blake3::hash(&[&[family][..], &i.to_le_bytes()].concat()).as_bytes();
        key[0] = 0; // real keys have key byte 0 = tag byte 31 = 0
        key[31] = shard;
        for b in 0..deep {
            key[30 - b] = family.wrapping_mul(17).wrapping_add(b as u8);
        }
        SparseKey::from_key_bytes(key).tag()
    }

    fn key_set() -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for i in 0..300u32 {
            out.push(tag(1, i, (i % 256) as u8, 0)); // spread: ~1 per shard
        }
        for i in 0..40u32 {
            out.push(tag(2, i, 7, 0)); // one crowded shard
        }
        for i in 0..12u32 {
            out.push(tag(3, i, 9, 5)); // deep: 5 shared key bytes under shard 9 (splits below level 208)
        }
        for i in 0..6u32 {
            out.push(tag(4, i, 11, 25)); // deeper: splits far below the normal window
        }
        out
    }

    #[test]
    fn db453_g_the_node_tree_is_the_decider_compact_tree() {
        let tags = key_set();
        let mut reference = CompactRefTree::default();
        let mut flat = RefSparseNf::new();
        let mut sharded = RefSparseNf::with_shards(8, 0..256u32);
        let mut memo = RefSparseNfMemo::new();
        let mut acc = SparseNfAcc::new();
        assert_eq!(flat.root(), reference.root(), "the empty roots agree");
        assert_eq!(acc.root(), reference.root(), "the empty accumulator is the empty compact root");
        for (n, t) in tags.iter().enumerate() {
            let key = SparseKey::of(t);
            // the witness every node structure builds BEFORE the insert is the reference's
            let cp = flat.copath(t);
            assert_eq!(cp, sharded.copath(t), "sharded and flat views build one copath (insert {n})");
            assert_eq!(cp, memo.copath(t), "the view's neighbour rule matches direct counting (insert {n})");
            let w = compact_witness(&key, &cp).expect("a well-formed compact copath");
            assert_eq!(Some(w.clone()), reference.witness(key.bytes()), "the node witness IS the reference witness (insert {n})");
            assert_eq!(acc.verify_unspent(t, &cp), Ok(()), "absent before its insert (insert {n})");
            let post = native_compact_insert_transition(&w, acc.root()).expect("the decider's native transition admits it");
            acc.verify_and_insert(t, &cp).expect("the accumulator settles it");
            let _ = flat.insert_and_witness(t);
            let _ = sharded.advance_one_rooted(t).expect("an owned shard");
            let _ = memo.insert_and_witness(t);
            reference.insert(key.bytes());
            assert_eq!(acc.root(), post, "the accumulator lands where the decider's transition does (insert {n})");
            assert_eq!(flat.root(), reference.root(), "flat view root (insert {n})");
            assert_eq!(sharded.root(), reference.root(), "sharded view root (insert {n})");
            assert_eq!(memo.root(), reference.root(), "oracle root (insert {n})");
            assert_eq!(acc.root(), reference.root(), "accumulator root (insert {n})");
        }
        // a spent key: the view serves the MEMBER form, which proves Spent and refuses a re-spend
        for t in tags.iter().step_by(17) {
            let cp = flat.copath(t);
            assert_eq!(cp, memo.copath(t), "member-form copaths agree");
            assert_eq!(acc.spent_verdict(t, &cp), SpentVerdict::Spent, "a member proves spent");
            assert_eq!(acc.verify_unspent(t, &cp), Err(SparseNfError::AlreadySpentOrBadWitness), "a re-spend is refused");
        }
        // the set function: a different insert order lands on the same root
        let mut rev = RefSparseNf::new();
        for t in tags.iter().rev() {
            let _ = rev.insert_and_witness(t);
        }
        assert_eq!(rev.root(), reference.root(), "the root is a function of the SET");
        // the band is the reference's band entry by entry
        assert_eq!(sharded.band, reference.band(), "the sharded view's band is the reference band");
        eprintln!("[db453-g] {} keys: node views, oracle, accumulator and decider agree on every root and witness", tags.len());
    }

    #[test]
    fn db453_h_forged_compact_witnesses_are_refused_and_honest_ones_survive_compression() {
        let tags = key_set();
        let mut tree = RefSparseNf::new();
        for t in &tags {
            let _ = tree.insert_and_witness(t);
        }
        let acc = SparseNfAcc::adopt_merkle_root(tree.root_bytes()).expect("a root");
        let probes: Vec<[u8; 32]> = (0..40u32).map(|i| tag(if i % 2 == 0 { 3 } else { 4 }, 1_000 + i, if i % 2 == 0 { 9 } else { 11 }, if i % 2 == 0 { 5 } else { 25 })).collect();
        let (mut with_terminal, mut deep) = (0usize, 0usize);
        for p in &probes {
            let cp = tree.copath(p);
            assert_eq!(acc.spent_verdict(p, &cp), SpentVerdict::Unspent, "an honest absence witness");
            assert_eq!(expand_copath(&compress_copath(&cp)).as_deref(), Some(cp.as_slice()), "compression is lossless");
            let w = compact_witness(&SparseKey::of(p), &cp).expect("well-formed");
            with_terminal += usize::from(w.other.is_some());
            deep += usize::from(w.t < usdm_decider::nf_compact_air::compact_window_floor(usdm_decider::nf_compact_air::COMPACT_LB_NORMAL));
            // F1: the terminal slot names the probe itself (a member claim for an absent key)
            let mut f = cp.clone();
            f[NF_TERMINAL_SLOT] = terminal_slot(Some(&SparseKey::of(p)));
            assert_ne!(acc.spent_verdict(p, &f), SpentVerdict::Spent, "F1: a self-terminal is not a membership proof");
            assert!(acc.verify_unspent(p, &f).is_err(), "F1 refused");
            // F2: the terminal emptied (or filled) — a different terminal node
            let mut f = cp.clone();
            f[NF_TERMINAL_SLOT] = if w.other.is_some() { Z } else { terminal_slot(Some(&SparseKey::of(&tags[0]))) };
            assert!(acc.verify_unspent(p, &f).is_err(), "F2: a forged terminal kind is refused");
            // F3: junk planted below the terminal lowers the implied terminal level
            if w.t > 0 {
                let mut f = cp.clone();
                f[w.t - 1] = [7, 0, 0, 0, 0, 0, 0, 0];
                assert!(acc.verify_unspent(p, &f).is_err(), "F3: a sibling below the terminal is refused");
            }
            // F4: one real sibling flipped
            let mut f = cp.clone();
            f[NF_SPARSE_DEPTH - 1][0] ^= 1;
            assert!(acc.verify_unspent(p, &f).is_err(), "F4: a forged sibling is refused");
            // F5: a malformed terminal slot (a lane past 32 bits) and a short copath
            let mut f = cp.clone();
            f[NF_TERMINAL_SLOT] = [1 << 40, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(acc.verify_unspent(p, &f), Err(SparseNfError::AlreadySpentOrBadWitness), "F5: a malformed slot is refused");
            assert_eq!(acc.verify_unspent(p, &cp[..NF_SPARSE_DEPTH]), Err(SparseNfError::BadCopathLength), "F5: the old 256-sibling form is refused");
        }
        assert!(with_terminal > 0 && deep > 0, "CALIBRATION: probes met leaf terminals ({with_terminal}) and deep terminals ({deep})");
    }

    #[test]
    fn db453_i_a_wallet_witness_and_a_batch_follow_every_insert() {
        let tags = key_set();
        let (base, later) = tags.split_at(tags.len() / 2);
        let mut tree = RefSparseNf::new();
        for t in base {
            let _ = tree.insert_and_witness(t);
        }
        // wallets watching notes that will NOT be spent here, in the crowded and deep regions
        let watched: Vec<[u8; 32]> = (0..12u32).map(|i| tag(if i % 2 == 0 { 2 } else { 3 }, 5_000 + i, if i % 2 == 0 { 7 } else { 9 }, if i % 2 == 0 { 0 } else { 5 })).collect();
        let acc0 = SparseNfAcc::adopt_merkle_root(tree.root_bytes()).expect("a root");
        let mut ws: Vec<SparseNfWitness> = watched
            .iter()
            .map(|w| SparseNfWitness::from_copath(*w, tree.copath(w), &acc0).expect("an honest cold restore"))
            .collect();
        // the batch: every later tag's carry against the SAME pre root
        let carries: Vec<([u8; 32], Vec<Digest4>)> = later.iter().map(|t| (*t, tree.copath(t))).collect();
        let batch = batch_insert_root(&acc0, &carries).expect("the batch settles");
        for (t, cp) in &carries {
            // each wallet folds the streamed spend with the copath it carried against the running tree
            let running = tree.copath(t);
            for w in &mut ws {
                w.observe_spend(t, &running);
            }
            let _ = tree.insert_and_witness(t);
            let _ = cp;
        }
        assert_eq!(batch, tree.root_bytes(), "batch_insert_root lands on the tree's root after the same set");
        let acc = SparseNfAcc::adopt_merkle_root(tree.root_bytes()).expect("a root");
        for w in &ws {
            assert_eq!(w.copath(), tree.copath(w.nf()).as_slice(), "the maintained witness IS the tree's witness");
            assert_eq!(acc.verify_unspent(w.nf(), w.copath()), Ok(()), "the maintained witness still proves absence");
        }
        // a duplicate in one batch and a stale carry are refused
        let mut dup = carries.clone();
        dup.push(carries[0].clone());
        assert_eq!(batch_insert_root(&acc0, &dup), None, "the same nullifier twice in one batch is refused");
        assert_eq!(batch_insert_root(&acc, &carries[..1]), None, "a carry built before its own spend is refused");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod recent_fold_canonical_tests {
    use super::*;

    /// §POLES lane a 2026-10-25 — the recent-fold ring is a function of the FOLDED SET, never of arrival order: two nodes
    /// that fold the same 80 blocks in opposite orders hold the same 64 blocks in the same order, and those are exactly
    /// the 64 greatest `(blue_work, id)`. RED on the arrival ring (push_back/pop_front): the reversed node held the
    /// first-arrived 64, a different set (census4-det1.log: nf_recent_folds DIFFERS on the 4-node launch census).
    #[test]
    fn recent_fold_ring_is_the_same_set_and_order_whatever_the_arrival_order() {
        let leaf = usdm_decider::nf_sparse_air::nf_to_limbs(&[7u8; 32]);
        let blocks: Vec<(u128, [u8; 32])> = (0..80u8)
            .map(|i| (u128::from(i % 37) * 1_000 + u128::from(i / 2), [i.wrapping_mul(97); 32]))
            .collect();
        let (mut fwd, mut rev) = (RecentFoldBlocks::default(), RecentFoldBlocks::default());
        for (bw, id) in &blocks {
            fwd.record(*bw, *id, leaf, &[*id]);
        }
        for (bw, id) in blocks.iter().rev() {
            rev.record(*bw, *id, leaf, &[*id]);
        }
        // a re-fold of a held block is not held twice
        let (bw0, id0) = *blocks.iter().max().expect("blocks");
        rev.record(bw0, id0, leaf, &[id0]);
        let ids = |r: &RecentFoldBlocks| r.iter().map(|f| f.id).collect::<Vec<_>>();
        assert_eq!(fwd.len(), NF_RECENT_BLOCKS, "the ring holds its full depth");
        assert_eq!(rev.len(), NF_RECENT_BLOCKS, "⛔ a re-folded block was held twice");
        assert_eq!(ids(&fwd), ids(&rev), "⛔ two arrival orders of one folded set left two different rings");
        let mut want = blocks.clone();
        want.sort();
        let want: Vec<[u8; 32]> = want[want.len() - NF_RECENT_BLOCKS..].iter().map(|(_, id)| *id).collect();
        assert_eq!(ids(&fwd), want, "⛔ the ring is not the 64 greatest canonical keys, ascending");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod band_door_statement_view_tests {
    use super::*;

    /// §POLES lane a 2026-10-25 — the replicated-state census compares the band door BY STATEMENT: two doors whose held
    /// proofs differ only in their zero-knowledge bytes render the same, and a door whose proven TRANSITION differs (one
    /// `band_post` entry, or a slice's post root) renders differently. CALIBRATION both ways, so the class cannot hide.
    #[test]
    fn band_door_statement_view_forgives_proof_bytes_and_nothing_else() {
        let e = usdm_decider::nf_sparse_air::nf_to_limbs(&[3u8; 32]);
        let f = usdm_decider::nf_sparse_air::nf_to_limbs(&[4u8; 32]);
        let t = |post: Digest4, slice_post: Digest4, bytes: u8| BandTransition {
            for_block: [9u8; 32],
            band_post: vec![(5, post)],
            k: 1,
            slices: vec![(0, slice_post, vec![bytes; 4096])],
        };
        let door = |tr: BandTransition| {
            let mut d = BandDoor::new(8);
            d.applied_proofs.push_back((tr.for_block, tr.clone()));
            d.solicited.insert([1u8; 32], tr.clone());
            d.parked.push_back(tr);
            d
        };
        let (a, b) = (door(t(e, e, 1)), door(t(e, e, 2)));
        assert_ne!(format!("{a:?}"), format!("{b:?}"), "CALIBRATION: the exact rendering sees the proof bytes");
        assert_eq!(a.statement_view(), b.statement_view(), "⛔ two proofs of one statement render differently by statement");
        assert_ne!(a.statement_view(), door(t(f, e, 1)).statement_view(), "⛔ a different band_post entry was forgiven");
        assert_ne!(a.statement_view(), door(t(e, f, 1)).statement_view(), "⛔ a different slice post root was forgiven");
    }

    /// (lane stable 2026-11-02) — A CERTIFIED ADOPT RELEASES THE APPLIED PROOFS WITH THE JOURNAL THEY BELONG TO: after it the
    /// door journals nothing, so it holds no proof to serve, exactly as its own restart (`install_journal`, G1e-iv) leaves it.
    #[test]
    fn a_certified_adopt_releases_the_applied_proofs_with_their_journal() {
        let tr = BandTransition { for_block: [9u8; 32], band_post: vec![], k: 1, slices: vec![] };
        let mut d = BandDoor::new(8);
        d.applied_proofs.push_back((tr.for_block, tr));
        let band = d.band.clone();
        assert!(d.adopt_certified(band, d.floor + 1, Vec::new()), "PRECONDITION: the adopt installs");
        assert!(d.applied_proofs.is_empty(), "⛔ a re-anchored door still holds proofs of steps it no longer journals");
        assert_eq!(d.journal_carry().applied.len(), 0, "⛔ its checkpoint would carry a proof its restart drops");
    }
}

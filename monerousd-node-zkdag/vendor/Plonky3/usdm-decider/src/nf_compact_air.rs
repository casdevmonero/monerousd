// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ DB-453 — THE COMPACT SHARD NULLIFIER TREE and its band carrier (docs/DB-453-COMPACT-SHARD-NULLIFIER-TREE.md).
//!
//! The sparse nullifier tree's shards become COMPACT sparse Merkle trees — the Jellyfish Merkle Tree's shape (Diem/Aptos)
//! and Haider's Compact Sparse Merkle Tree: a subtree holding exactly ONE key is that key's leaf node, an empty subtree is
//! `Z`, and only a subtree holding two or more keys hashes its two children. Compaction stops at the band (level 248): the
//! 256 shard roots fold PLAINLY through [`crate::nf_sparse_air::fold_band`], exactly as today. The root is still a
//! function of the spent SET (commutative, count-free, monotone), and a path is only as long as the keys' common prefix —
//! so a band step proves 64 trace rows per insert (a 63-level window plus a leaf row) instead of 256.
//!
//! This module is brick 1 of the spec: the ONE native definition ([`compact_leaf`], [`native_compact_insert_folds`]), a
//! reference tree for pins and parity ([`CompactRefTree`]), and the band carrier — a chain table generic over the window
//! (`LB = 6` normal, `LB = 8` deep) and the ten-lane key-digest table, proven on the BOUND batch engine (DB-452).

use crate::hiding_decider::{Ea4, Fa4};
use crate::nf_sparse_air::{fkred, fold_band, nf_bit, push_chain_residuals_at, NF_BAND_ENTRIES, NF_BAND_LEVEL, NF_SPARSE_DEPTH};
use crate::nullifier_insert_air::poseidon_pair_native;
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use p3_field::PrimeCharacteristicRing;

// ── the definition ───────────────────────────────────────────────────────────────────────────────────────────────────

/// The leaf hash's domain lane (`"LEAF"`, a canonical field element).
pub const COMPACT_LEAF_DOMAIN: u64 = 0x4c45_4146;
/// The number of compact key lanes.
pub const COMPACT_KEY_LANES: usize = 10; // PRODUCTION-SCALE-REVIEWED: lanes per key — ten ≤ 30-bit level ranges tiling the 256 levels, a layout constant, not a block/cover sample
/// The compact key lanes as inclusive LEVEL ranges, each read MSB-first in level order (the range's first level is the
/// most significant bit). Every lane is at most 30 bits, so every lane is a canonical field element (the DB-362 alias
/// class); the top three are exactly levels 192..=255, the normal window's bit stream, so no lane straddles a window.
pub const COMPACT_LANE_RANGES: [(usize, usize); COMPACT_KEY_LANES] =
    [(0, 29), (30, 59), (60, 89), (90, 119), (120, 149), (150, 179), (180, 191), (192, 221), (222, 251), (252, 255)];
const _: () = {
    let mut j = 0;
    let mut next = 0;
    while j < COMPACT_KEY_LANES {
        assert!(COMPACT_LANE_RANGES[j].0 == next, "the lanes tile the levels in order");
        assert!(COMPACT_LANE_RANGES[j].1 - COMPACT_LANE_RANGES[j].0 < 30, "a lane is at most 30 bits");
        next = COMPACT_LANE_RANGES[j].1 + 1;
        j += 1;
    }
    assert!(next == NF_SPARSE_DEPTH, "the lanes cover every level");
};

/// The NORMAL window: 64 rows per insert (a leaf row + levels 193..=255).
pub const COMPACT_LB_NORMAL: usize = 6; // PRODUCTION-SCALE-REVIEWED: log2 of the normal window's rows per insert, a layout constant, not a cover count
/// The DEEP window: 256 rows per insert (a leaf row + levels 1..=255) — today's row count, for the rare step whose split
/// falls below level 193 (P ≤ n_shard · 2^-55 per insert, docs/DB-453 §4.5). A slow step, never a refusal.
pub const COMPACT_LB_DEEP: usize = 8;

/// The lanes of the terminal key when the terminal is EMPTY: zero by law 4 (`(1 − TK)·K2 = 0`). The leaf row still hashes
/// them into an `LK2` that `T2 = TK·LK2` discards, so an empty terminal enters the pre chain as `Z`.
const EMPTY_TERMINAL_LANES: [u64; COMPACT_KEY_LANES] = [0; COMPACT_KEY_LANES];

/// An empty subtree, at every level.
#[must_use]
pub const fn compact_empty() -> Digest {
    [0u64; DIGEST_LANES]
}

/// The ten compact lanes of a tree KEY (`sparse_key_of_tag(tag)`).
#[must_use]
pub fn compact_key_lanes(key: &[u8; 32]) -> [u64; COMPACT_KEY_LANES] {
    core::array::from_fn(|j| {
        let (a, b) = COMPACT_LANE_RANGES[j];
        let mut v = 0u64;
        for l in a..=b {
            v = (v << 1) | u64::from(nf_bit(key, l));
        }
        v
    })
}

/// The two halves a leaf presents to the compression: `L0..L7 ‖ (L8, L9, LEAF, 0…)`.
fn leaf_inputs(lanes: &[u64; COMPACT_KEY_LANES]) -> (Digest, Digest) {
    let left: Digest = core::array::from_fn(|c| lanes[c]);
    let mut right = [0u64; DIGEST_LANES];
    right[0] = lanes[8];
    right[1] = lanes[9];
    right[2] = COMPACT_LEAF_DOMAIN;
    (left, right)
}

/// The leaf node of a key given its lanes.
#[must_use]
pub fn compact_leaf_of_lanes(lanes: &[u64; COMPACT_KEY_LANES]) -> Digest {
    let (l, r) = leaf_inputs(lanes);
    poseidon_pair_native(l, r)
}

/// The leaf node of a key — the value a one-key subtree takes at every level.
#[must_use]
pub fn compact_leaf(key: &[u8; 32]) -> Digest {
    compact_leaf_of_lanes(&compact_key_lanes(key))
}

/// One parent: `left` is the child whose path bit at the child's level is 0.
#[inline]
fn pair_by_bit(node: Digest, sib: Digest, bit: u8) -> Digest {
    if bit == 0 {
        poseidon_pair_native(node, sib)
    } else {
        poseidon_pair_native(sib, node)
    }
}

/// One compact insert's witness (docs/DB-453 §4.1): the KEY, the TERMINAL level `t` (the highest level on the key's path
/// whose subtree holds at most one key; at most the band level), the one key there if any, and the copath sibling at
/// every level `≥ t` (`siblings[l]` for `l` in `t..256`; the entries below `t` are ignored and laid as `Z`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactInsertWitness {
    pub key: [u8; 32],
    pub t: usize,
    pub other: Option<[u8; 32]>,
    pub siblings: Vec<Digest>,
}

/// The split level of `key` and `other` below the terminal `t`: the highest level `< t` where their bits differ. `None`
/// when they disagree at or above `t` (then `other` cannot live in that subtree) or never differ (the same key).
#[must_use]
pub fn compact_split_level(key: &[u8; 32], other: &[u8; 32], t: usize) -> Option<usize> {
    if (t..NF_SPARSE_DEPTH).any(|l| nf_bit(key, l) != nf_bit(other, l)) {
        return None;
    }
    (0..t).rev().find(|&l| nf_bit(key, l) != nf_bit(other, l))
}

/// ONE insert's two folds, from its own witness (window-free — what every native door runs): `(the root under which the
/// key is ABSENT, the root once it is inserted, the split level)`. `None` on a terminal above the band, a short copath, or
/// a terminal key that is the key itself or does not live in the terminal subtree (a re-spend has no split, so it never
/// folds).
#[must_use]
pub fn native_compact_insert_folds(w: &CompactInsertWitness) -> Option<(Digest, Digest, usize)> {
    // ROOT-LAYER: the all-zero key (the reserved value `nf_sparse::SparseNfError::ZeroNullifier` names) is refused where
    //   every compact witness is CONSUMED — this fold is the one the trace lay (`compact_chain_cols`) and every native door
    //   share, exactly as `nf_sparse_air::native_sparse_insert_folds` refuses it for the 256-deep tree (§9.6 Q6 parity).
    // MEASURED: `db453_e_…` RED before this line (night/link81-e-red.log: the 256-deep transition refused the zero key, a
    //   non-zero key folded, the compact transition ADMITTED the zero key at nf_compact_air.rs:1221) → GREEN after.
    // MUST-STAY-GREEN: db453_a (600 honest keys fold onto the recompute), db453_b/c (both shapes prove), db453_d censuses.
    if w.key == [0u8; 32] {
        return None;
    }
    if w.t > NF_BAND_LEVEL || w.siblings.len() != NF_SPARSE_DEPTH {
        return None;
    }
    let lk = compact_leaf(&w.key);
    let (terminal, start_post, s) = match &w.other {
        None => (compact_empty(), lk, w.t),
        Some(o) => {
            let s = compact_split_level(&w.key, o, w.t)?;
            let lo = compact_leaf(o);
            // the two leaves meet at level s; above them, up to the terminal, the other child is empty
            let mut node = pair_by_bit(lk, lo, nf_bit(&w.key, s));
            for l in (s + 1)..w.t {
                node = pair_by_bit(node, compact_empty(), nf_bit(&w.key, l));
            }
            (lo, node, s)
        }
    };
    let mut pre = terminal;
    let mut post = start_post;
    for l in w.t..NF_SPARSE_DEPTH {
        let b = nf_bit(&w.key, l);
        pre = pair_by_bit(pre, w.siblings[l], b);
        post = pair_by_bit(post, w.siblings[l], b);
    }
    Some((pre, post, s))
}

/// NATIVE reference: `w` inserts its key under `pre_root` (non-membership holds there) → the returned root.
#[must_use]
pub fn native_compact_insert_transition(w: &CompactInsertWitness, pre_root: Digest) -> Option<Digest> {
    let (pre, post, _s) = native_compact_insert_folds(w)?;
    (pre == pre_root).then_some(post)
}

/// The first window level of a shape (`2^lb` rows per insert; row 0 is the leaf row).
#[must_use]
pub const fn compact_window_floor(lb: usize) -> usize {
    NF_SPARSE_DEPTH - (1 << lb) + 1
}

/// Does `w` fit the `lb` window — its terminal and its split both on a window row? (Natively valid witnesses only.)
#[must_use]
pub fn compact_window_fits(w: &CompactInsertWitness, lb: usize) -> bool {
    let floor = compact_window_floor(lb);
    match native_compact_insert_folds(w) {
        Some((_, _, s)) => w.t >= floor && s >= floor,
        None => false,
    }
}

/// The step's shape: NORMAL when every insert fits its window, else DEEP (docs/DB-453 §4.5).
#[must_use]
pub fn compact_step_lb(inserts: &[CompactInsertWitness]) -> usize {
    if inserts.iter().all(|w| compact_window_fits(w, COMPACT_LB_NORMAL)) {
        COMPACT_LB_NORMAL
    } else {
        COMPACT_LB_DEEP
    }
}

/// The REFERENCE compact tree: the spent key set, every node recomputed from it. For pins and node parity — the node keeps
/// its own leaf set and branch cache (`nf_sparse::RefSparseNf`).
#[derive(Clone, Default, Debug)]
pub struct CompactRefTree {
    /// Keys in PATH order (the key's bytes reversed: level 255 is the most significant bit).
    keys: std::collections::BTreeSet<[u8; 32]>,
}

fn path_order(key: &[u8; 32]) -> [u8; 32] {
    let mut p = *key;
    p.reverse();
    p
}

impl CompactRefTree {
    /// Is `key` in the set?
    #[must_use]
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(&path_order(key))
    }

    /// The set's size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// A shard's keys (key byte 31 = the shard), in path order.
    fn shard_keys(&self, shard: usize) -> Vec<[u8; 32]> {
        let mut lo = [0u8; 32];
        lo[0] = shard as u8;
        let mut hi = [0xFFu8; 32];
        hi[0] = shard as u8;
        self.keys.range(lo..=hi).map(path_order).collect()
    }

    /// The node at `level` of a subtree whose keys (in path order) share every bit `≥ level`.
    fn node(level: usize, keys: &[[u8; 32]]) -> Digest {
        match keys {
            [] => compact_empty(),
            [k] => compact_leaf(k),
            _ => {
                let cut = keys.partition_point(|k| nf_bit(k, level - 1) == 0);
                poseidon_pair_native(Self::node(level - 1, &keys[..cut]), Self::node(level - 1, &keys[cut..]))
            }
        }
    }

    /// The band: every shard's compact root at level 248.
    #[must_use]
    pub fn band(&self) -> Vec<Digest> {
        (0..NF_BAND_ENTRIES).map(|s| Self::node(NF_BAND_LEVEL, &self.shard_keys(s))).collect()
    }

    /// The root: the band folded plainly.
    #[must_use]
    pub fn root(&self) -> Digest {
        fold_band(&self.band()).expect("a full band")
    }

    /// The insert witness of a key NOT in the set. `None` for a member (a member has no non-membership witness).
    #[must_use]
    pub fn witness(&self, key: &[u8; 32]) -> Option<CompactInsertWitness> {
        if self.contains(key) {
            return None;
        }
        let shard = key[31] as usize;
        let mut siblings = vec![compact_empty(); NF_SPARSE_DEPTH];
        // the band's plain tower: the sibling of shard `s` at band level 248 + j
        let mut tower = self.band();
        for j in 0..(NF_SPARSE_DEPTH - NF_BAND_LEVEL) {
            siblings[NF_BAND_LEVEL + j] = tower[(shard >> j) ^ 1];
            tower = (0..tower.len() / 2).map(|i| poseidon_pair_native(tower[2 * i], tower[2 * i + 1])).collect();
        }
        let mut c = self.shard_keys(shard);
        let mut level = NF_BAND_LEVEL;
        while c.len() >= 2 {
            let cut = c.partition_point(|k| nf_bit(k, level - 1) == 0);
            let (left, right) = c.split_at(cut);
            let (mine, theirs) = if nf_bit(key, level - 1) == 0 { (left, right) } else { (right, left) };
            siblings[level - 1] = Self::node(level - 1, theirs);
            c = mine.to_vec();
            level -= 1;
        }
        Some(CompactInsertWitness { key: *key, t: level, other: c.first().copied(), siblings })
    }

    /// Insert `key` (idempotent on the set).
    pub fn insert(&mut self, key: &[u8; 32]) {
        self.keys.insert(path_order(key));
    }

    /// The witness, then the insert — the producer's sequential walk.
    pub fn insert_and_witness(&mut self, key: &[u8; 32]) -> Option<CompactInsertWitness> {
        let w = self.witness(key)?;
        self.insert(key);
        Some(w)
    }
}

// ── the key digest (ten lanes) ───────────────────────────────────────────────────────────────────────────────────────

/// The compact carrier's key-digest chain start — distinct from the 256-deep carrier's, so the two digests never meet.
#[must_use]
pub fn compact_keys_digest_init() -> Digest {
    crate::poseidon2_compress::lanes_of(&[0x0DB4_53, 0x4350_4354, 0x4b45_5953, 0x2026_1021])
}

fn lanes_f(lanes: &[u64; COMPACT_KEY_LANES]) -> [Fa4; COMPACT_KEY_LANES] {
    core::array::from_fn(|j| Fa4::from_u64(lanes[j]))
}

/// The two right-hand inputs an insert's lanes present to the digest chain: step 0 `L0..L7`, step 1 `(L8, L9, REAL|PAD, 0…)`
/// (zeros for a padding insert). Shared by the prover's lay and the door's native recompute.
fn compact_keys_digest_absorb_inputs(lanes: &[u64; COMPACT_KEY_LANES], live: bool) -> (Digest, Digest) {
    let r0: Digest = core::array::from_fn(|c| if live { lanes[c] } else { 0 });
    let mut r1 = [0u64; DIGEST_LANES];
    r1[0] = if live { lanes[8] } else { 0 };
    r1[1] = if live { lanes[9] } else { 0 };
    r1[2] = if live { crate::nf_sparse_air::KEYS_DIGEST_REAL } else { crate::nf_sparse_air::KEYS_DIGEST_PAD };
    (r0, r1)
}

/// The PUBLIC key digest of a step's insert list — `keys` the REAL keys in trace order, `n ≥ keys.len()` the trace's insert
/// count; the inserts past `keys.len()` absorb PAD (length-bound). The door recomputes it from the header's tags.
#[must_use]
pub fn compact_keys_digest_of(keys: &[[u8; 32]], n: usize) -> Digest {
    let mut st = compact_keys_digest_init();
    for i in 0..n {
        let live = i < keys.len();
        let lanes = if live { compact_key_lanes(&keys[i]) } else { EMPTY_TERMINAL_LANES };
        let (r0, r1) = compact_keys_digest_absorb_inputs(&lanes, live);
        st = poseidon_pair_native(st, r0);
        st = poseidon_pair_native(st, r1);
    }
    st
}

// ── the chain table ──────────────────────────────────────────────────────────────────────────────────────────────────

const P2: usize = crate::pow_pq_air::P2_COLS;
const C_SIB: usize = 0;
const C_SIBS: usize = C_SIB + DIGEST_LANES;
const C_DIR: usize = C_SIBS + DIGEST_LANES;
const C_DIR2: usize = C_DIR + 1;
const C_ORD: usize = C_DIR2 + 1;
const C_AINE: usize = C_ORD + 1;
const C_BLKE: usize = C_AINE + DIGEST_LANES;
const C_AOUTE: usize = C_BLKE + P2;
const C_AINS: usize = C_AOUTE + DIGEST_LANES;
const C_BLKS: usize = C_AINS + DIGEST_LANES;
const C_AOUTS: usize = C_BLKS + P2;
const C_A: usize = C_AOUTS + DIGEST_LANES;
const C_B: usize = C_A + 1;
const C_SPL: usize = C_B + 1;
const C_TK: usize = C_SPL + 1;
const C_RROOT: usize = C_TK + 1;
const C_KEY: usize = C_RROOT + DIGEST_LANES;
const C_K2: usize = C_KEY + COMPACT_KEY_LANES;
const C_KACC: usize = C_K2 + COMPACT_KEY_LANES;
const C_KACC2: usize = C_KACC + 1;
const C_LK: usize = C_KACC2 + 1;
const C_LK2: usize = C_LK + DIGEST_LANES;
const C_T2: usize = C_LK2 + DIGEST_LANES;
/// The chain table's width.
pub const COMPACT_CHAIN_COLS: usize = C_T2 + DIGEST_LANES;

/// The lanes whose every level lies on a row of the `lb` window — the lanes the window's bit streams recompose.
fn window_lanes(lb: usize) -> Vec<usize> {
    let base = NF_SPARSE_DEPTH - (1 << lb);
    (0..COMPACT_KEY_LANES).filter(|&j| COMPACT_LANE_RANGES[j].0 >= base).collect()
}

/// The chain table of a step (columns), its committed post (after the REAL inserts) and its key digest. `None` when the
/// count cannot be addressed (`n` not a power of two, `real_n` outside `1..=n`), an insert does not fold natively, does not
/// fit the `lb` window, or does not chain onto the running root — the native transition's refusals, exactly.
pub fn compact_chain_cols(
    inserts: &[CompactInsertWitness],
    block_pre: Digest,
    real_n: usize,
    lb: usize,
) -> Option<(Vec<Vec<Fa4>>, Digest, Digest)> {
    use rayon::prelude::*;
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() || real_n == 0 || real_n > n || !(COMPACT_LB_NORMAL..=COMPACT_LB_DEEP).contains(&lb) {
        return None;
    }
    let rows_per = 1usize << lb;
    let base = NF_SPARSE_DEPTH - rows_per;
    let wl = window_lanes(lb);
    let laid: Vec<Option<(Vec<Vec<Fa4>>, (Digest, Digest))>> = inserts
        .par_iter()
        .map(|w| {
            let (pre, post, s) = native_compact_insert_folds(w)?;
            let floor = base + 1;
            if w.t < floor || s < floor {
                return None; // the step needs the deep shape
            }
            let lanes = compact_key_lanes(&w.key);
            let lanes2 = match &w.other {
                Some(o) => compact_key_lanes(o),
                None => EMPTY_TERMINAL_LANES,
            };
            let tk = w.other.is_some();
            let lk = compact_leaf_of_lanes(&lanes);
            let lk2 = compact_leaf_of_lanes(&lanes2);
            let t2 = if tk { lk2 } else { compact_empty() };
            let bit2 = |l: usize| -> u64 {
                match &w.other {
                    Some(o) => u64::from(nf_bit(o, l)),
                    None => 0,
                }
            };
            let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(rows_per);
            let (mut prev_a, mut prev_b) = (false, false);
            let (mut aout_e, mut aout_s) = (compact_empty(), compact_empty());
            let (mut kacc, mut kacc2) = (0u64, 0u64);
            for r in 0..rows_per {
                let l = base + r;
                let mut row = vec![Fa4::ZERO; COMPACT_CHAIN_COLS];
                let dir = u64::from(nf_bit(&w.key, l));
                let dir2 = bit2(l);
                row[C_DIR] = Fa4::from_u64(dir);
                row[C_DIR2] = Fa4::from_u64(dir2);
                // the lane accumulators over the window's bit streams
                let lane_start = wl.iter().any(|&j| COMPACT_LANE_RANGES[j].0 == l);
                kacc = if lane_start { dir } else { (kacc << 1) | dir };
                kacc2 = if lane_start { dir2 } else { (kacc2 << 1) | dir2 };
                row[C_KACC] = Fa4::from_u64(kacc);
                row[C_KACC2] = Fa4::from_u64(kacc2);
                let (a, b, spl, ord, sib, sib_s, ain_e, ain_s);
                if r == 0 {
                    // the LEAF ROW: the E slot hashes leaf(k''), the S slot leaf(k), both in input order 0
                    let (l2, r2) = leaf_inputs(&lanes2);
                    let (l1, r1) = leaf_inputs(&lanes);
                    (a, b, spl, ord) = (false, false, false, 0u64);
                    (sib, sib_s, ain_e, ain_s) = (r2, r1, l2, l1);
                } else {
                    a = l >= w.t;
                    b = l >= s;
                    spl = l == s;
                    ord = dir;
                    sib = if a { w.siblings[l] } else { compact_empty() };
                    sib_s = if a {
                        sib
                    } else if spl {
                        t2
                    } else {
                        compact_empty()
                    };
                    ain_e = if prev_a { aout_e } else { t2 };
                    ain_s = if prev_b { aout_s } else { lk };
                }
                for c in 0..DIGEST_LANES {
                    row[C_SIB + c] = fkred(sib[c]);
                    row[C_SIBS + c] = fkred(sib_s[c]);
                }
                row[C_ORD] = Fa4::from_u64(ord);
                aout_e = crate::nf_sparse_air::emit_chain_row_at(&mut row, C_AINE, C_BLKE, C_AOUTE, ain_e, sib, ord);
                aout_s = crate::nf_sparse_air::emit_chain_row_at(&mut row, C_AINS, C_BLKS, C_AOUTS, ain_s, sib_s, ord);
                row[C_A] = Fa4::from_u64(u64::from(a));
                row[C_B] = Fa4::from_u64(u64::from(b));
                row[C_SPL] = Fa4::from_u64(u64::from(spl));
                row[C_TK] = Fa4::from_u64(u64::from(tk));
                for j in 0..COMPACT_KEY_LANES {
                    row[C_KEY + j] = Fa4::from_u64(lanes[j]);
                    row[C_K2 + j] = Fa4::from_u64(lanes2[j]);
                }
                for c in 0..DIGEST_LANES {
                    row[C_LK + c] = fkred(lk[c]);
                    row[C_LK2 + c] = fkred(lk2[c]);
                    row[C_T2 + c] = fkred(t2[c]);
                }
                prev_a = a;
                prev_b = b;
                rows.push(row);
            }
            // the trace's two chains end where the native folds do — the trace IS the native transition
            if aout_e != pre || aout_s != post {
                return None;
            }
            Some((rows, (pre, post)))
        })
        .collect();
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n * rows_per);
    let mut running = block_pre;
    let mut post_real = block_pre;
    for (idx, insert) in laid.into_iter().enumerate() {
        let (mut insert_rows, (pre, post)) = insert?;
        if pre != running {
            return None; // non-membership against the running root
        }
        for row in &mut insert_rows {
            for c in 0..DIGEST_LANES {
                row[C_RROOT + c] = fkred(running[c]);
            }
        }
        rows.extend(insert_rows);
        running = post;
        if idx + 1 == real_n {
            post_real = running;
        }
    }
    let cols: Vec<Vec<Fa4>> = (0..COMPACT_CHAIN_COLS).into_par_iter().map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    let keys: Vec<[u8; 32]> = inserts[..real_n].iter().map(|w| w.key).collect();
    Some((cols, post_real, compact_keys_digest_of(&keys, n)))
}

/// `[row in insert == r]` over the low `lb` coordinates of the point (MSB first).
fn row_is<F: p3_field::Field>(x: &[F], lb: usize, r: usize) -> F {
    let nvars = x.len();
    let mut p = F::ONE;
    for (b, x_k) in x[nvars - lb..].iter().enumerate() {
        let bit = (r >> (lb - 1 - b)) & 1;
        p *= if bit == 1 { *x_k } else { F::ONE - *x_k };
    }
    p
}

/// `[insert index == m]` over the high coordinates (MSB first).
fn insert_is<F: p3_field::Field>(x: &[F], low_bits: usize, m: usize) -> F {
    let high = x.len() - low_bits;
    let mut p = F::ONE;
    for (k, x_k) in x.iter().take(high).enumerate() {
        let bit = (m >> (high - 1 - k)) & 1;
        p *= if bit == 1 { *x_k } else { F::ONE - *x_k };
    }
    p
}

/// The power table both gates batch their residuals with: two permutation blocks plus 512 laws of slack.
#[must_use]
pub fn compact_powers(gamma: Ea4) -> Vec<Ea4> {
    let n = 2 * crate::pow_pq_air::perm_residual_count() + 512;
    let mut v = Vec::with_capacity(n);
    let mut p = Ea4::ONE;
    for _ in 0..n {
        v.push(p);
        p *= gamma;
    }
    v
}

type Ext = crate::hiding_decider::Ea4;

/// The chain table's gate (docs/DB-453 §4.4, laws 1–8).
pub struct CompactChainGate {
    pub lb: usize,
    pub block_pre: [Fa4; DIGEST_LANES],
    pub block_post: [Fa4; DIGEST_LANES],
    pub bind_at: usize,
    pub gpow: Vec<Ea4>,
}

impl CompactChainGate {
    #[must_use]
    pub fn new(gamma: Ea4, lb: usize, block_pre: [Fa4; DIGEST_LANES], block_post: [Fa4; DIGEST_LANES], bind_at: usize) -> Self {
        Self { lb, block_pre, block_post, bind_at, gpow: compact_powers(gamma) }
    }

    /// The laws, generic over the row's field (base-field round 0 and the extension), like `SparseBlockGate::eval_in`.
    #[allow(non_camel_case_types, clippy::too_many_lines)]
    pub fn eval_in<Ea4>(&self, local: &crate::air_zerocheck::Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let lb = self.lb;
        let base = NF_SPARSE_DEPTH - (1usize << lb);
        let mut rs: Vec<Ea4> = Vec::new();
        // law 1: both permutation blocks, inputs ordered by ORD, outputs welded
        push_chain_residuals_at(local, C_SIB, C_ORD, C_AINE, C_BLKE, C_AOUTE, &mut rs);
        push_chain_residuals_at(local, C_SIBS, C_ORD, C_AINS, C_BLKS, C_AOUTS, &mut rs);
        let (a, b, spl, tk) = (local[C_A], local[C_B], local[C_SPL], local[C_TK]);
        let (dir, dir2, ord) = (local[C_DIR], local[C_DIR2], local[C_ORD]);
        // laws 3/4: booleans and the terminal laws (selector-free, column degree ≤ 3)
        for v in [dir, dir2, ord, a, b, spl, tk] {
            rs.push(v * (one - v));
        }
        rs.push(a * (one - b));
        rs.push((one - tk) * (b - a));
        rs.push(tk * spl * a);
        rs.push(tk * (b - spl) * (dir - dir2));
        rs.push(tk * spl * (dir + dir2 - one));
        rs.push((one - tk) * dir2);
        for j in 0..COMPACT_KEY_LANES {
            rs.push((one - tk) * local[C_K2 + j]);
        }
        for c in 0..DIGEST_LANES {
            rs.push(local[C_T2 + c] - tk * local[C_LK2 + c]);
        }
        // selectors
        let nvars = x.len();
        let is_row0 = row_is(x, lb, 0);
        let mut is_boundary = one;
        for x_k in &x[nvars - lb..] {
            is_boundary *= *x_k;
        }
        let not_boundary = one - is_boundary;
        let not_row0 = one - is_row0;
        let high = nvars - lb;
        let mut is_first_insert = one;
        let mut is_last_insert = one;
        for x_k in x.iter().take(high) {
            is_first_insert *= one - *x_k;
            is_last_insert *= *x_k;
        }
        let bind_sel = insert_is(x, lb, self.bind_at);
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        // ORD: 0 on the leaf row, the key's bit on every tree row
        rs.push(is_row0 * ord);
        rs.push(not_row0 * (ord - dir));
        // law 2: the leaf row
        let dl = Ea4::from(Fa4::from_u64(COMPACT_LEAF_DOMAIN));
        for c in 0..DIGEST_LANES {
            rs.push(is_row0 * (local[C_AINE + c] - local[C_K2 + c]));
            rs.push(is_row0 * (local[C_AINS + c] - local[C_KEY + c]));
            let (want2, want) = match c {
                0 => (local[C_K2 + 8], local[C_KEY + 8]),
                1 => (local[C_K2 + 9], local[C_KEY + 9]),
                2 => (dl, dl),
                _ => (zero, zero),
            };
            rs.push(is_row0 * (local[C_SIB + c] - want2));
            rs.push(is_row0 * (local[C_SIBS + c] - want));
            rs.push(is_row0 * (local[C_LK2 + c] - local[C_AOUTE + c]));
            rs.push(is_row0 * (local[C_LK + c] - local[C_AOUTS + c]));
        }
        rs.push(is_row0 * a);
        rs.push(is_row0 * b);
        rs.push(is_row0 * spl);
        // law 5: the tree rows' siblings
        for c in 0..DIGEST_LANES {
            rs.push(not_row0 * (one - a) * local[C_SIB + c]);
            rs.push(not_row0 * (local[C_SIBS + c] - a * local[C_SIB + c] - spl * local[C_T2 + c]));
        }
        // law 3: the band rows hash (A = 1 from level 248)
        rs.push(row_is(x, lb, NF_BAND_LEVEL - base) * (one - a));
        // laws 3 + 6: the transitions inside an insert
        let a_n = at(C_A, &sigma);
        let b_n = at(C_B, &sigma);
        rs.push(not_boundary * a * (one - a_n));
        rs.push(not_boundary * b * (one - b_n));
        rs.push(not_boundary * (at(C_SPL, &sigma) - (b_n - b)));
        for c in 0..DIGEST_LANES {
            rs.push(not_boundary * (at(C_AINE + c, &sigma) - a * local[C_AOUTE + c] - (one - a) * local[C_T2 + c]));
            rs.push(not_boundary * (at(C_AINS + c, &sigma) - b * local[C_AOUTS + c] - (one - b) * local[C_LK + c]));
        }
        // frozen within an insert
        for col in Self::frozen_cols() {
            rs.push(not_boundary * (at(col, &sigma) - local[col]));
        }
        // law 7: the boundary (level 255) — non-membership, the running root, the committed endpoints
        for c in 0..DIGEST_LANES {
            let rr = local[C_RROOT + c];
            let aos = local[C_AOUTS + c];
            rs.push(is_boundary * (local[C_AOUTE + c] - rr));
            rs.push(is_first_insert * (rr - Ea4::from(self.block_pre[c])));
            rs.push(bind_sel * is_boundary * (aos - Ea4::from(self.block_post[c])));
            rs.push(is_boundary * (one - is_last_insert) * (at(C_RROOT + c, &sigma) - aos));
        }
        // law 8: the window lanes, recomposed from the two bit streams
        let mut end_any = zero;
        for j in window_lanes(lb) {
            let (s0, e0) = COMPACT_LANE_RANGES[j];
            let start = row_is(x, lb, s0 - base);
            let end = row_is(x, lb, e0 - base);
            end_any += end;
            rs.push(start * (local[C_KACC] - dir));
            rs.push(start * (local[C_KACC2] - dir2));
            rs.push(end * (local[C_KEY + j] - local[C_KACC]));
            rs.push(end * (local[C_K2 + j] - local[C_KACC2]));
        }
        rs.push((one - end_any) * (at(C_KACC, &sigma) - local[C_KACC] - local[C_KACC] - at(C_DIR, &sigma)));
        rs.push((one - end_any) * (at(C_KACC2, &sigma) - local[C_KACC2] - local[C_KACC2] - at(C_DIR2, &sigma)));
        let mut out = Ext::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }

    /// The columns frozen within an insert.
    fn frozen_cols() -> Vec<usize> {
        let mut v = vec![C_TK];
        v.extend(C_RROOT..C_RROOT + DIGEST_LANES);
        v.extend(C_KEY..C_KEY + COMPACT_KEY_LANES);
        v.extend(C_K2..C_K2 + COMPACT_KEY_LANES);
        v.extend(C_LK..C_LK + DIGEST_LANES);
        v.extend(C_LK2..C_LK2 + DIGEST_LANES);
        v.extend(C_T2..C_T2 + DIGEST_LANES);
        v
    }

    /// The columns any law reads on the NEXT row.
    fn next_read_cols() -> Vec<usize> {
        let mut v = Self::frozen_cols();
        v.extend([C_A, C_B, C_SPL, C_KACC, C_KACC2, C_DIR, C_DIR2]);
        v.extend(C_AINE..C_AINE + DIGEST_LANES);
        v.extend(C_AINS..C_AINS + DIGEST_LANES);
        v.sort_unstable();
        v
    }
}

impl crate::air_zerocheck::AirConstraint for CompactChainGate {
    fn degree(&self, _nvars: usize) -> usize {
        // the permutation's cube and the terminal laws' three columns; every selected law is ≤ 2 in columns — asserted by
        // the degree census (`db453_d_…`), never inherited
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        self.eval_in::<Ea4>(local, at, x)
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let at2 = |c: usize, _p: &[Fa4]| -> Fa4 { at(c) };
        self.eval_in::<Fa4>(local, &at2, x)
    }
    /// Every column is read by a law.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some(Self::next_read_cols())
    }
}

// ── the digest table ─────────────────────────────────────────────────────────────────────────────────────────────────

const D_KEY: usize = 0;
const D_LIVE: usize = D_KEY + COMPACT_KEY_LANES;
const D_DIN: usize = D_LIVE + 1;
const D_BLK: usize = D_DIN + DIGEST_LANES;
/// The digest table's width.
pub const COMPACT_DIGEST_COLS: usize = D_BLK + P2;
const D_STEP_BITS: usize = 1;

/// The digest table: two rows per insert absorbing its ten lanes exactly as [`compact_keys_digest_of`] folds them.
pub fn compact_digest_cols(inserts: &[CompactInsertWitness], real_n: usize) -> Option<(Vec<Vec<Fa4>>, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() || real_n == 0 || real_n > n {
        return None;
    }
    let mut din = compact_keys_digest_init();
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n << D_STEP_BITS);
    for (idx, w) in inserts.iter().enumerate() {
        let lanes = compact_key_lanes(&w.key);
        let live = idx < real_n;
        let (r0, r1) = compact_keys_digest_absorb_inputs(&lanes, live);
        for right in [r0, r1] {
            let mut row = vec![Fa4::ZERO; COMPACT_DIGEST_COLS];
            row[D_KEY..D_KEY + COMPACT_KEY_LANES].copy_from_slice(&lanes_f(&lanes));
            row[D_LIVE] = Fa4::from_u64(u64::from(live));
            for c in 0..DIGEST_LANES {
                row[D_DIN + c] = fkred(din[c]);
            }
            crate::pow_pq_air::lay_perm_row_flat(&mut row, D_BLK, crate::pow_pq_air::pair_state(&din, &right));
            din = poseidon_pair_native(din, right);
            rows.push(row);
        }
    }
    let cols: Vec<Vec<Fa4>> = (0..COMPACT_DIGEST_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    Some((cols, din))
}

/// The digest table's gate: the ten-lane twin of `SparseKeysDigestGate` (the live laws, the frozen lanes, the chain from
/// [`compact_keys_digest_init`] to the PUBLIC digest).
pub struct CompactDigestGate {
    pub gpow: Vec<Ea4>,
    pub bind_at: usize,
    pub keys_digest: [Fa4; DIGEST_LANES],
}

impl CompactDigestGate {
    #[allow(non_camel_case_types)]
    pub fn eval_in<Ea4>(&self, local: &crate::air_zerocheck::Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let nvars = x.len();
        let high = nvars - D_STEP_BITS;
        let s1 = x[nvars - 1];
        let s0 = one - s1;
        let mut is_first_insert = one;
        let mut is_last_insert = one;
        for x_k in x.iter().take(high) {
            is_first_insert *= one - *x_k;
            is_last_insert *= *x_k;
        }
        let bind_sel = insert_is(x, D_STEP_BITS, self.bind_at);
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let mut rs: Vec<Ea4> = Vec::new();
        crate::pow_pq_air::push_perm_residuals(local, D_BLK, &mut rs);
        let live = local[D_LIVE];
        let live_n = at(D_LIVE, &sigma);
        rs.push(is_first_insert * s0 * (live - one));
        rs.push(s0 * (live_n - live));
        rs.push(s1 * (one - is_last_insert) * (live_n - live + bind_sel));
        for j in 0..COMPACT_KEY_LANES {
            rs.push(s0 * (at(D_KEY + j, &sigma) - local[D_KEY + j]));
        }
        let init = compact_keys_digest_init();
        let real_d = Ea4::from(Fa4::from_u64(crate::nf_sparse_air::KEYS_DIGEST_REAL));
        let pad_d = Ea4::from(Fa4::from_u64(crate::nf_sparse_air::KEYS_DIGEST_PAD));
        let last_row = s1 * is_last_insert;
        for c in 0..DIGEST_LANES {
            let din = local[D_DIN + c];
            let left = local[D_BLK + c];
            let right = local[D_BLK + DIGEST_LANES + c];
            let out_c = local[D_BLK + crate::pow_pq_air::PERM_OUT + c];
            rs.push(is_first_insert * s0 * (din - Ea4::from(fkred(init[c]))));
            rs.push(left - din);
            let r0 = live * local[D_KEY + c];
            let r1 = match c {
                0 => live * local[D_KEY + 8],
                1 => live * local[D_KEY + 9],
                2 => pad_d + live * (real_d - pad_d),
                _ => zero,
            };
            rs.push(right - (s0 * r0 + s1 * r1));
            rs.push((one - last_row) * (at(D_DIN + c, &sigma) - out_c));
            rs.push(last_row * (out_c - Ea4::from(self.keys_digest[c])));
        }
        let mut out = Ext::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }
}

impl crate::air_zerocheck::AirConstraint for CompactDigestGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        self.eval_in::<Ea4>(local, at, x)
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let at2 = |c: usize, _p: &[Fa4]| -> Fa4 { at(c) };
        self.eval_in::<Fa4>(local, &at2, x)
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let mut v = vec![D_LIVE];
        v.extend(D_KEY..D_KEY + COMPACT_KEY_LANES);
        v.extend(D_DIN..D_DIN + DIGEST_LANES);
        v.sort_unstable();
        Some(v)
    }
}

/// The carrier's two tables' gates under one constraint type (table 0 = the chain, table 1 = the digest).
pub enum CompactBandGate {
    Chain(CompactChainGate),
    Digest(CompactDigestGate),
}

impl CompactBandGate {
    #[must_use]
    pub fn for_table(
        i: usize,
        gamma: Ea4,
        lb: usize,
        block_pre: [Fa4; DIGEST_LANES],
        block_post: [Fa4; DIGEST_LANES],
        bind_at: usize,
        keys_digest: [Fa4; DIGEST_LANES],
    ) -> Self {
        if i == 0 {
            Self::Chain(CompactChainGate::new(gamma, lb, block_pre, block_post, bind_at))
        } else {
            Self::Digest(CompactDigestGate { gpow: compact_powers(gamma), bind_at, keys_digest })
        }
    }
}

impl crate::air_zerocheck::AirConstraint for CompactBandGate {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Chain(g) => g.degree(nvars),
            Self::Digest(g) => g.degree(nvars),
        }
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Chain(g) => g.eval(local, at, x),
            Self::Digest(g) => g.eval(local, at, x),
        }
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            Self::Chain(g) => g.eval_base(local, at, x),
            Self::Digest(g) => g.eval_base(local, at, x),
        }
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Chain(g) => g.free_columns(),
            Self::Digest(g) => g.free_columns(),
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Chain(g) => g.shifted_cols(),
            Self::Digest(g) => g.shifted_cols(),
        }
    }
}

// ── the carrier ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// The compact band carrier's statement domain — distinct from every 256-deep carrier's.
pub const NF_COMPACT_DOMAIN: u64 = 0x4e46_4350_4354;

fn compact_statement_bind(pre: &[Fa4; DIGEST_LANES], post: &[Fa4; DIGEST_LANES], n: usize, kd: &[Fa4; DIGEST_LANES], lb: usize) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_COMPACT_DOMAIN)];
    b.extend_from_slice(pre);
    b.extend_from_slice(post);
    b.push(Fa4::from_u64(n as u64));
    b.extend_from_slice(kd);
    b.push(Fa4::from_u64(lb as u64));
    b
}

/// The ONE column tie: the chain table's ten frozen key lanes at an insert's boundary row equal the digest table's at the
/// insert's first absorb step.
fn compact_column_tie(lb: usize) -> crate::whir_rec_block::ColumnTieSpec {
    (
        (0, (C_KEY..C_KEY + COMPACT_KEY_LANES).collect(), lb, (1 << lb) - 1),
        (1, (D_KEY..D_KEY + COMPACT_KEY_LANES).collect(), D_STEP_BITS, 0),
    )
}

/// The carrier's two committed tables, its committed post and its key digest — the ONE lay the prover and every pin build.
pub fn compact_band_tables(
    inserts: &[CompactInsertWitness],
    block_pre: Digest,
    real_n: usize,
    lb: usize,
) -> Option<(Vec<Vec<Vec<Fa4>>>, Digest, Digest)> {
    let (chain, post, digest) = compact_chain_cols(inserts, block_pre, real_n, lb)?;
    let (dg, end) = compact_digest_cols(inserts, real_n)?;
    if end != digest {
        return None;
    }
    Some((vec![chain, dg], post, digest))
}

fn to_f(d: &Digest) -> [Fa4; DIGEST_LANES] {
    core::array::from_fn(|i| fkred(d[i]))
}

/// PROVE a step's compact transition at window `lb` on the BOUND batch engine: `(carrier, post, keys_digest)`. `None` on an
/// invalid insert, a count the layout cannot address, or an insert outside the window (the step needs the deep shape).
pub fn prove_compact_band_carrier_bytes(
    inserts: &[CompactInsertWitness],
    block_pre: Digest,
    real_n: usize,
    lb: usize,
) -> Option<(Vec<u8>, Digest, Digest)> {
    let (tables, post, kd) = compact_band_tables(inserts, block_pre, real_n, lb)?;
    let (pre_f, post_f, kd_f) = (to_f(&block_pre), to_f(&post), to_f(&kd));
    let bind_at = real_n - 1;
    let make = move |i: usize, g: Ea4| CompactBandGate::for_table(i, g, lb, pre_f, post_f, bind_at, kd_f);
    let carrier = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make,
        Vec::new(),
        Vec::new(),
        vec![compact_column_tie(lb)],
        &compact_statement_bind(&pre_f, &post_f, inserts.len(), &kd_f, lb),
    )?;
    Some((carrier, post, kd))
}

/// The two table shapes of an `n`-insert carrier at window `lb` — built by the DOOR, never read off a carrier.
fn compact_shapes(n: usize, lb: usize) -> Option<[(usize, usize); 2]> {
    let rows = n.checked_mul(1usize << lb)?;
    let dg_rows = n.checked_mul(1usize << D_STEP_BITS)?;
    Some([(rows.trailing_zeros() as usize, COMPACT_CHAIN_COLS), (dg_rows.trailing_zeros() as usize, COMPACT_DIGEST_COLS)])
}

/// VERIFY a compact band carrier against `(pre, post, n_real, n, keys_digest, lb)` — every value DERIVED by the door.
#[must_use]
pub fn verify_compact_band_carrier_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    n_real: usize,
    n: usize,
    keys_digest: Digest,
    lb: usize,
) -> bool {
    if bytes.is_empty() || n == 0 || !n.is_power_of_two() || n_real == 0 || n_real > n || !(lb == COMPACT_LB_NORMAL || lb == COMPACT_LB_DEEP) {
        return false;
    }
    let (pre_f, post_f, kd_f) = (to_f(&block_pre), to_f(&block_post), to_f(&keys_digest));
    let bind_at = n_real - 1;
    let Some(shapes) = compact_shapes(n, lb) else { return false };
    let make = move |i: usize, g: Ea4| CompactBandGate::for_table(i, g, lb, pre_f, post_f, bind_at, kd_f);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make,
        Vec::new(),
        vec![compact_column_tie(lb)],
        &compact_statement_bind(&pre_f, &post_f, n, &kd_f, lb),
        &shapes,
        &[],
    )
}

/// VERIFY a compact band carrier at whichever shape it was proven in (docs/DB-453 §4.5: the shape is the prover's free
/// choice, bound in the transcript): the NORMAL shape first, the DEEP shape only when the normal one refuses. Either
/// verifies only the statement the door derived — the shape grants the prover nothing — and a refused carrier costs two
/// O(1) verifies.
#[must_use]
pub fn verify_compact_band_carrier_any_shape(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    n_real: usize,
    n: usize,
    keys_digest: Digest,
) -> bool {
    [COMPACT_LB_NORMAL, COMPACT_LB_DEEP]
        .iter()
        .any(|&lb| verify_compact_band_carrier_bytes(bytes, block_pre, block_post, n_real, n, keys_digest, lb))
}

// ── the band step: k chained compact slices (the twins of `nf_sparse_air::prove_band_slices` / `verify_band_slice`) ──

/// A chunk's compact inserts applied NATIVELY over `pre`: the committed post (the root after the `real`-th insert; the
/// padding inserts past it advance only the running root) and the chunk's key digest at its insert count. `None` when any
/// insert does not transition (a forged or stale witness never reaches a trace).
#[must_use]
pub fn compact_post_native(chunk: &[CompactInsertWitness], pre: Digest, real: usize) -> Option<(Digest, Digest)> {
    if real == 0 || real > chunk.len() {
        return None;
    }
    let mut root = pre;
    let mut post = pre;
    for (i, w) in chunk.iter().enumerate() {
        root = native_compact_insert_transition(w, root)?;
        if i + 1 == real {
            post = root;
        }
    }
    let keys: Vec<[u8; 32]> = chunk[..real].iter().map(|w| w.key).collect();
    Some((post, compact_keys_digest_of(&keys, chunk.len())))
}

/// ONE compact band slice, proven at the shape its inserts fit ([`compact_step_lb`]) — or, under the bound double, its
/// post computed natively and its bytes bound to the slice's whole public statement.
fn compact_slice_prove(chunk: &[CompactInsertWitness], pre: Digest, real: usize, bound: bool) -> Option<(Vec<u8>, Digest)> {
    if bound {
        return compact_band_bound::prove(chunk, pre, real);
    }
    let (bytes, post, _kd) = prove_compact_band_carrier_bytes(chunk, pre, real, compact_step_lb(chunk))?;
    Some((bytes, post))
}

/// ONE compact band slice, verified against the values the DOOR derived.
fn compact_slice_verify(bytes: &[u8], pre: Digest, post: Digest, n_real: usize, n: usize, keys_digest: Digest, bound: bool) -> bool {
    if bound {
        return compact_band_bound::verify(bytes, pre, post, n_real, n, keys_digest);
    }
    verify_compact_band_carrier_any_shape(bytes, pre, post, n_real, n, keys_digest)
}

/// ⭐ DB-453 — PROVE THE CHOSEN SLICES of a block's compact fold transition: the `k` contiguous chunks of the shard-major
/// ordered inserts (`inserts.len()` = the cover, admitted reals first, padding witnesses after), each proven against the
/// running root its predecessor left (computed NATIVELY for an unchosen slice). Returns `(index, post, bytes)` for each
/// chosen slice, ascending; a slice with no admitted key is returned with no bytes and `post == pre`. The 256-deep
/// [`crate::nf_sparse_air::prove_band_slices`]'s contract, on the compact carrier.
#[must_use]
pub fn prove_compact_band_slices(
    inserts: &[CompactInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    prove_compact_band_slices_with(inserts, fold_pre, admitted, k, chosen, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_compact_band_slices`] with the BOUND band-step double ([`compact_band_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn prove_compact_band_slices_bound(
    inserts: &[CompactInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    prove_compact_band_slices_with(inserts, fold_pre, admitted, k, chosen, true)
}

fn prove_compact_band_slices_with(
    inserts: &[CompactInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
    bound: bool,
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    let cover = crate::nf_sparse_air::PRODUCTION_BLOCK_COVER;
    if inserts.len() != cover || admitted == 0 || admitted > inserts.len() || k == 0 || !k.is_power_of_two() || k > cover {
        return None;
    }
    if chosen.iter().any(|i| *i >= k) || chosen.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    let per = cover / k;
    let mut out = Vec::with_capacity(chosen.len());
    let mut pre = fold_pre;
    for i in 0..k {
        let lo = i * per;
        let real = admitted.saturating_sub(lo).min(per);
        if real == 0 {
            if chosen.contains(&i) {
                out.push((i, pre, Vec::new()));
            }
            continue;
        }
        let post = if chosen.contains(&i) {
            let (bytes, post) = compact_slice_prove(&inserts[lo..lo + per], pre, real, bound)?;
            out.push((i, post, bytes));
            post
        } else {
            compact_post_native(&inserts[lo..lo + per], pre, real)?.0
        };
        pre = post;
    }
    Some(out)
}

/// ⭐ DB-453 — VERIFY ONE carried compact slice against values the DOOR derived: its `pre`, its chunk of the shard-major
/// ordered admitted KEYS (`nf_sparse_air::band_slices(.., k)[i]`) and its claimed `post`. A chunk with no admitted key must
/// carry no bytes and claim `post == pre`.
#[must_use]
pub fn verify_compact_band_slice(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8]) -> bool {
    verify_compact_band_slice_with(pre, post, chunk, k, bytes, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_compact_band_slice`] with the BOUND band-step double ([`compact_band_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_compact_band_slice_bound(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8]) -> bool {
    verify_compact_band_slice_with(pre, post, chunk, k, bytes, true)
}

fn verify_compact_band_slice_with(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8], bound: bool) -> bool {
    let cover = crate::nf_sparse_air::PRODUCTION_BLOCK_COVER;
    if k == 0 || !k.is_power_of_two() || k > cover {
        return false;
    }
    if chunk.is_empty() {
        return bytes.is_empty() && post == pre;
    }
    let per = cover / k;
    compact_slice_verify(bytes, pre, post, chunk.len(), per, compact_keys_digest_of(chunk, per), bound)
}

/// ⭐ DB-453 — VERIFY a block's compact fold transition carried as chained slices against values the DOOR derived: the
/// fold-point root, the post the band must fold to, and the shard-major ordered admitted KEYS. Fail-closed on any broken
/// link, wrong digest or count, or a carried slice that should be empty.
#[must_use]
pub fn verify_compact_chained_band_transition(
    fold_pre: Digest,
    post: Digest,
    ordered_keys: &[[u8; 32]],
    slices: &[crate::nf_sparse_air::BandSlice<'_>],
) -> bool {
    let k = slices.len();
    let Some(chunks) = crate::nf_sparse_air::band_slices(ordered_keys, k) else { return false };
    let mut pre = fold_pre;
    for (chunk, slice) in chunks.iter().zip(slices) {
        if !verify_compact_band_slice(pre, slice.post, chunk, k, slice.bytes) {
            return false;
        }
        pre = slice.post;
    }
    pre == post
}

/// ⭐⭐⭐ THE BOUND COMPACT BAND-STEP DOUBLE — the test double of the compact band PROVER, the same law as the 256-deep
/// carrier's (`nf_sparse_air::band_bound`): the post is computed NATIVELY over the same inserts the real prover traces
/// ([`compact_post_native`] — every insert must transition), and the bytes are a domain-separated digest of the real
/// verifier's public inputs `(pre, post, n_real, n, keys_digest)`, so a moved root, a different key chunk or count, or a
/// flipped byte is REFUSED exactly as the real door refuses it. It drops only the WHIR proof; this crate's compact pins
/// (`db453_*`, never bound) carry that soundness. Test builds only: a node binary's bound arms refuse outright, and a
/// bound slice never passes the real verifier.
mod compact_band_bound {
    use super::{CompactInsertWitness, Digest};

    #[cfg(any(test, feature = "test-support"))]
    fn bytes(pre: &Digest, post: &Digest, n_real: usize, n: usize, keys_digest: &Digest) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-bound-compact-band-step/v1");
        for d in [pre, post, keys_digest] {
            for x in d.iter() {
                h.update(&x.to_le_bytes());
            }
        }
        h.update(&(n_real as u64).to_le_bytes());
        h.update(&(n as u64).to_le_bytes());
        h.finalize().as_bytes().to_vec()
    }

    pub(super) fn prove(chunk: &[CompactInsertWitness], pre: Digest, real: usize) -> Option<(Vec<u8>, Digest)> {
        #[cfg(any(test, feature = "test-support"))]
        {
            let (post, kd) = super::compact_post_native(chunk, pre, real)?;
            Some((bytes(&pre, &post, real, chunk.len(), &kd), post))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (chunk, pre, real);
            None
        }
    }

    pub(super) fn verify(b: &[u8], pre: Digest, post: Digest, n_real: usize, n: usize, keys_digest: Digest) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            b == bytes(&pre, &post, n_real, n, &keys_digest).as_slice()
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (b, pre, post, n_real, n, keys_digest);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nf_sparse_air::PRODUCTION_BLOCK_COVER;

    /// A real-shaped tree key: a blake3 digest with key byte 0 zero (a real tag's byte 31 is always zero).
    fn key_from(seed: u64) -> [u8; 32] {
        let mut k = *blake3::hash(&[b"db453.key".as_slice(), &seed.to_le_bytes()].concat()).as_bytes();
        k[0] = 0;
        k
    }

    fn build(keys: &[[u8; 32]], tree: &mut CompactRefTree) -> Vec<CompactInsertWitness> {
        keys.iter().map(|k| tree.insert_and_witness(k).expect("a fresh key has a witness")).collect()
    }

    /// The deep fixture: `a` in the tree, then a production-cover step whose FIRST key `b` differs from `a` only at level
    /// 164 — below the normal window's floor (193) — and whose other keys are fresh.
    fn deep_step() -> (Digest, Vec<[u8; 32]>, Vec<CompactInsertWitness>, CompactRefTree, [u8; 32]) {
        let a = key_from(5);
        let mut b = a;
        b[20] ^= 0x10;
        let mut tree = CompactRefTree::default();
        tree.insert(&a);
        let pre = tree.root();
        let mut keys = vec![b];
        keys.extend((1..PRODUCTION_BLOCK_COVER as u64).map(|i| key_from(7_000 + i)));
        let inserts = build(&keys, &mut tree);
        assert_eq!(inserts[0].other, Some(a), "b's terminal is a's leaf");
        (pre, keys, inserts, tree, a)
    }

    /// T1 — THE DEFINITION. The compact root is a function of the SET (two insert orders, one root, and each equals the
    /// from-scratch recompute); every witness's native transition advances the running root to the recompute after it;
    /// and the native transition REFUSES a re-spend, a terminal claimed one level off either way, the wrong terminal kind,
    /// a wrong terminal key, and a forged sibling.
    #[test]
    fn db453_a_the_compact_root_is_a_set_function_and_the_native_transition_refuses_every_forgery() {
        let keys: Vec<[u8; 32]> = (0..600u64).map(key_from).collect();
        let mut t1 = CompactRefTree::default();
        let mut running = t1.root();
        assert_eq!(running, fold_band(&vec![compact_empty(); NF_BAND_ENTRIES]).unwrap(), "the empty tree is the empty band");
        let mut leafy = 0usize;
        for k in &keys {
            let w = t1.witness(k).expect("witness");
            leafy += usize::from(w.other.is_some());
            let post = native_compact_insert_transition(&w, running).expect("an honest insert folds");
            t1.insert(k);
            assert_eq!(post, t1.root(), "the transition lands on the recomputed root");
            running = post;
        }
        let mut t2 = CompactRefTree::default();
        for k in keys.iter().rev() {
            t2.insert(k);
        }
        assert_eq!(t1.root(), t2.root(), "two insert orders, one root — the accumulator is a SET function");
        assert!(leafy > 0, "CALIBRATION: some inserts met a one-key terminal (the split path ran)");
        eprintln!("[db453-a] 600 keys: {leafy} inserts met a leaf terminal");

        // the forgeries, against the 600-key root
        let fresh = key_from(10_000);
        let honest = t1.witness(&fresh).expect("a fresh witness");
        assert!(native_compact_insert_transition(&honest, running).is_some(), "the honest witness folds");
        // a re-spend: an existing key's own position, its terminal claimed as itself
        let spent = keys[17];
        let mut w = t1.witness(&key_from(77_777)).expect("w");
        w.key = spent;
        w.other = Some(spent);
        assert!(native_compact_insert_transition(&w, running).is_none(), "a re-spend has no split — refused");
        // the terminal one level off either way
        for dt in [-1i64, 1] {
            let mut f = honest.clone();
            f.t = (f.t as i64 + dt) as usize;
            assert!(native_compact_insert_transition(&f, running).is_none(), "a terminal at t{dt:+} misses the root");
        }
        // the wrong kind and the wrong terminal key
        let mut f = honest.clone();
        f.other = if honest.other.is_some() { None } else { Some(keys[3]) };
        assert!(native_compact_insert_transition(&f, running).is_none(), "the wrong terminal kind misses the root");
        if let Some(mut o) = honest.other {
            let mut f = honest.clone();
            o[1] ^= 1;
            f.other = Some(o);
            assert!(native_compact_insert_transition(&f, running).is_none(), "a wrong terminal key misses the root");
        }
        // a forged sibling
        let mut f = honest.clone();
        f.siblings[honest.t][0] ^= 1;
        assert!(native_compact_insert_transition(&f, running).is_none(), "a forged sibling misses the root");
    }

    /// ⭐ A-F56 DECIDER PROBE — IS A BAND-STEP REFUSAL EVER THE DECIDER'S? Real nodes logged honest band steps refused
    /// ("the step's slices or band_post do not verify"), 22 relayed and 2 own in three days; the own ones followed a fold
    /// rewind (a stale proof). This asks the decider alone, with no node state in the way: honest steps across tree sizes
    /// (empty to 20k keys), admitted counts (1 to the full 256 cover) and chain widths `k`, each proved by the producer's
    /// own entry (`prove_compact_band_slices`) and verified slice by slice, chained pre to post, by the DOOR's own entry
    /// (`verify_compact_band_slice`) against the door's chunking (`nf_sparse_air::band_slices`). Any refusal here is a
    /// decider fault; none means a refusal on a real node is a disagreement about the step's pre-state, not the proof.
    #[test]
    fn af56_every_honest_band_step_verifies_at_the_door_across_tree_sizes_counts_and_widths() {
        let shapes: [(usize, usize, usize); 11] =
            [(0, 1, 1), (0, 7, 2), (0, 256, 4), (500, 3, 1), (500, 64, 8), (500, 255, 4), (20_000, 1, 2), (20_000, 200, 8), (20_000, 256, 16), (3, 129, 4), (1_000, 33, 32)];
        let (mut slices_checked, mut real_slices) = (0usize, 0usize);
        let mut refused: Vec<String> = Vec::new();
        for (ti, &(prior_n, admitted, k)) in shapes.iter().enumerate() {
            let mut tree = CompactRefTree::default();
            for i in 0..prior_n {
                tree.insert(&key_from(90_000_000 + ti as u64 * 100_000 + i as u64));
            }
            let pre = tree.root();
            let keys: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64).map(|i| key_from(10_000_000 + ti as u64 * 1_000 + i)).collect();
            let inserts = build(&keys, &mut tree);
            let all: Vec<usize> = (0..k).collect();
            let Some(slices) = prove_compact_band_slices(&inserts, pre, admitted, k, &all) else {
                refused.push(format!("shape {ti} (prior {prior_n}, admitted {admitted}, k {k}): the producer refused an honest step"));
                continue;
            };
            let chunks = crate::nf_sparse_air::band_slices(&keys[..admitted], k).expect("the door's chunking");
            let mut at = pre;
            for (i, post, bytes) in &slices {
                slices_checked += 1;
                real_slices += usize::from(!bytes.is_empty());
                if !verify_compact_band_slice(at, *post, &chunks[*i], k, bytes) {
                    refused.push(format!("shape {ti} (prior {prior_n}, admitted {admitted}, k {k}) slice {i}"));
                }
                at = *post;
            }
        }
        eprintln!("[af56-probe] {} shapes, {slices_checked} slices ({real_slices} with a proof), refused {}", shapes.len(), refused.len());
        assert!(refused.is_empty(), "⛔ A-F56: the decider refused honest band steps: {refused:?}");
    }

    /// T2 + T4 — THE NORMAL STEP at the production cover over a warm tree: proves, verifies against the door-derived
    /// statement, and refuses a forged post, a changed key digest, a shape swap, the 256-deep door, and a position
    /// forgery. Prints the cost line the spec's §2 gate reads (run solo for the number).
    #[test]
    fn db453_b_a_normal_compact_step_proves_verifies_and_refuses_every_tamper() {
        let prior: Vec<[u8; 32]> = (0..20_000u64).map(|i| key_from(1_000_000 + i)).collect();
        let keys: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64).map(key_from).collect();
        let n = keys.len();
        let lb = COMPACT_LB_NORMAL;
        let mut tree = CompactRefTree::default();
        for k in &prior {
            tree.insert(k);
        }
        let pre = tree.root();
        let inserts = build(&keys, &mut tree);
        assert_eq!(compact_step_lb(&inserts), lb, "a warm 20k-key tree's step fits the normal window");
        let t0 = std::time::Instant::now();
        let (carrier, post, kd) = prove_compact_band_carrier_bytes(&inserts, pre, n, lb).expect("the step proves");
        let prove_ms = t0.elapsed().as_millis();
        assert_eq!(post, tree.root(), "the carrier's post is the recomputed root");
        assert_eq!(kd, compact_keys_digest_of(&keys, n), "the digest is the door's native recompute");
        let t1 = std::time::Instant::now();
        assert!(verify_compact_band_carrier_bytes(&carrier, pre, post, n, n, kd, lb), "the honest step verifies");
        eprintln!(
            "[db453-cost] normal: N={n} lb={lb} prove {prove_ms} ms, {} B, verify {} ms (prior {} keys)",
            carrier.len(),
            t1.elapsed().as_millis(),
            prior.len()
        );
        assert!(carrier.len() <= 1_800_000);
        let mut bad = post;
        bad[0] ^= 1;
        assert!(!verify_compact_band_carrier_bytes(&carrier, pre, bad, n, n, kd, lb), "a forged post is refused");
        let mut bad_kd = kd;
        bad_kd[2] = crate::nullifier_insert_air::kadd(bad_kd[2], 1);
        assert!(!verify_compact_band_carrier_bytes(&carrier, pre, post, n, n, bad_kd, lb), "a changed key digest is refused");
        assert!(!verify_compact_band_carrier_bytes(&carrier, pre, post, n, n, kd, COMPACT_LB_DEEP), "a shape swap is refused");
        assert!(
            !crate::nf_sparse_air::verify_sparse_block_keyed_carrier_bytes(&carrier, pre, post, n, n, kd),
            "the 256-deep keyed door refuses a compact carrier"
        );
        // the position forgery: a different key at slot 0 is an honest transition of ITS keys, refused under the header's
        let mut forged_keys = keys.clone();
        forged_keys[0] = key_from(0xF0F0);
        let mut ft = CompactRefTree::default();
        for k in &prior {
            ft.insert(k);
        }
        let forged = build(&forged_keys, &mut ft);
        assert_eq!(compact_step_lb(&forged), lb);
        let (fc, fpost, fkd) = prove_compact_band_carrier_bytes(&forged, pre, n, lb).expect("the forged step proves its own keys");
        assert!(verify_compact_band_carrier_bytes(&fc, pre, fpost, n, n, fkd, lb), "CALIBRATION: under its own digest it verifies");
        assert!(!verify_compact_band_carrier_bytes(&fc, pre, fpost, n, n, kd, lb), "under the header's digest it is refused");
    }

    /// T2 — A DEEP INSERT NEEDS THE DEEP SHAPE: a production-cover step whose first key shares every window level with a
    /// key already in its shard cannot be laid in the normal window (no normal carrier exists for it); the deep shape
    /// proves and verifies the same step (and prints its cost); a re-spend inside the step lays in neither.
    #[test]
    fn db453_c_a_deep_insert_is_refused_by_the_normal_window_and_proven_by_the_deep_one() {
        let (pre, keys, inserts, tree, _a) = deep_step();
        let n = keys.len();
        assert!(!compact_window_fits(&inserts[0], COMPACT_LB_NORMAL), "the split lies below the normal window");
        assert!(compact_window_fits(&inserts[0], COMPACT_LB_DEEP), "the deep window holds it");
        assert_eq!(compact_step_lb(&inserts), COMPACT_LB_DEEP);
        assert!(compact_chain_cols(&inserts, pre, n, COMPACT_LB_NORMAL).is_none(), "the normal window refuses the deep insert");
        let t0 = std::time::Instant::now();
        let (c, post, kd) = prove_compact_band_carrier_bytes(&inserts, pre, n, COMPACT_LB_DEEP).expect("the deep shape proves");
        eprintln!("[db453-cost] deep: N={n} lb={COMPACT_LB_DEEP} prove {} ms, {} B", t0.elapsed().as_millis(), c.len());
        assert_eq!(post, tree.root());
        assert!(verify_compact_band_carrier_bytes(&c, pre, post, n, n, kd, COMPACT_LB_DEEP), "the deep step verifies");
        assert!(!verify_compact_band_carrier_bytes(&c, pre, post, n, n, kd, COMPACT_LB_NORMAL), "and only as the deep shape");
        // a re-spend inside the step: the last insert forged to re-insert b (its terminal claimed as b itself)
        let mut f = inserts.clone();
        f[n - 1].key = keys[0];
        f[n - 1].other = Some(keys[0]);
        assert!(compact_chain_cols(&f, pre, n, COMPACT_LB_DEEP).is_none(), "a re-spend in a step is refused");
    }

    /// §9.6 Q6 PARITY — the 256-deep native transition refuses the all-zero key (`native_sparse_insert_folds`, the reserved
    /// value `SparseNfError::ZeroNullifier` names); the compact one must refuse it too, natively and in the lay (so no
    /// carrier exists for it), while CALIBRATION: the same witness with any non-zero key folds.
    #[test]
    fn db453_e_the_zero_key_is_refused_like_the_256_deep_transition_refuses_it() {
        let tree = CompactRefTree::default();
        let pre = tree.root();
        let zero = [0u8; 32];
        let w = tree.witness(&zero).expect("the reference tree builds a witness for any absent key");
        assert!(
            crate::nf_sparse_air::native_sparse_block_transition(
                &[crate::nf_sparse_air::SparseInsertWitness { key: zero, copath: vec![compact_empty(); NF_SPARSE_DEPTH] }],
                crate::nf_sparse_air::empty_subtree_native(NF_SPARSE_DEPTH)
            )
            .is_none(),
            "the 256-deep transition refuses the zero key (the parity target)"
        );
        let mut calib = w.clone();
        calib.key[5] = 1;
        let calib = tree.witness(&calib.key).expect("a non-zero key");
        assert!(native_compact_insert_transition(&calib, pre).is_some(), "CALIBRATION: a non-zero key folds");
        assert!(native_compact_insert_transition(&w, pre).is_none(), "the zero key is refused natively");
        let mut cover: Vec<CompactInsertWitness> = vec![w];
        let mut t = CompactRefTree::default();
        cover.extend((1..crate::nf_sparse_air::PRODUCTION_BLOCK_COVER as u64).map(|i| t.insert_and_witness(&key_from(9_000 + i)).expect("fresh")));
        assert!(compact_chain_cols(&cover, pre, cover.len(), COMPACT_LB_NORMAL).is_none(), "no carrier lays the zero key");
    }

    /// SOUND — THE LAWS REFUSE A FORGED TRACE, not only a forged statement. Direct evaluation of the chain gate over the
    /// honest normal trace (256 inserts over a warm tree) vanishes on EVERY row; then each local forgery a cheating prover
    /// would try leaves a nonzero residual inside the insert it touches: the split flag dropped, the terminal kind flipped,
    /// the pre chain started early beside a forged sibling, a `k''` bit flipped above the split, the post chain's split
    /// sibling replaced by `Z`, the leaf domain lane changed, a band row's pre flag cleared, and the non-membership weld.
    #[test]
    fn db453_f_every_law_refuses_a_local_trace_forgery_the_honest_trace_satisfies() {
        use crate::air_zerocheck::AirConstraint;
        let mut tree = CompactRefTree::default();
        for i in 0..3_000u64 {
            tree.insert(&key_from(4_000_000 + i));
        }
        let pre = tree.root();
        let keys: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64).map(|i| key_from(5_000_000 + i)).collect();
        let inserts = build(&keys, &mut tree);
        let n = inserts.len();
        let lb = COMPACT_LB_NORMAL;
        let rows_per = 1usize << lb;
        let base = NF_SPARSE_DEPTH - rows_per;
        let (cols, post, _kd) = compact_chain_cols(&inserts, pre, n, lb).expect("honest trace");
        let nvars = cols[0].len().trailing_zeros() as usize;
        let gamma = Ea4::from(Fa4::from_u64(0x0DB4_53F));
        let gate = CompactChainGate::new(gamma, lb, to_f(&pre), to_f(&post), n - 1);
        let eval_at_row = |cols: &Vec<Vec<Fa4>>, r: usize| -> Ea4 {
            let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
            let local: Vec<Ea4> = (0..cols.len()).map(|c| Ea4::from(cols[c][r])).collect();
            let at = |col: usize, pt: &[Ea4]| -> Ea4 {
                let mut row = 0usize;
                for (k, pk) in pt.iter().enumerate().take(nvars) {
                    if *pk == Ea4::ONE {
                        row |= 1 << (nvars - 1 - k);
                    }
                }
                Ea4::from(cols[col][row])
            };
            let oob = crate::air_zerocheck::OobLatch::new();
            let v = gate.eval(&crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
            assert!(!oob.hit(), "the gate read past the trace width");
            v
        };
        let total = cols[0].len();
        assert!((0..total).all(|r| eval_at_row(&cols, r) == Ea4::ZERO), "the honest trace satisfies every law on every row");
        // an insert whose terminal is a leaf and whose split lies at least two levels below it, both inside the window
        let (i, w, s) = inserts
            .iter()
            .enumerate()
            .find_map(|(i, w)| {
                let (_, _, s) = native_compact_insert_folds(w)?;
                (w.other.is_some() && s + 2 <= w.t && s >= base + 2).then_some((i, w.clone(), s))
            })
            .expect("a leaf-terminal insert with a two-level split run");
        let row_of = |l: usize| i * rows_per + (l - base);
        let refused = |forged: &Vec<Vec<Fa4>>| (i * rows_per..(i + 1) * rows_per).any(|r| eval_at_row(forged, r) != Ea4::ZERO);
        let flip = |v: Fa4| Fa4::ONE - v;
        // F1 — the split flag dropped at the split row
        let mut f = cols.clone();
        f[C_SPL][row_of(s)] = Fa4::ZERO;
        assert!(refused(&f), "F1: dropping the split flag is refused");
        // F2 — the terminal kind flipped to EMPTY across the insert (and its T2 with it)
        let mut f = cols.clone();
        for r in i * rows_per..(i + 1) * rows_per {
            f[C_TK][r] = Fa4::ZERO;
            for c in 0..DIGEST_LANES {
                f[C_T2 + c][r] = Fa4::ZERO;
            }
        }
        assert!(refused(&f), "F2: claiming an empty terminal for a leaf terminal is refused");
        // F3 — the pre chain started one level early beside a forged nonzero sibling
        let mut f = cols.clone();
        f[C_A][row_of(w.t - 1)] = Fa4::ONE;
        f[C_SIB][row_of(w.t - 1)] = Fa4::from_u64(7);
        assert!(refused(&f), "F3: starting the non-membership fold below the terminal is refused");
        // F4 — a k'' bit flipped above the split
        let mut f = cols.clone();
        f[C_DIR2][row_of(s + 1)] = flip(f[C_DIR2][row_of(s + 1)]);
        assert!(refused(&f), "F4: a terminal-key bit that disagrees with the key above the split is refused");
        // F5 — the post chain's split sibling replaced by Z
        let mut f = cols.clone();
        for c in 0..DIGEST_LANES {
            f[C_SIBS + c][row_of(s)] = Fa4::ZERO;
        }
        assert!(refused(&f), "F5: the split's sibling must be the terminal key's leaf");
        // F6 — the leaf domain lane changed on the leaf row
        let mut f = cols.clone();
        f[C_SIBS + 2][i * rows_per] = Fa4::from_u64(COMPACT_LEAF_DOMAIN + 1);
        assert!(refused(&f), "F6: a leaf hashed outside its domain is refused");
        // F7 — a band row's pre flag cleared
        let mut f = cols.clone();
        f[C_A][row_of(NF_BAND_LEVEL)] = Fa4::ZERO;
        assert!(refused(&f), "F7: a band level that does not hash is refused");
        // F8 — the non-membership weld: the running root moved under the pre fold's end
        let mut f = cols.clone();
        for r in i * rows_per..(i + 1) * rows_per {
            f[C_RROOT][r] += Fa4::ONE;
        }
        assert!(refused(&f), "F8: a pre fold that misses the running root is refused");
        eprintln!("[db453-f] insert {i}: t = {}, split = {s}; the honest trace's {total} rows vanish, F1–F8 refused", w.t);
    }

    /// T3 — THE CENSUSES: degree (measured ≤ 3), free-witness and decorative-block on both tables of both shapes, each at
    /// the production cover.
    #[test]
    fn db453_d_both_tables_of_both_shapes_pass_the_degree_free_witness_and_decorative_censuses() {
        use crate::air_zerocheck::AirConstraint;
        let gamma = Ea4::from(Fa4::from_u64(0x0DB4_53));
        let run = |inserts: &[CompactInsertWitness], pre: Digest, lb: usize| {
            let n = inserts.len();
            let (tables, post, kd) = compact_band_tables(inserts, pre, n, lb).expect("tables");
            for (t, cols) in tables.iter().enumerate() {
                let gate = CompactBandGate::for_table(t, gamma, lb, to_f(&pre), to_f(&post), n - 1, to_f(&kd));
                let tv = cols[0].len().trailing_zeros() as usize;
                let rl = gate.is_row_local();
                let sh = if rl { Some(Vec::new()) } else { gate.shifted_cols() };
                let t0 = std::time::Instant::now();
                crate::air_zerocheck::debug_degree_census(cols, &gate, tv, rl, &sh);
                crate::air_zerocheck::debug_free_witness_census(cols, &gate, tv, rl, &sh);
                crate::air_zerocheck::debug_decorative_block_census(cols, &gate, tv, rl, &sh);
                eprintln!("[db453-census] lb={lb} table {t}: degree + free-witness + decorative censuses passed in {} ms", t0.elapsed().as_millis());
            }
        };
        // normal: a warm tree so both terminal kinds occur
        let mut tree = CompactRefTree::default();
        for i in 0..3_000u64 {
            tree.insert(&key_from(2_000_000 + i));
        }
        let pre = tree.root();
        let keys: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64).map(|i| key_from(3_000_000 + i)).collect();
        let inserts = build(&keys, &mut tree);
        assert!(inserts.iter().any(|w| w.other.is_some()) && inserts.iter().any(|w| w.other.is_none()), "both terminal kinds");
        run(&inserts, pre, COMPACT_LB_NORMAL);
        let (dpre, _keys, dins, _tree, _a) = deep_step();
        run(&dins, dpre, COMPACT_LB_DEEP);
    }
}

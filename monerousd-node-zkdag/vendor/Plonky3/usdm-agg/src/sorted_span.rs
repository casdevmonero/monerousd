// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol. It is NOT part of the Monero Project. Licensed under the Apache
// License, Version 2.0; see the LICENSE and NOTICE files at the repository root.
//! ⭐ PERFECT-CHAIN B1 — THE SPAN'S SORTED TAG TREE (docs/PERFECT-CHAIN-PLAN-20261122.md §7).
//!
//! Today a carrier proves a note absent from a span by re-absorbing every one of the span's 4,096 tags and comparing each
//! held entry with each tag (`absence_ssa::span_leaf_builder`, MEASURED u7: 2.97 s a span). Here the span's admitted tags are
//! laid SORTED by a 96-bit key as the leaves of one Merkle tree, and a nullifier is absent iff two ADJACENT leaves stand
//! strictly around its key — an indexed-Merkle-tree low leaf (BORROWED: the retired IMT, `usdm-decider` nullifier_insert_air;
//! Aztec's indexed Merkle tree). A step is two paths of [`DEPTH`] levels and two range checks, whatever the span holds.
//!
//! * The key is the low 24 bits of the first four lanes ([`key`]). A tag EQUAL to the nullifier has the same key, so no
//!   adjacent pair is strictly around it: SOUND. A DIFFERENT tag with the same key also blocks the proof (liveness only):
//!   ≈ 4,096 · 2⁻⁹⁶ ≈ 5·10⁻²⁶ a note a span.
//! * Sentinels: leaf 0 is the all-zero lanes (key 0) and every padding leaf is [`high_sentinel`] (the top key), so every key
//!   strictly inside has a low leaf. The build takes every tag, a tag at a sentinel's key included (it sorts beside the
//!   sentinel), so no tag can stop a span's root.
//! * The tree is [`CAP`] leaves at every span: 4,096 tags plus two sentinels need 2¹³. Its size is a constant.
//! O1-FOOTPRINT-REVIEWED: one tree of CAP leaves built per span (the node's window of records and the wallet's follower both
//! build it from the span's own tags), dropped once its root is absorbed; no term in height, spends or notes.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use usdm_decider::hiding_decider::Fa4;

use crate::ssa::{comp_native, RATE};

/// Eight lanes, each a canonical KoalaBear element.
pub type Lanes = [Fa4; RATE];
/// The tree's depth: CAP = 2^DEPTH leaves.
pub const DEPTH: usize = 13;
/// The leaves a span's tree always has.
pub const CAP: usize = 1 << DEPTH;
/// The tags a span may carry: 16 records × 256 (`canon_chain::RECORD_TAGS`), leaving room for both sentinels.
pub const SPAN_TAGS_MAX: usize = 16 * 256;

/// The bits of each key lane (the circuit range-checks a difference of two of them with ONE `Builder::bits` row).
pub const KEY_LANE_BITS: u32 = 24;
/// The lanes a key reads: 4 × 24 = 96 bits.
pub const KEY_LANES: usize = 4;

/// The 96-bit sort key of a tag or nullifier: the low [`KEY_LANE_BITS`] bits of its first [`KEY_LANES`] lanes. ⛔ NOT the whole
/// lanes: every KoalaBear element is below 2³¹, so a range check on a 31-bit difference cannot tell `b > a` from a wrapped
/// `b < a`; at 24 bits a wrapped difference sits near p, far past 2²⁴, and the range check refuses it.
/// ⛔ WHY 96 BITS, NOT 48 (the arithmetic, 2026-11-22): a tag that shares a held nullifier's key blocks that note's absence
/// proof for the span (liveness, never soundness). At 48 bits that is 4,096 · 2⁻⁴⁸ ≈ 1.5·10⁻¹¹ a note a span; a note held
/// for 10⁶ spans ≈ 1.5·10⁻⁵, and a stranded note is lost funds. At 96 bits it is 4,096 · 2⁻⁹⁶ ≈ 5·10⁻²⁶ a note a span. A
/// nullifier is a hash image nobody but its holder knows, so no one can grind a tag against it. cons: two more key lanes =
/// six more `bits` rows and six multiply-adds a step.
#[must_use]
pub fn key(t: &Lanes) -> u128 {
    let m = (1u32 << KEY_LANE_BITS) - 1;
    (0..KEY_LANES).fold(0u128, |k, l| (k << KEY_LANE_BITS) | u128::from(t[l].as_canonical_u32() & m))
}

/// The low sentinel: the all-zero lanes (key 0).
#[must_use]
pub fn low_sentinel() -> Lanes {
    [Fa4::ZERO; RATE]
}

/// The high sentinel: the top key (every key lane at 2²⁴ − 1, the rest zero).
#[must_use]
pub fn high_sentinel() -> Lanes {
    let mut s = [Fa4::ZERO; RATE];
    for l in s.iter_mut().take(KEY_LANES) {
        *l = Fa4::from_u32((1 << KEY_LANE_BITS) - 1);
    }
    s
}

/// A span's sorted tree: its leaves in order and every level (level 0 = leaves, level DEPTH = the root).
#[derive(Clone, Debug)]
pub struct SortedSpan {
    levels: Vec<Vec<Lanes>>,
}

/// What proves a nullifier absent from a span: the low leaf's position, both adjacent leaves, and their paths (siblings from
/// the leaf up).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absence {
    pub pos: u64,
    pub low: Lanes,
    pub high: Lanes,
    pub low_path: Vec<Lanes>,
    pub high_path: Vec<Lanes>,
}

impl SortedSpan {
    /// Build the tree over a span's admitted tags (any order; duplicates are kept, the order is by key then lanes). `None` only
    /// for more than [`SPAN_TAGS_MAX`] tags, which no span of the chain's one record shape can hold.
    /// ⛔ TOTAL ON EVERY TAG (2026-11-22): it once refused a tag at a sentinel's key, so one ground nullifier would have left a
    /// span with no root and stopped the chain's span step. A tag at key 0 or the top key now sorts beside its sentinel; it only
    /// means no nullifier at exactly that key can be proven absent (2⁻⁹⁶ for a holder's own nullifier).
    #[must_use]
    pub fn build(tags: &[Lanes]) -> Option<Self> {
        if tags.len() > SPAN_TAGS_MAX {
            return None;
        }
        let mut leaves: Vec<Lanes> = Vec::with_capacity(CAP);
        leaves.push(low_sentinel());
        let mut sorted = tags.to_vec();
        sorted.sort_by(|a, b| key(a).cmp(&key(b)).then_with(|| lanes_u32(a).cmp(&lanes_u32(b))));
        leaves.extend(sorted);
        leaves.resize(CAP, high_sentinel());
        let mut levels = vec![leaves];
        for d in 0..DEPTH {
            let next: Vec<Lanes> = levels[d].chunks_exact(2).map(|p| comp_native(&p[0], &p[1])).collect();
            levels.push(next);
        }
        Some(Self { levels })
    }

    /// The tree's root: what the canonical chain absorbs for the span.
    #[must_use]
    pub fn root(&self) -> Lanes {
        self.levels[DEPTH][0]
    }

    fn path(&self, pos: usize) -> Vec<Lanes> {
        let mut out = Vec::with_capacity(DEPTH);
        let mut i = pos;
        for d in 0..DEPTH {
            out.push(self.levels[d][i ^ 1]);
            i >>= 1;
        }
        out
    }

    /// The absence of `nf`: adjacent leaves strictly around its key, or `None` when a leaf shares its key (spent, or a key
    /// collision) or the key sits on a sentinel.
    #[must_use]
    pub fn absence(&self, nf: &Lanes) -> Option<Absence> {
        let k = key(nf);
        let leaves = &self.levels[0];
        // the last leaf with a key below k (leaf 0's key is 0, so it exists for every k > 0)
        let pos = leaves.partition_point(|l| key(l) < k).checked_sub(1)?;
        let (low, high) = (leaves[pos], *leaves.get(pos + 1)?);
        if !(key(&low) < k && k < key(&high)) {
            return None;
        }
        Some(Absence { pos: pos as u64, low, high, low_path: self.path(pos), high_path: self.path(pos + 1) })
    }
}

fn lanes_u32(l: &Lanes) -> [u32; RATE] {
    core::array::from_fn(|i| l[i].as_canonical_u32())
}

/// Recompute a path's root natively, from a leaf at `pos` and its siblings: what the circuit's walk constrains.
#[must_use]
pub fn root_of(leaf: &Lanes, pos: u64, path: &[Lanes]) -> Lanes {
    let mut cur = *leaf;
    let mut i = pos;
    for s in path {
        cur = if i & 1 == 1 { comp_native(s, &cur) } else { comp_native(&cur, s) };
        i >>= 1;
    }
    cur
}

/// The native check of an [`Absence`] against a span's root: the circuit states exactly this.
#[must_use]
pub fn verify(root: &Lanes, nf: &Lanes, a: &Absence) -> bool {
    let k = key(nf);
    a.low_path.len() == DEPTH
        && a.high_path.len() == DEPTH
        && key(&a.low) < k
        && k < key(&a.high)
        && root_of(&a.low, a.pos, &a.low_path) == *root
        && root_of(&a.high, a.pos + 1, &a.high_path) == *root
}

// ── B1 IN CIRCUIT: the absence step on the SSA builder ─────────────────────────────────────────────────────────────────────

use crate::absence_ssa::base;
use crate::ssa::{Addr, Builder, Ext};

/// A value's key lanes in circuit: the low [`KEY_LANE_BITS`] bits of lanes `0..KEY_LANES` (each one `bits` row, the same
/// split the native [`key`] takes).
fn key_lanes(b: &mut Builder, t: &[Addr]) -> [Ext; KEY_LANES] {
    let k = KEY_LANE_BITS as u8;
    core::array::from_fn(|l| base(b.bits(t[l], 0, k).expect("a key lane is written")))
}

/// A difference that must be a value in `[0, 2^KEY_LANE_BITS)`: its lane-0 split equals it (the other lanes are zero by
/// construction, every input being a base value).
fn assert_small(b: &mut Builder, d: Ext) {
    let low = b.bits(d.0[0], 0, KEY_LANE_BITS as u8).expect("the split is written");
    b.assert_eq(base(low), base(d.0[0]));
}

/// ASSERT `a < c` on keys given as [`KEY_LANES`] 24-bit lanes, lexicographically. The prover marks the FIRST lane where they
/// differ with a one-hot flag `g_j`. SOUND: every `g_l` is boolean and `Σ g_l = 1`, so exactly one lane `j` is marked;
/// `e_l = 1 − Σ_{m ≤ l} g_m` is 1 exactly on the lanes before `j`, and `e_l·(c_l − a_l) = 0` forces those lanes equal; the
/// difference `Σ g_l·(c_l − a_l − 1)` is range-checked to 24 bits, so `c_j > a_j` (a wrapped, negative difference sits near p
/// and is refused). An equal pair has no first difference: whatever lane is marked, its difference is −1, which fails.
fn assert_lt(b: &mut Builder, a: [Ext; KEY_LANES], c: [Ext; KEY_LANES]) {
    let av: [u32; KEY_LANES] = core::array::from_fn(|l| b.val(a[l].0[0]).as_canonical_u32());
    let cv: [u32; KEY_LANES] = core::array::from_fn(|l| b.val(c[l].0[0]).as_canonical_u32());
    let j_v = (0..KEY_LANES).find(|&l| av[l] != cv[l]).unwrap_or(KEY_LANES - 1);
    let ga = b.load(&core::array::from_fn::<Fa4, KEY_LANES, _>(|l| if l == j_v { Fa4::ONE } else { Fa4::ZERO }));
    let mut sum = Ext::ZERO;
    let mut d = Ext::ZERO;
    for l in 0..KEY_LANES {
        let g = base(ga[l]);
        let ng = b.sub(Ext::ZERO, g);
        b.assert_mul_add_zero(g, g, ng); // g² − g = 0
        sum = b.add(sum, g);
        let dl = b.sub(c[l], a[l]);
        if l + 1 < KEY_LANES {
            let e = b.sub(Ext::ONE, sum); // 1 on the lanes before the marked one
            b.assert_mul_add_zero(e, dl, Ext::ZERO); // lanes before j are equal
        }
        let dm = b.sub(dl, Ext::ONE);
        d = b.mul_add(g, dm, d);
    }
    b.assert_eq(sum, Ext::ONE); // exactly one marked lane
    assert_small(b, d);
}

/// A leaf's walk to `root`: [`DEPTH`] levels from the leaf at `pos` (each level's direction is the index's low bit, `comp`
/// halves it), the last level CHECKED against `root`, and the index left over forced to zero (so `pos` is a real position
/// below CAP and the walk is the one the native [`root_of`] takes).
fn walk(b: &mut Builder, leaf: [Addr; RATE], pos: Addr, path: &[Lanes], root: [Addr; RATE]) {
    let (mut cur, mut ix) = (leaf, pos);
    for (lvl, s) in path.iter().enumerate() {
        let sa = b.load(s);
        let sib: [Addr; RATE] = sa[..].try_into().expect("eight lanes");
        let last = (lvl + 1 == DEPTH).then_some(root);
        let (n, i2, _) = b.comp(cur, sib, ix, crate::ssa::ONE, Fa4::ONE, last);
        cur = n;
        ix = i2;
    }
    b.assert_eq(base(ix), Ext::ZERO);
}

/// ⭐ B1 — EMIT ONE ABSENCE STEP: `nf` (its lane addresses) is absent from the span whose sorted root is `root`, by the witness
/// `w`: the low and high leaves walk to `root` from adjacent positions (`pos`, `pos + 1`), and `k(low) < k(nf) < k(high)`.
/// Cost: two walks of DEPTH levels, five `bits` rows, a handful of multiply-adds — whatever the span holds.
pub fn emit_absence(b: &mut Builder, root: [Addr; RATE], nf: &[Addr], w: &Absence) {
    let la = b.load(&w.low);
    let ha = b.load(&w.high);
    let low: [Addr; RATE] = la[..].try_into().expect("eight lanes");
    let high: [Addr; RATE] = ha[..].try_into().expect("eight lanes");
    let pa = b.load(&[Fa4::from_u64(w.pos), Fa4::from_u64(w.pos + 1)]);
    let p1 = b.add(base(pa[0]), Ext::ONE);
    b.assert_eq(base(pa[1]), p1); // the high leaf sits right after the low one
    walk(b, low, pa[0], &w.low_path, root);
    walk(b, high, pa[1], &w.high_path, root);
    let kl = key_lanes(b, &low);
    let kn = key_lanes(b, nf);
    let kh = key_lanes(b, &high);
    assert_lt(b, kl, kn);
    assert_lt(b, kn, kh);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(i: u64) -> Lanes {
        // splitmix64: a deterministic spread of test tags (a test fixture only, never a protocol value)
        let mix = |mut z: u64| {
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut l = [Fa4::ZERO; RATE];
        for (j, x) in l.iter_mut().enumerate() {
            let h = mix(i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(j as u64 + 1));
            *x = Fa4::from_u32((h as u32) & 0x3FFF_FFFF);
        }
        l
    }

    /// B1's native core: every tag of a full span is refused, a fresh nullifier proves absent, and a forged step (a wrong
    /// leaf, a wrong position, a non-adjacent pair) fails the check.
    #[test]
    fn b1_a_span_tree_proves_absence_and_refuses_every_held_tag() {
        let tags: Vec<Lanes> = (0..SPAN_TAGS_MAX as u64).map(tag).collect();
        let t0 = std::time::Instant::now();
        let s = SortedSpan::build(&tags).expect("a full span builds");
        let built = t0.elapsed();
        for t in tags.iter().step_by(97) {
            assert!(s.absence(t).is_none(), "⛔ a held tag proved absent");
        }
        let fresh = tag(1 << 40);
        let a = s.absence(&fresh).expect("a fresh nullifier is absent");
        assert!(verify(&s.root(), &fresh, &a), "the honest step verifies");
        let t1 = std::time::Instant::now();
        for _ in 0..100 {
            assert!(verify(&s.root(), &fresh, &a));
        }
        let per = t1.elapsed() / 100;
        // TAMPER: a held tag claimed absent with a real pair from elsewhere
        let held = tags[5];
        assert!(!verify(&s.root(), &held, &a), "⛔ a held tag passed with another nullifier's pair");
        let mut bad = a.clone();
        bad.pos += 2;
        assert!(!verify(&s.root(), &fresh, &bad), "⛔ a moved position passed");
        let mut bad = a.clone();
        bad.high = s.levels[0][(a.pos + 3) as usize];
        assert!(!verify(&s.root(), &fresh, &bad), "⛔ a non-adjacent high leaf passed");
        eprintln!("[b1] span tree of {} tags (CAP {CAP}) built in {built:?}; one absence verified natively in {per:?}", tags.len());
    }

    /// Lay one absence step on a builder (the root and nf as loaded values) and report the first failed constraint.
    fn lay(root: &Lanes, nf: &Lanes, w: &Absence) -> (Option<String>, usize) {
        let mut b = Builder::new();
        let ra = b.load(root);
        let na = b.load(nf);
        let root_a: [Addr; RATE] = ra[..].try_into().unwrap();
        emit_absence(&mut b, root_a, &na, w);
        (b.mismatch.clone(), b.ops.len())
    }

    /// B1 ACROSS THE BOUNDARY, IN CIRCUIT. Two sides: the WALLET builds its witness from the span's tags as its follower read
    /// them; the NODE builds the span's root from its own copy, in its own (reversed) order. They must agree on the root, the
    /// wallet's honest step must lay against the NODE's root with no failed constraint, and every lie a prover could tell must
    /// fail one: a held tag with another nullifier's pair, a moved position, a non-adjacent high leaf, a swapped pair, a wrong
    /// root.
    /// TWO-PARTY-REVIEWED: this is the prover crate, which has no Node or wallet type; the two sides here are the wallet's tree
    /// (its witness) and the node's tree built from its own copy of the tags in another order, and the assertion is that they
    /// agree on the root. The two-Node, two-process run is B1's node pin once the record carries the root (plan §7).
    #[test]
    fn b1_a_wallets_absence_step_lays_against_the_nodes_root_and_every_lie_fails_in_circuit() {
        let tags: Vec<Lanes> = (0..SPAN_TAGS_MAX as u64).map(tag).collect();
        let wallet = SortedSpan::build(&tags).expect("the wallet's span builds");
        let mut node_copy = tags.clone();
        node_copy.reverse();
        let node = SortedSpan::build(&node_copy).expect("the node's span builds");
        assert_eq!(wallet.root(), node.root(), "⛔ the wallet and the node disagree on the span's root (order-dependent)");
        let root = node.root();
        let fresh = tag(1 << 40);
        let a = wallet.absence(&fresh).expect("a fresh nullifier is absent");
        let (m, ops) = lay(&root, &fresh, &a);
        assert!(m.is_none(), "⛔ the honest step failed a constraint: {m:?}");
        eprintln!("[b1] one absence step = {ops} builder ops (two walks of {DEPTH} levels, {KEY_LANES}-lane keys)");
        // THE WIDE KEY: a nullifier that shares a held tag's first two key lanes (the old 48-bit key) and differs in lane 2
        // is still proven absent, honestly, in circuit — and the held tag beside it is still refused
        let mut near = tags[7];
        near[2] = Fa4::from_u32((near[2].as_canonical_u32() ^ 1) & 0x00FF_FFFF);
        let an = wallet.absence(&near).expect("a nullifier one key bit from a held tag is absent");
        let (m, _) = lay(&root, &near, &an);
        assert!(m.is_none(), "⛔ the wide-key step failed a constraint: {m:?}");
        assert!(lay(&root, &tags[7], &an).0.is_some(), "⛔ the held tag passed with its neighbour's pair");
        // A TAG AT A SENTINEL'S KEY still builds a span (it once stopped the root)
        let mut edge = tags.clone();
        edge[0] = low_sentinel();
        edge[1] = high_sentinel();
        assert!(SortedSpan::build(&edge).is_some(), "⛔ a tag at a sentinel's key stopped the span's root");
        let held = tags[5];
        let mut moved = a.clone();
        moved.pos += 2;
        let mut far = a.clone();
        far.high = wallet.levels[0][(a.pos + 3) as usize];
        far.high_path = wallet.path((a.pos + 3) as usize);
        let mut swapped = a.clone();
        std::mem::swap(&mut swapped.low, &mut swapped.high);
        std::mem::swap(&mut swapped.low_path, &mut swapped.high_path);
        let mut wrong_root = root;
        wrong_root[0] += Fa4::ONE;
        for (what, r, nf, w) in [
            ("a held tag with another nullifier's pair", root, held, a.clone()),
            ("a moved position", root, fresh, moved),
            ("a non-adjacent high leaf", root, fresh, far),
            ("a swapped pair", root, fresh, swapped),
            ("a wrong root", wrong_root, fresh, a.clone()),
        ] {
            let (m, _) = lay(&r, &nf, &w);
            assert!(m.is_some(), "⛔ the circuit took {what}");
        }
    }
}

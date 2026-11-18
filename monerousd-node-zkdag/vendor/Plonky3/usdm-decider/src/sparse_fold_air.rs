// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ THE SPARSE INSERT, PROVED OVER A REAL PERMUTATION — and naming the key it consumes.
//!
//! This replaces [`crate::nf_sparse_air`]'s `SparseChainGate`, which constrained the 1-round fold that
//! kill list §AG measured as invertible: `out = MDS·(l + 7·r)⁷` inverts in one division, so a
//! non-membership copath could be SOLVED and any note spent again. Here each fold level is one
//! [`crate::poseidon2_compress::compress`] — a whole Poseidon2₁₆ permutation, truncated — so there is no
//! algebraic route from a level's output back to a choice of sibling.
//!
//! ## Three chains in ONE row, and why they are not three tables
//! A row is one fold LEVEL and carries three permutation blocks side by side:
//!
//! | block | what it folds | why it exists |
//! |-------|---------------|---------------|
//! | EMPTY | `fold(EMPTY_LEAF, nf, copath)` → `pre_root` | NON-MEMBERSHIP: the leaf was unspent |
//! | SPENT | `fold(SPENT_LEAF, nf, copath)` → `post_root` | the FLIP: the same leaf is now spent |
//! | KEY   | `k ← compress(k, [dir])` → `key_digest` | ⛔ WHICH nullifier this carrier consumed |
//!
//! Side by side in one row means the sibling and the direction bit are shared by PLAIN SAME-ROW
//! EQUALITIES. As three tables they would need a cross-tie per level per lane — 256 × 9 ties, and the IVC
//! step already showed 237 ties costing 67 KB. One row, three blocks, zero ties.
//!
//! ## ⛔⛔⛔ THE KEY CHAIN CLOSES A SECOND HOLE, and it is the one that started this
//! `nf_sparse_air::verify_sparse_insert_carrier_bytes(bytes, pre, post)` proves only that *some* key moved
//! `pre → post`. It never names WHICH, because the nullifier lives in the trace ONLY as the per-level
//! direction bit — a private witness the verifier never sees. `nf_sparse_air.rs` says as much in a comment
//! (*"the 256-bit PATH binds which nullifier this is"*), and that is true INSIDE the trace and vacuous
//! outside it. A consumer could therefore burn a junk key and claim any nullifier had been consumed: one
//! deposit minting twice, one note spent twice.
//!
//! The KEY chain folds the SAME `dir` cell the other two chains steer by, into a digest the verifier
//! recomputes natively from the nullifier it cares about ([`key_chain_native`], 256 permutations, O(1) in
//! chain size). The last-row weld then forces the trace's path to BE that nullifier's path. A carrier
//! proved for key X is REFUSED when the verifier names key D — measured, not argued.

use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::{compress, Digest, DIGEST_LANES};
use crate::pow_pq_air::{lay_perm_row_at, P2_COLS, WIDTH};
use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, SymbolicVariable};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use std::collections::HashMap;
use std::sync::Arc;

/// Levels in the sparse tree — one per nullifier bit. MIRRORS `nf_sparse::NF_SPARSE_DEPTH`; a power of
/// two, so the trace needs no padding rows.
pub const DEPTH: usize = 256;

// ── COLUMN LAYOUT ────────────────────────────────────────────────────────────────────────────────────
/// The EMPTY chain's permutation block.
pub const EMP: usize = 0;
/// The SPENT chain's permutation block.
pub const SPT: usize = P2_COLS;
/// The KEY chain's permutation block.
pub const KEY: usize = 2 * P2_COLS;
/// This level's copath sibling.
pub const SIB: usize = 3 * P2_COLS;
/// This level's direction bit — the nullifier's bit, and the ONLY place the key enters the trace.
pub const DIR: usize = SIB + DIGEST_LANES;
/// The EMPTY chain's running accumulator entering this level.
pub const ACC_E: usize = DIR + 1;
/// The SPENT chain's running accumulator entering this level.
pub const ACC_S: usize = ACC_E + DIGEST_LANES;
/// The KEY chain's running accumulator entering this level.
pub const ACC_K: usize = ACC_S + DIGEST_LANES;
/// Total trace width.
pub const FOLD_COLS: usize = ACC_K + DIGEST_LANES;

/// A permutation block's OUTPUT cells, relative to the block's base. MEASURED by
/// `poseidon2_compress::the_permutation_input_and_output_columns_are_where_the_weld_expects`, never
/// inferred from the vendored struct's layout.
const OUT: usize = P2_COLS - WIDTH;

/// Domain seed for the key chain — distinct from every leaf constant so a key digest can never be mistaken
/// for a tree node.
#[must_use]
pub fn key_seed() -> Digest {
    let mut d = [0u64; DIGEST_LANES];
    for (i, s) in d.iter_mut().enumerate() {
        *s = 0x4b45_5941 + i as u64; // "KEYA" + lane
    }
    d
}

/// The EMPTY leaf — an unspent position.
#[must_use]
pub fn empty_leaf() -> Digest {
    [0u64; DIGEST_LANES]
}

/// The SPENT marker leaf. The 256-bit PATH says which nullifier a position belongs to, so the leaf value
/// only has to mean "spent" — but note that the path is a private witness, which is exactly why the KEY
/// chain exists. Domain-separated so it cannot coincide with a real subtree digest.
#[must_use]
pub fn spent_leaf() -> Digest {
    let dom: Digest = core::array::from_fn(|i| 0x4d55_5344_2d6e_66u64.wrapping_add(i as u64) % 0x7f00_0001);
    compress(&dom, &[1u64; DIGEST_LANES])
}

/// Bit `level` of a nullifier, LSB-first within each byte — the child side at that tree level.
#[must_use]
pub fn nf_bit(nf: &[u8; 32], level: usize) -> u8 {
    (nf[level >> 3] >> (level & 7)) & 1
}

/// The digest the KEY chain must reach: fold the nullifier's `DEPTH` path bits, one permutation each.
///
/// The verifier computes this from the nullifier it is asking about, so the last-row weld turns the
/// trace's private path into a public claim. `DEPTH` permutations, independent of chain size or spend
/// count — it is f(the key width) alone.
#[must_use]
pub fn key_chain_native(nf: &[u8; 32]) -> Digest {
    let mut k = key_seed();
    for level in 0..DEPTH {
        let mut bit = [0u64; DIGEST_LANES];
        bit[0] = u64::from(nf_bit(nf, level));
        k = compress(&k, &bit);
    }
    k
}

/// Fold `leaf` up the nullifier's bit-path with `copath` — the native reference the AIR constrains.
#[must_use]
pub fn fold_native(leaf: Digest, nf: &[u8; 32], copath: &[Digest]) -> Digest {
    let mut node = leaf;
    for (level, sib) in copath.iter().enumerate().take(DEPTH) {
        node = if nf_bit(nf, level) == 0 { compress(&node, sib) } else { compress(sib, &node) };
    }
    node
}

/// Does this witness prove a valid spend of `nf`, taking `pre_root` to the returned `post_root`?
/// `None` (fail-closed) on the zero key, a wrong-length copath, or a copath that does NOT prove the leaf
/// EMPTY under `pre_root` — which is also the double-spend refusal, since a spent leaf is not EMPTY.
#[must_use]
pub fn native_insert_transition(nf: &[u8; 32], copath: &[Digest], pre_root: Digest) -> Option<Digest> {
    if *nf == [0u8; 32] || copath.len() != DEPTH {
        return None;
    }
    if fold_native(empty_leaf(), nf, copath) != pre_root {
        return None;
    }
    Some(fold_native(spent_leaf(), nf, copath))
}

// ── TRACE ────────────────────────────────────────────────────────────────────────────────────────────

fn to_f(d: &Digest) -> [KoalaBear; DIGEST_LANES] {
    core::array::from_fn(|i| KoalaBear::from_u64(d[i]))
}

/// Build the `DEPTH`-row trace for a valid spend, plus the certified `post_root` and `key_digest`.
#[must_use]
pub fn fold_trace(
    nf: &[u8; 32],
    copath: &[Digest],
    pre_root: Digest,
) -> Option<(Vec<Vec<Fa4>>, Digest, Digest)> {
    let post = native_insert_transition(nf, copath, pre_root)?;
    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; DEPTH]; FOLD_COLS];
    let (mut acc_e, mut acc_s, mut acc_k) = (empty_leaf(), spent_leaf(), key_seed());
    for (level, sib) in copath.iter().enumerate().take(DEPTH) {
        let dir = nf_bit(nf, level);
        // The two tree chains steer by `dir`; the key chain FOLDS it. One cell, three readers — which is
        // what makes the key weld bind the same path the tree walk used.
        let (le, re) = if dir == 0 { (acc_e, *sib) } else { (*sib, acc_e) };
        let (ls, rs) = if dir == 0 { (acc_s, *sib) } else { (*sib, acc_s) };
        let mut bit = [0u64; DIGEST_LANES];
        bit[0] = u64::from(dir);

        let mut st_e = [KoalaBear::ZERO; WIDTH];
        st_e[..DIGEST_LANES].copy_from_slice(&to_f(&le));
        st_e[DIGEST_LANES..].copy_from_slice(&to_f(&re));
        lay_perm_row_at(&mut cols, EMP, level, st_e);

        let mut st_s = [KoalaBear::ZERO; WIDTH];
        st_s[..DIGEST_LANES].copy_from_slice(&to_f(&ls));
        st_s[DIGEST_LANES..].copy_from_slice(&to_f(&rs));
        lay_perm_row_at(&mut cols, SPT, level, st_s);

        let mut st_k = [KoalaBear::ZERO; WIDTH];
        st_k[..DIGEST_LANES].copy_from_slice(&to_f(&acc_k));
        st_k[DIGEST_LANES..].copy_from_slice(&to_f(&bit));
        lay_perm_row_at(&mut cols, KEY, level, st_k);

        for i in 0..DIGEST_LANES {
            cols[SIB + i][level] = KoalaBear::from_u64(sib[i]);
            cols[ACC_E + i][level] = KoalaBear::from_u64(acc_e[i]);
            cols[ACC_S + i][level] = KoalaBear::from_u64(acc_s[i]);
            cols[ACC_K + i][level] = KoalaBear::from_u64(acc_k[i]);
        }
        cols[DIR][level] = KoalaBear::from_u64(u64::from(dir));

        acc_e = compress(&le, &re);
        acc_s = compress(&ls, &rs);
        acc_k = compress(&acc_k, &bit);
    }
    debug_assert_eq!(acc_e, pre_root, "the empty chain must land on the committed pre-root");
    debug_assert_eq!(acc_s, post, "the spent chain must land on the certified post-root");
    Some((cols, post, acc_k))
}

// ── CONSTRAINTS ──────────────────────────────────────────────────────────────────────────────────────

type Expr = SymbolicExpression<KoalaBear>;

fn var(col: usize, next: bool) -> Expr {
    SymbolicExpr::Leaf(BaseLeaf::Variable(SymbolicVariable::new(
        BaseEntry::Main { offset: usize::from(next) },
        col,
    )))
}
fn konst(v: u64) -> Expr {
    SymbolicExpr::Leaf(BaseLeaf::Constant(KoalaBear::from_u64(v)))
}

/// Re-emit a permutation's symbolic constraints with every `Main` column index shifted by `delta`, so the
/// same block can appear three times in one row.
///
/// ⛔ MEMOISED BY `Arc` POINTER. The Poseidon2 constraint DAG shares sub-expressions heavily; a naive
/// recursive rebuild would expand that sharing into a tree and blow up exponentially. This is the same
/// hazard `whole_chain::CompiledTape` exists to handle, and the same fix.
fn shift_main(e: &Expr, delta: usize, memo: &mut HashMap<*const SymbolicExpr<BaseLeaf<KoalaBear>>, Arc<SymbolicExpr<BaseLeaf<KoalaBear>>>>) -> Expr {
    fn go(
        a: &Arc<SymbolicExpr<BaseLeaf<KoalaBear>>>,
        delta: usize,
        memo: &mut HashMap<*const SymbolicExpr<BaseLeaf<KoalaBear>>, Arc<SymbolicExpr<BaseLeaf<KoalaBear>>>>,
    ) -> Arc<SymbolicExpr<BaseLeaf<KoalaBear>>> {
        let key = Arc::as_ptr(a);
        if let Some(hit) = memo.get(&key) {
            return hit.clone();
        }
        let built = Arc::new(rebuild(a, delta, memo));
        memo.insert(key, built.clone());
        built
    }
    fn rebuild(
        e: &SymbolicExpr<BaseLeaf<KoalaBear>>,
        delta: usize,
        memo: &mut HashMap<*const SymbolicExpr<BaseLeaf<KoalaBear>>, Arc<SymbolicExpr<BaseLeaf<KoalaBear>>>>,
    ) -> SymbolicExpr<BaseLeaf<KoalaBear>> {
        match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset } => SymbolicExpr::Leaf(BaseLeaf::Variable(
                    SymbolicVariable::new(BaseEntry::Main { offset }, v.index + delta),
                )),
                _ => e.clone(),
            },
            SymbolicExpr::Leaf(_) => e.clone(),
            SymbolicExpr::Add { x, y, degree_multiple } => SymbolicExpr::Add {
                x: go(x, delta, memo),
                y: go(y, delta, memo),
                degree_multiple: *degree_multiple,
            },
            SymbolicExpr::Sub { x, y, degree_multiple } => SymbolicExpr::Sub {
                x: go(x, delta, memo),
                y: go(y, delta, memo),
                degree_multiple: *degree_multiple,
            },
            SymbolicExpr::Neg { x, degree_multiple } => {
                SymbolicExpr::Neg { x: go(x, delta, memo), degree_multiple: *degree_multiple }
            }
            SymbolicExpr::Mul { x, y, degree_multiple } => SymbolicExpr::Mul {
                x: go(x, delta, memo),
                y: go(y, delta, memo),
                degree_multiple: *degree_multiple,
            },
        }
    }
    rebuild(e, delta, memo)
}

/// The whole constraint set: three permutation blocks, the shared sibling/direction welds, the σ
/// accumulator chains, and the four boundary welds that make the statement public.
#[must_use]
pub fn fold_constraints(pre_root: Digest, post_root: Digest, key_digest: Digest) -> Vec<Expr> {
    let p2 = crate::pow_pq_air::perm_symbolic_constraints();
    let mut rs: Vec<Expr> = Vec::new();
    for base in [EMP, SPT, KEY] {
        let mut memo = HashMap::new();
        rs.extend(p2.iter().map(|e| shift_main(e, base, &mut memo)));
    }

    let one = konst(1);
    let dir = var(DIR, false);
    // The direction is a BIT. Without this the "selection" below is an arbitrary affine blend and the
    // prover picks any pair of operands it likes.
    rs.push(dir.clone() * (one - dir.clone()));

    // Both tree chains consume (acc, sib) in the order the direction bit names, and the KEY chain folds
    // that SAME cell — so the path the tree walked is the path the key digest commits to.
    for (base, acc) in [(EMP, ACC_E), (SPT, ACC_S)] {
        for i in 0..DIGEST_LANES {
            let a = var(acc + i, false);
            let s = var(SIB + i, false);
            // left  = dir ? sib : acc ;  right = dir ? acc : sib
            rs.push(var(base + i, false) - (a.clone() + dir.clone() * (s.clone() - a.clone())));
            rs.push(var(base + DIGEST_LANES + i, false) - (s.clone() + dir.clone() * (a - s)));
        }
    }
    for i in 0..DIGEST_LANES {
        rs.push(var(KEY + i, false) - var(ACC_K + i, false));
    }
    rs.push(var(KEY + DIGEST_LANES, false) - dir.clone());
    for j in 1..DIGEST_LANES {
        rs.push(var(KEY + DIGEST_LANES + j, false));
    }

    // σ CHAIN: the next level's accumulator is this level's permutation output. Guarded by IsTransition so
    // the last row does not reach past the end of the trace.
    let is_trans: Expr = SymbolicExpr::Leaf(BaseLeaf::IsTransition);
    for (base, acc) in [(EMP, ACC_E), (SPT, ACC_S), (KEY, ACC_K)] {
        for i in 0..DIGEST_LANES {
            rs.push(is_trans.clone() * (var(acc + i, true) - var(base + OUT + i, false)));
        }
    }

    // FIRST row: the three chains start at values the verifier knows — the empty leaf, the spent marker,
    // and the key domain. A free seed would let a prover start anywhere.
    let is_first: Expr = SymbolicExpr::Leaf(BaseLeaf::IsFirstRow);
    let (el, sl, ks) = (empty_leaf(), spent_leaf(), key_seed());
    for i in 0..DIGEST_LANES {
        rs.push(is_first.clone() * (var(ACC_E + i, false) - konst(el[i])));
        rs.push(is_first.clone() * (var(ACC_S + i, false) - konst(sl[i])));
        rs.push(is_first.clone() * (var(ACC_K + i, false) - konst(ks[i])));
    }

    // LAST row: the three chains land on the committed statement — non-membership, the flip, and WHICH key.
    let is_last: Expr = SymbolicExpr::Leaf(BaseLeaf::IsLastRow);
    for i in 0..DIGEST_LANES {
        rs.push(is_last.clone() * (var(EMP + OUT + i, false) - konst(pre_root[i])));
        rs.push(is_last.clone() * (var(SPT + OUT + i, false) - konst(post_root[i])));
        rs.push(is_last.clone() * (var(KEY + OUT + i, false) - konst(key_digest[i])));
    }
    rs
}

/// Domain tag for the keyed sparse settle transcript ("NFKEYED").
pub const NF_KEYED_DOMAIN: u64 = 0x4e46_4b45_5945_44;

fn statement_bind(pre: Digest, post: Digest, key: Digest) -> Vec<Fa4> {
    let mut b = vec![KoalaBear::from_u64(NF_KEYED_DOMAIN)];
    for d in [pre, post, key] {
        b.extend(d.iter().map(|&x| KoalaBear::from_u64(x)));
    }
    b
}

fn make(pre: Digest, post: Digest, key: Digest) -> impl Fn(Ea4) -> crate::whole_chain::WholeChainMainConstraint + Clone {
    let base = fold_constraints(pre, post, key);
    move |gamma: Ea4| {
        crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: FOLD_COLS, preproc_w: 0, npub: 0 },
            FOLD_COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        )
    }
}

/// PROVE one sparse spend as an O(1) carrier that NAMES the key it consumes.
/// Returns `(carrier_bytes, post_root)`; `None` when the witness is not a valid spend.
#[must_use]
pub fn prove_keyed_insert_carrier_bytes(
    nf: &[u8; 32],
    copath: &[Digest],
    pre_root: Digest,
) -> Option<(Vec<u8>, Digest)> {
    let (cols, post, key) = fold_trace(nf, copath, pre_root)?;
    debug_assert_eq!(key, key_chain_native(nf), "the trace's key chain must equal the native one");
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make(pre_root, post, key),
        &statement_bind(pre_root, post, key),
    )?;
    Some((carrier, post))
}

/// VERIFY that a carrier consumed EXACTLY `nf`, taking `pre_root` to `post_root`.
///
/// The verifier derives the key digest itself from the nullifier it is asking about, so a carrier proved
/// for a different key cannot satisfy this call — that is the whole difference from the unkeyed carrier.
#[must_use]
pub fn verify_keyed_insert_carrier_bytes(
    bytes: &[u8],
    nf: &[u8; 32],
    pre_root: Digest,
    post_root: Digest,
) -> bool {
    if bytes.is_empty() || *nf == [0u8; 32] {
        return false;
    }
    let key = key_chain_native(nf);
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make(pre_root, post_root, key),
        &statement_bind(pre_root, post_root, key),
        (DEPTH.trailing_zeros() as usize, FOLD_COLS),
    )
}

/// The digest a lane holds, read back out of a trace column — used by the gates to check welds without
/// re-deriving them.
#[must_use]
pub fn col_digest(cols: &[Vec<Fa4>], base: usize, row: usize) -> Digest {
    core::array::from_fn(|i| u64::from(cols[base + i][row].as_canonical_u32()))
}

#[cfg(test)]
mod sparse_fold_gates {
    use super::*;

    /// The all-empty subtree digest at `height`, memoised. Recomputing this ladder inside the tree walk
    /// was O(height) compressions per pruned branch and dominated everything else.
    fn empty_subtree(height: usize) -> Digest {
        static LADDER: std::sync::OnceLock<Vec<Digest>> = std::sync::OnceLock::new();
        LADDER.get_or_init(|| {
            let mut v = Vec::with_capacity(DEPTH + 1);
            let mut e = empty_leaf();
            v.push(e);
            for _ in 0..DEPTH {
                e = compress(&e, &e);
                v.push(e);
            }
            v
        })[height]
    }

    /// A REFERENCE sparse tree over a handful of spent keys, by pruned recursion: a branch no spent key
    /// enters is exactly `empty_subtree(height)`, so the walk touches only the levels that matter.
    ///
    /// ⛔ A node at HEIGHT `h` is identified by the key's HIGH bits `h..DEPTH`, not its low ones: the fold
    /// consumes bit `l` climbing OUT of height `l`, so by height `h` the low bits are already spent and
    /// what remains to distinguish nodes is everything above. My first version had this inverted and
    /// indexed past the end of the prefix on the very first call.
    fn node(h: usize, high: &[u8], spent: &[[u8; 32]]) -> Digest {
        debug_assert_eq!(high.len(), DEPTH - h, "a height-{h} node is named by bits {h}..{DEPTH}");
        let occupied =
            spent.iter().any(|k| (0..high.len()).all(|j| nf_bit(k, h + j) == high[j]));
        if !occupied {
            return empty_subtree(h);
        }
        if h == 0 {
            return spent_leaf();
        }
        let mut b0 = Vec::with_capacity(high.len() + 1);
        b0.push(0u8);
        b0.extend_from_slice(high);
        let mut b1 = Vec::with_capacity(high.len() + 1);
        b1.push(1u8);
        b1.extend_from_slice(high);
        // The child taken when bit == 0 is the LEFT operand, exactly as `fold_native` orders them.
        compress(&node(h - 1, &b0, spent), &node(h - 1, &b1, spent))
    }

    fn root_of(spent: &[[u8; 32]]) -> Digest {
        node(DEPTH, &[], spent)
    }

    /// The non-membership copath for `nf`: at each level, the sibling subtree — the same high bits with
    /// bit `l` flipped.
    fn copath_of(nf: &[u8; 32], spent: &[[u8; 32]]) -> Vec<Digest> {
        (0..DEPTH)
            .map(|l| {
                let mut high = Vec::with_capacity(DEPTH - l);
                high.push(1 - nf_bit(nf, l));
                high.extend((l + 1..DEPTH).map(|b| nf_bit(nf, b)));
                node(l, &high, spent)
            })
            .collect()
    }

    fn key(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"musdm.fold.gate".as_slice(), &i.to_le_bytes()].concat()).as_bytes()
    }

    /// The reference tree must agree with the fold the AIR constrains, or every gate below measures two
    /// different objects. Checked BEFORE any proving.
    #[test]
    fn the_reference_tree_and_the_fold_agree() {
        let spent = [key(1), key(2), key(3)];
        let root = root_of(&spent);
        let fresh = key(99);
        let cp = copath_of(&fresh, &spent);
        assert_eq!(cp.len(), DEPTH);
        assert_eq!(
            fold_native(empty_leaf(), &fresh, &cp),
            root,
            "an unspent key's empty-fold must reproduce the root"
        );
        // And a SPENT key folds to the root with the SPENT leaf, not the empty one — the two answers the
        // accumulator distinguishes.
        let cp1 = copath_of(&spent[0], &spent);
        assert_eq!(fold_native(spent_leaf(), &spent[0], &cp1), root, "a spent key must fold as spent");
        assert_ne!(
            fold_native(empty_leaf(), &spent[0], &cp1),
            root,
            "⛔ a SPENT key still proves EMPTY — the accumulator would accept a double-spend"
        );
        eprintln!("[fold-air] the reference tree and `fold_native` agree on both verdicts");
    }

    /// ⛔⛔⛔ THE REPAIR, MEASURED: the §AG solve cannot forge non-membership under the new fold.
    ///
    /// This is the same attack, run natively (no proving needed — if the FOLD resists, no witness exists
    /// to prove). The calibration that the solve works on the OLD fold lives in
    /// `poseidon2_compress::calibration_the_solve_still_breaks_the_old_fold`.
    #[test]
    fn the_ag_solve_cannot_forge_non_membership_under_the_new_fold() {
        use crate::sparse_fold_preimage_probe::sparse_fold_preimage_probe as attack;
        let spent = [key(1), key(2), key(3)];
        let root = root_of(&spent);
        let target = &spent[0]; // already spent: honest non-membership is impossible

        let mut hits = 0usize;
        for trial in 0..8u64 {
            let mut cp: Vec<Digest> = (0..DEPTH - 1)
                .map(|i| core::array::from_fn(|c| (i as u64 * 7 + c as u64 + trial + 1) % 0x7f00_0001))
                .collect();
            let node255 = fold_native(empty_leaf(), target, &cp);
            // The solve works on 4 lanes; try it on BOTH halves so a lucky alignment in either is caught.
            for half in 0..2usize {
                let n4: [u64; 4] = core::array::from_fn(|i| node255[half * 4 + i]);
                let t4: [u64; 4] = core::array::from_fn(|i| root[half * 4 + i]);
                let mut last = [0u64; DIGEST_LANES];
                if let Some(s4) = attack::solve_sibling(n4, t4, u64::from(nf_bit(target, DEPTH - 1))) {
                    last[half * 4..half * 4 + 4].copy_from_slice(&s4);
                }
                cp.push(last);
                if fold_native(empty_leaf(), target, &cp) == root {
                    hits += 1;
                }
                cp.pop();
            }
        }
        assert_eq!(
            hits, 0,
            "⛔⛔⛔ the §AG solve STILL forges non-membership — the replacement inherits the break"
        );
        // And the transition builder refuses outright: no witness ⇒ no proof can even be attempted.
        let forged: Vec<Digest> = (0..DEPTH).map(|i| [i as u64 + 1; DIGEST_LANES]).collect();
        assert!(
            native_insert_transition(target, &forged, root).is_none(),
            "⛔ a forged copath produced a transition witness"
        );
        eprintln!("[fold-air] REFUTATION: 16 §AG solve attempts against the new fold, 0 forgeries");
    }

    /// ⭐⭐⭐ THE CARRIER ACCEPTS AN HONEST SPEND — and a verifier naming a DIFFERENT key REFUSES it.
    ///
    /// The second half is the hole the unkeyed carrier left open: `verify_sparse_insert_carrier_bytes`
    /// proves only that SOME key moved `pre → post`, so one deposit could mint twice by burning junk keys.
    #[test]
    fn the_carrier_names_the_key_it_consumed() {
        let spent = [key(1), key(2)];
        let pre = root_of(&spent);
        let mine = key(500);
        let cp = copath_of(&mine, &spent);

        let (carrier, post) =
            prove_keyed_insert_carrier_bytes(&mine, &cp, pre).expect("an honest spend proves");
        assert!(
            verify_keyed_insert_carrier_bytes(&carrier, &mine, pre, post),
            "the honest carrier must verify, or every refusal below is vacuous"
        );
        eprintln!("[fold-air] honest keyed carrier = {} B, {DEPTH} rows × {FOLD_COLS} cols", carrier.len());

        // ⛔ THE KEY BIND. Someone else's key, same roots, same carrier bytes.
        let other = key(501);
        assert_ne!(other, mine);
        assert!(
            !verify_keyed_insert_carrier_bytes(&carrier, &other, pre, post),
            "⛔⛔⛔ A CARRIER FOR ONE KEY VERIFIED UNDER ANOTHER. The replay guard is defeated: a consumer \
             burns a junk key and claims any nullifier was consumed — one deposit minting twice, one note \
             spent twice."
        );
        // And the endpoints still bind, so the key weld did not replace the root weld.
        let wrong = root_of(&[key(1), key(2), key(3)]);
        assert!(!verify_keyed_insert_carrier_bytes(&carrier, &mine, wrong, post), "pre-root not bound");
        assert!(!verify_keyed_insert_carrier_bytes(&carrier, &mine, pre, wrong), "post-root not bound");
        assert!(!verify_keyed_insert_carrier_bytes(&[], &mine, pre, post), "an empty carrier verified");
        assert!(
            !verify_keyed_insert_carrier_bytes(&carrier, &[0u8; 32], pre, post),
            "the zero key must be refused"
        );
        eprintln!("[fold-air] a carrier for key A is REFUSED when the verifier names key B; both roots bind");
    }

    /// A spend of an ALREADY-SPENT key has no witness at all — non-membership fails inside the builder, so
    /// there is nothing to prove. Double-spend is refused before any proving starts.
    #[test]
    fn an_already_spent_key_has_no_witness() {
        let spent = [key(1), key(2), key(3)];
        let pre = root_of(&spent);
        let cp = copath_of(&spent[1], &spent);
        assert!(
            native_insert_transition(&spent[1], &cp, pre).is_none(),
            "⛔ a spent key produced an insert witness"
        );
        assert!(
            prove_keyed_insert_carrier_bytes(&spent[1], &cp, pre).is_none(),
            "⛔ a spent key produced a CARRIER"
        );
        // A stale copath (built before the tree moved) is refused too.
        let fresh = key(700);
        let stale = copath_of(&fresh, &[key(1), key(2)]);
        assert!(
            native_insert_transition(&fresh, &stale, pre).is_none(),
            "⛔ a stale copath was accepted against the moved root"
        );
        eprintln!("[fold-air] a spent key and a stale copath both fail before any proving");
    }

    /// A TAMPERED trace must not verify. The carrier is re-proved from a trace whose cells were moved, so
    /// this measures the constraints rather than the byte format.
    #[test]
    fn a_tampered_trace_is_refused() {
        let spent = [key(1)];
        let pre = root_of(&spent);
        let mine = key(800);
        let cp = copath_of(&mine, &spent);
        let (cols, post, keyd) = fold_trace(&mine, &cp, pre).expect("trace");

        // The weld points must hold on the honest trace first.
        assert_eq!(col_digest(&cols, ACC_E, 0), empty_leaf(), "row 0 empty seed");
        assert_eq!(col_digest(&cols, ACC_S, 0), spent_leaf(), "row 0 spent seed");
        assert_eq!(col_digest(&cols, ACC_K, 0), key_seed(), "row 0 key seed");
        assert_eq!(col_digest(&cols, EMP + OUT, DEPTH - 1), pre, "last row folds to pre_root");
        assert_eq!(col_digest(&cols, SPT + OUT, DEPTH - 1), post, "last row folds to post_root");
        assert_eq!(keyd, key_chain_native(&mine), "the trace's key digest is the native one");

        for (name, col, row) in [
            ("a direction bit", DIR, 7usize),
            ("a sibling lane", SIB, 11),
            ("the empty accumulator", ACC_E, 13),
            ("the spent accumulator", ACC_S, 17),
            ("the key accumulator", ACC_K, 19),
        ] {
            let mut t = cols.clone();
            t[col][row] += KoalaBear::ONE;
            let bad = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
                t,
                make(pre, post, keyd),
                &statement_bind(pre, post, keyd),
            );
            assert!(
                bad.map_or(true, |b: Vec<u8>| !verify_keyed_insert_carrier_bytes(&b, &mine, pre, post)),
                "⛔ tampering with {name} still produced a verifying carrier"
            );
        }
        eprintln!("[fold-air] 5/5 single-cell trace tampers refused");
    }
}

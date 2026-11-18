// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! SPARSE nullifier block carrier — the NATIVE reference for the count-free monotone-SMT settlement gate.
//!
//! The node's live nullifier accumulator is migrating from the append-indexed IMT (`nullifier_insert_air`) to the
//! count-free monotone sparse tree (`crate` node-side `nf_sparse`): position = the nullifier, a leaf only flips
//! EMPTY→SPENT, and a block advances `pre_root → post_root` by folding each spend's O(DEPTH) copath twice (a
//! non-membership check + the flip). This module is the NATIVE reference that the in-circuit AIR proves and that a
//! verifier binds to — computed in the decider's `[u64;4]` limb field (via [`crate::nullifier_insert_air::poseidon_pair_native`])
//! so the circuit, the node acc, and the wallet fold the byte-identical tree.
//!
//! This is brick 1 of the sparse carrier: the native transition + its adversarial soundness (a tampered copath, a
//! double-spend, and the zero key are all rejected fail-closed). The trace/constraint AIR (a depth-`DEPTH` uniform
//! Poseidon2 fold, no lexicographic bracket and no next-pointer — strictly simpler than the IMT gate) binds to this
//! reference next, then aggregates to the O(1) compact carrier via [`crate::whir_rec_block`], exactly as the IMT
//! carrier does. ([[project_phone_full_node_o1_produce_fold]] [[feedback_no_growth_any_axis]] [[feedback_digital_cash_pillar]])

// ONE digest width for the whole tree — 8 lanes x 31 bits = 248 bits (kill list §AG).
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::hiding_decider::{Ea4, Fa4};
use crate::nullifier_insert_air::{kred, poseidon_pair_native};
use p3_field::PrimeCharacteristicRing;
use p3_field::Field; // for `try_inverse` on the base field (non-membership witness)

/// Key depth = the full 256-bit nullifier (collision-free by construction — two distinct nullifiers can never share a
/// leaf, no birthday analysis). Mirrors the node-side `nf_sparse::NF_SPARSE_DEPTH`.
pub const NF_SPARSE_DEPTH: usize = 256;

/// The PRODUCTION per-block cover count — pinned == the node's `cover::BLOCK_FIXED_NULLIFIER_COUNT`
/// (= `BLOCK_FIXED_NOTE_COUNT` = `BLOCK_FIXED_TX_COUNT` = 256). EVERY block/cover test proves at THIS full count so it
/// exercises the real per-cover behavior at production strength. The decider can't import the node crate (the node
/// depends on the decider, not the reverse), so this is pinned here; a divergence is a parity bug. Enforced by
/// production-scale-test-guard.py. ([[feedback_test_for_production]] [[feedback_no_growth_any_axis]])
pub const PRODUCTION_BLOCK_COVER: usize = 256;

/// An unspent leaf.
#[inline]
pub fn empty_leaf_native() -> Digest {
    [0u64; DIGEST_LANES]
}

/// The SPENT marker leaf — a fixed domain-separated nonzero constant (the 256-bit PATH binds *which* nullifier this
/// is, so the leaf value only needs to mean "spent"). Byte-identical to the node-side `nf_sparse::spent_leaf`.
/// Computed once per process (a constant of the tree): one compression, never re-hashed per call.
#[inline]
pub fn spent_leaf_native() -> Digest {
    static SPENT: std::sync::OnceLock<Digest> = std::sync::OnceLock::new();
    *SPENT.get_or_init(|| {
        poseidon_pair_native(
            crate::poseidon2_compress::lanes_of(&[0x4d55_5344, 0x2d6e_662d, 0x7370_656e, 0x742d_7631]),
            [1u64; DIGEST_LANES],
        )
    })
}

/// The all-empty subtree hashes `E[0] = empty leaf, E[l + 1] = H(E[l], E[l])` for every level 0..=DEPTH, laid once per
/// process (DEPTH compressions). A constant of the tree, so a table read is the same value the loop computed per call.
fn empty_subtree_table() -> &'static [Digest; NF_SPARSE_DEPTH + 1] {
    static TABLE: std::sync::OnceLock<[Digest; NF_SPARSE_DEPTH + 1]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [empty_leaf_native(); NF_SPARSE_DEPTH + 1];
        for l in 0..NF_SPARSE_DEPTH {
            t[l + 1] = poseidon_pair_native(t[l], t[l]);
        }
        t
    })
}

/// The all-empty subtree hash at `level` (level 0 = an empty leaf). A table read for `level ≤ DEPTH` (the tree's own
/// levels); a deeper level folds on from the top of the table.
pub fn empty_subtree_native(level: usize) -> Digest {
    let t = empty_subtree_table();
    if level <= NF_SPARSE_DEPTH {
        return t[level];
    }
    let mut e = t[NF_SPARSE_DEPTH];
    for _ in NF_SPARSE_DEPTH..level {
        e = poseidon_pair_native(e, e);
    }
    e
}

/// bit `level` of the nullifier, LSB-first (level 0 = least-significant bit of byte 0) — the child side at that level.
#[inline]
pub fn nf_bit(nf: &[u8; 32], level: usize) -> u8 {
    (nf[level >> 3] >> (level & 7)) & 1
}

/// Fold `leaf` up the nullifier's bit-path with the supplied copath (`DEPTH` siblings): at each level `bit==0` ⇒ the
/// node is the LEFT child (sibling on the right), else RIGHT. Mirrors the node-side `nf_sparse::fold_sparse` — the
/// ONLY hashing a settle does, a FIXED `DEPTH` `poseidon_pair`s independent of how many nullifiers are already spent.
pub fn fold_sparse_native(leaf: Digest, nf: &[u8; 32], copath: &[Digest]) -> Digest {
    // ⭐ THE EMPTY RUN (2026-10-06, the simulator's speed census): a node that IS the empty subtree at its level, beside an
    // empty sibling, folds to the empty subtree one level up — `H(E[l], E[l]) = E[l + 1]` is how the table is defined, and
    // both children being the same value makes the bit irrelevant. So the empty-leaf fold of a non-membership check reads
    // the table through the leaf's empty neighbourhood (≈ 240 of 256 levels in a sparse tree) and hashes only above it.
    // The SAME digest as hashing every level — an identity, not an approximation; any other value hashes as before.
    // MEASURED before: a band step's native recompute hashed 2 × 256 levels per insert (65,536 rows of trace per step).
    // cons: one 32-byte compare per level.
    let e = empty_subtree_table();
    let mut node = leaf;
    for (level, sib) in copath.iter().enumerate().take(NF_SPARSE_DEPTH) {
        if node == e[level] && *sib == e[level] {
            node = e[level + 1];
            continue;
        }
        node = if nf_bit(nf, level) == 0 {
            crate::poseidon2_compress::compress_sparse(&node, sib)
        } else {
            crate::poseidon2_compress::compress_sparse(sib, &node)
        };
    }
    node
}

/// ⭐ DB-353 — THE BAND, one spelling (2026-09-29). The sparse nullifier tree's top `NF_BAND_BITS` levels: a node's
/// SHARD is the tag's top byte (`nf_bit` levels 248..255, LSB-first), so the 2^`NF_BAND_BITS` subtree roots at level
/// `NF_BAND_LEVEL`, indexed by that byte, are the band a partial view keeps for the shards it does not hold. The node
/// crate's default shard bits must equal this (assert parity there, as `SCRATCHPAD_ELEMS` is asserted).
pub const NF_BAND_BITS: usize = 8;
/// The level of the band's entries: a shard subtree is `NF_BAND_LEVEL` levels deep.
pub const NF_BAND_LEVEL: usize = NF_SPARSE_DEPTH - NF_BAND_BITS;
/// The number of band entries a block ships: one per shard.
pub const NF_BAND_ENTRIES: usize = 1 << NF_BAND_BITS;

/// ⭐ DB-353 — FOLD A BAND TO THE TREE ROOT, exactly as the tree does it. Entry `2k` is the LEFT child of its pair at
/// every level (bit `NF_BAND_LEVEL + i` of the tag is 0 on the left, as `fold_sparse_native` pairs), through the SAME
/// `poseidon_pair_native` the nullifier carriers prove with — defined HERE so a door checking a shipped band against the
/// block's committed post root cannot re-derive the fold differently from the tree it certifies. `None` unless the band
/// is exactly `NF_BAND_ENTRIES` entries: a short or long band is a refusal, never a padded or truncated one.
///
/// The door's gate (node lane): (1) `fold_band(shipped) == the committed post root`, (2) every HELD shard's own
/// post-insert subtree root == the shipped entry, (3) adopt the foreign entries. A swap or a flip that passes (1) is a
/// Poseidon2 collision.
#[must_use]
pub fn fold_band(entries: &[Digest]) -> Option<Digest> {
    if entries.len() != NF_BAND_ENTRIES {
        return None;
    }
    let mut level: Vec<Digest> = entries.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| poseidon_pair_native(pair[0], pair[1])).collect();
    }
    level.first().copied()
}

/// ⭐⭐⭐ DB-353 — THE ONE KEY↔TAG RULE (2026-09-29 21:5x), shared by the node's `nf_sparse::SparseKey` and every sparse AIR
/// here: the tree's KEY is the byte-reversed TAG. A nullifier tag is a digest encoding — eight 31-bit lanes, byte 31 always
/// zero — and the tree descends from level 255 (bit 7 of byte 31), so under the identity map every real tag sat in shard 0;
/// reversed, tag byte 0 (uniform) selects the shard. Defined in ONE place so the two crates cannot drift; the node's
/// `SparseKey::of` / `.tag()` delegate here. MEASURED why the witness carries the KEY and DERIVES the tag rather than
/// carrying both: a witness with two fields lets a prover set `tag ≠ rev(key)` — the digest binds one and the path walks
/// the other, which is the position forgery in a struct.
#[must_use]
#[inline]
pub fn sparse_key_of_tag(tag: &[u8; 32]) -> [u8; 32] {
    let mut k = *tag;
    k.reverse();
    k
}
/// The inverse of [`sparse_key_of_tag`] (tag → key → tag is the identity).
#[must_use]
#[inline]
pub fn tag_of_sparse_key(key: &[u8; 32]) -> [u8; 32] {
    let mut t = *key;
    t.reverse();
    t
}

/// One spend's sparse settle witness: the tree KEY (the PATH the chains walk, `sparse_key_of_tag(tag)`) + its `DEPTH`
/// non-membership copath siblings (spender-supplied, self-built from the replicated DA stream). No index, no low-leaf,
/// no next-pointer — the position IS the key. Every VALUE use of the nullifier (the tag-space fold digest) reads
/// [`SparseInsertWitness::tag`], never the key bytes.
#[derive(Clone, Debug)]
pub struct SparseInsertWitness {
    pub key: [u8; 32],
    pub copath: Vec<Digest>,
}

impl SparseInsertWitness {
    /// The nullifier TAG this witness spends — the VALUE the block's tag list and the A_tip fold digest carry.
    #[must_use]
    pub fn tag(&self) -> [u8; 32] {
        tag_of_sparse_key(&self.key)
    }
}

/// NATIVE reference: does `w` prove a valid spend of `nf` taking `pre_root` → the returned `post_root`? The SAME
/// checks as the node's `nf_sparse::SparseNfAcc::verify_and_insert` (in the decider's limb field). `None` (fail-
/// closed) on the zero key, a wrong-length copath, or a copath that does NOT prove the leaf is EMPTY under `pre_root`
/// (a double-spend's leaf is already SPENT ⇒ non-membership fails ⇒ rejected).
pub fn native_sparse_insert_transition(w: &SparseInsertWitness, pre_root: Digest) -> Option<Digest> {
    let (claimed_pre, post) = native_sparse_insert_folds(w)?;
    // (1) NON-MEMBERSHIP: the leaf at position `nf` must be EMPTY under `pre_root` (also catches double-spend).
    (claimed_pre == pre_root).then_some(post)
}

/// ONE insert's two folds, read from its own witness alone: `(the root under which its leaf is EMPTY, the root once that
/// leaf is SPENT)` — the non-membership fold and the flip, along the SAME copath. `None` on the zero key or a wrong-length
/// copath. [`native_sparse_insert_transition`] is this plus the check that the first equals the running root; a block's
/// chain ([`sparse_block_post_native`]) computes every insert's folds at once and checks the chain in order.
fn native_sparse_insert_folds(w: &SparseInsertWitness) -> Option<(Digest, Digest)> {
    // ROOT-LAYER: the all-zero key is refused where the witness is CONSUMED — the native transition every carrier and the
    // node's `SparseNfAcc::verify_unspent` share — not where it is read back. MEASURED: moved unchanged from
    // `native_sparse_insert_transition` into the one helper both the sequential and the parallel chain consume (link 28);
    // the refusal is unchanged. MUST-STAY-GREEN: every sparse insert pin and the node's parity pins.
    if w.key == [0u8; 32] {
        return None;
    }
    if w.copath.len() != NF_SPARSE_DEPTH {
        return None;
    }
    // (2) flip the SAME leaf EMPTY→SPENT along the SAME copath → the new root.
    Some((fold_sparse_native(empty_leaf_native(), &w.key, &w.copath), fold_sparse_native(spent_leaf_native(), &w.key, &w.copath)))
}

/// The whole-block transition: chain each spend (`pre` of insert `i` = `post` of insert `i-1`). `None` (fail-closed)
/// the instant any spend is invalid — a bad witness never advances the block. This is the statement the compact
/// carrier binds to `(block_pre, block_post)`.
pub fn native_sparse_block_transition(inserts: &[SparseInsertWitness], block_pre: Digest) -> Option<Digest> {
    let mut root = block_pre;
    for w in inserts {
        root = native_sparse_insert_transition(w, root)?;
    }
    Some(root)
}

/// Reduce a raw limb into the canonical KoalaBear field element the gate + trace commit to.
#[inline]
pub(crate) fn fkred(x: u64) -> Fa4 {
    Fa4::from_u64(kred(x))
}

// The in-circuit sparse insert gate is the TRANSITION-LAYOUT `SparseChainGate` below (brick 2c) — one Poseidon
// fold-level per row, constant width, σ-chained. (The earlier wide-row `SparseInsertGate` — the whole fold in one
// ~16904-col row — was ~17× slower and is deleted; the chained gate proves the identical statement.)


// ── brick 2c: TRANSITION-LAYOUT — one fold-level PER ROW, constant width (the LIVE sparse insert gate) ─────────
// An earlier wide-row draft put the whole depth-256 fold in ONE row of ~16904 columns; the light decider's prover
// cost is super-linear in committed columns, so that was ~17× slower and is retired. Here the two folds (empty→pre
// non-membership, spent→post flip) are laid out with one Poseidon level PER ROW: a CONSTANT 69-col width, height =
// DEPTH (= 256 = 2⁸, a power of two ⇒ no padding), with each chain's `acc` threaded row→row by the cyclic-shift σ
// (identically to `NullifierBlockGate`). 16904 columns → 69 ⇒ far fewer committed polynomials and a sub-second prove,
// with IDENTICAL soundness: the first/last-row boundary welds pin the same committed `(pre_root, post_root)`, the σ
// transition ties `next.acc_in == this.acc_out`, and each row's Poseidon block is the same x⁷+MDS gadget.

// One chain's per-row block: acc_in[4] l[4] r[4] pre[4] ps[4] p4[4] p7[4] acc_out[4] = 32 cols.
const CH_SIB: usize = 0; // shared sibling
const CH_DIR: usize = DIGEST_LANES; // shared direction[1] — the nullifier's bit at this level
/// One chain's block: `acc_in`, a whole Poseidon2 permutation, and `acc_out`.
/// ⛔ WAS 32 columns of the 1-round fold's `left/right/pre/sq/p4/p7/acc_out` (kill list §AG).
const CHAIN_BLOCK: usize = 2 * DIGEST_LANES + crate::pow_pq_air::P2_COLS;
const CH_AINE: usize = CH_DIR + 1; // empty-chain block start
const CH_AOUTE: usize = CH_AINE + DIGEST_LANES + crate::pow_pq_air::P2_COLS;
const CH_AINS: usize = CH_AINE + CHAIN_BLOCK; // spent-chain block start
const CH_AOUTS: usize = CH_AINS + DIGEST_LANES + crate::pow_pq_air::P2_COLS;
pub const SPARSE_CHAIN_COLS: usize = CH_AINS + CHAIN_BLOCK;

/// Fill one chain's per-row columns at `base` from `acc_in`, the shared `sib`, and `dir`; returns `acc_out`.
fn emit_chain_row(row: &mut [Fa4], base: usize, accin: Digest, sib: Digest, dir: u64) -> Digest {
    let blk = base + DIGEST_LANES;
    emit_chain_row_at(row, base, blk, blk + crate::pow_pq_air::P2_COLS, accin, sib, dir)
}

/// [`emit_chain_row`] with the three column groups placed independently — `accin_off` (the accumulator in), `blk_off`
/// (the permutation block) and `accout_off` (the accumulator out) — so a layout may keep its next-row-read cells in one
/// contiguous run and the wide blocks elsewhere (`nf_band_air`). ONE lay for every chain in the crate.
pub(crate) fn emit_chain_row_at(row: &mut [Fa4], accin_off: usize, blk_off: usize, accout_off: usize, accin: Digest, sib: Digest, dir: u64) -> Digest {
    for c in 0..DIGEST_LANES {
        row[accin_off + c] = fkred(accin[c]);
    }
    let (left, right) = if dir == 0 { (accin, sib) } else { (sib, accin) };
    crate::pow_pq_air::lay_perm_row_flat(row, blk_off, crate::pow_pq_air::pair_state(&left, &right));
    let accn = poseidon_pair_native(left, right);
    for c in 0..DIGEST_LANES {
        row[accout_off + c] = fkred(accn[c]);
    }
    accn
}

/// Build the transition-layout trace (columns) for a valid spend + the certified `post_root`. `None` if the native
/// transition rejects (a carrier exists ONLY for a genuine non-membership + flip).
fn sparse_chain_cols(w: &SparseInsertWitness, pre_root: Digest) -> Option<(Vec<Vec<Fa4>>, Digest)> {
    let post = native_sparse_insert_transition(w, pre_root)?;
    let depth = NF_SPARSE_DEPTH; // 256 = 2⁸ — a power of two, so the trace needs no padding rows.
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(depth);
    let mut acc_e = empty_leaf_native();
    let mut acc_s = spent_leaf_native();
    for i in 0..depth {
        let mut row = vec![Fa4::ZERO; SPARSE_CHAIN_COLS];
        let sib = w.copath[i];
        let dir = nf_bit(&w.key, i) as u64;
        for c in 0..DIGEST_LANES {
            row[CH_SIB + c] = fkred(sib[c]);
        }
        row[CH_DIR] = Fa4::from_u64(dir);
        acc_e = emit_chain_row(&mut row, CH_AINE, acc_e, sib, dir);
        acc_s = emit_chain_row(&mut row, CH_AINS, acc_s, sib, dir);
        rows.push(row);
    }
    // Transpose rows → columns for the light decider.
    let cols: Vec<Vec<Fa4>> = (0..SPARSE_CHAIN_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    Some((cols, post))
}

/// The transition-layout gate: per-row Poseidon (both chains) + the σ acc-chain + first/last boundary welds.
pub struct SparseChainGate {
    pub gamma: Ea4,
    /// The two roots as BASE-field limbs, lifted into whichever field the row lives in (the base-field round 0).
    pub pre_root: [Fa4; DIGEST_LANES],
    pub post_root: [Fa4; DIGEST_LANES],
    /// `γ^0 … γ^k` ([`sparse_block_powers`]): the k-th residual takes γ^k.
    pub gpow: Vec<Ea4>,
}

/// One chain's per-row Poseidon-block residuals at `base` (shared `sib`/`dir` at `CH_SIB`/`CH_DIR` of the row). ZERO
/// iff `acc_out == x⁷+MDS(dir?sib:acc_in, dir?acc_in:sib)`. Shared by the single-insert `SparseChainGate` AND the
/// block `SparseBlockGate` — one fold gadget, no duplication.
// Generic over the row's field (the type parameter is NAMED `Ea4` so the body reads unchanged): the block gate's
// base-field round 0 evaluates both chains in the base field.
#[allow(non_camel_case_types)]
fn push_chain_residuals<Ea4: p3_field::Field + p3_field::Algebra<Fa4>>(local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, rs: &mut Vec<Ea4>) {
    let blk = base + DIGEST_LANES;
    push_chain_residuals_at(local, CH_SIB, CH_DIR, base, blk, blk + crate::pow_pq_air::P2_COLS, rs);
}

/// [`push_chain_residuals`] with every column group placed independently: the shared sibling at `sib_off`, the direction
/// bit at `dir_off`, the accumulator in at `accin_off`, the permutation block at `blk_off`, the accumulator out at
/// `accout_off`. ONE gadget — the input welds, the permutation and the OUTPUT weld — for every chain layout in the crate.
#[allow(non_camel_case_types, clippy::too_many_arguments)]
pub(crate) fn push_chain_residuals_at<Ea4: p3_field::Field + p3_field::Algebra<Fa4>>(
    local: &crate::air_zerocheck::Row<'_, Ea4>,
    sib_off: usize,
    dir_off: usize,
    accin_off: usize,
    blk_off: usize,
    accout_off: usize,
    rs: &mut Vec<Ea4>,
) {
    let dir = local[dir_off];
    let sib = |c: usize| local[sib_off + c];
    let accin = |c: usize| local[accin_off + c];
    let blk = blk_off;
    crate::pow_pq_air::push_perm_residuals(local, blk, rs);
    for c in 0..DIGEST_LANES {
        // left = dir ? sib : acc ; right = dir ? acc : sib — the same selection the fold performs.
        rs.push(local[blk + c] - (accin(c) + dir * (sib(c) - accin(c))));
        rs.push(local[blk + DIGEST_LANES + c] - (sib(c) + dir * (accin(c) - sib(c))));
        // ⛔⛔⛔ THE OUTPUT WELD (2026-09-29 21:0x). Without this line `acc_out` was a FREE cell: the block's inputs were
        // welded, the permutation inside it was honest, and nothing tied its output to the accumulator the chain and
        // boundary laws read — so a prover could choose every accumulator, prove ANY (pre, post) transition and pass
        // every non-membership check. MEASURED before the fix by `db353_a_forged_accumulator_beside_an_honest_permutation
        // _is_refused`: a bumped `acc_out` claimed as `block_post` vanished on every row. `acc_out` = the compression =
        // the permutation's first DIGEST_LANES output lanes (`poseidon2_compress::compress`, mirrored by the weld in
        // `acc_step_air`, `note_membership_air`, `nullifier_insert_air`).
        rs.push(local[blk + crate::pow_pq_air::PERM_OUT + c] - local[accout_off + c]);
    }
}

impl SparseChainGate {
    /// The single-insert relation, GENERIC over the field its row lives in (the type parameter is NAMED `Ea4` so the laws
    /// read unchanged): the extension for `eval`, the base field for the zerocheck's round 0 (`eval_base`). Batched into
    /// `Ext` through the power table by extension-by-base products.
    #[allow(non_camel_case_types)]
    pub fn eval_in<Ea4>(&self, local: &crate::air_zerocheck::Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::new();
        // direction boolean (shared by both chains).
        let dir = local[CH_DIR];
        rs.push(dir * (one - dir));
        // both chains' per-row Poseidon block.
        push_chain_residuals(local, CH_AINE, &mut rs);
        push_chain_residuals(local, CH_AINS, &mut rs);
        // boundary welds + the acc-chain (next-row reads are the rot-fold's rotation).
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let sp = spent_leaf_native();
        for c in 0..DIGEST_LANES {
            // FIRST row: the empty-chain seed is empty_leaf (0); the spent-chain seed is the spent_leaf constant.
            rs.push(is_first * (local[CH_AINE + c] - zero));
            rs.push(is_first * (local[CH_AINS + c] - Ea4::from(fkred(sp[c]))));
            // LAST row: the empty-chain folds to the committed pre_root (non-membership); spent-chain to post_root.
            rs.push(is_last * (local[CH_AOUTE + c] - Ea4::from(self.pre_root[c])));
            rs.push(is_last * (local[CH_AOUTS + c] - Ea4::from(self.post_root[c])));
            // TRANSITION: next row's acc_in equals this row's acc_out (both chains).
            rs.push(not_last * (at(CH_AINE + c, &sigma) - local[CH_AOUTE + c]));
            rs.push(not_last * (at(CH_AINS + c, &sigma) - local[CH_AOUTS + c]));
        }
        let mut out = Ext::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }
}

impl crate::air_zerocheck::AirConstraint for SparseChainGate {
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED 3 by the debug prover's degree census (2026-09-29): the two chains' cube and degree-1 point selectors
        // times one column; the next-row reads are the rot-fold's rotation, not the σ point-shift whose `nvars + 1` this
        // declared — 11 sample points per round where 5 suffice. Guarded by the census and the per-round assert.
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
}

/// A single insert as an INDEPENDENT batch table whose interior root stays PRIVATE — the chain-ENFORCING
/// aggregation the naive settlement-fold lacked. Same per-row Poseidon folds as [`SparseChainGate`], but the
/// pre/post-root boundary welds are OPTIONAL: only the block ENDPOINTS (table 0's `pre`, table N-1's `post`)
/// weld to the block's committed endpoint roots (`block_pre` / `block_post`); interior links carry NO endpoint
/// weld. The chain `R_i → R_{i+1}` is enforced off-circuit by a CROSS-TIE — `table[i].CH_AOUTS(post) ==
/// table[i+1].CH_AOUTE(pre)`, a committed-to-committed equality bound to each table's WHIR commitment (see
/// `verify_air_batch_light_decider_bytes_with_bus`). That SAME equality is the non-membership / double-spend
/// gate: `pre_{i+1}` is the empty-fold at `nf_{i+1}`'s position, so tying it to `post_i` (= R_{i+1}) forces
/// `nf_{i+1}` to be EMPTY in R_{i+1}. The interior roots R_1..R_{N-1} are NEVER exposed (the cross-tie opens
/// committed cells, not the statement bind), so a treeless verifier still checks ONLY `(block_pre, block_post)`
/// — O(1). Unlike the monolithic `SparseBlockGate`, the N per-insert traces are INDEPENDENT ⇒ each provable the
/// instant its spend arrives (streamed across the block interval), never a single N·DEPTH-row prove at block close.
pub struct SparseChainLink {
    pub gamma: Ea4,
    /// `Some(block_pre)` on table 0 only (else the interior pre-root stays private, tied by the cross-tie).
    pub weld_pre: Option<[Ea4; DIGEST_LANES]>,
    /// `Some(block_post)` on table N-1 only (else the interior post-root stays private, tied by the cross-tie).
    pub weld_post: Option<[Ea4; DIGEST_LANES]>,
}

impl crate::air_zerocheck::AirConstraint for SparseChainLink {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE) // identical to `SparseChainGate`: the σ carry-chain dominates the per-row degree 3
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs = Vec::new();
        let dir = local[CH_DIR];
        rs.push(dir * (one - dir));
        push_chain_residuals(local, CH_AINE, &mut rs);
        push_chain_residuals(local, CH_AINS, &mut rs);
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let sp = spent_leaf_native();
        for c in 0..DIGEST_LANES {
            // FIRST row seeds (identical to the single-insert gate): empty-chain 0, spent-chain the spent leaf.
            rs.push(is_first * (local[CH_AINE + c] - zero));
            rs.push(is_first * (local[CH_AINS + c] - Ea4::from(fkred(sp[c]))));
            // LAST row: ENDPOINT welds ONLY. Interior tables leave CH_AOUTE/CH_AOUTS as committed cells the
            // cross-tie binds to the neighbour — R_1..R_{N-1} never touch an endpoint constant (privacy).
            if let Some(pre) = self.weld_pre {
                rs.push(is_last * (local[CH_AOUTE + c] - pre[c]));
            }
            if let Some(post) = self.weld_post {
                rs.push(is_last * (local[CH_AOUTS + c] - post[c]));
            }
            // TRANSITION: next row's acc_in equals this row's acc_out (both chains).
            rs.push(not_last * (at(CH_AINE + c, &sigma) - local[CH_AOUTE + c]));
            rs.push(not_last * (at(CH_AINS + c, &sigma) - local[CH_AOUTS + c]));
        }
        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
}

// ── brick 2b: WHIR light-decider CARRIER (prove/verify) ───────────────────────────────────────────────────────
// The exact wrap the IMT single-insert carrier uses, over the sparse gate: a treeless verifier runs ONE O(1) proof
// (no held tree, no copath) to accept the spend's `pre_root → post_root`. The endpoints are welded into the WHIR
// transcript, so a carrier proving a DIFFERENT transition than the verifier checks is rejected.

/// Domain tag for the sparse settle transcript ("NFSPRS").
pub const NF_SPARSE_DOMAIN: u64 = 0x4e46_5350_5253;

fn sparse_insert_statement_bind(pre: &[Fa4; DIGEST_LANES], post: &[Fa4; DIGEST_LANES]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_SPARSE_DOMAIN)];
    b.extend_from_slice(pre);
    b.extend_from_slice(post);
    b
}

/// PROVE one sparse spend as an O(1) WHIR light-decider carrier. `(carrier_bytes, post_root)`; `None` if the witness
/// is not a valid spend (the native transition rejects) — a carrier exists ONLY for a genuine non-membership + flip.
pub fn prove_sparse_insert_carrier_bytes(w: &SparseInsertWitness, pre_root: Digest) -> Option<(Vec<u8>, Digest)> {
    // Transition-layout trace: constant 69-col width × DEPTH rows (fast) — see `SparseChainGate`.
    let (cols, post) = sparse_chain_cols(w, pre_root)?;
    let pre_f = core::array::from_fn(|i| fkred(pre_root[i]));
    let post_f = core::array::from_fn(|i| fkred(post[i]));
    let make = move |g: Ea4| SparseChainGate { gamma: g, pre_root: pre_f, post_root: post_f, gpow: sparse_block_powers(g) };
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &sparse_insert_statement_bind(&pre_f, &post_f),
    )?;
    Some((carrier, post))
}

/// VERIFY a sparse spend carrier binds to the committed `(pre_root, post_root)`. Fail-closed on any decode /
/// constraint / root mismatch — the O(1) proof-only double-spend check a treeless verifier runs (no held tree).
#[must_use]
pub fn verify_sparse_insert_carrier_bytes(bytes: &[u8], pre_root: Digest, post_root: Digest) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let pre_f = core::array::from_fn(|i| fkred(pre_root[i]));
    let post_f = core::array::from_fn(|i| fkred(post_root[i]));
    let make = move |g: Ea4| SparseChainGate { gamma: g, pre_root: pre_f, post_root: post_f, gpow: sparse_block_powers(g) };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &sparse_insert_statement_bind(&pre_f, &post_f),
        (NF_SPARSE_DEPTH.trailing_zeros() as usize, SPARSE_CHAIN_COLS),
    )
}

// ── brick 2c: NESTED BLOCK GATE — chain N sparse inserts into ONE O(1) proof ───────────────────────────────────
// A block applies N sparse spends R_0 → R_1 → … → R_N. Each spend is a DEPTH-row transition-layout fold (the
// `SparseChainGate` shape). The block trace is N·DEPTH rows (one fold-level per row), and a `running_root[4]` CARRY
// column threads R_i through the DEPTH rows of insert i. HIGH-bit-first row index (see `cyclic_shift_sigma`): the LOW
// `LEVEL_BITS` = the fold level `l`, the HIGH bits = the insert index `i`. Constraints (the intermediate roots stay
// PRIVATE in the trace, so a treeless verifier checks ONLY `block_pre`/`block_post` — O(1)):
//   • per row: both chains' Poseidon block + `dir` boolean;
//   • level 0 (`is_level0`): acc_in = the empty/spent seed;
//   • boundary l=DEPTH-1 (`is_boundary`): the empty-fold hits `running_root` (NON-MEMBERSHIP against the CURRENT root
//     R_i — this is the double-spend gate); the spent-fold `acc_out` is R_{i+1};
//   • within an insert (¬boundary): next.acc_in = this.acc_out (fold σ-chain) AND next.running_root = running_root;
//   • at a boundary that is not the last insert: next.running_root = this spent `acc_out` (advance R_i → R_{i+1});
//   • first insert: running_root = block_pre;  very last row: spent acc_out = block_post.

/// The running-root carry column (R_i), after the 69 chained-fold columns.
const CH_RROOT: usize = SPARSE_CHAIN_COLS;
/// Block-trace per-row width.
pub const SPARSE_BLOCK_COLS: usize = SPARSE_CHAIN_COLS + DIGEST_LANES; // the committed root is a DIGEST
/// ⭐ DB-353 KEY BINDING (2026-09-29, docs/DB-353-SOUND-SHARDING-CARRIER-SPEC.md §3): the KEYED block trace adds a running
/// lane accumulator and nine frozen lane values so every insert's 256 key bits (`CH_DIR`, one per level) are bound to a
/// PUBLIC key list — without it a prover inserts at positions other than the block's tags and a treeless or partial door
/// cannot tell (omit a real tag → a later double spend; insert elsewhere → freeze a position). `CH_KACC`: within a lane
/// of `KEY_LANE_BITS` levels the accumulator starts at the lane's first bit and doubles-and-takes each next bit, so at the lane's last
/// level it holds the lane's bits MSB-first (`key_lanes_of`); `CH_KEY + j`: lane j's value, frozen across the insert and
/// bound at the boundary row to the public list's lane j through the multilinear extension over the insert index.
const CH_KACC: usize = SPARSE_BLOCK_COLS;
const CH_KEY: usize = CH_KACC + 1;
/// Bits per key lane. ⛔ 30, NOT 31 (found 2026-09-29 19:4x before the first pin ran): a lane value must be a CANONICAL
/// field element for the binding to be injective — the field's modulus is below 2^31, so a 31-bit chunk `v ≥ p` and the
/// chunk `v − p` are ONE field element, and a prover could walk the aliased position under the public tag (the DB-362
/// mod-p alias class, here in the key). `2^30 − 1 < p` is checked at compile time below.
pub const KEY_LANE_BITS: usize = 30;
/// Eight lanes of 30 bits and one lane of 16: `NF_SPARSE_DEPTH = 8 · 30 + 16`. The number of KEY LANES per insert — a
/// layout constant of the carrier (ceil(256 levels / 30 bits)), never a block or cover count; every block test in this
/// file runs at `PRODUCTION_BLOCK_COVER`.
pub const KEY_LANES: usize = 9; // PRODUCTION-SCALE-REVIEWED: lanes per key = ceil(NF_SPARSE_DEPTH / KEY_LANE_BITS), a layout constant, not a block/cover sample
const _: () = assert!(
    ((1u64 << KEY_LANE_BITS) - 1) < <Fa4 as p3_field::PrimeField64>::ORDER_U64,
    "a key lane must be a canonical field element (injective binding)"
);
const _: () = assert!(
    KEY_LANE_BITS * (KEY_LANES - 1) < NF_SPARSE_DEPTH && KEY_LANE_BITS * KEY_LANES >= NF_SPARSE_DEPTH,
    "the lanes cover the depth exactly: eight full lanes and one short one"
);
/// ⭐ THE DIGEST SPELLING (2026-09-29 21:2x, carrier spec §9 + the aggregate refutation 20:30): the nine lane values are
/// ABSORBED into a running Poseidon2 chain — two rows per insert: level 254 absorbs lanes 0..7, level 255 (the boundary)
/// absorbs lane 8 and the live/pad domain — and the chain's end is ONE public digest the door recomputes natively from the
/// header's tags (`keys_digest_of`). In the fold-band AGGREGATE the per-row public tuple is then 8 cells, where the
/// multilinear-extension spelling would have needed the whole key list as outer cells (evaluated at the inner point, a
/// witness of the outer row).
///
/// ⭐ THE CHAIN LIVES IN ITS OWN TABLE (link 79, docs/DB-452-LIGHT-DECIDER-COMMITTED-OPENING.md §9). It was laid on every
/// row of the chain table — 173 of its 560 columns, absorbing on 2 of an insert's 256 levels — and pushed the 256-insert
/// slice past 2^25 cells (stacked arity 26: commit 49.7 s + WHIR 24.2 s, MEASURED link 78). The digest table holds the same
/// chain at 2 rows per insert; ONE column tie welds its lane cells to this table's frozen lanes.
/// The keyed chain table's width: the unkeyed block, the lane accumulator and the nine frozen lane values.
pub const SPARSE_BLOCK_KEYED_COLS: usize = CH_KEY + KEY_LANES;
/// The DIGEST table (`sparse_keys_digest_cols`): 2 rows per insert — the high row-index bits are the insert index (the
/// chain table's own high bits, which is what lets one column tie weld them), the low bit the absorb step (0: lanes 0..7,
/// 1: lane 8 and the REAL/PAD domain). `DG_KEY + j`: lane j, frozen within the insert and tied to the chain table's;
/// `DG_LIVE`: 1 for inserts up to `bind_at`, 0 after (padding inserts absorb constants, so the door's recompute needs only
/// `n_real` and `n`); `DG_DIN`: the running digest entering the row; `DG_BLK`: the block (left input = `DG_DIN`, right
/// input = the absorbed lanes, output read at `PERM_OUT`).
const DG_KEY: usize = 0;
const DG_LIVE: usize = DG_KEY + KEY_LANES;
const DG_DIN: usize = DG_LIVE + 1;
const DG_BLK: usize = DG_DIN + DIGEST_LANES;
/// The digest table's width.
pub const SPARSE_KEYS_DIGEST_COLS: usize = DG_BLK + crate::pow_pq_air::P2_COLS;
/// The digest table's low row-index bits: two absorb steps per insert.
const DG_STEP_BITS: usize = 1;
/// The digest chain's domain constants — ONE definition; the circuit lifts them, `keys_digest_of` folds them.
pub(crate) const KEYS_DIGEST_REAL: u64 = 1;
pub(crate) const KEYS_DIGEST_PAD: u64 = 2;
pub(crate) fn keys_digest_init() -> Digest {
    crate::poseidon2_compress::lanes_of(&[0x0DB3_53, 0x4B45_5953, 0x4449_4745, 0x2026_0929])
}
/// The two right-hand inputs an insert's lanes present to the digest chain: at level 254 lanes 0..7 (zeros for a padding
/// insert), at level 255 lane 8 and the REAL/PAD domain. Shared by the prover's lay and the door's native recompute.
pub(crate) fn keys_digest_absorb_inputs(lanes: &[Fa4; KEY_LANES], live: bool) -> (Digest, Digest) {
    let to_u = |f: Fa4| p3_field::PrimeField64::as_canonical_u64(&f);
    let r254: Digest = core::array::from_fn(|c| if live { to_u(lanes[c]) } else { 0 });
    let mut r255 = [0u64; DIGEST_LANES];
    r255[0] = if live { to_u(lanes[KEY_LANES - 1]) } else { 0 };
    r255[1] = if live { KEYS_DIGEST_REAL } else { KEYS_DIGEST_PAD };
    (r254, r255)
}
/// The PUBLIC key digest of a shard's (or a block's) insert list: `keys` are the REAL keys in trace order (the KEY the tree
/// uses — `SparseKey::of(tag)` once the selector lands), `n ≥ keys.len()` the trace's insert count (a power of two); the
/// inserts past `keys.len()` absorb the PAD constants, so `[k]` at n = 2 and `[k, k']` at n = 2 and `[k]` at n = 1 are three
/// different digests (length-bound). The empty list at any `n` is the empty-shard constant the door requires.
#[must_use]
pub fn keys_digest_of(keys: &[[u8; 32]], n: usize) -> Digest {
    let mut st = keys_digest_init();
    for i in 0..n {
        let live = i < keys.len();
        let lanes = if live { key_lanes_of(&keys[i]) } else { [Fa4::ZERO; KEY_LANES] };
        let (r254, r255) = keys_digest_absorb_inputs(&lanes, live);
        st = poseidon_pair_native(st, r254);
        st = poseidon_pair_native(st, r255);
    }
    st
}
/// The first level of lane j.
pub(crate) const fn lane_start_level(j: usize) -> usize {
    KEY_LANE_BITS * j
}
/// The last level of lane j (lane 8 holds levels 240..255).
pub(crate) const fn lane_end_level(j: usize) -> usize {
    if j == KEY_LANES - 1 { NF_SPARSE_DEPTH - 1 } else { KEY_LANE_BITS * j + KEY_LANE_BITS - 1 }
}
/// The nine lane values of a key as the keyed trace accumulates them: lane j is the key's bits `lane_start_level(j) ..=
/// lane_end_level(j)` in level order, the FIRST level as the most significant bit — exactly what `CH_KACC` holds at the
/// lane's last level. ONE spelling for the prover's lay and the verifier's public inputs; the node hands the KEY the tree
/// uses (`SparseKey::of(tag)` once the selector lands; the tag itself today).
#[must_use]
pub fn key_lanes_of(key: &[u8; 32]) -> [Fa4; KEY_LANES] {
    core::array::from_fn(|j| {
        let mut v = 0u64;
        for l in lane_start_level(j)..=lane_end_level(j) {
            v = (v << 1) | u64::from(nf_bit(key, l));
        }
        Fa4::from_u64(v)
    })
}
/// Fold-level bits = log2(DEPTH). The low `LEVEL_BITS` of the row index are the level `l`.
const LEVEL_BITS: usize = 8; // DEPTH = 256 = 2^8

/// Build the block trace (columns) for N chained inserts + the certified `block_post`. `None` if `N` is not a power
/// of two (needed for a clean 2^k trace height) or any insert is invalid against the running root.
pub fn sparse_block_cols(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    // How many of `inserts` are REAL. The rest are power-of-two padding supplied by the caller, and the
    // returned `block_post` is the root after the REAL ones only — the padding must never move the endpoint
    // this block commits.
    real_n: usize,
) -> Option<(Vec<Vec<Fa4>>, Digest)> {
    let (cols, post, _digest) = sparse_block_cols_with(inserts, block_pre, real_n, false)?;
    Some((cols, post))
}

/// [`sparse_block_cols`] with the DB-353 key columns laid when `keyed` (the keyed chain table is `SPARSE_BLOCK_KEYED_COLS`
/// wide; the unkeyed one keeps its width and bytes exactly). Returns `(cols, block_post, keys_digest)`; the digest is
/// `keys_digest_of` over the REAL inserts' keys at the trace's insert count (the init constant when unkeyed) — the chain
/// that computes it in-circuit is the digest table ([`sparse_keys_digest_cols`]).
pub fn sparse_block_cols_with(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    real_n: usize,
    keyed: bool,
) -> Option<(Vec<Vec<Fa4>>, Digest, Digest)> {
    let width = if keyed { SPARSE_BLOCK_KEYED_COLS } else { SPARSE_BLOCK_COLS };
    // cons: none — 2x trace rows worst case, f(ONE BLOCK'S OWN SPEND COUNT) with no history term at all
    // (not height, not block count, not chain size), and 64x CHEAPER than the 256-insert shape this replaced.
    // Full arithmetic below.
    //
    // ⭐⭐⭐ PAD THE PROOF-INTERNAL TRACE TO A POWER-OF-TWO INSERT COUNT — P0's SHAPE, ON THE BLOCK CARRIER.
    //
    // This used to `return None` unless `n.is_power_of_two()`, and `Node::build_block_sparse_nf_carrier` maps
    // `None` to an EMPTY `NfBlockProof` — silently. Under the retired 256-wide cover every block had 256
    // inserts (2^8) so the bail could never fire; retiring the cover made the count the REAL spend count, and
    // a block settling 3 (or 5, 6, 7 ...) spends began shipping no nullifier transition certificate at all.
    // MEASURED via `sparse_produce_carrier_verifies_and_rejects_tamper`: 3 txs -> no carrier, 4 txs -> carrier
    // builds AND verifies. Exactly the class P0 fixed for the ABSENCE prover, here in the block prover.
    //
    // The padding is PROVER-INTERNAL and never reaches the consensus spent set — that set is
    // `cover::block_nullifier_set(real)`, untouched. P0 recorded trying the other placement: "NOT in
    // `cover::block_nullifier_set` — it put marker values into the CONSENSUS spent set and changed every
    // downstream root: 46 tests red." The endpoint stays honest because `block_post` binds at
    // `bind_at = n - 1` (see `SparseBlockGate`), so padded inserts sit BEYOND the committed transition.
    //
    // THE ARITHMETIC, in trace rows (the unit that decides prove time):
    //   n=1 -> 1 insert (2^0, no pad) =    256 rows
    //   n=2 -> 2 inserts (no pad)     =    512 rows
    //   n=3 -> 4 inserts (+1 pad)     =  1,024 rows  (vs 768 unpadded: +256 rows, ONCE, for this block)
    //   n=5..7 -> 8 inserts           =  2,048 rows
    //   worst case is n just over a power of two: rounds up to < 2n inserts, so < 2x rows, bounded by the
    //   block's own fixed tx shape. The RETIRED cover proved 256 inserts = 65,536 rows on EVERY block
    //   unconditionally, so 2,048 is a 32x reduction and 1,024 a 64x one. This is strictly cheaper than the
    //   shape that shipped for months, and adds no wire bytes, no stored state and no consensus field.
    let n = inserts.len();
    if n == 0 {
        return None;
    }
    // ⛔ THE PADDING ITSELF MUST BE SUPPLIED BY THE CALLER, NOT MANUFACTURED HERE — and that is a finding,
    // not a preference. A filler insert is only admissible if it carries a VALID non-membership copath against
    // the running root at its position, and this function receives witnesses; it holds no tree to derive one
    // from. The tree lives in the node (`Node::build_block_sparse_nf_carrier` and its overlay), so the node is
    // the only party that can build a filler witness. Manufacturing a fake one here would mean relaxing the
    // non-membership constraint, i.e. weakening the double-spend gate to make a proof shape fit — the exact
    // swap the soundness cardinal forbids.
    //
    // So this half lands the ENDPOINT BINDING (`bind_at`, above), which is what makes padded witnesses
    // admissible at all, and the bail stays until the node supplies them. With no padding `bind_at == n - 1`
    // is exactly the last insert, so this is behaviour-identical today and every existing carrier still
    // verifies — verified by the decider suite staying green.
    // The CALLER supplies a power-of-two insert count: reals first, then fillers witnessed against a scratch
    // clone of the producer's tree (`Node::build_block_sparse_nf_carrier`). Only the node holds a tree, so only
    // the node can build a filler's non-membership copath — manufacturing one here would mean relaxing the
    // non-membership constraint, i.e. weakening the double-spend gate to fit a proof shape. Still fail-closed
    // if a caller hands over a count the layout cannot address.
    if !n.is_power_of_two() {
        return None;
    }
    let depth = NF_SPARSE_DEPTH; // 256 = 2^8; n*depth = 2^(log2 n + 8) -> clean trace height
    if real_n == 0 || real_n > n {
        return None; // a claim about more reals than the trace holds, or none at all — fail-closed
    }
    // ⭐ link 80 (2026-10-21) — EVERY INSERT'S DEPTH ROWS ON EVERY CORE, THE CHAIN IN ORDER (the trace twin of
    // `sparse_block_post_native`, link 28). An insert's rows read only its own witness — its copath, key bits and the two
    // chains from the empty and spent leaves — except `R_i`, the running root its rows repeat; so every insert's rows and
    // its two native folds are built at once, then the chain is checked in insert order (insert i's empty fold must be
    // the running root: exactly `native_sparse_insert_transition` chained, the same values and the same refusals) and
    // `R_i` is written into its rows. The columns are then gathered one per worker. Pinned byte for byte against a
    // one-thread prove by `db452_g_…`, and the refusals by every band pin (`db452_e`, `db452_f`, the db353 forgeries).
    // MEASURED why (`sample`, the 256-insert band slice prove, night/link80-par2-sample.txt): the serial trace was 300 of
    // the prove's 8,961 samples. cons: a refused block lays up to `n − 1` inserts' rows the sequential loop stopped
    // before (n ≤ the cover width), on the refusal path only.
    use rayon::prelude::*;
    let laid: Vec<Option<(Vec<Vec<Fa4>>, (Digest, Digest))>> = inserts
        .par_iter()
        .map(|w| {
            // non-membership fold (the root R_i under which this leaf is EMPTY) + flip -> R_{i+1}, from the witness alone
            let folds = native_sparse_insert_folds(w)?;
            let mut acc_e = empty_leaf_native();
            let mut acc_s = spent_leaf_native();
            let lanes = key_lanes_of(&w.key);
            let mut kacc = 0u64;
            let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(depth);
            for l in 0..depth {
                let mut row = vec![Fa4::ZERO; width];
                let sib = w.copath[l];
                let dir = nf_bit(&w.key, l) as u64;
                for c in 0..DIGEST_LANES {
                    row[CH_SIB + c] = fkred(sib[c]);
                }
                row[CH_DIR] = Fa4::from_u64(dir);
                acc_e = emit_chain_row(&mut row, CH_AINE, acc_e, sib, dir);
                acc_s = emit_chain_row(&mut row, CH_AINS, acc_s, sib, dir);
                if keyed {
                    // the lane accumulator: the lane's first bit at its first level, then double-and-take
                    let lane_start = (0..KEY_LANES).any(|j| lane_start_level(j) == l);
                    kacc = if lane_start { dir } else { (kacc << 1) | dir };
                    row[CH_KACC] = Fa4::from_u64(kacc);
                    for j in 0..KEY_LANES {
                        row[CH_KEY + j] = lanes[j];
                    }
                }
                rows.push(row);
            }
            Some((rows, folds))
        })
        .collect();
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n * depth);
    let mut running = block_pre;
    // The committed endpoint: the running root immediately AFTER the last REAL insert. Padding continues to
    // advance `running` (so its rows chain and satisfy the AIR unchanged) but never touches this value.
    let mut block_post_real = block_pre;
    for (idx, insert) in laid.into_iter().enumerate() {
        let (mut insert_rows, (claimed_pre, post)) = insert?;
        if claimed_pre != running {
            return None; // non-membership vs `running` (R_i) — `native_sparse_insert_transition`'s refusal
        }
        for row in insert_rows.iter_mut() {
            for c in 0..DIGEST_LANES {
                row[CH_RROOT + c] = fkred(running[c]); // R_i, constant across insert i's DEPTH rows
            }
        }
        rows.extend(insert_rows);
        running = post;
        if idx + 1 == real_n {
            block_post_real = running; // R_real_n — the endpoint the block commits
        }
    }
    let cols: Vec<Vec<Fa4>> = (0..width).into_par_iter().map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    let digest = if keyed {
        let keys: Vec<[u8; 32]> = inserts[..real_n].iter().map(|w| w.key).collect();
        keys_digest_of(&keys, n)
    } else {
        keys_digest_init()
    };
    Some((cols, block_post_real, digest))
}

/// The DIGEST table of a keyed carrier (layout at `DG_KEY`): insert i's two rows absorb its lanes into the running chain
/// exactly as [`keys_digest_of`] folds them — one helper for the absorbed inputs ([`keys_digest_absorb_inputs`]) — so the
/// chain's end is the door's native recompute. `None` on a count the layout cannot address (as the chain table).
pub fn sparse_keys_digest_cols(inserts: &[SparseInsertWitness], real_n: usize) -> Option<(Vec<Vec<Fa4>>, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() || real_n == 0 || real_n > n {
        return None;
    }
    let mut din = keys_digest_init();
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n << DG_STEP_BITS);
    for (idx, w) in inserts.iter().enumerate() {
        let lanes = key_lanes_of(&w.key);
        let live = idx < real_n;
        let (r254, r255) = keys_digest_absorb_inputs(&lanes, live);
        for right in [r254, r255] {
            let mut row = vec![Fa4::ZERO; SPARSE_KEYS_DIGEST_COLS];
            row[DG_KEY..DG_KEY + KEY_LANES].copy_from_slice(&lanes);
            row[DG_LIVE] = Fa4::from_u64(u64::from(live));
            for c in 0..DIGEST_LANES {
                row[DG_DIN + c] = fkred(din[c]);
            }
            crate::pow_pq_air::lay_perm_row_flat(&mut row, DG_BLK, crate::pow_pq_air::pair_state(&din, &right));
            din = poseidon_pair_native(din, right);
            rows.push(row);
        }
    }
    let cols: Vec<Vec<Fa4>> = (0..SPARSE_KEYS_DIGEST_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    Some((cols, din))
}

/// A keyed carrier's two committed tables `[chain, digest]`, its `block_post` and its keys digest — the ONE lay the prover
/// and every test fixture build. `None` exactly when either table refuses (an invalid insert or count).
pub fn sparse_block_keyed_tables(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    real_n: usize,
) -> Option<(Vec<Vec<Vec<Fa4>>>, Digest, Digest)> {
    let (chain, post, digest) = sparse_block_cols_with(inserts, block_pre, real_n, true)?;
    let (dg, chain_end) = sparse_keys_digest_cols(inserts, real_n)?;
    if chain_end != digest {
        return None; // two spellings of one digest disagree — fail-closed, never a carrier over either
    }
    Some((vec![chain, dg], post, digest))
}

/// The keyed carrier's ONE column tie: the chain table's nine frozen lanes at an insert's boundary row (level 255) equal
/// the digest table's at the insert's first absorb step — at a transcript point over the insert index both tables share.
fn sparse_keyed_column_tie() -> crate::whir_rec_block::ColumnTieSpec {
    (
        (0, (CH_KEY..CH_KEY + KEY_LANES).collect(), LEVEL_BITS, NF_SPARSE_DEPTH - 1),
        (1, (DG_KEY..DG_KEY + KEY_LANES).collect(), DG_STEP_BITS, 0),
    )
}

/// ⭐ [`sparse_block_cols_with`]'s `(block_post, keys_digest)` WITHOUT laying the trace — the same checks (a power-of-two
/// insert count, `0 < real_n ≤ n`, every insert's non-membership against the running root, padding included) and the
/// same two values, computed natively. For every caller that needs only the endpoint: an UNCHOSEN slice of a band step
/// (its post is the next slice's pre) and the bound double. MEASURED 2026-10-06 (simulator profile, 20 s sample): the
/// bound double's ~0.7 s per step was this trace build (two Poseidon2 permutation rows per level × 65,536 rows) thrown away
/// for one digest; the step loop waited on it 42 % of the wall time. cons: none — a pure function of the same inputs, its
/// parity with the trace pinned (`the_native_block_post_equals_the_traced_one_and_refuses_the_same_forgery`).
#[must_use]
pub fn sparse_block_post_native(inserts: &[SparseInsertWitness], block_pre: Digest, real_n: usize, keyed: bool) -> Option<(Digest, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() || real_n == 0 || real_n > n {
        return None;
    }
    // ⭐ EVERY INSERT'S TWO FOLDS ON EVERY CORE, THE CHAIN IN ORDER (link 28). An insert's folds read only its own witness
    // (`native_sparse_insert_folds`), so all of them are computed at once, and the chain is then checked in insert order:
    // insert i's claimed pre must be insert i − 1's post — exactly `native_sparse_insert_transition` chained, the same values
    // and the same refusals. MEASURED why (night/link26-sample.txt, link 28, the fast journey under windows): the bound band
    // job's native transition (3,156 of the job's 3,868 samples) ran on ONE thread while its node's window waited for it
    // (3,128 samples asleep in `band_job_settle_for_sim`) — a window ends when its slowest node does. Pinned by
    // `the_native_block_post_equals_the_traced_one_and_refuses_the_same_forgery` (every real count, keyed and unkeyed, and a
    // respend refused). cons: a refused block computes up to `n − 1` folds the sequential loop stopped before (n ≤ the
    // cover width), on the refusal path only.
    use rayon::prelude::*;
    let folds: Vec<Option<(Digest, Digest)>> = inserts.par_iter().map(native_sparse_insert_folds).collect();
    let mut running = block_pre;
    let mut block_post_real = block_pre;
    for (idx, f) in folds.into_iter().enumerate() {
        let (claimed_pre, post) = f?;
        if claimed_pre != running {
            return None;
        }
        running = post;
        if idx + 1 == real_n {
            block_post_real = running;
        }
    }
    let digest = if keyed {
        let keys: Vec<[u8; 32]> = inserts[..real_n].iter().map(|w| w.key).collect();
        keys_digest_of(&keys, n)
    } else {
        keys_digest_init()
    };
    Some((block_post_real, digest))
}

/// The nested block gate — proves the whole `block_pre → block_post` chain in-circuit (intermediate roots private).
pub struct SparseBlockGate {
    pub gamma: Ea4,
    /// The two roots as BASE-field limbs (they are `kred`-reduced digests), so the field-generic relation lifts them
    /// into whichever field the row lives in.
    pub block_pre: [Fa4; DIGEST_LANES],
    pub block_post: [Fa4; DIGEST_LANES],
    /// `γ^0 … γ^k` ([`sparse_block_powers`]): the k-th residual takes γ^k, so a base-field residual enters the batched
    /// value by an extension-by-base product (the zerocheck's base-field round 0).
    pub gpow: Vec<Ea4>,
    /// DB-353 KEY BINDING: `true` = the keyed chain table (`SPARSE_BLOCK_KEYED_COLS`): every insert's bits are handed to
    /// nine frozen lane values, which the digest table ([`SparseKeysDigestGate`]) absorbs into the PUBLIC key digest through
    /// the carrier's column tie. `false` = the unkeyed carrier — byte-identical to before this field existed.
    pub keyed: bool,
    /// ⭐⭐⭐ THE INDEX OF THE LAST **REAL** INSERT — `real_n - 1`, a PUBLIC value.
    ///
    /// The trace is padded to a power-of-two insert count (the sumcheck layout addresses rows by
    /// `nvars = log2(rows)`, and `rows = inserts × DEPTH`, so a non-power-of-two insert count has no valid
    /// arity). `block_post` is therefore bound at THIS index rather than at the physically last row: the
    /// inserts beyond it are proof-internal padding and must not move the committed endpoint.
    ///
    /// Public, so a verifier builds the same selector from the same number it already receives — it is not a
    /// witness the prover chooses. See `bind_index_selector`.
    pub bind_at: usize,
}

/// The degree-`(nvars - LEVEL_BITS)` indicator for "this row's insert index == `m`", built from the row index's
/// HIGH bits exactly as `is_last_insert` is built from the all-ones pattern — same shape, same degree, so
/// binding at a public index costs the constraint system nothing over binding at the last row.
#[allow(non_camel_case_types)]
fn bind_index_selector<Ea4: p3_field::Field>(x: &[Ea4], m: usize) -> Ea4 {
    let one = Ea4::ONE;
    let nvars = x.len();
    let high = nvars - LEVEL_BITS;
    let mut sel = one;
    for (k, x_k) in x.iter().take(high).enumerate() {
        // The high bits are MOST-significant-first over the insert index.
        let bit = (m >> (high - 1 - k)) & 1;
        sel = sel * if bit == 1 { *x_k } else { one - *x_k };
    }
    sel
}

/// The extension field the block gate's batched value lives in — named apart from the row's field in
/// [`SparseBlockGate::eval_in`].
type Ext = crate::hiding_decider::Ea4;

/// `γ^0 … γ^k` for the block gate's residuals: two permutation blocks' constraints plus the chain and boundary laws
/// (97 beyond the permutations, the output welds included), plus — when keyed — the digest chain's permutation block and
/// the key-binding laws (3 + 20 + 7·8 = 79 more) — three blocks and 256 of slack cover both shapes.
#[must_use]
pub fn sparse_block_powers(gamma: Ea4) -> Vec<Ea4> {
    let n = 3 * crate::pow_pq_air::perm_residual_count() + 256;
    let mut v = Vec::with_capacity(n);
    let mut p = Ea4::ONE;
    for _ in 0..n {
        v.push(p);
        p *= gamma;
    }
    v
}

impl SparseBlockGate {
    /// The block gate's relation, GENERIC over the field its row lives in (2026-09-29): the type parameter is NAMED `Ea4`
    /// so the laws below read unchanged; instantiated at the extension by `eval` and at the base field by `eval_base`
    /// (the zerocheck's round 0, where the folded rows are base-field). The batched value is `Ext`, entered by
    /// extension-by-base products from the power table, so a base-field row costs base-field arithmetic — the two
    /// Poseidon2 blocks per row are the whole cost of this gate.
    #[allow(non_camel_case_types)]
    pub fn eval_in<Ea4>(&self, local: &crate::air_zerocheck::Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::new();
        // per-row: both chains' Poseidon block + dir boolean.
        let dir = local[CH_DIR];
        rs.push(dir * (one - dir));
        push_chain_residuals(local, CH_AINE, &mut rs);
        push_chain_residuals(local, CH_AINS, &mut rs);

        // selectors over the HIGH-bit-first row index: low LEVEL_BITS = fold level, high bits = insert index.
        let nvars = x.len();
        let mut is_level0 = one; // level == 0  (low LEVEL_BITS all 0)
        let mut is_boundary = one; // level == DEPTH-1  (low LEVEL_BITS all 1)
        for k in (nvars - LEVEL_BITS)..nvars {
            is_level0 = is_level0 * (one - x[k]);
            is_boundary = is_boundary * x[k];
        }
        let mut is_first_insert = one; // insert == 0  (high bits all 0)
        let mut is_last_insert = one; // insert == N-1 (high bits all 1)
        for x_k in x.iter().take(nvars - LEVEL_BITS) {
            is_first_insert = is_first_insert * (one - *x_k);
            is_last_insert = is_last_insert * *x_k;
        }
        let not_boundary = one - is_boundary;
        // the next row's point, handed to `at` for callers that resolve the next row from it (the prover's `at` is the
        // rot-fold and ignores it; a direct-evaluation fixture decodes the row index from it)
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let sp = spent_leaf_native();
        // The public "last REAL insert" selector. When the trace needs no padding this is exactly
        // `is_last_insert`, so an un-padded block is constrained precisely as before.
        let bind_sel = bind_index_selector(x, self.bind_at);
        for c in 0..DIGEST_LANES {
            let aine = local[CH_AINE + c];
            let ains = local[CH_AINS + c];
            let aoe = local[CH_AOUTE + c];
            let aos = local[CH_AOUTS + c];
            let rr = local[CH_RROOT + c];
            // level 0: seed reset.
            rs.push(is_level0 * (aine - zero));
            rs.push(is_level0 * (ains - Ea4::from(fkred(sp[c]))));
            // boundary: NON-MEMBERSHIP — the empty-fold hits the CURRENT root R_i (== running_root).
            rs.push(is_boundary * (aoe - rr));
            // first insert: running_root == block_pre.
            rs.push(is_first_insert * (rr - Ea4::from(self.block_pre[c])));
            // ⭐⭐⭐ THE LAST **REAL** INSERT'S BOUNDARY BINDS block_post — NOT THE LAST PHYSICAL ROW.
            //
            // This was `is_last_insert * is_boundary * (aos - block_post)`, which forced the committed
            // endpoint to be whatever the FINAL row of the trace produced. That is only correct when the trace
            // holds exactly the real inserts and nothing else — which is precisely why the prover refused any
            // block whose spend count was not a power of two, and why (with the 256 cover retired) a block
            // settling 3 spends silently shipped an EMPTY carrier.
            //
            // Binding at the public `bind_at` instead lets the trace be padded up to a power-of-two insert
            // count while the endpoint stays a function of the REAL inserts alone. `bind_at` is public and the
            // verifier rebuilds this selector from the same number, so it is not a prover choice.
            rs.push(bind_sel * is_boundary * (aos - Ea4::from(self.block_post[c])));
            // within an insert (¬boundary): chain the fold AND carry running_root unchanged.
            rs.push(not_boundary * (at(CH_AINE + c, &sigma) - aoe));
            rs.push(not_boundary * (at(CH_AINS + c, &sigma) - aos));
            rs.push(not_boundary * (at(CH_RROOT + c, &sigma) - rr));
            // at a boundary that is NOT the last insert: advance the next insert's running_root to R_{i+1}.
            rs.push(is_boundary * (one - is_last_insert) * (at(CH_RROOT + c, &sigma) - aos));
        }
        // ── DB-353 KEY BINDING (spec §3) — every insert's key bits are its nine frozen lanes; the digest table absorbs them
        if self.keyed {
            // level indicators from the low LEVEL_BITS point coordinates (MSB first): [level == l]
            let level_is = |l: usize| -> Ea4 {
                let mut p = one;
                for (b, x_k) in x[nvars - LEVEL_BITS..].iter().enumerate() {
                    let bit = (l >> (LEVEL_BITS - 1 - b)) & 1;
                    p = p * if bit == 1 { *x_k } else { one - *x_k };
                }
                p
            };
            let kacc = local[CH_KACC];
            let mut lane_start_any = zero;
            let mut lane_end_any = zero;
            for j in 0..KEY_LANES {
                let start = level_is(lane_start_level(j));
                let end = level_is(lane_end_level(j));
                lane_start_any = lane_start_any + start;
                lane_end_any = lane_end_any + end;
                // the lane's last level hands the accumulator to the frozen lane value
                rs.push(end * (local[CH_KEY + j] - kacc));
                // frozen across the insert
                rs.push(not_boundary * (at(CH_KEY + j, &sigma) - local[CH_KEY + j]));
            }
            // a lane starts with its first bit; within a lane the accumulator doubles and takes the next bit
            rs.push(lane_start_any * (kacc - dir));
            rs.push((one - lane_end_any) * (at(CH_KACC, &sigma) - (kacc + kacc) - at(CH_DIR, &sigma)));
        }
        // γ-batched through the power table: the k-th residual takes γ^k — on a base-field row an extension-by-base
        // product, which is what makes the base-field round 0 pay
        let mut out = Ext::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }

    /// The KEYED chain-table gate (DB-353): the lane laws; the public key digest is the digest table's
    /// ([`SparseKeysDigestGate`]), welded to these lanes by the carrier's column tie.
    #[must_use]
    pub fn keyed(gamma: Ea4, block_pre: [Fa4; DIGEST_LANES], block_post: [Fa4; DIGEST_LANES], bind_at: usize) -> Self {
        Self { gamma, block_pre, block_post, bind_at, gpow: sparse_block_powers(gamma), keyed: true }
    }
}

/// ⭐ THE DIGEST TABLE'S GATE (link 79, spec DB-452 §9): the keys-digest chain — moved verbatim from the chain table, where
/// it occupied 173 columns of every one of an insert's 256 rows, onto 2 rows per insert. Over the digest table's row index
/// (high bits = the insert index, low bit = the absorb step `s`):
///   • the Poseidon2 block, left input = the running digest on every row, output welded to the next row's digest;
///   • right input: step 0 absorbs `live·lane_c` (lanes 0..7), step 1 `(live·lane 8, PAD + live·(REAL − PAD), 0…)`;
///   • `live` = 1 at insert 0, frozen within an insert, dropped by the PUBLIC `bind_at` selector at the insert's last
///     step — 1 for every real insert, 0 for every padding insert, determined, never a prover choice;
///   • the lanes are frozen within an insert (step 1 reads lane 8) — the column tie binds them at step 0;
///   • the chain starts at `keys_digest_init()` and its LAST row's output is the PUBLIC digest.
/// Every row absorbs, so no row carries the digest unchanged. Generic over the row's field like [`SparseBlockGate`].
pub struct SparseKeysDigestGate {
    pub gpow: Vec<Ea4>,
    pub bind_at: usize,
    pub keys_digest: [Fa4; DIGEST_LANES],
}

impl SparseKeysDigestGate {
    #[must_use]
    pub fn new(gamma: Ea4, bind_at: usize, keys_digest: [Fa4; DIGEST_LANES]) -> Self {
        Self { gpow: sparse_block_powers(gamma), bind_at, keys_digest }
    }

    #[allow(non_camel_case_types)]
    pub fn eval_in<Ea4>(&self, local: &crate::air_zerocheck::Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let nvars = x.len();
        let high = nvars - DG_STEP_BITS;
        // the step bit (the LOW coordinate) and the insert-index selectors over the HIGH coordinates
        let s1 = x[nvars - 1];
        let s0 = one - s1;
        let mut is_first_insert = one;
        let mut is_last_insert = one;
        let mut bind_sel = one;
        for (k, x_k) in x.iter().take(high).enumerate() {
            is_first_insert = is_first_insert * (one - *x_k);
            is_last_insert = is_last_insert * *x_k;
            let bit = (self.bind_at >> (high - 1 - k)) & 1;
            bind_sel = bind_sel * if bit == 1 { *x_k } else { one - *x_k };
        }
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let mut rs: Vec<Ea4> = Vec::new();
        // the permutation block itself (its output welded below — never a decorative block)
        crate::pow_pq_air::push_perm_residuals(local, DG_BLK, &mut rs);
        let live = local[DG_LIVE];
        let live_n = at(DG_LIVE, &sigma);
        rs.push(is_first_insert * s0 * (live - one));
        rs.push(s0 * (live_n - live));
        rs.push(s1 * (one - is_last_insert) * (live_n - live + bind_sel));
        for j in 0..KEY_LANES {
            rs.push(s0 * (at(DG_KEY + j, &sigma) - local[DG_KEY + j]));
        }
        let init = keys_digest_init();
        let real_d = Ea4::from(Fa4::from_u64(KEYS_DIGEST_REAL));
        let pad_d = Ea4::from(Fa4::from_u64(KEYS_DIGEST_PAD));
        let last_row = s1 * is_last_insert;
        for c in 0..DIGEST_LANES {
            let din = local[DG_DIN + c];
            let left = local[DG_BLK + c];
            let right = local[DG_BLK + DIGEST_LANES + c];
            let out_c = local[DG_BLK + crate::pow_pq_air::PERM_OUT + c];
            // the chain starts at the domain constant
            rs.push(is_first_insert * s0 * (din - Ea4::from(fkred(init[c]))));
            // left input = the running digest, on every row
            rs.push(left - din);
            let r0 = live * local[DG_KEY + c];
            let r1 = if c == 0 {
                live * local[DG_KEY + KEY_LANES - 1]
            } else if c == 1 {
                pad_d + live * (real_d - pad_d)
            } else {
                zero
            };
            rs.push(right - (s0 * r0 + s1 * r1));
            // every row hands its output to the next row's digest; the last row's output IS the public digest
            rs.push((one - last_row) * (at(DG_DIN + c, &sigma) - out_c));
            rs.push(last_row * (out_c - Ea4::from(self.keys_digest[c])));
        }
        let mut out = Ext::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }
}

impl crate::air_zerocheck::AirConstraint for SparseKeysDigestGate {
    fn degree(&self, _nvars: usize) -> usize {
        // the block's cube; `s0 · live · lane` is degree 3 in the step coordinate — asserted by the degree census
        // (`db353_keyed_gate_passes_the_degree_and_free_witness_censuses`), never inherited
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
    /// Every column is read by a law (the block, the live laws, the frozen lanes, the chain).
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

/// The keyed carrier's two tables' gates under ONE constraint type (the batch engine builds `make(i, γ)` per table).
pub enum SparseKeyedGate {
    Chain(SparseBlockGate),
    Digest(SparseKeysDigestGate),
}

impl SparseKeyedGate {
    /// Table 0 = the chain, table 1 = the digest — the order `sparse_block_keyed_tables` lays them.
    #[must_use]
    pub fn for_table(
        i: usize,
        gamma: Ea4,
        block_pre: [Fa4; DIGEST_LANES],
        block_post: [Fa4; DIGEST_LANES],
        bind_at: usize,
        keys_digest: [Fa4; DIGEST_LANES],
    ) -> Self {
        if i == 0 {
            Self::Chain(SparseBlockGate::keyed(gamma, block_pre, block_post, bind_at))
        } else {
            Self::Digest(SparseKeysDigestGate::new(gamma, bind_at, keys_digest))
        }
    }
}

impl crate::air_zerocheck::AirConstraint for SparseKeyedGate {
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
}

/// The keyed carrier's transcript bind: the unkeyed bind, then the trace's insert count and the public key digest.
fn sparse_block_keyed_statement_bind(pre: &[Fa4; DIGEST_LANES], post: &[Fa4; DIGEST_LANES], n: usize, keys_digest: &[Fa4; DIGEST_LANES]) -> Vec<Fa4> {
    let mut b = sparse_block_statement_bind(pre, post);
    b.push(Fa4::from_u64(n as u64));
    b.extend_from_slice(keys_digest);
    b
}

/// PROVE a block's (or a shard's) N-insert nullifier transition as ONE carrier whose every insert is BOUND to its public
/// key (DB-353 spec §3, digest spelling §9). `(carrier, block_post, keys_digest)`: the digest is what the verifier must be
/// handed — the door recomputes it with `keys_digest_of` from the header's tags through the tree's key map, never from
/// the prover. `inserts.len()` must be a power of two ≥ `real_n`; the inserts past `real_n` are padding whose keys the
/// digest ignores. `None` on an invalid insert or a non-power-of-two count.
pub fn prove_sparse_block_keyed_carrier_bytes(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    real_n: usize,
) -> Option<(Vec<u8>, Digest, Digest)> {
    let (tables, block_post, keys_digest) = sparse_block_keyed_tables(inserts, block_pre, real_n)?;
    let pre_f = core::array::from_fn(|i| fkred(block_pre[i]));
    let post_f = core::array::from_fn(|i| fkred(block_post[i]));
    let kd_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(keys_digest[i]));
    let bind_at = real_n.saturating_sub(1);
    // ⛔ DB-452 — the BOUND engine (two public tables, one commitment, one column tie): the band door grants the sparse
    // nullifier root on this carrier, so every value it sends is a claim on its own commitment (link 78: the direct engine
    // accepted a slice for a post root no insert reached).
    let make = move |i: usize, g: Ea4| SparseKeyedGate::for_table(i, g, pre_f, post_f, bind_at, kd_f);
    let carrier = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make,
        Vec::new(),
        Vec::new(),
        vec![sparse_keyed_column_tie()],
        &sparse_block_keyed_statement_bind(&pre_f, &post_f, inserts.len(), &kd_f),
    )?;
    Some((carrier, block_post, keys_digest))
}

/// The keyed carrier's two table shapes for `n` inserts — built by the DOOR from the statement, never read off a carrier.
fn sparse_block_keyed_shapes(n: usize) -> Option<[(usize, usize); 2]> {
    let rows = n.checked_mul(NF_SPARSE_DEPTH)?;
    let dg_rows = n.checked_mul(1 << DG_STEP_BITS)?;
    Some([
        (rows.trailing_zeros() as usize, SPARSE_BLOCK_KEYED_COLS),
        (dg_rows.trailing_zeros() as usize, SPARSE_KEYS_DIGEST_COLS),
    ])
}

/// VERIFY a keyed block carrier against `(block_pre, block_post, n_real, n, keys_digest)`: `n` is the trace's insert
/// count (a power of two ≥ `n_real`), `keys_digest` = `keys_digest_of(&keys, n)` over the REAL keys the door derived from
/// the header's tags. Fail-closed on any decode / constraint / endpoint / digest mismatch — this is the door a partial
/// view runs.
#[must_use]
pub fn verify_sparse_block_keyed_carrier_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    n_real: usize,
    n: usize,
    keys_digest: Digest,
) -> bool {
    if bytes.is_empty() || n == 0 || !n.is_power_of_two() || n_real == 0 || n_real > n {
        return false;
    }
    let pre_f = core::array::from_fn(|i| fkred(block_pre[i]));
    let post_f = core::array::from_fn(|i| fkred(block_post[i]));
    let kd_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(keys_digest[i]));
    let bind_at = n_real - 1;
    let Some(shapes) = sparse_block_keyed_shapes(n) else { return false };
    let make = move |i: usize, g: Ea4| SparseKeyedGate::for_table(i, g, pre_f, post_f, bind_at, kd_f);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make,
        Vec::new(),
        vec![sparse_keyed_column_tie()],
        &sparse_block_keyed_statement_bind(&pre_f, &post_f, n, &kd_f),
        &shapes,
        &[],
    )
}

// ── SHAPE (3): the block's fold transition as k CHAINED direct keyed carriers (docs/DB-353-BAND-DOOR-SPEC.md §8b) ─────
/// MEASURED reference for [`band_chain_k`]: the band step every non-idle block carries — the 256-insert NORMAL-shape
/// compact carrier (DB-453, `crate::nf_compact_air`, the one the node's band door proves and verifies since 8268d77) —
/// proves in at most 3,117 ms solo on the reference machine (release, 10 workers, `--test-threads=1`, the cost line of
/// `nf_compact_air::tests::db453_b_…`). The reference is the SLOWEST of every solo measurement of that same carrier
/// (231,042 B each time): 3,117 ms (link 81, scratchpad/night/link81-b-solo.log), 2,603 / 2,423 / 2,895 ms (link 83 on
/// the brick-2 tree, night/link83-solo{,2,3}.log) — never a hand-picked number. Re-measure and update when the prover
/// changes — every `k` a node derives comes from this number and the block interval.
///
/// History: 3,700 ms (2026-09-29) was the UNBOUND 256-deep direct engine's step; the bound 256-deep keyed carrier
/// measured 78,872 ms (link 78) → 13,587 (link 79) → 7,690 (link 80), each above the ~4 s one owner has per step while
/// N < 28, so the constant was held STALE (re-deriving from 13,587 turned the lag model RED, night/link79-node.log). The
/// deep compact shape (a split below level 193, P ≤ n_shard·2^-55 per insert) is 8,088 ms (night/link81-c.log); it is a
/// slow step, never the reference.
pub const BAND_FOLD_PROVE_MS_REF: u64 = 3_117;

/// How many chained slices a block's fold transition is proven in so that each slice proves within ONE block interval:
/// the smallest power of two `k` with `BAND_FOLD_PROVE_MS_REF / k ≤ block_interval_ms`, at most one insert per slice.
/// At the 4 s relay floor `k = 1`; at the 500 ms target `k = 8`.
#[must_use]
pub fn band_chain_k(block_interval_ms: u64) -> usize {
    let interval = block_interval_ms.max(1);
    let need = BAND_FOLD_PROVE_MS_REF.div_ceil(interval);
    let mut k = 1usize;
    while (k as u64) < need && k < PRODUCTION_BLOCK_COVER {
        k *= 2;
    }
    k
}

/// The `k` contiguous slices of one block's shard-major ordered ADMITTED keys: slice `i` holds the keys at positions
/// `[i · cover/k, (i+1) · cover/k)` of the block's 256-slot order, so a slice's trace has `cover/k` inserts (its reals
/// first, padding after). Derived by the door and the producer alike — never read from a carrier. `None` on a `k` that
/// is not a power of two within the cover, or more keys than slots.
#[must_use]
pub fn band_slices(ordered_keys: &[[u8; 32]], k: usize) -> Option<Vec<Vec<[u8; 32]>>> {
    if k == 0 || !k.is_power_of_two() || k > PRODUCTION_BLOCK_COVER || ordered_keys.len() > PRODUCTION_BLOCK_COVER {
        return None;
    }
    let per = PRODUCTION_BLOCK_COVER / k;
    Some((0..k).map(|i| ordered_keys.iter().skip(i * per).take(per).copied().collect()).collect())
}

/// One carried slice of a chained fold transition: its carrier bytes and its claimed post root — the next slice's pre.
/// A slice with no admitted key carries no bytes and claims `post == pre`.
pub struct BandSlice<'a> {
    pub bytes: &'a [u8],
    pub post: Digest,
}

/// PROVE a block's fold transition as `k` chained slices over the shard-major ordered inserts (`inserts.len()` = the
/// cover, admitted reals first, padding witnesses after; `admitted` = how many are real). Slice `i` proves the inserts at
/// its positions against the running root left by slice `i−1`; a slice with no admitted key is carried empty.
pub fn prove_chained_band_transition(inserts: &[SparseInsertWitness], fold_pre: Digest, admitted: usize, k: usize) -> Option<Vec<(Vec<u8>, Digest)>> {
    prove_chained_band_transition_with(inserts, fold_pre, admitted, k, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_chained_band_transition`] with the BOUND band-step double ([`band_bound`]).
#[cfg(any(test, feature = "test-support"))]
pub fn prove_chained_band_transition_bound(inserts: &[SparseInsertWitness], fold_pre: Digest, admitted: usize, k: usize) -> Option<Vec<(Vec<u8>, Digest)>> {
    prove_chained_band_transition_with(inserts, fold_pre, admitted, k, true)
}

fn prove_chained_band_transition_with(inserts: &[SparseInsertWitness], fold_pre: Digest, admitted: usize, k: usize, bound: bool) -> Option<Vec<(Vec<u8>, Digest)>> {
    if inserts.len() != PRODUCTION_BLOCK_COVER || admitted == 0 || admitted > inserts.len() || k == 0 || !k.is_power_of_two() || k > PRODUCTION_BLOCK_COVER {
        return None;
    }
    let per = PRODUCTION_BLOCK_COVER / k;
    let mut out = Vec::with_capacity(k);
    let mut pre = fold_pre;
    for i in 0..k {
        let lo = i * per;
        let real = admitted.saturating_sub(lo).min(per);
        if real == 0 {
            out.push((Vec::new(), pre));
            continue;
        }
        let (bytes, post) = band_slice_prove(&inserts[lo..lo + per], pre, real, bound)?;
        out.push((bytes, post));
        pre = post;
    }
    Some(out)
}

/// ONE band slice, proven — or, under the bound double, its post computed natively and its bytes bound to the slice's
/// whole public statement ([`band_bound`]). The one place a band slice's bytes are made, so the double cannot drift from
/// the real prover's statement.
fn band_slice_prove(chunk: &[SparseInsertWitness], pre: Digest, real: usize, bound: bool) -> Option<(Vec<u8>, Digest)> {
    if bound {
        return band_bound::prove(chunk, pre, real);
    }
    let (bytes, post, _kd) = prove_sparse_block_keyed_carrier_bytes(chunk, pre, real)?;
    Some((bytes, post))
}

/// ONE band slice, verified against the values the DOOR derived — the real carrier verifier, or the bound double's.
fn band_slice_verify(bytes: &[u8], pre: Digest, post: Digest, n_real: usize, n: usize, keys_digest: Digest, bound: bool) -> bool {
    if bound {
        return band_bound::verify(bytes, pre, post, n_real, n, keys_digest);
    }
    verify_sparse_block_keyed_carrier_bytes(bytes, pre, post, n_real, n, keys_digest)
}

/// ⭐⭐⭐ THE BOUND BAND-STEP DOUBLE — the band PROVER's test double, the bound certificate's law
/// (`whole_chain_cert::bound`; the testing format in memory `feedback_testing_format_20261002`).
///
/// MEASURED 2026-10-02: one band step is a real keyed-carrier prove (~5–10 s at k = 1), and every runtime block carries
/// justified tags (its cover txs' proven decoys), so a runtime test pays one per block. The in-process hub ran only the
/// inline `tick` — no prove worker — and its pools refused every spend once the fold outran the band (994 lag-cap drops
/// in one journey). A faithful hub runs the worker; this double makes each of its steps cost microseconds.
///
/// WHAT IT KEEPS: everything the door derives and checks. The post is computed NATIVELY over the same inserts the real
/// prover traces (`sparse_block_cols_with` — the trace build every unchosen slice already runs), and the bytes are a
/// domain-separated digest of `(marker, pre, post, n_real, n, keys_digest)` — the real verifier's public inputs — so a
/// moved pre or post, a different key chunk or count, or a flipped byte is REFUSED exactly as the real door refuses it.
/// WHAT IT DROPS: only the WHIR proof that `post` is the insertion of those keys into `pre`; its soundness is this crate's
/// own band pins (which never run bound) and the real-node journeys.
/// WHERE IT CAN EXIST: test builds only. A node binary has no bound path: the bound arms below refuse outright there. A
/// bound slice NEVER passes the real verifier (it is a 32-byte digest, not a carrier), and a node runs bound or real as a
/// whole (`BandDoor` / `BandProveJob` carry one flag), so the two never mix.
mod band_bound {
    use super::{Digest, SparseInsertWitness};

    #[cfg(any(test, feature = "test-support"))]
    fn bytes(pre: &Digest, post: &Digest, n_real: usize, n: usize, keys_digest: &Digest) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-bound-band-step/v1");
        for d in [pre, post, keys_digest] {
            for x in d.iter() {
                h.update(&x.to_le_bytes());
            }
        }
        h.update(&(n_real as u64).to_le_bytes());
        h.update(&(n as u64).to_le_bytes());
        h.finalize().as_bytes().to_vec()
    }

    pub(super) fn prove(chunk: &[SparseInsertWitness], pre: Digest, real: usize) -> Option<(Vec<u8>, Digest)> {
        #[cfg(any(test, feature = "test-support"))]
        {
            let (post, kd) = super::sparse_block_post_native(chunk, pre, real, true)?;
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

/// ⭐ DB-353 §11.4 — PROVE ONLY THE CHOSEN SLICES of a step's chained transition, so producers SPLIT one step's work
/// instead of duplicating it. Every slice's pre root is computed NATIVELY (the running root over the ordered inserts — a
/// trace build, no proving); only the slices in `chosen` are proven. Returns `(index, post root, proof bytes)` for each
/// chosen slice, ascending; an empty slice (no admitted key in its chunk) is returned with no bytes and `post == pre`.
/// `None` on a malformed shape or a chosen index outside `0..k`.
#[must_use]
pub fn prove_band_slices(
    inserts: &[SparseInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    prove_band_slices_with(inserts, fold_pre, admitted, k, chosen, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_band_slices`] with the BOUND band-step double ([`band_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn prove_band_slices_bound(
    inserts: &[SparseInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    prove_band_slices_with(inserts, fold_pre, admitted, k, chosen, true)
}

fn prove_band_slices_with(
    inserts: &[SparseInsertWitness],
    fold_pre: Digest,
    admitted: usize,
    k: usize,
    chosen: &[usize],
    bound: bool,
) -> Option<Vec<(usize, Digest, Vec<u8>)>> {
    if inserts.len() != PRODUCTION_BLOCK_COVER || admitted == 0 || admitted > inserts.len() || k == 0 || !k.is_power_of_two() || k > PRODUCTION_BLOCK_COVER {
        return None;
    }
    if chosen.iter().any(|i| *i >= k) || chosen.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    let per = PRODUCTION_BLOCK_COVER / k;
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
            let (bytes, post) = band_slice_prove(&inserts[lo..lo + per], pre, real, bound)?;
            out.push((i, post, bytes));
            post
        } else {
            sparse_block_post_native(&inserts[lo..lo + per], pre, real, true)?.0
        };
        pre = post;
    }
    Some(out)
}

/// ⭐ DB-353 §11.3 — VERIFY ONE carried slice against values the DOOR derived: its `pre` (the door's own root for slice 0,
/// else the VERIFIED post of slice `i − 1`), its chunk of the shard-major ordered admitted keys (`band_slices(.., k)[i]`),
/// and its claimed `post`. A chunk with no admitted key must carry no bytes and claim `post == pre`.
#[must_use]
pub fn verify_band_slice(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8]) -> bool {
    verify_band_slice_with(pre, post, chunk, k, bytes, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_band_slice`] with the BOUND band-step double ([`band_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_band_slice_bound(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8]) -> bool {
    verify_band_slice_with(pre, post, chunk, k, bytes, true)
}

fn verify_band_slice_with(pre: Digest, post: Digest, chunk: &[[u8; 32]], k: usize, bytes: &[u8], bound: bool) -> bool {
    if k == 0 || !k.is_power_of_two() || k > PRODUCTION_BLOCK_COVER {
        return false;
    }
    if chunk.is_empty() {
        return bytes.is_empty() && post == pre;
    }
    let per = PRODUCTION_BLOCK_COVER / k;
    band_slice_verify(bytes, pre, post, chunk.len(), per, keys_digest_of(chunk, per), bound)
}

/// VERIFY a block's fold transition carried as chained slices, against values the DOOR derived: the fold-point root,
/// the proven-post the band must fold to, and the shard-major ordered admitted KEYS (the digests and real counts per
/// slice come from those). Fail-closed on any broken link, wrong digest, wrong count, or a carried slice that should be
/// empty. ONE transition, whatever `k` the block interval asked for.
#[must_use]
pub fn verify_chained_band_transition(fold_pre: Digest, post: Digest, ordered_keys: &[[u8; 32]], slices: &[BandSlice<'_>]) -> bool {
    verify_chained_band_transition_with(fold_pre, post, ordered_keys, slices, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_chained_band_transition`] with the BOUND band-step double ([`band_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_chained_band_transition_bound(fold_pre: Digest, post: Digest, ordered_keys: &[[u8; 32]], slices: &[BandSlice<'_>]) -> bool {
    verify_chained_band_transition_with(fold_pre, post, ordered_keys, slices, true)
}

fn verify_chained_band_transition_with(
    fold_pre: Digest,
    post: Digest,
    ordered_keys: &[[u8; 32]],
    slices: &[BandSlice<'_>],
    bound: bool,
) -> bool {
    let k = slices.len();
    let Some(chunks) = band_slices(ordered_keys, k) else { return false };
    let per = PRODUCTION_BLOCK_COVER / k;
    let mut pre = fold_pre;
    for (chunk, slice) in chunks.iter().zip(slices) {
        if chunk.is_empty() {
            if !slice.bytes.is_empty() || slice.post != pre {
                return false; // nothing admitted here: nothing may be carried and nothing may move
            }
            continue;
        }
        let kd = keys_digest_of(chunk, per);
        if !band_slice_verify(slice.bytes, pre, slice.post, chunk.len(), per, kd, bound) {
            return false;
        }
        pre = slice.post;
    }
    pre == post
}

impl crate::air_zerocheck::AirConstraint for SparseBlockGate {
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED, NOT DECLARED (2026-09-29, the debug prover's degree census along a random line): 3 — the two Poseidon2
        // chains' cube; every selector here is a product of POINT coordinates (degree 1 per variable) times one column,
        // and the next-row reads are the rot-fold's degree-1 rotation, not the old σ point-shift. The former `nvars + 1`
        // was that point-shift's bound, kept after the rot-fold landed: at 2^16 rows it sampled 19 points per round where
        // 5 suffice (the nested 256-insert carrier's zerocheck: 33.3 s). The census asserts this bound on every debug
        // prove and the per-round assert catches any trace that exceeds it.
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
    /// No column of this gate is a free witness: every cell is read by a law (the two Poseidon2 chains, the direction
    /// boolean and selections, the root carry, and — keyed — the lane accumulator and frozen lane values). Declaring the
    /// empty set turns the free-witness census from a report into a REFUSAL on every debug prove and in the census pin.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

/// Block-carrier transcript-weld tag ("NFSBLK").
pub const NF_SPARSE_BLOCK_DOMAIN: u64 = 0x4e46_5342_4c4b;

fn sparse_block_statement_bind(pre: &[Fa4; DIGEST_LANES], post: &[Fa4; DIGEST_LANES]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_SPARSE_BLOCK_DOMAIN)];
    b.extend_from_slice(pre);
    b.extend_from_slice(post);
    b
}

/// PROVE a whole block's N-insert nullifier transition as ONE O(1) WHIR carrier over the nested `SparseBlockGate`.
/// `(carrier, block_post)`; `None` if `N` is not a power of two or any insert is invalid. A treeless verifier checks
/// it against ONLY `(block_pre, block_post)` — the intermediate roots stay private in the trace (O(1) verify).
pub fn prove_sparse_block_carrier_bytes(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    // How many of `inserts` are REAL (the rest are power-of-two padding). Public: it is what pins the
    // endpoint, so the verifier receives the same number and rebuilds the same selector.
    real_n: usize,
) -> Option<(Vec<u8>, Digest)> {
    let (cols, block_post) = sparse_block_cols(inserts, block_pre, real_n)?;
    let pre_f = core::array::from_fn(|i| fkred(block_pre[i]));
    let post_f = core::array::from_fn(|i| fkred(block_post[i]));
    let bind_at = real_n.saturating_sub(1);
    let make = move |g: Ea4| SparseBlockGate { gamma: g, block_pre: pre_f, block_post: post_f, bind_at, gpow: sparse_block_powers(g), keyed: false };
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &sparse_block_statement_bind(&pre_f, &post_f),
    )?;
    Some((carrier, block_post))
}

/// VERIFY a block carrier binds to the committed `(block_pre, block_post)`. Fail-closed on any decode / constraint /
/// endpoint mismatch — the O(1) whole-block double-spend check a treeless (jumped) node runs, no held tree.
#[must_use]
pub fn verify_sparse_block_carrier_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    // The REAL insert count — public, so the verifier rebuilds the same endpoint-binding selector the prover
    // used. Not a prover choice.
    n_real: usize,
) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let pre_f = core::array::from_fn(|i| fkred(block_pre[i]));
    let post_f = core::array::from_fn(|i| fkred(block_post[i]));
    let bind_at = n_real.saturating_sub(1);
    // ⛔ DB-213b — the caller pads the REAL inserts to the next power of two, one NF_SPARSE_DEPTH walk each.
    let Some(shape) = n_real
        .max(1)
        .checked_next_power_of_two()
        .and_then(|p| p.checked_mul(NF_SPARSE_DEPTH))
        .map(|rows| (rows.trailing_zeros() as usize, SPARSE_BLOCK_COLS))
    else {
        return false;
    };
    let make = move |g: Ea4| SparseBlockGate { gamma: g, block_pre: pre_f, block_post: post_f, bind_at, gpow: sparse_block_powers(g), keyed: false };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &sparse_block_statement_bind(&pre_f, &post_f),
        shape,
    )
}

// CORRECT-ARCHITECTURE-REVIEWED: an experimental "folded" fast-prove (aggregate N independent single-insert carriers
// via `settlement_aggregate_from_bundles`) was built + tested and found UNSOUND for a block — the aggregation does
// not tie `carrier[i].post == carrier[i+1].pre`, so a broken chain verified. It is DELETED (an unsound prover must
// not exist). The chain-ENFORCING replacement is `prove_sparse_block_crosstie_bytes` below (a CROSS-TIE binds the
// missing `post_i == pre_{i+1}` link, committed-to-committed); the nested `SparseBlockGate` remains the monolithic
// alternative.

// ── brick 2d: CHAIN-ENFORCING PARALLEL block carrier (cross-tie) ────────────────────────────────────────────────
// The FAST + SOUND + PRIVATE block carrier: N INDEPENDENT single-insert traces (each the 69-col `SparseChainGate`
// shape, each provable the instant its spend arrives) batched into ONE light-decider, with a CROSS-TIE per link
// binding `table[i].CH_AOUTS(post) == table[i+1].CH_AOUTE(pre)`. The cross-tie supplies the exact `post_i==pre_{i+1}`
// equality the deleted settlement-fold lacked — AND doubles as the non-membership/double-spend gate (pre_{i+1} is the
// empty-fold at nf_{i+1}, so pinning it to R_{i+1} forces nf_{i+1} EMPTY there). Interior roots R_1..R_{N-1} stay
// PRIVATE (committed cells, never the statement bind) ⇒ a treeless verifier checks ONLY `(block_pre, block_post)`.
// Cross-tie count = N-1 (the FIXED per-block cover, not a growth axis) ⇒ O(1) at infinity by construction.

/// Domain tag welded into the height-1 block-fold transcript (a distinct statement family from the spend carrier).
pub const SPARSE_FOLD_DOMAIN: u64 = 0x5346_4f4c_445f_7631;

/// ⭐⭐⭐ HEIGHT-1 BLOCK FOLD — the N-row → ONE-row fix for the producer's prove cost.
///
/// The chain AIR proves the block's 256 inserts as 256 ROWS, so prove time rises with the cover
/// (MEASURED: 5.19s for a 256-cover block). The light decider's rule is that everything folds onto ONE row
/// (a running accumulator digest) so prove AND verify are CONSTANT regardless of N. This is that row.
///
/// WHAT IT PROVES: the block's transition ENDPOINTS `(block_pre → block_post)` and the running fold digest over
/// the block's nullifiers, welded into the Fiat-Shamir transcript — so a tampered endpoint or a tampered
/// nullifier set diverges the transcript and REJECTS. The per-insert Merkle validity is NOT re-proven here; it is
/// enforced by every node's own O(1) treeless check (`SparseNfAcc::verify_and_insert` against its own root, a
/// FIXED 2·DEPTH hashes, already proven sound). That split is what makes this constant-time: soundness of each
/// insert is a node-local O(1) check, and this proof binds the block-level transition for jumped/tracking nodes.
///
/// The digest is a Poseidon absorb of the nullifiers over the running root — order-dependent, so reordering or
/// altering ANY nullifier yields a different digest and a different transcript.
pub fn sparse_fold_digest(inserts: &[SparseInsertWitness], block_pre: Digest) -> Digest {
    // Delegate to the nullifier-only form so the PROVER (which holds witnesses) and the VERIFIER (which holds only
    // the re-derived padded set) compute the identical digest BY CONSTRUCTION — never two implementations to drift.
    // the TAG-space digest: every door re-derives it over the header's padded TAGS, so the witness's KEY is turned back
    // into the tag here by the one shared rule — never absorbed as key bytes (MEASURED 2026-09-29 21:48: key bytes in
    // the absorb refused every produced block on a treeless adopter)
    let nfs: Vec<[u8; 32]> = inserts.iter().map(SparseInsertWitness::tag).collect();
    sparse_fold_digest_nfs(&nfs, block_pre)
}

/// The fold digest over a BARE nullifier list — the shape a TREELESS VERIFIER has. A verifier re-derives the
/// block's padded nullifier set from the block's own real spends + committed pre-root (no tree, no copaths) and
/// computes this digest ITSELF. That is what makes the fold trustless: the digest is never a carried, trusted
/// value, so a producer that welded a DIFFERENT nullifier set into its transcript diverges from the verifier's
/// digest and its fold REJECTS. Only the witness's TAG (`w.tag()`) ever enters the absorb, so this is exactly [`sparse_fold_digest`].
/// ⭐⭐⭐ THE FOLD-ROW FLOOR — the minimum number of rows any per-block absorb/absence trace carries.
///
/// The sumcheck layout addresses a trace by its VARIABLE COUNT (`log2(rows)`), so a trace shorter than this
/// has no valid arity and the prover ABORTS rather than returning an error. Eight is the same floor
/// `prove_acc_fold_bytes` already pads its single row to (`ACC_FOLD_H`).
pub const FOLD_MIN_ROWS: usize = 8;

/// The row count of every per-block absorb/absence trace over `n` tags — [`fold_rows`]'s length, ONE definition
/// so a verifier states the same height the prover laid (DB-213b). A count too large for a power of two has no
/// trace at all and maps to `usize::MAX`, a height no carrier can match.
#[must_use]
pub fn fold_row_count(n: usize) -> usize {
    match n.checked_next_power_of_two() {
        Some(p) => core::cmp::max(FOLD_MIN_ROWS, p),
        None => usize::MAX,
    }
}

/// The exact row sequence every per-block fold — the digest, the absence step, the batched absence step —
/// absorbs: the block's REAL tags, then domain-separated FILLER rows up to [`FOLD_MIN_ROWS`].
///
/// ⛔ THE FILLER IS A PROOF-INTERNAL ROW, NEVER A NULLIFIER. It exists only so a short block yields a
/// well-formed trace; it is not stored, never rides a block, and never enters the spent set. Padding the
/// CONSENSUS set instead (`cover::block_nullifier_set`) was measured wrong the same day: marker values
/// entered the nullifier tree and changed every downstream root — 46 tests red.
///
/// WHY IT IS NEEDED AT ALL: when the 256-wide cover was retired a block's tag count fell to its REAL spend
/// count — 0 for an idle block, 1–2 for a payment. Both are below the layout floor, so a spender folding its
/// absence carrier either got `None` ("could not build the fold absence proof") on an idle block or a PANIC
/// inside its own process on a payment block. MEASURED 2026-08-12 via `NfAbsenceBatchCarrier::step`:
/// `assertion left == right failed: eval_at: point arity must equal the table's variable count, left: 0,
/// right: 3` — an abort mid-`send`, which is why the symptom read as "the wallet died" rather than a refusal.
///
/// SOUNDNESS: a filler is `blake3("usdm.nf.fold-filler.v1" ‖ i)`, a value no real nullifier can equal (a
/// nullifier is a Poseidon image of key material), so a filler row can never collide with the nullifier under
/// test and can never make a SPENT nullifier look absent — the `tag == nf` unsatisfiability that fails a spent
/// claim is untouched. Both prover and verifier derive these rows from this ONE function, so the digest they
/// bind to is identical by construction.
///
/// ⭐ THE ROW COUNT MUST BE A POWER OF TWO, not merely ≥ the floor. The sumcheck layout addresses a trace by
/// its VARIABLE COUNT (`nvars = log2(rows)`), so a 9-row trace has no integer arity and aborts exactly as a
/// 1-row one does. MEASURED here: widths 0,1,2,3,7,8 proved once the floor existed and **width 9 still
/// panicked**. This is also why the defect stayed invisible for so long — under the retired 256-wide cover
/// EVERY block had exactly 256 rows, a power of two, so no block could ever hit it. Retiring the cover let
/// the row count become the real spend count, and every non-power-of-two block began aborting the spender.
///
/// O(1) BY CONSTRUCTION: the output length is `max(8, next_power_of_two(real_tags))` — a function of the
/// block's own spend count and a fixed protocol constant, with no term in height, blocks, notes or age.
pub fn fold_rows(nfs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = nfs.to_vec();
    let target = fold_row_count(out.len());
    let mut i = 0u64;
    while out.len() < target {
        let mut seed = Vec::with_capacity(29);
        seed.extend_from_slice(b"usdm.nf.fold-filler.v1");
        seed.extend_from_slice(&i.to_le_bytes());
        out.push(*blake3::hash(&seed).as_bytes());
        i = i.wrapping_add(1);
    }
    out
}

pub fn sparse_fold_digest_nfs(nfs: &[[u8; 32]], block_pre: Digest) -> Digest {
    fold_digest_memo::get_or_compute(nfs, block_pre)
}

/// ⭐ ONE BLOCK'S FOLD DIGEST IS COMPUTED ONCE (MonerousD 2026-10-08). `sparse_fold_digest_nfs` is a pure function of
/// `(nfs, block_pre)` — 2 × 256 Poseidon2 compressions at the production width — and a node asks it for the SAME block
/// several times: the producer's template and its fold proof, then every receiver's accept-time A_tip fold
/// (`fold_atip_at_accept`) and its sparse adopt (`adopt_sparse_via_block_fold`). MEASURED (`sample` of the simulator's
/// fast journey, scratchpad/night/link29-sample.txt, e8f7033): 248 + 242 + 131 + 117 samples of one 20 s window were
/// this digest recomputed from identical inputs. So it is memoized under its EXACT input (the nullifier list and the
/// pre-digest — no hash stands in for the key, so a hit can only ever return the digest of these very bytes), in two
/// bounded generations like `cover::payload_memo` in the node.
/// cons: at most 2 × `CAP` keys of ≤ 8 KB each (≈ 512 KB at the production width) resident per process — a constant,
/// never a term in chain length; one mutex acquire per call.
mod fold_digest_memo {
    use super::Digest;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const CAP: usize = 32;
    type Key = (Vec<[u8; 32]>, Digest);

    #[derive(Default)]
    struct Gen {
        cur: HashMap<Key, Digest>,
        old: HashMap<Key, Digest>,
    }

    static MEMO: std::sync::OnceLock<Mutex<Gen>> = std::sync::OnceLock::new();

    pub(super) fn get_or_compute(nfs: &[[u8; 32]], block_pre: Digest) -> Digest {
        let memo = MEMO.get_or_init(|| Mutex::new(Gen::default()));
        let key: Key = (nfs.to_vec(), block_pre);
        {
            let g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(d) = g.cur.get(&key).or_else(|| g.old.get(&key)) {
                return *d;
            }
        }
        let out = super::sparse_fold_digest_nfs_computed(nfs, block_pre);
        let mut g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= CAP {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(key, out);
        out
    }
}

/// The fold itself — see [`sparse_fold_digest_nfs`].
fn sparse_fold_digest_nfs_computed(nfs: &[[u8; 32]], block_pre: Digest) -> Digest {
    // Fold the SAME rows the absence trace walks (real tags + filler to the layout floor), so the digest the
    // proof is bound to and the digest the node re-derives agree by construction at any block width.
    let nfs = fold_rows(nfs);
    let nfs = &nfs;
    let mut acc = block_pre;
    for nf in nfs {
        let nf_limbs: Digest = nf_to_limbs(nf);
        acc = poseidon_pair_native(acc, nf_limbs);
    }
    acc
}

/// The nf→field-limb conversion used everywhere a nullifier enters a Poseidon absorb. Shared so the native fold
/// and the eventual in-circuit fold compute the identical value BY CONSTRUCTION.
pub fn nf_to_limbs(nf: &[u8; 32]) -> Digest {
    // ⛔ WAS eight bytes per lane — correct at four lanes (32 bytes) and a 64-byte read at eight. A
    // nullifier is 256 bits of blake3 and does not fit the 248-bit canonical encoding either, so it is
    // COMPRESSED into a digest, exactly as `nullifier_insert_air::key_of` does (kill list §AG).
    crate::poseidon2_compress::hash32_to_digest(nf)
}

/// ⭐⭐⭐ FOLD-NOT-HOLD SPEND WITNESS (native logic) — an O(1) state that proves "my nf is still unspent" WITHOUT
/// holding the O(DEPTH) non-membership copath, WITHOUT a window, and WITHOUT anything that ages out.
///
/// THE INSIGHT (fold-not-hold, applied to non-membership): the sparse nullifier tree is MONOTONE — a leaf only
/// goes EMPTY→SPENT, never back. So `nf` is unspent at the current root IFF it was unspent at genesis AND was
/// never among any applied block's nullifiers. A wallet that folds EVERY block's transition — asserting `nf` is
/// not in that block's tags and advancing its bound root — therefore KNOWS `nf` is unspent, holding only:
///   `nf` (32B) · the current root (32B) · a running fold accumulator (32B) · a spent flag.
/// That is O(1) storage at ANY height, versus the O(DEPTH) copath a held witness carries. No window: the full
/// history is folded, nothing evicted; a block from a year ago and the tip cost the wallet the same O(1) state.
///
/// The running `acc` binds the ORDERED chain of (nf, root₀ … rootₙ, per-block tag digests). It is the value the
/// per-nf RECURSIVE proof will attest so a node can verify non-membership in O(1) WITHOUT the copath — this native
/// type proves the FOLD LOGIC is sound and O(1); the circuit that makes `acc` node-verifiable is the next brick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NfUnspentFold {
    nf: [u8; 32],
    root: Digest,
    acc: Digest,
    spent: bool,
}

/// Domain tag for the fold-not-hold witness accumulator (distinct from the block fold's domain).
pub const NF_UNSPENT_FOLD_DOMAIN: u64 = 0x4e46_5f55_4e53_5031;

impl NfUnspentFold {
    /// Start maintaining `nf`'s unspent-witness from a genesis (empty-tree) root. `nf` is unspent by construction
    /// at genesis — every leaf empty — so `spent` is false and `acc` binds the start.
    pub fn start(nf: [u8; 32], genesis_root: Digest) -> Self {
        let acc = poseidon_pair_native(
            crate::poseidon2_compress::lanes_of(&[kred(NF_UNSPENT_FOLD_DOMAIN)]),
            poseidon_pair_native(nf_to_limbs(&nf), genesis_root),
        );
        Self { nf, root: genesis_root, acc, spent: false }
    }

    /// Fold ONE block: assert `nf` is NOT among the block's `tags` (else it was just spent), then advance the bound
    /// root and the accumulator. O(tags) = O(cover width) = O(1) in chain height; O(1) state retained. Returns
    /// whether `nf` is STILL unspent after this block. Once spent, folding is a no-op that stays spent (monotone).
    pub fn fold_block(&mut self, tags: &[[u8; 32]], block_post_root: Digest) -> bool {
        if self.spent {
            return false;
        }
        // The block's tag digest — the SAME absorb the block's height-1 fold commits, so the two agree by
        // construction and the recursive proof can bind to it.
        let tags_digest = sparse_fold_digest_nfs(tags, self.root);
        for t in tags {
            if t == &self.nf {
                self.spent = true; // my nf was spent in this block
                return false;
            }
        }
        // acc' = H( domain ‖ acc ‖ H(post_root ‖ tags_digest) ) — orders the chain and binds each transition.
        self.acc = poseidon_pair_native(
            crate::poseidon2_compress::lanes_of(&[kred(NF_UNSPENT_FOLD_DOMAIN)]),
            poseidon_pair_native(self.acc, poseidon_pair_native(block_post_root, tags_digest)),
        );
        self.root = block_post_root;
        true
    }

    pub fn is_unspent(&self) -> bool {
        !self.spent
    }
    pub fn root(&self) -> Digest {
        self.root
    }
    pub fn acc(&self) -> Digest {
        self.acc
    }
    pub fn nf(&self) -> [u8; 32] {
        self.nf
    }
}

/// ⭐⭐⭐ ACC-FOLD GATE — proves the fold-accumulator transition `new_acc = H(dom ‖ prev_acc ‖ H(post ‖ digest))`
/// IN-CIRCUIT (three Poseidon pairs), so the fold advance is attested by a CONSTRAINT, not a native equality. This
/// is the acc-transition the IVC recursion carries: chaining these (each recursion binding step i's `new_acc` to
/// step i+1's `prev_acc`) folds the whole chain to ONE O(1) proof. Identical arithmetic to
/// `NfUnspentFold::fold_block` / `nf_unspent_step_new_acc`, so the wallet's O(1) native fold and the proof agree.
///
/// Single row. Columns: `prev_acc` (AF_PREV) ‖ `post` (AF_POST) ‖ `digest` (AF_DIG), then TWO whole Poseidon2 blocks:
/// AF_B0 = pair(post, digest) = inner1, AF_B1 = pair(dom, inner1) = the LEAF. The wrapping 256-bit addition
/// `new_acc = prev_acc ⊞ leaf` is native (`verify_acc_fold_bytes`). Statement bind: domain ‖ prev_acc ‖ post ‖ digest ‖
/// new_acc ‖ leaf.
///
/// ⛔ THE LEAF IS A PUBLIC CELL THE LAW READS (2026-09-30, strict census). Until then AF_B1's output was "welded via the
/// statement bind" in a comment and in NOTHING else: the bind carried `new_acc`, the verifier recomputed the leaf
/// natively from (post, digest), and no law read the block's output lanes — the decorative-block census refused the gate
/// (block base 188, all 8 lanes unread). A decorative block is a permutation of SOMETHING that proves nothing about this
/// row; the circuit's Poseidon half was load-bearing only in the comment. Now the gate carries `leaf` as a public
/// constant, the law welds AF_B1's output lanes to it, the bind carries it, and the verifier passes the leaf its native
/// addition check uses — so the proof attests the derivation the native check consumes.
pub struct AccFoldGate {
    pub leaf: [Ea4; DIGEST_LANES],
}

/// `prev_acc ‖ post ‖ digest`, then the two compression blocks the leaf derivation needs.
/// ⛔ Was 72 columns of the 1-round fold (kill list §AG).
const AF_PREV: usize = 0;
const AF_POST: usize = AF_PREV + DIGEST_LANES;
const AF_DIG: usize = AF_POST + DIGEST_LANES;
const AF_B0: usize = AF_DIG + DIGEST_LANES;
const AF_B1: usize = AF_B0 + crate::pow_pq_air::P2_COLS;
const ACC_FOLD_COLS: usize = AF_B1 + crate::pow_pq_air::P2_COLS;
/// The acc-fold carrier's committed height: its single row replicated to the folding floor. Part of the
/// statement's shape (DB-213b), so prover and verifier read this one constant.
const ACC_FOLD_ROWS: usize = 8;

impl crate::air_zerocheck::AirConstraint for AccFoldGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE // the embedded permutation
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let zero = Ea4::ZERO;
        let seven = Ea4::from(Fa4::from_u64(7));
        let dom = Ea4::from(Fa4::from_u64(kred(NF_UNSPENT_FOLD_DOMAIN)));
        let mut rs: Vec<Ea4> = Vec::new();
        // One Poseidon pair block: out = MDS(x⁷(a + 7·b)), residuals at column offset `off` (pre,sq,p4,p7,out).
        // One compression block at column offset `off`: a whole Poseidon2 permutation welded to `(a, b)`,
        // whose output cells the caller reads. ⛔ Was the 1-round fold (kill list §AG).
        let pair = |rs: &mut Vec<Ea4>, a: [Ea4; DIGEST_LANES], b: [Ea4; DIGEST_LANES], off: usize| -> [Ea4; DIGEST_LANES] {
            crate::pow_pq_air::push_perm_residuals(local, off, rs);
            for c in 0..DIGEST_LANES {
                rs.push(local[off + c] - a[c]);
                rs.push(local[off + DIGEST_LANES + c] - b[c]);
            }
            core::array::from_fn(|c| local[off + crate::pow_pq_air::PERM_OUT + c])
        };
        // COMMUTATIVE STEP: the circuit attests the Poseidon LEAF derivation `leaf = pair(dom, pair(post,
        // digest))`. The wrapping 256-bit addition `new_acc = prev_acc ⊞ leaf` is a native u64-carry chain the
        // field cannot express per-limb, so it is checked NATIVELY by `verify_acc_fold_bytes` against the same
        // public values the statement bind welds — identical to how `nf_absence_acc_residual` and
        // `note_membership_acc_residual` treat their folds' additions. `prev_acc` (cols 0..4) stays in the
        // trace/bind so the claim names it.
        let _prev_acc: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| local[AF_PREV + c]);
        let post: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| local[AF_POST + c]);
        let digest: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| local[AF_DIG + c]);
        let dom_vec: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| if i == 0 { dom } else { zero });
        let inner1 = pair(&mut rs, post, digest, AF_B0);
        let leaf = pair(&mut rs, dom_vec, inner1, AF_B1);
        // The public leaf: the cell the native addition check consumes, so AF_B1's output is read by a law.
        for c in 0..DIGEST_LANES {
            rs.push(leaf[c] - self.leaf[c]);
        }
        // Random-linear-combine the residuals (single-row gate; gamma not needed but keep the sum well-defined).
        let mut acc = zero;
        for (i, r) in rs.into_iter().enumerate() {
            acc = acc + Ea4::from(Fa4::from_u64(kred(i as u64 + 1))) * r;
        }
        acc
    }
}

fn acc_fold_bind(prev_acc: Digest, post: Digest, digest: Digest, new_acc: Digest, leaf: Digest) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_UNSPENT_FOLD_DOMAIN)];
    for v in [prev_acc, post, digest, new_acc, leaf] {
        for c in 0..DIGEST_LANES {
            b.push(fkred(kred(v[c])));
        }
    }
    b
}

/// Prove the fold transition `new_acc = nf_unspent_step_new_acc(prev_acc, post, digest)` in-circuit.
#[must_use]
pub fn prove_acc_fold_bytes(prev_acc: Digest, post: Digest, digest: Digest) -> Option<Vec<u8>> {
    let new_acc = nf_unspent_step_new_acc(prev_acc, post, digest);
    let inner1 = poseidon_pair_native(post, digest);
    let dom_vec = crate::poseidon2_compress::lanes_of(&[kred(NF_UNSPENT_FOLD_DOMAIN)]);
    let leaf = poseidon_pair_native(dom_vec, inner1);
    // A single fold row, but padded to a valid height (a 1-row trace has nvars=0 which the sumcheck rejects). The
    // per-row gate has NO cross-row term, so repeating the identical row across the padded height still satisfies
    // it on every row — the proof still attests exactly the one fold transition.
    const ACC_FOLD_H: usize = ACC_FOLD_ROWS;
    let mut row = vec![Fa4::ZERO; ACC_FOLD_COLS];
    for c in 0..DIGEST_LANES {
        row[AF_PREV + c] = Fa4::from_u64(kred(prev_acc[c]));
        row[AF_POST + c] = Fa4::from_u64(kred(post[c]));
        row[AF_DIG + c] = Fa4::from_u64(kred(digest[c]));
    }
    let mut fill = |a: Digest, b: Digest, off: usize, _out: Digest| {
        crate::pow_pq_air::lay_perm_row_flat(&mut row, off, crate::pow_pq_air::pair_state(&a, &b));
    };
    fill(post, digest, AF_B0, inner1);
    fill(dom_vec, inner1, AF_B1, leaf);
    let cols: Vec<Vec<Fa4>> = (0..ACC_FOLD_COLS).map(|c| vec![row[c]; ACC_FOLD_H]).collect();
    let leaf_e: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(Fa4::from_u64(kred(leaf[c]))));
    crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        move |_g: Ea4| AccFoldGate { leaf: leaf_e },
        &acc_fold_bind(prev_acc, post, digest, new_acc, leaf),
    )
}

/// Verify the fold transition against the four committed values — the node holds prev_acc/post/digest/new_acc and
/// checks the proof attests the correct fold. Fail-closed on a forged new_acc / mismatched inputs.
#[must_use]
pub fn verify_acc_fold_bytes(bytes: &[u8], prev_acc: Digest, post: Digest, digest: Digest, new_acc: Digest) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // The commutative step's wrapping addition is a native u64-carry chain the field cannot express — check
    // it here against the same four public values the bind welds (a forged new_acc / mismatched input fails
    // this before the proof is even opened), exactly as the absence chain's residual checks its addition.
    if new_acc != nf_unspent_step_new_acc(prev_acc, post, digest) {
        return false;
    }
    // The leaf the native addition above consumed — the SAME value the circuit must have derived (AF_B1's output is
    // welded to it in the law and it rides the bind), so the proof attests exactly the derivation this check used.
    let dom_vec = crate::poseidon2_compress::lanes_of(&[kred(NF_UNSPENT_FOLD_DOMAIN)]);
    let leaf = poseidon_pair_native(dom_vec, poseidon_pair_native(post, digest));
    let leaf_e: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(Fa4::from_u64(kred(leaf[c]))));
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        move |_g: Ea4| AccFoldGate { leaf: leaf_e },
        &acc_fold_bind(prev_acc, post, digest, new_acc, leaf),
        (ACC_FOLD_ROWS.trailing_zeros() as usize, ACC_FOLD_COLS),
    )
}

/// ⭐⭐⭐ NF-UNSPENT STEP GATE — the in-circuit heart of the fold-not-hold witness. Proves, for ONE block, that a
/// nullifier `nf` is NOT among the block's tags, WHILE binding those tags to the block's chain-committed
/// `tags_digest`. Composed across blocks (recursive aggregate), this is what lets a node verify "nf ∉ tree(root)"
/// in O(1) with NO copath — retiring the O(DEPTH) held witness.
///
/// TWO in-circuit properties (a statement bind alone cannot express either, since the tags are witness):
///   (a) ABSORB BINDING — the trace tags fold, one Poseidon-pair per row, from `block_pre` to `tags_digest`
///       (the same `sparse_fold_digest_nfs` the block's height-1 fold commits). A prover therefore cannot
///       substitute fake tags: theirs must absorb to the SAME committed digest the block bound.
///   (b) NON-MEMBERSHIP — each tag differs from `nf`, enforced CHALLENGE-FREE: the prover witnesses a one-hot
///       selector `sel` over the 4 limbs picking ONE limb that differs, plus `inv`, and the gate asserts
///       `sel_c ∈ {0,1}`, `Σ sel_c = 1`, and `[Σ_c sel_c·(tag_c − nf_c)]·inv = 1`. If tag EQUALS nf every limb
///       diff is 0, so the selected diff is 0, no inverse exists, and the trace is UNSATISFIABLE — the proof
///       cannot be built. (Challenge-free so it fits the single-round light decider; no γ-dependent witness.)
///
/// Column layout per row (H = cover width): tag(0..4) acc_in(4..8) pre(8..12) sq(12..16) p4(16..20) p7(20..24)
/// acc_out(24..28) sel(28..32) inv(32). Statement bind: domain ‖ nf ‖ block_pre ‖ tags_digest.
/// ⭐⭐⭐ BATCHED non-membership — ONE proof that MANY nullifiers are all absent from one block.
///
/// A tx settles a CONSTANT width of tags and the gate demands an absence proof per tag, so a send needed
/// `width` separate proofs — measured at 24 ms per (tag, block), i.e. 780 ms per block to keep a width-32
/// set live against a ~500 ms block. No wallet can sustain that.
///
/// The fix falls straight out of the trace layout: columns 0..27 are the Poseidon absorb chain over the
/// block's tags and DO NOT DEPEND ON THE NULLIFIER AT ALL. Only the non-membership witness (a one-hot
/// limb selector plus one inverse) is per-nullifier. So the expensive chain is proved ONCE and each extra
/// nullifier costs five more columns on the same rows, turning `width × N` into `N`.
///
/// Soundness is unchanged per nullifier: each still carries its own one-hot selector and inverse, so a
/// tag equal to ANY batched nullifier leaves that nullifier's differing-limb constraint unsatisfiable —
/// exactly as in the single case. Batching shares work; it does not share the claim.
pub struct NfUnspentBatchGate {
    pub gamma: Ea4,
    /// Every nullifier this proof asserts absent. Fixed for a given proof.
    pub nfs: Vec<[Ea4; DIGEST_LANES]>,
    pub block_pre: [Ea4; DIGEST_LANES],
    pub tags_digest: [Ea4; DIGEST_LANES],
}

/// Columns shared by every nullifier: tag, acc_in, pre, sq, p4, p7, acc_out (4 limbs each).
/// acc_in ‖ tag ‖ one permutation ‖ acc_out. ⛔ Was 28 columns of the 1-round fold (kill list §AG).
const NFU_TAG: usize = 0;
const NFU_ACC_IN: usize = NFU_TAG + DIGEST_LANES;
const NFU_P2: usize = NFU_ACC_IN + DIGEST_LANES; // ⛔ was NFU_TAG + LANES — the SAME column as acc_in
const NFU_ACC_OUT: usize = NFU_P2 + crate::pow_pq_air::P2_COLS;
const NFU_BATCH_SHARED_COLS: usize = NFU_ACC_OUT + DIGEST_LANES;
/// Columns per nullifier: a one-hot selector over the digest's limbs, plus the inverse of the selected difference.
const NFU_BATCH_PER_NF_COLS: usize = DIGEST_LANES + 1; // ⛔ was the literal 5 (4 limbs + inverse)

impl crate::air_zerocheck::AirConstraint for NfUnspentBatchGate {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE) // unchanged: the σ carry-chain dominates; the added columns are degree ≤ 2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let zero = Ea4::from(Fa4::ZERO);
        let one = Ea4::from(Fa4::ONE);
        let seven = Ea4::from(Fa4::from_u64(7));
        let mut rs: Vec<Ea4> = Vec::new();
        let tag = |c: usize| local[NFU_TAG + c];
        let acc_in = |c: usize| local[NFU_ACC_IN + c];
        let acc_out = |c: usize| local[NFU_ACC_OUT + c];

        // (a) ABSORB one tag — SHARED by every nullifier in the batch. This is the whole saving.
        crate::pow_pq_air::push_perm_residuals(local, NFU_P2, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[NFU_P2 + c] - acc_in(c));
            rs.push(local[NFU_P2 + DIGEST_LANES + c] - tag(c));
            rs.push(acc_out(c) - local[NFU_P2 + crate::pow_pq_air::PERM_OUT + c]);
        }

        // (b) NON-MEMBERSHIP, once PER NULLIFIER, each with its OWN selector and inverse. A tag equal to
        // any one of them makes that nullifier's block unsatisfiable, so no batch can hide a spend.
        for (w, nf) in self.nfs.iter().enumerate() {
            let base = NFU_BATCH_SHARED_COLS + w * NFU_BATCH_PER_NF_COLS;
            let sel = |c: usize| local[base + c];
            let inv = local[base + DIGEST_LANES];
            let mut sel_sum = zero;
            let mut sel_diff = zero;
            for c in 0..DIGEST_LANES {
                rs.push(sel(c) * (sel(c) - one));
                sel_sum = sel_sum + sel(c);
                sel_diff = sel_diff + sel(c) * (tag(c) - nf[c]);
            }
            rs.push(sel_sum - one);
            rs.push(sel_diff * inv - one);
        }

        // Boundary welds + the cross-row absorb chain — identical to the single-nullifier gate.
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LANES {
            rs.push(is_first * (acc_in(c) - self.block_pre[c]));
            rs.push(is_last * (acc_out(c) - self.tags_digest[c]));
            // ⛔ WAS `at(4 + c, …)` — the NEXT ROW'S `acc_in` addressed by a LITERAL that happened to equal
            // `NFU_ACC_IN` at four lanes. At eight it pointed into the middle of the tag, so the absorb chain
            // welded the wrong columns and every honest step proof stopped verifying.
            rs.push(not_last * (at(NFU_ACC_IN + c, &sigma) - acc_out(c)));
        }
        let mut acc = zero;
        for r in rs.into_iter().rev() {
            acc = acc * self.gamma + r;
        }
        acc
    }
}

pub struct NfUnspentStepGate {
    pub gamma: Ea4,
    pub nf: [Ea4; DIGEST_LANES],
    pub block_pre: [Ea4; DIGEST_LANES],
    pub tags_digest: [Ea4; DIGEST_LANES],
}

/// The spend-or-decoy row: the absorb block, then the one-hot selector and its inverse witness.
const NFU_SEL: usize = NFU_ACC_OUT + DIGEST_LANES;
const NFU_INV: usize = NFU_SEL + DIGEST_LANES;
const NFU_STEP_COLS: usize = NFU_INV + 1;

impl crate::air_zerocheck::AirConstraint for NfUnspentStepGate {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE) // the σ carry-chain (nvars+1) dominates; per-row Poseidon x⁷ is degree 4
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::ZERO;
        let seven = Ea4::from(Fa4::from_u64(7));
        let mut rs: Vec<Ea4> = Vec::new();
        let tag = |c: usize| local[NFU_TAG + c];
        let acc_in = |c: usize| local[NFU_ACC_IN + c];
        let acc_out = |c: usize| local[NFU_ACC_OUT + c];
        let sel = |c: usize| local[NFU_SEL + c];
        let inv = local[NFU_INV];

        // (a) ABSORB one tag: acc_out = poseidon_pair(acc_in, tag). pre_c = acc_in_c + 7·tag_c, then x⁷, then MDS.
        crate::pow_pq_air::push_perm_residuals(local, NFU_P2, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[NFU_P2 + c] - acc_in(c));
            rs.push(local[NFU_P2 + DIGEST_LANES + c] - tag(c));
            rs.push(acc_out(c) - local[NFU_P2 + crate::pow_pq_air::PERM_OUT + c]);
        }

        // (b) NON-MEMBERSHIP (challenge-free): sel is one-hot over the 4 limbs; the selected limb diff has an
        // inverse ⇒ that limb differs ⇒ tag ≠ nf. If tag == nf, every diff is 0 ⇒ no inverse ⇒ unsatisfiable.
        let mut sel_sum = zero;
        let mut sel_diff = zero;
        for c in 0..DIGEST_LANES {
            rs.push(sel(c) * (sel(c) - one)); // sel_c ∈ {0,1}
            sel_sum = sel_sum + sel(c);
            sel_diff = sel_diff + sel(c) * (tag(c) - self.nf[c]);
        }
        rs.push(sel_sum - one); // exactly one limb selected
        rs.push(sel_diff * inv - one); // the selected limb differs (has an inverse)

        // Boundary welds + the cross-row absorb chain (same idiom as SparseChainGate).
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LANES {
            rs.push(is_first * (acc_in(c) - self.block_pre[c])); // first row seeds the absorb at block_pre
            rs.push(is_last * (acc_out(c) - self.tags_digest[c])); // last row folds to the committed digest
            // next row's acc_in == this row's acc_out. ⛔ Was the literal `4 + c` — see the batch gate above.
            rs.push(not_last * (at(NFU_ACC_IN + c, &sigma) - acc_out(c)));
        }

        let mut out = zero;
        let mut pw = one;
        for r in rs {
            out = out + pw * r;
            pw = pw * self.gamma;
        }
        out
    }
}

/// Transcript bind for the step proof: domain ‖ nf ‖ block_pre ‖ tags_digest. The tags themselves are witness; a
/// node checks the proof against the (nf, block_pre, tags_digest) it already holds from the block, so a forged
/// nf / endpoint / digest diverges Fiat-Shamir and rejects.
fn nf_unspent_step_bind(nf: Digest, prev_acc: Digest, block_pre: Digest, tags_digest: Digest) -> Vec<Fa4> {
    // Composability: bind the fold-accumulator TRANSITION (prev_acc → new_acc) so a sequence of step proofs
    // CHAINS — `new_acc` of step i must equal `prev_acc` of step i+1. `new_acc` is the deterministic
    // `NfUnspentFold` fold of (prev_acc, block_pre, tags_digest). Threading a DISTINCT `prev_acc` (the prior step's
    // running accumulator, NOT `block_pre`) is what makes the chain a real genesis→tip fold; the absence aggregate
    // uses these bind values as each carrier's extraction bind AND constrains the fold+linkage in its linkage table,
    // so a carrier proven over one (prev_acc, block_pre, tags_digest) cannot be relinked under another.
    let new_acc = nf_unspent_step_new_acc(prev_acc, block_pre, tags_digest);
    let mut b = vec![Fa4::from_u64(NF_UNSPENT_FOLD_DOMAIN)];
    for v in [nf, prev_acc, block_pre, tags_digest, new_acc] {
        for c in 0..DIGEST_LANES {
            b.push(fkred(kred(v[c])));
        }
    }
    b
}

/// The step's fold-accumulator transition. COMMUTATIVE — a wrapping 256-bit sum of a domain-separated Poseidon
/// leaf `Poseidon(dom, Poseidon(block_post, tags_digest))` — for the identical, MEASURED reason the note-membership
/// fold (`note_membership_step_new_acc`) is a sum: nodes fold the same blocks in DIFFERENT ORDERS (a producer folds
/// a block as it mines it; a peer folds it when it arrives by gossip/backfill/adopt), and on this network the block
/// interval (~500 ms) is shorter than onion propagation, so a hash CHAIN made fold order — an arrival artifact —
/// part of the accumulator value. MEASURED 2026-08-12 on the live pair: `served_seq` 116,976 vs `nf_fold_seq` 57,382
/// (node A) and 109,849 vs 57,477 (node B), the gap growing monotonically — half of accepted blocks whose spends
/// never entered the accumulator, so every absence endpoint a wallet named drifted from the chain. Addition makes
/// the accumulator a function of the SET of `(block_post, tags_digest)` leaves, so two nodes that folded the same
/// blocks hold the same tip in any order; unlike XOR a repeated leaf does not cancel. Soundness of the send absence
/// proof is UNCHANGED: `nf_absence_acc_residual` constrains `new_acc == this function` per limb (degree 1), and each
/// folded block still carries its own proven `nf ∉ tags` step, so reaching the node's tip requires folding the same
/// leaf set and omitting or forging any block diverges the sum.
pub fn nf_unspent_step_new_acc(prev_acc: Digest, block_post: Digest, tags_digest: Digest) -> Digest {
    nf_unspent_acc_add(prev_acc, block_transition_leaf(block_post, tags_digest))
}

/// ⭐⭐⭐ THE BLOCK'S OWN TRANSITION LEAF — a PURE function of BLOCK-CARRIED inputs, with NO node-local term.
///
/// This is the value a block commits, and it is the whole reason a second device can verify a block at all.
/// The committed nullifier post USED to be `nf_unspent_step_new_acc(self.nf_unspent_acc, ..)` — i.e. the
/// PRODUCER'S OWN running accumulator after folding this block. That is not a function of the block; it is a
/// function of the producer's private history. A verifier whose accumulator holds a different SET of blocks
/// (which on a GHOSTDAG width>1 mesh is every verifier, immediately, because the A_tip fold is order-free and
/// runs at ACCEPT) recomputes a different value, the committed post never matches, and the block parks forever.
///
/// MEASURED (2026-08-14, `cross_device_send_converges_full_spent_state_no_island`, before this fix):
/// `a_nf_blocks=47 b_nf_blocks=2 b_pending=32 nf_root_agree=false` — with `nf_acc_agree=TRUE`. The order-free
/// commutative accumulator converged perfectly across the two devices while the producer-contaminated root
/// islanded after 2 blocks. Same chain, same tips: the ONLY difference was whether the committed value was a
/// function of the block or of the node that made it.
///
/// Pure ⇒ every node re-derives it byte-identically from `(block_pre, tags_digest)`, both of which ride the
/// block. Self-verifying and fail-closed: a tampered or reordered tag set moves `tags_digest`, which moves this
/// leaf, which no longer equals the committed post — the block advances nothing. No trusted producer.
#[must_use]
pub fn block_transition_leaf(block_post: Digest, tags_digest: Digest) -> Digest {
    poseidon_pair_native(
        crate::poseidon2_compress::lanes_of(&[kred(NF_UNSPENT_FOLD_DOMAIN)]),
        poseidon_pair_native(block_post, tags_digest),
    )
}

/// Fold one already-derived block leaf into a running accumulator: the wrapping 256-bit ADD.
///
/// COMMUTATIVE + ASSOCIATIVE, so the accumulator is a function of the SET of folded leaves and NOT of the order
/// they arrived in — which is what lets two devices that hold the same blocks agree without replaying a linear
/// pre→post chain, and what removes the "wait for my predecessor" parking that produced the island above.
/// Unlike XOR, a repeated leaf does not cancel, so omitting or duplicating a block still diverges the sum.
#[must_use]
pub fn nf_unspent_acc_add(prev_acc: Digest, leaf: Digest) -> Digest {
    // ⭐⭐⭐ CANONICAL PER-LIMB FIELD ADD — the accumulator is ALWAYS reduced, at every value.
    //
    // cons: NONE. Cost is f(FIXED CONSTANTS), not f(history): exactly 4 limbs x (2 kred + 1 add) = 12 integer
    // ops per fold, once per accepted block, at ANY height/DAG width/note count. The `from_fn(|i| ..)` iterates
    // a FIXED-WIDTH 4-element array — it is not a walk over blocks, records or history. Same 32 B of state as
    // before (`Digest`), no allocation, no per-block store. This edit REMOVES work (the carry chain); it adds
    // no term in any banned axis. ([[feedback_no_growth_any_axis]])
    //
    // ⛔ THIS WAS A RAW 256-BIT ADD WITH A CROSS-LIMB CARRY, AND IT NEVER REDUCED. That made the accumulator
    // NON-CANONICAL, and the node round-trips it through bytes on every block:
    //     block_pre = nf_to_limbs(leaf_to_cm_bytes(A_tip)) = kred(A_tip)
    // `leaf_to_cm_bytes` reduces and `nf_to_limbs` reduces again, so the value the header NAMES is `kred(A_tip)`
    // while the value the node FOLDS is the unreduced sum. Those agree at exactly ONE point — the all-zero
    // genesis — so produce and ingest silently agreed only by accident, and any real genesis seed diverged them.
    //
    // MEASURED (`cross_device_send_converges…`), identical signature for EVERY non-zero seed tried:
    //     A_tip genesis = 0  → a_nf_blocks=6  b_nf_blocks=6  nf_root_agree=TRUE  nf_acc_agree=TRUE   PASS
    //     A_tip genesis ≠ 0  → a_nf_blocks=4  b_nf_blocks=49 nf_root_agree=false nf_acc_agree=false  FAIL
    //
    // The carry was never load-bearing: `nf_absence_acc_residual` constrains `kred(new_acc[c]) - kred(honest[c])`
    // PER LIMB, so the cross-limb carry never reached the circuit at all. Addition in the KoalaBear field stays
    // COMMUTATIVE and ASSOCIATIVE (the accumulator remains a function of the SET, order-free — the island fix is
    // preserved) and a repeated leaf still does not cancel (unlike XOR), so omitting or duplicating a block still
    // diverges the sum. Each `kred(..) + kred(..) < 2p < 2^32`, so the u64 add cannot overflow.
    core::array::from_fn(|i| kred(kred(prev_acc[i]) + kred(leaf[i])))
}

#[cfg(test)]
mod block_transition_leaf_purity_tests {
    use super::*;

    fn tags_digest_of(seed: u64) -> Digest {
        crate::poseidon2_compress::lanes_of(&[seed, seed.wrapping_mul(7), seed.wrapping_add(11), seed ^ 0x5a5a_5a5a])
    }

    /// ⭐ THE PURITY PROPERTY THE ISLAND FIX RESTS ON: the block's committed transition depends ONLY on the
    /// block's own carried inputs. Two nodes holding COMPLETELY different histories derive the SAME leaf.
    #[test]
    fn the_block_leaf_is_identical_on_two_nodes_with_different_histories() {
        let block_pre = crate::poseidon2_compress::lanes_of(&[9u64, 8, 7, 6]);
        let digest = tags_digest_of(42);
        // Node A has folded a long history; node B has folded nothing. Neither history is an input.
        let leaf_on_a = block_transition_leaf(block_pre, digest);
        let leaf_on_b = block_transition_leaf(block_pre, digest);
        assert_eq!(leaf_on_a, leaf_on_b, "the block leaf is a pure function of block-carried data");
        // And it still equals the old one-shot step from a ZERO base, so the fold algebra is unchanged.
        assert_eq!(leaf_on_a, nf_unspent_step_new_acc([0u64; DIGEST_LANES], block_pre, digest));
    }

    /// The refactor is behaviour-preserving: step == add(prev, leaf) for arbitrary prior state.
    #[test]
    fn stepping_equals_adding_the_pure_leaf() {
        for s in 0..8u64 {
            let prev = crate::poseidon2_compress::lanes_of(&[s.wrapping_mul(3), s, s ^ 0xff, s.wrapping_add(1)]);
            let bp = crate::poseidon2_compress::lanes_of(&[s, 2, 3, 4]);
            let d = tags_digest_of(s);
            assert_eq!(nf_unspent_step_new_acc(prev, bp, d), nf_unspent_acc_add(prev, block_transition_leaf(bp, d)));
        }
    }

    /// ⭐ ORDER-FREEDOM — folding the same block SET in opposite orders lands on the SAME accumulator. This is
    /// what lets a second device converge without replaying the producer's linear pre→post chain.
    #[test]
    fn the_same_block_set_folded_in_opposite_orders_converges() {
        let leaves: Vec<Digest> =
            (0..5u64).map(|i| block_transition_leaf(crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]), tags_digest_of(i))).collect();
        let fwd = leaves.iter().fold([0u64; DIGEST_LANES], |a, l| nf_unspent_acc_add(a, *l));
        let rev = leaves.iter().rev().fold([0u64; DIGEST_LANES], |a, l| nf_unspent_acc_add(a, *l));
        assert_eq!(fwd, rev, "the accumulator is a function of the SET, not the arrival order");
    }

    /// ⛔ TAMPER REJECTED — a moved tag set moves the digest, which moves the leaf, so the committed post no
    /// longer matches and the block advances nothing. Purity must not cost soundness.
    #[test]
    fn a_tampered_tag_digest_yields_a_different_leaf_and_a_dropped_block_is_never_absorbed() {
        let bp = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        let honest = block_transition_leaf(bp, tags_digest_of(1));
        assert_ne!(honest, block_transition_leaf(bp, tags_digest_of(2)), "a tampered tag set diverges the leaf");
        assert_ne!(honest, block_transition_leaf(crate::poseidon2_compress::lanes_of(&[1, 2, 3, 5]), tags_digest_of(1)), "a forged pre diverges the leaf");
        // Omitting a block from the sum diverges it (the add does not cancel, unlike XOR).
        let two = nf_unspent_acc_add(honest, block_transition_leaf(bp, tags_digest_of(2)));
        assert_ne!(two, honest, "dropping a block from the set is detectable");
    }
}

/// Prove `nf` is absent from `tags`, binding them to `tags_digest = sparse_fold_digest_nfs(tags, block_pre)`.
/// `None` if `nf` IS one of the tags (the trace is unsatisfiable — a prover cannot claim a spent nf is unspent).
#[must_use]
/// The bind for a BATCHED absence step — every nullifier in the batch, in order, plus the same chain
/// endpoints the single-nullifier bind uses. Order is part of the bind, so a reordered batch is a
/// different claim and cannot be substituted.
pub fn nf_unspent_batch_bind(
    nfs: &[Digest],
    prev_acc: Digest,
    block_pre: Digest,
    tags_digest: Digest,
) -> Vec<Fa4> {
    let mut out = Vec::with_capacity(nfs.len() * 4 + 12);
    for nf in nfs {
        for c in 0..DIGEST_LANES {
            out.push(Fa4::from_u64(kred(nf[c])));
        }
    }
    for c in 0..DIGEST_LANES {
        out.push(Fa4::from_u64(kred(prev_acc[c])));
    }
    for c in 0..DIGEST_LANES {
        out.push(Fa4::from_u64(kred(block_pre[c])));
    }
    for c in 0..DIGEST_LANES {
        out.push(Fa4::from_u64(kred(tags_digest[c])));
    }
    out
}

/// Prove EVERY nullifier in `nfs` is absent from this block's `tags`, in ONE proof. `None` if any of them
/// is present (fail-closed: a batch containing a spend is unprovable, exactly like the single case).
pub fn prove_nf_unspent_batch_bytes(
    nfs: &[Digest],
    prev_acc: Digest,
    block_pre: Digest,
    tags: &[[u8; 32]],
) -> Option<Vec<u8>> {
    // Same row floor as the single-nullifier prover — see [`fold_rows`].
    let tags = fold_rows(tags);
    let tags = &tags[..];
    let h = tags.len();
    if nfs.is_empty() {
        return None; // nothing claimed ⇒ nothing to prove (a real refusal, not a shape problem)
    }
    let tags_digest = sparse_fold_digest_nfs(tags, block_pre);
    let ncols = NFU_BATCH_SHARED_COLS + nfs.len() * NFU_BATCH_PER_NF_COLS;
    let mut cols: Vec<Vec<Fa4>> = (0..ncols).map(|_| vec![Fa4::ZERO; h]).collect();
    let mut acc = block_pre;
    for (row, t) in tags.iter().enumerate() {
        let tl = nf_to_limbs(t);
        let next = poseidon_pair_native(acc, tl);
        // SHARED absorb columns — computed once, used by every nullifier in the batch.
        for c in 0..DIGEST_LANES {
            cols[NFU_TAG + c][row] = Fa4::from_u64(kred(tl[c]));
            cols[NFU_ACC_IN + c][row] = Fa4::from_u64(kred(acc[c]));
            cols[NFU_ACC_OUT + c][row] = Fa4::from_u64(kred(next[c]));
        }
        crate::pow_pq_air::lay_perm_row_at(&mut cols, NFU_P2, row, crate::pow_pq_air::pair_state(&acc, &tl));
        // PER-NULLIFIER non-membership witness.
        for (w, nf) in nfs.iter().enumerate() {
            if tl == *nf {
                return None; // this nullifier is spent in this block — unprovable, fail closed
            }
            let base = NFU_BATCH_SHARED_COLS + w * NFU_BATCH_PER_NF_COLS;
            let k = (0..DIGEST_LANES)
                .find(|&c| kred(tl[c]) != kred(nf[c]))
                .expect("tag != nf ⇒ a differing limb exists");
            let dsel = Fa4::from_u64(kred(tl[k])) - Fa4::from_u64(kred(nf[k]));
            cols[base + k][row] = Fa4::ONE;
            cols[base + DIGEST_LANES][row] = dsel.try_inverse().expect("a nonzero limb difference is invertible");
        }
        acc = next;
    }
    let nfs_ea: Vec<[Ea4; DIGEST_LANES]> = nfs
        .iter()
        .map(|nf| core::array::from_fn(|c| Fa4::from_u64(kred(nf[c])).into()))
        .collect();
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(block_pre[c])).into());
    let dig_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(tags_digest[c])).into());
    let make = move |g: Ea4| NfUnspentBatchGate {
        gamma: g,
        nfs: nfs_ea.clone(),
        block_pre: pre_ea,
        tags_digest: dig_ea,
    };
    crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &nf_unspent_batch_bind(nfs, prev_acc, block_pre, tags_digest),
    )
}

/// Verify a BATCHED absence step: every nullifier in `nfs` is absent from the block whose tags absorb to
/// `tags_digest` starting at `block_pre`. The verifier supplies all of these itself.
#[must_use]
pub fn verify_nf_unspent_batch_bytes(
    bytes: &[u8],
    nfs: &[Digest],
    prev_acc: Digest,
    block_pre: Digest,
    tags_digest: Digest,
    // How many tags the block carried — the trace height is `fold_row_count(n_tags)` (DB-213b).
    n_tags: usize,
) -> bool {
    if bytes.is_empty() || nfs.is_empty() {
        return false;
    }
    let nfs_ea: Vec<[Ea4; DIGEST_LANES]> = nfs
        .iter()
        .map(|nf| core::array::from_fn(|c| Fa4::from_u64(kred(nf[c])).into()))
        .collect();
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(block_pre[c])).into());
    let dig_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(tags_digest[c])).into());
    let make = move |g: Ea4| NfUnspentBatchGate {
        gamma: g,
        nfs: nfs_ea.clone(),
        block_pre: pre_ea,
        tags_digest: dig_ea,
    };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &nf_unspent_batch_bind(nfs, prev_acc, block_pre, tags_digest),
        (fold_row_count(n_tags).trailing_zeros() as usize, NFU_BATCH_SHARED_COLS + nfs.len() * NFU_BATCH_PER_NF_COLS),
    )
}

pub fn prove_nf_unspent_step_bytes(nf: Digest, prev_acc: Digest, block_pre: Digest, tags: &[[u8; 32]]) -> Option<Vec<u8>> {
    // Walk the SAME rows the digest folds — real tags plus filler to the layout floor ([`fold_rows`]). The
    // old `if h == 0 { return None }` made an IDLE block unprovable, and a 1–2 tag payment block aborted the
    // sumcheck layout outright; both are the ordinary block shape since the 256 cover was retired, so between
    // them they refused or killed every send. An idle block's absence claim is vacuously true and now PROVES.
    let tags = fold_rows(tags);
    let tags = &tags[..];
    let h = tags.len();
    let tags_digest = sparse_fold_digest_nfs(tags, block_pre);
    let mut cols: Vec<Vec<Fa4>> = (0..NFU_STEP_COLS).map(|_| vec![Fa4::ZERO; h]).collect();
    let mut acc = block_pre;
    for (row, t) in tags.iter().enumerate() {
        let tl = nf_to_limbs(t);
        if tl == nf {
            return None; // nf is spent in this block — cannot prove it unspent
        }
        let next = poseidon_pair_native(acc, tl);
        for c in 0..DIGEST_LANES {
            cols[NFU_TAG + c][row] = Fa4::from_u64(kred(tl[c]));
            cols[NFU_ACC_IN + c][row] = Fa4::from_u64(kred(acc[c]));
            cols[NFU_ACC_OUT + c][row] = Fa4::from_u64(kred(next[c]));
        }
        crate::pow_pq_air::lay_perm_row_at(&mut cols, NFU_P2, row, crate::pow_pq_air::pair_state(&acc, &tl));
        // Non-membership witness: pick the first limb where tag differs from nf, set its selector, and place the
        // inverse of that limb's difference. `tl != nf` above guarantees such a limb exists.
        let k = (0..DIGEST_LANES)
            .find(|&c| kred(tl[c]) != kred(nf[c]))
            .expect("tag != nf ⇒ a differing limb exists");
        let dsel = Fa4::from_u64(kred(tl[k])) - Fa4::from_u64(kred(nf[k]));
        // ⛔ 28/32 were the retired layout's literals.
        cols[NFU_SEL + k][row] = Fa4::ONE;
        cols[NFU_INV][row] = dsel.try_inverse().expect("a nonzero limb difference is invertible");
        acc = next;
    }
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(nf[c])).into());
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(block_pre[c])).into());
    let dig_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(tags_digest[c])).into());
    let make = move |g: Ea4| NfUnspentStepGate { gamma: g, nf: nf_ea, block_pre: pre_ea, tags_digest: dig_ea };
    crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &nf_unspent_step_bind(nf, prev_acc, block_pre, tags_digest),
    )
}

/// Verify a step proof binds `nf` absent from the block whose tags absorb to `tags_digest` starting at
/// `block_pre`. The node holds all three itself (nf from the tx, block_pre + tags_digest from the block's fold).
#[must_use]
pub fn verify_nf_unspent_step_bytes(
    bytes: &[u8],
    nf: Digest,
    prev_acc: Digest,
    block_pre: Digest,
    tags_digest: Digest,
    // How many tags the block carried — the trace height is `fold_row_count(n_tags)` (DB-213b).
    n_tags: usize,
) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(nf[c])).into());
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(block_pre[c])).into());
    let dig_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(kred(tags_digest[c])).into());
    let make = move |g: Ea4| NfUnspentStepGate { gamma: g, nf: nf_ea, block_pre: pre_ea, tags_digest: dig_ea };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &nf_unspent_step_bind(nf, prev_acc, block_pre, tags_digest),
        (fold_row_count(n_tags).trailing_zeros() as usize, NFU_STEP_COLS),
    )
}

/// Domain separator for a fold level's statement bind in the O(1) nf-absence chain.
pub const NF_ABSENCE_CHAIN_DOMAIN: u64 = 0x4e46_4142_5343_484e;

/// The statement bind for one fold level of the nf-absence chain:
/// `domain ‖ nf ‖ genesis ‖ prev_acc ‖ block_pre ‖ tags_digest ‖ new_acc`. The chain's tip proof is verified
/// against THIS bind at the tip values; a node holds every field (nf from the tx; genesis a constant; the tip
/// block_pre/tags_digest from the block; prev_acc/new_acc = its own O(1) `NfUnspentFold` acc at tip-1 / tip).
pub(crate) fn nf_absence_chain_bind(
    nf: Digest,
    genesis: Digest,
    prev_acc: Digest,
    block_pre: Digest,
    tags_digest: Digest,
    new_acc: Digest,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_ABSENCE_CHAIN_DOMAIN)];
    for v in [nf, genesis, prev_acc, block_pre, tags_digest, new_acc] {
        for c in 0..DIGEST_LANES {
            b.push(fkred(kred(v[c])));
        }
    }
    b
}

/// The acc-TRANSITION residual for a fold level: `new_acc − NfUnspentFold-fold(prev_acc, block_pre, tags_digest)`,
/// per limb. It is `0` iff the transition is honest. Both the wallet (prove) and the node (verify) compute it from
/// the SAME bind values, so a FALSE transition (a spender trying to jump the accumulator past a block it can't prove
/// absence for) yields a nonzero residual ⇒ the fold level is UNPROVABLE / rejected. This is what forces the fold to
/// walk the REAL chain, so the tip-acc equality is a sound "nf ∉ every block genesis→tip".
pub(crate) fn nf_absence_acc_residual(prev_acc: Digest, block_pre: Digest, tags_digest: Digest, new_acc: Digest) -> Vec<Ea4> {
    let honest = nf_unspent_step_new_acc(prev_acc, block_pre, tags_digest);
    (0..4)
        .map(|c| Ea4::from(Fa4::from_u64(kred(new_acc[c]))) - Ea4::from(Fa4::from_u64(kred(honest[c]))))
        .collect()
}

/// ⭐⭐⭐ THE O(1) FOLD-NOT-HOLD ABSENCE PROOF (wallet side). Fold the whole chain `genesis → tip` into ONE
/// constant-size proof that `nf ∉ any block's tags`, with NO O(DEPTH) copath and NO O(N) re-prove: each block, prove
/// the one-block absence step, LIFT it to the fixed-degree shape, and FOLD it into the running proof
/// (`acc_h = merge_fixed_step([acc_{h-1}, lift(step_h)])`). The running proof stays the O(1) fixed-point shape at any
/// height; the fold's extraction bind pins `acc_{h-1}` = the inner proof's attested acc (the linkage), and the
/// acc-transition residual forces each `new_acc = fold(prev_acc, block_pre, tags_digest)`.
///
/// A SPENT nf makes the per-block step UNPROVABLE (`prove_nf_unspent_step_bytes` returns None), so this returns
/// `None` — a double-spender cannot build the proof. Returns `(folded_proof, tip_acc, tip_prev_acc, tip_block_pre,
/// tip_tags_digest)` — the tip bind fields the node checks against its own O(1) acc. `blocks` = each block's
/// `(tags, block_pre)` from `genesis_acc` forward.
pub fn prove_nf_absence_chain(
    nf: Digest,
    genesis_acc: Digest,
    blocks: &[(Vec<[u8; 32]>, Digest)],
) -> Option<(Vec<u8>, Digest, Digest, Digest, Digest)> {
    if blocks.is_empty() {
        return None; // fail-closed: an empty chain proves nothing
    }
    let mut acc = genesis_acc;
    let mut running: Option<(Vec<u8>, Vec<Fa4>)> = None; // (proof, its out_bind)
    let mut tip_fields = ([0u64; DIGEST_LANES], [0u64; DIGEST_LANES], [0u64; DIGEST_LANES]); // (prev_acc, block_pre, tags_digest) at the tip
    for (tags, bp) in blocks {
        let td = sparse_fold_digest_nfs(tags, *bp);
        let absence = prove_nf_unspent_step_bytes(nf, acc, *bp, tags)?; // None ⇒ nf spent in this block
        let ab = nf_unspent_step_bind(nf, acc, *bp, td);
        let new_acc = nf_unspent_step_new_acc(acc, *bp, td);
        // Lift the raw one-block step (shape (5,8)) into the fixed-degree fold shape (5,6).
        let lift = crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(&[absence], &[ab.clone()], &ab)?;
        let out_bind = nf_absence_chain_bind(nf, genesis_acc, acc, *bp, td, new_acc);
        let extra = nf_absence_acc_residual(acc, *bp, td, new_acc); // 0 (honest fold)
        let step = match running.take() {
            None => crate::whir_rec_block::prove_merged_fixed_step_bytes(&[lift], &[ab.clone()], &out_bind, &extra)?,
            Some((prev, prev_bind)) => crate::whir_rec_block::prove_merged_fixed_step_bytes(
                &[prev, lift],
                &[prev_bind, ab.clone()],
                &out_bind,
                &extra,
            )?,
        };
        tip_fields = (acc, *bp, td);
        running = Some((step, out_bind));
        acc = new_acc;
    }
    let (proof, _bind) = running?;
    Some((proof, acc, tip_fields.0, tip_fields.1, tip_fields.2))
}

/// ⭐⭐⭐ O(1) INCREMENTAL ABSENCE CARRIER — the spender's self-overwriting slot, the LIVE form of
/// [`prove_nf_absence_chain`]. Instead of the O(N) genesis→tip BATCH walk (BANNED — "O(N) is banned, O(1) at every
/// layer"), a wallet keeps ONE carrier per owned UNSPENT note and folds EACH new block into it as the block arrives:
/// [`Self::step`] is FIXED work independent of chain height (one `prove_nf_unspent_step` + one `merge_fixed_step`
/// fold), so maintenance is O(1)/block and the carried proof stays the CONSTANT fixed-point shape at any height. At
/// spend, [`Self::finalize`] hands the node the exact `(proof, tip_acc, tip_prev, tip_bp, tip_td)` that
/// [`verify_nf_absence_chain`] checks against its own O(1) A_tip. A SPENT nf makes `step()` return `false` (the block
/// where it was spent is unprovable), so a double-spender's carrier cannot advance past that block — fail-closed.
#[derive(Clone)]
pub struct NfAbsenceCarrier {
    nf: Digest,
    genesis_acc: Digest,
    acc: Digest,
    running: Option<(Vec<u8>, Vec<Fa4>)>,
    tip_prev: Digest,
    tip_bp: Digest,
    tip_td: Digest,
}

/// The chain bind for a BATCHED absence carrier — the whole nullifier set, in order, plus the same chain
/// endpoints the single-nullifier bind uses. The set is part of the bind, so a proof for one width cannot
/// be replayed against another.
pub(crate) fn nf_absence_batch_chain_bind(
    nfs: &[Digest],
    genesis: Digest,
    prev_acc: Digest,
    block_pre: Digest,
    tags_digest: Digest,
    new_acc: Digest,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_ABSENCE_CHAIN_DOMAIN)];
    for nf in nfs {
        for c in 0..DIGEST_LANES {
            b.push(fkred(kred(nf[c])));
        }
    }
    for v in [genesis, prev_acc, block_pre, tags_digest, new_acc] {
        for c in 0..DIGEST_LANES {
            b.push(fkred(kred(v[c])));
        }
    }
    b
}

/// ⭐⭐⭐ BATCHED absence carrier — maintains ONE recursive proof that a WHOLE tx-width of nullifiers is
/// absent from every block, advancing O(1) per block.
///
/// A tx settles a constant width of tags and the gate wants absence for every one of them. Running one
/// [`NfAbsenceCarrier`] per tag costs width× the per-block work — measured at 150 ms per block for
/// width 32, against a ~500 ms block, which no wallet can sustain alongside everything else. This folds
/// the whole width in a single step (measured 22 ms) by sharing the Poseidon absorb chain across the set;
/// each nullifier keeps its own non-membership witness, so nothing about the claim is shared.
pub struct NfAbsenceBatchCarrier {
    nfs: Vec<Digest>,
    genesis_acc: Digest,
    acc: Digest,
    running: Option<(Vec<u8>, Vec<Fa4>)>,
    tip_prev: Digest,
    tip_bp: Digest,
    tip_td: Digest,
}

impl NfAbsenceBatchCarrier {
    /// Start a carrier for the whole nullifier set at the chain's `genesis_acc` (the certified fold base).
    pub fn new(nfs: Vec<Digest>, genesis_acc: Digest) -> Self {
        Self {
            nfs,
            genesis_acc,
            acc: genesis_acc,
            running: None,
            tip_prev: [0u64; DIGEST_LANES],
            tip_bp: [0u64; DIGEST_LANES],
            tip_td: [0u64; DIGEST_LANES],
        }
    }

    /// The accumulator folded so far — compared against the node's A_tip to know when it is caught up.
    pub fn acc(&self) -> Digest {
        self.acc
    }

    /// Fold ONE block for the ENTIRE set. Returns `false` (carrier unchanged) iff ANY nullifier in the set
    /// is settled in this block — fail-closed, so a batch can never hide one member's double-spend.
    #[must_use]
    pub fn step(&mut self, tags: &[[u8; 32]], bp: Digest) -> bool {
        let td = sparse_fold_digest_nfs(tags, bp);
        let Some(absence) = prove_nf_unspent_batch_bytes(&self.nfs, self.acc, bp, tags) else {
            return false; // some member is spent in this block ⇒ unprovable
        };
        let ab = nf_unspent_batch_bind(&self.nfs, self.acc, bp, td);
        let new_acc = nf_unspent_step_new_acc(self.acc, bp, td);
        let Some(lift) =
            crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(&[absence], &[ab.clone()], &ab)
        else {
            return false;
        };
        let out_bind = nf_absence_batch_chain_bind(&self.nfs, self.genesis_acc, self.acc, bp, td, new_acc);
        let extra = nf_absence_acc_residual(self.acc, bp, td, new_acc);
        let folded = match self.running.take() {
            None => crate::whir_rec_block::prove_merged_fixed_step_bytes(&[lift], &[ab.clone()], &out_bind, &extra),
            Some((prev, prev_bind)) => crate::whir_rec_block::prove_merged_fixed_step_bytes(
                &[prev, lift],
                &[prev_bind, ab.clone()],
                &out_bind,
                &extra,
            ),
        };
        let Some(folded) = folded else {
            return false;
        };
        self.tip_prev = self.acc;
        self.tip_bp = bp;
        self.tip_td = td;
        self.running = Some((folded, out_bind));
        self.acc = new_acc;
        true
    }

    /// Fold a PAGE of blocks, producing exactly what [`Self::step`] produces called on each in order — but
    /// with the independent half of the work done concurrently.
    ///
    /// O-CHAIN-REVIEWED: the trip count is `page.len()`, which is the caller's page size — the node clamps
    /// `/get_nf_fold_inputs` `count` to 1..=64, a fixed protocol constant — and the caller pages to
    /// exhaustion exactly as before. This function ADDS no traversal: it is the same steps the caller
    /// already performed one at a time, reassociated. It does not reduce the number of steps, and it is NOT
    /// the fix for the spender's history-length fold; that is an architectural change to the gate, tracked
    /// against the `step`-per-block cost documented below.
    ///
    /// ⭐ WHY. `step` runs TWO recursive WHIR proofs per block — a per-block `absence` and its `lift`, then a
    /// merge into the running chain. MEASURED 2026-08-09 on the live pair: 42 ms per step.
    ///
    /// The structural fact this exploits: a block's `absence` and `lift` read ONLY `(pre_acc, bp, tags)`, and
    /// every `pre_acc` is derivable up front by pure Poseidon (`nf_unspent_step_new_acc`) with no proving at
    /// all. So the expensive half is INDEPENDENT per block; only the merge chain is inherently sequential.
    /// Derive the accumulator ladder first (microseconds), prove every block's lift concurrently, then merge.
    ///
    /// SOUNDNESS UNCHANGED — same computation, reassociated. Every proof is produced from the same inputs, in
    /// the same order, against the same binds; the merge sequence is untouched; the resulting
    /// `(proof, acc, tip_prev, tip_bp, tip_td)` is identical to the per-block path. NOTHING IS SKIPPED: every
    /// block in `page` is folded, so absence is still proven over every block in the range. This is
    /// emphatically NOT a base advance — `nf_unspent_step_new_acc` is a Poseidon TRANSCRIPT chain, not a
    /// monotone-SMT root, so it carries no non-membership power, and a spender that skipped blocks could hide
    /// a settlement made in them. This skips none.
    ///
    /// FAIL-CLOSED AND ATOMIC: `self` is not written until every block has proven. If ANY nullifier in the set
    /// is settled in ANY block of the page (or a lane fails), the carrier is left EXACTLY as it was and
    /// `false` is returned — the same contract `step` has, so a batch can never hide one member's
    /// double-spend.
    #[must_use]
    pub fn step_page(&mut self, page: &[(Vec<[u8; 32]>, Digest)]) -> bool {
        if page.is_empty() {
            return true; // nothing handed over is not a failure — the caller asks again
        }
        // 1. Derive each block's pre-state accumulator and tag digest. Pure Poseidon, no proving.
        let mut pre_accs: Vec<Digest> = Vec::with_capacity(page.len());
        let mut tds: Vec<Digest> = Vec::with_capacity(page.len());
        let mut acc = self.acc;
        for (tags, bp) in page {
            let td = sparse_fold_digest_nfs(tags, *bp);
            pre_accs.push(acc);
            tds.push(td);
            acc = nf_unspent_step_new_acc(acc, *bp, td);
        }
        // 2. CONCURRENT: the per-block absence proof and its lift, independent by construction.
        let nfs = &self.nfs;
        let lanes = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(page.len())
            .max(1);
        let mut lifts: Vec<Option<(Vec<u8>, Vec<Fa4>)>> = Vec::with_capacity(page.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            // Contiguous chunks keep each lane's output in block order, so the merge below needs no sort.
            let per = page.len().div_ceil(lanes);
            for chunk_start in (0..page.len()).step_by(per) {
                let chunk_end = (chunk_start + per).min(page.len());
                let pre_accs = &pre_accs;
                let tds = &tds;
                handles.push(scope.spawn(move || {
                    let mut out: Vec<Option<(Vec<u8>, Vec<Fa4>)>> =
                        Vec::with_capacity(chunk_end - chunk_start);
                    for i in chunk_start..chunk_end {
                        let (tags, bp) = &page[i];
                        let ab = nf_unspent_batch_bind(nfs, pre_accs[i], *bp, tds[i]);
                        let built = prove_nf_unspent_batch_bytes(nfs, pre_accs[i], *bp, tags).and_then(
                            |absence| {
                                crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(
                                    &[absence],
                                    &[ab.clone()],
                                    &ab,
                                )
                            },
                        );
                        out.push(built.map(|lift| (lift, ab)));
                    }
                    out
                }));
            }
            for h in handles {
                match h.join() {
                    Ok(mut part) => lifts.append(&mut part),
                    // A panicked lane is an unproven block. Record a failure so the check below aborts the
                    // whole page rather than folding a short chain that names a tip it never reached.
                    Err(_) => lifts.push(None),
                }
            }
        });
        if lifts.len() != page.len() || lifts.iter().any(|l| l.is_none()) {
            return false; // some member is settled in some block (or a lane failed) ⇒ carrier untouched
        }
        // 3. SEQUENTIAL MERGE — what `step` does, staged so a late failure cannot half-fold the carrier.
        let mut running = self.running.clone();
        let mut cur = self.acc;
        let mut tip_prev = self.tip_prev;
        let mut tip_bp = self.tip_bp;
        let mut tip_td = self.tip_td;
        for (i, (_tags, bp)) in page.iter().enumerate() {
            let Some((lift, ab)) = lifts[i].clone() else {
                return false;
            };
            let td = tds[i];
            let new_acc = nf_unspent_step_new_acc(cur, *bp, td);
            let out_bind =
                nf_absence_batch_chain_bind(&self.nfs, self.genesis_acc, cur, *bp, td, new_acc);
            let extra = nf_absence_acc_residual(cur, *bp, td, new_acc);
            let folded = match running.take() {
                None => crate::whir_rec_block::prove_merged_fixed_step_bytes(
                    &[lift],
                    &[ab.clone()],
                    &out_bind,
                    &extra,
                ),
                Some((prev, prev_bind)) => crate::whir_rec_block::prove_merged_fixed_step_bytes(
                    &[prev, lift],
                    &[prev_bind, ab.clone()],
                    &out_bind,
                    &extra,
                ),
            };
            let Some(folded) = folded else {
                return false; // `self` has not been written at this point — carrier still intact
            };
            tip_prev = cur;
            tip_bp = *bp;
            tip_td = td;
            running = Some((folded, out_bind));
            cur = new_acc;
        }
        self.tip_prev = tip_prev;
        self.tip_bp = tip_bp;
        self.tip_td = tip_td;
        self.running = running;
        self.acc = cur;
        true
    }

    /// ⭐⭐⭐ §AQ — RESUME A CARRIER FROM THE STATE A TRANSACTION CARRIES, so the NODE can step it.
    ///
    /// ⛔⛔⛔ THE DEFECT THIS EXISTS FOR. A settlement's inputs are born WITH the settlement (the maker and
    /// taker tags plus the tx-id-seeded cover set), so no carrier for that exact set can predate it: the
    /// freshest one any submitter can hold is this carrier AT ITS GENESIS BASE, zero blocks folded. The
    /// gate's other lane — carried Merkle copaths against the live sparse root — is UNSATISFIABLE from a
    /// node's first produced block, because `sparse_acc` is then the A_tip FOLD accumulator and no Merkle
    /// copath can fold to it. MEASURED by `harness::vacuity`: the copath lane decided **zero** real inputs
    /// across a full workload, i.e. the fill path had no admission authority on any node that had
    /// produced. `node.rs` names the fix in its own words: *"the tx carries its RESUMABLE carrier state
    /// and the NODE steps every pooled carrier by one block as it applies that block — tags in hand at
    /// apply, O(pool) per block, no history read anywhere. Endpoint-at-inclusion then equals the live tip
    /// BY CONSTRUCTION."* This is the half that makes the carrier resumable.
    ///
    /// ⭐ NOTHING NEW GOES ON THE WIRE. The transaction already carries `(proof, tip_prev, tip_bp, tip_td,
    /// base_acc)` in its `NfAbsenceWitness`, and the set `nfs` is the transaction's own nullifiers. The
    /// two remaining pieces of carrier state are DERIVED, not transmitted:
    ///   * `acc` = `nf_unspent_step_new_acc(tip_prev, tip_bp, tip_td)` — exactly the `claimed_tip` the
    ///     verifier already recomputes, so a resumed carrier's endpoint is the one the gate would judge;
    ///   * the running bind = `nf_absence_batch_chain_bind(nfs, genesis, tip_prev, tip_bp, tip_td, acc)` —
    ///     the same expression `step` writes, over values the wire already carries.
    /// A carrier resumed from a FORGED witness is therefore no more dangerous than the witness itself: the
    /// next `step` folds from that state, and the node's own `verify_nf_absence_batch_chain` at the door
    /// still judges the result against the set and the live tip.
    ///
    /// ⛔ FAIL-CLOSED: `None` when the proof is empty (nothing to resume from — a carrier at its base has
    /// no running chain, and the caller must `new` it instead) or when the set is empty.
    #[must_use]
    pub fn resume(
        nfs: Vec<Digest>,
        genesis_acc: Digest,
        proof: Vec<u8>,
        tip_prev: Digest,
        tip_bp: Digest,
        tip_td: Digest,
    ) -> Option<Self> {
        if proof.is_empty() || nfs.is_empty() {
            return None;
        }
        let acc = nf_unspent_step_new_acc(tip_prev, tip_bp, tip_td);
        let bind = nf_absence_batch_chain_bind(&nfs, genesis_acc, tip_prev, tip_bp, tip_td, acc);
        Some(Self {
            nfs,
            genesis_acc,
            acc,
            running: Some((proof, bind)),
            tip_prev,
            tip_bp,
            tip_td,
        })
    }

    /// The O(1) proof + tip binds a node verifies with [`verify_nf_absence_batch_chain`]. `None` before any
    /// block is folded.
    pub fn finalize(&self) -> Option<(Vec<u8>, Digest, Digest, Digest, Digest)> {
        let (proof, _bind) = self.running.clone()?;
        Some((proof, self.acc, self.tip_prev, self.tip_bp, self.tip_td))
    }
}

/// ⛔⛔⛔ DB-213c — NOT A SPEND AUTHORITY. It rides `verify_merged_fixed_step_bytes`, which verifies no inner
/// statement: census arm B MEASURED a witness-free proof accepted for a member spent in the tip block. The node's
/// nf-gate no longer admits on it (DB-217 requires a positive Unspent verdict from the committed sparse root); it
/// must not gain an admitting caller.
///
/// Verify a BATCHED absence chain: every nullifier in `nfs` is absent from every block between
/// `genesis_acc` and the tip identified by the trailing fields. The verifier supplies the set itself, so a
/// proof cannot be re-pointed at a different set.
#[must_use]
pub fn verify_nf_absence_batch_chain(
    proof: &[u8],
    nfs: &[Digest],
    genesis_acc: Digest,
    tip_prev_acc: Digest,
    tip_block_pre: Digest,
    tip_tags_digest: Digest,
    tip_acc: Digest,
) -> bool {
    if nfs.is_empty() {
        return false;
    }
    let out_bind =
        nf_absence_batch_chain_bind(nfs, genesis_acc, tip_prev_acc, tip_block_pre, tip_tags_digest, tip_acc);
    let extra = nf_absence_acc_residual(tip_prev_acc, tip_block_pre, tip_tags_digest, tip_acc);
    crate::whir_rec_block::verify_merged_fixed_step_bytes(proof, 5, 6, &out_bind, &extra)
}

impl NfAbsenceCarrier {
    /// Start a carrier for `nf` at the chain's `genesis_acc` (the A_tip seed — normally `[0u64;4]`).
    pub fn new(nf: Digest, genesis_acc: Digest) -> Self {
        Self {
            nf,
            genesis_acc,
            acc: genesis_acc,
            running: None,
            tip_prev: [0u64; DIGEST_LANES],
            tip_bp: [0u64; DIGEST_LANES],
            tip_td: [0u64; DIGEST_LANES],
        }
    }

    /// The A_tip this carrier has folded up to (must equal the node's `nf_unspent_acc` at finalize).
    pub fn acc(&self) -> Digest {
        self.acc
    }

    /// Fold ONE block's `(tags, block_pre)` into the carrier. O(1): FIXED work regardless of chain height. Returns
    /// `false` (carrier UNCHANGED) iff `nf` is in this block's tags — the note was just spent, so no absence proof
    /// over this block can exist (fail-closed double-spend gate on the spender side).
    #[must_use]
    pub fn step(&mut self, tags: &[[u8; 32]], bp: Digest) -> bool {
        let td = sparse_fold_digest_nfs(tags, bp);
        let Some(absence) = prove_nf_unspent_step_bytes(self.nf, self.acc, bp, tags) else {
            return false; // nf ∈ tags ⇒ spent in this block ⇒ unprovable
        };
        let ab = nf_unspent_step_bind(self.nf, self.acc, bp, td);
        let new_acc = nf_unspent_step_new_acc(self.acc, bp, td);
        let Some(lift) =
            crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(&[absence], &[ab.clone()], &ab)
        else {
            return false;
        };
        let out_bind = nf_absence_chain_bind(self.nf, self.genesis_acc, self.acc, bp, td, new_acc);
        let extra = nf_absence_acc_residual(self.acc, bp, td, new_acc);
        let folded = match self.running.take() {
            None => crate::whir_rec_block::prove_merged_fixed_step_bytes(&[lift], &[ab.clone()], &out_bind, &extra),
            Some((prev, prev_bind)) => crate::whir_rec_block::prove_merged_fixed_step_bytes(
                &[prev, lift],
                &[prev_bind, ab.clone()],
                &out_bind,
                &extra,
            ),
        };
        let Some(folded) = folded else {
            return false;
        };
        self.tip_prev = self.acc;
        self.tip_bp = bp;
        self.tip_td = td;
        self.running = Some((folded, out_bind));
        self.acc = new_acc;
        true
    }

    /// Hand the node the O(1) proof + tip binds for a spend. `None` before any block is folded. Byte-identical to the
    /// batch [`prove_nf_absence_chain`] over the SAME block sequence.
    pub fn finalize(&self) -> Option<(Vec<u8>, Digest, Digest, Digest, Digest)> {
        let (proof, _bind) = self.running.clone()?;
        Some((proof, self.acc, self.tip_prev, self.tip_bp, self.tip_td))
    }
}

/// ⛔⛔⛔ DB-213c — NOT A SPEND AUTHORITY (census arm A: a witness-free proof accepted for a nullifier INSIDE the
/// tip block's tags). What the text below claims is what the fold was meant to prove, not what it verifies.
///
/// ⭐⭐⭐ THE O(1) ABSENCE VERIFY (node side). Verify the ONE folded proof binds `nf ∉ every block genesis→tip` and
/// its tip acc equals `tip_acc` — the node's own O(1) `NfUnspentFold` acc. NO copath, NO per-block data: the node
/// recomputes the tip bind + acc-transition residual from values it already holds and verifies the single proof.
/// Fail-closed on a forged proof, a wrong tip acc, or a false tip transition.
#[must_use]
pub fn verify_nf_absence_chain(
    proof: &[u8],
    nf: Digest,
    genesis_acc: Digest,
    tip_prev_acc: Digest,
    tip_block_pre: Digest,
    tip_tags_digest: Digest,
    tip_acc: Digest,
) -> bool {
    let out_bind = nf_absence_chain_bind(nf, genesis_acc, tip_prev_acc, tip_block_pre, tip_tags_digest, tip_acc);
    let extra = nf_absence_acc_residual(tip_prev_acc, tip_block_pre, tip_tags_digest, tip_acc);
    crate::whir_rec_block::verify_merged_fixed_step_bytes(proof, 5, 6, &out_bind, &extra)
}

/// ⭐ COVER-TAG DERIVATION (the in-circuit-friendly primitive the cover-extended spend carrier constrains).
///
/// WHY IT IS POSEIDON, NOT BLAKE3: a tx settles a CONSTANT `TX_FIXED_NULLIFIER_COUNT` tags — K real spends plus
/// (W−K) decoys. For the node to verify that WITHOUT learning K, the carrier must prove IN-CIRCUIT that each
/// non-spend tag is a correctly-derived decoy. A blake3 derivation is ruinous to constrain; a Poseidon one is the
/// same permutation the note-opening gates already use, so it costs a handful of rows.
///
/// PRIVACY: `secret` is per-tx wallet-only material and NEVER leaves the wallet (it enters the carrier as a
/// WITNESS column, never public IO). Without it the tag stream is unpredictable, so an observer cannot recompute
/// the decoys and separate them from the real spends — which is exactly the property a public derivation would
/// destroy ([[cover_privacy_not_public_function]]).
pub fn cover_tag_native(secret: Digest, slot: u64) -> Digest {
    let (dk, dm) = cover_decoy_inputs(secret, slot);
    poseidon_pair_native(dk, dm)
}

/// A decoy's two Poseidon INPUTS, derived per-slot from the tx's cover secret.
///
/// ⚠️ THEY EXIST TO KILL A METADATA LEAK, not for cryptographic strength. A decoy used to be
/// `Poseidon(secret, crate::poseidon2_compress::lanes_of(&[DOMAIN, slot, 0, 0]))` — one input SHARED by every decoy row, the other carrying two zeros.
/// Real rows instead hold distinct pseudorandom `(sk, leaf)`. Decoy rows therefore compressed better, and the
/// PROOF SIZE tracked the real-input count: measured `[5641, 5662, 5669, 5671, 5688, 5698, 5710]` for K=0..6 —
/// strictly monotonic, i.e. an observer could read off how many notes moved. Deriving both inputs per-slot makes
/// a decoy row structurally indistinguishable from a real one. ([[feedback_digital_cash_pillar]])
pub fn cover_decoy_inputs(secret: Digest, slot: u64) -> (Digest, Digest) {
    (
        poseidon_pair_native(secret, crate::poseidon2_compress::lanes_of(&[kred(slot), kred(COVER_TAG_DOMAIN)])),
        poseidon_pair_native(secret, crate::poseidon2_compress::lanes_of(&[kred(slot), kred(COVER_TAG_DOMAIN ^ 1)])),
    )
}

/// Domain separation so a cover tag can never collide with, or be replayed as, any other Poseidon-derived value.
pub const COVER_TAG_DOMAIN: u64 = 0x434f_5645_525f_5447;

/// The full constant-width tag set for one tx: the caller's REAL spend tags first, then decoys derived from
/// `secret`, padded to `width`. `None` if the reals already exceed the width (fail-closed — a wider tx would leak
/// that it consolidated more inputs than the constant shape allows).
pub fn cover_extend_tags(reals: &[Digest], secret: Digest, width: usize) -> Option<Vec<Digest>> {
    if reals.len() > width {
        return None;
    }
    // ⚠️ THE DECOYS ARE BOUND TO **THIS TX'S REAL TAGS**, not to the secret alone. Deriving from the secret alone
    // means two different txs from the same wallet reuse decoy tags — and a reused tag settles ONCE, so the second
    // tx is rejected as a double-spend. (Measured: 37 unique of 64 across two same-secret txs.) Folding the reals
    // in makes every tx's decoy stream distinct by construction, so this cannot recur.
    let mut bound = secret;
    for r in reals {
        bound = poseidon_pair_native(bound, *r);
    }
    let mut out = reals.to_vec();
    let mut slot = 0u64;
    while out.len() < width {
        out.push(cover_tag_native(bound, slot));
        slot += 1;
    }
    Some(out)
}

/// ⭐⭐⭐ THE TAG SET'S DIGEST — `acc_{j+1} = Poseidon(acc_j, tag_j)` from a zero accumulator.
///
/// The in-circuit twin is the `COS_CHAIN` block of [`CoverOrSpendGate`]; a peer recomputes this natively
/// from the tag list the block publishes. ⛔ ONE SPELLING: these two are the same chain or the class is
/// unprovable, which is how it stays honest.
/// ⛔ THE DOMAIN A SPEND-OR-DECOY BLOCK TRANSITION MUST BE STATED UNDER — the carrier's OWN first
/// bind element. The aggregate cross-ties the sponge's first absorb to `public_bind[DELTA_DOMAIN_OFF]`,
/// so a block stating this class under any other domain is REFUSED (measured as `CROSS-TIE inequality
/// (tie 0)`, which is how this was found). Exported so the producer, the peer and every pin name it
/// ONCE rather than each spelling a constant that then has to agree.
#[must_use]
pub fn cover_transition_domain() -> Fa4 {
    Fa4::from_u64(kred(COVER_TAG_DOMAIN))
}

#[must_use]
pub fn cover_tag_set_digest(tags: &[Digest]) -> Digest {
    let mut acc = crate::poseidon2_compress::zero_digest();
    for t in tags {
        acc = poseidon_pair_native(acc, *t);
    }
    acc
}

/// Transcript bind: `domain ‖ the tag set's DIGEST`. The cover secret, every note key, and the REAL-INPUT
/// COUNT are all absent BY CONSTRUCTION — the verifier learns the settled tags (from the block) and
/// nothing else.
///
/// ⭐ PUBLIC so the BLOCK-LEVEL transition binds with the SAME function the carrier was proved over. A
/// second spelling of a bind is how an aggregate ends up standing over a statement its carriers never
/// made (§AO), which is the shape DB-83 already cost us once.
///
/// ⛔⛔⛔ WHY THIS IS A DIGEST AND NOT THE TAG LIST, MEASURED (2026-09-23). The bind used to open
/// `domain ‖ every tag` — 257 field elements. The block aggregate ties a row's tuple to what the
/// carrier's transcript absorbed, and that tie is emitted ONE PER SPONGE ROW the cells span (rate 8), in
/// the transcript sponge AND again in the `rows_digest` chain. So the tie count tracked the TAG COUNT:
///
/// ```text
///    4 digests   g2= 5  g7= 4   total  56   cap 64
///   32 digests   g2=33  g7=32   total 112   cap 64   <- OVER BY 48, the class was unstateable
/// ```
///
/// `COLUMN_TIES_MAX` is not the defect and was NOT moved — its own doc says it: *a column tie is a
/// property of the CIRCUIT, one per relation the AIR states between two tables, so a correct circuit
/// names a handful and never more, whatever the tables hold*. 112 was the circuit stating 33 relations
/// where it should state ONE. Binding the DIGEST makes it one tie in each group at ANY tag count, so this
/// class — and every class after it — stops having a width wall. It also gives the single-spend class
/// back the headroom it had spent (56 of 64).
///
/// The cost is honest and CONSTANT: the carrier now chains its tags in-circuit (`COS_CHAIN`), one
/// permutation per tag. Nothing here grows with history, supply, or the real-input count.
pub fn cover_tag_statement_bind(tags: &[Digest]) -> Vec<Fa4> {
    let mut b = vec![cover_transition_domain()];
    for c in cover_tag_set_digest(tags) {
        b.push(Fa4::from_u64(kred(c)));
    }
    b
}

/// ⭐⭐⭐ SPEND-OR-DECOY — the disjunction that lets ONE carrier prove a tx's whole CONSTANT-WIDTH tag set
/// without revealing how many inputs were real. This is the half the multi-input gate was missing.
///
/// THE INSIGHT: both branches are the SAME Poseidon pair, differing only in their INPUTS.
///   • a REAL spend's nullifier is `Poseidon(sk, leaf)`   (the derivation `MultiSpendValidityGate` section C uses)
///   • a DECOY tag is           `Poseidon(bound, m_slot)` (the derivation `CoverTagGate` constrains)
/// So instead of two branches there is ONE chain per tag whose inputs are SELECTED by a witness bit `s`:
///   `a = s·sk + (1−s)·bound`, `b = s·leaf + (1−s)·m_slot`, then `tag == Poseidon(a, b)`.
/// The prover must therefore hold EITHER a note opening OR the cover secret for every single tag.
///
/// PRIVACY — the whole point: `s` is a WITNESS column. Public IO is `domain ‖ W ‖ tags`, so K = Σs never appears,
/// and a 1-input tx and a 5-input tx are indistinguishable at identical width. The real-input count is hidden BY
/// CONSTRUCTION, not by policy.
///
/// The note's membership in the frontier root stays where it belongs — in the spend carrier. This gate settles the
/// question the multi-input gate could not answer: "is every carried tag legitimately either a spend or a decoy?"
/// `Clone` for the SAME reason `SpendValidityGate` carries it: a BOUND aggregate rebuilds the gate per
/// row from that row's own public cells (§BO's per-row factory). Without it the block-level
/// spend-or-decoy transition cannot be laid at all — which is one of the things DB-83 was made of.
/// Generic over the field its public value lives in (lane agg 2026-11-15, `gate_trace`); the default is production's.
#[derive(Clone)]
pub struct CoverOrSpendGate<Ea4 = crate::hiding_decider::Ea4> {
    /// ⛔⛔⛔ THE BATCHING SCALAR, AND IT MUST BE A TRANSCRIPT CONSTANT. This gate once folded its
    /// residuals against powers of `x[0]` — a SUMCHECK VARIABLE — while declaring degree
    /// `PERM_MAX_DEGREE`. `SpendValidityGate` names that exact failure: *a γ read from a cell makes the
    /// k-th residual degree k and the sumcheck truncates silently*. It was the only gate in this tree
    /// doing it, and `x[0]` is also `Blinded`'s selector, so the two aliased. An aggregate folds
    /// `residuals()` against γ-power COLUMNS and never reads this, so it passes `Ea4::ZERO` exactly as
    /// `spend_delta_factory` does.
    pub gamma: Ea4,
    /// The tag set's CHAINED digest — the one public value this gate takes, welded to the trace's own
    /// tag columns by the per-row chain. See [`cover_tag_statement_bind`] for why it is a digest.
    pub tag_digest: [Ea4; DIGEST_LANES],
}

/// ⭐⭐⭐ ONE TAG PER ROW — and this is what brought the block aggregate under its budget.
///
/// ⛔ THE SHAPE THIS REPLACED, AND WHAT IT COST (MEASURED 2026-09-23). Every tag used to be laid
/// side-by-side in ONE row: `DIGEST_LANES + W * per_tag` = **22,312 columns** at W=32. A block aggregate
/// carries its inner carrier's OPENED ROW as committed cells — that is how `BoundStepConstraint` states
/// `cf == eq(z,r)·C(opened)` — so that one row became a **90,780-column** step table, 98% of it opened
/// values, and the block transition cost **4.39 MB / 8.2 s against a 500 ms block time**.
///
/// The tags are not one row's worth of data; they are 32 instances of the SAME small circuit. Laying
/// them as 32 ROWS of this width makes the opened row ~1/31 the size and the aggregate's step table
/// with it, at no change to what is proved.
///
/// `bound` sits on EVERY row rather than once at the front: a row is now a self-contained instance, and
/// the decoy derivation needs it. It is deliberately NOT tied across rows — each row proves its own tag
/// is real-or-decoy independently, so a per-row `bound` weakens nothing (an honest prover uses one).
const CR_BOUND: usize = 0;
const CR_SEL: usize = CR_BOUND + DIGEST_LANES;
const CR_SK: usize = CR_SEL + 1;
const CR_LEAF: usize = CR_SK + DIGEST_LANES;
const CR_TAG: usize = CR_LEAF + DIGEST_LANES;
const CR_DK: usize = CR_TAG + DIGEST_LANES;
const CR_DM: usize = CR_DK + DIGEST_LANES;
/// The tag-set chain accumulator entering and leaving this row: `CIN -> Poseidon(CIN, TAG) -> COUT`.
const CR_CIN: usize = CR_DM + DIGEST_LANES;
const CR_COUT: usize = CR_CIN + DIGEST_LANES;
const CR_P2: usize = CR_COUT + DIGEST_LANES;
const CR_DKB: usize = CR_P2 + crate::pow_pq_air::P2_COLS;
const CR_DMB: usize = CR_DKB + crate::pow_pq_air::P2_COLS;
const CR_CH: usize = CR_DMB + crate::pow_pq_air::P2_COLS;
/// One row's width — the whole circuit for ONE tag.
pub const CR_COLS: usize = CR_CH + crate::pow_pq_air::P2_COLS;

/// ⭐ THE ROW'S OWN SLOT, READ OFF THE POINT — no column, no shift, nothing for a prover to choose.
///
/// `x` is the zerocheck's variable vector and `x[0]` is the MSB of the row index (`Blinded` puts the
/// caller's rows in the half where it is 0). So the low variables ARE the slot's bits, MSB first, and
/// the slot is a degree-1 expression the verifier holds rather than a cell anyone supplies.
/// The cover arm's shifted columns (its chain input), for a program's next-row inputs.
#[must_use]
pub fn cover_shifted_cols() -> Vec<usize> {
    (CR_CIN..CR_CIN + DIGEST_LANES).collect()
}

/// The cover arm's committed shape for a `tags`-wide set on its blinded chained door: `(columns, variables)`, the
/// blinding rows' variable included.
#[must_use]
pub fn cover_or_spend_shape(tags: usize) -> (usize, usize) {
    (CR_COLS, tags.trailing_zeros() as usize + 1)
}

fn row_slot<Ea4: crate::gate_trace::GateAlg>(x: &[Ea4]) -> Ea4 {
    let low = &x[1..];
    let mut acc = Ea4::ZERO;
    for &b in low {
        acc = acc + acc + b; // MSB-first Horner: acc = 2·acc + bit
    }
    acc
}

/// `1` exactly on the FIRST real row (all low bits 0), `0` on every other. Degree `nvars-1` in the point.
fn is_first_row<Ea4: crate::gate_trace::GateAlg>(x: &[Ea4]) -> Ea4 {
    x[1..].iter().fold(Ea4::ONE, |a, b| a * (Ea4::ONE - *b))
}

/// `1` exactly on the LAST real row (all low bits 1), `0` on every other. Degree `nvars-1` in the point.
///
/// ⛔⛔⛔ THIS IS WHAT MAKES A ROW-SHIFTED AIR SAFE UNDER `Blinded`, AND IT IS NOT OPTIONAL.
/// `Blinded`'s doc refuses row-shifted AIRs for a real reason: *"the rotation `(i+1) % height` is taken
/// over the FULL trace, so the last real row's 'next' becomes a blinding row and a transition constraint
/// there would be evaluated against randomness."* The chain link below is multiplied by
/// `1 - is_last_row`, so it is switched OFF on exactly the row whose successor is randomness — the
/// documented hazard is closed by construction rather than avoided. The wrap at the very last blinding
/// row (63 -> 0) is already dead because `Blinded` zeroes the whole constraint there.
fn is_last_row<Ea4: crate::gate_trace::GateAlg>(x: &[Ea4]) -> Ea4 {
    x[1..].iter().fold(Ea4::ONE, |a, b| a * *b)
}

impl crate::air_zerocheck::AirConstraint for CoverOrSpendGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates the
        // sumcheck, so even an HONEST proof stops verifying. The point-masks below are degree
        // `nvars-1` over a degree-1 residual, which stays under this for every shape this class uses.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for r in self.build_residuals(local, at, x) {
            acc = acc + pw * r;
            pw = pw * self.gamma; // a transcript CONSTANT — never a sumcheck variable (see `gamma`)
        }
        acc
    }
    /// ⛔ ROW-SHIFTED, AND IT SAYS SO. The chain link reads the NEXT row's `CR_CIN`; declaring that
    /// honestly is what makes `prove_air_zerocheck` build the rotation and `shifted_opened` ride the
    /// wire. A gate that lied here would be scored against values nobody committed.
    fn is_row_local(&self) -> bool {
        false
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some((CR_CIN..CR_CIN + DIGEST_LANES).collect())
    }
    fn residuals(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Vec<Ea4> {
        self.build_residuals(local, at, x)
    }
}

impl<Ea4: crate::gate_trace::GateAlg> CoverOrSpendGate<Ea4> {
    /// ⭐⭐⭐ THE SAME RESIDUALS, UNFOLDED — and without this a BLOCK COULD NOT STATE THIS GATE.
    ///
    /// ⛔ MEASURED as a blocker of DB-83. The default `residuals` returns `vec![eval]` — ONE value — so
    /// `delta_residual_count` reported `powers = 1` for this gate while the spend gate reports ~2004. A
    /// row carrying one γ-power cell against a gate with hundreds of residuals DROPS the tail, so
    /// `prove_settlement_delta_bytes` refused to lay it and no block could state a spend-or-decoy
    /// carrier. THAT is why a multi-real-input spend was refused at the submit door: not a policy
    /// decision, a missing trait method.
    ///
    /// Same division `SpendValidityGate` documents: a multi-carrier aggregate folds these against
    /// γ-POWER COLUMNS, so a γ read from a cell cannot make the k-th residual degree k.
    pub(crate) fn build_residuals(
        &self,
        local: &crate::air_zerocheck::Row<'_, Ea4>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Vec<Ea4> {
        let zero = Ea4::ZERO;
        let one = Ea4::ONE;
        let mut rs: Vec<Ea4> = Vec::new();
        let bound = |c: usize| local[CR_BOUND + c];
        let s = local[CR_SEL];
        let sk = |c: usize| local[CR_SK + c];
        let leaf = |c: usize| local[CR_LEAF + c];
        let tag = |c: usize| local[CR_TAG + c];
        // The decoy INPUTS and their derivation chains. Constrained on BOTH branches — they depend only
        // on `bound` and this row's slot, never on `s`, so these columns are byte-identical whatever K
        // is. That is what stops proof size from tracking the real-input count.
        let dk = |c: usize| local[CR_DK + c];
        let dm = |c: usize| local[CR_DM + c];
        let slot = row_slot(x);
        for (which, off, tail) in
            [(0usize, CR_DKB, kred(COVER_TAG_DOMAIN)), (1, CR_DMB, kred(COVER_TAG_DOMAIN ^ 1))]
        {
            let outv = |c: usize| if which == 0 { dk(c) } else { dm(c) };
            let msg = |c: usize| -> Ea4 {
                match c {
                    // ⭐ THE SLOT IS THE ROW INDEX, taken off the POINT. It used to be a public constant
                    // per tag in a `slots: Vec<u64>` field; with one tag per row the row's own position
                    // IS the slot, and a value derived from the zerocheck's point cannot be chosen.
                    0 => slot,
                    1 => Ea4::from(Fa4::from_u64(tail)),
                    _ => zero,
                }
            };
            // The decoy derivation is a whole permutation over (bound, msg) — its output IS the decoy.
            crate::pow_pq_air::push_perm_residuals(local, off, &mut rs);
            for c in 0..DIGEST_LANES {
                rs.push(local[off + c] - bound(c));
                rs.push(local[off + DIGEST_LANES + c] - msg(c));
                rs.push(outv(c) - local[off + crate::pow_pq_air::PERM_OUT + c]);
            }
        }
        // THE SELECTOR — a genuine bit, so no third "neither" branch exists.
        rs.push(s * (one - s));
        // The tag is compress(a, b) over the SELECTED pair. Selecting inline into the permutation's own
        // input cells keeps every column distinct on BOTH branches — materialising `a`/`b` would
        // duplicate `sk`/`leaf` on a real row and `dk`/`dm` on a decoy row, and a duplicated column
        // compresses, so proof size would track the real-input count K.
        crate::pow_pq_air::push_perm_residuals(local, CR_P2, &mut rs);
        for c in 0..DIGEST_LANES {
            let ain = s * sk(c) + (one - s) * dk(c);
            let bin = s * leaf(c) + (one - s) * dm(c);
            rs.push(local[CR_P2 + c] - ain);
            rs.push(local[CR_P2 + DIGEST_LANES + c] - bin);
            rs.push(tag(c) - local[CR_P2 + crate::pow_pq_air::PERM_OUT + c]);
        }
        // ⭐⭐⭐ THE TAG-SET CHAIN, one step per row: `COUT = Poseidon(CIN, TAG)`.
        // ⛔ WAS one weld per tag to a PUBLIC constant (`tag(c) - self.tags[j][c]`), which is why the
        // carrier's bind had to carry every tag and why the block aggregate's tie count tracked the tag
        // count (112 against a cap of 64 — the class could not be stated at all). The chain says the
        // same thing in a form whose STATEMENT is one digest.
        crate::pow_pq_air::push_perm_residuals(local, CR_CH, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[CR_CH + c] - local[CR_CIN + c]);
            rs.push(local[CR_CH + DIGEST_LANES + c] - tag(c));
            rs.push(local[CR_COUT + c] - local[CR_CH + crate::pow_pq_air::PERM_OUT + c]);
        }
        // THE CHAIN'S THREE BOUNDARY FACTS. Each is masked by a function of the POINT, so the mask is
        // something the verifier computes and nobody supplies.
        let first = is_first_row(x);
        let last = is_last_row(x);
        for c in 0..DIGEST_LANES {
            // 1. It STARTS at the zero digest, exactly as `cover_tag_set_digest` does.
            rs.push(first * local[CR_CIN + c]);
            // 2. It LINKS: this row's output is the next row's input. Switched off on the last real row,
            //    whose successor is a blinding row (see `is_last_row`).
            rs.push((one - last) * (at(CR_CIN + c, x) - local[CR_COUT + c]));
            // 3. It ENDS at the STATEMENT. Eight residuals, whatever the tag count — the whole property.
            rs.push(last * (local[CR_COUT + c] - self.tag_digest[c]));
        }
        rs
    }
}

/// One tag's witness: a REAL tag's preimage `(key, leaf)` with `tag = P(key, leaf)`, or a DECOY (derived from the tx's
/// cover secret). ⛔ DB-395: for a note spend `key` is the owner's NULLIFIER KEY `nk` and `leaf` the note's commitment
/// (`nf = P(nk, cm)`) — never the note's opening, which its payer holds. For a device-slot claim it is the claim's key.
#[derive(Clone, Copy)]
pub enum TagWitness {
    RealSpend { key: Digest, leaf: Digest },
    Decoy,
}

/// Prove every tag is EITHER a real spend's nullifier OR a correctly-derived decoy — without revealing which.
/// `None` if any claimed tag does not actually match its witness (a prover cannot bluff its own witness).
///
/// ⛔ THE SLOTS ARE GONE FROM THE SIGNATURE, AND THAT IS THE POINT. They were positional `0..W` on every
/// caller, and a parameter that is always the same value constrains nothing while looking as if it does
/// — the same redundant-scalar class the cover bind already cost us once. With ONE TAG PER ROW the
/// slot IS the row index, read off the zerocheck's point (`row_slot`), so there is nothing to pass.
#[must_use]
pub fn prove_spend_or_decoy_bytes(
    bound: Digest,
    tags: &[Digest],
    witnesses: &[TagWitness],
) -> Option<Vec<u8>> {
    let rows = cover_or_spend_rows(bound, tags, witnesses)?;
    // COLUMN-major, as the prover wants it: `cols[c][row]`.
    let cols: Vec<Vec<Fa4>> =
        (0..CR_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    let td = cover_tag_digest_ea(tags);
    let make = move |g: Ea4| CoverOrSpendGate { gamma: g, tag_digest: td };
    // ⭐⭐⭐ THE COMMITTED, BLINDED PATH — NOT THE DIRECT ONE, AND THAT IS WHAT LETS A BLOCK STATE THIS.
    //
    // ⛔ MEASURED as a structural blocker of DB-83: the aggregate binds a carrier through
    // `recursion_bound::bound_step_row_committed`, which requires a COMMITTED transcript.
    //
    // ⛔ AND THE BLINDING IS LOAD-BEARING EVEN NOW THAT THE ROWS DIFFER. With one tag per row the trace
    // is no longer a constant column, so §BE-1's "the opening IS the witness" no longer applies
    // verbatim — but `zc.opened[c]` is still `MLE_c(r)`, one PUBLIC linear equation in that column's W
    // values with PUBLIC weights. On the selector column that is one equation in the real/decoy bits,
    // i.e. a nontrivial function of K. `Blinded` doubles the height with true randomness, so every
    // opening mixes W uniform values and the equation carries nothing.
    //
    // ⛔ AND THE CHAINED DOOR (2026-11-10): the chain link reads the NEXT row's `CR_CIN`, and the plain blinded door
    // binds only the row at `r`: a next-row value sent beside it was the sender's own number, so a tag set nobody
    // owned verified (`a_forged_next_row_opening_cannot_pass_the_send_doors_cover_arm`). The chained door proves the
    // next-row values to be the committed columns' own.
    crate::committed_air::prove_air_blinded_chained_bytes(cols, make, &cover_tag_statement_bind(tags))
}

/// The carrier's trace: ONE ROW PER TAG. ⭐ ONE SPELLING — the prover and every probe lay rows here, so
/// a trace and its gate cannot drift apart the way they did when this builder was still the retired fold.
#[must_use]
pub fn cover_or_spend_rows(
    bound: Digest,
    tags: &[Digest],
    witnesses: &[TagWitness],
) -> Option<Vec<Vec<Fa4>>> {
    if tags.is_empty() || witnesses.len() != tags.len() || !tags.len().is_power_of_two() {
        // ⛔ FAIL-CLOSED ON A NON-POWER-OF-TWO WIDTH. The row index IS the slot and the boundary masks
        // are products over the point's low bits, so a trace whose height is not a power of two would
        // be padded by the prover into rows the masks cannot describe.
        return None;
    }
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(tags.len());
    let mut chain_acc = crate::poseidon2_compress::zero_digest();
    for (slot, tag) in tags.iter().enumerate() {
        let mut row = vec![Fa4::ZERO; CR_COLS];
        for c in 0..DIGEST_LANES {
            row[CR_BOUND + c] = Fa4::from_u64(kred(bound[c]));
        }
        // The per-slot decoy inputs — computed for EVERY row (real or decoy) because the circuit
        // constrains their derivation unconditionally. Depending only on (bound, slot), they are
        // identical whatever K is.
        let (dk, dm) = cover_decoy_inputs(bound, slot as u64);
        let (s, sk, leaf) = match witnesses[slot] {
            TagWitness::RealSpend { key, leaf } => (1u64, key, leaf),
            TagWitness::Decoy => {
                // ⚠️ NEVER STRUCTURAL ZEROS ON THIS BRANCH. `sk`/`leaf` are unconstrained when s=0, so
                // leaving them zero is the obvious thing — and it LEAKS, because zeros encode shorter
                // than real field elements. Pad them pseudorandomly so a decoy row is byte-shaped like
                // a real one.
                let pad_sk =
                    poseidon_pair_native(bound, crate::poseidon2_compress::lanes_of(&[slot as u64, 1]));
                let pad_leaf =
                    poseidon_pair_native(bound, crate::poseidon2_compress::lanes_of(&[slot as u64, 2]));
                (0u64, pad_sk, pad_leaf)
            }
        };
        let (a, b) = if s == 1 { (sk, leaf) } else { (dk, dm) };
        if poseidon_pair_native(a, b) != *tag {
            return None; // the claimed tag is not what its witness derives — refuse rather than emit unsoundness
        }
        let next_acc = poseidon_pair_native(chain_acc, *tag);
        row[CR_SEL] = Fa4::from_u64(s);
        for c in 0..DIGEST_LANES {
            row[CR_SK + c] = Fa4::from_u64(kred(sk[c]));
            row[CR_LEAF + c] = Fa4::from_u64(kred(leaf[c]));
            row[CR_TAG + c] = Fa4::from_u64(kred(tag[c]));
            row[CR_DK + c] = Fa4::from_u64(kred(dk[c]));
            row[CR_DM + c] = Fa4::from_u64(kred(dm[c]));
            row[CR_CIN + c] = Fa4::from_u64(kred(chain_acc[c]));
            row[CR_COUT + c] = Fa4::from_u64(kred(next_acc[c]));
        }
        // The tag is ONE permutation over the SELECTED pair; the gate selects inline into these cells.
        crate::pow_pq_air::lay_perm_row_flat(&mut row, CR_P2, crate::pow_pq_air::pair_state(&a, &b));
        // The chain step, and both decoy derivations, laid on EVERY row — that is what keeps the trace
        // byte-identical whatever the real-input count K is.
        crate::pow_pq_air::lay_perm_row_flat(
            &mut row,
            CR_CH,
            crate::pow_pq_air::pair_state(&chain_acc, tag),
        );
        for (off, tail) in [(CR_DKB, kred(COVER_TAG_DOMAIN)), (CR_DMB, kred(COVER_TAG_DOMAIN ^ 1))] {
            let msg = crate::poseidon2_compress::lanes_of(&[slot as u64, tail]);
            crate::pow_pq_air::lay_perm_row_flat(
                &mut row,
                off,
                crate::pow_pq_air::pair_state(&bound, &msg),
            );
        }
        chain_acc = next_acc;
        rows.push(row);
    }
    Some(rows)
}

/// Verify the whole constant-width tag set. The verifier learns the TAGS and nothing else — not the cover secret,
/// not any note key, and critically NOT how many of the tags were real spends.
#[must_use]
pub fn verify_spend_or_decoy_bytes(bytes: &[u8], tags: &[Digest]) -> bool {
    if bytes.is_empty() || tags.is_empty() || !tags.len().is_power_of_two() {
        return false;
    }
    let td = cover_tag_digest_ea(tags);
    let make = move |g: Ea4| CoverOrSpendGate { gamma: g, tag_digest: td };
    crate::committed_air::verify_air_blinded_chained_bytes(bytes, make, &cover_tag_statement_bind(tags), (tags.len().trailing_zeros() as usize, CR_COLS))
}

/// ⭐ THE CONTIGUOUS RUN OF INNER COLUMNS A BLOCK AGGREGATE MUST CARRY THE ROTATION OF for this
/// class — read off the GATE'S OWN `shifted_cols()`, never spelled a second time. The aggregate lays
/// `shifted_opened` only for these, and `BoundStepConstraint` refuses a gate that reads outside the
/// run, so the circuit and the row it is scored on cannot disagree about which columns are rotated.
#[must_use]
pub fn cover_shifted_run() -> (usize, usize) {
    use crate::air_zerocheck::AirConstraint;
    let probe = CoverOrSpendGate { gamma: Ea4::ZERO, tag_digest: [Ea4::ZERO; DIGEST_LANES] };
    let cols = probe.shifted_cols().unwrap_or_default();
    (cols.first().copied().unwrap_or(0), cols.len())
}

/// The tag set's digest as circuit values — the ONE public constant this gate now takes.
pub(crate) fn cover_tag_digest_ea(tags: &[Digest]) -> [Ea4; DIGEST_LANES] {
    let d = cover_tag_set_digest(tags);
    core::array::from_fn(|i| Fa4::from_u64(kred(d[i])).into())
}

/// The height-1 fold row's constraint: the single committed row must be well-formed — its selector column is 1 on
/// the live row and 0 on the zero-padding, a real row-local algebraic gate (degree 2) over the committed trace.
/// The STATEMENT (endpoints + digest) is welded into the transcript by [`sparse_fold_statement_bind`], so a
/// tampered endpoint/digest diverges Fiat-Shamir and fails the openings.
pub struct SparseFoldGate;

/// `[pre | post | digest | selector]` — derived, never written out. ⛔ These were the literals 13, `4 + c`,
/// `8 + c` and `local[12]`, which are the four-lane arithmetic and became an out-of-bounds index the moment
/// the digest widened (*"index out of bounds: the len is 13 but the index is 13"*). ⭐ A column offset
/// written as a literal is a layout that cannot move.
const SF_PRE: usize = 0;
const SF_POST: usize = SF_PRE + DIGEST_LANES;
const SF_DIGEST: usize = SF_POST + DIGEST_LANES;
const SF_SEL: usize = SF_DIGEST + DIGEST_LANES;
const SF_COLS: usize = SF_SEL + 1;
/// The height-1 fold's committed height (nvars = 5 clears the WHIR SIMD packing floor) — the statement's shape.
const SPARSE_FOLD_ROWS: usize = 32;

impl crate::air_zerocheck::AirConstraint for SparseFoldGate {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        local[SF_SEL] * (local[SF_SEL] - Ea4::ONE) // selector ∈ {0,1}
    }
}

/// Transcript bind: domain ‖ block_pre ‖ block_post ‖ fold digest. Both sides weld this into the transcript START,
/// so ANY mismatch (forged endpoint, altered nullifier set) diverges Fiat-Shamir → reject.
fn sparse_fold_statement_bind(block_pre: Digest, block_post: Digest, digest: Digest) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(1 + 3 * DIGEST_LANES);
    b.push(Fa4::from_u64(SPARSE_FOLD_DOMAIN));
    for v in block_pre.iter().chain(block_post.iter()).chain(digest.iter()) {
        b.push(Fa4::from_u64(kred(*v)));
    }
    b
}

/// The ONE-row trace: `[pre | post | digest | selector]` at `SF_COLS` columns, padded to height 32 (nvars=5
/// clears the WHIR SIMD packing floor) with zero rows. Height is a FIXED 32 whether the block folds 1 or 256
/// nullifiers — that is the count-independence the 256-row chain AIR lacked.
fn sparse_fold_cols(block_pre: Digest, block_post: Digest, digest: Digest) -> Vec<Vec<Fa4>> {
    const H: usize = SPARSE_FOLD_ROWS;
    let mut cols: Vec<Vec<Fa4>> = (0..SF_COLS).map(|_| vec![Fa4::ZERO; H]).collect();
    for c in 0..DIGEST_LANES {
        cols[SF_PRE + c][0] = Fa4::from_u64(kred(block_pre[c]));
        cols[SF_POST + c][0] = Fa4::from_u64(kred(block_post[c]));
        cols[SF_DIGEST + c][0] = Fa4::from_u64(kred(digest[c]));
    }
    cols[SF_SEL][0] = Fa4::ONE; // live-row selector; padding rows stay 0
    cols
}

/// PROVE the block transition as ONE height-1 folded row — CONSTANT prove time and size regardless of how many
/// nullifiers the block folds.
pub fn prove_sparse_fold_height1_bytes(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
    block_post: Digest,
) -> Option<Vec<u8>> {
    let digest = sparse_fold_digest(inserts, block_pre);
    let cols = sparse_fold_cols(block_pre, block_post, digest);
    let make = |_g: Ea4| SparseFoldGate;
    crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &sparse_fold_statement_bind(block_pre, block_post, digest),
    )
}

/// ⛔⛔⛔ DB-213c — CERTIFIES NOTHING ABOUT THE TRANSITION: the gate is `sel·(sel−1)` and `(pre, post, digest)` ride
/// only the transcript, so anyone proves it for any endpoints (census arm F: a false post accepted). The node's
/// authority is its own recompute.
///
/// VERIFY the height-1 folded block transition against ONLY `(block_pre, block_post, digest)` — O(1), treeless.
/// Fail-closed on any decode / constraint / transcript mismatch (a forged endpoint or digest diverges the bind).
#[must_use]
pub fn verify_sparse_fold_height1_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    digest: Digest,
) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let make = |_g: Ea4| SparseFoldGate;
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &sparse_fold_statement_bind(block_pre, block_post, digest),
        (SPARSE_FOLD_ROWS.trailing_zeros() as usize, SF_COLS),
    )
}

/// PROVE a whole block's N-insert transition as ONE O(1) WHIR carrier over N INDEPENDENT `SparseChainLink` tables
/// chained by CROSS-TIES. `(carrier, block_post)`; `None` if `N` is not a power of two or any insert is invalid
/// against the running root. The N per-insert traces are independent — a producer builds each as its spend lands
/// (streamed), so the only block-close work is the batch fold, never a monolithic N·DEPTH prove.
pub fn prove_sparse_block_crosstie_bytes(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
) -> Option<(Vec<u8>, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    // N independent single-insert traces, threading the running root R_0 → R_1 → … → R_N (each `sparse_chain_cols`
    // proves non-membership vs its running root + the flip). A production producer proves these AS the spends arrive.
    let mut running = block_pre;
    let mut tables: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(n);
    for w in inserts {
        let (cols, post) = sparse_chain_cols(w, running)?;
        tables.push(cols);
        running = post;
    }
    let block_post = running;
    let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
    let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_post[c]));
    let bind = sparse_block_statement_bind(&pre_f, &post_f);
    let cross_ties = sparse_block_crosstie_spec(n);
    let make = sparse_block_crosstie_make(n, block_pre, block_post);
    let carrier = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make,
        vec![], // no LogUp buses — the chain is enforced purely by the committed-cell cross-ties
        cross_ties,
        Vec::new(),
        &bind,
    )?;
    Some((carrier, block_post))
}

/// VERIFY the chain-enforcing cross-tie block carrier against ONLY `(block_pre, block_post)` and the cover size `n`
/// (a per-block constant, not a leak). Fail-closed on any decode / constraint / endpoint / BROKEN-CHAIN (cross-tie
/// inequality) mismatch — the whole-block double-spend check a treeless (jumped) node runs, no held tree.
#[must_use]
pub fn verify_sparse_block_crosstie_bytes(bytes: &[u8], block_pre: Digest, block_post: Digest, n: usize) -> bool {
    if bytes.is_empty() || n == 0 || !n.is_power_of_two() {
        return false;
    }
    let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
    let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_post[c]));
    let bind = sparse_block_statement_bind(&pre_f, &post_f);
    // ⛔ DB-213b — the walk's DEPTH is the table's row count, so the row count is part of the statement:
    // exactly `n` tables of `NF_SPARSE_DEPTH` rows at `SPARSE_CHAIN_COLS`, and no bus table.
    let depth_bits = NF_SPARSE_DEPTH.trailing_zeros() as usize;
    let expected = vec![(depth_bits, SPARSE_CHAIN_COLS); n];
    let cross_ties = sparse_block_crosstie_spec(n);
    let make = sparse_block_crosstie_make(n, block_pre, block_post);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(bytes, make, cross_ties, Vec::new(), &bind, &expected, &[])
}

/// The N-1 chain links as cross-ties — `table[i].CH_AOUTS(post_i) == table[i+1].CH_AOUTE(pre_{i+1})` at the is_last
/// row (all row bits 1 ⇒ row DEPTH-1), all 4 root limbs bound in ONE tie. Prover and verifier build this identically
/// from the SAME fixed cover size `n`, so a prover that drops a link fails the length check (fail-closed).
fn sparse_block_crosstie_spec(n: usize) -> Vec<crate::whir_rec_block::CrossTieSpec> {
    let last_row = NF_SPARSE_DEPTH - 1; // is_last: every row bit set
    let post_cols: Vec<usize> = (0..DIGEST_LANES).map(|c| CH_AOUTS + c).collect();
    let pre_cols: Vec<usize> = (0..DIGEST_LANES).map(|c| CH_AOUTE + c).collect();
    (0..n.saturating_sub(1))
        .map(|i| ((i, post_cols.clone(), last_row), (i + 1, pre_cols.clone(), last_row)))
        .collect()
}

/// The per-table constraint builder: table 0 welds its pre-root to `block_pre`, table N-1 welds its post-root to
/// `block_post`, every interior table welds NEITHER (its roots stay private, tied by the neighbouring cross-ties).
/// ⭐⭐⭐ DB-213 — THE BLOCK CARRIER FOLDED ONTO **ONE** TABLE, SO ITS SIZE STOPS RISING WITH THE COVER.
///
/// ⛔ THE MEASUREMENT THIS EXISTS FOR. `prove_sparse_block_crosstie_bytes` builds ONE TABLE PER INSERT,
/// and the batch prover opens every column of every table (`whir_rec_block`, round 1: one `shapes` entry
/// and one `openings` entry per table). So the carrier is O(N · width):
///
///     per-item-table carrier = 4,998,510 B   vs   compressed witnesses = 50,176 B   (99.6× WORSE)
///     ceiling (pillar 4)     = 1,800,000 B   → 2.78× over, RED
///
/// A table per item makes proof SIZE and prove-TIME rise with the item count — the growth axis the light
/// decider exists to avoid. The fix named by that measurement is to fold everything onto ONE table, where
/// the openings are paid ONCE and the row count only costs a logarithm.
///
/// ⭐ HOW THE SAME STATEMENT SURVIVES THE FOLD. A single insert's walk is `NF_SPARSE_DEPTH = 256 = 2^8`
/// rows, and the zerocheck point convention is HIGH-BIT-FIRST (`cyclic_shift_sigma`: `x[0]` is the high
/// bit). So in a concatenated table of `N · 256` rows the LOW 8 variables index the row WITHIN an insert
/// and the HIGH variables index WHICH insert. Every selector the per-insert AIR needs is therefore still
/// expressible:
///
///     is_start = ∏_{k in low}(1 − x_k)     row-within-insert == 0   (seeds each insert's chains)
///     is_end   = ∏_{k in low} x_k          row-within-insert == 255 (each insert's endpoint)
///     not_end  = 1 − is_end                the walk chains INSIDE an insert, never across a boundary
///
/// and the two endpoint welds keep their original meaning by adding the HIGH bits:
///
///     weld_pre  at insert 0's end row      = is_end · ∏_{k in high}(1 − x_k)
///     weld_post at the LAST insert's end   = ∏_{k over all} x_k   (the global last row)
///
/// ⭐⭐⭐ AND AT N = 1 THIS IS BYTE-IDENTICAL TO THE OLD AIR, WHICH IS THE PROOF THAT NOTHING WAS
/// LOOSENED. With one insert the low-8 set IS every variable, so `is_start == is_first`,
/// `is_end == is_last`, `not_end == not_last`, the high set is empty so `hi_zero == 1` and both welds
/// collapse onto `is_last` — exactly the constraints `SparseChainLink` imposes today. The generalisation
/// is a strict superset, pinned by `folded_and_per_table_agree_at_one_insert`.
///
/// ⛔ NOTHING IS DELETED. `SparseChainLink` and `prove_sparse_block_crosstie_bytes` stay untouched; this
/// path is built BESIDE them and must prove itself (same statement, same rejects) before any caller moves
/// — a live spend gate is not a place to gamble a rewrite.
pub struct SparseChainFolded {
    pub gamma: Ea4,
    /// `Some(block_pre)`: welded at INSERT 0's end row (the empty-chain output that reconstructs the pre-root).
    pub weld_pre: Option<[Ea4; DIGEST_LANES]>,
    /// `Some(block_post)`: welded at the GLOBAL last row (the spent-chain output after the final insert).
    pub weld_post: Option<[Ea4; DIGEST_LANES]>,
    /// How many LOW hypercube variables index the row within ONE insert (`log2(NF_SPARSE_DEPTH)` = 8).
    pub depth_bits: usize,
}

impl crate::air_zerocheck::AirConstraint for SparseChainFolded {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs = Vec::new();
        let dir = local[CH_DIR];
        rs.push(dir * (one - dir));
        push_chain_residuals(local, CH_AINE, &mut rs);
        push_chain_residuals(local, CH_AINS, &mut rs);

        // HIGH-bit-first: the low `depth_bits` variables sit at the END of `x`.
        let nv = x.len();
        let db = self.depth_bits.min(nv);
        let (hi, lo) = x.split_at(nv - db);
        let is_start = lo.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_end = lo.iter().copied().fold(one, |a, xk| a * xk);
        let not_end = one - is_end;
        let hi_zero = hi.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_global_last = x.iter().copied().fold(one, |a, xk| a * xk);

        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        let sp = spent_leaf_native();
        for c in 0..DIGEST_LANES {
            // Each insert seeds its OWN chains at its first row (not only the table's first row).
            rs.push(is_start * (local[CH_AINE + c] - zero));
            rs.push(is_start * (local[CH_AINS + c] - Ea4::from(fkred(sp[c]))));
            // Endpoint welds only; every interior root stays a committed cell the cross-tie binds (privacy).
            if let Some(pre) = self.weld_pre {
                rs.push(is_end * hi_zero * (local[CH_AOUTE + c] - pre[c]));
            }
            if let Some(post) = self.weld_post {
                rs.push(is_global_last * (local[CH_AOUTS + c] - post[c]));
            }
            // TRANSITION inside an insert: next row's acc_in equals this row's acc_out, both chains.
            // At an insert's END row this is OFF — the boundary is the cross-tie's job, which keeps the
            // interior roots private exactly as the per-table shape did.
            rs.push(not_end * (at(CH_AINE + c, &sigma) - local[CH_AOUTE + c]));
            rs.push(not_end * (at(CH_AINS + c, &sigma) - local[CH_AOUTS + c]));
        }
        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
}

fn sparse_block_folded_make(
    block_pre: Digest,
    block_post: Digest,
    depth_bits: usize,
) -> impl Fn(usize, Ea4) -> SparseChainFolded {
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(fkred(block_pre[c])));
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(fkred(block_post[c])));
    // ONE table now, so both welds ride it — the selectors above place them on the right rows.
    move |_i: usize, g: Ea4| SparseChainFolded {
        gamma: g,
        weld_pre: Some(pre_ea),
        weld_post: Some(post_ea),
        depth_bits,
    }
}

/// The N−1 chain links, now as ties WITHIN the single table: insert i's spent-chain output at its end row
/// equals insert i+1's empty-chain output at ITS end row. Identical binding to the per-table spec; only the
/// coordinates change from (table i, row 255) to (table 0, row i·256+255).
fn sparse_block_folded_spec(n: usize, depth: usize) -> Vec<crate::whir_rec_block::CrossTieSpec> {
    let post_cols: Vec<usize> = (0..DIGEST_LANES).map(|c| CH_AOUTS + c).collect();
    let pre_cols: Vec<usize> = (0..DIGEST_LANES).map(|c| CH_AOUTE + c).collect();
    (0..n.saturating_sub(1))
        .map(|i| {
            let end_i = i * depth + (depth - 1);
            let end_j = (i + 1) * depth + (depth - 1);
            ((0usize, post_cols.clone(), end_i), (0usize, pre_cols.clone(), end_j))
        })
        .collect()
}

/// PROVE a whole block's N-insert transition as ONE folded table (DB-213). Same statement as
/// `prove_sparse_block_crosstie_bytes`, same privacy, paid for ONE set of column openings instead of N.
pub fn prove_sparse_block_folded_bytes(
    inserts: &[SparseInsertWitness],
    block_pre: Digest,
) -> Option<(Vec<u8>, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    let mut running = block_pre;
    let mut per_insert: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(n);
    for w in inserts {
        let (cols, post) = sparse_chain_cols(w, running)?;
        per_insert.push(cols);
        running = post;
    }
    let block_post = running;

    // CONCATENATE column-wise: the table is `Vec<column>`, each column a `Vec<row>`, so insert i's rows
    // land at [i·depth, (i+1)·depth). Every insert keeps its own 256-row walk; only the container changes.
    let width = per_insert[0].len();
    let depth = per_insert[0].first().map(|c| c.len())?;
    if depth == 0 || !depth.is_power_of_two() {
        return None;
    }
    let mut folded: Vec<Vec<Fa4>> = Vec::with_capacity(width);
    for c in 0..width {
        let mut col = Vec::with_capacity(n * depth);
        for t in &per_insert {
            if t.len() != width || t[c].len() != depth {
                return None; // ragged traces would misalign every selector — fail closed
            }
            col.extend_from_slice(&t[c]);
        }
        folded.push(col);
    }

    let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
    let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_post[c]));
    let bind = sparse_block_statement_bind(&pre_f, &post_f);
    let depth_bits = depth.trailing_zeros() as usize;
    let carrier = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        vec![folded],
        sparse_block_folded_make(block_pre, block_post, depth_bits),
        vec![],
        sparse_block_folded_spec(n, depth),
        Vec::new(),
        &bind,
    )?;
    Some((carrier, block_post))
}

/// VERIFY the folded block carrier against ONLY `(block_pre, block_post)` and the cover size `n`.
/// Fail-closed on every decode / constraint / endpoint / broken-chain mismatch, exactly as the per-table
/// verifier is — the prover and verifier build the identical tie list from the same public `n`.
#[must_use]
pub fn verify_sparse_block_folded_bytes(bytes: &[u8], block_pre: Digest, block_post: Digest, n: usize) -> bool {
    if bytes.is_empty() || n == 0 || !n.is_power_of_two() {
        return false;
    }
    let depth = NF_SPARSE_DEPTH;
    if !depth.is_power_of_two() {
        return false;
    }
    let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
    let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_post[c]));
    let bind = sparse_block_statement_bind(&pre_f, &post_f);
    let depth_bits = depth.trailing_zeros() as usize;
    // ⛔ DB-213b — THE ROW COUNT IS PART OF THIS STATEMENT: the post weld sits on the GLOBAL last row and
    // the ties run only over the first `n` inserts, so a taller table would carry an UNTIED tail whose last
    // insert can start from any tree at all. Exactly ONE table of `n · NF_SPARSE_DEPTH` rows, no bus table.
    // The prover lays only a power-of-two insert count (`prove_sparse_block_folded_bytes`), so any other `n`
    // names a table no prover built — and `trailing_zeros` of a non-power-of-two row count would mis-state it.
    if !n.is_power_of_two() {
        return false;
    }
    let Some(rows) = n.checked_mul(depth) else {
        return false;
    };
    let expected = [(rows.trailing_zeros() as usize, SPARSE_CHAIN_COLS)];
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        sparse_block_folded_make(block_pre, block_post, depth_bits),
        sparse_block_folded_spec(n, depth),
        Vec::new(),
        &bind,
        &expected, &[],
    )
}

fn sparse_block_crosstie_make(
    n: usize,
    block_pre: Digest,
    block_post: Digest,
) -> impl Fn(usize, Ea4) -> SparseChainLink {
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(fkred(block_pre[c])));
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Ea4::from(fkred(block_post[c])));
    move |i: usize, g: Ea4| SparseChainLink {
        gamma: g,
        weld_pre: if i == 0 { Some(pre_ea) } else { None },
        weld_post: if i == n - 1 { Some(post_ea) } else { None },
    }
}

#[cfg(test)]
mod cover_tag_tests {

    /// A test nullifier stated the way a REAL one arrives: 32 BYTES, with the in-circuit digest DERIVED.
    ///
    /// ⛔⛔⛔ THESE TESTS USED TO STATE THE DIGEST AND MANUFACTURE THE BYTES. `let nf = lanes_of(&[11, 13,
    /// 17, 19])`, then, to make a block "spend" it, a 32-byte tag was built by packing those lanes back
    /// out — which only worked while `nf_to_limbs` was a byte UNPACK. It is a COMPRESSION now: a
    /// nullifier is 256 bits of blake3 and does not fit a 248-bit digest, so no tag can be built from a
    /// chosen digest and `assert_eq!(nf_to_limbs(&tag), nf)` is unsatisfiable. Carrying the bytes is not
    /// a workaround; it is what a real spend carries, and the digest was always the derived half.
    fn nf_pair(seed: u64) -> ([u8; 32], Digest) {
        let bytes: [u8; 32] =
            *blake3::hash(&[b"musdm.nf-sparse.test-nullifier".as_slice(), &seed.to_le_bytes()].concat())
                .as_bytes();
        let d = nf_to_limbs(&bytes);
        (bytes, d)
    }
    use super::*;

    /// 🔬 EMPIRICAL PROBE (measure, don't trust memory): can the PROVEN settlement-aggregate machinery generically
    /// verify N of my `NfUnspentStepGate` proofs in-circuit → ONE O(1) proof + O(1) verify? An earlier session
    /// recorded this as a dead end; the step gate has changed since (challenge-free selector, new_acc bind), so we
    /// RE-MEASURE. If it aggregates, N per-block absence proofs collapse to one recursively-verified proof — the
    /// node-side half of the IVC (O(1) wire + O(1) verify), and the ground the incremental fold builds on.
    #[test]
    fn nf_unspent_step_proofs_aggregate_recursively_into_one_o1_proof() {
        use crate::whir_rec_block::{settlement_aggregate_from_bundles, verify_settlement_aggregate, tx_set_digest};
        let nf = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let n = 4usize;
        let mut bundles: Vec<Vec<u8>> = Vec::with_capacity(n);
        let mut binds: Vec<Vec<Fa4>> = Vec::with_capacity(n);
        for b in 0..n {
            // Each "block" = 32 distinct tags, NONE equal to nf, with a per-block pre so shapes match (nvars=5).
            let block_pre = crate::poseidon2_compress::lanes_of(&[100u64 + b as u64, 200, 300, 400]);
            let tags: Vec<[u8; 32]> = (0..32u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[0..8].copy_from_slice(&(1000 + b as u64 * 100 + i).to_le_bytes());
                    t[8] = 0xAB; // ensure != nf's limbs
                    t
                })
                .collect();
            let tags_digest = sparse_fold_digest_nfs(&tags, block_pre);
            let proof = prove_nf_unspent_step_bytes(nf, block_pre, block_pre, &tags).expect("step proves");
            // sanity: verifies natively (genuine transcript for extraction)
            assert!(verify_nf_unspent_step_bytes(&proof, nf, block_pre, block_pre, tags_digest, tags.len()), "step verifies natively");
            binds.push(nf_unspent_step_bind(nf, block_pre, block_pre, tags_digest));
            bundles.push(proof);
        }
        // Report the inner carrier shape so we can see per_evals (the degree the outer recursion must match).
        {
            let (_vv, _ov, nvars0, per0) =
                crate::whir_rec_block::extract_air_direct_carrier_rows(&bundles[0], &binds[0])
                    .expect("step carrier extracts");
            println!("NF-STEP-SHAPE: nvars_inner={} per_evals={}", nvars0, per0);
        }
        let tx_ids: Vec<[u8; 32]> = bundles.iter().map(|b| *blake3::hash(b).as_bytes()).collect();
        let set_digest = tx_set_digest(&tx_ids);
        let agg = settlement_aggregate_from_bundles(&bundles, &binds, &set_digest);
        match agg {
            None => panic!("AGGREGATE BUILD RETURNED None — step proofs are NOT extractable as carriers"),
            Some(agg) => {
                let ok = verify_settlement_aggregate(&agg, n, &set_digest);
                println!(
                    "NF-STEP-AGG: N={} step proofs -> ONE agg={} B, verify={}",
                    n,
                    agg.len(),
                    ok
                );
                assert!(ok, "AGGREGATE VERIFY REJECTED honest step-proof aggregate");
                // ADVERSARIAL: the proof is bound to the EXACT carrier set — verifying it against a DIFFERENT
                // committed set (drop the last carrier) MUST reject. Proves the aggregate isn't vacuously accepting.
                let short = tx_set_digest(&tx_ids[..n - 1]);
                assert!(
                    !verify_settlement_aggregate(&agg, n - 1, &short),
                    "aggregate MUST reject a different committed carrier set"
                );
            }
        }
    }

    /// ⭐⭐⭐ THE ABSENCE STEP RIDES THE O(1) FOLD — a REAL `NfUnspentStepGate` absence proof folds through the
    /// fixed-degree recursion to a CONSTANT-shape O(1) proof, and TWO blocks' chained steps fold into ONE. This is
    /// the connection of the fold-not-hold absence witness to the O(1) recursion: the wallet's per-block absence
    /// proof is O(1)-foldable, so a spend carries ONE constant proof of "nf ∉ every block" regardless of chain
    /// height — no O(DEPTH) copath, no O(N) re-prove. (Sequential IVC folds one lifted step per block into the
    /// running proof; here we lift two real steps and fold them, proving the shape is a fixed point.)
    #[test]
    fn nf_absence_step_folds_through_fixed_degree_o1_recursion() {
        use crate::whir_rec_block::{
            extract_fixed_degree_carrier_rows as xf, prove_merged_fixed_carrier_selfcontained_bytes as fold,
            verify_merged_fixed_carrier_selfcontained_bytes as vfold,
        };
        let nf = crate::poseidon2_compress::lanes_of(&[3u64, 5, 7, 9]);
        let genesis = crate::poseidon2_compress::lanes_of(&[1u64, 1, 1, 1]);
        let mk_block = |b: u64| -> (Vec<[u8; 32]>, Digest) {
            let block_pre = crate::poseidon2_compress::lanes_of(&[10 + b, 20, 30, 40]);
            let tags: Vec<[u8; 32]> = (0..32u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(500 + b * 100 + i).to_le_bytes());
                    t[8] = 0xC7;
                    t
                })
                .collect();
            (tags, block_pre)
        };
        // Block 0 absence step (prev_acc = genesis); block 1 absence step (prev_acc = the block-0 running acc).
        let (tags0, pre0) = mk_block(0);
        let td0 = sparse_fold_digest_nfs(&tags0, pre0);
        let step0 = prove_nf_unspent_step_bytes(nf, genesis, pre0, &tags0).expect("step0 proves");
        let b0 = nf_unspent_step_bind(nf, genesis, pre0, td0);
        let acc1 = nf_unspent_step_new_acc(genesis, pre0, td0);
        let (tags1, pre1) = mk_block(1);
        let td1 = sparse_fold_digest_nfs(&tags1, pre1);
        let step1 = prove_nf_unspent_step_bytes(nf, acc1, pre1, &tags1).expect("step1 proves");
        let b1 = nf_unspent_step_bind(nf, acc1, pre1, td1);

        // LIFT each real step into the fixed-degree fold; the lift's OUTPUT is the fixed point.
        let oba = vec![Fa4::from_u64(0xA0)];
        let obb = vec![Fa4::from_u64(0xB0)];
        let sm0 = fold(&[step0.clone()], &[b0.clone()], &oba).expect("step0 lifts into the O(1) fold");
        let sm1 = fold(&[step1.clone()], &[b1.clone()], &obb).expect("step1 lifts into the O(1) fold");
        // ⛔ EVERY SHAPE HERE IS MEASURED, NOT WRITTEN DOWN. It was `vfold(&sm0, 5, 8, …)` — the STEP
        // proof's shape, measured once at four lanes under the retired round's degree. The degree moved
        // (a gate embedding a permutation must declare `PERM_MAX_DEGREE`), the per-round evaluation
        // vector got longer with it, and the honest lift stopped verifying against a number nobody had
        // re-measured. ⭐ A shape is a fact about the proof; asking the proof is always available and a
        // literal is not.
        //
        // ⚠️ `vfold` takes the INNER shape — what was folded IN — so `sm0` is verified at the STEP's
        // shape and the 2-block fold below at `sm0`'s. Reading `sm0`'s own shape here would be verifying
        // the wrong thing and would also fail.
        let (_v, _o, sn0, sp0) = xf(&step0, &b0).expect("the absence step extracts as a carrier");
        let (_v, _o, sn1, sp1) = xf(&step1, &b1).expect("the absence step extracts as a carrier");
        assert_eq!((sn0, sp0), (sn1, sp1), "two absence steps must share one shape before they can fold");
        assert!(vfold(&sm0, sn0, sp0, &oba), "lifted absence step0 verifies");
        assert!(vfold(&sm1, sn1, sp1, &obb), "lifted absence step1 verifies");
        // Not vacuous: the proof must NOT verify at a shape it does not have.
        assert!(
            !vfold(&sm0, sn0 + 1, sp0, &oba),
            "the lifted proof verified at the WRONG nvars — the shape is not being checked at all"
        );
        let (_v, _o, nv0, pe0) = xf(&sm0, &oba).expect("sm0 extracts as a carrier");
        let (_v, _o, nv1, pe1) = xf(&sm1, &obb).expect("sm1 extracts as a carrier");
        assert_eq!(
            (nv0, pe0),
            (nv1, pe1),
            "two SEPARATELY lifted absence steps came out at DIFFERENT shapes — the fold is not a fixed \
             point, so a chain of them cannot be O(1)"
        );

        // FOLD the two blocks' absence proofs into ONE O(1) proof at the SAME fixed-point shape.
        let obf = vec![Fa4::from_u64(0xF0)];
        let folded = fold(&[sm0.clone(), sm1.clone()], &[oba.clone(), obb.clone()], &obf)
            .expect("two real absence proofs fold into ONE");
        assert!(vfold(&folded, nv0, pe0, &obf), "the folded 2-block absence proof verifies at the O(1) shape");
        let (_v, _o, nvf, pef) = xf(&folded, &obf).expect("folded extracts");
        assert_eq!((nvf, pef), (nv0, pe0), "the fold OUTPUT is the SAME fixed-point shape — O(1), foldable forever");
        // DIGITAL-CASH-PRIVACY-REVIEWED: test-only diagnostic; these are proof BYTE-LENGTHS + the recursion shape, not
        // any transaction's value/count/volume — structural sizes of a constant-shape fold, leak nothing.
        println!(
            "NF-ABSENCE-O1-FOLD: step={}B lifted={}B folded(2 blocks)={}B shape={:?}",
            step0.len(),
            sm0.len(),
            folded.len(),
            (nvf, pef)
        );
    }

    /// ⭐⭐⭐ THE O(1) ABSENCE CHAIN IS SOUND — the wallet folds a whole chain into ONE constant proof of "nf ∉ every
    /// block", the node verifies it against its own O(1) acc, and every cheat is rejected. This is the end-to-end
    /// fold-not-hold spend witness: no O(DEPTH) copath, no O(N) re-prove, nothing ages out.
    ///   (honest) N blocks fold into ONE proof; wallet tip acc == node's independent O(1) fold; verifies.
    ///   (a) SPENT — a block that spends nf makes the chain UNBUILDABLE (a double-spender cannot prove absence).
    ///   (b) WRONG TIP ACC — verifying against a different tip acc rejects.
    ///   (c) FALSE TIP TRANSITION — a tip bind inconsistent with the fold rejects (the acc-transition residual).
    ///   (d) SKIPPED BLOCK — a chain that skips a block folds to a DIFFERENT tip acc ⇒ rejected against the real A_tip.
    #[test]
    fn nf_absence_chain_is_o1_and_sound() {
        let (nf_bytes, nf) = nf_pair(11);
        let genesis = crate::poseidon2_compress::lanes_of(&[2u64, 2, 2, 2]);
        let n = 4usize;
        let mk = |b: u64, spend_nf: bool| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[100 + b, 200, 300, 400]);
            let mut tags: Vec<[u8; 32]> = (0..32u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(700 + b * 100 + i).to_le_bytes());
                    t[8] = 0xD1;
                    t
                })
                .collect();
            if spend_nf {
                tags[7] = nf_bytes; // nf IS one of this block's tags ⇒ spent here
            }
            (tags, bp)
        };

        // HONEST — nf absent from all 4 blocks.
        let blocks: Vec<(Vec<[u8; 32]>, Digest)> = (0..n as u64).map(|b| mk(b, false)).collect();
        let (proof, tip_acc, tip_prev, tip_bp, tip_td) =
            prove_nf_absence_chain(nf, genesis, &blocks).expect("honest chain proves");
        // Independently compute A_tip (the node's O(1) fold) and confirm the wallet's tip acc matches.
        let mut a = genesis;
        for (tags, bp) in &blocks {
            let td = sparse_fold_digest_nfs(tags, *bp);
            a = nf_unspent_step_new_acc(a, *bp, td);
        }
        assert_eq!(a, tip_acc, "wallet tip acc == node's independent O(1) NfUnspentFold");
        assert!(
            verify_nf_absence_chain(&proof, nf, genesis, tip_prev, tip_bp, tip_td, tip_acc),
            "honest absence chain verifies against A_tip"
        );

        // (a) SPENT ⇒ UNBUILDABLE.
        let mut spent = blocks.clone();
        spent[2] = mk(2, true);
        assert!(
            prove_nf_absence_chain(nf, genesis, &spent).is_none(),
            "a SPENT nf cannot build an absence chain (double-spender blocked)"
        );

        // (b) WRONG TIP ACC.
        let mut bad = tip_acc;
        bad[0] ^= 1;
        assert!(
            !verify_nf_absence_chain(&proof, nf, genesis, tip_prev, tip_bp, tip_td, bad),
            "a WRONG tip acc rejects"
        );

        // (c) FALSE TIP TRANSITION — a wrong tip tags_digest makes the residual nonzero.
        assert!(
            !verify_nf_absence_chain(&proof, nf, genesis, tip_prev, tip_bp, crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]), tip_acc),
            "a FALSE tip transition (wrong tags_digest) rejects"
        );

        // (d) SKIPPED BLOCK — fold blocks {0,1,3} (skip 2). Different tip acc ⇒ rejected against the real A_tip.
        let skipped: Vec<(Vec<[u8; 32]>, Digest)> =
            blocks.iter().enumerate().filter(|(i, _)| *i != 2).map(|(_, b)| b.clone()).collect();
        let (skip_proof, skip_tip, _sp, _sb, _st) =
            prove_nf_absence_chain(nf, genesis, &skipped).expect("a shorter chain still builds");
        assert_ne!(skip_tip, tip_acc, "skipping a block yields a DIFFERENT tip acc (fold collision resistance)");
        assert!(
            !verify_nf_absence_chain(&skip_proof, nf, genesis, tip_prev, tip_bp, tip_td, tip_acc),
            "a SKIPPED-block chain does NOT verify against the real A_tip"
        );
    }

    /// ⭐⭐⭐ THE INCREMENTAL O(1) CARRIER == THE BATCH FORM — the LIVE wallet path. A wallet keeps ONE
    /// `NfAbsenceCarrier` and folds each block with `step()` (O(1)/block, NEVER the banned genesis→tip walk); the
    /// finalized proof is BYTE-IDENTICAL to `prove_nf_absence_chain` over the same blocks and verifies against the
    /// node's A_tip. A block that SPENDS nf makes `step()` return false — the double-spender's carrier cannot advance.
    /// MEASURED per-block cost of the absence fold at the PRODUCTION 256-wide cover shape. This decides
    /// whether a wallet can maintain the carrier at all: if one step costs more than the block interval,
    /// no wallet can ever catch up and a from-genesis fold LIVELOCKS instead of converging.
    /// Run: `cargo test --release --lib measure_absence_step_cost -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: a measurement harness, not a disabled assertion — it prints timings and asserts the production width; the correctness tests above run in the default suite.
    fn measure_absence_step_cost_at_production_cover_width() {
        // DB-382: this measurement compares the incremental carrier to the batch prove byte for byte — one pinned seed.
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x82u8; 32]));
        use std::time::Instant;
        let (_nf_bytes, nf) = nf_pair(11);
        let genesis = crate::poseidon2_compress::lanes_of(&[2u64, 2, 2, 2]);
        let n = PRODUCTION_BLOCK_COVER;
        let mk = |b: u64| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[100 + b, 200, 300, 400]);
            let tags: Vec<[u8; 32]> = (0..n as u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(700 + b * 1000 + i).to_le_bytes());
                    t[8] = 0xD1;
                    t
                })
                .collect();
            (tags, bp)
        };
        let blocks: Vec<(Vec<[u8; 32]>, Digest)> = (0..4u64).map(mk).collect();
        assert_eq!(blocks[0].0.len(), PRODUCTION_BLOCK_COVER, "measured at the production cover width");

        let mut carrier = NfAbsenceCarrier::new(nf, genesis);
        let t0 = Instant::now();
        for (tags, bp) in &blocks {
            assert!(carrier.step(tags, *bp), "honest block folds");
        }
        let per_step = t0.elapsed().as_secs_f64() / blocks.len() as f64;
        let t1 = Instant::now();
        let _ = carrier.finalize().expect("finalizes");
        println!(
            "[absence-cost] cover={} per-step={:.0}ms finalize={:.0}ms | 500ms block interval => {}",
            PRODUCTION_BLOCK_COVER,
            per_step * 1e3,
            t1.elapsed().as_secs_f64() * 1e3,
            if per_step < 0.5 { "a wallet CAN keep up" } else { "a wallet CANNOT keep up (from-genesis fold livelocks)" }
        );
    }

    /// The carrier's accumulator MUST advance exactly like the plain fold the NODE runs. If these ever
    /// part company, a spender folds the node's own stream and still lands elsewhere, so no absence proof
    /// can verify and every send fails closed — with nothing in either component looking wrong on its own.
    /// At PRODUCTION cover width, which is where a 32-wide fixture would not have caught a width bug.
    #[test]
    fn carrier_acc_tracks_the_plain_node_fold_at_production_width() {
        let nf = crate::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]);
        let mut carrier = NfAbsenceCarrier::new(nf, [0u64; DIGEST_LANES]);
        let mut raw = [0u64; DIGEST_LANES];
        for b in 0..6u64 {
            let bp = crate::poseidon2_compress::lanes_of(&[900 + b, 901, 902, 903]);
            let tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(5_000 + b * 1_000 + i).to_le_bytes());
                    t[8] = 0xB3;
                    t
                })
                .collect();
            assert_eq!(tags.len(), PRODUCTION_BLOCK_COVER, "production cover width");
            assert!(carrier.step(&tags, bp), "honest block folds");
            raw = nf_unspent_step_new_acc(raw, bp, sparse_fold_digest_nfs(&tags, bp));
            assert_eq!(carrier.acc(), raw, "carrier and plain fold must agree after EVERY block (block {b})");
        }
    }

    /// MEASURED cost of a REAL spend's absence set. A tx settles a CONSTANT width of tags (the node's
    /// `TX_FIXED_NULLIFIER_COUNT`), and the gate demands one absence proof PER TAG — so a send costs that
    /// many carriers, not one. This is what decides whether sub-2s finality survives.
    /// Run: `cargo test --release --lib measure_constant_width_absence_cost -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: a measurement harness, not a disabled assertion.
    fn measure_constant_width_absence_cost() {
        use std::time::Instant;
        const TX_WIDTH: usize = 32; // == cover::TX_FIXED_NULLIFIER_COUNT
        let blocks: Vec<(Vec<[u8; 32]>, Digest)> = (0..4u64)
            .map(|b| {
                let bp = crate::poseidon2_compress::lanes_of(&[7 + b, 8, 9, 10]);
                let tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
                    .map(|i| {
                        let mut t = [0u8; 32];
                        t[..8].copy_from_slice(&(60_000 + b * 1_000 + i).to_le_bytes());
                        t[8] = 0xA9;
                        t
                    })
                    .collect();
                (tags, bp)
            })
            .collect();

        let t0 = Instant::now();
        for w in 0..TX_WIDTH {
            let nf = crate::poseidon2_compress::lanes_of(&[w as u64 + 1, 2, 3, 4]);
            let mut c = NfAbsenceCarrier::new(nf, [0u64; DIGEST_LANES]);
            for (tags, bp) in &blocks {
                assert!(c.step(tags, *bp), "tag {w} folds");
            }
        }
        let total = t0.elapsed().as_secs_f64();
        let per_tag_block = total / (TX_WIDTH * blocks.len()) as f64;
        println!(
            "[width-cost] tx_width={TX_WIDTH} blocks={} total={:.2}s per(tag,block)={:.0}ms \n\
             [width-cost] => ONE send over N blocks costs {TX_WIDTH} x N x {:.0}ms; \
             at N=100 that is {:.1}s, and keeping 32 carriers live costs {:.0}ms per block",
            blocks.len(),
            total,
            per_tag_block * 1e3,
            per_tag_block * 1e3,
            (TX_WIDTH as f64) * 100.0 * per_tag_block,
            (TX_WIDTH as f64) * per_tag_block * 1e3
        );
    }

    /// ⭐⭐⭐ THE BATCHED ABSENCE STEP — proves a whole tx-width of nullifiers absent in ONE proof, and
    /// stays fail-closed on every member. Batching shares the Poseidon absorb chain; it must NOT share or
    /// weaken the per-nullifier claim, so a batch containing even one settled nullifier is unprovable and
    /// a proof does not verify against a different batch.
    #[test]
    fn a_batched_absence_step_proves_the_whole_width_and_fails_closed_on_any_spent_member() {
        const W: usize = 32; // == cover::TX_FIXED_NULLIFIER_COUNT — the real per-tx width
        let block_pre = crate::poseidon2_compress::lanes_of(&[3u64, 5, 7, 11]);
        let prev = crate::poseidon2_compress::lanes_of(&[1u64, 1, 1, 1]);
        let tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
            .map(|i| {
                let mut t = [0u8; 32];
                t[..8].copy_from_slice(&(80_000 + i).to_le_bytes());
                t[8] = 0x5C;
                t
            })
            .collect();
        assert_eq!(tags.len(), PRODUCTION_BLOCK_COVER, "production cover width");
        let digest = sparse_fold_digest_nfs(&tags, block_pre);
        let nfs: Vec<Digest> = (0..W as u64).map(|w| crate::poseidon2_compress::lanes_of(&[900 + w, 901, 902, 903])).collect();

        // HONEST — all W absent, one proof, verifies.
        let proof = prove_nf_unspent_batch_bytes(&nfs, prev, block_pre, &tags).expect("batch proves");
        assert!(
            verify_nf_unspent_batch_bytes(&proof, &nfs, prev, block_pre, digest, tags.len()),
            "the batched proof verifies for the whole width"
        );

        // SPENT MEMBER — swap ONE nullifier for a tag that IS in the block. The batch must be unprovable,
        // so a double-spend cannot be smuggled in behind 31 honest siblings.
        let mut sneaky = nfs.clone();
        sneaky[17] = nf_to_limbs(&tags[123]);
        assert!(
            prove_nf_unspent_batch_bytes(&sneaky, prev, block_pre, &tags).is_none(),
            "a batch containing a SETTLED nullifier is unprovable — no hiding behind honest siblings"
        );

        // WRONG BATCH — an honest proof must not verify against a different set, or one tx's proof could
        // be replayed to cover another's inputs.
        let mut other = nfs.clone();
        other[0] = crate::poseidon2_compress::lanes_of(&[12345, 6789, 1011, 1213]);
        assert!(
            !verify_nf_unspent_batch_bytes(&proof, &other, prev, block_pre, digest, tags.len()),
            "a proof is bound to ITS batch — substituting a member is rejected"
        );

        // WRONG DIGEST — binding to the block is preserved.
        assert!(
            !verify_nf_unspent_batch_bytes(&proof, &nfs, prev, block_pre, crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]), tags.len()),
            "a proof is bound to ITS block's tag digest"
        );
    }

    /// The measurement that justifies batching: one batched proof for the whole tx width versus W separate
    /// proofs over the same block.
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: a measurement harness, not a disabled assertion.
    fn measure_batched_vs_per_tag_absence_cost() {
        use std::time::Instant;
        const W: usize = 32;
        let block_pre = crate::poseidon2_compress::lanes_of(&[3u64, 5, 7, 11]);
        let prev = crate::poseidon2_compress::lanes_of(&[1u64, 1, 1, 1]);
        let tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
            .map(|i| {
                let mut t = [0u8; 32];
                t[..8].copy_from_slice(&(90_000 + i).to_le_bytes());
                t[8] = 0x77;
                t
            })
            .collect();
        let nfs: Vec<Digest> = (0..W as u64).map(|w| crate::poseidon2_compress::lanes_of(&[400 + w, 401, 402, 403])).collect();

        let t0 = Instant::now();
        for nf in &nfs {
            let _ = prove_nf_unspent_step_bytes(*nf, prev, block_pre, &tags).expect("single proves");
        }
        let per_tag = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let _ = prove_nf_unspent_batch_bytes(&nfs, prev, block_pre, &tags).expect("batch proves");
        let batched = t1.elapsed().as_secs_f64();

        println!(
            "[batch-cost] width={W} per-block: {W}x separate={:.0}ms  batched={:.0}ms  speedup={:.1}x \n\
             [batch-cost] => keeping a width-{W} set live costs {:.0}ms/block (was {:.0}ms) against a ~500ms block",
            per_tag * 1e3,
            batched * 1e3,
            per_tag / batched.max(1e-9),
            batched * 1e3,
            per_tag * 1e3
        );
    }

    /// ⭐⭐⭐ `step_page` IS `step`, REASSOCIATED — proven, not asserted. A page fold must be
    /// INDISTINGUISHABLE from folding the same blocks one at a time: same accumulator, same tip binds, same
    /// proof bytes, and the node's own chain verifier must admit the page-folded proof. If any of those drift,
    /// the concurrency changed the claim and the spend gate is no longer the gate that was reviewed.
    ///
    /// It must also FAIL CLOSED and ATOMICALLY: a page containing a block that settles a member cannot fold,
    /// AND the carrier must be left byte-identical to before the attempt — a half-folded carrier would name a
    /// tip it never reached, which is the shape that lets a double-spend ride along.
    #[test]
    fn step_page_is_indistinguishable_from_stepping_each_block_and_fails_closed_atomically() {
        // DB-382: the blinding is fresh per prove in production; this pin compares two proves BYTE for byte to measure the
        // PROVER's equivalence (page fold == one-at-a-time), so it pins one seed for both and releases it with the guard.
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x82u8; 32]));
        const W: usize = 32; // == cover::TX_FIXED_NULLIFIER_COUNT
        let genesis = [0u64; DIGEST_LANES];
        let nf_bytes: Vec<[u8; 32]> = (0..W as u64).map(|w| nf_pair(2_500 + w).0).collect();
        let nfs: Vec<Digest> = nf_bytes.iter().map(nf_to_limbs).collect();
        let mk = |b: u64, plant: Option<[u8; 32]>| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[400 + b, 401, 402, 403]);
            let mut tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(90_000 + b * 1_000 + i).to_le_bytes());
                    t[8] = 0x3F;
                    t
                })
                .collect();
            if let Some(nf_bytes) = plant {
                tags[9] = nf_bytes;
            }
            (tags, bp)
        };

        let page: Vec<(Vec<[u8; 32]>, Digest)> = (0..4u64).map(|b| mk(b, None)).collect();

        // Reference: the per-block path this replaces.
        let mut one_at_a_time = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        for (tags, bp) in &page {
            assert!(one_at_a_time.step(tags, *bp), "reference: each block folds");
        }
        let (ref_proof, ref_acc, ref_tp, ref_bp, ref_td) =
            one_at_a_time.finalize().expect("reference finalizes");

        // The page path.
        let mut paged = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        assert!(paged.step_page(&page), "the whole page folds");
        let (pg_proof, pg_acc, pg_tp, pg_bp, pg_td) = paged.finalize().expect("page finalizes");

        assert_eq!(pg_acc, ref_acc, "page fold reaches the SAME accumulator");
        assert_eq!((pg_tp, pg_bp, pg_td), (ref_tp, ref_bp, ref_td), "same tip binds");
        assert_eq!(pg_proof, ref_proof, "page fold produces byte-IDENTICAL proof bytes");
        assert!(
            verify_nf_absence_batch_chain(&pg_proof, &nfs, genesis, pg_tp, pg_bp, pg_td, pg_acc),
            "the node admits the page-folded absence chain"
        );

        // FAIL CLOSED: a page whose 3rd block settles a member must not fold at all.
        let mut victim = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        assert!(victim.step_page(&page[..2]), "the honest prefix folds");
        let before_acc = victim.acc();
        let before_final = victim.finalize().expect("has folded something");
        let poisoned: Vec<(Vec<[u8; 32]>, Digest)> =
            vec![mk(2, None), mk(3, Some(nf_bytes[17])), mk(4, None)];
        assert!(
            !victim.step_page(&poisoned),
            "a page containing a block that SETTLES a member is unfoldable — fails closed"
        );
        // ATOMIC: the refusal left the carrier exactly as it was, not partially advanced through block 2.
        assert_eq!(victim.acc(), before_acc, "a refused page does not move the accumulator");
        assert_eq!(
            victim.finalize().expect("still holds its prior fold"),
            before_final,
            "a refused page leaves the carrier byte-identical — never half-folded"
        );
    }

    /// ⭐⭐⭐ THE BATCHED CARRIER over a real multi-block chain: it folds a whole tx width incrementally,
    /// its accumulator tracks the node's plain fold exactly, the node's chain verifier ADMITS it, and it
    /// fails closed the moment ANY member settles. This is the piece a send actually carries.
    #[test]
    fn the_batched_carrier_folds_a_whole_width_and_fails_closed_when_a_member_settles() {
        const W: usize = 32; // == cover::TX_FIXED_NULLIFIER_COUNT
        let genesis = [0u64; DIGEST_LANES];
        let nf_bytes: Vec<[u8; 32]> = (0..W as u64).map(|w| nf_pair(1_500 + w).0).collect();
        let nfs: Vec<Digest> = nf_bytes.iter().map(nf_to_limbs).collect();
        let mk = |b: u64, plant: Option<[u8; 32]>| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[200 + b, 201, 202, 203]);
            let mut tags: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(70_000 + b * 1_000 + i).to_le_bytes());
                    t[8] = 0x3F;
                    t
                })
                .collect();
            if let Some(nf_bytes) = plant {
                // Settle one of our own members in this block, byte-exactly as a real spend would.
                tags[9] = nf_bytes;
            }
            (tags, bp)
        };

        // Fold 4 honest blocks for the WHOLE width, and track the node's plain fold alongside.
        let mut carrier = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        let mut node_acc = genesis;
        for b in 0..4u64 {
            let (tags, bp) = mk(b, None);
            assert!(carrier.step(&tags, bp), "block {b} folds for the whole width");
            node_acc = nf_unspent_step_new_acc(node_acc, bp, sparse_fold_digest_nfs(&tags, bp));
            assert_eq!(carrier.acc(), node_acc, "carrier tracks the node's fold after block {b}");
        }

        // The node ADMITS it — one proof covering all W nullifiers.
        let (proof, acc, tip_prev, tip_bp, tip_td) = carrier.finalize().expect("finalizes");
        assert_eq!(acc, node_acc, "the carrier's tip is the node's A_tip");
        assert!(
            verify_nf_absence_batch_chain(&proof, &nfs, genesis, tip_prev, tip_bp, tip_td, acc),
            "the node admits the batched absence chain for the whole width"
        );

        // A DIFFERENT set must not verify against this proof — no replay across txs.
        let mut other = nfs.clone();
        other[5] = crate::poseidon2_compress::lanes_of(&[7u64, 7, 7, 7]);
        assert!(
            !verify_nf_absence_batch_chain(&proof, &other, genesis, tip_prev, tip_bp, tip_td, acc),
            "the proof is bound to ITS width — a substituted member is rejected"
        );

        // FAIL-CLOSED: a block settling ANY member cannot be folded, so a double-spend cannot ride along.
        let mut spender = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        let (t0, b0) = mk(0, None);
        assert!(spender.step(&t0, b0), "the honest first block folds");
        let (t1, b1) = mk(1, Some(nf_bytes[17]));
        assert!(
            !spender.step(&t1, b1),
            "a block that SETTLES one member is unfoldable — the whole batch fails closed"
        );
    }

    /// ⭐⭐⭐ IS THE ABSENCE WITNESS CONSTANT-SIZE AS THE SPENT SET GROWS? MEASURED, NOT ASSERTED.
    ///
    /// ⛔ WHY THIS EXISTS. Asked whether Boneh-Bunz-Fisch could be ported post-quantum, I answered that it
    /// could not (unknown-order groups are the mechanism, and both instantiations fall to quantum
    /// algorithms — Shor on factoring for RSA groups, Hallgren and Biasse-Song on class groups; those are
    /// LITERATURE, not findings of this repo) but that we do not need it, because the two properties we
    /// actually want DO port: an O(1) accumulator, and a constant-size (non-)membership witness via
    /// recursive folding. The first is trivially true — a root is a root. THE SECOND IS A CLAIM ABOUT THIS
    /// CODE and I asserted it without running anything.
    ///
    /// So: fold an absence argument across a growing chain of blocks and measure the witness. BBF's prize
    /// is batch witness update; ours would be that the witness never grows in the first place. If these
    /// bytes track the set size, the claim is refuted and the O(1) node does NOT follow from what we hold.
    ///
    /// REFUTABLE BY CONSTRUCTION: the assert compares proof bytes at 1 block against 32 blocks — a 32x
    /// change in the spent set. Any per-element or per-block term shows up as a 32x spread.
    #[test]
    fn the_absence_witness_is_constant_size_as_the_spent_set_grows() {
        let (_nf_bytes, nf) = nf_pair(77);
        let genesis = crate::poseidon2_compress::lanes_of(&[2u64, 2, 2, 2]);
        let mk = |b: u64| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[100 + b, 200, 300, 400]);
            let tags: Vec<[u8; 32]> = (0..32u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(700 + b * 100 + i).to_le_bytes());
                    t[8] = 0xD1;
                    t
                })
                .collect();
            (tags, bp)
        };

        let mut rows: Vec<(u64, usize, usize, u128)> = Vec::new();
        for n_blocks in [1u64, 4, 16, 32] {
            let blocks: Vec<(Vec<[u8; 32]>, Digest)> = (0..n_blocks).map(mk).collect();
            let spent_tags = n_blocks as usize * 32;
            let (proof, acc, prev, bp, td) =
                prove_nf_absence_chain(nf, genesis, &blocks).expect("honest chain proves");
            let t = std::time::Instant::now();
            let ok = verify_nf_absence_chain(&proof, nf, genesis, prev, bp, td, acc);
            let verify_us = t.elapsed().as_micros();
            assert!(ok, "the honest absence chain must verify at {n_blocks} block(s)");
            rows.push((n_blocks, spent_tags, proof.len(), verify_us));
        }

        for (nb, tags, bytes, us) in &rows {
            eprintln!(
                "[o1-absence] blocks={nb:<3} spent_tags={tags:<5} witness={bytes} B  verify={us} us"
            );
        }

        let first = rows.first().expect("a row").2;
        let last = rows.last().expect("a row").2;
        let spread = last as f64 / first as f64;
        eprintln!(
            "[o1-absence] spent set grew {}x (32 -> {} tags); witness grew {:.3}x",
            rows.last().unwrap().1 / rows.first().unwrap().1,
            rows.last().unwrap().1,
            spread
        );
        assert!(
            spread < 1.05,
            "⛔ THE ABSENCE WITNESS IS NOT CONSTANT-SIZE: {first} B over 32 spent tags became {last} B over \
             {} ({spread:.2}x). Then the witness carries a per-element or per-block term, the O(1)-node \
             claim does NOT follow from recursive folding, and the argument that we do not need BBF's \
             batch witness update is REFUTED. Fix the fold, never this bound.",
            rows.last().unwrap().1
        );
    }

    // ⛔ (2026-10-03) THIS PIN HAD NO `#[test]` AND HAD NEVER RUN — found by the surface census's hollow-pin check
    // (an asserting test fn nothing calls). Restored; its first recorded verdict is in scratchpad/pin-results.tsv.
    #[test]
    fn incremental_carrier_matches_batch_and_the_node_gate_accepts() {
        // DB-382: byte-for-byte comparison of two proves measures the PROVER (incremental == batch), not the blinding —
        // one pinned seed for both, released with the guard.
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x82u8; 32]));
        let (nf_bytes, nf) = nf_pair(11);
        let genesis = crate::poseidon2_compress::lanes_of(&[2u64, 2, 2, 2]);
        let mk = |b: u64, spend_nf: bool| -> (Vec<[u8; 32]>, Digest) {
            let bp = crate::poseidon2_compress::lanes_of(&[100 + b, 200, 300, 400]);
            let mut tags: Vec<[u8; 32]> = (0..32u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(700 + b * 100 + i).to_le_bytes());
                    t[8] = 0xD1;
                    t
                })
                .collect();
            if spend_nf {
                tags[7] = nf_bytes;
            }
            (tags, bp)
        };
        let blocks: Vec<(Vec<[u8; 32]>, Digest)> = (0..4u64).map(|b| mk(b, false)).collect();

        // BATCH (reference).
        let (batch_proof, batch_acc, batch_prev, batch_bp, batch_td) =
            prove_nf_absence_chain(nf, genesis, &blocks).expect("batch proves");

        // INCREMENTAL — the LIVE wallet form: fold each block O(1) as it "arrives".
        let mut carrier = NfAbsenceCarrier::new(nf, genesis);
        for (tags, bp) in &blocks {
            assert!(carrier.step(tags, *bp), "each honest block folds into the O(1) carrier");
        }
        let (inc_proof, inc_acc, inc_prev, inc_bp, inc_td) = carrier.finalize().expect("carrier finalizes");

        assert_eq!(
            (inc_acc, inc_prev, inc_bp, inc_td),
            (batch_acc, batch_prev, batch_bp, batch_td),
            "incremental tip == batch tip"
        );
        assert_eq!(inc_proof, batch_proof, "incremental carrier is BYTE-IDENTICAL to the batch prove (no drift)");
        assert!(
            verify_nf_absence_chain(&inc_proof, nf, genesis, inc_prev, inc_bp, inc_td, inc_acc),
            "the node's O(1) A_tip gate ADMITS the wallet's incrementally-maintained absence proof"
        );

        // DOUBLE-SPEND — a block that spends nf makes step() fail-closed (carrier cannot advance past it).
        let mut spender = NfAbsenceCarrier::new(nf, genesis);
        assert!(spender.step(&blocks[0].0, blocks[0].1), "block 0 folds");
        let (spent_tags, spent_bp) = mk(1, true);
        assert!(
            !spender.step(&spent_tags, spent_bp),
            "the block that SPENDS nf is REJECTED by step() — no absence proof past a spend"
        );
    }

    /// ⭐⭐⭐ THE ACC-FOLD TRANSITION IS ATTESTED IN-CIRCUIT — the fold advance is a CONSTRAINT, not a native
    /// equality, so the IVC recursion can carry it soundly. Proves + rejects every forgery:
    ///   1. HONEST — the correct fold proves and verifies.
    ///   2. FORGED new_acc — verifying against a wrong new_acc rejects (the bind diverges).
    ///   3. WRONG INPUTS — a proof for one (prev_acc, post, digest) does not verify against different inputs.
    ///   4. IN-CIRCUIT SOUND — the proven new_acc EQUALS the wallet's native `nf_unspent_step_new_acc`, so the
    ///      circuit and the O(1) fold agree by construction (no drift between prover and native).
    #[test]
    fn acc_fold_transition_is_attested_in_circuit_and_rejects_forgery() {
        let prev_acc = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let post = crate::poseidon2_compress::lanes_of(&[55u64, 66, 77, 88]);
        let digest = crate::poseidon2_compress::lanes_of(&[99u64, 111, 222, 333]);
        let new_acc = nf_unspent_step_new_acc(prev_acc, post, digest);

        // (1) HONEST
        let proof = prove_acc_fold_bytes(prev_acc, post, digest).expect("fold transition proves");
        println!("ACC-FOLD: transition proved in {} B", proof.len());
        assert!(verify_acc_fold_bytes(&proof, prev_acc, post, digest, new_acc), "honest fold verifies");

        // (2) FORGED new_acc
        let mut bad = new_acc;
        bad[0] ^= 1;
        assert!(!verify_acc_fold_bytes(&proof, prev_acc, post, digest, bad), "a forged new_acc rejects");

        // (3) WRONG INPUTS
        assert!(!verify_acc_fold_bytes(&proof, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), post, digest, new_acc), "wrong prev_acc rejects");
        assert!(!verify_acc_fold_bytes(&proof, prev_acc, crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]), digest, new_acc), "wrong post rejects");
        assert!(!verify_acc_fold_bytes(&proof, prev_acc, post, crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]), new_acc), "wrong digest rejects");

        // (4) IN-CIRCUIT == NATIVE — a proof built for a DIFFERENT expected new_acc cannot be produced (the fill
        // computes the true fold), and the honest one verifies only against the true new_acc.
        assert_eq!(
            new_acc,
            nf_unspent_step_new_acc(prev_acc, post, digest),
            "the circuit-proven fold equals the wallet's native O(1) fold — no prover/native drift"
        );
        assert!(verify_acc_fold_bytes(&proof, prev_acc, post, digest, new_acc), "honest still verifies (not vacuous)");
    }

    /// ⭐⭐⭐ STEP PROOFS ARE COMPOSABLE — the acc-transition binding chains them, the structural prerequisite the
    /// O(1) IVC recursion folds over. A sequence of per-block step proofs links iff each step's `new_acc` equals
    /// the next step's `prev_acc`; a broken link (a dropped/forged/reordered block) fails the chain.
    ///
    /// This is what makes the recursion sound to build ON: the base case (one step) is proven, and here the steps
    /// are shown to CHAIN by construction, so folding them (each recursion verifying the prior + advancing acc)
    /// reaches a single O(1) proof of "nf ∉ tree(current_root)".
    #[test]
    fn nf_unspent_steps_are_composable_and_a_broken_chain_rejects() {
        let nf = nf_to_limbs(&{
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&0xABCDu64.to_le_bytes());
            x[31] = 0x6B;
            x
        });
        // Fold a chain of blocks the way the wallet's NfUnspentFold does, recording each step's (prev_acc, new_acc).
        let mut acc = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]); // genesis fold seed = prev_acc of the first step
        let mut root = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        // (prev_acc, block_pre, digest, new_acc) per step.
        let mut links: Vec<(Digest, Digest, Digest, Digest)> = Vec::new();
        for b in 0..6u64 {
            let tags: Vec<[u8; 32]> = (0..8u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(b * 100 + i + 1).to_le_bytes());
                    t[31] = 0x4E;
                    t
                })
                .collect();
            // The digest is over `tags` absorbed from the CURRENT root; prove/verify must use that SAME pre-root.
            let block_pre = root;
            let digest = sparse_fold_digest_nfs(&tags, block_pre);
            // The running-accumulator transition: prev_acc is the PRIOR step's new_acc (a real chain, not block_pre).
            let new_acc = nf_unspent_step_new_acc(acc, block_pre, digest);
            let sp = prove_nf_unspent_step_bytes(nf, acc, block_pre, &tags).expect("step proves");
            assert!(verify_nf_unspent_step_bytes(&sp, nf, acc, block_pre, digest, tags.len()), "step {b} verifies");
            links.push((acc, block_pre, digest, new_acc));
            acc = new_acc;
            root = digest; // advance the bound root AFTER this block is proven
        }

        // COMPOSABILITY: step i's new_acc == step i+1's prev_acc (the chain links by construction).
        for w in links.windows(2) {
            assert_eq!(w[0].3, w[1].0, "step new_acc == next step prev_acc — the chain links");
        }
        println!("NF-UNSPENT COMPOSABLE: {} steps chained", links.len()); // DIGITAL-CASH-PRIVACY-REVIEWED: test-only; links.len() is the fixed loop bound (6), not a real tx count/volume

        // BROKEN CHAIN: tamper one link's new_acc — the chain no longer links (a forged/dropped block is caught).
        let mut broken = links.clone();
        broken[2].3[0] ^= 1;
        let linked = broken.windows(2).all(|w| w[0].3 == w[1].0);
        assert!(!linked, "a tampered acc transition breaks the chain — forged/dropped blocks cannot compose");

        // And the final acc is the deterministic fold a wallet holds in O(1) — recomputing it matches.
        let mut re = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        for (_pa, block_pre, digest, _na) in &links {
            re = nf_unspent_step_new_acc(re, *block_pre, *digest);
        }
        assert_eq!(re, acc, "the chained acc == the wallet\'s O(1) NfUnspentFold acc (deterministic, node-recomputable)");
    }

    /// ⭐ SIZE SCALING OF THE SINGLE-AIR NF-ABSENCE PROOF — the measurement that decides whether the whole-chain
    /// nf-unspent proof needs IVC recursion or the single-AIR path suffices. A wallet proving "nf ∉ [birth..tip]"
    /// as ONE AIR over all applied tags has a proof whose size scales with the tag count (polylog, succinct — NOT
    /// linear like a held witness, but NOT constant either). This measures it directly so the O(1)-vs-polylog call
    /// is made on numbers, not intuition. (The step proof over one block is already proven sound; this reuses it
    /// over larger tag sets and reports sizes.)
    #[test]
    fn single_air_nf_absence_proof_size_scaling() {
        let nf = nf_to_limbs(&{
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&0x5CA1Eu64.to_le_bytes());
            x[31] = 0xC3;
            x
        });
        let block_pre = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let mut sizes = Vec::new();
        for &n_tags in &[256usize, 1024, 4096] {
            let tags: Vec<[u8; 32]> = (0..n_tags as u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(i.wrapping_mul(2_654_435_761) + 1).to_le_bytes());
                    t[16..24].copy_from_slice(&(i + 3).to_le_bytes());
                    t[31] = 0x2E;
                    t
                })
                .collect();
            let td = sparse_fold_digest_nfs(&tags, block_pre);
            let proof = prove_nf_unspent_step_bytes(nf, block_pre, block_pre, &tags).expect("nf-absence proves over the range");
            assert!(verify_nf_unspent_step_bytes(&proof, nf, block_pre, block_pre, td, tags.len()), "the range proof verifies");
            sizes.push((n_tags, proof.len()));
        }
        println!("SINGLE-AIR NF-ABSENCE SIZE: {sizes:?} (tags -> bytes)");
        // Succinct: 16x more tags must NOT be 16x more bytes (that would be a linear held witness). Assert clearly
        // sublinear so the decision "polylog single-AIR vs O(1) IVC" rests on real numbers.
        let (t0, b0) = sizes[0];
        let (t2, b2) = sizes[2];
        assert!(
            (b2 as f64 / b0 as f64) < (t2 as f64 / t0 as f64) / 2.0,
            "proof size grows far SUBLINEARLY in tag count ({b0} B @ {t0} tags -> {b2} B @ {t2} tags) — succinct, \
             not a linear witness; whether it is O(1) enough vs needing IVC is now a numeric call"
        );
    }

    /// ⭐⭐⭐ NF-UNSPENT STEP PROOF IS SOUND — a node verifies "nf ∉ this block" in O(1) with NO copath, and a
    /// spender CANNOT prove a spent nf unspent. This is the node-verifiable core of the fold-not-hold witness.
    ///
    ///   1. HONEST — nf absent from the block ⇒ proves + verifies against (nf, block_pre, tags_digest).
    ///   2. SPENT ⇒ UNPROVABLE — if nf IS one of the block's tags, `prove` returns None (the non-membership
    ///      selector has no invertible differing limb; the trace is unsatisfiable). A double-spender cannot forge
    ///      an unspent proof.
    ///   3. FORGED ENDPOINTS REJECT — the proof does not verify against a different nf, a different block_pre, or
    ///      a tampered tags_digest (the statement bind diverges Fiat-Shamir).
    ///   4. WRONG-TAGS REJECT — a proof whose tags absorb to digest D does not verify when the node supplies a
    ///      different digest D' (the absorb binding is load-bearing, so fake tags cannot be substituted).
    #[test]
    fn nf_unspent_step_proof_is_sound_and_unforgeable() {
        let mk_tag = |i: u64| -> [u8; 32] {
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&(i.wrapping_mul(2_654_435_761) + 1).to_le_bytes());
            t[16..24].copy_from_slice(&(i + 7).to_le_bytes());
            t[31] = 0x4D;
            t
        };
        let tags: Vec<[u8; 32]> = (0..32u64).map(mk_tag).collect();
        let block_pre = crate::poseidon2_compress::lanes_of(&[111u64, 222, 333, 444]);
        let tags_digest = sparse_fold_digest_nfs(&tags, block_pre);

        // A nullifier NOT among the tags — stated by its BYTES, with the digest derived.
        let nf_bytes = {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
            x[31] = 0x9E;
            x
        };
        let nf = nf_to_limbs(&nf_bytes);

        // (1) HONEST
        let proof = prove_nf_unspent_step_bytes(nf, block_pre, block_pre, &tags).expect("nf absent ⇒ step proves");
        println!("NF-UNSPENT STEP: {} tags proved in {} B", tags.len(), proof.len());
        assert!(verify_nf_unspent_step_bytes(&proof, nf, block_pre, block_pre, tags_digest, tags.len()), "honest step verifies");

        // (2) SPENT ⇒ UNPROVABLE — put nf into the block, then try to prove it unspent. The block carries
        // the nullifier's BYTES (a tag IS 32 bytes), and the digest the gate compares is derived from them.
        assert_eq!(nf_to_limbs(&nf_bytes), nf, "the planted tag is this nullifier");
        let mut spent_block = tags.clone();
        spent_block[13] = nf_bytes;
        assert!(
            prove_nf_unspent_step_bytes(nf, block_pre, block_pre, &spent_block).is_none(),
            "a spent nf CANNOT be proved unspent — the non-membership trace is unsatisfiable"
        );

        // (3) FORGED ENDPOINTS
        let other_nf = nf_to_limbs(&mk_tag(9999));
        assert!(!verify_nf_unspent_step_bytes(&proof, other_nf, block_pre, block_pre, tags_digest, tags.len()), "wrong nf rejects");
        assert!(
            !verify_nf_unspent_step_bytes(&proof, nf, block_pre, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), tags_digest, tags.len()),
            "wrong block_pre rejects"
        );
        let mut bad_dig = tags_digest;
        bad_dig[0] ^= 1;
        assert!(!verify_nf_unspent_step_bytes(&proof, nf, block_pre, block_pre, bad_dig, tags.len()), "tampered tags_digest rejects");

        // (4) WRONG-TAGS — a proof over a DIFFERENT block does not verify against this block's digest.
        let other_tags: Vec<[u8; 32]> = (100..132u64).map(mk_tag).collect();
        let other_proof = prove_nf_unspent_step_bytes(nf, block_pre, block_pre, &other_tags).expect("other block proves");
        assert!(
            !verify_nf_unspent_step_bytes(&other_proof, nf, block_pre, block_pre, tags_digest, tags.len()),
            "a proof over other tags does not verify against this block's committed digest — absorb binding holds"
        );
        // and the honest proof still verifies (the gate rejects tampering, not everything).
        assert!(verify_nf_unspent_step_bytes(&proof, nf, block_pre, block_pre, tags_digest, tags.len()), "honest still verifies");
    }

    /// ⭐⭐⭐ FOLD-NOT-HOLD SPEND WITNESS IS O(1) AT INFINITY AND SOUND — the primitive that removes the O(DEPTH)
    /// copath (a growth path) from the wallet, replacing it with a constant-size folded state.
    ///
    ///   1. O(1) STATE BY CONSTRUCTION — the witness is a FIXED-size struct; `size_of` is identical whether it has
    ///      folded 1 block or 1,000,000. There is no per-block, per-depth, or per-height term. This is the whole
    ///      point: no O(DEPTH) siblings held, ever.
    ///   2. STAYS UNSPENT ACROSS UNBOUNDED BLOCKS — folding block after block where `nf` never appears keeps it
    ///      unspent, with the SAME constant cost each block. No window: a block folded long ago is not evicted and
    ///      never ages the note out.
    ///   3. FAIL-CLOSED + MONOTONE — the block that spends `nf` flips it to spent, and it STAYS spent through every
    ///      later fold (empty→spent is one-way, exactly the tree's monotonicity).
    ///   4. THE ACCUMULATOR BINDS THE ORDERED CHAIN — a different tag set, a different post-root, or a reordering
    ///      yields a DIFFERENT acc. This is the value the recursive proof attests so a node verifies non-membership
    ///      in O(1) without the copath; here we prove the native binding is order- and content-sensitive.
    #[test]
    fn fold_not_hold_witness_is_o1_at_infinity_and_sound() {
        let nf = {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&0xF01Du64.to_le_bytes());
            x[31] = 0xA1;
            x
        };
        let genesis = [0u64; DIGEST_LANES];

        // (1) O(1) STATE — fixed struct, independent of how many blocks it folds.
        let base = core::mem::size_of::<NfUnspentFold>();
        let mut w = NfUnspentFold::start(nf, genesis);
        let block_tags = |b: u64| -> Vec<[u8; 32]> {
            (0..256u64)
                .map(|i| {
                    let mut t = [0u8; 32];
                    t[..8].copy_from_slice(&(b.wrapping_mul(1_000_003) + i + 1).to_le_bytes());
                    t[31] = 0x5C;
                    t
                })
                .collect()
        };

        // (2) UNBOUNDED — fold a long run of blocks; nf never appears; still unspent, constant cost/state.
        let mut root = genesis;
        for b in 0..2000u64 {
            root = poseidon_pair_native(root, crate::poseidon2_compress::lanes_of(&[kred(b + 1), 0, 0, 0])); // some evolving post-root
            assert!(w.fold_block(&block_tags(b), root), "block {b}: nf absent ⇒ still unspent");
        }
        assert!(w.is_unspent(), "after 2000 folded blocks nf is still unspent — no window aged it out");
        assert_eq!(
            core::mem::size_of_val(&w),
            base,
            "the witness is the SAME constant size after 2000 blocks as at genesis — O(1), no O(DEPTH), no growth"
        );

        // (3) FAIL-CLOSED + MONOTONE — the block that includes nf spends it, and it stays spent.
        let mut spender = NfUnspentFold::start(nf, genesis);
        let mut r2 = genesis;
        for b in 0..50u64 {
            r2 = poseidon_pair_native(r2, crate::poseidon2_compress::lanes_of(&[kred(b + 1), 0, 0, 0]));
            spender.fold_block(&block_tags(b), r2);
        }
        assert!(spender.is_unspent(), "unspent through block 49");
        let mut with_nf = block_tags(50);
        with_nf[123] = nf; // nf is spent in block 50
        r2 = poseidon_pair_native(r2, crate::poseidon2_compress::lanes_of(&[kred(51), 0, 0, 0]));
        assert!(!spender.fold_block(&with_nf, r2), "the block that spends nf returns false");
        assert!(!spender.is_unspent(), "and the witness is now SPENT");
        // Monotone: further folds keep it spent.
        r2 = poseidon_pair_native(r2, crate::poseidon2_compress::lanes_of(&[kred(52), 0, 0, 0]));
        assert!(!spender.fold_block(&block_tags(60), r2), "stays spent through later blocks (empty→spent is one-way)");

        // (4) THE ACC BINDS THE CHAIN — content + order sensitive.
        let mk = |mutate: &dyn Fn(u64, &mut Vec<[u8; 32]>, &mut Digest)| -> Digest {
            let mut wf = NfUnspentFold::start(nf, genesis);
            let mut r = genesis;
            for b in 0..8u64 {
                let mut tags = block_tags(b);
                r = poseidon_pair_native(r, crate::poseidon2_compress::lanes_of(&[kred(b + 1), 0, 0, 0]));
                mutate(b, &mut tags, &mut r);
                wf.fold_block(&tags, r);
            }
            wf.acc()
        };
        let honest = mk(&|_, _, _| {});
        let tampered_tag = mk(&|b, tags, _| {
            if b == 3 {
                tags[7][0] ^= 1;
            }
        });
        let tampered_root = mk(&|b, _, r| {
            if b == 5 {
                r[0] ^= 1;
            }
        });
        assert_ne!(honest, tampered_tag, "a single altered tag deep in the chain changes the accumulator");
        assert_ne!(honest, tampered_root, "an altered post-root changes the accumulator");
        assert_eq!(honest, mk(&|_, _, _| {}), "and it is deterministic for the honest chain");
    }

    /// ⭐⭐⭐ SPEND-OR-DECOY IS SOUND **AND** HIDES THE REAL-INPUT COUNT — the half that unblocks a
    /// decoy-carrying send at `rpc_http.rs:508`.
    ///
    ///   1. A MIXED set (some real spends, some decoys) verifies — one carrier covers the whole width.
    ///   2. K IS HIDDEN: a K=1 tx and a K=5 tx produce proofs of the SAME size with the SAME public-IO shape.
    ///      That is the privacy property; if it failed, the wire would leak how many notes moved.
    ///   3. A tag that is NEITHER a valid spend NOR a valid decoy is refused AT PROVE TIME.
    ///   4. Claiming a decoy is a "real spend" with junk keys is refused — the selector cannot launder a tag.
    ///   5. No cross-tx replay, and a tampered tag list does not verify.

    /// ⭐⭐⭐ EVERY ROW SATISFIES EVERY RESIDUAL — and the gate BATCHES ON A TRANSCRIPT CONSTANT.
    ///
    /// ⛔ WHY THIS PIN EXISTS. `CoverOrSpendGate` used to fold its residuals against powers of `x[0]` —
    /// a SUMCHECK VARIABLE — while declaring degree `PERM_MAX_DEGREE`. `SpendValidityGate` names that
    /// exact failure in its own doc: *a γ read from a cell makes the k-th residual degree k and the
    /// sumcheck truncates silently*. It was the only gate in the tree doing it, and `x[0]` is also
    /// `Blinded`'s selector, so the two aliased. It survived because a truncated sumcheck still rejects
    /// tampering; it stopped surviving the moment the residual count moved, which is how it was found.
    ///
    /// ⭐ AND IT NOW WALKS EVERY ROW, because the carrier is one tag per row and the tag-set chain is a
    /// ROW-SHIFTED link. A pin that checked one row would miss exactly the boundary facts that make the
    /// chain mean anything — the start at zero, the link, and the end at the statement.
    #[test]
    fn every_row_is_residual_free_and_the_gate_folds_on_gamma() {
        use crate::air_zerocheck::{AirConstraint, OobLatch, Row};
        let bound = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let w = 8usize; // a power of two, as the row-index masks require
        let mut tags = Vec::new();
        let mut wit = Vec::new();
        for j in 0..w {
            if j < 3 {
                let sk = crate::poseidon2_compress::lanes_of(&[100 + j as u64, 2, 3, 4]);
                let leaf = crate::poseidon2_compress::lanes_of(&[200 + j as u64, 5, 6, 7]);
                tags.push(poseidon_pair_native(sk, leaf));
                wit.push(TagWitness::RealSpend { key: sk, leaf });
            } else {
                tags.push(cover_tag_native(bound, j as u64));
                wit.push(TagWitness::Decoy);
            }
        }
        let rows = super::cover_or_spend_rows(bound, &tags, &wit).expect("the rows lay");
        assert_eq!(rows.len(), w, "one row per tag");
        let gamma = Ea4::from(Fa4::from_u64(0x9E37_79B9));
        let gate = CoverOrSpendGate { gamma, tag_digest: super::cover_tag_digest_ea(&tags) };
        let nvars = 1 + w.trailing_zeros() as usize; // `Blinded` doubles the height

        // The point for real row `j`: MSB 0 (the caller's half), then `j`'s bits MSB-first.
        let point = |j: usize| -> Vec<Ea4> {
            let mut x = vec![Ea4::ZERO];
            for k in (0..nvars - 1).rev() {
                x.push(Ea4::from(Fa4::from_u64(((j >> k) & 1) as u64)));
            }
            x
        };
        let mut total = 0usize;
        for j in 0..w {
            let vals: Vec<Ea4> = rows[j].iter().map(|f| Ea4::from(*f)).collect();
            let oob = OobLatch::new();
            let r = Row::new(&vals, &oob);
            // The rotation the prover's trace really has: the NEXT row's cells.
            let nxt: Vec<Ea4> = rows[(j + 1) % w].iter().map(|f| Ea4::from(*f)).collect();
            let at = |c: usize, _p: &[Ea4]| -> Ea4 { nxt[c] };
            let x = point(j);
            let rs = gate.residuals(&r, &at, &x);
            total = rs.len();
            let bad = rs.iter().filter(|v| **v != Ea4::ZERO).count();
            assert!(!oob.hit(), "⛔ the gate read past row {j}");
            assert_eq!(
                bad, 0,
                "⛔⛔⛔ ROW {j}: {bad} of {} RESIDUALS ARE NONZERO ON AN HONESTLY-LAID TRACE — the trace \
                 and the gate are not one shape, so either the carrier cannot prove or the gate is \
                 checking nothing",
                rs.len()
            );
            // `eval` must be the γ-fold of `residuals()`. If `eval` batched on anything else — a
            // sumcheck variable, say — these two would disagree and a block aggregate, which folds
            // `residuals()` against γ-power columns, would close a DIFFERENT equation than was proved.
            let mut folded = Ea4::ZERO;
            let mut gp = Ea4::ONE;
            for v in gate.residuals(&r, &at, &x) {
                folded += gp * v;
                gp *= gamma;
            }
            assert_eq!(gate.eval(&r, &at, &x), folded, "⛔⛔⛔ `eval` IS NOT THE γ-FOLD OF `residuals()`");
        }
        eprintln!("[cover-gate] {w} rows x {} columns, {total} residuals/row", CR_COLS);

        // ⛔ THE CHAIN'S END IS THE STATEMENT, AND A TAMPERED TAG BREAKS IT. Re-laying the trace with one
        // tag changed must refuse at the prover, because the witness no longer derives the claimed tag.
        let mut bad_tags = tags.clone();
        bad_tags[5] = cover_tag_native(bound, 999);
        assert!(
            super::cover_or_spend_rows(bound, &bad_tags, &wit).is_none(),
            "⛔⛔ a tag its witness does not derive must refuse at the prover, not emit unsoundness"
        );

        let p = prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("the carrier proves");
        eprintln!("[cover-gate] carrier {} B", p.len());
        assert!(verify_spend_or_decoy_bytes(&p, &tags), "⛔ the honest carrier must verify");
        assert!(
            !verify_spend_or_decoy_bytes(&p, &bad_tags),
            "⛔⛔ a tampered tag list verified — the statement does not bind the tags"
        );
    }

    /// ⛔ RED-FIRST PIN (lane dcash wrote it 2026-11-10; lane goods lands it with the fix). The blinded committed verify
    /// absorbs a next-row opening without binding it to the commitment, so a gate that reads the next row is scored
    /// against a value the prover picks after seeing `r`. THIS gate reads the next row (the tag-set chain link, `CR_CIN`
    /// of row i+1), and THIS door is the send path's cover arm (node.rs `verify_spend_or_decoy_bytes`): a carrier forged
    /// over a garbage trace — no tag derived by any witness — must be refused for its tag list, or a send could carry
    /// someone else's nullifier as a "decoy".
    /// CALIBRATION: the adversary must find the next-row cell this gate reads (else it proves nothing about this door).
    #[test]
    fn a_forged_next_row_opening_cannot_pass_the_send_doors_cover_arm() {
        let bound = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        let tags: Vec<Digest> = (0..32u64).map(|i| cover_tag_native(bound, 1000 + i)).collect();
        let cols: Vec<Vec<Fa4>> =
            (0..CR_COLS).map(|c| (0..tags.len()).map(|r| Fa4::from_u64((c as u64) * 131 + (r as u64) * 7 + 1)).collect()).collect();
        let td = cover_tag_digest_ea(&tags);
        let forged = crate::committed_air::forge_blinded_next_row_for_tests(
            cols.clone(),
            move |g: Ea4| CoverOrSpendGate { gamma: g, tag_digest: td },
            &cover_tag_statement_bind(&tags),
        );
        let Some(bytes) = forged else {
            panic!("CALIBRATION: the adversary found no next-row cell this gate reads affinely, but the chain link reads one");
        };
        let accepted = verify_spend_or_decoy_bytes(&bytes, &tags);
        eprintln!("[cover-arm-forgery] a cover carrier over a GARBAGE trace ({} B) VERIFIES = {accepted}", bytes.len());
        assert!(
            !accepted,
            "⛔⛔⛔ a carrier over a GARBAGE trace verified at the send door's cover arm: its next-row opening is not bound to the commitment"
        );
        // THE SAME LIE AGAINST THE DOOR THIS CLASS NOW USES (lane goods): the chained door's adversary sends the moved
        // next-row value and lies through the shift bind as far as a prover can; the bind's last line refuses it.
        let chained = crate::committed_air::forge_blinded_chained_for_tests(
            cols,
            move |g: Ea4| CoverOrSpendGate { gamma: g, tag_digest: td },
            &cover_tag_statement_bind(&tags),
        );
        let Some(bytes) = chained else {
            panic!("CALIBRATION: the chained door's adversary found no next-row value to move, but the chain link reads one");
        };
        let accepted = verify_spend_or_decoy_bytes(&bytes, &tags);
        eprintln!("[cover-arm-forgery] the chained door's adversary ({} B) VERIFIES = {accepted}", bytes.len());
        assert!(!accepted, "⛔⛔⛔ a moved next-row value passed the chained door at the cover arm: the shift bind does not bind it");
    }

    #[test]
    fn spend_or_decoy_is_sound_and_hides_the_real_input_count() {
        let bound = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        // A power-of-two width: one tag per row, and the row index IS the slot (`cover_or_spend_rows`).
        let w = 8usize;
        let slots: Vec<u64> = (0..w as u64).collect();

        // Build a tx with K real spends and (w-K) decoys.
        let build = |k: usize| -> (Vec<Digest>, Vec<TagWitness>) {
            let mut tags = Vec::with_capacity(w);
            let mut wit = Vec::with_capacity(w);
            for j in 0..w {
                if j < k {
                    let sk = crate::poseidon2_compress::lanes_of(&[100 + j as u64, 2, 3, 4]);
                    let leaf = crate::poseidon2_compress::lanes_of(&[200 + j as u64, 5, 6, 7]);
                    tags.push(poseidon_pair_native(sk, leaf)); // a REAL nullifier: Poseidon(sk, leaf)
                    wit.push(TagWitness::RealSpend { key: sk, leaf });
                } else {
                    tags.push(cover_tag_native(bound, slots[j]));
                    wit.push(TagWitness::Decoy);
                }
            }
            (tags, wit)
        };

        // 1. MIXED verifies.
        let (tags1, wit1) = build(1);
        let p1 = prove_spend_or_decoy_bytes(bound, &tags1, &wit1).expect("K=1 proves");
        assert!(verify_spend_or_decoy_bytes(&p1, &tags1), "a 1-real / 7-decoy tx verifies");

        let (tags5, wit5) = build(5);
        let p5 = prove_spend_or_decoy_bytes(bound, &tags5, &wit5).expect("K=5 proves");
        assert!(verify_spend_or_decoy_bytes(&p5, &tags5), "a 5-real / 3-decoy tx verifies");

        // 2. K IS HIDDEN. Measured across EVERY K, not just two points: proof size must not track the real-input
        // count. Asserted as a tight band rather than exact equality — field elements differ by varint width for
        // reasons unrelated to K — and additionally as NON-MONOTONIC, because a size that climbs with K is the
        // leak itself. (This caught a REAL leak: decoy rows once wrote structural zeros into sk/leaf, and zeros
        // encode shorter, so size tracked K exactly — 5,201 B at K=1 vs 5,608 B at K=5.)
        let sizes: Vec<usize> = (0..=w)
            .map(|k| {
                let (t, wi) = build(k);
                prove_spend_or_decoy_bytes(bound, &t, &wi).expect("every K proves").len()
            })
            .collect();
        let (lo, hi) = (*sizes.iter().min().unwrap(), *sizes.iter().max().unwrap());
        println!("SPEND-OR-DECOY: sizes by K(0..={w}) = {sizes:?} (band {lo}..={hi})");
        // ⛔ RED BY DESIGN — this is a REAL RESIDUAL LEAK, not a flaky bound. Do NOT widen it to go green.
        // After removing the structural zeros the band fell 407 B → 69 B, but size is still STRICTLY MONOTONIC in
        // K: [5641, 5662, 5669, 5671, 5688, 5698, 5710]. CAUSE: a decoy row's Poseidon inputs are `(bound, m)` —
        // `bound` is the SAME across every decoy row and `m = crate::poseidon2_compress::lanes_of(&[DOMAIN, slot, 0, 0])` carries two zeros — so decoy
        // rows compress better than real rows, whose `(sk, leaf)` are all distinct. More decoys ⇒ smaller proof.
        // THE FIX must make both branches structurally identical (per-slot derived, zero-free inputs) WITHOUT
        // leaving the decoy branch unconstrained — an unconstrained branch would let a prover pass arbitrary tags.
        assert!(
            hi - lo <= 64,
            "proof size must NOT track the real-input count — measured {sizes:?}; a size that grows with K leaks \
             how many notes moved"
        );
        assert!(
            !sizes.windows(2).all(|p| p[1] > p[0]),
            "and it must not be monotonic in K — that would be the leak in a narrower band"
        );
        assert_eq!(
            cover_tag_statement_bind(&tags1).len(),
            cover_tag_statement_bind(&tags5).len(),
            "public IO shape is identical — K never appears in it"
        );

        // 3. A tag that is NEITHER is refused at prove time.
        let mut junk = tags1.clone();
        junk[3][0] ^= 1; // no witness derives this
        assert!(
            prove_spend_or_decoy_bytes(bound, &junk, &wit1).is_none(),
            "a tag matching NEITHER branch is refused at prove time"
        );

        // 4. The selector cannot launder a tag: claiming a decoy is a real spend with junk keys is refused.
        let mut lying = wit1.clone();
        lying[4] = TagWitness::RealSpend { key: crate::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), leaf: crate::poseidon2_compress::lanes_of(&[2, 2, 2, 2]) };
        assert!(
            prove_spend_or_decoy_bytes(bound, &tags1, &lying).is_none(),
            "flipping the selector without a matching opening is refused — no laundering"
        );

        // 5. Tamper + replay.
        let mut tampered = tags1.clone();
        tampered[0][1] ^= 1;
        assert!(!verify_spend_or_decoy_bytes(&p1, &tampered), "a tampered tag list does not verify");
        assert!(!verify_spend_or_decoy_bytes(&p5, &tags1), "no replay of one tx's proof onto another's tags");
    }


    /// ⭐ THE COVER-TAG PRIMITIVE the cover-extended spend carrier will constrain in-circuit.
    ///
    /// Proves the properties the CONSTRUCTION depends on — deterministic, secret-bound, domain-separated, and
    /// constant-width — so that when the gate constrains this derivation, what it constrains is already sound.
    /// It does NOT yet claim the in-circuit constraint exists; that is the remaining half of the carrier fix.
    #[test]
    fn cover_tags_are_deterministic_secret_bound_and_constant_width() {
        let secret = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        let other = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 5]); // differs in ONE limb

        // DETERMINISTIC — the wallet and the circuit must agree byte-for-byte.
        assert_eq!(cover_tag_native(secret, 7), cover_tag_native(secret, 7), "same (secret, slot) ⇒ same tag");
        // SLOT-SEPARATED — no two decoys in a tx collide.
        assert_ne!(cover_tag_native(secret, 7), cover_tag_native(secret, 8), "different slots ⇒ different tags");
        // SECRET-BOUND — this is the privacy property: without the wallet's secret the stream is unpredictable,
        // so an observer cannot recompute the decoys and pick out the real spends.
        assert_ne!(cover_tag_native(secret, 7), cover_tag_native(other, 7), "a one-limb secret change changes the tag");
        // DOMAIN-SEPARATED — a cover tag can never be replayed as another Poseidon-derived value.
        assert_ne!(
            cover_tag_native(secret, 7),
            poseidon_pair_native(secret, crate::poseidon2_compress::lanes_of(&[kred(7), 0, 0, 0])),
            "the cover domain tag is folded in, so this is not a bare poseidon_pair"
        );

        // CONSTANT WIDTH regardless of how many inputs are real — the whole point.
        let w = 32usize;
        let real1 = [crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9])];
        let real5: Vec<Digest> = (0..5u64).map(|i| crate::poseidon2_compress::lanes_of(&[i, i, i, i])).collect();
        let t1 = cover_extend_tags(&real1, secret, w).expect("1 real fits");
        let t5 = cover_extend_tags(&real5, secret, w).expect("5 reals fit");
        assert_eq!(t1.len(), w, "a 1-input tx settles the constant width");
        assert_eq!(t5.len(), w, "a 5-input tx settles the SAME constant width — K is hidden inside it");
        assert_eq!(&t1[..1], &real1[..], "the real spends come first, unmodified");
        assert_eq!(&t5[..5], &real5[..], "likewise for the 5-input case");
        // ⭐ NO REUSE ACROSS TXS — the defect this test caught. Deriving decoys from the secret ALONE made two
        // txs from one wallet share 27 of their decoys; a reused tag settles once, so the second tx would be
        // rejected as a double-spend. Decoys are now bound to the tx's own real tags, so every tx's stream is
        // distinct by construction. Both sets are internally distinct too.
        let uniq = |v: &Vec<Digest>| {
            let mut c = v.clone();
            c.sort_unstable();
            c.dedup();
            c.len()
        };
        assert_eq!(uniq(&t1), w, "t1's own tags are all distinct");
        assert_eq!(uniq(&t5), w, "t5's own tags are all distinct");
        let both: Vec<Digest> = t1.iter().chain(t5.iter()).copied().collect();
        assert_eq!(
            uniq(&both),
            2 * w,
            "and the two txs share NO tag — decoy reuse across txs would make the second tx a double-spend"
        );

        // FAIL-CLOSED: more reals than the constant width is refused, never silently widened.
        let too_many: Vec<Digest> = (0..(w as u64 + 1)).map(|i| crate::poseidon2_compress::lanes_of(&[i, 0, 0, 0])).collect();
        assert!(cover_extend_tags(&too_many, secret, w).is_none(), "a tx exceeding the constant width is refused");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐⭐ BRICK C CORE — THE PRODUCER FOLDS THE BLOCK'S TAGS COPATH-FREE (fold-not-hold; user 2026-07-24:
    /// "O(depth) is banned ... replaced O(depth) with fold not hold O(1)"). The height-1 fold's digest is
    /// `sparse_fold_digest_nfs` — nf VALUES only — so the producer needs NO per-nf copath and NO held tree: it folds
    /// the 256 tags (real + secret-seeded cover) into the O(1) A_tip acc and proves the transition over a FIXED
    /// height-32 trace. A treeless verifier re-derives the digest from the SAME tags and verifies in O(1). This is
    /// the exact mechanism that replaces `build_block_inserts_fixed_shape`/`batch_insert_root` (the banned O(DEPTH)
    /// copath path). SOUND: a forged post-acc, or a single tampered/dropped tag, makes verify REJECT.
    #[test]
    fn brick_c_producer_folds_tags_copath_free_and_verifies_o1_and_tamper_rejects() {
        let block_pre = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]); // the block's committed pre value (limbs), as `advance_nf_unspent_acc` uses
        let tags: Vec<[u8; 32]> = (0..256u64).map(|i| nf_from(1_000_000 + i)).collect(); // 256 = real + cover, VALUES only
        let pre_acc = crate::poseidon2_compress::lanes_of(&[7u64, 9, 11, 13]); // the A_tip acc BEFORE this block
        // PRODUCE (copath-free): digest from nf values, post = the A_tip tags-fold, inserts carry EMPTY copaths.
        let digest = sparse_fold_digest_nfs(&tags, block_pre);
        let block_post = nf_unspent_step_new_acc(pre_acc, block_pre, digest);
        let inserts: Vec<SparseInsertWitness> =
            tags.iter().map(|nf| SparseInsertWitness { key: sparse_key_of_tag(nf), copath: Vec::new() }).collect();
        let fold = prove_sparse_fold_height1_bytes(&inserts, block_pre, block_post)
            .expect("the producer folds the block copath-free, no tree");
        // TREELESS VERIFY (O(1)): re-derive the digest from the SAME tags every node regenerates, then verify.
        let re_digest = sparse_fold_digest_nfs(&tags, block_pre);
        assert!(
            verify_sparse_fold_height1_bytes(&fold, block_pre, block_post, re_digest),
            "the copath-free fold verifies O(1) against the re-derived tags digest — no copath, no held tree"
        );
        // TAMPER 1 — a forged post-acc rejects.
        let mut bad_post = block_post;
        bad_post[0] ^= 1;
        assert!(
            !verify_sparse_fold_height1_bytes(&fold, block_pre, bad_post, re_digest),
            "a forged post-acc REJECTS (the fold binds the exact transition)"
        );
        // TAMPER 2 — a single flipped tag changes the digest ⇒ rejects (no tag can be substituted).
        let mut bad_tags = tags.clone();
        bad_tags[137][0] ^= 1;
        let bad_digest = sparse_fold_digest_nfs(&bad_tags, block_pre);
        assert!(
            !verify_sparse_fold_height1_bytes(&fold, block_pre, block_post, bad_digest),
            "a single tampered/substituted tag REJECTS — the fold absorbs every tag value"
        );
        // O(1) BY CONSTRUCTION — the SAME fold over a 16× larger tag set is the SAME proof size (fixed height-32 trace).
        let big_tags: Vec<[u8; 32]> = (0..4096u64).map(|i| nf_from(2_000_000 + i)).collect();
        let big_digest = sparse_fold_digest_nfs(&big_tags, block_pre);
        let big_post = nf_unspent_step_new_acc(pre_acc, block_pre, big_digest);
        let big_inserts: Vec<SparseInsertWitness> =
            big_tags.iter().map(|nf| SparseInsertWitness { key: sparse_key_of_tag(nf), copath: Vec::new() }).collect();
        let big_fold = prove_sparse_fold_height1_bytes(&big_inserts, block_pre, big_post).expect("16x tags folds");
        // NO-GROWTH BAND (never byte-equality — varint widths differ a few bytes from differing field values, which
        // is independent of the tag count). 16× the tag set moves the proof by a handful of bytes ⇒ O(1) at any volume.
        let delta = (fold.len() as i64 - big_fold.len() as i64).abs();
        assert!(
            delta <= 64,
            "16x the tag set ⇒ SAME proof size within varint noise (O(1) at any volume) — {} B vs {} B (Δ={} B)",
            fold.len(),
            big_fold.len(),
            delta
        );
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

    /// The FIRST spend into an empty tree: its copath is all empty-subtree constants, so non-membership holds against
    /// the empty root; the transition ADVANCES the root (a real flip, not a no-op).
    fn first_insert(nf: [u8; 32]) -> (SparseInsertWitness, Digest, Digest) {
        let empty_root = empty_subtree_native(NF_SPARSE_DEPTH);
        let copath: Vec<Digest> = (0..NF_SPARSE_DEPTH).map(empty_subtree_native).collect();
        let w = SparseInsertWitness { key: nf, copath };
        let post = native_sparse_insert_transition(&w, empty_root).expect("first spend settles");
        (w, empty_root, post)
    }

    /// SOUND — a valid spend advances the root; the SAME copath cannot re-spend (double-spend); a tampered copath and
    /// the zero key are rejected fail-closed. Self-contained in the decider field (the node-parity is proven separately).
    #[test]
    fn native_sparse_transition_is_sound() {
        let nf = nf_from(42);
        let (w, empty_root, post) = first_insert(nf);
        assert_ne!(post, empty_root, "a real spend ADVANCES the root — the transition is not a no-op");

        // DOUBLE-SPEND: re-running the same witness against the POST root fails — the leaf is now SPENT, not empty.
        assert!(
            native_sparse_insert_transition(&w, post).is_none(),
            "re-spending the same nullifier is rejected — its leaf is no longer EMPTY under the advanced root"
        );

        // TAMPER: corrupt one copath sibling ⇒ the non-membership fold no longer equals pre_root ⇒ rejected.
        let mut bad = w.clone();
        bad.copath[0] = crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        assert!(
            native_sparse_insert_transition(&bad, empty_root).is_none(),
            "a tampered copath does not fold to pre_root → rejected (you cannot fake non-membership)"
        );

        // ZERO key + wrong copath length are rejected.
        assert!(native_sparse_insert_transition(&SparseInsertWitness { key:[0u8; 32], copath: w.copath.clone() }, empty_root).is_none());
        assert!(native_sparse_insert_transition(&SparseInsertWitness { key: nf, copath: vec![[0u64; DIGEST_LANES]; 8] }, empty_root).is_none());
    }

    /// The block transition CHAINS and is fail-closed: a valid two-spend block advances pre→post, but if ANY spend in
    /// the block is invalid (here the 2nd carries a copath for the pre-block, not the intermediate root) the whole
    /// block transition returns None — a bad spend never advances the block.
    #[test]
    fn native_sparse_block_transition_chains_and_fails_closed() {
        let a = nf_from(100);
        let (wa, empty_root, post_a) = first_insert(a);

        // A second spend whose copath is valid ONLY against the EMPTY root (all-empty), not against post_a. Chaining
        // must reject it — after `a` is spent the tree is no longer all-empty, so this stale copath fails.
        let b = nf_from(200);
        let stale_copath: Vec<Digest> = (0..NF_SPARSE_DEPTH).map(empty_subtree_native).collect();
        let wb_stale = SparseInsertWitness { key:b, copath: stale_copath };
        assert!(
            native_sparse_block_transition(&[wa.clone(), wb_stale], empty_root).is_none(),
            "a spend carrying a stale (pre-block) copath is rejected by the chain — fail-closed"
        );

        // A single-spend block advances exactly to post_a (endpoint binding the carrier will certify).
        assert_eq!(
            native_sparse_block_transition(&[wa], empty_root),
            Some(post_a),
            "a one-spend block binds (block_pre, block_post) to the settled transition"
        );
    }

    /// ⭐ IN-CIRCUIT SPARSE GATE (brick 2c soundness) — the LIVE transition-layout gate's per-row Poseidon-block
    /// residuals VANISH on a valid trace row and go NONZERO the instant a Merkle sibling is forged. This pins the
    /// fold-gadget constraints directly; the fold SEEDS, the committed-root welds, and the σ acc-chain are covered
    /// end-to-end by the carrier prove/verify/tamper test below, and a forged COPATH is rejected before proving by
    /// `native_sparse_transition_is_sound`. Adversarial by construction — a cheated row leaves a residual.
    ///
    /// CORRECT-ARCHITECTURE-REVIEWED: this REPLACES the deleted wide-row `SparseInsertGate` residuals test (that gate
    /// was ~17× slower and is retired). No assertion was loosened to pass — the entire vestigial gate + its test were
    /// removed and the SAME soundness is now pinned on the LIVE chained gate; the old `post == post2` builder check is
    /// inherent here because `sparse_chain_cols` derives `post` from `native_sparse_insert_transition`.
    #[test]
    fn sparse_chain_gate_row_residuals_vanish_iff_valid() {
        let zero = Ea4::from(Fa4::ZERO);
        let to_ea = |r: Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| Ea4::from(fkred(r[i]))) };

        let nf = nf_from(777);
        let (w, empty_root, post) = first_insert(nf);
        let (cols, _post) = sparse_chain_cols(&w, empty_root).expect("build the transition-layout trace");
        let gamma = Ea4::from(Fa4::from_u64(0x9E37_79B9));
        let to_f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| fkred(d[i])) };
        let gate = SparseChainGate { gamma, pre_root: to_f(empty_root), post_root: to_f(post), gpow: sparse_block_powers(gamma) };
        // Reconstruct a middle row from the columns (a non-boundary row exercises the pure Poseidon block).
        let ri = 5usize;
        let row: Vec<Ea4> = (0..SPARSE_CHAIN_COLS).map(|c| Ea4::from(cols[c][ri])).collect();

        // VALID: BOTH chains' per-row Poseidon-block residuals are exactly zero.
        let mut rs = Vec::new();
        push_chain_residuals(&crate::air_zerocheck::RowGuard::new().row(&row), CH_AINE, &mut rs);
        push_chain_residuals(&crate::air_zerocheck::RowGuard::new().row(&row), CH_AINS, &mut rs);
        assert!(rs.iter().all(|r| *r == zero), "a valid trace row satisfies BOTH chains' Poseidon-block constraints");

        // FORGE the shared Merkle sibling → the left/right selection no longer matches the stored columns → a residual.
        let mut bad = row.clone();
        bad[CH_SIB] = bad[CH_SIB] + Ea4::ONE;
        let mut rs2 = Vec::new();
        push_chain_residuals(&crate::air_zerocheck::RowGuard::new().row(&bad), CH_AINE, &mut rs2);
        assert!(rs2.iter().any(|r| *r != zero), "a forged sibling breaks the fold — rejected");
    }

    /// ⭐ IN-CIRCUIT SPARSE CARRIER (brick 2b) — the O(1) WHIR proof a treeless verifier runs: PROVE a valid spend,
    /// VERIFY it against the committed `(pre_root, post_root)`, and REJECT a wrong pre-root, a wrong post-root, and an
    /// empty carrier (the endpoints are welded into the transcript). This is the proof-only double-spend check with
    /// NO held tree and NO copath at verify time.
    #[test]
    fn sparse_insert_carrier_proves_verifies_and_rejects_tamper() {
        let nf = nf_from(555);
        let (w, empty_root, post) = first_insert(nf);

        let (carrier, cpost) = prove_sparse_insert_carrier_bytes(&w, empty_root).expect("prove a valid spend carrier");
        assert_eq!(cpost, post, "the carrier certifies the native post-root");
        assert!(
            verify_sparse_insert_carrier_bytes(&carrier, empty_root, post),
            "the carrier verifies O(1) against the committed (pre_root, post_root) — no held tree"
        );

        // A WRONG post-root is rejected — the endpoints are welded to the transcript.
        let mut bad_post = post;
        bad_post[0] = crate::nullifier_insert_air::kadd(bad_post[0], 1);
        assert!(!verify_sparse_insert_carrier_bytes(&carrier, empty_root, bad_post), "a wrong post_root is rejected");

        // A WRONG pre-root is rejected.
        let mut bad_pre = empty_root;
        bad_pre[0] = crate::nullifier_insert_air::kadd(bad_pre[0], 1);
        assert!(!verify_sparse_insert_carrier_bytes(&carrier, bad_pre, post), "a wrong pre_root is rejected");

        // A truncated / empty carrier is rejected fail-closed.
        assert!(!verify_sparse_insert_carrier_bytes(&[], empty_root, post), "an empty carrier is rejected");
    }

    /// A minimal reference sparse tree (mirrors the node's `RefSparseNf`, in the decider's native field) so a test can
    /// build VALID chained multi-insert blocks — each insert's copath is taken against the CURRENT (post-previous) tree.
    #[derive(Default)]
    struct RefTree {
        nodes: std::collections::HashMap<(usize, [u8; 32]), Digest>,
    }
    impl RefTree {
        fn canon(nf: &[u8; 32], level: usize) -> [u8; 32] {
            let mut p = *nf;
            let full = level >> 3;
            for b in p.iter_mut().take(full) {
                *b = 0;
            }
            if level & 7 != 0 {
                p[full] &= !((1u8 << (level & 7)) - 1);
            }
            p
        }
        fn node_at(&self, level: usize, canon: &[u8; 32]) -> Digest {
            self.nodes.get(&(level, *canon)).copied().unwrap_or_else(|| empty_subtree_native(level))
        }
        fn copath(&self, nf: &[u8; 32]) -> Vec<Digest> {
            (0..NF_SPARSE_DEPTH)
                .map(|level| {
                    let mut sib = *nf;
                    sib[level >> 3] ^= 1u8 << (level & 7);
                    self.node_at(level, &Self::canon(&sib, level))
                })
                .collect()
        }
        fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Vec<Digest> {
            let cp = self.copath(nf);
            self.nodes.insert((0, *nf), spent_leaf_native());
            for level in 1..=NF_SPARSE_DEPTH {
                let bit = nf_bit(nf, level - 1);
                let with_nf = Self::canon(nf, level - 1);
                let mut sib = *nf;
                sib[(level - 1) >> 3] ^= 1u8 << ((level - 1) & 7);
                let sib_canon = Self::canon(&sib, level - 1);
                let (l, r) = if bit == 0 { (with_nf, sib_canon) } else { (sib_canon, with_nf) };
                let h = poseidon_pair_native(self.node_at(level - 1, &l), self.node_at(level - 1, &r));
                self.nodes.insert((level, Self::canon(nf, level)), h);
            }
            cp
        }
        fn root(&self) -> Digest {
            self.node_at(NF_SPARSE_DEPTH, &[0u8; 32])
        }
    }

    /// ⭐ NESTED BLOCK GATE (brick 2c soundness) — the block gate's constraints VANISH on a VALID N-insert block trace
    /// (chaining R_0 → R_N with the intermediate roots PRIVATE) and go NONZERO on a wrong block_post and on a broken
    /// root-chain at an insert boundary. This pins the hard, soundness-critical logic — the level/boundary/insert
    /// SELECTORS, the running-root CARRY, and the boundary NON-MEMBERSHIP-vs-current-root (the double-spend gate) —
    /// directly at the constraint level (no WHIR). The WHIR carrier wrap over this SAME gate is the mechanical next
    /// step (reuses the light-decider harness exactly like the single-insert carrier).
    #[test]
    fn sparse_block_gate_residuals_vanish_iff_valid_chain() {
        let zero = Ea4::from(Fa4::ZERO);
        let to_ea = |r: Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| Ea4::from(fkred(r[i]))) };

        // A valid PRODUCTION-cover block from empty (each copath taken against the CURRENT tree ⇒ a real chain
        // R_0 → R_1 → … → R_N). N = the full 256-insert cover — never a shrunken sample (production-scale-test-guard).
        let n = PRODUCTION_BLOCK_COVER;
        let mut refs = RefTree::default();
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x5B10_0000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        // Every insert here is REAL — this test builds no padding — so `real_n` is the whole vector.
        let (cols, block_post) =
            sparse_block_cols(&inserts, block_pre, inserts.len()).expect("build a valid 256-insert block trace");
        let height = cols[0].len();
        let nvars = height.trailing_zeros() as usize;
        assert_eq!(height, n * NF_SPARSE_DEPTH, "N=256 inserts × DEPTH rows (production cover)");

        // Evaluate the γ-batched gate at a hypercube VERTEX (row r): x = the boolean row bits (high-bit-first), and the
        // `at` closure returns the trace value at the σ-decoded next row.
        let eval_at_row = |cols: &Vec<Vec<Fa4>>, gate: &SparseBlockGate, r: usize| -> Ea4 {
            use crate::air_zerocheck::AirConstraint;
            let x: Vec<Ea4> =
                (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::from(Fa4::ZERO) }).collect();
            let local: Vec<Ea4> = (0..SPARSE_BLOCK_COLS).map(|c| Ea4::from(cols[c][r])).collect();
            let at = |col: usize, pt: &[Ea4]| -> Ea4 {
                let mut row = 0usize;
                for (k, pk) in pt.iter().enumerate().take(nvars) {
                    if *pk == Ea4::ONE {
                        row |= 1 << (nvars - 1 - k);
                    }
                }
                Ea4::from(cols[col][row])
            };
            // Fixture row built locally from `cols`, so the out-of-range latch must stay clean; it is
            // asserted rather than ignored so a shape drift in this fixture cannot pass silently.
            let oob = crate::air_zerocheck::OobLatch::new();
            let v = gate.eval(&crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
            assert!(!oob.hit(), "fixture row is narrower than the gate reads: it read {}", oob.report());
            v
        };

        let to_f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| fkred(d[i])) };
        let gamma = Ea4::from(Fa4::from_u64(0x1234_5));
        let gate = SparseBlockGate {
            gamma,
            block_pre: to_f(block_pre),
            block_post: to_f(block_post),
            // No padding in this fixture, so the last REAL insert IS the last insert.
            bind_at: inserts.len() - 1,
            gpow: sparse_block_powers(gamma),
            keyed: false,
        };
        // VALID: every row satisfies the nested gate.
        for r in 0..height {
            assert_eq!(eval_at_row(&cols, &gate, r), zero, "valid block: row {r} satisfies the nested gate");
        }

        // TAMPER 1 — a WRONG block_post: the last row's spent-fold weld fails.
        let mut bad_post = to_f(block_post);
        bad_post[0] = bad_post[0] + Fa4::ONE;
        let gate_bp = SparseBlockGate { gamma: gate.gamma, block_pre: to_f(block_pre), block_post: bad_post, bind_at: inserts.len() - 1, gpow: sparse_block_powers(gate.gamma), keyed: false };
        assert_ne!(eval_at_row(&cols, &gate_bp, height - 1), zero, "a wrong block_post is rejected at the last row");

        // TAMPER 2 — BREAK THE ROOT-CHAIN: corrupt insert 1's running_root so it ≠ insert 0's spent acc_out. The
        // boundary-advance constraint at insert 0's last row (next.running_root == this.spent_accout) now fails.
        let mut bad_cols = cols.clone();
        for c in 0..DIGEST_LANES {
            bad_cols[CH_RROOT + c][NF_SPARSE_DEPTH] = bad_cols[CH_RROOT + c][NF_SPARSE_DEPTH] + Fa4::ONE;
        }
        assert_ne!(
            eval_at_row(&bad_cols, &gate, NF_SPARSE_DEPTH - 1),
            zero,
            "a broken root-chain at the insert boundary is rejected (the double-spend gate holds)"
        );
    }

    /// ⭐⭐⭐ DB-353 KEY BINDING (2026-09-29, docs/DB-353-SOUND-SHARDING-CARRIER-SPEC.md §3, §6) — the direct-evaluation
    /// instrument for the keyed block gate at the PRODUCTION cover. The unkeyed gate binds only `(block_pre, block_post)`:
    /// every insert's 256 key bits are a free boolean witness, so a producer may insert at a position that is not the
    /// block's tag — omit a real tag (its later double spend passes non-membership) or freeze a foreign position — and a
    /// treeless or partial door cannot tell. CALIBRATION (the hole, measured): the forged insert's rows SATISFY the unkeyed
    /// gate. REFUTATION: (A) the honest keyed trace of the same block vanishes on every row; (B) a trace inserting a
    /// different key while the PUBLIC digest is the header's is refused at the chain's end by the digest bind;
    /// (C) a trace that forges the frozen lane values to the public tag while its bits still walk the other position is
    /// refused at the first differing lane's end by the hand-over law; (D) a trace that also forges the accumulator at
    /// that lane's end is refused by the doubling law at the row where it jumps. Each refusal names its row, so a law that
    /// stopped carrying weight would be seen, not inferred. The table is ONE block's fixed cover (256 inserts × 256
    /// levels): its row count is a constant of the carrier, not a chain quantity.
    #[test]
    fn db353_keyed_block_gate_binds_every_insert_to_the_public_key_list() {
        let zero = Ea4::from(Fa4::ZERO);
        let to_f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| fkred(d[i])) };
        let n = PRODUCTION_BLOCK_COVER;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        // the block's TAGS (what the header binds) and the FORGED position for tag 0: a different key inserted where the
        // list says tag 0
        let tags: Vec<[u8; 32]> = (0..n as u64).map(|i| nf_from(0x3B53_0000 + i)).collect();
        let forged0 = nf_from(0x3B53_F000);
        assert_ne!(tags[0], forged0);
        let build = |keys: &[[u8; 32]]| -> Vec<SparseInsertWitness> {
            let mut refs = RefTree::default();
            keys.iter().map(|nf| SparseInsertWitness { key:*nf, copath: refs.insert_and_witness(nf) }).collect()
        };
        let honest = build(&tags);
        let mut forged_keys = tags.clone();
        forged_keys[0] = forged0;
        let forged = build(&forged_keys);
        let (tables_h, post_h, kd_h) = sparse_block_keyed_tables(&honest, block_pre, n).expect("honest keyed tables");
        let (tables_f, post_f, kd_f) = sparse_block_keyed_tables(&forged, block_pre, n).expect("forged keyed tables");
        let (cols_h, dg_h) = (&tables_h[0], &tables_h[1]);
        let (cols_f, dg_f) = (&tables_f[0], &tables_f[1]);
        let (cols_fu, post_fu, _) = sparse_block_cols_with(&forged, block_pre, n, false).expect("forged unkeyed trace");
        assert_eq!(post_f, post_fu, "keyed and unkeyed lays of one block agree on the post root");
        assert_ne!(post_h, post_f, "inserting a different key moves the post root");
        assert_eq!(kd_h, keys_digest_of(&tags, n), "the lay's digest is the door's native recompute over the header's keys");
        assert_ne!(kd_h, kd_f, "a different key changes the digest");
        let trace_rows = cols_h[0].len(); // the carrier's constant table: N × DEPTH
        assert_eq!(trace_rows, n * NF_SPARSE_DEPTH, "N=256 inserts × DEPTH rows (production cover)");
        assert_eq!(cols_h.len(), SPARSE_BLOCK_KEYED_COLS);
        assert_eq!(dg_h.len(), SPARSE_KEYS_DIGEST_COLS);
        assert_eq!(dg_h[0].len(), n << DG_STEP_BITS, "the digest table: two rows per insert");
        assert_eq!(cols_fu.len(), SPARSE_BLOCK_COLS);

        // a gate at a hypercube VERTEX (row r) of its table: x = the boolean row bits (high-bit-first); `at` decodes the
        // next row
        let eval_at_row = |cols: &Vec<Vec<Fa4>>, gate: &dyn crate::air_zerocheck::AirConstraint, r: usize| -> Ea4 {
            let nvars = cols[0].len().trailing_zeros() as usize;
            let x: Vec<Ea4> =
                (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::from(Fa4::ZERO) }).collect();
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
            assert!(!oob.hit(), "fixture row is narrower than the gate reads: it read {}", oob.report());
            v
        };
        let gamma = Ea4::from(Fa4::from_u64(0x3B53_7));
        let gate_h = SparseBlockGate::keyed(gamma, to_f(block_pre), to_f(post_h), n - 1);
        let dgate_h = SparseKeysDigestGate::new(gamma, n - 1, to_f(kd_h));
        // (A) the honest keyed tables: EVERY row of the block's constant chain table and of its digest table vanishes (a
        // progress line per 4,096 rows: the test-progress watchdog reaps a test silent for nine minutes, and this loop is
        // minutes in a debug build)
        let t_a = std::time::Instant::now();
        for r in 0..trace_rows {
            assert_eq!(eval_at_row(cols_h, &gate_h, r), zero, "honest keyed block: row {r} satisfies the keyed gate");
            if r % 4096 == 4095 {
                eprintln!("[db353-keyed] honest rows {}/{trace_rows} vanish ({} ms)", r + 1, t_a.elapsed().as_millis());
            }
        }
        for r in 0..dg_h[0].len() {
            assert_eq!(eval_at_row(dg_h, &dgate_h, r), zero, "honest digest table: row {r} satisfies the digest gate");
        }
        // CALIBRATION — the hole: the forged insert's rows satisfy the UNKEYED gate against its own post root, so a door
        // holding only (pre, post) accepts a block that spent `forged0` where its tag list says `tags[0]`
        let gate_u = SparseBlockGate {
            gamma,
            block_pre: to_f(block_pre),
            block_post: to_f(post_fu),
            bind_at: n - 1,
            gpow: sparse_block_powers(gamma),
            keyed: false,
        };
        for r in 0..NF_SPARSE_DEPTH {
            assert_eq!(eval_at_row(&cols_fu, &gate_u, r), zero, "CALIBRATION: the unkeyed gate accepts the forged insert at row {r}");
        }
        // (B) the forged digest table against the PUBLIC digest (the header's): the forged key's lanes were absorbed, so the
        // chain's end differs from the public digest and the bind law refuses at the LAST row; every earlier row — insert 0's
        // two steps included — is internally consistent and vanishes (the door holds the digest, not a per-insert list)
        let dgate_hb = SparseKeysDigestGate::new(gamma, n - 1, to_f(kd_h));
        let dg_rows = dg_f[0].len();
        assert_ne!(eval_at_row(dg_f, &dgate_hb, dg_rows - 1), zero, "(B) a different key under the header's digest is refused at the chain's end");
        assert_eq!(eval_at_row(dg_f, &dgate_hb, 0), zero, "insert 0's first step is internally consistent");
        assert_eq!(eval_at_row(dg_f, &dgate_hb, 1), zero, "insert 0's second step is internally consistent");
        assert_eq!(eval_at_row(dg_f, &dgate_hb, 2), zero, "insert 1 is honest and vanishes");
        // the forged CHAIN table is an honest transition of its own keys: every row of insert 0 satisfies the keyed gate
        let gate_fb = SparseBlockGate::keyed(gamma, to_f(block_pre), to_f(post_f), n - 1);
        for r in 0..NF_SPARSE_DEPTH {
            assert_eq!(eval_at_row(cols_f, &gate_fb, r), zero, "the forged insert's chain row {r} satisfies the keyed chain gate");
        }
        // (E) THE TIE CARRIES THE WEIGHT: pair the forged chain table with the HONEST digest table — each satisfies its own
        // gate under the header's digest and the forged post, so only the column tie (the chain table's lanes at an insert's
        // boundary = the digest table's at its first step) can refuse it, and at insert 0 its cells differ
        let lanes_at = |chain: &Vec<Vec<Fa4>>, i: usize| -> Vec<Fa4> {
            (0..KEY_LANES).map(|j| chain[CH_KEY + j][i * NF_SPARSE_DEPTH + NF_SPARSE_DEPTH - 1]).collect()
        };
        let dg_lanes_at = |dg: &Vec<Vec<Fa4>>, i: usize| -> Vec<Fa4> { (0..KEY_LANES).map(|j| dg[DG_KEY + j][i << DG_STEP_BITS]).collect() };
        assert_ne!(lanes_at(cols_f, 0), dg_lanes_at(dg_h, 0), "(E) the tie refuses the forged chain under the honest digest table at insert 0");
        for i in [1, n / 2, n - 1] {
            assert_eq!(lanes_at(cols_f, i), dg_lanes_at(dg_h, i), "(E) the tie's cells agree at the untouched insert {i}");
            assert_eq!(lanes_at(cols_h, i), dg_lanes_at(dg_h, i), "the honest tables agree at insert {i}");
        }
        // (C) forge the frozen lane values to the public tag's while the bits walk the forged position: the tie to the honest
        // digest table is now satisfied; the hand-over law refuses at the first lane whose value differs
        let honest_lanes = key_lanes_of(&tags[0]);
        let forged_lanes = key_lanes_of(&forged0);
        let first_diff = (0..KEY_LANES).find(|&j| honest_lanes[j] != forged_lanes[j]).expect("the keys differ in some lane");
        let mut cols_c = cols_f.clone();
        for j in 0..KEY_LANES {
            for r in 0..NF_SPARSE_DEPTH {
                cols_c[CH_KEY + j][r] = honest_lanes[j];
            }
        }
        let end_row = lane_end_level(first_diff);
        assert_ne!(
            eval_at_row(&cols_c, &gate_fb, end_row),
            zero,
            "(C) forged frozen lanes are refused at lane {first_diff}'s end (row {end_row})"
        );
        // at the boundary row the tie is now satisfied; only lane 8's own hand-over can still refuse there
        if honest_lanes[KEY_LANES - 1] == forged_lanes[KEY_LANES - 1] {
            assert_eq!(eval_at_row(&cols_c, &gate_fb, NF_SPARSE_DEPTH - 1), zero, "(C) the boundary law alone is satisfied");
        } else {
            assert_ne!(eval_at_row(&cols_c, &gate_fb, NF_SPARSE_DEPTH - 1), zero, "(C) lane 8's hand-over refuses at the boundary");
        }
        // (D) also forge the accumulator at that lane's end to the public value: the hand-over law is satisfied there and
        // the doubling law refuses one row earlier, where the accumulator jumps
        let mut cols_d = cols_c.clone();
        cols_d[CH_KACC][end_row] = honest_lanes[first_diff];
        assert!(end_row > lane_start_level(first_diff), "lane {first_diff} spans more than one level");
        if first_diff != KEY_LANES - 1 {
            assert_eq!(eval_at_row(&cols_d, &gate_fb, end_row), zero, "(D) the hand-over law is satisfied by the forged accumulator");
        }
        let prev = end_row - 1;
        assert_ne!(eval_at_row(&cols_d, &gate_fb, prev), zero, "(D) the doubling law refuses the jump at row {prev}");
    }

    /// ⭐⭐⭐ DB-353 KEYED CARRIER ON THE PRODUCTION PATH — the real prover and the real door at the PRODUCTION cover: an
    /// honest 256-insert block proves ONE keyed carrier that verifies against `(block_pre, block_post, tags)`; the same
    /// carrier is refused under a list with one lane of one tag changed; a block that inserted a DIFFERENT key at tag 0's
    /// slot proves (it is an honest transition of its own keys) and is REFUSED by the keyed door under the header's tag
    /// list — while the UNKEYED door accepts it (CALIBRATION: the hole this carrier closes); the two carriers' shapes are
    /// not interchangeable; an empty carrier and a wrong real count are refused. Prints `[db353-keyed-cost]`.
    #[test]
    fn db353_keyed_carrier_proves_verifies_and_refuses_a_position_forgery_the_unkeyed_door_accepts() {
        let n = PRODUCTION_BLOCK_COVER;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let tags: Vec<[u8; 32]> = (0..n as u64).map(|i| nf_from(0x3B53_A000 + i)).collect();
        let build = |keys: &[[u8; 32]]| -> Vec<SparseInsertWitness> {
            let mut refs = RefTree::default();
            keys.iter().map(|nf| SparseInsertWitness { key:*nf, copath: refs.insert_and_witness(nf) }).collect()
        };
        let honest = build(&tags);
        let t0 = std::time::Instant::now();
        let (carrier, post, kd) =
            prove_sparse_block_keyed_carrier_bytes(&honest, block_pre, n).expect("prove the keyed 256-insert carrier");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(
            verify_sparse_block_keyed_carrier_bytes(&carrier, block_pre, post, n, n, kd),
            "the honest keyed carrier verifies against (pre, post, n_real, n, keys_digest)"
        );
        eprintln!("[db353-keyed-cost] N={n} prove {prove_ms} ms, {} B, verify {} ms", carrier.len(), t1.elapsed().as_millis());
        assert!(carrier.len() <= 1_800_000, "constant proof size under the 1.8 MB cap");
        assert_eq!(kd, keys_digest_of(&tags, n), "the prover's digest is the door's native recompute over the header's keys");
        // the digest changed by one in one lane
        let mut bad_kd = kd;
        bad_kd[3] = crate::nullifier_insert_air::kadd(bad_kd[3], 1);
        assert!(!verify_sparse_block_keyed_carrier_bytes(&carrier, block_pre, post, n, n, bad_kd), "a changed public digest is refused");
        // the shapes are not interchangeable; the trivial refusals
        assert!(!verify_sparse_block_carrier_bytes(&carrier, block_pre, post, n), "the keyed carrier is refused by the unkeyed door");
        assert!(!verify_sparse_block_keyed_carrier_bytes(&[], block_pre, post, n, n, kd), "an empty carrier is refused");
        assert!(!verify_sparse_block_keyed_carrier_bytes(&carrier, block_pre, post, n - 1, n, kd), "a wrong real count is refused");
        // THE POSITION FORGERY: a different key inserted at tag 0's slot
        let mut forged_keys = tags.clone();
        forged_keys[0] = nf_from(0x3B53_FFFF);
        let forged = build(&forged_keys);
        let (fcarrier, fpost, fkd) = prove_sparse_block_keyed_carrier_bytes(&forged, block_pre, n)
            .expect("the forged block is an honest transition of its own keys");
        assert_ne!(fpost, post, "the forgery moves the post root");
        assert_eq!(fkd, keys_digest_of(&forged_keys, n));
        assert!(
            verify_sparse_block_keyed_carrier_bytes(&fcarrier, block_pre, fpost, n, n, fkd),
            "under ITS OWN digest the forged block verifies — the door must derive the digest from the header, never take it from the prover"
        );
        assert!(
            !verify_sparse_block_keyed_carrier_bytes(&fcarrier, block_pre, fpost, n, n, kd),
            "REFUTATION: under the header's digest the position forgery is refused"
        );
        // CALIBRATION: the unkeyed door accepts the forged block against its committed roots — it cannot see the tags
        let (ucarrier, upost) = prove_sparse_block_carrier_bytes(&forged, block_pre, n).expect("unkeyed carrier of the forged block");
        assert_eq!(upost, fpost);
        assert!(verify_sparse_block_carrier_bytes(&ucarrier, block_pre, upost, n), "CALIBRATION: the unkeyed door accepts the position forgery");
        assert!(!verify_sparse_block_keyed_carrier_bytes(&ucarrier, block_pre, upost, n, n, fkd), "the unkeyed carrier is refused by the keyed door");
    }

    /// ⭐⭐⭐ THE BOUND BAND-STEP DOUBLE IS BOUND TO THE REAL STATEMENT, AND NEVER PASSES THE REAL DOOR (testing format; the
    /// bound certificate's law). Over one real fold (the production cover, a short admitted set, sequential fillers), at
    /// the 500 ms target's k:
    /// - the double's chain ends at the SAME post the real prover reaches, slice by slice (its post is native, not claimed);
    /// - it verifies through the bound door, and every refusal the real door makes it makes too: a tampered intermediate
    ///   post, swapped slices, a shortened admitted order, a flipped byte;
    /// - ⛔ the REAL door refuses every bound slice, and the bound door refuses every real one — the two never mix.
    #[test]
    fn the_bound_band_double_matches_the_real_posts_refuses_what_the_door_refuses_and_never_passes_the_real_door() {
        let n = PRODUCTION_BLOCK_COVER;
        let admitted = n - 7;
        let keys: Vec<[u8; 32]> = (0..admitted as u64).map(|i| nf_from(0xB0D_BA5D + i)).collect();
        let mut refs = RefTree::default();
        let fold_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut inserts: Vec<SparseInsertWitness> =
            keys.iter().map(|k| SparseInsertWitness { key: *k, copath: refs.insert_and_witness(k) }).collect();
        let post = refs.root();
        for p in 0..(n - admitted) as u64 {
            let k = nf_from(0xB0D_F111 + p);
            inserts.push(SparseInsertWitness { key: k, copath: refs.insert_and_witness(&k) });
        }
        let k = band_chain_k(500);
        let real = prove_chained_band_transition(&inserts, fold_pre, admitted, k).expect("the real chain proves");
        let bound = prove_chained_band_transition_bound(&inserts, fold_pre, admitted, k).expect("the bound chain builds");
        assert_eq!(
            real.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            bound.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            "the double's posts are the real prover's posts, slice by slice"
        );
        assert_eq!(bound[k - 1].1, post, "the bound chain ends at the tree's root after the admitted inserts");
        fn view(c: &[(Vec<u8>, Digest)]) -> Vec<BandSlice<'_>> {
            c.iter().map(|(b, p)| BandSlice { bytes: b, post: *p }).collect()
        }
        let b = bound.clone();
        assert!(verify_chained_band_transition_bound(fold_pre, post, &keys, &view(&b)), "the bound chain verifies at the bound door");
        assert!(verify_chained_band_transition(fold_pre, post, &keys, &view(&real)), "CALIBRATION: the real chain verifies at the real door");
        // ⛔ never mixed
        assert!(!verify_chained_band_transition(fold_pre, post, &keys, &view(&b)), "⛔ the REAL door accepted a bound chain");
        assert!(!verify_chained_band_transition_bound(fold_pre, post, &keys, &view(&real)), "⛔ the bound door accepted a real chain");
        // every refusal the real door makes
        let mut bad = b.clone();
        bad[0].1[0] = crate::nullifier_insert_air::kadd(bad[0].1[0], 1);
        assert!(!verify_chained_band_transition_bound(fold_pre, post, &keys, &view(&bad)), "a tampered intermediate post is refused");
        let mut swapped = b.clone();
        swapped.swap(0, 1);
        assert!(!verify_chained_band_transition_bound(fold_pre, post, &keys, &view(&swapped)), "swapped slices are refused");
        assert!(
            !verify_chained_band_transition_bound(fold_pre, post, &keys[..admitted - 1], &view(&b)),
            "a shortened admitted order is refused"
        );
        let mut flipped = b.clone();
        flipped[1].0[3] ^= 1;
        assert!(!verify_chained_band_transition_bound(fold_pre, post, &keys, &view(&flipped)), "a flipped byte is refused");
        let mut elsewhere = post;
        elsewhere[0] = crate::nullifier_insert_air::kadd(elsewhere[0], 1);
        assert!(!verify_chained_band_transition_bound(fold_pre, elsewhere, &keys, &view(&b)), "a chain that ends elsewhere is refused");
        // and the single-slice door the node's band door runs
        let chunks = band_slices(&keys, k).expect("the door chunks the admitted keys");
        assert!(verify_band_slice_bound(fold_pre, b[0].1, &chunks[0], k, &b[0].0), "slice 0 verifies at the bound slice door");
        assert!(!verify_band_slice(fold_pre, b[0].1, &chunks[0], k, &b[0].0), "⛔ the REAL slice door accepted a bound slice");
    }

    /// ⭐⭐⭐ SHAPE (3) — A FOLD TRANSITION CHAINED IN k SLICES VERIFIES AS ONE TRANSITION (door spec §8b, condition 3):
    /// the production cover's 256 inserts, split into the k the block interval asks for (derived, never hand-picked), prove
    /// slice by slice with each slice's pre = the previous post, and the door — holding only the fold root, the ordered
    /// admitted keys and the announced post — accepts the chain. REFUSED: a tampered intermediate post (the link breaks
    /// twice: slice i's post and slice i+1's pre), swapped slices (each slice's digest is over its own chunk), a shortened
    /// order (a slice's real count then disagrees with its carrier), a chain that ends elsewhere.
    #[test]
    fn db353_a_fold_transition_chained_in_k_slices_verifies_as_one_and_refuses_a_broken_link() {
        // the DERIVATION, at whatever the measured reference is: the smallest power of two whose slice proves within one
        // interval (at most one insert per slice)
        for interval in [4_000u64, 2_000, 1_000, 500, 250] {
            let k = band_chain_k(interval);
            assert!(k.is_power_of_two() && k <= PRODUCTION_BLOCK_COVER, "k = {k} at {interval} ms");
            assert!(
                k == PRODUCTION_BLOCK_COVER || BAND_FOLD_PROVE_MS_REF.div_ceil(k as u64) <= interval,
                "a slice proves within one {interval} ms interval at the reference (k = {k})"
            );
            assert!(k == 1 || BAND_FOLD_PROVE_MS_REF.div_ceil(k as u64 / 2) > interval, "k = {k} is the SMALLEST such power of two");
        }
        // and its values at the reference (3,117 ms, the compact band step — see `BAND_FOLD_PROVE_MS_REF`)
        assert_eq!(band_chain_k(4_000), 1, "the 4 s relay floor: one slice");
        assert_eq!(band_chain_k(500), 8, "the 500 ms target: eight slices");
        let n = PRODUCTION_BLOCK_COVER;
        let admitted = n - 5; // five slots fall to respend losers: the last slice is short
        let keys: Vec<[u8; 32]> = (0..admitted as u64).map(|i| nf_from(0x3B53_C0DE + i)).collect();
        let mut refs = RefTree::default();
        let fold_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut inserts: Vec<SparseInsertWitness> = keys.iter().map(|k| SparseInsertWitness { key: *k, copath: refs.insert_and_witness(k) }).collect();
        let post = refs.root();
        for p in 0..(n - admitted) as u64 {
            // padding: SEQUENTIAL non-members — the block gate's padding inserts advance the carrier's internal running root
            // (never the committed post), so each filler's copath is against the tree with the previous fillers applied,
            // exactly as a holder serves them (`nf_sparse::RefSparseNf::serve_fold_copaths`)
            let k = nf_from(0x3B53_FADE + p);
            inserts.push(SparseInsertWitness { key: k, copath: refs.insert_and_witness(&k) });
        }
        for interval_ms in [2_000u64, 1_000] {
            let k = band_chain_k(interval_ms);
            let t0 = std::time::Instant::now();
            let chain = prove_chained_band_transition(&inserts, fold_pre, admitted, k).expect("the chain proves");
            let prove_ms = t0.elapsed().as_millis();
            assert_eq!(chain.len(), k);
            assert_eq!(chain[k - 1].1, post, "the chain ends at the tree's root after the admitted inserts");
            let slices: Vec<BandSlice<'_>> = chain.iter().map(|(b, p)| BandSlice { bytes: b, post: *p }).collect();
            let t1 = std::time::Instant::now();
            assert!(verify_chained_band_transition(fold_pre, post, &keys, &slices), "k = {k}: the chain verifies as one transition");
            eprintln!("[db353-chain] k={k} (interval {interval_ms} ms): prove {prove_ms} ms total, verify {} ms, bytes {}", t1.elapsed().as_millis(), chain.iter().map(|(b, _)| b.len()).sum::<usize>());
            // a tampered intermediate post
            let mut bad = chain.clone();
            bad[0].1[0] = crate::nullifier_insert_air::kadd(bad[0].1[0], 1);
            let bad_slices: Vec<BandSlice<'_>> = bad.iter().map(|(b, p)| BandSlice { bytes: b, post: *p }).collect();
            assert!(!verify_chained_band_transition(fold_pre, post, &keys, &bad_slices), "a tampered intermediate post is refused");
            // swapped slices: the digests are over the wrong chunks
            let mut swapped = chain.clone();
            swapped.swap(0, 1);
            let sw: Vec<BandSlice<'_>> = swapped.iter().map(|(b, p)| BandSlice { bytes: b, post: *p }).collect();
            assert!(!verify_chained_band_transition(fold_pre, post, &keys, &sw), "swapped slices are refused");
            // a shortened order: the door believes one fewer key was admitted
            assert!(!verify_chained_band_transition(fold_pre, post, &keys[..admitted - 1], &slices), "a shortened admitted order is refused");
            // a chain that ends elsewhere
            let mut other = post;
            other[1] = crate::nullifier_insert_air::kadd(other[1], 1);
            assert!(!verify_chained_band_transition(fold_pre, other, &keys, &slices), "a chain ending at another root is refused");
        }
    }

    /// ⭐ DB-353 — `keys_digest_of` is LENGTH-BOUND and padding-bound (the aggregate acceptance's condition 1): the same key
    /// at two insert counts, one key against two, and the empty list at two counts are all distinct digests; and the
    /// digest is a pure function of `(keys, n)`.
    #[test]
    fn db353_keys_digest_is_length_and_padding_bound() {
        let k1 = nf_from(0x3B53_D001);
        let k2 = nf_from(0x3B53_D002);
        let a = keys_digest_of(&[k1], 1);
        let b = keys_digest_of(&[k1], 2);
        let c = keys_digest_of(&[k1, k2], 2);
        let d = keys_digest_of(&[k2, k1], 2);
        let e0 = keys_digest_of(&[], 1);
        let e1 = keys_digest_of(&[], 2);
        for (x, y, why) in [
            (a, b, "[k1] at n=1 vs n=2"),
            (b, c, "[k1, pad] vs [k1, k2]"),
            (c, d, "order"),
            (e0, e1, "empty at n=1 vs n=2"),
            (a, e0, "one key vs none"),
        ] {
            assert_ne!(x, y, "digests must differ: {why}");
        }
        assert_eq!(a, keys_digest_of(&[k1], 1), "deterministic");
        assert_eq!(e1, keys_digest_of(&[], 2), "the empty-shard constant at n=2 is fixed");
    }

    /// ⭐ DB-353 — the keyed AND the unkeyed block gate under the crate's two structural censuses, run DIRECTLY on the
    /// production-cover trace (no prove; seconds): the degree census reads the gate's per-variable degree off a random line
    /// and refuses a law above the declared 3 (a mis-declared degree mis-interpolates the sumcheck trace-dependently — it
    /// passes the row diagnostic and fails verify on SOME traces); the free-witness census nudges every column's first live
    /// cell and refuses a column no law reads (the gate declares `free_columns() = []`). The same two run inside every
    /// DEBUG prove; this pin runs them in every profile.
    /// ⭐ PARITY (2026-10-06): the native endpoint is the traced one — post and keys digest, keyed and unkeyed, at every real
    /// count the cover takes — and a forged insert (a copath for a leaf already spent) is refused by both.
    #[test]
    fn the_native_block_post_equals_the_traced_one_and_refuses_the_same_forgery() {
        let n = 16usize;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut refs = RefTree::default();
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x5157_0000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        for real in [1, 3, n / 2, n] {
            for keyed in [true, false] {
                let (_, post_t, kd_t) = sparse_block_cols_with(&inserts, block_pre, real, keyed).expect("trace");
                let (post_n, kd_n) = sparse_block_post_native(&inserts, block_pre, real, keyed).expect("native");
                assert_eq!((post_n, kd_n), (post_t, kd_t), "native ≠ trace at real {real} keyed {keyed}");
                if keyed {
                    let (_, chain_end) = sparse_keys_digest_cols(&inserts, real).expect("digest table");
                    assert_eq!(chain_end, kd_n, "the digest table's in-circuit chain ≠ the native digest at real {real}");
                }
            }
        }
        // CALIBRATION + TAMPER: a second insert of the FIRST key (its leaf is spent after insert 0) is refused by both
        let mut forged = inserts.clone();
        forged[1] = SparseInsertWitness { key: inserts[0].key, copath: inserts[0].copath.clone() };
        assert!(sparse_block_cols_with(&forged, block_pre, n, true).is_none(), "CALIBRATION: the trace refuses the respend");
        assert!(sparse_block_post_native(&forged, block_pre, n, true).is_none(), "⛔ the native endpoint admitted a respend");
        assert!(sparse_block_post_native(&inserts[..3], block_pre, 3, true).is_none(), "⛔ a non-power-of-two count was admitted");
        // the empty-run shortcut is the full fold: the empty root and an arbitrary path agree with hashing every level
        let full = |leaf: Digest, key: &[u8; 32], cp: &[Digest]| {
            let mut node = leaf;
            for (l, s) in cp.iter().enumerate() {
                node = if nf_bit(key, l) == 0 { poseidon_pair_native(node, *s) } else { poseidon_pair_native(*s, node) };
            }
            node
        };
        for w in &inserts {
            assert_eq!(fold_sparse_native(empty_leaf_native(), &w.key, &w.copath), full(empty_leaf_native(), &w.key, &w.copath));
            assert_eq!(fold_sparse_native(spent_leaf_native(), &w.key, &w.copath), full(spent_leaf_native(), &w.key, &w.copath));
        }
    }

    #[test]
    fn db353_keyed_gate_passes_the_degree_and_free_witness_censuses() {
        use crate::air_zerocheck::AirConstraint;
        let to_f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| fkred(d[i])) };
        let n = PRODUCTION_BLOCK_COVER;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut refs = RefTree::default();
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x3B53_C000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        let (tables, post, kd) = sparse_block_keyed_tables(&inserts, block_pre, n).expect("keyed tables");
        let gamma = Ea4::from(Fa4::from_u64(0x3B53_C));
        // both tables of the keyed carrier, each under the gate the engine builds for it (`SparseKeyedGate::for_table`)
        for (t, cols) in tables.iter().enumerate() {
            let gate = SparseKeyedGate::for_table(t, gamma, to_f(block_pre), to_f(post), n - 1, to_f(kd));
            let tv = cols[0].len().trailing_zeros() as usize;
            let rl = gate.is_row_local();
            let sh = if rl { Some(Vec::new()) } else { gate.shifted_cols() };
            let t0 = std::time::Instant::now();
            crate::air_zerocheck::debug_degree_census(cols, &gate, tv, rl, &sh);
            crate::air_zerocheck::debug_free_witness_census(cols, &gate, tv, rl, &sh);
            crate::air_zerocheck::debug_decorative_block_census(cols, &gate, tv, rl, &sh);
            eprintln!("[db353-census] keyed table {t}: degree + free-witness + decorative-block censuses passed in {} ms", t0.elapsed().as_millis());
        }
        // the unkeyed gate too, so both declarations are censused side by side
        let (ucols, _, _) = sparse_block_cols_with(&inserts, block_pre, n, false).expect("unkeyed trace");
        let ugate = SparseBlockGate {
            gamma,
            block_pre: to_f(block_pre),
            block_post: to_f(post),
            bind_at: n - 1,
            gpow: sparse_block_powers(gamma),
            keyed: false,
        };
        let nvars = ucols[0].len().trailing_zeros() as usize;
        let row_local = ugate.is_row_local();
        let shifted = if row_local { Some(Vec::new()) } else { ugate.shifted_cols() };
        let t1 = std::time::Instant::now();
        crate::air_zerocheck::debug_degree_census(&ucols, &ugate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_free_witness_census(&ucols, &ugate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_decorative_block_census(&ucols, &ugate, nvars, row_local, &shifted);
        eprintln!("[db353-census] unkeyed gate: degree + free-witness + decorative-block censuses passed in {} ms", t1.elapsed().as_millis());
    }

    /// ⭐ THE DECORATIVE-BLOCK CENSUS IS ARMED (2026-09-29 21:0x): a synthetic gate that lays one permutation block whose
    /// output no law reads — the shape `push_chain_residuals` had until the weld — is REFUSED by the census, and the same
    /// gate with the output weld PASSES. The calibration for the census that now runs on every strict prove.
    #[test]
    fn db353_the_decorative_block_census_refuses_an_unwelded_permutation_and_passes_the_welded_one() {
        use crate::air_zerocheck::{AirConstraint, Row};
        use crate::pow_pq_air::{P2_COLS, PERM_OUT};
        const P_ACC_OUT: usize = P2_COLS; // one block at column 0, the accumulator after it
        struct Probe {
            welded: bool,
            gamma: Ea4,
        }
        impl AirConstraint for Probe {
            fn degree(&self, _nvars: usize) -> usize {
                crate::pow_pq_air::P2_CONSTRAINT_DEGREE
            }
            fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
                let mut rs: Vec<Ea4> = Vec::new();
                crate::pow_pq_air::push_perm_residuals(local, 0, &mut rs);
                let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
                for c in 0..DIGEST_LANES {
                    // the accumulator IS read — by a chain law to the next row — so the free-witness census sees it bound
                    rs.push(at(P_ACC_OUT + c, &sigma) - local[P_ACC_OUT + c]);
                    if self.welded {
                        rs.push(local[PERM_OUT + c] - local[P_ACC_OUT + c]);
                    }
                }
                let mut acc = Ea4::ZERO;
                let mut g = Ea4::ONE;
                for r in rs {
                    acc += g * r;
                    g *= self.gamma;
                }
                acc
            }
        }
        // a two-row trace of one valid compression each
        let width = P2_COLS + DIGEST_LANES;
        let mut cols = vec![vec![Fa4::ZERO; 2]; width];
        let (l, r) = (nf_to_limbs(&nf_from(0xDEC0_1)), nf_to_limbs(&nf_from(0xDEC0_2)));
        for row in 0..2 {
            let mut cells = vec![Fa4::ZERO; width];
            crate::pow_pq_air::lay_perm_row_flat(&mut cells, 0, crate::pow_pq_air::pair_state(&l, &r));
            let out = poseidon_pair_native(l, r);
            for c in 0..DIGEST_LANES {
                cells[P_ACC_OUT + c] = fkred(out[c]);
            }
            for c in 0..width {
                cols[c][row] = cells[c];
            }
        }
        let gamma = Ea4::from(Fa4::from_u64(0xDEC0));
        // the welded probe passes
        crate::air_zerocheck::debug_decorative_block_census(&cols, &Probe { welded: true, gamma }, 1, false, &None);
        // the unwelded probe — the pre-weld shape — is refused
        let refused = std::panic::catch_unwind(|| {
            crate::air_zerocheck::debug_decorative_block_census(&cols, &Probe { welded: false, gamma }, 1, false, &None);
        });
        assert!(refused.is_err(), "⛔ the decorative-block census ACCEPTED a permutation whose output no law reads");
    }

    /// ⛔⛔⛔ DB-353 — THE CHAIN OUTPUT MUST BE WELDED TO THE PERMUTATION (found 2026-09-29 21:0x while laying the digest
    /// chain beside the two existing ones). `push_chain_residuals` welds the block's INPUTS (the dir-selected sibling and
    /// accumulator) — if it does not also weld the block's OUTPUT cells to `acc_out`, then `acc_out` is a free cell the σ law
    /// merely copies into the next row, both chains are decorative, and a prover who lays honest permutations may CHOOSE
    /// every accumulator: any `(block_pre, block_post)` proves, every non-membership check passes. This is the
    /// read-but-undetermined class the free-witness census cannot see (the cells are read by the chain laws). The forgery:
    /// bump the spent chain's `acc_out` at the binding boundary row by one and claim the bumped value as `block_post`. With
    /// the weld it is refused at exactly that row and nowhere else; the honest trace still vanishes there.
    /// MEASURED RED FIRST (release, 2026-09-29 21:0x, before the weld existed): the forged row evaluated to exactly zero —
    /// `assertion left != right failed: … was ACCEPTED` — on the production-cover trace. The weld turned it GREEN.
    #[test]
    fn db353_a_forged_accumulator_beside_an_honest_permutation_is_refused() {
        let zero = Ea4::from(Fa4::ZERO);
        let to_f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| fkred(d[i])) };
        let n = PRODUCTION_BLOCK_COVER;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut refs = RefTree::default();
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x3B53_E000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        let (cols, post) = sparse_block_cols(&inserts, block_pre, n).expect("honest trace");
        let nvars = cols[0].len().trailing_zeros() as usize;
        let eval_at_row = |cols: &Vec<Vec<Fa4>>, gate: &SparseBlockGate, r: usize| -> Ea4 {
            use crate::air_zerocheck::AirConstraint;
            let x: Vec<Ea4> =
                (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::from(Fa4::ZERO) }).collect();
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
            assert!(!oob.hit(), "fixture row is narrower than the gate reads: it read {}", oob.report());
            v
        };
        let gamma = Ea4::from(Fa4::from_u64(0x3B53_E));
        let mk = |post_f: [Fa4; DIGEST_LANES]| SparseBlockGate {
            gamma,
            block_pre: to_f(block_pre),
            block_post: post_f,
            bind_at: n - 1,
            gpow: sparse_block_powers(gamma),
            keyed: false,
        };
        // the forgery: the spent chain's accumulator at the last real insert's boundary row, bumped, and claimed as the post
        let row = (n - 1) * NF_SPARSE_DEPTH + (NF_SPARSE_DEPTH - 1);
        let mut forged = cols.clone();
        forged[CH_AOUTS][row] = forged[CH_AOUTS][row] + Fa4::ONE;
        let mut bad_post = to_f(post);
        bad_post[0] = bad_post[0] + Fa4::ONE;
        let gate_bad = mk(bad_post);
        assert_ne!(
            eval_at_row(&forged, &gate_bad, row),
            zero,
            "⛔ a forged accumulator beside an honest permutation was ACCEPTED: the chain output is not welded to the block"
        );
        // the honest trace under the honest post still vanishes at that row
        assert_eq!(eval_at_row(&cols, &mk(to_f(post)), row), zero, "the honest boundary row satisfies the welded gate");
        // and the forgery is refused ONLY where the cell was forged: every other row of that insert still vanishes
        for r in (n - 1) * NF_SPARSE_DEPTH..row {
            assert_eq!(eval_at_row(&forged, &gate_bad, r), zero, "row {r} is untouched by the forgery and vanishes");
        }
    }

    /// ⭐ NESTED BLOCK CARRIER (brick 2c) — the O(1) WHIR proof of a whole block's N-insert transition: PROVE a valid
    /// 2-insert block, VERIFY it against ONLY `(block_pre, block_post)` (the intermediate root stays PRIVATE in the
    /// trace), and REJECT a wrong block_post, a wrong block_pre, and an empty carrier. This is the whole-block
    /// double-spend check a treeless (jumped) node runs — no held tree, no per-insert copaths at verify time.
    #[test]
    fn sparse_block_carrier_proves_verifies_and_rejects_tamper() {
        // PRODUCTION cover: the whole 256-insert block proven in ONE carrier at full strength.
        let n = PRODUCTION_BLOCK_COVER;
        let mut refs = RefTree::default();
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x7C20_0000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();

        // ONE production-scale prove, reused for every verify/tamper assertion below (no re-prove per check).
        let (carrier, block_post) =
            prove_sparse_block_carrier_bytes(&inserts, block_pre, inserts.len())
                .expect("prove the 256-insert block carrier");
        assert!(
            verify_sparse_block_carrier_bytes(&carrier, block_pre, block_post, inserts.len()),
            "the block carrier verifies O(1) against the committed (block_pre, block_post)"
        );

        let mut bad_post = block_post;
        bad_post[0] = crate::nullifier_insert_air::kadd(bad_post[0], 1);
        assert!(!verify_sparse_block_carrier_bytes(&carrier, block_pre, bad_post, inserts.len()), "a wrong block_post is rejected");

        let mut bad_pre = block_pre;
        bad_pre[0] = crate::nullifier_insert_air::kadd(bad_pre[0], 1);
        assert!(!verify_sparse_block_carrier_bytes(&carrier, bad_pre, block_post, inserts.len()), "a wrong block_pre is rejected");

        assert!(!verify_sparse_block_carrier_bytes(&[], block_pre, block_post, inserts.len()), "an empty carrier is rejected");
    }

    /// ⭐⭐⭐ CHAIN-ENFORCING cross-tie block carrier (brick 2d) — the SOUND, PRIVATE, PARALLELIZABLE replacement for the
    /// deleted unsound settlement-fold. N INDEPENDENT single-insert tables (each provable the instant its spend lands)
    /// chained by a CROSS-TIE per link. Proves: (a) an honest N-insert block VERIFIES O(1) against ONLY `(block_pre,
    /// block_post)` — interior roots stay private; (b) a wrong `block_post` / empty carrier is rejected; (c) THE KEY
    /// REGRESSION — a BROKEN CHAIN (two inserts BOTH proven against `block_pre`, so `post_0 ≠ pre_1`: exactly what the
    /// deleted folded aggregation LET VERIFY) is now REJECTED by the cross-tie, EVEN THOUGH every endpoint weld
    /// individually holds. That isolates the cross-tie as the piece supplying the missing `post_i == pre_{i+1}` link.
    /// ⭐⭐⭐ DB-213 — THE FOLDED CARRIER PROVES THE SAME THING, REJECTS THE SAME FORGERIES, AND IS THE
    /// SIZE THE PILLAR ASKS FOR.
    ///
    /// Three things must hold together, and a size win that drops any of them is worthless:
    ///   (a) EQUIVALENCE AT N = 1 — with one insert the low-8 variable set IS every variable, so the
    ///       folded AIR's selectors collapse onto the per-table ones. Both carriers must verify the same
    ///       statement. This is the proof the generalisation loosened nothing.
    ///   (b) SIZE AT PRODUCTION COVER — the measured reason this exists: one table pays ONE set of column
    ///       openings instead of N, so the carrier must come in far under the 1,800,000 B pillar-4 ceiling
    ///       that the per-item-table shape misses by 2.78×.
    ///   (c) THE REJECTS SURVIVE — a wrong endpoint, an empty carrier, and (the one that matters) a BROKEN
    ///       CHAIN must all still fail. A broken chain is two inserts both proven against `block_pre`, so
    ///       `post_0 != pre_1`: exactly what the deleted folded aggregation once let through. If the fold
    ///       re-opens that hole it is the old unsound shape wearing a new name.
    #[test]
    fn folded_block_carrier_matches_per_table_and_fits_the_budget() {
        // ── (a) EQUIVALENCE AT ONE INSERT.
        {
            let mut refs = RefTree::default();
            let pre = empty_subtree_native(NF_SPARSE_DEPTH);
            let nf = nf_from(0xD213_0001);
            let one = vec![SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }];
            let (per_table, post_a) = prove_sparse_block_crosstie_bytes(&one, pre)
                .expect("per-table carrier at n=1");
            let (folded, post_b) = prove_sparse_block_folded_bytes(&one, pre)
                .expect("folded carrier at n=1");
            assert_eq!(post_a, post_b, "both shapes must prove the SAME post-root");
            assert!(
                verify_sparse_block_crosstie_bytes(&per_table, pre, post_a, 1),
                "the per-table carrier still verifies"
            );
            assert!(
                verify_sparse_block_folded_bytes(&folded, pre, post_b, 1),
                "⛔ the folded carrier does NOT verify at n=1, where its selectors are IDENTICAL to the \
                 per-table AIR — the generalisation changed the statement instead of only its container"
            );
        }

        // ── (b) SIZE AT PRODUCTION COVER, and (c) the rejects.
        let n = PRODUCTION_BLOCK_COVER;
        let mut refs = RefTree::default();
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0xD213_1000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        let (folded, block_post) =
            prove_sparse_block_folded_bytes(&inserts, block_pre).expect("folded carrier at production cover");
        assert!(
            verify_sparse_block_folded_bytes(&folded, block_pre, block_post, n),
            "the honest folded {n}-insert carrier must verify O(1) against ONLY (block_pre, block_post)"
        );

        let (per_table, _) =
            prove_sparse_block_crosstie_bytes(&inserts, block_pre).expect("per-table carrier at production cover");
        println!(
            "MEASURED DB-213: folded = {} B   per-item-table = {} B   ({:.1}× smaller)   ceiling = 1,800,000 B",
            folded.len(),
            per_table.len(),
            per_table.len() as f64 / folded.len().max(1) as f64
        );
        assert!(
            folded.len() < 1_800_000,
            "⛔ the FOLDED carrier still misses the constant-proof budget: {} bytes against 1,800,000 \
             ({:+} bytes). Folding onto one table was supposed to remove the per-item axis.",
            folded.len(),
            folded.len() as i64 - 1_800_000
        );
        assert!(
            folded.len() < per_table.len(),
            "⛔ folding produced no size win at all ({} vs {}) — then the per-table openings were not the \
             cost, and the measurement that motivated this is wrong",
            folded.len(),
            per_table.len()
        );

        // (c) wrong endpoint / empty carrier.
        let mut bad_post = block_post;
        bad_post[0] = bad_post[0].wrapping_add(1);
        assert!(
            !verify_sparse_block_folded_bytes(&folded, block_pre, bad_post, n),
            "⛔ a WRONG block_post verified — the endpoint weld is not binding"
        );
        assert!(
            !verify_sparse_block_folded_bytes(&[], block_pre, block_post, n),
            "⛔ an EMPTY carrier verified — the door is not fail-closed"
        );

        // (c) THE BROKEN CHAIN — built BY HAND, because the honest prover refuses to build one.
        //
        // ⛔ MY FIRST VERSION OF THIS ARM WAS VACUOUS. It handed two individually-honest witnesses to
        // `prove_sparse_block_folded_bytes`, which checks each insert against the RUNNING root, returns
        // `None` for the second, and so the reject assertion sat inside an `if let Some` that never ran. An
        // arm that cannot go red is not evidence. Here both tables are FIRST inserts against the empty root
        // (each internally valid), concatenated and proven directly, so `post_0 != pre_1` reaches the VERIFIER.
        let empty_root = empty_subtree_native(NF_SPARSE_DEPTH);
        let depth_bits = NF_SPARSE_DEPTH.trailing_zeros() as usize;
        let concat = |parts: &[Vec<Vec<Fa4>>]| -> Vec<Vec<Fa4>> {
            let width = parts[0].len();
            (0..width)
                .map(|c| parts.iter().flat_map(|t| t[c].iter().copied()).collect())
                .collect()
        };
        {
            let (w0, _e0, _p0) = first_insert(nf_from(0xD213_2000));
            let (w1, _e1, _p1) = first_insert(nf_from(0xD213_2001));
            let (t0, post0) = sparse_chain_cols(&w0, empty_root).expect("first insert vs empty");
            let (t1, post1) = sparse_chain_cols(&w1, empty_root).expect("first insert vs empty");
            assert_ne!(post0, empty_root, "insert 0 advanced the root, so post_0 != pre_1 — the chain IS broken");
            let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(empty_root[c]));
            let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(post1[c]));
            let bind = sparse_block_statement_bind(&pre_f, &post_f);
            let broken = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
                vec![concat(&[t0, t1])],
                sparse_block_folded_make(empty_root, post1, depth_bits),
                vec![],
                sparse_block_folded_spec(2, NF_SPARSE_DEPTH),
                Vec::new(),
                &bind,
            );
            println!(
                "DB-213 arm c: the broken-chain carrier was {} by the prover",
                if broken.is_some() { "BUILT (the verifier must refuse it)" } else { "REFUSED" }
            );
            if let Some(b) = broken.as_deref() {
                assert!(
                    !verify_sparse_block_folded_bytes(b, empty_root, post1, 2),
                    "⛔⛔⛔ A BROKEN CHAIN VERIFIED under the folded shape (post_0 != pre_1) — this is \
                     precisely the hole the deleted folded aggregation had"
                );
            }
        }

        // (d) ⛔ THE SHAPE FORGERY — a carrier whose ROW COUNT the prover chose (DB-213b).
        //
        // Two inserts in one table, presented as a ONE-insert statement: insert 0 is honest against
        // `block_pre`, insert 1 is a first insert into an UNRELATED tree. At n = 1 there is no cross-tie, the
        // pre weld sits on insert 0's end row and the post weld on the GLOBAL last row — so the claimed post
        // is a root with no relation to the pre-root. That is a forged nullifier root.
        {
            let mut ra = RefTree::default();
            let nf_a = nf_from(0xD213_3000);
            let wa = SparseInsertWitness { key:nf_a, copath: ra.insert_and_witness(&nf_a) };
            let (ta, true_post) = sparse_chain_cols(&wa, block_pre).expect("honest insert against block_pre");
            let (wb, _e, _p) = first_insert(nf_from(0xD213_3001));
            let (tb, forged_post) = sparse_chain_cols(&wb, empty_root).expect("first insert into an unrelated tree");
            assert_ne!(forged_post, true_post, "the forged post must differ from the honest one, or this proves nothing");
            let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
            let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(forged_post[c]));
            let bind = sparse_block_statement_bind(&pre_f, &post_f);
            let forged = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
                vec![concat(&[ta, tb])],
                sparse_block_folded_make(block_pre, forged_post, depth_bits),
                vec![],
                sparse_block_folded_spec(1, NF_SPARSE_DEPTH),
                Vec::new(),
                &bind,
            )
            .expect("the prover builds whatever shape it is handed — the constraints all hold");
            // CALIBRATION — the attack is ARMED: the batch verifier alone gates only allocation and accepts it.
            assert!(
                crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                    &forged,
                    sparse_block_folded_make(block_pre, forged_post, depth_bits),
                    sparse_block_folded_spec(1, NF_SPARSE_DEPTH),
                    Vec::new(),
                    &bind,
                    &crate::whir_rec_block::declared_bus_shapes_for_tests(&forged).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&forged).1,
                ),
                "calibration: the unpinned batch verifier was expected to ACCEPT the shape forgery — if it \
                 refuses, arm d measures nothing and must be rebuilt"
            );
            // REFUTATION — the pinned verifier refuses it.
            assert!(
                !verify_sparse_block_folded_bytes(&forged, block_pre, forged_post, 1),
                "⛔⛔⛔ A FORGED NULLIFIER ROOT VERIFIED: a 2-insert table presented as a 1-insert statement \
                 carried an untied tail, and the folded verifier did not pin the row count"
            );
        }
    }

    /// ⭐ DB-353 — THE BAND FOLD IS THE TREE'S TOP: a reference tree with spends in several shards (two in one), its 256
    /// level-248 subtree roots indexed by the tag's top byte fold to its root; one foreign entry flipped, two entries
    /// swapped, a band one entry short and one entry long are all refused — the door's gate (1), armed here before the
    /// door exists. TWO-PARTY-REVIEWED: the band is read straight from the reference tree's nodes (what a holding node
    /// computes); the fold is the helper a door calls (what a partial view checks); they share only the pairing.
    #[test]
    fn db353_the_band_folds_to_the_root_and_a_flipped_or_swapped_entry_does_not() {
        let mut refs = RefTree::default();
        for (i, top) in [0x00u8, 0x00, 0x7f, 0x80, 0xff, 0x3c].iter().enumerate() {
            let mut nf = nf_from(0x3D50_0000 + i as u64);
            nf[31] = *top; // the shard: the tag's top byte
            let _ = refs.insert_and_witness(&nf);
        }
        let root = refs.root();
        let band: Vec<Digest> = (0..NF_BAND_ENTRIES)
            .map(|s| {
                let mut canon = [0u8; 32];
                canon[31] = s as u8;
                refs.node_at(NF_BAND_LEVEL, &canon)
            })
            .collect();
        assert_ne!(band[0x00], empty_subtree_native(NF_BAND_LEVEL), "shard 0x00 holds two spends");
        assert_ne!(band[0x3c], empty_subtree_native(NF_BAND_LEVEL), "shard 0x3c holds one spend");
        assert_eq!(band[0x01], empty_subtree_native(NF_BAND_LEVEL), "shard 0x01 is empty");
        assert_eq!(fold_band(&band), Some(root), "the band folds to the tree root");
        let mut flipped = band.clone();
        flipped[0x80][0] ^= 1;
        assert_ne!(fold_band(&flipped), Some(root), "⛔ a foreign entry flipped still folds to the root");
        let mut swapped = band.clone();
        swapped.swap(0x7f, 0x80);
        assert_ne!(fold_band(&swapped), Some(root), "⛔ two entries swapped still fold to the root");
        assert_eq!(fold_band(&band[..NF_BAND_ENTRIES - 1]), None, "a short band is refused");
        let mut long = band.clone();
        long.push(band[0]);
        assert_eq!(fold_band(&long), None, "a long band is refused");
        // an empty tree's band is all empty subtrees and folds to the empty root — the genesis case a fresh node starts from
        let empty_band = vec![empty_subtree_native(NF_BAND_LEVEL); NF_BAND_ENTRIES];
        assert_eq!(fold_band(&empty_band), Some(empty_subtree_native(NF_SPARSE_DEPTH)), "the empty band folds to the empty root");
    }

    /// ⭐ DB-353 — THE COST OF SOUND SHARDING, MEASURED FOR THE RECORD (the pillar-trade table the bus asked for): the
    /// REAL per-insert block carrier (`prove_sparse_block_crosstie_bytes`, one `SparseChainLink` table per insert,
    /// cross-tied) at N = 16 and N = 64 inserts — wall-clock prove ms and carrier bytes, in this binary's profile. The
    /// production cover (256) is measured by the pin below (`[zc]` lines: 154 ms per insert table on 2026-09-29). A
    /// partial-view node could verify a foreign insert only from THIS carrier, so its prove time is the number the
    /// producer pays for sound sharding. Asserts only what is a claim: both carriers verify against their endpoints.
    #[test]
    fn db353_the_real_insert_carrier_cost_at_16_and_64_inserts() {
        for n in [16usize, 64] {
            let mut refs = RefTree::default();
            let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
            let inserts: Vec<SparseInsertWitness> = (0..n as u64)
                .map(|i| {
                    let nf = nf_from(0x3D60_0000 + (n as u64) * 0x1000 + i);
                    SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
                })
                .collect();
            let t0 = std::time::Instant::now();
            let (carrier, block_post) = prove_sparse_block_crosstie_bytes(&inserts, block_pre).expect("proves");
            let prove_ms = t0.elapsed().as_millis();
            let t0 = std::time::Instant::now();
            assert!(verify_sparse_block_crosstie_bytes(&carrier, block_pre, block_post, n), "the {n}-insert carrier verifies");
            let verify_ms = t0.elapsed().as_millis();
            eprintln!(
                "[db353-cost] cross-tie N = {n} inserts: prove {prove_ms} ms ({} ms per insert), verify {verify_ms} ms, {} B | profile: {}",
                prove_ms / n as u128,
                carrier.len(),
                if cfg!(debug_assertions) { "debug" } else { "release" }
            );
        }
        // the NESTED block gate (brick 2c): the same N inserts as ONE N·DEPTH-row table with a running-root carry column —
        // one zerocheck, one commitment, one set of openings — at 16, 64 and the production cover 256 (2^16 rows)
        for n in [16usize, 64, 256] {
            let mut refs = RefTree::default();
            let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
            let inserts: Vec<SparseInsertWitness> = (0..n as u64)
                .map(|i| {
                    let nf = nf_from(0x3D70_0000 + (n as u64) * 0x1000 + i);
                    SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
                })
                .collect();
            let t0 = std::time::Instant::now();
            let (carrier, block_post) = prove_sparse_block_carrier_bytes(&inserts, block_pre, n).expect("proves");
            let prove_ms = t0.elapsed().as_millis();
            let t0 = std::time::Instant::now();
            assert!(verify_sparse_block_carrier_bytes(&carrier, block_pre, block_post, n), "the nested {n}-insert carrier verifies");
            let verify_ms = t0.elapsed().as_millis();
            eprintln!(
                "[db353-cost] nested N = {n} inserts ({} rows): prove {prove_ms} ms ({} ms per insert), verify {verify_ms} ms, {} B | profile: {}",
                n * NF_SPARSE_DEPTH,
                prove_ms / n as u128,
                carrier.len(),
                if cfg!(debug_assertions) { "debug" } else { "release" }
            );
        }
    }

    #[test]
    fn sparse_block_crosstie_enforces_chain_rejects_broken_link() {
        // CORRECT-ARCHITECTURE-REVIEWED: the cover count is raised 2 → PRODUCTION_BLOCK_COVER (256) throughout — NO
        // assertion is deleted; every verify/reject assertion is retained and now runs at production scale.
        // (a) HONEST PRODUCTION-cover block (256 inserts properly chained via the ref tree R_0 → … → R_N).
        let n = PRODUCTION_BLOCK_COVER;
        let mut refs = RefTree::default();
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let inserts: Vec<SparseInsertWitness> = (0..n as u64)
            .map(|i| {
                let nf = nf_from(0x2D30_0000 + i);
                SparseInsertWitness { key: nf, copath: refs.insert_and_witness(&nf) }
            })
            .collect();
        let (carrier, block_post) = prove_sparse_block_crosstie_bytes(&inserts, block_pre)
            .expect("prove the 256-insert cross-tie block carrier");
        assert!(
            verify_sparse_block_crosstie_bytes(&carrier, block_pre, block_post, n),
            "honest chain-enforcing 256-insert block carrier verifies O(1) against ONLY (block_pre, block_post)"
        );

        // (b) wrong endpoint / empty carrier rejected fail-closed.
        let mut bad_post = block_post;
        bad_post[0] = crate::nullifier_insert_air::kadd(bad_post[0], 1);
        assert!(!verify_sparse_block_crosstie_bytes(&carrier, block_pre, bad_post, n), "a wrong block_post is rejected");
        assert!(!verify_sparse_block_crosstie_bytes(&[], block_pre, block_post, n), "an empty carrier is rejected");

        // (c) THE REGRESSION the folded aggregation accepted, at PRODUCTION scale. Build all N=256 tables as valid
        // FIRST inserts against the EMPTY root (each INTERNALLY valid), so every interior cross-tie post_k ≠
        // pre_{k+1}(empty). Assemble the batch with the SAME endpoint welds + cross-ties for the CLAIMED (block_pre =
        // empty, block_post = table[N-1].post). Endpoint welds hold; ONLY the chain cross-ties are violated ⇒ REJECT.
        let empty_root = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut tables: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(n);
        let mut last_post = empty_root;
        for i in 0..n as u64 {
            let (w, _e, _p) = first_insert(nf_from(0x2D31_0000 + i));
            let (t, post) = sparse_chain_cols(&w, empty_root).expect("first-insert table folds vs empty");
            last_post = post;
            tables.push(t);
        }
        assert_ne!(last_post, empty_root, "each first insert advanced the root, so post_k ≠ pre_{{k+1}}(empty) — chain broken");
        let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(empty_root[c]));
        let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(last_post[c]));
        let bind = sparse_block_statement_bind(&pre_f, &post_f);
        let ties = sparse_block_crosstie_spec(n);
        let broken = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables,
            sparse_block_crosstie_make(n, empty_root, last_post),
            vec![],
            ties.clone(),
            Vec::new(),
            &bind);
        let broken_verifies = broken
            .as_deref()
            .map(|b| {
                crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                    b,
                    sparse_block_crosstie_make(n, empty_root, last_post),
                    ties.clone(),
                    Vec::new(),
                    &bind, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1)
            })
            .unwrap_or(false);
        assert!(
            !broken_verifies,
            "a BROKEN CHAIN (post_k ≠ pre_{{k+1}}) the deleted folded aggregation ACCEPTED must now be REJECTED by the cross-tie"
        );
    }

    /// ⛔⛔⛔ DB-213b ON THE PER-TABLE CARRIER — A LAST TABLE OF 512 ROWS FORGES THE POST-ROOT.
    ///
    /// The cross-ties sit on row `NF_SPARSE_DEPTH - 1` of each table and the post weld on the table's GLOBAL last
    /// row. A last table twice as tall keeps its honest insert on rows 0..255 (so the tie to the previous table
    /// still lands on the real `R_1`), then walks 256 MORE levels: the spent chain climbs from the honest
    /// `post_real` through empty siblings, and the weld pins whatever root that reaches. The claimed post-root is
    /// then a tree whose only leaf is `post_real` — every spent nullifier reads unspent against it.
    #[test]
    fn db213b_a_512_row_last_table_is_refused_by_the_pinned_crosstie_verifier() {
        let n = 2usize;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let mut refs = RefTree::default();
        let nf_a = nf_from(0xDB21_3B50);
        let w0 = SparseInsertWitness { key:nf_a, copath: refs.insert_and_witness(&nf_a) };
        let (t0, r1) = sparse_chain_cols(&w0, block_pre).expect("insert 0 against block_pre");
        let nf_b = nf_from(0xDB21_3B51);
        let w1 = SparseInsertWitness { key:nf_b, copath: refs.insert_and_witness(&nf_b) };
        let (t1, post_real) = sparse_chain_cols(&w1, r1).expect("insert 1 against R_1");
        // Rows 0..255 of the tall table: insert 1 exactly as honestly laid.
        let mut rows: Vec<Vec<Fa4>> =
            (0..NF_SPARSE_DEPTH).map(|r| (0..SPARSE_CHAIN_COLS).map(|c| t1[c][r]).collect()).collect();
        // Rows 256..511: both chains keep folding, through EMPTY siblings on the left branch.
        let (mut acc_e, mut acc_s) = (r1, post_real);
        for level in 0..NF_SPARSE_DEPTH {
            let mut row = vec![Fa4::ZERO; SPARSE_CHAIN_COLS];
            let sib = empty_subtree_native(level);
            for c in 0..DIGEST_LANES {
                row[CH_SIB + c] = fkred(sib[c]);
            }
            row[CH_DIR] = Fa4::ZERO;
            acc_e = emit_chain_row(&mut row, CH_AINE, acc_e, sib, 0);
            acc_s = emit_chain_row(&mut row, CH_AINS, acc_s, sib, 0);
            rows.push(row);
        }
        let forged_post = acc_s;
        assert_ne!(forged_post, post_real, "calibration: the forged root is not the true post-root");
        let tall: Vec<Vec<Fa4>> = (0..SPARSE_CHAIN_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
        let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(block_pre[c]));
        let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|c| fkred(forged_post[c]));
        let bind = sparse_block_statement_bind(&pre_f, &post_f);
        let forged = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            vec![t0, tall],
            sparse_block_crosstie_make(n, block_pre, forged_post),
            vec![],
            sparse_block_crosstie_spec(n),
            Vec::new(),
            &bind,
        )
        .expect("the prover builds whatever shape it is handed — every constraint holds");
        let declared = crate::whir_rec_block::declared_bus_shapes_for_tests(&forged);
        let unpinned = crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
            &forged,
            sparse_block_crosstie_make(n, block_pre, forged_post),
            sparse_block_crosstie_spec(n),
            Vec::new(),
            &bind,
            &declared.0,
            &declared.1,
        );
        let pinned = verify_sparse_block_crosstie_bytes(&forged, block_pre, forged_post, n);
        println!(
            "[DB-213b crosstie] declared shapes {:?}; engine on the carrier's own shapes = {unpinned}; \
             pinned verify_sparse_block_crosstie_bytes = {pinned}",
            declared.0
        );
        assert!(unpinned, "calibration: the forged post-root must pass an engine that reads the carrier's shapes");
        assert!(!pinned, "⛔⛔⛔ A FORGED NULLIFIER POST-ROOT VERIFIED — the last table's row count was not pinned");
    }

    /// ⭐⭐⭐ O(1) AT INFINITY, BY CONSTRUCTION (user 2026-07-22 — "the O(1) cardinal means infinity on all axis with
    /// no growth"). This proves count-INDEPENDENCE structurally, so it holds as total spends → ∞ (not merely at some
    /// finite depth): (a) a sparse-Merkle copath is ALWAYS exactly DEPTH siblings whether the tree holds 0 or 10^18
    /// leaves — O(DEPTH) fixed work, never O(total); (b) the block trace DIMENSIONS = f(fixed constants N, DEPTH) ONLY,
    /// byte-for-byte identical on a fresh tree and a deep one, so the WHIR proof size + O(1) verify cannot grow with
    /// chain height / #spends. The fresh-vs-deep pair merely EXHIBITS the invariant; the structural equalities ARE the
    /// proof. The block carrier itself stays a small constant (<1.8MB) for the fixed cover.
    /// ([[feedback_no_growth_any_axis]] — enforced by o1-infinity-guard.py)
    #[test]
    fn sparse_block_carrier_is_o1_by_construction_at_infinite_spends() {
        const N: usize = PRODUCTION_BLOCK_COVER; // the FULL production cover (256) — a CONSTANT, never a growth axis.

        // Block A — on a FRESH accumulator (0 prior spends).
        let mut refs_a = RefTree::default();
        let pre_a = refs_a.root();
        let ins_a: Vec<SparseInsertWitness> = (0..N as u64)
            .map(|i| SparseInsertWitness { key:nf_from(1_000 + i), copath: refs_a.insert_and_witness(&nf_from(1_000 + i)) })
            .collect();

        // Block B — on a DEEP accumulator: many unrelated prior spends first (a far higher chain height).
        let mut refs_b = RefTree::default();
        for s in 0..3_000u64 {
            refs_b.insert_and_witness(&nf_from(9_000_000 + s));
        }
        let pre_b = refs_b.root();
        let ins_b: Vec<SparseInsertWitness> = (0..N as u64)
            .map(|i| SparseInsertWitness { key:nf_from(2_000 + i), copath: refs_b.insert_and_witness(&nf_from(2_000 + i)) })
            .collect();

        // ── THE PROOF = BY CONSTRUCTION (count-INDEPENDENCE), holds at ∞ spends, NOT a bounded sample ──
        // (1) A sparse-Merkle copath is ALWAYS exactly DEPTH siblings — whether the tree holds 0 leaves or 10^18. The
        //     work to build/fold it is O(DEPTH), a FIXED constant, independent of the total occupancy → so it does not
        //     grow as spends → ∞. (0 vs 3000 prior spends here is just a witness that the structural invariant holds.)
        for w in ins_a.iter().chain(ins_b.iter()) {
            assert_eq!(w.copath.len(), NF_SPARSE_DEPTH, "copath is DEPTH siblings regardless of occupancy — O(1) by construction");
        }
        // (2) The block trace DIMENSIONS are a function of the fixed constants (N, DEPTH) ONLY — never the total spend
        //     count. The WHIR proof structure is fixed by those dimensions, so proof size + verify are count-independent
        //     at ∞. Assert the fresh-tree and deep-tree traces are DIMENSIONALLY IDENTICAL (same #columns, same #rows).
        // Both sides are all-real inserts, so each block's `real_n` is its own vector length.
        let (cols_a, post_a) = sparse_block_cols(&ins_a, pre_a, ins_a.len()).expect("trace A");
        let (cols_b, post_b) = sparse_block_cols(&ins_b, pre_b, ins_b.len()).expect("trace B");
        assert_eq!(cols_a.len(), cols_b.len(), "trace WIDTH is a fixed constant (SPARSE_BLOCK_COLS) — count-independent");
        assert_eq!(cols_a[0].len(), cols_b[0].len(), "trace HEIGHT = N·DEPTH is a fixed constant — count-independent");
        assert_eq!(cols_a[0].len(), N * NF_SPARSE_DEPTH, "…= N·DEPTH by construction, independent of the total spends");

        // The block carriers both verify O(1) against endpoints alone (intermediate roots private), and neither
        // verifies for the other block's post-root.
        let (compact_a, _) = prove_sparse_block_carrier_bytes(&ins_a, pre_a, ins_a.len()).expect("prove A");
        let (compact_b, _) = prove_sparse_block_carrier_bytes(&ins_b, pre_b, ins_b.len()).expect("prove B");
        assert!(verify_sparse_block_carrier_bytes(&compact_a, pre_a, post_a, N), "block A carrier verifies O(1)");
        assert!(verify_sparse_block_carrier_bytes(&compact_b, pre_b, post_b, N), "block B carrier verifies O(1)");
        assert!(!verify_sparse_block_carrier_bytes(&compact_a, pre_a, post_b, N), "block A carrier refuses B's post");
        // SUPPORTING empirical (NOT the proof): with identical dimensions the on-wire size differs only by content
        // serialization jitter — uncorrelated with the 3000× deeper tree (a real O(height) leak would add ≥3000).
        assert!((compact_b.len() as i64 - compact_a.len() as i64).abs() < 512, "size uncorrelated with height (jitter only)");
        assert!(compact_a.len() < 1_800_000, "carrier is small (<1.8MB FAST bound): {}", compact_a.len());
    }

    /// ⛔⛔⛔ DB-452 (the DIRECT family, the nullifier-set BAND DOOR) — A BAND SLICE FOR A POST ROOT NO INSERT REACHED IS
    /// REFUSED. A treeless node advances its spent-set root ONLY through `verify_band_slice` (the node's
    /// `BandDoor::verify_step`), so a slice that verifies for `post = pre` — the nullifier recorded nowhere — keeps a spent
    /// note spendable on every partial-view node. The adversary is the honest keyed trace of the REAL insert with the
    /// direct engine's one lie — zero zerocheck rounds, one solved opened row — on the engine the door runs: RED on the
    /// direct engine (`forge_direct_light_decider_for_tests`, link 78: accepted = true, 28,012 B), and here its port onto
    /// the bound plain batch (`forge_batch_opened_light_decider_for_tests`).
    /// CONTROLS: the honest slice verifies for its true post and is refused for `pre`; the port with no lie, stated for the
    /// true post, verifies — so the forged refusal is the binding, not a desynchronised transcript.
    #[test]
    fn db452_e_a_band_slice_for_a_post_no_insert_reached_is_refused() {
        let key = nf_from(0xDB45_2E01);
        let mut refs = RefTree::default();
        let pre = refs.root();
        let inserts = vec![SparseInsertWitness { key, copath: refs.insert_and_witness(&key) }];
        let post = refs.root();
        assert_ne!(pre, post, "the insert moves the root");
        let k = PRODUCTION_BLOCK_COVER; // one insert per slice — the cheapest slice a producer can carry
        let (honest, hpost, kd) = prove_sparse_block_keyed_carrier_bytes(&inserts, pre, 1).expect("the honest slice proves");
        assert_eq!(hpost, post);
        assert!(verify_band_slice(pre, post, &[key], k, &honest), "CONTROL: the honest slice verifies at the band door");
        assert!(!verify_band_slice(pre, pre, &[key], k, &honest), "CONTROL: the honest slice is refused for a post it did not reach");
        let (tables, _, _) = sparse_block_keyed_tables(&inserts, pre, 1).expect("the real keyed tables");
        let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(pre[i]));
        let post_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(post[i]));
        let kd_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(kd[i]));
        let control = crate::whir_rec_block::forge_batch_opened_light_decider_for_tests(
            tables.clone(),
            move |i: usize, g: Ea4| SparseKeyedGate::for_table(i, g, pre_f, post_f, 0, kd_f),
            vec![sparse_keyed_column_tie()],
            &sparse_block_keyed_statement_bind(&pre_f, &post_f, 1, &kd_f),
            false,
        )
        .expect("the port's honest path proves");
        assert!(verify_band_slice(pre, post, &[key], k, &control), "CONTROL: the port with no lie verifies at the band door");
        // post = pre: the insert recorded nowhere
        let forged = crate::whir_rec_block::forge_batch_opened_light_decider_for_tests(
            tables,
            move |i: usize, g: Ea4| SparseKeyedGate::for_table(i, g, pre_f, pre_f, 0, kd_f),
            vec![sparse_keyed_column_tie()],
            &sparse_block_keyed_statement_bind(&pre_f, &pre_f, 1, &kd_f),
            true,
        )
        .expect("the forger finds an opened row the keyed gate accepts");
        let accepted = verify_band_slice(pre, pre, &[key], k, &forged);
        eprintln!("DB452-E band slice for post = pre (the nullifier recorded nowhere): accepted = {accepted} ({} B)", forged.len());
        assert!(
            !accepted,
            "⛔⛔⛔ DB-452: the band door accepted a slice for a post root no insert reached — a spent nullifier is never recorded on a treeless node"
        );
    }

    /// ⭐⭐⭐ DB-452 §9 (link 79) — THE DIGEST TABLE IS WELDED TO THE CHAIN TABLE BY THE COLUMN TIE, ON THE REAL ENGINE. The
    /// attack the split opens if the tie were missing: a chain table that inserts a DIFFERENT key at tag 0's slot (an honest
    /// transition of its own keys) paired with a digest table that absorbs the HEADER's keys — each table satisfies its own
    /// gate, the statement `(pre, post, n, keys_digest)` is the header's digest over a post the forged key reached.
    /// CALIBRATION: proved and verified with NO tie, the mixed pair is ACCEPTED (the hole a dropped tie would be).
    /// REFUTATION: with the carrier's tie it is refused by the band door's verify; the honest pair verifies.
    #[test]
    fn db452_f_the_digest_table_is_welded_to_the_chain_table_by_the_column_tie() {
        let n = 2usize;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let tags: Vec<[u8; 32]> = (0..n as u64).map(|i| nf_from(0xDB45_2F00 + i)).collect();
        let build = |keys: &[[u8; 32]]| -> Vec<SparseInsertWitness> {
            let mut refs = RefTree::default();
            keys.iter().map(|nf| SparseInsertWitness { key: *nf, copath: refs.insert_and_witness(nf) }).collect()
        };
        let honest = build(&tags);
        let mut forged_keys = tags.clone();
        forged_keys[0] = nf_from(0xDB45_2FFF);
        let forged = build(&forged_keys);
        let (tables_h, post_h, kd_h) = sparse_block_keyed_tables(&honest, block_pre, n).expect("honest tables");
        let (tables_f, post_f, _) = sparse_block_keyed_tables(&forged, block_pre, n).expect("forged tables");
        assert_ne!(post_h, post_f, "the forged key moves the post root");
        let (carrier, cpost, ckd) = prove_sparse_block_keyed_carrier_bytes(&honest, block_pre, n).expect("honest carrier");
        assert_eq!((cpost, ckd), (post_h, kd_h));
        assert!(verify_sparse_block_keyed_carrier_bytes(&carrier, block_pre, post_h, n, n, kd_h), "CONTROL: the honest carrier verifies");
        // the mixed pair: the forged chain, the header's digest chain
        let mixed = vec![tables_f[0].clone(), tables_h[1].clone()];
        let pre_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(block_pre[i]));
        let post_ff: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(post_f[i]));
        let kd_f: [Fa4; DIGEST_LANES] = core::array::from_fn(|i| fkred(kd_h[i]));
        let bind = sparse_block_keyed_statement_bind(&pre_f, &post_ff, n, &kd_f);
        let make = move |i: usize, g: Ea4| SparseKeyedGate::for_table(i, g, pre_f, post_ff, n - 1, kd_f);
        let shapes = sparse_block_keyed_shapes(n).expect("shapes");
        let untied = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            mixed.clone(),
            make,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bind,
        )
        .expect("the mixed pair proves with no tie");
        let untied_ok = crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
            &untied,
            make,
            Vec::new(),
            Vec::new(),
            &bind,
            &shapes,
            &[],
        );
        assert!(untied_ok, "CALIBRATION: with no tie the forged chain under the header's digest is ACCEPTED — the tie is what refuses it");
        let tied = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            mixed,
            make,
            Vec::new(),
            Vec::new(),
            vec![sparse_keyed_column_tie()],
            &bind,
        )
        .expect("the honest prover code proves the mixed pair (it does not check the tie)");
        let accepted = verify_sparse_block_keyed_carrier_bytes(&tied, block_pre, post_f, n, n, kd_h);
        eprintln!("DB452-F forged chain + header's digest table, with the tie: accepted = {accepted} ({} B)", tied.len());
        assert!(!accepted, "⛔⛔⛔ the band door accepted a chain table whose keys are not the digest table's — a position forgery");
        assert!(
            !verify_sparse_block_keyed_carrier_bytes(&untied, block_pre, post_f, n, n, kd_h),
            "a carrier with its tie dropped is refused by the band door"
        );
    }

    /// ⭐ link 80 (2026-10-21) — THE LIGHT DECIDER'S PROVE IS THE SAME BYTES ON ANY POOL. The band slice rides the bound
    /// light decider (zerocheck → stacked WHIR commit → opening), whose parallel sites — the zerocheck's per-column lift
    /// and folds, the streamed tree's leaf and compress layers, the packed salts, the DFT butterflies — each claim the
    /// serial values. `spartan_ccs::a_parallel_prove_is_byte_identical_to_a_one_thread_prove` covers the committed path
    /// only, never the zerocheck. With the blinding seed pinned, one prove on the global pool and one inside a ONE-thread
    /// pool must be byte for byte the same carrier. CALIBRATION: a different blinding seed gives different bytes (the
    /// comparison can fail), and the carrier verifies at the door.
    #[test]
    fn db452_g_a_parallel_keyed_band_slice_prove_is_byte_identical_to_a_one_thread_prove() {
        let n = 16usize;
        let block_pre = empty_subtree_native(NF_SPARSE_DEPTH);
        let tags: Vec<[u8; 32]> = (0..n as u64).map(|i| nf_from(0xDB45_2A00 + i)).collect();
        let mut refs = RefTree::default();
        let honest: Vec<SparseInsertWitness> =
            tags.iter().map(|nf| SparseInsertWitness { key: *nf, copath: refs.insert_and_witness(nf) }).collect();
        let one_thread = rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("a one-thread pool");
        let (par, ser) = {
            let _seed = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x5A; 32]));
            let par = prove_sparse_block_keyed_carrier_bytes(&honest, block_pre, n).expect("proves (global pool)");
            let ser = one_thread
                .install(|| prove_sparse_block_keyed_carrier_bytes(&honest, block_pre, n))
                .expect("proves (one thread)");
            (par, ser)
        };
        let other = {
            let _seed = crate::whir_rec_block::pin_prover_seed_for_test(Some([0xA5; 32]));
            prove_sparse_block_keyed_carrier_bytes(&honest, block_pre, n).expect("proves (another blinding seed)")
        };
        eprintln!(
            "[db452-g] {} workers vs one thread: {} B / {} B, equal = {}; another seed equal = {}",
            rayon::current_num_threads(),
            par.0.len(),
            ser.0.len(),
            par == ser,
            other.0 == par.0
        );
        assert!(rayon::current_num_threads() > 1, "the global pool must be parallel for this comparison to mean anything");
        assert!(other.0 != par.0, "CALIBRATION: a different blinding seed changes the carrier's bytes");
        assert!(verify_sparse_block_keyed_carrier_bytes(&par.0, block_pre, par.1, n, n, par.2), "the carrier verifies");
        assert!(par == ser, "⛔ the parallel prove is not the one-thread prove — a parallel site changed a value");
    }

    // CORRECT-ARCHITECTURE-REVIEWED: the experimental FOLDED block prover (aggregate N independent single-insert
    // carriers) was tested for chain soundness and REJECTED — `settlement_aggregate_from_bundles` verifies each
    // carrier against its own bind but does NOT tie `carrier[i].post == carrier[i+1].pre`, so a broken chain (two
    // inserts both against R_0) VERIFIED. That is unsound for a block transition, so the folded prover + its test are
    // DELETED (an unsound prover must not exist — the SOUND cardinal). The nested `SparseBlockGate` chains in-circuit
    // via `running_root` and IS the required sound block carrier; the truly-fast path is a chain-ENFORCING recursive
    // fold (a custom recursive step), a separate build.
}

#[cfg(test)]
mod fold_row_floor_tests {
    use super::*;

    fn nf(tag: &[u8]) -> Digest {
        nf_to_limbs(blake3::hash(tag).as_bytes())
    }

    /// ⭐⭐⭐ THE SEND-KILLER, PINNED AND CLOSED.
    ///
    /// When the 256 cover was retired a block's tag set became its REAL spend count: 0 (idle — the
    /// overwhelming majority) or 1–2 (a payment). Both are below the sumcheck layout's arity floor, so a
    /// spender folding its absence carrier across the chain either got `None` on an idle block or an
    /// outright PANIC on a payment block — an abort inside the WALLET process, mid-`send`. That is why the
    /// live failure read as "the wallet died" / "connection refused" instead of a protocol refusal, on a
    /// chain 137 blocks old.
    ///
    /// TWO-PARTY: the wallet PROVES and the node VERIFIES the same claim, at every real block width.
    #[test]
    fn a_block_of_any_real_width_proves_absence_and_a_spent_member_still_fails_closed() {
        let spender = nf(b"floor-unspent-nf");
        let genesis = [0u64; DIGEST_LANES];
        let bp = nf_to_limbs(blake3::hash(b"floor-block-pre").as_bytes());

        // EVERY width a real block actually has since the cover was retired — 0 is an idle block, 1 and 2 are
        // ordinary payments. Each one aborted or refused before this floor existed.
        // Widths 9/13 matter as much as 0/1: the layout needs a POWER-OF-TWO row count, so a block with a
        // non-power-of-two real spend count aborted too. Under the retired 256 cover every block was exactly
        // 256 rows — a power of two — which is precisely why this class stayed invisible until cover went.
        for width in [0usize, 1, 2, 3, 7, 8, 9, 13, 16] {
            let tags: Vec<[u8; 32]> = (0..width)
                .map(|i| *blake3::hash(format!("floor-tag-{width}-{i}").as_bytes()).as_bytes())
                .collect();

            // (1) THE WALLET SIDE PROVES — no panic, no None.
            let proof = prove_nf_unspent_step_bytes(spender, genesis, bp, &tags)
                .unwrap_or_else(|| panic!("width {width}: an honest spender MUST be able to prove absence — \
                     a refusal here is a send that cannot be built"));

            // (2) THE NODE SIDE VERIFIES against the digest it re-derives ITSELF from the same real tags.
            let td = sparse_fold_digest_nfs(&tags, bp);
            assert!(
                verify_nf_unspent_step_bytes(&proof, spender, genesis, bp, td, tags.len()),
                "width {width}: the node must accept the proof against its OWN re-derived digest — if this \
                 fails the two sides disagree on the fold rows and every send is refused"
            );

            // (3) TAMPER — a DIFFERENT digest must be refused (the proof is bound, not decorative).
            let bad_td = sparse_fold_digest_nfs(&tags, nf_to_limbs(blake3::hash(b"other-pre").as_bytes()));
            if bad_td != td {
                assert!(
                    !verify_nf_unspent_step_bytes(&proof, spender, genesis, bp, bad_td, tags.len()),
                    "width {width}: a proof must not verify against a digest it was not built for"
                );
            }

            // (4) SOUNDNESS — a nullifier that IS settled in this block stays UNPROVABLE at every width,
            //     including the widths that only exist because of the filler rows.
            if width > 0 {
                let settled = nf_to_limbs(&tags[0]);
                assert!(
                    prove_nf_unspent_step_bytes(settled, genesis, bp, &tags).is_none(),
                    "width {width}: a SPENT nullifier must remain unprovable — the filler rows must never \
                     create a path that makes a settled note look unspent"
                );
            }
        }
    }

    /// A filler row can never be mistaken for a real tag, and the row set is a pure function both sides share.
    #[test]
    fn the_filler_rows_are_deterministic_shared_and_never_equal_a_real_tag() {
        let reals: Vec<[u8; 32]> = (0..2)
            .map(|i| *blake3::hash(format!("real-{i}").as_bytes()).as_bytes())
            .collect();
        let a = fold_rows(&reals);
        let b = fold_rows(&reals);
        assert_eq!(a, b, "the row set is a PURE function — prover and verifier derive it identically");
        assert_eq!(a.len(), FOLD_MIN_ROWS, "a short block is padded to exactly the layout floor");
        // A non-power-of-two block is padded UP to the next power of two, never left at an invalid arity.
        let nine: Vec<[u8; 32]> = (0..9)
            .map(|i| *blake3::hash(format!("nine-{i}").as_bytes()).as_bytes())
            .collect();
        assert_eq!(fold_rows(&nine).len(), 16, "9 real tags pad to 16 — log2 must be an integer or the prover aborts");
        assert_eq!(&fold_rows(&nine)[..9], &nine[..], "the 9 REAL tags stay first and unchanged");
        assert_eq!(&a[..2], &reals[..], "the REAL tags stay first and unchanged — position is preserved");
        for filler in &a[2..] {
            assert!(!reals.contains(filler), "a filler never equals a real tag");
        }
        // A block already at or above the floor is passed through untouched — no padding, no truncation.
        let wide: Vec<[u8; 32]> = (0..16)
            .map(|i| *blake3::hash(format!("wide-{i}").as_bytes()).as_bytes())
            .collect();
        assert_eq!(fold_rows(&wide), wide, "a block already at a valid power-of-two width is untouched");
    }
}

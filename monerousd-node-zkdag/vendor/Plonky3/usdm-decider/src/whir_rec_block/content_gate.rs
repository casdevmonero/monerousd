// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CONTENT PROOF — "the key behind this delivery lock opens these sealed blocks to the content the offer names"
//! (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §3.3: downloads, licenses, tickets, codes).
//!
//! A seller of digital content seals it under a key `k` and locks the buyer's vault with the delivery lock over that
//! same `k` ([`super::vault_gate`]): the spend that pays the seller publishes `k` to the buyer. This proof is what the
//! buyer checks BEFORE it locks any money: the key that the claim will publish is the key that opens the sealed
//! content, and the content it opens to is the one the offer names by its root. Borrowed shapes: Maxwell's
//! zero-knowledge contingent payment (2011) and, for large content, sampling a committed encoding as in FairSwap
//! (Dziembowski, Eckey, Faust, CCS 2018) with the check done in zero knowledge instead of by a judge.
//!
//! THE CONTENT'S SHAPE (all of it native, none of it on the chain):
//!
//! ```text
//! block j        = 30 bytes, as eight 30-bit lanes m_j                       (the last block zero-padded)
//! sealed block j = m_j + P([STREAM, j, 0…], [k 0..3, 0…])                    (lane by lane, in the field)
//! leaf j         = P([LEAF, j, 0…], m_j)
//! root           = P(merkle(leaf 0 … leaf n-1), [ROOT, byte length, n, 0…])  (what the offer names)
//! ```
//!
//! THE STATEMENT. Public: the seller's address key, the listing's salt, the listing's eight-lane delivery lock, and
//! for each listed block its index, its sealed lanes and its leaf. One row per listed block, each row on its own:
//!
//! ```text
//!     lock 1 ‖ lock 2 == P([CLAIM, 1, 1, 0, spk 0..3], [k, salt])            the key is the lock's
//!     leaf_j          == P([LEAF, j, 0…], sealed_j − P([STREAM, j, 0…], [k, 0…]))   and it opens block j to leaf j
//! ```
//!
//! Every row states the lock, so every row uses the one key the lock binds (eight lanes: two keys under one lock are
//! a 2^124 search). The listed blocks' public values enter as PUBLIC columns: the gate evaluates their multilinear
//! extensions at the zerocheck's own point, so there is nothing for a prover to choose. The verifier checks each
//! listed leaf against the offer's root itself ([`leaf_under_root`]).
//!
//! ONE PROOF PER LISTING. The lock is the listing's (the same for every buyer), so the seller makes this proof once,
//! when it lists, and every buyer checks the same bytes. A sale adds no proof: the buyer's wallet builds the vault
//! itself under the lock the offer states.
//!
//! WHAT IT NEVER SHOWS: the key or any plaintext lane (the columns are blinded). No node sees a proof and no chain
//! byte is written.
//!
//! cons: none on the chain. Off the chain three permutations a listed block; a row is [`CONTENT_WIDTH`] columns and
//! row-local (degree 3). Bytes and milliseconds are measured by `content_tests::the_content_proof_is_measured`.

use super::vault_gate::{delivery_claim_inputs, ListingSalt, VaultLock, VaultSecret, LOCK_LANES};
use super::*;

/// Domain word of a content proof's public bind ("CNTP").
pub const CONTENT_DOMAIN: u64 = 0x434E_5450;
/// Domain word of a keystream block ("CSTR"), of a leaf ("CLEF") and of a root ("CROT").
const STREAM_DOMAIN: u64 = 0x4353_5452;
const LEAF_DOMAIN: u64 = 0x434C_4546;
const ROOT_DOMAIN: u64 = 0x4352_4F54;
/// Bits of content one lane carries. A lane is a field value (the field is above 2^30).
// PRODUCTION-SCALE-REVIEWED: the content encoding's lane width, fixed by the field, not a count of anything.
pub const CONTENT_LANE_BITS: usize = 30;
/// Bytes of content one block carries: eight 30-bit lanes.
// PRODUCTION-SCALE-REVIEWED: the content encoding's block size (8 lanes x 30 bits), not a limit on content.
pub const CONTENT_BLOCK_BYTES: usize = DIGEST_LANES * CONTENT_LANE_BITS / 8;
/// The most blocks one content holds: a block index is one lane.
// PRODUCTION-SCALE-REVIEWED: the index lane's range (2^30 blocks, 32 GB of content), the same in production.
pub const CONTENT_MAX_BLOCKS: u64 = 1 << CONTENT_LANE_BITS;
/// The most blocks one proof lists. A longer list is several proofs.
// PRODUCTION-SCALE-REVIEWED: a bound on ONE off-chain statement's table (2^10 rows, 30 KB proven exactly), not a
// limit on content: larger content is proven by sampling.
pub const CONTENT_PROOF_MAX_ROWS: usize = 1024;

const P2: usize = crate::pow_pq_air::P2_COLS;
/// The lock's claim block.
const CG_LOCK_BLK: usize = 0;
/// The keystream block.
const CG_KS_BLK: usize = CG_LOCK_BLK + P2;
/// The leaf block.
const CG_LEAF_BLK: usize = CG_KS_BLK + P2;
/// The row's width: three permutation blocks and nothing else.
pub const CONTENT_WIDTH: usize = CG_LEAF_BLK + P2;

// ---- the content's native shape

/// Content as blocks of eight 30-bit lanes, low bit first, the last block zero-padded. Content of no bytes is one
/// block of zeros. `None` past [`CONTENT_MAX_BLOCKS`].
#[must_use]
pub fn content_blocks(bytes: &[u8]) -> Option<Vec<Digest>> {
    let n = bytes.len().div_ceil(CONTENT_BLOCK_BYTES).max(1);
    if n as u64 > CONTENT_MAX_BLOCKS {
        return None;
    }
    let bit = |i: usize| -> u64 { bytes.get(i / 8).map_or(0, |b| u64::from((b >> (i % 8)) & 1)) };
    Some(
        (0..n)
            .map(|j| core::array::from_fn(|c| (0..CONTENT_LANE_BITS).fold(0u64, |v, b| v | (bit((j * DIGEST_LANES + c) * CONTENT_LANE_BITS + b) << b))))
            .collect(),
    )
}

/// The content `blocks` hold, `len` bytes of it. `None` when a lane is not 30 bits, when `len` does not fit the
/// blocks, or when a bit past `len` is set (so one content has one encoding).
#[must_use]
pub fn content_bytes(blocks: &[Digest], len: u64) -> Option<Vec<u8>> {
    let len = usize::try_from(len).ok()?;
    if len.div_ceil(CONTENT_BLOCK_BYTES).max(1) != blocks.len() || blocks.iter().flatten().any(|l| *l >> CONTENT_LANE_BITS != 0) {
        return None;
    }
    let bit = |i: usize| -> u8 { ((blocks[i / (DIGEST_LANES * CONTENT_LANE_BITS)][(i / CONTENT_LANE_BITS) % DIGEST_LANES] >> (i % CONTENT_LANE_BITS)) & 1) as u8 };
    let total_bits = blocks.len() * DIGEST_LANES * CONTENT_LANE_BITS;
    if (len * 8..total_bits).any(|i| bit(i) != 0) {
        return None;
    }
    Some((0..len).map(|i| (0..8).fold(0u8, |v, b| v | (bit(i * 8 + b) << b))).collect())
}

fn stream_inputs(key: &VaultSecret, index: u64) -> (Digest, Digest) {
    let mut right = [0u64; DIGEST_LANES];
    right[..LOCK_LANES].copy_from_slice(key);
    (crate::poseidon2_compress::lanes_of(&[STREAM_DOMAIN, index]), right)
}

/// The keystream of block `index` under `key`.
#[must_use]
pub fn stream_block(key: &VaultSecret, index: u64) -> Digest {
    let (left, right) = stream_inputs(key, index);
    poseidon_pair(left, right)
}

/// Block `index` sealed under `key`: each lane plus its keystream lane, in the field.
#[must_use]
pub fn seal_block(block: &Digest, key: &VaultSecret, index: u64) -> Digest {
    use p3_field::PrimeField64;
    let ks = stream_block(key, index);
    core::array::from_fn(|c| (Fa4::from_u64(block[c]) + Fa4::from_u64(ks[c])).as_canonical_u64())
}

/// The block a sealed block opens to under `key`.
#[must_use]
pub fn open_block(sealed: &Digest, key: &VaultSecret, index: u64) -> Digest {
    use p3_field::PrimeField64;
    let ks = stream_block(key, index);
    core::array::from_fn(|c| (Fa4::from_u64(sealed[c]) - Fa4::from_u64(ks[c])).as_canonical_u64())
}

/// The leaf of block `index`.
#[must_use]
pub fn content_leaf(index: u64, block: &Digest) -> Digest {
    poseidon_pair(crate::poseidon2_compress::lanes_of(&[LEAF_DOMAIN, index]), *block)
}

/// The levels of the tree over `leaves`, the leaves first, padded with zero digests to a power of two.
fn tree_levels(leaves: &[Digest]) -> Vec<Vec<Digest>> {
    let mut level: Vec<Digest> = leaves.to_vec();
    level.resize(leaves.len().next_power_of_two().max(1), [0u64; DIGEST_LANES]);
    let mut levels = vec![level];
    while levels[levels.len() - 1].len() > 1 {
        let next: Vec<Digest> = levels[levels.len() - 1].chunks_exact(2).map(|p| poseidon_pair(p[0], p[1])).collect();
        levels.push(next);
    }
    levels
}

fn root_of(top: Digest, len: u64, blocks: u64) -> Digest {
    poseidon_pair(top, crate::poseidon2_compress::lanes_of(&[ROOT_DOMAIN, len & 0x3FFF_FFFF, len >> CONTENT_LANE_BITS, blocks & 0x3FFF_FFFF, blocks >> CONTENT_LANE_BITS]))
}

/// THE ROOT AN OFFER NAMES: the tree over the content's leaves, bound to its byte length and block count.
#[must_use]
pub fn content_root(leaves: &[Digest], len: u64) -> Digest {
    let levels = tree_levels(leaves);
    root_of(levels[levels.len() - 1][0], len, leaves.len() as u64)
}

/// The sibling path of leaf `index`, lowest level first.
#[must_use]
pub fn leaf_path(leaves: &[Digest], index: u64) -> Option<Vec<Digest>> {
    let i = usize::try_from(index).ok().filter(|i| *i < leaves.len())?;
    let levels = tree_levels(leaves);
    Some((0..levels.len() - 1).map(|l| levels[l][(i >> l) ^ 1]).collect())
}

/// Is `leaf` the leaf of block `index` under `root`, for content of `len` bytes? The path is the one [`leaf_path`]
/// gives; its length must be the tree's own depth for that length.
#[must_use]
pub fn leaf_under_root(leaf: &Digest, index: u64, path: &[Digest], len: u64, root: &Digest) -> bool {
    let blocks = len.div_ceil(CONTENT_BLOCK_BYTES as u64).max(1);
    if index >= blocks || blocks > CONTENT_MAX_BLOCKS || path.len() != blocks.next_power_of_two().trailing_zeros() as usize {
        return false;
    }
    let top = path.iter().enumerate().fold(*leaf, |h, (l, sib)| if (index >> l) & 1 == 0 { poseidon_pair(h, *sib) } else { poseidon_pair(*sib, h) });
    root_of(top, len, blocks) == *root
}

// ---- the statement

/// One listed block: its index, its sealed lanes, its leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentRow {
    pub index: u64,
    pub sealed: Digest,
    pub leaf: Digest,
}

/// What a content proof states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentStatement {
    /// The seller's address key: the party the delivery lock names.
    pub seller_spk: Digest,
    /// The listing's salt.
    pub salt: ListingSalt,
    /// The listing's delivery lock: lock 1, lock 2 of every vault that buys it.
    pub locks: [VaultLock; 2],
    /// The listed blocks, in the order the proof lays them.
    pub rows: Vec<ContentRow>,
    /// What the proof answers: the listing it is for (the offer's content root).
    pub context: Digest,
}

impl ContentStatement {
    /// Is the list one this class proves: at least one block, at most [`CONTENT_PROOF_MAX_ROWS`], every value a field
    /// value, no block named twice?
    fn well_formed(&self) -> bool {
        let field = |d: &[u64]| d.iter().all(|v| *v < <Fa4 as p3_field::PrimeField64>::ORDER_U64);
        let distinct: std::collections::HashSet<u64> = self.rows.iter().map(|r| r.index).collect();
        !self.rows.is_empty()
            && self.rows.len() <= CONTENT_PROOF_MAX_ROWS
            && distinct.len() == self.rows.len()
            && self.rows.iter().all(|r| r.index < CONTENT_MAX_BLOCKS && field(&r.sealed) && field(&r.leaf))
            && field(&self.seller_spk)
            && field(&self.salt)
            && field(&self.locks[0])
            && field(&self.locks[1])
    }

    /// The rows the table lays: the count padded to a power of two, never below the light carrier's.
    fn laid(&self) -> usize {
        self.rows.len().next_power_of_two().max(LIGHT_CARRIER_ROWS)
    }

    /// The listed block row `r` of the table states: a row past the list restates the last listed block.
    fn row(&self, r: usize) -> &ContentRow {
        &self.rows[r.min(self.rows.len() - 1)]
    }
}

/// The multilinear weights of a table's rows at `x` (row index high bit first): `(shift, low, w)`, where row
/// `(h << shift) | low` weighs `w[h]` and every other row weighs nothing. The trailing coordinates that are exactly 0
/// or 1 fix the row's low bits, so on the points a sumcheck prover visits the work is the size of the folded prefix,
/// never the table's.
pub(super) fn row_weights<F: p3_field::Field>(x: &[F]) -> (usize, usize, Vec<F>) {
    let (mut shift, mut low) = (0usize, 0usize);
    while shift < x.len() {
        let v = x[x.len() - 1 - shift];
        if v == F::ONE {
            low |= 1 << shift;
        } else if v != F::ZERO {
            break;
        }
        shift += 1;
    }
    let mut w: Vec<F> = vec![F::ONE];
    for xk in &x[..x.len() - shift] {
        let mut next = Vec::with_capacity(w.len() * 2);
        for v in &w {
            next.push(*v * (F::ONE - *xk));
            next.push(*v * *xk);
        }
        w = next;
    }
    (shift, low, w)
}

/// The public values of one row: the index, the sealed lanes, the leaf.
const PUB_LANES: usize = 1 + 2 * DIGEST_LANES;

#[derive(Clone)]
struct ContentGate {
    /// The powers of `gamma` the laws are batched with, one per law.
    gpow: Vec<Ea4>,
    /// log2 of the rows the table lays (the blinding half is one more variable, the point's first).
    data_vars: usize,
    /// The laid rows' public values.
    table: Vec<[Fa4; PUB_LANES]>,
    /// The lock block's left input, and the salt lanes of its right input.
    lock_left: [Fa4; DIGEST_LANES],
    salt: [Fa4; LOCK_LANES],
    /// The delivery lock: the lock block's whole output.
    lock: [Fa4; DIGEST_LANES],
}

impl ContentGate {
    fn of(st: &ContentStatement, gamma: Ea4) -> Self {
        let f = Fa4::from_u64;
        let (left, _) = delivery_claim_inputs(&st.seller_spk, &[0; LOCK_LANES], &st.salt);
        let table: Vec<[Fa4; PUB_LANES]> = (0..st.laid())
            .map(|r| {
                let row = st.row(r);
                core::array::from_fn(|i| match i {
                    0 => f(row.index),
                    i if i <= DIGEST_LANES => f(row.sealed[i - 1]),
                    i => f(row.leaf[i - 1 - DIGEST_LANES]),
                })
            })
            .collect();
        let laws = 3 * crate::pow_pq_air::perm_residual_count() + WELDS;
        let mut gpow = Vec::with_capacity(laws);
        let mut gp = Ea4::ONE;
        for _ in 0..laws {
            gpow.push(gp);
            gp *= gamma;
        }
        ContentGate {
            gpow,
            data_vars: st.laid().trailing_zeros() as usize,
            table,
            lock_left: core::array::from_fn(|c| f(left[c])),
            salt: core::array::from_fn(|c| f(st.salt[c])),
            lock: core::array::from_fn(|c| f(if c < LOCK_LANES { st.locks[0][c] } else { st.locks[1][c - LOCK_LANES] })),
        }
    }

    /// Every law of the row, unbatched, in the row's own field. `x[0]` is the blinding half's variable; the rest
    /// index the laid rows, high bit first.
    fn laws<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, local: &crate::air_zerocheck::Row<'_, F>, x: &[F]) -> Vec<F> {
        if x.len() != self.data_vars + 1 || self.table.len() != (1usize << self.data_vars) {
            // a point of another shape is not this class's: one law that never holds
            return vec![F::ONE];
        }
        let k = |v: Fa4| -> F { F::from(v) };
        // the row's public values at this point
        let (shift, low, w) = row_weights(&x[1..]);
        let mut pubv = [F::ZERO; PUB_LANES];
        for (h, wh) in w.iter().enumerate() {
            let row = &self.table[(h << shift) | low];
            for (p, v) in pubv.iter_mut().zip(row) {
                *p += *wh * k(*v);
            }
        }
        let (index, sealed, leaf) = (pubv[0], &pubv[1..1 + DIGEST_LANES], &pubv[1 + DIGEST_LANES..]);
        let out = crate::pow_pq_air::PERM_OUT;
        let mut rs: Vec<F> = Vec::with_capacity(self.gpow.len());
        for blk in [CG_LOCK_BLK, CG_KS_BLK, CG_LEAF_BLK] {
            crate::pow_pq_air::push_perm_residuals(local, blk, &mut rs);
        }
        for c in 0..DIGEST_LANES {
            let word = |domain: u64| -> F {
                match c {
                    0 => k(Fa4::from_u64(domain)),
                    1 => index,
                    _ => F::ZERO,
                }
            };
            // the lock: P([CLAIM, 1, 1, 0, spk], [k, salt]) is the listing's eight-lane delivery lock
            rs.push(local[CG_LOCK_BLK + c] - k(self.lock_left[c]));
            let key_or_salt = if c < LOCK_LANES { local[CG_KS_BLK + DIGEST_LANES + c] } else { k(self.salt[c - LOCK_LANES]) };
            rs.push(local[CG_LOCK_BLK + DIGEST_LANES + c] - key_or_salt);
            rs.push(local[CG_LOCK_BLK + out + c] - k(self.lock[c]));
            // the keystream: P([STREAM, j, 0…], [k, 0…]); the key lanes are the lock's (welded above)
            rs.push(local[CG_KS_BLK + c] - word(STREAM_DOMAIN));
            if c >= LOCK_LANES {
                rs.push(local[CG_KS_BLK + DIGEST_LANES + c]);
            }
            // the leaf: P([LEAF, j, 0…], sealed − keystream) is the listed leaf
            rs.push(local[CG_LEAF_BLK + c] - word(LEAF_DOMAIN));
            rs.push(local[CG_LEAF_BLK + DIGEST_LANES + c] - (sealed[c] - local[CG_KS_BLK + out + c]));
            rs.push(local[CG_LEAF_BLK + out + c] - leaf[c]);
        }
        rs
    }
}

/// The welds [`ContentGate::laws`] pushes after the three blocks: seven a lane, and one more for each keystream input
/// lane past the key.
// PRODUCTION-SCALE-REVIEWED: a count of the laws written in `laws`, read by its γ-power table; not a limit.
const WELDS: usize = 7 * DIGEST_LANES + (DIGEST_LANES - LOCK_LANES);

impl crate::air_zerocheck::AirConstraint for ContentGate {
    /// The three blocks are cubes applied inline and every weld is affine in the cells and in the point.
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let rs = self.laws::<Ea4>(local, x);
        if rs.len() != self.gpow.len() {
            return Ea4::ONE;
        }
        rs.into_iter().zip(&self.gpow).fold(Ea4::ZERO, |acc, (r, g)| acc + *g * r)
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        self.laws::<Ea4>(local, x)
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, _at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let rs = self.laws::<Fa4>(local, x);
        if rs.len() != self.gpow.len() {
            return Ea4::ONE;
        }
        rs.into_iter().zip(&self.gpow).fold(Ea4::ZERO, |acc, (r, g)| acc + *g * r)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
    /// The key lanes are HIDING witnesses read by the lock's input weld; no column is free.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

fn content_bind(st: &ContentStatement) -> Vec<Fa4> {
    let f = Fa4::from_u64;
    let mut b = vec![f(CONTENT_DOMAIN), f(st.rows.len() as u64)];
    b.extend(st.seller_spk.iter().chain(&st.salt).chain(&st.locks[0]).chain(&st.locks[1]).chain(&st.context).map(|v| f(*v)));
    for r in &st.rows {
        b.push(f(r.index));
        b.extend(r.sealed.iter().chain(&r.leaf).map(|v| f(*v)));
    }
    b
}

/// The table for `st` under `key`, laid exactly as given (no check that it is true: the gate decides).
fn content_cols(st: &ContentStatement, key: &VaultSecret) -> Vec<Vec<Fa4>> {
    let (lock_left, lock_right) = delivery_claim_inputs(&st.seller_spk, key, &st.salt);
    let mut table: Vec<Vec<Fa4>> = Vec::with_capacity(st.laid());
    for r in 0..st.laid() {
        let listed = st.row(r);
        let mut row = vec![Fa4::ZERO; CONTENT_WIDTH];
        crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_LOCK_BLK, pose_state(&to_f(&lock_left), &to_f(&lock_right)));
        let (ks_left, ks_right) = stream_inputs(key, listed.index);
        crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_KS_BLK, pose_state(&to_f(&ks_left), &to_f(&ks_right)));
        let ks: DigestF = core::array::from_fn(|c| row[CG_KS_BLK + crate::pow_pq_air::PERM_OUT + c]);
        let block: DigestF = core::array::from_fn(|c| Fa4::from_u64(listed.sealed[c]) - ks[c]);
        crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_LEAF_BLK, pose_state(&to_f(&crate::poseidon2_compress::lanes_of(&[LEAF_DOMAIN, listed.index])), &block));
        table.push(row);
    }
    (0..CONTENT_WIDTH).map(|c| table.iter().map(|row| row[c]).collect()).collect()
}

/// PROVE: the seller, holding `key`, shows `st` to every buyer of the listing. `None` when `key` is not the key of the statement's
/// lock, when a listed block does not open to its listed leaf, or when the list is not one this class proves (never a
/// proof of a false statement).
#[must_use]
pub fn prove_content(st: &ContentStatement, key: &VaultSecret) -> Option<Vec<u8>> {
    if !st.well_formed() || super::vault_gate::delivery_locks(&st.seller_spk, key, &st.salt) != st.locks {
        return None;
    }
    if st.rows.iter().any(|r| content_leaf(r.index, &open_block(&r.sealed, key, r.index)) != r.leaf) {
        return None;
    }
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_bytes(content_cols(st, key), move |g: Ea4| ContentGate::of(&st2, g), &content_bind(st))
}

/// VERIFY a content proof against the statement the buyer itself wrote down: the lock and salt the offer states, the
/// sealed lanes it holds, the leaves it checked against the offer's root. True means: one key is the key of the
/// listing's delivery lock AND opens every listed sealed block to its listed leaf.
#[must_use]
pub fn verify_content(bytes: &[u8], st: &ContentStatement) -> bool {
    if bytes.is_empty() || !st.well_formed() {
        return false;
    }
    let st2 = st.clone();
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        move |g: Ea4| ContentGate::of(&st2, g),
        &content_bind(st),
        (st.laid().trailing_zeros() as usize, CONTENT_WIDTH),
    )
}

#[cfg(test)]
mod content_tests;

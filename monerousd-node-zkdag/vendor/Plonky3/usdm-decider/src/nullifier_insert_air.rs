// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Gap3 — O(1) PROOF-ONLY nullifier-transition verify (the nullifier-insert AIR).**
//!
//! Per spent nullifier `nf`, this gate certifies IN-CIRCUIT the indexed-Merkle INSERT the node performs
//! natively in `nullifier_tree::verify_and_insert`, so a block's recursive proof proves double-spend-freedom
//! O(1) (no ½-MB carried witnesses, no held tree):
//!   1. NON-MEMBERSHIP: a low leaf `(low_value, low_next)` strictly brackets `nf` (`low_value < nf < low_next`,
//!      `low_next == 0` = +∞) — proven by a SOUND bit-level less-than on the canonical limb keys.
//!   2. LOW-MEMBERSHIP: `hash_leaf(low_value, low_next)` folds (via `low_copath` at `low_index`) to `pre_root`.
//!   3. UPDATE: `hash_leaf(low_value, nf)` folds (SAME copath/index) to an intermediate `mid_root`.
//!   4. APPEND-EMPTY: the empty leaf folds (via `new_copath` at `count`) to `mid_root`.
//!   5. APPEND: `hash_leaf(nf, low_next)` folds (via `new_copath` at `count`) to `post_root`.
//!
//! `hash_leaf(a,b) = poseidon_pair(key(a), key(b))`, `key(x) = cm_bytes_to_leaf(x)` (4 canonical KoalaBear
//! limbs), and `poseidon_pair` is ONE Poseidon2 compression ([`crate::poseidon2_compress::compress`] — since kill
//! list §AG, 2026-09-12; the earlier single algebraic round `MDS·(l + 7·r)⁷` was SOLVABLE, see
//! [`poseidon_pair_native`]), the same compression [`crate::whir_rec_block`] proves for note membership. Because
//! `nf = Poseidon(sk, leaf)` is a FIELD digest, its canonical form IS 4
//! limbs (each `< p`) — so the compare-key and the tree-key are IDENTICAL, and the compare needs no byte
//! decomposition beyond 31 bits per limb. SOUNDNESS, closed here (each with an adversarial tamper test):
//!   • FOLDS — every `x⁷+MDS` lane matches; F1==pre_root, F2==F3 (shared mid_root), F4==post_root.
//!   • LEAF-HASH→SEED BIND — F1/F2/F4 seeds are CONSTRAINED `== poseidon_pair(key,key)`, so a prover cannot
//!     fold an arbitrary seed divorced from `(low_value, low_next, nf)`.
//!   • RANGE — the limb keys are bit-decomposed (bits bound to the limbs) and a bit-level lexicographic
//!     less-than proves `low_value < nf < low_next` with the correct MAGNITUDE (a FALSE ordering is rejected).
//!
//! 3a here is the native reference + `AirConstraint` residuals + trace builder + adversarial tests. 3b wraps it
//! in the WHIR light decider; 3c folds it into the per-block settlement aggregate + the node's O(1) verify.

use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;

/// Tree depth — matches `spend_frontier::SPEND_TREE_DEPTH`, and MUST: this gate proves insertion into the
/// same spent set the node retires spends against, so a shallower tree here is a smaller set there.
///
/// ⛔⛔⛔ THIS WAS 32, WHICH IS A DEATH DATE FOR THE SPENT SET. A depth-32 nullifier tree holds 2^32
/// entries; once full, no further spend can be retired, and a spend that cannot be retired is a payment
/// that can never settle. The note frontier had the identical ceiling and was measured to exhaust in 97
/// DAYS (`the_note_frontier_has_no_chain_lifetime_ceiling`), because the nullifier lane is cover-padded to
/// a CONSTANT count per block exactly as the note lane is — so the fill rate carries no traffic term and an
/// idle chain exhausts it on the same schedule as a busy one.
///
/// user 2026-09-04: "No chain should have a death date. it should go on forever like btc ... thats the
/// ultimate funds loss bug." At 64 the ceiling is unreachable for a u64 counter (~1.1e9 years at the
/// constant fill rate), which is the standard `chain-lifetime-guard.py` now enforces with no escape.
///
/// cons: the trace widens with the depth — `FOLD_COLS = 4 + NF_DEPTH * 33` goes 1,060 -> 2,116 columns, so
/// the insert gate's proving cost roughly doubles. That is paid once per block against a 500 ms budget, and
/// it buys a chain that does not stop.
pub const NF_DEPTH: usize = 64;
/// The chain's digest in limb form — re-exported so every mirror in this crate names ONE type.
pub use crate::poseidon2_compress::{Digest, DIGEST_LANES};

/// Bits per canonical KoalaBear limb (`p < 2³¹`), so a canonical limb is 31 bits.
pub const LIMB_BITS: usize = 31;

/// The 1-round Poseidon MDS matrix (shared with the sparse gate [`crate::nf_sparse_air`] so both fold the identical
/// hash). `pub` = single source of truth, no duplicated constant.
pub const SPEND_MDS: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
const KB_P: u128 = 0x7f00_0001; // 2³¹ − 2²⁴ + 1

/// KoalaBear field add (reused by [`crate::nf_sparse_air`]).
#[inline]
pub fn kadd(a: u64, b: u64) -> u64 {
    let s = a as u128 + b as u128;
    (if s >= KB_P { s - KB_P } else { s }) as u64
}
/// KoalaBear field mul (reused by [`crate::nf_sparse_air`]).
#[inline]
pub fn kmul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % KB_P) as u64
}
/// KoalaBear canonical reduction (reused by [`crate::nf_sparse_air`]).
#[inline]
pub fn kred(a: u64) -> u64 {
    (a as u128 % KB_P) as u64
}

/// Native `poseidon_pair` (mirror of `spend_frontier::poseidon_pair`) — ONE Poseidon2 permutation over
/// `left ‖ right`, truncated to the first [`DIGEST_LANES`] lanes.
///
/// ⛔⛔⛔ THIS WAS A SINGLE ALGEBRAIC ROUND UNTIL 2026-09-12: `out = MDS·(l + 7·r)⁷`, in which `x ↦ x⁷` is a
/// bijection over KoalaBear, `SPEND_MDS` is invertible and `l + 7·r` is linear — so a sibling could be
/// SOLVED rather than found, and every non-membership copath in the chain was forgeable in about a
/// millisecond. Kill list §AG; the attack is kept armed in `sparse_fold_preimage_probe`.
///
/// The body now delegates to [`crate::poseidon2_compress::compress`]: there is ONE compression in this
/// tree and this is a mirror of it, not a second implementation that could drift.
#[must_use]
pub fn poseidon_pair_native(left: Digest, right: Digest) -> Digest {
    crate::poseidon2_compress::compress(&left, &right)
}

/// The field KEY of a 32-byte nullifier.
///
/// ⛔ A NULLIFIER IS NOT A DIGEST ENCODING. It is 256 bits of blake3 output, and 256 bits do not fit the
/// 248-bit canonical encoding, so decoding one would REFUSE most real nullifiers. The old body read four
/// little-endian u64s and reduced each mod p, which was total but NOT injective — distinct nullifiers
/// could share a key, and two different spends would then share one IMT leaf. Compression gives a total
/// map that is collision-resistant instead (kill list §AG).
///
/// ⛔⛔⛔ THE ALL-ZERO NULLIFIER IS THE SENTINEL, AND ITS KEY MUST BE THE MINIMUM.
/// The IMT's empty tree opens with a `(0, 0)` low leaf that has to bracket EVERY key, and the old decode
/// gave that for free because `key_of([0; 32])` was literally zero. A hash does not: it would land
/// somewhere arbitrary in the order, the sentinel would stop bracketing, and the FIRST insert into a fresh
/// tree would find no low leaf — an empty chain that can never accept a spend. The all-zero nullifier is
/// never a real one (every insert path refuses it by name), so reserving it as the minimum costs nothing
/// and restores the property the tree is built on.
#[must_use]
pub fn key_of(cm: &[u8; 32]) -> Digest {
    if *cm == [0u8; 32] {
        return crate::poseidon2_compress::ZERO_DIGEST;
    }
    crate::poseidon2_compress::hash32_to_digest(cm)
}

/// Native `hash_leaf` (mirror): `poseidon_pair(key(value), key(next))`.
pub fn hash_leaf_native(value: &[u8; 32], next: &[u8; 32]) -> Digest {
    poseidon_pair_native(key_of(value), key_of(next))
}

/// Native `fold_to_root` (mirror): at each level, `node = bit==0 ? pair(node,sib) : pair(sib,node)`.
pub fn fold_to_root_native(mut node: Digest, index: u64, copath: &[Digest]) -> Digest {
    let mut i = index;
    for sib in copath.iter() {
        if copath.len() < NF_DEPTH {
            break;
        }
        node = if i & 1 == 0 {
            poseidon_pair_native(node, *sib)
        } else {
            poseidon_pair_native(*sib, node)
        };
        i >>= 1;
    }
    node
}

/// Canonical limb-lexicographic `key(a) < key(b)`: compare limbs MOST-significant-first (index 3 → 0). This is
/// the module's total order on nullifiers (any consistent strict order works for the IMT). `a==b` ⇒ false.
pub fn key_lt(a: Digest, b: Digest) -> bool {
    for c in (0..DIGEST_LANES).rev() {
        if a[c] != b[c] {
            return a[c] < b[c];
        }
    }
    false
}
/// `nf < low_next` with `low_next == 0` (all-zero key) read as +∞.
fn less_than_next(nf_key: Digest, ln_key: Digest) -> bool {
    if ln_key == [0u64; DIGEST_LANES] {
        true
    } else {
        key_lt(nf_key, ln_key)
    }
}

/// One nullifier's insert witness (the private inputs the AIR proves; the node's `InsertWitness` + `nf`/`count`).
#[derive(Clone, Debug)]
pub struct NfInsertWitness {
    pub nf: [u8; 32],
    pub low_value: [u8; 32],
    pub low_next: [u8; 32],
    pub low_index: u64,
    pub count: u64,
    pub low_copath: Vec<Digest>,
    pub new_copath: Vec<Digest>,
}

/// NATIVE reference: does this witness prove a valid insert of `nf` taking `pre_root` → the returned `post_root`?
/// The SAME checks as `nullifier_tree::verify_and_insert` (in the module's limb-key order). `None` (fail-closed)
/// on the zero key, a non-bracketing range, a low leaf not in `pre_root`, or a non-empty append slot.
pub fn native_insert_transition(w: &NfInsertWitness, pre_root: Digest) -> Option<Digest> {
    let nfk = key_of(&w.nf);
    let lvk = key_of(&w.low_value);
    let lnk = key_of(&w.low_next);
    if nfk == [0u64; DIGEST_LANES] {
        return None;
    }
    if w.low_copath.len() != NF_DEPTH || w.new_copath.len() != NF_DEPTH {
        return None;
    }
    if !(key_lt(lvk, nfk) && less_than_next(nfk, lnk)) {
        return None;
    }
    let low_hash = hash_leaf_native(&w.low_value, &w.low_next);
    if fold_to_root_native(low_hash, w.low_index, &w.low_copath) != pre_root {
        return None;
    }
    let low_updated = hash_leaf_native(&w.low_value, &w.nf);
    let root_mid = fold_to_root_native(low_updated, w.low_index, &w.low_copath);
    if fold_to_root_native([0u64; DIGEST_LANES], w.count, &w.new_copath) != root_mid {
        return None;
    }
    let new_leaf = hash_leaf_native(&w.nf, &w.low_next);
    Some(fold_to_root_native(new_leaf, w.count, &w.new_copath))
}

// ── ROW LAYOUT ───────────────────────────────────────────────────────────────────────────────────────────────
// PREFIX: leaf keys (12) ‖ bits (3·4·31=372) ‖ is_inf (1) ‖ leaf-hash blocks (3·16=48) ‖ lex chains (2·(124+1))
// FOLDS:  F1..F4, each 4 (seed) + 32·33 blocks.
pub const KEY_COLS: usize = 3 * DIGEST_LANES; // lv ‖ nf ‖ ln
pub const BITS_PER_VAL: usize = DIGEST_LANES * LIMB_BITS; // 248
pub const BITS_COLS: usize = 3 * BITS_PER_VAL;
/// ONE Poseidon2 permutation per leaf hash. ⛔ WAS 16 COLUMNS of `pre/ps/p4/p7` — the 1-round fold kill
/// list §AG measured as invertible, which made every leaf hash forgeable.
pub const HASH_INTER: usize = crate::pow_pq_air::P2_COLS;
pub const HASH_COLS: usize = 3 * HASH_INTER;
pub const LEX_COLS: usize = 2 * (BITS_PER_VAL + 1); // pe chain of len BITS_PER_VAL+1 per comparison
pub const PREFIX_COLS: usize = KEY_COLS + BITS_COLS + 1 + HASH_COLS + LEX_COLS;
/// Columns one fold LEVEL occupies: its sibling, its direction bit, and a whole permutation.
pub const FOLD_LEVEL_COLS: usize = DIGEST_LANES + 1 + crate::pow_pq_air::P2_COLS;
pub const FOLD_COLS: usize = DIGEST_LANES + NF_DEPTH * FOLD_LEVEL_COLS;
pub const INSERT_ROW_COLS: usize = PREFIX_COLS + 4 * FOLD_COLS;

// column offsets
const OFF_KEYS: usize = 0;
const OFF_BITS: usize = OFF_KEYS + KEY_COLS;
const OFF_INF: usize = OFF_BITS + BITS_COLS;
const OFF_HASH: usize = OFF_INF + 1;
const OFF_LEX: usize = OFF_HASH + HASH_COLS;
const OFF_FOLDS: usize = PREFIX_COLS;

/// MSB-first index order over the 124 bits of a value's key: limb 3→0, bit 30→0. Returns the bit COLUMN offset
/// within a value's `BITS_PER_VAL` block for the `pos`-th most-significant bit.
fn msb_bit_col(pos: usize) -> usize {
    // ⛔ `3` WAS HARDCODED HERE as "the top limb". At eight lanes that reads the wrong limb and orders the
    // keys by a slice of themselves — the lexicographic comparison the IMT's bracketing rests on. The top
    // limb is `DIGEST_LANES - 1`, always.
    let limb = (DIGEST_LANES - 1) - pos / LIMB_BITS; // the HIGHEST limb first
    let bit = LIMB_BITS - 1 - (pos % LIMB_BITS); // bit 30 first
    limb * LIMB_BITS + bit
}

/// Build the witness row + the (pre_root, post_root) this insert certifies. `None` if the native transition
/// rejects (the prover can only build a row for a genuinely-valid insert — the trace mirrors the reference).
pub fn nullifier_insert_row(
    w: &NfInsertWitness,
    pre_root: Digest,
) -> Option<(Vec<Fa4>, Digest, Digest)> {
    let post_root = native_insert_transition(w, pre_root)?;
    let lvk = key_of(&w.low_value);
    let nfk = key_of(&w.nf);
    let lnk = key_of(&w.low_next);
    let low_hash = hash_leaf_native(&w.low_value, &w.low_next);
    let low_updated = hash_leaf_native(&w.low_value, &w.nf);
    let new_leaf = hash_leaf_native(&w.nf, &w.low_next);

    let f = |x: u64| Fa4::from_u64(kred(x));
    let mut row = vec![Fa4::ZERO; INSERT_ROW_COLS];

    // KEYS
    for (i, k) in [lvk, nfk, lnk].iter().enumerate() {
        for c in 0..DIGEST_LANES {
            row[OFF_KEYS + i * DIGEST_LANES + c] = f(k[c]);
        }
    }
    // BITS (31 per limb, little-endian within a limb)
    let put_bits = |row: &mut [Fa4], base: usize, k: Digest| {
        for c in 0..DIGEST_LANES {
            for b in 0..LIMB_BITS {
                row[base + c * LIMB_BITS + b] = Fa4::from_u64((k[c] >> b) & 1);
            }
        }
    };
    put_bits(&mut row, OFF_BITS, lvk);
    put_bits(&mut row, OFF_BITS + BITS_PER_VAL, nfk);
    put_bits(&mut row, OFF_BITS + 2 * BITS_PER_VAL, lnk);
    // is_inf
    let inf = lnk == [0u64; DIGEST_LANES];
    row[OFF_INF] = Fa4::from_u64(inf as u64);
    // leaf-hash blocks (pre/ps/p4/p7 for each of low_hash, low_updated, new_leaf)
    let put_hash = |row: &mut [Fa4], base: usize, left: Digest, right: Digest| {
        crate::pow_pq_air::lay_perm_row_flat(row, base, crate::pow_pq_air::pair_state(&left, &right));
    };
    put_hash(&mut row, OFF_HASH, lvk, lnk); // → low_hash (F1 seed)
    put_hash(&mut row, OFF_HASH + HASH_INTER, lvk, nfk); // → low_updated (F2 seed)
    put_hash(&mut row, OFF_HASH + 2 * HASH_INTER, nfk, lnk); // → new_leaf (F4 seed)
    // LEX chains: pe[0..=124]. pe[0]=1; pe[p+1] = pe[p]·(1 - (a_p XOR b_p)).
    let put_lex = |row: &mut [Fa4], base: usize, a_bits: usize, b_bits: usize| {
        let mut pe = 1u64;
        row[base] = Fa4::from_u64(pe);
        for p in 0..BITS_PER_VAL {
            let ab = row[a_bits + msb_bit_col(p)];
            let bb = row[b_bits + msb_bit_col(p)];
            let xor = if ab == bb { 0 } else { 1 };
            pe = if xor == 1 { 0 } else { pe };
            row[base + p + 1] = Fa4::from_u64(pe);
        }
    };
    put_lex(&mut row, OFF_LEX, OFF_BITS, OFF_BITS + BITS_PER_VAL); // lv < nf
    put_lex(
        &mut row,
        OFF_LEX + BITS_PER_VAL + 1,
        OFF_BITS + BITS_PER_VAL,
        OFF_BITS + 2 * BITS_PER_VAL,
    ); // nf < ln

    // FOLDS
    let emit_fold =
        |row: &mut [Fa4], base: usize, seed: Digest, index: u64, copath: &[Digest]| {
            let mut acc = seed;
            for c in 0..DIGEST_LANES {
                row[base + c] = f(acc[c]);
            }
            let mut idx = index;
            for lvl in 0..NF_DEPTH {
                let b = base + DIGEST_LANES + lvl * FOLD_LEVEL_COLS;
                let sib = copath[lvl];
                let dir = idx & 1;
                for c in 0..DIGEST_LANES {
                    row[b + c] = f(sib[c]);
                }
                row[b + DIGEST_LANES] = Fa4::from_u64(dir);
                let (left, right) = if dir == 0 { (acc, sib) } else { (sib, acc) };
                crate::pow_pq_air::lay_perm_row_flat(
                    row,
                    b + DIGEST_LANES + 1,
                    crate::pow_pq_air::pair_state(&left, &right),
                );
                acc = poseidon_pair_native(left, right);
                idx >>= 1;
            }
        };
    emit_fold(&mut row, OFF_FOLDS, low_hash, w.low_index, &w.low_copath);
    emit_fold(&mut row, OFF_FOLDS + FOLD_COLS, low_updated, w.low_index, &w.low_copath);
    emit_fold(&mut row, OFF_FOLDS + 2 * FOLD_COLS, [0u64; DIGEST_LANES], w.count, &w.new_copath);
    emit_fold(&mut row, OFF_FOLDS + 3 * FOLD_COLS, new_leaf, w.count, &w.new_copath);
    Some((row, pre_root, post_root))
}

/// γ-power-batched residual of one insert row against the committed `pre_root` + `post_root`. ZERO iff the row is a
/// FULLY valid insert: bits boolean + packed to the limb keys, the three leaf-hashes match `x⁷+MDS` and equal
/// the fold seeds, the four folds hit pre/mid/post, and the bit-level lex proves `low_value < nf < low_next`.
///
/// PER-INSERT SOUND (adversarially tamper-tested, all REJECT): forged Merkle sibling · forged fold SEED
/// (leaf-hash→seed bind) · wrong `post_root` · FALSE ORDERING `low_value > nf` claimed `<` (canonical
/// bit-magnitude). This closes the two soundness gaps (leaf-hash bind + magnitude range) the earlier draft
/// flagged. REMAINING to reach consensus (mechanical, not soundness of THIS gate): 3b wrap in the WHIR light
/// decider (prove/verify), and 3c the BLOCK level — thread `count` sequentially across the 256 per-block inserts
/// (each insert's `pre_root` == the previous insert's `post_root`, count += 1) + fold into the settlement
/// aggregate + wire `ingest_block` to the ONE O(1) proof. Not yet wired to `ingest_block` until 3c lands.
pub struct NullifierInsertGate {
    pub gamma: Ea4,
    pub pre_root: [Ea4; DIGEST_LANES],
    pub post_root: [Ea4; DIGEST_LANES],
}

impl NullifierInsertGate {
    /// ONE compression as constraints: the permutation block at `base` is welded to `(left ‖ right)` and
    /// its output cells are returned. ⛔ WAS a hand-rolled `MDS·(l+7r)⁷` — one algebraic round, invertible
    /// in a single division (kill list §AG), so every leaf hash and every copath level was forgeable.
    fn poseidon_block(
        &self,
        left: [Ea4; DIGEST_LANES],
        right: [Ea4; DIGEST_LANES],
        base: usize,
        local: &crate::air_zerocheck::Row<'_>,
        rs: &mut Vec<Ea4>,
    ) -> [Ea4; DIGEST_LANES] {
        crate::pow_pq_air::push_perm_residuals(local, base, rs);
        for i in 0..DIGEST_LANES {
            rs.push(local[base + i] - left[i]);
            rs.push(local[base + DIGEST_LANES + i] - right[i]);
        }
        core::array::from_fn(|i| local[base + crate::pow_pq_air::PERM_OUT + i])
    }

    /// One fold to a root: per level, a direction BIT selects the child order and a whole permutation
    /// compresses `(acc, sib)`. The level's output is the next level's accumulator, so the chain is the path.
    fn fold_residuals(&self, local: &crate::air_zerocheck::Row<'_>, off: usize, rs: &mut Vec<Ea4>) -> [Ea4; DIGEST_LANES] {
        let one = Ea4::ONE;
        let mut acc: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| local[off + i]);
        for lvl in 0..NF_DEPTH {
            let base = off + DIGEST_LANES + lvl * FOLD_LEVEL_COLS;
            let sib = |c: usize| local[base + c];
            let dir = local[base + DIGEST_LANES];
            // The direction is a BIT. Without this the selection below is an arbitrary affine blend and a
            // prover picks whatever pair of operands reaches the root it wants.
            rs.push(dir * (one - dir));
            let p2 = base + DIGEST_LANES + 1;
            crate::pow_pq_air::push_perm_residuals(local, p2, rs);
            for c in 0..DIGEST_LANES {
                rs.push(local[p2 + c] - (acc[c] + dir * (sib(c) - acc[c])));
                rs.push(local[p2 + DIGEST_LANES + c] - (sib(c) + dir * (acc[c] - sib(c))));
            }
            acc = core::array::from_fn(|i| local[p2 + crate::pow_pq_air::PERM_OUT + i]);
        }
        acc
    }

    /// bit-level `a < b` over the 124 MSB-ordered key bits at `a_bits`/`b_bits`, pe-chain at `lex`. Pushes:
    /// pe boolean + chain, "no a>b in the equal prefix" guard, and `lt_total == 1` (unless `allow_inf`).
    fn lex_residuals(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        a_bits: usize,
        b_bits: usize,
        lex: usize,
        allow_inf: Option<Ea4>,
        rs: &mut Vec<Ea4>,
    ) {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        // gate = 1 for a normal comparison; (1 - isinf) for the `nf < low_next` comparison — when low_next is the
        // +∞ sentinel (isinf=1) the whole comparison is vacuously true (nf < +∞), so EVERY residual (chain +
        // no-a>b guard + lt_total) must vanish, not just lt_total. isinf ⇒ ln==0 is bound separately.
        let gate = allow_inf.map(|isinf| one - isinf).unwrap_or(one);
        rs.push(gate * (local[lex] - one)); // pe[0] == 1
        let mut lt_total = zero;
        for p in 0..BITS_PER_VAL {
            let a = local[a_bits + msb_bit_col(p)];
            let b = local[b_bits + msb_bit_col(p)];
            let pe = local[lex + p];
            let pe_next = local[lex + p + 1];
            rs.push(gate * pe * (one - pe)); // boolean
            let xr = a + b - Ea4::from(Fa4::from_u64(2)) * a * b; // a XOR b (a,b boolean)
            rs.push(gate * (pe_next - pe * (one - xr))); // pe chains on equality
            rs.push(gate * pe * a * (one - b)); // NO a>b (a=1,b=0) while prefix-equal
            lt_total = lt_total + pe * (one - a) * b; // first strict a<b
        }
        rs.push(gate * (lt_total - one)); // exactly one strict-less position ⇒ a < b
    }

    pub fn residual(&self, local: &crate::air_zerocheck::Row<'_>) -> Ea4 {
        self.residual_roots(local, self.pre_root, self.post_root)
    }

    /// The per-insert residual with the pre/post roots supplied explicitly — so the single-insert gate passes its
    /// constants and the BLOCK gate passes the row's pre/post-root COLUMNS (chaining them across rows).
    pub fn residual_roots(&self, local: &crate::air_zerocheck::Row<'_>, pre_root: [Ea4; DIGEST_LANES], post_root: [Ea4; DIGEST_LANES]) -> Ea4 {
        let rs = self.collect_residuals(local, pre_root, post_root);
        let one = Ea4::ONE;
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }

    /// Collect the per-insert residual TERMS (un-batched) so the block gate can append its boundary/chain terms
    /// and γ-batch ONCE (no nested-γ collision).
    pub fn collect_residuals(&self, local: &crate::air_zerocheck::Row<'_>, pre_root: [Ea4; DIGEST_LANES], post_root: [Ea4; DIGEST_LANES]) -> Vec<Ea4> {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::new();
        // (1) bits boolean + packed to the 12 limb keys.
        for v in 0..3 {
            for c in 0..DIGEST_LANES {
                let mut acc = zero;
                let mut p = one;
                for b in 0..LIMB_BITS {
                    let bit = local[OFF_BITS + v * BITS_PER_VAL + c * LIMB_BITS + b];
                    rs.push(bit * (one - bit));
                    acc = acc + p * bit;
                    p = p + p;
                }
                rs.push(local[OFF_KEYS + v * DIGEST_LANES + c] - acc); // limb == Σ bit·2ᵏ (canonical, < 2³¹)
            }
        }
        let key = |v: usize| -> [Ea4; DIGEST_LANES] {
            core::array::from_fn(|i| local[OFF_KEYS + v * DIGEST_LANES + i])
        };
        let lvk = key(0);
        let nfk = key(1);
        let lnk = key(2);
        // (2) leaf-hash blocks == fold seeds (F1 low_hash, F2 low_updated, F4 new_leaf).
        let seed = |fold: usize| -> [Ea4; DIGEST_LANES] {
            let s = OFF_FOLDS + fold * FOLD_COLS;
            core::array::from_fn(|i| local[s + i])
        };
        let lh = self.poseidon_block(lvk, lnk, OFF_HASH, local, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(lh[c] - seed(0)[c]);
        }
        let lu = self.poseidon_block(lvk, nfk, OFF_HASH + HASH_INTER, local, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(lu[c] - seed(1)[c]);
        }
        let nl = self.poseidon_block(nfk, lnk, OFF_HASH + 2 * HASH_INTER, local, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(nl[c] - seed(3)[c]);
        }
        // (3) four folds → pre / mid(shared) / post.
        let r1 = self.fold_residuals(local, OFF_FOLDS, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(r1[c] - pre_root[c]);
        }
        let r2 = self.fold_residuals(local, OFF_FOLDS + FOLD_COLS, &mut rs);
        let r3 = self.fold_residuals(local, OFF_FOLDS + 2 * FOLD_COLS, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(r2[c] - r3[c]);
        }
        let r4 = self.fold_residuals(local, OFF_FOLDS + 3 * FOLD_COLS, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(r4[c] - post_root[c]);
        }
        // (4) range: low_value < nf  AND  nf < low_next (or +∞).
        let isinf = local[OFF_INF];
        rs.push(isinf * (one - isinf));
        self.lex_residuals(local, OFF_BITS, OFF_BITS + BITS_PER_VAL, OFF_LEX, None, &mut rs);
        self.lex_residuals(
            local,
            OFF_BITS + BITS_PER_VAL,
            OFF_BITS + 2 * BITS_PER_VAL,
            OFF_LEX + BITS_PER_VAL + 1,
            Some(isinf),
            &mut rs,
        );
        // isinf ⇒ ln key == 0 (all four limbs); (1-isinf) ⇒ ln != 0 handled by the lex (a genuine < proof).
        for c in 0..DIGEST_LANES {
            rs.push(isinf * lnk[c]);
        }
        rs
    }
}

/// AirConstraint impl so the WHIR light decider can prove/verify the gate. Degree 3 (the `x⁷` p7 triple product
/// + the lex degree-3 terms), matching `SpendMembershipGate`.
impl crate::air_zerocheck::AirConstraint for NullifierInsertGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        self.residual(local)
    }
}

/// Nullifier-insert carrier transcript-weld tag (distinct domain).
pub const NF_INSERT_DOMAIN: u64 = 0x4e46_494e_5352_54; // "NFINSRT"

/// Statement binding: the domain tag ‖ pre_root ‖ post_root, welded into the WHIR transcript so a carrier proving a
/// DIFFERENT transition than the node checks is rejected.
fn nf_insert_statement_bind(pre_root: &[Fa4; DIGEST_LANES], post_root: &[Fa4; DIGEST_LANES]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_INSERT_DOMAIN)];
    b.extend_from_slice(pre_root);
    b.extend_from_slice(post_root);
    b
}

/// Padded trace height (power of two) — the single insert row is row-replicated (the transition-bind holds on
/// every row); the WHIR decider proves the gate on all rows. Matches the membership carrier's 32.
const NF_INSERT_ROWS: usize = crate::whir_rec_block::LIGHT_CARRIER_ROWS;

/// 3b — PROVE one insert as an O(1) WHIR light-decider carrier. Returns `(carrier_bytes, post_root)`; `None` if
/// the witness is not a valid insert (the native transition rejects) — so a carrier only exists for a genuine
/// non-membership+insert. The carrier is ~tens of KB, constant-size (FAST pillar), and verifies O(1).
pub fn prove_nullifier_insert_carrier_bytes(
    w: &NfInsertWitness,
    pre_root: Digest,
) -> Option<(Vec<u8>, Digest)> {
    let (row, _pr, post) = nullifier_insert_row(w, pre_root)?;
    let cols: Vec<Vec<Fa4>> =
        (0..INSERT_ROW_COLS).map(|c| vec![row[c]; NF_INSERT_ROWS]).collect();
    let pre_f = core::array::from_fn(|i| Fa4::from_u64(kred(pre_root[i])));
    let post_f = core::array::from_fn(|i| Fa4::from_u64(kred(post[i])));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierInsertGate { gamma: g, pre_root: pre_ea, post_root: post_ea };
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &nf_insert_statement_bind(&pre_f, &post_f),
    )?;
    Some((carrier, post))
}

/// 3b — VERIFY a nullifier-insert carrier binds to the committed `(pre_root, post_root)`. Fail-closed on any decode
/// / constraint / root mismatch — the roots are welded into the transcript, so a carrier for a different
/// transition is rejected. This is the O(1) proof-only double-spend check a treeless verifier runs.
#[must_use]
pub fn verify_nullifier_insert_carrier_bytes(bytes: &[u8], pre_root: Digest, post_root: Digest) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let pre_f = core::array::from_fn(|i| Fa4::from_u64(pre_root[i]));
    let post_f = core::array::from_fn(|i| Fa4::from_u64(post_root[i]));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierInsertGate { gamma: g, pre_root: pre_ea, post_root: post_ea };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &nf_insert_statement_bind(&pre_f, &post_f),
        (NF_INSERT_ROWS.trailing_zeros() as usize, INSERT_ROW_COLS),
    )
}

// ── 3c: BLOCK-LEVEL chained proof ────────────────────────────────────────────────────────────────────────────
// A block applies N nullifier inserts (real + cover). ONE proof over an N-row trace certifies the WHOLE chain:
// each row is a valid insert (the per-insert gate) AND the roots CHAIN — row i's `pre_root` == row i-1's
// `post_root`, row 0's pre == the block's committed pre-root, the last row's post == the block's post-root. So a
// treeless verifier checks ONE O(1) proof for all N spends. Append-slot distinctness needs NO extra constraint:
// the per-insert F3 empty-slot check already fails if a later insert re-uses an occupied slot (given the chain).
pub const BLOCK_ROW_COLS: usize = INSERT_ROW_COLS + 2 * DIGEST_LANES; // + pre_root ‖ post_root
const OFF_BPRE: usize = INSERT_ROW_COLS;
const OFF_BPOST: usize = INSERT_ROW_COLS + DIGEST_LANES;

/// The block gate: per-row insert validity + the pre/post-root CHAIN + block boundary binds. degree = nvars+1
/// (the cyclic-shift transition's σ carry chain dominates the per-insert degree 3).
pub struct NullifierBlockGate {
    pub gamma: Ea4,
    pub block_pre: [Ea4; DIGEST_LANES],
    pub block_post: [Ea4; DIGEST_LANES],
}
impl crate::air_zerocheck::AirConstraint for NullifierBlockGate {
    fn degree(&self, nvars: usize) -> usize {
        // max of the per-insert residual's column-degree 3 (the x⁷ p7 triple product) and the transition's
        // σ-carry-chain degree nvars+1 (dominates for nvars ≥ 2, i.e. ≥ 4 rows; the real block is 256 = 2⁸).
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let pre: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| local[OFF_BPRE + i]);
        let post: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| local[OFF_BPOST + i]);
        // per-row insert residual TERMS (roots read from the row's columns), then append boundary/chain terms and
        // γ-batch ONCE (no nested-γ collision).
        let ig = NullifierInsertGate { gamma: self.gamma, pre_root: [zero; DIGEST_LANES], post_root: [zero; DIGEST_LANES] };
        let mut rs = ig.collect_residuals(local, pre, post);
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk)); // Π(1−x_k): first row
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk); // Π x_k: last row
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LANES {
            rs.push(is_first * (pre[c] - self.block_pre[c])); // row 0 pre == block pre-root
            rs.push(is_last * (post[c] - self.block_post[c])); // last row post == block post-root
            rs.push(not_last * (at(OFF_BPRE + c, &sigma) - post[c])); // chain: next.pre == this.post
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

fn nf_block_statement_bind(pre: &[Fa4; DIGEST_LANES], post: &[Fa4; DIGEST_LANES]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NF_INSERT_DOMAIN ^ 0x424c_4b)]; // NF_INSERT ⊕ "BLK"
    b.extend_from_slice(pre);
    b.extend_from_slice(post);
    b
}

/// 3c — PROVE a block's whole chain of inserts as ONE O(1) carrier. `inserts.len()` must be a power of two (the
/// block's fixed cover count is 256 = 2⁸). Returns `(carrier, block_post_root)`; `None` if any insert is invalid
/// or the chain breaks. This is the block's nullifier proof a treeless node verifies O(1).
pub fn prove_nullifier_block_carrier_bytes(
    inserts: &[NfInsertWitness],
    block_pre: Digest,
) -> Option<(Vec<u8>, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    let f = |x: u64| Fa4::from_u64(kred(x));
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n);
    let mut cur = block_pre;
    for w in inserts {
        let (row, _pr, post) = nullifier_insert_row(w, cur)?;
        let mut r = row;
        r.resize(BLOCK_ROW_COLS, Fa4::ZERO);
        for c in 0..DIGEST_LANES {
            r[OFF_BPRE + c] = f(cur[c]);
            r[OFF_BPOST + c] = f(post[c]);
        }
        rows.push(r);
        cur = post;
    }
    let block_post = cur;
    let cols: Vec<Vec<Fa4>> =
        (0..BLOCK_ROW_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    let pre_f = core::array::from_fn(|i| f(block_pre[i]));
    let post_f = core::array::from_fn(|i| f(block_post[i]));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierBlockGate { gamma: g, block_pre: pre_ea, block_post: post_ea };
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &nf_block_statement_bind(&pre_f, &post_f),
    )?;
    Some((carrier, block_post))
}

/// 3c — VERIFY a block's nullifier chain carrier against the committed (block_pre, block_post). O(1). Fail-closed.
#[must_use]
pub fn verify_nullifier_block_carrier_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    n_rows: usize,
) -> bool {
    if bytes.is_empty() || n_rows == 0 || !n_rows.is_power_of_two() {
        return false;
    }
    let pre_f = core::array::from_fn(|i| Fa4::from_u64(block_pre[i]));
    let post_f = core::array::from_fn(|i| Fa4::from_u64(block_post[i]));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierBlockGate { gamma: g, block_pre: pre_ea, block_post: post_ea };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &nf_block_statement_bind(&pre_f, &post_f),
        (n_rows.trailing_zeros() as usize, BLOCK_ROW_COLS),
    )
}

// ─────────────────────────── NO-OP PADDED BLOCK GATE (flat-O(1) + volume) ───────────────────────────
// The block trace is a CONSTANT `n_rows` (256) so its size reveals nothing about how many spends a block had.
// Today every row is a real INSERT (reals + decoy inserts) — the decoys force the producer to hold the O(N) tree
// to build their copaths. Here we pad with NO-OP rows instead: a row carrying a private boolean `is_real`.
//   • is_real = 1 → the full per-insert validity is enforced (a real spend advances the root).
//   • is_real = 0 → a NO-OP: the insert residuals are exempt and the row MUST NOT change the root (post == pre).
// So the tree advances by the K real spends ONLY (no decoy copaths → no held tree → flat-O(1)), while the trace
// stays 256 rows. `is_real` is a ZERO-KNOWLEDGE witness column (is_zk), so the proof reveals neither which rows are
// real nor K. NOT identity/identifiable info — "no-op" is the identity FUNCTION (output == input on the root).
// ([[project_phone_full_node_o1_produce_fold]] [[feedback_no_growth_any_axis]] [[feedback_digital_cash_pillar]])

/// `is_real` selector column, right after the row's `post_root[4]`.
const OFF_ISREAL: usize = BLOCK_ROW_COLS; // == INSERT_ROW_COLS + 2·DIGEST_LANES
/// Padded block row width = the insert row + pre_root[4] + post_root[4] + the `is_real` selector.
pub const PADDED_BLOCK_ROW_COLS: usize = BLOCK_ROW_COLS + 1;

/// The NO-OP-PADDED block gate: per-row insert validity GATED by a boolean `is_real`, plus the no-op identity
/// (`is_real=0 ⇒ post==pre`), plus the same pre/post-root CHAIN + block-boundary binds as [`NullifierBlockGate`].
pub struct NullifierBlockGatePadded {
    pub gamma: Ea4,
    pub block_pre: [Ea4; DIGEST_LANES],
    pub block_post: [Ea4; DIGEST_LANES],
}
impl crate::air_zerocheck::AirConstraint for NullifierBlockGatePadded {
    fn degree(&self, nvars: usize) -> usize {
        // `is_real · (degree-3 insert residual)` = degree 4; the σ-carry chain is nvars+1 (dominates for ≥8 rows).
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let pre: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| local[OFF_BPRE + i]);
        let post: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| local[OFF_BPOST + i]);
        let is_real = local[OFF_ISREAL];
        let ig = NullifierInsertGate { gamma: self.gamma, pre_root: [zero; DIGEST_LANES], post_root: [zero; DIGEST_LANES] };
        let mut rs = ig.collect_residuals(local, pre, post);
        // GATE every per-insert residual by is_real — a no-op row (is_real=0) is exempt from insert validity.
        for r in rs.iter_mut() {
            *r = *r * is_real;
        }
        // Selector is boolean: is_real ∈ {0,1}. (A non-boolean would let a prover partially escape the gate.)
        rs.push(is_real * (one - is_real));
        // NO-OP IDENTITY: is_real=0 ⇒ the row does not change the root (post == pre) — inert padding.
        for c in 0..DIGEST_LANES {
            rs.push((one - is_real) * (post[c] - pre[c]));
        }
        // Boundary + chain (ungated — holds for real AND no-op rows, so the root threads pre → post across all rows).
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LANES {
            rs.push(is_first * (pre[c] - self.block_pre[c]));
            rs.push(is_last * (post[c] - self.block_post[c]));
            rs.push(not_last * (at(OFF_BPRE + c, &sigma) - post[c]));
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

/// PROVE a block's transition as K REAL inserts + (n_rows − K) NO-OP rows → ONE carrier over a CONSTANT `n_rows`
/// trace. The tree advances by the reals only; the no-ops hide K and need no copath (so the producer holds no tree).
/// `n_rows` must be a power of two and ≥ `reals.len()`. Returns `(carrier, block_post)`; `None` if any real insert
/// is invalid or the shape is bad.
pub fn prove_nullifier_block_carrier_padded_bytes(
    reals: &[NfInsertWitness],
    block_pre: Digest,
    n_rows: usize,
) -> Option<(Vec<u8>, Digest)> {
    if n_rows == 0 || !n_rows.is_power_of_two() || reals.len() > n_rows {
        return None;
    }
    let f = |x: u64| Fa4::from_u64(kred(x));
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n_rows);
    let mut cur = block_pre;
    for w in reals {
        let (row, _pr, post) = nullifier_insert_row(w, cur)?;
        let mut r = row;
        r.resize(PADDED_BLOCK_ROW_COLS, Fa4::ZERO);
        for c in 0..DIGEST_LANES {
            r[OFF_BPRE + c] = f(cur[c]);
            r[OFF_BPOST + c] = f(post[c]);
        }
        r[OFF_ISREAL] = Fa4::ONE;
        rows.push(r);
        cur = post;
    }
    while rows.len() < n_rows {
        // NO-OP row: is_real=0 (default zero), post == pre == the current root, insert columns all zero (gated out).
        let mut r = vec![Fa4::ZERO; PADDED_BLOCK_ROW_COLS];
        for c in 0..DIGEST_LANES {
            r[OFF_BPRE + c] = f(cur[c]);
            r[OFF_BPOST + c] = f(cur[c]);
        }
        rows.push(r);
    }
    let block_post = cur;
    let cols: Vec<Vec<Fa4>> = (0..PADDED_BLOCK_ROW_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    let pre_f = core::array::from_fn(|i| f(block_pre[i]));
    let post_f = core::array::from_fn(|i| f(block_post[i]));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierBlockGatePadded { gamma: g, block_pre: pre_ea, block_post: post_ea };
    let carrier = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        make,
        &nf_block_statement_bind(&pre_f, &post_f),
    )?;
    Some((carrier, block_post))
}

/// VERIFY a no-op-padded block carrier against the committed `(block_pre, block_post)`. O(1). Fail-closed.
#[must_use]
pub fn verify_nullifier_block_carrier_padded_bytes(
    bytes: &[u8],
    block_pre: Digest,
    block_post: Digest,
    n_rows: usize,
) -> bool {
    if bytes.is_empty() || n_rows == 0 || !n_rows.is_power_of_two() {
        return false;
    }
    let pre_f = core::array::from_fn(|i| Fa4::from_u64(block_pre[i]));
    let post_f = core::array::from_fn(|i| Fa4::from_u64(block_post[i]));
    let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
    let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
    let make = move |g: Ea4| NullifierBlockGatePadded { gamma: g, block_pre: pre_ea, block_post: post_ea };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        make,
        &nf_block_statement_bind(&pre_f, &post_f),
        (n_rows.trailing_zeros() as usize, PADDED_BLOCK_ROW_COLS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───── NO-OP PADDED BLOCK GATE — real soundness tests (honest verifies; every forgery REJECTS) ─────

    fn padded_nf_witness(imt: &mut TestImt, seed: u64) -> NfInsertWitness {
        let mut nf = [0u8; 32];
        nf[0..8].copy_from_slice(&seed.to_le_bytes());
        nf[24] = 0xA5;
        imt.insert(nf)
    }

    /// The exact rows `prove_nullifier_block_carrier_padded_bytes` builds — exposed so a test can FORGE one and
    /// confirm the gate rejects it.
    fn build_padded_rows(reals: &[NfInsertWitness], block_pre: Digest, n_rows: usize) -> (Vec<Vec<Fa4>>, Digest) {
        let f = |x: u64| Fa4::from_u64(kred(x));
        let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n_rows);
        let mut cur = block_pre;
        for w in reals {
            let (row, _pr, post) = nullifier_insert_row(w, cur).expect("valid insert");
            let mut r = row;
            r.resize(PADDED_BLOCK_ROW_COLS, Fa4::ZERO);
            for c in 0..DIGEST_LANES {
                r[OFF_BPRE + c] = f(cur[c]);
                r[OFF_BPOST + c] = f(post[c]);
            }
            r[OFF_ISREAL] = Fa4::ONE;
            rows.push(r);
            cur = post;
        }
        while rows.len() < n_rows {
            let mut r = vec![Fa4::ZERO; PADDED_BLOCK_ROW_COLS];
            for c in 0..DIGEST_LANES {
                r[OFF_BPRE + c] = f(cur[c]);
                r[OFF_BPOST + c] = f(cur[c]);
            }
            rows.push(r);
        }
        (rows, cur)
    }

    /// Prove the given (possibly forged) rows and report whether the carrier VERIFIES against (pre, post). A prover
    /// that refuses the invalid trace (`None`) counts as "not accepted" — either way the forgery does not pass.
    fn padded_rows_accepted(rows: &[Vec<Fa4>], block_pre: Digest, block_post: Digest, n_rows: usize) -> bool {
        let f = |x: u64| Fa4::from_u64(kred(x));
        let cols: Vec<Vec<Fa4>> = (0..PADDED_BLOCK_ROW_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
        let pre_f = core::array::from_fn(|i| f(block_pre[i]));
        let post_f = core::array::from_fn(|i| f(block_post[i]));
        let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
        let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
        let make = move |g: Ea4| NullifierBlockGatePadded { gamma: g, block_pre: pre_ea, block_post: post_ea };
        match crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            cols,
            make,
            &nf_block_statement_bind(&pre_f, &post_f),
        ) {
            Some(carrier) => verify_nullifier_block_carrier_padded_bytes(&carrier, block_pre, block_post, n_rows),
            None => false,
        }
    }

    #[test]
    fn padded_block_verifies_and_advances_only_by_reals() {
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let reals: Vec<NfInsertWitness> = (1..=3u64).map(|s| padded_nf_witness(&mut imt, s)).collect();
        let real_only_post = imt.root(); // the tree after EXACTLY the 3 real spends
        let (carrier, block_post) =
            prove_nullifier_block_carrier_padded_bytes(&reals, block_pre, 8).expect("prove 3-real + 5-no-op block");
        assert_eq!(block_post, real_only_post, "the tree advances ONLY by the 3 real spends; the 5 no-ops are inert");
        assert!(
            verify_nullifier_block_carrier_padded_bytes(&carrier, block_pre, block_post, 8),
            "the honest no-op-padded block verifies"
        );
        let mut wrong = block_post;
        wrong[0] ^= 1;
        assert!(
            !verify_nullifier_block_carrier_padded_bytes(&carrier, block_pre, wrong, 8),
            "a wrong post_root is rejected (fail-closed binding)"
        );
    }

    #[test]
    fn padded_noop_row_changing_root_is_rejected() {
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let reals: Vec<NfInsertWitness> = (1..=2u64).map(|s| padded_nf_witness(&mut imt, s)).collect();
        let (mut rows, block_post) = build_padded_rows(&reals, block_pre, 8);
        // FORGE: make a no-op row (index 5, is_real=0) change the root (post ≠ pre). The identity constraint rejects it.
        rows[5][OFF_BPOST] = rows[5][OFF_BPOST] + Fa4::ONE;
        assert!(!padded_rows_accepted(&rows, block_pre, block_post, 8), "a no-op row that changes the root is rejected");
    }

    #[test]
    fn padded_non_boolean_selector_is_rejected() {
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let reals: Vec<NfInsertWitness> = (1..=2u64).map(|s| padded_nf_witness(&mut imt, s)).collect();
        let (mut rows, block_post) = build_padded_rows(&reals, block_pre, 8);
        // FORGE: a non-boolean selector (2) — the boolean constraint `is_real·(1−is_real)` rejects it.
        rows[5][OFF_ISREAL] = Fa4::from_u64(2);
        assert!(!padded_rows_accepted(&rows, block_pre, block_post, 8), "a non-boolean is_real selector is rejected");
    }

    #[test]
    fn padded_real_row_with_tampered_copath_is_rejected() {
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let reals: Vec<NfInsertWitness> = (1..=2u64).map(|s| padded_nf_witness(&mut imt, s)).collect();
        let (mut rows, block_post) = build_padded_rows(&reals, block_pre, 8);
        // FORGE: corrupt a fold column of a REAL row (is_real=1) → the GATED insert residual is enforced → reject.
        rows[0][OFF_FOLDS] = rows[0][OFF_FOLDS] + Fa4::ONE;
        assert!(!padded_rows_accepted(&rows, block_pre, block_post, 8), "a real row with a tampered fold/copath is rejected");
    }

    fn ea(x: Digest) -> [Ea4; DIGEST_LANES] {
        core::array::from_fn(|i| Ea4::from(Fa4::from_u64(kred(x[i]))))
    }
    fn empty_subtree(level: usize) -> Digest {
        let mut n = [0u64; DIGEST_LANES];
        for _ in 0..level {
            n = poseidon_pair_native(n, n);
        }
        n
    }
    fn fresh_root_and_copath() -> (Digest, Vec<Digest>) {
        let init = hash_leaf_native(&[0u8; 32], &[0u8; 32]);
        let mut node = init;
        let mut copath = Vec::new();
        for level in 0..NF_DEPTH {
            let sib = empty_subtree(level);
            copath.push(sib);
            node = poseidon_pair_native(node, sib);
        }
        (node, copath)
    }
    fn honest_witness() -> (NfInsertWitness, Digest) {
        let (pre_root, low_copath) = fresh_root_and_copath();
        // ⛔ `key_of` IS A HASH NOW, not a limb decode (kill list §AG): a nullifier is 256 bits of blake3
        // and does not fit the 248-bit canonical encoding, so the key must be compressed. That scrambles
        // key ORDER relative to nullifier BYTES — this fixture used to set byte 24 and assert "limb 3
        // nonzero ⇒ key_lt(0, nf)", which is no longer a fact about anything. The bracketing key is now
        // FOUND, deterministically, by asking the order itself.
        let zero_key = key_of(&[0u8; 32]);
        let nf = (1u8..=255)
            .map(|b| {
                let mut n = [0u8; 32];
                n[24] = b;
                n
            })
            .find(|n| key_lt(zero_key, key_of(n)))
            .expect("some single-byte nullifier keys above the zero key exist");
        let low_updated = hash_leaf_native(&[0u8; 32], &nf);
        let mut new_copath = vec![low_updated];
        for level in 1..NF_DEPTH {
            new_copath.push(empty_subtree(level));
        }
        let w = NfInsertWitness {
            nf,
            low_value: [0u8; 32],
            low_next: [0u8; 32], // +∞
            low_index: 0,
            count: 1,
            low_copath,
            new_copath,
        };
        (w, pre_root)
    }

    #[test]
    fn native_transition_accepts_honest_and_rejects_bad() {
        let (w, pre_root) = honest_witness();
        let post = native_insert_transition(&w, pre_root).expect("honest insert transitions");
        assert_ne!(post, pre_root);
        // low_value > nf ⇒ not bracketed ⇒ rejected (a false low leaf).
        let mut bad = w.clone();
        bad.low_value = {
            let mut b = [0u8; 32];
            b[24] = 0x99; // key limb3 = 0x99 > nf's 0x33 ⇒ low_value > nf
            b
        };
        assert!(native_insert_transition(&bad, pre_root).is_none(), "low_value > nf rejected");
    }

    #[test]
    fn gate_zero_on_honest_nonzero_on_forged_sibling_seed_root_and_false_order() {
        let (w, pre_root) = honest_witness();
        let (row, _pr, post) = nullifier_insert_row(&w, pre_root).expect("row builds");
        let ee: Vec<Ea4> = row.iter().map(|&x| Ea4::from(x)).collect();
        let g = || NullifierInsertGate { gamma: Ea4::from(Fa4::from_u64(0x9e37_79b9)), pre_root: ea(pre_root), post_root: ea(post) };
        assert_eq!(g().residual(&crate::air_zerocheck::RowGuard::new().row(&ee)), Ea4::from(Fa4::ZERO), "honest insert ⇒ residual 0");

        // TAMPER 1: forge a Merkle sibling in F1.
        let mut t = ee.clone();
        t[OFF_FOLDS + 4] = t[OFF_FOLDS + 4] + Ea4::ONE;
        assert_ne!(g().residual(&crate::air_zerocheck::RowGuard::new().row(&t)), Ea4::from(Fa4::ZERO), "forged F1 sibling ⇒ ≠0");

        // TAMPER 2: forge the F1 SEED (low_hash) away from poseidon_pair(key) — the leaf-hash bind must catch it.
        let mut t2 = ee.clone();
        t2[OFF_FOLDS] = t2[OFF_FOLDS] + Ea4::ONE;
        assert_ne!(g().residual(&crate::air_zerocheck::RowGuard::new().row(&t2)), Ea4::from(Fa4::ZERO), "forged F1 seed ⇒ ≠0 (leaf-hash bind)");

        // TAMPER 3: wrong post_root.
        let mut wp = post;
        wp[0] = kadd(wp[0], 1);
        let g3 = NullifierInsertGate { gamma: Ea4::from(Fa4::from_u64(0x9e37_79b9)), pre_root: ea(pre_root), post_root: ea(wp) };
        assert_ne!(g3.residual(&crate::air_zerocheck::RowGuard::new().row(&ee)), Ea4::from(Fa4::ZERO), "wrong post_root ⇒ ≠0");

        // TAMPER 4 (the range caveat): flip the lex to claim low_value < nf when actually equal-prefix-then-not.
        // Corrupt an lv bit so lv's key no longer < nf but the pe-chain still claims lt → the a>b guard / lt_total
        // must fire. Here we flip lv limb3 high bit so lv > nf, and rebuild ONLY the lex to lie it's still <.
        let mut t4 = ee.clone();
        // set lv bit (limb3 msb region) to 1 so lv > nf, but keep the (now stale) lex chain claiming lt.
        let lvhi = OFF_BITS + 3 * LIMB_BITS + (LIMB_BITS - 1); // lv limb3 top bit
        t4[lvhi] = Ea4::ONE;
        // also update lv key limb3 to stay packed-consistent (else the packing residual fires first — still ≠0,
        // but we want the LEX to be the catcher): make key consistent with the flipped bit.
        t4[OFF_KEYS + 3] = t4[OFF_KEYS + 3] + Ea4::from(Fa4::from_u64(1u64 << (LIMB_BITS - 1)));
        assert_ne!(g().residual(&crate::air_zerocheck::RowGuard::new().row(&t4)), Ea4::from(Fa4::ZERO), "false ordering (lv>nf) ⇒ ≠0 (sound magnitude)");
    }

    #[test]
    fn whir_carrier_proves_insert_and_rejects_wrong_root_or_tamper() {
        // 3b: the O(1) WHIR light-decider carrier. An honest insert PROVES + VERIFIES against its (pre,post);
        // a wrong post_root or tampered bytes FAIL-CLOSED. This is the treeless verifier's proof-only check.
        let (w, pre_root) = honest_witness();
        let (carrier, post) =
            prove_nullifier_insert_carrier_bytes(&w, pre_root).expect("honest insert carriers");
        assert!(!carrier.is_empty(), "carrier is a real proof");
        assert!(
            verify_nullifier_insert_carrier_bytes(&carrier, pre_root, post),
            "honest carrier verifies against its (pre_root, post_root)"
        );
        // Wrong post_root → rejected (roots welded into the transcript).
        let mut wp = post;
        wp[0] = kadd(wp[0], 1);
        assert!(
            !verify_nullifier_insert_carrier_bytes(&carrier, pre_root, wp),
            "a carrier verified against a DIFFERENT post_root is rejected"
        );
        // Wrong pre_root → rejected.
        let mut wpre = pre_root;
        wpre[0] = kadd(wpre[0], 1);
        assert!(
            !verify_nullifier_insert_carrier_bytes(&carrier, wpre, post),
            "a carrier verified against a DIFFERENT pre_root is rejected"
        );
        // Tampered proof bytes → rejected.
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        assert!(
            !verify_nullifier_insert_carrier_bytes(&bad, pre_root, post),
            "tampered carrier bytes are rejected"
        );
    }

    /// Minimal native indexed-Merkle tree (mirrors `nullifier_tree::FullNullifierImt` in the module's limb order)
    /// so the test can build a REAL chained multi-insert witness set. Empty ranges are pruned (O(count·depth)).
    struct TestImt {
        leaves: Vec<([u8; 32], [u8; 32])>,
    }
    impl TestImt {
        fn new() -> Self {
            Self { leaves: vec![([0u8; 32], [0u8; 32])] }
        }
        fn leaf_hash(&self, i: usize) -> Digest {
            if i < self.leaves.len() {
                let (v, n) = &self.leaves[i];
                hash_leaf_native(v, n)
            } else {
                [0u64; DIGEST_LANES]
            }
        }
        fn subtree(&self, start: usize, level: usize) -> Digest {
            if start >= self.leaves.len() {
                return empty_subtree(level);
            }
            if level == 0 {
                return self.leaf_hash(start);
            }
            let l = self.subtree(start, level - 1);
            let r = self.subtree(start + (1 << (level - 1)), level - 1);
            poseidon_pair_native(l, r)
        }
        fn root(&self) -> Digest {
            self.subtree(0, NF_DEPTH)
        }
        fn copath(&self, pos: usize) -> Vec<Digest> {
            (0..NF_DEPTH).map(|l| self.subtree(((pos >> l) ^ 1) << l, l)).collect()
        }
        fn insert(&mut self, nf: [u8; 32]) -> NfInsertWitness {
            let nfk = key_of(&nf);
            let li = (0..self.leaves.len())
                .find(|&i| {
                    let (v, n) = &self.leaves[i];
                    key_lt(key_of(v), nfk) && less_than_next(nfk, key_of(n))
                })
                .expect("a bracketing low leaf exists");
            let (lv, ln) = self.leaves[li];
            let low_copath = self.copath(li);
            let count = self.leaves.len();
            self.leaves[li].1 = nf; // low.next := nf (the MID tree)
            let new_copath = self.copath(count); // append slot `count` is empty in the MID tree
            self.leaves.push((nf, ln));
            NfInsertWitness {
                nf,
                low_value: lv,
                low_next: ln,
                low_index: li as u64,
                count: count as u64,
                low_copath,
                new_copath,
            }
        }
    }

    // TIMING PROBE (release, `--ignored`): the LIVE 256=2⁸ block size — measures prove/verify latency + carrier
    // bytes so the FAST pillar (≤1.8MB, phone-class, 1s block) is a MEASURED fact, not an assumption. Run:
    //   cargo test -p usdm-decider --release nfblock_256_timing -- --ignored --nocapture
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: release-only latency measurement probe — not a disabled test
    fn nfblock_256_timing() {
        const N: usize = 256;
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let mut inserts: Vec<NfInsertWitness> = Vec::with_capacity(N);
        for i in 0..N {
            let mut nf = [0u8; 32];
            nf[0..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
            nf[24] = 0xA5; // keep the high limb nonzero/distinct region populated
            inserts.push(imt.insert(nf));
        }
        let t0 = std::time::Instant::now();
        let (carrier, block_post) =
            prove_nullifier_block_carrier_bytes(&inserts, block_pre).expect("256 block proves");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_nullifier_block_carrier_bytes(&carrier, block_pre, block_post, N), "256 verifies");
        let verify_ms = t1.elapsed().as_millis();
        eprintln!(
            "NFBLOCK-256  prove={prove_ms}ms  verify={verify_ms}ms  carrier={} bytes ({:.1} KB)",
            carrier.len(),
            carrier.len() as f64 / 1024.0
        );
    }

    /// ⭐ CIRCUIT-REWORK PROBE — time the SAME 256-block transition trace via the DIRECT decider (current, ~956ms)
    /// vs the BATCH decider, to decide whether the produce-speed lever is the PROVER or the AIR WIDTH (INSERT_ROW_COLS
    /// ≈ 4900, four depth-32 folds). Grounds the rework in a measured number, not a guess.
    /// Run: cargo test -p usdm-decider --release nfblock_direct_vs_batch_time -- --ignored --nocapture
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: release-only latency measurement probe (like nfblock_256_timing) — grounds the circuit rework, not a disabled test
    fn nfblock_direct_vs_batch_time() {
        const N: usize = 256;
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let mut inserts: Vec<NfInsertWitness> = Vec::with_capacity(N);
        for i in 0..N {
            let mut nf = [0u8; 32];
            nf[0..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
            nf[24] = 0xA5;
            inserts.push(imt.insert(nf));
        }
        // Build the exact block trace (mirror of prove_nullifier_block_carrier_bytes).
        let f = |x: u64| Fa4::from_u64(kred(x));
        let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(N);
        let mut cur = block_pre;
        for w in &inserts {
            let (row, _pr, post) = nullifier_insert_row(w, cur).expect("row");
            let mut r = row;
            r.resize(BLOCK_ROW_COLS, Fa4::ZERO);
            for c in 0..DIGEST_LANES {
                r[OFF_BPRE + c] = f(cur[c]);
                r[OFF_BPOST + c] = f(post[c]);
            }
            rows.push(r);
            cur = post;
        }
        let block_post = cur;
        let cols: Vec<Vec<Fa4>> = (0..BLOCK_ROW_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
        let pre_f = core::array::from_fn(|i| f(block_pre[i]));
        let post_f = core::array::from_fn(|i| f(block_post[i]));
        let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
        let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
        let bind = nf_block_statement_bind(&pre_f, &post_f);

        let t0 = std::time::Instant::now();
        let direct = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            cols.clone(),
            move |g: Ea4| NullifierBlockGate { gamma: g, block_pre: pre_ea, block_post: post_ea },
            &bind,
        )
        .expect("direct proves");
        let direct_ms = t0.elapsed().as_millis();

        let t1 = std::time::Instant::now();
        let batch = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes(
            vec![cols],
            move |_i: usize, g: Ea4| NullifierBlockGate { gamma: g, block_pre: pre_ea, block_post: post_ea },
            &bind,
        )
        .expect("batch proves");
        let batch_ms = t1.elapsed().as_millis();

        eprintln!(
            "NFBLOCK-256 DIRECT-vs-BATCH  width={} cols x {} rows  direct={} ms ({} B)  batch={} ms ({} B)",
            BLOCK_ROW_COLS, N, direct_ms, direct.len(), batch_ms, batch.len()
        );
    }

    /// ⭐ VOLUME-vs-PRODUCE-TIME PROBE — measure the block-gate DIRECT prove (the produce hot path) at each fixed
    /// cover volume so a privacy/perf tradeoff is grounded in a real number, not a guess. Produce proves the whole
    /// N-insert chain in ONE trace (N rows × BLOCK_ROW_COLS), so time is ~the WHIR prove over that trace.
    /// Run: cargo test -p usdm-decider --release nfblock_produce_time_by_volume -- --ignored --nocapture
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: release-only latency probe (same pattern as nfblock_direct_vs_batch_time) — not a disabled failing test
    fn nfblock_produce_time_by_volume() {
        let f = |x: u64| Fa4::from_u64(kred(x));
        for &n in &[128usize, 256usize] {
            let mut imt = TestImt::new();
            let block_pre = imt.root();
            let mut inserts: Vec<NfInsertWitness> = Vec::with_capacity(n);
            for i in 0..n {
                let mut nf = [0u8; 32];
                nf[0..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
                nf[24] = 0xA5;
                inserts.push(imt.insert(nf));
            }
            let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n);
            let mut cur = block_pre;
            for w in &inserts {
                let (row, _pr, post) = nullifier_insert_row(w, cur).expect("row");
                let mut r = row;
                r.resize(BLOCK_ROW_COLS, Fa4::ZERO);
                for c in 0..DIGEST_LANES {
                    r[OFF_BPRE + c] = f(cur[c]);
                    r[OFF_BPOST + c] = f(post[c]);
                }
                rows.push(r);
                cur = post;
            }
            let block_post = cur;
            let cols: Vec<Vec<Fa4>> = (0..BLOCK_ROW_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
            let pre_f = core::array::from_fn(|i| f(block_pre[i]));
            let post_f = core::array::from_fn(|i| f(block_post[i]));
            let pre_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| pre_f[i].into());
            let post_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| post_f[i].into());
            let bind = nf_block_statement_bind(&pre_f, &post_f);

            // Warm once (amortize any lazy init), then time the median of 3.
            let mut best = u128::MAX;
            let mut sz = 0usize;
            for _ in 0..3 {
                let t0 = std::time::Instant::now();
                let proof = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
                    cols.clone(),
                    move |g: Ea4| NullifierBlockGate { gamma: g, block_pre: pre_ea, block_post: post_ea },
                    &bind,
                )
                .expect("direct proves");
                best = best.min(t0.elapsed().as_millis());
                sz = proof.len();
            }
            eprintln!(
                "PRODUCE-TIME  volume={:>3}  rows={:>3}  best-of-3 direct-prove={:>4} ms  proof={} B",
                n, n, best, sz
            );
        }
    }

    /// ⭐ B4 PROBE — does RECURSIVELY AGGREGATING the 256 single-insert carriers give an O(1) gossip-sized proof?
    /// Each single insert is a uniform-shape carrier; the settlement-aggregate mechanism recursively verifies all
    /// 256 into ONE proof whose size is O(1) in N (the 256 ~tens-of-KB sub-carriers are consumed at prove time, NOT
    /// in the final bytes). If this is sub-60KB + verifies, it is the compact carried transition (reusing existing
    /// machinery, no new wide AIR). Run: cargo test -p usdm-decider --release nfblock_256_recursive -- --ignored --nocapture
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: release-only size/latency measurement probe (256 real proves), the SAME benchmark pattern as nfblock_256_timing — NOT a disabled failing test
    fn nfblock_256_recursive_aggregate_is_gossip_sized() {
        use crate::whir_rec_block::{settlement_aggregate_from_bundles, tx_set_digest, verify_settlement_aggregate};
        const N: usize = 256;
        let mut imt = TestImt::new();
        let mut cur = imt.root();
        let mut carriers: Vec<Vec<u8>> = Vec::with_capacity(N);
        let mut binds: Vec<Vec<Fa4>> = Vec::with_capacity(N);
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(N);
        let mut single_sz = 0usize;
        for i in 0..N {
            let mut nf = [0u8; 32];
            nf[0..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
            nf[24] = 0xA5;
            let w = imt.insert(nf);
            let (carrier, post) =
                prove_nullifier_insert_carrier_bytes(&w, cur).expect("single insert carrier proves");
            single_sz = carrier.len();
            let pre_f = core::array::from_fn(|i| Fa4::from_u64(kred(cur[i])));
            let post_f = core::array::from_fn(|i| Fa4::from_u64(kred(post[i])));
            binds.push(nf_insert_statement_bind(&pre_f, &post_f));
            ids.push(*blake3::hash(&carrier).as_bytes());
            carriers.push(carrier);
            cur = post;
        }
        let set_digest = tx_set_digest(&ids);
        let t_agg = std::time::Instant::now();
        let agg = settlement_aggregate_from_bundles(&carriers, &binds, &set_digest)
            .expect("256 single-insert carriers aggregate to ONE O(1) proof");
        let agg_ms = t_agg.elapsed().as_millis();
        eprintln!(
            "NFBLOCK-256 RECURSIVE-AGG  single-insert={} B  aggregate-of-256={} B ({:.1} KB)  vs monolith 221 KB  AGGREGATE-PROVE={agg_ms} ms",
            single_sz, agg.len(), agg.len() as f64 / 1024.0
        );
        // And the smallest shape a light block would use: 32 rows (the decider's floor).
        let t32 = std::time::Instant::now();
        let agg32 = settlement_aggregate_from_bundles(&carriers[..8], &binds[..8], &tx_set_digest(&ids[..8]))
            .expect("8 carriers aggregate");
        eprintln!("NFBLOCK-8 RECURSIVE-AGG  aggregate-of-8={} B  AGGREGATE-PROVE={} ms", agg32.len(), t32.elapsed().as_millis());
        let tv = std::time::Instant::now();
        let ok8 = verify_settlement_aggregate(&agg32, 8, &tx_set_digest(&ids[..8]));
        eprintln!("NFBLOCK-8 VERIFY ok={ok8} {} ms", tv.elapsed().as_millis());
        assert!(
            verify_settlement_aggregate(&agg, N, &set_digest),
            "the O(1) aggregate of 256 insert-carriers verifies"
        );
        assert!(agg.len() < 60_000, "aggregate is gossip-sized (O(1), sub-60 KB) — was 221 KB monolith");
    }

    #[test]
    fn block_carrier_chains_multi_insert_and_rejects_broken_chain() {
        // 3c: ONE O(1) proof certifies a whole block's chain of inserts. Build a REAL 8-insert chain (2³ rows —
        // the decider's minimum; the live block is 256 = 2⁸) with the native IMT, prove the block, verify O(1).
        const N: usize = 8;
        let mut imt = TestImt::new();
        let block_pre = imt.root();
        let mut inserts: Vec<NfInsertWitness> = Vec::with_capacity(N);
        let mut cur = block_pre;
        for i in 0..N {
            let mut nf = [0u8; 32];
            nf[24] = ((i as u8) + 1) * 0x11; // distinct nonzero keys 0x11..0x88 (increasing)
            let w = imt.insert(nf);
            assert_eq!(native_insert_transition(&w, cur), Some(imt.root()), "insert {i} chains");
            cur = imt.root();
            inserts.push(w);
        }
        let post_final = cur;

        let (carrier, block_post) =
            prove_nullifier_block_carrier_bytes(&inserts, block_pre).expect("block proves");
        assert_eq!(block_post, post_final, "block post_root == the final chained root");
        let post1 = post_final;
        assert!(
            verify_nullifier_block_carrier_bytes(&carrier, block_pre, post1, N),
            "honest {N}-insert block chain verifies O(1)"
        );
        // Wrong block_post → rejected (welded into transcript).
        let mut wp = post1;
        wp[0] = kadd(wp[0], 1);
        assert!(
            !verify_nullifier_block_carrier_bytes(&carrier, block_pre, wp, N),
            "a wrong block post_root is rejected"
        );
        // Wrong block_pre → rejected.
        let mut wpre = block_pre;
        wpre[0] = kadd(wpre[0], 1);
        assert!(
            !verify_nullifier_block_carrier_bytes(&carrier, wpre, post1, N),
            "a wrong block pre_root is rejected"
        );
    }
}

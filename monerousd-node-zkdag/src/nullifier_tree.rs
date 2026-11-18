// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Indexed-Merkle nullifier accumulator — O(1) node state, sound double-spend prevention (no-growth pillar).**
//!
//! The cross-block double-spend gate used to be `spent_nullifiers: HashSet<Hash32>` — 32 bytes per spend, kept
//! forever in RAM AND on disk. That is a per-spend growth axis: a busy chain's node grows without bound, exactly
//! the Monero UTXO-set-in-RAM anti-pattern the O(1) node exists to kill. This module replaces the set with a
//! constant-size commitment: the node keeps ONLY the current Merkle `root` (one Poseidon digest) + the leaf
//! `count`. No nullifier set is stored anywhere.
//!
//! **How non-membership stays sound without the set (the point of the recursive/DA design).** This is an *indexed
//! Merkle tree* (IMT): every leaf is `(value, next_value)`, and the leaves form a sorted singly-linked list by
//! value. To prove a nullifier `x` is UNSPENT you exhibit its *low leaf* — the leaf whose range brackets it:
//! `low.value < x < low.next_value` (with `next_value == 0` read as +∞, the largest leaf). The witness (the low
//! leaf + its Merkle copath, and the copath of the append slot) is supplied from DA — the node VERIFIES it against
//! `root` and applies the O(DEPTH) root transition. It never needs the full set to answer non-membership.
//!
//! **Double-spend is impossible by construction.** Inserting `x` splits the bracketing gap: `low.next` becomes
//! `x` and a new leaf `(x, old_next)` is appended. After that there is NO leaf with `low.value < x < low.next`
//! (the gap that once contained `x` now ends exactly at `x`), so a second insert of `x` has no valid low-leaf
//! witness: either the claimed low leaf fails the Merkle membership check against the (updated) `root`, or the
//! range check `low.value < x < low.next` fails. Fail-closed on the bad spend only — never a chain halt.
//!
//! Reuses the SAME Poseidon (`poseidon_pair`), leaf packing (`cm_bytes_to_leaf`), empty leaf (`[0;4]`) and
//! `DEPTH=32` as [`crate::spend_frontier`], so the in-circuit gate and the wallet build the identical tree.

use crate::spend_frontier::{
    cm_bytes_to_leaf, empty_leaf, poseidon_pair, Digest4, SPEND_TREE_DEPTH,
};

/// Depth of the nullifier IMT — one linked-list leaf per *insertion position*, up to `2^DEPTH` spent nullifiers.
/// Matches the note/spend tree depth so the whole-chain proof folds all three with one Poseidon convention.
pub const NULLIFIER_TREE_DEPTH: usize = SPEND_TREE_DEPTH;

/// ⛔⛔⛔ A SHIFT BY THE FULL WORD WIDTH IS NOT ZERO — IT IS A NO-OP, AND IT SILENTLY BROKE THE ROOT.
///
/// `NULLIFIER_TREE_DEPTH` is `SPEND_TREE_DEPTH`, which was raised to **64** so the frontier can never fill
/// ([[project_chain_death_date_removed]]). Every walk here runs `for level in 1..=DEPTH`, so `level` reaches
/// 64 — and in Rust `x >> 64` on a `u64` is not `0`, it is **masked to `x >> 0` = `x`** in release (it
/// panics in debug, which is why this hid in `--release` runs only).
///
/// MEASURED 2026-09-04. At the top level `recompute_path` computed `idx = pos >> 64 = pos` and wrote the
/// node under key `(64, pos)` instead of `(64, 0)`. `root()` reads `node_at(DEPTH, 0)`, so **the root only
/// ever updated when the touched leaf happened to be index 0** and was otherwise STALE. A probe over six
/// inserts: `full.leaves` grew 8 → 9 → 10 while `root()` returned the same bytes every time, and moved only
/// on the one step whose low leaf was index 0. Four `nullifier_tree` tests had been red since the depth
/// bump; the live cost is larger than the tests — a node holding this tree serves and commits a root that
/// does not describe its own leaves.
///
/// These two helpers are the only sanctioned way to turn a `(pos, level)` into a subtree index or its first
/// leaf. They saturate instead of wrapping: a subtree whose first leaf cannot be represented starts beyond
/// every leaf that exists, which is exactly what `node_at`'s emptiness test wants to hear.
#[inline]
fn subtree_index(pos: u64, level: usize) -> u64 {
    if level >= u64::BITS as usize {
        0 // the whole tree is one subtree at the top level
    } else {
        pos >> level
    }
}

#[inline]
fn first_leaf_under(idx: u64, level: usize) -> u64 {
    if idx == 0 {
        return 0; // the leftmost subtree always starts at leaf 0, at every level
    }
    if level >= u64::BITS as usize || idx > (u64::MAX >> level) {
        return u64::MAX; // starts past any leaf that could exist ⇒ treated as empty
    }
    idx << level
}


/// Why an insert was rejected. Every variant is a fail-closed rejection of the ONE bad spend — never a halt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullifierError {
    /// `nf` is the reserved zero sentinel (0 = the initial low leaf's value / the +∞ `next` marker).
    ZeroNullifier,
    /// The low-leaf range does not bracket `nf` (`low.value < nf < low.next` is false) → `nf` is already spent
    /// or the witness lied about the neighbourhood. Double-spend rejected here.
    NotBracketed,
    /// The low leaf does not hash up its copath to the current `root` → forged / stale membership witness.
    BadLowMembership,
    /// The claimed append slot is not empty under the mid-root → forged / occupied append witness.
    AppendSlotNotEmpty,
    /// A copath was not exactly `DEPTH` siblings.
    BadCopathLength,
}

/// The complete non-membership + insertion witness for one nullifier. TRUSTLESS by construction: it SELF-VERIFIES
/// against the node's O(1) `root` (a forged/wrong witness is rejected — no trusted issuer), and the SPENDER
/// self-builds it from the public replicated block stream (no witness-server that could censor). Serializable so a
/// spend carries it on the wire; `Vec<Digest4>` = `Vec<[u64;4]>` serdes natively.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InsertWitness {
    /// The low leaf's value (`low.value < nf`).
    pub low_value: [u8; 32],
    /// The low leaf's successor pointer (`nf < low.next`, or `low.next == 0` meaning +∞).
    pub low_next: [u8; 32],
    /// The low leaf's position in the tree.
    pub low_index: u64,
    /// The low leaf's Merkle copath to `root` (`DEPTH` siblings, level 0 → top).
    pub low_copath: Vec<Digest4>,
    /// The append slot's (`= count`) Merkle copath, under the root AFTER the low leaf's `next` is updated to `nf`.
    pub new_copath: Vec<Digest4>,
}

/// The O(1) node-side nullifier accumulator: current Merkle `root` + leaf `count`. NO nullifier set stored. Its
/// serialized form is fixed-width (8-byte count + 32-byte root), so this state is TRUE constant size at any spend
/// count — like [`crate::frontier`]/[`crate::spend_frontier`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierTree {
    root: Digest4,
    count: u64,
}

/// `empty_subtree(l)` = the root of an all-empty subtree of height `l` (the empty-tail ladder). `l = 0` is the
/// empty leaf `[0;4]`; each level hashes the previous with itself. Identical convention to the spend frontier.
fn empty_subtree(level: usize) -> Digest4 {
    let mut e = empty_leaf();
    for _ in 0..level {
        e = poseidon_pair(e, e);
    }
    e
}

/// Poseidon hash of an IMT leaf `(value, next_value)` — the two 32-byte fields packed as Poseidon leaves and
/// combined. An empty (never-occupied) position is `empty_leaf()`, distinct from the initial `(0,0)` leaf hash.
pub fn hash_leaf(value: &[u8; 32], next: &[u8; 32]) -> Digest4 {
    poseidon_pair(nf_key(value), nf_key(next))
}

/// ⭐⭐⭐ THE IMT'S KEY — ONE DEFINITION, BORROWED, NOT MIRRORED.
///
/// ⛔⛔⛔ THIS FILE USED `cm_bytes_to_leaf` AND THE DECIDER USED `key_of`, AND THEY DISAGREE ON ONE
/// INPUT. `key_of` reserves the all-zero value and maps it to the ZERO DIGEST; `cm_bytes_to_leaf` is a
/// total hash with no special case, so it sends `[0; 32]` to `hash([0; 32])`. The IMT's `(0,0)` low leaf
/// is built from exactly that value — so the node's tree and the in-circuit tree hashed their sentinel
/// leaf DIFFERENTLY, their roots could never agree, and the carrier could not prove the transition its
/// own node had just made ("carrier post == the reals-only seam post", two different 8-lane digests).
///
/// ⭐ The repair is to CALL the decider's definition, not to re-state it here. A hash that has to be
/// byte-identical in two crates has one home; a second copy is how these two drifted in the first place,
/// and re-deriving it would only reset the clock on the next drift. The sentinel ordering that
/// [`nf_key_lt`] and [`belimb_key`] need falls out of it for free: `ZERO_DIGEST` sorts below every
/// nonzero key, lane for lane.
#[inline]
pub fn nf_key(v: &[u8; 32]) -> Digest4 {
    usdm_decider::nullifier_insert_air::key_of(v)
}

/// Fold `leaf_hash` at position `index` up `copath` (level 0 → top) to a candidate root. At each level the
/// index's bit selects whether the running node is the left (bit 0) or right (bit 1) child.
/// TEST-ONLY hash counter: proves the O(1) fold's work is FLAT (a fixed number of `poseidon_pair`s per insert),
/// independent of chain height — the decider-analog for the nullifier accumulator.
#[cfg(test)]
thread_local! {
    pub static NF_FOLD_HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn fold_to_root(mut node: Digest4, index: u64, copath: &[Digest4]) -> Digest4 {
    let mut i = index;
    for sib in copath.iter().take(NULLIFIER_TREE_DEPTH) {
        #[cfg(test)]
        NF_FOLD_HASHES.with(|c| c.set(c.get() + 1));
        node = if i & 1 == 0 {
            poseidon_pair(node, *sib)
        } else {
            poseidon_pair(*sib, node)
        };
        i >>= 1;
    }
    node
}

/// Canonical LIMB-lexicographic order on a nullifier's 32-byte serialization: compare its 4 KoalaBear leaf limbs
/// (`spend_frontier::cm_bytes_to_leaf`) MOST-significant-first. This is the EXACT total order the Gap3
/// nullifier-insert AIR (`usdm_decider::nullifier_insert_air`) proves in-circuit — so a low-leaf witness the node
/// builds satisfies the recursive O(1) block proof BY CONSTRUCTION. `nf = Poseidon(sk, leaf)` is a field digest,
/// so its canonical form IS these 4 limbs ⇒ this is a valid strict total order on real nullifiers.
pub fn nf_key_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // ⛔⛔⛔ WAS `(0..4).rev()` OVER `cm_bytes_to_leaf` — HALF THE KEY, AND THE WRONG KEY (kill list §AG;
    // the decider's `key_lt` had the identical width defect). A digest is EIGHT lanes, so two nullifiers
    // differing only above lane 3 compared EQUAL and the IMT's bracketing seated them in one leaf — the
    // set that exists to refuse a second spend could not tell them apart. And `cm_bytes_to_leaf` is not
    // the IMT's key at all: `nf_key` reserves the all-zero sentinel, which is what makes the `(0,0)` low
    // leaf the minimum rather than a value that happens to hash low.
    // ⭐ `ka.len()` and not a constant: the loop bound IS the key width, so it cannot be left behind again.
    let ka = nf_key(a);
    let kb = nf_key(b);
    for c in (0..ka.len()).rev() {
        if ka[c] != kb[c] {
            return ka[c] < kb[c];
        }
    }
    false
}

/// `nf < low_next`, treating `low_next == 0` (all-zero) as +∞ (the largest leaf has no successor). LIMB-order.
fn less_than_next(nf: &[u8; 32], low_next: &[u8; 32]) -> bool {
    if *low_next == [0u8; 32] {
        true // +∞ sentinel
    } else {
        nf_key_lt(nf, low_next)
    }
}

impl Default for NullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierTree {
    /// A fresh tree: position 0 holds the initial low leaf `(0, 0)` = "value 0 present, no successor (+∞)", every
    /// other position empty. `count = 1`. Any real nullifier `x > 0` brackets against this single leaf.
    pub fn new() -> Self {
        let init = hash_leaf(&[0u8; 32], &[0u8; 32]);
        // Leaf 0 is the leftmost leaf: at every level its sibling is the empty subtree of that level.
        let mut node = init;
        for level in 0..NULLIFIER_TREE_DEPTH {
            node = poseidon_pair(node, empty_subtree(level));
        }
        Self {
            root: node,
            count: 1,
        }
    }

    /// The current Merkle root (the O(1) nullifier commitment folded into the whole-chain proof / snapshot).
    pub fn root(&self) -> Digest4 {
        self.root
    }

    /// The 32-byte on-chain encoding of the root (little-endian limbs), for hashing into block/state commitments.
    pub fn root_bytes(&self) -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(self.root)
    }

    /// Number of occupied leaves (the next append index). Includes the initial `(0,0)` leaf.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// ADOPT a certified spent-state on #29 DSYNC (Gap2): jump this O(1) accumulator straight to `(root, count)`
    /// inherited from a verified [`crate::sync::SyncBundle`]. `root_bytes` is the 32-byte limb encoding
    /// ([`crate::spend_frontier::leaf_to_cm_bytes`]); it is BOUND into the bundle's `sync_binding` (tied to the
    /// decider-certified tip), so a joining node inherits a spent-state a peer cannot forge — the trustless O(1)
    /// jump twin of the frontier snapshot. Verifier-side only: a re-spend's carried `InsertWitness` self-verifies
    /// against this adopted `root` with NO stored set ([[project_trustless_nullifier_o1_design]] [[feedback_always_trustless]]).
    /// ⛔⛔⛔ WAS `cm_bytes_to_leaf`, WHICH IS A **HASH** (kill list §AG). This installed
    /// `hash(the certified root)` as the spent-state a joiner gates every spend against — a value the
    /// serving node never committed to and no carried `InsertWitness` can ever verify against. Same
    /// defect, same day, as `SparseNfAcc::adopt_merkle_root`; see
    /// [`crate::spend_frontier::cm_bytes_to_root`] for why the round-trip pair changed under everyone.
    ///
    /// `false` when the bytes are not a canonical digest: such a value did not come from this chain, and
    /// the tree is left exactly as it was rather than gated on something laundered into range.
    #[must_use]
    pub fn adopt(&mut self, root_bytes: [u8; 32], count: u64) -> bool {
        match crate::spend_frontier::cm_bytes_to_root(&root_bytes) {
            Some(r) => {
                self.root = r;
                self.count = count;
                true
            }
            None => false,
        }
    }

    /// Verify that `nf` is UNSPENT against the current `root` (using the DA-supplied witness) and INSERT it,
    /// advancing `root`/`count`. Returns `Err` (fail-closed, chain keeps running) if the witness does not prove
    /// non-membership — which is exactly what happens for an already-spent nullifier (double-spend rejected).
    pub fn verify_and_insert(
        &mut self,
        nf: &[u8; 32],
        w: &InsertWitness,
    ) -> Result<(), NullifierError> {
        if *nf == [0u8; 32] {
            return Err(NullifierError::ZeroNullifier);
        }
        if w.low_copath.len() != NULLIFIER_TREE_DEPTH || w.new_copath.len() != NULLIFIER_TREE_DEPTH
        {
            return Err(NullifierError::BadCopathLength);
        }
        // (1) NON-MEMBERSHIP: the low leaf's range must strictly bracket nf.
        if !(nf_key_lt(&w.low_value, nf) && less_than_next(nf, &w.low_next)) {
            return Err(NullifierError::NotBracketed);
        }
        // (2) The low leaf must actually be in the tree (membership against the current root).
        let low_hash = hash_leaf(&w.low_value, &w.low_next);
        if fold_to_root(low_hash, w.low_index, &w.low_copath) != self.root {
            return Err(NullifierError::BadLowMembership);
        }
        // (3) Update the low leaf's successor to nf → the intermediate root (same copath; only the leaf changed).
        let low_updated = hash_leaf(&w.low_value, nf);
        let root_mid = fold_to_root(low_updated, w.low_index, &w.low_copath);
        // (4) The append slot (index = count) must be EMPTY under the intermediate root.
        if fold_to_root(empty_leaf(), self.count, &w.new_copath) != root_mid {
            return Err(NullifierError::AppendSlotNotEmpty);
        }
        // (5) Append the new leaf (nf, old low.next) → the new root. nf is now spent.
        let new_leaf = hash_leaf(nf, &w.low_next);
        self.root = fold_to_root(new_leaf, self.count, &w.new_copath);
        self.count += 1;
        Ok(())
    }

    /// READ-ONLY non-membership check: does `w` prove `nf` is UNSPENT against the current root, WITHOUT mutating?
    /// The mempool admit gate uses this to reject a double-spend before block-apply (which does the real insert).
    /// TRUSTLESS: self-verifies against this node's own O(1) root — a stale/forged witness returns false; no stored
    /// nullifier set, no trusted party. Returns false (fail-closed) for the zero sentinel, a wrong-length copath, a
    /// range that does not bracket `nf`, or a low leaf that does not fold to the current root.
    pub fn verify_unspent(&self, nf: &[u8; 32], w: &InsertWitness) -> bool {
        if *nf == [0u8; 32] {
            return false;
        }
        if w.low_copath.len() != NULLIFIER_TREE_DEPTH {
            return false;
        }
        if !(nf_key_lt(&w.low_value, nf) && less_than_next(nf, &w.low_next)) {
            return false;
        }
        let low_hash = hash_leaf(&w.low_value, &w.low_next);
        fold_to_root(low_hash, w.low_index, &w.low_copath) == self.root
    }
}

// FIXED-WIDTH, height-invariant serialization (true constant size — the no-growth pillar): 8-byte big-endian
// `count` + 32-byte little-endian `root`. Byte-identical at any spend count. See the twin note on
// `crate::frontier::NoteFrontier`.
const NULLIFIER_TREE_WIRE_LEN: usize = 8 + 32;

impl serde::Serialize for NullifierTree {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; NULLIFIER_TREE_WIRE_LEN];
        buf[..8].copy_from_slice(&self.count.to_be_bytes());
        buf[8..].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(self.root));
        serializer.serialize_bytes(&buf)
    }
}

impl<'de> serde::Deserialize<'de> for NullifierTree {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NtVisitor;
        impl<'de> serde::de::Visitor<'de> for NtVisitor {
            type Value = NullifierTree;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("fixed-width NullifierTree bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<NullifierTree, E> {
                if b.len() != NULLIFIER_TREE_WIRE_LEN {
                    return Err(E::custom("bad NullifierTree wire length"));
                }
                let mut c = [0u8; 8];
                c.copy_from_slice(&b[..8]);
                let mut rb = [0u8; 32];
                rb.copy_from_slice(&b[8..]);
                // ⛔⛔⛔ THE ROUND TRIP MUST BE THE IDENTITY, AND IT WAS NOT. `serialize` writes
                // `leaf_to_cm_bytes` (the canonical injective encoding) and this read it back with
                // `cm_bytes_to_leaf` — a HASH since kill list §AG. So `deserialize(serialize(t)).root
                // != t.root`: EVERY restart brought the node back with a different double-spend root
                // than the one it saved, and its gate then disagreed with the chain it was resuming.
                // The pair is `digest_to_bytes` / `digest_from_bytes`, and the decode REFUSES a
                // non-canonical value rather than reducing it — a pre-fork or corrupt checkpoint is a
                // decode failure, never a different root.
                Ok(NullifierTree {
                    count: u64::from_be_bytes(c),
                    root: crate::spend_frontier::cm_bytes_to_root(&rb).ok_or_else(|| {
                        E::custom("non-canonical nullifier root — not a digest this chain produced")
                    })?,
                })
            }
        }
        deserializer.deserialize_bytes(NtVisitor)
    }
}

/// The FULL indexed Merkle nullifier tree — stores every leaf so it can (a) answer `is_spent`, and (b) GENERATE
/// the non-membership + insertion witnesses that the O(1) [`NullifierTree`] verifies. This is the PROVER / DA side:
/// a producing node uses it to build the block's nullifier witnesses; a pure verifier keeps only the O(1)
/// `NullifierTree` (root+count) and receives witnesses from DA. It is NEVER part of the persisted O(1) snapshot
/// (only `root`+`count` are); under the no-growth design its leaves live in DA (#27 DAS), never on disk, and a
/// returning node rebuilds it from DA rather than persisting the set.
#[derive(Clone, Debug)]
pub struct FullNullifierImt {
    pub leaves: Vec<([u8; 32], [u8; 32])>, // (value, next_value) per position; leaf 0 = the (0,0) low leaf
    /// MEMOIZED hashes of the OCCUPIED nodes, keyed `(level, subtree_index)` (level 0 = a leaf hash). A subtree with
    /// no occupied leaf is NOT stored — it folds to `empty_subtree(level)` — so this stays O(count), and a leaf change
    /// recomputes only the O(DEPTH) nodes on that leaf's root-path. This is what makes `insert_and_witness` O(DEPTH)
    /// instead of the old O(count) full-tree re-hash + full-`leaves` clone per insert (the padded-nullifier hot-path
    /// regression: a per-block rebuild of the 256×height set was O(count²)). It is transient producer state, NEVER
    /// persisted or sent (only the O(1) `NullifierTree` root+count is), so it carries no serde and no growth axis to
    /// the snapshot.
    nodes: std::collections::HashMap<(u8, u64), Digest4>,
    /// Predecessor index for O(log) `find_low`: the LIMB-lex key ([`nf_key_lt`] order, MSB limb first) → leaf position.
    /// Replaces the old O(count) linear scan over `leaves`. Byte-lex on the key == `nf_key_lt`, so a `BTreeMap` range
    /// query returns the exact bracketing low leaf.
    index: std::collections::BTreeMap<[u8; NF_KEY_BYTES], u64>,
}

impl Default for FullNullifierImt {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes in one BTreeMap key: every digest lane, big-endian, MSB lane first — `8 × DIGEST_LANES`.
pub const NF_KEY_BYTES: usize = 8 * usdm_decider::poseidon2_compress::DIGEST_LANES;

/// The LIMB-lex sort key of a nullifier value: its 4 KoalaBear limbs ([`cm_bytes_to_leaf`]) packed MSB-first as
/// big-endian bytes, so byte-lexicographic order on the key is EXACTLY [`nf_key_lt`]. Keys the O(log) predecessor
/// index; a purely local ordering aid, never a served value.
/// The ORDER KEY the IMT's index is sorted by — and it must agree with [`nf_key_lt`] on every pair, or
/// `find_low`'s range query and the bracketing check are two different orderings.
///
/// ⛔⛔⛔ IT PACKED FOUR LANES AND THE DIGEST HAS EIGHT (kill list §AG). `limbs[3..0]` big-endian is the
/// whole key only while a key IS four lanes; at eight it silently dropped half of every key, so the
/// BTreeMap's `range(..key)` ordered by a PREFIX while `nf_key_lt` (once repaired) ordered by the whole
/// thing. The two disagreeing is what produced `NotBracketed` on honest inserts: the range query returned
/// a predecessor the bracket check then rejected.
///
/// ⭐ AND THE SENTINEL IS PLACED, NOT HASHED. The `(0,0)` low leaf is indexed under the all-zero key, so
/// it really is the minimum of this ordering — matching `nf_key_lt`'s reservation. Indexing it at
/// `belimb_key(hash([0;32]))` put the sentinel in the middle of the key space, where it brackets nothing.
///
/// Eight lanes × 8 bytes = 64, so the key is `[u8; NF_KEY_BYTES]`: wider than the value it orders, which
/// is the honest shape — the ordering is over the DIGEST, not over the 32 bytes that hash to it. The width
/// is DERIVED from the lane count (§AG class 9: a literal here is a layout that cannot move).
pub fn belimb_key(v: &[u8; 32]) -> [u8; NF_KEY_BYTES] {
    let mut k = [0u8; NF_KEY_BYTES];
    // `nf_key` sends the reserved sentinel to the ZERO digest, so the low leaf lands at the all-zero key
    // — the true minimum of this ordering — with no special case needed here.
    let limbs = nf_key(v);
    // Big-endian, MSB lane first — an ORDERING key, not the wire form, so it cannot delegate to the
    // little-endian lane encoder. Bounded by ZIP over the key's own chunks (NF_KEY_BYTES = 8 × DIGEST_LANES):
    // no index arithmetic that could stride past either side when the width moves (§AG class 9).
    for (chunk, limb) in k.chunks_exact_mut(8).zip(limbs.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    k
}

impl FullNullifierImt {
    pub fn new() -> Self {
        let mut t = Self {
            leaves: vec![([0u8; 32], [0u8; 32])],
            nodes: std::collections::HashMap::new(),
            index: std::collections::BTreeMap::new(),
        };
        t.index.insert(belimb_key(&[0u8; 32]), 0);
        t.recompute_path(0);
        t
    }

    /// Hash of the OCCUPIED-aware node at `(level, idx)`: a fully-empty subtree (its leftmost leaf position is at or
    /// beyond `count`) folds to `empty_subtree(level)`; otherwise the memoized hash (an occupied node is always cached
    /// by `recompute_path`). Reproduces the EXACT sparse tree the old recursive `subtree` computed → identical roots.
    fn node_at(&self, level: usize, idx: u64) -> Digest4 {
        let first_leaf = first_leaf_under(idx, level); // leftmost leaf position under this subtree
        if first_leaf >= self.leaves.len() as u64 {
            return empty_subtree(level);
        }
        self.nodes
            .get(&(level as u8, idx))
            .copied()
            .unwrap_or_else(|| empty_subtree(level))
    }

    /// Recompute the memoized nodes on the root-path of leaf `pos` (O(DEPTH)). Called after every leaf mutation so the
    /// cache stays in lockstep with `leaves`; the root is `node_at(DEPTH, 0)`. Handles an EMPTIED position (`pos >=
    /// count`, after a `pop_insert` rollback): its leaf + any now-fully-empty ancestor are removed from the cache so
    /// `node_at` folds them to `empty_subtree` — the tree returns BYTE-IDENTICAL to before the undone insert.
    fn recompute_path(&mut self, pos: u64) {
        if (pos as usize) < self.leaves.len() {
            let (v, n) = self.leaves[pos as usize];
            self.nodes.insert((0u8, pos), hash_leaf(&v, &n));
        } else {
            self.nodes.remove(&(0u8, pos));
        }
        for level in 1..=NULLIFIER_TREE_DEPTH {
            let idx = subtree_index(pos, level);
            let first_leaf = first_leaf_under(idx, level);
            if first_leaf >= self.leaves.len() as u64 {
                self.nodes.remove(&(level as u8, idx)); // fully-empty subtree → node_at returns empty_subtree
            } else {
                let l = self.node_at(level - 1, idx * 2);
                let r = self.node_at(level - 1, idx * 2 + 1);
                self.nodes.insert((level as u8, idx), poseidon_pair(l, r));
            }
        }
    }

    /// Undo the most-recent `insert_and_witness` (reverse order), restoring the tree BYTE-IDENTICAL — the O(DEPTH)
    /// rollback that lets a producer DERIVE a block's post-root over the HELD working tree WITHOUT an O(count) clone
    /// (the tree is left exactly at the acc after the speculative derive). `low_index`/`old_low_next` come from the
    /// insert's returned `InsertWitness`. Undoes the append (pop the last leaf) then the low-leaf `next` update, in the
    /// reverse of the insert's (update-low, then append) order.
    pub fn pop_insert(&mut self, low_index: u64, old_low_next: &[u8; 32]) {
        let last = self.leaves.len().saturating_sub(1) as u64;
        if last == 0 {
            return; // never pop the (0,0) sentinel
        }
        let popped_val = self.leaves[last as usize].0;
        self.index.remove(&belimb_key(&popped_val));
        self.leaves.pop();
        self.recompute_path(last); // the popped position is now empty
        self.leaves[low_index as usize].1 = *old_low_next;
        self.recompute_path(low_index); // restore the low leaf's successor pointer
    }

    /// DERIVE the post-root over `padded` WITHOUT permanently mutating the tree (insert each, capture the root, then
    /// `pop_insert`-rollback every insert in reverse). O(padded·DEPTH), no O(count) clone. `None` iff a REAL nullifier
    /// is already spent (fail-closed) — the partial batch is rolled back before returning. This is the produce-side
    /// idempotent path: the held working tree is byte-identical afterward, so the following graft/ingest re-derives it
    /// (the acc advances there), never double-advancing.
    pub fn derive_post_root(&mut self, padded: &[[u8; 32]]) -> Option<[u8; 32]> {
        let mut undo: Vec<(u64, [u8; 32])> = Vec::with_capacity(padded.len());
        for nf in padded {
            match self.insert_and_witness(nf) {
                Ok(w) => undo.push((w.low_index, w.low_next)),
                Err(_) => {
                    for (li, ln) in undo.into_iter().rev() {
                        self.pop_insert(li, &ln);
                    }
                    return None;
                }
            }
        }
        let root = crate::spend_frontier::leaf_to_cm_bytes(self.root());
        for (li, ln) in undo.into_iter().rev() {
            self.pop_insert(li, &ln);
        }
        Some(root)
    }

    pub fn root(&self) -> Digest4 {
        self.node_at(NULLIFIER_TREE_DEPTH, 0)
    }

    pub fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn copath(&self, index: u64) -> Vec<Digest4> {
        (0..NULLIFIER_TREE_DEPTH)
            .map(|level| self.node_at(level, (index >> level) ^ 1))
            .collect()
    }

    /// Is `nf` already spent? — now the O(log) index lookup (was an O(count) linear scan). The all-zero value is the
    /// reserved IMT SENTINEL (initial low leaf / +∞ marker), never a real spend, so a query for 0 is "not spent".
    pub fn is_spent(&self, nf: &[u8; 32]) -> bool {
        if nf == &[0u8; 32] {
            return false;
        }
        self.index.contains_key(&belimb_key(nf))
    }

    /// The bracketing low leaf of `x` (`low.value < x < low.next`) via the O(log) predecessor index: the largest
    /// stored value strictly less than `x`. `None` if `x` is already present or unbracketed (fail-closed — the same
    /// double-spend rejection the linear scan gave).
    fn find_low(&self, x: &[u8; 32]) -> Option<u64> {
        let (_, &li) = self.index.range(..belimb_key(x)).next_back()?;
        let (v, n) = self.leaves[li as usize];
        if nf_key_lt(&v, x) && less_than_next(x, &n) {
            Some(li)
        } else {
            None
        }
    }

    /// Build the insertion witness for `nf` AND apply the insertion — O(DEPTH) via the memoized `nodes` (was O(count):
    /// a full-`leaves` clone + full-tree re-hash per insert, the padded-nullifier hot-path regression). `Err` if `nf`
    /// is zero or already spent (no bracketing low leaf) — the same fail-closed double-spend rejection.
    pub fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Result<InsertWitness, NullifierError> {
        if *nf == [0u8; 32] {
            return Err(NullifierError::ZeroNullifier);
        }
        let li = self.find_low(nf).ok_or(NullifierError::NotBracketed)?;
        let (lv, ln) = self.leaves[li as usize];
        let low_copath = self.copath(li); // BEFORE any mutation
                                          // (1) low.next → nf: mutate + recompute li's O(DEPTH) path → the intermediate ("mid") root.
        self.leaves[li as usize].1 = *nf;
        self.recompute_path(li);
        // (2) the append slot (index = old count) is still empty here; its copath is under the intermediate root —
        //     identical to the old code's `mid.copath(append_index)`, but read from the memoized nodes (no clone).
        let append_index = self.leaves.len() as u64;
        let new_copath = self.copath(append_index);
        // (3) append (nf, old low.next); index + recompute its O(DEPTH) path → the new root. `nf` is now spent.
        self.leaves.push((*nf, ln));
        self.index.insert(belimb_key(nf), append_index);
        self.recompute_path(append_index);
        Ok(InsertWitness {
            low_value: lv,
            low_next: ln,
            low_index: li,
            low_copath,
            new_copath,
        })
    }

    /// READ-ONLY: build the non-membership `InsertWitness` proving `nf` is UNSPENT, WITHOUT mutating the tree. This
    /// is the DA-SERVE side of the trustless flow — a node holding the tree answers a spender's witness query; the
    /// spender then CARRIES the returned witness in its tx and EVERY node self-verifies it against the O(1) root
    /// (`NullifierTree::verify_unspent`/`verify_and_insert`), so the serving node is NOT trusted (a wrong witness is
    /// rejected). `None` if `nf` is the zero sentinel or already spent (no bracketing low leaf → fail-closed).
    pub fn build_unspent_witness(&self, nf: &[u8; 32]) -> Option<InsertWitness> {
        if *nf == [0u8; 32] {
            return None;
        }
        let li = self.find_low(nf)?;
        let (lv, ln) = self.leaves[li as usize];
        let low_copath = self.copath(li);
        // new_copath = the append slot's copath AFTER low.next→nf, computed via an O(DEPTH) overlay so `self` is never
        // mutated and never cloned (this is a read-only serve, not an insert).
        let new_copath =
            self.copath_with_leaf_override(self.leaves.len() as u64, li, hash_leaf(&lv, nf));
        Some(InsertWitness {
            low_value: lv,
            low_next: ln,
            low_index: li,
            low_copath,
            new_copath,
        })
    }

    /// The copath of `index` computed as if leaf `changed_pos`'s hash were `changed_hash`, WITHOUT mutating `self` —
    /// an O(DEPTH) overlay of that leaf's root-path laid over the memoized `nodes`. Used by the read-only serve to
    /// reflect the low-leaf `next→nf` update (the "mid" root) without cloning `leaves`.
    fn copath_with_leaf_override(
        &self,
        index: u64,
        changed_pos: u64,
        changed_hash: Digest4,
    ) -> Vec<Digest4> {
        let mut overlay: std::collections::HashMap<(u8, u64), Digest4> =
            std::collections::HashMap::new();
        overlay.insert((0u8, changed_pos), changed_hash);
        for level in 1..=NULLIFIER_TREE_DEPTH {
            let idx = subtree_index(changed_pos, level);
            let l = self.node_ov(level - 1, idx * 2, &overlay);
            let r = self.node_ov(level - 1, idx * 2 + 1, &overlay);
            overlay.insert((level as u8, idx), poseidon_pair(l, r));
        }
        (0..NULLIFIER_TREE_DEPTH)
            .map(|level| self.node_ov(level, (index >> level) ^ 1, &overlay))
            .collect()
    }

    fn node_ov(
        &self,
        level: usize,
        idx: u64,
        overlay: &std::collections::HashMap<(u8, u64), Digest4>,
    ) -> Digest4 {
        if let Some(h) = overlay.get(&(level as u8, idx)) {
            return *h;
        }
        self.node_at(level, idx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// TREELESS PRODUCE SEAM — build the block's 256 nullifier witnesses WITHOUT a node holding the O(N) tree.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//
// The producer used to hold a full `FullNullifierImt` in RAM (a per-spend growth axis) purely to BUILD each block's
// InsertWitnesses. This seam removes that: the pre-block tree lives SHARDED across the mesh (#27 DAS); the producer
// fetches only the O(DEPTH) neighborhood it needs per value (`BaseNullifierTree`) and applies its OWN ≤256 block
// inserts as a BOUNDED overlay (`PartialNullifierImt`, O(256·DEPTH) held, discarded after the block). Both the full
// tree (a serving/archival shard) and the partial tree expose the SAME `NfInsertTree` interface, so `node.rs`'s
// carrier/derive path is generic over "where the tree lives" and a phone produces byte-identically to a desktop.
// The `partial_matches_full_tree_byte_identical` test is the soundness oracle: the overlay tree yields the EXACT
// witnesses + post-root the held tree would — so `verify_and_insert`/the Gap-3 AIR accept it unchanged, trustlessly.
// ([[project_phone_full_node_o1_produce_fold]] [[feedback_no_growth_any_axis]] [[feedback_always_trustless]])

/// The seam a producer inserts through. Implemented by both the full held tree (a DA shard / archival node) and the
/// bounded `PartialNullifierImt` (a phone-class producer). `insert_and_witness` MUST advance the tree AND return the
/// same self-verifying `InsertWitness` a `FullNullifierImt` would, so a treeless verifier's O(1) `verify_and_insert`
/// accepts it. No method here is O(count): appends touch O(DEPTH) nodes.
pub trait NfInsertTree {
    fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Result<InsertWitness, NullifierError>;
    /// Occupied-leaf count (the next append index) — matches [`FullNullifierImt::count`].
    fn count(&self) -> u64;
    /// The current 32-byte root — matches [`FullNullifierImt`]'s root encoding.
    fn root_bytes(&self) -> [u8; 32];
}

impl NfInsertTree for FullNullifierImt {
    fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Result<InsertWitness, NullifierError> {
        FullNullifierImt::insert_and_witness(self, nf)
    }
    fn count(&self) -> u64 {
        FullNullifierImt::count(self)
    }
    fn root_bytes(&self) -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(FullNullifierImt::root(self))
    }
}

/// The SHARDED pre-block tree a partial producer queries — the #27 DAS serve side. A node holding a shard (or the
/// whole tree, for an archival serve) answers O(DEPTH) neighborhood queries; the producer holds NONE of it. TRUSTLESS:
/// the producer never trusts these answers — every witness it builds from them self-verifies against the O(1) acc root
/// (`verify_and_insert`), so a shard that lies produces a witness that is simply rejected, never a wrong spend.
pub trait BaseNullifierTree {
    /// Occupied-leaf count of the base (pre-block) tree.
    fn base_count(&self) -> u64;
    /// The base tree's node at `(level, idx)` (occupied-aware: a fully-empty subtree folds to `empty_subtree`). Only
    /// called for `idx` within the base's occupied range; the partial handles appended positions from its overlay.
    fn base_node(&self, level: usize, idx: u64) -> Digest4;
    /// The largest base leaf value STRICTLY less than `x` (LIMB-lex predecessor) + its `(value, next, index)`. `None`
    /// only for `x == 0`. The partial refines this with its own overlaid leaves + does the final bracket check, so this
    /// returns the raw predecessor even when a later overlay insert now sits between it and `x`.
    fn base_predecessor(&self, x: &[u8; 32]) -> Option<([u8; 32], [u8; 32], u64)>;
}

impl BaseNullifierTree for FullNullifierImt {
    fn base_count(&self) -> u64 {
        self.leaves.len() as u64
    }
    fn base_node(&self, level: usize, idx: u64) -> Digest4 {
        self.node_at(level, idx)
    }
    fn base_predecessor(&self, x: &[u8; 32]) -> Option<([u8; 32], [u8; 32], u64)> {
        let (_, &li) = self.index.range(..belimb_key(x)).next_back()?;
        let (v, n) = self.leaves[li as usize];
        Some((v, n, li))
    }
}

/// A BOUNDED overlay over a sharded [`BaseNullifierTree`]: it reproduces the exact indexed-Merkle tree the producer
/// would hold, but stores ONLY this block's ≤256 inserts (modified low leaves + appended leaves + the O(DEPTH) nodes
/// on their root-paths). Every untouched subtree is fetched from the base on demand (O(DEPTH) per query). Held state
/// is O(256·DEPTH), never O(count) — so a phone produces without the tree. Mirrors `FullNullifierImt`'s hash
/// conventions EXACTLY (`hash_leaf`/`poseidon_pair`/`empty_subtree`), verified byte-identical by the seam test.
pub struct PartialNullifierImt<'a> {
    base: &'a dyn BaseNullifierTree,
    /// (value, next) for positions this block TOUCHED (a modified base low leaf, or an appended leaf).
    over_leaves: std::collections::HashMap<u64, ([u8; 32], [u8; 32])>,
    /// LIMB-lex key → position for leaves this block APPENDED (refines `find_low`'s predecessor search).
    over_index: std::collections::BTreeMap<[u8; NF_KEY_BYTES], u64>,
    /// Recomputed nodes on touched root-paths; shadows `base_node` for any subtree this block mutated.
    over_nodes: std::collections::HashMap<(u8, u64), Digest4>,
    /// Occupied-leaf count = base_count + appends so far.
    count: u64,
}

impl<'a> PartialNullifierImt<'a> {
    /// A fresh overlay over `base` at the pre-block state (no inserts applied yet).
    pub fn new(base: &'a dyn BaseNullifierTree) -> Self {
        Self {
            count: base.base_count(),
            base,
            over_leaves: std::collections::HashMap::new(),
            over_index: std::collections::BTreeMap::new(),
            over_nodes: std::collections::HashMap::new(),
        }
    }

    /// Occupied-aware node at `(level, idx)`: overlay shadow first, then a fully-empty tail (`first_leaf >= count`)
    /// folds to `empty_subtree`, else the base's node. Identical result to `FullNullifierImt::node_at` on the combined
    /// leaf set.
    fn node_at(&self, level: usize, idx: u64) -> Digest4 {
        if let Some(h) = self.over_nodes.get(&(level as u8, idx)) {
            return *h;
        }
        let first_leaf = first_leaf_under(idx, level);
        if first_leaf >= self.count {
            return empty_subtree(level);
        }
        // Positions in `[base_count, count)` are this block's appends; if occupied they are in `over_nodes` (handled
        // above), so a miss here means the whole subtree is within the base's occupied range → ask the base.
        self.base.base_node(level, idx)
    }

    fn copath(&self, index: u64) -> Vec<Digest4> {
        (0..NULLIFIER_TREE_DEPTH)
            .map(|level| self.node_at(level, (index >> level) ^ 1))
            .collect()
    }

    /// The current `(value, next)` at `pos` — only ever called for a position this block has written (a touched low
    /// leaf or an append), so the overlay always holds it.
    /// `None` (unreachable by construction) ⇒ the caller writes nothing for `pos`.
    fn leaf_at(&self, pos: u64) -> Option<([u8; 32], [u8; 32])> {
        self.over_leaves.get(&pos).copied()
    }

    /// Recompute the memoized nodes on `pos`'s root-path into the overlay (O(DEPTH)) — the twin of
    /// [`FullNullifierImt::recompute_path`], writing to `over_nodes` (children resolved via the base-aware `node_at`).
    fn recompute_path(&mut self, pos: u64) {
        let Some((v, n)) = self.leaf_at(pos) else { return };
        self.over_nodes.insert((0u8, pos), hash_leaf(&v, &n));
        for level in 1..=NULLIFIER_TREE_DEPTH {
            let idx = subtree_index(pos, level);
            let l = self.node_at(level - 1, idx * 2);
            let r = self.node_at(level - 1, idx * 2 + 1);
            self.over_nodes
                .insert((level as u8, idx), poseidon_pair(l, r));
        }
    }

    /// The bracketing low leaf of `nf` over the COMBINED (base + overlay) tree: the largest leaf value `< nf` whose
    /// (possibly overlaid) `next` still exceeds `nf`. `None` ⇒ `nf` already present (double-spend, fail-closed).
    fn find_low(&self, nf: &[u8; 32]) -> Option<(u64, [u8; 32], [u8; 32])> {
        let key = belimb_key(nf);
        let base_pred = self.base.base_predecessor(nf);
        let over_pred = self
            .over_index
            .range(..key)
            .next_back()
            .and_then(|(_, &oi)| self.leaf_at(oi).map(|(v, _)| (v, oi)));
        // Choose the larger predecessor value (the true immediate predecessor in the merged linked list).
        let (pi, pv) = match (base_pred, over_pred) {
            (Some((bv, _, bi)), Some((ov, oi))) => {
                if nf_key_lt(&bv, &ov) {
                    (oi, ov)
                } else {
                    (bi, bv)
                }
            }
            (Some((bv, _, bi)), None) => (bi, bv),
            (None, Some((ov, oi))) => (oi, ov),
            (None, None) => return None,
        };
        // Its CURRENT next (overlay shadows the base if this block already updated that leaf's successor).
        let (cur_v, cur_next) = self
            .over_leaves
            .get(&pi)
            .copied()
            .or_else(|| {
                base_pred
                    .filter(|(_, _, bi)| *bi == pi)
                    .map(|(v, n, _)| (v, n))
            })
            .unwrap_or((pv, [0u8; 32]));
        if nf_key_lt(&cur_v, nf) && less_than_next(nf, &cur_next) {
            Some((pi, cur_v, cur_next))
        } else {
            None // nf is already a leaf, or lands outside — fail-closed (double-spend rejected)
        }
    }
}

impl<'a> NfInsertTree for PartialNullifierImt<'a> {
    /// Byte-identical twin of [`FullNullifierImt::insert_and_witness`] over the base+overlay tree: (1) find low leaf,
    /// (2) copath BEFORE mutation, (3) low.next → nf → intermediate root, (4) append `(nf, old_next)` at `count`.
    fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Result<InsertWitness, NullifierError> {
        if *nf == [0u8; 32] {
            return Err(NullifierError::ZeroNullifier);
        }
        let (li, lv, ln) = self.find_low(nf).ok_or(NullifierError::NotBracketed)?;
        let low_copath = self.copath(li); // BEFORE any mutation
                                          // (1) low.next → nf, recompute li's O(DEPTH) path → the intermediate ("mid") root.
        self.over_leaves.insert(li, (lv, *nf));
        self.recompute_path(li);
        // (2) the append slot (index = current count) is empty here; its copath is under the intermediate root.
        let append_index = self.count;
        let new_copath = self.copath(append_index);
        // (3) append (nf, old low.next); index it; recompute its O(DEPTH) path → the new root. nf is now spent.
        self.over_leaves.insert(append_index, (*nf, ln));
        self.over_index.insert(belimb_key(nf), append_index);
        self.count += 1;
        self.recompute_path(append_index);
        Ok(InsertWitness {
            low_value: lv,
            low_next: ln,
            low_index: li,
            low_copath,
            new_copath,
        })
    }
    fn count(&self) -> u64 {
        self.count
    }
    fn root_bytes(&self) -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(self.node_at(NULLIFIER_TREE_DEPTH, 0))
    }
}

/// A [`BaseNullifierTree`] backed by SUPPLIED COPATHS instead of a held tree — the keystone of the FLAT-O(1)
/// block path. A producer holds only its O(1) acc + an O(DEPTH) frontier (the copath of the append boundary
/// `count`); each spend arrives with a spender-self-built low witness (the non-membership copath of its
/// nullifier's predecessor, [[project_trustless_nullifier_o1_design]]). This base answers the seam's O(DEPTH)
/// neighborhood queries from those supplied copaths + the frontier, so a [`PartialNullifierImt`] settles the whole
/// block byte-identically to a node holding the full tree — while holding only O(K·DEPTH), never O(count).
/// TRUSTLESS: every witness the seam builds still self-verifies against the O(1) acc root, so a lying supplier
/// produces a rejected witness, never a wrong spend. ([[feedback_no_growth_any_axis]] [[feedback_always_trustless]])
pub struct CopathBase {
    base_count: u64,
    /// Occupied base nodes learned from the frontier (append-boundary copath) + each supplied low copath. A miss is
    /// a genuinely-empty subtree (`empty_subtree`) — the seam only queries siblings these copaths cover.
    nodes: std::collections::HashMap<(u8, u64), Digest4>,
    /// nf → its supplied pre-block predecessor `(low_value, low_next, low_index)` for `find_low`.
    preds: std::collections::HashMap<[u8; 32], ([u8; 32], [u8; 32], u64)>,
}

impl CopathBase {
    /// Build from the producer's held O(DEPTH) `frontier` (the copath of position `base_count`) and the block's
    /// spender-supplied low witnesses `(nf, InsertWitness)` (only `low_value/low_next/low_index/low_copath` are read;
    /// the append copaths are producer-derived from the frontier, so a spender need not know the intra-block order).
    pub fn from_supplied(
        base_count: u64,
        frontier: &[Digest4],
        supplied: &[([u8; 32], InsertWitness)],
    ) -> Self {
        let mut nodes = std::collections::HashMap::new();
        // The append-boundary frontier: the sibling of `base_count` at each level.
        for (level, sib) in frontier.iter().enumerate().take(NULLIFIER_TREE_DEPTH) {
            nodes.insert((level as u8, (base_count >> level) ^ 1), *sib);
        }
        let mut preds = std::collections::HashMap::new();
        for (nf, w) in supplied {
            // The non-membership neighborhood: the siblings along the low leaf's path.
            for (level, sib) in w.low_copath.iter().enumerate().take(NULLIFIER_TREE_DEPTH) {
                nodes.insert((level as u8, (w.low_index >> level) ^ 1), *sib);
            }
            preds.insert(*nf, (w.low_value, w.low_next, w.low_index));
        }
        Self {
            base_count,
            nodes,
            preds,
        }
    }
}

impl BaseNullifierTree for CopathBase {
    fn base_count(&self) -> u64 {
        self.base_count
    }
    fn base_node(&self, level: usize, idx: u64) -> Digest4 {
        // A supplied node shadows; a miss is a genuinely-empty subtree the copaths didn't need to cover.
        self.nodes
            .get(&(level as u8, idx))
            .copied()
            .unwrap_or_else(|| empty_subtree(level))
    }
    fn base_predecessor(&self, x: &[u8; 32]) -> Option<([u8; 32], [u8; 32], u64)> {
        self.preds.get(x).copied()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// Deterministic varied 32-byte nullifier from a seed (splitmix64-filled) — nonzero, mixed LIMB order so the
    /// low-leaf search exercises predecessors scattered across the base tree AND the block overlay.
    fn nf_from(seed: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
        for chunk in out.chunks_mut(8) {
            z = z.wrapping_add(0x9E3779B97F4A7C15);
            let mut v = z;
            v = (v ^ (v >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            v = (v ^ (v >> 27)).wrapping_mul(0x94D049BB133111EB);
            v ^= v >> 31;
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        out[0] |= 0x01; // guarantee nonzero
        out
    }

    /// Build a base `FullNullifierImt` AND the lockstep O(1) `NullifierTree` acc over `base_seeds`.
    fn base_pair(base_seeds: &[u64]) -> (FullNullifierImt, NullifierTree) {
        let mut full = FullNullifierImt::new();
        let mut acc = NullifierTree::new();
        for &s in base_seeds {
            let nf = nf_from(s);
            let w = full.insert_and_witness(&nf).expect("base insert");
            acc.verify_and_insert(&nf, &w).expect("base acc insert");
        }
        (full, acc)
    }

    /// ⭐ SEAM SOUNDNESS ORACLE (B1/B3): a treeless producer's `PartialNullifierImt` (O(256·DEPTH) overlay over a
    /// SHARDED base) builds the BYTE-IDENTICAL 256 witnesses + post-root a node HOLDING the full tree would — so the
    /// O(1) verifier's `verify_and_insert` accepts them unchanged and lands the SAME root. This is what lets a phone
    /// produce without the O(N) tree. ([[project_phone_full_node_o1_produce_fold]])
    #[test]
    fn partial_matches_full_tree_byte_identical() {
        // A non-trivial base (stands in for the deep chain history living in the sharded DA).
        let base_seeds: Vec<u64> = (1_000..1_600).collect();
        let (base_full, base_acc) = base_pair(&base_seeds);

        // The block's 256-wide padded set (reals + secret-seeded decoys), values scattered vs the base.
        let padded: Vec<[u8; 32]> = (5_000..5_256).map(nf_from).collect();

        // (A) node HOLDING the full tree.
        let mut full_a = base_full.clone();
        let mut w_full = Vec::new();
        for nf in &padded {
            w_full.push(full_a.insert_and_witness(nf).expect("full insert"));
        }
        let root_full = crate::spend_frontier::leaf_to_cm_bytes(full_a.root());

        // (B) TREELESS producer: bounded overlay over the base it only QUERIES (never holds).
        let mut partial = PartialNullifierImt::new(&base_full);
        let mut w_partial = Vec::new();
        for nf in &padded {
            w_partial.push(partial.insert_and_witness(nf).expect("partial insert"));
        }
        let root_partial = partial.root_bytes();

        // Byte-identical witnesses AND post-root — the partial is indistinguishable from the held tree.
        assert_eq!(
            w_full, w_partial,
            "partial witnesses must be byte-identical to the held tree's"
        );
        assert_eq!(
            root_full, root_partial,
            "partial post-root must equal the held tree's"
        );

        // The O(1) verifier (root+count only, NO tree) accepts every partial-built witness and lands the same root.
        let mut acc = base_acc.clone();
        for (nf, w) in padded.iter().zip(&w_partial) {
            acc.verify_and_insert(nf, w)
                .expect("treeless verifier accepts partial witness");
        }
        assert_eq!(
            acc.root_bytes(),
            root_full,
            "treeless acc lands the held-tree post-root"
        );

        // NO-GROWTH: the overlay is bounded by the block's inserts, INDEPENDENT of the base size.
        assert!(
            partial.over_leaves.len() <= padded.len() * 2 + 1,
            "overlay leaves bounded by block inserts, not base size"
        );
    }

    /// ⭐ FLAT-O(1) SETTLEMENT — the nullifier decider-analog. The producer/verifier settle a spend by folding a
    /// SUPPLIED witness into an accumulator that is JUST `(root, count)` — NO tree, NO history. This test proves the
    /// fold's work is a FIXED constant (a set number of hashes) that is BYTE-IDENTICAL whether the chain is at height
    /// ~256 or ~4096 (16×) — it never grows with height, exactly like the WHIR decider's constant verify. The tree is
    /// needed ONLY to BUILD a decoy's witness; a REAL spend's witness is spender-supplied ([[project_trustless_nullifier_o1_design]]),
    /// so a producer that settles only spender-witnessed reals (regenerating decoy cover at SERVE, not as tree
    /// inserts) produces in FLAT O(1). ([[feedback_no_growth_any_axis]] [[feedback_always_trustless]])
    #[test]
    fn nullifier_settle_is_flat_o1_regardless_of_height() {
        // The O(1) acc holds ONLY root+count — a fixed footprint at ANY height (no Vec/Map/tree).
        assert_eq!(
            std::mem::size_of::<NullifierTree>(),
            std::mem::size_of::<Digest4>() + std::mem::size_of::<u64>(),
            "the settlement accumulator is exactly (root, count) — O(1) memory at any chain height"
        );

        // Settle ONE fresh spend against a SHORT chain (~256) and a 16× TALLER chain (~4096), counting the fold's
        // hash work each time. The witness is built by a full tree here ONLY as test scaffolding (in production the
        // SPENDER self-builds it); we reset the counter AFTER building so we measure the SETTLE fold alone.
        let settle_hashes = |height: u64| -> u64 {
            let (mut full, mut acc) = base_pair(&(1..=height).collect::<Vec<u64>>());
            let fresh = nf_from(10_000_000 + height); // a value above the base range → a real, fresh spend
            let w = full
                .insert_and_witness(&fresh)
                .expect("build witness (spender does this in prod)");
            NF_FOLD_HASHES.with(|c| c.set(0)); // measure ONLY the O(1) settle below
            acc.verify_and_insert(&fresh, &w)
                .expect("O(1) acc settles the supplied witness");
            NF_FOLD_HASHES.with(|c| c.get())
        };

        let short = settle_hashes(256);
        let tall = settle_hashes(4_096); // 16× the height

        // FLAT-O(1): the settle does the SAME fixed hash work at both heights — it does not grow with the chain.
        // (4 `fold_to_root` calls × DEPTH siblings each = a constant, independent of `count`.)
        assert_eq!(
            short, tall,
            "settle work must be height-INVARIANT (flat O(1) like the decider): h=256 did {short} hashes, h=4096 did {tall}"
        );
        assert_eq!(
            short,
            4 * NULLIFIER_TREE_DEPTH as u64,
            "settle is exactly 4 depth-folds (low-membership, low-update, append-empty, append) — a fixed constant"
        );
    }

    /// ⭐ FLAT-O(1) PRODUCE CORE — a PRODUCER holding ONLY the O(1) `(root,count)` acc (NO tree) settles a whole
    /// block of K SUPPLIED witnesses and lands a post-root doing a FIXED 128 hashes per spend — byte-identical at
    /// height ~256 and ~4096. The producer's per-block work is K·128 (K = the block's real spends, ≤ block capacity —
    /// a CONSTANT independent of chain height), and it holds zero tree. This is the decider-shaped produce: witnesses
    /// are the spenders' job (self-built from the replicated DA stream, [[project_trustless_nullifier_o1_design]]);
    /// the producer just folds them. The one thing still tying a producer to a held tree is BUILDING decoy witnesses —
    /// removing decoys from the tree (serve-time cover) is what makes produce fully tree-free. ([[feedback_no_growth_any_axis]])
    #[test]
    fn producer_settles_block_flat_o1_holding_no_tree() {
        // K real spends this block (bounded by block capacity — NEVER by chain height).
        let reals: Vec<[u8; 32]> = (7_000_000..7_000_008).map(nf_from).collect();

        // Run the SAME block against a short chain and a 16× taller one; the PRODUCER is only a NullifierTree (O(1)).
        let settle_block = |height: u64| -> ([u8; 32], u64) {
            // "The spenders" hold the stream/tree and self-build each witness fresh against the CURRENT root; the
            // producer (the O(1) acc) never touches this — it only receives (nf, witness) and folds.
            let (mut spender_side, mut producer_acc) =
                base_pair(&(1..=height).collect::<Vec<u64>>());
            NF_FOLD_HASHES.with(|c| c.set(0));
            for nf in &reals {
                let w = spender_side
                    .insert_and_witness(nf)
                    .expect("spender self-builds witness from the stream");
                producer_acc
                    .verify_and_insert(nf, &w)
                    .expect("producer folds it into the O(1) acc — no tree");
            }
            (producer_acc.root_bytes(), NF_FOLD_HASHES.with(|c| c.get()))
        };

        let (root_short, hashes_short) = settle_block(256);
        let (root_tall, hashes_tall) = settle_block(4_096);

        // (1) The producer's settle work is FLAT — identical at both heights, and exactly K·128 (no height term).
        assert_eq!(
            hashes_short, hashes_tall,
            "producer block-settle work must be height-INVARIANT: h=256 did {hashes_short}, h=4096 did {hashes_tall}"
        );
        assert_eq!(
            hashes_short,
            reals.len() as u64 * 4 * NULLIFIER_TREE_DEPTH as u64,
            "block settle = K spends × 4 depth-folds each — bounded by block capacity, NEVER by chain height"
        );
        // (2) The producer is the O(1) acc itself — a fixed (root,count) footprint at ANY height, holding no tree.
        assert_eq!(
            std::mem::size_of::<NullifierTree>(),
            std::mem::size_of::<Digest4>() + std::mem::size_of::<u64>(),
            "the producer holds only (root,count) — O(1) memory regardless of chain height"
        );
        // (Roots differ across heights because the base differs — the point is the WORK/RAM are flat, not the root.)
        let _ = (root_short, root_tall);
    }

    /// ⭐ FLAT-O(1) BLOCK PATH — a producer holding ONLY its O(1) acc + an O(DEPTH) frontier (NO tree) settles a
    /// whole block from SPENDER-SUPPLIED low witnesses (via [`CopathBase`]) and lands the BYTE-IDENTICAL post-root a
    /// node holding the full tree would. Held state is O(K·DEPTH) (the block) + O(DEPTH) (the frontier), NEVER
    /// O(count) — so the producer is treeless. This is the produce path node-perf can wire: the seam runs against
    /// copaths the spenders self-build, not a held tree. ([[project_phone_full_node_o1_produce_fold]])
    #[test]
    fn producer_settles_block_from_supplied_copaths_no_tree() {
        // Base = the chain history a NODE never has to hold (lives in the replicated DA the spenders read).
        let (base_full, _base_acc) = base_pair(&(1..=300u64).collect::<Vec<u64>>());
        let count = base_full.count();

        // The producer's ONLY held nullifier state besides the O(1) acc root: the O(DEPTH) frontier = the copath of
        // the append boundary `count`. (Maintained incrementally in production; extracted here as scaffolding.)
        let frontier: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
            .map(|l| base_full.node_at(l, (count >> l) ^ 1))
            .collect();

        // K real spends, each with a spender-SELF-BUILT low witness (predecessor + its non-membership copath) against
        // the pre-block root — exactly what a wallet builds from the replicated DA stream.
        let reals: Vec<[u8; 32]> = (8_000_000..8_000_008).map(nf_from).collect();
        let supplied: Vec<([u8; 32], InsertWitness)> = reals
            .iter()
            .map(|nf| {
                let (lv, ln, li) = base_full.base_predecessor(nf).expect("predecessor exists");
                let low_copath: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
                    .map(|l| base_full.node_at(l, (li >> l) ^ 1))
                    .collect();
                (
                    *nf,
                    InsertWitness {
                        low_value: lv,
                        low_next: ln,
                        low_index: li,
                        low_copath,
                        new_copath: Vec::new(),
                    },
                )
            })
            .collect();

        // (A) TREELESS producer: seam over a CopathBase built from the frontier + supplied lows. Holds no tree.
        let cbase = CopathBase::from_supplied(count, &frontier, &supplied);
        let mut seam = PartialNullifierImt::new(&cbase);
        for nf in &reals {
            NfInsertTree::insert_and_witness(&mut seam, nf)
                .expect("treeless producer settles the supplied spend");
        }
        let post_treeless = NfInsertTree::root_bytes(&seam);

        // (B) node HOLDING the full tree settles the SAME K reals.
        let mut full = base_full.clone();
        for nf in &reals {
            full.insert_and_witness(nf).expect("held-tree insert");
        }
        let post_full = crate::spend_frontier::leaf_to_cm_bytes(full.root());

        assert_eq!(
            post_treeless, post_full,
            "treeless block path lands the EXACT held-tree post-root"
        );

        // NO-GROWTH: the producer's transient state is O(K·DEPTH) + O(DEPTH) frontier — bounded by the block, not N.
        assert!(
            cbase.nodes.len() <= (reals.len() + 1) * NULLIFIER_TREE_DEPTH,
            "copath base holds only the block's + frontier's O(DEPTH) neighborhoods, never O(count)"
        );
        assert!(
            frontier.len() == NULLIFIER_TREE_DEPTH,
            "frontier is O(DEPTH), independent of chain height"
        );
    }

    /// ⭐ KEYSTONE — flat-O(1) + volume, COMPOSED end-to-end: a producer holding ONLY the O(DEPTH) frontier (NO
    /// tree) settles REALS-ONLY through `CopathBase` (spender copaths), pads to a CONSTANT `n_rows` with NO-OP rows,
    /// and emits the block carrier; a treeless PEER verifies it and adopts `post_root`. The tree advances by
    /// the K reals only (flat-O(1), no decoy copaths) while the observable trace stays a constant `n_rows` (K hidden
    /// — the volume fix). This is the node/circuit wiring the live cutover flips on. ([[project_phone_full_node_o1_produce_fold]])
    #[test]
    fn treeless_reals_only_noop_padded_block_produces_and_verifies_o1() {
        use usdm_decider::nullifier_insert_air as nia;
        // Chain history a node never holds (lives in the replicated DA the spenders read) + the pre-block acc root.
        let (base_full, base_acc) = base_pair(&(1..=200u64).collect::<Vec<u64>>());
        let count = base_full.count();
        let pre_limbs = base_acc.root(); // [u64;4] the carrier binds block_pre to

        // Producer's ONLY held nullifier state: the O(DEPTH) frontier (copath of the append boundary `count`).
        let frontier: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
            .map(|l| base_full.node_at(l, (count >> l) ^ 1))
            .collect();

        // K real spends, each with a spender-self-built low witness against the pre-block root.
        let reals: Vec<[u8; 32]> = (5_000_000..5_000_003).map(nf_from).collect(); // K=3
        let supplied: Vec<([u8; 32], InsertWitness)> = reals
            .iter()
            .map(|nf| {
                let (lv, ln, li) = base_full.base_predecessor(nf).expect("predecessor");
                let low_copath: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
                    .map(|l| base_full.node_at(l, (li >> l) ^ 1))
                    .collect();
                (
                    *nf,
                    InsertWitness {
                        low_value: lv,
                        low_next: ln,
                        low_index: li,
                        low_copath,
                        new_copath: Vec::new(),
                    },
                )
            })
            .collect();

        // TREELESS produce: seam over CopathBase (frontier + supplied copaths) → the K real insert witnesses.
        let cbase = CopathBase::from_supplied(count, &frontier, &supplied);
        let mut seam = PartialNullifierImt::new(&cbase);
        let mut inserts: Vec<nia::NfInsertWitness> = Vec::new();
        for nf in &reals {
            let c = NfInsertTree::count(&seam);
            let w = NfInsertTree::insert_and_witness(&mut seam, nf).expect("settle real");
            inserts.push(nia::NfInsertWitness {
                nf: *nf,
                low_value: w.low_value,
                low_next: w.low_next,
                low_index: w.low_index,
                count: c,
                low_copath: w.low_copath,
                new_copath: w.new_copath,
            });
        }
        // ⛔ WAS `cm_bytes_to_leaf(...)` — a ROOT round-tripped through a HASH (§AI). The carrier proves
        // about the DIGEST, so hashing the byte form here compared the carrier's post against
        // `hash(the seam post)` and they could never match.
        let seam_post = crate::spend_frontier::cm_bytes_to_root(&NfInsertTree::root_bytes(&seam)).expect("a root this tree produced decodes injectively");

        // Reals-only + NO-OP-padded block carrier (K reals + (n_rows−K) no-ops). n_rows is a CONSTANT (hides K).
        let n_rows = 8usize;
        let (carrier, carrier_post) =
            nia::prove_nullifier_block_carrier_padded_bytes(&inserts, pre_limbs, n_rows)
                .expect("reals-only no-op-padded block prove");
        assert_eq!(
            carrier_post, seam_post,
            "carrier post == the reals-only seam post (tree advanced by K reals only)"
        );

        // A treeless PEER verifies O(1) + adopts post_root — no held tree, K not derivable from the carrier.
        assert!(
            nia::verify_nullifier_block_carrier_padded_bytes(&carrier, pre_limbs, carrier_post, n_rows),
            "a treeless peer verifies the reals-only no-op-padded carrier O(1)"
        );
        let mut wrong = carrier_post;
        wrong[0] ^= 1;
        assert!(
            !nia::verify_nullifier_block_carrier_padded_bytes(&carrier, pre_limbs, wrong, n_rows),
            "a wrong post_root is rejected (fail-closed)"
        );
    }

    /// ⭐ CUTOVER CONVERGENCE GATE — two treeless nodes AGREE on a REALS-ONLY no-op-padded block. Node A produces
    /// (frontier only, settles K reals, pads no-ops, emits the carrier) and advances its O(1) acc by K. Node B holds
    /// only the same pre-acc, INDEPENDENTLY verifies A's carrier O(1), and adopts `(post_root, count+K)`. Both land
    /// the IDENTICAL `(root, count)` — the honest consensus gate the live cutover rides on (advance by real_count,
    /// NOT +256), with neither node holding a tree. ([[project_beacon_adopt_convergence]] [[feedback_always_trustless]])
    #[test]
    fn two_treeless_nodes_converge_on_reals_only_padded_block() {
        use usdm_decider::nullifier_insert_air as nia;
        let (base_full, base_acc) = base_pair(&(1..=200u64).collect::<Vec<u64>>());
        let count = base_full.count();
        let pre_limbs = base_acc.root();
        let pre_count = base_acc.count();

        // ── Node A: PRODUCER holding only the O(DEPTH) frontier + the O(1) acc (no tree). ──
        let frontier: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
            .map(|l| base_full.node_at(l, (count >> l) ^ 1))
            .collect();
        let reals: Vec<[u8; 32]> = (6_000_000..6_000_005).map(nf_from).collect(); // K=5 real spends
        let supplied: Vec<([u8; 32], InsertWitness)> = reals
            .iter()
            .map(|nf| {
                let (lv, ln, li) = base_full.base_predecessor(nf).expect("predecessor");
                let low_copath: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
                    .map(|l| base_full.node_at(l, (li >> l) ^ 1))
                    .collect();
                (
                    *nf,
                    InsertWitness {
                        low_value: lv,
                        low_next: ln,
                        low_index: li,
                        low_copath,
                        new_copath: Vec::new(),
                    },
                )
            })
            .collect();
        let cbase = CopathBase::from_supplied(count, &frontier, &supplied);
        let mut seam = PartialNullifierImt::new(&cbase);
        let mut inserts: Vec<nia::NfInsertWitness> = Vec::new();
        for nf in &reals {
            let c = NfInsertTree::count(&seam);
            let w = NfInsertTree::insert_and_witness(&mut seam, nf).expect("settle real");
            inserts.push(nia::NfInsertWitness {
                nf: *nf,
                low_value: w.low_value,
                low_next: w.low_next,
                low_index: w.low_index,
                count: c,
                low_copath: w.low_copath,
                new_copath: w.new_copath,
            });
        }
        let (carrier, post_limbs) =
            nia::prove_nullifier_block_carrier_padded_bytes(&inserts, pre_limbs, 8)
                .expect("prove");
        // A advances its O(1) acc by K (real_count) — NOT +256. post_root = the carrier's proven post.
        let mut acc_a = base_acc.clone();
        assert!(
            acc_a.adopt(
                crate::spend_frontier::leaf_to_cm_bytes(post_limbs),
                pre_count + reals.len() as u64,
            ),
            "a root the fixture produced must adopt — a refusal here means the canonical decode rejected this chain's own value"
        );

        // ── Node B: VERIFIER holding only the same pre-acc (no tree, never saw A's frontier or copaths). ──
        assert!(
            nia::verify_nullifier_block_carrier_padded_bytes(&carrier, pre_limbs, post_limbs, 8),
            "B independently verifies A's reals-only carrier O(1) (trustless adopt)"
        );
        let mut acc_b = base_acc.clone();
        assert!(
            acc_b.adopt(
                crate::spend_frontier::leaf_to_cm_bytes(post_limbs),
                pre_count + reals.len() as u64,
            ),
            "a root the fixture produced must adopt — a refusal here means the canonical decode rejected this chain's own value"
        );

        // CONVERGENCE: A (producer) and B (independent verifier) land the IDENTICAL O(1) acc, treelessly.
        assert_eq!(
            acc_a.root_bytes(),
            acc_b.root_bytes(),
            "producer and verifier converge on the SAME acc root"
        );
        assert_eq!(
            acc_a.count(),
            acc_b.count(),
            "…and the SAME acc count (advanced by K real spends, not 256)"
        );
        assert_eq!(
            acc_a.count(),
            pre_count + 5,
            "the count advanced by exactly the 5 real spends"
        );
        // A rogue post B would reject → no false convergence.
        let mut rogue = post_limbs;
        rogue[0] ^= 1;
        assert!(
            !nia::verify_nullifier_block_carrier_padded_bytes(&carrier, pre_limbs, rogue, 8),
            "a rogue post is rejected"
        );
    }

    /// ⭐ CORRECTED-DIRECTION KEYSTONE — a treeless producer builds the STANDARD CONSTANT-256 block (privacy intact:
    /// reals hidden among secret-seeded decoys, every block advances by the fixed 256, K burned) holding NO tree, and
    /// the UNCHANGED consensus carrier verifies it. The producer supplies ALL 256 low-copaths — reals self-built by
    /// spenders, DECOYS served from a sharded DA (#27 DAS) — into `CopathBase`; the seam yields the BYTE-IDENTICAL 256
    /// witnesses + post-root a held-tree node would, and `prove_nullifier_block_carrier_bytes` (the SAME
    /// constant-256 carrier already on-chain — NO reals-only, NO no-op padding, NO consensus change / re-genesis)
    /// verifies O(1). This is flat-O(1) WITHOUT touching the cover. ([[project_phone_full_node_o1_produce_fold]] [[feedback_digital_cash_pillar]])
    #[test]
    fn treeless_producer_builds_constant256_block_from_supplied_copaths() {
        use usdm_decider::nullifier_insert_air as nia;
        let (base_full, base_acc) = base_pair(&(1..=300u64).collect::<Vec<u64>>());
        let count = base_full.count();
        let pre_limbs = base_acc.root();
        // Producer's ONLY held nullifier state: the O(DEPTH) frontier (copath of the append boundary).
        let frontier: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
            .map(|l| base_full.node_at(l, (count >> l) ^ 1))
            .collect();

        // The CONSTANT-256 padded set: reals + secret-seeded decoys — indistinguishable, so ALL blocks look identical.
        let reals: Vec<[u8; 32]> = (7_000_000..7_000_003).map(nf_from).collect();
        let secret = crate::cover::nullifier_block_secret(
            b"blobs",
            &crate::spend_frontier::leaf_to_cm_bytes(pre_limbs),
        );
        let padded = crate::cover::nullifier_wire_fill(&reals, &secret);
        assert_eq!(
            padded.len(),
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT,
            "block is the fixed 256 cover"
        );

        // ALL 256 low-witnesses supplied — reals from spenders, DECOYS from a sharded DA serve — producer holds NO tree.
        let supplied: Vec<([u8; 32], InsertWitness)> = padded
            .iter()
            .map(|nf| {
                let (lv, ln, li) = base_full.base_predecessor(nf).expect("predecessor");
                let low_copath: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
                    .map(|l| base_full.node_at(l, (li >> l) ^ 1))
                    .collect();
                (
                    *nf,
                    InsertWitness {
                        low_value: lv,
                        low_next: ln,
                        low_index: li,
                        low_copath,
                        new_copath: Vec::new(),
                    },
                )
            })
            .collect();

        // TREELESS producer: seam over CopathBase → the 256 witnesses (no held tree).
        let cbase = CopathBase::from_supplied(count, &frontier, &supplied);
        let mut seam = PartialNullifierImt::new(&cbase);
        let mut inserts: Vec<nia::NfInsertWitness> = Vec::with_capacity(padded.len());
        for nf in &padded {
            let c = NfInsertTree::count(&seam);
            let w = NfInsertTree::insert_and_witness(&mut seam, nf).expect("settle padded nf");
            inserts.push(nia::NfInsertWitness {
                nf: *nf,
                low_value: w.low_value,
                low_next: w.low_next,
                low_index: w.low_index,
                count: c,
                low_copath: w.low_copath,
                new_copath: w.new_copath,
            });
        }
        let treeless_post = NfInsertTree::root_bytes(&seam);

        // Held-tree producer settles the SAME 256 → byte-identical post.
        let mut full = base_full.clone();
        for nf in &padded {
            full.insert_and_witness(nf).expect("held-tree insert");
        }
        assert_eq!(
            treeless_post,
            crate::spend_frontier::leaf_to_cm_bytes(full.root()),
            "treeless constant-256 producer is BYTE-IDENTICAL to the held-tree producer"
        );

        // The UNCHANGED on-chain constant-256 carrier verifies — no consensus change, no re-genesis.
        let (carrier, cpost) =
            nia::prove_nullifier_block_carrier_bytes(&inserts, pre_limbs)
                .expect("standard 256 carrier");
        assert_eq!(
            cpost,
            crate::spend_frontier::cm_bytes_to_root(&treeless_post).expect("a root this tree produced decodes injectively")
        );
        assert!(
            nia::verify_nullifier_block_carrier_bytes(&carrier, pre_limbs, cpost, inserts.len()),
            "the SAME constant-256 carrier already on-chain verifies the treeless-built block"
        );
    }

    /// ⭐ TRUSTLESS SHARDED SERVE (corrected brick 2 soundness): a LYING copath server cannot settle a spend. The
    /// witness a shard serves is checked by the O(1) consensus acc's `verify_and_insert` — a tampered low-copath does
    /// not fold to the committed root, so it is REJECTED (`BadLowMembership`). The producer just retries another
    /// shard; a lie is never a wrong spend, and needs no trusted server. ([[feedback_always_trustless]])
    #[test]
    fn lying_shard_witness_is_rejected_by_the_o1_acc() {
        let (mut full, mut acc) = base_pair(&(1..=100u64).collect::<Vec<u64>>());
        let nf = nf_from(555_000);
        // The HONEST witness a shard would serve (built from its tree; against the pre-insert root the acc holds).
        let honest = full
            .insert_and_witness(&nf)
            .expect("shard builds the served witness");
        // A LYING shard tampers the low copath.
        let mut lying = honest.clone();
        lying.low_copath[0] = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        // The O(1) consensus acc REJECTS the lying witness — a bad served copath can never settle a spend.
        assert_eq!(
            acc.verify_and_insert(&nf, &lying).unwrap_err(),
            NullifierError::BadLowMembership,
            "a lying shard's tampered copath does not fold to the acc root → rejected"
        );
        // The honest served witness settles fine against the SAME acc (unchanged by the rejected attempt).
        acc.verify_and_insert(&nf, &honest)
            .expect("the honest served witness settles");
    }

    /// ⭐⭐⭐ THE O(1)-PRODUCE ANSWER (retires PIR): the producer is flat-O(1) with ZERO retrieval — no serve, no PIR,
    /// no held tree. The cover is SPENDER-SUPPLIED PER-TX: every tx pads its own nullifier-insertions to a constant `M`
    /// (its reals + secret-seeded decoys), and the spender self-builds ALL `M` copaths from its OWN node view (trustless
    /// — the spender is already online to spend; reals ride the tx this way today, decoys just ride alongside). The
    /// producer concatenates every tx's supplied witnesses into `CopathBase`, holding ONLY the O(DEPTH) frontier, and
    /// settles the block — it builds/serves/queries NOTHING. So the copath cost lands on the TRANSIENT spender (once per
    /// spend), never on the always-on no-growth-critical producer. This is why sublinear PIR is the wrong tool: the
    /// producer needs no retrieval at all. Constant `M`/tx hides K (per-spend real count); a tampered decoy copath is
    /// rejected by the O(1) acc. ([[project_phone_full_node_o1_produce_fold]] [[feedback_digital_cash_pillar]] [[feedback_always_trustless]])
    #[test]
    fn producer_is_flat_o1_with_spender_supplied_per_tx_cover_no_serve_no_pir() {
        use usdm_decider::nullifier_insert_air as nia;
        const M: usize = 4; // per-tx cover width — every tx inserts exactly M nullifiers regardless of its real count.

        // A spender self-builds the InsertWitness for one nf from ITS OWN node view (here `view` stands in for the
        // spender's tree; in production the spender holds/oblivious-restores only its own spend neighborhood).
        fn spender_builds(view: &FullNullifierImt, nf: &[u8; 32]) -> InsertWitness {
            let (lv, ln, li) = view
                .base_predecessor(nf)
                .expect("spender finds predecessor in its own view");
            let low_copath: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
                .map(|l| view.node_at(l, (li >> l) ^ 1))
                .collect();
            InsertWitness {
                low_value: lv,
                low_next: ln,
                low_index: li,
                low_copath,
                new_copath: Vec::new(),
            }
        }

        let (base_full, base_acc) = base_pair(&(1..=300u64).collect::<Vec<u64>>());
        let count = base_full.count();
        let pre_limbs = base_acc.root();
        // The producer's ENTIRE held nullifier state: the O(DEPTH) frontier. Nothing else — no tree, no DA, no shard db.
        let frontier: Vec<Digest4> = (0..NULLIFIER_TREE_DEPTH)
            .map(|l| base_full.node_at(l, (count >> l) ^ 1))
            .collect();
        assert_eq!(
            frontier.len(),
            NULLIFIER_TREE_DEPTH,
            "producer holds exactly DEPTH digests — flat-O(1), any height"
        );

        // PRODUCTION-PARITY block: the full BLOCK_FIXED_NULLIFIER_COUNT (256) insertions, assembled as N_TX txs each
        // padded to the SAME per-tx width M (256 = N_TX·M). Real counts VARY per tx (1..=M) — each tx still inserts
        // exactly M, so its real count K is hidden inside the constant width. Every witness is spender-self-built.
        const N_TX: usize = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT / M; // 64 txs × M=4 = 256
        let mut supplied: Vec<([u8; 32], InsertWitness)> = Vec::new();
        let mut used: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut seed = 8_000_000u64;
        for t in 0..N_TX {
            let k = (t % M) + 1; // real count cycles 1..=M — the per-tx width M hides which it was
            let mut this_tx = 0usize;
            while this_tx < k {
                let nf = nf_from(seed);
                seed += 1;
                if !used.insert(nf) {
                    continue;
                }
                supplied.push((nf, spender_builds(&base_full, &nf))); // a REAL spend, spender-self-built
                this_tx += 1;
            }
            // Decoys pad THIS tx to M — secret-seeded per the spender's tx, indistinguishable from its reals, and the
            // spender builds their copaths from the same view. The producer will never learn which of the M are real.
            let tx_secret = crate::cover::nullifier_block_secret(
                &[t as u8],
                &crate::spend_frontier::leaf_to_cm_bytes(pre_limbs),
            );
            let mut d = 0usize;
            while this_tx < M {
                let decoy = crate::cover::cover_nullifier_det(&tx_secret, d);
                d += 1;
                if base_full.base_predecessor(&decoy).is_none() || !used.insert(decoy) {
                    continue;
                }
                supplied.push((decoy, spender_builds(&base_full, &decoy)));
                this_tx += 1;
            }
            assert_eq!(this_tx, M, "tx {t} inserts exactly M — its real count K={k} is hidden inside the constant width");
        }
        assert_eq!(
            supplied.len(),
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT,
            "block is the production-parity 256"
        );

        // ── TREELESS PRODUCER: folds the spender-supplied witnesses over CopathBase, holding ONLY the frontier. ──
        // It calls NO serve, NO PIR, NO tree — from_supplied consumes exactly what rode in on the txs.
        let cbase = CopathBase::from_supplied(count, &frontier, &supplied);
        let mut seam = PartialNullifierImt::new(&cbase);
        let mut inserts: Vec<nia::NfInsertWitness> = Vec::with_capacity(supplied.len());
        for (nf, _) in &supplied {
            let c = NfInsertTree::count(&seam);
            let w = NfInsertTree::insert_and_witness(&mut seam, nf)
                .expect("settle spender-supplied nf");
            inserts.push(nia::NfInsertWitness {
                nf: *nf,
                low_value: w.low_value,
                low_next: w.low_next,
                low_index: w.low_index,
                count: c,
                low_copath: w.low_copath,
                new_copath: w.new_copath,
            });
        }
        let treeless_post = NfInsertTree::root_bytes(&seam);

        // Byte-identical to a held-tree producer settling the SAME insertions — no consensus change.
        let mut full = base_full.clone();
        for (nf, _) in &supplied {
            full.insert_and_witness(nf).expect("held-tree insert");
        }
        assert_eq!(
            treeless_post,
            crate::spend_frontier::leaf_to_cm_bytes(full.root()),
            "the retrieval-free treeless producer is BYTE-IDENTICAL to a held-tree producer"
        );

        // The UNCHANGED on-chain carrier verifies the retrieval-free block O(1).
        let (carrier, cpost) =
            nia::prove_nullifier_block_carrier_bytes(&inserts, pre_limbs).expect("carrier");
        assert!(
            nia::verify_nullifier_block_carrier_bytes(&carrier, pre_limbs, cpost, inserts.len()),
            "the standard carrier verifies the block built with NO serve and NO PIR"
        );

        // TRUSTLESS: a spender (or relay) that tampers a supplied copath is rejected by the O(1) acc — never a wrong
        // spend, and the producer needed no trusted server to detect it. (Full witness built against the base acc.)
        let fresh = nf_from(9_999_001);
        let honest_full = base_full
            .clone()
            .insert_and_witness(&fresh)
            .expect("complete witness for a fresh nf");
        let mut tampered = honest_full.clone();
        tampered.low_copath[0] = usdm_decider::poseidon2_compress::lanes_of(&[7, 7, 7, 7]);
        let mut acc = base_acc.clone();
        assert_eq!(
            acc.verify_and_insert(&fresh, &tampered).unwrap_err(),
            NullifierError::BadLowMembership,
            "a tampered spender-supplied copath does not fold to the acc root → rejected"
        );
    }

    /// ⭐ SEAM TAMPER (B2/soundness): a double-spend is rejected at BOTH the treeless build (no bracketing low leaf)
    /// AND the O(1) verify — the seam never weakens the double-spend gate.
    #[test]
    fn partial_seam_rejects_double_spend() {
        let base_seeds: Vec<u64> = (1..300).collect();
        let (base_full, base_acc) = base_pair(&base_seeds);

        // (a) a value ALREADY in the base cannot be re-inserted via the partial (fail-closed at build).
        let already = nf_from(42);
        let mut partial = PartialNullifierImt::new(&base_full);
        assert_eq!(
            partial.insert_and_witness(&already).unwrap_err(),
            NullifierError::NotBracketed,
            "re-spend of a base nullifier has no bracketing low leaf → rejected at build"
        );

        // (b) a value inserted EARLIER in the SAME block cannot be inserted again (overlay double-spend).
        let fresh = nf_from(999_999);
        partial.insert_and_witness(&fresh).expect("first spend ok");
        assert_eq!(
            partial.insert_and_witness(&fresh).unwrap_err(),
            NullifierError::NotBracketed,
            "same-block re-spend rejected via the overlay predecessor"
        );

        // (c) a partial-built witness carried for an already-spent nf is rejected by the O(1) verifier too.
        let mut fresh_full = base_full.clone();
        let w = fresh_full
            .insert_and_witness(&fresh)
            .expect("build witness");
        let mut acc = base_acc.clone();
        acc.verify_and_insert(&fresh, &w).expect("first insert ok");
        assert!(
            acc.verify_and_insert(&fresh, &w).is_err(),
            "the O(1) verifier rejects the re-used witness (double-spend)"
        );
    }

    /// REGRESSION (node wedge root-cause): the produce→graft lockstep. `produce_template` calls
    /// `derive_post_root` (speculative insert-then-`pop_insert` rollback) and MUST leave the working tree
    /// byte-identical; the following graft's `nf_stream_apply` then REAL-inserts the SAME padded set and MUST
    /// reproduce the derived post-root. If the rollback is imperfect, the re-insert diverges → `nf_work` is
    /// dropped → `ensure_nf_work` full-rebuilds from DA EVERY block = O(N)/block = the 92%-CPU wedge at height.
    #[test]
    fn derive_post_root_roundtrip_keeps_nf_work_in_lockstep() {
        let mk = |i: u64, tag: u8| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            b[16] = tag;
            b
        };
        let mut imt = FullNullifierImt::new();
        // Seed a non-trivial pre-state (many prior blocks' worth of nullifiers).
        for i in 1..=500u64 {
            imt.insert_and_witness(&mk(i, 0x11)).expect("seed insert");
        }
        let root_before = crate::spend_frontier::leaf_to_cm_bytes(imt.root());
        let count_before = imt.count();

        // A block's padded set (values that interleave with the pre-state so low-leaves are interior, not just tip).
        let padded: Vec<[u8; 32]> = (1..=256u64).map(|i| mk(i, 0x77)).collect();

        // (1) Speculative derive must roll back to a BYTE-IDENTICAL tree.
        let derived = imt.derive_post_root(&padded).expect("derive post");
        assert_eq!(
            crate::spend_frontier::leaf_to_cm_bytes(imt.root()),
            root_before,
            "derive_post_root must leave the root unchanged (rollback byte-identical)"
        );
        assert_eq!(
            imt.count(),
            count_before,
            "derive_post_root must leave the count unchanged"
        );

        // (2) The REAL re-insert of the SAME set (what graft/nf_stream_apply does) must reproduce derive's root.
        for nf in &padded {
            imt.insert_and_witness(nf).expect("real insert");
        }
        assert_eq!(
            crate::spend_frontier::leaf_to_cm_bytes(imt.root()),
            derived,
            "re-insert after a speculative derive MUST reproduce the derived post-root — else nf_work drifts \
             from the acc and the producer rebuilds the whole tree from DA every block (the CPU wedge)"
        );
    }

    /// A test-only FULL indexed Merkle tree that stores every leaf so it can GENERATE the witnesses the O(1)
    /// `NullifierTree` verifies. This is the DA/prover side; the node never holds this. Its `root()` MUST always
    /// equal the O(1) tree's `root`, which each test asserts (cross-check that the O(1) transition is exact).
    struct RefImt {
        leaves: Vec<([u8; 32], [u8; 32])>, // (value, next) per position
    }

    impl RefImt {
        fn new() -> Self {
            Self {
                leaves: vec![([0u8; 32], [0u8; 32])], // position 0 = the initial (0,0) low leaf
            }
        }

        fn leaf_hash(&self, pos: usize) -> Digest4 {
            if pos < self.leaves.len() {
                let (v, n) = &self.leaves[pos];
                hash_leaf(v, n)
            } else {
                empty_leaf()
            }
        }

        /// Hash of the subtree of height `level` whose leftmost leaf is `start` (sparse: empty tail folds to the
        /// empty ladder).
        fn subtree(&self, level: usize, start: usize) -> Digest4 {
            if level == 0 {
                return self.leaf_hash(start);
            }
            if start >= self.leaves.len() {
                return empty_subtree(level);
            }
            let half = 1usize << (level - 1);
            poseidon_pair(
                self.subtree(level - 1, start),
                self.subtree(level - 1, start + half),
            )
        }

        fn root(&self) -> Digest4 {
            self.subtree(NULLIFIER_TREE_DEPTH, 0)
        }

        fn copath(&self, index: u64) -> Vec<Digest4> {
            let mut path = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
            for level in 0..NULLIFIER_TREE_DEPTH {
                let sib_start = (((index >> level) ^ 1) << level) as usize;
                path.push(self.subtree(level, sib_start));
            }
            path
        }

        /// Find the low leaf that brackets `x`: `value < x < next` (next==0 is +∞).
        fn find_low(&self, x: &[u8; 32]) -> u64 {
            for (i, (v, n)) in self.leaves.iter().enumerate() {
                if nf_key_lt(v, x) && less_than_next(x, n) {
                    return i as u64;
                }
            }
            panic!("no low leaf for x — already present or malformed");
        }

        /// Build the witness for inserting `x`, then MUTATE the reference tree to reflect the insertion (so
        /// subsequent inserts see the new linked list). Returns the witness the O(1) tree will verify.
        fn insert_witness(&mut self, x: &[u8; 32]) -> InsertWitness {
            let li = self.find_low(x);
            let (lv, ln) = self.leaves[li as usize];
            let low_copath = self.copath(li);
            // Apply the low-leaf update in a CLONE to compute the append slot's copath under the mid-root.
            let mut mid = RefImt {
                leaves: self.leaves.clone(),
            };
            mid.leaves[li as usize].1 = *x; // low.next = x
            let append_index = self.leaves.len() as u64;
            let new_copath = mid.copath(append_index);
            // Commit the real mutation: low.next = x, append (x, old low.next).
            self.leaves[li as usize].1 = *x;
            self.leaves.push((*x, ln));
            InsertWitness {
                low_value: lv,
                low_next: ln,
                low_index: li,
                low_copath,
                new_copath,
            }
        }
    }

    fn nf(byte: u8, tail: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = byte;
        x[31] = tail;
        x
    }

    #[test]
    fn honest_inserts_advance_root_and_ref_matches() {
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        assert_eq!(tree.root(), refi.root(), "fresh roots must agree");

        // Insert several nullifiers in mixed order; each must verify + move the root + match the reference.
        for (b, t) in [(5u8, 1u8), (2, 9), (9, 3), (1, 7), (7, 0)] {
            let x = nf(b, t);
            let mut r2 = RefImt {
                leaves: refi.leaves.clone(),
            };
            let w = r2.insert_witness(&x);
            let before = tree.root();
            tree.verify_and_insert(&x, &w)
                .expect("honest insert verifies");
            assert_ne!(before, tree.root(), "an honest insert must move the root");
            // Keep the shared reference in lockstep and cross-check the O(1) transition is exact.
            refi.insert_witness(&x);
            assert_eq!(
                tree.root(),
                refi.root(),
                "O(1) root must equal the full-tree root after insert"
            );
            assert_eq!(tree.count(), refi.leaves.len() as u64, "counts must agree");
        }
    }

    #[test]
    fn double_spend_is_rejected_fail_closed() {
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        let x = nf(4, 2);
        let w = refi.insert_witness(&x);
        tree.verify_and_insert(&x, &w).expect("first spend ok");
        let root_after = tree.root();

        // Re-mint a witness for the SAME nf against the now-updated reference tree: find_low must fail because the
        // bracketing gap is closed (no leaf has value < x < next around x anymore).
        let dup =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| refi.insert_witness(&x)));
        assert!(
            dup.is_err(),
            "reference cannot even build a low-leaf witness for a spent nullifier"
        );

        // And a REPLAY of the original witness (stale root/neighbourhood) must be rejected by the O(1) tree —
        // fail-closed on the bad spend (the stale low-leaf copath no longer folds to the updated root).
        assert!(
            tree.verify_and_insert(&x, &w).is_err(),
            "replaying a spent nullifier's witness must be rejected (double-spend)"
        );
        assert_eq!(
            tree.root(),
            root_after,
            "a rejected double-spend must NOT change state"
        );
        assert_eq!(
            tree.count(),
            2,
            "a rejected double-spend must NOT advance count"
        );
    }

    #[test]
    fn forged_membership_copath_is_rejected() {
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        let x = nf(6, 6);
        let mut w = refi.insert_witness(&x);
        // Tamper: flip a byte in the low-leaf copath → membership no longer folds to root.
        w.low_copath[3][0] ^= 1;
        assert_eq!(
            tree.verify_and_insert(&x, &w),
            Err(NullifierError::BadLowMembership),
            "a forged membership copath must be rejected"
        );
    }

    #[test]
    fn forged_range_is_rejected() {
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        // Establish two leaves so there is an interior gap to lie about.
        let a = nf(3, 0);
        let wa = refi.insert_witness(&a);
        tree.verify_and_insert(&a, &wa).unwrap();

        // Try to insert a value with a low-leaf claim whose range does NOT bracket it (claim the (0,·) low leaf
        // for a value that actually sits above `a`).
        let y = nf(8, 0);
        let mut bad = RefImt {
            leaves: refi.leaves.clone(),
        };
        let mut w = bad.insert_witness(&y); // correct low leaf = the (3,0) leaf
                                            // Corrupt the witness to claim leaf 0 (value 0, next a) — range 0 < y < a is FALSE since y=8 > a=3.
        w.low_value = [0u8; 32];
        w.low_next = a;
        w.low_index = 0;
        w.low_copath = refi.copath(0);
        assert_eq!(
            tree.verify_and_insert(&y, &w),
            Err(NullifierError::NotBracketed),
            "a low-leaf claim that does not bracket the nullifier must be rejected"
        );
    }

    #[test]
    fn zero_nullifier_is_rejected() {
        let mut tree = NullifierTree::new();
        let refi = RefImt::new();
        let w = InsertWitness {
            low_value: [0u8; 32],
            low_next: [0u8; 32],
            low_index: 0,
            low_copath: refi.copath(0),
            new_copath: refi.copath(1),
        };
        assert_eq!(
            tree.verify_and_insert(&[0u8; 32], &w),
            Err(NullifierError::ZeroNullifier),
            "the reserved zero nullifier must be rejected"
        );
    }

    #[test]
    fn verify_unspent_is_read_only_and_catches_double_spend() {
        // TRUSTLESS read-only gate (mempool admit): self-verifies against the O(1) root, no stored set.
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        let x = nf(5, 0);
        let w = {
            let mut r = RefImt {
                leaves: refi.leaves.clone(),
            };
            r.insert_witness(&x)
        };
        // Before the insert a valid witness proves nf UNSPENT — and the check does NOT mutate.
        let root0 = tree.root();
        assert!(
            tree.verify_unspent(&x, &w),
            "a valid witness proves nf unspent"
        );
        assert_eq!(
            tree.root(),
            root0,
            "verify_unspent must be read-only (no mutation)"
        );
        assert_eq!(tree.count(), 1, "verify_unspent must not advance count");
        // Insert for real; the SAME (now-stale) witness must NO LONGER prove unspent → double-spend caught
        // read-only, self-verifying against the advanced root, with zero stored nullifier set.
        tree.verify_and_insert(&x, &w).expect("first spend ok");
        refi.insert_witness(&x);
        assert!(
            !tree.verify_unspent(&x, &w),
            "after the insert the stale witness must NOT prove unspent (double-spend rejected read-only)"
        );
        // The zero sentinel is never provably-unspent.
        assert!(
            !tree.verify_unspent(&[0u8; 32], &w),
            "the reserved zero nullifier is rejected"
        );
    }

    #[test]
    fn insert_witness_serializes_roundtrip() {
        // The witness must ride on the wire (a spend carries it) — verify postcard round-trips it byte-exact.
        let mut refi = RefImt::new();
        let w = refi.insert_witness(&nf(9, 1));
        let bytes = postcard::to_stdvec(&w).expect("witness serializes");
        let w2: InsertWitness = postcard::from_bytes(&bytes).expect("witness deserializes");
        let mut t1 = NullifierTree::new();
        let mut t2 = NullifierTree::new();
        t1.verify_and_insert(&nf(9, 1), &w)
            .expect("orig witness verifies");
        t2.verify_and_insert(&nf(9, 1), &w2)
            .expect("roundtripped witness verifies identically");
        assert_eq!(
            t1.root(),
            t2.root(),
            "a roundtripped witness advances the root identically"
        );
    }

    #[test]
    fn state_is_true_constant_size_regardless_of_count() {
        // The nullifier accumulator's serialized state is byte-identical at 1 vs many spends (root+count only).
        let mut tree = NullifierTree::new();
        let mut refi = RefImt::new();
        let empty_len = postcard::to_stdvec(&tree).unwrap().len();
        // Strictly-increasing nullifiers always bracket against the current max leaf (next == +∞), so every insert
        // succeeds and `count` climbs — proving the size is invariant to the count VALUE, not just to zero spends.
        for i in 1u8..40 {
            let x = nf(i, 0);
            let w = refi.insert_witness(&x);
            tree.verify_and_insert(&x, &w)
                .expect("increasing nullifier always brackets");
        }
        assert_eq!(tree.count(), 40, "39 inserts + the initial leaf");
        let full_len = postcard::to_stdvec(&tree).unwrap().len();
        assert_eq!(
            empty_len, full_len,
            "nullifier accumulator state must be byte-constant regardless of spends"
        );
        assert!(
            full_len <= 44,
            "state is a small fixed body (40 bytes + short length prefix), got {full_len}"
        );
    }
}

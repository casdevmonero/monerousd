// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-12 / DSOL door landing 1 — THE CONTRACT-STATE ROOT (docs/DSOL-NODE-DOOR-SPEC.md §2, §12).
//!
//! ONE sparse Merkle map `cid → P(leaf(code_id), storage_root)` of depth 256 over the contract id's bits, Poseidon2 at every
//! node, the empty leaf the zero digest and every empty subtree's root memoised once. The NODE holds the 32-byte root alone
//! (`PegLedger::contract_state_root`): a deploy carries the non-membership path of its `cid`, a call carries the path of the
//! leaf it moves, and the node verifies the path against its root and recomputes the new root from the same siblings. There
//! is no per-contract map anywhere on the node — contract state is a no-growth axis by construction (AGENTS.md §2).
//!
//! ROOT-LAYER: the root is PRODUCED here, by the one fold that applies a deploy or a call from the path the object carries;
//!   every reader (the next deploy's path check, a call's `storage_pre` check, the bundle word a joiner adopts) reads this one
//!   function of the chain, never a per-node map. MEASURED: the unit pin below — the node's recomputed root equals the full
//!   prover-side tree's root after 5 inserts and 1 update, and each tamper (a sibling, the key, the old leaf, an insert at an
//!   occupied key, a short path, a mask/count mismatch) is refused. MUST-STAY-GREEN: nothing reads this module before the
//!   deploy door lands; the replica and restart censuses compare `PegLedger` whole, so the new word is in them by construction.
//!
//! BORROWED: the account trie keyed by identity → `H(code, storage_root)` (Ethereum's state trie; Aztec's note/nullifier
//! sparse trees), carried as compact proofs — a 256-bit mask of the siblings that are NOT an empty subtree's root plus those
//! siblings, so a tree of k contracts costs about log₂ k siblings per path (Ethereum's compact SMT proof encoding).
//!
//! WHO HOLDS THE LEAVES (corrected 2026-11-11, lane goods; this header used to say "never a node field"). CONSENSUS state
//! is the one root, and nothing below changes that: no fold reads a leaf from a map. But a path can only be produced by
//! someone who holds the leaves, and since IonSwap's pools a NODE keeps a copy of them too: its own pools cache
//! (`node::objects::ion_pool::IonCache`: one leaf a contract, one row a pool), checked against the root at every use,
//! resumed from the node's own checkpoint and refilled from peers leaf by leaf with proof. That copy grows with the
//! number of CONTRACTS AND POOLS (each paid for at its creation), never with height, blocks, notes or orders: the same
//! standing as the directory's records. Which nodes hold it is a holding policy (today every node; a sliced policy
//! changes who answers a refill, never what an asker accepts).
//!
//! O1-FOOTPRINT-REVIEWED: the chain's share is one digest. [`ContractStateTree`] (the full map) is a HOLDER's side — a
//! publishing wallet, a node's pools cache, a test — and never consensus state.
//! DIGITAL-CASH-PRIVACY-REVIEWED: a `cid` and a `code_id` are public by the door's own spec (§5, "which contract"); a storage
//! root is a digest; nothing here is a value, a key or an owner.

use crate::spend_frontier::{cm_bytes_to_leaf, poseidon_pair, Digest4};
use usdm_decider::poseidon2_compress::zero_digest;

/// The tree's depth: every bit of the 32-byte contract id, most significant bit of byte 0 first.
pub const DEPTH: usize = 256;

/// The leaf of a key no contract occupies.
#[must_use]
pub fn empty_leaf() -> Digest4 {
    zero_digest()
}

/// `empty_roots()[h]` is the root of an empty perfect subtree of height `h` (height 0 = the empty leaf).
fn empty_roots() -> &'static [Digest4] {
    static T: std::sync::OnceLock<Vec<Digest4>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut v = Vec::with_capacity(DEPTH + 1);
        let mut cur = empty_leaf();
        v.push(cur);
        for _ in 0..DEPTH {
            cur = poseidon_pair(cur, cur);
            v.push(cur);
        }
        v
    })
}

/// The root of the tree with no contract in it — what a chain starts with.
#[must_use]
pub fn empty_root() -> Digest4 {
    empty_roots()[DEPTH]
}

/// The leaf a deployed contract occupies: `P(P(leaf(code_id), manifest), storage_root)` — its code identity and its
/// publisher-fee MANIFEST digest (§BR-12 L2: what every call's fee is measured against, so the node needs no per-contract
/// store to enforce the deployed fee) beside its storage root.
#[must_use]
pub fn contract_leaf(code_id: &[u8; 32], manifest: Digest4, storage_root: Digest4) -> Digest4 {
    poseidon_pair(poseidon_pair(cm_bytes_to_leaf(code_id), manifest), storage_root)
}

/// Bit `depth` of the key (0 = the root's first branching), MSB of byte 0 first.
#[inline]
fn key_bit(key: &[u8; 32], depth: usize) -> bool {
    (key[depth / 8] >> (7 - (depth % 8))) & 1 == 1
}

/// Fold `leaf` up the path of `key` with `siblings[j]` the sibling at height `j` (0 = the leaf's own level).
/// `None` unless exactly [`DEPTH`] siblings are given.
#[must_use]
pub fn root_with(key: &[u8; 32], leaf: Digest4, siblings: &[Digest4]) -> Option<Digest4> {
    if siblings.len() != DEPTH {
        return None;
    }
    let mut node = leaf;
    for (j, sib) in siblings.iter().enumerate() {
        let depth = DEPTH - 1 - j;
        node = if key_bit(key, depth) { poseidon_pair(*sib, node) } else { poseidon_pair(node, *sib) };
    }
    Some(node)
}

/// Does `leaf` sit at `key` under `root`, by these siblings?
#[must_use]
pub fn verify_path(root: Digest4, key: &[u8; 32], leaf: Digest4, siblings: &[Digest4]) -> bool {
    root_with(key, leaf, siblings) == Some(root)
}

/// A DEPLOY: prove `key` EMPTY under `root`, then the root with `new_leaf` there. `None` when the key is occupied, the path
/// does not open `root` (the root moved since the path was built — refused on the item, the deployer re-proves) or the
/// path is malformed.
#[must_use]
pub fn insert_root(root: Digest4, key: &[u8; 32], new_leaf: Digest4, siblings: &[Digest4]) -> Option<Digest4> {
    if !verify_path(root, key, empty_leaf(), siblings) {
        return None;
    }
    root_with(key, new_leaf, siblings)
}

/// A CALL: prove `old_leaf` at `key` under `root`, then the root with `new_leaf` there (the same two-step as an insert; a
/// call that names a storage root the chain no longer holds opens nothing).
#[must_use]
pub fn update_root(root: Digest4, key: &[u8; 32], old_leaf: Digest4, new_leaf: Digest4, siblings: &[Digest4]) -> Option<Digest4> {
    if !verify_path(root, key, old_leaf, siblings) {
        return None;
    }
    root_with(key, new_leaf, siblings)
}

/// ⭐ THE PATH OF `key` AFTER ANOTHER KEY'S LEAF CHANGED (IonSwap pools, 2026-11-11: several pools settle in one fold
/// step). `siblings` opens `key` under some root R; `other_siblings` opens `other` under the SAME root R; `other`'s leaf
/// has since been set to `other_leaf`. Exactly one sibling of `key`'s path is different under the new root: the one at
/// the depth where the two keys part, which is the root of the subtree on `other`'s side there, and that is `other`'s
/// new leaf folded up its own path to that depth. `true` when the sibling was replaced; `false`, with nothing changed,
/// for the same key or a path that is not [`DEPTH`] siblings.
/// Nothing is trusted from it: the caller verifies the rebased path against the root the ledger holds.
/// cons: at most `DEPTH - 1` hashes a call; no state.
pub fn rebase_path(key: &[u8; 32], siblings: &mut [Digest4], other: &[u8; 32], other_leaf: Digest4, other_siblings: &[Digest4]) -> bool {
    if siblings.len() != DEPTH || other_siblings.len() != DEPTH {
        return false;
    }
    let Some(parts_at) = (0..DEPTH).find(|d| key_bit(key, *d) != key_bit(other, *d)) else {
        return false; // the same key: its own leaf changed, and no path of it survives that
    };
    // `other`'s subtree root at depth `parts_at + 1`: its leaf folded up through the heights below that depth
    let mut node = other_leaf;
    for (j, sib) in other_siblings.iter().enumerate().take(DEPTH - 1 - parts_at) {
        let depth = DEPTH - 1 - j;
        node = if key_bit(other, depth) { poseidon_pair(*sib, node) } else { poseidon_pair(node, *sib) };
    }
    siblings[DEPTH - 1 - parts_at] = node;
    true
}

/// A path on the wire: bit `j` of `mask` (byte `j / 8`, MSB first) set ⇔ `siblings[j]` is NOT the empty subtree root of height
/// `j` and is carried in `sibs`, in height order. Everything not carried is the empty root of its height.
/// O1-FOOTPRINT-REVIEWED: at most [`DEPTH`] siblings, one object's worth; nothing is retained.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathWire {
    pub mask: [u8; 32],
    pub sibs: Vec<[u8; 32]>,
}

impl PathWire {
    /// Compact the full sibling list: every empty-subtree root is dropped and named by the mask. `None` for a list that is
    /// not exactly [`DEPTH`] long (a path from no tree).
    #[must_use]
    pub fn compact(siblings: &[Digest4]) -> Option<Self> {
        if siblings.len() != DEPTH {
            return None;
        }
        let empties = empty_roots();
        // a BITMAP of the 256 sibling heights that are carried (one bit per height, set below as each non-default sibling is
        // met) — a presence map, not a key, seed or identity; it is fully determined by the siblings
        let mut carried_heights = PathWire::default().mask;
        let mut sibs = Vec::new();
        for (j, s) in siblings.iter().enumerate() {
            if *s != empties[j] {
                carried_heights[j / 8] |= 1 << (7 - (j % 8));
                sibs.push(crate::spend_frontier::leaf_to_cm_bytes(*s));
            }
        }
        Some(PathWire { mask: carried_heights, sibs })
    }

    /// The full sibling list, or `None` when the carried count does not match the mask or a sibling is not a canonical
    /// digest (bytes that came from no prover are refused, never padded).
    #[must_use]
    pub fn expand(&self) -> Option<Vec<Digest4>> {
        let empties = empty_roots();
        let mut out = Vec::with_capacity(DEPTH);
        let mut carried = self.sibs.iter();
        for (j, empty) in empties.iter().enumerate().take(DEPTH) {
            let set = (self.mask[j / 8] >> (7 - (j % 8))) & 1 == 1;
            if set {
                out.push(crate::spend_frontier::cm_bytes_to_root(carried.next()?)?);
            } else {
                out.push(*empty);
            }
        }
        if carried.next().is_some() {
            return None; // more siblings than the mask names
        }
        Some(out)
    }
}

/// The PROVER's full map (a wallet rebuilding the tree from the chain's deploy objects; a test): every occupied key's leaf.
/// ⭐ §BR-12 F13 — ONE CONTRACT-STATE TRANSITION the fold applied: the root before it, the leaf written under `cid`, and
/// the root after. A follower (a publishing wallet, an app holding its contract's state) applies an entry only when `pre`
/// is the root ITS tree holds, so the entries form a chain of state transitions it walks from wherever it stands
/// (Ethereum: state is a function of the chain; a client replays transitions from the state it has). A fold rewind
/// needs no hook: the abandoned branch's entries match no follower's root. `blue` is the fold height the node filed it
/// at — a paging hint for `/contract_leaves_from`, never the thing a follower trusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractLeafUpdate {
    pub blue: u64,
    pub pre: Digest4,
    pub cid: [u8; 32],
    pub leaf: Digest4,
    pub post: Digest4,
}

/// The node keeps the last this-many transitions — a CONSTANT ring (4096 × 136 B ≈ 557 KB), never a per-contract store;
/// the node's state stays the one root. A follower further behind than the ring takes the tree from any holder and
/// verifies it against the root (Mina's archive shape: anyone may hold history; the chain holds the root).
pub const CONTRACT_LEAF_RING: usize = 4096;

/// Its root and paths are what the node's [`verify_path`] / [`insert_root`] judge. Never chain state: the chain holds the
/// root, and whoever keeps this (a publishing wallet, a node's own pools cache) checks it against that root.
///
/// ⭐ SAFE AT SCALE (2026-11-11, lane goods) — THE HOLDER KEEPS THE ROOT OF EVERY SUBTREE THAT HOLDS TWO OR MORE LEAVES
/// (`inner`), so a root read is one lookup, and a write or a path read re-hashes one path (256 hashes) plus one lone
/// leaf's chain for each level of shared prefix it crosses (about log₂ k levels for k hashed keys): a few thousand hashes
/// whatever the tree holds. MEASURED BEFORE: `root()` and `siblings()` re-hashed EVERY leaf's whole path on every call
/// (about 256 hashes a leaf, a quarter of a million a call at a thousand leaves), and a node that keeps the tree reads
/// both on every tick and once for every settlement it forms, so the cost of one pool's batch grew with every other pool.
/// (a) nodes that bond: no term. (b) leaves held: memory 32 + 32 B a leaf and one 66 B entry for every subtree that
/// holds two or more leaves, which is one for each level a leaf shares with another key: about log₂ k a leaf for
/// hashed keys (0.66 KB a leaf at a thousand leaves, 1.3 KB at a million), up to 255 for two keys that differ in their
/// last bit alone (contract ids are hashes: a pair that shares n leading bits costs its maker about 2ⁿ hashes and buys n
/// entries of this holder's memory). MEASURED 2026-11-11: 2,929 entries for 300 leaves that include ten pairs differing
/// in their last bit alone and two families sharing 9 and 70 leading bits; the first text here said "about one a leaf"
/// and was wrong. Keeping
/// only the branching points (exactly k − 1 entries) is the smaller store and is not built. Time per operation about
/// 256 + 250·log₂ k hashes. (c) height: no term.
/// AI RESISTANT: (b) ordinary code. Nothing here is believed: a path it yields is judged by `verify_path` against the
/// chain's root at the fold, so a wrong node in `inner` makes this holder's own objects refused and moves nobody's value.
/// BORROWED: the stored-internal-node sparse Merkle tree (Diem's Jellyfish Merkle tree; Ethereum's trie node store).
/// O1-FOOTPRINT-REVIEWED: O(contracts) on the holder's side only; the chain's share is the one root.
#[derive(Clone, Debug, Default)]
pub struct ContractStateTree {
    leaves: std::collections::BTreeMap<[u8; 32], Digest4>,
    /// `(depth, the depth's key prefix with every lower bit clear)` → that subtree's root, for every subtree that holds two
    /// or more leaves. A function of `leaves` alone: [`Self::refresh`] after every write, [`Self::from_entries`] in bulk.
    inner: std::collections::HashMap<(u16, [u8; 32]), Digest4>,
}

/// `key` with every bit from `depth` on cleared: the first key of the depth-`depth` subtree it lies in.
fn prefix_of(key: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut p = [0u8; 32];
    let full = depth / 8;
    p[..full].copy_from_slice(&key[..full]);
    if depth % 8 != 0 {
        p[full] = key[full] & (0xFFu8 << (8 - depth % 8));
    }
    p
}

/// The last key of the subtree `prefix` names at `depth`.
fn last_of(prefix: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut p = [0xFFu8; 32];
    let full = depth / 8;
    p[..full].copy_from_slice(&prefix[..full]);
    if depth % 8 != 0 {
        p[full] = prefix[full] | (0xFFu8 >> (depth % 8));
    }
    p
}

/// The root, at `depth`, of the subtree that holds the one leaf `leaf` at `key` and nothing else.
fn lone_root(depth: usize, key: &[u8; 32], leaf: Digest4) -> Digest4 {
    let empties = empty_roots();
    let mut h = leaf;
    for d in (depth..DEPTH).rev() {
        let empty = empties[DEPTH - (d + 1)];
        h = if key_bit(key, d) { poseidon_pair(empty, h) } else { poseidon_pair(h, empty) };
    }
    h
}

impl ContractStateTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: [u8; 32], leaf: Digest4) {
        self.leaves.insert(key, leaf);
        self.refresh(&key);
    }

    #[must_use]
    pub fn get(&self, key: &[u8; 32]) -> Option<Digest4> {
        self.leaves.get(key).copied()
    }

    /// Take a leaf back out (a holder un-folding a step that inserted it).
    pub fn remove(&mut self, key: &[u8; 32]) {
        if self.leaves.remove(key).is_some() {
            self.refresh(key);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The root of the subtree at `depth` over the sorted keys in `keys` (all of which lie in that subtree), re-hashed from
    /// the leaves alone: what the stored nodes must equal (the unit pin compares them after every write).
    fn subtree_root(&self, depth: usize, keys: &[&[u8; 32]]) -> Digest4 {
        if keys.is_empty() {
            return empty_roots()[DEPTH - depth];
        }
        if depth == DEPTH {
            return self.leaves[keys[0]];
        }
        // the keys are sorted, so the left half (bit = 0) is a prefix of the slice
        let split = keys.partition_point(|k| !key_bit(k, depth));
        let (l, r) = keys.split_at(split);
        poseidon_pair(self.subtree_root(depth + 1, l), self.subtree_root(depth + 1, r))
    }

    /// The whole tree's root re-hashed from the leaves alone (every leaf's whole path): the oracle for [`Self::root`].
    #[must_use]
    pub fn root_recomputed(&self) -> Digest4 {
        let keys: Vec<&[u8; 32]> = self.leaves.keys().collect();
        self.subtree_root(0, &keys)
    }

    /// The root of the subtree `prefix` names at `depth`, from the stored nodes: empty, one leaf's chain, or a stored node.
    fn node_root(&self, depth: usize, prefix: &[u8; 32]) -> Digest4 {
        let mut held = self.leaves.range(*prefix..=last_of(prefix, depth));
        match (held.next(), held.next()) {
            (None, _) => empty_roots()[DEPTH - depth],
            (Some((k, leaf)), None) => lone_root(depth, k, *leaf),
            (Some(_), Some(_)) => match self.inner.get(&(depth as u16, *prefix)) {
                Some(h) => *h,
                // every subtree of two or more leaves has its node (`refresh`, `from_entries`); were one ever missing,
                // re-hash it from the leaves rather than hand out a root that is not the leaves'
                None => {
                    let keys: Vec<&[u8; 32]> = self.leaves.range(*prefix..=last_of(prefix, depth)).map(|(k, _)| k).collect();
                    self.subtree_root(depth, &keys)
                }
            },
        }
    }

    /// Re-hash the stored nodes on `key`'s path after its leaf changed, deepest first (a node's children are final
    /// before it is hashed). A subtree left with fewer than two leaves keeps no node.
    fn refresh(&mut self, key: &[u8; 32]) {
        for depth in (0..DEPTH).rev() {
            let p = prefix_of(key, depth);
            if self.leaves.range(p..=last_of(&p, depth)).nth(1).is_some() {
                let mut right = p;
                right[depth / 8] |= 0x80u8 >> (depth % 8);
                let h = poseidon_pair(self.node_root(depth + 1, &p), self.node_root(depth + 1, &right));
                self.inner.insert((depth as u16, p), h);
            } else {
                self.inner.remove(&(depth as u16, p));
            }
        }
    }

    /// One pass over the sorted `keys` (all in the subtree at `depth`): its root, storing every node of two or more leaves.
    fn build(
        leaves: &std::collections::BTreeMap<[u8; 32], Digest4>,
        depth: usize,
        keys: &[[u8; 32]],
        inner: &mut std::collections::HashMap<(u16, [u8; 32]), Digest4>,
    ) -> Digest4 {
        match keys {
            [] => empty_roots()[DEPTH - depth],
            [k] => lone_root(depth, k, leaves[k]),
            _ => {
                let split = keys.partition_point(|k| !key_bit(k, depth));
                let (l, r) = keys.split_at(split);
                let h = poseidon_pair(Self::build(leaves, depth + 1, l, inner), Self::build(leaves, depth + 1, r, inner));
                inner.insert((depth as u16, prefix_of(&keys[0], depth)), h);
                h
            }
        }
    }

    #[must_use]
    pub fn root(&self) -> Digest4 {
        self.node_root(0, &[0u8; 32])
    }

    /// The full sibling list of `key` (height order, leaf level first), for the tree as it stands — a membership path when the
    /// key is occupied, a non-membership path (against the empty leaf) when it is not. Always exactly [`DEPTH`] long.
    #[must_use]
    pub fn siblings(&self, key: &[u8; 32]) -> Vec<Digest4> {
        let mut sibs = Vec::with_capacity(DEPTH);
        for depth in 0..DEPTH {
            // the other child of the node at `depth` on the key's path: the key's own prefix with bit `depth` flipped
            let mut other = prefix_of(key, depth + 1);
            other[depth / 8] ^= 0x80u8 >> (depth % 8);
            sibs.push(self.node_root(depth + 1, &other));
        }
        sibs.reverse(); // read root-down, carried leaf-up
        sibs
    }

    /// [`Self::siblings`] on the wire. A full tree's sibling list is always [`DEPTH`] long, so the compaction cannot fail; a
    /// failure here is a defect in this module and stops the prover loudly rather than sending an empty path.
    #[must_use]
    /// Every leaf this replica holds, in key order — what a holder hands another follower (verified against the root).
    #[must_use]
    pub fn entries(&self) -> Vec<([u8; 32], Digest4)> {
        self.leaves.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// The next `n` leaves after `after` in key order (the zero key: from the first leaf) — one page of what a holder
    /// hands a follower.
    #[must_use]
    pub fn entries_after(&self, after: &[u8; 32], n: usize) -> Vec<([u8; 32], Digest4)> {
        use std::ops::Bound::{Excluded, Unbounded};
        let from = if *after == [0u8; 32] { Unbounded } else { Excluded(*after) };
        self.leaves.range((from, Unbounded)).take(n).map(|(k, v)| (*k, *v)).collect()
    }

    /// A replica from the leaves a holder served; the caller compares [`Self::root`] with the chain's root before trusting it.
    #[must_use]
    pub fn from_entries(entries: &[([u8; 32], Digest4)]) -> Self {
        let leaves: std::collections::BTreeMap<[u8; 32], Digest4> = entries.iter().copied().collect();
        let keys: Vec<[u8; 32]> = leaves.keys().copied().collect();
        let mut inner = std::collections::HashMap::new();
        let _ = Self::build(&leaves, 0, &keys, &mut inner);
        Self { leaves, inner }
    }

    /// ⭐ §BR-12 F13 — FOLLOW THE CHAIN'S TRANSITIONS: apply, in order, every update whose `pre` is this replica's root,
    /// skipping the rest (an abandoned fold branch, or steps this replica already holds). Returns how many applied. After a
    /// run the caller compares the root with the node's: equal = current; not equal = behind the ring (take a replica).
    pub fn follow(&mut self, updates: &[ContractLeafUpdate]) -> usize {
        let mut applied = 0;
        for u in updates {
            if self.root() != u.pre {
                continue;
            }
            self.insert(u.cid, u.leaf);
            debug_assert_eq!(self.root(), u.post, "a transition whose post root is not the leaf's: the node served a bad entry");
            applied += 1;
        }
        applied
    }

    pub fn path(&self, key: &[u8; 32]) -> PathWire {
        PathWire::compact(&self.siblings(key)).expect("ContractStateTree::siblings yields exactly DEPTH siblings")
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use usdm_decider::poseidon2_compress::lanes_of;

    fn key(tag: u8) -> [u8; 32] {
        let mut k = [tag; 32];
        k[0] = tag.wrapping_mul(37);
        k[31] = tag ^ 0xA5;
        k
    }

    /// ⭐ RED→GREEN PIN (§BR-12 L1) — THE NODE'S ROOT IS THE PROVER'S TREE, AND A PATH IS WHAT MOVES IT. A deploy inserts
    /// against the empty leaf and the recomputed root equals the full tree's; a call updates and the two agree again; every
    /// occupied key's path verifies; an unoccupied key's non-membership path verifies against the empty leaf. TAMPERS, each
    /// refused: one sibling changed, the wrong key, the wrong old leaf, an insert at an occupied key, a path of the wrong
    /// length. The compact wire form round-trips and refuses a sibling count that disagrees with its mask. CALIBRATION: the
    /// empty tree's root is [`empty_root`], and two different leaf sets have different roots.
    #[test]
    fn contract_state_insert_update_and_paths_agree_with_the_full_tree_and_tampers_are_refused() {
        let mut tree = ContractStateTree::new();
        assert_eq!(tree.root(), empty_root(), "CALIBRATION: the empty tree's root is the empty root");
        let mut root = empty_root();
        let code = [0xC0u8; 32];
        let man = lanes_of(&[0x3a, 0x11]);
        for tag in 1..=5u8 {
            let k = key(tag);
            let leaf = contract_leaf(&code, man, lanes_of(&[u64::from(tag), 0x51]));
            // the node's side: the deployer's non-membership path against the CURRENT root
            let sibs = tree.siblings(&k);
            assert!(verify_path(root, &k, empty_leaf(), &sibs), "an unoccupied key opens the root with the empty leaf");
            let new_root = insert_root(root, &k, leaf, &sibs).expect("⛔ the deploy's insert was refused");
            tree.insert(k, leaf);
            assert_eq!(new_root, tree.root(), "⛔ the node's recomputed root is not the full tree's after insert {tag}");
            assert_ne!(new_root, root, "CALIBRATION: an insert moves the root");
            root = new_root;
        }
        // every occupied key's membership path verifies; the wrong key with the right leaf does not
        for tag in 1..=5u8 {
            let k = key(tag);
            let sibs = tree.siblings(&k);
            assert!(verify_path(root, &k, tree.get(&k).unwrap(), &sibs));
            assert!(!verify_path(root, &key(tag + 10), tree.get(&k).unwrap(), &sibs), "the wrong key is refused");
            assert!(insert_root(root, &k, empty_leaf(), &sibs).is_none(), "⛔ an insert at an OCCUPIED key was admitted");
        }
        // a call moves one leaf
        let k = key(3);
        let old = tree.get(&k).unwrap();
        let new = contract_leaf(&code, man, lanes_of(&[3, 0x52]));
        let sibs = tree.siblings(&k);
        assert!(update_root(root, &k, new, new, &sibs).is_none(), "⛔ an update naming the wrong old leaf was admitted");
        let moved = update_root(root, &k, old, new, &sibs).expect("the call's update");
        tree.insert(k, new);
        assert_eq!(moved, tree.root(), "⛔ the node's root after the update is not the full tree's");
        root = moved;
        // TAMPER: one sibling changed; a short path
        let mut bad = tree.siblings(&k);
        bad[17][0] ^= 1;
        assert!(!verify_path(root, &k, new, &bad), "⛔ a tampered sibling verified");
        assert!(root_with(&k, new, &bad[..DEPTH - 1]).is_none(), "a short path is refused, never padded");
        // the wire form
        let wire = tree.path(&k);
        assert!(wire.sibs.len() <= 8, "a tree of 5 contracts carries a handful of siblings, not 256: {}", wire.sibs.len());
        assert_eq!(wire.expand().as_deref(), Some(tree.siblings(&k).as_slice()), "the compact path expands to the full one");
        let mut short = wire.clone();
        short.sibs.pop();
        assert_eq!(short.expand(), None, "fewer siblings than the mask names is refused");
        let mut long = wire.clone();
        long.sibs.push([0x11; 32]);
        assert_eq!(long.expand(), None, "more siblings than the mask names is refused");
        // a tree of other leaves has another root
        let mut other = ContractStateTree::new();
        other.insert(key(1), contract_leaf(&code, man, lanes_of(&[1, 0x51])));
        assert_ne!(other.root(), root);
    }

    /// ⭐ SEVERAL WRITERS OF ONE STEP (2026-11-11) — A PATH PROVEN BEFORE OTHER LEAVES CHANGED IS BROUGHT FORWARD OVER
    /// THEM, AND ONLY THEN OPENS THE ROOT. Forty keys (hashed ones, a family sharing 70 leading bits, and two pairs that
    /// differ in the last bit alone, so the parting depth is shallow, deep and the deepest possible) all take their
    /// paths under ONE root; then each is written in turn, an update or an insert, through its own path as brought
    /// forward over every write before it. After every write the root computed from the brought-forward path is the
    /// full tree's. CALIBRATION / TAMPER: from the second write on, the path as first taken does NOT open the root
    /// (the fold refused every such settlement before this); a path brought forward with a wrong leaf for an earlier
    /// write does not open it either; the same key is not rebased (`false`), nor is a short path.
    #[test]
    fn contract_state_a_path_is_brought_forward_over_the_writes_of_one_step_and_opens_the_root_only_then() {
        let hashed = |i: u32| *blake3::hash(&i.to_le_bytes()).as_bytes();
        let mut keys: Vec<[u8; 32]> = (0..28u32).map(hashed).collect();
        let base = hashed(900);
        for i in 0..8u32 {
            let mut k = hashed(100 + i);
            k[..8].copy_from_slice(&base[..8]);
            k[8] = (k[8] & 0x03) | (base[8] & 0xFC); // 70 shared leading bits
            keys.push(k);
        }
        for i in 0..2u32 {
            let mut a = hashed(500 + i);
            a[31] &= 0xFE;
            let mut b = a;
            b[31] |= 1;
            keys.push(a);
            keys.push(b);
        }
        assert_eq!(keys.len(), 40);
        let leaf = |k: &[u8; 32], v: u64| contract_leaf(k, lanes_of(&[7, v]), lanes_of(&[v, 0x51]));
        // the tree before the step: every other key already holds a leaf (so the step both updates and inserts)
        let mut tree = ContractStateTree::new();
        for k in keys.iter().step_by(2) {
            tree.insert(*k, leaf(k, 1));
        }
        let root0 = tree.root();
        let taken: Vec<(Digest4, Vec<Digest4>)> = keys.iter().map(|k| (tree.get(k).unwrap_or_else(empty_leaf), tree.siblings(k))).collect();
        let mut root = root0;
        let mut written: Vec<([u8; 32], Digest4, Vec<Digest4>)> = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            let (old, first) = &taken[i];
            assert!(verify_path(root0, k, *old, first), "PRECONDITION: every path opens the root the step began on");
            let mut sibs = first.clone();
            for (other, new_leaf, path) in &written {
                assert!(rebase_path(k, &mut sibs, other, *new_leaf, path), "two different keys part somewhere");
            }
            if i > 0 {
                assert!(!verify_path(root, k, *old, first), "CALIBRATION: after {i} write(s) the path as first taken no longer opens the root");
                // TAMPER: the newest write brought forward with a leaf that was never written (the newest, because a later
                // write on the same side of this key replaces the same sibling and would correct an older lie)
                let mut wrong = first.clone();
                for (j, (other, new_leaf, path)) in written.iter().enumerate() {
                    let lie = if j + 1 == written.len() { lanes_of(&[0xDE, 0xAD]) } else { *new_leaf };
                    let _ = rebase_path(k, &mut wrong, other, lie, path);
                }
                assert!(!verify_path(root, k, *old, &wrong), "⛔ a path brought forward over a leaf that was never written opened the root");
            }
            assert!(verify_path(root, k, *old, &sibs), "⛔ the path brought forward over {i} write(s) does not open the root");
            let new = leaf(k, 2);
            let next = root_with(k, new, &sibs).expect("a whole path");
            tree.insert(*k, new);
            assert_eq!(next, tree.root(), "⛔ the root written through the brought-forward path is not the full tree's (write {i})");
            written.push((*k, new, sibs));
            root = next;
        }
        let mut same = taken[0].1.clone();
        assert!(!rebase_path(&keys[0], &mut same, &keys[0], leaf(&keys[0], 9), &taken[0].1), "the same key is not rebased");
        assert_eq!(same, taken[0].1);
        let mut short = taken[1].1[..DEPTH - 1].to_vec();
        assert!(!rebase_path(&keys[1], &mut short, &keys[0], leaf(&keys[0], 9), &taken[0].1), "a short path is not rebased");
    }

    /// ⭐ SAFE AT SCALE PIN — THE STORED NODES ARE THE LEAVES' TREE, AFTER EVERY WRITE. 300 keys (hashed ones, and families
    /// that share 9, 70 and 255 leading bits, so branching points sit at every depth a real tree has and at the deepest
    /// one possible) are inserted, a third are updated, and half are removed. After EVERY write the root from the stored
    /// nodes equals the root re-hashed from the leaves alone; sampled paths (an occupied key's and an absent key's) verify
    /// against it; a bulk-built replica has the same root and the same nodes. Removing everything returns the empty root
    /// with NO node left. CALIBRATION: one stored node tampered makes the root differ from the re-hashed one (so the
    /// comparison can fail), and the node count is measured (a node a shared level, never one a level for every leaf).
    #[test]
    fn contract_state_stored_nodes_equal_the_leaves_tree_after_every_write() {
        let hashed = |i: u32| *blake3::hash(&i.to_le_bytes()).as_bytes();
        let family = |i: u32, shared_bits: usize| {
            let mut k = hashed(i);
            let base = hashed(9_000 + shared_bits as u32);
            for bit in 0..shared_bits {
                let (byte, m) = (bit / 8, 0x80u8 >> (bit % 8));
                k[byte] = (k[byte] & !m) | (base[byte] & m);
            }
            k
        };
        let mut keys: Vec<[u8; 32]> = (0..240u32).map(hashed).collect();
        keys.extend((0..20u32).map(|i| family(i, 9)));
        keys.extend((0..20u32).map(|i| family(i, 70)));
        // two pairs that differ in the LAST bit alone
        for i in 0..10u32 {
            let mut a = hashed(5_000 + i);
            a[31] &= 0xFE;
            let mut b = a;
            b[31] |= 1;
            keys.push(a);
            keys.push(b);
        }
        assert_eq!(keys.len(), 300);
        let leaf = |k: &[u8; 32], v: u64| contract_leaf(k, lanes_of(&[7, v]), lanes_of(&[v, 0x51]));
        let mut tree = ContractStateTree::new();
        let check = |tree: &ContractStateTree, at: &[u8; 32], what: &str| {
            let root = tree.root();
            assert_eq!(root, tree.root_recomputed(), "⛔ the stored nodes are not the leaves' tree after {what}");
            let held = tree.get(at).unwrap_or_else(empty_leaf);
            assert!(verify_path(root, at, held, &tree.siblings(at)), "⛔ a path from the stored nodes does not open the root after {what}");
        };
        for (i, k) in keys.iter().enumerate() {
            tree.insert(*k, leaf(k, 1));
            check(&tree, k, "an insert");
            if i % 37 == 0 {
                check(&tree, &hashed(70_000 + i as u32), "an insert (an absent key's path)");
            }
        }
        // HOW MANY NODES IT KEEPS, MEASURED (the first run of this pin, 2026-11-11, refuted "about one a leaf": 2,929 nodes
        // for these 300 leaves). A node is kept for every subtree that holds two or more leaves, so a leaf costs one node
        // for each level it shares with another key: about log₂ k for hashed keys, and up to 255 for the pairs above that
        // differ in their last bit alone. Never one a level for every leaf (that would be 76,800 here).
        assert!(tree.inner.len() < 32 * tree.len(), "the tree keeps a node a shared level, not one a level: {} nodes for {} leaves", tree.inner.len(), tree.len());
        let mut hashed_only = ContractStateTree::new();
        for k in keys.iter().take(240) {
            hashed_only.insert(*k, leaf(k, 1));
        }
        assert!(
            hashed_only.inner.len() <= 10 * hashed_only.len(),
            "hashed keys cost about log₂ k nodes a leaf (8 at 240): {} nodes for {} leaves",
            hashed_only.inner.len(),
            hashed_only.len()
        );
        for k in keys.iter().step_by(3) {
            tree.insert(*k, leaf(k, 2));
            check(&tree, k, "an update");
        }
        let replica = ContractStateTree::from_entries(&tree.entries());
        assert_eq!(replica.root(), tree.root(), "⛔ a bulk-built replica has another root");
        assert_eq!(replica.inner, tree.inner, "⛔ a bulk-built replica keeps other nodes than the written one");
        // CALIBRATION: the comparison can fail
        let mut bent = tree.clone();
        let top = *bent.inner.keys().find(|(d, _)| *d == 0).expect("the root node is stored");
        bent.inner.get_mut(&top).expect("stored")[0] ^= 1;
        assert_ne!(bent.root(), bent.root_recomputed(), "CALIBRATION: a tampered node is seen by the comparison");
        for (i, k) in keys.iter().enumerate() {
            if i % 2 == 0 {
                tree.remove(k);
                check(&tree, k, "a removal");
            }
        }
        for k in &keys {
            tree.remove(k);
        }
        assert_eq!(tree.root(), empty_root(), "⛔ the emptied tree's root is not the empty root");
        assert!(tree.inner.is_empty() && tree.is_empty(), "⛔ the emptied tree kept {} node(s)", tree.inner.len());
    }
}

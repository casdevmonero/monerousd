// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Binary merkle tree over blake3 leaves — the shared inclusion-proof primitive.
//!
//! Used by data-availability sampling ([`crate::da`]) and by verifiable sovereign-site serving
//! ([`crate::site`]): a prover commits a set of leaves to a root, then serves any single leaf with an
//! O(log n) sibling path a verifier checks against the (independently anchored) root. Odd layers
//! duplicate the last node; an empty leaf set commits to the zero root.

use crate::hash::Hash32;

/// Hash two child nodes into their parent.
pub fn hash_pair(a: &Hash32, b: &Hash32) -> Hash32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a.as_bytes());
    buf[32..].copy_from_slice(b.as_bytes());
    Hash32::hash(&buf)
}

/// All layers bottom (leaves) → top (root); an odd layer duplicates its last node.
fn layers(leaves: &[Hash32]) -> Vec<Vec<Hash32>> {
    let mut layers = vec![leaves.to_vec()];
    loop {
        let cur = match layers.last() {
            Some(cur) if cur.len() > 1 => cur,
            _ => break,
        };
        let mut next = Vec::with_capacity((cur.len() + 1) / 2);
        let mut i = 0;
        while i < cur.len() {
            let l = cur[i];
            let r = if i + 1 < cur.len() {
                cur[i + 1]
            } else {
                cur[i]
            };
            next.push(hash_pair(&l, &r));
            i += 2;
        }
        layers.push(next);
    }
    layers
}

/// The merkle root over `leaves`. Empty ⇒ [`Hash32::ZERO`].
pub fn root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return Hash32::ZERO;
    }
    layers(leaves).last().and_then(|top| top.first()).copied().unwrap_or(Hash32::ZERO)
}

/// The inclusion proof (sibling hashes, bottom-up) for `leaves[index]`, or `None` if out of range.
pub fn inclusion_proof(leaves: &[Hash32], index: usize) -> Option<Vec<Hash32>> {
    if index >= leaves.len() {
        return None;
    }
    let ls = layers(leaves);
    let mut proof = Vec::with_capacity(ls.len());
    let mut idx = index;
    for layer in &ls[..ls.len() - 1] {
        let sib = if (idx ^ 1) < layer.len() {
            layer[idx ^ 1]
        } else {
            layer[idx]
        };
        proof.push(sib);
        idx /= 2;
    }
    Some(proof)
}

/// Verify `leaf` sits at `index` under `root` via `proof`. Fail-closed on any mismatch.
pub fn verify(root: &Hash32, index: usize, leaf: &Hash32, proof: &[Hash32]) -> bool {
    let mut h = *leaf;
    let mut idx = index;
    for sib in proof {
        h = if idx & 1 == 0 {
            hash_pair(&h, sib)
        } else {
            hash_pair(sib, &h)
        };
        idx >>= 1;
    }
    &h == root
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn root_proof_verify_roundtrip_and_edges() {
        let leaves: Vec<Hash32> = (0..5u8).map(|i| Hash32::hash(&[i])).collect();
        let r = root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let p = inclusion_proof(&leaves, i).unwrap();
            assert!(verify(&r, i, leaf, &p));
            // a wrong leaf at the right index fails.
            assert!(!verify(&r, i, &Hash32::hash(b"forged"), &p));
        }
        // single leaf: empty proof, root == leaf.
        let one = vec![Hash32::hash(b"only")];
        assert_eq!(root(&one), one[0]);
        assert!(verify(&root(&one), 0, &one[0], &[]));
        // empty ⇒ zero root; out-of-range proof is None.
        assert_eq!(root(&[]), Hash32::ZERO);
        assert!(inclusion_proof(&leaves, 5).is_none());
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Data-availability sampling (DAS) — greenfield, blake3.
//!
//! A validium node must confirm a block's data is AVAILABLE without downloading the bulk. The
//! producer commits the data as a merkle tree over fixed-size chunks; a node then samples a few
//! random chunks + their inclusion proofs and verifies each against the committed root. If the data
//! were withheld, the sampled proofs could not be produced, so a node catches unavailability with
//! high probability while pulling only O(samples) bytes — never O(block). A tampered chunk or proof
//! fails verification (fail-closed).

use crate::fixed::FixedBytes;
use crate::hash::Hash32;

/// Fixed DA chunk size in bytes.
pub const DA_CHUNK_SIZE: usize = 1024;
/// Number of chunks a node samples per block (availability confidence vs bandwidth).
pub const DA_SAMPLES: usize = 16;

/// A committed block payload: the merkle root + its padded chunks.
pub struct DaCommit {
    pub root: Hash32,
    pub chunks: Vec<Vec<u8>>,
}

impl DaCommit {
    pub fn n_chunks(&self) -> usize {
        self.chunks.len()
    }
}

// The merkle inclusion-proof primitive lives in crate::merkle (shared with the sovereign-site layer).

/// Split `data` into fixed padded chunks and merkle-commit over the chunk hashes.
pub fn commit(data: &[u8]) -> DaCommit {
    let mut chunks: Vec<Vec<u8>> = data
        .chunks(DA_CHUNK_SIZE)
        .map(|c| {
            let mut v = c.to_vec();
            v.resize(DA_CHUNK_SIZE, 0);
            v
        })
        .collect();
    if chunks.is_empty() {
        chunks.push(vec![0u8; DA_CHUNK_SIZE]);
    }
    let leaves: Vec<Hash32> = chunks.iter().map(|c| Hash32::hash(c)).collect();
    let root = crate::merkle::root(&leaves);
    DaCommit { root, chunks }
}

/// The inclusion proof (sibling hashes, bottom-up) for chunk `index`.
pub fn inclusion_proof(commit: &DaCommit, index: usize) -> Option<Vec<Hash32>> {
    if index >= commit.chunks.len() {
        return None;
    }
    let leaves: Vec<Hash32> = commit.chunks.iter().map(|c| Hash32::hash(c)).collect();
    crate::merkle::inclusion_proof(&leaves, index)
}

/// Verify a sampled chunk is committed under `root` at `index`. Fail-closed on any tamper.
pub fn verify_chunk(root: &Hash32, index: usize, chunk: &[u8], proof: &[Hash32]) -> bool {
    crate::merkle::verify(root, index, &Hash32::hash(chunk), proof)
}

/// Deterministically sample up to `k` DISTINCT chunk indices from `seed` (in production the seed is
/// the node's per-block sampling challenge / OS entropy — kept out of this pure function).
pub fn sample_indices(seed: &[u8; 32], n: usize, k: usize) -> Vec<usize> {
    if n == 0 {
        return vec![];
    }
    let k = k.min(n);
    let mut out: Vec<usize> = Vec::with_capacity(k);
    let mut ctr: u64 = 0;
    while out.len() < k {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(seed);
        buf[32..].copy_from_slice(&ctr.to_le_bytes());
        let h = Hash32::hash(&buf);
        let arr: [u8; 8] = h.as_bytes()[..8].fixed();
        let idx = (u64::from_le_bytes(arr) as usize) % n;
        if !out.contains(&idx) {
            out.push(idx);
        }
        ctr += 1;
    }
    out
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn sample_verify_roundtrip_and_reject_tamper() {
        // ~10 chunks of block data.
        let data: Vec<u8> = (0..(DA_CHUNK_SIZE * 10 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let c = commit(&data);
        assert_eq!(c.n_chunks(), 11);

        let seed = Hash32::hash(b"per-block DA challenge");
        let idxs = sample_indices(seed.as_bytes(), c.n_chunks(), DA_SAMPLES);
        // distinct + in range; capped at n.
        assert_eq!(idxs.len(), c.n_chunks().min(DA_SAMPLES));
        for &i in &idxs {
            assert!(i < c.n_chunks());
            let proof = inclusion_proof(&c, i).unwrap();
            assert!(
                verify_chunk(&c.root, i, &c.chunks[i], &proof),
                "honest sample verifies"
            );
        }

        // tampered chunk fails.
        let i = idxs[0];
        let proof = inclusion_proof(&c, i).unwrap();
        let mut bad = c.chunks[i].clone();
        bad[0] ^= 0xff;
        assert!(
            !verify_chunk(&c.root, i, &bad, &proof),
            "tampered chunk rejected"
        );

        // tampered proof fails.
        let mut bad_proof = proof.clone();
        if !bad_proof.is_empty() {
            let mut b = *bad_proof[0].as_bytes();
            b[0] ^= 0x01;
            bad_proof[0] = Hash32(b);
        }
        assert!(
            !verify_chunk(&c.root, i, &c.chunks[i], &bad_proof),
            "tampered proof rejected"
        );

        // wrong index fails.
        let other = (i + 1) % c.n_chunks();
        assert!(
            !verify_chunk(&c.root, other, &c.chunks[i], &proof),
            "wrong index rejected"
        );
    }

    #[test]
    fn single_chunk_and_empty_data() {
        let c = commit(b"tiny");
        assert_eq!(c.n_chunks(), 1);
        let proof = inclusion_proof(&c, 0).unwrap();
        assert!(verify_chunk(&c.root, 0, &c.chunks[0], &proof));
        // empty data still commits to one padded chunk.
        let e = commit(&[]);
        assert_eq!(e.n_chunks(), 1);
    }
}

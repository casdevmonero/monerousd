// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! OBLIVIOUS copath retrieval — the WHICH-ITEM-private serve for the flat-O(1) treeless producer.
//!
//! A treeless producer building the constant-256 block needs the DECOY copaths (reals ride the tx, self-built on the
//! spender's own node). A naive `serve_copath(nf)` is a WHICH-ITEM query: the serving node learns which nullifiers the
//! producer is inserting (digital-cash cardinal violation — the `digital-cash-privacy-guard` correctly blocks it). The
//! fix is oblivious retrieval: the producer fetches a tree-node from a shard WITHOUT the shard learning which index.
//!
//! This is a 2-server INFORMATION-THEORETIC XOR PIR — POST-QUANTUM by construction (no computational hardness
//! assumption at all, so no classical crypto and nothing a quantum adversary can break). To read `db[index]` from a
//! DB replicated on ≥2 non-colluding shards: pick a UNIFORM random subset `s1 ⊆ [0,len)`, set `s2 = s1 △ {index}`
//! (symmetric difference), send `s1` to shard A and `s2` to shard B; each returns the XOR of the DB entries its subset
//! selects; the producer XORs the two answers. Because `s1 △ s2 = {index}`, that XOR is exactly `db[index]`. Each
//! shard sees ONE uniform subset (s1 uniform ⇒ s2 = s1 △ {index} uniform too), so NEITHER learns `index`. A copath is
//! DEPTH such reads (one node per level), each independently oblivious.
//!
//! TRUSTLESS: the producer never trusts the answer — every witness it builds from the fetched nodes self-verifies
//! against the O(1) acc ([[project_trustless_nullifier_o1_design]]), so a lying shard yields a REJECTED witness, never
//! a wrong spend. Cost note: XOR PIR is O(len) server work + O(len) query per read — this fixes the WHICH-ITEM leak
//! (the privacy cardinal); a sublinear (still-PQ) query is the no-growth follow-on. ([[feedback_digital_cash_pillar]]
//! [[feedback_always_trustless]] [[feedback_no_classical_crypto_unconditional]])

use crate::spend_frontier::Digest4;

/// A per-shard query: the subset of DB indices this shard XORs. `bits[j] == true` ⇒ include `db[j]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirSubset {
    pub bits: Vec<bool>,
}

/// Split a read of `db[index]` (a DB of `db_len` entries) into two per-shard subsets that leak NOTHING about `index`.
/// `s1` is a UNIFORM random mask the producer draws from its OWN secret (never sent in the clear anywhere); `s2` is
/// `s1` with bit `index` flipped, so `s1 △ s2 = {index}`. Each shard receives exactly one subset. `s1_mask` must be
/// `db_len` uniform-random bits (caller-supplied so the randomness source stays the producer's — the trustless
/// self-build; a fixed/biased mask would break obliviousness, so production draws it from a CSPRNG).
pub fn pir_split(index: usize, db_len: usize, s1_mask: &[bool]) -> Option<(PirSubset, PirSubset)> {
    if index >= db_len || s1_mask.len() != db_len {
        return None;
    }
    let s1: Vec<bool> = s1_mask.to_vec();
    let mut s2 = s1.clone();
    s2[index] = !s2[index]; // s2 = s1 △ {index}
    Some((PirSubset { bits: s1 }, PirSubset { bits: s2 }))
}

/// A shard's O(len) response: XOR of every `db[j]` its subset selects. The shard sees only this ONE uniform subset,
/// so it cannot tell which index the producer wanted.
pub fn pir_respond(db: &[Digest4], subset: &PirSubset) -> Option<Digest4> {
    if subset.bits.len() != db.len() {
        return None;
    }
    let mut acc = usdm_decider::poseidon2_compress::zero_digest();
    for (j, &sel) in subset.bits.iter().enumerate() {
        if sel {
            // Every lane, bounded by the digest itself — ⛔ §AG class 9 (the silent half) lived here as
            // `for c in 0..4`: at eight lanes a PIR answer carried HALF of each digest and the client
            // reconstructed `db[index]` with lanes 4..7 zero — a wrong value, quietly.
            for (a, d) in acc.iter_mut().zip(db[j].iter()) {
                *a ^= *d;
            }
        }
    }
    Some(acc)
}

/// Recombine the two shards' answers → `db[index]` (because `s1 △ s2 = {index}`, all other terms cancel in the XOR).
pub fn pir_reconstruct(r1: Digest4, r2: Digest4) -> Digest4 {
    // Lane-wise over the whole digest (was `0..4` — half the lanes at the current width).
    core::array::from_fn(|c| r1[c] ^ r2[c])
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A FULL-WIDTH entry: every lane populated (a blake3 seed through the crate's one 32-bytes→digest
    /// map). ⛔ This was a four-lane `lanes_of(&[..4 values..])`, so lanes 4..7 were zero in every DB
    /// entry and the half-width XOR in `pir_respond` / `pir_reconstruct` (§AG class 9) read as exact.
    /// A fixture that cannot see the defect is a fixture that agrees with it.
    fn entry(seed: u64) -> Digest4 {
        usdm_decider::poseidon2_compress::hash32_to_digest(
            blake3::hash(&seed.to_le_bytes()).as_bytes(),
        )
    }

    /// CORRECT: the two oblivious shard answers recombine to EXACTLY the requested DB entry, for every index.
    #[test]
    fn oblivious_read_reconstructs_the_exact_entry() {
        let db: Vec<Digest4> = (0..37u64).map(entry).collect();
        // A deterministic-but-varied mask stands in for the producer's CSPRNG draw (fixed here so the test is stable).
        let mask: Vec<bool> = (0..db.len())
            .map(|j| (j * 2_654_435_761usize).wrapping_add(7) & 1 == 1)
            .collect();
        for index in 0..db.len() {
            let (s1, s2) = pir_split(index, db.len(), &mask).expect("split");
            let r1 = pir_respond(&db, &s1).expect("shard A");
            let r2 = pir_respond(&db, &s2).expect("shard B");
            assert_eq!(
                pir_reconstruct(r1, r2),
                db[index],
                "oblivious read returns db[{index}] exactly"
            );
        }
    }

    /// PRIVATE (which-item hiding): the two subsets differ ONLY at `index` (`s1 △ s2 = {index}`), and `s1` is exactly
    /// the producer's mask — INDEPENDENT of `index`. So a shard seeing ONE subset (a uniform mask) cannot learn the
    /// index: the SAME `s1` serves every index, and `s2` is just a uniform mask too. A quantum adversary gains nothing
    /// (information-theoretic — there is no assumption to break).
    #[test]
    fn shard_subset_leaks_nothing_about_the_index() {
        let db_len = 37;
        let mask: Vec<bool> = (0..db_len).map(|j| (j * 40_503) & 1 == 1).collect();
        let (s1_a, s2_a) = pir_split(5, db_len, &mask).unwrap();
        let (s1_b, s2_b) = pir_split(29, db_len, &mask).unwrap();

        // Shard A's subset is the producer's mask, IDENTICAL regardless of which index was wanted → reveals nothing.
        assert_eq!(
            s1_a, s1_b,
            "shard A sees the same mask for index 5 and 29 — index-independent"
        );
        assert_eq!(
            s1_a.bits, mask,
            "shard A's subset is exactly the producer's own random mask"
        );

        // s1 △ s2 == {index}: the two subsets differ in exactly one position (the requested index), nowhere else.
        let diff_a: Vec<usize> = (0..db_len)
            .filter(|&j| s1_a.bits[j] != s2_a.bits[j])
            .collect();
        let diff_b: Vec<usize> = (0..db_len)
            .filter(|&j| s1_b.bits[j] != s2_b.bits[j])
            .collect();
        assert_eq!(
            diff_a,
            vec![5],
            "shard-B mask differs from shard-A ONLY at the queried index 5"
        );
        assert_eq!(
            diff_b,
            vec![29],
            "…and at index 29 for the second read — one bit, never the value itself"
        );
    }

    /// A wrong index / mask length fails closed (no silent partial read).
    #[test]
    fn malformed_query_fails_closed() {
        let db_len = 10;
        let mask = vec![false; db_len];
        assert!(
            pir_split(10, db_len, &mask).is_none(),
            "index == len is out of range → None"
        );
        assert!(
            pir_split(3, db_len, &vec![false; 9]).is_none(),
            "mask length mismatch → None"
        );
        let db: Vec<Digest4> = (0..db_len as u64).map(entry).collect();
        assert!(
            pir_respond(
                &db,
                &PirSubset {
                    bits: vec![true; 9]
                }
            )
            .is_none(),
            "subset length mismatch → None"
        );
    }
}

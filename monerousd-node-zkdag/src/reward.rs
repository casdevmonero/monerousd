// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Confidential coinbase reward-note commitment — the header's `miner_commitment`. Ported in the PQ shape from
//! the old tree's `HF_VERSION_CONFIDENTIAL_COINBASE=30` / `RESERVE_YIELD=45`.
//!
//! ZERO-ISSUANCE: a block's "reward" is a CONFIDENTIAL note to the miner (a redistribution of fees /
//! reserve-yield, NEVER fresh emission), committed as an OPAQUE 32-byte digest that reveals NO amount and NO
//! identity to any chain observer — the digital-cash pillar. The commitment is PER-NODE (each miner derives it
//! from its OWN seed — the decentralization pillar forbids a shared reward key, even the founder's) and
//! block-unique (bound to the block's state), so no two blocks reuse a commitment.

use crate::hash::Hash32;

/// Domain separator for the confidential reward-note commitment.
const DS_REWARD: &[u8] = b"MUSD-coinbase-reward-note-v1";

/// The per-block confidential reward-note commitment for the header's `miner_commitment`. Binds the miner's
/// PER-NODE reward seed to a block-unique context (`bind`, e.g. the selected tip / frontier root) under a
/// domain separator. The result is an opaque digest: an observer learns neither the reward amount nor the
/// miner — only that the block carries a reward commitment, exactly like every block (constant shape).
/// Zero-issuance by construction (it commits a confidential redistribution note; it does not mint).
pub fn reward_note_commitment(miner_seed: &[u8; 32], bind: &Hash32) -> Hash32 {
    let mut buf = Vec::with_capacity(DS_REWARD.len() + 64);
    buf.extend_from_slice(DS_REWARD);
    buf.extend_from_slice(miner_seed);
    buf.extend_from_slice(bind.as_bytes());
    Hash32::hash(&buf)
}

/// Derive a fresh PER-NODE miner reward seed (decentralization pillar: each node its OWN, never shared). It is
/// PQ-derived from a fresh ML-DSA public key so two nodes never share a reward key. A deployment may override
/// it with a stable configured seed so a miner can later spend its accumulated rewards.
pub fn derive_node_miner_seed() -> [u8; 32] {
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    *Hash32::hash(&pk).as_bytes()
}

/// The seed `Node::new` installs. A node binary draws a fresh one ([`derive_node_miner_seed`]) — unchanged.
///
/// ⛔ TEST BUILDS ONLY: a seed that is a pure function of (the running test's name, how many nodes that test made
/// before this one). MEASURED 2026-10-02: `db321_a_node_that_cannot_vouch…` proved every whole-chain certificate step
/// from scratch on TWO consecutive runs of the same code (398–506 s each, ~6 steps, past the 30-min task bound once):
/// the fresh random seed enters every block's reward commitment, so each run built a different chain, every step
/// statement differed, and the cross-run cert cache (`sync::test_cert_fixture_cache`, keyed on the exact statement)
/// could never hit. The scenario fixtures already pin seeds (`party_miner_seed`); this makes EVERY test node
/// reproducible at the one site they all pass through. Two nodes in one test still get DISTINCT seeds (the counter), and
/// no assertion is narrowed — the cache still re-verifies whatever it serves. Libtest names each test's thread after the
/// test, so the key is stable across runs and filters; an unnamed helper thread shares one process-wide counter
/// (distinct seeds, order-dependent — only a cache miss, never a wrong answer).
pub fn new_node_miner_seed() -> [u8; 32] {
    #[cfg(test)]
    {
        use std::collections::BTreeMap;
        use std::sync::{Mutex, OnceLock};
        static MADE: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
        let name = std::thread::current().name().map(str::to_owned).unwrap_or_default();
        let n = {
            let mut made = MADE.get_or_init(|| Mutex::new(BTreeMap::new())).lock().unwrap_or_else(|e| e.into_inner());
            let slot = made.entry(name.clone()).or_insert(0);
            let n = *slot;
            *slot += 1;
            n
        };
        let mut buf = Vec::with_capacity(32 + name.len());
        buf.extend_from_slice(b"MUSD-test-node-miner-seed-v1");
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&n.to_le_bytes());
        *Hash32::hash(&buf).as_bytes()
    }
    #[cfg(not(test))]
    derive_node_miner_seed()
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A test node's seed is DISTINCT per node within a test and a pure function of (the test, the node's index) — so a
    /// test's chain is the same bytes on every run and the cert cache can hit. CALIBRATION: recomputed independently.
    #[test]
    fn a_test_node_seed_is_distinct_per_node_and_reproducible_per_test() {
        let (a, b) = (new_node_miner_seed(), new_node_miner_seed());
        assert_ne!(a, b, "two nodes of one test must never share a reward seed");
        let name = std::thread::current().name().expect("libtest names the test thread").to_owned();
        let expect = |n: u64| {
            let mut buf = b"MUSD-test-node-miner-seed-v1".to_vec();
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&n.to_le_bytes());
            *Hash32::hash(&buf).as_bytes()
        };
        assert_eq!((a, b), (expect(0), expect(1)), "the seed is a function of (test, index) — the same every run");
    }

    #[test]
    fn reward_commitment_is_opaque_per_node_and_block_unique() {
        let seed_a = derive_node_miner_seed();
        let seed_b = derive_node_miner_seed();
        assert_ne!(
            seed_a, seed_b,
            "each node derives its OWN reward seed (never shared)"
        );
        let b1 = Hash32::hash(b"block-1");
        let b2 = Hash32::hash(b"block-2");
        let c1 = reward_note_commitment(&seed_a, &b1);
        assert_ne!(
            c1,
            Hash32::ZERO,
            "a real commitment, not the ZERO placeholder"
        );
        assert_ne!(c1, reward_note_commitment(&seed_a, &b2), "block-unique");
        assert_ne!(
            c1,
            reward_note_commitment(&seed_b, &b1),
            "per-node (different miner)"
        );
        assert_eq!(
            c1,
            reward_note_commitment(&seed_a, &b1),
            "deterministic for the same (seed, block)"
        );
    }
}

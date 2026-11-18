// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::divergent_root_adoption_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! ⛔⛔⛔ THE DETERMINISTIC REVERT CLASS AT ITS ROOT (gate 29 scratch pair, 2026-09-02): a node that
//! JUMPED (payloads it never applied) folded a divergent unspent root over the payloads it did
//! receive and PUBLISHED it; the COMPLETE node adopted it as certified and could never fold its own
//! gapless ledger to it (146 REVERTs, target moving with production). Two invariants close it:
//!   (I1) a node with outstanding record wants must not advance/publish its unspent root past the
//!        gap — carry-what-you-verify, applied to the accumulator;
//!   (I2) a READY node whose gapless ledger folds to R must not adopt a different certified root
//!        for the same era — it IS the reproducible view; the holed peer re-syncs from it.
//! Both parties are real nodes; node_b is the jumped peer, node_a the complete one.
use super::*;
use super::tests::genesis_block;

fn carried(cm: [u8; 32]) -> Vec<u8> {
    let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    n[..32].copy_from_slice(&cm);
    n
}


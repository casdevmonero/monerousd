// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔ FROZEN v29 SNAPSHOT DOOR — the layout every schema-29 writer (through binary d1e11e84, the
//! 2026-08-31 gate-certified deploy) put on disk. v30 exists because `ChainParams` gained
//! `order_fill_fee_bps` MID-STRUCT on 2026-09-01 (the DEX taker fee), which changes the positional
//! postcard layout of `params` — so a v30 binary can no longer decode a v29 file through the
//! current struct, and without this door the next deploy would refuse to start BOTH live nodes
//! with real custody on disk (the measured 8/26 blocker class, replayed through the parameters).
//!
//! The v29 layout is EXACTLY the frozen v27 layout plus `chain_id` appended at the tail (v28's
//! amm fields were retired at source before any v28 writer shipped, and v29 added only the chain
//! identity). postcard flattens a nested struct positionally, so this door COMPOSES the already-
//! frozen `NodeSnapshotV27` byte-for-byte instead of re-declaring a single field — no duplication,
//! no new state, and the v27 freeze (including the frozen `ChainParamsV27`) is the single source
//! of the byte contract. cons: none — decode-only, transient inside `load`, nothing serialized
//! from this type in production, no new disk/RAM/wire/time term.
//!
//! Upgrade-custody law (user 2026-08-24): a bump must carry custody forward, never orphan it.
//! Frozen-door self-contained law (2026-08-26): the byte contract lives in frozen types; verified
//! against the live pair's REAL on-disk files by `persist::real_v29_fixture_tests`.

/// The schema-29 snapshot exactly as its writers serialized it: the frozen v27 body (positional
/// inline — postcard nests transparently) followed by the v29 `chain_id` tail.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshotV29 {
    /// The entire v27-frozen field run (`schema` through `deletion_sidecars`), byte-identical at
    /// schema 29 — the file's `schema` field reads 29 through `body.schema`.
    pub body: super::legacy_v27::NodeSnapshotV27,
    /// v29's one addition: the chain identity that gates resume (see `NodeSnapshot::chain_id`).
    pub chain_id: [u8; 32],
}

impl NodeSnapshotV29 {
    /// The file's schema byte (lives inside the composed v27 body).
    pub fn schema(&self) -> u32 {
        self.body.schema
    }

    // ⛔⛔⛔ THERE IS DELIBERATELY NO `migrate()` — THE REFUSAL IS BY CONSTRUCTION (2026-09-12, §AG).
    // Every root, commitment and accumulator in a pre-fork file is a digest of the RETIRED one-round
    // `MDS·(l + 7·r)^7`, which kill list §AG measured as INVERTIBLE and which this chain replaced with a
    // truncated Poseidon2 permutation. A migrated snapshot would seat the node on a root that no honest
    // producer can ever reproduce and no proof can open: a tip no peer shares. That is strictly worse
    // than refusing, because it looks like custody. The layout above stays FROZEN so a real file still
    // DECODES and earns a NAMED refusal in `persist::load` instead of a parse error — but no code path
    // exists that can turn these bytes into a current `NodeSnapshot`. Same law as the v31 door.
}

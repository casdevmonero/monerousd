// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::hole_adopt_revert_and_sidecar_cure_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! LIVE INCIDENT 2026-09-02: the deterministic REVERT loop, mechanism and cure, in-process.
//! node_a folds a receive it has the sidecar for; node_b (a HOLED peer — it knows it wants that
//! record and has not received it) ADOPTS node_a's certified root, which its own ledger cannot
//! reproduce, so its heal REVERTs every tick. The cure is the record's sidecar arriving from a peer
//! that holds it, which retires the want and lets the replay reach the certified root.
//! (Post-I2 shape: a READY peer with ZERO wants keeps its own root and never adopts — that case is
//! divergent_root_adoption_tests; here the peer is holed, so adopting is the live behaviour.)
use super::*;
use super::tests::genesis_block;


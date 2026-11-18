// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::not_ready_save_carries_its_anchor_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! LIVE INCIDENT 2026-09-02: every live snapshot carried `unspent_map_anchor_root = 0`, so every
//! resume DISCARDED the persisted map. A save taken while NOT_READY stamped zero. These pin that a
//! NOT_READY node with a verified map saves THAT anchor, and a peer resuming the bytes VERIFIES it.
use super::*;
use super::tests::genesis_block;


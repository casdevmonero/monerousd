// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::idle_record_presence_across_restart_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! LIVE INCIDENT 2026-09-02: after a rolling restart, each live node wants records the OTHER node
//! wrote; 150/150 sampled were idle (seed-only) rows, and the writer answers "hold 0". So an idle
//! row's PRESENCE is lost somewhere between write and the next boot. This pins where, in the LIVE
//! shape: a produced block, a real funded note (root beyond genesis), idle rows around it.
use super::*;
use super::tests::genesis_block;

fn carried(cms: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new();
    for cm in cms {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(cm);
        out.extend_from_slice(&n);
    }
    out
}


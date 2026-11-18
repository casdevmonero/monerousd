#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ROOT FIX for the username-IMT OOM core-dump (2026-06-24):
# circuit.rs::username_imt_empty_root_bytes was fixed (ry_sparse_root_leftmost, O(depth), no 2^32 alloc)
# but the compiled libpqpool.a on the VPS was STALE (2026-06-23, pre-fix) -> a fresh `make daemon`
# relinked the daemon against the old O(2^32) symbol -> alloc abort in rebuild_pq_state_from_chain on
# startup (blockchain.cpp:390 calls username_imt_empty_root(PQ_NOTE_TREE_DEPTH=32)).
# Fix = rebuild libpqpool.a + libpqpool_ffi.a from the fixed source, then relink the daemon (which also
# picks up the already-present no-halts rec-bond cap in tx_pool.cpp). No source change. No consensus change
# (sparse root is byte-identical to the dense root; proven for depth 32 by ry_frontier_byte_identical_to_sparse_root).
set -u
P3=/root/MoneroUSD-clean/monero/external/Plonky3
BUILD=/root/MoneroUSD-clean/monero/build
SRC=/root/MoneroUSD-clean/monero/src/cryptonote_core
LOG=/root/build_oomfix.log
rm -f "$LOG"
echo "=== STEP1 cargo build --release -p pqpool -p pqpool_ffi (regenerate FIXED libpqpool.a)  $(date) ===" > "$LOG"
cd "$P3" || { echo "EXIT_CARGO=98 (no P3 dir)" >> "$LOG"; exit 98; }
cargo build --release -p pqpool -p pqpool_ffi >> "$LOG" 2>&1
echo "EXIT_CARGO=$?" >> "$LOG"
echo "--- libpqpool.a timestamp after cargo (must be today) ---" >> "$LOG"
ls -la --time-style=+%Y-%m-%d_%H:%M "$P3/target/release/libpqpool.a" "$P3/target/release/libpqpool_ffi.a" >> "$LOG" 2>&1
echo "=== STEP2 force daemon relink against the fresh staticlib  $(date) ===" >> "$LOG"
touch "$SRC/tx_pool.cpp"   # forces the link step to re-run so the new libpqpool.a is pulled in
cd "$BUILD" || { echo "EXIT_MAKE=99 (no build dir)" >> "$LOG"; exit 99; }
CMAKE_POLICY_VERSION_MINIMUM=3.5 make daemon -j"$(nproc)" >> "$LOG" 2>&1
echo "EXIT_MAKE=$?" >> "$LOG"
echo "=== DONE $(date) ===" >> "$LOG"

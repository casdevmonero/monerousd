#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# VPS daemon rebuild after the no-halts rec-bond-carrier cap (tx_pool.cpp fill_block_template) +
# the reverted blockchain.cpp (broken create_block_template edit undone, bond-admission fix retained).
# Touch both sources to force recompile (rsync -a preserves mtime). Daemon-only C++ change.
set -u
SRC=/root/MoneroUSD-clean/monero/src/cryptonote_core
BUILD=/root/MoneroUSD-clean/monero/build
LOG=/root/build_nohalts.log
touch "$SRC/tx_pool.cpp" "$SRC/blockchain.cpp"
rm -f "$LOG"
cd "$BUILD" || { echo "EXIT=99 (no build dir)" > "$LOG"; exit 99; }
CMAKE_POLICY_VERSION_MINIMUM=3.5 make daemon -j"$(nproc)" > "$LOG" 2>&1
echo "EXIT=$?" >> "$LOG"

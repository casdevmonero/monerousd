#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Incremental VPS daemon rebuild after the validator-bond admission edit
# (blockchain.cpp: retire legacy DOMAIN_VALIDATOR_BOND admission -> #92 rec-bond only).
# Daemon-only C++ change => only the `daemon` target needs rebuilding (no Rust/wallet).
# Detached + logged so it survives an SSH drop; EXIT= line lets the poller read the real exit.
set -u
SRC=/root/MoneroUSD-clean/monero/src/cryptonote_core/blockchain.cpp
BUILD=/root/MoneroUSD-clean/monero/build
LOG=/root/build_bondadmission.log

touch "$SRC"          # force recompile (rsync -a preserved the source mtime)
rm -f "$LOG"
cd "$BUILD" || { echo "EXIT=99 (no build dir $BUILD)" > "$LOG"; exit 99; }
CMAKE_POLICY_VERSION_MINIMUM=3.5 make daemon -j"$(nproc)" > "$LOG" 2>&1
echo "EXIT=$?" >> "$LOG"

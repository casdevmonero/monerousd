#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# phase2-finish-v2.sh
#
# Re-runs cmake with -DMANUAL_SUBMODULES=1 to bypass the git-submodule
# staleness check that aborted Step 3 of the original script. Then
# builds the daemon, locates the binary, swaps it into the running
# USDmd.service, and verifies Phase C + Phase E endpoints respond.
#
# Why -DMANUAL_SUBMODULES=1: the source was rsync'd from local Mac
# where submodules are populated as ordinary files (not git checkouts).
# rsync changes file ownership which trips git's "dubious ownership"
# safety; cmake then refuses to proceed. -DMANUAL_SUBMODULES=1 tells
# cmake "I (the operator) attest that all submodule content is
# present and current; skip the git check." Safe because we just
# rsync'd the entire source tree verbatim.
#
# Run:    /bin/bash $HOME/Desktop/connect/scripts/phase2-finish-v2.sh

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly REMOTE_SRC="/root/MoneroUSD/MoneroUSD-main"
readonly TS="$(date +%Y%m%d-%H%M%S)"

cyan(){ printf '\033[36m[phase2]\033[0m %s\n' "$*"; }
fail(){ printf '\033[31m[phase2 ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# Strict pipefail in the REMOTE shell too — Step 1's silent build
# failure happened because pipefail wasn't set on the SSH side, so
# `make | tail` returned 0 even when make errored.
readonly REMOTE_SHELL='set -euo pipefail;'

# ── 1. cmake configure with submodule-check bypass ─────────────────
cyan "Step 1/5: cmake configure with -DMANUAL_SUBMODULES=1"
ssh "$VPS_HOST" "$REMOTE_SHELL cd $REMOTE_SRC && \
  rm -rf build-linux && mkdir build-linux && cd build-linux && \
  cmake -DCMAKE_BUILD_TYPE=Release -DMANUAL_SUBMODULES=1 .. 2>&1 | tail -20" \
  || fail "cmake configure failed even with -DMANUAL_SUBMODULES=1 — see output above"
cyan "  ✓ cmake configure succeeded"

# ── 2. Verify Makefile was generated AND has a daemon target ───────
cyan "Step 2/5: Verify Makefile + daemon target exist"
ssh "$VPS_HOST" "$REMOTE_SHELL cd $REMOTE_SRC/build-linux && \
  [ -f Makefile ] && \
  make help 2>/dev/null | grep -q '^\\.\\.\\. daemon\$'" \
  || fail "cmake didn't produce a daemon target. Run: ssh $VPS_HOST 'cd $REMOTE_SRC/build-linux && make help | grep -iE daemon | head -10'"
cyan "  ✓ Makefile + daemon target present"

# ── 3. Build daemon (the slow step — 20-30 min) ────────────────────
cyan "Step 3/5: Build daemon target (~20-30 min). Output streams below."
ssh "$VPS_HOST" "$REMOTE_SHELL cd $REMOTE_SRC/build-linux && \
  make -j\$(nproc) daemon 2>&1 | tail -40" \
  || fail "daemon build failed — see output above. Rollback rsync: ssh $VPS_HOST 'rm -rf $REMOTE_SRC && mv ${REMOTE_SRC}.bak-* $REMOTE_SRC' (pick most-recent timestamp)"
cyan "  ✓ daemon built"

# ── 4. Locate fresh binary + verify Phase C symbols + swap ─────────
cyan "Step 4/5: Locate + verify + swap binary"
NEW_BIN=$(ssh "$VPS_HOST" "find $REMOTE_SRC/build-linux -type f -name USDmd -executable -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print \$2}'")
[ -n "$NEW_BIN" ] || fail "no fresh USDmd binary anywhere under build-linux. make daemon may have produced a different output name."
cyan "  binary: $NEW_BIN"

SYMS=$(ssh "$VPS_HOST" "nm '$NEW_BIN' 2>/dev/null | grep -cE 'side_index|scope_tag'")
[ "${SYMS:-0}" -gt 0 ] || fail "binary at $NEW_BIN lacks Phase C symbols (got $SYMS)"
cyan "  ✓ $SYMS Phase C symbols present"

RUNNING_BIN=$(ssh "$VPS_HOST" "systemctl show -p ExecStart --value USDmd.service | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1")
[ -n "$RUNNING_BIN" ] || fail "could not read ExecStart"
cyan "  service uses: $RUNNING_BIN"

ssh "$VPS_HOST" "$REMOTE_SHELL cp '$RUNNING_BIN' /root/MoneroUSD/USDmd.pre-phaseC.$TS && \
  cp '$NEW_BIN' '$RUNNING_BIN' && \
  systemctl restart USDmd.service && \
  sleep 6 && \
  systemctl is-active USDmd.service" \
  || fail "restart failed. Rollback: ssh $VPS_HOST 'cp /root/MoneroUSD/USDmd.pre-phaseC.$TS \"$RUNNING_BIN\" && systemctl restart USDmd.service'"
cyan "  ✓ USDmd.service running new binary (rollback: /root/MoneroUSD/USDmd.pre-phaseC.$TS)"

# ── 5. Verify Phase C + Phase E endpoints respond ──────────────────
cyan "Step 5/5: Probe Phase C + Phase E endpoints"
ssh "$VPS_HOST" "
  echo '─── Phase C: get_side_index_root ───';
  curl -s -m 6 -X POST http://127.0.0.1:17750/json_rpc -H 'Content-Type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_side_index_root\",\"params\":{}}' | head -c 300
  echo ''
  echo '─── Phase E: get_attestations_in_range ───';
  curl -s -m 6 -X POST http://127.0.0.1:17750/json_rpc -H 'Content-Type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_attestations_in_range\",\"params\":{\"from_height\":0,\"to_height\":1,\"max_results\":1}}' | head -c 300
"
echo ""
cyan "PHASE 2 COMPLETE if both endpoints returned status:OK (instead of 'Method not found')."
cyan "Next: /bin/bash $HOME/Desktop/connect/scripts/safe-deploy-usdmd-binary.sh --execute"

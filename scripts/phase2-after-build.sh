#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# phase2-after-build.sh
#
# Run AFTER `make daemon` on the VPS has finished. Locates the fresh
# binary, verifies Phase C symbols, swaps it into the running
# USDmd.service binary path, restarts the service, verifies Phase C
# + Phase E endpoints. Idempotent — safe to re-run if anything errors.
#
# Run:    /bin/bash $HOME/Desktop/connect/scripts/phase2-after-build.sh
set -euo pipefail
readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly REMOTE_SRC="/root/MoneroUSD/MoneroUSD-main"
readonly TS="$(date +%Y%m%d-%H%M%S)"
cyan(){ printf '\033[36m[phase2]\033[0m %s\n' "$*"; }
fail(){ printf '\033[31m[phase2 ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

cyan "Locating fresh USDmd binary (newest under build-linux/)"
NEW_BIN=$(ssh "$VPS_HOST" "find $REMOTE_SRC/build-linux -type f -name USDmd -executable -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print \$2}'")
[ -n "$NEW_BIN" ] || fail "No fresh USDmd binary. Build still running? Or 'make daemon' produced a different filename. Run: ssh $VPS_HOST 'find $REMOTE_SRC -type f -executable -newer $REMOTE_SRC/build-linux/CMakeCache.txt 2>/dev/null | head -5'"
cyan "  → $NEW_BIN"

SYMS=$(ssh "$VPS_HOST" "nm '$NEW_BIN' 2>/dev/null | grep -cE 'side_index|scope_tag'")
[ "${SYMS:-0}" -gt 0 ] || fail "Binary at $NEW_BIN has $SYMS Phase C symbols (expected >0). Build used stale source — rerun rsync."
cyan "  ✓ $SYMS Phase C symbols present"

RUNNING_BIN=$(ssh "$VPS_HOST" "systemctl show -p ExecStart --value USDmd.service | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1")
[ -n "$RUNNING_BIN" ] || fail "Could not read USDmd.service ExecStart path"
cyan "  service uses: $RUNNING_BIN"

cyan "Backing up running binary + swapping + restarting"
ssh "$VPS_HOST" "set -euo pipefail; \
  cp '$RUNNING_BIN' /root/MoneroUSD/USDmd.pre-phaseC.$TS && \
  cp '$NEW_BIN' '$RUNNING_BIN' && \
  systemctl restart USDmd.service && \
  sleep 8 && \
  systemctl is-active USDmd.service" \
  || fail "USDmd.service didn't come up. Rollback: ssh $VPS_HOST \"cp /root/MoneroUSD/USDmd.pre-phaseC.$TS $RUNNING_BIN && systemctl restart USDmd.service\""
cyan "  ✓ USDmd.service running new binary (rollback: /root/MoneroUSD/USDmd.pre-phaseC.$TS)"

cyan "Probing Phase C + Phase E endpoints"
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
cyan "✓ PHASE 2 COMPLETE if endpoints returned status:OK (not 'Method not found')."
cyan "  Next: /bin/bash $HOME/Desktop/connect/scripts/safe-deploy-usdmd-binary.sh --execute"

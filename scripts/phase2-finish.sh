#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# phase2-finish.sh
#
# Picks up after phase2-vps-daemon-rebuild.sh's Step 3 (build) succeeded
# but Step 5 (binary swap) failed because of a wrong path. Locates the
# fresh binary, verifies Phase C symbols, swaps it in, restarts USDmd.
#
# Run:    /bin/bash $HOME/Desktop/connect/scripts/phase2-finish.sh

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly REMOTE_SRC="/root/MoneroUSD/MoneroUSD-main"
readonly TS="$(date +%Y%m%d-%H%M%S)"

cyan(){ printf '\033[36m[phase2-finish]\033[0m %s\n' "$*"; }
fail(){ printf '\033[31m[phase2-finish ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

cyan "Locating fresh USDmd binary anywhere under $REMOTE_SRC/build-linux"
NEW_BIN=$(ssh "$VPS_HOST" "find $REMOTE_SRC/build-linux -type f -name USDmd -executable -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print \$2}'")
[ -n "$NEW_BIN" ] || fail "no USDmd binary found. Run: ssh $VPS_HOST 'find $REMOTE_SRC -name USDmd -type f 2>/dev/null'"
cyan "  binary located: $NEW_BIN"

cyan "Verifying Phase C symbols"
SYMS=$(ssh "$VPS_HOST" "nm '$NEW_BIN' 2>/dev/null | grep -cE 'side_index|scope_tag'")
[ "${SYMS:-0}" -gt 0 ] || fail "binary lacks Phase C symbols (got $SYMS). Build used stale source."
cyan "  ✓ $SYMS Phase C symbols present"

cyan "Reading current USDmd.service ExecStart binary path"
RUNNING_BIN=$(ssh "$VPS_HOST" "systemctl show -p ExecStart --value USDmd.service | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1")
[ -n "$RUNNING_BIN" ] || fail "could not read ExecStart"
cyan "  service uses: $RUNNING_BIN"

if [ "$NEW_BIN" = "$RUNNING_BIN" ]; then
  cyan "  (binary IS the ExecStart path — restart will pick it up directly)"
else
  cyan "  Backing up + swapping $RUNNING_BIN ← $NEW_BIN"
fi

cyan "Backing up running binary + swapping + restarting USDmd.service"
ssh "$VPS_HOST" "cp '$RUNNING_BIN' /root/MoneroUSD/USDmd.pre-phaseC.$TS && \
  cp '$NEW_BIN' '$RUNNING_BIN' && \
  systemctl restart USDmd.service && \
  sleep 6 && \
  systemctl is-active USDmd.service" \
  || fail "restart failed. Rollback: ssh $VPS_HOST 'cp /root/MoneroUSD/USDmd.pre-phaseC.$TS \"$RUNNING_BIN\" && systemctl restart USDmd.service'"
cyan "  ✓ USDmd.service running new binary (rollback at /root/MoneroUSD/USDmd.pre-phaseC.$TS)"

cyan "Verifying Phase C + Phase E endpoints respond"
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
cyan "PHASE 2 COMPLETE. If both endpoints returned valid JSON with status:OK, Phase C is live on VPS."
cyan "Next: bash $HOME/Desktop/connect/scripts/safe-deploy-usdmd-binary.sh --execute"

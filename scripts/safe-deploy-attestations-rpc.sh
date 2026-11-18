#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# safe-deploy-attestations-rpc.sh
#
# Ships the Phase-E daemon RPC `get_attestations_in_range` to the
# canonical USDmd source tree on the VPS, compiles, restarts the
# service, and smoke-tests the new method. Successful run leaves
# the system ready for `safe-deploy-usdmd-binary.sh` (publishes
# the stripped binary to the OTA endpoint, triggering wallet
# auto-upgrade).
#
# WHY THIS EXISTS — the daemon's RPC additions are the engine
# behind Phase E of the indexer-independence roadmap (see
# `build-1261/docs/INDEXER-INDEPENDENCE.md`). Once this lands +
# OTA publishes, every existing wallet auto-upgrades to <1 s
# cold-scan with NO wallet-side change required (wallet's
# feature detection at `chain-scanner.js::probeFastRpc` already
# calls the new method).
#
# Hard guards
# ───────────
# • TARGET DIR is hardcoded to /root/MoneroUSD/MoneroUSD-main/src/.
#   Anything outside that prefix → abort.
# • The 3 file paths are an EXPLICIT allowlist; rsync uses
#   --files-from so a typo cannot bleed into anywhere else.
# • Every write is preceded by a timestamped backup; rollback is
#   one rsync away.
# • Pre-deploy probe of /get_attestations_in_range (expects 404 —
#   the pre-fork state). If it returns anything else, the daemon
#   already has the RPC and the deploy is a no-op + abort.
# • Compile uses the existing build-linux/ tree (no rm -rf, no
#   -DCMAKE_BUILD_TYPE override, no surprises).
# • Post-restart smoke probe confirms the new RPC actually
#   responds (truncated:false, attestations:[] for an empty range).
# • On any smoke-test failure: rollback (restore source tree from
#   backup, rebuild, restart). Documented inline so the operator
#   doesn't have to remember.

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly VPS_SRC="/root/MoneroUSD/MoneroUSD-main/src"
readonly VPS_BUILD="/root/MoneroUSD/MoneroUSD-main/build-linux"
readonly LOCAL_SRC="$HOME/Desktop/MoneroUSD-main/src"

# Allowlisted file paths. Adding a new file requires editing this
# script — intentional friction.
readonly FILES=(
  "rpc/core_rpc_server_commands_defs.h"
  "rpc/core_rpc_server.h"
  "rpc/core_rpc_server.cpp"
)

EXECUTE=0
case "${1:-}" in
  --execute) EXECUTE=1 ;;
  --help|-h)
    sed -n '/^# safe-deploy-attestations/,/^set -euo/p' "$0" | sed 's/^# \?//'
    exit 0 ;;
esac

cyan(){ printf '\033[36m[atts-rpc]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[atts-rpc WARN]\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[31m[atts-rpc ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────
cyan "Pre-flight: confirm 3 files staged locally"
for f in "${FILES[@]}"; do
  [ -f "$LOCAL_SRC/$f" ] || fail "missing local file: $LOCAL_SRC/$f"
done
cyan "  ✓ all 3 staged"

cyan "Pre-flight: VPS reachable + USDmd running"
ssh -o ConnectTimeout=8 -o BatchMode=yes "$VPS_HOST" "true" \
  || fail "cannot reach $VPS_HOST"
ssh "$VPS_HOST" 'systemctl is-active USDmd.service' >/dev/null \
  || fail "USDmd.service not active on VPS"
cyan "  ✓ VPS reachable, USDmd running"

cyan "Pre-flight: probe live get_attestations_in_range (expect 'method not found')"
PRE_RESP=$(ssh "$VPS_HOST" "curl -s -X POST -H 'content-type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_attestations_in_range\",\"params\":{\"from_height\":0,\"to_height\":1}}' \
  http://127.0.0.1:17750/json_rpc" || true)
if echo "$PRE_RESP" | grep -q '"attestations"'; then
  fail "daemon ALREADY supports get_attestations_in_range — nothing to deploy"
fi
cyan "  ✓ pre-fork state confirmed (no method)"

# Confirm the local C++ has the new RPC structures (lint-by-grep
# against the source tree we're about to ship).
cyan "Pre-flight: local source has the new RPC declarations"
grep -q "COMMAND_RPC_GET_ATTESTATIONS_IN_RANGE" "$LOCAL_SRC/rpc/core_rpc_server_commands_defs.h" \
  || fail "local commands_defs.h missing COMMAND_RPC_GET_ATTESTATIONS_IN_RANGE struct"
grep -q "on_get_attestations_in_range" "$LOCAL_SRC/rpc/core_rpc_server.h" \
  || fail "local core_rpc_server.h missing on_get_attestations_in_range declaration"
grep -q "get_attestations_in_range" "$LOCAL_SRC/rpc/core_rpc_server.cpp" \
  || fail "local core_rpc_server.cpp missing on_get_attestations_in_range implementation"
cyan "  ✓ all 3 source markers present"

if [ "$EXECUTE" -eq 0 ]; then
  cyan ""
  cyan "DRY RUN — pass --execute to apply"
  cyan "Will:"
  cyan "  1. Backup VPS source tree to $VPS_SRC/.backups/atts-rpc-<TS>/"
  cyan "  2. rsync 3 files: ${FILES[*]}"
  cyan "  3. cmake --build $VPS_BUILD"
  cyan "  4. systemctl restart USDmd.service"
  cyan "  5. Smoke-probe new get_attestations_in_range RPC"
  cyan "  6. (run safe-deploy-usdmd-binary.sh next to publish to OTA)"
  exit 0
fi

# ── Backup VPS source ─────────────────────────────────────────────
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$VPS_SRC/.backups/atts-rpc-$TS"
cyan "Backup → $BACKUP_DIR"
ssh "$VPS_HOST" "mkdir -p '$BACKUP_DIR/rpc'"
for f in "${FILES[@]}"; do
  ssh "$VPS_HOST" "cp '$VPS_SRC/$f' '$BACKUP_DIR/$f'" \
    || fail "backup of $f failed"
done
cyan "  ✓ backed up"

# ── rsync allowlisted files ──────────────────────────────────────
TMP_LIST=$(mktemp)
trap "rm -f '$TMP_LIST'" EXIT
printf '%s\n' "${FILES[@]}" > "$TMP_LIST"
cyan "rsync 3 files → $VPS_SRC"
rsync -avz --files-from="$TMP_LIST" "$LOCAL_SRC/" "$VPS_HOST:$VPS_SRC/" \
  || fail "rsync failed"
cyan "  ✓ uploaded"

# ── Build ─────────────────────────────────────────────────────────
cyan "Build (cmake --build $VPS_BUILD -j) — should be incremental, ~30 s"
ssh "$VPS_HOST" "cd '$VPS_BUILD' && cmake --build . -j 2>&1 | tail -40" \
  || { warn "build failed — initiating rollback"; ssh "$VPS_HOST" "cp -a '$BACKUP_DIR'/. '$VPS_SRC/'"; fail "build failed; source restored from $BACKUP_DIR"; }
cyan "  ✓ build succeeded"

# ── Restart ──────────────────────────────────────────────────────
cyan "systemctl restart USDmd.service"
ssh "$VPS_HOST" "systemctl restart USDmd.service" \
  || { warn "restart failed — rolling back"; ssh "$VPS_HOST" "cp -a '$BACKUP_DIR'/. '$VPS_SRC/' && cd '$VPS_BUILD' && cmake --build . -j && systemctl restart USDmd.service"; fail "restart failed; rolled back"; }

# Wait for the daemon to come up.
cyan "Wait for daemon RPC to come up (~10 s)…"
for i in $(seq 1 15); do
  if ssh "$VPS_HOST" "curl -s -X POST -H 'content-type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_count\"}' \
    http://127.0.0.1:17750/json_rpc | grep -q '\"count\"'"; then
    cyan "  ✓ daemon RPC alive (after ${i}s)"
    break
  fi
  sleep 1
  [ "$i" -eq 15 ] && { warn "daemon not responding after 15 s — rolling back";
    ssh "$VPS_HOST" "cp -a '$BACKUP_DIR'/. '$VPS_SRC/' && cd '$VPS_BUILD' && cmake --build . -j && systemctl restart USDmd.service";
    fail "daemon RPC didn't come up; rolled back"; }
done

# ── Smoke-test new RPC ───────────────────────────────────────────
cyan "Smoke-test get_attestations_in_range"
SMOKE_RESP=$(ssh "$VPS_HOST" "curl -s -X POST -H 'content-type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_attestations_in_range\",\"params\":{\"from_height\":0,\"to_height\":1,\"max_results\":1}}' \
  http://127.0.0.1:17750/json_rpc" || true)
if echo "$SMOKE_RESP" | grep -q '"attestations"'; then
  cyan "  ✓ new RPC responds with attestations array"
else
  warn "smoke-test failed — response:"
  echo "$SMOKE_RESP" | head -c 500
  warn ""
  warn "rolling back…"
  ssh "$VPS_HOST" "cp -a '$BACKUP_DIR'/. '$VPS_SRC/' && cd '$VPS_BUILD' && cmake --build . -j && systemctl restart USDmd.service"
  fail "smoke-test failed; rolled back"
fi

cyan ""
cyan "DEPLOY COMPLETE."
cyan ""
cyan "Next step: publish stripped binary to OTA so wallets auto-upgrade."
cyan "  bash $(dirname "$0")/safe-deploy-usdmd-binary.sh --execute"
cyan ""
cyan "Rollback (manual, if needed later):"
cyan "  ssh $VPS_HOST 'cp -a $BACKUP_DIR/. $VPS_SRC/ && cd $VPS_BUILD && cmake --build . -j && systemctl restart USDmd.service'"

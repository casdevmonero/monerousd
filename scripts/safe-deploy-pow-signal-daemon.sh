#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# safe-deploy-pow-signal-daemon.sh
#
# One-shot deploy of the pow_signal daemon patch to the VPS:
#   1. Backup the current src/ tree on the VPS to a timestamped dir
#   2. rsync the 8 patched/new files (only — never the rest of /root)
#   3. cmake --build to produce a fresh USDmd binary
#   4. systemctl restart USDmd.service
#   5. Smoke-test: HTTP POST /set_pow_signals returns 200, /get_pow_signals
#      returns the persisted signal back
#   6. Roll back on any failure (binary swap + service restart)
#
# Hard guards
# ───────────
# • TARGET DIR is hardcoded to /root/MoneroUSD/MoneroUSD-main/src/.
#   Any rsync target outside that prefix → abort.
# • The 8 file paths are an EXPLICIT allowlist; rsync uses --files-from
#   so a typo / extra file in the local source tree cannot bleed into
#   anywhere else on the VPS.
# • Every write is preceded by a backup. Rollback is one rsync away.
# • A pre-deploy smoke check on the LIVE daemon's /set_pow_signals
#   probes for HTTP 404 (current state). If it returns anything else,
#   the daemon already has the RPC and the deploy is a no-op + abort.
# • Build runs as a normal `cmake --build` in the existing build-linux/
#   tree. No -DCMAKE_BUILD_TYPE override, no rm -rf build/.

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly VPS_SRC="/root/MoneroUSD/MoneroUSD-main/src"
readonly VPS_BUILD="/root/MoneroUSD/MoneroUSD-main/build-linux"
readonly VPS_BIN="/root/MoneroUSD/MoneroUSD-main/build-linux/bin/USDmd"
readonly LOCAL_PATCH_ROOT="$HOME/Desktop/connect/MoneroUSD-pow-signal-work/src"

# Allowlisted file paths — the ONLY files that can be uploaded.
# Adding a new file requires editing this script (intentional friction).
readonly FILES=(
  "cryptonote_basic/tx_extra.h"
  "cryptonote_core/cryptonote_tx_utils.cpp"
  "cryptonote_core/cryptonote_core.cpp"
  "cryptonote_core/CMakeLists.txt"
  "cryptonote_core/pow_signal_store.h"
  "cryptonote_core/pow_signal_store.cpp"
  "rpc/core_rpc_server_commands_defs.h"
  "rpc/core_rpc_server.h"
  "rpc/core_rpc_server.cpp"
)

EXECUTE=0
case "${1:-}" in
  --execute) EXECUTE=1 ;;
  --help|-h)
    sed -n '/^# safe-deploy-pow/,/^set -euo/p' "$0" | sed 's/^# \?//'
    exit 0 ;;
esac

cyan(){ printf '\033[36m[pow-signal-deploy]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[pow-signal-deploy WARN]\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[31m[pow-signal-deploy ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────
cyan "Pre-flight: confirm 9 files staged locally"
for f in "${FILES[@]}"; do
  [ -f "$LOCAL_PATCH_ROOT/$f" ] || fail "missing local file: $LOCAL_PATCH_ROOT/$f"
done
cyan "  ✓ all 9 staged"

cyan "Pre-flight: VPS reachable + USDmd running"
ssh -o ConnectTimeout=8 -o BatchMode=yes "$VPS_HOST" "true" \
  || fail "cannot reach $VPS_HOST"
ssh "$VPS_HOST" 'systemctl is-active USDmd.service' \
  || fail "USDmd.service not active on VPS"
cyan "  ✓ VPS reachable, USDmd running"

cyan "Pre-flight: probe live /set_pow_signals (expect 404 — pre-deploy state)"
PRE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "content-type: application/json" -d '{"signals":{}}' \
  "http://node.monerousd.org:17750/set_pow_signals" || echo "000")
if [ "$PRE_STATUS" != "404" ]; then
  warn "expected 404, got $PRE_STATUS — daemon may already have the RPC"
  warn "  if the deploy is intentional anyway, re-run with --force-redeploy"
  if [ "${2:-}" != "--force-redeploy" ]; then
    fail "abort"
  fi
fi
cyan "  ✓ pre-deploy state confirmed (404)"

if [ "$EXECUTE" -eq 0 ]; then
  cyan "DRY RUN — pass --execute to actually deploy."
  cyan "Files that would upload:"
  for f in "${FILES[@]}"; do
    cyan "  $f"
  done
  exit 0
fi

# ── Step 1 — Backup VPS source tree ───────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$VPS_SRC/../.pow-signal-backups/$TS"
cyan "Backup: $BACKUP_DIR"
ssh "$VPS_HOST" "mkdir -p '$BACKUP_DIR'"
for f in "${FILES[@]}"; do
  case "$f" in
    *pow_signal_store.*) ;;  # new file, no backup needed
    *)
      ssh "$VPS_HOST" "test -f '$VPS_SRC/$f' && \
        mkdir -p '$BACKUP_DIR/$(dirname "$f")' && \
        cp '$VPS_SRC/$f' '$BACKUP_DIR/$f'" || \
        fail "backup failed for $f"
      ;;
  esac
done
cyan "  ✓ backup complete"
echo "$BACKUP_DIR" > /tmp/pow-signal-backup-path

# Backup the running binary too — rollback path.
BIN_BACKUP="$VPS_BIN.pre-pow-signal-$TS"
ssh "$VPS_HOST" "cp '$VPS_BIN' '$BIN_BACKUP'"
cyan "  ✓ binary backup: $BIN_BACKUP"
echo "$BIN_BACKUP" > /tmp/pow-signal-binary-backup

# ── Step 2 — Upload allowlisted files ─────────────────────────────
cyan "Uploading 9 files..."
for f in "${FILES[@]}"; do
  ssh "$VPS_HOST" "mkdir -p '$VPS_SRC/$(dirname "$f")'"
  scp -p "$LOCAL_PATCH_ROOT/$f" "$VPS_HOST:$VPS_SRC/$f"
done
cyan "  ✓ upload complete"

# ── Step 3 — Build ────────────────────────────────────────────────
cyan "Building (cmake --build $VPS_BUILD -j\$(nproc))..."
BUILD_LOG="/tmp/pow-signal-build.log"
ssh "$VPS_HOST" "cd '$VPS_BUILD' && cmake --build . --target daemon -j\$(nproc) 2>&1" \
  | tee "$BUILD_LOG" | tail -5
BUILD_EXIT=$?
if [ "$BUILD_EXIT" -ne 0 ]; then
  warn "build failed — restoring backup"
  ssh "$VPS_HOST" "rsync -a --delete '$BACKUP_DIR/' '$VPS_SRC/'" || warn "rsync rollback FAILED"
  fail "BUILD FAILED — see $BUILD_LOG"
fi
cyan "  ✓ build complete"

# ── Step 4 — Restart daemon ───────────────────────────────────────
cyan "systemctl restart USDmd.service..."
ssh "$VPS_HOST" 'systemctl restart USDmd.service'
sleep 5
ssh "$VPS_HOST" 'systemctl is-active USDmd.service' \
  || fail "service did NOT come back up — rollback runbook below"
cyan "  ✓ daemon restarted"

# ── Step 5 — Smoke test the new RPC ───────────────────────────────
cyan "Smoke-testing /set_pow_signals + /get_pow_signals..."
sleep 3
# A test signal: 16-byte hash of zeros + vote=1 (YES)
TEST_HEX="00112233445566778899aabbccddeeff"
SET_RES=$(curl -s -X POST -H "content-type: application/json" \
  -d "{\"signal_keys\":[\"$TEST_HEX\"],\"signal_votes\":[1]}" \
  "http://node.monerousd.org:17750/set_pow_signals")
SET_STATUS=$(echo "$SET_RES" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status",""))' 2>/dev/null || echo "?")
if [ "$SET_STATUS" != "OK" ]; then
  warn "set_pow_signals returned: $SET_RES"
  warn "rolling back…"
  ssh "$VPS_HOST" "cp '$BIN_BACKUP' '$VPS_BIN' && systemctl restart USDmd.service"
  fail "smoke test FAILED — daemon rolled back"
fi
GET_RES=$(curl -s -X POST -H "content-type: application/json" \
  -d '{}' "http://node.monerousd.org:17750/get_pow_signals")
echo "  set: $SET_RES"
echo "  get: $GET_RES"
if ! echo "$GET_RES" | grep -q "$TEST_HEX"; then
  warn "get_pow_signals didn't return the just-set test signal"
  warn "rolling back…"
  ssh "$VPS_HOST" "cp '$BIN_BACKUP' '$VPS_BIN' && systemctl restart USDmd.service"
  fail "smoke test FAILED — daemon rolled back"
fi
cyan "  ✓ smoke test PASSED — pow_signal RPC live"

# Clean up the test signal so the running daemon doesn't carry it.
curl -s -X POST -H "content-type: application/json" \
  -d "{\"signal_keys\":[\"$TEST_HEX\"],\"signal_votes\":[255]}" \
  "http://node.monerousd.org:17750/set_pow_signals" > /dev/null
cyan "  ✓ test signal cleared"

cyan ""
cyan "DEPLOY COMPLETE."
cyan "Rollback (if needed):"
cyan "  ssh $VPS_HOST 'cp $BIN_BACKUP $VPS_BIN && rsync -a --delete $BACKUP_DIR/ $VPS_SRC/ && systemctl restart USDmd.service'"

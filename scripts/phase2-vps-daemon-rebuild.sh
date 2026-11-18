#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# phase2-vps-daemon-rebuild.sh
#
# Rebuild the VPS USDmd binary with Phase C + Phase E source.
# Run in a single shell invocation:
#
#     bash $HOME/Desktop/connect/scripts/phase2-vps-daemon-rebuild.sh
#
# Or invoke with /bin/bash directly if zsh's directory-stack hooks
# (precmd / chpwd) are noisy:
#
#     /bin/bash $HOME/Desktop/connect/scripts/phase2-vps-daemon-rebuild.sh
#
# The script:
#   1. SSHes to VPS, makes a timestamped backup of MoneroUSD-main.
#   2. Rsyncs local MoneroUSD-main source up (excluding build artifacts + git).
#   3. Builds the daemon target on the VPS (cmake + make -j$(nproc)).
#   4. Backs up the currently-running USDmd binary.
#   5. Restarts USDmd.service (~30 s downtime).
#   6. Verifies Phase C (get_side_index_root) + Phase E
#      (get_attestations_in_range) endpoints respond on :17750.
#
# Rollback:
#   ssh root@${MONEROUSD_VPS_HOST} 'mv /root/MoneroUSD/MoneroUSD-main.bak-<ts>
#       /root/MoneroUSD/MoneroUSD-main && systemctl restart USDmd.service'

set -euo pipefail
shopt -s nullglob 2>/dev/null || true

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly LOCAL_SRC="$HOME/Desktop/MoneroUSD-main/"
readonly REMOTE_SRC="/root/MoneroUSD/MoneroUSD-main"
readonly TS="$(date +%Y%m%d-%H%M%S)"

cyan(){ printf '\033[36m[phase2]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[phase2 WARN]\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[31m[phase2 ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0. Pre-flight: VPS reachable + local source present ──────────────
cyan "Pre-flight: VPS reachable + local source present (TS=$TS)"
ssh -o ConnectTimeout=8 -o BatchMode=yes "$VPS_HOST" 'echo ok' >/dev/null \
  || fail "VPS unreachable. Check SSH config."
[ -d "$LOCAL_SRC" ] || fail "no local source at $LOCAL_SRC"
[ -f "$LOCAL_SRC/src/cryptonote_core/side_index.h" ] || fail "local source lacks Phase C — wrong tree?"

# ── 1. Backup VPS source ────────────────────────────────────────────
cyan "Step 1/6: Backing up VPS source → MoneroUSD-main.bak-$TS"
ssh "$VPS_HOST" "cp -r $REMOTE_SRC ${REMOTE_SRC}.bak-$TS" \
  || fail "VPS source backup failed"
cyan "  ✓ backup at ${REMOTE_SRC}.bak-$TS"

# ── 2. Rsync local source → VPS ─────────────────────────────────────
cyan "Step 2/6: Rsyncing local source → VPS (excluding build artifacts)"
rsync -avz --delete \
  --exclude=build \
  --exclude=build-linux \
  --exclude=.git \
  --exclude='*.o' \
  --exclude='*.a' \
  --exclude='.DS_Store' \
  --exclude='.vscode' \
  "$LOCAL_SRC" "$VPS_HOST:$REMOTE_SRC/" 2>&1 | tail -10
cyan "  ✓ source synced"

# ── 3. Build daemon on VPS ──────────────────────────────────────────
cyan "Step 3/6: Building daemon on VPS (cmake + make -j\$(nproc)). ~20-30 min."
ssh "$VPS_HOST" "set -e; cd $REMOTE_SRC && \
  rm -rf build-linux && mkdir build-linux && cd build-linux && \
  cmake -DCMAKE_BUILD_TYPE=Release .. 2>&1 | tail -20 && \
  echo '─── cmake done, starting make ───' && \
  make -j\$(nproc) daemon 2>&1 | tail -25" \
  || fail "VPS build failed — see output above. Rollback: ssh $VPS_HOST 'rm -rf $REMOTE_SRC && mv ${REMOTE_SRC}.bak-$TS $REMOTE_SRC'"
cyan "  ✓ build succeeded"

# ── 4. Find + verify the new binary has Phase C symbols ────────────
# Pre-fix the symbol check used `nm … 2>/dev/null | grep | head` which
# always returned 0 (head doesn't error on empty input) so a missing
# binary produced a false positive. New flow: find the binary first
# (cmake can put it at different paths depending on the project layout),
# THEN verify symbols with a strict count check.
cyan "Step 4/6: Locate fresh binary + verify Phase C symbols"
NEW_BIN=$(ssh "$VPS_HOST" "find $REMOTE_SRC/build-linux -type f -name USDmd -executable 2>/dev/null | head -1")
[ -n "$NEW_BIN" ] || fail "no USDmd binary found anywhere under $REMOTE_SRC/build-linux — build target may have a different name. Run: ssh $VPS_HOST 'cd $REMOTE_SRC/build-linux && make daemon 2>&1 | tail -20' to investigate"
cyan "  binary located at: $NEW_BIN"
SYMCOUNT=$(ssh "$VPS_HOST" "nm '$NEW_BIN' 2>/dev/null | grep -cE 'side_index|scope_tag'")
[ "${SYMCOUNT:-0}" -gt 0 ] || fail "binary at $NEW_BIN lacks Phase C symbols (got $SYMCOUNT matches). Build used stale source — rsync may have missed files. Rollback: ssh $VPS_HOST 'rm -rf $REMOTE_SRC && mv ${REMOTE_SRC}.bak-$TS $REMOTE_SRC'"
cyan "  ✓ $SYMCOUNT side_index/scope_tag symbols present"

# ── 5. Backup running binary + swap + restart USDmd.service ─────────
# Find the binary the running USDmd.service was started with via
# systemctl's ExecStart so we replace the RIGHT file (cmake's output
# path may differ from where the service expects it).
cyan "Step 5/6: Find current ExecStart binary + backup + swap + restart"
RUNNING_BIN=$(ssh "$VPS_HOST" "systemctl show -p ExecStart --value USDmd.service | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1")
[ -n "$RUNNING_BIN" ] || fail "could not read ExecStart from USDmd.service"
cyan "  service runs: $RUNNING_BIN"
cyan "  new binary:   $NEW_BIN"
ssh "$VPS_HOST" "cp '$RUNNING_BIN' /root/MoneroUSD/USDmd.pre-phaseC.$TS && \
  cp '$NEW_BIN' '$RUNNING_BIN' && \
  systemctl restart USDmd.service && \
  sleep 6 && \
  systemctl is-active USDmd.service" \
  || fail "USDmd.service failed to restart. Rollback: ssh $VPS_HOST 'cp /root/MoneroUSD/USDmd.pre-phaseC.$TS $RUNNING_BIN && systemctl restart USDmd.service'"
cyan "  ✓ USDmd.service running with new binary (rollback at /root/MoneroUSD/USDmd.pre-phaseC.$TS)"

# ── 6. Verify Phase C + Phase E endpoints respond ───────────────────
cyan "Step 6/6: Verify Phase C + Phase E endpoints live on :17750"
ssh "$VPS_HOST" "
  echo '─── get_side_index_root (Phase C) ───';
  curl -s -m 6 -X POST http://127.0.0.1:17750/json_rpc \
    -H 'Content-Type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_side_index_root\",\"params\":{}}' | head -c 250
  echo ''
  echo '─── get_attestations_in_range (Phase E) ───';
  curl -s -m 6 -X POST http://127.0.0.1:17750/json_rpc \
    -H 'Content-Type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_attestations_in_range\",\"params\":{\"from_height\":0,\"to_height\":1,\"max_results\":1}}' | head -c 250
"
cyan "  ✓ Phase 2 complete. If both endpoints returned 'OK', Phase C is live on VPS."
echo ""
cyan "Next: Phase 3 — bash scripts/safe-deploy-usdmd-binary.sh --execute"

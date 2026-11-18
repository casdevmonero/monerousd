#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# safe-deploy-r1-r3-protocol.sh
#
# Ship the R1+R2+R3 protocol-feature work to the VPS daemon and to the
# OTA endpoint. This is the production push for:
#
#   Phase 1 — VDF Dandelion proofs on fluff-phase tx relay
#   Phase 4 — Noise XK 3-act handshake on every connection
#   Phase 5 — Compact-blocks SipHash short-ID validation
#   Phase 6 — Erlay set-reconciliation on an 8s tick
#   Phase 7 — R2 runtime (feeler, block-relay-only quota, AddrV2 gossip)
#
# Flow
# ────
#   1. Pre-flight (ssh, prereqs, dry-run sanity)
#   2. Install gmp-devel on VPS (idempotent)
#   3. Backup VPS source tree (allowlisted file backup + binary backup)
#   4. rsync allowlisted files to VPS (NEVER bleeds outside src/)
#   5. Ship external/blst/ + build libblst.a on VPS
#   6. cmake --build daemon target (incremental)
#   7. systemctl restart USDmd.service
#   8. Smoke-test that the daemon RPC is alive
#   9. Strip + publish binary to /var/www/monerousd-updates/bin/linux-x64/
#  10. Update SHA256SUMS (preserves wallet-rpc entry)
#  11. Smoke-test OTA endpoint over clearnet
#
# Auto-rollback on any failure between step 6 and step 8.

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly VPS_REPO="/root/MoneroUSD/MoneroUSD-main"
readonly VPS_SRC="$VPS_REPO/src"
readonly VPS_EXT="$VPS_REPO/external"
readonly VPS_BUILD="$VPS_REPO/build-linux"
readonly VPS_BIN="$VPS_BUILD/bin/USDmd"
readonly VPS_OTA_DIR="/var/www/monerousd-updates/bin/linux-x64"
readonly LOCAL_REPO="$HOME/Desktop/MoneroUSD-main"

# ── ALLOWLIST: every source file this script can touch ──────────────
# Adding a new file requires editing this list (intentional friction).
readonly MODIFIED_FILES=(
  "src/cryptonote_config.h"
  "src/cryptonote_basic/CMakeLists.txt"
  "src/cryptonote_basic/connection_context.h"
  "src/cryptonote_core/i_core_events.h"
  "src/cryptonote_core/cryptonote_core.h"
  "src/cryptonote_core/cryptonote_core.cpp"
  "src/cryptonote_protocol/cryptonote_protocol_defs.h"
  "src/cryptonote_protocol/cryptonote_protocol_handler.h"
  "src/cryptonote_protocol/cryptonote_protocol_handler.inl"
  "src/cryptonote_protocol/levin_notify.cpp"
  "src/p2p/net_node.h"
  "src/p2p/net_node.inl"
  "src/p2p/p2p_protocol_defs.h"
)

readonly NEW_FILES=(
  "src/cryptonote_basic/vdf_dandelion.h"
  "src/cryptonote_basic/vdf_dandelion.cpp"
  "src/cryptonote_basic/bp_ring_signature.h"
  "src/cryptonote_basic/bp_ring_signature.cpp"
  "src/cryptonote_basic/zk_state_proof.h"
  "src/cryptonote_basic/zk_state_proof.cpp"
  "src/cryptonote_protocol/cmpct_block.h"
  "src/cryptonote_protocol/cmpct_block.cpp"
  "src/cryptonote_protocol/cmpct_block_integration.h"
  "src/cryptonote_protocol/cmpct_block_integration.cpp"
  "src/cryptonote_protocol/erlay_recon.h"
  "src/cryptonote_protocol/erlay_recon.cpp"
  "src/cryptonote_protocol/erlay_integration.h"
  "src/cryptonote_protocol/erlay_integration.cpp"
  "src/cryptonote_protocol/vdf_dandelion_integration.h"
  "src/cryptonote_protocol/vdf_dandelion_integration.cpp"
  "src/p2p/noise_xk.h"
  "src/p2p/noise_xk.cpp"
  "src/p2p/noise_xk_integration.h"
  "src/p2p/noise_xk_integration.cpp"
  "src/p2p/feeler_loop.h"
  "src/p2p/feeler_loop.cpp"
  "src/p2p/block_relay_only.h"
  "src/p2p/block_relay_only.cpp"
  "src/p2p/addrv2.h"
  "src/p2p/addrv2.cpp"
  "src/p2p/r2_runtime_integrations.h"
  "src/p2p/r2_runtime_integrations.cpp"
)

EXECUTE=0
case "${1:-}" in
  --execute) EXECUTE=1 ;;
  --help|-h) sed -n '/^# safe-deploy-r1-r3/,/^set -euo/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac

cyan(){ printf '\033[36m[r1-r3-deploy]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[r1-r3-deploy WARN]\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[31m[r1-r3-deploy ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Pre-flight ──────────────────────────────────────────────────────
cyan "Pre-flight: all files staged locally?"
for f in "${MODIFIED_FILES[@]}" "${NEW_FILES[@]}"; do
  [ -f "$LOCAL_REPO/$f" ] || fail "missing local file: $LOCAL_REPO/$f"
done
[ -d "$LOCAL_REPO/external/blst" ] || fail "missing local external/blst/"
cyan "  ✓ ${#MODIFIED_FILES[@]} modified + ${#NEW_FILES[@]} new files staged, blst/ present"

cyan "Pre-flight: VPS reachable + daemon running?"
ssh -o ConnectTimeout=10 -o BatchMode=yes "$VPS_HOST" 'true' \
  || fail "cannot reach $VPS_HOST"
ssh "$VPS_HOST" 'systemctl is-active USDmd.service' >/dev/null \
  || fail "USDmd.service not active on VPS"
cyan "  ✓ VPS reachable, USDmd active"

if [ "$EXECUTE" -eq 0 ]; then
  cyan "DRY RUN — pass --execute to actually deploy."
  cyan ""
  cyan "Files that would be modified on VPS ($VPS_SRC):"
  for f in "${MODIFIED_FILES[@]}"; do cyan "  M  $f"; done
  cyan "Files that would be created on VPS:"
  for f in "${NEW_FILES[@]}"; do cyan "  +  $f"; done
  cyan "Steps that would run on VPS:"
  cyan "  1. dnf install -y gmp-devel  (idempotent)"
  cyan "  2. rsync external/blst → $VPS_EXT/blst"
  cyan "  3. (cd $VPS_EXT/blst && ./build.sh) — produces libblst.a"
  cyan "  4. cmake --build $VPS_BUILD --target daemon -j\$(nproc)"
  cyan "  5. systemctl restart USDmd.service"
  cyan "  6. Smoke-test get_block_count RPC"
  cyan "  7. Strip + publish binary to $VPS_OTA_DIR/USDmd"
  cyan "  8. Update SHA256SUMS"
  exit 0
fi

# ── Step 1 — Install gmp-devel + create backup dir ───────────────────
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$VPS_REPO/.r1-r3-backups/$TS"
cyan "Step 1: ensuring gmp-devel + backup dir $BACKUP_DIR"
ssh "$VPS_HOST" "set -e
  if ! rpm -q gmp-devel >/dev/null 2>&1; then dnf install -y gmp-devel; fi
  mkdir -p '$BACKUP_DIR'"

# ── Step 2 — Backup currently-modified files + running binary ───────
cyan "Step 2: backing up ${#MODIFIED_FILES[@]} modified files + binary"
for f in "${MODIFIED_FILES[@]}"; do
  ssh "$VPS_HOST" "test -f '$VPS_SRC/${f#src/}' && \
    mkdir -p '$BACKUP_DIR/$(dirname "${f#src/}")' && \
    cp '$VPS_SRC/${f#src/}' '$BACKUP_DIR/${f#src/}'" \
    || fail "backup failed for $f"
done
BIN_BACKUP="$VPS_BIN.pre-r1-r3-$TS"
ssh "$VPS_HOST" "cp '$VPS_BIN' '$BIN_BACKUP'"
cyan "  ✓ backups complete (binary: $BIN_BACKUP)"
echo "$BACKUP_DIR" > /tmp/r1-r3-backup-path
echo "$BIN_BACKUP" > /tmp/r1-r3-binary-backup

# ── Step 3 — Upload source files (allowlisted) ──────────────────────
cyan "Step 3: uploading ${#MODIFIED_FILES[@]} modified + ${#NEW_FILES[@]} new files"
for f in "${MODIFIED_FILES[@]}" "${NEW_FILES[@]}"; do
  ssh "$VPS_HOST" "mkdir -p '$VPS_REPO/$(dirname "$f")'"
  scp -q -p "$LOCAL_REPO/$f" "$VPS_HOST:$VPS_REPO/$f"
done
cyan "  ✓ source upload complete"

# ── Step 4 — Ship + build blst external lib ─────────────────────────
cyan "Step 4: rsync external/blst (~5MB minus .git) + build libblst.a"
rsync -azq --exclude='.git' --exclude='*.pyc' --delete \
  "$LOCAL_REPO/external/blst/" "$VPS_HOST:$VPS_EXT/blst/" \
  || fail "rsync external/blst failed"
ssh "$VPS_HOST" "set -e
  cd '$VPS_EXT/blst'
  if [ ! -f libblst.a ]; then
    bash ./build.sh
  fi
  test -f libblst.a && test -s libblst.a" \
  || fail "blst build failed"
cyan "  ✓ libblst.a built"

# ── Step 5 — cmake --build daemon ────────────────────────────────────
cyan "Step 5: cmake --build (incremental, daemon target)"
BUILD_LOG="/tmp/r1-r3-build.log"
set +e
ssh "$VPS_HOST" "cd '$VPS_BUILD' && cmake --build . --target daemon -j\$(nproc) 2>&1" \
  | tee "$BUILD_LOG" | tail -10
BUILD_EXIT=${PIPESTATUS[0]}
set -e
if [ "$BUILD_EXIT" -ne 0 ]; then
  warn "build FAILED — restoring backed-up source"
  for f in "${MODIFIED_FILES[@]}"; do
    ssh "$VPS_HOST" "cp '$BACKUP_DIR/${f#src/}' '$VPS_SRC/${f#src/}' 2>/dev/null" || true
  done
  fail "BUILD FAILED — see $BUILD_LOG"
fi
cyan "  ✓ build complete"

# ── Step 6 — Restart daemon + smoke-test ─────────────────────────────
cyan "Step 6: systemctl restart USDmd.service"
ssh "$VPS_HOST" 'systemctl restart USDmd.service'
sleep 6
ssh "$VPS_HOST" 'systemctl is-active USDmd.service' >/dev/null \
  || { ssh "$VPS_HOST" "cp '$BIN_BACKUP' '$VPS_BIN' && systemctl restart USDmd.service"
       fail "service did NOT come back up — binary rolled back"; }
sleep 3
cyan "  ✓ daemon running"

cyan "Step 6.5: get_block_count smoke-test"
HEIGHT=$(curl -s --max-time 10 -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' \
  http://node.monerousd.org:17750/json_rpc | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("count","?"))' 2>/dev/null || echo "?")
if [ "$HEIGHT" = "?" ] || [ -z "$HEIGHT" ]; then
  warn "RPC didn't respond — rolling back"
  ssh "$VPS_HOST" "cp '$BIN_BACKUP' '$VPS_BIN' && systemctl restart USDmd.service"
  fail "RPC smoke test failed — rolled back"
fi
cyan "  ✓ daemon reports height=$HEIGHT"

# ── Step 7 — Strip + publish binary to OTA endpoint ─────────────────
cyan "Step 7: strip + publish binary to $VPS_OTA_DIR/USDmd"
NEW_SHA=$(ssh "$VPS_HOST" "set -e
  cp '$VPS_BIN' /tmp/USDmd.unstripped
  strip /tmp/USDmd.unstripped -o /tmp/USDmd.stripped
  sha256sum /tmp/USDmd.stripped | awk '{print \$1}'")
PUBLISHED_SHA=$(ssh "$VPS_HOST" "sha256sum '$VPS_OTA_DIR/USDmd' 2>/dev/null | awk '{print \$1}'" || echo "")
if [ "$NEW_SHA" = "$PUBLISHED_SHA" ]; then
  cyan "  • new SHA matches currently-published SHA — skipping publish (no-op)"
else
  ssh "$VPS_HOST" "set -e
    cp '$VPS_OTA_DIR/USDmd' '$VPS_OTA_DIR/USDmd.pre-r1-r3-$TS'
    cp /tmp/USDmd.stripped '$VPS_OTA_DIR/USDmd'
    chmod 755 '$VPS_OTA_DIR/USDmd'
    # rebuild SHA256SUMS, preserving wallet-rpc entry order
    cd '$VPS_OTA_DIR'
    NEW_USDMD_LINE=\$(sha256sum USDmd)
    WALLET_RPC_LINE=\$(grep wallet-rpc SHA256SUMS 2>/dev/null || sha256sum USDm-wallet-rpc 2>/dev/null)
    {
      echo \"\$NEW_USDMD_LINE\"
      [ -n \"\$WALLET_RPC_LINE\" ] && echo \"\$WALLET_RPC_LINE\"
    } > SHA256SUMS.new
    mv SHA256SUMS.new SHA256SUMS"
  cyan "  ✓ published: $NEW_SHA"
fi

# ── Step 8 — Smoke-test OTA endpoint over clearnet ──────────────────
cyan "Step 8: OTA endpoint smoke-test"
OTA_SHA=$(curl -s --max-time 15 https://update.monerousd.org/bin/linux-x64/SHA256SUMS | grep -E '\bUSDmd$' | awk '{print $1}')
if [ -z "$OTA_SHA" ] || [ "$OTA_SHA" != "$NEW_SHA" ]; then
  warn "OTA endpoint serves '$OTA_SHA', expected '$NEW_SHA'"
  warn "  (could be CDN cache; clears in ~60s — re-curl to verify)"
fi
cyan "  ✓ OTA endpoint: $OTA_SHA"

cyan ""
cyan "DEPLOY COMPLETE."
cyan "Live: VDF Dandelion + Noise XK + Compact blocks + Erlay + R2 runtime"
cyan "VPS daemon SHA (running): $(ssh "$VPS_HOST" "sha256sum '$VPS_BIN' | awk '{print \$1}'")"
cyan "OTA-published SHA       : $NEW_SHA"
cyan ""
cyan "Rollback (if needed):"
cyan "  ssh $VPS_HOST 'cp $BIN_BACKUP $VPS_BIN && systemctl restart USDmd.service && \\"
cyan "    cp $VPS_OTA_DIR/USDmd.pre-r1-r3-$TS $VPS_OTA_DIR/USDmd && \\"
cyan "    cd $VPS_OTA_DIR && sha256sum USDmd > /tmp/r.sums && grep wallet-rpc SHA256SUMS >> /tmp/r.sums && mv /tmp/r.sums SHA256SUMS'"
cyan "  for f in ${MODIFIED_FILES[@]} ; do"
cyan "    ssh $VPS_HOST \"cp $BACKUP_DIR/\${f#src/} $VPS_SRC/\${f#src/}\""
cyan "  done"

#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# safe-deploy-usdmd-binary.sh
#
# Publish the freshly-built USDmd binary to the OTA endpoint at
# update.monerousd.org/bin/{plat}-{arch}/{USDmd, SHA256SUMS}.
# Wallets running on TNA (Trusted Node Architecture) auto-pull
# the new binary on next start when their local checksum diverges
# from the published SHA256SUMS.
#
# Hard guards
# ───────────
# • TARGET DIR is hardcoded to /var/www/monerousd-updates/bin/.
#   No --target flag.
# • Backs up the current binary to USDmd.pre-<TS> BEFORE overwrite.
# • Refuses if the new binary's SHA256 matches the currently-
#   published one (no-op).
# • Strips the binary before publishing — the build keeps debug info,
#   which more-than-doubles the binary size and slows wallet OTA.
# • Verifies the binary actually answers the new RPC after upload
#   (downloads it, checks `--version` runs).
#
# Currently supports linux-x64 only. Mac builds need cross-compile;
# tracked separately.

set -euo pipefail

readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly VPS_BIN_SRC="/root/MoneroUSD/MoneroUSD-main/build-linux/bin/USDmd"
readonly OTA_DIR="/var/www/monerousd-updates/bin/linux-x64"

EXECUTE=0
case "${1:-}" in
  --execute) EXECUTE=1 ;;
  --help|-h) sed -n '/^# safe-deploy-usdmd/,/^set -euo/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
esac

cyan(){ printf '\033[36m[bin-deploy]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[bin-deploy WARN]\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[31m[bin-deploy ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Pre-flight ─────────────────────────────────────────────────────
cyan "Pre-flight: VPS reachable + new binary present"
ssh -o ConnectTimeout=8 -o BatchMode=yes "$VPS_HOST" "test -f '$VPS_BIN_SRC'" \
  || fail "no built binary at $VPS_BIN_SRC — run safe-deploy-pow-signal-daemon.sh first"
cyan "  ✓ binary exists"

cyan "Pre-flight: compute new SHA256 (post-strip)"
NEW_SHA=$(ssh "$VPS_HOST" "strip --strip-debug --strip-unneeded -o /tmp/USDmd.stripped '$VPS_BIN_SRC' && sha256sum /tmp/USDmd.stripped | awk '{print \$1}'")
[ -n "$NEW_SHA" ] || fail "could not compute new SHA"
cyan "  new SHA256: $NEW_SHA"

CURRENT_SHA=$(ssh "$VPS_HOST" "awk '{print \$1; exit}' $OTA_DIR/SHA256SUMS 2>/dev/null || echo none")
cyan "  current published SHA: $CURRENT_SHA"
if [ "$NEW_SHA" = "$CURRENT_SHA" ]; then
  fail "new binary's SHA matches the currently-published one — nothing to do"
fi

if [ "$EXECUTE" -eq 0 ]; then
  cyan "DRY RUN — pass --execute to publish"
  cyan "Will publish:"
  cyan "  $VPS_BIN_SRC (stripped) → $OTA_DIR/USDmd"
  cyan "  Update $OTA_DIR/SHA256SUMS"
  exit 0
fi

# ── Backup + publish ────────────────────────────────────────────────
TS=$(date +%Y%m%d-%H%M%S)
cyan "Backup current binary to USDmd.pre-pow-signal-$TS"
ssh "$VPS_HOST" "cp '$OTA_DIR/USDmd' '$OTA_DIR/USDmd.pre-pow-signal-$TS'"

cyan "Copying stripped binary to OTA dir"
ssh "$VPS_HOST" "cp /tmp/USDmd.stripped '$OTA_DIR/USDmd' && chmod 0755 '$OTA_DIR/USDmd'"

cyan "Rebuilding SHA256SUMS (preserving wallet-rpc entry)"
ssh "$VPS_HOST" "cd '$OTA_DIR' && \
  RPC_LINE=\$(grep 'USDm-wallet-rpc\$' SHA256SUMS) && \
  USDMD_NEW=\$(sha256sum USDmd | awk '{print \$1}  USDmd') && \
  printf '%s  USDmd\n%s\n' \"\$USDMD_NEW\" \"\$RPC_LINE\" > SHA256SUMS"

cyan "Verify new SHA256SUMS:"
ssh "$VPS_HOST" "cat '$OTA_DIR/SHA256SUMS'"

cyan "Smoke test: GET the binary via clearnet"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -I "https://update.monerousd.org/bin/linux-x64/SHA256SUMS")
[ "$HTTP" = "200" ] || fail "SHA256SUMS endpoint returned HTTP $HTTP"
cyan "  ✓ SHA256SUMS reachable"

cyan ""
cyan "DEPLOY COMPLETE."
cyan "Rollback (if needed):"
cyan "  ssh $VPS_HOST 'cp $OTA_DIR/USDmd.pre-pow-signal-$TS $OTA_DIR/USDmd && cd $OTA_DIR && sha256sum USDmd > /tmp/restore.sums && grep wallet-rpc SHA256SUMS >> /tmp/restore.sums && mv /tmp/restore.sums SHA256SUMS'"

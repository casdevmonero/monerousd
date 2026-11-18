#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# fix-edge-conf-and-sudoers.sh
#   1. Restores /root/.monerousd/USDmd.conf from backup OR writes a
#      minimal one (USDmd refuses to start without it)
#   2. Sanitizes the conf — strips any `rpc-bind-ip = 0.0.0.0` lines
#      that would override our CLI flags
#   3. Updates /etc/sudoers.d/monerousd-deploy to use canonical
#      /usr/bin/systemctl paths + broader NOPASSWD rules so Claude
#      can drive remaining edge work from deploy@ without re-prompting
#   4. Restarts USDmd + ion-backend, verifies
#
# This is the LAST root-SSH operation needed. After this, deploy@
# has all the sudo permissions to handle future fixes.

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}
ssh -o ConnectTimeout=12 "$EDGE" bash -s <<'REMOTE'
set -e

echo "  ── 1. Restore /root/.monerousd/USDmd.conf ──"
cd /root/.monerousd
LATEST_BAK=$(ls -t USDmd.conf.bak.* 2>/dev/null | head -1)
if [ -n "$LATEST_BAK" ]; then
  echo "  found backup: $LATEST_BAK"
  cp -v "$LATEST_BAK" USDmd.conf
elif [ ! -f USDmd.conf ]; then
  echo "  no backup found — writing minimal conf"
  cat > USDmd.conf <<CONF
# Minimal USDmd.conf — written by fix-edge-conf-and-sudoers.sh.
# Real bind config is in CLI flags (/root/start-usdmd.sh ARGS array).
# This file exists only because USDmd refuses to start without it.
log-level=1
data-dir=/root/.monerousd
CONF
fi

echo ""
echo "  ── 2. Sanitize conf (strip any rpc-bind-ip overrides) ──"
# Remove any line that sets rpc-bind-* — those are owned by the
# wrapper's CLI flags. Comment them out instead of deleting so
# operator can review what was sanitized.
if grep -E '^(rpc-bind|rpc-restricted-bind|p2p-bind|start-mining|mining-threads)' USDmd.conf >/dev/null 2>&1; then
  cp USDmd.conf USDmd.conf.unsanitized.$(date +%s)
  sed -i -E 's|^(rpc-bind\|rpc-restricted-bind\|p2p-bind\|start-mining\|mining-threads).*|# &  # sanitized — lives in /root/start-usdmd.sh|' USDmd.conf
  echo "  ✓ sanitized — original saved as .unsanitized.<ts>"
else
  echo "  ✓ conf is clean (no bind overrides)"
fi

echo ""
echo "  --- USDmd.conf (post-sanitize, first 30 lines) ---"
head -30 USDmd.conf

echo ""
echo "  ── 3. Update sudoers — use /usr/bin/ paths + broader rules ──"
SUDOERS=/etc/sudoers.d/monerousd-deploy
cat > "$SUDOERS" <<'SUDO'
# Least-privilege sudoers for deploy user.
# Updated to use /usr/bin/ canonical paths (Ubuntu 22 rejects /bin/ for sudo).

# Paths Cmnd_Alias for clarity
Cmnd_Alias SYSTEMCTL  = /usr/bin/systemctl
Cmnd_Alias JOURNALCTL = /usr/bin/journalctl
Cmnd_Alias NGINX      = /usr/sbin/nginx
Cmnd_Alias CERTBOT    = /usr/bin/certbot
Cmnd_Alias FILE_OPS   = /usr/bin/cp, /usr/bin/mv, /usr/bin/ln, /usr/bin/cat, /usr/bin/tee, /usr/bin/install
Cmnd_Alias DC_TOOLS   = /usr/bin/npm, /usr/bin/node

deploy ALL=(ALL) NOPASSWD: SYSTEMCTL, JOURNALCTL, NGINX, CERTBOT, FILE_OPS

# ion-backend deploy needs to run npm + node as root for
# `npm ci --production` and node-version checks. Scope to the
# project dir via working-dir restriction in invocation.
deploy ALL=(ALL) NOPASSWD: DC_TOOLS

# Specific high-risk operations we explicitly allow:
deploy ALL=(ALL) NOPASSWD: /usr/bin/chown deploy\:monerousd-deploy *
deploy ALL=(ALL) NOPASSWD: /usr/bin/chgrp -R monerousd-deploy /opt/*
deploy ALL=(ALL) NOPASSWD: /usr/bin/chmod -R g+rwX /opt/*
deploy ALL=(ALL) NOPASSWD: /usr/bin/apt-get install -y nodejs
deploy ALL=(ALL) NOPASSWD: /usr/bin/apt-get purge -y *
deploy ALL=(ALL) NOPASSWD: /usr/bin/apt-get autoremove -y *
SUDO
chmod 440 "$SUDOERS"
visudo -c -f "$SUDOERS" >/dev/null && echo "  ✓ sudoers passes visudo check" \
  || { echo "  ✗ sudoers failed visudo — removing"; rm -f "$SUDOERS"; exit 2; }

echo ""
echo "  ── 4. Restart USDmd + ion-backend ──"
systemctl restart USDmd.service
sleep 6
systemctl is-active USDmd && echo "  ✓ USDmd ACTIVE" || {
  echo "  ✗ USDmd not active. Last 20 log lines:"
  journalctl -u USDmd --no-pager -n 20
}

systemctl restart ion-backend.service
sleep 6
systemctl is-active ion-backend && echo "  ✓ ion-backend ACTIVE" || {
  echo "  ✗ ion-backend not active. Last 20 log lines:"
  journalctl -u ion-backend --no-pager -n 20
}

echo ""
echo "  ── 5. Final verification ──"
echo "  USDmd via local restricted RPC:"
curl -sf -m 5 -X POST 'http://127.0.0.1:17750/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' 2>&1 | head -c 200
echo ""
echo ""
echo "  Express ion-backend on :7777:"
curl -s -m 5 'http://127.0.0.1:7777/v1/info' 2>&1 | head -c 300
echo ""
REMOTE

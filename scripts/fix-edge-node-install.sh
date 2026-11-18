#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# fix-edge-node-install.sh
#
# Resolves the Node 20 install failure on the edge:
#   "dpkg: trying to overwrite '/usr/include/node/common.gypi',
#    which is also in package libnode-dev 12.22.9~dfsg-1ubuntu3.6"
#
# Old Ubuntu-distro Node 12 packages (libnode-dev, libnode72, nodejs-doc,
# the dozens of orphaned node-*) collide with the NodeSource Node 20
# .deb. Standard fix: purge the old set, autoremove the orphans, then
# install Node 20 from NodeSource cleanly.
#
# After Node 20 is in: re-run the ion-backend ESM fix + restart.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}

ssh -o ConnectTimeout=12 "$EDGE" bash -s <<'REMOTE'
set -e

echo "  ── 1. purge old Node 12 packages + orphans ──"
# Remove the conflicting old set. -y is OK here because:
#  • libnode-dev 12 is what's blocking the Node 20 install
#  • libnode72 is its companion
#  • nodejs-doc + node-* are orphans from the old Ubuntu Node install
#  • npm itself is a target since the Node 20 .deb bundles its own npm
#
# Use --purge to also blow away configs (we don't keep any).
apt-get purge -y \
  libnode-dev libnode72 nodejs-doc \
  npm node-* 2>&1 | tail -3 || true

# Sweep up the rest of the orphaned node-* and any deps no longer needed
apt-get autoremove -y --purge 2>&1 | tail -3

echo ""
echo "  ── 2. install Node 20 from NodeSource ──"
apt-get install -y nodejs 2>&1 | tail -5

echo ""
echo "  ── 3. verify ──"
NODE_V=$(node --version 2>&1)
NPM_V=$(npm --version 2>&1)
echo "    node:  $NODE_V"
echo "    npm:   $NPM_V"
if [[ "$NODE_V" != v20* && "$NODE_V" != v21* && "$NODE_V" != v22* ]]; then
  echo "  ✗ Node 20+ not active. Manual investigation needed." >&2
  exit 1
fi

echo ""
echo "  ── 4. ion-backend: ensure type:module + npm ci + restart ──"
PKG=/opt/ion-monerousd-org/backend/package.json
if [ -f "$PKG" ]; then
  cp "$PKG" "$PKG.bak.$(date +%s)"
  if ! grep -q '"type"\s*:\s*"module"' "$PKG"; then
    node -e "
      const fs=require('fs');
      const p='$PKG';
      const j=JSON.parse(fs.readFileSync(p,'utf8'));
      j.type='module';
      fs.writeFileSync(p, JSON.stringify(j, null, 2)+'\n');
    "
    echo "    ✓ added 'type': 'module' to package.json"
  else
    echo "    ✓ package.json already has 'type': 'module'"
  fi

  cd /opt/ion-monerousd-org/backend
  echo "    running npm ci (this may take ~60s)..."
  if [ -f package-lock.json ]; then
    npm ci --production 2>&1 | tail -5
  else
    npm install --production 2>&1 | tail -5
  fi
fi

systemctl restart ion-backend.service
sleep 6
if systemctl is-active ion-backend >/dev/null 2>&1; then
  echo "  ✓ ion-backend ACTIVE"
  echo ""
  echo "  --- verify Express is listening on :7777 ---"
  ss -tlnp | grep ':7777' | head -3
  echo ""
  echo "  --- /v1/info via Host: ion.monerousd.org ---"
  curl -s -m 5 -H 'Host: ion.monerousd.org' 'http://127.0.0.1/v1/info' 2>&1 | head -c 400
  echo ""
else
  echo "  ✗ ion-backend NOT active. Last 30 log lines:"
  journalctl -u ion-backend --no-pager -n 30
  exit 2
fi
REMOTE

echo ""
echo "  ── external verification ──"
curl -s -m 8 -H 'Host: ion.monerousd.org' 'http://${MONEROUSD_EDGE_HOST}/v1/info' 2>&1 | head -c 400
echo ""

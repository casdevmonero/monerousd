#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# fix-edge-final.sh
# Final pass: rsync parent package.json, fix systemd WorkingDirectory,
# simplify USDmd wrapper to single-port --restricted-rpc, restart all,
# verify.

set -euo pipefail

EDGE=deploy@${MONEROUSD_EDGE_HOST}

echo "  ── 1. rsync parent package.json + lock ──"
rsync -az \
  $HOME/Desktop/connect/ion-monerousd-org/package.json \
  $HOME/Desktop/connect/ion-monerousd-org/package-lock.json \
  "$EDGE":/opt/ion-monerousd-org/ 2>&1 | tail -5

echo ""
echo "  ── 2. systemd unit + npm install + USDmd wrapper rewrite ──"
ssh "$EDGE" 'bash -s' <<'REMOTE'
set -e

# Systemd unit — WorkingDirectory at parent (where package.json is)
sudo tee /etc/systemd/system/ion-backend.service >/dev/null <<UNIT
[Unit]
Description=Ion Swap backend (Express + indexer)
After=network-online.target USDmd.service
Wants=network-online.target
Requires=USDmd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ion-monerousd-org
ExecStart=/usr/bin/node backend/server.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=7777
Environment=WS_PORT=7778
Environment=USDMD_RPC=http://127.0.0.1:17750
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
echo "  ✓ ion-backend systemd unit updated"

# npm install at parent
cd /opt/ion-monerousd-org
echo ""
echo "  --- ls /opt/ion-monerousd-org/ ---"
ls -la | head -15
echo ""
echo "  --- npm install (production) ---"
sudo npm install --production 2>&1 | tail -10

# USDmd wrapper — simplified single-port + --restricted-rpc model
sudo tee /root/start-usdmd.sh >/dev/null <<'WRAPPER'
#!/bin/bash
# /root/start-usdmd.sh — Edge USDmd launcher (rev 3 — single-port restricted).
# Public RPC on 17750 with admin methods refused via --restricted-rpc.
# No separate full-RPC port; operator uses systemd journal / SSH for admin.
set -e

ARGS=(
  --rpc-bind-ip 0.0.0.0
  --rpc-bind-port 17750
  --restricted-rpc
  --confirm-external-bind
  --p2p-bind-ip 0.0.0.0
  --p2p-bind-port 17749
  --start-mining "MuNn2qjZ5VwVK5VZQazTBS6RQUz9CkyXjciHkQ58PcV6Dahk4V3ScsiWpjLpDFkMPrWVgUBZRif5fU54fNwxxkCuBAHQLhj"
  --mining-threads 2
  --add-peer ${MONEROUSD_VPS_HOST}:17749
  --non-interactive
  --disable-rpc-ban
  --log-level 1
  --log-file /root/.monerousd/monerousd.log
)

exec /root/usdmd-bundle/lib/ld-linux-x86-64.so.2 \
  --library-path /root/usdmd-bundle/lib \
  /root/usdmd-bundle/USDmd \
  "${ARGS[@]}"
WRAPPER
sudo chmod +x /root/start-usdmd.sh
sudo bash -n /root/start-usdmd.sh && echo "  ✓ wrapper syntax OK"

# Restart both services
sudo systemctl restart USDmd
sleep 6
sudo systemctl restart ion-backend
sleep 6

echo ""
echo "  ── final status ──"
sudo systemctl is-active USDmd && echo "  ✓ USDmd ACTIVE" || {
  echo "  ✗ USDmd not active. Last log lines:"
  sudo journalctl -u USDmd --no-pager -n 15
}
sudo systemctl is-active ion-backend && echo "  ✓ ion-backend ACTIVE" || {
  echo "  ✗ ion-backend not active. Last log lines:"
  sudo journalctl -u ion-backend --no-pager -n 15
}

echo ""
echo "  ── port bindings ──"
ss -tlnp 2>/dev/null | grep -E ':7777|:7778|:17749|:17750' | head
REMOTE

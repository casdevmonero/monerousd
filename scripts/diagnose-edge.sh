#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# diagnose-edge.sh — read-only diagnostic; no production writes.
# Gathers everything I'd need to know to figure out why Phase B / C
# didn't take. Paste the full output back into chat.

set -u
EDGE=root@${MONEROUSD_EDGE_HOST}

ssh -o ConnectTimeout=12 "$EDGE" bash -s <<'REMOTE'
echo "════════════════════════════════════════════════"
echo "  USDmd wrapper script (mining + RPC flags)"
echo "════════════════════════════════════════════════"
if [ -f /root/start-usdmd.sh ]; then
  cat /root/start-usdmd.sh | head -40
  echo ""
  echo "  --- backups ---"
  ls -la /root/start-usdmd.sh.bak.* 2>&1 | tail -10
else
  echo "  /root/start-usdmd.sh NOT FOUND"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  USDmd systemd state"
echo "════════════════════════════════════════════════"
systemctl is-active USDmd && echo "  USDmd: ACTIVE" || echo "  USDmd: not active"
echo ""
echo "  --- recent USDmd logs (last 30 lines) ---"
journalctl -u USDmd --since '5 minutes ago' --no-pager | tail -30

echo ""
echo "════════════════════════════════════════════════"
echo "  Mining status (via local full RPC :17751)"
echo "════════════════════════════════════════════════"
curl -sf -m 5 -X POST 'http://127.0.0.1:17751/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"mining_status"}' 2>&1 | head -c 500
echo ""

echo ""
echo "════════════════════════════════════════════════"
echo "  ion-backend service state"
echo "════════════════════════════════════════════════"
if systemctl list-unit-files ion-backend.service >/dev/null 2>&1; then
  systemctl is-active ion-backend && echo "  ion-backend: ACTIVE" || echo "  ion-backend: not active"
  echo ""
  echo "  --- ion-backend recent logs ---"
  journalctl -u ion-backend --since '5 minutes ago' --no-pager | tail -30
else
  echo "  ion-backend.service NOT INSTALLED"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  nginx configs (sites-enabled + relevant snippets)"
echo "════════════════════════════════════════════════"
echo "  --- sites-enabled/ ---"
ls -la /etc/nginx/sites-enabled/ 2>&1
echo ""
echo "  --- ion-monerousd vhost (if exists) ---"
[ -f /etc/nginx/sites-available/ion-monerousd ] && cat /etc/nginx/sites-available/ion-monerousd || echo "  /etc/nginx/sites-available/ion-monerousd NOT FOUND"
echo ""
echo "  --- nginx -t ---"
nginx -t 2>&1
echo ""
echo "  --- which server-block matches Host: ion.monerousd.org ---"
echo "  (the first matching server_name wins)"
grep -r "server_name" /etc/nginx/sites-enabled/ 2>&1 | head -20
echo ""
echo "  --- listing all listen directives ---"
grep -r "listen" /etc/nginx/sites-enabled/ 2>&1 | head -20

echo ""
echo "════════════════════════════════════════════════"
echo "  Express ion-backend listening?"
echo "════════════════════════════════════════════════"
ss -tlnp 2>/dev/null | grep -E ':7777|:7778|:17749|:17750|:17751' | head -10

echo ""
echo "════════════════════════════════════════════════"
echo "  Local probe: ion-backend Express direct (127.0.0.1:7777)"
echo "════════════════════════════════════════════════"
curl -s -m 5 'http://127.0.0.1:7777/v1/info' 2>&1 | head -c 300
echo ""
REMOTE

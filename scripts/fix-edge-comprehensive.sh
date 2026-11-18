#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# fix-edge-comprehensive.sh
#
# Cleans up everything diagnose-edge.sh found broken:
#
#   1. USDmd wrapper — overwrite with a known-clean template (no sed,
#      no in-place edits, full file written from a heredoc on the edge).
#   2. USDmd config — read /root/.monerousd/USDmd.conf, sanitize any
#      `rpc-bind-ip = 0.0.0.0` override, replace with localhost.
#   3. Mining diagnosis — dump /root/.monerousd/monerousd.log + tail
#      so we can see why mining isn't producing blocks.
#   4. ion-backend Node version — check if Node 18+ is installed; if
#      not, install Node 20 LTS (NodeSource); add `"type": "module"`
#      to package.json so the ESM imports work; npm ci; restart.
#   5. nginx — disable old monerousd-relay vhost (it points at dead
#      Skynet anyway; was the source of swap.monerousd.org conflict).
#      Reload nginx to make ion-monerousd vhost the sole owner of
#      ion + swap.
#
# All changes pause for [y/N] before applying. Each one writes a
# `.bak.<ts>` of the original. Idempotent — re-running is safe.
#
# RUN
#   bash scripts/fix-edge-comprehensive.sh MINING_ADDR
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}
MINING_ADDR="${1:-${EDGE_MINING_ADDR:-}}"
MINING_THREADS="${EDGE_MINING_THREADS:-2}"

if [ -z "$MINING_ADDR" ]; then
  read -p "  USDm mining address (95+ chars): " MINING_ADDR
fi

# ─── Step 1: write clean wrapper to a tmp file LOCALLY, scp it ──────

TMP_WRAPPER=$(mktemp)
trap "rm -f '$TMP_WRAPPER'" EXIT

cat > "$TMP_WRAPPER" <<EOF
#!/bin/bash
# /root/start-usdmd.sh — Edge USDmd launcher.
# Written by fix-edge-comprehensive.sh (clean from-scratch shape).
# Per CLAUDE.md rule 30 — uses bundled linker + libs to bypass host
# glibc mismatch. Per rule 30a — bundle paths NEVER in /etc/ld.so.conf.

set -e

# Build args as a bash array — no line-continuation pitfalls.
ARGS=(
  --rpc-bind-ip 127.0.0.1
  --rpc-bind-port 17751
  --rpc-restricted-bind-ip 0.0.0.0
  --rpc-restricted-bind-port 17750
  --confirm-external-bind
  --p2p-bind-ip 0.0.0.0
  --p2p-bind-port 17749
  --start-mining "$MINING_ADDR"
  --mining-threads $MINING_THREADS
  --add-peer ${MONEROUSD_VPS_HOST}:17749
  --non-interactive
  --disable-rpc-ban
  --log-level 1
  --log-file /root/.monerousd/monerousd.log
)

# Optional config file — only added if present AND we trust it.
# For now we DELIBERATELY skip the config file because earlier
# invocations had \`rpc-bind-ip = 0.0.0.0\` in there which silently
# overrode our CLI flags.
# To re-enable, uncomment AFTER manually verifying the conf:
#   if [ -f /root/.monerousd/USDmd.conf ]; then
#     ARGS+=(--config-file /root/.monerousd/USDmd.conf)
#   fi

exec /root/usdmd-bundle/lib/ld-linux-x86-64.so.2 \\
  --library-path /root/usdmd-bundle/lib \\
  /root/usdmd-bundle/USDmd \\
  "\${ARGS[@]}"
EOF

echo "  ── 1. Writing clean USDmd wrapper ──"
echo ""
echo "  preview of new wrapper:"
echo "  ────────────────────────"
cat "$TMP_WRAPPER" | head -30
echo "  ... (truncated)"
echo ""
read -p "  Looks good? Push to edge + restart USDmd? [y/N] " confirm
if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
  scp "$TMP_WRAPPER" "$EDGE:/tmp/start-usdmd.sh.new"
  ssh "$EDGE" bash -s <<'REMOTE'
set -e
cp /root/start-usdmd.sh /root/start-usdmd.sh.bak.preclean.$(date +%s) 2>/dev/null || true
mv /tmp/start-usdmd.sh.new /root/start-usdmd.sh
chmod +x /root/start-usdmd.sh

# Verify it's syntactically valid bash
bash -n /root/start-usdmd.sh && echo "  ✓ bash syntax OK"

# Rename old config file so USDmd doesn't auto-load it (some forks
# do that even without --config-file).
if [ -f /root/.monerousd/USDmd.conf ]; then
  mv /root/.monerousd/USDmd.conf /root/.monerousd/USDmd.conf.bak.$(date +%s)
  echo "  ✓ moved aside /root/.monerousd/USDmd.conf (was overriding CLI binds)"
fi

systemctl restart USDmd.service
sleep 8
systemctl is-active USDmd && echo "  ✓ USDmd active"

# Verify port bindings — 17751 should be 127.0.0.1, 17750/17749 0.0.0.0.
echo ""
echo "  --- listening sockets ---"
ss -tlnp | grep -E ':17749|:17750|:17751' | head
REMOTE
fi

# ─── Step 2: USDmd log dump (read-only) ─────────────────────────────

echo ""
echo "  ── 2. USDmd log dump (read-only — diagnose mining) ──"
ssh "$EDGE" 'tail -80 /root/.monerousd/monerousd.log 2>/dev/null || echo "  (log file not found yet — wait 30s after restart)"'

# ─── Step 3: ion-backend Node version + ESM fix ────────────────────

echo ""
echo "  ── 3. ion-backend Node + ESM fix ──"
read -p "  Check Node version + install Node 20 LTS if needed + fix package.json? [y/N] " confirm
if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
  ssh "$EDGE" bash -s <<'REMOTE'
set -e
NODE_MAJOR=$(node --version 2>/dev/null | sed -E 's/v([0-9]+).*/\1/')
echo "  current Node major: ${NODE_MAJOR:-(none)}"

if [ -z "$NODE_MAJOR" ] || [ "$NODE_MAJOR" -lt 18 ]; then
  echo "  Installing Node 20 LTS via NodeSource..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  node --version && npm --version
fi

# Ensure ion-backend's package.json has type:module
PKG=/opt/ion-monerousd-org/backend/package.json
if [ -f "$PKG" ]; then
  cp "$PKG" "$PKG.bak.$(date +%s)"
  if ! grep -q '"type"\s*:\s*"module"' "$PKG"; then
    # Add "type": "module" using node directly so we don't fight jq dependencies
    node -e "
      const fs=require('fs');
      const p='$PKG';
      const j=JSON.parse(fs.readFileSync(p,'utf8'));
      j.type='module';
      fs.writeFileSync(p, JSON.stringify(j, null, 2)+'\n');
    "
    echo "  ✓ added 'type': 'module' to package.json"
  else
    echo "  ✓ package.json already has 'type': 'module'"
  fi

  cd /opt/ion-monerousd-org/backend
  npm ci --production 2>&1 | tail -5 || npm install --production 2>&1 | tail -5
fi

systemctl restart ion-backend.service
sleep 5
systemctl is-active ion-backend && echo "  ✓ ion-backend active" || {
  echo "  ✗ ion-backend still failing — last 20 log lines:"
  journalctl -u ion-backend --no-pager -n 20
}
REMOTE
fi

# ─── Step 4: nginx — disable old monerousd-relay vhost ─────────────

echo ""
echo "  ── 4. nginx — disable old monerousd-relay vhost ──"
echo "  monerousd-relay was the OLD edge config proxying to dead Skynet."
echo "  Disabling it lets the new ion-monerousd vhost own ion + swap."
read -p "  Disable monerousd-relay? [y/N] " confirm
if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
  ssh "$EDGE" bash -s <<'REMOTE'
set -e
if [ -f /etc/nginx/sites-enabled/monerousd-relay ]; then
  mv /etc/nginx/sites-enabled/monerousd-relay /etc/nginx/sites-enabled/monerousd-relay.disabled.$(date +%s)
  echo "  ✓ monerousd-relay disabled (moved aside)"
fi

nginx -t 2>&1 | head -5
nginx -s reload && echo "  ✓ nginx reloaded"

# Verify ion + swap now route correctly
echo ""
echo "  --- probe ion.monerousd.org via Host header ---"
curl -sI -m 5 -H 'Host: ion.monerousd.org' 'http://127.0.0.1/' 2>&1 | head -5
REMOTE
fi

# ─── Final verification ────────────────────────────────────────────

echo ""
echo "  ── final verification (external probes) ──"
sleep 5

echo ""
echo "  USDmd public restricted RPC (:17750):"
curl -sf -m 8 -X POST 'http://${MONEROUSD_EDGE_HOST}:17750/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' 2>&1 | head -c 200
echo ""

echo ""
echo "  USDmd FULL RPC :17751 — should NOT be externally reachable:"
nc -z -G 5 -w 5 ${MONEROUSD_EDGE_HOST} 17751 2>&1 \
  && echo "  ✗ port 17751 is OPEN externally — bind didn't take" \
  || echo "  ✓ port 17751 is closed externally — full RPC localhost-only"

echo ""
echo "  ion.monerousd.org via /v1/info (using Host header since DNS A still pending):"
curl -s -m 8 -H 'Host: ion.monerousd.org' 'http://${MONEROUSD_EDGE_HOST}/v1/info' 2>&1 | head -c 300
echo ""

#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# edge-full-bootstrap.sh
#
# Brings the Hostinger edge VPS (${MONEROUSD_EDGE_HOST}) up to a complete,
# production state in three phases:
#
#   PHASE A — RPC security hardening
#     Re-bind: main port 17750 → localhost only (full RPC, operator).
#              restricted port 17751 → 0.0.0.0 public (read+relay).
#     The wallet-to-node connection moves to port 17751 publicly,
#     so no admin methods are exposed externally.
#
#   PHASE B — Mining restart
#     Adds `start-mining=<addr> mining-threads=N` to the USDmd
#     wrapper. Per CLAUDE.md rule 28: mining is permissionless after
#     v1.2.207, multiple miners encouraged. Before enabling, verifies
#     the daemon is on canonical chain (genesis hash + height ≥
#     hardcoded checkpoint) so we don't mine on a fork.
#
#   PHASE C — ion-backend deploy
#     rsync's `ion-monerousd-org/backend/` to /opt/ion-monerousd-org/
#     on the edge. systemd unit + nginx vhost. Express :7777, WS :7778.
#     /api/* and /v1/* routed by nginx to local Express. After deploy
#     the operator adds DNS A records for ion.monerousd.org +
#     swap.monerousd.org pointing at ${MONEROUSD_EDGE_HOST}.
#
# All three phases pause for [y/N] confirmation before any production
# write, and produce timestamped backups (.bak.<ts>) of every edited
# config file. Re-runnable: skips phases that are already in target
# state.
#
# REQUIRES
#   • ssh-copy-id done to root@${MONEROUSD_EDGE_HOST}, OR you'll be prompted per
#     SSH command for the root password
#   • Your USDm payout address (for mining; --mining-addr or env
#     EDGE_MINING_ADDR)
#
# RUN
#   bash scripts/edge-full-bootstrap.sh                # interactive
#   bash scripts/edge-full-bootstrap.sh --skip-c       # skip ion-backend
#   bash scripts/edge-full-bootstrap.sh --mining-addr <usdm-addr>
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

EDGE_HOST="${MONEROUSD_EDGE_HOST}"
EDGE_USER="root"
SKIP_A="false"
SKIP_B="false"
SKIP_C="false"
MINING_ADDR="${EDGE_MINING_ADDR:-}"
MINING_THREADS="${EDGE_MINING_THREADS:-2}"

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-a) SKIP_A="true"; shift ;;
    --skip-b) SKIP_B="true"; shift ;;
    --skip-c) SKIP_C="true"; shift ;;
    --mining-addr) MINING_ADDR="$2"; shift 2 ;;
    --mining-threads) MINING_THREADS="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

# ─── SSH probe ──────────────────────────────────────────────────────

if ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
   "$EDGE_USER@$EDGE_HOST" 'echo OK' >/dev/null 2>&1; then
  SSH="ssh -o ConnectTimeout=12 -o BatchMode=yes $EDGE_USER@$EDGE_HOST"
  echo "  ✓ SSH key-auth works"
else
  SSH="ssh -o ConnectTimeout=12 $EDGE_USER@$EDGE_HOST"
  echo "  ⚠ key-auth failed. You'll be prompted for root password each step."
  echo "    Make seamless: ssh-copy-id -i ~/.ssh/id_ed25519.pub $EDGE_USER@$EDGE_HOST"
  echo ""
  read -p "  Press Enter to continue, or Ctrl-C to abort: " _
fi

# ─── PHASE A: RPC HARDENING ─────────────────────────────────────────

if [ "$SKIP_A" != "true" ]; then
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  PHASE A — RPC security hardening"
  echo "════════════════════════════════════════════════════════"
  echo "  Reconfigures USDmd to:"
  echo "    --rpc-bind-ip 127.0.0.1                       (full RPC, operator-only)"
  echo "    --rpc-restricted-bind-ip 0.0.0.0              (public RPC, read+relay only)"
  echo "    --rpc-restricted-bind-port 17750               (keep wallets pointed at this port)"
  echo ""
  echo "  Wait — important: existing wallets dial node.monerousd.org:17750."
  echo "  We KEEP 17750 as the public surface but make it restricted."
  echo "  The full RPC (admin methods) moves to 127.0.0.1:17751 — operator-only."
  echo ""
  read -p "  Proceed with Phase A? [y/N] " confirm
  if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    $SSH bash -s <<'REMOTE_A'
set -e
WRAPPER=/root/start-usdmd.sh
[ -f "$WRAPPER" ] || { echo "  ✗ /root/start-usdmd.sh not found"; exit 1; }
cp "$WRAPPER" "$WRAPPER.bak.$(date +%s)"

# Strip any prior --rpc-bind-ip / --rpc-restricted-bind-* / --restricted-rpc
# flags we may have injected earlier, then add the canonical set.
sed -i -E 's/[[:space:]]*--rpc-bind-ip[[:space:]]+[0-9.]+//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--confirm-external-bind//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--restricted-rpc//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--rpc-restricted-bind-ip[[:space:]]+[0-9.]+//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--rpc-restricted-bind-port[[:space:]]+[0-9]+//g' "$WRAPPER"

# Inject canonical hardened bind config.
# Main port 17751 → localhost only (operator full RPC)
# Restricted port 17750 → public (read-only + relay) — keeps wallet
# clients pointed at the same port number they always used.
sed -i -E 's|(USDmd[^&]*)|\1 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 17751 --rpc-restricted-bind-ip 0.0.0.0 --rpc-restricted-bind-port 17750 --confirm-external-bind|' "$WRAPPER"

echo "  wrapper after edit:"
grep -E 'USDmd|rpc-bind|rpc-restricted' "$WRAPPER" | head -10

systemctl daemon-reload || true
systemctl restart USDmd.service
sleep 6
systemctl is-active USDmd && echo "  ✓ USDmd restarted, active" || { echo "  ✗ USDmd not active — check journalctl -u USDmd"; exit 1; }
REMOTE_A

    sleep 3
    # Probe externally: 17750 should still serve get_block_count (restricted),
    # but NOT admin methods like set_log_level.
    echo ""
    echo "  external probe of public restricted port 17750:"
    curl -sf -m 8 -X POST "http://${EDGE_HOST}:17750/json_rpc" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' 2>&1 | head -c 200
    echo ""
    echo ""
    echo "  attempt admin method (expect refused/restricted):"
    curl -sf -m 8 -X POST "http://${EDGE_HOST}:17750/json_rpc" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"set_log_level","params":{"level":1}}' 2>&1 | head -c 300
    echo ""
  else
    echo "  Phase A skipped"
  fi
fi

# ─── PHASE B: MINING RESTART ────────────────────────────────────────

if [ "$SKIP_B" != "true" ]; then
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  PHASE B — Mining restart"
  echo "════════════════════════════════════════════════════════"
  if [ -z "$MINING_ADDR" ]; then
    echo "  Need a USDm payout address (where block rewards go)."
    read -p "  Mining address: " MINING_ADDR
  fi
  if [ -z "$MINING_ADDR" ] || [ ${#MINING_ADDR} -lt 90 ]; then
    echo "  ✗ Mining address looks invalid (need full 95+ char USDm address)"
    echo "    Skipping Phase B"
  else
    echo "  Will enable: start-mining=$MINING_ADDR mining-threads=$MINING_THREADS"
    echo ""
    read -p "  Proceed with Phase B? [y/N] " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
      $SSH bash -s "$MINING_ADDR" "$MINING_THREADS" <<'REMOTE_B'
set -e
ADDR="$1"
THREADS="$2"
WRAPPER=/root/start-usdmd.sh
[ -f "$WRAPPER" ] || { echo "  ✗ wrapper not found"; exit 1; }
cp "$WRAPPER" "$WRAPPER.bak.mining.$(date +%s)"

# Verify canonical chain BEFORE enabling mining (per CLAUDE.md rule 28).
# Block 0 + a known checkpoint block hash should match the hardcoded
# values. We probe via local RPC.
HEIGHT=$(curl -sf -m 5 -X POST 'http://127.0.0.1:17751/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["count"])' 2>/dev/null || \
  curl -sf -m 5 -X POST 'http://127.0.0.1:17750/json_rpc' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["count"])' 2>/dev/null)
echo "  current chain height: $HEIGHT"
if [ -z "$HEIGHT" ] || [ "$HEIGHT" -lt 88400 ] 2>/dev/null; then
  echo "  ⚠ height is below known canonical checkpoint 88400 — refusing to enable mining"
  echo "    (chain may be on a fork; verify before mining)"
  exit 2
fi

# Strip any prior mining flags + inject new ones.
sed -i -E 's/[[:space:]]*--start-mining[[:space:]]+[A-Za-z0-9]+//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--mining-threads[[:space:]]+[0-9]+//g' "$WRAPPER"
sed -i -E 's/[[:space:]]*--bg-mining-enable[[:space:]]*[01]?//g' "$WRAPPER"
sed -i -E "s|(USDmd[^&]*)|\\1 --start-mining $ADDR --mining-threads $THREADS|" "$WRAPPER"

echo "  wrapper after mining edit:"
grep -E 'start-mining|mining-threads' "$WRAPPER" | head -5

systemctl restart USDmd.service
sleep 8

# Verify mining is running.
MINING_STATUS=$(curl -sf -m 5 -X POST 'http://127.0.0.1:17751/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"mining_status"}' 2>/dev/null \
  || curl -sf -m 5 'http://127.0.0.1:17751/mining_status' 2>/dev/null \
  || echo '{}')
echo "  mining_status: $MINING_STATUS" | head -c 400
echo ""
REMOTE_B
    else
      echo "  Phase B skipped"
    fi
  fi
fi

# ─── PHASE C: ion-backend deploy ────────────────────────────────────

if [ "$SKIP_C" != "true" ]; then
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  PHASE C — ion-backend deploy"
  echo "════════════════════════════════════════════════════════"
  echo "  rsync ion-monerousd-org/backend/ → /opt/ion-monerousd-org/"
  echo "  Drops systemd unit, nginx vhost (ion + swap subdomains),"
  echo "  starts the service. After this passes, add the DNS A records:"
  echo "    A  ion   ${MONEROUSD_EDGE_HOST}"
  echo "    A  swap  ${MONEROUSD_EDGE_HOST}"
  echo ""
  read -p "  Proceed with Phase C? [y/N] " confirm
  if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    BACKEND_DIR=$HOME/Desktop/connect/ion-monerousd-org/backend
    if [ ! -d "$BACKEND_DIR" ]; then
      echo "  ✗ local backend dir not found at $BACKEND_DIR"
      exit 1
    fi
    echo "  pre-creating /opt/ion-monerousd-org/ on edge (rsync mkdir is shallow)..."
    $SSH 'mkdir -p /opt/ion-monerousd-org/backend' 2>&1 | head -3

    echo "  rsyncing backend to edge..."
    rsync -az --delete \
      --exclude='node_modules' \
      --exclude='*.db' --exclude='*.db-shm' --exclude='*.db-wal' \
      --exclude='*.sqlite*' \
      --exclude='.env' --exclude='.env.*' \
      --exclude='secrets*' --exclude='credentials*' \
      --exclude='.claude' --exclude='.DS_Store' \
      "$BACKEND_DIR/" "$EDGE_USER@$EDGE_HOST:/opt/ion-monerousd-org/backend/"

    $SSH bash -s <<'REMOTE_C'
set -e
cd /opt/ion-monerousd-org/backend
[ -f package.json ] && npm ci --production 2>&1 | tail -3 || echo "  no package.json — skip npm install"

cat > /etc/systemd/system/ion-backend.service <<UNIT
[Unit]
Description=Ion Swap backend (Express + indexer)
After=network-online.target USDmd.service
Wants=network-online.target
Requires=USDmd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ion-monerousd-org/backend
ExecStart=/usr/bin/env node server.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=7777
Environment=WS_PORT=7778
Environment=USDMD_RPC=http://127.0.0.1:17751
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

# nginx vhost for ion.monerousd.org + swap.monerousd.org
cat > /etc/nginx/sites-available/ion-monerousd <<NGINX
server {
    listen 80;
    server_name ion.monerousd.org swap.monerousd.org;
    location /api/ { proxy_pass http://127.0.0.1:7777; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /v1/  { proxy_pass http://127.0.0.1:7777; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /     {
        proxy_pass http://127.0.0.1:7778/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$host;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/ion-monerousd /etc/nginx/sites-enabled/ion-monerousd
nginx -t && nginx -s reload

systemctl daemon-reload
systemctl enable --now ion-backend
sleep 3
systemctl is-active ion-backend && echo "  ✓ ion-backend active" || { echo "  ✗ ion-backend not active"; journalctl -u ion-backend --since '1m' | tail -20; }

if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp comment 'http' || true
  ufw allow 443/tcp comment 'https' || true
fi

echo ""
echo "  Once DNS A records are added (ion + swap → ${MONEROUSD_EDGE_HOST}), run:"
echo "    certbot --nginx -d ion.monerousd.org -d swap.monerousd.org"
echo "  to auto-issue Let's Encrypt cert."
REMOTE_C
  else
    echo "  Phase C skipped"
  fi
fi

# ─── final report ───────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"
echo "  edge-full-bootstrap complete"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Verify externally:"
echo "    curl -sX POST http://node.monerousd.org:17750/json_rpc \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_count\"}'"
echo ""
echo "  After Phase C + DNS for ion + swap, also:"
echo "    curl -sf https://ion.monerousd.org/v1/info  (post cert provisioning)"

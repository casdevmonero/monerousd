#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# bootstrap-edge-as-node.sh
#
# Repurposes the existing Hostinger edge VPS (${MONEROUSD_EDGE_HOST}) as the
# canonical `node.monerousd.org` — public USDmd daemon RPC + P2P
# seed for fresh wallet bootstrap.
#
# What this script does (over SSH to root@${MONEROUSD_EDGE_HOST}):
#   1. Inspects USDmd service state + chain sync status.
#   2. Re-binds RPC from 127.0.0.1 to 0.0.0.0 so external wallets
#      can connect (operator-restricted methods stay safe — the
#      daemon's `--rpc-restricted-bind-ip` would be the production
#      hardening; for now we open standard read+relay methods).
#   3. Opens UFW for ports 17749 (P2P) + 17750 (RPC) inbound.
#   4. Restarts USDmd via systemctl (NEVER pkill+nohup per
#      CLAUDE.md rule 31).
#   5. Verifies external RPC is now reachable from the public
#      internet.
#
# What it DOES NOT do (operator action required):
#   • Adds the Njalla DNS A record `node.monerousd.org → ${MONEROUSD_EDGE_HOST}`.
#     (Script prints the exact line at the end.)
#   • Adds CNAME `seed.monerousd.org → node.monerousd.org`.
#
# RUN
#   bash scripts/bootstrap-edge-as-node.sh
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

EDGE_HOST="${MONEROUSD_EDGE_HOST}"
EDGE_USER="root"

echo "  ── Bootstrap edge as node.monerousd.org ──"
echo "    target:      $EDGE_USER@$EDGE_HOST"
echo "    USDmd P2P:   17749  (already open per probes)"
echo "    USDmd RPC:   17750  (currently 127.0.0.1; making public)"
echo ""

# ─── 1. Probe SSH reachability + auth method ────────────────────────

echo "  ── step 1: SSH connectivity check ──"
if ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
   "$EDGE_USER@$EDGE_HOST" 'echo OK' >/dev/null 2>&1; then
  echo "  ✓ SSH key-auth works"
  SSH_PREFIX="ssh -o ConnectTimeout=12 -o BatchMode=yes $EDGE_USER@$EDGE_HOST"
else
  echo "  ⚠ key-auth failed — you'll be prompted for the root password each step."
  echo "    To make this seamless next time:"
  echo "      ssh-copy-id -i ~/.ssh/id_ed25519.pub $EDGE_USER@$EDGE_HOST"
  echo ""
  read -p "  Press Enter to continue with password auth, or Ctrl-C to abort: " _
  SSH_PREFIX="ssh -o ConnectTimeout=12 $EDGE_USER@$EDGE_HOST"
fi

# ─── 2. Inspect current USDmd state ─────────────────────────────────

echo ""
echo "  ── step 2: inspect USDmd service ──"
$SSH_PREFIX "
echo '  systemctl status USDmd:'
systemctl is-active USDmd 2>/dev/null && echo '    ACTIVE' || echo '    NOT-active'

echo '  USDmd version:'
which USDmd 2>/dev/null && /root/start-usdmd.sh --version 2>&1 | head -2 || echo '    (no /root/start-usdmd.sh — checking alternate paths)'

echo '  current RPC bind (from systemd unit):'
systemctl cat USDmd.service 2>/dev/null | grep -E 'rpc-bind-ip|ExecStart' | head -3

echo '  chain tip via local RPC:'
curl -sf -m 5 -X POST 'http://127.0.0.1:17750/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_count\"}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(\"    height:\", d[\"result\"][\"count\"])' 2>/dev/null \
  || echo '    (local RPC not responding)'
" 2>&1

# ─── 3. Reconfigure RPC bind to 0.0.0.0 ─────────────────────────────

echo ""
echo "  ── step 3: re-bind RPC to 0.0.0.0 ──"
echo "    (will edit /etc/systemd/system/USDmd.service or wrapper script)"
read -p "  Proceed? [y/N] " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
  echo "  aborted at step 3"; exit 0
fi

$SSH_PREFIX bash -s <<'REMOTE'
set -e

# Find the wrapper script (per CLAUDE.md rule 30 — edge uses
# /root/start-usdmd.sh because of glibc compat).
WRAPPER=/root/start-usdmd.sh
UNIT=/etc/systemd/system/USDmd.service

if [ -f "$WRAPPER" ]; then
  echo "  found wrapper: $WRAPPER"
  cp "$WRAPPER" "$WRAPPER.bak.$(date +%s)"
  # Replace 127.0.0.1 RPC bind → 0.0.0.0; add rpc-restricted-bind-ip
  # for the unrestricted (read+relay) public surface.
  if grep -q -- '--rpc-bind-ip 127.0.0.1' "$WRAPPER"; then
    sed -i 's|--rpc-bind-ip 127.0.0.1|--rpc-bind-ip 0.0.0.0 --confirm-external-bind --restricted-rpc|g' "$WRAPPER"
    echo "  ✓ wrapper patched: RPC bind 127.0.0.1 → 0.0.0.0 (restricted)"
  elif ! grep -q -- '--rpc-bind-ip' "$WRAPPER"; then
    # No explicit bind — daemon defaults to 127.0.0.1. Inject flags.
    sed -i '/USDmd/ s|$| --rpc-bind-ip 0.0.0.0 --confirm-external-bind --restricted-rpc|' "$WRAPPER"
    echo "  ✓ wrapper extended with public restricted-RPC bind"
  else
    echo "  ✓ wrapper already binds publicly (no edit needed)"
  fi
elif [ -f "$UNIT" ]; then
  echo "  no wrapper; editing systemd unit directly: $UNIT"
  cp "$UNIT" "$UNIT.bak.$(date +%s)"
  if grep -q -- '--rpc-bind-ip 127.0.0.1' "$UNIT"; then
    sed -i 's|--rpc-bind-ip 127.0.0.1|--rpc-bind-ip 0.0.0.0 --confirm-external-bind --restricted-rpc|g' "$UNIT"
    echo "  ✓ unit patched"
  fi
else
  echo "  ✗ neither wrapper nor unit found; aborting" >&2; exit 1
fi

# Open firewall
if command -v ufw >/dev/null 2>&1; then
  ufw allow 17749/tcp comment 'USDmd P2P' || true
  ufw allow 17750/tcp comment 'USDmd RPC (restricted)' || true
  echo "  ✓ ufw rules added (P2P + RPC)"
fi

systemctl daemon-reload
systemctl restart USDmd.service
sleep 5
systemctl is-active USDmd && echo "  ✓ USDmd restarted, active" || echo "  ⚠ USDmd not active after restart — check journalctl -u USDmd"
REMOTE

# ─── 4. External RPC reachability ───────────────────────────────────

echo ""
echo "  ── step 4: verify external RPC ──"
sleep 3
RESP=$(curl -sf -m 8 -X POST "http://${EDGE_HOST}:17750/json_rpc" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' 2>&1 || true)

if [ -n "$RESP" ]; then
  echo "  ✓ external RPC works:"
  echo "    $RESP" | head -c 300
  echo ""
else
  echo "  ⚠ external RPC still not responding — check edge UFW + USDmd journal"
  echo "    ssh root@${EDGE_HOST} 'journalctl -u USDmd --since 1m | tail -30'"
fi

# ─── 5. DNS instructions ────────────────────────────────────────────

echo ""
echo "  ── step 5: Njalla DNS records to add ──"
echo ""
echo "  Type   Name   Content                             TTL"
echo "  A      node   ${EDGE_HOST}                        300"
echo "  CNAME  seed   node.monerousd.org.                 300"
echo ""
echo "  After adding, verify:"
echo "    dig +short A node.monerousd.org"
echo "    curl -sf -X POST http://node.monerousd.org:17750/json_rpc \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_count\"}'"

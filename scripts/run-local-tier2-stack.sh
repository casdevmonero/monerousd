#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# scripts/run-local-tier2-stack.sh
#
# Single-shot launcher for the full Tier 2 LWS dev stack.
# Brings up:
#   1. LWS server on :7790 with a deterministic dev operator key
#   2. The wallet (dev tree) configured to use the local LWS endpoint
#
# This works for BOTH:
#   - TNA users (wallet-rpc → edge daemon ${MONEROUSD_EDGE_HOST}:17750)
#   - Local-node users (wallet-rpc → local USDmd 127.0.0.1:17750)
#
# The LWS server's scanner is pointed via LWS_DAEMON_RPC env. We
# default it to the same daemon the wallet uses (edge today; flip
# to local with LWS_DAEMON_RPC=http://127.0.0.1:17750 if you have
# a local USDmd running).
#
# Usage:
#   bash scripts/run-local-tier2-stack.sh             # TNA mode
#   LOCAL_DAEMON=1 bash scripts/run-local-tier2-stack.sh   # local USDmd
#   STOP=1 bash scripts/run-local-tier2-stack.sh      # tear everything down
#
# All logs go under /tmp/monerousd-tier2/ — tail them to debug.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="/tmp/monerousd-tier2"
mkdir -p "$LOG_DIR"
PID_DIR="$LOG_DIR/pids"
mkdir -p "$PID_DIR"

# ── Config ──────────────────────────────────────────────────────────

LWS_PORT="${LWS_PORT:-7790}"

if [[ "${LOCAL_DAEMON:-0}" == "1" ]]; then
  DAEMON_RPC_URL="http://127.0.0.1:17750"
  DAEMON_NOTE="LOCAL USDmd (127.0.0.1:17750)"
else
  DAEMON_RPC_URL="http://${MONEROUSD_EDGE_HOST}:17750"
  DAEMON_NOTE="EDGE daemon (${MONEROUSD_EDGE_HOST}:17750)"
fi

LWS_ENDPOINT="http://127.0.0.1:${LWS_PORT}"

# Persisted dev operator key — same across runs so the wallet's
# LWS_QUORUM_PUBKEY_HASH stays valid.
DEV_KEY_FILE="$LOG_DIR/lws-dev-operator.json"
if [[ ! -f "$DEV_KEY_FILE" ]]; then
  echo "Generating dev operator key (one-time)…"
  node -e "
const crypto = require('node:crypto');
const { ed25519 } = require('${ROOT}/build-1261/node_modules/@noble/curves/ed25519.js');
const priv = crypto.randomBytes(32);
const pub = Buffer.from(ed25519.getPublicKey(priv));
const pubHash = crypto.createHash('sha256').update(pub).digest();
process.stdout.write(JSON.stringify({
  priv_hex: priv.toString('hex'),
  pub_hex:  pub.toString('hex'),
  pub_hash_hex: pubHash.toString('hex'),
}, null, 2));
" > "$DEV_KEY_FILE"
fi

DEV_PRIV="$(node -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).priv_hex)" "$DEV_KEY_FILE")"
DEV_PUB="$(node -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).pub_hex)" "$DEV_KEY_FILE")"
DEV_PUB_HASH="$(node -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).pub_hash_hex)" "$DEV_KEY_FILE")"

# ── Stop ────────────────────────────────────────────────────────────

if [[ "${STOP:-0}" == "1" ]]; then
  for f in "$PID_DIR"/*.pid; do
    [[ -e "$f" ]] || continue
    pid="$(cat "$f")"
    name="$(basename "$f" .pid)"
    if kill -0 "$pid" 2>/dev/null; then
      echo "stopping $name (pid $pid)…"
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  done
  echo "all tier-2 dev processes stopped."
  exit 0
fi

# ── Pre-flight ──────────────────────────────────────────────────────

if [[ ! -L "${ROOT}/MoneroUSD-main/build/bin/USDm-wallet-rpc" && ! -x "${ROOT}/MoneroUSD-main/build/bin/USDm-wallet-rpc" ]]; then
  echo "✗ Dev-tree wallet-rpc symlink missing. Creating it now…"
  mkdir -p "${ROOT}/MoneroUSD-main/build/bin"
  ln -sf ~/Desktop/MoneroUSD-main/build/bin/USDm-wallet-rpc "${ROOT}/MoneroUSD-main/build/bin/USDm-wallet-rpc"
  ln -sf ~/Desktop/MoneroUSD-main/build/bin/USDmd            "${ROOT}/MoneroUSD-main/build/bin/USDmd"
fi

# ── Step 1: Start LWS server ────────────────────────────────────────

echo "─── Tier 2 dev stack ──────────────────────────────────────────"
echo "  daemon          : $DAEMON_NOTE"
echo "  LWS endpoint    : $LWS_ENDPOINT"
echo "  LWS log         : $LOG_DIR/lws.log"
echo "  operator pubkey : ${DEV_PUB:0:16}…"
echo ""

# Kill any previous LWS instance on this port.
if lsof -nP -iTCP:${LWS_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Stopping previous LWS server on :${LWS_PORT}…"
  pid="$(lsof -nP -iTCP:${LWS_PORT} -sTCP:LISTEN -t)"
  kill "$pid" 2>/dev/null || true
  sleep 0.5
fi

LWS_LISTEN_PORT="$LWS_PORT" \
LWS_OPERATOR_PRIVKEY_HEX="$DEV_PRIV" \
LWS_OPERATOR_PUBKEY_HEX="$DEV_PUB" \
LWS_DAEMON_RPC="$DAEMON_RPC_URL" \
  node "${ROOT}/ion-monerousd-org/backend/lws/index.cjs" > "$LOG_DIR/lws.log" 2>&1 &

echo "$!" > "$PID_DIR/lws.pid"
sleep 1

if ! curl -sf "http://127.0.0.1:${LWS_PORT}/v1/lws/stats" >/dev/null; then
  echo "✗ LWS server did not become ready. Tail $LOG_DIR/lws.log for details."
  exit 1
fi
echo "✓ LWS server up on :${LWS_PORT}"

# ── Step 2: Launch wallet (dev tree) ────────────────────────────────

# The wallet must be told (a) where the local LWS endpoint is and
# (b) what quorum_pubkey_hash to expect from it. These are env vars
# the wallet picks up at boot.

cat <<EOF

─── To launch the wallet ───────────────────────────────────────────

Run this in a NEW terminal:

  cd ${ROOT}/build-1261
  MONEROUSD_LWS_ENDPOINT=${LWS_ENDPOINT} \\
  LWS_QUORUM_PUBKEY_HASH=${DEV_PUB_HASH} \\
  npm start

What you should see:
  - Welcome screen → click Restore → paste seed → Restore wallet
  - In the wallet's DevTools console (Cmd-Opt-I):
      [restore-lws] fast-restore returned N outputs across 16 subaddresses
    OR (if classical-scan ran first):
      [post-restore-watcher] synced + stable for K ticks — exiting cleanly
      [lws-backfill] kicking off post-sync backfill for <fingerprint>
      [lws-backfill] completed: added=N deduped=M processed=K

The backfill runs ONCE per wallet identity per app launch. After it
completes, the next restore on a different device finishes in <2 s
(because the LWS index already has every historical output).

─── To stop everything ─────────────────────────────────────────────

  STOP=1 bash ${ROOT}/scripts/run-local-tier2-stack.sh

EOF

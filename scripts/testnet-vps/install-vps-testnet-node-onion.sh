#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# install-vps-testnet-node-onion.sh — W25.1
# =========================================================================
# Install a DAG-USDmd testnet node on a VPS with **ONION-ONLY P2P**.
# Replaces W24.1's IP-exposing install (deleted) because exposing a
# public P2P port unmasks the VPS — the network is supposed to be
# 100% private. Every P2P link rides over Tor v3 hidden services.
#
# Topology this script provisions:
#
#   [VPS host]
#     ├── systemd: USDmd-tor.service        (Phase A.1 sidecar Tor — SocksPort + HiddenServiceDir)
#     │     persistent HiddenServiceDir → <56-char>.onion
#     │     virtual port 18083 → 127.0.0.1:18083 (USDmd anonymous-inbound bind)
#     │
#     └── systemd: USDmd-testnet.service    (DAG-USDmd daemon, ONION-ONLY)
#           --tx-proxy        tor,127.0.0.1:<SOCKS>,16
#           --anonymous-inbound <self>.onion:18083,127.0.0.1:18083,16
#           --add-priority-node <peer1>.onion:18083
#           --add-priority-node <peer2>.onion:18083
#           --p2p-bind-ip 127.0.0.1   (loopback only — NOT public)
#           --rpc-bind-ip 127.0.0.1   (loopback only — ssh-tunnel for ops)
#
# Net result: from outside the host, only port 9001 (Tor OR port) is
# reachable, and only because Tor needs to talk to the directory
# authorities. Everything USDmd-related — P2P, RPC, ZMQ — is loopback.
# No port-scan can confirm USDmd is running.
#
# Mesh peering: this node's .onion address is the only thing the other
# two nodes need. After install, the script prints the .onion and the
# operator pastes it into the OTHER nodes' `--add-priority-node` config
# (or rerun this script on them with --peer-1-onion / --peer-2-onion).
#
# Usage (operator runs after scp'ing files into place):
#   sudo bash install-vps-testnet-node-onion.sh \
#       --node-tag B \
#       --peer-1-onion <56-char>.onion \
#       --peer-2-onion <56-char>.onion
#
# Bootstrap order (chicken-and-egg):
#   1. Pick one node (call it N1) to bootstrap first. Run this script
#      with EMPTY --peer-1-onion / --peer-2-onion (or just omit them).
#      It produces an .onion identity but the daemon has no peers.
#   2. Copy N1's .onion. Install N2 with --peer-1-onion <N1>. N2 now
#      has its own .onion + can reach N1.
#   3. Copy N2's .onion. Re-install N1 with --peer-1-onion <N2>.
#      Re-install N3 with --peer-1-onion <N1> --peer-2-onion <N2>.
#
# Re-running is idempotent: existing onion identity is reused.
#
# Cross-references:
#   - CLAUDE.md rule 28a (mining is permissionless) — N/A for a non-mining peer
#   - CLAUDE.md rule 31 (systemctl is the only valid VPS daemon lifecycle)
#   - CLAUDE.md rule 30a (no usdmd lib paths in /etc/ld.so.conf*)
#   - Survivability A.1 (`scripts/testnet/start-usdmd-testnet-onion.sh` —
#     the local dev equivalent of this script's USDmd args)
# =========================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NODE_TAG=""
PEER_1_ONION=""
PEER_2_ONION=""
PEER_VPORT=18083   # virtual port every node exposes inbound on its .onion

TESTNET_BIN_PATH="${TESTNET_BIN_PATH:-/usr/local/bin/USDmd-testnet}"
TESTNET_DATA_DIR="${TESTNET_DATA_DIR:-/var/lib/usdmd-testnet}"
TESTNET_LOG_DIR="${TESTNET_LOG_DIR:-/var/log/usdmd-testnet}"
TESTNET_USER="${TESTNET_USER:-usdmd-testnet}"

# Sidecar Tor sits next to the daemon. Service user is the daemon's
# user so it can read the HiddenServiceDir's hostname file.
TOR_DATA_DIR="${TOR_DATA_DIR:-/var/lib/usdmd-tor}"
TOR_HSDIR="$TOR_DATA_DIR/hs"
TOR_LOG="$TESTNET_LOG_DIR/tor.log"
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-19051}"

# USDmd ports — all loopback.
TESTNET_RPC_PORT=28080
TESTNET_P2P_PORT=28081     # loopback only; never bound to a public iface
TESTNET_ZMQ_PORT=28082
OBIND_PORT=18083           # 127.0.0.1:OBIND_PORT — Tor maps this to vport

USDMD_UNIT="USDmd-testnet.service"
TOR_UNIT="USDmd-tor.service"

# ---------------------------------------------------------------------------
# CLI parse
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-tag)       NODE_TAG="$2";       shift 2 ;;
    --peer-1-onion)   PEER_1_ONION="$2";   shift 2 ;;
    --peer-2-onion)   PEER_2_ONION="$2";   shift 2 ;;
    --peer-vport)     PEER_VPORT="$2";     shift 2 ;;
    --bin-path)       TESTNET_BIN_PATH="$2"; shift 2 ;;
    --data-dir)       TESTNET_DATA_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,60p' "$0"; exit 0 ;;
    *)
      echo "[install-vps-onion] unknown flag: $1" >&2
      exit 2 ;;
  esac
done

if [[ -z "$NODE_TAG" ]]; then
  echo "[install-vps-onion] FATAL — required: --node-tag <A|B|C>" >&2
  exit 2
fi

echo "[install-vps-onion] node-tag       : $NODE_TAG"
echo "[install-vps-onion] bin-path       : $TESTNET_BIN_PATH"
echo "[install-vps-onion] tor data-dir   : $TOR_DATA_DIR"
echo "[install-vps-onion] usdmd data-dir : $TESTNET_DATA_DIR"
echo "[install-vps-onion] tor SOCKS      : 127.0.0.1:$TOR_SOCKS_PORT"
echo "[install-vps-onion] usdmd RPC      : 127.0.0.1:$TESTNET_RPC_PORT (loopback only)"
echo "[install-vps-onion] usdmd P2P      : 127.0.0.1:$TESTNET_P2P_PORT (loopback only — onion-served)"
echo "[install-vps-onion] anon-inbound   : <self>.onion:$PEER_VPORT -> 127.0.0.1:$OBIND_PORT"
echo "[install-vps-onion] peer 1         : ${PEER_1_ONION:-(none — bootstrap node)}"
echo "[install-vps-onion] peer 2         : ${PEER_2_ONION:-(none — bootstrap node)}"

# ---------------------------------------------------------------------------
# Pre-flight: root + dependencies
# ---------------------------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
  echo "[install-vps-onion] FATAL — must run as root" >&2
  exit 1
fi

# Install tor if missing. ufw is NOT required (no public ports to open).
if ! command -v tor >/dev/null 2>&1; then
  echo "[install-vps-onion] installing tor via apt"
  apt-get update -y >/dev/null
  apt-get install -y tor >/dev/null
fi
TOR_BIN="$(command -v tor)"

# ---------------------------------------------------------------------------
# DAG-binary verification (mirror of wallet's W24.3 gate).
# Refusing a legacy USDmd here protects the entire mesh from a
# fork-the-chain regression.
# ---------------------------------------------------------------------------
if [[ ! -x "$TESTNET_BIN_PATH" ]]; then
  echo "[install-vps-onion] FATAL — binary not found: $TESTNET_BIN_PATH" >&2
  exit 1
fi
if ! strings "$TESTNET_BIN_PATH" 2>/dev/null \
     | grep -q 'DAG-GHOSTDAG\|DAG_PARENT_HASHES\|TX_EXTRA_TAG_DAG'; then
  echo "[install-vps-onion] FATAL — binary lacks DAG-GHOSTDAG markers" >&2
  echo "[install-vps-onion]   refusing to install a legacy USDmd into the testnet mesh" >&2
  exit 1
fi
echo "[install-vps-onion] DAG-binary marker OK"

# ---------------------------------------------------------------------------
# Service user + directories
# ---------------------------------------------------------------------------
if ! id -u "$TESTNET_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$TESTNET_USER"
  echo "[install-vps-onion] created service user $TESTNET_USER"
fi
mkdir -p "$TESTNET_DATA_DIR" "$TESTNET_LOG_DIR" "$TOR_DATA_DIR/data" "$TOR_HSDIR"
chown -R "$TESTNET_USER:$TESTNET_USER" "$TESTNET_DATA_DIR" "$TESTNET_LOG_DIR" "$TOR_DATA_DIR"
chmod 0750 "$TESTNET_DATA_DIR" "$TESTNET_LOG_DIR" "$TOR_DATA_DIR"
chmod 0700 "$TOR_HSDIR"

# ---------------------------------------------------------------------------
# 1. Sidecar Tor: torrc + systemd unit
# ---------------------------------------------------------------------------
cat > "$TOR_DATA_DIR/torrc" <<EOF
DataDirectory $TOR_DATA_DIR/data
SocksPort 127.0.0.1:$TOR_SOCKS_PORT
Log notice file $TOR_LOG
HiddenServiceDir $TOR_HSDIR
HiddenServiceVersion 3
HiddenServicePort $PEER_VPORT 127.0.0.1:$OBIND_PORT
EOF
chown "$TESTNET_USER:$TESTNET_USER" "$TOR_DATA_DIR/torrc"
chmod 0600 "$TOR_DATA_DIR/torrc"

cat > "/etc/systemd/system/$TOR_UNIT" <<EOF
[Unit]
Description=Sidecar Tor for MoneroUSD DAG-USDmd testnet Node $NODE_TAG
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$TESTNET_USER
Group=$TESTNET_USER
ExecStart=$TOR_BIN -f $TOR_DATA_DIR/torrc
Restart=on-failure
RestartSec=10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$TOR_DATA_DIR $TESTNET_LOG_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "/etc/systemd/system/$TOR_UNIT"

systemctl daemon-reload
systemctl enable "$TOR_UNIT" >/dev/null
systemctl restart "$TOR_UNIT"

# ---------------------------------------------------------------------------
# 2. Wait for Tor bootstrap + .onion provisioning
# ---------------------------------------------------------------------------
echo "[install-vps-onion] waiting for Tor bootstrap + .onion provisioning ..."
ONION=""
for i in $(seq 1 60); do
  if [ -f "$TOR_HSDIR/hostname" ] && grep -q "Bootstrapped 100%" "$TOR_LOG" 2>/dev/null; then
    ONION="$(cat "$TOR_HSDIR/hostname" 2>/dev/null || true)"
    if [ -n "$ONION" ]; then break; fi
  fi
  sleep 2
done
if [ -z "$ONION" ]; then
  echo "[install-vps-onion] FATAL — onion not provisioned within 120s" >&2
  tail -20 "$TOR_LOG" 2>/dev/null
  exit 1
fi
echo "$ONION" > "$TOR_DATA_DIR/node.onion"
chown "$TESTNET_USER:$TESTNET_USER" "$TOR_DATA_DIR/node.onion"
echo "[install-vps-onion] Node $NODE_TAG onion identity: $ONION"

# ---------------------------------------------------------------------------
# 3. USDmd systemd unit — ONION-ONLY P2P
# ---------------------------------------------------------------------------
# Build the per-peer --add-priority-node args. Empty values are
# tolerated (bootstrap node case — we install with no peers first,
# then rerun once we have the other two .onions).
PEER_ARGS=""
if [[ -n "$PEER_1_ONION" ]]; then
  PEER_ARGS="$PEER_ARGS --add-priority-node $PEER_1_ONION:$PEER_VPORT"
fi
if [[ -n "$PEER_2_ONION" ]]; then
  PEER_ARGS="$PEER_ARGS --add-priority-node $PEER_2_ONION:$PEER_VPORT"
fi

cat > "/etc/systemd/system/$USDMD_UNIT" <<EOF
[Unit]
Description=MoneroUSD DAG-USDmd testnet (Node $NODE_TAG, ONION-ONLY)
After=network-online.target $TOR_UNIT
Wants=network-online.target
Requires=$TOR_UNIT

[Service]
Type=simple
User=$TESTNET_USER
Group=$TESTNET_USER

Environment=MONEROUSD_ONION_ONLY=1

ExecStart=$TESTNET_BIN_PATH \\
    --testnet \\
    --non-interactive \\
    --no-igd \\
    --hide-my-port \\
    --confirm-external-bind \\
    --data-dir $TESTNET_DATA_DIR \\
    --rpc-bind-ip 127.0.0.1 \\
    --rpc-bind-port $TESTNET_RPC_PORT \\
    --p2p-bind-ip 127.0.0.1 \\
    --p2p-bind-port $TESTNET_P2P_PORT \\
    --zmq-rpc-bind-ip 127.0.0.1 \\
    --zmq-rpc-bind-port $TESTNET_ZMQ_PORT \\
    --tx-proxy tor,127.0.0.1:$TOR_SOCKS_PORT,16 \\
    --anonymous-inbound $ONION:$PEER_VPORT,127.0.0.1:$OBIND_PORT,16 \\
    $PEER_ARGS \\
    --log-file $TESTNET_LOG_DIR/usdmd-testnet.log \\
    --log-level 0

Restart=on-failure
RestartSec=10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$TESTNET_DATA_DIR $TESTNET_LOG_DIR
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "/etc/systemd/system/$USDMD_UNIT"

systemctl daemon-reload
systemctl enable "$USDMD_UNIT" >/dev/null
systemctl restart "$USDMD_UNIT"

# ---------------------------------------------------------------------------
# 4. Wait for RPC + summary
# ---------------------------------------------------------------------------
echo "[install-vps-onion] waiting for USDmd RPC on 127.0.0.1:$TESTNET_RPC_PORT ..."
for i in $(seq 1 30); do
  if curl -sm 2 "http://127.0.0.1:$TESTNET_RPC_PORT/json_rpc" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' 2>/dev/null \
      | grep -q '"status"'; then
    cat <<EOF

[install-vps-onion] OK — Node $NODE_TAG ONLINE (onion-only)

  systemd units : $TOR_UNIT, $USDMD_UNIT
  status        : systemctl status $USDMD_UNIT
  logs          : journalctl -u $USDMD_UNIT -f

  THIS NODE'S ONION (share with the other 2 mesh nodes):

    $ONION

  Re-run this script on the other nodes with:

    --peer-1-onion $ONION   (if this is their first peer)
    --peer-2-onion $ONION   (if they already had a peer-1)

EOF
    exit 0
  fi
  sleep 1
done

echo "[install-vps-onion] FATAL — RPC did not come up within 30s" >&2
echo "[install-vps-onion]   journalctl -u $USDMD_UNIT -n 50" >&2
exit 1

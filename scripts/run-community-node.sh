#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# run-community-node.sh — one-command MoneroUSD community node bootstrap.
#
# What this does, in order:
#   1. Verifies build / install prerequisites (curl, tar, zstd, awk).
#   2. Downloads the latest signed USDmd binary + SHA256SUMS from
#      update.monerousd.org/bin/<platform>-<arch>/.
#   3. Verifies the SHA-256 of the binary against the manifest.
#   4. Installs to ~/.monerousd/bin/USDmd (chmod 0755).
#   5. Drops a systemd-user / launchd unit so the node runs in the
#      background regardless of whether any wallet UI is open.
#   6. Starts the daemon. From here on launchd / systemd-user keeps
#      it up across reboot / sleep / wake / crash.
#
# After this script finishes, the node is part of the MoneroUSD
# P2P mesh. The first ~30 seconds will discover seeds; from that
# point on the node automatically gossips chain state to other
# nodes, serves any wallet that points at it, and adds resilience
# to the network as a whole.
#
# Idempotent: re-running upgrades binaries in place and reloads the
# service unit. Does NOT touch wallet keys or wallet data.

set -euo pipefail

OTA_HOST="${OTA_HOST:-update.monerousd.org}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.monerousd}"
BIN_DIR="$INSTALL_DIR/bin"
DATA_DIR="$INSTALL_DIR/blockchain"
LOG_DIR="$INSTALL_DIR/logs"

# Network ports (mainnet)
P2P_PORT=17749
RPC_PORT=17750

mkdir -p "$BIN_DIR" "$DATA_DIR" "$LOG_DIR"

# ── Detect platform ────────────────────────────────────────────────
case "$(uname -s)" in
  Darwin) PLAT=mac ;;
  Linux)  PLAT=linux ;;
  *) echo "Unsupported OS: $(uname -s) — please run on macOS or Linux." >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "Unsupported arch: $(uname -m)" >&2; exit 2 ;;
esac
TARGET="${PLAT}-${ARCH}"

echo "MoneroUSD community node bootstrap — target: $TARGET"
echo "  install dir: $INSTALL_DIR"
echo "  data dir:    $DATA_DIR"

# ── Tool dependencies ──────────────────────────────────────────────
for tool in curl tar awk grep shasum; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Missing required tool: $tool" >&2; exit 2; }
done

# ── Fetch + verify USDmd binary ────────────────────────────────────
SUM_URL="https://${OTA_HOST}/bin/${TARGET}/SHA256SUMS"
BIN_URL="https://${OTA_HOST}/bin/${TARGET}/USDmd"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading SHA256SUMS manifest..."
curl -fsSL "$SUM_URL" -o "$TMP/SHA256SUMS"

echo "Downloading USDmd binary (this may take a minute)..."
curl -fsSL "$BIN_URL" -o "$TMP/USDmd"

echo "Verifying SHA-256..."
EXPECTED=$(awk '/USDmd$/{print $1}' "$TMP/SHA256SUMS")
ACTUAL=$(shasum -a 256 "$TMP/USDmd" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA-256 mismatch!"
  echo "  expected: $EXPECTED"
  echo "  actual:   $ACTUAL"
  echo "Refusing to install. Aborting."
  exit 3
fi
echo "  OK — $ACTUAL"

install -m 0755 "$TMP/USDmd" "$BIN_DIR/USDmd"
echo "Installed: $BIN_DIR/USDmd"

# ── Build the daemon-args list ─────────────────────────────────────
# Args mirror the launchd/systemd units shipped with the desktop
# wallet so the same binary behaves identically across single-user
# (wallet) and operator (this script) installs.
DAEMON_ARGS=(
  "$BIN_DIR/USDmd"
  --data-dir "$DATA_DIR"
  --rpc-bind-ip 127.0.0.1
  --rpc-bind-port "$RPC_PORT"
  --p2p-bind-port "$P2P_PORT"
  --confirm-external-bind
  --non-interactive
  --log-level 1
  --log-file "$LOG_DIR/usdmd.log"
  --max-concurrency 4
  --block-sync-size 200
  --disable-dns-checkpoints
  --bootstrap-daemon-address ${MONEROUSD_EDGE_HOST}:17750
  --add-peer ${MONEROUSD_EDGE_HOST}:17749
  --add-peer ${MONEROUSD_VPS_HOST}:17749
)

# ── Install the service unit ───────────────────────────────────────
if [ "$PLAT" = "mac" ]; then
  PLIST="$HOME/Library/LaunchAgents/org.monerousd.usdmd.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    printf '<plist version="1.0"><dict>\n'
    printf '  <key>Label</key><string>org.monerousd.usdmd</string>\n'
    printf '  <key>RunAtLoad</key><true/>\n'
    printf '  <key>KeepAlive</key><true/>\n'
    printf '  <key>ThrottleInterval</key><integer>10</integer>\n'
    printf '  <key>StandardOutPath</key><string>%s/usdmd.out.log</string>\n' "$LOG_DIR"
    printf '  <key>StandardErrorPath</key><string>%s/usdmd.err.log</string>\n' "$LOG_DIR"
    printf '  <key>ProcessType</key><string>Background</string>\n'
    printf '  <key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>\n'
    printf '  <key>HardResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>\n'
    printf '  <key>ProgramArguments</key>\n  <array>\n'
    for a in "${DAEMON_ARGS[@]}"; do printf '    <string>%s</string>\n' "$a"; done
    printf '  </array>\n'
    printf '</dict></plist>\n'
  } > "$PLIST"
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load -w "$PLIST"
  echo "Installed launchd agent: $PLIST"
  echo "  manage:   launchctl unload/load \"$PLIST\""
  echo "  uninstall: rm \"$PLIST\""
else
  UNIT="$HOME/.config/systemd/user/usdmd.service"
  mkdir -p "$(dirname "$UNIT")"
  {
    printf '[Unit]\nDescription=MoneroUSD community node\nAfter=network-online.target\n\n'
    printf '[Service]\nType=simple\nLimitNOFILE=65536\nRestart=always\nRestartSec=10\n'
    printf 'ExecStart='
    for a in "${DAEMON_ARGS[@]}"; do printf '%s ' "$a"; done; printf '\n\n'
    printf '[Install]\nWantedBy=default.target\n'
  } > "$UNIT"
  systemctl --user daemon-reload
  systemctl --user enable usdmd.service
  systemctl --user restart usdmd.service
  echo "Installed systemd-user unit: $UNIT"
  echo "  manage:   systemctl --user {start,stop,restart,status} usdmd"
  echo "  uninstall: systemctl --user disable usdmd && rm \"$UNIT\""
fi

echo
echo "── Done ─────────────────────────────────────────────────────────"
echo "Node is running in the background and will auto-restart on crash"
echo "and on reboot. Logs at: $LOG_DIR"
echo
echo "Verify with:"
echo "  curl -s http://127.0.0.1:${RPC_PORT}/get_info | head"
echo
echo "Submit your public IP to the volunteer-seed list so other nodes"
echo "can find you (optional but encouraged):"
echo "  https://github.com/casdevmonero/monerousd-volunteer-seeds"
echo

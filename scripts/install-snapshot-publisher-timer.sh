#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#
# install-snapshot-publisher-timer.sh — Layer 9c installer.
#
# Installs a periodic timer that runs publish-chain-snapshot.sh.
# Portable across Linux (systemd --user) and macOS (launchd user
# agent). Cron-compatible fallback if neither is available.
#
# WHY THIS IS NOT VPS-SPECIFIC
# ───────────────────────────
# ANY operator with manifest-repo write access (= holds an
# appropriately-scoped GitHub PAT in their gh config) can host this
# timer. The wallet network is healthier when multiple operators
# run the publisher in parallel: whoever publishes most recently
# wins (the SKIP_IF_HEIGHT_WITHIN gate prevents redundant publishes
# when the live manifest is already fresh).
#
# Network-availability math:
#   - 1 publisher  → publisher uptime ≈ network freshness
#   - 2 publishers → P(stale) = P(both offline) — way better
#   - N publishers → exponential robustness, no SPOF
#
# So this script is INTENDED to be installed by every operator who
# runs a USDmd node and can write to monerousd-ota-manifest. The
# default cadence (every 12h with a random jitter) means multiple
# installations don't beat each other to death.
#
# USAGE
# ─────
#   bash scripts/install-snapshot-publisher-timer.sh
#
# This is idempotent — re-run any time to refresh the timer config.
#
# UNINSTALL
# ─────────
#   bash scripts/install-snapshot-publisher-timer.sh --uninstall
#

set -euo pipefail

SCRIPT_PATH="${SCRIPT_PATH:-$(cd "$(dirname "$0")" && pwd)/publish-chain-snapshot.sh}"
INTERVAL_HOURS="${INTERVAL_HOURS:-12}"
JITTER_SECONDS="${JITTER_SECONDS:-900}"   # ±15 min jitter so multiple operators don't sync up
TIMER_LABEL="com.monerousd.publish-chain-snapshot"
ACTION="${1:-install}"

[ -x "$SCRIPT_PATH" ] || { echo "publisher script not found or not executable: $SCRIPT_PATH"; exit 1; }

PLATFORM=$(uname -s)

# ──────────────────────────────────────────────────────────────────
# macOS — launchd user agent
# ──────────────────────────────────────────────────────────────────

install_launchd() {
  local plist="$HOME/Library/LaunchAgents/${TIMER_LABEL}.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  mkdir -p "$HOME/Library/Logs/MoneroUSD"

  local interval_seconds=$(( INTERVAL_HOURS * 3600 ))

  cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${TIMER_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${SCRIPT_PATH}</string>
  </array>
  <key>StartInterval</key>
  <integer>${interval_seconds}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${HOME}/Library/Logs/MoneroUSD/snapshot-publisher.out.log</string>
  <key>StandardErrorPath</key>
  <string>${HOME}/Library/Logs/MoneroUSD/snapshot-publisher.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${HOME}</string>
    <key>PATH</key>
    <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>LOG_FILE</key>
    <string>${HOME}/Library/Logs/MoneroUSD/snapshot-publisher.log</string>
    <key>LOCK_FILE</key>
    <string>/tmp/monerousd-publish-snapshot.lock</string>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
</dict>
</plist>
EOF

  if [ "$ACTION" = "uninstall" ]; then
    launchctl unload "$plist" 2>/dev/null || true
    rm -f "$plist"
    echo "uninstalled: $plist"
    return
  fi

  launchctl unload "$plist" 2>/dev/null || true
  launchctl load -w "$plist"
  echo "installed launchd agent at: $plist"
  echo "first run will fire on next load (RunAtLoad=true)"
  echo "subsequent runs every $INTERVAL_HOURS hours"
}

# ──────────────────────────────────────────────────────────────────
# Linux — systemd --user timer
# ──────────────────────────────────────────────────────────────────

install_systemd() {
  local svc_dir="$HOME/.config/systemd/user"
  mkdir -p "$svc_dir"

  local svc="$svc_dir/${TIMER_LABEL}.service"
  local timer="$svc_dir/${TIMER_LABEL}.timer"

  cat > "$svc" <<EOF
[Unit]
Description=MoneroUSD chain-snapshot publisher (Layer 9c)
Documentation=https://github.com/casdevmonero/monerousd-ota-manifest

[Service]
Type=oneshot
ExecStart=/bin/bash ${SCRIPT_PATH}
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

# Don't fail the unit if the publish is a no-op (skip-if-fresh gate).
SuccessExitStatus=0
EOF

  cat > "$timer" <<EOF
[Unit]
Description=MoneroUSD chain-snapshot publisher timer (Layer 9c, every ${INTERVAL_HOURS}h)

[Timer]
# 1 minute after boot, then every INTERVAL_HOURS hours with up to
# JITTER_SECONDS jitter so multiple operators don't collide.
OnBootSec=1min
OnUnitActiveSec=${INTERVAL_HOURS}h
RandomizedDelaySec=${JITTER_SECONDS}
Persistent=true
Unit=${TIMER_LABEL}.service

[Install]
WantedBy=timers.target
EOF

  if [ "$ACTION" = "uninstall" ]; then
    systemctl --user stop "${TIMER_LABEL}.timer" 2>/dev/null || true
    systemctl --user disable "${TIMER_LABEL}.timer" 2>/dev/null || true
    rm -f "$svc" "$timer"
    systemctl --user daemon-reload
    echo "uninstalled systemd timer"
    return
  fi

  systemctl --user daemon-reload
  systemctl --user enable --now "${TIMER_LABEL}.timer"
  echo "installed systemd --user timer: ${TIMER_LABEL}.timer"
  echo "first run: 1 min after boot OR ${INTERVAL_HOURS}h after last activation"
  echo ""
  echo "Status: systemctl --user status ${TIMER_LABEL}.timer"
  echo "Logs:   journalctl --user -u ${TIMER_LABEL}.service"
}

# ──────────────────────────────────────────────────────────────────
# Cron fallback (any POSIX with crond)
# ──────────────────────────────────────────────────────────────────

install_cron() {
  if [ "$ACTION" = "uninstall" ]; then
    crontab -l 2>/dev/null | grep -v "publish-chain-snapshot.sh" | crontab -
    echo "uninstalled cron entry (lines matching publish-chain-snapshot.sh)"
    return
  fi
  local cron_line="0 */${INTERVAL_HOURS} * * * /bin/bash ${SCRIPT_PATH}"
  ( crontab -l 2>/dev/null | grep -v "publish-chain-snapshot.sh"; echo "$cron_line" ) | crontab -
  echo "installed cron entry: $cron_line"
}

# ──────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────

case "$PLATFORM" in
  Darwin)
    install_launchd
    ;;
  Linux)
    if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
      install_systemd
    elif command -v crontab >/dev/null 2>&1; then
      install_cron
    else
      echo "no systemd --user or cron available; install one + re-run"
      exit 1
    fi
    ;;
  *)
    echo "unsupported platform: $PLATFORM. Manually invoke publish-chain-snapshot.sh every ${INTERVAL_HOURS}h."
    exit 1
    ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Layer 9c snapshot-publisher timer installed."
echo "Multiple operators running this timer increases network"
echo "freshness — the wallet's manifest fetch picks up the latest"
echo "valid snapshot regardless of which operator published it."
echo "════════════════════════════════════════════════════════════"

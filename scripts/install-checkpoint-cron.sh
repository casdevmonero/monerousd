#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# install-checkpoint-cron.sh — schedule the checkpoint publisher
# to run weekly under launchd.
#
# What this gives you:
#   • Every Sunday at 04:00 local time, `publish-checkpoints-auto.js`
#     runs from your account. It mints an ephemeral Njalla API token,
#     publishes the latest 5-checkpoint slate to the DNS zone, and
#     revokes the ephemeral token before exiting.
#   • Output goes to `~/Library/Logs/MoneroUSD/checkpoint-cron.log`.
#   • If the publish fails (Njalla unreachable, daemon RPC unreachable,
#     etc.), launchd retries every 5 minutes for up to an hour, then
#     waits until the next Sunday.
#
# Requirements (one-time):
#   1. Bootstrap token stored in Keychain. Run:
#        bash scripts/njalla-keychain.sh set
#      (paste the token at the hidden prompt).
#   2. macOS Keychain unlocked at boot (default).
#
# Usage:
#   bash scripts/install-checkpoint-cron.sh         # install + load
#   bash scripts/install-checkpoint-cron.sh --remove # uninstall + unload
#   bash scripts/install-checkpoint-cron.sh --run-now # one-off test run

set -euo pipefail

PLIST="$HOME/Library/LaunchAgents/com.monerousd.checkpoint-publisher.plist"
LABEL="com.monerousd.checkpoint-publisher"
SCRIPT="$(cd "$(dirname "$0")" && pwd)/publish-checkpoints-auto.js"
LOG_DIR="$HOME/Library/Logs/MoneroUSD"
NODE_BIN="$(command -v node 2>/dev/null || true)"

cmd="${1:-install}"

if [ "$cmd" = "--remove" ]; then
  if [ -f "$PLIST" ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "removed $PLIST"
  else
    echo "no installed plist found at $PLIST"
  fi
  exit 0
fi

if [ "$cmd" = "--run-now" ]; then
  mkdir -p "$LOG_DIR"
  node "$SCRIPT" 2>&1 | tee -a "$LOG_DIR/checkpoint-cron.log"
  exit 0
fi

# ── install ──
if [ -z "$NODE_BIN" ]; then
  echo "ERROR: node not found on PATH. Install Node.js + re-run." >&2
  exit 2
fi
if [ ! -f "$SCRIPT" ]; then
  echo "ERROR: $SCRIPT not found" >&2
  exit 3
fi
# Verify bootstrap token is already in Keychain — refuse to install
# a schedule that would fail at every run.
if ! bash "$(dirname "$0")/njalla-keychain.sh" get >/dev/null 2>&1; then
  echo "ERROR: bootstrap token not in Keychain. Run \`bash scripts/njalla-keychain.sh set\` first." >&2
  exit 4
fi

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$PLIST")"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>

  <key>ProgramArguments</key>
  <array>
    <string>$NODE_BIN</string>
    <string>$SCRIPT</string>
  </array>

  <!-- Sundays at 04:00 local time. -->
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key><integer>0</integer>
    <key>Hour</key><integer>4</integer>
    <key>Minute</key><integer>0</integer>
  </dict>

  <!-- If the publish fails, retry every 5 minutes up to an hour. -->
  <key>ThrottleInterval</key>
  <integer>300</integer>

  <key>StandardOutPath</key>
  <string>$LOG_DIR/checkpoint-cron.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/checkpoint-cron.log</string>

  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>

  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
EOF

# Unload any prior version, then load the new one.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo "installed:        $PLIST"
echo "label:            $LABEL"
echo "schedule:         every Sunday 04:00 local"
echo "log file:         $LOG_DIR/checkpoint-cron.log"
echo
echo "Next steps:"
echo "  • To verify it'll run, do a one-off test:"
echo "      bash $0 --run-now"
echo "  • To see the next scheduled run:"
echo "      launchctl print gui/\$(id -u)/$LABEL | grep -E 'next-time|state'"
echo "  • To uninstall:"
echo "      bash $0 --remove"

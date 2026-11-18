#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#
# auto-republish-peer-manifest.sh — operator-side cron wrapper around
# publish-peer-manifest.js + git push.
#
# What this does
# ──────────────
# Runs every 12 hours (per the launchd plist that loads it) to keep
# the chain-anchored peer manifest fresh on the GH Pages mirror. The
# manifest's TTL is 1024 blocks (~17h at 60s target block time); if
# the operator forgets to refresh, every wallet's fetcher will skip
# the cached manifest as expired and fall back to the hardcoded
# floor (which still works, but loses the dynamic seed surface).
#
# Idempotent: if the manifest at update.monerousd.org/peer-manifest.json
# is less than `MIN_REPUBLISH_AGE_HOURS` old AND covers a chain tip
# within 256 blocks of the current tip, we skip the republish. This
# prevents tight loops on a machine whose clock drifts or where the
# script gets fired more often than expected.
#
# Failure modes are LOGGED to ~/.monerousd/logs/peer-manifest-republish.log
# but do NOT abort the script — a missing manifest is recoverable on
# the next run; a hard-fail here doesn't help anyone.
#
# Activation
# ──────────
#   1. Test once: SKIP_GIT_PUSH=1 bash scripts/auto-republish-peer-manifest.sh
#   2. Install the launchd plist:
#        launchctl load ~/Library/LaunchAgents/com.monerousd.peer-manifest-republish.plist
#   3. Verify it's loaded:
#        launchctl list | grep peer-manifest-republish
#

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────

CONNECT_ROOT="${CONNECT_ROOT:-$HOME/Desktop/connect}"
GH_PAGES_CLONE="${GH_PAGES_CLONE:-/tmp/monerousd-ota-manifest}"
LIVE_URL="https://update.monerousd.org/peer-manifest.json"
MIN_REPUBLISH_AGE_HOURS="${MIN_REPUBLISH_AGE_HOURS:-12}"
TIP_DRIFT_THRESHOLD="${TIP_DRIFT_THRESHOLD:-256}"
LOG_DIR="$HOME/.monerousd/logs"
LOG_FILE="$LOG_DIR/peer-manifest-republish.log"

mkdir -p "$LOG_DIR"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

log "─── peer-manifest auto-republish run ───"

# ── 1. Probe live manifest age + height ──────────────────────────

LIVE_TMP=$(mktemp -t peer-manifest-XXXXXX.json)
trap 'rm -f "$LIVE_TMP"' EXIT

if ! curl -sf --max-time 10 -o "$LIVE_TMP" "$LIVE_URL"; then
  log "live manifest fetch failed — proceeding with republish (assume stale)"
  LIVE_AGE_HOURS=999
  LIVE_HEIGHT=0
else
  # publish_at_block_height from the manifest body.
  LIVE_HEIGHT=$(node -e '
    try {
      const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      const h = (m.manifest && m.manifest.published_at_block_height) || 0;
      console.log(h);
    } catch (_) { console.log(0); }
  ' "$LIVE_TMP")

  # GH Pages doesn't reliably ship a Last-Modified — use head of file
  # mtime via the git history. Simpler heuristic: compare the live
  # height to the local daemon's height; if the local has moved
  # forward by > TIP_DRIFT_THRESHOLD, it's time to republish.
  LIVE_AGE_HOURS=0  # default — we'll decide based on height drift below
fi

# ── 2. Probe local daemon for current height ─────────────────────

LOCAL_INFO=$(curl -sf --max-time 5 -X POST \
  http://127.0.0.1:17750/get_info \
  -H "Content-Type: application/json" -d '{}' || true)

if [ -z "$LOCAL_INFO" ]; then
  log "local daemon RPC unreachable — cannot determine current tip"
  log "skip republish (no fresh height to bake in)"
  exit 0
fi

LOCAL_HEIGHT=$(printf '%s' "$LOCAL_INFO" | node -e '
  let d=""; process.stdin.on("data",c=>d+=c);
  process.stdin.on("end",()=>{ try { console.log(JSON.parse(d).height || 0); } catch (_) { console.log(0); } });
' 2>/dev/null)

if [ -z "$LOCAL_HEIGHT" ] || [ "$LOCAL_HEIGHT" -lt 1 ]; then
  log "local daemon returned invalid height — abort"
  exit 0
fi

DRIFT=$(( LOCAL_HEIGHT - LIVE_HEIGHT ))
log "live manifest height=$LIVE_HEIGHT  local daemon height=$LOCAL_HEIGHT  drift=$DRIFT"

# ── 3. Decide: republish or skip ─────────────────────────────────

if [ "$LIVE_HEIGHT" -gt 0 ] && [ "$DRIFT" -lt "$TIP_DRIFT_THRESHOLD" ]; then
  log "live manifest is within $TIP_DRIFT_THRESHOLD blocks of tip — skip"
  exit 0
fi

log "republishing — drift $DRIFT ≥ threshold $TIP_DRIFT_THRESHOLD blocks"

# ── 4. Run the publisher ─────────────────────────────────────────

cd "$CONNECT_ROOT"
if ! node scripts/publish-peer-manifest.js >>"$LOG_FILE" 2>&1; then
  log "publish-peer-manifest.js FAILED — see log above"
  exit 1
fi

if [ ! -f "$CONNECT_ROOT/_release/peer-manifest.json" ]; then
  log "expected _release/peer-manifest.json missing after publisher run"
  exit 1
fi

# ── 5. Push to GH Pages ──────────────────────────────────────────

if [ "${SKIP_GIT_PUSH:-0}" = "1" ]; then
  log "SKIP_GIT_PUSH=1 — skipping git operations (test mode)"
  log "─── done (test mode) ───"
  exit 0
fi

if [ ! -d "$GH_PAGES_CLONE/.git" ]; then
  log "cloning monerousd-ota-manifest to $GH_PAGES_CLONE"
  git clone --depth 1 \
    https://github.com/casdevmonero/monerousd-ota-manifest.git \
    "$GH_PAGES_CLONE" >>"$LOG_FILE" 2>&1
fi

cd "$GH_PAGES_CLONE"
git pull --rebase --quiet >>"$LOG_FILE" 2>&1 || log "git pull failed — continuing anyway"

cp "$CONNECT_ROOT/_release/peer-manifest.json" ./peer-manifest.json

if git diff --quiet -- peer-manifest.json 2>/dev/null; then
  log "no diff vs HEAD — nothing to commit"
  exit 0
fi

git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
  add peer-manifest.json
git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
  commit -m "peer-manifest: auto-republish (height $LOCAL_HEIGHT, drift $DRIFT)" \
  >>"$LOG_FILE" 2>&1

if ! git push origin main >>"$LOG_FILE" 2>&1; then
  log "git push FAILED — manifest committed locally but not live"
  exit 1
fi

log "pushed — manifest live within ~30s at $LIVE_URL"
log "─── done ───"

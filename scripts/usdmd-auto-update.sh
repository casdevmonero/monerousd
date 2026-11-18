#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# usdmd-auto-update.sh — pull latest USDmd bundle from canonical
# manifest, verify SHA-256, atomic-swap, restart, health-check, and
# auto-rollback on failure.
#
# Runs via cron (default every 6h) on every USDmd peer node. Closes
# the v1.2.205 incident class where the edge ran a stale Apr 20
# binary that didn't recognize tokens-v2 / v30 hardfork rules and
# stalled at height 92701 for 23,575 blocks.
#
# CANONICAL TRUST MODEL (Phase 1 — labeled rule-110d stopgap)
#
#   Trust anchor: the manifest URL itself
#     https://update.monerousd.org/usdmd-bundle/manifest.json
#   This is operator-controlled today (single point of trust).
#
#   Phase 2 (planned): manifest is ed25519-signed by a quorum of
#   active validators. The watchdog verifies the aggregate FROST
#   signature against the on-chain validator-set-root before
#   trusting the manifest. Until then this script verifies SHA-256
#   ONLY — anyone with control of the canonical hostname can push a
#   bundle. This is acceptable for SOLO bootstrap (you ARE the
#   operator); not acceptable once community validators join.
#
# SAFETY GUARDRAILS
#
#   1. Only updates UPWARD (version compare; no downgrade).
#   2. SHA-256 verification of the downloaded bundle.
#   3. Pre-swap snapshot — bundle backed up to .bak-<TS>.
#   4. Post-swap health check — daemon must be running + syncing
#      within HEALTH_CHECK_GRACE_S, else rollback to backup.
#   5. Lockfile prevents concurrent updates (cron racing itself).
#   6. Logs to /var/log/usdmd-auto-update.log.
#
# USAGE
#
#   /usr/local/bin/usdmd-auto-update.sh         # update if newer
#   /usr/local/bin/usdmd-auto-update.sh --check # report-only
#   /usr/local/bin/usdmd-auto-update.sh --force # update regardless
#
# Cron: every 6 hours, default
#   /etc/cron.d/usdmd-auto-update:
#   0 */6 * * * root /usr/local/bin/usdmd-auto-update.sh >> /var/log/usdmd-auto-update.log 2>&1

set -euo pipefail

MANIFEST_URL="${MANIFEST_URL:-https://update.monerousd.org/usdmd-bundle/manifest.json}"
BUNDLE_DIR="${BUNDLE_DIR:-/root/usdmd-bundle}"
LOCAL_VERSION_FILE="${BUNDLE_DIR}/.bundle-version"
LOCK_FILE="/var/lock/usdmd-auto-update.lock"
LOG_TAG="[usdmd-auto-update]"
HEALTH_CHECK_GRACE_S="${HEALTH_CHECK_GRACE_S:-60}"
RPC_URL="${RPC_URL:-http://127.0.0.1:17750/json_rpc}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-USDmd.service}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $LOG_TAG $*"; }
fail() { log "ERROR: $*"; exit 1; }

MODE=update
case "${1:-}" in
  --check) MODE=check ;;
  --force) MODE=force ;;
  '') MODE=update ;;
  *) fail "unknown arg: $1" ;;
esac

# ── Single-instance lock ─────────────────────────────────────────
exec 9>"$LOCK_FILE"
flock -n 9 || { log "another update in progress (lock held); skipping"; exit 0; }

# ── Fetch + verify manifest ──────────────────────────────────────
log "fetching manifest from $MANIFEST_URL"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
MANIFEST_FILE="$TMPDIR/manifest.json"

if ! curl -sSf --max-time 30 -o "$MANIFEST_FILE" "$MANIFEST_URL"; then
  fail "manifest fetch failed (network unreachable or 4xx/5xx)"
fi

REMOTE_VERSION=$(jq -r '.version // empty' "$MANIFEST_FILE")
REMOTE_BUNDLE_URL=$(jq -r '.bundle_url // empty' "$MANIFEST_FILE")
REMOTE_BUNDLE_SHA256=$(jq -r '.bundle_sha256 // empty' "$MANIFEST_FILE")
REMOTE_BINARY_MD5=$(jq -r '.binary_md5 // empty' "$MANIFEST_FILE")
REMOTE_RELEASED_AT=$(jq -r '.released_at // empty' "$MANIFEST_FILE")

[ -n "$REMOTE_VERSION" ]     || fail "manifest missing 'version'"
[ -n "$REMOTE_BUNDLE_URL" ]  || fail "manifest missing 'bundle_url'"
[ -n "$REMOTE_BUNDLE_SHA256" ] || fail "manifest missing 'bundle_sha256'"

# ── Decide: update needed? ───────────────────────────────────────
LOCAL_VERSION=$(cat "$LOCAL_VERSION_FILE" 2>/dev/null || echo "0.0.0")
log "local=$LOCAL_VERSION  remote=$REMOTE_VERSION  released=$REMOTE_RELEASED_AT"

if [ "$MODE" = check ]; then
  if [ "$LOCAL_VERSION" = "$REMOTE_VERSION" ]; then
    log "up-to-date"
  else
    log "update available: $LOCAL_VERSION -> $REMOTE_VERSION"
  fi
  exit 0
fi

if [ "$MODE" != force ] && [ "$LOCAL_VERSION" = "$REMOTE_VERSION" ]; then
  log "already on $REMOTE_VERSION, nothing to do"
  exit 0
fi

# Refuse downgrades (lexicographic; assumes semver-ish or
# date-stamped). Operator override: --force.
if [ "$MODE" != force ] && [ -n "$LOCAL_VERSION" ] \
    && [ "$LOCAL_VERSION" != "0.0.0" ] \
    && [[ "$LOCAL_VERSION" > "$REMOTE_VERSION" ]]; then
  fail "refusing downgrade $LOCAL_VERSION -> $REMOTE_VERSION (use --force)"
fi

# ── Download + verify bundle ─────────────────────────────────────
TARBALL="$TMPDIR/bundle.tar.gz"
log "downloading bundle from $REMOTE_BUNDLE_URL"
curl -sSf --max-time 600 -o "$TARBALL" "$REMOTE_BUNDLE_URL" \
  || fail "bundle download failed"

ACTUAL_SHA=$(sha256sum "$TARBALL" | awk '{print $1}')
[ "$ACTUAL_SHA" = "$REMOTE_BUNDLE_SHA256" ] \
  || fail "SHA-256 mismatch: got $ACTUAL_SHA expected $REMOTE_BUNDLE_SHA256"
log "SHA-256 verified"

# ── Stop daemon ─────────────────────────────────────────────────
log "stopping $SYSTEMD_UNIT"
systemctl stop "$SYSTEMD_UNIT" || true
sleep 2
if pgrep -af USDmd > /dev/null; then
  log "daemon still running after stop, sending SIGKILL"
  pkill -9 -f USDmd || true
  sleep 2
fi

# ── Backup current bundle ────────────────────────────────────────
TS=$(date -u +%Y%m%d-%H%M%S)
BACKUP="${BUNDLE_DIR}.bak-$TS"
log "backing up current bundle to $BACKUP"
cp -a "$BUNDLE_DIR" "$BACKUP"

# ── Atomic swap ──────────────────────────────────────────────────
NEWDIR="${BUNDLE_DIR}.new-$TS"
mkdir -p "$NEWDIR"
log "extracting new bundle to $NEWDIR"
tar xzf "$TARBALL" -C "$NEWDIR"
chmod +x "$NEWDIR/USDmd" "$NEWDIR/lib/ld-linux-x86-64.so.2" 2>/dev/null || true

if [ -n "$REMOTE_BINARY_MD5" ]; then
  ACTUAL_MD5=$(md5sum "$NEWDIR/USDmd" | awk '{print $1}')
  if [ "$ACTUAL_MD5" != "$REMOTE_BINARY_MD5" ]; then
    log "WARNING: extracted binary md5 $ACTUAL_MD5 != manifest claim $REMOTE_BINARY_MD5"
  fi
fi

OLDDIR="${BUNDLE_DIR}.old-$TS"
mv "$BUNDLE_DIR" "$OLDDIR"
mv "$NEWDIR" "$BUNDLE_DIR"
echo "$REMOTE_VERSION" > "$LOCAL_VERSION_FILE"
log "bundle swapped to $REMOTE_VERSION"

# ── Restart daemon ───────────────────────────────────────────────
log "starting $SYSTEMD_UNIT"
systemctl start "$SYSTEMD_UNIT"

# ── Post-swap health check ───────────────────────────────────────
log "running post-swap health check (grace=${HEALTH_CHECK_GRACE_S}s)"
sleep 5
HEALTH_OK=0
DEADLINE=$(($(date +%s) + HEALTH_CHECK_GRACE_S))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if ! systemctl is-active --quiet "$SYSTEMD_UNIT"; then
    log "daemon NOT running; will rollback"
    break
  fi
  HEIGHT=$(curl -sSf --max-time 5 "$RPC_URL" \
    -d '{"jsonrpc":"2.0","method":"get_info"}' \
    -H 'Content-Type: application/json' 2>/dev/null \
    | jq -r '.result.height // 0' 2>/dev/null || echo 0)
  if [ "${HEIGHT:-0}" -gt 0 ]; then
    log "daemon healthy: height=$HEIGHT"
    HEALTH_OK=1
    break
  fi
  sleep 5
done

if [ "$HEALTH_OK" -ne 1 ]; then
  log "HEALTH CHECK FAILED — rolling back to $BACKUP"
  systemctl stop "$SYSTEMD_UNIT" || true
  sleep 2
  pkill -9 -f USDmd || true
  rm -rf "$BUNDLE_DIR"
  mv "$BACKUP" "$BUNDLE_DIR"
  systemctl start "$SYSTEMD_UNIT"
  fail "auto-rollback complete; daemon restored to $LOCAL_VERSION"
fi

log "update complete: $LOCAL_VERSION -> $REMOTE_VERSION (healthy)"
log "old bundle preserved at $OLDDIR (delete after operator-verify)"

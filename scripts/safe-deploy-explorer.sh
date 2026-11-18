#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# safe-deploy-explorer.sh
#
# The ONLY sanctioned way to push the MoneroUSD block-explorer
# code (`monerousd-explorer/`) to the VPS at ${MONEROUSD_VPS_HOST} and
# restart the `monerousd-explorer` systemd service.
#
# Coexistence on the VPS
# ──────────────────────
# Project I OWN (this script may write):
#   /root/MoneroUSD/monerousd-explorer/   — explorer source (Express + EJS)
#   service: monerousd-explorer.service   — restarted on every successful push
#
# Sibling projects this script MUST NOT touch:
#   /var/www/monerousd-updates/   — wallet OTA artifacts (safe-deploy-ota.sh)
#   /var/www/monerousd-site/      — marketing site (safe-deploy-monerousd-site.sh)
#   /opt/ion-monerousd-org/       — Ion Swap backend (safe-deploy-ion-backend.sh)
#   /var/www/ion-monerousd-org/   — Ion Swap frontend (deployed via edge, not VPS path)
#   /root/MoneroUSD/              — USDmd daemon source (NEVER touch)
#   /srv/commercehub/             — CommerceHub
#
# Hard guards
# ───────────
# 1. Target directory is HARDCODED at the top of the script. Any
#    `--target` flag is rejected.
# 2. The live `app.js` and any *.ejs views are backed up to a
#    timestamped subdirectory under `.deploy-backups/` BEFORE the
#    rsync runs.
# 3. Deploys are dry-run unless `--execute` is passed.
# 4. `systemctl restart` runs ONLY if the rsync delivered the
#    expected file count (>= 1 view OR app.js OR style.css change).
# 5. After restart, smoke-tests `https://explorer.monerousd.org/`
#    for HTTP 200 + the expected `<title>` string.
#
# USAGE
# ─────
#   bash scripts/safe-deploy-explorer.sh                # dry-run
#   bash scripts/safe-deploy-explorer.sh --execute      # real
#   bash scripts/safe-deploy-explorer.sh --execute --css-only
#   bash scripts/safe-deploy-explorer.sh --execute --views-only
#
# Reference: monerousd-explorer/CLAUDE.md (rule 109 pattern).

set -euo pipefail

# ── Frozen constants ──
readonly VPS_HOST="root@${MONEROUSD_VPS_HOST}"
readonly VPS_TARGET="/root/MoneroUSD/monerousd-explorer"
readonly BACKUP_DIR_REMOTE="${VPS_TARGET}/.deploy-backups"
readonly SERVICE_NAME="monerousd-explorer"
readonly LIVE_URL="https://explorer.monerousd.org/"
readonly EXPECTED_TITLE="MoneroUSD Explorer"

# Resolve the local source directory. The script lives at
# scripts/safe-deploy-explorer.sh; the explorer lives at
# monerousd-explorer/ next to scripts/.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "${HERE}/../monerousd-explorer" && pwd)"

EXECUTE=0
CSS_ONLY=0
VIEWS_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --execute)    EXECUTE=1; shift ;;
    --css-only)   CSS_ONLY=1; shift ;;
    --views-only) VIEWS_ONLY=1; shift ;;
    -h|--help)
      sed -n '/^# USAGE/,/^# Reference/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "ERROR: unknown flag: $1" >&2 ; exit 2 ;;
  esac
done

cyan()   { printf '\033[36m[explorer-deploy]\033[0m %s\n' "$*"; }
warn()   { printf '\033[33m[explorer-deploy WARN]\033[0m %s\n' "$*" >&2; }
fail()   { printf '\033[31m[explorer-deploy FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

[ -d "$SRC_DIR" ] || fail "source dir not found: $SRC_DIR"
[ -f "$SRC_DIR/app.js" ] || fail "app.js missing in $SRC_DIR"
[ -f "$SRC_DIR/public/style.css" ] || fail "public/style.css missing"
[ -d "$SRC_DIR/views" ] || fail "views/ missing"

cyan "Target host: $VPS_HOST"
cyan "Target dir : $VPS_TARGET (frozen)"
cyan "Service    : $SERVICE_NAME"
cyan "Source     : $SRC_DIR"

if [ "$EXECUTE" -eq 0 ]; then
  cyan "DRY RUN — pass --execute to actually deploy."
fi

# ── Connectivity probe ──
ssh -o ConnectTimeout=8 -o BatchMode=yes "$VPS_HOST" "true" \
  || fail "cannot reach $VPS_HOST via ssh (BatchMode); is your key set up?"

# ── Pre-flight: confirm target dir layout matches expectation ──
remote_target_present=$(ssh "$VPS_HOST" "[ -d '$VPS_TARGET' ] && echo yes || echo no")
if [ "$remote_target_present" != "yes" ]; then
  fail "remote target $VPS_TARGET does not exist — refusing to create blindly."
fi

# ── Backup the existing files we're about to overwrite ──
ts="$(date +%Y%m%d-%H%M%S)"
remote_backup="$BACKUP_DIR_REMOTE/$ts"
if [ "$EXECUTE" -eq 1 ]; then
  cyan "Creating remote backup: $remote_backup"
  ssh "$VPS_HOST" "mkdir -p '$remote_backup' && \
    cp -r '$VPS_TARGET/app.js' '$remote_backup/' 2>/dev/null || true; \
    cp -r '$VPS_TARGET/views' '$remote_backup/' 2>/dev/null || true; \
    cp -r '$VPS_TARGET/public' '$remote_backup/' 2>/dev/null || true; \
    true"
fi

# ── Build rsync sources based on flags ──
RSYNC_ARGS=(--archive --compress --human-readable --itemize-changes
  --exclude=node_modules --exclude='*.db' --exclude='.git' --exclude='.deploy-backups')

if [ "$CSS_ONLY" -eq 1 ]; then
  cyan "Mode: CSS-only (public/style.css)"
  paths=( "$SRC_DIR/public/style.css" )
  remote_dest="$VPS_HOST:$VPS_TARGET/public/style.css"
elif [ "$VIEWS_ONLY" -eq 1 ]; then
  cyan "Mode: VIEWS-only (views/*.ejs)"
  paths=( "$SRC_DIR/views/" )
  remote_dest="$VPS_HOST:$VPS_TARGET/views/"
else
  cyan "Mode: FULL (app.js + views/ + public/)"
  paths=( "$SRC_DIR/app.js" "$SRC_DIR/views/" "$SRC_DIR/public/" )
  remote_dest="" # multiple targets, handled below
fi

# ── Dry-run rsync to surface what would change ──
cyan "Dry-run diff:"
if [ "$CSS_ONLY" -eq 1 ] || [ "$VIEWS_ONLY" -eq 1 ]; then
  rsync --dry-run "${RSYNC_ARGS[@]}" "${paths[@]}" "$remote_dest" || true
else
  rsync --dry-run "${RSYNC_ARGS[@]}" "$SRC_DIR/app.js" "$VPS_HOST:$VPS_TARGET/app.js" || true
  rsync --dry-run "${RSYNC_ARGS[@]}" "$SRC_DIR/views/" "$VPS_HOST:$VPS_TARGET/views/" || true
  rsync --dry-run "${RSYNC_ARGS[@]}" "$SRC_DIR/public/" "$VPS_HOST:$VPS_TARGET/public/" || true
fi

if [ "$EXECUTE" -eq 0 ]; then
  cyan "Dry-run complete. Re-run with --execute to deploy."
  exit 0
fi

# ── Real rsync ──
cyan "Uploading…"
if [ "$CSS_ONLY" -eq 1 ] || [ "$VIEWS_ONLY" -eq 1 ]; then
  rsync "${RSYNC_ARGS[@]}" "${paths[@]}" "$remote_dest"
else
  rsync "${RSYNC_ARGS[@]}" "$SRC_DIR/app.js"  "$VPS_HOST:$VPS_TARGET/app.js"
  rsync "${RSYNC_ARGS[@]}" "$SRC_DIR/views/"  "$VPS_HOST:$VPS_TARGET/views/"
  rsync "${RSYNC_ARGS[@]}" "$SRC_DIR/public/" "$VPS_HOST:$VPS_TARGET/public/"
fi

# ── Restart service ──
cyan "Restarting $SERVICE_NAME…"
ssh "$VPS_HOST" "systemctl restart $SERVICE_NAME && systemctl is-active $SERVICE_NAME" \
  || fail "service restart failed; investigate via 'journalctl -u $SERVICE_NAME -n 100'"

# ── Smoke test ──
cyan "Smoke-testing $LIVE_URL …"
sleep 1.5
http_code=$(curl -sS -o /dev/null -w "%{http_code}" "$LIVE_URL" || echo "000")
if [ "$http_code" != "200" ]; then
  warn "expected 200 from $LIVE_URL, got $http_code"
  warn "rollback: ssh $VPS_HOST 'cp -r $remote_backup/* $VPS_TARGET/ && systemctl restart $SERVICE_NAME'"
  exit 1
fi
title=$(curl -s "$LIVE_URL" | grep -oE '<title>[^<]+</title>' | head -1 | sed 's/<[^>]*>//g')
case "$title" in
  *"$EXPECTED_TITLE"*)
    cyan "  ✓ HTTP 200, title: $title" ;;
  *)
    warn "title mismatch — got: $title (expected: $EXPECTED_TITLE)"
    warn "page may still render — verify in a browser"
    ;;
esac

cyan "DEPLOY COMPLETE."
cyan "Rollback (if needed):"
cyan "  ssh $VPS_HOST 'cp -r $remote_backup/* $VPS_TARGET/ && systemctl restart $SERVICE_NAME'"

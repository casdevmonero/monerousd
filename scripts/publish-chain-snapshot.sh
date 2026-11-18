#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#
# publish-chain-snapshot.sh — Layer 9c operator-side automation.
#
# WHAT THIS DOES
# ──────────────
# Generates a fresh canonical chain snapshot from the operator's
# VPS USDmd daemon and publishes it to:
#
#   1. GitHub Releases on casdevmonero/monerousd-ota-releases
#      (path: chain-snapshot-h<HEIGHT>/usdmd-chain-snapshot-h<HEIGHT>.tar.zst)
#   2. update.monerousd.org/chain-snapshot.json
#      (manifest committed to casdevmonero/monerousd-ota-manifest)
#
# Every wallet's `downloadBlockchainSnapshot` polls #2 + downloads
# from #1 + SHA-verifies before applying. With this script running
# DAILY via a cron / systemd timer (Layer 9c), the snapshot URL is
# never 404, and the chain-snapshot.json manifest always points at
# a fresh canonical chain — so `chain-snapshot.tar.zst.download`
# partials can never put a wallet on a fork.
#
# WHY MANIFEST CARRIES top_block_hash AND recent_block_hashes
# ──────────────────────────────────────────────────────────
# The Layer 9b verified-snapshot-apply path in the wallet
# (build-1261/main.js::downloadBlockchainSnapshot) checks:
#
#   * SHA-256 of the tarball matches manifest.sha256          (existing)
#   * top_block_hash from manifest matches what ≥2 peers       (Layer 9b)
#     report for that height
#
# The recent_block_hashes array (last 100 block hashes) lets a
# wallet do a lightweight chain-identity probe against any peer
# without needing the full snapshot. If those don't match what
# peers report, the snapshot is rejected before LMDB is wiped.
#
# REQUIREMENTS (operator-side)
# ────────────────────────────
#   - USDmd.service running, RPC on 127.0.0.1:17750
#   - data-dir at /root/.monerousd (LMDB at /root/.monerousd/lmdb)
#   - zstd, tar, curl, gh, jq, systemctl available on PATH
#   - GH CLI authenticated as a user with push access to
#     casdevmonero/monerousd-ota-releases and -manifest repos
#   - Free disk: ≥4× LMDB size (work + final tarball + safety margin)
#
# CRON FRIENDLINESS
# ─────────────────
# Safe to invoke from a daily cron / systemd timer. Locks on
# /var/lock/publish-chain-snapshot.lock so two concurrent runs don't
# step on each other. Logs to /var/log/publish-chain-snapshot.log.
# Returns exit 0 on success / publish, exit 0 (no-op) when a
# snapshot for the same height already exists, exit >=1 on real
# failure (filesystem, daemon-down, gh-auth, etc.).
#
# Per CLAUDE.md no-islanding Layer 9 (chain consistency) +
# Layer 9c (automated snapshot publishing).
#

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────

DATA_DIR="${DATA_DIR:-/root/.monerousd}"
LMDB_DIR="$DATA_DIR/lmdb"
WORK_DIR="${WORK_DIR:-/tmp/usdmd-snap-work}"
LOG_FILE="${LOG_FILE:-/var/log/publish-chain-snapshot.log}"
LOCK_FILE="${LOCK_FILE:-/var/lock/publish-chain-snapshot.lock}"

RELEASES_REPO="${RELEASES_REPO:-casdevmonero/monerousd-ota-releases}"
MANIFEST_REPO="${MANIFEST_REPO:-casdevmonero/monerousd-ota-manifest}"
MANIFEST_CLONE="${MANIFEST_CLONE:-/var/tmp/monerousd-ota-manifest.clone}"

DAEMON_RPC="${DAEMON_RPC:-http://127.0.0.1:17750}"
DAEMON_SERVICE="${DAEMON_SERVICE:-USDmd.service}"

# ZSTD level — higher = smaller but slower. Default 19 (near-max)
# because the snapshot needs to fit under GitHub's 100MB per-file
# limit when we use the manifest-repo direct-hosting fallback path
# (no GH-LFS, no GH Releases). zstd -19 on a 300MB LMDB takes ~30-60s
# on a modern VPS and shaves ~10% off the size vs -3, which is the
# difference between fitting and not fitting.
# Override per environment: ZSTD_LEVEL=3 for fast ad-hoc dev runs,
# ZSTD_LEVEL=22 (ultra) for marginal extra compression at high CPU cost.
ZSTD_LEVEL="${ZSTD_LEVEL:-19}"
SKIP_IF_HEIGHT_WITHIN="${SKIP_IF_HEIGHT_WITHIN:-100}"

# Auto-detect github branch
GH_BRANCH="${GH_BRANCH:-main}"

# ── Helpers ────────────────────────────────────────────────────────

log() {
  local msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
  echo "$msg" | tee -a "$LOG_FILE" >&2
}

die() {
  log "FATAL: $*"
  exit 1
}

# ── Lock so cron + ad-hoc don't race ──────────────────────────────

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  log "another run is in flight (lock held) — skipping"
  exit 0
fi

log "════════════════════════════════════════════════════════════"
log "publish-chain-snapshot.sh starting"

# ── Sanity: tools + daemon ─────────────────────────────────────────

for cmd in tar zstd curl gh jq sha256sum systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || die "missing required tool: $cmd"
done

# Daemon must be running + RPC must respond + we need the current
# chain height + top_block_hash for the manifest.
RPC_PAYLOAD='{"jsonrpc":"2.0","id":"0","method":"get_info","params":{}}'
RPC_RESP=$(curl -sf -m 8 -X POST "$DAEMON_RPC/json_rpc" \
  -H "Content-Type: application/json" -d "$RPC_PAYLOAD") \
  || die "daemon RPC unreachable at $DAEMON_RPC — is $DAEMON_SERVICE active?"

CURRENT_HEIGHT_COUNT=$(echo "$RPC_RESP" | jq -re '.result.height') \
  || die "RPC response missing .result.height: $RPC_RESP"
CURRENT_TOP_HASH=$(echo "$RPC_RESP" | jq -re '.result.top_block_hash') \
  || die "RPC response missing .result.top_block_hash"
# CryptoNote convention: `get_info.height` is block COUNT (top
# block index + 1). The hash returned by `on_get_block_hash(N)` is
# defined for N ∈ [0, height-1]. To make the manifest verifiable
# by Layer 9b (which queries `on_get_block_hash(manifest.height)`
# against peers), we record height = block_count - 1 = top block
# INDEX. This makes manifest.height match what get_info.top_block_hash
# corresponds to.
CURRENT_HEIGHT=$((CURRENT_HEIGHT_COUNT - 1))
CURRENT_DIFFICULTY=$(echo "$RPC_RESP" | jq -re '.result.cumulative_difficulty') \
  || die "RPC response missing .result.cumulative_difficulty"
NETTYPE=$(echo "$RPC_RESP" | jq -re '.result.nettype') \
  || die "RPC response missing .result.nettype"

[ "$NETTYPE" = "mainnet" ] \
  || die "REFUSING to publish: nettype=$NETTYPE (snapshot must be mainnet)"

log "daemon healthy: height=$CURRENT_HEIGHT top=$CURRENT_TOP_HASH"
log "cumulative_difficulty=$CURRENT_DIFFICULTY nettype=$NETTYPE"

# ── Skip-if-not-stale gate ─────────────────────────────────────────
# If the live manifest already points at a height within
# SKIP_IF_HEIGHT_WITHIN blocks of current, this run is a no-op —
# don't waste bandwidth republishing trivially-incrementally.

LIVE_MANIFEST=$(curl -sf -m 8 https://update.monerousd.org/chain-snapshot.json 2>/dev/null || echo '')
if [ -n "$LIVE_MANIFEST" ]; then
  LIVE_HEIGHT=$(echo "$LIVE_MANIFEST" | jq -r '.height // 0' 2>/dev/null || echo 0)
  DRIFT=$((CURRENT_HEIGHT - LIVE_HEIGHT))
  if [ "$LIVE_HEIGHT" -gt 0 ] && [ "$DRIFT" -lt "$SKIP_IF_HEIGHT_WITHIN" ]; then
    log "live manifest at h=$LIVE_HEIGHT, current h=$CURRENT_HEIGHT, drift=$DRIFT"
    log "within SKIP_IF_HEIGHT_WITHIN ($SKIP_IF_HEIGHT_WITHIN) — no-op"
    exit 0
  fi
  log "live manifest at h=$LIVE_HEIGHT, current h=$CURRENT_HEIGHT, drift=$DRIFT — proceeding"
else
  log "no live manifest at update.monerousd.org/chain-snapshot.json — first publish"
fi

# ── Capture recent block hash chain (chain-identity proof) ─────────
# Last 100 block hashes prove our snapshot was generated from the
# canonical chain. A wallet's Layer 9b path can verify these against
# any peer before applying the snapshot.

log "capturing last 100 block hashes for chain-identity proof..."
RECENT_HASHES_JSON='[]'
RECENT_BUF=""
START_H=$((CURRENT_HEIGHT - 100))
[ "$START_H" -lt 0 ] && START_H=0
for h in $(seq "$START_H" "$CURRENT_HEIGHT"); do
  HASH=$(curl -sf -m 4 -X POST "$DAEMON_RPC/json_rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"on_get_block_hash\",\"params\":[$h]}" \
    | jq -re '.result' 2>/dev/null) || HASH=""
  [ -n "$HASH" ] && RECENT_BUF="$RECENT_BUF{\"h\":$h,\"hash\":\"$HASH\"},"
done
RECENT_BUF="${RECENT_BUF%,}"
RECENT_HASHES_JSON="[$RECENT_BUF]"

# ── Free-disk check ───────────────────────────────────────────────

LMDB_SIZE=$(du -sb "$LMDB_DIR" | awk '{print $1}')
NEED_BYTES=$((LMDB_SIZE * 4))
WORK_ROOT=$(dirname "$WORK_DIR")
AVAIL_BYTES=$(df -B1 --output=avail "$WORK_ROOT" | tail -1)
[ "$AVAIL_BYTES" -gt "$NEED_BYTES" ] \
  || die "insufficient disk: need $NEED_BYTES bytes (4× LMDB), have $AVAIL_BYTES at $WORK_ROOT"

log "LMDB size: $LMDB_SIZE bytes, work-space free: $AVAIL_BYTES bytes"

# ── Stop daemon briefly for atomic LMDB copy ──────────────────────
# Without mdb_copy/mdb_dump installed, the safest path to a
# consistent LMDB snapshot is to stop the daemon, copy files, and
# restart. Total downtime is typically 5-20s (file copy time).
# A trap restarts the daemon on any error path so we never leave
# the daemon stopped.

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
trap 'systemctl start "$DAEMON_SERVICE" 2>/dev/null || true; rm -rf "$WORK_DIR"; log "trap: cleaning up + restarting daemon"' EXIT INT TERM

log "stopping $DAEMON_SERVICE for atomic LMDB copy..."
systemctl stop "$DAEMON_SERVICE" || die "failed to stop $DAEMON_SERVICE"

# Brief wait for the daemon to actually exit (so LMDB is flushed).
for _ in $(seq 1 30); do
  if ! systemctl is-active "$DAEMON_SERVICE" >/dev/null 2>&1; then break; fi
  sleep 1
done

log "copying LMDB to work-dir..."
cp -a "$LMDB_DIR" "$WORK_DIR/lmdb" \
  || die "cp -a $LMDB_DIR -> $WORK_DIR/lmdb FAILED"

log "restarting $DAEMON_SERVICE..."
systemctl start "$DAEMON_SERVICE" || die "failed to restart $DAEMON_SERVICE after copy"

# Clear the daemon-restart trap since the daemon is up. Still
# cleanup work-dir on exit UNLESS KEEP_WORK_DIR=1 — that env-var is
# the publish-from-different-host workflow: generate snapshot on
# VPS (which has the live chain), scp it elsewhere (which has the
# write-credentialed PAT), then publish from there.
trap '[ "${KEEP_WORK_DIR:-0}" = "1" ] || rm -rf "$WORK_DIR"' EXIT INT TERM

# ── Compress the snapshot ─────────────────────────────────────────

SNAP_NAME="usdmd-chain-snapshot-h${CURRENT_HEIGHT}.tar.zst"
SNAP_PATH="$WORK_DIR/$SNAP_NAME"
log "compressing LMDB to $SNAP_PATH (zstd -$ZSTD_LEVEL)..."
( cd "$WORK_DIR" && tar -cf - lmdb | zstd -T0 -"$ZSTD_LEVEL" -o "$SNAP_NAME" ) \
  || die "tar+zstd FAILED"
SNAP_SIZE=$(stat -c%s "$SNAP_PATH")
log "compressed snapshot: $SNAP_SIZE bytes"

SNAP_SHA=$(sha256sum "$SNAP_PATH" | awk '{print $1}')
log "snapshot sha256: $SNAP_SHA"

# ── Upload to GH Releases ─────────────────────────────────────────

RELEASE_TAG="chain-snapshot-h${CURRENT_HEIGHT}"
RELEASE_URL="https://github.com/${RELEASES_REPO}/releases/download/${RELEASE_TAG}/${SNAP_NAME}"

# Publishing strategy: PREFER GH Releases on $RELEASES_REPO (clean
# binary hosting, doesn't bloat manifest repo history), but FALL BACK
# to committing the tarball directly into the manifest repo when
# the token doesn't have releases permission. The fallback is what
# makes the publisher VPS-INDEPENDENT — any operator with manifest-
# repo write access can publish, no separate releases-repo grant
# needed.
USE_MANIFEST_REPO_FALLBACK=0
if gh release view "$RELEASE_TAG" --repo "$RELEASES_REPO" >/dev/null 2>&1; then
  log "release $RELEASE_TAG already exists on $RELEASES_REPO — will re-upload asset"
else
  log "attempting to create GH release $RELEASE_TAG on $RELEASES_REPO..."
  if gh release create "$RELEASE_TAG" \
    --repo "$RELEASES_REPO" \
    --title "Chain snapshot height $CURRENT_HEIGHT" \
    --notes "Automated snapshot from publish-chain-snapshot.sh
height: $CURRENT_HEIGHT
top_block_hash: $CURRENT_TOP_HASH
cumulative_difficulty: $CURRENT_DIFFICULTY
sha256: $SNAP_SHA
size_bytes: $SNAP_SIZE" 2>&1 | tee -a "$LOG_FILE"; then
    log "GH release created"
  else
    log "GH release create rejected (token lacks releases scope on $RELEASES_REPO)"
    log "FALLING BACK to manifest-repo direct hosting"
    USE_MANIFEST_REPO_FALLBACK=1
  fi
fi

if [ "$USE_MANIFEST_REPO_FALLBACK" = "0" ]; then
  log "uploading snapshot asset to GH Releases (this may take minutes for a multi-GB tarball)..."
  gh release upload "$RELEASE_TAG" "$SNAP_PATH" \
    --repo "$RELEASES_REPO" \
    --clobber 2>&1 | tee -a "$LOG_FILE" \
    || die "gh release upload FAILED"
  log "snapshot uploaded to GH Releases: $RELEASE_URL"
else
  # Fallback path: commit snapshot into manifest repo. GH Pages
  # serves any file from the repo root, so the URL is just
  # https://update.monerousd.org/<filename>. This keeps the publish
  # pipeline runnable by any operator with manifest-repo write
  # access (no separate releases-repo grant needed).
  log "Layer 9c fallback: committing snapshot tarball to $MANIFEST_REPO"

  # Snapshots tend to be 100-500 MB. GitHub's per-file limit is 100MB
  # for regular pushes; LFS needed for larger. Bail loudly if we'd
  # exceed the limit so operator can switch to GH-LFS or back to
  # releases-repo with broader-scope PAT.
  if [ "$SNAP_SIZE" -gt 99999999 ]; then
    die "snapshot is $SNAP_SIZE bytes (>100MB GitHub per-file limit). " \
        "Token-fallback mode requires snapshot ≤100MB. " \
        "Options: (a) grant PAT releases:write on $RELEASES_REPO, " \
        "(b) configure git-lfs on $MANIFEST_REPO, " \
        "(c) bump ZSTD_LEVEL for tighter compression."
  fi

  if [ ! -d "$MANIFEST_CLONE/.git" ]; then
    git clone --depth 1 "https://github.com/${MANIFEST_REPO}.git" "$MANIFEST_CLONE" 2>&1 | tee -a "$LOG_FILE"
  fi
  (
    cd "$MANIFEST_CLONE"
    git fetch origin "$GH_BRANCH" --quiet 2>>"$LOG_FILE" || true
    git checkout "$GH_BRANCH" --quiet 2>>"$LOG_FILE"
    git reset --hard "origin/$GH_BRANCH" --quiet 2>>"$LOG_FILE" || true

    # Remove any previous chain-snapshot tarballs to keep history small.
    # The latest is the only one needed (older heights are obsolete the
    # moment a fresher snapshot exists). Older wallet binaries that
    # pinned a specific snapshot URL won't find that exact filename
    # anymore — but they have the GH-Releases CHAIN_SNAPSHOT_FALLBACK_URL
    # baked in for that case.
    find . -maxdepth 1 -name 'usdmd-chain-snapshot-h*.tar.zst' -type f -delete

    cp "$SNAP_PATH" "./$SNAP_NAME"

    # Allowlist the snapshot file pattern in the gitignore. The
    # manifest repo's .gitignore is deny-by-default (per the
    # "Default-deny" pattern), so we explicitly un-ignore.
    if ! grep -q '^!usdmd-chain-snapshot-h' .gitignore 2>/dev/null; then
      {
        echo ''
        echo '# Layer 9c automated snapshot (committed by publish-chain-snapshot.sh'
        echo '# when the PAT lacks releases:write on monerousd-ota-releases)'
        echo '!usdmd-chain-snapshot-h*.tar.zst'
      } >> .gitignore
    fi

    git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
      add "$SNAP_NAME" .gitignore
    if git diff --cached --quiet; then
      log "no diff for snapshot tarball — likely identical to HEAD"
    else
      git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
        commit -m "chain-snapshot tarball: h=$CURRENT_HEIGHT (Layer 9c fallback)" 2>&1 | tee -a "$LOG_FILE"
      git push origin "$GH_BRANCH" 2>&1 | tee -a "$LOG_FILE" \
        || die "git push of snapshot tarball FAILED"
      log "snapshot committed to $MANIFEST_REPO"
    fi
  )

  # Override RELEASE_URL so the manifest below points at the
  # GH-Pages-served file rather than the (non-existent) GH release.
  RELEASE_URL="https://update.monerousd.org/${SNAP_NAME}"
  log "snapshot URL via fallback: $RELEASE_URL"
fi

# ── Update the manifest on GH Pages ───────────────────────────────

log "updating chain-snapshot.json on $MANIFEST_REPO..."

if [ ! -d "$MANIFEST_CLONE/.git" ]; then
  log "cloning $MANIFEST_REPO to $MANIFEST_CLONE..."
  git clone --depth 1 "https://github.com/${MANIFEST_REPO}.git" "$MANIFEST_CLONE" 2>&1 | tee -a "$LOG_FILE"
fi

(
  cd "$MANIFEST_CLONE"
  git fetch origin "$GH_BRANCH" --quiet 2>>"$LOG_FILE" || true
  git checkout "$GH_BRANCH" --quiet 2>>"$LOG_FILE"
  git reset --hard "origin/$GH_BRANCH" --quiet 2>>"$LOG_FILE" || true

  # Build new chain-snapshot.json. Layer 9b consumers read:
  #   .url, .sha256, .height, .top_block_hash, .recent_block_hashes
  cat > chain-snapshot.json <<EOF
{
  "version": 2,
  "url": "$RELEASE_URL",
  "sha256": "$SNAP_SHA",
  "size_bytes": $SNAP_SIZE,
  "height": $CURRENT_HEIGHT,
  "top_block_hash": "$CURRENT_TOP_HASH",
  "cumulative_difficulty": "$CURRENT_DIFFICULTY",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "generator": "publish-chain-snapshot.sh",
  "recent_block_hashes": $RECENT_HASHES_JSON
}
EOF

  # Make sure the file is allowed by .gitignore (it normally
  # already is, but the OTA-manifest repo uses a default-deny
  # gitignore so we explicitly check + add the allowlist entry if
  # needed).
  if ! grep -q '^!chain-snapshot.json' .gitignore 2>/dev/null; then
    {
      echo ''
      echo '# Layer 9c automated snapshot manifest (Layer 9b wallet path consumes this)'
      echo '!chain-snapshot.json'
    } >> .gitignore
  fi

  git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
    add chain-snapshot.json .gitignore
  if git diff --cached --quiet -- chain-snapshot.json .gitignore; then
    log "no diff vs HEAD — nothing to commit"
  else
    git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
      commit -m "chain-snapshot: auto-publish height $CURRENT_HEIGHT (Layer 9c)" 2>&1 | tee -a "$LOG_FILE"
    git push origin "$GH_BRANCH" 2>&1 | tee -a "$LOG_FILE" \
      || die "git push FAILED"
    log "manifest committed + pushed"
  fi
)

log "════════════════════════════════════════════════════════════"
log "SUCCESS"
log "  snapshot:  $RELEASE_URL"
log "  height:    $CURRENT_HEIGHT"
log "  top_hash:  $CURRENT_TOP_HASH"
log "  sha256:    $SNAP_SHA"
log "  size:      $SNAP_SIZE bytes"
log "  manifest:  https://update.monerousd.org/chain-snapshot.json"
log "════════════════════════════════════════════════════════════"

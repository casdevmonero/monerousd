#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#
# publish-snapshot-from-staged.sh — companion to publish-chain-snapshot.sh.
#
# Use case
# ────────
# When the host that generates the snapshot (e.g. the VPS with the
# live chain) has a DIFFERENT GitHub PAT than the host that has
# write access to monerousd-ota-manifest, the workflow is:
#
#   1. Generator host: `KEEP_WORK_DIR=1 publish-chain-snapshot.sh`
#      → produces snapshot tarball + SHA + height + top_block_hash
#   2. scp the tarball + the metadata to a publisher host
#   3. Publisher host: `publish-snapshot-from-staged.sh <tarball>`
#      → reads tarball + computes SHA + commits to manifest repo
#
# The Layer 9c timer (install-snapshot-publisher-timer.sh) runs the
# unified publish-chain-snapshot.sh end-to-end on a host that has
# BOTH chain access AND a write-credentialed PAT. This script is the
# split-host fallback for operators whose VPS holds the chain but
# whose Mac/laptop holds the manifest-repo PAT.
#
# Inputs
# ──────
#   $1   path to local tarball (usdmd-chain-snapshot-h<HEIGHT>.tar.zst)
#
# Env (optional):
#   MANIFEST_REPO       default casdevmonero/monerousd-ota-manifest
#   MANIFEST_CLONE      default /tmp/monerousd-ota-manifest.clone
#   USDMD_RPC_URL       default http://${MONEROUSD_VPS_HOST}:17750  (where we
#                       query top_block_hash for the manifest)
#   RECENT_HASH_COUNT   default 100
#

set -euo pipefail

TARBALL="${1:-}"
[ -n "$TARBALL" ] || { echo "usage: $0 <path-to-snapshot.tar.zst>"; exit 1; }
[ -f "$TARBALL" ] || { echo "tarball not found: $TARBALL"; exit 1; }

# Filename must follow `usdmd-chain-snapshot-h<HEIGHT>.tar.zst` so we
# can extract the height. This is the convention the wallet's
# `_fetchChainSnapshotManifest` expects.
#
# NOTE on Monero height semantics: the publisher (publish-chain-snapshot.sh)
# now records BLOCK COUNT in the filename (legacy form), but the manifest's
# .height field carries the TOP BLOCK INDEX (= block_count - 1). The
# distinction matters because the wallet's Layer 9b verifies via
# `on_get_block_hash(.height)` which is defined for INDEX, not COUNT.
# We derive both from the filename: assume the filename's <N> is the
# block count (legacy compat) and use N-1 as the manifest .height.
BASENAME=$(basename "$TARBALL")
HEIGHT_FROM_NAME=$(echo "$BASENAME" | sed -E 's/^usdmd-chain-snapshot-h([0-9]+)\.tar\.zst$/\1/')
[ -n "$HEIGHT_FROM_NAME" ] && [ "$HEIGHT_FROM_NAME" != "$BASENAME" ] \
  || { echo "tarball name must be usdmd-chain-snapshot-h<HEIGHT>.tar.zst, got: $BASENAME"; exit 1; }
# Layer 9b expects manifest.height = top block INDEX. The new
# publisher already writes that into the filename, but back-compat
# accepts either count or index. We probe both and use whichever
# returns a valid hash via on_get_block_hash.
HEIGHT="$HEIGHT_FROM_NAME"

MANIFEST_REPO="${MANIFEST_REPO:-casdevmonero/monerousd-ota-manifest}"
MANIFEST_CLONE="${MANIFEST_CLONE:-/tmp/monerousd-ota-manifest.clone}"
USDMD_RPC_URL="${USDMD_RPC_URL:-http://${MONEROUSD_VPS_HOST}:17750}"
RECENT_HASH_COUNT="${RECENT_HASH_COUNT:-100}"
GH_BRANCH="${GH_BRANCH:-main}"

echo "[publish-from-staged] tarball: $TARBALL"
echo "[publish-from-staged] height:  $HEIGHT"
echo "[publish-from-staged] size:    $(stat -f%z "$TARBALL" 2>/dev/null || stat -c%s "$TARBALL")"

SNAP_SHA=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
echo "[publish-from-staged] sha256:  $SNAP_SHA"

SNAP_SIZE=$(stat -f%z "$TARBALL" 2>/dev/null || stat -c%s "$TARBALL")

# Query the canonical daemon for the top_block_hash at this snapshot's
# height + the recent block hashes. This is what Layer 9b in the wallet
# verifies against — without it, Layer 9b auto-rejects the snapshot.
#
# IMPORTANT: on_get_block_hash(N) returns zeros for N == block_count
# (the next-to-mine block doesn't exist yet). We probe both
# HEIGHT and HEIGHT-1, choose whichever returns a non-zero hash.
# This handles both "filename has block count" and "filename has
# top index" conventions, since the publisher transitioned between
# them and old + new tarballs may co-exist briefly.
echo "[publish-from-staged] querying $USDMD_RPC_URL for chain-identity proof..."
ALL_ZERO='0000000000000000000000000000000000000000000000000000000000000000'
_query_hash() {
  curl -sf -m 8 -X POST "$USDMD_RPC_URL/json_rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"on_get_block_hash\",\"params\":[$1]}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",""))' \
    2>/dev/null
}
TOP_HASH=$(_query_hash "$HEIGHT")
if [ "$TOP_HASH" = "$ALL_ZERO" ] || [ -z "$TOP_HASH" ]; then
  # Filename was using block-count convention; use INDEX = count - 1
  PROBE=$((HEIGHT - 1))
  CANDIDATE=$(_query_hash "$PROBE")
  if [ -n "$CANDIDATE" ] && [ "$CANDIDATE" != "$ALL_ZERO" ] && [ "${#CANDIDATE}" = "64" ]; then
    echo "[publish-from-staged] filename's height ($HEIGHT) is block count;"
    echo "[publish-from-staged] using top INDEX = $PROBE for manifest"
    HEIGHT="$PROBE"
    TOP_HASH="$CANDIDATE"
  fi
fi
[ -n "$TOP_HASH" ] && [ "${#TOP_HASH}" = "64" ] && [ "$TOP_HASH" != "$ALL_ZERO" ] \
  || { echo "could not fetch a valid top_block_hash near h=$HEIGHT_FROM_NAME from $USDMD_RPC_URL"; exit 1; }
echo "[publish-from-staged] manifest.height (top index): $HEIGHT"
echo "[publish-from-staged] top_block_hash: $TOP_HASH"

# Cumulative difficulty (informational).
CUM_DIFFICULTY=$(curl -sf -m 8 -X POST "$USDMD_RPC_URL/json_rpc" \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":$HEIGHT}}" \
  | python3 -c 'import sys,json; r=json.load(sys.stdin).get("result",{}).get("block_header",{}); print(r.get("cumulative_difficulty",""))' \
  || echo "")

# Build the recent block hash chain.
echo "[publish-from-staged] capturing last $RECENT_HASH_COUNT block hashes..."
START_H=$((HEIGHT - RECENT_HASH_COUNT))
[ "$START_H" -lt 0 ] && START_H=0
RECENT_BUF=""
for h in $(seq "$START_H" "$HEIGHT"); do
  HASH=$(curl -sf -m 4 -X POST "$USDMD_RPC_URL/json_rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"on_get_block_hash\",\"params\":[$h]}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",""))' 2>/dev/null) || HASH=""
  [ -n "$HASH" ] && [ "${#HASH}" = "64" ] && RECENT_BUF="$RECENT_BUF{\"h\":$h,\"hash\":\"$HASH\"},"
done
RECENT_BUF="${RECENT_BUF%,}"
RECENT_HASHES_JSON="[$RECENT_BUF]"

# Clone or pull the manifest repo.
if [ ! -d "$MANIFEST_CLONE/.git" ]; then
  echo "[publish-from-staged] cloning $MANIFEST_REPO to $MANIFEST_CLONE..."
  git clone --depth 1 "https://github.com/${MANIFEST_REPO}.git" "$MANIFEST_CLONE"
fi

cd "$MANIFEST_CLONE"
git fetch origin "$GH_BRANCH" --quiet
git checkout "$GH_BRANCH" --quiet
git reset --hard "origin/$GH_BRANCH" --quiet

# Remove any previous chain-snapshot tarballs to keep history small.
find . -maxdepth 1 -name 'usdmd-chain-snapshot-h*.tar.zst' -type f -delete

cp "$TARBALL" "./$BASENAME"

# Write the manifest. Layer 9b in the wallet reads:
#   .url, .sha256, .height, .top_block_hash, .recent_block_hashes
RELEASE_URL="https://update.monerousd.org/${BASENAME}"
cat > chain-snapshot.json <<EOF
{
  "version": 2,
  "url": "$RELEASE_URL",
  "sha256": "$SNAP_SHA",
  "size_bytes": $SNAP_SIZE,
  "height": $HEIGHT,
  "top_block_hash": "$TOP_HASH",
  "cumulative_difficulty": "$CUM_DIFFICULTY",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "generator": "publish-snapshot-from-staged.sh",
  "recent_block_hashes": $RECENT_HASHES_JSON
}
EOF

# Allowlist the file pattern in .gitignore (idempotent).
if ! grep -q '^!usdmd-chain-snapshot-h' .gitignore 2>/dev/null; then
  {
    echo ''
    echo '# Layer 9c chain-snapshot tarball (manifest-repo direct hosting)'
    echo '!usdmd-chain-snapshot-h*.tar.zst'
  } >> .gitignore
fi
if ! grep -q '^!chain-snapshot.json' .gitignore 2>/dev/null; then
  echo '!chain-snapshot.json' >> .gitignore
fi

git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
  add "$BASENAME" chain-snapshot.json .gitignore
if git diff --cached --quiet; then
  echo "[publish-from-staged] no diff vs HEAD — nothing to commit"
  exit 0
fi
git -c user.email="ops@monerousd.org" -c user.name="MoneroUSD Ops" \
  commit -m "chain-snapshot: publish h=$HEIGHT (Layer 9c)"
git push origin "$GH_BRANCH"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Snapshot published."
echo "  URL:      $RELEASE_URL"
echo "  manifest: https://update.monerousd.org/chain-snapshot.json"
echo "  height:   $HEIGHT"
echo "  top_hash: $TOP_HASH"
echo "  sha256:   $SNAP_SHA"
echo "════════════════════════════════════════════════════════════"

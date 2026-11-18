#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# deploy-multi-cdn.sh
#
# Deploys the OTA mirror + static sites to N independent CDNs in
# parallel so no single CDN failure can take wallets offline. The
# wallet's site-updater (Phase F) + binary-release-verifier (Phase H)
# already do multi-source fetch with chain-anchored hash verification
# — this script is the publish side of that contract.
#
# Sources targeted (any subset):
#   1. Cloudflare Pages    — wrangler CLI
#   2. Bunny.net Storage   — direct PUT to storage zone
#   3. GitHub Pages        — git push to a Pages-enabled repo
#   4. IPFS (Pinata)       — pinata HTTP API
#
# Each source produces an independent endpoint URL. The user updates
# DNS so update.monerousd.org / monerousd.org / etc resolve to one
# (the primary); the other endpoints are configured as fallbacks in
# the wallet's `lib/indexer-failover.js` mirror list.
#
# Usage
# ─────
#   bash scripts/deploy-multi-cdn.sh \
#       --target ota \
#       --source out/ota-mirror \
#       --to     cloudflare-pages,bunny,github-pages
#
#   bash scripts/deploy-multi-cdn.sh \
#       --target site \
#       --source build-1261/sites/monerousd-org \
#       --to     cloudflare-pages,bunny
#
# Required env vars (per CDN, only those you target):
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_PAGES_PROJECT
#   BUNNY_STORAGE_ZONE, BUNNY_STORAGE_PASSWORD, BUNNY_REGION (default: ny)
#   GITHUB_TOKEN, GITHUB_PAGES_REPO   (e.g. monerousd/ota-mirror)
#   PINATA_JWT
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── arg parsing ────────────────────────────────────────────────────

TARGET=""
SOURCE=""
TO=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --to)     TO="$2";     shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

[ -z "$TARGET" ] && { echo "--target required (ota|site|generic)" >&2; exit 1; }
[ -z "$SOURCE" ] && { echo "--source <dir> required" >&2; exit 1; }
[ -z "$TO" ]     && { echo "--to <comma,list> required" >&2; exit 1; }
[ ! -d "$SOURCE" ] && { echo "source dir not found: $SOURCE" >&2; exit 1; }

SOURCE=$(cd "$SOURCE" && pwd)

echo "  ── deploy-multi-cdn ──"
echo "  target: $TARGET"
echo "  source: $SOURCE  ($(du -sh "$SOURCE" 2>/dev/null | awk '{print $1}'))"
echo "  to:     $TO"
echo ""

# ─── per-source deployers ───────────────────────────────────────────

deploy_cloudflare_pages() {
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN env not set}"
  : "${CLOUDFLARE_PAGES_PROJECT:?CLOUDFLARE_PAGES_PROJECT env not set}"
  if ! command -v wrangler >/dev/null 2>&1; then
    echo "  wrangler CLI not installed. Install: npm i -g wrangler"
    return 1
  fi
  echo "  [cloudflare-pages] uploading $SOURCE → $CLOUDFLARE_PAGES_PROJECT"
  CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
    wrangler pages deploy "$SOURCE" \
      --project-name "$CLOUDFLARE_PAGES_PROJECT" \
      --commit-message "deploy-multi-cdn target=$TARGET source=$(basename "$SOURCE")" \
      2>&1 | tail -10
}

deploy_bunny() {
  : "${BUNNY_STORAGE_ZONE:?BUNNY_STORAGE_ZONE env not set}"
  : "${BUNNY_STORAGE_PASSWORD:?BUNNY_STORAGE_PASSWORD env not set}"
  local region="${BUNNY_REGION:-ny}"
  local base="https://${region}.storage.bunnycdn.com/${BUNNY_STORAGE_ZONE}"
  echo "  [bunny.net] uploading to $base"
  local count=0
  cd "$SOURCE"
  while IFS= read -r -d '' f; do
    local rel="${f#./}"
    local url="${base}/${rel}"
    curl -sf -X PUT "$url" \
      -H "AccessKey: $BUNNY_STORAGE_PASSWORD" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@$f" \
      || { echo "  [bunny.net] FAILED on $rel" >&2; cd - >/dev/null; return 1; }
    count=$((count + 1))
  done < <(find . -type f -print0)
  cd - >/dev/null
  echo "  [bunny.net] uploaded $count files"
}

deploy_github_pages() {
  : "${GITHUB_TOKEN:?GITHUB_TOKEN env not set}"
  : "${GITHUB_PAGES_REPO:?GITHUB_PAGES_REPO env not set (e.g. monerousd/ota-mirror)}"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf '$tmp'" RETURN
  echo "  [github-pages] cloning $GITHUB_PAGES_REPO"
  git clone --depth 1 \
    "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_PAGES_REPO}.git" \
    "$tmp/repo" 2>&1 | tail -3 || return 1
  rsync -a --delete "$SOURCE/" "$tmp/repo/" \
    --exclude '.git' --exclude '.github'
  cd "$tmp/repo"
  git add -A
  if git diff --cached --quiet; then
    echo "  [github-pages] no changes"
    cd - >/dev/null
    return 0
  fi
  git -c user.email=deploy@monerousd.org -c user.name=deploy-bot \
      commit -m "deploy-multi-cdn target=$TARGET" 2>&1 | tail -3
  git push origin HEAD 2>&1 | tail -3
  cd - >/dev/null
  echo "  [github-pages] pushed"
}

deploy_pinata() {
  : "${PINATA_JWT:?PINATA_JWT env not set}"
  echo "  [pinata-ipfs] tarballing + uploading"
  local tarball
  tarball=$(mktemp)
  trap "rm -f '$tarball'" RETURN
  tar -C "$SOURCE" -czf "$tarball" .
  local resp
  resp=$(curl -sf -X POST "https://api.pinata.cloud/pinning/pinFileToIPFS" \
    -H "Authorization: Bearer $PINATA_JWT" \
    -F "file=@$tarball" \
    -F "pinataMetadata={\"name\":\"$TARGET-$(date +%Y%m%dT%H%M%S)\"}" \
    || true)
  if [ -z "$resp" ]; then
    echo "  [pinata-ipfs] FAILED" >&2
    return 1
  fi
  local cid
  cid=$(echo "$resp" | python3 -c "import json,sys;print(json.load(sys.stdin).get('IpfsHash',''))")
  echo "  [pinata-ipfs] pinned: ipfs://$cid"
  echo "  [pinata-ipfs] gateway: https://gateway.pinata.cloud/ipfs/$cid"
}

# ─── dispatch ───────────────────────────────────────────────────────

IFS=',' read -ra DESTS <<< "$TO"
FAILED=()
SUCCEEDED=()

for d in "${DESTS[@]}"; do
  d=$(echo "$d" | tr -d '[:space:]')
  case "$d" in
    cloudflare-pages|cf-pages|cloudflare)
      if deploy_cloudflare_pages; then SUCCEEDED+=("cloudflare-pages"); else FAILED+=("cloudflare-pages"); fi
      ;;
    bunny|bunny.net|bunnycdn)
      if deploy_bunny; then SUCCEEDED+=("bunny"); else FAILED+=("bunny"); fi
      ;;
    github-pages|gh-pages|github)
      if deploy_github_pages; then SUCCEEDED+=("github-pages"); else FAILED+=("github-pages"); fi
      ;;
    pinata|ipfs)
      if deploy_pinata; then SUCCEEDED+=("pinata"); else FAILED+=("pinata"); fi
      ;;
    *)
      echo "  unknown destination: $d" >&2
      FAILED+=("$d")
      ;;
  esac
  echo ""
done

echo "  ── summary ──"
echo "  succeeded: ${SUCCEEDED[*]:-(none)}"
echo "  failed:    ${FAILED[*]:-(none)}"
[ ${#FAILED[@]} -eq 0 ] || exit 1

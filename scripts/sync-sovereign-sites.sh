#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# scripts/sync-sovereign-sites.sh
#
# Release-pipeline tool. Pulls the official site bundles from the VPS
# (${MONEROUSD_VPS_HOST}) / EDGE (${MONEROUSD_EDGE_HOST}) into build-1261/sites/ so the
# Electron build can package them via extraResources.
#
# Run BEFORE every wallet release that ships a site update.
#
# After this runs, hash + sign + write _meta.json.rootHash so Phase 2 can
# enforce SW-1 against the chain anchor.
#
# Usage:
#   ./scripts/sync-sovereign-sites.sh             # release mode — pulls from VPS+EDGE
#   VPS=root@${MONEROUSD_VPS_HOST} ./scripts/sync-sovereign-sites.sh
#   SKIP_RSYNC=1 ./scripts/sync-sovereign-sites.sh   # skip remote pulls,
#                                                    # only inject sovereign overlays
#
#   # DEV MODE — sync from local clearnet source instead of VPS/EDGE.
#   # Use this every time you edit clearnet pages so the sovereign mirror
#   # stays in sync. Wired into `npm prestart` so it runs automatically.
#   LOCAL_FRONTEND=1 ./scripts/sync-sovereign-sites.sh
#
#   # Override individual local sources:
#   LOCAL_ION_FRONTEND=/abs/path/to/ion-monerousd-org/frontend \
#   LOCAL_MONEROUSD_SITE=/abs/path/to/monerousd-site \
#     ./scripts/sync-sovereign-sites.sh
#
# Sites synced:
#   /var/www/monerousd-site/                  → build-1261/sites/monerousd-org/
#   /var/www/ion-monerousd-org/               → build-1261/sites/ionswap-monerousd-org/
#   /var/www/explorer-monerousd-org/          → build-1261/sites/explorer-monerousd-org/
#                                               (Phase 3 — SPA port lands here)
#   monerousd-ide/dist/monerousd-ide-<v>/     → build-1261/sites/ide-monerousd-org/
#                                               (built locally by scripts/build-bundle.sh)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPS="${VPS:-root@${MONEROUSD_VPS_HOST}}"
EDGE="${EDGE:-root@${MONEROUSD_EDGE_HOST}}"
DEST_ROOT="$REPO_ROOT/build-1261/sites"
APP_VERSION="$(grep '"version"' "$REPO_ROOT/build-1261/package.json" | head -1 | cut -d'"' -f4)"

# LOCAL_FRONTEND=1 → auto-detect in-repo clearnet source and rsync from there.
# This is the dev-mode default; `npm prestart` flips it on automatically.
# Otherwise the script behaves as a release pipeline tool (VPS+EDGE pulls).
if [ "${LOCAL_FRONTEND:-0}" = "1" ]; then
  : "${LOCAL_ION_FRONTEND:=$REPO_ROOT/ion-monerousd-org/frontend}"
  # No local source for monerousd-site (it lives only on the VPS) so we
  # leave it alone in dev mode unless the operator points us at one.
fi

echo "[sync-sovereign-sites] VPS=$VPS  EDGE=$EDGE"
echo "[sync-sovereign-sites] DEST=$DEST_ROOT"
echo "[sync-sovereign-sites] APP_VERSION=$APP_VERSION"
if [ -n "${LOCAL_ION_FRONTEND:-}" ]; then
  echo "[sync-sovereign-sites] LOCAL_ION_FRONTEND=$LOCAL_ION_FRONTEND"
fi
if [ -n "${LOCAL_MONEROUSD_SITE:-}" ]; then
  echo "[sync-sovereign-sites] LOCAL_MONEROUSD_SITE=$LOCAL_MONEROUSD_SITE"
fi

# Sovereign-only overlay paths that must never be deleted by rsync --delete.
# These are added by Phase 3 (offline cache) and Phase 1 (_meta.json) — they
# do not exist on the live operator's filesystem.
SOVEREIGN_OVERLAYS=(
  "_meta.json"
  "_offline-api"
  "js/offline-cache.js"
)

# ---------------------------------------------------------------------------
# Helper: inject `<script src="js/offline-cache.js"></script>` into a site's
# index.html as the FIRST script tag, idempotently. The wrapped fetch must be
# in place before any client lib (swap-client.js, amm-client.js) reaches for
# it. Safe to re-run — the marker comment is the dedup key.
# ---------------------------------------------------------------------------
inject_offline_cache() {
  local html="$1"
  if [ ! -f "$html" ]; then
    echo "[inject] skip — $html not found"
    return 0
  fi
  if grep -q 'sov-offline-cache-installed' "$html"; then
    echo "[inject] already installed in $html"
    return 0
  fi
  # Insert just before </head> (or before the first <script> if no </head>).
  local marker='<!-- sov-offline-cache-installed -->'
  local script_tag='<script src="js/offline-cache.js"></script>'
  if grep -q '</head>' "$html"; then
    sed -i.bak "s#</head>#  $marker\n  $script_tag\n</head>#" "$html"
  else
    sed -i.bak "0,/<script/s#<script#$marker\n$script_tag\n<script#" "$html"
  fi
  rm -f "$html.bak"
  echo "[inject] $script_tag → $html"
}

# ---------------------------------------------------------------------------
# Helper: write the bundled offline-cache.js into the site's js/ dir.
# Sourced from this repo's reference copy so the file is identical across
# every sovereign mirror.
# ---------------------------------------------------------------------------
copy_offline_cache_js() {
  local site_dir="$1"
  local src="$DEST_ROOT/ionswap-monerousd-org/js/offline-cache.js"
  if [ ! -f "$src" ]; then
    echo "[overlay] WARN: reference offline-cache.js not found at $src"
    return 0
  fi
  mkdir -p "$site_dir/js"
  cp "$src" "$site_dir/js/offline-cache.js"
  echo "[overlay] offline-cache.js → $site_dir/js/"
}

# ---------------------------------------------------------------------------
# Helper: write _offline-api/ tree from the reference copy.
# ---------------------------------------------------------------------------
copy_offline_api_tree() {
  local site_dir="$1"
  local src="$DEST_ROOT/ionswap-monerousd-org/_offline-api"
  if [ ! -d "$src" ]; then
    echo "[overlay] WARN: reference _offline-api/ not found at $src"
    return 0
  fi
  rsync -a --delete "$src/" "$site_dir/_offline-api/"
  echo "[overlay] _offline-api/ → $site_dir/"
}

# ---------------------------------------------------------------------------
# Helper: stamp _meta.json with the current bundle's size + version.
# ---------------------------------------------------------------------------
stamp_meta() {
  local site_dir="$1"
  local content_type="$2"
  local display_name="$3"
  local primary_domain="$4"
  local tier="$5"           # T1, T2, T3
  local verified="$6"        # true / false

  # Portable byte-count: macOS `du` lacks `-b`. Use `find + stat`
  # with a per-OS stat flag, then fall back to `du -sk` × 1024 if
  # both forms fail (extremely defensive — find/stat work on
  # every supported platform).
  local size
  if [ "$(uname)" = "Darwin" ]; then
    size=$(find "$site_dir" -type f -exec stat -f%z {} \; 2>/dev/null | awk '{s+=$1} END {print s+0}')
  else
    size=$(du -sb "$site_dir" 2>/dev/null | cut -f1)
  fi
  if [ -z "$size" ] || [ "$size" = "0" ]; then
    size=$(( $(du -sk "$site_dir" | cut -f1) * 1024 ))
  fi
  cat > "$site_dir/_meta.json" <<EOF
{
  "version": "$APP_VERSION",
  "contentType": "$content_type",
  "rootHash": null,
  "bundleSize": $size,
  "publisher": "official",
  "publishedAt": null,
  "displayName": "$display_name",
  "primaryDomain": "$primary_domain",
  "tier": "$tier",
  "verified": $verified
}
EOF
  echo "[meta] $site_dir/_meta.json (bundleSize=$size)"
}

# ===========================================================================
# 1) monerousd.org — static main site
# ===========================================================================
DEST_MO="$DEST_ROOT/monerousd-org"
echo "[sync] monerousd.org → $DEST_MO"
mkdir -p "$DEST_MO"

if [ "${SKIP_RSYNC:-0}" != "1" ]; then
  # The VPS docroot for monerousd.org doubles as the OTA hosting target,
  # so it ships a `Monero USD Wallet-*.dmg|zip|exe|AppImage|deb` per
  # release plus `latest*.yml` blockmaps. Those binaries can grow the
  # bundle into the multi-GB range and would inflate the wallet
  # installer to a useless size. Exclude them from the T1 mirror — the
  # OTA flow uses `update.monerousd.org` directly, not the sovereign
  # mirror.
  BINARY_EXCLUDES=(
    --exclude '*.dmg'        --exclude '*.dmg.blockmap'
    --exclude '*.zip'        --exclude '*.zip.blockmap'
    --exclude '*.AppImage'   --exclude '*.deb'
    --exclude '*.exe'        --exclude 'latest*.yml'
  )
  if [ -n "${LOCAL_MONEROUSD_SITE:-}" ] && [ -d "$LOCAL_MONEROUSD_SITE" ]; then
    echo "[sync]   source: LOCAL $LOCAL_MONEROUSD_SITE"
    rsync -a --delete \
      --exclude '.git' --exclude 'node_modules' \
      "${BINARY_EXCLUDES[@]}" \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$LOCAL_MONEROUSD_SITE/" "$DEST_MO/" || \
      echo "[sync] WARN — local main-site rsync failed, keeping current contents"
  elif [ "${LOCAL_FRONTEND:-0}" = "1" ]; then
    # Dev mode without an explicit local source — keep the current bundle.
    # Avoids a network round-trip to the VPS on every `npm start`.
    echo "[sync]   skipped (LOCAL_FRONTEND=1 + no LOCAL_MONEROUSD_SITE) — keeping existing bundle"
  else
    echo "[sync]   source: VPS $VPS:/var/www/monerousd-site/"
    rsync -av --delete \
      --exclude '.git' --exclude 'node_modules' \
      "${BINARY_EXCLUDES[@]}" \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$VPS:/var/www/monerousd-site/" "$DEST_MO/" || \
      echo "[sync] WARN — main-site rsync failed, keeping current contents"
  fi
fi
stamp_meta "$DEST_MO" "static" "MoneroUSD" "monerousd.org" "T1" "true"
# main site doesn't call /api/* or /v1/*, so offline-cache is unnecessary —
# but we still inject it to keep behavior uniform across mirrors.
inject_offline_cache "$DEST_MO/index.html"
copy_offline_cache_js "$DEST_MO"

# ===========================================================================
# 2) ionswap.monerousd.org — DEX SPA + offline cache
# ===========================================================================
DEST_IS="$DEST_ROOT/ionswap-monerousd-org"
echo "[sync] ionswap.monerousd.org → $DEST_IS"
mkdir -p "$DEST_IS"

if [ "${SKIP_RSYNC:-0}" != "1" ]; then
  if [ -n "${LOCAL_ION_FRONTEND:-}" ] && [ -d "$LOCAL_ION_FRONTEND" ]; then
    # Sync from the local clearnet source. This is the dev-mode default
    # under `LOCAL_FRONTEND=1` — every clearnet edit lands in the
    # sovereign bundle on the next `npm start`. Keeps the two surfaces
    # from drifting apart silently.
    echo "[sync]   source: LOCAL $LOCAL_ION_FRONTEND"
    rsync -a --delete \
      --exclude '.git' --exclude 'node_modules' \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$LOCAL_ION_FRONTEND/" "$DEST_IS/" || \
      echo "[sync] WARN — local Ion Swap frontend rsync failed, keeping current placeholder"
  else
    # Pull from the EDGE (which holds the deployed frontend, per the
    # Ion Swap dual-server topology). The edge serves at the path
    # /var/www/ion-monerousd-org/.
    echo "[sync]   source: EDGE $EDGE:/var/www/ion-monerousd-org/"
    rsync -av --delete \
      --exclude '.git' --exclude 'node_modules' \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$EDGE:/var/www/ion-monerousd-org/" "$DEST_IS/" || \
      echo "[sync] WARN — Ion Swap frontend rsync failed, keeping current placeholder"
  fi
fi
# Restore sovereign overlays AFTER the rsync (they were excluded above).
copy_offline_cache_js "$DEST_IS"
copy_offline_api_tree "$DEST_IS"
inject_offline_cache "$DEST_IS/index.html"
stamp_meta "$DEST_IS" "spa-with-api" "Ion Swap" "ionswap.monerousd.org" "T1" "true"

# ===========================================================================
# 3) explorer.monerousd.org — Phase 3 SPA shell
# ===========================================================================
DEST_EX="$DEST_ROOT/explorer-monerousd-org"
echo "[sync] explorer.monerousd.org → $DEST_EX"
mkdir -p "$DEST_EX"

if [ "${SKIP_RSYNC:-0}" != "1" ]; then
  if [ "${LOCAL_FRONTEND:-0}" = "1" ]; then
    echo "[sync]   skipped (LOCAL_FRONTEND=1) — Phase 3 explorer SPA shell is bundled locally"
  else
    rsync -av --delete \
      --exclude '.git' --exclude 'node_modules' --exclude 'views' \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$VPS:/var/www/explorer-monerousd-org/" "$DEST_EX/" 2>/dev/null || \
      echo "[sync] explorer rsync skipped (Phase 3 SPA shell is bundled locally)"
  fi
fi
copy_offline_cache_js "$DEST_EX"
inject_offline_cache "$DEST_EX/index.html"
stamp_meta "$DEST_EX" "spa-with-api" "Explorer" "explorer.monerousd.org" "T1" "true"

# ===========================================================================
# 4) ide.monerousd.org — MoneroUSD IDE (built locally, not pulled from VPS)
# ===========================================================================
DEST_IDE="$DEST_ROOT/ide-monerousd-org"
IDE_REPO="$REPO_ROOT/monerousd-ide"
echo "[sync] ide.monerousd.org → $DEST_IDE"
mkdir -p "$DEST_IDE"

if [ -d "$IDE_REPO" ]; then
  IDE_VERSION="$(grep '"version"' "$IDE_REPO/package.json" | head -1 | cut -d'"' -f4)"
  IDE_STAGE="$IDE_REPO/dist/monerousd-ide-${IDE_VERSION}"
  # Build the bundle if it isn't already staged. build-bundle.sh is reproducible
  # so re-running is cheap once Monaco + fonts are vendored.
  if [ ! -d "$IDE_STAGE" ] && [ "${SKIP_IDE_BUILD:-0}" != "1" ]; then
    echo "[sync]   building IDE v${IDE_VERSION} via $IDE_REPO/scripts/build-bundle.sh"
    ( cd "$IDE_REPO" && bash scripts/build-bundle.sh ) || \
      echo "[sync] WARN — IDE build-bundle.sh failed, keeping current bundle"
  fi
  if [ -d "$IDE_STAGE" ]; then
    echo "[sync]   source: LOCAL $IDE_STAGE"
    rsync -a --delete \
      --exclude '.git' --exclude 'node_modules' \
      $(printf -- '--exclude %s ' "${SOVEREIGN_OVERLAYS[@]}") \
      "$IDE_STAGE/" "$DEST_IDE/"
  else
    echo "[sync]   no IDE bundle staged at $IDE_STAGE — keeping current contents"
  fi
else
  echo "[sync]   monerousd-ide/ repo not found at $IDE_REPO — keeping current placeholder"
fi
# IDE talks to /v1/* directly via the sovereign-server proxy — no offline-cache
# overlay needed. Stamp _meta.json with the wallet-build version so the
# T1 entry advertises the same version as the wallet bundle.
stamp_meta "$DEST_IDE" "spa" "MoneroUSD IDE" "ide.monerousd.org" "T1" "true"

echo "[sync-sovereign-sites] done."

#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# publish-usdmd-bundle.sh — operator-side daemon-bundle release script.
#
# Pairs with /usr/local/bin/usdmd-auto-update.sh (running on every
# peer node). Workflow:
#
#   1. Operator rebuilds USDmd on the canonical VPS:
#        cd /root/MoneroUSD/MoneroUSD-main/build-linux && cmake --build . --target daemon -j4
#
#   2. Operator runs THIS script:
#        scripts/publish-usdmd-bundle.sh [--version <tag>]
#
#   3. Every other peer node (edge, user laptops, future operators)
#      auto-pulls the new bundle within 6h, verifies SHA-256, atomic
#      swaps, restarts. Health-check + auto-rollback on failure.
#
# What this script does:
#   - Gathers the binary + every transitive lib it depends on
#     (resolved via `ldd`).
#   - Tarballs into a self-contained bundle that runs on any Linux
#     host via /usr/local/bin/usdmd-auto-update.sh's bundled
#     ld-linux-x86-64.so.2 + LD_LIBRARY_PATH technique.
#   - Computes SHA-256 + MD5 hashes.
#   - Writes /var/www/monerousd-updates/usdmd-bundle/manifest.json
#     + the timestamped tarball.
#   - The web server (already serving update.monerousd.org) picks
#     them up automatically.
#
# CRITICAL — only run on the canonical VPS. Pushing a bad manifest
# from a non-canonical machine would cause every peer node to
# auto-update to an attacker-controlled binary (Phase 1 trust:
# canonical-hostname-only). Phase 2 adds ed25519-signed manifests.

set -euo pipefail

VERSION_TAG="${1:-}"
BINARY="${BINARY:-/root/MoneroUSD/MoneroUSD-main/build-linux/bin/USDmd}"
PUBLISH_DIR="${PUBLISH_DIR:-/var/www/monerousd-updates/usdmd-bundle}"

if [[ "$VERSION_TAG" == "--version" ]]; then
  VERSION_TAG="$2"
fi
if [[ -z "$VERSION_TAG" ]]; then
  VERSION_TAG="$(date -u +%Y%m%d-%H%M%S)"
fi

[[ -x "$BINARY" ]] || { echo "ERROR: binary not found or not executable: $BINARY"; exit 1; }
[[ -d "$PUBLISH_DIR" ]] || mkdir -p "$PUBLISH_DIR"

VERSION="1.2.x-daemon-$VERSION_TAG"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "[publish] staging bundle for $VERSION"
mkdir -p "$TMPDIR/bundle/lib"
cp -L "$BINARY" "$TMPDIR/bundle/USDmd"

# Resolve every transitive lib dep + the dynamic linker.
ldd "$BINARY" 2>/dev/null | awk '{print $3}' | grep -v '^$' | sort -u > "$TMPDIR/deps.txt"
DEP_COUNT=$(wc -l < "$TMPDIR/deps.txt")
echo "[publish] $DEP_COUNT direct lib deps"
while read -r f; do
  [[ -f "$f" ]] && cp -L "$f" "$TMPDIR/bundle/lib/" || true
done < "$TMPDIR/deps.txt"
# The dynamic linker itself (the bundle's start-script invokes it
# with --library-path to pin the bundled libs).
cp /lib64/ld-linux-x86-64.so.2 "$TMPDIR/bundle/lib/" 2>/dev/null \
  || cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$TMPDIR/bundle/lib/"

LIB_COUNT=$(ls "$TMPDIR/bundle/lib/" | wc -l)
echo "[publish] $LIB_COUNT libs bundled"

# Pack
TARBALL="$TMPDIR/usdmd-bundle-$VERSION.tar.gz"
tar czf "$TARBALL" -C "$TMPDIR/bundle" .

SHA256=$(sha256sum "$TARBALL" | awk '{print $1}')
MD5=$(   md5sum "$BINARY"     | awk '{print $1}')
SIZE=$(  stat -c %s "$TARBALL")

echo "[publish] bundle sha256:  $SHA256"
echo "[publish] binary md5:     $MD5"
echo "[publish] bundle size:    $SIZE bytes"

# Move into publish dir + write manifest
cp "$TARBALL" "$PUBLISH_DIR/usdmd-bundle-$VERSION.tar.gz"

cat > "$PUBLISH_DIR/manifest.json" <<EOF
{
  "version": "$VERSION",
  "released_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "binary_md5": "$MD5",
  "bundle_url": "https://update.monerousd.org/usdmd-bundle/usdmd-bundle-$VERSION.tar.gz",
  "bundle_sha256": "$SHA256",
  "bundle_bytes": $SIZE
}
EOF

echo "[publish] manifest:"
cat "$PUBLISH_DIR/manifest.json"
echo "[publish] DONE"
echo "[publish] every peer node running usdmd-auto-update.sh will"
echo "[publish] pick up $VERSION within 6h (or run the script with --check"
echo "[publish] for an immediate dry-run)."

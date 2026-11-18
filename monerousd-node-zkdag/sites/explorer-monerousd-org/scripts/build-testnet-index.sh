#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# build-testnet-index.sh
# ─────────────────────────────────────────────────────────────────────
# Generates testnet/index.html from the root index.html so that
# GitHub Pages serves the SPA at explorer.monerousd.org/testnet
# (path-prefix routing, like Ion Swap — no new nameserver needed).
#
# The ONLY transformation is absolutizing the two relative asset refs
# (styles/theme.css, app.js) → /styles/theme.css, /app.js — so the
# copy living at /testnet/ loads the SAME root assets instead of
# nonexistent /testnet/app.js. Everything else is byte-identical, so
# there is zero structural drift: re-run this after ANY index.html
# edit and commit both files.
#
# The SPA reads window.location.pathname to decide mainnet vs testnet
# (see lib/data-source.js::getNetwork) — there is NO separate testnet
# bundle, just this thin index that points at the shared root assets.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$here/index.html"
out_dir="$here/testnet"
out="$out_dir/index.html"

[ -f "$src" ] || { echo "ERROR: $src not found" >&2; exit 1; }
mkdir -p "$out_dir"

# Absolutize the two relative asset references. Anchored on the exact
# attribute prefixes so we never touch hash links (href="#/...").
sed -E \
  -e 's#(href=")styles/#\1/styles/#g' \
  -e 's#(src=")app\.js#\1/app.js#g' \
  "$src" > "$out"

# Sanity: the generated file must reference the absolute assets and
# must NOT contain a relative app.js/styles ref anymore.
if grep -qE '(href="styles/|src="app\.js)' "$out"; then
  echo "ERROR: testnet/index.html still has relative asset refs" >&2
  exit 1
fi
if ! grep -q 'src="/app.js' "$out" || ! grep -q 'href="/styles/theme.css' "$out"; then
  echo "ERROR: testnet/index.html missing absolutized asset refs" >&2
  exit 1
fi

echo "✓ generated $out (absolute asset refs → shared root bundle)"

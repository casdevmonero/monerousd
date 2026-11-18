#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# deploy-sovereign-site.sh
#
# Generalized version of `deploy-sovereign-ota.sh` for ANY static
# sovereign site (monerousd.org, ide.monerousd.org,
# explorer.monerousd.org, installers.monerousd.org). Same trust
# pattern: a public GitHub repo with GitHub Pages serves the static
# bundle at a custom domain via Njalla CNAME (subdomain) or A
# records (apex).
#
# Each deploy is fully isolated:
#   • Fresh `mktemp -d` working directory (no cross-contamination)
#   • Permissive `.gitignore` from `ota-mirror-gitignore.template`
#     (default-deny → only OTA artifact patterns allowed). Adapted
#     here to also allow .html, .css, .js, .svg, .png, fonts, etc.
#     since this is a SITE bundle, not just OTA artifacts.
#   • Bundle SHA-anchored via `_meta.json` rootHash (the wallet's
#     site-updater verifies; CDN-served bytes are the same).
#
# USAGE
#   bash scripts/deploy-sovereign-site.sh \
#     --src   build-1261/sites/monerousd-org \
#     --domain monerousd.org \
#     --repo  monerousd-org-site \
#     --org   casdevmonero
#
# For the APEX domain `monerousd.org`, the script tells you to
# point 4 A records at GitHub Pages anycast IPs at the end. For
# subdomains, it tells you the single CNAME line.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

SRC=""
DOMAIN=""
REPO=""
ORG=""
DRY_RUN="false"

while [ $# -gt 0 ]; do
  case "$1" in
    --src)     SRC="$2"; shift 2 ;;
    --domain)  DOMAIN="$2"; shift 2 ;;
    --repo)    REPO="$2"; shift 2 ;;
    --org)     ORG="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

[ -z "$SRC" ]    && { echo "--src <bundle-dir> required"     >&2; exit 1; }
[ -z "$DOMAIN" ] && { echo "--domain <hostname> required"     >&2; exit 1; }
[ -z "$REPO" ]   && { echo "--repo <name> required"           >&2; exit 1; }
[ -z "$ORG" ]    && { echo "--org <gh-user> required"         >&2; exit 1; }
[ ! -d "$SRC" ]  && { echo "--src dir not found: $SRC"        >&2; exit 1; }

if ! command -v gh >/dev/null 2>&1; then
  echo "  gh CLI not installed; brew install gh" >&2; exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "  gh not authenticated; gh auth login" >&2; exit 1
fi

SRC=$(cd "$SRC" && pwd)
echo "  ── Sovereign site deploy ──"
echo "    src:    $SRC"
echo "    domain: $DOMAIN"
echo "    repo:   $ORG/$REPO"
echo "    files:  $(find "$SRC" -type f | wc -l | awk '{print $1}')"
echo "    size:   $(du -sh "$SRC" | awk '{print $1}')"
echo ""

# ─── 1. ensure repo exists ──────────────────────────────────────────

if gh repo view "$ORG/$REPO" >/dev/null 2>&1; then
  echo "  ✓ repo $ORG/$REPO already exists"
else
  if [ "$DRY_RUN" = "true" ]; then
    echo "  [dry] would create $ORG/$REPO"
  else
    gh repo create "$ORG/$REPO" --public --description "MoneroUSD sovereign mirror — $DOMAIN. Public for unauthenticated browser access. Default-deny gitignore prevents secret leaks." 2>&1 | tail -3
    echo "  ✓ created $ORG/$REPO"
  fi
fi

# ─── 2. stage the bundle in a fresh tmp dir ─────────────────────────

WORK=$(mktemp -d)
trap "rm -rf '$WORK'" EXIT

# Mirror the source bundle into work dir.
# `--exclude` keeps Claude / IDE / OS metadata out (defense in depth;
# default-deny gitignore catches them too).
rsync -a \
  --exclude='.claude*' \
  --exclude='.cursor*' \
  --exclude='.DS_Store' \
  --exclude='.idea*' \
  --exclude='.vscode*' \
  --exclude='*.swp' \
  --exclude='*.swo' \
  --exclude='*.pem' \
  --exclude='*.key' \
  --exclude='*.seed' \
  --exclude='*.env' \
  --exclude='node_modules' \
  --exclude='__pycache__' \
  "$SRC/" "$WORK/"

# Permissive site-bundle .gitignore — denies sensitive globs but
# allows the standard static-site mime types.
cat > "$WORK/.gitignore" <<'GITIGNORE'
# Sovereign site bundle — default-deny stance with web-asset allowlist.
# Anything not explicitly allowed is blocked. New file types adding to
# the bundle require a PR updating this list.

# Default-deny.
*

# Web assets
!*.html
!*.htm
!*.css
!*.js
!*.cjs
!*.mjs
!*.json
!*.yml
!*.yaml
!*.svg
!*.png
!*.jpg
!*.jpeg
!*.gif
!*.webp
!*.ico
!*.woff
!*.woff2
!*.ttf
!*.otf
!*.txt
!*.md
!*.pdf
!*.wasm
!*.xml
!*.mp4
!*.webm

# Bundle metadata
!_meta.json
!SHA256SUMS

# The bundle's own license, shipped with every copy (IonSwap's front end is BUSL-1.1, whose terms require the license
# to be shown on each copy; the repository's Apache-2.0 sites carry it the same way)
!LICENSE
!NOTICE

# GitHub Pages markers
!CNAME
!.gitignore
!.nojekyll

# Allow descending into directories so the patterns above can match
# nested files. Without this, `*` would block every directory and
# the !-allowlist below would never be reached.
!*/

# Explicit deny — credential-class files (defense in depth)
*.seed
*.keys
*.wallet
*.address.txt
*.spend_key
*.view_key
*.pem
*.key
*.crt
*.p12
*.pfx
*.gpg
*.asc
.env
.env.*
.envrc
secrets.*
credentials.*
*.token
*.pat
.npmrc
.netrc

# Personal config dirs
.aws/
.ssh/
.gnupg/
.monerousd/
.docker/
.claude/
.cursor/

# OS / IDE metadata
.DS_Store
.idea/
.vscode/
*.swp
*.swo

# Database files
*.db
*.sqlite
*.sqlite3
*.db-shm
*.db-wal
GITIGNORE

# CNAME for GitHub Pages custom domain
printf '%s' "$DOMAIN" > "$WORK/CNAME"

# .nojekyll — don't run Jekyll, just serve the bundle as-is
touch "$WORK/.nojekyll"

# README — explains what's in this repo
cat > "$WORK/README.md" <<README
# MoneroUSD Sovereign Mirror — \`$DOMAIN\`

This is the public, GitHub Pages-served mirror of the MoneroUSD
sovereign site at \`https://$DOMAIN\`. The bundle is byte-identical
to the chain-anchored T2 bundle (per SITE_PUBLISH attestation) and
to the T1 bundle shipped inside the desktop wallet's installer.

## Trust model

The bytes here are NOT trusted directly — the wallet verifies every
byte against the chain-anchored \`rootHash\` from the
\`SITE_PUBLISH\` attestation before rendering. This repo is just a
fast, free, anycast-served transport.

## Why public

GitHub Pages requires a public repo on the free tier, and any wallet
or browser must be able to fetch the bundle without authentication.
The default-deny \`.gitignore\` prevents wallet seeds, SSH keys,
PATs, env files, or Claude state from accidentally landing here.
README

# ─── 3. push to GitHub ──────────────────────────────────────────────

cd "$WORK"
git init -q
git checkout -q -b main
git add -A
git -c user.email="deploy@monerousd.org" -c user.name="sovereign-deploy" \
    commit -q -m "Sovereign site deploy: $DOMAIN"

git remote add origin "https://github.com/$ORG/$REPO.git"
if [ "$DRY_RUN" = "true" ]; then
  echo "  [dry] would force-push to $ORG/$REPO main"
else
  git push -q --force origin main 2>&1 | tail -3
  echo "  ✓ pushed to $ORG/$REPO"
fi

cd /

# ─── 4. enable GitHub Pages ─────────────────────────────────────────

if [ "$DRY_RUN" = "false" ]; then
  gh api -X POST "repos/$ORG/$REPO/pages" \
    -f source[branch]=main \
    -f source[path]=/ \
    -H "Accept: application/vnd.github+json" >/dev/null 2>&1 || \
  gh api -X PUT "repos/$ORG/$REPO/pages" \
    -f source[branch]=main \
    -f source[path]=/ \
    -H "Accept: application/vnd.github+json" >/dev/null 2>&1 || true
  echo "  ✓ Pages enabled for $ORG/$REPO (custom domain via CNAME file)"
fi

# ─── 5. DNS instructions ────────────────────────────────────────────

echo ""
echo "  ── deploy complete: $DOMAIN ──"
echo ""
echo "  Source repo:  https://github.com/$ORG/$REPO"
echo "  Pages URL:    https://${ORG}.github.io/$REPO/"

if [[ "$DOMAIN" == *.* && "$DOMAIN" != *.*.* ]]; then
  # APEX (only one dot — e.g. "monerousd.org")
  echo ""
  echo "  ── Njalla DNS (APEX — needs 4 A records) ──"
  echo ""
  echo "  Type   Name   Content              TTL"
  echo "  A      @      185.199.108.153      300"
  echo "  A      @      185.199.109.153      300"
  echo "  A      @      185.199.110.153      300"
  echo "  A      @      185.199.111.153      300"
  echo ""
  echo "  Optional AAAA (IPv6):"
  echo "  AAAA   @      2606:50c0:8000::153"
  echo "  AAAA   @      2606:50c0:8001::153"
  echo "  AAAA   @      2606:50c0:8002::153"
  echo "  AAAA   @      2606:50c0:8003::153"
else
  # Subdomain — single CNAME
  SUB=${DOMAIN%%.*}
  echo ""
  echo "  ── Njalla DNS (subdomain — single CNAME) ──"
  echo ""
  echo "  Type   Name        Content                          TTL"
  echo "  CNAME  $SUB        $ORG.github.io.                  300"
fi

echo ""
echo "  After DNS propagates (~5-10 min), GitHub auto-issues a TLS"
echo "  cert (~5-30 min more). Verify with:"
echo "    curl -sI https://$DOMAIN/"

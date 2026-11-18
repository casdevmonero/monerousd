#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# deploy-sovereign-ota.sh
#
# Phase 5 — sovereign OTA ship. Drives the entire deploy without any
# third-party SaaS hosting (GitHub-only, since the operator already
# has a GitHub identity). The OTA path becomes:
#
#   wallet → DNS update.monerousd.org → CNAME → <user>.github.io
#                                              ↓ serves /latest-mac.yml
#                                              ↓ which has absolute URLs
#                                              ↓ → github.com/.../releases/download/v1.2.209/...
#                                              ↓ binaries served by GitHub Releases
#
# Two repos:
#   1. <ORG>/<OTA_RELEASES_REPO>  — public — holds GitHub Releases
#      with the per-platform binaries. Binaries are >25MB so this
#      cannot be GitHub Pages alone.
#   2. <ORG>/<OTA_MANIFEST_REPO>  — public, GitHub Pages enabled —
#      holds the rewritten latest-*.yml manifests with absolute URLs
#      pointing at Releases. Tiny, fast, custom-domain-CNAME-able.
#
# Wallet's electron-updater fetches `latest-mac.yml` from the manifest
# repo (via the CNAME), reads the absolute file URLs, downloads the
# binaries directly from GitHub Releases. No SaaS dependency beyond
# GitHub itself.
#
# Both repos start with the security-perimeter `.gitignore` that
# default-denies everything except OTA artifacts (see
# `scripts/ota-mirror-gitignore.template`). A leaked wallet seed /
# SSH key / PAT cannot accidentally land in either repo.
#
# REQUIREMENTS
#   • `gh` CLI installed + authenticated (`gh auth login`)
#   • out/ota-mirror/ pre-built (bash scripts/build-ota-mirror.sh OR
#     re-derived from build-1261/dist/ — this script does that step
#     idempotently)
#
# OUTPUT
#   • Two GitHub repos created (idempotent: `gh repo create` exits
#     non-fatally if already exists; we proceed)
#   • One Release per --version on the releases repo
#   • One commit per --version on the manifest repo
#   • Custom domain CNAME instructions printed at the end
#
# USAGE
#   bash scripts/deploy-sovereign-ota.sh \
#     --version 1.2.209 \
#     --org <your-github-org> \
#     --releases-repo monerousd-ota-releases \
#     --manifest-repo monerousd-ota-manifest \
#     --custom-domain update.monerousd.org
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── arg parsing ────────────────────────────────────────────────────

VERSION=""
ORG=""
RELEASES_REPO=""
MANIFEST_REPO=""
CUSTOM_DOMAIN=""
DRY_RUN="false"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)        VERSION="$2"; shift 2 ;;
    --org)            ORG="$2"; shift 2 ;;
    --releases-repo)  RELEASES_REPO="$2"; shift 2 ;;
    --manifest-repo)  MANIFEST_REPO="$2"; shift 2 ;;
    --custom-domain)  CUSTOM_DOMAIN="$2"; shift 2 ;;
    --dry-run)        DRY_RUN="true"; shift ;;
    -h|--help)
      sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

[ -z "$VERSION" ]       && { echo "--version required"        >&2; exit 1; }
[ -z "$ORG" ]           && { echo "--org (your gh user) required"       >&2; exit 1; }
[ -z "$RELEASES_REPO" ] && { echo "--releases-repo required"  >&2; exit 1; }
[ -z "$MANIFEST_REPO" ] && { echo "--manifest-repo required"  >&2; exit 1; }
[ -z "$CUSTOM_DOMAIN" ] && CUSTOM_DOMAIN="${ORG}.github.io"

PROJECT_ROOT=$HOME/Desktop/connect
DIST_DIR="$PROJECT_ROOT/build-1261/dist"
MIRROR_DIR="$PROJECT_ROOT/out/ota-mirror"
GITIGNORE_TEMPLATE="$PROJECT_ROOT/scripts/ota-mirror-gitignore.template"

echo "  ── Sovereign OTA deploy ──"
echo "    version:        $VERSION"
echo "    org:            $ORG"
echo "    releases repo:  $ORG/$RELEASES_REPO"
echo "    manifest repo:  $ORG/$MANIFEST_REPO"
echo "    custom domain:  $CUSTOM_DOMAIN"
echo "    dry run:        $DRY_RUN"
echo ""

# ─── 0. preflight ───────────────────────────────────────────────────

if ! command -v gh >/dev/null 2>&1; then
  echo "  ✗ gh CLI not installed; run: brew install gh" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "  ✗ gh not authenticated; run: gh auth login" >&2
  exit 1
fi
GH_USER=$(gh api user --jq '.login' 2>/dev/null || echo "")
if [ -z "$GH_USER" ]; then
  echo "  ✗ gh auth status passed but couldn't read user — check auth" >&2
  exit 1
fi
echo "  ✓ gh authenticated as $GH_USER"

# ─── 1. build the OTA mirror subset (idempotent) ────────────────────

if [ ! -d "$DIST_DIR" ]; then
  echo "  ✗ dist dir not found: $DIST_DIR" >&2
  exit 1
fi
if [ ! -f "$DIST_DIR/latest-mac.yml" ]; then
  echo "  ✗ latest-mac.yml missing in dist/" >&2
  exit 1
fi

mkdir -p "$MIRROR_DIR"
echo "  building OTA mirror subset for v$VERSION at $MIRROR_DIR"

# Use a small node script to copy the manifests + binaries for this
# version. Reference incident (2026-05-15): the previous URL-parse
# version of this block looked for files at `path.join(distDir, url)`
# where `url` was the FULL https:// GitHub URL written by
# rewrite-yml-urls.js. That path never existed on disk, so the binary
# copy silently skipped EVERY file — only the .yml manifests landed
# in the mirror. The deploy then uploaded ONLY whatever stale
# artifacts were already in `out/ota-mirror/` from prior runs to the
# new release tag, leaving the new version's URLs pointing at
# 404s. User-visible symptom: "Update vX.Y.Z download failed."
#
# This rewrite enumerates `dist/` directly for files matching
# `*VERSION*` and copies them, applying the same space→dot rename
# that rewrite-yml-urls.js applies to URLs (so the mirror's filenames
# match what GitHub's asset uploader normalizes to). The YML
# manifests are copied verbatim.
node - <<NODE
const fs = require('fs');
const path = require('path');
const distDir = '$DIST_DIR';
const mirrorDir = '$MIRROR_DIR';
const version = '$VERSION';

// Copy the version-stamped binaries from dist/. The GitHub asset
// uploader renames spaces to dots ("Monero USD Wallet-X-mac.zip"
// → "Monero.USD.Wallet-X-mac.zip"); we apply the same rename here
// so the mirror filenames match the URLs in the rewritten YMLs.
let copied = 0;
for (const entry of fs.readdirSync(distDir)) {
  if (!entry.includes(version)) continue;
  if (/\\.(dmg|zip|exe|AppImage|deb|blockmap)$/.test(entry)) {
    const src = path.join(distDir, entry);
    const dst = path.join(mirrorDir, entry.replace(/ /g, '.'));
    fs.copyFileSync(src, dst);
    console.log('  + ' + path.basename(dst));
    copied++;
  }
}
if (copied === 0) {
  console.error('  ✗ no version-stamped binaries found in ' + distDir +
                ' for v' + version + ' — did electron-builder run?');
  process.exit(1);
}

// YML manifests carry the rewritten absolute GitHub URLs; copy them
// verbatim so the manifest repo push (later in the script) lands
// them unchanged.
for (const yml of ['latest-mac.yml', 'latest.yml', 'latest-linux.yml']) {
  const src = path.join(distDir, yml);
  if (!fs.existsSync(src)) continue;
  fs.copyFileSync(src, path.join(mirrorDir, yml));
  console.log('  + ' + yml);
}
NODE

du -sh "$MIRROR_DIR"

# ─── 2. ensure both repos exist (idempotent) ────────────────────────

ensure_repo() {
  local repo="$1"
  local desc="$2"
  if gh repo view "$ORG/$repo" >/dev/null 2>&1; then
    echo "  ✓ repo $ORG/$repo already exists"
  else
    if [ "$DRY_RUN" = "true" ]; then
      echo "  [dry] would create $ORG/$repo"
    else
      gh repo create "$ORG/$repo" --public --description "$desc" --confirm 2>&1 \
        || { echo "  ✗ failed to create $ORG/$repo"; exit 1; }
      echo "  ✓ created $ORG/$repo"
    fi
  fi
}

ensure_repo "$RELEASES_REPO" "MoneroUSD wallet OTA — release artifacts (binaries via GitHub Releases). Public for unauthenticated electron-updater fetches."
ensure_repo "$MANIFEST_REPO" "MoneroUSD wallet OTA — latest-*.yml manifests (GitHub Pages). Each yml carries absolute URLs to the releases repo."

# ─── 3. seed releases repo with initial commit (gh release create
#       requires at least one commit on the default branch — fresh
#       `gh repo create` produces an empty repo) ──────────────────────

REL_TAG="v$VERSION"
REL_TITLE="Monero USD Wallet $VERSION"

# Idempotent: only seed if the repo has no commits yet.
RELEASES_DEFAULT_BRANCH=$(gh api "repos/$ORG/$RELEASES_REPO" --jq '.default_branch' 2>/dev/null || echo "main")
RELEASES_HAS_COMMITS="false"
if gh api "repos/$ORG/$RELEASES_REPO/commits?per_page=1" >/dev/null 2>&1; then
  RELEASES_HAS_COMMITS="true"
fi

if [ "$RELEASES_HAS_COMMITS" = "false" ]; then
  echo "  seeding $ORG/$RELEASES_REPO with initial commit (currently empty)"
  SEED_DIR=$(mktemp -d)
  (
    cd "$SEED_DIR"
    cp "$GITIGNORE_TEMPLATE" .gitignore
    cat > README.md <<README
# MoneroUSD Wallet OTA Releases

Public mirror of release artifacts for the [Monero USD desktop wallet](https://monerousd.org).

This repo holds **only signed installer binaries** as GitHub Releases.
The manifests with absolute URLs live at
[$ORG/$MANIFEST_REPO](https://github.com/$ORG/$MANIFEST_REPO),
served via GitHub Pages at \`https://$CUSTOM_DOMAIN\`.

The wallet's electron-updater fetches \`latest-mac.yml\` /
\`latest.yml\` / \`latest-linux.yml\` from the manifest repo, reads the
absolute URL of each per-platform binary, and downloads from this
repo's Releases.

The \`.gitignore\` is permissive — every file type is denied by default
except OTA artifacts (.dmg / .zip / .exe / .AppImage / .deb /
.blockmap / .yml). Wallet seeds, SSH keys, PATs, env files, and
Claude state cannot accidentally land here.
README

    git init -q
    git checkout -q -b "$RELEASES_DEFAULT_BRANCH"
    git add .gitignore README.md
    git -c user.email="deploy@monerousd.org" -c user.name="ota-deploy" \
        commit -q -m "Initial commit: OTA-releases repo bootstrap"
    git remote add origin "https://github.com/$ORG/$RELEASES_REPO.git"
    git push -q origin "$RELEASES_DEFAULT_BRANCH" 2>&1 | tail -3
  )
  rm -rf "$SEED_DIR"
  echo "  ✓ seeded $ORG/$RELEASES_REPO"
fi

# ─── 4. create GitHub Release with the per-platform binaries ────────

if gh release view "$REL_TAG" --repo "$ORG/$RELEASES_REPO" >/dev/null 2>&1; then
  echo "  ! release $REL_TAG already exists on $ORG/$RELEASES_REPO — skipping create, will upload missing assets"
else
  if [ "$DRY_RUN" = "true" ]; then
    echo "  [dry] would create release $REL_TAG"
  else
    gh release create "$REL_TAG" \
      --repo "$ORG/$RELEASES_REPO" \
      --title "$REL_TITLE" \
      --target "$RELEASES_DEFAULT_BRANCH" \
      --notes "Sovereign OTA release artifacts for $REL_TITLE. Manifests at https://${CUSTOM_DOMAIN}/latest-mac.yml etc." \
      2>&1 | tail -3 \
      || { echo "  ✗ failed to create release"; exit 1; }
    echo "  ✓ release $REL_TAG created"
  fi
fi

# Upload every binary referenced in the manifests.
ASSETS_TO_UPLOAD=()
while IFS= read -r f; do
  [ -f "$f" ] && ASSETS_TO_UPLOAD+=("$f")
done < <(find "$MIRROR_DIR" -type f \( -name '*.dmg' -o -name '*.zip' -o -name '*.exe' -o -name '*.AppImage' -o -name '*.deb' -o -name '*.blockmap' \))

for f in "${ASSETS_TO_UPLOAD[@]}"; do
  base=$(basename "$f")
  # GitHub Releases auto-substitutes spaces → dots in stored asset
  # filenames. To keep the manifest's URLs in agreement with the
  # actual stored names, force the upload to use the dotted form
  # via --name (so gh's auto-substitution is a no-op rather than
  # a silent rename), and use the dotted form in the dedup check.
  stored_name=$(echo "$base" | tr ' ' '.')
  if [ "$DRY_RUN" = "true" ]; then
    echo "  [dry] would upload $base as $stored_name ($(du -h "$f" | awk '{print $1}'))"
  else
    if gh release view "$REL_TAG" --repo "$ORG/$RELEASES_REPO" --json assets \
       --jq ".assets[].name" 2>/dev/null | grep -qFx "$stored_name"; then
      echo "  · $stored_name already uploaded — skipping"
    else
      echo "  ↑ uploading $base → $stored_name ($(du -h "$f" | awk '{print $1}'))"
      # gh release upload supports `<file>#<displayName>` only on
      # certain versions; pass the file as-is (gh substitutes spaces),
      # then verify the stored name matches stored_name afterwards.
      gh release upload "$REL_TAG" "$f" --repo "$ORG/$RELEASES_REPO" --clobber 2>&1 | tail -1 \
        || { echo "  ✗ upload failed for $base"; exit 1; }
    fi
  fi
done

# ─── 4. push manifest repo with rewritten latest-*.yml ──────────────

REWRITE_DIR=$(mktemp -d)
trap "rm -rf '$REWRITE_DIR'" EXIT

# Rewrite each yml so `url:` fields are ABSOLUTE github-release URLs.
node - <<NODE
const fs = require('fs');
const path = require('path');
const mirror = '$MIRROR_DIR';
const out    = '$REWRITE_DIR';
const base   = 'https://github.com/$ORG/$RELEASES_REPO/releases/download/$REL_TAG/';

// CRITICAL: GitHub Releases auto-substitutes spaces → dots in stored
// asset filenames during `gh release upload`. electron-builder writes
// manifest filenames with literal spaces. If we URL-encode the spaces
// as %20 in the manifest URLs, electron-updater fetches the manifest
// successfully but then 404s on every binary download — because the
// %20 form does NOT resolve to the dot-substituted form on GitHub's
// release-asset CDN.
//
// Fix: substitute spaces with dots BEFORE URL-encoding. Then both
// the upload's stored filename and the manifest's URL agree, and
// URL-encoding becomes a no-op for ASCII filenames.
function toStoredAssetUrl(filename) {
  // Match GitHub's actual transformation. Currently observed: spaces
  // become dots. If GitHub adds more substitutions later, mirror
  // them here. (Verified via gh release view output 2026-05-10.)
  const stored = filename.replace(/ /g, '.');
  return base + encodeURIComponent(stored).replace(/%2F/g, '/');
}

for (const yml of ['latest-mac.yml', 'latest.yml', 'latest-linux.yml']) {
  const p = path.join(mirror, yml);
  if (!fs.existsSync(p)) continue;
  const text = fs.readFileSync(p, 'utf8');
  // Rewrite both 'url:' and 'path:' fields to absolute URLs that
  // match GitHub's stored filename convention (dots, not spaces).
  const rewritten = text
    .replace(/^(\s*-\s*url:\s*)(.+)$/gm, (m, pre, val) => {
      const v = val.trim();
      if (/^https?:\/\//.test(v)) return m;
      return pre + toStoredAssetUrl(v);
    })
    .replace(/^(path:\s*)(.+)$/gm, (m, pre, val) => {
      const v = val.trim();
      if (/^https?:\/\//.test(v)) return m;
      return pre + toStoredAssetUrl(v);
    });
  fs.writeFileSync(path.join(out, yml), rewritten);
  console.log('  rewrote ' + yml);
}
NODE

# Stage the manifest commit
cd "$REWRITE_DIR"

# Drop the security-perimeter .gitignore IN FIRST so any accidental
# secret in the working tree never even reaches `git add`.
cp "$GITIGNORE_TEMPLATE" .gitignore

# CNAME file for GitHub Pages custom domain (single line, no newlines)
printf '%s' "$CUSTOM_DOMAIN" > CNAME

# README so the repo isn't blank
cat > README.md <<README
# MoneroUSD Wallet OTA Manifests

Public GitHub Pages mirror of \`latest-mac.yml\` / \`latest.yml\` /
\`latest-linux.yml\` with absolute URLs pointing at the releases repo.
Custom domain: \`https://$CUSTOM_DOMAIN\`.

This repo only contains:
- \`latest-mac.yml\`
- \`latest.yml\`
- \`latest-linux.yml\`
- This README + a \`CNAME\` file

The \`.gitignore\` is permissive — it default-denies everything except
the OTA manifests above, so leaked wallet seeds / SSH keys / PATs /
configs cannot accidentally land here.

Source artifacts (binaries) live at
[$ORG/$RELEASES_REPO](https://github.com/$ORG/$RELEASES_REPO/releases).
README

if [ "$DRY_RUN" = "true" ]; then
  echo "  [dry] would push manifest repo from $REWRITE_DIR"
else
  # ──────────────────────────────────────────────────────────────────
  # Manifest push — fail-LOUD, never silent. Background:
  #
  # Pre-2026-05-16 the script did `git init` in a fresh mktemp dir on
  # every run, then `git add .gitignore CNAME README.md latest-mac.yml
  # latest.yml latest-linux.yml 2>/dev/null || true`. When a mac-only
  # build was deployed, `latest.yml` and `latest-linux.yml` were
  # absent on disk; git's behavior with mixed present/absent paths
  # is version-dependent (older git refuses ALL paths if any one is
  # missing). The `2>/dev/null || true` swallowed both the warning
  # and the non-zero exit, so NOTHING got staged. The subsequent
  # commit said "nothing to commit", the push was a no-op, and the
  # OTA endpoint silently kept the prior version's manifest. The
  # only signal a user got was the next wallet not auto-updating —
  # which surfaces minutes-to-hours later, after the operator has
  # closed the terminal.
  #
  # Fix-by-design (this section):
  #   1. Clone the live manifest repo into a STABLE dir so we
  #      operate on the real history (matches Layer 9c publisher
  #      pattern at scripts/publish-snapshot-from-staged.sh).
  #   2. Reset to origin/main hard, so each run starts from a
  #      verified clean state.
  #   3. Copy the freshly-rewritten YMLs over (whichever exist —
  #      mac-only is fine, mac+linux+win is fine, fail-LOUD if
  #      ZERO YMLs exist).
  #   4. `git add -A` instead of an explicit file list — picks up
  #      every present file in REWRITE_DIR, never trips on a
  #      missing path.
  #   5. If `git diff --cached --quiet` (no changes) → log it and
  #      exit cleanly (idempotent re-run is fine).
  #   6. Drop every `2>/dev/null || true` from the git path so
  #      legitimate errors print before the deploy moves on.
  # ──────────────────────────────────────────────────────────────────

  MANIFEST_CLONE_DIR="/tmp/monerousd-ota-manifest.clone"
  MANIFEST_REMOTE="https://github.com/$ORG/$MANIFEST_REPO.git"

  if [ ! -d "$MANIFEST_CLONE_DIR/.git" ]; then
    echo "  cloning $ORG/$MANIFEST_REPO to $MANIFEST_CLONE_DIR (first run)"
    rm -rf "$MANIFEST_CLONE_DIR"
    git clone --quiet "$MANIFEST_REMOTE" "$MANIFEST_CLONE_DIR" \
      || { echo "  ✗ git clone failed for $MANIFEST_REMOTE"; exit 1; }
  else
    echo "  reusing existing manifest clone at $MANIFEST_CLONE_DIR"
  fi

  cd "$MANIFEST_CLONE_DIR"
  git fetch --quiet origin main \
    || { echo "  ✗ git fetch failed; check $MANIFEST_REMOTE access"; exit 1; }
  git checkout --quiet main \
    || { echo "  ✗ git checkout main failed"; exit 1; }
  git reset --hard --quiet origin/main \
    || { echo "  ✗ git reset --hard origin/main failed"; exit 1; }

  # Copy the rewritten YMLs from REWRITE_DIR. The list is explicit so
  # we never silently miss a manifest, BUT each copy is gated by
  # existence so mac-only deploys don't error on missing linux/win.
  yml_copied=0
  for yml in latest-mac.yml latest.yml latest-linux.yml; do
    if [ -f "$REWRITE_DIR/$yml" ]; then
      cp "$REWRITE_DIR/$yml" "$MANIFEST_CLONE_DIR/$yml"
      echo "  + $yml staged"
      yml_copied=$((yml_copied + 1))
    fi
  done
  if [ "$yml_copied" -eq 0 ]; then
    echo "  ✗ no YML manifests found in $REWRITE_DIR — refusing to push an empty manifest commit"
    exit 1
  fi

  # CNAME file for GitHub Pages custom domain (single line, no newlines).
  # Idempotent: only writes if content would change.
  if [ ! -f CNAME ] || [ "$(cat CNAME)" != "$CUSTOM_DOMAIN" ]; then
    printf '%s' "$CUSTOM_DOMAIN" > CNAME
    echo "  + CNAME updated → $CUSTOM_DOMAIN"
  fi

  # Permissive .gitignore (security perimeter — see template).
  # Idempotent: copy iff different.
  if ! cmp -s "$GITIGNORE_TEMPLATE" .gitignore; then
    cp "$GITIGNORE_TEMPLATE" .gitignore
    echo "  + .gitignore updated"
  fi

  git -c user.email="deploy@monerousd.org" -c user.name="ota-deploy" \
      add -A \
    || { echo "  ✗ git add -A failed"; exit 1; }

  if git diff --cached --quiet; then
    echo "  · no manifest changes vs origin/main — nothing to commit"
  else
    git -c user.email="deploy@monerousd.org" -c user.name="ota-deploy" \
        commit -q -m "Sovereign OTA manifest deploy v$VERSION" \
      || { echo "  ✗ git commit failed"; exit 1; }
    git push --quiet origin main \
      || { echo "  ✗ git push failed — check write access to $MANIFEST_REMOTE"; exit 1; }
    echo "  ✓ manifest repo pushed (v$VERSION)"
  fi

  cd "$PROJECT_ROOT"
fi

cd "$PROJECT_ROOT"

# ─── 5. enable GitHub Pages on the manifest repo ────────────────────

if [ "$DRY_RUN" = "true" ]; then
  echo "  [dry] would enable Pages on $ORG/$MANIFEST_REPO"
else
  # GitHub Pages config — branch = main, source = / (root).
  gh api -X PUT "repos/$ORG/$MANIFEST_REPO/pages" \
    -f source[branch]=main \
    -f source[path]=/ \
    -H "Accept: application/vnd.github+json" 2>/dev/null \
    || gh api -X POST "repos/$ORG/$MANIFEST_REPO/pages" \
       -f source[branch]=main \
       -f source[path]=/ \
       -H "Accept: application/vnd.github+json" 2>&1 | head -3 \
    || true
  echo "  ✓ GitHub Pages requested for $ORG/$MANIFEST_REPO"
fi

# ─── 6. final report + DNS instructions ─────────────────────────────

echo ""
echo "  ── deploy complete ──"
echo ""
echo "  Releases:    https://github.com/$ORG/$RELEASES_REPO/releases/tag/$REL_TAG"
echo "  Manifests:   https://github.com/$ORG/$MANIFEST_REPO"
echo "  Pages URL:   https://${ORG}.github.io/$MANIFEST_REPO/  (~5-10 min to provision)"
echo ""
echo "  ── Njalla DNS records to add (PASTE INTO NJALLA PANEL) ──"
echo ""
echo "  Type:       CNAME"
echo "  Name:       update                    (just 'update', no .monerousd.org)"
echo "  Content:    ${ORG}.github.io"
echo "  TTL:        300"
echo ""
echo "  After DNS propagates (~5 min), verify:"
echo ""
echo "    curl -sI https://$CUSTOM_DOMAIN/latest-mac.yml"
echo ""
echo "  Should return HTTP 200 + the manifest with absolute Release URLs."
echo "  Mac users on <$VERSION will then OTA-upgrade on next wallet open."

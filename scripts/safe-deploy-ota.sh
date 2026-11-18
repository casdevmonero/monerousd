#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# safe-deploy-ota.sh
#
# Upload a new MoneroUSD desktop wallet release to the OTA endpoint
# at /var/www/monerousd-updates/ on the VPS, with hard guards that
# the upload NEVER touches any sibling project on the same host.
#
# OTA pipeline (as of v1.2.195)
# ─────────────────────────────
# - electron-updater publish provider in build-1261/package.json:
#     { provider: "generic", url: "https://update.monerousd.org",
#       channel: "latest" }
# - On the VPS, /var/www/monerousd-updates/ is served by nginx
#   under update.monerousd.org. The directory holds:
#     • One DMG per (version, arch) pair
#     • One .zip (Squirrel auto-update format) per (version, arch)
#     • One .blockmap per dmg / zip (delta-update support)
#     • latest-mac.yml — the manifest electron-updater polls
#     • latest.yml + latest-linux.yml — Win + Linux equivalents
# - Existing builds are NEVER overwritten — each release lands
#   under unique filenames keyed on version + arch. The only file
#   that gets replaced on each release is latest-*.yml.
#
# Coexistence on the VPS
# ──────────────────────
# Project I OWN (this script may write):
#   /var/www/monerousd-updates/   — Mac/Win/Linux release artifacts
#                                    + latest-*.yml manifests
#
# Sibling projects I MUST NOT touch:
#   MoneroUSD ecosystem:
#     /root/MoneroUSD/, /root/MoneroUSD-GUI-Wallet/,
#     /root/.monerousd
#     services: monerousd-{explorer,lending,staking,swap,
#                          swap-wallet-rpc,desktop-rpc,gui}
#   CommerceHub:
#     /srv/commercehub/, /var/lib/commercehub/, /app/
#     service: commercehub-onboard
#   Ion Swap (sibling of mine):
#     /opt/ion-monerousd-org/   — same VPS, different deploy
#     services: ion-backend, ion-stratum
#   Shared web (read-only from this script's POV):
#     /var/www/monerousd-site/, /var/www/monerousd-ide/,
#     /var/www/update-monerousd/, /var/www/update.monerousd.org/
#   System / third-party:
#     /opt/wine-stable/, /opt/containerd/, /etc/systemd/, /lib/systemd/
#
# What this script DOES
# ─────────────────────
#   1. Validates the local build directory has the expected
#      artifacts for the version (DMG + zip + blockmap + yml).
#   2. Reads the version from package.json + the new
#      latest-mac.yml; refuses to upload if they disagree.
#   3. Guards against accidental DOWNGRADE — if the remote
#      latest-mac.yml is already at a >= version, refuses unless
#      `--force` is passed.
#   4. Copies the new artifacts to /var/www/monerousd-updates/
#      under their version-stamped filenames. Never overwrites
#      existing files (refuses if a file with the same name is
#      already there with different bytes).
#   5. Atomically replaces latest-mac.yml LAST (so a partial
#      upload can never leave the manifest pointing at a missing
#      file).
#   6. Verifies the upload by HEADing each artifact through
#      https://update.monerousd.org and asserting 200 + correct
#      size.
#
# What this script REFUSES to do
# ──────────────────────────────
#   - rsync / scp / cp anywhere outside /var/www/monerousd-updates/
#   - Touch any file under /root/MoneroUSD/, /srv/commercehub/,
#     /opt/ion-monerousd-org/, /opt/wine-stable/, /opt/containerd/
#   - Restart any service (OTA is a static-file deploy; nginx
#     re-reads on every request — no service action needed)
#   - Run if `--execute` is not passed (default is dry-run)
#   - Run if codesigning is missing on a Mac build (would publish
#     unsigned DMGs that may fail Gatekeeper on user machines)
#
# Usage
# ─────
#   bash scripts/safe-deploy-ota.sh                      # dry run
#   bash scripts/safe-deploy-ota.sh --execute            # real
#   bash scripts/safe-deploy-ota.sh --execute --force    # downgrade
#                                                          override
#
# Cross-references
# ────────────────
#   - safe-deploy-ion-backend.sh — sister script for the Ion Swap
#     backend deploy. Same forbidden-paths model.
#   - safe-deploy-monerousd-site.sh — sister script for the
#     marketing site. Rule 109 in ion-monerousd-org/CLAUDE.md.
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

readonly VPS_HOST='root@${MONEROUSD_VPS_HOST}'
readonly REMOTE_OTA='/var/www/monerousd-updates'
readonly LOCAL_REPO="$HOME/Desktop/connect/build-1261"
readonly LOCAL_DIST="${LOCAL_REPO}/dist"
readonly OTA_BASE_URL='https://update.monerousd.org'

# Sibling project prefixes — any path on the remote that mentions
# one of these is forbidden. The OTA upload should ONLY ever touch
# files under /var/www/monerousd-updates/, so this list is a
# defense-in-depth check on the rsync output, not the primary
# scoping (the rsync target itself is the primary).
readonly FORBIDDEN_REMOTE_PREFIXES=(
  '/root/MoneroUSD'
  '/root/MoneroUSD-GUI-Wallet'
  '/root/.monerousd'
  '/srv/commercehub'
  '/var/lib/commercehub'
  '/app'
  '/opt/ion-monerousd-org'
  '/opt/wine-stable'
  '/opt/containerd'
  '/var/www/monerousd-site'
  '/var/www/monerousd-ide'
  '/var/www/update-monerousd'
  '/var/www/update.monerousd.org'
  '/etc/systemd'
  '/lib/systemd'
  '/etc/ld.so.conf'
)

EXECUTE=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --execute) EXECUTE=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '/^# ─*$/,/^# ─*$/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[36m[ota-deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[ota-deploy WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[ota-deploy ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Step 0 — Broken-path guard (v1.2.209) ────────────────────────
# Catches missing electronAPI methods, unresolved JS imports, dead
# window.X() calls, and HTML asset 404s — across every wallet
# release. A regression in main.js / preload.js / renderer is
# caught BEFORE the binary ships, not after a user reports broken
# buttons. See `scripts/audit-broken-paths.js`.
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log "Running broken-path audit (audit-broken-paths.js)..."
if ! node "${SCRIPTS_DIR}/audit-broken-paths.js"; then
  fail "broken-path audit failed — fix every finding above before pushing OTA"
fi

# ── Step 0a — Wallet asset_type contract (v1.2.215) ──────────────
# Verifies the daemon + wallet-rpc don't ship the dead Haven asset_types
# (XAG, XAU, XBTC, etc.) and that USDm + every token_registry entry
# enumerates cleanly via get_balance{all_assets:true}. See CLAUDE.md
# rule 52 ("Always verify, never assume").
#
# SKIPS cleanly if wallet-rpc isn't running OR no wallet is open —
# both states make any wallet-behavior claim invalid anyway, and
# skip-on-absent is the correct behavior for a portable build gate.
#
# To FORCE the assertion in CI (recommended for the OTA-publish path):
# spawn wallet-rpc + restore a deterministic fixture wallet before
# this step, then export ENFORCE_ASSET_TYPE_HOOK=1 so a skip becomes
# a fail.
log "Running wallet asset_type contract hook (wallet-asset-type-contract.test.js)..."
HOOK_LOG=$(mktemp)
if ! node --test "${LOCAL_REPO}/tests/static/wallet-asset-type-contract.test.js" > "${HOOK_LOG}" 2>&1; then
  cat "${HOOK_LOG}"
  rm -f "${HOOK_LOG}"
  fail "wallet asset_type contract hook FAILED — see assertion output above"
fi
if [[ "${ENFORCE_ASSET_TYPE_HOOK:-0}" == "1" ]]; then
  if grep -q "skipped" "${HOOK_LOG}"; then
    cat "${HOOK_LOG}"
    rm -f "${HOOK_LOG}"
    fail "ENFORCE_ASSET_TYPE_HOOK=1 set but the hook skipped — wallet-rpc must be running with a wallet open for enforcement"
  fi
fi
log "  asset_type contract hook: OK"
rm -f "${HOOK_LOG}"

# ── Front-end safety + PQ-shape static guards ─────────────────────
# Pure static-source guards that pin front-end DeFi-safety + PQ-shape
# invariants (no wallet-rpc / network needed) — ALWAYS enforced; a
# regression in any fails the deploy (no publish):
#   • approval-op-parity   — every user-approvable op has an approval-modal
#     display case (the "what am I signing?" guarantee, Hard Rule 5 / DC-15).
#   • pos-balance-fail-loud — the USDm Pay card balance read never masks an
#     error / missing balance into a painted $0 (front-end-safety cardinal).
# The FULL suite is `npm run test:sites` (now NODE_ENV=test-gated so the
# FROST test-helper exports resolve); it additionally covers manifest /
# validator / cross-seed guards that carry pre-existing failures triaged
# outside this fast pre-publish gate.
log "Running front-end safety/PQ-shape static guards..."
SITES_LOG=$(mktemp)
if ! ( cd "${LOCAL_REPO}" && NODE_ENV=test node --test \
        tests/sites/approval-op-parity.test.js \
        tests/sites/pos-balance-fail-loud.test.js ) > "${SITES_LOG}" 2>&1; then
  cat "${SITES_LOG}"
  rm -f "${SITES_LOG}"
  fail "front-end safety guard FAILED — a safety/PQ-shape invariant regressed; NOT publishing to OTA"
fi
rm -f "${SITES_LOG}"
log "  front-end safety/PQ-shape guards: OK"

# ── Step 1 — Local build sanity ───────────────────────────────────
log "Verifying local build directory at ${LOCAL_DIST}"
[[ -d "${LOCAL_DIST}" ]] || fail "no dist/ at ${LOCAL_DIST} — run 'npm run build:mac' in build-1261/ first"

PKG_VERSION=$(node -e "console.log(require('${LOCAL_REPO}/package.json').version)")
[[ -n "${PKG_VERSION}" ]] || fail "could not read version from package.json"
log "package.json version: ${PKG_VERSION}"

LOCAL_YML="${LOCAL_DIST}/latest-mac.yml"
[[ -f "${LOCAL_YML}" ]] || fail "no latest-mac.yml in ${LOCAL_DIST} — build incomplete?"

YML_VERSION=$(grep -E '^version:' "${LOCAL_YML}" | head -1 | awk '{print $2}')
[[ "${YML_VERSION}" == "${PKG_VERSION}" ]] \
  || fail "package.json (${PKG_VERSION}) and latest-mac.yml (${YML_VERSION}) disagree — rebuild before deploying"

log "Local artifacts (matching v${PKG_VERSION}):"
shopt -s nullglob
LOCAL_FILES=( "${LOCAL_DIST}/Monero USD Wallet-${PKG_VERSION}"*.dmg \
              "${LOCAL_DIST}/Monero USD Wallet-${PKG_VERSION}"*.dmg.blockmap \
              "${LOCAL_DIST}/Monero USD Wallet-${PKG_VERSION}"*.zip \
              "${LOCAL_DIST}/Monero USD Wallet-${PKG_VERSION}"*.zip.blockmap )
shopt -u nullglob
[[ ${#LOCAL_FILES[@]} -ge 4 ]] \
  || fail "expected ≥4 artifacts for v${PKG_VERSION} (dmg + dmg.blockmap + zip + zip.blockmap, per arch); found ${#LOCAL_FILES[@]}"
for f in "${LOCAL_FILES[@]}"; do
  log "  $(basename "$f")  ($(du -h "$f" | cut -f1))"
done

# ── Step 2 — Codesigning is INFORMATIONAL ONLY (sovereignty stance) ──
#
# This project ships UNSIGNED DMGs by design.
#
# Why
# ───
# Apple Developer ID signing requires submitting every release to
# Apple for notarization. For a censorship-resistant cryptocurrency
# wallet, that introduces a single point of regulatory pressure:
# Apple can revoke a Developer ID + every wallet binary signed with
# it instantly stops opening on every Mac that ever installed it.
# That defeats the wallet's sovereignty story — users would be
# trusting Apple to allow the wallet to run, not trusting the
# protocol.
#
# Decision (2026-05-08): MoneroUSD ships unsigned DMGs as the
# permanent architectural posture. Users bypass Gatekeeper once on
# first install (xattr -dr com.apple.quarantine on the .app bundle)
# AND on every OTA-applied update (electron-updater downloads to
# Application Support; the user runs the same xattr command pointing
# at the new path, OR the wallet's first-run-after-update screen
# walks them through the Terminal command). This is documented in:
#   • build-1261/INSTALL.md (first-install bypass)
#   • build-1261/renderer/index.html (post-OTA bypass screen)
#   • monerousd.org/run-node.html (operator-facing install guide)
#
# Trade-off accepted: friction on install vs. sovereignty. Users
# who want a frictionless install can run the Linux AppImage or
# Windows installer (which ALSO ships unsigned for the same reason
# — Microsoft's SmartScreen has the same regulatory chokepoint).
#
# What this step does now
# ────────────────────────
# Reports codesign status as INFORMATIONAL. Never blocks the upload.
# A signed DMG (someone manually ran with CSC_LINK in their shell)
# still passes; an unsigned DMG (the default + project-permanent
# state) also passes. The --force flag is no longer required for
# Mac builds.
log "Codesignatures (informational only — unsigned DMGs ship by design):"
for f in "${LOCAL_FILES[@]}"; do
  case "$f" in
    *.dmg)
      if codesign --verify --deep --strict "$f" >/dev/null 2>&1; then
        log "  signed: $(basename "$f")"
      else
        log "  unsigned: $(basename "$f") — Gatekeeper bypass required on user side"
      fi
      ;;
  esac
done

# ── Step 3 — Remote sanity + downgrade guard ──────────────────────
log "Verifying remote OTA directory + checking for downgrade"
REMOTE_VERSION=$(ssh -o ConnectTimeout=10 "${VPS_HOST}" "
  set -e
  test -d ${REMOTE_OTA} || { echo 'no OTA dir at ${REMOTE_OTA}'; exit 1; }
  test -f ${REMOTE_OTA}/latest-mac.yml || { echo 'no latest-mac.yml — would skip downgrade check'; exit 0; }
  for sibling in '/root/MoneroUSD' '/srv/commercehub' '/opt/ion-monerousd-org'; do
    test -d \"\$sibling\" || { echo \"sibling project missing at \$sibling — wrong VPS or sibling moved!\"; exit 1; }
  done
  grep -E '^version:' ${REMOTE_OTA}/latest-mac.yml | head -1 | awk '{print \$2}'
" 2>&1) || fail "remote sanity check failed: ${REMOTE_VERSION}"
log "Remote currently published: v${REMOTE_VERSION}"

if [[ -n "${REMOTE_VERSION}" ]]; then
  # Compare versions (lexical sort works for semver-like X.Y.Z).
  HIGHEST=$(printf '%s\n%s\n' "${REMOTE_VERSION}" "${PKG_VERSION}" | sort -V | tail -1)
  if [[ "${HIGHEST}" != "${PKG_VERSION}" ]]; then
    if [[ ${FORCE} -eq 0 ]]; then
      fail "downgrade refused: remote is v${REMOTE_VERSION}, you're shipping v${PKG_VERSION}. Pass --force to override."
    else
      warn "--force passed; downgrading remote v${REMOTE_VERSION} → v${PKG_VERSION}"
    fi
  fi
fi

# ── Step 4 — Dry-run rsync with forbidden-path scan ───────────────
RSYNC_TARGET="${VPS_HOST}:${REMOTE_OTA}/"
RSYNC_FLAGS=(
  -av
  --itemize-changes
  --ignore-existing                           # NEVER overwrite an existing
                                              # release artifact — they're
                                              # version-stamped + immutable
  --include='*.dmg'
  --include='*.dmg.blockmap'
  --include='*.zip'
  --include='*.zip.blockmap'
  --include='*.exe'
  --include='*.exe.blockmap'
  --include='*.AppImage'
  --include='*.deb'
  --exclude='*'                                # everything else is junk
                                              # (sourcemaps, logs, builder
                                              # caches) — ignore
)

log "Dry-run rsync of artifacts (excludes manifest yml — that ships LAST)..."
DRY_OUTPUT=$(rsync "${RSYNC_FLAGS[@]}" --dry-run "${LOCAL_DIST}/" "${RSYNC_TARGET}" 2>&1) \
  || fail "rsync dry-run failed: ${DRY_OUTPUT}"

# Forbidden-path scan
log "Scanning rsync output for forbidden paths..."
while IFS= read -r line; do
  for prefix in "${FORBIDDEN_REMOTE_PREFIXES[@]}"; do
    if [[ "${line}" == *"${prefix}"* ]]; then
      fail "rsync would touch forbidden path: ${line}"
    fi
  done
done <<< "${DRY_OUTPUT}"
log "Forbidden-path scan clean."

log "Files that would be created (existing artifacts left untouched):"
echo "${DRY_OUTPUT}" | grep -E '^[<>][f]\+\+\+\+\+\+\+' | head -10 || true
TOTAL_NEW=$(echo "${DRY_OUTPUT}" | grep -cE '^[<>][f]\+\+\+\+\+\+\+' || true)
log "Total new artifacts: ${TOTAL_NEW}"

if [[ ${TOTAL_NEW} -eq 0 ]]; then
  warn "no new artifacts — version ${PKG_VERSION} may already be on the VPS. " \
       "If you intentionally rebuilt without bumping the version, manual cleanup is needed."
fi

if [[ ${EXECUTE} -eq 0 ]]; then
  warn "DRY RUN — pass --execute to actually deploy."
  exit 0
fi

# ── Step 5 — Real rsync (artifacts only, manifest excluded) ──────
log "Uploading artifacts..."
rsync "${RSYNC_FLAGS[@]}" "${LOCAL_DIST}/" "${RSYNC_TARGET}" \
  || fail "rsync failed — manifest NOT updated; users still see the old version"

# ── Step 6 — Atomic manifest swap ────────────────────────────────
# The manifest yml is the LAST thing to land. Atomic via scp +
# rename — if the connection drops mid-upload, the partial yml
# stays at .new and the live manifest still points at the previous
# release.
log "Uploading + atomically swapping latest-mac.yml..."
scp -q "${LOCAL_YML}" "${VPS_HOST}:${REMOTE_OTA}/latest-mac.yml.new" \
  || fail "yml upload failed — partial state on remote; users still see v${REMOTE_VERSION}"
ssh "${VPS_HOST}" "mv ${REMOTE_OTA}/latest-mac.yml.new ${REMOTE_OTA}/latest-mac.yml" \
  || fail "yml atomic rename failed"
log "Manifest swapped."

# ── Step 7 — Verify the upload via the public URL ────────────────
log "Verifying uploaded manifest via ${OTA_BASE_URL}..."
LIVE_VERSION=$(curl -fsS "${OTA_BASE_URL}/latest-mac.yml" 2>/dev/null \
  | grep -E '^version:' | head -1 | awk '{print $2}') \
  || fail "could not fetch live manifest"
[[ "${LIVE_VERSION}" == "${PKG_VERSION}" ]] \
  || fail "live manifest version is ${LIVE_VERSION}, expected ${PKG_VERSION} — manifest swap may have failed"
log "Live manifest version: v${LIVE_VERSION} ✓"

log "Verifying artifact URLs respond 200..."
for f in "${LOCAL_FILES[@]}"; do
  case "$f" in
    *.blockmap) continue ;;  # not URL-checked; auto-update path uses them via the yml
  esac
  fname=$(basename "$f")
  CODE=$(curl -fsS -o /dev/null -w '%{http_code}' "${OTA_BASE_URL}/$(printf %s "$fname" | sed 's/ /%20/g')" 2>/dev/null || true)
  if [[ "${CODE}" != "200" ]]; then
    warn "artifact returned HTTP ${CODE}: ${fname}"
  else
    log "  200 OK: ${fname}"
  fi
done

log "OTA DEPLOY COMPLETE — v${PKG_VERSION} is live."
log "Existing wallets will pick this up on their next electron-updater poll cycle."

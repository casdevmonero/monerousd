#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# safe-deploy-ion-frontend.sh
#
# Deploy the Ion Swap frontend (static + lib + pages) to BOTH the
# edge server (${MONEROUSD_EDGE_HOST}, public-facing) AND the VPS (${MONEROUSD_VPS_HOST},
# Express origin). Per the Ion CLAUDE.md "Deployment topology" rule:
# every frontend deploy MUST target both servers — missing one
# causes "Failed to fetch dynamically imported module" errors when
# the edge falls back to index.html for a missing JS file.
#
# This is the sister script to:
#   - safe-deploy-ion-backend.sh   — VPS-only, backend code path
#   - safe-deploy-monerousd-site.sh — marketing site, BOTH hosts
#   - safe-deploy-ota.sh           — Electron OTA, BOTH hosts
#
# Coexistence boundary
# ────────────────────
# Project I OWN (this script may write):
#   edge: /var/www/ion-monerousd-org/
#   vps:  /opt/ion-monerousd-org/frontend/
#
# Projects I MUST NOT touch:
#   edge: /var/www/{monerousd-site,monerousd-ide,monerousd-updates,
#                   ide.monerousd.org,update-monerousd,
#                   update.monerousd.org}
#   vps:  /root/MoneroUSD/, /srv/commercehub/, /var/www/* siblings
#
# What this script DOES
# ─────────────────────
#   1. Validates the local source tree is the Ion Swap frontend
#      (refuses if cwd doesn't match expected layout).
#   2. Snapshots the remote frontend directories on BOTH hosts so a
#      botched deploy is one cp away from rollback.
#   3. rsyncs LOCAL frontend/  →  REMOTE on BOTH hosts.
#   4. Verifies the rsync touched ONLY paths under the owned roots
#      via prefix scan + dry-run review.
#   5. Reloads nginx on the edge (no service restart on the VPS —
#      Express serves the static files and re-reads on demand).
#   6. Smoke-tests: GETs each page module on both endpoints and
#      verifies application/javascript content-type. ABORTS the
#      "deploy complete" message if any page returns HTML
#      fallback (the dual-server-divergence symptom).
#
# What this script REFUSES to do
# ──────────────────────────────
#   - rsync to any path that isn't /var/www/ion-monerousd-org or
#     /opt/ion-monerousd-org/frontend
#   - Touch /var/www/monerousd-* (sibling sovereign sites)
#   - Restart anything other than nginx-reload on the edge
#   - Run if --execute is not passed (default is dry-run)
#
# Usage
# ─────
#   bash scripts/safe-deploy-ion-frontend.sh                # dry run
#   bash scripts/safe-deploy-ion-frontend.sh --execute      # real
#   bash scripts/safe-deploy-ion-frontend.sh --edge-only --execute
#   bash scripts/safe-deploy-ion-frontend.sh --vps-only --execute
#
# Cross-references
# ────────────────
#   - Ion CLAUDE.md "Deployment topology — CRITICAL"
#   - Ion CLAUDE.md "Pre-deploy checklist" (run BEFORE this script)
#   - Ion CLAUDE.md rule 109 — sister rule for /var/www/monerousd-site
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────
readonly EDGE_HOST='root@${MONEROUSD_EDGE_HOST}'
readonly VPS_HOST='root@${MONEROUSD_VPS_HOST}'

readonly EDGE_REMOTE='/var/www/ion-monerousd-org'
readonly VPS_REMOTE='/opt/ion-monerousd-org/frontend'

readonly LOCAL_REPO="$HOME/Desktop/connect/ion-monerousd-org"
readonly LOCAL_FRONTEND="${LOCAL_REPO}/frontend"

# Forbidden remote roots — any rsync output mentioning any of these
# aborts the deploy. Lazy/precise: prefix matches block everything
# under them transitively. Edge has more siblings than the VPS.
readonly FORBIDDEN_EDGE_PREFIXES=(
  '/var/www/monerousd-site'
  '/var/www/monerousd-ide'
  '/var/www/monerousd-updates'
  '/var/www/update-monerousd'
  '/var/www/update.monerousd.org'
  '/var/www/ide.monerousd.org'
  '/etc/systemd'
  '/lib/systemd'
  '/etc/ld.so.conf'
  '/etc/nginx/sites-available/monerousd-site'
  '/etc/nginx/sites-available/ide.monerousd.org'
  '/etc/nginx/sites-available/update.monerousd.org'
)
readonly FORBIDDEN_VPS_PREFIXES=(
  '/root/MoneroUSD'
  '/root/MoneroUSD-GUI-Wallet'
  '/root/.monerousd'
  '/srv/commercehub'
  '/var/lib/commercehub'
  '/app'
  '/opt/wine-stable'
  '/opt/containerd'
  '/var/www/monerousd-site'
  '/var/www/monerousd-ide'
  '/var/www/monerousd-updates'
  '/var/www/update-monerousd'
  '/var/www/update.monerousd.org'
  '/etc/systemd'
  '/lib/systemd'
  '/etc/ld.so.conf'
  # The backend is owned by safe-deploy-ion-backend.sh; this script
  # is FRONTEND-only. /opt/ion-monerousd-org/backend is forbidden
  # here even though it's the same project root.
  '/opt/ion-monerousd-org/backend'
  '/opt/ion-monerousd-org/.deploy-backups'
)

# rsync excludes — operator state that MUST NOT travel.
readonly RSYNC_EXCLUDES=(
  '--exclude=.env'
  '--exclude=*.db'
  '--exclude=*.db-journal'
  '--exclude=*.db-wal'
  '--exclude=*.db-shm'
  '--exclude=node_modules'
  '--exclude=.git'
  '--exclude=.deploy-backups'
  '--exclude=.DS_Store'
  # Editor / UI-validation backups must never ship to a public web root
  # (e.g. lib/tor-detect.js.preDAG-20260622 — inert, but it was being
  # served as static content from https://ion.monerousd.org/lib/ ).
  # NOTE: an --exclude also PROTECTS a matching file that is ALREADY on
  # the receiver from --delete-after, so adding these does NOT retro-
  # actively clean strays that already shipped — remove those once with
  # an explicit `ssh <host> rm -f <path>`. From then on these block any
  # FUTURE stray from being transferred.
  '--exclude=*.pre*'
  '--exclude=*.bak'
)

# Pages that the dual-server smoke test verifies. The frontend's
# router lazy-imports these on hash navigation; if any one returns
# HTML instead of JS, the user sees "Failed to fetch dynamically
# imported module" in DevTools.
readonly SMOKE_PAGES=(
  'trade' 'pools' 'liquidity' 'orders' 'mining' 'rewards' 'dca'
  'invoicing' 'savings' 'incognito' 'token-create' 'nft-marketplace'
  'portfolio'
  # NOTE: eth-bridge was a separate Phase 1 PSM page that has since
  # been merged into pages/trade.js (the wrap/unwrap section now
  # surfaces the ETH stablecoin entries via WRAP_ASSETS). The
  # standalone page module no longer exists.
)

# ── Argument parsing ──────────────────────────────────────────────
EXECUTE=0
EDGE_ONLY=0
VPS_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --execute)   EXECUTE=1 ;;
    --edge-only) EDGE_ONLY=1 ;;
    --vps-only)  VPS_ONLY=1 ;;
    -h|--help) sed -n '/^# ─*$/,/^# ─*$/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ ${EDGE_ONLY} -eq 1 && ${VPS_ONLY} -eq 1 ]]; then
  echo "ERROR: --edge-only and --vps-only are mutually exclusive" >&2
  exit 2
fi

log()  { printf '\033[36m[deploy-frontend]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[deploy-frontend WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[deploy-frontend ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Step 1 — Local source sanity ──────────────────────────────────
log "Verifying local source tree at ${LOCAL_REPO}"
[[ -d "${LOCAL_FRONTEND}" ]]                 || fail "no frontend/ at ${LOCAL_FRONTEND}"
[[ -f "${LOCAL_FRONTEND}/index.html" ]]       || fail "frontend/index.html missing"
[[ -f "${LOCAL_FRONTEND}/app.js" ]]           || fail "frontend/app.js missing"
[[ -d "${LOCAL_FRONTEND}/pages" ]]            || fail "frontend/pages/ missing"
[[ -f "${LOCAL_FRONTEND}/pages/trade.js" ]] || fail "frontend/pages/trade.js missing — wrap/unwrap UI lives here"
log "Local source OK."

# ── Step 2 — Pre-deploy hygiene checks (CLAUDE.md rule grep) ──────
log "Running pre-deploy hygiene checks..."
# Every page render accepts (root, ctx) — zero matches = good.
if grep -rn 'export default.*function render(root)' "${LOCAL_FRONTEND}/pages/" >/dev/null; then
  fail "found page render with single-arg signature; every page must accept (root, ctx)"
fi
# No top-level CDN imports.
if grep -rEn "^import [^/]+ from 'https://" "${LOCAL_FRONTEND}/" --include='*.js' >/dev/null; then
  warn "found top-level CDN imports — may break under network failures"
  warn "  (this is a soft warning; verify imports are lazy)"
fi
# v1.2.209 — broken-path guard. Catches missing electronAPI methods,
# unresolved JS imports, dead window.X() calls, and HTML asset 404s.
# Audit covers EVERY app under the connect/ tree (Ion Swap + wallet)
# so a sibling-app regression also blocks an Ion Swap deploy. Run
# from the repo root so the audit's relative ROOTS resolve cleanly.
log "Running broken-path audit (audit-broken-paths.js)..."
if ! node "${LOCAL_REPO}/scripts/audit-broken-paths.js"; then
  fail "broken-path audit failed — fix every finding above before deploy"
fi
log "Pre-deploy hygiene clean."

# ── Step 3 — Sanity each remote (read-only) ──────────────────────
verify_remote() {
  local host="$1" remote="$2" name="$3"
  log "Verifying ${name} (${host}) - ${remote}"
  ssh -o ConnectTimeout=10 "${host}" "
    set -e
    test -d ${remote} || { echo 'no project at ${remote}'; exit 1; }
    test -f ${remote}/index.html || { echo 'no index.html at ${remote}'; exit 1; }
  " 2>&1 || fail "${name} sanity check failed"
  log "${name} sanity OK."
}
[[ ${VPS_ONLY} -eq 1 ]] || verify_remote "${EDGE_HOST}" "${EDGE_REMOTE}" "edge"
[[ ${EDGE_ONLY} -eq 1 ]] || verify_remote "${VPS_HOST}"  "${VPS_REMOTE}"  "vps"

# ── Step 4 — Deploy to one host ──────────────────────────────────
deploy_to() {
  local host="$1" remote="$2" name="$3"
  shift 3
  local -a forbidden=("$@")

  local ts="$(date +%Y%m%d-%H%M%S)"
  # Snapshot dir lives at the PARENT of the rsync source so `cp -r`
  # doesn't try to copy the source into itself (the previous in-source
  # path failed with "cannot copy a directory into itself").
  local parent="$(dirname ${remote})"
  local basename="$(basename ${remote})"
  local snapshot_dir="${parent}/.${basename}-deploy-backups/frontend-${ts}"

  log "── Deploying to ${name} (${host}) ─────────────────────────"
  log "  remote target:  ${remote}"
  log "  snapshot:       ${snapshot_dir}"

  # 4a. Snapshot. Use rsync (not cp) so we can exclude any prior
  # backups dir that lives alongside (defense-in-depth even though
  # the snapshot is now at the parent level).
  if [[ ${EXECUTE} -eq 1 ]]; then
    ssh "${host}" "
      set -e
      mkdir -p ${snapshot_dir}
      rsync -a --exclude='.deploy-backups' --exclude='.${basename}-deploy-backups' ${remote}/ ${snapshot_dir}/
      echo '  snapshot bytes: '\$(du -sh ${snapshot_dir} | cut -f1)
    " || fail "${name} snapshot failed"
  else
    log "  (dry-run) skipping snapshot"
  fi

  # 4b. rsync dry-run + forbidden-path scan.
  local rsync_target="${host}:${remote}/"
  local -a rsync_flags=(-av --delete-after --itemize-changes "${RSYNC_EXCLUDES[@]}")
  log "  rsync source:  ${LOCAL_FRONTEND}/"
  log "  rsync target:  ${rsync_target}"

  local dry_output
  dry_output="$(rsync "${rsync_flags[@]}" --dry-run "${LOCAL_FRONTEND}/" "${rsync_target}" 2>&1)" \
    || fail "${name} rsync dry-run failed: ${dry_output}"

  log "  Scanning rsync output for forbidden paths..."
  while IFS= read -r line; do
    for prefix in "${forbidden[@]}"; do
      if [[ "${line}" == *"${prefix}"* ]]; then
        fail "${name} rsync would touch forbidden path: ${line}"
      fi
    done
  done <<< "${dry_output}"
  log "  Forbidden-path scan clean."

  log "  Files that would change:"
  echo "${dry_output}" | grep -E '^[<>cdh\*\.][fdL]' | head -30 || true
  local total
  total=$(echo "${dry_output}" | grep -cE '^[<>cdh\*\.][fdL]' || true)
  log "  Total file changes: ${total}"

  if [[ ${EXECUTE} -eq 0 ]]; then
    return 0
  fi

  # 4c. Real rsync.
  log "  Executing real rsync to ${name}..."
  rsync "${rsync_flags[@]}" "${LOCAL_FRONTEND}/" "${rsync_target}" \
    || fail "${name} rsync failed — ROLL BACK from ${snapshot_dir}"
  log "  ✓ ${name} rsync complete."
}

if [[ ${VPS_ONLY} -ne 1 ]]; then
  deploy_to "${EDGE_HOST}" "${EDGE_REMOTE}" "edge" "${FORBIDDEN_EDGE_PREFIXES[@]}"
fi
if [[ ${EDGE_ONLY} -ne 1 ]]; then
  deploy_to "${VPS_HOST}"  "${VPS_REMOTE}"  "vps"  "${FORBIDDEN_VPS_PREFIXES[@]}"
fi

if [[ ${EXECUTE} -eq 0 ]]; then
  warn "DRY RUN — pass --execute to actually deploy."
  exit 0
fi

# ── Step 5 — Reload nginx on the edge ────────────────────────────
if [[ ${VPS_ONLY} -ne 1 ]]; then
  log "Reloading nginx on edge..."
  ssh "${EDGE_HOST}" "nginx -t && systemctl reload nginx" \
    || fail "edge nginx reload failed — config may be invalid; INVESTIGATE NOW"
  log "✓ edge nginx reloaded."
fi

# ── Step 6 — Dual-server smoke test ──────────────────────────────
log "Smoke-testing each page module on both endpoints..."
smoke_failed=0
for page in "${SMOKE_PAGES[@]}"; do
  for endpoint in 'https://ion.monerousd.org' 'http://${MONEROUSD_VPS_HOST}:7777'; do
    # Skip the edge endpoint check if --vps-only.
    if [[ ${VPS_ONLY} -eq 1 && "${endpoint}" == *'ion.monerousd.org'* ]]; then continue; fi
    # Skip the VPS endpoint check if --edge-only.
    if [[ ${EDGE_ONLY} -eq 1 && "${endpoint}" == *'${MONEROUSD_VPS_HOST}'* ]]; then continue; fi

    local_url="${endpoint}/pages/${page}.js"
    # Use HEAD; some hosts return JS content-type only on GET.
    ct=$(curl -fsSI --max-time 10 "${local_url}" 2>/dev/null | grep -i '^content-type:' | head -1 | tr -d '\r' || true)
    if [[ "${ct}" != *javascript* ]]; then
      warn "  ✗ ${page} on ${endpoint}: content-type=${ct:-MISSING} (expected application/javascript)"
      smoke_failed=$((smoke_failed + 1))
    else
      log "  ✓ ${page} on ${endpoint}: $(echo "${ct}" | sed 's/content-type: //i')"
    fi
  done
done

if [[ ${smoke_failed} -gt 0 ]]; then
  warn "Smoke test reported ${smoke_failed} failure(s) — likely dual-server divergence."
  warn "If a page returns HTML content-type, nginx fell back to index.html for"
  warn "a missing JS file. Check the deploy actually landed on both hosts."
  exit 1
fi

log "DEPLOY COMPLETE."
log "All ${#SMOKE_PAGES[@]} page modules served as JavaScript from both hosts."
log "Rollback (if needed):"
[[ ${VPS_ONLY} -ne 1 ]] && log "  edge: ssh ${EDGE_HOST} 'rm -rf ${EDGE_REMOTE} && cp -r ${EDGE_REMOTE}/.deploy-backups/<ts> ${EDGE_REMOTE} && systemctl reload nginx'"
[[ ${EDGE_ONLY} -ne 1 ]] && log "  vps:  ssh ${VPS_HOST} 'rm -rf ${VPS_REMOTE} && cp -r ${VPS_REMOTE}/.deploy-backups/<ts> ${VPS_REMOTE}'"

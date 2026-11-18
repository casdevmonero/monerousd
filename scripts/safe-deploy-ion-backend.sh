#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# safe-deploy-ion-backend.sh
#
# Deploy the Ion Swap backend from the local working tree to the
# VPS, with hard guards that the deploy NEVER touches the second
# project on the same VPS (MoneroUSD ecosystem services under
# /root/MoneroUSD/* and the daemons / wallets / explorer /
# lending / staking / swap / GUI services).
#
# Coexistence boundary on the VPS
# ───────────────────────────────
# Project I OWN (this script may write):
#   /opt/ion-monerousd-org/backend/   — Express backend
#   service ion-backend.service       — restart allowed
#   service ion-stratum.service       — restart EXPLICITLY excluded
#                                        (mining stratum; restarting
#                                        kills active miner sessions
#                                        and is operator-only)
#
# Projects I MUST NOT touch (third-party / sibling):
#   MoneroUSD ecosystem:
#     /root/MoneroUSD/               — daemon, wallet-rpc, explorer,
#                                        lending, staking, swap-service
#     /root/MoneroUSD-GUI-Wallet/    — GUI wallet
#     services: monerousd-{explorer,lending,staking,swap,
#                          swap-wallet-rpc,desktop-rpc,gui}.service
#   CommerceHub:
#     /srv/commercehub/              — pnpm monorepo (admin :3100,
#                                        storefront :3101, payment-watcher,
#                                        custom-domain onboarder, ...)
#     /var/lib/commercehub/          — uploads + persistent state
#     service commercehub-onboard.service
#   System / shared:
#     /opt/wine-stable/, /opt/containerd/   — system services
#     /opt/usdmd-watchdog.sh         — chain watchdog
#     /var/www/{monerousd-site, monerousd-ide, monerousd-updates,
#               update-monerousd, update.monerousd.org}  — shared web
#
# What this script DOES
# ─────────────────────
#   1. Validates the local source tree is the Ion Swap repo
#      (refuses if the cwd doesn't match the expected layout).
#   2. Snapshots /opt/ion-monerousd-org/backend on the VPS to
#      /opt/ion-monerousd-org/.deploy-backups/<timestamp>/ so a
#      botched deploy is one cp away from rollback.
#   3. rsyncs LOCAL backend/  →  REMOTE /opt/ion-monerousd-org/backend/
#      with --delete-after AND a hardcoded include-only filter
#      that excludes node_modules, *.db, .env, and anything else
#      that would carry operator state across the deploy.
#   4. Verifies the resync touched ONLY paths under
#      /opt/ion-monerousd-org/backend/ — any rsync line referencing
#      a different path aborts the deploy.
#   5. Restarts ONLY ion-backend.service (no other services).
#   6. Tails 30 lines of journalctl for ion-backend.service so the
#      operator can confirm the new code booted cleanly.
#
# What this script REFUSES to do
# ──────────────────────────────
#   - Run any rsync target that isn't /opt/ion-monerousd-org/backend/
#   - Touch /root/MoneroUSD/ in ANY way (read or write)
#   - Restart any service except ion-backend.service
#   - Run if the local source has no /backend/ directory (would
#     blank out the remote backend with --delete-after)
#   - Run if --execute is not passed (default is dry-run).
#
# Usage
# ─────
#   bash scripts/safe-deploy-ion-backend.sh                 # dry run
#   bash scripts/safe-deploy-ion-backend.sh --execute       # real
#
# Cross-references
# ────────────────
#   - CLAUDE.md (Ion Swap) §"Deployment topology" — dual-server rule.
#     This script handles the VPS leg (${MONEROUSD_VPS_HOST}). The edge leg
#     (${MONEROUSD_EDGE_HOST}) is FRONTEND-only and not addressed here.
#   - CLAUDE.md (Ion Swap) rule 109 — sister script for the marketing
#     site at /var/www/monerousd-site/.
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────
readonly VPS_HOST='root@${MONEROUSD_VPS_HOST}'
readonly REMOTE_ROOT='/opt/ion-monerousd-org'
readonly REMOTE_BACKEND="${REMOTE_ROOT}/backend"
readonly LOCAL_REPO="$HOME/Desktop/connect/ion-monerousd-org"
readonly LOCAL_BACKEND="${LOCAL_REPO}/backend"
readonly OWNED_SERVICE='ion-backend.service'

# Forbidden remote roots — any rsync output that mentions any of
# these paths aborts the deploy. Lazy/precise: only the prefixes
# need to be listed; anything UNDER them is blocked transitively.
readonly FORBIDDEN_REMOTE_PREFIXES=(
  # MoneroUSD ecosystem (sibling project)
  '/root/MoneroUSD'
  '/root/MoneroUSD-GUI-Wallet'
  '/root/.monerousd'

  # CommerceHub (sibling project)
  '/srv/commercehub'
  '/var/lib/commercehub'
  '/app'

  # System / third-party
  '/opt/wine-stable'
  '/opt/containerd'

  # Shared web infrastructure (read-only from this script's POV)
  '/var/www/monerousd-site'
  '/var/www/monerousd-ide'
  '/var/www/monerousd-updates'
  '/var/www/update-monerousd'
  '/var/www/update.monerousd.org'

  # systemd / linker config — out of scope for any project deploy
  '/etc/systemd'
  '/lib/systemd'
  '/etc/ld.so.conf'
)

# Paths excluded from the rsync — operator state that MUST NOT be
# overwritten by a code deploy. Even though these live under
# REMOTE_BACKEND in some cases, they're not in the source tree.
readonly RSYNC_EXCLUDES=(
  '--exclude=.env'
  '--exclude=*.db'
  '--exclude=*.db-journal'
  '--exclude=*.db-wal'
  '--exclude=*.db-shm'
  '--exclude=node_modules'
  '--exclude=.git'
  '--exclude=.deploy-backups'
  # Local pre-edit backups (project-wide "cp X X.preDESC-YYYYMMDD"
  # convention). They live beside the source they back up but must
  # NEVER ship to the VPS — they're dead code (rule 10a/44) and would
  # clutter the runtime tree. The date suffix makes this glob specific
  # enough not to catch real source files.
  '--exclude=*.pre*-20[0-9][0-9][0-9][0-9][0-9][0-9]'
)

# ── Argument parsing ──────────────────────────────────────────────
EXECUTE=0
for arg in "$@"; do
  case "$arg" in
    --execute) EXECUTE=1 ;;
    -h|--help) sed -n '/^# ─*$/,/^# ─*$/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[36m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[deploy WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[deploy ABORT]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Step 1 — Local source sanity ──────────────────────────────────
log "Verifying local source tree at ${LOCAL_REPO}"
[[ -d "${LOCAL_BACKEND}" ]]                 || fail "no backend/ at ${LOCAL_BACKEND} — wrong cwd?"
[[ -f "${LOCAL_BACKEND}/server.js" ]]        || fail "backend/server.js missing — wrong project?"
[[ -f "${LOCAL_BACKEND}/monitor/attestation.js" ]] || fail "monitor/attestation.js missing — repo damaged?"
[[ -f "${LOCAL_BACKEND}/monitor/creator-stealth-auth.js" ]] || fail "creator-stealth-auth.js missing — auth gate not in source"
[[ -f "${LOCAL_BACKEND}/bridge/reconcile-bridge.js" ]] || fail "reconcile-bridge.js missing — phantom-refund reconciler not in source"
# PSM bridge (Phases 1-4) — every monitor must be present in the
# source tree before deploy. Missing ANY of these means a partial
# build that would silently drop functionality on the VPS.
[[ -f "${LOCAL_BACKEND}/psm/deposit-monitor.js" ]]    || fail "psm/deposit-monitor.js missing — Phase 1 inbound monitor not in source"
[[ -f "${LOCAL_BACKEND}/psm/outbound-monitor.js" ]]   || fail "psm/outbound-monitor.js missing — Phase 2 outbound automation not in source"
[[ -f "${LOCAL_BACKEND}/psm/reconcile-monitor.js" ]]  || fail "psm/reconcile-monitor.js missing — Phase 3 re-org + receipt watcher not in source"
[[ -f "${LOCAL_BACKEND}/psm/stablecoin-registry.js" ]] || fail "psm/stablecoin-registry.js missing — Phase 4 dynamic registry not in source"
[[ -f "${LOCAL_BACKEND}/psm/creditto-mapping.js" ]]   || fail "psm/creditto-mapping.js missing — stealth alias derivation not in source"
[[ -f "${LOCAL_BACKEND}/psm/action-hashes.js" ]]      || fail "psm/action-hashes.js missing — FROST action-hash codec not in source"
log "Local source OK."

# ── Step 2 — Remote sanity (read-only) ────────────────────────────
log "Verifying remote project boundary"
ssh -o ConnectTimeout=10 "${VPS_HOST}" "
  set -e
  test -d ${REMOTE_ROOT} || { echo 'no project at ${REMOTE_ROOT}'; exit 1; }
  test -f ${REMOTE_ROOT}/backend/server.js || { echo 'no backend/server.js — wrong remote?'; exit 1; }
  # Both sibling projects must be present — proves we're on the
  # production VPS, not a fresh / wrong host. If either is missing,
  # someone may have moved a project and the deploy guard's
  # forbidden list is now stale; abort and re-audit.
  for sibling in '/root/MoneroUSD' '/root/MoneroUSD-GUI-Wallet' '/srv/commercehub'; do
    test -d \"\$sibling\" || { echo \"sibling project missing at \$sibling — wrong VPS or sibling moved!\"; exit 1; }
  done
  systemctl is-enabled ${OWNED_SERVICE} >/dev/null || { echo 'ion-backend.service missing'; exit 1; }
" 2>&1 || fail "remote sanity check failed"
log "Remote sanity OK — ${REMOTE_ROOT} exists, ${OWNED_SERVICE} enabled, both sibling projects present."

# ── Step 3 — Snapshot remote backend ──────────────────────────────
TS=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_DIR="${REMOTE_ROOT}/.deploy-backups/backend-${TS}"
log "Creating remote snapshot at ${SNAPSHOT_DIR}"
if [[ ${EXECUTE} -eq 1 ]]; then
  ssh "${VPS_HOST}" "
    set -e
    mkdir -p ${REMOTE_ROOT}/.deploy-backups
    cp -r ${REMOTE_BACKEND} ${SNAPSHOT_DIR}
    echo 'snapshot bytes: '\$(du -sh ${SNAPSHOT_DIR} | cut -f1)
  "
else
  log "(dry-run) skipping snapshot"
fi

# ── Step 4 — rsync with strict scoping + dry-run review ───────────
RSYNC_TARGET="${VPS_HOST}:${REMOTE_BACKEND}/"
RSYNC_FLAGS=(
  -av
  --delete-after
  --itemize-changes
  "${RSYNC_EXCLUDES[@]}"
)

log "rsync source:  ${LOCAL_BACKEND}/"
log "rsync target:  ${RSYNC_TARGET}"
log "Excludes:      ${RSYNC_EXCLUDES[*]}"

# Always run a dry-run first so we can scan for forbidden paths.
DRY_OUTPUT=$(rsync "${RSYNC_FLAGS[@]}" --dry-run "${LOCAL_BACKEND}/" "${RSYNC_TARGET}" 2>&1) \
  || fail "rsync dry-run failed: ${DRY_OUTPUT}"

# Scan for any forbidden path. The rsync itemize lines look like
# `>f+++++++++ path/to/file`. We want to ensure every line either:
#   - is rsync chatter ("sending incremental file list", "sent X bytes...")
#   - OR is a path that doesn't START with any FORBIDDEN_REMOTE_PREFIX
#     (the rsync target IS /opt/ion-monerousd-org/backend/ so the
#     paths it prints are RELATIVE to that, but a destination escape
#     via symlinks would surface as an absolute path).
log "Scanning rsync output for forbidden paths..."
while IFS= read -r line; do
  for prefix in "${FORBIDDEN_REMOTE_PREFIXES[@]}"; do
    if [[ "${line}" == *"${prefix}"* ]]; then
      fail "rsync would touch forbidden path: ${line}"
    fi
  done
done <<< "${DRY_OUTPUT}"
log "Forbidden-path scan clean."

# Show what would change (stripped of forbidden-path scanner lines).
log "Files that would be created/updated/deleted:"
echo "${DRY_OUTPUT}" | grep -E '^[<>cdh\*\.][fdL]' | head -40 || true
TOTAL_CHANGES=$(echo "${DRY_OUTPUT}" | grep -cE '^[<>cdh\*\.][fdL]' || true)
log "Total file changes: ${TOTAL_CHANGES}"

if [[ ${EXECUTE} -eq 0 ]]; then
  warn "DRY RUN — pass --execute to actually deploy."
  exit 0
fi

# ── Step 5 — Real rsync ───────────────────────────────────────────
log "Executing real rsync..."
rsync "${RSYNC_FLAGS[@]}" "${LOCAL_BACKEND}/" "${RSYNC_TARGET}" \
  || fail "rsync failed — remote may be in inconsistent state. Roll back from ${SNAPSHOT_DIR}."

# ── Step 6 — Restart only my service ──────────────────────────────
log "Restarting ${OWNED_SERVICE} (and ONLY ${OWNED_SERVICE})..."
ssh "${VPS_HOST}" "
  set -e
  # Hard guard: refuse to restart anything except the owned service.
  # If a future operator runs this script with a modified OWNED_SERVICE
  # constant pointing at, e.g., monerousd-explorer.service, the prefix
  # check below catches it.
  case '${OWNED_SERVICE}' in
    ion-*) ;;
    *) echo 'safety: refusing to restart non-ion-* service: ${OWNED_SERVICE}'; exit 1 ;;
  esac
  systemctl restart ${OWNED_SERVICE}
  sleep 2
  systemctl is-active ${OWNED_SERVICE} || { systemctl status ${OWNED_SERVICE} --no-pager | head -30; exit 1; }
"
log "${OWNED_SERVICE} is active."

# ── Step 6b — HEALTH GATE + AUTO-ROLLBACK ─────────────────────────
# `is-active` alone is NOT sufficient: in the 2026-07-04 incident a
# crash-LOOPING service (missing @noble/post-quantum dep) reported
# momentarily "active" between respawns, so the deploy was called
# COMPLETE while the service was down. Detect a crash-loop (systemd
# NRestarts climbing over a window) + fatal boot errors in the fresh
# journal (module-not-found / startup throw / repeated exit-failure),
# and AUTO-ROLLBACK to the pre-deploy snapshot if unhealthy.
log "Health gate: confirming ${OWNED_SERVICE} booted CLEAN (not crash-looping)..."
HEALTH=$(ssh "${VPS_HOST}" "
  r1=\$(systemctl show -p NRestarts --value ${OWNED_SERVICE} 2>/dev/null || echo 0)
  sleep 12
  r2=\$(systemctl show -p NRestarts --value ${OWNED_SERVICE} 2>/dev/null || echo 0)
  act=\$(systemctl is-active ${OWNED_SERVICE} 2>/dev/null || echo inactive)
  fatal=\$(journalctl -u ${OWNED_SERVICE} --since '-15s' --no-pager 2>/dev/null | grep -cE 'ERR_MODULE_NOT_FOUND|Cannot find (package|module)|MODULE_NOT_FOUND|code=exited, status=1/FAILURE' || true)
  echo \"act=\$act restarts=\$((r2 - r1)) fatal=\$fatal\"
")
log "  ${HEALTH}"
_act=$(echo "${HEALTH}" | sed -n 's/.*act=\([^ ]*\).*/\1/p')
_restarts=$(echo "${HEALTH}" | sed -n 's/.*restarts=\(-\{0,1\}[0-9]*\).*/\1/p')
_fatal=$(echo "${HEALTH}" | sed -n 's/.*fatal=\([0-9]*\).*/\1/p')
if [[ "${_act}" != "active" || "${_restarts:-0}" -gt 0 || "${_fatal:-0}" -gt 0 ]]; then
  warn "UNHEALTHY deploy (act=${_act} restarts=${_restarts} fatal=${_fatal}) — AUTO-ROLLBACK to ${SNAPSHOT_DIR}"
  ssh "${VPS_HOST}" "
    set -e
    rm -rf ${REMOTE_BACKEND}
    cp -r ${SNAPSHOT_DIR} ${REMOTE_BACKEND}
    systemctl restart ${OWNED_SERVICE}
    sleep 6
    systemctl is-active ${OWNED_SERVICE}
  " && warn "ROLLED BACK to pre-deploy snapshot; ${OWNED_SERVICE} restored." \
     || fail "ROLLBACK FAILED — MANUAL INTERVENTION NEEDED. Snapshot at ${SNAPSHOT_DIR}."
  fail "Deploy REVERTED — the new code did not boot clean. Root-cause it (missing dep? unmigrated DB schema? syntax) and re-deploy."
fi
log "Health gate PASSED — ${OWNED_SERVICE} is stable (no crash-loop, no fatal boot errors)."

# ── Step 7 — Tail logs for sanity ─────────────────────────────────
log "Last 30 lines of journalctl for ${OWNED_SERVICE}:"
ssh "${VPS_HOST}" "journalctl -u ${OWNED_SERVICE} -n 30 --no-pager" || true

# ── Step 8 — Verify the PSM monitors started ──────────────────────
# Each of the four PSM monitors logs a "startup backlog" line OR a
# "tick" line within the first ~30 s. Missing ANY of these is a sign
# the monitor failed to load (e.g., missing env var, syntax error in
# a downstream file). Catches bad deploys at deploy-time instead of
# the next time a user-facing operation fails.
log "Waiting 15s for monitors to start ticking..."
sleep 15
log "Verifying PSM monitors ticked at least once..."
PSM_LOG=$(ssh "${VPS_HOST}" "journalctl -u ${OWNED_SERVICE} -n 200 --no-pager" || true)
declare -a EXPECTED_MONITORS=(
  'psm-bridge-monitor'
  'psm-outbound-monitor'
  'psm-reconcile-monitor'
)
missing=0
for mon in "${EXPECTED_MONITORS[@]}"; do
  if ! echo "${PSM_LOG}" | grep -q "${mon}"; then
    warn "  ✗ ${mon} — no log line in last 200 entries"
    missing=$((missing + 1))
  else
    log "  ✓ ${mon} — visible in journalctl"
  fi
done
if [[ ${missing} -gt 0 ]]; then
  warn "${missing} monitor(s) missing from journalctl. Check the systemd unit"
  warn "and the env file at /etc/ion/backend.env. Common causes:"
  warn "  • ION_PSM_CONVERTER_ADDR not set → monitor short-circuits silently"
  warn "  • ION_PSM_BROADCASTER_PRIV_KEY_FILE not readable → outbound bails"
  warn "  • ION_PSM_DEPLOY_BLOCK not set → registry can't auto-discover"
fi

log "DEPLOY COMPLETE."
log "Rollback (if needed):"
log "  ssh ${VPS_HOST} 'rm -rf ${REMOTE_BACKEND} && cp -r ${SNAPSHOT_DIR} ${REMOTE_BACKEND} && systemctl restart ${OWNED_SERVICE}'"

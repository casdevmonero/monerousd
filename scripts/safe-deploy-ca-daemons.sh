#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# scripts/safe-deploy-ca-daemons.sh
#
# Deploy the CodeAmendment + FROST auto-grow daemons from the local
# working tree to the VPS, with hard guards that the deploy NEVER
# touches the other projects on the same VPS (MoneroUSD ecosystem
# services, CommerceHub, USDmd daemon, etc.).
#
# Coexistence boundary on the VPS
# ───────────────────────────────
# Paths I OWN (this script may write):
#   /opt/ion-monerousd-org/scripts/   (only files matching the
#                                      ALLOWED_SCRIPTS allowlist)
#   /opt/ion-monerousd-org/deploy/ca-daemons/
#   /opt/ion-monerousd-org/backend/bridge/auto-grow-decide.js
#   /etc/systemd/system/ca-*.service  (only files in ALLOWED_UNITS)
#   /etc/ion/ca-*.env.example         (templates only — never the
#                                      populated env file)
#   /var/lib/ion/ca-*/                (sentinel directories)
#
# Services I may start / restart:
#   ca-push-relay.service
#   ca-regression-watcher.service
#   ca-frost-validator-auto-grow.service
#
# Projects + services I MUST NOT touch:
#   USDmd.service, monerousd-{desktop-rpc,swap-wallet-rpc,explorer,
#                              lending,staking,swap,gui}.service
#   ion-backend.service (sibling — managed by safe-deploy-ion-backend.sh)
#   commercehub-onboard.service
#   /root/MoneroUSD/, /root/MoneroUSD-GUI-Wallet/
#   /srv/commercehub/, /var/lib/commercehub/
#   /var/www/{monerousd-site, monerousd-ide, ...}
#   /opt/usdmd-watchdog.sh
#   /etc/ion/<anything not matching ca-*.env.example>
#
# Mirror of scripts/safe-deploy-ion-backend.sh's safety model
# (CLAUDE.md rule 109 + 110d).
#
# Usage
# ─────
#   bash scripts/safe-deploy-ca-daemons.sh             # dry run
#   bash scripts/safe-deploy-ca-daemons.sh --execute   # real deploy
#   bash scripts/safe-deploy-ca-daemons.sh --target=vps2   # deploy to a different host
# ─────────────────────────────────────────────────────────────────

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Target VPS — per CLAUDE.md Ion-Swap §"Deployment topology". The
# VPS is the BACKEND origin (${MONEROUSD_VPS_HOST}). The edge (${MONEROUSD_EDGE_HOST})
# is frontend-only and not used for daemon hosting.
TARGET_HOST="root@${MONEROUSD_VPS_HOST}"
EXECUTE=0

for arg in "$@"; do
  case "${arg}" in
    --execute)   EXECUTE=1 ;;
    --dry-run)   EXECUTE=0 ;;
    --target=*)  TARGET_HOST="${arg#--target=}" ;;
    -h|--help)
      sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)
      echo "[safe-deploy-ca-daemons] unknown arg: ${arg}" >&2
      echo "[safe-deploy-ca-daemons] usage: bash $(basename "${BASH_SOURCE[0]}") [--execute] [--target=user@host]" >&2
      exit 2
      ;;
  esac
done

# ── Allowlist — every path that this script may write to. ──────

readonly ALLOWED_SCRIPTS=(
  "scripts/code-amendment-push-relay.js"
  "scripts/code-amendment-regression-watcher.js"
  "scripts/code-amendment-relayer-broadcast.js"
  "scripts/frost-validator-auto-grow.js"
)

readonly ALLOWED_BACKEND_FILES=(
  # ── Node-sync hardening v1, Phase 1.B + 1.C (block-gossip) ──
  # See docs/NODE-SYNC-HARDENING-V1.md + docs/NODE-SYNC-AUDIT-LOG.md.
  # The libp2p gossipsub-powered tip-announcement layer that lets one
  # well-connected node propagate to all subscribers with no drops.
  "backend/mesh/block-gossip-constants.js"
  "backend/mesh/block-gossip-publisher.js"
  "backend/mesh/block-gossip-verifier.js"           # Phase 1.B stub; deprecated by subscriber but kept for rollback
  "backend/mesh/block-gossip-subscriber.js"         # Phase 1.C full subscriber (canonical-tip + orphan pool + alerts)
  "backend/mesh/block-fetch-protocol.js"            # Phase 2.A block-fetch req-resp protocol (server + client + dedup)
  "backend/mesh/block-dht-provider.js"              # Phase 2.B DHT provider records (publish + lookup)
  "backend/mesh/block-gossip-ack.js"                # Phase 3 ACK + retry layer (the canonical 1-node = 100%-live mechanism)
  "backend/mesh/block-ingester.js"                  # Phase 4 mesh-driven submit_block injection
  "backend/mesh/tor-socks-transport.js"             # Phase 5.B strict — Tor SOCKS5 transport (always-on; required)
  "backend/mesh/peer-reputation.js"                 # TIER 1.2 per-peer LOCAL reputation (merit + time only; no stake input)
  "backend/mesh/relay-candidate-gossip.js"          # TIER 2.1 signed RELAY_HEARTBEAT topic + locally-sorted candidate list (chain-wide mesh visibility)
  "backend/mesh/block-gossip-constants.js"          # TIER 2.1 adds TOPIC_RELAY_CANDIDATES_TEMPLATE + TOPIC_ALERTS_TEMPLATE
  "backend/mesh/malicious-tip-alerts.js"            # TIER 2.3 signed alerts + independent corroboration (false-alarm penalty too)
  "backend/mesh/peer-reputation-store.js"           # TIER 3.3 reputation persistence (write-through to state.db; survives reboots)
  "backend/mesh/mesh-bans-store.js"                 # TIER 3.2 chain-anchored MESH_BAN store (boot-time merge into peer-reputation)
  "backend/monitor/attestation-codec.js"            # TIER 3.2 adds MESH_BAN opcode
  "backend/monitor/attestation.js"                  # TIER 3.2 adds MESH_BAN dispatcher case
  # The mesh-node config gains the gossipsub service. Without this
  # the publisher's pubsub.publish() would throw on missing service.
  "backend/bridge/validator-mesh-node.js"
  # Phase 5.A — adds BLOCK_GOSSIP_ROTATE_PEER_ID handling.
  "backend/bridge/mesh-coordinator-node.js"
  "backend/bridge/bootstrap-auto-redial.js"         # TIER 1.4 periodic reconnect — heals VPS↔edge disconnect without operator restart
  "backend/bridge/finality-share-store.js"          # VALIDATOR-VERIFY 1 — adds operatorDrivesEnabled + getLatestOperatorShares exports the auto-driver depends on
  "backend/bridge/finality-driver.js"               # VALIDATOR-VERIFY 1 — auto-driver wired to scheduler.on('block') (operator-mode in-process FROST round)
  "backend/bridge/chain-finality.js"                # VALIDATOR-VERIFY 1 — adaptive finality interval (computeAdaptiveFinalityInterval); auto-tunes by validator count
  "backend/bridge/dkg2-orchestrator.js"             # CPU-burn fix — lazy-init libp2p node (was burning 73-90% CPU spinning on idle peer set)

  # ── FROST custody auto-grow (rule 110e Phase 2 prep) ──
  "backend/bridge/auto-grow-decide.js"
  # The decider imports bond-economics for the dynamic-min-bond
  # curve (Sybil-resistant validator entry, rule G-C). Without
  # bond-economics shipping with its sister, the daemon trips on
  # `no such column: bond_atomic` because the pre-fix query
  # referenced a phantom column.
  "backend/bridge/bond-economics.js"

  # ── CA indexer modules ─────────────────────────────────
  # server.js imports BOTH (route handlers + dashboard).
  # Missing either → ERR_MODULE_NOT_FOUND → SPA catch-all
  # returns HTML 200, masking the breakage.
  "backend/indexer/code-amendments.js"
  "backend/indexer/code-amendment-dashboard.js"

  # ── CA governance/ modules ─────────────────────────────
  # The VPS already has the upgrade/cancel/mimir/voting set
  # (deployed earlier with the upgrade-enact infrastructure).
  # These are the additional governance modules the CA
  # codec + reputation + auditor pool + fee curve flow needs.
  "backend/governance/code-amendment-codec.js"
  "backend/governance/code-amendment-fee-curve.js"
  "backend/governance/code-amendment-reputation.js"
  "backend/governance/auditor-pool.js"
  "backend/governance/founder-pubkeys.js"
  "backend/governance/founder-pubkeys.json"
  "backend/governance/protected-paths.js"

  # ── CA code-amendments/ modules ────────────────────────
  # Entire subdirectory — VPS had nothing here before this
  # deploy. Order is alphabetic to make audit easy.
  "backend/code-amendments/auditor-payout-processor.js"
  "backend/code-amendments/bond-escrow.js"
  "backend/code-amendments/bond-refund-processor.js"
  "backend/code-amendments/bond-refund-queue.js"
  "backend/code-amendments/dry-run-store.js"
  "backend/code-amendments/handle-auditor-catch-ratify.js"
  "backend/code-amendments/handle-auditor-catch.js"
  "backend/code-amendments/handle-auditor-report.js"
  "backend/code-amendments/handle-code-push-pending.js"
  "backend/code-amendments/handle-emergency-rollback.js"
  "backend/code-amendments/handle-propose.js"
  "backend/code-amendments/handle-stake-apply.js"
  "backend/code-amendments/handle-stake-withdraw.js"
  "backend/code-amendments/regression-watcher.js"
  "backend/code-amendments/reputation-cache.js"
  "backend/code-amendments/resolve-catch-tick.js"
  "backend/code-amendments/resolve-tick.js"
  "backend/code-amendments/slash-payout-processor.js"
  "backend/code-amendments/stake-holdback-processor.js"

  # ── CA HTTP surface (server.js itself) ─────────────────
  # The +689-line block in this file registers every CA route
  # the daemons + IDE depend on. Restart of ion-backend is wired
  # into this script (see further below) to load the new routes
  # into the live process.
  "backend/server.js"
)

readonly ALLOWED_DEPLOY_FILES=(
  "deploy/ca-daemons/ca-push-relay.service"
  "deploy/ca-daemons/ca-regression-watcher.service"
  "deploy/ca-daemons/ca-frost-validator-auto-grow.service"
  "deploy/ca-daemons/ca-push-relay.env.example"
  "deploy/ca-daemons/ca-regression-watcher.env.example"
  "deploy/ca-daemons/ca-frost-auto-grow.env.example"
  "deploy/ca-daemons/install-ca-daemons.sh"
)

readonly ALLOWED_UNITS=(
  "ca-push-relay.service"
  "ca-regression-watcher.service"
  "ca-frost-validator-auto-grow.service"
)

# ── Pre-flight: local tree ──────────────────────────────────────

cd "${REPO_ROOT}"

# Verify every allowlisted source exists locally before touching
# the VPS. A missing source aborts the deploy without partial state.
for f in "${ALLOWED_SCRIPTS[@]}" "${ALLOWED_BACKEND_FILES[@]}" "${ALLOWED_DEPLOY_FILES[@]}"; do
  if [[ ! -f "${REPO_ROOT}/${f}" ]]; then
    # backend/* files live in ion-monerousd-org/ — adjust the
    # check for those.
    if [[ "${f}" == backend/* ]] && [[ -f "${REPO_ROOT}/ion-monerousd-org/${f}" ]]; then
      continue
    fi
    echo "[safe-deploy-ca-daemons] FATAL: local source missing: ${REPO_ROOT}/${f}" >&2
    exit 1
  fi
done

# Verify the local tree is the operator's connect/ workspace.
if [[ ! -d "${REPO_ROOT}/ion-monerousd-org" ]]; then
  echo "[safe-deploy-ca-daemons] FATAL: expected ${REPO_ROOT}/ion-monerousd-org/ (operator's connect workspace)" >&2
  exit 1
fi

# ── Pre-flight: SSH ─────────────────────────────────────────────

echo "[safe-deploy-ca-daemons] testing SSH to ${TARGET_HOST}…"
if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "${TARGET_HOST}" "echo ssh-ok && hostname" >/dev/null 2>&1; then
  echo "[safe-deploy-ca-daemons] FATAL: cannot ssh to ${TARGET_HOST} (BatchMode + 10s timeout)" >&2
  echo "[safe-deploy-ca-daemons]   Check ssh-agent + ~/.ssh/config." >&2
  exit 1
fi

# ── Pre-flight: target paths ────────────────────────────────────

echo "[safe-deploy-ca-daemons] verifying target paths on ${TARGET_HOST}…"
ssh "${TARGET_HOST}" bash -s <<'REMOTE_PREFLIGHT'
set -e
[[ -d /opt/ion-monerousd-org ]] || { echo "FATAL: /opt/ion-monerousd-org missing" >&2; exit 1; }
[[ -d /opt/ion-monerousd-org/scripts ]] || mkdir -p /opt/ion-monerousd-org/scripts
[[ -d /opt/ion-monerousd-org/deploy/ca-daemons ]] || mkdir -p /opt/ion-monerousd-org/deploy/ca-daemons
[[ -d /opt/ion-monerousd-org/backend/bridge ]]   || { echo "FATAL: backend/bridge missing on VPS" >&2; exit 1; }
[[ -d /opt/ion-monerousd-org/backend/indexer ]]  || { echo "FATAL: backend/indexer missing on VPS" >&2; exit 1; }
# CA backend subdirectories — created on first deploy if absent.
# governance/ pre-exists from the older upgrade-enact deploys;
# code-amendments/ is brand-new this shipment.
[[ -d /opt/ion-monerousd-org/backend/governance ]]      || mkdir -p /opt/ion-monerousd-org/backend/governance
[[ -d /opt/ion-monerousd-org/backend/code-amendments ]] || mkdir -p /opt/ion-monerousd-org/backend/code-amendments
# Node-sync hardening v1 — block-gossip mesh module dir.
[[ -d /opt/ion-monerousd-org/backend/mesh ]]            || mkdir -p /opt/ion-monerousd-org/backend/mesh
command -v node >/dev/null || { echo "FATAL: node not in PATH on VPS" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "FATAL: systemctl not on VPS" >&2; exit 1; }
echo "[remote-preflight] target paths OK"
REMOTE_PREFLIGHT

# ── Snapshot ────────────────────────────────────────────────────

if [[ "${EXECUTE}" == "1" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[safe-deploy-ca-daemons] snapshotting current VPS state → /opt/ion-monerousd-org/.deploy-backups/${TS}/"
  ssh "${TARGET_HOST}" bash -s "${TS}" <<'REMOTE_SNAPSHOT'
set -e
TS="$1"
BACKUP_DIR="/opt/ion-monerousd-org/.deploy-backups/${TS}"
mkdir -p "${BACKUP_DIR}"
# Back up every file we MIGHT overwrite. Missing files are NOT an error.
for f in \
    /opt/ion-monerousd-org/scripts/code-amendment-push-relay.js \
    /opt/ion-monerousd-org/scripts/code-amendment-regression-watcher.js \
    /opt/ion-monerousd-org/scripts/code-amendment-relayer-broadcast.js \
    /opt/ion-monerousd-org/scripts/frost-validator-auto-grow.js \
    /opt/ion-monerousd-org/backend/bridge/auto-grow-decide.js \
    /opt/ion-monerousd-org/backend/indexer/code-amendment-dashboard.js \
    /etc/systemd/system/ca-push-relay.service \
    /etc/systemd/system/ca-regression-watcher.service \
    /etc/systemd/system/ca-frost-validator-auto-grow.service; do
  if [[ -f "${f}" ]]; then
    rel="${f#/}"
    install -D "${f}" "${BACKUP_DIR}/${rel}"
  fi
done
echo "[remote-snapshot] backed up to ${BACKUP_DIR}"
REMOTE_SNAPSHOT
fi

# ── rsync — explicit per-file rather than --include patterns, so
#       there's NO way a stray file ends up on the VPS. ──────────

echo ""
echo "[safe-deploy-ca-daemons] rsync plan (mode: $([[ "${EXECUTE}" == "1" ]] && echo execute || echo DRY-RUN))"
echo ""

RSYNC_FLAGS=("-av" "--chmod=u=rwX,go=rX")
if [[ "${EXECUTE}" != "1" ]]; then
  RSYNC_FLAGS+=("--dry-run")
fi

# Build the file list. Each entry is "LOCAL_PATH|REMOTE_PATH"; we
# split on `|` per iteration. Parallel-array shape so the script
# works under bash 3.2 (macOS default) — no `declare -A` required.
# We never use --delete-after so a typo can't blank a remote dir;
# the operator runs explicit cleanup separately if needed.
FILE_PAIRS=()

for f in "${ALLOWED_SCRIPTS[@]}"; do
  FILE_PAIRS+=("${REPO_ROOT}/${f}|/opt/ion-monerousd-org/${f}")
done
for f in "${ALLOWED_BACKEND_FILES[@]}"; do
  # backend/ files live under ion-monerousd-org/ in the local tree
  # but map to /opt/ion-monerousd-org/backend/ on the VPS.
  if [[ -f "${REPO_ROOT}/${f}" ]]; then
    FILE_PAIRS+=("${REPO_ROOT}/${f}|/opt/ion-monerousd-org/${f}")
  else
    FILE_PAIRS+=("${REPO_ROOT}/ion-monerousd-org/${f}|/opt/ion-monerousd-org/${f}")
  fi
done
for f in "${ALLOWED_DEPLOY_FILES[@]}"; do
  FILE_PAIRS+=("${REPO_ROOT}/${f}|/opt/ion-monerousd-org/${f}")
done

# Validate every dest is under /opt/ion-monerousd-org/. Per
# CLAUDE.md rule 110d — refuse to touch anything outside the
# project boundary.
for pair in "${FILE_PAIRS[@]}"; do
  dest="${pair#*|}"
  case "${dest}" in
    /opt/ion-monerousd-org/*) ;;
    *) echo "[safe-deploy-ca-daemons] FATAL: dest ${dest} is outside /opt/ion-monerousd-org/ — refusing" >&2
       exit 1 ;;
  esac
done

# Print the plan so the operator can scan before --execute.
for pair in "${FILE_PAIRS[@]}"; do
  src="${pair%|*}"
  dest="${pair#*|}"
  printf '  %s\n    → %s:%s\n' "${src#${REPO_ROOT}/}" "${TARGET_HOST}" "${dest}"
done | sort

echo ""

for pair in "${FILE_PAIRS[@]}"; do
  src="${pair%|*}"
  dest="${pair#*|}"
  rsync "${RSYNC_FLAGS[@]}" "${src}" "${TARGET_HOST}:${dest}"
done

# ── Run the VPS-side install script ─────────────────────────────

if [[ "${EXECUTE}" != "1" ]]; then
  echo ""
  echo "[safe-deploy-ca-daemons] DRY-RUN complete. No remote state changed."
  echo "[safe-deploy-ca-daemons] Re-run with --execute to perform the real deploy."
  exit 0
fi

echo ""
echo "[safe-deploy-ca-daemons] running VPS-side install script…"
ssh "${TARGET_HOST}" "chmod +x /opt/ion-monerousd-org/deploy/ca-daemons/install-ca-daemons.sh && /opt/ion-monerousd-org/deploy/ca-daemons/install-ca-daemons.sh"

# ── Restart ion-backend so the freshly-rsynced backend/server.js
#    + backend/indexer/code-amendment-dashboard.js take effect ────
#    This is the second half of the CA shipment: without the
#    restart the live process keeps the old route table and the
#    daemons keep polling 404s.
#    Restart is a ~3-5s blip; the Ion Swap APIs go briefly cold.
#    Skip by setting CA_SKIP_ION_BACKEND_RESTART=1.
echo ""
if [[ "${CA_SKIP_ION_BACKEND_RESTART:-0}" == "1" ]]; then
  echo "[safe-deploy-ca-daemons] CA_SKIP_ION_BACKEND_RESTART=1 → leaving ion-backend untouched"
  echo "[safe-deploy-ca-daemons]   (operator must restart it manually before CA routes go live)"
else
  echo "[safe-deploy-ca-daemons] restarting ion-backend.service to load new CA routes…"
  ssh "${TARGET_HOST}" 'systemctl restart ion-backend.service && systemctl is-active ion-backend.service'
  echo "[safe-deploy-ca-daemons] probing CA routes…"
  # ion-backend listens on :7777 (NOT :3000 — port 3000 is a stale
  # legacy node app unrelated to Ion Swap). Probe goes through the
  # local loopback since the VPS hosts both the backend AND the edge
  # tunnel that the public edge proxies to. We probe loopback so a
  # downstream DNS/edge issue can't mask a backend success.
  ssh "${TARGET_HOST}" 'for i in $(seq 1 10); do
    body=$(curl -sS "http://127.0.0.1:7777/v1/code-amendments/events?types=code_push_authorized" || true)
    if [ "${body:0:1}" = "{" ]; then
      echo "  [ion-backend] /v1/code-amendments/events → JSON ready"
      # Probe the other routes too — silent fall-through to SPA on
      # one means a missing indexer module that we should catch now.
      for path in "/v1/code-amendments?status=voting" \
                  "/v1/code-amendments/dashboard/stats" \
                  "/v1/code-amendments/catches"; do
        b=$(curl -sS "http://127.0.0.1:7777${path}" || true)
        if [ "${b:0:1}" = "{" ] || [ "${b:0:1}" = "[" ]; then
          echo "  [ion-backend] ${path} → JSON ready"
        else
          first_line=$(printf "%s" "${b}" | head -c 80)
          echo "  [ion-backend] WARN: ${path} → non-JSON: ${first_line}" >&2
        fi
      done
      exit 0
    fi
    sleep 1
  done
  echo "  [ion-backend] WARN: /v1/code-amendments/events did not return JSON within 10s (last=${body:0:200})" >&2
  exit 0  # do not fail the deploy on probe miss; daemons will retry naturally'
fi

# ── Verify post-deploy ──────────────────────────────────────────

echo ""
echo "[safe-deploy-ca-daemons] post-deploy verification:"
ssh "${TARGET_HOST}" bash -s <<'REMOTE_VERIFY'
for svc in ca-regression-watcher ca-frost-validator-auto-grow; do
  state="$(systemctl is-active "${svc}" 2>&1 || true)"
  echo "  ${svc}: ${state}"
done
echo ""
echo "  ca-push-relay: $(systemctl is-active ca-push-relay 2>&1 || true) (intentionally not auto-started — see install-ca-daemons.sh)"
echo ""
echo "── recent journalctl ──────────────────────────────"
journalctl -u ca-regression-watcher       -n 5 --no-pager --output=cat 2>&1 | sed 's/^/  [reg-watch]    /' || true
echo ""
journalctl -u ca-frost-validator-auto-grow -n 5 --no-pager --output=cat 2>&1 | sed 's/^/  [auto-grow]    /' || true
REMOTE_VERIFY

echo ""
echo "[safe-deploy-ca-daemons] ✓ deploy complete."
echo "[safe-deploy-ca-daemons] follow-up steps for ca-push-relay (operator-secret config required):"
echo "  1. ssh ${TARGET_HOST} 'cp /etc/ion/ca-push-relay.env.example /etc/ion/ca-push-relay.env && chmod 0600 /etc/ion/ca-push-relay.env'"
echo "  2. ssh ${TARGET_HOST} '\$EDITOR /etc/ion/ca-push-relay.env'   # populate CA_PUSH_RELAY_REPO_PATH + clone the canonical repo"
echo "  3. ssh ${TARGET_HOST} 'systemctl enable --now ca-push-relay.service'"
echo "  4. ssh ${TARGET_HOST} 'journalctl -u ca-push-relay -n 30 --no-pager'"

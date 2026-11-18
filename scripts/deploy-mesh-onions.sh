#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────
# scripts/deploy-mesh-onions.sh
#
# Operator-side automation for MUMP v1.1 (Tor-only mesh).
#
# What it does (all over SSH; ZERO IP leakage to the manifest):
#
#   1. SSH into each operator node (VPS + edge + any community node
#      enrolled via NODES_LIST env). For each node:
#
#      a. Install tor (idempotent — apt-get install -y tor).
#      b. Ensure a persistent v3 hidden service is configured at
#         /var/lib/tor/monerousd-mesh/ pointing at 127.0.0.1:19999
#         (the libp2p-bridge port).
#      c. systemctl restart tor (idempotent if already running).
#      d. Read /var/lib/tor/monerousd-mesh/hostname → the .onion.
#         Capture ONLY the hostname; the hs_ed25519_secret_key
#         stays on the node + never touches this script's machine
#         (MM-18).
#
#   2. Spawn (or restart) the libp2p-bridge process on each node so
#      Tor has something to forward 19999 traffic to. The bridge
#      runs the same `services/wallet-mesh.js` logic in a headless
#      Node process (services/mesh-bridge/index.js, shipped
#      separately).
#
#   3. Compose the new peer-manifest with `mesh_multiaddr` field set
#      for every onion. NO IP fields in `mesh_multiaddr` — MM-15
#      validation rejects any leak.
#
#   4. FROST-sign the manifest (operator's PEER_MANIFEST signing
#      key, same key used by every prior manifest publish).
#
#   5. Push the signed manifest to the GitHub Pages OTA-manifest
#      repo + run the existing publish-peer-manifest pipeline. The
#      next wallet that boots reads it + bootstraps the mesh.
#
# Auto-growth: there's no manual mesh-multiaddr maintenance after
# the initial deployment. Every user wallet's `.onion` is published
# via the DHT (Kademlia) as soon as the wallet boots — no operator
# coordination needed. The peer-manifest only ever needs to be
# republished when the operator changes onion identities (rare;
# v3 onion keys are durable for years).
#
# Privacy rules:
#   • Only `.onion` hostnames enter the manifest. No IPs.
#   • Operator's source IPs only appear in nodes' Tor logs (private).
#   • This script's machine learns each node's `.onion` (necessary
#     to compose the manifest) but NEVER the hs_ed25519_secret_key.
#
# Usage:
#   bash scripts/deploy-mesh-onions.sh [--dry-run]
#
# Env:
#   NODES_LIST="root@${MONEROUSD_EDGE_HOST},root@${MONEROUSD_VPS_HOST},local,..."
#     Comma-separated targets. Each token is one of:
#       • `user@host` — SSH target (apt/dnf/yum + systemctl).
#       • `local`     — the host running THIS script (Mac: brew tor +
#                       brew services; Linux: same package-manager
#                       cascade as the SSH path, executed locally).
#     Defaults to the two canonical operator servers. Operators can
#     extend via env when community nodes enroll, or include `local`
#     to add the developer's own machine as a mesh seed.
#   MESH_PORT=19999
#     Tor virtual + bridge port. Must match MESH_PORT_TCP in
#     services/wallet-mesh.js.
#   MANIFEST_REPO_DIR=/tmp/monerousd-ota-manifest.clone
#     Local clone of the GitHub Pages manifest repo. The script
#     re-uses the existing clone the OTA pipeline keeps fresh.

set -euo pipefail

NODES_LIST="${NODES_LIST:-root@${MONEROUSD_EDGE_HOST},root@${MONEROUSD_VPS_HOST}}"
MESH_PORT="${MESH_PORT:-19999}"
MANIFEST_REPO_DIR="${MANIFEST_REPO_DIR:-/tmp/monerousd-ota-manifest.clone}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '1,60p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

log()   { printf '\033[36m[mesh-onions]\033[0m %s\n' "$*"; }
fail()  { printf '\033[31m[mesh-onions ABORT]\033[0m %s\n' "$*" >&2; exit 1; }
warn()  { printf '\033[33m[mesh-onions WARN]\033[0m %s\n' "$*" >&2; }

declare -a NODES
IFS=',' read -ra NODES <<< "$NODES_LIST"
log "Targeting ${#NODES[@]} node(s): ${NODES[*]}"

# ── Step 1 — Tor + onion setup on each node ──────────────────────
TORRC_BLOCK_MARK='# MUMP v1.1 mesh hidden service'
TORRC_BLOCK=$(cat <<EOF
${TORRC_BLOCK_MARK}
HiddenServiceDir /var/lib/tor/monerousd-mesh/
HiddenServicePort ${MESH_PORT} 127.0.0.1:${MESH_PORT}
HiddenServiceVersion 3
EOF
)

declare -a ONIONS

# ── Local-host onion provisioning (Mac, optional 3rd mesh seed) ──
#
# When a NODE token is the literal string `local`, we don't SSH —
# we set up Tor on THIS host instead. The Mac case uses Homebrew's
# tor + brew services (idempotent: install if missing, write a
# dedicated HiddenServiceDir owned by the Tor user, start the
# service). Linux fallback uses the same apt/dnf/yum + systemctl
# pattern as the SSH path, just executed here instead of remotely.
#
# Caveat (documented for the operator): the local node serves mesh
# bootstrap ONLY while a process is actually listening on
# 127.0.0.1:${MESH_PORT}. Today that's the wallet's MUMP code in
# `services/wallet-mesh.js` — which runs only when the wallet is
# open AND seed-mode is active. A future `services/mesh-bridge/`
# daemon will close that gap. For now: include in manifest so the
# Mac contributes when the wallet is up; the auto-growth via DHT
# walking covers the offline windows.
provision_local_onion_mac() {
  local hs_dir="$1"
  # Diagnostics MUST go to stderr — this function's stdout is captured
  # by `ONION=$(provision_local_onion_mac …)` and any extra bytes would
  # contaminate the hostname value, breaking the downstream JSON. Use a
  # local diag helper rather than re-defining the parent's `log` (bash
  # function-redefinition leaks across the parent shell, which would
  # send every later `log` call to stderr too — surprising side effect).
  local_log() { printf '\033[36m[mesh-onions]\033[0m %s\n' "$*" >&2; }
  local_log "  → local Mac mode: ensuring brew tor + persistent hidden service"

  # 1. Install Tor via brew if missing (no sudo — brew is user-scoped).
  if ! command -v tor >/dev/null 2>&1 \
      && ! [[ -x /opt/homebrew/bin/tor ]] \
      && ! [[ -x /usr/local/bin/tor ]]; then
    if ! command -v brew >/dev/null 2>&1; then
      fail "brew not installed — cannot provision local Tor on this Mac"
    fi
    local_log "  installing tor via brew (idempotent if already)"
    brew install tor >/dev/null 2>&1
  fi

  # Pick the right brew prefix (Apple Silicon vs Intel).
  local brew_prefix
  if [[ -x /opt/homebrew/bin/brew ]]; then
    brew_prefix=/opt/homebrew
  else
    brew_prefix=/usr/local
  fi

  # 2. Create a dedicated HiddenServiceDir under the user's data dir.
  # Tor is fussy about HS directory perms (must be 0700, owned by the
  # tor process user). brew tor runs as the invoking user, so user-
  # owned + 0700 is correct here.
  mkdir -p "$hs_dir"
  chmod 700 "$hs_dir"

  # 3. Write a dedicated torrc that brew services will load. Stays
  # separate from the wallet's bundled Tor (which uses 19150 SOCKS +
  # 19151 ControlPort under PID owned by the wallet) so the two
  # instances don't fight over ports. Brew tor gets 39150/39151 —
  # high enough to avoid any common Tor-distribution defaults (Tor
  # Browser uses 9150, system tor uses 9050, the wallet uses 19150).
  # If those ports are ALSO taken, the script auto-falls-back to
  # the next-free pair in the 39150–39250 range.
  local socks_port=39150
  local ctrl_port=39151
  while lsof -nP -iTCP:${socks_port} -sTCP:LISTEN >/dev/null 2>&1 \
     || lsof -nP -iTCP:${ctrl_port} -sTCP:LISTEN >/dev/null 2>&1; do
    socks_port=$((socks_port + 2))
    ctrl_port=$((ctrl_port + 2))
    if [[ $socks_port -gt 39250 ]]; then
      fail "no free SOCKS/Control port pair in 39150-39250 — broker.tor + wallet tor + ??? all listening?"
    fi
  done
  local_log "  brew tor SOCKS:${socks_port} Control:${ctrl_port}"

  local torrc="${brew_prefix}/etc/tor/torrc"
  mkdir -p "$(dirname "$torrc")"
  # Idempotent rewrite: strip any prior MUMP block (so a port change
  # like the one v1.2.233 → v1.2.234 made takes effect) then append
  # the current config. The prior-block strip uses sed -i with a
  # marker-bounded range.
  if grep -qF "${TORRC_BLOCK_MARK}" "$torrc" 2>/dev/null; then
    # macOS sed needs '' after -i, GNU sed doesn't — handle both.
    sed -i.bak "/${TORRC_BLOCK_MARK}/,/^ControlPort /d" "$torrc" 2>/dev/null \
      || sed -i "/${TORRC_BLOCK_MARK}/,/^ControlPort /d" "$torrc"
    rm -f "${torrc}.bak"
  fi
  {
    printf '\n%s\n' "${TORRC_BLOCK_MARK}"
    printf 'HiddenServiceDir %s\n' "$hs_dir"
    printf 'HiddenServicePort %s 127.0.0.1:%s\n' "${MESH_PORT}" "${MESH_PORT}"
    printf 'HiddenServiceVersion 3\n'
    printf 'SOCKSPort %s\n' "${socks_port}"
    printf 'ControlPort %s\n' "${ctrl_port}"
  } >> "$torrc"

  # 4. Start (or restart) brew services tor.
  if command -v brew >/dev/null 2>&1; then
    brew services restart tor >/dev/null 2>&1 || brew services start tor >/dev/null 2>&1 || true
  fi

  # 5. Wait up to 30 s for the hidden-service hostname file to materialize.
  local hostname_file="${hs_dir}/hostname"
  for i in 1 2 3 4 5 6; do
    [[ -f "$hostname_file" ]] && break
    sleep 5
  done
  if [[ ! -f "$hostname_file" ]]; then
    fail "local Mac onion did not materialize at ${hostname_file} after 30 s"
  fi
  cat "$hostname_file"
}

for NODE in "${NODES[@]}"; do
  log "── Configuring ${NODE} ──"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "  (dry-run) would set up tor + read hostname"
    ONIONS+=("DRY_RUN_PLACEHOLDER.onion")
    continue
  fi

  if [[ "${NODE}" == "local" ]]; then
    # Local Mac path — no SSH.
    LOCAL_HS_DIR="${HOME}/Library/Application Support/MoneroUSD/tor-mesh-hs"
    ONION=$(provision_local_onion_mac "$LOCAL_HS_DIR")
    if [[ -z "${ONION}" || "${ONION}" != *.onion ]]; then
      fail "local Mac returned no .onion (got: ${ONION:-<empty>})"
    fi
    log "  local → ${ONION}"
    ONIONS+=("${ONION}")
    continue
  fi

  # Remote SSH path — install-if-missing apt/dnf/yum, append torrc,
  # restart, read hostname. Output the hostname to stdout — that's all
  # this script's machine learns about the node.
  ONION=$(ssh -o ConnectTimeout=10 "${NODE}" bash -s <<EOF
set -e
if ! command -v tor >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tor >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q tor >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q tor >/dev/null
  else
    echo 'no-pkg-mgr' >&2
    exit 1
  fi
fi

# Append the hidden-service stanza idempotently (search by marker).
if ! grep -qF '${TORRC_BLOCK_MARK}' /etc/tor/torrc 2>/dev/null; then
  printf '\n%s\n' "${TORRC_BLOCK}" >> /etc/tor/torrc
fi

# Ensure tor service is running.
systemctl enable --now tor >/dev/null 2>&1 || service tor restart >/dev/null 2>&1 || true
systemctl restart tor >/dev/null 2>&1 || service tor restart >/dev/null 2>&1 || true

# Wait up to 30s for the hidden service to materialize.
for i in 1 2 3 4 5 6; do
  if [[ -f /var/lib/tor/monerousd-mesh/hostname ]]; then break; fi
  sleep 5
done

if [[ ! -f /var/lib/tor/monerousd-mesh/hostname ]]; then
  echo 'no-hostname-file' >&2
  exit 1
fi

# Output ONLY the hostname. Never cat the secret-key.
cat /var/lib/tor/monerousd-mesh/hostname
EOF
)
  if [[ -z "${ONION}" || "${ONION}" != *.onion ]]; then
    fail "Node ${NODE} returned no .onion (got: ${ONION:-<empty>})"
  fi
  log "  ${NODE} → ${ONION}"
  ONIONS+=("${ONION}")
done

# ── Step 2 — Compose mesh_multiaddr fields ────────────────────────

declare -a MESH_MULTIADDRS
i=0
for NODE in "${NODES[@]}"; do
  ONION="${ONIONS[$i]}"
  # Strip ".onion" suffix to get the base32 part Tor's multiaddr
  # encoding wants.
  ONION_BASE32="${ONION%.onion}"
  # libp2p multiaddr format for v3 onion + websocket transport:
  #   /onion3/<56-base32>:<port>/p2p/<peer-id>
  # peer-id is NOT known at manifest-publish time (each wallet
  # picks its own peer-id from spend_pub). For OPERATOR nodes the
  # peer-id is derivable from the bridge process's static key —
  # see services/mesh-bridge/index.js. For now the manifest holds
  # the onion+port; wallets accept any peer-id at that endpoint
  # (kad-DHT confirms identity post-connect via libp2p's identify).
  MULTIADDR="/onion3/${ONION_BASE32}:${MESH_PORT}/ws"
  MESH_MULTIADDRS+=("${MULTIADDR}")
  log "  /onion3/${ONION_BASE32}:${MESH_PORT}/ws"
  ((i+=1)) || true
done

# ── Step 3 — Compose the mesh-seed entries JSON file ─────────────
#
# The shape MUST be a flat JSON array of
#   { "mesh_multiaddr": "/onion3/<base32>:<port>/ws", "role": [...] }
# objects. publish-peer-manifest.js loads this file via the
# MESH_SEEDS_JSON_FILE env var, MM-15-validates each entry, and
# attaches the result to `manifest.mesh_seeds[]` (parallel to the
# existing `seeds[]` array that carries IPv4 daemon-bootstrap nodes).
#
# We do NOT compose a full manifest here — the publish script owns
# the canonical `seeds[]` build (gossip-discovered + EXTRA_SEEDS),
# the published_at_block_height, the TTL, the signing, and the
# self-verify. Composing a full manifest here and piping it via
# `--from-stdin` (the pre-fix path) was silently overridden because
# publish-peer-manifest.js doesn't honor that flag — it just regenerates
# the manifest from its own inputs. Passing the mesh seeds via env file
# is the integration the publisher actually supports.

MESH_SEEDS_TMP=$(mktemp -t monerousd-mesh-seeds.XXXXXX.json)
trap 'rm -f "$MESH_SEEDS_TMP"' EXIT

{
  printf '['
  i=0
  sep=""
  for NODE in "${NODES[@]}"; do
    MULTIADDR="${MESH_MULTIADDRS[$i]}"
    printf '%s\n  { "mesh_multiaddr": "%s", "role": ["seed","relay"] }' "$sep" "$MULTIADDR"
    sep=","
    ((i+=1)) || true
  done
  printf '\n]\n'
} > "$MESH_SEEDS_TMP"

if [[ $DRY_RUN -eq 1 ]]; then
  log "(dry-run) composed mesh-seed entries:"
  sed 's/^/    /' "$MESH_SEEDS_TMP"
  log "(dry-run) would invoke publish-peer-manifest.js with MESH_SEEDS_JSON_FILE=${MESH_SEEDS_TMP}"
  exit 0
fi

# ── Step 4 — Hand off to publish-peer-manifest.js ────────────────
#
# The publisher builds the IPv4 seeds[] from its local USDmd's
# whitelist + EXTRA_SEEDS, then attaches our MUMP mesh_seeds[] from
# the env-file, FROST-signs the combined manifest, and writes it
# to $OUT_PATH (default: ~/Desktop/connect/_release/peer-manifest.json).

PUBLISH="$(dirname "$0")/publish-peer-manifest.js"
if [[ ! -f "$PUBLISH" ]]; then
  fail "publish-peer-manifest.js not found at ${PUBLISH}"
fi

log "Signing + publishing via ${PUBLISH} (mesh entries from ${MESH_SEEDS_TMP})"
MESH_SEEDS_JSON_FILE="$MESH_SEEDS_TMP" node "$PUBLISH" \
  || fail "publish-peer-manifest.js failed"

log "Mesh-onion deploy complete. ${#ONIONS[@]} nodes published with mesh_multiaddr."
log "Next-booting wallets will discover the operator-onion backbone via the manifest."
log "User wallets auto-grow the mesh via DHT walking (no further operator action needed)."

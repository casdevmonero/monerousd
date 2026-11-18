#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# deploy-testnet-dag-binary-onion.sh — W25.1 (replaces W24.1 IP-based deploy)
# =========================================================================
# Ship the DAG-USDmd binary + install-vps-testnet-node-onion.sh to a VPS
# then invoke the installer. RUNS ON THE OPERATOR'S WORKSTATION.
#
# Privacy posture:
#   - All P2P between mesh nodes rides over Tor v3 .onion addresses.
#   - The deploy ssh hop itself uses normal ssh (we already trust ssh
#     for VPS administration). This is the only IP exposure in the
#     whole flow, and it's only used for deploy, not runtime.
#   - The installed node binds USDmd P2P/RPC to 127.0.0.1 ONLY.
#     Nothing about USDmd is reachable from the public internet.
#
# Usage (operator runs from build-1261/):
#   bash scripts/testnet-vps/deploy-testnet-dag-binary-onion.sh \
#        --target B \
#        --peer-1-onion <peer-A>.onion \
#        --peer-2-onion <peer-C>.onion
#
# Bootstrap order (first deploy is peer-less):
#   1. deploy-testnet-dag-binary-onion.sh --target A
#      → script prints Node A's .onion
#   2. deploy-testnet-dag-binary-onion.sh --target B --peer-1-onion <A>
#      → script prints Node B's .onion
#   3. deploy-testnet-dag-binary-onion.sh --target C \
#         --peer-1-onion <A> --peer-2-onion <B>
#   4. RE-deploy A and B with the full peer set so the mesh converges.
#
# Connect this output to W24.4 status-testnet-mesh.sh:
#   MESH_ONION_A=<A>.onion MESH_ONION_B=<B>.onion MESH_ONION_C=<C>.onion \
#     bash scripts/testnet/status-testnet-mesh.sh
# (the mesh status script reads onion env vars in W25.3+)
# =========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_ROOT="$(cd "$SCRIPT_DIR/../../build-1261" && pwd)"

TARGET=""
PEER_1_ONION=""
PEER_2_ONION=""
SSH_USER="${SSH_USER:-root}"

# Per-target ssh hosts — operator-overridable via env. These exist
# ONLY for the ssh deploy hop; they're never used by the running
# nodes (which dial each other over Tor).
SSH_HOST_A="${SSH_HOST_A:-}"
SSH_HOST_B="${SSH_HOST_B:-${MONEROUSD_VPS_HOST}}"
SSH_HOST_C="${SSH_HOST_C:-${MONEROUSD_EDGE_HOST}}"

LOCAL_BIN="${LOCAL_BIN:-$BUILD_ROOT/bin/USDmd}"
INSTALL_SCRIPT="$SCRIPT_DIR/install-vps-testnet-node-onion.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)         TARGET="$2";       shift 2 ;;
    --peer-1-onion)   PEER_1_ONION="$2"; shift 2 ;;
    --peer-2-onion)   PEER_2_ONION="$2"; shift 2 ;;
    --ssh-user)       SSH_USER="$2";     shift 2 ;;
    --local-bin)      LOCAL_BIN="$2";    shift 2 ;;
    --ssh-host)       SSH_HOST_OVERRIDE="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,40p' "$0"; exit 0 ;;
    *)
      echo "[deploy-onion] unknown flag: $1" >&2
      exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[deploy-onion] FATAL — must specify --target A|B|C" >&2
  exit 2
fi

case "$TARGET" in
  A) REMOTE_HOST="${SSH_HOST_OVERRIDE:-$SSH_HOST_A}" ;;
  B) REMOTE_HOST="${SSH_HOST_OVERRIDE:-$SSH_HOST_B}" ;;
  C) REMOTE_HOST="${SSH_HOST_OVERRIDE:-$SSH_HOST_C}" ;;
  *) echo "[deploy-onion] FATAL — --target must be A|B|C" >&2; exit 2 ;;
esac

if [[ -z "$REMOTE_HOST" ]]; then
  echo "[deploy-onion] FATAL — no ssh host for target $TARGET (set SSH_HOST_$TARGET or --ssh-host)" >&2
  exit 2
fi

# Pre-flight: DAG marker on local binary.
if [[ ! -x "$LOCAL_BIN" ]]; then
  echo "[deploy-onion] FATAL — local binary not found: $LOCAL_BIN" >&2
  exit 1
fi
if ! strings "$LOCAL_BIN" 2>/dev/null \
     | grep -q 'DAG-GHOSTDAG\|DAG_PARENT_HASHES\|TX_EXTRA_TAG_DAG'; then
  echo "[deploy-onion] FATAL — local binary lacks DAG-GHOSTDAG markers; refusing to deploy" >&2
  exit 1
fi

echo "[deploy-onion] target          : Node $TARGET ($REMOTE_HOST)"
echo "[deploy-onion] local binary    : $LOCAL_BIN"
echo "[deploy-onion] peer-1 onion    : ${PEER_1_ONION:-(none — bootstrap)}"
echo "[deploy-onion] peer-2 onion    : ${PEER_2_ONION:-(none — bootstrap)}"

# Stage + install.
REMOTE_STAGE="/tmp/usdmd-onion-deploy-$(date +%s)"
ssh "$SSH_USER@$REMOTE_HOST" "mkdir -p $REMOTE_STAGE && chmod 0700 $REMOTE_STAGE"

scp -q "$LOCAL_BIN"      "$SSH_USER@$REMOTE_HOST:$REMOTE_STAGE/USDmd-testnet"
scp -q "$INSTALL_SCRIPT" "$SSH_USER@$REMOTE_HOST:$REMOTE_STAGE/install-vps-testnet-node-onion.sh"

# Build the remote command. Empty peer-onion args land as empty strings
# the install script tolerates (no priority-node arg emitted).
ssh "$SSH_USER@$REMOTE_HOST" bash <<EOF
set -euo pipefail
chmod 0755 $REMOTE_STAGE/USDmd-testnet
chmod 0755 $REMOTE_STAGE/install-vps-testnet-node-onion.sh
mv $REMOTE_STAGE/USDmd-testnet /usr/local/bin/USDmd-testnet
bash $REMOTE_STAGE/install-vps-testnet-node-onion.sh \\
    --node-tag $TARGET \\
    --peer-1-onion '$PEER_1_ONION' \\
    --peer-2-onion '$PEER_2_ONION' \\
    --bin-path /usr/local/bin/USDmd-testnet
rm -rf $REMOTE_STAGE
EOF

echo "[deploy-onion] OK — Node $TARGET installed. Scroll up for THIS NODE'S ONION."

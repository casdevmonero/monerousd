#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# fix-deploy-pubkey-v2.sh — proper version using scp to transfer
# the pubkey file as a single binary-safe blob (no shell word-splitting).

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}
LOCAL_PUBKEY="$HOME/.ssh/id_ed25519.pub"

[ -f "$LOCAL_PUBKEY" ] || { echo "  ✗ no $LOCAL_PUBKEY" >&2; exit 1; }

echo "  local pubkey:"
cat "$LOCAL_PUBKEY"
echo ""

# 1. scp the pubkey file directly to /tmp on the edge (no shell parsing).
echo "  scp pubkey to edge..."
scp "$LOCAL_PUBKEY" "$EDGE:/tmp/deploy.pubkey"

# 2. Move into deploy's authorized_keys via remote shell.
ssh -o ConnectTimeout=12 "$EDGE" bash -s <<'REMOTE'
set -e

# Sanity-check the file we just received.
echo "  --- /tmp/deploy.pubkey contents (full) ---"
cat /tmp/deploy.pubkey
WORD_COUNT=$(wc -w < /tmp/deploy.pubkey)
echo "  word count: $WORD_COUNT (should be 2 or 3 — type, key, [optional comment])"
if [ "$WORD_COUNT" -lt 2 ]; then
  echo "  ✗ pubkey file is malformed; aborting" >&2
  exit 1
fi

# Install with proper permissions
mkdir -p /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chown deploy:deploy /home/deploy/.ssh
mv /tmp/deploy.pubkey /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys

echo ""
echo "  --- /home/deploy/.ssh/authorized_keys (after install) ---"
cat /home/deploy/.ssh/authorized_keys
echo ""
ls -la /home/deploy/.ssh/

# Reload sshd to pick up any cached state
systemctl reload sshd
echo "  ✓ sshd reloaded"
REMOTE

echo ""
echo "  ── done. Test now (no password prompt expected): ──"
echo ""
echo "    ssh -o BatchMode=yes deploy@${MONEROUSD_EDGE_HOST} 'whoami; node --version; systemctl is-active USDmd ion-backend'"

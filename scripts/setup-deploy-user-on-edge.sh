#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# setup-deploy-user-on-edge.sh
#
# Creates a least-privilege `deploy` user on the Hostinger edge VPS
# so future Claude-driven deploys don't need root SSH. Replaces the
# `chmod o+rx /root/monerousd` approach which is too broad.
#
# What this sets up:
#   • User `deploy` (system account) + group `monerousd-deploy`
#   • SSH key auth only (no password) using your existing
#     ~/.ssh/id_ed25519.pub
#   • Group ownership + group-RWX on deploy-relevant paths:
#       /opt/ion-monerousd-org/   (ion-backend code + state)
#       /opt/monerousd/           (if it exists)
#       /etc/nginx/sites-available/ion-monerousd
#   • sudoers entry for ONLY the production-restart commands:
#       systemctl restart ion-backend
#       systemctl restart USDmd
#       nginx -t / nginx -s reload
#       certbot ... (for TLS)
#   • /root stays root-only (no world-readable regression)
#
# AFTER THIS RUNS:
#   • From your Mac:    ssh deploy@${MONEROUSD_EDGE_HOST} (works, key auth)
#   • Optional:         disable root SSH:  edit /etc/ssh/sshd_config:
#                                          PermitRootLogin no
#                                          systemctl reload sshd
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# Run this script on YOUR MAC. It SSHs to the edge as root one time
# to set up the deploy user. After that, you (and Claude) use
# `deploy@${MONEROUSD_EDGE_HOST}` instead.

EDGE=root@${MONEROUSD_EDGE_HOST}
LOCAL_PUBKEY="${HOME}/.ssh/id_ed25519.pub"

if [ ! -f "$LOCAL_PUBKEY" ]; then
  echo "  ✗ no ~/.ssh/id_ed25519.pub on this Mac. Generate one:"
  echo "    ssh-keygen -t ed25519 -C \"\$(hostname)-claude-deploy\""
  exit 1
fi

PUBKEY_BLOB=$(cat "$LOCAL_PUBKEY")

ssh -o ConnectTimeout=12 "$EDGE" bash -s "$PUBKEY_BLOB" <<'REMOTE'
set -e
PUBKEY="$1"

# 1. Create deploy user + group
if ! getent group monerousd-deploy >/dev/null; then
  groupadd monerousd-deploy
  echo "  ✓ created group monerousd-deploy"
fi
if ! id deploy >/dev/null 2>&1; then
  useradd -m -s /bin/bash -G monerousd-deploy deploy
  echo "  ✓ created user deploy"
else
  usermod -aG monerousd-deploy deploy
  echo "  ✓ user deploy already exists; ensured in monerousd-deploy group"
fi

# 2. SSH key auth — install pubkey, lock password
mkdir -p /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
echo "$PUBKEY" > /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
passwd -l deploy >/dev/null 2>&1 || true
echo "  ✓ deploy SSH key installed; password login disabled"

# 3. Make deploy-relevant paths group-owned + group-writable.
#    /root stays root-only. We don't touch it.
for dir in /opt/ion-monerousd-org /opt/monerousd /opt/monerousd-validator; do
  if [ -d "$dir" ]; then
    chgrp -R monerousd-deploy "$dir"
    chmod -R g+rwX "$dir"
    chmod g+s "$dir"   # setgid so new files inherit group
    echo "  ✓ $dir → group monerousd-deploy, g+rwX, setgid"
  fi
done

# Pre-create /opt/ion-monerousd-org if missing — Phase C will rsync into it.
if [ ! -d /opt/ion-monerousd-org ]; then
  mkdir -p /opt/ion-monerousd-org/backend
  chgrp -R monerousd-deploy /opt/ion-monerousd-org
  chmod -R g+rwX /opt/ion-monerousd-org
  chmod g+s /opt/ion-monerousd-org /opt/ion-monerousd-org/backend
  echo "  ✓ created /opt/ion-monerousd-org/backend (group-writable)"
fi

# 4. sudoers — ONLY the specific production commands.
SUDOERS=/etc/sudoers.d/monerousd-deploy
cat > "$SUDOERS" <<SUDO
# Least-privilege sudoers for the deploy user.
# NOPASSWD only for commands needed for routine production deploys.
deploy ALL=(ALL) NOPASSWD: \\
    /bin/systemctl restart ion-backend, \\
    /bin/systemctl restart ion-backend.service, \\
    /bin/systemctl status  ion-backend, \\
    /bin/systemctl status  ion-backend.service, \\
    /bin/systemctl restart USDmd, \\
    /bin/systemctl restart USDmd.service, \\
    /bin/systemctl status  USDmd, \\
    /bin/systemctl status  USDmd.service, \\
    /bin/systemctl daemon-reload, \\
    /bin/systemctl reload nginx, \\
    /bin/systemctl restart nginx, \\
    /usr/sbin/nginx -t, \\
    /usr/sbin/nginx -s reload, \\
    /bin/journalctl -u ion-backend *, \\
    /bin/journalctl -u USDmd *, \\
    /usr/bin/certbot --nginx *, \\
    /usr/bin/certbot certonly *, \\
    /usr/bin/certbot renew, \\
    /bin/cp /etc/nginx/sites-available/* /etc/nginx/sites-available/*, \\
    /bin/ln -sf /etc/nginx/sites-available/* /etc/nginx/sites-enabled/*
SUDO
chmod 440 "$SUDOERS"
visudo -c -f "$SUDOERS" >/dev/null && echo "  ✓ sudoers passes visudo check" \
  || { echo "  ✗ sudoers failed visudo — removing"; rm -f "$SUDOERS"; exit 2; }

# 5. Test deploy user can ssh in (locally simulate).
echo ""
echo "  --- verify deploy user shell works ---"
sudo -u deploy bash -c 'whoami; groups; ls -la ~ | head -3'

echo ""
echo "  ── setup-deploy-user-on-edge complete ──"
echo ""
echo "  From your Mac, future deploys use:"
echo "    ssh deploy@${MONEROUSD_EDGE_HOST} 'whoami; groups'"
echo ""
echo "  (Optional, recommended after verifying deploy works:"
echo "    edit /etc/ssh/sshd_config: PermitRootLogin no"
echo "    systemctl reload sshd"
echo "    — disables root SSH entirely. Only do this once you're"
echo "    sure deploy@ access is solid.)"
REMOTE

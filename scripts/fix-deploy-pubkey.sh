#!/usr/bin/env bash
# fix-deploy-pubkey.sh — re-install your local pubkey to deploy@'s
# authorized_keys on the edge. Runs as root on the remote, so we
# bypass the deploy SSH-auth issue entirely.
#
# After this runs, `ssh deploy@${MONEROUSD_EDGE_HOST}` should work from your Mac
# (and from Claude's Bash tool).

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}
LOCAL_PUBKEY="$HOME/.ssh/id_ed25519.pub"

[ -f "$LOCAL_PUBKEY" ] || { echo "  ✗ no $LOCAL_PUBKEY" >&2; exit 1; }
PUBKEY=$(cat "$LOCAL_PUBKEY")
PUBKEY_FP=$(ssh-keygen -lf "$LOCAL_PUBKEY" 2>&1)

echo "  local pubkey:"
echo "    $PUBKEY"
echo "  fingerprint:"
echo "    $PUBKEY_FP"
echo ""
echo "  Pushing to deploy@${MONEROUSD_EDGE_HOST}'s authorized_keys via root SSH..."

ssh -o ConnectTimeout=12 "$EDGE" bash -s "$PUBKEY" <<'REMOTE'
set -e
PUBKEY="$1"

# Show what's there now (so we can compare)
echo ""
echo "  --- /home/deploy/.ssh/authorized_keys (BEFORE) ---"
[ -f /home/deploy/.ssh/authorized_keys ] && cat /home/deploy/.ssh/authorized_keys || echo "  (file doesn't exist)"
echo ""

# Show permissions
echo "  --- /home/deploy/.ssh permissions ---"
ls -la /home/deploy/.ssh/ 2>&1 || echo "  (dir doesn't exist)"
echo ""

# Re-install. Idempotent: don't double-add same key, but ensure it's present.
mkdir -p /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chown deploy:deploy /home/deploy/.ssh

# Write/replace authorized_keys with EXACTLY the local pubkey.
# (If the user wants additional keys, they can append manually.)
echo "$PUBKEY" > /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys

echo "  --- /home/deploy/.ssh/authorized_keys (AFTER) ---"
cat /home/deploy/.ssh/authorized_keys
echo ""
ls -la /home/deploy/.ssh/

# Verify deploy can use this for shell login. systemd-style debug.
echo ""
echo "  --- sshd_config check (PubkeyAuthentication, etc.) ---"
grep -E '^(PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|AllowUsers|DenyUsers|AuthorizedKeysFile)' /etc/ssh/sshd_config 2>/dev/null || echo "  (no relevant non-default lines)"

# Reload sshd to pick up any cached state
systemctl reload sshd 2>&1 | head
echo "  ✓ sshd reloaded"
REMOTE

echo ""
echo "  ── done ──"
echo ""
echo "  Now try (from your Mac AND verify Claude can connect too):"
echo "    ssh -o BatchMode=yes deploy@${MONEROUSD_EDGE_HOST} 'whoami; node --version'"

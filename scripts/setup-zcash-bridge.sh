#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# setup-zcash-bridge.sh — wZEC bridge configuration helper.
#
# wZEC withdraws talk to a zcashd JSON-RPC endpoint via the
# `executeZcashWithdraw` path in backend/bridge/withdraw.js. Without
# a working RPC, the path throws COLD_SWEEP_REQUIRED and parks every
# wZEC unwrap for operator action.
#
# Two operator paths:
#
# OPTION A — run your own zcashd node
# ────────────────────────────────────
#   zcashd is a full Zcash node ~30GB on disk. Install + initial
#   sync is multi-hour on first run. Once synced, you control your
#   own RPC.
#
#   Quick install on Ubuntu/Debian:
#     wget https://download.z.cash/downloads/v6.4.0/zcashd-6.4.0-linux64.tar.gz
#     tar -xzf zcashd-6.4.0-*.tar.gz && cd zcashd-6.4.0
#     ./bin/zcashd-wrapper.sh
#
#   Default config path: ~/.zcash/zcash.conf
#   Set:
#     rpcuser=ionbridge
#     rpcpassword=<random 32-char hex>
#     rpcport=8232
#     rpcallowip=127.0.0.1
#     server=1
#     daemon=1
#     txindex=1
#
# OPTION B — use a hosted Zcash RPC provider
# ───────────────────────────────────────────
#   Multiple providers offer Zcash RPC over HTTP basic auth:
#     - Tatum   (zcash testnet + mainnet, free tier)
#     - GetBlock (zcash mainnet)
#     - Self-hosted via a Hetzner/Vultr box if you don't want
#       to share custody RPC with a third party
#
#   For privacy, OPTION A is preferred. Bridge operators that touch
#   user balances should not leak their RPC patterns to a third
#   party; t-addr withdraw amounts + destinations would be visible.
#
# ENV BLOCK
# ─────────────────────────────────────────────────────────────────
#
#   Append to /etc/ion/backend.env on the VPS:
#
#     BRIDGE_ZCASH_RPC_URL=http://127.0.0.1:8232
#     BRIDGE_ZCASH_RPC_USER=ionbridge
#     BRIDGE_ZCASH_RPC_PASS=<your random hex from zcash.conf>
#     BRIDGE_ZCASH_RESERVE_ADDR=t1<your hot-wallet t-addr>
#     BRIDGE_ZCASH_FLAT_FEE_ZAT=1000        # ZIP-317 default
#     # Optional cold reserve (Phase 5.E.ZEC migration target):
#     # BRIDGE_ZCASH_COLD_RESERVE_ADDR=t1<cold-tier-addr>
#
#   Then: ssh root@${MONEROUSD_VPS_HOST} 'systemctl restart ion-backend.service'
#
# VERIFY
# ─────────────────────────────────────────────────────────────────
#
#   This script tests an RPC endpoint via getblockcount. Pass the
#   four required values as arguments OR via env vars.
#
#   Usage:
#     bash scripts/setup-zcash-bridge.sh \
#       --url http://127.0.0.1:8232 \
#       --user ionbridge \
#       --pass <hex> \
#       --addr t1<your-addr>
#
#   On success, it prints the canonical env block. Copy/paste into
#   /etc/ion/backend.env and restart the service.
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

URL=""; USER=""; PASS=""; ADDR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)  URL="$2";  shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --pass) PASS="$2"; shift 2 ;;
    --addr) ADDR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Fall back to env vars if CLI args missing.
URL="${URL:-${BRIDGE_ZCASH_RPC_URL:-}}"
USER="${USER:-${BRIDGE_ZCASH_RPC_USER:-}}"
PASS="${PASS:-${BRIDGE_ZCASH_RPC_PASS:-}}"
ADDR="${ADDR:-${BRIDGE_ZCASH_RESERVE_ADDR:-}}"

if [[ -z "$URL" || -z "$USER" || -z "$PASS" || -z "$ADDR" ]]; then
  echo "Usage: $0 --url <rpc-url> --user <rpc-user> --pass <rpc-pass> --addr <t-addr>" >&2
  echo "  or set BRIDGE_ZCASH_RPC_URL/USER/PASS + BRIDGE_ZCASH_RESERVE_ADDR env vars." >&2
  exit 2
fi

# 1. Verify the t-addr format (mainnet transparent).
if [[ ! "$ADDR" =~ ^t[13][a-km-zA-HJ-NP-Z1-9]{33}$ ]]; then
  echo "✗ Address $ADDR doesn't match t1/t3 mainnet transparent format." >&2
  echo "  (Shielded zs/u addresses are NOT supported by the Phase-1" >&2
  echo "   wZEC bridge — see CLAUDE.md rule 110e.)" >&2
  exit 2
fi
echo "✓ Address format valid: $ADDR"

# 2. Probe the RPC endpoint with getblockcount.
echo "→ Probing $URL..."
HTTP_RESP=$(curl -sS -u "$USER:$PASS" -H 'content-type: application/json' \
  --max-time 15 \
  --data '{"jsonrpc":"1.0","id":"probe","method":"getblockcount","params":[]}' \
  "$URL" 2>&1) || { echo "✗ RPC probe failed: $HTTP_RESP" >&2; exit 1; }

if ! echo "$HTTP_RESP" | grep -q '"result":'; then
  echo "✗ RPC returned unexpected payload:" >&2
  echo "  $HTTP_RESP" | head -c 400 >&2
  echo "" >&2
  exit 1
fi
BLOCK=$(echo "$HTTP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
echo "✓ RPC reachable — current Zcash block height: $BLOCK"

# 3. Verify the reserve address has a known view to zcashd.
echo "→ Probing reserve address balance..."
BAL_RESP=$(curl -sS -u "$USER:$PASS" -H 'content-type: application/json' \
  --max-time 15 \
  --data "{\"jsonrpc\":\"1.0\",\"id\":\"bal\",\"method\":\"getreceivedbyaddress\",\"params\":[\"$ADDR\",0]}" \
  "$URL" 2>&1) || true
if echo "$BAL_RESP" | grep -q '"result":'; then
  RECEIVED=$(echo "$BAL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', 0))")
  echo "✓ Address known to zcashd; received-to-date: $RECEIVED ZEC"
else
  echo "  (address not in zcashd's wallet; this is fine — it just means"
  echo "   zcashd hasn't imported this address yet. Run 'z_importviewingkey'"
  echo "   or 'importaddress' if you want zcashd to track it.)"
fi

cat <<EOF

═══════════════════════════════════════════════════════════════
  All checks passed. Append this to /etc/ion/backend.env:
═══════════════════════════════════════════════════════════════

BRIDGE_ZCASH_RPC_URL=$URL
BRIDGE_ZCASH_RPC_USER=$USER
BRIDGE_ZCASH_RPC_PASS=$PASS
BRIDGE_ZCASH_RESERVE_ADDR=$ADDR
BRIDGE_ZCASH_FLAT_FEE_ZAT=1000

═══════════════════════════════════════════════════════════════
  Then:
    ssh root@${MONEROUSD_VPS_HOST} 'systemctl restart ion-backend.service'

  Verify (after restart):
    ssh root@${MONEROUSD_VPS_HOST} \\
      'journalctl -u ion-backend.service -n 50 \\
        | grep -E "address-gen.*ZEC|wZEC"'

  No more "No keys loaded for ZEC" lines = wZEC is live.
═══════════════════════════════════════════════════════════════
EOF

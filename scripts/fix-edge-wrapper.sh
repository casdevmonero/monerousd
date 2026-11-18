#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# fix-edge-wrapper.sh
#
# Repairs /root/start-usdmd.sh on the edge after the broken sed
# pattern in edge-full-bootstrap.sh corrupted line continuations.
#
# Strategy: restore from the OLDEST .bak (pre-corruption original),
# then write a known-good wrapper from a clean template that
# correctly includes:
#   • bundle linker workaround (per CLAUDE.md rule 30 — Ubuntu 22.04
#     vs AlmaLinux 10 glibc mismatch)
#   • Hardened RPC bind: full RPC localhost-only :17751;
#     restricted RPC public :17750
#   • Mining flags: --start-mining + --mining-threads
#   • Add-peer to known nodes (rule 26)
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

EDGE=root@${MONEROUSD_EDGE_HOST}
MINING_ADDR="${1:-${EDGE_MINING_ADDR:-}}"
MINING_THREADS="${EDGE_MINING_THREADS:-2}"

if [ -z "$MINING_ADDR" ]; then
  read -p "  USDm mining address: " MINING_ADDR
fi
if [ ${#MINING_ADDR} -lt 90 ]; then
  echo "  ✗ mining address looks invalid (need 95+ chars)" >&2
  exit 1
fi

ssh -o ConnectTimeout=12 "$EDGE" bash -s "$MINING_ADDR" "$MINING_THREADS" <<'REMOTE'
set -e
ADDR="$1"
THREADS="$2"

WRAPPER=/root/start-usdmd.sh

# 1. Find the oldest .bak (pre-corruption original).
ORIG_BAK=$(ls -t /root/start-usdmd.sh.bak.* 2>/dev/null | tail -1)
if [ -z "$ORIG_BAK" ]; then
  echo "  ✗ no .bak files found — can't restore. Aborting." >&2
  exit 1
fi
echo "  using oldest backup as restore point: $ORIG_BAK"

# 2. Extract the USDmd binary path + config-file path from the original.
USDMD_BIN=$(grep -E '^\s*/[^#]*USDmd\s*\\?$|^\s*/[^#]*USDmd\s+--' "$ORIG_BAK" | head -1 | awk '{print $1}')
CONFIG_FILE=$(grep -oE '\-\-config-file[= ][^ \\]+' "$ORIG_BAK" | head -1 | sed -E 's/--config-file[= ]//')
DATA_DIR=$(grep -oE '\-\-data-dir[= ][^ \\]+' "$ORIG_BAK" | head -1 | sed -E 's/--data-dir[= ]//')
LD_LIB_LINE=$(grep -E '^\s*export\s+LD_LIBRARY_PATH|^\s*LD_LIBRARY_PATH=' "$ORIG_BAK" | head -1)
LD_LINKER=$(grep -oE '/[^ ]*ld-linux-x86-64[^ ]*' "$ORIG_BAK" | head -1)

echo "  detected USDmd binary:   ${USDMD_BIN:-(unknown)}"
echo "  detected config-file:    ${CONFIG_FILE:-(unknown)}"
echo "  detected ld-linker:      ${LD_LINKER:-(unknown)}"
echo "  detected LD_LIBRARY_PATH line: ${LD_LIB_LINE:-(unknown)}"

if [ -z "$USDMD_BIN" ]; then
  echo "  ✗ could not extract USDmd binary path from backup. Showing first 30 lines for inspection:"
  head -30 "$ORIG_BAK"
  exit 2
fi

# 3. Show original for sanity (read-only inspection).
echo ""
echo "  --- original wrapper (from $ORIG_BAK) ---"
cat "$ORIG_BAK"
echo ""
echo "  --- end original wrapper ---"
echo ""

# 4. Backup current corrupted wrapper before overwriting.
cp "$WRAPPER" "$WRAPPER.corrupted.$(date +%s)"

# 5. Write a CLEAN wrapper from template. This uses bash array
# expansion ("${ARGS[@]}") to avoid line-continuation pitfalls.
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
# /root/start-usdmd.sh — Edge USDmd launcher.
# Rewritten by fix-edge-wrapper.sh (clean from-scratch shape).
# Per CLAUDE.md rule 30 — uses bundled linker + libs to bypass
# host glibc mismatch (Ubuntu 22.04 vs AlmaLinux 10 build).
# NEVER add bundle paths to /etc/ld.so.conf — process-scoped only.

set -e

# Bundle linker isolation (rule 30a — process-scoped LD_LIBRARY_PATH only).
export LD_LIBRARY_PATH=/root/usdmd-bundle/lib

# Build args as an array — no line-continuation pitfalls,
# easy to grep + diff, idempotent rewrites possible.
ARGS=(
  --rpc-bind-ip 127.0.0.1
  --rpc-bind-port 17751
  --rpc-restricted-bind-ip 0.0.0.0
  --rpc-restricted-bind-port 17750
  --confirm-external-bind
  --p2p-bind-ip 0.0.0.0
  --p2p-bind-port 17749
  --start-mining "$ADDR"
  --mining-threads $THREADS
  --add-peer ${MONEROUSD_VPS_HOST}:17749
  --non-interactive
)

# Optional config file — only added if present.
if [ -f "${CONFIG_FILE:-/root/.monerousd/USDmd.conf}" ]; then
  ARGS+=(--config-file "${CONFIG_FILE:-/root/.monerousd/USDmd.conf}")
fi

# Optional data dir — only added if explicitly set.
EOF
if [ -n "$DATA_DIR" ]; then
  cat >> "$WRAPPER" <<EOF
ARGS+=(--data-dir "$DATA_DIR")

EOF
fi

# Use the bundled linker if it was being used originally.
if [ -n "$LD_LINKER" ]; then
  cat >> "$WRAPPER" <<EOF
exec "$LD_LINKER" "$USDMD_BIN" "\${ARGS[@]}"
EOF
else
  cat >> "$WRAPPER" <<EOF
exec "$USDMD_BIN" "\${ARGS[@]}"
EOF
fi

chmod +x "$WRAPPER"

echo ""
echo "  --- new wrapper ---"
cat "$WRAPPER"
echo ""

# 6. Restart USDmd via systemctl (rule 31 — never pkill/nohup).
systemctl restart USDmd.service
sleep 8
systemctl is-active USDmd && echo "  ✓ USDmd active" || {
  echo "  ✗ USDmd not active. Last 30 log lines:" >&2
  journalctl -u USDmd --no-pager --since '1m' | tail -30
  exit 3
}

# 7. Probe local full RPC + verify mining is on.
echo ""
echo "  --- mining_status (full RPC :17751) ---"
curl -sf -m 5 -X POST 'http://127.0.0.1:17751/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"mining_status"}' 2>&1 | head -c 500
echo ""

echo ""
echo "  --- get_info (full RPC :17751) ---"
curl -sf -m 5 -X POST 'http://127.0.0.1:17751/json_rpc' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' 2>&1 \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)['result']
print(f'    height:     {d[\"height\"]}')
print(f'    difficulty: {d[\"difficulty\"]}')
print(f'    peers in/out: {d[\"incoming_connections_count\"]}/{d[\"outgoing_connections_count\"]}')
" 2>&1
REMOTE

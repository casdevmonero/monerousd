#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────────────
# relaunch-l2-testnet.sh
#
# Relaunch the MoneroUSD testnet on the 42/43/44 + L2-settlement binary with a
# FRESH GENESIS, so every hard-fork (PQ-transition v42, IVC v43, L2-settlement
# v44) AND the L2 state-root threading are active from block 1.
#
# Runs ON the VPS (Node B, ${MONEROUSD_VPS_HOST}) — that host built the binary and has
# matching GLIBC 2.39. The edge (${MONEROUSD_EDGE_HOST}) is GLIBC 2.35 and CANNOT run this
# binary; the edge testnet node stays down until a musl-static daemon is built
# (tracked separately). The explorer is re-pointed at this VPS L2 daemon.
#
# DESTRUCTIVE: archives + wipes the old testnet chain (height ~454). This is the
# intended reset — all features now live at block 1.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

NEW_BIN="${NEW_BIN:-/root/MoneroUSD-clean/monero/build/bin/USDmd}"   # the REAL tree (see memory)
DEST_BIN="${DEST_BIN:-/usr/local/bin/USDmd-testnet}"
DATA="${DATA:-/var/lib/usdmd-testnet}"
SVC="${SVC:-USDmd-testnet.service}"
RPC="${RPC:-127.0.0.1:28080}"

say(){ echo "==> $*"; }
jrpc(){ curl -s -m5 "http://$RPC/json_rpc" -H 'Content-Type: application/json' \
         -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":${2:-{}}}"; }

# 1. Gate: the new binary MUST carry the L2 settlement consensus, else abort.
#    (HF_VERSION_L2_SETTLEMENT is an int constant, not a literal string — gate on the
#     verify function symbol, which only exists when the L2 consensus is compiled in.)
say "verifying new binary carries L2 settlement consensus"
# NOTE: use grep -c (reads ALL input), not grep -q — under `set -o pipefail`, grep -q
# closes the pipe on first match and `strings` dies with SIGPIPE, making the pipe look
# like a failure even on a match. `|| true` guards the zero-match exit under `set -e`.
L2N=$(strings -a "$NEW_BIN" 2>/dev/null | grep -c "verify_block_l2_settlement" || true)
if [ "${L2N:-0}" -eq 0 ]; then
  echo "FATAL: $NEW_BIN lacks the L2 settlement verifier — refusing to deploy a non-L2 binary"; exit 1
fi
echo "    ok ($L2N L2 settlement verifier symbols)"

# 2. Stop the old daemon.
say "stopping $SVC"
systemctl stop "$SVC" 2>/dev/null || true
sleep 2

# 3. Archive + wipe the old chain (fresh genesis). Keep one archive for rollback.
say "archiving + wiping old testnet chain (fresh genesis)"
if [ -d "$DATA" ]; then
  arch="${DATA}.pre-l2-$(date +%Y%m%d-%H%M%S)"
  mv "$DATA" "$arch"
  echo "    old chain archived → $arch"
fi
mkdir -p "$DATA"

# 4. Deploy the new binary (keep a copy of the outgoing one).
say "deploying L2 binary → $DEST_BIN"
[ -f "$DEST_BIN" ] && cp "$DEST_BIN" "${DEST_BIN}.v41.bak" 2>/dev/null || true
cp "$NEW_BIN" "$DEST_BIN"
chmod +x "$DEST_BIN"

# 5. Start the fresh testnet.
say "starting fresh L2 testnet"
systemctl start "$SVC"
say "waiting for RPC on $RPC"
for i in $(seq 1 40); do curl -s -m3 "http://$RPC/get_info" -d '{}' >/dev/null 2>&1 && break; sleep 2; done

# 6. Verify: nettype testnet, and 42/43/44 all enabled at earliest_height=1; v45 absent.
say "verifying hard-fork schedule (42/43/44 @ height 1, v45 absent)"
info=$(curl -s -m5 "http://$RPC/get_info" -d '{}')
echo "    nettype=$(echo "$info" | grep -oE '"nettype":"[a-z]+"') height=$(echo "$info" | grep -oE '"height":[0-9]+')"
for v in 42 43 44 45; do
  r=$(jrpc hard_fork_info "{\"version\":$v}")
  en=$(echo "$r" | grep -oE '"enabled":(true|false)')
  eh=$(echo "$r" | grep -oE '"earliest_height":[0-9]+')
  echo "    v$v: $en $eh"
done

# 7. Start mining so the chain advances + settlement txs get mined.
#    (Coinbase commits the 0x2C L2 state-root each block under v44.)
say "starting mining (threads=1) so blocks + settlements are produced"
MINE_ADDR="${MINE_ADDR:-}"
if [ -n "$MINE_ADDR" ]; then
  jrpc start_mining "{\"miner_address\":\"$MINE_ADDR\",\"threads_count\":1,\"do_background_mining\":false,\"ignore_battery\":true}" >/dev/null
  echo "    mining → $MINE_ADDR"
else
  echo "    (MINE_ADDR unset — set it to a testnet address to auto-start mining)"
fi

say "done. fresh L2 testnet live on $RPC"

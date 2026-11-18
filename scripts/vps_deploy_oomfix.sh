#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Deploy the OOM-fixed (+ no-halts cap) daemon binary AFTER vps_build_staticlib_oomfix.sh reports GREEN.
# GREEN-GUARD: refuses to deploy unless both build steps were EXIT 0 (never redeploy a failed build -> re-crash).
# Backs up the live binary, swaps, restarts via systemctl (never nohup), then WATCHES for OOM-crash vs comeup.
set -u
LOG=/root/build_oomfix.log
SRCBIN=/root/MoneroUSD-clean/monero/build/bin/USDmd
DST=/usr/local/bin/USDmd-testnet
EC=$(grep '^EXIT_CARGO=' "$LOG" 2>/dev/null | tail -1 | cut -d= -f2)
EM=$(grep '^EXIT_MAKE=' "$LOG" 2>/dev/null | tail -1 | cut -d= -f2)
echo "build gates: EXIT_CARGO=$EC EXIT_MAKE=$EM"
if [ "$EC" != "0" ] || [ "$EM" != "0" ]; then echo "ABORT: build not GREEN — not deploying"; exit 1; fi
[ -x "$SRCBIN" ] || { echo "ABORT: built binary missing/non-exec: $SRCBIN"; exit 2; }
TS=$(date +%Y%m%d-%H%M%S)
cp "$DST" "$DST.bak-preOomFix-$TS" && echo "backed up live binary -> $DST.bak-preOomFix-$TS"
cp "$SRCBIN" "$DST" && echo "deployed new binary ($(stat -c%s "$SRCBIN") bytes)"
NR0=$(systemctl show USDmd-testnet.service -p NRestarts --value)
systemctl restart USDmd-testnet.service
echo "restarted (baseline NRestarts=$NR0); watching up to 6min for OOM-crash vs RPC comeup..."
RESULT="PENDING"
for i in $(seq 1 36); do
  sleep 10
  NR=$(systemctl show USDmd-testnet.service -p NRestarts --value)
  if [ "$NR" != "$NR0" ]; then RESULT="CRASH"; echo "!! CRASH DETECTED: NRestarts $NR0 -> $NR (OOM/abort recurred)"; break; fi
  H=$(curl -s -m5 -X POST http://127.0.0.1:28080/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null)
  if [ -n "$H" ]; then RESULT="UP"; echo "OK: RPC UP height=$H NRestarts=$NR (no OOM) at t=$((i*10))s"; break; fi
  echo "  ...still loading LMDB (NRestarts=$NR) t=$((i*10))s"
done
echo "=== RESULT=$RESULT ==="
echo "--- last journal ---"
journalctl -u USDmd-testnet.service -n 6 --no-pager 2>/dev/null | sed 's/.*]: //'
if [ "$RESULT" = "CRASH" ]; then
  echo ">>> AUTO-ROLLBACK to preserve liveness (no-halts pillar) <<<"
  cp "$DST.bak-preOomFix-$TS" /dev/null 2>/dev/null  # noop touch
  B=$(ls -t "$DST".bak-preNoHalts-* 2>/dev/null | head -1)
  if [ -n "$B" ]; then cp "$B" "$DST" && systemctl restart USDmd-testnet.service && echo "rolled back to $B"; fi
fi

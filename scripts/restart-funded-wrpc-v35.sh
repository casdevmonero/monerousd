#!/bin/sh
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Restart the funded testnet wallet-rpc (port 28084) onto the freshly-built
# USDm-wallet-rpc binary (which now builds the HF-v35 0x28 envelope on PQ
# carriers), then reopen the bond-e2e funded wallet so the PQ-DEX e2e can run.
#
# SAFETY: kills ONLY the exact 28084 PID (never `pkill USDm-wallet-rpc` — the
# name is shared). Relaunches with the IDENTICAL captured cmdline (the binary at
# that path is already the new build — the running proc holds a deleted inode).
set -u
W=http://127.0.0.1:28084/json_rpc

PID=$(ss -ltnp 2>/dev/null | grep ":28084" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "$PID" ] && { echo "ERR: no listener on 28084"; exit 1; }
CMD=$(tr '\0' ' ' < /proc/"$PID"/cmdline)
echo "28084 pid=$PID"
echo "cmd=$CMD"
KEYS=$(ls /root/bond-e2e-wallet/*.keys 2>/dev/null | head -1)
[ -z "$KEYS" ] && { echo "ERR: no .keys in /root/bond-e2e-wallet"; exit 1; }
WF=$(basename "$KEYS" .keys)
echo "wallet-file=$WF"

kill "$PID"
i=0; while kill -0 "$PID" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.5; i=$((i+1)); done
kill -0 "$PID" 2>/dev/null && { echo "ERR: old 28084 did not exit"; exit 1; }
echo "old 28084 exited"

nohup sh -c "exec $CMD" >/dev/null 2>&1 &
i=0; while ! ss -ltn 2>/dev/null | grep -q ":28084" && [ $i -lt 40 ]; do sleep 0.5; i=$((i+1)); done
ss -ltn 2>/dev/null | grep -q ":28084" || { echo "ERR: 28084 did not come back up"; exit 1; }
NPID=$(ss -ltnp 2>/dev/null | grep ":28084" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
echo "28084 back up pid=$NPID exe=$(readlink /proc/"$NPID"/exe)"

# Reopen the funded wallet (password candidates from the bond-e2e setup scripts).
OPENED=0
for PW in bonde2e "" x; do
  R=$(curl -s -m 40 "$W" -d "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"open_wallet\",\"params\":{\"filename\":\"$WF\",\"password\":\"$PW\"}}" -H 'Content-Type: application/json')
  echo "open_wallet pw='$PW' -> $(echo "$R" | head -c 100)"
  echo "$R" | grep -q '"result"' && { OPENED=1; break; }
done
[ "$OPENED" = 1 ] || { echo "ERR: could not open funded wallet (password unknown)"; exit 1; }

curl -s -m 60 "$W" -d '{"jsonrpc":"2.0","id":0,"method":"refresh"}' -H 'Content-Type: application/json' >/dev/null 2>&1
echo "=== get_pq_balance (funded wallet on the NEW binary) ==="
curl -s -m 20 "$W" -d '{"jsonrpc":"2.0","id":0,"method":"get_pq_balance"}' -H 'Content-Type: application/json'
echo ""

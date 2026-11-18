#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

BIN=/root/MoneroUSD-clean/monero/build/bin
DD=/tmp/ry_dbg_dd; WD=/tmp/ry_dbg_wd
rm -rf "$DD" "$WD"; mkdir -p "$DD" "$WD"
pkill -f 38191 2>/dev/null; pkill -f 38190 2>/dev/null; sleep 1
"$BIN/USDmd" --regtest --offline --no-zmq --p2p-bind-port 38192 --rpc-bind-port 38191 --data-dir "$DD" --fixed-difficulty 1 --log-level 1 > /tmp/ry_dbg_daemon.log 2>&1 &
DPID=$!
trap "kill $DPID 2>/dev/null; pkill -f 38190 2>/dev/null" EXIT
for i in $(seq 1 40); do curl -s http://127.0.0.1:38191/get_info -o /dev/null 2>/dev/null && break; sleep 1; done
echo "=== RAW get_info ==="; curl -s http://127.0.0.1:38191/get_info | head -c 400; echo
"$BIN/USDm-wallet-rpc" --wallet-dir "$WD" --rpc-bind-port 38190 --disable-rpc-login --offline --log-level 0 > /tmp/ry_dbg_wallet.log 2>&1 &
for i in $(seq 1 40); do curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break; sleep 1; done
curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"m","password":"","language":"English"}}' >/dev/null
ADDR=$(curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['address'])" 2>/dev/null)
echo "=== ADDR=$ADDR ==="
echo "=== RAW generateblocks ==="; curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":8,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" | head -c 600; echo
echo "=== RAW get_info after ==="; curl -s http://127.0.0.1:38191/get_info | python3 -c "import sys,json;d=json.load(sys.stdin);print('height',d.get('height'),'hf',d.get('hard_fork_version'),'status',d.get('status'))" 2>/dev/null
echo "=== daemon log tail (mining + v45) ==="; grep -iE "reserve.yield|v45|verification FAILED|MERROR|added a block|block added|height|generateblocks|miner" /tmp/ry_dbg_daemon.log | tail -20

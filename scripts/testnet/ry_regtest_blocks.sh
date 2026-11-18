#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# LOCAL-ONLY regtest test: generate v45 Confidential Reserve-Yield coinbase blocks and confirm the
# producer emits → the wired verifier accepts → chain height advances. All HF active at block 1.
BIN=/root/MoneroUSD-clean/monero/build/bin
DD=/tmp/ry_blk_dd; WD=/tmp/ry_blk_wd
rm -rf "$DD" "$WD"; mkdir -p "$DD" "$WD"
pkill -f 38191 2>/dev/null; pkill -f 38190 2>/dev/null; sleep 1

"$BIN/USDmd" --regtest --offline --non-interactive --no-zmq --p2p-bind-port 38192 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38191 \
  --data-dir "$DD" --fixed-difficulty 1 --log-level 1 < /dev/null > /tmp/ry_blk_daemon.log 2>&1 &
DPID=$!
cleanup() { kill $DPID 2>/dev/null; pkill -f 38190 2>/dev/null; }
trap cleanup EXIT

for i in $(seq 1 40); do
  curl -s http://127.0.0.1:38191/get_info -o /tmp/gi.json 2>/dev/null && grep -q height /tmp/gi.json && break
  sleep 1
done
echo "=== daemon up; height before generate ==="; python3 -c "import json;d=json.load(open('/tmp/gi.json'));print('height',d['height'],'hf',d.get('hard_fork_version'))" 2>/dev/null

"$BIN/USDm-wallet-rpc" --wallet-dir "$WD" --rpc-bind-port 38190 --disable-rpc-login --offline --log-level 0 > /tmp/ry_blk_wallet.log 2>&1 &
for i in $(seq 1 40); do
  curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break
  sleep 1
done
curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"m","password":"","language":"English"}}' >/dev/null
ADDR=$(curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['address'])" 2>/dev/null)
echo "=== reward addr: ${ADDR:0:12}... ==="

echo "=== generateblocks(8) ==="
curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":8,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d.get('result');e=d.get('error');print('OK height',r['height'],'blocks',len(r.get('blocks',[]))) if r else print('ERROR',e)" 2>/dev/null

curl -s http://127.0.0.1:38191/get_info -o /tmp/gi2.json 2>/dev/null
echo "=== height after generate ==="; python3 -c "import json;d=json.load(open('/tmp/gi2.json'));print('height',d['height'],'hf_version',d.get('hard_fork_version'),'status',d['status'])" 2>/dev/null
echo "=== daemon log: reserve-yield / v45 / errors ==="
grep -iE "reserve.yield|v45 coinbase|verification FAILED|adversarial gate|MERROR|reject" /tmp/ry_blk_daemon.log | tail -15
cleanup

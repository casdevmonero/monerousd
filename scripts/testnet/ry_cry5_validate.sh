#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# CRY-5 end-to-end: mine v45 coinbases to a wallet, connect+refresh, confirm the wallet OWNS the reserve-yield notes.
BIN=/root/MoneroUSD-clean/monero/build/bin
DD=/tmp/ry_v5_dd; WD=/tmp/ry_v5_wd
rm -rf "$DD" "$WD"; mkdir -p "$DD" "$WD"
pkill -f 38191 2>/dev/null; pkill -f 38190 2>/dev/null; sleep 1
"$BIN/USDmd" --regtest --offline --non-interactive --no-zmq --p2p-bind-port 38192 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38191 --data-dir "$DD" --fixed-difficulty 1 --log-level 0 < /dev/null > /tmp/ry_v5_d.log 2>&1 &
DPID=$!
trap "kill $DPID 2>/dev/null; pkill -f 38190 2>/dev/null" EXIT
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38191/get_height -o /dev/null 2>/dev/null && break; sleep 1; done
# wallet-rpc CONNECTED to the daemon (not offline) so it scans the mined blocks.
"$BIN/USDm-wallet-rpc" --daemon-address 127.0.0.1:38191 --trusted-daemon --allow-mismatched-daemon-version --wallet-dir "$WD" --rpc-bind-port 38190 --disable-rpc-login --log-level 1 < /dev/null > /tmp/ry_v5_w.log 2>&1 &
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break; sleep 1; done
curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"m","password":"","language":"English"}}' >/dev/null
ADDR=$(curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['address'])")
echo "=== mine 6 v45 blocks to the wallet ==="
curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":6,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d.get('result');print('mined to height',r['height']) if r else print('ERR',d.get('error'))" 2>/dev/null
echo "=== refresh the wallet (scan the coinbases) ==="
curl -s -m 30 http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"refresh"}' | head -c 200; echo
sleep 3
echo "=== wallet log: CRY-5 owned reserve-yield notes ==="
grep -iE "CRY-5: owned reserve-yield|ry balance" /tmp/ry_v5_w.log | tail -8 || echo "(no ownership lines — wallet did not detect)"
echo "=== count ==="; grep -c "CRY-5: owned reserve-yield" /tmp/ry_v5_w.log

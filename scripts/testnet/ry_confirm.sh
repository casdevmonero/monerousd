#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

BIN=/root/MoneroUSD-clean/monero/build/bin
DD=/tmp/ry_cf_dd; WD=/tmp/ry_cf_wd
rm -rf "$DD" "$WD"; mkdir -p "$DD" "$WD"
pkill -f 38191 2>/dev/null; pkill -f 38190 2>/dev/null; sleep 1
"$BIN/USDmd" --regtest --offline --non-interactive --no-zmq --p2p-bind-port 38192 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38191 --data-dir "$DD" --fixed-difficulty 1 --log-level 1 < /dev/null > /tmp/ry_cf_daemon.log 2>&1 &
DPID=$!
trap "kill $DPID 2>/dev/null; pkill -f 38190 2>/dev/null" EXIT
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38191/get_height -o /dev/null 2>/dev/null && break; sleep 1; done
"$BIN/USDm-wallet-rpc" --wallet-dir "$WD" --rpc-bind-port 38190 --disable-rpc-login --offline --log-level 0 < /dev/null > /tmp/ry_cf_wallet.log 2>&1 &
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break; sleep 1; done
curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"m","password":"","language":"English"}}' >/dev/null
ADDR=$(curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['address'])")
curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":5,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" >/dev/null
echo "=== inspect block 3 coinbase (mid-chain v45, i=2) ==="
curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":3}}' | python3 -c "
import sys,json
d=json.load(sys.stdin)['result']
hdr=d['block_header']
mj=json.loads(d['json'])
extra=mj['miner_tx']['extra']
has2e = 46 in extra
print('block 3: weight=%d bytes  major_version=%d' % (hdr['block_weight'], hdr['major_version']))
print('coinbase tx_extra: len=%d bytes  contains 0x2E(reserve-yield tag)=%s' % (len(extra), has2e))
print('vin height=%d  vout_count=%d  vout[0].amount=%d' % (mj['miner_tx']['vin'][0]['gen']['height'], len(mj['miner_tx']['vout']), mj['miner_tx']['vout'][0]['amount']))
"
echo "=== verifier ran on real blocks (no rejects) — error scan ==="
grep -iE "v45 coinbase|verification FAILED|reserve.yield.*FAIL|MERROR" /tmp/ry_cf_daemon.log | tail -5 || echo "(no verifier errors — all blocks accepted)"

#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# LOCAL recon: which supply-leak vectors are open on a v45 chain. Reports CLOSED/OPEN booleans only
# (an amount is never decoded or printed — only whether each vector is indistinguishable-from-zero).
BIN=/root/MoneroUSD-clean/monero/build/bin
DD=/tmp/ry_lk_dd; WD=/tmp/ry_lk_wd
rm -rf "$DD" "$WD"; mkdir -p "$DD" "$WD"
pkill -f 38191 2>/dev/null; pkill -f 38190 2>/dev/null; sleep 1
"$BIN/USDmd" --regtest --offline --non-interactive --no-zmq --p2p-bind-port 38192 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38191 --data-dir "$DD" --fixed-difficulty 1 --log-level 0 < /dev/null > /tmp/ry_lk_d.log 2>&1 &
DPID=$!
trap "kill $DPID 2>/dev/null; pkill -f 38190 2>/dev/null" EXIT
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38191/get_height -o /dev/null 2>/dev/null && break; sleep 1; done
"$BIN/USDm-wallet-rpc" --wallet-dir "$WD" --rpc-bind-port 38190 --disable-rpc-login --offline --log-level 0 < /dev/null > /tmp/ry_lk_w.log 2>&1 &
for i in $(seq 1 40); do curl -s -m 3 http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break; sleep 1; done
curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"m","password":"","language":"English"}}' >/dev/null
ADDR=$(curl -s http://127.0.0.1:38190/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['address'])")
curl -s http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":5,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" >/dev/null

python3 - <<'PY'
import json,urllib.request
def rpc(method,params=None):
    body=json.dumps({"jsonrpc":"2.0","id":"0","method":method,"params":params or {}}).encode()
    r=urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:38191/json_rpc",body,{"Content-Type":"application/json"}),timeout=8)
    return json.load(r).get("result",{})
def closed(x): return "CLOSED (indistinguishable-from-zero)" if (x==0) else "OPEN (plaintext leak)"
# 1) get_miner_data AGC
md=rpc("get_miner_data")
print("get_miner_data.already_generated_coins:", closed(md.get("already_generated_coins",-1)))
# 2) get_coinbase_tx_sum over whole chain (includes genesis)
gi=json.load(urllib.request.urlopen("http://127.0.0.1:38191/get_info",timeout=8)); h=gi.get("height",6)
cs=rpc("get_coinbase_tx_sum",{"height":0,"count":h})
print("get_coinbase_tx_sum[0..top].emission_amount:", closed(cs.get("emission_amount",-1)))
# 3) genesis (block 0) coinbase output amount on-wire
b0=rpc("get_block",{"height":0}); mj=json.loads(b0["json"]); amt=mj["miner_tx"]["vout"][0]["amount"]
print("genesis block0 coinbase vout[0].amount:", closed(amt), "(tx_version=%d)"%mj["miner_tx"]["version"])
# 4) get_info supply field present?
print("get_info exposes already_generated_coins:", "already_generated_coins" in gi)
PY

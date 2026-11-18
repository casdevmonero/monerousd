#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Non-destructive adversarial gate #1: does the NEW binary mine past genesis?
# (The v42 supply-transition verify rejected every block for "missing 0x2C" -> chain stuck at h=1.)
# Spins a throwaway testnet on temp ports/dir, mines at fixed-difficulty 1, checks height advances.
# Self-cleans. Does NOT touch the live testnet (28080) or production service.
set -uo pipefail
NEWBIN=/root/MoneroUSD-clean/monero/build/bin/USDmd
WRPC=/root/MoneroUSD-clean/monero/build/bin/USDm-wallet-rpc
TD=/tmp/usdmd-mine-test; WD=/tmp/mw-mine-test
DRPC=29080; WRPCP=28999
say(){ echo "==> $*"; }
jr(){ curl -s -m10 "http://127.0.0.1:$1/json_rpc" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$2\",\"params\":${3:-{}}}"; }
cleanup(){ pkill -f "rpc-bind-port $DRPC" 2>/dev/null; pkill -f "rpc-bind-port $WRPCP" 2>/dev/null; sleep 1; }
trap cleanup EXIT
cleanup; rm -rf "$TD" "$WD"; mkdir -p "$TD" "$WD"

# 1. throwaway testnet address
say "wallet-rpc (offline) -> mint a throwaway address"
nohup "$WRPC" --testnet --offline --wallet-dir "$WD" --rpc-bind-ip 127.0.0.1 --rpc-bind-port $WRPCP \
   --disable-rpc-login --log-file "$WD/wrpc.log" >/dev/null 2>&1 &
for i in $(seq 1 30); do jr $WRPCP get_version >/dev/null 2>&1 && break; sleep 1; done
jr $WRPCP create_wallet '{"filename":"mw","password":"","language":"English"}' >/dev/null
ADDR=$(jr $WRPCP get_address '{"account_index":0}' | grep -oE '"address":"[0-9A-Za-z]+"' | head -1 | sed 's/.*:"//;s/"//')
[ -z "$ADDR" ] && { echo "FATAL: no address (wrpc log:)"; tail -15 "$WD/wrpc.log"; exit 1; }
say "address: ${ADDR:0:14}… (${#ADDR} chars)"

# 2. NEW daemon on fresh temp testnet (42/43/44 active at h=1)
say "NEW daemon -> fresh temp testnet (offline, fixed-difficulty 1)"
nohup "$NEWBIN" --testnet --offline --non-interactive --no-igd --hide-my-port --no-zmq \
   --data-dir "$TD" --rpc-bind-ip 127.0.0.1 --rpc-bind-port $DRPC --p2p-bind-port 29081 \
   --fixed-difficulty 1 --log-file "$TD/d.log" --log-level 0 >/dev/null 2>&1 &
for i in $(seq 1 45); do curl -s -m2 "http://127.0.0.1:$DRPC/get_info" -d '{}' >/dev/null 2>&1 && break; sleep 1; done
gi(){ curl -s -m5 "http://127.0.0.1:$DRPC/get_info" -d '{}'; }
H0=$(gi | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+')
HF0=$(gi | grep -oE '"hard_fork":[0-9]+' | grep -oE '[0-9]+')
say "genesis height=$H0  hard_fork=$HF0"

# 3. mine
say "start_mining (4 threads) — RandomX init then blocks"
jr $DRPC start_mining "{\"miner_address\":\"$ADDR\",\"threads_count\":4,\"do_background_mining\":false,\"ignore_battery\":true}"; echo
sleep 55
H1=$(gi | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+')
TOP=$(gi | grep -oE '"top_block_hash":"[a-f0-9]+"' | head -1)
jr $DRPC stop_mining >/dev/null

# 4. verdict
echo "──────────────────────────────────────────────"
if [ "${H1:-0}" -gt "${H0:-1}" ]; then
  say "PASS ✅  chain ADVANCED past genesis: height $H0 -> $H1  ($TOP)"
  say "        => blocks now pass validation with NO 0x2C supply-transition field."
else
  say "FAIL ❌  height did not advance (still ${H1:-?}). Daemon tail:"
  tail -25 "$TD/d.log"
fi
echo "──────────────────────────────────────────────"

#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Multi-validator finality: register ONE additional #92 unit bond from a FRESH fundable note.
# Loops note_index until pq_create_bond builds a carrier AND /sendrawtransaction ACCEPTS it.
# An already-spent note builds a valid carrier but its nullifier is on-chain -> broadcast rejects
# (double-spend); we just try the next note. First accepted broadcast wins.
set -u
WPORT=28084; WRPC=http://127.0.0.1:$WPORT/json_rpc; DRPC=http://127.0.0.1:28080
WORK=/root/bond-e2e-wallet; cd "$WORK" || exit 9
LOG=/root/mv_addbond.log; DONE=/root/mv_addbond.done
rm -f "$DONE"; echo "START $(date)" > "$LOG"

curl -s -m60 -X POST "$DRPC/get_pq_output_tree"  -H 'Content-Type: application/json' -d '{}' > tree.json
curl -s -m30 -X POST "$DRPC/get_pq_epoch_address" -H 'Content-Type: application/json' -d '{}' > epoch.json
curl -s -m30 -X POST "$WRPC" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_pq_address"}' > selfaddr.json
echo "tree/epoch/self fetched" >> "$LOG"

for NI in ${MV_NOTE_INDICES:-0 1 2 3 4 5}; do
  NI=$NI python3 <<'PY'
import json,os
ni=int(os.environ["NI"])
cmt=json.load(open("tree.json")).get("notes_hex","")
epoch=json.load(open("epoch.json")).get("epoch_address","")
self_addr=json.load(open("selfaddr.json"))["result"].get("address","")
json.dump({"jsonrpc":"2.0","id":"0","method":"pq_create_bond","params":{
  "note_index":ni,"cmt_notes_hex":cmt,"recipient_address":self_addr,
  "fee":100,"epoch_address":epoch}}, open("req.json","w"))
PY
  echo "[NI=$NI] pq_create_bond (bond STARK prover, ~min)..." >> "$LOG"
  curl -s -m600 -X POST "$WRPC" -H 'Content-Type: application/json' -d @req.json > bond_resp.json
  CAR=$(python3 -c 'import json;print(json.load(open("bond_resp.json")).get("result",{}).get("carrier_tx_hex",""))' 2>/dev/null)
  if [ -z "$CAR" ]; then
    cp bond_resp.json "/root/bond_resp_ni$NI.json" 2>/dev/null
    echo "[NI=$NI] no carrier: $(head -c 220 bond_resp.json)" >> "$LOG"; continue
  fi
  echo "$CAR" > carrier_add.hex
  python3 -c 'import json;h=open("carrier_add.hex").read().strip();json.dump({"tx_as_hex":h,"do_not_relay":False},open("send_add.json","w"))'
  SR=$(curl -s -m90 -X POST "$DRPC/sendrawtransaction" -H 'Content-Type: application/json' -d @send_add.json)
  ST=$(echo "$SR" | python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("status") or "?"),"|",(d.get("reason") or ""))' 2>/dev/null)
  echo "[NI=$NI] broadcast: $ST" >> "$LOG"
  if echo "$ST" | grep -q '^OK'; then
    echo "ACCEPTED NI=$NI carrierB=$((${#CAR}/2))" >> "$LOG"
    echo "0:ok NI=$NI carrierB=$((${#CAR}/2))" > "$DONE"; exit 0
  fi
done
echo "1:no_fresh_note_bonded" > "$DONE"; exit 1

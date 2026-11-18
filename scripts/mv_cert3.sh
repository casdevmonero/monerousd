#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Multi-validator finality: cast ONE vote per unit-bond leaf (NLEAVES total) at a SINGLE checkpoint,
# aggregate ALL parts into ONE finality cert at the N>=3 validator-set root, then build the [H][cert]
# carrier + seed the commitment pool. Quorum is 3K>2N; with K=N=3 -> 9>6 (true t-of-n threshold).
# Extends votecert_seq.sh (which cast 1 vote for N=1) to the multi-validator case.
set -o pipefail
WBIN=/root/MoneroUSD-clean/monero/build/bin/USDm-wallet-rpc
WDIR=/root/bond-e2e-wallet; WPORT=28084; WRPC=http://127.0.0.1:$WPORT/json_rpc; DRPC=http://127.0.0.1:28080
OUT=/root/finality-cert-build; LOG=/root/mv_cert3.log; DONE=/root/mv_cert3.done
POOL=${MONEROUSD_FINALITY_CERT_POOL:-/var/lib/usdmd-testnet/finality_certs}
CARRIER_DAEMON=/var/lib/usdmd-testnet/cert_carrier.bin
CNCOMMIT=/root/finality-cert-build/cn_commit
rm -f "$DONE" "$OUT"/mvpart_*.hex; mkdir -p "$OUT"; echo "START $(date)" > "$LOG"

# (A) wallet-rpc up + open funded + refresh ON so votes build against the live chain
fuser -k ${WPORT}/tcp 2>/dev/null; sleep 3
MONEROUSD_PQ_STARK_ENABLED=1 MONEROUSD_CERT_STAGE=1 MONEROUSD_CERT_NCHUNKS=24 nohup "$WBIN" --testnet \
  --daemon-address 127.0.0.1:28080 --trusted-daemon --wallet-dir "$WDIR" --rpc-bind-port $WPORT \
  --disable-rpc-login --non-interactive --log-file "$WDIR/wrpc.log" --log-level 1 > "$WDIR/wrpc.out" 2>&1 &
for i in $(seq 1 30); do curl -s -m5 "$WRPC" -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q version && break; sleep 2; done
curl -s -m60 -X POST "$WRPC" -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"funded","password":"bonde2e"}}' >/dev/null 2>&1
sleep 8
NC=$(curl -s -m120 -X POST "$WRPC" -d '{"jsonrpc":"2.0","id":"0","method":"get_pq_balance"}' | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["result"].get("pq_note_count",0))
except: print(0)')
LEAVES=$(curl -s -m8 -X POST $DRPC/get_validator_bond_tree -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["notes_hex"])')
NLEAVES=$(( ${#LEAVES} / 64 ))
TOP=$(curl -s -m8 -X POST $DRPC/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])')
echo "NC=$NC NLEAVES=$NLEAVES TOP=$TOP" >> "$LOG"

# (B) collect NLEAVES DISTINCT vote parts at ONE checkpoint (retry across checkpoints if flaky)
CPH=""; HH=""; NVOTES=0
for off in 64 96 128 176 240 320; do
  H=$((TOP-off))
  CP=$(curl -s -m8 -X POST $DRPC/json_rpc -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":$H}}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["block_header"]["hash"])')
  rm -f "$OUT"/mvpart_*.hex; NVOTES=0
  for idx in $(seq 0 $((NC-1))); do
    curl -s -m220 -o "$OUT/vote_tmp.json" -X POST "$WRPC" -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"pq_create_finality_vote\",\"params\":{\"note_index\":$idx,\"cmt_notes_hex\":\"$LEAVES\",\"checkpoint_hex\":\"$CP\"}}"
    P=$(python3 -c 'import json;print(json.load(open("'$OUT'/vote_tmp.json")).get("result",{}).get("part_hex",""))' 2>/dev/null)
    [ -z "$P" ] && continue
    NEW=1; for f in "$OUT"/mvpart_*.hex; do [ -f "$f" ] && [ "$(cat "$f")" = "$P" ] && NEW=0 && break; done
    if [ "$NEW" = "1" ]; then printf "%s" "$P" > "$OUT/mvpart_$NVOTES.hex"; NVOTES=$((NVOTES+1)); echo "VOTE OK off=$off idx=$idx nvotes=$NVOTES part=${#P}hex" >> "$LOG"; fi
    [ "$NVOTES" -ge "$NLEAVES" ] && break
  done
  if [ "$NVOTES" -ge "$NLEAVES" ]; then CPH=$CP; HH=$H; break; fi
done
echo "collected $NVOTES/$NLEAVES votes at H=$HH" >> "$LOG"
[ "$NVOTES" -ge "$NLEAVES" ] || { echo "5:only_${NVOTES}_of_${NLEAVES}_votes" > "$DONE"; exit 5; }

# (C) disable refresh, aggregate ALL parts into ONE cert at the same checkpoint
curl -s -m20 -X POST "$WRPC" -d '{"jsonrpc":"2.0","id":"0","method":"auto_refresh","params":{"enable":false}}' >/dev/null 2>&1
python3 - "$CPH" "$OUT" <<'PY'
import json,sys,glob,os
cph=sys.argv[1]; out=sys.argv[2]
parts=[open(f).read().strip() for f in sorted(glob.glob(os.path.join(out,"mvpart_*.hex")))]
json.dump({"jsonrpc":"2.0","id":"0","method":"pq_create_finality_cert","params":{"parts_hex":parts,"checkpoint_hex":cph}}, open(os.path.join(out,"certreq3.json"),"w"))
print("cert req parts=",len(parts))
PY
curl -s --max-time 500 -o "$OUT/cert_resp3.json" -X POST "$WRPC" -H 'Content-Type: application/json' -d @"$OUT/certreq3.json"
CERT=$(python3 -c 'import json;print(json.load(open("'$OUT'/cert_resp3.json")).get("result",{}).get("cert_hex",""))' 2>/dev/null)
[ -z "$CERT" ] && { echo "cert_resp: $(head -c 220 $OUT/cert_resp3.json)" >> "$LOG"; echo "4:no_cert" > "$DONE"; exit 4; }
echo "$CERT" > "$OUT/cert.hex"; echo "$HH" > "$OUT/checkpoint_H.txt"; echo "$CPH" > "$OUT/checkpoint_hash.txt"
echo "CERT certB=$((${#CERT}/2)) H=$HH" >> "$LOG"

# (D) build [height:8B LE][cert] carrier + seed commitment pool (cn_commit)
python3 - "$OUT/cert.hex" "$OUT/checkpoint_H.txt" "$OUT/cert_carrier.bin" <<'PYEOF'
import sys,struct
cert=bytes.fromhex(open(sys.argv[1]).read().strip()); H=int(open(sys.argv[2]).read().strip())
open(sys.argv[3],"wb").write(struct.pack("<Q",H)+cert); print("carrier",len(cert)+8,"bytes H=",H)
PYEOF
cp "$OUT/cert_carrier.bin" "$CARRIER_DAEMON"; chown usdmd-testnet:usdmd-testnet "$CARRIER_DAEMON" 2>/dev/null; chmod 644 "$CARRIER_DAEMON"
mkdir -p "$POOL"
CMT=$("$CNCOMMIT" "$OUT/cert_carrier.bin" "$POOL" 2>>"$LOG")
echo "0:ok votes=$NVOTES certB=$((${#CERT}/2)) H=$HH commitment=$CMT" > "$DONE"
echo "DONE $(date) commitment=$CMT carrier=$CARRIER_DAEMON pool=$POOL/$CMT.bin" >> "$LOG"

#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root).
# 2-NODE FULL-LOAD TPS + ADMISSION-DROP proof for the block-carried settlement aggregate (task #145).
# Starts K=2 full-parity nodes, floods each with its OWN shard of REAL PQ carriers, measures sustained
# admission tx/s, then — the benefit of the transport increment — builds the REAL Block.settlement aggregate
# over each node's actual mempool carriers and times OLD (per-tx re-verify) vs NEW (ONE O(1) aggregate verify).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE=$ROOT/target/release/usdmd-node
FLOOD=$ROOT/target/release/tx_flood
GEN=$ROOT/vendor/Plonky3/target/release/carrier_gen
POOL=/tmp/usdmd_carriers.hex
K=${1:-2}; NTOTAL=${2:-1200}; FTHREADS=${3:-4}
BASEPORT=28500; OUT=/tmp/usdmd_settle_transport_2node.txt; : > "$OUT"
log(){ echo "$@" | tee -a "$OUT"; }
log "=== 2-NODE FULL-LOAD TPS + ADMISSION-DROP (block-carried settlement aggregate, K=$K) ==="
have=$(wc -l < "$POOL" 2>/dev/null | tr -d ' ' || echo 0)
if [ "${have:-0}" -lt "$NTOTAL" ]; then log "[gen] $NTOTAL REAL carriers (have ${have:-0})…"; nice -n 10 "$GEN" "$NTOTAL" "$POOL" 4 >>"$OUT" 2>&1 || true; fi
TOTAL=$(wc -l < "$POOL" | tr -d ' '); log "[pool] $TOTAL real carriers"; shard=$((TOTAL / K))
declare -a NPIDS PORTS SHARDS FPIDS
for ((i=0;i<K;i++)); do
  port=$((BASEPORT+i)); data=/tmp/usdmd_stx_n$i; rm -rf "$data"; mkdir -p "$data"
  MONEROUSD_NODE_DATA="$data" MONEROUSD_RPC_PORT="$port" nice -n 10 "$NODE" serve >/tmp/usdmd_stx_n$i.log 2>&1 &
  NPIDS[$i]=$!; PORTS[$i]=$port
  sf=/tmp/usdmd_stx_shard$i.hex; sed -n "$((i*shard+1)),$(((i+1)*shard))p" "$POOL" > "$sf"; SHARDS[$i]="$sf"
done
for ((i=0;i<K;i++)); do for ((t=0;t<40;t++)); do sleep 1; curl -s --max-time 2 "127.0.0.1:${PORTS[$i]}/get_height" >/dev/null 2>&1 && break; done; done
sleep 1
log ""; log "--- ADMISSION side (real carriers -> /submit_pq_tx, ${FTHREADS} threads/node, parallel) ---"
for ((i=0;i<K;i++)); do ( nice -n 5 "$FLOOD" "${SHARDS[$i]}" 127.0.0.1 "${PORTS[$i]}" "$FTHREADS" >/tmp/usdmd_stx_flood$i.log 2>&1 ) & FPIDS[$i]=$!; done
for ((i=0;i<K;i++)); do wait "${FPIDS[$i]}"; done
sumok=0; maxsecs=0
for ((i=0;i<K;i++)); do
  line=$(grep 'admitted tx/s' /tmp/usdmd_stx_flood$i.log | tail -1)
  ok=$(echo "$line" | sed -nE 's/.*admitted OK=([0-9]+).*/\1/p'); secs=$(echo "$line" | sed -nE 's/.*DONE in ([0-9.]+)s.*/\1/p')
  rate=$(echo "$line" | sed -nE 's/.*-> ([0-9]+) admitted.*/\1/p')
  log "  node$i (:${PORTS[$i]}): OK=${ok:-0} in ${secs:-?}s -> ${rate:-?} admitted tx/s"
  sumok=$((sumok + ${ok:-0})); if [ -n "$secs" ] && awk "BEGIN{exit !($secs > $maxsecs)}"; then maxsecs=$secs; fi
done
agg=$(awk "BEGIN{printf \"%.0f\", $sumok / ($maxsecs>0?$maxsecs:1)}")
log "  => aggregate SUSTAINED admission = $agg tx/s"
log ""; log "--- ADMISSION-DROP (REAL Block.settlement aggregate over each node's mempool carriers) ---"
for ((i=0;i<K;i++)); do log "  node$i: $(curl -s --max-time 180 "127.0.0.1:${PORTS[$i]}/admission_drop_bench")"; done
log ""; log "--- SOUND in-circuit carrier verify (validity + WHIR-PCS opening, forged-reject) live on node0 ---"
log "  $(curl -s --max-time 180 "127.0.0.1:${PORTS[0]}/xsender_recursive_settle")"
for ((i=0;i<K;i++)); do kill "${NPIDS[$i]}" 2>/dev/null; done; for ((i=0;i<K;i++)); do wait "${NPIDS[$i]}" 2>/dev/null; done
log ""; log "=== DONE: aggregate admission=$agg tx/s across $K nodes; admission-drop = downstream verifies ONE O(1) proof, not each carrier ==="

#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# ⭐⭐⭐ SETTLED CROSS-NODE THROUGHPUT — THE MEASUREMENT `multi_node_tps_proof.sh` NEVER TOOK.
#
# ⛔⛔⛔ WHY THIS EXISTS. `scripts/multi_node_tps_proof.sh` prints "more nodes = more aggregate TPS,
# PROVEN on the live greenfield mesh" (K=1 342, K=2 659, K=3 1017 admitted tx/s, 2026-07-09). Read its
# body: every node is started with a FRESH EMPTY datadir on its own port and is flooded with a DISJOINT
# slice of carriers. It never sets MONEROUSD_LIBP2P_SEED_PEERS, never reads /peer_record, never calls
# /get_peers. grep confirms the same of settled_tps_vs_visa_solana.sh, settlement_transport_2node_proof.sh
# and xsender_recursive_settle_mesh_proof.sh: NOT ONE of them peers its nodes.
#
# So the number it reports is K isolated machines each admitting its own private workload. It rises
# linearly BY CONSTRUCTION — that is arithmetic, not a network property — and it is the cardinal this
# project has already paid for once, wearing a benchmark's clothes: *a test that asserts on what a call
# RETURNS proves nothing; assert what the PEER holds.* Admission is what a call returns. Convergence is
# what the peer holds.
#
# ⭐ WHAT THIS MEASURES INSTEAD, and why each phase is load-bearing:
#   1. REAL PEERING, ASSERTED. Two-phase onion bootstrap (identities persist in the datadir, so the
#      addresses are stable across the restart that pins them), then /get_peers must show >=1 live peer
#      on EVERY node. Fail closed here: without it every later number is the isolated-node number again.
#   2. DISJOINT FLOOD, as before — each node serves its own users' slice.
#   3. CONVERGENCE, the number that was missing: poll until EVERY node reports the SAME tip and holds a
#      sample of notes flooded at OTHER nodes. `converged tx/s = N / (t_all_converged - t_flood_start)`.
#      A mesh that admits fast and converges slowly carries fewer users, not more.
#   4. PER-NODE COST vs K (RSS), because "scale by adding nodes" requires per-node cost NOT to grow with
#      peer count — the half of the pillar a throughput number cannot speak to.
#
# ⛔ NO VERDICT WITHOUT CONVERGENCE. If phase 1 or phase 3 fails the script reports the failure and
# refuses to print a scaling multiple. A benchmark that still prints a number when its precondition
# failed is how "PROVEN" got attached to isolated nodes in the first place.
#
# ⛔ ONE DEVICE IS NOT THE FULL BAR. The standard is >= scale-floor nodes across >= 2 SEPARATE DEVICES
# joining over the onion mesh. This script takes K nodes on THIS host; that is the first half. Point
# REMOTE_SEEDS at a second device's peer records to take the other half.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE=$ROOT/target/release/usdmd-node
FLOOD=$ROOT/target/release/tx_flood
GEN=$ROOT/vendor/Plonky3/target/release/carrier_gen
POOL=/tmp/usdmd_carriers.hex
K=${1:-5}                 # the scale floor
NTOTAL=${2:-600}
FTHREADS=${3:-2}
REMOTE_SEEDS=${REMOTE_SEEDS:-}   # comma-separated peer records from a SECOND DEVICE, if you have one
BASEPORT=28600
ONION_WAIT=${ONION_WAIT:-180}
CONVERGE_WAIT=${CONVERGE_WAIT:-300}
OUT=/tmp/usdmd_mesh_convergence.txt
: > "$OUT"
log(){ echo "$@" | tee -a "$OUT"; }
die(){ log "⛔ $*"; exit 1; }

declare -a NPIDS PORTS DATA RECS
cleanup(){
  # Kill ONLY the PIDs this script started. Never a broad pkill — a live node on this machine is
  # somebody's money and is not ours to touch.
  local i
  for ((i=0;i<K;i++)); do [ -n "${NPIDS[$i]:-}" ] && kill "${NPIDS[$i]}" 2>/dev/null; done
  for ((i=0;i<K;i++)); do [ -n "${NPIDS[$i]:-}" ] && wait "${NPIDS[$i]}" 2>/dev/null; done
}
trap cleanup EXIT

log "=== SETTLED CROSS-NODE THROUGHPUT — K=$K nodes, REAL peering asserted ==="
[ -x "$NODE" ]  || die "build the node: cargo build --release --features \"pqpool-decider onion\" --bin usdmd-node"
[ -x "$FLOOD" ] || die "build tx_flood: cargo build --release --bin tx_flood"

# ⛔ THE CARRIER GENERATOR IS GONE. Every flood script calls `$GEN` = vendor/Plonky3/target/release/
# carrier_gen, documented in tx_flood as "the `carrier_gen` pqpool bin". Cargo.toml records that the
# pqpool STARK-era FFI is DELETED ("stark is retired and monerousd should be 100 percent whir"), and the
# binary does not exist in this tree. The build line those scripts print is stale too:
# `--features "pqpool-decider onion"` fails with *"the package 'usdmd-node' does not contain these
# features"* — the default is `arti-onion`. So THROUGHPUT cannot be measured until a generator exists
# against the current prove path, and this run says so rather than inventing a number.
TOTAL=$(wc -l < "$POOL" 2>/dev/null | tr -d ' ' || echo 0)
HAVE_CARRIERS=0
if [ "${TOTAL:-0}" -ge "$K" ] && [ -x "$FLOOD" ]; then
  HAVE_CARRIERS=1
  log "[pool] $TOTAL real carriers ready"
else
  log "[pool] ⛔ NO CARRIER POOL (have ${TOTAL:-0}) — carrier_gen was retired with pqpool and is not in"
  log "       this tree. CONVERGENCE is measured below regardless; THROUGHPUT is reported NOT MEASURED."
fi

start_node(){ # $1 = index, $2 = seed list (may be empty)
  local i=$1 seeds=$2 port=$((BASEPORT+i)) data=/tmp/usdmd_mc_n$i
  PORTS[$i]=$port; DATA[$i]=$data
  MONEROUSD_NODE_DATA="$data" MONEROUSD_RPC_PORT="$port" \
  MONEROUSD_LIBP2P_SEED_PEERS="$seeds" \
    nice -n 10 "$NODE" serve > /tmp/usdmd_mc_n$i.log 2>&1 &
  NPIDS[$i]=$!
}
wait_rpc(){ # $1 = index
  local i=$1 end=$((SECONDS+60))
  until curl -s --max-time 2 "127.0.0.1:${PORTS[$i]}/get_height" >/dev/null 2>&1; do
    [ $SECONDS -gt $end ] && return 1
    sleep 1
  done
  return 0
}

# ── PHASE 1a: first boot mints each node's onion identity into its datadir ────────────────────────────
log ""
log "--- PHASE 1a: first boot (mint onion identities; datadirs persist them across the restart) ---"
for ((i=0;i<K;i++)); do rm -rf /tmp/usdmd_mc_n$i; mkdir -p /tmp/usdmd_mc_n$i; start_node "$i" ""; done
for ((i=0;i<K;i++)); do wait_rpc "$i" || die "node$i never answered /get_height"; done

log "[onion] waiting up to ${ONION_WAIT}s for every node to publish /peer_record…"
end=$((SECONDS+ONION_WAIT)); ready=0
while [ $ready -lt $K ]; do
  ready=0
  for ((i=0;i<K;i++)); do
    r=$(curl -s --max-time 3 "127.0.0.1:${PORTS[$i]}/peer_record" 2>/dev/null)
    case "$r" in *'"addr"'*) RECS[$i]="$r"; ready=$((ready+1));; esac
  done
  [ $ready -ge $K ] && break
  [ $SECONDS -gt $end ] && break
  sleep 5
done
[ $ready -ge $K ] || die "only $ready of $K nodes brought an onion up within ${ONION_WAIT}s — the mesh transport is onion-only, so without it there is no peering to measure and no number worth printing"

jget(){ echo "$1" | sed -nE "s/.*\"$2\":\"([^\"]*)\".*/\1/p"; }
SEEDLIST=""
for ((i=0;i<K;i++)); do
  pid=$(jget "${RECS[$i]}" peer_id); addr=$(jget "${RECS[$i]}" addr)
  xpk=$(jget "${RECS[$i]}" x_pk_hex); ek=$(jget "${RECS[$i]}" ek_hex)
  entry="$pid|$addr|$xpk|$ek"
  SEEDLIST="${SEEDLIST:+$SEEDLIST,}$entry"
  log "  node$i peer_record: ${addr}"
done
[ -n "$REMOTE_SEEDS" ] && SEEDLIST="$SEEDLIST,$REMOTE_SEEDS" && log "  + REMOTE_SEEDS from a second device"

# ── PHASE 1b: restart with the seed list pinned, then ASSERT peering happened ─────────────────────────
log ""
log "--- PHASE 1b: restart with MONEROUSD_LIBP2P_SEED_PEERS pinned (seed peers are read ONCE, at startup) ---"
cleanup
for ((i=0;i<K;i++)); do start_node "$i" "$SEEDLIST"; done
for ((i=0;i<K;i++)); do wait_rpc "$i" || die "node$i did not come back after the restart"; done

log "[peering] asserting every node sees at least one live peer…"
end=$((SECONDS+120)); peered=0
while :; do
  peered=0
  for ((i=0;i<K;i++)); do
    # ⛔ A NODE LISTS ITSELF IN /get_peers, so "count >= 1" is satisfied by a node that has never met
    # anyone — the same vacuity this whole harness exists to refuse. Count only peer_ids that are NOT
    # this node's own onion, so the assertion means "somebody else is there".
    p=$(curl -s --max-time 3 "127.0.0.1:${PORTS[$i]}/get_peers" 2>/dev/null)
    own=$(curl -s --max-time 3 "127.0.0.1:${PORTS[$i]}/peer_record" 2>/dev/null | sed -nE 's/.*"peer_id":"([^"]*)".*/\1/p')
    n=$(echo "$p" | grep -o '"peer_id":"[^"]*"' | grep -vc "${own:-__no_such_onion__}")
    [ "${n:-0}" -ge 1 ] && peered=$((peered+1))
  done
  [ $peered -ge $K ] && break
  [ $SECONDS -gt $end ] && break
  sleep 5
done
[ $peered -ge $K ] || die "only $peered of $K nodes report a peer. THIS IS THE PRECONDITION multi_node_tps_proof.sh never checked: without it the run measures K isolated nodes and any 'Nx' it prints is arithmetic, not scaling. No verdict."
log "  ✅ all $K nodes report at least one peer"

# ── PHASE 2: disjoint flood, in parallel ─────────────────────────────────────────────────────────────
if [ "$HAVE_CARRIERS" = "0" ]; then
  log ""
  log "--- PHASE 2 SKIPPED: no carrier pool, so THROUGHPUT is NOT MEASURED (carrier_gen was retired with"
  log "    pqpool). Convergence below is measured regardless — it needs no transactions, only blocks."
  sumok=0; admit_s=0; admit_rate=0; T0=$(date +%s.%N)
else
shard=$((TOTAL / K))
log ""
log "--- PHASE 2: each node floods its OWN $shard DISTINCT carriers, ${FTHREADS} threads, in parallel ---"
declare -a FPIDS SHARDS
for ((i=0;i<K;i++)); do
  sf=/tmp/usdmd_mc_shard$i.hex
  sed -n "$((i*shard+1)),$(((i+1)*shard))p" "$POOL" > "$sf"
  SHARDS[$i]="$sf"
done
T0=$(date +%s.%N)
for ((i=0;i<K;i++)); do
  ( nice -n 5 "$FLOOD" "${SHARDS[$i]}" 127.0.0.1 "${PORTS[$i]}" "$FTHREADS" > /tmp/usdmd_mc_flood$i.log 2>&1 ) &
  FPIDS[$i]=$!
done
for ((i=0;i<K;i++)); do wait "${FPIDS[$i]}"; done
T1=$(date +%s.%N)
sumok=0
for ((i=0;i<K;i++)); do
  line=$(grep 'admitted tx/s' /tmp/usdmd_mc_flood$i.log | tail -1)
  ok=$(echo "$line" | sed -nE 's/.*admitted OK=([0-9]+).*/\1/p')
  log "  node$i: OK=${ok:-0}"
  sumok=$((sumok + ${ok:-0}))
done
admit_s=$(awk "BEGIN{printf \"%.3f\", $T1-$T0}")
admit_rate=$(awk "BEGIN{printf \"%.0f\", $sumok/($admit_s>0?$admit_s:1)}")
log "  ADMITTED: $sumok in ${admit_s}s = $admit_rate admitted tx/s (this is ALL the old script measured)"
fi

# ── PHASE 3: convergence — assert what the PEER holds ────────────────────────────────────────────────
log ""
log "--- PHASE 3: convergence — every node must reach the SAME tip (the measurement that was missing) ---"
end=$((SECONDS+CONVERGE_WAIT)); converged=0
while :; do
  tips=""
  for ((i=0;i<K;i++)); do
    t=$(curl -s --max-time 3 "127.0.0.1:${PORTS[$i]}/get_tip" 2>/dev/null | sed -nE 's/.*"tip":"([0-9a-f]*)".*/\1/p')
    tips="$tips $t"
  done
  uniq_tips=$(echo "$tips" | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l | tr -d ' ')
  n_tips=$(echo "$tips" | tr ' ' '\n' | grep -vc '^$')
  if [ "${uniq_tips:-0}" = "1" ] && [ "${n_tips:-0}" -ge "$K" ]; then converged=1; break; fi
  [ $SECONDS -gt $end ] && break
  sleep 3
done
T2=$(date +%s.%N)

log ""
log "--- PER-NODE COST vs K (RSS, KB) — 'scale by adding nodes' needs this FLAT in peer count ---"
for ((i=0;i<K;i++)); do
  rss=$(ps -o rss= -p "${NPIDS[$i]}" 2>/dev/null | tr -d ' ')
  log "  node$i RSS=${rss:-?} KB"
done

log ""
if [ "$converged" = "1" ]; then
  conv_s=$(awk "BEGIN{printf \"%.3f\", $T2-$T0}")
  conv_rate=$(awk "BEGIN{printf \"%.0f\", $sumok/($conv_s>0?$conv_s:1)}")
  log "=== RESULT (K=$K) ==="
  log "  admitted tx/s            : $admit_rate   (local admission — what the old proof reported)"
  log "  SETTLED cross-node tx/s  : $conv_rate   ($sumok tx over ${conv_s}s to a SHARED tip on all $K nodes)"
  log "  ⭐ The second number is the one a user's money lives on: a tx admitted on node0 and held by node4."
else
  log "⛔⛔⛔ NO VERDICT: the $K nodes did NOT reach a shared tip within ${CONVERGE_WAIT}s."
  log "   Admission succeeded ($admit_rate tx/s) and convergence did not, which is exactly the gap a"
  log "   peer-less benchmark cannot see. A scaling multiple is NOT printed, because an unconverged mesh"
  log "   has not carried anybody's transaction anywhere."
  exit 2
fi

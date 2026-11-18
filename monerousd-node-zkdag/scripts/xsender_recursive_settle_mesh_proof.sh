#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# ⭐⭐⭐ CROSS-SENDER WHIR-SHAPED RECURSIVE-VERIFY SETTLE — LIVE-MESH PROOF (task #144).
#
# Proves the WHIR-verifies-WHIR, N-independent-proof recursive verifier ON THE LIVE GREENFIELD MESH, run
# THROUGH the FULL-PARITY node binary (built with --features bench-routes — ALL features present,
# NO standalone-bin workaround). It boots K greenfield `usdmd-node serve` instances (each a first-class
# producer+verifier+prover on the real ZK-verify gate + onion transport), then curls each node's
# GET /xsender_recursive_settle: the LIVE NODE ITSELF recursively verifies N INDEPENDENT senders' inner spend
# proofs into ONE O(1) outer proof and returns {o1_carrier_constant, forged_rejected, settled_us_per_tx,sweep}.
# PASS iff EVERY live node reports O(1) carrier + forged-reject. Thermal-safe: high ports, surgical PID-only
# kills (never touches a node it did not start), niced.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE=$ROOT/target/release/usdmd-node
K=${1:-2}
BASEPORT=28300   # high ports: never collide with / kill a live node
OUT=/tmp/usdmd_xsender_mesh.txt
: > "$OUT"
log(){ echo "$@" | tee -a "$OUT"; }

log "=== CROSS-SENDER RECURSIVE-VERIFY SETTLE — LIVE-MESH PROOF (full-parity node) ==="
if [ ! -x "$NODE" ]; then log "[err] $NODE missing — build: cargo build --release --features bench-routes --bin usdmd-node"; exit 1; fi
# FULL-PARITY GATE = the LIVE endpoint, not `strings` (which does not surface the Rust match-arm route literal).
# A node built WITHOUT --features bench-routes answers `/xsender_recursive_settle` 404 (the shipped node never serves it)
# (o1_carrier_constant absent) → the per-node check below FAILS it, so a
# stripped binary can NEVER false-pass. The gate is enforced live, per node.

declare -a NPIDS PORTS
for ((i=0;i<K;i++)); do
  port=$((BASEPORT+i)); data=/tmp/usdmd_xs_n$i
  rm -rf "$data"; mkdir -p "$data"
  MONEROUSD_NODE_DATA="$data" MONEROUSD_RPC_PORT="$port" nice -n 10 "$NODE" serve >/tmp/usdmd_xs_n$i.log 2>&1 &
  NPIDS[$i]=$!; PORTS[$i]=$port
done
# wait for each node's RPC to come up
for ((i=0;i<K;i++)); do
  for ((t=0;t<40;t++)); do sleep 1; curl -s --max-time 2 "127.0.0.1:${PORTS[$i]}/get_height" >/dev/null 2>&1 && break; done
done
sleep 1

pass=1
for ((i=0;i<K;i++)); do
  log ""
  log "--- node$i (127.0.0.1:${PORTS[$i]}) performs the recursive verify ITSELF ---"
  resp=$(curl -s --max-time 120 "127.0.0.1:${PORTS[$i]}/xsender_recursive_settle")
  log "  $resp"
  o1=$(echo "$resp"     | sed -nE 's/.*"o1_carrier_constant":([a-z]+).*/\1/p')
  forged=$(echo "$resp" | sed -nE 's/.*"forged_rejected":([a-z]+).*/\1/p')
  if [ "$o1" = "true" ] && [ "$forged" = "true" ]; then
    log "  ✅ node$i: O(1) carrier CONSTANT + FORGED inner proof REJECTED — WHIR-verifies-WHIR settle sound on the live node."
  else
    log "  ❌ node$i: o1=$o1 forged_rejected=$forged (FAIL)"; pass=0
  fi
done

for ((i=0;i<K;i++)); do kill "${NPIDS[$i]}" 2>/dev/null; done
for ((i=0;i<K;i++)); do wait "${NPIDS[$i]}" 2>/dev/null; done

log ""
if [ "$pass" = "1" ]; then
  log "=== ✅ PASS — all $K live full-parity nodes recursively verified N independent senders into ONE O(1) proof, forged-reject, ALL features present. ==="
else
  log "=== ❌ FAIL — at least one live node did not report O(1)+forged-reject. ==="; exit 1
fi

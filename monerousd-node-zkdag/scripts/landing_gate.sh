#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# landing_gate.sh — THE ONE LANDING GATE (user 2026-09-28, usage rule 4). A change lands only on this: ONE full lib suite,
# with the real-node journeys spawning the daemon built from the SAME tree in the SAME target dir. No partial reruns.
#
#   usage: scripts/landing_gate.sh <lane-name> [pin filter ...]
#     <lane-name>   names the bus posts and the target dir (~/.cargo-targets/<lane-name>, reused, never minted per run)
#     pin filters   optional: run these first (fast); a red there stops before the heavy full suite
#
# Output: <out>/gate-<lane>-<time>.{build,node,pins,full}.log, plus one summary line per stage on stdout.
# Refuses below a 20 GiB free-disk floor (AGENTS.md §8.4). Announces START/DONE on the bus (§8.3 one heavy job).
set -uo pipefail
LANE="${1:?usage: landing_gate.sh <lane-name> [pin filter ...]}"; shift
REAL="$(cd "$(dirname "$0")/.." && pwd)"
TD="$HOME/.cargo-targets/$LANE"
OUT="${GATE_OUT_DIR:-$HOME/.cargo-targets/gate-logs}"
mkdir -p "$OUT"
T="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT/gate-$LANE-$T"
SEND="$HOME/.claude/hooks/agent-send.sh"

avail=$(df -g / | tail -1 | awk '{print $4}')
if [ "$avail" -lt 20 ]; then echo "[gate] ⛔ REFUSED: ${avail} GiB free, below the 20 GiB floor"; exit 2; fi

echo "[gate] build START $(date +%H:%M:%S) lane=$LANE target=$TD"
( cd "$REAL" && CARGO_TARGET_DIR="$TD" nice -n 10 cargo test --release --lib --no-run -j 5 > "$LOG.build.log" 2>&1 ) \
  || { echo "[gate] test build FAILED"; grep -aE "^error" -A12 "$LOG.build.log" | head -40; exit 1; }
( cd "$REAL" && CARGO_TARGET_DIR="$TD" nice -n 10 cargo build --release --bin usdmd-node -j 5 > "$LOG.node.log" 2>&1 ) \
  || { echo "[gate] daemon build FAILED"; grep -aE "^error" -A12 "$LOG.node.log" | head -40; exit 1; }
TB="$(grep -aoE '\(/[^)]*usdmd_node-[0-9a-f]+\)' "$LOG.build.log" | tail -1 | tr -d '()')"
NODE="$TD/release/usdmd-node"
echo "[gate] build DONE $(date +%H:%M:%S) testbin $(shasum -a 256 "$TB" | cut -c1-8) daemon $(shasum -a 256 "$NODE" | cut -c1-8)"

if [ "$#" -gt 0 ]; then
  ( cd "$REAL" && MONEROUSD_JOURNEY_NODE_BIN="$NODE" "$TB" "$@" --test-threads=4 > "$LOG.pins.log" 2>&1 )
  echo "[gate] pins: $(grep -a 'test result' "$LOG.pins.log" | tail -1)"
  grep -aE "^test .*FAILED$" "$LOG.pins.log" | head -30
  grep -aq "test result: ok" "$LOG.pins.log" || { echo "[gate] pins RED — the full suite is not run"; exit 1; }
fi

[ -x "$SEND" ] && "$SEND" "$LANE" "all" "[gate] FULL lib suite START $(date +%H:%M:%S) (HEAVY; daemon $(shasum -a 256 "$NODE" | cut -c1-8)). Ask before another heavy job."
# GATE_FULL_THREADS (default 4): MEASURED 2026-09-28 the full suite was SIGKILLed by memory pressure at 4 threads (each
# synchronous DSYNC bundle build proves a certificate step of GBs, DB-360 §8), so a memory-tight run passes 2.
( cd "$REAL" && MONEROUSD_JOURNEY_NODE_BIN="$NODE" "$TB" --test-threads="${GATE_FULL_THREADS:-4}" > "$LOG.full.log" 2>&1 )
RES="$(grep -a 'test result' "$LOG.full.log" | tail -1)"
echo "[gate] FULL: $RES"
grep -aE "^test .*FAILED$" "$LOG.full.log" | head -60
[ -x "$SEND" ] && "$SEND" "$LANE" "all" "[gate] FULL lib suite DONE $(date +%H:%M:%S): ${RES:0:120}"
echo "[gate] logs: $LOG.*"
grep -aq "test result: ok" "$LOG.full.log"

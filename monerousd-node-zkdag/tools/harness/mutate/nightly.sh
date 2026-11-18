#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# LANE M NIGHTLY - run the mutation engine over every configured target, one at a time.
#
# WHY THIS IS CHEAP ENOUGH TO RUN EVERY NIGHT: the engine mutates only CHECK-BEARING lines and runs
# only the pins that CLAIM the mutated site, so the cost is (mutants selected) x (one incremental
# rebuild + one small pin subset). The clone and the build directory are both reused across nights,
# so only the mutated crate recompiles. Nothing here scales with chain height, note count, record
# count or peer count.
#
# WHAT IT NEVER DOES: touch the live tree. The engine works in an isolated clone and hashes the live
# tree before and after; this script propagates a non-zero exit if that check ever says otherwise.
#
# The engine's own load gate holds each target until the machine is quiet, because a measurement
# taken under load is void.
#
# Usage:  tools/harness/mutate/nightly.sh [target ...]      (default: every target in targets.json)

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${LANE_M_OUT:-$HOME/.cargo-targets/harness/nightly}"
mkdir -p "$OUT"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  # shellcheck disable=SC2207
  TARGETS=($(python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["targets"])))' "$HERE/targets.json"))
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="$OUT/summary-$STAMP.txt"
worst=0

for t in "${TARGETS[@]}"; do
  log="$OUT/$t-$STAMP.log"
  echo "=== target $t -> $log" | tee -a "$SUMMARY"
  python3 -u "$HERE/mutate.py" run --target "$t" --verify-survivors > "$log" 2>&1
  rc=$?
  [ $rc -gt $worst ] && worst=$rc
  grep -E "MUTATION SCORE|score=|SURVIVING MUTANTS|LIVE TREE UNTOUCHED|INCOMPLETE" "$log" >> "$SUMMARY"
  echo "    exit=$rc" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "summary: $SUMMARY"
cat "$SUMMARY"
exit $worst

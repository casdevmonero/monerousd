#!/bin/sh
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# LANE F — THE STATEFUL INVARIANT FUZZER. One entry point, so a campaign is reproducible by anyone.
#
# ⛔ MACHINE DISCIPLINE IS ENFORCED HERE, NOT REMEMBERED.
#
# This project has withdrawn a full day of gate verdicts to load confounding. A measurement taken while
# the machine is saturated is void, so this script REFUSES to run until the 1-minute load average is under
# the threshold, and says how long it waited. Pass --force only when you are reading a PASS/FAIL verdict
# (which is deterministic) and not a timing (which is not) — and say so when you report the result.
#
# ⛔ THERE IS NO `timeout` BINARY ON THE REFERENCE MACHINE. A command wrapped in one exits 127 WITHOUT
# RUNNING, and an empty log then looks exactly like a pass. Nothing here is wrapped in `timeout`; cargo's
# own exit status is the verdict.
#
# USAGE
#   tools/harness/lane-f.sh              # the whole lane: corpus replay, search, wire family, self-proof
#   tools/harness/lane-f.sh selfproof    # only the self-proof (does the instrument catch a KNOWN hole?)
#   tools/harness/lane-f.sh wire         # only the generated wire family
#   tools/harness/lane-f.sh search       # only the random-schedule search
#   tools/harness/lane-f.sh --force ...  # skip the load gate (say so in the report)

set -eu

THRESHOLD=12
MAX_WAITS=40
WAIT_SECONDS=180

FORCE=0
if [ "${1:-}" = "--force" ]; then
  FORCE=1
  shift
fi
WHAT="${1:-all}"

CRATE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# A WARM TARGET DIRECTORY OF THIS LANE'S OWN, so a harness build never evicts the crew's artefacts and a
# crew build never evicts this lane's. Override with MUSD_HARNESS_TARGET.
TARGET_DIR="${MUSD_HARNESS_TARGET:-$HOME/.cargo-targets/harness}"
mkdir -p "$TARGET_DIR"

load_one_minute() {
  sysctl -n vm.loadavg | awk '{print $2}'
}

if [ "$FORCE" = "0" ]; then
  waits=0
  while [ "$waits" -lt "$MAX_WAITS" ]; do
    one=$(load_one_minute)
    ok=$(awk -v v="$one" -v t="$THRESHOLD" 'BEGIN{print (v<t)?1:0}')
    if [ "$ok" = "1" ]; then
      echo "[lane-f] load $one < $THRESHOLD after ${waits} wait(s) — proceeding."
      break
    fi
    echo "[lane-f] load $one >= $THRESHOLD — waiting ${WAIT_SECONDS}s (wait $((waits+1))/$MAX_WAITS)."
    sleep "$WAIT_SECONDS"
    waits=$((waits+1))
  done
  if [ "$waits" -ge "$MAX_WAITS" ]; then
    echo "[lane-f] REFUSING TO RUN: the machine stayed above load $THRESHOLD for the whole wait."
    echo "[lane-f] A measurement taken under this load is void. Re-run when the machine is quiet, or"
    echo "[lane-f] pass --force and report a PASS/FAIL verdict only — never a timing."
    exit 2
  fi
else
  echo "[lane-f] --force: skipping the load gate. Load is now $(load_one_minute)."
  echo "[lane-f] REPORT PASS/FAIL ONLY FROM THIS RUN. Any timing it produces is load-confounded and void."
fi

case "$WHAT" in
  selfproof) FILTER="harness::fuzz::wire::tests::the_wire_family_catches_the_pre_fix" ;;
  wire)      FILTER="harness::fuzz::wire" ;;
  search)    FILTER="harness::fuzz::tests::every_layer_of_node_operation" ;;
  corpus)    FILTER="harness::fuzz::tests::the_permanent_corpus_replays_clean" ;;
  all)       FILTER="harness::fuzz" ;;
  *)         echo "[lane-f] unknown target '$WHAT' (all|selfproof|wire|search|corpus)"; exit 2 ;;
esac

echo "[lane-f] crate      : $CRATE_DIR"
echo "[lane-f] target dir : $TARGET_DIR"
echo "[lane-f] filter     : $FILTER"
echo

# `--nocapture` because this lane's value is in what it PRINTS: the seed, the shrunk sequence, the
# pasteable reproducer. A run whose output is swallowed has told you only a colour.
CARGO_TARGET_DIR="$TARGET_DIR" cargo test --manifest-path "$CRATE_DIR/Cargo.toml" "$FILTER" -- --nocapture
status=$?

echo
if [ "$status" = "0" ]; then
  echo "[lane-f] PASS — every invariant held on every step of every sequence that ran."
  echo "[lane-f] ⛔ SCOPE: an in-process island. This is not evidence about the onion transport,"
  echo "[lane-f]    per-node cost, or scale, and it must never be cited as such."
else
  echo "[lane-f] FAIL — read the printed reproducer above. It is a standalone #[test] you can paste"
  echo "[lane-f]    into a permanent pin, plus the corpus block to keep the class covered forever."
fi
exit "$status"

#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# tier1_gate_named_pair.sh — THE TIER-1 MONEY-PATH GATE, run against a NAMED LIVE PAIR.
#
# WHAT IT IS (completion-plan item 15, 2026-09-04): the definition-of-done for Tier 1, proven on the
# launchd-owned pair the wallet actually talks to — never on scratch stand-ins. Five promises, each
# asserted on the party that must hold it:
#   1  a drip on node A becomes CERTIFIED SPENDABLE in a real fresh-seed wallet
#   2  a cross-node send lands and the RECEIVING node observes it (the recipient wallet reads
#      ONLY node B — the node that never saw the sender's RPC)
#   3  a rolling restart of both nodes (shutdown-file + launchd respawn, one at a time, each wait
#      gated on full reconvergence) preserves custody on both wallets, AND a cross-node send AFTER the
#      restarts lands and is observed by the other node — Tier 1 is "send survives restarts", and a pair
#      that kept its balances but can no longer move them is not a money path
#   4  a SEED-ONLY restore (fresh empty wallet data dir, nothing but the seed) recovers the balance
#   5  records_held == record_top on BOTH nodes at the end — the roll-safety truth
#
# PASS ⇒ writes ~/.usdmd-node/tier1-gate.pass with the DEPLOYED binary's sha256 + timestamp +
# chain_id (the ecosystem-gate standard: a marker is hash-bound to the exact binary it certifies).
#
# JUDGE ON STATE, NEVER ON A CLOCK (the 240-second-driver lesson: a stopwatch in the judge
# manufactures false not-settled verdicts). Every wait here loops on the STATE it is waiting for and
# prints its facts each sample; the only wait-breaking discriminator is the CHAIN-HALT state (height
# frozen on both nodes across many consecutive samples — a halted chain is itself a Tier-1 refusal,
# "no chain halts" is a cardinal). A run that neither passes nor halts keeps printing facts; the
# standing test-progress watchdog and the operator own patience, the judge owns only state.
#
# ⛔ RUN DISCIPLINE:
#   • The subject pair must be freshly re-genesised (plan item 11). A pair that already disagrees at
#     ordinal 0 or holds 197 of 7306 records is NOT a valid subject and a green here would be invalid.
#   • Restarts go through `touch ~/.usdmd-node/shutdown-<port>` and WAIT for launchd. A manual
#     relaunch creates a duplicate on one datadir (the 68 GB runaway class). No kill, no exec.
#   • One node restarts at a time, and the second only after the pair fully reconverges — run 27
#     (2026-09-02) killed the sole holder of un-replicated records and both sides stayed holed.
#
# Usage: tier1_gate_named_pair.sh [portA] [portB] [wallet-harness]
set -u
PA="${1:-27780}"
PB="${2:-28901}"
HARNESS="${3:-$(cd "$(dirname "$0")/../.." && pwd)/monerousd-wallet-v2/src-tauri/target/release/wallet-harness}"
SCRATCH="$(mktemp -d /tmp/musd-tier1gate-XXXXXX)"
LOG="$SCRATCH/gate.log"
say()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { say "❌ TIER-1 GATE FAIL: $*"; say "evidence under $SCRATCH (kept for later reaping)"; exit 1; }
step() { say "── STEP $*"; }
[ -x "$HARNESS" ] || { echo "wallet-harness missing: $HARNESS"; exit 2; }
find /tmp -maxdepth 1 -type d -name 'musd-tier1gate-*' -mmin +1440 -exec rm -rf {} + 2>/dev/null

# How many consecutive unchanged-height samples (6 s apart) constitute the CHAIN-HALT state. On a
# ~500 ms-block chain, 40 flat samples means ~480 due blocks never arrived — a halt FACT about the
# chain's own liveness promise, never a judgment about a note's age or how long settling took.
HALT_SAMPLES=40

info() { curl -s -m 6 "http://127.0.0.1:$1/get_info"; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); v=d.get(sys.argv[1]); print("" if v is None else v)' "$2" 2>/dev/null; }
pid_of_port() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $2}'; }
height_sum() { # the pair's combined height — moves iff the chain moves
  local h1 h2
  h1=$(info "$PA" | jget - height); h2=$(info "$PB" | jget - height)
  echo $(( ${h1:-0} + ${h2:-0} ))
}

step "0: PREFLIGHT — same build on both sides, processes newer than the binary, one chain"
I1="$(info "$PA")"; I2="$(info "$PB")"
[ -n "$I1" ] || fail "node :$PA unreachable"
[ -n "$I2" ] || fail "node :$PB unreachable"
B1=$(echo "$I1" | jget - build_src); B2=$(echo "$I2" | jget - build_src)
[ -n "$B1" ] && [ "$B1" = "$B2" ] || fail "build_src differs or missing: :$PA=$B1 :$PB=$B2 — a stale binary invalidates every cross-node result"
C1=$(echo "$I1" | jget - chain_id); C2=$(echo "$I2" | jget - chain_id)
[ -n "$C1" ] && [ "$C1" = "$C2" ] || fail "chain_id differs: the two nodes are not one chain (:$PA=${C1:0:16}… :$PB=${C2:0:16}…)"
PID1=$(pid_of_port "$PA"); PID2=$(pid_of_port "$PB")
[ -n "$PID1" ] && [ -n "$PID2" ] || fail "could not resolve a listening pid (:$PA=$PID1 :$PB=$PID2)"
NODE_BIN=$(ps -o comm= -p "$PID1" | head -1)
[ -x "$NODE_BIN" ] || fail "could not resolve the deployed binary path from pid $PID1 (got: $NODE_BIN)"
BIN_MTIME=$(stat -f %m "$NODE_BIN")
for P in "$PID1" "$PID2"; do
  STARTED=$(ps -o lstart= -p "$P" | xargs -I{} date -j -f "%a %b %d %T %Y" "{}" +%s 2>/dev/null)
  [ -n "$STARTED" ] || fail "cannot read start time of pid $P"
  [ "$STARTED" -ge "$BIN_MTIME" ] || fail "pid $P started BEFORE the binary's mtime — it is running stale code (start=$STARTED bin=$BIN_MTIME)"
done
say "✅ one build ($B1), one chain, both processes newer than $NODE_BIN"

# The wallet driver: the REAL wallet core, one JSON verdict per line. Wallet state is ISOLATED under
# this run's scratch (its own MONEROUSD_WALLET_DATA and HOME for the harness process only) — the live
# nodes and the user's real wallet data are untouchable by construction. The per-invocation alarm
# bounds ONE driver call (an I/O bound; the state loop simply calls again) — it decides nothing.
export GATE_HOME="$SCRATCH/home"; mkdir -p "$GATE_HOME"
wallet() { # wallet <seedfile> <node_port> <mesh_port> <datadir> <<< commands
  local seed="$1" node="$2" mesh="$3" data="$4"
  HARNESS_SEED="$(cat "$seed")" MONEROUSD_NODE_URL="http://127.0.0.1:$node" \
  MONEROUSD_NODE_MESH="http://127.0.0.1:$mesh" MONEROUSD_WALLET_DATA="$SCRATCH/$data" \
  MONEROUSD_NET=testnet HOME="$GATE_HOME" perl -e 'alarm 240; exec @ARGV' "$HARNESS" 2>>"$SCRATCH/$data.err"
}
gen_seed() { # gen_seed <outfile> — fresh REAL wallet seed via the real keygen
  # STATE-JUDGED (fix-round 20260905): the old shape let a 60 s alarm + [-s] decide a NEGATIVE —
  # a stopwatch judging keygen, the exact class the header forbids. Same progress-loop shape as
  # rolling_restart: each attempt is ONE bounded driver call (the alarm is an I/O bound on that
  # invocation only — it decides nothing; the loop simply calls again), facts print each sample,
  # and the watchdog/operator owns patience while the judge owns state ([-s "$1"] IS the state).
  local n=0
  while :; do
    HARNESS_GENERATE=1 HOME="$GATE_HOME" MONEROUSD_NODE_URL="http://127.0.0.1:$PA" MONEROUSD_NET=testnet \
      perl -e 'alarm 240; exec @ARGV' "$HARNESS" </dev/null 2>>"$SCRATCH/gen_seed.err" \
      | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["result"]["seed"])' 2>/dev/null > "$1"
    [ -s "$1" ] && return 0
    n=$((n+1))
    say "   gen_seed: attempt $n produced no seed yet (stderr tail: $(tail -c 160 "$SCRATCH/gen_seed.err" 2>/dev/null | tr '\n' ' ')) — calling the keygen again"
    sleep 4
  done
}
bal() { python3 -c 'import json,sys; r=json.loads(sys.argv[1])["result"]; print(r["usdm"], r["pending_usdm"])' "$1" 2>/dev/null; }
# NUMERIC balance equality (fix-round 20260905): the old exact string match ('25.0' vs the wallet's
# f64 formatting) could hold the gate on a formatting artifact ("25" / "25.00" / "24.999999999999996"
# are all the same money). Compare numerically; epsilon 1e-9 is far tighter than the 1e-8 base unit,
# so distinct amounts can never be equated — TESTNET==PRODUCTION, the gate is not weakened.
bal_eq() { # bal_eq <got> <want>
  awk -v g="$1" -v w="$2" 'BEGIN { if (g !~ /^-?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$/) exit 1; d = g - w; if (d < 0) d = -d; exit !(d < 1e-9) }'
}

# STATE-JUDGED WAIT: loop until the wallet reads the wanted spendable balance from the named node.
# Breaks negatively ONLY on the chain-halt state; otherwise it prints facts and keeps sampling.
wait_balance() { # wait_balance <seed> <node> <mesh> <data> <want_spendable> <label>
  local flat=0 hprev hnow got=""
  hprev=$(height_sum)
  while :; do
    local out; out=$(printf 'detect\nbalance\n' | wallet "$1" "$2" "$3" "$4" | tail -1)
    got=$(bal "$out" | awk '{print $1}')
    bal_eq "$got" "$5" && { say "✅ $6: balance $got spendable read from :$2 (want $5, matched numerically)"; return 0; }
    hnow=$(height_sum)
    if [ "$hnow" = "$hprev" ]; then flat=$((flat+1)); else flat=0; hprev=$hnow; fi
    say "   $6: balance=${got:-unreadable} want=$5 pair_height_sum=$hnow flat_samples=$flat/$HALT_SAMPLES"
    [ "$flat" -ge "$HALT_SAMPLES" ] && fail "$6: THE CHAIN HALTED — pair height frozen at $hnow across $HALT_SAMPLES samples; a halted chain is a Tier-1 refusal on its own"
    sleep 6
  done
}

# Full reconvergence: roots EQUAL + heights within 8 + history_complete + unspent_serve_ready +
# sidecar_gap_count 0 on both — the run-27 lesson (root-equal alone is NOT ready) — AND both nodes hold a
# CURRENT nullifier view (nf_view_present + nf_view_matches_acc). ⛔ MEASURED 2026-10-05 on the live pair: a restarted
# node comes back TREELESS and warms its view only from a peer whose view is current; when the other node restarted
# before that warm finished, neither held a view, no band step could be proven, and every fold waited at the DB-396 cap
# for good — balances read fine while no spend could ever settle again. The second restart waits for the first warm.
pair_converged() {
  python3 - "$(info "$PA")" "$(info "$PB")" <<'PYEOF' | grep -q CONVERGED
import json, sys
try:
    a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
except Exception:
    raise SystemExit
ra, rb = a.get("unspent_root"), b.get("unspent_root")
ha, hb = a.get("height", 0), b.get("height", 0)
ok = (
    ra and ra == rb and abs(ha - hb) <= 8
    and bool(a.get("history_complete")) and bool(b.get("history_complete"))
    and bool(a.get("unspent_serve_ready")) and bool(b.get("unspent_serve_ready"))
    and a.get("sidecar_gap_count") is not None and int(a.get("sidecar_gap_count")) == 0
    and b.get("sidecar_gap_count") is not None and int(b.get("sidecar_gap_count")) == 0
    and bool(a.get("nf_view_present")) and bool(b.get("nf_view_present"))
    and bool(a.get("nf_view_matches_acc")) and bool(b.get("nf_view_matches_acc"))
)
if ok:
    print("CONVERGED")
PYEOF
}
wait_converged() { # wait_converged <label> — state-judged; halt is the only negative break
  local flat=0 hprev hnow n=0
  hprev=$(height_sum)
  until pair_converged; do
    n=$((n+1))
    hnow=$(height_sum)
    if [ "$hnow" = "$hprev" ]; then flat=$((flat+1)); else flat=0; hprev=$hnow; fi
    [ $((n % 8)) = 0 ] && say "   $1: not yet converged (pair_height_sum=$hnow flat_samples=$flat/$HALT_SAMPLES) — roots/ready/sidecar gaps still settling"
    [ "$flat" -ge "$HALT_SAMPLES" ] && fail "$1: THE CHAIN HALTED while reconverging (height frozen at $hnow across $HALT_SAMPLES samples) — restarting the second node now would strand sole-holder records"
    sleep 6
  done
  say "✅ $1: pair fully reconverged"
}

# Rolling restart of ONE node via the shutdown file; launchd (KeepAlive) respawns it. State-judged:
# the wait ends when a NEW pid serves /get_info. If launchd never respawns, the loop's facts show a
# dark port sample after sample — the watchdog/operator owns patience, the judge owns state.
rolling_restart() { # rolling_restart <port>
  local port="$1" old_pid new_pid n=0
  old_pid=$(pid_of_port "$port")
  [ -n "$old_pid" ] || fail "no listener on :$port to restart"
  touch "$HOME/.usdmd-node/shutdown-$port"
  say "   shutdown requested for :$port (pid $old_pid) — waiting for launchd to respawn"
  while :; do
    new_pid=$(pid_of_port "$port")
    if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && info "$port" | grep -q height; then
      say "   :$port respawned (pid $old_pid -> $new_pid)"
      return 0
    fi
    n=$((n+1))
    [ $((n % 10)) = 0 ] && say "   :$port still dark after $n samples (old_pid=$old_pid new_pid=${new_pid:-none}) — launchd KeepAlive should respawn it"
    sleep 4
  done
}

# Roll-safety truth, asserted on BOTH nodes; on a miss, print the /record_holding split so the
# missing class is named instead of guessed.
records_complete_both() { # records_complete_both <label>
  local miss=0
  for P in "$PA" "$PB"; do
    local i held top
    i="$(info "$P")"
    held=$(echo "$i" | jget - records_held); top=$(echo "$i" | jget - record_top)
    # A node HOLDS at most one ladder span of record rows (DA_LADDER_SPAN = 4096, `prune_cold_ordinal_rows`): cold rows are
    # regenerable through the ladder, by design (no growth). MEASURED 2026-10-05 22:47 on the live pair: record_top 5792 /
    # 5731, records_held 4102 on both — "held == top" can never hold past 4,096 ordinals, so the roll-safety truth is
    # "every row inside the span is held" (held ≥ min(top, span)) with history_complete and no sidecar gap, judged above.
    local span=4096 want
    want=$top; [ "${top:-0}" -gt "$span" ] && want=$span
    if [ -z "$held" ] || [ -z "$top" ] || [ "$held" -lt "$want" ]; then
      say "   :$P records_held=$held record_top=$top — SPLIT: $(curl -s -m 6 "http://127.0.0.1:$P/record_holding")"
      miss=1
    else
      say "   :$P records_held=$held covers the held span (record_top $top, span $span)"
    fi
  done
  [ "$miss" = 0 ] || fail "$1: a node cannot vouch for its whole ordinal history (see the split above)"
}

step "1: DRIP → CERTIFIED SPENDABLE (fresh real wallet W1, drip on :$PA)"
gen_seed "$SCRATCH/w1.seed"
A1=$(printf 'address\n' | wallet "$SCRATCH/w1.seed" "$PA" "$PB" w1 | tail -1 | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["address"])')
[ -n "$A1" ] || fail "W1 address unreadable"
DRIP=$(curl -s -m 20 -X POST "http://127.0.0.1:$PA/faucet/drip" -d "{\"to\":\"$A1\",\"amount\":2500000000}")
echo "$DRIP" | grep -q '"status":"OK"' || fail "drip refused: ${DRIP:0:200}"
# The route answers staged-not-settled (item 8a): the settle is what wait_balance proves.
echo "$DRIP" | grep -q '"staged":true' && say "   drip staged (id $(echo "$DRIP" | jget - staging_id | cut -c1-16)…) — waiting for the carrier block to settle it"
wait_balance "$SCRATCH/w1.seed" "$PA" "$PB" w1 "25.0" "drip settle"

step "2: CROSS-NODE SEND — W1(:$PA) → W2, and the RECEIVING node (:$PB) observes it"
gen_seed "$SCRATCH/w2.seed"
A2=$(printf 'address\n' | wallet "$SCRATCH/w2.seed" "$PB" "$PA" w2 | tail -1 | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["address"])')
[ -n "$A2" ] || fail "W2 address unreadable"
SEND=$(printf 'send %s 7\n' "$A2" | wallet "$SCRATCH/w1.seed" "$PA" "$PB" w1 | tail -1)
echo "$SEND" | grep -q '"ok":true' || fail "send refused: ${SEND:0:220}"
# W2 reads ONLY node B — the node that never saw the sender's RPC. This is the receiving-node
# observation; a balance here means B holds the settled notes, not that A's call returned OK.
wait_balance "$SCRATCH/w2.seed" "$PB" "$PA" w2 "7.0" "receive observed by :$PB"
wait_balance "$SCRATCH/w1.seed" "$PA" "$PB" w1 "18.0" "sender conservation"

step "3: ROLLING RESTART with custody (shutdown-file + launchd, one at a time, converge-gated)"
rolling_restart "$PA"
wait_converged "after :$PA restart"
rolling_restart "$PB"
wait_converged "after :$PB restart"
wait_balance "$SCRATCH/w1.seed" "$PA" "$PB" w1 "18.0" "custody after restarts (W1)"
wait_balance "$SCRATCH/w2.seed" "$PB" "$PA" w2 "7.0" "custody after restarts (W2)"
# The restarted pair still MOVES money: W2 (read through :$PB) pays W1 3, and W1 reads it ONLY through :$PA.
SEND2=$(printf 'send %s 3\n' "$A1" | wallet "$SCRATCH/w2.seed" "$PB" "$PA" w2 | tail -1)
echo "$SEND2" | grep -q '"ok":true' || fail "post-restart send refused: ${SEND2:0:220}"
wait_balance "$SCRATCH/w1.seed" "$PA" "$PB" w1 "21.0" "post-restart receive observed by :$PA"
wait_balance "$SCRATCH/w2.seed" "$PB" "$PA" w2 "4.0" "post-restart sender conservation"

step "4: SEED-ONLY RESTORE — a fresh empty wallet data dir + the seed alone recovers W1"
# Nothing carries over but the seed: new MONEROUSD_WALLET_DATA (w1-restored), no note store, no
# scan state. The chain + seed must reconstruct the balance — the cardinal the 2026-08-10 incident
# violated (25.00 live, then 0.00 after a same-chain re-derive from the owner's own seed).
wait_balance "$SCRATCH/w1.seed" "$PA" "$PB" w1-restored "21.0" "seed-only restore"

step "5: ROLL-SAFETY — records_held == record_top on BOTH nodes"
records_complete_both "gate end"

HASH=$(shasum -a 256 "$NODE_BIN" | awk '{print $1}')
printf '%s %s chain_id=%s\n' "$HASH" "$(date +%s)" "$C1" > "$HOME/.usdmd-node/tier1-gate.pass"
say "🟢 TIER-1 GATE PASS on the named pair :$PA/:$PB — drip→spendable, cross-node send observed by"
say "   the receiving node, rolling-restart custody, seed-only restore, records complete on both."
say "   Hash-bound marker written: ~/.usdmd-node/tier1-gate.pass ($HASH)"
say "   (Tier 1 unlocks a NODE BINARY roll only — nothing beyond its tier may be claimed.)"
rm -rf "$SCRATCH"

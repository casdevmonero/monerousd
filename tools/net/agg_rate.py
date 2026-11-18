#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
"""THE LEVEL AGGREGATE ON REAL NODES (lane agg, docs/LEVEL-AGGREGATE-SPEC-20261115.md §6 / R6): settled payments a second at
this rig's node count, split by carriage (AGGREGATED: held by the node a payment was pushed to and laid as cores + an
openings table; FULL: announced and carried whole, as today). Run it once per size on ONE binary, each on a fresh rig:

    NET_NODES=2 NET_LANE=agg NET_THREADS=2 python3 agg_rate.py run 12
    NET_NODES=4 NET_LANE=agg NET_THREADS=2 python3 agg_rate.py run 12
    python3 agg_rate.py compare            # reads the two rows above

`run P`: P payers in all, spread over the rig's nodes round-robin — the SAME offered load at every size, so the node count
is the only thing that changes (on one machine more payers would also mean more wallet proving on the same cores) — funded
first, then all send one payment at once to one receiver on the last node; the window is from the first send to the receiver holding
every payment as spendable. Counted from each node's OWN log since the mark: `[agg] held a pushed payment` (a payment
taken for aggregation) and `[agg] proved … over N payment(s)` (laid in an openings table). Nothing is inferred from timing.
`compare`: PASS when the aggregated rate at the larger node count exceeds the smaller's by more than both runs' spread
(the spread is the run's own: its slowest payment's settle time over its fastest's), the total is not below the smaller
run's, and both runs settled every payment (which `run` asserts: every payment reached the receiver).
PASS_ALONE: a throughput measurement — a neighbour's load changes the number (charter §5).
"""
PASS_ALONE = "measures throughput: a neighbour's load would change the number"
import json, os, re, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from net import post, record, data, PORTS  # noqa: E402
from pay_lib import Wallet, wait_spendable, fail  # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agg_rate_results.jsonl")
HELD = re.compile(rb"\[agg\] held a pushed payment")
PROVED = re.compile(rb"\[agg\] proved (\d+) openings table\(s\) over (\d+) payment\(s\): (\d+) rows in (\d+) ms")
# milestone 2 (the tree, src/node_runtime.rs): one root a block over its held payments
ROOT = re.compile(rb"\[agg\] proved one root over (\d+) payment\(s\) in (\d+) ms")


def counts_since(marks):
    held, laid, tables, rows, ms = 0, 0, 0, 0, 0
    for i in range(len(PORTS)):
        with open(f"{data(i)}/node.log", "rb") as f:
            f.seek(marks[i])
            for line in f:
                if HELD.search(line):
                    held += 1
                m = PROVED.search(line)
                if m:
                    tables += int(m.group(1))
                    laid += int(m.group(2))
                    rows += int(m.group(3))
                    ms += int(m.group(4))
                m = ROOT.search(line)
                if m:
                    tables += 1
                    laid += int(m.group(1))
                    ms += int(m.group(2))
    return held, laid, tables, rows, ms


def run(total):
    n = len(PORTS)
    payers = [Wallet(f"agg{i}", i % n) for i in range(total)]
    to = Wallet("agg_to", n - 1)
    to.spendable(); to.close()
    t = time.time()
    for w in payers:
        post(0, "/faucet/drip", json.dumps({"amount": 300_000_000, "to": w.address}))
        w.spendable(); w.close()
    for w in payers:
        wait_spendable(w, 300_000_000, "agg-rate")
        w.close()
    print(f"[agg-rate] {len(payers)} payers on {n} nodes funded in {time.time() - t:.0f} s", flush=True)
    marks = [os.path.getsize(f"{data(i)}/node.log") for i in range(n)]
    t0 = time.time()
    sent, failed = [], []

    def go(w):
        try:
            w.send(to.address, "1.0", "agg-rate")
            w.close()
            sent.append(time.time() - t0)
        except BaseException as e:  # a sender that fails fails the check, never just its thread
            failed.append((w.role, repr(e)[:200]))

    ts = [threading.Thread(target=go, args=(w,)) for w in payers]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    if failed:
        fail("agg-rate", f"{len(failed)} of {len(payers)} senders did not send: {failed[:3]}")
    wait_spendable(to, len(payers) * 100_000_000, "agg-rate")
    dt = time.time() - t0
    held, laid, tables, rows, ms = counts_since(marks)
    total = len(payers) / dt
    agg = laid / dt
    row = {
        "at": time.strftime("%FT%T"), "nodes": n, "payers": len(payers), "window_s": round(dt, 1),
        "settled_per_s": round(total, 4), "aggregated_laid": laid, "aggregated_per_s": round(agg, 4), "held": held,
        "tables": tables, "table_rows": rows, "table_ms": ms, "submit_spread_s": round(max(sent) - min(sent), 1),
        "threads": os.environ.get("NET_THREADS", ""), "binary": os.environ.get("NET_NODE_BIN", ""),
    }
    with open(RESULTS, "a") as f:
        f.write(json.dumps(row) + "\n")
    detail = (f"{n} nodes: {len(payers)} payments settled in {dt:.0f} s = {total:.3f}/s; {laid} laid aggregated "
              f"({agg:.3f}/s, {held} held, {tables} table(s), {rows} rows in {ms} ms), the rest full")
    print(f"[agg-rate] {detail}", flush=True)
    record(f"agg-rate-n{n}", "PASS", detail)


def compare():
    rows = [json.loads(l) for l in open(RESULTS)] if os.path.exists(RESULTS) else []
    by_n = {}
    for r in rows:
        by_n[r["nodes"]] = r  # the latest run at each size
    if len(by_n) < 2:
        print("[agg-rate] compare needs runs at two node counts", flush=True)
        sys.exit(2)
    small, large = by_n[min(by_n)], by_n[max(by_n)]
    if small["binary"] != large["binary"]:
        record("agg-rate", "FAIL", f"the two runs used different binaries: {small['binary']} vs {large['binary']}")
        sys.exit(1)
    spread = max(small["submit_spread_s"] / max(small["window_s"], 1), large["submit_spread_s"] / max(large["window_s"], 1))
    rises = large["aggregated_per_s"] > small["aggregated_per_s"] * (1 + spread) and large["aggregated_laid"] > small["aggregated_laid"]
    not_below = large["settled_per_s"] >= small["settled_per_s"]
    verdict = "PASS" if rises and not_below else "FAIL"
    detail = (f"aggregated {small['aggregated_per_s']:.3f}/s at {small['nodes']} nodes → {large['aggregated_per_s']:.3f}/s at "
              f"{large['nodes']} (spread {spread:.0%}); settled {small['settled_per_s']:.3f} → {large['settled_per_s']:.3f}/s; "
              f"{small['threads'] or '?'} proving threads a node; binary {os.path.basename(large['binary'] or '?')}")
    print(f"[agg-rate] {verdict}: {detail}", flush=True)
    record("agg-rate", verdict, detail)
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "compare":
        compare()
    else:
        run(int(sys.argv[2]) if len(sys.argv) > 2 else 12)

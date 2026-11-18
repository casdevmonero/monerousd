#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
"""THE BUNDLE RELAY by ARITHMETIC (lane speed5 with lane agg, 2026-11-16; no build, no node, milliseconds).

The question (user 2026-11-16): why does settled throughput not rise as nodes join, and what design makes it rise?
This is the proof instrument for docs/LEVEL-AGGREGATE-SPEC-20261115.md §14. It runs no prover and no node.

Every input is READ FROM SOURCE here (file and constant printed by the run) or is a MEASUREMENT whose record is named.
Nothing is tuned. What was never measured is a NAMED SCENARIO and its rows say so.

THE LAW. Every node pulls each proof exactly once. A merge of two proofs into one, made anywhere BEFORE the network-wide
pull, removes one proof (P bytes) from every node's download. So with M merges a second across the network:

    throughput = (B + P * M) / (P + s)          until the bundle-size bound   B / (P / k + s)

(while fewer than half the payments are merged, each merge turns two carrier payments, 2 * 293 KB, into one bundle of
two, 348 KB + 2 statements, and the rest ride as today: throughput = today + M * 0.79; see `relay`.)

B a node's intake left for payments, P one tree proof, s one payment's statement, k the largest bundle. M <= n * c: the
network's merges a second are its node count times one node's. Throughput is linear in n from the first node.

Designs compared:
  today   every payment's carriers ride to every node.
  held    AS BUILT on main: the node a payment is pushed to proves its leaf and merges it into ITS OWN next block.
          Its own rule turns it off once a node's block cadence (n * target) passes half the echo window.
  relay   §14: the unit of relay is a BUNDLE (statements + one tree proof). Any node merges two bundles of equal size it
          holds; a bundle is announced when merging it further would cost more time than queueing; any producer lays it.
"""
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(os.path.dirname(HERE))
NODE = os.path.join(TREE, "monerousd-node-zkdag", "src")
SPEC = os.path.join(TREE, "docs", "LEVEL-AGGREGATE-SPEC-20261115.md")


def src(path):
    return open(path, encoding="utf-8", errors="replace").read()


def need(m, what):
    if not m:
        sys.exit(f"NOT READ: {what} — the source moved; this model refuses to guess")
    return m


def read_inputs():
    dag = src(os.path.join(NODE, "dag.rs"))
    rt = src(os.path.join(NODE, "node_runtime.rs"))
    spec = src(SPEC)
    num = lambda s: int(s.replace("_", "").replace(",", ""))
    block_bytes = num(need(re.search(r"const RELAY_BLOCK_BYTES: u64 = ([\d_]+);", dag), "dag.rs RELAY_BLOCK_BYTES").group(1))
    lanes = num(need(re.search(r"const RELAY_LANES: u64 = ([\d_]+);", dag), "dag.rs RELAY_LANES").group(1))
    lane_rate = num(need(re.search(r"const RELAY_LANE_BYTES_PER_MS: u64 = ([\d_]+);", dag), "dag.rs RELAY_LANE_BYTES_PER_MS").group(1))
    need(re.search(r"MESH_TARGET_SPACING_MS: u64 = \(2 \* RELAY_BLOCK_BYTES\)\.div_ceil\(RELAY_LANES \* RELAY_LANE_BYTES_PER_MS\)", dag),
         "dag.rs MESH_TARGET_SPACING_MS derivation")
    target_ms = -(-2 * block_bytes // (lanes * lane_rate))
    echo_ms = num(need(re.search(r"const OWN_PUSH_AGAIN_MS: u64 = ([\d_]+);", rt), "node_runtime.rs OWN_PUSH_AGAIN_MS").group(1))
    # the built hold rule: nothing is held once this node's own cadence passes half the echo window
    need(re.search(r"self\.fair_share_spacing_ms\(\) > OWN_PUSH_AGAIN_MS / 2", rt), "node_runtime.rs agg_room_rows cadence rule")
    leaf = need(re.search(r"a LEAF: one payment's three real carriers verified wholly \(t1\) \| ([\d,]+) \(T 2\^16\) \| ([\d,]+) B \| ([\d.]+) s \| ([\d.]+) ms", spec), "spec §13.1 leaf row")
    merge = need(re.search(r"a MERGE of two real leaves \(t2\) \| [^|]+\| ([\d,]+) B[^|]*\| ([\d.]+) s \| ([\d.]+) s", spec), "spec §13.1 merge row")
    leaf_quiet = need(re.search(r"prove 17\.9 s = commit", spec), "spec §13.1 leaf phases (17.9 s)")
    need(re.search(r"its tags and so on|Today every node pulls every payment's ~293 KB of carriers", spec), "spec §0 carriers 293 KB")
    need(re.search(r"the statement, ≤ 3,699 B", spec), "spec §1.1 statement bound")
    del leaf_quiet
    return {
        "target_ms": target_ms,
        "lane_bytes_s": lanes * lane_rate * 1000,  # every lane of the reference host, B/s
        "echo_ms": echo_ms,
        "slots": 32,  # cover.rs:447 BLOCK_FIXED_SPEND_TX_COUNT, the value the spec §1.1 states; a block's constant spend slots
        "p_full": 293_000,  # spec §0: a payment's carriers
        "p_leaf": num(leaf.group(2)),
        "p_root": num(merge.group(1)),
        "stmt": 3_699,  # spec §1.1: an upper bound; the send's own statement is NOT MEASURED
        "leaf_s_loaded": float(leaf.group(3)),  # 2 threads, the loaded machine of the merge row
        "leaf_s": 17.9,  # 2 threads, lighter load (spec §13.1 phases)
        "merge_s_loaded": float(merge.group(2)),  # 2 threads, loaded: the ONLY merge measurement
        "leaf_check_s": float(leaf.group(4)) / 1000.0,
        "root_check_s": float(merge.group(3)),
        "threads_measured": 2,
        "own_duty_s": 13.117,  # spec §0 A3: a node's own block proof (10 s) + band share (3.117 s) per n * target
    }


def free_share(inp, n):
    """The share of a node's prover its own block and band leave (spec §0 A3)."""
    return max(0.0, 1.0 - inp["own_duty_s"] / (n * inp["target_ms"] / 1000.0))


def today(inp, intake):
    return min(intake / inp["p_full"], inp["slots"] / (inp["target_ms"] / 1000.0))


def held(inp, n, intake, threads, merge_s):
    """As built: leaf + its share of merges on the holder, into the holder's own block; off past half the echo window."""
    cadence_ms = n * inp["target_ms"]
    if cadence_ms > inp["echo_ms"] / 2:
        return today(inp, intake), 0.0
    per = (inp["leaf_s"] + merge_s) * inp["threads_measured"] / threads
    a = n * free_share(inp, n) / per
    # an aggregated payment costs every node its statement and its share of one root a block
    lam = (intake + a * (inp["p_full"] - inp["stmt"])) / inp["p_full"]
    return min(lam, inp["slots"] / (inp["target_ms"] / 1000.0)), a


def relay(inp, n, intake, threads, merge_s, kmax, node_makes_leaf=False, slots_follow=True):
    """§14. Returns (throughput, share of payments that ride in a bundle, mean bundle size, seconds a bundled payment
    spends being merged). An UNMERGED payment rides as today's carriers (never below today); a merged one as its bundle.
    Two regimes, both conservative (pairs first, never a deep bundle for a few payments):
      pairs   merges < half the payments: each merge turns two carrier payments into one bundle of two;
      bundled every payment is in a bundle; further merges halve the proofs again."""
    wall_merge = merge_s * inp["threads_measured"] / threads
    cost = wall_merge + (inp["leaf_s"] * inp["threads_measured"] / threads if node_makes_leaf else 0.0)
    supply = n * free_share(inp, n) / cost  # merges a second the network can make
    pf, p, s = inp["p_full"], inp["p_root"], inp["stmt"]
    hop = p / inp["lane_bytes_s"]  # one point-to-point pull of a bundle, every lane of the reference host
    level = wall_merge + hop + inp["root_check_s"]
    lam_pairs = (intake + supply * (2 * pf - p - 2 * s)) / pf
    if supply < lam_pairs / 2:
        lam, share, k = lam_pairs, 2 * supply / lam_pairs, 2.0
    else:
        lam = min((intake + p * supply) / (p + s), intake / (p / kmax + s))
        share, k = 1.0, 1.0 / max(1.0 / kmax, 1.0 - min(supply, lam * (1 - 1.0 / kmax)) / lam)
    if not slots_follow:
        lam = min(lam, inp["slots"] / (inp["target_ms"] / 1000.0))
    return lam, share, k, math.log2(k) * level


def ladder(inp):
    """§15 — every ceiling between today and Visa class, one rung at a time. Each rung keeps the rungs above it.
    Rows marked SCENARIO use an input nobody has measured; the row says which."""
    dag = src(os.path.join(NODE, "dag.rs"))
    mp = src(os.path.join(NODE, "mempool.rs"))
    cover = src(os.path.join(NODE, "cover.rs"))
    frame = int(need(re.search(r"const RELAY_BLOCK_BYTES: u64 = ([\d_]+);", dag), "dag.rs RELAY_BLOCK_BYTES").group(1).replace("_", ""))
    need(re.search(r"note_cm\(32\) ‖ ML-KEM ct\(1088\) ‖ enc_amount\(32\) ‖ view_tag\(1\)", mp), "mempool.rs output note layout")
    tags = int(need(re.search(r"pub const TX_FIXED_NULLIFIER_COUNT: usize = (\d+);", cover), "cover.rs TX_FIXED_NULLIFIER_COUNT").group(1))
    note = 32 + 1088 + 32 + 1
    state_part = tags * 32 + 2 * 32 + 32  # the tags, two note commitments, one digest of everything else
    # lane agg, bus 2026-11-16 02:21, branch agg-land-20261116 fb48e449 (NOT on main when this was written): the SSA row
    # with four multiply-add units — leaf 26,418 rows, 7.7 s, 333 KB; merge of two leaves 31,324 rows, 6.9 s, 338 KB;
    # root check 0.19 s; 2 proving threads, pin profile.
    new = dict(inp, leaf_s=7.7, leaf_s_loaded=7.7, merge_s_loaded=6.9, p_root=338_000, root_check_s=0.19)
    t = inp["target_ms"] / 1000.0
    print("\n=== §15 THE LADDER — payments/s settled, each rung on top of the one before ===")
    print(f"  a statement today ≤ {inp['stmt']:,} B, of which two output notes are 2 × {note:,} B (mempool.rs: commitment 32, ML-KEM ciphertext 1,088, amount 32, view tag 1)")
    print(f"  the part every node needs to keep its own state: {tags} tags + 2 note commitments + 1 digest = {state_part} B (by arithmetic from field widths; NOT MEASURED)")
    da_share = 0.05 * (inp["stmt"] - state_part)
    rungs = [
        ("today: every node pulls every payment's carriers", None),
        ("R1 bundle relay, 32 slots a block", dict(slots_follow=False)),
        ("R2 + slots follow the producers", dict()),
        (f"R3 + statement diet: {state_part} B to every node, the rest sampled (5% share ≈ {da_share:.0f} B)  SCENARIO", dict(stmt=state_part + da_share)),
        ("R4 + a transport ten times Tor's (6 MB/s for payments)  SCENARIO", dict(stmt=state_part + da_share, intake=6_000_000)),
    ]
    print("  rung                                                                                  | n=100 | n=1,000 | n=10,000 | n=10,000 at 16 threads SCENARIO")
    for label, opt in rungs:
        cells = []
        for n, thr in ((100, 2), (1000, 2), (10000, 2), (10000, 16)):
            if opt is None:
                cells.append(today(inp, 600_000))
                continue
            o = dict(new, stmt=opt.get("stmt", inp["stmt"]))
            lam, _, _, _ = relay(o, n, opt.get("intake", 600_000), thr, o["merge_s_loaded"], 1 << 16, slots_follow=opt.get("slots_follow", True))
            cells.append(lam)
        print(f"  {label:86s}| {cells[0]:7.1f} | {cells[1]:7.1f} | {cells[2]:8.1f} | {cells[3]:8.1f}")
    per_node = new["threads_measured"] / new["merge_s_loaded"] / 2  # merges a second per proving thread
    for goal in (1_700, 7_000):
        print(f"  {goal:,} payments/s needs {goal / per_node:,.0f} proving threads merging (at {new['merge_s_loaded']} s a merge on 2 threads)"
              f" and ≤ {600_000 / goal:,.0f} B a payment on every node at 600 KB/s, ≤ {6_000_000 / goal:,.0f} B at 6 MB/s")
    print("\n=== §15 THE BLOCK INTERVAL — dag.rs's own derivation, target = ⌈2 × frame / (lanes × lane rate)⌉ ===")
    ledger = 916_717  # docs/SPEED-MAX-PROGRAM-20261112.md §1: the joined ledger proof inside a 1.17–1.20 MB block (audit rig 11-12)
    wrapped = frame - ledger + new["p_root"]
    rate = inp["lane_bytes_s"] / 1000  # bytes per ms
    for what, fr, mult in (("today's frame", frame, 1), ("ledger proof wrapped in one tree proof (by arithmetic)", wrapped, 1),
                           ("wrapped, transport ten times Tor's  SCENARIO", wrapped, 10)):
        print(f"  {what:58s} {fr:9,} B → {-(-2 * fr // int(rate * mult)):6,} ms")
    assert abs(-(-2 * frame // int(rate)) - inp["target_ms"]) <= 1, "the ladder's formula must reproduce the source's target"
    del t


def main():
    inp = read_inputs()
    t = inp["target_ms"] / 1000.0
    print("INPUTS (read from source / the named measurement):")
    print(f"  mesh target            {inp['target_ms']} ms      dag.rs MESH_TARGET_SPACING_MS (derived there)")
    print(f"  echo window            {inp['echo_ms']} ms     node_runtime.rs OWN_PUSH_AGAIN_MS")
    print(f"  spend slots a block    {inp['slots']}           cover.rs BLOCK_FIXED_SPEND_TX_COUNT  → {inp['slots'] / t:.2f} payments/s of slots")
    print(f"  carriers a payment     {inp['p_full']:,} B    spec §0")
    print(f"  leaf / merged root     {inp['p_leaf']:,} / {inp['p_root']:,} B   spec §13.1 (pins t1, t2)")
    print(f"  statement              ≤ {inp['stmt']:,} B    spec §1.1 (the send's own: NOT MEASURED)")
    print(f"  leaf prove             {inp['leaf_s']} s at 2 threads ({inp['leaf_s_loaded']} s loaded)   spec §13.1")
    print(f"  merge prove            {inp['merge_s_loaded']} s at 2 threads, loaded — the only merge measurement   spec §13.1")
    print(f"  native check           leaf {inp['leaf_check_s'] * 1000:.0f} ms, merged root {inp['root_check_s']} s   spec §13.1")
    merge_quiet = inp["merge_s_loaded"] * inp["leaf_s"] / inp["leaf_s_loaded"]
    print(f"  SCENARIO merge, quiet  {merge_quiet:.1f} s at 2 threads = 45.0 × 17.9 / 35.4 (the leaf's own loaded→quiet ratio; NOT MEASURED)")
    print("  SCENARIO 8 threads     the 2-thread time ÷ 4 (thread scaling of the SSA prover: NOT MEASURED)")

    cad_off = math.floor(inp["echo_ms"] / 2 / inp["target_ms"])
    print(f"\nTHE WALL, from the code: a held payment rides only its holder's own block, which comes every n × {t:.3f} s;")
    print(f"  agg_room_rows returns 0 once that passes {inp['echo_ms'] // 2000} s, so the built path holds nothing past n = {cad_off} producers,")
    per2 = inp["leaf_s"] + inp["merge_s_loaded"]
    print(f"  while one node's tree capacity is 1/{per2:.0f} payment/s at 2 threads: it would pass today's rate only near n = {math.ceil(today(inp, 600_000) * per2)}.")

    ns = [2, 4, 5, 6, 8, 13, 32, 100, 320, 1000, 3000]
    cell = lambda r: f"{r[0]:7.2f} ({r[1] * 100:3.0f}% bundled, k {r[2]:6.1f}, +{r[3]:3.0f} s)"
    for intake, label in ((600_000, "800 KB/s lanes, 600 KB/s left after frames"), (200_000, "400 KB/s reference, 200 KB/s left after frames")):
        print(f"\n=== payments/s settled — {label} ===")
        print("    n | today | held as built | relay, 2 threads MEASURED times        | same, node makes the leaf | relay, 8 threads SCENARIO")
        for n in ns:
            td = today(inp, intake)
            hd, _ = held(inp, n, intake, 2, inp["merge_s_loaded"])
            r2 = relay(inp, n, intake, 2, inp["merge_s_loaded"], 1024)
            r2n = relay(inp, n, intake, 2, inp["merge_s_loaded"], 1024, node_makes_leaf=True)
            r8 = relay(inp, n, intake, 8, merge_quiet, 1024)
            assert r2[0] >= td - 1e-9 and r8[0] >= td - 1e-9, "the relay must never settle less than today"
            print(f"{n:5d} | {td:5.2f} | {hd:13.2f} | {cell(r2)} | {r2n[0]:25.2f} | {cell(r8)}")
        for goal in (10, 100):
            for thr, ms, tag in ((2, inp["merge_s_loaded"], "2 threads measured"), (8, merge_quiet, "8 threads scenario")):
                need_n = next((n for n in range(2, 200_001) if relay(inp, n, intake, thr, ms, 1024)[0] >= goal), None)
                print(f"  nodes for {goal:3d} payments/s, {tag}: {need_n if need_n else 'never (the statement bound is below it)'}")

    print("\nWHAT BINDS, at 600 KB/s:")
    for k in (2, 8, 32, 128, 1024):
        print(f"  bundles of {k:5d}: {inp['p_root'] / k + inp['stmt']:9,.0f} B a payment a node → at most {600_000 / (inp['p_root'] / k + inp['stmt']):6.1f} payments/s")
    print(f"  the statement alone: {600_000 / inp['stmt']:.0f} payments/s — past it the lever is the statement's bytes, not this design")
    print(f"  the block's {inp['slots']} constant slots: {inp['slots'] / t:.2f} payments/s — the slot count must follow the producers (spec §1.6) or it binds first")

    ladder(inp)

    # calibration: the law must reproduce today's number when nothing merges, and refuse a free lunch
    lam0, share0, _, _ = relay(inp, 2, 600_000, 2, 1e18, 1024)
    assert abs(lam0 - today(inp, 600_000)) < 1e-6 and share0 < 1e-9, "no merging must be exactly today"
    lam_inf, _, _, _ = relay(inp, 10**7, 600_000, 2, inp["merge_s_loaded"], 1024)
    assert lam_inf <= 600_000 / inp["stmt"], "throughput can never pass the statement bound"
    a, _, _, _ = relay(inp, 100, 600_000, 2, inp["merge_s_loaded"], 1024)
    b, _, _, _ = relay(inp, 200, 600_000, 2, inp["merge_s_loaded"], 1024)
    assert b > a, "more nodes must settle more while proving binds"
    print("\ncalibration: no merges = today exactly; never below today at any n; never past the statement bound; rises with n while proving binds — OK")


if __name__ == "__main__":
    main()

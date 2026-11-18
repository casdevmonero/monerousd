#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
"""THE LEVEL AGGREGATE by ARITHMETIC — does settled throughput RISE as nodes join? (lane agg, 2026-11-15; no build, no node, ms)

User 2026-11-15: "be sure to prove your fixes without causing machine tension and no waiting". This model is the proof instrument
for docs/LEVEL-AGGREGATE-SPEC-20261115.md; nothing in it runs a prover, a node or a build.

Every constant below is READ FROM SOURCE or is a MEASUREMENT whose record is named. Nothing is tuned. The laws are the chain's own:
  * every node holds every block frame and every byte it verifies (TRUSTLESS: each node verifies alone);
  * the mesh block rate is the DERIVED target (lane speed5, dag.rs MESH_TARGET_SPACING_MS): frames take half of a node's
    reference intake whatever the producer count, and the DAA holds the mesh at it;
  * a block's spend slots are a CONSTANT (cover.rs BLOCK_FIXED_SPEND_TX_COUNT): the count is privacy, never load.

Designs:
  today     every payment's carriers ride to every node (FULL slots only).
  agg       AGGREGATED slots only: a payment's carriers travel ONE hop (the push it already makes) to the node that includes
            it; that node's block proof verifies them in circuit; every other node takes the slot's statement (the delta) and
            the block's one proof. K_A aggregated slots per block, a CONSTANT; decoys fill the rest.
  agg+full  HYBRID: a node aggregates only what its own measured prover covers before its next block; the rest goes FULL as
            today, so it never settles less than today (AGG_NO_HYBRID=1 removes the rule: the calibration must go red).
  agg-tree  K_A follows the PUBLIC producer count (a tree of fixed-size leaf aggregates, constant RAM per proof step):
            unbounded until the delta bandwidth binds.
"""
import os
import re
import sys

MAIN = os.path.expanduser("~/Desktop/connect")
sys.path.insert(0, os.path.join(MAIN, "scratchpad", "speedmodel"))
import whir_model  # noqa: E402  the exact port of p3-whir's sizing (lane speed5); reproduces the measured carriers

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(os.path.dirname(HERE))
SPEED5_DAG = os.environ.get("AGG_DAG_RS", os.path.join(MAIN, ".worktrees/speed5/monerousd-node-zkdag/src/dag.rs"))
COVER_RS = os.environ.get("AGG_COVER_RS", os.path.join(TREE, "monerousd-node-zkdag/src/cover.rs"))


def const(path, pat, name):
    m = re.search(pat, open(path).read())
    if not m:
        raise SystemExit(f"[agg-model] {name} not found in {path}: the model refuses to run on a guessed constant")
    return int(m.group(1).replace("_", ""))


RELAY_BLOCK_BYTES = const(SPEED5_DAG, r"const RELAY_BLOCK_BYTES: u64 = ([0-9_]+);", "RELAY_BLOCK_BYTES")        # dag.rs:106
RELAY_LANES = const(SPEED5_DAG, r"const RELAY_LANES: u64 = ([0-9_]+);", "RELAY_LANES")                          # dag.rs:108
RELAY_LANE_BYTES_PER_MS = const(SPEED5_DAG, r"const RELAY_LANE_BYTES_PER_MS: u64 = ([0-9_]+);", "lane rate")      # dag.rs:109
TARGET_S = -(-(2 * RELAY_BLOCK_BYTES) // (RELAY_LANES * RELAY_LANE_BYTES_PER_MS)) / 1e3                         # dag.rs:140
_cov = open(COVER_RS).read()
# the alias chain as written in cover.rs: NULLIFIER_COUNT = NOTE_COUNT (:440) = TX_COUNT (:55) = 256 (:48)
if not (re.search(r"pub const BLOCK_FIXED_NULLIFIER_COUNT: usize = BLOCK_FIXED_NOTE_COUNT;", _cov)
        and re.search(r"pub const BLOCK_FIXED_NOTE_COUNT: usize = BLOCK_FIXED_TX_COUNT;", _cov)):
    raise SystemExit("[agg-model] cover.rs no longer aliases the nullifier budget to the tx count: re-read it")
SPEND_SLOTS = (const(COVER_RS, r"pub const BLOCK_FIXED_TX_COUNT: usize = ([0-9_]+);", "block tx count")
               // const(COVER_RS, r"pub const TX_FIXED_NULLIFIER_COUNT: usize = ([0-9_]+);", "tx width"))         # cover.rs:447

# ── measured (record named) ─────────────────────────────────────────────────────────────────────────────────────────
B_NODE = 800e3   # B/s a node pulls: 4 bulk lanes × ~200 KB/s (docs/SPEED-MAX-PROGRAM-20261112.md §14 table, 2026-11-12 trace)
B_REF = RELAY_LANES * RELAY_LANE_BYTES_PER_MS * 1e3  # 400 KB/s: the reference intake speed5's target is derived from
T_PAY = 293_110  # B a payment carries (rig log 2026-11-15 "[tx-origin] pushed … (293110 B)", scratchpad/speedmodel/chain_model.py)
DELTA = 3_699    # B a CLAIM carries — notes, clues, targets, no carrier ("[tx-origin] pushed … (3699 B)", ~/.usdmd-localnet/n0/node.log).
#                  Used as what a node holds of an aggregated payment. NOT MEASURED for a send's own statement: probe P0 prints it.
# The BOUND engine — the only one that may carry public data (memory project_c4_refuted_direct_engine_unbound_20261113; A-F55):
# lane c4 SPEED-MAX-PROGRAM §14.1f: three member carriers' openings as ONE table, 16,384 rows × 258 cols, 5.3 s at 4 threads.
BOUND_ROWS_PER_S_4T = 16_384 / 5.3
# P1 MEASURED 2026-11-15 19:3x (lane agg, agg_probe::tests::p1, 2 threads, machine load ~55 — a loaded figure, never compared
# with a solo one): the stacked committed door on the NARROW permutation layout (164 columns) proves 16,384 rows in 8.46 s
# (1,937 rows/s; blinded 1,502), 8,192 in 4.82 s (1,699), with proofs of 194–206 KB verifying in ~20 ms.
P1_NARROW_ROWS_PER_S_2T_LOADED = 1_937
# Thread scaling of the same prover family on a permutation table (§14.1b, c4_probe2: 7,195 / 9,521 / 10,915 perms/s at 2/4/8).
SCALE = {2: 7_195 / 9_521, 4: 1.0, 8: 10_915 / 9_521}
LEAF_RATE = 8    # words a Poseidon2-16 sponge absorbs per permutation (DIGEST_LANES = 8, whir_rec_block.rs:27)
# V5–V8 (fold, sumcheck rounds, domain point, combine + final) beside V4's hashing — lane c4 §14.1c's ESTIMATE, ~1,000 rows a
# carrier. NOT MEASURED; probe P2 replaces it. An UPPER reference, measured: the certificate's universal-row WHIR program
# (whir_program.rs, pinned against the native verifier; scratchpad/holes-circuit-mod-whir_program.log) lays 21,109 rows for one
# 16-variable verify with 231 query paths (~91 rows a path) and 8,167 for a 15-variable one with 131 (~62); the count here is
# ~30 rows a path for dedicated tables, so the in-circuit rows below may be low by up to 3× (the SENSITIVITY rows show it).
ARITH_ROWS_PER_CARRIER = 1_000
# A payment's carriers (mempool.rs PqTx: blob, membership_carrier, spend_or_decoy, member_carrier) and their variable counts
# (§15: member 17, spend-or-decoy 14, membership 20). The spend blob's: NOT MEASURED (P0 prints it); counted as member-sized.
CARRIERS = {"member": 17, "spend_or_decoy": 14, "membership": 20, "spend(blob)": 17}


def verify_rows(nv, leaf_cols=1):
    sib, words = whir_model.opening_counts(whir_model.live(nv), leaf_cols=leaf_cols)
    return sib + -(-words // LEAF_RATE) + ARITH_ROWS_PER_CARRIER


def payment_rows():
    return sum(verify_rows(nv) for nv in CARRIERS.values())


ROWS = payment_rows()
# THE TABLE CAP: one proof's stacked polynomial is at most 2^24 cells — committed_air.rs:202 "the 24-variable production cap"
# (two-adicity: KoalaBear TWO_ADICITY = 24, koala_bear.rs:67; `vars + start_rate − first_fold ≤ 24`). So no single proof can
# verify a block's payments: a block's aggregate is a TREE of proofs, each ≤ 2^24 cells.
KB_RS = os.path.join(TREE, "monerousd-node-zkdag/vendor/Plonky3/koala-bear/src/koala_bear.rs")
TWO_ADICITY = const(KB_RS, r"const TWO_ADICITY: usize = ([0-9_]+);", "TWO_ADICITY")
TABLE_VARS = 24
assert TABLE_VARS <= TWO_ADICITY + 4 - 2, "the cap must respect the two-adicity relation"
# A table's width: the measured openings table (§14.1f) is 258 columns → 512 as a power of two; the narrow permutation layout
# (§14.1, 164 columns) → 256. Its prove rate per row: NOT MEASURED (assumed equal; P1 measures it).
LAYOUTS = {"wide-258": 512, "narrow-164": 256}
LAYOUT = os.environ.get("AGG_LAYOUT", "wide-258")


def tree(layout=None):
    """(payments per leaf, merge fan-in, merge rows per payment) for a layout. A merged child is a FULL table (2^24 cells),
    so verifying it in circuit costs the WHIR opening of a 24-variable stacked polynomial."""
    cols = LAYOUTS[layout or LAYOUT]
    rows_cap = (1 << TABLE_VARS) // cols
    per_leaf = rows_cap // ROWS
    child = verify_rows(TABLE_VARS)
    fan_in = rows_cap // child
    if per_leaf < 1 or fan_in < 2:
        return per_leaf, fan_in, float("inf")
    return per_leaf, fan_in, child / per_leaf * fan_in / (fan_in - 1)




# A node's own block proof (SPEED-MAX-PROGRAM §1: 9–14 s; chain_model.py BLOCK_PROOF = 10 s; thread count NOT MEASURED): proving
# time a node spends on its own blocks is time it cannot spend on aggregation. Each node produces once per n × TARGET_S.
BLOCK_PROOF_S = 10.0


# ── MILESTONE 1: stage A at block scale (spec §10) — the openings proved in the block's tables, the cores held by peers ──
# A send's three carriers (monerousd-wallet-v2 lib.rs:14937, the send body: membership_carrier empty, "§19 NO ONE-STEP BIND"): the note spend (`blob`), the member leg, the cover arm.
# Their variable counts: member 17, spend-or-decoy 14 (§15); the note spend: NOT MEASURED (counted at 17). P0 prints them.
STAGE_A_CARRIERS = {"note_spend": 17, "member": 17, "spend_or_decoy": 14}
CORE_BYTES = 12_455        # a member carrier's core (lane c4 §14.1e, measured); the other two: NOT MEASURED (P0), taken equal
STAGE_A_TABLE_LOG = 16     # agg_mode::TABLE_MAX_ROWS_LOG
STAGE_A_TABLE_COLS = 258   # stir_group_air::ROW_COLS


def stage_a_rows():
    """openings-table rows a payment's groups take: siblings + leaf-sponge permutations, no arithmetic rows, no merges."""
    return sum(verify_rows(nv) - ARITH_ROWS_PER_CARRIER for nv in STAGE_A_CARRIERS.values())


# MEASURED 2026-11-15 19:52 (lane agg, node::agg_level_aggregate_tests on a production-shaped send, two in-process nodes):
# full send 292,320 B; its AGGREGATED body (statement + three cores) 73,134 B; the block's one table for that one payment
# 178,968 B; a peer that never saw the payment judged the block in 637 ms. Decider pin (two payments, four carriers): one
# 32,768-row table 187,786 B — a table's bytes barely move with its rows, so its share falls with the payments in it.
AGG_BODY_BYTES = 73_134
TABLE_BYTES_ONE = 178_968


def stage_a_bytes(per_table=None):
    """bytes a peer pulls per aggregated payment: its measured aggregated body + its share of one table proof (the larger of
    the measured one-payment table and the WHIR sizing at a full table's stacked arity)."""
    stacked = STAGE_A_TABLE_LOG + (STAGE_A_TABLE_COLS - 1).bit_length()
    table = max(TABLE_BYTES_ONE, whir_model.opening_bytes(whir_model.live(stacked)) + STAGE_A_TABLE_COLS * 16)
    k = per_table or max(1, (1 << STAGE_A_TABLE_LOG) // stage_a_rows())
    return AGG_BODY_BYTES + table / k


def stage_a(n, threads=4, b=B_NODE, hosts=None):
    blocks_s = 1.0 / TARGET_S
    bw = max(0.0, b - RELAY_BLOCK_BYTES * blocks_s)
    eff = n if hosts is None else min(n, hosts / threads)
    c = stage_a_rows() / (BOUND_ROWS_PER_S_4T * SCALE[threads])
    agg = min(eff * spare(n) / c, bw / stage_a_bytes(), blocks_s * SPEND_SLOTS)
    left = max(0.0, bw - agg * stage_a_bytes())
    full = min(left / T_PAY, max(0.0, blocks_s * SPEND_SLOTS - agg))
    return agg + full, agg


def c_pay(threads, layout=None):
    """seconds a node proving at `threads` threads spends per aggregated payment: its leaf + its share of the merge tree."""
    return (ROWS + tree(layout)[2]) / (BOUND_ROWS_PER_S_4T * SCALE[threads])


NF_AIR = os.path.join(TREE, "monerousd-node-zkdag/vendor/Plonky3/usdm-decider/src/nf_sparse_air.rs")
# The band (lane dcash): one proven nullifier step per fold step, owners by HRW among the view holders (CHAIN-DEATH-AUDIT §C14).
BAND_STEP_S = const(NF_AIR, r"pub const BAND_FOLD_PROVE_MS_REF: u64 = ([0-9_]+);", "BAND_FOLD_PROVE_MS_REF") / 1e3  # :1365


def spare(n):
    """the fraction of a node's proving time left after its own block proofs and its share of the band (every node a view
    holder; a phone that holds no view proves no band step and keeps more)."""
    duty = BLOCK_PROOF_S / (n * TARGET_S) + BAND_STEP_S / (n * TARGET_S)
    return max(0.0, 1.0 - duty)


def throughput(n, design, threads=4, k_a=8, b=B_NODE, hybrid=True, rows_scale=1.0, layout=None, hosts=None):
    """settled payments/s with n producing nodes (each with `threads` proving threads), and the binding term. `hosts` = the
    proving threads ALL n nodes share (one machine: 10); None = each node on its own hardware."""
    blocks_s = 1.0 / TARGET_S                 # the derived mesh rate: constant in n (speed5)
    bw = max(0.0, b - RELAY_BLOCK_BYTES * blocks_s)   # what a node's intake leaves after frames
    cap_slots = blocks_s * SPEND_SLOTS
    if design == "today":
        lim = {"bandwidth": bw / T_PAY, "slots": cap_slots}
        v = min(lim.values())
        return v, min(lim, key=lim.get)
    eff = n if hosts is None else min(n, hosts / threads)     # on one machine the threads, not the nodes, are the capacity
    prove = eff * spare(n) / (c_pay(threads, layout) * rows_scale)  # leaves streamed in the time own blocks leave
    if design == "agg-tree":
        lim = {"proving": prove, "delta-bw": bw / DELTA}
        v = min(lim.values())
        return v, min(lim, key=lim.get)
    agg = min(prove, blocks_s * k_a, bw / DELTA)
    if design == "agg+full" and hybrid:
        left = max(0.0, bw - agg * DELTA)                    # an aggregated payment costs a node DELTA, a full one T_PAY
        full = min(left / T_PAY, max(0.0, cap_slots - agg))  # the full path keeps the slots and the bandwidth left over
        return agg + full, ("agg+full" if full > 1e-9 else "agg")
    lim = {"proving": prove, "agg-slots": blocks_s * k_a, "delta-bw": bw / DELTA}
    v = min(lim.values())
    return v, min(lim, key=lim.get)


def main():
    print(f"[agg-model] read from source: target {TARGET_S:.3f} s (speed5 dag.rs:140), {SPEND_SLOTS} spend slots (cover.rs:447), "
          f"frames {RELAY_BLOCK_BYTES / TARGET_S / 1e3:.0f} KB/s into every node")
    print(f"[agg-model] in-circuit rows per payment {ROWS:,} (whir_model.py openings + {ARITH_ROWS_PER_CARRIER} arithmetic rows a carrier)")
    print(f"[agg-model] table cap 2^{TABLE_VARS} cells (committed_air.rs:202; KoalaBear two-adicity {TWO_ADICITY}): merging one "
          f"full child costs {verify_rows(TABLE_VARS):,} rows (every engine here stacks its tables: light_commit.rs:374)")
    for lay in LAYOUTS:
        pl, f, m = tree(lay)
        print(f"[agg-model] layout {lay}: {pl} payment(s) a leaf, merge fan-in {f}, {m:,.0f} merge rows a payment; "
              + "  ".join(f"{t} threads {c_pay(t, lay):.2f} s" for t in (2, 4, 8)) + " per aggregated payment")
    print(f"[agg-model] band step {BAND_STEP_S:.3f} s (nf_sparse_air.rs:1365); proving left after own blocks + band share: " + "  ".join(f"n={n}: {spare(n):.0%}" for n in (2, 4, 8, 16, 64)))
    ns = [2, 4, 8, 13, 16, 32, 64, 128, 1000]
    for b, label in ((B_NODE, "measured 800 KB/s"), (B_REF, "reference 400 KB/s")):
        print(f"\nSETTLED PAYMENTS/s, node intake {label}, 4 proving threads a node (binding term)")
        print(f"{'design':10}" + "".join(f"{'n=' + str(n):>17}" for n in ns))
        for d in ("today", "agg", "agg+full", "agg-tree"):
            print(f"{d:10}" + "".join(f"{v:9.2f} {w[:7]:>7}" for v, w in (throughput(n, d, b=b) for n in ns)))
    print(f"\nMILESTONE 1 (stage A, block-scale tables, cores held): {stage_a_rows():,} table rows and ≈ {stage_a_bytes() / 1024:.0f} KB "
          f"a payment on the envelope at a full table, {stage_a_bytes(1) / 1024:.0f} KB alone in one (from {T_PAY / 1024:.0f}); "
          f"4 threads a node: settled (aggregated) /s")
    print("  " + "  ".join(f"n={n}: {stage_a(n)[0]:.2f} ({stage_a(n)[1]:.2f})" for n in (2, 4, 8, 16, 32, 64, 1000)))
    print("  one machine, 2 threads a node: " + "  ".join(
        f"n={n}: {stage_a(n, threads=2, hosts=10)[0]:.2f} ({stage_a(n, threads=2, hosts=10)[1]:.3f})" for n in (2, 4, 5)))
    print("\nONE MACHINE (10 cores shared by every node, 2 proving threads a node), measured intake per node:")
    for n in (2, 4, 5, 8):
        a = throughput(n, "agg-tree", threads=2, hosts=10)[0]
        h = throughput(n, "agg+full", threads=2, hosts=10)[0]
        print(f"  n={n}: aggregated only {a:.3f}/s, hybrid {h:.2f}/s, today {throughput(n, 'today')[0]:.2f}/s")
    print("\nNARROW LAYOUT (164-column permutation rows, rate per row assumed equal — NOT MEASURED): agg-tree " + "  ".join(
        f"n={n}: {throughput(n, 'agg-tree', layout='narrow-164')[0]:.2f}/s" for n in (8, 16, 64, 1000)))
    print("\nSENSITIVITY: agg-tree at n = 8 / 64 if the in-circuit rows are 2x or 0.5x the estimate")
    for s in (0.5, 1.0, 2.0):
        print(f"  rows x{s}: " + "  ".join(f"n={n}: {throughput(n, 'agg-tree', rows_scale=s)[0]:.2f}/s" for n in (8, 64)))
    # ── calibration: each can go red ───────────────────────────────────────────────────────────────────────────────
    ok = True
    t2 = throughput(2, "today")[0]
    if not 1.4 <= t2 <= 2.3:  # the measured band at 2 nodes (§14: ≈ 1.8/s; §15 table: 2.3/s)
        print(f"[agg-model] RED: today at n = 2 reads {t2:.2f}/s, outside the measured 1.4–2.3/s")
        ok = False
    for n in (2, 4, 8, 16, 64):
        if throughput(n, "agg+full")[0] + 1e-9 < throughput(n, "today")[0]:
            print(f"[agg-model] RED: the hybrid settles less than today at n = {n}")
            ok = False
    for n in (2, 4, 8, 16, 64):
        if stage_a(n)[0] + 1e-9 < throughput(n, "today")[0]:
            print(f"[agg-model] RED: milestone 1 settles less than today at n = {n}")
            ok = False
    rise = [throughput(n, "agg-tree")[0] for n in (2, 4, 8, 16, 32, 64)]
    if not all(b2 > a for a, b2 in zip(rise, rise[1:])):
        print(f"[agg-model] RED: agg-tree does not rise with n: {rise}")
        ok = False
    flat = [throughput(n, "today")[0] for n in (2, 64)]
    if abs(flat[0] - flat[1]) > 1e-9:
        print(f"[agg-model] RED: today is not flat in n under speed5's target: {flat}")
        ok = False
    if os.environ.get("AGG_NO_HYBRID") == "1":
        a2 = throughput(2, "agg+full", hybrid=False)[0]
        bad = a2 < t2
        print(f"[agg-model] switch: hybrid rule removed → agg alone at n = 2 = {a2:.2f}/s vs today {t2:.2f}/s: "
              f"{'red, as it must be' if bad else 'NOT red — the rule proves nothing'}")
        ok = ok and bad
    print("\n[agg-model] " + ("GREEN" if ok else "RED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

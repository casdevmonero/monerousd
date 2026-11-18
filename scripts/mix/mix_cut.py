#!/usr/bin/env python3
"""Tor cut, payments on the mix alone, Tor back, nothing forked, no funds lost. Real usdmd-node processes and real wallets.

  PYTHONPATH=<main checkout>/scratchpad/net NET_ROOT=~/.usdmd-localnet-mix NET_PORT=29100 NET_NODES=3 \
  NET_NODE_BIN=scripts/mix/mix_node.sh MIX_REAL_NODE_BIN=~/.cargo-targets/mix/release/usdmd-node \
  NET_WALLET_BIN=~/.cargo-targets/mix-wallet/release/wallet-harness python3 scripts/mix/mix_cut.py unix|relay

Tor is cut from outside, by the OS sandbox: the node cannot reach any outside address (mix_node.sh), and each phase checks that it really
had no Tor link. `unix`: nodes on one machine over Unix sockets, every outbound IP refused. `relay`: nodes dial each other's relay faces
over TCP on this machine, everything else refused: the links a real network runs on, with no outside provider anywhere. Neither proves
internet behaviour: this machine has no real latency, loss or NAT.

Phases: A) Tor cut from the first block: a chain forms and money moves over the mix alone. B) Tor returns: the same chain continues,
every balance holds, and a payment lands. C) Tor is cut again under a running chain, and a payment lands."""
import json, os, re, shutil, subprocess, sys, time

ROOT = os.environ["NET_ROOT"]
os.makedirs(ROOT, exist_ok=True)
CARRIER = sys.argv[1] if len(sys.argv) > 1 else "unix"
CUT_FILE = f"{ROOT}/tor-cut"
N = int(os.environ.get("NET_NODES", "3"))


def set_cut(mode):
    if mode:
        open(CUT_FILE, "w").write(mode)
    elif os.path.exists(CUT_FILE):
        os.remove(CUT_FILE)


CUT_MODE = "all" if CARRIER == "unix" else "local"
set_cut(CUT_MODE)  # before net.py's first spawn

per_node = {}
if CARRIER == "unix":
    # A short fixed path: a socket path has a small length limit, and NET_ROOT can be long.
    socks = [f"/tmp/mixrig-{os.environ.get('NET_PORT', '0')}-{i}.sock" for i in range(N)]
    for i in range(N):
        per_node[str(i)] = {
            "MONEROUSD_MIX_UNIX": socks[i],
            "MONEROUSD_MIX_SEEDS": ",".join(f"unix:{s}" for j, s in enumerate(socks) if j != i),
        }
else:
    base = int(os.environ.get("NET_PORT", "29100")) + 100
    faces = [f"relay:127.0.0.1:{base + i}" for i in range(N)]
    for i in range(N):
        per_node[str(i)] = {
            "MONEROUSD_MIX_RELAY": faces[i],
            "MONEROUSD_MIX_SEEDS": ",".join(f for j, f in enumerate(faces) if j != i),
        }
os.environ["NET_PER_NODE"] = json.dumps(per_node)

from net import alive, data, height, info, post, record, spawn, stop, up, wait  # noqa: E402
from pay_lib import Wallet, wait_spendable  # noqa: E402


def state_files(i, name):
    found = []
    for base, _, files in os.walk(data(i)):
        if name in files:
            found.append(os.path.join(base, name))
    return found


def status(i):
    for p in state_files(i, "mix-status.json"):
        try:
            return json.load(open(p))
        except Exception:
            pass
    return {}


def fail(why):
    record("mix-tor-cut", "FAIL", f"{CARRIER}: {why}"[:300])
    print(f"[mix] FAIL {why}", flush=True)
    for i in range(N):
        print(f"--- node {i}: height {info(i).get('height')} {status(i)}", flush=True)
    sys.exit(1)


def show(tag):
    keys = ["active", "primary_down", "links", "view", "sent_real", "sent_cover", "cells_in", "asks_sent", "asks_answered", "asks_timed_out", "asks_served", "loops_sent", "loops_back", "bad_mac", "replays", "tagged", "dropped_pool", "dropped_link", "dropped_queue", "out_bulk"]
    for i in range(N):
        s, d = status(i), info(i)
        print(f"[mix] {tag} node {i}: height {d.get('height')} seq {d.get('served_seq')} " + " ".join(f"{k}={s.get(k)}" for k in keys), flush=True)


def wipe():
    for i in range(N):
        stop(i)
    for d in os.listdir(ROOT):
        if d.startswith("netw_") or (d[0] == "n" and d[1:].isdigit()):
            shutil.rmtree(f"{ROOT}/{d}", ignore_errors=True)


def one_chain(tag):
    h = [info(i).get("height", 0) for i in range(N)]
    print(f"[mix] {tag}: heights {h}", flush=True)
    return max(h) - min(h) <= 8 and min(h) > 0


def pay(from_w, to_w, amount, atomic, tag):
    t = time.time()
    from_w.send(to_w.address, amount, "mix-tor-cut")
    from_w.close()
    print(f"[mix] {tag}: sent in {time.time() - t:.1f} s", flush=True)
    return wait_spendable(to_w, atomic, "mix-tor-cut")


def build_chain():
    head = int(os.environ.get("NET_HEAD_START", "16"))
    spawn(0, "", origin=True)
    wait("node 0 answering", lambda: up(0))
    wait(f"node 0 holding {head} blocks", lambda: height(0) >= head)
    for i in range(1, N):
        spawn(i, "")
        wait(f"node {i} answering", lambda i=i: up(i))
    for i in range(1, N):
        wait(f"node {i} on the chain over the mix", lambda i=i: height(i) >= height(0) - 8 and height(i) > 0)


def restart_all(mode, tag):
    set_cut(mode)
    for i in range(N):
        stop(i)
    for i in range(N):
        spawn(i, "")
    for i in range(N):
        wait(f"{tag}: node {i} answering", lambda i=i: up(i))


wipe()
set_cut(CUT_MODE)
t0 = time.time()

# ── A: Tor has never been reachable ─────────────────────────────────────────────────────────────────────────────────────────
build_chain()
print(f"[mix] A: {N} nodes on one chain over the mix alone at {time.time() - t0:.0f} s", flush=True)
# A node calls its Tor down only after 20 s of silence, and the last node has just started.
deadline = time.time() + 60
while time.time() < deadline and not all(status(i).get("primary_down") for i in range(N)):
    time.sleep(3)
show("A")
for i in range(N):
    s = status(i)
    if not s.get("primary_down"):
        fail(f"node {i} still believes Tor is up 60 s into the OS cut, so this run would prove nothing")
    if s.get("links", 0) == 0:
        fail(f"node {i} holds no mix link")
    log = open(f"{data(i)}/node.log", errors="ignore").read()
    if re.search(r"cell link up", log):
        fail(f"node {i} logged a Tor cell link inside the OS cut")

a = Wallet("mixa", 0)
b = Wallet("mixb", 1)
c = Wallet("mixc", 2 if N > 2 else 1)
r = post(0, "/faucet/drip", json.dumps({"amount": 2_500_000_000, "to": a.address}))
if '"published":true' not in r:
    fail(f"the faucet published nothing: {r[:200]}")
fund = wait_spendable(a, 2_500_000_000, "mix-tor-cut")
show("A funded")
s1 = pay(a, b, "7.0", 700_000_000, "A pay")
print(f"[mix] A: paid on the mix alone, spendable on the other node after {s1:.0f} s", flush=True)
b.send(c.address, "2.0", "mix-tor-cut")
b.close()
s2 = wait_spendable(c, 200_000_000, "mix-tor-cut")
c.close()
print(f"[mix] A: the payee spent it to a third wallet; spendable after {s2:.0f} s", flush=True)
show("A paid")
hA = [info(i).get("height", 0) for i in range(N)]

if CARRIER == "unix" and os.environ.get("MIX_ATTACKS", "1") == "1":
    # While the network is up: a real neighbour attacks a real node, and only the node's own counters decide.
    here = os.path.dirname(os.path.abspath(__file__))
    r = subprocess.run([sys.executable, f"{here}/mix_attacks.py"], env=dict(os.environ, MIX_VICTIM_SOCK=per_node["0"]["MONEROUSD_MIX_UNIX"]), capture_output=True, text=True, timeout=600)
    print(r.stdout + r.stderr, flush=True)
    if r.returncode != 0:
        fail("a tamper check did not reject")

# ── B: Tor returns ──────────────────────────────────────────────────────────────────────────────────────────────────────────
a_before, b_before, c_before = a.spendable(), b.spendable(), c.spendable()
a.close(), b.close(), c.close()
print(f"[mix] B: balances before Tor returns: a {a_before} b {b_before} c {c_before}", flush=True)
restart_all(None, "B")
for i in range(N):
    wait(f"B: node {i} back at its height", lambda i=i: height(i) >= hA[i] - 8)
time.sleep(int(os.environ.get("MIX_TOR_SOAK", "90")))
show("B")
hB = [info(i).get("height", 0) for i in range(N)]
print(f"[mix] B: heights {hB}, links as the runtime counts them {[info(i).get('live_writers_held') for i in range(N)]}", flush=True)
if not one_chain("B"):
    fail(f"nodes split after Tor returned: {hB}")
a_now, b_now, c_now = a.spendable(), b.spendable(), c.spendable()
a.close(), b.close(), c.close()
if (a_now, b_now, c_now) != (a_before, b_before, c_before):
    fail(f"balances moved when Tor returned: {(a_before, b_before, c_before)} -> {(a_now, b_now, c_now)}")
s3 = pay(a, c, "3.0", c_before + 300_000_000, "B pay")
c.close()
print(f"[mix] B: a payment landed with Tor back after {s3:.0f} s", flush=True)

# ── C: Tor is cut again under a running chain ───────────────────────────────────────────────────────────────────────────────
restart_all(CUT_MODE, "C")
for i in range(N):
    wait(f"C: node {i} on the chain", lambda i=i: height(i) >= hB[i] - 8)
time.sleep(30)
s4 = pay(c, b, "1.0", b_now + 100_000_000, "C pay")
b.close()
show("C")
if not one_chain("C"):
    fail("nodes split after the second cut")

detail = f"{CARRIER}: funded {fund:.0f} s; paid on the mix alone {s1:.0f} s; spent onward {s2:.0f} s; Tor back: same chain, balances held, paid {s3:.0f} s; cut again: paid {s4:.0f} s"
print(f"[mix] PASS {detail}", flush=True)
record("mix-tor-cut", "PASS", detail)

#!/usr/bin/env python3
"""Tor going down under running nodes, with no user action and no restart, and coming back.

  PYTHONPATH=<main checkout>/scratchpad/net NET_ROOT=... NET_PORT=... NET_NODES=3 NET_NODE_BIN=... NET_WALLET_BIN=... python3 scripts/mix/mix_outage.py

Every node stays on Automatic. Each cut starts with a payment in flight. In turn: Tor stalls for 30 s on every node (lag, which must move no
one), Tor fails on every node, it returns, it fails on the one node holding the paid wallet, and it flaps on every node every 20 s under a
payment, as an attack might (each 20 s silence is lag too, so no one moves). Each payment must land on the other node's
wallet, the nodes must report the network they moved to, the chain must stay one chain, and the payer's money must add up exactly.

The cut is `MONEROUSD_TEST_TOR_OUTAGE_FILE`: the node's Tor links go silent in both directions and it has to notice. What this does not prove: an
outage the internet itself causes, where Tor's own circuits fail and rebuild; mix_cut.py covers a node starting under a real OS cut."""
import json, os, sys, time

N = int(os.environ.get("NET_NODES", "3"))
ROOT = os.environ["NET_ROOT"]
base = int(os.environ.get("NET_PORT", "29100")) + 100
faces = [f"relay:127.0.0.1:{base + i}" for i in range(N)]
cut_files = [f"{ROOT}/tor-outage-{i}" for i in range(N)]
os.environ["NET_PER_NODE"] = json.dumps({
    str(i): {
        "MONEROUSD_MIX_RELAY": faces[i],
        "MONEROUSD_MIX_SEEDS": ",".join(f for j, f in enumerate(faces) if j != i),
        "MONEROUSD_TEST_TOR_OUTAGE_FILE": cut_files[i],
    }
    for i in range(N)
})

from net import get, info, post, record, start, wait  # noqa: E402
from pay_lib import Wallet, wait_spendable  # noqa: E402

CHECK = "network-outage"
ALL = list(range(N))


def fail(why):
    record(CHECK, "FAIL", str(why)[:300])
    print(f"[outage] FAIL {why}", flush=True)
    sys.exit(1)


def cut(nodes):
    for i in nodes:
        open(cut_files[i], "w").close()


def restore(nodes):
    for i in nodes:
        if os.path.exists(cut_files[i]):
            os.remove(cut_files[i])


def reports(i):
    r = json.loads(get(i, "/network_choice"))
    if r.get("choice") != "auto":
        fail(f"node {i} left Automatic with no one asking: {r}")
    return r.get("carrying")


def wait_carrying(nodes, want, limit):
    t = time.time()
    while time.time() - t < limit:
        states = [reports(i) for i in nodes]
        if all(s == want for s in states):
            return time.time() - t
        time.sleep(1)
    fail(f"nodes {nodes} never reported {want} within {limit} s: {[reports(i) for i in nodes]}")


def one_chain(tag):
    h = [info(i).get("height", 0) for i in ALL]
    print(f"[outage] {tag}: heights {h}", flush=True)
    if max(h) - min(h) > 12 or min(h) == 0:
        fail(f"{tag}: nodes split {h}")


restore(ALL)
start()
one_chain("start")
a, b = Wallet("outage_a", 0), Wallet("outage_b", 1 % N)
fund = 3_000_000_000
r = post(0, "/faucet/drip", json.dumps({"amount": fund, "to": a.address}))
if '"published":true' not in r:
    fail(f"the faucet published nothing: {r[:200]}")
wait_spendable(a, fund, CHECK)
a.close()
wait_carrying(ALL, "tor", 180)

paid = 0
sends = 0
timings = []


def pay_through(label, action):
    """Send, do the thing with the payment in flight, and require it on the other node's wallet."""
    global paid, sends
    a.send(b.address, "1.0", CHECK)
    a.close()
    sends += 1
    action()
    paid += 100_000_000
    took = wait_spendable(b, paid, CHECK)
    b.close()
    timings.append((label, round(took)))
    print(f"[outage] {label}: the payment landed, spendable after {took:.0f} s", flush=True)
    one_chain(label)


# Tor stalls for 30 s: lag, not an outage. No node may move (user 2026-11-07: "the automatic switch must only happen in a true tor-wide
# outage not just lag").
def stall():
    cut(ALL)
    t = time.time()
    while time.time() - t < 30:
        states = [reports(i) for i in ALL]
        if any(s != "tor" for s in states):
            fail(f"a 30 s Tor stall moved nodes off Tor after {time.time() - t:.0f} s: {states}")
        time.sleep(1)
    restore(ALL)
    t = time.time()
    while time.time() - t < 30:
        states = [reports(i) for i in ALL]
        if any(s != "tor" for s in states):
            fail(f"nodes moved off Tor {time.time() - t:.0f} s after a 30 s stall ended: {states}")
        time.sleep(1)


pay_through("30 s stall", stall)
print("[outage] a 30 s Tor stall moved no node", flush=True)

# Tor fails on every node. A minute with no cell from any peer, two fresh circuits to two known onions failing, then the debounce.
moved = []
pay_through("all cut", lambda: (cut(ALL), moved.append(wait_carrying(ALL, "mix", 180))))
print(f"[outage] every node moved to our network {moved[0]:.0f} s after the cut, by itself", flush=True)
pay_through("still cut", lambda: None)

# Tor comes back.
back = []
pay_through("restored", lambda: (restore(ALL), back.append(wait_carrying(ALL, "tor", 120))))
print(f"[outage] every node back on Tor {back[0]:.0f} s after it returned", flush=True)

# Tor fails only for the node holding the paid wallet. Its peers still have Tor.
lone = 1 % N
pay_through("one node cut", lambda: (cut([lone]), wait_carrying([lone], "mix", 180)))
restore([lone])
wait_carrying(ALL, "tor", 120)

# Tor flaps under a payment.
def flap():
    for _ in range(3):
        cut(ALL)
        time.sleep(20)
        restore(ALL)
        time.sleep(20)


pay_through("flapping", flap)
pay_through("after flapping", lambda: None)

FEE = 100_000
want_a = fund - paid - sends * FEE
deadline = time.time() + 240
got_a = a.spendable()
while got_a != want_a and time.time() < deadline:
    time.sleep(5)
    got_a = a.spendable()
a.close()
if got_a != want_a:
    fail(f"money does not add up: payer holds {got_a}, should hold {want_a}")
detail = f"{timings}; moved to our network in {moved[0]:.0f} s, back on Tor in {back[0]:.0f} s; payer exact; one chain"
print(f"[outage] PASS {detail}", flush=True)
record(CHECK, "PASS", detail)

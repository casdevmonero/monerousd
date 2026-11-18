#!/usr/bin/env python3
"""Moving between Tor and our own network with nothing lost, on real nodes and real wallets, with no restart.

  PYTHONPATH=<main checkout>/scratchpad/net NET_ROOT=... NET_PORT=... NET_NODES=3 NET_NODE_BIN=... NET_WALLET_BIN=... python3 scripts/mix/mix_switch.py

Every node runs Tor and its own relay face. The script moves all of them between Auto, Tor only and Own only through the same RPC the wallet
uses, sends each payment right before a move so it is in flight during the move, then moves repeatedly under a payment. It asserts what the
paying and paid wallets hold on other nodes, that nothing forked, and that every wallet's money adds up exactly.

What this does not prove: a Tor outage arriving with no user action while a node runs. The rig has no way to cut Tor from a live process, so
that detection is exercised only from a node's start under the OS cut, in mix_cut.py."""
import json, os, sys, time

N = int(os.environ.get("NET_NODES", "3"))
base = int(os.environ.get("NET_PORT", "29100")) + 100
faces = [f"relay:127.0.0.1:{base + i}" for i in range(N)]
os.environ["NET_PER_NODE"] = json.dumps({
    str(i): {"MONEROUSD_MIX_RELAY": faces[i], "MONEROUSD_MIX_SEEDS": ",".join(f for j, f in enumerate(faces) if j != i)} for i in range(N)
})

from net import height, info, post, record, start, wait  # noqa: E402
from pay_lib import Wallet, wait_spendable  # noqa: E402


def fail(why):
    record("network-switch", "FAIL", str(why)[:300])
    print(f"[switch] FAIL {why}", flush=True)
    sys.exit(1)


def choose(choice):
    for i in range(N):
        r = post(i, "/network_choice", json.dumps({"choice": choice}))
        if f'"choice":"{choice}"' not in r:
            fail(f"node {i} refused {choice}: {r[:120]}")
    print(f"[switch] all nodes now {choice}", flush=True)


def one_chain(tag):
    h = [info(i).get("height", 0) for i in range(N)]
    print(f"[switch] {tag}: heights {h}", flush=True)
    if max(h) - min(h) > 12 or min(h) == 0:
        fail(f"{tag}: nodes split {h}")


start()
one_chain("start")
a, b = Wallet("switch_a", 0), Wallet("switch_b", 1 % N)
fund = 3_000_000_000
r = post(0, "/faucet/drip", json.dumps({"amount": fund, "to": a.address}))
if '"published":true' not in r:
    fail(f"the faucet published nothing: {r[:200]}")
wait_spendable(a, fund, "network-switch")
a.close()

paid = 0
timings = []
# Each step: pay, move with the payment still in flight, and assert it lands under the network just chosen.
for step, choice in enumerate(["own", "auto", "tor", "auto", "own", "tor", "auto"]):
    t = time.time()
    a.send(b.address, "1.0", "network-switch")
    a.close()
    choose(choice)
    paid += 100_000_000
    took = wait_spendable(b, paid, "network-switch")
    b.close()
    timings.append((choice, round(took)))
    print(f"[switch] step {step}: moved to {choice} with a payment in flight; it landed, spendable after {took:.0f} s", flush=True)
    one_chain(f"step {step}")

# Moves faster than a payment settles.
a.send(b.address, "1.0", "network-switch")
a.close()
for choice in ["own", "auto", "tor", "own", "auto", "tor", "auto"]:
    choose(choice)
    time.sleep(10)
paid += 100_000_000
took = wait_spendable(b, paid, "network-switch")
b.close()
one_chain("after rapid moves")

# Fee per send comes from the wallet's own accounting: what left it must be exactly what arrived plus flat fees.
sends = 8
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
detail = f"{timings}; rapid moves: spendable after {took:.0f} s; payer and payee exact; one chain"
print(f"[switch] PASS {detail}", flush=True)
record("network-switch", "PASS", detail)

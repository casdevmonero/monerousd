#!/usr/bin/env python3
"""A payment never names its sender's node: it leaves by push through our own network, and the sending node never announces it.

  PYTHONPATH=<main checkout>/scratchpad/net NET_ROOT=... NET_PORT=... NET_NODES=3 NET_NODE_BIN=... NET_WALLET_BIN=... python3 scripts/mix/mix_private_send.py

Every node runs Tor and its own relay face, on Automatic, Tor up. A wallet on node 0 pays a wallet on node 1 three times. Passes only when every
payment is spendable on node 1, node 0 logged a push for each and never an announce of its own, another node took each push and
announced it as its own, node 0 heard each one echoed back, and the payer's money adds up exactly.

What this does not prove: anonymity against an observer of all traffic, which needs the anonymous-broadcast rounds (spec §6d); this
proves only that the sending node is never the one that names the payment."""
import json, os, sys, time

N = int(os.environ.get("NET_NODES", "3"))
ROOT = os.environ["NET_ROOT"]
base = int(os.environ.get("NET_PORT", "29100")) + 100
faces = [f"relay:127.0.0.1:{base + i}" for i in range(N)]
os.environ["NET_PER_NODE"] = json.dumps({
    str(i): {"MONEROUSD_MIX_RELAY": faces[i], "MONEROUSD_MIX_SEEDS": ",".join(f for j, f in enumerate(faces) if j != i)} for i in range(N)
})

from net import data, info, post, record, start  # noqa: E402
from pay_lib import Wallet, wait_spendable  # noqa: E402

CHECK = "private-send"
PAYMENTS = 3


def fail(why):
    record(CHECK, "FAIL", str(why)[:300])
    print(f"[private] FAIL {why}", flush=True)
    sys.exit(1)


def count(i, text, since):
    with open(f"{data(i)}/node.log", "rb") as f:
        f.seek(since[i])
        return sum(1 for line in f if text.encode() in line)


start()
a, b = Wallet("private_a", 0), Wallet("private_b", 1 % N)
fund = 1_000_000_000
r = post(0, "/faucet/drip", json.dumps({"amount": fund, "to": a.address}))
if '"published":true' not in r:
    fail(f"the faucet published nothing: {r[:200]}")
wait_spendable(a, fund, CHECK)
a.close()

marks = [os.path.getsize(f"{data(i)}/node.log") for i in range(N)]
paid = 0
times = []
for k in range(PAYMENTS):
    a.send(b.address, "1.0", CHECK)
    a.close()
    paid += 100_000_000
    took = wait_spendable(b, paid, CHECK)
    b.close()
    times.append(round(took))
    print(f"[private] payment {k + 1}: spendable on node {1 % N} after {took:.0f} s", flush=True)

pushed = count(0, "[tx-origin] pushed this node's own transaction", marks)
echoed = count(0, "[tx-origin] the network echoed this node's own transaction", marks)
refused = count(0, "[tx-origin] ⛔ an announce of this node's own transaction was refused", marks)
taken = sum(count(i, "[tx-origin] took a pushed transaction", marks) for i in range(1, N))
taken_on_0 = count(0, "[tx-origin] took a pushed transaction", marks)
print(f"[private] node 0 pushed {pushed}, heard {echoed} echoed, refused {refused} announce(s) of its own; other nodes took {taken} push(es)", flush=True)
if pushed < PAYMENTS:
    fail(f"node 0 pushed {pushed} of {PAYMENTS} payments")
if echoed < PAYMENTS:
    fail(f"node 0 heard {echoed} of {PAYMENTS} payments echoed back")
if taken < PAYMENTS:
    fail(f"other nodes took {taken} of {PAYMENTS} pushes")
if taken_on_0:
    fail(f"node 0 took {taken_on_0} push(es) of its own payments, which means it pushed to itself")

FEE = 100_000
want_a = fund - paid - PAYMENTS * FEE
deadline = time.time() + 240
got_a = a.spendable()
while got_a != want_a and time.time() < deadline:
    time.sleep(5)
    got_a = a.spendable()
a.close()
if got_a != want_a:
    fail(f"money does not add up: payer holds {got_a}, should hold {want_a}")
detail = f"spendable after {times} s; node 0 pushed {pushed}, announced none of its own, heard {echoed} echoes; others took {taken}; payer exact"
print(f"[private] PASS {detail}", flush=True)
record(CHECK, "PASS", detail)

#!/usr/bin/env python3
"""Tamper checks on a running mix network: a real neighbour attacks a real node, and the node's own counters must show the refusal.
mix_cut.py runs this while its Unix-socket network is up. Each row in attacks.txt named mix-* is one attack here. A Sybil-heavy path
choice is pinned in src/pqmix/view.rs and has no row here, because one machine has no way to stand for many operators."""
import json, os, subprocess, sys, time

ATTACK = os.environ.get("MIX_ATTACK_BIN", os.path.expanduser("~/.cargo-targets/mix/release/mix_attack"))
from net import data, record  # noqa: E402


def status():
    for base, _, files in os.walk(data(0)):
        if "mix-status.json" in files:
            return json.load(open(os.path.join(base, "mix-status.json")))
    sys.exit("[mix-attacks] node 0 has no status file; raise the network first")


SOCK = os.environ["MIX_VICTIM_SOCK"]


def run(name, arg, counter, expect):
    before = status()
    r = subprocess.run([ATTACK, SOCK, arg], capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        record(name, "FAIL", f"the attacker itself failed: {r.stderr[-200:]}")
        sys.exit(f"[mix-attacks] FAIL {name}: {r.stderr[-300:]}")
    time.sleep(7)  # the status file is rewritten every 5 s
    after = status()
    moved = after[counter] - before[counter]
    if moved < expect:
        record(name, "FAIL", f"{counter} moved {moved}, needed {expect}")
        sys.exit(f"[mix-attacks] FAIL {name}: the node recorded no refusal: {counter} {before[counter]} -> {after[counter]}")
    print(f"[mix-attacks] PASS {name}: {counter} {before[counter]} -> {after[counter]}", flush=True)
    record(name, "PASS", f"{counter} moved {moved} on the running node")


run("mix-replay", "replay", "replays", 1)
run("mix-tag", "tag", "tagged", 1)
run("mix-forged-header", "forged-header", "bad_mac", 1)
run("mix-forged-record", "forged-record", "records_refused", 1)
run("mix-ip-record", "ip-record", "records_refused", 1)
run("mix-unknown-frame", "unknown-frame", "frames_unknown", 1)

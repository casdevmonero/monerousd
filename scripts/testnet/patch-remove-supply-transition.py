#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Cycle 1 — remove the v42 supply-transition consensus core (4 edits).
# Each edit is anchored + asserted (exactly-one-match, expected content present) so it
# either applies cleanly or aborts loudly with NO partial state. Run ON the VPS.
import re, sys, os

BASE = "/root/MoneroUSD-clean/monero/src"

def read(p):
    with open(os.path.join(BASE, p), encoding="utf-8") as f:
        return f.read()

def write(p, s):
    with open(os.path.join(BASE, p), "w", encoding="utf-8") as f:
        f.write(s)

def cut(p, start, end, must_contain):
    """Remove s[i:j] where i=start anchor, j=start of end anchor. Assert uniqueness + content."""
    s = read(p)
    assert s.count(start) == 1, f"[{p}] start anchor not unique ({s.count(start)}): {start[:50]!r}"
    i = s.index(start)
    j = s.index(end, i)
    chunk = s[i:j]
    for m in must_contain:
        assert m in chunk, f"[{p}] expected {m!r} inside removed chunk"
    # safety: the end anchor must be the very next line-group, not miles away
    assert j - i < 4000, f"[{p}] removal span suspiciously large ({j-i} bytes)"
    write(p, s[:i] + s[j:])
    print(f"OK  {p}: cut {j-i} bytes (anchor {start[:46]!r})")

def regex_cut(p, pattern, must_change=True):
    s = read(p)
    s2, n = re.subn(pattern, "", s, count=1)
    assert n == 1, f"[{p}] regex matched {n} times (want 1): {pattern[:50]}"
    if must_change:
        assert s2 != s
    write(p, s2)
    print(f"OK  {p}: regex-cut /{pattern[:46]}/")

# ── 1. PRODUCER: drop the 0x2C supply-transition attach in construct_miner_tx ──
cut("cryptonote_core/cryptonote_tx_utils.cpp",
    "      // ── MoneroUSD PQ transition (v>=HF_VERSION_PQ_TRANSITION): per-block state-commitment carrier",
    "      // 8. Finalize tx header.",
    ["sisopen_prove", "TX_EXTRA_TAG_SUPPLY_TRANSITION"])

# ── 2. VERIFY: drop the v42 supply-transition verify block (KEEP v32 above, IVC below) ──
cut("cryptonote_core/blockchain.cpp",
    "    // PQ transition (v>=HF_VERSION_PQ_TRANSITION): verify the per-block state-commitment transition.",
    "    // ── #30 Path A · B3: IVC STEP PROOF validation",
    ["verify_supply_transition", "missing/short state-transition (0x2C)"])

# ── 3. THREADING: drop the cm_state header-digest threading in create_block_template ──
cut("cryptonote_core/blockchain.cpp",
    "  // PQ transition (v>=HF_VERSION_PQ_TRANSITION): set the header state-commitment digest =",
    "#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)",
    ["compute_next_cm_state", "b.cm_state = cs"])

# ── 4. HEADER: drop the cm_state field + its gated serialization ──
regex_cut("cryptonote_basic/cryptonote_basic.h",
          r"\n *crypto::hash cm_state;[^\n]*")
regex_cut("cryptonote_basic/cryptonote_basic.h",
          r"\n *if \(major_version >= HF_VERSION_PQ_TRANSITION\)[^\n]*\n *FIELD\(cm_state\)")

print("\nAll 4 consensus-core edits applied cleanly.")

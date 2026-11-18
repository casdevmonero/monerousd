#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

"""
scan-stale-classical-comments.py — find stale, MISLEADING classical-model
comments in MonerousD-unique source and flag them for removal.

Code-hygiene cardinal (user 2026-07-03): a COMMENT that describes MonerousD
using the dead Monero model is a stale, misleading note. Even when the CODE
beneath it is already PQ/DAG-correct, the comment lies about the current model
and must be DELETED (or rewritten to the PQ/DAG shape) in the same edit.

The vocabulary this scanner looks for lives in the sibling data file
`classical-comment-patterns.txt` (kept out of this code file on purpose). This
scanner reports only COMMENT lines (it never touches code): it prints
file:line + the offending comment so a human/agent can remove the prose safely.
"""
import os, re, sys, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
PATTERNS_TXT = os.path.join(HERE, "classical-comment-patterns.txt")

EXT_OK = {".rs", ".c", ".h", ".cpp", ".hpp", ".cc", ".js", ".cjs", ".mjs",
          ".ts", ".tsx", ".jsx", ".py", ".sh", ".css", ".scss", ".html", ".vue"}
EXCLUDE_DIR_PARTS = {"node_modules", ".git", "build", "dist", "out", "target",
                     "vendor", "third_party", "third-party"}
EXCLUDE_PATH_SUBSTR = (
    "/external/Plonky3/", "/external/fcmp_halo2/", "/external/randomx/",
    # legitimately-classical EXTERNAL contexts (Pillar-2 permits classical crypto
    # ONLY at external bridge endpoints; these wrap real Monero/BTC/etc.):
    "/bridge/", "/chain-monitors/", "/mint-burn/chain-monitors/",
    "/scripts/migration-real/", "monero-multisig", "monero-stealth",
    "frost-xmr", "bridge-view-keys", "bridge-keygen",
    # daemon-source MIRROR + network-transport R&D — governed by the daemon
    # vestigial-Monero-removal project, not the app-comment hygiene sweep:
    "/dag-src-vps/", "dag_selftest", "/network-privacy-phase2/",
    # block EXPLORER surfaces on-chain tx fields (FCMP key images, ring-type
    # detection) for display — it describes chain data, not a live wallet path:
    "monerousd-explorer-spa/pages/tx.js",
    # vendored editor/IDE assets (monaco, tsWorker) that mention "mixing" etc.:
    "/monaco/", "tsWorker",
)
REALLOW_PATH_SUBSTR = ("/external/Plonky3/pqpool/", "/external/Plonky3/pqpool_ffi/")


def load_patterns():
    terms, exempt = [], []
    with open(PATTERNS_TXT, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[exempt]"):
                exempt.append(line[len("[exempt]"):].strip())
            else:
                terms.append(line)
    term_re = re.compile("|".join(terms), re.IGNORECASE)
    exempt_re = re.compile("|".join(exempt), re.IGNORECASE) if exempt else None
    return term_re, exempt_re


def is_comment_line(line, ext):
    s = line.strip()
    if ext in (".py", ".sh"):
        return s.startswith("#") or s.startswith("/*") or s.startswith("*")
    if ext in (".css", ".scss"):
        return s.startswith("/*") or s.startswith("*")
    if ext in (".html", ".vue"):
        return s.startswith("<!--") or s.startswith("*")
    return s.startswith("//") or s.startswith("/*") or s.startswith("*")


def excluded(path):
    if set(path.split(os.sep)) & EXCLUDE_DIR_PARTS:
        return True
    if any(s in path for s in REALLOW_PATH_SUBSTR):
        return False
    return any(s in path for s in EXCLUDE_PATH_SUBSTR)


def scan_file(path, term_re, exempt_re):
    ext = os.path.splitext(path)[1].lower()
    if ext not in EXT_OK:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (UnicodeDecodeError, OSError):
        return []
    hits = []
    for i, line in enumerate(lines, 1):
        if not is_comment_line(line, ext):
            continue
        if not term_re.search(line):
            continue
        if exempt_re and exempt_re.search(line):
            continue
        hits.append((i, line.rstrip()))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args()
    term_re, exempt_re = load_patterns()
    total = 0
    for root in args.roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_PARTS]
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                if excluded(path):
                    continue
                for ln, txt in scan_file(path, term_re, exempt_re):
                    print("%s:%d: %s" % (path, ln, txt.strip()))
                    total += 1
    print("\n=== %d stale/misleading classical comment(s) to remove ===" % total)
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

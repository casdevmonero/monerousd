# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - SITE SELECTION and PIN SELECTION.

Two selections, and the honesty of the whole engine rests on both.

SITE SELECTION answers "which lines are worth mutating?". Mutating everything is the textbook
answer and it is useless here: it costs a full rebuild per mutant and it spends that cost on
constructors and getters, where a survivor means nothing. This engine targets CHECK-BEARING lines
only - refusals, bounds, comparisons and logical conjunctions inside functions that verify, admit or
refuse. That is where an undefended invariant can actually hide.

PIN SELECTION answers "which of our tests CLAIM to cover this site?". The claim is textual and
deliberately so: a pin that never names the function it is supposed to defend is not covering it by
any reading a human would accept. Three tiers, in order of strength:

  tier 0  the pin lives in the same file as the mutated code  (module-local pins)
  tier 1  the pin's body names the mutated function
  tier 2  the pin's body names the mutated module

A SURVIVED verdict from this subset is therefore a precise claim, and the manifest states it in
those words: *no pin that claims this site noticed the change*. It is NOT the claim "the whole suite
misses it" - that stronger claim needs the full-suite re-run, which `--verify-survivors` performs and
records separately. Conflating the two would be the kind of overstatement this instrument exists to
prevent.
"""

import re

import operators
import rustsrc

# A function worth mutating: it decides something. Either its return type is a verdict, or its body
# refuses, or its name says it checks.
VERDICT_RET_RE = re.compile(r"^(bool|Result<|Option<|ConsensusResult|MempoolResult)")
# ⛔ THE LEXICON IS THE DESIGN'S (Part C.9), AND FOUR OF ITS WORDS WERE MISSING.
# MEASURED 2026-09-08: `accept`, `refus`, `authoris` and `justif` are named in C.9's selection rule
# and were absent here, so `accept_fetched_record`, `accept_verified`, `accept_bundle` and
# `accept_fetched_root_run` — four DOORS, one of them the site of calibration row C-H1 — were not
# check-bearing functions to this engine and could not be selected as sites at any budget. `adopt` is
# added with them because the adopt gate is a first-class door in this tree (rows D-2/D-3/C-H2 all
# live behind one) and the same reasoning applies to it word for word.
CHECKING_NAME_RE = re.compile(
    r"(verify|valid|check|admit|admissible|accept|adopt|refus|reject|authoris|justif|"
    r"meets|binds?|allow|guard|door|gate|"
    r"^is_|_is_|^has_|_has_|^can_|_can_|within|bound|conserv|sound|match)")
REFUSAL_TOKENS = ("return false", "return None", "return Err(", "panic!(", "unreachable!(")

# A line is check-bearing when it does one of these. Everything else is plumbing.
GUARD_LINE_RE = re.compile(r"^[ \t]*(\}\s*else\s+)?if\s+.+\{\s*$")
COMPARISON_RE = re.compile(r" (==|!=|<=|>=|<|>) ")
LOGIC_RE = re.compile(r" (&&|\|\|) ")
RETURN_BOOL_RE = re.compile(r"^[ \t]*return (true|false);\s*$")

SITE_RANK = {
    "fail_closed_guard": 0,
    "refusal_return": 1,
    "comparison": 2,
    "logic": 3,
    "bound": 4,
    "flow_guard": 5,
    "accept_return": 6,
}


def module_of(relpath):
    """`src/pow.rs` -> `pow`. Nested paths keep their directory as the first segment."""
    p = relpath
    if p.startswith("src/"):
        p = p[4:]
    if p.endswith(".rs"):
        p = p[:-3]
    if p.endswith("/mod"):
        p = p[:-4]
    return p.replace("/", "::")


def is_checking_fn(rf, fn):
    if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
        return False
    body = rf.body_text(fn)
    if VERDICT_RET_RE.match(fn["ret"].strip()):
        return True
    if any(t in body for t in REFUSAL_TOKENS):
        return True
    if CHECKING_NAME_RE.search(fn["name"]):
        return True
    return False


def _guard_kind(rf, idx):
    """Does this `if` guard a REFUSAL, or just control flow?"""
    line = rf.masked[idx]
    col = line.rfind("{")
    if col < 0:
        return "flow_guard"
    end = rf.match_block_from(idx, col)
    if end is None:
        return "flow_guard"
    block = "\n".join(rf.lines[idx:min(end, idx + 16) + 1])
    for t in REFUSAL_TOKENS:
        if t in block:
            return "fail_closed_guard"
    return "flow_guard"


def sites_in_file(rf, focus_fns=(), focus_only=False):
    """Every check-bearing line inside every check-bearing function of `rf`.

    `focus_only` IS WHAT MAKES A 46,000-LINE FILE AFFORDABLE, and it is a scope declaration rather
    than a budget. MEASURED 2026-09-08: `node.rs` carries 653 check-bearing sites across 124
    check-bearing functions. Selecting over all of them and then truncating at a per-file budget is
    the N-2 defect the calibration named - the budget silently decides which door stays measured, in
    file order, and the most safety-critical guard in the file is usually not in the first twelve
    lines. Naming the doors instead means the target says WHICH doors it measures, the manifest
    records it, and a door outside the list is visibly unmeasured rather than invisibly truncated.
    """
    out = []
    focus = set(focus_fns or ())
    for fn in rf.fns:
        if focus_only and fn["name"] not in focus:
            continue
        if not is_checking_fn(rf, fn):
            continue
        for idx in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(idx):
                continue
            raw = rf.lines[idx]
            masked = rf.masked[idx]
            if masked.strip() == "" or masked.strip().startswith("//"):
                continue
            if raw.strip().startswith("///") or raw.strip().startswith("//"):
                continue
            kinds = []
            if GUARD_LINE_RE.match(masked):
                kinds.append(_guard_kind(rf, idx))
            if RETURN_BOOL_RE.match(masked):
                kinds.append("refusal_return" if "false" in masked else "accept_return")
            if COMPARISON_RE.search(masked):
                kinds.append("comparison")
            if LOGIC_RE.search(masked):
                kinds.append("logic")
            if not kinds:
                continue
            kind = sorted(kinds, key=lambda k: SITE_RANK.get(k, 9))[0]
            out.append({
                "file": rf.relpath,
                "line": idx,
                "fn": fn["name"],
                "kind": kind,
                "focus": fn["name"] in focus,
            })
    return out


def mutants_for_file(rf, focus_fns=(), cap=12, ops_filter=None, focus_only=False):
    """Selected sites -> concrete mutants, ranked, deduplicated and capped.

    Ranking is deterministic: focus functions first, then site strength (a fail-closed guard beats a
    stray comparison), then file order. The cap is what makes this runnable nightly; it is recorded
    in the manifest so a score is never mistaken for a full census.
    """
    sites = sites_in_file(rf, focus_fns, focus_only)
    sites.sort(key=lambda s: (0 if s["focus"] else 1, SITE_RANK.get(s["kind"], 9), s["line"]))
    seen = set()
    out = []
    for site in sites:
        for opfn in operators.ALL_LINE_OPS:
            for m in opfn(rf, site):
                if ops_filter and m.op not in ops_filter:
                    continue
                if m.mutant_id in seen:
                    continue
                seen.add(m.mutant_id)
                out.append((site, m))
    # The predicate-body probe, per checking bool function.
    focus_set = set(focus_fns or ())
    focus_body, other_body = [], []
    for fn in rf.fns:
        if not is_checking_fn(rf, fn):
            continue
        for m in operators.body_ops(rf, fn):
            if ops_filter and m.op not in ops_filter:
                continue
            if m.mutant_id in seen:
                continue
            seen.add(m.mutant_id)
            (focus_body if fn["name"] in focus_set else other_body).append(m)
    # ⭐ THE SEMANTIC OPERATORS (semantic.py) — the ones named after faults this tree produced.
    # They are ranked ABOVE the generic line operators on purpose: the 2026-09-08 calibration measured
    # the generic set at 2 of the 5 rows lane M owns, and all three misses (B1, B4, C-H1) are shapes no
    # generic operator can express. A small budget spent on `guard_disable` at a stray comparison while
    # an M4 write into the double-spend set three lines away goes unmeasured is a budget spent wrongly.
    # Import is local so the generic engine keeps working if this module is ever removed.
    import semantic
    sem_focus, sem_other = [], []
    for opfn in semantic.ALL_SEMANTIC_OPS:
        for m in opfn(rf, focus_fns):
            if ops_filter and m.op not in ops_filter:
                continue
            if m.mutant_id in seen:
                continue
            seen.add(m.mutant_id)
            (sem_focus if m.fn_name in set(focus_fns or ()) else sem_other).append(m)
    sem_focus.sort(key=lambda m: m.a)
    sem_other.sort(key=lambda m: m.a)
    focus_body.sort(key=lambda m: m.a)
    other_body.sort(key=lambda m: m.a)
    # ORDER MATTERS WHEN THE BUDGET IS SMALL, so it is stated rather than incidental:
    #   1. the vacuity probe on the functions this target names as its focus
    #   2. the SEMANTIC operators on those same focus functions
    #   3. the semantic operators everywhere else in the file
    #   4. the generic line mutants, refusal guards first
    #   5. the vacuity probe on every other checking predicate
    # Putting all body probes first would spend a small budget on `is_empty` and `contains` while a
    # real fail-closed guard three lines away went unmeasured; putting the generic operators above the
    # semantic ones would spend it on comparisons while the write into the double-spend set went
    # unmeasured, which is calibration row B2 exactly.
    merged = focus_body + sem_focus + sem_other + [m for (_s, m) in out] + other_body
    return merged[:cap] if cap else merged


# ── PIN SELECTION ─────────────────────────────────────────────────────────────────────────────────

WORD = r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])"


class PinIndex(object):
    """Every oracle function in the crate, with the file it lives in and its body text."""

    def __init__(self, files):
        self.by_leaf = {}        # leaf fn name -> list of (relpath, body)
        for rf in files:
            for fn in rf.fns:
                if not fn["is_oracle_fn"]:
                    continue
                self.by_leaf.setdefault(fn["name"], []).append((rf.relpath, rf.body_text(fn)))
        self.paths = []          # authoritative libtest paths, filled from `--list`
        self.leaf_of = {}

    def load_libtest_paths(self, paths):
        self.paths = list(paths)
        for p in paths:
            self.leaf_of[p] = p.split("::")[-1]

    def file_of(self, path):
        leaf = self.leaf_of.get(path, path.split("::")[-1])
        entries = self.by_leaf.get(leaf, [])
        if not entries:
            return None
        if len(entries) == 1:
            return entries[0][0]
        head = path.split("::")[0]
        for (relpath, _body) in entries:
            if module_of(relpath).split("::")[0] == head:
                return relpath
        return entries[0][0]

    def body_of(self, path):
        leaf = self.leaf_of.get(path, path.split("::")[-1])
        entries = self.by_leaf.get(leaf, [])
        relpath = self.file_of(path)
        for (rp, body) in entries:
            if rp == relpath:
                return body
        return ""

    def pins_for(self, relpath, fn_name, cap=25):
        """The pins that CLAIM the site, strongest tier first. Returns (paths, tiers)."""
        mod = module_of(relpath)
        fn_re = re.compile(WORD % re.escape(fn_name))
        mod_re = re.compile(WORD % re.escape(mod.split("::")[-1]) + r"::")
        tier0, tier1, tier2 = [], [], []
        for path in self.paths:
            body = self.body_of(path)
            f = self.file_of(path)
            if f == relpath:
                tier0.append(path)
            elif fn_re.search(body):
                tier1.append(path)
            elif mod_re.search(body):
                tier2.append(path)
        chosen = tier0 + tier1 + tier2
        tiers = {}
        for p in tier0:
            tiers[p] = 0
        for p in tier1:
            tiers[p] = 1
        for p in tier2:
            tiers[p] = 2
        return chosen[:cap], tiers

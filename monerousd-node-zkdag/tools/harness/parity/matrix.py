#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""THE PARITY MATRIX - a door x check matrix whose EMPTY CELLS ARE THE FINDING.

I-11 DOOR PARITY, stated by `docs/harness-design.md`: for a class of object, all doors that admit it
must reach the same verdict on the same bytes. A check one door runs and another does not is a hole
until proven otherwise, and the proof must be a *reason the check is not computable there*, never
"should be unreachable".

This generator is the static half of that instrument. It reads production Rust with the lane-M
reader (`tools/harness/mutate/rustsrc.py` - function spans, brace matching with literals masked,
cfg(test) exclusion), resolves each door's call closure, and prints the matrix. Every empty cell is
handed on as a differential-test candidate: same bytes, both doors, verdicts must match.

FOUR RULES MAKE IT HONEST, and each is enforced in code rather than asserted in a comment:

1. A COMMENT CAN NEVER FILL A CELL. Cells are filled from `RustFile.masked`, in which `//`, `///`
   and `/* */` regions are blanked. A door whose doc comment discusses `verify_block_pow` at length
   while its body never calls it scores EMPTY - which is the shape of the 2026-09-07 PoW hole.

2. AN UNPROVEN REACHABILITY CLAIM IS AN EMPTY CELL, NOT A FILLED ONE. `claim_lines()` finds claim
   language in the door's comments and the cell is annotated `EMPTY (unproven reachability claim)`.
   There is no code path anywhere in this file by which a claim can raise a cell to FILLED.

3. THE ONLY LEGITIMATE EMPTY IS A NAMED EXEMPTION WITH A NON-COMPUTABILITY REASON. An exemption
   whose reason is itself reachability language is REFUSED (`REFUSED-EXEMPTION`) and the cell stays
   EMPTY and is still reported as a finding.

4. WHERE THE READER IS UNSURE IT BIASES TOWARD EMPTY. Call edges are followed only through receivers
   it can resolve honestly (`self.`, `Self::`, `crate::a::b::`, bare free fn). `x.foo()` on any other
   receiver is recorded UNRESOLVED and not followed. An unresolved edge can only cost the matrix a
   FILLED cell, i.e. produce a candidate hole somebody must disprove - never hide one.

SELF-PROOF (`selfproof` subcommand). The design names E-8 as this generator's own calibration:
"if the matrix generator does not produce this exact empty cell when run against
`node.rs.preDescentLane-20260907`, the generator is wrong." The self-proof runs the matrix against
that file, requires (graft_wanted_block_shell x pow_verified) EMPTY against a FILLED
(preverify_block x pow_verified), requires the SAME door's tx_merkle and parents_present cells FILLED
so the empty cell cannot be a reader that simply sees nothing, and then runs the CURRENT tree and
requires the cell to have CLOSED. A generator that reported empty everywhere would pass a one-sided
check; it cannot pass this one.

USAGE
    matrix.py selfproof                     # the E-8 calibration - run this before trusting a report
    matrix.py report                        # the whole matrix over the current tree
    matrix.py report --class block          # one class
    matrix.py report --at src/node.rs.preDescentLane-20260907=src/node.rs
    matrix.py report --json out.json

EXIT CODES
    0  no empty cells (or `--no-fail`)
    1  at least one EMPTY cell - the finding
    2  the door table is wrong (a listed door does not exist, an exemption was refused)
    3  selfproof FAILED - the generator is not trustworthy and no report from it may be cited
"""

import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, os.pardir, "mutate"))
import rustsrc  # noqa: E402  (the lane-M reader, reused verbatim)

REPO = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir, os.pardir))

# ---------------------------------------------------------------------------------------------
# Call extraction
# ---------------------------------------------------------------------------------------------

# `name(` with whatever qualifies it captured to its left. Run over MASKED lines only.
CALL_RE = re.compile(
    r"(?P<qual>(?:[A-Za-z_][A-Za-z0-9_]*\s*(?:::|\.)\s*)*)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*::\s*<[^<>;{}]*>)?"
    r"\s*\("
)

# Rust keywords that are followed by `(` and are not calls.
NOT_CALLS = frozenset(
    "if while for match return fn let else in as move ref mut where impl unsafe "
    "loop break continue await async const static type use mod pub struct enum trait".split()
)

# Language constructs that look like a qualified call but never resolve to a fn in this tree.
QUAL_SKIP_PREFIXES = ("Some", "Ok", "Err", "None", "Vec", "Box", "String", "Result", "Option")

# The claim language rule 2 exists for. Deliberately broad: a false positive costs one annotation
# line, a false negative silently converts a hole into a green cell.
REACHABILITY_CLAIM_RE = re.compile(
    r"should\s+be\s+unreachable"
    r"|(?:is|are)\s+unreachable"
    r"|unreachable\s+(?:here|by\s+construction|in\s+practice)"
    r"|cannot\s+(?:have\s+)?(?:passed|reach|get\s+here|happen|arrive)"
    r"|can\s?not\s+(?:have\s+)?(?:passed|reach|get\s+here|happen)"
    r"|never\s+(?:reaches|reached|gets\s+here|happens)"
    r"|(?:should|will)\s+never\s+(?:happen|be\s+reached|get\s+here)"
    r"|already\s+(?:been\s+)?(?:checked|verified|validated)\s+by\s+(?:the\s+)?caller"
    r"|the\s+caller\s+(?:has\s+)?already\s+(?:checked|verified|validated)"
    r"|precheck(?:ed)?\s+by\s+(?:its|the)\s+caller",
    re.IGNORECASE,
)


FIELD_HOP_RE = re.compile(r"^(?:self\.)?[a-z_][a-z0-9_]*\.$")


def resolvable(qual, follow_field_hops=False):
    """Rule 4. How far this reader will follow a call, and how sure it is when it does.

    Returns "certain", "guess" or None.

    CERTAIN - `f()`, `self.f()`, `Self::f()`, `crate::a::b::f()`. The callee is named outright or
    lives on the same `self`; resolving it by name is not a guess.

    GUESS - one field hop, `self.node.f()` / `pp.f()`, and ONLY when the caller asks for it. This
    reader has no type information, so `self.node.accept_fetched_record` is resolved by NAME alone.
    That is right far more often than not in this tree, and it is still a guess: every cell filled
    through such a hop is printed `[AMBIGUOUS HOP - verify by hand]`, and the two readings are
    reported SEPARATELY and never summed - the same discipline this project applies to permissive
    and restrictive mutation scores.

    None - UNRESOLVED (`a().f()`, `Type::f()`, deeper chains). Not followed, but COUNTED: an empty
    cell on a door with unresolved hops is a weaker finding than one on a fully-resolved door, and
    the report says which it is rather than presenting both as the same colour.
    """
    q = re.sub(r"\s+", "", qual or "")
    if q == "" or q in ("self.", "Self::") or q.startswith("crate::"):
        return "certain"
    if follow_field_hops and FIELD_HOP_RE.match(q):
        return "guess"
    return None


def calls_in(rf, fn):
    """Every call in a function body, over MASKED lines. Returns [(name, qual, line_no_1based)]."""
    out = []
    for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
        line = rf.masked[i]
        if "(" not in line:
            continue
        for m in CALL_RE.finditer(line):
            name = m.group("name")
            if name in NOT_CALLS:
                continue
            qual = m.group("qual") or ""
            head = qual.split(":")[0].split(".")[0]
            if head in QUAL_SKIP_PREFIXES:
                continue
            out.append((name, qual, i + 1))
    return out


def claim_lines(rf, fn):
    """Rule 2. Reachability-claim language in the door's own comments and its doc block above it."""
    hits = []
    start = fn["sig_idx"]
    j = start - 1
    while j >= 0 and (rf.lines[j].strip().startswith("//") or rf.lines[j].strip() == ""):
        start = j
        j -= 1
    for i in range(start, fn["body_end_idx"] + 1):
        raw = rf.lines[i]
        if "//" not in raw and "/*" not in raw and "*" not in raw:
            continue  # not a comment line
        m = REACHABILITY_CLAIM_RE.search(raw)
        if m:
            hits.append((i + 1, raw.strip()[:160]))
    return hits


# ---------------------------------------------------------------------------------------------
# The index: every production fn in the scanned files, by name
# ---------------------------------------------------------------------------------------------


class Index(object):
    def __init__(self, files, at_map):
        self.files = []
        self.by_name = {}
        self.at_map = at_map or {}
        for rel in files:
            actual = self.at_map.get(rel, rel)
            full = os.path.join(REPO, actual)
            if not os.path.exists(full):
                continue
            with open(full, "r", errors="replace") as fh:
                rf = rustsrc.RustFile(rel, fh.read())
            rf.scanned_path = actual
            self.files.append(rf)
            for fn in rf.fns:
                # Rule 1's companion: a test is never a door and never a resolution target.
                if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                    continue
                self.by_name.setdefault(fn["name"], []).append((rf, fn))
        self._calls = {}

    def calls_of(self, rf, fn):
        key = (rf.relpath, fn["sig_idx"])
        if key not in self._calls:
            self._calls[key] = calls_in(rf, fn)
        return self._calls[key]

    def find(self, name, relpath=None):
        cands = self.by_name.get(name, [])
        if relpath:
            same = [c for c in cands if c[0].relpath == relpath]
            if same:
                return same
        return cands


def closure(index, rf0, fn0, max_depth, follow_field_hops=False):
    """BFS over resolvable call edges.

    Returns (seen, unresolved) where seen is {(relpath, sig_idx): (rf, fn, depth, trail)} and
    unresolved is the list of call sites the reader declined to follow. `unresolved` is not
    bookkeeping: it is what tells a reader of the matrix whether an EMPTY cell is a fully-resolved
    absence or a limit of the reader, and the report prints it beside every empty cell.
    """
    start = (rf0.relpath, fn0["sig_idx"])
    seen = {start: (rf0, fn0, 0, [])}
    unresolved = []
    frontier = [(rf0, fn0, 0, [])]
    while frontier:
        rf, fn, d, trail = frontier.pop(0)
        if d >= max_depth:
            continue
        for (name, qual, line) in index.calls_of(rf, fn):
            how = resolvable(qual, follow_field_hops)
            if how is None:
                if index.by_name.get(name):
                    # A production fn of this name EXISTS; only the receiver stopped the reader.
                    unresolved.append({"call": (qual + name).replace(" ", ""),
                                       "at": "%s:%d" % (rf.scanned_path, line),
                                       "in_fn": fn["name"]})
                continue
            targets = index.find(name, rf.relpath)
            if not targets:
                continue
            ambiguous = (len(targets) > 1) or (how == "guess")
            for (trf, tfn) in targets:
                key = (trf.relpath, tfn["sig_idx"])
                if key in seen:
                    continue
                hop = {
                    "from": "%s:%s" % (rf.relpath, fn["name"]),
                    "call": (qual + name).replace(" ", ""),
                    "at": "%s:%d" % (rf.scanned_path, line),
                    "ambiguous": ambiguous,
                }
                nt = trail + [hop]
                seen[key] = (trf, tfn, d + 1, nt)
                frontier.append((trf, tfn, d + 1, nt))
    return seen, unresolved


# ---------------------------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------------------------

FILLED = "FILLED"
EXEMPT = "EXEMPT"
EMPTY = "EMPTY"


def exemption_for(table, cls, door, check):
    for ex in table.get("exemptions", []):
        if ex.get("class") == cls and ex.get("door") == door and ex.get("check") == check:
            return ex
    return None


def build(table, cls_name, at_map, only_door=None, follow_field_hops=False):
    cls = table["classes"][cls_name]
    max_depth = table.get("max_call_depth", 6)
    index = Index(cls["files"], at_map)
    checks = [(c, table["checks"][c]) for c in cls["checks"]]

    rows = []
    problems = []
    for spec in cls["doors"]:
        if only_door and spec["fn"] != only_door:
            continue
        found = index.find(spec["fn"], spec["file"])
        if not found:
            if not spec.get("optional"):
                problems.append(
                    "DOOR TABLE WRONG: %s::%s is listed as a door of class '%s' and does not exist "
                    "in the scanned tree." % (spec["file"], spec["fn"], cls_name)
                )
            rows.append({"door": spec["fn"], "file": spec["file"], "role": spec.get("role", ""),
                         "absent": True, "cells": {}})
            continue
        rf0, fn0 = found[0]
        if len(found) > 1:
            problems.append(
                "AMBIGUOUS DOOR: %d functions named %s in %s; scored the first at line %d."
                % (len(found), spec["fn"], spec["file"], fn0["sig_idx"] + 1)
            )
        cl, unresolved = closure(index, rf0, fn0, max_depth, follow_field_hops)
        claims = claim_lines(rf0, fn0)

        # Every call name reachable from this door, with where it was seen and how far in.
        reach = {}
        for (trf, tfn, d, trail) in cl.values():
            for (name, qual, line) in index.calls_of(trf, tfn):
                prev = reach.get(name)
                if prev is None or d < prev["depth"]:
                    reach[name] = {
                        "depth": d,
                        "site": "%s:%d" % (trf.scanned_path, line),
                        "in_fn": tfn["name"],
                        "call": (qual + name).replace(" ", ""),
                        "trail": trail,
                        "ambiguous": any(h["ambiguous"] for h in trail),
                    }

        cells = {}
        for (cname, cspec) in checks:
            hit = None
            for sym in cspec["symbols"]:
                h = reach.get(sym)
                if h is not None and (hit is None or h["depth"] < hit["depth"]):
                    hit = dict(h, symbol=sym)
            if hit is not None:
                cells[cname] = {
                    "state": FILLED,
                    "symbol": hit["symbol"],
                    "site": hit["site"],
                    "in_fn": hit["in_fn"],
                    "depth": hit["depth"],
                    "via": [h["call"] for h in hit["trail"]],
                    "ambiguous": hit["ambiguous"],
                }
                continue

            ex = exemption_for(table, cls_name, spec["fn"], cname)
            if ex is not None:
                reason = ex.get("noncomputable_because", "")
                if not reason.strip():
                    problems.append("REFUSED-EXEMPTION (%s x %s): no noncomputable_because given."
                                    % (spec["fn"], cname))
                    ex = None
                elif REACHABILITY_CLAIM_RE.search(reason):
                    # Rule 3, in code.
                    problems.append(
                        "REFUSED-EXEMPTION (%s x %s): the reason is a REACHABILITY CLAIM, not a "
                        "reason of non-computability. The cell stays EMPTY." % (spec["fn"], cname)
                    )
                    ex = None
            if ex is not None:
                cells[cname] = {"state": EXEMPT, "reason": ex["noncomputable_because"]}
                continue

            cells[cname] = {"state": EMPTY, "claims": claims, "unresolved": len(unresolved)}

        rows.append({
            "door": spec["fn"], "file": spec["file"], "role": spec.get("role", ""),
            "line": fn0["sig_idx"] + 1, "absent": False, "cells": cells,
            "claims": claims, "unresolved": unresolved, "closure_size": len(cl),
        })

    return {"class": cls_name, "checks": [c for c, _ in checks], "check_specs": dict(checks),
            "rows": rows, "problems": problems, "field_hops": follow_field_hops,
            "files": [rf.scanned_path for rf in index.files]}


# ---------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------

GLYPH = {FILLED: "X", EXEMPT: "~", EMPTY: "."}


def render(m, table, verbose=False):
    out = []
    cls = table["classes"][m["class"]]
    out.append("")
    out.append("=" * 100)
    out.append("CLASS '%s' - %s" % (m["class"], cls.get("_comment", "")))
    out.append("scanned: %s" % ", ".join(m["files"]))
    out.append("=" * 100)

    names = m["checks"]
    w = max([len(r["door"]) for r in m["rows"]] + [16])
    out.append("")
    out.append(" " * (w + 2) + "  ".join("%-16s" % n[:16] for n in names))
    for r in m["rows"]:
        if r["absent"]:
            out.append("%-*s  %s" % (w, r["door"], "(not present in this tree)"))
            continue
        cells = "  ".join("%-16s" % GLYPH[r["cells"][n]["state"]] for n in names)
        out.append("%-*s  %s" % (w, r["door"], cells))
    out.append("")
    out.append("  X = FILLED (a real call, found over comment-masked source)")
    out.append("  ~ = EXEMPT (a written, accepted reason of NON-COMPUTABILITY)")
    out.append("  . = EMPTY  -- THE FINDING")
    out.append("")
    out.append("  reading: %s" % ("PERMISSIVE - one field hop (self.node.f()) followed by NAME, cells "
                                  "filled through one are marked AMBIGUOUS"
                                  if m["field_hops"] else
                                  "STRICT - only self./Self::/crate::/bare calls followed"))
    out.append("  CLOSURE PER DOOR (a big unresolved count makes that door's empty cells WEAKER "
               "findings, not stronger):")
    for r in m["rows"]:
        if r["absent"]:
            continue
        out.append("    %-*s  %3d fn(s) reached, %3d unresolved receiver hop(s)"
                   % (w, r["door"], r["closure_size"], len(r["unresolved"])))
    out.append("")

    empties = []
    for r in m["rows"]:
        if r["absent"]:
            continue
        for n in names:
            c = r["cells"][n]
            if c["state"] == EMPTY:
                empties.append((r, n, c))

    if verbose:
        out.append("-" * 100)
        out.append("FILLED CELLS, WITH EVIDENCE")
        out.append("-" * 100)
        for r in m["rows"]:
            if r["absent"]:
                continue
            for n in names:
                c = r["cells"][n]
                if c["state"] != FILLED:
                    continue
                via = (" via " + " -> ".join(c["via"])) if c["via"] else " (direct)"
                amb = "  [AMBIGUOUS HOP - verify by hand]" if c["ambiguous"] else ""
                out.append("  %-38s x %-16s  %s at %s (in %s, depth %d)%s%s"
                           % (r["door"], n, c["symbol"], c["site"], c["in_fn"], c["depth"], via, amb))
        out.append("")

    out.append("-" * 100)
    out.append("EMPTY CELLS - %d. EACH IS A CANDIDATE HOLE UNTIL DISPROVEN." % len(empties))
    out.append("-" * 100)
    if not empties:
        out.append("  none for this class.")
    for (r, n, c) in empties:
        sibs = [o["door"] for o in m["rows"]
                if not o["absent"] and o["door"] != r["door"]
                and o["cells"].get(n, {}).get("state") == FILLED]
        out.append("")
        out.append("  (%s x %s)   %s" % (r["door"], n, m["check_specs"][n]["title"]))
        out.append("      door     : %s:%d  -- %s" % (r["file"], r["line"], r["role"]))
        out.append("      invariant: %s" % m["check_specs"][n]["invariant"])
        if sibs:
            out.append("      SIBLINGS THAT RUN IT: %s" % ", ".join(sibs))
            out.append("      => differential test: the same bytes to %s and to %s; verdicts must match."
                       % (r["door"], sibs[0]))
        else:
            out.append("      no sibling door of this class runs it either - the check may be absent")
            out.append("      for the whole class, which is a wider finding, not a smaller one.")
        if r["unresolved"]:
            out.append("      STRENGTH: WEAKER - %d receiver hop(s) in this door's closure were not"
                       % len(r["unresolved"]))
            out.append("      followed, so the check could be behind one. Re-run with "
                       "--follow-field-hops; e.g.")
            for u in r["unresolved"][:3]:
                out.append("        %s  (in %s, at %s)" % (u["call"], u["in_fn"], u["at"]))
        else:
            out.append("      STRENGTH: STRONG - this door's closure is fully resolved; the check is")
            out.append("      absent from it, not merely unfound.")
        if c.get("claims"):
            out.append("      UNPROVEN REACHABILITY CLAIM IN THIS DOOR - the design's rule is that this")
            out.append("      keeps the cell EMPTY; it never fills it:")
            for (ln, txt) in c["claims"][:3]:
                out.append("        %s:%d  %s" % (r["file"], ln, txt))
    out.append("")

    if m["problems"]:
        out.append("-" * 100)
        out.append("TABLE / EXEMPTION PROBLEMS - %d" % len(m["problems"]))
        out.append("-" * 100)
        for p in m["problems"]:
            out.append("  ! " + p)
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------
# The self-proof: E-8 against node.rs.preDescentLane-20260907
# ---------------------------------------------------------------------------------------------

PRE = "src/node.rs.preDescentLane-20260907"
DESCENT = "graft_wanted_block_shell"
DESCENT_BODY = "graft_block_shell_from_trusted_id"
GOSSIP = "preverify_block"


def cell(m, door, check):
    for r in m["rows"]:
        if r["door"] == door:
            if r["absent"]:
                return None
            return r["cells"].get(check)
    return None


def selfproof(table, verbose=False, follow_field_hops=False):
    """The design's own acceptance test for this generator.

    'if the matrix generator does not produce this exact empty cell when run against
     node.rs.preDescentLane-20260907, the generator is wrong.'
    """
    lines = []
    state = {"ok": True}

    def want(label, cond, detail):
        if not cond:
            state["ok"] = False
        lines.append("  %s  %s" % ("PASS" if cond else "FAIL", label))
        lines.append("        %s" % detail)

    if not os.path.exists(os.path.join(REPO, PRE)):
        return False, ("SELFPROOF CANNOT RUN: %s is absent. The generator is UNCALIBRATED and no\n"
                       "report from it may be cited." % PRE)

    lines.append("")
    lines.append("=" * 100)
    lines.append("SELF-PROOF - E-8 AGAINST %s" % PRE)
    lines.append("=" * 100)
    lines.append("The 2026-09-07 hole: the block-locator descent lane added a second way for a block")
    lines.append("to enter the DAG, carried the merkle and parents-present checks across, and did")
    lines.append("NOT carry the PoW check. A fabricated shell with no proof entered the DAG claiming")
    lines.append("work 8.5e37 against an honest tip of 295.")
    lines.append("")

    m_pre = build(table, "block", {"src/node.rs": PRE}, follow_field_hops=follow_field_hops)
    m_cur = build(table, "block", {}, follow_field_hops=follow_field_hops)

    def show(c):
        if c is None:
            return "door absent"
        if c["state"] == FILLED:
            return "FILLED -- %s at %s (in %s, depth %d)" % (c["symbol"], c["site"], c["in_fn"], c["depth"])
        return c["state"]

    # 1. THE EMPTY CELL ITSELF.
    c = cell(m_pre, DESCENT, "pow_verified")
    want("(%s x pow_verified) is EMPTY in the pre-fix tree" % DESCENT,
         c is not None and c["state"] == EMPTY, "got %s" % show(c))

    # 2. The sibling that DOES run it - without this the empty cell means nothing.
    c = cell(m_pre, GOSSIP, "pow_verified")
    want("(%s x pow_verified) is FILLED in the same tree" % GOSSIP,
         c is not None and c["state"] == FILLED, "got %s" % show(c))

    # 3. AND THE SAME DOOR'S OTHER CELLS ARE FILLED. A generator that reported EMPTY everywhere
    #    would pass 1 and 2 above; it cannot pass this. This is what makes the empty cell a
    #    MEASUREMENT of that door rather than a silence of the reader.
    for other in ("tx_merkle", "parents_present"):
        c = cell(m_pre, DESCENT, other)
        want("(%s x %s) is FILLED in the same tree - the reader can see THIS door" % (DESCENT, other),
             c is not None and c["state"] == FILLED, "got %s" % show(c))

    # 4. THE FIX SHOWS UP. Against the current tree the cell must be closed, on whichever of the two
    #    descent-door rows exists. A generator whose answer does not move when the hole is fixed is
    #    not measuring the source.
    cw = cell(m_cur, DESCENT, "pow_verified")
    cb = cell(m_cur, DESCENT_BODY, "pow_verified")
    closed = [x for x in (cw, cb) if x is not None and x["state"] == FILLED]
    want("the descent door's pow_verified cell is CLOSED in the CURRENT tree",
         bool(closed),
         "graft_wanted_block_shell=%s | graft_block_shell_from_trusted_id=%s" % (show(cw), show(cb)))

    lines.append("")
    if state["ok"]:
        lines.append("SELF-PROOF PASSED. The generator reproduces E-8's empty cell, distinguishes it")
        lines.append("from the sibling door that runs the check, sees the OTHER checks the same door")
        lines.append("does run, and the cell closes when the hole is fixed.")
    else:
        lines.append("SELF-PROOF FAILED. Per the design, the generator is wrong and no matrix it")
        lines.append("prints may be cited.")
    lines.append("")

    if verbose:
        lines.append(render(m_pre, table, verbose=True))
    return state["ok"], "\n".join(lines)


# ---------------------------------------------------------------------------------------------


def door_table(spec_file):
    with open(spec_file) as fh:
        return json.load(fh)


def parse_at(pairs):
    at = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit("--at wants SCANNED=DECLARED, e.g. --at %s=src/node.rs" % PRE)
        scanned, declared = p.split("=", 1)
        at[declared] = scanned
    return at


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")

    r = sub.add_parser("report", help="print the door x check matrix")
    r.add_argument("--doors", default=os.path.join(_HERE, "doors.json"))
    r.add_argument("--class", dest="cls", default=None, help="one class only")
    r.add_argument("--door", default=None, help="one door only")
    r.add_argument("--at", action="append", help="SCANNED=DECLARED file substitution")
    r.add_argument("--json", default=None)
    r.add_argument("--verbose", action="store_true", help="print filled-cell evidence too")
    r.add_argument("--no-fail", action="store_true", help="exit 0 even with empty cells")
    r.add_argument("--follow-field-hops", action="store_true",
                   help="permissive reading: follow one field hop (self.node.f()) by NAME. Cells "
                        "filled through one are marked AMBIGUOUS. Report it SEPARATELY from the "
                        "strict reading; never sum the two.")

    s = sub.add_parser("selfproof", help="the E-8 calibration - run before trusting a report")
    s.add_argument("--doors", default=os.path.join(_HERE, "doors.json"))
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--follow-field-hops", action="store_true",
                   help="permissive reading: follow one field hop (self.node.f()) by NAME")

    a = ap.parse_args()
    if a.cmd is None:
        ap.print_help()
        return 0

    table = door_table(a.doors)

    if a.cmd == "selfproof":
        ok, text = selfproof(table, a.verbose, a.follow_field_hops)
        print(text)
        return 0 if ok else 3

    at = parse_at(a.at)
    classes = [a.cls] if a.cls else list(table["classes"].keys())
    total_empty = 0
    problems = 0
    blob = []
    for cn in classes:
        if cn not in table["classes"]:
            raise SystemExit("unknown class %r; have %s" % (cn, ", ".join(table["classes"])))
        m = build(table, cn, at, only_door=a.door, follow_field_hops=a.follow_field_hops)
        print(render(m, table, a.verbose))
        blob.append(m)
        problems += len(m["problems"])
        for row in m["rows"]:
            if row["absent"]:
                continue
            total_empty += sum(1 for c in row["cells"].values() if c["state"] == EMPTY)

    print("=" * 100)
    print("PARITY MATRIX TOTAL: %d EMPTY CELL(S) across %d class(es). %d table/exemption problem(s)."
          % (total_empty, len(classes), problems))
    print("An empty cell is a candidate hole and is handed to lane F as a differential test.")
    print("=" * 100)

    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"classes": blob, "empty_cells": total_empty}, fh, indent=2)
        print("wrote %s" % a.json)

    if problems:
        return 2
    if total_empty and not a.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

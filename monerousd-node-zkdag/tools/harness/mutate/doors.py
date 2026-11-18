# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - THE DOOR x CHECK MATRIX.  **An empty cell is the finding.**

THE QUESTION: *this class of object enters through N doors - does every door run the same checks?*

A tree grows doors faster than it grows pins. Every door in this project that admitted something it
should not have admitted was a SIBLING of a door that refused it correctly:

  E-8  the block-locator DESCENT door carried merkle and parents-present across and NOT the PoW check
  B3   `ingest_tx_prechecked` omitted the `chain_object::admissible` its sibling `ingest_tx` ran
  D-2  `instant_sync` ran no `verify_block_pow` on the blocks it carried
  E-2  `admissible` at admission but not at the graft note seam

None of these is findable by reading one door: each is only visible as a HOLE IN A ROW. So the
instrument is a matrix, and the design's rule about it is the important half:

  ⛔ AN UNPROVEN REACHABILITY CLAIM IS AN EMPTY CELL, NOT A FILLED ONE.

  `ingest_tx_prechecked`'s own comment said "a framed blob cannot have passed the caller's off-lock
  precheck, so this arm should be unreachable". That sentence is an argument, and this matrix does not
  accept arguments - only invocations. The cell stays empty until a call fills it.

TRANSITIVITY IS REQUIRED, AND IT IS WHAT MAKES A CLEAN ROW MEAN SOMETHING. After the 2026-09-07 fix
both tx doors call `admit_tx_shared`, which calls `admissible`. A one-level-deep reader would call
BOTH cells empty and report a hole that had just been closed - an instrument that fires on the fix is
worse than one that fires on nothing. The closure below walks callees through the analysed files to a
bounded depth and records the PATH, so a filled cell prints how the check is reached.

COST: cons NONE on chain. A Python reader under tools/, no build, no crate graph, 0 bytes on the DA.
Run time is f(bytes of the named files); `node.rs` at 2.8 MB is about a second.
"""

import re

import selection

# How a check reaches a door. Bounded so the closure terminates on a recursive call graph, and stated
# rather than inferred: 4 hops covers door -> shared arm -> helper -> check, which is the deepest real
# chain in this tree (`ingest_tx` -> `admit_tx_shared` -> `mempool.accept_verified` -> `admissible`).
MAX_HOPS = 4

# Names that are DOOR DECORATION, not a different door: two functions whose names differ only by one
# of these are siblings of the same family. Generated families come from this list, so a door added
# tomorrow with a familiar suffix joins its family without anyone editing a config.
SIBLING_AFFIXES = (
    "_prechecked", "_unverified", "_verified", "_inner", "_shared", "_unchecked",
    "_for_test", "_run", "_one", "_locked", "_offlock", "_fast", "_slow", "_bytes",
)

CALL_RE = re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# A method call keeps its receiver out of the name: `self.foo(` and `crate::x::foo(` both name `foo`.
QUALIFIED_RE = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*\s*(?:::|\.))*([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Words that are calls but never checks - excluded so a row is readable. Nothing here can hide a
# check: every name is a language or container primitive.
NOISE = frozenset("""
if while for match return Some None Ok Err Vec String format println eprintln write writeln assert
assert_eq assert_ne debug_assert panic unreachable todo unimplemented vec HashMap HashSet BTreeMap
BTreeSet Box Arc Rc RefCell Mutex RwLock clone to_string to_vec to_owned into from as_bytes as_ref
as_mut as_slice iter into_iter map filter collect len push pop insert remove get get_mut entry or
unwrap unwrap_or unwrap_or_else unwrap_or_default expect min max abs saturating_add saturating_sub
saturating_mul wrapping_add wrapping_mul checked_add checked_sub checked_mul copied cloned sort
sort_by sort_unstable dedup extend truncate retain drain contains contains_key starts_with ends_with
split trim parse count sum last first take skip zip enumerate rev any all find position chars bytes
elapsed now try_into try_from ok ok_or ok_or_else and_then or_else is_some is_none is_ok is_err is_empty is_null is_nan
""".split())


def _fn_index(files):
    """name -> [(rf, fn)] for every non-oracle function in the analysed files."""
    idx = {}
    for rf in files:
        for fn in rf.fns:
            if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                continue
            idx.setdefault(fn["name"], []).append((rf, fn))
    return idx


def callees(rf, fn):
    """Every name this function calls, with the noise words dropped. Textual, and the report says so."""
    out = set()
    for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
        if rf.in_oracle_region(i):
            continue
        line = rf.masked[i]
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        for m in QUALIFIED_RE.finditer(line):
            name = m.group(1)
            if name in NOISE or name == fn["name"]:
                continue
            out.add(name)
    return out


def is_check_name(name):
    """A callee whose NAME says it decides something. The lexicon is the design's, verbatim."""
    return bool(selection.CHECKING_NAME_RE.search(name))


def reaches(idx, start_rf, start_fn, targets, max_hops=MAX_HOPS):
    """{check name -> the call path that reaches it} from `start_fn`, through the analysed files.

    A check named DIRECTLY in the body is depth 0. Anything else is reached through a callee that this
    reader can also see the body of; a callee defined outside the analysed files is a wall, and a check
    behind that wall is NOT recorded as reached - which keeps the matrix conservative in the direction
    that produces findings rather than hides them.
    """
    found = {}
    seen = set()
    frontier = [(start_rf, start_fn, [])]
    for _hop in range(max_hops + 1):
        nxt = []
        for (rf, fn, path) in frontier:
            key = (rf.relpath, fn["name"], fn["sig_idx"])
            if key in seen:
                continue
            seen.add(key)
            cs = callees(rf, fn)
            for name in cs:
                if name in targets and name not in found:
                    found[name] = path + [fn["name"]]
            for name in cs:
                for (crf, cfn) in idx.get(name, []):
                    nxt.append((crf, cfn, path + [fn["name"]]))
        frontier = nxt
        if not frontier:
            break
    return found


def _stem(name):
    for affix in SIBLING_AFFIXES:
        if name.endswith(affix) and len(name) > len(affix) + 2:
            return name[: -len(affix)]
    return name


def generated_families(files):
    """Door families READ OFF THE SOURCE: functions whose names differ only by a sibling affix.

    Nothing is curated, so `ingest_tx` / `ingest_tx_prechecked` / `ingest_tx_unverified` are one family
    the day the third one lands. A family of one is not a family and is dropped.
    """
    by_stem = {}
    for rf in files:
        for fn in rf.fns:
            if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                continue
            by_stem.setdefault(_stem(fn["name"]), set()).add(fn["name"])
    return dict((k, sorted(v)) for k, v in by_stem.items() if len(v) > 1)


def matrix(files, families, columns=None):
    """For each family: the checks any member reaches, and which members do NOT reach them.

    `columns` optionally names the REQUIRED check set for a family. Without it the columns are
    generated from what the doors call, which is drift-proof but noisy where the doors legitimately do
    different amounts of work: a bundle-admission door is not a full block ingest, and reporting the
    twelve things it does not do buries the one it must. Naming the columns is the family declaring
    WHAT THE CLASS REQUIRES, and an empty cell then means "a door of this class skips a check the
    class requires" rather than "these two functions differ".

    Returns [{family, doors, checks, cells: {(door, check): path or None}, empty: [(door, check)]}].
    """
    idx = _fn_index(files)
    columns = columns or {}
    rows = []
    for fam, doors in sorted(families.items()):
        members = []
        for d in doors:
            for (rf, fn) in idx.get(d, []):
                members.append((d, rf, fn))
        if len(members) < 2:
            continue
        declared_cols = columns.get(fam)
        if declared_cols:
            universe = set(declared_cols)
        else:
            # Pass 1: what does any member call at all? The check columns are the check-named callees.
            universe = set()
            for (_d, rf, fn) in members:
                universe |= set(n for n in callees(rf, fn) if is_check_name(n))
            # Pass 2 widens the columns with checks reachable transitively, so a door that reaches a
            # check only through a shared arm still contributes that column.
            for (_d, rf, fn) in members:
                universe |= set(reaches(idx, rf, fn, set(n for n in idx if is_check_name(n))).keys())
        if not universe:
            continue
        cells = {}
        for (d, rf, fn) in members:
            got = reaches(idx, rf, fn, universe)
            for c in universe:
                cells[(d, c)] = got.get(c)
        empty = sorted([(d, c) for (d, c) in cells if cells[(d, c)] is None
                        and any(cells.get((d2, c)) for (d2, _rf2, _fn2) in members if d2 != d)])
        if not empty:
            continue
        rows.append({
            "family": fam,
            "doors": [d for (d, _rf, _fn) in members],
            "checks": sorted(universe),
            "cells": cells,
            "empty": empty,
        })
    return rows


def filled_cells(files, families):
    """Every FILLED (door, check) cell with the site that fills it - M2's injection inventory.

    M2 empties one filled cell at a time, so the operator is complete by construction over the matrix
    rather than over the source text. A cell is emptiable only where the call is TEXTUALLY IN THE DOOR
    (depth 0): emptying a call inside a shared arm removes it from every sibling at once, which is a
    different operator (M12) and a different finding.
    """
    idx = _fn_index(files)
    out = []
    for fam, doors in sorted(families.items()):
        members = [(d, rf, fn) for d in doors for (rf, fn) in idx.get(d, [])]
        if len(members) < 2:
            continue
        universe = set()
        for (_d, rf, fn) in members:
            universe |= set(n for n in callees(rf, fn) if is_check_name(n))
        for (d, rf, fn) in members:
            call_re = None
            for c in sorted(universe):
                call_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"\s*\(")
                for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
                    if rf.in_oracle_region(i):
                        continue
                    if call_re.search(rf.masked[i]):
                        siblings = [d2 for (d2, _r, _f) in members if d2 != d]
                        out.append({"family": fam, "door": d, "check": c, "rf": rf,
                                    "fn": fn, "line": i, "siblings": siblings})
                        break
    return out

#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE X - THE PREIMAGE / BINDING ENUMERATION.  **ACTED must be a SUBSET of BOUND.**

THE QUESTION THIS ANSWERS: *is every field of a peer-supplied struct that the adopt path READS AND
ACTS ON also folded into the binding the proof certifies?*  A field that is acted on but not folded
rides a valid proof unbound: the peer may write anything into it and the proof still verifies.

WHY THIS IS A SEPARATE INSTRUMENT AND NOT A TEST.  It needs NO attack, no prover, no chain and no
build.  It is an ENUMERATION and a set difference, so it finds the field NOBODY SUSPECTED - which is
the whole point.  The 2026-09-07 hand audit's own pins MISSED `anchor_ordinal` (row A5) and its table
CAUGHT it, and the harness design records that as "the single strongest argument for building lane
X".  Mutation cannot find this class (every line behaves exactly as written) and fuzzing cannot find
it (the honest peer never writes a hostile value into the field).

  BOUND    a field whose bytes reach the binding preimage - it appears in an argument expression at a
           PRODUCTION call site of the binding function, or is reachable through one that does.
  EQUATED  a field the adopt path REFUSES unless it equals something already BOUND.  Binding by
           derivation rather than by folding, and it is genuinely sound, so it is a distinct verdict
           and not a hole.  (`tip_block` is bound this way: `tip_block.id() != decider.tip` refuses.)
  ACTED    a field the adopt path reads outside the binding call itself - the adopter's behaviour
           depends on it.

  FINDING  = ACTED \\ (BOUND u EQUATED).   Each row prints the exact read site that acts on it.

HONESTY RULES, because an enumerator that overstates is worse than none:

  * A field the adopt path never reads is reported as UNREAD, never as a finding.  Unbound and unused
    is not a hole; it is dead weight, and saying otherwise would train the reader to skim the report.
  * Reachability is TEXTUAL and the report says so.  A `<binder>.<field>` inside the adopt span is a
    read; the tool does not prove the read changes an outcome.  That direction is the SAFE one: it can
    only over-report ACTED, never under-report it, and every ACTED row prints its site so a human can
    adjudicate in one line.  The reverse error - silently deciding a read "does not matter" - is the
    error that lets A5 through, so it is not available to this tool.
  * The ORACLE FILES ARE NEVER READ AS EVIDENCE.  A binding-fn call site inside a `#[test]` fn or a
    `cfg(test)` module is EXCLUDED from BOUND: a fixture that passes a field to the binder proves the
    fixture folds it, not that the production adopt path does.  (Every fixture in `sync.rs` passes all
    eleven arguments; counting those would have reported A3 and A5 as BOUND.)
  * Nothing is curated.  The struct's fields, the adopt functions (every non-oracle fn whose signature
    names the struct type) and the binder names are all READ OFF THE SOURCE, so a new field or a new
    adopt path joins the enumeration the day it lands rather than the day someone remembers.

COST: cons NONE on chain.  A Python reader under tools/ that never enters the crate graph - 0 bytes on
the DA, 0 node RAM, 0 gates.  It does not build: run time is f(bytes of the named files), and it is
sub-second on `node.rs` at 2.8 MB.

USAGE
  enumerate.py                                   # every subject in bindings.json, live tree
  enumerate.py --subject sync_bundle
  enumerate.py --subject sync_bundle --at preHoleClose2-20260907   # the PRE-FIX pair (calibration)
  enumerate.py --expect-findings blue_work,anchor_blue_work,anchor_ordinal   # exit 1 unless exact
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "mutate"))

import rustsrc  # noqa: E402

FIELD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?),?\s*$")
REFUSAL_TOKENS = ("return false", "return None", "return Err(", "return AdoptOutcome::",
                  "return Some(", "panic!(", "?;")


def struct_fields(rf, name):
    """The declared fields of `struct <name>`, in declaration order. Attributes and docs skipped."""
    open_re = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+" + re.escape(name) + r"\b[^;{]*\{")
    for i, line in enumerate(rf.masked):
        if not open_re.match(line):
            continue
        end = rf.match_block_from(i, line.index("{"))
        if end is None:
            return []
        out = []
        depth_extra = 0
        for j in range(i + 1, end):
            raw = rf.lines[j]
            s = rf.masked[j].strip()
            if not s or s.startswith("//") or raw.strip().startswith("//") or s.startswith("#["):
                continue
            # a nested brace (an inline enum/closure type) is skipped whole rather than guessed at
            depth_extra += s.count("{") - s.count("}")
            if depth_extra > 0:
                continue
            m = FIELD_RE.match(rf.masked[j])
            if m:
                out.append((m.group(1), m.group(2).strip(), j))
        return out
    return []


def fn_at(rf, idx):
    """The innermost function span containing line `idx`, or None."""
    best = None
    for fn in rf.fns:
        if fn["body_open_idx"] <= idx <= fn["body_end_idx"]:
            if best is None or fn["body_open_idx"] > best["body_open_idx"]:
                best = fn
    return best


def is_oracle_line(rf, idx):
    if rf.in_oracle_region(idx):
        return True
    fn = fn_at(rf, idx)
    return bool(fn and (fn["is_oracle_fn"] or fn["in_oracle_mod"]))


def balanced_args(rf, idx, col):
    """The text between the parens opening at (idx, col), across lines. Literals are NOT masked here:
    the argument text is what the reader adjudicates, so it is returned verbatim."""
    depth = 0
    out = []
    for i in range(idx, min(idx + 60, len(rf.lines))):
        line = rf.masked[i]
        start = col if i == idx else 0
        for c in range(start, len(line)):
            ch = line[c]
            if ch == "(":
                depth += 1
                if depth == 1:
                    continue
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return "".join(out), i
            if depth >= 1:
                out.append(rf.lines[i][c] if c < len(rf.lines[i]) else " ")
        out.append("\n")
    return "".join(out), idx


def split_params(sig):
    """The parameter list of a signature, split at TOP-LEVEL commas only.

    Depth-aware over `(` `[` `<` so `Vec<(u64, u128)>` and `&dyn Fn(a, b)` stay one parameter. A
    regex cannot do this and the first version of this function proved it: it bound `verifier` from
    `adopt_sync_bundle(verifier: &dyn ConsensusVerifier, bundle: &SyncBundle)` and reported every
    field UNREAD - the enumeration silently measured nothing. Getting the signature wrong is a
    SILENT under-report, which is the one direction this tool may not fail in.
    """
    start = sig.find("(")
    if start < 0:
        return []
    depth = 0
    parts, cur = [], []
    for ch in sig[start:]:
        if ch in "([<":
            depth += 1
            if depth == 1:
                continue
        elif ch in ")]>":
            depth -= 1
            if depth == 0:
                parts.append("".join(cur))
                return parts
        if depth == 1 and ch == ",":
            parts.append("".join(cur))
            cur = []
            continue
        if depth >= 1:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def binder_names(rf, fn, struct_name):
    """Parameter names in `fn` whose declared type names `struct_name`. Read off the signature."""
    sig = " ".join(rf.lines[fn["sig_idx"]:fn["body_open_idx"] + 1])
    ty_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(struct_name) + r"(?![A-Za-z0-9_])")
    names = []
    for part in split_params(sig):
        if ":" not in part:
            continue                       # `&self` / `self` carry no name of their own
        name, _, ty = part.partition(":")
        if not ty_re.search(ty):
            continue
        m = re.match(r"\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*$", name)
        if m:
            names.append(m.group(1))
    return names


def adopt_fns(files, struct_name, adopt_files):
    """Every NON-ORACLE function in `adopt_files` whose signature names the struct type, with the
    parameter name it binds it to. Generated, never curated."""
    out = []
    for rf in files:
        if rf.relpath not in adopt_files:
            continue
        for fn in rf.fns:
            if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                continue
            names = binder_names(rf, fn, struct_name)
            if names:
                out.append((rf, fn, names))
    return out


def bound_fields(files, binding_fn, fields, struct_name, adopt_files):
    """Fields whose bytes reach the binding preimage, via a PRODUCTION call site of `binding_fn`.

    Two sources, and both are needed:
      1. an argument expression naming `<binder>.<field>` at a call site inside an adopt function;
      2. an argument naming a LOCAL that was itself assigned from `<binder>.<field>` in that function
         (the binding call is often several lines below the read).
    """
    names = set(f[0] for f in fields)
    call_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(binding_fn) + r"\s*\(")
    bound = {}
    for rf in files:
        for i, line in enumerate(rf.masked):
            m = call_re.search(line)
            if not m:
                continue
            if is_oracle_line(rf, i):
                continue          # a fixture folds what a fixture folds - never evidence about production
            fn = fn_at(rf, i)
            if fn is None or fn["name"] == binding_fn:
                continue
            args, _end = balanced_args(rf, i, m.end() - 1)
            binders = binder_names(rf, fn, struct_name) or (["bundle"] if rf.relpath in adopt_files else [])
            # direct: an argument names bundle.field
            for b in binders:
                for fname in names:
                    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(b) + r"\." + re.escape(fname) + r"\b", args):
                        bound.setdefault(fname, []).append((rf.relpath, i + 1, "argument"))
            # indirect: an argument names a local assigned from bundle.field inside this fn
            for tok in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", args)):
                if tok in names:
                    continue
                assign = re.compile(r"\blet\s+(?:mut\s+)?" + re.escape(tok) + r"\s*(?::[^=]+)?=\s*(.+)")
                for j in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
                    am = assign.search(rf.masked[j])
                    if not am:
                        continue
                    rhs = am.group(1)
                    for b in binders:
                        for fname in names:
                            if re.search(r"(?<![A-Za-z0-9_])" + re.escape(b) + r"\." + re.escape(fname) + r"\b", rhs):
                                bound.setdefault(fname, []).append((rf.relpath, j + 1, "via local `%s`" % tok))
    return bound


def equated_fields(files, adopts, fields, bound):
    """Fields the adopt path REFUSES unless they equal something already BOUND.

    Sound binding by derivation: `bundle.tip_block.id() != bundle.decider.tip -> refuse` binds
    `tip_block` to a field the proof certifies. Required shape: an equality/inequality naming the
    field on one side and a BOUND field on the other, whose guard block REFUSES.
    """
    names = set(f[0] for f in fields)
    out = {}
    for (rf, fn, binders) in adopts:
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            line = rf.masked[i]
            if "==" not in line and "!=" not in line:
                continue
            block = "\n".join(rf.lines[i:min(i + 8, fn["body_end_idx"] + 1)])
            if not any(t in block for t in REFUSAL_TOKENS):
                continue
            present = set()
            for b in binders:
                for fname in names:
                    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(b) + r"\." + re.escape(fname) + r"\b", line):
                        present.add(fname)
            anchor = present & set(bound.keys())
            if not anchor:
                continue
            for fname in present - anchor:
                out.setdefault(fname, []).append((rf.relpath, i + 1, sorted(anchor)[0]))
    return out


def acted_fields(files, adopts, fields, binding_fn):
    """Every read of `<binder>.<field>` inside an adopt function, EXCLUDING the binding call's own
    argument lines (passing a field to the binder is folding it, not acting on it)."""
    names = set(f[0] for f in fields)
    call_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(binding_fn) + r"\s*\(")
    out = {}
    for (rf, fn, binders) in adopts:
        skip = set()
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            m = call_re.search(rf.masked[i])
            if m:
                _args, end = balanced_args(rf, i, m.end() - 1)
                for k in range(i, end + 1):
                    skip.add(k)
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if i in skip:
                continue
            line = rf.masked[i]
            if line.strip().startswith("//"):
                continue
            for b in binders:
                for fname in names:
                    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(b) + r"\." + re.escape(fname) + r"\b", line):
                        out.setdefault(fname, []).append((rf.relpath, i + 1, fn["name"], rf.lines[i].strip()[:120]))
    return out


def read_file(root, rel, at):
    """Read `rel`, or its `.<at>` backup when a calibration point is named. A subject measured at a
    point in history must read EVERY file at that same point, or the diff is between two trees."""
    path = os.path.join(root, rel)
    if at:
        cand = path + "." + at
        if not os.path.exists(cand):
            raise SystemExit("no backup `%s` for %s - a calibration point must exist for every file "
                             "of the subject, or the enumeration compares two different trees" % (at, rel))
        path = cand
    with open(path, "r", errors="replace") as fh:
        return rustsrc.RustFile(rel, fh.read())


def run_subject(root, key, subj, at, out):
    rels = sorted(set([subj["struct_file"], subj["binding_file"]] + subj["adopt_files"]))
    files = [read_file(root, r, at) for r in rels]
    by_rel = dict((f.relpath, f) for f in files)

    sfile = by_rel[subj["struct_file"]]
    fields = struct_fields(sfile, subj["struct"])
    if not fields:
        raise SystemExit("subject %s: struct %s not found in %s" % (key, subj["struct"], subj["struct_file"]))

    adopts = adopt_fns(files, subj["struct"], set(subj["adopt_files"]))
    bound = bound_fields(files, subj["binding_fn"], fields, subj["struct"], set(subj["adopt_files"]))
    acted = acted_fields(files, adopts, fields, subj["binding_fn"])
    equated = equated_fields(files, adopts, fields, bound)

    findings = [f for (f, _t, _l) in fields if f in acted and f not in bound and f not in equated]

    out("")
    out("=== SUBJECT %s  ·  struct %s (%d fields)  ·  binding `%s`%s" %
        (key, subj["struct"], len(fields), subj["binding_fn"], ("  ·  AT " + at) if at else "  ·  LIVE TREE"))
    out("    invariant: %s" % subj.get("invariant", "(none declared)"))
    out("    adopt path (generated, every non-oracle fn whose signature names the type):")
    for (rf, fn, binders) in adopts:
        out("      %s::%s  binds %s" % (rf.relpath, fn["name"], ",".join(binders)))
    if not adopts:
        out("      (NONE - nothing reads this struct by value or reference; ACTED is empty by construction)")
    out("")
    out("    %-24s %-9s %s" % ("FIELD", "VERDICT", "EVIDENCE"))
    for (fname, ftype, _l) in fields:
        if fname in bound:
            rel, ln, how = bound[fname][0]
            out("    %-24s %-9s folded at %s:%d (%s)" % (fname, "BOUND", rel, ln, how))
        elif fname in equated:
            rel, ln, anchor = equated[fname][0]
            out("    %-24s %-9s refused unless equal to BOUND `%s` at %s:%d" % (fname, "EQUATED", anchor, rel, ln))
        elif fname in acted:
            rel, ln, fn, text = acted[fname][0]
            out("    %-24s %-9s READ AND ACTED ON at %s:%d in %s()" % (fname, "**UNBOUND**", rel, ln, fn))
            out("    %-24s %-9s   %s" % ("", "", text))
            for (r2, l2, f2, _t2) in acted[fname][1:4]:
                out("    %-24s %-9s   also %s:%d in %s()" % ("", "", r2, l2, f2))
        else:
            out("    %-24s %-9s no read in the adopt path (unbound but unused is not a hole)" % (fname, "UNREAD"))
    out("")
    if findings:
        out("    ⛔ ACTED ⊄ BOUND — %d field(s) ride the proof unbound: %s" % (len(findings), ", ".join(findings)))
        out("       A peer may write ANY value into each of these and the proof still verifies.")
    else:
        out("    ✅ ACTED ⊆ BOUND — every field the adopt path acts on is folded or equated.")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crate", default=os.path.abspath(os.path.join(HERE, "..", "..", "..")))
    ap.add_argument("--config", default=os.path.join(HERE, "bindings.json"))
    ap.add_argument("--subject", default=None)
    ap.add_argument("--at", default=None,
                    help="a backup suffix (e.g. preHoleClose2-20260907): enumerate the tree AS OF that point")
    ap.add_argument("--expect-findings", default=None,
                    help="comma-separated field names; exit 1 unless the finding set matches EXACTLY")
    args = ap.parse_args()

    with open(args.config) as fh:
        cfg = json.load(fh)

    lines = []

    def out(msg):
        lines.append(msg)
        print(msg)

    subjects = cfg["subjects"]
    keys = [args.subject] if args.subject else sorted(subjects.keys())
    all_findings = []
    for k in keys:
        if k not in subjects:
            raise SystemExit("no subject %r in %s" % (k, args.config))
        all_findings += run_subject(args.crate, k, subjects[k], args.at, out)

    if args.expect_findings is not None:
        want = sorted(x for x in args.expect_findings.split(",") if x)
        got = sorted(all_findings)
        out("")
        out("EXPECTED findings: %s" % (want or "(none)"))
        out("MEASURED findings: %s" % (got or "(none)"))
        if want != got:
            out("⛔ CALIBRATION FAILED — the enumeration does not reproduce the expected set.")
            return 1
        out("✅ CALIBRATION HELD — the enumeration reproduces the expected set exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

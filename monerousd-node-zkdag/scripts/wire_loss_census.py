#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""wire_loss_census.py — DB-402 R3: THE WIRE-LOSS CENSUS (DB-401's class, auto-discovering every conversion).

DB-401: `OrderWire::of` / `into_order` wrote `membership_carrier: Vec::new()` although the order it converted CARRIED the
maker's bind, so every book but the poster's held the offer hollow and every fill through a peer was refused. No guard saw
it: the hooks match added text, and every census compared a hand-picked list. This census has no list:

  1. every `struct Name { field: Type, .. }` in the tree's non-test source is read (name → fields);
  2. every conversion fn (`fn of`, `fn from`, `fn into_*`, `fn to_*`, `fn wire*`, `fn decode*`, `fn encode*`) is found, with
     its INPUT types — each parameter's type and, for a `self` receiver, the impl's type;
  3. inside its body, a struct-literal field set to an EMPTY literal (`Vec::new()`, `String::new()`, `Default::default()`,
     `None`, `[0u8; N]`, `0`, `Vec::default()`, `*Map::new()`, `*Set::new()`) whose name is a field of an input type is a
     DROP: the source carried it and the conversion threw it away.

Each drop prints `file:line  fn  Input.field dropped (empty literal)`. `DECLARED_DROPS` (Input.field → reason) is
SHRINK-ONLY: a deliberate drop is declared with why the receiver must not have it; an entry matching no drop is refused.

usage:
  wire_loss_census.py [--root DIR]                 scan the tree (default: this crate's src/); exit 1 on an undeclared drop
  wire_loss_census.py --root DIR --text TEXT       scan TEXT as one extra file, with the tree's struct table (calibration)
  wire_loss_census.py --root DIR --file PATH       scan only PATH (with the tree's struct table) — the edit-time hook
"""
import os
import re
import sys

# Input.field → why the receiver must NOT carry it. Shrink-only; an entry matching no drop is refused (stale).
DECLARED_DROPS = {
}

CONV = re.compile(r"\bfn\s+(of|from|into_\w+|to_\w+|wire\w*|decode\w*|encode\w*)\s*(?:<[^>{]*>)?\s*\(")
EMPTY = re.compile(
    r"^\s*(\w+)\s*:\s*(Vec::new\(\)|Vec::default\(\)|String::new\(\)|Default::default\(\)|None|\[0u8;\s*\w+\]|0|0u\d+"
    r"|\w*Map::new\(\)|\w*Set::new\(\))\s*,?\s*(//.*)?$"
)
STRUCT = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)\s*(?:<[^>{]*>)?\s*\{\s*$")
FIELD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*\S")
IMPL = re.compile(r"^impl(?:<[^>]*>)?\s+(?:[\w:<>, ]+\s+for\s+)?([\w:]+)")


def strip_comment(line):
    return line.split("//", 1)[0]


def rs_files(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in ("target", "harness", "tests")]
        for f in files:
            if f.endswith(".rs"):  # backups are `*.rs.pre…`, never `*.rs`
                yield os.path.join(d, f)


def non_test_lines(text):
    """The file's lines with `#[cfg(test)]` items blanked (a `mod tests` block or a test-only fn): test code is not a wire."""
    lines = text.split("\n")
    out = list(lines)
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines) and (lines[j].strip().startswith("#[") or not lines[j].strip()):
                j += 1
            depth, k, opened = 0, j, False
            while k < len(lines):
                s = strip_comment(lines[k])
                depth += s.count("{") - s.count("}")
                opened = opened or "{" in s
                if (opened and depth <= 0) or (not opened and s.rstrip().endswith(";")):
                    break
                k += 1
            for m in range(i, min(k + 1, len(lines))):
                out[m] = ""
            i = k + 1
            continue
        i += 1
    return out


def structs_of(lines, table):
    i = 0
    while i < len(lines):
        m = STRUCT.match(lines[i])
        if m:
            name, fields, j, depth = m.group(1), set(), i + 1, 1
            while j < len(lines) and depth > 0:
                s = strip_comment(lines[j])
                if depth == 1:
                    fm = FIELD.match(s)
                    if fm and not s.strip().startswith("#"):
                        fields.add(fm.group(1))
                depth += s.count("{") - s.count("}")
                j += 1
            table.setdefault(name, set()).update(fields)
            i = j
            continue
        i += 1


def param_types(sig):
    """`(o: &RestingOrder, x: u64)` → ['RestingOrder', 'u64']; `self` / `&self` → ['Self']."""
    inner = sig[sig.find("(") + 1:]
    depth, cur, parts = 0, "", []
    for ch in inner:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    out = []
    for p in parts:
        p = p.strip()
        if re.fullmatch(r"&?\s*(mut\s+)?self", p) or p.startswith("self:"):
            out.append("Self")
        elif ":" in p:
            t = p.split(":", 1)[1]
            t = re.sub(r"&|mut\b|'\w+|\bdyn\b|\bimpl\b", " ", t).strip()
            out.append(re.split(r"[<\s]", t.split("::")[-1] if "<" not in t else t.split("<")[0].split("::")[-1])[0])
    return out


def drops_in(path, lines, table):
    found = []
    impl_ty = None
    i = 0
    while i < len(lines):
        line = lines[i]
        im = IMPL.match(line)
        if im:
            impl_ty = im.group(1).split("::")[-1]
        cm = CONV.search(strip_comment(line))
        if not cm:
            i += 1
            continue
        sig, j = line, i
        while "{" not in strip_comment(sig) and j + 1 < len(lines) and j - i < 12:
            j += 1
            sig += " " + lines[j]
        inputs = [impl_ty if t == "Self" else t for t in param_types(sig)]
        carried = {}
        for t in inputs:
            for f in table.get(t or "", ()):
                carried.setdefault(f, t)
        depth, k, opened = 0, j, False
        while k < len(lines):
            s = strip_comment(lines[k])
            if k > j or "{" in s:
                em = EMPTY.match(lines[k])
                if em and em.group(1) in carried and k > i:
                    found.append((path, k + 1, cm.group(1), f"{carried[em.group(1)]}.{em.group(1)}", em.group(2)))
            depth += s.count("{") - s.count("}")
            opened = opened or "{" in s
            if opened and depth <= 0:
                break
            k += 1
        i = k + 1 if opened else j + 1
    return found


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, "..", "src")
    text, only = None, None
    a = iter(argv[1:])
    for x in a:
        if x == "--root":
            root = next(a)
        elif x == "--text":
            text = next(a)
        elif x == "--file":
            only = next(a)
    table, files = {}, {}
    for p in rs_files(root):
        try:
            files[p] = non_test_lines(open(p, errors="replace").read())
        except OSError:
            continue
        structs_of(files[p], table)
    if text is not None:
        files = {"<text>": non_test_lines(text)}
        structs_of(files["<text>"], table)
    elif only is not None:
        files = {only: non_test_lines(open(only, errors="replace").read())}
        structs_of(files[only], table)
    drops = []
    for p, lines in sorted(files.items()):
        drops.extend(drops_in(p, lines, table))
    undeclared = [d for d in drops if d[3] not in DECLARED_DROPS]
    stale = [k for k in DECLARED_DROPS if not any(d[3] == k for d in drops)] if text is None and only is None else []
    for p, line, fn, field, lit in drops:
        tag = "DECLARED" if field in DECLARED_DROPS else "DROP"
        print(f"[wire-loss] {tag}\t{os.path.relpath(p, os.path.join(root, '..')) if p != '<text>' else p}:{line}\tfn {fn}\t{field} dropped ({lit})")
    for k in stale:
        print(f"[wire-loss] STALE-DECLARATION\t{k}\t(no conversion drops it any more — remove the entry)")
    print(f"[wire-loss] {len(table)} struct(s), {sum(len(v) for v in files.values())} line(s) scanned · {len(undeclared)} undeclared drop(s) · {len(stale)} stale declaration(s)")
    return 1 if undeclared or stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

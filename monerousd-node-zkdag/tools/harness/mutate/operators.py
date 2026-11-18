# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - THE OPERATOR SET.

COST ARITHMETIC (written down rather than assumed) - cons: NONE on chain, and the reason is
structural, not a judgement call. Nothing in this file is compiled into the node: it is a Python
driver under tools/ that never enters the crate graph, so the delta it adds to every cardinal is
exactly zero - 0 bytes on the DA, 0 bytes of node RAM, 0 gates removed from any shipping path, 0
change to consensus. The weakened gates described below are written ONLY into an isolated clone
under the warm dir; the live tree is hashed before and after every run and the run FAILS if a single
byte differs, so no mutant can reach a shipping path. Engine cost is bounded by construction: per
night it is (mutants selected) x (1 incremental rebuild + 1 targeted pin subset), and mutants
selected is a fixed cap in targets.json - f(cap), never f(chain height / notes / records / peers).

Every operator here answers one question and only one: *if this specific check stopped checking,
would anything in our suite go red?* They are chosen to model the failure classes this project has
actually MEASURED, not the generic arithmetic mutations a textbook engine emits:

  guard_disable   a fail-closed refusal stops refusing            (the descent door that ran no PoW)
  guard_force     a refusal fires unconditionally                 (a chain stall dressed as hardening)
  cmp_relax       a bound admits its own boundary                 (off-by-one at a frontier)
  cmp_tighten     a bound refuses its own boundary
  eq_flip         a binding equality stops binding                (WrongWork; root equality)
  and_to_or       a conjunction of admission checks weakens       (any ONE check now suffices)
  or_to_and       a disjunction narrows
  bound_relax     a declared bound becomes effectively unbounded  (I-5 growth on an axis)
  return_accept   a `return false` becomes `return true`          (fail-closed -> fail-open)
  return_refuse   a `return true` becomes `return false`
  body_true       a whole predicate becomes vacuous               (THE vacuous-gate probe)
  body_false      a whole predicate refuses everything

DIRECTION MATTERS. `guard_disable`, `cmp_relax`, `eq_flip`, `and_to_or`, `bound_relax`,
`return_accept` and `body_true` are the FUND-SAFETY direction: they make the node MORE permissive,
and a survivor there is an undefended soundness invariant. `guard_force`, `cmp_tighten`, `or_to_and`,
`return_refuse` and `body_false` are the CHAIN-CONTINUITY direction: they make the node refuse more,
and a survivor there is an undefended progress invariant. Both are reported, never merged into one
number, because the charter treats a stalled chain and a free mint as different failures.

Every operator is a pure text rewrite over a span of lines. Nothing here decides a verdict; a
mutation that does not compile is the ENGINE's own defect and is scored UNCOMPILABLE, never a kill.
"""

import hashlib
import re

# Direction of the semantic change: does the mutant make the node admit more, or refuse more?
PERMISSIVE = "permissive"     # soundness / fund-safety direction
RESTRICTIVE = "restrictive"   # progress / chain-continuity direction

IF_OPEN_RE = re.compile(r"^(?P<pre>[ \t]*(?:\}\s*else\s+)?)if\s+(?P<cond>.+?)\s*\{\s*$")
CMP_TOKENS = [" == ", " != ", " <= ", " >= ", " < ", " > "]
INT_LIT_RE = re.compile(r"(?<![\w.])(\d[\d_]*)(?:usize|u8|u16|u32|u64|u128|i32|i64)?(?![\w.])")


class Mutation(object):
    """One applied semantic change: replace source lines [a, b] with `after`."""

    def __init__(self, op, direction, relpath, a, b, before, after, fn_name, site_kind, note=""):
        self.op = op
        self.direction = direction
        self.relpath = relpath
        self.a = a            # 0-based inclusive first line replaced
        self.b = b            # 0-based inclusive last line replaced
        self.before = before  # exact original text of that span
        self.after = after    # replacement text for that span
        self.fn_name = fn_name
        self.site_kind = site_kind
        self.note = note

    @property
    def site_hash(self):
        return hashlib.sha256(self.before.encode("utf-8")).hexdigest()[:12]

    @property
    def mutant_id(self):
        return "%s@%d:%s:%s" % (self.relpath, self.a + 1, self.op, self.site_hash)

    def to_json(self):
        return {
            "mutant_id": self.mutant_id,
            "operator": self.op,
            "direction": self.direction,
            "file": self.relpath,
            "line": self.a + 1,
            "span_lines": [self.a + 1, self.b + 1],
            "function": self.fn_name,
            "site_kind": self.site_kind,
            "site_hash": self.site_hash,
            "before": self.before,
            "after": self.after,
            "note": self.note,
        }


def _cond_span(line):
    """(prefix, condition) for a single-line `if <cond> {`, else None."""
    m = IF_OPEN_RE.match(line)
    if not m:
        return None
    cond = m.group("cond")
    # `if let ...` binds a pattern; it has no boolean condition to disable, so it is not a site.
    if cond.startswith("let ") or cond.startswith("let("):
        return None
    return (m.group("pre"), cond)


def guard_ops(rf, site):
    """A refusal guard that stops refusing (permissive) / fires always (restrictive)."""
    line = rf.lines[site["line"]]
    parts = _cond_span(line)
    if not parts:
        return []
    pre, cond = parts
    out = []
    out.append(Mutation(
        "guard_disable", PERMISSIVE, rf.relpath, site["line"], site["line"], line,
        pre + "if false {", site["fn"], site["kind"],
        note="the guard `%s` no longer refuses anything" % cond.strip()))
    out.append(Mutation(
        "guard_force", RESTRICTIVE, rf.relpath, site["line"], site["line"], line,
        pre + "if true {", site["fn"], site["kind"],
        note="the guard `%s` refuses unconditionally" % cond.strip()))
    return out


def _replace_nth(line, token, repl, n):
    idx = -1
    for _ in range(n + 1):
        idx = line.find(token, idx + 1)
        if idx < 0:
            return None
    return line[:idx] + repl + line[idx + len(token):]


def comparison_ops(rf, site):
    """Relational / equality operator mutation, one mutant per occurrence on the line."""
    line = rf.lines[site["line"]]
    out = []
    swaps = [
        (" < ", " <= ", "cmp_relax", PERMISSIVE),
        (" > ", " >= ", "cmp_relax", PERMISSIVE),
        (" <= ", " < ", "cmp_tighten", RESTRICTIVE),
        (" >= ", " > ", "cmp_tighten", RESTRICTIVE),
        (" == ", " != ", "eq_flip", PERMISSIVE),
        (" != ", " == ", "eq_flip", PERMISSIVE),
    ]
    for token, repl, op, direction in swaps:
        count = line.count(token)
        for n in range(count):
            new = _replace_nth(line, token, repl, n)
            if new is None or new == line:
                continue
            out.append(Mutation(op, direction, rf.relpath, site["line"], site["line"], line, new,
                                site["fn"], site["kind"],
                                note="occurrence %d of `%s` -> `%s`" % (n + 1, token.strip(), repl.strip())))
    return out


def logic_ops(rf, site):
    """Weaken a conjunction of checks / narrow a disjunction."""
    line = rf.lines[site["line"]]
    out = []
    for token, repl, op, direction in ((" && ", " || ", "and_to_or", PERMISSIVE),
                                       (" || ", " && ", "or_to_and", RESTRICTIVE)):
        for n in range(line.count(token)):
            new = _replace_nth(line, token, repl, n)
            if new is None:
                continue
            out.append(Mutation(op, direction, rf.relpath, site["line"], site["line"], line, new,
                                site["fn"], site["kind"],
                                note="occurrence %d of `%s`" % (n + 1, token.strip())))
    return out


def bound_ops(rf, site):
    """A declared numeric bound becomes effectively unbounded (I-5: no growth on any axis)."""
    line = rf.lines[site["line"]]
    if not any(t in line for t in CMP_TOKENS):
        return []
    out = []
    for n, m in enumerate(list(INT_LIT_RE.finditer(line))):
        lit = m.group(1)
        if lit.replace("_", "") in ("0", "1"):
            continue  # 0 is unchanged by multiplication; 1 is usually a shape constant, not a bound
        new = line[:m.start(1)] + ("%s.saturating_mul(1_000_000)" % lit) + line[m.end(1):]
        out.append(Mutation("bound_relax", PERMISSIVE, rf.relpath, site["line"], site["line"], line, new,
                            site["fn"], site["kind"],
                            note="bound literal %s widened by 1e6 (occurrence %d)" % (lit, n + 1)))
    return out


def return_ops(rf, site):
    """A fail-closed `return false` opens; an accepting `return true` closes."""
    line = rf.lines[site["line"]]
    stripped = line.strip()
    out = []
    if stripped == "return false;":
        out.append(Mutation("return_accept", PERMISSIVE, rf.relpath, site["line"], site["line"], line,
                            line.replace("return false;", "return true;"), site["fn"], site["kind"],
                            note="a refusal becomes an acceptance"))
    elif stripped == "return true;":
        out.append(Mutation("return_refuse", RESTRICTIVE, rf.relpath, site["line"], site["line"], line,
                            line.replace("return true;", "return false;"), site["fn"], site["kind"],
                            note="an acceptance becomes a refusal"))
    return out


def body_ops(rf, fn):
    """THE VACUOUS-GATE PROBE: replace a whole boolean predicate with a constant.

    `body_true` asks the sharpest question this engine can ask of a verify function: *does the suite
    notice if this predicate stops predicating at all?* A survivor is not a subtle gap - it is a gate
    that defends nothing our pins can see. `body_false` is its progress-side twin.
    """
    ret = fn["ret"].strip()
    if ret != "bool":
        return []
    a = fn["body_open_idx"]
    b = fn["body_end_idx"]
    before = "\n".join(rf.lines[a:b + 1])
    open_line = rf.lines[a]
    col = fn["body_open_col"]
    head = open_line[:col]
    indent = fn["indent"]
    out = []
    for op, val, direction in (("body_true", "true", PERMISSIVE), ("body_false", "false", RESTRICTIVE)):
        after = head + "{\n" + indent + "    " + val + "\n" + indent + "}"
        out.append(Mutation(op, direction, rf.relpath, a, b, before, after, fn["name"], "predicate_body",
                            note="the whole predicate `%s` collapses to `%s`" % (fn["name"], val)))
    return out


ALL_LINE_OPS = (guard_ops, comparison_ops, logic_ops, bound_ops, return_ops)

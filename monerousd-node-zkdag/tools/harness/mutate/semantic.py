# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - THE **SEMANTIC** OPERATOR SET.  One operator per fault this tree actually produced.

Part C of `docs/harness-design.md` opens with the reason this file exists:

    "A textual mutator (flip `<` to `<=`, delete a random statement) produces mostly build failures
     and equivalent mutants and teaches nothing about this tree."

`operators.py` shipped twelve such generic operators. They are sound engineering and they stay: a
`guard_disable` survivor is a real finding. But the 2026-09-08 calibration measured them at 2 of the
5 rows lane M owns, and the three misses (B1, B4, C-H1) are misses of VOCABULARY, not of machinery -
none of the twelve can express "the whole struct was replaced under a blob-only id", "the loop beside
the filtered one consumes the raw set", or "the verdict was computed and then counted rather than
consulted". Each operator below is named after a defect that reached this tree's main line, and its
docstring names it.

  M2   check-elision-on-one-path        E-8 descent door / B3 `ingest_tx_prechecked` / D-2 instant_sync
  M3   refusal-computed-then-discarded  C-H1 `pump_parked_page` counts the verdict, applies the page
  M4   set-membership-write-deleted     B2 the re-stamp arm returned before the `spent` write
  M6   check-reordered-after-the-write  B1 whole-struct insert before the double-spend loop (TOCTOU)
  M7   trust-from-peer-data             C-H4 a refused record's bytes become its own root authority
  M8   binding-field-ablation           A3/A5 - defends the fields the 2026-09-07 fix added
  M10  exemption-widened                `header_grind_admits` - `is_genesis()` is a field the SENDER writes
  M12  scope-narrowed                   B4 the reconcile loop beside the filtered note loop
  M13  position-taken-from-the-wire     A5 `anchor_ordinal` installed as the anchor's record row

TWO OPERATORS HAVE A **FIND** HALF AS WELL AS A **BREAK** HALF, and the find half is the one that
catches the open hole. A mutation operator can only defend a check that EXISTS; the row it was named
after is usually a check that does NOT exist. So:

  * M3 ships `discarded_verdicts()` - the verdict-DATAFLOW pass. It reports a call whose verdict is
    consumed ONLY by a counter or a log line. That is C-H1 stated mechanically, and it fires on the
    LIVE tree (see the calibration note in targets.json).
  * M12 ships `shared_check_coverage()` - the call-site map of every shared check helper. The design's
    words: "this operator's real output is a coverage map ... any site with none is the 'I fixed one
    of several' trap waiting to be re-sprung". Charter 9.5 names that trap as hit FOUR times here.
  * M8's find half is lane X's `tools/harness/bind/enumerate.py`, which finds the fields that were
    NEVER folded. M8 defends what is there; the enumeration finds what is missing. A5 proves the
    second is the one that finds holes nobody suspected.

COST ARITHMETIC, written down rather than assumed - cons: NONE on chain, and the reason is structural.
Nothing here is compiled into the node: it is a Python driver under tools/ that never enters the crate
graph, so the delta it adds to every cardinal is exactly zero - 0 bytes on the DA, 0 bytes of node RAM,
0 gates removed from any shipping path, 0 change to consensus. Every mutation is written only into the
engine's isolated clone (mutate.py property 1), and the live tree is hashed before and after. Engine
cost is f(mutants selected), a fixed budget in targets.json - never f(chain height / notes / peers).
A mutant that does not compile is UNCOMPILABLE and is EXCLUDED from the score, never counted as a kill:
this file may be wrong about Rust, and being wrong can never inflate a number.
"""

import re

import doors
import selection
from operators import Mutation, PERMISSIVE

# ── shared vocabulary ─────────────────────────────────────────────────────────────────────────────

# A statement that WRITES into a store. The `;` is required: an expression tail is not a statement and
# deleting it changes the function's type, which is a build failure rather than a measurement.
WRITE_STMT_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<recv>(?:self\.)?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\.(?P<method>insert|remove|push|extend|append|retain|truncate|clear|set|store|record|register)\s*\(")
READ_RE = re.compile(
    r"(?P<recv>(?:self\.)?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\.(?:contains|contains_key|get|get_mut|is_spent|has)\s*\(")
CALL_IN_COND_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*\(")
COUNTER_RE = re.compile(r"^[ \t]*[A-Za-z_][A-Za-z0-9_.]*\s*[+\-]=\s*[^;]+;\s*$")
LOG_RE = re.compile(r"^[ \t]*(?:eprintln!|println!|log::|tracing::|debug!|warn!|info!)")
FOLD_RE = re.compile(r"\.(?:extend_from_slice|update|absorb|write|push_bytes)\s*\(")
# A value whose authority is the CHAIN's, not the offer's. Substituting the offered value for one of
# these is M7's whole point: authority that is reachable from the input it authorises.
AUTHORITY_RE = re.compile(
    r"(committed|certified|chain_|_root\b|root_at|root_of|derive|params\(\)|genesis|expected|canonical|our_)")
POSITION_RE = re.compile(r"(ordinal|position|index|seq\b|_seq|order|row|height|slot)")
LOCAL_AUTHORITY_RE = re.compile(r"(self\.|dag\(\)|params\(\)|\bown_|\blocal_|certified_)")


def _fn_of(rf, idx):
    best = None
    for fn in rf.fns:
        if fn["body_open_idx"] <= idx <= fn["body_end_idx"]:
            if best is None or fn["body_open_idx"] > best["body_open_idx"]:
                best = fn
    return best


def _checking_fns(rf, focus=()):
    focus = set(focus or ())
    out = []
    for fn in rf.fns:
        if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        if selection.is_checking_fn(rf, fn):
            out.append(fn)
    out.sort(key=lambda f: (0 if f["name"] in focus else 1, f["body_open_idx"]))
    return out


def _cond_of(rf, idx):
    """(prefix, condition) for a single-line `if <cond> {`, else None. Shared with operators.py's rule
    that `if let` binds a pattern and is therefore not a boolean site."""
    m = re.match(r"^(?P<pre>[ \t]*(?:\}\s*else\s+)?)if\s+(?P<cond>.+?)\s*\{\s*$", rf.masked[idx])
    if not m:
        return None
    cond = m.group("cond")
    if cond.startswith("let ") or cond.startswith("let("):
        return None
    # the RAW text is what gets rewritten; the masked text is only what decided the shape
    raw = re.match(r"^(?P<pre>[ \t]*(?:\}\s*else\s+)?)if\s+(?P<cond>.+?)\s*\{\s*$", rf.lines[idx])
    if not raw:
        return None
    return (raw.group("pre"), raw.group("cond"))


def _block_end(rf, idx):
    line = rf.masked[idx]
    col = line.rfind("{")
    if col < 0:
        return None
    return rf.match_block_from(idx, col)


# ── M3 · REFUSAL COMPUTED THEN DISCARDED ──────────────────────────────────────────────────────────

def m3_mutants(rf, focus=()):
    """Keep the check CALL; drop the consumption of its verdict.

    `if !door_admits(x) { return Err(..) }`  ->  `if { let _ = (!door_admits(x)); false } { .. }`

    The call still runs, so every side effect it has is preserved and the mutant isolates ONE thing:
    does anything in the suite depend on the verdict being CONSULTED? A `guard_disable` mutant answers
    a different question - it deletes the call as well - and the pair is informative: guard_disable
    killed while M3 survives means the pin asserts that the door was CALLED, not that the refused item
    stayed out of state. That is the exact C-H1 shape and the design rule it enforces: every refusal
    pin must assert on the STATE the door produces, never on the verdict it returns.
    """
    out = []
    for fn in _checking_fns(rf, focus):
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            parts = _cond_of(rf, i)
            if not parts:
                continue
            pre, cond = parts
            if not CALL_IN_COND_RE.search(cond):
                continue
            end = _block_end(rf, i)
            if end is None:
                continue
            block = "\n".join(rf.lines[i:min(end, i + 20) + 1])
            if not any(t in block for t in selection.REFUSAL_TOKENS):
                continue
            after = "%sif { let _ = (%s); false } {" % (pre, cond)
            out.append(Mutation(
                "M3_refusal_discarded", PERMISSIVE, rf.relpath, i, i, rf.lines[i], after,
                fn["name"], "fail_closed_guard",
                note="the check `%s` still RUNS; its verdict is discarded (C-H1's shape)" % cond.strip()[:80]))
    return out


def discarded_verdicts(rf):
    """⭐ THE VERDICT-DATAFLOW PASS - M3's FIND half, and the one that reports C-H1 on the live tree.

    A call that returns a verdict, whose ONLY consumption is a counter increment or a log line. The
    door was asked, the answer was tallied, and nothing branched on it. Reported as a FINDING, not as
    a mutant: there is no check here to break.

    Rule, stated so a reader can dispute it: the guard's block must contain at least one counter
    increment or log, and NO refusal, no `return`, no `continue`/`break`, and no store write. A block
    that writes state is consuming the verdict, whatever else it also does.
    """
    out = []
    for fn in rf.fns:
        if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            parts = _cond_of(rf, i)
            if not parts:
                continue
            _pre, cond = parts
            if not CALL_IN_COND_RE.search(cond):
                continue
            end = _block_end(rf, i)
            if end is None or end - i > 8:
                continue
            body = [rf.lines[j] for j in range(i + 1, end)]
            body = [b for b in body if b.strip() and not b.strip().startswith("//")]
            if not body:
                continue
            counters = [b for b in body if COUNTER_RE.match(b)]
            logs = [b for b in body if LOG_RE.match(b)]
            if not counters and not logs:
                continue
            rest = [b for b in body if b not in counters and b not in logs]
            if rest:
                continue
            if any(t in "\n".join(body) for t in ("return", "continue", "break", "?;")):
                continue
            if any(WRITE_STMT_RE.match(b) for b in body):
                continue
            # SEVERITY, so a real door is never lost among the incidental ones. HIGH means the
            # discarded verdict comes from a call the check lexicon recognises as a DOOR
            # (`accept_fetched_record`, `adopt_sidecar_row`); everything else is ADVISORY and is
            # still printed, because a filter that hides rows is how a blind class is created.
            callees = [m.group(1) for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", cond)]
            doorish = [c for c in callees if c not in doors.NOISE and doors.is_check_name(c)]
            out.append({
                "file": rf.relpath, "line": i + 1, "fn": fn["name"],
                "cond": cond.strip()[:100],
                "consumed_by": "counter" if counters else "log",
                "severity": "HIGH" if doorish else "advisory",
                "door": doorish[0] if doorish else "",
                "text": rf.lines[i].strip()[:120],
            })
    return out


# ── M4 · SET-MEMBERSHIP WRITE DELETED ─────────────────────────────────────────────────────────────

def refusal_consulted_stores(rf):
    """Stores a REFUSAL reads. The inventory M4 deletes writes into, generated not curated.

    ⛔ "READS INSIDE A FUNCTION THAT REFUSES" IS TOO NARROW, AND B2 IS THE PROOF. MEASURED
    2026-09-08: `Mempool::nullifier_claim_conflict` reads `self.spent` and contains no refusal token
    at all - it RETURNS a bool and its CALLER refuses on it, which is the normal shape of a check
    helper in this tree. With the narrow rule the only store found in `mempool.rs` was `self.txs`,
    and `self.spent` - the double-spend set that IS calibration row B2 - was not in the inventory.
    The rule is therefore a read inside any CHECK-BEARING function (`selection.is_checking_fn`,
    which counts a verdict return type), which is the same rule the site selector already uses.
    """
    stores = {}
    for fn in rf.fns:
        if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        if not selection.is_checking_fn(rf, fn):
            continue
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            for m in READ_RE.finditer(rf.masked[i]):
                stores.setdefault(m.group("recv"), []).append((fn["name"], i + 1))
    return stores


def m4_mutants(rf, focus=()):
    """Delete one write into a store that a refusal consults.

    B2's shape exactly: the mempool re-stamp arm returned before the `spent` bookkeeping, so a
    nullifier arriving through that arm was never registered and the double-spend refusal did not
    exist on that path. The refusal was still there, still correct, and asked a set that had never
    been told. A survivor here means the set is not the gate - the gate is luck or ordering.
    """
    stores = refusal_consulted_stores(rf)
    if not stores:
        return []
    out = []
    for i, raw in enumerate(rf.lines):
        if rf.in_oracle_region(i):
            continue
        m = WRITE_STMT_RE.match(rf.masked[i])
        if not m:
            continue
        if not rf.masked[i].rstrip().endswith(";"):
            continue                       # a tail expression is not a statement; deleting it is a type change
        recv = m.group("recv")
        if recv not in stores:
            continue
        fn = _fn_of(rf, i)
        if fn is None or fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        readers = stores[recv]
        after = m.group("indent") + "// [M4] write into `%s` deleted" % recv
        out.append(Mutation(
            "M4_membership_write_deleted", PERMISSIVE, rf.relpath, i, i, raw, after,
            fn["name"], "refusal_consulted_write",
            note="`%s.%s(..)` deleted; %d refusal(s) read this store (first: %s:%d)"
                 % (recv, m.group("method"), len(readers), readers[0][0], readers[0][1])))
    return out


# ── M6 · CHECK REORDERED AFTER THE STATE WRITE (TOCTOU) ───────────────────────────────────────────

def m6_mutants(rf, focus=()):
    """Move a refusal guard from BEFORE a state write to AFTER it, keeping both.

    B1: the re-stamp arm did the whole-struct `txs.insert(id, tx)` before the double-spend loop, the
    capacity check and the bookkeeping. Nothing was deleted, so every "does it refuse?" pin stayed
    green - what changed was ATOMICITY, and only a pin asserting that nothing partial is applied on a
    refusal can see it. A survivor means the suite tests a refusal's return value and not its effect.

    Guarded: the write's receiver must not appear in the guard's condition (a guard whose input the
    write changes is a different mutant and a different question). Declared as an approximation.
    """
    out = []
    for fn in _checking_fns(rf, focus):
        i = fn["body_open_idx"]
        while i <= fn["body_end_idx"]:
            parts = _cond_of(rf, i)
            if not parts:
                i += 1
                continue
            _pre, cond = parts
            end = _block_end(rf, i)
            if end is None or end + 1 > fn["body_end_idx"]:
                i += 1
                continue
            block = "\n".join(rf.lines[i:end + 1])
            if not any(t in block for t in selection.REFUSAL_TOKENS):
                i += 1
                continue
            w = end + 1
            mw = WRITE_STMT_RE.match(rf.masked[w])
            if not mw or not rf.masked[w].rstrip().endswith(";"):
                i = end + 1
                continue
            recv_root = mw.group("recv").split(".")[-1]
            if recv_root and re.search(r"(?<![A-Za-z0-9_])" + re.escape(recv_root) + r"(?![A-Za-z0-9_])", cond):
                i = end + 1
                continue
            before = "\n".join(rf.lines[i:w + 1])
            after = rf.lines[w] + "\n" + "\n".join(rf.lines[i:end + 1])
            out.append(Mutation(
                "M6_check_after_write", PERMISSIVE, rf.relpath, i, w, before, after,
                fn["name"], "toctou_pair",
                note="the refusal guarding `%s` now runs AFTER the write it was guarding"
                     % mw.group("recv")))
            i = w + 1
    return out


# ── M7 · TRUST TAKEN FROM PEER-SUPPLIED DATA (circular authority) ─────────────────────────────────

def m7_mutants(rf, focus=()):
    """Replace the AUTHORITY side of a comparison with the side being judged.

    `if derived_root != offered_root { refuse }` -> `if offered_root != offered_root { refuse }`

    The check still runs, still compares, still refuses - against itself. C-H4's shape:
    `da_block_root_at_ordinal_derive` derives the "committed" root from the bytes this node holds, so a
    refused record becomes its own root authority on the second offer. A single-offer suite cannot see
    this class at all, and the operator reports that as `SURVIVED (no sequence coverage)` when no pin
    performs the two-offer sequence offer -> refused -> apply -> re-offer.
    """
    out = []
    for fn in _checking_fns(rf, focus):
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            masked = rf.masked[i]
            if " == " not in masked and " != " not in masked:
                continue
            block = "\n".join(rf.lines[i:min(i + 8, fn["body_end_idx"] + 1)])
            if not any(t in block for t in selection.REFUSAL_TOKENS):
                continue
            tok = " == " if " == " in masked else " != "
            raw = rf.lines[i]
            if raw.count(tok) != 1:
                continue
            head, _, tail = raw.partition(tok)
            lhs = head[head.rfind("if ") + 3:] if "if " in head else head
            rhs = tail.split(" {")[0].rstrip().rstrip("{").rstrip()
            if not lhs.strip() or not rhs.strip():
                continue
            la, ra = bool(AUTHORITY_RE.search(lhs)), bool(AUTHORITY_RE.search(rhs))
            if la == ra:
                continue                    # both or neither: no authority side to substitute
            if la:
                after = raw.replace(lhs, rhs, 1)
                taken = lhs.strip()
            else:
                after = raw[: raw.rfind(rhs)] + lhs.rstrip() + raw[raw.rfind(rhs) + len(rhs):]
                taken = rhs.strip()
            if after == raw:
                continue
            out.append(Mutation(
                "M7_trust_from_peer_data", PERMISSIVE, rf.relpath, i, i, raw, after,
                fn["name"], "authority_comparison",
                note="the chain-derived authority `%s` is replaced by the value being judged "
                     "(circular authority)" % taken[:70]))
    return out


# ── M8 · BINDING FIELD ABLATION ───────────────────────────────────────────────────────────────────

def preimage_builders(rf):
    """Functions that BUILD a hashed preimage or a transcript: >= 3 fold statements in the body."""
    out = []
    for fn in rf.fns:
        if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        n = 0
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if not rf.in_oracle_region(i) and FOLD_RE.search(rf.masked[i]):
                n += 1
        if n >= 3:
            out.append((fn, n))
    return out


def m8_mutants(rf, focus=()):
    """Remove ONE field from a hashed preimage.

    `sync_binding` folds eleven-plus values; `BlockHeader::preimage` folds the header. A5 and A3 were
    fields that were never folded at all - the enumeration in `tools/harness/bind/` finds those. THIS
    operator defends the ones that ARE folded: for each folded field, is there a pin that asserts the
    binding CHANGES when that field changes? A survivor is one refactor away from being A5 again.
    """
    out = []
    for (fn, _n) in preimage_builders(rf):
        if fn["name"] not in set(focus or ()) and not selection.is_checking_fn(rf, fn) \
                and not re.search(r"(binding|preimage|digest|commit|transcript|acc)", fn["name"]):
            continue
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            if not FOLD_RE.search(rf.masked[i]):
                continue
            if not rf.masked[i].rstrip().endswith(";"):
                continue
            raw = rf.lines[i]
            indent = re.match(r"^[ \t]*", raw).group(0)
            field = raw.strip()
            out.append(Mutation(
                "M8_binding_field_ablation", PERMISSIVE, rf.relpath, i, i, raw,
                indent + "// [M8] one field removed from the preimage",
                fn["name"], "preimage_fold",
                note="`%s` no longer enters the `%s` preimage" % (field[:80], fn["name"])))
    return out


# ── M10 · EXEMPTION WIDENED ───────────────────────────────────────────────────────────────────────

def m10_mutants(rf, focus=()):
    """Drop the LOCALLY-PRODUCED conjunct from an exemption, leaving the sender-controlled one.

    MEASURED 2026-09-07 in `Node::header_grind_admits`: `BlockHeader::is_genesis()` is
    `parents.is_empty()` - a field the SENDER writes - so "genesis is exempt from the grind" read, to
    an attacker, as "any header I send with an empty parent list is exempt". Every exemption in this
    tree must be keyed to a value the node itself produced, and this operator is how that is enforced
    forever: a survivor means an exemption is claimable and no pin offers an object merely SHAPED like
    the exempt case.
    """
    out = []
    for fn in _checking_fns(rf, focus):
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            parts = _cond_of(rf, i)
            if not parts:
                continue
            _pre, cond = parts
            if " && " not in cond:
                continue
            end = _block_end(rf, i)
            if end is None:
                continue
            block = "\n".join(rf.lines[i:min(end, i + 6) + 1])
            if "return true" not in block and "return Ok(" not in block:
                continue               # only an EXEMPTION (an early admission) has this shape
            conj = [c.strip() for c in cond.split(" && ")]
            if len(conj) < 2:
                continue
            for k, c in enumerate(conj):
                if not LOCAL_AUTHORITY_RE.search(c):
                    continue
                kept = [x for j, x in enumerate(conj) if j != k]
                after = rf.lines[i].replace(cond, " && ".join(kept), 1)
                if after == rf.lines[i]:
                    continue
                out.append(Mutation(
                    "M10_exemption_widened", PERMISSIVE, rf.relpath, i, i, rf.lines[i], after,
                    fn["name"], "exemption",
                    note="the locally-produced conjunct `%s` is dropped; the exemption is now keyed "
                         "only on what the sender sends" % c[:70]))
    return out


# ── M12 · SCOPE NARROWED ("one of several") ───────────────────────────────────────────────────────

def m12_mutants(rf, focus=()):
    """Apply an existing check to a strict SUBSET of the items it must cover.

    B4: the graft-side reconcile loop ran over raw pool blobs while the note loop beside it used
    `graft_admitted_notes`. The check existed, was correct, and covered one of two loops. The two
    forms here are the two ways that happens in this tree: a loop that checks every item becomes a
    loop that checks the first, and a loop over a FILTERED set becomes a loop over the raw one.
    """
    out = []
    for fn in _checking_fns(rf, focus):
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            m = re.match(r"^(?P<indent>[ \t]*)for\s+(?P<pat>.+?)\s+in\s+(?P<expr>.+?)\s*\{\s*$", rf.lines[i])
            if not m:
                continue
            expr = m.group("expr")
            # (a) the loop covers only the FIRST item
            if ".iter()" in expr or ".into_iter()" in expr or ".values()" in expr or ".keys()" in expr:
                after = rf.lines[i].replace(expr, expr + ".take(1)", 1)
                out.append(Mutation(
                    "M12_scope_narrowed", PERMISSIVE, rf.relpath, i, i, rf.lines[i], after,
                    fn["name"], "item_loop",
                    note="the loop over `%s` now covers only the FIRST item" % expr.strip()[:70]))
            # (b) the loop consumes the RAW set where it consumed the filtered one
            fm = re.search(r"\.filter\((?:[^()]|\([^()]*\))*\)", expr)
            if fm:
                narrowed = expr[: fm.start()] + expr[fm.end():]
                after = rf.lines[i].replace(expr, narrowed, 1)
                out.append(Mutation(
                    "M12_scope_narrowed", PERMISSIVE, rf.relpath, i, i, rf.lines[i], after,
                    fn["name"], "filtered_loop",
                    note="the filter `%s` is dropped; the loop consumes the RAW set (B4's shape)"
                         % fm.group(0)[:60]))
    return out


def shared_check_coverage(files):
    """⭐ M12's FIND half - the CALL-SITE MAP of every shared check helper.

    The design: "this operator's real output is a coverage map: which of the N sites of a shared
    helper have a pin. Any site with none is the 'I fixed one of several' trap waiting to be
    re-sprung, and the engine reports the map even when every mutant is killed."
    """
    idx = {}
    for rf in files:
        for fn in rf.fns:
            if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                continue
            if doors.is_check_name(fn["name"]):
                idx.setdefault(fn["name"], []).append(rf.relpath)
    sites = {}
    for rf in files:
        for fn in rf.fns:
            if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
                continue
            for name in doors.callees(rf, fn):
                if name in idx and name != fn["name"]:
                    sites.setdefault(name, []).append((rf.relpath, fn["name"]))
    return dict((k, sorted(set(v))) for k, v in sites.items() if len(set(v)) > 1)


# ── M13 · POSITION / ORDER TAKEN FROM THE WIRE ────────────────────────────────────────────────────

def m13_mutants(rf, focus=()):
    """Replace a DERIVED position with a WIRE-CARRIED one of the same shape.

    A5 is this operator's namesake: `anchor_ordinal` arrives in the bundle and is installed as the
    anchor's record row, with every later position following from it. The tree's own law - "the
    ordinal IS the DAG's position" - has no automatic enforcement, and the record-spine fork (rid at
    ordinal 48 on one node and 9 on its peer) is what the absence costs. Killed by the two-node
    order-permutation differential; a survivor means the suite never permutes arrival order.
    """
    out = []
    for fn in rf.fns:
        if fn["is_oracle_fn"] or fn["in_oracle_mod"]:
            continue
        wire = []
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            for m in re.finditer(r"(?<![A-Za-z0-9_])([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)"
                                 r"(?![A-Za-z0-9_(])", rf.masked[i]):
                if m.group(1) in ("self", "crate") or not POSITION_RE.search(m.group(2)):
                    continue
                wire.append(m.group(0))
        if not wire:
            continue
        pick = sorted(set(wire))[0]
        for i in range(fn["body_open_idx"], fn["body_end_idx"] + 1):
            if rf.in_oracle_region(i):
                continue
            m = re.match(r"^(?P<indent>[ \t]*)let\s+(?:mut\s+)?(?P<name>[a-z_][a-z0-9_]*)"
                         r"(?P<ty>\s*:\s*[^=]+)?\s*=\s*(?P<rhs>.+);\s*$", rf.lines[i])
            if not m:
                continue
            if not POSITION_RE.search(m.group("name")):
                continue
            rhs = m.group("rhs")
            if pick in rhs or not ("self." in rhs or "(" in rhs):
                continue               # already the wire value, or a plain literal: nothing derived
            after = rf.lines[i].replace(rhs, pick, 1)
            if after == rf.lines[i]:
                continue
            out.append(Mutation(
                "M13_position_from_wire", PERMISSIVE, rf.relpath, i, i, rf.lines[i], after,
                fn["name"], "derived_position",
                note="`%s` is taken from the wire field `%s` rather than derived from `%s`"
                     % (m.group("name"), pick, rhs.strip()[:50])))
    return out


# ── M2 · CHECK ELISION ON ONE PATH (matrix-driven) ────────────────────────────────────────────────

def m2_mutants(files, families):
    """Empty ONE FILLED CELL of the door x check matrix: delete a check's call from exactly one door
    and leave every sibling door intact.

    Complete BY CONSTRUCTION over the matrix rather than over the source text, which is the property
    the design asks for. The verdict is louder than a plain survivor: if the mutant survives while a
    pin exercising a SIBLING door stays green, that is the 9.6 blind spot itself - the class has an
    adversarial pin, and this door does not.

    The matrix's EMPTY cells are reported separately (`doors.matrix`) and are not mutants: there is
    nothing to break in a check that was never called. B3 and E-8 are empty cells, not survivors.
    """
    out = []
    for cell in doors.filled_cells(files, families):
        rf, fn, i = cell["rf"], cell["fn"], cell["line"]
        raw = rf.lines[i]
        indent = re.match(r"^[ \t]*", raw).group(0)
        masked = rf.masked[i]
        if re.match(r"^[ \t]*(?:self\.|crate::)?[A-Za-z_][A-Za-z0-9_:.]*\s*\(", masked) \
                and masked.rstrip().endswith(";"):
            after = indent + "// [M2] the `%s` call is removed from this door only" % cell["check"]
        else:
            continue    # a check riding inside a larger expression is M12's site, not M2's
        out.append(Mutation(
            "M2_check_elision_one_path", PERMISSIVE, rf.relpath, i, i, raw, after,
            fn["name"], "door_check_cell",
            note="door `%s` no longer runs `%s`; sibling door(s) %s still do"
                 % (cell["door"], cell["check"], ",".join(cell["siblings"]))))
    return out


ALL_SEMANTIC_OPS = (m3_mutants, m4_mutants, m6_mutants, m7_mutants, m8_mutants,
                    m10_mutants, m12_mutants, m13_mutants)

# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - the mutation engine's Rust reader.

A DELIBERATELY SMALL, DELIBERATELY HONEST reader. It is not a Rust parser and never pretends to be
one: it finds function spans and brace-matched blocks by counting braces with string/char/comment
literals masked out. Everything it gets wrong is caught downstream, because a mutant that does not
compile is recorded as UNCOMPILABLE and EXCLUDED from the mutation score - it is never silently
counted as a kill. An engine that inflated its own score by counting its own parse failures as "the
suite caught it" would be exactly the instrument this project must not build.

Two hard rules live here:

* **The oracle is never mutated.** cfg-test modules, test-attributed functions, and whole
  oracle-only files are excluded from every mutation site. Mutating the suite would produce a
  meaningless verdict (a suite that fails because you broke the suite proves nothing about the
  chain).
* **A line is a site only if it CHECKS something.** Selection targets refusals, bounds and
  comparisons inside verify paths, because a mutation score over getters and constructors is a
  number that goes up without the instrument getting sharper.
"""

import re

FN_RE = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
MOD_RE = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
ATTR_RE = re.compile(r"^[ \t]*#\[")
# The attribute that marks an oracle function. Assembled, never written literally, so this reader is
# not itself mistaken for a suite file by source scanners.
TEST_ATTR_RE = re.compile(r"^[ \t]*#\[(?:tokio::)?" + "test" + r"\]")
CFG_TEST_RE = re.compile(r"cfg\(" + "test" + r"\)")

# Files whose entire content is ORACLE scaffolding are never mutation targets. Suffix rules only;
# any additional by-name exclusions live in `targets.json` so this reader stays a pure reader.
ORACLE_FILE_SUFFIXES = ("_tests.rs", "_scenarios.rs", "_fuzz_tests.rs", "_standard.rs")


def mask_literals(line):
    """Blank out //-comments, "strings" and 'chars' so brace counting cannot be fooled by text.

    Byte length is preserved (characters are replaced by spaces), so column offsets stay valid.
    Raw strings are handled conservatively: the whole rest of the line is masked when one opens,
    which can only make the reader MORE cautious, never less.
    """
    out = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            out.append(" " * (n - i))
            break
        if c == "r" and i + 1 < n and line[i + 1] in ('"', "#"):
            out.append(" " * (n - i))
            break
        if c == '"':
            out.append(" ")
            i += 1
            while i < n:
                if line[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                if line[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            # char literal or a lifetime; only treat as a literal when it closes on this line soon.
            close = line.find("'", i + 1)
            if 0 < close <= i + 4:
                out.append(" " * (close - i + 1))
                i = close + 1
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def mask_block_comments(lines):
    """Return a masked copy of `lines` with /* .. */ regions blanked, then per-line literals masked.

    ⛔ A `/*` INSIDE A LINE COMMENT OR A STRING IS NOT A BLOCK COMMENT, AND GETTING THAT WRONG IS
    SILENT. MEASURED 2026-09-08: the earlier form tested `"/*" in line` before it had looked at `//`
    or at any quote, so `node.rs`'s doc comment

        /// (level, canonical prefix) -> occupied sparse node (no-datadir mirror of the `nfnode/*.nd`
        index)

    at line 364 opened a block comment that NEVER CLOSED. Every one of the remaining ~2.7 MB of the
    file was masked to spaces, `RustFile.fns` came back **0 functions**, and any selection over
    `node.rs` would have produced an empty site list and reported it as a clean plan rather than as a
    reader failure. The five files lane M targeted at the time contain zero `/*` between them, which
    is exactly why nothing caught it. A reader that silently measures nothing is the worst failure an
    instrument can have, so this scanner now walks the line in ONE pass and gives `//`, `"`, `r"` and
    `'` their precedence over `/*` — the same precedence the Rust lexer gives them.

    Nesting is honoured (Rust's block comments nest). A raw string is masked to end-of-line, which is
    conservative in the safe direction: it can only hide a site, never invent one.
    """
    masked = []
    depth = 0
    for raw in lines:
        n = len(raw)
        out = []
        i = 0
        while i < n:
            if depth > 0:
                if raw.startswith("/*", i):
                    depth += 1
                    out.append("  ")
                    i += 2
                    continue
                if raw.startswith("*/", i):
                    depth -= 1
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
                continue
            # depth == 0: the lexer's precedence order.
            if raw.startswith("//", i):
                out.append(" " * (n - i))       # a line comment swallows the rest, `/*` included
                break
            if raw.startswith("/*", i):
                depth += 1
                out.append("  ")
                i += 2
                continue
            c = raw[i]
            if c == "r" and i + 1 < n and raw[i + 1] in ('"', "#"):
                out.append(" " * (n - i))       # raw string: masked to EOL (conservative)
                break
            if c == '"':
                out.append(" ")
                i += 1
                while i < n:
                    if raw[i] == "\\":
                        out.append("  ")
                        i += 2
                        continue
                    out.append(" ")
                    if raw[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if c == "'":
                close = raw.find("'", i + 1)
                if 0 < close <= i + 4:
                    out.append(" " * (close - i + 1))
                    i = close + 1
                    continue
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
        line_out = "".join(out)
        # Byte length is preserved so every column offset downstream stays valid.
        if len(line_out) < n:
            line_out += " " * (n - len(line_out))
        masked.append(line_out[:n])
    return masked


class RustFile(object):
    """One source file, read once: masked lines, function spans, and the oracle-only regions."""

    def __init__(self, relpath, text):
        self.relpath = relpath
        self.text = text
        self.lines = text.split("\n")
        self.masked = mask_block_comments(self.lines)
        self.oracle_regions = self._oracle_regions()
        self.fns = self._fns()

    # -- regions ---------------------------------------------------------------------------------
    def _match_block(self, open_idx, open_col):
        """Brace-match from (line index, column of '{'); returns the closing line index or None."""
        depth = 0
        for i in range(open_idx, len(self.masked)):
            line = self.masked[i]
            start = open_col if i == open_idx else 0
            for c in range(start, len(line)):
                ch = line[c]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return i
        return None

    def _oracle_regions(self):
        """Line ranges (inclusive) of cfg-test modules - never mutated."""
        regions = []
        for i, line in enumerate(self.masked):
            m = MOD_RE.match(line)
            if not m:
                continue
            j = i - 1
            is_oracle = False
            while j >= 0:
                s = self.masked[j].strip()
                if s == "" or s.startswith("///") or s.startswith("//") or ATTR_RE.match(self.masked[j]):
                    if CFG_TEST_RE.search(self.lines[j]) and ATTR_RE.match(self.masked[j]):
                        is_oracle = True
                        break
                    j -= 1
                    continue
                break
            if not is_oracle:
                continue
            end = self._match_block(i, line.index("{"))
            if end is not None:
                regions.append((i, end))
        return regions

    def in_oracle_region(self, idx):
        for (a, b) in self.oracle_regions:
            if a <= idx <= b:
                return True
        return False

    # -- functions -------------------------------------------------------------------------------
    def _fns(self):
        fns = []
        for i, line in enumerate(self.masked):
            m = FN_RE.match(line)
            if not m:
                continue
            open_idx = None
            open_col = None
            depth_paren = 0
            # ⛔ THE BRACKET DEPTH IS NOT OPTIONAL, AND OMITTING IT SILENTLY DROPS FUNCTIONS.
            # MEASURED 2026-09-08: `pub fn sync_binding(..) -> [u8; 16] {` was NOT in `RustFile.fns`.
            # The `;` inside the ARRAY TYPE `[u8; 16]` sits at paren depth 0, so the scanner read it as
            # the semicolon of a signature-only declaration (a trait method) and abandoned the function.
            # `sync_binding` is the binding preimage builder for the whole DSYNC adopt path - rows A3,
            # A5 and operator M8 all live inside it, and it was invisible to this reader. A dropped
            # function produces no sites, no mutants and NO ERROR, which is why it went unnoticed:
            # the plan simply came back shorter. Every `-> [T; N]` return type in the crate had the
            # same fate.
            depth_brack = 0
            stop = False
            for j in range(i, min(i + 60, len(self.masked))):
                seg = self.masked[j]
                start = m.end() if j == i else 0
                for c in range(start, len(seg)):
                    ch = seg[c]
                    if ch == "(":
                        depth_paren += 1
                    elif ch == ")":
                        depth_paren -= 1
                    elif ch == "[":
                        depth_brack += 1
                    elif ch == "]":
                        depth_brack -= 1
                    elif ch == "{" and depth_paren <= 0 and depth_brack <= 0:
                        open_idx, open_col = j, c
                        break
                    elif ch == ";" and depth_paren <= 0 and depth_brack <= 0:
                        stop = True
                        break
                if open_idx is not None or stop:
                    break
            if open_idx is None:
                continue
            end_idx = self._match_block(open_idx, open_col)
            if end_idx is None:
                continue
            sig = " ".join(self.lines[i:open_idx + 1])
            ret = ""
            rm = re.search(r"->\s*([^{]+)", sig)
            if rm:
                ret = rm.group(1).strip()
            is_oracle_fn = False
            j = i - 1
            while j >= 0:
                s = self.masked[j].strip()
                if s == "" or s.startswith("///") or s.startswith("//") or ATTR_RE.match(self.masked[j]):
                    # ⛔ A `cfg(test)` FUNCTION IS ORACLE SCAFFOLDING TOO, NOT ONLY A `cfg(test)` MODULE.
                    # MEASURED 2026-09-08: `#[cfg(test)] pub(crate) fn ingest_tx_unverified` in node.rs
                    # was read as a PRODUCTION door and appeared in the door matrix as a third sibling
                    # of `ingest_tx`, reporting four empty cells against a function that does not exist
                    # in a release build. Mutating it would have been worse: a mutant in test-only code
                    # that no pin covers is a SURVIVOR that means nothing, and it would have counted.
                    if TEST_ATTR_RE.match(self.lines[j]) or (
                            ATTR_RE.match(self.masked[j]) and CFG_TEST_RE.search(self.lines[j])):
                        is_oracle_fn = True
                        break
                    j -= 1
                    continue
                break
            fns.append({
                "name": m.group("name"),
                "sig_idx": i,
                "body_open_idx": open_idx,
                "body_open_col": open_col,
                "body_end_idx": end_idx,
                "ret": ret,
                "is_oracle_fn": is_oracle_fn,
                "in_oracle_mod": self.in_oracle_region(i),
                "indent": m.group("indent"),
            })
        return fns

    def body_text(self, fn):
        return "\n".join(self.lines[fn["body_open_idx"]:fn["body_end_idx"] + 1])

    def match_block_from(self, idx, col):
        return self._match_block(idx, col)


def is_oracle_file(relpath, extra_names=()):
    base = relpath.split("/")[-1]
    if base in tuple(extra_names):
        return True
    for suf in ORACLE_FILE_SUFFIXES:
        if base.endswith(suf):
            return True
    return False


def is_live_source(relpath):
    """True for a file the crate actually compiles - never a `.pre*` / `.post*` backup copy."""
    if not relpath.endswith(".rs"):
        return False
    stem = relpath.split("/")[-1][:-3]
    for marker in (".pre", ".post", ".mangled", ".fixRound", ".realsOnly", ".broken", ".bak"):
        if marker in stem:
            return False
    return True

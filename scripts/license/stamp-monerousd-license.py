#!/usr/bin/env python3
"""
stamp-monerousd-license.py — stamp the Apache-2.0 MoneroUSD header onto
MonerousD-UNIQUE source files (original works of the MoneroUSD Protocol).

Design goals (idempotent, safe, conservative):
  * Never touch vendored third-party code (Plonky3 core, node_modules, external
    SNARK libs, build/vendor/dist output) — only MonerousD's own files.
  * Never re-stamp: if "The MoneroUSD Protocol" already appears near the top, skip.
  * By default SKIP files that carry a Monero Project copyright — those are
    Monero-DERIVED, not "unique". Monero's BSD-3 requires their notice be
    retained, so we do not overwrite it and we do not claim their files.
    (Use --include-derived to ADD the MonerousD notice ABOVE a retained Monero
    notice for files MonerousD has substantially rewritten.)
  * Respect shebangs (insert after `#!...`) and encoding/xml/doctype header lines.
  * --dry-run prints what WOULD change; default is dry-run unless --apply given.

Comment styles are chosen per extension. The header text is read from
monerousd-license-header.txt next to this script.
"""
import os, sys, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER_TXT = os.path.join(HERE, "monerousd-license-header.txt")
MARKER = "The MoneroUSD Protocol"

SLASH = "//"
HASH = "#"
EXT_STYLE = {
    ".rs": SLASH, ".c": SLASH, ".h": SLASH, ".cpp": SLASH, ".hpp": SLASH,
    ".cc": SLASH, ".cxx": SLASH, ".js": SLASH, ".cjs": SLASH, ".mjs": SLASH,
    ".ts": SLASH, ".tsx": SLASH, ".jsx": SLASH, ".go": SLASH, ".java": SLASH,
    ".swift": SLASH, ".kt": SLASH, ".proto": SLASH,
    ".py": HASH, ".sh": HASH, ".bash": HASH, ".zsh": HASH, ".rb": HASH,
    ".yml": HASH, ".yaml": HASH, ".toml": HASH, ".cfg": HASH,
    ".css": "block-css", ".scss": "block-css",
    ".html": "block-html", ".htm": "block-html", ".xml": "block-html", ".vue": "block-html",
}

# Directory names that mean "not MonerousD-unique" — never stamp inside these.
EXCLUDE_DIR_PARTS = {
    "node_modules", ".git", "build", "dist", "out", "target", "vendor",
    "third_party", "third-party", "test-results", "_leaked-archive", "_release",
    "release-keys", ".cache", "coverage",
}
# Vendored third-party under external/ that MonerousD must never claim.
EXCLUDE_PATH_SUBSTR = (
    "/external/Plonky3/", "/external/fcmp_halo2/", "/external/randomx/",
    "/external/unbound/", "/external/miniupnp/", "/external/trezor",
    "/external/supercop", "/external/rapidjson", "/external/db_drivers",
)
# Re-allow MonerousD's own crates that happen to live under the Plonky3 vendor dir.
REALLOW_PATH_SUBSTR = ("/external/Plonky3/pqpool/", "/external/Plonky3/pqpool_ffi/")
EXCLUDE_NAME_SUBSTR = (".min.", ".macbak", ".pre20", ".bak", ".preDATE", "-lock.")


def load_header_lines():
    with open(HEADER_TXT, "r", encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f.readlines()]


def render_header(style, lines):
    if style in (SLASH, HASH):
        body = "\n".join((style + " " + l).rstrip() for l in lines)
        return body + "\n\n"
    if style == "block-css":
        inner = "\n".join(("   " + l).rstrip() for l in lines)
        return "/*\n" + inner + "\n*/\n\n"
    if style == "block-html":
        inner = "\n".join(("   " + l).rstrip() for l in lines)
        return "<!--\n" + inner + "\n-->\n\n"
    raise ValueError(style)


def is_excluded(path):
    if set(path.split(os.sep)) & EXCLUDE_DIR_PARTS:
        return True
    # backup / archived copies are never stamped — this beats REALLOW so a
    # `src.macbak-*/` under an allow-listed crate is still skipped.
    if any(s in path for s in EXCLUDE_NAME_SUBSTR):
        return True
    if any(s in path for s in REALLOW_PATH_SUBSTR):
        return False
    if any(s in path for s in EXCLUDE_PATH_SUBSTR):
        return True
    return False


def already_stamped(head):
    return MARKER in head


def has_monero_copyright(head):
    return "The Monero Project" in head or "Copyright (c) 2014" in head


def split_top_matter(text):
    """Keep any shebang / coding / xml-decl / doctype header lines on top; the
    license header is inserted immediately after them. Returns (prefix, rest)."""
    lines = text.split("\n")
    keep = 0
    while keep < len(lines):
        stripped = lines[keep].lstrip().lower()
        first = lines[keep]
        is_shebang = keep == 0 and first.startswith("#!")
        is_coding = ("coding:" in first) and first.lstrip().startswith("#")
        is_xml = stripped.startswith("<?xml")
        is_doctype = stripped.startswith("<!doctype")
        if is_shebang or is_coding or is_xml or is_doctype:
            keep += 1
            continue
        break
    prefix = "\n".join(lines[:keep])
    rest = "\n".join(lines[keep:])
    if prefix:
        prefix += "\n"
    return prefix, rest


def process(path, header_lines, include_derived, apply, markers=None):
    ext = os.path.splitext(path)[1].lower()
    style = EXT_STYLE.get(ext)
    if not style:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except (UnicodeDecodeError, OSError):
        return None
    head = text[:600]
    if already_stamped(head):
        return ("skip-stamped", path)
    # --require-marker: only stamp files that are DEMONSTRABLY MonerousD's own
    # work (their content bears a MonerousD-identifying token). This lets us
    # sweep a Monero-derived tree (src/) and stamp ONLY the genuinely-new
    # MonerousD files, never a third-party primitive (keccak.c, etc.).
    if markers is not None:
        low = text.lower()
        if not any(m in low for m in markers):
            return ("skip-no-marker", path)
    derived = has_monero_copyright(head)
    if derived and not include_derived:
        return ("skip-monero-derived", path)
    header = render_header(style, header_lines)
    prefix, rest = split_top_matter(text)
    new = prefix + header + rest
    if apply:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
    return ("stamped-derived" if derived else "stamped", path)


def walk_roots(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_PARTS]
            for fn in filenames:
                yield os.path.join(dirpath, fn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+", help="MonerousD-unique dirs/files to stamp")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--include-derived", action="store_true",
                    help="also add the MonerousD notice ABOVE a retained Monero notice")
    ap.add_argument("--require-marker", default=None,
                    help="comma-separated tokens; only stamp files whose content "
                         "contains one (case-insensitive). Use to safely sweep a "
                         "Monero-derived tree and stamp ONLY genuinely-new MonerousD files.")
    args = ap.parse_args()
    header_lines = load_header_lines()
    markers = None
    if args.require_marker:
        markers = [m.strip().lower() for m in args.require_marker.split(",") if m.strip()]
    counts = {}
    for path in walk_roots(args.roots):
        if is_excluded(path):
            continue
        r = process(path, header_lines, args.include_derived, args.apply, markers)
        if r is None:
            continue
        tag, p = r
        counts[tag] = counts.get(tag, 0) + 1
        if tag.startswith("stamped"):
            print(("APPLIED " if args.apply else "WOULD   ") + tag + ": " + p)
    print("\n=== summary (%s) ===" % ("APPLY" if args.apply else "DRY-RUN"))
    for k in sorted(counts):
        print("  %-22s %d" % (k, counts[k]))


if __name__ == "__main__":
    sys.exit(main())

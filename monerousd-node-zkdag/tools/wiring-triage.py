#!/usr/bin/env python3
"""Turn the wiring census into DECISIONS, in one pass.

For every unwired production function it computes the signals that decide WIRE vs DELETE:
  prod   — mentions in production code (0 by definition of the census; a cross-check)
  test   — mentions inside #[cfg(test)]/#[test]/mod tests regions
  own    — how many of those are in its own file
  vis    — pub / pub(crate) / private
A function with test>0 is a feature whose PRODUCTION caller was never written.
A function with test==0 has not been referred to by anything, anywhere, and is dead.
"""
import re, sys, pathlib, collections, json

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
WALLET = ROOT.parent / "monerousd-wallet-v2" / "src-tauri" / "src"

def sources():
    # src/*.rs, src/*/*.rs (the harness tier lives there) and the wallet crate.
    for d in (SRC, WALLET):
        if d.is_dir():
            for pat in ("*.rs", "*/*.rs"):
                for p in sorted(d.glob(pat)):
                    if ".pre" not in p.name:
                        yield p

TEXT = {p: p.read_text(errors="replace") for p in sources()}

def test_regions(src):
    out = []
    for m in ("#[cfg(test)]", "#[test]", "mod tests"):
        i = 0
        while True:
            at = src.find(m, i)
            if at < 0:
                break
            i = at + len(m)
            if any(a <= at < b for a, b in out):
                continue
            o = src.find("{", at)
            if o < 0:
                continue
            d, end = 0, o
            for k in range(o, len(src)):
                if src[k] == "{":
                    d += 1
                elif src[k] == "}":
                    d -= 1
                    if d == 0:
                        end = k + 1
                        break
            out.append((at, end))
    return out

REG = {p: test_regions(t) for p, t in TEXT.items()}

def classify(file, name):
    path = SRC / file
    text = TEXT.get(path, "")
    lines = text.split("\n")
    vis, ln, doc = "private", 0, ""
    pat = re.compile(r"\s*(pub\(crate\)|pub\(super\)|pub)?\s*(async\s+)?(unsafe\s+)?(const\s+)?fn\s+" + re.escape(name) + r"\b")
    for i, l in enumerate(lines):
        if pat.match(l):
            ln, vis = i + 1, (pat.match(l).group(1) or "private")
            j = i - 1
            while j >= 0 and lines[j].strip().startswith("///"):
                doc = lines[j].strip()[3:].strip()
                j -= 1
            break
    prod = test = own = 0
    word = re.compile(r"\b" + re.escape(name) + r"\b")
    for p, t in TEXT.items():
        regs = REG[p]
        for m in word.finditer(t):
            at = m.start()
            if p == path and ln and t[:at].count("\n") + 1 == ln:
                continue  # its own definition line
            if any(a <= at < b for a, b in regs):
                test += 1
                if p == path:
                    own += 1
            else:
                prod += 1
    return dict(file=file, name=name, line=ln, vis=vis, prod=prod, test=test, own=own, doc=doc[:120])

rows = []
for line in (ROOT / "target" / "wiring-census.txt").read_text().split("\n"):
    line = line.strip()
    if "::" in line:
        f, n = line.split("::", 1)
        rows.append(classify(f, n))

if "--json" in sys.argv:
    print(json.dumps(rows))
    sys.exit()

dead = [r for r in rows if r["test"] == 0]
feat = [r for r in rows if r["test"] > 0]
print(f"DEAD (no mention anywhere, not even a test): {len(dead)}")
print(f"UNWIRED FEATURE (tests call it, production does not): {len(feat)}")
by = collections.defaultdict(list)
for r in feat:
    by[r["file"]].append(r)
for f in sorted(by, key=lambda k: -len(by[k])):
    print(f"\n## {f} ({len(by[f])})")
    for r in sorted(by[f], key=lambda x: -x["test"]):
        print(f"  {r['vis']:<10} {r['name']:<42} test={r['test']:<4} own={r['own']:<4} {r['doc'][:70]}")

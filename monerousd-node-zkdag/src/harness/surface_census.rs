// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE SURFACE CENSUS — the zero-blind-spot layer of the one-sweep hole scanner.
//!
//! User 2026-10-03, verbatim: *"the ecosystem scanner MUST NOT have ANY blindspots at all. Blindspots are a product of
//! assumption. treat your assumptions as abug themselves because there must be 0 assumptions whatsoever. Every single
//! inch of the ecosystem must be included and tiered based on vulnerability. Upon completion of the list of
//! bugs/exploits we should be able to safely say that our chain is ready for real funds"*.
//!
//! THE RULE THIS FILE ENFORCES. Every census before this one answered questions about a universe someone CHOSE (the
//! fields of `Block`, the classes of `chain_object`, the sites a person listed). Whatever was outside the chosen universe
//! was invisible, and invisible read as "no holes". This census enumerates every SURFACE of the ecosystem from the code
//! itself, and every surface that no measured check covers is a hole in its own right (a BLIND SPOT):
//!
//! | surface | universe (read from the tree) | covered when |
//! |---|---|---|
//! | node RPC route | every `("GET"/"POST", "/x")` arm + every sovereign arm | an ADVERSARIAL test names the route |
//! | P2P wire message | every `WireMsg` / `GovernGossip` variant | an adversarial test names it or its handler |
//! | wallet command | every `#[tauri::command]` | a wallet test / harness / journey drives it |
//! | dapp bridge | every `dapp_provider_*` command + the origin check | a value move is auth-gated, a private read is consent-gated, the origin is loopback/onion, a proxy has a route allowlist |
//! | decode of outside bytes | every postcard / serde_json decode site | strict (`decode_exact`) in a consensus file; fuzzed elsewhere |
//! | disk write | every filesystem write site | a USER-approved line in `user-approved-local-storage.txt` |
//! | log line | every print / log macro that INTERPOLATES a sensitive name | never |
//! | memory-unsafe code | every `unsafe` | never (listed for review) |
//! | dependency | every crate in every `Cargo.lock`, every vendored script | not pre-quantum crypto / TLS; an advisory scan ran |
//! | primitive | ML-KEM-768, ML-DSA-65, blake3, SHA3, Poseidon2 | a known-answer test exists |
//! | source file | every shippable file of node, decider, wallet core, wallet front end, launchpad apps | a test reaches a function defined in it |
//! | census claim | every row another census calls CLOSED | it cites a real `#[test]` whose LATEST recorded run passed |
//!
//! THE TIERS (impact if the hole is real; an UNKNOWN impact takes the WORST tier — that is the no-assumption rule):
//! T0 FUNDS — value created, destroyed, stolen or locked; soundness. T1 PRIVACY — value, identity, linkage, amount or
//! metadata revealed. T2 KEYS & PQ — a key exposed, or pre-quantum crypto. T3 LIVENESS — halt, crash, exhaustion,
//! unbounded growth. T4 FUNCTION — a feature a user relies on is dead or unproven.
//!
//! THE KINDS: EXPLOIT (a defect the scanner measured), BLIND SPOT (a surface no check covers), UNMEASURED (a claim of
//! safety with no recorded passing measurement behind it).
//!
//! READY FOR REAL FUNDS ⇔ this census, every other census and the circuit sweep print ZERO holes at T0–T4.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// One hole found by the surface census.
#[derive(Debug, Clone)]
pub struct SurfaceHole {
    pub tier: u8,
    pub kind: &'static str,
    pub category: &'static str,
    pub name: String,
    pub detail: String,
}

pub const EXPLOIT: &str = "EXPLOIT";
pub const BLIND: &str = "BLIND SPOT";
pub const UNMEASURED: &str = "UNMEASURED";

fn sh(tier: u8, kind: &'static str, category: &'static str, name: impl Into<String>, detail: impl Into<String>) -> SurfaceHole {
    SurfaceHole { tier, kind, category, name: name.into(), detail: detail.into() }
}

fn node_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn repo_root() -> PathBuf {
    node_root().parent().map(Path::to_path_buf).unwrap_or_else(node_root)
}

fn is_backup(p: &Path) -> bool {
    let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    n.contains(".pre") || n.contains(".bak") || n.contains("recreated-backup") || n.ends_with('~') || n.contains(".orig")
}
fn is_vendored_script(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/node_modules/") || s.contains(".min.") || s.contains("/monaco") || s.contains("/vendor/") || s.contains("/lib/vendor")
}

/// One file of the ecosystem: its part, its path relative to the repo, its text, its SHIPPABLE text (every test item
/// blanked to spaces, so line numbers hold) and its TEST text (every test item, joined).
pub struct Src {
    pub part: &'static str,
    pub rel: String,
    pub text: String,
    pub ship: String,
    pub test_text: String,
    pub test_file: bool,
    /// false when a `#[cfg(test)]` item's end could not be found (reported as a hole, never silently shrunk).
    pub parsed: bool,
}
impl Src {
    fn shippable(&self) -> &str {
        &self.ship
    }
    fn tests(&self) -> &str {
        &self.test_text
    }
    fn base(&self) -> &str {
        self.rel.rsplit('/').next().unwrap_or(&self.rel)
    }
}

/// The index just past the brace that closes the one at `open`, skipping strings, raw strings, char literals and
/// comments (a brace inside any of them is not code).
fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut depth = 0i64;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#')) && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) => {
                let mut j = i + 1;
                let mut hashes = 0;
                while j < b.len() && b[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < b.len() && b[j] == b'"' {
                    let close = format!("\"{}", "#".repeat(hashes));
                    match text[j + 1..].find(&close) {
                        Some(e) => i = j + 1 + e + close.len() - 1,
                        None => return None,
                    }
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // a char literal ('x', '\n', '\u{..}') or a lifetime ('a): a literal closes within a few bytes
                if b.get(i + 1) == Some(&b'\\') {
                    if let Some(e) = text[i + 2..].find('\'') {
                        i += 2 + e;
                    }
                } else if b.get(i + 2) == Some(&b'\'') {
                    i += 2;
                } else if let Some(ch) = text[i + 1..].chars().next() {
                    if text[i + 1 + ch.len_utf8()..].starts_with('\'') {
                        i += ch.len_utf8() + 1;
                    }
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Offset of the next ITEM in `rest`: past whitespace, comments and attributes.
fn next_item_offset(rest: &str) -> usize {
    let b = rest.as_bytes();
    let mut i = 0;
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if rest[i..].starts_with("//") {
            i += rest[i..].find('\n').unwrap_or(rest.len() - i);
        } else if rest[i..].starts_with("#[") || rest[i..].starts_with("#![") {
            let mut depth = 0i32;
            while i < b.len() {
                if b[i] == b'[' {
                    depth += 1;
                } else if b[i] == b']' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
        } else {
            return i;
        }
    }
}

/// A `#[cfg(...)]` predicate that compiles ONLY under `cfg(test)`: `test` itself, or an `all(...)` whose top-level
/// conjuncts include one — the test-family gates `#[cfg(all(test, feature = "pins-node"))]` (4bad001, 2026-10-22).
/// `any(test, feature = "x")` and `not(test)` ship under some configuration, so they are shippable code.
/// MEASURED why (scratchpad/verify/holes-20261022-1915.log): with only the literal `#[cfg(test)]` matched, the family
/// refactor's 136k test lines scanned as shippable and the register read 4,436 holes (3,242 "panic in shippable code",
/// 112 the scan before) — a census that cannot see its own universe is a blind spot, not a finding.
fn test_only_predicate(pred: &str) -> bool {
    let p = pred.trim();
    if p == "test" {
        return true;
    }
    let Some(inner) = p.strip_prefix("all(").and_then(|r| r.strip_suffix(')')) else { return false };
    let (mut depth, mut start, mut parts) = (0i32, 0usize, Vec::new());
    for (i, c) in inner.bytes().enumerate() {
        match c {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts.iter().any(|q| test_only_predicate(q))
}

/// Every test-only item of a Rust file as a byte range (attribute through the item's closing `}` or `;`), and the
/// names of `#[cfg(test)] mod name;` declarations (their files are test files). Test-only = a `#[cfg(...)]` attribute
/// whose predicate is [`test_only_predicate`] (`#[cfg(test)]` and every `#[cfg(all(test, feature = "pins-…"))]`).
fn test_items(text: &str) -> (Vec<(usize, usize)>, Vec<String>, bool) {
    let mut ranges = Vec::new();
    let mut mods = Vec::new();
    let mut complete = true;
    let mut from = 0;
    while let Some(at) = text[from..].find("#[cfg(") {
        let pos = from + at;
        let open = pos + "#[cfg".len();
        // the predicate: the balanced `( … )` after `#[cfg`, closed by `]`
        let b = text.as_bytes();
        let (mut depth, mut i) = (0i32, open);
        let close = loop {
            match b.get(i) {
                Some(b'(') => depth += 1,
                Some(b')') => {
                    depth -= 1;
                    if depth == 0 {
                        break Some(i);
                    }
                }
                Some(b'\n') | None => break None,
                _ => {}
            }
            i += 1;
        };
        let Some(close) = close.filter(|&c| b.get(c + 1) == Some(&b']')) else {
            from = open;
            continue;
        };
        let after = close + 2;
        if !test_only_predicate(&text[open + 1..close]) {
            from = after;
            continue;
        }
        // an ATTRIBUTE starts its line; the same text inside a comment or a string literal is not one
        let line_start = text[..pos].rfind('\n').map_or(0, |i| i + 1);
        if !text[line_start..pos].trim().is_empty() {
            from = after;
            continue;
        }
        let item_at = after + next_item_offset(&text[after..]);
        let item = &text[item_at..];
        let semi = item.find(';');
        let brace = item.find('{');
        let end = match (brace, semi) {
            (Some(b), s) if s.is_none_or(|s| b < s) => matching_brace(text, item_at + b),
            (_, Some(s)) => {
                let decl = item[..s].trim();
                if let Some(name) = decl.strip_prefix("mod ").or_else(|| decl.strip_prefix("pub mod ")).or_else(|| decl.strip_prefix("pub(crate) mod ")) {
                    mods.push(name.trim().to_string());
                }
                Some(item_at + s + 1)
            }
            _ => None,
        };
        match end {
            Some(e) => {
                ranges.push((pos, e));
                from = e;
            }
            None => {
                // an item whose end cannot be found: everything after it is treated as test text AND reported by the
                // calibration pin (a parse the census cannot complete must not shrink the shippable universe silently)
                ranges.push((pos, text.len()));
                complete = false;
                break;
            }
        }
    }
    (ranges, mods, complete)
}

/// A file that is test code in its entirety, by its path.
fn test_file_by_path(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    rel.contains("/harness/")
        || rel.contains("/tests/")
        || rel.contains("/bin/") && (base.contains("harness") || base.contains("flood"))
        || base.contains("_tests")
        || base.contains("scenarios")
        || base.ends_with("_pin.rs")
        || base.starts_with("test_")
        || base.contains("fuzz")
}

fn walk(dir: &Path, exts: &[&str], skipped_backups: &mut usize, vendored: &mut Vec<String>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if is_backup(&p) {
                    *skipped_backups += 1;
                } else if p.file_name().is_some_and(|n| n == "target" || n == ".git") {
                    continue;
                } else {
                    stack.push(p);
                }
                continue;
            }
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if is_backup(&p) {
                *skipped_backups += 1;
                continue;
            }
            if !exts.contains(&ext) {
                continue;
            }
            if is_vendored_script(&p) && ext != "rs" {
                vendored.push(p.strip_prefix(repo_root()).unwrap_or(&p).to_string_lossy().into_owned());
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Every source file of the ecosystem, by part, plus the vendored third-party scripts and the backup count.
pub struct Ecosystem {
    pub files: Vec<Src>,
    pub vendored_scripts: Vec<String>,
    pub backups_skipped: usize,
    pub upstream_prover_files: usize,
}

#[must_use]
pub fn ecosystem() -> Ecosystem {
    let mut backups = 0usize;
    let mut vendored = Vec::new();
    let node = node_root();
    let wallet = repo_root().join("monerousd-wallet-v2");
    let parts: Vec<(&'static str, PathBuf, &[&str])> = vec![
        ("node", node.join("src"), &["rs"][..]),
        ("decider", node.join("vendor/Plonky3/usdm-decider/src"), &["rs"][..]),
        ("wallet core", wallet.join("src-tauri/src"), &["rs"][..]),
        ("wallet front end", wallet.join("dist"), &["js", "mjs", "html"][..]),
        ("launchpad", node.join("sites"), &["js", "mjs", "html"][..]),
    ];
    let mut files = Vec::new();
    // `#[cfg(test)] mod name;` declared in `dir/x.rs` lives at `dir/name.rs` (lib/main/mod) or `dir/x/name.rs`.
    let mut test_mod_paths: Vec<String> = Vec::new();
    for (part, dir, exts) in parts {
        for p in walk(&dir, exts, &mut backups, &mut vendored) {
            let Ok(text) = fs::read_to_string(&p) else { continue };
            let rel = p.strip_prefix(repo_root()).unwrap_or(&p).to_string_lossy().into_owned();
            if !rel.ends_with(".rs") {
                files.push(Src { part, rel, ship: text.clone(), text, test_text: String::new(), test_file: false, parsed: true });
                continue;
            }
            let (ranges, mods, parsed) = test_items(&text);
            let parent = rel.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
            let stem = rel.rsplit('/').next().unwrap_or("").trim_end_matches(".rs").to_string();
            let mod_dir = if ["lib", "main", "mod"].contains(&stem.as_str()) { parent.clone() } else { format!("{parent}/{stem}") };
            for m in mods {
                test_mod_paths.push(format!("{mod_dir}/{m}.rs"));
                test_mod_paths.push(format!("{mod_dir}/{m}/"));
            }
            let mut ship = text.clone().into_bytes();
            let mut test_text = String::new();
            for (a, e) in &ranges {
                test_text.push_str(&text[*a..*e]);
                test_text.push('\n');
                for c in &mut ship[*a..*e] {
                    if *c != b'\n' {
                        *c = b' ';
                    }
                }
            }
            let ship = String::from_utf8(ship).unwrap_or_default();
            files.push(Src { part, rel, text, ship, test_text, test_file: false, parsed });
        }
    }
    for f in files.iter_mut().filter(|f| f.rel.ends_with(".rs")) {
        if test_file_by_path(&f.rel) || test_mod_paths.iter().any(|t| if t.ends_with('/') { f.rel.starts_with(t.as_str()) } else { f.rel == *t }) {
            f.test_file = true;
            f.test_text = f.text.clone();
            f.ship = f.text.chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect();
        }
    }
    // The upstream Plonky3 crates the decider builds on: counted (they are the field, hash and FRI the proofs rest on).
    let mut upstream = 0usize;
    if let Ok(rd) = fs::read_dir(node.join("vendor/Plonky3")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && p.file_name().is_some_and(|n| n != "usdm-decider") {
                let mut b = 0;
                let mut v = Vec::new();
                upstream += walk(&p.join("src"), &["rs"], &mut b, &mut v).len();
            }
        }
    }
    Ecosystem { files, vendored_scripts: vendored, backups_skipped: backups, upstream_prover_files: upstream }
}

// ── TEST INDEX ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// Words in a test's NAME that make it adversarial: it asserts a refusal, a bound or a failed attack.
const ADVERSARIAL: &[&str] = &[
    "refus", "reject", "forge", "tamper", "rogue", "replay", "hostile", "attack", "cannot", "never", "malformed", "oversiz",
    "garbage", "flood", "double", "steal", "theft", "inflat", "substitut", "strip", "bypass", "invalid", "wrong", "lie",
    "lying", "fake", "poison", "spoof", "deni", "fail_closed", "fails_closed", "bounded", "unbound", "dos", "adversar",
    "evil", "fabricat", "mutat", "census", "not_credit", "no_credit", "does_not", "doesnt", "only_once", "twice", "leak",
    "drop", "bad_", "truncat", "trailing", "exhaust",
];

/// One `#[test]` function anywhere in the ecosystem.
pub struct TestFn {
    pub name: String,
    pub file: String,
    pub ignored: bool,
    pub adversarial: bool,
    pub body: String,
}

#[must_use]
pub fn test_index(eco: &Ecosystem) -> Vec<TestFn> {
    let mut out = Vec::new();
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        let lines: Vec<&str> = f.text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim_start();
            if t.starts_with("#[test]") || t.starts_with("#[tokio::test") {
                let mut ignored = false;
                let mut j = i + 1;
                let mut name = String::new();
                while j < lines.len() && j <= i + 8 {
                    let l = lines[j];
                    if l.contains("#[ignore") {
                        ignored = true;
                    }
                    if let Some(at) = l.find("fn ") {
                        name = l[at + 3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                        break;
                    }
                    j += 1;
                }
                let mut k = j + 1;
                while k < lines.len() {
                    let l = lines[k].trim_start();
                    if l.starts_with("#[test]") || l.starts_with("#[tokio::test") {
                        break;
                    }
                    k += 1;
                }
                if !name.is_empty() {
                    let lower = name.to_ascii_lowercase();
                    out.push(TestFn {
                        adversarial: ADVERSARIAL.iter().any(|w| lower.contains(w)),
                        name,
                        file: f.rel.clone(),
                        ignored,
                        body: lines[j.min(lines.len())..k.min(lines.len())].join("\n"),
                    });
                }
                i = k;
                continue;
            }
            i += 1;
        }
    }
    out
}

/// Every token a test mentions → (mentioned at all, mentioned by an adversarial test). Paths are indexed by every `/…`
/// suffix so `"http://127.0.0.1:27780/get_info"` counts for `/get_info`.
pub struct Tokens(HashMap<String, (bool, bool)>);
impl Tokens {
    fn add(&mut self, tok: &str, adv: bool) {
        let e = self.0.entry(tok.to_string()).or_insert((false, false));
        e.0 = true;
        e.1 |= adv;
    }
    #[must_use]
    pub fn get(&self, tok: &str) -> (bool, bool) {
        self.0.get(tok).copied().unwrap_or((false, false))
    }
}
fn index_text(tokens: &mut Tokens, text: &str, adv: bool) {
    let is_tok = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == ':' || c == '-';
    for run in text.split(|c: char| !is_tok(c)).filter(|r| !r.is_empty()) {
        tokens.add(run, adv);
        for part in run.split("::").filter(|p| !p.is_empty()) {
            tokens.add(part, adv);
        }
        for (i, _) in run.match_indices('/') {
            let suffix = run[i..].trim_end_matches('/');
            if suffix.len() > 1 {
                tokens.add(suffix, adv);
            }
        }
    }
}
#[must_use]
pub fn test_tokens(tests: &[TestFn], eco: &Ecosystem) -> Tokens {
    let mut t = Tokens(HashMap::new());
    for f in tests {
        index_text(&mut t, &f.name, f.adversarial);
        index_text(&mut t, &f.body, f.adversarial);
    }
    // Test-region text outside a test fn (fixtures, helpers) reaches code too — it counts as non-adversarial reach.
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        index_text(&mut t, f.tests(), false);
    }
    t
}

// ── SURFACE ENUMERATORS ───────────────────────────────────────────────────────────────────────────────────────────

/// Every quoted string literal on `line` (single, double or backtick), in order; the closing quote is the first
/// UNESCAPED one. The ONE literal reader both censuses use.
pub(crate) fn quoted(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q == b'\'' || q == b'"' || q == b'`' {
            // the closing quote is the first UNESCAPED one
            let mut j = i + 1;
            while j < b.len() && b[j] != q {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j < b.len() {
                out.push(&line[i + 1..j]);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn file<'a>(eco: &'a Ecosystem, suffix: &str) -> Option<&'a Src> {
    eco.files.iter().find(|f| f.rel.ends_with(suffix))
}

/// `(method, path, file:line)` for every route the node serves: the `("GET"|"POST", "/x")` arms of `rpc_http.rs`, the
/// `"/x" =>` arms of `sovereign.rs`, and in both files every `path == "/x"` test and every `starts_with("/x")` /
/// `strip_prefix("/x")` PREFIX route (recorded as `/x*`). A form without a method reads as `ANY`.
#[must_use]
pub fn routes(eco: &Ecosystem) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |m: &str, p: &str, at: String, out: &mut Vec<(String, String, String)>| {
        let p = p.split('?').next().unwrap_or(p);
        if p.starts_with('/') && p.len() > 1 && !p.contains(' ') && seen.insert((m.to_string(), p.to_string())) {
            out.push((m.to_string(), p.to_string(), at));
        }
    };
    for srv in ["monerousd-node-zkdag/src/rpc_http.rs", "monerousd-node-zkdag/src/sovereign.rs"] {
        let Some(f) = file(eco, srv) else { continue };
        for (n, line) in f.shippable().lines().enumerate() {
            let l = line.trim();
            if l.starts_with("//") {
                continue;
            }
            let at = || format!("{}:{}", f.rel, n + 1);
            for m in ["GET", "POST", "PUT", "DELETE"] {
                let needle = format!("(\"{m}\",");
                for (i, _) in line.match_indices(&needle) {
                    if let Some(p) = quoted(&line[i + needle.len()..]).first() {
                        push(m, p, at(), &mut out);
                    }
                }
            }
            for eq in ["path == ", "p == ", "route == ", "url == ", "path.as_str() == "] {
                for (i, _) in line.match_indices(eq) {
                    if let Some(p) = quoted(&line[i + eq.len()..]).first() {
                        push("ANY", p, at(), &mut out);
                    }
                }
            }
            for pre in ["starts_with(", "strip_prefix("] {
                for (i, _) in line.match_indices(pre) {
                    if let Some(p) = quoted(&line[i + pre.len()..]).first() {
                        if p.starts_with('/') && p.len() > 1 {
                            push("ANY", &format!("{}*", p.trim_end_matches('/')), at(), &mut out);
                        }
                    }
                }
            }
            if srv.ends_with("sovereign.rs") && l.contains("=>") {
                let head = &l[..l.find("=>").unwrap_or(l.len())];
                for p in quoted(head) {
                    push("ANY", p, at(), &mut out);
                }
            }
        }
    }
    out
}

/// Is `path` served by one of `routes` (exactly, or under a `/x*` prefix route)?
#[must_use]
pub fn served(routes: &[(String, String, String)], path: &str) -> bool {
    let path = path.trim_end_matches('/');
    routes.iter().any(|(_, r, _)| match r.strip_suffix('*') {
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")) || path.starts_with(prefix) && prefix.ends_with('_'),
        None => r.trim_end_matches('/') == path,
    })
}

/// `(enum, variant, handler names)` for every peer-to-peer message.
#[must_use]
pub fn wire_messages(eco: &Ecosystem) -> Vec<(String, String, Vec<String>)> {
    let mut out = Vec::new();
    for (src, en) in [("monerousd-node-zkdag/src/protocol.rs", "WireMsg"), ("monerousd-node-zkdag/src/governance.rs", "GovernGossip")] {
        let Some(f) = file(eco, src) else { continue };
        let head = format!("pub enum {en} {{");
        let Some(at) = f.text.find(&head) else { continue };
        let body = &f.text[at + head.len()..];
        let body = &body[..body.find("\n}").unwrap_or(body.len())];
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('#') || t.is_empty() {
                continue;
            }
            let v: String = t.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if v.is_empty() || !v.starts_with(|c: char| c.is_ascii_uppercase()) {
                continue;
            }
            // Handlers: the calls on every shippable match arm `En::V(… =>` in the node.
            let arm = format!("{en}::{v}");
            let mut handlers = BTreeSet::new();
            for g in eco.files.iter().filter(|g| g.part == "node") {
                let t = g.shippable();
                for (pos, _) in t.match_indices(&arm) {
                    // `WireMsg::Block` must not match inside `WireMsg::BlockAck`
                    if t[pos + arm.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                        continue;
                    }
                    let line_end = t[pos..].find('\n').map_or(t.len(), |e| pos + e);
                    let Some(arrow) = t[pos..line_end].find("=>").map(|a| pos + a) else { continue };
                    // the arm: a `{ … }` block (brace-matched) or the rest of the line
                    let after = t[arrow + 2..].trim_start();
                    let start = t.len() - after.len();
                    let end = if after.starts_with('{') { matching_brace(t, start).unwrap_or(line_end) } else { line_end };
                    let rhs = &t[arrow..end.max(arrow)];
                    let mut ident = String::new();
                    for c in rhs.chars() {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            ident.push(c);
                        } else {
                            if c == '(' && ident.len() >= 6 && ident.contains('_') {
                                handlers.insert(ident.clone());
                            }
                            ident.clear();
                        }
                    }
                }
            }
            out.push((en.to_string(), v, handlers.into_iter().collect()));
        }
    }
    out
}

/// `(name, file:line, body)` for every command the wallet REGISTERS (`tauri::generate_handler![…]` — the only commands a
/// page can invoke). The body is the `#[tauri::command] fn`'s own, or, for an `off_ui_thread!(cmd => body(…))` command,
/// the body function's. A registered name with no definition found reads with an empty body (and gates as ungated).
#[must_use]
pub fn wallet_commands(eco: &Ecosystem) -> Vec<(String, String, String)> {
    let core: Vec<&Src> = eco.files.iter().filter(|f| f.part == "wallet core").collect();
    let fn_body = |name: &str| -> Option<(String, String)> {
        for f in &core {
            let t = f.shippable();
            for pat in [format!("fn {name}("), format!("fn {name}<")] {
                if let Some(at) = t.find(&pat) {
                    let open = t[at..].find('{').map(|o| at + o)?;
                    let end = matching_brace(t, open).unwrap_or(t.len());
                    return Some((format!("{}:{}", f.rel, t[..at].lines().count()), t[at..end].to_string()));
                }
            }
        }
        None
    };
    let mut names: Vec<String> = Vec::new();
    for f in &core {
        let t = f.shippable();
        if let Some(at) = t.find("generate_handler![") {
            let list = &t[at + "generate_handler![".len()..];
            let list = &list[..list.find(']').unwrap_or(list.len())];
            for item in list.split(',') {
                let item: String = item.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join(" ");
                let name = item.trim().rsplit("::").next().unwrap_or("").trim().to_string();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    names.push(name);
                }
            }
        }
    }
    // Every invocation of a command-generating wrapper (`off_ui_thread!`, DB-373's `off_ui_thread_approved!` /
    // `off_ui_thread_consented!`), multi-line included: the command is the last identifier before `=>`, its body the
    // first after. A gated wrapper puts its gate in the generated command, so the body is prefixed with the gate's name.
    let mut macro_body: HashMap<String, (String, &'static str)> = HashMap::new();
    for f in &core {
        let t = f.shippable();
        for (wrapper, gate) in [
            ("off_ui_thread!(", ""),
            ("off_ui_thread_approved!(", "require_user_approval"),
            ("off_ui_thread_consented!(", "require_session_consent"),
        ] {
            for (i, _) in t.match_indices(wrapper) {
                let line_start = t[..i].rfind('\n').map_or(0, |p| p + 1);
                if t[line_start..i].contains("macro_rules") || t[line_start..i].trim_start().starts_with("//") {
                    continue;
                }
                let rest = &t[i + wrapper.len()..];
                let Some(arrow) = rest.find("=>") else { continue };
                let before = &rest[..arrow];
                let cmd: String = before
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .filter(|w| !w.is_empty())
                    .last()
                    .unwrap_or_default()
                    .to_string();
                let body: String = rest[arrow + 2..].trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                if !cmd.is_empty() && !cmd.starts_with('$') {
                    macro_body.insert(cmd, (body, gate));
                }
            }
        }
    }
    names
        .into_iter()
        .map(|n| {
            let (target, gate) = match macro_body.get(&n) {
                Some((b, g)) => (b.clone(), *g),
                None => (n.clone(), ""),
            };
            let (at, body) = match fn_body(&target) {
                Some(found) => found,
                None => ("(definition not found)".to_string(), String::new()),
            };
            let body = if gate.is_empty() { body } else { format!("// wrapper gate: {gate}(…)\n{body}") };
            (n, at, body)
        })
        .collect()
}

// ── TIER RULES (by what the surface can touch; unknown ⇒ the worst) ────────────────────────────────────────────────

const VALUE_WORDS: &[&str] = &[
    "send", "transfer", "spend", "swap_execute", "fill", "order", "bond", "stake", "withdraw", "deposit", "peg", "mint",
    "burn", "claim", "liquidat", "faucet", "pay", "tap", "submit", "settle", "payout", "custody", "reward", "yield", "pool",
    "deploy", "create_token", "drip", "block", "_tx", "note", "credit",
];
const KEY_WORDS: &[&str] =
    &["seed", "mnemonic", "key", "backup", "restore", "export", "import", "password", "pin", "auth", "biometric", "unlock", "wipe", "sign"];
const PRIVATE_WORDS: &[&str] =
    &["balance", "address", "connect", "inbox", "history", "letter", "owned", "profile", "dir", "name", "scan", "contacts", "clue"];

fn has_any(s: &str, words: &[&str]) -> bool {
    let l = s.to_ascii_lowercase();
    words.iter().any(|w| l.contains(w))
}

/// A value VERB as a word of the command's name, not a substring of another word: a name token that begins or ends with the verb
/// (`send`, `sendall`, `unbond`, `unstake`), a multi-word verb matched token by token. MEASURED 2026-11-03: the substring test read
/// `wallet_repayment_pot` (a read of the pot's public figures) as a `pay` and filed it an unapproved value move; over the 132
/// registered commands the token rule changes that one verdict and no other (the BLE merchant commands stay read-only by their
/// READ_ONLY tokens, `unbond`/`unstake` stay movers).
fn has_verb(s: &str, words: &[&str]) -> bool {
    let l = s.to_ascii_lowercase();
    let t: Vec<&str> = l.split('_').collect();
    words.iter().any(|w| {
        let wt: Vec<&str> = w.split('_').collect();
        (0..t.len().saturating_sub(wt.len() - 1)).any(|i| {
            (t[i].starts_with(wt[0]) || (wt.len() == 1 && t[i].ends_with(wt[0]))) && t[i + 1..i + wt.len()] == wt[1..]
        })
    })
}

/// Every shippable, non-comment line that names crate `ident` (`use ident` / `ident::`) with no `CLASSICAL-CRYPTO-EXEMPT` marker on
/// it or on the line above, as `file:line`.
fn unmarked_uses(eco: &Ecosystem, ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        let lines: Vec<&str> = f.shippable().lines().collect();
        for (n, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") || !names_crate(line, ident) {
                continue;
            }
            let marked = line.contains("CLASSICAL-CRYPTO-EXEMPT") || (n > 0 && lines[n - 1].contains("CLASSICAL-CRYPTO-EXEMPT"));
            if !marked {
                out.push(format!("{}:{}", f.rel, n + 1));
            }
        }
    }
    out
}

/// Does `text` name crate `ident` as a PATH (`use ident…` or `ident::` starting a word)? A substring is not a use:
/// MEASURED 2026-11-03, `Keccak256::new()` in address.rs read as a direct use of the secp crate (`…k256::`).
fn names_crate(text: &str, ident: &str) -> bool {
    let word_start = |i: usize| i == 0 || !text.as_bytes()[i - 1].is_ascii_alphanumeric() && text.as_bytes()[i - 1] != b'_';
    text.match_indices(&format!("{ident}::")).any(|(i, _)| word_start(i))
        || text.match_indices(&format!("use {ident}")).any(|(i, _)| word_start(i))
}

fn command_tier(name: &str) -> u8 {
    if has_any(name, VALUE_WORDS) {
        0
    } else if has_any(name, KEY_WORDS) {
        2
    } else if has_any(name, PRIVATE_WORDS) || name.starts_with("dapp_provider_") {
        1
    } else {
        4
    }
}

fn wire_tier(v: &str) -> u8 {
    let reads = ["Req", "Resp", "Letter", "Dir", "Clue", "Peer", "Name"];
    if reads.iter().any(|r| v.contains(r)) && !v.starts_with("Peg") && !v.starts_with("Band") {
        1
    } else if ["TipBeacon", "BlockAck", "SyncRequest", "ChunkReq"].contains(&v) {
        3
    } else {
        0
    }
}

/// Bridge methods that move value or publish under the user's identity (must be approval-gated).
const BRIDGE_MOVES: &[&str] = &[
    "transfer", "send", "swap_execute", "order_post", "order_cancel", "fill", "bond", "stake", "mint", "deploy", "create_token",
    "register", "profile_set", "letter_send", "pay", "withdraw", "deposit", "peg", "claim", "sign",
];
/// Name tokens of a command that only reads, watches, or credits the user's OWN wallet (never a value verb).
const READ_ONLY_TOKENS: &[&str] =
    &["status", "my", "await", "merchant", "selftest", "start", "stop", "request", "quote", "price", "verify", "charge", "nearby", "clue", "try"];

/// Bridge methods that reveal the wallet's own private data (must be consent-gated).
const BRIDGE_REVEALS: &[&str] = &["balance", "connect", "address", "inbox", "history", "owned", "letter_address", "notes", "portfolio"];

/// Every function defined in the wallet core's shippable code: name → body.
fn wallet_core_fns(eco: &Ecosystem) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for f in eco.files.iter().filter(|f| f.part == "wallet core") {
        let t = f.shippable();
        for (i, _) in t.match_indices("fn ") {
            if i > 0 && (t.as_bytes()[i - 1].is_ascii_alphanumeric() || t.as_bytes()[i - 1] == b'_') {
                continue;
            }
            let name: String = t[i + 3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            let Some(open) = t[i..].find('{').map(|o| i + o) else { continue };
            if t[i..open].contains(';') {
                continue; // a declaration, not a definition
            }
            let end = matching_brace(t, open).unwrap_or(t.len());
            m.entry(name).or_insert_with(|| t[i..end].to_string());
        }
    }
    m
}

/// `body` plus the bodies of every wallet-core function it calls, to `depth` levels.
fn gate_reach(fns: &HashMap<String, String>, body: &str, depth: usize) -> String {
    let mut out = body.to_string();
    let mut frontier = vec![body.to_string()];
    let mut seen = BTreeSet::new();
    for _ in 0..depth {
        let mut next = Vec::new();
        for b in &frontier {
            let mut ident = String::new();
            for c in b.chars() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    ident.push(c);
                } else {
                    if c == '(' && fns.contains_key(&ident) && seen.insert(ident.clone()) {
                        let callee = &fns[&ident];
                        out.push('\n');
                        out.push_str(callee);
                        next.push(callee.clone());
                    }
                    ident.clear();
                }
            }
        }
        frontier = next;
    }
    out
}

// ── THE CENSUS ────────────────────────────────────────────────────────────────────────────────────────────────────

const CONSENSUS_FILE_WORDS: &[&str] = &[
    "block", "chain_object", "protocol", "relay", "node", "sync", "mempool", "consensus", "ghostdag", "dag", "da.rs", "_tx.rs",
    "peg", "settlement", "member_", "note_", "nullifier", "spend_frontier", "cover", "oli", "governance", "directory", "names",
    "serve", "bond", "liquidation", "solvency", "economics", "reward", "validator", "omr", "nf_", "respend", "dsol", "order",
];

/// Does the function enclosing line `n` (its `fn` line to the next `fn` line) create or open a FILE? A `write_all` there
/// writes to disk; a `write_all` in a function that opens no file writes to a socket or an in-memory buffer.
fn write_all_on_a_file(lines: &[&str], n: usize) -> bool {
    let is_fn = |l: &str| {
        let t = l.trim_start();
        t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ") || t.starts_with("pub(super) fn ") || t.starts_with("pub async fn ") || t.starts_with("async fn ")
    };
    let start = (0..=n).rev().find(|&i| is_fn(lines[i])).unwrap_or(0);
    let end = (n + 1..lines.len()).find(|&i| is_fn(lines[i])).unwrap_or(lines.len());
    let file_openers = [concat!("File::", "create"), concat!("File::", "open"), concat!("OpenOptions", "::new"), concat!("fs::", "File")];
    lines[start..end].iter().any(|l| file_openers.iter().any(|o| l.contains(o)))
}

/// Lines of shippable Rust that write to the filesystem (needles built in parts: they are search patterns, not writes).
fn disk_write_needles() -> [&'static str; 8] {
    [
        concat!("fs::", "write"),
        concat!("fs::", "create_dir_all"),
        concat!("fs::", "create_dir("),
        concat!("fs::", "rename"),
        concat!("fs::", "copy"),
        concat!("File::", "create"),
        concat!("OpenOptions", "::new"),
        concat!(".write", "_all("),
    ]
}

fn approved_writes() -> Vec<(String, String)> {
    let p = std::env::var("HOME").map(PathBuf::from).unwrap_or_default().join(".claude/hooks/user-approved-local-storage.txt");
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':').map(|(a, b)| (a.trim().to_string(), b.split_whitespace().next().unwrap_or("").to_string())))
        .collect()
}

/// Identifiers whose VALUE must never reach a log. Matched as whole identifiers, so `seed_path` (a path) and `seed_line`
/// (a peer's public bootstrap line) are not `seed`.
const SENSITIVE: &[&str] = &[
    "nullifier", "usdm_nullifier", "nf", "nf_hex", "nf_bytes", "secret", "secret_key", "seed", "seed_phrase", "phrase", "mnemonic",
    "master_seed", "seed_bytes", "spend_key", "scan_key", "private_key", "privkey", "sk", "amount", "amount_atomic",
    "value_atomic", "blind", "blinding", "opening", "witness",
];
const PRINT_MACROS: &[&str] =
    &["eprintln!(", "println!(", "info!(", "warn!(", "error!(", "debug!(", "trace!(", "print!(", "eprint!(", "console.log(", "console.debug(", "console.info(", "console.warn(", "console.error("];

/// The sensitive name a print macro INTERPOLATES (a `{name}` placeholder or an argument after the format string), if any.
fn interpolated_sensitive(line: &str) -> Option<&'static str> {
    let (mac_at, mac) = PRINT_MACROS.iter().find_map(|m| line.find(m).map(|i| (i, *m)))?;
    let rest = &line[mac_at + mac.len()..];
    let lits = quoted(rest);
    let fmt = lits.first().copied().unwrap_or("");
    let mut placeholders = String::new();
    let mut in_ph = false;
    for c in fmt.chars() {
        if c == '{' {
            in_ph = true;
        } else if c == '}' {
            in_ph = false;
            placeholders.push(' ');
        } else if in_ph {
            placeholders.push(c);
        }
    }
    // the arguments: everything after the format literal's CLOSING quote (or the whole call for console.*)
    let args = match rest.find(fmt) {
        Some(i) if !fmt.is_empty() => rest.get(i + fmt.len() + 1..).unwrap_or(""),
        _ => rest,
    };
    // strip every remaining string literal from the args (a literal is not a value)
    let mut a = args.to_string();
    for l in quoted(args) {
        a = a.replacen(l, "", 1);
    }
    // a trailing `// …` comment is not an argument (MEASURED 2026-10-05: `eprintln!("…"); // no amount, no address` was
    // filed as a log that prints an amount) — literals are already removed, so a `//` left in `a` starts a comment
    if let Some(i) = a.find("//") {
        a.truncate(i);
    }
    let hay = format!("{} {}", placeholders.to_ascii_lowercase(), a.to_ascii_lowercase());
    // whole identifiers only; a field access counts by its last segment (`self.amount`, `n.nf`)
    hay.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find_map(|tok| SENSITIVE.iter().find(|w| **w == tok).copied())
}

const CLASSICAL_CRATES: &[&str] = &[
    "ed25519", "ed25519-dalek", "ed25519-compact", "x25519-dalek", "curve25519-dalek", "curve25519-dalek-ng", "secp256k1",
    "secp256k1-sys", "k256", "p256", "p384", "p521", "rsa", "ecdsa", "elliptic-curve", "bls12_381", "blst", "dalek",
    "schnorrkel", "libsecp256k1", "x448", "ed448",
];
const TLS_CRATES: &[&str] = &["rustls", "native-tls", "openssl", "openssl-sys", "ring", "tokio-rustls", "hyper-rustls", "webpki", "aws-lc-rs"];

/// Does `crate_name` reach a workspace member in `lock_rel` (a lockfile path relative to the repo) ONLY through the Tor
/// stack? The reverse-dependency walk stops at any `tor-*` / `arti*` crate (Tor's link layer is TLS by design); reaching a
/// non-registry package (a workspace member) any other way is a clearnet-capable path. A crate absent from the lock is
/// vacuously Tor-only.
fn tls_reaches_workspace_only_through_tor(lock_rel: &str, crate_name: &str) -> bool {
    let Ok(t) = fs::read_to_string(repo_root().join(lock_rel)) else { return false };
    let mut deps_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut external: HashMap<String, bool> = HashMap::new();
    for block in t.split("[[package]]").skip(1) {
        let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().trim_matches('"').to_string()));
        let name = field("name = ").unwrap_or_default();
        external.insert(name.clone(), block.contains("source = "));
        let mut deps = Vec::new();
        if let Some(d) = block.find("dependencies = [") {
            for l in block[d..].lines().skip(1) {
                let l = l.trim();
                if l.starts_with(']') {
                    break;
                }
                deps.push(l.trim_matches(|c| c == '"' || c == ',').split(' ').next().unwrap_or("").to_string());
            }
        }
        deps_of.insert(name, deps);
    }
    let is_tor = |n: &str| n.starts_with("tor-") || n.starts_with("arti");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![crate_name.to_string()];
    while let Some(n) = stack.pop() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if n != crate_name && is_tor(&n) {
            continue; // the Tor stack: every path above it is Tor's own
        }
        if n != crate_name && external.get(&n) == Some(&false) {
            return false; // a workspace member reached without passing the Tor stack
        }
        for (p, ds) in &deps_of {
            if ds.iter().any(|d| d == &n) {
                stack.push(p.clone());
            }
        }
    }
    true
}

/// `(lockfile, name, version, reverse dependents)` for every registry/git crate in every lockfile.
fn locked_crates() -> Vec<(String, String, String, Vec<String>)> {
    let mut out = Vec::new();
    for lock in [
        node_root().join("Cargo.lock"),
        node_root().join("vendor/Plonky3/Cargo.lock"),
        repo_root().join("monerousd-wallet-v2/src-tauri/Cargo.lock"),
    ] {
        let Ok(t) = fs::read_to_string(&lock) else { continue };
        let rel = lock.strip_prefix(repo_root()).unwrap_or(&lock).to_string_lossy().into_owned();
        let mut pkgs: Vec<(String, String, bool, Vec<String>)> = Vec::new();
        for block in t.split("[[package]]").skip(1) {
            let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().trim_matches('"').to_string()));
            let name = field("name = ").unwrap_or_default();
            let ver = field("version = ").unwrap_or_default();
            let external = block.contains("source = ");
            let mut deps = Vec::new();
            if let Some(d) = block.find("dependencies = [") {
                for l in block[d..].lines().skip(1) {
                    let l = l.trim();
                    if l.starts_with(']') {
                        break;
                    }
                    deps.push(l.trim_matches(|c| c == '"' || c == ',').split(' ').next().unwrap_or("").to_string());
                }
            }
            pkgs.push((name, ver, external, deps));
        }
        for (name, ver, external, _) in &pkgs {
            if !external {
                continue;
            }
            let rdeps: Vec<String> = pkgs.iter().filter(|p| p.3.iter().any(|d| d == name)).map(|p| p.0.clone()).collect();
            out.push((rel.clone(), name.clone(), ver.clone(), rdeps));
        }
    }
    out
}

/// One row of `scratchpad/pin-results.tsv` (`ts \t crate \t test path \t ok|FAILED|KILLED \t head [\t branch]`), appended by
/// `lane_run.sh` on every run of every test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRow {
    /// ISO timestamp, second precision.
    pub ts: String,
    pub krate: String,
    /// The full `module::path::name` — the test's one identity (cargo's own key); the short name is derived, never stored.
    pub path: String,
    /// `ok`, `FAILED` or `KILLED` (a job ended by memory/stall: not a verdict).
    pub verdict: String,
    pub head: String,
    /// The branch the run was built on; `detached` (certify/watch/farm worktrees), `farm`, or empty on older rows.
    pub branch: String,
}

impl PinRow {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.verdict == "ok"
    }
    /// The last `::` segment.
    #[must_use]
    pub fn short(&self) -> &str {
        self.path.rsplit("::").next().unwrap_or(&self.path)
    }
}

/// Does the tree a ledger row was built on still exist? A row on a DELETED lane branch (an archived worktree's red) is not a
/// verdict about this tree (the register counted 39 "known reds" on 2026-10-05 that were other lanes' worktree reds). A row with
/// no branch column (older ledgers), on a live branch, or from a worktree that is not a branch at all (`detached` — the certify,
/// watch and farm worktrees run main's own commit — or `farm`) counts. MEASURED 2026-10-27 (lane d): the old branch filter
/// treated `detached` as a deleted branch and dropped 14,239 of 39,000 rows — the newest, from certify — so 14 tests read RED on
/// a 10/24 lane row after passing on 10/26 ("STALE LISTING" ×13 in ROOT CAUSES) and 12 tests that FAILED on 10/26–27 read ok.
#[must_use]
pub fn ledger_tree_exists(branch: &str, live: &BTreeSet<String>) -> bool {
    let b = branch.trim();
    b.is_empty() || !b.contains('/') || live.contains(b)
}

/// THE ONE READER of the pin ledger (user 2026-10-27: one normalisation at one site): the newest row — by TIMESTAMP, never file
/// order (four lanes append concurrently) — of every test PATH, from trees that exist (`ledger_tree_exists`). Every consumer
/// (the red-pin listing, the census row verdicts, the cause index) derives from this map, so no two sites can disagree about
/// which run is a test's latest.
#[must_use]
pub fn parse_pin_ledger(text: &str, live: &BTreeSet<String>) -> BTreeMap<String, PinRow> {
    let mut m: BTreeMap<String, PinRow> = BTreeMap::new();
    for l in text.lines() {
        let c: Vec<&str> = l.split('\t').collect();
        if c.len() < 4 {
            continue;
        }
        let branch = c.get(5).map_or("", |b| b.trim());
        if !ledger_tree_exists(branch, live) {
            continue;
        }
        let row = PinRow {
            ts: c[0].to_string(),
            krate: c[1].to_string(),
            path: c[2].to_string(),
            verdict: c[3].trim().to_string(),
            head: c.get(4).map_or("", |h| h.trim()).to_string(),
            branch: branch.to_string(),
        };
        match m.get(&row.path) {
            Some(have) if have.ts > row.ts => {}
            _ => {
                m.insert(row.path.clone(), row);
            }
        }
    }
    m
}

/// The live branches of the repository (`git branch`); `None` when git cannot be asked (then every row counts).
fn live_branches() -> BTreeSet<String> {
    std::process::Command::new("git")
        .args(["branch", "--format=%(refname:short)"])
        .current_dir(repo_root())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default()
}

/// The newest row of every test path in `scratchpad/pin-results.tsv` (see `parse_pin_ledger`).
#[must_use]
pub fn pin_ledger() -> BTreeMap<String, PinRow> {
    let text = fs::read_to_string(crate::harness::scratchpad_dir().join("pin-results.tsv")).unwrap_or_default();
    parse_pin_ledger(&text, &live_branches())
}

/// The newest row of every SHORT name (last path segment) — the key the cause ledgers and census rows carry. Two paths sharing a
/// short name (a test moved between modules) resolve to whichever ran last.
#[must_use]
pub fn pin_ledger_by_short_name() -> HashMap<String, PinRow> {
    let mut m: HashMap<String, PinRow> = HashMap::new();
    for row in pin_ledger().into_values() {
        let short = row.short().to_string();
        match m.get(&short) {
            Some(have) if have.ts > row.ts => {}
            _ => {
                m.insert(short, row);
            }
        }
    }
    m
}

/// The latest recorded verdict of every pin, by its last path segment (derived from `pin_ledger`).
#[must_use]
pub fn pin_results() -> HashMap<String, String> {
    pin_ledger_by_short_name().into_iter().map(|(short, row)| (short, row.verdict)).collect()
}

/// Positions of `ch` at nesting depth 0 of `e` (outside brackets and string literals).
fn top_level(e: &str, pat: &str) -> Vec<usize> {
    let b = e.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            q @ (b'\'' | b'"' | b'`') => {
                // skip the literal, honouring backslash escapes (`'You\'ll'`)
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ if depth == 0 && b[i..].starts_with(pat.as_bytes()) => {
                out.push(i);
                i += pat.len();
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Is a JS expression safe to place in HTML: every value it can PRODUCE is a literal, a number, or escaped?
/// A ternary is judged by its branches (its condition is never output), `+` / `||` / `??` / `&&` by every operand, a
/// nested template by its own interpolations.
fn expr_safe(e: &str) -> bool {
    let e = strip_outer_parens(e);
    if e.is_empty() {
        return true;
    }
    if let Some(&q) = top_level(e, "?").iter().find(|&&q| !e[q..].starts_with("??") && !e[..q].ends_with('?')) {
        let rest = &e[q + 1..];
        if let Some(&c) = top_level(rest, ":").first() {
            return expr_safe(&rest[..c]) && expr_safe(&rest[c + 1..]);
        }
    }
    for op in ["||", "??", "&&", "+"] {
        let at = top_level(e, op);
        if !at.is_empty() {
            let mut parts = Vec::new();
            let mut from = 0;
            for a in at {
                parts.push(&e[from..a]);
                from = a + op.len();
            }
            parts.push(&e[from..]);
            return parts.iter().all(|p| expr_safe(p));
        }
    }
    // ONE whole literal (escape-aware: `'You\'ll'` is one literal)
    if (e.starts_with('\'') || e.starts_with('"')) && quoted(e).first().is_some_and(|l| l.len() + 2 == e.len()) {
        return true;
    }
    if e.starts_with('`') {
        if e.ends_with('`') && e.len() >= 2 && !e[1..e.len() - 1].contains("${") {
            return true; // a template with no interpolation is a literal
        }
        return unescaped_interpolation(&e[1..]).is_none();
    }
    if e.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-') || ["true", "false", "null", "undefined", "''", "\"\""].contains(&e) {
        return true;
    }
    // a call through an object (`H.escapeHtml(…)`) is judged by the function's own name
    let callee = e.split('(').next().unwrap_or(e);
    let fname = callee.rsplit('.').next().unwrap_or(callee).to_ascii_lowercase();
    if ["esc", "escape", "sanit", "encodeuricomponent", "number", "parseint", "parsefloat", "bigint", "textcontent"].iter().any(|s| fname.starts_with(s))
        || e.starts_with("Math.")
    {
        return true;
    }
    if [".length", ".size"].iter().any(|s| e.ends_with(s))
        || [".toFixed(", ".toLocaleString(", ".toPrecision(", ".toUTCString(", ".toISOString(", ".toDateString(", ".toLocaleDateString(", ".toLocaleTimeString(", ".toExponential("].iter().any(|s| e.contains(s))
    {
        return true;
    }
    // a LOCAL markup helper is judged by what it RETURNS, a literal table by its values, a single-assignment local by its
    // initializer, `xs.map(f).join('')` by the mapped expression — one shared rule (js_helpers / helper_returns_safe)
    if let Some(v) = map_join_safe(e) {
        return v;
    }
    if let Some(v) = map_only_safe(e) {
        return v;
    }
    let callee_t = callee.trim();
    if is_js_ident(callee_t) && e.as_bytes().get(callee_t.len()) == Some(&b'(') && helper_returns_safe(callee_t) {
        return true;
    }
    if let Some(i) = e.find(['[', '.']) {
        let t = &e[..i];
        if is_js_ident(t) && e.ends_with(']') | e[i..].chars().skip(1).all(|c| c.is_ascii_alphanumeric() || c == '_') && helper_returns_safe(t) {
            return true;
        }
    }
    if is_js_ident(e) && local_single_assignment_safe(e) {
        return true;
    }
    // `rows.join('')` over a local that holds `xs.map(f)`: judged by the mapped expression
    if let Some(dot) = e.find(".join(") {
        let t = &e[..dot];
        if is_js_ident(t) && local_single_assignment_safe(t) {
            return true;
        }
    }
    false
}

/// `xs.map(ARG)` with no `.join` (an array of markup the caller joins or interpolates): judged by the mapped expression.
fn map_only_safe(e: &str) -> Option<bool> {
    let m = *top_level(e, ".map(").first()?;
    let inner = js_balanced(e, m + 4)?;
    let after = e[m + 4 + inner.len() + 2..].trim();
    if !after.is_empty() {
        return None;
    }
    Some(mapped_expr_safe(inner.trim()))
}

/// The first value an HTML sink's right-hand side places in the page unescaped, if any.

thread_local! {
    /// The JS file under judgement: `name → body` for every `function NAME(…) {…}`, `const NAME = (…) => …` and literal
    /// table `const NAME = {…}` it defines. A sink fed by a LOCAL markup helper (`heroHTML(info)`,
    /// `rows.map(siteCard).join('')`, `KIND_ICON[kind]`) is judged by what the helper RETURNS — its own templates go through
    /// the same rule — instead of being refused at the call (2026-10-05, the HTML-sink CLASS: 135 rows, most of them a
    /// call into a helper whose raw interpolations the old rule never looked at; one shared rule, strictly more coverage).
    static JS_HELPERS: std::cell::RefCell<HashMap<String, String>> = std::cell::RefCell::new(HashMap::new());
    /// Helpers being judged right now (a cycle or a chain deeper than 6 is refused, never trusted).
    static JS_IN_PROGRESS: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
    /// The file's lines and the sink's line, for the single-assignment local rule.
    static JS_CONTEXT: std::cell::RefCell<(Vec<String>, usize, String)> = std::cell::RefCell::new((Vec::new(), 0, String::new()));
}

fn is_js_ident(t: &str) -> bool {
    !t.is_empty() && !t.as_bytes()[0].is_ascii_digit() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// `open` indexes a `{` / `(`: the text inside its matching close, string and template literals skipped.
fn js_balanced(text: &str, open: usize) -> Option<&str> {
    let b = text.as_bytes();
    let (o, c) = match b.get(open)? {
        b'{' => (b'{', b'}'),
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        let ch = b[i];
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(&text[open + 1..i]);
            }
        } else if ch == b'\'' || ch == b'"' || ch == b'`' {
            i += 1;
            while i < b.len() && b[i] != ch {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
        }
        i += 1;
    }
    None
}

/// The statement that starts at `from`: up to the first `;` at depth 0 (literals skipped), at most 40 lines.
fn js_statement(text: &str, from: usize) -> &str {
    let b = text.as_bytes();
    let mut depth = 0i32;
    let mut i = from;
    let mut nl = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    return &text[from..i];
                }
            }
            b';' if depth == 0 => return &text[from..i],
            b'\n' => {
                nl += 1;
                if nl > 40 {
                    return &text[from..i];
                }
            }
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    &text[from..]
}

/// Every `return <expr>` of a function body — the body's OWN returns: a nested `function (…) {…}` or `=> {…}` block is
/// skipped (its returns belong to it: measured 2026-10-05, an inner `rnd = () => { …; return st/2**32; }` made the whole
/// identicon helper read unsafe), string and template literals are skipped too.
fn js_returns(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !body.is_char_boundary(i) {
            i += 1;
            continue;
        }
        match b[i] {
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            b'=' if b.get(i + 1) == Some(&b'>') => {
                // an arrow: a block body is skipped whole
                let mut j = i + 2;
                while j < b.len() && (b[j] == b' ' || b[j] == b'\n') {
                    j += 1;
                }
                if b.get(j) == Some(&b'{') {
                    if let Some(inner) = js_balanced(body, j) {
                        i = j + inner.len() + 2;
                        continue;
                    }
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        let rest = &body[i..];
        if rest.starts_with("function") && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
            if let Some(ob) = rest.find('{') {
                if let Some(inner) = js_balanced(body, i + ob) {
                    i = i + ob + inner.len() + 2;
                    continue;
                }
            }
        }
        if rest.starts_with("return") {
            let before_ok = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_' || b[i - 1] == b'$' || b[i - 1] == b'.');
            let after = b.get(i + 6).copied().unwrap_or(b';');
            let after_ok = after == b' ' || after == b'\n' || after == b'(' || after == b'`' || after == b';';
            if before_ok && after_ok {
                out.push(js_statement(body, i + 6).trim());
            }
            i += 6;
            continue;
        }
        i += 1;
    }
    out
}

/// A literal table's values: `{ a: 'x', b: `<i/>` }` → the text after each top-level `key:`.
fn js_table_values(body: &str) -> Vec<&str> {
    let mut vals = Vec::new();
    let mut from = 0;
    let mut cuts = top_level(body, ",");
    cuts.push(body.len());
    for c in cuts {
        let entry = &body[from..c.min(body.len())];
        if let Some(&k) = top_level(entry, ":").first() {
            vals.push(entry[k + 1..].trim());
        } else if !entry.trim().is_empty() {
            vals.push(entry.trim()); // shorthand `{ name }` — a raw value
        }
        from = (c + 1).min(body.len());
    }
    vals
}

/// Index every helper the file defines. A name defined twice is dropped: ambiguity is never trusted.
fn js_helpers(text: &str) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut dup: Vec<String> = Vec::new();
    let mut put = |name: &str, body: String| {
        if out.insert(name.to_string(), body).is_some() {
            dup.push(name.to_string());
        }
    };
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("function ") && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_' || b[i - 1] == b'.')) {
            let after = &rest[9..];
            let name: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$').collect();
            if let Some(p) = after.find('(') {
                if let Some(params) = js_balanced(after, p) {
                    let body_at = i + 9 + p + 1 + params.len() + 1;
                    if let Some(bo) = text[body_at..].find('{') {
                        if text[body_at..body_at + bo].trim().is_empty() {
                            if let Some(body) = js_balanced(text, body_at + bo) {
                                if !name.is_empty() {
                                    put(&name, format!("{{{body}"));
                                }
                            }
                        }
                    }
                }
            }
            i += 9;
            continue;
        }
        for kw in ["const ", "let ", "var "] {
            if rest.starts_with(kw) && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
                let after = &rest[kw.len()..];
                let name: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$').collect();
                let tail = after[name.len()..].trim_start();
                if !name.is_empty() && tail.starts_with('=') && !tail.starts_with("==") {
                    let val_at = i + (text.len() - rest.len() - i) + kw.len() + name.len() + (after[name.len()..].len() - tail.len()) + 1;
                    let stmt = js_statement(text, val_at).trim_start();
                    if stmt.starts_with('{') {
                        if let Some(body) = js_balanced(stmt, 0) {
                            put(&name, format!("#{body}"));
                        }
                    } else if let Some(&arrow) = top_level(stmt, "=>").first() {
                        let head = stmt[..arrow].trim();
                        if head.starts_with('(') || is_js_ident(head) || head == "async" || head.starts_with("async ") {
                            let body = stmt[arrow + 2..].trim();
                            if body.starts_with('{') {
                                if let Some(inner) = js_balanced(body, 0) {
                                    put(&name, format!("{{{inner}"));
                                }
                            } else {
                                put(&name, format!("={body}"));
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    for d in dup {
        out.remove(&d);
    }
    out
}

/// What a local helper RETURNS is judged by the same rule as a sink; a cycle, an unknown name, a body with no return,
/// or a chain deeper than 6 is refused.
fn helper_returns_safe(name: &str) -> bool {
    let Some(body) = JS_HELPERS.with(|h| h.borrow().get(name).cloned()) else { return false };
    if JS_IN_PROGRESS.with(|v| v.borrow().iter().any(|n| n == name) || v.borrow().len() > 6) {
        return false;
    }
    JS_IN_PROGRESS.with(|v| v.borrow_mut().push(name.to_string()));
    let saved = JS_CONTEXT.with(|c| std::mem::replace(&mut c.borrow_mut().2, body[1..].to_string()));
    let ok = match body.as_bytes().first() {
        Some(b'{') => {
            let rets = js_returns(&body[1..]);
            !rets.is_empty() && rets.iter().all(|r| expr_safe(r))
        }
        Some(b'=') => expr_safe(&body[1..]),
        Some(b'#') => js_table_values(&body[1..]).iter().all(|v| expr_safe(v)),
        _ => false,
    };
    JS_CONTEXT.with(|c| c.borrow_mut().2 = saved);
    JS_IN_PROGRESS.with(|v| {
        v.borrow_mut().pop();
    });
    ok
}

/// A bare identifier declared ONCE (`const html = …`) above the sink, with no reassignment between, is judged by its
/// initializer; `html += …` or a second `html =` refuses it (the value can no longer be traced).
fn local_single_assignment_safe(name: &str) -> bool {
    if JS_IN_PROGRESS.with(|v| v.borrow().iter().any(|n| n == name) || v.borrow().len() > 6) {
        return false;
    }
    let found = JS_CONTEXT.with(|c| {
        let (lines, sink, rhs) = &*c.borrow();
        // a declaration INSIDE the sink's own statement (a block arrow's local) comes first
        for kw in ["const ", "let ", "var "] {
            for decl in [format!("{kw}{name} ="), format!("{kw}{name}=")] {
                let Some(at) = rhs.find(&decl) else { continue };
                let after = &rhs[at + decl.len()..];
                if after.starts_with('=') {
                    continue; // `==`
                }
                let init = js_statement(after, 0).trim().to_string();
                let tail = &rhs[at + decl.len()..];
                let tail = &tail[tail.find(&init).map(|k| k + init.len()).unwrap_or(0)..];
                let written = tail.contains(&format!("{name} +=")) || tail.contains(&format!("{name}+=")) || tail.contains(&format!(" {name} = ")) || tail.contains(&format!(";{name} = ")) || tail.contains(&format!(";{name}="));
                return Some((init, written));
            }
        }
        if *sink == 0 || lines.is_empty() {
            return None;
        }
        let mut k = (*sink).min(lines.len()) - 1; // the sink's own line (0-based)
        let floor = k.saturating_sub(120);
        while k > floor {
            k -= 1;
            let t = lines[k].trim_start();
            for kw in ["const ", "let ", "var "] {
                // the declaration may sit mid-line (`else { const p=…; const bio=…; }`): find it anywhere on the line
                let found = t.find(&format!("{kw}{name}")).map(|at| &t[at + kw.len()..]);
                if let Some(after) = found {
                    if after.starts_with(name) && after[name.len()..].trim_start().starts_with('=') && !after[name.len()..].trim_start().starts_with("==") {
                        let eq = after[name.len()..].find('=').unwrap() + name.len() + 1;
                        let rest: String = std::iter::once(after[eq..].to_string()).chain(lines[k + 1..*sink].iter().map(|l| l.to_string())).collect::<Vec<_>>().join("\n");
                        let init = js_statement(&rest, 0).trim().to_string();
                        // any later write to the name between the declaration and the sink refuses it
                        let written = lines[k + 1..*sink - 1].iter().any(|l| {
                            let l = l.trim_start();
                            l.starts_with(&format!("{name} =")) && !l.starts_with(&format!("{name} ==")) || l.starts_with(&format!("{name} +="))
                        });
                        return Some((init, written));
                    }
                }
            }
            if t.starts_with(&format!("{name} +=")) || t.starts_with(&format!("{name}+=")) || ((t.starts_with(&format!("{name} =")) || t.starts_with(&format!("{name}="))) && !t.starts_with(&format!("{name} ==")) && !t.starts_with(&format!("{name}=="))) {
                return Some((String::new(), true));
            }
        }
        None
    });
    let Some((init, written)) = found else { return false };
    if written || init.is_empty() {
        return false;
    }
    JS_IN_PROGRESS.with(|v| v.borrow_mut().push(name.to_string()));
    let ok = expr_safe(&init);
    JS_IN_PROGRESS.with(|v| {
        v.borrow_mut().pop();
    });
    ok
}

/// `xs.map(ARG).join(…)` (any `.filter`/`.slice` before it): judged by the mapped expression — a helper by its returns, an
/// arrow by its body (a block arrow by its returns). `None` when the expression is not that shape.
fn map_join_safe(e: &str) -> Option<bool> {
    let m = *top_level(e, ".map(").first()?;
    let inner = js_balanced(e, m + 4)?;
    let after = e[m + 4 + inner.len() + 2..].trim_start();
    if !after.starts_with(".join(") {
        return None;
    }
    Some(mapped_expr_safe(inner.trim()))
}

fn mapped_expr_safe(arg: &str) -> bool {
    if is_js_ident(arg) {
        return helper_returns_safe(arg);
    }
    let Some(&a) = top_level(arg, "=>").first() else { return false };
    let body = arg[a + 2..].trim();
    let saved = JS_CONTEXT.with(|c| std::mem::replace(&mut c.borrow_mut().2, body.to_string()));
    let ok = if body.starts_with('{') {
        match js_balanced(body, 0) {
            Some(inner) => {
                let rets = js_returns(inner);
                !rets.is_empty() && rets.iter().all(|r| expr_safe(r))
            }
            None => false,
        }
    } else {
        expr_safe(body)
    };
    JS_CONTEXT.with(|c| c.borrow_mut().2 = saved);
    ok
}

/// Every HTML sink of one JS/HTML file: `(sinks counted, [(1-based line, the first unescaped value)])`.
fn html_sink_holes(text: &str) -> (usize, Vec<(usize, String)>) {
    JS_HELPERS.with(|h| *h.borrow_mut() = js_helpers(text));
    let lines: Vec<&str> = text.lines().collect();
    JS_CONTEXT.with(|c| *c.borrow_mut() = (lines.iter().map(|l| l.to_string()).collect(), 0, String::new()));
    let mut sinks = 0usize;
    let mut bad_sinks = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let sink = ["innerHTML =", "innerHTML=", "innerHTML +=", "outerHTML =", "insertAdjacentHTML(", "document.write("].iter().find_map(|s| line.find(s).map(|i| (i, s.len())));
        let Some((at, len)) = sink else { continue };
        if line.trim_start().starts_with("//") {
            continue;
        }
        sinks += 1;
        // the right-hand side: to the statement's end, at most 15 lines
        let mut rhs = line[at + len..].to_string();
        let mut k = n + 1;
        while !rhs.trim_end().ends_with(';') && k < lines.len() && k <= n + 15 {
            rhs.push('\n');
            rhs.push_str(lines[k]);
            k += 1;
        }
        JS_CONTEXT.with(|c| {
            let mut c = c.borrow_mut();
            c.1 = n + 1;
            c.2 = format!("{}\n{}", &line[..at], rhs); // the sink line's prefix holds same-line declarations
        });
        JS_IN_PROGRESS.with(|v| v.borrow_mut().clear());
        if let Some(bad) = unescaped_interpolation(&rhs) {
            bad_sinks.push((n + 1, bad));
        }
    }
    JS_CONTEXT.with(|c| *c.borrow_mut() = (Vec::new(), 0, String::new()));
    JS_HELPERS.with(|h| h.borrow_mut().clear());
    (sinks, bad_sinks)
}

/// `(expr)` → `expr`, repeatedly, only when the leading `(` closes at the very end (a balanced wrapper); the old
/// `trim_start_matches('(')` / `trim_end_matches(')')` cut `((cond) ? a : (b + f(x)))` into unmatched halves and every
/// ternary error message in the wallet fired (measured 2026-10-05).
fn strip_outer_parens(e: &str) -> &str {
    let mut e = e.trim();
    loop {
        if !e.starts_with('(') {
            return e;
        }
        match js_balanced(e, 0) {
            Some(inner) if inner.len() + 2 == e.len() => e = inner.trim(),
            _ => return e,
        }
    }
}

fn unescaped_interpolation(rhs: &str) -> Option<String> {
    // the whole statement wrapped in ONE sanitizing / escaping call (`sanitizeHtml(xs.map(…).join(''))`): judged safe here,
    // before the `${…}` inside the wrapped markup are looked at one by one
    {
        let stmt = strip_outer_parens(js_statement(rhs, 0));
        let callee = stmt.split('(').next().unwrap_or("");
        let fname = callee.rsplit('.').next().unwrap_or(callee).to_ascii_lowercase();
        if is_js_ident(callee.rsplit('.').next().unwrap_or(callee)) && (fname.starts_with("sanit") || fname.starts_with("esc")) {
            if let Some(inner) = js_balanced(stmt, callee.len()) {
                if callee.len() + inner.len() + 2 == stmt.len() {
                    return None;
                }
            }
        }
    }
    let b = rhs.as_bytes();
    let mut i = 0;
    let mut saw_template = false;
    while i + 1 < b.len() {
        if b[i] == b'$' && b[i + 1] == b'{' {
            saw_template = true;
            let mut depth = 0i32;
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let expr = &rhs[i + 2..j.min(rhs.len())];
            // a nested template inside the interpolation is judged by ITS interpolations
            let ok = if let Some(v) = map_join_safe(expr) { v } else if expr.contains('`') { expr_safe(expr) || (unescaped_interpolation(expr).is_none() && expr_safe_outside_templates(expr)) } else { expr_safe(expr) };
            if !ok {
                return Some(expr.to_string());
            }
            i = j;
        }
        i += 1;
    }
    if !saw_template {
        // the statement, literal-aware: a `;` inside a style attribute never ends it (fresh sweep 2026-10-05: 20 rows)
        let stmt = js_statement(rhs, 0);
        let t = stmt.trim();
        // a template literal with no interpolation is a literal (`<span>Connecting…</span>`), never a value
        let whole_template = t.starts_with('`') && t.ends_with('`') && t.len() >= 2 && !t[1..t.len() - 1].contains('`');
        if !whole_template && !expr_safe(stmt) {
            return Some(t.to_string());
        }
    }
    None
}

/// For an interpolation holding a nested template (`xs.map(x => `…${…}…`).join('')`): the parts OUTSIDE the nested
/// templates may only be calls that assemble markup (map / join / filter / slice) — never a raw value.
fn expr_safe_outside_templates(expr: &str) -> bool {
    let mut outside = String::new();
    let mut in_tpl = false;
    for c in expr.chars() {
        if c == '`' {
            in_tpl = !in_tpl;
            continue;
        }
        if !in_tpl {
            outside.push(c);
        }
    }
    let o = outside.replace(' ', "");
    // markup assembly only: `.map(`, `.join(`, arrow params, `.filter(`, `.slice(`
    o.contains(".map(") || o.contains(".join(")
}

/// `(line, fn name, stacked?)` for every hollow pin in a Rust file: a zero-argument fn in a TEST region that asserts,
/// carries no test attribute and is referenced nowhere else in `all_rust` (it never runs) — or (`stacked`) a fn carrying
/// two test attributes.
fn hollow_pins(text: &str, ship: &str, test_file: bool, all_rust: &str) -> Vec<(usize, String, bool)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let ship_lines: Vec<&str> = ship.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let in_test = test_file || ship_lines.get(i).is_some_and(|s| s.trim().is_empty());
        let t = l.trim_start();
        if !in_test || !t.starts_with("fn ") {
            continue;
        }
        let name: String = t[3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if !t[3 + name.len()..].starts_with("()") {
            continue;
        }
        // the attributes above it, skipping doc comments, comments and blank lines
        let mut tests = 0usize;
        for back in lines[..i].iter().rev().take(80) {
            let b = back.trim_start();
            if b.starts_with("//") || b.is_empty() {
                continue;
            }
            // `#[test] fn one_liner() { … }` is an ITEM above, not an attribute of this fn (measured: the runtime
            // backend's one-line case pins read as stacked attributes on the diagnostic below them)
            if b.starts_with("#[") && !b.contains("fn ") {
                if b.starts_with("#[test]") || b.starts_with("#[tokio::test") {
                    tests += 1;
                }
                continue;
            }
            break;
        }
        if tests >= 2 {
            out.push((i + 1, name, true));
        } else if tests == 0 {
            let rest = lines[i..].join("\n");
            let end = rest.find("\n    }\n").or_else(|| rest.find("\n}\n")).unwrap_or(rest.len().min(4000));
            let asserts = rest[..end].contains("assert");
            let called_elsewhere = all_rust.matches(name.as_str()).count() > 1;
            if asserts && !called_elsewhere && name.len() > 8 {
                out.push((i + 1, name, false));
            }
        }
    }
    out
}

/// The latest recorded verdict of every pin by its FULL test path: path → (crate, ok|FAILED|KILLED), derived from `pin_ledger`
/// (one reader, one branch rule, newest by timestamp).
#[must_use]
pub fn latest_pin_verdicts() -> BTreeMap<String, (String, String)> {
    pin_ledger().into_iter().map(|(path, row)| (path, (row.krate, row.verdict))).collect()
}

/// Snake-case identifiers in a census row that look like pin names (long, many words).
fn pin_like(s: &str) -> BTreeSet<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.len() >= 20 && w.matches('_').count() >= 3 && w.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        .map(str::to_string)
        .collect()
}

/// Every hole the surface census finds, with its tier and kind.
#[must_use]
/// One decode of OUTSIDE bytes in shippable code (section 5's universe, shared with the decode-door replay pin), with the
/// decode DOOR (`decode_doors::DOORS`) that drives it.
pub struct DecodeSite {
    /// `file:line`.
    pub at: String,
    /// The turbofish type, when the line names one (`""` otherwise).
    pub ty: String,
    /// A postcard / bincode decode that tolerates trailing bytes.
    pub lenient: bool,
    /// In a consensus file of the node (where lenient is the "two encodings" hole).
    pub consensus: bool,
    /// The turbofish type is named in the stateful fuzz catalogue's text (`src/harness/fuzz/`).
    pub textually_fuzzed: bool,
    /// The door the replay drives for this site, read from the site's own text (`decode_door_for`).
    pub door: Option<&'static str>,
}

/// Every `postcard::from_bytes` / `bincode::deserialize` / `serde_json::from_*` in shippable code outside the decider.
pub fn decode_sites(eco: &Ecosystem) -> Vec<DecodeSite> {
    let fuzz_text: String = eco.files.iter().filter(|f| f.rel.contains("/harness/fuzz/")).map(|f| f.text.as_str()).collect::<Vec<_>>().join("\n");
    let mut out = Vec::new();
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs") && f.part != "decider") {
        let text = f.shippable();
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("pub fn decode_exact") {
                continue;
            }
            let lenient = line.contains("postcard::from_bytes") || line.contains("bincode::deserialize");
            let json = line.contains("serde_json::from_");
            if !(lenient || json) {
                continue;
            }
            let ty: String = line.split("::<").nth(1).map(|s| s.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect()).unwrap_or_default();
            // the decode line with the six lines before and two after: a `let x: T =` or a closure's `|c: &T|` names the type
            let window = lines[n.saturating_sub(6)..(n + 3).min(lines.len())].join("\n");
            // a std container's name closes nothing (MEASURED 2026-10-22: `Vec` in the catalogue's text had closed the
            // wallet's `Vec<SwapRec>` swap-log read, lib.rs:2954, with no fuzzer anywhere near it)
            let container = matches!(ty.as_str(), "Vec" | "Option" | "Box" | "HashMap" | "BTreeMap" | "String" | "Arc");
            out.push(DecodeSite {
                at: format!("{}:{}", f.rel, n + 1),
                textually_fuzzed: !ty.is_empty() && !container && fuzz_text.contains(&ty),
                lenient,
                consensus: f.part == "node" && !f.base().starts_with("persist") && has_any(f.base(), CONSENSUS_FILE_WORDS),
                door: decode_door_for(&window),
                ty,
            });
        }
    }
    out
}

/// The decode door (`decode_doors::DOORS`) that drives a site, from the site's own text: the decoded TYPE names the door.
/// Specific types first; a `serde_json::Value` anywhere in the window is the JSON door LAST, so a postcard decode beside a
/// JSON read keeps its own door. A site naming none stays a hole until a door is added for it.
pub fn decode_door_for(window: &str) -> Option<&'static str> {
    use crate::decode_doors as d;
    [
        ("NodeSnapshot", d::SNAPSHOT_FILE),
        ("NameRecord", d::NAME_REGISTRY_FILE),
        ("CompressedCopath", d::COMPRESSED_COPATH_VEC),
        ("guard_sample", d::TOR_GUARDS_DOC),
        ("serde_json::Value", d::JSON_VALUE),
        ("Option<Answer>", d::PRICE_RELAY_ANSWER), // `price_relay::parse`'s signature, in the window above its body read
    ]
    .iter()
    .find(|(tok, _)| window.contains(tok))
    .map(|(_, door)| *door)
}

/// The isolated realms of the ecosystem's sites (see the vendored-script rule in [`surface_holes`]).
pub struct IsolatedRealms {
    /// Realm documents and the scripts only they load, by repo-relative path.
    pub members: BTreeSet<String>,
    /// `(realm document, framing file)` for every `<iframe>` of a realm that lacks the opaque-origin sandbox.
    pub framed_unsandboxed: Vec<(String, String)>,
    site_files: Vec<(String, String)>, // (rel, text) of every non-vendored site file
}

impl IsolatedRealms {
    /// The non-realm files that load `vendored` (by its file name or its vendored directory), or `None` when every loader
    /// is realm code. A vendored file nobody names at all is loaded by its vendored neighbours (a bundle's own chunks):
    /// it follows its directory's loaders.
    #[must_use]
    pub fn loaders_outside(&self, vendored: &str) -> Option<Vec<String>> {
        let base = vendored.rsplit('/').next().unwrap_or(vendored);
        // the vendored root: the path up to and including the first vendored marker segment, e.g. `…/lib/monaco/`,
        // `…/vendor/three/`, `…/lib/vendor/`
        let root = vendored_root(vendored);
        let root_tail = root.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
        let names_it = |text: &str| {
            text.contains(base)
                || (!root_tail.is_empty() && (text.contains(&format!("{root_tail}/")) || text.contains(&format!("/{root_tail}'")) || text.contains(&format!("/{root_tail}\""))))
        };
        let outside: Vec<String> = self
            .site_files
            .iter()
            .filter(|(rel, text)| rel != vendored && names_it(text) && !self.members.contains(rel))
            .map(|(rel, _)| rel.clone())
            .collect();
        if outside.is_empty() {
            None
        } else {
            Some(outside)
        }
    }
}

fn vendored_root(rel: &str) -> String {
    for marker in ["/lib/vendor/", "/node_modules/", "/vendor/", "/monaco/", "/monaco"] {
        if let Some(i) = rel.find(marker) {
            let end = i + marker.len();
            let end = if marker.ends_with('/') { end } else { rel[end..].find('/').map_or(rel.len(), |k| end + k + 1) };
            // one more segment for the generic `/vendor/` (e.g. `vendor/three/`)
            if marker == "/vendor/" || marker == "/lib/vendor/" {
                if let Some(k) = rel[end..].find('/') {
                    return rel[..end + k + 1].to_string();
                }
            }
            return rel[..end].to_string();
        }
    }
    rel.rsplit_once('/').map_or_else(String::new, |(d, _)| format!("{d}/"))
}

/// Every isolated realm document (the marker meta, no wallet bridge) and the scripts only realm documents load.
#[must_use]
pub fn isolated_realms(eco: &Ecosystem) -> IsolatedRealms {
    let site_files: Vec<(String, String)> =
        eco.files.iter().filter(|f| f.part == "launchpad" || f.part == "wallet front end").map(|f| (f.rel.clone(), f.text.clone())).collect();
    let mut members: BTreeSet<String> = BTreeSet::new();
    let mut docs: Vec<String> = Vec::new();
    for (rel, text) in &site_files {
        if rel.ends_with(".html")
            && text.contains("name=\"monerousd-realm\"")
            && text.contains("content=\"isolated\"")
            && !text.contains("wallet-bridge")
            && !text.contains("monerousd:rpc")
        {
            members.insert(rel.clone());
            docs.push(rel.clone());
        }
    }
    // scripts a realm document loads by `<script src="X">`, resolved against the document's directory, are realm code
    // when NO non-realm file loads them too
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for doc in &docs {
        let dir = doc.rsplit_once('/').map_or("", |(d, _)| d);
        let text = &site_files.iter().find(|(r, _)| r == doc).map(|(_, t)| t.clone()).unwrap_or_default();
        for q in quoted(text) {
            if (q.ends_with(".js") || q.ends_with(".mjs")) && !q.contains("://") {
                let path = if let Some(p) = q.strip_prefix('/') { p.to_string() } else { format!("{dir}/{q}") };
                candidates.insert(path);
            }
        }
    }
    for c in candidates {
        let base = c.rsplit('/').next().unwrap_or(&c).to_string();
        let loaded_outside = site_files.iter().any(|(rel, text)| !members.contains(rel) && rel != &c && text.contains(&base) && !rel.ends_with(".html") || (!members.contains(rel) && rel.ends_with(".html") && text.contains(&base) && rel != &c));
        if !loaded_outside && site_files.iter().any(|(rel, _)| rel == &c) {
            members.insert(c);
        }
    }
    // every <iframe> naming a realm document must carry the opaque-origin sandbox
    let mut framed_unsandboxed = Vec::new();
    for doc in &docs {
        let base = doc.rsplit('/').next().unwrap_or(doc);
        for (rel, text) in &site_files {
            if rel == doc || !text.contains(base) {
                continue;
            }
            for (pos, _) in text.match_indices(base) {
                let window_start = text[..pos].rfind("<iframe").or_else(|| text[..pos].rfind("createElement('iframe')")).or_else(|| text[..pos].rfind("createElement(\"iframe\")"));
                let Some(ws) = window_start else { continue };
                if pos - ws > 2_000 {
                    continue; // not this frame's own attributes
                }
                let window_end = (pos + 2_000).min(text.len());
                let w = &text[ws..window_end];
                let sandboxed = (w.contains("sandbox=\"allow-scripts\"") || w.contains("'sandbox','allow-scripts'") || w.contains("\"sandbox\",\"allow-scripts\"") || w.contains("sandbox', 'allow-scripts'"))
                    && !w.contains("allow-same-origin");
                if !sandboxed {
                    framed_unsandboxed.push((doc.clone(), rel.clone()));
                }
                break;
            }
        }
    }
    IsolatedRealms { members, framed_unsandboxed, site_files }
}

pub fn surface_holes() -> (Vec<SurfaceHole>, Vec<String>) {
    let eco = ecosystem();
    let tests = test_index(&eco);
    let tok = test_tokens(&tests, &eco);
    let mut h: Vec<SurfaceHole> = Vec::new();
    let mut coverage: Vec<String> = Vec::new();
    for f in eco.files.iter().filter(|f| !f.parsed) {
        h.push(sh(0, UNMEASURED, "source file the census could not parse", f.rel.clone(), "a #[cfg(test)] item never closes: the file's shippable code after it is unscanned"));
    }
    let by_part = |p: &str| eco.files.iter().filter(|f| f.part == p).count();
    coverage.push(format!(
        "files: node {} · decider {} · wallet core {} · wallet front end {} · launchpad {} · upstream prover {} (counted) · vendored scripts {} · backups skipped {}",
        by_part("node"),
        by_part("decider"),
        by_part("wallet core"),
        by_part("wallet front end"),
        by_part("launchpad"),
        eco.upstream_prover_files,
        eco.vendored_scripts.len(),
        eco.backups_skipped
    ));
    coverage.push(format!("tests indexed: {} ({} adversarial, {} ignored)", tests.len(), tests.iter().filter(|t| t.adversarial).count(), tests.iter().filter(|t| t.ignored).count()));

    // 1. NODE RPC ROUTES
    let rs = routes(&eco);
    coverage.push(format!("node routes: {}", rs.len()));
    for (m, p, at) in &rs {
        let (any, adv) = tok.get(p.trim_end_matches('*'));
        if !adv {
            let tier = if m == "GET" { 1 } else { 0 };
            let why = if any { "exercised only by non-adversarial tests" } else { "no test names this route" };
            h.push(sh(tier, BLIND, "node route with no adversarial test", format!("{m} {p}"), format!("{why}; its door answers (proof, conservation, replay, bounded work, privacy of the answer) are unmeasured — {at}")));
        }
    }

    // 2. P2P WIRE MESSAGES
    let ws = wire_messages(&eco);
    coverage.push(format!("wire messages: {}", ws.len()));
    for (en, v, handlers) in &ws {
        let named = tok.get(&format!("{en}::{v}")).1 || handlers.iter().any(|hn| tok.get(hn).1);
        if !named {
            h.push(sh(wire_tier(v), BLIND, "peer message with no adversarial test", format!("{en}::{v}"), format!("handlers {handlers:?}: no adversarial test sends this message or calls its handler")));
        }
    }

    // 3. WALLET COMMANDS + 4. THE DAPP BRIDGE
    let cmds = wallet_commands(&eco);
    let core_fns = wallet_core_fns(&eco);
    coverage.push(format!("wallet commands: {}", cmds.len()));
    for (name, at, body) in &cmds {
        let reached = [name.clone(), format!("{name}_blocking"), name.trim_start_matches("dapp_provider_").to_string()]
            .iter()
            .any(|n| tok.get(n).0);
        if !reached {
            h.push(sh(command_tier(name), BLIND, "wallet command no test drives", name.clone(), format!("no wallet test, harness or journey reaches it — {at}")));
        }
        // DB-373 — EVERY registered command (any script that reaches `invoke` can call any of them, so a front-end prompt
        // gates nothing): a command that moves value, publishes or signs must reach the core's fail-closed approval; a
        // bridge read of private data must reach session consent. ONLY the fail-closed helpers count as a gate — the raw
        // prompt answered `Ok{authorized:false}` on a device without one, and `?` passed it (measured 2026-10-03).
        // The gate may sit in a callee: follow every wallet-core function the body calls, three levels deep.
        let reach = gate_reach(&core_fns, body, 3);
        let approved = reach.contains("require_user_approval(");
        let consented = approved || reach.contains("require_session_consent(");
        // "moves" is judged by REACH, not the name alone: the command posts to the node or reaches the spend primitive,
        // and either its name is a value verb or it reaches the spend primitive outright.
        let spends = reach.contains("wallet_send_atomic_blocking(") || reach.contains("submit_pq_tx");
        let posts = spends || reach.contains(".post(") || reach.contains("send_json(");
        // A name that says the command only READS, WATCHES, or credits the user's OWN wallet is not a value verb even
        // when it posts (a POST query, a merchant broadcast, a deposit's own mint). MEASURED 2026-10-03: without this,
        // `wallet_send_status`, `wallet_my_bond`, `wallet_await_payment`, `moneropay_ble_start_merchant`,
        // `wallet_register_clue` and `wallet_try_mint` read as unapproved value moves. A command that reaches the SPEND
        // primitive is a mover whatever its name says.
        let read_only_name = name.split('_').any(|t| READ_ONLY_TOKENS.contains(&t));
        let moves = posts && (spends || (has_verb(name, BRIDGE_MOVES) && !read_only_name));
        let reveals = name.starts_with("dapp_provider_") && !moves && has_any(name, BRIDGE_REVEALS);
        if moves && !approved {
            let cat = if name.starts_with("dapp_provider_") { "dapp bridge moves value or publishes with no user approval" } else { "wallet command moves value with no approval in the core" };
            h.push(sh(0, EXPLOIT, cat, name.clone(), format!("any script that reaches `invoke` calls it and the core asks nobody — {at}")));
        } else if reveals && !consented {
            h.push(sh(1, EXPLOIT, "dapp bridge reveals private wallet data with no user consent", name.clone(), format!("a framed page reads it silently (the borrowed shape: EIP-1102 connect consent) — {at}")));
        }
        if name.starts_with("dapp_provider_") {
            let lower = body.to_ascii_lowercase();
            let proxies = body.contains("path: String") || body.contains("path:String");
            // allowlisted ⇔ the body REFUSES (`return Err(`) and names the routes it admits (a quoted `/…` literal, or a
            // route-list constant) — a keyword in a comment is not an allowlist
            let names_routes = quoted(body).iter().any(|q| q.starts_with('/') && q.len() > 1) || body.contains("ALLOWED");
            let allowlisted = names_routes && body.contains("return Err(");
            let _ = &lower;
            if proxies && !allowlisted {
                h.push(sh(0, BLIND, "dapp bridge proxies ANY node route", name.clone(), format!("a framed page chooses the path and body and the wallet forwards it to its own node with no route allowlist — {at}")));
            }
        }
    }
    // DB-373 — a Tauri capability that grants IPC to a REMOTE origin hands that origin the wallet's commands directly,
    // with no JS bridge (and no origin check) in between. Only the user's own node (loopback) or an onion may be named.
    // MEASURED 2026-10-03: capabilities/dapp.json named clearnet `https://*.monerousd.org` for the transfer, letter,
    // directory, profile, token and node-proxy commands.
    let caps_dir = repo_root().join("monerousd-wallet-v2/src-tauri/capabilities");
    let mut caps_read = 0usize;
    if let Ok(rd) = fs::read_dir(&caps_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if is_backup(&p) || p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Ok(t) = fs::read_to_string(&p) else { continue };
            caps_read += 1;
            let Some(r) = t.find("\"remote\"") else { continue };
            let Some(u) = t[r..].find("\"urls\"") else { continue };
            let list = &t[r + u..];
            let list = &list[..list.find(']').map_or(list.len(), |e| e + 1)];
            for url in quoted(list).into_iter().filter(|q| q.contains("://")) {
                let host = url.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
                let local = host == "127.0.0.1" || host == "localhost" || host.starts_with('[') || host.ends_with(".onion");
                if !local {
                    let rel = p.strip_prefix(repo_root()).unwrap_or(&p).display().to_string();
                    h.push(sh(0, EXPLOIT, "Tauri capability grants wallet IPC to a remote clearnet origin", url.to_string(), format!("{rel}: a page served from (or a DNS hijack of) this host invokes the granted wallet commands directly")));
                }
            }
        }
    }
    coverage.push(format!("wallet Tauri capability files: {caps_read}"));
    for f in eco.files.iter().filter(|f| f.part == "wallet front end") {
        if let Some(at) = f.text.find("function _isDappOrigin") {
            let body = &f.text[at..at + f.text[at..].find("\n}").unwrap_or(0)];
            // only HOST-SHAPED literals are origins (a comment's apostrophes pair up into prose otherwise — measured)
            for host in quoted(body).into_iter().filter(|q| !q.is_empty() && q.chars().all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c))) {
                let local = host == "127.0.0.1" || host == "localhost" || host.ends_with(".onion") || host.starts_with('[');
                if !local && host.contains('.') {
                    h.push(sh(1, EXPLOIT, "dapp bridge trusts a clearnet origin", host.to_string(), format!("any page served from this host (or a hijack of its DNS) may call the wallet bridge — {}", f.rel)));
                }
            }
        }
    }

    // 5. DECODES OF OUTSIDE BYTES — the universe is `decode_sites` (shared with the decode-door replay pin,
    //    harness::fuzz::decode_doors_tests, B1 (ii) 2026-10-22); the hole scanner closes a site whose DOOR a green replay
    //    drove on the current source (the `decode-fuzz` coverage rows, holes.rs::fuzz_driven_decode_doors).
    let sites = decode_sites(&eco);
    for s in &sites {
        if s.lenient && s.consensus {
            h.push(sh(0, BLIND, "lenient decode in a consensus file", s.at.clone(), "trailing bytes are accepted, so one object has two encodings unless the caller binds the exact bytes (one consensus object, ONE encoding — use decode_exact)"));
        } else if !s.textually_fuzzed {
            let ty = if s.ty.is_empty() { "?" } else { s.ty.as_str() };
            let detail = match s.door {
                Some(d) => format!("type `{ty}` is in no fuzz corpus and no `decode-fuzz` row on the current source drives its door `{d}`: hostile bytes here are unmeasured (crash, allocation)"),
                None => format!("type `{ty}` is in no fuzz corpus and no door of decode_doors maps this site (add one): hostile bytes here are unmeasured (crash, allocation)"),
            };
            h.push(sh(3, BLIND, "decode of outside bytes no fuzzer reaches", s.at.clone(), detail));
        }
    }
    coverage.push(format!("decode sites: {}", sites.len()));

    // 6. DISK WRITES
    let approved = approved_writes();
    let mut writes = 0usize;
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        let shippable = f.shippable();
        let lines: Vec<&str> = shippable.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") || !disk_write_needles().iter().any(|w| line.contains(w)) {
                continue;
            }
            // ⛔ A `write_all` IS A DISK WRITE ONLY WHEN ITS FUNCTION OPENS A FILE (2026-10-04). The needle alone counted
            // every socket write — the sovereign host's HTTP responses, the daemon's `/get_info` probe (MEASURED: 12 of
            // the 75 rows in the user's list were TCP streams) — and a list the user cannot act on is not a list. The
            // function span (from its `fn` line to the next) must create or open a file, or the row is not a disk write.
            if line.contains(concat!(".write", "_all(")) && !write_all_on_a_file(&lines, n) {
                continue;
            }
            writes += 1;
            let ok = approved.iter().any(|(b, id)| b == f.base() && !id.is_empty() && f.shippable().contains(id.as_str()));
            if !ok {
                let tier = if has_any(f.base(), &["key", "vote_guard", "custody", "seal"]) { 2 } else { 3 };
                h.push(sh(tier, BLIND, "disk write with no user-approved bound", format!("{}:{}", f.rel, n + 1), "no line in user-approved-local-storage.txt covers it: its growth and what it stores are unmeasured"));
            }
        }
    }
    coverage.push(format!("disk-write sites: {writes}"));

    // 7. LOG LINES THAT INTERPOLATE A SENSITIVE NAME
    let mut logs = 0usize;
    for f in eco.files.iter() {
        for (n, line) in f.shippable().lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if let Some(w) = interpolated_sensitive(line) {
                logs += 1;
                let tier = if has_any(w, &["seed", "mnemonic", "secret", "key", "sk_", "_sk", "blind", "opening"]) { 2 } else { 1 };
                h.push(sh(tier, EXPLOIT, "log line prints a sensitive value", format!("{}:{}", f.rel, n + 1), format!("interpolates `{w}` into a log any reader of the log sees")));
            }
        }
    }
    coverage.push(format!("sensitive log lines: {logs}"));

    // 8. MEMORY-UNSAFE CODE
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        for (n, line) in f.shippable().lines().enumerate() {
            let t = line.trim_start();
            if !t.starts_with("//") && (line.contains("unsafe {") || line.contains("unsafe fn ") || line.contains("unsafe impl ")) {
                let tier = if has_any(f.base(), &["transport", "onion", "arti", "key", "pq", "serve", "main"]) { 2 } else { 3 };
                h.push(sh(tier, BLIND, "memory-unsafe code", format!("{}:{}", f.rel, n + 1), "memory safety rests on hand-checked code no test can certify"));
            }
        }
    }

    // 9. DEPENDENCIES
    let crates = locked_crates();
    coverage.push(format!("locked third-party crates: {}", crates.len()));
    let node_src: String = eco.files.iter().filter(|f| f.rel.ends_with(".rs")).map(|f| f.shippable()).collect::<Vec<_>>().join("\n");
    let mut seen = BTreeSet::new();
    for (lock, name, ver, rdeps) in &crates {
        if !seen.insert((name.clone(), ver.clone())) {
            continue;
        }
        let ident = name.replace('-', "_");
        let direct = names_crate(&node_src, &ident);
        if CLASSICAL_CRATES.contains(&name.as_str()) {
            // THE ONE CARVE-OUT (AGENTS.md §2 pillar 2): the external bridge's work on a FOREIGN chain that admits only its own
            // classical primitive, each such line marked `CLASSICAL-CRYPTO-EXEMPT: <reason>` (the no-classical-crypto guard's
            // contract). A direct use is an EXPLOIT only where a using line carries no marker on it or the line above; a crate
            // used only on marked lines is the audited carve-out, listed (BLIND) for review, never hidden. MEASURED 2026-11-03:
            // the three "USED DIRECTLY" rows were all read off `use`/`::` text alone, marker or not.
            let unmarked = if direct { unmarked_uses(&eco, &ident) } else { Vec::new() };
            let kind = if !unmarked.is_empty() { EXPLOIT } else { BLIND };
            let how = if !direct {
                String::new()
            } else if unmarked.is_empty() {
                "; used directly ONLY on CLASSICAL-CRYPTO-EXEMPT lines (the foreign-chain carve-out) — audit them".to_string()
            } else {
                format!("; USED DIRECTLY with no CLASSICAL-CRYPTO-EXEMPT marker at {}", unmarked.iter().take(4).cloned().collect::<Vec<_>>().join(", "))
            };
            h.push(sh(2, kind, "pre-quantum crypto in the dependency graph", format!("{name} {ver}"), format!("{lock}; pulled by {rdeps:?}{how}")));
        } else if TLS_CRATES.contains(&name.as_str()) {
            // ⭐ PROVEN ONION-ONLY (2026-10-28): Tor's own link layer is TLS (an OR connection is TLS to a relay — the onion
            // overlay's substrate, never a clearnet service), so a TLS crate that reaches the workspace ONLY through the
            // Tor stack (`tor-*`, `arti*`) offers no clearnet path. The lock graph is walked upward from the crate; a walk
            // that reaches a workspace member without passing a Tor crate is the clearnet path the row names.
            if tls_reaches_workspace_only_through_tor(lock, name) {
                continue;
            }
            h.push(sh(1, BLIND, "clearnet TLS stack in the dependency graph", format!("{name} {ver}"), format!("{lock}; pulled by {rdeps:?}: a clearnet connection path exists unless every caller is proven onion-only")));
        }
    }
    let adv_file = crate::harness::scratchpad_dir().join("dep-advisories.txt");
    let advisory_fresh = fs::metadata(&adv_file).and_then(|m| m.modified()).ok().is_some_and(|t| {
        [node_root().join("Cargo.lock"), repo_root().join("monerousd-wallet-v2/src-tauri/Cargo.lock")]
            .iter()
            .all(|l| fs::metadata(l).and_then(|m| m.modified()).map(|lt| lt <= t).unwrap_or(true))
    });
    if !advisory_fresh {
        h.push(sh(2, BLIND, "dependency advisories never scanned", "every locked crate", "no RustSec / OSV advisory scan ran against the current lockfiles (scratchpad/dep-advisories.txt absent or older than a lockfile)"));
    } else {
        for l in fs::read_to_string(&adv_file).unwrap_or_default().lines().filter(|l| l.starts_with("ID") || l.contains("RUSTSEC-")) {
            h.push(sh(2, EXPLOIT, "dependency with a published advisory", l.trim().to_string(), "scratchpad/dep-advisories.txt"));
        }
    }
    // ⭐ ISOLATED REALMS (2026-10-28). A vendored script is a hole when it shares a frame that can call the wallet bridge.
    // It is NOT one when every document or script that loads it is an ISOLATED REALM: an HTML document declaring
    // `<meta name="monerousd-realm" content="isolated">` that loads no wallet bridge and is framed by the app ONLY through
    // `<iframe … sandbox="allow-scripts">` (no `allow-same-origin`) — an opaque origin the browser keeps out of the app's
    // storage, scripting and the wallet's `event.source` check. A realm framed without that sandbox is its own hole.
    let realms = isolated_realms(&eco);
    for v in &eco.vendored_scripts {
        match realms.loaders_outside(v) {
            None => {} // loaded by isolated realm code only
            Some(outside) => h.push(sh(
                1,
                BLIND,
                "third-party script runs in an app frame unaudited",
                v.clone(),
                format!("vendored / minified code shares the frame that can call the wallet bridge (loaded by {})", outside.join(", ")),
            )),
        }
    }
    for (doc, by) in &realms.framed_unsandboxed {
        h.push(sh(1, BLIND, "isolated realm framed without a sandbox", doc.clone(), format!("{by} frames it without `sandbox=\"allow-scripts\"` (or with allow-same-origin), so its vendored code shares the app's origin")));
    }

    // 10. PRIMITIVE KNOWN-ANSWER TESTS
    for (prim, keys, tier) in [
        ("Poseidon2", &["poseidon"][..], 0u8),
        ("blake3", &["blake3"][..], 0),
        ("SHA3 / Keccak", &["sha3", "keccak"][..], 0),
        ("ML-KEM-768", &["ml_kem", "mlkem", "kyber", "pqkem", "kem"][..], 2),
        ("ML-DSA-65", &["ml_dsa", "mldsa", "dilithium", "pqauth"][..], 2),
    ] {
        let kat = tests.iter().any(|t| {
            let n = t.name.to_ascii_lowercase();
            let b = t.body.to_ascii_lowercase();
            (n.contains("kat") || n.contains("known_answer") || n.contains("test_vector") || n.contains("reference_vector") || n.contains("nist"))
                && keys.iter().any(|k| n.contains(k) || b.contains(k))
        });
        if !kat {
            h.push(sh(tier, BLIND, "primitive with no known-answer test", prim, "no test checks this implementation against the reference vectors: a wrong permutation or parameter set would pass every round-trip test"));
        }
    }

    // 11. SOURCE FILES NO TEST REACHES
    let fn_re = |text: &str| -> Vec<String> {
        let mut v = Vec::new();
        for (i, _) in text.match_indices("fn ") {
            if i > 0 && (text.as_bytes()[i - 1].is_ascii_alphanumeric() || text.as_bytes()[i - 1] == b'_') {
                continue;
            }
            let name: String = text[i + 3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if name.len() >= 6 && name != "default" && name != "fmt" {
                v.push(name);
            }
        }
        v
    };
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs") && !f.test_file) {
        let own_tests = tests.iter().any(|t| t.file == f.rel);
        let reached = own_tests || fn_re(f.shippable()).iter().any(|n| tok.get(n).0);
        if !reached {
            let s = f.shippable();
            let tier = if has_any(s, &["amount", "mint", "credit", "nullifier", "balance", "fee"]) {
                0
            } else if has_any(s, &["secret", "seed", "keypair", "sign("]) {
                2
            } else if has_any(s, &["eprintln", "serve", "query"]) {
                1
            } else {
                3
            };
            h.push(sh(tier, BLIND, "source file no test reaches", f.rel.clone(), format!("{} shippable lines; no test calls any function it defines", s.lines().count())));
        }
    }
    let app_tier = |name: &str, text: &str| -> u8 {
        if ["transfer", "swapExecute", "signAndBroadcast", "send", "order", "bond", "stake", "fill", "mint", "drip"].iter().any(|m| text.contains(&format!("rpc('{m}'")) || text.contains(&format!("rpc(\"{m}\"")))
            || name == "wallet front end"
        {
            0
        } else if text.contains("rpc('letter") || text.contains("rpc('profile") || text.contains("rpc('dir") {
            1
        } else {
            4
        }
    };
    let mut apps: BTreeMap<String, String> = BTreeMap::new();
    for f in eco.files.iter().filter(|f| f.part == "launchpad" || f.part == "wallet front end") {
        let app = if f.part == "launchpad" {
            f.rel.split("/sites/").nth(1).and_then(|s| s.split('/').next()).unwrap_or("?").to_string()
        } else {
            "wallet front end".to_string()
        };
        apps.entry(app).or_default().push_str(&f.text);
    }
    for (app, text) in &apps {
        h.push(sh(app_tier(app, text), BLIND, "app code no automated test exercises", app.clone(), "no test loads this bundle and drives it: its handling of amounts, floors, addresses and errors is unmeasured"));
    }

    // 18. WALLET CORE → NODE ROUTE PARITY: every route the wallet's Rust core calls (`format!("{base}/x")`, a quoted
    //     `"/x"` handed to an RPC helper) must be one the node serves.
    for f in eco.files.iter().filter(|f| f.part == "wallet core") {
        let mut seen_p = BTreeSet::new();
        for (n, line) in f.shippable().lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let mut called: Vec<String> = Vec::new();
            for lit in quoted(line) {
                // a URL: `{base}/x…` with the base FIRST in the literal, or `http://host/x…`
                let url_base = lit.starts_with('{') || lit.starts_with("http://") || lit.starts_with("https://");
                for (i, _) in lit.match_indices("}/").filter(|_| url_base) {
                    let rest = &lit[i + 1..];
                    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '/')).unwrap_or(rest.len());
                    if rest[end..].starts_with('.') {
                        continue; // `{uid}/org.monerousd.node` is a label, not a route
                    }
                    called.push(rest[..end].trim_end_matches('/').to_string());
                }
                // a literal ending in `/` is a PREFIX the code tests against (an allowlist), not a route it calls
                if lit.starts_with('/') && !lit.ends_with('/') && (line.contains("rpc") || line.contains("get(") || line.contains("post(")) {
                    let end = lit.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '/')).unwrap_or(lit.len());
                    called.push(lit[..end].trim_end_matches('/').to_string());
                }
            }
            for p in called.into_iter().filter(|p| p.len() > 1 && p[1..].starts_with(|c: char| c.is_ascii_lowercase())) {
                if !served(&rs, &p) && seen_p.insert(p.clone()) {
                    h.push(sh(4, EXPLOIT, "wallet core calls a node route that does not exist", format!("{}:{}", f.rel, n + 1), p));
                }
            }
        }
    }

    // 13. HTML INJECTION SINKS — every innerHTML / outerHTML / insertAdjacentHTML / document.write fed by an interpolation
    //     that no escape helper or numeric cast wraps. In the wallet (CSP checked below) an injected script reaches every
    //     wallet command; in a framed app it reaches the bridge.
    let mut sinks = 0usize;
    for f in eco.files.iter().filter(|f| f.part == "wallet front end" || f.part == "launchpad") {
        let (n_sinks, bad_sinks) = html_sink_holes(&f.text);
        sinks += n_sinks;
        for (line, bad) in bad_sinks {
            h.push(sh(0, BLIND, "HTML sink fed by an unescaped value", format!("{}:{}", f.rel, line), format!("`{}` reaches the page as HTML: if it can carry outside text (a name, a letter, a token, a server reply) it is script injection", bad.chars().take(60).collect::<String>())));
        }
    }
    coverage.push(format!("HTML sinks: {sinks}"));

    // 14. THE WALLET WEBVIEW'S CONTENT SECURITY POLICY
    let conf = repo_root().join("monerousd-wallet-v2/src-tauri/tauri.conf.json");
    match fs::read_to_string(&conf) {
        Ok(c) => {
            let csp_null = c.contains("\"csp\": null") || c.contains("\"csp\":null") || !c.contains("\"csp\"");
            if csp_null {
                h.push(sh(0, EXPLOIT, "wallet webview has no Content Security Policy", "monerousd-wallet-v2/src-tauri/tauri.conf.json", format!("csp is null{}: one injected script anywhere in the front end runs with every wallet command in reach", if c.contains("\"withGlobalTauri\": true") { " and withGlobalTauri is on" } else { "" })));
            }
            // a policy that exists but still runs injected script is no policy: no eval, no inline script, no remote
            // script origin
            if let Some(sp) = c.find("\"script-src\"") {
                let line = c[sp..].lines().next().unwrap_or("");
                if line.contains("unsafe-inline") || line.contains("unsafe-eval") || line.contains("http") || line.contains('*') {
                    h.push(sh(0, EXPLOIT, "wallet CSP still runs injected script", "monerousd-wallet-v2/src-tauri/tauri.conf.json", format!("script-src allows more than the bundle: {}", line.trim())));
                }
            } else if !csp_null {
                h.push(sh(0, EXPLOIT, "wallet CSP still runs injected script", "monerousd-wallet-v2/src-tauri/tauri.conf.json", "no script-src directive"));
            }
            if c.contains("dangerousRemoteDomainIpcAccess") || c.contains("dangerousDisableAssetCspModification") {
                h.push(sh(0, EXPLOIT, "wallet webview enables a dangerous IPC option", "tauri.conf.json", "a remote domain or asset CSP override can reach the wallet's commands"));
            }
        }
        Err(_) => h.push(sh(0, UNMEASURED, "wallet webview configuration unread", "tauri.conf.json", "the CSP and IPC settings could not be read")),
    }

    // 15. LOCAL HTTP SERVERS THAT ANSWER ANY WEB PAGE. Binding to the local interface keeps the network out, not the
    //     user's own browser: without a Host / Origin check, any site the user visits can POST to the node (CSRF) and,
    //     through DNS rebinding, read its answers.
    //     TWO-PARTY-REVIEWED: this is a STATIC SOURCE SCAN — it constructs no endpoint and tests no capability; it reads
    //     the server's source for a request-origin check. The two parties of the attack (a hostile page, the node) are
    //     exercised by the adversarial pin the fix lands with.
    for (srv, label) in [("monerousd-node-zkdag/src/rpc_http.rs", "node RPC"), ("monerousd-node-zkdag/src/sovereign.rs", "sovereign site server")] {
        if let Some(f) = file(&eco, srv) {
            let s = f.shippable().to_ascii_lowercase();
            let host_checked = s.contains("\"host\"") && s.contains("header");
            // DB-374's shared admission (`local_origin::admit`, pinned by `db374_*`) is the check both servers run
            let checks = host_checked || s.contains("\"origin\"") || s.contains("sec-fetch-site") || s.contains("local_origin::admit(");
            if !checks {
                h.push(sh(0, EXPLOIT, "local HTTP server answers any web page", label, format!("{srv}: no Host / Origin / Sec-Fetch-Site check — CSRF from any visited page triggers its POST routes and DNS rebinding reads its GET routes")));
            }
        }
    }

    // 16. INSTALLER INTEGRITY — a binary a user downloads must carry a published hash or signature.
    for f in eco.files.iter().filter(|f| f.rel.contains("/sites/monerousd-installers/")) {
        let l = f.text.to_ascii_lowercase();
        let ships = [".dmg", ".exe", ".msi", ".appimage", ".deb", ".rpm", ".zip", ".tar.gz", ".apk", ".ipa"].iter().any(|x| l.contains(x));
        let verified = ["sha256", "sha3", "blake3", "checksum", ".sig", "signature", "ml-dsa"].iter().any(|x| l.contains(x));
        if ships && !verified {
            h.push(sh(0, EXPLOIT, "installer offers a binary with no published hash or signature", f.rel.clone(), "a swapped download (mirror, DNS, CDN) installs a wallet that steals the seed; nothing lets the user detect it"));
        }
    }

    // 17. PRODUCTION SWITCHES — every environment variable shippable code reads; a name that weakens, skips, forces or
    //     pauses is a gate switch whose production effect is unmeasured (TESTNET == PRODUCTION).
    let mut envs: BTreeMap<String, String> = BTreeMap::new();
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs") && f.part != "decider") {
        for (n, line) in f.shippable().lines().enumerate() {
            for (i, _) in line.match_indices("env::var") {
                if let Some(q) = quoted(&line[i..]).first() {
                    if !q.is_empty() && q.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                        envs.entry((*q).to_string()).or_insert_with(|| format!("{}:{}", f.rel, n + 1));
                    }
                }
            }
        }
    }
    coverage.push(format!("environment switches read by shippable code: {}", envs.len()));
    for (e, at) in &envs {
        if ["SKIP", "DISABLE", "PAUSE", "BYPASS", "UNSAFE", "INSECURE", "NO_", "FORCE", "FAKE", "DEV", "ALLOW", "LEGACY", "OVERRIDE", "TRUST"].iter().any(|w| e.contains(w)) {
            h.push(sh(0, BLIND, "production switch that can weaken behaviour", e.clone(), format!("read at {at}: what it changes in a production node is unmeasured")));
        }
    }

    // 19. RELEASE ARITHMETIC — without `overflow-checks = true` in `[profile.release]`, an integer overflow in value math
    //     WRAPS silently in the shipped binary (only explicit checked_/saturating_ math is safe).
    for (toml, label) in [
        (node_root().join("Cargo.toml"), "node"),
        (repo_root().join("monerousd-wallet-v2/src-tauri/Cargo.toml"), "wallet"),
        (node_root().join("vendor/Plonky3/Cargo.toml"), "prover workspace"),
    ] {
        let t = fs::read_to_string(&toml).unwrap_or_default();
        let release = t.split("[profile.release]").nth(1).map(|r| r.split("\n[").next().unwrap_or(r)).unwrap_or("");
        if !release.replace(' ', "").contains("overflow-checks=true") {
            h.push(sh(0, BLIND, "release build wraps integer overflow silently", label, format!("{}: no `overflow-checks = true` under [profile.release] — an overflowing amount, fee or index wraps instead of refusing", toml.strip_prefix(repo_root()).unwrap_or(&toml).display())));
        }
    }

    // 20. THE WALLET'S SECRETS AT REST — the custody census covers the secrets a NODE holds; a wallet seed / key file that
    //     no custody row names is unaudited (owner-only? recoverable? never leaves?).
    let custody_src = eco.files.iter().find(|f| f.rel.ends_with("src/harness/custody.rs")).map(|f| f.text.as_str()).unwrap_or("");
    if !custody_src.contains("monerousd-wallet-v2") {
        let wallet_secret_writes: Vec<String> = eco
            .files
            .iter()
            .filter(|f| f.part == "wallet core")
            .flat_map(|f| {
                f.shippable()
                    .lines()
                    .enumerate()
                    .filter(|(_, l)| disk_write_needles().iter().any(|w| l.contains(w)) && has_any(l, &["seed", "key", "secret", "mnemonic", "keystore"]))
                    .map(|(n, _)| format!("{}:{}", f.rel, n + 1))
                    .collect::<Vec<_>>()
            })
            .collect();
        h.push(sh(2, BLIND, "wallet secrets at rest in no custody census", "monerousd-wallet-v2", format!("the custody census names no wallet file; secret-bearing writes: {wallet_secret_writes:?}")));
    }

    // 21. PANICS IN SHIPPABLE CODE — a panic reached by outside input is a crash (node) or a frozen wallet; a todo! /
    //     unimplemented! is an unfinished path. The decider is scanned in its VERIFIER files (hostile proof bytes).
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs") && !f.test_file && (f.part != "decider" || f.base().contains("verif") || f.base().contains("door"))) {
        for (n, line) in f.shippable().lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            // the needles are built in parts: they are search patterns, and a literal stub macro name here reads as one
            let unfinished = line.contains(concat!("to", "do!(")) || line.contains(concat!("unimpl", "emented!("));
            if unfinished || line.contains(".unwrap()") || line.contains(".expect(") || line.contains("panic!(") || line.contains("unreachable!(") {
                h.push(sh(if unfinished { 0 } else { 3 }, BLIND, if unfinished { "unfinished path in shippable code" } else { "panic in shippable code" }, format!("{}:{}", f.rel, n + 1), t.chars().take(110).collect::<String>()));
            }
        }
    }

    // 22. COMMAND-LINE SWITCHES — a node or wallet flag whose name weakens, skips, forces or trusts.
    for f in eco.files.iter().filter(|f| f.rel.ends_with("/main.rs") && !f.test_file) {
        for (n, line) in f.shippable().lines().enumerate() {
            for q in quoted(line).into_iter().filter(|q| q.starts_with("--") && q.len() > 3) {
                let up = q.to_ascii_uppercase();
                if ["SKIP", "DISABLE", "NO-", "BYPASS", "UNSAFE", "INSECURE", "FORCE", "TRUST", "DEV", "FAKE", "ALLOW"].iter().any(|w| up.contains(w)) {
                    h.push(sh(0, BLIND, "command-line switch that can weaken behaviour", q.to_string(), format!("{}:{}: what it changes in production is unmeasured", f.rel, n + 1)));
                }
            }
        }
    }

    // 24. EVERY PIN WHOSE LATEST RECORDED RUN IS RED — whichever run recorded it (lane_run's pin ledger), in any crate.
    //     A red already listed in scratchpad/known-reds.txt is reported there, not twice.
    //     A red whose test no longer exists in the tree is a claim the tree no longer makes (renamed or retired): it is listed as
    //     measurement debt, never a hole. MEASURED 2026-11-03: 15 of the 115 latest-red tests named no `fn` anywhere in the tree.
    let known_reds = fs::read_to_string(crate::harness::scratchpad_dir().join("known-reds.txt")).unwrap_or_default();
    for (path, (krate, verdict)) in latest_pin_verdicts() {
        let last = path.rsplit("::").next().unwrap_or(&path).to_string();
        if verdict == "FAILED" && !known_reds.contains(&last) {
            let needle = format!("fn {last}(");
            if !eco.files.iter().any(|f| f.text.contains(&needle)) {
                h.push(sh(0, UNMEASURED, "red pin no longer in the tree", format!("{krate}: {path}"), "its latest recorded run is red, but no test of that name exists any more"));
                continue;
            }
            h.push(sh(0, EXPLOIT, "pin RED in its latest recorded run", format!("{krate}: {path}"), "scratchpad/pin-results.tsv — a red pin is a claim the tree currently fails"));
        }
    }

    // 25. HOLLOW PINS — an asserting, zero-argument fn in a TEST region with no test attribute that nothing calls never
    //     runs, while its name and doc read as proof (the charter's own forbidden trap). And a fn carrying TWO test
    //     attributes: the stray one usually belongs to a neighbour left hollow. MEASURED 2026-10-03:
    //     `value_creation::every_local_note_minting_function_is_in_the_census` had no attribute — its `#[test]` was
    //     stacked on the next test.
    let all_rust: String = eco.files.iter().filter(|f| f.rel.ends_with(".rs")).map(|f| f.text.as_str()).collect::<Vec<_>>().join("\n");
    let mut hollow = 0usize;
    for f in eco.files.iter().filter(|f| f.rel.ends_with(".rs")) {
        for (line, name, stacked) in hollow_pins(&f.text, &f.ship, f.test_file, &all_rust) {
            hollow += 1;
            if stacked {
                // hygiene: measured 2026-10-03, all nine were a doc comment inserted between two attributes of ONE fn
                // (no neighbour lost its own); a neighbour that DID lose one is caught by the hollow-pin rule itself
                h.push(sh(4, EXPLOIT, "duplicate test attribute on one fn (hygiene)", format!("{}:{line} {name}", f.rel), "two `#[test]` on one function — remove the stray one"));
            } else {
                h.push(sh(0, UNMEASURED, "hollow pin: an asserting test fn that never runs", format!("{}:{line} {name}", f.rel), "no #[test] attribute and nothing calls it — it has never run, whatever its name and doc claim"));
            }
        }
    }
    coverage.push(format!("hollow pins / stacked test attributes: {hollow}"));

    // 23. INSTRUMENTS THIS SCANNER DOES NOT HAVE — each is a whole class it cannot see, so each is a hole until built.
    h.push(sh(2, BLIND, "instrument missing: constant-time census", "secret-dependent branches and memory access", "no census measures whether wallet / prover code branches or indexes on a secret (timing side channel)"));

    // 12. CENSUS CLAIMS — every CLOSED row must cite a real #[test] whose latest recorded run passed.
    let results = pin_results();
    let test_names: HashMap<&str, &TestFn> = tests.iter().map(|t| (t.name.as_str(), t)).collect();
    let all_fns: BTreeSet<String> = eco.files.iter().filter(|f| f.rel.ends_with(".rs")).flat_map(|f| fn_re(&f.text)).collect();
    let journey_passed = crate::harness::e2e_claims::real_node_pins_whose_latest_run_passed();
    let mut audit = |tier: u8, census: &'static str, row: String, text: String| {
        // a row's OWN name is not a citation (MEASURED: `Serve::order_book_membership_bind` read as "a pin that exists
        // nowhere" because its name is pin-shaped — holes-20261028-214053.log)
        let own = row.rsplit("::").next().unwrap_or(&row).to_string();
        let cited: BTreeSet<String> = pin_like(&text).into_iter().filter(|c| *c != own).collect();
        let pins: Vec<&String> = cited.iter().filter(|c| test_names.contains_key(c.as_str())).collect();
        for c in cited.iter().filter(|c| !all_fns.contains(*c) && !test_names.contains_key(c.as_str())) {
            h.push(sh(tier, UNMEASURED, "census row cites a pin that exists nowhere", format!("{census}: {row}"), c.clone()));
        }
        if pins.is_empty() {
            h.push(sh(tier, UNMEASURED, "census row closed by declaration", format!("{census}: {row}"), "it is called closed, but cites no #[test] that measures it"));
            return;
        }
        for p in pins {
            let t = test_names[p.as_str()];
            let measured = if t.ignored { journey_passed(p) } else { results.get(p.as_str()).is_some_and(|v| v == "ok") };
            if !measured {
                let why = match results.get(p.as_str()) {
                    Some(v) => format!("its latest recorded run is {v}"),
                    None if t.ignored => "it is #[ignore] and the journey ledger holds no passing run".to_string(),
                    None => "no run of it is recorded (scratchpad/pin-results.tsv)".to_string(),
                };
                h.push(sh(tier, UNMEASURED, "census row's pin has no recorded passing run", format!("{census}: {row}"), format!("{p}: {why}")));
            }
        }
    };
    use crate::harness::{custody, e2e_claims, privacy, rogue_census, value_creation};
    for s in value_creation::SITES.iter().filter(|s| s.is_closed()) {
        audit(0, "value-creation", s.name.to_string(), format!("{s:?}"));
    }
    for s in privacy::SURFACES.iter().filter(|s| s.is_closed()) {
        audit(1, "privacy", s.name.to_string(), format!("{s:?}"));
    }
    for c in custody::SECRETS.iter().filter(|c| c.open() == 0) {
        audit(2, "custody", c.name.to_string(), format!("{c:?}"));
    }
    for (class, attack, cell) in rogue_census::CELLS {
        if let rogue_census::Cell::Pinned(pin) = cell {
            audit(0, "rogue-role", format!("{class} × {attack}"), (*pin).to_string());
        }
    }
    for (site, cell) in value_creation::DESTRUCTION_BY_TRANSITION {
        if let rogue_census::Cell::Pinned(pin) = cell {
            audit(0, "value-destruction", (*site).to_string(), (*pin).to_string());
        }
    }
    for (class, m) in e2e_claims::VALUE_CLASSES {
        match m {
            e2e_claims::Moved::CrossNode(pin) | e2e_claims::Moved::RealNodes(pin) => audit(0, "value-class", (*class).to_string(), (*pin).to_string()),
            _ => {}
        }
    }
    coverage.push(format!("pin results recorded: {}", results.len()));
    (h, coverage)
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    /// A value verb is a WORD of the command's name: `repayment` is not `pay`, while `unbond`, `sendall` and a multi-word verb
    /// still read as movers. RED-first on the substring rule (it read `wallet_repayment_pot` as a pay).
    /// TWO-PARTY-REVIEWED: a classifier of command NAMES inside the hole scanner — no value crosses any boundary here; the
    /// commands it classifies are driven two-party by their own journeys.
    #[test]
    fn a_value_verb_is_a_word_of_the_name_not_a_substring_of_another_word() {
        use super::{has_verb, BRIDGE_MOVES};
        assert!(!has_verb("wallet_repayment_pot", BRIDGE_MOVES), "a read of the pot's figures is not a pay");
        for mover in ["wallet_send", "wallet_sendall", "wallet_unbond", "wallet_unstake", "dapp_provider_swap_execute", "wallet_pot_pay"] {
            assert!(has_verb(mover, BRIDGE_MOVES), "{mover} moves value");
        }
    }

    /// THE ONE LEDGER READER is armed: a row on a deleted lane branch is dropped; a `detached` (certify) row counts and, being
    /// newer, overrides a live-branch FAILED; a newer row appended BEFORE an older one (concurrent lanes) still wins by timestamp;
    /// a FAILED detached row newer than a live-branch ok is a red, not hidden. RED-first 2026-10-27: the old filter failed
    /// the second and fourth claims (14 stale reds listed, 12 real reds hidden).
    #[test]
    fn the_pin_ledger_reader_counts_detached_rows_and_orders_by_timestamp_not_file_order() {
        use super::{ledger_tree_exists, parse_pin_ledger};
        let live: std::collections::BTreeSet<String> = ["main", "lane/mech"].iter().map(|s| s.to_string()).collect();
        assert!(ledger_tree_exists("", &live) && ledger_tree_exists("detached", &live) && ledger_tree_exists("farm", &live));
        assert!(ledger_tree_exists("lane/mech", &live) && !ledger_tree_exists("lane/archived", &live));
        let text = "\
2026-10-24T22:53:03\tnode\tm::tests::a_planted_stale_red\tFAILED\tbd1ead8f\tlane/mech
2026-10-26T07:05:44\tnode\tm::tests::a_planted_stale_red\tok\t38954c15\tdetached
2026-10-26T07:05:44\tnode\tm::tests::a_planted_hidden_red\tok\t38954c15\tlane/mech
2026-10-27T03:01:25\tnode\tm::tests::a_planted_hidden_red\tFAILED\t0fc837f1\tdetached
2026-10-27T02:00:00\tnode\tm::tests::a_planted_out_of_order\tok\t?\t
2026-10-27T01:00:00\tnode\tm::tests::a_planted_out_of_order\tFAILED\t?\t
2026-10-27T03:00:00\tnode\tm::tests::a_planted_deleted_lane_red\tFAILED\t?\tlane/archived
2026-10-20T00:00:00\tnode\tm::tests::a_planted_deleted_lane_red\tok\t?\tmain
";
        let m = parse_pin_ledger(text, &live);
        assert_eq!(m["m::tests::a_planted_stale_red"].verdict, "ok", "the newer detached (certify) pass is the latest verdict");
        assert_eq!(m["m::tests::a_planted_hidden_red"].verdict, "FAILED", "a newer detached FAILED is a red, never hidden");
        assert_eq!(m["m::tests::a_planted_out_of_order"].verdict, "ok", "newest by timestamp, not by file order");
        assert_eq!(m["m::tests::a_planted_deleted_lane_red"].verdict, "ok", "a deleted lane's row is not a verdict about this tree");
        assert_eq!(m["m::tests::a_planted_stale_red"].short(), "a_planted_stale_red");
    }

    use super::*;

    /// CALIBRATION: every universe reads non-empty (an unread universe would print "no holes").
    #[test]
    fn surface_census_reads_every_universe() {
        let eco = ecosystem();
        for part in ["node", "decider", "wallet core", "wallet front end", "launchpad"] {
            assert!(eco.files.iter().any(|f| f.part == part), "part `{part}` unread");
        }
        assert!(routes(&eco).len() >= 50, "route universe unread");
        assert!(wire_messages(&eco).len() >= 30, "wire universe unread");
        assert!(wallet_commands(&eco).len() >= 30, "command universe unread");
        assert!(test_index(&eco).len() >= 500, "test index unread");
        assert!(!locked_crates().is_empty(), "lockfiles unread");
    }

    /// CALIBRATION: each check fires on a planted defect.
    #[test]
    fn surface_census_checks_fire_on_planted_defects() {
        assert_eq!(interpolated_sensitive("eprintln!(\"spent {nf_hex}\");"), Some("nf_hex"));
        assert_eq!(interpolated_sensitive("eprintln!(\"note amount {}\", amount);"), Some("amount"));
        assert_eq!(interpolated_sensitive("eprintln!(\"amount refused\");"), None, "a word in the literal is not a value");
        assert_eq!(interpolated_sensitive("eprintln!(\"could not persist the seed to {}\", seed_path.display());"), None, "a path is not a seed");
        assert_eq!(interpolated_sensitive("println!(\"seed line {seed_line}\");"), None, "a peer's public seed line is not a seed");
        assert_eq!(interpolated_sensitive("eprintln!(\"gate {}: {}\", 3, \"let x = f(&usdm_nullifier)\");"), None, "code quoted in a literal is not a value");
        assert_eq!(interpolated_sensitive("eprintln!(\"burn {}\", h32(&usdm_nullifier));"), Some("usdm_nullifier"));
        // HTML sinks: escaped, numeric, literal and condition-only values are safe; a raw value is not
        for safe in ["H.escapeHtml(e && e.message)", "VERIFIED_NFTS.length", "inPool ? 'yes' : 'no'", "spreadPct > 0 ? spreadPct.toFixed(2) + '%' : '\u{2014}'", "'\\u2026'"] {
            assert!(expr_safe(safe), "{safe} judged unsafe");
        }
        for unsafe_ in ["name", "'<b>' + name + '</b>'", "ok ? user.bio : ''"] {
            assert!(!expr_safe(unsafe_), "{unsafe_} judged safe");
        }
        assert_eq!(unescaped_interpolation("`<td>${row.memo}</td>`;").as_deref(), Some("row.memo"));
        // an escaped quote and a multibyte character inside a literal (measured panic, 2026-10-03)
        assert!(expr_safe("'You\\'ll receive <b>\u{2248} ' + n.toLocaleString() + '</b>'"));
        assert_eq!(quoted("x('a\\'b', \"c\")"), vec!["a\\'b", "c"]);
        assert_eq!(unescaped_interpolation("`<td>${escapeHtml(row.memo)}</td>`;"), None);
        // HOLLOW PINS: an asserting test fn with no attribute that nothing calls fires; a real pin, a called helper and
        // a fn with two stacked attributes are told apart (planted 2026-10-03 after value_creation's hollow census pin)
        let planted = "mod t {\n    #[test]\n    fn a_real_pin_runs() {\n        assert!(true);\n    }\n\n    fn a_hollow_census_pin() {\n        assert!(false);\n    }\n\n    fn a_called_helper() {\n        assert!(true);\n    }\n\n    #[test]\n    #[test]\n    fn a_doubly_marked() {\n        assert!(true);\n    }\n\n    #[test] fn one_liner_a() { assert!(true) }\n    #[test] fn one_liner_b() { assert!(true) }\n    #[test]\n    fn below_one_liners() {\n        assert!(true);\n    }\n}\n";
        let all = format!("{planted}\nfn caller() {{ a_called_helper(); }}\n");
        let found = hollow_pins(planted, &" ".repeat(planted.len()), true, &all);
        let names: Vec<(&str, bool)> = found.iter().map(|(_, n, s)| (n.as_str(), *s)).collect();
        assert_eq!(names, vec![("a_hollow_census_pin", false), ("a_doubly_marked", true)], "hollow-pin detector: {found:?}");
        // a gate that sits in a CALLEE counts; a body that reaches no gate does not
        let mut fns = HashMap::new();
        fns.insert("approve_blocking".to_string(), "fn approve_blocking() { wallet_biometric_auth_blocking() }".to_string());
        fns.insert("do_swap".to_string(), "fn do_swap() { approve_blocking(); }".to_string());
        assert!(gate_reach(&fns, "fn cmd() { do_swap(); }", 2).contains("biometric"));
        assert!(!gate_reach(&fns, "fn cmd() { build(); }", 2).contains("biometric"));
        assert!(pin_like("pin a_peer_refuses_a_forged_fill_from_a_rogue_producer").contains("a_peer_refuses_a_forged_fill_from_a_rogue_producer"));
        assert_eq!(test_items("fn a(){}\n#[cfg(test)]\nfn helper(){}\n#[cfg(test)]\nmod tests {}\n").0, vec![(9, 35), (36, 61)]);
        assert!(!test_items("#[cfg(test)]\nmod t { fn x() {\n").2, "an unclosed test item must read as UNPARSED");
        // an INLINE test module mid-file (the wallet's shape): the code after it stays shippable, and a brace inside a
        // string, a char or a comment does not end the module early
        let src = "fn a(){}\n#[cfg(test)]\nmod t { fn x(){ let s = \"}\"; let c = '}'; /* } */ } }\nfn b(){}\n";
        let (r, _, ok) = test_items(src);
        assert!(ok);
        assert_eq!(r.len(), 1);
        assert!(src[r[0].1..].contains("fn b(){}"), "code after an inline test module must stay shippable: {r:?}");
        assert_eq!(test_items("#[cfg(test)]\nmod test_standard;\n").1, vec!["test_standard".to_string()]);
        // THE TEST-FAMILY GATES (4bad001): `#[cfg(all(test, feature = "pins-node"))]` is a test region exactly like
        // `#[cfg(test)]`; `any(test, feature = "x")` ships under the feature and stays shippable (planted 2026-10-22
        // after the register read 4,436 holes with 3,242 "panic in shippable code" inside the family-gated modules)
        assert_eq!(test_items("fn a(){}\n#[cfg(all(test, feature = \"pins-node\"))]\nmod pins {}\nfn b(){}\n").0, vec![(9, 61)]);
        assert_eq!(test_items("#[cfg(all(feature = \"pins-core\", test))]\nmod t;\n").1, vec!["t".to_string()]);
        assert!(test_items("#[cfg(any(test, feature = \"bridge-test-oracle\"))]\nfn f(){}\n").0.is_empty(), "any(test, …) ships under the feature");
        assert!(test_items("#[cfg(not(test))]\nfn f(){}\n#[cfg(feature = \"x\")]\nfn g(){}\n").0.is_empty(), "not(test) and a feature gate are shippable");
        assert!(test_only_predicate("all(test, not(feature = \"a\"), feature = \"b\")"));
        assert!(!test_only_predicate("all(feature = \"a\", any(test, feature = \"b\"))"));
        let mut t = Tokens(HashMap::new());
        index_text(&mut t, "let r = get(\"http://127.0.0.1:27780/get_info?x=1\");", true);
        assert_eq!(t.get("/get_info"), (true, true));
        assert_eq!(command_tier("dapp_provider_transfer"), 0);
        assert_eq!(command_tier("wallet_export_seed"), 2);
    }

    /// ⭐ THE LENIENT-DECODE CLASS, as a pin (2026-10-05): the scanner's row "lenient decode in a consensus file" was closed
    /// at EVERY shippable site of the node crate by `chain_object::decode_exact` (one shared helper, §9.5), and this pin keeps
    /// the whole crate closed — a re-added `postcard::from_bytes` / `bincode::deserialize` anywhere shippable is RED here.
    /// `persist*` is the one exception: the snapshot door decodes by version trial and is pinned by the restart suite.
    /// RED-FIRST: 45 sites on 2026-10-05 before the swap.
    #[test]
    fn no_shippable_decode_in_the_node_accepts_trailing_bytes() {
        let eco = ecosystem();
        let mut lenient = Vec::new();
        for f in eco.files.iter().filter(|f| f.part == "node" && f.rel.ends_with(".rs") && !f.base().starts_with("persist")) {
            for (n, line) in f.shippable().lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("pub fn decode_exact") {
                    continue;
                }
                if line.contains("postcard::from_bytes") || line.contains("bincode::deserialize") {
                    lenient.push(format!("{}:{}", f.rel, n + 1));
                }
            }
        }
        assert!(lenient.is_empty(), "lenient decoders — one object, ONE encoding: use chain_object::decode_exact at {lenient:?}");
    }

    /// CALIBRATION (2026-10-05, the HTML-sink CLASS): a sink fed by a LOCAL helper is judged by the helper's returns — a
    /// raw interpolation inside the helper still fires (it never did before: the old rule refused the call and looked no
    /// further), an escaped one closes; a literal table closes, a table with a value does not; a single-assignment local
    /// closes by its initializer, a `+=` local refuses; a cycle refuses; `xs.map(helper).join('')` follows the helper.
    #[test]
    fn html_sinks_fed_by_local_helpers_are_judged_by_what_the_helper_returns() {
        let fired = |text: &str| html_sink_holes(text).1.into_iter().map(|(_, b)| b).collect::<Vec<_>>();
        assert_eq!(fired("function card(p) {\n  return `<b>${p.name}</b>`;\n}\nel.innerHTML = card(p);\n"), vec!["card(p)".to_string()], "a raw value INSIDE the helper fires (reported at the sink)");
        assert_eq!(fired("function card(p) {\n  return `<b>${esc(p.name)}</b>`;\n}\nel.innerHTML = card(p);\n"), Vec::<String>::new(), "an escaped helper closes");
        assert_eq!(fired("const card = (p) => `<b>${esc(p.name)}</b>`;\nel.innerHTML = rows.map(card).join('');\n"), Vec::<String>::new(), "map→join over an escaped arrow helper closes");
        assert_eq!(fired("const card = (p) => `<b>${p.name}</b>`;\nel.innerHTML = rows.map(card).join('');\n"), vec!["rows.map(card).join('')".to_string()], "map→join over a raw arrow helper fires");
        assert_eq!(fired("el.innerHTML = rows.map((r) => { const t = esc(r.a); return `<i>${t}</i>`; }).join('');\n"), Vec::<String>::new(), "a block arrow is judged by its return and its single-assignment local");
        assert_eq!(fired("el.innerHTML = rows.map((r) => { let t = esc(r.a); t += r.b; return `<i>${t}</i>`; }).join('');\n"), vec!["t".to_string()], "a `+=` local refuses");
        assert_eq!(fired("const ICON = { ok: '<i>✓</i>', warn: `<i>!</i>` };\nel.innerHTML = ICON[kind];\n"), Vec::<String>::new(), "a literal table closes");
        assert_eq!(fired("const ICON = { ok: '<i>✓</i>', warn: label };\nel.innerHTML = ICON[kind];\n"), vec!["ICON[kind]".to_string()], "a table with a raw value fires");
        assert_eq!(fired("function a(x) { return b(x); }\nfunction b(x) { return a(x); }\nel.innerHTML = a(1);\n"), vec!["a(1)".to_string()], "a cycle refuses");
        assert_eq!(fired("function hero(i) {\n  const html = `<h1>${esc(i.name)}</h1>`;\n  return html;\n}\nel.innerHTML = hero(info);\n"), Vec::<String>::new(), "a helper returning its single-assignment local closes");
        assert_eq!(fired("el.innerHTML = unknownHelper(x);\n"), vec!["unknownHelper(x)".to_string()], "an unknown name still fires");
        assert_eq!(fired("el.innerHTML = sanitizeHtml(xs.map(x => `<b>${x.name}</b>`).join(''));\n"), Vec::<String>::new(), "one sanitizing call around the whole statement closes");
        assert_eq!(fired("el.innerHTML = sanitizeHtml(a) + b;\n"), vec!["sanitizeHtml(a) + b".to_string()], "a sanitizing call that does not cover the statement does not close it");
        assert_eq!(fired("else if(m.media){ const cap=m.body?`<i>${escapeHtml(m.body)}</i>`:''; row.innerHTML=`<div>${cap}</div>`; }\n"), Vec::<String>::new(), "a declaration earlier on the sink's own line is found");
        assert_eq!(fired("el.innerHTML = `<td>${h.ts ? new Date(h.ts * 1000).toUTCString() : '—'}</td>`;\n"), Vec::<String>::new(), "a date-formatting method produces no markup");
        assert_eq!(fired("function identicon(a,px){\n  let st=1; const rnd=()=>{ st^=st<<13; return st/4294967296; };\n  let cells='';\n  for(let y=0;y<5;y++){ if(rnd()<.48) continue; cells+='<rect y=\"'+y+'\"/>'; }\n  return sanitizeHtml('<svg>'+cells+'</svg>');\n}\nel.innerHTML=identicon(a,22);\n"), Vec::<String>::new(), "a nested arrow's return is not the helper's return");
        // the shapes the 2026-10-05 sweep still fired on
        assert_eq!(fired("function sourceLabel(s) {\n  if (s === 'indexer') return '<span style=\"color:var(--success)\">live</span>';\n  if (s === 'cache')   return '<span style=\"color:var(--text-muted)\">cached</span>';\n  return escape(s || '—');\n}\nfunction statusBadge(s) {\n  return s;\n}\nif (activeSub) activeSub.innerHTML = sourceLabel(r.source);\n"), Vec::<String>::new(), "a helper with literal returns and an escaped fallback closes");
        assert_eq!(fired("function identicon(a,px){\n  let cells='';\n  for(let y=0;y<5;y++) cells+='<rect x=\"'+y+'\"/>';\n  return sanitizeHtml('<svg style=\"width:'+Number(px)+'px\">'+cells+'</svg>');\n}\nfunction avatarHtml(a,grp,px){ if(grp) return '👥';\n  const p=profiles[a];\n  if(p&&p.avatar) return '<img src=\"'+sanitizeMediaUrl('data:image/jpeg;base64,'+p.avatar)+'\" alt=\"\">';\n  return identicon(a,px||22); }\nel.innerHTML=avatarHtml(a,!!grp,26);\n"), Vec::<String>::new(), "one-line helpers calling a sanitizing helper close");
        assert_eq!(fired("el.innerHTML = rows.map((c, i) => `<li>${c.shortcut ? `<span>${escapeHtml(c.shortcut)}</span>` : ''}</li>`).join('');\n"), Vec::<String>::new(), "a ternary of templates inside a template is judged by its branches");
        assert_eq!(fired("const cap=m.body?`<div class=\"cap\">${escapeHtml(m.body)}</div>`:'';\nrow.innerHTML=`<div>${cap}</div>`;\n"), Vec::<String>::new(), "a local holding a ternary of templates closes");
        assert_eq!(fired("const rows = xs.map(pos => { const act = esc(pos.a); return `<li>${act}</li>`; });\nel.innerHTML = `<ul>${rows.join('')}</ul>`;\n"), Vec::<String>::new(), "a block arrow's own local is found inside the arrow");
        assert_eq!(fired("el.innerHTML = `<span class=\"dot\"></span><span>Connecting…</span>`;\n"), Vec::<String>::new(), "a template with no interpolation is a literal");
        assert_eq!(fired("el.innerHTML = '<div>' + ((e && e.message === 'X') ? 'open the app' : ('Unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';\n"), Vec::<String>::new(), "a doubly-parenthesised ternary with an escaped branch closes");
        assert_eq!(fired("el.innerHTML = '<div>' + ((e && e.message === 'X') ? 'open the app' : ('Unavailable: ' + (e && (e.message || e)))) + '</div>';\n"), vec!["'<div>' + ((e && e.message === 'X') ? 'open the app' : ('Unavailable: ' + (e && (e.message || e)))) + '</div>'".to_string()], "the raw branch still fires");
        assert_eq!(fired("const who=(grp&&m.from)?`<b>${escapeHtml(m.from)}</b>`:'';\nel.innerHTML=`<div>${who}</div>`;\n"), Vec::<String>::new(), "a declaration without spaces is found");
        assert_eq!(fired("else { const p=profiles[a]; const bio=p&&p.bio?escapeHtml(p.bio)+' · ':'';\n  el.innerHTML='<i>'+bio+'</i>'; }\n"), Vec::<String>::new(), "a mid-line declaration is found");
        assert_eq!(fired("function line(p) {\n  const best = esc(p.best);\n  return `<i>${best}</i>`;\n}\nel.innerHTML = line(p);\n"), Vec::<String>::new(), "a helper's own local is found inside the helper");
        assert_eq!(fired("const rows = xs.map((x) => `<li>${esc(x)}</li>`);\nel.innerHTML = `<ul>${rows.join('')}</ul>`;\n"), Vec::<String>::new(), "a joined local that holds a map of escaped templates closes");
        assert_eq!(fired("const rows = xs.map((x) => `<li>${x}</li>`);\nel.innerHTML = `<ul>${rows.join('')}</ul>`;\n"), vec!["rows.join('')".to_string()], "a joined local that holds a map of raw templates fires");
        assert_eq!(fired("el.innerHTML = '<div style=\"padding:12px;text-align:center\">Loading…</div>';\n"), Vec::<String>::new(), "a `;` inside a literal does not end the statement");
        assert_eq!(fired("el.innerHTML = '<div style=\"padding:12px;x\">' + name + '</div>';\n"), vec!["'<div style=\"padding:12px;x\">' + name + '</div>'".to_string()], "a raw value after a `;`-bearing literal still fires");
        assert_eq!(fired("function v(x) { let s = ''; s += x; return s; }\nel.innerHTML = v(x);\n"), vec!["v(x)".to_string()], "a helper that accumulates with += fires");
    }

}

#[cfg(all(test, feature = "pins-harness"))]
mod sensitive_log_calibration {
    use super::interpolated_sensitive;

    #[test]
    fn a_trailing_comment_naming_a_sensitive_word_is_not_an_interpolated_value_and_a_real_one_still_is() {
        assert_eq!(interpolated_sensitive(r#"        eprintln!("[sat-send] published"); // no amount, no address"#), None);
        assert_eq!(interpolated_sensitive(r#"        eprintln!("[x] sent {amount}");"#), Some("amount"), "calibration: a real interpolation is still caught");
        assert_eq!(interpolated_sensitive(r#"        eprintln!("[x] sent {}", amount); // fine"#), Some("amount"), "an argument before the comment is still caught");
    }
}

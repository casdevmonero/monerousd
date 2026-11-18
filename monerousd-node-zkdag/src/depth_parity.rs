//! MonerousD Protocol — DEPTH-PARITY GUARD (DB-81, 2026-09-19).
//!
//! User: "watch out for depth mismatches that's plagued us all day. if you encounter them fix them, in fact make
//! a guard for them." The class (DB-73/74/75): the wallet proved a send at 64 filler levels while the block
//! aggregate was laid at 0; the burn door was frozen at 2 × 64; the bond verifier refused depth 0 on its own.
//! Each was a literal or an arithmetic expression in a DEPTH SLOT that another site spelled differently, and
//! every one cost a real-node run with no payment or redeem.
//!
//! THE RULE: every carrier class that still walks a Merkle path has ONE named depth constant in `spend_frontier`
//! (`MULTI_SPEND_CARRIER_DEPTH`, `SPEND_TREE_DEPTH` for the accumulator) that the wallet re-exports and never
//! redefines. A prove/verify call's depth slot may hold ONLY a `_DEPTH` path, or a local bound to one. A numeric
//! literal, arithmetic, or a runtime length (`siblings.len()`) in a depth slot is a violation.
//!
//! 2026-09-30: the spend, burn and welded bond carriers have NO depth slot any more — gate D (their path, found
//! DECORATIVE by the census) is deleted and their provers and verifiers take no depth and no root, so that whole
//! class is closed by construction. The scan below keeps only the entries that still take a depth.
//!
//! THIS PIN scans the NODE and the WALLET sources (production code; test modules are skipped — the calibration
//! pins probe wrong depths on purpose) and names every violation with file:line. It is a derived guard: the call
//! sites are FOUND, never hand-listed.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use std::path::PathBuf;

    /// (function name, 0-based index of the depth argument among its top-level arguments)
    const DEPTH_TAKING: &[(&str, usize)] = &[
        ("verify_multi_spend_validity_carrier_bytes", 5),
        ("multi_validity_carrier_selfverifies", 5),
    ];

    fn sources() -> Vec<PathBuf> {
        let node = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let wallet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("monerousd-wallet-v2")
            .join("src-tauri")
            .join("src");
        let mut out = Vec::new();
        for dir in [node, wallet] {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "rs").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
        out.sort();
        assert!(out.len() > 40, "the scan must see both trees; saw {} files", out.len());
        out
    }

    /// Strip `//` comments (the call sites interleave them) — string literals never carry `//` in these files' calls.
    fn strip_line_comments(src: &str) -> String {
        src.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Byte ranges of `#[cfg(test)] mod … { … }` blocks (brace-matched) — skipped: calibration pins probe wrong depths.
    fn test_ranges(src: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(i) = src[from..].find("#[cfg(test)]") {
            let at = from + i;
            let Some(brace_rel) = src[at..].find('{') else { break };
            let open = at + brace_rel;
            let mut depth = 0i32;
            let mut end = open;
            for (k, c) in src[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + k;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push((at, end));
            from = end.max(at + 1);
        }
        out
    }

    /// Top-level comma split of the text between the call's parentheses.
    fn call_args(src: &str, open_paren: usize) -> Option<(Vec<String>, usize)> {
        let bytes = src.as_bytes();
        let mut depth = 0i32;
        let mut args = Vec::new();
        let mut cur = String::new();
        let mut i = open_paren;
        while i < bytes.len() {
            let c = bytes[i] as char;
            match c {
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth > 1 {
                        cur.push(c);
                    }
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if !cur.trim().is_empty() {
                            args.push(cur.trim().to_string());
                        }
                        return Some((args, i));
                    }
                    cur.push(c);
                }
                ',' if depth == 1 => {
                    args.push(cur.trim().to_string());
                    cur.clear();
                }
                _ => cur.push(c),
            }
            i += 1;
        }
        None
    }

    fn is_depth_path(expr: &str) -> bool {
        let e = expr.trim().trim_start_matches('*').trim_start_matches('&');
        !e.is_empty()
            && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
            && e.ends_with("_DEPTH")
    }

    fn has_literal_or_arithmetic(expr: &str) -> bool {
        let e = expr.replace("->", "");
        let tokens: Vec<&str> = e
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.'))
            .filter(|t| !t.is_empty())
            .collect();
        let literal = tokens.iter().any(|t| t.chars().all(|c| c.is_ascii_digit() || c == '_') && t.chars().any(|c| c.is_ascii_digit()));
        let arith = e.contains(" / ") || e.contains(" * ") || e.contains(" + ") || e.contains(" - ") || e.ends_with(".len()") || e.contains(".len() ");
        literal || arith
    }

    /// A bare local (`depth`, `cdepth`, `d`, …) resolves to the nearest preceding `let <name> =` / `|<name>|` /
    /// `<name>: usize` binding in the file; the bound expression must itself be depth-parity clean.
    fn local_is_clean(src: &str, name: &str, before: usize) -> Result<(), String> {
        let head = &src[..before];
        let pat_let = format!("let {name} ");
        let pat_let2 = format!("let {name}:");
        let pat_mut = format!("let mut {name} ");
        if let Some(i) = head.rfind(&pat_let).or_else(|| head.rfind(&pat_let2)).or_else(|| head.rfind(&pat_mut)) {
            let rest = &head[i..];
            let Some(eq) = rest.find('=') else { return Err(format!("`{name}` bound without `=`")) };
            let Some(semi) = rest[eq..].find(';') else { return Err(format!("`{name}` binding has no `;`")) };
            let expr = rest[eq + 1..eq + semi].trim();
            if expr.contains("_DEPTH") && !has_literal_or_arithmetic(expr) {
                return Ok(());
            }
            if expr.contains("_DEPTH") && !expr.contains(".len()") && !expr.chars().any(|c| "/*+".contains(c)) {
                return Ok(()); // an `if a { X_DEPTH } else { Y_DEPTH }` selection between named constants
            }
            return Err(format!("`{name}` is bound to `{expr}` — not a named `_DEPTH` constant"));
        }
        // a function PARAMETER named depth/d (`depth: usize`, `|d|`) is the caller's constant — clean by construction
        let param = format!("{name}: usize");
        let closure = format!("|{name}|");
        let closure2 = format!("|{name}, ");
        let closure3 = format!(", {name}|");
        if head.rfind(&param).is_some() || head.rfind(&closure).is_some() || head.rfind(&closure2).is_some() || head.rfind(&closure3).is_some() {
            return Ok(());
        }
        Err(format!("`{name}` has no visible binding"))
    }

    #[test]
    fn every_carrier_depth_slot_names_a_shared_constant() {
        let mut violations: Vec<String> = Vec::new();
        let mut sites = 0usize;
        for path in sources() {
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            let src = strip_line_comments(&raw);
            let skip = test_ranges(&src);
            let in_test = |pos: usize| skip.iter().any(|(a, b)| pos >= *a && pos <= *b);
            for (fname, idx) in DEPTH_TAKING {
                let mut from = 0;
                while let Some(rel) = src[from..].find(fname) {
                    let at = from + rel;
                    from = at + fname.len();
                    // a longer identifier that merely CONTAINS the name (`multi_validity_carrier_selfverifies`)
                    if at > 0 {
                        let prev = src.as_bytes()[at - 1] as char;
                        if prev.is_ascii_alphanumeric() || prev == '_' {
                            continue;
                        }
                    }
                    // a definition (`fn name(`) or a use path, not a call
                    let before = src[..at].trim_end();
                    if before.ends_with("fn") || before.ends_with("use") {
                        continue;
                    }
                    let after = &src[at + fname.len()..];
                    if !after.starts_with('(') {
                        continue;
                    }
                    if in_test(at) {
                        continue;
                    }
                    let Some((args, _end)) = call_args(&src, at + fname.len()) else { continue };
                    let Some(depth_expr) = args.get(*idx) else {
                        violations.push(format!("{}:{} `{fname}` has {} args, no depth slot {idx}", path.display(), src[..at].lines().count(), args.len()));
                        continue;
                    };
                    sites += 1;
                    let line = src[..at].lines().count();
                    let clean = if is_depth_path(depth_expr) {
                        Ok(())
                    } else if has_literal_or_arithmetic(depth_expr) {
                        Err(format!("depth slot is `{depth_expr}` — a literal, arithmetic or runtime length"))
                    } else {
                        local_is_clean(&src, depth_expr.trim_start_matches('*'), at)
                    };
                    if let Err(why) = clean {
                        violations.push(format!("{}:{} {fname}(…): {why}", path.display(), line));
                    }
                }
            }
        }
        // The production universe after gate D's deletion is the multi-input class alone: the submit door's
        // `verify_multi_spend_validity_carrier_bytes` arm in rpc_http.rs is its one production site.
        assert!(sites >= 1, "the derived scan found no depth-taking call site — the pattern list rotted");
        assert!(
            violations.is_empty(),
            "⛔ DEPTH-PARITY VIOLATION(S) — a prove/verify depth slot that is not a shared named constant (this is the \
             DB-73/74/75 class that cost three real-node runs):\n  {}",
            violations.join("\n  ")
        );
        eprintln!("[depth-parity] {sites} depth-taking call sites, every depth slot a named constant");
    }

    /// The constants themselves: the wallet re-exports, never redefines (a second spelling IS the class).
    #[test]
    fn the_wallet_spells_no_depth_of_its_own() {
        let wallet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("monerousd-wallet-v2")
            .join("src-tauri")
            .join("src");
        let mut own: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&wallet) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.extension().map(|x| x == "rs").unwrap_or(false) {
                    continue;
                }
                let src = strip_line_comments(&std::fs::read_to_string(&p).unwrap_or_default());
                for (n, l) in src.lines().enumerate() {
                    let t = l.trim();
                    if t.starts_with("pub const ") && t.contains("_DEPTH") && t.contains("usize") {
                        let rhs = t.split('=').nth(1).unwrap_or("").trim();
                        if !rhs.contains("usdmd_node::") && !rhs.contains("_DEPTH") {
                            own.push(format!("{}:{} {t}", p.display(), n + 1));
                        }
                    }
                }
            }
        }
        assert!(own.is_empty(), "⛔ the wallet defines a depth of its own instead of re-exporting the node's:\n  {}", own.join("\n  "));
    }
}

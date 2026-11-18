//! # WIRING CENSUS — the guard for "built, pinned, and never called"
//!
//! Protocol: MonerousD node (usdmd-node). Test-only module; it compiles out of production entirely.
//!
//! ## Why this exists
//!
//! ⛔ THE UNWIRED FEATURE IS THIS TREE'S MOST EXPENSIVE RECURRING CLASS, and it is invisible to every
//! other gate we have. A function is written, a pin is written against it BY HAND, the pin goes green,
//! and nothing in the running node ever calls it. The suite is green, the census is green, the gate is
//! green, and the feature does not exist.
//!
//! MEASURED, all found by hand and all after the fact:
//!   • `Node::new_sparse_work` — the SHARDED tree constructor. One caller, inside `rebuild_nullifier_tree`,
//!     which itself had zero production callers. So Z2 sharding had NEVER run on a live node at any mesh
//!     size, while two green pins built sharded trees by hand and compared them.
//!   • `warm_sparse_work`, `rebuild_nullifier_tree`, `warm_nullifier_trees_from_peer_stream` — the three
//!     functions that re-warm a restarted node's copath source. Zero production callers between them, so
//!     every restarted and every jumped node was treeless for good (DB-151).
//!   • `ensure_sparse_work` — named in four comments, never written at all.
//!   • `build_block_sparse_nf_carrier` — the only path producing a real Merkle post root. Reached only
//!     from tests, which is why the chain commits a fold value instead (DB-154).
//!   • `capture_at_receipt` (2026-08-11) — 18 green tests, zero call sites, and a deploy was started.
//!
//! The existing PreToolUse guard catches a function built in THE SAME SESSION. None of the above were.
//! This is the standing sweep: every production function in the crate, every session, enforced by the
//! suite rather than by anyone remembering to look.
//!
//! ## What it does NOT claim
//!
//! It is a reachability census over TEXT, not a call graph. A function reached only through a trait
//! object, a macro, or another crate is not visible to it, which is why the exemption list exists and why
//! each entry carries a REASON rather than a name alone. An entry with no reason is the bug this module
//! exists to catch, wearing a different hat.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    /// A function that text-reachability cannot see, with the reason it cannot. NEVER add a name here to
    /// make the census pass — the whole point is that "nothing calls it" is the finding. Add it only when
    /// the call is real and this sweep structurally cannot observe it.
    const EXEMPT: &[(&str, &str)] = &[
        ("main", "the binary entry point; called by the runtime, not by us"),
        ("fmt", "std::fmt::Display / Debug, called through the trait"),
        ("default", "std::default::Default, called through the trait"),
        ("drop", "std::ops::Drop, called by the compiler at scope exit"),
        ("clone", "std::clone::Clone, called through the trait"),
        ("eq", "std::cmp::PartialEq, called through the trait"),
        ("cmp", "std::cmp::Ord, called through the trait"),
        ("partial_cmp", "std::cmp::PartialOrd, called through the trait"),
        ("hash", "std::hash::Hash, called through the trait"),
        ("next", "std::iter::Iterator, called through the trait"),
        ("from", "std::convert::From, called through the trait"),
        ("into", "std::convert::Into, called through the trait"),
        ("deref", "std::ops::Deref, called through the trait"),
        ("serialize", "serde, called through the trait"),
        ("deserialize", "serde, called through the trait"),
    ];

    /// Every file that may legitimately CALL this crate's production code: this crate's own sources, and
    /// the wallet's, which consumes the node as a library (`usdmd_node::...`).
    ///
    /// ⛔ LEAVING THE WALLET OUT MAKES THE CENSUS LIE IN THE DANGEROUS DIRECTION. A `pub fn` the wallet
    /// calls and the node does not is WIRED — reporting it as dead invites deleting the wallet's floor out
    /// from under it. The census may only ever err toward reporting something as wired when it is not;
    /// never the reverse.
    fn caller_sources() -> Vec<(String, String)> {
        let mut out = crate_sources();
        // ⛔ AND THE SUBDIRECTORIES. `src/harness/` is a whole test tier and the census could not see it,
        // so seven functions it is the only caller of read as "not mentioned anywhere" — a bulk delete on
        // that number broke the harness build. Depth one is enough for this tree's layout.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        if let Ok(rd) = std::fs::read_dir(&src) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_dir() {
                    continue;
                }
                let Ok(inner) = std::fs::read_dir(&p) else {
                    continue;
                };
                for f in inner.flatten() {
                    let q = f.path();
                    let Some(name) = q.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if !name.ends_with(".rs") || name.contains(".pre") {
                        continue;
                    }
                    if let Ok(text) = std::fs::read_to_string(&q) {
                        out.push((format!("sub/{name}"), text));
                    }
                }
            }
        }
        let wallet = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("monerousd-wallet-v2").join("src-tauri").join("src"));
        if let Some(dir) = wallet {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if !name.ends_with(".rs") || name.contains(".pre") {
                        continue;
                    }
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        out.push((format!("wallet/{name}"), text));
                    }
                }
            }
        }
        out
    }

    /// Module files that `lib.rs` declares under `#[cfg(test)]`. Their whole contents are test-only.
    ///
    /// ⛔ THE CENSUS READ EACH FILE IN ISOLATION AND SO COULD NOT SEE THIS. A scenario suite gated with
    /// `#[cfg(test)] mod consensus_scenarios;` compiles out entirely, but its own file carries no marker,
    /// so every helper in it read as production and as unwired. MEASURED: that inflated the census by
    /// about 30 entries and would have had working test suites "wired" into production to satisfy it.
    fn test_gated_modules() -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("lib.rs");
        let Ok(text) = std::fs::read_to_string(&lib) else {
            return out;
        };
        let lines: Vec<&str> = text.split('\n').collect();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim_start();
            let Some(rest) = t.strip_prefix("mod ").or_else(|| t.strip_prefix("pub mod ")) else {
                continue;
            };
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if name.is_empty() {
                continue;
            }
            let gated_here = t.contains("#[cfg(test)]");
            let gated_above = i > 0 && lines[i - 1].contains("#[cfg(test)]");
            if gated_here || gated_above {
                out.insert(format!("{name}.rs"));
            }
        }
        out
    }

    /// Source files this crate owns, excluding the dated backups this tree keeps beside them.
    fn crate_sources() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            // `.pre<TAG>-<DATE>` backups are history, not the tree under test.
            if !name.ends_with(".rs") || name.contains(".pre") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                out.push((name.to_string(), text));
            }
        }
        out
    }

    /// Byte ranges of every `#[cfg(test)]` / `#[test]` / `mod tests` region in one file.
    ///
    /// Brace-counted from the attribute, so a nested module inside a test module is covered by the outer
    /// range and never mistaken for production.
    fn test_regions(src: &str) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = Vec::new();
        let marks = ["#[cfg(test)]", "#[test]", "mod tests"];
        for m in marks {
            let mut from = 0usize;
            while let Some(rel) = src[from..].find(m) {
                let at = from + rel;
                from = at + m.len();
                if out.iter().any(|(a, b)| at >= *a && at < *b) {
                    continue; // already inside a region we recorded
                }
                let Some(open_rel) = src[at..].find('{') else {
                    continue;
                };
                let open = at + open_rel;
                let mut depth = 0i32;
                let mut end = open;
                for (i, c) in src[open..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = open + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                out.push((at, end.max(open)));
            }
        }
        out
    }

    /// Byte ranges of every `impl <Trait> for <Type>` block.
    ///
    /// ⛔ A TRAIT-IMPL METHOD IS CALLED THROUGH THE TRAIT, so text reachability cannot see its call and
    /// listing it as dead would be a false positive of the dangerous kind. The thing that must be wired is
    /// the TRAIT, not each implementation of it — an unused trait shows up as its own finding. Inherent
    /// `impl Type` blocks are NOT covered here: their methods are called by name and must be wired.
    fn trait_impl_regions(src: &str) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("impl ") {
            let at = from + rel;
            from = at + 5;
            let Some(brace_rel) = src[at..].find('{') else {
                break;
            };
            let head = &src[at..at + brace_rel];
            // `impl X for Y` — the ` for ` must be in the header, not in a body below it.
            if !head.contains(" for ") {
                continue;
            }
            let open = at + brace_rel;
            let mut depth = 0i32;
            let mut end = open;
            for (i, c) in src[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push((at, end.max(open)));
        }
        out
    }

    fn in_any(ranges: &[(usize, usize)], at: usize) -> bool {
        ranges.iter().any(|(a, b)| at >= *a && at < *b)
    }

    /// Blank out `//` comments so a function NAMED in a doc comment does not read as a call to it — the
    /// exact confusion that let `ensure_sparse_work` be "referenced" four times while never existing.
    ///
    /// ⛔ BYTE OFFSETS MUST SURVIVE THIS, and the first version did not. Removing the comment text shifts
    /// every offset after it, so the test-region ranges (computed against the raw file) stop lining up and
    /// production lines get classified as test code. Their calls are then dropped and the functions they
    /// call read as unwired. MEASURED: that bug reported 97 unwired functions including `repair_round`,
    /// which is called one line above its own definition's caller. A census with false positives is worse
    /// than none, because it gets working code deleted.
    fn code_only(src: &str) -> String {
        src.split('\n')
            .map(|l| match l.find("//") {
                // Blanked IN PLACE, same byte count, so nothing downstream moves.
                Some(at) => format!("{}{}", &l[..at], " ".repeat(l.len() - at)),
                None => l.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// ⭐⭐⭐ EVERY PRODUCTION FUNCTION IN THIS CRATE IS CALLED BY PRODUCTION CODE.
    ///
    /// A function that only tests call is a feature that does not exist, however green its pins are. This
    /// is the standing sweep; the PreToolUse guard beside it only sees functions built in one session.
    #[test]
    fn every_production_function_is_reachable_from_production_code() {
        let files = crate_sources();
        let callers = caller_sources();
        assert!(
            callers.len() > files.len(),
            "the census must read the WALLET too ({} caller files vs {} crate files) — a pub fn the wallet              calls and the node does not is WIRED, and reporting it dead invites deleting it",
            callers.len(),
            files.len()
        );
        assert!(
            files.len() > 20,
            "the census must actually read the crate ({} files) — a sweep that reads nothing passes \
             vacuously, which is the same failure it exists to catch",
            files.len()
        );

        // 1. Every production function definition, and where it was defined.
        let mut defined: BTreeMap<String, String> = BTreeMap::new();
        // 2. Every identifier that appears in production code OUTSIDE a definition line.
        let mut referenced: BTreeSet<String> = BTreeSet::new();

        let fn_at = |line: &str| -> Option<String> {
            let t = line.trim_start();
            let rest = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub(super) "))
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            let rest = rest.strip_prefix("async ").unwrap_or(rest);
            let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
            let rest = rest.strip_prefix("const ").unwrap_or(rest);
            let rest = rest.strip_prefix("fn ")?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        };

        let gated = test_gated_modules();
        for (file, raw) in &files {
            if gated.contains(file) {
                continue; // the whole module compiles out of production; nothing in it is production
            }
            let regions = test_regions(raw);
            let traits = trait_impl_regions(raw);
            let src = code_only(raw);
            // Offsets shift when comments are stripped, so classify by scanning the RAW text for
            // definitions and using the raw offset for the region test.
            let mut at = 0usize;
            for line in raw.lines() {
                let here = at;
                at += line.len() + 1;
                let Some(name) = fn_at(line) else { continue };
                if in_any(&regions, here) {
                    continue; // a test's own helper is not production
                }
                if in_any(&traits, here) {
                    continue; // called through the trait; the TRAIT is what must be wired
                }
                defined.entry(name).or_insert_with(|| file.clone());
            }
            let _ = &src;
        }
        for (_file, raw) in &callers {
            let regions = test_regions(raw);
            let src = code_only(raw);
            // References: every identifier in production code, minus the definition lines themselves.
            let mut off = 0usize;
            for line in src.lines() {
                let here = off;
                off += line.len() + 1;
                if in_any(&regions, here) {
                    continue;
                }
                if fn_at(line).is_some() {
                    continue; // the definition is not a call
                }
                let mut word = String::new();
                for c in line.chars() {
                    if c.is_alphanumeric() || c == '_' {
                        word.push(c);
                    } else {
                        if !word.is_empty() {
                            referenced.insert(std::mem::take(&mut word));
                        }
                    }
                }
                if !word.is_empty() {
                    referenced.insert(word);
                }
            }
        }

        let exempt: BTreeSet<&str> = EXEMPT.iter().map(|(n, _)| *n).collect();
        let mut unwired: Vec<(String, String)> = defined
            .into_iter()
            .filter(|(name, _)| !exempt.contains(name.as_str()))
            .filter(|(name, _)| !referenced.contains(name))
            .collect();
        unwired.sort();

        assert!(
            !unwired.is_empty() || !EXEMPT.is_empty(),
            "the census produced no verdict at all"
        );

        if !unwired.is_empty() {
            // The whole list goes to a file: a panic message truncated to fit a terminal is how a census
            // of 97 gets triaged as a census of 40.
            let full: String = unwired
                .iter()
                .map(|(n, f)| format!("{f}::{n}\n"))
                .collect();
            let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("wiring-census.txt");
            let _ = std::fs::write(&out, &full);
            let shown: Vec<String> = unwired
                .iter()
                .take(40)
                .map(|(n, f)| format!("  ✗ {f}::{n}"))
                .collect();
            panic!(
                "⛔ {} PRODUCTION FUNCTION(S) ARE CALLED BY NOTHING IN PRODUCTION CODE.\n{}\n\n\
                 A function only tests call is a feature that does not exist, however green its pins are. \
                 Z2 sharding shipped this way: `new_sparse_work` had one caller, inside a function with \
                 zero production callers, so `with_shards` never ran on a live node while two hand-built \
                 pins passed. WIRE IT, DELETE IT, or add it to EXEMPT WITH A REASON — and a reason is \
                 \"text reachability structurally cannot see this call\", never \"the census is noisy\".",
                unwired.len(),
                shown.join("\n")
            );
        }
    }
}

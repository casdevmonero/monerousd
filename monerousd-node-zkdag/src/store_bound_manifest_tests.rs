// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ STORE-BOUND MANIFEST — every collection-typed struct field in an ENFORCED file carries an
//! `O1-FOOTPRINT-REVIEWED: bounded by …` line within the 8 lines above it. 2026-09-03: the pump's
//! `outbound: VecDeque<Vec<u8>>` had no bound for consensus classes and reached 4.7 M cells / 23 GB per
//! node (the user's fourth "node eats all my memory" incident). The edit-time guard
//! (`~/.claude/hooks/node-store-bound-guard.py`) denies NEW unreviewed fields anywhere in the crate; this
//! test holds the already-reviewed files to the standard forever and names the backlog in the others so
//! it shrinks pass by pass (a file joins `ENFORCED` when its last field is reviewed — never removed).

#[cfg(all(test, feature = "pins-core"))]
mod store_bound_manifest_tests {
    const MARK: &str = "O1-FOOTPRINT-REVIEWED";
    /// Files whose every store is reviewed. ONLY GROWS.
    const ENFORCED: &[&str] = &["transport.rs", "net.rs", "arti_transport.rs", "log_cap.rs"];
    const COLLECTIONS: &[&str] = &[
        "Vec<", "VecDeque<", "HashMap<", "BTreeMap<", "HashSet<", "BTreeSet<", "IndexMap<", "LinkedList<",
        "BinaryHeap<",
    ];

    /// A `;` INSIDE `<...>`, `[...]` or `(...)` is part of a TYPE — `[u8; 32]` — not a statement
    /// terminator.
    ///
    /// ⛔⛔⛔ THE BLIND SPOT THIS CLOSES, MEASURED 2026-09-12. `is_collection_field` used a bare
    /// `!t.contains(';')` to skip statements. That ALSO skipped every field whose type carries a
    /// fixed-size array — and in a post-quantum codebase `[u8; 32]` is the dominant shape, so the guard
    /// enforcing the O(1) node cardinal could not see **70 collection fields**, among them all FOUR
    /// replay sets in `PegLedger` (`spent_burns`, `confidential_deposit_ids`, `released`, `liquidated`)
    /// — unbounded, persisted, and holding the stablecoin's supply state. `peg.rs` did not even appear
    /// in the backlog census, so the silence read as "nothing there".
    ///
    /// This is the [[reference_refutation_before_green]] class exactly: a detector that reports clean
    /// because it cannot see. The calibration below pins BOTH directions so it cannot regress.
    fn has_top_level_semicolon(t: &str) -> bool {
        let mut depth = 0i32;
        let mut prev = ' ';
        for c in t.chars() {
            match c {
                '<' | '[' | '(' => depth += 1,
                // `->` is an arrow, not a closing bracket: counting it would unbalance a signature.
                '>' if prev != '-' => depth -= 1,
                ']' | ')' => depth -= 1,
                ';' if depth <= 0 => return true,
                _ => {}
            }
            prev = c;
        }
        false
    }

    fn is_collection_field(line: &str) -> bool {
        let t = line.trim_start();
        let t = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
        let Some((name, ty)) = t.split_once(':') else { return false };
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
        let ty = ty.trim();
        let ty = ["Arc<Mutex<", "Arc<RwLock<", "Mutex<", "RwLock<", "Option<"]
            .iter()
            .fold(ty, |acc, w| acc.strip_prefix(w).unwrap_or(acc));
        let ends_like_field =
            t.trim_end().ends_with(',') && !has_top_level_semicolon(t) && !t.contains('=') && !t.contains('{');
        ends_like_field && COLLECTIONS.iter().any(|c| ty.starts_with(c))
    }

    fn unreviewed(src: &str) -> Vec<(usize, String)> {
        let lines: Vec<&str> = src.lines().collect();
        let mut out = Vec::new();
        for (i, ln) in lines.iter().enumerate() {
            if !is_collection_field(ln) || ln.contains(MARK) {
                continue;
            }
            let above = lines[i.saturating_sub(8)..i].join("\n");
            if above.contains(MARK) {
                continue;
            }
            let near = lines[i.saturating_sub(6)..i].join("\n");
            // a fn signature parameter is not a store
            if near.rfind("fn ").map(|p| !near[p..].contains(')')).unwrap_or(false) {
                continue;
            }
            out.push((i + 1, ln.trim().to_string()));
        }
        out
    }

    #[test]
    fn every_store_in_an_enforced_file_declares_its_bound() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut violations = Vec::new();
        let mut backlog = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let bad = unreviewed(&src);
            if bad.is_empty() {
                continue;
            }
            if ENFORCED.contains(&name.as_str()) {
                for (l, t) in bad {
                    violations.push(format!("{name}:{l}: {t}"));
                }
            } else {
                backlog.push(format!("{name}={}", bad.len()));
            }
        }
        eprintln!(
            "[store-bound] backlog of unreviewed collection fields outside ENFORCED files ({} files): {}",
            backlog.len(),
            backlog.join(" ")
        );
        assert!(
            violations.is_empty(),
            "collection fields WITHOUT a declared bound in enforced files:\n  {}\nDeclare the bound within the 8 lines above (`{MARK}: bounded by …`) and make it true.",
            violations.join("\n  ")
        );
    }

    /// The detector itself: a bare field is caught, a reviewed one passes, a fn parameter is ignored.
    #[test]
    fn detector_catches_bare_fields_and_ignores_reviewed_and_params() {
        let bare = "pub struct S {\n    pending: VecDeque<Vec<u8>>,\n}\n";
        assert_eq!(unreviewed(bare).len(), 1);
        let reviewed = "pub struct S {\n    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant 16\n    pending: VecDeque<Vec<u8>>,\n}\n";
        assert!(unreviewed(reviewed).is_empty());
        let param = "fn f(\n    cells: Vec<Vec<u8>>,\n) {}\n";
        assert!(unreviewed(param).is_empty());
    }

    /// ⭐ THE DETECTOR MUST SEE ARRAY-TYPED STORES, and must still ignore statements. Calibrated BOTH
    /// directions, because the bug this pins was a SILENT one: the manifest reported a clean `peg.rs`
    /// while four unbounded replay sets sat in it.
    #[test]
    fn the_classifier_sees_array_typed_collections_and_still_ignores_statements() {
        let must_see = [
            "    spent_burns: HashSet<[u8; 32]>,",
            "    confidential_deposit_ids: HashSet<[u8; 32]>,",
            "    keys: HashMap<[u8; 32], Vec<u8>>,",
            "    padded_tags: Vec<[u8; 32]>,",
            "    pub(crate) owed: BTreeMap<[u8; 32], u64>,",
        ];
        for ln in must_see {
            assert!(
                is_collection_field(ln),
                "⛔ the classifier is BLIND to an array-typed store — the 70-field blind spot: {ln}"
            );
        }
        let must_ignore = [
            "        let v: Vec<u8> = Vec::new();",
            "        ratio_bps: u32,",
            "    reserve_commit: crate::spend_frontier::Digest4,",
            "        let m: HashMap<[u8; 32], u64> = HashMap::new();",
        ];
        for ln in must_ignore {
            assert!(!is_collection_field(ln), "⛔ the classifier claimed a non-store: {ln}");
        }
        assert!(has_top_level_semicolon("let v: Vec<u8> = x;"), "a statement's `;` is top level");
        assert!(!has_top_level_semicolon("a: HashSet<[u8; 32]>,"), "a type's `;` is not");
        eprintln!(
            "[store-bound] classifier calibrated: {} array-typed store(s) seen, {} non-store(s) ignored",
            must_see.len(),
            must_ignore.len()
        );
    }
}

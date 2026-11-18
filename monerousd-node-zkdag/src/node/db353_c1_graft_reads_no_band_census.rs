// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::db353_c1_graft_reads_no_band_census` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
const GRAFT: [&str; 11] = [
    "ingest_block",
    "ingest_block_inner",
    "ingest_block_preverified",
    "ingest_block_preverified_budgeted",
    "graft_admitted_notes",
    "graft_mined_own",
    "graft_mined_own_budgeted",
    "rehydrate_block_body",
    "fill_shell_body_preverified",
    "readmit_parked_shell",
    "header_door_admits_witnessed",
];

/// The calibration's planted source: a graft entry point reaching a band read through a helper, and one calling the
/// sanctioned fold pass. A module constant, not a literal inside the test, because it is SOURCE TEXT under census —
/// inside a test body its words read as a test that builds chain state (`test_standard`'s syntactic two-party census),
/// while the test itself builds no node, no block and no value.
const PLANTED: &str = "impl Node {\n    pub fn ingest_block(&mut self) { self.judge_admission(); }\n    fn judge_admission(&self) -> bool { self.band_pointer().is_some() }\n    pub fn graft_admitted_notes(&mut self) { self.fold_canonical_records(); }\n    fn fold_canonical_records(&mut self) { self.band_drain(); }\n}\n";

/// CALIBRATION (the attack is armed): a graft entry point that reaches a band read only through a helper is FLAGGED,
/// and one that calls the sanctioned fold pass is not.
#[test]
fn db353_c1_the_census_flags_a_graft_path_that_reads_the_band_through_a_helper() {
    let (_, readers) = scan(PLANTED);
    assert!(readers.contains_key("ingest_block"), "a graft path reading the band through a helper must be flagged");
    assert!(
        !readers.contains_key("graft_admitted_notes"),
        "calling the sanctioned fold pass is not a graft-time band read"
    );
}

/// Every fn of `src` as `(name, text)`, and the closure of band readers as `reader -> why` (never propagating
/// through the fold pass).
fn scan(src: &str) -> (Vec<(String, String)>, std::collections::BTreeMap<String, String>) {
    let lines: Vec<&str> = src.lines().collect();
    // (name, text) for every fn in the file: a one-line fn is its own line; otherwise the body runs to the closing
    // brace at the signature's own indentation. Nested fns are scanned as entries of their own too.
    let mut fns: Vec<(String, String)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        let indent = l.len() - t.len();
        let Some(rest) = t
            .strip_prefix("pub(crate) fn ")
            .or_else(|| t.strip_prefix("pub(super) fn "))
            .or_else(|| t.strip_prefix("pub fn "))
            .or_else(|| t.strip_prefix("fn "))
        else {
            continue;
        };
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if t.contains('{') && t.trim_end().ends_with('}') {
            fns.push((name, (*l).to_string()));
            continue;
        }
        let close = format!("{}}}", " ".repeat(indent));
        let end = lines[i + 1..].iter().position(|x| *x == close).map_or(lines.len(), |p| i + 1 + p);
        // Whole-line comments are not code: a quoted call in a `//` line (MEASURED: `graft_mined_own_budgeted`'s
        // history comment quotes `if self.sparse_acc.root_bytes() == …`) is not a read. Trailing comments stay in,
        // which can only over-flag.
        let code: Vec<&str> =
            lines[i..end].iter().copied().filter(|l| !l.trim_start().starts_with("//")).collect();
        fns.push((name, code.join("\n")));
    }
    // A READ is an access through the node itself: `self.band_door…` or a `self.band_*(` accessor call. A field
    // INITIALISER (`band_door: BandDoor::new(..)` in a constructor) is not a read, and an edge is a METHOD call on the
    // node (`self.f(` / `Self::f(`), so a common name elsewhere (`Vec::new(`) never forges one.
    // ⭐ DB-353 P1 (spec §13.5): the sparse VIEW is band-pointer state — it moves only in the band drain — so its
    // fields are band reads too (`nf_recent`, the view's old recent-root ring, is deleted: the door answers it).
    const DIRECT: [&str; 9] = [
        "self.band_door",
        "self.band_root(",
        "self.band_root_at(",
        "self.band_pointer(",
        "self.band_drain(",
        "self.band_receive(",
        "self.sparse_work",
        "self.sparse_acc",
        "self.da_sparse_copath(",
    ];
    // The fold pass and its REWIND are where band state is maintained: `rewind_fold_to_common` un-applies band steps
    // (`band_door.rewind_to`) when the canonical fold changes under a reorg — a write of the fold's own journal,
    // never a value that decides whether a block is admitted. MEASURED 2026-09-30: every graft path's only route to
    // the band was a late block or a healed shell reaching this rewind.
    // ⭐ POINTER-FREE (§13.5): `fold_point_spent_set` reads the view ∪ the known pending steps, a union a drain does not
    // change — so a graft path may read it (DB-358's first-contact memo does) without two nodes at different pointers
    // splitting. Pinned by `db353_p1_the_fold_point_set_is_pointer_free`. Its parts stay readers: a graft path that
    // read the view or the pending sets ALONE is still flagged.
    // ⭐ PERSISTENCE (§13.5 item 4): `export_snapshot` (reached from `autosave` on the graft path) writes THIS node's own
    // band state into THIS node's own checkpoint; it decides nothing about any block and is read by no other node
    // (P5 reshapes what the checkpoint and the bundle carry). Named here so any OTHER graft-time read of the band or the
    // view is still flagged. `capture_fold_record` is the SAME checkpoint's other half — its fold-record trailer, which
    // since landing 2 carries the band door (`FoldRecord::band`, so a restart resumes the door it stood on) — reached
    // from the same `autosave`, written to the same file, and read by no admission decision on any node.
    // `capture_nf_view_cache` (DB-397 fix A): the view's tags written into this node's own resume cache at a checkpoint —
    // the `capture_fold_record` class, decides nothing about any block.
    const SANCTIONED: [&str; 6] = [
        "fold_canonical_records",
        "rewind_fold_to_common",
        "fold_point_spent_set",
        "export_snapshot",
        "capture_fold_record",
        "capture_nf_view_cache",
    ];
    let calls = |text: &str, f: &str| text.contains(&format!("self.{f}(")) || text.contains(&format!("Self::{f}("));
    // reader -> why ("direct", or the reader it calls)
    let mut readers: std::collections::BTreeMap<String, String> = fns
        .iter()
        .filter(|(n, text)| !SANCTIONED.contains(&n.as_str()) && DIRECT.iter().any(|d| text.contains(d)))
        .map(|(n, _)| (n.clone(), "direct".to_string()))
        .collect();
    loop {
        let grown: Vec<(String, String)> = fns
            .iter()
            .filter(|(n, _)| !readers.contains_key(n) && !SANCTIONED.contains(&n.as_str()))
            .filter_map(|(n, text)| readers.keys().find(|r| calls(text, r)).map(|r| (n.clone(), r.clone())))
            .collect();
        if grown.is_empty() {
            break;
        }
        readers.extend(grown);
    }
    (fns, readers)
}

#[test]
fn db353_c1_no_graft_time_door_reads_the_band_or_its_pointer() {
    // `impl Node` lives in node.rs AND every module of src/node/ since the §SPLIT (2a95f22): the census reads them all, or it
    // reads a fraction of the doors and goes blind (RED on the calibration since 2026-10-28: the fold helper moved to fold.rs)
    let src = crate::test_census::node_production_source().expect("node.rs reads");
    let (fns, readers) = scan(&src);
    // CALIBRATION: the scanner sees a real band read (the fold's own step helper).
    assert!(
        readers.contains_key("band_note_fold_step"),
        "CALIBRATION: the census must see the fold helper's band read — it is blind otherwise"
    );
    for g in GRAFT {
        assert!(
            fns.iter().any(|(n, _)| n == g),
            "CALIBRATION: graft entry point `{g}` was not found — renamed? The census would be vacuous for it"
        );
    }
    let offenders: Vec<&str> = GRAFT.iter().copied().filter(|g| readers.contains_key(*g)).collect();
    // The chain that makes each offender a reader, so a flag is always explicable.
    for g in &offenders {
        let mut chain = vec![g.to_string()];
        while let Some(next) = readers.get(chain.last().expect("non-empty")) {
            if next == "direct" || chain.contains(next) || chain.len() > 12 {
                break;
            }
            chain.push(next.clone());
        }
        eprintln!("[db353-c1] offender chain: {}", chain.join(" -> "));
    }
    eprintln!("[db353-c1] {} band-reading fns in node.rs; graft offenders: {offenders:?}", readers.len());
    assert!(
        offenders.is_empty(),
        "⛔⛔⛔ DB-353 C1: graft-path entry point(s) {offenders:?} read the band or its pointer (directly or through a \
         helper) — a local-progress value would decide admission, and two honest nodes at different pointers would \
         split. Move the verdict to the fold (wait, never exclude) or the pool."
    );
}

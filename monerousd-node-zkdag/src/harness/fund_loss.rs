// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE RETENTION CENSUS — CAN A NOTE ITS OWNER **ALREADY OWNS** BECOME UNREACHABLE?
//!
//! ⛔⛔⛔ WHY THIS EXISTS, AND IT IS A CRITICISM OF EVERY OTHER INSTRUMENT HERE. The harness censuses
//! value CREATION ([`super::value_creation`] — who may mint, how much, how often), value DESTRUCTION (the
//! same module's mirror), OBSERVABILITY ([`super::privacy`]), GATE EXECUTION ([`super::vacuity`]),
//! DEAD CODE ([`super::seam`]) and END-TO-END MOVABILITY ([`super::e2e_claims`]).
//!
//! **Not one of them asks whether a note that already exists, that its owner already owns, can stop being
//! findable or spendable.** That is a third verb beside create and destroy — RETAIN — and it is where
//! money is actually lost on this chain: not minted from nothing and not burned by an attacker, but
//! carried in a block, recorded, and then absent from the tree that decides spendability, or present in
//! the tree and absent from the index that makes it findable from a seed.
//!
//! MEASURED 2026-09-16, the only finding the whole fuzz catalogue reports:
//!
//! ```text
//! inv=I-CP STATE-NOT-DERIVABLE-FROM-THE-CHAIN :: party 0 holds Some(1) received-note sidecar rows
//! (which notes were PAID TO someone) in `da_recv_mem` where a node fed ONLY the blocks derives Some(2).
//! ```
//!
//! A retention hole, invisible to all six instruments above, found by a fuzz invariant rather than by any
//! census — which means nothing guaranteed it would be found at all.
//!
//! ## WHAT IT DERIVES, AND WHY THERE IS NO JUDGEMENT IN IT
//!
//! ⛔ A REGISTER OF HAND-WRITTEN ANSWERS ROTS, AND THIS TREE HAS THE RECEIPT.
//! `value_creation::DESTRUCTION_SITES_WITHOUT_AUTHORITY` still says *"any block producer can burn any
//! note on every node"* — §BB closed that, and `Node::graft_admitted_deletions` has been wired in
//! production since. A list built from that const reports a hole the code does not have. So this census
//! asks the code two mechanical questions and takes no opinion of mine:
//!
//! 1. **WHICH FUNCTIONS WRITE RETENTION STATE?** Derived by scanning the production source for writes to
//!    the three structures that together decide *reachable and spendable* — the unspent-note accumulator,
//!    the record store, and the account index. Test bodies are stripped, so the answer is production only.
//! 2. **DOES ANY TEST NAME EACH ONE?** A writer no test names is not proven safe by anything. It is not
//!    thereby a defect — it may be an inner helper reached through a named wrapper — but it MUST be filed
//!    with the reason, exactly as `e2e_claims` makes an unproven class name its blocker.
//!
//! Both questions are answered from the filesystem at test time, so a new retention writer fails this
//! module the moment it lands, with nothing to remember.
//!
//! ⭐ BORROWED SHAPE — ETHEREUM'S STATE TRANSITION: *state is a function of the chain, local state is a
//! cache.* A retention writer is exactly a place where this node's cache of "what exists and who can
//! spend it" is updated, and the only sound property is that a node fed the same blocks derives the same
//! answer. That is what invariant I-CP checks and what every entry here is ultimately about.

use std::collections::{BTreeMap, BTreeSet};

/// The three structures that together decide whether a note its owner owns stays reachable and spendable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Structure {
    /// The unspent-note accumulator and its path map — decides SPENDABLE.
    UnspentTree,
    /// The DA record store and the received-note sidecar — decides the note EXISTS here at all.
    RecordStore,
    /// The account buckets and their targets — decides FINDABLE FROM A SEED.
    AccountIndex,
}

impl Structure {
    /// The source-text patterns that identify a write to this structure.
    ///
    /// CHAIN-PUBLISH-REVIEWED: a census FIXTURE — these are string literals matched against this
    /// repository's own source text at test time. Nothing here touches a note, a root or a chain object;
    /// the identifiers merely NAME the functions that do.
    fn patterns(self) -> &'static [&'static str] {
        match self {
            Structure::UnspentTree => &[
                ".receive(",
                "set_unspent_root(",
                "uns_map_apply(",
                "unspent_present_complete =",
                ".spend(",
                "mark_unspent_ready(",
                "unspent_recover_from_cms(",
                "try_rebuild_unspent_map(",
            ],
            Structure::RecordStore => &[
                "record_note_payload",
                "stage_credit_note(",
                "da_recv_store(",
                "graft_admitted_notes(",
            ],
            Structure::AccountIndex => &[
                "record_account_target(",
                "stage_carried_account_targets(",
                "account_bucket_append(",
            ],
        }
    }
    pub fn all() -> [Structure; 3] {
        [Structure::UnspentTree, Structure::RecordStore, Structure::AccountIndex]
    }
}

/// The source-text shapes that DROP a fallible result without saying so.
///
/// ⭐ BORROWED SHAPE — BITCOIN'S `CValidationState`: every rejection carries a REASON, and a block or
/// transaction never fails silently. Ethereum's STF is the same: an apply either produces the expected
/// post-state or the node reports which rule it violated. A retention write that swallows its error is
/// the one shape neither chain permits, because it turns lost money into a no-op.
const SILENT_DROP: &[&str] = &[
    "let _ =",
    ".is_ok()",
    ".is_err()",
    "if let Ok(",
    "if let Some(",
    ".ok()",
    ".unwrap_or_default()",
    ".unwrap_or(",
];

/// A production retention write the rule flags as SWALLOWED, with what reading it actually showed.
///
/// ⛔⛔⛔ THIS LIST IS THE RULE'S OUTPUT PLUS A REASON — NOT A SECOND OPINION ABOUT IT. Every entry was
/// read at its call site; the reason says what makes the discard correct, or names the work if it is not.
/// `nothing_filed_is_stale` fails the build the moment the rule stops flagging one, so the register is
/// exactly the flagged set and can only shrink when the CODE changes.
///
/// ⭐ HOW IT GOT THIS SHORT. The first rule flagged 10 functions; **9 of them propagate their failure**
/// (`return false` / `return None`) and were textbook fail-closed. The one real defect was
/// `fold_record_sidecars_inner` — both halves of the sidecar REPLAY loop
/// (`acc.receive(..).is_ok()` and `acc.spend(..).is_ok()`, each with no `else`). A dropped entry there is
/// the "ledger hole" the stranding site later reports, so the hole was made in one function and blamed on
/// another. Both halves now name the refusal and mark the map INCOMPLETE, and the entry left this list
/// because the anti-rot gate failed the build until it did.
///
/// ⭐ EMPTY SINCE 2026-10-04. The last two rows — `fold_canonical_records`'s idle-record write (an EMPTY payload; the
/// writer has no failure return) and `graft_unfolded_carry`'s admitted-record write (the same writer) — left the list
/// the way the law above requires: the CODE changed. Both sites now read the address the writer returns and compare it
/// with the canonical slot the fold addresses, printing a legible line on a mismatch; the returned value is used, so the
/// rule no longer flags either site, and `nothing_filed_is_stale` would have failed the build had the rows stayed.
pub const FILED_SILENT: &[(&str, &str)] = &[];

/// Clamp a byte index to the next lower UTF-8 char boundary.
///
/// ⛔ NOT COSMETIC. This tree's source is dense with `⛔`, `⭐` and `…`, so a fixed-size lookahead window
/// lands inside a multi-byte character constantly, and `&src[a..b]` PANICS there. The census panicked on
/// its first run at exactly this — byte 475041, inside a `…`.
fn floor_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Read one source file with `#[cfg(test)]` modules and `#[test]` functions blanked out.
///
/// THE STRIPPING IS THE WHOLE ACCURACY OF THIS CENSUS. A first pass that did not strip test bodies
/// reported 93 writers, 37 of which were test functions — a list with test functions in it is exactly the
/// kind of "derived" answer that is really a guess.
fn production_source(path: &std::path::Path) -> String {
    let Ok(src) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let n = src.len();
    let b = src.as_bytes();
    let mut keep = vec![true; n];
    for marker in ["#[cfg(test)]", "#[test]"] {
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(marker) {
            let start = at + rel;
            let win_end = floor_boundary(&src, (start + 1200).min(n));
            let win = &src[start..win_end];
            let kw = match (win.find("mod "), win.find("fn ")) {
                (Some(a), Some(c)) => Some(a.min(c)),
                (Some(a), None) => Some(a),
                (None, Some(c)) => Some(c),
                (None, None) => None,
            };
            if let Some(kw) = kw {
                if let Some(brace) = win[kw..].find('{') {
                    let open = start + kw + brace;
                    let mut depth = 0usize;
                    let mut i = open;
                    while i < n {
                        match b[i] {
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    for k in keep.iter_mut().take((i + 1).min(n)).skip(start) {
                        *k = false;
                    }
                }
            }
            at = start + marker.len();
        }
    }
    src.char_indices().filter(|(i, _)| keep[*i]).map(|(_, c)| c).collect()
}

/// Every production function that writes retention state, as `file::fn -> structures`.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: reads this repository's own source files and returns function NAMES.
/// No chain value, note, tag, amount, key or owner is involved.
pub fn derive_retention_writers() -> BTreeMap<String, BTreeSet<Structure>> {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut out: BTreeMap<String, BTreeSet<Structure>> = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            let rel = p
                .strip_prefix(concat!(env!("CARGO_MANIFEST_DIR"), "/"))
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string();
            let src = production_source(&p);
            let mut cur = String::from("<top>");
            for line in src.lines() {
                let t = line.trim_start();
                for pre in ["pub(crate) fn ", "pub(super) fn ", "pub async fn ", "pub fn ", "fn "] {
                    if let Some(rest) = t.strip_prefix(pre) {
                        cur = rest
                            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                            .next()
                            .unwrap_or("")
                            .to_string();
                        break;
                    }
                }
                let code = line.split("//").next().unwrap_or("");
                if code.trim().is_empty() {
                    continue;
                }
                for s in Structure::all() {
                    if s.patterns().iter().any(|p| code.contains(p)) {
                        out.entry(format!("{rel}::{cur}")).or_default().insert(s);
                    }
                }
            }
        }
    }
    out
}

/// Every source file concatenated — what "a test names this" is answered against.
fn all_source() -> String {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut out = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                if let Ok(s) = std::fs::read_to_string(&p) {
                    out.push_str(&s);
                }
            }
        }
    }
    out
}

/// The identifiers inside `#[test] fn` bodies only.
fn test_bodies() -> String {
    let all = all_source();
    let mut out = String::new();
    let b = all.as_bytes();
    let mut at = 0usize;
    while let Some(rel) = all[at..].find("#[test]") {
        let start = at + rel;
        let win_end = floor_boundary(&all, (start + 1200).min(all.len()));
        if let Some(kw) = all[start..win_end].find("fn ") {
            if let Some(brace) = all[start + kw..win_end].find('{') {
                let open = start + kw + brace;
                let mut depth = 0usize;
                let mut i = open;
                while i < all.len() {
                    match b[i] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                let body = &all[start..floor_boundary(&all, (i + 1).min(all.len()))];
                // ⛔ COMMENTS INSIDE A TEST ARE NOT A PIN. Measured 2026-09-16: the first version of
                // this scan matched raw text, and three writers came back "named by a test" purely
                // because a comment in a test body mentioned them. A doc line saying a function is
                // load-bearing asserts nothing about it — only CODE that calls it does. This tree's
                // tests are comment-dense by house style, so without this strip the census would
                // report coverage that does not exist, which is the exact failure it was built to end.
                for l in body.lines() {
                    out.push_str(l.split("//").next().unwrap_or(""));
                    out.push('\n');
                }
            }
        }
        at = start + 7;
    }
    out
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// The body of one production function, comments stripped, from its `fn` line to the next one.
    fn function_bodies() -> BTreeMap<String, String> {
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                // ⛔ THE CENSUS DOES NOT AUDIT ITSELF. `Structure::patterns` holds the write patterns as
                // STRING LITERALS, so scanning this file matches every one of them and reports the
                // census as a retention writer that swallows — measured on the first run after the rule
                // was factored out (`src/harness/fund_loss.rs::all`, 57 writers became 58). A detector
                // that counts its own detector is not a finding, it is a mirror.
                if p.ends_with("harness/fund_loss.rs") {
                    continue;
                }
                let rel = p
                    .strip_prefix(concat!(env!("CARGO_MANIFEST_DIR"), "/"))
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string();
                let src = production_source(&p);
                let mut cur = String::from("<top>");
                let mut body = String::new();
                for line in src.lines() {
                    let t = line.trim_start();
                    let mut is_fn = false;
                    for pre in ["pub(crate) fn ", "pub(super) fn ", "pub async fn ", "pub fn ", "fn "] {
                        if let Some(rest) = t.strip_prefix(pre) {
                            out.insert(format!("{rel}::{cur}"), std::mem::take(&mut body));
                            cur = rest
                                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                .unwrap_or("")
                                .to_string();
                            is_fn = true;
                            break;
                        }
                    }
                    if is_fn {
                        continue;
                    }
                    body.push_str(line.split("//").next().unwrap_or(""));
                    body.push('\n');
                }
                out.insert(format!("{rel}::{cur}"), body);
            }
        }
        out
    }

    /// ⛔⛔⛔ NO RETENTION WRITER SWALLOWS A FALLIBLE WRITE.
    ///
    /// ⭐ THE RULE IS NARROW ON PURPOSE, AND TWO WIDER ONES WERE MEASURED WRONG FIRST.
    ///   * *"is it named by a test?"* — the test-body extractor ran past the `#[test] fn` into production
    ///     code and reported three writers as pinned that no test calls. Sound-looking, wrong.
    ///   * *"does the function contain a drop shape anywhere?"* — 10 hits, and **9 of them propagate**
    ///     (`return false` / `return None`): textbook fail-closed, flagged as defects.
    ///
    /// What survives contact with the code is: a retention write whose result is dropped **on its own
    /// line**, with no propagation and no diagnostic in the surrounding statement. `with_params` folds
    /// the genesis cover set with `if acc.receive(..).is_ok() { .. } else { present_complete = false }`
    /// and then logs — that is the CORRECT shape and this rule must not flag it.
    ///
    /// ⭐ BORROWED STANDARD — BITCOIN'S `CValidationState`, ETHEREUM'S STF: a rejection always carries a
    /// reason, and an apply that cannot reach the expected post-state names the rule it violated.
    /// Every site the SWALLOW rule flags — the single source both gates read, so they cannot drift.
    fn swallowed_sites() -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                // ⛔ THE CENSUS DOES NOT AUDIT ITSELF. `Structure::patterns` holds the write patterns as
                // STRING LITERALS, so scanning this file matches every one of them and reports the
                // census as a retention writer that swallows — measured on the first run after the rule
                // was factored out (`src/harness/fund_loss.rs::all`, 57 writers became 58). A detector
                // that counts its own detector is not a finding, it is a mirror.
                if p.ends_with("harness/fund_loss.rs") {
                    continue;
                }
                let rel = p
                    .strip_prefix(concat!(env!("CARGO_MANIFEST_DIR"), "/"))
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string();
                let src = production_source(&p);
                let lines: Vec<&str> = src.lines().collect();
                let mut cur = String::from("<top>");
                for (n, raw) in lines.iter().enumerate() {
                    let t = raw.trim_start();
                    for pre in ["pub(crate) fn ", "pub(super) fn ", "pub async fn ", "pub fn ", "fn "] {
                        if let Some(rest) = t.strip_prefix(pre) {
                            cur = rest
                                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                .unwrap_or("")
                                .to_string();
                            break;
                        }
                    }
                    let line = raw.split("//").next().unwrap_or("");
                    let writes = Structure::all()
                        .iter()
                        .any(|s| s.patterns().iter().any(|q| line.contains(q)));
                    if !writes || !SILENT_DROP.iter().any(|d| line.contains(d)) {
                        continue;
                    }
                    // THE PROPAGATION WINDOW. `let ok = <write>.is_ok();` followed a few lines later by
                    // `if !ok { return false }` IS fail-closed; a 3-line window called those swallows,
                    // and `with_params`'s `else { present_complete = false }` + log is correct too.
                    let lo = n.saturating_sub(2);
                    let hi = (n + 9).min(lines.len());
                    let ctx: String = lines[lo..hi]
                        .iter()
                        .map(|l| l.split("//").next().unwrap_or(""))
                        .collect::<Vec<_>>()
                        .join("\n");
                    if ["return", "Err(", "eprintln!", "?;", "panic!", "assert", "break"]
                        .iter()
                        .any(|k| ctx.contains(k))
                    {
                        continue;
                    }
                    out.insert(format!("{rel}::{cur}"));
                }
            }
        }
        out
    }


    #[test]
    fn no_retention_writer_swallows_a_fallible_write() {
        let writers = derive_retention_writers();
        let filed: BTreeSet<&str> = FILED_SILENT.iter().map(|(n, _)| *n).collect();
        let flagged = swallowed_sites();
        let unfiled: Vec<&String> =
            flagged.iter().filter(|s| !filed.contains(s.as_str())).collect();
        eprintln!(
            "[fund-loss] {} production retention writers derived; {} flagged as swallowed; {} filed",
            writers.len(),
            flagged.len(),
            FILED_SILENT.len()
        );
        assert!(
            unfiled.is_empty(),
            "A RETENTION WRITE IS SWALLOWED — dropped on its own line, with nothing propagated and \
             nothing said: {unfiled:?}\n\nThat is the shape of both the 2026-08-09 silent-copath bug (a \
             second settlement left the root byte-identical) and the 2026-08-13 stranded drip: fund loss \
             wearing the shape of a no-op. Name the refusal, or file it with the reason."
        );
    }

    /// ⛔⛔⛔ NOTHING FILED IS STALE — THE ANTI-ROT GATE, AND IT IS THE POINT.
    ///
    /// The register must be EXACTLY what the rule flags. An entry the rule no longer flags is a closed
    /// hole still being reported as open, and a funds-loss list built from it is wrong.
    ///
    /// THE RECEIPT IS IN THIS REPOSITORY. `value_creation::DESTRUCTION_SITES_WITHOUT_AUTHORITY` still
    /// reads *"any block producer can burn any note on every node"*; §BB closed that and
    /// `Node::graft_admitted_deletions` has been wired in production since. The const was never updated,
    /// so every funds-loss list assembled from it carried a closed hole as an open one.
    ///
    /// It has already earned its keep: it failed the build when `fold_record_sidecars_inner` gained its
    /// refusals, forcing the register from 10 entries down to 3.
    #[test]
    fn nothing_filed_is_stale() {
        let flagged = swallowed_sites();
        let stale: Vec<&str> = FILED_SILENT
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| !flagged.contains(*s))
            .collect();
        assert!(
            stale.is_empty(),
            "{stale:?} are no longer flagged by the rule — take them out of FILED_SILENT. A register \
             that can only grow is a register nobody can act on."
        );
    }

    /// EVERY FILED ENTRY NAMES ITS REASON. "Not done yet" is not a reason.
    #[test]
    fn every_filed_silent_writer_names_why() {
        let thin: Vec<&str> =
            FILED_SILENT.iter().filter(|(_, why)| why.len() < 60).map(|(n, _)| *n).collect();
        assert!(thin.is_empty(), "{thin:?} are filed with no usable reason");
    }

    /// THE CALIBRATION — the derivation must find real writers, exclude test code, and the silent-drop
    /// detector must actually discriminate.
    ///
    /// Without this a scanner that matched nothing would report "0 silent writers" and read exactly like
    /// a clean bill of health. `super::vacuity`'s whole subject is gates that never ran.
    #[test]
    fn the_derivation_finds_real_writers_and_the_detector_discriminates() {
        let w = derive_retention_writers();
        // ⛔ THE FLOOR MOVED 40 -> 30 ON 2026-09-23, AND WHY IT MOVED IS THE WHOLE POINT. The Z-build
        // deleted the deletion/presence lane, and its writers went with it: the tree now has 39, so a
        // floor of 40 was failing because the CODE shrank, not because the SCAN stopped matching. A
        // floor exists to catch a scanner that matched NOTHING and therefore reports "0 silent writers"
        // as a clean bill of health; 39 is not nothing.
        //
        // ⛔ IT IS NOT SET TO 39. A bound tightened to exactly today's number passes by construction and
        // measures nothing the next time the tree moves — that is the shape where a threshold gets
        // nudged to fit instead of re-derived. 30 keeps a real margin under the observed 39 while still
        // failing loudly if the scan's reach collapses.
        assert!(
            w.len() >= 30,
            "the retention scan found only {} writers — it has stopped matching the tree it audits",
            w.len()
        );
        // ⛔ REPOINTED 2026-09-23. These named `advance_unspent_notes_for_block_inner` and
        // `set_unspent_root`, which the Z-build DELETED with the deletion/presence lane — so the
        // calibration was asserting that a derived scan finds two functions that no longer exist, and
        // it went red the moment anything else in this file was touched. A calibration must name
        // something the CURRENT tree has, or it stops measuring the scan and starts measuring history.
        assert!(
            // the §SPLIT (2a95f22) moved the admission filter into node/ingest.rs; the calibration names where it lives now
            w.contains_key("src/node/ingest.rs::graft_admitted_notes"),
            "the scan misses the admission filter — a note refused there is a note its owner cannot find"
        );
        assert!(
            w.contains_key("src/node/ingest.rs::record_note_payload"),
            "the scan misses the note-record writer, the most retention-critical function here"
        );
        let leaked: Vec<&String> = w
            .keys()
            .filter(|k| k.contains("::a_") || k.contains("::the_") || k.contains("::diag_"))
            .collect();
        assert!(
            leaked.is_empty(),
            "the test-stripper leaked {} test function(s) into the production census: {:?} — a derived \
             list with test functions in it is a guess wearing a derivation's clothes",
            leaked.len(),
            leaked
        );
        // THE DETECTOR MUST SAY NO SOMEWHERE: the fold arm that reports stranding DOES name its refusal,
        // so it must NOT be flagged. A detector that flags everything is as useless as one that flags
        // nothing.
        let bodies = function_bodies();
        // ⛔ REPOINTED 2026-09-23 — this named `advance_unspent_notes_for_block_inner`, deleted by the
        // Z-build with the presence lane, so the discriminator was asserting on a function the tree no
        // longer has. `graft_admitted_notes` is the equivalent arm today: it is the admission filter a
        // note must pass to be recorded, and it NAMES every refusal rather than dropping it silently.
        // ⛔ REPOINTED AGAIN 2026-10-03 — 6329ccf (the DSYNC tip fix) made `graft_admitted_notes` a two-line wrapper over
        // `graft_admitted_notes_given`, which now holds the judgement and its five named refusals. The first recorded run
        // of this pin (pin ledger, 22:39) was RED on the wrapper's empty body: the arm moved, the naming did not stop.
        let strand_arm = bodies
            .get("src/node/ingest.rs::graft_admitted_notes_given")
            .expect("the admission filter is in the census");
        assert!(
            strand_arm.contains("eprintln!"),
            "the admission filter no longer names its refusals — the one arm that made the live loss \
             visible at all has gone quiet"
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE REPRODUCER AND THE CORPUS — what makes a find PERMANENT.**
//!
//! ⛔⛔ WHY THIS FILE WRITES NOTHING TO DISK, AND WHAT THAT COSTS.
//!
//! The original design for this module PERSISTED the corpus and the emitted reproducers as files, so a
//! campaign could resume where the last one stopped. That design is refused by this repo's local-storage
//! ban — "PROOF NOT STORAGE… BAN LOCAL STORAGE WRITES ECOSYSTEM WIDE" — which has no escape marker and
//! names any exception as a USER decision, not a reviewed comment. So this module RENDERS artefacts as
//! text and hands them to whoever ran it, and persistence happens the way this tree already does it for
//! `consensus_scenarios.txt`: a human pastes the printed block into a source file that is `include_str!`-ed
//! and lives in version control.
//!
//! That is a real trade and it is stated rather than hidden:
//!
//! | | file-backed corpus (refused) | source-backed corpus (this) |
//! |---|---|---|
//! | survives a reboot | yes, automatically | yes, once pasted |
//! | survives a `git clone` | no | **yes** |
//! | reviewable | no | **yes — it lands in a diff** |
//! | grows unattended | yes | no |
//! | costs a human step | no | **yes, and that is the gap** |
//!
//! The honest cost is the last row: an unattended overnight campaign accumulates nothing unless someone
//! reads its output. Closing that needs a user decision on the storage ban, and it is reported as an open
//! item rather than worked around.
//!
//! **cons: none.** Everything here is string formatting over an op sequence of at most
//! `engine::MAX_STEPS` = 48 entries. No I/O, no allocation that scales with the chain, no term in blocks,
//! notes or peers.

use crate::harness::fuzz::op::{as_case, as_corpus, Op};
use crate::harness::fuzz::shrink::ShrinkReport;

/// The seed corpus, in version control, exactly the way `consensus_scenarios.txt` is.
///
/// Each block is one sequence that was INTERESTING — it reached a behaviour no earlier sequence in this
/// file reached. A campaign replays every one of these BEFORE it generates anything new, so a class found
/// once is re-checked on every run, forever, by anyone, from a clean clone.
pub const CORPUS: &str = include_str!("corpus_seeds.txt");

/// Split [`CORPUS`] into its entries. Blocks are separated by a line of three dashes.
///
/// A block that carries no OP LINE at all — the file's own header prose, or a block someone commented out
/// — is not an entry and is dropped here rather than handed to the parser. This matters: the corpus test
/// asserts that ZERO entries were unreadable, and the file's explanatory header would otherwise count as
/// an unreadable entry and make an empty corpus look like a broken one.
///
/// cons: none — one pass over a compile-time constant string.
pub fn corpus_entries() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut has_op_line = false;
    for line in CORPUS.lines() {
        if line.trim() == "---" {
            if has_op_line {
                out.push(current);
            }
            current = String::new();
            has_op_line = false;
        } else {
            if !line.trim().is_empty() && !line.trim().starts_with('#') {
                has_op_line = true;
            }
            current = format!("{current}{line}\n");
        }
    }
    if has_op_line {
        out.push(current);
    }
    out
}

/// ⭐⭐⭐ RENDER A MINIMAL FAILING CASE AS A STANDALONE `#[test]`.
///
/// The output is complete and self-contained: the op sequence as literals, the seed, the party count, the
/// invariant it must reproduce, what the node actually did, and whether minimality was PROVEN or merely
/// reached. It is meant to be pasted into a permanent pin unchanged.
///
/// The assertion it generates is deliberately two-part — the sequence must still fail, AND it must fail on
/// the SAME invariant. A reproducer that only asserts "something failed" turns green the moment an
/// unrelated bug masks the original one, which is the failure mode that makes regression suites lie.
pub fn reproducer_source(ops: &[Op], report: &ShrinkReport) -> String {
    let mut literals: Vec<String> = Vec::new();
    for op in ops {
        literals.push(format!("        {},", op.to_rust()));
    }

    let minimality = if report.budget_exhausted {
        format!(
            "NOT PROVEN 1-minimal — the shrinker used its whole budget of {} candidates. This case does \
             reproduce the finding; it may not be the smallest case that does.",
            report.candidates_run
        )
    } else {
        format!(
            "1-MINIMAL — removing ANY single op below makes the finding disappear. Proven in {} \
             candidate runs.",
            report.candidates_run
        )
    };

    let ident = sanitise(report.invariant, '_');
    let name = format!("{}-seed-{:016x}", sanitise(report.invariant, '-'), report.seed);

    format!(
        "// Copyright (c) 2026, The MoneroUSD Protocol\n\
         // SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root).\n\
         //\n\
         // EMITTED BY THE LANE-F INVARIANT FUZZER — paste this into a permanent pin.\n\
         //\n\
         // INVARIANT VIOLATED : {invariant}\n\
         // WHAT THE NODE DID  : {detail}\n\
         // SHRUNK             : {before} ops -> {after} ops, {parties} parties\n\
         // MINIMALITY         : {minimality}\n\
         \n\
         #[test]\n\
         fn fuzz_repro_{ident}_seed_{seed:016x}() {{\n\
         \x20   use crate::harness::fuzz::engine::run_sequence;\n\
         \x20   use crate::harness::fuzz::op::Op;\n\
         \x20   let ops = vec![\n{literals}\n\x20   ];\n\
         \x20   let outcome = run_sequence({parties}, 0x{seed:016x}, &ops);\n\
         \x20   let finding = outcome.finding.expect(\n\
         \x20       \"this sequence must still reproduce the finding it was emitted for. If it does not, \\\n\
         \x20        the hole is FIXED — turn this into a MUST-STAY-GREEN pin rather than deleting it.\",\n\
         \x20   );\n\
         \x20   assert_eq!(\n\
         \x20       finding.invariant, \"{invariant}\",\n\
         \x20       \"the sequence still fails, but on a DIFFERENT invariant — a new bug, not this one\"\n\
         \x20   );\n\
         }}\n\
         \n\
         /* paste this block into src/harness/fuzz/corpus_seeds.txt to keep the class covered forever:\n\
         \n{corpus}---\n*/\n\
         \n\
         /* or into consensus_scenarios.txt, to cover it on every backend:\n\n{case}*/\n",
        invariant = report.invariant,
        detail = report.detail,
        before = report.before_len,
        after = report.after_len,
        parties = report.parties,
        seed = report.seed,
        minimality = minimality,
        ident = ident,
        literals = literals.join("\n"),
        corpus = as_corpus(report.parties, report.seed, ops),
        case = as_case(&name, report.parties, ops),
    )
}

/// The corpus block for a sequence that was merely INTERESTING rather than failing — what a campaign
/// prints so a human can widen the permanent corpus.
pub fn corpus_block(parties: usize, seed: u64, ops: &[Op], signature: u64) -> String {
    format!("# signature {signature:016x}\n{}---\n", as_corpus(parties, seed, ops))
}

/// Lower-case an invariant id and collapse every non-alphanumeric run to a single `sep`, with no leading
/// or trailing separator. Written over bytes so it depends on no character-class helper.
///
/// cons: none — one pass over a `&'static str` of a few dozen bytes, fixed at compile time.
fn sanitise(invariant: &str, sep: char) -> String {
    let mut s = String::new();
    let mut pending_sep = false;
    for b in invariant.bytes() {
        let keep: Option<char> = match b {
            b'a'..=b'z' | b'0'..=b'9' => Some(b as char),
            b'A'..=b'Z' => Some((b + 32) as char),
            _ => None,
        };
        match keep {
            Some(c) => {
                if pending_sep && !s.is_empty() {
                    s = format!("{s}{sep}");
                }
                pending_sep = false;
                s = format!("{s}{c}");
            }
            None => pending_sep = true,
        }
    }
    s
}

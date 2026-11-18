// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE VACUITY CENSUS — DID THE GATE ACTUALLY RUN, OR DID IT RETURN `true` WITHOUT LOOKING?
//!
//! ⛔⛔⛔ WHY THIS EXISTS, AND IT IS NOT A HYPOTHETICAL. Every other instrument in this harness asks
//! **"is every X enumerated?"** — [`super::value_creation`] derives its site list by parsing source,
//! [`super::seam`] finds modules with zero production callers, [`super::privacy`] derives `Block`'s fields
//! from `block.rs`, [`super::e2e_claims`] makes every value class name a pin. Not one of them asks
//! **"did this gate EXECUTE, on an input that could have failed it?"**
//!
//! That gap cost four live consensus defects in one day (2026-09-15). The fuzz corpus's spend fixture set
//! `nullifiers: Vec::new()`, and every nullifier gate has an early return — *"a nullifier-free tx (cover /
//! coinbase) carries none and passes vacuously"*, *"no spends → nothing to double-spend-check"*. The gates
//! returned `true` without running. The census saw a site with a gate attached and called it covered, and
//! **§CC** (a DSYNC joiner can receive money and never move it), **§CD** (the spend carrier is not
//! byte-deterministic), **§CE** (the nullifier accumulator diverged on every body-less peer) and the
//! `AlreadyPresent` fund-stranding defect all sat behind that one shortcut.
//!
//! ⭐ **COVERAGE OF CODE PATHS IS NOT COVERAGE OF GATE DECISIONS.** A line can be executed a thousand times
//! and decide nothing. What matters is whether the gate was ever handed an input it could have REFUSED.
//!
//! ⛔ AND THE PROJECT ALREADY HAD THE LESSON AND DID NOT GENERALISE IT. `Node::spend_tx_for_test`'s own doc
//! records the same mistake twice — an id that bound nothing (*"0 of 28 sends landed across 16 campaign
//! runs"*) and an unground anti-spam stamp — and `a_campaign_actually_lands_sends_it_does_not_merely_
//! schedule_them` exists to catch "the send path was never walked". But that pin only asks whether a send
//! LANDED. A send that lands while skipping four doors still counts. One lesson, three instruments that
//! could have been built from it, zero built until now.
//!
//! ## HOW IT WORKS
//!
//! A gate calls [`record`] on every decision, saying whether that decision was REAL (it examined something
//! that could have failed) or VACUOUS (an early return over an empty/absent input). The census then asserts
//! that every registered gate has been handed at least one REAL decision. A gate whose real arm never ran
//! is reported by name — it is not covered, however green the suite is.
//!
//! O1-FOOTPRINT-REVIEWED: a fixed-size table of `(name, real, vacuous)` counters, one row per REGISTERED
//! gate (a compile-time constant list). It takes no term in height, blocks, notes or transactions, and it
//! is test-only — `record` compiles to nothing outside `cfg(test)`.

use std::sync::atomic::{AtomicU64, Ordering};

/// One consensus gate that has a vacuous arm, and what that arm is.
///
/// ⛔ ADDING A GATE HERE IS THE POINT. A gate with an early return that is NOT listed is a gate nobody is
/// checking ran — which is the condition this module exists to make visible.
pub struct Gate {
    /// The function the decision lives in.
    pub name: &'static str,
    /// The input shape that makes it return without deciding — quoted from the code where possible.
    pub vacuous_when: &'static str,
    /// What a REAL decision means here: the thing it could have refused.
    pub real_means: &'static str,
}

/// The registered gates. Each has a counter pair at the same index in [`COUNTS`].
pub const GATES: &[Gate] = &[
    Gate {
        name: "Node::nullifier_witnesses_gate",
        vacuous_when: "tx.nullifiers.is_empty() — \"cover / coinbase — nothing to gate\"",
        real_means: "a spend-bearing tx was checked against the O(1) nullifier accumulator",
    },
    Gate {
        name: "Node::tx_double_spend_free",
        vacuous_when: "no spends — \"nothing to double-spend-check (e.g. a coinbase / reward-only tx)\"",
        real_means: "a tx naming at least one spend was checked for a cross-block double spend",
    },
    Gate {
        name: "Node::graft_admitted_notes",
        vacuous_when: "the block carries no notes, so no admission decision is made",
        real_means: "a carried note was judged against the transition, the credit set or the bond map",
    },
    // ⛔ `Node::graft_admitted_deletions` WAS REGISTERED HERE AND THE FUNCTION NO LONGER EXISTS.
    //
    // Removed 2026-09-22. This registration is NOT being deleted to silence a gate that merely lacks a
    // workload — that is the move this census exists to refuse, and its own failure message says so
    // ("Fix the WORKLOAD ... never the registration"). It is deleted because the DELETION TREE ITSELF
    // was retired by the Z-build: `grep -n 'fn graft_admitted_deletions' src/node.rs` returns nothing,
    // and the only surviving mention in the tree was a stale comment at node.rs:1796 describing a
    // function that had already gone. A spent note is now refused by the NULLIFIER SET (the Zcash
    // shape), so there is no deletion for any gate to judge and no input that could ever reach it.
    //
    // A registration naming a deleted function is the same defect as the 19 stale field entries the
    // authority manifest carried and the `unspent_notes` seam entry beside them: a manifest that
    // describes code which is gone reads as coverage while protecting nothing.
    Gate {
        name: "note_transition::verify",
        vacuous_when: "the block carries no transition, so no allow-list is built",
        real_means: "a bound aggregate was verified and an allow-list derived from it",
    },
    Gate {
        name: "chain_object::wrapper_binds_object",
        vacuous_when: "the tx carries no framed object, so there is no carriage to bind",
        real_means: "a framed object's declared notes were compared with its wrapper's",
    },
    // ⭐⭐⭐ A SECOND VACUITY SHAPE, AND IT IS NOT AN EMPTY INPUT — IT IS A **SPLIT GATE**.
    //
    // Every gate above goes vacuous because it was handed nothing. This one goes vacuous because its
    // ADMIT arm can be REACHED without the check that justifies it: `nf_absent_by_reconstructed_tip`'s
    // base-state lane admits on *"a carrier is declared and the witness list is non-empty"*, and the
    // substantive half — each copath folded against the live sparse root — runs in the CALLER, one frame
    // up (`nullifier_witnesses_gate`). Two consequences, both found by measuring on 2026-09-16 (§CF):
    //
    //   1. any OTHER caller of the inner function gets an admit with no authority at all (audited: today
    //      there is exactly one caller, and a pre-check I added became the second for one build — it
    //      answered `absent` for every tag and decided nothing);
    //   2. the copath lane is UNSATISFIABLE from a node's first produced block, because `sparse_acc` is
    //      then the A_tip fold accumulator and no Merkle copath can fold to it — so on any realistic
    //      workload this lane's real arm never runs, and nothing said so.
    //
    // Registering it makes (2) a NUMBER instead of a comment: if `real` stays 0 across a suite whose
    // parties produce blocks, the lane is decorative and the fill path has no admission authority.
    Gate {
        name: "Node::nullifier_witnesses_gate::copath_lane",
        vacuous_when: "tx.nullifier_witnesses.is_empty() — the tx carries no live-root copaths at all",
        real_means: "a carried copath was actually folded against this node's live sparse root",
    },
];

/// `(real, vacuous)` per gate, indexed like [`GATES`].
/// O1-FOOTPRINT-REVIEWED: a fixed array sized by the constant `GATES`, never by workload.
static COUNTS: [(AtomicU64, AtomicU64); 7] = [
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
    (AtomicU64::new(0), AtomicU64::new(0)),
];

/// Record one decision. `vacuous` is TRUE when the gate returned over an empty/absent input without
/// examining anything that could have failed it.
///
/// ⛔ CALL THIS ON EVERY PATH OUT OF THE GATE, including the refusals — a gate that only records its
/// accepts cannot tell "never ran" from "ran and always passed", which is the distinction that matters.
pub fn record(name: &'static str, vacuous: bool) {
    if let Some(i) = GATES.iter().position(|g| g.name == name) {
        let c = &COUNTS[i];
        if vacuous {
            c.1.fetch_add(1, Ordering::Relaxed);
        } else {
            c.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `(real, vacuous)` for a gate by name.
#[must_use]
pub fn counts(name: &str) -> (u64, u64) {
    GATES
        .iter()
        .position(|g| g.name == name)
        .map(|i| (COUNTS[i].0.load(Ordering::Relaxed), COUNTS[i].1.load(Ordering::Relaxed)))
        .unwrap_or((0, 0))
}

/// Every gate whose REAL arm has never run in this process.
#[must_use]
pub fn never_really_ran() -> Vec<&'static str> {
    GATES
        .iter()
        .enumerate()
        .filter(|(i, _)| COUNTS[*i].0.load(Ordering::Relaxed) == 0)
        .map(|(_, g)| g.name)
        .collect()
}

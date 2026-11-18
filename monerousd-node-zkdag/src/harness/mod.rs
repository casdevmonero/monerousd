// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE ADVERSARIAL HARNESS.** Not a test suite: the instrument that decides whether real user funds
//! are safe. A test suite answers "does this code do what its author meant?". The harness answers
//! "does any reachable sequence of real door calls break a catalogue invariant?".
//!
//! Lane F — the stateful invariant fuzzer — lives in [`fuzz`]. Lane C — CIRCUIT SOUNDNESS, the
//! adversary that asks whether the ZK proofs CONSTRAIN what they claim — lives in [`circuit`]. Lane M
//! (mutation) is a separate module owned by a separate author; this file registers only what has
//! landed, so a missing lane is visible as a missing module rather than as an unstated gap.
//!
//! ⛔ SCOPE, stated before any result is cited: everything here is an IN-PROCESS island. It proves
//! nothing about the onion transport, per-node cost, or scale. The live pair gate and the multi-device
//! run at the scale floor remain the only network proofs.

#![allow(dead_code)]

/// LANE C — CIRCUIT SOUNDNESS. The highest-risk surface: if a public input is unconstrained or a
/// balance check is not enforced IN-CIRCUIT, that is unlimited minting with every other test green
/// and no door audit able to see it.
#[cfg(feature = "pins-harness")] pub mod circuit;
/// ⭐ NETSIM — the daemon's relay and producer loops on a simulated clock over a Tor-latency wire with BOTH lanes:
/// the production pull relay no other in-process mesh runs (DB-326). A discovery instrument, calibrated first.
pub mod netsim;
#[cfg(feature = "pins-harness")] pub mod mix_journey; // §BR-6 B6-c: the entry mix on the simulated mesh
pub use crate::test_census::sim_coverage; // what the simulator touched — every route and wire kind, vs the tree's universes (user 2026-10-06)
/// ⛔ THE SEAM CENSUS — does anything in PRODUCTION call this subsystem? The instrument the DA gap
/// (kill list §AM) got past: it sat with zero callers behind a dozen comments calling it the note store.
pub mod e2e_claims;

/// ⭐⭐⭐ THE FUNCTIONAL TIER — journeys driven against the REAL `usdmd-node` binary over its real RPC.
///
/// Everything else under `harness` runs IN PROCESS, and `mod harness` is already `#[cfg(test)]`, so
/// nothing here is linked into the shipped node. The distinction this module exists to draw is not
/// test-vs-ship but FIXTURE-vs-CHAIN: an in-process pin cannot tell a chain that refuses from a fixture
/// that forgot its setup, and on 2026-09-16 we read one as the other for three turns.
pub mod real_node_journey;
#[cfg(feature = "pins-harness")]
pub mod ui_layer2; // ⭐ R7 LAYER 2: the shipped wallet UI against a simulated mesh (the `ui-harness` binary)
/// ⭐⭐⭐ THE VALUE-CREATION CENSUS — every site that brings value into existence must answer AUTHORITY,
/// AMOUNT and ONCE. The instrument §AT, §AV and §AX each got past on the day they landed.
pub mod value_creation;
/// ⭐⭐⭐ THE OBSERVABLE-SURFACE CENSUS — the privacy mirror of [`value_creation`]. Every surface an
/// observer can SEE must answer what viewing it reveals, and the SHAPE axis is MEASURED rather than
/// declared: a proof can be perfectly zero-knowledge and still publish the real spend count in its
/// LENGTH (measured 2026-09-15, §BW).
pub mod privacy;
pub mod readiness;
// ⛔⛔⛔ THE ROGUE-ROLE CENSUS (2026-10-03): every chain-object class × {forge, strip, substitute, replay}, pinned or open.
pub mod rogue_census;
#[cfg(feature = "pins-harness")] pub mod adversary_census; // the adversaries no surface census measures, as simulated events with recorded pins (user 2026-10-04)
#[cfg(feature = "pins-harness")] pub mod crypto_parameters; // H12: crypto parameters COMPUTED from what the code runs (FIPS 203/204 sizes, Poseidon2 inequalities)
// ⛔⛔⛔ THE ONE-SWEEP HOLE SCANNER (user 2026-10-03): every census, every open hole, by name, in one cheap run.
#[cfg(feature = "pins-harness")] pub mod holes;
// ⛔⛔⛔ THE APP HALF of the sweep (user 2026-10-03: the ecosystem includes the launchpad apps): wallet + every sites/ bundle.
#[cfg(feature = "pins-harness")] pub mod app_census;
// ⛔⛔⛔ THE ZERO-BLIND-SPOT LAYER (user 2026-10-03: "0 assumptions … every single inch … tiered"): every surface of the
// ecosystem enumerated from the tree; a surface no measured check covers is a hole.
pub mod surface_census;
pub mod custody; // CUSTODY KEY SAFETY (user 2026-09-28): every secret a node holds, four questions each
#[cfg(feature = "pins-harness")] pub mod fund_loss;
#[cfg(feature = "pins-harness")] pub mod flash_price; // §19.6: the flash-loan price census — no value-moving door reads a movable price
pub use crate::test_census::vacuity;
#[cfg(feature = "pins-harness")] pub mod seam;
pub mod fuzz;

/// The repo's `scratchpad/` (untracked: the pin ledger, known reds, the hole list). Found by walking up from the crate, so a
/// git WORKTREE (whose own root has no scratchpad) reads the main checkout's — MEASURED 2026-10-06: the sweep run from a
/// worktree read no known reds and no pin verdicts and printed H8 as PASS with 0 holes.
pub(crate) fn scratchpad_dir() -> std::path::PathBuf {
    let mut dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    loop {
        let cand = dir.join("scratchpad");
        if cand.join("known-reds.txt").exists() {
            return cand;
        }
        if !dir.pop() {
            return std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scratchpad");
        }
    }
}

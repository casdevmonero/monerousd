// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **LANE F — THE STATEFUL INVARIANT FUZZER.**
//!
//! The question this lane answers, and no other lane can: *does any REACHABLE sequence of real door calls
//! break a catalogue invariant?* Mutation testing cannot see a check that was never written — there is
//! nothing to mutate. Circuit analysis looks at one proof, not at a schedule. Only a stateful fuzzer walks
//! the machine into states nobody thought to write a test for.
//!
//! ```text
//!   rng.rs      the seed IS the run — splitmix64, in-tree, so a recorded seed never moves
//!   op.rs       the ALPHABET: honest ops + a hostile sub-grammar, in consensus_scenarios.txt syntax
//!   engine.rs   drive 2..4 REAL nodes; ask the catalogue after EVERY step
//!   oracle.rs   the CATALOGUE, fixed-width: folds and derived facts, never a store
//!   shrink.rs   ddmin to a 1-minimal case, keyed on the INVARIANT ID and not on "it failed"
//!   report.rs   render the reproducer and the corpus block as text to paste
//!   wire.rs     the hostile WIRE family, generated per class from the class table — and the self-proof
//!   tests.rs    the campaigns
//! ```
//!
//! **What makes this different from the schedule search already in the tree.** That search
//! (`mesh_schedule_search_tests`) generates schedules over the same alphabet and drives the same `Sim`,
//! and it is good. It asserts its property ONCE, after `drain()`. This lane asserts after EVERY step. The
//! difference is not stylistic: a note that leaves the unspent set and comes back, a record folded at one
//! ordinal and renumbered to another, a tip that visits a block nobody mined and moves off it — every one
//! of those is a fund-safety event, and every one is INVISIBLE to an end-of-run verdict. **A violation
//! that self-heals before the end is still a violation.**
//!
//! ⛔ SCOPE, before any result is cited: an in-process island. It proves nothing about the onion
//! transport, per-node cost or scale. The live pair gate and the multi-device run at the scale floor
//! remain the only network proofs.

pub mod calibration;
pub mod engine;
pub mod op;
pub mod oracle;
pub mod report;
pub mod rng;
// ⛔⛔ THE SELF-MINT ADVERSARY IS DECLARED HERE, AND THE DECLARATION IS THE CAPABILITY.
// `selfmint.rs` was written 2026-09-08 carrying rows A4 / D-3 / D-4 and left UNDECLARED, by its own
// note, because the machine's 1-minute load never fell under the charter ceiling and an uncompiled
// module in a shared tree breaks every other crew's `cargo test --lib`. That was the right call at
// the time and the WRONG state to leave calibrated: a 352-line file holding three calibration rows
// that `rustc` never reads is not an instrument, it is a document — the same shape as the phantom
// pin C-5, where a register named a measurement nobody had taken. A harness lane is caught or
// missed by what COMPILES, so the file is declared and the rows are scored on its real verdict.
/// ⛔ THE AUTHORITY MANIFEST — whose state is each of `struct Node`'s 142 fields? Seven registered
/// holes are one class: local state read as truth. This answers it once, for every field, where a
/// test can read it, and ratchets the undecided backlog downward.
pub mod authority;
pub mod authority_book;
pub mod authority_peg;
pub mod selfmint;
/// ⛔ THE REFUTATION LANE — every detector must be SHOWN to fire, and shown NOT to always fire.
/// A green test is worth nothing until someone has made it go red; see the module header for the
/// measured precedent (`I-4 TIP-WEIGHT-SATURATED` shipped unable to fire at all).
pub mod selfproof;
pub mod shrink;
pub mod wire;

#[cfg(all(test, feature = "pins-harness"))]
mod tests;
/// THE DECODE-DOOR REPLAY (B1 (ii), 2026-10-22): every production decoder of outside bytes (`crate::decode_doors`) on
/// the kept fuzz corpus, the crash artifacts and seeded hostile bytes, fail-closed; its green doors are `decode-fuzz`
/// coverage rows the hole scanner closes decode sites by.
#[cfg(all(test, feature = "pins-harness"))]
mod decode_doors_tests;

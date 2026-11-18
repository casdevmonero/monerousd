// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE CONSTRAINT MANIFEST — WHICH VALUE-CARRYING COLUMNS ARE RANGE-BOUND, AND WHICH ARE NOT.**
//!
//! ROOT-LAYER: this sits at the layer where an amount ENTERS THE TRACE, which is where its binding is
//! decided. Not at the verifier (which only READS a column that was already unbound) and not at the
//! node harness (which cannot see this class at all — see below). A manifest anywhere downstream would
//! record a consequence instead of the decision.
//!
//! MEASURED 2026-09-09: 4 trace-column builders in `whir_rec_block.rs`, 0 range-bound, 4 carrying raw
//! field elements; the prover-side `checked_add` idiom appears 13 times in the same file (12 LINES
//! carry it — `grep -c` counts lines, the test counts occurrences; the numbers differ by one line that
//! holds two, and the test's figure is the authoritative one).
//!
//! MUST-STAY-GREEN: this file adds no production code path — it is a manifest plus source-parsing
//! tests, so `usdm-decider`'s 343 lib tests and the node crate's lane-C circuit pins
//! (`harness::circuit::*`) must be unaffected.
//! ⛔ VERIFIED SO FAR, stated exactly rather than implied: the crate COMPILES and its test binary runs
//! (`constraint_manifest` 3 passed, 340 filtered out — so 343 are reachable). A full-suite baseline is
//! NOT yet measured: the first attempt exceeded a 600 s window and returned no `test result:` line at
//! all, which is a timeout and not a verdict. Do not read this line as "the suite is green" until a
//! run has printed one.
//!
//! ⛔ THE CLASS NO FIELD-COMPARISON ORACLE CAN EVER REACH. The node harness answers "does a node hold a
//! value the chain did not produce". It cannot answer "is this constraint system sound", because a
//! circuit that accepts a forged witness is one whose nodes all AGREE — every one verifies the same bad
//! proof and reaches the same state. `I-CP` is silent. `I-3` is silent. The mesh is consistently wrong.
//!
//! So this is the circuit's own manifest, built for the reason the node's authority manifest was: the
//! coverage was CHOSEN, and chosen coverage is where a gap hides. It answers ONE question per
//! value-carrying site — **is the amount range-bound, or a raw field element?** — and ratchets the
//! unbound count downward.
//!
//! ── WHY A RAW FIELD ELEMENT IS AN INFLATION HOLE ────────────────────────────────────────────────
//! `Fa4::from_u64(v)` reduces mod p = 2,130,706,433. Two u64 amounts differing by p become the SAME
//! field element, so `in - out - fee == 0` over the field is satisfied by `out = in + k·p`. USDm is 1e8
//! atomic units, so **amounts alias at 21.31 USDm**. The `checked_add` beside these sites is a check
//! the PROVER performs ON ITSELF and then declines to build — it binds an honest prover and nobody else.
//!
//! ── THE FIX SHAPE IS PROVEN IN THIS CRATE — BUT NOT WHERE I FIRST WROTE ─────────────────────────
//! ⛔ CORRECTION, MEASURED 2026-09-09. I first recorded that `limb_gadgets`'s functions are "already
//! used by other paths". That is FALSE and the distinction matters to whoever lands the fix:
//!   * `limb_gadgets::{push_add, push_carry_bind, push_scale, push_sub, push_mul}` have **ZERO callers
//!     outside their own file** and carry 3 tests. They are unexercised code.
//!   * The TECHNIQUE, however, IS in production: `confidential_solvency.rs` has its own
//!     `push_scale_constraints` — same shape, carry base plus a bit ("pbits") base — called at NINE
//!     sites, in a file carrying 45 tests.
//! So the approach is not speculative, and the model to copy is `confidential_solvency`'s exercised
//! version, NOT the unused gadgets. Building the fix on code that has never run would be its own risk.
//!
//! `limb_gadgets` nevertheless states the shape most clearly:
//!   * `push_carry_bind` bit-decomposes a carry, constrains every bit boolean (`bit * (bit - 1)`) and
//!     binds the reconstruction — that IS a range constraint;
//!   * `push_add` does limb-wise `s = a + b` with a carry chain and NO CARRY OUT OF THE TOP LIMB;
//!   * `push_scale` says it outright: *"the top carry is constrained to zero, so the scaled value
//!     provably fits its block."*
//! Closing these is therefore a TRACE-LAYOUT change (more columns, hence a carrier-format version
//! door), not soundness research — the difference between a week and a quarter, which is why the fix
//! shape is recorded beside each site and not just the defect.

/// How a value-carrying column is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueBinding {
    /// Limb-represented with carries bound to a bit width — the sum provably did not wrap. Sound.
    RangeBound,
    /// ⛔ A RAW FIELD ELEMENT. Any constraint over it holds modulo p, so amounts alias at p. The only
    /// thing between this and inflation is that an HONEST prover declines to build the row.
    FieldOnly,
}

/// Every site that puts a user-controlled AMOUNT into the trace: `(function, what it carries, binding)`.
///
/// A site missing from this list is a site nobody has ruled on, which is why the test below parses the
/// source and fails on a builder it does not recognise.
pub const VALUE_SITES: &[(&str, &str, ValueBinding)] = &[
    // ✅ RANGE-BOUND 2026-09-11 (item 1, site 1 of 4): u64 as 4×16-bit limbs, carry chain with the top
    // carry forced ZERO, every limb bit-decomposed with booleanity + reconstruction — the Zcash value
    // shape, in the exact form `confidential_solvency` already exercises. Acceptance in
    // `whir_rec_block::range_binding_acceptance` (5 pins, mutation-checked: removing the reconstruction
    // constraint turns the 70000-limb pin RED while the control stays green).
    ("spend_carrier_cols", "in_value / out_value / fee — the no-inflation gate itself", ValueBinding::RangeBound),
    // ✅ RANGE-BOUND 2026-09-11 (site 2 of 4): the shared block appended at column 31, gate 0 replaced,
    // legacy value columns 0..3 bound to their limbs by recombination. Acceptance: `site2_spend_main_...`.
    ("spend_main_cols", "in_value / out_value / fee on the arm that IS `spend_ok`", ValueBinding::RangeBound),
    // ✅ RANGE-BOUND 2026-09-11 (site 3 of 4): the value rides the transcript as four 16-bit limbs (a
    // reduced element let a carrier for `v` verify for `v + p` — mutation-checked: collapsing the limbs
    // back to one element turns `site3_a_mint_carrier_for_v_does_not_verify_for_v_plus_p` RED), the
    // trace carries the limbs bit-bound, and the opened column is bound to them by recombination.
    ("mint_validity_cols", "the minted `value` a coinbase/mint commitment opens to", ValueBinding::RangeBound),
    // ✅ RANGE-BOUND 2026-09-11 (site 4 of 4): same shape as site 3; pin `site4_an_asset_mint_...`.
    ("asset_mint_cols", "the minted `value` for a WRAPPED asset", ValueBinding::RangeBound),
    // ✅ RANGE-BOUND (DB-80, 2026-09-19; declared 2026-09-25 — the builders landed without a row and this pin
    // was RED since). Each extends its site-3/4 builder, so the value's limbs are the SAME range block
    // (`MintValidityCommittedGate` / `AssetMintValidityCommittedGate` run `push_u64_range` on it), and the
    // 16 committed-delta limbs (`MVC_V16` / `AMC_V16`) are welded limb-for-limb to those bound limbs.
    ("mint_validity_committed_cols", "the COMMITTED minted `value` (DB-80: never a public input)", ValueBinding::RangeBound),
    ("asset_mint_committed_cols", "the COMMITTED minted `value` of a WRAPPED asset (DB-80)", ValueBinding::RangeBound),
    // ✅ RANGE-BOUND (DB-365 reward-follows-principal, landed 2026-10-02; declared 2026-10-03 — found RED by the
    // one-sweep scanner's strict circuit pass: the builder landed without a row). The reward `r` and the principal
    // weight `w` are filled by `fill_u64_range_row` at `RF_R` / `RF_W` (the shared u64 range block) and ride the
    // transcript as u64 limbs. Alias pin (site 7): `db365_site7_a_reward_carrier_for_r_does_not_verify_for_r_plus_p_
    // nor_for_w_plus_p`.
    ("reward_follows_cols", "the stake REWARD `r` and the principal WEIGHT `w` (DB-365)", ValueBinding::RangeBound),
];

/// The ceiling on `FieldOnly` sites. **MAY BE LOWERED, NEVER RAISED.**
///
/// ⛔ NOT A CHOSEN NUMBER — MEASURED 2026-09-09: four value-carrying builders, none range-bound.
/// Lowering it is the work: move a site to the limb form (`push_add` + `push_carry_bind`), prove the
/// aliasing row now REJECTS, then drop this number. Written down rather than computed so that adding an
/// unbound site cannot silently raise the backlog.
// 4 → 3 on 2026-09-11: `spend_carrier_cols` became RangeBound. Three sites still alias.
// 4 → 3 → 2 → 0 on 2026-09-11. Every value-carrying site is RangeBound. ⛔ This ceiling is ZERO and
// stays zero: a new site that puts an amount into a trace as a raw field element fails the manifest
// pin, and the fix is the shared block (`push_u64_conservation` / `push_u64_range`), never an exemption.
pub const MAX_FIELD_ONLY_VALUE_SITES: usize = 0;

#[cfg(test)]
mod manifest {
    use super::*;

    /// Column-builder names parsed out of the AIR source.
    ///
    /// ⭐ SOURCE-ABSENCE TECHNIQUE. A missing range constraint is an ABSENCE: there is no runtime handle
    /// for "this column was never bounded", and no proof fails to observe it, because the circuit is
    /// perfectly happy. Reading the source is the only way an absence becomes assertable.
    fn column_builders(src: &str) -> Vec<&str> {
        let mut out = Vec::new();
        for line in src.lines() {
            let t = line.trim_start();
            let t = if let Some(r) = t.strip_prefix("pub ") { r } else { t };
            let Some(rest) = t.strip_prefix("fn ") else { continue };
            let Some(name) = rest.split('(').next() else { continue };
            if name.ends_with("_cols") {
                out.push(name);
            }
        }
        out
    }

    /// ⛔⛔⛔ EVERY VALUE-CARRYING SITE MUST DECLARE HOW ITS AMOUNTS ARE BOUND.
    #[test]
    fn every_value_carrying_column_declares_its_binding() {
        let src = include_str!("whir_rec_block.rs");
        let builders = column_builders(src);
        assert!(
            builders.len() >= 4,
            "the source parse found only {} column builder(s) — `whir_rec_block.rs` changed shape and \
             this test is reading the wrong thing. Fix the parse; a manifest checked against nothing is \
             worse than no manifest.",
            builders.len()
        );

        let undeclared: Vec<&&str> = builders
            .iter()
            .filter(|b| !VALUE_SITES.iter().any(|(n, _, _)| n == *b))
            .collect();
        assert!(
            undeclared.is_empty(),
            "⛔ {} TRACE-COLUMN BUILDER(S) WITH NO BINDING DECLARED: {undeclared:?}\n\n\
             Every site putting a user-controlled AMOUNT into the trace must say whether that amount is \
             RANGE-BOUND or a RAW FIELD ELEMENT. A raw field element reduces mod p = 2,130,706,433, so \
             any conservation constraint over it is satisfied by `out = in + k·p` and amounts alias at \
             21.31 USDm. Declare it in `VALUE_SITES`.",
            undeclared.len()
        );
    }

    /// ⛔⛔ THE RATCHET — the unbound-amount backlog may only shrink.
    #[test]
    fn the_field_only_value_site_backlog_only_shrinks() {
        let n = VALUE_SITES.iter().filter(|(_, _, b)| *b == ValueBinding::FieldOnly).count();
        println!(
            "[constraint] {} value site(s) · {} RANGE-BOUND · {} FIELD-ONLY (ceiling {})",
            VALUE_SITES.len(),
            VALUE_SITES.len() - n,
            n,
            MAX_FIELD_ONLY_VALUE_SITES
        );
        assert!(
            n <= MAX_FIELD_ONLY_VALUE_SITES,
            "⛔ THE UNBOUND-AMOUNT BACKLOG GREW: {n} value sites carry raw field elements against a \
             ceiling of {}. Each is a site where `out = in + k·p` satisfies the circuit and the only \
             thing preventing inflation is an honest prover declining to build the row.",
            MAX_FIELD_ONLY_VALUE_SITES
        );
    }

    /// ⛔⛔⛔ THE INTEGER CONSERVATION CHECK IS PROVER-SIDE ONLY — PINNED SO NOBODY MISREADS IT.
    ///
    /// Every `FieldOnly` site sits beside a `checked_add` verifying conservation IN INTEGERS. It reads
    /// like the no-inflation gate and is not one: it runs in the PROVER, and a prover that wants to
    /// inflate simply does not run it. This pin exists because one of these sites is commented
    /// *"(also enforced in-circuit by the zerocheck)"* — true, and exactly the point, since the
    /// in-circuit form is the FIELD identity that aliases.
    #[test]
    fn the_integer_conservation_check_is_prover_side_only_and_this_is_recorded() {
        let src = include_str!("whir_rec_block.rs");
        let occurrences = src.matches(".checked_add(").count();
        println!("[constraint] prover-side integer conservation idiom appears {occurrences} time(s)");
        assert!(
            occurrences > 0,
            "the prover-side idiom has vanished. Either the value sites moved to the limb form — then \
             UPDATE `VALUE_SITES` to `RangeBound` and lower the ceiling — or the integer check was \
             deleted outright, which removes even the honest-prover bind and is strictly worse than the \
             hole it was masking."
        );
    }
}

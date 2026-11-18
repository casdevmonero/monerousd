// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE TWO-THIRDS THRESHOLDS — the one place every bonded tally (peg, PSM mint, reserve move, price mark, finality)
//! decides "does this weight carry two thirds of the bond?". Pure, dependency-free and Kani-proven (`kani-proofs`).
//!
//! ⛔ EXACT, NEVER SATURATING (§PROOFS 2026-10-24): the six sites this replaces each wrote
//! `weight.saturating_mul(3) >= total.saturating_mul(2)`. Once `total > u128::MAX / 2` the right side pins at
//! `u128::MAX`, and any weight ≥ ⌈u128::MAX / 3⌉ — about HALF of such a total — cleared a two-thirds quorum. The forms
//! below never multiply: ⌈2t/3⌉ = t − ⌊t/3⌋ and ⌊2t/3⌋ = t − ⌈t/3⌉, both exact for every u128 (t = 3k + r, r ∈ {0,1,2}).
//! For every total ≤ u128::MAX / 2 — every bond the ledger can hold — they decide exactly what the old forms decided.
//! A saturating `weight` sum stays safe: it only saturates past every u128 `total`, where the true answer is also yes.

/// ≥ 2/3 — `weight · 3 ≥ total · 2`, exactly; never with no bond at all.
#[must_use]
pub const fn two_thirds_met(weight: u128, total: u128) -> bool {
    total > 0 && weight >= total - total / 3
}

/// > 2/3 strictly — `weight · 3 > total · 2` (`2f + 1` of `3f + 1`, DB-387), exactly; never with no bond at all.
#[must_use]
pub const fn more_than_two_thirds(weight: u128, total: u128) -> bool {
    total > 0 && weight > total - total.div_ceil(3)
}

/// The least weight that, bonded beside `honest`, clears [`two_thirds_met`] ALONE — the custody tally's own inverse, so a
/// shown takeover cost is the threshold the tally applies, never a neighbour of it: `A ≥ ⌈2(A + H)/3⌉ ⇔ A ≥ 2H`, and 1
/// when nothing is bonded (a tally needs some bond). R3 2026-10-24: the figure read `2H + 1` ([`more_than_two_thirds`]'s
/// inverse), one base unit above what captures custody.
#[must_use]
pub const fn least_capturing_weight(honest: u128) -> u128 {
    if honest == 0 {
        1
    } else {
        honest.saturating_mul(2)
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ FREE-CELL CENSUS — which cells of an HONEST trace does the constraint not constrain?
//!
//! Engine #2 of the 2026-09-27 plan (user-approved): find under-constraint as a CLASS instead of one hole per review.
//! The holes that put funds at risk this month were statements a gate never tied down: DB-213c (a witness-free proof
//! passed membership and absence) and DB-223 (outputs credited on a statement that never named its inputs). The
//! existing circuit lane (`harness/circuit`) attacks about five statement classes by hand. This census attacks every
//! gate that any test proves, with no per-gate code.
//!
//! HOW. `prove_air_zerocheck` is the one core every prover reaches (38 call sites). Under `#[cfg(test)]`, when
//! `FREE_CELL_CENSUS` is set, it hands this module the exact trace and constraint being proved. For each column the
//! census adds one to that column at a few probe rows, and re-evaluates the constraint DIRECTLY on the affected rows
//! (the row itself, and the row before it for next-row reads). No proof is built.
//! - If the constraint is still zero, that cell is FREE: nothing in the circuit constrains it.
//! - A column free at EVERY probe row is the strong signal.
//! - Free only on some rows is usually padding (an `active = 0` row), and is reported apart.
//!
//! Control first: the honest trace must already satisfy the constraint at every data row, or the census for that
//! trace is VOID and is reported as void, never as clean.
//!
//! A free cell is a LEAD, not a verdict. It is a hole only if the free value can reach something the verifier relies
//! on: a public output, a bind, or a cross-table tie. Every lead is triaged by reading the gate.
//!
//! BLINDED traces (`Blinded<…>`): only the data half is probed. The random half is masked by the selector by design.
//!
//! ROOT-LAYER: the census sits in `prove_air_zerocheck`, the single place where a trace meets the constraint that is
//! supposed to bind it. Under-constraint is PRODUCED there, not at any caller, so one hook covers all 38 provers.
//! MEASURED: first run pending. The per-trace control prints VOID wherever an honest trace does not satisfy its own
//! gate, so the census can never report "clean" on a trace it could not check.
//! MUST-STAY-GREEN: the whole decider suite. The hook is `#[cfg(test)]` and env-gated, so production and an unset
//! environment run exactly as before.

use crate::air_zerocheck::{AirConstraint, OobLatch, Row};
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;

/// Each (gate type, rows, columns) shape is censused once per process. O1-FOOTPRINT-REVIEWED: test-only, bounded by
/// the number of distinct gate shapes the suite proves.
static SEEN: std::sync::Mutex<Vec<(String, usize, usize)>> = std::sync::Mutex::new(Vec::new());

fn point_of(r: usize, n: usize) -> Vec<Ea4> {
    // High-bit-first, the convention of `cyclic_shift_sigma`, `eq_z_hypercube` and `Blinded`.
    (0..n).map(|k| if (r >> (n - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect()
}

fn eval_row<C: AirConstraint>(c: &C, cols: &[Vec<Fa4>], r: usize, n: usize) -> Ea4 {
    let h = 1usize << n;
    let vals: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[r])).collect();
    let oob = OobLatch::new();
    let row = Row::new(&vals, &oob);
    let next = (r + 1) % h;
    // A next-row read outside the trace indexes out of bounds and PANICS: a gate that reads a column its own trace
    // does not have is a defect to see, never a zero to substitute.
    let at = |ci: usize, _p: &[Ea4]| -> Ea4 { Ea4::from(cols[ci][next]) };
    c.eval(&row, &at, &point_of(r, n))
}

/// Called by `prove_air_zerocheck` under `#[cfg(test)]`. It does nothing unless `FREE_CELL_CENSUS` is set.
pub(crate) fn observe<C: AirConstraint>(cols: &[Vec<Fa4>], c: &C) {
    if std::env::var_os("FREE_CELL_CENSUS").is_none() {
        return;
    }
    let width = cols.len();
    let h = cols.first().map_or(0, Vec::len);
    if width == 0 || h < 2 || !h.is_power_of_two() || cols.iter().any(|col| col.len() != h) {
        return; // not a trace a prover accepts either; the prover's own shape check reports it
    }
    let name = std::any::type_name::<C>().to_string();
    if SEEN
        .lock()
        .expect("the census lock is never held across a panic")
        .iter()
        .any(|(g, r, w)| g == &name && *r == h && *w == width)
    {
        return;
    }
    let n = h.trailing_zeros() as usize;
    let data = if name.contains("Blinded<") { h / 2 } else { h };

    // CONTROL: the honest trace satisfies the constraint on every data row. A trace that does not is usually a
    // TAMPER test proving a bad trace on purpose, so the shape is NOT marked seen: a later honest trace of the same
    // shape still gets its census (the first run marked the shape at a tamper trace and never came back to it).
    let bad: Vec<usize> = (0..data).filter(|&r| eval_row(c, cols, r, n) != Ea4::ZERO).collect();
    if bad.is_empty() {
        SEEN.lock().expect("the census lock is never held across a panic").push((name.clone(), h, width));
    } else {
        eprintln!(
            "[free-cells] VOID {name} rows={h} cols={width}: the honest trace already fails at {} data row(s) \
             (first {:?}), so a mutation proves nothing here",
            bad.len(),
            &bad[..bad.len().min(4)]
        );
        return;
    }

    // EVERY data row on a small trace: four probes could not tell a column free only on DECOY rows (legitimately
    // multiplied by a zero selector) from one free on a REAL row too — the first run's CoverOrSpendGate lead. On a
    // tall trace, 16 evenly spaced rows plus both ends bound the work.
    let mut probes: Vec<usize> = if data <= 64 {
        (0..data).collect()
    } else {
        (0..16).map(|k| k * data / 16).chain([1, data - 1]).collect()
    };
    probes.sort_unstable();
    probes.dedup();
    // HOMOGENEITY (the DB-213 class): does the ALL-ZERO row satisfy the gate? A sound production gate is
    // non-homogeneous — its public bind enters its own residual, so C(0) ≠ 0 — and a gate a zero row satisfies
    // states nothing a zero trace cannot prove: the recursion AIR was exactly this (§BD-2, recursion_bound.rs).
    // Relations among cells alone (a hash step, a path fold) are homogeneous by nature and are sound only
    // through a tie or a public input somewhere else; the marker says where that "somewhere else" must exist.
    let zero_cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; h]; width];
    let homogeneous = probes.iter().all(|&r| eval_row(c, &zero_cols, r, n) == Ea4::ZERO);
    let mut work = cols.to_vec();
    let mut all_rows: Vec<usize> = Vec::new();
    let mut some_rows: Vec<usize> = Vec::new();
    for col in 0..width {
        let mut free_at = 0usize;
        for &r in &probes {
            let orig = work[col][r];
            work[col][r] = orig + Fa4::ONE;
            let prev = (r + h - 1) % h;
            let free = eval_row(c, &work, r, n) == Ea4::ZERO && eval_row(c, &work, prev, n) == Ea4::ZERO;
            work[col][r] = orig;
            if free {
                free_at += 1;
            }
        }
        if free_at == probes.len() {
            all_rows.push(col);
        } else if free_at > 0 {
            some_rows.push(col);
        }
    }
    let show = |v: &[usize]| -> String {
        if v.len() <= 24 {
            format!("{v:?}")
        } else {
            format!("{:?}… ({} total)", &v[..24], v.len())
        }
    };
    eprintln!(
        "[free-cells] {} {name} rows={h} (data {data}) cols={width}: FREE AT EVERY PROBE {} ; free at some probes {} ; \
         zero row {}",
        if all_rows.is_empty() { "ok  " } else { "LEAD" },
        show(&all_rows),
        show(&some_rows),
        if homogeneous { "SATISFIES the gate (HOMOGENEOUS: no public input in the residual)" } else { "refused" }
    );
}

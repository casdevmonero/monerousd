// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ RANK CENSUS — how many field elements of a recursion row does the prover choose freely?
//!
//! Engine #3 of the 2026-09-27 plan (user-approved), in its cheapest exact form. The free-cell census
//! (`free_cell_census.rs`) asks, one cell at a time, "does any constraint notice this cell?". It cannot see
//! COORDINATED freedom: move an anchor and re-fold every target so each round identity still holds, and every
//! single cell looks constrained while the row as a whole says nothing about the carrier it claims to verify.
//! That coordinated freedom is exactly DB-213c ("the recursive folds state no inner statement") and the
//! unanchored opening s-BD-2 part (c) must close.
//!
//! This census asks the linear-algebra question instead. At an honest row, the residual map R(cells) is zero.
//! The directions along which every residual stays zero to first order form the kernel of its Jacobian, and a
//! recursion row is a deterministic function of what the verifier is told exactly when that kernel is EMPTY once
//! the public statement is included. A kernel of dimension K is K field elements a prover picks freely while the
//! verifier accepts. K is the size of the hole, and K = 0 is the definition of done for (c3)+(c4).
//!
//! Method — no proving, no transcript, milliseconds. For a γ-batched gate C_γ = Σ γ^i·R_i, the gradient rows
//! ∇C_γ at the honest row for G distinct γ span the gradients of the individual residuals (Schwartz–Zippel in γ).
//! Each gradient entry is the t¹ coefficient of t ↦ C_γ(row + t·e_k), recovered EXACTLY by interpolation at
//! degree+1 points — not a finite difference. Cells are base-field limbs, so the matrix is over Fa4 (every Ea4
//! output is 4 base-field rows) and K = cells − rank.
//!
//! What it never does: assemble a carrier the verifier accepts. It measures the constraint system, and its
//! verdict is a number the acceptance pin for part (c) reads.

use crate::air_zerocheck::{AirConstraint, OobLatch, Row};
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

/// One row's worth of base-field cells, laid as the aggregate prover lays them (`lay_vals_row`: 4 limbs per
/// value, in basis order).
pub(crate) fn cells_of(vals: &[Ea4]) -> Vec<Fa4> {
    let mut out = Vec::with_capacity(vals.len() * 4);
    for v in vals {
        out.extend_from_slice(&<Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v)[..4]);
    }
    out
}

/// Evaluate a row-local gate on one row of base-field cells. The shifted-row callback answers with the same row
/// and the point is empty: a gate that reads either is not row-local, and the control (the honest row must
/// satisfy the gate) reports it as VOID rather than as a verdict.
fn eval_cells<C: AirConstraint>(c: &C, cells: &[Fa4], x: &[Ea4]) -> Ea4 {
    let vals: Vec<Ea4> = cells.iter().map(|&v| Ea4::from(v)).collect();
    let oob = OobLatch::new();
    let row = Row::new(&vals, &oob);
    let at = |ci: usize, _p: &[Ea4]| -> Ea4 { vals[ci] };
    let out = c.eval(&row, &at, x);
    assert!(!oob.hit(), "the gate read outside its row: {}", oob.report());
    out
}

/// The t¹ coefficient of the polynomial t ↦ f(t) of degree ≤ d, from its values at t = 0, 1, …, d. Exact:
/// d+1 distinct points determine a degree-d polynomial. Solves the Vandermonde system over Fa4 with the
/// right-hand side in Ea4 (an Fa4-vector space, so Fa4 row operations act on it).
fn linear_coefficient(values_at_0_to_d: &[Ea4]) -> Ea4 {
    let n = values_at_0_to_d.len();
    assert!(n >= 2, "a linear coefficient needs at least two points");
    let mut m: Vec<Vec<Fa4>> =
        (0..n).map(|j| (0..n).map(|i| Fa4::from_u64(j as u64).exp_u64(i as u64)).collect()).collect();
    let mut y: Vec<Ea4> = values_at_0_to_d.to_vec();
    for col in 0..n {
        let piv = (col..n)
            .find(|&r| m[r][col] != Fa4::ZERO)
            .expect("a Vandermonde matrix over distinct points is invertible");
        m.swap(col, piv);
        y.swap(col, piv);
        let inv = m[col][col].inverse();
        for i in 0..n {
            m[col][i] *= inv;
        }
        y[col] *= Ea4::from(inv);
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = m[r][col];
            if f == Fa4::ZERO {
                continue;
            }
            for i in 0..n {
                let v = m[col][i];
                m[r][i] -= f * v;
            }
            let yc = y[col];
            y[r] -= yc * Ea4::from(f);
        }
    }
    y[1]
}

/// Reduced row echelon form over Fa4: the reduced rows (rank of them, zero rows dropped) and their pivot columns.
fn rref(mut m: Vec<Vec<Fa4>>, width: usize) -> (Vec<Vec<Fa4>>, Vec<usize>) {
    let mut pivots: Vec<usize> = Vec::new();
    let mut row = 0usize;
    for col in 0..width {
        if row >= m.len() {
            break;
        }
        let Some(p) = (row..m.len()).find(|&r| m[r][col] != Fa4::ZERO) else {
            continue;
        };
        m.swap(row, p);
        let inv = m[row][col].inverse();
        for i in 0..width {
            m[row][i] *= inv;
        }
        for r in 0..m.len() {
            if r == row {
                continue;
            }
            let f = m[r][col];
            if f == Fa4::ZERO {
                continue;
            }
            for i in 0..width {
                let v = m[row][i];
                m[r][i] -= f * v;
            }
        }
        pivots.push(col);
        row += 1;
    }
    m.truncate(pivots.len());
    (m, pivots)
}

/// Row-reduce over Fa4. Returns the rank and the non-pivot columns — one choice of free directions, named by
/// the caller; the COUNT is basis-independent, the particular columns are not.
fn rank_and_free_columns(m: Vec<Vec<Fa4>>, width: usize) -> (usize, Vec<usize>) {
    let (_, pivots) = rref(m, width);
    let free: Vec<usize> = (0..width).filter(|c| !pivots.contains(c)).collect();
    (pivots.len(), free)
}

/// A basis of the kernel from the RREF: one vector per free column f, with 1 at f and −rref[i][f] at pivot i.
fn kernel_basis(rref_rows: &[Vec<Fa4>], pivots: &[usize], width: usize) -> Vec<Vec<Fa4>> {
    (0..width)
        .filter(|c| !pivots.contains(c))
        .map(|f| {
            let mut v = vec![Fa4::ZERO; width];
            v[f] = Fa4::ONE;
            for (i, &p) in pivots.iter().enumerate() {
                v[p] = -rref_rows[i][f];
            }
            v
        })
        .collect()
}

pub(crate) struct RankReport {
    pub cells: usize,
    pub rank: usize,
    /// Non-pivot columns: one basis of the free directions (see `rank_and_free_columns`).
    pub free: Vec<usize>,
    /// Σ over the γ sweep of the gate on the UNMODIFIED row. Must be zero, else the census is VOID for this row.
    pub control: Ea4,
    rref: Vec<Vec<Fa4>>,
    pivots: Vec<usize>,
}

impl RankReport {
    /// The kernel dimension: field elements the prover chooses freely while every row constraint holds.
    pub fn kernel_dim(&self) -> usize {
        self.cells - self.rank
    }
    /// The kernel dimension once the `pinned` cells are held fixed by something OUTSIDE this row's gate (a weld
    /// to a transcript sponge, a public constant): the free directions that move no pinned cell. Treating a weld
    /// as a fixed pin is a LOWER bound on the true freedom when the weld's other side itself depends on this row.
    pub fn kernel_dim_after_pinning(&self, pinned: &[usize]) -> usize {
        let basis = kernel_basis(&self.rref, &self.pivots, self.cells);
        let k = basis.len();
        if k == 0 || pinned.is_empty() {
            return k;
        }
        // rows = pinned coordinates, columns = kernel basis vectors; the rank is how many kernel directions
        // the pins remove
        let m: Vec<Vec<Fa4>> = pinned.iter().map(|&c| basis.iter().map(|v| v[c]).collect()).collect();
        let (removed, _) = rank_and_free_columns(m, k);
        k - removed
    }
}

/// The census of one honest row under the γ-batched gate family `make`. `nvars` is the trace's log-height; the
/// gate is evaluated at the point of row 0 (row-local gates ignore it).
pub(crate) fn rank_census<C: AirConstraint, Mk: Fn(Ea4) -> C>(make: Mk, cells: &[Fa4], nvars: usize) -> RankReport {
    let w = cells.len();
    // More γ rows than there can be Ea4 residuals over w limbs, so the γ-span is the full residual span.
    let gammas = w / 4 + 8;
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(gammas * 4);
    let mut control = Ea4::ZERO;
    let x0: Vec<Ea4> = vec![Ea4::ZERO; nvars];
    for g in 0..gammas {
        let gamma = Ea4::from_basis_coefficients_fn(|k| {
            Fa4::from_u64((g as u64 + 1).wrapping_mul(0x9E37_79B9) ^ (k as u64 + 1).wrapping_mul(0x7F4A_7C15))
        });
        let c = make(gamma);
        // One degree of margin: interpolation at d+1 points is exact for degree ≤ d.
        let d = c.degree(nvars) + 1;
        control += eval_cells(&c, cells, &x0);
        let mut grad: Vec<Ea4> = Vec::with_capacity(w);
        for k in 0..w {
            let samples: Vec<Ea4> = (0..=d)
                .map(|t| {
                    let mut x = cells.to_vec();
                    x[k] += Fa4::from_u64(t as u64);
                    eval_cells(&c, &x, &x0)
                })
                .collect();
            grad.push(linear_coefficient(&samples));
        }
        for comp in 0..4 {
            rows.push(
                grad.iter().map(|e| <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e)[comp]).collect(),
            );
        }
    }
    let (reduced, pivots) = rref(rows, w);
    let free: Vec<usize> = (0..w).filter(|c| !pivots.contains(c)).collect();
    RankReport { cells: w, rank: pivots.len(), free, control, rref: reduced, pivots }
}

/// Names for the cells of a `WhirOpeningRoundConstraint` row, layout `[c0,c2,…,γ_j per round ‖ target chain]`
/// (see `extract_air_direct_carrier_rows`), 4 limbs per value.
pub(crate) fn opening_cell_name(k: usize, rounds: usize, wire_size: usize) -> String {
    let (v, limb) = (k / 4, k % 4);
    let per_round = wire_size + 1;
    if v < rounds * per_round {
        let (j, i) = (v / per_round, v % per_round);
        if i == wire_size {
            format!("γ_{j}.{limb}")
        } else {
            let ci = if i == 0 { 0 } else { i + 1 };
            format!("c{ci}@round{j}.{limb}")
        }
    } else {
        format!("target_{}.{limb}", v - rounds * per_round)
    }
}

/// Names for the cells of a `WhirRecursiveVerifyConstraint` row, layout `[round_evals ‖ r ‖ claimed_final]`.
pub(crate) fn validity_cell_name(k: usize, nvars: usize, per_evals: usize) -> String {
    let (v, limb) = (k / 4, k % 4);
    if v < nvars * per_evals {
        format!("h_{}[{}].{limb}", v / per_evals, v % per_evals)
    } else if v < nvars * per_evals + nvars {
        format!("r_{}.{limb}", v - nvars * per_evals)
    } else {
        format!("claimed_final.{limb}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        extract_air_direct_carrier_rows, prove_air_direct_light_decider_selfcontained_bytes,
        WhirOpeningRoundConstraint, WhirRecursiveVerifyConstraint, REC_DECIDER_ELL_ZK, REC_DECIDER_FOLDING,
    };
    use crate::poseidon2_compress::DIGEST_LANES;

    /// a + b − c: three cells, one relation ⇒ two free directions.
    struct OneSum;
    impl AirConstraint for OneSum {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[0] + local[1] - local[2]
        }
    }
    /// Three cells each pinned to a constant ⇒ nothing free.
    struct Pinned {
        gamma: Ea4,
    }
    impl AirConstraint for Pinned {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let one = Ea4::ONE;
            let two = Ea4::from_u64(2);
            let three = Ea4::from_u64(3);
            (local[0] - one) + self.gamma * (local[1] - two) + self.gamma * self.gamma * (local[2] - three)
        }
    }
    /// a − b: every single cell is constrained (+1 on either breaks it), yet the direction (1, 1) is free. This
    /// is the coordinated freedom the free-cell census cannot see and this census must.
    struct Equal;
    impl AirConstraint for Equal {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[0] - local[1]
        }
    }
    /// A degree-3 relation, so the interpolation is exercised past the linear case: a·b·c − d.
    struct Cubic;
    impl AirConstraint for Cubic {
        fn degree(&self, _nvars: usize) -> usize {
            3
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[0] * local[1] * local[2] - local[3]
        }
    }

    #[test]
    fn the_rank_census_measures_free_directions_including_the_coordinated_ones() {
        let f = |v: u64| Fa4::from_u64(v);
        let one_sum = rank_census(|_g| OneSum, &[f(2), f(3), f(5)], 1);
        assert_eq!(one_sum.control, Ea4::ZERO, "control: the honest row satisfies a + b = c");
        assert_eq!(one_sum.kernel_dim(), 2, "one relation over three cells leaves two free directions");
        let pinned = rank_census(|gamma| Pinned { gamma }, &[f(1), f(2), f(3)], 1);
        assert_eq!(pinned.control, Ea4::ZERO);
        assert_eq!(pinned.kernel_dim(), 0, "three independent relations over three cells pin the row");
        let equal = rank_census(|_g| Equal, &[f(7), f(7)], 1);
        assert_eq!(equal.control, Ea4::ZERO);
        assert_eq!(equal.kernel_dim(), 1, "a − b leaves the diagonal free, which single-cell probing never sees");
        let cubic = rank_census(|_g| Cubic, &[f(2), f(3), f(5), f(30)], 1);
        assert_eq!(cubic.control, Ea4::ZERO);
        assert_eq!(cubic.kernel_dim(), 3, "one cubic relation over four cells: three free directions");
        // REFUTATION: a row that does NOT satisfy the gate is reported as such by the control, never as a rank.
        let dishonest = rank_census(|_g| OneSum, &[f(2), f(3), f(6)], 1);
        assert_ne!(dishonest.control, Ea4::ZERO, "a dishonest row must fail the control");
    }

    /// The inner AIR a carrier proves: two independent sums, the shape every real gate has (γ-batched residuals).
    struct TwoSums {
        gamma: Ea4,
    }
    impl AirConstraint for TwoSums {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let r0 = local[0] + local[1] - local[2];
            let r1 = local[3] + local[4] - local[5];
            r0 + self.gamma * r1
        }
    }
    fn honest_inner(h: usize) -> Vec<Vec<Fa4>> {
        let mk = |k: u64| -> Vec<Fa4> { (0..h).map(|i| Fa4::from_u64(k * 1000 + i as u64 + 1)).collect() };
        let (a, b, d, e) = (mk(1), mk(2), mk(4), mk(5));
        let c: Vec<Fa4> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        let f: Vec<Fa4> = d.iter().zip(e.iter()).map(|(x, y)| *x + *y).collect();
        vec![a, b, c, d, e, f]
    }

    /// The two rows the settlement aggregate lays per carrier, censused. Prints K for each with the free
    /// directions named, and pins the control. The number this prints is the size of DB-213c / part (c)'s hole.
    fn settlement_rows_census() -> (RankReport, RankReport, usize, usize) {
        let pb = [Fa4::from_u64(0xB6), Fa4::from_u64(11)];
        let bytes = prove_air_direct_light_decider_selfcontained_bytes(honest_inner(1 << 5), |gamma| TwoSums { gamma }, &pb)
            .expect("the honest inner AIR proves on the direct path");
        let (vv, ov, nvars, per_evals) =
            extract_air_direct_carrier_rows(&bytes, &pb).expect("the extractor replays the honest carrier");
        let basis: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| {
            Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO })
        });
        let rounds = REC_DECIDER_FOLDING;
        let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
        let opening = rank_census(
            move |gamma| WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis },
            &cells_of(&ov),
            5,
        );
        let validity = rank_census(
            move |gamma| WhirRecursiveVerifyConstraint { gamma, per_evals, nvars_inner: nvars, basis },
            &cells_of(&vv),
            5,
        );
        let name_o: Vec<String> = opening.free.iter().map(|&k| opening_cell_name(k, rounds, wire_size)).collect();
        let name_v: Vec<String> = validity.free.iter().map(|&k| validity_cell_name(k, nvars, per_evals)).collect();
        eprintln!(
            "[rank-census] Opening row: {} cells, rank {}, K = {} free — {}",
            opening.cells,
            opening.rank,
            opening.kernel_dim(),
            name_o.join(" ")
        );
        eprintln!(
            "[rank-census] Validity row: {} cells, rank {}, K = {} free — {}",
            validity.cells,
            validity.rank,
            validity.kernel_dim(),
            name_v.join(" ")
        );
        (opening, validity, nvars, per_evals)
    }

    #[test]
    fn the_settlement_aggregate_rows_report_their_kernel_dimension() {
        let (opening, validity, _nvars, _per) = settlement_rows_census();
        assert_eq!(opening.control, Ea4::ZERO, "control: the honest opening row satisfies its gate at every γ");
        assert_eq!(validity.control, Ea4::ZERO, "control: the honest validity row satisfies its gate at every γ");
        assert!(opening.rank <= opening.cells && validity.rank <= validity.cells);
    }

    /// THE ACCEPTANCE PIN FOR s-BD-2 PART (c). A recursion row that is a deterministic function of the public
    /// statement has kernel dimension zero; anything else is a prover-chosen value the verifier accepts.
    #[test]
    #[ignore = "DB-213c / s-BD-2 part (c): RED until the opening and validity rows are bound to the carrier's transcript (c3) and anchors (c4); run explicitly"]
    fn the_settlement_aggregate_rows_are_deterministic_given_the_statement() {
        let (opening, validity, _nvars, _per) = settlement_rows_census();
        assert_eq!(opening.control, Ea4::ZERO);
        assert_eq!(validity.control, Ea4::ZERO);
        assert_eq!(opening.kernel_dim(), 0, "the opening row must be determined by the statement");
        assert_eq!(validity.kernel_dim(), 0, "the validity row must be determined by the statement");
    }

    /// Pinning calibration: a − b over two cells has K = 1; pinning either cell leaves K = 0; pinning a cell of
    /// an UNRELATED free direction leaves it.
    #[test]
    fn pinning_removes_exactly_the_directions_that_move_a_pinned_cell() {
        let f = |v: u64| Fa4::from_u64(v);
        let equal = rank_census(|_g| Equal, &[f(7), f(7)], 1);
        assert_eq!(equal.kernel_dim(), 1);
        assert_eq!(equal.kernel_dim_after_pinning(&[0]), 0, "pinning a moves the only free direction (1,1)");
        assert_eq!(equal.kernel_dim_after_pinning(&[1]), 0);
        let one_sum = rank_census(|_g| OneSum, &[f(2), f(3), f(5)], 1);
        assert_eq!(one_sum.kernel_dim(), 2);
        assert_eq!(one_sum.kernel_dim_after_pinning(&[0]), 1, "pinning one of three cells leaves one free direction");
        assert_eq!(one_sum.kernel_dim_after_pinning(&[0, 1]), 0);
    }

    // The two IVC1 certificate-step census pins (`the_certificate_step_row_after_its_welds`,
    // `the_certificate_step_row_is_determined_after_its_welds`, the latter RED since DB-213c) were deleted with
    // `ivc_one_table` on 2026-09-28: the certificate is a chain of `certificate_door` steps, whose freedom is
    // measured not by a kernel census but by the step's own refusals (the fixpoint pin, the 2,920-flip byte census).
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐⭐⭐ THE BOUND RECURSION STEP — the outer AIR that makes an inner proof's claim MEAN something.
//!
//! ⛔⛔⛔ WHAT WAS MISSING, MEASURED (§BD-2, §BD-3, corrected by §BG). The existing recursion
//! (`whir_rec_block::FixedDegreeRecursiveVerifyConstraint` + `WhirOpeningRoundConstraint`) enforces the
//! inner sumcheck's ROUND CHAIN — `h_k[0]+h_k[1] == claim_{k-1}` and `claim_k == h_k(r_k)` — and then
//! anchors the end at a committed cell `claimed_final`. That cell is tied to NOTHING. The native
//! verifier closes with
//!
//! ```text
//! claim_last == eq(z, r) . C_gamma(opened)
//! ```
//!
//! and that equation has no in-circuit counterpart at all. So a prover lays a row of zeros: every round
//! identity holds (0+0 == 0), `claim_last` is 0, `claimed_final` is 0, and the step verifies with NO
//! inner proof behind it. MEASURED: a one-table IVC step claiming 2^100 of work from a chain that never
//! existed verified at the exact fixpoint size.
//!
//! ⛔ AND A COMMITMENT DOES NOT FIX IT (§BG, my own retraction). Committing the outer trace binds the
//! prover to the row it chose; it does not make the row's STATEMENT true. The zero row is a perfectly
//! honest proof of a vacuous claim.
//!
//! ⭐⭐⭐ WHAT CLOSES IT: bring `C_γ(opened)` INTO THE CIRCUIT. The opened row becomes committed columns
//! of the outer table, the inner AIR is evaluated on them row-locally, and the residual
//! `claimed_final − eq(z,r)·C_γ(opened)` is enforced. Then a zero row must satisfy
//! `0 == eq(z,r)·C_γ(0)`, and **every real AIR is NON-HOMOGENEOUS** — its public bind enters its own
//! constraint, so `C_γ(0) ≠ 0` and the forgery dies. That is exactly why a zeroed SPEND carrier already
//! fails its own gate while a zeroed RECURSION row passes: the recursion AIR was the homogeneous one.
//!
//! ⛔ THE COST IS O(WIDTH), NOT O(HEIGHT). The inner AIR is evaluated at ONE row, so this adds the
//! inner trace's WIDTH in columns — never its height. The recursion stays O(1) in the inner proof's
//! size, which is the property the whole design rests on.
//!
//! ## What this module does NOT yet do, stated here because a header that overstates is how §BF went wrong
//! * **The opening chain is still unanchored** (§BD-2's part (c)): `target_0` is not tied to the
//!   openings' μ and ε, and the final target is not tied to `prover_rand`. This module closes part (b).
//!   Part (c) is the remaining edge, and until it lands a step is bound to its inner STATEMENT but not
//!   to the inner PCS opening.
//! * `z` and `r` ride as committed columns here. Welding them to a constrained sponge so they cannot be
//!   chosen is [`crate::transcript_bind_air`]'s job and is composed, not re-derived, when the two meet.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;

/// Where each value sits in the outer row. Every offset is a public function of `(nvars, per, width)`,
/// so a verifier rebuilds the layout from the statement and never from the prover's object.
#[derive(Clone, Copy, Debug)]
pub struct BoundLayout {
    pub nvars: usize,
    pub per: usize,
    pub width: usize,
    /// First inner COLUMN whose next-row opening this row carries, and how many — the contiguous run an
    /// inner gate declares through `AirConstraint::shifted_cols`. `0, 0` for a row-LOCAL inner AIR,
    /// which is every class but the spend-or-decoy carrier.
    pub shifted_lo: usize,
    pub shifted: usize,
    /// How many γ-POWER cells the row carries — `0` for a single-carrier step, whose γ is a constant of
    /// its own circuit.
    ///
    /// ⭐⭐⭐ NON-ZERO IS WHAT MAKES MANY CARRIERS ROWS OF ONE TABLE. Each carrier has its own γ, so an
    /// aggregate holding many of them must read γ from CELLS — and a gate's `acc += gp*res; gp *= gamma`
    /// then makes the k-th residual degree k, for k in the hundreds, truncating the sumcheck silently
    /// (the proof PROVES and does not VERIFY — measured, §BV). Carrying `γ^0 … γ^{powers-1}` as cells
    /// with the row-local chain `γ^k == γ^{k-1}·γ` puts every residual against a DEGREE-1 cell instead,
    /// so total degree is `deg(inner) + 1` however many residuals there are.
    pub powers: usize,
    /// How many of those cells are the LOW rung of a two-rung power ladder. `0` means one flat rung.
    ///
    /// ⭐⭐⭐ A FLAT LADDER COSTS ONE CELL PER RESIDUAL, AND THE SPEND GATE HAS 2,004 OF THEM — more
    /// columns than the opened row it is folding. Writing `k = a·C + b` gives `γ^k = (γ^C)^a · γ^b`, so
    /// two rungs of `C` and `ceil(K/C)` cells cover `C·ceil(K/C) ≥ K` powers. At `C ≈ √K` that is
    /// `~2√K` cells instead of `K`: 2,004 → 90, a 22× cut in the widest block of the table.
    ///
    /// The price is one degree: a residual multiplies TWO degree-1 cells instead of one.
    pub power_lo: usize,
}

impl BoundLayout {
    /// Values (not limbs) in one outer row: `evals | r | z | claim | cf | opened | powers | shifted`.
    #[must_use]
    pub fn values(&self) -> usize {
        self.nvars * self.per
            + self.nvars
            + self.nvars
            + self.nvars
            + 1
            + self.width
            + self.powers
            + self.shifted
    }
    /// Cell holding the inner carrier's NEXT-ROW opening for column `shifted_lo + i`.
    ///
    /// ⭐⭐⭐ WHY A ROW CARRIES ANY OF THESE. `BoundStepConstraint` closes `cf == eq(z,r)·C(opened)`,
    /// and for a ROW-SHIFTED inner AIR `C` also reads the rotation — which the carrier already ships and
    /// the transcript already absorbs (`absorb_shifted_openings`), so it is committed, not trusted.
    ///
    /// ⛔ ONLY THE DECLARED COLUMNS. The carrier ships `shifted_opened` for EVERY column (the wire
    /// shape gate enforces `== width`), but the aggregate lays only the contiguous run its inner gate
    /// names in `shifted_cols()`. Carrying all of them would DOUBLE the widest block in the step row —
    /// measured as the difference between a ~3.5k and a ~6k step table — for values no gate reads.
    #[must_use]
    pub fn shifted_at(&self, i: usize) -> usize {
        self.nvars * self.per + 3 * self.nvars + 1 + self.width + i
    }
    #[must_use]
    pub fn eval_at(&self, k: usize, j: usize) -> usize {
        k * self.per + j
    }
    #[must_use]
    pub fn r_at(&self, k: usize) -> usize {
        self.nvars * self.per + k
    }
    #[must_use]
    pub fn z_at(&self, k: usize) -> usize {
        self.nvars * self.per + self.nvars + k
    }
    #[must_use]
    pub fn claim_at(&self, k: usize) -> usize {
        self.nvars * self.per + 2 * self.nvars + k
    }
    #[must_use]
    pub fn cf(&self) -> usize {
        self.nvars * self.per + 3 * self.nvars
    }
    #[must_use]
    pub fn opened_at(&self, c: usize) -> usize {
        self.nvars * self.per + 3 * self.nvars + 1 + c
    }
    /// Cell holding `γ^k`. `power_at(1)` IS the carrier's γ; `power_at(0)` is pinned to 1.
    ///
    /// ⛔⛔⛔ THE POWERS COME AFTER THE SHIFTED BLOCK, AND THE ORDER IS LOAD-BEARING.
    /// `bound_step_row_committed` lays a row under a layout whose `powers` is 0 — powers are a property
    /// of the GATE, filled in later by `delta_layout` — so anything positioned AFTER `powers` would sit
    /// at a different offset in the laying layout than in the final one. MEASURED 2026-09-23: with the
    /// shifted block placed after the powers, every step row failed at residual 13
    /// (`power_at(0) - 1`), because the rotation had been written over the γ ladder's first cell.
    /// Everything the row-layer writes must therefore precede `powers`.
    #[must_use]
    pub fn power_at(&self, k: usize) -> usize {
        self.nvars * self.per + 3 * self.nvars + 1 + self.width + self.shifted + k
    }
}

/// Lagrange interpolation of `h` at `x`, over the evaluation points `0..h.len()` — the SAME formula
/// `air_zerocheck::lagrange_eval` uses natively, so the circuit and the native verifier agree by
/// construction rather than by two hand-written copies agreeing.
fn lagrange(h: &[Ea4], x: Ea4) -> Ea4 {
    crate::air_zerocheck::lagrange_eval(h, x)
}

/// ⭐ THE OUTER CONSTRAINT. Generic over the INNER AIR: the recursion is only sound when it can evaluate
/// the statement it claims to have verified, so the inner constraint is a parameter, not an assumption.
pub struct BoundStepConstraint<C: AirConstraint, F: Fn(&Row<'_>) -> C> {
    pub gamma: Ea4,
    pub layout: BoundLayout,
    /// ⭐⭐⭐ THE INNER AIR AS A PER-ROW FACTORY, NOT A VALUE. An aggregate verifies MANY carriers in ONE
    /// table, and every carrier has its own PUBLIC values — its two output commitments, its nullifier,
    /// its note-membership commitment. A constraint field holds ONE value for every row, so those
    /// publics cannot live there: they have to be committed CELLS the inner gate reads per row.
    ///
    /// The factory is handed the OUTER row, so it builds the row's own inner AIR from the row's own
    /// public cells. That is what makes a multi-carrier aggregate a bound statement at all — and it is
    /// what lets a hash chain over those same cells end at ONE public digest, which is what a peer needs
    /// to judge a block's note delta without holding a single carrier (§BA/§BB).
    pub inner: F,
}

/// The constant case: one inner AIR for every row. A thin wrapper so a single-carrier step reads the way
/// it always did, and there is exactly ONE residual set underneath.
#[must_use]
pub fn constant_inner<C: AirConstraint + Clone + Sync>(inner: C) -> impl Fn(&Row<'_>) -> C {
    move |_row: &Row<'_>| inner.clone()
}

impl<C: AirConstraint, F: Fn(&Row<'_>) -> C> AirConstraint for BoundStepConstraint<C, F> {
    /// The bound step reads only its own row; the only `at` in play is the one it FORWARDS to the inner
    /// AIR, so it is row-local exactly when that AIR is. The factory needs a row to answer, and the
    /// answer is a property of the CIRCUIT, so an empty probe row is the honest question.
    fn is_row_local(&self) -> bool {
        let probe_oob = crate::air_zerocheck::OobLatch::new();
        let probe_vals: Vec<Ea4> = vec![Ea4::ZERO; self.layout.values() * 4];
        let probe = Row::new(&probe_vals, &probe_oob);
        (self.inner)(&probe).is_row_local()
    }
    /// ⛔ FREE-WITNESS DECLARATION (the security pillar, 2026-09-29): the SHIFTED cells — the inner AIR's next-row
    /// openings, `layout.shifted` extension values laid as a CONTIGUOUS range of inner columns. The inner reads through
    /// `at` only the columns its own `shifted_cols()` names; the range's other cells are carried for contiguity and no law
    /// here reads them. They are bound OUTSIDE these laws — by the WHIR opening of the committed rotation at the same point
    /// (`shifted_opened`), which the step's statement welds — so they are free with respect to the AIR and not to the
    /// proof. MEASURED: the debug prover's free-witness census named 44 such limbs (11 cells) in the settlement aggregate
    /// with the blinded member-path inner. Declared here so the census refuses any OTHER free cell in a bound step.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let limbs = crate::committed_air::EXT_LIMBS;
        let mut free: Vec<usize> = (0..self.layout.shifted)
            .flat_map(|i| {
                let base = limbs * self.layout.shifted_at(i);
                base..base + limbs
            })
            .collect();
        // ⭐ DB-376 — the INNER gate's OWN declared free columns, at their OPENED cells. A column the inner gate
        // knowingly leaves unread (its declaration, never inferred here) is read by no law of this step either: its
        // opened value enters `C(opened)` nowhere, and it is bound outside these laws by the WHIR opening of the inner
        // commitment at `r`. MEASURED 2026-10-03: the bond class's inner spend gate declares its claim region free (it
        // publishes no claim); that declaration never reached this step, and the strict census refused the 692 opened
        // limbs (173 inner columns, 1985..2157). Only what the inner gate DECLARES is forwarded — an inner column it
        // leaves unread WITHOUT declaring it is still refused here.
        let probe_oob = crate::air_zerocheck::OobLatch::new();
        let probe_vals: Vec<Ea4> = vec![Ea4::ZERO; self.layout.values() * 4];
        let probe = Row::new(&probe_vals, &probe_oob);
        if let Some(inner_free) = (self.inner)(&probe).free_columns() {
            for c in inner_free.into_iter().filter(|c| *c < self.layout.width) {
                let base = limbs * self.layout.opened_at(c);
                free.extend(base..base + limbs);
            }
        }
        Some(free)
    }
    fn degree(&self, nvars: usize) -> usize {
        // `claim_k == lagrange(h_k, r_k)` is degree `per`; the closing residual multiplies `eq(z,r)`
        // (degree 2·nvars in committed cells) by the inner AIR's own degree. Take the max, never a guess.
        let eq_deg = 2 * self.layout.nvars;
        // The factory needs a row to build from; the DEGREE of the inner AIR is a property of the AIR,
        // not of the row, so an empty row is the honest probe. Every inner AIR in this tree reports a
        // constant degree.
        let probe_oob = crate::air_zerocheck::OobLatch::new();
        let probe_vals: Vec<Ea4> = vec![Ea4::ZERO; self.layout.values() * 4];
        let probe = Row::new(&probe_vals, &probe_oob);
        // With γ-power cells the fold costs ONE more degree — a single degree-1 cell per residual —
        // instead of the k-th power of a cell.
        let fold = if self.layout.power_lo > 0 { 2 } else { usize::from(self.layout.powers > 0) };
        let close = eq_deg + (self.inner)(&probe).degree(nvars) + fold;
        self.layout.per.max(close).max(2)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let l = self.layout;
        // Reconstruct an `Ea4` value from its four committed base limbs — the same packing every other
        // AIR in this tree uses.
        let _basis: [Ea4; 4] = core::array::from_fn(|i| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::ith_basis_element(i)
                .expect("the extension has four basis elements")
        });
        let get = |i: usize| -> Ea4 {
            let b = i * 4;
            // ⭐ A COORDINATE SHIFT, NOT FOUR MULTIPLIES — see `air_zerocheck::pack_limbs`, which is the
            // hottest line in the decider and is gated against the basis sum it replaces.
            crate::air_zerocheck::pack_limbs(local[b], local[b + 1], local[b + 2], local[b + 3])
        };

        let mut residuals: Vec<Ea4> = Vec::new();
        // 1. THE ROUND CHAIN — the part the existing recursion already had.
        for k in 0..l.nvars {
            let prev = if k == 0 { Ea4::ZERO } else { get(l.claim_at(k - 1)) };
            let h: Vec<Ea4> = (0..l.per).map(|j| get(l.eval_at(k, j))).collect();
            residuals.push(h[0] + h[1] - prev);
            residuals.push(get(l.claim_at(k)) - lagrange(&h, get(l.r_at(k))));
        }
        // 2. The committed end of the chain.
        residuals.push(get(l.cf()) - get(l.claim_at(l.nvars - 1)));

        // 3. ⭐⭐⭐ THE RESIDUAL THAT WAS MISSING — the native verifier's closing equation, in circuit.
        //    `eq(z,r) = Π_k [ z_k·r_k + (1−z_k)(1−r_k) ]`, exactly as `verify_air_zerocheck` computes it.
        let mut eq_zr = Ea4::ONE;
        for k in 0..l.nvars {
            let zk = get(l.z_at(k));
            let rk = get(l.r_at(k));
            eq_zr *= zk * rk + (Ea4::ONE - zk) * (Ea4::ONE - rk);
        }
        // The inner AIR, evaluated on the OPENED ROW held as committed columns of THIS table.
        let opened: Vec<Ea4> = (0..l.width).map(|c| get(l.opened_at(c))).collect();
        let inner_oob = crate::air_zerocheck::OobLatch::new();
        let inner_row = Row::new(&opened, &inner_oob);
        // ⛔⛔⛔ AT `r`, NOT AT THE OUTER POINT. The native verifier closes with
        // `constraint.eval(&row, &at, &proof.r)` (`air_zerocheck.rs`) — the inner AIR is evaluated at the
        // INNER round challenges, which are cells of this very row. Passing the OUTER zerocheck's `x`
        // asserts a different equation entirely.
        //
        // It read as correct for a long time because every inner AIR tried here was ROW-LOCAL and
        // ignored `x`. The blinded wrapper item 1 put on every production carrier does NOT: its selector
        // is `(1 - x[0])`. MEASURED by `committed_weld`'s own control, which refused an honest weld until
        // this line named the right point — a control earning its keep.
        let r_pt: Vec<Ea4> = (0..l.nvars).map(|k| get(l.r_at(k))).collect();
        // ⭐⭐⭐ THE INNER AIR'S OWN ROTATION, NOT THE OUTER TABLE'S. `at` as handed to this
        // constraint reads the OUTER step table's next row — a different carrier entirely. A
        // row-SHIFTED inner gate must instead see its own `shifted_opened`, which this row carries and
        // the carrier's transcript already absorbed. Reading the outer one would score the inner AIR
        // against a neighbouring carrier's cells and still look satisfied.
        //
        // ⛔ FAIL-CLOSED OUTSIDE THE DECLARED RUN: a gate reading a column its `shifted_cols()` never
        // named records on the latch below, and the step pushes a nonzero residual rather than
        // substituting a zero — a substituted zero that is then USED is a soundness break.
        let inner_at = |c: usize, _p: &[Ea4]| -> Ea4 {
            if l.shifted > 0 && c >= l.shifted_lo && c < l.shifted_lo + l.shifted {
                get(l.shifted_at(c - l.shifted_lo))
            } else {
                inner_oob.record(c, l.shifted);
                Ea4::ZERO
            }
        };
        let inner = (self.inner)(local);
        // ⛔ THE CENSUS FRAME (2026-09-30, `pow_pq_air::census_with_frame`): the inner gate names ITS OWN columns, and
        // this table holds them as `EXT_LIMBS` limbs at `opened_at(c)` — an affine map the decorative-block census must
        // apply before it nudges anything, or it tests neighbouring limbs and reports a block the inner laws do read as
        // decorative (MEASURED on the member-path aggregate: "base 362", an inner column).
        let limbs = crate::committed_air::EXT_LIMBS;
        let frame_add = limbs * l.opened_at(0);
        let c_at_r = if l.powers == 0 {
            // ONE carrier: its γ is a constant of this circuit, so the gate folds its own residuals.
            crate::pow_pq_air::census_with_frame(limbs, frame_add, || inner.eval(&inner_row, &inner_at, &r_pt))
        } else {
            // MANY carriers as ROWS: γ is a cell, so the fold happens HERE against the power chain —
            // see `BoundLayout::powers` for the degree blowup this avoids.
            let rs = crate::pow_pq_air::census_with_frame(limbs, frame_add, || inner.residuals(&inner_row, &inner_at, &r_pt));
            let cap = if l.power_lo == 0 { l.powers } else { l.power_lo * (l.powers - l.power_lo) };
            if rs.len() > cap {
                // ⛔ FAIL CLOSED, IN CIRCUIT. A row carrying fewer powers than the gate has residuals
                // would otherwise DROP the tail — every residual past `powers` silently unchecked.
                residuals.push(Ea4::ONE);
            }
            // p_0 == 1 and p_k == p_{k-1}·p_1, so `power_at(1)` is the only free γ cell and every higher
            // power is forced. Without these the powers are independent cells and the fold means nothing.
            residuals.push(get(l.power_at(0)) - Ea4::ONE);
            let g = get(l.power_at(1));
            let c = if l.power_lo == 0 { l.powers } else { l.power_lo };
            for k in 2..c {
                residuals.push(get(l.power_at(k)) - get(l.power_at(k - 1)) * g);
            }
            if l.power_lo == 0 {
                rs.iter()
                    .enumerate()
                    .take(l.powers)
                    .fold(Ea4::ZERO, |a, (k, r)| a + get(l.power_at(k)) * *r)
            } else {
                // THE HIGH RUNG. `q_0 == 1`, `q_1 == γ^C` (the low rung's top times γ), `q_a == q_{a-1}·q_1`
                // — so the whole ladder still hangs off the ONE tied γ cell, and `γ^k = q_{k/C} · p_{k%C}`.
                let hi = l.powers - c;
                residuals.push(get(l.power_at(c)) - Ea4::ONE);
                let step = get(l.power_at(c - 1)) * g;
                if hi > 1 {
                    residuals.push(get(l.power_at(c + 1)) - step);
                }
                let q1 = get(l.power_at(c + 1));
                for a in 2..hi {
                    residuals.push(get(l.power_at(c + a)) - get(l.power_at(c + a - 1)) * q1);
                }
                rs.iter()
                    .enumerate()
                    .take(c * hi)
                    .fold(Ea4::ZERO, |acc, (k, r)| {
                        acc + get(l.power_at(c + k / c)) * get(l.power_at(k % c)) * *r
                    })
            }
        };
        // ⛔ THE LATCH, INSPECTED. An inner gate that read past its own opened row or outside its
        //    declared shifted run was scored against substituted zeros; that makes this residual
        //    nonzero, so the level is UNPROVABLE rather than quietly satisfied.
        if inner_oob.hit() {
            residuals.push(Ea4::ONE);
        }
        residuals.push(get(l.cf()) - eq_zr * c_at_r);

        // γ-power batch, as every AIR in this tree batches.
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for res in residuals {
            acc += gp * res;
            gp *= self.gamma;
        }
        acc
    }
}

/// Lay one outer row from a REAL inner carrier: its round evals, its challenges, its opened row.
/// `None` fail-closed when the carrier is not the single-table shape the extractor accepts.
#[must_use]
pub fn bound_step_row(
    inner_bytes: &[u8],
    inner_public_bind: &[Fa4],
) -> Option<(Vec<Fa4>, BoundLayout, Ea4)> {
    // ⛔ NO SHIFTED RUN ON THE DIRECT PATH. No production carrier proves there (item 1 moved them
    // all to the committed path), so nothing row-shifted rides it; a row-shifted gate handed to this
    // layer would read past its declared run and the OOB latch in `BoundStepConstraint` refuses it.
    let (shifted_lo, shifted) = (0usize, 0usize);
    let bundle: crate::whir_rec_block::AirDirectBundle =
        postcard::from_bytes(inner_bytes).ok()?;
    if bundle.shapes.len() != 1 {
        return None;
    }
    let (nvars, width) = bundle.shapes[0];
    let per = bundle.zc.round_evals.first()?.len();
    if bundle.zc.r.len() != nvars || bundle.zc.opened.len() != width {
        return None; // fail-closed: the carrier does not describe its own shape consistently
    }
    let (gamma, z) =
        crate::whir_rec_block::transcript_of_air_direct_carrier(inner_bytes, inner_public_bind)?;
    if z.len() != nvars {
        return None;
    }
    let layout = BoundLayout { nvars, per, width, powers: 0, power_lo: 0, shifted_lo, shifted };
    let mut vals: Vec<Ea4> = vec![Ea4::ZERO; layout.values()];
    // The claim chain, recomputed natively exactly as the verifier does — never carried.
    let mut claim = Ea4::ZERO;
    for k in 0..nvars {
        let h = &bundle.zc.round_evals[k];
        if h.len() != per {
            return None;
        }
        for (j, e) in h.iter().enumerate() {
            vals[layout.eval_at(k, j)] = *e;
        }
        vals[layout.r_at(k)] = bundle.zc.r[k];
        vals[layout.z_at(k)] = z[k];
        claim = lagrange(h, bundle.zc.r[k]);
        vals[layout.claim_at(k)] = claim;
    }
    vals[layout.cf()] = claim;
    for (c, o) in bundle.zc.opened.iter().enumerate() {
        vals[layout.opened_at(c)] = *o;
    }
    let limbs: Vec<Fa4> = vals
        .iter()
        .flat_map(|v| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v)[..4].to_vec()
        })
        .collect();
    Some((limbs, layout, gamma))
}

#[cfg(test)]
mod gates {
    use super::*;
    use crate::committed_air::{prove_air_committed_bytes, verify_air_committed_bytes};
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };

    /// ⭐ A NON-HOMOGENEOUS, NON-LINEAR inner AIR — the shape every real one has: its public statement enters its
    /// own constraint, so the all-zero row is NOT a solution, and its degree is ≥ 2 so its sumcheck carries live
    /// values (see `degree()` below). `col0 · col1 − col2 == PUB`.
    #[derive(Clone)]
    struct InnerGate {
        gamma: Ea4,
        pub_val: Ea4,
    }
    impl AirConstraint for InnerGate {
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        // ⛔ NON-LINEAR ON PURPOSE (2026-09-30, strict census). This fixture was `a + b − c − pub`: a LINEAR law that
        // holds on the hypercube holds at every multilinear-extension point too, so the inner sumcheck it produces is
        // identically zero — every claim, every round eval and `cf` are 0, and the bound step's closing equation
        // `cf − eq(z, r)·C(opened)` never READS `r` or `z`. The free-witness census then reported the 20 challenge and
        // OOD cells (80 limbs) as free: a fact about the fixture's degenerate statement, not about the bound step
        // (a production inner gate has degree ≥ 3 and `C(opened(r)) ≠ 0` generically). A degree-2 law gives the
        // sumcheck live values, so this test exercises the binding it exists to exercise.
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let _ = self.gamma;
            local[0] * local[1] - local[2] - self.pub_val
        }
    }

    const PUB: u64 = 0xBD_2C;

    fn inner_make() -> impl Fn(Ea4) -> InnerGate + Clone {
        move |gamma: Ea4| InnerGate { gamma, pub_val: Ea4::from(Fa4::from_u64(PUB)) }
    }

    fn inner_cols(h: usize) -> Vec<Vec<Fa4>> {
        let a: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64(i as u64 + 1)).collect();
        let b: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64((i as u64 + 1) * 5)).collect();
        // col2 = col0 · col1 − PUB, so the (non-linear) AIR holds on every row.
        let c: Vec<Fa4> = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| *x * *y - Fa4::from_u64(PUB))
            .collect();
        vec![a, b, c]
    }

    /// ⭐⭐⭐ THE GATE §BD-2 EXISTS FOR — AND THE FORGERY IT ACCEPTS TODAY, SIDE BY SIDE.
    ///
    /// Left: today's recursion shape, which asserts only the round chain and a free `claimed_final`.
    /// A row of ZEROS satisfies it, with no inner proof anywhere. Right: the same step with the
    /// native verifier's closing equation added. The forgery must now satisfy
    /// `0 == eq(z,r)·C_γ(0)`, and `C_γ(0) = −PUB ≠ 0`, so it dies.
    #[test]
    fn a_step_with_no_inner_proof_passes_the_old_shape_and_dies_on_the_bound_one() {
        let inner_pb = [Fa4::from_u64(PUB)];
        let h = 1usize << 10;
        // A REAL inner carrier — the control's subject.
        let inner = prove_air_direct_light_decider_selfcontained_bytes(inner_cols(h), inner_make(), &inner_pb)
            .expect("the inner AIR proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&inner, inner_make(), &inner_pb, crate::whir_rec_block::declared_direct_shape_for_tests(&inner)),
            "CONTROL: the inner carrier must verify on its own"
        );
        let (row, layout, gamma) =
            bound_step_row(&inner, &inner_pb).expect("an outer row from a real inner carrier");
        let vals = layout.values();
        assert_eq!(row.len(), vals * 4, "the row is four base limbs per value");

        // The outer statement. Held in the public bind so the step cannot be replayed elsewhere.
        let out_pb = [Fa4::from_u64(0xB0_11), Fa4::from_u64(PUB)];
        let outer_h = 1usize << 10;
        let make_outer = {
            let inner_gate = InnerGate { gamma, pub_val: Ea4::from(Fa4::from_u64(PUB)) };
            move |g: Ea4| BoundStepConstraint {
                gamma: g,
                layout,
                inner: constant_inner(inner_gate.clone()),
            }
        };
        let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; outer_h]).collect();
        let t = std::time::Instant::now();
        let honest = prove_air_committed_bytes(cols, make_outer.clone(), &out_pb)
            .expect("the BOUND step proves over a real inner carrier");
        let pm = t.elapsed().as_millis();
        let ok = verify_air_committed_bytes(&honest, make_outer.clone(), &out_pb, crate::committed_air::declared_committed_shape_for_tests(&honest));
        eprintln!(
            "[bound-step] CONTROL: a bound step over a REAL inner carrier — prove {pm} ms, {} B, verifies={ok} (inner nvars={} per={} width={})",
            honest.len(), layout.nvars, layout.per, layout.width
        );
        assert!(ok, "CONTROL FAILED: an honest bound step must verify, or the refusal below proves nothing");

        // ⛔⛔⛔ THE FORGERY: a step with NO inner proof at all — every value zero. This is exactly the
        // object the one-table IVC step (deleted at source 2026-09-28) accepted while claiming 2^100 of work.
        let zero_cols: Vec<Vec<Fa4>> = (0..vals * 4).map(|_| vec![Fa4::ZERO; outer_h]).collect();
        let forged = prove_air_committed_bytes(zero_cols.clone(), make_outer.clone(), &out_pb);
        let bound_verdict = forged
            .as_ref()
            .map(|b| verify_air_committed_bytes(b, make_outer.clone(), &out_pb, crate::committed_air::declared_committed_shape_for_tests(b)));

        // And the SAME zero row against the OLD shape (round chain + free `claimed_final`), to show the
        // difference is the closing residual and nothing else.
        struct OldShape {
            gamma: Ea4,
            layout: BoundLayout,
        }
        impl AirConstraint for OldShape {
            fn degree(&self, _nvars: usize) -> usize {
                self.layout.per.max(2)
            }
            fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
                let l = self.layout;
                let basis: [Ea4; 4] = core::array::from_fn(|i| {
                    <Ea4 as p3_field::BasedVectorSpace<Fa4>>::ith_basis_element(i).expect("basis")
                });
                let get = |i: usize| -> Ea4 {
                    let b = i * 4;
                    // ⭐ A coordinate shift, not four multiplies — `air_zerocheck::pack_limbs`.
                    crate::air_zerocheck::pack_limbs(local[b], local[b + 1], local[b + 2], local[b + 3])
                };
                let mut res: Vec<Ea4> = Vec::new();
                for k in 0..l.nvars {
                    let prev = if k == 0 { Ea4::ZERO } else { get(l.claim_at(k - 1)) };
                    let hh: Vec<Ea4> = (0..l.per).map(|j| get(l.eval_at(k, j))).collect();
                    res.push(hh[0] + hh[1] - prev);
                    res.push(get(l.claim_at(k)) - super::lagrange(&hh, get(l.r_at(k))));
                }
                res.push(get(l.cf()) - get(l.claim_at(l.nvars - 1)));
                let mut acc = Ea4::ZERO;
                let mut gp = Ea4::ONE;
                for r in res {
                    acc += gp * r;
                    gp *= self.gamma;
                }
                acc
            }
        }
        let make_old = move |g: Ea4| OldShape { gamma: g, layout };
        let old_verdict = prove_air_committed_bytes(zero_cols, make_old.clone(), &out_pb)
            .map(|b| verify_air_committed_bytes(&b, make_old.clone(), &out_pb, crate::committed_air::declared_committed_shape_for_tests(&b)));

        eprintln!(
            "[bound-step] ZERO STEP, NO INNER PROOF: old shape (round chain + free claimed_final) = {old_verdict:?} · BOUND shape (closing residual added) = {bound_verdict:?}"
        );
        assert_eq!(
            old_verdict,
            Some(true),
            "CALIBRATION: the old shape MUST accept the zero step, or this test is not measuring §BD-2"
        );
        assert!(
            bound_verdict != Some(true),
            "⛔⛔⛔ §BD-2(b) IS NOT CLOSED: a step with no inner proof still verifies once the closing \
             residual is enforced. Re-derive `eq(z,r)·C_γ(opened)` before trusting any recursion."
        );

        // ⛔⛔⛔ AND NOW PROBE THE FIX ITSELF — §BG's lesson, applied to my own work.
        //
        // (b) forces `cf == eq(z,r)·C_γ(opened)`. A forger who cannot invent `cf` freely can still try
        // the OTHER direction: supply an `opened` row that SATISFIES the inner AIR (so C_γ(opened)=0),
        // set cf=0, and close the chain with zero round-evals. Nothing here ties `opened` to a COMMITTED
        // inner trace — that is part (c), the opening chain — so this is exactly what (b) alone leaves.
        let mut solved = vec![Fa4::ZERO; vals * 4];
        {
            // A row satisfying `col0 + col1 − col2 == PUB`, written into the opened slots. Everything
            // else stays zero: chain at zero, cf at zero, and eq(z,r)·0 == 0.
            let put = |dst: &mut Vec<Fa4>, idx: usize, val: Ea4| {
                let limbs = <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&val);
                for (t, &limb) in limbs.iter().enumerate().take(4) {
                    dst[idx * 4 + t] = limb;
                }
            };
            put(&mut solved, layout.opened_at(0), Ea4::from(Fa4::from_u64(7)));
            put(&mut solved, layout.opened_at(1), Ea4::from(Fa4::from_u64(PUB)));
            put(&mut solved, layout.opened_at(2), Ea4::from(Fa4::from_u64(7)));
        }
        let solved_cols: Vec<Vec<Fa4>> = solved.iter().map(|&v| vec![v; outer_h]).collect();
        let solved_verdict = prove_air_committed_bytes(solved_cols, make_outer.clone(), &out_pb)
            .map(|b| verify_air_committed_bytes(&b, make_outer.clone(), &out_pb, crate::committed_air::declared_committed_shape_for_tests(&b)));
        eprintln!(
            "[bound-step] ⛔ PROBE OF THE FIX — `opened` SOLVED to satisfy the inner AIR, chain and cf zero, \
             NO inner proof: verifies={solved_verdict:?}  (this is exactly what part (c) — the unanchored \
             opening chain — still leaves open)"
        );
        // Recorded, not asserted away. When (c) lands this becomes `!= Some(true)` and §BD-2 closes whole.
        assert!(
            solved_verdict.is_some(),
            "the probe must at least produce a proof, or it measures nothing"
        );
    }
}

/// The committed twin of [`bound_step_row`] — lay one outer row from a carrier on the path item 1 moved
/// production onto.
///
/// ⭐⭐⭐ WHY IT EXISTS. `bound_step_row` parses `AirDirectBundle`, and after item 1 no production
/// value-carrying carrier is one. A note-transition aggregate (§BA/§BB) is N of these rows, so without
/// this there is no aggregate to build. §BQ named it as the remaining gap the moment the migration
/// landed.
///
/// ⭐ AND IT IS WHERE THE 63× SHOWS UP (§BP). The transcript this replays is the carrier's public bind,
/// its COMMITMENT, and its OOD answers — 49 field elements before γ, against 7,977 on the direct path.
/// That is what makes deriving these challenges IN CIRCUIT affordable, which is what a bound aggregate
/// ultimately needs so a prover cannot choose its own batching scalar.
#[must_use]
pub fn bound_step_row_committed(
    inner_bytes: &[u8],
    inner_public_bind: &[Fa4],
    shifted_lo: usize,
    shifted: usize,
) -> Option<(Vec<Fa4>, BoundLayout, Ea4)> {
    // ⛔ ONE LAYOUT PER CLASS (2026-11-10). A class whose gate reads the next row (`shifted > 0`) is carried by the
    // CHAINED door, whose next-row values are bound to the commitment; a row-local class (`shifted == 0`) by the plain
    // door, whose carrier ships none. The class says which, never the bytes: nothing here tries both.
    let (zc, next, (nvars, width)) = if shifted == 0 {
        let (zc, shape) = crate::committed_air::zerocheck_of_committed_carrier(inner_bytes)?;
        if !zc.shifted_opened.is_empty() {
            return None; // the plain door's one encoding carries no next-row opening
        }
        (zc, Vec::new(), shape)
    } else {
        crate::committed_air::zerocheck_of_chained_carrier(inner_bytes)?
    };
    if next.len() != shifted || shifted_lo.checked_add(shifted).map_or(true, |end| end > width) {
        return None; // fail-closed: the carrier's next-row values are not this class's run
    }
    let per = zc.round_evals.first()?.len();
    if zc.r.len() != nvars || zc.opened.len() != width || zc.round_evals.len() != nvars {
        return None; // fail-closed: the carrier does not describe its own shape consistently
    }
    let (gamma, z) = if shifted == 0 {
        crate::committed_air::transcript_of_committed_carrier(inner_bytes, inner_public_bind)?
    } else {
        crate::committed_air::transcript_of_chained_carrier(inner_bytes, inner_public_bind)?
    };
    if z.len() != nvars {
        return None;
    }
    let layout = BoundLayout { nvars, per, width, powers: 0, power_lo: 0, shifted_lo, shifted };
    let mut vals: Vec<Ea4> = vec![Ea4::ZERO; layout.values()];
    // The claim chain, recomputed natively exactly as the verifier does — never carried.
    let mut claim = Ea4::ZERO;
    for k in 0..nvars {
        let h = &zc.round_evals[k];
        if h.len() != per {
            return None;
        }
        for (j, e) in h.iter().enumerate() {
            vals[layout.eval_at(k, j)] = *e;
        }
        vals[layout.r_at(k)] = zc.r[k];
        vals[layout.z_at(k)] = z[k];
        claim = lagrange(h, zc.r[k]);
        vals[layout.claim_at(k)] = claim;
    }
    vals[layout.cf()] = claim;
    for (c, o) in zc.opened.iter().enumerate() {
        vals[layout.opened_at(c)] = *o;
    }
    // ⛔ THE ROTATION THE INNER GATE READS: the chained carrier's own next-row values, one per column of the class's
    // run `shifted_lo ..`, in order (the count was checked against the run above).
    for (i, value) in next.iter().enumerate() {
        vals[layout.shifted_at(i)] = *value;
    }
    let limbs: Vec<Fa4> = vals
        .iter()
        .flat_map(|v| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v)[..4].to_vec()
        })
        .collect();
    Some((limbs, layout, gamma))
}

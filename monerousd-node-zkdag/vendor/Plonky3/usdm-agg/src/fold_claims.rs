// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! MANY PROGRAM CLAIMS INTO ONE (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13): a merge's children each leave claims of the
//! form "the program's preprocessed columns `J` at point `p` are `v`" (`ssa_inner::Deferred`). Checked one by one at the
//! root they would cost two program MLEs a proof — more per payment than today's direct check. Folded here, in circuit,
//! into ONE claim on all `NFIXED` columns at a fresh point, the root checks O(depth) MLEs a block.
//!
//! PROTOCOL (BORROWED: the standard multi-point to one-point reduction by sumcheck, e.g. Thaler §4.5.2; the claims'
//! values are absorbed before μ, ν exist): `S = Σ_i μ^i Σ_{j∈J_i} ν^j v_ij = Σ_y [D_all(y)·K_all(y) + D_bus(y)·K_bus(y)]`
//! with `D_J(y) = Σ_{j∈J} ν^j col_j(y)` and `K_J(y) = Σ_{i: J_i = J} μ^i eq(p_i, y)`; a sumcheck over `y` (degree 2 a
//! round: `g(0), g(2)` sent, `g(1) = claim − g(0)`) ends at `y*`, where the prover states every column `V*` and the
//! circuit checks `claim == D_all(V*)·K_all(y*) + D_bus(V*)·K_bus(y*)`. The output `(y*, V*)` is a claim of the same kind
//! (all columns), checked exactly by whoever holds the program — so a false `V*_j` is caught there, and a false input
//! claim makes the sumcheck's last check fail but with probability `≤ 2n/|F| + claims/|F|`.
//!
//! AI RESISTANT: (a) — a sumcheck the circuit checks and an exact native check at the root.
//! SAFE AT SCALE: `n` rounds and `claims × n` products, whatever the tree's size.

use p3_field::PrimeCharacteristicRing;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::door_ssa::{eq_ext, horner, lagrange};
use crate::ssa::{Builder, Chal, Ext, F_ADDR, F_MULT, NFIXED, NSLOT};

/// The columns a claim names: the bus's address and multiplicity columns (an `x`-claim), or every preprocessed column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cols {
    Bus,
    All,
}

impl Cols {
    #[must_use]
    pub fn indices(self) -> Vec<usize> {
        match self {
            Cols::Bus => (F_ADDR..F_MULT + NSLOT).collect(),
            Cols::All => (0..NFIXED).collect(),
        }
    }
}

/// A claim about one program's preprocessed columns: at `point`, the columns `cols` have `vals` (in `cols` order).
#[derive(Clone, Debug)]
pub struct Claim {
    pub point: Vec<Ext>,
    pub cols: Cols,
    pub vals: Vec<Ext>,
}

/// The folded claim: every preprocessed column at `y`.
#[derive(Clone, Debug)]
pub struct Folded {
    pub y: Vec<Ext>,
    pub v: Vec<Ext>,
}

fn eq_table_e(p: &[Ea4]) -> Vec<Ea4> {
    crate::gkr::eq_table(p)
}

/// Fold `claims` (all about the program whose preprocessed columns are `fixed`, `None` when only the program is being
/// built) into one. The values the prover needs (round polynomials, `V*`) are computed from `fixed` and the builder's
/// own values of the claims.
pub fn emit_fold(b: &mut Builder, claims: &[Claim], nvars: usize, fixed: Option<&[Vec<Fa4>]>) -> Result<Folded, String> {
    if claims.is_empty() {
        return Err("no claim to fold".into());
    }
    for c in claims {
        if c.point.len() != nvars || c.vals.len() != c.cols.indices().len() {
            return Err("a claim is not of this program's shape".into());
        }
    }
    let mut ch = Chal::new();
    for c in claims {
        for e in c.point.iter().chain(&c.vals) {
            ch.observe_ext(b, *e);
        }
    }
    let mu = ch.sample_ext(b);
    let nu = ch.sample_ext(b);
    // S = Σ_i μ^i Σ_j ν^(col j) v_ij — the ν power is the column's own index, so D_bus and D_all agree on a column
    let mut nu_pows: Vec<Ext> = vec![Ext::ONE];
    for _ in 1..NFIXED {
        let l = *nu_pows.last().expect("a power");
        nu_pows.push(b.mul(l, nu));
    }
    let mut per_claim = Vec::with_capacity(claims.len());
    for c in claims {
        let mut acc = Ext::ZERO;
        for (k, j) in c.cols.indices().into_iter().enumerate() {
            acc = b.mul_add(nu_pows[j], c.vals[k], acc);
        }
        per_claim.push(acc);
    }
    let mut claim = horner(b, &per_claim, mu);
    // the prover's tables (native), when the program is known
    let (mu_v, nu_v) = (b.ext_val(mu), b.ext_val(nu));
    let t = 1usize << nvars;
    let mut tabs: Option<[Vec<Ea4>; 4]> = fixed.map(|fx| {
        let mut d_all = vec![Ea4::ZERO; t];
        let mut d_bus = vec![Ea4::ZERO; t];
        let mut np = Ea4::ONE;
        for (j, col) in fx.iter().enumerate() {
            let bus = (F_ADDR..F_MULT + NSLOT).contains(&j);
            for (y, v) in col.iter().enumerate() {
                if *v != Fa4::ZERO {
                    let w = np * *v;
                    d_all[y] += w;
                    if bus {
                        d_bus[y] += w;
                    }
                }
            }
            np *= nu_v;
        }
        let mut k_all = vec![Ea4::ZERO; t];
        let mut k_bus = vec![Ea4::ZERO; t];
        let mut mp = Ea4::ONE;
        for c in claims {
            let p: Vec<Ea4> = c.point.iter().map(|e| b.ext_val(*e)).collect();
            let eq = eq_table_e(&p);
            let dst = if c.cols == Cols::Bus { &mut k_bus } else { &mut k_all };
            for (y, e) in eq.iter().enumerate() {
                dst[y] += mp * *e;
            }
            mp *= mu_v;
        }
        [d_all, k_all, d_bus, k_bus]
    });
    let mut ystar = Vec::with_capacity(nvars);
    for _ in 0..nvars {
        let g = |tabs: &Option<[Vec<Ea4>; 4]>, tt: Ea4| -> Ea4 {
            let Some([da, ka, db, kb]) = tabs else { return Ea4::ZERO };
            let h = da.len() / 2;
            let line = |v: &[Ea4], i: usize| v[i] + tt * (v[i + h] - v[i]);
            (0..h).map(|i| line(da, i) * line(ka, i) + line(db, i) * line(kb, i)).sum()
        };
        let (g0, g2) = (g(&tabs, Ea4::ZERO), g(&tabs, Ea4::from(Fa4::TWO)));
        let a0 = b.load_ext(g0);
        let a2 = b.load_ext(g2);
        ch.observe_ext(b, a0);
        ch.observe_ext(b, a2);
        let c = ch.sample_ext(b);
        let a1 = b.sub(claim, a0);
        claim = lagrange(b, &[a0, a1, a2], c);
        let cv = b.ext_val(c);
        if let Some(tb) = tabs.as_mut() {
            for v in tb.iter_mut() {
                let h = v.len() / 2;
                *v = (0..h).map(|i| v[i] + cv * (v[i + h] - v[i])).collect();
            }
        }
        ystar.push(c);
    }
    // V*: every column at y*
    let yv: Vec<Ea4> = ystar.iter().map(|e| b.ext_val(*e)).collect();
    let vstar_v: Vec<Ea4> = match fixed {
        Some(fx) => {
            let eq = eq_table_e(&yv);
            fx.iter().map(|col| col.iter().zip(&eq).filter(|(v, _)| **v != Fa4::ZERO).map(|(v, e)| *e * *v).sum()).collect()
        }
        None => vec![Ea4::ZERO; NFIXED],
    };
    let vstar: Vec<Ext> = vstar_v.iter().map(|v| b.load_ext(*v)).collect();
    // the last check
    let mut d_all = Ext::ZERO;
    let mut d_bus = Ext::ZERO;
    for j in 0..NFIXED {
        d_all = b.mul_add(nu_pows[j], vstar[j], d_all);
        if (F_ADDR..F_MULT + NSLOT).contains(&j) {
            d_bus = b.mul_add(nu_pows[j], vstar[j], d_bus);
        }
    }
    let (mut k_all, mut k_bus) = (Ext::ZERO, Ext::ZERO);
    let mut mp = Ext::ONE;
    for c in claims {
        let e = eq_ext(b, &c.point, &ystar);
        if c.cols == Cols::Bus {
            k_bus = b.mul_add(mp, e, k_bus);
        } else {
            k_all = b.mul_add(mp, e, k_all);
        }
        mp = b.mul(mp, mu);
    }
    let t1 = b.mul(d_bus, k_bus);
    let rhs = b.mul_add(d_all, k_all, t1);
    b.assert_eq(claim, rhs);
    Ok(Folded { y: ystar, v: vstar })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;

    fn rnd(seed: &mut u64) -> Ea4 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let s = *seed;
        let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((s >> (9 * i)) % 2_130_706_433));
        Ea4::from_basis_coefficients_slice(&l).expect("limbs")
    }

    /// ⭐ THE FOLD'S PIN — four true claims about a program (two on the bus columns, two on all) fold into one claim the
    /// program satisfies (its MLE at `y*` IS `V*`), every assertion holding; one false input value is a failed assertion
    /// (the prover cannot make the last check with the program's true `V*`).
    #[test]
    fn f1_program_claims_fold_into_one_the_program_satisfies() {
        let mut seed = 0xF01Du64;
        let nvars = 5usize;
        let t = 1usize << nvars;
        let fixed: Vec<Vec<Fa4>> = (0..NFIXED).map(|j| (0..t).map(|y| if (j + y) % 3 == 0 { Fa4::from_u64((j * 31 + y) as u64) } else { Fa4::ZERO }).collect()).collect();
        let prog_at = |p: &[Ea4]| -> Vec<Ea4> {
            let eq = crate::gkr::eq_table(p);
            fixed.iter().map(|c| c.iter().zip(&eq).map(|(v, e)| *e * *v).sum()).collect()
        };
        let pts: Vec<Vec<Ea4>> = (0..4).map(|_| (0..nvars).map(|_| rnd(&mut seed)).collect()).collect();
        let build = |lie: bool| -> (Builder, Folded) {
            let mut b = Builder::new();
            let mut claims = Vec::new();
            for (i, p) in pts.iter().enumerate() {
                let cols = if i % 2 == 0 { Cols::Bus } else { Cols::All };
                let all = prog_at(p);
                let mut vals: Vec<Ea4> = cols.indices().iter().map(|&j| all[j]).collect();
                if lie && i == 3 {
                    vals[7] += Ea4::ONE;
                }
                let point = p.iter().map(|v| b.load_ext(*v)).collect();
                let vals = vals.iter().map(|v| b.load_ext(*v)).collect();
                claims.push(Claim { point, cols, vals });
            }
            let f = emit_fold(&mut b, &claims, nvars, Some(&fixed)).expect("folds");
            (b, f)
        };
        let (b, f) = build(false);
        assert_eq!(b.mismatch, None, "⛔ an assertion of the fold fails on true claims");
        let y: Vec<Ea4> = f.y.iter().map(|e| b.ext_val(*e)).collect();
        let v: Vec<Ea4> = f.v.iter().map(|e| b.ext_val(*e)).collect();
        assert_eq!(v, prog_at(&y), "⛔ the folded claim is not the program's");
        let (lb, _) = build(true);
        assert!(lb.mismatch.is_some(), "⛔ a false input claim folded into a claim the program satisfies");
        let (_, prog) = crate::ssa::lay(&b).expect("lays");
        println!("[agg-f1] four claims folded: {} ops, {} rows", b.ops.len(), prog.rows);
    }
}

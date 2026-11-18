// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! AN SSA PROOF VERIFIED INSIDE AN SSA PROGRAM (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13) — a merge's child:
//! `ssa_door::verify`, step for step, on the builder, except the one check a circuit cannot afford: that the child's
//! preprocessed values at its two points are its PROGRAM's (an MLE over the whole program). Those are DEFERRED: the
//! returned [`Deferred`] names the points and the values (folded at α, drawn after the child's transcript absorbed them),
//! and the caller binds it into its own statement; the root checks every deferred claim natively against the programs it
//! rebuilds. Everything else — the bus's GKR and its balance with the child's public values, the leaf claim, the
//! zerocheck against the universal gate evaluated in circuit, the batched claim and the WHIR opening — is a constraint.
//!
//! An inverse the circuit needs (`1/q` of a public fraction, `1/Q₀`) is loaded and asserted: `inv·q = 1`.

use p3_field::{Field, PrimeCharacteristicRing};
use usdm_decider::committed_air::door_whir_config;
use usdm_decider::gate_trace::GateProgram;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::door_ssa::{eq_ext, horner, lagrange, selector_prefix_sums, WhirSsa};
use crate::gate_ssa::emit_gate;
use crate::ssa::{slot_col, Addr, Builder, Chal, Ext, NCOMMIT, NFIXED, NSLOT, RATE};
use crate::ssa_door::{SsaBundle, PARAMS, SLOT_BITS};

/// The universal gate as a program (permutation blocks inline), over `NCOMMIT + NFIXED` inputs.
#[must_use]
pub fn ssa_gate_program() -> Option<GateProgram> {
    usdm_decider::gate_trace::trace(NCOMMIT + NFIXED, |ins| {
        let oob = usdm_decider::air_zerocheck::OobLatch::new();
        let row = usdm_decider::air_zerocheck::Row::new(ins, &oob);
        crate::ssa::ssa_residuals(&row)
    })
}

/// A child's public value as the parent holds it: a constant of the child's program, or a lane of the child's
/// statement (an address in the parent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PubVal {
    Const(Fa4),
    At(Addr),
}

/// What the parent knows of a child's program: its arity and its public part (address, value, multiplicity).
#[derive(Clone, Debug)]
pub struct ChildShape {
    pub nvars: usize,
    pub public: Vec<(Addr, PubVal, u64)>,
}

impl ChildShape {
    /// A child's shape from its program: its constants stay constants, its statement lanes are `io` (addresses in
    /// the parent, in the child's statement order).
    #[must_use]
    pub fn of(prog: &crate::ssa::Program, io: &[Addr]) -> Option<ChildShape> {
        if io.len() != prog.statement.len() {
            return None;
        }
        let public = prog
            .public
            .iter()
            .map(|&(a, v, m)| match prog.statement.iter().position(|&s| s == a) {
                Some(i) => (a, PubVal::At(io[i]), m),
                None => (a, PubVal::Const(v), m),
            })
            .collect();
        Some(ChildShape { nvars: prog.nvars, public })
    }
}

/// A child's deferred program claim: the points and the preprocessed values there, folded at `alpha`.
#[derive(Clone, Copy, Debug)]
pub struct DeferredAt {
    pub alpha: Ext,
    /// `Σ_j α^j · fixed_at_x[j]` (the 2·NSLOT bus columns) and `Σ_j α^j · fixed_at_r[j]` (all NFIXED).
    pub combo_x: Ext,
    pub combo_r: Ext,
}

#[derive(Clone, Debug)]
pub struct Deferred {
    pub x: Vec<Ext>,
    pub r: Vec<Ext>,
    pub at: DeferredAt,
    /// The child's bus address and multiplicity columns at `x` (`2·NSLOT`, `fold_claims::Cols::Bus` order).
    pub fx: Vec<Ext>,
    /// Every preprocessed column of the child at `r` (`NFIXED`).
    pub fr: Vec<Ext>,
}

fn inv_checked(b: &mut Builder, q: Ext) -> Ext {
    let v = b.ext_val(q);
    let inv = b.load_ext(v.try_inverse().unwrap_or(Ea4::ZERO));
    let prod = b.mul(inv, q);
    b.assert_eq(prod, Ext::ONE);
    inv
}

/// `Σ_j α^(j+off)·eq(lift(col_j), pt)` over a contiguous run of columns `[lo, hi)` claimed as consecutive claims starting
/// at α-power `off`: `α^(off − lo)·(P(hi) − P(lo))`, with `α^(−lo)` loaded and checked when `off < lo`.
fn run_weight(b: &mut Builder, sel: &[Ext], alpha: Ext, lo: usize, hi: usize, off: usize) -> Ext {
    let (p, _) = selector_prefix_sums(b, sel, alpha, &[lo, hi]);
    let diff = b.sub(p[1], p[0]);
    let scale = if off >= lo {
        pow(b, alpha, off - lo)
    } else {
        let up = pow(b, alpha, lo - off);
        inv_checked(b, up)
    };
    b.mul(scale, diff)
}

fn pow(b: &mut Builder, a: Ext, e: usize) -> Ext {
    let (mut acc, mut p, mut k) = (Ext::ONE, a, e);
    while k > 0 {
        if k & 1 == 1 {
            acc = b.mul(acc, p);
        }
        k >>= 1;
        if k > 0 {
            p = b.mul(p, p);
        }
    }
    acc
}

/// The SSA door's initial constraint (`LayoutVerifier::constraint` of its claims: the 64 slot columns at `x`, the
/// committed row at `r`, then the virtual out-of-domain answers) weighted at the folding point `coords`, in closed form:
/// `eq(x, low)·(Σ_{j<16} α^j·eq(bits(j), sel) + α^(16−148)·Σ_{c∈[148,196)} α^c·eq(bits(c), sel))
/// + α^64·eq(r, low)·Σ_{c<197} α^c·eq(bits(c), sel) + α^261·Σ_i α^i·eq(expand(y_i), coords)`.
pub(crate) fn child_init_weight(b: &mut Builder, coords: &[Ext], sbits: usize, alpha: Ext, x: &[Ext], r: &[Ext], ys: &[Ext]) -> Ext {
    let (selc, low) = crate::door_ssa::split_lifted(coords, coords.len() - sbits);
    let (selc, low) = (&selc[..], &low[..]);
    // slots 0..16 are columns 0..16 (α^0..); slots 16..NSLOT are columns POUT..POUT+NSLOT−16 (α^16..)
    debug_assert!((16..NSLOT).all(|j| slot_col(j) == slot_col(16) + (j - 16)));
    let w1 = run_weight(b, selc, alpha, 0, 16, 0);
    let w2 = run_weight(b, selc, alpha, slot_col(16), slot_col(16) + NSLOT - 16, 16);
    let wx0 = b.add(w1, w2);
    let ex = eq_ext(b, x, low);
    let wx = b.mul(ex, wx0);
    let wr0 = run_weight(b, selc, alpha, 0, NCOMMIT, NSLOT);
    let er = eq_ext(b, r, low);
    let wsum = b.mul_add(er, wr0, wx);
    let k = coords.len();
    let mut osum = Ext::ZERO;
    for y in ys.iter().rev() {
        let mut pw = vec![*y];
        for _ in 1..k {
            let last = *pw.last().expect("a power");
            pw.push(b.mul(last, last));
        }
        pw.reverse();
        let ey = eq_ext(b, &pw, coords);
        osum = b.mul_add(osum, alpha, ey);
    }
    let anc = pow(b, alpha, NSLOT + NCOMMIT);
    b.mul_add(anc, osum, wsum)
}

/// Emit the verification of one SSA child proof. `gate` is [`ssa_gate_program`]; `bytes` the child proof (or `None`).
pub fn emit_ssa_child(b: &mut Builder, child: &ChildShape, gate: &GateProgram, bytes: Option<&[u8]>, whir: &mut dyn WhirSsa) -> Result<Deferred, String> {
    let n = child.nvars;
    let (stacked, cfg) = door_whir_config((n, NCOMMIT), PARAMS).ok_or("no door admits the child's shape")?;
    let per = usdm_decider::pow_pq_air::P2_CONSTRAINT_DEGREE + 1 + 2;
    let lgk = SLOT_BITS + n;
    let bundle: Option<SsaBundle> = match bytes {
        Some(by) => Some(postcard::from_bytes(by).map_err(|e| format!("the child proof does not decode: {e}"))?),
        None => None,
    };
    if let Some(bb) = &bundle {
        if bb.nvars != n || bb.slot_at_x.len() != NSLOT || bb.fixed_at_x.len() != 2 * NSLOT || bb.zc.opened.len() != NCOMMIT + NFIXED || bb.zc.round_evals.len() != n || bb.zc.round_evals.iter().any(|h| h.len() != per) || bb.gkr.layers.len() != lgk || bb.gkr.layers.iter().enumerate().any(|(k, l)| l.rounds.len() != k) || bb.open.initial_ood_answers.len() != cfg.commitment_ood_samples || !bb.open.hvzk_mask_commits.is_empty() {
            return Err("the child proof is not its shape".into());
        }
    }
    let z4 = Ea4::ZERO;
    b.phase = "child: statement".into();
    let mut ch = Chal::new();
    // the statement: every public value, in order
    let pubs: Vec<Addr> = child.public.iter().map(|&(_, v, _)| match v { PubVal::Const(c) => b.konst(c), PubVal::At(a) => a }).collect();
    ch.observe_all(b, &pubs);
    let root_words: [Fa4; RATE] = bundle.as_ref().map_or([Fa4::ZERO; RATE], |bb| {
        let cap: &[[Fa4; RATE]] = bb.commitment.as_ref();
        cap[0]
    });
    let rv = b.load(&root_words);
    let root: [Addr; RATE] = rv[..].try_into().map_err(|_| "eight root words")?;
    ch.observe_all(b, &root);
    let mut oods = Vec::new();
    for i in 0..cfg.commitment_ood_samples {
        let y = ch.sample_ext(b);
        let a = b.load_ext(bundle.as_ref().map_or(z4, |bb| bb.open.initial_ood_answers[i]));
        ch.observe_ext(b, a);
        oods.push((y, a));
    }
    // the bus: GKR
    let rho = ch.sample_ext(b);
    let beta = ch.sample_ext(b);
    let g = bundle.as_ref().map(|bb| &bb.gkr);
    let p0 = b.load_ext(g.map_or(z4, |g| g.root[0]));
    let q0 = b.load_ext(g.map_or(z4, |g| g.root[1]));
    ch.observe_ext(b, p0);
    ch.observe_ext(b, q0);
    let mut zpt: Vec<Ext> = Vec::new();
    let (mut cp, mut cq) = (p0, q0);
    for k in 0..lgk {
        b.phase = format!("child: gkr layer {k}");
        let lambda = ch.sample_ext(b);
        let mut claim = b.mul_add(lambda, cq, cp);
        let mut bstar = Vec::with_capacity(k + 1);
        for j in 0..k {
            let sent = g.map_or([z4; 3], |g| g.layers[k].rounds[j]);
            let s: Vec<Ext> = sent.iter().map(|v| b.load_ext(*v)).collect();
            for e in &s {
                ch.observe_ext(b, *e);
            }
            let rr = ch.sample_ext(b);
            let g1 = b.sub(claim, s[0]);
            claim = lagrange(b, &[s[0], g1, s[1], s[2]], rr);
            bstar.push(rr);
        }
        let ends = g.map_or([z4; 4], |g| g.layers[k].ends);
        let [e0, e1, e2, e3] = ends.map(|v| b.load_ext(v));
        let eqz = eq_ext(b, &zpt, &bstar);
        let t1 = b.mul(e0, e3);
        let t2 = b.mul_add(e1, e2, t1);
        let t3 = b.mul(e2, e3);
        let inner = b.mul_add(lambda, t3, t2);
        let lhs = b.mul(eqz, inner);
        b.assert_eq(lhs, claim);
        for e in [e0, e1, e2, e3] {
            ch.observe_ext(b, e);
        }
        let c = ch.sample_ext(b);
        let d1 = b.sub(e1, e0);
        cp = b.mul_add(c, d1, e0);
        let d2 = b.sub(e3, e2);
        cq = b.mul_add(c, d2, e2);
        bstar.push(c);
        zpt = bstar;
    }
    b.phase = "child: bus balance".into();
    // the balance: P₀ + Q₀·Σ_public m/(ρ − (addr + β·v)) = 0, Q₀ ≠ 0
    let _ = inv_checked(b, q0);
    let mut spub = Ext::ZERO;
    for (&(addr, _, m), &va) in child.public.iter().zip(&pubs) {
        if m == 0 {
            continue;
        }
        let ka = b.konst_ext(-Ea4::from(Fa4::from_u64(u64::from(addr))));
        let bv = b.mul(beta, Ext([va, crate::ssa::ZERO, crate::ssa::ZERO, crate::ssa::ZERO]));
        let ra = b.add(rho, ka);
        let q = b.sub(ra, bv);
        let inv = inv_checked(b, q);
        spub = b.mul_k_add(inv, Ea4::from(Fa4::from_u64(m)), spub);
    }
    let bal = b.mul_add(q0, spub, p0);
    b.assert_eq(bal, Ext::ZERO);
    b.phase = "child: leaf claim".into();
    // the leaf claim at x* = (xs ‖ x)
    let (xs, x) = zpt.split_at(SLOT_BITS);
    let (xs, x) = (xs.to_vec(), x.to_vec());
    let slot_at_x: Vec<Ext> = (0..NSLOT).map(|s| b.load_ext(bundle.as_ref().map_or(z4, |bb| bb.slot_at_x[s]))).collect();
    for e in &slot_at_x {
        ch.observe_ext(b, *e);
    }
    let fixed_at_x: Vec<Ext> = (0..2 * NSLOT).map(|s| b.load_ext(bundle.as_ref().map_or(z4, |bb| bb.fixed_at_x[s]))).collect();
    for e in &fixed_at_x {
        ch.observe_ext(b, *e);
    }
    // eq(xs, s) for every slot
    let mut eqs = vec![Ext::ONE];
    for xi in &xs {
        let one_m = b.sub(Ext::ONE, *xi);
        let mut nx = Vec::with_capacity(eqs.len() * 2);
        for e in &eqs {
            nx.push(b.mul(*e, one_m));
            nx.push(b.mul(*e, *xi));
        }
        eqs = nx;
    }
    let (mut lp, mut lq) = (Ext::ZERO, Ext::ZERO);
    // the pad slots' constant 0 / 1: q gains their eq weights
    for e in &eqs[NSLOT..] {
        lq = b.add(lq, *e);
    }
    for s in 0..NSLOT {
        lp = b.mul_add(eqs[s], fixed_at_x[NSLOT + s], lp);
        let bsv = b.mul(beta, slot_at_x[s]);
        let ra = b.sub(rho, fixed_at_x[s]);
        let q = b.sub(ra, bsv);
        lq = b.mul_add(eqs[s], q, lq);
    }
    b.assert_eq(lp, cp);
    b.assert_eq(lq, cq);
    b.phase = "child: zerocheck".into();
    // the gate's zerocheck
    let gamma = ch.sample_ext(b);
    let z: Vec<Ext> = (0..n).map(|_| ch.sample_ext(b)).collect();
    let mut claim = Ext::ZERO;
    let mut r = Vec::with_capacity(n);
    for k in 0..n {
        let hv: Vec<Ext> = (0..per).map(|j| b.load_ext(bundle.as_ref().map_or(z4, |bb| bb.zc.round_evals[k][j]))).collect();
        let s = b.add(hv[0], hv[1]);
        b.assert_eq(s, claim);
        for e in &hv {
            ch.observe_ext(b, *e);
        }
        let rk = ch.sample_ext(b);
        claim = lagrange(b, &hv, rk);
        r.push(rk);
    }
    let opened: Vec<Ext> = (0..NCOMMIT + NFIXED).map(|c| b.load_ext(bundle.as_ref().map_or(z4, |bb| bb.zc.opened[c]))).collect();
    b.phase = "child: closing gate check".into();
    let cg = emit_gate(b, gate, &opened, gamma)?;
    let e = eq_ext(b, &z, &r);
    let ec = b.mul(e, cg);
    b.assert_eq(ec, claim);
    for o in &opened {
        ch.observe_ext(b, *o);
    }
    let alpha = ch.sample_ext(b);
    // claimed: the slot claims at x (64), the committed row at r (NCOMMIT), then the virtual answers
    let mut all: Vec<Ext> = slot_at_x.clone();
    all.extend_from_slice(&opened[..NCOMMIT]);
    all.extend(oods.iter().map(|p| p.1));
    let claimed = horner(b, &all, alpha);
    let sbits = stacked - n;
    let (xc, rc, oc) = (x.clone(), r.clone(), oods.clone());
    let ys: Vec<Ext> = oc.iter().map(|p| p.0).collect();
    let mut init = |b: &mut Builder, coords: &[Ext]| -> Ext { child_init_weight(b, coords, sbits, alpha, &xc, &rc, &ys) };
    b.phase = "child: whir".into();
    whir.emit(b, &mut ch, &cfg, bundle.as_ref().map(|bb| &bb.open), root, claimed, &mut init)?;
    // the deferred program claim, folded at α (drawn after the child absorbed every one of these values)
    let combo_x = horner(b, &fixed_at_x, alpha);
    let combo_r = horner(b, &opened[NCOMMIT..], alpha);
    Ok(Deferred { x, r, at: DeferredAt { alpha, combo_x, combo_r }, fx: fixed_at_x, fr: opened[NCOMMIT..].to_vec() })
}

/// The deferred claim's native check: the child program's preprocessed columns at `x` and `r`, folded at α, are the
/// stated combinations.
#[must_use]
pub fn deferred_holds(prog: &crate::ssa::Program, x: &[Ea4], r: &[Ea4], alpha: Ea4, combo_x: Ea4, combo_r: Ea4) -> bool {
    let fx = prog.fixed_at(x);
    let fr = prog.fixed_at(r);
    let fold = |v: &[Ea4]| v.iter().rev().fold(Ea4::ZERO, |acc, e| acc * alpha + *e);
    fold(&fx[crate::ssa::F_ADDR..crate::ssa::F_MULT + NSLOT]) == combo_x && fold(&fr) == combo_r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_whir_ssa::WhirOnSsa;

    /// A child program: a statement of eight lanes absorbed, a few permutations, arithmetic, a walk, a draw.
    fn child_builder(io: &[Fa4; 8]) -> Builder {
        let mut b = Builder::new();
        let st = b.public_vals(io);
        let mut ch = Chal::new();
        ch.observe_all(&mut b, &st);
        let v = b.load(&(0..20u64).map(|i| Fa4::from_u64(i * 13 + 1)).collect::<Vec<_>>());
        ch.observe_all(&mut b, &v);
        let c = ch.sample_ext(&mut b);
        let x = b.load_ext(Ea4::from(Fa4::from_u64(9)));
        let y = b.mul_add(c, x, c);
        ch.observe_ext(&mut b, y);
        let s = ch.draw_index_sum(&mut b, 5);
        let _ = b.bits(s, 0, 2);
        b
    }

    /// THE CLOSED-FORM INITIAL WEIGHT'S PIN — against `LayoutVerifier::constraint` itself: the SSA door's claims (the 64
    /// slot columns at `x`, the committed row at `r`, two virtual answers whose points the layout draws) at random values,
    /// α and a random folding point; `eval_constraints_poly` of the layout's constraint must be the circuit's value.
    #[test]
    fn w2_the_ssa_doors_initial_weight_is_the_layouts_constraint() {
        use p3_challenger::FieldChallenger;
        use p3_multilinear_util::point::Point;
        use p3_sumcheck::layout::{Layout, PrefixProver, Verifier as LayoutVerifier};
        let mut seed = 0xA2_u64;
        let mut rnd = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let s = seed;
            let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((s >> (9 * i)) % 2_130_706_433));
            p3_field::BasedVectorSpace::<Fa4>::from_basis_coefficients_slice(&l).expect("limbs")
        };
        let n = 5usize;
        let (stacked, _) = door_whir_config((n, NCOMMIT), PARAMS).expect("a shape the door admits");
        let shapes = vec![p3_sumcheck::table::TableShape::new(n, NCOMMIT)];
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
        let mut chl = usdm_decider::committed_air::door_challenger();
        let x: Vec<Ea4> = (0..n).map(|_| rnd()).collect();
        let r: Vec<Ea4> = (0..n).map(|_| rnd()).collect();
        let sv: Vec<Ea4> = (0..NSLOT).map(|_| rnd()).collect();
        let cv: Vec<Ea4> = (0..NCOMMIT).map(|_| rnd()).collect();
        let slot_cols: Vec<usize> = (0..NSLOT).map(slot_col).collect();
        lv.add_claim_at(0, &slot_cols, &sv, &Point::new(x.clone()), &mut chl);
        lv.add_claim_at(0, &(0..NCOMMIT).collect::<Vec<_>>(), &cv, &Point::new(r.clone()), &mut chl);
        let mut ys = Vec::new();
        for _ in 0..2 {
            let y: Ea4 = chl.clone().sample_algebra_element();
            ys.push(y);
            lv.add_virtual_eval(rnd(), &mut chl);
        }
        let alpha = rnd();
        let pt: Vec<Ea4> = (0..stacked).map(|_| rnd()).collect();
        let want = PrefixProver::<Fa4, Ea4>::variable_order().eval_constraints_poly(&[lv.constraint(alpha)], &Point::new(pt.clone()));
        let mut b = Builder::new();
        let l = |b: &mut Builder, v: &[Ea4]| -> Vec<Ext> { v.iter().map(|e| b.load_ext(*e)).collect() };
        let (xa, ra, ya, pa) = (l(&mut b, &x), l(&mut b, &r), l(&mut b, &ys), l(&mut b, &pt));
        let aa = b.load_ext(alpha);
        let got = child_init_weight(&mut b, &pa, stacked - n, aa, &xa, &ra, &ya);
        assert_eq!(b.ext_val(got), want, "⛔ the closed-form initial weight is not the layout's constraint");
    }

    /// The weight's pieces, one at a time, against brute force and the layout: `Σ_{c<w} α^c·eq(bits(c), sel)` for
    /// several `w`; then each claim kind alone (the slot claim, the row claim, the virtual answers).
    #[test]
    fn w3_the_weights_pieces_one_at_a_time() {
        use p3_challenger::FieldChallenger;
        use p3_multilinear_util::point::Point;
        use p3_sumcheck::layout::{Layout, PrefixProver, Verifier as LayoutVerifier};
        let mut seed = 0xA3_u64;
        let mut rnd = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let s = seed;
            let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((s >> (9 * i)) % 2_130_706_433));
            p3_field::BasedVectorSpace::<Fa4>::from_basis_coefficients_slice(&l).expect("limbs")
        };
        // (a) the selector prefix sums
        let sb = 8usize;
        let sel: Vec<Ea4> = (0..sb).map(|_| rnd()).collect();
        let alpha = rnd();
        let brute = |w: usize| -> Ea4 {
            (0..w).map(|c| {
                let hyp: Vec<Ea4> = (0..sb).map(|i| if (c >> (sb - 1 - i)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
                alpha.exp_u64(c as u64) * crate::gkr::eq_at(&hyp, &sel)
            }).sum()
        };
        let targets = [0usize, 1, 2, 3, 16, 148, 196, 197, 255, 256];
        let mut b = Builder::new();
        let sa: Vec<Ext> = sel.iter().map(|e| b.load_ext(*e)).collect();
        let aa = b.load_ext(alpha);
        let (p, _) = crate::door_ssa::selector_prefix_sums(&mut b, &sa, aa, &targets);
        for (k, &w) in targets.iter().enumerate() {
            assert_eq!(b.ext_val(p[k]), brute(w), "⛔ the selector prefix sum below {w} is not the brute-force sum");
        }
        // (b) each claim kind alone, against the layout
        let n = 5usize;
        let shapes = vec![p3_sumcheck::table::TableShape::new(n, NCOMMIT)];
        let mut stacked_seen = 0;
        let mut results = Vec::new();
        for case in [1usize, 2, 3, 4, 0] {
            let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
            let mut chl = usdm_decider::committed_air::door_challenger();
            let pt0: Vec<Ea4> = (0..n).map(|_| rnd()).collect();
            let mut ys = Vec::new();
            match case {
                0 => {
                    let v: Vec<Ea4> = (0..NSLOT).map(|_| rnd()).collect();
                    lv.add_claim_at(0, &(0..NSLOT).map(slot_col).collect::<Vec<_>>(), &v, &Point::new(pt0.clone()), &mut chl);
                }
                1 => {
                    let v: Vec<Ea4> = (0..NCOMMIT).map(|_| rnd()).collect();
                    lv.add_claim_at(0, &(0..NCOMMIT).collect::<Vec<_>>(), &v, &Point::new(pt0.clone()), &mut chl);
                }
                3 => {
                    let v: Vec<Ea4> = (0..16).map(|_| rnd()).collect();
                    lv.add_claim_at(0, &(0..16).collect::<Vec<_>>(), &v, &Point::new(pt0.clone()), &mut chl);
                }
                4 => {
                    let v: Vec<Ea4> = (0..48).map(|_| rnd()).collect();
                    lv.add_claim_at(0, &(148..196).collect::<Vec<_>>(), &v, &Point::new(pt0.clone()), &mut chl);
                }
                _ => {
                    let y: Ea4 = chl.clone().sample_algebra_element();
                    ys.push(y);
                    lv.add_virtual_eval(rnd(), &mut chl);
                }
            }
            let c = lv.constraint(alpha);
            let k = c.num_variables();
            stacked_seen = k;
            let pt: Vec<Ea4> = (0..k).map(|_| rnd()).collect();
            let want = PrefixProver::<Fa4, Ea4>::variable_order().eval_constraints_poly(&[c], &Point::new(pt.clone()));
            let mut b = Builder::new();
            let pa: Vec<Ext> = pt.iter().map(|e| b.load_ext(*e)).collect();
            let p0: Vec<Ext> = pt0.iter().map(|e| b.load_ext(*e)).collect();
            let aa = b.load_ext(alpha);
            let (selc, low) = crate::door_ssa::split_lifted(&pa, n);
            let (selc, low) = (&selc[..], &low[..]);
            let got = match case {
                0 => {
                    let w1 = run_weight(&mut b, selc, aa, 0, 16, 0);
                    let w2 = run_weight(&mut b, selc, aa, slot_col(16), slot_col(16) + NSLOT - 16, 16);
                    let w = b.add(w1, w2);
                    let e = eq_ext(&mut b, &p0, low);
                    b.mul(e, w)
                }
                1 => {
                    let w = run_weight(&mut b, selc, aa, 0, NCOMMIT, 0);
                    let e = eq_ext(&mut b, &p0, low);
                    b.mul(e, w)
                }
                3 => {
                    let w = run_weight(&mut b, selc, aa, 0, 16, 0);
                    let e = eq_ext(&mut b, &p0, low);
                    b.mul(e, w)
                }
                4 => {
                    let w = run_weight(&mut b, selc, aa, 148, 196, 0);
                    let e = eq_ext(&mut b, &p0, low);
                    b.mul(e, w)
                }
                _ => {
                    let y = b.load_ext(ys[0]);
                    let mut pw = vec![y];
                    for _ in 1..k {
                        let l = *pw.last().expect("p");
                        pw.push(b.mul(l, l));
                    }
                    pw.reverse();
                    eq_ext(&mut b, &pw, &pa)
                }
            };
            results.push((case, b.ext_val(got) == want, k));
        }
        println!("[agg-w3] (claim kind, closed form matches, stacked): {results:?}");
        assert!(results.iter().all(|r| r.1), "⛔ a claim kind's closed form is not the layout's: {results:?}");
        let (dw, _) = door_whir_config((n, NCOMMIT), PARAMS).expect("admits");
        assert_eq!(dw, stacked_seen, "⛔ the layout's stacked arity is not door_whir_config's");
    }

    /// ⭐ THE MERGE CHILD'S PIN — an SSA proof verified INSIDE an SSA program: every assertion holds on the honest proof,
    /// the deferred program claim holds natively against the child's program, and the verifying program built from the
    /// child's shape alone lays the same rows; a moved GKR round, a moved opened value and another statement are each a
    /// failed assertion.
    #[test]
    fn m1_an_ssa_proof_verifies_inside_an_ssa_program() {
        let io: [Fa4; 8] = core::array::from_fn(|i| Fa4::from_u64(40 + i as u64));
        let cb = child_builder(&io);
        let (crows, cprog) = crate::ssa::lay(&cb).expect("lays");
        let ccols = crate::ssa::execute(&cb, &crows, &cprog).expect("runs");
        let child = crate::ssa_door::prove(&cprog, ccols).expect("proves");
        assert!(crate::ssa_door::verify(&child, &cprog), "CALIBRATION: the child verifies natively");
        let gate = ssa_gate_program().expect("the universal gate traces");
        let parent = |bytes: Option<&[u8]>, io_v: &[Fa4; 8]| -> (Builder, Result<Deferred, String>) {
            let mut b = Builder::new();
            let ioa = b.load(io_v);
            let shape = ChildShape::of(&cprog, &ioa).expect("shape");
            let d = emit_ssa_child(&mut b, &shape, &gate, bytes, &mut WhirOnSsa);
            (b, d)
        };
        let t0 = std::time::Instant::now();
        let (b, d) = parent(Some(&child), &io);
        let d = d.expect("the verifying program builds");
        assert_eq!(b.mismatch, None, "⛔ an assertion fails on an honest child proof");
        let ev = |e: Ext| b.ext_val(e);
        let x: Vec<Ea4> = d.x.iter().map(|e| ev(*e)).collect();
        let r: Vec<Ea4> = d.r.iter().map(|e| ev(*e)).collect();
        assert!(deferred_holds(&cprog, &x, &r, ev(d.at.alpha), ev(d.at.combo_x), ev(d.at.combo_r)), "⛔ the deferred program claim does not hold natively");
        let (vb, _) = parent(None, &[Fa4::ZERO; 8]);
        let (rows, prog) = crate::ssa::lay(&b).expect("lays");
        let (_, vprog) = crate::ssa::lay(&vb).expect("lays");
        assert_eq!(prog.fixed, vprog.fixed, "⛔ the verifying program depends on the child proof's values");
        let alu = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Alu(_))).count();
        println!("[agg-m1] a child of T = 2^{} verified in circuit: {} ops ({alu} multiply-adds), {} rows (T = 2^{}), built in {} ms", cprog.nvars, b.ops.len(), prog.rows, prog.nvars, t0.elapsed().as_millis());
        let _ = rows;
        // the lies
        let mut bb: crate::ssa_door::SsaBundle = postcard::from_bytes(&child).expect("decodes");
        let k = bb.gkr.layers.len() - 2;
        bb.gkr.layers[k].rounds[1][2] += Ea4::ONE;
        let (lb, ld) = parent(Some(&postcard::to_allocvec(&bb).expect("encodes")), &io);
        assert!(ld.is_err() || lb.mismatch.is_some(), "⛔ LIE: a moved GKR round passed in circuit");
        let mut bb: crate::ssa_door::SsaBundle = postcard::from_bytes(&child).expect("decodes");
        bb.zc.opened[5] += Ea4::ONE;
        let (lb, ld) = parent(Some(&postcard::to_allocvec(&bb).expect("encodes")), &io);
        assert!(ld.is_err() || lb.mismatch.is_some(), "⛔ LIE: a moved opened value passed in circuit");
        let mut io2 = io;
        io2[3] += Fa4::ONE;
        let (lb, ld) = parent(Some(&child), &io2);
        assert!(ld.is_err() || lb.mismatch.is_some(), "⛔ LIE: the child proof passed for another statement");
    }
}

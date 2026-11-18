// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! `WhirVerifier::verify` ON THE SSA ROW (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13): lane aggc's pinned program
//! (`verify_whir::emit_whir_verify`, 101c3461) ported onto addresses. Same transcript, same checks, in the native
//! verifier's order (whir/src/pcs/verifier/mod.rs): the initial sumcheck (each round `[c0, c_inf]`, its grind witness
//! words and `sample_bits == 0`); per round: the new root, the out-of-domain points and answers, the round's grind, the
//! checkpoint sample, every STIR query (`draw_below`, the hiding leaf sponge over `values ‖ salt`, the Merkle walk to the
//! PREVIOUS root carrying `g^index`, the fold `Poly::eval_ext` at the previous sumcheck's coordinates), α and
//! `combine_evals`, the round's sumcheck; the final polynomial (absorbed), its grind, the final queries checked against it
//! (`SelectStatement::verify`: `Σ c_i z^i == fold`), the final sumcheck; the closing `claim == W(point)·f(point)`.
//!
//! On the SSA row a value stays addressed, so each round's α-combine is made in place (the register machine had to defer
//! it to the closing check); the statement is the same.
//!
//! AI RESISTANT: (a) — every check is an assertion; the pin `w1` runs the program on a real carrier opening.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_whir::pcs::proof::QueryOpening;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::door_ssa::{eq_ext, horner, WhirSsa};
use crate::ssa::{Addr, Builder, Chal, Ext, ONE, RATE, WIDTH, ZERO};
use crate::verify_whir::{CarrierWhirConfig, CarrierWhirProof};

/// The salt words of a hiding leaf (`Mmcs16`'s `SALT_ELEMS`).
pub const SALT: usize = 8;

/// The WHIR program on the SSA builder.
#[derive(Clone, Copy, Debug, Default)]
pub struct WhirOnSsa;

fn limbs(e: &Ea4) -> [Fa4; 4] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

/// One sumcheck round (`SumcheckData::verify_rounds_each`): absorb `[c0, c_inf]`, the grind, draw `r`, and
/// `claim ← c0 + r·(claim − 2·c0 − c_inf) + c_inf·r²`.
fn sumcheck_round(b: &mut Builder, ch: &mut Chal, c0: Ea4, cinf: Ea4, grind: Option<(u8, [Fa4; 2])>, claim: Ext) -> (Ext, Ext) {
    let a0 = b.load_ext(c0);
    let ai = b.load_ext(cinf);
    ch.observe_ext(b, a0);
    ch.observe_ext(b, ai);
    if let Some((bits, w)) = grind {
        let wa = b.load(&w);
        ch.observe(b, wa[0]);
        ch.observe(b, wa[1]);
        let s = ch.sample(b);
        b.bits(s, bits, 0);
    }
    let r = ch.sample_ext(b);
    let m2 = b.mul_k_add(a0, -(Ea4::ONE + Ea4::ONE), claim);
    let u = b.sub(m2, ai);
    let r2 = b.mul(r, r);
    let a = b.mul_add(r, u, a0);
    (b.mul_add(ai, r2, a), r)
}

fn sumcheck_fold(b: &mut Builder, ch: &mut Chal, data: Option<&p3_sumcheck::SumcheckData<Fa4, Ea4>>, bits: &[usize], claim: &mut Ext, coords: &mut Vec<Ext>) -> Result<(), String> {
    let mut w = data.map(|d| d.pow_witnesses.iter());
    for (i, &bb) in bits.iter().enumerate() {
        let [c0, ci] = data.and_then(|d| d.polynomial_evaluations.get(i).copied()).unwrap_or([Ea4::ZERO; 2]);
        let grind = if bb == 0 {
            None
        } else {
            if bb > crate::ssa::NLOW {
                return Err(format!("a grind of {bb} bits is past a Bits row"));
            }
            let mut next = || w.as_mut().and_then(|it| it.next().copied()).unwrap_or(Fa4::ZERO);
            Some((bb as u8, [next(), next()]))
        };
        let (c, r) = sumcheck_round(b, ch, c0, ci, grind, *claim);
        *claim = c;
        coords.push(r);
    }
    Ok(())
}

/// The leaf sponge (`PaddingFreeSponge<Perm16, 16, 8, 8>`): eight lanes overwritten a permutation, a short last chunk
/// overwriting only its own lanes. Returns the digest.
fn leaf_digest(b: &mut Builder, words: &[Addr]) -> [Addr; RATE] {
    let mut st = [ZERO; WIDTH];
    for chunk in words.chunks(RATE) {
        let mut inp = st;
        inp[..chunk.len()].copy_from_slice(chunk);
        st = b.perm(inp);
    }
    st[..RATE].try_into().expect("eight lanes")
}

/// One STIR query: the index, the leaf, the walk to `root` carrying `g^index`, the fold at `fold_pt`. Returns
/// `(fold, g^index)`.
#[allow(clippy::too_many_arguments)]
fn query(b: &mut Builder, ch: &mut Chal, k: usize, kg: Fa4, ext_leaf: bool, values: &[Fa4], salt: &[Fa4], sibs: &[[Fa4; RATE]], root: [Addr; RATE], fold_pt: &[Ext]) -> Result<(Ext, Ext), String> {
    if k > crate::ssa::NLOW || sibs.len() != k {
        return Err(format!("a query of {k} levels and {} siblings", sibs.len()));
    }
    let idx = ch.draw_index_sum(b, k as u8);
    let mut words = b.load(values);
    let salt_a = b.load(salt);
    words.extend_from_slice(&salt_a);
    let mut cur = leaf_digest(b, &words);
    let (mut ix, mut var, mut g) = (idx, ONE, kg);
    for (lvl, s) in sibs.iter().enumerate() {
        let sa = b.load(s);
        let sib: [Addr; RATE] = sa[..].try_into().expect("eight");
        let last = (lvl + 1 == k).then_some(root);
        let (n, i2, v2) = b.comp(cur, sib, ix, var, g, last);
        cur = n;
        ix = i2;
        var = v2;
        g = g * g;
    }
    // the sum of four k-bit draws is below 2^(k+2): two carry levels, the last read from ZERO, force every walked bit
    let c1 = b.halve(ix, false);
    let _ = b.halve(c1, true);
    // the fold: Poly::eval_ext of the leaf at fold_pt (big-endian; coordinate 0 binds the top half)
    let per = if ext_leaf { 4 } else { 1 };
    let f = fold_pt.len();
    if values.len() != per << f {
        return Err(format!("a leaf of {} words for 2^{f} values", values.len()));
    }
    let mut vals: Vec<Ext> = (0..1usize << f)
        .map(|i| if ext_leaf { Ext([words[4 * i], words[4 * i + 1], words[4 * i + 2], words[4 * i + 3]]) } else { Ext([words[i], ZERO, ZERO, ZERO]) })
        .collect();
    for c in fold_pt {
        let h = vals.len() / 2;
        let mut nv = Vec::with_capacity(h);
        for i in 0..h {
            let d = b.sub(vals[i + h], vals[i]);
            nv.push(b.mul_add(*c, d, vals[i]));
        }
        vals = nv;
    }
    Ok((vals[0], Ext([var, ZERO, ZERO, ZERO])))
}

fn opening(q: Option<&QueryOpening<Fa4, Ea4, (Vec<Vec<Fa4>>, Vec<[Fa4; 8]>)>>, f: usize, ext: bool, k: usize) -> (Vec<Fa4>, Vec<Fa4>, Vec<[Fa4; RATE]>) {
    match q {
        Some(QueryOpening::Base { values, proof }) => (values.clone(), proof.0.first().cloned().unwrap_or_default(), proof.1.clone()),
        Some(QueryOpening::Extension { values, proof }) => (values.iter().flat_map(limbs).collect(), proof.0.first().cloned().unwrap_or_default(), proof.1.clone()),
        None => (vec![Fa4::ZERO; (if ext { 4 } else { 1 }) << f], vec![Fa4::ZERO; SALT], vec![[Fa4::ZERO; RATE]; k]),
    }
}

/// `Point::select_poly(var)` at `local`: `Π (r·(var^(2^i) − 1) + 1)`, the local coordinates LAST first.
fn select_weight(b: &mut Builder, local: &[Ext], var: Ext) -> Ext {
    let mut v = var;
    let mut out = Ext::ONE;
    let m1 = b.konst_ext(-Ea4::ONE);
    for (step, r) in local.iter().rev().enumerate() {
        let vm1 = b.add(v, m1);
        let t = b.mul_add(*r, vm1, Ext::ONE);
        out = b.mul(out, t);
        if step + 1 < local.len() {
            v = b.mul(v, v);
        }
    }
    out
}

/// `expand_from_univariate(y, n).eq_poly(local)`: `[y^(2^(n−1)), …, y², y]`.
fn ood_weight(b: &mut Builder, local: &[Ext], y: Ext) -> Ext {
    let mut pw = vec![y];
    for _ in 1..local.len() {
        let l = *pw.last().expect("a power");
        pw.push(b.mul(l, l));
    }
    pw.reverse();
    eq_ext(b, &pw, local)
}

impl WhirSsa for WhirOnSsa {
    fn emit(&mut self, b: &mut Builder, ch: &mut Chal, cfg: &CarrierWhirConfig, proof: Option<&CarrierWhirProof>, root: [Addr; RATE], claim: Ext, init_weight: &mut dyn FnMut(&mut Builder, &[Ext]) -> Ext) -> Result<(), String> {
        let n_rounds = cfg.n_rounds();
        if proof.is_some_and(|p| p.rounds.len() != n_rounds) {
            return Err("the proof's rounds are not the configuration's".into());
        }
        let mut claim = claim;
        let mut coords: Vec<Ext> = Vec::new();
        let base = b.phase.clone();
        b.phase = format!("{base} / initial sumcheck");
        sumcheck_fold(b, ch, proof.map(|p| &p.initial_sumcheck), &cfg.starting_fold_grinds(), &mut claim, &mut coords)?;
        let mut fold_start = 0usize;
        let mut prev_root = root;
        // (num_variables, out-of-domain points, query points, α) a round, for the closing weights
        let mut meta: Vec<(usize, Vec<Ext>, Vec<Ext>, Ext)> = Vec::new();
        for r in 0..n_rounds {
            b.phase = format!("{base} / round {r}");
            let rp = &cfg.round_parameters[r];
            let rproof = proof.map(|p| &p.rounds[r]);
            let rootw: [Fa4; RATE] = rproof.and_then(|p| p.commitment.as_ref()).map_or([Fa4::ZERO; RATE], |c| c.as_ref()[0]);
            let ra = b.load(&rootw);
            let new_root: [Addr; RATE] = ra[..].try_into().expect("eight");
            ch.observe_all(b, &new_root);
            let mut ys = Vec::new();
            let mut answers = Vec::new();
            for i in 0..rp.ood_samples {
                ys.push(ch.sample_ext(b));
                let a = b.load_ext(rproof.and_then(|p| p.ood_answers.get(i).copied()).unwrap_or(Ea4::ZERO));
                ch.observe_ext(b, a);
                answers.push(a);
            }
            if rp.pow_bits > 0 {
                let w = b.load(&[rproof.map_or(Fa4::ZERO, |p| p.pow_witness)])[0];
                ch.check_witness(b, w, u8::try_from(rp.pow_bits).map_err(|_| "a round grind past 255 bits")?);
            }
            ch.sample_unused(b);
            let k = (rp.domain_size >> rp.folding_factor).trailing_zeros() as usize;
            let f = rp.folding_factor;
            let fold_pt: Vec<Ext> = coords[fold_start..fold_start + f].to_vec();
            let mut folds = Vec::new();
            let mut points = Vec::new();
            for qi in 0..rp.num_queries {
                b.phase = format!("{base} / round {r} query {qi}");
                let (values, salt, sibs) = opening(rproof.and_then(|p| p.queries.get(qi)), f, r > 0, k);
                let (fv, z) = query(b, ch, k, rp.folded_domain_gen, r > 0, &values, &salt, &sibs, prev_root, &fold_pt)?;
                folds.push(fv);
                points.push(z);
            }
            let alpha = ch.sample_ext(b);
            let mut evals = answers.clone();
            evals.extend_from_slice(&folds);
            let comb = horner(b, &evals, alpha);
            claim = b.add(claim, comb);
            meta.push((rp.num_variables, ys, points, alpha));
            fold_start = coords.len();
            sumcheck_fold(b, ch, rproof.map(|p| &p.sumcheck), &cfg.round_fold_grinds(r), &mut claim, &mut coords)?;
            prev_root = new_root;
        }
        // the final polynomial, its grind, its queries
        b.phase = format!("{base} / final polynomial");
        let fin = cfg.final_round_config();
        let n_final = 1usize << fin.num_variables;
        let coeffs_v: Vec<Ea4> = proof.and_then(|p| p.final_poly.as_ref()).map_or_else(|| vec![Ea4::ZERO; n_final], |p| p.as_slice().to_vec());
        if coeffs_v.len() != n_final {
            return Err("the final polynomial's length is not the configuration's".into());
        }
        let coeffs: Vec<Ext> = coeffs_v.iter().map(|c| b.load_ext(*c)).collect();
        for c in &coeffs {
            ch.observe_ext(b, *c);
        }
        if fin.pow_bits > 0 {
            let w = b.load(&[proof.map_or(Fa4::ZERO, |p| p.final_pow_witness)])[0];
            ch.check_witness(b, w, u8::try_from(fin.pow_bits).map_err(|_| "a final grind past 255 bits")?);
        }
        let (k, f) = ((fin.domain_size >> fin.folding_factor).trailing_zeros() as usize, fin.folding_factor);
        let fold_pt: Vec<Ext> = coords[fold_start..fold_start + f].to_vec();
        for qi in 0..cfg.final_queries {
            b.phase = format!("{base} / final query {qi}");
            let (values, salt, sibs) = opening(proof.and_then(|p| p.final_queries.get(qi)), f, n_rounds > 0, k);
            let (fv, z) = query(b, ch, k, fin.folded_domain_gen, n_rounds > 0, &values, &salt, &sibs, prev_root, &fold_pt)?;
            // SelectStatement::verify: Σ c_i z^i == fold (Horner from the top)
            let mut acc = *coeffs.last().expect("a coefficient");
            for c in coeffs.iter().rev().skip(1) {
                acc = b.mul_add(acc, z, *c);
            }
            b.assert_eq(acc, fv);
        }
        b.phase = format!("{base} / final sumcheck and closing");
        let final_start = coords.len();
        let fbits = vec![cfg.final_folding_pow_bits; cfg.final_sumcheck_rounds];
        sumcheck_fold(b, ch, proof.and_then(|p| p.final_sumcheck.as_ref()), &fbits, &mut claim, &mut coords)?;
        if coords.len() != cfg.num_variables {
            return Err(format!("{} folding coordinates for {} variables", coords.len(), cfg.num_variables));
        }
        // the closing check: claim == (W_init + Σ rounds' weights)·final_value
        let fpt: Vec<Ext> = coords[final_start..].to_vec();
        let mut vals = coeffs.clone();
        for c in &fpt {
            let h = vals.len() / 2;
            let mut nv = Vec::with_capacity(h);
            for i in 0..h {
                let d = b.sub(vals[i + h], vals[i]);
                nv.push(b.mul_add(*c, d, vals[i]));
            }
            vals = nv;
        }
        if vals.len() != 1 {
            return Err("the final sumcheck's point is not the final polynomial's arity".into());
        }
        let fval = vals[0];
        let mut wsum = init_weight(b, &coords);
        for (nv, ys, zs, alpha) in &meta {
            let local: Vec<Ext> = coords[coords.len() - nv..].to_vec();
            let mut ws = Vec::new();
            for y in ys {
                ws.push(ood_weight(b, &local, *y));
            }
            for z in zs {
                ws.push(select_weight(b, &local, *z));
            }
            let s = horner(b, &ws, *alpha);
            wsum = b.add(wsum, s);
        }
        let rhs = b.mul(wsum, fval);
        b.assert_eq(claim, rhs);
        Ok(())
    }
}

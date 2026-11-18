// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! AN INNER GATE ON THE SSA ROW (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13): `C_γ(inputs) = Σ γ^i · r_i`.
//!
//! A carrier's or a child's gate, traced to a program (`usdm_decider::gate_trace::trace`, permutation blocks INLINE: the
//! SSA row has no chip), is emitted one multiply-add per operation. Values are addresses, so a shared subexpression is
//! read again for nothing and nothing is spilled; the fold is a reverse Horner over the residuals. A product whose only
//! reader is a sum fuses into that sum's multiply-add.
//!
//! The gate's PUBLIC values are the caller's (constants of the program, or statement addresses); its opened values
//! are the inner transcript's own addresses — the very lanes the inner transcript absorbed — so there is nothing to
//! re-bind: a read IS the absorbed value (the bus).
//!
//! AI RESISTANT: (a) — the program is the gate; `agg_t1` pins the trace against every carrier gate, `g2` this emission.

use p3_field::PrimeCharacteristicRing;
use usdm_decider::gate_trace::{GOp, GateProgram};
use usdm_decider::hiding_decider::Ea4;

use crate::ssa::{Builder, Ext};

/// Emit `g` over `inputs` (one address-quad per program input) and fold its residuals at `gamma`. Returns the fold.
/// `Err` for a program traced with OPAQUE permutation blocks (this row evaluates them inline).
pub fn emit_gate(b: &mut Builder, g: &GateProgram, inputs: &[Ext], gamma: Ext) -> Result<Ext, String> {
    if inputs.len() != g.n_inputs {
        return Err(format!("{} inputs for a program of {}", inputs.len(), g.n_inputs));
    }
    // readers of each op, so a product read once by a sum fuses into it
    let n = g.ops.len();
    let mut readers = vec![0u32; n];
    let mut live = vec![false; n];
    for &o in &g.outputs {
        live[o as usize] = true;
        readers[o as usize] += 1;
    }
    for i in (0..n).rev() {
        if !live[i] {
            continue;
        }
        let mut mark = |k: u32| {
            live[k as usize] = true;
            readers[k as usize] += 1;
        };
        match g.ops[i] {
            GOp::Add(x, y) | GOp::Sub(x, y) | GOp::Mul(x, y) => {
                mark(x);
                mark(y);
            }
            GOp::Neg(x) => mark(x),
            GOp::PermOut { .. } => return Err("a permutation block traced opaque: trace it inline for the SSA row".into()),
            _ => {}
        }
    }
    let mut val: Vec<Option<Ext>> = vec![None; n];
    // a product deferred for fusion: (a, b)
    let mut pending: Vec<Option<(Ext, Ext)>> = vec![None; n];
    for i in 0..n {
        if !live[i] {
            continue;
        }
        let v = match g.ops[i] {
            GOp::Input(k) => *inputs.get(k as usize).ok_or("an input past the program's")?,
            GOp::Konst(c) => b.konst_ext(c),
            GOp::Mul(x, y) => {
                let (vx, vy) = (realize(b, &mut val, &mut pending, x)?, realize(b, &mut val, &mut pending, y)?);
                let fusable = readers[i] == 1 && !g.outputs.contains(&(i as u32));
                if fusable {
                    pending[i] = Some((vx, vy));
                    continue;
                }
                b.mul(vx, vy)
            }
            GOp::Add(x, y) => {
                if let Some((p, q)) = pending[x as usize].take() {
                    let vy = realize(b, &mut val, &mut pending, y)?;
                    b.mul_add(p, q, vy)
                } else if let Some((p, q)) = pending[y as usize].take() {
                    let vx = realize(b, &mut val, &mut pending, x)?;
                    b.mul_add(p, q, vx)
                } else {
                    let (vx, vy) = (realize(b, &mut val, &mut pending, x)?, realize(b, &mut val, &mut pending, y)?);
                    b.add(vx, vy)
                }
            }
            GOp::Sub(x, y) => {
                let (vx, vy) = (realize(b, &mut val, &mut pending, x)?, realize(b, &mut val, &mut pending, y)?);
                b.sub(vx, vy)
            }
            GOp::Neg(x) => {
                let vx = realize(b, &mut val, &mut pending, x)?;
                b.mul_k_add(vx, -Ea4::ONE, Ext::ZERO)
            }
            GOp::PermOut { .. } => unreachable!("refused above"),
        };
        val[i] = Some(v);
    }
    // Σ γ^i r_i: reverse Horner
    let outs: Vec<Ext> = g.outputs.iter().map(|&o| realize(b, &mut val, &mut pending, o)).collect::<Result<_, _>>()?;
    let mut acc = *outs.last().ok_or("a gate with no residual")?;
    for r in outs.iter().rev().skip(1) {
        acc = b.mul_add(acc, gamma, *r);
    }
    Ok(acc)
}

/// The value of op `k`, laying a deferred product now if fusion did not take it.
fn realize(b: &mut Builder, val: &mut [Option<Ext>], pending: &mut [Option<(Ext, Ext)>], k: u32) -> Result<Ext, String> {
    if let Some(v) = val[k as usize] {
        return Ok(v);
    }
    if let Some((p, q)) = pending[k as usize].take() {
        let v = b.mul(p, q);
        val[k as usize] = Some(v);
        return Ok(v);
    }
    Err(format!("op {k} read before it is laid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;
    use usdm_decider::hiding_decider::Fa4;

    fn rnd(seed: &mut u64) -> Ea4 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let s = *seed;
        let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((s >> (9 * i)) % 2_130_706_433));
        Ea4::from_basis_coefficients_slice(&l).expect("limbs")
    }

    /// ⭐ THE GATE-ON-SSA PIN — the member leg's and the cover arm's gates (permutation blocks inline), emitted on the
    /// SSA row over random opened rows, fold to the gate's own `eval` at γ; the program lays, its bus balances and every
    /// row's law holds; a moved input moves the fold.
    #[test]
    fn g2_an_inner_gate_on_the_ssa_row_is_its_native_fold() {
        use usdm_decider::air_zerocheck::{AirConstraint, RowGuard};
        let mut seed = 0x6A_7E5u64;
        let d8 = |seed: &mut u64| -> [Ea4; 8] { core::array::from_fn(|_| rnd(seed)) };
        let mg = usdm_decider::member_path_gate::MemberPathGate { gamma: Ea4::ZERO, leaf_commit: d8(&mut seed), binder: d8(&mut seed), root: d8(&mut seed) };
        let (mw, mn) = usdm_decider::member_path_gate::member_path_shape();
        let (gp, lay) = usdm_decider::gate_trace::member_path_program(mw, mn).expect("traces inline");
        let publics = usdm_decider::gate_trace::member_path_publics(&mg);
        let opened: Vec<Ea4> = (0..lay.width).map(|_| rnd(&mut seed)).collect();
        let next: Vec<Ea4> = (0..lay.shifted.len()).map(|_| rnd(&mut seed)).collect();
        let x: Vec<Ea4> = (0..lay.nvars).map(|_| rnd(&mut seed)).collect();
        let gamma = rnd(&mut seed);
        let want = {
            let gate = usdm_decider::member_path_gate::MemberPathGate { gamma, ..mg.clone() };
            let guard = RowGuard::new();
            let row = guard.row(&opened);
            let sh = lay.shifted.clone();
            let nn = next.clone();
            let at = move |c: usize, _p: &[Ea4]| sh.iter().position(|&s| s == c).map_or(Ea4::ZERO, |k| nn[k]);
            gate.eval(&row, &at, &x)
        };
        let mut b = Builder::new();
        let ins = lay.assemble(&opened, &next, &x, &publics).expect("assembles");
        let addrs: Vec<Ext> = ins.iter().map(|v| b.load_ext(*v)).collect();
        let g = b.load_ext(gamma);
        let fold = emit_gate(&mut b, &gp, &addrs, g).expect("emits");
        assert_eq!(b.ext_val(fold), want, "⛔ the SSA fold is not the member gate's eval");
        let (rows, prog) = crate::ssa::lay(&b).expect("lays");
        let cols = crate::ssa::execute(&b, &rows, &prog).expect("runs");
        let alu = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Alu(_))).count();
        println!("[agg-g2] member gate on the SSA row: {} ops traced, {alu} multiply-adds, {} rows (T = 2^{})", gp.ops.len(), prog.rows, prog.nvars);
        let oob = usdm_decider::air_zerocheck::OobLatch::new();
        let gate = crate::ssa::SsaGate { gamma: Ea4::ZERO };
        for r in 0..1usize << prog.nvars {
            let vals: Vec<Ea4> = cols.iter().map(|c| Ea4::from(c[r])).chain(prog.fixed.iter().map(|c| Ea4::from(c[r]))).collect();
            let row = usdm_decider::air_zerocheck::Row::new(&vals, &oob);
            assert!(gate.residuals(&row, &|_, _| Ea4::ZERO, &[]).iter().all(|v| *v == Ea4::ZERO), "⛔ row {r}: a law fails");
        }
        // a moved input moves the fold
        let mut b2 = Builder::new();
        let mut ins2 = ins.clone();
        ins2[5] += Ea4::ONE;
        let addrs2: Vec<Ext> = ins2.iter().map(|v| b2.load_ext(*v)).collect();
        let g2 = b2.load_ext(gamma);
        let fold2 = emit_gate(&mut b2, &gp, &addrs2, g2).expect("emits");
        assert_ne!(b2.ext_val(fold2), want, "⛔ a moved input left the fold unchanged");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE VERIFIER ROW'S CONSTRAINT, its proof and its program check (spec §12, step 2–3).
//!
//! [`VmGate::residuals`] states, for every row, exactly what [`crate::isa::execute`] does: the permutation is a real
//! `COMMITTED_AIR_SEED` permutation of the input its kind routes, every register moves the way its kind (or a unit's
//! write) says and otherwise holds, a `Bits` row's next bits are the canonical decomposition of the lane it names,
//! asserted values are zero, a pop matches the stack top, `CLR` zeroes the stack and statement sponge, `STMT` pins the
//! statement digest, and `TIE` repeats the stream. It reads no row selector (no `x`): a program's first row clears
//! what it must and its last real row states the digest, so the wrap from the last row to row 0 is an ordinary hold
//! (NOP rows pad) and the constraint's degree does not grow with the trace.
//!
//! WHO CHECKS THE PROGRAM. The flags are committed cells; [`program_claim_holds`] compares the proof's opened flag
//! cells at the zerocheck point `r` with the program's multilinear extension at `r`. Two different programs differ
//! there except with probability `nvars / |Ea4|`. A merge that verifies this proof in circuit cannot afford the MLE, so
//! it defers `(program, r, the opened flags folded at a challenge it draws after absorbing them)` upward (spec §12.3).
//!
//! §9.6 (a new proof family; its door is `verify_vm`): (1) PoW — none, it is not a block; (2) the proof is verified by
//! the unchanged chained committed door, plus the program claim; (3) value — none: it states a digest; (4) replay — a
//! statement is a digest of what it proves, so a replayed proof proves the same thing; (5) work — one chained-door
//! verify (`O(nvars)` + WHIR) and one MLE of the flags (`O(T · flags)`), both bounded by the shape the caller states;
//! (6) parity — the same door every chained carrier uses; (7) scale — a constant shape; (8) protected by (a), a proof
//! every node checks.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use usdm_decider::air_zerocheck::{AirConstraint, Row};
use usdm_decider::gate_trace::GateAlg;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::isa::*;

/// The extension's `X⁴ = W`.
fn w_const() -> Fa4 {
    <Fa4 as p3_field::extension::BinomiallyExtendable<4>>::W
}

/// `(Σ a_i X^i)(Σ b_j X^j) mod X⁴ − W`, limb by limb, over any ring the row lives in.
#[allow(non_camel_case_types)]
fn emul<Ea4: GateAlg>(a: [Ea4; 4], b: [Ea4; 4]) -> [Ea4; 4] {
    let w = w_const();
    let mut c = [Ea4::ZERO; 4];
    for i in 0..4 {
        for j in 0..4 {
            let p = a[i] * b[j];
            if i + j < 4 {
                c[i + j] += p;
            } else {
                c[i + j - 4] += p * w;
            }
        }
    }
    c
}

/// The verifier row's constraint. `io` is the proof's statement digest (its public value); `gamma` folds the residuals.
#[derive(Clone)]
pub struct VmGate<Ea4 = usdm_decider::hiding_decider::Ea4> {
    pub gamma: Ea4,
    pub io: [Ea4; RATE],
}

impl<Ea4: GateAlg> VmGate<Ea4> {
    /// Every residual of one row, in a fixed order. `at(c, _)` is column `c`'s NEXT-row value (the chained door's
    /// shifted columns are `SHIFT_LO..SHIFT_HI`).
    #[allow(clippy::too_many_lines)]
    pub fn residuals(&self, l: &Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let one = Ea4::ONE;
        let zero = Ea4::ZERO;
        let nx = |c: usize| at(c, x);
        let f = |c: usize| l[c];
        let kind = |k: Kind| f(F_KIND + KINDS.iter().position(|&q| q == k).expect("a kind"));
        let k_draw = kind(Kind::Draw);
        let (k_dup, k_res, k_comp, k_l0, k_ln, k_push, k_pop, k_bits, k_io, k_fsr, k_fsd) = (
            kind(Kind::Duplex),
            kind(Kind::Reset),
            kind(Kind::Comp),
            kind(Kind::Leaf0),
            kind(Kind::LeafN),
            kind(Kind::Push),
            kind(Kind::Pop),
            kind(Kind::Bits),
            kind(Kind::Io),
            kind(Kind::FsReset),
            kind(Kind::FsDup),
        );
        let k_perm = k_dup + k_res + k_comp + k_l0 + k_ln + k_push + k_pop + k_io + k_fsr + k_fsd;
        let am = |i: usize| f(F_AM + i);
        let d = |i: usize| f(D + i);
        let s = |i: usize| f(S + i);
        let h = |i: usize| f(H + i);
        let bk = |i: usize| f(BK + i);
        let io = |i: usize| f(IO + i);
        let fs = |i: usize| f(FS + i);
        let pin = |i: usize| f(PERM + i);
        let pout = |i: usize| f(PERM + PERM_OUT + i);
        let v4 = |base: usize| -> [Ea4; 4] { core::array::from_fn(|t| f(base + t)) };
        let n4 = |base: usize| -> [Ea4; 4] { core::array::from_fn(|t| nx(base + t)) };
        let xr = |k: usize| v4(X + 4 * k);
        let add4 = |a: [Ea4; 4], b: [Ea4; 4]| -> [Ea4; 4] { core::array::from_fn(|t| a[t] + b[t]) };
        let sub4 = |a: [Ea4; 4], b: [Ea4; 4]| -> [Ea4; 4] { core::array::from_fn(|t| a[t] - b[t]) };
        let scale4 = |k: Ea4, a: [Ea4; 4]| -> [Ea4; 4] { core::array::from_fn(|t| k * a[t]) };
        let base4 = |c: Ea4| -> [Ea4; 4] { [c, zero, zero, zero] };
        let mut rs: Vec<Ea4> = Vec::new();
        let push4 = |rs: &mut Vec<Ea4>, k: Ea4, v: [Ea4; 4]| {
            for t in 0..4 {
                rs.push(k * v[t]);
            }
        };

        // 1. the permutation, on every row that uses it
        let mut pr: Vec<Ea4> = Vec::new();
        usdm_decider::pow_pq_air::push_perm_residuals_seeded(SEED, l, PERM, &mut pr);
        rs.extend(pr.into_iter().map(|r| k_perm * r));

        // 2. its input, as the row's kind routes it
        let b0 = f(B);
        let px = |t: usize| (0..NX).fold(zero, |acc, k| acc + f(F_PX + k) * f(X + 4 * k + t));
        for i in 0..WIDTH {
            let lo = i < RATE;
            let ow = |base: Ea4| if lo { am(i) * d(i) + (one - am(i)) * base } else { base };
            let fresh = if lo { am(i) * d(i) } else { zero };
            let comp = if lo { (one - b0) * h(i) + b0 * d(i) } else { (one - b0) * d(i - RATE) + b0 * h(i - RATE) };
            let bank2 = f(F_BANK2);
            let push = if lo {
                bk(i) + bank2 * (f(BK2 + i) - bk(i))
            } else if i < RATE + 4 {
                px(i - RATE)
            } else if i == RATE + 4 {
                Ea4::from(Fa4::from_u64(STACK_TAG))
            } else {
                zero
            };
            let pop = if i < 12 { d(i) } else if i == 12 { Ea4::from(Fa4::from_u64(STACK_TAG)) } else { zero };
            let routed = k_dup * ow(s(i))
                + (k_res + k_l0 + k_fsr) * fresh
                + k_comp * comp
                + k_ln * ow(h(i))
                + k_push * push
                + k_pop * pop
                + k_io * ow(io(i))
                + k_fsd * ow(fs(i));
            rs.push(k_perm * pin(i) - routed);
        }

        // 3. the registers' next values
        let k_sp = k_dup + k_res;
        for i in 0..WIDTH {
            rs.push(nx(S + i) - s(i) - k_sp * (pout(i) - s(i)));
        }
        for i in 0..RATE {
            rs.push(nx(OS + i) - f(OS + i) - k_sp * (s(i) - f(OS + i)));
        }
        let k_h = k_comp + k_l0 + k_ln;
        for i in 0..WIDTH {
            rs.push(nx(H + i) - h(i) - k_h * (pout(i) - h(i)));
        }
        for i in 0..NB {
            let shifted = if i + 1 < NB { f(B + i + 1) } else { zero };
            let moved = k_comp * shifted + (one - k_comp) * f(B + i);
            rs.push((one - k_bits - k_draw) * (nx(B + i) - moved));
        }
        let g = f(G);
        let var = f(VAR);
        rs.push(nx(G) - g - k_draw * (f(F_KG) - g) - k_comp * (g * g - g));
        rs.push(nx(VAR) - var - k_draw * (one - var) - k_comp * (var * (one + b0 * (g - one)) - var));
        // the draw: TSUM accumulates each sample's masked low bits; a Draw row spells TSUM in 26 bits and starts a walk
        let tsum = f(TSUM);
        let mut masked = zero;
        let mut pw = one;
        for l in 0..NZB {
            masked += f(F_AMK + l) * pw * nx(B + l);
            pw = pw + pw;
        }
        rs.push(nx(TSUM) - tsum - k_bits * f(F_ACC) * masked + k_draw * tsum);
        let mut rec26 = zero;
        let mut pw = one;
        for l in 0..NB {
            let bl = nx(B + l);
            if l < 26 {
                rs.push(k_draw * bl * (bl - one));
                rec26 += bl * pw;
                pw = pw + pw;
            } else {
                rs.push(k_draw * bl);
            }
        }
        rs.push(k_draw * (rec26 - tsum));
        // the roots: latched off the row that absorbs one; a walk's end asserted equal to one
        for (q, base) in [R0, R1].into_iter().enumerate() {
            for i in 0..RATE {
                // the window's eight lanes ending `loff` before its end
                let w8 = (0..NOFF).fold(zero, |acc, o| acc + f(F_LOFF + o) * f(WL + NWL - RATE - o + i));
                rs.push(nx(base + i) - f(base + i) - f(F_LATCH + q) * (d(i) - f(base + i)) - f(F_LATW + q) * (w8 - f(base + i)));
                rs.push(f(F_HEQ + q) * (h(i) - f(base + i)));
            }
        }
        let clr = f(F_CLR);
        let bank2 = f(F_BANK2);
        for i in 0..RATE {
            // the first stack moves on a push/pop without bank2, the second on one with it
            let b1 = bk(i);
            let b2 = f(BK2 + i);
            let moved1 = b1 + (one - bank2) * (k_push * (pout(i) - b1) + k_pop * (d(i) - b1));
            let moved2 = b2 + bank2 * (k_push * (pout(i) - b2) + k_pop * (d(i) - b2));
            rs.push(nx(BK + i) - (one - clr) * moved1);
            rs.push(nx(BK2 + i) - (one - clr) * moved2);
            let top = b1 + bank2 * (b2 - b1);
            rs.push(k_pop * (pout(i) - top));
        }
        for i in 0..WIDTH {
            let moved = io(i) + k_io * (pout(i) - io(i));
            rs.push(nx(IO + i) - (one - clr) * moved);
        }
        let k_fs = k_fsr + k_fsd;
        for i in 0..WIDTH {
            rs.push(nx(FS + i) - fs(i) - k_fs * (pout(i) - fs(i)));
        }
        let stmt = f(F_STMT);
        for i in 0..RATE {
            rs.push(stmt * (nx(IO + i) - self.io[i]));
        }
        let tie = f(F_TIE);
        for i in 0..RATE {
            rs.push(tie * (nx(D + i) - d(i)));
        }
        let wsh = f(F_WSH);
        for i in 0..NWL {
            let src = if i + RATE < NWL { f(WL + i + RATE) } else { d(i + RATE - NWL) };
            rs.push(nx(WL + i) - f(WL + i) - wsh * (src - f(WL + i)));
        }

        // 4. a Bits row: the next bits are boolean, recompose the named lane, are canonical, and the asserted ones are zero
        let lane = (0..RATE).fold(zero, |acc, j| acc + f(F_BSEL + j) * s(j));
        let mut rec = zero;
        let mut pw = one;
        for i in 0..NB {
            let bi = nx(B + i);
            rs.push(k_bits * bi * (bi - one));
            rec += bi * pw;
            pw = pw + pw;
        }
        rs.push(k_bits * (rec - lane));
        let (p1, p2, p3) = (f(AUX), f(AUX + 1), f(AUX + 2));
        rs.push(k_bits * (p1 - nx(B + 24) * nx(B + 25) * nx(B + 26)));
        rs.push(k_bits * (p2 - p1 * nx(B + 27) * nx(B + 28)));
        rs.push(k_bits * (p3 - p2 * nx(B + 29) * nx(B + 30)));
        // top seven bits all one ⇒ the low 24 are zero (KoalaBear p = 2^31 − 2^24 + 1): no second spelling of a sample
        let low = (0..24).fold(zero, |acc, i| acc + nx(B + i));
        rs.push(k_bits * p3 * low);
        for z in 0..NZB {
            rs.push(k_bits * f(F_ZB + z) * nx(B + z));
        }

        // 5. the chip: one Poseidon2 round of an INNER proof's opened block, at extension values, as limb vectors
        let coff = |o: usize| f(F_COFF + o);
        let win_val = |start_from_end: usize, idx: usize| -> [Ea4; 4] {
            // Σ_o COFF_o · the value `idx` of a group that begins `start_from_end + o` lanes before the window's end
            let mut acc = [zero; 4];
            for o in 0..NOFF {
                let st = NWL - start_from_end - o + 4 * idx;
                for t in 0..4 {
                    acc[t] += coff(o) * f(WL + st + t);
                }
            }
            acc
        };
        let w16: Vec<[Ea4; 4]> = (0..WIDTH).map(|li| win_val(64, li)).collect();
        let w2: Vec<[Ea4; 4]> = (0..2).map(|li| win_val(8, li)).collect();
        // the logUp unit's pair, at its own anchor
        let lw2: Vec<[Ea4; 4]> = (0..2)
            .map(|li| {
                let mut acc = [zero; 4];
                for o in 0..NOFF {
                    let st = NWL - 8 - o + 4 * li;
                    for t in 0..4 {
                        acc[t] += f(F_LOFF + o) * f(WL + st + t);
                    }
                }
                acc
            })
            .collect();
        let cs = |li: usize| v4(CS + 4 * li);
        let rc = |li: usize| f(F_RC + li);
        let gpow = |k: usize| xr(X_GAMMA_POW + k);
        let cube = |a: [Ea4; 4]| emul(emul(a, a), a);
        // a linear layer over limb vectors: the same base-coefficient map on each limb
        let lin = |v: &[[Ea4; 4]], external: bool| -> Vec<[Ea4; 4]> {
            let mut out = vec![[zero; 4]; WIDTH];
            for t in 0..4 {
                let mut lanes: [Ea4; WIDTH] = core::array::from_fn(|li| v[li][t]);
                if external {
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut lanes);
                } else {
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut lanes);
                }
                for li in 0..WIDTH {
                    out[li][t] = lanes[li];
                }
            }
            out
        };
        let (c_init, c_full, c_part, cclr) = (f(F_CINIT), f(F_CFULL), f(F_CPART), f(F_CCLR));
        let cacc = v4(CACC);
        let cgp = v4(CGP);
        // Init: CS' = M_E(in), CGP' = X[X_GP]
        let me_in = lin(&w16, true);
        // Full: r = M_E((CS + rc)³) − post
        let cubes: Vec<[Ea4; 4]> = (0..WIDTH).map(|li| cube(add4(cs(li), base4(rc(li))))).collect();
        let me_c = lin(&cubes, true);
        let mut dot = [zero; 4];
        for li in 0..WIDTH {
            // the AIR's residual: state − post (assert_eq order, poseidon2-air eval_full_round)
            dot = add4(dot, emul(gpow(li), sub4(me_c[li], w16[li].clone())));
        }
        // Part: two partial rounds through the same-row state CS2
        let t1 = cube(add4(cs(0), base4(rc(0))));
        let r1 = sub4(t1, w2[0]);
        let mut s2: Vec<[Ea4; 4]> = (0..WIDTH).map(cs).collect();
        s2[0] = w2[0];
        let s2m = lin(&s2, false);
        let cs2 = |li: usize| v4(CS2 + 4 * li);
        let t2 = cube(add4(cs2(0), base4(rc(1))));
        let r2 = sub4(t2, w2[1]);
        let mut s3: Vec<[Ea4; 4]> = (0..WIDTH).map(cs2).collect();
        s3[0] = w2[1];
        let s3m = lin(&s3, false);
        let c_any = c_init + c_full + c_part;
        for li in 0..WIDTH {
            let held = cs(li);
            let want: [Ea4; 4] = core::array::from_fn(|t| c_init * me_in[li][t] + c_full * w16[li][t] + c_part * s3m[li][t] + (one - c_any) * held[t]);
            push4(&mut rs, one, sub4(n4(CS + 4 * li), want));
            // CS2 is the mid-row state on a Part row (free elsewhere)
            push4(&mut rs, c_part, sub4(cs2(li), s2m[li]));
        }
        let acc_full = emul(cgp, dot);
        let acc_part = add4(emul(cgp, r1), emul(emul(cgp, gpow(1)), r2));
        let acc_next: [Ea4; 4] = core::array::from_fn(|t| cacc[t] + c_full * acc_full[t] + c_part * acc_part[t]);
        push4(&mut rs, one, sub4(n4(CACC), scale4(one - cclr, acc_next)));
        let gp_full = emul(cgp, xr(X_G16));
        let gp_part = emul(cgp, gpow(2));
        let xgp = xr(X_GP);
        let gp_next: [Ea4; 4] = core::array::from_fn(|t| c_init * xgp[t] + c_full * gp_full[t] + c_part * gp_part[t] + (one - c_any) * cgp[t]);
        push4(&mut rs, one, sub4(n4(CGP), gp_next));

        // 6. logUp: (ρ − addr − β·v)·w = mult, and LACC accumulates w
        let luw = f(F_LUW);
        let rho = xr(X_RHO);
        let beta = xr(X_BETA);
        let mut lacc_add = [zero; 4];
        for q in 0..2 {
            let on = f(F_LU + q);
            let vd = v4(D + 4 * q);
            let v: [Ea4; 4] = core::array::from_fn(|t| luw * lw2[q][t] + (one - luw) * vd[t]);
            let w = v4(D + 8 + 4 * q);
            let den = sub4(sub4(rho, base4(f(F_LA + q))), emul(beta, v));
            push4(&mut rs, on, sub4(emul(den, w), base4(f(F_LM + q))));
            lacc_add = add4(lacc_add, scale4(on, w));
        }
        let lclr = f(F_LCLR);
        push4(&mut rs, one, sub4(n4(LACC), scale4(one - lclr, add4(v4(LACC), lacc_add))));

        // 7. the units: R = A·B + C, written and/or asserted
        let one4 = [one, zero, zero, zero];
        let mut writes: Vec<[Ea4; 4]> = vec![[zero; 4]; NX];
        let mut wsel: Vec<Ea4> = vec![zero; NX];
        for u in 0..NU {
            let base = F_UNIT + u * UNIT_W;
            let sa = |k: usize| f(base + U_SA + k);
            let sb = |k: usize| f(base + U_SB + k);
            let sc = |k: usize| f(base + U_SC + k);
            let kc = v4(base + U_KC);
            let mut a = [zero; 4];
            let mut bv = [zero; 4];
            let mut c = [zero; 4];
            for t in 0..4 {
                for k in 0..NX {
                    let xk = f(X + 4 * k + t);
                    a[t] += sa(k) * xk;
                    bv[t] += sb(k) * xk;
                    c[t] += sc(k) * xk;
                }
                a[t] += sa(NX) * one4[t];
                for q in 0..4 {
                    bv[t] += sb(NX + q) * d(4 * q + t);
                    c[t] += sc(NX + q) * d(4 * q + t);
                }
                bv[t] += sb(NX + 4) * kc[t] + sb(NX + 5) * one4[t];
                c[t] += sc(NX + 4) * kc[t] + sc(NX + 5) * one4[t];
                for j in 0..5 {
                    bv[t] += sb(NX + 6 + j) * s(7 - j - t);
                    bv[t] += sb(NX + 15 + j) * fs(7 - j - t);
                }
                for m in 1..=3usize {
                    let v = if t < m { f(OS + m - 1 - t) } else { s(7 - (t - m)) };
                    bv[t] += sb(NX + 11 + m - 1) * v;
                }
                bv[t] += sb(NX + 14) * if t == 0 { var } else { zero };
                bv[t] += sb(NX + 20) * cacc[t] + sb(NX + 21) * f(LACC + t);
                c[t] += sc(NX + 6) * cacc[t] + sc(NX + 7) * f(LACC + t);
                if t == 0 {
                    for l in 0..RATE {
                        bv[0] += sb(NX + 22 + l) * d(l);
                        c[0] += sc(NX + 8 + l) * d(l);
                    }
                }
            }
            let p = emul(a, bv);
            let r: [Ea4; 4] = core::array::from_fn(|t| p[t] + c[t]);
            push4(&mut rs, f(base + U_Z), r);
            for k in 0..NX {
                let wk = f(base + U_WR + k);
                wsel[k] += wk;
                for t in 0..4 {
                    writes[k][t] += wk * r[t];
                }
            }
        }
        for k in 0..NX {
            for t in 0..4 {
                let xk = f(X + 4 * k + t);
                rs.push(nx(X + 4 * k + t) - xk - (writes[k][t] - wsel[k] * xk));
            }
        }
        rs
    }
}

impl AirConstraint for VmGate {
    fn degree(&self, _nvars: usize) -> usize {
        // The permutation's own degree times its kind flag; the chip's γ-power · Γ · cube times its flag is 6; a logUp
        // term flag · β · (flag·window) · w is 5. Measured by the degree census on the prover's debug path.
        (usdm_decider::pow_pq_air::PERM_MAX_DEGREE + 1).max(7)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let (mut acc, mut pw) = (Ea4::ZERO, Ea4::ONE);
        for r in self.residuals(local, at, x) {
            acc += pw * r;
            pw *= self.gamma;
        }
        acc
    }
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        VmGate::residuals(self, local, at, x)
    }
    fn is_row_local(&self) -> bool {
        false
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some((SHIFT_LO..SHIFT_HI).collect())
    }
}

/// The public bind a verifier-row proof is proved under: its domain, then its statement digest.
pub const VM_DOMAIN: u64 = 0x4147_4756_4d31; // "AGGVM1"
#[must_use]
pub fn vm_bind(io: &[Fa4; RATE]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(VM_DOMAIN)];
    b.extend_from_slice(io);
    b
}

fn io_ea(io: &[Fa4; RATE]) -> [Ea4; RATE] {
    core::array::from_fn(|i| Ea4::from(io[i]))
}

/// Prove `prog` on stream `d`: the proof, its statement digest and its shape `(nvars, width)`.
pub fn prove_vm(prog: &[Instr], d: &[[Fa4; ND]], min_rows: usize) -> Result<(Vec<u8>, [Fa4; RATE], (usize, usize)), ExecError> {
    let (cols, io) = execute(prog, d, min_rows)?;
    let t = cols[0].len();
    let ioe = io_ea(&io);
    let bytes = usdm_decider::committed_air::prove_air_chained_bytes(cols, move |g: Ea4| VmGate { gamma: g, io: ioe }, &vm_bind(&io))
        .ok_or(ExecError { row: t, why: "the chained door did not prove the trace" })?;
    Ok((bytes, io, (t.trailing_zeros() as usize, WIDTH_VM)))
}

/// The multilinear extension of the program's flag columns at `r`, point HIGH-bit first (row `i`'s bit `k` is
/// `x[k] = (i >> (nvars-1-k)) & 1`), padded rows NOP. `O(T · flags)`.
#[must_use]
pub fn program_flags_at(prog: &[Instr], nvars: usize, r: &[Ea4]) -> Option<Vec<Ea4>> {
    if r.len() != nvars {
        return None;
    }
    let t = 1usize << nvars;
    if prog.len() >= t {
        return None;
    }
    // eq(i, r) for every row, by the standard doubling.
    let mut eq = vec![Ea4::ONE];
    for &rk in r {
        let mut nxt = Vec::with_capacity(eq.len() * 2);
        for &e in &eq {
            nxt.push(e * (Ea4::ONE - rk));
            nxt.push(e * rk);
        }
        eq = nxt;
    }
    let nf = WIDTH_VM - FLAGS;
    let mut out = vec![Ea4::ZERO; nf];
    for (i, ins) in prog.iter().enumerate() {
        let cells = flag_cells(ins);
        for (c, v) in cells.iter().enumerate() {
            if *v != Fa4::ZERO {
                out[c] += eq[i] * *v;
            }
        }
    }
    Some(out)
}

/// The program claim: the proof's opened flag cells at its zerocheck point are the program's (module doc).
#[must_use]
pub fn program_claim_holds(bytes: &[u8], prog: &[Instr]) -> bool {
    let Some((zc, _next, shape)) = usdm_decider::committed_air::zerocheck_of_chained_carrier(bytes) else { return false };
    if shape.1 != WIDTH_VM || zc.opened.len() != WIDTH_VM {
        return false;
    }
    let Some(want) = program_flags_at(prog, shape.0, &zc.r) else { return false };
    zc.opened[FLAGS..] == want[..]
}

/// Verify a verifier-row proof natively: the chained door under its statement digest, then the program claim.
#[must_use]
pub fn verify_vm(bytes: &[u8], prog: &[Instr], io: &[Fa4; RATE], shape: (usize, usize)) -> bool {
    if shape.1 != WIDTH_VM {
        return false;
    }
    let ioe = io_ea(io);
    usdm_decider::committed_air::verify_air_chained_bytes(bytes, move |g: Ea4| VmGate { gamma: g, io: ioe }, &vm_bind(io), shape)
        && program_claim_holds(bytes, prog)
}

/// Check every row of an executed trace against the constraint in the BASE field (each residual must be zero), the
/// executor's twin: a disagreement names its row and residual. Test and debugging use only.
pub fn trace_satisfies(cols: &[Vec<Fa4>], io: &[Fa4; RATE]) -> Result<(), (usize, usize)> {
    let t = cols[0].len();
    let gate = VmGate::<Fa4> { gamma: Fa4::ZERO, io: *io };
    let guard = usdm_decider::air_zerocheck::OobLatch::new();
    for row in 0..t {
        let cur: Vec<Fa4> = (0..WIDTH_VM).map(|c| cols[c][row]).collect();
        let nxt: Vec<Fa4> = (0..WIDTH_VM).map(|c| cols[c][(row + 1) % t]).collect();
        let lrow = Row::new(&cur, &guard);
        let at = |c: usize, _p: &[Fa4]| nxt[c];
        let rs = gate.residuals(&lrow, &at, &[]);
        if let Some(k) = rs.iter().position(|v| *v != Fa4::ZERO) {
            return Err((row, k));
        }
    }
    Ok(())
}

/// The extension element of four stream lanes (a helper for programs and tests).
#[must_use]
pub fn limbs_of(e: Ea4) -> [Fa4; 4] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

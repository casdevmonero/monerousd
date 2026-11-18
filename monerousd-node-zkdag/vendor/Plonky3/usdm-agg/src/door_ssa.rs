// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! A CARRIER'S DOOR AS AN SSA PROGRAM (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13): `committed_air::verify_committed_body`
//! and `verify_chained_body`, step for step, on the SSA builder — the statement, the commitment, its out-of-domain
//! answers, γ, z, the zerocheck's rounds and closing check against the gate evaluated in circuit (`gate_ssa`), the opened
//! row's claim, the chained door's shift bind, α and the batched claim, then the WHIR opening (`WhirSsa`, the closing
//! weight of the initial constraint supplied here in closed form).
//!
//! Every value the transcript absorbs is an address the gate and the closing checks read again — there is nothing to
//! carry, re-stream or bind twice. The program is a function of the door's statement and shapes alone; the proof only
//! fills values (`bytes = None` lays the same operations over zeros).
//!
//! AI RESISTANT: (a) — each check the native door makes is an assertion here (a read of `ZERO`), so a carrier the door
//! refuses has no satisfying trace.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use usdm_decider::committed_air::{door_whir_config, CarrierParams, ChainedAirBundle, CommittedAirBundle};
use usdm_decider::gate_trace::{GateInputs, GateProgram};
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::gate_ssa::emit_gate;
use crate::ssa::{Addr, Builder, Chal, Ext, RATE};
use crate::verify_whir::{CarrierWhirConfig, CarrierWhirProof};

/// The WHIR opening as an SSA program (lane aggc ports `verify_whir::emit_whir_verify` onto the builder): on entry the
/// transcript is at `WhirVerifier::verify`'s entry (after α), `root` is the commitment, `claim` the batched claim;
/// `init_weight(b, coords)` returns the initial constraint's weight at the folding point (`coords` in sampling order).
pub trait WhirSsa {
    #[allow(clippy::too_many_arguments)]
    fn emit(&mut self, b: &mut Builder, ch: &mut Chal, cfg: &CarrierWhirConfig, proof: Option<&CarrierWhirProof>, root: [Addr; RATE], claim: Ext, init_weight: &mut dyn FnMut(&mut Builder, &[Ext]) -> Ext) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorKind {
    Committed,
    Chained,
}

/// A carrier door's statement and shapes.
#[derive(Clone, Debug)]
pub struct CarrierDoor {
    pub kind: DoorKind,
    pub blinded: bool,
    /// The COMMITTED shape `(nvars, width)` (a blinded door's laid shape plus one variable).
    pub shape: (usize, usize),
    pub params: CarrierParams,
    /// `constraint.degree(nvars) + 2`.
    pub round_len: usize,
    /// The chained door's next-row columns (one ascending run); empty for a committed door.
    pub next_cols: Vec<usize>,
}

/// What the door's proof supplies, or zeros of its shapes.
struct Data {
    root: [Fa4; RATE],
    ood: Vec<Ea4>,
    rounds: Vec<Vec<Ea4>>,
    opened: Vec<Ea4>,
    next: Vec<Ea4>,
    bind_rounds: Vec<Vec<Ea4>>,
    bind_opened: Vec<Ea4>,
    open: Option<CarrierWhirProof>,
}

fn parse(door: &CarrierDoor, n_ood: usize, bytes: Option<&[u8]>) -> Result<Data, String> {
    let (n, w) = door.shape;
    let l = door.next_cols.len();
    let Some(bytes) = bytes else {
        return Ok(Data {
            root: [Fa4::ZERO; RATE],
            ood: vec![Ea4::ZERO; n_ood],
            rounds: vec![vec![Ea4::ZERO; door.round_len]; n],
            opened: vec![Ea4::ZERO; w],
            next: vec![Ea4::ZERO; l],
            bind_rounds: if door.kind == DoorKind::Chained { vec![vec![Ea4::ZERO; 3]; n] } else { Vec::new() },
            bind_opened: vec![Ea4::ZERO; l],
            open: None,
        });
    };
    let root_of = |c: &<usdm_decider::hiding_decider::Mmcs16 as p3_commit::Mmcs<Fa4>>::Commitment| -> Result<[Fa4; RATE], String> {
        let cap: &[[Fa4; RATE]] = c.as_ref();
        (cap.len() == 1).then(|| cap[0]).ok_or_else(|| "a commitment cap of more than one root".to_string())
    };
    let d = match door.kind {
        DoorKind::Committed => {
            let b: CommittedAirBundle = postcard::from_bytes(bytes).map_err(|e| format!("the carrier does not decode: {e}"))?;
            if b.shape != door.shape || !b.zc.shifted_opened.is_empty() || !b.open.hvzk_mask_commits.is_empty() {
                return Err("the carrier is not this door's shape".into());
            }
            Data { root: root_of(&b.commitment)?, ood: b.open.initial_ood_answers.clone(), rounds: b.zc.round_evals, opened: b.zc.opened, next: Vec::new(), bind_rounds: Vec::new(), bind_opened: Vec::new(), open: Some(b.open) }
        }
        DoorKind::Chained => {
            let b: ChainedAirBundle = postcard::from_bytes(bytes).map_err(|e| format!("the carrier does not decode: {e}"))?;
            if b.shape != door.shape || !b.zc.shifted_opened.is_empty() || !b.open.hvzk_mask_commits.is_empty() {
                return Err("the carrier is not this door's shape".into());
            }
            Data { root: root_of(&b.commitment)?, ood: b.open.initial_ood_answers.clone(), rounds: b.zc.round_evals, opened: b.zc.opened, next: b.next, bind_rounds: b.bind_rounds, bind_opened: b.bind_opened, open: Some(b.open) }
        }
    };
    if d.ood.len() != n_ood || d.rounds.len() != n || d.rounds.iter().any(|h| h.len() != door.round_len) || d.opened.len() != w || d.next.len() != l || d.bind_opened.len() != l || d.bind_rounds.iter().any(|h| h.len() != 3) || (door.kind == DoorKind::Chained && d.bind_rounds.len() != n) {
        return Err("the carrier's lengths are not this door's".into());
    }
    Ok(d)
}

/// `g(t)` from its values at `0..=d` (Newton's forward form): `Σ_j Δʲg(0)/j! · t(t−1)…(t−j+1)`.
pub fn lagrange(b: &mut Builder, h: &[Ext], t: Ext) -> Ext {
    let d = h.len() - 1;
    // Δʲ h₀, j = 0..=d
    let mut diffs = vec![h[0]];
    let mut row: Vec<Ext> = h.to_vec();
    for _ in 1..=d {
        row = row.windows(2).map(|w| b.sub(w[1], w[0])).collect();
        diffs.push(row[0]);
    }
    let mut fact = Fa4::ONE;
    let mut a = vec![diffs[0], diffs.get(1).copied().unwrap_or(Ext::ZERO)];
    for (j, dj) in diffs.iter().enumerate().skip(2) {
        fact *= Fa4::from_u64(j as u64);
        let inv = Ea4::from(p3_field::Field::inverse(&fact));
        a.push(b.mul_k_add(*dj, inv, Ext::ZERO));
    }
    a.truncate(d + 1);
    let mut acc = a[d];
    for j in (0..d).rev() {
        let kj = b.konst_ext(-Ea4::from(Fa4::from_u64(j as u64)));
        let tj = b.add(t, kj);
        acc = b.mul_add(acc, tj, a[j]);
    }
    acc
}

/// `eq(a, b) = Π (aᵢ bᵢ + (1 − aᵢ)(1 − bᵢ))`.
pub fn eq_ext(b: &mut Builder, x: &[Ext], y: &[Ext]) -> Ext {
    let mut e = Ext::ONE;
    for (xi, yi) in x.iter().zip(y) {
        // (2x − 1)·y + (1 − x)
        let m1 = b.konst_ext(-Ea4::ONE);
        let two_x_m1 = b.mul_k_add(*xi, Ea4::from(Fa4::TWO), m1);
        let one_m_x = b.sub(Ext::ONE, *xi);
        let f = b.mul_add(two_x_m1, *yi, one_m_x);
        e = b.mul(e, f);
    }
    e
}

/// `Σ_j λʲ v_j` (reverse Horner).
pub fn horner(b: &mut Builder, v: &[Ext], lambda: Ext) -> Ext {
    let Some(mut acc) = v.last().copied() else { return Ext::ZERO };
    for x in v.iter().rev().skip(1) {
        acc = b.mul_add(acc, lambda, *x);
    }
    acc
}

/// `light_commit::shift_mle(x, y)` ("y is the row after x", the last row wrapping), by the forward recurrence
/// `A' = A·s + P·g, P' = P·e, W' = W·s` with `s = x(1−y), g = (1−x)y, e = eq(x, y)`; the value is `A + W`.
pub fn shift_mle(b: &mut Builder, x: &[Ext], y: &[Ext]) -> Ext {
    let (mut a, mut p, mut w) = (Ext::ZERO, Ext::ONE, Ext::ONE);
    for (xi, yi) in x.iter().zip(y) {
        let one_m_y = b.sub(Ext::ONE, *yi);
        let one_m_x = b.sub(Ext::ONE, *xi);
        let s = b.mul(*xi, one_m_y);
        let g = b.mul(one_m_x, *yi);
        let xy = b.mul(*xi, *yi);
        let e = b.mul_add(one_m_x, one_m_y, xy);
        let pg = b.mul(p, g);
        a = b.mul_add(a, s, pg);
        p = b.mul(p, e);
        w = b.mul(w, s);
    }
    b.add(a, w)
}

/// `Σ_{c < w} α^c · eq(bits_s(c), sel)` for each `w` in `targets` (bits big-endian: coordinate 0 is the most significant),
/// by the backward recurrence over the selector coordinates (`R_i = f_i(0)·Q_{i+1} + f_i(1)·R_{i+1}` where `w`'s bit is
/// set, `f_i(0)·R_{i+1}` where not; `Q_i = (f_i(0) + f_i(1))·Q_{i+1}`; `f_i(0) = 1 − sel_i`, `f_i(1) = sel_i·α^(2^(s−1−i))`).
/// `w = 2^s` is `Q_0`. Also returns `α^(2^s)`.
pub fn selector_prefix_sums(b: &mut Builder, sel: &[Ext], alpha: Ext, targets: &[usize]) -> (Vec<Ext>, Ext) {
    let s = sel.len();
    let mut apow = alpha;
    let mut q = Ext::ONE;
    let mut r: Vec<Ext> = vec![Ext::ZERO; targets.len()];
    for i in (0..s).rev() {
        let f0 = b.sub(Ext::ONE, sel[i]);
        let f1 = b.mul(sel[i], apow);
        let bit = s - 1 - i;
        for (k, &w) in targets.iter().enumerate() {
            if w >= 1 << s {
                continue;
            }
            r[k] = if (w >> bit) & 1 == 1 {
                let t = b.mul(f1, r[k]);
                b.mul_add(f0, q, t)
            } else {
                b.mul(f0, r[k])
            };
        }
        let full = b.add(f0, f1);
        q = b.mul(full, q);
        apow = b.mul(apow, apow);
    }
    for (k, &w) in targets.iter().enumerate() {
        if w == 1 << s {
            r[k] = q;
        }
    }
    (r, apow)
}

/// The folding point's coordinates as the committed layout lifts a column's claim (`PrefixProver::strategy()` is
/// `(reverse_selectors = true, Prefix)`, sumcheck/src/layout/prover/prefix.rs:455: `lift_suffix` puts the claim's
/// own point FIRST and the column's REVERSED selector bits after it, so selector coordinate `i` is bit `i` of the column,
/// least significant first): `(selector coordinates most significant first, the local coordinates)`.
#[must_use]
pub fn split_lifted(coords: &[Ext], local: usize) -> (Vec<Ext>, Vec<Ext>) {
    let (low, sel) = coords.split_at(local);
    (sel.iter().rev().copied().collect(), low.to_vec())
}

/// `α^e` from the powers `α^(2^i)` (square and multiply; `e < 2^(pows.len())`).
fn pow_from(b: &mut Builder, alpha: Ext, e: usize) -> Ext {
    let mut acc = Ext::ONE;
    let mut p = alpha;
    let mut k = e;
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

/// What the door hands its caller.
#[derive(Clone, Debug)]
pub struct DoorOut {
    pub r: Vec<Ext>,
    pub gamma: Ext,
}

/// Emit one carrier door. `bind` are the statement's addresses (absorbed first, in order); `gate` the door's gate
/// traced INLINE over `lay` with its public values `publics` (addresses); `whir` the opening's emitter.
#[allow(clippy::too_many_arguments)]
pub fn emit_carrier_door(b: &mut Builder, door: &CarrierDoor, bind: &[Addr], gate: &GateProgram, lay: &GateInputs, publics: &[Ext], bytes: Option<&[u8]>, whir: &mut dyn WhirSsa) -> Result<DoorOut, String> {
    let (n, w) = door.shape;
    let chained = door.kind == DoorKind::Chained;
    let (stacked, cfg) = door_whir_config(door.shape, door.params).ok_or("no door admits this shape")?;
    if lay.width != w || lay.nvars != n || lay.publics != publics.len() || lay.shifted != door.next_cols {
        return Err("the gate's layout is not the door's".into());
    }
    if chained && !door.next_cols.windows(2).all(|p| p[1] == p[0] + 1) {
        return Err("a chained door's next-row columns are not one run".into());
    }
    let data = parse(door, cfg.commitment_ood_samples, bytes)?;
    b.phase = format!("door {:?}: zerocheck", door.kind);
    let mut ch = Chal::new();
    ch.observe_all(b, bind);
    let root_v = b.load(&data.root);
    let root: [Addr; RATE] = root_v[..].try_into().map_err(|_| "eight root words")?;
    ch.observe_all(b, &root);
    let mut oods: Vec<(Ext, Ext)> = Vec::new();
    for e in &data.ood {
        let y = ch.sample_ext(b);
        let a = b.load_ext(*e);
        ch.observe_ext(b, a);
        oods.push((y, a));
    }
    let gamma = ch.sample_ext(b);
    let z: Vec<Ext> = (0..n).map(|_| ch.sample_ext(b)).collect();
    // the zerocheck: Σ must be 0, each round's sum the claim, the claim the round polynomial at r_k
    let mut claim = Ext::ZERO;
    let mut r = Vec::with_capacity(n);
    for h in &data.rounds {
        let hv: Vec<Ext> = h.iter().map(|v| b.load_ext(*v)).collect();
        let s = b.add(hv[0], hv[1]);
        b.assert_eq(s, claim);
        for e in &hv {
            ch.observe_ext(b, *e);
        }
        let rk = ch.sample_ext(b);
        claim = lagrange(b, &hv, rk);
        r.push(rk);
    }
    let opened: Vec<Ext> = data.opened.iter().map(|v| b.load_ext(*v)).collect();
    let next: Vec<Ext> = data.next.iter().map(|v| b.load_ext(*v)).collect();
    // the closing check: eq(z, r)·C_γ(opened, next, r) == claim
    let mut inputs = opened.clone();
    inputs.extend_from_slice(&next);
    inputs.extend_from_slice(&r);
    inputs.extend_from_slice(publics);
    let mut cg = emit_gate(b, gate, &inputs, gamma)?;
    if door.blinded {
        let sel = b.sub(Ext::ONE, r[0]);
        cg = b.mul(sel, cg);
    }
    b.phase = format!("door {:?}: closing gate check", door.kind);
    let e = eq_ext(b, &z, &r);
    let ec = b.mul(e, cg);
    b.assert_eq(ec, claim);
    // the row at r is the commitment's (add_claim_at absorbs the opened values)
    for o in &opened {
        ch.observe_ext(b, *o);
    }
    let mut concretes = opened.clone();
    let mut rho: Vec<Ext> = Vec::new();
    b.phase = format!("door {:?}: shift bind", door.kind);
    if chained {
        for v in &next {
            ch.observe_ext(b, *v);
        }
        let lambda = ch.sample_ext(b);
        let mut cb = horner(b, &next, lambda);
        for h in &data.bind_rounds {
            let hv: Vec<Ext> = h.iter().map(|v| b.load_ext(*v)).collect();
            let s = b.add(hv[0], hv[1]);
            b.assert_eq(s, cb);
            for e in &hv {
                ch.observe_ext(b, *e);
            }
            let c = ch.sample_ext(b);
            cb = lagrange(b, &hv, c);
            rho.push(c);
        }
        let bo: Vec<Ext> = data.bind_opened.iter().map(|v| b.load_ext(*v)).collect();
        for v in &bo {
            ch.observe_ext(b, *v);
        }
        let sh = shift_mle(b, &r, &rho);
        let lf = horner(b, &bo, lambda);
        let want = b.mul(sh, lf);
        b.assert_eq(cb, want);
        concretes.extend_from_slice(&bo);
    }
    let alpha = ch.sample_ext(b);
    // claimed = Σ_j α^j·concrete_j + Σ_i α^(nc+i)·ood_i (combine_evals over LayoutVerifier::constraint's order)
    let mut all: Vec<Ext> = concretes.clone();
    all.extend(oods.iter().map(|p| p.1));
    let claimed = horner(b, &all, alpha);
    // the initial constraint's weight at the folding point, in closed form
    let nc = concretes.len();
    let sbits = stacked - n;
    let (a0, l) = (door.next_cols.first().copied().unwrap_or(0), door.next_cols.len());
    let r_c = r.clone();
    let rho_c = rho.clone();
    let oods_c = oods.clone();
    let _ = sbits;
    let mut init = |b: &mut Builder, coords: &[Ext]| -> Ext {
        let (selc, low) = split_lifted(coords, n);
        let (selc, low) = (&selc[..], &low[..]);
        let targets: Vec<usize> = if chained { vec![w, a0, a0 + l] } else { vec![w] };
        let (p, _) = selector_prefix_sums(b, selc, alpha, &targets);
        let er = eq_ext(b, &r_c, low);
        let mut wsum = b.mul(er, p[0]);
        if chained {
            let erho = eq_ext(b, &rho_c, low);
            let diff = b.sub(p[2], p[1]);
            let shift = pow_from(b, alpha, w - a0);
            let t = b.mul(shift, diff);
            wsum = b.mul_add(erho, t, wsum);
        }
        // the out-of-domain points: expand(y, K) = [y^(2^(K−1)), …, y², y]
        let k = coords.len();
        let mut osum = Ext::ZERO;
        for (y, _) in oods_c.iter().rev() {
            let mut pw = vec![*y];
            for _ in 1..k {
                let last = *pw.last().expect("a power");
                pw.push(b.mul(last, last));
            }
            pw.reverse();
            let ey = eq_ext(b, &pw, coords);
            osum = b.mul_add(osum, alpha, ey);
        }
        let anc = pow_from(b, alpha, nc);
        b.mul_add(anc, osum, wsum)
    };
    b.phase = format!("door {:?}: whir", door.kind);
    whir.emit(b, &mut ch, &cfg, data.open.as_ref(), root, claimed, &mut init)?;
    Ok(DoorOut { r, gamma })
}

/// The extension element of four lanes (a helper for callers).
#[must_use]
pub fn ea(l: [Fa4; 4]) -> Ea4 {
    Ea4::from_basis_coefficients_slice(&l).expect("four limbs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_whir_ssa::WhirOnSsa;
    use usdm_decider::air_zerocheck::AirConstraint;
    use usdm_decider::member_path_gate::{member_path_gate, member_shifted_run, prove_member_path_carrier, MemberTuple, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};

    fn dig(seed: u64) -> [u64; 8] {
        core::array::from_fn(|i| (seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919)) % 2_130_706_433)
    }

    /// The member leg's door, its gate program and publics, from its tuple.
    fn member_door(t: &MemberTuple) -> (CarrierDoor, GateProgram, GateInputs, Vec<Ea4>) {
        let laid = MEMBER_PATH_DEPTH.trailing_zeros() as usize;
        let n = laid + 1;
        let gate = member_path_gate(t)(Ea4::ZERO);
        let round_len = usdm_decider::committed_air::Blinded { inner: gate.clone() }.degree(n) + 2;
        let (lo, run) = member_shifted_run();
        let (gp, lay) = usdm_decider::gate_trace::member_path_program(MEMBER_PATH_COLS, n).expect("traces inline");
        let publics = usdm_decider::gate_trace::member_path_publics(&gate);
        let door = CarrierDoor { kind: DoorKind::Chained, blinded: true, shape: (n, MEMBER_PATH_COLS), params: CarrierParams::LIVE, round_len, next_cols: (lo..lo + run).collect() };
        (door, gp, lay, publics)
    }

    fn build(t: &MemberTuple, bytes: Option<&[u8]>) -> Result<Builder, String> {
        let (door, gp, lay, publics) = member_door(t);
        let mut b = Builder::new();
        let bind = b.public_vals(&t.bind());
        let pubs: Vec<Ext> = publics.iter().map(|v| b.konst_ext(*v)).collect();
        emit_carrier_door(&mut b, &door, &bind, &gp, &lay, &pubs, bytes, &mut WhirOnSsa)?;
        Ok(b)
    }

    /// ⭐⭐ A REAL CARRIER VERIFIED ON THE SSA ROW. A member-leg carrier made by the wallet's own prover (the blinded
    /// chained door) is verified natively AND by the SSA program: every assertion of the program holds on it (the door's
    /// transcript, the zerocheck against the gate evaluated in circuit, the shift bind, the WHIR opening); the program
    /// built from the statement alone lays the same rows; the laid program runs on the SSA row and its SSA proof
    /// verifies. Then the lies, each a failed assertion: a moved opened value, a moved zerocheck round value, a moved
    /// bind round value, a moved WHIR leaf word.
    #[test]
    fn d2_a_real_member_carrier_verifies_on_the_ssa_row() {
        let sibs: Vec<[u64; 8]> = (0..MEMBER_PATH_DEPTH as u64).map(|k| dig(100 + k)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|k| k % 3 == 1).collect();
        let (bytes, t) = prove_member_path_carrier(dig(1), &sibs, &dirs, dig(2), dig(3), dig(4)).expect("the wallet proves its carrier");
        assert!(usdm_decider::member_path_gate::verify_member_path_carrier(&bytes, &t), "CALIBRATION: the native door accepts it");
        let t0 = std::time::Instant::now();
        let b = build(&t, Some(&bytes)).expect("the program builds");
        assert_eq!(b.mismatch, None, "⛔ an assertion of the SSA door fails on an honest carrier");
        let vb = build(&t, None).expect("the statement-only program builds");
        let (rows, prog) = crate::ssa::lay(&b).expect("lays");
        let (_, vprog) = crate::ssa::lay(&vb).expect("lays");
        assert_eq!(prog.fixed, vprog.fixed, "⛔ the program depends on the proof's values");
        let ops = b.ops.len();
        let alu = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Alu(_))).count();
        let perms = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Perm { .. } | crate::ssa::Op::Comp { .. })).count();
        println!("[agg-d2] member carrier on the SSA row: {ops} ops ({alu} multiply-adds, {perms} permutations), {} rows (T = 2^{}), built in {} ms", prog.rows, prog.nvars, t0.elapsed().as_millis());
        let cols = crate::ssa::execute(&b, &rows, &prog).expect("runs");
        let t1 = std::time::Instant::now();
        let proof = crate::ssa_door::prove(&prog, cols).expect("the SSA program proves");
        let pms = t1.elapsed().as_millis();
        assert!(crate::ssa_door::verify(&proof, &vprog), "⛔ the SSA proof of the carrier's verification is refused");
        println!("[agg-d2] SSA proof {} B, prove {pms} ms", proof.len());
        // the lies
        let mut cb: ChainedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        let lie = |cb: &ChainedAirBundle| -> bool {
            let by = postcard::to_allocvec(cb).expect("encodes");
            build(&t, Some(&by)).map_or(true, |b| b.mismatch.is_some())
        };
        cb.zc.opened[17] += Ea4::ONE;
        assert!(lie(&cb), "⛔ LIE: a moved opened value passed");
        let mut cb: ChainedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        cb.zc.round_evals[2][3] += Ea4::ONE;
        assert!(lie(&cb), "⛔ LIE: a moved zerocheck round passed");
        let mut cb: ChainedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        cb.bind_rounds[1][2] += Ea4::ONE;
        assert!(lie(&cb), "⛔ LIE: a moved bind round passed");
        let mut cb: ChainedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        if let Some(p3_whir::pcs::proof::QueryOpening::Base { values, .. }) = cb.open.rounds.get_mut(0).and_then(|r| r.queries.get_mut(0)) {
            values[0] += Fa4::ONE;
            assert!(lie(&cb), "⛔ LIE: a moved WHIR leaf word passed");
        }
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE SSA DOOR (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13): a proof that a laid SSA program ran — the committed
//! door's own commitment, transcript and WHIR opening (`committed_air::door_pcs`, `door_challenger`), with the memory bus
//! proven by GKR on challenges drawn AFTER the commitment, and the gate's zerocheck over the committed columns beside the
//! PREPROCESSED ones, whose values at both points the verifier checks against the program it rebuilt.
//!
//! TRANSCRIPT (prover and verifier, in this order): the statement (every public value) · the commitment · its
//! out-of-domain answers · ρ, β · the GKR proof over the bus's `NSLOT·T` leaves (leaf `slot·T + row`) · the 64 slot
//! columns at the leaf point's row part `x` (WHIR claims) · the preprocessed address and multiplicity columns at `x` ·
//! γ, z, the zerocheck · the committed row at `r` (WHIR claims) · the preprocessed row at `r` · α · the WHIR opening.
//!
//! §9.6 — (1) PoW: the block's, unchanged. (2) the proof: this door — the zerocheck (the gate), GKR (the bus) and WHIR
//! (the openings at `x` and `r`), the preprocessed values checked natively against the verifier's own program. (3) value:
//! none created — a read must see what was written or the bus does not balance. (4) replay: the statement is absorbed
//! first. (5) work: `O(T · NFIXED)` for the program's MLE twice, `O(L²)` GKR rounds, one WHIR opening. (6) parity with the
//! committed door: the same PCS, challenger, out-of-domain step and opening; the next-row class cannot arise (the gate is
//! row-local). (7) scale: a function of the program alone. (8) (a) a proof every node checks; a LYING PROVER — a read of a
//! value never written, a multiplicity off by one, a moved opening — is refused by the bus root, the GKR leaf check or the
//! opening (pins s1).

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_commit::Mmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier as LayoutVerifier};
use p3_whir::pcs::proof::WhirProof;
use p3_whir::pcs::verifier::WhirVerifier;
use serde::{Deserialize, Serialize};
use usdm_decider::air_zerocheck::{prove_air_zerocheck, verify_air_zerocheck, AirConstraint, AirZerocheckProof};
use usdm_decider::committed_air::{door_challenger, door_pcs, door_whir_config, CarrierParams};
use usdm_decider::hiding_decider::{Ea4, Fa4, Mmcs16};

use crate::gkr::{self, GkrProof};
use crate::ssa::{bus_leaves, slot_col, Program, SsaGate, BUS_SLOTS, F_ADDR, F_MULT, NCOMMIT, NFIXED, NSLOT};

/// The slot bits of a bus leaf index.
pub const SLOT_BITS: usize = BUS_SLOTS.trailing_zeros() as usize;

/// An SSA proof.
#[derive(Clone, Serialize, Deserialize)]
pub struct SsaBundle {
    pub nvars: usize,
    pub commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    pub gkr: GkrProof,
    /// The `NSLOT` slot columns at `x` (slot order).
    pub slot_at_x: Vec<Ea4>,
    /// The preprocessed address then multiplicity columns at `x` (`2·NSLOT`).
    pub fixed_at_x: Vec<Ea4>,
    /// The zerocheck; its opened row is the committed columns then the preprocessed ones, at `r`.
    pub zc: AirZerocheckProof,
    pub open: WhirProof<Fa4, Ea4, Mmcs16>,
}

/// The door's parameters: the committed door's LIVE carrier parameters (rate 1/4, Johnson bound, 100 bits).
pub const PARAMS: CarrierParams = CarrierParams::LIVE;

fn slot_cols() -> Vec<usize> {
    (0..NSLOT).map(slot_col).collect()
}

fn bus_fixed(fixed: &[Ea4]) -> Vec<Ea4> {
    fixed[F_ADDR..F_MULT + NSLOT].to_vec()
}

/// The leaf claims the bus's last GKR layer must equal, from the slot columns and the preprocessed columns at `x`.
fn leaf_claims(xs: &[Ea4], slot_at_x: &[Ea4], fixed_at_x: &[Ea4], rho: Ea4, beta: Ea4) -> (Ea4, Ea4) {
    let eq = gkr::eq_table(xs);
    let (mut p, mut q) = (Ea4::ZERO, Ea4::ZERO);
    for s in 0..NSLOT {
        let (addr, mult) = (fixed_at_x[s], fixed_at_x[NSLOT + s]);
        p += eq[s] * mult;
        q += eq[s] * (rho - addr - beta * slot_at_x[s]);
    }
    // the pad slots' constant 0 / 1
    q += eq[NSLOT..BUS_SLOTS].iter().copied().sum::<Ea4>();
    (p, q)
}

/// PROVE a laid program from its committed columns. `None` on any shape no door admits.
#[must_use]
pub fn prove(prog: &Program, committed: Vec<Vec<Fa4>>) -> Option<Vec<u8>> {
    let nvars = prog.nvars;
    let t = 1usize << nvars;
    if committed.len() != NCOMMIT || committed.iter().any(|c| c.len() != t) || prog.fixed.len() != NFIXED {
        return None;
    }
    let (stacked, _) = door_whir_config((nvars, NCOMMIT), PARAMS)?;
    let pcs = door_pcs(stacked, PARAMS);
    let progress = std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok();
    let t0 = std::time::Instant::now();
    let mut chl = door_challenger();
    for &(_, v, _) in &prog.public {
        chl.observe(v);
    }
    let table = Table::new(committed.iter().cloned().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], PARAMS.first_fold);
    let (mut layout, commitment, merkle_data) = PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, PARAMS.first_fold, PARAMS.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let commit_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    // the bus
    let rho: Ea4 = chl.sample_algebra_element();
    let beta: Ea4 = chl.sample_algebra_element();
    let (lp, lq) = bus_leaves(prog, &committed, rho, beta);
    let (gproof, claims) = gkr::prove(lp, lq, &mut chl)?;
    let x: Vec<Ea4> = claims.point[SLOT_BITS..].to_vec();
    let slot_at_x = layout.eval_at(0, &slot_cols(), &Point::new(x.clone()), &mut chl);
    let fixed_at_x = bus_fixed(&prog.fixed_at(&x));
    chl.observe_algebra_slice(&fixed_at_x);
    let gkr_ms = t1.elapsed().as_millis();
    let t2 = std::time::Instant::now();
    // the gate
    let gamma: Ea4 = chl.sample_algebra_element();
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let mut all = committed;
    all.extend(prog.fixed.iter().cloned());
    let mut zc = prove_air_zerocheck(&all, &SsaGate { gamma }, &z, &mut chl);
    zc.shifted_opened = Vec::new();
    let committed_idx: Vec<usize> = (0..NCOMMIT).collect();
    let _ = layout.eval_at(0, &committed_idx, &Point::new(zc.r.clone()), &mut chl);
    chl.observe_algebra_slice(&zc.opened[NCOMMIT..]);
    let zc_ms = t2.elapsed().as_millis();
    let t3 = std::time::Instant::now();
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    if progress {
        // DIGITAL-CASH-PRIVACY-REVIEWED: a shape and durations; no value, witness or key.
        eprintln!("[ssa-phase] 2^{nvars} rows x {NCOMMIT} cols: commit {commit_ms} ms, bus GKR {gkr_ms} ms, zerocheck {zc_ms} ms, opening {} ms", t3.elapsed().as_millis());
    }
    postcard::to_allocvec(&SsaBundle { nvars, commitment, gkr: gproof, slot_at_x, fixed_at_x, zc, open }).ok()
}

/// What a verifier holds of the program: the native evaluation of its preprocessed columns and its public part.
pub trait ProgramView {
    fn nvars(&self) -> usize;
    fn fixed_at(&self, x: &[Ea4]) -> Vec<Ea4>;
    fn public_sum(&self, rho: Ea4, beta: Ea4) -> Option<Ea4>;
    fn public_values(&self) -> Vec<Fa4>;
}

impl ProgramView for Program {
    fn nvars(&self) -> usize {
        self.nvars
    }
    fn fixed_at(&self, x: &[Ea4]) -> Vec<Ea4> {
        Program::fixed_at(self, x)
    }
    fn public_sum(&self, rho: Ea4, beta: Ea4) -> Option<Ea4> {
        Program::public_sum(self, rho, beta)
    }
    fn public_values(&self) -> Vec<Fa4> {
        self.public.iter().map(|p| p.1).collect()
    }
}

/// VERIFY an SSA proof against the program the verifier rebuilt. Fail-closed; never panics on remote bytes.
#[must_use]
pub fn verify(bytes: &[u8], prog: &dyn ProgramView) -> bool {
    let Ok(b) = postcard::from_bytes::<SsaBundle>(bytes) else { return false };
    let nvars = prog.nvars();
    let gate = SsaGate { gamma: Ea4::ZERO };
    let per = gate.degree(nvars) + 2;
    if b.nvars != nvars
        || b.slot_at_x.len() != NSLOT
        || b.fixed_at_x.len() != 2 * NSLOT
        || b.zc.opened.len() != NCOMMIT + NFIXED
        || b.zc.r.len() != nvars
        || b.zc.round_evals.len() != nvars
        || b.zc.round_evals.iter().any(|h| h.len() != per)
        || !b.zc.shifted_opened.is_empty()
        || b.gkr.layers.len() != SLOT_BITS + nvars
    {
        return false;
    }
    let Some((stacked, _)) = door_whir_config((nvars, NCOMMIT), PARAMS) else { return false };
    let pcs = door_pcs(stacked, PARAMS);
    let mut chl = door_challenger();
    for v in prog.public_values() {
        chl.observe(v);
    }
    chl.observe(b.commitment.clone());
    if !b.open.hvzk_mask_commits.is_empty() || b.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples {
        return false;
    }
    let shapes = vec![p3_sumcheck::table::TableShape::new(nvars, NCOMMIT)];
    let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
    for &e in &b.open.initial_ood_answers {
        lv.add_virtual_eval(e, &mut chl);
    }
    // the bus
    let rho: Ea4 = chl.sample_algebra_element();
    let beta: Ea4 = chl.sample_algebra_element();
    let Some(claims) = gkr::verify(&b.gkr, SLOT_BITS + nvars, &mut chl) else { return false };
    let Some(public) = prog.public_sum(rho, beta) else { return false };
    let [p0, q0] = claims.root;
    if q0 == Ea4::ZERO || p0 + public * q0 != Ea4::ZERO {
        return false; // the bus does not balance: a read saw a value nobody wrote
    }
    let (xs, x) = claims.point.split_at(SLOT_BITS);
    lv.add_claim_at(0, &slot_cols(), &b.slot_at_x, &Point::new(x.to_vec()), &mut chl);
    chl.observe_algebra_slice(&b.fixed_at_x);
    if b.fixed_at_x != bus_fixed(&prog.fixed_at(x)) {
        return false; // the addresses or multiplicities are not the program's
    }
    let (lp, lq) = leaf_claims(xs, &b.slot_at_x, &b.fixed_at_x, rho, beta);
    if lp != claims.p || lq != claims.q {
        return false;
    }
    // the gate
    let gamma: Ea4 = chl.sample_algebra_element();
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    if !verify_air_zerocheck(&b.zc, &SsaGate { gamma }, &z, &mut chl) {
        return false;
    }
    let committed_idx: Vec<usize> = (0..NCOMMIT).collect();
    lv.add_claim_at(0, &committed_idx, &b.zc.opened[..NCOMMIT], &Point::new(b.zc.r.clone()), &mut chl);
    chl.observe_algebra_slice(&b.zc.opened[NCOMMIT..]);
    if b.zc.opened[NCOMMIT..] != prog.fixed_at(&b.zc.r)[..] {
        return false; // the preprocessed row at r is not the program's
    }
    let alpha: Ea4 = chl.sample_algebra_element();
    let constraint = lv.constraint(alpha);
    let mut claimed = Ea4::ZERO;
    constraint.combine_evals(&mut claimed);
    WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order()).verify(&b.open, &mut chl, &b.commitment, constraint, claimed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::{execute, lay, Builder, Chal, Ext};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::Field;

    /// A small program that uses every row kind: a transcript (observes, samples, an extension challenge, a grind
    /// check, a draw), extension arithmetic, a leaf sponge and a Merkle walk to a root it checks, loads.
    fn sample_program() -> Builder {
        let mut b = Builder::new();
        let stmt = b.public_vals(&[Fa4::from_u64(7), Fa4::from_u64(11)]);
        let mut ch = Chal::new();
        ch.observe_all(&mut b, &stmt);
        let vals: Vec<Fa4> = (0..12u64).map(|i| Fa4::from_u64(i * 31 + 5)).collect();
        let loaded = b.load(&vals);
        ch.observe_all(&mut b, &loaded);
        let c = ch.sample_ext(&mut b);
        let x = b.load_ext(Ea4::from(Fa4::from_u64(3)));
        let y = b.mul_add(c, x, Ext::ONE);
        let y2 = b.mul(y, y);
        ch.observe_ext(&mut b, y2);
        // a leaf of 8 lanes and a walk of 3 levels to a root the program computes, then checks
        let leaf = b.load(&(0..8u64).map(|i| Fa4::from_u64(100 + i)).collect::<Vec<_>>());
        let mut inp = [crate::ssa::ZERO; 16];
        inp[..8].copy_from_slice(&leaf);
        let d0 = b.perm(inp);
        let sibs: Vec<Vec<u32>> = (0..3u64).map(|k| b.load(&(0..8u64).map(|i| Fa4::from_u64(1000 * (k + 1) + i)).collect::<Vec<_>>())).collect();
        let idx = b.load(&[Fa4::from_u64(5)])[0];
        let mut cur: [u32; 8] = d0[..8].try_into().expect("8");
        let mut ix = idx;
        let mut var = crate::ssa::ONE;
        let mut digests = Vec::new();
        let g0 = Fa4::from_u64(7);
        let mut gk = g0;
        for s in &sibs {
            let sib: [u32; 8] = s[..].try_into().expect("8");
            let (n, i2, v2) = b.comp(cur, sib, ix, var, gk, None);
            digests.push(n);
            cur = n;
            ix = i2;
            var = v2;
            gk = gk * gk;
        }
        assert_eq!(b.val(var), g0.exp_u64(5), "the walk carries g^index");
        let _ = b.halve(ix, true);
        // the walk again, its last level CHECKED against the root the first walk reached
        let mut cur2: [u32; 8] = d0[..8].try_into().expect("8");
        let mut ix2 = idx;
        let mut gk = g0;
        for (k, s) in sibs.iter().enumerate() {
            let sib: [u32; 8] = s[..].try_into().expect("8");
            let root = (k == 2).then_some(digests[2]);
            let (n, i2, _) = b.comp(cur2, sib, ix2, crate::ssa::ONE, gk, root);
            cur2 = n;
            ix2 = i2;
            gk = gk * gk;
        }
        let w = b.load(&[Fa4::ZERO])[0];
        ch.check_witness(&mut b, w, 0);
        let sum = ch.draw_index_sum(&mut b, 6);
        let _ = b.bits(sum, 0, 3);
        b
    }

    /// ⭐ THE SSA DOOR'S PIN — a program using every row kind lays, runs, proves and verifies against the program the
    /// verifier rebuilt from the statement alone (no values); the lies, each refused: a value read that nobody wrote, a
    /// proof checked against another program (one multiplicity off), a moved opening, a moved GKR round, a moved
    /// statement value.
    #[test]
    fn s1_an_ssa_program_proves_and_every_lie_is_refused() {
        let b = sample_program();
        let (rows, prog) = lay(&b).expect("lays");
        let cols = execute(&b, &rows, &prog).expect("runs");
        // the gate holds on every row (native, before any proof)
        let g = SsaGate { gamma: Ea4::ZERO };
        let oob = usdm_decider::air_zerocheck::OobLatch::new();
        for r in 0..(1usize << prog.nvars) {
            let vals: Vec<Ea4> = cols.iter().map(|c| Ea4::from(c[r])).chain(prog.fixed.iter().map(|c| Ea4::from(c[r]))).collect();
            let row = usdm_decider::air_zerocheck::Row::new(&vals, &oob);
            let rs = g.residuals(&row, &|_, _| Ea4::ZERO, &[]);
            if let Some(k) = rs.iter().position(|v| *v != Ea4::ZERO) {
                panic!("⛔ row {r}: residual {k} is not zero");
            }
        }
        // the bus balances natively
        let (rho, beta) = (Ea4::from(Fa4::from_u64(123_457)), Ea4::from(Fa4::from_u64(98_765)));
        let (lp, lq) = bus_leaves(&prog, &cols, rho, beta);
        let s: Ea4 = lp.iter().zip(&lq).map(|(p, q)| *p * p3_field::Field::inverse(q)).sum::<Ea4>() + prog.public_sum(rho, beta).expect("nonzero");
        assert_eq!(s, Ea4::ZERO, "⛔ the honest program's bus does not balance");
        let t0 = std::time::Instant::now();
        let bytes = prove(&prog, cols.clone()).expect("proves");
        let prove_ms = t0.elapsed().as_millis();
        // the verifier's program, from the statement alone (no proof values)
        let vb = {
            let mut b2 = sample_program();
            for v in b2.vals.iter_mut().skip(2) {
                *v = Fa4::ZERO;
            }
            b2
        };
        let (_, vprog) = lay(&vb).expect("lays");
        assert_eq!(vprog.fixed, prog.fixed, "⛔ the program depends on the proof's values");
        let t1 = std::time::Instant::now();
        assert!(verify(&bytes, &prog), "⛔ the honest SSA proof is refused");
        println!("[agg-s1] {} rows (T = 2^{}), {} public, proof {} B, prove {prove_ms} ms, verify {} ms", prog.rows, prog.nvars, prog.public.len(), bytes.len(), t1.elapsed().as_millis());
        // LIE 1: a value read that nobody wrote — one load-written lane moved in the prover's columns (no law reads a
        // load row, so only the bus can refuse it)
        {
            // a loaded lane's own write slot (the packer lays a load only where no active law reads the column)
            let t = 1usize << prog.nvars;
            let loads: std::collections::HashSet<u32> = b.ops.iter().filter_map(|o| if let crate::ssa::Op::Load { lanes } = o { Some(lanes.clone()) } else { None }).flatten().collect();
            let (r, sl) = (0..t)
                .flat_map(|r| (0..NSLOT).map(move |sl| (r, sl)))
                .find(|&(r, sl)| {
                    let m = prog.fixed[F_MULT + sl][r];
                    m != Fa4::ZERO && m != Fa4::NEG_ONE && loads.contains(&(p3_field::PrimeField32::as_canonical_u32(&prog.fixed[F_ADDR + sl][r])))
                })
                .expect("CALIBRATION: the program has a load that is read");
            let mut lcols = cols.clone();
            lcols[slot_col(sl)][r] += Fa4::ONE;
            let lbytes = prove(&prog, lcols).expect("a lying prover still produces bytes");
            assert!(!verify(&lbytes, &prog), "⛔ LIE 1: a read of a value nobody wrote verified");
        }
        // LIE 2: another program (one multiplicity off) — the verifier's own program refuses the proof
        let mut other = prog.clone();
        let c = &mut other.fixed[F_MULT + 20];
        if let Some(k) = c.iter().position(|v| *v != Fa4::ZERO && *v != Fa4::NEG_ONE) {
            c[k] += Fa4::ONE;
        }
        assert!(!verify(&bytes, &other), "⛔ LIE 2: a proof verified against a program with a multiplicity moved");
        // LIE 3: a moved opening
        let mut bb: SsaBundle = postcard::from_bytes(&bytes).expect("decodes");
        bb.zc.opened[3] += Ea4::ONE;
        assert!(!verify(&postcard::to_allocvec(&bb).expect("encodes"), &prog), "⛔ LIE 3: a moved opening verified");
        // LIE 4: a moved GKR round value
        let mut bb: SsaBundle = postcard::from_bytes(&bytes).expect("decodes");
        let k = bb.gkr.layers.len() - 1;
        bb.gkr.layers[k].rounds[0][0] += Ea4::ONE;
        assert!(!verify(&postcard::to_allocvec(&bb).expect("encodes"), &prog), "⛔ LIE 4: a moved GKR round verified");
        // LIE 5: a moved slot opening at x
        let mut bb: SsaBundle = postcard::from_bytes(&bytes).expect("decodes");
        bb.slot_at_x[40] += Ea4::ONE;
        assert!(!verify(&postcard::to_allocvec(&bb).expect("encodes"), &prog), "⛔ LIE 5: a moved slot opening verified");
        // LIE 6: another statement
        let mut st = prog.clone();
        st.public[2].1 += Fa4::ONE;
        assert!(!verify(&bytes, &st), "⛔ LIE 6: the proof verified for another statement");
    }
}

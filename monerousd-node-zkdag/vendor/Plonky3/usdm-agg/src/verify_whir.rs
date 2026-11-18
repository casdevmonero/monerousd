// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! `WhirVerifier::verify` AS A PROGRAM (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12, step 3; piece C, lane aggc) — the
//! layers above `verify_prog::Asm`'s transcript, sumcheck round, α-combine, index draw and query, each pinned against
//! the native code it mirrors on real commitments.
//!
//! This file's first part is the QUERY's pin (the layer itself is `verify_prog::Asm::query`): a real hiding Merkle
//! commitment (`hiding_decider::Mmcs16`, the committed door's own hash and compression), opened where the real
//! challenger's `draw_below` lands, verified by the native `verify_batch` and by the program — whose walk must end at
//! the latched root, whose fold must be `Poly::eval_ext` at the folding point, and whose query point must be
//! `g^index` — for base-field leaves (round 0) and extension leaves (later rounds), at several leaf widths.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_symmetric::CryptographicHasher;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::isa::{Alu, Instr, Kind, SrcA, SrcB, SrcC, ND, RATE};
use crate::verify_prog::Asm;

fn sponge() -> usdm_decider::hiding_decider::SpongeHash {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(usdm_decider::committed_air::COMMITTED_AIR_SEED);
    usdm_decider::hiding_decider::SpongeHash::new(usdm_decider::hiding_decider::Perm16::new_from_rng_128(&mut rng))
}

fn limbs(e: &Ea4) -> [Fa4; 4] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

/// A leaf-sponge row over all eight rate lanes (the first chunk of a sponge, or a later one), with its two units.
fn leaf_row(first: bool, alu: [Option<Alu>; 2]) -> Instr {
    let mut i = Instr::default();
    i.kind = Some(if first { Kind::Leaf0 } else { Kind::LeafN });
    i.am = 0xFF;
    i.alu = alu;
    i
}

/// A row whose only flags are a root bank's latch and/or check, with its two units.
fn bank_row(latch: Option<usize>, heq: Option<usize>, alu: [Option<Alu>; 2]) -> Instr {
    let mut i = Instr::default();
    if let Some(b) = latch {
        i.latch[b] = true;
    }
    if let Some(b) = heq {
        i.heq[b] = true;
    }
    i.alu = alu;
    i
}

/// The registers the final polynomial's check uses for one query (all distinct, in `X[0..20]` or `X[23..48]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalRegs {
    /// `1/z`, `1/z²`, the Horner sum, two products, the power of `1/z`, the square it is built from, a scratch.
    pub w: u8,
    pub w2: u8,
    pub acc: u8,
    pub t: u8,
    pub s: u8,
    pub pw: u8,
    pub sq: u8,
    pub neg: u8,
}

/// ⭐ LAYER 4a — THE FINAL POLYNOMIAL, BOUND ONCE. `WhirVerifier::verify` observes the final polynomial's coefficients
/// (`observe_algebra_slice(final_evaluations)`, whir/src/pcs/verifier/mod.rs) BEFORE the final queries are drawn, and
/// then checks every final query's fold against it (`SelectStatement::verify`: `Horner(coeffs, z) == fold`). The
/// coefficients are more than the registers hold and are needed once a query, so they are bound here to a digest and
/// re-streamed by each query ([`final_poly_check`]): each transcript row that absorbs two coefficients is TIED to a
/// leaf-sponge row over the same eight lanes (`PaddingFreeSponge`, the committed door's hash), the sponge's digest is
/// latched into root bank `bank` (free at the final round: the final queries open the other one) and asserted equal to
/// the sponge on the next row. A re-streamed coefficient that differs changes the digest, so the check's `HEQ` fails.
/// The coefficients must start on a word boundary (they follow a squeeze in `verify`), which is checked here.
pub fn absorb_final_poly(asm: &mut Asm, coeffs: &[Ea4], bank: usize) {
    assert!(coeffs.len() >= 2 && coeffs.len().is_power_of_two(), "a final polynomial of 2^v ≥ 2 coefficients");
    for (i, pair) in coeffs.chunks(2).enumerate() {
        let before = asm.len();
        asm.observe_ext(pair[0], None);
        asm.observe_ext(pair[1], None);
        let row = asm.len() - 1;
        let absorbed = asm.len() == before + 1 && matches!(asm.b.prog[row].kind, Some(Kind::Duplex | Kind::Reset)) && asm.b.prog[row].am == 0xFF;
        assert!(absorbed, "the final polynomial's coefficients do not start on a word boundary");
        asm.b.prog[row].tie = true;
        let w = asm.b.stream[row];
        asm.row(leaf_row(i == 0, [None, None]), w);
    }
    let digest: [Fa4; 8] = sponge().hash_iter(coeffs.iter().flat_map(limbs));
    let mut w = [Fa4::ZERO; ND];
    w[..RATE].copy_from_slice(&digest);
    asm.row(bank_row(Some(bank), None, [None, None]), w);
    asm.row(bank_row(None, Some(bank), [None, None]), [Fa4::ZERO; ND]);
}

/// ⭐ LAYER 4b — ONE FINAL QUERY'S CHECK: `Horner(coeffs, z) == fold` (`SelectStatement::verify`,
/// sumcheck/src/constraints/statement/select.rs:295). The coefficients are re-streamed in their absorbed order as leaf
/// rows whose sponge must reach the digest [`absorb_final_poly`] latched in `bank`. Horner in that order with
/// `w = 1/z` gives `Σ c_i w^(n−1−i) = w^(n−1)·p(z)`, so the check is `acc == fold·w^(n−1)`; `1/z` is the prover's
/// (a stream word) and is asserted to be `z`'s inverse. `z` is a base-field point (`g^index`), so its inverse is too.
/// Per pair of coefficients: a leaf row (`t = w·c_a + c_b`, `s = acc·w²`) and a row `acc = s + t`.
pub fn final_poly_check(asm: &mut Asm, coeffs: &[Ea4], bank: usize, fold: u8, z: u8, z_value: Fa4, r: FinalRegs) {
    let n = coeffs.len();
    assert!(n >= 2 && n.is_power_of_two(), "a final polynomial of 2^v ≥ 2 coefficients");
    let m1 = -Ea4::ONE;
    // w = 1/z (the prover's), and z·w = 1 asserted
    let inv = p3_field::Field::try_inverse(&z_value).unwrap_or(Fa4::ZERO);
    let mut iw = [Fa4::ZERO; ND];
    iw[0] = inv;
    let assert_inv = Alu { a: SrcA::X(z), b: SrcB::Dx(0), c: Some(SrcC::Kc), wr: None, zero: true, kc: m1 };
    asm.row(bank_row(None, None, [Asm::mul_add(SrcA::One, SrcB::Dx(0), None, r.w), Some(assert_inv)]), iw);
    // w², acc = 0, the power's start (pw = 1, sq = w)
    asm.units(Asm::mul_add(SrcA::X(r.w), SrcB::X(r.w), None, r.w2), Asm::mul_k(SrcA::One, Ea4::ZERO, None, r.acc));
    asm.units(Asm::mul_k(SrcA::One, Ea4::ONE, None, r.pw), Asm::mul_add(SrcA::One, SrcB::X(r.w), None, r.sq));
    // the re-stream and the Horner sum
    for (i, pair) in coeffs.chunks(2).enumerate() {
        let mut w = [Fa4::ZERO; ND];
        w[..4].copy_from_slice(&limbs(&pair[0]));
        w[4..8].copy_from_slice(&limbs(&pair[1]));
        let t = Asm::mul_add(SrcA::X(r.w), SrcB::Dx(0), Some(SrcC::Dx(1)), r.t);
        let s = Asm::mul_add(SrcA::X(r.acc), SrcB::X(r.w2), None, r.s);
        asm.row(leaf_row(i == 0, [t, s]), w);
        asm.units(Asm::mul_add(SrcA::One, SrcB::X(r.s), Some(SrcC::X(r.t)), r.acc), None);
    }
    // w^(n−1) = w·w²·w⁴·…: one row a squaring
    for _ in 0..n.trailing_zeros() {
        asm.units(Asm::mul_add(SrcA::X(r.pw), SrcB::X(r.sq), None, r.pw), Asm::mul_add(SrcA::X(r.sq), SrcB::X(r.sq), None, r.sq));
    }
    // acc − fold·w^(n−1) = 0, beside the re-stream's digest = the latched one
    asm.units(Asm::mul_add(SrcA::X(fold), SrcB::X(r.pw), None, r.neg), None);
    let check = Alu { a: SrcA::X(r.neg), b: SrcB::Kc, c: Some(SrcC::X(r.acc)), wr: None, zero: true, kc: m1 };
    asm.row(bank_row(None, Some(bank), [Some(check), None]), [Fa4::ZERO; ND]);
}

/// `X[wr] = X[a]·k + c`: a unit whose constant is the multiplier.
fn times_k(a: u8, k: Ea4, c: Option<SrcC>, wr: u8) -> Option<Alu> {
    Some(Alu { a: SrcA::X(a), b: SrcB::Kc, c, wr: Some(wr), zero: false, kc: k })
}

/// The registers one weight evaluation uses (distinct; `point` is consumed: it is squared in place).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightRegs {
    pub point: u8,
    pub out: u8,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    /// the out-of-domain weight's term, kept until the next coordinate's product
    pub t: u8,
}

/// ⭐ LAYER 5a — A QUERY POINT'S WEIGHT, `Point::select_poly(var)` (multilinear-util/src/point.rs:144):
/// `Π_i (r_i·(var^(2^i) − 1) + 1)` with the local coordinates taken LAST first (`self.iter().rev()`) against
/// `var, var², var⁴, …`. `coords` are the registers of the constraint's local point, in order (`eval_constraints_poly`
/// passes the last `num_variables` folding coordinates, sumcheck/src/strategy.rs:306); `X[w.point]` holds `var` and is
/// squared in place. Leaves the weight in `X[w.out]`. Rows: two a coordinate, plus one.
pub fn select_weight(asm: &mut Asm, coords: &[u8], w: WeightRegs) {
    let m1 = -Ea4::ONE;
    for (step, &r) in coords.iter().rev().enumerate() {
        // a = var − 1 ; var = var²
        asm.units(times_k(w.point, Ea4::ONE, Some(SrcC::Kc), w.a).map(|mut u| {
            u.b = SrcB::One;
            u.kc = m1;
            u
        }), Asm::mul_add(SrcA::X(w.point), SrcB::X(w.point), None, w.point));
        // b = r·a + 1 ; out = out·b (the previous coordinate's term), or out = 1 on the first
        let carry = if step == 0 { Asm::mul_k(SrcA::One, Ea4::ONE, None, w.out) } else { Asm::mul_add(SrcA::X(w.out), SrcB::X(w.b), None, w.out) };
        asm.units(Asm::mul_add(SrcA::X(r), SrcB::X(w.a), Some(SrcC::One), w.b), carry);
    }
    asm.units(Asm::mul_add(SrcA::X(w.out), SrcB::X(w.b), None, w.out), None);
}

/// ⭐ LAYER 5b — AN OUT-OF-DOMAIN POINT'S WEIGHT, `expand_from_univariate(y, n).eq_poly(local)`: the point is
/// `[y^(2^(n−1)), …, y², y]` (point.rs:82) and `eq` is `Π_i (p_i·r_i + (1 − p_i)(1 − r_i))`, so the LAST coordinate
/// pairs with `y`, as in [`select_weight`]. Each term is laid as `(1 − p) − r·(1 − 2p)`. `X[w.point]` holds `y` and is
/// squared in place. Rows: three a coordinate, plus one.
pub fn eq_weight(asm: &mut Asm, coords: &[u8], w: WeightRegs) {
    let (m1, m2) = (-Ea4::ONE, -(Ea4::ONE + Ea4::ONE));
    for (step, &r) in coords.iter().rev().enumerate() {
        // a = 1 − 2p ; c = 1 − p
        asm.units(times_k(w.point, m2, Some(SrcC::One), w.a), times_k(w.point, m1, Some(SrcC::One), w.c));
        // b = r·a ; p = p²
        asm.units(Asm::mul_add(SrcA::X(r), SrcB::X(w.a), None, w.b), Asm::mul_add(SrcA::X(w.point), SrcB::X(w.point), None, w.point));
        // t = c − b (the term) ; out = out·(the previous term), or 1 on the first
        let carry = if step == 0 { Asm::mul_k(SrcA::One, Ea4::ONE, None, w.out) } else { Asm::mul_add(SrcA::X(w.out), SrcB::X(w.t), None, w.out) };
        asm.units(times_k(w.b, m1, Some(SrcC::X(w.c)), w.t), carry);
    }
    asm.units(Asm::mul_add(SrcA::X(w.out), SrcB::X(w.t), None, w.out), None);
}


// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// LAYER 6 — `WhirVerifier::verify`, WHOLE (whir/src/pcs/verifier/mod.rs), on top of the layers above.
// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// The WHIR proof type of every committed-door carrier (`committed_air::Pcs`'s).
pub type CarrierWhirProof = p3_whir::pcs::proof::WhirProof<Fa4, Ea4, usdm_decider::hiding_decider::Mmcs16>;
/// The WHIR configuration of a committed-door carrier.
pub type CarrierWhirConfig = p3_whir::parameters::WhirConfig<Ea4, Fa4, usdm_decider::hiding_decider::Chl>;

/// The registers of the folding coordinates: `X[COORDS + k]` holds the `k`-th coordinate sampled (24 at most: the
/// stacked arity's cap, committed_air.rs:202).
pub const COORDS: u8 = 23;
/// The salt words a hiding leaf carries (`Mmcs16`'s `SALT_ELEMS`; stir_group_air.rs:59 `SALT_WORDS`).
pub const SALT: usize = 8;

/// The initial constraint's weight at the closing check: given the registers of every folding coordinate in sampling
/// order, lay rows that leave `Σ_i α^i·eq(p_i, coords)` of the door's initial constraint in the output register. The
/// door that built the constraint (`LayoutVerifier::constraint`) writes it, in closed form.
pub type InitWeight<'a> = dyn FnMut(&mut Asm, &[u8], u8) + 'a;

fn zero_ext() -> Ea4 {
    Ea4::ZERO
}

fn pop_into(asm: &mut Asm, reg: u8) {
    asm.pop_with(Asm::mul_k(SrcA::One, Ea4::ZERO, Some(crate::verify_prog::POPPED), reg), None);
}

/// One query's opening, read from the proof (or zeros of the right shape when there is no proof).
fn opening_words(q: Option<&p3_whir::pcs::proof::QueryOpening<Fa4, Ea4, (Vec<Vec<Fa4>>, Vec<[Fa4; 8]>)>>, f: usize, ext: bool, k: usize) -> (Vec<Fa4>, Vec<Fa4>, Vec<[Fa4; RATE]>) {
    use p3_whir::pcs::proof::QueryOpening;
    match q {
        Some(QueryOpening::Base { values, proof }) => (values.clone(), proof.0.first().cloned().unwrap_or_default(), proof.1.clone()),
        Some(QueryOpening::Extension { values, proof }) => (values.iter().flat_map(limbs).collect(), proof.0.first().cloned().unwrap_or_default(), proof.1.clone()),
        None => (vec![Fa4::ZERO; (if ext { 4 } else { 1 }) << f], vec![Fa4::ZERO; SALT], vec![[Fa4::ZERO; RATE]; k]),
    }
}

/// The sumcheck rounds of one fold (`verify_rounds_each`, sumcheck/src/data.rs:122), each challenge copied into the next
/// coordinate register. `bits[i]` is round `i`'s grind; `X[0]` is the claim.
fn sumcheck_fold(asm: &mut Asm, data: Option<&p3_sumcheck::SumcheckData<Fa4, Ea4>>, bits: &[usize], next_coord: &mut u8) -> Result<(), String> {
    let regs = crate::verify_prog::SumcheckRegs { claim: 0, r: 1, c0: 2, cinf: 3, t: [4, 5, 6] };
    let mut w = data.map(|d| d.pow_witnesses.iter());
    for (i, &b) in bits.iter().enumerate() {
        let [c0, cinf] = data.and_then(|d| d.polynomial_evaluations.get(i).copied()).unwrap_or([zero_ext(), zero_ext()]);
        let grind = if b == 0 {
            None
        } else {
            let mut next = || w.as_mut().and_then(|it| it.next().copied()).unwrap_or(Fa4::ZERO);
            Some((b, [next(), next()]))
        };
        asm.sumcheck_round(c0, cinf, grind, regs);
        if *next_coord >= COORDS + 24 {
            return Err("more than 24 folding coordinates".into());
        }
        asm.units(Asm::mul_add(SrcA::One, SrcB::X(regs.r), None, *next_coord), None);
        *next_coord += 1;
    }
    Ok(())
}

/// ⭐⭐ `WhirVerifier::verify` AS A PROGRAM. On entry the transcript is at `verify`'s entry (the door has absorbed
/// everything before it and drawn its α), the commitment is latched in root bank 0, and `X[claim]` holds `claimed_eval`
/// (`constraint.combine_evals` of the door's initial constraint). `proof = None` lays the same rows over a zero stream.
///
/// THE ONE DEPARTURE IN SHAPE, NOT IN STATEMENT — the α-combine is DEFERRED. Each sumcheck round maps the claim
/// affinely, `claim' = r·claim + (c0·(1 − 2r) + c_inf·r(r − 1))` (`extrapolate_01inf`), and nothing reads the claim
/// before the last line of `verify`. So round `j`'s combine term `D_j = Σ_i α^i·ood_i + Σ_k α^(n+k)·fold_k` enters the
/// final claim as `D_j·Π(every sumcheck challenge after it)`, and those challenges are round `j`'s local point (its
/// last `num_variables` coordinates). The program carries the claim WITHOUT the `D_j`, pushes each round's
/// `(y_i, ood_i)` and `(z_k, fold_k)` pairs and its `α`, and at the closing check pops them back, accumulating `D_j`
/// and the weight `S_j` (`select_poly` / `eq_poly` of the same points at the same local point) in one pass, then
/// asserts `claim + Σ D_j·Π local_j == (W_init + Σ S_j)·final_value` — `verify`'s own last line, rearranged.
///
/// SAFE AT SCALE: rows are a function of the configuration alone (rounds, queries, folding factors, Merkle depths);
/// nothing grows with height, blocks, notes or nodes. AI RESISTANT: (a) — every check `verify` makes is a constraint.
pub fn emit_whir_verify(asm: &mut Asm, cfg: &CarrierWhirConfig, proof: Option<&CarrierWhirProof>, claim: u8, init_weight: &mut InitWeight<'_>) -> Result<(), String> {
    let n_rounds = cfg.n_rounds();
    if proof.is_some_and(|p| p.rounds.len() != n_rounds) {
        return Err("the proof's rounds are not the configuration's".into());
    }
    // the claim in X[0]
    if claim != 0 {
        asm.units(Asm::mul_add(SrcA::One, SrcB::X(claim), None, 0), None);
    }
    let mut next_coord = COORDS;
    // the initial sumcheck
    sumcheck_fold(asm, proof.map(|p| &p.initial_sumcheck), &cfg.starting_fold_grinds(), &mut next_coord)?;
    let mut fold_start = COORDS; // the coordinates the previous fold sampled (the queries' folding point)
    let mut round_meta: Vec<(usize, usize, usize)> = Vec::new(); // (num_variables, ood, queries) a round
    for r in 0..n_rounds {
        let rp = &cfg.round_parameters[r];
        let rproof = proof.map(|p| &p.rounds[r]);
        let folding = cfg.folding_factor(r);
        if rp.ood_samples > 2 || folding > 4 || rp.pow_bits > crate::isa::NZB {
            return Err(format!("round {r}: a shape past this program's registers (ood {}, folding {}, pow {})", rp.ood_samples, folding, rp.pow_bits));
        }
        // parse_with_round: the new root (latched in the other bank), then each out-of-domain point and its answer
        let root: [Fa4; RATE] = rproof.and_then(|p| p.commitment.as_ref()).map_or([Fa4::ZERO; RATE], |c| c.as_ref()[0]);
        asm.observe_root(&root, (r + 1) % 2);
        for i in 0..rp.ood_samples {
            asm.challenge_into(7 + i as u8);
            let ans = rproof.and_then(|p| p.ood_answers.get(i).copied()).unwrap_or_else(zero_ext);
            asm.observe_ext(ans, Some(9 + i as u8));
        }
        // verify_stir_challenges: the grind, the checkpoint sample (it also lands the answers' loads), the pairs
        if rp.pow_bits > 0 {
            asm.observe(&[rproof.map_or(Fa4::ZERO, |p| p.pow_witness)]);
            asm.sample_bits(rp.pow_bits);
        }
        asm.sample_bits(0);
        for i in 0..rp.ood_samples {
            asm.push(7 + i as u8);
            asm.push(9 + i as u8);
        }
        let k = (rp.domain_size >> rp.folding_factor).trailing_zeros() as usize;
        let f = rp.folding_factor;
        // q = 1 − r for the fold's coordinates
        let rs: Vec<u8> = (fold_start..fold_start + f as u8).collect();
        for (i, &rr) in rs.iter().enumerate() {
            asm.units(times_k(rr, -Ea4::ONE, Some(SrcC::One), 1 + i as u8), None);
        }
        let qregs = crate::verify_prog::QueryRegs { r: rs.clone(), q: (1..1 + f as u8).collect(), w: (11..19).collect(), p: [6, 19], gidx: 7 };
        for qi in 0..rp.num_queries {
            let (values, salt, sibs) = opening_words(rproof.and_then(|p| p.queries.get(qi)), f, r > 0, k);
            asm.query(k, rp.folded_domain_gen, f, r > 0, r % 2, &values, &salt, &sibs, &qregs);
            asm.push(qregs.gidx);
            asm.push(qregs.w[0]);
        }
        // α, kept for the closing check
        asm.challenge_into(8);
        asm.push(8);
        round_meta.push((rp.num_variables, rp.ood_samples, rp.num_queries));
        // the round's sumcheck
        fold_start = next_coord;
        sumcheck_fold(asm, rproof.map(|p| &p.sumcheck), &cfg.round_fold_grinds(r), &mut next_coord)?;
    }
    // the final polynomial, bound once in the bank the final queries do not open
    let fin = cfg.final_round_config();
    let n_final = 1usize << fin.num_variables;
    let coeffs: Vec<Ea4> = proof.and_then(|p| p.final_poly.as_ref()).map_or_else(|| vec![Ea4::ZERO; n_final], |p| p.as_slice().to_vec());
    if coeffs.len() != n_final {
        return Err("the final polynomial's length is not the configuration's".into());
    }
    let free = (n_rounds + 1) % 2;
    absorb_final_poly(asm, &coeffs, free);
    if fin.pow_bits > 0 {
        asm.observe(&[proof.map_or(Fa4::ZERO, |p| p.final_pow_witness)]);
        asm.sample_bits(fin.pow_bits);
    }
    let (k, f) = ((fin.domain_size >> fin.folding_factor).trailing_zeros() as usize, fin.folding_factor);
    let rs: Vec<u8> = (fold_start..fold_start + f as u8).collect();
    let qregs = crate::verify_prog::QueryRegs { r: rs.clone(), q: (1..1 + f as u8).collect(), w: (11..19).collect(), p: [6, 19], gidx: 7 };
    let fregs = FinalRegs { w: 2, w2: 3, acc: 4, t: 5, s: 8, pw: 9, sq: 10, neg: 6 };
    for qi in 0..cfg.final_queries {
        // q = 1 − r, laid again before every final query: the previous query's polynomial check used X[2..6]
        for (i, &rr) in rs.iter().enumerate() {
            asm.units(times_k(rr, -Ea4::ONE, Some(SrcC::One), 1 + i as u8), None);
        }
        let (values, salt, sibs) = opening_words(proof.and_then(|p| p.final_queries.get(qi)), f, n_rounds > 0, k);
        asm.query(k, fin.folded_domain_gen, f, n_rounds > 0, n_rounds % 2, &values, &salt, &sibs, &qregs);
        // z's value for the prover's 1/z: the walk's g^index (read off the opening, which the walk itself asserts)
        let zv = match proof {
            None => Fa4::ONE,
            Some(p) => match p.query_indices.get(n_rounds).and_then(|v| v.get(qi)) {
                Some(&i) => fin.folded_domain_gen.exp_u64(i as u64),
                None => return Err(format!("final query {qi}: the proof names no index (query_indices)")),
            },
        };
        final_poly_check(asm, &coeffs, free, qregs.w[0], qregs.gidx, zv, fregs);
    }
    // the final sumcheck
    let final_start = next_coord;
    let fbits = vec![cfg.final_folding_pow_bits; cfg.final_sumcheck_rounds];
    sumcheck_fold(asm, proof.and_then(|p| p.final_sumcheck.as_ref()), &fbits, &mut next_coord)?;
    let coords: Vec<u8> = (COORDS..next_coord).collect();
    if coords.len() != cfg.num_variables {
        return Err(format!("{} folding coordinates for {} variables", coords.len(), cfg.num_variables));
    }
    // ── the closing check ──
    // final_value: the final polynomial's evaluations at the final sumcheck's point (Prefix; the last coordinate folds
    // adjacent pairs first, poly.rs:657), over a third re-stream bound to the same digest; a binary counter of levels
    let fpt: Vec<u8> = (final_start..next_coord).collect();
    if fpt.len() != fin.num_variables || fpt.len() > 7 {
        return Err("the final sumcheck's point is not the final polynomial's arity".into());
    }
    let fv = 13u8;
    let level_reg = |l: usize| 1 + l as u8; // X1..X7 pend per level
    let (lo, hi, d) = (9u8, 10u8, 12u8);
    let mut pending = vec![false; fpt.len() + 1];
    let nvf = fpt.len();
    for (i, pair) in coeffs.chunks(2).enumerate() {
        let mut w = [Fa4::ZERO; ND];
        w[..4].copy_from_slice(&limbs(&pair[0]));
        w[4..8].copy_from_slice(&limbs(&pair[1]));
        asm.row(leaf_row(i == 0, [Asm::mul_add(SrcA::One, SrcB::Dx(0), None, lo), Asm::mul_add(SrcA::One, SrcB::Dx(1), None, hi)]), w);
        // v = lo + x·(hi − lo) with x the LAST coordinate: level 1
        let mut level = 1usize;
        let mut x = fpt[nvf - 1];
        loop {
            asm.units(times_k(lo, -Ea4::ONE, Some(SrcC::X(hi)), d), None);
            asm.units(Asm::mul_add(SrcA::X(x), SrcB::X(d), Some(SrcC::X(lo)), hi), None);
            if level == nvf {
                asm.units(Asm::mul_add(SrcA::One, SrcB::X(hi), None, fv), None);
                break;
            }
            if !pending[level] {
                asm.units(Asm::mul_add(SrcA::One, SrcB::X(hi), None, level_reg(level)), None);
                pending[level] = true;
                break;
            }
            // two values at this level: fold them with the next coordinate up
            asm.units(Asm::mul_add(SrcA::One, SrcB::X(level_reg(level)), None, lo), None);
            pending[level] = false;
            level += 1;
            x = fpt[nvf - level];
        }
    }
    if nvf == 0 {
        return Err("a final polynomial of no variables".into());
    }
    asm.row(bank_row(None, Some(free), [None, None]), [Fa4::ZERO; ND]);
    // W = the initial constraint's weight (the door's, in closed form)
    let wsum = 14u8;
    init_weight(asm, &coords, wsum);
    // the rounds, newest first: α, then each pair newest first (queries, then out-of-domain), by reverse Horner
    let (alpha, rd, rs_, prod) = (15u8, 16u8, 17u8, 18u8);
    let wr = WeightRegs { point: 1, out: 2, a: 3, b: 4, c: 5, t: 6 };
    for &(nv, nood, nq) in round_meta.iter().rev() {
        let local: Vec<u8> = coords[coords.len() - nv..].to_vec();
        pop_into(asm, alpha);
        asm.units(Asm::mul_k(SrcA::One, Ea4::ZERO, None, rd), Asm::mul_k(SrcA::One, Ea4::ZERO, None, rs_));
        for _ in 0..nq {
            asm.pop_with(Asm::mul_add(SrcA::X(rd), SrcB::X(alpha), Some(crate::verify_prog::POPPED), rd), None);
            pop_into(asm, wr.point);
            select_weight(asm, &local, wr);
            asm.units(Asm::mul_add(SrcA::X(rs_), SrcB::X(alpha), Some(SrcC::X(wr.out)), rs_), None);
        }
        for _ in 0..nood {
            asm.pop_with(Asm::mul_add(SrcA::X(rd), SrcB::X(alpha), Some(crate::verify_prog::POPPED), rd), None);
            pop_into(asm, wr.point);
            eq_weight(asm, &local, wr);
            asm.units(Asm::mul_add(SrcA::X(rs_), SrcB::X(alpha), Some(SrcC::X(wr.out)), rs_), None);
        }
        // Π local, then claim += D·Π and W += S
        asm.units(Asm::mul_k(SrcA::One, Ea4::ONE, None, prod), None);
        for &c in &local {
            asm.units(Asm::mul_add(SrcA::X(prod), SrcB::X(c), None, prod), None);
        }
        asm.units(Asm::mul_add(SrcA::X(rd), SrcB::X(prod), Some(SrcC::X(0)), 0), Asm::mul_add(SrcA::One, SrcB::X(rs_), Some(SrcC::X(wsum)), wsum));
    }
    // claimed == weights·final_value
    asm.units(Asm::mul_add(SrcA::X(wsum), SrcB::X(fv), None, 19), None);
    asm.row(bank_row(None, None, [Some(Alu { a: SrcA::X(19), b: SrcB::Kc, c: Some(SrcC::X(0)), wr: None, zero: true, kc: -Ea4::ONE }), None]), [Fa4::ZERO; ND]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_challenger::CanObserve;
    use p3_commit::{ExtensionMmcs, Mmcs};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_multilinear_util::point::Point;
    use p3_multilinear_util::poly::Poly;
    use p3_whir::pcs::utils::draw_below;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;
    use usdm_decider::hiding_decider::{Chl, CompressHash, Ea4, Fa4, Mmcs16, Perm16, SpongeHash};

    use crate::isa::{ea, execute, ExecError, Instr, ND, RATE, X};
    use crate::verify_prog::{Asm, QueryRegs};

    fn perm() -> Perm16 {
        let mut rng = SmallRng::seed_from_u64(usdm_decider::committed_air::COMMITTED_AIR_SEED);
        Perm16::new_from_rng_128(&mut rng)
    }

    /// The committed door's Merkle scheme (committed_air.rs `mmcs_with`), salted from a fixed seed (the salt is the
    /// prover's blinding; a pin needs it reproducible).
    fn mmcs() -> Mmcs16 {
        Mmcs16::new(SpongeHash::new(perm()), CompressHash::new(perm()), 0, SmallRng::seed_from_u64(0xC5))
    }

    /// One query laid as a program: the transcript opens by absorbing the root (latched in bank `bank`), the folding
    /// coordinates are stated in their registers, then the query. Returns the program, its stream and the row from
    /// which the fold and `g^index` are readable.
    #[allow(clippy::too_many_arguments)]
    fn lay(root: &[Fa4; RATE], bank: usize, k: usize, kg: Fa4, f: usize, ext_leaf: bool, rs: &[Ea4], values: &[Fa4], salt: &[Fa4], siblings: &[[Fa4; RATE]]) -> (Vec<Instr>, Vec<[Fa4; ND]>, usize, QueryRegs) {
        let regs = QueryRegs { r: (0..f as u8).collect(), q: (5..5 + f as u8).collect(), w: (10..18).collect(), p: [18, 19], gidx: 4 };
        let mut asm = Asm::new();
        asm.observe_root(root, bank);
        for (i, r) in rs.iter().enumerate() {
            asm.units(Asm::mul_k(crate::isa::SrcA::One, *r, None, regs.r[i]), Asm::mul_k(crate::isa::SrcA::One, Ea4::ONE - *r, None, regs.q[i]));
        }
        asm.query(k, kg, f, ext_leaf, bank, values, salt, siblings, &regs);
        let end = asm.len();
        let (prog, d) = asm.finish();
        (prog, d, end, regs)
    }

    fn reg(cols: &[Vec<Fa4>], k: u8, row: usize) -> Ea4 {
        ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols[X + 4 * k as usize + t][row]))
    }

    /// ⭐ LAYER 3c's PIN — A QUERY IS THE NATIVE OPENING CHECK AND FOLD. For base leaves of width 2, 4 and 16 and
    /// extension leaves of width 2 and 8, over a tree of 2^6 leaves: the index is the real challenger's `draw_below`
    /// after it absorbed the root; the opening is the real scheme's `open_batch` there (accepted by `verify_batch`);
    /// the program runs (its walk ends at the latched root), its fold register holds `Poly::eval_ext` of the leaf at
    /// the folding point and its point register `g^index`. Then the lies, each a row the executor cannot run: a moved
    /// leaf value, a moved salt word, a moved sibling, and the honest opening against the OTHER root bank.
    #[test]
    fn c5_a_query_is_the_native_opening_check_and_fold() {
        let mut seed: u64 = 0xC5_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let k = 6usize;
        let kg = Fa4::two_adic_generator(k);
        let mut laid = Vec::new();
        for (f, ext_leaf) in [(1usize, false), (2, false), (4, false), (1, true), (3, true)] {
            let width = 1usize << f;
            let m = mmcs();
            let rs: Vec<Ea4> = (0..f).map(|_| ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)))).collect();
            // commit a random matrix (2^k rows, 2^f values a row), the leaf being one row
            let (root, values_at, salt_at, sibs_at, leaf_ext): (_, Vec<Fa4>, Vec<Fa4>, Vec<[Fa4; RATE]>, Vec<Ea4>);
            let mut real: Chl = Chl::new(perm());
            if ext_leaf {
                let em = ExtensionMmcs::<Fa4, Ea4, Mmcs16>::new(m.clone());
                let vals: Vec<Ea4> = (0..width << k).map(|_| ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)))).collect();
                let (c, pd) = em.commit(vec![RowMajorMatrix::new(vals, width)]);
                real.observe(c.clone());
                let index = draw_below::<_, Fa4>(&mut real, 1usize << k);
                let opening = em.open_batch(index, &pd);
                let dims = [p3_matrix::Dimensions { height: 1 << k, width }];
                em.verify_batch(&c, &dims, index, (&opening).into()).expect("CALIBRATION: the native scheme accepts its own opening");
                let (opened, (salts, siblings)) = opening.unpack();
                leaf_ext = opened[0].clone();
                values_at = leaf_ext.iter().flat_map(|e| e.as_basis_coefficients_slice().to_vec()).collect();
                salt_at = salts[0].clone();
                sibs_at = siblings;
                root = c;
                laid.push((f, ext_leaf, index));
            } else {
                let vals: Vec<Fa4> = (0..width << k).map(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)).collect();
                let (c, pd) = m.commit(vec![RowMajorMatrix::new(vals, width)]);
                real.observe(c.clone());
                let index = draw_below::<_, Fa4>(&mut real, 1usize << k);
                let opening = m.open_batch(index, &pd);
                let dims = [p3_matrix::Dimensions { height: 1 << k, width }];
                m.verify_batch(&c, &dims, index, (&opening).into()).expect("CALIBRATION: the native scheme accepts its own opening");
                let (opened, (salts, siblings)) = opening.unpack();
                values_at = opened[0].clone();
                leaf_ext = values_at.iter().map(|v| Ea4::from(*v)).collect();
                salt_at = salts[0].clone();
                sibs_at = siblings;
                root = c;
                laid.push((f, ext_leaf, index));
            }
            let index = laid.last().expect("laid").2;
            let root_words: [Fa4; RATE] = root.as_ref()[0];
            let want_fold = Poly::new(leaf_ext.clone()).eval_ext::<Fa4>(&Point::new(rs.clone()));
            let want_point = kg.exp_u64(index as u64);
            for bank in 0..2 {
                let (prog, d, end, regs) = lay(&root_words, bank, k, kg, f, ext_leaf, &rs, &values_at, &salt_at, &sibs_at);
                let (cols, _io) = execute(&prog, &d, 8).unwrap_or_else(|e: ExecError| panic!("⛔ (f = {f}, ext = {ext_leaf}, bank {bank}): the honest query does not run: row {} — {}", e.row, e.why));
                assert_eq!(reg(&cols, regs.w[0], end), want_fold, "⛔ (f = {f}, ext = {ext_leaf}): the program's fold is not Poly::eval_ext at the folding point");
                assert_eq!(reg(&cols, regs.gidx, end), Ea4::from(want_point), "⛔ (f = {f}, ext = {ext_leaf}): the program's query point is not g^index");
            }
            // the lies: each must leave the executor with a row it cannot run
            let run = |values: &[Fa4], salt: &[Fa4], sibs: &[[Fa4; RATE]]| {
                let (prog, d, _, _) = lay(&root_words, 0, k, kg, f, ext_leaf, &rs, values, salt, sibs);
                execute(&prog, &d, 8).is_err()
            };
            let mut v = values_at.clone();
            v[values_at.len() / 2] += Fa4::ONE;
            assert!(run(&v, &salt_at, &sibs_at), "⛔ (f = {f}, ext = {ext_leaf}): a moved leaf value still walked to the root");
            let mut s = salt_at.clone();
            s[3] += Fa4::ONE;
            assert!(run(&values_at, &s, &sibs_at), "⛔ (f = {f}, ext = {ext_leaf}): a moved salt word still walked to the root");
            let mut sb = sibs_at.clone();
            sb[k / 2][5] += Fa4::ONE;
            assert!(run(&values_at, &salt_at, &sb), "⛔ (f = {f}, ext = {ext_leaf}): a moved sibling still walked to the root");
            // the other bank holds no root: the same honest opening checked against it is refused
            let mut asm = Asm::new();
            asm.observe_root(&root_words, 0);
            let regs = QueryRegs { r: (0..f as u8).collect(), q: (5..5 + f as u8).collect(), w: (10..18).collect(), p: [18, 19], gidx: 4 };
            for (i, r) in rs.iter().enumerate() {
                asm.units(Asm::mul_k(crate::isa::SrcA::One, *r, None, regs.r[i]), Asm::mul_k(crate::isa::SrcA::One, Ea4::ONE - *r, None, regs.q[i]));
            }
            asm.query(k, kg, f, ext_leaf, 1, &values_at, &salt_at, &sibs_at, &regs);
            let (prog, d) = asm.finish();
            assert!(execute(&prog, &d, 8).is_err(), "⛔ (f = {f}, ext = {ext_leaf}): a walk was accepted against a bank that holds another root");
        }
        println!("[agg-c5] queries laid (f, extension leaf, index): {laid:?}");
    }

    /// ⭐⭐ LAYER 6's PIN — THE WHOLE PROGRAM IS `WhirVerifier::verify`. A real opening, made the way a committed carrier
    /// makes it (committed_air.rs ~600: `PrefixProver::commit`, the out-of-domain virtual evaluations, a claim at a point by
    /// `eval_at`, `WhirProver::prove`) under a real WHIR configuration (constant folding 4, Johnson bound, the hiding
    /// Merkle scheme `Mmcs16`), verified natively (`WhirVerifier::verify`, after the verifier-side prefix of
    /// committed_air.rs ~957) and by the program: the program runs, its folding coordinates ARE the point the native
    /// verifier returns, and the program laid with no proof is the same instruction sequence (the program is a
    /// function of the configuration alone). Then the lies, each refused by the native verifier AND by the program: a
    /// moved final-polynomial coefficient, a moved out-of-domain answer, a moved leaf value in a round query, and a
    /// moved sumcheck evaluation.
    #[test]
    fn c8_the_whole_program_is_whir_verify() {
        use crate::verify_whir::{emit_whir_verify, CarrierWhirProof, COORDS};
        use p3_challenger::FieldChallenger;
        use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier as LayoutVerifier};
        use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
        use p3_whir::pcs::prover::WhirProver;
        use p3_whir::pcs::verifier::WhirVerifier;
        type Dft = p3_dft::Radix2DFTSmallBatch<Fa4>;
        type Pcs = WhirProver<Ea4, Fa4, Dft, Mmcs16, Chl, PrefixProver<Fa4, Ea4>>;
        let mut seed: u64 = 0xC8_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let rnd_e = |next: &mut dyn FnMut() -> u64| ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)));
        let nvars = 12usize;
        let folding = 4usize;
        let col: Vec<Fa4> = (0..1usize << nvars).map(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)).collect();
        let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![Table::new(vec![Poly::new(col)])], folding);
        let stacked = witness.num_variables();
        let ff = FoldingFactor::Constant(folding);
        let (n_rounds, _) = ff.compute_number_of_rounds(stacked);
        let rates: Vec<usize> = (0..n_rounds).map(|r| 2 + r + 1).collect();
        let params = ProtocolParameters {
            hiding: true,
            security_level: 40,
            pow_bits: 8,
            round_log_inv_rates: rates,
            folding_factor: ff,
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 2,
        };
        let pcs = Pcs::new(WhirConfig::new(stacked, params), Dft::default(), mmcs());
        // the prover, as a committed carrier proves
        let mut chl = Chl::new(perm());
        let (mut layout, commitment, md) = PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, folding, 2);
        let mut open: CarrierWhirProof = pcs.config.empty_proof();
        open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
        let point: Vec<Ea4> = (0..nvars).map(|_| rnd_e(&mut next)).collect();
        let evals = layout.eval_at(0, &[0], &Point::new(point.clone()), &mut chl);
        pcs.prove(&mut open, &mut chl, layout, md);
        println!("[agg-c8] stacked {stacked} variables, {} rounds, {} final queries", pcs.config.n_rounds(), pcs.config.final_queries);
        // the native verifier, at verify()'s entry exactly as the door reaches it
        let native = |open: &CarrierWhirProof| -> Result<(Vec<Ea4>, Ea4, Ea4, Vec<Ea4>), String> {
            let mut v = Chl::new(perm());
            v.observe(commitment.clone());
            for mc in &open.hvzk_mask_commits {
                v.observe(mc.clone());
            }
            let shapes = vec![p3_sumcheck::table::TableShape::new(nvars, 1)];
            let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
            let mut ood_points = Vec::new();
            for &e in &open.initial_ood_answers {
                let before = v.clone();
                lv.add_virtual_eval(e, &mut v);
                let mut b = before;
                ood_points.push(b.sample_algebra_element::<Ea4>());
            }
            lv.add_claim_at(0, &[0], &evals, &Point::new(point.clone()), &mut v);
            let alpha: Ea4 = v.sample_algebra_element();
            let constraint = lv.constraint(alpha);
            let mut claimed = Ea4::ZERO;
            constraint.combine_evals(&mut claimed);
            let c2 = constraint.clone();
            let fr = WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order())
                .verify(open, &mut v, &commitment, constraint, claimed)
                .map_err(|e| format!("{e:?}"))?;
            let w_init = p3_sumcheck::strategy::VariableOrder::Prefix.eval_constraints_poly(core::slice::from_ref(&c2), &fr);
            Ok((fr.as_slice().to_vec(), claimed, w_init, ood_points))
        };
        let (want_coords, claimed, w_init, _) = native(&open).expect("CALIBRATION: the native verifier accepts the honest opening");
        // the program: the door's prefix (the root, the masks, the virtual evaluations, the claim, α), then verify
        let build = |o: &CarrierWhirProof, open: Option<&CarrierWhirProof>| -> Result<(Vec<Instr>, Vec<[Fa4; ND]>, usize), String> {
            let mut asm = Asm::new();
            asm.observe_root(&commitment.as_ref()[0], 0);
            for mc in &o.hvzk_mask_commits {
                asm.observe(&mc.as_ref()[0]);
            }
            for &e in &o.initial_ood_answers {
                asm.challenge_into(12);
                asm.observe_ext(e, None);
            }
            asm.observe_ext(evals[0], None);
            asm.challenge_into(12);
            asm.units(Asm::mul_k(crate::isa::SrcA::One, claimed, None, 0), None);
            emit_whir_verify(&mut asm, &pcs.config, open, 0, &mut |a: &mut Asm, _coords: &[u8], out: u8| {
                a.units(Asm::mul_k(crate::isa::SrcA::One, w_init, None, out), None);
            })?;
            let end = asm.len();
            let (p, d) = asm.finish();
            Ok((p, d, end))
        };
        let (prog, d, end) = build(&open, Some(&open)).expect("the program lays");
        let (shape_only, _, _) = build(&open, None).expect("the program lays with no proof");
        assert!(shape_only == prog, "⛔ the program laid with no proof is not the program laid with one");
        let (cols, _io) = execute(&prog, &d, 8).unwrap_or_else(|e: ExecError| panic!("⛔ the honest opening does not run: row {} of {} — {}", e.row, prog.len(), e.why));
        for (k, want) in want_coords.iter().enumerate() {
            assert_eq!(reg(&cols, COORDS + k as u8, end), *want, "⛔ folding coordinate {k} is not the native verifier's");
        }
        println!("[agg-c8] the whole verifier: {} rows (T = {})", prog.len(), cols[0].len());
        // the lies: each refused natively AND by the program
        let mut lies: Vec<(&str, CarrierWhirProof)> = Vec::new();
        let mut l = open.clone();
        if let Some(fp) = l.final_poly.as_mut() {
            let mut v = fp.as_slice().to_vec();
            v[1] += Ea4::ONE;
            *fp = Poly::new(v);
        }
        lies.push(("a moved final-polynomial coefficient", l));
        if !open.rounds.is_empty() {
            let mut l = open.clone();
            l.rounds[0].ood_answers[0] += Ea4::ONE;
            lies.push(("a moved out-of-domain answer", l));
            let mut l = open.clone();
            if let Some(p3_whir::pcs::proof::QueryOpening::Base { values, .. }) = l.rounds[0].queries.get_mut(0) {
                values[0] += Fa4::ONE;
            }
            lies.push(("a moved leaf value", l));
        }
        let mut l = open.clone();
        l.initial_sumcheck.polynomial_evaluations[0][0] += Ea4::ONE;
        lies.push(("a moved sumcheck evaluation", l));
        for (what, lie) in lies {
            assert!(native(&lie).is_err(), "CALIBRATION: the native verifier refuses {what}");
            let refused = match build(&lie, Some(&lie)) {
                Err(_) => true,
                Ok((p, d, _)) => execute(&p, &d, 8).is_err(),
            };
            assert!(refused, "⛔ the program ran {what}");
        }
    }

    /// ⭐ LAYER 5's PIN — the closing check's weights ARE `select_poly` and `eq_poly` of an expanded point. For local points
    /// of 1, 3, 8 and 24 coordinates (the stacked arity reaches 24, the coordinates held in `X[23..47]`), a query point
    /// `g^index` and an out-of-domain `y`: the program's weights equal `Point::select_poly(var)` and
    /// `Point::expand_from_univariate(y, n).eq_poly(local)` computed by the native code. A moved coordinate changes both.
    #[test]
    fn c7_the_closing_weights_are_select_poly_and_eq_poly() {
        use crate::verify_whir::{eq_weight, select_weight, WeightRegs};
        let mut seed: u64 = 0xC7_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let w = WeightRegs { point: 0, out: 1, a: 2, b: 3, c: 4, t: 5 };
        for n in [1usize, 3, 8, 24] {
            let coords: Vec<Ea4> = (0..n).map(|_| ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)))).collect();
            let regs: Vec<u8> = (23..23 + n as u8).collect();
            let var = Fa4::two_adic_generator(20).exp_u64(next() % (1 << 20));
            let y = ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)));
            let local = Point::new(coords.clone());
            let want_sel = local.select_poly(var);
            let want_eq = Point::expand_from_univariate(y, n).eq_poly(&local);
            let run = |coords: &[Ea4]| {
                let mut asm = Asm::new();
                asm.observe(&[Fa4::ZERO; RATE]);
                for (r, c) in regs.iter().zip(coords) {
                    asm.units(Asm::mul_k(crate::isa::SrcA::One, *c, None, *r), None);
                }
                asm.units(Asm::mul_k(crate::isa::SrcA::One, Ea4::from(var), None, w.point), None);
                select_weight(&mut asm, &regs, w);
                let sel_row = asm.len();
                asm.units(Asm::mul_add(crate::isa::SrcA::One, crate::isa::SrcB::X(w.out), None, 10), Asm::mul_k(crate::isa::SrcA::One, y, None, w.point));
                eq_weight(&mut asm, &regs, w);
                let eq_row = asm.len();
                let (prog, d) = asm.finish();
                let (cols, _io) = execute(&prog, &d, 8).expect("the weights run");
                (reg(&cols, w.out, sel_row), reg(&cols, w.out, eq_row))
            };
            let (sel, eq) = run(&coords);
            assert_eq!(sel, want_sel, "⛔ n = {n}: the program's select weight is not select_poly");
            assert_eq!(eq, want_eq, "⛔ n = {n}: the program's eq weight is not eq_poly of the expanded point");
            let mut moved = coords.clone();
            moved[n / 2] += Ea4::ONE;
            let (s2, e2) = run(&moved);
            assert!(s2 != want_sel && e2 != want_eq, "⛔ n = {n}: a moved coordinate left a weight unchanged");
        }
    }

    /// ⭐ LAYER 4's PIN — the final polynomial's check IS `SelectStatement::verify`. For 2, 4, 8 and 32 coefficients:
    /// the coefficients absorbed (tied to their sponge, digest latched), then five queries at points `g^index` whose
    /// folds are the polynomial there (computed here as Σ c_i z^i, the formula select.rs:295 evaluates by Horner) run;
    /// the lies cannot run: a fold off by one, a coefficient moved in ONE query's re-stream (the digest), and an inverse
    /// that is not `z`'s.
    #[test]
    fn c6_the_final_polynomial_check_is_select_statement_verify() {
        use crate::verify_whir::{absorb_final_poly, final_poly_check, FinalRegs};
        let mut seed: u64 = 0xC6_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let r = FinalRegs { w: 0, w2: 1, acc: 2, t: 3, s: 4, pw: 5, sq: 6, neg: 7 };
        let g = Fa4::two_adic_generator(10);
        for n in [2usize, 4, 8, 32] {
            let coeffs: Vec<Ea4> = (0..n).map(|_| ea(&core::array::from_fn::<Fa4, 4, _>(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)))).collect();
            let points: Vec<Fa4> = (0..5).map(|_| g.exp_u64(next() % 1024)).collect();
            let eval = |z: Fa4| -> Ea4 { coeffs.iter().rev().fold(Ea4::ZERO, |acc, c| acc * Ea4::from(z) + *c) };
            // `bad` = (query, what): 0 none, 1 fold off by one, 2 a moved coefficient in this query's re-stream
            let build = |bad: Option<(usize, u8)>| {
                let mut asm = Asm::new();
                asm.observe(&[Fa4::ZERO; RATE]); // the program opens with a word; the coefficients then start on a boundary
                absorb_final_poly(&mut asm, &coeffs, 1);
                for (q, z) in points.iter().enumerate() {
                    let mut fold = eval(*z);
                    let mut cs = coeffs.clone();
                    match bad {
                        Some((bq, 1)) if bq == q => fold += Ea4::ONE,
                        Some((bq, 2)) if bq == q => cs[n / 2] += Ea4::ONE,
                        _ => {}
                    }
                    asm.units(Asm::mul_k(crate::isa::SrcA::One, fold, None, 10), Asm::mul_k(crate::isa::SrcA::One, Ea4::from(*z), None, 11));
                    final_poly_check(&mut asm, &cs, 1, 10, 11, *z, r);
                }
                asm.finish()
            };
            let (prog, d) = build(None);
            let _ = execute(&prog, &d, 8).unwrap_or_else(|e: ExecError| panic!("⛔ n = {n}: the honest final check does not run: row {} — {}", e.row, e.why));
            println!("[agg-c6] n = {n}: {} rows for the absorb and five final queries", prog.len());
            for what in [1u8, 2] {
                let (p, d) = build(Some((2, what)));
                assert!(execute(&p, &d, 8).is_err(), "⛔ n = {n}: lie {what} ran");
            }
            // an inverse that is not z's: move the stream word of the first check's first row
            let (p, mut d) = build(None);
            let row = p.iter().position(|i| i.alu[1].is_some_and(|a| a.zero)).expect("the inverse's assertion");
            d[row][0] += Fa4::ONE;
            assert!(execute(&p, &d, 8).is_err(), "⛔ n = {n}: a false inverse ran");
        }
    }
}

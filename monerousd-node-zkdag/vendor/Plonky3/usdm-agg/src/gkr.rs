// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE MEMORY ARGUMENT'S SUM, BY GKR (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13). BORROWED: Papini–Haböck 2023,
//! "Improving logarithmic derivative lookups using GKR" (the fractional-sum circuit), on Thaler's GKR layer sumcheck.
//!
//! The SSA row's memory is a logUp balance: every read and every write is a fraction `p / q` with `q = ρ − (addr + β·v)`
//! and `p` the term's signed multiplicity, and the program is honest iff `Σ p/q` equals the public values' sum. The sum is
//! proven by a binary tree of fraction additions `(p_a, q_a) + (p_b, q_b) = (p_a·q_b + p_b·q_a, q_a·q_b)`, layer by layer
//! from the root: layer `k` holds `2^k` fractions, entry `j`'s children are `2j` and `2j + 1` at layer `k + 1`, so a
//! layer's point is its parent's sumcheck point with the child bit appended LAST (big-endian, the crate's MLE order). No
//! helper column is committed: the leaves are functions of the committed trace and the preprocessed program, so the last
//! layer's claim `(p̃(x*), q̃(x*))` reduces to column openings at the row part of `x*` — one commitment carries it.
//!
//! PROTOCOL (prover sends, verifier draws), on the door's own challenger after the trace commitment:
//! 1. the root `(P₀, Q₀)` is absorbed;
//! 2. per layer `k = 0 … L−1`, with claims `(p̃_k(z), q̃_k(z))` at `z ∈ F^k`: draw `λ`; the claim
//!    `p̃_k(z) + λ·q̃_k(z) = Σ_b eq(z, b)·[P(b,0)·Q(b,1) + P(b,1)·Q(b,0) + λ·Q(b,0)·Q(b,1)]` (P, Q of layer `k + 1`) is
//!    reduced by a sumcheck over `b` (`k` rounds, degree 3; each round sends `g(0), g(2), g(3)`, `g(1) = claim − g(0)`;
//!    the coordinates are bound first to last); then the four values `P(b*,0), P(b*,1), Q(b*,0), Q(b*,1)` are absorbed and
//!    checked against the last round's claim with `eq(z, b*)`; draw `c`: the next claims are the lines through them at `c`
//!    at the point `(b*, c)`.
//!
//! SOUNDNESS: the standard GKR bound, `Σ_k (3k + 2)/|F|` with `|F| = |Ea4| ≈ 2^124` (L ≤ 32: below 2^−113), plus logUp's
//! `(terms)/|F|` for the balance. AI RESISTANT: (a) — every value is checked by the verifier's own arithmetic.
//! SAFE AT SCALE: `L(L − 1)/2` rounds for `2^L` fractions; nothing grows with height, nodes or notes.

use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};
use usdm_decider::hiding_decider::{Ea4, Fa4};

/// One layer's reduction: its sumcheck rounds (`g(0), g(2), g(3)` each) and the four child values at the end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GkrLayer {
    pub rounds: Vec<[Ea4; 3]>,
    pub ends: [Ea4; 4],
}

/// A fractional-sum proof over `2^L` leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GkrProof {
    pub root: [Ea4; 2],
    pub layers: Vec<GkrLayer>,
}

/// What the verifier learns: the root fraction and the leaf layer's claims at the point `x*` (`L` coordinates).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkrClaims {
    pub root: [Ea4; 2],
    pub point: Vec<Ea4>,
    pub p: Ea4,
    pub q: Ea4,
}

fn observe_ext<Ch: FieldChallenger<Fa4>>(ch: &mut Ch, v: Ea4) {
    ch.observe_algebra_element(v);
}

fn sample_ext<Ch: FieldChallenger<Fa4>>(ch: &mut Ch) -> Ea4 {
    ch.sample_algebra_element()
}

/// `g(t)` from `g(0), g(1), g(2), g(3)` at any `t` (Newton forward differences on the nodes 0..3).
#[must_use]
pub fn cubic_at(g: [Ea4; 4], t: Ea4) -> Ea4 {
    let d1 = [g[1] - g[0], g[2] - g[1], g[3] - g[2]];
    let d2 = [d1[1] - d1[0], d1[2] - d1[1]];
    let d3 = d2[1] - d2[0];
    let two = Ea4::from(Fa4::TWO);
    let six = Ea4::from(Fa4::from_u64(6));
    // g(0) + t·Δ + t(t−1)/2·Δ² + t(t−1)(t−2)/6·Δ³
    let t1 = t - Ea4::ONE;
    let t2 = t - two;
    g[0] + t * d1[0] + t * t1 * d2[0] * two.inverse() + t * t1 * t2 * d3 * six.inverse()
}

/// `eq(a, b) = Π (aᵢ·bᵢ + (1 − aᵢ)(1 − bᵢ))`.
#[must_use]
pub fn eq_at(a: &[Ea4], b: &[Ea4]) -> Ea4 {
    a.iter().zip(b).fold(Ea4::ONE, |acc, (x, y)| acc * (*x * *y + (Ea4::ONE - *x) * (Ea4::ONE - *y)))
}

/// The table `eq(z, b)` over `b ∈ {0,1}^k`, `b` big-endian (index bit `k−1−i` is coordinate `i`).
#[must_use]
pub fn eq_table(z: &[Ea4]) -> Vec<Ea4> {
    let mut t = vec![Ea4::ONE];
    for &zi in z {
        let mut n = Vec::with_capacity(t.len() * 2);
        for &e in &t {
            n.push(e * (Ea4::ONE - zi));
            n.push(e * zi);
        }
        t = n;
    }
    t
}

/// The layers of the fraction tree, root first: `layers[k] = (P_k, Q_k)`, `2^k` entries each.
fn build_layers(p: Vec<Ea4>, q: Vec<Ea4>) -> Vec<(Vec<Ea4>, Vec<Ea4>)> {
    let mut layers = vec![(p, q)];
    while layers.last().expect("a layer").0.len() > 1 {
        let (lp, lq) = layers.last().expect("a layer");
        let n = lp.len() / 2;
        let mut np = Vec::with_capacity(n);
        let mut nq = Vec::with_capacity(n);
        for j in 0..n {
            np.push(lp[2 * j] * lq[2 * j + 1] + lp[2 * j + 1] * lq[2 * j]);
            nq.push(lq[2 * j] * lq[2 * j + 1]);
        }
        layers.push((np, nq));
    }
    layers.reverse();
    layers
}

/// PROVE `Σ p_i / q_i` over `2^L` leaves (`p.len() == q.len()`, a power of two, at least 2). Returns the proof and the
/// leaf-layer claims the verifier will hold.
#[must_use]
pub fn prove<Ch: FieldChallenger<Fa4>>(p: Vec<Ea4>, q: Vec<Ea4>, ch: &mut Ch) -> Option<(GkrProof, GkrClaims)> {
    let n = p.len();
    if n < 2 || !n.is_power_of_two() || q.len() != n {
        return None;
    }
    let l = n.trailing_zeros() as usize;
    let layers = build_layers(p, q);
    let root = [layers[0].0[0], layers[0].1[0]];
    observe_ext(ch, root[0]);
    observe_ext(ch, root[1]);
    let mut z: Vec<Ea4> = Vec::new();
    let (mut cp, mut cq) = (root[0], root[1]);
    let mut out_layers = Vec::with_capacity(l);
    for k in 0..l {
        let lambda = sample_ext(ch);
        let (np, nq) = &layers[k + 1];
        // children split: P(b,0) = np[2b], P(b,1) = np[2b+1]
        let half = np.len() / 2;
        let mut a0: Vec<Ea4> = (0..half).map(|b| np[2 * b]).collect();
        let mut a1: Vec<Ea4> = (0..half).map(|b| np[2 * b + 1]).collect();
        let mut b0: Vec<Ea4> = (0..half).map(|b| nq[2 * b]).collect();
        let mut b1: Vec<Ea4> = (0..half).map(|b| nq[2 * b + 1]).collect();
        let mut e = eq_table(&z);
        let mut claim = cp + lambda * cq;
        let mut rounds = Vec::with_capacity(k);
        let mut bstar = Vec::with_capacity(k);
        for _ in 0..k {
            let h = e.len() / 2;
            let mut g = [Ea4::ZERO; 4];
            for i in 0..h {
                let line = |v: &[Ea4], t: Ea4| v[i] + t * (v[i + h] - v[i]);
                for (ti, gt) in g.iter_mut().enumerate() {
                    let t = Ea4::from(Fa4::from_u64(ti as u64));
                    let (ee, x0, x1, y0, y1) = (line(&e, t), line(&a0, t), line(&a1, t), line(&b0, t), line(&b1, t));
                    *gt += ee * (x0 * y1 + x1 * y0 + lambda * y0 * y1);
                }
            }
            debug_assert_eq!(g[0] + g[1], claim, "a GKR round's sum is the claim");
            let sent = [g[0], g[2], g[3]];
            for v in sent {
                observe_ext(ch, v);
            }
            let r = sample_ext(ch);
            claim = cubic_at(g, r);
            let fold = |v: &mut Vec<Ea4>| {
                let hh = v.len() / 2;
                let nv: Vec<Ea4> = (0..hh).map(|i| v[i] + r * (v[i + hh] - v[i])).collect();
                *v = nv;
            };
            fold(&mut e);
            fold(&mut a0);
            fold(&mut a1);
            fold(&mut b0);
            fold(&mut b1);
            rounds.push(sent);
            bstar.push(r);
        }
        let ends = [a0[0], a1[0], b0[0], b1[0]];
        debug_assert_eq!(e[0] * (ends[0] * ends[3] + ends[1] * ends[2] + lambda * ends[2] * ends[3]), claim);
        for v in ends {
            observe_ext(ch, v);
        }
        let c = sample_ext(ch);
        cp = ends[0] + c * (ends[1] - ends[0]);
        cq = ends[2] + c * (ends[3] - ends[2]);
        bstar.push(c);
        z = bstar;
        out_layers.push(GkrLayer { rounds, ends });
    }
    Some((GkrProof { root, layers: out_layers }, GkrClaims { root, point: z, p: cp, q: cq }))
}

/// VERIFY a fractional-sum proof over `2^l` leaves: every layer's sumcheck and end check. Returns the root and the
/// leaf-layer claims the caller must check against the trace (and the root against the statement). `None` on any
/// failed check or a proof of another shape.
#[must_use]
pub fn verify<Ch: FieldChallenger<Fa4>>(proof: &GkrProof, l: usize, ch: &mut Ch) -> Option<GkrClaims> {
    if l == 0 || proof.layers.len() != l || proof.layers.iter().enumerate().any(|(k, ly)| ly.rounds.len() != k) {
        return None;
    }
    observe_ext(ch, proof.root[0]);
    observe_ext(ch, proof.root[1]);
    let mut z: Vec<Ea4> = Vec::new();
    let (mut cp, mut cq) = (proof.root[0], proof.root[1]);
    for ly in &proof.layers {
        let lambda = sample_ext(ch);
        let mut claim = cp + lambda * cq;
        let mut bstar = Vec::with_capacity(z.len() + 1);
        for sent in &ly.rounds {
            for v in sent {
                observe_ext(ch, *v);
            }
            let r = sample_ext(ch);
            let g = [sent[0], claim - sent[0], sent[1], sent[2]];
            claim = cubic_at(g, r);
            bstar.push(r);
        }
        let [p0, p1, q0, q1] = ly.ends;
        if eq_at(&z, &bstar) * (p0 * q1 + p1 * q0 + lambda * q0 * q1) != claim {
            return None;
        }
        for v in ly.ends {
            observe_ext(ch, v);
        }
        let c = sample_ext(ch);
        cp = p0 + c * (p1 - p0);
        cq = q0 + c * (q1 - q0);
        bstar.push(c);
        z = bstar;
    }
    Some(GkrClaims { root: proof.root, point: z, p: cp, q: cq })
}

/// The multilinear extension of `v` (length `2^n`, big-endian index bits) at `x`.
#[must_use]
pub fn mle_at(v: &[Ea4], x: &[Ea4]) -> Ea4 {
    debug_assert_eq!(v.len(), 1 << x.len());
    let mut cur = v.to_vec();
    for &xi in x {
        let h = cur.len() / 2;
        cur = (0..h).map(|i| cur[i] + xi * (cur[i + h] - cur[i])).collect();
    }
    cur[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;
    use usdm_decider::hiding_decider::{Chl, Perm16};

    fn chl() -> Chl {
        let mut rng = SmallRng::seed_from_u64(usdm_decider::committed_air::COMMITTED_AIR_SEED);
        Chl::new(Perm16::new_from_rng_128(&mut rng))
    }

    fn rnd(seed: &mut u64) -> Ea4 {
        use p3_field::BasedVectorSpace;
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let s = *seed;
        let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((s >> (9 * i)) % 2_130_706_433));
        Ea4::from_basis_coefficients_slice(&l).expect("limbs")
    }

    /// ⭐ THE GKR PIN — a fractional sum is proven and verified, the root IS the sum, and the leaf claims ARE the leaves'
    /// multilinear extensions at the point the transcript drew. Then the lies, each refused: a moved round value, a moved
    /// end value, a moved root; and a moved LEAF (the proof re-made honestly over it) changes the leaf claim, which is what
    /// the door checks against the trace.
    #[test]
    fn g1_a_fraction_sum_is_proven_and_its_leaf_claims_are_the_leaves() {
        let mut seed = 0x61_5EEDu64;
        for l in [1usize, 2, 5, 9] {
            let n = 1usize << l;
            let p: Vec<Ea4> = (0..n).map(|_| rnd(&mut seed)).collect();
            let q: Vec<Ea4> = (0..n).map(|_| rnd(&mut seed)).collect();
            let (proof, claims) = prove(p.clone(), q.clone(), &mut chl()).expect("proves");
            let v = verify(&proof, l, &mut chl()).expect("⛔ the honest proof is refused");
            assert_eq!(v, claims, "⛔ the verifier's claims are not the prover's");
            let sum: Ea4 = p.iter().zip(&q).map(|(a, b)| *a * b.inverse()).sum();
            assert_eq!(v.root[0] * v.root[1].inverse(), sum, "⛔ l = {l}: the root fraction is not the sum");
            assert_eq!(mle_at(&p, &v.point), v.p, "⛔ l = {l}: the leaf claim p̃(x*) is not the leaves' MLE");
            assert_eq!(mle_at(&q, &v.point), v.q, "⛔ l = {l}: the leaf claim q̃(x*) is not the leaves' MLE");
            // lies
            if l >= 2 {
                let mut bad = proof.clone();
                bad.layers[l - 1].rounds[0][1] += Ea4::ONE;
                assert!(verify(&bad, l, &mut chl()).is_none_or(|c| c.p != mle_at(&p, &c.point) || c.q != mle_at(&q, &c.point)), "⛔ a moved round value passed");
            }
            let mut bad = proof.clone();
            bad.layers[l - 1].ends[2] += Ea4::ONE;
            assert!(verify(&bad, l, &mut chl()).is_none(), "⛔ l = {l}: a moved end value passed");
            let mut bad = proof.clone();
            bad.root[0] += Ea4::ONE;
            assert!(verify(&bad, l, &mut chl()).is_none(), "⛔ l = {l}: a moved root passed");
            let mut p2 = p.clone();
            p2[n / 3] += Ea4::ONE;
            let (proof2, _) = prove(p2.clone(), q.clone(), &mut chl()).expect("proves");
            let v2 = verify(&proof2, l, &mut chl()).expect("an honest proof over moved leaves verifies");
            assert_ne!(v2.p, mle_at(&p, &v2.point), "⛔ l = {l}: a moved leaf left the leaf claim equal to the honest leaves'");
        }
    }
}

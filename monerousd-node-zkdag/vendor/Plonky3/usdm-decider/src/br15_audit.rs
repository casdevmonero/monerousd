// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ §BR-15 (spec §18.8) — THE AUDITED CLEARING'S PROOF COST, MEASURED BEFORE THE CIRCUITS ARE CHOSEN.
//!
//! The audited clearing proves each custodian's LOCAL steps of the honest-majority computation with an ordinary
//! single-prover proof on the decider's R1CS argument (`spartan_ccs::prove_committed`). What that costs per
//! constraint decides the shape of everything above it (which field the shares live in, how many comparisons a batch may
//! run), so it is measured here at two scales — a constant and a slope are told apart by two scales, never one.

use crate::hiding_decider::{Ea4, Fa4};
use crate::spartan_gadgets::{Lc, R1csBuilder};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// The audited share field's limbs: 22 limbs of 12 bits (264 bits). A limb product is below 2^24 and a column of 22 of them
/// below 2^28.5. Whether a column identity can wrap KoalaBear (≈ 2^31) depends on its carry too: [`plan_reduction`] sizes
/// every carry so it cannot (finding A-F71).
pub const LIMB_BITS: usize = 12;
pub const LIMBS: usize = 22;
/// A value in reduced form is below 2^256: its top limb carries `256 − 21·12 = 4` bits.
const TOP_BITS: usize = 256 - (LIMBS - 1) * LIMB_BITS;

/// 2^255 − 19, little-endian 64-bit words.
pub const P255_WORDS: [u64; 4] = [0xFFFF_FFFF_FFFF_FFED, u64::MAX, u64::MAX, 0x7FFF_FFFF_FFFF_FFFF];

type Big = [u64; 9];

fn big_from(w: &[u64]) -> Big {
    let mut b = [0u64; 9];
    b[..w.len()].copy_from_slice(w);
    b
}
fn big_mul(a: &[u64; 4], b: &[u64; 4]) -> Big {
    let mut w = [0u128; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = w[i + j] + u128::from(a[i]) * u128::from(b[j]) + carry;
            w[i + j] = cur & u128::from(u64::MAX);
            carry = cur >> 64;
        }
        w[i + 4] += carry;
    }
    core::array::from_fn(|i| w[i] as u64)
}
fn big_add(a: &Big, b: &Big) -> Big {
    let mut out = [0u64; 9];
    let mut c = 0u64;
    for i in 0..9 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(c);
        out[i] = s;
        c = u64::from(c1 || c2);
    }
    out
}
fn big_sub(a: &Big, b: &Big) -> Big {
    let mut out = [0u64; 9];
    let mut br = 0u64;
    for i in 0..9 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(br);
        out[i] = d;
        br = u64::from(b1 || b2);
    }
    out
}
fn big_geq(a: &Big, b: &Big) -> bool {
    for i in (0..9).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}
fn big_mul_small(a: &Big, k: u64) -> Big {
    let mut out = [0u64; 9];
    let mut c = 0u128;
    for i in 0..9 {
        let cur = u128::from(a[i]) * u128::from(k) + c;
        out[i] = cur as u64;
        c = cur >> 64;
    }
    out
}
/// `x >> 255` and `x mod 2^255`.
fn big_split255(x: &Big) -> (Big, Big) {
    let mut hi = [0u64; 9];
    for i in 0..5 {
        hi[i] = (x[i + 3] >> 63) | (x[i + 4] << 1);
    }
    hi[5] = x[8] >> 63;
    let mut lo = [0u64; 9];
    lo[..4].copy_from_slice(&x[..4]);
    lo[3] &= u64::MAX >> 1;
    (hi, lo)
}
/// `(⌊x / P⌋, x mod P)` for `x < 2^520`: P = 2^255 − 19, so x = q₀·P + (lo + 19·q₀) with q₀ = x >> 255, then a few subtractions.
fn big_divmod_p(x: &Big) -> (Big, Big) {
    let p = big_from(&P255_WORDS);
    let (mut q, lo) = big_split255(x);
    let mut r = big_add(&lo, &big_mul_small(&q, 19));
    while big_geq(&r, &p) {
        r = big_sub(&r, &p);
        q = big_add(&q, &big_from(&[1]));
    }
    (q, r)
}
fn limbs_of(x: &Big) -> [u64; LIMBS] {
    let v = limbs_of_n(x, LIMBS);
    core::array::from_fn(|i| v[i])
}
/// The first `n` 12-bit limbs of `x` (a 576-bit integer has 48).
fn limbs_of_n(x: &Big, n: usize) -> Vec<u64> {
    (0..n).map(|i| {
        let bit = i * LIMB_BITS;
        let (w, o) = (bit / 64, bit % 64);
        let mut v = x[w] >> o;
        if o + LIMB_BITS > 64 && w + 1 < 9 {
            v |= x[w + 1] << (64 - o);
        }
        v & ((1 << LIMB_BITS) - 1)
    }).collect()
}
fn words_of_limbs(l: &[u64; LIMBS]) -> [u64; 4] {
    let mut w = [0u64; 5];
    for (i, v) in l.iter().enumerate() {
        let bit = i * LIMB_BITS;
        let (k, o) = (bit / 64, bit % 64);
        w[k] |= v << o;
        if o + LIMB_BITS > 64 {
            w[k + 1] |= v >> (64 - o);
        }
    }
    [w[0], w[1], w[2], w[3]]
}

/// ⭐ A share-field element inside the audit circuit: 22 range-checked 12-bit limbs (reduced form: below 2^256).
#[derive(Clone, Debug)]
pub struct Nn(pub Vec<Lc>);

/// A value `v` of `bits` bits as a wire: its bits allocated and squared to themselves, the wire their weighted sum.
fn range_wire(b: &mut R1csBuilder, v: u64, bits: usize) -> Lc {
    let mut acc = Lc::constant(Fa4::ZERO);
    for i in 0..bits {
        let w = b.witness(Fa4::from_u64((v >> i) & 1));
        b.constrain(&w, &w, &w);
        acc = acc.add(&w.scale(Fa4::from_u64(1 << i)));
    }
    acc
}

impl Nn {
    /// Allocate `x` (four 64-bit words, below 2^256) as range-checked limbs.
    pub fn alloc(b: &mut R1csBuilder, x: &[u64; 4]) -> Nn {
        let l = limbs_of(&big_from(x));
        Nn((0..LIMBS).map(|i| range_wire(b, l[i], if i == LIMBS - 1 { TOP_BITS } else { LIMB_BITS })).collect())
    }
    /// The value this element holds under the builder's assignment.
    #[must_use]
    pub fn value(&self, b: &R1csBuilder) -> [u64; 4] {
        let l: [u64; LIMBS] = core::array::from_fn(|i| b.value_of(&self.0[i]).as_canonical_u64());
        words_of_limbs(&l)
    }
    /// ⭐ `self · other ≡ r (mod 2^255 − 19)`: 484 limb products laid as 43 columns, then [`reduce_columns`]. MEASURED by
    /// `br15_the_share_field_multiplication_gadget_is_sound`.
    pub fn mul(&self, other: &Nn, b: &mut R1csBuilder) -> Nn {
        let (al, bl) = (limbs_of(&big_from(&self.value(b))), limbs_of(&big_from(&other.value(b))));
        let mut cols: Vec<(Lc, i128)> = vec![(Lc::constant(Fa4::ZERO), 0); 2 * LIMBS - 1];
        let mut mags = vec![0u128; 2 * LIMBS - 1];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                let pij = b.mul(&self.0[i], &other.0[j]);
                cols[i + j].0 = cols[i + j].0.add(&pij);
                cols[i + j].1 += i128::from(al[i]) * i128::from(bl[j]);
                mags[i + j] += LIMB_MAX * LIMB_MAX;
            }
        }
        reduce_columns(b, cols, &mags, 0, &big_mul(&NN_MAX, &NN_MAX))
    }
    /// ⭐ `self² − self (mod 2^255 − 19)` — the bit check's term (`b_k − b_k²` is its negation): 253 limb products (each
    /// off-diagonal pair once, doubled), the element's own limbs subtracted in the same columns, ONE reduction. `x² − x ≥ 0`
    /// for every integer `x ≥ 0`, so no offset is needed. What `mul` then `lin` computed in 484 products and two reductions.
    pub fn square_minus_self(&self, b: &mut R1csBuilder) -> Nn {
        let al = limbs_of(&big_from(&self.value(b)));
        let mut cols: Vec<(Lc, i128)> = vec![(Lc::constant(Fa4::ZERO), 0); 2 * LIMBS - 1];
        let mut mags = vec![0u128; 2 * LIMBS - 1];
        for i in 0..LIMBS {
            for j in i..LIMBS {
                let k2: u64 = if i == j { 1 } else { 2 };
                let pij = b.mul(&self.0[i], &self.0[j]);
                cols[i + j].0 = cols[i + j].0.add(&pij.scale(Fa4::from_u64(k2)));
                cols[i + j].1 += i128::from(k2) * i128::from(al[i]) * i128::from(al[j]);
                mags[i + j] += u128::from(k2) * LIMB_MAX * LIMB_MAX;
            }
        }
        for k in 0..LIMBS {
            cols[k].0 = cols[k].0.add(&self.0[k].scale(Fa4::ZERO - Fa4::ONE));
            cols[k].1 -= i128::from(al[k]);
            mags[k] += LIMB_MAX;
        }
        reduce_columns(b, cols, &mags, 0, &big_mul(&NN_MAX, &NN_MAX))
    }
    /// `self + other (mod p)`: linear columns, then the reduction (no limb product).
    pub fn add(&self, other: &Nn, b: &mut R1csBuilder) -> Nn {
        self.lin(&[(other, 1)], 1, b)
    }
    /// `self − other (mod p)` (a multiple of p is added so the reduced value is non-negative).
    pub fn sub(&self, other: &Nn, b: &mut R1csBuilder) -> Nn {
        self.lin(&[(other, -1)], 1, b)
    }
    /// `c_self·self + Σ c_i·x_i (mod p)` for small signed integer coefficients (|c| < 2^12): linear columns, one reduction.
    pub fn lin(&self, terms: &[(&Nn, i64)], c_self: i64, b: &mut R1csBuilder) -> Nn {
        let mut cols: Vec<(Lc, i128)> = vec![(Lc::constant(Fa4::ZERO), 0); LIMBS];
        let mut push = |x: &Nn, c: i64, b: &R1csBuilder| {
            let xl = limbs_of(&big_from(&x.value(b)));
            for k in 0..LIMBS {
                cols[k].0 = cols[k].0.add(&x.0[k].scale(signed(c)));
                cols[k].1 += i128::from(c) * i128::from(xl[k]);
            }
        };
        push(self, c_self, b);
        for (x, c) in terms {
            push(x, *c, b);
        }
        let coefs = || std::iter::once(c_self).chain(terms.iter().map(|t| t.1));
        let neg: i64 = coefs().filter(|c| *c < 0).map(|c| -c).sum();
        let pos: u64 = coefs().filter(|c| *c > 0).map(|c| c as u64).sum();
        let abs: u128 = coefs().map(|c| u128::from(c.unsigned_abs())).sum();
        let mags = vec![abs * LIMB_MAX; LIMBS];
        reduce_columns(b, cols, &mags, u64::try_from(neg).unwrap_or(0) * 2 + 2, &big_mul_small(&big_from(&NN_MAX), pos))
    }
    /// `c · self (mod p)` for a PUBLIC constant c (below 2^256): the limb convolution with constant coefficients is linear — no
    /// limb product — then one reduction. The custodians' `ΣY·D_t − ΣX·N_t` is two of these and a `sub`.
    pub fn scale_const(&self, c: &[u64; 4], b: &mut R1csBuilder) -> Nn {
        let (xl, cl) = (limbs_of(&big_from(&self.value(b))), limbs_of(&big_from(c)));
        let mut cols: Vec<(Lc, i128)> = vec![(Lc::constant(Fa4::ZERO), 0); 2 * LIMBS - 1];
        let mut mags = vec![0u128; 2 * LIMBS - 1];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                if cl[j] != 0 {
                    cols[i + j].0 = cols[i + j].0.add(&self.0[i].scale(Fa4::from_u64(cl[j])));
                    cols[i + j].1 += i128::from(xl[i]) * i128::from(cl[j]);
                    mags[i + j] += LIMB_MAX * u128::from(cl[j]);
                }
            }
        }
        reduce_columns(b, cols, &mags, 0, &big_mul(&NN_MAX, c))
    }
    /// A public constant as an element (its limbs are constant wires: no allocation, no range bits).
    #[must_use]
    pub fn constant(c: &[u64; 4]) -> Nn {
        let l = limbs_of(&big_from(c));
        Nn(l.iter().map(|v| Lc::constant(Fa4::from_u64(*v))).collect())
    }
    /// Enforce `self ≡ other` for two REDUCED elements (each below 2^256 < 2p): their difference is 0 or ±p, so the limbs are
    /// compared after one reduction of the difference — `sub` then every limb of the result pinned to zero.
    pub fn enforce_eq(&self, other: &Nn, b: &mut R1csBuilder) {
        let d = self.sub(other, b);
        for l in &d.0 {
            b.enforce_eq(l, &Lc::constant(Fa4::ZERO));
        }
    }
}

/// The domain word of a share commitment's sponge (`"BR15CMT\0"` folded into the field).
const COMMIT_DOMAIN: u64 = 0x4252_3135 ^ 0x434D_5400;
/// The phase-1 digest's domain (`"PH2"`: its lanes pack two limbs; `"PH1"` was one limb a lane).
const PHASE1_DOMAIN: u64 = COMMIT_DOMAIN ^ 0x5048_3200;
const RATE: usize = 8;

/// ⭐ THE SHARE COMMITMENT, natively: a Poseidon2 sponge (the production permutation, rate 8) over the element's 22 limbs and a
/// 4-word salt, domain-separated; the first four lanes are the digest. What a sender publishes for a value it sends a party,
/// and what that party's audit proves it opened ([`Nn::commit`] is the same function inside the circuit).
#[must_use]
pub fn share_commit(x: &[u64; 4], salt: &[Fa4; 4]) -> [Fa4; 4] {
    use p3_symmetric::Permutation;
    let perm = crate::pow_pq_air::production_perm();
    let l = limbs_of(&big_from(x));
    let input: Vec<Fa4> = l.iter().map(|v| Fa4::from_u64(*v)).chain(salt.iter().copied()).collect();
    let mut st = [Fa4::ZERO; crate::pow_pq_air::WIDTH];
    st[crate::pow_pq_air::WIDTH - 1] = Fa4::from_u64(COMMIT_DOMAIN);
    for chunk in input.chunks(RATE) {
        for (i, v) in chunk.iter().enumerate() {
            st[i] += *v;
        }
        perm.permute_mut(&mut st);
    }
    [st[0], st[1], st[2], st[3]]
}

impl Nn {
    /// ⭐ The share commitment inside the circuit: the same sponge as [`share_commit`], on this element's limb wires and a
    /// salt witness; returns the digest wires. ≈ 4 permutations.
    pub fn commit(&self, salt: &[Lc; 4], b: &mut R1csBuilder) -> [Lc; 4] {
        let p2 = crate::spartan_gadgets::P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
        let input: Vec<Lc> = self.0.iter().cloned().chain(salt.iter().cloned()).collect();
        let mut st: [Lc; crate::pow_pq_air::WIDTH] = core::array::from_fn(|_| Lc::constant(Fa4::ZERO));
        st[crate::pow_pq_air::WIDTH - 1] = Lc::constant(Fa4::from_u64(COMMIT_DOMAIN));
        for chunk in input.chunks(RATE) {
            for (i, v) in chunk.iter().enumerate() {
                st[i] = st[i].add(v);
            }
            st = crate::spartan_gadgets::poseidon2_permutation(b, &p2, &st);
        }
        [st[0].clone(), st[1].clone(), st[2].clone(), st[3].clone()]
    }
}

// ───────────────────────────── the native share field (witness generation and the nodes' checks) ─────────────────────────────

/// An element of 2^255 − 19 as four words (always reduced below p).
pub type F = [u64; 4];

fn red4(x: &Big) -> F {
    let (_, r) = big_divmod_p(x);
    [r[0], r[1], r[2], r[3]]
}
/// `a + b mod p`.
#[must_use]
pub fn fadd(a: &F, b: &F) -> F {
    red4(&big_add(&big_from(a), &big_from(b)))
}
/// `a − b mod p`.
#[must_use]
pub fn fsub(a: &F, b: &F) -> F {
    red4(&big_sub(&big_add(&big_from(a), &big_from(&P255_WORDS)), &big_from(b)))
}
/// `a · b mod p`.
#[must_use]
pub fn fmul(a: &F, b: &F) -> F {
    red4(&big_mul(a, b))
}
/// The element of a small integer.
#[must_use]
pub fn fsmall(v: u64) -> F {
    [v, 0, 0, 0]
}
fn fpow(a: &F, e: &F) -> F {
    let mut r = fsmall(1);
    for i in (0..256).rev() {
        r = fmul(&r, &r);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = fmul(&r, a);
        }
    }
    r
}
/// `a⁻¹ mod p` (Fermat).
#[must_use]
pub fn finv(a: &F) -> F {
    let mut e = P255_WORDS;
    e[0] -= 2;
    fpow(a, &e)
}
/// `2^k` as an element.
#[must_use]
pub fn fpow2(k: usize) -> F {
    let mut w = [0u64; 4];
    w[k / 64] = 1 << (k % 64);
    w
}
/// Evaluate the polynomial with coefficients `c` (constant first) at the small point `x`.
#[must_use]
pub fn poly_eval(c: &[F], x: u64) -> F {
    c.iter().rev().fold(fsmall(0), |acc, k| fadd(&fmul(&acc, &fsmall(x)), k))
}

/// ⭐ THE NODES' CHECK ON A PUBLISHED SHARING: the n published shares (party i at x = i + 1) lie on ONE polynomial of degree
/// at most `deg`, and — when `zero` — its constant is 0. Interpolates through the first `deg + 1` points (Lagrange) and requires
/// every other point to agree. `false` for too few shares to check anything (`n ≤ deg + 1` proves nothing).
#[must_use]
pub fn sharing_holds(shares: &[F], deg: usize, zero: bool) -> bool {
    let n = shares.len();
    if n <= deg + 1 {
        return false;
    }
    let at = |x: u64| -> F {
        // Lagrange over x_i = i + 1, i ≤ deg
        let mut acc = fsmall(0);
        for i in 0..=deg {
            let xi = (i + 1) as u64;
            let mut num = fsmall(1);
            let mut den = fsmall(1);
            for j in 0..=deg {
                if j == i {
                    continue;
                }
                let xj = (j + 1) as u64;
                num = fmul(&num, &fsub(&fsmall(x), &fsmall(xj)));
                den = fmul(&den, &fsub(&fsmall(xi), &fsmall(xj)));
            }
            acc = fadd(&acc, &fmul(&shares[i], &fmul(&num, &finv(&den))));
        }
        acc
    };
    if zero && at(0) != fsmall(0) {
        return false;
    }
    (deg + 1..n).all(|i| at((i + 1) as u64) == shares[i])
}

// ───────────────────────────── the custodian audit circuit (spec §18.8) ─────────────────────────────

/// Every audited statement's width ([`statement_bits`]): each statement `z` lies in `[0, 2^bits)`. The tick pair's upper side
/// and the booking bounds lie below 2^92 (both sides below 2^88 on the clearing tick, each booking bound below 4·N ≤ 2^91). The
/// tick pair's LOWER side counts the buckets that would fill one tick down (spec §18.10), so it is bounded only by its sums —
/// below `2^65 · d ≤ 2^153` — and gets [`WIDE_BITS`]: no order at a bucket's edge can push an honest batch past its audit.
/// A false statement has no such bits.
pub const AUDIT_BITS: usize = 92;
/// The lower tick statement's width (see [`AUDIT_BITS`]).
pub const WIDE_BITS: usize = 156;
/// ⭐ EARN STEP 3 — THE NARROW STATEMENTS, each at the width its honest value needs over BOTH batch kinds at its index (a
/// narrower range proof is a STRICTER check — fewer `z` pass — so this changes no soundness; an honest `z` above its width
/// would only stop its batch settling, and none can be, by the bounds named):
/// - 8 and 9: a trading batch's `φ_s` truncation pair (`z < 2^16`) / an Earn batch's income booking pair (`Ψ` is the ceiling
///   of `(I·ΣWU − ΣWUI)/2^S`, so `z ∈ [0, 2^S)` and `4·2^S − 1 − z < 2^(S+2)`): [`INCOME_ROW_BITS`];
/// - 11, 12, 13: a trading batch's `φ_b` upper and `φ_d` pair (`z < 2^16`) / an Earn batch's empty rows (`0`): [`FEE_ROW_BITS`];
/// - 14 and 15: the merge's truncation pair (`z < 2^EARN_RATE_BITS`): [`MERGE_ROW_BITS`].
/// MEASURED why (lane vaults, 2026-11-15): one custodian's audit with the merge rows at 92 bits peaked at 6.56 GB in the
/// decider's pin and was killed by the machine's memory guard (6,144 MB a process); these cut the statements' bit columns
/// from 1,536 to 1,111.
pub const INCOME_ROW_BITS: usize = INCOME_SHIFT as usize + 3;
pub const FEE_ROW_BITS: usize = FEE_SHIFT as usize + 1;
pub const MERGE_ROW_BITS: usize = EARN_RATE_BITS as usize + 1;
/// Statement `si`'s width (the batch audit's; an EarnEpoch's two statements are its indices 0 and 1).
#[must_use]
pub fn statement_bits(si: usize) -> usize {
    match si {
        0 => WIDE_BITS,
        8 | 9 => INCOME_ROW_BITS,
        11..=13 => FEE_ROW_BITS,
        14 | 15 => MERGE_ROW_BITS,
        _ => AUDIT_BITS,
    }
}
/// Repetitions of each randomized check, each with 12-bit challenges: a false statement passes one with probability ≤ 2^-12,
/// all of them with ≤ 2^-132.
pub const AUDIT_REPS: usize = 11;
/// A challenge's width (small coefficients keep every column of a combination inside the native field).
pub const CHALLENGE_BITS: u32 = 12;
/// ⭐ THE ORDER'S MAXIMUM-PRICE BUCKETS (spec §18.10): a buy names one of [`ORDER_BUCKETS`] maximum prices over its batch's
/// opening tick (the node's `defi_clear::BUCKET_TICKS`: +2 %, +10 %, +50 %, none) and deals its amount on that bucket's Y line,
/// every other line a sharing of 0. Which buckets fill at a tick is public (the tick and the opening tick decide it), so the
/// custody set's demand at any tick is a LINEAR function of its shares — no comparison per order, no product per order.
pub const ORDER_BUCKETS: usize = 4;
/// ⭐ EARN STEP 2 — the provider's lines every order carries (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md, "Step 2, build
/// plan"): a SAT deposit's sold half ([`DEPOSIT_SOLD_LINE`], priced by the search as a sell), its other half
/// ([`DEPOSIT_JOIN_LINE`], joins the pool), a withdrawal's units ([`WITHDRAW_UNITS_LINE`]) and units × entry index
/// ([`WITHDRAW_INDEX_LINE`]). Every order deals every line (a sharing of 0 where it has nothing), so the shares never say
/// which kind an order is.
pub const EARN_LINES: usize = 4;
/// What an order's share commitment opens: its X line, one Y line per bucket, then the [`EARN_LINES`].
pub const ORDER_LINES: usize = 1 + ORDER_BUCKETS + EARN_LINES;
/// A deposit's sold half `⌊a/2⌋`.
pub const DEPOSIT_SOLD_LINE: usize = 1 + ORDER_BUCKETS;
/// A deposit's other half `a − ⌊a/2⌋`.
pub const DEPOSIT_JOIN_LINE: usize = DEPOSIT_SOLD_LINE + 1;
/// A withdrawal's units (Earn step 2, piece 3; a sharing of 0 until then).
pub const WITHDRAW_UNITS_LINE: usize = DEPOSIT_SOLD_LINE + 2;
/// A withdrawal's units × its position's entry index (Earn step 3's income; a sharing of 0 until then).
pub const WITHDRAW_INDEX_LINE: usize = DEPOSIT_SOLD_LINE + 3;
/// What a pool commitment opens: X, Y, and the two FLOORS `F_X`, `F_Y` (spec §18.10): the launch position's virtual depth,
/// which no batch may pay out — `X ≥ F_X` keeps the position's real SAT the only SAT it sells, `Y ≥ F_Y` keeps its virtual
/// USDm unpaid.
pub const POOL_LINES: usize = 4;
/// The committed values a statement is linear in, in this order: the pool's X and Y shares, the batch's sums ΔX, ΔY₁ and ΔY₂
/// (the Y lines of the buckets that FILL at the tick — the node names the same buckets for both since finding A-F46, when
/// ΔY₁'s buckets that fill one tick DOWN let a buy past its own cap set the sellers' price and refund), the booked outflows q_X (X paid to the
/// buyers) and q_Y (Y paid to the sellers), the pool's floors F_X, F_Y, and the batch's two fee bookings φ_s (out of the
/// sellers' ΔX) and φ_b (out of the buyers' q_X), both SAT, both to the fee line ([`FEE_NUM`]).
/// ⭐ Earn step 2 adds ΣDS (the deposits' sold halves: priced by the search as sells), ΣDX (their other halves: they join
/// the pool) and φ_d = ⌊ΣDS·f⌋ (the deposit-sells' own fee, to the fee line).
/// ⭐ Earn steps 2–3 add ΣWU (the withdrawals' units), ΣWUI (units × entry index), Ψ (the income booked out of the fee line),
/// then this custodian's FEE STATE (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md, "Step 3 REFUTED … the replacement"): the
/// backing B (what income is paid from), the open window's fresh fees E and sampled presence A, the CLOSED window's E_c and
/// A_c, and the merge's allocation `alloc = ⌊dG·2A_c / 2^EARN_RATE_BITS⌋` — ΣWU, ΣWUI, Ψ and alloc are 0 wherever their
/// batch kind does not book them.
pub const AUDIT_VALUES: usize = 23;
/// The statements of one batch: the tick pair, each pool side's booking bounds (lower and upper), each side's floor, the
/// three fee bookings' exact truncations (lower and upper each), and the merge's truncation (lower and upper).
pub const AUDIT_STATEMENTS: usize = 16;
/// ⭐ EARN STEP 3 — the fee state's OPEN lines one commitment holds: the backing B, the fresh fees E, the sampled presence A.
pub const FEE_LINES: usize = 3;
/// ⭐ EARN STEP 3 — the CLOSED window's lines, in a commitment of their own (stable from the close to the merge, so the
/// EarnEpoch's audit never meets a moved commitment): E_c, A_c.
pub const CLOSE_LINES: usize = 2;
/// ⭐ EARN STEP 3 — the protocol-wide rate's precision: `dG = ⌊2^EARN_RATE_BITS · ΣE_c / (2·ΣA_c)⌋` (SAT of income per SAT of
/// sampled presence), and the merge allocates `⌊dG·2A_c / 2^EARN_RATE_BITS⌋`.
pub const EARN_RATE_BITS: u32 = 48;
/// The rate grid's top (`dG < 2^(EARN_RATE_BITS + 8)`: a window's fees past 256 × its sampled presence pay at the top and
/// the rest stays fresh). At the top the EarnEpoch's upper statement is empty.
pub const EARN_DG_MAX: u64 = (1 << (EARN_RATE_BITS + 8)) - 1;
/// Value indices of the fee state and the merge.
pub const V_B: usize = 17;
pub const V_E: usize = 18;
pub const V_A: usize = 19;
pub const V_EC: usize = 20;
pub const V_AC: usize = 21;
pub const V_ALLOC: usize = 22;

/// ⭐ EARN STEP 3 — the two merge statements every batch carries, over the public rate `dG` (0 in a batch that merges
/// nothing, which pins `alloc = 0`): `dG·2A_c − 2^K·alloc ≥ 0` and `2^K − 1 − (dG·2A_c − 2^K·alloc) ≥ 0`.
fn merge_rows(dg: &F) -> [([F; AUDIT_VALUES], F); 2] {
    let z = fsmall(0);
    let k = fsmall(1 << EARN_RATE_BITS);
    let two_dg = fmul(&fsmall(2), dg);
    let mut lo = [z; AUDIT_VALUES];
    lo[V_AC] = two_dg;
    lo[V_ALLOC] = fsub(&z, &k);
    let mut hi = [z; AUDIT_VALUES];
    hi[V_AC] = fsub(&z, &two_dg);
    hi[V_ALLOC] = k;
    [(lo, z), (hi, fsub(&k, &fsmall(1)))]
}

/// ⭐⭐ EARN STEP 1 — THE FEE ON THE SAT LEG (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md "Build step 1" and its second reading):
/// `f = FEE_NUM / 2^FEE_SHIFT` = 131/65536 ≈ 0.1999 % of every fill's SAT leg leaves the pool for the pair's FEE LINE, never
/// back into a pool (a fee left in the pool would make the pool's growth a published function of one pair's volume over its
/// depth — the leak the spec's first refutation found). A public product and an EXACT truncation by a power of two: the step
/// shape the custody runtime already runs and this audit already proves, never a division by 10,000.
/// The one rounding rule that keeps it sound: per CLAIM the fee rounds UP ([`claim_fee`]), per BATCH the booking rounds DOWN
/// ([`batch_fee`]), so the claims always leave at least what the fee line books and the dust stays with the pool:
/// `Σ⌈x·f⌉ ≥ ⌊ΔX·f⌋` (sells) and `⌊q_X·f⌋ ≤ q_X·f ≤ Σ⌈g·f⌉ + (q_X − Σg)` (buys, for any number of buys).
/// AI RESISTANT: (a) — every node checks the audit's statements 9–12 and the claim relation's two fee range checks; a
/// custodian whose φ is one unit off, or a claim that takes its fee down, fails a proof.
pub const FEE_NUM: u64 = 131;
/// The fee's power-of-two denominator's exponent.
pub const FEE_SHIFT: u32 = 16;

/// A claim's fee on a SAT amount `v`: `⌈v·f⌉`. Exact integer arithmetic (`v < 2^64`, the product below 2^72).
#[must_use]
pub fn claim_fee(v: u64) -> u64 {
    let m = u128::from(v) * u128::from(FEE_NUM);
    u64::try_from((m + (1u128 << FEE_SHIFT) - 1) >> FEE_SHIFT).unwrap_or(u64::MAX)
}

/// A batch's fee booking on a SAT sum `v`: `⌊v·f⌋`.
#[must_use]
pub fn batch_fee(v: u128) -> u128 {
    v.saturating_mul(u128::from(FEE_NUM)) >> FEE_SHIFT
}

/// One audited statement `z = Σ_j coeffs[j]·V_j + c0 ∈ [0, 2^statement_bits)` as custodian i holds it: the public form and its
/// shares of z's bits and of the masks.
#[derive(Clone, Debug)]
pub struct AuditStatement {
    pub coeffs: [F; AUDIT_VALUES],
    pub c0: F,
    /// this custodian's shares of the bits of z (least significant first)
    pub bits: Vec<F>,
    /// its shares of the masks: a degree-t sharing of 0 (w), AUDIT_REPS degree-2t sharings of 0 (s), AUDIT_REPS random degree-t
    /// sharings (u) — dealt by the custody set and summed, never audited (soundness needs only that they are FIXED before the
    /// challenges, which the phase-1 digest does; privacy needs one honest dealer).
    pub w_mask: F,
    pub s_masks: Vec<F>,
    pub u_masks: Vec<F>,
}

/// Everything custodian i proves over.
#[derive(Clone, Debug)]
pub struct AuditWitness {
    /// its shares of the pool's [`POOL_LINES`] (X, Y, F_X, F_Y) and the salt of its own last commitment to them
    pub pool: [F; POOL_LINES],
    pub pool_salt: [Fa4; 4],
    /// the order shares it received: [`ORDER_LINES`] shares (the X line, then each bucket's Y line) and the owner's salt —
    /// EVERY order carries every line, so the statement's shape never says which way an order trades or at what maximum
    pub orders: Vec<(Vec<F>, [Fa4; 4])>,
    /// which buckets' Y lines ΔY₁ and ΔY₂ sum — public, a function of the tick and the batch's opening tick
    pub select: [[bool; ORDER_BUCKETS]; 2],
    /// ⭐ §18.14 — whether the batch's sells count (public, in the settlement): off, ΔX is 0 and every seller's own SAT comes back, so sells past the pool's floor stop no buyer
    pub sells: bool,
    /// ⭐ EARN STEP 2 PIECE 6 — an EARN batch (public: its number): no trade or deposit sum; with `sells` (its withdrawals-paid
    /// bit) the withdrawals' ΣWU and ΣWUI are summed, booked at the two roots and their income Ψ out of the fee line
    pub earn: bool,
    /// its shares of the booked outflows (q_X, q_Y)
    pub booked: [F; 2],
    /// ⭐ Earn steps 1 + 3 — its shares of the pair's OPEN fee state (B, E, A) and the salt of its last fee commitment (the
    /// book's `fee_commits[i]`)
    pub fee: [F; FEE_LINES],
    pub fee_salt: [Fa4; 4],
    /// ⭐ Earn step 3 — its shares of the CLOSED window's lines (E_c, A_c) and the salt of its last close commitment (the
    /// book's `close_commits[i]`)
    pub close: [F; CLOSE_LINES],
    pub close_salt: [Fa4; 4],
    /// its shares of the batch's fee bookings (φ_s, φ_b, and Earn step 2's φ_d on the deposits' sold halves)
    /// … and Earn step 3's Ψ, the income booked out of the backing (0 in a trading batch)
    pub fees: [F; 4],
    /// ⭐ Earn step 3 — its share of the merge's allocation `⌊dG·2A_c / 2^K⌋` (0 unless `merge`)
    pub alloc: F,
    /// ⭐ Earn step 3 — the batch's public fee-state kind, every one snapshotted when the batch OPENED: `merge` folds the
    /// raised closed window in (B += alloc, E += E_c − alloc, closed lines → 0); `close_out` closes the open window after
    /// this batch's own bookings (E_c ← E, A_c ← A, E, A ← 0); `sample` adds the pool's X to A (an Earn batch while its pair
    /// samples)
    pub merge: bool,
    pub close_out: bool,
    pub sample: bool,
    /// ⭐ Earn step 3 — a DEPOSIT batch (public, snapshotted at its opening: the first batch after a raise): the only batch
    /// whose deposits count (with its sells); in every other the deposit lines are not summed and every deposit comes back
    pub deposits: bool,
    pub statements: Vec<AuditStatement>,
    /// the salt of its new pool commitment `(X + ΔX − φ_s − q_X, Y + ΔY₂ − q_Y, F_X, F_Y)`
    pub new_pool_salt: [Fa4; 4],
    /// the salt of its new fee commitment ([`new_fee_shares`])
    pub new_fee_salt: [Fa4; 4],
    /// the salt of its new close commitment ([`new_close_shares`])
    pub new_close_salt: [Fa4; 4],
    /// the salt of its phase-1 commitment
    pub phase1_salt: [Fa4; 4],
}

/// The challenges every node derives from the batch's phase-1 commitments: per statement, AUDIT_REPS rows of γ's (the bit
/// check) and AUDIT_REPS rows of ρ's (the degree check), one per bit of the statement, each below 2^CHALLENGE_BITS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChallenges {
    pub gamma: Vec<Vec<Vec<u64>>>,
    pub rho: Vec<Vec<Vec<u64>>>,
}

impl AuditChallenges {
    /// Fiat–Shamir: every challenge from one blake3 XOF over the batch's public phase-1 bytes (the batch id and every
    /// custodian's phase-1 digest, in custody order).
    #[must_use]
    pub fn derive(transcript: &[u8]) -> Self {
        Self::derive_n(transcript, AUDIT_STATEMENTS)
    }
    /// The challenges of `n` statements (an EarnEpoch's audit has [`EPOCH_STATEMENTS`]).
    #[must_use]
    pub fn derive_n(transcript: &[u8], n: usize) -> Self {
        let mut h = blake3::Hasher::new_derive_key("USDMD-BR15-AUDIT-CHALLENGES-v3");
        h.update(transcript);
        let mut xof = h.finalize_xof();
        let mut draw = || {
            let mut b = [0u8; 2];
            xof.fill(&mut b);
            u64::from(u16::from_le_bytes(b)) & ((1 << CHALLENGE_BITS) - 1)
        };
        let mut gamma = Vec::with_capacity(n);
        let mut rho = Vec::with_capacity(n);
        for si in 0..n {
            let k = statement_bits(si);
            gamma.push((0..AUDIT_REPS).map(|_| (0..k).map(|_| draw()).collect()).collect());
            rho.push((0..AUDIT_REPS).map(|_| (0..k).map(|_| draw()).collect()).collect());
        }
        AuditChallenges { gamma, rho }
    }
}

/// What custodian i publishes for one statement: `w = Σ 2^k b_k − z + w_mask` (degree t, constant 0), `s_r = Σ γ_{r,k}(b_k −
/// b_k²) + s_mask_r` (degree 2t, constant 0), `u_r = Σ ρ_{r,k} b_k + u_mask_r` (degree t).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPublished {
    pub w: F,
    pub s: Vec<F>,
    pub u: Vec<F>,
}

/// ⭐ THE BATCH'S STATEMENTS from its tick ratios, in [`AUDIT_STATEMENTS`] order — the one place their public form is written:
/// with `(n0, d0) = p_t` and `(n1, d1) = p_{t+1}` (each price `n/d`),
/// 1. `(Y+ΔY₁)·d0 − (X+ΔX−φ_s)·n0 ≥ 0` (with the demand that fills at the tick, the price reaches the tick — A-F46: ΔY₁ sums
///    the same buckets as ΔY₂, so both bounds are over the demand that executes),
/// 2. `(X+ΔX−φ_s)·n1 − (Y+ΔY₂)·d1 − 1 ≥ 0` (with the demand that fills at the tick, it stays below the next) — so the tick
///    is the largest at which the buckets' demand lifts the price to it, a monotone test with exactly one answer, and every
///    filled bucket's maximum is at or above the price its buyers pay (`p_{t+1}`); the sellers' fee is out of the pool
///    before the price, as Uniswap's `amountInWithFee` is,
/// 3. `q_X·n1 − ΔY₂·d1 ≥ 0` (the X booked for the buyers covers every buyer's ⌊y/p_{t+1}⌋),
/// 4. `4·n1 − 1 − (q_X·n1 − ΔY₂·d1) ≥ 0` (and over-books by fewer than four units),
/// 5. `q_Y·d0 − (ΔX−φ_s)·n0 ≥ 0` (the Y booked for the sellers covers every seller's ⌊(x − ⌈x·f⌉)·p_t⌋),
/// 6. `4·d0 − 1 − (q_Y·d0 − (ΔX−φ_s)·n0) ≥ 0`,
/// 7. `X + ΔX − φ_s − q_X − F_X ≥ 0` (the pool never sells below its X floor: only the position's real SAT leaves),
/// 8. `Y + ΔY₂ − q_Y − F_Y ≥ 0` (and never pays below its Y floor: the virtual USDm is never paid),
/// 9. `131·ΔX − 2^16·φ_s ≥ 0` and 10. `2^16 − 1 − (131·ΔX − 2^16·φ_s) ≥ 0` (φ_s is exactly `⌊ΔX·f⌋`; with the sells off
///    ΔX is 0, so φ_s is 0),
/// 11. `131·q_X − 2^16·φ_b ≥ 0` and 12. `2^16 − 1 − (131·q_X − 2^16·φ_b) ≥ 0` (φ_b is exactly `⌊q_X·f⌋`),
/// 13. `131·ΣDS − 2^16·φ_d ≥ 0` and 14. `2^16 − 1 − (131·ΣDS − 2^16·φ_d) ≥ 0` (Earn step 2: φ_d is exactly `⌊ΣDS·f⌋`),
/// 15. and 16. the merge's truncation at the public rate `dg` ([`merge_rows`]; `dg = 0` where nothing merges).
/// ⭐ Earn step 2: in 1 and 2 the pool's X side is `X + ΔX − φ_s + ΣDS − φ_d` (a deposit's sold half is a sell, priced by
/// the search, its fee off before the price); in 7 the floor is over the new X, which also gains ΣDX (the other halves).
#[must_use]
pub fn batch_statements(n0: &F, d0: &F, n1: &F, d1: &F, dg: &F) -> [([F; AUDIT_VALUES], F); AUDIT_STATEMENTS] {
    let z = fsmall(0);
    let one = fsmall(1);
    let neg = |v: &F| fsub(&z, v);
    let four = |v: &F| fsub(&fmul(&fsmall(4), v), &fsmall(1));
    let fnum = fsmall(FEE_NUM);
    let fden = fsmall(1 << FEE_SHIFT);
    let fgap = fsmall((1 << FEE_SHIFT) - 1);
    // a trading batch's statements are over the first 14 values; the Earn values (ΣWU, ΣWUI, Ψ) are 0 here, and the fee
    // state is read only by the merge rows
    let pad = |r: [F; 14]| -> [F; AUDIT_VALUES] { core::array::from_fn(|i| if i < 14 { r[i] } else { z }) };
    let rows: [([F; 14], F); 14] = [
        ([neg(n0), *d0, neg(n0), *d0, z, z, z, z, z, *n0, z, neg(n0), z, *n0], z),
        ([*n1, neg(d1), *n1, z, neg(d1), z, z, z, z, neg(n1), z, *n1, z, neg(n1)], neg(&one)),
        ([z, z, z, z, neg(d1), *n1, z, z, z, z, z, z, z, z], z),
        ([z, z, z, z, *d1, neg(n1), z, z, z, z, z, z, z, z], four(n1)),
        ([z, z, neg(n0), z, z, z, *d0, z, z, *n0, z, z, z, z], z),
        ([z, z, *n0, z, z, z, neg(d0), z, z, neg(n0), z, z, z, z], four(d0)),
        ([one, z, one, z, z, neg(&one), z, neg(&one), z, neg(&one), z, one, one, neg(&one)], z),
        ([z, one, z, z, one, z, neg(&one), z, neg(&one), z, z, z, z, z], z),
        ([z, z, fnum, z, z, z, z, z, z, neg(&fden), z, z, z, z], z),
        ([z, z, neg(&fnum), z, z, z, z, z, z, fden, z, z, z, z], fgap),
        ([z, z, z, z, z, fnum, z, z, z, z, neg(&fden), z, z, z], z),
        ([z, z, z, z, z, neg(&fnum), z, z, z, z, fden, z, z, z], fgap),
        ([z, z, z, z, z, z, z, z, z, z, z, fnum, z, neg(&fden)], z),
        ([z, z, z, z, z, z, z, z, z, z, z, neg(&fnum), z, fden], fgap),
    ];
    let all: Vec<([F; AUDIT_VALUES], F)> = rows.into_iter().map(|(r, c)| (pad(r), c)).chain(merge_rows(dg)).collect();
    core::array::from_fn(|i| all[i])
}

/// Value indices of the Earn batch's own values.
pub const V_WU: usize = 14;
pub const V_WUI: usize = 15;
pub const V_PSI: usize = 16;

/// ⭐⭐ EARN STEP 2 PIECE 6 + STEP 3 — AN EARN BATCH'S STATEMENTS, over the same 18 values (the trade and deposit sums are 0:
/// an Earn batch clears no trade), with `(n0, d0) = p_a`, `(n1, d1) = p_{a+1}`, the SAT rate `sat_d/sat_n` per unit
/// (`1/r'`), the coin rate `coin_n/coin_d` (`r`) and the income index `I`:
/// 1. `Y·d0 − X·n0 ≥ 0` and 2. `X·n1 − Y·d1 − 1 ≥ 0` (the tick brackets the pool's own ratio — no demand at all),
/// 3. `W_X·sat_n − ΣWU·sat_d ≥ 0` and 4. `4·sat_n − 1 − (…) ≥ 0` (the SAT booked covers every withdrawal's `⌊u/r'⌋`),
/// 5. `W_Y·coin_d − ΣWU·coin_n ≥ 0` and 6. `4·coin_d − 1 − (…) ≥ 0` (the coin booked covers every `⌊u·r⌋`),
/// 7. `X − W_X − F_X ≥ 0` and 8. `Y − W_Y − F_Y ≥ 0` (both floors after the payouts),
/// 9. `Ψ·2^S − (I·ΣWU − ΣWUI) ≥ 0` and 10. `4·2^S − 1 − (…) ≥ 0` (the income booked covers every `⌊u·(I − I_entry)/2^S⌋`,
/// `I` the batch's OPENING index, the one every withdrawal of it dealt as its "now"),
/// 11. `B − Ψ ≥ 0` (the backing pays only what the merges allocated it — the turnstile; the merge, if any, comes first),
/// 12–14 empty (`0 ≥ 0`), 15. and 16. the merge ([`merge_rows`]).
/// In an Earn batch whose withdrawals are off, ΣWU, ΣWUI and every booking are 0 and every statement still holds.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn earn_statements(n0: &F, d0: &F, n1: &F, d1: &F, sat_n: &F, sat_d: &F, coin_n: &F, coin_d: &F, index: &F, dg: &F) -> [([F; AUDIT_VALUES], F); AUDIT_STATEMENTS] {
    let z = fsmall(0);
    let one = fsmall(1);
    let neg = |v: &F| fsub(&z, v);
    let four = |v: &F| fsub(&fmul(&fsmall(4), v), &fsmall(1));
    let row = |terms: &[(usize, F)]| -> [F; AUDIT_VALUES] {
        let mut r = [z; AUDIT_VALUES];
        for (i, v) in terms {
            r[*i] = *v;
        }
        r
    };
    let s = fsmall(1 << INCOME_SHIFT);
    let [m0, m1] = merge_rows(dg);
    // the turnstile reads the backing AFTER this batch's merge: B + alloc − Ψ ≥ 0
    [
        (row(&[(0, neg(n0)), (1, *d0)]), z),
        (row(&[(0, *n1), (1, neg(d1))]), neg(&one)),
        (row(&[(5, *sat_n), (V_WU, neg(sat_d))]), z),
        (row(&[(5, neg(sat_n)), (V_WU, *sat_d)]), four(sat_n)),
        (row(&[(6, *coin_d), (V_WU, neg(coin_n))]), z),
        (row(&[(6, neg(coin_d)), (V_WU, *coin_n)]), four(coin_d)),
        (row(&[(0, one), (5, neg(&one)), (7, neg(&one))]), z),
        (row(&[(1, one), (6, neg(&one)), (8, neg(&one))]), z),
        (row(&[(V_PSI, s), (V_WU, neg(index)), (V_WUI, one)]), z),
        (row(&[(V_PSI, neg(&s)), (V_WU, *index), (V_WUI, neg(&one))]), four(&s)),
        (row(&[(V_B, one), (V_ALLOC, one), (V_PSI, neg(&one))]), z),
        (row(&[]), z),
        (row(&[]), z),
        (row(&[]), z),
        m0,
        m1,
    ]
}

/// The custodian's committed values, natively.
fn values(w: &AuditWitness) -> [F; AUDIT_VALUES] {
    let mut dx = fsmall(0);
    let mut dy = [fsmall(0), fsmall(0)];
    // ⭐ Earn step 2 piece 6: an Earn batch sums no trade line (its `select` is empty too)
    let trades = w.sells && !w.earn;
    for (lines, _) in &w.orders {
        if trades {
            dx = fadd(&dx, &lines[0]);
        }
        for (s, sel) in w.select.iter().enumerate() {
            for (j, on) in sel.iter().enumerate() {
                if *on {
                    dy[s] = fadd(&dy[s], &lines[1 + j]);
                }
            }
        }
    }
    // ⭐ Earn step 2 — a deposit's sold half IS a sell: the deposits count exactly when the batch's sells do (with the sells
    // off every deposit is refunded whole, as every seller is), so a withdrawable leaf always names the sellers' price p_t.
    // ⭐ Earn step 3 — and only in a DEPOSIT batch (`deposits`): anywhere else every deposit's claim returns its SAT whole,
    // so the pool must not take it (the leaf's deposit lane is `sells && deposits`, the same bit)
    let (mut ds, mut dj) = (fsmall(0), fsmall(0));
    if trades && w.deposits {
        for (lines, _) in &w.orders {
            ds = fadd(&ds, &lines[DEPOSIT_SOLD_LINE]);
            dj = fadd(&dj, &lines[DEPOSIT_JOIN_LINE]);
        }
    }
    // ⭐ Earn step 2 piece 6: an Earn batch whose withdrawals are paid sums their units and units × entry index
    let (mut wu, mut wui) = (fsmall(0), fsmall(0));
    if w.earn && w.sells {
        for (lines, _) in &w.orders {
            wu = fadd(&wu, &lines[WITHDRAW_UNITS_LINE]);
            wui = fadd(&wui, &lines[WITHDRAW_INDEX_LINE]);
        }
    }
    [
        w.pool[0], w.pool[1], dx, dy[0], dy[1], w.booked[0], w.booked[1], w.pool[2], w.pool[3], w.fees[0], w.fees[1], ds, dj, w.fees[2], wu, wui,
        w.fees[3], w.fee[0], w.fee[1], w.fee[2], w.close[0], w.close[1], w.alloc,
    ]
}

fn statement_z(st: &AuditStatement, v: &[F; AUDIT_VALUES]) -> F {
    st.coeffs.iter().zip(v).fold(st.c0, |acc, (c, x)| fadd(&acc, &fmul(c, x)))
}

/// The new pool shares `(X + ΔX − φ_s − q_X, Y + ΔY₂ − q_Y, F_X, F_Y)`, natively.
#[must_use]
pub fn new_pool_shares(w: &AuditWitness) -> [F; POOL_LINES] {
    let v = values(w);
    // X + ΔX − φ_s − q_X + ΣDS − φ_d + ΣDX (Earn step 2: the deposits' SAT joins, less the sold halves' fee)
    let x = fsub(&fsub(&fadd(&v[0], &v[2]), &v[9]), &v[5]);
    let x = fsub(&fadd(&fadd(&x, &v[11]), &v[12]), &v[13]);
    [x, fsub(&fadd(&v[1], &v[4]), &v[6]), v[7], v[8]]
}

/// ⭐⭐ EARN STEP 3 — THE NEW FEE STATE, natively, in the one order every batch applies it (each step a public selection by
/// the batch's kind, snapshotted at its opening):
/// 1. the merge (`merge`): `B += alloc`, `E += E_c − alloc` (and the closed lines go to 0, [`new_close_shares`]);
/// 2. this batch's own bookings: `E += φ_s + φ_b + φ_d` (the trading and deposit fees), `B −= Ψ` (an Earn batch's income);
/// 3. the sample (`sample`): `A += X` (the pool's X before the batch's payouts — an Earn batch's tick brackets the ratio);
/// 4. the close (`close_out`): `E_c ← E`, `A_c ← A`, then `E, A ← 0`.
/// Returns the new open lines `[B, E, A]`.
#[must_use]
pub fn new_fee_shares(w: &AuditWitness) -> [F; FEE_LINES] {
    fee_state_after(w).0
}

/// The new closed lines `[E_c, A_c]` ([`new_fee_shares`]' four steps).
#[must_use]
pub fn new_close_shares(w: &AuditWitness) -> [F; CLOSE_LINES] {
    fee_state_after(w).1
}

fn fee_state_after(w: &AuditWitness) -> ([F; FEE_LINES], [F; CLOSE_LINES]) {
    let [mut b, mut e, mut a] = w.fee;
    let mut close = w.close;
    if w.merge {
        b = fadd(&b, &w.alloc);
        e = fadd(&e, &fsub(&close[0], &w.alloc));
        close = [fsmall(0), fsmall(0)];
    }
    e = fadd(&fadd(&fadd(&e, &w.fees[0]), &w.fees[1]), &w.fees[2]);
    b = fsub(&b, &w.fees[3]);
    if w.sample {
        a = fadd(&a, &w.pool[0]);
    }
    if w.close_out {
        close = [e, a];
        e = fsmall(0);
        a = fsmall(0);
    }
    ([b, e, a], close)
}

/// ⭐ Earn steps 1 + 3 — a fee-state commitment: [`chain_commit`] over the open lines `[B, E, A]`. The launch's is over three
/// public zeros with the salt every node derives ([`launch_fee_salt`]): every share of a public zero is zero, so no dealer
/// and nothing secret.
#[must_use]
pub fn fee_commit(lines: &[F; FEE_LINES], salt: &[Fa4; 4]) -> [Fa4; 4] {
    chain_commit(lines, salt)
}

/// ⭐ Earn step 3 — a closed-lines commitment: [`chain_commit`] over `[E_c, A_c]`; the launch's over two public zeros
/// ([`launch_close_salt`]).
#[must_use]
pub fn close_commit(lines: &[F; CLOSE_LINES], salt: &[Fa4; 4]) -> [Fa4; 4] {
    chain_commit(lines, salt)
}

/// The launch close-lines salt of custodian `i` of pair `pair` (public: the launch's closed lines are public zeros).
#[must_use]
pub fn launch_close_salt(pair: u8, i: usize) -> [Fa4; 4] {
    let mut h = blake3::Hasher::new_derive_key("USDMD-BR15-LAUNCH-CLOSE-SALT-v1");
    h.update(&[pair]);
    h.update(&(i as u64).to_le_bytes());
    let mut x = h.finalize_xof();
    core::array::from_fn(|_| {
        let mut b = [0u8; 8];
        x.fill(&mut b);
        Fa4::from_u64(u64::from_le_bytes(b))
    })
}

/// The launch fee-line salt of custodian `i` of pair `pair` (public: the launch's fee line is the public zero).
#[must_use]
pub fn launch_fee_salt(pair: u8, i: usize) -> [Fa4; 4] {
    let mut h = blake3::Hasher::new_derive_key("USDMD-BR15-LAUNCH-FEE-SALT-v1");
    h.update(&[pair]);
    h.update(&(i as u64).to_le_bytes());
    let mut x = h.finalize_xof();
    core::array::from_fn(|_| {
        let mut b = [0u8; 8];
        x.fill(&mut b);
        Fa4::from_u64(u64::from_le_bytes(b))
    })
}

/// The phase-1 digest: one Poseidon2 sponge over the booked outflows, the fee bookings, every bit-share and mask of every
/// statement, and the salt — binds them before the challenges are drawn.
#[must_use]
pub fn phase1_digest(w: &AuditWitness) -> [Fa4; 4] {
    use p3_symmetric::Permutation;
    let perm = crate::pow_pq_air::production_perm();
    let mut input: Vec<Fa4> = Vec::new();
    // each element as 11 lanes of two 12-bit limbs (the circuit's packing, `audit_constraints`)
    let packed = |v: &F| -> Vec<Fa4> { limbs_of(&big_from(v)).chunks(2).map(|pr| Fa4::from_u64(pr[0] | (pr.get(1).copied().unwrap_or(0) << LIMB_BITS))).collect() };
    for v in w.booked.iter().chain(&w.fees).chain(std::iter::once(&w.alloc)) {
        input.extend(packed(v));
    }
    for st in &w.statements {
        for v in st.bits.iter().chain(std::iter::once(&st.w_mask)).chain(&st.s_masks).chain(&st.u_masks) {
            input.extend(packed(v));
        }
    }
    input.extend_from_slice(&w.phase1_salt);
    let mut st = [Fa4::ZERO; crate::pow_pq_air::WIDTH];
    st[crate::pow_pq_air::WIDTH - 1] = Fa4::from_u64(PHASE1_DOMAIN);
    for chunk in input.chunks(RATE) {
        for (i, v) in chunk.iter().enumerate() {
            st[i] += *v;
        }
        perm.permute_mut(&mut st);
    }
    [st[0], st[1], st[2], st[3]]
}

/// ⭐ What custodian i publishes, natively (the circuit proves exactly this).
#[must_use]
pub fn audit_published(w: &AuditWitness, ch: &AuditChallenges) -> Vec<AuditPublished> {
    let v = values(w);
    w.statements
        .iter()
        .enumerate()
        .map(|(si, st)| {
            let z = statement_z(st, &v);
            let acc = st.bits.iter().enumerate().fold(fsmall(0), |a, (k, b)| fadd(&a, &fmul(&fpow2(k), b)));
            let wv = fadd(&fsub(&acc, &z), &st.w_mask);
            let s = (0..AUDIT_REPS)
                .map(|r| {
                    st.bits.iter().enumerate().fold(st.s_masks[r], |a, (k, b)| {
                        fadd(&a, &fmul(&fsmall(ch.gamma[si][r][k]), &fsub(b, &fmul(b, b))))
                    })
                })
                .collect();
            let u = (0..AUDIT_REPS)
                .map(|r| st.bits.iter().enumerate().fold(st.u_masks[r], |a, (k, b)| fadd(&a, &fmul(&fsmall(ch.rho[si][r][k]), b))))
                .collect();
            AuditPublished { w: wv, s, u }
        })
        .collect()
}

/// A combination `Σ c_j · 2^(12·shift_j) · x_j` (+ an optional base) with small signed coefficients, reduced in chunks so every
/// column stays inside the native field's signed half (at most 16 terms per reduction).
fn lin_small(b: &mut R1csBuilder, base: Option<Nn>, terms: &[(&Nn, i64, usize)]) -> Nn {
    // ⭐ A CHUNK HOLDS AS MANY TERMS AS ITS REDUCTION'S PLAN ALLOWS (A-F71's plan: no column may wrap the native field) — the
    // terms' column bounds and value bound, accumulated term by term; the first term that would make the plan refuse starts the
    // next chunk. Was 15 terms a chunk: the budget the plan derives holds about 40 small coefficients.
    let mut acc = base;
    let mut i = 0;
    while i < terms.len() {
        let chunk = lin_small_chunk(&terms[i..], acc.is_some());
        assert!(chunk > 0, "⛔ A-F71: one combination term alone could wrap the native field (its coefficient is too wide)");
        let part = &terms[i..i + chunk];
        let width = LIMBS + part.iter().map(|t| t.2).max().unwrap_or(0);
        let mut cols: Vec<(Lc, i128)> = vec![(Lc::constant(Fa4::ZERO), 0); width];
        let mut lay = |x: &Nn, c: i64, sh: usize, b: &R1csBuilder| {
            let xl = limbs_of(&big_from(&x.value(b)));
            for k in 0..LIMBS {
                cols[k + sh].0 = cols[k + sh].0.add(&x.0[k].scale(signed(c)));
                cols[k + sh].1 += i128::from(c) * i128::from(xl[k]);
            }
        };
        if let Some(a) = &acc {
            lay(a, 1, 0, b);
        }
        for (x, c, sh) in part {
            lay(x, *c, *sh, b);
        }
        let (mags, neg, v_max) = lin_small_bounds(part, acc.is_some()).expect("the chunk was planned");
        acc = Some(reduce_columns(b, cols, &mags, 2 * neg + 2, &v_max));
        i += chunk;
    }
    acc.unwrap_or_else(|| Nn::constant(&[0; 4]))
}

/// A `lin_small` chunk's bounds: each column's magnitude, the negative coefficients' weight (for the offset `2·neg + 2`) and
/// the value's bound. `None` past what the bounds can hold.
fn lin_small_bounds(part: &[(&Nn, i64, usize)], with_acc: bool) -> Option<(Vec<u128>, u64, Big)> {
    let width = LIMBS + part.iter().map(|t| t.2).max().unwrap_or(0);
    let mut mags = vec![0u128; width];
    let mut neg: u64 = 0;
    let mut v_max = if with_acc { big_from(&NN_MAX) } else { [0u64; 9] };
    if with_acc {
        for m in mags.iter_mut().take(LIMBS) {
            *m += LIMB_MAX;
        }
    }
    for (_, c, sh) in part {
        for m in mags.iter_mut().skip(*sh).take(LIMBS) {
            *m += u128::from(c.unsigned_abs()) * LIMB_MAX;
        }
        if *c < 0 {
            neg = neg.checked_add(c.unsigned_abs().checked_shl(u32::try_from(12 * sh).ok()?)?)?;
        } else {
            v_max = big_add(&v_max, &big_mul_small(&big_shl_limbs(&big_from(&NN_MAX), *sh)?, c.unsigned_abs()));
        }
    }
    Some((mags, neg, v_max))
}

/// How many of `terms`, from the first, one `lin_small` reduction takes: the longest prefix whose plan is wrap-free.
fn lin_small_chunk(terms: &[(&Nn, i64, usize)], with_acc: bool) -> usize {
    let mut n = 0;
    while n < terms.len() {
        let fits = lin_small_bounds(&terms[..=n], with_acc).is_some_and(|(mags, neg, v_max)| {
            neg.checked_mul(2).and_then(|x| x.checked_add(2)).is_some_and(|q_off| plan_reduction(&mags, mags.len(), q_off, &v_max).is_some())
        });
        if !fits {
            break;
        }
        n += 1;
    }
    n
}

/// The public input layout of a custodian audit: its pool commitment, its fee commitment, its close commitment, each order's
/// share commitment, its phase-1 digest, its new pool, fee and close commitments, then per statement its challenges, its
/// public form and its published values (22 limbs each).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn audit_io(
    pool_commit: &[Fa4; 4],
    fee_commit: &[Fa4; 4],
    close_commit: &[Fa4; 4],
    order_commits: &[[Fa4; 4]],
    phase1: &[Fa4; 4],
    new_pool: &[Fa4; 4],
    new_fee: &[Fa4; 4],
    new_close: &[Fa4; 4],
    ch: &AuditChallenges,
    forms: &[([F; AUDIT_VALUES], F)],
    published: &[AuditPublished],
) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = Vec::new();
    io.extend_from_slice(pool_commit);
    io.extend_from_slice(fee_commit);
    io.extend_from_slice(close_commit);
    for c in order_commits {
        io.extend_from_slice(c);
    }
    io.extend_from_slice(phase1);
    io.extend_from_slice(new_pool);
    io.extend_from_slice(new_fee);
    io.extend_from_slice(new_close);
    let limbs = |io: &mut Vec<Fa4>, v: &F| io.extend(limbs_of(&big_from(v)).iter().map(|l| Fa4::from_u64(*l)));
    for (si, (coeffs, c0)) in forms.iter().enumerate() {
        for r in 0..AUDIT_REPS {
            io.extend(ch.gamma[si][r].iter().map(|v| Fa4::from_u64(*v)));
            io.extend(ch.rho[si][r].iter().map(|v| Fa4::from_u64(*v)));
        }
        for c in coeffs.iter().chain(std::iter::once(c0)) {
            limbs(&mut io, c);
        }
        limbs(&mut io, &published[si].w);
        for v in published[si].s.iter().chain(&published[si].u) {
            limbs(&mut io, v);
        }
    }
    io
}

/// ⭐ A CHAINED SHARE COMMITMENT: `share_commit` folded over `vals` from `salt` — a pool's lines, an order's lines. One sponge
/// per value, each keyed by the last digest, so a commitment opens exactly one vector.
#[must_use]
pub fn chain_commit(vals: &[F], salt: &[Fa4; 4]) -> [Fa4; 4] {
    vals.iter().fold(*salt, |acc, v| share_commit(v, &acc))
}

/// [`chain_commit`] on wires: each value's limbs absorbed under the last digest.
fn chain_commit_w(vals: &[Nn], salt: &[Lc; 4], b: &mut R1csBuilder) -> [Lc; 4] {
    vals.iter().fold(salt.clone(), |acc, v| v.commit(&acc, b))
}

/// ⭐ ONE AUDIT CIRCUIT IN MEMORY PER PROCESS (lane af58, 2026-11-15) — the one gate under which an audit circuit is FORMED and
/// used, whoever forms it: a custodian proving ([`custodian_audit_circuit`], `usdm_ledger::defi_custody`), a node verifying
/// ([`audit_r1cs`], `DefiSettleTx::verdict`), or a test. MEASURED: one 2^22-row audit, formed, proved and its circuit rebuilt
/// by the verifier, peaks at 7,403 MB in one process (`br15_the_custodian_audit_pins_the_tick_and_refuses_every_tamper`, 105 s);
/// two at once is past a 16 GB machine — a node test binary at 25.5 GB reset this Mac on 2026-11-15 (n custodians forming at
/// once), and memguard killed the decider, ledger and node test binaries at 6.6 GB each with two audits in flight.
/// SCALE: a process's audit memory is ONE audit, constant in the roster size, the runs it hosts and its test threads.
/// AI RESISTANT: (b) ordinary code; it decides only WHEN a circuit is formed, never what is proved or verified.
pub static AUDIT_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold [`AUDIT_GATE`] (a poisoned gate is still a gate: a panicked holder's circuit is gone).
pub fn audit_gate() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// ⭐⭐ THE CUSTODIAN AUDIT CIRCUIT: every published value is the stated function of the custodian's shares — its pool shares
/// open its own commitment, its fee-line share opens its fee commitment, each order's lines open the owner's commitment, the
/// booked outflows, fee bookings, bit-shares and masks open its phase-1 digest, `w`, `s_r`, `u_r` of every statement are
/// computed from them under the public challenges, its new pool commitment opens `(X + ΔX − φ_s − q_X, Y + ΔY₂ − q_Y, F_X,
/// F_Y)` and its new fee commitment `Φ + φ_s + φ_b`. `None` when the witness does not fit its layout.
#[must_use]
pub fn custodian_audit_circuit(w: &AuditWitness, ch: &AuditChallenges) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    // the size: one sizing pass at a width that holds any audit (2^24 cells), then the real build at the smallest width whose
    // halves hold the publics and every allocated cell — the circuit's shape is value-independent, so the count is exact
    let (io, nv, _) = audit_io_and_width(w, ch)?;
    build_audit(nv, w, ch, &io)
}

/// A section marker for the audit's own pins (`BR15_AUDIT_TRACE=1`): the row each gadget section starts at.
fn trace_mark(b: &R1csBuilder, name: &str, sizing: bool) {
    if !sizing && std::env::var("BR15_AUDIT_TRACE").is_ok() {
        eprintln!("[br15-audit-trace] {name} starts at row {}", b.constraints());
    }
}

/// The sizing pass's width: 2^24 cells (a witness half of 2^23 holds every audit with up to tens of thousands of orders).
const SIZING_VARS: usize = 24;

/// The batch's public fee-state kind ([`AuditWitness`]'s `merge`, `close_out`, `sample`, `deposits`), as a verifier forms its
/// circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeKind {
    pub merge: bool,
    pub close_out: bool,
    pub sample: bool,
    pub deposits: bool,
}

/// ⭐ THE VERIFIER'S CIRCUIT: the same constraint system rebuilt from PUBLIC data alone (the order count, the bucket
/// selection, the challenges, the statements' public forms, the fee-state kind) over an all-zero witness — the shape of
/// every gadget is value-independent, so a node never takes the prover's matrices.
#[must_use]
pub fn audit_r1cs(
    n_orders: usize,
    select: [[bool; ORDER_BUCKETS]; 2],
    sells: bool,
    earn: bool,
    kind: FeeKind,
    ch: &AuditChallenges,
    forms: &[([F; AUDIT_VALUES], F)],
) -> Option<crate::spartan_ccs::R1cs> {
    custodian_audit_circuit(&audit_dummy(n_orders, select, sells, earn, kind, forms), ch).map(|(r, _, _)| r)
}

/// The verifier's all-zero witness of an audit's PUBLIC shape ([`audit_r1cs`], [`audit_verify`]): one definition, so the
/// laid and the streamed verifier form the same circuit.
fn audit_dummy(n_orders: usize, select: [[bool; ORDER_BUCKETS]; 2], sells: bool, earn: bool, kind: FeeKind, forms: &[([F; AUDIT_VALUES], F)]) -> AuditWitness {
    AuditWitness {
        pool: [[0; 4]; POOL_LINES],
        pool_salt: [Fa4::ZERO; 4],
        orders: vec![(vec![[0; 4]; ORDER_LINES], [Fa4::ZERO; 4]); n_orders],
        select,
        sells,
        earn,
        booked: [[0; 4]; 2],
        fee: [[0; 4]; FEE_LINES],
        fee_salt: [Fa4::ZERO; 4],
        close: [[0; 4]; CLOSE_LINES],
        close_salt: [Fa4::ZERO; 4],
        fees: [[0; 4]; 4],
        alloc: [0; 4],
        merge: kind.merge,
        close_out: kind.close_out,
        sample: kind.sample,
        deposits: kind.deposits,
        statements: forms
            .iter()
            .enumerate()
            .map(|(si, (coeffs, c0))| AuditStatement {
                coeffs: *coeffs,
                c0: *c0,
                bits: vec![[0; 4]; statement_bits(si)],
                w_mask: [0; 4],
                s_masks: vec![[0; 4]; AUDIT_REPS],
                u_masks: vec![[0; 4]; AUDIT_REPS],
            })
            .collect(),
        new_pool_salt: [Fa4::ZERO; 4],
        new_fee_salt: [Fa4::ZERO; 4],
        new_close_salt: [Fa4::ZERO; 4],
        phase1_salt: [Fa4::ZERO; 4],
    }
}

/// The audit LAID at width `nv` (its matrices stored): the circuit [`audit_r1cs`] hands a node and the pins read.
fn build_audit(nv: usize, w: &AuditWitness, ch: &AuditChallenges, io: &[Fa4]) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    let b = audit_constraints(R1csBuilder::new(nv, io)?, w, ch, io, false)?;
    b.finish().map(|(r, wit)| (r, io.to_vec(), wit))
}

/// The audit's constraints and assignment, into whichever builder the caller made (sizing, laid, or streaming).
fn audit_constraints(mut b: R1csBuilder, w: &AuditWitness, ch: &AuditChallenges, io: &[Fa4], sizing: bool) -> Option<R1csBuilder> {
    let mut cursor = 0usize;
    let mut take = |b: &R1csBuilder, n: usize| -> Vec<Lc> {
        let v: Vec<Lc> = (cursor..cursor + n).map(|i| b.io(i)).collect();
        cursor += n;
        v
    };
    let pin4 = |b: &mut R1csBuilder, got: &[Lc; 4], want: &[Lc]| {
        for i in 0..4 {
            b.enforce_eq(&got[i], &want[i]);
        }
    };
    let salt_w = |b: &mut R1csBuilder, s: &[Fa4; 4]| -> [Lc; 4] { core::array::from_fn(|i| b.witness(s[i])) };
    // the pool's four lines open the custodian's own commitment
    let pool: Vec<Nn> = w.pool.iter().map(|v| Nn::alloc(&mut b, v)).collect();
    let ps = salt_w(&mut b, &w.pool_salt);
    let pc = chain_commit_w(&pool, &ps, &mut b);
    let want = take(&b, 4);
    pin4(&mut b, &pc, &want);
    // ⭐ Earn steps 1 + 3 — its open fee state (B, E, A) opens its own fee commitment, its closed lines (E_c, A_c) its own
    // close commitment
    let fee: Vec<Nn> = w.fee.iter().map(|v| Nn::alloc(&mut b, v)).collect();
    let fsw = salt_w(&mut b, &w.fee_salt);
    let fc = chain_commit_w(&fee, &fsw, &mut b);
    let want = take(&b, 4);
    pin4(&mut b, &fc, &want);
    let close: Vec<Nn> = w.close.iter().map(|v| Nn::alloc(&mut b, v)).collect();
    let csw = salt_w(&mut b, &w.close_salt);
    let cc = chain_commit_w(&close, &csw, &mut b);
    let want = take(&b, 4);
    pin4(&mut b, &cc, &want);
    trace_mark(&b, "orders", sizing);
    // every order's lines open the owner's commitment; the sums are linear (the bucket selection is a public constant)
    let mut lines: Vec<Vec<Nn>> = Vec::new();
    for (ls, salt) in &w.orders {
        let ns: Vec<Nn> = ls.iter().map(|v| Nn::alloc(&mut b, v)).collect();
        let sw = salt_w(&mut b, salt);
        let d = chain_commit_w(&ns, &sw, &mut b);
        let want = take(&b, 4);
        pin4(&mut b, &d, &want);
        lines.push(ns);
    }
    let sum = |b: &mut R1csBuilder, terms: Vec<(&Nn, i64, usize)>| -> Nn {
        if terms.is_empty() {
            return Nn::constant(&[0; 4]);
        }
        lin_small(b, None, &terms)
    };
    let trades = w.sells && !w.earn;
    let dx = sum(&mut b, if trades { lines.iter().map(|l| (&l[0], 1i64, 0usize)).collect() } else { Vec::new() });
    let dy_of = |b: &mut R1csBuilder, sel: &[bool; ORDER_BUCKETS]| -> Nn {
        let terms: Vec<(&Nn, i64, usize)> =
            lines.iter().flat_map(|l| (0..ORDER_BUCKETS).map(move |j| (&l[1 + j], i64::from(sel[j]), 0usize))).collect();
        sum(b, terms)
    };
    let dy1 = dy_of(&mut b, &w.select[0]);
    let dy2 = dy_of(&mut b, &w.select[1]);
    // ⭐ Earn step 2 — the deposits' two halves, counted exactly when the sells are (a deposit's sold half is a sell)
    // ⭐ Earn step 3 — the deposits count only in a deposit batch (the leaf's deposit lane is the same bit)
    let dep_on = trades && w.deposits;
    let ds = sum(&mut b, if dep_on { lines.iter().map(|l| (&l[DEPOSIT_SOLD_LINE], 1i64, 0usize)).collect() } else { Vec::new() });
    let dj = sum(&mut b, if dep_on { lines.iter().map(|l| (&l[DEPOSIT_JOIN_LINE], 1i64, 0usize)).collect() } else { Vec::new() });
    // ⭐ Earn step 2 piece 6 — an Earn batch whose withdrawals are paid: their units and units × entry index
    let paid = w.earn && w.sells;
    let wu = sum(&mut b, if paid { lines.iter().map(|l| (&l[WITHDRAW_UNITS_LINE], 1i64, 0usize)).collect() } else { Vec::new() });
    let wui = sum(&mut b, if paid { lines.iter().map(|l| (&l[WITHDRAW_INDEX_LINE], 1i64, 0usize)).collect() } else { Vec::new() });
    trace_mark(&b, "phase1", sizing);
    // phase-1: the booked outflows, the fee bookings, every statement's bit-shares and masks, bound by the digest
    let qx = Nn::alloc(&mut b, &w.booked[0]);
    let qy = Nn::alloc(&mut b, &w.booked[1]);
    let phis = Nn::alloc(&mut b, &w.fees[0]);
    let phib = Nn::alloc(&mut b, &w.fees[1]);
    let phid = Nn::alloc(&mut b, &w.fees[2]);
    let psi = Nn::alloc(&mut b, &w.fees[3]);
    let alloc = Nn::alloc(&mut b, &w.alloc);
    // ⭐ the digest absorbs each element as 11 lanes of TWO range-checked 12-bit limbs (`l_2i + 2^12·l_2i+1 < 2^24`, injective in
    // KoalaBear): half the sponge permutations of one limb a lane ([`phase1_digest`] packs the same)
    let packed = |n: &Nn| -> Vec<Lc> { n.0.chunks(2).map(|pr| pr.iter().enumerate().fold(Lc::constant(Fa4::ZERO), |a, (k, l)| a.add(&l.scale(Fa4::from_u64(1 << (LIMB_BITS * k)))))).collect() };
    let mut p1_limbs: Vec<Lc> = [&qx, &qy, &phis, &phib, &phid, &psi, &alloc].iter().flat_map(|n| packed(n)).collect();
    let mut sts: Vec<(Vec<Nn>, Nn, Vec<Nn>, Vec<Nn>)> = Vec::new();
    for st in &w.statements {
        let bits: Vec<Nn> = st.bits.iter().map(|v| Nn::alloc(&mut b, v)).collect();
        let wm = Nn::alloc(&mut b, &st.w_mask);
        let sm: Vec<Nn> = st.s_masks.iter().map(|v| Nn::alloc(&mut b, v)).collect();
        let um: Vec<Nn> = st.u_masks.iter().map(|v| Nn::alloc(&mut b, v)).collect();
        for n in bits.iter().chain(std::iter::once(&wm)).chain(&sm).chain(&um) {
            p1_limbs.extend(packed(n));
        }
        sts.push((bits, wm, sm, um));
    }
    let p1s = salt_w(&mut b, &w.phase1_salt);
    p1_limbs.extend(p1s.iter().cloned());
    {
        let p2 = crate::spartan_gadgets::P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
        let mut st: [Lc; crate::pow_pq_air::WIDTH] = core::array::from_fn(|_| Lc::constant(Fa4::ZERO));
        st[crate::pow_pq_air::WIDTH - 1] = Lc::constant(Fa4::from_u64(PHASE1_DOMAIN));
        for chunk in p1_limbs.chunks(RATE) {
            for (i, v) in chunk.iter().enumerate() {
                st[i] = st[i].add(v);
            }
            st = crate::spartan_gadgets::poseidon2_permutation(&mut b, &p2, &st);
        }
        let want = take(&b, 4);
        pin4(&mut b, &[st[0].clone(), st[1].clone(), st[2].clone(), st[3].clone()], &want);
    }
    // the new pool commitment: (X + ΔX − φ_s − q_X, Y + ΔY₂ − q_Y, F_X, F_Y)
    {
        let nx_ = pool[0].lin(&[(&dx, 1), (&phis, -1), (&qx, -1), (&ds, 1), (&dj, 1), (&phid, -1)], 1, &mut b);
        let ny_ = pool[1].lin(&[(&dy2, 1), (&qy, -1)], 1, &mut b);
        let ns = salt_w(&mut b, &w.new_pool_salt);
        let c = chain_commit_w(&[nx_, ny_, pool[2].clone(), pool[3].clone()], &ns, &mut b);
        let want = take(&b, 4);
        pin4(&mut b, &c, &want);
    }
    // ⭐ Earn steps 1 + 3 — the new fee and close commitments ([`new_fee_shares`]' four steps, each a public selection by the
    // batch's kind: the merge, this batch's bookings, the sample, the close)
    {
        let zero = Nn::constant(&[0; 4]);
        let (mut nb, mut ne, mut na) = (fee[0].clone(), fee[1].clone(), fee[2].clone());
        let (mut nec, mut nac) = (close[0].clone(), close[1].clone());
        if w.merge {
            nb = nb.lin(&[(&alloc, 1)], 1, &mut b);
            ne = ne.lin(&[(&close[0], 1), (&alloc, -1)], 1, &mut b);
            nec = zero.clone();
            nac = zero.clone();
        }
        ne = ne.lin(&[(&phis, 1), (&phib, 1), (&phid, 1)], 1, &mut b);
        nb = nb.lin(&[(&psi, -1)], 1, &mut b);
        if w.sample {
            na = na.lin(&[(&pool[0], 1)], 1, &mut b);
        }
        if w.close_out {
            nec = ne;
            nac = na;
            ne = zero.clone();
            na = zero.clone();
        }
        let ns = salt_w(&mut b, &w.new_fee_salt);
        let c = chain_commit_w(&[nb, ne, na], &ns, &mut b);
        let want = take(&b, 4);
        pin4(&mut b, &c, &want);
        let ns = salt_w(&mut b, &w.new_close_salt);
        let c = chain_commit_w(&[nec, nac], &ns, &mut b);
        let want = take(&b, 4);
        pin4(&mut b, &c, &want);
    }
    let pin_nn = |b: &mut R1csBuilder, got: &Nn, want: &[Lc]| {
        for (g, wv) in got.0.iter().zip(want) {
            b.enforce_eq(g, wv);
        }
    };
    let vals: [&Nn; AUDIT_VALUES] = [
        &pool[0], &pool[1], &dx, &dy1, &dy2, &qx, &qy, &pool[2], &pool[3], &phis, &phib, &ds, &dj, &phid, &wu, &wui, &psi, &fee[0], &fee[1], &fee[2], &close[0],
        &close[1], &alloc,
    ];
    for (si, st) in w.statements.iter().enumerate() {
        let (bits, wm, sm, um) = &sts[si];
        let nb = bits.len();
        // challenges and the form are public: the circuit uses them as constants; their io slots bind the statement
        let _ = take(&b, 2 * AUDIT_REPS * nb);
        let _ = take(&b, (AUDIT_VALUES + 1) * LIMBS);
        trace_mark(&b, "z", sizing);
        // z = Σ c_j V_j + c0 (each term one public-constant scaling)
        let mut z = Nn::constant(&st.c0);
        for (j, v) in vals.iter().enumerate() {
            if st.coeffs[j] != [0; 4] {
                let t = v.scale_const(&st.coeffs[j], &mut b);
                z = z.add(&t, &mut b);
            }
        }
        // w = Σ 2^k b_k − z + w_mask
        let mut terms: Vec<(&Nn, i64, usize)> = bits.iter().enumerate().map(|(k, x)| (x, 1i64 << (k % 12), k / 12)).collect();
        terms.push((&z, -1, 0));
        terms.push((wm, 1, 0));
        let wv = lin_small(&mut b, None, &terms);
        let want = take(&b, LIMBS);
        pin_nn(&mut b, &wv, &want);
        trace_mark(&b, "squares", sizing);
        // `e_k = b_k² − b_k`, one fused reduction each; `s_r = Σ γ_{r,k}(b_k − b_k²) + s_mask_r = −Σ γ_{r,k} e_k + s_mask_r`, the
        // same value with half the terms
        let es: Vec<Nn> = bits.iter().map(|x| x.square_minus_self(&mut b)).collect();
        for r in 0..AUDIT_REPS {
            let mut t: Vec<(&Nn, i64, usize)> = Vec::with_capacity(nb + 1);
            for k in 0..nb {
                let g = i64::try_from(ch.gamma[si][r][k]).unwrap_or(0);
                t.push((&es[k], -g, 0));
            }
            t.push((&sm[r], 1, 0));
            let sv = lin_small(&mut b, None, &t);
            let want = take(&b, LIMBS);
            pin_nn(&mut b, &sv, &want);
        }
        trace_mark(&b, "u", sizing);
        for r in 0..AUDIT_REPS {
            let mut t: Vec<(&Nn, i64, usize)> = (0..nb).map(|k| (&bits[k], i64::try_from(ch.rho[si][r][k]).unwrap_or(0), 0)).collect();
            t.push((&um[r], 1, 0));
            let uv = lin_small(&mut b, None, &t);
            let want = take(&b, LIMBS);
            pin_nn(&mut b, &uv, &want);
        }
    }
    let _ = cursor;
    let _ = io;
    Some(b)
}

/// The audit's publics, width and row count for `w`: what [`custodian_audit_circuit`] computes before it builds (the row count
/// from the values-only sizing pass, which counts every constraint the laid build makes). `None` when the witness does not
/// fit its layout.
fn audit_io_and_width(w: &AuditWitness, ch: &AuditChallenges) -> Option<(Vec<Fa4>, usize, usize)> {
    let shaped = w.statements.len() == AUDIT_STATEMENTS
        && w.orders.iter().all(|(l, _)| l.len() == ORDER_LINES)
        && w.statements.iter().enumerate().all(|(si, s)| {
            s.bits.len() == statement_bits(si) && s.s_masks.len() == AUDIT_REPS && s.u_masks.len() == AUDIT_REPS
        })
        && ch.gamma.len() == AUDIT_STATEMENTS
        && ch.gamma.iter().enumerate().all(|(si, g)| g.iter().all(|r| r.len() == statement_bits(si)));
    if !shaped {
        return None;
    }
    let pool_commit = chain_commit(&w.pool, &w.pool_salt);
    let fee_c = fee_commit(&w.fee, &w.fee_salt);
    let close_c = close_commit(&w.close, &w.close_salt);
    let order_commits: Vec<[Fa4; 4]> = w.orders.iter().map(|(l, salt)| chain_commit(l, salt)).collect();
    let phase1 = phase1_digest(w);
    let new_pool = chain_commit(&new_pool_shares(w), &w.new_pool_salt);
    let new_fee = fee_commit(&new_fee_shares(w), &w.new_fee_salt);
    let new_close = close_commit(&new_close_shares(w), &w.new_close_salt);
    let published = audit_published(w, ch);
    let forms: Vec<([F; AUDIT_VALUES], F)> = w.statements.iter().map(|s| (s.coeffs, s.c0)).collect();
    let io = audit_io(&pool_commit, &fee_c, &close_c, &order_commits, &phase1, &new_pool, &new_fee, &new_close, ch, &forms, &published);
    let sized = audit_constraints(R1csBuilder::new_values_only(SIZING_VARS, &io)?, w, ch, &io, true)?;
    let vars = sized.last_var() + 1 - (1usize << (SIZING_VARS - 1));
    let rows = sized.constraints();
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    Some((io, nv, rows))
}

/// ⭐⭐ ONE CUSTODIAN'S AUDIT, PROVEN WITHOUT LAYING ITS MATRICES (lane vaults, 2026-11-15): the circuit of
/// [`custodian_audit_circuit`], built once into a streaming builder that folds `A·z`, `B·z`, `C·z` as it makes each entry,
/// and once more — inside the prover, once `r_x` exists — into `M_r` (`spartan_gadgets::Sink`); the proof is
/// `spartan_ccs::prove_committed_streamed`'s, which [`audit_verify`] and `verify_committed` against [`audit_r1cs`] both accept.
/// `(io, proof)`; `None` exactly where the laid circuit does not form or does not prove.
/// MEASURED why (`br15_one_custodians_audit_is_measured_for_its_size_and_its_prove_peak`): 133 M entries, 3.1 GB laid, out of a
/// 4.0 GB prove peak. SAFE AT SCALE: the prove holds O(2^23) words whatever the entries. AI RESISTANT: (a) — the same proof,
/// every node checks it. cons: the circuit is built twice per prove (MEASURED in the pin).
#[must_use]
pub fn custodian_audit_prove(w: &AuditWitness, ch: &AuditChallenges) -> Option<(Vec<Fa4>, Vec<u8>)> {
    let (io, nv, _) = audit_io_and_width(w, ch)?;
    let b = audit_constraints(R1csBuilder::new_streaming(nv, &io, crate::spartan_gadgets::Sink::Abc(Default::default()))?, w, ch, &io, false)?;
    let (shape, sink, wit) = b.finish_stream()?;
    let crate::spartan_gadgets::Sink::Abc(abc) = sink else { return None };
    let cols = shape.cols();
    let proof = crate::spartan_ccs::prove_committed_streamed(&shape, &io, &wit, abc, |eq, coef| {
        let sink = crate::spartan_gadgets::Sink::Mr { eq, coef, out: vec![Ea4::ZERO; cols] };
        let b = audit_constraints(R1csBuilder::new_streaming(nv, &io, sink)?, w, ch, &io, false)?;
        match b.finish_stream()? {
            (_, crate::spartan_gadgets::Sink::Mr { out, .. }, _) => Some(out),
            _ => None,
        }
    })?;
    Some((io, proof))
}

/// ⭐⭐ A NODE'S CHECK OF ONE CUSTODIAN'S AUDIT, WITHOUT LAYING ITS MATRICES: the circuit [`audit_r1cs`] forms from PUBLIC data
/// alone (the same all-zero witness, so the same shape), replayed into `ra·Ã + rb·B̃ + rc·C̃` at the proof's point
/// (`spartan_gadgets::Sink::Mle`) — `spartan_ccs::verify_committed_streamed`, which accepts exactly the proofs
/// `verify_committed` accepts against the laid circuit. RAM: the two `eq` tables and the replay's assignment, never the
/// 133 M entries.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn audit_verify(
    n_orders: usize,
    select: [[bool; ORDER_BUCKETS]; 2],
    sells: bool,
    earn: bool,
    kind: FeeKind,
    ch: &AuditChallenges,
    forms: &[([F; AUDIT_VALUES], F)],
    io: &[Fa4],
    proof: &[u8],
) -> bool {
    AuditVerifier::new(n_orders, select, sells, earn, kind, ch, forms).is_some_and(|v| v.verify(io, proof))
}

/// [`audit_verify`] for every part of one settlement: the circuit's public shape formed ONCE (one values-only sizing pass),
/// then one replay per part (each part's proof has its own point).
pub struct AuditVerifier<'a> {
    dummy: AuditWitness,
    ch: &'a AuditChallenges,
    dio: Vec<Fa4>,
    nv: usize,
    shape: crate::spartan_ccs::R1cs,
}

impl<'a> AuditVerifier<'a> {
    /// The verifier of an audit of this PUBLIC shape; `None` when the circuit cannot form.
    #[must_use]
    pub fn new(n_orders: usize, select: [[bool; ORDER_BUCKETS]; 2], sells: bool, earn: bool, kind: FeeKind, ch: &'a AuditChallenges, forms: &[([F; AUDIT_VALUES], F)]) -> Option<Self> {
        let dummy = audit_dummy(n_orders, select, sells, earn, kind, forms);
        let (dio, nv, rows) = audit_io_and_width(&dummy, ch)?;
        if rows == 0 {
            return None;
        }
        // the instance's shape from the sizing pass (its row count is the laid build's: `constraints()` counts in both)
        let m_vars = ((usize::BITS - (rows - 1).leading_zeros()) as usize).max(1);
        let shape = crate::spartan_ccs::R1cs { m_vars, n_vars: nv, io_len: dio.len(), a: Vec::new(), b: Vec::new(), c: Vec::new() };
        Some(AuditVerifier { dummy, ch, dio, nv, shape })
    }
    /// One custodian's audit `proof` over its publics `io`: one replay of the circuit into its matrices' evaluation.
    #[must_use]
    pub fn verify(&self, io: &[Fa4], proof: &[u8]) -> bool {
        if io.len() != self.dio.len() {
            return false;
        }
        crate::spartan_ccs::verify_committed_streamed(&self.shape, io, proof, &|eq_x, eq_y, coef| {
            let sink = crate::spartan_gadgets::Sink::Mle { eq_x, eq_y, coef, acc: Ea4::ZERO };
            let b = audit_constraints(R1csBuilder::new_streaming(self.nv, &self.dio, sink)?, &self.dummy, self.ch, &self.dio, false)?;
            match b.finish_stream()? {
                (_, crate::spartan_gadgets::Sink::Mle { acc, .. }, _) => Some(acc),
                _ => None,
            }
        })
    }
}

// ───────────────────────────── the claim relation (spec §18.8 item 6) ─────────────────────────────

impl Nn {
    /// Enforce `value < 2^k` (k < 256) for an element in reduced form: every limb wholly above bit k is pinned to zero and the
    /// limb that straddles it is re-decomposed into its low `k mod 12` bits. A negative integer reduced mod p (≈ 2^255) cannot
    /// pass, so this is the range proof `0 ≤ value < 2^k`.
    pub fn enforce_below_pow2(&self, k: usize, b: &mut R1csBuilder) {
        let full = k / LIMB_BITS;
        let part = k % LIMB_BITS;
        for (i, l) in self.0.iter().enumerate() {
            if i > full || (i == full && part == 0) {
                b.enforce_eq(l, &Lc::constant(Fa4::ZERO));
            } else if i == full {
                let v = b.value_of(l).as_canonical_u64();
                let w = range_wire(b, v & ((1 << part) - 1), part);
                b.enforce_eq(l, &w);
            }
        }
    }
}

/// A value below 2^nbits (nbits ≤ 128) from its bits: the 12-bit limbs of the share field (for the relation) and its
/// 16-bit limbs (for the commitments), both linear in the same bits.
fn value_from_bits_n(b: &mut R1csBuilder, v: u128, nbits: usize) -> (Nn, Vec<Lc>) {
    value_of_bits(&bit_wires(b, v, nbits))
}

/// A value below 2^64 from its 64 bits (the order and claim amounts).
fn value_from_bits(b: &mut R1csBuilder, v: u64) -> (Nn, [Lc; 4]) {
    let (nn, l) = value_from_bits_n(b, u128::from(v), 64);
    (nn, core::array::from_fn(|i| l[i].clone()))
}

/// `poseidon_pair(left, right)` on wires: the production permutation over 16 lanes, the first 8 out.
fn pair_gadget(b: &mut R1csBuilder, left: &[Lc; 8], right: &[Lc; 8]) -> [Lc; 8] {
    let p2 = crate::spartan_gadgets::P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
    let st: [Lc; crate::pow_pq_air::WIDTH] = core::array::from_fn(|i| if i < 8 { left[i].clone() } else { right[i - 8].clone() });
    let out = crate::spartan_gadgets::poseidon2_permutation(b, &p2, &st);
    core::array::from_fn(|i| out[i].clone())
}

/// `solvency_commit_256(v, blind)` on wires for a value below 2^64 (its 16-bit limbs 4..16 are zero).
fn commit_gadget(b: &mut R1csBuilder, l16: &[Lc; 4], blind: &[Lc; 8]) -> [Lc; 8] {
    let zero = || Lc::constant(Fa4::ZERO);
    let lo: [Lc; 8] = core::array::from_fn(|i| if i < 4 { l16[i].clone() } else { zero() });
    let hi: [Lc; 8] = core::array::from_fn(|_| zero());
    let inner = pair_gadget(b, &lo, &hi);
    pair_gadget(b, &inner, blind)
}

/// The claim's output for an order of `a` at the price `p_num / p_den`: `⌊a · p_num / p_den⌋` (a seller's `⌊a·p_t⌋` with
/// `(N_t, D_t)`; a buyer's `⌊a / p_{t+1}⌋` with `(D_{t+1}, N_{t+1})`; a refund's `a` with `(1, 1)`). `None` past 2^64 or for a zero
/// denominator.
#[must_use]
pub fn claim_out(a: u64, p_num: u128, p_den: u128) -> Option<u64> {
    if p_den == 0 {
        return None;
    }
    let prod = big_mul(&[a, 0, 0, 0], &[p_num as u64, (p_num >> 64) as u64, 0, 0]);
    let mut q = [0u64; 9];
    let mut rem: u128 = 0;
    for i in (0..192).rev() {
        let bit = (prod[i / 64] >> (i % 64)) & 1;
        let top = rem >> 127;
        rem = (rem << 1) | u128::from(bit);
        if top == 1 || rem >= p_den {
            rem = rem.wrapping_sub(p_den);
            q[i / 64] |= 1 << (i % 64);
        }
    }
    (q[1..].iter().all(|w| *w == 0)).then_some(q[0])
}

/// ⭐ Earn step 1 — what a FILLED BUY's claim mints: its fill `g = ⌊a·p_num/p_den⌋` less its fee `⌈g·f⌉` ([`claim_fee`]).
#[must_use]
pub fn buy_paid(a: u64, p_num: u128, p_den: u128) -> Option<u64> {
    let g = claim_out(a, p_num, p_den)?;
    Some(g - claim_fee(g))
}

/// ⭐ Earn step 1 — what a FILLED SELL's claim mints: `⌊(a − ⌈a·f⌉)·s_num/s_den⌋` — its SAT less its fee, at the sellers' price.
#[must_use]
pub fn sell_paid(a: u64, s_num: u128, s_den: u128) -> Option<u64> {
    claim_out(a - claim_fee(a), s_num, s_den)
}

/// The claim nullifier's domain lanes (`"BR15CLM"`): an order's claim and its refund both spend `P(a_blind, this)`.
const CLAIM_NF_DOMAIN: [u64; 8] = [0x4252_3135, 0x434C_4D00, 0, 0, 0, 0, 0, 1];
/// ⭐ EARN STEP 2 PIECE 6 — a withdrawal's SECOND claim (its coin leg) spends `P(a_blind, this)` (`"BR15CLM"`, leg 2).
pub const CLAIM_NF_DOMAIN_COIN: [u64; 8] = [0x4252_3135, 0x434C_4D00, 0, 0, 0, 0, 0, 2];
/// ⭐ EARN STEP 3 — the income index's fixed point: `I` is SAT per unit × 2^INCOME_SHIFT.
pub const INCOME_SHIFT: u32 = 32;

fn l16_128(v: u128) -> [u64; 8] {
    core::array::from_fn(|i| ((v >> (16 * i)) & 0xFFFF) as u64)
}

/// `solvency_commit_256(v, blind)` for a value below 2^64 — the order's burned amount and the claim's minted amount.
#[must_use]
pub fn amount_commit(v: u64, blind: &[u64; 8]) -> [u64; 8] {
    let l: [u64; 8] = core::array::from_fn(|i| if i < 4 { (v >> (16 * i)) & 0xFFFF } else { 0 });
    crate::whir_rec_block::poseidon_pair(crate::whir_rec_block::poseidon_pair(l, [0; 8]), *blind)
}

/// ⭐ §18.14 — what an order's limit commitment opens to: its bucket for a buy, `SELL_BUCKET_BASE` above it for a sell, so a claim can never take another side than its order's.
pub const SELL_BUCKET_BASE: u64 = 4;
#[must_use]
pub fn side_bucket(bucket: u64, sell: bool) -> u64 {
    if sell { bucket + SELL_BUCKET_BASE } else { bucket }
}
/// ⭐ EARN STEP 2 — a SAT DEPOSIT's code sits `DEPOSIT_BUCKET_BASE` above the buy codes (a deposit spends SAT, so it is a
/// sell's code plus `SELL_BUCKET_BASE` once more): the claim relation's sell/buy branches cannot open it, so a deposit's
/// leaf pays only through its own branch.
pub const DEPOSIT_BUCKET_BASE: u64 = 2 * SELL_BUCKET_BASE;
/// The code an order's limit commitment opens to, every kind.
#[must_use]
pub fn kind_code(bucket: u64, sell: bool, deposit: bool) -> u64 {
    side_bucket(bucket, sell) + if deposit { SELL_BUCKET_BASE } else { 0 }
}

/// The limit commitment's domain lanes (`"BR15LIM"`).
const LIMIT_DOMAIN: [u64; 2] = [0x4252_3135, 0x4C49_4D00];

/// ⭐ THE ORDER'S LIMIT COMMITMENT: `P(P([bucket, domain], 0), a_blind)` — which maximum-price bucket the order named, hidden
/// under the order's own blind (the same blind its amount commitment and its claim nullifier use, each under its own domain).
#[must_use]
pub fn limit_commit(bucket: u64, blind: &[u64; 8]) -> [u64; 8] {
    limit_commit_x(bucket, blind, 0, 0)
}

/// ⭐ EARN STEP 3 — the limit commitment with the two INCOME INDICES in its free lanes, each two 30-bit lanes: `entry` — the
/// index a position's units entered at (a deposit's: its batch's opening index; a withdrawal's: its position's, carried
/// through every batch that paid nothing); `now` — a withdrawal's batch's opening index, the one its income is paid to.
/// A trade's are both 0: the old commitment.
#[must_use]
pub fn limit_commit_x(bucket: u64, blind: &[u64; 8], entry: u64, now: u64) -> [u64; 8] {
    let m = (1u64 << 30) - 1;
    let l: [u64; 8] = [bucket, LIMIT_DOMAIN[0], LIMIT_DOMAIN[1], entry & m, (entry >> 30) & m, now & m, (now >> 30) & m, 0];
    crate::whir_rec_block::poseidon_pair(crate::whir_rec_block::poseidon_pair(l, [0; 8]), *blind)
}

/// ⭐ THE CLAIM LEAF a settlement inserts into the note set for each of its orders (every node computes it from public data):
/// `P(P(amount commitment, limit commitment), P(P(p_num limbs, p_den limbs), [j_min]))` — the batch's buy price at its tick
/// and the lowest bucket that FILLS there (`j_min`; an order of a lower bucket refunds). An expired batch's leaf is `(1, 1)` at
/// `j_min = ORDER_BUCKETS` (nothing fills: every order refunds). The leaf is the same whatever the order's bucket — a
/// settlement never says which orders filled. ⭐ §18.14: it also names the sellers' price `(s_num, s_den)`, `p_t`, or `(0, 1)` when the batch's sells did not fit
/// above the pool's floor (every seller's own SAT back), so one leaf serves either side and says neither.
#[must_use]
pub fn claim_leaf(order_commit: &[u64; 8], limit_cm: &[u64; 8], p_num: u128, p_den: u128, j_min: u64, s_num: u128, s_den: u128) -> [u64; 8] {
    claim_leaf_x(order_commit, limit_cm, p_num, p_den, j_min, s_num, s_den, LeafExtra::default())
}

/// ⭐ EARN STEP 2/3 — what a leaf says beyond its prices, in the tick hash's free lanes (all zero is exactly the old leaf):
/// The claim leaf's batch-wide lanes beyond the price: `earn` — an EARN batch's leaf (refund-leaf semantics for every trade
/// and deposit: `j_min = ORDER_BUCKETS`, sells' price zero; its price slots carry the withdrawal's SAT rate and coin rate);
/// `dep` — ⭐ Earn step 3: a DEPOSIT batch's leaf whose sells counted, where every deposit COUNTED (its SAT joined the pool and
/// this leaf is its position); anywhere else (`dep = 0`) a deposit's SAT comes back whole. No leaf names an income index:
/// the ORDER carries its batch's opening index (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md, step 3's second reading), so a
/// wallet rebuilds every leaf from what it knew when it placed its order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeafExtra {
    pub earn: bool,
    pub dep: bool,
}

/// The income index's ceiling: two 30-bit lanes.
pub const INDEX_BITS: u32 = 60;

/// The claim leaf with its [`LeafExtra`] lanes.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn claim_leaf_x(order_commit: &[u64; 8], limit_cm: &[u64; 8], p_num: u128, p_den: u128, j_min: u64, s_num: u128, s_den: u128, x: LeafExtra) -> [u64; 8] {
    let buy = crate::whir_rec_block::poseidon_pair(l16_128(p_num), l16_128(p_den));
    let sell = crate::whir_rec_block::poseidon_pair(l16_128(s_num), l16_128(s_den));
    let price = crate::whir_rec_block::poseidon_pair(buy, sell);
    // an Earn leaf's sell slot carries the withdrawal's coin rate, and its sells never fill there: the fill lane is 0
    let lanes = [j_min, u64::from(s_num != 0 && !x.earn), u64::from(x.earn), u64::from(x.dep), 0, 0, 0, 0];
    let tick = crate::whir_rec_block::poseidon_pair(price, lanes);
    let order = crate::whir_rec_block::poseidon_pair(*order_commit, *limit_cm);
    crate::whir_rec_block::poseidon_pair(order, tick)
}

/// The largest `u` with `u²·n ≤ q²·d` (`u ≤ q·√(d/n)`), in exact 256-bit products (`q < 2^64`, `n, d < 2^128`).
#[must_use]
pub fn largest_root_fit(q: u64, n: u128, d: u128) -> u64 {
    let sq = |v: u64| -> [u64; 4] {
        let b = big_mul(&[v, 0, 0, 0], &[v, 0, 0, 0]);
        [b[0], b[1], 0, 0]
    };
    let w = |v: u128| -> [u64; 4] { [v as u64, (v >> 64) as u64, 0, 0] };
    let rhs = big_mul(&sq(q), &w(d));
    let fits = |u: u64| -> bool { big_geq(&rhs, &big_mul(&sq(u), &w(n))) };
    let (mut lo, mut hi) = (0u64, u64::MAX);
    while lo < hi {
        let mid = lo + (hi - lo) / 2 + 1;
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    lo
}

/// ⭐ EARN STEP 2 PIECE 3 — a withdrawal's code: `WITHDRAW_BUCKET_BASE` above the buy codes (above a deposit's).
pub const WITHDRAW_BUCKET_BASE: u64 = 3 * SELL_BUCKET_BASE;

/// The position-nullifier domain (`"BR15POS"`): a POSITION (a deposit's counted leaf, or a withdrawal's own non-Earn leaf)
/// is spent once by `P(its blind, this)`, beside its claim nullifier `P(blind, CLAIM_NF_DOMAIN)`.
pub const POSITION_NF_DOMAIN: [u64; 8] = [0x4252_3135, 0x504F_5300, 0, 0, 0, 0, 0, 7];

/// ⭐ A POSITION as its owner holds it: the order that made it (a SAT deposit of `x`, or a withdrawal of `x` units whose batch
/// paid nothing — `from_withdrawal`), its blind and bucket, and the leaf its batch inserted for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionWitness {
    pub x: u64,
    pub x_blind: [u64; 8],
    pub bucket: u64,
    pub from_withdrawal: bool,
    /// the index its units entered at, from its order's limit commitment: a deposit's batch's opening index, or a carried
    /// withdrawal's own entry
    pub entry: u64,
    /// a carried withdrawal's own "now" (its limit commitment names it beside the entry); 0 for a deposit
    pub now: u64,
    pub p_num: u128,
    pub p_den: u128,
    pub j_min: u64,
    pub s_num: u128,
    pub s_den: u128,
    pub extra: LeafExtra,
}

impl PositionWitness {
    /// The order's code: a deposit's, or a withdrawal's.
    #[must_use]
    pub fn code(&self) -> u64 {
        if self.from_withdrawal { self.bucket + WITHDRAW_BUCKET_BASE } else { kind_code(self.bucket, true, true) }
    }
    /// The leaf this position is.
    #[must_use]
    pub fn leaf(&self) -> [u64; 8] {
        let now = if self.from_withdrawal { self.now } else { 0 };
        claim_leaf_x(&amount_commit(self.x, &self.x_blind), &limit_commit_x(self.code(), &self.x_blind, self.entry, now), self.p_num, self.p_den, self.j_min, self.s_num, self.s_den, self.extra)
    }
    /// The income index this position's units entered at (its order's limit commitment names it).
    #[must_use]
    pub fn entry_index(&self) -> u64 {
        self.entry
    }
    /// Its nullifier: `P(blind, POSITION_NF_DOMAIN)`.
    #[must_use]
    pub fn nullifier(&self) -> [u64; 8] {
        crate::whir_rec_block::poseidon_pair(self.x_blind, POSITION_NF_DOMAIN)
    }
    /// The deposit's sold half's coin `q = ⌊(h − ⌈h·f⌉)·s_num/s_den⌋`, `h = ⌊x/2⌋` (`None` past 2^64).
    #[must_use]
    pub fn deposit_coin(&self) -> Option<u64> {
        sell_paid(self.x / 2, self.s_num, self.s_den)
    }
    /// The most units this position is: a deposit's largest `u` with `u²·s_num ≤ q²·s_den` (u ≤ q/√p_t); a carried
    /// withdrawal's own units. `None` for a leaf that is not a position (an Earn leaf; a deposit that did not count — its
    /// batch was no deposit batch, or its sells were off).
    #[must_use]
    pub fn units_max(&self) -> Option<u64> {
        if self.extra.earn {
            return None;
        }
        if self.from_withdrawal {
            return Some(self.x);
        }
        if self.s_num == 0 || !self.extra.dep {
            return None;
        }
        let q = self.deposit_coin()?;
        let (sn, sd) = (self.s_num, self.s_den);
        Some(largest_root_fit(q, sn, sd))
    }
}

/// The claim's nullifier: `P(a_blind, CLAIM_NF_DOMAIN)` — one per order, shared by its claim and its refund.
#[must_use]
pub fn claim_nullifier(a_blind: &[u64; 8]) -> [u64; 8] {
    crate::whir_rec_block::poseidon_pair(*a_blind, CLAIM_NF_DOMAIN)
}

/// The membership cross-bind of a claim leaf: `P(P(leaf, nf), lc_blind)` — the value the note-membership carrier binds
/// (`whir_rec_block`'s spend cross-bind, the same two rounds), so the claim's own proof and its member leg name ONE leaf.
#[must_use]
pub fn claim_leaf_commit(leaf: &[u64; 8], nf: &[u64; 8], lc_blind: &[u64; 8]) -> [u64; 8] {
    crate::whir_rec_block::poseidon_pair(crate::whir_rec_block::poseidon_pair(*leaf, *nf), *lc_blind)
}

/// The public input of a claim: its nullifier, its leaf cross-bind, its minted amount's commitment, and whether it is a
/// refund (the minted asset is the order's own USDm, not SAT).
#[must_use]
pub fn claim_io(nf: &[u64; 8], lc: &[u64; 8], out_commit: &[u64; 8], refund: bool) -> Vec<Fa4> {
    nf.iter().chain(lc).chain(out_commit).map(|v| Fa4::from_u64(*v)).chain(std::iter::once(Fa4::from_u64(u64::from(refund)))).collect()
}

/// The private side of a claim (only the order's owner holds it).
#[derive(Clone, Debug)]
pub struct ClaimWitness {
    pub amount: u64,
    pub amount_blind: [u64; 8],
    /// the order's maximum-price bucket (below [`ORDER_BUCKETS`])
    pub bucket: u64,
    /// ⭐ §18.14 — whether the order sold X (a witness: its limit commitment binds it)
    pub sell: bool,
    /// ⭐ EARN STEP 2 PIECE 6 — whether the order was a WITHDRAWAL (never `sell` nor `deposit`): it is paid only at an Earn
    /// leaf, in two claims — `leg` 0 its SAT (`⌊u·p_num/p_den⌋`, the Earn leaf's SAT rate) plus its income, `leg` 1 its coin
    /// (`⌊u·s_num/s_den⌋`, the coin rate) — and mints 0 anywhere else (its position is re-created by that batch's leaf)
    pub withdraw: bool,
    pub leg: u8,
    /// the leaf's lanes ([`LeafExtra`]): the Earn flag and the deposit batch's flag
    pub extra: LeafExtra,
    /// ⭐ EARN STEP 3 — the order's two income indices, from its limit commitment's lanes: a deposit's or a withdrawal's
    /// `entry`, and a withdrawal's `now` (its batch's opening index); 0 for a trade
    pub entry: u64,
    pub now: u64,
    /// ⭐ EARN STEP 2 — whether the order was a SAT DEPOSIT (only with `sell`; its limit commitment's code binds it): never
    /// filled, it mints its SAT back wherever the leaf's deposit lane is 0 (a refund leaf — expiry, complaint set — any batch
    /// but a deposit batch, or a deposit batch whose sells were off: a deposit's sold half is a sell) and nothing where it is
    /// 1 (its SAT joined the pool; its position is that leaf)
    pub deposit: bool,
    /// the leaf's price and lowest filling bucket
    pub p_num: u128,
    pub p_den: u128,
    pub j_min: u64,
    /// ⭐ §18.14 — the leaf's sellers' price; `(0, 1)` when the batch's sells were returned
    pub s_num: u128,
    pub s_den: u128,
    pub out: u64,
    pub out_blind: [u64; 8],
    pub lc_blind: [u64; 8],
    /// ⭐ spec §18.12 — a COVER claim: it mints 0; its leg names any leaf (`.0`) under the nullifier
    /// `P(secret, CLAIM_COVER_DOMAIN)` (`.1` the secret) — its own domain, so no cover can retire a real order's claim
    pub cover: Option<([u64; 8], [u64; 8])>,
}

impl ClaimWitness {
    /// Whether the order filled: its bucket is at or above the leaf's lowest filling bucket.
    #[must_use]
    pub fn fills(&self) -> bool {
        if self.withdraw {
            self.extra.earn
        } else if self.deposit {
            false
        } else if self.sell {
            self.sells_filled()
        } else {
            self.bucket >= self.j_min
        }
    }
    /// Whether the leaf's sells counted: a nonzero sellers' price on a leaf that is no Earn leaf (an Earn leaf's sell slot
    /// carries the withdrawals' coin rate, and no sell fills there) — the leaf's lane 1, which the claim relation binds.
    #[must_use]
    pub fn sells_filled(&self) -> bool {
        self.s_num != 0 && !self.extra.earn
    }
    /// Whether the leaf is a REFUND leaf (an expired batch's, or the complaint set's): no bucket fills there.
    #[must_use]
    pub fn at_refund_leaf(&self) -> bool {
        self.j_min == ORDER_BUCKETS as u64
    }
    /// The price the claim pays at: the leaf's when the order filled, `(1, 1)` (its own amount back) when it did not.
    #[must_use]
    pub fn paid_at(&self) -> (u128, u128) {
        match (self.fills(), self.sell) {
            (false, _) => (1, 1),
            (true, true) => (self.s_num, self.s_den),
            (true, false) => (self.p_num, self.p_den),
        }
    }
    /// ⭐ Earn step 1 — what this claim mints at its own terms: a filled buy its fill less `⌈g·f⌉` ([`buy_paid`]), a filled
    /// sell over its SAT less `⌈a·f⌉` ([`sell_paid`]), an order that did not fill its amount back, whole. `None` past 2^64.
    #[must_use]
    pub fn paid(&self) -> Option<u64> {
        if self.deposit {
            return Some(if self.extra.dep { 0 } else { self.amount });
        }
        if self.withdraw {
            if !self.extra.earn {
                return Some(0);
            }
            return if self.leg == 0 {
                claim_out(self.amount, self.p_num, self.p_den)?.checked_add(self.income()?)
            } else {
                claim_out(self.amount, self.s_num, self.s_den)
            };
        }
        match (self.fills(), self.sell) {
            (false, _) => Some(self.amount),
            (true, true) => sell_paid(self.amount, self.s_num, self.s_den),
            (true, false) => buy_paid(self.amount, self.p_num, self.p_den),
        }
    }
    /// ⭐ §18.14 — whether the claim mints the pair's Y asset (a seller's fill, a buyer's money back) rather than X (a buyer's fill, a seller's SAT back): all a claim says.
    #[must_use]
    pub fn pays_y(&self) -> bool {
        if self.withdraw { self.leg == 1 } else { self.sell == self.fills() }
    }
    /// ⭐ EARN STEP 3 — `⌊amount·(I_now − I_entry) / 2^INCOME_SHIFT⌋` (the relation pins it for every claim; only a
    /// withdrawal's SAT leg at an Earn leaf is paid it). `None` when the index fell or the income passes 2^64.
    #[must_use]
    pub fn income(&self) -> Option<u64> {
        let d = self.now.checked_sub(self.entry)?;
        u64::try_from((u128::from(self.amount) * u128::from(d)) >> INCOME_SHIFT).ok()
    }
    /// The order's code ([`kind_code`], or a withdrawal's).
    #[must_use]
    pub fn code(&self) -> u64 {
        if self.withdraw { self.bucket + WITHDRAW_BUCKET_BASE } else { kind_code(self.bucket, self.sell, self.deposit) }
    }
    /// The claim leaf this witness opens.
    #[must_use]
    pub fn leaf(&self) -> [u64; 8] {
        claim_leaf_x(
            &amount_commit(self.amount, &self.amount_blind),
            &limit_commit_x(self.code(), &self.amount_blind, self.entry, self.now),
            self.p_num,
            self.p_den,
            self.j_min,
            self.s_num,
            self.s_den,
            self.extra,
        )
    }
    /// `(nf, lc, out_commit, refund)` — what the claim publishes.
    #[must_use]
    pub fn publics(&self) -> ([u64; 8], [u64; 8], [u64; 8], bool) {
        let (leaf, nf) = match self.cover {
            Some((leaf, secret)) => (leaf, crate::whir_rec_block::poseidon_pair(secret, CLAIM_COVER_DOMAIN)),
            None => (self.leaf(), if self.leg == 1 { crate::whir_rec_block::poseidon_pair(self.amount_blind, CLAIM_NF_DOMAIN_COIN) } else { claim_nullifier(&self.amount_blind) }),
        };
        (nf, claim_leaf_commit(&leaf, &nf, &self.lc_blind), amount_commit(self.out, &self.out_blind), self.pays_y())
    }
}

/// The bits of `v` (below 2^nbits) as allocated, self-squared wires.
fn bit_wires(b: &mut R1csBuilder, v: u128, nbits: usize) -> Vec<Lc> {
    (0..nbits)
        .map(|i| {
            let w = b.witness(Fa4::from_u64(((v >> i) & 1) as u64));
            b.constrain(&w, &w, &w);
            w
        })
        .collect()
}

/// A value from its bit wires: its 12-bit limbs (the share-field relation) and its 16-bit limbs (the commitments).
fn value_of_bits(bits: &[Lc]) -> (Nn, Vec<Lc>) {
    let nbits = bits.len();
    let pack = |lo: usize, n: usize| -> Lc {
        (lo..(lo + n).min(nbits)).fold(Lc::constant(Fa4::ZERO), |acc, i| acc.add(&bits[i].scale(Fa4::from_u64(1 << (i - lo)))))
    };
    let nn = Nn((0..LIMBS).map(|j| if 12 * j < nbits { pack(12 * j, 12) } else { Lc::constant(Fa4::ZERO) }).collect());
    (nn, (0..nbits.div_ceil(16)).map(|j| pack(16 * j, 16)).collect())
}

/// `limit_commit(bucket, blind)` on wires.
/// [`limit_commit_x`] in the circuit: the entry index's and the "now" index's two 30-bit lanes each.
fn limit_gadget_x(b: &mut R1csBuilder, bucket: &Lc, blind: &[Lc; 8], entry: [&Lc; 2], now: [&Lc; 2]) -> [Lc; 8] {
    let z = || Lc::constant(Fa4::ZERO);
    let l: [Lc; 8] = core::array::from_fn(|i| match i {
        0 => bucket.clone(),
        1 | 2 => Lc::constant(Fa4::from_u64(LIMIT_DOMAIN[i - 1])),
        3 => entry[0].clone(),
        4 => entry[1].clone(),
        5 => now[0].clone(),
        6 => now[1].clone(),
        _ => z(),
    });
    let inner = pair_gadget(b, &l, &core::array::from_fn(|_| z()));
    pair_gadget(b, &inner, blind)
}

/// ⭐⭐ THE CLAIM RELATION: the owner knows an order's openings `(a, a_blind, bucket)` and a leaf's price and lowest filling
/// bucket `(p_num, p_den, j_min)` whose claim leaf is the one its member leg proves is in the note set (through `lc`), spends
/// that order's ONE nullifier, and mints `out` with `0 ≤ a·P − out·D < D` where `(P, D)` is the leaf's price when
/// `bucket ≥ j_min` (the order filled: `⌊a·p⌋` SAT) and `(1, 1)` otherwise (its maximum was below the price: `a` USDm back),
/// and the public `refund` flag says which. Neither the order, nor its batch, nor its tick, nor its bucket is public: a claim
/// is unlinkable to the order it fills.
#[must_use]
pub fn claim_circuit(c: &ClaimWitness) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    if c.bucket >= ORDER_BUCKETS as u64 || c.j_min > ORDER_BUCKETS as u64 || (c.cover.is_some() && (c.out != 0 || c.amount != 0)) || (c.deposit && !c.sell) {
        return None;
    }
    if (c.withdraw && (c.sell || c.deposit)) || c.leg > 1 || (c.leg == 1 && !c.withdraw) || c.entry >> INDEX_BITS != 0 || c.now >> INDEX_BITS != 0 {
        return None;
    }
    let (nf, lc, oc, refund) = c.publics();
    let io = claim_io(&nf, &lc, &oc, refund);
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let w8 = |b: &mut R1csBuilder, v: &[u64; 8]| -> [Lc; 8] { core::array::from_fn(|i| b.witness(Fa4::from_u64(v[i]))) };
        let k8 = |v: &[u64; 8]| -> [Lc; 8] { core::array::from_fn(|i| Lc::constant(Fa4::from_u64(v[i]))) };
        let (an, al16) = value_from_bits(&mut b, c.amount);
        let (on, ol16) = value_from_bits(&mut b, c.out);
        let pbits = bit_wires(&mut b, c.p_num, 128);
        let dbits = bit_wires(&mut b, c.p_den, 128);
        let (_, pl16) = value_of_bits(&pbits);
        let (_, dl16) = value_of_bits(&dbits);
        // ⭐ §18.14 — the sellers' price, the hidden side and whether the batch's sells filled
        let snbits = bit_wires(&mut b, c.s_num, 128);
        let sdbits = bit_wires(&mut b, c.s_den, 128);
        let (_, snl16) = value_of_bits(&snbits);
        let (_, sdl16) = value_of_bits(&sdbits);
        let sv = b.witness(Fa4::from_u64(u64::from(c.sell)));
        b.constrain(&sv, &sv, &sv);
        // the leaf's sell-fill lane: the sells counted (a nonzero sellers' price) and this is no Earn leaf (whose sell slot
        // carries the withdrawals' coin rate and whose sells never fill) — exactly `claim_leaf_x`'s lane 1
        let sfill = b.witness(Fa4::from_u64(u64::from(c.sells_filled())));
        b.constrain(&sfill, &sfill, &sfill);
        // the bucket (2 bits), j_min (3 bits), and fill = [bucket ≥ j_min] as bit 2 of bucket − j_min + 4 ∈ [0, 8)
        let bk = bit_wires(&mut b, u128::from(c.bucket), 2);
        let jm = bit_wires(&mut b, u128::from(c.j_min), 3);
        let lin = |bits: &[Lc]| bits.iter().enumerate().fold(Lc::constant(Fa4::ZERO), |a, (i, x)| a.add(&x.scale(Fa4::from_u64(1 << i))));
        let (bucket, jmin) = (lin(&bk), lin(&jm));
        let diff = (c.bucket + 4 - c.j_min) as u128;
        let db = bit_wires(&mut b, diff, 3);
        b.enforce_eq(&lin(&db), &bucket.add(&Lc::constant(Fa4::from_u64(4))).add(&jmin.scale(Fa4::ZERO - Fa4::ONE)));
        let buy_fill = db[2].clone();
        // ⭐ EARN STEP 2 — THE DEPOSIT BIT: only on a SAT order (`dep·(1 − sv) = 0`); a deposit never fills
        let dep = b.witness(Fa4::from_u64(u64::from(c.deposit)));
        b.constrain(&dep, &dep, &dep);
        let not_sv = Lc::constant(Fa4::ONE).add(&sv.scale(Fa4::ZERO - Fa4::ONE));
        b.constrain(&dep, &not_sv, &Lc::constant(Fa4::ZERO));
        let not_dep = Lc::constant(Fa4::ONE).add(&dep.scale(Fa4::ZERO - Fa4::ONE));
        // the order's own fill: the sells' for a sell (never a deposit's), its bucket's for a buy
        let m1_raw = b.mul(&sv, &sfill);
        let m1 = b.mul(&m1_raw, &not_dep);
        let m2 = b.mul(&sv, &buy_fill);
        let fill_raw = m1.add(&buy_fill).add(&m2.scale(Fa4::ZERO - Fa4::ONE));
        // ⭐ EARN STEP 2 PIECE 6 — THE WITHDRAWAL BIT (never a sell or a deposit) and its LEG (0: SAT and income, 1: coin; only a
        // withdrawal has a leg 1), and the leaf's EARN lane: a withdrawal is "filled" exactly at an Earn leaf, never as a trade
        let wd = b.witness(Fa4::from_u64(u64::from(c.withdraw)));
        b.constrain(&wd, &wd, &wd);
        b.constrain(&wd, &sv, &Lc::constant(Fa4::ZERO));
        b.constrain(&wd, &dep, &Lc::constant(Fa4::ZERO));
        let not_wd = Lc::constant(Fa4::ONE).add(&wd.scale(Fa4::ZERO - Fa4::ONE));
        let leg = b.witness(Fa4::from_u64(u64::from(c.leg)));
        b.constrain(&leg, &leg, &leg);
        b.constrain(&leg, &not_wd, &Lc::constant(Fa4::ZERO));
        let earn = b.witness(Fa4::from_u64(u64::from(c.extra.earn)));
        b.constrain(&earn, &earn, &earn);
        let fill_t = b.mul(&fill_raw, &not_wd);
        let wde = b.mul(&wd, &earn);
        let fill = fill_t.add(&wde);
        // j_min ≤ ORDER_BUCKETS: ORDER_BUCKETS − j_min as 3 bits
        let room = bit_wires(&mut b, (ORDER_BUCKETS as u64 - c.j_min.min(ORDER_BUCKETS as u64)) as u128, 3);
        b.enforce_eq(&lin(&room), &Lc::constant(Fa4::from_u64(ORDER_BUCKETS as u64)).add(&jmin.scale(Fa4::ZERO - Fa4::ONE)));
        // ⭐ EARN STEP 3 — a deposit keeps its amount exactly where the leaf's DEPOSIT lane is 0 (a refund leaf, any batch but
        // a deposit batch, or a deposit batch whose sells were off), `keep = 1 − dep·dl`; at a leaf where it is 1 the deposit
        // mints 0 (its SAT joined the pool; that leaf is its position)
        let dlane = b.witness(Fa4::from_u64(u64::from(c.extra.dep)));
        b.constrain(&dlane, &dlane, &dlane);
        let dep_counted = b.mul(&dep, &dlane);
        // ⭐ a withdrawal keeps its units only at an Earn leaf (`keep = 1 − dep·dl − wd + wd·earn`); anywhere else it mints 0
        // — its position is re-created by that batch's own leaf (the order relation's carried branch)
        let keep = Lc::constant(Fa4::ONE).add(&dep_counted.scale(Fa4::ZERO - Fa4::ONE)).add(&wd.scale(Fa4::ZERO - Fa4::ONE)).add(&wde);
        // ⭐ EARN STEP 3 — the order's own two indices, from its limit lanes: "now" (a withdrawal's batch's opening index) and
        // its entry, two 30-bit lanes each
        let now_lo = bit_wires(&mut b, u128::from(c.now & ((1 << 30) - 1)), 30);
        let now_hi = bit_wires(&mut b, u128::from(c.now >> 30), 30);
        let ent_lo = bit_wires(&mut b, u128::from(c.entry & ((1 << 30) - 1)), 30);
        let ent_hi = bit_wires(&mut b, u128::from(c.entry >> 30), 30);
        let ab = w8(&mut b, &c.amount_blind);
        let obl = w8(&mut b, &c.out_blind);
        let lcb = w8(&mut b, &c.lc_blind);
        let bc = commit_gadget(&mut b, &al16, &ab);
        // the kind's code ([`kind_code`]): + SELL_BUCKET_BASE for a sell, + SELL_BUCKET_BASE more for a deposit
        let side_b = bucket
            .add(&sv.scale(Fa4::from_u64(SELL_BUCKET_BASE)))
            .add(&dep.scale(Fa4::from_u64(SELL_BUCKET_BASE)))
            .add(&wd.scale(Fa4::from_u64(WITHDRAW_BUCKET_BASE)));
        let limit = limit_gadget_x(&mut b, &side_b, &ab, [&lin(&ent_lo), &lin(&ent_hi)], [&lin(&now_lo), &lin(&now_hi)]);
        let pl: [Lc; 8] = core::array::from_fn(|i| pl16[i].clone());
        let dl: [Lc; 8] = core::array::from_fn(|i| dl16[i].clone());
        let buy_price = pair_gadget(&mut b, &pl, &dl);
        let snl: [Lc; 8] = core::array::from_fn(|i| snl16[i].clone());
        let sdl: [Lc; 8] = core::array::from_fn(|i| sdl16[i].clone());
        let sell_price = pair_gadget(&mut b, &snl, &sdl);
        let price = pair_gadget(&mut b, &buy_price, &sell_price);
        let jl: [Lc; 8] = core::array::from_fn(|i| match i {
            0 => jmin.clone(),
            1 => sfill.clone(),
            2 => earn.clone(),
            3 => dlane.clone(),
            _ => Lc::constant(Fa4::ZERO),
        });
        let tick = pair_gadget(&mut b, &price, &jl);
        let order = pair_gadget(&mut b, &bc, &limit);
        let leaf = pair_gadget(&mut b, &order, &tick);
        // the claim nullifier's domain by leg: CLAIM_NF_DOMAIN, or CLAIM_NF_DOMAIN_COIN for a withdrawal's coin leg
        let nf_dom: [Lc; 8] = core::array::from_fn(|i| {
            Lc::constant(Fa4::from_u64(CLAIM_NF_DOMAIN[i])).add(&leg.scale(Fa4::from_u64(CLAIM_NF_DOMAIN_COIN[i]) - Fa4::from_u64(CLAIM_NF_DOMAIN[i])))
        });
        let nf_real = pair_gadget(&mut b, &ab, &nf_dom);
        // the branch: s = 1 claims the leaf above; s = 0 is a COVER — it mints 0 (every output limb times (1 − s) is 0) and
        // the leaf and nullifier its leg binds are free witnesses
        let s = b.witness(Fa4::from_u64(u64::from(c.cover.is_none())));
        b.constrain(&s, &s, &s);
        let not_s = Lc::constant(Fa4::ONE).add(&s.scale(Fa4::ZERO - Fa4::ONE));
        for l in ol16.iter() {
            b.constrain(l, &not_s, &Lc::constant(Fa4::ZERO));
        }
        let (free_leaf, free_secret) = c.cover.unwrap_or((c.leaf(), [0; 8]));
        let fl = w8(&mut b, &free_leaf);
        let fs = w8(&mut b, &free_secret);
        let fnf = pair_gadget(&mut b, &fs, &k8(&CLAIM_COVER_DOMAIN));
        let sel = |b: &mut R1csBuilder, real: &[Lc; 8], free: &[Lc; 8]| -> [Lc; 8] {
            core::array::from_fn(|i| {
                let diff = real[i].add(&free[i].scale(Fa4::ZERO - Fa4::ONE));
                let m = b.mul(&s, &diff);
                free[i].add(&m)
            })
        };
        let leaf = sel(&mut b, &leaf, &fl);
        let nfw = sel(&mut b, &nf_real, &fnf);
        let inner = pair_gadget(&mut b, &leaf, &nfw);
        let lcw = pair_gadget(&mut b, &inner, &lcb);
        let ocw = commit_gadget(&mut b, &ol16, &obl);
        for i in 0..8 {
            let (x, y, z) = (b.io(i), b.io(8 + i), b.io(16 + i));
            b.enforce_eq(&nfw[i], &x);
            b.enforce_eq(&lcw[i], &y);
            b.enforce_eq(&ocw[i], &z);
        }
        // ⭐ §18.14 — the public flag says only which asset the claim mints: 1 for Y (a seller's fill, a buyer's money back), 0 for X (a buyer's fill, a seller's SAT back) —
        // 1 − v − fill + 2·v·fill. A cover's flag follows its own bucket and j_min.
        let vf = b.mul(&sv, &fill);
        let rf = b.io(24);
        // a withdrawal's asset is its leg's (0 SAT, 1 coin): `rf = (1 − wd)·(1 − v − fill + 2·v·fill) + wd·leg`
        let trade_rf = Lc::constant(Fa4::ONE).add(&sv.scale(Fa4::ZERO - Fa4::ONE)).add(&fill.scale(Fa4::ZERO - Fa4::ONE)).add(&vf.scale(Fa4::from_u64(2)));
        let wd_rf = b.mul(&wd, &trade_rf);
        let wl = b.mul(&wd, &leg);
        b.enforce_eq(&rf, &trade_rf.add(&wd_rf.scale(Fa4::ZERO - Fa4::ONE)).add(&wl));
        // the price slot: a sell's (and a withdrawal's coin leg's) is the leaf's sell slot, everyone else's its buy slot
        let ss = sv.add(&wl);
        // the side's price, bit by bit: v·s_i + (1 − v)·p_i
        let side_of = |b: &mut R1csBuilder, sell: &[Lc], buy: &[Lc]| -> Vec<Lc> {
            sell.iter()
                .zip(buy)
                .map(|(s, p)| {
                    let diff = s.add(&p.scale(Fa4::ZERO - Fa4::ONE));
                    let m = b.mul(&ss, &diff);
                    p.add(&m)
                })
                .collect()
        };
        let num_bits = side_of(&mut b, &snbits, &pbits);
        let den_bits = side_of(&mut b, &sdbits, &dbits);
        // the paid price: the side's when filled, (1, 1) when not — bit by bit, P_i = fill·p_i (+ (1 − fill) at bit 0)
        let sel = |b: &mut R1csBuilder, bits: &[Lc]| -> Vec<Lc> {
            bits.iter()
                .enumerate()
                .map(|(i, x)| {
                    let m = b.mul(&fill, x);
                    if i == 0 { m.add(&Lc::constant(Fa4::ONE)).add(&fill.scale(Fa4::ZERO - Fa4::ONE)) } else { m }
                })
                .collect()
        };
        let (pn, _) = value_of_bits(&sel(&mut b, &num_bits));
        let (pd, _) = value_of_bits(&sel(&mut b, &den_bits));
        // ⭐ Earn step 1 — THE FEE ON THE SAT LEG ([`FEE_NUM`]): φ_a = ⌈a·f⌉ and φ_g = ⌈g·f⌉, each pinned exactly by
        // `2^16·φ − 131·v ∈ [0, 2^16)` (64-bit φ: a negative difference reduces mod p far above 2^16). A filled SELL is paid
        // over `a − φ_a`; a filled BUY is paid `g − φ_g` where `g = out + φ_g` is its fill before the fee; a refund and a cover
        // pay as before (their selector is 0). Both φ are determined whatever the side, used only where the selector is 1.
        let sell_filled = m1.clone();
        let buy_filled_raw = buy_fill.add(&m2.scale(Fa4::ZERO - Fa4::ONE));
        let buy_filled = b.mul(&buy_filled_raw, &not_wd);
        let buy_filled_v = c.cover.is_none() && !c.sell && !c.withdraw && c.fills();
        let g_v = if buy_filled_v { claim_out(c.amount, c.p_num, c.p_den).unwrap_or(0) } else { c.out };
        let (phi_a, _) = value_from_bits(&mut b, claim_fee(c.amount));
        let fee_a = lin_small(&mut b, None, &[(&phi_a, 1 << (FEE_SHIFT as usize - LIMB_BITS), 1), (&an, -(FEE_NUM as i64), 0)]);
        fee_a.enforce_below_pow2(FEE_SHIFT as usize, &mut b);
        let (phi_g, _) = value_from_bits(&mut b, claim_fee(g_v));
        let phi_g_on = nn_select(&mut b, &phi_g, &buy_filled);
        let gn = on.add(&phi_g_on, &mut b);
        let fee_g = lin_small(&mut b, None, &[(&phi_g, 1 << (FEE_SHIFT as usize - LIMB_BITS), 1), (&gn, -(FEE_NUM as i64), 0)]);
        fee_g.enforce_below_pow2(FEE_SHIFT as usize, &mut b);
        let phi_a_on = nn_select(&mut b, &phi_a, &sell_filled);
        let a_net = an.sub(&phi_a_on, &mut b);
        let a_eff = nn_select(&mut b, &a_net, &keep);
        // ⭐ EARN STEP 3 — A WITHDRAWAL'S INCOME on its SAT leg at an Earn leaf: `inc = ⌊u·(I_now − I_entry) / 2^INCOME_SHIFT⌋`
        // (`I_now ≥ I_entry`, 60 bits; `0 ≤ u·ΔI − inc·2^INCOME_SHIFT < 2^INCOME_SHIFT`), paid on top of the SAT rate; zero for
        // every other claim
        let now_b: Vec<Lc> = now_lo.iter().chain(&now_hi).cloned().collect();
        let ent_b: Vec<Lc> = ent_lo.iter().chain(&ent_hi).cloned().collect();
        let (now_nn, _) = value_of_bits(&now_b);
        let (ent_nn, _) = value_of_bits(&ent_b);
        // the gap is a withdrawal's alone (`d = wd·(I_now − I_entry)`): a deposit's lanes are (entry, 0), so its raw gap is
        // negative past the first raise — ungated, a deposit made after a raise had NO claim, and its refund could never
        // mint (MEASURED 2026-11-15 by `earn_a_deposits_claim_is_its_sat_at_a_refund_leaf_and_nothing_at_a_settled_one`). Only
        // a withdrawal is paid income (`inc_gate` below carries `wd`), so gating the gap moves no claim's value.
        let d_raw = now_nn.sub(&ent_nn, &mut b);
        let d_i = nn_select(&mut b, &d_raw, &wd);
        d_i.enforce_below_pow2(INDEX_BITS as usize, &mut b);
        let inc_v = c.income().unwrap_or(0);
        let (inc_nn, _) = value_from_bits(&mut b, inc_v);
        let ui = an.mul(&d_i, &mut b);
        let inc_rem = ui.sub(&inc_nn.scale_const(&fsmall(1u64 << INCOME_SHIFT), &mut b), &mut b);
        inc_rem.enforce_below_pow2(INCOME_SHIFT as usize, &mut b);
        let not_leg = Lc::constant(Fa4::ONE).add(&leg.scale(Fa4::ZERO - Fa4::ONE));
        let inc_gate = b.mul(&wde, &not_leg);
        let inc_on = nn_select(&mut b, &inc_nn, &inc_gate);
        let gn = gn.sub(&inc_on, &mut b);
        // 0 ≤ e = (a − φ_a·[sell filled])·P − (out + φ_g·[buy filled])·D and D − 1 − e ≥ 0, each below 2^128 (the price is
        // private, so both are range-checked)
        let lhs = a_eff.mul(&pn, &mut b);
        let rhs = gn.mul(&pd, &mut b);
        let e = lhs.sub(&rhs, &mut b);
        e.enforce_below_pow2(128, &mut b);
        let gap = pd.lin(&[(&e, -1)], 1, &mut b).sub(&Nn::constant(&fsmall(1)), &mut b);
        gap.enforce_below_pow2(128, &mut b);
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, w)| (r, io.clone(), w))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S CLAIM CIRCUIT: formed over an all-zero witness (the relation's shape is fixed), never taken from a prover.
#[must_use]
pub fn claim_r1cs() -> Option<crate::spartan_ccs::R1cs> {
    let dummy = ClaimWitness {
        amount: 0,
        amount_blind: [0; 8],
        bucket: 0,
        sell: false,
        deposit: false,
        withdraw: false,
        leg: 0,
        extra: LeafExtra::default(),
        entry: 0,
        now: 0,
        p_num: 1,
        p_den: 1,
        j_min: 0,
        s_num: 0,
        s_den: 1,
        out: 0,
        out_blind: [0; 8],
        lc_blind: [0; 8],
        cover: None,
    };
    claim_circuit(&dummy).map(|(r, _, _)| r)
}

// ───────────────────────────── the order's share proof (spec §18.8 item 1, §18.10) ─────────────────────────────

/// What an order's owner deals: the polynomials' non-constant coefficients for each line (degree t; the X line's constant is
/// 0 and the named bucket's Y line's is the order amount for a buy, every other line's 0 — every order carries every line, so
/// its shape never says which way it trades or at what maximum) and one salt per custodian.
#[derive(Clone, Debug)]
pub struct OrderDealing {
    pub amount: u64,
    pub amount_blind: [u64; 8],
    /// the maximum-price bucket (below [`ORDER_BUCKETS`]); a sell's amount is on the X line whatever its bucket
    pub bucket: usize,
    /// true: the amount is on the X side (a sell of X); false: on the bucket's Y line (a buy of X with Y). ⭐ §18.14: a WITNESS: nothing public says which
    pub on_x: bool,
    /// ⭐ EARN STEP 2 — a SAT DEPOSIT (requires `on_x`: it spends a SAT note): its amount is dealt `⌊a/2⌋` on
    /// [`DEPOSIT_SOLD_LINE`] and the rest on [`DEPOSIT_JOIN_LINE`], nothing on the X line. A witness, like the side.
    pub deposit: bool,
    /// ⭐ EARN STEP 2 PIECE 3 — a WITHDRAWAL (not `on_x`, not `deposit`, not a cover): it spends no note but a POSITION — the
    /// leaf of a deposit that counted, or of an earlier withdrawal whose batch paid nothing — under the position nullifier,
    /// and deals its `amount` (its units, at most the position's: [`PositionWitness::units_max`]) on
    /// [`WITHDRAW_UNITS_LINE`]. A witness, like the side.
    pub withdraw: Option<PositionWitness>,
    /// ⭐ EARN STEP 3 — the income index of the batch this order is made for, as that batch OPENED (public: every order
    /// carries it, whatever its kind, and a node excludes an order whose batch opened at another). The proof binds it into
    /// the limit commitment: a deposit's entry, a withdrawal's "now"; a trade's lanes are 0.
    pub index: u64,
    /// ⭐ §18.14 — the pair's two assets: the note a sell spends carries `x_tag`, the note a buy spends `y_tag`
    pub x_tag: [u64; 3],
    pub y_tag: [u64; 3],
    /// one coefficient vector per line (X, then each bucket's Y), each of length t
    pub coeffs: Vec<Vec<F>>,
    pub salts: Vec<[Fa4; 4]>,
    /// the order's carried bytes this proof is bound to (its batch and every sealed share, as 30-bit lanes): public input the
    /// transcript absorbs, so a proof never travels with another order's sealed shares
    pub binding: [u64; 8],
    /// ⭐ spec §18.12 — THE NOTE THE ORDER SPENDS: its owner `(ask, nk, seed)` (a USDm note of exactly the amount — the buyer's
    /// own, or a value-0 note custody owns for a COVER slot) and the member leg's cross-bind blind
    pub owner: [[u64; 8]; 3],
    pub lc_blind: [u64; 8],
    /// ⭐ spec §18.12 — a COVER slot: amount 0, no note spent — its member leg names any leaf the custody holds (`.0`) under
    /// the nullifier `P(secret, ORDER_COVER_DOMAIN)` (`.1` the secret). The proof is the same relation, its branch a hidden
    /// witness bit. ⛔ The cover nullifier lives in its OWN domain: a free nullifier would let a rogue custodian give a cover
    /// the nullifier of a buyer's pending order and burn that buyer's note; equal to a note's `P(nk, cm)` only by a Poseidon
    /// collision.
    pub cover: Option<([u64; 8], [u64; 8])>,
}

/// The order-cover nullifier domain (`"BR15OCV"`).
pub const ORDER_COVER_DOMAIN: [u64; 8] = [0x4252_3135, 0x4F43_5600, 0, 0, 0, 0, 0, 3];
/// The claim-cover nullifier domain (`"BR15CCV"`).
pub const CLAIM_COVER_DOMAIN: [u64; 8] = [0x4252_3135, 0x4343_5600, 0, 0, 0, 0, 0, 5];

/// The spent note of an order slot: its commitment `asset_note_cm(a, tag, P(P(ask, nk), seed))`, `tag` the side's asset.
#[must_use]
pub fn slot_note_cm(amount: u64, tag: [u64; 3], owner: &[[u64; 8]; 3]) -> [u64; 8] {
    let wr = |a: [u64; 8], b: [u64; 8]| crate::whir_rec_block::poseidon_pair(a, b);
    let o = wr(wr(owner[0], owner[1]), owner[2]);
    crate::whir_rec_block::asset_note_cm(amount, tag, o)
}

impl OrderDealing {
    /// The spent note's commitment, its nullifier `P(nk, cm)` and the member leg's cross-bind `P(P(cm, nf), lc_blind)`.
    #[must_use]
    pub fn spend_publics(&self) -> ([u64; 8], [u64; 8], [u64; 8]) {
        if let Some(pos) = &self.withdraw {
            let (cm, nf) = (pos.leaf(), pos.nullifier());
            return (cm, nf, claim_leaf_commit(&cm, &nf, &self.lc_blind));
        }
        let (cm, nf) = match self.cover {
            Some((leaf, secret)) => (leaf, crate::whir_rec_block::poseidon_pair(secret, ORDER_COVER_DOMAIN)),
            None => {
                let cm = slot_note_cm(self.amount, if self.on_x { self.x_tag } else { self.y_tag }, &self.owner);
                (cm, crate::whir_rec_block::poseidon_pair(self.owner[1], cm))
            }
        };
        (cm, nf, claim_leaf_commit(&cm, &nf, &self.lc_blind))
    }
    /// Each line's constant: `a` on the X line for a sell, on the bucket's Y line for a buy; a deposit's two halves on the
    /// deposit lines; 0 elsewhere.
    fn constants(&self) -> Vec<F> {
        let a = fsmall(self.amount);
        let half = self.amount / 2;
        (0..ORDER_LINES)
            .map(|l| {
                if let Some(pos) = &self.withdraw {
                    if l == WITHDRAW_UNITS_LINE {
                        a
                    } else if l == WITHDRAW_INDEX_LINE {
                        fmul(&a, &fsmall(pos.entry_index()))
                    } else {
                        fsmall(0)
                    }
                } else if self.deposit {
                    if l == DEPOSIT_SOLD_LINE {
                        fsmall(half)
                    } else if l == DEPOSIT_JOIN_LINE {
                        fsmall(self.amount - half)
                    } else {
                        fsmall(0)
                    }
                } else if (self.on_x && l == 0) || (!self.on_x && l == 1 + self.bucket) {
                    a
                } else {
                    fsmall(0)
                }
            })
            .collect()
    }
    /// Custodian `i`'s (0-based, at x = i + 1) shares of every line.
    #[must_use]
    pub fn shares(&self, i: usize) -> Vec<F> {
        let x = (i + 1) as u64;
        self.constants()
            .iter()
            .zip(&self.coeffs)
            .map(|(c0, cs)| poly_eval(&std::iter::once(*c0).chain(cs.iter().copied()).collect::<Vec<_>>(), x))
            .collect()
    }
    /// The commitments every custodian's shares must open (what the order object carries).
    #[must_use]
    pub fn share_commits(&self) -> Vec<[Fa4; 4]> {
        (0..self.salts.len()).map(|i| chain_commit(&self.shares(i), &self.salts[i])).collect()
    }
    /// The order amount's commitment (the burn's committed amount): `solvency_commit_256(amount, blind)`.
    #[must_use]
    pub fn amount_commit(&self) -> [u64; 8] {
        amount_commit(self.amount, &self.amount_blind)
    }
    /// The order's limit commitment (its kind's code: [`kind_code`]).
    #[must_use]
    pub fn limit_commit(&self) -> [u64; 8] {
        match &self.withdraw {
            Some(pos) => limit_commit_x(self.bucket as u64 + WITHDRAW_BUCKET_BASE, &self.amount_blind, pos.entry_index(), self.index),
            None if self.deposit => limit_commit_x(kind_code(self.bucket as u64, true, true), &self.amount_blind, self.index, 0),
            None => limit_commit(kind_code(self.bucket as u64, self.on_x, self.deposit), &self.amount_blind),
        }
    }
}

/// The public input of an order's share proof: the amount commitment, the side flag, the limit commitment, then each
/// custodian's share commitment, then the binding, then the spent note's nullifier and the member leg's cross-bind, then
/// (Earn step 3) its batch's opening income index as two 30-bit lanes.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn order_share_io(
    amount_commit: &[u64; 8],
    limit_cm: &[u64; 8],
    commits: &[[Fa4; 4]],
    binding: &[u64; 8],
    nf: &[u64; 8],
    lc: &[u64; 8],
    index: u64,
) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = amount_commit.iter().map(|v| Fa4::from_u64(*v)).collect();
    // §18.14: the side is a witness now; this slot stays zero so the proof's public offsets do not move
    io.push(Fa4::ZERO);
    io.extend(limit_cm.iter().map(|v| Fa4::from_u64(*v)));
    for c in commits {
        io.extend_from_slice(c);
    }
    io.extend(binding.iter().map(|v| Fa4::from_u64(*v & ((1 << 30) - 1))));
    io.extend(nf.iter().chain(lc).map(|v| Fa4::from_u64(*v)));
    io.push(Fa4::from_u64(index & ((1 << 30) - 1)));
    io.push(Fa4::from_u64((index >> 30) & ((1 << 30) - 1)));
    io
}

/// `x · bit` on an element's limbs (a limb times a bit stays a limb): one constraint per limb.
fn nn_select(b: &mut R1csBuilder, x: &Nn, bit: &Lc) -> Nn {
    Nn(x.0.iter().map(|l| b.mul(l, bit)).collect())
}

/// ⭐⭐ THE ORDER'S SHARE PROOF: the burned amount's commitment opens to `a`; the limit commitment opens to a bucket (one-hot
/// over [`ORDER_BUCKETS`], under the same blind); for every custodian i, its line shares are the evaluations at i + 1 of
/// degree-t polynomials whose constants are `a` on the named line and 0 on every other, and they open the commitment the
/// order carries for it. A custodian that opens its commitment holds correct shares without learning `a` or the bucket.
#[must_use]
pub fn order_share_circuit(d: &OrderDealing) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    let t = d.coeffs.first().map_or(0, Vec::len);
    if d.bucket >= ORDER_BUCKETS || d.coeffs.len() != ORDER_LINES || d.coeffs.iter().any(|c| c.len() != t) || (d.cover.is_some() && d.amount != 0) || (d.deposit && !d.on_x) {
        return None;
    }
    if d.index >> INDEX_BITS != 0 {
        return None;
    }
    if let Some(pos) = &d.withdraw {
        // a withdrawal spends a position, never a note: no side, no deposit, no cover; its units within the position's
        if d.on_x || d.deposit || d.cover.is_some() || pos.bucket >= ORDER_BUCKETS as u64 || pos.j_min > ORDER_BUCKETS as u64 || pos.now >> INDEX_BITS != 0 || pos.entry >> INDEX_BITS != 0 {
            return None;
        }
    }
    let commits = d.share_commits();
    let (_, nf, lc) = d.spend_publics();
    let io = order_share_io(&d.amount_commit(), &d.limit_commit(), &commits, &d.binding, &nf, &lc, d.index);
    let n = d.salts.len();
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let (an, al16) = value_from_bits(&mut b, d.amount);
        let ab: [Lc; 8] = core::array::from_fn(|i| b.witness(Fa4::from_u64(d.amount_blind[i])));
        let c = commit_gadget(&mut b, &al16, &ab);
        for (i, ci) in c.iter().enumerate() {
            let x = b.io(i);
            b.enforce_eq(ci, &x);
        }
        // ⭐ §18.14 — THE SIDE, HIDDEN: v = 1 sells X, v = 0 buys X with Y
        let v_side = b.witness(Fa4::from_u64(u64::from(d.on_x)));
        b.constrain(&v_side, &v_side, &v_side);
        // ⭐ EARN STEP 2 — THE DEPOSIT BIT, HIDDEN: w = 1 deposits SAT (only with v = 1: `w·(1 − v) = 0`), and its amount is
        // the sum of its two halves: `a = 2·h + o`, h a 64-bit value and o a bit, so h = ⌊a/2⌋
        let w_dep = b.witness(Fa4::from_u64(u64::from(d.deposit)));
        b.constrain(&w_dep, &w_dep, &w_dep);
        let not_v_dep = Lc::constant(Fa4::ONE).add(&v_side.scale(Fa4::ZERO - Fa4::ONE));
        b.constrain(&w_dep, &not_v_dep, &Lc::constant(Fa4::ZERO));
        let (hn, _) = value_from_bits(&mut b, d.amount / 2);
        let odd = b.witness(Fa4::from_u64(d.amount & 1));
        b.constrain(&odd, &odd, &odd);
        let odd_nn = Nn(std::iter::once(odd.clone()).chain((1..LIMBS).map(|_| Lc::constant(Fa4::ZERO))).collect());
        let twice = hn.lin(&[(&odd_nn, 1)], 2, &mut b);
        twice.enforce_eq(&an, &mut b);
        // ⭐ EARN STEP 2 PIECE 3 — THE WITHDRAWAL BIT, HIDDEN: z = 1 spends a POSITION (no note; no side, no deposit:
        // `z·v = 0`, `z·w = 0`), its units the order's amount
        let z_w = b.witness(Fa4::from_u64(u64::from(d.withdraw.is_some())));
        b.constrain(&z_w, &z_w, &z_w);
        b.constrain(&z_w, &v_side, &Lc::constant(Fa4::ZERO));
        b.constrain(&z_w, &w_dep, &Lc::constant(Fa4::ZERO));
        let not_z = Lc::constant(Fa4::ONE).add(&z_w.scale(Fa4::ZERO - Fa4::ONE));
        // THE POSITION: its leaf re-derived from the order that made it (a deposit that COUNTED, or a withdrawal whose batch
        // paid nothing) and the prices its batch named, under the position nullifier; a dummy (x = 0, s = (0, 1)) when z = 0,
        // every bound below gated by z
        let pos = d.withdraw.clone().unwrap_or(PositionWitness {
            x: 0,
            x_blind: [0; 8],
            bucket: 0,
            from_withdrawal: false,
            entry: 0,
            now: 0,
            p_num: 1,
            p_den: 1,
            j_min: 0,
            s_num: 0,
            s_den: 1,
            extra: LeafExtra::default(),
        });
        let (pleaf, pnf, wui, lim_lo, lim_hi) = {
            let w8p = |b: &mut R1csBuilder, v: &[u64; 8]| -> [Lc; 8] { core::array::from_fn(|i| b.witness(Fa4::from_u64(v[i]))) };
            let linb = |bits: &[Lc]| bits.iter().enumerate().fold(Lc::constant(Fa4::ZERO), |a, (i, x)| a.add(&x.scale(Fa4::from_u64(1 << i))));
            let (xn, xl16) = value_from_bits(&mut b, pos.x);
            let xbl = w8p(&mut b, &pos.x_blind);
            let pbc = commit_gadget(&mut b, &xl16, &xbl);
            let fw = b.witness(Fa4::from_u64(u64::from(pos.from_withdrawal)));
            b.constrain(&fw, &fw, &fw);
            let pbk = bit_wires(&mut b, u128::from(pos.bucket), 2);
            let pcode = linb(&pbk).add(&Lc::constant(Fa4::from_u64(kind_code(0, true, true)))).add(&fw.scale(Fa4::from_u64(SELL_BUCKET_BASE)));
            // the position's order names its entry in its limit lanes (a deposit's: its batch's opening index; a carried
            // withdrawal's: its own), and a carried withdrawal its own "now" beside it (a deposit's "now" lanes are 0)
            let elo = bit_wires(&mut b, u128::from(pos.entry & ((1 << 30) - 1)), 30);
            let ehi = bit_wires(&mut b, u128::from(pos.entry >> 30), 30);
            let (elo_l, ehi_l) = (linb(&elo), linb(&ehi));
            let nlo = bit_wires(&mut b, u128::from(pos.now & ((1 << 30) - 1)), 30);
            let nhi = bit_wires(&mut b, u128::from(pos.now >> 30), 30);
            let fn_lo = b.mul(&fw, &linb(&nlo));
            let fn_hi = b.mul(&fw, &linb(&nhi));
            let plim = limit_gadget_x(&mut b, &pcode, &xbl, [&elo_l, &ehi_l], [&fn_lo, &fn_hi]);
            let ppb = bit_wires(&mut b, pos.p_num, 128);
            let pdb = bit_wires(&mut b, pos.p_den, 128);
            let psn = bit_wires(&mut b, pos.s_num, 128);
            let psd = bit_wires(&mut b, pos.s_den, 128);
            let (_, ppl) = value_of_bits(&ppb);
            let (_, pdl) = value_of_bits(&pdb);
            let (snn, psnl) = value_of_bits(&psn);
            let (sdn, psdl) = value_of_bits(&psd);
            let l8 = |v: &[Lc]| -> [Lc; 8] { core::array::from_fn(|i| v[i].clone()) };
            let pbuy = pair_gadget(&mut b, &l8(&ppl), &l8(&pdl));
            let psell = pair_gadget(&mut b, &l8(&psnl), &l8(&psdl));
            let pprice = pair_gadget(&mut b, &pbuy, &psell);
            let pjm = bit_wires(&mut b, u128::from(pos.j_min), 3);
            let psf = b.witness(Fa4::from_u64(u64::from(pos.s_num != 0)));
            b.constrain(&psf, &psf, &psf);
            // the leaf's deposit lane: 1 at a deposit batch whose sells counted (where a deposit's SAT joined the pool)
            let pdep = b.witness(Fa4::from_u64(u64::from(pos.extra.dep)));
            b.constrain(&pdep, &pdep, &pdep);
            // a position is never an Earn leaf (that batch already paid it): its lane is 0
            let pjl: [Lc; 8] = core::array::from_fn(|i| match i {
                0 => linb(&pjm),
                1 => psf.clone(),
                3 => pdep.clone(),
                _ => Lc::constant(Fa4::ZERO),
            });
            let ptick = pair_gadget(&mut b, &pprice, &pjl);
            let porder = pair_gadget(&mut b, &pbc, &plim);
            let pleaf = pair_gadget(&mut b, &porder, &ptick);
            let pdom: [Lc; 8] = core::array::from_fn(|i| Lc::constant(Fa4::from_u64(POSITION_NF_DOMAIN[i])));
            let pnf = pair_gadget(&mut b, &xbl, &pdom);
            // the units it may take: a deposit's u ≤ q/√p_t, `u²·s_num ≤ q²·s_den`, with q = ⌊(h − ⌈h·f⌉)·s_num/s_den⌋,
            // h = ⌊x/2⌋, and only where it counted (`sfill = 1`); a carried withdrawal's u ≤ its own units
            let not_fw = Lc::constant(Fa4::ONE).add(&fw.scale(Fa4::ZERO - Fa4::ONE));
            let zd = b.mul(&z_w, &not_fw);
            let not_psf = Lc::constant(Fa4::ONE).add(&psf.scale(Fa4::ZERO - Fa4::ONE));
            b.constrain(&zd, &not_psf, &Lc::constant(Fa4::ZERO));
            // ⭐ Earn step 3 — and only where its batch was a DEPOSIT batch (its leaf's deposit lane): a deposit anywhere else
            // came back whole and is no position
            let not_pdep = Lc::constant(Fa4::ONE).add(&pdep.scale(Fa4::ZERO - Fa4::ONE));
            b.constrain(&zd, &not_pdep, &Lc::constant(Fa4::ZERO));
            let (hn2, _) = value_from_bits(&mut b, pos.x / 2);
            let odd2 = b.witness(Fa4::from_u64(pos.x & 1));
            b.constrain(&odd2, &odd2, &odd2);
            let odd2_nn = Nn(std::iter::once(odd2.clone()).chain((1..LIMBS).map(|_| Lc::constant(Fa4::ZERO))).collect());
            hn2.lin(&[(&odd2_nn, 1)], 2, &mut b).enforce_eq(&xn, &mut b);
            let (phn, _) = value_from_bits(&mut b, claim_fee(pos.x / 2));
            let fee_h = lin_small(&mut b, None, &[(&phn, 1 << (FEE_SHIFT as usize - LIMB_BITS), 1), (&hn2, -(FEE_NUM as i64), 0)]);
            fee_h.enforce_below_pow2(FEE_SHIFT as usize, &mut b);
            let q_v = if pos.s_num == 0 { 0 } else { claim_out(pos.x / 2 - claim_fee(pos.x / 2), pos.s_num, pos.s_den).unwrap_or(0) };
            let (qn, _) = value_from_bits(&mut b, q_v);
            let h_net = hn2.sub(&phn, &mut b);
            let e = h_net.mul(&snn, &mut b).sub(&qn.mul(&sdn, &mut b), &mut b);
            e.enforce_below_pow2(128, &mut b);
            sdn.lin(&[(&e, -1)], 1, &mut b).sub(&Nn::constant(&fsmall(1)), &mut b).enforce_below_pow2(128, &mut b);
            let ud = nn_select(&mut b, &an, &zd);
            let lhs = ud.mul(&ud, &mut b).mul(&snn, &mut b);
            let rhs = qn.mul(&qn, &mut b).mul(&sdn, &mut b);
            rhs.sub(&lhs, &mut b).enforce_below_pow2(220, &mut b);
            let zf = b.mul(&z_w, &fw);
            let uf = nn_select(&mut b, &an, &zf);
            xn.sub(&uf, &mut b).enforce_below_pow2(64, &mut b);
            // step 3's entry index of the new withdrawal: its position's own (the position order's limit lanes, whichever kind
            // made it); its units × that entry is dealt on the index line
            let ie_b: Vec<Lc> = elo.iter().chain(&ehi).cloned().collect();
            let (ie_nn, _) = value_of_bits(&ie_b);
            let uz = nn_select(&mut b, &an, &z_w);
            let wui = uz.mul(&ie_nn, &mut b);
            // the new withdrawal's own entry lanes: its position's entry, 0 for every other order
            let lim_lo = b.mul(&z_w, &elo_l);
            let lim_hi = b.mul(&z_w, &ehi_l);
            (pleaf, pnf, wui, lim_lo, lim_hi)
        };
        // ⭐ §18.12 — the spend of the order's note: spk = P(ask, nk), o = P(spk, seed), cm = asset_note_cm(a, the side's asset, o),
        // nf = P(nk, cm), lc = P(P(cm, nf), lc_blind) — the amount on the note IS the amount dealt (the same limbs)
        {
            let w8 = |b: &mut R1csBuilder, v: &[u64; 8]| -> [Lc; 8] { core::array::from_fn(|i| b.witness(Fa4::from_u64(v[i]))) };
            let z = || Lc::constant(Fa4::ZERO);
            let (ask, nk, seed) = (w8(&mut b, &d.owner[0]), w8(&mut b, &d.owner[1]), w8(&mut b, &d.owner[2]));
            let lcb = w8(&mut b, &d.lc_blind);
            let spk = pair_gadget(&mut b, &ask, &nk);
            let o = pair_gadget(&mut b, &spk, &seed);
            // ⭐ §18.14 — the spent note's asset by the hidden side: v·x_tag + (1 − v)·y_tag (linear: the tags are public constants of the pair's circuit)
            let (tx, ty) = (crate::poseidon2_compress::lanes_of(&d.x_tag), crate::poseidon2_compress::lanes_of(&d.y_tag));
            let tag: [Lc; 8] = core::array::from_fn(|i| {
                v_side.scale(Fa4::from_u64(tx[i])).add(&Lc::constant(Fa4::ONE).add(&v_side.scale(Fa4::ZERO - Fa4::ONE)).scale(Fa4::from_u64(ty[i])))
            });
            let inner = pair_gadget(&mut b, &tag, &o);
            let lanes: [Lc; 8] = core::array::from_fn(|i| if i < 4 { al16[i].clone() } else { z() });
            let cm_real = pair_gadget(&mut b, &lanes, &inner);
            let nf_real = pair_gadget(&mut b, &nk, &cm_real);
            // the branch: s = 1 spends the note above; s = 0 is a COVER — amount 0 (every limb times (1 − s) is 0), and the
            // leaf and nullifier the leg binds are free witnesses
            let s = b.witness(Fa4::from_u64(u64::from(d.cover.is_none())));
            b.constrain(&s, &s, &s);
            let not_s = Lc::constant(Fa4::ONE).add(&s.scale(Fa4::ZERO - Fa4::ONE));
            for l in al16.iter() {
                b.constrain(l, &not_s, &z());
            }
            let (free_cm, free_secret) = d.cover.unwrap_or((d.spend_publics().0, [0; 8]));
            let fc = w8(&mut b, &free_cm);
            let fs = w8(&mut b, &free_secret);
            let dom: [Lc; 8] = core::array::from_fn(|i| Lc::constant(Fa4::from_u64(ORDER_COVER_DOMAIN[i])));
            let fnf = pair_gadget(&mut b, &fs, &dom);
            let sel = |b: &mut R1csBuilder, real: &[Lc; 8], free: &[Lc; 8]| -> [Lc; 8] {
                core::array::from_fn(|i| {
                    let diff = real[i].add(&free[i].scale(Fa4::ZERO - Fa4::ONE));
                    let m = b.mul(&s, &diff);
                    free[i].add(&m)
                })
            };
            let cm = sel(&mut b, &cm_real, &fc);
            let nfw = sel(&mut b, &nf_real, &fnf);
            // ⭐ a withdrawal binds its POSITION's leaf and nullifier instead (z selects)
            let zsel = |b: &mut R1csBuilder, pos_v: &[Lc; 8], other: &[Lc; 8]| -> [Lc; 8] {
                core::array::from_fn(|i| {
                    let diff = pos_v[i].add(&other[i].scale(Fa4::ZERO - Fa4::ONE));
                    let m = b.mul(&z_w, &diff);
                    other[i].add(&m)
                })
            };
            let cm = zsel(&mut b, &pleaf, &cm);
            let nfw = zsel(&mut b, &pnf, &nfw);
            let x = pair_gadget(&mut b, &cm, &nfw);
            let lcw = pair_gadget(&mut b, &x, &lcb);
            let off = 17 + 4 * n + 8;
            for i in 0..8 {
                let (wn, wl) = (b.io(off + i), b.io(off + 8 + i));
                b.enforce_eq(&nfw[i], &wn);
                b.enforce_eq(&lcw[i], &wl);
            }
        }
        // the bucket, one-hot: h_j bits summing to 1, bucket = Σ j·h_j, opening the limit commitment
        let h: Vec<Lc> = (0..ORDER_BUCKETS)
            .map(|j| {
                let w = b.witness(Fa4::from_u64(u64::from(j == d.bucket)));
                b.constrain(&w, &w, &w);
                w
            })
            .collect();
        let one_hot = h.iter().fold(Lc::constant(Fa4::ZERO), |a, x| a.add(x));
        b.enforce_eq(&one_hot, &Lc::constant(Fa4::ONE));
        let bucket = h.iter().enumerate().fold(Lc::constant(Fa4::ZERO), |a, (j, x)| a.add(&x.scale(Fa4::from_u64(j as u64))));
        // the kind's code ([`kind_code`]): + SELL_BUCKET_BASE for a sell, + SELL_BUCKET_BASE more for a deposit
        let side_b = bucket
            .add(&v_side.scale(Fa4::from_u64(SELL_BUCKET_BASE)))
            .add(&w_dep.scale(Fa4::from_u64(SELL_BUCKET_BASE)))
            .add(&z_w.scale(Fa4::from_u64(WITHDRAW_BUCKET_BASE)));
        // ⭐ Earn step 3 — the order's own index lanes from its PUBLIC batch index (the io's last two lanes): a deposit's entry
        // is the batch's index (`w·idx`), a withdrawal's entry is its position's and its "now" the batch's (`z·idx`); a
        // trade's lanes are 0
        let idx_off = 17 + 4 * n + 24;
        let (ix_lo, ix_hi) = (b.io(idx_off), b.io(idx_off + 1));
        let dix_lo = b.mul(&w_dep, &ix_lo);
        let dix_hi = b.mul(&w_dep, &ix_hi);
        let ent_lo = dix_lo.add(&lim_lo);
        let ent_hi = dix_hi.add(&lim_hi);
        let now_lo = b.mul(&z_w, &ix_lo);
        let now_hi = b.mul(&z_w, &ix_hi);
        let lim = limit_gadget_x(&mut b, &side_b, &ab, [&ent_lo, &ent_hi], [&now_lo, &now_hi]);
        for (i, li) in lim.iter().enumerate() {
            let x = b.io(9 + i);
            b.enforce_eq(li, &x);
        }
        let zero = Nn::constant(&[0; 4]);
        let _ = &zero;
        let not_v = Lc::constant(Fa4::ONE).add(&v_side.scale(Fa4::ZERO - Fa4::ONE));
        let not_dep = Lc::constant(Fa4::ONE).add(&w_dep.scale(Fa4::ZERO - Fa4::ONE));
        let sell_only = b.mul(&v_side, &not_dep);
        let rest = an.sub(&hn, &mut b);
        let consts: Vec<Nn> = (0..ORDER_LINES)
            .map(|l| {
                if l == 0 {
                    nn_select(&mut b, &an, &sell_only)
                } else if l <= ORDER_BUCKETS {
                    let on_v = b.mul(&h[l - 1], &not_v);
                    let on = b.mul(&on_v, &not_z);
                    nn_select(&mut b, &an, &on)
                } else if l == DEPOSIT_SOLD_LINE {
                    nn_select(&mut b, &hn, &w_dep)
                } else if l == DEPOSIT_JOIN_LINE {
                    nn_select(&mut b, &rest, &w_dep)
                } else if l == WITHDRAW_UNITS_LINE {
                    nn_select(&mut b, &an, &z_w)
                } else {
                    // WITHDRAW_INDEX_LINE: units × the position's income index (0 for every other order)
                    wui.clone()
                }
            })
            .collect();
        let cs: Vec<Vec<Nn>> = d.coeffs.iter().map(|line| line.iter().map(|v| Nn::alloc(&mut b, v)).collect()).collect();
        let horner = |b: &mut R1csBuilder, c0: &Nn, cs: &[Nn], x: i64| -> Nn {
            let Some(top) = cs.last() else { return c0.clone() };
            let mut acc = top.clone();
            for k in (0..cs.len() - 1).rev() {
                acc = lin_small(b, None, &[(&acc, x, 0), (&cs[k], 1, 0)]);
            }
            lin_small(b, None, &[(&acc, x, 0), (c0, 1, 0)])
        };
        for (i, salt) in d.salts.iter().enumerate() {
            let x = (i + 1) as i64;
            let shares: Vec<Nn> = (0..ORDER_LINES).map(|l| horner(&mut b, &consts[l], &cs[l], x)).collect();
            let sw: [Lc; 4] = core::array::from_fn(|k| b.witness(salt[k]));
            let hc = chain_commit_w(&shares, &sw, &mut b);
            for k in 0..4 {
                let want = b.io(17 + 4 * i + k);
                b.enforce_eq(&hc[k], &want);
            }
        }
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, w)| (r, io.clone(), w))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S ORDER-SHARE CIRCUIT for a roster of `n` at threshold `t` (a buy: the amount on a Y line), formed over an
/// all-zero dealing — the shape depends only on (n, t).
#[must_use]
pub fn order_share_r1cs(n: usize, t: usize, x_tag: [u64; 3], y_tag: [u64; 3]) -> Option<crate::spartan_ccs::R1cs> {
    let dummy = OrderDealing {
        amount: 0,
        amount_blind: [0; 8],
        bucket: 0,
        on_x: false,
        deposit: false,
        withdraw: None,
        x_tag,
        y_tag,
        coeffs: vec![vec![[0; 4]; t]; ORDER_LINES],
        salts: vec![[Fa4::ZERO; 4]; n],
        binding: [0; 8],
        owner: [[0; 8]; 3],
        lc_blind: [0; 8],
        cover: None,
        index: 0,
    };
    order_share_circuit(&dummy).map(|(r, _, _)| r)
}

// ───────────────────────────── the keyless launch position (spec §18.3, §18.10) ─────────────────────────────

/// ⭐ THE LAUNCH POSITION'S DEALING (spec §18.13 — the PUBLIC donation, user 2026-11-02: "lets let the first sat pool be a
/// public donation"): the position note `asset_note_cm(position, tag, sk)` holds the SAT the genesis split moved into it, and
/// the pool is a full-range constant-product curve on exactly those SAT at the launch price `price = (num, den)` (USDm per SAT,
/// atomic units): X = position, Y = ⌊position · num / den⌋, and the floors F_X = 0 (only real SAT is ever sold, and on a
/// full-range curve the price grows without bound as X → 0, so the pool is never bought out) and F_Y = Y (the virtual USDm is
/// never paid). Each line a degree-t sharing, one salt per custodian. The position is PUBLIC — a public input of the proof.
#[derive(Clone, Debug)]
pub struct PoolDealing {
    pub position: u64,
    pub sk: [u64; 8],
    pub tag: [u64; 3],
    pub price: (u64, u64),
    /// one coefficient vector per pool line (X, Y, F_X, F_Y), each of length t
    pub coeffs: Vec<Vec<F>>,
    pub salts: Vec<[Fa4; 4]>,
}

impl PoolDealing {
    /// The virtual Y at the launch price: `⌊position · num / den⌋`.
    #[must_use]
    pub fn y0(&self) -> u64 {
        claim_out(self.position, u128::from(self.price.0), u128::from(self.price.1)).unwrap_or(0)
    }
    /// The pool's four lines' constants `(X, Y, F_X, F_Y)`.
    #[must_use]
    pub fn lines(&self) -> [u64; POOL_LINES] {
        let y0 = self.y0();
        [self.position, y0, 0, y0]
    }
    /// Custodian `i`'s (at x = i + 1) shares of the four lines.
    #[must_use]
    pub fn shares(&self, i: usize) -> [F; POOL_LINES] {
        let x = (i + 1) as u64;
        let c = self.lines();
        core::array::from_fn(|l| poly_eval(&std::iter::once(fsmall(c[l])).chain(self.coeffs[l].iter().copied()).collect::<Vec<_>>(), x))
    }
    /// Every custodian's pool commitment (the book's genesis `pool_commits`).
    #[must_use]
    pub fn share_commits(&self) -> Vec<[Fa4; 4]> {
        (0..self.salts.len()).map(|i| chain_commit(&self.shares(i), &self.salts[i])).collect()
    }
    /// The position note's commitment.
    #[must_use]
    pub fn position_cm(&self) -> [u64; 8] {
        crate::whir_rec_block::asset_note_cm(self.position, self.tag, self.sk)
    }
}

/// The public input of the launch position's proof: the position note's commitment, the PUBLIC position as its four 16-bit
/// limbs (the limbs the commitment is built from), then each custodian's pool commitment.
#[must_use]
pub fn pool_open_io(position_cm: &[u64; 8], position: u64, commits: &[[Fa4; 4]]) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = position_cm.iter().map(|v| Fa4::from_u64(*v)).collect();
    io.extend((0..4).map(|k| Fa4::from_u64((position >> (16 * k)) & 0xFFFF)));
    for c in commits {
        io.extend_from_slice(c);
    }
    io
}

/// ⭐⭐ THE LAUNCH POSITION'S PROOF (spec §18.13): the position note `asset_note_cm(P, tag, sk)` holds the PUBLIC `P` (its
/// 16-bit limbs are the public input's); `0 ≤ P·num − Y·den < den`; and the roster's pool shares are the evaluations at i + 1
/// of degree-t polynomials with constants `(P, Y, 0, Y)` — so the pool the custody set starts from sells exactly the SAT the
/// genesis split moved into the position, along the full-range curve of its own depth at the launch price. The price and
/// the tag are the shape's constants (the verifier forms the same circuit).
#[must_use]
pub fn pool_open_circuit(d: &PoolDealing) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    let t = d.coeffs.first().map_or(0, Vec::len);
    if d.coeffs.len() != POOL_LINES || d.coeffs.iter().any(|c| c.len() != t) || d.price.1 == 0 {
        return None;
    }
    let commits = d.share_commits();
    let io = pool_open_io(&d.position_cm(), d.position, &commits);
    let lines = d.lines();
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let (vn, pl16) = value_from_bits(&mut b, d.position);
        for (k, limb) in pl16.iter().enumerate() {
            let x = b.io(8 + k);
            b.enforce_eq(limb, &x);
        }
        let (yn, _) = value_from_bits(&mut b, lines[1]);
        let sk: [Lc; 8] = core::array::from_fn(|i| b.witness(Fa4::from_u64(d.sk[i])));
        let tag: [Lc; 8] = core::array::from_fn(|i| Lc::constant(Fa4::from_u64(if i < 3 { d.tag[i] } else { 0 })));
        let inner = pair_gadget(&mut b, &tag, &sk);
        let lo: [Lc; 8] = core::array::from_fn(|i| if i < 4 { pl16[i].clone() } else { Lc::constant(Fa4::ZERO) });
        let cm = pair_gadget(&mut b, &lo, &inner);
        for (i, ci) in cm.iter().enumerate() {
            let x = b.io(i);
            b.enforce_eq(ci, &x);
        }
        // Y is the launch price's: 0 ≤ e = V·num − Y·den < den
        let e = vn.scale_const(&fsmall(d.price.0), &mut b).sub(&yn.scale_const(&fsmall(d.price.1), &mut b), &mut b);
        e.enforce_below_pow2(128, &mut b);
        let gap = Nn::constant(&fsmall(d.price.1 - 1)).sub(&e, &mut b);
        gap.enforce_below_pow2(128, &mut b);
        let consts = [vn, yn.clone(), Nn::constant(&[0; 4]), yn];
        let cs: Vec<Vec<Nn>> = d.coeffs.iter().map(|line| line.iter().map(|v| Nn::alloc(&mut b, v)).collect()).collect();
        let horner = |b: &mut R1csBuilder, c0: &Nn, cs: &[Nn], x: i64| -> Nn {
            let Some(top) = cs.last() else { return c0.clone() };
            let mut acc = top.clone();
            for k in (0..cs.len() - 1).rev() {
                acc = lin_small(b, None, &[(&acc, x, 0), (&cs[k], 1, 0)]);
            }
            lin_small(b, None, &[(&acc, x, 0), (c0, 1, 0)])
        };
        for (i, salt) in d.salts.iter().enumerate() {
            let x = (i + 1) as i64;
            let shares: Vec<Nn> = (0..POOL_LINES).map(|l| horner(&mut b, &consts[l], &cs[l], x)).collect();
            let sw: [Lc; 4] = core::array::from_fn(|k| b.witness(salt[k]));
            let hc = chain_commit_w(&shares, &sw, &mut b);
            for k in 0..4 {
                let want = b.io(12 + 4 * i + k);
                b.enforce_eq(&hc[k], &want);
            }
        }
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, w)| (r, io.clone(), w))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S LAUNCH-POSITION CIRCUIT for `n` custodians at threshold `t`, the launch price and the tag — formed over an
/// all-zero dealing (the shape depends only on these).
#[must_use]
pub fn pool_open_r1cs(n: usize, t: usize, price: (u64, u64), tag: [u64; 3]) -> Option<crate::spartan_ccs::R1cs> {
    if price.1 == 0 {
        return None;
    }
    let dummy = PoolDealing { position: 0, sk: [0; 8], tag, price, coeffs: vec![vec![[0; 4]; t]; POOL_LINES], salts: vec![[Fa4::ZERO; 4]; n] };
    pool_open_circuit(&dummy).map(|(r, _, _)| r)
}

// ───────────────────────────── the custody handover (spec §18.11) ─────────────────────────────

/// ⭐ ONE OLD CUSTODIAN'S HANDOVER DEALING (Herzberg–Jarecki–Krawczyk–Yung 1995 / Desmedt–Jajodia 1997 redistribution,
/// borrowed): its four pool-line shares AND its fee-line share (Earn step 1), re-shared among the NEW roster on degree-t'
/// polynomials whose constants are those shares, one salt per new custodian. Its proof shows the constants are exactly what
/// its own pool commitment and its own fee commitment hold — a handover moves the fees the pool has taken with the pool, so a
/// roster change never drops (or invents) a unit of the providers' income.
#[derive(Clone, Debug)]
pub struct HandoverDealing {
    /// the dealer's state shares — the pool's [`POOL_LINES`], then the fee state's [`FEE_LINES`], then the closed window's
    /// [`CLOSE_LINES`] — and the salts of its pool, fee and close commitments (the book's)
    pub lines: [F; STATE_LINES],
    pub salt: [Fa4; 4],
    pub fee_salt: [Fa4; 4],
    pub close_salt: [Fa4; 4],
    /// one coefficient vector per line, each of length t'
    pub coeffs: Vec<Vec<F>>,
    /// one salt per NEW custodian
    pub salts: Vec<[Fa4; 4]>,
    /// the dealing's carried bytes (its sealed sub-shares), as 30-bit lanes the transcript absorbs
    pub binding: [u64; 8],
}

/// ⭐ What a custodian holds and a handover re-shares: the pool's [`POOL_LINES`], the fee state's [`FEE_LINES`] and the
/// closed window's [`CLOSE_LINES`] (Earn steps 1 + 3). A sealed sub-share carries all of them in the one sealed-share shape
/// of [`ORDER_LINES`] slots.
pub const STATE_LINES: usize = POOL_LINES + FEE_LINES + CLOSE_LINES;
const _: () = assert!(STATE_LINES <= ORDER_LINES, "a custodian's state fits the one sealed-share shape");
/// Where the fee state and the closed lines sit among the [`STATE_LINES`].
pub const FEE_AT: usize = POOL_LINES;
pub const CLOSE_AT: usize = POOL_LINES + FEE_LINES;

impl HandoverDealing {
    /// New custodian `j`'s (at x = j + 1) sub-shares of the dealer's state lines.
    #[must_use]
    pub fn shares(&self, j: usize) -> [F; STATE_LINES] {
        let x = (j + 1) as u64;
        core::array::from_fn(|l| poly_eval(&std::iter::once(self.lines[l]).chain(self.coeffs[l].iter().copied()).collect::<Vec<_>>(), x))
    }
    /// The sub-share commitment for each new custodian.
    #[must_use]
    pub fn sub_commits(&self) -> Vec<[Fa4; 4]> {
        (0..self.salts.len()).map(|j| chain_commit(&self.shares(j), &self.salts[j])).collect()
    }
    /// The dealer's pool, fee and close commitments (what the book holds for it).
    #[must_use]
    pub fn commits(&self) -> ([Fa4; 4], [Fa4; 4], [Fa4; 4]) {
        let (pool, fee, close) = split_state(&self.lines);
        (chain_commit(&pool, &self.salt), fee_commit(&fee, &self.fee_salt), close_commit(&close, &self.close_salt))
    }
}

/// A custodian's state lines split into the pool's, the fee state's and the closed window's.
#[must_use]
pub fn split_state(lines: &[F; STATE_LINES]) -> ([F; POOL_LINES], [F; FEE_LINES], [F; CLOSE_LINES]) {
    (core::array::from_fn(|l| lines[l]), core::array::from_fn(|l| lines[FEE_AT + l]), core::array::from_fn(|l| lines[CLOSE_AT + l]))
}

/// The public input of a handover dealing: the dealer's pool, fee and close commitments, each sub-share commitment, the
/// binding.
#[must_use]
pub fn handover_deal_io(pool_commit: &[Fa4; 4], fee_commit: &[Fa4; 4], close_commit: &[Fa4; 4], subs: &[[Fa4; 4]], binding: &[u64; 8]) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = pool_commit.to_vec();
    io.extend_from_slice(fee_commit);
    io.extend_from_slice(close_commit);
    for c in subs {
        io.extend_from_slice(c);
    }
    io.extend(binding.iter().map(|v| Fa4::from_u64(*v & ((1 << 30) - 1))));
    io
}

/// ⭐⭐ THE HANDOVER DEALING PROOF: the dealer's four line shares open ITS pool commitment, and for every new custodian j the
/// sub-shares are the evaluations at j + 1 of degree-t' polynomials whose constants are those line shares, opening the
/// sub-share commitment the dealing carries for j. A dealer cannot hand over anything but the shares it holds.
#[must_use]
pub fn handover_deal_circuit(d: &HandoverDealing) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    let t = d.coeffs.first().map_or(0, Vec::len);
    if d.coeffs.len() != STATE_LINES || d.coeffs.iter().any(|c| c.len() != t) || d.salts.is_empty() {
        return None;
    }
    let (pool_c, fee_c, close_c) = d.commits();
    let io = handover_deal_io(&pool_c, &fee_c, &close_c, &d.sub_commits(), &d.binding);
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let lines: Vec<Nn> = d.lines.iter().map(|v| Nn::alloc(&mut b, v)).collect();
        // the pool's lines open the dealer's pool commitment, the fee state its fee commitment, the closed lines its close
        // commitment
        let sw: [Lc; 4] = core::array::from_fn(|k| b.witness(d.salt[k]));
        let pc = chain_commit_w(&lines[..FEE_AT], &sw, &mut b);
        let fw: [Lc; 4] = core::array::from_fn(|k| b.witness(d.fee_salt[k]));
        let fc = chain_commit_w(&lines[FEE_AT..CLOSE_AT], &fw, &mut b);
        let cw: [Lc; 4] = core::array::from_fn(|k| b.witness(d.close_salt[k]));
        let cc = chain_commit_w(&lines[CLOSE_AT..], &cw, &mut b);
        for (k, c) in pc.iter().chain(fc.iter()).chain(cc.iter()).enumerate() {
            let x = b.io(k);
            b.enforce_eq(c, &x);
        }
        let cs: Vec<Vec<Nn>> = d.coeffs.iter().map(|line| line.iter().map(|v| Nn::alloc(&mut b, v)).collect()).collect();
        let horner = |b: &mut R1csBuilder, c0: &Nn, cs: &[Nn], x: i64| -> Nn {
            let Some(top) = cs.last() else { return c0.clone() };
            let mut acc = top.clone();
            for k in (0..cs.len() - 1).rev() {
                acc = lin_small(b, None, &[(&acc, x, 0), (&cs[k], 1, 0)]);
            }
            lin_small(b, None, &[(&acc, x, 0), (c0, 1, 0)])
        };
        for (j, salt) in d.salts.iter().enumerate() {
            let x = (j + 1) as i64;
            let subs: Vec<Nn> = (0..STATE_LINES).map(|l| horner(&mut b, &lines[l], &cs[l], x)).collect();
            let s: [Lc; 4] = core::array::from_fn(|k| b.witness(salt[k]));
            let hc = chain_commit_w(&subs, &s, &mut b);
            for k in 0..4 {
                let want = b.io(12 + 4 * j + k);
                b.enforce_eq(&hc[k], &want);
            }
        }
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, w)| (r, io.clone(), w))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S HANDOVER DEALING CIRCUIT for a new roster of `n_new` at threshold `t_new` (the shape depends only on these).
#[must_use]
pub fn handover_deal_r1cs(n_new: usize, t_new: usize) -> Option<crate::spartan_ccs::R1cs> {
    let dummy = HandoverDealing {
        lines: [[0; 4]; STATE_LINES],
        salt: [Fa4::ZERO; 4],
        fee_salt: [Fa4::ZERO; 4],
        close_salt: [Fa4::ZERO; 4],
        coeffs: vec![vec![[0; 4]; t_new]; STATE_LINES],
        salts: vec![[Fa4::ZERO; 4]; n_new],
        binding: [0; 8],
    };
    handover_deal_circuit(&dummy).map(|(r, _, _)| r)
}

/// The Lagrange coefficients at 0 over the old roster's points x = 1..=n (every old custodian deals): `λ_i = Π_{k≠i} x_k / (x_k − x_i)`.
#[must_use]
pub fn lagrange_at_zero(n: usize) -> Vec<F> {
    (0..n)
        .map(|i| {
            let xi = fsmall((i + 1) as u64);
            (0..n).filter(|k| *k != i).fold(fsmall(1), |acc, k| {
                let xk = fsmall((k + 1) as u64);
                fmul(&fmul(&acc, &xk), &finv(&fsub(&xk, &xi)))
            })
        })
        .collect()
}

/// ⭐ ONE NEW CUSTODIAN'S HANDOVER ACCEPTANCE: the sub-shares every old custodian dealt it (each with the dealer's salt for
/// it), combined at the old roster's Lagrange coefficients into its new state shares — the pool's lines committed under a
/// fresh salt, the fee state under another, the closed lines under a third (Earn steps 1 + 3).
#[derive(Clone, Debug)]
pub struct HandoverAccept {
    pub subs: Vec<([F; STATE_LINES], [Fa4; 4])>,
    pub new_salt: [Fa4; 4],
    pub new_fee_salt: [Fa4; 4],
    pub new_close_salt: [Fa4; 4],
}

impl HandoverAccept {
    /// The new state shares: `Σ_i λ_i · sub_i` per line.
    #[must_use]
    pub fn lines(&self) -> [F; STATE_LINES] {
        let lam = lagrange_at_zero(self.subs.len());
        core::array::from_fn(|l| self.subs.iter().zip(&lam).fold(fsmall(0), |acc, ((s, _), w)| fadd(&acc, &fmul(w, &s[l]))))
    }
    /// The new pool commitment.
    #[must_use]
    pub fn new_commit(&self) -> [Fa4; 4] {
        chain_commit(&split_state(&self.lines()).0, &self.new_salt)
    }
    /// The new fee commitment.
    #[must_use]
    pub fn new_fee_commit(&self) -> [Fa4; 4] {
        fee_commit(&split_state(&self.lines()).1, &self.new_fee_salt)
    }
    /// The new close commitment.
    #[must_use]
    pub fn new_close_commit(&self) -> [Fa4; 4] {
        close_commit(&split_state(&self.lines()).2, &self.new_close_salt)
    }
}

/// The public input of an acceptance: each dealer's sub-share commitment for this custodian (old roster order), then its new
/// pool, fee and close commitments.
#[must_use]
pub fn handover_accept_io(subs: &[[Fa4; 4]], new_pool: &[Fa4; 4], new_fee: &[Fa4; 4], new_close: &[Fa4; 4]) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = Vec::with_capacity(4 * subs.len() + 12);
    for c in subs {
        io.extend_from_slice(c);
    }
    io.extend_from_slice(new_pool);
    io.extend_from_slice(new_fee);
    io.extend_from_slice(new_close);
    io
}

/// ⭐⭐ THE HANDOVER ACCEPTANCE PROOF: each dealer's sub-shares open the commitment that dealer published for this custodian,
/// and the new pool and fee commitments open exactly `Σ λ_i · sub_i` per line — so the new roster's shares are a degree-t'
/// sharing of the SAME pool and the SAME fee line (no value created or lost by the handover), and no party ever held a line
/// in the clear.
#[must_use]
pub fn handover_accept_circuit(a: &HandoverAccept) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    if a.subs.is_empty() {
        return None;
    }
    let subs_c: Vec<[Fa4; 4]> = a.subs.iter().map(|(l, s)| chain_commit(l, s)).collect();
    let io = handover_accept_io(&subs_c, &a.new_commit(), &a.new_fee_commit(), &a.new_close_commit());
    let lam = lagrange_at_zero(a.subs.len());
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let mut acc: Vec<Option<Nn>> = vec![None; STATE_LINES];
        for (i, (lines, salt)) in a.subs.iter().enumerate() {
            let ns: Vec<Nn> = lines.iter().map(|v| Nn::alloc(&mut b, v)).collect();
            let sw: [Lc; 4] = core::array::from_fn(|k| b.witness(salt[k]));
            let c = chain_commit_w(&ns, &sw, &mut b);
            for k in 0..4 {
                let want = b.io(4 * i + k);
                b.enforce_eq(&c[k], &want);
            }
            for (l, n) in ns.iter().enumerate() {
                let term = n.scale_const(&lam[i], &mut b);
                acc[l] = Some(match acc[l].take() {
                    Some(a0) => a0.add(&term, &mut b),
                    None => term,
                });
            }
        }
        let new_lines: Vec<Nn> = acc.into_iter().map(|x| x.unwrap_or_else(|| Nn::constant(&[0; 4]))).collect();
        let ns: [Lc; 4] = core::array::from_fn(|k| b.witness(a.new_salt[k]));
        let nc = chain_commit_w(&new_lines[..FEE_AT], &ns, &mut b);
        let nfs: [Lc; 4] = core::array::from_fn(|k| b.witness(a.new_fee_salt[k]));
        let nfc = chain_commit_w(&new_lines[FEE_AT..CLOSE_AT], &nfs, &mut b);
        let ncs: [Lc; 4] = core::array::from_fn(|k| b.witness(a.new_close_salt[k]));
        let ncc = chain_commit_w(&new_lines[CLOSE_AT..], &ncs, &mut b);
        let off = 4 * a.subs.len();
        for (k, c) in nc.iter().chain(nfc.iter()).chain(ncc.iter()).enumerate() {
            let want = b.io(off + k);
            b.enforce_eq(c, &want);
        }
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, w)| (r, io.clone(), w))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S HANDOVER ACCEPTANCE CIRCUIT for an old roster of `n_old` (the shape depends only on it).
#[must_use]
pub fn handover_accept_r1cs(n_old: usize) -> Option<crate::spartan_ccs::R1cs> {
    let dummy = HandoverAccept {
        subs: vec![([[0; 4]; STATE_LINES], [Fa4::ZERO; 4]); n_old],
        new_salt: [Fa4::ZERO; 4],
        new_fee_salt: [Fa4::ZERO; 4],
        new_close_salt: [Fa4::ZERO; 4],
    };
    handover_accept_circuit(&dummy).map(|(r, _, _)| r)
}

// ───────────────────────────── the EarnEpoch's audit (Earn step 3) ─────────────────────────────

/// ⭐ The EarnEpoch's statements: the rate's two bounds.
pub const EPOCH_STATEMENTS: usize = 2;
/// The most pairs one EarnEpoch spans: its values are each pair's (E_c, A_c), laid into the batch audit's value vector.
pub const EPOCH_PAIRS_MAX: usize = AUDIT_VALUES / CLOSE_LINES;

/// ⭐⭐ EARN STEP 3 — THE EARNEPOCH'S STATEMENTS over every pair's closed lines (values `2i`, `2i + 1` = pair i's E_c, A_c), at
/// the protocol-wide rate `dg` it opens: 1. `2^K·ΣE_c − dG·2ΣA_c ≥ 0` (the rate pays no more than the window's fees) and
/// 2. `(dG + 1)·2ΣA_c − 1 − 2^K·ΣE_c ≥ 0` (and is the largest that does) — empty at the grid's top ([`EARN_DG_MAX`]), where
/// the rest of the fees stays fresh. `None` past [`EPOCH_PAIRS_MAX`] pairs.
#[must_use]
pub fn epoch_statements(pairs: usize, dg: u64) -> Option<[([F; AUDIT_VALUES], F); EPOCH_STATEMENTS]> {
    if pairs == 0 || pairs > EPOCH_PAIRS_MAX || dg > EARN_DG_MAX {
        return None;
    }
    let z = fsmall(0);
    let k = fsmall(1 << EARN_RATE_BITS);
    let two_dg = fmul(&fsmall(2), &fsmall(dg));
    let two_dg1 = fmul(&fsmall(2), &fsmall(dg + 1));
    let mut lo = [z; AUDIT_VALUES];
    let mut hi = [z; AUDIT_VALUES];
    for i in 0..pairs {
        lo[2 * i] = k;
        lo[2 * i + 1] = fsub(&z, &two_dg);
        hi[2 * i] = fsub(&z, &k);
        hi[2 * i + 1] = two_dg1;
    }
    let upper = if dg == EARN_DG_MAX { ([z; AUDIT_VALUES], z) } else { (hi, fsub(&z, &fsmall(1))) };
    Some([(lo, z), upper])
}

/// The public rate a window's closed totals give: `⌊2^K·F / (2·V)⌋` at most the grid's top, and the top when `V = 0` (no
/// sample was taken, so nothing is allocated whatever the rate). What every custodian's search must land on.
#[must_use]
pub fn epoch_rate(fees: u128, presence: u128) -> u64 {
    if presence == 0 {
        return EARN_DG_MAX;
    }
    let num = u128::from(fees).checked_shl(EARN_RATE_BITS).unwrap_or(u128::MAX);
    u64::try_from(num / (2 * presence)).unwrap_or(EARN_DG_MAX).min(EARN_DG_MAX)
}

/// One custodian's side of an EarnEpoch: its shares of every pair's closed lines and the salt of each close commitment (the
/// books' `close_commits[i]`), the statements' bit-shares and masks, and its phase-1 salt.
#[derive(Clone, Debug)]
pub struct EpochWitness {
    pub close: Vec<([F; CLOSE_LINES], [Fa4; 4])>,
    pub statements: Vec<AuditStatement>,
    pub phase1_salt: [Fa4; 4],
}

fn epoch_values(w: &EpochWitness) -> [F; AUDIT_VALUES] {
    let mut v = [fsmall(0); AUDIT_VALUES];
    for (i, (lines, _)) in w.close.iter().enumerate() {
        v[2 * i] = lines[0];
        v[2 * i + 1] = lines[1];
    }
    v
}

/// The EarnEpoch's phase-1 digest: one Poseidon2 sponge over every statement's bit-shares and masks and the salt.
#[must_use]
pub fn epoch_phase1_digest(w: &EpochWitness) -> [Fa4; 4] {
    use p3_symmetric::Permutation;
    let perm = crate::pow_pq_air::production_perm();
    let mut input: Vec<Fa4> = Vec::new();
    for st in &w.statements {
        for v in st.bits.iter().chain(std::iter::once(&st.w_mask)).chain(&st.s_masks).chain(&st.u_masks) {
            input.extend(limbs_of(&big_from(v)).iter().map(|l| Fa4::from_u64(*l)));
        }
    }
    input.extend_from_slice(&w.phase1_salt);
    let mut st = [Fa4::ZERO; crate::pow_pq_air::WIDTH];
    st[crate::pow_pq_air::WIDTH - 1] = Fa4::from_u64(COMMIT_DOMAIN ^ 0x4550_3100);
    for chunk in input.chunks(RATE) {
        for (i, v) in chunk.iter().enumerate() {
            st[i] += *v;
        }
        perm.permute_mut(&mut st);
    }
    [st[0], st[1], st[2], st[3]]
}

/// What custodian i publishes for each EarnEpoch statement, natively (the circuit proves exactly this).
#[must_use]
pub fn epoch_published(w: &EpochWitness, ch: &AuditChallenges) -> Vec<AuditPublished> {
    let v = epoch_values(w);
    w.statements
        .iter()
        .enumerate()
        .map(|(si, st)| {
            let z = statement_z(st, &v);
            let acc = st.bits.iter().enumerate().fold(fsmall(0), |a, (k, b)| fadd(&a, &fmul(&fpow2(k), b)));
            let wv = fadd(&fsub(&acc, &z), &st.w_mask);
            let s = (0..AUDIT_REPS)
                .map(|r| st.bits.iter().enumerate().fold(st.s_masks[r], |a, (k, b)| fadd(&a, &fmul(&fsmall(ch.gamma[si][r][k]), &fsub(b, &fmul(b, b))))))
                .collect();
            let u = (0..AUDIT_REPS)
                .map(|r| st.bits.iter().enumerate().fold(st.u_masks[r], |a, (k, b)| fadd(&a, &fmul(&fsmall(ch.rho[si][r][k]), b))))
                .collect();
            AuditPublished { w: wv, s, u }
        })
        .collect()
}

/// The public input of a custodian's EarnEpoch audit: each pair's close commitment (pair order), its phase-1 digest, then per
/// statement its challenges, its public form and its published values.
#[must_use]
pub fn epoch_io(close_commits: &[[Fa4; 4]], phase1: &[Fa4; 4], ch: &AuditChallenges, forms: &[([F; AUDIT_VALUES], F)], published: &[AuditPublished]) -> Vec<Fa4> {
    let mut io: Vec<Fa4> = Vec::new();
    for c in close_commits {
        io.extend_from_slice(c);
    }
    io.extend_from_slice(phase1);
    let limbs = |io: &mut Vec<Fa4>, v: &F| io.extend(limbs_of(&big_from(v)).iter().map(|l| Fa4::from_u64(*l)));
    for (si, (coeffs, c0)) in forms.iter().enumerate() {
        for r in 0..AUDIT_REPS {
            io.extend(ch.gamma[si][r].iter().map(|v| Fa4::from_u64(*v)));
            io.extend(ch.rho[si][r].iter().map(|v| Fa4::from_u64(*v)));
        }
        for c in coeffs.iter().chain(std::iter::once(c0)) {
            limbs(&mut io, c);
        }
        limbs(&mut io, &published[si].w);
        for v in published[si].s.iter().chain(&published[si].u) {
            limbs(&mut io, v);
        }
    }
    io
}

/// ⭐⭐ THE EARNEPOCH'S CUSTODIAN AUDIT CIRCUIT: each pair's closed-line shares open that pair's close commitment, the bit-shares
/// and masks open its phase-1 digest, and every statement's `w`, `s_r`, `u_r` is computed from them under the public
/// challenges — the batch audit's statement shape over the closed lines alone (the EarnEpoch moves no commitment). `None`
/// when the witness does not fit its layout.
#[must_use]
pub fn epoch_audit_circuit(w: &EpochWitness, ch: &AuditChallenges) -> Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)> {
    let shaped = w.statements.len() == EPOCH_STATEMENTS
        && !w.close.is_empty()
        && w.close.len() <= EPOCH_PAIRS_MAX
        && w.statements.iter().enumerate().all(|(si, s)| s.bits.len() == statement_bits(si) && s.s_masks.len() == AUDIT_REPS && s.u_masks.len() == AUDIT_REPS)
        && ch.gamma.len() == EPOCH_STATEMENTS
        && ch.gamma.iter().enumerate().all(|(si, g)| g.iter().all(|r| r.len() == statement_bits(si)));
    if !shaped {
        return None;
    }
    let commits: Vec<[Fa4; 4]> = w.close.iter().map(|(l, s)| close_commit(l, s)).collect();
    let phase1 = epoch_phase1_digest(w);
    let published = epoch_published(w, ch);
    let forms: Vec<([F; AUDIT_VALUES], F)> = w.statements.iter().map(|s| (s.coeffs, s.c0)).collect();
    let io = epoch_io(&commits, &phase1, ch, &forms, &published);
    let build = |nv: usize, sizing: bool| -> Option<(usize, Option<(crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>)>)> {
        let mut b = if sizing { R1csBuilder::new_values_only(nv, &io)? } else { R1csBuilder::new(nv, &io)? };
        let mut cursor = 0usize;
        let mut take = |b: &R1csBuilder, n: usize| -> Vec<Lc> {
            let v: Vec<Lc> = (cursor..cursor + n).map(|i| b.io(i)).collect();
            cursor += n;
            v
        };
        let mut vals: Vec<Nn> = Vec::with_capacity(AUDIT_VALUES);
        for (lines, salt) in &w.close {
            let ns: Vec<Nn> = lines.iter().map(|v| Nn::alloc(&mut b, v)).collect();
            let sw: [Lc; 4] = core::array::from_fn(|k| b.witness(salt[k]));
            let c = chain_commit_w(&ns, &sw, &mut b);
            let want = take(&b, 4);
            for k in 0..4 {
                b.enforce_eq(&c[k], &want[k]);
            }
            vals.extend(ns);
        }
        while vals.len() < AUDIT_VALUES {
            vals.push(Nn::constant(&[0; 4]));
        }
        let mut p1_limbs: Vec<Lc> = Vec::new();
        let mut sts: Vec<(Vec<Nn>, Nn, Vec<Nn>, Vec<Nn>)> = Vec::new();
        for st in &w.statements {
            let bits: Vec<Nn> = st.bits.iter().map(|v| Nn::alloc(&mut b, v)).collect();
            let wm = Nn::alloc(&mut b, &st.w_mask);
            let sm: Vec<Nn> = st.s_masks.iter().map(|v| Nn::alloc(&mut b, v)).collect();
            let um: Vec<Nn> = st.u_masks.iter().map(|v| Nn::alloc(&mut b, v)).collect();
            for n in bits.iter().chain(std::iter::once(&wm)).chain(&sm).chain(&um) {
                p1_limbs.extend(n.0.iter().cloned());
            }
            sts.push((bits, wm, sm, um));
        }
        let p1s: [Lc; 4] = core::array::from_fn(|i| b.witness(w.phase1_salt[i]));
        p1_limbs.extend(p1s.iter().cloned());
        {
            let p2 = crate::spartan_gadgets::P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
            let mut st: [Lc; crate::pow_pq_air::WIDTH] = core::array::from_fn(|_| Lc::constant(Fa4::ZERO));
            st[crate::pow_pq_air::WIDTH - 1] = Lc::constant(Fa4::from_u64(COMMIT_DOMAIN ^ 0x4550_3100));
            for chunk in p1_limbs.chunks(RATE) {
                for (i, v) in chunk.iter().enumerate() {
                    st[i] = st[i].add(v);
                }
                st = crate::spartan_gadgets::poseidon2_permutation(&mut b, &p2, &st);
            }
            let want = take(&b, 4);
            for k in 0..4 {
                b.enforce_eq(&st[k], &want[k]);
            }
        }
        for (si, st) in w.statements.iter().enumerate() {
            let (bits, wm, sm, um) = &sts[si];
            let nb = bits.len();
            let _ = take(&b, 2 * AUDIT_REPS * nb);
            let _ = take(&b, (AUDIT_VALUES + 1) * LIMBS);
            let mut z = Nn::constant(&st.c0);
            for (j, v) in vals.iter().enumerate() {
                if st.coeffs[j] != [0; 4] {
                    let t = v.scale_const(&st.coeffs[j], &mut b);
                    z = z.add(&t, &mut b);
                }
            }
            let mut terms: Vec<(&Nn, i64, usize)> = bits.iter().enumerate().map(|(k, x)| (x, 1i64 << (k % 12), k / 12)).collect();
            terms.push((&z, -1, 0));
            terms.push((wm, 1, 0));
            let wv = lin_small(&mut b, None, &terms);
            let want = take(&b, LIMBS);
            for (g, wl) in wv.0.iter().zip(&want) {
                b.enforce_eq(g, wl);
            }
            // `s_r = −Σ γ_{r,k} e_k + s_mask_r`, `e_k = b_k² − b_k` (the batch audit's fused bit check)
            let es: Vec<Nn> = bits.iter().map(|x| x.square_minus_self(&mut b)).collect();
            for r in 0..AUDIT_REPS {
                let mut t: Vec<(&Nn, i64, usize)> = Vec::with_capacity(nb + 1);
                for k in 0..nb {
                    let g = i64::try_from(ch.gamma[si][r][k]).unwrap_or(0);
                    t.push((&es[k], -g, 0));
                }
                t.push((&sm[r], 1, 0));
                let sv = lin_small(&mut b, None, &t);
                let want = take(&b, LIMBS);
                for (g, wl) in sv.0.iter().zip(&want) {
                    b.enforce_eq(g, wl);
                }
            }
            for r in 0..AUDIT_REPS {
                let mut t: Vec<(&Nn, i64, usize)> = (0..nb).map(|k| (&bits[k], i64::try_from(ch.rho[si][r][k]).unwrap_or(0), 0)).collect();
                t.push((&um[r], 1, 0));
                let uv = lin_small(&mut b, None, &t);
                let want = take(&b, LIMBS);
                for (g, wl) in uv.0.iter().zip(&want) {
                    b.enforce_eq(g, wl);
                }
            }
        }
        let _ = cursor;
        let vars = b.last_var() + 1 - (1usize << (nv - 1));
        if sizing {
            return Some((vars, None));
        }
        Some((vars, b.finish().map(|(r, wit)| (r, io.clone(), wit))))
    };
    let (vars, _) = build(SIZING_VARS, true)?;
    let need = vars.max(1 + io.len());
    let mut nv = 2usize;
    while (1usize << (nv - 1)) < need {
        nv += 1;
    }
    build(nv, false)?.1
}

/// ⭐ THE VERIFIER'S EARNEPOCH CIRCUIT over `pairs` pairs, formed from public data alone (the challenges and the statements'
/// forms) over an all-zero witness.
#[must_use]
pub fn epoch_r1cs(pairs: usize, ch: &AuditChallenges, forms: &[([F; AUDIT_VALUES], F)]) -> Option<crate::spartan_ccs::R1cs> {
    let dummy = EpochWitness {
        close: vec![([[0; 4]; CLOSE_LINES], [Fa4::ZERO; 4]); pairs],
        statements: forms
            .iter()
            .enumerate()
            .map(|(si, (coeffs, c0))| AuditStatement {
                coeffs: *coeffs,
                c0: *c0,
                bits: vec![[0; 4]; statement_bits(si)],
                w_mask: [0; 4],
                s_masks: vec![[0; 4]; AUDIT_REPS],
                u_masks: vec![[0; 4]; AUDIT_REPS],
            })
            .collect(),
        phase1_salt: [Fa4::ZERO; 4],
    };
    epoch_audit_circuit(&dummy, ch).map(|(r, _, _)| r)
}

fn signed(c: i64) -> Fa4 {
    if c >= 0 { Fa4::from_u64(c as u64) } else { Fa4::ZERO - Fa4::from_u64((-c) as u64) }
}

/// The native proof field's modulus (KoalaBear, `2^31 − 2^24 + 1`): a column identity is an integer identity only while
/// every term of it stays below this in magnitude.
const NATIVE_P: u64 = <Fa4 as PrimeField64>::ORDER_U64;

#[cfg(test)]
thread_local! {
    /// FINDING A-F71's lying prover, on in one test thread only (see [`reduce_columns`]).
    static WRAP_LIE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The largest value an element holds: every [`Nn`] is below 2^256 (its producers range-check the top limb to [`TOP_BITS`], or
/// build it from fewer bits).
const NN_MAX: [u64; 4] = [u64::MAX; 4];
/// A limb's largest value.
const LIMB_MAX: u128 = (1 << LIMB_BITS) - 1;

/// The bit length of `x` (0 for 0).
fn big_bits(x: &Big) -> usize {
    (0..9).rev().find(|&i| x[i] != 0).map_or(0, |i| 64 * i + 64 - x[i].leading_zeros() as usize)
}

/// `x · 2^(12·limbs)` (`None` past 576 bits).
fn big_shl_limbs(x: &Big, limbs: usize) -> Option<Big> {
    let bits = LIMB_BITS * limbs;
    if big_bits(x) + bits > 64 * 9 {
        return None;
    }
    let (w, o) = (bits / 64, bits % 64);
    let mut out = [0u64; 9];
    for i in (0..9).rev() {
        if i >= w {
            out[i] = x[i - w] << o;
            if o > 0 && i > w {
                out[i] |= x[i - w - 1] >> (64 - o);
            }
        }
    }
    Some(out)
}

/// ⭐⭐ A REDUCTION'S PLAN — FINDING A-F71 CLOSED BY CONSTRUCTION. From each column's magnitude bound (`mags[k]`: the largest
/// |value| the gadget can put in column k), the value's bound (`v_max ≥ V`) and the offset `q_off`: the quotient's limbs
/// (`q ≤ ⌊(v_max + q_off·p)/p⌋`, so a small-coefficient combination's quotient is two limbs, not 22), the chain's width (every
/// column `q·p`, `r` or the gadget can reach, plus the closing one), and each carry's bit width. A carry's width holds the
/// honest carry (`|c_k| ≤ L_k/4096`, `L_k` the column's bound with the incoming carry at its RANGE, a lying prover's most) and is
/// the smallest that does. The plan is REFUSED (`None`) unless every column satisfies `L_k + range_k·4096 < p_nat`, the closing
/// one `L_last < p_nat`: then a column equation `lhs = c·4096` that holds in KoalaBear holds over the integers, so `V + q_off·p
/// = q·p + r` exactly. MEASURED why: the fixed 20-bit carry let `|c·4096|` reach 2^31 > p_nat, and a lying prover proved
/// `x·y ≡ r + p_nat` (`br15_a_reduction_whose_carry_wraps_the_native_field_is_refused`). Cons: none. The carries are no wider
/// than the fixed 20 bits and most are narrower, so the circuit only shrinks.
struct ReductionPlan {
    q_limbs: usize,
    q_top: usize,
    width: usize,
    carry_bits: Vec<usize>,
}

fn plan_reduction(mags: &[u128], n_cols: usize, q_off: u64, v_max: &Big) -> Option<ReductionPlan> {
    let p = big_from(&P255_WORDS);
    let pl = limbs_of(&p);
    let (q_max, _) = big_divmod_p(&big_add(v_max, &big_mul_small(&p, q_off)));
    let q_bits = big_bits(&q_max).max(1);
    let q_limbs = q_bits.div_ceil(LIMB_BITS);
    let q_top = q_bits - LIMB_BITS * (q_limbs - 1);
    let width = n_cols.max(q_limbs + LIMBS - 1).max(LIMBS) + 1;
    if width * LIMB_BITS > 64 * 9 {
        return None;
    }
    let offp = limbs_of_n(&big_mul_small(&p, q_off), width);
    let native = u128::from(NATIVE_P);
    let mut carry_bits = Vec::with_capacity(width - 1);
    let mut cin: u128 = 0;
    for k in 0..width {
        let mut qp: u128 = 0;
        for i in 0..q_limbs {
            if k >= i && k - i < LIMBS {
                let qm = if i + 1 == q_limbs { (1u128 << q_top) - 1 } else { LIMB_MAX };
                qp += qm * u128::from(pl[k - i]);
            }
        }
        let r = if k + 1 == LIMBS { (1u128 << TOP_BITS) - 1 } else if k < LIMBS { LIMB_MAX } else { 0 };
        let l_max = mags.get(k).copied().unwrap_or(0) + u128::from(offp[k]) + qp + r + cin;
        if k + 1 == width {
            return (l_max < native).then_some(ReductionPlan { q_limbs, q_top, width, carry_bits });
        }
        let honest = l_max >> LIMB_BITS;
        let mut cb = 1usize;
        while (1u128 << (cb - 1)) <= honest {
            cb += 1;
        }
        let range = 1u128 << (cb - 1);
        if l_max + (range << LIMB_BITS) >= native {
            return None;
        }
        carry_bits.push(cb);
        cin = range;
    }
    None
}

/// ⭐ THE ONE REDUCTION every gadget op ends in: columns `(wire, its integer value)` of weight 2^(12k) whose integer sum V may
/// be negative; `q_off · p` is added as constant columns so `V + q_off·p ≥ 0`, and the witnesses `q, r` (range-checked limbs,
/// r below 2^256) satisfy `V + q_off·p = q·p + r` column by column under a signed carry chain whose last carry is zero. The
/// quotient's limbs, the chain's width and every carry's width are [`plan_reduction`]'s from the caller's column bounds `mags`
/// and value bound `v_max`: the native identity IS the integer one, column by column, by the plan's own check.
fn reduce_columns(b: &mut R1csBuilder, mut cols: Vec<(Lc, i128)>, mags: &[u128], q_off: u64, v_max: &Big) -> Nn {
    let plan = plan_reduction(mags, cols.len(), q_off, v_max).expect("⛔ A-F71: a reduction whose column could wrap the native field (the gadget's bound is too wide)");
    let p = big_from(&P255_WORDS);
    let pl = limbs_of(&p);
    let width = plan.width;
    // the offset q_off·p in FULL (q_off may exceed 2^9, putting q_off·p above 2^264)
    let offp = limbs_of_n(&big_mul_small(&p, q_off), width);
    cols.resize(width, (Lc::constant(Fa4::ZERO), 0));
    for (k, o) in offp.iter().enumerate() {
        cols[k].0 = cols[k].0.add_const(Fa4::from_u64(*o));
        cols[k].1 += i128::from(*o);
    }
    // the integer V + q_off·p from the columns (signed carries, base 2^12)
    let mut norm = [0u64; 9];
    let mut carry: i128 = 0;
    for (k, (_, v)) in cols.iter().enumerate() {
        let t = *v + carry;
        let limb = t.rem_euclid(1 << LIMB_BITS) as u64;
        carry = t.div_euclid(1 << LIMB_BITS);
        let bit = k * LIMB_BITS;
        if bit < 576 {
            norm[bit / 64] |= limb << (bit % 64);
            if bit % 64 + LIMB_BITS > 64 && bit / 64 + 1 < 9 {
                norm[bit / 64 + 1] |= limb >> (64 - bit % 64);
            }
        }
    }
    debug_assert!(carry == 0, "the columns' value is non-negative after the offset");
    let (q, r) = big_divmod_p(&norm);
    // FINDING A-F71's LYING PROVER (test builds only): the remainder `r + p_nat` with column 0's carry absorbing `p_nat` — every
    // column equation then holds in the native field while the integer identity is off by `p_nat`
    #[cfg(test)]
    let (r, wrap) = if WRAP_LIE.with(std::cell::Cell::get) { (big_add(&r, &big_from(&[NATIVE_P])), i128::from(NATIVE_P)) } else { (r, 0) };
    #[cfg(not(test))]
    let wrap: i128 = 0;
    let (ql, rl) = (limbs_of_n(&q, plan.q_limbs), limbs_of(&r));
    let qn: Vec<Lc> = (0..plan.q_limbs).map(|i| range_wire(b, ql[i], if i + 1 == plan.q_limbs { plan.q_top } else { LIMB_BITS })).collect();
    let rn: Vec<Lc> = (0..LIMBS).map(|i| range_wire(b, rl[i], if i == LIMBS - 1 { TOP_BITS } else { LIMB_BITS })).collect();
    let neg = |v: Fa4| Fa4::ZERO - v;
    let mut carry_in = Lc::constant(Fa4::ZERO);
    let mut carry_v: i128 = 0;
    for k in 0..width {
        let mut lhs = cols[k].0.add(&carry_in);
        let mut colv = cols[k].1 + carry_v + if k == 0 { wrap } else { 0 };
        for i in 0..plan.q_limbs {
            if k >= i && k - i < LIMBS {
                lhs = lhs.add(&qn[i].scale(neg(Fa4::from_u64(pl[k - i]))));
                colv -= i128::from(ql[i]) * i128::from(pl[k - i]);
            }
        }
        if k < LIMBS {
            lhs = lhs.add(&rn[k].scale(neg(Fa4::ONE)));
            colv -= i128::from(rl[k]);
        }
        if k + 1 == width {
            b.enforce_eq(&lhs, &Lc::constant(Fa4::ZERO));
            break;
        }
        let carry_out = colv >> LIMB_BITS;
        // the carry's range [−2^(cb−1), 2^(cb−1)), its width the plan's: a carry outside it has no bits that open it
        let cb = plan.carry_bits[k];
        let off = 1u64 << (cb - 1);
        let shifted = u64::try_from(carry_out + i128::from(off)).unwrap_or(u64::MAX);
        let c = range_wire(b, shifted, cb).add_const(neg(Fa4::from_u64(off)));
        b.enforce_eq(&lhs, &c.scale(Fa4::from_u64(1 << LIMB_BITS)));
        carry_in = c;
        carry_v = carry_out;
    }
    Nn(rn)
}

#[cfg(test)]
mod tests {
    use crate::hiding_decider::Fa4;
    use crate::spartan_ccs::{prove_committed, verify_committed};
    use crate::spartan_gadgets::{Lc, R1csBuilder};
    use p3_field::PrimeCharacteristicRing;

    /// `n` chained multiplications `x_{i+1} = x_i · x_i + i` with the first and last public: one R1CS row each.
    fn chain(log_rows: usize) -> (crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>) {
        let n = (1usize << log_rows) - 4;
        let mut x = Fa4::from_u64(3);
        let mut vals = Vec::with_capacity(n + 1);
        vals.push(x);
        for i in 0..n {
            x = x * x + Fa4::from_u64(i as u64);
            vals.push(x);
        }
        let io = vec![vals[0], vals[n]];
        let mut b = R1csBuilder::new(log_rows + 1, &io).expect("the publics fit");
        let mut w = b.io(0);
        for i in 0..n {
            w = b.mul(&w, &w).add_const(Fa4::from_u64(i as u64));
        }
        let last = b.io(1);
        b.enforce_eq(&w, &last);
        let _ = Lc::var(0);
        let (r1cs, wit) = b.finish().expect("the witness fits");
        (r1cs, io, wit)
    }

    /// ⭐ MEASURED: the committed argument's prove and verify time and its proof bytes at 2^14, 2^16 and 2^18 rows.
    #[test]
    fn br15_the_audit_argument_cost_is_measured_at_three_scales() {
        for log_rows in [14usize, 16, 18] {
            let (r1cs, io, w) = chain(log_rows);
            let t0 = std::time::Instant::now();
            let bytes = prove_committed(&r1cs, &io, &w).expect("the chain proves");
            let prove = t0.elapsed();
            let t1 = std::time::Instant::now();
            assert!(verify_committed(&r1cs, &io, &bytes), "the chain verifies");
            let verify = t1.elapsed();
            let mut bad = io.clone();
            bad[1] += Fa4::ONE;
            assert!(!verify_committed(&r1cs, &bad, &bytes), "TAMPER: another output for the same proof is refused");
            eprintln!(
                "[br15-audit] 2^{log_rows} rows: prove {} ms, verify {} ms, proof {} B",
                prove.as_millis(),
                verify.as_millis(),
                bytes.len()
            );
        }
    }

    /// ⭐⭐ FINDING A-F71 — A REDUCTION WHOSE CARRY WRAPS THE NATIVE FIELD IS REFUSED. LYING PROVER (well-formed, false in one
    /// place): for `x·y` it sets the remainder to `r + p_nat` and lets column 0's carry absorb `p_nat`
    /// (`(lhs_0 + p_nat)/4096 ≈ 520,192`). Column 0's equation `lhs = c·4096` then holds in KoalaBear, every later column is
    /// exact, and the gadget would prove `x·y ≡ r + p_nat (mod 2^255 − 19)`. The same for a small-coefficient combination
    /// (`lin`). CALIBRATION: each honest assignment satisfies, and the lie names another value.
    #[test]
    fn br15_a_reduction_whose_carry_wraps_the_native_field_is_refused() {
        use super::*;
        let x = [0x1234_5678_9abc_def0, 7, 9, 0x0FFF_0000_0000_0001];
        let y = [0x0fed_cba9_8765_4321, 3, 5, 0x0AAA_0000_0000_0003];
        for (what, op) in [("a multiplication", 0u8), ("a small-coefficient combination", 1u8)] {
            let lay = |lie: bool| {
                let mut b = R1csBuilder::new(14, &[]).expect("builder");
                let (xn, yn) = (Nn::alloc(&mut b, &x), Nn::alloc(&mut b, &y));
                WRAP_LIE.with(|c| c.set(lie));
                let r = if op == 0 { xn.mul(&yn, &mut b) } else { xn.lin(&[(&yn, 3)], 2, &mut b) };
                WRAP_LIE.with(|c| c.set(false));
                let v = r.value(&b);
                let (r1cs, w) = b.finish().expect("finishes");
                let ok = r1cs.is_satisfied(&r1cs.lay_z(&[], &w).expect("lays"));
                (ok, v)
            };
            let (honest_ok, honest_v) = lay(false);
            assert!(honest_ok, "CALIBRATION: {what} holds on its honest assignment");
            let (lie_ok, lie_v) = lay(true);
            assert_ne!(lie_v, honest_v, "PRECONDITION: the lie names another value for {what}");
            assert!(!lie_ok, "⛔ A-F71: {what} was proven to be its value plus p_nat (a carry wrapped the native field)");
        }
    }

    /// ⭐ THE NON-NATIVE MULTIPLICATION GADGET IS THE FIELD'S: for random and edge elements the circuit's remainder equals
    /// `defi`-side arithmetic mod 2^255 − 19 (cross-checked against a direct schoolbook reduction), the honest witness
    /// satisfies every row, and TAMPERS — a remainder one too large, a moved limb product, a carry off by one — are each
    /// refused. Prints the constraint count per multiplication and proves one on the committed argument.
    #[test]
    fn br15_the_share_field_multiplication_gadget_is_sound() {
        use super::*;
        let mut seed = 0xA5A5_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let p = big_from(&P255_WORDS);
        for case in 0..6 {
            let pick = |n: &mut dyn FnMut() -> u64| -> [u64; 4] {
                let w = [n(), n(), n(), n() >> 1];
                let (_, r) = big_divmod_p(&big_from(&w));
                [r[0], r[1], r[2], r[3]]
            };
            let (a, c) = if case == 0 {
                let pm1 = big_sub(&p, &big_from(&[1]));
                ([pm1[0], pm1[1], pm1[2], pm1[3]], [pm1[0], pm1[1], pm1[2], pm1[3]])
            } else {
                (pick(&mut next), pick(&mut next))
            };
            let mut b = R1csBuilder::new(14, &[]).expect("fits");
            let (na, nc) = (Nn::alloc(&mut b, &a), Nn::alloc(&mut b, &c));
            let rows_before = b.constraints();
            let r = na.mul(&nc, &mut b);
            let per_mul = b.constraints() - rows_before;
            let got = r.value(&b);
            let (_, want) = big_divmod_p(&big_mul(&a, &c));
            assert_eq!(got, [want[0], want[1], want[2], want[3]], "the gadget's remainder is a·b mod p");
            if case == 0 {
                assert_eq!(got, [1, 0, 0, 0], "(p − 1)² ≡ 1");
                eprintln!("[br15-audit] one 2^255−19 multiplication: {per_mul} constraints");
            }
            let used = b.last_var() + 1 - (1usize << 13);
            let (r1cs, w) = b.finish().expect("fits");
            let z = r1cs.lay_z(&[], &w).expect("lays");
            assert!(r1cs.is_satisfied(&z), "the honest witness satisfies every row");
            // TAMPERS on the witness half: the first input bit, a middle cell, the last carry bit — each must break a row
            for (idx, what) in [(0, "input limb bit"), (used / 2, "middle cell"), (used - 1, "last carry bit")] {
                let mut bad = w.clone();
                bad[idx] += Fa4::ONE;
                let zb = r1cs.lay_z(&[], &bad).expect("lays");
                assert!(!r1cs.is_satisfied(&zb), "TAMPER: a moved {what} is refused");
            }
            if case == 1 {
                let t0 = std::time::Instant::now();
                let bytes = crate::spartan_ccs::prove_committed(&r1cs, &[], &w).expect("one multiplication proves");
                assert!(crate::spartan_ccs::verify_committed(&r1cs, &[], &bytes));
                eprintln!("[br15-audit] one multiplication proved in {} ms ({} B)", t0.elapsed().as_millis(), bytes.len());
            }
        }
    }

    /// ⭐ THE LINEAR OPS REDUCE CORRECTLY: `add`, `sub` (through zero), `lin` with negative coefficients and `scale_const` by a
    /// 255-bit public constant each equal direct arithmetic mod 2^255 − 19 with every row satisfied; `enforce_eq` holds for equal
    /// elements and is UNSATISFIABLE for unequal ones (TAMPER: a claimed equality of a and a + 1).
    #[test]
    fn br15_the_share_field_linear_ops_reduce_correctly() {
        use super::*;
        let p = big_from(&P255_WORDS);
        let red = |x: &Big| -> [u64; 4] {
            let (_, r) = big_divmod_p(x);
            [r[0], r[1], r[2], r[3]]
        };
        let (a, c) = (red(&big_from(&[11, 22, 33, 0x7000_0000_0000_0000])), red(&big_from(&[5, 0, 0, 0x7FFF_FFFF_FFFF_FFF0])));
        let k = red(&big_from(&[0xDEAD, 0xBEEF, 0x1234, 0x7ABC_0000_0000_0000]));
        let mut b = R1csBuilder::new(15, &[]).expect("fits");
        let (na, nc) = (Nn::alloc(&mut b, &a), Nn::alloc(&mut b, &c));
        let s = na.add(&nc, &mut b);
        assert_eq!(s.value(&b), red(&big_add(&big_from(&a), &big_from(&c))), "a + c");
        let d = nc.sub(&na, &mut b);
        assert_eq!(d.value(&b), red(&big_sub(&big_add(&big_from(&c), &p), &big_from(&a))), "c − a wraps through p");
        let l = na.lin(&[(&nc, -3)], 2, &mut b);
        let want_l = red(&big_sub(&big_add(&big_mul_small(&big_from(&a), 2), &big_mul_small(&p, 3)), &big_mul_small(&big_from(&c), 3)));
        assert_eq!(l.value(&b), want_l, "2a − 3c");
        let sc = na.scale_const(&k, &mut b);
        assert_eq!(sc.value(&b), red(&big_mul(&a, &k)), "k · a");
        let again = na.mul(&Nn::constant(&k), &mut b);
        sc.enforce_eq(&again, &mut b);
        let (r1cs, w) = b.finish().expect("fits");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&[], &w).expect("lays")), "every row of the honest ops holds");
        // TAMPER: claim a ≡ a + 1 — the equality's pinned limbs cannot all be zero
        let mut b2 = R1csBuilder::new(14, &[]).expect("fits");
        let a1 = red(&big_add(&big_from(&a), &big_from(&[1])));
        let (x, y) = (Nn::alloc(&mut b2, &a), Nn::alloc(&mut b2, &a1));
        x.enforce_eq(&y, &mut b2);
        let (r2, w2) = b2.finish().expect("fits");
        assert!(!r2.is_satisfied(&r2.lay_z(&[], &w2).expect("lays")), "⛔ a ≡ a + 1 was satisfiable");
        eprintln!("[br15-audit] scale_const by a 255-bit constant + sub: linear (no limb product); ops pin satisfied");
    }

    /// ⭐ THE SHARE COMMITMENT GADGET IS THE NATIVE ONE: the circuit's digest equals `share_commit` wire for wire; a digest pinned
    /// to a public input verifies on the committed argument, and TAMPERS — another value under the same digest, another salt —
    /// are refused.
    #[test]
    fn br15_the_share_commitment_gadget_matches_the_native_sponge() {
        use super::*;
        let x = [0x1111, 0x2222, 0x3333, 0x0444];
        let salt = [Fa4::from_u64(7), Fa4::from_u64(8), Fa4::from_u64(9), Fa4::from_u64(10)];
        let want = share_commit(&x, &salt);
        let build = |val: &[u64; 4], sl: &[Fa4; 4]| {
            let mut b = R1csBuilder::new(14, &want).expect("fits");
            let n = Nn::alloc(&mut b, val);
            let s: [Lc; 4] = core::array::from_fn(|i| b.witness(sl[i]));
            let d = n.commit(&s, &mut b);
            for (i, w) in d.iter().enumerate() {
                let io = b.io(i);
                b.enforce_eq(w, &io);
            }
            let rows = b.constraints();
            let (r, w) = b.finish().expect("fits");
            (r, w, rows)
        };
        let (r1cs, w, rows) = build(&x, &salt);
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&want, &w).expect("lays")), "the circuit's digest is the native one");
        let bytes = crate::spartan_ccs::prove_committed(&r1cs, &want, &w).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&r1cs, &want, &bytes));
        let (r2, w2, _) = build(&[0x1112, 0x2222, 0x3333, 0x0444], &salt);
        assert!(!r2.is_satisfied(&r2.lay_z(&want, &w2).expect("lays")), "⛔ another value opened the same digest");
        let mut salt2 = salt;
        salt2[0] += Fa4::ONE;
        let (r3, w3, _) = build(&x, &salt2);
        assert!(!r3.is_satisfied(&r3.lay_z(&want, &w3).expect("lays")), "⛔ another salt opened the same digest");
        eprintln!("[br15-audit] one share commitment opened in-circuit: {rows} constraints (alloc + 4 permutations)");
    }

    /// A test custody set: shares of `v` on a random degree-`deg` polynomial (constant `v`) at x = 1..=n.
    fn share_poly(v: &super::F, deg: usize, n: usize, seed: &mut u64) -> Vec<super::F> {
        use super::*;
        let mut next = || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        };
        let coeffs: Vec<F> = std::iter::once(*v).chain((0..deg).map(|_| red4(&big_from(&[next(), next(), next(), next() >> 1])))).collect();
        (1..=n as u64).map(|x| poly_eval(&coeffs, x)).collect()
    }

    /// The honest witnesses of an n-custodian batch: pool (X 1,000, Y 1,500, floors (fx, 0)), three buy orders (Y 300 in the
    /// unlimited bucket, 200 in bucket 1, and 0), every bucket filling at the tick, tick ratios p_t = n0/1000 and
    /// p_{t+1} = 2001/1000 around the batch price 2, booked q_X = 250 (≥ 500·1000/2001), q_Y = 0. `digits` overrides
    /// statement 0's bit vector (a TAMPER), `n0` its tick (a wrong tick) and `fx` the X floor (a floor above the pool's X after
    /// the batch) when given.
    #[allow(clippy::type_complexity)]
    fn batch(n: usize, t: usize, digits: Option<Vec<u64>>, n0: u64, fx: u64) -> (Vec<super::AuditWitness>, Vec<[super::Fa4; 4]>) {
        batch_with(n, t, digits, n0, fx, 1, 0, [0, 0])
    }

    /// [`batch`] at `k` times its pool and buys, with a SELL of `sell` SAT as its third order, and the custodians' fee bookings
    /// moved by `fee_off` from the rule's `⌊ΔX·f⌋`, `⌊q_X·f⌋` (a LYING custodian set when non-zero). The booking: q_X =
    /// ⌈ΔY·d1/n1⌉, q_Y = ⌈(ΔX − φ_s)·n0/d0⌉ — the honest φ_s, so a moved φ is the only lie.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn batch_with(n: usize, t: usize, digits: Option<Vec<u64>>, n0: u64, fx: u64, k: u64, sell: u64, fee_off: [i64; 2]) -> (Vec<super::AuditWitness>, Vec<[super::Fa4; 4]>) {
        use super::*;
        let mut seed = 0x15_AD17u64;
        let pool = [1_000u64 * k, 1_500 * k, fx, 0];
        // (x, bucket, y)
        let orders: Vec<(u64, usize, u64)> = vec![(0, 3, 300 * k), (0, 1, 200 * k), (sell, 0, 0)];
        let dx = orders.iter().map(|o| o.0).sum::<u64>();
        let dy = orders.iter().map(|o| o.2).sum::<u64>();
        let (d0, n1, d1) = (1_000u64, 2_001u64, 1_000u64);
        let phi_s_true = u64::try_from(batch_fee(u128::from(dx))).expect("fits");
        let qx = (dy * d1).div_ceil(n1);
        let qy = ((dx - phi_s_true) * n0).div_ceil(d0);
        let phi_s = phi_s_true.checked_add_signed(fee_off[0]).expect("a fee booking stays non-negative");
        let phi_b = u64::try_from(batch_fee(u128::from(qx))).expect("fits").checked_add_signed(fee_off[1]).expect("non-negative");
        // nothing merges in this batch: the merge rows' rate is 0 (they pin alloc = 0)
        let forms = batch_statements(&fsmall(n0), &fsmall(d0), &fsmall(n1), &fsmall(d1), &fsmall(0));
        let ints = [pool[0], pool[1], dx, dy, dy, qx, qy, pool[2], pool[3], phi_s, phi_b];
        // each statement's integer value (it may be "negative" — a field element near p — for a wrong tick or floor)
        let zv: Vec<F> = forms.iter().map(|(c, c0)| c.iter().zip(&ints).fold(*c0, |a, (k, v)| fadd(&a, &fmul(k, &fsmall(*v))))).collect();
        let bits_of = |z: &F, k: usize| -> u64 { (z[k / 64] >> (k % 64)) & 1 };
        let sh = |v: &F, deg: usize, seed: &mut u64| share_poly(v, deg, n, seed);
        let ps: Vec<Vec<F>> = pool.iter().map(|v| sh(&fsmall(*v), t, &mut seed)).collect();
        let os: Vec<Vec<Vec<F>>> = orders
            .iter()
            .map(|(x, bk, y)| {
                (0..ORDER_LINES)
                    .map(|l| {
                        let c = if l == 0 { *x } else if l == 1 + *bk { *y } else { 0 };
                        sh(&fsmall(c), t, &mut seed)
                    })
                    .collect()
            })
            .collect();
        let qs = [sh(&fsmall(qx), t, &mut seed), sh(&fsmall(qy), t, &mut seed)];
        let fs = [sh(&fsmall(phi_s), t, &mut seed), sh(&fsmall(phi_b), t, &mut seed)];
        let line = sh(&fsmall(0), t, &mut seed);
        let st_shares: Vec<(Vec<Vec<F>>, Vec<F>, Vec<Vec<F>>, Vec<Vec<F>>)> = (0..AUDIT_STATEMENTS)
            .map(|si| {
                let ds: Vec<u64> = match (&digits, si) {
                    (Some(d), 0) => d.clone(),
                    _ => (0..statement_bits(si)).map(|k| bits_of(&zv[si], k)).collect(),
                };
                let bits = ds.iter().map(|d| sh(&fsmall(*d), t, &mut seed)).collect();
                let wm = sh(&fsmall(0), t, &mut seed);
                let sm = (0..AUDIT_REPS).map(|_| sh(&fsmall(0), 2 * t, &mut seed)).collect();
                let um = (0..AUDIT_REPS).map(|r| sh(&fsmall(77 + r as u64), t, &mut seed)).collect();
                (bits, wm, sm, um)
            })
            .collect();
        let salt = |i: usize, k: u64| [Fa4::from_u64(i as u64), Fa4::from_u64(k), Fa4::from_u64(3), Fa4::from_u64(4)];
        let ws: Vec<AuditWitness> = (0..n)
            .map(|i| AuditWitness {
                pool: core::array::from_fn(|l| ps[l][i]),
                pool_salt: salt(i, 1),
                orders: os.iter().enumerate().map(|(o, ls)| (ls.iter().map(|v| v[i]).collect(), salt(i, 10 + o as u64))).collect(),
                select: [[true; ORDER_BUCKETS]; 2],
                sells: true,
                earn: false,
                booked: [qs[0][i], qs[1][i]],
                // the fee state at the launch's zeros (B, E, A) and no closed window
                fee: [line[i], line[i], line[i]],
                fee_salt: salt(i, 2),
                close: [line[i], line[i]],
                close_salt: salt(i, 3),
                // no deposit and no Earn income in this batch: φ_d and Ψ are the public zero, every share of them zero
                fees: [fs[0][i], fs[1][i], [0; 4], [0; 4]],
                alloc: [0; 4],
                merge: false,
                close_out: false,
                sample: false,
                deposits: false,
                statements: (0..AUDIT_STATEMENTS)
                    .map(|si| AuditStatement {
                        coeffs: forms[si].0,
                        c0: forms[si].1,
                        bits: st_shares[si].0.iter().map(|v| v[i]).collect(),
                        w_mask: st_shares[si].1[i],
                        s_masks: st_shares[si].2.iter().map(|v| v[i]).collect(),
                        u_masks: st_shares[si].3.iter().map(|v| v[i]).collect(),
                    })
                    .collect(),
                new_pool_salt: salt(i, 50),
                new_fee_salt: salt(i, 51),
                new_close_salt: salt(i, 52),
                phase1_salt: salt(i, 99),
            })
            .collect();
        let p1: Vec<[Fa4; 4]> = ws.iter().map(phase1_digest).collect();
        (ws, p1)
    }

    /// A witness's fee-state kind, as a node forms the circuit.
    fn kind_of(w: &super::AuditWitness) -> super::FeeKind {
        super::FeeKind { merge: w.merge, close_out: w.close_out, sample: w.sample, deposits: w.deposits }
    }

    /// ⭐ ONE CUSTODIAN'S AUDIT, MEASURED: the STREAMED prove and verify a custodian and a node run (`custodian_audit_prove`,
    /// `audit_verify` — no matrix laid), their time and the process's footprint peak, FIRST (the peak is a lifetime figure);
    /// then the laid circuit's dimensions, entries and footprint, and the cross-check: the streamed proof verifies against the
    /// laid circuit, the laid proof against the streamed verifier. TAMPER: a moved public refused by the streamed verifier.
    /// FLOOR: the streamed prove's peak stays under half the laid circuit's own footprint.
    #[test]
    fn br15_one_custodians_audit_is_measured_for_its_size_and_its_prove_peak() {
        use super::*;
        let _one_audit = audit_gate(); // it LAYS one audit for its cross-check (3.8 GB peak): one per process, under AUDIT_GATE
        let (n, t) = (4usize, 1usize);
        let (ws, p1) = batch_with(n, t, None, 1_999, 0, 1_000, 501, [0, 0]);
        let ch = AuditChallenges::derive(&transcript(&p1));
        let mb = || crate::spartan_ccs::process_footprint_mb().unwrap_or((0, 0));
        let forms: Vec<([F; AUDIT_VALUES], F)> = ws[0].statements.iter().map(|s| (s.coeffs, s.c0)).collect();
        let w0 = &ws[0];
        let fixture = mb();
        let t0 = std::time::Instant::now();
        let (sio, sproof) = custodian_audit_prove(w0, &ch).expect("the streamed audit proves");
        let prove_ms = t0.elapsed().as_millis();
        let after_prove = mb();
        let t1 = std::time::Instant::now();
        assert!(audit_verify(w0.orders.len(), w0.select, w0.sells, w0.earn, kind_of(w0), &ch, &forms, &sio, &sproof), "⛔ the streamed audit fails the streamed verifier");
        let verify_ms = t1.elapsed().as_millis();
        let after_verify = mb();
        eprintln!("[br15-audit-size] STREAMED prove {prove_ms} ms ({} B), verify {verify_ms} ms | footprint MB (cur, peak) fixture {fixture:?} after prove {after_prove:?} after verify {after_verify:?}", sproof.len());
        let mut moved = sio.clone();
        moved[0] += Fa4::ONE;
        assert!(!audit_verify(w0.orders.len(), w0.select, w0.sells, w0.earn, kind_of(w0), &ch, &forms, &moved, &sproof), "⛔ TAMPER: the streamed verifier accepted a moved public");
        let before = mb();
        let (r1cs, io, wit) = custodian_audit_circuit(&ws[0], &ch).expect("builds");
        assert_eq!(io, sio, "the laid and the streamed audit name the same publics");
        assert!(crate::spartan_ccs::verify_committed(&r1cs, &io, &sproof), "⛔ the streamed proof fails the laid verifier");
        let built = mb();
        eprintln!(
            "[br15-audit-size] m_vars {} n_vars {} nnz a {} b {} c {} witness {} | footprint MB before {:?} built {:?}",
            r1cs.m_vars,
            r1cs.n_vars,
            r1cs.a.len(),
            r1cs.b.len(),
            r1cs.c.len(),
            wit.len(),
            before,
            built
        );
        let t0 = std::time::Instant::now();
        let bytes = crate::spartan_ccs::prove_committed(&r1cs, &io, &wit).expect("the audit proves");
        eprintln!("[br15-audit-size] LAID prove {} ms, {} B | footprint MB after prove {:?}", t0.elapsed().as_millis(), bytes.len(), mb());
        assert!(crate::spartan_ccs::verify_committed(&r1cs, &io, &bytes), "the audit verifies");
        assert!(audit_verify(w0.orders.len(), w0.select, w0.sells, w0.earn, kind_of(w0), &ch, &forms, &io, &bytes), "⛔ the laid proof fails the streamed verifier");
        eprintln!("[br15-audit-size] footprint MB after verify {:?}", mb());
        // the floor: the streamed prove's whole-process peak (fixture included) under half of the laid circuit's own bytes
        let laid_mb = (r1cs.a.len() + r1cs.b.len() + r1cs.c.len()) * std::mem::size_of::<(usize, usize, Fa4)>() / (1 << 20);
        assert!(after_verify.1 > 0 && (after_verify.1 as usize) < laid_mb / 2 + fixture.1 as usize, "⛔ the streamed audit's peak {} MB is not under half the laid matrices' {laid_mb} MB", after_verify.1);
    }

    /// ⭐⭐ EARN STEP 1 — THE FEE ON THE SAT LEG IS AUDITED TO THE UNIT: four custodians (t = 1) clear a batch of 500,000 USDm
    /// of buys and a 501-SAT sell at a 1,000,000 / 1,500,000 pool. The rule's bookings are φ_s = ⌊501·131/2^16⌋ = 1 (the sells'
    /// SAT entering the pool is 500, and the price is over it) and φ_b = ⌊249,876·131/2^16⌋ = 499; the new pool reconstructs to
    /// X = 1,000,000 + 501 − 1 − 249,876 = 750,624 and the fee line to 500, and one custodian's proof verifies against the
    /// circuit a node rebuilds. LYING CUSTODIANS (well-formed, false in one place — AGENTS F6), each refused by every node's
    /// sharing checks: φ_s one unit high, φ_s one unit low, φ_b one unit high, φ_b one unit low (the fee line skimmed or
    /// padded by a unit). CALIBRATION: the honest set passes the same checks.
    #[test]
    fn earn_the_fee_on_the_sat_leg_is_audited_to_the_unit_and_a_custodian_set_one_unit_off_is_refused() {
        use super::*;
        let _one_audit = audit_gate(); // streamed audits (793 MB peak each): one per process, under AUDIT_GATE
        let (n, t) = (4usize, 1usize);
        assert_eq!(claim_fee(501), 2, "a claim's fee rounds up");
        assert_eq!(batch_fee(501), 1, "a batch's booking rounds down");
        let (ws, p1) = batch_with(n, t, None, 1_999, 0, 1_000, 501, [0, 0]);
        let ch = AuditChallenges::derive(&transcript(&p1));
        for (i, w) in ws.iter().enumerate() {
            let io = audit_publics(w, &ch);
            let bad_rows = bad_rows_under(w, &ch, &io);
            assert!(bad_rows.is_empty(), "custodian {i}'s audit with the fee holds — first unsatisfied rows {:?}", &bad_rows[..bad_rows.len().min(8)]);
            if i == 0 {
                let (pio, bytes) = custodian_audit_prove(w, &ch).expect("the audit proves");
                assert_eq!(pio, io, "the proof's publics are the audit's");
                let forms: Vec<([F; AUDIT_VALUES], F)> = w.statements.iter().map(|s| (s.coeffs, s.c0)).collect();
                assert!(audit_verify(w.orders.len(), w.select, w.sells, w.earn, kind_of(w), &ch, &forms, &io, &bytes), "the fee audit verifies against the circuit a node forms");
                eprintln!("[br15-audit] the audit with the fee (3 orders, {AUDIT_STATEMENTS} statements): {} B", bytes.len());
                // a custodian that keeps its fee commitment but moves its fee share is refused by its own circuit
                let mut moved = w.clone();
                moved.fee[1] = fadd(&moved.fee[1], &fsmall(1));
                assert!(!bad_rows_under(&moved, &ch, &io).is_empty(), "⛔ a moved fee-line share opened the old fee commitment");
            }
        }
        assert!(nodes_accept(&ws, &ch, t), "CALIBRATION: every node's sharing checks pass on the honest fee bookings");
        let rec = |v: &[F]| fsub(&fmul(&fsmall(2), &v[0]), &v[1]);
        let np: Vec<[F; POOL_LINES]> = ws.iter().map(new_pool_shares).collect();
        assert_eq!(rec(&np.iter().map(|p| p[0]).collect::<Vec<_>>()), fsmall(750_624), "the pool's X: in 501 less the 1 SAT fee, out 249,876");
        assert_eq!(rec(&np.iter().map(|p| p[1]).collect::<Vec<_>>()), fsmall(1_999_000), "the pool's Y: in 500,000, out 1,000");
        // the trading fees land on the open window's fresh line E (the backing B moves only by a merge or a payout)
        let nf: Vec<F> = ws.iter().map(|w| new_fee_shares(w)[1]).collect();
        assert_eq!(rec(&nf), fsmall(500), "the fresh fee line holds φ_s + φ_b = 1 + 499 SAT, out of every pool");
        let nb: Vec<F> = ws.iter().map(|w| new_fee_shares(w)[0]).collect();
        assert_eq!(rec(&nb), fsmall(0), "the backing does not move in a trading batch that merges nothing");
        for (off, what) in [([1, 0], "φ_s one unit high"), ([-1, 0], "φ_s one unit low"), ([0, 1], "φ_b one unit high"), ([0, -1], "φ_b one unit low")] {
            let (lw, lp1) = batch_with(n, t, None, 1_999, 0, 1_000, 501, off);
            let lch = AuditChallenges::derive(&transcript(&lp1));
            assert!(!nodes_accept(&lw, &lch, t), "⛔ LYING CUSTODIANS: {what} passed the audit");
        }
    }

    /// The publics of `w`'s audit (what its proof is verified against).
    fn audit_publics(w: &super::AuditWitness, ch: &super::AuditChallenges) -> Vec<super::Fa4> {
        super::audit_io_and_width(w, ch).expect("the audit witness is shaped").0
    }

    /// The rows of `w`'s audit that do not hold under the publics `io` — a STREAMING build (the products `A·z`, `B·z`, `C·z`
    /// folded as each entry is made, no matrix laid), so a row fails exactly where `(A·z)·(B·z) ≠ C·z`, the laid circuit's
    /// `unsatisfied_rows`. With `io` another witness's publics, it reads `w` under that witness's commitments (a moved share
    /// under the old commitment).
    fn bad_rows_under(w: &super::AuditWitness, ch: &super::AuditChallenges, io: &[super::Fa4]) -> Vec<usize> {
        use super::*;
        let (_, nv, _) = audit_io_and_width(w, ch).expect("the audit witness is shaped");
        let b = audit_constraints(R1csBuilder::new_streaming(nv, io, crate::spartan_gadgets::Sink::Abc(Default::default())).expect("builder"), w, ch, io, false).expect("the audit builds");
        let (_, sink, _) = b.finish_stream().expect("the audit streams");
        let crate::spartan_gadgets::Sink::Abc(t) = sink else { unreachable!("an Abc sink comes back an Abc sink") };
        (0..t[0].len()).filter(|&r| t[0][r] * t[1][r] != t[2][r]).collect()
    }

    /// Every node's checks over the batch's publications.
    fn nodes_accept(ws: &[super::AuditWitness], ch: &super::AuditChallenges, t: usize) -> bool {
        use super::*;
        let pubs: Vec<Vec<AuditPublished>> = ws.iter().map(|w| audit_published(w, ch)).collect();
        (0..AUDIT_STATEMENTS).all(|si| {
            let col = |f: &dyn Fn(&AuditPublished) -> F| -> Vec<F> { pubs.iter().map(|p| f(&p[si])).collect() };
            sharing_holds(&col(&|p| p.w), t, true)
                && (0..AUDIT_REPS).all(|r| sharing_holds(&col(&|p| p.s[r]), 2 * t, true))
                && (0..AUDIT_REPS).all(|r| sharing_holds(&col(&|p| p.u[r]), t, false))
        })
    }

    fn transcript(p1: &[[super::Fa4; 4]]) -> Vec<u8> {
        use p3_field::PrimeField64;
        p1.iter().flat_map(|d| d.iter().flat_map(|v| v.as_canonical_u64().to_le_bytes())).collect()
    }

    /// ⭐⭐ §BR-15 — THE CUSTODIAN AUDIT PINS THE TICK AND THE BOOKING: four custodians (t = 1) audit an honest batch (the tick
    /// pair and both pools' booking bounds) — every custodian's circuit is satisfied, every node's sharing checks pass, the new
    /// pool shares reconstruct to (750, 2000); one custodian's proof verifies against the circuit a node REBUILDS from public
    /// data. TAMPERS, each refused: a non-bit digit (a "2" that keeps Σ 2^k b_k = z), a moved pool share under the old
    /// commitment, a tick above the price (z < 0 has no bits), a sale below the pool's X floor.
    #[test]
    fn br15_the_custodian_audit_pins_the_tick_and_refuses_every_tamper() {
        use super::*;
        let _one_audit = audit_gate(); // streamed audits (793 MB peak each): one per process, under AUDIT_GATE
        let (n, t) = (4usize, 1usize);
        let line: Vec<F> = (1..=4u64).map(|x| fmul(&fsmall(x), &fsmall(5))).collect();
        assert!(sharing_holds(&line, 1, true), "CALIBRATION: 5x is a degree-1 sharing of 0");
        let (ws, p1) = batch(n, t, None, 1_999, 0);
        let ch = AuditChallenges::derive(&transcript(&p1));
        for (i, w) in ws.iter().enumerate() {
            let io = audit_publics(w, &ch);
            let bad_rows = bad_rows_under(w, &ch, &io);
            assert!(bad_rows.is_empty(), "custodian {i}'s audit holds — first unsatisfied rows {:?}", &bad_rows[..bad_rows.len().min(8)]);
            if i == 0 {
                let t0 = std::time::Instant::now();
                let (pio, bytes) = custodian_audit_prove(w, &ch).expect("the audit proves");
                let prove = t0.elapsed();
                assert_eq!(pio, io, "the proof's publics are the audit's");
                let forms: Vec<([F; AUDIT_VALUES], F)> = w.statements.iter().map(|s| (s.coeffs, s.c0)).collect();
                let verifier = AuditVerifier::new(w.orders.len(), w.select, w.sells, w.earn, kind_of(w), &ch, &forms).expect("a node forms the circuit");
                assert!(verifier.verify(&io, &bytes), "the proof verifies against the circuit a node forms");
                let mut bad = io.clone();
                let last = bad.len() - 1;
                bad[last] += Fa4::ONE;
                assert!(!verifier.verify(&bad, &bytes), "TAMPER: a moved published limb is refused");
                eprintln!("[br15-audit] one custodian's audit (3 orders, io {} words) proved in {} ms ({} B)", io.len(), prove.as_millis(), bytes.len());
            }
        }
        assert!(nodes_accept(&ws, &ch, t), "every node's sharing checks pass on the honest batch");
        let np: Vec<[F; POOL_LINES]> = ws.iter().map(new_pool_shares).collect();
        let rec = |v: &[F]| fsub(&fmul(&fsmall(2), &v[0]), &v[1]);
        assert_eq!(rec(&np.iter().map(|p| p[0]).collect::<Vec<_>>()), fsmall(750), "the pool's X after the batch");
        assert_eq!(rec(&np.iter().map(|p| p[1]).collect::<Vec<_>>()), fsmall(2_000), "the pool's Y after the batch");
        assert_eq!(rec(&np.iter().map(|p| p[2]).collect::<Vec<_>>()), fsmall(0), "the floors ride along unchanged");
        // TAMPER 1: a non-bit digit in statement 0 (z = 1000: bit 3 set, bit 2 clear → 2 at bit 2)
        let mut digits: Vec<u64> = (0..statement_bits(0)).map(|k| 1_000u64.checked_shr(k as u32).unwrap_or(0) & 1).collect();
        digits[2] = 2;
        digits[3] = 0;
        let (bad_ws, bad_p1) = batch(n, t, Some(digits), 1_999, 0);
        let bad_ch = AuditChallenges::derive(&transcript(&bad_p1));
        assert!(!nodes_accept(&bad_ws, &bad_ch, t), "⛔ a non-bit digit passed the nodes' bit check");
        // TAMPER 2: custodian 1's pool share moved, its commitment kept
        let honest_io = audit_publics(&ws[1], &ch);
        let mut moved = ws[1].clone();
        moved.pool[0] = fadd(&moved.pool[0], &fsmall(1));
        assert!(!bad_rows_under(&moved, &ch, &honest_io).is_empty(), "⛔ a moved pool share opened the old commitment");
        // TAMPER 3: a tick above the price (2.001 claimed as p_t): z < 0 has no bits — the honest bits of z mod p fail the sum
        let (wrong, wrong_p1) = batch(n, t, None, 2_001, 0);
        let wrong_ch = AuditChallenges::derive(&transcript(&wrong_p1));
        assert!(!nodes_accept(&wrong, &wrong_ch, t), "⛔ a tick above the price passed the weighted-sum check");
        // TAMPER 4 (spec §18.10): the batch sells below the pool's X floor (F_X = 800 > X after = 750) — the floor statement has
        // no bits, so the position's virtual depth never pays out
        let (sunk, sunk_p1) = batch(n, t, None, 1_999, 800);
        let sunk_ch = AuditChallenges::derive(&transcript(&sunk_p1));
        assert!(!nodes_accept(&sunk, &sunk_ch, t), "⛔ a batch selling below the pool's X floor passed the audit");
        let (edge, edge_p1) = batch(n, t, None, 1_999, 750);
        let edge_ch = AuditChallenges::derive(&transcript(&edge_p1));
        assert!(nodes_accept(&edge, &edge_ch, t), "CALIBRATION: a batch that sells exactly down to its floor is accepted");
    }

    /// ⭐⭐ §BR-15 — A CLAIM IS EXACTLY ITS ORDER'S FILL AT THE TICK, AND NAMES NO ORDER: the honest claim holds, proves and
    /// verifies with only (nullifier, leaf cross-bind, output commitment) public; its leaf is the settlement's `claim_leaf`; a
    /// refund is the same relation at (1, 1) and spends the SAME nullifier. TAMPERS — one unit more (the over-claim), a price
    /// whose leaf the settlement never inserted, another amount under the order's commitment — are refused.
    /// TWO-PARTY-REVIEWED: the two sides here are the owner's prover and an independent verifier holding only the proof bytes
    /// and the three public digests (`verify_committed` never sees the witness); the claim crossing two NODES (the order folded
    /// on one, claimed on the other) is the node crate's br15 claim pin.
    #[test]
    fn br15_a_claim_paying_more_than_its_order_at_the_price_is_refused() {
        use super::*;
        let base = ClaimWitness {
            amount: 1_000_000_007,
            amount_blind: [7; 8],
            bucket: 2,
            sell: false, deposit: false, withdraw: false, leg: 0, extra: LeafExtra::default(), entry: 0, now: 0,
            p_num: 1u128 << 23,
            p_den: 3_000_001,
            j_min: 1,
            s_num: 3_000_000,
            s_den: 1u128 << 23,
            out: 0,
            out_blind: [9; 8],
            lc_blind: [11; 8],
            cover: None,
        };
        let w = ClaimWitness { out: buy_paid(base.amount, base.p_num, base.p_den).expect("fits"), ..base };
        let g = u128::from(w.amount) * w.p_num / w.p_den;
        assert_eq!(u128::from(claim_out(w.amount, w.p_num, w.p_den).expect("fits")), g, "claim_out is the floor");
        assert_eq!(u128::from(w.out), g - (g * 131).div_ceil(1 << 16), "a filled buy is paid its fill less ⌈g·f⌉ (Earn step 1)");
        let (r1cs, io, wit) = claim_circuit(&w).expect("builds");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &wit).expect("lays")), "the exact fill holds");
        // ⭐ EARN STEP 1 — LYING CLAIMS: a filled buy that takes its fee down (paid its whole fill), or by one unit, has no witness
        for (out, what) in [(u64::try_from(g).expect("fits"), "its whole fill, no fee"), (w.out + 1, "one unit of its fee")] {
            let lie = ClaimWitness { out, ..w.clone() };
            let (lr, li, lw) = claim_circuit(&lie).expect("builds");
            assert!(!lr.is_satisfied(&lr.lay_z(&li, &lw).expect("lays")), "⛔ a filled buy's claim took {what}");
        }
        let t0 = std::time::Instant::now();
        let bytes = crate::spartan_ccs::prove_committed(&r1cs, &io, &wit).expect("proves");
        let (vnf, vlc, voc, vref) = w.publics();
        assert!(!vref, "a bucket at or above j_min fills");
        let shape = claim_r1cs().expect("the verifier forms the shape");
        assert!(crate::spartan_ccs::verify_committed(&shape, &claim_io(&vnf, &vlc, &voc, false), &bytes), "an independent verifier accepts it");
        assert!(!crate::spartan_ccs::verify_committed(&shape, &claim_io(&vnf, &vlc, &voc, true), &bytes), "⛔ a fill verified as a refund");
        eprintln!("[br15-claim] claim (private order, tick, bucket and amounts): {} rows, proved in {} ms ({} B)", r1cs.rows(), t0.elapsed().as_millis(), bytes.len());
        let leaf = claim_leaf(&amount_commit(w.amount, &w.amount_blind), &limit_commit(w.bucket, &w.amount_blind), w.p_num, w.p_den, w.j_min, w.s_num, w.s_den);
        assert_eq!(vlc, claim_leaf_commit(&leaf, &vnf, &w.lc_blind), "the claim binds the settlement's leaf");
        // the refund of an expired batch: the leaf at (1, 1) with nothing filling (j_min = ORDER_BUCKETS), out = a
        let refund = ClaimWitness { p_num: 1, p_den: 1, j_min: ORDER_BUCKETS as u64, out: w.amount, ..w.clone() };
        let (rr, ri, rw) = claim_circuit(&refund).expect("builds");
        assert!(rr.is_satisfied(&rr.lay_z(&ri, &rw).expect("lays")), "a refund returns exactly the order's amount");
        assert!(refund.publics().3, "an expired batch's claim is a refund");
        assert_eq!(refund.publics().0, vnf, "⛔ a refund spends another nullifier than the claim (both could pay)");
        // ⭐ §18.10 — a MAXIMUM BELOW THE PRICE: the same settled leaf, the order's bucket below j_min — it refunds a, at the
        // leaf the settlement inserted for every order of the batch
        let low = ClaimWitness { bucket: 0, out: w.amount, ..w.clone() };
        let (lr, li, lw) = claim_circuit(&low).expect("builds");
        assert!(lr.is_satisfied(&lr.lay_z(&li, &lw).expect("lays")), "an order whose maximum is below the price is refunded");
        assert!(low.publics().3, "and its claim says refund");
        // TAMPER: the low-bucket order claims the SAT fill under the refund-free flag — its publics name refund, so a fill
        // amount with refund = false is unsatisfiable
        let sneak = ClaimWitness { bucket: 0, out: w.out, ..w.clone() };
        let (_, _, sw) = claim_circuit(&sneak).expect("builds");
        let mut sio = claim_io(&sneak.publics().0, &sneak.publics().1, &sneak.publics().2, false);
        assert!(!lr.is_satisfied(&lr.lay_z(&sio, &sw).expect("lays")), "⛔ an order above its maximum was paid the fill");
        sio[24] = Fa4::ONE;
        assert!(!lr.is_satisfied(&lr.lay_z(&sio, &sw).expect("lays")), "⛔ a refund paid the fill's amount");
        // TAMPER: the over-claim under its own publics
        let over = ClaimWitness { out: w.out + 1, ..w.clone() };
        let (r2, i2, w2) = claim_circuit(&over).expect("builds");
        assert!(!r2.is_satisfied(&r2.lay_z(&i2, &w2).expect("lays")), "⛔ an over-claim satisfied its own relation");
        // TAMPER: a better price than the batch's (its leaf was never inserted — the published lc names another leaf)
        let better = ClaimWitness { p_num: w.p_num + 1, out: buy_paid(w.amount, w.p_num + 1, w.p_den).expect("fits"), ..w.clone() };
        assert_ne!(better.publics().1, vlc, "⛔ a claim at another price bound the batch's leaf");
        // TAMPER: a bucket the order never named (its limit commitment opens another bucket — another leaf)
        let other = ClaimWitness { bucket: 3, ..w.clone() };
        assert_ne!(other.publics().1, vlc, "⛔ a claim under another bucket bound the order's leaf");
        // ⭐ §18.12 — a COVER claim mints 0 under any leaf and a fresh nullifier, through the one claim shape; a cover that mints
        // anything has no witness
        let cov = ClaimWitness { amount: 0, out: 0, cover: Some(([31; 8], [32; 8])), ..w.clone() };
        let (rc, ic, wc) = claim_circuit(&cov).expect("a cover claim builds");
        assert!(rc.is_satisfied(&rc.lay_z(&ic, &wc).expect("lays")), "a cover claim holds");
        let cb = crate::spartan_ccs::prove_committed(&rc, &ic, &wc).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&shape, &ic, &cb), "a cover claim verifies against the one claim shape");
        assert!(claim_circuit(&ClaimWitness { out: 5, ..cov.clone() }).is_none(), "the builder refuses a cover that mints");
        let mut stolen = ic.clone();
        stolen[..8].copy_from_slice(&claim_io(&vnf, &vlc, &voc, false)[..8]); // the real claim's nullifier
        assert!(!rc.is_satisfied(&rc.lay_z(&stolen, &wc).expect("lays")), "⛔ a cover claim retired a real order's claim nullifier");
        let mut minted = ic.clone();
        minted[16..24].copy_from_slice(&claim_io(&vnf, &vlc, &voc, false)[16..24]); // the real fill's output commitment
        assert!(!rc.is_satisfied(&rc.lay_z(&minted, &wc).expect("lays")), "⛔ a cover claim minted the real fill's amount");
        // TAMPER: another amount under the honest publics
        let (_, _, wa) = claim_circuit(&ClaimWitness { amount: w.amount + 1, ..w.clone() }).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wa).expect("lays")), "⛔ another amount opened the order's commitment");
    }

    /// ⭐ §18.14 — A SELL PAYS Y AT THE SELLERS' PRICE AND THE SIDE CANNOT BE CHANGED AFTER THE ORDER: the same relation as a buy; a seller's fill and a buyer's money back
    /// both say `pays_y`, so the flag names an asset and never a side; a seller whose batch returned its sells gets its own amount back, in X; a seller claiming a buyer's
    /// price, or a buyer claiming as a seller, opens another leaf. CALIBRATION: the honest sell holds and verifies against the one shape.
    #[test]
    fn a_sell_pays_y_at_the_sellers_price_and_the_side_cannot_change() {
        use super::*;
        let shape = claim_r1cs().expect("the shape forms");
        let sell = ClaimWitness { amount: 1_000_000_007, amount_blind: [7; 8], bucket: 2, sell: true, deposit: false, withdraw: false, leg: 0, extra: LeafExtra::default(), entry: 0, now: 0, p_num: 1u128 << 23, p_den: 3_000_001, j_min: 1, s_num: 3_000_000, s_den: 1u128 << 23, out: 0, out_blind: [9; 8], lc_blind: [11; 8], cover: None };
        let sell = ClaimWitness { out: sell_paid(sell.amount, sell.s_num, sell.s_den).expect("fits"), ..sell };
        let (r, i, w) = claim_circuit(&sell).expect("builds");
        assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "an honest sell holds");
        // ⭐ EARN STEP 1 — LYING CLAIM: a filled sell paid over its whole SAT (its fee taken down) has no witness
        let no_fee = claim_out(sell.amount, sell.s_num, sell.s_den).expect("fits");
        assert!(no_fee > sell.out, "CALIBRATION: the fee moves this sell's payout");
        let lie = ClaimWitness { out: no_fee, ..sell.clone() };
        let (lr, li, lw) = claim_circuit(&lie).expect("builds");
        assert!(!lr.is_satisfied(&lr.lay_z(&li, &lw).expect("lays")), "⛔ a filled sell's claim was paid over its whole SAT, its fee taken down");
        let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ a sell does not verify against the one claim shape");
        assert!(sell.pays_y(), "a seller's fill mints Y");
        // the buyer's money back says the same thing: the flag names an asset, never a side
        let refund = ClaimWitness { sell: false, bucket: 0, j_min: 1, out: sell.amount, ..sell.clone() };
        assert_eq!(refund.pays_y(), sell.pays_y(), "⛔ the flag told a seller's fill from a buyer's money back");
        let (rr, ri, rw) = claim_circuit(&refund).expect("builds");
        assert!(rr.is_satisfied(&rr.lay_z(&ri, &rw).expect("lays")), "a buyer's money back holds");
        // a batch that returned its sells: the seller's own amount, in X
        let back = ClaimWitness { s_num: 0, s_den: 1, out: sell.amount, ..sell.clone() };
        let (br, bi, bw) = claim_circuit(&back).expect("builds");
        assert!(br.is_satisfied(&br.lay_z(&bi, &bw).expect("lays")), "a returned sell gets its amount back");
        assert!(!back.pays_y(), "a seller's own SAT back mints X, as a buyer's fill does");
        // TAMPERS
        let over = ClaimWitness { out: sell.out + 1, ..sell.clone() };
        let (or, oi, ow) = claim_circuit(&over).expect("builds");
        assert!(!or.is_satisfied(&or.lay_z(&oi, &ow).expect("lays")), "⛔ an over-claim on a sell satisfied the relation");
        let back_more = ClaimWitness { out: sell.amount + 1, ..back.clone() };
        let (mr, mi, mw) = claim_circuit(&back_more).expect("builds");
        assert!(!mr.is_satisfied(&mr.lay_z(&mi, &mw).expect("lays")), "⛔ a returned sell paid more than it put in");
        let as_buyer = ClaimWitness { sell: false, ..sell.clone() };
        assert_ne!(as_buyer.publics().1, sell.publics().1, "⛔ a seller's claim bound a buyer's leaf");
        let other_price = ClaimWitness { s_num: sell.s_num + 1, ..sell.clone() };
        assert_ne!(other_price.publics().1, sell.publics().1, "⛔ a sell at another price bound the batch's leaf");
        let (_, _, fw) = claim_circuit(&ClaimWitness { sell: false, ..sell.clone() }).expect("builds");
        assert!(!r.is_satisfied(&r.lay_z(&i, &fw).expect("lays")), "⛔ a buyer's witness opened a seller's publics");
    }

    /// ⭐ §18.14 — AN ORDER'S SIDE IS HIDDEN AND ITS NOTE MUST BE THE SIDE'S ASSET: a sell and a buy verify against one shape with the same public layout; a sell's shares put the amount on
    /// the X line and spend an X note; dealing the amount on a line its note's asset does not pay for has no witness. CALIBRATION: both honest sides hold.
    #[test]
    fn an_orders_side_is_hidden_and_its_note_is_the_sides_asset() {
        use super::*;
        let (n, t) = (4usize, 1usize);
        let (x_tag, y_tag) = ([0x51, 0x52, 0x53], [2, 0, 0]);
        let base = |on_x: bool| OrderDealing {
            amount: 70_000,
            amount_blind: [4; 8],
            bucket: 1,
            on_x,
            deposit: false,
            withdraw: None,
            x_tag,
            y_tag,
            coeffs: (0..ORDER_LINES).map(|l| (0..t).map(|k| fsmall(1 + 7 * l as u64 + k as u64)).collect()).collect(),
            salts: (0..n).map(|i| [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(2), Fa4::from_u64(3), Fa4::from_u64(4)]).collect(),
            binding: [7; 8],
            owner: [[11; 8], [12; 8], [13; 8]],
            lc_blind: [14; 8],
            cover: None,
            index: 3 << 32,
        };
        let shape = order_share_r1cs(n, t, x_tag, y_tag).expect("forms");
        for on_x in [true, false] {
            let d = base(on_x);
            let (r, i, w) = order_share_circuit(&d).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "an honest side holds");
            let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
            assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ one side does not verify against the one shape");
            assert_eq!(i[8], Fa4::ZERO, "⛔ the side reached the public input");
        }
        // the spent note is the side's: a sell spends an X note, a buy a Y note, and they differ
        assert_ne!(slot_note_cm(70_000, x_tag, &base(true).owner), slot_note_cm(70_000, y_tag, &base(true).owner), "the two assets' notes differ");
        assert_ne!(base(true).spend_publics().1, base(false).spend_publics().1, "each side's nullifier is its own note's");
        // TAMPER: a sell's witness under a buy's publics (the same amount and bucket): the limit commitment and the nullifier bind the side
        let (rb, ib, _) = order_share_circuit(&base(false)).expect("builds");
        let (_, _, ws) = order_share_circuit(&base(true)).expect("builds");
        assert!(!rb.is_satisfied(&rb.lay_z(&ib, &ws).expect("lays")), "⛔ a sell's witness opened a buy's publics");
        // ⭐ EARN STEP 2 — A SAT DEPOSIT is a third hidden kind under the SAME shape: it proves and verifies against the one
        // statement, its shares reconstruct to ⌊a/2⌋ on the sold line and the rest on the join line (nothing on the X line),
        // its code is its own (a sell's publics refuse its witness), and a deposit of the coin side does not build
        for amount in [70_000u64, 70_001] {
            let dep = OrderDealing { amount, deposit: true, ..base(true) };
            let (r, i, w) = order_share_circuit(&dep).expect("a deposit builds");
            assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "an honest deposit holds");
            let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
            assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ a deposit does not verify against the one shape");
            let at = |l: usize| {
                let ys: Vec<F> = (0..n).map(|k| dep.shares(k)[l]).collect();
                let lag = |k: usize| (0..n).filter(|j| *j != k).fold(fsmall(1), |acc, j| fmul(&acc, &fmul(&fsmall(j as u64 + 1), &finv(&fsub(&fsmall(j as u64 + 1), &fsmall(k as u64 + 1))))));
                (0..n).fold(fsmall(0), |acc, k| fadd(&acc, &fmul(&ys[k], &lag(k))))
            };
            assert_eq!(at(DEPOSIT_SOLD_LINE), fsmall(amount / 2), "⛔ the sold half is not ⌊a/2⌋");
            assert_eq!(at(DEPOSIT_JOIN_LINE), fsmall(amount - amount / 2), "⛔ the join half is not the rest");
            assert_eq!(at(0), fsmall(0), "⛔ a deposit put its amount on the sell line");
            let (rs, is, _) = order_share_circuit(&base(true)).expect("builds");
            assert!(!rs.is_satisfied(&rs.lay_z(&is, &w).expect("lays")), "⛔ a deposit's witness opened a sell's publics");
        }
        assert!(order_share_circuit(&OrderDealing { deposit: true, ..base(false) }).is_none(), "⛔ a deposit of the coin side built");
    }

    /// ⭐ EARN STEP 2 PIECE 3 — A WITHDRAWAL SPENDS A POSITION, NEVER MORE UNITS THAN IT IS. A deposit of 100,001 SAT counted
    /// at p_t = 1 is a position of at most `units_max` units: a withdrawal of exactly that proves and verifies under the one
    /// order shape and binds the position's leaf and its position nullifier; LYING: one unit more has no witness; a deposit
    /// that did NOT count (its batch's sells off, `s_num = 0`) is no position; an Earn leaf is no position; a withdrawal whose
    /// batch paid nothing is a position of exactly its own units (one more: no witness).
    /// TWO-PARTY-REVIEWED: the prover's witness against the VERIFIER's own shape (`order_share_r1cs`, formed from public data
    /// alone), the boundary every node's order door checks.
    #[test]
    fn earn_a_withdrawal_spends_a_position_and_never_more_units_than_it_is() {
        use super::*;
        let (n, t) = (4usize, 1usize);
        let one = 1u128 << 23;
        // a deposit made for a deposit batch that opened at index 7·2^32: its limit commitment names that entry, and its batch's
        // leaf the deposit lane (the deposits counted there)
        let pos = PositionWitness {
            x: 100_001,
            x_blind: [5; 8],
            bucket: 0,
            from_withdrawal: false,
            entry: 7 << 32,
            now: 0,
            p_num: one,
            p_den: one,
            j_min: 1,
            s_num: one,
            s_den: one,
            extra: LeafExtra { earn: false, dep: true },
        };
        let umax = pos.units_max().expect("a counted deposit is a position");
        assert!(umax > 49_000 && umax <= 50_000, "units ≈ the coin of the sold half at price 1: {umax}");
        let dealing = |u: u64, p: &PositionWitness| OrderDealing {
            amount: u,
            amount_blind: [6; 8],
            bucket: 0,
            on_x: false,
            deposit: false,
            withdraw: Some(p.clone()),
            x_tag: [0x51, 0x52, 0x53],
            y_tag: [2, 0, 0],
            coeffs: (0..ORDER_LINES).map(|l| (0..t).map(|k| fsmall(3 + 5 * l as u64 + k as u64)).collect()).collect(),
            salts: (0..n).map(|i| [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(2), Fa4::from_u64(3), Fa4::from_u64(4)]).collect(),
            binding: [7; 8],
            owner: [[0; 8]; 3],
            lc_blind: [8; 8],
            cover: None,
            // the Earn batch it rides opened at index 9·2^32: its "now"
            index: 9 << 32,
        };
        let shape = order_share_r1cs(n, t, [0x51, 0x52, 0x53], [2, 0, 0]).expect("forms");
        let d = dealing(umax, &pos);
        let (r, i, w) = order_share_circuit(&d).expect("builds");
        assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "an honest withdrawal holds");
        let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ a withdrawal does not verify against the one shape");
        assert_eq!(d.spend_publics().0, pos.leaf(), "the withdrawal's leg names the position's leaf");
        assert_eq!(d.spend_publics().1, pos.nullifier(), "and spends its position nullifier");
        // its own limit commitment names its position's entry and its batch's index as "now"
        assert_eq!(d.limit_commit(), limit_commit_x(WITHDRAW_BUCKET_BASE, &[6; 8], 7 << 32, 9 << 32), "the withdrawal names (entry, now)");
        for (what, lie) in [
            ("one unit more than the position", dealing(umax + 1, &pos)),
            ("a deposit that did not count (its sells off)", dealing(1, &PositionWitness { s_num: 0, s_den: 1, ..pos.clone() })),
            ("a deposit in a batch that was no deposit batch", dealing(1, &PositionWitness { extra: LeafExtra { dep: false, ..pos.extra }, ..pos.clone() })),
        ] {
            let (r, i, w) = order_share_circuit(&lie).expect("builds");
            assert!(!r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ a withdrawal of {what} has a witness");
        }
        assert_eq!(PositionWitness { extra: LeafExtra { dep: false, ..pos.extra }, ..pos.clone() }.units_max(), None, "a deposit outside a deposit batch is no position");
        assert_eq!(PositionWitness { extra: LeafExtra { earn: true, ..pos.extra }, ..pos.clone() }.units_max(), None, "an Earn leaf is no position");
        // a withdrawal whose batch paid nothing: its own leaf is the position, naming its own (entry, now)
        let carried = PositionWitness { x: 1_234, x_blind: [9; 8], bucket: 2, from_withdrawal: true, entry: 7 << 32, now: 8 << 32, extra: LeafExtra { dep: false, ..pos.extra }, ..pos.clone() };
        assert_eq!(carried.units_max(), Some(1_234));
        assert_eq!(carried.entry_index(), 7 << 32, "a carried withdrawal keeps its own entry");
        let (r, i, w) = order_share_circuit(&dealing(1_234, &carried)).expect("builds");
        assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "a carried withdrawal holds");
        let (r, i, w) = order_share_circuit(&dealing(1_235, &carried)).expect("builds");
        assert!(!r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ a carried withdrawal took one unit more");
    }

    /// ⭐ EARN STEP 2 PIECE 6 + STEP 3 — A WITHDRAWAL'S TWO CLAIMS at an Earn leaf: leg 0 its SAT at the leaf's SAT rate plus
    /// its income `⌊u·(I_now − I_entry)/2^32⌋`, leg 1 its coin at the coin rate (the coin asset), each under its own
    /// nullifier; at a trading leaf both mint 0. LYING: one unit more on either leg, its units at a trading leaf — no witness;
    /// an entry index below its own (more income) names another leaf, which no settlement inserted (the member leg refuses it).
    /// TWO-PARTY-REVIEWED: the claimant's witness against the VERIFIER's own shape (`claim_r1cs`), the boundary every node's
    /// claim door checks.
    #[test]
    fn earn_a_withdrawals_claims_pay_its_share_and_its_income_at_an_earn_leaf_only() {
        use super::*;
        let leg0 = ClaimWitness {
            amount: 50_000,
            amount_blind: [3; 8],
            bucket: 0,
            sell: false,
            deposit: false,
            withdraw: true,
            leg: 0,
            extra: LeafExtra { earn: true, dep: false },
            entry: 7 << 32,
            // its Earn batch's opening index, which its own limit commitment names
            now: (9u64 << 32) + 12_345,
            p_num: 1_000,
            p_den: 1_003,
            j_min: ORDER_BUCKETS as u64,
            s_num: 997,
            s_den: 1_000,
            out: 0,
            out_blind: [4; 8],
            lc_blind: [5; 8],
            cover: None,
        };
        let leg0 = ClaimWitness { out: leg0.paid().expect("fits"), ..leg0 };
        let leg1 = ClaimWitness { leg: 1, out: 0, ..leg0.clone() };
        let leg1 = ClaimWitness { out: leg1.paid().expect("fits"), ..leg1 };
        assert_eq!(u128::from(leg0.out), u128::from(claim_out(50_000, 1_000, 1_003).unwrap()) + ((50_000u128 * ((2u128 << 32) + 12_345)) >> 32));
        assert_eq!(leg1.out, claim_out(50_000, 997, 1_000).unwrap());
        assert_ne!(leg0.publics().0, leg1.publics().0, "two legs, two nullifiers");
        let shape = claim_r1cs().expect("forms");
        for (what, c) in [("SAT and income", &leg0), ("coin", &leg1)] {
            let (r, i, w) = claim_circuit(c).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "a withdrawal's {what} leg holds");
            let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
            assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ a withdrawal's {what} leg does not verify");
        }
        assert!(!leg0.pays_y() && leg1.pays_y(), "leg 0 mints SAT, leg 1 the coin");
        let trading = ClaimWitness { extra: LeafExtra { earn: false, ..leg0.extra }, j_min: 1, out: 0, ..leg0.clone() };
        assert_eq!(trading.paid(), Some(0));
        let (r, i, w) = claim_circuit(&trading).expect("builds");
        assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "at a trading leaf a withdrawal's claim mints 0");
        for (what, lie) in [
            ("one unit more on its SAT leg", ClaimWitness { out: leg0.out + 1, ..leg0.clone() }),
            ("one unit more on its coin leg", ClaimWitness { out: leg1.out + 1, ..leg1.clone() }),
            ("its units at a trading leaf", ClaimWitness { out: 1, ..trading.clone() }),
        ] {
            let (r, i, w) = claim_circuit(&lie).expect("builds");
            assert!(!r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ a withdrawal claim with {what} has a witness");
        }
        let earlier = ClaimWitness { entry: (7 << 32) - (1 << 20), ..leg0.clone() };
        assert_ne!(earlier.leaf(), leg0.leaf(), "⛔ a lower entry index names the same leaf (it would draw more income)");
        let later = ClaimWitness { now: leg0.now + (1 << 20), ..leg0.clone() };
        assert_ne!(later.leaf(), leg0.leaf(), "⛔ a later \"now\" names the same leaf (it would draw more income)");
        // an Earn leaf is a refund leaf for every trade and deposit: a sell and a deposit that land in an Earn batch get their
        // SAT back whole (the leaf's sell slot carries the coin rate, and its sell-fill lane is 0); paying a sell there at the
        // coin rate has no witness
        let sell_there = ClaimWitness { withdraw: false, leg: 0, sell: true, entry: 0, now: 0, out: 0, ..leg0.clone() };
        let dep_there = ClaimWitness { deposit: true, ..sell_there.clone() };
        for (what, c) in [("a sell", sell_there.clone()), ("a deposit", dep_there)] {
            assert_eq!(c.paid(), Some(c.amount), "{what} at an Earn leaf is refunded whole");
            let c = ClaimWitness { out: c.amount, ..c };
            let (r, i, w) = claim_circuit(&c).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ {what} at an Earn leaf cannot claim its SAT back");
        }
        let as_sold = ClaimWitness { out: sell_paid(sell_there.amount, sell_there.s_num, sell_there.s_den).expect("fits"), ..sell_there };
        let (r, i, w) = claim_circuit(&as_sold).expect("builds");
        assert!(!r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ a sell was paid at an Earn leaf's coin rate");
    }

    /// ⭐ EARN STEPS 2 + 3 — A DEPOSIT'S CLAIM: NOTHING at a deposit batch's leaf whose sells counted (its SAT joined the pool and
    /// its position is that leaf); its SAT back, whole, everywhere else — a REFUND leaf (an expired batch's or the complaint
    /// set's), a deposit batch whose sells were off, and a trading batch that was no deposit batch. LYING CLAIMS: the deposit's
    /// SAT taken at its deposit leaf, one unit more at a refund leaf, nothing outside a deposit batch (a deposit lost), and the
    /// deposit paid as the sell it resembles (its code is its own), each have no proof.
    #[test]
    fn earn_a_deposits_claim_is_its_sat_at_a_refund_leaf_and_nothing_at_a_settled_one() {
        use super::*;
        let settled = ClaimWitness {
            amount: 80_001,
            amount_blind: [9; 8],
            bucket: 1,
            sell: true,
            deposit: true,
            withdraw: false,
            leg: 0,
            extra: LeafExtra { earn: false, dep: true },
            // the deposit batch's opening index, its entry
            entry: 5 << 32,
            now: 0,
            p_num: 1_000,
            p_den: 997,
            j_min: 1,
            s_num: 997,
            s_den: 1_000,
            out: 0,
            out_blind: [3; 8],
            lc_blind: [4; 8],
            cover: None,
        };
        let no_dep = LeafExtra { earn: false, dep: false };
        let refund = ClaimWitness { p_num: 1, p_den: 1, j_min: ORDER_BUCKETS as u64, s_num: 0, s_den: 1, out: 80_001, extra: no_dep, ..settled.clone() };
        // a deposit batch whose sells were off (the floor bit): a deposit's sold half is a sell, so the deposit is refunded whole
        let sells_off = ClaimWitness { s_num: 0, s_den: 1, out: 80_001, extra: no_dep, ..settled.clone() };
        // a trading batch that was no deposit batch: its sells counted, its deposits did not
        let not_dep = ClaimWitness { out: 80_001, extra: no_dep, ..settled.clone() };
        let shape = claim_r1cs().expect("forms");
        for (what, c) in [
            ("at its deposit leaf, nothing", &settled),
            ("at a refund leaf, its SAT", &refund),
            ("where the sells were off, its SAT", &sells_off),
            ("in a batch that was no deposit batch, its SAT", &not_dep),
        ] {
            assert_eq!(c.paid(), Some(c.out), "the native rule: {what}");
            let (r, i, w) = claim_circuit(c).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "a deposit's claim {what} holds");
            let bytes = crate::spartan_ccs::prove_committed(&r, &i, &w).expect("proves");
            assert!(crate::spartan_ccs::verify_committed(&shape, &i, &bytes), "⛔ a deposit's claim does not verify against the one shape");
            assert!(!c.pays_y(), "⛔ a deposit's claim mints the coin");
        }
        for (what, lie) in [
            ("its SAT taken at its deposit leaf", ClaimWitness { out: 80_001, ..settled.clone() }),
            ("one unit more at a refund leaf", ClaimWitness { out: 80_002, ..refund.clone() }),
            ("nothing where the sells were off (a deposit lost)", ClaimWitness { out: 0, ..sells_off.clone() }),
            ("nothing outside a deposit batch (a deposit lost)", ClaimWitness { out: 0, ..not_dep.clone() }),
        ] {
            let (r, i, w) = claim_circuit(&lie).expect("builds");
            assert!(!r.is_satisfied(&r.lay_z(&i, &w).expect("lays")), "⛔ a deposit's claim with {what} has a witness");
        }
        // the deposit's leaf is not a sell's: a sell's claim at the same terms names a different leaf
        assert_ne!(settled.leaf(), ClaimWitness { deposit: false, ..settled.clone() }.leaf(), "⛔ a deposit's leaf is a sell's");
        assert!(claim_circuit(&ClaimWitness { sell: false, ..settled.clone() }).is_none(), "⛔ a deposit claim of the coin side built");
    }

    /// The native share field on LARGE random elements: associativity, distributivity, inverses, and the nodes' sharing check on
    /// a random degree-1 sharing of 0 with a full-size slope.
    #[test]
    fn br15_the_native_share_field_is_a_field_on_large_elements() {
        use super::*;
        let mut seed = 0xF1E1Du64;
        let mut big = || {
            let mut n = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            red4(&big_from(&[n(), n(), n(), n() >> 1]))
        };
        for _ in 0..50 {
            let (a, b, c) = (big(), big(), big());
            assert_eq!(fmul(&fmul(&a, &b), &c), fmul(&a, &fmul(&b, &c)), "(ab)c = a(bc)");
            assert_eq!(fmul(&fadd(&a, &b), &c), fadd(&fmul(&a, &c), &fmul(&b, &c)), "(a+b)c = ac + bc");
            assert_eq!(fmul(&a, &finv(&a)), fsmall(1), "a·a⁻¹ = 1");
            assert_eq!(fadd(&fsub(&a, &b), &b), a, "(a − b) + b = a");
            let slope = big();
            let line: Vec<F> = (1..=4u64).map(|x| fmul(&fsmall(x), &slope)).collect();
            assert!(sharing_holds(&line, 1, true), "a full-size degree-1 sharing of 0 holds: {line:?}");
        }
    }

    /// ⭐⭐ §BR-15 — AN ORDER'S SHARES ARE ITS AMOUNT'S: the share proof holds for an honest dealing (7 custodians, t = 2), proves
    /// and verifies; the named bucket's line interpolates to a and every other line to 0 at degree t; TAMPERS — a dealing whose
    /// amount is a + 1 under the honest commitments, the amount moved to another bucket, a share commitment for another
    /// custodian's share — are unsatisfiable.
    #[test]
    fn br15_an_orders_shares_open_to_its_committed_amount() {
        use super::*;
        let (n, t) = (7usize, 2usize);
        let mut seed = 0x0D_E5u64;
        let mut big = || {
            let mut nx = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            red4(&big_from(&[nx(), nx(), nx(), nx() >> 1]))
        };
        let d = OrderDealing {
            amount: 250_000_000,
            amount_blind: [5; 8],
            bucket: 1,
            on_x: false,
            deposit: false,
            withdraw: None,
            x_tag: [9, 9, 9],
            y_tag: [0, 0, 0],
            coeffs: (0..ORDER_LINES).map(|_| (0..t).map(|_| big()).collect()).collect(),
            salts: (0..n).map(|i| [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(2), Fa4::from_u64(3), Fa4::from_u64(4)]).collect(),
            binding: [7; 8],
            owner: [[11; 8], [12; 8], [13; 8]],
            lc_blind: [14; 8],
            cover: None,
            index: 0,
        };
        for l in 0..ORDER_LINES {
            let col: Vec<F> = (0..n).map(|i| d.shares(i)[l]).collect();
            if l == 1 + d.bucket {
                assert!(sharing_holds(&fsub_all(&col, &fsmall(d.amount)), t, true), "the named bucket's Y line is a degree-t sharing of a");
            } else {
                assert!(sharing_holds(&col, t, true), "line {l} is a degree-t sharing of 0");
            }
        }
        let (r1cs, io, w) = order_share_circuit(&d).expect("builds");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).expect("lays")), "the honest dealing holds");
        let t0 = std::time::Instant::now();
        let bytes = crate::spartan_ccs::prove_committed(&r1cs, &io, &w).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&r1cs, &io, &bytes), "and verifies");
        eprintln!("[br15-order] share proof for {n} custodians at t = {t}: {} constraints, proved in {} ms ({} B)", r1cs.rows(), t0.elapsed().as_millis(), bytes.len());
        let mut bad = d.clone();
        bad.amount += 1;
        let (_, _, wb) = order_share_circuit(&bad).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wb).expect("lays")), "⛔ another amount dealt under the honest commitments");
        // TAMPER: the amount dealt on another bucket's line than the limit commitment names
        let mut moved = d.clone();
        moved.bucket = 3;
        let (_, _, wm) = order_share_circuit(&moved).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wm).expect("lays")), "⛔ an order's amount moved to a bucket its limit commitment does not name");
        let mut swapped = io.clone();
        for k in 0..4 {
            swapped.swap(17 + k, 17 + 4 + k);
        }
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&swapped, &w).expect("lays")), "⛔ custodian 1's commitment opened custodian 2's share");
        // TAMPER (§18.12): the spend of a note this owner does not hold — another nullifier under the honest proof — is refused,
        // and a note whose value is not the amount dealt does not open the cross-bind
        let mut other_nf = io.clone();
        let at = other_nf.len() - 16;
        other_nf[at] += Fa4::ONE;
        assert!(!crate::spartan_ccs::verify_committed(&r1cs, &other_nf, &bytes), "⛔ an order spent another nullifier than its note's");
        let wrong_owner = OrderDealing { owner: [[11; 8], [99; 8], [13; 8]], ..d.clone() };
        let (_, _, wo) = order_share_circuit(&wrong_owner).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wo).expect("lays")), "⛔ another nullifier key opened the order's note");
        // ⭐ §18.12 — a COVER slot: amount 0, any leaf, a fresh nullifier — the same relation, verified by the same shape; a
        // cover claiming an amount is unsatisfiable (no note backs it)
        let cover = OrderDealing { amount: 0, cover: Some(([21; 8], [22; 8])), ..d.clone() };
        let (rc, ioc, wc) = order_share_circuit(&cover).expect("a cover builds");
        assert!(rc.is_satisfied(&rc.lay_z(&ioc, &wc).expect("lays")), "a cover slot holds");
        let cbytes = crate::spartan_ccs::prove_committed(&rc, &ioc, &wc).expect("a cover proves");
        assert_eq!(cbytes.len(), bytes.len(), "⛔ a cover's proof is not the shape of a real slot's");
        assert!(crate::spartan_ccs::verify_committed(&r1cs, &ioc, &cbytes), "a cover verifies against the one order shape");
        let mut rich = d.clone();
        rich.cover = Some(([21; 8], [22; 8]));
        assert!(order_share_circuit(&rich).is_none(), "the builder refuses a cover with an amount");
        let (_, _, wr) = order_share_circuit(&OrderDealing { amount: 0, ..cover.clone() }).expect("builds");
        // TAMPER (the burn attack): a cover under the REAL order's nullifier — its nullifier is in the cover domain, so the
        // real nullifier has no cover witness
        let mut stolen = ioc.clone();
        let at_nf = stolen.len() - 16;
        stolen[at_nf..at_nf + 8].copy_from_slice(&io[io.len() - 16..io.len() - 8]);
        assert!(!rc.is_satisfied(&rc.lay_z(&stolen, &wc).expect("lays")), "⛔ a cover retired a real order's nullifier");
        let mut forged_io = ioc.clone();
        forged_io[..8].copy_from_slice(&io[..8]); // the real order's amount commitment on a cover
        assert!(!rc.is_satisfied(&rc.lay_z(&forged_io, &wr).expect("lays")), "⛔ a cover carried an amount commitment it cannot open");
        // TAMPER: the proof carried with another order's sealed shares (another binding) does not verify
        let mut rebound = io.clone();
        let last = rebound.len() - 17;
        rebound[last] += Fa4::ONE;
        assert!(!crate::spartan_ccs::verify_committed(&r1cs, &rebound, &bytes), "⛔ a share proof verified under another order's binding");
    }

    /// ⭐ THE LAUNCH POSITION'S PROOF (spec §18.13): an honest dealing of the public 225,000-SAT donation at $1/SAT proves and
    /// verifies against the circuit the verifier forms from (n, t, price, tag) alone, and its lines are (P, Y, 0, Y) — a
    /// full-range curve on the position's own SAT.
    /// TAMPER: a position one unit above the note's value, a public position one unit off (the donation misstated), a virtual
    /// Y one unit off the price, and the proof under another note's commitment are each refused.
    #[test]
    fn br15_the_launch_position_opens_exactly_the_position_note_at_the_floor() {
        use super::*;
        let (n, t) = (4usize, 1usize);
        let price = (1u64, 1u64);
        let tag = crate::whir_rec_block::satoshi_asset_tag();
        let d = PoolDealing {
            position: 22_500_000_000_000,
            sk: [0x5A, 1, 2, 3, 4, 5, 6, 7],
            tag,
            price,
            coeffs: (0..POOL_LINES).map(|l| vec![[9 + l as u64, 8, 7, 1]; t]).collect(),
            salts: (0..n).map(|i| [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(5), Fa4::from_u64(6), Fa4::from_u64(7)]).collect(),
        };
        assert_eq!(d.lines(), [22_500_000_000_000, 22_500_000_000_000, 0, 22_500_000_000_000], "(P, Y, 0, Y) at $1/SAT");
        let (r1cs, io, w) = pool_open_circuit(&d).expect("builds");
        let shape = pool_open_r1cs(n, t, price, tag).expect("the verifier forms the shape");
        let t0 = std::time::Instant::now();
        let bytes = crate::spartan_ccs::prove_committed(&r1cs, &io, &w).expect("proves");
        assert!(crate::spartan_ccs::verify_committed(&shape, &io, &bytes), "the honest position verifies against the formed shape");
        eprintln!("[br15-launch] position proof for {n} custodians at t = {t}: {} constraints, {} ms, {} B", shape.rows(), t0.elapsed().as_millis(), bytes.len());
        let mut over = d.clone();
        over.position += 1;
        let (_, _, wo) = pool_open_circuit(&over).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wo).expect("lays")), "⛔ a position above the note's value opened");
        let commits = d.share_commits();
        let misstated = pool_open_io(&d.position_cm(), d.position - 1, &commits);
        assert!(!crate::spartan_ccs::verify_committed(&shape, &misstated, &bytes), "⛔ the proof verified a misstated public donation");
        let mut other = io.clone();
        other[0] += Fa4::ONE;
        assert!(!crate::spartan_ccs::verify_committed(&shape, &other, &bytes), "⛔ the proof verified under another note");
        let off = PoolDealing { price: (2, 1), ..d.clone() };
        let (_, _, wf) = pool_open_circuit(&off).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &wf).expect("lays")), "⛔ a virtual Y off the launch price opened");
    }

    /// ⭐⭐ §BR-15 (spec §18.11) — THE CUSTODY HANDOVER MOVES THE SAME POOL TO A NEW ROSTER: an old roster of 4 (t = 1) holding a
    /// pool hands it to a new roster of 7 (t' = 2): every old custodian's dealing proves against its pool commitment, every new
    /// custodian's acceptance proves its new commitment opens the Lagrange combination of its sub-shares, and the new shares
    /// interpolate (degree t') to the SAME four lines. TAMPERS: a dealer handing over a share it does not hold (one unit more
    /// under its own pool commitment), and a new custodian committing one unit more than its combination, are unsatisfiable.
    #[test]
    fn br15_the_custody_handover_moves_the_same_pool_to_a_new_roster() {
        use super::*;
        let (n, t, n2, t2) = (4usize, 1usize, 7usize, 2usize);
        let mut seed = 0x4A_7D0Fu64;
        // the pool's four lines, (Earn steps 1 + 3) the fee state — a backing of 2,000 SAT, 12,345 SAT of fresh fees, 9,000,000
        // of sampled presence — and a closed window of 3,000 SAT over 8,000,000 of presence awaiting its raise
        let pool = [7_000_000u64, 3_500_000, 1_000, 3_500_000, 2_000, 12_345, 9_000_000, 3_000, 8_000_000];
        assert_eq!(pool.len(), STATE_LINES);
        let cols: Vec<Vec<F>> = pool.iter().map(|v| share_poly(&fsmall(*v), t, n, &mut seed)).collect();
        let salt = |i: usize, k: u64| [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(k), Fa4::from_u64(3), Fa4::from_u64(4)];
        let deals: Vec<HandoverDealing> = (0..n)
            .map(|i| HandoverDealing {
                lines: core::array::from_fn(|l| cols[l][i]),
                salt: salt(i, 1),
                fee_salt: salt(i, 2),
                close_salt: salt(i, 3),
                coeffs: (0..STATE_LINES).map(|l| share_poly(&fsmall(l as u64), t2, t2, &mut seed)).collect(),
                salts: (0..n2).map(|j| salt(j, 100 + i as u64)).collect(),
                binding: [i as u64; 8],
            })
            .collect();
        let shape = handover_deal_r1cs(n2, t2).expect("the verifier forms the dealing shape");
        for (i, d) in deals.iter().enumerate() {
            let (r, io, w) = handover_deal_circuit(d).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&io, &w).expect("lays")), "dealer {i}'s dealing holds");
            if i == 0 {
                let t0 = std::time::Instant::now();
                let bytes = crate::spartan_ccs::prove_committed(&r, &io, &w).expect("proves");
                assert!(crate::spartan_ccs::verify_committed(&shape, &io, &bytes), "the dealing verifies against the formed shape");
                eprintln!("[br15-handover] one dealing to {n2} custodians: {} rows, {} ms, {} B", shape.rows(), t0.elapsed().as_millis(), bytes.len());
            }
        }
        // TAMPER: a dealer handing over one unit more than it holds, under its own (honest) pool commitment
        let mut liar = deals[1].clone();
        liar.lines[0] = fadd(&liar.lines[0], &fsmall(1));
        let (r1, io1, _) = handover_deal_circuit(&deals[1]).expect("builds");
        let (_, _, wl) = handover_deal_circuit(&liar).expect("builds");
        assert!(!r1.is_satisfied(&r1.lay_z(&io1, &wl).expect("lays")), "⛔ a dealer handed over a share its commitment does not hold");
        // ⭐ EARN STEP 1 — TAMPER: a dealer that drops (or pads) the fee line under its own fee commitment
        let mut skim = deals[2].clone();
        skim.lines[POOL_LINES] = fsmall(0);
        let (r2, io2, _) = handover_deal_circuit(&deals[2]).expect("builds");
        let (_, _, ws) = handover_deal_circuit(&skim).expect("builds");
        assert!(!r2.is_satisfied(&r2.lay_z(&io2, &ws).expect("lays")), "⛔ a dealer dropped the fee line its fee commitment holds");
        // ⭐ EARN STEP 3 — TAMPER: a dealer that drops a closed window's fees under its own close commitment
        let mut drop_closed = deals[3].clone();
        drop_closed.lines[CLOSE_AT] = fsmall(0);
        let (r3, io3, _) = handover_deal_circuit(&deals[3]).expect("builds");
        let (_, _, wc) = handover_deal_circuit(&drop_closed).expect("builds");
        assert!(!r3.is_satisfied(&r3.lay_z(&io3, &wc).expect("lays")), "⛔ a dealer dropped the closed window its close commitment holds");
        let accepts: Vec<HandoverAccept> = (0..n2)
            .map(|j| HandoverAccept {
                subs: deals.iter().map(|d| (d.shares(j), d.salts[j])).collect(),
                new_salt: salt(j, 900),
                new_fee_salt: salt(j, 901),
                new_close_salt: salt(j, 902),
            })
            .collect();
        let ashape = handover_accept_r1cs(n).expect("the verifier forms the acceptance shape");
        for (j, a) in accepts.iter().enumerate() {
            let (r, io, w) = handover_accept_circuit(a).expect("builds");
            assert!(r.is_satisfied(&r.lay_z(&io, &w).expect("lays")), "new custodian {j}'s acceptance holds");
            let subs: Vec<[Fa4; 4]> = deals.iter().map(|d| d.sub_commits()[j]).collect();
            assert_eq!(io, handover_accept_io(&subs, &a.new_commit(), &a.new_fee_commit(), &a.new_close_commit()), "the acceptance names the dealers' published commitments");
            if j == 0 {
                let bytes = crate::spartan_ccs::prove_committed(&r, &io, &w).expect("proves");
                assert!(crate::spartan_ccs::verify_committed(&ashape, &io, &bytes), "the acceptance verifies against the formed shape");
            }
        }
        // the new shares are a degree-t' sharing of the SAME pool and the SAME fee line
        for l in 0..STATE_LINES {
            let col: Vec<F> = accepts.iter().map(|a| a.lines()[l]).collect();
            assert!(sharing_holds(&fsub_all(&col, &fsmall(pool[l])), t2, true), "⛔ line {l} moved in the handover");
        }
        // TAMPER: a new custodian commits one unit more than its combination
        let (ra, ioa, _) = handover_accept_circuit(&accepts[3]).expect("builds");
        let mut fat = accepts[3].clone();
        fat.subs[0].0[1] = fadd(&fat.subs[0].0[1], &fsmall(1));
        let (_, _, wf) = handover_accept_circuit(&fat).expect("builds");
        assert!(!ra.is_satisfied(&ra.lay_z(&ioa, &wf).expect("lays")), "⛔ a new custodian's commitment opened more than its sub-shares combine to");
        // ⭐ EARN STEP 1 — TAMPER: a new custodian whose fee commitment opens a fee line one unit fatter than it was dealt
        let mut fat_fee = accepts[4].clone();
        fat_fee.subs[1].0[FEE_AT] = fadd(&fat_fee.subs[1].0[FEE_AT], &fsmall(1));
        let (rf, iof, _) = handover_accept_circuit(&accepts[4]).expect("builds");
        let (_, _, wff) = handover_accept_circuit(&fat_fee).expect("builds");
        assert!(!rf.is_satisfied(&rf.lay_z(&iof, &wff).expect("lays")), "⛔ a new custodian's fee commitment opened more than the fee line it was dealt");
        // ⭐ EARN STEP 3 — TAMPER: a new custodian whose close commitment opens a closed window's fees one unit fatter
        let mut fat_close = accepts[5].clone();
        fat_close.subs[2].0[CLOSE_AT] = fadd(&fat_close.subs[2].0[CLOSE_AT], &fsmall(1));
        let (rc, ioc, _) = handover_accept_circuit(&accepts[5]).expect("builds");
        let (_, _, wfc) = handover_accept_circuit(&fat_close).expect("builds");
        assert!(!rc.is_satisfied(&rc.lay_z(&ioc, &wfc).expect("lays")), "⛔ a new custodian's close commitment opened more than the closed window it was dealt");
    }

    fn fsub_all(v: &[super::F], c: &super::F) -> Vec<super::F> {
        v.iter().map(|x| super::fsub(x, c)).collect()
    }

    /// An EMPTY trading batch's custodian set (no orders: the pool 1,000 / 1,500 at the tick pair 1499/1000, 1501/1000 that
    /// brackets it) carrying the fee state `fee` = (B, E, A) and the closed lines `close` = (E_c, A_c), of kind `kind`, at the
    /// merge rate `dg` and with the custodians' allocation `alloc` (the rule's `⌊dg·2A_c/2^K⌋`, or a LIE).
    #[allow(clippy::type_complexity)]
    fn fee_batch(n: usize, t: usize, fee: [u64; 3], close: [u64; 2], kind: super::FeeKind, dg: u64, alloc: u64) -> (Vec<super::AuditWitness>, Vec<[super::Fa4; 4]>) {
        use super::*;
        let mut seed = 0xFE_E5A7u64;
        let pool = [1_000u64, 1_500, 0, 0];
        let forms = batch_statements(&fsmall(1_499), &fsmall(1_000), &fsmall(1_501), &fsmall(1_000), &fsmall(dg));
        let mut ints = [0u64; AUDIT_VALUES];
        ints[0] = pool[0];
        ints[1] = pool[1];
        ints[V_B] = fee[0];
        ints[V_E] = fee[1];
        ints[V_A] = fee[2];
        ints[V_EC] = close[0];
        ints[V_AC] = close[1];
        ints[V_ALLOC] = alloc;
        let zv: Vec<F> = forms.iter().map(|(c, c0)| c.iter().zip(&ints).fold(*c0, |a, (k, v)| fadd(&a, &fmul(k, &fsmall(*v))))).collect();
        let bits_of = |z: &F, k: usize| -> u64 { (z[k / 64] >> (k % 64)) & 1 };
        let sh = |v: u64, deg: usize, seed: &mut u64| share_poly(&fsmall(v), deg, n, seed);
        let ps: Vec<Vec<F>> = pool.iter().map(|v| sh(*v, t, &mut seed)).collect();
        let fs: Vec<Vec<F>> = fee.iter().map(|v| sh(*v, t, &mut seed)).collect();
        let cs: Vec<Vec<F>> = close.iter().map(|v| sh(*v, t, &mut seed)).collect();
        let al = sh(alloc, t, &mut seed);
        let zero = sh(0, t, &mut seed);
        let st_shares: Vec<(Vec<Vec<F>>, Vec<F>, Vec<Vec<F>>, Vec<Vec<F>>)> = (0..AUDIT_STATEMENTS)
            .map(|si| {
                let bits = (0..statement_bits(si)).map(|k| sh(bits_of(&zv[si], k), t, &mut seed)).collect();
                let wm = sh(0, t, &mut seed);
                let sm = (0..AUDIT_REPS).map(|_| sh(0, 2 * t, &mut seed)).collect();
                let um = (0..AUDIT_REPS).map(|r| sh(77 + r as u64, t, &mut seed)).collect();
                (bits, wm, sm, um)
            })
            .collect();
        let salt = |i: usize, k: u64| [Fa4::from_u64(i as u64), Fa4::from_u64(k), Fa4::from_u64(5), Fa4::from_u64(6)];
        let ws: Vec<AuditWitness> = (0..n)
            .map(|i| AuditWitness {
                pool: core::array::from_fn(|l| ps[l][i]),
                pool_salt: salt(i, 1),
                orders: Vec::new(),
                select: [[true; ORDER_BUCKETS]; 2],
                sells: true,
                earn: false,
                booked: [zero[i], zero[i]],
                fee: core::array::from_fn(|l| fs[l][i]),
                fee_salt: salt(i, 2),
                close: core::array::from_fn(|l| cs[l][i]),
                close_salt: salt(i, 3),
                fees: [zero[i], zero[i], zero[i], zero[i]],
                alloc: al[i],
                merge: kind.merge,
                close_out: kind.close_out,
                sample: kind.sample,
                deposits: kind.deposits,
                statements: (0..AUDIT_STATEMENTS)
                    .map(|si| AuditStatement {
                        coeffs: forms[si].0,
                        c0: forms[si].1,
                        bits: st_shares[si].0.iter().map(|v| v[i]).collect(),
                        w_mask: st_shares[si].1[i],
                        s_masks: st_shares[si].2.iter().map(|v| v[i]).collect(),
                        u_masks: st_shares[si].3.iter().map(|v| v[i]).collect(),
                    })
                    .collect(),
                new_pool_salt: salt(i, 50),
                new_fee_salt: salt(i, 51),
                new_close_salt: salt(i, 52),
                phase1_salt: salt(i, 99),
            })
            .collect();
        let p1: Vec<[Fa4; 4]> = ws.iter().map(phase1_digest).collect();
        (ws, p1)
    }

    /// ⭐⭐ EARN STEP 3 — THE FEE STATE MOVES BY THE BATCH'S KIND, AUDITED TO THE UNIT: four custodians (t = 1) over an empty
    /// batch. THE MERGE: a closed window of 3,000 SAT over 8,000,000 of presence, raised at the rate `epoch_rate(3,000,
    /// 8,000,000)`, allocates exactly `⌊dG·2A_c/2^K⌋` to the backing and the rest to the fresh line, and the closed lines go to
    /// 0; LYING CUSTODIANS one unit high or low on the allocation are refused by every node's sharing checks. THE CLOSE: the
    /// open window's fresh fees and presence move to the closed lines and the open ones go to 0. THE SAMPLE: the pool's X is
    /// added to the presence. Each proves against the circuit a node rebuilds for that kind. CALIBRATION: the honest sets pass.
    #[test]
    fn earn_the_fee_state_moves_by_the_batch_kind_and_a_custody_set_one_unit_off_on_the_merge_is_refused() {
        use super::*;
        let _one_audit = audit_gate(); // streamed audits (793 MB peak each): one per process, under AUDIT_GATE
        let (n, t) = (4usize, 1usize);
        let rec = |v: &[F]| fsub(&fmul(&fsmall(2), &v[0]), &v[1]);
        let col = |ws: &[AuditWitness], f: &dyn Fn(&AuditWitness) -> F| -> F { rec(&ws.iter().map(f).collect::<Vec<_>>()) };
        let prove_one = |ws: &[AuditWitness], ch: &AuditChallenges, what: &str| {
            for (i, w) in ws.iter().enumerate() {
                let io = audit_publics(w, ch);
                let bad = bad_rows_under(w, ch, &io);
                assert!(bad.is_empty(), "{what}: custodian {i}'s audit holds — first unsatisfied rows {:?}", &bad[..bad.len().min(8)]);
                if i == 0 {
                    let (pio, bytes) = custodian_audit_prove(w, ch).expect("the audit proves");
                    assert_eq!(pio, io, "{what}: the proof's publics are the audit's");
                    let forms: Vec<([F; AUDIT_VALUES], F)> = w.statements.iter().map(|s| (s.coeffs, s.c0)).collect();
                    assert!(audit_verify(0, w.select, w.sells, w.earn, kind_of(w), ch, &forms, &io, &bytes), "{what}: the audit verifies against the circuit a node forms");
                }
            }
        };
        // THE MERGE
        let dg = epoch_rate(3_000, 8_000_000);
        let alloc = u64::try_from((u128::from(dg) * 2 * 8_000_000) >> EARN_RATE_BITS).expect("fits");
        assert!(alloc <= 3_000 && alloc + 2 >= 3_000, "the rate allocates the window's fees to within its two floors: {alloc}");
        let merge = FeeKind { merge: true, ..FeeKind::default() };
        let (ws, p1) = fee_batch(n, t, [2_000, 500, 0], [3_000, 8_000_000], merge, dg, alloc);
        let ch = AuditChallenges::derive(&transcript(&p1));
        prove_one(&ws, &ch, "the merge");
        assert!(nodes_accept(&ws, &ch, t), "CALIBRATION: the honest merge passes every node's checks");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[0]), fsmall(2_000 + alloc), "the backing gains the allocation");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[1]), fsmall(500 + 3_000 - alloc), "the fresh line gains the rest of the window's fees");
        assert_eq!(col(&ws, &|w| new_close_shares(w)[0]), fsmall(0), "the closed fees are merged out");
        assert_eq!(col(&ws, &|w| new_close_shares(w)[1]), fsmall(0), "the closed presence is merged out");
        for (lie, what) in [(alloc + 1, "one unit high (the backing padded from the fresh fees)"), (alloc - 1, "one unit low (a provider's income skimmed)")] {
            let (lw, lp1) = fee_batch(n, t, [2_000, 500, 0], [3_000, 8_000_000], merge, dg, lie);
            let lch = AuditChallenges::derive(&transcript(&lp1));
            assert!(!nodes_accept(&lw, &lch, t), "⛔ LYING CUSTODIANS: an allocation {what} passed the audit");
        }
        // a batch that merges nothing may allocate nothing
        let (lw, lp1) = fee_batch(n, t, [2_000, 500, 0], [3_000, 8_000_000], FeeKind::default(), 0, 1);
        let lch = AuditChallenges::derive(&transcript(&lp1));
        assert!(!nodes_accept(&lw, &lch, t), "⛔ LYING CUSTODIANS: a batch that merges nothing allocated a unit");
        // THE CLOSE
        let close = FeeKind { close_out: true, ..FeeKind::default() };
        let (ws, p1) = fee_batch(n, t, [2_000, 700, 5_000_000], [0, 0], close, 0, 0);
        let ch = AuditChallenges::derive(&transcript(&p1));
        prove_one(&ws, &ch, "the close");
        assert!(nodes_accept(&ws, &ch, t), "CALIBRATION: the honest close passes every node's checks");
        assert_eq!(col(&ws, &|w| new_close_shares(w)[0]), fsmall(700), "the close moves the window's fresh fees");
        assert_eq!(col(&ws, &|w| new_close_shares(w)[1]), fsmall(5_000_000), "and its presence");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[1]), fsmall(0), "the open window starts empty");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[2]), fsmall(0), "with no presence");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[0]), fsmall(2_000), "the backing stays");
        // a custodian that keeps its close commitment but moves its closed share is refused by its own circuit
        let io = audit_publics(&ws[0], &ch);
        let mut moved = ws[0].clone();
        moved.close[0] = fadd(&moved.close[0], &fsmall(1));
        assert!(!bad_rows_under(&moved, &ch, &io).is_empty(), "⛔ a moved closed-line share opened the old close commitment");
        // THE SAMPLE
        let sample = FeeKind { sample: true, ..FeeKind::default() };
        let (ws, p1) = fee_batch(n, t, [2_000, 700, 5_000_000], [0, 0], sample, 0, 0);
        let ch = AuditChallenges::derive(&transcript(&p1));
        prove_one(&ws, &ch, "the sample");
        assert_eq!(col(&ws, &|w| new_fee_shares(w)[2]), fsmall(5_001_000), "the sample adds the pool's X to the presence");
    }

    /// One custodian set's EarnEpoch over the closed lines `closes` (one (E_c, A_c) per pair) at the rate `dg` they publish (the
    /// rule's [`epoch_rate`], or a LIE).
    fn epoch_set(n: usize, t: usize, closes: &[[u64; 2]], dg: u64) -> (Vec<super::EpochWitness>, Vec<[super::Fa4; 4]>, Vec<([super::F; super::AUDIT_VALUES], super::F)>) {
        use super::*;
        let mut seed = 0xE9_0C4Du64;
        let forms = epoch_statements(closes.len(), dg).expect("forms").to_vec();
        let mut ints = [0u64; AUDIT_VALUES];
        for (i, c) in closes.iter().enumerate() {
            ints[2 * i] = c[0];
            ints[2 * i + 1] = c[1];
        }
        let zv: Vec<F> = forms.iter().map(|(c, c0)| c.iter().zip(&ints).fold(*c0, |a, (k, v)| fadd(&a, &fmul(k, &fsmall(*v))))).collect();
        let bits_of = |z: &F, k: usize| -> u64 { (z[k / 64] >> (k % 64)) & 1 };
        let sh = |v: u64, deg: usize, seed: &mut u64| share_poly(&fsmall(v), deg, n, seed);
        let cs: Vec<[Vec<F>; 2]> = closes.iter().map(|c| [sh(c[0], t, &mut seed), sh(c[1], t, &mut seed)]).collect();
        let st_shares: Vec<(Vec<Vec<F>>, Vec<F>, Vec<Vec<F>>, Vec<Vec<F>>)> = (0..EPOCH_STATEMENTS)
            .map(|si| {
                let bits = (0..statement_bits(si)).map(|k| sh(bits_of(&zv[si], k), t, &mut seed)).collect();
                let wm = sh(0, t, &mut seed);
                let sm = (0..AUDIT_REPS).map(|_| sh(0, 2 * t, &mut seed)).collect();
                let um = (0..AUDIT_REPS).map(|r| sh(91 + r as u64, t, &mut seed)).collect();
                (bits, wm, sm, um)
            })
            .collect();
        let salt = |i: usize, k: u64| [Fa4::from_u64(i as u64), Fa4::from_u64(k), Fa4::from_u64(7), Fa4::from_u64(8)];
        let ws: Vec<EpochWitness> = (0..n)
            .map(|i| EpochWitness {
                close: cs.iter().enumerate().map(|(p, c)| ([c[0][i], c[1][i]], salt(i, 10 + p as u64))).collect(),
                statements: (0..EPOCH_STATEMENTS)
                    .map(|si| AuditStatement {
                        coeffs: forms[si].0,
                        c0: forms[si].1,
                        bits: st_shares[si].0.iter().map(|v| v[i]).collect(),
                        w_mask: st_shares[si].1[i],
                        s_masks: st_shares[si].2.iter().map(|v| v[i]).collect(),
                        u_masks: st_shares[si].3.iter().map(|v| v[i]).collect(),
                    })
                    .collect(),
                phase1_salt: salt(i, 99),
            })
            .collect();
        let p1: Vec<[Fa4; 4]> = ws.iter().map(epoch_phase1_digest).collect();
        (ws, p1, forms)
    }

    fn epoch_nodes_accept(ws: &[super::EpochWitness], ch: &super::AuditChallenges, t: usize) -> bool {
        use super::*;
        let pubs: Vec<Vec<AuditPublished>> = ws.iter().map(|w| epoch_published(w, ch)).collect();
        (0..EPOCH_STATEMENTS).all(|si| {
            let col = |f: &dyn Fn(&AuditPublished) -> F| -> Vec<F> { pubs.iter().map(|p| f(&p[si])).collect() };
            sharing_holds(&col(&|p| p.w), t, true)
                && (0..AUDIT_REPS).all(|r| sharing_holds(&col(&|p| p.s[r]), 2 * t, true))
                && (0..AUDIT_REPS).all(|r| sharing_holds(&col(&|p| p.u[r]), t, false))
        })
    }

    /// ⭐⭐ EARN STEP 3 — THE EARNEPOCH OPENS THE ONE PROTOCOL-WIDE RATE ITS CLOSED WINDOWS GIVE: four custodians (t = 1) over two
    /// pairs' closed windows (3,000 SAT over 8,000,000 of presence; 1,000 over 2,000,000) publish `dG = epoch_rate(4,000,
    /// 10,000,000)`; every custodian's audit holds and one proof verifies against the circuit a node forms from public data; every
    /// node's sharing checks pass. LYING CUSTODIANS: a rate one unit high (more income than the fees) and one unit low (less
    /// than the fees allow), each refused; a moved closed-line share under its close commitment, refused by its own circuit.
    /// A window with no sample publishes the grid's top and allocates nothing.
    #[test]
    fn earn_the_earn_epoch_opens_the_one_rate_its_closed_windows_give_and_refuses_a_lying_rate() {
        use super::*;
        let (n, t) = (4usize, 1usize);
        let closes = [[3_000u64, 8_000_000], [1_000, 2_000_000]];
        let dg = epoch_rate(4_000, 10_000_000);
        assert!(dg > 0 && dg < EARN_DG_MAX, "an ordinary window's rate is inside the grid: {dg}");
        let (ws, p1, forms) = epoch_set(n, t, &closes, dg);
        let ch = AuditChallenges::derive_n(&transcript(&p1), EPOCH_STATEMENTS);
        for (i, w) in ws.iter().enumerate() {
            let (r1cs, io, wit) = epoch_audit_circuit(w, &ch).expect("builds");
            let bad = r1cs.unsatisfied_rows(&r1cs.lay_z(&io, &wit).expect("lays"));
            assert!(bad.is_empty(), "custodian {i}'s EarnEpoch audit holds — first unsatisfied rows {:?}", &bad[..bad.len().min(8)]);
            if i == 0 {
                let bytes = crate::spartan_ccs::prove_committed(&r1cs, &io, &wit).expect("proves");
                let rebuilt = epoch_r1cs(closes.len(), &ch, &forms).expect("a node forms the circuit");
                assert!(crate::spartan_ccs::verify_committed(&rebuilt, &io, &bytes), "the EarnEpoch audit verifies against the FORMED circuit");
                eprintln!("[br15-epoch] one custodian's EarnEpoch audit over {} pairs: {} rows (2^{}), {} B", closes.len(), r1cs.rows(), r1cs.m_vars, bytes.len());
                let mut moved = w.clone();
                moved.close[1].0[0] = fadd(&moved.close[1].0[0], &fsmall(1));
                let (_, _, mw) = epoch_audit_circuit(&moved, &ch).expect("builds");
                assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &mw).expect("lays")), "⛔ a moved closed-line share opened the old close commitment");
            }
        }
        assert!(epoch_nodes_accept(&ws, &ch, t), "CALIBRATION: the honest rate passes every node's checks");
        for (lie, what) in [(dg + 1, "one unit high (income past the window's fees)"), (dg - 1, "one unit low (providers paid less than the fees allow)")] {
            let (lw, lp1, _) = epoch_set(n, t, &closes, lie);
            let lch = AuditChallenges::derive_n(&transcript(&lp1), EPOCH_STATEMENTS);
            assert!(!epoch_nodes_accept(&lw, &lch, t), "⛔ LYING CUSTODIANS: a rate {what} passed the EarnEpoch audit");
        }
        // no sample in the window: the top of the grid, and every allocation ⌊dG·2·0/2^K⌋ = 0
        assert_eq!(epoch_rate(500, 0), EARN_DG_MAX);
        let (ws, p1, _) = epoch_set(n, t, &[[500, 0], [0, 0]], EARN_DG_MAX);
        let ch = AuditChallenges::derive_n(&transcript(&p1), EPOCH_STATEMENTS);
        assert!(epoch_nodes_accept(&ws, &ch, t), "a window with no sample opens the top and allocates nothing");
    }
}

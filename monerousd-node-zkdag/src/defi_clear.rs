// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18) — THE BATCH CLEARING RULE AND ITS THRESHOLD COMPUTATION, MEASURED.
//!
//! **The rule (borrowed: Penumbra's per-block batch swap against a constant-product pool, Uniswap v2's curve).** A batch's
//! sellers put ΔX of asset X in, its buyers ΔY of asset Y. Every order fills at ONE price against the pool `(X, Y)`:
//!
//! ```text
//!     p = (Y + ΔY) / (X + ΔX)          seller i gets ⌊x_i · p⌋ of Y      buyer j gets ⌊y_j / p⌋ of X
//! ```
//!
//! — exactly "everyone deposits into the pool, then withdraws at the new ratio": the pool ends at
//! `X' = (X + ΔX) · Y / (Y + ΔY)`, `Y' = (Y + ΔY) · X / (X + ΔX)`, so `X'·Y' = X·Y` before rounding, and every rounding is
//! down, against the trader ([`clear`]; the invariant never falls and each asset is conserved to the unit). The price depends
//! only on four sums, so the threshold computation over the custody set needs no per-order comparison to find it — only ONE
//! opened number, the price rounded to the 0.1 % tick grid (Uniswap v3's tick shape, [`rule_tick`]): opening the exact
//! rational would hand out both sums whenever they are near-coprime (the depth and the volume), which the separation clause
//! forbids.
//!
//! **The threshold computation (spec §18.8), measured.** Honest-majority Shamir sharing over the prime field 2²⁵⁵ − 19 among
//! the custody set at threshold `⌊(n − 1)/3⌋`: multiplication by Damgård–Nielsen 2007 (one round per product, the double
//! sharings preprocessed); random bits by squaring (Damgård–Fitzi–Kiltz–Nielsen–Toft 2006, preprocessed); comparison by a
//! masked opening and a log-depth carry-lookahead less-than (Catrina–de Hoogh 2010); the tick by a k-ary search whose every
//! comparison of a stage runs in one set. [`ThresholdRun`] counts the ONLINE rounds and elements (the batch's latency) apart
//! from the OFFLINE ones (preprocessing, produced ahead of the batch). The 2026-11-01 prototype this replaces (2⁶¹ − 1, BGW
//! re-sharing, a bit-serial less-than, a binary search) measured 506 rounds per batch.

/// One batch's clearing: the price as the pair `(num, den)` = `(Y + ΔY, X + ΔX)`, each order's fill, and the pool after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clearing {
    pub num: u128,
    pub den: u128,
    pub seller_out: Vec<u128>,
    pub buyer_out: Vec<u128>,
    pub pool_x: u128,
    pub pool_y: u128,
}

/// ⭐ THE CLEARING RULE: sellers' X amounts `sells`, buyers' Y amounts `buys`, against the pool `(x, y)`. `None` for an empty
/// pool side (a pool with no depth prices nothing) or an overflow. Rounding is always down, so the pool never loses.
#[must_use]
pub fn clear(x: u128, y: u128, sells: &[u128], buys: &[u128]) -> Option<Clearing> {
    if x == 0 || y == 0 {
        return None;
    }
    let dx = sells.iter().try_fold(0u128, |a, v| a.checked_add(*v))?;
    let dy = buys.iter().try_fold(0u128, |a, v| a.checked_add(*v))?;
    let (num, den) = (y.checked_add(dy)?, x.checked_add(dx)?);
    let seller_out: Vec<u128> = sells.iter().map(|s| s.checked_mul(num).map(|v| v / den)).collect::<Option<_>>()?;
    let buyer_out: Vec<u128> = buys.iter().map(|b| b.checked_mul(den).map(|v| v / num)).collect::<Option<_>>()?;
    let pool_x = den.checked_sub(buyer_out.iter().sum())?;
    let pool_y = num.checked_sub(seller_out.iter().sum())?;
    Some(Clearing { num, den, seller_out, buyer_out, pool_x, pool_y })
}

// ─────────────── §18.8 THE REDESIGNED CLEARING over 2^255 − 19: DN07, a log-depth less-than, parallel k-ary stages ───────────────

/// An element of the prime field `2^255 − 19`, four little-endian 64-bit limbs, always reduced. Used here ONLY as a prime field
/// for Shamir shares (no curve, no group: §2's pre-quantum ban is on signatures and key exchange, not on a prime modulus).
/// Wide enough that every candidate comparison of the clearing (`|z| < 2^153`) plus a [`MASK255`]-bit statistical mask stays
/// below the modulus — no case split on the tick's exponent, no wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct F255(pub [u64; 4]);

const P255: [u64; 4] = [0xFFFF_FFFF_FFFF_FFED, u64::MAX, u64::MAX, 0x7FFF_FFFF_FFFF_FFFF];
/// The compared width: `z = Y·D − X·N` with `X, Y < 2^64` and the candidate's public scales below `2^88` lifts to `[0, 2^K)`.
pub const K255: u32 = 154;
/// The statistical mask of every masked opening: `z + r` with `r < 2^(K + MASK)` hides `z` to `2^-MASK`.
pub const MASK255: u32 = 40;

impl F255 {
    pub const ZERO: F255 = F255([0; 4]);
    pub const ONE: F255 = F255([1, 0, 0, 0]);
    #[must_use]
    pub fn from_u128(v: u128) -> F255 {
        F255([v as u64, (v >> 64) as u64, 0, 0])
    }
    #[must_use]
    pub fn pow2(k: u32) -> F255 {
        let mut l = [0u64; 4];
        l[(k / 64) as usize] = 1u64 << (k % 64);
        F255(l)
    }
    fn geq_p(l: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if l[i] != P255[i] {
                return l[i] > P255[i];
            }
        }
        true
    }
    fn sub_p(l: &mut [u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = l[i].overflowing_sub(P255[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            l[i] = d;
            borrow = u64::from(b1 || b2);
        }
    }
    #[must_use]
    pub fn add(self, o: F255) -> F255 {
        let mut l = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            l[i] = s;
            carry = u64::from(c1 || c2);
        }
        // both < p < 2^255: the sum < 2^256, so no limb carry is lost
        if Self::geq_p(&l) {
            Self::sub_p(&mut l);
        }
        F255(l)
    }
    #[must_use]
    pub fn neg(self) -> F255 {
        if self == F255::ZERO {
            return self;
        }
        let mut l = P255;
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = l[i].overflowing_sub(self.0[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            l[i] = d;
            borrow = u64::from(b1 || b2);
        }
        F255(l)
    }
    #[must_use]
    pub fn sub(self, o: F255) -> F255 {
        self.add(o.neg())
    }
    #[must_use]
    pub fn mul(self, o: F255) -> F255 {
        let mut w = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur = w[i + j] + u128::from(self.0[i]) * u128::from(o.0[j]) + carry;
                w[i + j] = cur & u128::from(u64::MAX);
                carry = cur >> 64;
            }
            w[i + 4] += carry;
        }
        // x = lo + 2^256·hi ≡ lo + 38·hi
        let mut r = [0u128; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            let cur = w[i] + 38 * w[i + 4] + carry;
            r[i] = cur & u128::from(u64::MAX);
            carry = cur >> 64;
        }
        r[4] = carry;
        // fold the bits at and above 2^255 (×19), twice is enough
        for _ in 0..2 {
            let top = (r[4] << 1) | (r[3] >> 63);
            r[3] &= u128::from(u64::MAX >> 1);
            r[4] = 0;
            let mut c = top * 19;
            for limb in r.iter_mut().take(4) {
                let cur = *limb + c;
                *limb = cur & u128::from(u64::MAX);
                c = cur >> 64;
            }
            r[4] = c;
        }
        let mut l = [r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64];
        if Self::geq_p(&l) {
            Self::sub_p(&mut l);
        }
        F255(l)
    }
    #[must_use]
    pub fn pow(self, e: &[u64; 4]) -> F255 {
        let mut r = F255::ONE;
        for i in (0..256).rev() {
            r = r.mul(r);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }
    #[must_use]
    pub fn inv(self) -> F255 {
        let mut e = P255;
        e[0] -= 2;
        self.pow(&e)
    }
    /// A square root (p ≡ 5 mod 8, Atkin's form): `x = a^((p+3)/8)`, times `√−1` when `x² = −a`. `None` for a non-square.
    #[must_use]
    pub fn sqrt(self) -> Option<F255> {
        // (p + 3) / 8 = 2^252 − 2
        let mut e = [u64::MAX, u64::MAX, u64::MAX, 0x0FFF_FFFF_FFFF_FFFF];
        e[0] = u64::MAX - 1;
        let x = self.pow(&e);
        if x.mul(x) == self {
            return Some(x);
        }
        // √−1 = 2^((p − 1)/4), (p − 1)/4 = 2^253 − 5
        let mut q = [u64::MAX, u64::MAX, u64::MAX, 0x1FFF_FFFF_FFFF_FFFF];
        q[0] = u64::MAX - 4;
        let i = F255::from_u128(2).pow(&q);
        let y = x.mul(i);
        (y.mul(y) == self).then_some(y)
    }
    /// The low 128 bits (a reduced element below 2^128 reads back exactly).
    #[must_use]
    pub fn low_u128(self) -> u128 {
        u128::from(self.0[0]) | (u128::from(self.0[1]) << 64)
    }
    /// Bit `i` of the canonical representative.
    #[must_use]
    pub fn bit(self, i: u32) -> bool {
        (self.0[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }
    /// The representative mod 2^k (k < 256).
    #[must_use]
    pub fn mod_pow2(self, k: u32) -> F255 {
        let mut l = self.0;
        for (j, limb) in l.iter_mut().enumerate() {
            let lo = 64 * j as u32;
            if lo >= k {
                *limb = 0;
            } else if k - lo < 64 {
                *limb &= (1u64 << (k - lo)) - 1;
            }
        }
        F255(l)
    }
}

/// The run's randomness: a blake3 XOF keyed by 32 bytes of entropy (the custody runtime's keys come from the OS, or the
/// simulator's stream when one is installed; a calibration keys it from its seed). Never consensus, never key material.
struct Prg(blake3::OutputReader);
impl Prg {
    fn keyed(key: &[u8; 32]) -> Self {
        Prg(blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-MPC-PRG-v1").finalize_xof())
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn field(&mut self) -> F255 {
        let l = [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64() >> 2];
        F255(l)
    }
}

/// A shared value: party i's share at index i (its evaluation at x = i + 1).
pub type Shared = Vec<F255>;

/// ⭐ An honest-majority run among `n` custodians at threshold `t = ⌊(n − 1)/3⌋` — privacy below a third of custody (§18.2 item
/// 3); `2t + 1 ≤ n`, so a degree-2t product opens directly. Multiplication is Damgård–Nielsen 2007 (DN07, borrowed): each party
/// masks its local product with its share of a preprocessed double sharing `([r]_t, [r]_2t)`, the king opens `xy + r` and sends
/// it back, every party subtracts `[r]_t` — ONE round and `2(n − 1)` elements per product online. The counters split ONLINE (the
/// batch's latency path) from OFFLINE (preprocessing, produced ahead of the batch and pipelined), the two numbers the onion
/// latency and the custody bandwidth are functions of.
pub struct ThresholdRun {
    pub n: usize,
    pub t: usize,
    pub rounds: u64,
    pub online_elements: u64,
    pub offline_rounds: u64,
    pub offline_elements: u64,
    prg: Prg,
    lagrange_cache: Vec<(usize, Vec<F255>)>,
}

impl ThresholdRun {
    #[must_use]
    pub fn new(n: usize, seed: u64) -> Self {
        Self {
            n,
            t: (n - 1) / 3,
            rounds: 0,
            online_elements: 0,
            offline_rounds: 0,
            offline_elements: 0,
            prg: Prg::keyed(blake3::hash(&seed.to_le_bytes()).as_bytes()),
            lagrange_cache: Vec::new(),
        }
    }
    fn share_deg(&mut self, v: F255, deg: usize) -> Shared {
        let coeffs: Vec<F255> = std::iter::once(v).chain((0..deg).map(|_| self.prg.field()).map(reduce_field)).collect();
        (1..=self.n as u128)
            .map(|x| {
                let x = F255::from_u128(x);
                coeffs.iter().rev().fold(F255::ZERO, |acc, c| acc.mul(x).add(*c))
            })
            .collect()
    }
    /// A dealer's degree-t sharing (an order owner's amount, or a party's own random).
    pub fn share(&mut self, v: F255) -> Shared {
        let t = self.t;
        self.share_deg(v, t)
    }
    fn lagrange(&mut self, k: usize) -> Vec<F255> {
        if let Some((_, w)) = self.lagrange_cache.iter().find(|(kk, _)| *kk == k) {
            return w.clone();
        }
        let w: Vec<F255> = (1..=k as u128)
            .map(|i| {
                (1..=k as u128).filter(|j| *j != i).fold(F255::ONE, |acc, j| {
                    acc.mul(F255::from_u128(j)).mul(F255::from_u128(j).sub(F255::from_u128(i)).inv())
                })
            })
            .collect();
        self.lagrange_cache.push((k, w.clone()));
        w
    }
    fn reconstruct(&mut self, s: &[F255], deg: usize) -> F255 {
        let w = self.lagrange(deg + 1);
        w.iter().zip(s).fold(F255::ZERO, |acc, (a, b)| acc.add(a.mul(*b)))
    }
    /// OPEN shared values of degree `deg` (t, or 2t for a product opened directly) in ONE round through the king.
    pub fn open_many_deg(&mut self, ss: &[Shared], deg: usize) -> Vec<F255> {
        self.rounds += 1;
        self.online_elements += (2 * (self.n - 1) * ss.len()) as u64;
        ss.iter().map(|s| self.reconstruct(s, deg)).collect()
    }
    pub fn open_many(&mut self, ss: &[Shared]) -> Vec<F255> {
        let t = self.t;
        self.open_many_deg(ss, t)
    }
    #[must_use]
    pub fn lin(a: &Shared, ca: F255, b: &Shared, cb: F255) -> Shared {
        a.iter().zip(b).map(|(x, y)| x.mul(ca).add(y.mul(cb))).collect()
    }
    #[must_use]
    pub fn add(a: &Shared, b: &Shared) -> Shared {
        a.iter().zip(b).map(|(x, y)| x.add(*y)).collect()
    }
    #[must_use]
    pub fn add_const(a: &Shared, c: F255) -> Shared {
        a.iter().map(|x| x.add(c)).collect()
    }
    #[must_use]
    pub fn scale(a: &Shared, c: F255) -> Shared {
        a.iter().map(|x| x.mul(c)).collect()
    }
    /// ⭐ DN07 MULTIPLY, every pair in ONE round. The double sharing is preprocessing: each party deals two sharings per
    /// `n − t` pairs extracted (DN07 §3's Vandermonde extraction), `2n(n − 1)/(n − t)` elements per pair, offline.
    pub fn mul_many(&mut self, pairs: &[(&Shared, &Shared)]) -> Vec<Shared> {
        self.rounds += 1;
        self.online_elements += (2 * (self.n - 1) * pairs.len()) as u64;
        self.offline_elements += ((2 * self.n * (self.n - 1)) as u64 * pairs.len() as u64).div_ceil((self.n - self.t) as u64);
        let (t, t2) = (self.t, 2 * self.t);
        let mut out = Vec::with_capacity(pairs.len());
        for (a, b) in pairs {
            let r = reduce_field(self.prg.field());
            let (rt, r2t) = (self.share_deg(r, t), self.share_deg(r, t2));
            let masked: Vec<F255> = a.iter().zip(b.iter()).zip(&r2t).map(|((x, y), m)| x.mul(*y).add(*m)).collect();
            let opened = self.reconstruct(&masked, t2);
            out.push(rt.iter().map(|s| opened.sub(*s)).collect());
        }
        out
    }
    /// `count` shared uniformly random BITS (Damgård et al. 2006: square a random shared `a`, open `a²`,
    /// `b = (a/√a² + 1)/2`) — OFFLINE: one product and one opening for any count. A zero square is redrawn, never patched.
    pub fn random_bits(&mut self, count: usize) -> Vec<Shared> {
        let (r0, e0) = (self.rounds, self.online_elements);
        let half = F255::from_u128(2).inv();
        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            let need = count - out.len();
            let rs: Vec<Shared> = (0..need).map(|_| { let v = reduce_field(self.prg.field()); self.share(v) }).collect();
            let sq = self.mul_many(&rs.iter().map(|r| (r, r)).collect::<Vec<_>>());
            let opened = self.open_many(&sq);
            for (r, a2) in rs.iter().zip(opened) {
                let Some(root) = (a2 != F255::ZERO).then(|| a2.sqrt()).flatten() else { continue };
                out.push(Self::add_const(&Self::scale(r, root.inv().mul(half)), half));
            }
        }
        self.offline_rounds += self.rounds - r0;
        self.offline_elements += self.online_elements - e0;
        self.rounds = r0;
        self.online_elements = e0;
        out
    }
    /// ⭐ `[c < r]` for MANY (public `c`, shared bits of `r`, least significant first) together, by the carry-lookahead tree:
    /// leaf `(g, p) = (r_i ∧ ¬c_i, r_i = c_i)` is linear (c is public); `(g, p)_{hi∘lo} = (g_hi + p_hi·g_lo, p_hi·p_lo)` —
    /// ⌈log₂ bits⌉ rounds for the whole set (Catrina–de Hoogh 2010's log-depth less-than, borrowed).
    pub fn public_lt_many(&mut self, cs: &[F255], r_bits: &[Vec<Shared>]) -> Vec<Shared> {
        let n = self.n;
        let neg1 = F255::ONE.neg();
        let mut level: Vec<Vec<(Shared, Shared)>> = cs
            .iter()
            .zip(r_bits)
            .map(|(c, bits)| {
                bits.iter()
                    .enumerate()
                    .map(|(i, rb)| {
                        if c.bit(i as u32) {
                            (vec![F255::ZERO; n], rb.clone())
                        } else {
                            (rb.clone(), Self::add_const(&Self::scale(rb, neg1), F255::ONE))
                        }
                    })
                    .collect()
            })
            .collect();
        while level.iter().any(|l| l.len() > 1) {
            let mut owned: Vec<(Shared, Shared)> = Vec::new();
            for l in &level {
                for ch in l.chunks(2) {
                    if let [lo, hi] = ch {
                        owned.push((hi.1.clone(), lo.0.clone()));
                        owned.push((hi.1.clone(), lo.1.clone()));
                    }
                }
            }
            let prods = self.mul_many(&owned.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>());
            let mut k = 0usize;
            level = level
                .into_iter()
                .map(|l| {
                    l.chunks(2)
                        .map(|ch| {
                            if let [_, hi] = ch {
                                let g = Self::add(&hi.0, &prods[k]);
                                let p = prods[k + 1].clone();
                                k += 2;
                                (g, p)
                            } else {
                                ch[0].clone()
                            }
                        })
                        .collect()
                })
                .collect();
        }
        level.into_iter().map(|mut l| l.remove(0).0).collect()
    }
    /// ⭐ `[a ≥ b]` for MANY shared pairs together (`|a − b| < 2^(K255 − 1)`): lift `z = a − b + 2^L` (L = K − 1, so
    /// `z ∈ [0, 2^K)` and the answer is z's bit L), mask it with a preprocessed `r = r_lo + 2^L·r_hi` (r_lo's L bits shared,
    /// r_hi of MASK255 bits), open every `z + r` in one round, recover `z mod 2^L = c' − r_lo + 2^L·[c' < r_lo]` through the
    /// log-depth less-than, and `(z − z mod 2^L)/2^L` is the bit — `1 + ⌈log₂ L⌉` online rounds for the whole set.
    pub fn geq_many(&mut self, ab: &[(Shared, Shared)]) -> Vec<Shared> {
        let l = K255 - 1;
        let lift = F255::pow2(l);
        let zs: Vec<Shared> = ab.iter().map(|(a, b)| Self::add_const(&Self::lin(a, F255::ONE, b, F255::ONE.neg()), lift)).collect();
        let lo_bits: Vec<Vec<Shared>> = (0..ab.len()).map(|_| self.random_bits(l as usize)).collect();
        let hi_bits: Vec<Vec<Shared>> = (0..ab.len()).map(|_| self.random_bits(MASK255 as usize)).collect();
        let n = self.n;
        let fold = |bits: &[Shared]| -> Shared {
            bits.iter().enumerate().fold(vec![F255::ZERO; n], |acc, (i, b)| Self::lin(&acc, F255::ONE, b, F255::pow2(i as u32)))
        };
        let r_lo: Vec<Shared> = lo_bits.iter().map(|b| fold(b)).collect();
        let r_hi: Vec<Shared> = hi_bits.iter().map(|b| fold(b)).collect();
        let masked: Vec<Shared> =
            zs.iter().zip(&r_lo).zip(&r_hi).map(|((z, lo), hi)| Self::lin(&Self::add(z, lo), F255::ONE, hi, lift)).collect();
        let opened = self.open_many(&masked);
        let c_lo: Vec<F255> = opened.iter().map(|c| c.mod_pow2(l)).collect();
        let borrow = self.public_lt_many(&c_lo, &lo_bits);
        let inv_lift = lift.inv();
        (0..ab.len())
            .map(|i| {
                let z_mod = Self::lin(&Self::add_const(&Self::scale(&r_lo[i], F255::ONE.neg()), c_lo[i]), F255::ONE, &borrow[i], lift);
                Self::scale(&Self::lin(&zs[i], F255::ONE, &z_mod, F255::ONE.neg()), inv_lift)
            })
            .collect()
    }

}

/// A uniformly drawn 254-bit pattern is below the modulus except with probability ≈ 2^-250; reduce it anyway (one compare).
fn reduce_field(x: F255) -> F255 {
    x.add(F255::ZERO)
}

/// `1.001^t = m · 2^(e − 23)` with the mantissa `m ∈ [2^23, 2^24)` — exact integer arithmetic, the same on every node: each
/// step multiplies (or divides) by 1.001 in ppm, rounding down, and renormalizes. For `|t| ≤ TICK_RANGE`.
#[must_use]
pub fn tick_mantissa(t: i64) -> (u128, i64) {
    let (mut m, mut e) = (1u128 << 23, 0i64);
    for _ in 0..t.unsigned_abs() {
        if t > 0 {
            m = m * 1_001_000 / 1_000_000;
            if m >= 1 << 24 {
                m >>= 1;
                e += 1;
            }
        } else {
            m = m * 1_000_000 / 1_001_000;
            if m < 1 << 23 {
                m <<= 1;
                e -= 1;
            }
        }
    }
    (m, e)
}

/// The tick range: `1.001^±45,000 = 2^±64.9` covers every price of two sums below 2^64 (`[2^-64, 2^64)`), so the search's
/// outer bounds are TRUE facts about every batch (the lowest candidate always tests true, the highest always false) — a
/// statement about the arithmetic, not a cap on a price.
pub const TICK_RANGE: i64 = 45_000;

/// ⭐ THE MAXIMUM-PRICE BUCKETS (spec §18.10): how far above its batch's opening tick an order's buyers will pay — +2 %, +10 %,
/// +50 % (1.001^20, 1.001^96, 1.001^406) — and none. An order names one (hidden: `br15_audit::limit_commit`); it fills at tick
/// `t` only if the price its buyers pay, `p_{t+1}`, is at or below its maximum. NOT a cap on the market: a bucket bounds what
/// ONE order pays; the price rises as far as any order (the last bucket names no maximum) or any later batch will pay.
pub const BUCKET_TICKS: [Option<i64>; usdm_decider::br15_audit::ORDER_BUCKETS] = [Some(20), Some(96), Some(406), None];

/// The bucket the wallet names by default (+10 %): a buyer is protected from a batch that moves more than 10 % before it fills,
/// and a rising market is not bounced batch after batch at the tight edge (Uniswap's 0.5 % default assumes a price the buyer
/// saw one block ago; a sealed batch's buyer sees none).
pub const DEFAULT_BUCKET: usize = 1;

/// Whether bucket `j` of a batch opened at `base` fills at tick `t`: its buyers pay `p_{t+1}`, at or below `p_{base + δ_j}`.
#[must_use]
pub fn bucket_fills(base: i64, j: usize, t: i64) -> bool {
    BUCKET_TICKS.get(j).copied().flatten().map_or(true, |d| base.saturating_add(d) >= t.saturating_add(1))
}

/// Which buckets fill at `t` (an upward-closed set: a larger maximum fills wherever a smaller one does).
#[must_use]
pub fn fill_select(base: i64, t: i64) -> [bool; usdm_decider::br15_audit::ORDER_BUCKETS] {
    core::array::from_fn(|j| bucket_fills(base, j, t))
}

/// The lowest bucket that fills at `t` (`ORDER_BUCKETS` when none does) — what a claim leaf names.
#[must_use]
pub fn j_min(base: i64, t: i64) -> u64 {
    (0..usdm_decider::br15_audit::ORDER_BUCKETS).find(|j| bucket_fills(base, *j, t)).unwrap_or(usdm_decider::br15_audit::ORDER_BUCKETS) as u64
}

/// The public scales of candidate `t`'s test `ΣY ≥ ΣX · 1.001^t`: `ΣY · 2^(23 + max(0, −e))` against `ΣX · m · 2^max(0, e)` —
/// both sides below `2^(88 + 65)`, so the difference fits [`K255`] with no case split and no wrap.
#[must_use]
pub fn candidate_scales(t: i64) -> (F255, F255) {
    let (m, e) = tick_mantissa(t);
    let ys = F255::pow2(23 + u32::try_from((-e).max(0)).unwrap_or(0));
    let xs = F255::from_u128(m).mul(F255::pow2(u32::try_from(e.max(0)).unwrap_or(0)));
    (ys, xs)
}

/// The plain rule's answer to the same test, in exact integers (what every node can check a settled tick against with the two
/// sums, and what the calibration compares the threshold run to).
#[must_use]
pub fn candidate_holds(sum_x: u128, sum_y: u128, t: i64) -> bool {
    let (m, e) = tick_mantissa(t);
    // ΣY · 2^(23 + max(0,−e)) ≥ ΣX · m · 2^max(0,e), in 256-bit integers via F255 (both sides < 2^153 < p: exact)
    let lhs = F255::from_u128(sum_y).mul(F255::pow2(23 + u32::try_from((-e).max(0)).unwrap_or(0)));
    let rhs = F255::from_u128(sum_x).mul(F255::from_u128(m)).mul(F255::pow2(u32::try_from(e.max(0)).unwrap_or(0)));
    for i in (0..4).rev() {
        if lhs.0[i] != rhs.0[i] {
            return lhs.0[i] > rhs.0[i];
        }
    }
    true
}

/// The plain rule's tick: the largest `t` in `[−TICK_RANGE, TICK_RANGE)` whose test holds (binary search; the test is monotone).
#[must_use]
pub fn rule_tick(sum_x: u128, sum_y: u128) -> i64 {
    let (mut lo, mut hi) = (-TICK_RANGE, TICK_RANGE);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if candidate_holds(sum_x, sum_y, mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Tick `t`'s price as the exact rational `(num, den)` = `(m · 2^max(0,e), 2^(23 + max(0,−e)))` — the one spelling every claim,
/// every settlement check and the pool's booking read.
#[must_use]
pub fn tick_ratio(t: i64) -> (u128, u128) {
    let (m, e) = tick_mantissa(t);
    let up = u32::try_from(e.max(0)).unwrap_or(0);
    let down = u32::try_from((-e).max(0)).unwrap_or(0);
    (m << up, 1u128 << (23 + down))
}

/// A seller's claim at tick `t`: `⌊x · p_t⌋` of Y — at the tick's own price, never above the rule's (`p_t ≤ p`).
#[must_use]
pub fn seller_claim(x: u128, t: i64) -> Option<u128> {
    let (num, den) = tick_ratio(t);
    Some(x.checked_mul(num)? / den)
}

/// A buyer's claim at tick `t`: `⌊y / p_{t+1}⌋` of X — at the NEXT tick's price, never better than the rule's (`p < p_{t+1}`).
#[must_use]
pub fn buyer_claim(y: u128, t: i64) -> Option<u128> {
    let (num, den) = tick_ratio(t + 1);
    Some(y.checked_mul(den)? / num)
}

/// ⭐ THE SETTLEMENT AT A TICK (§18.8): every seller is paid at `p_t`, every buyer at `p_{t+1}` — each side at the tick edge
/// that favours the pool, so for the tick of the rule's price (`p_t ≤ p < p_{t+1}`) every outflow is at most the rule's and
/// the pool ends at or above its invariant (`X'·Y' ≥ X·Y`, exact; MEASURED 2026-11-01: a single rounded price for both sides
/// broke it by up to 0.3 %, even under a 0.3 % fee). The pool books its outflows as the totals' claims
/// (`⌊ΔX·p_t⌋`, `⌊ΔY/p_{t+1}⌋`), which no sum of the orders' own floors can exceed — the custody set needs only the two sums.
/// Returns `(seller claims, buyer claims, pool X', pool Y')`; `None` on an overflow or an empty pool side.
#[must_use]
pub fn settle_at_tick(x: u128, y: u128, sells: &[u128], buys: &[u128], t: i64) -> Option<(Vec<u128>, Vec<u128>, u128, u128)> {
    if x == 0 || y == 0 {
        return None;
    }
    let dx = sells.iter().try_fold(0u128, |a, v| a.checked_add(*v))?;
    let dy = buys.iter().try_fold(0u128, |a, v| a.checked_add(*v))?;
    let s: Vec<u128> = sells.iter().map(|v| seller_claim(*v, t)).collect::<Option<_>>()?;
    let b: Vec<u128> = buys.iter().map(|v| buyer_claim(*v, t)).collect::<Option<_>>()?;
    let pool_x = x.checked_add(dx)?.checked_sub(buyer_claim(dy, t)?)?;
    let pool_y = y.checked_add(dy)?.checked_sub(seller_claim(dx, t)?)?;
    Some((s, b, pool_x, pool_y))
}

/// ⭐⭐ THE REDESIGNED THRESHOLD CLEARING (§18.8), end to end over shares: the custody set holds `ΣX`, `ΣY` as shares (each
/// order shared by its owner, the sums local). Stage one tests, IN PARALLEL, the `width` ticks around the last public tick
/// `around`; if the price left that window, each later stage splits the remaining interval `width + 1` ways (a k-ary search,
/// every comparison of a stage in one set). Opened: one comparison bit per candidate — each a bit every observer also derives
/// from the final tick (the candidates are public and the test is monotone in t). Returns the tick, the stages and the run.
pub fn threshold_tick_staged(n: usize, seed: u64, pool: (u64, u64), sells: &[u64], buys: &[u64], around: i64, width: usize) -> (i64, usize, ThresholdRun) {
    let mut run = ThresholdRun::new(n, seed);
    let mut sx = run.share(F255::from_u128(u128::from(pool.0)));
    let mut sy = run.share(F255::from_u128(u128::from(pool.1)));
    for v in sells {
        let sh = run.share(F255::from_u128(u128::from(*v)));
        sx = ThresholdRun::add(&sx, &sh);
    }
    for v in buys {
        let sh = run.share(F255::from_u128(u128::from(*v)));
        sy = ThresholdRun::add(&sy, &sh);
    }
    let (tick, stages) = tick_search(&mut run, &sx, &sy, around, width);
    (tick, stages, run)
}

/// ⭐ THE STAGED TICK SEARCH over shared sums `ΣX`, `ΣY` (the custody runtime's and the calibration's one search): the largest
/// `t` whose test `ΣY ≥ ΣX · 1.001^t` holds, opening one comparison bit per candidate. Returns the tick and the stages.
pub fn tick_search(run: &mut ThresholdRun, sx: &Shared, sy: &Shared, around: i64, width: usize) -> (i64, usize) {
    // (lo, hi): the tick lies in [lo, hi); lo's test holds, hi's fails (the range's outer bounds hold by arithmetic)
    let (mut lo, mut hi) = (-TICK_RANGE, TICK_RANGE);
    let half = (width / 2) as i64;
    let mut cands: Vec<i64> = ((around - half).max(lo + 1)..(around + half + 1).min(hi)).collect();
    let mut stages = 0usize;
    while hi - lo > 1 {
        stages += 1;
        let pairs: Vec<(Shared, Shared)> = cands
            .iter()
            .map(|t| {
                let (ys, xs) = candidate_scales(*t);
                (ThresholdRun::scale(sy, ys), ThresholdRun::scale(sx, xs))
            })
            .collect();
        let ge = run.geq_many(&pairs);
        let bits = run.open_many(&ge);
        for (t, b) in cands.iter().zip(&bits) {
            if *b == F255::ONE {
                lo = lo.max(*t);
            } else {
                hi = hi.min(*t);
            }
        }
        let span = hi - lo;
        let step = (span / (width as i64 + 1)).max(1);
        cands = (1..=width as i64).map(|k| lo + k * step).filter(|c| *c < hi).collect();
    }
    (lo, stages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ THE RULE IS SOUND: every batch keeps the pool's invariant (never below `x·y`), conserves each asset to the unit (what
    /// went in = what came out + what the pool kept) and pays every order at the one price, rounded down.
    /// TAMPER: a payout one unit above the rule's breaks conservation (the pool would pay what it does not hold).
    #[test]
    fn br15_the_batch_clearing_keeps_the_invariant_and_conserves_each_asset() {
        let mut seed = 0x15_u64;
        let mut r = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let x = 1_000 + u128::from(r() % 1_000_000_000);
            let y = 1_000 + u128::from(r() % 1_000_000_000);
            let sells: Vec<u128> = (0..(r() % 8)).map(|_| u128::from(r() % 10_000_000)).collect();
            let buys: Vec<u128> = (0..(r() % 8)).map(|_| u128::from(r() % 10_000_000)).collect();
            let c = clear(x, y, &sells, &buys).expect("a priced pool clears");
            assert!(c.pool_x * c.pool_y >= x * y, "⛔ the pool's invariant fell");
            let in_x: u128 = x + sells.iter().sum::<u128>();
            let in_y: u128 = y + buys.iter().sum::<u128>();
            assert_eq!(c.pool_x + c.buyer_out.iter().sum::<u128>(), in_x, "⛔ X not conserved");
            assert_eq!(c.pool_y + c.seller_out.iter().sum::<u128>(), in_y, "⛔ Y not conserved");
            for (s, o) in sells.iter().zip(&c.seller_out) {
                assert!(*o * c.den <= s * c.num && (o + 1) * c.den > s * c.num, "every seller is paid ⌊x·p⌋");
            }
            if let Some(o) = c.seller_out.first() {
                let mut forged = c.seller_out.clone();
                forged[0] = o + 1;
                assert_ne!(c.pool_y + forged.iter().sum::<u128>(), in_y, "TAMPER: an over-payment shows as a conservation break");
            }
        }
        assert_eq!(clear(0, 5, &[1], &[]), None, "a pool with no depth prices nothing");
    }

    /// The tick grid: [`rule_tick`] lands on the largest `t` whose exact test holds, the same on every node, monotone in the
    /// price; the mantissa grid steps 0.1 % (within its rounding) and renormalizes at each doubling.
    #[test]
    fn br15_the_tick_grid_is_exact_and_monotone() {
        assert_eq!(rule_tick(1, 1), 0);
        assert_eq!(rule_tick(1_000, 1_001), 1, "a 0.1 % move up reaches the next tick (its mantissa rounds down)");
        assert_eq!(rule_tick(1_000, 1_002), 1);
        assert_eq!(rule_tick(1_001, 1_000), -1);
        assert_eq!(tick_mantissa(693).1, 0, "693 ticks stay below a doubling");
        assert_eq!(tick_mantissa(694).1, 1, "694 ticks cross it");
        let mut last = i64::MIN;
        for k in 1..400u128 {
            let t = rule_tick(1_000, 1_000 + k * 7);
            assert!(t >= last, "monotone");
            last = t;
        }
        assert!(candidate_holds(u128::from(u64::MAX), 1, -TICK_RANGE), "the lowest candidate holds for the lowest price");
        assert!(!candidate_holds(1, u128::from(u64::MAX), TICK_RANGE), "the highest fails for the highest price");
    }

    /// ⭐ THE SETTLEMENT AT THE RULE'S TICK IS SOUND: the pool never falls below its invariant, no order's claim exceeds the rule's
    /// own fill, the claims never exceed what the pool booked (so no claim can overdraw it), and the dust the booking keeps out
    /// of the claims is at most one unit per order. TAMPER: settling the buyers at the tick's own price (one price for both
    /// sides) breaks the invariant on some batch.
    #[test]
    fn br15_settling_each_side_at_its_tick_edge_keeps_the_invariant() {
        let mut seed = 0x1588_u64;
        let mut r = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut one_price_broke = false;
        for _ in 0..2_000 {
            let x = 1_000 + u128::from(r() % 1_000_000_000_000);
            let y = 1_000 + u128::from(r() % 1_000_000_000_000);
            let sells: Vec<u128> = (0..(r() % 6)).map(|_| u128::from(r()) % (3 * x / 4 + 1)).collect();
            let buys: Vec<u128> = (0..(r() % 6)).map(|_| u128::from(r()) % (3 * y / 4 + 1)).collect();
            let rule = clear(x, y, &sells, &buys).expect("clears");
            let t = rule_tick(rule.den, rule.num);
            let (sc, bc, px, py) = settle_at_tick(x, y, &sells, &buys, t).expect("settles");
            assert!(px * py >= x * y, "⛔ the pool fell below its invariant at the tick");
            for (a, b) in sc.iter().zip(&rule.seller_out) {
                assert!(a <= b, "⛔ a seller's claim exceeds the rule's fill");
            }
            for (a, b) in bc.iter().zip(&rule.buyer_out) {
                assert!(a <= b, "⛔ a buyer's claim exceeds the rule's fill");
            }
            let dx: u128 = sells.iter().sum();
            let dy: u128 = buys.iter().sum();
            let (booked_y, booked_x) = (seller_claim(dx, t).unwrap(), buyer_claim(dy, t).unwrap());
            assert!(sc.iter().sum::<u128>() <= booked_y && bc.iter().sum::<u128>() <= booked_x, "⛔ the claims overdraw the booking");
            assert!(booked_y - sc.iter().sum::<u128>() <= sc.len() as u128, "dust ≤ one unit per seller");
            assert!(booked_x - bc.iter().sum::<u128>() <= bc.len() as u128, "dust ≤ one unit per buyer");
            // TAMPER: buyers at the tick's own price
            let (num, den) = tick_ratio(t);
            let one_x = x + dx - dy * den / num;
            if one_x * py < x * y {
                one_price_broke = true;
            }
        }
        assert!(one_price_broke, "CALIBRATION: one price for both sides must break the invariant on some batch");
    }

    /// The field: the reduction, inverse and square root agree with their definitions on random and edge elements.
    #[test]
    fn br15_the_share_field_is_the_prime_field_2_255_minus_19() {
        let mut prg = Prg::keyed(&[7; 32]);
        let neg1 = F255::ONE.neg();
        assert_eq!(neg1.add(F255::ONE), F255::ZERO);
        assert_eq!(neg1.mul(neg1), F255::ONE, "(−1)² = 1 across the reduction");
        for _ in 0..200 {
            let (a, b) = (reduce_field(prg.field()), reduce_field(prg.field()));
            assert_eq!(a.mul(b), b.mul(a));
            if a != F255::ZERO {
                assert_eq!(a.mul(a.inv()), F255::ONE, "a · a⁻¹ = 1");
            }
            let sq = a.mul(a);
            let r = sq.sqrt().expect("a square has a root");
            assert!(r == a || r == a.neg(), "√(a²) = ±a");
            assert_eq!(a.sub(b).add(b), a);
        }
        assert_eq!(F255::from_u128(u128::MAX).mul(F255::from_u128(u128::MAX)).mul(F255::ONE), F255::from_u128(u128::MAX).mul(F255::from_u128(u128::MAX)));
    }

    /// ⭐⭐ §BR-15 (spec §18.8) — THE REDESIGNED THRESHOLD CLEARING LANDS ON THE RULE'S TICK, OPENS ONLY CANDIDATE BITS, AND ITS
    /// COST IS MEASURED at n = 20 (t = 6): one stage when the price stays inside the window, more when it jumps, the ONLINE
    /// rounds and bytes (the batch's latency) and the OFFLINE preprocessing printed apart. CALIBRATION: `geq_many` agrees with
    /// the plain comparison on both sides of equality and at the width's edge; a shared random bit opens to 0 or 1.
    #[test]
    fn br15_the_threshold_clearing_opens_only_the_tick_and_its_rounds_are_measured() {
        let mut run = ThresholdRun::new(7, 0xC0FFEE);
        let cases: Vec<(u128, u128)> = vec![(5, 3), (3, 5), (9, 9), (0, 1), (u128::MAX, 0), (0, u128::MAX), (u128::MAX, u128::MAX - 1)];
        let pairs: Vec<(Shared, Shared)> =
            cases.iter().map(|(a, b)| (run.share(F255::from_u128(*a)), run.share(F255::from_u128(*b)))).collect();
        let ge = run.geq_many(&pairs);
        let opened = run.open_many(&ge);
        for ((a, b), g) in cases.iter().zip(&opened) {
            assert_eq!(*g, if a >= b { F255::ONE } else { F255::ZERO }, "CALIBRATION: [{a} ≥ {b}] over shares");
        }
        let bits = run.random_bits(8);
        for b in &bits {
            let v = run.open_many(std::slice::from_ref(b))[0];
            assert!(v == F255::ZERO || v == F255::ONE, "CALIBRATION: a shared random bit is a bit");
        }
        let pool = (4_000_000u64, 8_000_000u64);
        let sells: Vec<u64> = (1..=5).map(|i| 10_000 * i).collect();
        let buys: Vec<u64> = (1..=5).map(|i| 25_000 * i).collect();
        let wide = |v: &[u64]| v.iter().map(|x| u128::from(*x)).collect::<Vec<_>>();
        let plain = clear(u128::from(pool.0), u128::from(pool.1), &wide(&sells), &wide(&buys)).expect("clears");
        let want = rule_tick(plain.den, plain.num);
        for (label, around, width) in [("price inside the window", want - 3, 15usize), ("price jumped", want - 5_000, 15), ("wide window", want, 63)] {
            let t0 = std::time::Instant::now();
            let (tick, stages, run) = threshold_tick_staged(20, 0xBEEF, pool, &sells, &buys, around, width);
            let cpu = t0.elapsed();
            assert_eq!(tick, want, "⛔ the threshold clearing landed on tick {tick}, the rule's is {want} ({label})");
            eprintln!(
                "[br15-mpc] n=20 t={} {label} (window {width}): {stages} stage(s), ONLINE {} rounds / {:.1} MB in all · OFFLINE {} rounds / {:.1} MB in all · {} ms CPU in-process · at 0.5 s a round over onion links: {:.1} s on the latency path",
                run.t,
                run.rounds,
                run.online_elements as f64 * 32.0 / 1e6,
                run.offline_rounds,
                run.offline_elements as f64 * 32.0 / 1e6,
                cpu.as_millis(),
                run.rounds as f64 * 0.5
            );
        }
    }
}

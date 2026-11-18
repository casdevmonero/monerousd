// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! YPIR+SP — the hint-free payload PIR of DB-223 §12i (docs/DB-223-Q2-PATH-REFRESH-INDEX-SPEC.md), built
//! STANDALONE first, nothing wired. Borrowed, not invented: Menon & Wu, *YPIR* (USENIX Security '24),
//! Table 5 "YPIR+SP"; the LWE→RLWE packing is Chen–Dai–Kim–Song key switching at `d` = 2048 over a 56-bit
//! NTT-friendly modulus.
//!
//! Layers, bottom up (each lands on its own pins before the next is built on it):
//! 1. **The ring** `R_Q = Z_Q[x]/(x^D + 1)`, `D` = 2048, `Q` a 56-bit prime ≡ 1 (mod 2D): negacyclic NTT
//!    multiplication, checked against the schoolbook product.
//! 2. **Symmetric RLWE** over that ring (ternary secret, centered-binomial error, plaintext modulus
//!    `P` = 256 — the same cell width as `oli::P_CELL`): the calibration pin decodes a record with the right
//!    key and FAILS with a wrong one, and the measured noise is printed beside its headroom.
//! 3. **The SimplePIR column pass** at `Q` (YPIR §3): the query is the LWE encoding of the unit vector at
//!    the record's column under the RLWE secret's coefficient vector; the server answers one LWE ciphertext
//!    per record byte (row). **CDKS packing** (Chen–Dai–Kim–Song, Alg. 2 PackLWEs) folds those `D` LWE
//!    answers into ONE RLWE ciphertext with `log D` automorphism key-switch keys `τ_k(s) → s`,
//!    `k = 2^j + 1` — the fixed `pk` of YPIR Table 3.
//!    The column vectors are the rows of negacyclic matrices of public ring elements (YPIR §4.2), so the
//!    query-independent hint `DB·A` is computed through the NTT; key switching uses balanced digits.
//! 4. **Modulus reduction** `Q → (q1, q2) = (2^28, 2^20)` on the packed response (12,288 B), and the
//!    27.5 MB / 1,761 B record pin with measured upload, download and server time.
//!
//! No ingress path: this module verifies nothing a peer sends and moves no value (AGENTS.md §9.6 n/a until
//! it is wired). Soundness of a served record never rests on it — the wallet refuses a wrong record by its
//! `note_cm` + copath checks; PIR only decides what the server LEARNS (nothing, under RLWE).

use std::sync::OnceLock;

/// Ring degree `D` (power of two). PRODUCTION-SCALE-REVIEWED: the published YPIR packing degree, a ring
/// dimension, not a cover/block count.
pub const D: usize = 2048;
/// 56-bit NTT-friendly prime, `Q ≡ 1 (mod 2D)` (largest such prime below 2^56).
pub const Q: u64 = 0x00ff_ffff_fffb_a001;
/// Plaintext modulus — one byte per coefficient (matches `oli::P_CELL`).
pub const P: u64 = 256;
/// Scaling factor `⌊Q/P⌋`.
pub const DELTA: u64 = Q / P;
/// Centered-binomial error parameter η (σ = √(η/2) = 4).
const ETA: usize = 32;

/// Barrett constant `⌊2^112 / Q⌋` (k = 56 = bitlen Q).
const MU: u128 = (1u128 << 112) / Q as u128;

/// `a·b mod Q` for `a, b < Q` by Barrett reduction (Menezes et al., HAC 14.42): the estimate is at most
/// 2 below the true quotient, so ≤ 2 conditional subtractions; the layer-3 pin checks it against `%`.
#[inline]
fn mul(a: u64, b: u64) -> u64 {
    let x = a as u128 * b as u128;
    let q = ((x >> 55) * MU) >> 57;
    let mut r = (x - q * Q as u128) as u64;
    while r >= Q {
        r -= Q;
    }
    r
}
#[inline]
fn add(a: u64, b: u64) -> u64 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}
#[inline]
fn sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { a + Q - b }
}
fn pow(mut b: u64, mut e: u64) -> u64 {
    let mut r = 1u64;
    while e > 0 {
        if e & 1 == 1 {
            r = mul(r, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    r
}

struct Tables {
    /// ψ^i, ψ a primitive 2D-th root of unity (the negacyclic twist).
    psi: Vec<u64>,
    /// ψ^-i · D^-1 (untwist + inverse-NTT scaling in one pass).
    psi_inv_scaled: Vec<u64>,
    omega: u64,
    omega_inv: u64,
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let two_d = 2 * D as u64;
        let mut g = 2u64;
        let psi = loop {
            let c = pow(g, (Q - 1) / two_d);
            // primitive 2D-th root ⇔ c^D = −1
            if pow(c, D as u64) == Q - 1 {
                break c;
            }
            g += 1;
        };
        let psi_inv = pow(psi, Q - 2);
        let d_inv = pow(D as u64, Q - 2);
        let mut fw = Vec::with_capacity(D);
        let mut bw = Vec::with_capacity(D);
        let (mut x, mut y) = (1u64, d_inv);
        for _ in 0..D {
            fw.push(x);
            bw.push(y);
            x = mul(x, psi);
            y = mul(y, psi_inv);
        }
        let omega = mul(psi, psi);
        Tables { psi: fw, psi_inv_scaled: bw, omega, omega_inv: pow(omega, Q - 2) }
    })
}

/// In-place cyclic NTT of length `D` with root `w` (iterative Cooley–Tukey, bit-reversed input order).
fn ntt(a: &mut [u64], w: u64) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let wl = pow(w, (n / len) as u64);
        for start in (0..n).step_by(len) {
            let mut wk = 1u64;
            for k in 0..len / 2 {
                let u = a[start + k];
                let v = mul(a[start + k + len / 2], wk);
                a[start + k] = add(u, v);
                a[start + k + len / 2] = sub(u, v);
                wk = mul(wk, wl);
            }
        }
        len <<= 1;
    }
}

/// Negacyclic product in `R_Q`: `a·b mod (x^D + 1, Q)`. `None` on a wrong-length operand (fail closed).
pub fn ring_mul(a: &[u64], b: &[u64]) -> Option<Vec<u64>> {
    if a.len() != D || b.len() != D {
        return None;
    }
    let t = tables();
    let mut fa: Vec<u64> = a.iter().zip(&t.psi).map(|(&x, &p)| mul(x % Q, p)).collect();
    let mut fb: Vec<u64> = b.iter().zip(&t.psi).map(|(&x, &p)| mul(x % Q, p)).collect();
    ntt(&mut fa, t.omega);
    ntt(&mut fb, t.omega);
    for (x, y) in fa.iter_mut().zip(&fb) {
        *x = mul(*x, *y);
    }
    ntt(&mut fa, t.omega_inv);
    Some(fa.iter().zip(&t.psi_inv_scaled).map(|(&x, &s)| mul(x, s)).collect())
}

/// Uniform element of `R_Q` expanded from `seed` under `label` (rejection-sampled 56-bit words).
pub fn uniform_poly(seed: &[u8; 32], label: &[u8]) -> Vec<u64> {
    let mut h = blake3::Hasher::new_keyed(seed);
    h.update(b"MUSD/pir-ypir/uniform/v1");
    h.update(label);
    let mut xof = h.finalize_xof();
    let mut out = Vec::with_capacity(D);
    let mut w = [0u8; 8];
    while out.len() < D {
        xof.fill(&mut w[..7]);
        let v = u64::from_le_bytes(w);
        if v < Q {
            out.push(v);
        }
    }
    out
}

fn cbd_vec(xof: &mut blake3::OutputReader, n: usize) -> Vec<u64> {
    let mut bytes = vec![0u8; n * ETA / 4];
    xof.fill(&mut bytes);
    (0..n)
        .map(|i| {
            let mut acc = 0i64;
            for k in 0..ETA {
                let bit = |n: usize| (bytes[n / 8] >> (n % 8)) & 1;
                let base = (i * ETA + k) * 2;
                acc += bit(base) as i64 - bit(base + 1) as i64;
            }
            if acc >= 0 { acc as u64 } else { Q - (-acc) as u64 }
        })
        .collect()
}

/// RLWE secret: ternary coefficients in {−1, 0, 1} (as residues mod `Q`), derived from the wallet's seed.
pub struct SecretKey(Vec<u64>);

impl SecretKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = blake3::Hasher::new_keyed(seed);
        h.update(b"MUSD/pir-ypir/sk/v1");
        let mut xof = h.finalize_xof();
        let mut buf = vec![0u8; D];
        xof.fill(&mut buf);
        // 256 = 3·85 + 1: reject the top byte value so each of the three classes is exactly uniform.
        let mut s = Vec::with_capacity(D);
        let mut i = 0;
        while s.len() < D {
            if i == buf.len() {
                xof.fill(&mut buf);
                i = 0;
            }
            let b = buf[i];
            i += 1;
            if b == 255 {
                continue;
            }
            s.push(match b % 3 {
                0 => 0,
                1 => 1,
                _ => Q - 1,
            });
        }
        SecretKey(s)
    }
}

/// An RLWE ciphertext `(a, b = a·s + e + Δ·m)`.
#[derive(Clone)]
pub struct Ciphertext {
    pub a: Vec<u64>,
    pub b: Vec<u64>,
}

/// Encrypt a `D`-byte record (one byte per coefficient). `a_seed` expands the public `a`; `noise_seed`
/// draws the error. `None` on a wrong-length record (fail closed).
pub fn encrypt(sk: &SecretKey, msg: &[u8], a_seed: &[u8; 32], noise_seed: &[u8; 32]) -> Option<Ciphertext> {
    if msg.len() != D {
        return None;
    }
    let a = uniform_poly(a_seed, b"a");
    let mut h = blake3::Hasher::new_keyed(noise_seed);
    h.update(b"MUSD/pir-ypir/err/v1");
    let e = cbd_vec(&mut h.finalize_xof(), D);
    let as_ = ring_mul(&a, &sk.0)?;
    let b = (0..D).map(|i| add(add(as_[i], e[i]), mul(DELTA, msg[i] as u64))).collect();
    Some(Ciphertext { a, b })
}

/// The phase `b − a·s` = `Δ·m + e`.
fn phase(sk: &SecretKey, ct: &Ciphertext) -> Option<Vec<u64>> {
    if ct.a.len() != D || ct.b.len() != D {
        return None;
    }
    let as_ = ring_mul(&ct.a, &sk.0)?;
    Some((0..D).map(|i| sub(ct.b[i] % Q, as_[i])).collect())
}

/// Decrypt to `D` bytes: round(phase · P / Q) mod P.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Option<Vec<u8>> {
    Some(
        phase(sk, ct)?
            .into_iter()
            .map(|v| (((v as u128 * P as u128 + Q as u128 / 2) / Q as u128) % P as u128) as u8)
            .collect(),
    )
}

/// Largest |e| over the coefficients, given the plaintext — the noise census (decoding is exact while
/// it stays below Δ/2). The fold starts at 0 because |e| ≥ 0 — the identity of max, not a rescue.
pub fn max_noise(sk: &SecretKey, ct: &Ciphertext, msg: &[u8]) -> Option<u64> {
    if msg.len() != D {
        return None;
    }
    let ph = phase(sk, ct)?;
    Some((0..D).map(|i| {
        let e = sub(ph[i], mul(DELTA, msg[i] as u64));
        e.min(Q - e)
    }).fold(0u64, u64::max))
}

// ── Layer 3: the SimplePIR column pass + CDKS packing ─────────────────────────────────────────────

/// An LWE ciphertext over `Z_Q^D` under the RLWE secret's coefficient vector: phase `b − ⟨a, s⟩`.
#[derive(Clone)]
pub struct LweCiphertext {
    pub a: Vec<u64>,
    pub b: u64,
}

fn inner(a: &[u64], s: &[u64]) -> u64 {
    a.iter().zip(s).fold(0u64, |acc, (&x, &y)| add(acc, mul(x, y)))
}

fn round_p(phase: u64) -> u8 {
    (((phase as u128 * P as u128 + Q as u128 / 2) / Q as u128) % P as u128) as u8
}

/// Decrypt one LWE ciphertext to its byte. `None` on a wrong-length `a` (fail closed).
pub fn lwe_decrypt(sk: &SecretKey, ct: &LweCiphertext) -> Option<u8> {
    if ct.a.len() != D {
        return None;
    }
    Some(round_p(sub(ct.b % Q, inner(&ct.a, &sk.0))))
}

/// The public ring element of column block `k` (columns `kD .. kD + D`), expanded from the DB's public
/// seed (never uploaded). YPIR §4.2 shape: the LWE vectors of a block are the rows of the negacyclic
/// matrix of one ring element, so the query is a set of RLWE samples and the hint `DB·A` is `D`-fold
/// cheaper through the NTT.
fn block_poly(pub_seed: &[u8; 32], k: usize) -> Vec<u64> {
    let mut label = b"colblk".to_vec();
    label.extend_from_slice(&(k as u64).to_le_bytes());
    uniform_poly(pub_seed, &label)
}

/// The public LWE vector of column `j`: row `j mod D` of the negacyclic matrix of block `j / D`'s ring
/// element `a`, i.e. `⟨a_j, s⟩ = (a·s)_{j mod D}`.
fn column_a(pub_seed: &[u8; 32], j: usize) -> Vec<u64> {
    let a = block_poly(pub_seed, j / D);
    let i = j % D;
    (0..D).map(|k| if k <= i { a[i - k] } else { sub(0, a[D + i - k]) }).collect()
}

/// The SimplePIR query: `c2[j] = ⟨a_j, s⟩ + e_j + Δ·[j = col]` for every column — RLWE-hiding, so every
/// column's query is indistinguishable. `None` when `col ≥ n_cols` (fail closed).
pub fn column_query(
    sk: &SecretKey,
    n_cols: usize,
    col: usize,
    pub_seed: &[u8; 32],
    noise_seed: &[u8; 32],
) -> Option<Vec<u64>> {
    if col >= n_cols {
        return None;
    }
    let mut h = blake3::Hasher::new_keyed(noise_seed);
    h.update(b"MUSD/pir-ypir/query-err/v1");
    let e = cbd_vec(&mut h.finalize_xof(), n_cols);
    let mut c = Vec::with_capacity(n_cols);
    for k in 0..n_cols.div_ceil(D) {
        let as_ = ring_mul(&block_poly(pub_seed, k), &sk.0)?;
        for (i, &v) in as_.iter().enumerate().take(n_cols - k * D) {
            let j = k * D + i;
            let x = add(v, e[j]);
            c.push(if j == col { add(x, DELTA) } else { x });
        }
    }
    Some(c)
}

/// The server's offline hint (YPIR "silent preprocessing": query-independent, never downloaded): row `i`
/// holds `Σ_j db[i][j]·a_j`. Through the block structure that is `Σ_k ā_k · v_{i,k}` with `v_{i,k}` the
/// row's block-`k` bytes and `ā(x) = a(x⁻¹)` (the transpose of a negacyclic matrix is the negacyclic
/// matrix of the conjugate) — `rows·(blocks + 1)` NTTs instead of `rows·cols·D` mulmods.
pub struct Hint(Vec<Vec<u64>>);

impl Hint {
    /// `None` on an empty or ragged DB (fail closed).
    pub fn precompute(db: &[Vec<u8>], pub_seed: &[u8; 32]) -> Option<Hint> {
        let n = db.first()?.len();
        if n == 0 || db.iter().any(|row| row.len() != n) {
            return None;
        }
        let conj: Vec<Vec<u64>> = (0..n.div_ceil(D))
            .map(|k| {
                let a = block_poly(pub_seed, k);
                let mut c = vec![0u64; D];
                c[0] = a[0];
                for m in 1..D {
                    c[m] = sub(0, a[D - m]);
                }
                to_ntt(&c)
            })
            .collect();
        Some(Hint(
            db.iter()
                .map(|row| {
                    let mut acc = vec![0u64; D];
                    for (k, c_hat) in conj.iter().enumerate() {
                        let mut v = vec![0u64; D];
                        for (x, &b) in v.iter_mut().zip(&row[k * D..n.min(k * D + D)]) {
                            *x = b as u64;
                        }
                        for (x, (&y, &z)) in acc.iter_mut().zip(to_ntt(&v).iter().zip(c_hat)) {
                            *x = add(*x, mul(y, z));
                        }
                    }
                    from_ntt(acc)
                })
                .collect(),
        ))
    }
}

/// The online column pass against a precomputed hint: row `i` answers the LWE ciphertext
/// `(hint_i, Σ_j db[i][j]·c2[j])`, whose phase is `Δ·db[i][col] + Σ_j db[i][j]·e_j` — `rows·cols`
/// mulmods. `None` on a ragged DB, a query of the wrong width or a hint of another shape (fail closed).
pub fn column_answer_with_hint(db: &[Vec<u8>], query: &[u64], hint: &Hint) -> Option<Vec<LweCiphertext>> {
    let n = query.len();
    if hint.0.len() != db.len() || db.iter().any(|row| row.len() != n) {
        return None;
    }
    Some(
        db.iter()
            .zip(&hint.0)
            .map(|(row, h)| {
                let b = row.iter().zip(query).fold(0u64, |acc, (&v, &c)| add(acc, mul(v as u64, c)));
                LweCiphertext { a: h.clone(), b }
            })
            .collect(),
    )
}

/// Hint + online pass in one call (the shape the layer-3 pins use).
pub fn column_answer(db: &[Vec<u8>], query: &[u64], pub_seed: &[u8; 32]) -> Option<Vec<LweCiphertext>> {
    if db.iter().any(|row| row.len() != query.len()) {
        return None;
    }
    column_answer_with_hint(db, query, &Hint::precompute(db, pub_seed)?)
}

/// Gadget base `2^B_BITS`, `T` digits: `T·B_BITS = 57 ≥ 56`.
const B_BITS: u32 = 19;
const T: usize = 3;

fn to_ntt(a: &[u64]) -> Vec<u64> {
    let t = tables();
    let mut f: Vec<u64> = a.iter().zip(&t.psi).map(|(&x, &p)| mul(x % Q, p)).collect();
    ntt(&mut f, t.omega);
    f
}

fn from_ntt(mut f: Vec<u64>) -> Vec<u64> {
    let t = tables();
    ntt(&mut f, t.omega_inv);
    f.iter().zip(&t.psi_inv_scaled).map(|(&x, &s)| mul(x, s)).collect()
}

/// `τ_k: x ↦ x^k` on `R_Q` (`k` odd, so a signed permutation of the coefficients).
fn automorph(a: &[u64], k: usize) -> Vec<u64> {
    let mut r = vec![0u64; D];
    for (i, &c) in a.iter().enumerate() {
        let j = (i * k) % (2 * D);
        if j < D { r[j] = c } else { r[j - D] = sub(0, c) }
    }
    r
}

/// Balanced gadget digits: each coefficient, centered into `(−Q/2, Q/2]`, as `Σ_t d_t·2^(B·t)` with
/// `d_t ∈ [−2^(B−1), 2^(B−1))` (as residues). `|c| < 2^55` leaves the top digit within `±(2^17 + 1)`, so
/// no carry escapes the `T`-th digit; each digit's magnitude is half the unsigned one's (the packed
/// noise measured 2^37 at `ilog2` resolution both ways — the 9-bit headroom is not digit-bound).
fn signed_digits(a: &[u64]) -> Vec<Vec<u64>> {
    let half = 1i64 << (B_BITS - 1);
    let mut out = vec![vec![0u64; a.len()]; T];
    for (i, &c) in a.iter().enumerate() {
        let mut x = if c > Q / 2 { c as i64 - Q as i64 } else { c as i64 };
        for row in out.iter_mut() {
            let mut d = x & ((1i64 << B_BITS) - 1);
            if d >= half {
                d -= 1i64 << B_BITS;
            }
            x = (x - d) >> B_BITS;
            row[i] = if d >= 0 { d as u64 } else { Q - (-d) as u64 };
        }
        debug_assert_eq!(x, 0, "a carry escaped the top gadget digit");
    }
    out
}

/// Multiply by the monomial `x^e`, `e < D`.
fn mul_monomial(a: &[u64], e: usize) -> Vec<u64> {
    let mut r = vec![0u64; D];
    for (i, &c) in a.iter().enumerate() {
        if i + e < D { r[i + e] = c } else { r[i + e - D] = sub(0, c) }
    }
    r
}

/// The CDKS packing keys: for `k = 2^j + 1`, `j = 1..=log D`, `T` RLWE encryptions under `s` of
/// `B^t·τ_k(s)`, held in NTT form. Only the `b` halves travel (`u` expands from the public seed).
pub struct PackingKeys {
    /// `keys[j−1][t] = (û_t, b̂_t)`.
    keys: Vec<Vec<(Vec<u64>, Vec<u64>)>>,
}

impl PackingKeys {
    pub fn generate(sk: &SecretKey, pub_seed: &[u8; 32], noise_seed: &[u8; 32]) -> Self {
        let s_hat = to_ntt(&sk.0);
        let mut keys = Vec::new();
        for j in 1..=D.ilog2() {
            let k = (1usize << j) + 1;
            let tau_s = automorph(&sk.0, k);
            let mut row = Vec::with_capacity(T);
            for t in 0..T {
                let mut label = b"ksk".to_vec();
                label.extend_from_slice(&(k as u64).to_le_bytes());
                label.push(t as u8);
                let u_hat = to_ntt(&uniform_poly(pub_seed, &label));
                let mut h = blake3::Hasher::new_keyed(noise_seed);
                h.update(b"MUSD/pir-ypir/ksk-err/v1");
                h.update(&label);
                let e = cbd_vec(&mut h.finalize_xof(), D);
                let us = from_ntt(u_hat.iter().zip(&s_hat).map(|(&x, &y)| mul(x, y)).collect());
                let g = 1u64 << (B_BITS as usize * t);
                let b: Vec<u64> = (0..D).map(|i| add(add(us[i], e[i]), mul(g, tau_s[i]))).collect();
                row.push((u_hat, to_ntt(&b)));
            }
            keys.push(row);
        }
        PackingKeys { keys }
    }

    /// The bytes a client uploads once: the `b` halves, 7 B per coefficient.
    pub fn upload_bytes(&self) -> usize {
        self.keys.len() * T * D * 7
    }

    /// `τ_k(ct)` key-switched back to `s`: `(−Σ d_t·u_t, τ_k(b) − Σ d_t·b_t)` over the base-`2^B` digits
    /// `d_t` of `τ_k(a)` — phase preserved up to the switch noise `Σ d_t·e_t`.
    fn eval_auto(&self, ct: &Ciphertext, j: u32) -> Ciphertext {
        let k = (1usize << j) + 1;
        let ta = automorph(&ct.a, k);
        let tb = automorph(&ct.b, k);
        let (mut acc_a, mut acc_b) = (vec![0u64; D], vec![0u64; D]);
        let digits = signed_digits(&ta);
        for ((u_hat, b_hat), digit) in self.keys[j as usize - 1].iter().zip(&digits) {
            let d_hat = to_ntt(digit);
            for i in 0..D {
                acc_a[i] = add(acc_a[i], mul(d_hat[i], u_hat[i]));
                acc_b[i] = add(acc_b[i], mul(d_hat[i], b_hat[i]));
            }
        }
        let sa = from_ntt(acc_a);
        let sb = from_ntt(acc_b);
        Ciphertext {
            a: sa.iter().map(|&x| sub(0, x)).collect(),
            b: tb.iter().zip(&sb).map(|(&x, &y)| sub(x, y)).collect(),
        }
    }

    fn pack_rec(&self, mut cts: Vec<Ciphertext>) -> Ciphertext {
        let n = cts.len();
        if n <= 1 {
            // one ciphertext packs to itself; an empty list (unreachable: the caller halves an even count) to zero
            return cts.pop().unwrap_or_else(|| Ciphertext { a: vec![0; D], b: vec![0; D] });
        }
        let (mut even, mut odd) = (Vec::with_capacity(n / 2), Vec::with_capacity(n / 2));
        for (i, c) in cts.into_iter().enumerate() {
            if i % 2 == 0 { even.push(c) } else { odd.push(c) }
        }
        let e = self.pack_rec(even);
        let o = self.pack_rec(odd);
        let shift = D / n;
        let (xa, xb) = (mul_monomial(&o.a, shift), mul_monomial(&o.b, shift));
        let diff = Ciphertext {
            a: e.a.iter().zip(&xa).map(|(&x, &y)| sub(x, y)).collect(),
            b: e.b.iter().zip(&xb).map(|(&x, &y)| sub(x, y)).collect(),
        };
        let rot = self.eval_auto(&diff, n.ilog2());
        Ciphertext {
            a: (0..D).map(|i| add(add(e.a[i], xa[i]), rot.a[i])).collect(),
            b: (0..D).map(|i| add(add(e.b[i], xb[i]), rot.b[i])).collect(),
        }
    }

    /// PackLWEs: `D` LWE ciphertexts → one RLWE ciphertext whose coefficient `i` decodes byte `i`. Each
    /// LWE ct is lifted to the RLWE ct whose constant phase is its phase, pre-scaled by `D⁻¹ mod Q` (exact:
    /// the trace multiplies by `D`). `None` unless exactly `D` well-formed inputs (fail closed).
    pub fn pack(&self, lwes: &[LweCiphertext]) -> Option<Ciphertext> {
        if lwes.len() != D || lwes.iter().any(|c| c.a.len() != D) {
            return None;
        }
        let d_inv = pow(D as u64, Q - 2);
        let cts = lwes
            .iter()
            .map(|c| {
                let mut a = vec![0u64; D];
                a[0] = mul(c.a[0] % Q, d_inv);
                for k in 1..D {
                    a[k] = sub(0, mul(c.a[D - k] % Q, d_inv));
                }
                let mut b = vec![0u64; D];
                b[0] = mul(c.b % Q, d_inv);
                Ciphertext { a, b }
            })
            .collect();
        Some(self.pack_rec(cts))
    }
}

// ── Layer 4: modulus reduction Q → (q1, q2), the ~12 KB response ──────────────────────────────────

/// The response's `a`-half modulus (YPIR's larger `q̃_1`): the `a·s` rounding error is scaled by
/// `q2/q1` = 2^-8 into the `b`-half's units, so it stays far below `Δ'/2`.
pub const Q1_BITS: u32 = 28;
/// The response's `b`-half modulus `q̃_2`: `Δ' = q2/P = 2^12`, decoding exact while the scaled noise is
/// below 2^11.
pub const Q2_BITS: u32 = 20;

/// A packed response after modulus switching: coefficients of `a` below `2^Q1_BITS`, of `b` below
/// `2^Q2_BITS` — `D·(28 + 20)/8` = 12,288 B on the wire.
pub struct Reduced {
    pub a: Vec<u32>,
    pub b: Vec<u32>,
}

impl Reduced {
    /// Wire size in bytes (bit-packed halves).
    pub fn bytes(&self) -> usize {
        (self.a.len() * Q1_BITS as usize + self.b.len() * Q2_BITS as usize).div_ceil(8)
    }
}

fn switch(x: u64, bits: u32) -> u32 {
    (((x as u128) << bits).wrapping_add(Q as u128 / 2) / Q as u128 % (1u128 << bits)) as u32
}

/// `round(x · q_i / Q)` coefficient-wise on both halves (Brakerski–Gentry–Vaikuntanathan modulus
/// switching, YPIR §4 two-modulus variant). `None` on a malformed ciphertext (fail closed).
pub fn reduce(ct: &Ciphertext) -> Option<Reduced> {
    if ct.a.len() != D || ct.b.len() != D {
        return None;
    }
    Some(Reduced {
        a: ct.a.iter().map(|&x| switch(x % Q, Q1_BITS)).collect(),
        b: ct.b.iter().map(|&x| switch(x % Q, Q2_BITS)).collect(),
    })
}

/// The reduced phase in `q2` units: `b − round((a·s mod q1) · q2/q1) mod q2`. `a·s` is computed over `Q`
/// and is exact as an integer (`|coef| ≤ D·2^28 < Q/2`).
fn reduced_phase(sk: &SecretKey, r: &Reduced) -> Option<Vec<u64>> {
    if r.a.len() != D || r.b.len() != D || r.a.iter().any(|&x| x >> Q1_BITS != 0) || r.b.iter().any(|&x| x >> Q2_BITS != 0) {
        return None;
    }
    let a: Vec<u64> = r.a.iter().map(|&x| x as u64).collect();
    let as_ = ring_mul(&a, &sk.0)?;
    let (m1, m2) = ((1u64 << Q1_BITS) - 1, (1u64 << Q2_BITS) - 1);
    let sh = Q1_BITS - Q2_BITS;
    Some(
        as_.iter()
            .zip(&r.b)
            .map(|(&v, &b)| {
                let as_q1 = if v > Q / 2 { (v as i128 - Q as i128).rem_euclid(1i128 << Q1_BITS) as u64 } else { v & m1 };
                let scaled = ((as_q1 + (1 << (sh - 1))) >> sh) & m2;
                (b as u64).wrapping_sub(scaled) & m2
            })
            .collect(),
    )
}

/// Decrypt a reduced response to `D` bytes: `round(phase · P / q2) mod P`.
pub fn decrypt_reduced(sk: &SecretKey, r: &Reduced) -> Option<Vec<u8>> {
    let sh = Q2_BITS - P.ilog2();
    Some(reduced_phase(sk, r)?.into_iter().map(|v| (((v + (1 << (sh - 1))) >> sh) % P) as u8).collect())
}

/// Largest |e| in `q2` units after the switch — the census beside `Δ'/2` = 2^11.
pub fn max_noise_reduced(sk: &SecretKey, r: &Reduced, msg: &[u8]) -> Option<u64> {
    if msg.len() != D {
        return None;
    }
    let sh = Q2_BITS - P.ilog2();
    let m2 = (1u64 << Q2_BITS) - 1;
    Some(
        reduced_phase(sk, r)?
            .iter()
            .zip(msg)
            .map(|(&v, &m)| {
                let e = v.wrapping_sub((m as u64) << sh) & m2;
                e.min((1u64 << Q2_BITS) - e)
            })
            .fold(0u64, u64::max),
    )
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn seed(label: &str) -> [u8; 32] {
        *blake3::hash(label.as_bytes()).as_bytes()
    }

    fn record(label: &str) -> Vec<u8> {
        let mut m = vec![0u8; D];
        blake3::Hasher::new_keyed(&seed(label)).finalize_xof().fill(&mut m);
        m
    }

    /// Layer 1: the NTT product equals the schoolbook negacyclic product (x^D = −1) on uniform operands.
    #[test]
    fn ring_mul_matches_schoolbook_negacyclic() {
        let a = uniform_poly(&seed("ypir/a"), b"x");
        let b = uniform_poly(&seed("ypir/b"), b"y");
        let mut want = vec![0u64; D];
        for i in 0..D {
            for j in 0..D {
                let p = mul(a[i], b[j]);
                let k = i + j;
                if k < D {
                    want[k] = add(want[k], p);
                } else {
                    want[k - D] = sub(want[k - D], p);
                }
            }
        }
        assert_eq!(ring_mul(&a, &b).unwrap(), want);
        // A twist that ignores the negacyclic wrap must be caught: x^(D−1) · x = −1, never +1.
        let mut xd1 = vec![0u64; D];
        xd1[D - 1] = 1;
        let mut x = vec![0u64; D];
        x[1] = 1;
        let r = ring_mul(&xd1, &x).unwrap();
        assert_eq!(r[0], Q - 1);
        assert!(r[1..].iter().all(|&c| c == 0));
        assert!(ring_mul(&a[..D - 1], &b).is_none(), "a wrong-length operand fails closed");
    }

    /// Layer 2 calibration (§12i): the right key decodes the record exactly; a wrong key decodes noise
    /// (agreement at the 1/P chance rate, never the record); the measured noise has wide headroom.
    #[test]
    fn rlwe_calibration_right_key_decodes_wrong_key_fails() {
        let sk = SecretKey::from_seed(&seed("ypir/sk/right"));
        let wrong = SecretKey::from_seed(&seed("ypir/sk/wrong"));
        let msg = record("ypir/record");
        let ct = encrypt(&sk, &msg, &seed("ypir/a-seed"), &seed("ypir/noise")).unwrap();
        assert_eq!(decrypt(&sk, &ct).unwrap(), msg, "right key must decode the record exactly");
        let bad = decrypt(&wrong, &ct).unwrap();
        let agree = bad.iter().zip(&msg).filter(|(x, y)| x == y).count();
        // Binomial(2048, 1/256): mean 8, sd 2.8 — 32 is 8.5 sd above chance.
        assert!(agree <= 32, "wrong key agreed on {agree}/{D} bytes — must be chance (~8)");
        let noise = max_noise(&sk, &ct, &msg).unwrap();
        let headroom_bits = (DELTA / 2).ilog2() - noise.max(1).ilog2();
        println!(
            "[pir_ypir] D={D} Q=2^{:.2} Δ=2^{} fresh max|e|={noise} headroom={headroom_bits} bits, \
             ct={} B, wrong-key agreement {agree}/{D}",
            (Q as f64).log2(),
            DELTA.ilog2(),
            2 * D * 7
        );
        assert!(noise < DELTA / 2, "noise {noise} ≥ Δ/2 — decoding is not exact");
        assert!(headroom_bits >= 40, "fresh noise must leave ≥ 40 bits for the packing key switch");
        // Tamper: a ciphertext shifted by Δ at one coefficient decodes to a different record there only —
        // RLWE is malleable, which is why the wallet's note_cm + copath checks own record soundness.
        let mut t = ct.clone();
        t.b[7] = add(t.b[7], DELTA);
        let d = decrypt(&sk, &t).unwrap();
        assert_eq!(d[7], msg[7].wrapping_add(1));
        assert_eq!(d.iter().zip(&msg).filter(|(x, y)| x != y).count(), 1);
        assert!(encrypt(&sk, &msg[..D - 1], &seed("a"), &seed("n")).is_none(), "short record fails closed");
    }

    fn db(rows: usize, cols: usize, label: &str) -> Vec<Vec<u8>> {
        (0..rows).map(|i| record(&format!("{label}/{i}"))[..cols].to_vec()).collect()
    }

    /// Layer 3a: the SimplePIR column pass returns exactly the queried column, one LWE ct per row; a
    /// wrong key decodes chance; the neighbouring column is not what comes back; Barrett equals `%`.
    #[test]
    fn column_pass_decodes_the_queried_column_wrong_key_fails() {
        for i in 0..4096u64 {
            let (a, b) = (uniform_poly(&seed("ypir/barrett"), &i.to_le_bytes())[0], Q - 1 - i);
            assert_eq!(mul(a, b), ((a as u128 * b as u128) % Q as u128) as u64, "Barrett ≠ % at {a}·{b}");
        }
        let (rows, cols, col) = (64, 32, 13);
        let table = db(rows, cols, "ypir/db-a");
        let sk = SecretKey::from_seed(&seed("ypir/sk/right"));
        let wrong = SecretKey::from_seed(&seed("ypir/sk/wrong"));
        let pubs = seed("ypir/pub");
        let q = column_query(&sk, cols, col, &pubs, &seed("ypir/qnoise")).unwrap();
        let ans = column_answer(&table, &q, &pubs).unwrap();
        let got: Vec<u8> = ans.iter().map(|c| lwe_decrypt(&sk, c).unwrap()).collect();
        let want: Vec<u8> = table.iter().map(|r| r[col]).collect();
        assert_eq!(got, want, "the right key must decode the queried column exactly");
        let next: Vec<u8> = table.iter().map(|r| r[col - 1]).collect();
        assert_ne!(got, next, "the neighbouring column must not come back");
        let agree = ans.iter().zip(&want).filter(|(c, w)| lwe_decrypt(&wrong, c).unwrap() == **w).count();
        // Binomial(64, 1/256): mean 0.25 — 6 is far past chance.
        assert!(agree <= 6, "wrong key agreed on {agree}/{rows} rows — must be chance");
        let noise = ans
            .iter()
            .zip(&want)
            .map(|(c, &w)| {
                let e = sub(sub(c.b, inner(&c.a, &sk.0)), mul(DELTA, w as u64));
                e.min(Q - e)
            })
            .fold(0u64, u64::max);
        println!("[pir_ypir] column pass {rows}×{cols}: max|e|={noise} (2^{}), Δ/2=2^{}", noise.max(1).ilog2(), (DELTA / 2).ilog2());
        assert!(noise < DELTA / 2);
        assert!(column_query(&sk, cols, cols, &pubs, &seed("n")).is_none(), "col ≥ n fails closed");
        let mut ragged = table.clone();
        ragged[3].pop();
        assert!(column_answer(&ragged, &q, &pubs).is_none(), "a ragged DB fails closed");
        assert!(column_answer(&table, &q[..cols - 1], &pubs).is_none(), "a short query fails closed");
    }

    /// Layer 3b: CDKS PackLWEs folds the column pass's `D` row answers into ONE RLWE ciphertext that
    /// decodes the whole record; a wrong key decodes chance; noise, key and response sizes are printed.
    #[test]
    fn cdks_packing_folds_d_answers_into_one_rlwe_ct() {
        let (cols, col) = (8, 5);
        let table = db(D, cols, "ypir/db-b");
        let sk = SecretKey::from_seed(&seed("ypir/sk/right"));
        let wrong = SecretKey::from_seed(&seed("ypir/sk/wrong"));
        let pubs = seed("ypir/pub");
        let q = column_query(&sk, cols, col, &pubs, &seed("ypir/qnoise")).unwrap();
        let t0 = std::time::Instant::now();
        let ans = column_answer(&table, &q, &pubs).unwrap();
        let t_pass = t0.elapsed();
        let keys = PackingKeys::generate(&sk, &pubs, &seed("ypir/kskn"));
        let t1 = std::time::Instant::now();
        let packed = keys.pack(&ans).unwrap();
        let t_pack = t1.elapsed();
        let want: Vec<u8> = table.iter().map(|r| r[col]).collect();
        assert_eq!(decrypt(&sk, &packed).unwrap(), want, "the packed ct must decode the whole column");
        let bad = decrypt(&wrong, &packed).unwrap();
        let agree = bad.iter().zip(&want).filter(|(x, y)| x == y).count();
        assert!(agree <= 32, "wrong key agreed on {agree}/{D} bytes — must be chance (~8)");
        let noise = max_noise(&sk, &packed, &want).unwrap();
        let headroom = (DELTA / 2).ilog2() - noise.max(1).ilog2();
        println!(
            "[pir_ypir] packed D={D}: max|e|=2^{} headroom={headroom} bits; pk upload {} B (YPIR T3: 462 KB), \
             c2 {} B, response {} B before mod-switch; pass {:?} pack {:?}",
            noise.max(1).ilog2(),
            keys.upload_bytes(),
            cols * 7,
            2 * D * 7,
            t_pass,
            t_pack
        );
        assert!(headroom >= 4, "packing noise must leave ≥ 4 bits for modulus reduction");
        assert!(keys.pack(&ans[..D - 1]).is_none(), "fewer than D answers fail closed");
    }

    /// Layer 4a: the NTT hint equals the naive `Σ_j db[i][j]·a_j` across a block boundary and a partial
    /// last block, and balanced gadget digits recompose every coefficient within `±2^(B−1)`.
    #[test]
    fn structured_hint_matches_naive_and_signed_digits_recompose() {
        let (rows, cols) = (3, D + 100);
        let table: Vec<Vec<u8>> = (0..rows)
            .map(|i| (0..cols).map(|j| record(&format!("ypir/hint/{i}/{}", j / D))[j % D]).collect())
            .collect();
        let pubs = seed("ypir/pub");
        let hint = Hint::precompute(&table, &pubs).unwrap();
        let a_cols: Vec<Vec<u64>> = (0..cols).map(|j| column_a(&pubs, j)).collect();
        for (i, row) in table.iter().enumerate() {
            let mut naive = vec![0u64; D];
            for (j, &v) in row.iter().enumerate() {
                for (x, &c) in naive.iter_mut().zip(&a_cols[j]) {
                    *x = add(*x, mul(v as u64, c));
                }
            }
            assert_eq!(hint.0[i], naive, "NTT hint row {i} ≠ naive DB·A");
        }
        let mut ragged = table.clone();
        ragged[1].pop();
        assert!(Hint::precompute(&ragged, &pubs).is_none(), "a ragged DB fails closed");
        assert!(Hint::precompute(&[], &pubs).is_none(), "an empty DB fails closed");
        let mut coeffs = uniform_poly(&seed("ypir/digits"), b"c");
        coeffs[..6].copy_from_slice(&[0, 1, Q - 1, Q / 2, Q / 2 + 1, (1 << B_BITS) - 1]);
        let digits = signed_digits(&coeffs);
        let half = 1u64 << (B_BITS - 1);
        for (i, &c) in coeffs.iter().enumerate() {
            let mut acc = 0u64;
            for (t, row) in digits.iter().enumerate() {
                let d = row[i];
                assert!(d.min(Q - d) <= half, "digit {t} of coeff {i} out of the balanced range");
                acc = add(acc, mul(d, 1u64 << (B_BITS as usize * t)));
            }
            assert_eq!(acc, c, "balanced digits of coeff {i} do not recompose");
        }
    }

    /// Layer 4b: the DB-223 §12i payload shard — 16,384 records × 1,761 B (27.5 MB), one record per
    /// column — answered by hint + online pass + CDKS packing + modulus reduction: the queried record
    /// decodes exactly from the 12 KB response, a wrong key decodes chance, and upload / download /
    /// server time are printed beside the §12i model (526 KB up, ~12 KB down, ~39 ms packing).
    #[test]
    fn ypir_sp_record_shard_returns_the_record_in_12_kb() {
        const RECORDS: usize = 16_384;
        const REC: usize = 1_761;
        let col = 12_345;
        let mut xof = blake3::Hasher::new_keyed(&seed("ypir/shard")).finalize_xof();
        let table: Vec<Vec<u8>> = (0..D)
            .map(|i| {
                let mut row = vec![0u8; RECORDS];
                if i < REC {
                    xof.fill(&mut row);
                }
                row
            })
            .collect();
        let sk = SecretKey::from_seed(&seed("ypir/sk/right"));
        let wrong = SecretKey::from_seed(&seed("ypir/sk/wrong"));
        let pubs = seed("ypir/pub");
        let t0 = std::time::Instant::now();
        let hint = Hint::precompute(&table, &pubs).unwrap();
        let t_hint = t0.elapsed();
        let keys = PackingKeys::generate(&sk, &pubs, &seed("ypir/kskn"));
        let q = column_query(&sk, RECORDS, col, &pubs, &seed("ypir/qnoise")).unwrap();
        let t1 = std::time::Instant::now();
        let ans = column_answer_with_hint(&table, &q, &hint).unwrap();
        let t_pass = t1.elapsed();
        let packed = keys.pack(&ans).unwrap();
        let t_pack = t1.elapsed() - t_pass;
        let resp = reduce(&packed).unwrap();
        let t_server = t1.elapsed();
        let want: Vec<u8> = table.iter().map(|r| r[col]).collect();
        let got = decrypt_reduced(&sk, &resp).unwrap();
        assert_eq!(&got[..REC], &want[..REC], "the 12 KB response must decode the queried record exactly");
        assert!(got[REC..].iter().all(|&b| b == 0), "the padding rows decode to zero");
        assert_ne!(&got[..REC], &table.iter().map(|r| r[col + 1]).collect::<Vec<u8>>()[..REC], "not the neighbour");
        let agree = decrypt_reduced(&wrong, &resp).unwrap().iter().zip(&want).take(REC).filter(|(x, y)| x == y).count();
        assert!(agree <= 32, "wrong key agreed on {agree}/{REC} bytes — must be chance (~7)");
        let pre = max_noise(&sk, &packed, &want).unwrap();
        let post = max_noise_reduced(&sk, &resp, &want).unwrap();
        let bound = 1u64 << (Q2_BITS - P.ilog2() - 1);
        let up = RECORDS * 7 + keys.upload_bytes();
        println!(
            "[pir_ypir] shard {RECORDS}×{REC} B: up {up} B (c2 {} + pk {}; §12i model 526 KB), down {} B (model ~12 KB); \
             noise packed 2^{} (headroom {} bits), reduced {post} vs Δ'/2={bound}; hint {:?} (offline), \
             server {:?} = pass {:?} + pack {:?} + switch (model: pass few ms + pack ~39 ms)",
            RECORDS * 7,
            keys.upload_bytes(),
            resp.bytes(),
            pre.max(1).ilog2(),
            (DELTA / 2).ilog2() - pre.max(1).ilog2(),
            t_hint,
            t_server,
            t_pass,
            t_pack
        );
        assert_eq!(resp.bytes(), 12_288, "the response is D·(28+20)/8 bytes");
        assert!(post < bound, "the reduced noise must stay below Δ'/2");
        let mut bad = Reduced { a: resp.a.clone(), b: resp.b.clone() };
        bad.a[0] = 1 << Q1_BITS;
        assert!(decrypt_reduced(&sk, &bad).is_none(), "an out-of-range coefficient fails closed");
    }
}

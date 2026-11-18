// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §BR-9a — THE PER-EPOCH THRESHOLD KEY (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §19).
//!
//! One public key per future epoch, ONE ciphertext per ticket whatever the custody size, and early reading only by ≥ t =
//! ⌈2n/3⌉ custodians — the per-ticket Shamir shares' trust at one ciphertext instead of one sealed share per custodian.
//!
//! - **Ring and instance** (borrowed: ML-DSA-65, FIPS 204): R_q = Z_q[X]/(X²⁵⁶ + 1), q = 8,380,417, A ∈ R_q^{6×5} expanded
//!   from a public per-epoch seed (blake3 XOF, 23-bit rejection — ML-DSA's ExpandA shape), secrets and errors uniform in
//!   [−4, 4] (ML-DSA's η = 4 rejection on nibbles). b = A·s + e is ML-DSA-65's module-LWE instance.
//! - **Dealer-free key generation** (the GJKR distributed key generation shape, over a lattice — novel crypto, ours): each
//!   custodian i deals short (s_i, e_i) and publishes b_i = A·s_i + e_i; the epoch key is b = Σ b_i = A·s + e, s = Σ s_i.
//!   One honest dealer leaves a coalition that knows every other s_i facing ML-DSA-65's instance.
//! - **Threshold release** (Shamir 1979, over Z_q): each dealer splits every coefficient of s_i with a degree t − 1
//!   polynomial; custodian j's epoch share σ_j = Σ_i share_{i→j} is, by linearity, a Shamir share of s. Any t published σ_j
//!   reconstruct s; t − 1 are consistent with every secret (information-theoretic, so post-quantum by construction).
//! - **Encryption** (the Kyber/Regev shape, Fujisaki–Okamoto transformed): u = Aᵀr + e₁, v = bᵀr + e₂ + ⌊q/2⌋·m, with
//!   (r, e₁, e₂) derived from H(m ‖ H(pk)); the key is H(m ‖ H(ct)); decapsulation re-encrypts and refuses any ciphertext
//!   that does not match. Before the epoch nobody holds s, so there is no decryption oracle; after it the key is public.
//! - **The release check** fails closed on the bad item: a reconstructed s is accepted only if s and b − A·s are both within
//!   ±4·contributors. A dealer whose shares do not match its b_i, a long dealer secret, or a reconstruction from too few
//!   shares fails it; that epoch's key is refused and its tickets take their own refund path.
//!
//! Decryption noise: honest sums of 255 dealers give a standard deviation ≈ 5,600 against q/4 = 2,095,104 (the
//! `br9a_decryption_never_fails_at_255_contributors` pin measures it). Even dealers at the ±4n bound with every sign aligned
//! leave ≈ 20 standard deviations, since r is the encryptor's and FO-derived; a ticket writer grinding m can only spoil its
//! own ticket.
//!
//! Step (a) of §19: pure cryptography. The DKG and the epoch-share publication become chain objects in step (b); this module
//! names no ingress door yet. DIGITAL-CASH-PRIVACY-REVIEWED: every ciphertext is `CT_BYTES` wide whatever its contents and
//! whatever the custody size; a published epoch share is one constant-size vector per custodian.

use std::sync::OnceLock;

/// Coefficients per ring element.
pub const N: usize = 256;
/// ML-DSA's prime: 2²³ − 2¹³ + 1.
pub const Q: u32 = 8_380_417;
/// Rows of A (ranks of b, e, r).
pub const K: usize = 6;
/// Columns of A (ranks of s, e₁, u).
pub const L: usize = 5;
/// The secret and error bound: coefficients uniform in [−ETA, ETA].
pub const ETA: u32 = 4;
/// One ciphertext: u (L ring elements) then v (one), three bytes per coefficient.
pub const CT_BYTES: usize = (L + 1) * N * 3;
/// One ring element, coefficients in [0, q).
pub type Poly = [u32; N];

const Q64: u64 = Q as u64;
/// A primitive 512th root of unity mod q (ML-DSA's ζ), so X²⁵⁶ + 1 splits completely and the NTT is negacyclic.
const PSI: u64 = 1753;
const HALF_Q: u32 = Q / 2;

fn pow_mod(mut b: u64, mut e: u64) -> u64 {
    let mut r = 1u64;
    b %= Q64;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q64;
        }
        b = b * b % Q64;
        e >>= 1;
    }
    r
}

/// ψ^{brv₈(k)} — the powers the Cooley–Tukey butterflies take in ML-DSA's order.
fn zetas() -> &'static [u32; N] {
    static Z: OnceLock<[u32; N]> = OnceLock::new();
    Z.get_or_init(|| std::array::from_fn(|k| pow_mod(PSI, u64::from((k as u8).reverse_bits())) as u32))
}

fn add_q(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= Q {
        s - Q
    } else {
        s
    }
}

fn sub_q(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

fn mul_q(a: u32, b: u32) -> u32 {
    (u64::from(a) * u64::from(b) % Q64) as u32
}

/// Forward negacyclic NTT, in place (ML-DSA's reference loop, plain modular arithmetic).
fn ntt(a: &mut Poly) {
    let z = zetas();
    let mut k = 0usize;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = z[k];
            for j in start..start + len {
                let t = mul_q(zeta, a[j + len]);
                a[j + len] = sub_q(a[j], t);
                a[j] = add_q(a[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse of [`ntt`], including the 1/256 scaling.
fn inv_ntt(a: &mut Poly) {
    let z = zetas();
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = Q - z[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = add_q(t, a[j + len]);
                a[j + len] = mul_q(zeta, sub_q(t, a[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let f = pow_mod(N as u64, Q64 - 2) as u32;
    for c in a.iter_mut() {
        *c = mul_q(*c, f);
    }
}

fn to_ntt(a: &Poly) -> Poly {
    let mut h = *a;
    ntt(&mut h);
    h
}

fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for ((c, x), y) in acc.iter_mut().zip(a).zip(b) {
        *c = add_q(*c, mul_q(*x, *y));
    }
}

/// The product in R_q, through the NTT.
#[must_use]
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let (ah, bh) = (to_ntt(a), to_ntt(b));
    let mut c = [0u32; N];
    pointwise_acc(&mut c, &ah, &bh);
    inv_ntt(&mut c);
    c
}

/// The product in R_q by the definition (X²⁵⁶ = −1) — the reference [`poly_mul`] is pinned against.
#[must_use]
pub fn poly_mul_schoolbook(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0u32; N];
    for i in 0..N {
        for j in 0..N {
            let p = mul_q(a[i], b[j]);
            if i + j < N {
                c[i + j] = add_q(c[i + j], p);
            } else {
                c[i + j - N] = sub_q(c[i + j - N], p);
            }
        }
    }
    c
}

/// Coefficient-wise sum in R_q.
#[must_use]
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    std::array::from_fn(|i| add_q(a[i], b[i]))
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    std::array::from_fn(|i| sub_q(a[i], b[i]))
}

/// |c| for c read as the centered representative in (−q/2, q/2].
fn centered_abs(c: u32) -> u32 {
    if c > HALF_Q {
        Q - c
    } else {
        c
    }
}

/// A domain-separated blake3 XOF over `parts`.
fn xof(domain: &[u8], parts: &[&[u8]]) -> blake3::OutputReader {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize_xof()
}

/// The next value uniform in [0, q): 23-bit rejection (ML-DSA's ExpandA rule).
fn next_mod_q(r: &mut blake3::OutputReader) -> u32 {
    loop {
        let mut b = [0u8; 3];
        r.fill(&mut b);
        let v = (u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16) & 0x7F_FFFF;
        if v < Q {
            return v;
        }
    }
}

/// A ring element uniform in R_q from `seed` and `nonce`.
#[must_use]
pub fn uniform_poly(seed: &[u8; 32], nonce: u16) -> Poly {
    let mut r = xof(b"MUSD/epoch-key/uniform/v1", &[seed, &nonce.to_le_bytes()]);
    std::array::from_fn(|_| next_mod_q(&mut r))
}

/// A ring element with coefficients uniform in [−4, 4] (ML-DSA's η = 4 rule: a nibble t < 9 gives 4 − t).
fn short_poly(seed: &[u8; 32], nonce: u16) -> Poly {
    let mut r = xof(b"MUSD/epoch-key/short/v1", &[seed, &nonce.to_le_bytes()]);
    let mut out = [0u32; N];
    let mut filled = 0;
    while filled < N {
        let mut byte = [0u8; 1];
        r.fill(&mut byte);
        for t in [byte[0] & 0x0F, byte[0] >> 4] {
            if t < 9 && filled < N {
                out[filled] = sub_q(ETA, u32::from(t));
                filled += 1;
            }
        }
    }
    out
}

/// The public per-epoch seed A is expanded from: a function of the chain and the epoch only.
#[must_use]
pub fn epoch_seed(chain_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    xof(b"MUSD/epoch-key/seed/v1", &[chain_id, &epoch.to_le_bytes()]).fill(&mut out);
    out
}

/// Â = NTT(A), row-major K × L.
fn matrix_hat(seed: &[u8; 32]) -> Vec<Vec<Poly>> {
    (0..K).map(|i| (0..L).map(|j| to_ntt(&uniform_poly(seed, ((i as u16) << 8) | j as u16))).collect()).collect()
}

/// A dealer's secret contribution (s_i, e_i). Zeroed when dropped (§19 item 6: erasure).
#[derive(Clone, Debug)]
pub struct DealerSecret {
    s: Vec<Poly>,
    e: Vec<Poly>,
}

impl Drop for DealerSecret {
    fn drop(&mut self) {
        for p in self.s.iter_mut().chain(self.e.iter_mut()) {
            p.fill(0);
        }
        // keep the zeroing from being optimised away as a dead store
        std::hint::black_box(&self.s);
        std::hint::black_box(&self.e);
    }
}

/// A dealer's public contribution b_i = A·s_i + e_i.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPart {
    pub b: Vec<Poly>,
}

/// The epoch's one public key: its seed, b = Σ b_i, and how many dealers contributed (the release check's bound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochPublicKey {
    pub seed: [u8; 32],
    pub b: Vec<Poly>,
    pub contributors: u32,
}

/// One Shamir share of a vector in R_q^L at evaluation point `x` (`1..=255`; 0 is the secret itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretShare {
    pub x: u32,
    pub v: Vec<Poly>,
}

/// The reconstructed epoch secret s.
#[derive(Clone, Debug)]
pub struct EpochSecretKey {
    s: Vec<Poly>,
}

/// b = A·s + e for a dealer's secret.
#[must_use]
pub fn public_part(seed: &[u8; 32], sec: &DealerSecret) -> PublicPart {
    let a = matrix_hat(seed);
    let s_hat: Vec<Poly> = sec.s.iter().map(to_ntt).collect();
    let b = (0..K)
        .map(|i| {
            let mut acc = [0u32; N];
            for j in 0..L {
                pointwise_acc(&mut acc, &a[i][j], &s_hat[j]);
            }
            inv_ntt(&mut acc);
            poly_add(&acc, &sec.e[i])
        })
        .collect();
    PublicPart { b }
}

/// A packed public part: K ring elements, three bytes per coefficient.
pub const B_BYTES: usize = K * N * 3;

/// Pack a public part for the wire (`epoch_deal_tx`).
#[must_use]
pub fn pack_b(p: &PublicPart) -> Vec<u8> {
    let mut out = Vec::with_capacity(B_BYTES);
    for c in p.b.iter().flatten() {
        out.extend_from_slice(&c.to_le_bytes()[..3]);
    }
    out
}

/// Unpack a public part: exactly [`B_BYTES`] bytes, every coefficient in [0, q). `None` otherwise.
#[must_use]
pub fn unpack_b(bytes: &[u8]) -> Option<PublicPart> {
    if bytes.len() != B_BYTES {
        return None;
    }
    let mut b = Vec::with_capacity(K);
    for p in bytes.chunks_exact(N * 3) {
        let mut poly = [0u32; N];
        for (c, x) in poly.iter_mut().zip(p.chunks_exact(3)) {
            *c = u32::from(x[0]) | u32::from(x[1]) << 8 | u32::from(x[2]) << 16;
            if *c >= Q {
                return None;
            }
        }
        b.push(poly);
    }
    Some(PublicPart { b })
}

/// A dealer's contribution from its `entropy` (production passes OS randomness): short (s_i, e_i) and b_i.
///
/// The secret is derived from (entropy, epoch seed), never from the entropy alone: a dealer that reuses its entropy still
/// deals a different secret in every epoch, so an erased epoch key never reappears in another epoch.
/// ROOT-LAYER: the secret is bound to its epoch where it is produced (here), so no reader has to compare epochs.
/// MEASURED: before, `br9a_an_epoch_key_opens_no_other_epochs_ticket` failed — two epochs dealt from the same entropy gave
/// identical secrets and epoch 42's key opened epoch 41's ticket (1 of 9 pins red); after, 9 of 9.
/// MUST-STAY-GREEN: every `br9a_` pin, the cash-out ticket pin `a_ticket_opens_only_with_the_threshold_and_only_to_the_attested_destination`.
#[must_use]
pub fn deal(seed: &[u8; 32], entropy: &[u8; 32]) -> (DealerSecret, PublicPart) {
    let mut bound = [0u8; 32];
    xof(b"MUSD/epoch-key/dealer/v1", &[entropy, seed]).fill(&mut bound);
    let sec = DealerSecret {
        s: (0..L).map(|j| short_poly(&bound, j as u16)).collect(),
        e: (0..K).map(|i| short_poly(&bound, (L + i) as u16)).collect(),
    };
    let part = public_part(seed, &sec);
    (sec, part)
}

/// The epoch secret s = Σ s_i from every dealer's rebuilt secret (the release, once each dealer's seed is rebuilt).
#[must_use]
pub fn secret_from(dealers: &[DealerSecret]) -> EpochSecretKey {
    let mut s = vec![[0u32; N]; L];
    for d in dealers {
        for (acc, si) in s.iter_mut().zip(&d.s) {
            *acc = poly_add(acc, si);
        }
    }
    EpochSecretKey { s }
}

/// The epoch public key from every dealer's public part.
#[must_use]
pub fn combine_public(seed: &[u8; 32], parts: &[PublicPart]) -> EpochPublicKey {
    let mut b = vec![[0u32; N]; K];
    for p in parts {
        for (acc, bi) in b.iter_mut().zip(&p.b) {
            *acc = poly_add(acc, bi);
        }
    }
    EpochPublicKey { seed: *seed, b, contributors: parts.len() as u32 }
}

/// Split a dealer's s_i into `n` Shamir shares with threshold `t` (`1 ≤ t ≤ n ≤ 255`), the polynomial coefficients drawn
/// from `entropy`. Share `j` is evaluated at x = j + 1.
#[must_use]
pub fn share_dealer_secret(sec: &DealerSecret, t: usize, n: usize, entropy: &[u8; 32]) -> Option<Vec<SecretShare>> {
    if t == 0 || t > n || n > 255 {
        return None;
    }
    let mut r = xof(b"MUSD/epoch-key/shamir/v1", &[entropy]);
    let mut shares: Vec<SecretShare> = (1..=n as u32).map(|x| SecretShare { x, v: vec![[0u32; N]; L] }).collect();
    for (k, poly) in sec.s.iter().enumerate() {
        for (c, secret) in poly.iter().enumerate() {
            let coeffs: Vec<u32> = std::iter::once(*secret).chain((1..t).map(|_| next_mod_q(&mut r))).collect();
            for sh in shares.iter_mut() {
                // Horner from the highest coefficient
                let mut y = 0u32;
                for a in coeffs.iter().rev() {
                    y = add_q(mul_q(y, sh.x), *a);
                }
                sh.v[k][c] = y;
            }
        }
    }
    Some(shares)
}

/// Custodian j's epoch share: the sum of every dealer's share at j. `None` if empty or the points disagree.
#[must_use]
pub fn epoch_share(received: &[SecretShare]) -> Option<SecretShare> {
    let x = received.first()?.x;
    if received.iter().any(|s| s.x != x || s.v.len() != L) {
        return None;
    }
    let mut v = vec![[0u32; N]; L];
    for s in received {
        for (acc, p) in v.iter_mut().zip(&s.v) {
            *acc = poly_add(acc, p);
        }
    }
    Some(SecretShare { x, v })
}

/// The polynomial through `points` evaluated at `x` (Lagrange over Z_q). `None` on a repeated or out-of-field point.
#[must_use]
pub fn interpolate_at(points: &[SecretShare], x: u32) -> Option<Vec<Poly>> {
    if points.is_empty() || x >= Q || points.iter().any(|p| p.x >= Q || p.v.len() != L) {
        return None;
    }
    for (i, p) in points.iter().enumerate() {
        if points[..i].iter().any(|q| q.x == p.x) {
            return None;
        }
    }
    let mut out = vec![[0u32; N]; L];
    for (i, pi) in points.iter().enumerate() {
        let (mut num, mut den) = (1u32, 1u32);
        for (j, pj) in points.iter().enumerate() {
            if i != j {
                num = mul_q(num, sub_q(x, pj.x));
                den = mul_q(den, sub_q(pi.x, pj.x));
            }
        }
        let lambda = mul_q(num, pow_mod(u64::from(den), Q64 - 2) as u32);
        for (acc, p) in out.iter_mut().zip(&pi.v) {
            for (a, c) in acc.iter_mut().zip(p) {
                *a = add_q(*a, mul_q(lambda, *c));
            }
        }
    }
    Some(out)
}

/// Reconstruct s from the first `t` published epoch shares. `None` with fewer than `t`, `t` = 0, a zero point or a repeat.
#[must_use]
pub fn reconstruct(shares: &[SecretShare], t: usize) -> Option<EpochSecretKey> {
    if t == 0 || shares.len() < t || shares[..t].iter().any(|s| s.x == 0) {
        return None;
    }
    interpolate_at(&shares[..t], 0).map(|s| EpochSecretKey { s })
}

/// ⭐ THE RELEASE CHECK: s and b − A·s both within ±ETA·contributors. Anything else is refused, never used.
#[must_use]
pub fn release_check(pk: &EpochPublicKey, sk: &EpochSecretKey) -> bool {
    let bound = ETA.saturating_mul(pk.contributors);
    if pk.contributors == 0 || sk.s.len() != L || pk.b.len() != K {
        return false;
    }
    if sk.s.iter().flatten().any(|c| centered_abs(*c) > bound) {
        return false;
    }
    let as_ = public_part(&pk.seed, &DealerSecret { s: sk.s.clone(), e: vec![[0u32; N]; K] });
    pk.b.iter().zip(&as_.b).all(|(b, a)| poly_sub(b, a).iter().all(|c| centered_abs(*c) <= bound))
}

fn pk_hash(pk: &EpochPublicKey) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/epoch-key/pk/v1");
    h.update(&pk.seed);
    h.update(&pk.contributors.to_le_bytes());
    for c in pk.b.iter().flatten() {
        h.update(&c.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// (u, v) for message `m` under coins derived from (m, H(pk)) — deterministic in `m`, so decapsulation can re-encrypt.
fn encrypt(pk: &EpochPublicKey, m: &[u8; 32]) -> (Vec<Poly>, Poly) {
    let coins = {
        let mut c = [0u8; 32];
        xof(b"MUSD/epoch-key/coins/v1", &[m, &pk_hash(pk)]).fill(&mut c);
        c
    };
    let a = matrix_hat(&pk.seed);
    let r_hat: Vec<Poly> = (0..K).map(|i| to_ntt(&short_poly(&coins, i as u16))).collect();
    let u = (0..L)
        .map(|j| {
            let mut acc = [0u32; N];
            for i in 0..K {
                pointwise_acc(&mut acc, &a[i][j], &r_hat[i]);
            }
            inv_ntt(&mut acc);
            poly_add(&acc, &short_poly(&coins, (K + j) as u16))
        })
        .collect();
    let mut v = [0u32; N];
    for i in 0..K {
        pointwise_acc(&mut v, &to_ntt(&pk.b[i]), &r_hat[i]);
    }
    inv_ntt(&mut v);
    let v = poly_add(&poly_add(&v, &short_poly(&coins, (K + L) as u16)), &encode(m));
    (u, v)
}

fn encode(m: &[u8; 32]) -> Poly {
    std::array::from_fn(|i| if (m[i / 8] >> (i % 8)) & 1 == 1 { HALF_Q } else { 0 })
}

fn serialize(u: &[Poly], v: &Poly) -> Vec<u8> {
    let mut out = Vec::with_capacity(CT_BYTES);
    for c in u.iter().chain(std::iter::once(v)).flatten() {
        out.extend_from_slice(&c.to_le_bytes()[..3]);
    }
    out
}

fn deserialize(ct: &[u8]) -> Option<(Vec<Poly>, Poly)> {
    if ct.len() != CT_BYTES {
        return None;
    }
    let mut polys = Vec::with_capacity(L + 1);
    for p in ct.chunks_exact(N * 3) {
        let mut poly = [0u32; N];
        for (c, b) in poly.iter_mut().zip(p.chunks_exact(3)) {
            *c = u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16;
            if *c >= Q {
                return None;
            }
        }
        polys.push(poly);
    }
    let v = polys.pop()?;
    Some((polys, v))
}

/// w = v − sᵀu: the message plus the decryption noise.
fn decrypt_raw(sk: &EpochSecretKey, u: &[Poly], v: &Poly) -> Poly {
    let mut su = [0u32; N];
    for (s, uj) in sk.s.iter().zip(u) {
        pointwise_acc(&mut su, &to_ntt(s), &to_ntt(uj));
    }
    inv_ntt(&mut su);
    poly_sub(v, &su)
}

fn ticket_key(m: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    xof(b"MUSD/epoch-key/key/v1", &[m, blake3::hash(ct).as_bytes()]).fill(&mut k);
    k
}

/// Encapsulate to the epoch key: `(ticket key, ciphertext of CT_BYTES)` for a random 256-bit `m` (the caller's entropy).
#[must_use]
pub fn encapsulate(pk: &EpochPublicKey, m: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let (u, v) = encrypt(pk, m);
    let ct = serialize(&u, &v);
    (ticket_key(m, &ct), ct)
}

/// Decapsulate with the released epoch secret. `None` for a ciphertext of the wrong width or one that does not re-encrypt to
/// itself under the decrypted message (Fujisaki–Okamoto: a tampered or foreign-epoch ciphertext opens nothing).
#[must_use]
pub fn decapsulate(pk: &EpochPublicKey, sk: &EpochSecretKey, ct: &[u8]) -> Option<[u8; 32]> {
    decapsulate_message(pk, sk, ct).map(|(_, k)| k)
}

/// [`decapsulate`], also returning the encapsulated message `m` (§BR-5 B5-d: an escrowed piece's escrow keys derive from `m`,
/// which the wallet derives from its own words, so a restore re-derives them with no chain state). Same FO check.
#[must_use]
pub fn decapsulate_message(pk: &EpochPublicKey, sk: &EpochSecretKey, ct: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (u, v) = deserialize(ct)?;
    if sk.s.len() != L {
        return None;
    }
    let w = decrypt_raw(sk, &u, &v);
    let mut m = [0u8; 32];
    for (i, c) in w.iter().enumerate() {
        if centered_abs(*c) > Q / 4 {
            m[i / 8] |= 1 << (i % 8);
        }
    }
    let (u2, v2) = encrypt(pk, &m);
    (serialize(&u2, &v2) == ct).then(|| (m, ticket_key(&m, ct)))
}

/// The largest |w − ⌊q/2⌋·m| over the coefficients — the noise a decryption of `m` faced (measured by the pins).
#[must_use]
pub fn decryption_noise(pk: &EpochPublicKey, sk: &EpochSecretKey, m: &[u8; 32]) -> u32 {
    let (u, v) = encrypt(pk, m);
    let w = decrypt_raw(sk, &u, &v);
    poly_sub(&w, &encode(m)).iter().fold(0, |worst, c| worst.max(centered_abs(*c)))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::cashout_ticket::{open_bound, seal, TICKET_BYTES};
    use crate::shamir::two_thirds_threshold;

    fn bytes(tag: u8, i: u32) -> [u8; 32] {
        *blake3::hash(&[&[tag][..], &i.to_le_bytes()[..]].concat()).as_bytes()
    }

    /// One epoch's DKG among `n` custodians: every dealer's secret, the epoch public key, and the epoch share each custodian
    /// publishes at the epoch (the sum of the shares the dealers sealed to it).
    fn ceremony(seed: &[u8; 32], n: usize, t: usize) -> (EpochPublicKey, Vec<DealerSecret>, Vec<SecretShare>) {
        let dealt: Vec<(DealerSecret, PublicPart)> = (0..n).map(|i| deal(seed, &bytes(1, i as u32))).collect();
        let pk = combine_public(seed, &dealt.iter().map(|d| d.1.clone()).collect::<Vec<_>>());
        let sent: Vec<Vec<SecretShare>> =
            dealt.iter().enumerate().map(|(i, d)| share_dealer_secret(&d.0, t, n, &bytes(2, i as u32)).unwrap()).collect();
        let published = publish(&sent, n);
        (pk, dealt.into_iter().map(|d| d.0).collect(), published)
    }

    /// Custodian j's published epoch share: the sum of what every dealer sealed to j.
    fn publish(sent: &[Vec<SecretShare>], n: usize) -> Vec<SecretShare> {
        (0..n).map(|j| epoch_share(&sent.iter().map(|s| s[j].clone()).collect::<Vec<_>>()).unwrap()).collect()
    }

    /// THE RECIPIENT — any node, not a custodian: it holds only what the chain carries (the epoch public key, the published
    /// epoch shares, the ticket's ciphertexts and the burn's commitment), never a dealer's secret.
    fn recipient_opens(
        pk: &EpochPublicKey,
        published: &[SecretShare],
        t: usize,
        ct: &[u8],
        ticket: &[u8; TICKET_BYTES],
        commit: &[u8; 32],
    ) -> Option<(Vec<u8>, u64, crate::spend_frontier::Digest4)> {
        let sk = reconstruct(published, t)?;
        if !release_check(pk, &sk) {
            return None;
        }
        open_bound(&decapsulate(pk, &sk, ct)?, ticket, commit)
    }

    /// ⭐ §BR-9a — the NTT the whole scheme multiplies with agrees with the schoolbook negacyclic product over R_q.
    #[test]
    fn br9a_the_ntt_product_equals_the_schoolbook_negacyclic_product() {
        for i in 0..8u32 {
            let a = uniform_poly(&bytes(3, i), 0);
            let b = uniform_poly(&bytes(4, i), 0);
            assert_eq!(poly_mul(&a, &b), poly_mul_schoolbook(&a, &b), "case {i}");
        }
        // X · X^255 = X^256 = −1 in R_q
        let mut x = [0u32; N];
        x[1] = 1;
        let mut x255 = [0u32; N];
        x255[255] = 1;
        let mut minus_one = [0u32; N];
        minus_one[0] = Q - 1;
        assert_eq!(poly_mul(&x, &x255), minus_one);
    }

    /// ⭐ §BR-9a — A TICKET SEALED TO AN EPOCH OPENS WITH t EPOCH SHARES AND NOT WITH t − 1.
    /// Ten custodians (t = 7) run the dealer-free DKG; the requester seals a cash-out ticket under a key encapsulated to the
    /// epoch's one public key. The RECIPIENT — a party that holds only the chain's public data — opens it from the last seven
    /// published epoch shares, to the attested destination. TAMPERS: six shares are refused; six shares forced through a
    /// six-point interpolation give a secret that fails the release check and decapsulates nothing.
    /// The crossing between nodes (dealers on separate custodian nodes, shares sealed per receiver, epoch shares carried by a
    /// block and opened on a peer) is §19 step (b)'s pin; this pins the cryptography both sides run.
    #[test]
    fn br9a_a_ticket_sealed_to_an_epoch_opens_with_t_epoch_shares_and_not_with_t_minus_one() {
        let n = 10;
        let t = two_thirds_threshold(n);
        assert_eq!(t, 7);
        let seed = epoch_seed(&bytes(5, 0), 41);
        let (pk, _, published) = ceremony(&seed, n, t);

        // the requester
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0x9a, 1, 2, 3]);
        let addr = b"tb1qepochkeyticketdestination000000000000000".to_vec();
        let commit = crate::peg::redeem_commit(&addr, 7_000, &blind);
        let (key, ct) = encapsulate(&pk, &bytes(6, 0));
        let ticket = seal(&key, &addr, 7_000, &blind).unwrap();

        // the recipient, from any t published shares
        assert_eq!(recipient_opens(&pk, &published[n - t..], t, &ct, &ticket, &commit), Some((addr, 7_000, blind)));

        assert!(reconstruct(&published[..t - 1], t).is_none(), "t − 1 shares are refused");
        let forced = reconstruct(&published[..t - 1], t - 1).expect("a six-point interpolation runs");
        assert!(!release_check(&pk, &forced), "t − 1 shares never give the epoch secret");
        assert!(decapsulate(&pk, &forced, &ct).is_none(), "and open nothing");
    }

    /// ⭐ §BR-9a — ONE CIPHERTEXT PER TICKET, WHATEVER THE CUSTODY SIZE: the ciphertext under a 4-custodian key and under a
    /// 40-custodian key is the same `CT_BYTES` (today's per-ticket shares grow by one sealed share per custodian).
    #[test]
    fn br9a_one_ciphertext_per_ticket_whatever_the_custody_size() {
        for (n, e) in [(4usize, 1u64), (40, 2)] {
            let seed = epoch_seed(&bytes(5, 1), e);
            let parts: Vec<PublicPart> = (0..n).map(|i| deal(&seed, &bytes(7, i as u32)).1).collect();
            let pk = combine_public(&seed, &parts);
            for m in 0..3u32 {
                let (_, ct) = encapsulate(&pk, &bytes(8, m));
                assert_eq!(ct.len(), CT_BYTES, "n = {n}");
            }
        }
        assert_eq!(CT_BYTES, 4_608);
    }

    /// ⭐ §BR-9a — t − 1 EPOCH SHARES ARE CONSISTENT WITH EVERY SECRET (Shamir over Z_q is information-theoretic). The
    /// ADVERSARY is a coalition of t − 1 custodians: for the real secret AND for unrelated ones, a degree t − 1 polynomial
    /// passes through its t − 1 shares, so its view cannot distinguish the epoch secret from any other.
    #[test]
    fn br9a_t_minus_one_epoch_shares_are_consistent_with_every_secret() {
        let n = 10;
        let t = two_thirds_threshold(n);
        let seed = epoch_seed(&bytes(5, 2), 3);
        let (_, _, published) = ceremony(&seed, n, t);
        let real = reconstruct(&published[..t], t).unwrap();
        let adversary = &published[..t - 1];
        for other in [vec![[0u32; N]; L], (0..L).map(|i| uniform_poly(&bytes(9, i as u32), 0)).collect::<Vec<_>>()] {
            // the polynomial through (0, other) and the adversary's points, evaluated at a further holder's x
            let mut pts: Vec<SecretShare> = vec![SecretShare { x: 0, v: other.clone() }];
            pts.extend_from_slice(adversary);
            let further = SecretShare { x: published[t - 1].x, v: interpolate_at(&pts, published[t - 1].x).unwrap() };
            let mut view: Vec<SecretShare> = adversary.to_vec();
            view.push(further);
            let opened = reconstruct(&view, t).unwrap();
            assert_eq!(opened.s, other, "t − 1 shares plus one consistent point give any secret");
            assert_ne!(opened.s, real.s);
        }
    }

    /// ⭐ §BR-9a TAMPER — a dealer that publishes b_0 = A·s_0 + e_0 but shares a DIFFERENT short secret makes the
    /// reconstructed key fail the release check (b − A·s is no longer short): the epoch key is refused, never used.
    #[test]
    fn br9a_a_dealer_whose_shares_do_not_match_its_public_part_fails_the_release_check() {
        let n = 10;
        let t = two_thirds_threshold(n);
        let seed = epoch_seed(&bytes(5, 3), 9);
        let mut dealt: Vec<(DealerSecret, PublicPart)> = (0..n).map(|i| deal(&seed, &bytes(10, i as u32))).collect();
        let pk = combine_public(&seed, &dealt.iter().map(|d| d.1.clone()).collect::<Vec<_>>());
        let open = |dealt: &[(DealerSecret, PublicPart)]| {
            let sent: Vec<Vec<SecretShare>> =
                dealt.iter().map(|d| share_dealer_secret(&d.0, t, n, &bytes(11, 0)).unwrap()).collect();
            reconstruct(&publish(&sent, n)[..t], t).unwrap()
        };
        assert!(release_check(&pk, &open(&dealt)), "calibration: the honest ceremony passes");

        dealt[0].0 = deal(&seed, &bytes(12, 0)).0; // shares another short secret than the one its b_0 commits to
        assert!(!release_check(&pk, &open(&dealt)), "a mismatched dealer is caught by the release check");
    }

    /// ⭐ §BR-9a TAMPER — a dealer whose secret is NOT short (consistent b_i and shares, coefficients near q/3) would push the
    /// decryption noise past q/4: the reconstructed secret fails the release check's shortness bound and is refused.
    #[test]
    fn br9a_a_dealer_with_a_long_secret_fails_the_release_check() {
        let n = 10;
        let t = two_thirds_threshold(n);
        let seed = epoch_seed(&bytes(5, 4), 11);
        let mut dealt: Vec<(DealerSecret, PublicPart)> = (0..n).map(|i| deal(&seed, &bytes(13, i as u32))).collect();
        let long = DealerSecret { s: vec![[Q / 3; N]; L], e: dealt[0].0.e.clone() };
        let b0 = public_part(&seed, &long);
        dealt[0] = (long, b0);
        let pk = combine_public(&seed, &dealt.iter().map(|d| d.1.clone()).collect::<Vec<_>>());
        let sent: Vec<Vec<SecretShare>> =
            dealt.iter().map(|d| share_dealer_secret(&d.0, t, n, &bytes(14, 0)).unwrap()).collect();
        let sk = reconstruct(&publish(&sent, n)[..t], t).unwrap();
        assert!(!release_check(&pk, &sk), "a long dealer secret is refused");
    }

    /// ⭐ §BR-9a — DECRYPTION NEVER FAILS AT 255 CONTRIBUTORS (the most custodians a Shamir x-coordinate set names). The
    /// secret is the sum of 255 dealers' secrets; 64 encapsulations all decapsulate, and the largest decryption noise
    /// measured stays under q/8 — half the q/4 at which a bit would flip.
    #[test]
    fn br9a_decryption_never_fails_at_255_contributors() {
        let seed = epoch_seed(&bytes(5, 5), 255);
        let dealt: Vec<(DealerSecret, PublicPart)> = (0..255).map(|i| deal(&seed, &bytes(15, i))).collect();
        let pk = combine_public(&seed, &dealt.iter().map(|d| d.1.clone()).collect::<Vec<_>>());
        let mut s = vec![[0u32; N]; L];
        for d in &dealt {
            for (acc, si) in s.iter_mut().zip(&d.0.s) {
                *acc = poly_add(acc, si);
            }
        }
        let sk = EpochSecretKey { s };
        assert!(release_check(&pk, &sk));
        let mut worst = 0u32;
        for m in 0..64u32 {
            let (key, ct) = encapsulate(&pk, &bytes(16, m));
            assert_eq!(decapsulate(&pk, &sk, &ct), Some(key), "message {m}");
            worst = worst.max(decryption_noise(&pk, &sk, &bytes(16, m)));
        }
        eprintln!("br9a: 255 contributors, worst decryption noise {worst} against q/4 = {}", Q / 4);
        assert!(worst < Q / 8, "noise {worst} must stay under q/8");
    }

    /// ⭐ §BR-9a — AN EPOCH KEY OPENS NO OTHER EPOCH'S TICKET: a ciphertext to epoch 41's key decapsulates to nothing under
    /// epoch 42's key (either pairing).
    #[test]
    fn br9a_an_epoch_key_opens_no_other_epochs_ticket() {
        let n = 7;
        let t = two_thirds_threshold(n);
        let (pk41, _, sh41) = ceremony(&epoch_seed(&bytes(5, 6), 41), n, t);
        let (pk42, _, sh42) = ceremony(&epoch_seed(&bytes(5, 6), 42), n, t);
        let sk41 = reconstruct(&sh41[..t], t).unwrap();
        let sk42 = reconstruct(&sh42[..t], t).unwrap();
        let (key, ct) = encapsulate(&pk41, &bytes(17, 0));
        assert_eq!(decapsulate(&pk41, &sk41, &ct), Some(key), "calibration");
        assert!(decapsulate(&pk42, &sk42, &ct).is_none());
        assert!(decapsulate(&pk41, &sk42, &ct).is_none());
        assert!(decapsulate(&pk42, &sk41, &ct).is_none());
    }

    /// ⭐ §BR-9a TAMPER — a ciphertext with any one byte changed, or of the wrong length, is refused (Fujisaki–Okamoto
    /// re-encryption): it never decapsulates to a key.
    #[test]
    fn br9a_a_tampered_ciphertext_is_refused() {
        let n = 4;
        let t = two_thirds_threshold(n);
        let (pk, _, sh) = ceremony(&epoch_seed(&bytes(5, 7), 1), n, t);
        let sk = reconstruct(&sh[..t], t).unwrap();
        let (key, ct) = encapsulate(&pk, &bytes(18, 0));
        assert_eq!(decapsulate(&pk, &sk, &ct), Some(key), "calibration");
        for at in [0usize, 1, 700, CT_BYTES / 2, CT_BYTES - 1] {
            let mut bad = ct.clone();
            bad[at] ^= 0x01;
            assert!(decapsulate(&pk, &sk, &bad).is_none(), "byte {at}");
        }
        assert!(decapsulate(&pk, &sk, &ct[..CT_BYTES - 1]).is_none());
    }
}

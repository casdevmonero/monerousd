// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §BR-5 — SHAMIR SECRET SHARING over GF(2⁸), byte-wise (Shamir 1979; the field and its reduction polynomial
//! x⁸ + x⁴ + x³ + x + 1 are AES's). A secret of any length is split into `n` shares, any `t` of which reconstruct it and any
//! `t − 1` of which are independent of it (information-theoretic: unconditional, so post-quantum by construction).
//! Used for the cash-out ticket key (docs/BR-5-CASHOUT-TICKETS-SPEC-20261029.md): reading a destination early needs ≥ t
//! custodians, never one.
//!
//! A share is `(x, y)`: `x ∈ 1..=255` its evaluation point (0 would be the secret itself), `y` one byte per secret byte.
//! Constant time over the share bytes (table-free multiply), so a reconstruction leaks nothing through timing.

/// GF(2⁸) multiply (carry-less, reduced by 0x11B), constant time in its operands.
#[must_use]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    p
}

/// GF(2⁸) inverse (a²⁵⁴), `0` for `0`.
#[must_use]
pub fn gf_inv(a: u8) -> u8 {
    let mut r = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

/// One share: its evaluation point and one byte per secret byte.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Share {
    pub x: u8,
    pub y: Vec<u8>,
}

/// Split `secret` into `n` shares with threshold `t` (`1 ≤ t ≤ n ≤ 255`), the polynomial coefficients drawn from `coeffs`
/// (`(t − 1) · secret.len()` random bytes — the caller's entropy; production passes OS randomness). `None` on a bad
/// threshold or too few coefficient bytes. Share `i` is evaluated at `x = i + 1`.
#[must_use]
pub fn split(secret: &[u8], t: usize, n: usize, coeffs: &[u8]) -> Option<Vec<Share>> {
    if t == 0 || t > n || n > 255 || coeffs.len() < (t - 1) * secret.len() {
        return None;
    }
    let mut shares: Vec<Share> = (1..=n).map(|x| Share { x: x as u8, y: Vec::with_capacity(secret.len()) }).collect();
    for (j, s) in secret.iter().enumerate() {
        // coefficients of the byte's polynomial: a_0 = the secret byte, a_1..a_{t-1} random
        let poly: Vec<u8> = std::iter::once(*s).chain((0..t - 1).map(|k| coeffs[k * secret.len() + j])).collect();
        for sh in shares.iter_mut() {
            // Horner: evaluate at x
            let mut acc = 0u8;
            for c in poly.iter().rev() {
                acc = gf_mul(acc, sh.x) ^ c;
            }
            sh.y.push(acc);
        }
    }
    Some(shares)
}

/// Reconstruct the secret from `shares` by Lagrange interpolation at 0. `None` with no share, mismatched lengths, a zero or a
/// repeated `x`. With fewer than the threshold the result is a value unrelated to the secret (the caller checks it against
/// a binding commitment, never trusts it).
#[must_use]
pub fn combine(shares: &[Share]) -> Option<Vec<u8>> {
    let first = shares.first()?;
    let len = first.y.len();
    let mut xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    if shares.iter().any(|s| s.y.len() != len || s.x == 0) {
        return None;
    }
    xs.sort_unstable();
    if xs.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    let mut out = vec![0u8; len];
    for (i, si) in shares.iter().enumerate() {
        // l_i(0) = Π_{j≠i} x_j / (x_j − x_i); subtraction is XOR in GF(2⁸)
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                num = gf_mul(num, sj.x);
                den = gf_mul(den, sj.x ^ si.x);
            }
        }
        let l = gf_mul(num, gf_inv(den));
        for (o, y) in out.iter_mut().zip(&si.y) {
            *o ^= gf_mul(*y, l);
        }
    }
    Some(out)
}

/// The threshold for `n` custodians: ⌈2n/3⌉ (at least 1) — the two thirds every custody action needs.
#[must_use]
pub fn two_thirds_threshold(n: usize) -> usize {
    ((2 * n).div_ceil(3)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ §BR-5 — ANY t SHARES RECONSTRUCT, AND t − 1 SHARES ARE INDEPENDENT OF THE SECRET.
    /// - The field: every non-zero element times its inverse is 1, and multiplication is commutative and distributes over XOR
    ///   (exhaustive over all 256 × 256 pairs).
    /// - Every t-subset of a 7-share, t = 5 split reconstructs the 32-byte secret; a 4-subset does not.
    /// - INDEPENDENCE (exhaustive, one byte, t = 2, n = 3): for a fixed share 1 value, every secret byte is consistent with
    ///   exactly one coefficient — so one share alone says nothing about the secret.
    /// TAMPERS: a repeated x, a zero x and a short share are refused; a flipped share byte reconstructs another secret.
    #[test]
    fn any_threshold_of_shares_reconstructs_and_fewer_are_independent_of_the_secret() {
        for a in 0..=255u8 {
            if a != 0 {
                assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
            }
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
                assert_eq!(gf_mul(a, b ^ 0x53), gf_mul(a, b) ^ gf_mul(a, 0x53));
            }
        }
        assert_eq!(gf_mul(0x57, 0x83), 0xC1, "FIPS-197 §4.2's worked product");
        let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
        let coeffs: Vec<u8> = (0..4 * 32).map(|i| (i as u8).wrapping_mul(101).wrapping_add(7)).collect();
        let shares = split(&secret, 5, 7, &coeffs).expect("splits");
        assert_eq!(shares.len(), 7);
        for mask in 0u32..(1 << 7) {
            let pick: Vec<Share> = (0..7).filter(|i| mask & (1 << i) != 0).map(|i| shares[i].clone()).collect();
            if pick.is_empty() {
                continue;
            }
            let got = combine(&pick).expect("combines");
            if pick.len() >= 5 {
                assert_eq!(got, secret, "a {}-subset failed to reconstruct", pick.len());
            } else {
                assert_ne!(got, secret, "⛔ {} shares (below the threshold) reconstructed the secret", pick.len());
            }
        }
        // independence: t = 2, n = 3, one byte — share 1's value is uniform over the coefficient for every secret
        for y1 in [0u8, 1, 0x80, 0xff] {
            for s in 0..=255u8 {
                let matching = (0..=255u8).filter(|c| split(&[s], 2, 3, &[*c]).expect("splits")[0].y[0] == y1).count();
                assert_eq!(matching, 1, "share 1 = {y1} must be consistent with secret {s} through exactly one coefficient");
            }
        }
        let mut dup = shares[..5].to_vec();
        dup[1].x = dup[0].x;
        assert!(combine(&dup).is_none(), "⛔ a repeated x combined");
        let mut zero = shares[..5].to_vec();
        zero[0].x = 0;
        assert!(combine(&zero).is_none(), "⛔ a zero x combined");
        let mut short = shares[..5].to_vec();
        short[2].y.pop();
        assert!(combine(&short).is_none(), "⛔ a short share combined");
        let mut flipped = shares[..5].to_vec();
        flipped[3].y[0] ^= 1;
        assert_ne!(combine(&flipped).expect("combines"), secret, "⛔ a flipped share still reconstructed the secret");
        assert!(split(&secret, 0, 3, &coeffs).is_none() && split(&secret, 4, 3, &coeffs).is_none(), "bad thresholds refused");
        assert_eq!((two_thirds_threshold(1), two_thirds_threshold(3), two_thirds_threshold(4), two_thirds_threshold(100)), (1, 2, 3, 67));
    }
}

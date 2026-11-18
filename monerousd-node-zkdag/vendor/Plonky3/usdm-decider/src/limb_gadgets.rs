// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! **LIMB GADGETS — 8-bit-limb arithmetic for in-circuit ≥ / conservation constraints over hidden values.**
//!
//! Extracted from the retired confidential-AMM curve AIR (user ruling 2026-08-26: the pool AMM is deleted
//! at source; the P2P limit-order DEX replaces it). The curve retired — THIS machinery is what survives,
//! because the order-crossing constraint needs exactly the same bricks: decompose hidden values into
//! 8-bit limbs, multiply/subtract them without ever materialising an overflow-prone integer, and prove a
//! `≥` between hidden quantities via a borrow-free subtraction. 8-bit limbs are mandatory over KoalaBear
//! (p ≈ 2^31): 16-bit partial products reach 2^32 and WRAP — measured as the limbs8 masked-shift class of
//! silent garbage, so every helper here asserts its bounds instead of defaulting.
//!
//! Witness-side helpers (`limbs8`, `mul_limbs`, `sub_limbs`, `scale_carries`) build the limb columns; the
//! `push_*` builders emit the matching AIR constraints against caller-chosen column indices, so any trace
//! layout can reuse them. All of it is layout-free by construction — the retired AIR's layout-bound
//! pieces were deliberately NOT carried over.

use crate::confidential_solvency::N_LIMB16;
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;

/// 8 bits per limb — the ONLY safe width over KoalaBear (see the module doc).
pub const BITS_PER_LIMB: usize = 8;
/// Limb count of a u64 value.
pub const L64: usize = 8;
/// Limb count of an 80-bit intermediate (u64 × u16-scale).
pub const L80: usize = 10;
/// Limb count of a 144-bit product (80-bit × 64-bit).
pub const L144: usize = 18;

/// Little-endian 8-bit limbs of a value that FITS IN `u128`. A limb position past the source type's
/// width is ZERO — never a wrapped shift.
///
/// ROOT-LAYER: this function is where a limb's VALUE IS PRODUCED — the trace's only source of limb data.
/// The defect was a masked shift here, so patching any consumer (the product constraint, the trace
/// writer) would have left every other caller reading the same garbage.
/// MEASURED 2026-08-26 (before): limb 17 evaluated `(v >> 136) & 0xFF`, and Rust MASKS a `u128` shift by
/// 127 in release, so it silently returned `(v >> 8) & 0xFF` — the k' block held `169` where the true
/// product limb is `0`. Effect: all 4 honest-settlement tests RED while all 5 extraction gates stayed
/// GREEN — a soundness gate that looks alive because only its refusals still work.
/// MUST-STAY-GREEN: the five adversarial gates (extraction, zero-input, over-drain, fee-free, tamper),
/// which must keep refusing after this fix, plus the layout test.
pub fn limbs8(v: u128, n: usize) -> Vec<u64> {
    (0..n)
        .map(|i| {
            let sh = 8 * i;
            if sh >= 128 {
                0
            } else {
                ((v >> sh) & 0xFF) as u64
            }
        })
        .collect()
}

/// Schoolbook `a·b` over 8-bit limbs, returning `(product limbs, carries)`.
///
/// ROOT-LAYER: the product is PRODUCED here, limb-wise, and is never materialised as an integer —
/// because it cannot be. At u64-scale reserves `xn·yn` reaches `2^139`, which OVERFLOWS `u128`, so any
/// design that computed the product first and split it into limbs afterwards is unsound at the top of
/// the value domain no matter how the splitting is written.
/// MEASURED 2026-08-26: `the_curve_holds_at_the_top_of_the_u64_value_domain` uses `x = u64::MAX/4`,
/// `y = u64::MAX/8` — `k' ≈ 2^139`, i.e. 2^11 times past `u128::MAX`.
/// MUST-STAY-GREEN: the five adversarial gates, which rely on this returning `None` (top carry set) when
/// a product does not fit its block.
pub fn mul_limbs(al: &[u64], bl: &[u64], np: usize) -> Option<(Vec<u64>, Vec<u64>)> {
    let mut prod = Vec::with_capacity(np);
    let mut carry = Vec::with_capacity(np);
    let mut cin = 0u64;
    for k in 0..np {
        let mut acc = 0u64;
        for (i, a) in al.iter().enumerate() {
            if k < i {
                continue;
            }
            let j = k - i;
            if j < bl.len() {
                acc += a * bl[j];
            }
        }
        let t = acc + cin;
        prod.push(t & 0xFF);
        cin = t >> BITS_PER_LIMB;
        carry.push(cin);
    }
    if cin != 0 {
        return None; // the product does not fit its block
    }
    Some((prod, carry))
}

/// Limb-wise `a − b` over `n` limbs, returning `(difference limbs, borrows)`. `None` when `a < b` (a
/// borrow out of the top limb) — exactly how both `y ≥ dy` and the `k' ≥ k` invariant are decided
/// natively, on values too wide to subtract as integers.
///
/// ROOT-LAYER: the difference AND the borrow chain are produced together here; the AIR constrains that
/// same chain, so a single producer keeps the native and in-circuit answers identical by construction.
/// MEASURED 2026-08-26: `k'` and `k` are 18-limb (144-bit) quantities — subtracting them as `u128` is
/// impossible, which is why the native invariant check must live at the limb layer too.
/// MUST-STAY-GREEN: `paying_out_more_than_the_reserve_holds_is_unprovable` and
/// `taking_one_atomic_unit_more_than_the_curve_allows_is_unprovable` both depend on the `None` arm.
///
/// Both slices must be at least `n` long — a short slice is a layout bug in the caller, so it panics
/// rather than defaulting a limb to zero and silently proving a different number.
pub fn sub_limbs(al: &[u64], bl: &[u64], n: usize) -> Option<(Vec<u64>, Vec<u64>)> {
    assert!(al.len() >= n && bl.len() >= n, "sub_limbs: operand shorter than the block");
    let mut diff = Vec::with_capacity(n);
    let mut borrow = Vec::with_capacity(n);
    let mut bin = 0i64;
    for i in 0..n {
        let d = al[i] as i64 - bl[i] as i64 - bin;
        if d < 0 {
            diff.push((d + 256) as u64);
            bin = 1;
        } else {
            diff.push(d as u64);
            bin = 0;
        }
        borrow.push(bin as u64);
    }
    if bin != 0 {
        return None; // a < b
    }
    Some((diff, borrow))
}

/// Native carry chain for `k·src` over `L80` limbs. `None` when the scaled value overflows its block.
pub fn scale_carries(src: u128, k: u64) -> Option<Vec<u64>> {
    let sl = limbs8(src, L80);
    let mut out = Vec::with_capacity(L80);
    let mut cin = 0u64;
    for l in sl.iter().take(L80) {
        cin = (l * k + cin) >> BITS_PER_LIMB;
        out.push(cin);
    }
    if cin != 0 {
        return None;
    }
    Some(out)
}

/// Push a `w`-bit range bind over `cnt` carry columns at `carry`, decomposed into `bits`.
pub fn push_carry_bind(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, carry: usize, cnt: usize, bits: usize, w: usize) {
    let two = Ea4::from(Fa4::from_u64(2));
    for i in 0..cnt {
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for b in 0..w {
            let bit = local[bits + i * w + b];
            cs.push(bit * (bit - Ea4::ONE));
            rec += bit * pw;
            pw *= two;
        }
        cs.push(rec - local[carry + i]);
    }
}

/// `out = k · src` limb-wise with a carry chain, `k` a CONSENSUS CONSTANT (the fee multiplier). The top
/// carry is constrained to zero, so the scaled value provably fits its block.
pub fn push_scale(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, src: usize, out: usize, carry: usize, n: usize, k: u64) {
    let radix = Ea4::from(Fa4::from_u64(1 << BITS_PER_LIMB));
    let kf = Ea4::from(Fa4::from_u64(k));
    for i in 0..n {
        let cin = if i == 0 { Ea4::ZERO } else { local[carry + i - 1] };
        cs.push(local[src + i] * kf + cin - local[out + i] - local[carry + i] * radix);
    }
    cs.push(local[carry + n - 1]); // no carry out of the top limb
}

/// `s = a + b` limb-wise, carries BOOLEAN, no carry out of the top limb.
pub fn push_add(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: usize, b: usize, s: usize, carry: usize, n: usize) {
    let radix = Ea4::from(Fa4::from_u64(1 << BITS_PER_LIMB));
    for i in 0..n {
        let cin = if i == 0 { Ea4::ZERO } else { local[carry + i - 1] };
        let cout = local[carry + i];
        cs.push(local[a + i] + local[b + i] + cin - local[s + i] - cout * radix);
        cs.push(cout * (cout - Ea4::ONE));
    }
    cs.push(local[carry + n - 1]);
}

/// `d = a − b` limb-wise with BOOLEAN borrows. The top borrow is constrained to ZERO, which IS the
/// in-circuit proof that `a ≥ b` — used twice, and both uses are load-bearing safety properties:
/// `y ≥ dy` (the pool can actually pay the trader) and `k' ≥ k` (the curve invariant itself).
pub fn push_sub(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: usize, b: usize, d: usize, borrow: usize, n: usize) {
    let radix = Ea4::from(Fa4::from_u64(1 << BITS_PER_LIMB));
    for i in 0..n {
        let bin = if i == 0 { Ea4::ZERO } else { local[borrow + i - 1] };
        let bout = local[borrow + i];
        cs.push(local[a + i] - local[b + i] - bin - local[d + i] + bout * radix);
        cs.push(bout * (bout - Ea4::ONE));
    }
    cs.push(local[borrow + n - 1]); // no borrow out of the top limb ⇒ a ≥ b
}

/// `p = a · b` schoolbook over 8-bit limbs (see the module doc for the field-safety argument).
#[allow(clippy::too_many_arguments)]
pub fn push_mul(
    cs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_>,
    a: usize,
    na: usize,
    b: usize,
    nb: usize,
    p: usize,
    np: usize,
    carry: usize,
) {
    let radix = Ea4::from(Fa4::from_u64(1 << BITS_PER_LIMB));
    for k in 0..np {
        let mut acc = Ea4::ZERO;
        for i in 0..na {
            if k < i {
                continue;
            }
            let j = k - i;
            if j < nb {
                acc += local[a + i] * local[b + j];
            }
        }
        let cin = if k == 0 { Ea4::ZERO } else { local[carry + k - 1] };
        cs.push(acc + cin - local[p + k] - local[carry + k] * radix);
    }
    cs.push(local[carry + np - 1]); // the product fits its block
}

/// Tie a commitment block's 16-bit value limbs to the SAME number other constraints used, held elsewhere
/// as 8-bit limbs: `v16_i = limb8_{2i} + 256·limb8_{2i+1}`. Limb positions above the 8-bit block's width
/// are pinned to ZERO, so a prover cannot commit to a larger number than the one it proved a relation
/// for. This join is what makes an opening and an invariant speak about one value; degree 1. The 16-limb
/// width is `confidential_solvency::N_LIMB16` itself — the same constant its commit-open fold walks.
/// `v16` is the CALLER's column index of the first 16-bit value limb (layout-free, unlike the retired
/// AMM AIR's version which hard-wired its own commit-open block offset).
pub fn push_limb_join(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, v16: usize, a8: usize, n8: usize) {
    let radix = Ea4::from(Fa4::from_u64(1 << BITS_PER_LIMB));
    for i in 0..N_LIMB16 {
        let (lo, hi) = (2 * i, 2 * i + 1);
        let mut want = Ea4::ZERO;
        if lo < n8 {
            want += local[a8 + lo];
        }
        if hi < n8 {
            want += local[a8 + hi] * radix;
        }
        cs.push(local[v16 + i] - want);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The masked-shift class, pinned at the new home: a shift ≥ 128 on u128 silently masks to
    /// `shift % 128`, which turned limb 17 of a 144-bit decomposition into garbage while every refusal
    /// gate stayed green. `limbs8` must return ZERO for out-of-range limbs, at any requested width.
    #[test]
    fn limbs8_high_limbs_are_zero_not_masked_shift_garbage() {
        let v = u128::MAX;
        let l = limbs8(v, 20);
        for (i, limb) in l.iter().enumerate() {
            if i < 16 {
                assert_eq!(*limb, 0xFF, "limb {i} of u128::MAX");
            } else {
                assert_eq!(*limb, 0, "limb {i} must be ZERO past 128 bits, never a masked re-read");
            }
        }
    }

    /// Limb multiplication must agree withinteger arithmetic wherever the integers themselves fit.
    #[test]
    fn mul_limbs_matches_integer_products_in_range() {
        for (a, b) in [(0u128, 0u128), (1, 1), (255, 255), (65_535, 4_294_967_295), (1 << 40, (1 << 30) + 7)] {
            let al = limbs8(a, L80);
            let bl = limbs8(b, L64);
            let (prod, _carries) = mul_limbs(&al, &bl, L144).expect("in-range product");
            let expect = limbs8(a * b, L144);
            assert_eq!(prod, expect, "{a} × {b}");
        }
    }

    /// `sub_limbs` is the ≥ gadget: it returns Some exactly when a ≥ b, and the difference re-composes.
    #[test]
    fn sub_limbs_is_the_ge_comparison_and_recomposes() {
        let a = limbs8(1_000_000_007, L64);
        let b = limbs8(999_999_999, L64);
        let (d, _borrows) = sub_limbs(&a, &b, L64).expect("a ≥ b must decompose");
        assert_eq!(d, limbs8(8, L64), "difference recomposes");
        assert!(sub_limbs(&b, &a, L64).is_none(), "a < b must refuse, never wrap");
        let eq = sub_limbs(&a, &a, L64).expect("equality is ≥");
        assert_eq!(eq.0, limbs8(0, L64));
    }
}

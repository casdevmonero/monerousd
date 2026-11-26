// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ THE PRODUCTION POSEIDON2 ON THE SSA ROW, AS MULTIPLY-ADDS (A-F114 2b, lane speed5, 2026-11-22;
//! docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md "2b's binding").
//!
//! The SSA row's permutation block is `COMMITTED_AIR_SEED`'s Poseidon2, but the chain's note and nullifier hashes
//! (`poseidon2_compress::compress`, the member leg's `leaf_commit`) use the PRODUCTION constants (`REC_DECIDER_SEED`). A
//! spend wrapper needs one or two of those hashes, so rather than widen the universal row (which every child verification
//! evaluates in circuit, and so every merge would pay for), this emits the production permutation as ordinary
//! multiply-adds, paid only by a program that calls it.
//!
//! EXACT BY CONSTRUCTION: the round constants are `pow_pq_air::production_constants()`, and the two linear layers are
//! READ off Plonky3's own `GenericPoseidon2LinearLayersKoalaBear` by applying each to the unit vectors (the matrices it
//! multiplies by), so no constant is retyped here. Pin `p1` checks the emitted permutation against the native `compress`.
//! AI RESISTANT: (a) — every operation is a constrained multiply-add of the SSA row; a value off the permutation fails the
//! row's own law.
//! SCALE: a fixed operation count a permutation (measured by p1), no term in anything.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::ssa::{Builder, Ext, WIDTH};

struct Layers {
    external: [[Fa4; WIDTH]; WIDTH],
    internal: [[Fa4; WIDTH]; WIDTH],
}

fn layers() -> &'static Layers {
    static L: std::sync::OnceLock<Layers> = std::sync::OnceLock::new();
    L.get_or_init(|| {
        let mut external = [[Fa4::ZERO; WIDTH]; WIDTH];
        let mut internal = [[Fa4::ZERO; WIDTH]; WIDTH];
        for j in 0..WIDTH {
            let mut ce = [KoalaBear::ZERO; WIDTH];
            ce[j] = KoalaBear::ONE;
            let mut ci = ce;
            GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut ce);
            GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut ci);
            for i in 0..WIDTH {
                external[i][j] = ce[i];
                internal[i][j] = ci[i];
            }
        }
        Layers { external, internal }
    })
}

/// `M·x` for a fixed matrix, as multiply-adds by constants.
fn matmul(b: &mut Builder, m: &[[Fa4; WIDTH]; WIDTH], x: &[Ext; WIDTH]) -> [Ext; WIDTH] {
    core::array::from_fn(|i| {
        let mut acc = Ext::ZERO;
        for j in 0..WIDTH {
            let k = m[i][j];
            if k != Fa4::ZERO {
                acc = b.mul_k_add(x[j], Ea4::from(k), acc);
            }
        }
        acc
    })
}

/// KoalaBear's S-box, `x^3`.
fn sbox(b: &mut Builder, x: Ext) -> Ext {
    let x2 = b.mul(x, x);
    b.mul(x2, x)
}

fn add_const(b: &mut Builder, x: Ext, c: Fa4) -> Ext {
    if c == Fa4::ZERO {
        return x;
    }
    let k = b.konst_ext(Ea4::from(c));
    b.add(x, k)
}

/// The production Poseidon2 permutation of `inp` (base-field lanes held as extension values), every step constrained.
pub fn production_perm(b: &mut Builder, inp: [Ext; WIDTH]) -> [Ext; WIDTH] {
    let rc = usdm_decider::pow_pq_air::production_constants();
    let l = layers();
    let mut s = matmul(b, &l.external, &inp);
    for round in &rc.beginning_full_round_constants {
        for i in 0..WIDTH {
            let t = add_const(b, s[i], round[i]);
            s[i] = sbox(b, t);
        }
        s = matmul(b, &l.external, &s);
    }
    for &c in &rc.partial_round_constants {
        let t = add_const(b, s[0], c);
        s[0] = sbox(b, t);
        s = matmul(b, &l.internal, &s);
    }
    for round in &rc.ending_full_round_constants {
        for i in 0..WIDTH {
            let t = add_const(b, s[i], round[i]);
            s[i] = sbox(b, t);
        }
        s = matmul(b, &l.external, &s);
    }
    s
}

/// `poseidon2_compress::compress(left, right)` in circuit: the first eight lanes of the production permutation of
/// `left ‖ right`.
pub fn production_compress(b: &mut Builder, left: [Ext; 8], right: [Ext; 8]) -> [Ext; 8] {
    let inp: [Ext; WIDTH] = core::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] });
    let out = production_perm(b, inp);
    core::array::from_fn(|i| out[i])
}

// TWO-PARTY-REVIEWED: a pure function compared against the native permutation every node and wallet runs (`compress`);
// its second party is whichever program calls it, pinned where that program is.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField32;

    /// ⭐ P1: the emitted permutation IS the chain's `compress` (two inputs), the builder's own values satisfy every law,
    /// and the operation count is measured.
    #[test]
    fn p1_the_emitted_permutation_is_the_chains_compress() {
        for seed in [1u64, 77] {
            let l: usdm_decider::poseidon2_compress::Digest = core::array::from_fn(|i| (seed * 1_000_003 + i as u64 * 97) % 2_130_706_433);
            let r: usdm_decider::poseidon2_compress::Digest = core::array::from_fn(|i| (seed * 7_919 + i as u64 * 31 + 5) % 2_130_706_433);
            let want = usdm_decider::poseidon2_compress::compress(&l, &r);
            let mut b = Builder::new();
            let la: [Ext; 8] = core::array::from_fn(|i| b.load_ext(Ea4::from(Fa4::from_u64(l[i]))));
            let ra: [Ext; 8] = core::array::from_fn(|i| b.load_ext(Ea4::from(Fa4::from_u64(r[i]))));
            let before = b.ops.len();
            let out = production_compress(&mut b, la, ra);
            let got: Vec<u64> = out.iter().map(|e| u64::from(b.val(e.0[0]).as_canonical_u32())).collect();
            assert_eq!(got, want.to_vec(), "the emitted permutation is the production compress");
            assert!(b.mismatch.is_none(), "every law holds on the honest values");
            eprintln!("[p1] one production permutation: {} operations", b.ops.len() - before);
        }
    }
}

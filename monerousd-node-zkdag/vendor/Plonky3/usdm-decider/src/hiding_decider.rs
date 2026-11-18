// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! Decider-side HVZK-WHIR hiding entries (#135), in the decider's KoalaBear field.
//!
//! Consumes the `p3-whir` HVZK API (`HidingWhirProver` / `prove_hvzk` / `hvzk_verifier` /
//! `verify_hvzk`, Construction 6.3 of eprint 2026/391) so the rec-block prover can blind its
//! out-of-domain answers + sumcheck round images — the Four-Pillars `is_zk()` privacy path.
//! These are the KoalaBear-typed produce/verify entry points the decider wires into
//! `pqspend_rec_block_prove`; the whir crate proves the generic API sound (honest-accept +
//! forged-reject), this module proves it holds in the decider's actual field.

use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_whir::pcs::hiding::{
    HidingWhirProver, ReedSolomonZkEncoding, ZkPrefixProver, ZkVerifier, hvzk_verifier,
};
use rand::rngs::SmallRng;

/// Decider field (matches the `a4_pcs_whir` KoalaBear config in `circuit.rs`).
pub type Fa4 = KoalaBear;
pub type Ea4 = BinomialExtensionField<Fa4, 4>;
pub type Perm16 = Poseidon2KoalaBear<16>;
pub type SpongeHash = PaddingFreeSponge<Perm16, 16, 8, 8>;
pub type CompressHash = TruncatedPermutation<Perm16, 2, 8, 16>;
pub type Chl = DuplexChallenger<Fa4, Perm16, 16, 8>;
type Packed = <Fa4 as Field>::Packing;
pub type Mmcs16 = MerkleTreeHidingMmcs<Packed, Packed, SpongeHash, CompressHash, SmallRng, 2, 8, 8>;
pub type Dft16 = Radix2DFTSmallBatch<Fa4>;
pub type Enc16 = ReedSolomonZkEncoding<Fa4, Dft16>;

/// Build the decider's Reed-Solomon zero-knowledge mask code. `t` = query count (privacy
/// parameter), `ell_zk` = mask message length (Lemma 6.4 requires `ell_zk >= 2`).
#[must_use]
pub fn decider_mask_encoding(t: usize, ell_zk: usize) -> Enc16 {
    let m = (ell_zk + t).next_power_of_two();
    Enc16::new(t, ell_zk, m, Dft16::default())
}

/// Build the decider's HVZK-WHIR hiding prover over the rec-block `tables` (one `Table` per
/// aggregated PqSpend AIR, each a `Vec` of `2^n`-evaluation trace columns), with the mask
/// encoding bundled in. The caller records its opening/virtual claims on the returned prover
/// (in lockstep with the verifier), then finishes via `p3_whir::pcs::hiding::prove_hvzk` to
/// obtain the mask commitments.
#[must_use]
pub fn build_decider_hiding_prover(
    tables: Vec<Vec<Vec<Fa4>>>,
    folding_factor: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
) -> ZkPrefixProver<Fa4, Ea4, Enc16, Mmcs16> {
    HidingWhirProver::new(encoding).build_prover::<Fa4, Ea4, _>(tables, folding_factor, mmcs)
}

/// Build the matching decider HVZK-WHIR verifier from the per-table `(n_vars, width)` shapes.
/// `shapes` MUST match the `tables` given to `build_decider_hiding_prover` (one entry per AIR).
#[must_use]
pub fn build_decider_hiding_verifier(shapes: &[(usize, usize)]) -> ZkVerifier<Fa4, Ea4> {
    hvzk_verifier::<Fa4, Ea4>(shapes)
}

#[cfg(test)]
mod tests {
    use super::{
        Chl, CompressHash, Ea4, Enc16, Fa4, Mmcs16, Perm16, SpongeHash, build_decider_hiding_prover,
        build_decider_hiding_verifier, decider_mask_encoding,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_whir::pcs::hiding::{ZkSumcheckData, prove_hvzk, verify_hvzk};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    /// Honest HVZK-WHIR proof verifies + a forged evaluation claim is rejected, in the
    /// decider's KoalaBear field. Proves the whir HVZK API composes here (Four-Pillars
    /// adversarial tamper test).
    fn roundtrip(forge: bool) -> bool {
        let seed = 0u64;
        let (ell_zk, folding_factor, n_vars, pow_bits, t) = (4usize, 3usize, 8usize, 4usize, 2usize);

        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let n = 1usize << n_vars;
        // Two AIR tables of two trace columns each — the multi-table/multi-column rec-block shape.
        let c0: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let c1: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let c2: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let c3: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let shapes = [(n_vars, 2usize), (n_vars, 2usize)];

        let mut prover = build_decider_hiding_prover(
            vec![vec![c0, c1], vec![c2, c3]],
            folding_factor,
            mmcs,
            encoding,
        );
        let mut verifier = build_decider_hiding_verifier(&shapes);

        let mut pch = Chl::new(perm.clone());
        let mut vch = Chl::new(perm);

        let openings = prover.eval(0, &[0], &mut pch);
        verifier.add_claim(0, &[0], &openings, &mut vch);

        let mut eval = prover.add_virtual_eval(&mut pch);
        if forge {
            eval += Ea4::ONE;
        }
        verifier.add_virtual_eval(eval, &mut vch);

        let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let (mask_commits, prover_rand) =
            prove_hvzk(prover, &mut zk_data, pow_bits, &mut pch, &mut prover_rng);

        match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
            verifier,
            &zk_data,
            &mask_commits,
            ell_zk,
            folding_factor,
            pow_bits,
            &mut vch,
        ) {
            Some(vpoint) => prover_rand == vpoint,
            None => false,
        }
    }

    #[test]
    fn decider_hvzk_accepts_honest_and_rejects_forged_claim() {
        assert!(roundtrip(false), "honest decider HVZK-WHIR proof must verify");
        assert!(!roundtrip(true), "forged evaluation claim must be rejected");
    }

    /// #135 explicit-point opening (`eval_at` / `add_claim_at`): commit a table, open a column at an
    /// ARBITRARY multilinear point `r` (independent per-variable challenges — NOT a tensor point
    /// `expand_from_univariate(ζ)`), run the masked HVZK sumcheck, and verify. This is the binding
    /// primitive the light-decider AIR zerocheck needs: the zerocheck folds to an arbitrary `r`, and
    /// the committed columns are opened AT THAT `r` so the residual column claims are proven against
    /// the WHIR commitment. Honest proof verifies; a forged opening at `r` is rejected (soundness).
    fn roundtrip_eval_at(forge: bool) -> bool {
        use p3_challenger::FieldChallenger;
        use p3_multilinear_util::point::Point;

        let seed = 0u64;
        let (ell_zk, folding_factor, n_vars, pow_bits) = (4usize, 3usize, 8usize, 4usize);

        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(2usize, ell_zk);

        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let n = 1usize << n_vars;
        let c0: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let c1: Vec<Fa4> = (0..n).map(|_| data_rng.random()).collect();
        let shapes = [(n_vars, 2usize)];

        let mut prover =
            build_decider_hiding_prover(vec![vec![c0, c1]], folding_factor, mmcs, encoding);
        let mut verifier = build_decider_hiding_verifier(&shapes);

        let mut pch = Chl::new(perm.clone());
        let mut vch = Chl::new(perm);

        // Draw an ARBITRARY multilinear point `r` (n_vars independent challenges) from BOTH
        // transcripts identically — this is exactly how the zerocheck fold point is shared.
        let r_p: Vec<Ea4> = (0..n_vars).map(|_| pch.sample_algebra_element()).collect();
        let point_p = Point::new(r_p);
        let mut openings = prover.eval_at(0, &[0, 1], &point_p, &mut pch);

        let r_v: Vec<Ea4> = (0..n_vars).map(|_| vch.sample_algebra_element()).collect();
        let point_v = Point::new(r_v);
        if forge {
            openings[0] += Ea4::ONE; // tamper the opened value at r
        }
        verifier.add_claim_at(0, &[0, 1], &openings, &point_v, &mut vch);

        // The protocol's virtual OOD eval, mirrored honestly on both sides.
        let eval = prover.add_virtual_eval(&mut pch);
        verifier.add_virtual_eval(eval, &mut vch);

        let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let (mask_commits, prover_rand) =
            prove_hvzk(prover, &mut zk_data, pow_bits, &mut pch, &mut prover_rng);

        match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
            verifier,
            &zk_data,
            &mask_commits,
            ell_zk,
            folding_factor,
            pow_bits,
            &mut vch,
        ) {
            Some(vpoint) => prover_rand == vpoint,
            None => false,
        }
    }

    #[test]
    fn eval_at_arbitrary_point_binds_honest_accepts_forged_rejects() {
        assert!(
            roundtrip_eval_at(false),
            "honest arbitrary-point (eval_at) opening must verify"
        );
        assert!(
            !roundtrip_eval_at(true),
            "forged arbitrary-point opening must be rejected"
        );
    }
}

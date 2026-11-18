//! HVZK-WHIR hiding path (MonerousD original, task #135).
//!
//! Wires the crate `p3_sumcheck`'s honest-verifier zero-knowledge sumcheck
//! (`sumcheck::zk`, Construction 6.3 of eprint 2026/391) into the WHIR PCS so the
//! PUBLISHED proof leaks nothing about the committed message — the Four-Pillars
//! `is_zk()` privacy requirement for using WHIR as the MonerousD decider PCS.
//!
//! The plain WHIR sumcheck (`SuffixProver`) is NON-private: every round-polynomial
//! coefficient and every out-of-domain answer is an affine function of the secret
//! witness. HVZK requires the PREFIX-binding layout (`PrefixProver`) blinded by `k`
//! mask polynomials, one per fold round (`ZkPrefixProver`). This module builds that
//! blinded prover in the WHIR crate's own field / MMCS / encoding types — the piece
//! that existed in `sumcheck::zk` but was never constructed from WHIR.
//!
//! Field constraints (Lemma 6.4, checked at `ZkPrefixProver` entry): base-field
//! characteristic != 2, mask message length `ell_zk` >= 2.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use p3_zk_codes::ZkEncoding;
use rand::Rng;
use rand::distr::{Distribution, StandardUniform};

use crate::sumcheck::layout::{Layout, PrefixProver, Table, TableShape, Witness};
use p3_multilinear_util::poly::Poly;

// Re-export the decider-facing HVZK-WHIR API surface so a consumer (the pqpool decider)
// needs only depend on `p3-whir` to drive the hiding path end to end.
pub use crate::sumcheck::zk::{MaskOracle, ZkPrefixProver, ZkSumcheckData, ZkVerifier};
pub use p3_zk_codes::reed_solomon::ReedSolomonZkEncoding;

/// Build the HVZK-WHIR prover over the PREFIX-binding layout for a single-column
/// witness of `2^n` evaluations, blinded by the zero-knowledge sumcheck overlay.
///
/// `evals.len()` must be a power of two. `folding_factor` is the WHIR round-0 fold
/// width; `encoding` is the zero-knowledge mask code (e.g. `ReedSolomonZkEncoding`);
/// `mmcs` commits each encoded mask. The returned prover, when driven by the WHIR
/// fold loop, produces mask oracles that make the round polynomials + OOD answers
/// simulatable without the witness (honest-verifier zero-knowledge).
#[must_use]
pub fn hvzk_prefix_prover<F, EF, Enc, M>(
    tables: Vec<Vec<Vec<F>>>,
    folding_factor: usize,
    encoding: Enc,
    mmcs: M,
) -> ZkPrefixProver<F, EF, Enc, M>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Enc: ZkEncoding<F>,
    M: Mmcs<F>,
{
    // One `Table` per AIR (the rec-block aggregates several PqSpend AIRs), each holding all its
    // trace-column polynomials, interleaved into the stacked layout the inner prefix prover
    // expects (mirrors the proven zk::test_helpers path, generalized to the full AIR/column set).
    let tbls: Vec<_> = tables
        .into_iter()
        .map(|cols| Table::new(cols.into_iter().map(Poly::new).collect()))
        .collect();
    let witness: Witness<F> = Witness::new_interleaved(tbls, folding_factor);

    // Prefix-binding inner prover + HVZK mask overlay (Construction 6.3).
    let inner = PrefixProver::<F, EF>::from_witness(witness);
    ZkPrefixProver::new(inner, encoding, mmcs)
}

/// Build the matching HVZK-WHIR verifier for the given per-table `(n_vars, width)` shapes —
/// one entry per AIR/table, MUST match the tables passed to [`hvzk_prefix_prover`] (a shape
/// mismatch is rejected). The verifier replays the masked sumcheck transcript and reconstructs
/// the dropped (blinded) round coefficients, so it accepts an honest proof and rejects any
/// tampered claim / mask commitment.
#[must_use]
pub fn hvzk_verifier<F, EF>(shapes: &[(usize, usize)]) -> ZkVerifier<F, EF>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
{
    let table_shapes: Vec<_> = shapes
        .iter()
        .map(|&(n_vars, width)| TableShape::new(n_vars, width))
        .collect();
    ZkVerifier::<F, EF>::new(&table_shapes)
}

/// Prover side of the HVZK-WHIR masked sumcheck (#135). Runs the mask-blinded sumcheck
/// and returns the mask-code commitments (to store in `WhirProof::hvzk_mask_commits`)
/// plus the fold randomness. Consumes the prover. The adapter's `open` calls this on the
/// `hiding` path instead of the plain, message-revealing sumcheck.
#[must_use]
pub fn prove_hvzk<F, EF, Enc, M, R, Ch>(
    prover: ZkPrefixProver<F, EF, Enc, M>,
    zk_data: &mut ZkSumcheckData<F, EF>,
    pow_bits: usize,
    challenger: &mut Ch,
    rng: &mut R,
) -> (Vec<M::Commitment>, Vec<EF>)
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Enc: ZkEncoding<F>,
    Enc::Codeword: Matrix<F>,
    M: Mmcs<F>,
    R: Rng,
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<M::Commitment>,
    StandardUniform: Distribution<F>,
{
    let (_residual, randomness, mask_oracles) =
        prover.into_sumcheck(zk_data, pow_bits, challenger, rng);
    let mask_commits = mask_oracles.iter().map(|(c, _)| c.clone()).collect();
    (mask_commits, randomness.iter().copied().collect())
}

/// Verifier side of the HVZK-WHIR masked sumcheck (#135). Returns `Some(fold_randomness)`
/// when the masked proof verifies, `None` when it is rejected (a tampered claim, mask
/// commitment, or shape). The adapter's `verify` calls this on the `hiding` path.
#[must_use]
pub fn verify_hvzk<F, EF, M, Ch>(
    verifier: ZkVerifier<F, EF>,
    zk_data: &ZkSumcheckData<F, EF>,
    mask_commits: &[M::Commitment],
    ell_zk: usize,
    folding_factor: usize,
    pow_bits: usize,
    challenger: &mut Ch,
) -> Option<Vec<EF>>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    M: Mmcs<F>,
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<M::Commitment>,
{
    verifier
        .into_sumcheck::<M, _>(zk_data, mask_commits, ell_zk, folding_factor, pow_bits, challenger)
        .ok()
        .map(|(point, _target)| point.iter().copied().collect())
}

/// Capture variant of [`verify_hvzk`]: same masked-sumcheck replay, but ALSO returns the per-round target
/// chain `[target_0, …, target_folding]`. The cross-sender recursion uses this to lift a REAL carrier's
/// opening transcript into the in-circuit `WhirOpeningRoundConstraint` (the opening-row witness = the mask
/// wires from `zk_data`, the folding-point challenges, and this target chain). Returns
/// `(folding_point_challenges, target_chain)` or `None` on any opening mismatch (fail-closed).
pub fn verify_hvzk_capture<F, EF, M, Ch>(
    verifier: ZkVerifier<F, EF>,
    zk_data: &ZkSumcheckData<F, EF>,
    mask_commits: &[M::Commitment],
    ell_zk: usize,
    folding_factor: usize,
    pow_bits: usize,
    challenger: &mut Ch,
) -> Option<(Vec<EF>, Vec<EF>)>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    M: Mmcs<F>,
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<M::Commitment>,
{
    verifier
        .into_sumcheck_capture::<M, _>(zk_data, mask_commits, ell_zk, folding_factor, pow_bits, challenger)
        .ok()
        .map(|(point, _target, chain)| (point.iter().copied().collect(), chain))
}

/// Hiding-WHIR prover context (#135): bundles the zero-knowledge mask ENCODING that the
/// generic `WhirProver` adapter has no type slot for. The produce-side of the decider
/// constructs this with a `ReedSolomonZkEncoding`, then calls [`HidingWhirProver::prove_masks`]
/// to run the HVZK masked sumcheck and obtain the mask-code commitments to store in
/// `WhirProof::hvzk_mask_commits` (which `adapter::verify` binds to the transcript).
pub struct HidingWhirProver<Enc> {
    encoding: Enc,
}

impl<Enc> HidingWhirProver<Enc> {
    /// Bind the mask encoding for this hiding prover.
    pub const fn new(encoding: Enc) -> Self {
        Self { encoding }
    }

    /// Build the HVZK prefix prover for a witness of one-or-more `2^n`-evaluation columns, with
    /// this context's mask encoding bundled in. The caller records opening/virtual claims on the
    /// returned prover (interactively, in lockstep with the verifier), then finishes via
    /// [`prove_hvzk`] to get the mask commitments to store in `WhirProof::hvzk_mask_commits`. This
    /// is the produce-side counterpart to `adapter::verify`'s mask-commit observe.
    #[must_use]
    pub fn build_prover<F, EF, M>(
        self,
        tables: Vec<Vec<Vec<F>>>,
        folding_factor: usize,
        mmcs: M,
    ) -> ZkPrefixProver<F, EF, Enc, M>
    where
        F: TwoAdicField + Ord,
        EF: ExtensionField<F> + TwoAdicField,
        Enc: ZkEncoding<F>,
        M: Mmcs<F>,
    {
        hvzk_prefix_prover::<F, EF, Enc, M>(tables, folding_factor, self.encoding, mmcs)
    }
}

#[cfg(test)]
mod tests {
    use super::{HidingWhirProver, hvzk_verifier, prove_hvzk, verify_hvzk};
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_zk_codes::reed_solomon::ReedSolomonZkEncoding;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use crate::sumcheck::zk::ZkSumcheckData;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
    type PackedF = <F as Field>::Packing;
    type MyMmcs = MerkleTreeMmcs<PackedF, PackedF, MyHash, MyCompress, 2, 8>;
    type MyDft = Radix2DFTSmallBatch<F>;

    /// One HVZK-WHIR prover -> verifier roundtrip through the production
    /// `hvzk_prefix_prover` + `hvzk_verifier`. When `forge` is set, the virtual
    /// evaluation claim handed to the verifier is corrupted. Returns `true` iff the
    /// verifier ACCEPTS (Ok AND the parallel challengers stayed in lockstep).
    fn roundtrip(forge: bool) -> bool {
        let seed = 0u64;
        let (ell_zk, folding_factor, n_vars, pow_bits, t) = (4usize, 3usize, 8usize, 4usize, 2usize);

        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm::new_from_rng_128(&mut perm_rng);
        let mmcs = MyMmcs::new(MyHash::new(perm.clone()), MyCompress::new(perm.clone()), 0);
        let m = (ell_zk + t).next_power_of_two();
        let encoding = ReedSolomonZkEncoding::<F, MyDft>::new(t, ell_zk, m, MyDft::default());

        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let evals: Vec<F> = (0..(1usize << n_vars)).map(|_| data_rng.random()).collect();

        // Drive the produce-side context: bundle the encoding, build the HVZK prover over the
        // witness columns (here a single column; the pqpool decider test exercises multi-column).
        let mut prover = HidingWhirProver::new(encoding)
            .build_prover::<F, EF, _>(Vec::from([Vec::from([evals])]), folding_factor, mmcs);
        let mut verifier = hvzk_verifier::<F, EF>(&[(n_vars, 1)]);

        let mut pch = MyChallenger::new(perm.clone());
        let mut vch = MyChallenger::new(perm);

        // Concrete opening claim (kept in lockstep on both challengers).
        let openings = prover.eval(0, &[0], &mut pch);
        verifier.add_claim(0, &[0], &openings, &mut vch);

        // Virtual evaluation claim — the tamper point.
        let mut eval = prover.add_virtual_eval(&mut pch);
        if forge {
            eval += EF::ONE;
        }
        verifier.add_virtual_eval(eval, &mut vch);

        // Masked HVZK sumcheck through the production entry points. `prove_hvzk` draws the
        // per-round masks + runs the code-switch; `verify_hvzk` replays the transcript and
        // reconstructs the blinded round coefficients.
        let mut zk_data = ZkSumcheckData::<F, EF>::default();
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let (mask_commits, prover_rand) =
            prove_hvzk(prover, &mut zk_data, pow_bits, &mut pch, &mut prover_rng);

        match verify_hvzk::<F, EF, MyMmcs, _>(
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

    /// Completeness + soundness: the honest HVZK-WHIR proof verifies, and a forged
    /// evaluation claim is rejected (Four-Pillars adversarial tamper test).
    #[test]
    fn hvzk_whir_accepts_honest_and_rejects_forged_claim() {
        assert!(roundtrip(false), "honest HVZK-WHIR proof must verify");
        assert!(!roundtrip(true), "forged evaluation claim must be rejected");
    }
}

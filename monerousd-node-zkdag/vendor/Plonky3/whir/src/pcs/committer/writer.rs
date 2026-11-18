use alloc::sync::Arc;

use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
#[cfg(test)]
use p3_matrix::Matrix;
#[cfg(test)]
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::extension::FlatMatrixView;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::commit::CodewordRows;
use tracing::info_span;

use crate::sumcheck::strategy::VariableOrder;

/// Encodes and commits a folded extension-field polynomial.
///
/// This is used after each non-final WHIR folding round. The layout mirrors
/// the base-field path, but the DFT runs over extension-field values and the
/// commitment is made through an extension MMCS that views extension rows as
/// base-field data for the underlying Merkle tree.
///
/// ⭐ DB-371 — STREAMED, exactly as the base commitment is (`p3_sumcheck::commit::commit_base`): the codeword is hashed
/// sub-coset by sub-coset from the folded coefficients and the prover data opens from a [`CodewordRows`] that
/// recomputes a queried row. The coefficients are COPIED (`poly` is the sumcheck's running polynomial and keeps folding
/// after this call). MEASURED 2026-10-03 at the certificate's round 1 (2^23 `Ea4` coefficients, folding 4, rate 1/16):
/// the dense commit took the process from 130 MB to 2,980 MB held — a 2 GiB padded codeword — and set the genesis
/// certificate's peak inside `open_w`. Byte identity: `db371_a_streamed_extension_commitment_equals_the_dense_one`.
/// Cons: one copy of the folded coefficients (`2^n` EF elements, 128 MiB at round 1, 1/16 of the codeword it replaces);
/// an opened row is recomputed (`2^n` EF·F multiply-adds); the fold is `2^(ρ+s)` passes over the coefficients.
#[allow(clippy::type_complexity)]
pub(crate) fn commit_extension<F, EF, Dft, MT>(
    order: VariableOrder,
    dft: &Dft,
    extension_mmcs: &ExtensionMmcs<F, EF, MT>,
    poly: &Poly<EF>,
    folding: usize,
    inv_rate: usize,
) -> (
    MT::Commitment,
    <MT as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, CodewordRows<F, EF>>>,
)
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    MT: Mmcs<F>,
{
    assert!(inv_rate.is_power_of_two(), "a WHIR round's inverse rate is a power of two");
    let rows = CodewordRows::<F, EF>::new(Arc::new(poly.clone()), order, folding, inv_rate.trailing_zeros() as usize);
    let sub_cosets = rows.sub_cosets();
    info_span!("commit_streamed (extension)", sub_cosets).in_scope(|| {
        extension_mmcs.commit_streamed(rows, sub_cosets, |rows, j| ext_coset_rows(dft, rows, j))
    })
}

/// Sub-coset `j` of a folded round's EXTENSION codeword: the coset transform of the folded coefficients. The ONE
/// derivation the round's commit hashes ([`commit_extension`]) and its opening keeps the queried rows from
/// (`CodewordRows::prime_rows`, SPEED R4) — one function, so an opened row is a committed row by construction.
pub(crate) fn ext_coset_rows<F, EF, Dft>(dft: &Dft, rows: &CodewordRows<F, EF>, j: usize) -> p3_matrix::dense::RowMajorMatrix<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let (folded, shift) = rows.sub_coset_input(j);
    dft.coset_dft_algebra_batch(folded, shift)
}

/// The DENSE encoding [`commit_extension`] replaced — kept only as its byte-identity reference.
#[cfg(test)]
pub(crate) fn dense_extension_codeword<F, EF, Dft>(
    order: VariableOrder,
    dft: &Dft,
    poly: &Poly<EF>,
    folding: usize,
    inv_rate: usize,
) -> DenseMatrix<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let num_variables = poly.num_variables();
    let height = inv_rate * (1 << (num_variables - folding));

    let encoded = match order {
        VariableOrder::Prefix => {
            let padded = info_span!("transpose & pad").in_scope(|| {
                let mut mat =
                    RowMajorMatrixView::new(poly.as_slice(), 1 << (num_variables - folding))
                        .transpose();
                mat.pad_to_height(height, EF::ZERO);
                mat
            });
            info_span!("dft", height = padded.height(), width = padded.width())
                .in_scope(|| dft.dft_algebra_batch(padded).to_row_major_matrix())
        }
        VariableOrder::Suffix => {
            let padded = info_span!("pad").in_scope(|| {
                let mut mat = RowMajorMatrix::new(poly.as_slice().to_vec(), 1 << folding);
                mat.pad_to_height(height, EF::ZERO);
                mat
            });
            info_span!("dft", height = padded.height(), width = padded.width())
                .in_scope(|| dft.dft_algebra_batch(padded).to_row_major_matrix())
        }
    };
    encoded
}

#[cfg(test)]
mod db371_tests {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type H = PaddingFreeSponge<Perm, 16, 8, 8>;
    type C = TruncatedPermutation<Perm, 2, 8, 16>;
    type MT = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, 2, 8>;
    type HMT = MerkleTreeHidingMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, SmallRng, 2, 8, 8>;

    /// ⭐ DB-371 BYTE-IDENTITY, EXTENSION ROUNDS — for both orders, several (variables, folding, inverse rate) shapes and
    /// both the plain and the SALTED MMCS (the certificate's), the streamed [`commit_extension`] equals the dense
    /// encoding committed through `commit_matrix`: root, every opened row, every salt and every sibling. RED-first: a
    /// streamed commitment of a polynomial with one planted coefficient has a different root.
    #[test]
    fn db371_a_streamed_extension_commitment_equals_the_dense_one() {
        let mut rng = SmallRng::seed_from_u64(373);
        let perm = Perm::new_from_rng_128(&mut rng);
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut checked = 0;
        for order in [VariableOrder::Prefix, VariableOrder::Suffix] {
            for (n, folding, inv_rate) in [(8usize, 2usize, 2usize), (9, 3, 8), (7, 4, 16), (6, 1, 1), (5, 4, 2)] {
                let poly = Poly::new((0..1 << n).map(|_| rng.random::<EF>()).collect());
                let dense = dense_extension_codeword::<F, EF, _>(order, &dft, &poly, folding, inv_rate);
                // plain
                let ext = ExtensionMmcs::<F, EF, MT>::new(MT::new(H::new(perm.clone()), C::new(perm.clone()), 0));
                let (want_root, want) = ext.commit_matrix(dense.clone());
                let (root, got) = commit_extension(order, &dft, &ext, &poly, folding, inv_rate);
                assert_eq!(root, want_root, "{order:?} n={n} f={folding} 1/{inv_rate}: root");
                // salted, two instances from one seed
                let salted = |seed| {
                    ExtensionMmcs::<F, EF, HMT>::new(HMT::new(H::new(perm.clone()), C::new(perm.clone()), 0, SmallRng::seed_from_u64(seed)))
                };
                let (sa, sb) = (salted(9), salted(9));
                let (s_want_root, s_want) = sa.commit_matrix(dense.clone());
                let (s_root, s_got) = commit_extension(order, &dft, &sb, &poly, folding, inv_rate);
                assert_eq!(s_root, s_want_root, "salted {order:?} n={n}: root");
                for i in 0..dense.height() {
                    let (w, g) = (ext.open_batch(i, &want), ext.open_batch(i, &got));
                    assert_eq!(g.opened_values, w.opened_values, "{order:?} n={n}: row {i}");
                    assert_eq!(g.opening_proof, w.opening_proof, "{order:?} n={n}: path {i}");
                    let (w, g) = (sa.open_batch(i, &s_want), sb.open_batch(i, &s_got));
                    assert_eq!(g.opened_values, w.opened_values, "salted {order:?} n={n}: row {i}");
                    assert_eq!(g.opening_proof, w.opening_proof, "salted {order:?} n={n}: salts/path {i}");
                    checked += 2;
                }
            }
        }
        // RED half: one planted coefficient moves the root (the comparisons above are not vacuous)
        let poly: Poly<EF> = Poly::new((0..1 << 8).map(|_| rng.random::<EF>()).collect());
        let mut planted = poly.as_slice().to_vec();
        planted[3] += EF::ONE;
        let ext = ExtensionMmcs::<F, EF, MT>::new(MT::new(H::new(perm.clone()), C::new(perm), 0));
        let (a, _) = commit_extension(VariableOrder::Prefix, &dft, &ext, &poly, 2, 2);
        let (b, _) = commit_extension(VariableOrder::Prefix, &dft, &ext, &Poly::new(planted), 2, 2);
        assert_ne!(a, b, "a planted coefficient went unnoticed");
        std::eprintln!("[db371] streamed extension == dense on {checked} openings (both orders, 5 shapes, plain + salted)");
    }
}

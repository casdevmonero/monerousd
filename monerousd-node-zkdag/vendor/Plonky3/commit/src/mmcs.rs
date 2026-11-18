use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{Dimensions, Matrix};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A "Mixed Matrix Commitment Scheme" (MMCS) is a generalization of a vector commitment scheme.
///
/// It supports committing to matrices and then opening rows. It is also batch-oriented; one can commit
/// to a batch of matrices at once even if their widths and heights differ.
///
/// When a particular row index is opened, it is interpreted directly as a row index for matrices
/// with the largest height. For matrices with smaller heights, some bits of the row index are
/// removed (from the least-significant side) to get the effective row index. These semantics are
/// useful in the FRI protocol. See the documentation for `open_batch` for more details.
pub trait Mmcs<T: Send + Sync + Clone>: Clone {
    type ProverData<M>;
    type Commitment: Clone + Serialize + DeserializeOwned;
    type Proof: Clone + Serialize + DeserializeOwned;
    type Error: Debug;

    /// Commits to a batch of matrices at once and returns both the commitment and associated prover data.
    ///
    /// Each matrix in the batch may have different dimensions.
    ///
    /// # Parameters
    /// - `inputs`: A vector of matrices to commit to.
    ///
    /// # Returns
    /// A tuple `(commitment, prover_data)` where:
    /// - `commitment` is a compact representation of all matrix elements and will be sent to the verifier.
    /// - `prover_data` is auxiliary data used by the prover open the commitment.
    fn commit<M: Matrix<T>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>);

    /// Convenience method to commit to a single matrix.
    ///
    /// Internally wraps the matrix in a singleton vector and delegates to [`Self::commit`].
    ///
    /// # Parameters
    /// - `input`: The matrix to commit to.
    ///
    /// # Returns
    /// A tuple `(commitment, prover_data)` as in [`Self::commit`].
    fn commit_matrix<M: Matrix<T>>(&self, input: M) -> (Self::Commitment, Self::ProverData<M>) {
        self.commit(vec![input])
    }

    /// ⭐ DB-371 — commit ONE matrix `leaf` whose rows are supplied coset by coset, so the whole matrix is never
    /// resident while its leaves are hashed.
    ///
    /// `leaf.height()` rows split into `cosets` interleaved classes: row `i` is in coset `i % cosets`, and
    /// `coset_rows(&leaf, k)` returns coset `k`'s rows in order (its row `j` is row `k + cosets·j` of `leaf`). `leaf`
    /// is what the prover data OPENS from — typically a matrix that recomputes a queried row — and is handed to the
    /// closure so no part of it is copied to build a coset. The commitment and every opening equal
    /// `commit_matrix(leaf)`'s whenever `coset_rows` agrees with `leaf`.
    ///
    /// There is deliberately no default body: a default would have to hash through `leaf`'s rows, which for a
    /// recomputing matrix is one full evaluation per row — every implementation streams for real.
    fn commit_streamed<M: Matrix<T>>(
        &self,
        leaf: M,
        cosets: usize,
        coset_rows: impl FnMut(&M, usize) -> RowMajorMatrix<T>,
    ) -> (Self::Commitment, Self::ProverData<M>);

    /// ⭐ SPEED R4 (2026-11-10) — the rows of a commitment's ONE lazily-opened matrix that [`Self::open_batch`] at
    /// each of `indices` will read: the opened row itself and any row a dropped digest is recomputed from. A prover
    /// whose matrix recomputes a queried row derives these together before it takes the openings
    /// (`p3_sumcheck::commit::CodewordRows::prime_rows`): 16 passes over the coefficients where the per-row recompute
    /// made 1,032 at the block proofs' shape, with the same one-sub-coset working set the commit has.
    ///
    /// The default names nothing, which is always correct: every row is then recomputed on its own, as before. An
    /// implementation that holds its matrices (nothing lazy) keeps the default.
    /// cons: none — a list of `q · 2^dropped` indices; no stored state, no byte of any opening changes.
    fn rows_read_by_open<M: Matrix<T>>(&self, indices: &[usize], prover_data: &Self::ProverData<M>) -> Vec<usize> {
        let _ = (indices, prover_data);
        Vec::new()
    }

    /// Convenience method to commit to a single column vector, treated as a column matrix.
    ///
    /// Automatically wraps the vector into a column matrix using [`RowMajorMatrix::new_col`].
    ///
    /// # Parameters
    /// - `input`: A vector of field elements representing a single column.
    ///
    /// # Returns
    /// A tuple `(commitment, prover_data)` for the resulting 1-column matrix.
    fn commit_vec(&self, input: Vec<T>) -> (Self::Commitment, Self::ProverData<RowMajorMatrix<T>>)
    where
        T: Clone + Send + Sync,
    {
        self.commit_matrix(RowMajorMatrix::new_col(input))
    }

    /// Opens a specific row (identified by `index`) from each matrix in the batch.
    ///
    /// This function is designed to support batch opening semantics where matrices may have different heights.
    /// The given index is interpreted relative to the maximum matrix height; smaller matrices apply a
    /// bit-shift to extract the corresponding row.
    ///
    /// # Parameters
    /// - `index`: The global row index (relative to max height).
    /// - `prover_data`: Prover data returned from [`Self::commit`] or related methods.
    ///
    /// # Returns
    /// A [`BatchOpening`] containing the opened rows and the proof of their correctness.
    ///
    /// # Opening Index Semantics
    /// For each matrix `M[i]`, the row index used is:
    /// ```text
    /// j = index >> (log2_ceil(max_height) - log2_ceil(M[i].height))
    /// ```
    fn open_batch<M: Matrix<T>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<T, Self>;

    /// Returns references to all matrices originally committed to in the batch.
    ///
    /// This allows access to the underlying data for inspection or additional logic.
    ///
    /// # Parameters
    /// - `prover_data`: The prover data returned by [`Self::commit`].
    ///
    /// # Returns
    /// A vector of references to the committed matrices.
    fn get_matrices<'a, M: Matrix<T>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M>;

    /// Returns the height (number of rows) of each matrix in the batch.
    ///
    /// This is a utility method derived from [`Self::get_matrices`].
    ///
    /// # Parameters
    /// - `prover_data`: The prover data returned by [`Self::commit`].
    ///
    /// # Returns
    /// A vector containing the height of each committed matrix.
    fn get_matrix_heights<M: Matrix<T>>(&self, prover_data: &Self::ProverData<M>) -> Vec<usize> {
        self.get_matrices(prover_data)
            .iter()
            .map(|matrix| matrix.height())
            .collect()
    }

    /// Get the largest height of any committed matrix.
    ///
    /// # Panics
    /// This may panic if there are no committed matrices.
    fn get_max_height<M: Matrix<T>>(&self, prover_data: &Self::ProverData<M>) -> usize {
        self.get_matrix_heights(prover_data)
            .into_iter()
            .max()
            .unwrap_or_else(|| panic!("No committed matrices?"))
    }

    /// Verifies a batch opening at a specific row index against the original commitment.
    ///
    /// This is the verifier-side analogue of [`Self::open_batch`]. The verifier receives:
    /// - The original commitment.
    /// - Dimensions of each matrix being opened (in the same order as originally committed).
    /// - The global index used for opening (interpreted as in [`Self::open_batch`]).
    /// - A [`BatchOpeningRef`] containing the claimed opened values and the proof.
    ///
    /// # Parameters
    /// - `commit`: The original commitment.
    /// - `dimensions`: Dimensions of the committed matrices, in order.
    /// - `index`: The global row index that was opened.
    /// - `batch_opening`: A reference to the values and proof to verify.
    ///
    /// # Returns
    /// `Ok(())` if the opening is valid; otherwise returns a verification error.
    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, T, Self>,
    ) -> Result<(), Self::Error>;
}

/// A Batched opening proof.
///
/// Contains a collection of opened values at a Merkle proof for those openings.
///
/// Primarily used by the prover.
#[derive(Serialize, Deserialize, Clone)]
// Enable Serialize/Deserialize whenever T supports it.
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct BatchOpening<T: Send + Sync + Clone, InputMmcs: Mmcs<T>> {
    /// The opened row values from each matrix in the batch.
    /// Each inner vector corresponds to one matrix.
    pub opened_values: Vec<Vec<T>>,
    /// The proof showing the values are valid openings.
    pub opening_proof: InputMmcs::Proof,
}

impl<T: Send + Sync + Clone, InputMmcs: Mmcs<T>> BatchOpening<T, InputMmcs> {
    /// Creates a new batch opening proof.
    #[inline]
    pub const fn new(opened_values: Vec<Vec<T>>, opening_proof: InputMmcs::Proof) -> Self {
        Self {
            opened_values,
            opening_proof,
        }
    }

    /// Unpacks the batch opening proof into its components.
    #[inline]
    pub fn unpack(self) -> (Vec<Vec<T>>, InputMmcs::Proof) {
        (self.opened_values, self.opening_proof)
    }
}

/// A reference to a batched opening proof.
///
/// Contains references to a collection of claimed opening values and a Merkle proof for those values.
///
/// Primarily used by the verifier.
#[derive(Copy, Clone)]
pub struct BatchOpeningRef<'a, T: Send + Sync + Clone, InputMmcs: Mmcs<T>> {
    /// Reference to the opened row values, as slices of base elements.
    pub opened_values: &'a [Vec<T>],
    /// Reference to the proof object used for verification.
    pub opening_proof: &'a InputMmcs::Proof,
}

impl<'a, T: Send + Sync + Clone, InputMmcs: Mmcs<T>> BatchOpeningRef<'a, T, InputMmcs> {
    /// Creates a new batch opening proof.
    #[inline]
    pub const fn new(opened_values: &'a [Vec<T>], opening_proof: &'a InputMmcs::Proof) -> Self {
        Self {
            opened_values,
            opening_proof,
        }
    }

    /// Unpacks the batch opening proof into its components.
    #[inline]
    pub const fn unpack(&self) -> (&'a [Vec<T>], &'a InputMmcs::Proof) {
        (self.opened_values, self.opening_proof)
    }
}

impl<'a, T: Send + Sync + Clone, InputMmcs: Mmcs<T>> From<&'a BatchOpening<T, InputMmcs>>
    for BatchOpeningRef<'a, T, InputMmcs>
{
    #[inline]
    fn from(batch_opening: &'a BatchOpening<T, InputMmcs>) -> Self {
        Self::new(&batch_opening.opened_values, &batch_opening.opening_proof)
    }
}

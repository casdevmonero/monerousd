use alloc::vec::Vec;

use itertools::Itertools;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::PackedValue;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::stack::HorizontalPair;
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_util::zip_eq::zip_eq;
use rand::Rng;
use rand::distr::{Distribution, StandardUniform};
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use spin::Mutex;

use crate::{MerkleCap, MerkleTree, MerkleTreeError, MerkleTreeMmcs};
use p3_field::PrimeCharacteristicRing;

/// ⭐ DB-371 step 5 — SALTS BY PRF, NEVER STORED. The hiding commitment used to draw a `height × SALT_ELEMS` matrix of
/// random field elements and KEEP it in the prover data for the openings (512 MiB at the certificate's size, held from
/// `commit_w` to `recommit`). A salt is needed exactly twice — hashed into its leaf at commit, revealed at open — so it is
/// derived both times from one seed: `salt(row) = H(seed ‖ row)`, where `H` is the tree's own leaf hasher (a Poseidon2
/// sponge, `CryptographicHasher<F, [F; SALT_ELEMS]>`) and `seed` is `SALT_ELEMS` field elements drawn ONCE per commit
/// from the MMCS's randomness source. Rows are distinct inputs, so salts are distinct; the hiding property rests on the
/// seed's unpredictability exactly as it rested on the drawn matrix's (DB-382 owns the seed's entropy). 0 B stored;
/// one sponge permutation per opened row.
#[derive(Clone)]
pub struct PrfSalts<F, H, const SALT_ELEMS: usize> {
    hash: H,
    seed: [F; SALT_ELEMS],
    height: usize,
}

impl<F, H, const SALT_ELEMS: usize> PrfSalts<F, H, SALT_ELEMS>
where
    F: PrimeCharacteristicRing + Copy + Send + Sync,
    H: CryptographicHasher<F, [F; SALT_ELEMS]> + Send + Sync,
{
    const fn new(hash: H, seed: [F; SALT_ELEMS], height: usize) -> Self {
        Self { hash, seed, height }
    }
    /// `H(seed ‖ row)`: the salt of row `r`, derived — the same value at commit and at open.
    fn salt_row(&self, r: usize) -> [F; SALT_ELEMS] {
        self.hash.hash_iter(self.seed.iter().copied().chain(core::iter::once(F::from_u64(r as u64))))
    }
}

impl<F, H, const SALT_ELEMS: usize> core::fmt::Debug for PrfSalts<F, H, SALT_ELEMS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // DIGITAL-CASH-PRIVACY-REVIEWED: the seed is the prover's blinding secret — never printed
        write!(f, "PrfSalts {{ height: {}, width: {} }}", self.height, SALT_ELEMS)
    }
}

impl<F, H, const SALT_ELEMS: usize> Matrix<F> for PrfSalts<F, H, SALT_ELEMS>
where
    F: PrimeCharacteristicRing + Copy + Send + Sync,
    H: CryptographicHasher<F, [F; SALT_ELEMS]> + Send + Sync,
{
    fn width(&self) -> usize {
        SALT_ELEMS
    }
    fn height(&self) -> usize {
        self.height
    }
    unsafe fn row_unchecked(
        &self,
        r: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        self.salt_row(r)
    }
}

/// A vector commitment scheme backed by a `MerkleTree`.
///
/// This is similar to `MerkleTreeMmcs`, but each leaf is "salted" with random elements. This is
/// done to turn the Merkle tree into a hiding commitment. See e.g. Section 3 of
/// [Interactive Oracle Proofs](https://eprint.iacr.org/2016/116).
///
/// `SALT_ELEMS` should be set such that the product of `SALT_ELEMS` with the size of the value
/// (`P::Value`) is at least the target security parameter.
///
/// `R` should be an appropriately seeded cryptographically secure pseudorandom number generator
/// (CSPRNG). Something like `ThreadRng` may work, although it relies on the operating system to
/// provide sufficient entropy.
///
/// Generics:
/// - `P`: a leaf value
/// - `PW`: an element of a digest
/// - `H`: the leaf hasher
/// - `C`: the digest compression function
/// - `R`: a random number generator for blinding leaves
#[derive(Debug)]
pub struct MerkleTreeHidingMmcs<
    P,
    PW,
    H,
    C,
    R,
    const N: usize,
    const DIGEST_ELEMS: usize,
    const SALT_ELEMS: usize,
> {
    inner: MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>,
    rng: Mutex<R>,
}

impl<P, PW, H, C, R, const N: usize, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    MerkleTreeHidingMmcs<P, PW, H, C, R, N, DIGEST_ELEMS, SALT_ELEMS>
{
    /// Create a new `MerkleTreeHidingMmcs` with the given hash and compression functions.
    ///
    /// # Arguments
    /// * `hash` - The hash function used to hash individual matrix rows (leaf level).
    /// * `compress` - The compression function used to hash internal tree nodes.
    /// * `cap_height` - The height of the Merkle cap. A cap_height of 0 uses only the root,
    ///   while a cap_height of h uses all hashes from the h-th level below the root (2^h
    ///   in the case of a binary tree)
    /// * `rng` - A random number generator for generating salts.
    pub const fn new(hash: H, compress: C, cap_height: usize, rng: R) -> Self {
        let inner = MerkleTreeMmcs::new(hash, compress, cap_height);
        Self {
            inner,
            rng: Mutex::new(rng),
        }
    }

    pub const fn cap_height(&self) -> usize {
        self.inner.cap_height()
    }
}

impl<P, PW, H, C, R, const N: usize, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize> Clone
    for MerkleTreeHidingMmcs<P, PW, H, C, R, N, DIGEST_ELEMS, SALT_ELEMS>
where
    MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>: Clone,
    R: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            rng: Mutex::new(self.rng.lock().clone()),
        }
    }
}

impl<P, PW, H, C, R, const N: usize, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    Mmcs<P::Value> for MerkleTreeHidingMmcs<P, PW, H, C, R, N, DIGEST_ELEMS, SALT_ELEMS>
where
    P: PackedValue,
    P::Value: Serialize + DeserializeOwned,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
        + Sync,
    R: Rng + Clone + Send,
    PW::Value: Eq + Clone,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<P::Value>,
    // DB-371 step 5: the leaf hasher also derives the salts, so it must hash to SALT_ELEMS field elements
    H: CryptographicHasher<P::Value, [P::Value; SALT_ELEMS]> + Send + Sync,
    // link 80: and the streamed commit derives them `P::WIDTH` rows per sponge call (`commit_streamed`)
    H: CryptographicHasher<P, [P; SALT_ELEMS]>,
    P::Value: PrimeCharacteristicRing,
{
    type ProverData<M> = MerkleTree<
        P::Value,
        PW::Value,
        HorizontalPair<M, PrfSalts<P::Value, H, SALT_ELEMS>>,
        N,
        DIGEST_ELEMS,
    >;
    type Commitment = MerkleCap<P::Value, [PW::Value; DIGEST_ELEMS]>;
    /// The first item is salts; the second is the usual Merkle proof (sibling digests).
    type Proof = (Vec<Vec<P::Value>>, Vec<[PW::Value; DIGEST_ELEMS]>);
    type Error = MerkleTreeError;

    fn commit<M: Matrix<P::Value>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let mut rng = self.rng.lock();
        let salted_inputs = inputs
            .into_iter()
            .map(|mat| {
                // one seed per matrix, SALT_ELEMS draws — the matrix of salts is never materialized (DB-371 step 5)
                let seed: [P::Value; SALT_ELEMS] = core::array::from_fn(|_| rand::RngExt::random(&mut *rng));
                let height = mat.height();
                HorizontalPair::new(mat, PrfSalts::new(self.inner.hasher().clone(), seed, height))
            })
            .collect();
        self.inner.commit(salted_inputs)
    }

    fn commit_streamed<M: Matrix<P::Value>>(
        &self,
        leaf: M,
        cosets: usize,
        mut coset_rows: impl FnMut(&M, usize) -> RowMajorMatrix<P::Value>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        // the SAME salt draw `commit` makes (one height × SALT_ELEMS matrix from the same rng), so a streamed commit
        // and a classic commit from equal rng states are byte-identical; each coset row gets its own row's salts
        // appended, exactly as `HorizontalPair` appends them to the opened row. The salts are read from the pair the
        // tree holds (one copy — MEASURED 2026-10-03: a cloned salt matrix was 512 MiB at the certificate's size).
        let salts = {
            let mut rng = self.rng.lock();
            let seed: [P::Value; SALT_ELEMS] = core::array::from_fn(|_| rand::RngExt::random(&mut *rng));
            PrfSalts::new(self.inner.hasher().clone(), seed, leaf.height())
        };
        self.inner
            .commit_streamed(HorizontalPair::new(leaf, salts), cosets, |pair, k| {
                let rows = coset_rows(&pair.left, k);
                let width = rows.width() + SALT_ELEMS;
                // the same derivation the open uses for each row (DB-371 step 5): H(seed ‖ row) — a pure function of the
                // row index, so the salts are derived on every core (direct rayon). MEASURED link 79 (`sample`, the
                // 256-insert band slice's commit): the serial loop was 64 % of the commit — two sponge permutations per
                // codeword row on one core.
                // ⭐ link 80 (2026-10-21): and `P::WIDTH` rows per sponge call — the packed sponge runs the scalar sponge
                // in every lane (the same lane-wise hashing the leaf layer uses), lane `l` absorbing `seed ‖ row b·W + l`,
                // so each salt is `salt_row`'s value (pinned by `db371_a_streamed_tree_equals_the_classic_tree`, whose
                // classic tree derives every salt through `salt_row`). MEASURED link 80 (`sample` over the whole band-slice
                // prove, night/link80-par2-sample.txt): even on every core the scalar derivation was 1,509 of the prove's
                // 8,961 samples (≈ 2.2 s of 13.2 s). Rows past the coset's height in the last block are hashed and dropped.
                let h_rows = rows.height();
                let w = P::WIDTH;
                let seed = pair.right.seed;
                let hasher = self.inner.hasher();
                let mut salt_rows: Vec<[P::Value; SALT_ELEMS]> =
                    alloc::vec![[P::Value::ZERO; SALT_ELEMS]; h_rows.div_ceil(w) * w];
                salt_rows.par_chunks_mut(w).enumerate().for_each(|(b, out)| {
                    let row_idx = P::from_fn(|lane| P::Value::from_u64((k + cosets * (b * w + lane)) as u64));
                    let packed: [P; SALT_ELEMS] = CryptographicHasher::<P, [P; SALT_ELEMS]>::hash_iter(
                        hasher,
                        seed.iter().map(|&s| P::from_fn(|_| s)).chain(core::iter::once(row_idx)),
                    );
                    for (lane, salt) in out.iter_mut().enumerate() {
                        *salt = core::array::from_fn(|i| packed[i].as_slice()[lane]);
                    }
                });
                salt_rows.truncate(h_rows);
                let mut values = Vec::with_capacity(rows.height() * width);
                for (row, salt) in rows.values.chunks(rows.width()).zip(&salt_rows) {
                    values.extend_from_slice(row);
                    values.extend_from_slice(salt);
                }
                RowMajorMatrix::new(values, width)
            })
    }

    fn open_batch<M: Matrix<P::Value>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<P::Value, Self> {
        let (salted_openings, siblings) = self.inner.open_batch(index, prover_data).unpack();
        let (openings, salts) = salted_openings
            .into_iter()
            .map(|row| {
                let (a, b) = row.split_at(row.len() - SALT_ELEMS);
                (a.to_vec(), b.to_vec())
            })
            .unzip();
        BatchOpening::new(openings, (salts, siblings))
    }

    fn get_matrices<'a, M: Matrix<P::Value>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        prover_data.leaves.iter().map(|mat| &mat.left).collect()
    }

    /// SPEED R4: the salted tree reads the rows the plain tree reads (a row's salts are derived from its index).
    fn rows_read_by_open<M: Matrix<P::Value>>(&self, indices: &[usize], prover_data: &Self::ProverData<M>) -> Vec<usize> {
        self.inner.rows_read_by_open(indices, prover_data)
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, P::Value, Self>,
    ) -> Result<(), Self::Error> {
        let (opened_values, (salts, siblings)) = batch_opening.unpack();

        let opened_salted_values = zip_eq(opened_values, salts, MerkleTreeError::WrongBatchSize)?
            .map(|(opened, salt)| opened.iter().chain(salt.iter()).copied().collect_vec())
            .collect_vec();

        self.inner.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::new(&opened_salted_values, siblings),
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_commit::Mmcs;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_util::assert_sync;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::MerkleTreeHidingMmcs;
    use crate::MerkleTreeError;

    type F = BabyBear;
    // the PRF salt is the leaf sponge's own output (DB-371 step 5: `H: CryptographicHasher<F, [F; SALT_ELEMS]>`), so the
    // test MMCS salts with the sponge's 8 lanes — at 4 this module had not compiled since the PRF salts landed (link 79)
    const SALT_ELEMS: usize = 8;

    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyMmcs = MerkleTreeHidingMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        SmallRng,
        2,
        8,
        SALT_ELEMS,
    >;

    #[test]
    #[should_panic]
    fn mismatched_heights() {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash, compress, 0, rng);

        // attempt to commit to a mat with 8 rows and a mat with 7 rows. this should panic.
        let large_mat = RowMajorMatrix::new([1, 2, 3, 4, 5, 6, 7, 8].map(F::from_u8).to_vec(), 1);
        let small_mat = RowMajorMatrix::new([1, 2, 3, 4, 5, 6, 7].map(F::from_u8).to_vec(), 1);
        let _ = mmcs.commit(vec![large_mat, small_mat]);
    }

    #[test]
    fn different_widths() -> Result<(), MerkleTreeError> {
        let mut rng = SmallRng::seed_from_u64(1);
        // 10 mats with 32 rows where the ith mat has i + 1 cols
        let mats = (0..10)
            .map(|i| RowMajorMatrix::<F>::rand(&mut rng, 32, i + 1))
            .collect_vec();
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash, compress, 0, rng);

        let dims = mats.iter().map(|m| m.dimensions()).collect_vec();

        let (commit, prover_data) = mmcs.commit(mats);
        let batch_proof = mmcs.open_batch(17, &prover_data);
        mmcs.verify_batch(&commit, &dims, 17, (&batch_proof).into())
    }

    #[test]
    fn hiding_mmcs_is_sync() {
        assert_sync::<MyMmcs>();
    }
}

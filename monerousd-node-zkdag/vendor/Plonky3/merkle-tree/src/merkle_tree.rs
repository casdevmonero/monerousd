use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::cmp::Reverse;
use core::marker::PhantomData;

use itertools::Itertools;
use p3_field::PackedValue;
use p3_matrix::Matrix;
// ⛔ MEASURED 2026-09-28 19:08 (§M6-T): switching THIS import to `rayon::prelude::*` (direct rayon for the three
// layer-hashing loops, the shim's graph-wide feature still off) made the decider's committed prover return None on
// its first prove and turned the same anchor_set_membership pins red that the graph-wide feature had — the parallel
// tree is NOT the serial tree this crate's callers were pinned against, even though each chunk writes only its own
// digests. Reverted the same hour; the serial shim stays. Whoever parallelises this file next must first show the
// serial and parallel roots equal on the byte-identity pin (`usdm_decider::spartan_ccs::tests::
// a_parallel_prove_is_byte_identical_to_a_one_thread_prove`) and name the semantic difference.
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, Hash, MerkleCap, PseudoCompressionFunction};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// An N-ary Merkle tree whose leaves are vectors of matrix rows.
///
/// * `F` – scalar element type inside each matrix row.
/// * `W` – scalar element type of every digest word.
/// * `M` – matrix type. Must implement [`Matrix<F>`].
/// * `N` – arity of the compression function.
/// * `DIGEST_ELEMS` – number of `W` words in one digest.
///
/// The tree is **balanced only at the digest layer**.
/// Leaf matrices may have arbitrary heights as long as any two heights
/// that round **up** to the same power-of-two are equal.
///
/// Use [`Self::root`] to fetch the final digest once the tree is built.
///
/// This generally shouldn't be used directly. If you're using a Merkle tree as an MMCS,
/// see `MerkleTreeMmcs`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleTree<F, W, M, const N: usize, const DIGEST_ELEMS: usize> {
    /// All leaf matrices in insertion order.
    ///
    /// Each matrix contributes rows to one or more digest layers, depending on its height.
    /// Specifically, only the tallest matrices are included in the first digest layer,
    /// while shorter matrices are injected into higher digest layers at positions determined
    /// by their padded heights.
    ///
    /// This vector is retained only for inspection or re-opening of the tree; it is not used
    /// after construction time.
    pub(crate) leaves: Vec<M>,

    /// All intermediate digest layers, index 0 being the first layer above
    /// the leaves and the last layer containing exactly one root digest.
    ///
    /// Every inner vector holds contiguous digests `[left₀, right₀, left₁,
    /// right₁, …]`; higher layers refer to these by index.
    ///
    /// Serialization requires that `[W; DIGEST_ELEMS]` implements `Serialize` and
    /// `Deserialize`. This is automatically satisfied when `W` is a fixed-size type.
    #[serde(
        bound(serialize = "[W; DIGEST_ELEMS]: Serialize"),
        bound(deserialize = "[W; DIGEST_ELEMS]: Deserialize<'de>")
    )]
    pub(crate) digest_layers: Vec<Vec<[W; DIGEST_ELEMS]>>,

    /// The compression arity used at each tree level (transition from
    /// `digest_layers[i]` to `digest_layers[i+1]`).
    ///
    /// Each entry is either `N` (full N-ary step) as specified by the `N`
    /// parameter associated to the compression function, or `2` (binary step)
    /// when a matrix injection falls between N-ary levels.
    pub(crate) arity_schedule: Vec<usize>,

    /// ⭐ DB-371 step 6 (lane stable 2026-11-02) — how many of the LOWEST digest layers this tree no longer stores (their
    /// slots in `digest_layers` are empty). A dropped digest is recomputed on demand by [`Self::digest_at`] from the leaf
    /// rows (a lazy codeword recomputes a row) and the same compression, so every opening — values and sibling path — is
    /// byte-identical to the stored tree's. Set only on a ONE-matrix tree (`drop_low_layers`).
    #[serde(default)]
    pub(crate) low_dropped: usize,

    /// Zero-sized marker that binds the generic `F` but occupies no space.
    _phantom: PhantomData<F>,
}

impl<F: Clone + Send + Sync, W: Clone, M: Matrix<F>, const N: usize, const DIGEST_ELEMS: usize>
    MerkleTree<F, W, M, N, DIGEST_ELEMS>
{
    /// Build a tree from **one or more matrices**.
    ///
    /// * `h` – hashing function used on raw rows.
    /// * `c` – N-to-1 compression function used on digests.
    /// * `leaves` – matrices to commit to. Must be non-empty.
    ///
    /// Matrices do **not** need to have power-of-two heights. However, any two matrices
    /// whose heights **round up** to the same power-of-two must have **equal actual height**.
    /// This ensures proper balancing when folding digests layer-by-layer.
    ///
    /// All matrices are hashed row-by-row with `h`. The resulting digests are
    /// then folded upwards with `c` until a single root remains.
    ///
    /// # Panics
    /// * If `leaves` is empty.
    /// * If the packing widths of `P` and `PW` differ.
    /// * If two leaf heights *round up* to the same power-of-two but are not
    ///   equal (violates balancing rule).
    #[instrument(name = "build merkle tree", level = "debug", skip_all,
                 fields(dimensions = alloc::format!("{:?}", leaves.iter().map(|l| l.dimensions()).collect::<Vec<_>>())))]
    pub fn new<P, PW, H, C>(h: &H, c: &C, leaves: Vec<M>) -> Self
    where
        P: PackedValue<Value = F>,
        PW: PackedValue<Value = W>,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], N>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
            + Sync,
    {
        assert!(!leaves.is_empty(), "No matrices given?");
        const {
            assert!(N >= 2, "Arity N must be at least 2");
            assert!(N.is_power_of_two(), "Arity N must be a power of two");
            assert!(P::WIDTH == PW::WIDTH, "Packing widths must match");
        }

        let mut leaves_largest_first = leaves
            .iter()
            .sorted_by_key(|l| Reverse(l.height()))
            .peekable();

        // check height property
        assert!(
            leaves_largest_first
                .clone()
                .map(|m| m.height())
                .tuple_windows()
                .all(|(curr, next)| curr == next
                    || curr.next_power_of_two() != next.next_power_of_two()),
            "matrix heights that round up to the same power of two must be equal"
        );

        let max_height = leaves_largest_first.peek().unwrap().height();
        let leaf_height_npt = max_height.next_power_of_two();
        let tallest_matrices = leaves_largest_first
            .peeking_take_while(|m| m.height() == max_height)
            .collect_vec();

        let mut digest_layers = vec![first_digest_layer::<P, _, _, _, N, DIGEST_ELEMS>(
            h,
            &tallest_matrices,
        )];
        let mut arity_schedule = Vec::new();

        loop {
            let prev_layer = digest_layers.last().unwrap().as_slice();
            if prev_layer.len() <= 1 {
                break;
            }

            // Decide whether this level is a full N-ary step or a binary step.
            let step = select_arity_step::<N>(
                prev_layer.len(),
                leaf_height_npt,
                leaves_largest_first.clone().map(|m| m.height()),
            );

            let next_layer_len = (prev_layer.len() / step).next_power_of_two();

            // The matrices that get injected at this layer.
            let matrices_to_inject = leaves_largest_first
                .peeking_take_while(|m| m.height().next_power_of_two() == next_layer_len)
                .collect_vec();

            let next_digests = compress_and_inject::<P, _, _, _, _, N, DIGEST_ELEMS>(
                prev_layer,
                step,
                &matrices_to_inject,
                h,
                c,
            );
            arity_schedule.push(step);
            digest_layers.push(next_digests);
        }

        Self {
            leaves,
            digest_layers,
            arity_schedule,
            low_dropped: 0,
            _phantom: PhantomData,
        }
    }

    /// ⭐ DB-371 — build the SAME tree as [`Self::new`] for ONE matrix `leaf`, hashing its rows coset by coset so the
    /// full matrix never has to be resident while the leaves are hashed.
    ///
    /// `leaf.height()` rows split into `cosets` interleaved classes: row `i` belongs to coset `i % cosets`.
    /// `coset_rows(&leaf, k)` returns coset `k`'s rows in order (row `j` of it is row `k + cosets·j` of `leaf`); it is
    /// handed the leaf so a wrapper can read stored parts of it (the hiding MMCS's salts) without a second copy. Each
    /// coset is hashed with the tree's own leaf hasher and dropped before the next is asked for. The layers above the
    /// leaves are built exactly as `new` builds them for a single matrix. `leaf` is the matrix the tree OPENS from —
    /// a lazy matrix that recomputes a queried row is the point, so the full codeword is never held.
    ///
    /// The tree (root, every layer, every opening) is byte-identical to `new(h, c, vec![leaf])` whenever
    /// `coset_rows(k)` agrees with `leaf`'s rows — pinned by `db371_a_streamed_tree_equals_the_classic_tree`.
    pub fn new_streamed<P, PW, H, C, G>(h: &H, c: &C, leaf: M, cosets: usize, mut coset_rows: G) -> Self
    where
        P: PackedValue<Value = F>,
        PW: PackedValue<Value = W>,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], N>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
            + Sync,
        G: FnMut(&M, usize) -> p3_matrix::dense::RowMajorMatrix<F>,
        W: Default + Copy,
    {
        const {
            assert!(N >= 2, "Arity N must be at least 2");
            assert!(N.is_power_of_two(), "Arity N must be a power of two");
            assert!(P::WIDTH == PW::WIDTH, "Packing widths must match");
        }
        let height = leaf.height();
        assert!(height > 0, "an empty matrix has no tree");
        assert!(
            cosets.is_power_of_two() && height % cosets == 0,
            "cosets ({cosets}) must be a power of two dividing the height ({height})"
        );
        let default_digest = [W::default(); DIGEST_ELEMS];
        let mut first = vec![default_digest; padded_len(height, N)];
        for k in 0..cosets {
            let rows = coset_rows(&leaf, k);
            assert_eq!(rows.height(), height / cosets, "coset {k} has the wrong height");
            assert_eq!(rows.width(), leaf.width(), "coset {k} has the wrong width");
            // SPEED G2: the accelerator's digests when it answers (`crate::accel`), this crate's own pass otherwise.
            let digests = accel_leaves::<F, W, H, DIGEST_ELEMS>(h, &rows)
                .unwrap_or_else(|| streamed_par::leaf_digests::<P, PW, H, N, DIGEST_ELEMS>(h, &rows));
            for (j, d) in digests.into_iter().take(height / cosets).enumerate() {
                first[k + cosets * j] = d;
            }
            // `rows` (one coset of the codeword) is dropped here, before the next is computed
        }
        let leaf_height_npt = height.next_power_of_two();
        let mut digest_layers = vec![first];
        let mut arity_schedule = Vec::new();
        loop {
            let prev_layer = digest_layers.last().unwrap().as_slice();
            if prev_layer.len() <= 1 {
                break;
            }
            // one matrix: nothing is injected above the leaves, exactly as `new` decides for a single matrix
            let step = select_arity_step::<N>(prev_layer.len(), leaf_height_npt, core::iter::empty());
            // SPEED G2: the accelerator's layer when it answers (`crate::accel`), this crate's own pass otherwise.
            let next_digests = accel_compress::<W, C, N, DIGEST_ELEMS>(prev_layer, step, c)
                .unwrap_or_else(|| streamed_par::compress::<PW, _, N, DIGEST_ELEMS>(prev_layer, step, c));
            arity_schedule.push(step);
            digest_layers.push(next_digests);
        }
        Self {
            leaves: vec![leaf],
            digest_layers,
            arity_schedule,
            low_dropped: 0,
            _phantom: PhantomData,
        }
    }

    /// Return the root digest of the tree.
    #[must_use]
    pub fn root(&self) -> Hash<F, W, DIGEST_ELEMS>
    where
        W: Copy,
    {
        self.digest_layers.last().unwrap()[0].into()
    }

    /// Return the Merkle cap at the specified height from the root.
    ///
    /// A cap height of 0 returns just the root (1 element).
    /// A cap height of h returns `product(arity_schedule[layer_idx..])` elements,
    /// where each arity is either N or 2 depending on the tree layout.
    ///
    /// # Panics
    /// Panics if `cap_height` exceeds the tree depth.
    #[must_use]
    pub fn cap(&self, cap_height: usize) -> MerkleCap<F, [W; DIGEST_ELEMS]>
    where
        W: Clone,
    {
        let num_layers = self.digest_layers.len();
        assert!(
            cap_height < num_layers,
            "cap_height {} exceeds tree depth {}",
            cap_height,
            num_layers
        );

        let layer_idx = num_layers - 1 - cap_height;
        let layer = &self.digest_layers[layer_idx];

        let cap_len: usize = self.arity_schedule[layer_idx..].iter().product();
        let cap_len = cap_len.min(layer.len());

        MerkleCap::new(layer[..cap_len].to_vec())
    }

    #[must_use]
    pub const fn num_layers(&self) -> usize {
        self.digest_layers.len()
    }

    /// ⭐ DB-371 step 6 (lane stable 2026-11-02) — stop storing the lowest `k` digest layers of a ONE-matrix tree (a tree that
    /// injects shorter matrices above its leaves keeps every layer). The leaf layer is half of a binary tree's digests and
    /// the layer above it a quarter: `k = 2` keeps 25 % of the digest bytes. MEASURED (release-shape certificate profile under
    /// the node's allocator, stable/prof5.log): the witness commitment's tree is held from `commit_w` to `ood` and again
    /// from `recommit` through `open_w` (the profile's lifetime peak, 5,065 MB). The cap and every layer above `k` stay.
    /// cons: per opened index, the dropped siblings are recomputed — `2^k − 1` extra leaf rows (a lazy codeword row is
    /// `2^n` multiply-adds) and `2^k − 2` compressions; no byte of any opening, root or proof changes.
    pub fn drop_low_layers(&mut self, k: usize) {
        if self.leaves.len() != 1 {
            return;
        }
        let k = k.min(self.digest_layers.len().saturating_sub(1));
        for layer in self.digest_layers.iter_mut().take(k) {
            *layer = Vec::new();
        }
        self.low_dropped = k;
    }

    /// The digest at `(layer, i)`: stored, or — for a dropped layer — recomputed exactly as the build computed it: a leaf
    /// is `h` over its row, a parent `c` over its `arity_schedule` children padded with the default digest, and every
    /// position past a layer's unpadded length is the default digest the build left there.
    pub fn digest_at<H, C>(&self, h: &H, c: &C, layer: usize, i: usize) -> [W; DIGEST_ELEMS]
    where
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], N>,
        W: Default + Copy,
    {
        if layer >= self.low_dropped {
            return self.digest_layers[layer][i];
        }
        // the layer's unpadded length: the leaf height, then each padded predecessor divided by its step
        let mut actual = self.leaves[0].height();
        for l in 0..layer {
            actual = padded_len(actual, N) / self.arity_schedule[l];
        }
        if i >= actual {
            return [W::default(); DIGEST_ELEMS];
        }
        if layer == 0 {
            let row = self.leaves[0].row(i).expect("a row below the matrix height");
            return h.hash_iter(row);
        }
        let step = self.arity_schedule[layer - 1];
        let children: [[W; DIGEST_ELEMS]; N] =
            array::from_fn(|n| if n < step { self.digest_at(h, c, layer - 1, step * i + n) } else { [W::default(); DIGEST_ELEMS] });
        c.compress(children)
    }

    /// ⭐ SPEED R4 (2026-11-10) — the leaf rows the openings at `indices` READ from a ONE-matrix tree: each index's own
    /// row and, where low digest layers were dropped ([`Self::drop_low_layers`]), every row under its dropped siblings
    /// ([`Self::digest_at`] recomputes those digests from their rows). Together they are the whole block of leaves under
    /// the index's ancestor in the first STORED layer: `Π arity_schedule[..low_dropped]` consecutive rows, aligned.
    /// Sorted, without repeats, never past the matrix. Empty for a tree of several matrices (they are held, not lazy).
    /// What the answer is for: a lazy leaf matrix derives these rows together before the openings are taken
    /// (`p3_sumcheck::commit::CodewordRows::prime_rows`). An index this misses is still opened correctly, one lazy
    /// row at a time; a row named here that no opening reads costs its copy. cons: none (a list of `q · 2^dropped` indices).
    #[must_use]
    pub fn rows_read_by_open(&self, indices: &[usize]) -> Vec<usize> {
        if self.leaves.len() != 1 {
            return Vec::new();
        }
        let height = self.leaves[0].height();
        let block: usize = self.arity_schedule.iter().take(self.low_dropped).product::<usize>().max(1);
        let mut rows: Vec<usize> = indices
            .iter()
            .flat_map(|&i| {
                let start = (i / block) * block;
                start..start + block
            })
            .filter(|&r| r < height)
            .collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    /// The sibling digests of the opening at `index` (layers below `proof_levels`), in path order — the dropped ones
    /// recomputed SIDE BY SIDE (each is an independent leaf-row recompute), the stored ones read.
    pub fn sibling_path<H, C>(&self, h: &H, c: &C, index: usize, proof_levels: usize) -> Vec<[W; DIGEST_ELEMS]>
    where
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]> + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], N> + Sync,
        W: Default + Copy + Send + Sync,
    {
        let mut wanted: Vec<(usize, usize)> = Vec::new();
        let mut idx = index;
        for layer_idx in 0..proof_levels {
            let step = self.arity_schedule[layer_idx];
            let group_start = (idx / step) * step;
            let pos_in_group = idx % step;
            for k in 0..step {
                if k != pos_in_group {
                    wanted.push((layer_idx, group_start + k));
                }
            }
            idx /= step;
        }
        wanted.par_iter().map(|&(layer, pos)| self.digest_at(h, c, layer, pos)).collect()
    }
}

/// Select the compression arity for the current layer.
///
/// Returns `N` for a full N-ary step, or `2` for a binary bridge step when a
/// matrix injection must happen before the next N-ary target level.
pub(crate) fn select_arity_step<const N: usize>(
    curr_height_padded: usize,
    leaf_height_npt: usize,
    remaining_heights_tallest_first: impl Iterator<Item = usize>,
) -> usize {
    if curr_height_padded < N {
        return 2;
    }

    let n_ary_target = (curr_height_padded / N).next_power_of_two();
    let has_intermediate = remaining_heights_tallest_first
        .filter(|height| height.next_power_of_two() != leaf_height_npt)
        .any(|height| height.next_power_of_two() > n_ary_target);

    if has_intermediate { 2 } else { N }
}

/// Hash every row of the tallest matrices and build the first digest layer.
///
/// This function is responsible for creating the first layer of Merkle digests,
/// starting from raw rows of the tallest matrices. Each row is hashed using the
/// provided cryptographic hasher `h`. The result is a vector of digests that serve
/// as the base (leaf-level) nodes for the rest of the Merkle tree.
///
/// # Details
/// - We always return an *even number of digests* (except when height is 1), to
///   ensure even pairing at higher layers.
/// - Matrices are "vertically packed" to allow SIMD-friendly parallel hashing,
///   meaning rows can be processed in batches.
/// - If the total number of rows isn't a multiple of the SIMD packing width,
///   the final few rows are handled using a fallback scalar path.
///
/// # Arguments
/// - `h`: Reference to the cryptographic hasher.
/// - `tallest_matrices`: References to the tallest matrices (all must have same height).
///
/// # Returns
/// A vector of `[PW::Value; DIGEST_ELEMS]`, containing the digests of each row.
#[instrument(name = "first digest layer", level = "debug", skip_all)]
fn first_digest_layer<P, PW, H, M, const N: usize, const DIGEST_ELEMS: usize>(
    h: &H,
    tallest_matrices: &[&M],
) -> Vec<[PW::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    M: Matrix<P::Value>,
{
    // The number of rows to pack and hash together in one SIMD batch.
    let width = PW::WIDTH;

    // Get the height of the tallest matrices (they are guaranteed to be equal).
    let max_height = tallest_matrices[0].height();

    let max_height_padded = padded_len(max_height, N);

    // Prepare a default digest value to fill unused slots or padding.
    let default_digest = [PW::Value::default(); DIGEST_ELEMS];

    // Allocate the digest vector with padded size, initialized to default digest.
    let mut digests = vec![default_digest; max_height_padded];

    // Parallel loop: process complete batches of `width` rows at a time.
    digests[0..max_height]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            // Compute the starting row index for this chunk.
            let first_row = i * width;

            // Collect all vertically packed rows from each matrix at `first_row`.
            // These packed rows are then hashed together using `h`.
            let packed_digest: [PW; DIGEST_ELEMS] = h.hash_iter(
                tallest_matrices
                    .iter()
                    .flat_map(|m| m.vertically_packed_row(first_row)),
            );

            // Unpack the resulting packed digest into individual scalar digests.
            PW::unpack_into(&packed_digest, digests_chunk);
        });

    // Handle leftover rows that do not form a full SIMD batch (if any).
    // `digests` is padded to `max_height_padded`, so cap the slice at `max_height`
    // to leave the padding tail untouched.
    let leftover_start = (max_height / width) * width;
    for (offset, digest) in digests[leftover_start..max_height].iter_mut().enumerate() {
        let i = leftover_start + offset;
        unsafe {
            // Safety: i < max_height == matrix height.
            // Use `row_unchecked` to avoid bounds checks for performance.
            *digest = h.hash_iter(tallest_matrices.iter().flat_map(|m| m.row_unchecked(i)));
        }
    }

    // Return the final digest vector (now fully populated).
    digests
}

/// ⭐ link 79 (2026-10-21) — the STREAMED tree's leaf layer on DIRECT rayon (`MerkleTree::new_streamed` only; the classic
/// tree keeps the serial shim). A leaf digest is a pure function of its own row, so the coset's rows are hashed in blocks
/// on every core — each block through [`first_digest_layer`], the same packed-then-scalar hashing — and concatenated in
/// row order: byte-identical to one serial pass (pinned by `db371_a_streamed_tree_equals_the_classic_tree` against the
/// classic serial tree, and by the decider's one-thread-pool identity pin). MEASURED (`sample`, the 256-insert band
/// slice's commit): the serial leaf hashing was 18 % of the commit.
mod streamed_par {
    use alloc::vec::Vec;

    use p3_field::PackedValue;
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
    use p3_symmetric::CryptographicHasher;
    use rayon::prelude::*;

    /// Rows per parallel block: a multiple of every packing width (a rayon grain, not a protocol value — any block size
    /// gives the same digests, a row's digest never depends on its neighbours).
    const LEAF_BLOCK_ROWS: usize = 1 << 12;

    pub(super) fn leaf_digests<P, PW, H, const N: usize, const DIGEST_ELEMS: usize>(
        h: &H,
        rows: &RowMajorMatrix<P::Value>,
    ) -> Vec<[PW::Value; DIGEST_ELEMS]>
    where
        P: PackedValue,
        PW: PackedValue,
        H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
    {
        let width = rows.width;
        let blocks: Vec<Vec<[PW::Value; DIGEST_ELEMS]>> = rows
            .values
            .par_chunks(LEAF_BLOCK_ROWS * width)
            .map(|vals| {
                let n = vals.len() / width;
                let view = RowMajorMatrixView::new(vals, width);
                let mut d = super::first_digest_layer::<P, PW, H, _, N, DIGEST_ELEMS>(h, &[&view]);
                d.truncate(n); // the block's own rows; the tree pads the whole layer once
                d
            })
            .collect();
        blocks.concat()
    }

    /// ⭐ link 80 (2026-10-21) — the streamed tree's layers ABOVE the leaves on direct rayon: [`super::compress`] with
    /// its packed chunks on every core. A parent digest is a pure function of its own `step` children and each chunk
    /// writes only its own `P::WIDTH` parents, so the layer is byte-identical to the serial pass whatever the schedule
    /// (pinned as `leaf_digests` is). MEASURED (`sample`, link 79's parallel band-slice commit): these serial layers were
    /// 1,038 of the commit's samples — the largest single-threaded term left in it.
    pub(super) fn compress<P, C, const N: usize, const DIGEST_ELEMS: usize>(
        prev_layer: &[[P::Value; DIGEST_ELEMS]],
        step: usize,
        c: &C,
    ) -> Vec<[P::Value; DIGEST_ELEMS]>
    where
        P: PackedValue,
        C: p3_symmetric::PseudoCompressionFunction<[P::Value; DIGEST_ELEMS], N>
            + p3_symmetric::PseudoCompressionFunction<[P; DIGEST_ELEMS], N>
            + Sync,
    {
        let width = P::WIDTH;
        let next_len = prev_layer.len() / step;
        let next_len_padded = super::padded_len(next_len, N);

        let default_digest = [P::Value::default(); DIGEST_ELEMS];
        let mut next_digests = alloc::vec![default_digest; next_len_padded];

        next_digests[0..next_len / width * width]
            .par_chunks_exact_mut(width)
            .enumerate()
            .for_each(|(i, digests_chunk)| {
                let first_row = i * width;
                let default_packed: [P; DIGEST_ELEMS] = core::array::from_fn(|_| P::broadcast(P::Value::default()));
                let children: [[P; DIGEST_ELEMS]; N] = core::array::from_fn(|n| {
                    if n < step {
                        P::pack_columns_fn(|lane| prev_layer[step * (first_row + lane) + n])
                    } else {
                        default_packed
                    }
                });
                let packed_digest = c.compress(children);
                P::unpack_into(&packed_digest, digests_chunk);
            });

        for i in (next_len / width * width)..next_len {
            let children: [_; N] = core::array::from_fn(|n| {
                if n < step {
                    prev_layer[step * i + n]
                } else {
                    default_digest
                }
            });
            next_digests[i] = c.compress(children);
        }

        next_digests
    }
}

/// Fold one digest layer into the next and, when present, mix in rows
/// taken from smaller matrices.
///
/// `step` is the grouping size for this level (either `N` for a full N-ary
/// step or `2` for a binary step when a matrix injection falls between
/// N-ary layers). Groups of `step` children are taken from `prev_layer`,
/// padded to `N` inputs with the default digest, then compressed with the
/// N-to-1 compression function.
fn compress_and_inject<P, PW, H, C, M, const N: usize, const DIGEST_ELEMS: usize>(
    prev_layer: &[[PW::Value; DIGEST_ELEMS]],
    step: usize,
    matrices_to_inject: &[&M],
    h: &H,
    c: &C,
) -> Vec<[PW::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
        + Sync,
    M: Matrix<P::Value>,
{
    if matrices_to_inject.is_empty() {
        return compress::<PW, _, N, DIGEST_ELEMS>(prev_layer, step, c);
    }

    let width = PW::WIDTH;
    let next_len = matrices_to_inject[0].height();
    let raw_next = prev_layer.len() / step;
    let next_len_padded = padded_len(raw_next, N);

    let default_digest = [PW::Value::default(); DIGEST_ELEMS];
    let mut next_digests = vec![default_digest; next_len_padded];

    next_digests[0..next_len]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            let first_row = i * width;
            let default_packed: [PW; DIGEST_ELEMS] =
                array::from_fn(|_| PW::broadcast(PW::Value::default()));

            let children: [[PW; DIGEST_ELEMS]; N] = array::from_fn(|n| {
                if n < step {
                    PW::pack_columns_fn(|lane| prev_layer[step * (first_row + lane) + n])
                } else {
                    default_packed
                }
            });
            let mut packed_digest = c.compress(children);

            let tallest_digest = h.hash_iter(
                matrices_to_inject
                    .iter()
                    .flat_map(|m| m.vertically_packed_row(first_row)),
            );
            let inject_inputs: [[PW; DIGEST_ELEMS]; N] = array::from_fn(|n| {
                if n == 0 {
                    packed_digest
                } else if n == 1 {
                    tallest_digest
                } else {
                    default_packed
                }
            });
            packed_digest = c.compress(inject_inputs);
            PW::unpack_into(&packed_digest, digests_chunk);
        });

    for i in (next_len / width * width)..next_len {
        let children: [_; N] = array::from_fn(|n| {
            if n < step {
                prev_layer[step * i + n]
            } else {
                default_digest
            }
        });
        let digest = c.compress(children);
        let rows_digest =
            unsafe { h.hash_iter(matrices_to_inject.iter().flat_map(|m| m.row_unchecked(i))) };
        let inject_inputs: [_; N] = array::from_fn(|n| {
            if n == 0 {
                digest
            } else if n == 1 {
                rows_digest
            } else {
                default_digest
            }
        });
        next_digests[i] = c.compress(inject_inputs);
    }

    for i in next_len..raw_next {
        let children: [_; N] = array::from_fn(|n| {
            if n < step {
                prev_layer[step * i + n]
            } else {
                default_digest
            }
        });
        let digest = c.compress(children);
        let inject_inputs: [_; N] =
            array::from_fn(|n| if n == 0 { digest } else { default_digest });
        next_digests[i] = c.compress(inject_inputs);
    }

    next_digests
}

/// Compute the padded output length for a compression step.
///
/// The output layer must be large enough for the *next* compression step
/// to form complete groups. There are three cases:
///
/// - `raw_len <= 1`: this is the root, no padding needed.
/// - `raw_len >= n`: pad up to the next multiple of `n`.
/// - `1 < raw_len < n`: pad to exactly `n` so that the next step can do a
///   single full N-to-1 compression to produce the root. This is safe
///   because the extra slots are filled with the default digest — the same
///   value that `compress` would use as padding internally.
pub(crate) const fn padded_len(raw_len: usize, n: usize) -> usize {
    if raw_len <= 1 {
        raw_len
    } else if raw_len >= n {
        raw_len.div_ceil(n) * n
    } else {
        n
    }
}

/// SPEED G2: the streamed tree's leaf digests from the installed accelerator, or `None` (then the CPU pass runs). Only
/// 4-byte values and digests are offered; the accelerator recognises its own hasher by type name.
fn accel_leaves<F, W: Copy, H, const DIGEST_ELEMS: usize>(
    h: &H,
    rows: &p3_matrix::dense::RowMajorMatrix<F>,
) -> Option<Vec<[W; DIGEST_ELEMS]>> {
    let a = crate::accel::installed()?;
    if core::mem::size_of::<F>() != 4 || core::mem::size_of::<W>() != 4 || rows.width == 0 {
        return None;
    }
    let n = rows.values.len() / rows.width;
    let job = crate::accel::LeafJob {
        hasher_type: core::any::type_name::<H>(),
        value_type: core::any::type_name::<F>(),
        digest_type: core::any::type_name::<W>(),
        hasher: h as *const H as *const (),
        rows: crate::accel::bytes_of(&rows.values),
        width: rows.width,
        digest_elems: DIGEST_ELEMS,
    };
    let raw = (a.leaves)(&job)?;
    let flat: Vec<W> = crate::accel::values_from_bytes(&raw, n * DIGEST_ELEMS)?;
    Some(flat.chunks_exact(DIGEST_ELEMS).map(|c| core::array::from_fn(|i| c[i])).collect())
}

/// SPEED G2: one layer above the leaves from the installed accelerator, padded exactly as [`streamed_par::compress`]
/// pads it, or `None` (then the CPU pass runs).
fn accel_compress<W: Copy + Default, C, const N: usize, const DIGEST_ELEMS: usize>(
    prev_layer: &[[W; DIGEST_ELEMS]],
    step: usize,
    c: &C,
) -> Option<Vec<[W; DIGEST_ELEMS]>> {
    let a = crate::accel::installed()?;
    if core::mem::size_of::<W>() != 4 || step == 0 {
        return None;
    }
    let next_len = prev_layer.len() / step;
    let job = crate::accel::CompressJob {
        compress_type: core::any::type_name::<C>(),
        digest_type: core::any::type_name::<W>(),
        compress: c as *const C as *const (),
        prev: crate::accel::bytes_of(prev_layer),
        step,
        arity: N,
        digest_elems: DIGEST_ELEMS,
        out_len: next_len,
    };
    let raw = (a.compress)(&job)?;
    let flat: Vec<W> = crate::accel::values_from_bytes(&raw, next_len * DIGEST_ELEMS)?;
    let mut out: Vec<[W; DIGEST_ELEMS]> = flat.chunks_exact(DIGEST_ELEMS).map(|c| core::array::from_fn(|i| c[i])).collect();
    out.resize(padded_len(next_len, N), [W::default(); DIGEST_ELEMS]);
    Some(out)
}

/// Pure compression step used when no extra rows are injected.
///
/// Takes groups of digests from `prev_layer`, feeds them to `c`,
/// and writes the results in order.
///
/// Groups `step` consecutive digests from `prev_layer`, pads each group
/// to `N` inputs with the default digest, then compresses N-to-1.
fn compress<P, C, const N: usize, const DIGEST_ELEMS: usize>(
    prev_layer: &[[P::Value; DIGEST_ELEMS]],
    step: usize,
    c: &C,
) -> Vec<[P::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    C: PseudoCompressionFunction<[P::Value; DIGEST_ELEMS], N>
        + PseudoCompressionFunction<[P; DIGEST_ELEMS], N>
        + Sync,
{
    let width = P::WIDTH;
    let next_len = prev_layer.len() / step;
    let next_len_padded = padded_len(next_len, N);

    let default_digest = [P::Value::default(); DIGEST_ELEMS];
    let mut next_digests = vec![default_digest; next_len_padded];

    next_digests[0..next_len]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            let first_row = i * width;
            let default_packed: [P; DIGEST_ELEMS] =
                array::from_fn(|_| P::broadcast(P::Value::default()));
            let children: [[P; DIGEST_ELEMS]; N] = array::from_fn(|n| {
                if n < step {
                    P::pack_columns_fn(|lane| prev_layer[step * (first_row + lane) + n])
                } else {
                    default_packed
                }
            });
            let packed_digest = c.compress(children);
            P::unpack_into(&packed_digest, digests_chunk);
        });

    for i in (next_len / width * width)..next_len {
        let children: [_; N] = array::from_fn(|n| {
            if n < step {
                prev_layer[step * i + n]
            } else {
                default_digest
            }
        });
        next_digests[i] = c.compress(children);
    }

    next_digests
}

#[cfg(test)]
mod tests {
    use p3_symmetric::PseudoCompressionFunction;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    #[derive(Clone, Copy)]
    struct DummyCompressionFunction;

    impl PseudoCompressionFunction<[u8; 32], 2> for DummyCompressionFunction {
        fn compress(&self, input: [[u8; 32]; 2]) -> [u8; 32] {
            let mut output = [0u8; 32];
            for (i, o) in output.iter_mut().enumerate() {
                // Simple XOR-based compression
                *o = input[0][i] ^ input[1][i];
            }
            output
        }
    }

    #[test]
    fn test_compress_even_length() {
        let prev_layer = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];
        let compressor = DummyCompressionFunction;
        let expected = vec![
            [0x03; 32], // 0x01 ^ 0x02
            [0x07; 32], // 0x03 ^ 0x04
        ];
        let result = compress::<u8, DummyCompressionFunction, 2, 32>(&prev_layer, 2, &compressor);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compress_odd_length() {
        let prev_layer = [[0x05; 32], [0x06; 32], [0x07; 32]];
        let compressor = DummyCompressionFunction;
        let expected = vec![
            [0x03; 32], // 0x05 ^ 0x06
        ];
        let result = compress::<u8, DummyCompressionFunction, 2, 32>(&prev_layer, 2, &compressor);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compress_random_values() {
        let mut rng = SmallRng::seed_from_u64(1);
        let prev_layer: Vec<[u8; 32]> = (0..8).map(|_| rng.random()).collect();
        let compressor = DummyCompressionFunction;
        let expected: Vec<[u8; 32]> = prev_layer
            .chunks_exact(2)
            .map(|pair| {
                let mut result = [0u8; 32];
                for (i, r) in result.iter_mut().enumerate() {
                    *r = pair[0][i] ^ pair[1][i];
                }
                result
            })
            .collect();
        let result = compress::<u8, DummyCompressionFunction, 2, 32>(&prev_layer, 2, &compressor);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compress_root_case_single_pair() {
        // When `prev_layer.len() == 2` we are at the “root-formation” case and
        // the function must return exactly one digest.
        //
        // 0xAA ^ 0x55 = 0xFF
        let prev_layer = [[0xAA; 32], [0x55; 32]];
        let compressor = DummyCompressionFunction;
        let expected = vec![[0xFF; 32]];
        let result = compress::<u8, DummyCompressionFunction, 2, 32>(&prev_layer, 2, &compressor);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compress_non_power_of_two_with_padding() {
        // The code intentionally pads to the next even length unless the output
        // would become the root.  With `len() == 6` the output length must be 4
        // (three real digests plus one zero digest).

        let prev_layer = [
            [0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32],
        ];
        let compressor = DummyCompressionFunction;

        let mut expected = vec![
            [0x03; 32], // 01 ^ 02
            [0x07; 32], // 03 ^ 04
            [0x03; 32], // 05 ^ 06
        ];
        // extra padded digest filled with 0
        expected.push([0x00; 32]);

        let result = compress::<u8, DummyCompressionFunction, 2, 32>(&prev_layer, 2, &compressor);
        assert_eq!(result, expected);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_padded_len_n2() {
        assert_eq!(padded_len(0, 2), 0);
        assert_eq!(padded_len(1, 2), 1);
        assert_eq!(padded_len(2, 2), 2);
        assert_eq!(padded_len(3, 2), 4);
        assert_eq!(padded_len(4, 2), 4);
        assert_eq!(padded_len(5, 2), 6);
        assert_eq!(padded_len(7, 2), 8);
        assert_eq!(padded_len(8, 2), 8);
        assert_eq!(padded_len(9, 2), 10);
        assert_eq!(padded_len(15, 2), 16);
        assert_eq!(padded_len(16, 2), 16);
    }

    #[test]
    fn test_padded_len_n4() {
        assert_eq!(padded_len(0, 4), 0);
        assert_eq!(padded_len(1, 4), 1);
        // Below-arity case: pad to exactly N
        assert_eq!(padded_len(2, 4), 4);
        assert_eq!(padded_len(3, 4), 4);
        // At or above arity: pad to next multiple of N
        assert_eq!(padded_len(4, 4), 4);
        assert_eq!(padded_len(5, 4), 8);
        assert_eq!(padded_len(7, 4), 8);
        assert_eq!(padded_len(8, 4), 8);
        assert_eq!(padded_len(9, 4), 12);
    }

    #[test]
    fn test_padded_len_n8() {
        assert_eq!(padded_len(0, 8), 0);
        assert_eq!(padded_len(1, 8), 1);
        // Below-arity: all pad to exactly N=8
        assert_eq!(padded_len(2, 8), 8);
        assert_eq!(padded_len(3, 8), 8);
        assert_eq!(padded_len(5, 8), 8);
        assert_eq!(padded_len(7, 8), 8);
        // At or above arity: next multiple of 8
        assert_eq!(padded_len(8, 8), 8);
        assert_eq!(padded_len(9, 8), 16);
        assert_eq!(padded_len(15, 8), 16);
        assert_eq!(padded_len(16, 8), 16);
    }

    #[test]
    fn test_padded_len_always_admits_full_groups() {
        // For any N in {2, 4, 8} and any raw_len > 1,
        // padded_len must be >= N and divisible by N (so a full compression
        // group is always possible), OR padded_len == raw_len <= 1 (root).
        for n in [2, 4, 8] {
            for raw_len in 2..=128 {
                let pl = padded_len(raw_len, n);
                assert!(
                    pl >= n && pl.is_multiple_of(n),
                    "padded_len({raw_len}, {n}) = {pl} is not a valid multiple of {n}",
                );
            }
        }
    }
}

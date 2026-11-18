//! Base-field commitment used by the sumcheck opening protocol.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::CanObserve;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrixView;
use p3_multilinear_util::poly::Poly;
use tracing::info_span;

use crate::strategy::VariableOrder;

/// ⭐ DB-371 — the base codeword as a matrix that RECOMPUTES a queried row instead of holding all `2^(k+ρ)` rows.
///
/// The codeword is the Reed–Solomon encoding [`commit_base`] commits: `2^f` columns, column `c` the evaluations of the
/// degree-`< 2^k` polynomial whose coefficients are column `c` of the layout's coefficient matrix, over the size-`2^(k+ρ)`
/// subgroup in natural order (row `i` ↔ `ω^i`, ω = `F::two_adic_generator(k+ρ)`). Row `i` is therefore `2^f` polynomial
/// evaluations at `ω^i`. Holding the coefficients (shared with the layout, which keeps them anyway) instead of the
/// codeword removes the codeword's `2^(n+ρ)` elements from the prover's resident set; a WHIR opening reads ~100 rows, each
/// `2^n` multiply-adds.
///
/// GENERIC OVER THE COEFFICIENTS: the evaluation domain is always `F`'s subgroup, the coefficients are any `V: Algebra<F>`
/// — `V = F` for the base commitment ([`commit_base`]) and `V = EF` for every folded WHIR round's extension commitment
/// (`p3_whir`'s `commit_extension`, MEASURED 2026-10-03: round 1 alone held 2,980 MB at the certificate's shape).
#[derive(Clone, Debug)]
pub struct CodewordRows<F, V = F> {
    /// The committed multilinear polynomial's `2^n` coefficients, in the layout's own order.
    coeffs: Arc<Poly<V>>,
    /// How the coefficients lie in the coefficient matrix (see [`commit_base`]).
    order: VariableOrder,
    /// `f` — log2 of the row width (the round's folding factor).
    log_cols: usize,
    /// `k = n − f` — log2 of each column polynomial's coefficient count.
    log_k: usize,
    /// `k + ρ` — log2 of the codeword height.
    log_height: usize,
    /// The rows an opening derived ahead of its queries ([`Self::prime_rows`]); a row found here is returned instead
    /// of being evaluated again. Empty until an opening primes it; shared by clones (they are one codeword).
    primed: Arc<spin::RwLock<BTreeMap<usize, Vec<V>>>>,
    _domain: PhantomData<F>,
}

/// ⭐ link 79 (2026-10-21) — the streamed commit's two hot loops on DIRECT rayon: the sub-coset fold
/// ([`CodewordRows::sub_coset_input`], every commit) and the lazy row evaluation ([`CodewordRows::eval_row`], every WHIR
/// query of a streamed round). Through the shim (its graph-wide `parallel` feature off) both ran on ONE core: MEASURED
/// (`sample`, the 256-insert band slice) the fold was 14 % of the commit and the row evaluation 48 % of the opening. Each
/// work item writes or returns only its own row / grain and the grains are recombined in index order, so the result is
/// byte-identical on any pool — pinned by `db371_the_streamed_base_commitment_equals_the_dense_one` (against the dense
/// serial encoding) and the decider's `a_parallel_prove_is_byte_identical_to_a_one_thread_prove` (one-thread pool).
mod direct_par {
    use alloc::vec::Vec;

    use rayon::prelude::*;

    /// `f(u, row_u)` for every `width`-wide row of `buf`, on every core.
    pub(super) fn for_each_row_mut<V: Send>(buf: &mut [V], width: usize, f: impl Fn(usize, &mut [V]) + Sync + Send) {
        buf.par_chunks_mut(width).enumerate().for_each(|(u, row)| f(u, row));
    }

    /// `[f(0), …, f(n − 1)]` in index order, on every core.
    pub(super) fn map_range<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
        (0..n).into_par_iter().map(f).collect()
    }

    /// `[f(i, chunk_i)]` over `chunk`-sized chunks of `s`, in index order, on every core.
    pub(super) fn map_chunks<V: Sync, T: Send>(s: &[V], chunk: usize, f: impl Fn(usize, &[V]) -> T + Sync + Send) -> Vec<T> {
        s.par_chunks(chunk).enumerate().map(|(i, c)| f(i, c)).collect()
    }
}

/// Coefficients per parallel work item when a row is evaluated (a rayon grain size, not a protocol value: any value
/// gives the same field result, since the chunks are recombined exactly by `x^start`).
const ROW_EVAL_GRAIN: usize = 1 << 14;

impl<F: TwoAdicField, V: Algebra<F> + Copy + Send + Sync> CodewordRows<F, V> {
    /// The codeword of `coeffs` laid out by `order` with row width `2^folding`, at rate `2^-log_inv_rate`.
    pub fn new(coeffs: Arc<Poly<V>>, order: VariableOrder, folding: usize, log_inv_rate: usize) -> Self {
        let log_k = coeffs.num_variables() - folding;
        Self {
            coeffs,
            order,
            log_cols: folding,
            log_k,
            log_height: log_k + log_inv_rate,
            primed: Arc::new(spin::RwLock::new(BTreeMap::new())),
            _domain: PhantomData,
        }
    }

    /// How many sub-cosets the streamed commit hashes: `2^(ρ + s)` ([`Self::log_split`]).
    pub fn sub_cosets(&self) -> usize {
        1 << (self.log_height - self.log_k + self.log_split())
    }

    /// ⭐⭐ SPEED R4 (2026-11-10) — THE ROWS AN OPENING WILL READ, DERIVED ONE SUB-COSET AT A TIME INSTEAD OF ONE ROW AT A TIME.
    ///
    /// MEASURED (two real nodes, the landed binary, `MONEROUSD_PROVE_PROGRESS`, 2026-11-10): the WHIR opening is the
    /// largest phase of BOTH proofs a block costs — about 12 s of the joined ledger's 27 s and 12 s of the spent-set
    /// step's 18 s, against 5 to 6 s for the commit that built the whole codeword. The cause is in this file and in
    /// `p3_merkle_tree`: a streamed commitment holds no codeword and no low digest layers, so each of a round's `q`
    /// queries recomputes its row AND the rows under its dropped siblings (`2^STREAMED_DROPPED_LAYERS` rows a query),
    /// each row one Horner pass over all `2^n` coefficients ([`Self::eval_row`]). At the block proofs' shape (n = 23,
    /// 258 queries, 4 rows each) that is 1,032 passes over 8.4 million coefficients in round 0 alone — while the commit
    /// derived EVERY row of the same codeword in 16 passes (its sub-cosets) and dropped them.
    ///
    /// Here the opening does what the commit did: `coset_rows(self, j)` — the SAME derivation the commit hashed, handed
    /// in by the caller that holds the transform — is run once for each sub-coset a wanted row lies in (row `r` is row
    /// `r / cosets` of sub-coset `r mod cosets`), the wanted rows are kept, and the sub-coset is dropped before the
    /// next is derived. [`Self::eval_row`] then returns a kept row instead of evaluating it. Returns how many rows
    /// were kept (0: nothing was derived, every row is evaluated lazily as before).
    ///
    /// The rows are the ones the commit hashed (it hashed these same sub-coset matrices), so no opened value, path,
    /// salt or proof byte changes — pinned by `speed_r4_primed_rows_are_the_lazy_rows_at_every_index` (every row of
    /// every shape, both orders, base and extension coefficients) and by every prove-then-verify pin above it: a row
    /// that is not the committed one fails its Merkle path at the unchanged verifier.
    /// BORROWED: the batched decommitment of FRI/STIR provers (Plonky3's own two-adic FRI opens its queries from the
    /// LDE it built once; here the LDE is rebuilt once per opening because it is deliberately not held).
    /// A sub-coset is derived only when that is the cheaper way to get its rows: one sub-coset costs one fold of every
    /// coefficient (a lazy row's `2^n` multiply-adds) plus a transform of `2^(n−s)` values, counted below in lazy rows
    /// from the shape itself, never a tuned number.
    /// cons: none on RAM — one sub-coset is resident at a time, exactly the commit's own peak (DB-371's point stands),
    /// and the kept rows are `q · 2^dropped` rows of `2^f` values (66 KB at the block's shape); none on the wire.
    pub fn prime_rows(&self, rows: &[usize], mut coset_rows: impl FnMut(&Self, usize) -> RowMajorMatrix<V>) -> usize {
        let cosets = self.sub_cosets();
        let height = 1usize << self.log_height;
        let width = 1usize << self.log_cols;
        let mut by_coset: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut wanted = 0usize;
        {
            let held = self.primed.read();
            let mut sorted: Vec<usize> = rows.iter().copied().filter(|&r| r < height && !held.contains_key(&r)).collect();
            sorted.sort_unstable();
            sorted.dedup();
            for r in sorted {
                by_coset.entry(r % cosets).or_default().push(r);
                wanted += 1;
            }
        }
        // one sub-coset in lazy rows: its fold (1) and its transform, `(k − s)/2` butterflies over `2^(n−s)` values
        let s = self.log_split();
        let coset_in_rows = 2 + ((self.log_k - s) >> (s + 1));
        if wanted <= by_coset.len() * coset_in_rows {
            return 0;
        }
        let mut kept: Vec<(usize, Vec<V>)> = Vec::with_capacity(wanted);
        for (j, rs) in by_coset {
            let m = coset_rows(self, j);
            assert_eq!(m.height() * cosets, height, "sub-coset {j} has the wrong height");
            assert_eq!(m.width(), width, "sub-coset {j} has the wrong width");
            for r in rs {
                let i = r / cosets;
                kept.push((r, m.values[i * width..(i + 1) * width].to_vec()));
            }
            // `m` (one sub-coset of the codeword) is dropped here, before the next is derived
        }
        let n = kept.len();
        self.primed.write().extend(kept);
        n
    }


    /// The coefficient of `X^t` in column `c`.
    fn coeff_index(&self, t: usize, c: usize) -> usize {
        match self.order {
            // the coefficient matrix is the TRANSPOSE of the `2^f × 2^k` row-major view: column `c` is contiguous
            VariableOrder::Prefix => (c << self.log_k) + t,
            // the coefficient matrix is the `2^k × 2^f` row-major view itself
            VariableOrder::Suffix => (t << self.log_cols) + c,
        }
    }

    /// `s`, the log of how finely each of the `2^ρ` cosets is split for the commit: split until ONE SUB-COSET holds at
    /// most ONE COLUMN of the codeword (`2^(k+ρ)` evaluations: `2^(k−s)` rows × `2^f` columns ≤ `2^(k+ρ)` ⟺ `s ≥ f − ρ`),
    /// and no further — `s = max(0, f − ρ)`, clamped to `k` (a sub-coset keeps ≥ 1 row). The two costs it balances, both
    /// MEASURED 2026-10-03 at the certificate's shapes:
    /// - the transient: base round (2^27, f = 4, ρ = 1), held after the commit — dense 3,204 MB; s = 0 3,396; s = 3
    ///   **2,155** (19.1 s); s = 4 2,103 (23.1 s); s = 6 2,064 (45.8 s);
    /// - the fold: `2^s` passes over the coefficients per coset, `2^s ×` the codeword in all. At s = f on the extension
    ///   rounds (ρ = 4, 7, …) that was 16× the codeword and the genesis certificate went 493 → 704 s; with ρ ≥ f a whole
    ///   coset already holds one codeword column, so those rounds take s = 0 (a single twist pass).
    fn log_split(&self) -> usize {
        let rho = self.log_height - self.log_k;
        self.log_cols.saturating_sub(rho).min(self.log_k)
    }

    /// SUB-COSET `j` of `2^(ρ+s)`: codeword rows `j, j + C, j + 2C, …` (`C = 2^(ρ+s)`, `m = 2^(k−s)` rows). Row
    /// `j + C·u` evaluates every column at `ω^j·(ω^C)^u`, and `ω^C` generates the size-`m` subgroup, so the sub-coset is
    /// `coset_dft(b, ω^j)` of the coefficients FOLDED modulo `m`: `b[u][c] = Σ_q a_c[u + q·m] · z^q`, `z = ω^(j·m)`
    /// (the `ω^(j·t)` twist of `t = u + q·m` splits as `ω^(j·u)` — the shift — times `z^q`). Returns `(b, ω^j)`; the
    /// caller runs the DFT its field needs (`coset_dft_batch` for `V = F`, `coset_dft_algebra_batch` for an extension).
    /// One `m × 2^f` buffer.
    pub fn sub_coset_input(&self, j: usize) -> (RowMajorMatrix<V>, F) {
        let s = self.log_split();
        let m = 1usize << (self.log_k - s);
        let width = 1usize << self.log_cols;
        let omega = F::two_adic_generator(self.log_height);
        let z_pows: Vec<F> = omega.exp_u64((j * m) as u64).powers().take(1 << s).collect();
        let coeffs = self.coeffs.as_slice();
        let mut folded = vec![V::ZERO; m * width];
        direct_par::for_each_row_mut(&mut folded, width, |u, row| {
            for (q, &zq) in z_pows.iter().enumerate() {
                for (c, slot) in row.iter_mut().enumerate() {
                    *slot += coeffs[self.coeff_index(u + q * m, c)] * zq;
                }
            }
        });
        (RowMajorMatrix::new(folded, width), omega.exp_u64(j as u64))
    }

    /// `p(x)` for the contiguous coefficients `col` (lowest degree first), as `LANES` INTERLEAVED Horner chains:
    /// `p(x) = Σ_{r<L} x^r · q_r(x^L)` with `q_r(y) = Σ_u col[L·u + r] · y^u`, each chain independent so the CPU
    /// overlaps them. MEASURED 2026-10-04 (`db371_round1_extension_commit_memory`, 2^19 × 16 EF coefficients): the plain
    /// chain `acc·x + a` was latency-bound at 46 ms per opened row (4.6 s per 100 queries, the whole time con of the
    /// streamed extension rounds); the interleave is the fix, with the same field result (the chains are recombined
    /// exactly by `x^r`).
    fn eval_poly_at(col: &[V], x: F) -> V {
        const LANES: usize = 8;
        let x_l = x.exp_u64(LANES as u64);
        let mut acc = [V::ZERO; LANES];
        // whole groups of LANES coefficients, highest first, so every lane's Horner chain sees its coefficients in order
        let groups = col.len() / LANES;
        for g in (0..groups).rev() {
            let base = &col[g * LANES..(g + 1) * LANES];
            for r in 0..LANES {
                acc[r] = acc[r] * x_l + base[r];
            }
        }
        // the tail (fewer than LANES coefficients) sits ABOVE the groups: it is evaluated directly and scaled by
        // x^(LANES·groups)
        let tail = &col[groups * LANES..];
        let tail_val = tail.iter().rev().fold(V::ZERO, |a, &c| a * x + c) * x.exp_u64((groups * LANES) as u64);
        let mut xr = F::ONE;
        let mut out = tail_val;
        for a in acc {
            out += a * xr;
            xr *= x;
        }
        out
    }

    /// Row `r` of the codeword: every column polynomial evaluated at `ω^r` (a point of `F`'s subgroup).
    fn eval_row(&self, r: usize) -> Vec<V> {
        // a row the opening derived ahead of its queries ([`Self::prime_rows`]) is the committed row itself
        if let Some(row) = self.primed.read().get(&r) {
            return row.clone();
        }
        self.eval_row_lazily(r)
    }

    /// Row `r` evaluated from the coefficients: one Horner pass over every column polynomial (`2^n` multiply-adds).
    fn eval_row_lazily(&self, r: usize) -> Vec<V> {
        let x = F::two_adic_generator(self.log_height).exp_u64(r as u64);
        let k = 1usize << self.log_k;
        let width = 1usize << self.log_cols;
        let coeffs = self.coeffs.as_slice();
        match self.order {
            // one task per (column, grain): each evaluates its grain's polynomial with the interleaved chains and
            // scales by x^start, and the grains of a column sum (an exact split of the polynomial)
            VariableOrder::Prefix => {
                let grains = k.div_ceil(ROW_EVAL_GRAIN);
                let parts: Vec<V> = direct_par::map_range(width * grains, |t| {
                    let (c, i) = (t / grains, t % grains);
                    let col = &coeffs[self.coeff_index(0, c)..][..k];
                    let start = i * ROW_EVAL_GRAIN;
                    let chunk = &col[start..(start + ROW_EVAL_GRAIN).min(k)];
                    Self::eval_poly_at(chunk, x) * x.exp_u64(start as u64)
                });
                parts.chunks(grains).map(|ps| ps.iter().copied().sum()).collect()
            }
            VariableOrder::Suffix => {
                let partials: Vec<Vec<V>> = direct_par::map_chunks(coeffs, ROW_EVAL_GRAIN * width, |i, block| {
                    let mut acc = vec![V::ZERO; width];
                    for row in block.chunks(width).rev() {
                        for (a, &v) in acc.iter_mut().zip(row) {
                            *a = *a * x + v;
                        }
                    }
                    let scale = x.exp_u64((i * ROW_EVAL_GRAIN) as u64);
                    acc.iter_mut().for_each(|a| *a *= scale);
                    acc
                });
                let mut row = vec![V::ZERO; width];
                for partial in partials {
                    row.iter_mut().zip(partial).for_each(|(a, b)| *a += b);
                }
                row
            }
        }
    }
}

impl<F: TwoAdicField, V: Algebra<F> + Copy + Send + Sync> Matrix<V> for CodewordRows<F, V> {
    fn width(&self) -> usize {
        1 << self.log_cols
    }

    fn height(&self) -> usize {
        1 << self.log_height
    }

    unsafe fn row_unchecked(
        &self,
        r: usize,
    ) -> impl IntoIterator<Item = V, IntoIter = impl Iterator<Item = V> + Send + Sync> {
        self.eval_row(r)
    }
}

/// Encodes and commits the initial base-field polynomial.
///
/// This is the first WHIR commitment. It lays out the polynomial according to
/// the residual variable order, applies the Reed-Solomon expansion with `dft`,
/// commits the resulting codeword matrix with `mmcs`, and observes the Merkle
/// root in the transcript.
///
/// Prefix order transposes the local folding block before padding so the first
/// folded variables become columns. Suffix order keeps the folding block as the
/// row width and only zero-pads the row count.
///
/// ⭐ DB-371 — STREAMED. The height-`2^(k+ρ)` codeword is `2^(ρ+s)` interleaved SUB-COSETS of the size-`2^(k−s)`
/// subgroup (row `i` in sub-coset `i mod 2^(ρ+s)`, [`CodewordRows::log_split`]); each is the coset DFT of the folded
/// coefficients ([`CodewordRows::sub_coset_input`]), hashed into the tree's leaf layer and dropped before the next is
/// computed, and the prover data opens from [`CodewordRows`]. The root, every opened row and every authentication path
/// equal the dense encoding's — pinned by `db371_the_streamed_base_commitment_equals_the_dense_one`.
/// Cons (MEASURED on the certificate's shape): the commit's fold is `2^(ρ+s)` passes over the coefficients (+6 s of a
/// 17 s commit at 2^27); an opened row is recomputed (`2^n` multiply-adds); 0 bytes on the wire, no verifier change.
pub fn commit_base<F, Dft, MT, Challenger>(
    order: VariableOrder,
    dft: &Dft,
    mmcs: &MT,
    challenger: &mut Challenger,
    poly: Arc<Poly<F>>,
    folding: usize,
    starting_log_inv_rate: usize,
) -> (MT::Commitment, MT::ProverData<CodewordRows<F>>)
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    MT: Mmcs<F>,
    Challenger: CanObserve<MT::Commitment>,
{
    let rows = CodewordRows::new(poly, order, folding, starting_log_inv_rate);
    let sub_cosets = rows.sub_cosets();
    let (root, prover_data) = info_span!("commit_streamed", sub_cosets).in_scope(|| {
        mmcs.commit_streamed(rows, sub_cosets, |rows, j| base_coset_rows(dft, rows, j))
    });
    challenger.observe(root.clone());
    (root, prover_data)
}

/// Sub-coset `j` of the BASE codeword: the coset transform of the folded coefficients. The ONE derivation the commit
/// hashes ([`commit_base`]) and an opening keeps its queried rows from ([`CodewordRows::prime_rows`]) — one function,
/// so the rows an opening sends are the rows the commitment was built over by construction.
pub fn base_coset_rows<F, Dft>(dft: &Dft, rows: &CodewordRows<F>, j: usize) -> RowMajorMatrix<F>
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    info_span!("sub-coset dft", sub_coset = j).in_scope(|| {
        let (folded, shift) = rows.sub_coset_input(j);
        dft.coset_dft_batch(folded, shift).to_row_major_matrix()
    })
}

/// The DENSE encoding `commit_base` replaced: the whole zero-padded coefficient matrix through one `dft_batch`. Kept
/// only as the byte-identity reference of the streamed path's pin.
#[cfg(test)]
pub(crate) fn dense_codeword<F: TwoAdicField, Dft: TwoAdicSubgroupDft<F>>(
    order: VariableOrder,
    dft: &Dft,
    poly: &Poly<F>,
    folding: usize,
    starting_log_inv_rate: usize,
) -> RowMajorMatrix<F> {
    let num_variables = poly.num_variables();
    let height = 1 << (num_variables + starting_log_inv_rate - folding);
    let mut padded = match order {
        VariableOrder::Prefix => {
            RowMajorMatrixView::new(poly.as_slice(), 1 << (num_variables - folding)).transpose()
        }
        VariableOrder::Suffix => RowMajorMatrix::new(poly.as_slice().to_vec(), 1 << folding),
    };
    padded.pad_to_height(height, F::ZERO);
    dft.dft_batch(padded).to_row_major_matrix()
}

#[cfg(test)]
mod db371_tests {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type H = PaddingFreeSponge<Perm, 16, 8, 8>;
    type C = TruncatedPermutation<Perm, 2, 8, 16>;
    type MT = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, 2, 8>;
    type HMT = MerkleTreeHidingMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, SmallRng, 2, 8, 8>;

    /// ⭐ DB-371 BYTE-IDENTITY — for both variable orders and rates 1/2, 1/4 and 1 (one coset), the streamed commitment's
    /// root, every row of its lazy matrix, and the opening (row + authentication path) at every index equal the dense
    /// encoding committed through `commit_matrix`. RED-first: a lazy matrix built with one wrong coefficient opens a
    /// different row than the dense codeword at that row.
    #[test]
    fn db371_the_streamed_base_commitment_equals_the_dense_one() {
        let mut rng = SmallRng::seed_from_u64(371);
        let perm = Perm::new_from_rng_128(&mut rng);
        let mmcs = MT::new(H::new(perm.clone()), C::new(perm.clone()), 0);
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut checked = 0;
        for order in [VariableOrder::Prefix, VariableOrder::Suffix] {
            // s = f in every case but the last, where k = 1 < f clamps the split to one row per sub-coset
            for (n, folding, rate) in [(8, 2, 1), (9, 3, 2), (7, 1, 0), (10, 4, 1), (5, 4, 1)] {
                let poly = Poly::new((0..1 << n).map(|_| rng.random::<F>()).collect());
                let dense = dense_codeword(order, &dft, &poly, folding, rate);
                let (dense_root, dense_data) = mmcs.commit_matrix(dense.clone());
                let mut ch = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
                let (root, data) =
                    commit_base(order, &dft, &mmcs, &mut ch, Arc::new(poly.clone()), folding, rate);
                assert_eq!(root, dense_root, "{order:?} n={n} f={folding} ρ={rate}: root differs");
                let lazy = &mmcs.get_matrices(&data)[0];
                assert_eq!((lazy.width(), lazy.height()), (dense.width(), dense.height()));
                for i in 0..dense.height() {
                    let want = mmcs.open_batch(i, &dense_data);
                    let got = mmcs.open_batch(i, &data);
                    assert_eq!(got.opened_values, want.opened_values, "{order:?} n={n}: row {i} differs");
                    assert_eq!(got.opening_proof, want.opening_proof, "{order:?} n={n}: path {i} differs");
                    checked += 1;
                }
            }
        }
        // the SALTED MMCS the committed AIR proves with: two instances seeded alike draw the same salts, so the streamed
        // and the classic commitment — root, every opened row, every salt and every sibling — must be equal
        for order in [VariableOrder::Prefix, VariableOrder::Suffix] {
            for (n, folding, rate) in [(8, 2, 1), (9, 3, 2)] {
                let salted = |seed| HMT::new(H::new(perm.clone()), C::new(perm.clone()), 0, SmallRng::seed_from_u64(seed));
                let (classic, streamed) = (salted(7), salted(7));
                let poly = Poly::new((0..1 << n).map(|_| rng.random::<F>()).collect());
                let dense = dense_codeword(order, &dft, &poly, folding, rate);
                let (want_root, want_data) = classic.commit_matrix(dense.clone());
                let mut ch = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
                let (root, data) = commit_base(order, &dft, &streamed, &mut ch, Arc::new(poly), folding, rate);
                assert_eq!(root, want_root, "salted {order:?} n={n}: root differs");
                for i in 0..dense.height() {
                    let (want, got) = (classic.open_batch(i, &want_data), streamed.open_batch(i, &data));
                    assert_eq!(got.opened_values, want.opened_values, "salted {order:?} n={n}: row {i} differs");
                    assert_eq!(got.opening_proof, want.opening_proof, "salted {order:?} n={n}: salts/path {i} differ");
                    checked += 1;
                }
            }
        }
        // the RED half: one planted coefficient moves the lazy row (the comparison above is not vacuous)
        let poly = Poly::new((0..1 << 8).map(|_| rng.random::<F>()).collect::<Vec<F>>());
        let dense = dense_codeword(VariableOrder::Prefix, &dft, &poly, 2, 1);
        let mut planted = poly.as_slice().to_vec();
        planted[5] += F::ONE;
        let lazy = CodewordRows::<F>::new(Arc::new(Poly::new(planted)), VariableOrder::Prefix, 2, 1);
        assert_ne!(lazy.eval_row(3), dense.row_slice(3).unwrap().to_vec(), "a planted coefficient went unnoticed");
        std::eprintln!("[db371] streamed == dense on {checked} openings across both orders, rates 1, 1/2, 1/4, plain and salted");
    }

    /// ⭐ SPEED R4 (2026-11-10) — A ROW DERIVED AHEAD OF AN OPENING IS THE COMMITTED ROW, AT EVERY INDEX.
    /// [`CodewordRows::prime_rows`] derives the rows an opening will read one sub-coset at a time (the commit's own
    /// derivation) instead of one Horner pass per row. For every shape, both orders: (1) every primed row equals the
    /// lazy evaluation and the dense codeword's row; (2) through the SALTED commitment the decider proves with, an
    /// opening taken after priming the rows the tree names equals the classic tree's opening — values, salts and path —
    /// and the verifier accepts it against the commitment; (3) too few wanted rows derive nothing (the lazy path stands).
    /// RED half: a row primed from a WRONG derivation differs from the lazy row and its opening is REFUSED by the
    /// verifier — a primed row is bound by the commitment exactly as a lazy one is, so the store cannot carry a forgery.
    /// TWO-PARTY-REVIEWED: the second side of an opening is the verifier; its unchanged `verify_batch` judges every
    /// opening here against the commitment the classic (dense) tree made. The row store itself never leaves the prover.
    #[test]
    fn speed_r4_primed_rows_are_the_lazy_rows_at_every_index() {
        use p3_commit::BatchOpeningRef;
        use p3_matrix::Dimensions;
        let mut rng = SmallRng::seed_from_u64(375);
        let perm = Perm::new_from_rng_128(&mut rng);
        let dft = Radix2DFTSmallBatch::<F>::default();
        let salted = |seed| HMT::new(H::new(perm.clone()), C::new(perm.clone()), 0, SmallRng::seed_from_u64(seed));
        let (mut rows_checked, mut openings_checked) = (0, 0);
        for order in [VariableOrder::Prefix, VariableOrder::Suffix] {
            for (n, folding, rate) in [(10usize, 4usize, 2usize), (9, 3, 2), (8, 2, 1), (10, 4, 1), (7, 1, 0)] {
                let poly = Arc::new(Poly::new((0..1 << n).map(|_| rng.random::<F>()).collect::<Vec<F>>()));
                let dense = dense_codeword(order, &dft, &poly, folding, rate);
                let height = dense.height();
                // (1) the rows themselves
                let rows = CodewordRows::<F>::new(poly.clone(), order, folding, rate);
                let wanted: Vec<usize> = (0..height).filter(|r| r % 4 != 3).collect();
                let kept = rows.prime_rows(&wanted, |m, j| base_coset_rows(&dft, m, j));
                assert_eq!(kept, wanted.len(), "CALIBRATION {order:?} n={n}: the wanted rows were not derived");
                assert_eq!(rows.prime_rows(&wanted, |_, _| panic!("a held row was derived again")), 0);
                for r in 0..height {
                    let lazy = rows.eval_row_lazily(r);
                    assert_eq!(rows.eval_row(r), lazy, "⛔ {order:?} n={n} f={folding} ρ={rate}: primed row {r} is not the lazy row");
                    assert_eq!(lazy, dense.row_slice(r).unwrap().to_vec(), "{order:?} n={n}: lazy row {r} is not the dense row");
                    rows_checked += 1;
                }
                // (3) one wanted row: deriving its sub-coset is not the cheaper way, nothing is kept
                let alone = CodewordRows::<F>::new(poly.clone(), order, folding, rate);
                assert_eq!(alone.prime_rows(&[1], |_, _| panic!("a sub-coset was derived for one row")), 0);
                // (2) through the salted commitment, primed from the rows the tree names
                let (classic, streamed) = (salted(11), salted(11));
                let (want_root, want_data) = classic.commit_matrix(dense.clone());
                let mut ch = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
                let (root, data) = commit_base(order, &dft, &streamed, &mut ch, poly.clone(), folding, rate);
                assert_eq!(root, want_root, "PRECONDITION: one commitment");
                let queried: Vec<usize> = (0..height).filter(|r| r % 3 != 1).collect();
                let named = streamed.rows_read_by_open(&queried, &data);
                assert!(named.len() >= queried.len(), "CALIBRATION: the tree named {} row(s) for {} queries", named.len(), queried.len());
                let primed = streamed.get_matrices(&data)[0].prime_rows(&named, |m, j| base_coset_rows(&dft, m, j));
                assert_eq!(primed, named.len(), "CALIBRATION {order:?} n={n}: the named rows were not derived");
                let dims = [Dimensions { height, width: dense.width() }];
                for &i in &queried {
                    let (want, got) = (classic.open_batch(i, &want_data), streamed.open_batch(i, &data));
                    assert_eq!(got.opened_values, want.opened_values, "⛔ {order:?} n={n}: primed opening {i} differs in its row");
                    assert_eq!(got.opening_proof, want.opening_proof, "⛔ {order:?} n={n}: primed opening {i} differs in salts or path");
                    classic.verify_batch(&root, &dims, i, BatchOpeningRef::from(&got)).expect("⛔ a primed opening does not verify");
                    openings_checked += 1;
                }
            }
        }
        // the RED half: rows primed from a wrong derivation are not the lazy rows, and the verifier refuses their opening
        let (order, n, folding, rate) = (VariableOrder::Prefix, 9usize, 3usize, 2usize);
        let poly = Arc::new(Poly::new((0..1 << n).map(|_| rng.random::<F>()).collect::<Vec<F>>()));
        let streamed = salted(12);
        let mut ch = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
        let (root, data) = commit_base(order, &dft, &streamed, &mut ch, poly, folding, rate);
        let codeword = streamed.get_matrices(&data)[0];
        let height = codeword.height();
        let all: Vec<usize> = (0..height).collect();
        let forged = codeword.prime_rows(&all, |m, j| {
            let mut wrong = base_coset_rows(&dft, m, j);
            wrong.values[0] += F::ONE; // the first value of this sub-coset's first row
            wrong
        });
        assert_eq!(forged, height, "CALIBRATION: the forged rows were not kept");
        assert_ne!(codeword.eval_row(0), codeword.eval_row_lazily(0), "CALIBRATION: the planted value is not in the store");
        let dims = [Dimensions { height, width: codeword.width() }];
        let opening = streamed.open_batch(0, &data);
        assert!(
            streamed.verify_batch(&root, &dims, 0, BatchOpeningRef::from(&opening)).is_err(),
            "⛔ an opening over a row that is not the committed one VERIFIED"
        );
        std::eprintln!("[speed-r4] primed == lazy == dense on {rows_checked} rows; {openings_checked} primed openings equal the classic tree's and verify; a forged row is refused");
    }
}

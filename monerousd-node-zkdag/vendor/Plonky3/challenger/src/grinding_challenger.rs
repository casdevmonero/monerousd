use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PackedValue, PrimeCharacteristicRing, PrimeField, PrimeField32, PrimeField64};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::CryptographicPermutation;
// The deterministic parallel grind below uses rayon directly (see `grind`); the traits are imported under
// their own names because `p3_maybe_rayon::prelude::*` above exports the same trait names for the serial shim.
use rayon::iter::{IntoParallelIterator as RayonIntoPar, ParallelIterator as RayonPar};
use tracing::instrument;

use crate::{
    CanObserve, CanSampleBits, CanSampleUniformBits, DuplexChallenger, MultiField32Challenger,
    UniformSamplingField,
};

/// Trait for challengers that support proof-of-work (PoW) grinding.
///
/// A `GrindingChallenger` can:
/// - Absorb a candidate witness into the transcript
/// - Sample random bitstrings to check the PoW condition
/// - Brute-force search for a valid witness that satisfies the PoW
///
/// This trait is typically used in protocols requiring computational effort
/// from the prover.
pub trait GrindingChallenger:
    CanObserve<Self::Witness> + CanSampleBits<usize> + Sync + Clone
{
    /// The underlying field element type used as the witness.
    type Witness: Field;

    /// Perform a brute-force search to find a valid PoW witness.
    ///
    /// Given a `bits` parameter, this function searches for a field element
    /// `witness` such that after observing it, the next `bits` bits that challenger outputs
    /// are all `0`.
    fn grind(&mut self, bits: usize) -> Self::Witness;

    /// [`Self::grind`] that reports EXHAUSTION instead of panicking: `None` when no witness exists in the whole
    /// field for this transcript state and `bits`. In a 31-bit field a `bits`-bit grind has 2^(31 − bits) expected
    /// solutions — about two at 30 bits, and NONE with probability e^−2 ≈ 13.5% (MonerousD 2026-09-28, MEASURED: the
    /// recursive certificate's deepest folding grind is 30 bits; one of two proves found no witness). A caller that
    /// grinds at such depths uses [`Self::grind_wide`]. The default wraps `grind` (which panics on exhaustion);
    /// a search that can end without a hit overrides it.
    fn try_grind(&mut self, bits: usize) -> Option<Self::Witness> {
        Some(self.grind(bits))
    }

    /// THE TWO-WORD PROOF OF WORK (MonerousD 2026-09-28) for the FOLDING grinds, whose depth the WHIR config derives
    /// per round (up to 30 bits at rate 1/2 in a 31-bit field). The witness is `[hi, lo]`: both words are observed
    /// in order and the PoW condition is checked on the sample after `lo`, so the nonce space is 2^62 and a grind
    /// of any depth this workspace's configs derive (≤ 35 bits) has ≥ 2^27 solutions — it never fails to exist.
    /// Deterministic: the smallest `hi` for which some `lo` exists, then the smallest `lo`, so proof bytes do not
    /// depend on the thread count. `bits == 0` ⇒ an EMPTY witness (no words). The folding witnesses already lived in
    /// a list (`SumcheckData::pow_witnesses`, empty at 0 bits), so a proof without grinding keeps its exact bytes;
    /// the QUERY grinds stay one word (`grind`: ≤ `params.pow_bits` ≤ 24 bits, ≥ 2^7 solutions).
    fn grind_wide(&mut self, bits: usize) -> Vec<Self::Witness> {
        if bits == 0 {
            return Vec::new();
        }
        let mut hi = Self::Witness::ZERO;
        loop {
            let mut probe = self.clone();
            probe.observe(hi);
            if let Some(lo) = probe.try_grind(bits) {
                self.observe(hi);
                assert!(self.check_witness(bits, lo), "the wide grind's witness must pass the wide check");
                return vec![hi, lo];
            }
            hi += Self::Witness::ONE;
        }
    }

    /// The verifier's side of [`Self::grind_wide`]: with `bits == 0` the witness must be EMPTY (one encoding,
    /// no free bytes); otherwise exactly two words, observed in order, and the sample after them has `bits` zero
    /// low bits.
    fn check_witness_wide(&mut self, bits: usize, witness: &[Self::Witness]) -> bool {
        if bits == 0 {
            return witness.is_empty();
        }
        if witness.len() != 2 {
            return false;
        }
        self.observe(witness[0]);
        self.check_witness(bits, witness[1])
    }

    /// Check whether a given `witness` satisfies the PoW condition.
    ///
    /// After absorbing the witness, the challenger samples `bits` random bits
    /// and verifies that all bits sampled are zero.
    ///
    /// Returns `true` if the witness passes the PoW check, `false` otherwise.
    #[must_use]
    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        if bits == 0 {
            return true;
        }
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

/// Trait for challengers that support proof-of-work (PoW) grinding with
/// guaranteed uniformly sampled bits.
pub trait UniformGrindingChallenger:
    GrindingChallenger + CanSampleUniformBits<Self::Witness>
{
    /// Grinds based on *uniformly sampled bits*. This variant is allowed to do rejection
    /// sampling if a value is sampled that would violate our uniformity requirement
    /// (chance of about 1/P).
    ///
    /// Use this together with `check_witness_uniform`.
    fn grind_uniform(&mut self, bits: usize) -> Self::Witness;

    /// Grinds based on *uniformly sampled bits*. This variant errors if a value is
    /// sampled, which would violate our uniformity requirement (chance of about 1/P).
    /// See the `UniformSamplingField` trait implemented for each field for details.
    ///
    /// Use this together with `check_witness_uniform_may_error`.
    fn grind_uniform_may_error(&mut self, bits: usize) -> Self::Witness;

    /// Check whether a given `witness` satisfies the PoW condition.
    ///
    /// After absorbing the witness, the challenger samples `bits` random bits
    /// *uniformly* and verifies that all bits sampled are zero. The uniform
    /// sampling implies we do rejection sampling in about ~1/P cases.
    ///
    /// Returns `true` if the witness passes the PoW check, `false` otherwise.
    fn check_witness_uniform(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.sample_uniform_bits::<true>(bits)
            .expect("Error impossible here due to resampling strategy")
            == 0
    }

    /// Check whether a given `witness` satisfies the PoW condition.
    ///
    /// After absorbing the witness, the challenger samples `bits` random bits
    /// *uniformly* and verifies that all bits sampled are zero. In about ~1/P
    /// cases this function may error if a sampled value lies outside a range
    /// in which we can guarantee uniform bits.
    ///
    /// Returns `true` if the witness passes the PoW check, `false` otherwise.
    fn check_witness_uniform_may_error(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.sample_uniform_bits::<false>(bits)
            .is_ok_and(|v| v == 0)
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> GrindingChallenger
    for DuplexChallenger<F, P, WIDTH, RATE>
where
    F: PrimeField64,
    P: CryptographicPermutation<[F; WIDTH]>
        + CryptographicPermutation<[<F as Field>::Packing; WIDTH]>
        + 'static,
{
    type Witness = F;

    #[instrument(name = "grind for proof-of-work witness", skip_all)]
    fn grind(&mut self, bits: usize) -> Self::Witness {
        // A ONE-word grind needs a field with room: at `bits`, a `F::bits()`-bit field holds 2^(F::bits() − bits)
        // expected solutions and none with probability e^−that. Below 2^7 (≈ e^−128) the search is a lottery, not a
        // cost — the caller must use `grind_wide` (MonerousD 2026-09-28: the 30-bit folding grinds did exactly this).
        assert!(
            bits + 7 <= F::bits(),
            "a one-word grind of {bits} bits in a {}-bit field has only 2^{} expected solutions: use grind_wide",
            F::bits(),
            F::bits() as i64 - bits as i64
        );
        let Some(witness) = self.try_grind(bits) else {
            panic!(
                "no proof-of-work witness exists for {bits} bits in the {}-bit field (2^{} expected solutions): grind_wide is the two-word search for this depth",
                F::bits(),
                F::bits() as i64 - bits as i64
            );
        };
        // Double-check the witness using the standard verifier logic and update the challenger state.
        assert!(self.check_witness(bits, witness));
        witness
    }

    /// The search for the SMALLEST witness; `None` when the whole field holds no witness. Reads the transcript state and
    /// mutates nothing (`grind` and `grind_wide` apply the witness they take).
    /// ⭐ SPEED G1 (MonerousD lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8): when an accelerator is
    /// installed ([`crate::set_grind_accel`]) it is asked first. It answers with the smallest witness or nothing; its
    /// answer is taken only when THIS challenger's own `check_witness` accepts it on a clone (one permutation), so an
    /// accelerator can never put an invalid witness into a proof. Anything else — no accelerator, a permutation it does
    /// not know, no answer, a refused answer — runs [`DuplexChallenger::try_grind_cpu`], the search as it was.
    /// cons: one atomic load per grind with no accelerator installed.
    fn try_grind(&mut self, bits: usize) -> Option<Self::Witness> {
        if bits > 0 && bits < 64 && (1u64 << bits) < F::ORDER_U64 {
            if let Some(accel) = crate::grind_accel::installed() {
                let base: [u64; WIDTH] = core::array::from_fn(|i| {
                    if i < self.input_buffer.len() {
                        self.input_buffer[i].as_canonical_u64()
                    } else {
                        self.sponge_state[i].as_canonical_u64()
                    }
                });
                let job = crate::grind_accel::GrindJob {
                    permutation: &self.permutation as &dyn core::any::Any,
                    base: &base,
                    witness_idx: self.input_buffer.len(),
                    out_idx: RATE - 1,
                    bits,
                    order: F::ORDER_U64,
                };
                if let Some(w) = accel(&job) {
                    if w < F::ORDER_U64 {
                        // SAFETY: w < the field order, so it is a canonical element.
                        let witness = unsafe { F::from_canonical_unchecked(w) };
                        if self.clone().check_witness(bits, witness) {
                            return Some(witness);
                        }
                    }
                }
            }
        }
        self.try_grind_cpu(bits)
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> DuplexChallenger<F, P, WIDTH, RATE>
where
    F: PrimeField64,
    P: CryptographicPermutation<[F; WIDTH]>
        + CryptographicPermutation<[<F as Field>::Packing; WIDTH]>
        + 'static,
{
    /// The SIMD-vectorized, deterministic parallel search on the CPU; `None` when the whole field holds no witness.
    /// Reads the transcript state and mutates nothing. This is the reference every accelerated search is held to.
    pub fn try_grind_cpu(&self, bits: usize) -> Option<F> {
        // Ensure `bits` is small enough to be used in a shift.
        assert!(bits < 64, "bit count must be valid");

        // Ensure the PoW target 2^bits is smaller than the field order.
        // Otherwise, the probability analysis for grinding would break.
        assert!((1u64 << bits) < F::ORDER_U64);

        // Trivial case: 0 bits mean no PoW is required and any witness is valid.
        if bits == 0 {
            return Some(F::ZERO);
        }

        // SIMD width: number of field elements processed in parallel.
        // Each SIMD lane corresponds to one candidate witness.
        let lanes = F::Packing::WIDTH;

        // Total number of batches needed to cover all field elements.
        // Each batch tests `lanes` witnesses in parallel.
        let num_batches = F::ORDER_U64.div_ceil(lanes as u64);

        // Cache the field order.
        let order = F::ORDER_U64;

        // Bitmask used to check the PoW condition. eg. bits = 3 => mask = 0b111
        // We accept a witness if (sample & mask) == 0. This verifies 'bits' trailing zeros.
        let mask = (1u64 << bits) - 1;

        // In a duplex sponge, new inputs are absorbed sequentially at indices [0, 1, 2, ...].
        // The grinding witness is therefore absorbed at the next available position.
        let witness_idx = self.input_buffer.len();

        // Build the sponge state as packed field elements (SIMD vectors).
        //
        // The current transcript is split across:
        // - `input_buffer`: recently observed transcript elements that have not yet been permuted
        // - `sponge_state`: the internal sponge state after previous permutations
        //
        // Logically, the next permutation would act on:
        //   [input_buffer || sponge_state]
        //
        // This is invariant across batches, so we compute it once.
        let base_packed_state: [_; WIDTH] = core::array::from_fn(|i| {
            if i < self.input_buffer.len() {
                // Broadcast buffered transcript elements (input_buffer) to all SIMD lanes.
                F::Packing::from(self.input_buffer[i])
            } else {
                // Broadcast existing sponge state (sponge_state) to all SIMD lanes.
                F::Packing::from(self.sponge_state[i])
            }
        });

        // Grinding is a brute-force search over candidate witnesses: vectorized with SIMD (one permutation tests
        // `lanes` candidates) and PARALLEL over batches — DETERMINISTICALLY. The answer is the SMALLEST valid
        // witness, exactly the element a serial scan returns, so a proof's bytes never depend on the thread count.
        //
        // MonerousD 2026-09-28: `p3-maybe-rayon`'s `parallel` feature stays OFF graph-wide (it made proving
        // nondeterministic — the workspace Cargo.toml, §CA), so this grind uses rayon DIRECTLY and keeps the serial
        // answer: batches are searched chunk by chunk in index order; inside a chunk every batch is tested in
        // parallel and the minimum hit is taken (candidates grow with the batch index, so the minimum over a chunk
        // is the first hit the serial scan would have met); the first chunk with a hit ends the search.
        // ROOT-LAYER: the grind is where the prover's wall time went — 1 of 12 threads busy for the whole search.
        // MEASURED before this change (2026-09-28, the recursive certificate at T = 2^14, deepest fold grind 2^30
        // permutations): ≈ 8 minutes per proof on one core, most of a 17-minute prove. MUST-STAY-GREEN: every
        // carrier proof's bytes — the pin `the_parallel_grind_returns_the_serial_witness` (usdm-decider) compares
        // the witness with a serial scan for several bit counts.
        //
        // Each batch processes `F::Packing::WIDTH` candidates:
        //   - Batch 0 -> candidates [0, 1, ..., F::Packing::WIDTH - 1]
        //   - Batch k -> candidates [k * F::Packing::WIDTH, ..., (k+1) * F::Packing::WIDTH - 1]
        let check_batch = |batch: u64| -> Option<F> {
            let base = batch * lanes as u64;
            // Start with a copy of the precomputed base state.
            let mut packed_state = base_packed_state;
            // Generate SIMD-packed candidate witnesses: each lane receives a distinct field element
            //   [base + 0, base + 1, ..., base + F::Packing::WIDTH - 1]
            let packed_witnesses = F::Packing::from_fn(|lane| {
                let candidate = base + lane as u64;
                if candidate < order {
                    // SAFETY: candidate < field order, so this is a valid canonical field element.
                    unsafe { F::from_canonical_unchecked(candidate) }
                } else {
                    // Values outside the field order can never satisfy PoW, so we repeat the last potential witness
                    F::NEG_ONE
                }
            });
            // Insert the candidate witnesses at the next absorption position: this simulates absorbing
            // `transcript || witness` before the Fiat–Shamir challenge is derived.
            packed_state[witness_idx] = packed_witnesses;
            // Apply the cryptographic permutation (SIMD version): all `lanes` candidates at once.
            self.permutation.permute_mut(&mut packed_state);
            // In a duplex sponge the output is read from position [RATE-1]; accept the FIRST lane whose low `bits`
            // bits are all zero (lanes are in increasing candidate order).
            packed_state[RATE - 1]
                .as_slice()
                .iter()
                .zip(packed_witnesses.as_slice())
                .find(|(sample, _)| (sample.as_canonical_u64() & mask) == 0)
                .map(|(_, &witness)| witness)
        };
        // Batches per parallel chunk at most: 2^14 batches × `lanes` candidates ≈ a few ms of work per core, so a
        // deep search stops within one chunk of the serial answer's position.
        const BATCHES_PER_CHUNK: u64 = 1 << 14;
        // ⭐ THE SEARCH IS SIZED BY THE GRIND'S OWN EXPECTED WORK (MonerousD 2026-10-08). A `bits`-bit grind meets its
        // first hit after 2^bits candidates on average — `expected` batches. The search used to open with a full
        // 2^14-batch parallel chunk whatever `bits` was, and a parallel chunk evaluates EVERY batch before it takes
        // its minimum: the light decider grinds every sumcheck round at `REC_DECIDER_POW_BITS` = 4 (≈ 16 candidates),
        // so each of those grinds ran 16,384 packed permutations where ≈ 4 find the answer. MEASURED (`sample` of the
        // simulator's fast journey, scratchpad/night/link29-sample.txt): 1,970 of the block template's 2,470 fold-proof
        // samples were this grind, and its permutations were 12,428 of the process's 17,242.
        // So: (1) a SERIAL prefix of 16 × `expected` batches (capped at `SERIAL_BATCHES`) — it returns the FIRST hit
        // and stops, and misses only with probability ≈ e^−16 for a shallow grind; (2) then parallel chunks that
        // open at 4 × `expected` and double up to `BATCHES_PER_CHUNK`. The ANSWER IS UNCHANGED: the chunks still tile
        // the batch range in index order, a serial scan's first hit is the minimum of its range, and the first range
        // with a hit holds the serial answer — so every proof's bytes are what they were (the pin
        // `the_parallel_grind_returns_the_serial_witness` compares with a serial scan at 1 … 24 bits).
        // cons: none — no witness, transcript or proof byte changes; a deep grind (expected ≥ 2^12 batches) pays one
        // 256-batch serial prefix (≈ 0.1 ms) before its first parallel chunk.
        const SERIAL_BATCHES: u64 = 1 << 8;
        let expected = (1u64 << bits).div_ceil(lanes as u64).max(1);
        let serial_end = expected.saturating_mul(16).min(SERIAL_BATCHES).min(num_batches);
        if let Some(hit) = (0..serial_end).find_map(&check_batch) {
            return Some(hit);
        }
        let mut chunk_len = expected.saturating_mul(4).clamp(SERIAL_BATCHES, BATCHES_PER_CHUNK);
        let mut found: Option<F> = None;
        let mut chunk_start = serial_end;
        while chunk_start < num_batches {
            let chunk_end = (chunk_start + chunk_len).min(num_batches);
            chunk_len = (chunk_len * 2).min(BATCHES_PER_CHUNK);
            let hit = RayonPar::min_by_key(
                RayonPar::filter_map(RayonIntoPar::into_par_iter(chunk_start..chunk_end), &check_batch),
                |w: &F| w.as_canonical_u64(),
            );
            if hit.is_some() {
                found = hit;
                break;
            }
            chunk_start = chunk_end;
        }
        found
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> UniformGrindingChallenger
    for DuplexChallenger<F, P, WIDTH, RATE>
where
    F: UniformSamplingField + PrimeField64,
    P: CryptographicPermutation<[F; WIDTH]>
        + CryptographicPermutation<[<F as Field>::Packing; WIDTH]>
        + 'static,
{
    #[instrument(name = "grind uniform for proof-of-work witness", skip_all)]
    fn grind_uniform(&mut self, bits: usize) -> Self::Witness {
        // Call the generic grinder with the "resample" checking logic.
        self.grind_generic(bits, |challenger, witness| {
            challenger.check_witness_uniform(bits, witness)
        })
    }
    #[instrument(name = "grind uniform may error for proof-of-work witness", skip_all)]
    fn grind_uniform_may_error(&mut self, bits: usize) -> Self::Witness {
        // Call the generic grinder with the "error" checking logic.
        self.grind_generic(bits, |challenger, witness| {
            challenger.check_witness_uniform_may_error(bits, witness)
        })
    }
}
impl<F, P, const WIDTH: usize, const RATE: usize> DuplexChallenger<F, P, WIDTH, RATE>
where
    F: PrimeField64,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    /// A generic, private helper for PoW grinding, parameterized by the checking function.
    fn grind_generic<CHECK>(&mut self, bits: usize, check_fn: CHECK) -> F
    where
        CHECK: Fn(&mut Self, F) -> bool + Sync + Send,
    {
        // Maybe check that bits is greater than 0?
        assert!(bits < (usize::BITS as usize), "bit count must be valid");
        assert!(
            (1u64 << bits) < F::ORDER_U64,
            "bit count exceeds field order"
        );
        // The core parallel brute-force search logic.
        let witness = p3_maybe_rayon::prelude::IntoParallelIterator::into_par_iter(0..F::ORDER_U64)
            .map(|i| unsafe {
                // This is safe as i is always in range.
                F::from_canonical_unchecked(i)
            })
            .find_any(|&witness| check_fn(&mut self.clone(), witness))
            .expect("failed to find proof-of-work witness");
        // Run the check one last time on the *original* challenger to update its state
        // and confirm the witness is valid.
        assert!(check_fn(self, witness));
        witness
    }
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> GrindingChallenger
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField32,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    type Witness = F;

    #[instrument(name = "grind for proof-of-work witness", skip_all)]
    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < (usize::BITS as usize), "bit count must be valid");
        assert!((1 << bits) < F::ORDER_U32);

        // Trivial case: 0 bits mean no PoW is required and any witness is valid.
        if bits == 0 {
            return F::ZERO;
        }

        let witness = p3_maybe_rayon::prelude::IntoParallelIterator::into_par_iter(0..F::ORDER_U32)
            .map(|i| unsafe {
                // i < F::ORDER_U32 by construction so this is safe.
                F::from_canonical_unchecked(i)
            })
            .find_any(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");
        assert!(self.check_witness(bits, witness));
        witness
    }
}

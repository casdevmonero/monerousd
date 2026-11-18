use alloc::vec::Vec;

use p3_challenger::{CanSample, CanSampleUniformBits, FieldChallenger};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_util::log2_strict_usize;

/// Sample `t` distinct STIR query indices uniformly from the transcript.
///
/// # Pipeline
///
/// ```text
///   transcript --> uniform draws --> reject collisions --> sort
///                  [0, 2^k)          distinct              ascending
/// ```
///
/// with `k = log2(folded_domain_size)` and
/// `folded_domain_size = domain_size >> folding_factor`.
///
/// # Output
///
/// - length = `t = min(num_queries, folded_domain_size)`
/// - range  = `[0, folded_domain_size)`
/// - order  = strictly ascending, pairwise distinct, uniform per index
///
/// # Soundness
///
/// WHIR shift-query bound (Arnon-Chiesa-Fenzi-Yogev 2024, Thm 5.2):
///
/// ```text
///   eps_shift  <=  (1 - delta)^t
/// ```
///
/// `t` counts independent **uniformly-sampled** positions; distinctness
/// is not required (collisions waste opening work but do not weaken the
/// bound). Per-draw uniformity is the only leak closed here:
///
/// - **Biased draws** — bit-decomposing a uniform field element biases
///   each draw by `~ 2^bits / |F|`, which inflates `delta`. Routed
///   through `sample_uniform_bits` for exact uniformity.
///
/// Duplicate rejection is a cleanliness choice — it pins output length
/// at `t = min(num_queries, folded_domain_size)` and unifies the
/// common-case and saturation-case paths below.
///
/// # Saturation
///
/// `num_queries > folded_domain_size` returns the full domain. This is
/// WHIR's final round: 1-4 folded positions vs. `final_queries` up to 75.
///
/// # Cost
///
/// ```text
///   per draw         | 1-2 field samples, reject prob ~ 1 / |F|
///   loop, common     | O(t)
///   loop, saturated  | O(t log t)   (coupon collector)
/// ```
///
/// # Panics
///
/// `domain_size >> folding_factor` must be a power of two.
///
/// # TODO (possible recursion ideas)
///
/// - Prefer `n` independent draws (with duplicates allowed) over
///   `n` distinct indices for recursion-friendliness.
/// - The WHIR paper's `(1 - delta)^t` bound is over independent
///   draws; distinctness only lets `t` shrink slightly for the
///   same security, with negligible practical effect.
/// - Revisit when wiring this through a recursive verifier.
pub fn get_challenge_stir_queries<Challenger, F, EF>(
    domain_size: usize,
    folding_factor: usize,
    num_queries: usize,
    challenger: &mut Challenger,
) -> Vec<usize>
where
    Challenger: FieldChallenger<F> + CanSampleUniformBits<F>,
    F: Field + p3_field::PrimeField64,
    EF: ExtensionField<F>,
{
    // Phase 1: derive the addressable folded domain.
    //
    //   folded_domain_size = domain_size >> folding_factor
    //   k                  = log2(folded_domain_size)
    //
    // Each index fits in `k` bits.
    let folded_domain_size = domain_size >> folding_factor;
    let domain_size_bits = log2_strict_usize(folded_domain_size);

    // Phase 2: cap the request at the domain size.
    //
    //   num_queries <= folded_domain_size  ->  target = num_queries
    //   num_queries  > folded_domain_size  ->  target = folded_domain_size
    //                                          (open every position)
    let target = num_queries.min(folded_domain_size);

    // Phase 3: rejection-sample distinct indices.
    //
    //   loop:
    //     q <- uniform on [0, 2^k)
    //     append q if not already present
    //   until len == target
    let mut queries: Vec<usize> = Vec::with_capacity(target);
    while queries.len() < target {
        // RESAMPLE = true: the impl loops on field-side rejection internally.
        //
        // So the error arm is unreachable for every challenger in this workspace.
        let q = challenger
            .sample_uniform_bits::<true>(domain_size_bits)
            .expect("RESAMPLE = true: rejection loops internally, never errors");

        if !queries.contains(&q) {
            queries.push(q);
        }
    }

    // Phase 4: verifier and Merkle-proof code consume ascending indices.
    queries.sort_unstable();
    queries
}

#[cfg(test)]
mod route_d_distribution {
    use super::*;

    /// The production sampler after 2026-09-27: `t` INDEPENDENT `draw_below(folded_domain)` draws, with
    /// replacement, in draw order — by definition equal to `t` direct draws from the same challenger state,
    /// every index inside the folded domain, and EXACTLY `t · DRAW_ELEMS` samples consumed whatever the
    /// transcript holds (the trace height of the in-circuit verifier is a function of the shape alone).
    #[test]
    fn the_sampler_is_t_independent_draws_with_a_fixed_sample_count() {
        use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
        use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
        use p3_field::extension::BinomialExtensionField;
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        type F = BabyBear;
        type EF = BinomialExtensionField<F, 4>;
        type Ch = DuplexChallenger<F, Poseidon2BabyBear<16>, 16, 8>;
        let perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut SmallRng::seed_from_u64(9));
        for (domain_bits, folding, t) in [(15usize, 4usize, 160usize), (13, 4, 160), (11, 4, 128), (5, 4, 3)] {
            for seed in 0..3u64 {
                let mut ch = Ch::new(perm.clone());
                ch.observe(F::new((seed * 7 + 1) as u32));
                let mut direct = ch.clone();
                let mut counter = ch.clone();
                let n = (1usize << domain_bits) >> folding;
                let got = stir_queries_fixed_time::<Ch, F, EF>(1 << domain_bits, folding, t, &mut ch);
                let want: alloc::vec::Vec<usize> = (0..t).map(|_| draw_below::<Ch, F>(&mut direct, n)).collect();
                assert_eq!(got, want, "domain 2^{domain_bits} folding {folding} t {t} seed {seed}: not t direct draws");
                assert_eq!(got.len(), t);
                assert!(got.iter().all(|&q| q < n), "an index left the folded domain");
                for _ in 0..t * DRAW_ELEMS {
                    let _: F = counter.sample();
                }
                let (a, b): (F, F) = (counter.sample(), ch.sample());
                assert_eq!(a, b, "the sampler consumed a sample count other than t · DRAW_ELEMS");
            }
        }
        std::eprintln!("[sampler] t independent draws with replacement, t · DRAW_ELEMS samples, every index in range");
    }

    /// ⭐⭐ THE OTHER HALF OF THE JUSTIFICATION, IN EXACT INTEGER ARITHMETIC. `draw_below` reduces
    /// `DRAW_ELEMS` field elements modulo `m` instead of rejecting, which leaves a deviation from
    /// uniform. With `p^n = q·m + r` the total-variation distance is exactly `r(m-r) / (m · p^n)`, at
    /// most `m / (4 p^n)`. This computes it for the real prime and the real domain sizes and demands the
    /// union bound over a whole proof's draws land below the 100-bit level these parameters target — so
    /// the deviation is DOMINATED by the claimed error rather than traded against it.
    #[test]
    fn draw_deviation_is_below_the_claimed_security_level() {
        // KoalaBear. Stated here so a field change cannot silently invalidate the bound.
        const P: u128 = 0x7f00_0001;
        const SECURITY_BITS: u32 = 100;
        // §BK-2's measured shape: at most 2^11 folded positions, 160 queries, three rounds.
        const MAX_M: u128 = 1 << 11;
        const TOTAL_DRAWS: u128 = 160 * 3;

        let mut pn: u128 = 1;
        for _ in 0..DRAW_ELEMS {
            pn = pn.checked_mul(P).expect("p^DRAW_ELEMS must fit a u128, or `draw_below` overflows");
        }
        // The Horner accumulator reaches p^DRAW_ELEMS - 1, so the multiply above is also the overflow
        // proof for `draw_below` itself.
        assert!(pn > 0);

        // TV <= m / (4 p^n). Compare TOTAL_DRAWS * TV < 2^-SECURITY_BITS by cross-multiplying, so the
        // whole comparison stays in exact integers: TOTAL_DRAWS * m * 2^SECURITY_BITS < 4 * p^n.
        let lhs = TOTAL_DRAWS
            .checked_mul(MAX_M)
            .and_then(|v| v.checked_mul(1u128 << SECURITY_BITS))
            .expect("the bound must be computable in exact integers");
        let rhs = 4u128.checked_mul(pn).expect("4 p^n must fit");
        assert!(
            lhs < rhs,
            "⛔ THE DRAW DEVIATION IS NOT DOMINATED: {TOTAL_DRAWS} draws at m <= {MAX_M} leave more than \
             2^-{SECURITY_BITS} of statistical distance with DRAW_ELEMS = {DRAW_ELEMS}. Raise DRAW_ELEMS."
        );
        // And show the margin, so a later parameter change that erodes it is visible rather than silent.
        let mut margin = 0u32;
        while rhs >> margin > lhs && margin < 127 {
            margin += 1;
        }
        std::eprintln!(
            "[route-d] DRAW_ELEMS={DRAW_ELEMS}: {TOTAL_DRAWS} draws deviate < 2^-{} total, vs a \
             2^-{SECURITY_BITS} claim",
            SECURITY_BITS + margin - 1
        );
        assert!(margin >= 2, "the deviation should be comfortably under the claim, margin {margin} bit(s)");
    }

    /// ⛔ NON-VACUITY FOR THE BOUND ABOVE: at `DRAW_ELEMS = 1` the same computation must FAIL. A bound
    /// that passed for every parameter would be telling us nothing about this one.
    #[test]
    fn the_deviation_bound_actually_discriminates() {
        const P: u128 = 0x7f00_0001;
        const MAX_M: u128 = 1 << 11;
        const TOTAL_DRAWS: u128 = 160 * 3;
        let lhs = TOTAL_DRAWS * MAX_M * (1u128 << 100);
        assert!(lhs >= 4 * P, "a single field element must NOT satisfy the 100-bit bound");
        assert!(lhs >= 4 * P * P, "two elements must not either");
        std::eprintln!("[route-d] the deviation bound rejects DRAW_ELEMS = 1 and 2, as it must");
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    use p3_challenger::{CanObserve, DuplexChallenger};
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use proptest::prelude::*;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2KoalaBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    /// Build a deterministic duplex challenger from a seed.
    ///
    /// - Permutation: fixed across calls (seed-independent)
    /// - Transcript prefix: derived from `seed`
    ///
    /// Same seed -> byte-identical sample stream.
    fn challenger_with_seed(seed: u64) -> MyChallenger {
        // Permutation: deterministic across all test runs.
        let mut perm_rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut perm_rng);
        let mut challenger = MyChallenger::new(perm);

        // Transcript primer: 8 field elements derived from `seed`. This is
        // what makes two challengers with the same seed byte-identical.
        let mut transcript_rng = SmallRng::seed_from_u64(seed);
        let primer: Vec<F> = (0..8).map(|_| transcript_rng.random()).collect();
        challenger.observe_slice(&primer);
        challenger
    }

    /// Strategy for non-saturated `(domain_size, folding_factor, num_queries)`.
    ///
    /// ```text
    ///   log_folded     in [1, 8]   -> folded in [2, 256]
    ///   folding_factor in [0, 4]
    ///   num_queries    in [1, folded]
    /// ```
    ///
    /// Saturation (`num_queries > folded`) is covered by a dedicated test.
    fn arb_query_params() -> impl Strategy<Value = (usize, usize, usize)> {
        (1usize..=8, 0usize..=4).prop_flat_map(|(log_folded, folding_factor)| {
            let folded = 1usize << log_folded;
            let domain_size = folded << folding_factor;
            (1usize..=folded)
                .prop_map(move |num_queries| (domain_size, folding_factor, num_queries))
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_get_challenge_stir_queries_invariants(
            (domain_size, folding_factor, num_queries) in arb_query_params(),
            seed in any::<u64>(),
        ) {
            // Five invariants, one challenger setup per case:
            // (1) length
            // (2) range
            // (3) strict sort
            // (4) distinct
            // (5) deterministic replay
            let folded_domain_size = domain_size >> folding_factor;

            // First run: seed -> queries_a.
            let mut challenger_a = challenger_with_seed(seed);
            let queries_a = get_challenge_stir_queries::<MyChallenger, F, EF>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger_a,
            );

            // (1) length == request.
            prop_assert_eq!(queries_a.len(), num_queries);

            // (2) every index in [0, folded_domain_size).
            for &q in &queries_a {
                prop_assert!(
                    q < folded_domain_size,
                    "out of range: {} not in [0, {})", q, folded_domain_size
                );
            }

            // (3) strictly ascending.
            prop_assert!(
                queries_a.windows(2).all(|w| w[0] < w[1]),
                "not sorted: {:?}", queries_a
            );

            // (4) pairwise distinct -- redundant given (3); set check
            //     guards against a future weakening of (3).
            let unique: BTreeSet<usize> = queries_a.iter().copied().collect();
            prop_assert_eq!(unique.len(), num_queries, "duplicates in {:?}", queries_a);

            // (5) determinism: same seed -> byte-identical output.
            //     This is the prover/verifier Fiat-Shamir replay property.
            let mut challenger_b = challenger_with_seed(seed);
            let queries_b = get_challenge_stir_queries::<MyChallenger, F, EF>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger_b,
            );
            prop_assert_eq!(queries_a, queries_b);
        }
    }

    #[test]
    fn saturates_when_num_queries_exceeds_domain() {
        // WHIR final-round regime: ask for more queries than positions.
        //
        //   folded_domain_size = 16 >> 2 = 4
        //   num_queries        = 75            (>> 4)
        //   expected           = [0, 1, 2, 3]  (full domain, ascending)
        let domain_size = 16usize;
        let folding_factor = 2usize;
        let folded_domain_size = domain_size >> folding_factor;
        let num_queries = 75usize;

        let mut challenger = challenger_with_seed(0xC0FFEE);
        let queries = get_challenge_stir_queries::<MyChallenger, F, EF>(
            domain_size,
            folding_factor,
            num_queries,
            &mut challenger,
        );

        // Length capped at the domain; output is the full domain ascending.
        assert_eq!(queries.len(), folded_domain_size);
        assert_eq!(queries, (0..folded_domain_size).collect::<Vec<_>>());
    }

    #[test]
    fn empirical_uniformity_single_query() {
        // Histogram-based regression detector for uniform sampling.
        //
        //   N = 16 buckets, M = 4096 draws, expected = M/N = 256
        //
        // Hoeffding on the bucket indicator 1[q == k]:
        //
        //   Pr[ |count_k - 256| >= t ]  <=  2 * exp(-2 t^2 / M)
        //
        // With t = 160:
        //
        //   per-bucket    : 2  * exp(-12.5) ~ 7.4e-6
        //   union 16 bins : 32 * exp(-12.5) ~ 1.2e-4
        //
        // Cryptographic uniformity rests on the field-side rejection
        // primitive; this test only catches gross regressions.
        const FOLDED_DOMAIN_SIZE: usize = 16;
        const NUM_DRAWS: usize = 4096;
        const TOLERANCE: usize = 160;

        // Pick parameters so the folded domain has exactly 16 positions.
        let domain_size: usize = 64;
        let folding_factor: usize = 2;
        assert_eq!(domain_size >> folding_factor, FOLDED_DOMAIN_SIZE);

        // Histogram one draw per challenger seed.
        let mut counts = [0usize; FOLDED_DOMAIN_SIZE];
        // Histogram: one draw per seed.
        for seed in 0u64..NUM_DRAWS as u64 {
            let mut challenger = challenger_with_seed(seed);
            let q = get_challenge_stir_queries::<MyChallenger, F, EF>(
                domain_size,
                folding_factor,
                1,
                &mut challenger,
            );
            assert_eq!(q.len(), 1);
            counts[q[0]] += 1;
        }

        // Each bucket within +/- TOLERANCE of expected count.
        let expected = NUM_DRAWS / FOLDED_DOMAIN_SIZE;
        for (bucket, &count) in counts.iter().enumerate() {
            let deviation = count.abs_diff(expected);
            assert!(
                deviation <= TOLERANCE,
                "bucket {bucket}: count {count} deviates from {expected} by {deviation} > {TOLERANCE}; counts = {counts:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ROUTE D — THE SAME QUERY DISTRIBUTION, DRAWN IN FIXED TIME (MonerousD §BK-3)
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// `get_challenge_stir_queries` above is correct and is not a circuit. It nests three data-dependent
// loops: a distinctness rejection loop, a field-side rejection loop inside `sample_uniform_bits`, and a
// sort. MEASURED on a real committed-carrier transcript (MonerousD §BK-2): round 0 took 165 draws for
// t = 160, round 1 took 192, and the FINAL round — where `num_queries >= folded_domain_size`, so the
// target is the whole domain — took 632 draws for 128 positions and is a coupon collector whose count
// has no upper bound at all. An AIR has fixed rows, so a recursive verifier cannot replay any of that;
// bounding it with a cap would make a rare transcript unprovable, which is a liveness hole.
//
// The functions below draw the SAME DISTRIBUTION in a fixed number of operations:
//
//   * the saturated case is not sampled at all — when `t == folded_domain_size` the answer is
//     `[0, 1, ..., N-1]` for every transcript, so nothing about it is a function of the challenger;
//   * distinctness comes from a partial Fisher-Yates selection rather than from rejection, which is
//     sampling WITHOUT REPLACEMENT in exactly `t` draws — the identical uniform `t`-subset, by a
//     different algorithm, NOT a weaker substitute for it;
//   * each draw is built from a fixed number of field elements rather than by rejection, leaving a
//     deviation from uniform that is provably below the security level being claimed.

/// Base field elements combined into one fixed-width draw.
///
/// ⛔ WHY FOUR, AND WHY THIS IS NOT A TUNING KNOB. A uniform value on a range that does not divide a
/// prime field's order needs either rejection (unbounded time, exact) or excess entropy (bounded time,
/// exponentially small deviation) — there is no third construction. With `p ~ 2^31` and a folded domain
/// at most `2^11`, combining `n` elements leaves statistical distance at most `M / (4 p^n)`, so
/// `n = 4` gives `<= 2^-115` per draw and `~2^-106` union-bounded over a whole proof's draws. That is
/// BELOW the 100-bit level these parameters target, so it cannot be the binding term in the soundness
/// error. `draw_deviation_is_below_the_claimed_security_level` computes the bound in exact integer
/// arithmetic rather than asserting it.
pub const DRAW_ELEMS: usize = 4;

/// One draw, uniform on `[0, m)` up to the deviation [`DRAW_ELEMS`] documents, in FIXED time.
///
/// Horner over `DRAW_ELEMS` field elements: `x = ((f0·p + f1)·p + f2)·p + f3 < p^4`, which for a 31-bit
/// prime is under 2^124 and so cannot overflow the `u128` it is accumulated in.
pub fn draw_below<Challenger, F>(challenger: &mut Challenger, m: usize) -> usize
where
    Challenger: CanSample<F>,
    F: PrimeField64,
{
    assert!(m > 0, "a draw range must be non-empty");
    let p = u128::from(F::ORDER_U64);
    let mut x: u128 = 0;
    for _ in 0..DRAW_ELEMS {
        let f: F = challenger.sample();
        x = x * p + u128::from(f.as_canonical_u64());
    }
    (x % m as u128) as usize
}

/// Sample the STIR query indices in fixed time: `num_queries` INDEPENDENT draws of
/// [`draw_below`]`(folded_domain_size)`, in draw order, WITH replacement.
///
/// Why with replacement (2026-09-27, the O(1)-openings recursion, spec in
/// `docs/O1-OPENINGS-RECURSION-SPEC.md` § "The STIR sampler decision"): WHIR's proximity soundness is
/// the `(1 − δ)^t` bound over `t` independent queries — with replacement IS the analyzed setting
/// (`SecurityAssumption::queries` computes `t` from exactly that bound); distinctness was a proof-size
/// optimization, never a soundness input. The previous partial Fisher–Yates drew modulo the
/// NON-power-of-two `n − i` and kept a data-dependent swap map, which the recursive verifier cannot
/// mirror at a fixed size; a power-of-two domain makes every draw the low `k` bits of the four-sample
/// fold (KoalaBear `p ≡ 1 (mod 2^24)`), ~180 constraints per query in-circuit. The per-draw deviation
/// bound of [`DRAW_ELEMS`] is unchanged. Cons: a duplicate index re-ships its Merkle path — expected
/// `t²/2n` duplicates per round (≈ 0.08 at `t = 100`, `n = 2^16`), i.e. ~0 bytes. Consensus-affecting
/// (every WHIR transcript), at height 1 like every change. The prover and the verifier share this one
/// function, and a duplicate query is simply verified twice.
pub fn stir_queries_fixed_time<Challenger, F, EF>(
    domain_size: usize,
    folding_factor: usize,
    num_queries: usize,
    challenger: &mut Challenger,
) -> Vec<usize>
where
    Challenger: FieldChallenger<F>,
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let folded_domain_size = domain_size >> folding_factor;
    // O1-INFINITY-REVIEWED: exactly `num_queries` entries — a security constant of the round config
    // (f(λ, rate)), never a function of any chain total; the vector lives for one verification.
    (0..num_queries).map(|_| draw_below::<Challenger, F>(challenger, folded_domain_size)).collect()
}

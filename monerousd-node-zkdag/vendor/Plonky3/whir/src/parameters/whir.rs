//! Derived WHIR protocol configuration computed from user-facing parameters.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Deref;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field, TwoAdicField};

use super::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use crate::pcs::proof::WhirProof;

/// Derived configuration for a single intermediate WHIR round.
///
/// All values are computed from the user-facing protocol parameters
/// and the accumulated state from prior rounds.
/// MonerousD 2026-10-04 (H12): a grind requirement in bits → the integer grind a round buys. A proven regime rounds UP (the
/// requirement is a lower bound); the CapacityBound conjecture keeps the historical truncation — see the round fields below.
fn round_pow(bits: f64, regime: SecurityAssumption) -> usize {
    if matches!(regime, SecurityAssumption::CapacityBound) {
        bits as usize
    } else {
        bits.ceil() as usize
    }
}

#[derive(Debug, Clone)]
pub struct RoundConfig<F> {
    /// Proof-of-work difficulty (in bits) for the STIR query phase.
    pub pow_bits: usize,
    /// Proof-of-work difficulty (in bits) for the folding sumcheck phase.
    pub folding_pow_bits: usize,
    /// Number of STIR proximity queries to make in this round.
    pub num_queries: usize,
    /// Number of out-of-domain evaluation samples.
    pub ood_samples: usize,
    /// Number of multilinear variables remaining after folding in this round.
    pub num_variables: usize,
    /// Number of variables folded in this round.
    pub folding_factor: usize,
    /// Log-inverse rate of the codeword committed after this round.
    pub log_inv_rate: usize,
    /// Size of the evaluation domain before folding in this round.
    pub domain_size: usize,
    /// Generator of the folded evaluation domain after this round's fold.
    pub folded_domain_gen: F,
}

/// Fully derived WHIR protocol configuration.
///
/// Built from user-facing protocol parameters plus the polynomial size.
///
/// Contains all precomputed values needed by the prover and verifier.
#[derive(Debug, Clone)]
pub struct WhirConfig<EF, F, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Number of variables in the original multilinear polynomial.
    pub num_variables: usize,
    /// Protocol parameters.
    pub params: ProtocolParameters,
    /// Per-round derived configuration for each intermediate STIR round.
    pub round_parameters: Vec<RoundConfig<F>>,
    /// Number of out-of-domain samples during the commitment phase.
    pub commitment_ood_samples: usize,
    /// PoW bits for the initial folding sumcheck (before any STIR rounds).
    pub starting_folding_pow_bits: usize,
    /// Number of STIR queries in the final proximity test.
    pub final_queries: usize,
    /// PoW bits for the final STIR query phase.
    pub final_pow_bits: usize,
    /// Number of sumcheck rounds in the final phase.
    pub final_sumcheck_rounds: usize,
    /// PoW bits for the final folding sumcheck.
    pub final_folding_pow_bits: usize,
    /// ⭐ SPEED R4-G — each folding sub-round's own grind, when the configuration sizes it at the code that fold acts
    /// on ([`WhirConfig::with_fold_grinds_at_the_folded_code`]). `None`: every sub-round of a group grinds the group's
    /// one figure (`starting_folding_pow_bits`, each round's `folding_pow_bits`) — the configuration `new` derives.
    /// Read only through [`WhirConfig::starting_fold_grinds`] and [`WhirConfig::round_fold_grinds`], by the prover and
    /// the verifier alike.
    pub fold_grinds: Option<FoldGrinds>,
    /// Phantom marker for the extension field type.
    pub _extension_field: PhantomData<EF>,
    /// Phantom marker for the challenger type.
    pub _challenger: PhantomData<Challenger>,
}

/// ⭐ SPEED R4-G — the proof-of-work bits of every folding sub-round: `starting[s]` for the first group's sub-round
/// `s`, `rounds[i][s]` for the group that follows STIR round `i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldGrinds {
    pub starting: Vec<usize>,
    pub rounds: Vec<Vec<usize>>,
}

impl<EF, F, Challenger> Deref for WhirConfig<EF, F, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Target = ProtocolParameters;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

impl<EF, F, Challenger> WhirConfig<EF, F, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Construct an empty proof with this configuration.
    pub fn empty_proof<MT: Mmcs<F>>(&self) -> WhirProof<F, EF, MT> {
        WhirProof::from_protocol_parameters(&self.params, self.num_variables)
    }

    /// Derive a full protocol configuration from user-facing parameters.
    #[allow(clippy::too_many_lines)]
    pub fn new(num_variables: usize, whir_parameters: ProtocolParameters) -> Self {
        // ---------------------------------------------------------------
        // Phase 1: Validate inputs and set up global constants.
        // ---------------------------------------------------------------

        // Preserve the original variable count; the mutable copy below
        // tracks the remaining variables as we consume them round by round.
        let initial_num_variables = num_variables;

        // Reject folding factors that are incompatible with the polynomial size.
        whir_parameters
            .folding_factor
            .check_validity(num_variables)
            .unwrap();

        // PoW contributes an independent additive term to security,
        // so the algebraic protocol only needs to cover the remainder.
        let protocol_security_level = whir_parameters
            .security_level
            .saturating_sub(whir_parameters.pow_bits);

        // Number of bits in the extension field; upper-bounds all per-element errors.
        let field_size_bits = EF::bits();

        // Mutable state that evolves as we derive per-round parameters.
        let mut log_inv_rate = whir_parameters.starting_log_inv_rate;
        let mut num_variables = num_variables;

        // Initial evaluation domain: 2^(num_variables + log_inv_rate) points.
        let log_domain_size = num_variables + log_inv_rate;
        let mut domain_size: usize = 1 << log_domain_size;

        // ---------------------------------------------------------------
        // Phase 2: Two-adicity guard.
        // ---------------------------------------------------------------
        //
        // After the first fold the domain has size 2^log_folded_domain_size.
        // We restrict this to F::TWO_ADICITY so that:
        //   - FFT twiddle factors stay in the base field (faster).
        //   - WHIR query equality polynomials stay in the base field.
        //
        // A larger folding_factor_0 pushes the folded domain below the limit.
        // This does NOT restrict how much data can be committed.
        let log_folded_domain_size = log_domain_size - whir_parameters.folding_factor.at_round(0);
        assert!(
            log_folded_domain_size <= F::TWO_ADICITY,
            "Increase folding_factor_0"
        );

        // ---------------------------------------------------------------
        // Phase 3: Determine round structure.
        // ---------------------------------------------------------------

        // How many intermediate STIR rounds, and how many variables remain
        // for the final direct-send sumcheck.
        let (num_rounds, final_sumcheck_rounds) = whir_parameters
            .folding_factor
            .compute_number_of_rounds(num_variables);

        let round_log_inv_rates = if whir_parameters.round_log_inv_rates.is_empty() {
            let mut rates = Vec::with_capacity(num_rounds);
            let mut rate = whir_parameters.starting_log_inv_rate;
            for round in 0..num_rounds {
                rate += whir_parameters.folding_factor.at_round(round) - 1;
                rates.push(rate);
            }
            rates
        } else {
            assert_eq!(
                whir_parameters.round_log_inv_rates.len(),
                num_rounds,
                "Explicit codeword rates must have one entry per intermediate WHIR round"
            );
            whir_parameters.round_log_inv_rates.clone()
        };
        if let FoldingFactor::PerRound(factors) | FoldingFactor::PerRoundSendAt(factors, _) = &whir_parameters.folding_factor {
            assert_eq!(
                factors.len(),
                num_rounds + 1,
                "Explicit folding factors must have one entry per folding phase"
            );
        }

        // OOD samples for the commitment phase (before any folding).
        let commitment_ood_samples = whir_parameters.soundness_type.determine_ood_samples(
            whir_parameters.security_level,
            num_variables,
            log_inv_rate,
            field_size_bits,
        );

        // PoW difficulty for the very first folding sumcheck.
        // the regime decides how every grind requirement is rounded (`round_pow`); read before the parameters move
        let regime = whir_parameters.soundness_type;
        let starting_folding_pow_bits = whir_parameters.soundness_type.folding_pow_bits(
            whir_parameters.security_level,
            field_size_bits,
            num_variables,
            log_inv_rate,
        );

        // ---------------------------------------------------------------
        // Phase 4: Per-round parameter derivation.
        // ---------------------------------------------------------------
        //
        // After the initial fold, each round i:
        //   1. Reads the configured/derived code rate after folding.
        //   2. Determines query count from the old rate (queries test
        //      proximity to the code *before* this round's fold).
        //   3. Determines OOD sample count from the new rate.
        //   4. Derives PoW for both the query and folding sub-steps.
        //   5. Records the domain generator for the folded evaluation domain.

        let mut round_parameters = Vec::with_capacity(num_rounds);

        // Subtract the first-round folding factor; the loop below
        // handles subsequent rounds.
        num_variables -= whir_parameters.folding_factor.at_round(0);

        for (round, &next_rate) in round_log_inv_rates.iter().enumerate() {
            let folding_factor = whir_parameters.folding_factor.at_round(round);
            assert!(
                next_rate <= log_inv_rate + folding_factor,
                "Codeword rate would require growing the RS domain"
            );
            let rs_reduction_factor = log_inv_rate + folding_factor - next_rate;

            // Queries use the *old* rate; OOD and folding use the *new* rate.
            // Number of STIR proximity queries at the current (old) rate.
            let num_queries = whir_parameters
                .soundness_type
                .queries(protocol_security_level, log_inv_rate);

            // OOD samples needed at the post-fold (new) rate.
            let ood_samples = whir_parameters.soundness_type.determine_ood_samples(
                whir_parameters.security_level,
                num_variables,
                next_rate,
                field_size_bits,
            );

            // Two independent error sources bound the STIR round:
            //   - query_error: (1 - delta)^num_queries proximity test.
            //   - combination_error: random linear combination of OOD + queries.
            // The weaker bound determines how much PoW is needed.
            let query_error = whir_parameters
                .soundness_type
                .queries_error(log_inv_rate, num_queries);
            let combination_error = whir_parameters.soundness_type.queries_combination_error(
                field_size_bits,
                num_variables,
                next_rate,
                ood_samples,
                num_queries,
            );

            // PoW bridges the gap between the target and the weaker bound.
            let pow_bits = 0_f64
                .max(whir_parameters.security_level as f64 - (query_error.min(combination_error)));

            // PoW difficulty for the folding sumcheck at the new rate.
            let folding_pow_bits = whir_parameters.soundness_type.folding_pow_bits(
                whir_parameters.security_level,
                field_size_bits,
                num_variables,
                next_rate,
            );

            let next_folding_factor = whir_parameters.folding_factor.at_round(round + 1);

            // Generator of the two-adic subgroup for the folded domain.
            let folded_domain_gen =
                F::two_adic_generator(domain_size.ilog2() as usize - folding_factor);

            round_parameters.push(RoundConfig {
                // MonerousD 2026-10-04 (H12): a grind requirement is a LOWER bound on the bits a term must buy back, so in
                // every regime the proven-soundness pin certifies (Johnson bound, unique decoding) it rounds UP — `as usize`
                // truncated, and every live carrier scored 99.0–99.6 proven bits against a 100 target (MEASURED: queries
                // first, then the folds, `scratchpad/live-jb3.log`). ⛔ Under the CapacityBound CONJECTURE the old
                // truncation stays: only the recursive certificate is sized there (an OPEN H12 row at 59 proven bits), and
                // rounded up its deepest fold needs 31 bits, above the verifier row's 30-bit grind table — it resolves with
                // the stream-and-commit banks (docs/H12 §12), whose Johnson-bound T = 2^15 shape folds with grinds ≤ 2^25.
                pow_bits: round_pow(pow_bits, regime),
                folding_pow_bits: round_pow(folding_pow_bits, regime),
                num_queries,
                ood_samples,
                num_variables,
                folding_factor,
                log_inv_rate: next_rate,
                domain_size,
                folded_domain_gen,
            });

            // Advance mutable state for the next iteration.
            num_variables -= next_folding_factor;
            log_inv_rate = next_rate;
            domain_size >>= rs_reduction_factor;
        }

        // ---------------------------------------------------------------
        // Phase 5: Final round parameters.
        // ---------------------------------------------------------------

        // Final proximity queries at the last accumulated rate.
        let final_queries = whir_parameters
            .soundness_type
            .queries(protocol_security_level, log_inv_rate);

        // PoW for the final query phase: covers the gap between the
        // target and the query error at the final rate.
        let final_pow_bits = 0_f64.max(
            whir_parameters.security_level as f64
                - whir_parameters
                    .soundness_type
                    .queries_error(log_inv_rate, final_queries),
        );

        // The final folding sumcheck error is bounded by 1/|F|,
        // so PoW = max(0, security_level - (field_size - 1)).
        let final_folding_pow_bits =
            0_f64.max(whir_parameters.security_level as f64 - (field_size_bits - 1) as f64);

        // Validate construction
        assert_eq!(
            initial_num_variables,
            whir_parameters
                .folding_factor
                .total_number(round_parameters.len())
                + final_sumcheck_rounds
        );

        Self {
            params: whir_parameters,
            commitment_ood_samples,
            num_variables: initial_num_variables,
            starting_folding_pow_bits: round_pow(starting_folding_pow_bits, regime),
            round_parameters,
            final_queries,
            final_pow_bits: round_pow(final_pow_bits, regime),
            final_sumcheck_rounds,
            final_folding_pow_bits: round_pow(final_folding_pow_bits, regime),
            fold_grinds: None,
            _extension_field: PhantomData,
            _challenger: PhantomData,
        }
    }

    /// ⭐⭐ SPEED R4-G (2026-11-10) — SIZE EACH FOLD'S GRIND AT THE CODE THAT FOLD ACTS ON.
    ///
    /// `new` derives ONE grind per folding group from the group's START: the proximity-gaps error of the code with
    /// `num_variables` variables at the group's rate, used for all `k` sumcheck sub-rounds of the group. But sub-round
    /// `s` (1-based) does not fold that code. The committed word is `2^k` interleaved codewords of the small code
    /// (dimension `2^(num_variables − k)`, the rows the Merkle tree opens); sub-round `s` combines them pairwise with
    /// one challenge, `2^(k−s)` pairs at once. The mutual-correlated-agreement bound this file already uses for one
    /// pair (BCSS25 Theorem 1.5 in the Johnson regime, [`SecurityAssumption::prox_gaps_error`]) is LINEAR in the block
    /// length, so its union over those `2^(k−s)` pairs is the same bound at block length `2^(k−s)` times the small
    /// code's: the code with `num_variables − s` variables at the same rate. That is the code named for sub-round `s`
    /// in WHIR's round-by-round soundness (ACFY24, the fold errors `ε^fold_{i,s}` over `RS[F, L^(2^s), m − s]`).
    /// So sub-round `s` is scored — and ground — at `num_variables − s`: one bit less per fold where the bound is the
    /// binding term. Every figure is `folding_pow_bits` itself at that size, so the sumcheck term and the rounding of
    /// the regime are exactly `new`'s.
    ///
    /// MEASURED why (two real nodes, 2026-11-10, a stack sample of a proving node): the fold grinds were 27 % of all
    /// proving work and 26 % of a proving thread's wall time. At the block proofs' shape (23 variables, rate 1/4, groups
    /// of 4) the schedule is 21,21,21,21 / 19,… / 18,… / 16,… = 11.8 million candidates an opening; sized per fold it
    /// is 20,19,18,17 / 18,17,16,15 / 17,16,15,14 / 15,14,13,12 = 2.76 million.
    /// Not the tightest reading on record: the WHIR authors' reference implementation scores every sub-round of a
    /// group at the fully interleaved code (`num_variables − k`, no union over the pairs; `WizardOfMenlo/whir`,
    /// `irs_commit.rs::rbr_soundness_fold_prox_gaps`), four bits under `new` at this shape. That value is not taken
    /// here; this one needs nothing beyond the pair bound `new` already rests on.
    /// The target does not move: each sub-round's error plus its grind is at least `security_level` bits, and
    /// `usdm_decider::committed_air::proven_bits` scores every sub-round of every production shape against it.
    /// Opt-in per configuration: a configuration that does not call this keeps `new`'s schedule bit for bit, and so
    /// does every proof and every in-circuit verifier built on it.
    /// cons: none on bytes (a grinded round carries its two-word witness as before) or on the verifier (the same
    /// check at a lower difficulty); the configuration holds one small list per folding group.
    #[must_use]
    pub fn with_fold_grinds_at_the_folded_code(mut self) -> Self {
        let (regime, level, field_size_bits) = (self.params.soundness_type, self.params.security_level, EF::bits());
        let group = |num_variables: usize, log_inv_rate: usize, folds: usize| -> Vec<usize> {
            (1..=folds)
                .map(|s| round_pow(regime.folding_pow_bits(level, field_size_bits, num_variables - s, log_inv_rate), regime))
                .collect()
        };
        let starting = group(self.num_variables, self.params.starting_log_inv_rate, self.folding_factor(0));
        let rounds = self
            .round_parameters
            .iter()
            .enumerate()
            .map(|(i, rc)| group(rc.num_variables, rc.log_inv_rate, self.folding_factor(i + 1)))
            .collect();
        self.fold_grinds = Some(FoldGrinds { starting, rounds });
        self
    }

    /// The proof-of-work bits of the FIRST folding group, one per sub-round (the prover grinds them, the verifier
    /// checks them): the per-fold list when the configuration carries one, else the group's one figure for each.
    #[must_use]
    pub fn starting_fold_grinds(&self) -> Vec<usize> {
        match &self.fold_grinds {
            Some(g) => g.starting.clone(),
            None => alloc::vec![self.starting_folding_pow_bits; self.folding_factor(0)],
        }
    }

    /// The proof-of-work bits of the folding group that follows STIR round `round_index`, one per sub-round.
    #[must_use]
    pub fn round_fold_grinds(&self, round_index: usize) -> Vec<usize> {
        match &self.fold_grinds {
            Some(g) => g.rounds[round_index].clone(),
            None => alloc::vec![self.round_parameters[round_index].folding_pow_bits; self.folding_factor(round_index + 1)],
        }
    }

    /// Returns the size of the initial evaluation domain.
    ///
    /// This is the size of the domain used to evaluate the original multilinear polynomial
    /// before any folding or reduction steps are applied in the WHIR protocol.
    ///
    /// It is computed as:
    ///
    /// \begin{equation}
    /// 2^{\text{num\_variables} + \text{starting\_log\_inv\_rate}}
    /// \end{equation}
    ///
    /// - `num_variables` is the number of variables in the original multivariate polynomial.
    /// - `starting_log_inv_rate` is the initial inverse rate of the Reed-Solomon code,
    ///   controlling redundancy relative to the degree.
    ///
    /// # Returns
    /// A power-of-two value representing the number of evaluation points in the starting domain.
    pub const fn starting_domain_size(&self) -> usize {
        1 << (self.num_variables + self.params.starting_log_inv_rate)
    }

    /// Returns the number of intermediate STIR rounds (excludes the final round).
    pub const fn n_rounds(&self) -> usize {
        self.round_parameters.len()
    }

    /// Returns how many bits the RS domain shrinks by at the given round.
    pub fn rs_reduction_factor(&self, round: usize) -> usize {
        let previous_log_inv_rate = if round == 0 {
            self.params.starting_log_inv_rate
        } else {
            self.round_parameters[round - 1].log_inv_rate
        };
        previous_log_inv_rate + self.folding_factor(round)
            - self.round_parameters[round].log_inv_rate
    }

    /// Returns the log2 size of the largest FFT
    /// (At commitment we perform 2^folding_factor FFT of size 2^max_fft_size)
    pub fn max_fft_size(&self) -> usize {
        self.num_variables + self.params.starting_log_inv_rate - self.folding_factor(0)
    }

    /// Returns whether all PoW difficulties are within the configured maximum.
    ///
    /// Checks the starting, final, and per-round PoW bits against the ceiling.
    /// Returns false if any value exceeds the limit.
    pub fn check_pow_bits(&self) -> bool {
        let max_bits = self.params.pow_bits;

        // Check the main pow bits values
        if self.starting_folding_pow_bits > max_bits
            || self.final_pow_bits > max_bits
            || self.final_folding_pow_bits > max_bits
        {
            return false;
        }

        // Check all round parameters
        self.round_parameters
            .iter()
            .all(|r| r.pow_bits <= max_bits && r.folding_pow_bits <= max_bits)
    }

    /// Retrieves the folding factor for a given round.
    pub fn folding_factor(&self, round: usize) -> usize {
        self.params.folding_factor.at_round(round)
    }

    /// Compute the synthetic or derived `RoundConfig` for the final phase.
    ///
    /// - If no folding rounds were configured, constructs a fallback config
    ///   based on the starting domain and folding factor.
    /// - If rounds were configured, derives the final config by adapting
    ///   the last round's values for the final folding phase.
    ///
    /// This is used by the verifier when verifying the final polynomial,
    /// ensuring consistent challenge selection and STIR constraint handling.
    pub fn final_round_config(&self) -> RoundConfig<F> {
        if self.round_parameters.is_empty() {
            // No intermediate rounds: the polynomial was small enough that
            // the initial fold leads directly to the final phase.
            // Use the starting domain and initial folding factor.
            RoundConfig {
                num_variables: self.num_variables - self.folding_factor(0),
                folding_factor: self.folding_factor(self.n_rounds()),
                num_queries: self.final_queries,
                pow_bits: self.final_pow_bits,
                log_inv_rate: self.params.starting_log_inv_rate,
                domain_size: self.starting_domain_size(),
                folded_domain_gen: F::two_adic_generator(
                    self.starting_domain_size().ilog2() as usize - self.folding_factor(0),
                ),
                ood_samples: 0,
                folding_pow_bits: self.final_folding_pow_bits,
            }
        } else {
            // Apply the last round's domain reduction to get the domain
            // size entering the final phase.
            let rs_reduction_factor = self.rs_reduction_factor(self.n_rounds() - 1);
            let folding_factor = self.folding_factor(self.n_rounds());

            let last = self.round_parameters.last().unwrap();

            // The domain shrinks by the RS reduction factor from the last round.
            let domain_size = last.domain_size >> rs_reduction_factor;

            // Generator for the final folded domain.
            let folded_domain_gen = F::two_adic_generator(
                domain_size.ilog2() as usize - self.folding_factor(self.n_rounds()),
            );

            RoundConfig {
                // Variables remaining after this final fold.
                num_variables: last.num_variables - folding_factor,
                folding_factor,
                num_queries: self.final_queries,
                pow_bits: self.final_pow_bits,
                log_inv_rate: last.log_inv_rate,
                domain_size,
                folded_domain_gen,
                // Inherit OOD count from the last intermediate round.
                ood_samples: last.ood_samples,
                folding_pow_bits: self.final_folding_pow_bits,
            }
        }
    }

    /// Returns the inverse rate of the codeword committed after an
    /// intermediate round.
    pub fn inv_rate(&self, round: usize) -> usize {
        1 << self.round_parameters[round].log_inv_rate
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::parameters::{FoldingFactor, SecurityAssumption};

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    /// Generates default WHIR parameters
    fn default_whir_params() -> ProtocolParameters {
        ProtocolParameters {
            hiding: false,
            security_level: 100,
            pow_bits: 20,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::ConstantFromSecondRound(4, 4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        }
    }

    #[test]
    fn test_whir_config_creation() {
        let params = default_whir_params();

        let config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        assert_eq!(config.security_level, 100);
        assert_eq!(config.params.pow_bits, 20);
        assert_eq!(config.soundness_type, SecurityAssumption::CapacityBound);
    }

    #[test]
    fn test_n_rounds() {
        let params = default_whir_params();
        let config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        assert_eq!(config.n_rounds(), config.round_parameters.len());
    }

    #[test]
    fn test_explicit_round_log_inv_rates() {
        let mut params = default_whir_params();
        params.folding_factor = FoldingFactor::Constant(4);
        params.round_log_inv_rates = vec![3, 2];

        let config = WhirConfig::<F, F, MyChallenger>::new(16, params);

        assert_eq!(config.round_parameters[0].log_inv_rate, 3);
        assert_eq!(config.round_parameters[1].log_inv_rate, 2);
        assert_eq!(config.rs_reduction_factor(0), 2);
        assert_eq!(config.rs_reduction_factor(1), 5);
        assert_eq!(config.inv_rate(0), 1 << 3);
        assert_eq!(config.inv_rate(1), 1 << 2);
    }

    #[test]
    fn test_check_pow_bits_within_limits() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        // Set all values within limits
        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 15;
        config.final_pow_bits = 18;
        config.final_folding_pow_bits = 19;

        // Ensure all rounds are within limits
        config.round_parameters = vec![
            RoundConfig {
                pow_bits: 17,
                folding_pow_bits: 19,
                num_queries: 5,
                ood_samples: 2,
                num_variables: 10,
                folding_factor: 2,
                log_inv_rate: 1,
                domain_size: 10,
                folded_domain_gen: F::from_u64(2),
            },
            RoundConfig {
                pow_bits: 18,
                folding_pow_bits: 19,
                num_queries: 6,
                ood_samples: 2,
                num_variables: 10,
                folding_factor: 2,
                log_inv_rate: 1,
                domain_size: 10,
                folded_domain_gen: F::from_u64(2),
            },
        ];

        assert!(
            config.check_pow_bits(),
            "All values are within limits, check_pow_bits should return true."
        );
    }

    #[test]
    fn test_check_pow_bits_starting_folding_exceeds() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 21; // Exceeds max_pow_bits
        config.final_pow_bits = 18;
        config.final_folding_pow_bits = 19;

        assert!(
            !config.check_pow_bits(),
            "Starting folding pow bits exceeds max_pow_bits, should return false."
        );
    }

    #[test]
    fn test_check_pow_bits_final_pow_exceeds() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 15;
        config.final_pow_bits = 21; // Exceeds max_pow_bits
        config.final_folding_pow_bits = 19;

        assert!(
            !config.check_pow_bits(),
            "Final pow bits exceeds max_pow_bits, should return false."
        );
    }

    #[test]
    fn test_check_pow_bits_round_pow_exceeds() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 15;
        config.final_pow_bits = 18;
        config.final_folding_pow_bits = 19;

        // One round's pow_bits exceeds limit
        config.round_parameters = vec![RoundConfig {
            pow_bits: 21, // Exceeds pow_bits
            folding_pow_bits: 19,
            num_queries: 5,
            ood_samples: 2,
            num_variables: 10,
            folding_factor: 2,
            log_inv_rate: 1,
            domain_size: 10,
            folded_domain_gen: F::from_u64(2),
        }];

        assert!(
            !config.check_pow_bits(),
            "A round has pow_bits exceeding pow_bits, should return false."
        );
    }

    #[test]
    fn test_check_pow_bits_round_folding_pow_exceeds() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 15;
        config.final_pow_bits = 18;
        config.final_folding_pow_bits = 19;

        // One round's folding_pow_bits exceeds limit
        config.round_parameters = vec![RoundConfig {
            pow_bits: 19,
            folding_pow_bits: 21, // Exceeds pow_bits
            num_queries: 5,
            ood_samples: 2,
            num_variables: 10,
            folding_factor: 2,
            log_inv_rate: 1,
            domain_size: 10,
            folded_domain_gen: F::from_u64(2),
        }];

        assert!(
            !config.check_pow_bits(),
            "A round has folding_pow_bits exceeding pow_bits, should return false."
        );
    }

    #[test]
    fn test_check_pow_bits_exactly_at_limit() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 20;
        config.final_pow_bits = 20;
        config.final_folding_pow_bits = 20;

        config.round_parameters = vec![RoundConfig {
            pow_bits: 20,
            folding_pow_bits: 20,
            num_queries: 5,
            ood_samples: 2,
            num_variables: 10,
            folding_factor: 2,
            log_inv_rate: 1,
            domain_size: 10,
            folded_domain_gen: F::from_u64(2),
        }];

        assert!(
            config.check_pow_bits(),
            "All pow_bits are exactly at pow_bits, should return true."
        );
    }

    #[test]
    fn test_check_pow_bits_all_exceed() {
        let params = default_whir_params();
        let mut config = WhirConfig::<F, F, MyChallenger>::new(10, params);

        config.params.pow_bits = 20;
        config.starting_folding_pow_bits = 22;
        config.final_pow_bits = 23;
        config.final_folding_pow_bits = 24;

        config.round_parameters = vec![RoundConfig {
            pow_bits: 25,
            folding_pow_bits: 26,
            num_queries: 5,
            ood_samples: 2,
            num_variables: 10,
            folding_factor: 2,
            log_inv_rate: 1,
            domain_size: 10,
            folded_domain_gen: F::from_u64(2),
        }];

        assert!(
            !config.check_pow_bits(),
            "All values exceed max_pow_bits, should return false."
        );
    }
}

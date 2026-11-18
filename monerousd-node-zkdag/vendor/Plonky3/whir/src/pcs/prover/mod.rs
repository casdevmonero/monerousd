use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Deref;

use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_matrix::extension::FlatMatrixView;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::commit::CodewordRows;
use tracing::instrument;

use crate::constraints::Constraint;
use crate::constraints::statement::{EqStatement, SelectStatement};
use crate::fiat_shamir::domain_separator::DomainSeparator;
use crate::parameters::WhirConfig;
use crate::pcs::committer::writer::commit_extension;
use crate::pcs::proof::{QueryOpening, SumcheckData, WhirProof};
use crate::pcs::utils::stir_queries_fixed_time;
use crate::sumcheck::layout::Layout;
use crate::sumcheck::strategy::{SumcheckProver, VariableOrder};

pub type Proof<W, const DIGEST_ELEMS: usize> = Vec<Vec<[W; DIGEST_ELEMS]>>;
pub type Leafs<F> = Vec<Vec<F>>;

/// THE QUERY OPENINGS, IN PARALLEL AND IN QUERY ORDER (MonerousD 2026-11-03). Each query's Merkle opening is independent of every other:
/// it reads the committed tree and, on a streamed tree, re-derives its rows, so the openings run on direct rayon (the crate's rule: named
/// sites, `p3-maybe-rayon`'s `parallel` stays off) and `collect` returns them in the input's order. The transcript and the statement stay
/// serial in the caller, so a proof's bytes do not depend on the thread count. MEASURED (`sample`, the real joined ledger): 32 % of the
/// WHIR opening was this loop on one thread. MUST-STAY-GREEN: usdm-decider's `a_parallel_prove_is_byte_identical_to_a_one_thread_prove`.
fn open_all<T: Send>(indexes: &[usize], open: impl Fn(usize) -> T + Sync) -> Vec<T> {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    indexes.par_iter().map(|&c| open(c)).collect()
}

/// Per-round prover state with the Merkle authentication shapes
/// baked in for the WHIR commitment scheme.
///
/// - The first round commits to evaluations laid out as a base-field
///   row-major matrix.
/// - Subsequent rounds commit to folded extension-field evaluations,
///   reinterpreted as wider base-field rows so a single Merkle backend
///   handles both shapes.
type WhirRoundState<EF, F, MT> = RoundState<
    EF,
    F,
    <MT as Mmcs<F>>::ProverData<CodewordRows<F>>,
    <MT as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, CodewordRows<F, EF>>>,
>;

/// Active Merkle prover data for the polynomial currently being queried.
#[derive(Debug)]
enum RoundData<BaseData, ExtData> {
    /// Base-field commitment produced by the initial round.
    Base(BaseData),
    /// Extension-field commitment produced by every subsequent folded round.
    Ext(ExtData),
}

/// Per-round state during WHIR proof generation.
///
/// Tracks the sumcheck prover, folding randomness, and Merkle
/// commitments across base and extension field rounds.
#[derive(Debug)]
pub struct RoundState<EF, F, BaseData, ExtData>
where
    F: TwoAdicField + p3_field::PrimeField64,
    EF: ExtensionField<F> + TwoAdicField,
{
    /// Sumcheck prover managing constraint batching and polynomial folding.
    sumcheck_prover: SumcheckProver<F, EF>,
    /// Folding challenges (alpha_1, ..., alpha_k) for the current round.
    folding_randomness: Point<EF>,
    /// Active Merkle prover data for the polynomial currently being queried.
    round_data: RoundData<BaseData, ExtData>,
}

/// WHIR prover bundling the protocol config with its FFT and commitment backends.
#[derive(Debug)]
pub struct WhirProver<EF, F, Dft, MT, Challenger, Layout>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
{
    /// Derived per-protocol parameters and per-round configuration.
    pub config: WhirConfig<EF, F, Challenger>,
    /// FFT engine used to encode polynomials before each commitment.
    pub dft: Dft,
    /// Base-field Merkle commitment scheme used in the initial round.
    pub mmcs: MT,
    /// Extension-field commitment scheme used in every folded round.
    pub extension_mmcs: ExtensionMmcs<F, EF, MT>,
    /// Marker tying the prover to a specific stacked-layout binding mode.
    _marker: PhantomData<Layout>,
}

impl<EF, F, Dft, MT, Challenger, Layout> Deref for WhirProver<EF, F, Dft, MT, Challenger, Layout>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
{
    type Target = WhirConfig<EF, F, Challenger>;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<EF, F, Dft, MT, Challenger, L> WhirProver<EF, F, Dft, MT, Challenger, L>
where
    F: TwoAdicField + Ord + p3_field::PrimeField64,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
    MT: Mmcs<F> + Sync,
    MT::Proof: Send,
    MT::ProverData<CodewordRows<F>>: Sync,
    MT::ProverData<FlatMatrixView<F, EF, CodewordRows<F, EF>>>: Sync,
    L: Layout<F, EF>,
{
    /// Builds a prover from a derived config, an FFT engine, and a base-field MMCS.
    ///
    /// The extension-field MMCS is constructed by wrapping the base-field one,
    /// so callers never have to thread it through manually.
    pub fn new(config: WhirConfig<EF, F, Challenger>, dft: Dft, mmcs: MT) -> Self {
        let extension_mmcs = ExtensionMmcs::new(mmcs.clone());
        Self {
            config,
            dft,
            mmcs,
            extension_mmcs,
            _marker: PhantomData,
        }
    }

    /// Build the Fiat-Shamir domain separator for this protocol instance.
    ///
    /// The domain separator encodes all public protocol parameters into
    /// the transcript so the verifier's challenges are bound to this
    /// specific configuration (see Construction 5.1, step 1).
    pub fn add_domain_separator<const DIGEST_ELEMS: usize>(&self, ds: &mut DomainSeparator<EF, F>)
    where
        EF: TwoAdicField,
    {
        // Encode the public parameters (num_variables, security, rate, etc.).
        ds.commit_statement::<Challenger, DIGEST_ELEMS>(&self.config);
        // Encode the full proof structure (round counts, query counts, etc.).
        ds.add_whir_proof::<Challenger, DIGEST_ELEMS>(&self.config);
    }

    /// Execute the full WHIR proving protocol.
    ///
    /// Performs multi-round sumcheck-based polynomial folding,
    /// producing Merkle authentication paths and constraint evaluations.
    /// ⭐ SPEED R4 (2026-11-10) — before a round's queries are opened from the BASE commitment, the rows those openings
    /// will read are derived together, one sub-coset at a time (`CodewordRows::prime_rows`): the opening used to
    /// recompute each of them alone, a full pass over the coefficients per row. The rows the tree reads are named by
    /// the tree itself ([`Mmcs::rows_read_by_open`]); the derivation is the commit's own (`base_coset_rows`). Nothing
    /// the transcript, the statement or the proof holds changes: an opened row is the same field elements either way.
    #[instrument(skip_all)]
    fn prime_base_rows(&self, indexes: &[usize], data: &MT::ProverData<CodewordRows<F>>) {
        let rows = self.mmcs.rows_read_by_open(indexes, data);
        if let Some(codeword) = self.mmcs.get_matrices(data).first() {
            codeword.prime_rows(&rows, |m, j| p3_sumcheck::commit::base_coset_rows(&self.dft, m, j));
        }
    }

    /// [`Self::prime_base_rows`] for a folded round's EXTENSION commitment (`ext_coset_rows`, its commit's derivation).
    #[instrument(skip_all)]
    fn prime_ext_rows(&self, indexes: &[usize], data: &MT::ProverData<FlatMatrixView<F, EF, CodewordRows<F, EF>>>) {
        let rows = self.extension_mmcs.rows_read_by_open(indexes, data);
        if let Some(codeword) = self.extension_mmcs.get_matrices(data).first() {
            codeword.prime_rows(&rows, |m, j| crate::pcs::committer::writer::ext_coset_rows(&self.dft, m, j));
        }
    }

    #[instrument(skip_all)]
    pub fn prove(
        &self,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        layout: L,
        prover_data: MT::ProverData<CodewordRows<F>>,
    ) where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: CanObserve<MT::Commitment>,
    {
        // The claim-batching challenge is the first transcript action of the proof (`Layout::into_sumcheck`
        // sampled it at the same position before `prove_with_alpha` existed).
        let alpha: EF = challenger.sample_algebra_element();
        self.prove_with_alpha(alpha, proof, challenger, layout, prover_data);
    }

    /// [`Self::prove`] with the claim-batching challenge `alpha` sampled by the caller — for a protocol that
    /// samples every commitment's batching challenge before the first opening runs (the verifier of such a
    /// protocol samples `alpha` itself and passes `layout.constraint(alpha)` to `WhirVerifier::verify`, so the
    /// transcript positions agree).
    #[instrument(skip_all)]
    pub fn prove_with_alpha(
        &self,
        alpha: EF,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        layout: L,
        prover_data: MT::ProverData<CodewordRows<F>>,
    ) where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: CanObserve<MT::Commitment>,
    {
        assert_eq!(self.folding_factor.at_round(0), layout.folding());
        let variable_order = L::variable_order();

        // SPEED R4-G: each sub-round ground at its own difficulty (`WhirConfig::starting_fold_grinds`) — the list the
        // verifier checks.
        let (sumcheck_prover, folding_randomness) = layout.into_sumcheck_with_alpha_each(
            alpha,
            &mut proof.initial_sumcheck,
            &self.starting_fold_grinds(),
            challenger,
        );

        let mut round_state = RoundState {
            sumcheck_prover,
            folding_randomness,
            round_data: RoundData::Base(prover_data),
        };

        // Run each WHIR folding round.
        for round in 0..=self.n_rounds() {
            self.round(round, proof, challenger, &mut round_state, variable_order);
        }
    }

    #[instrument(skip_all, fields(round_number = round_index, log_size = self.num_variables - self.params.folding_factor.total_number(round_index)))]
    #[allow(clippy::too_many_lines)]
    fn round(
        &self,
        round_index: usize,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        round_state: &mut WhirRoundState<EF, F, MT>,
        variable_order: VariableOrder,
    ) where
        Challenger: CanObserve<MT::Commitment>,
    {
        let folded_evaluations = &round_state.sumcheck_prover.evals();
        let num_variables =
            self.num_variables - self.params.folding_factor.total_number(round_index);
        assert_eq!(num_variables, folded_evaluations.num_variables());

        // Final round: send polynomial in the clear.
        if round_index == self.n_rounds() {
            return self.final_round(round_index, proof, challenger, round_state);
        }

        let round_params = &self.round_parameters[round_index];
        let folding_factor_next = self.params.folding_factor.at_round(round_index + 1);
        let inv_rate = self.inv_rate(round_index);

        let (root, prover_data) = commit_extension(
            variable_order,
            &self.dft,
            &self.extension_mmcs,
            folded_evaluations,
            folding_factor_next,
            inv_rate,
        );

        // Observe the round commitment.
        challenger.observe(root.clone());
        proof.rounds[round_index].commitment = Some(root);

        // OOD sampling.
        let mut ood_statement = EqStatement::initialize(num_variables);
        let mut ood_answers = Vec::with_capacity(round_params.ood_samples);
        (0..round_params.ood_samples).for_each(|_| {
            let point =
                Point::expand_from_univariate(challenger.sample_algebra_element(), num_variables);
            let eval = round_state.sumcheck_prover.eval(&point);
            challenger.observe_algebra_element(eval);

            ood_answers.push(eval);
            ood_statement.add_evaluated_constraint(point, eval);
        });
        proof.rounds[round_index].ood_answers = ood_answers;

        // PoW grinding: prevents query manipulation by forcing work after committing.
        if round_params.pow_bits > 0 {
            proof.rounds[round_index].pow_witness = challenger.grind(round_params.pow_bits);
        }

        challenger.sample();

        // STIR query sampling.
        let stir_challenges_indexes = stir_queries_fixed_time::<Challenger, F, EF>(
            round_params.domain_size,
            self.params.folding_factor.at_round(round_index),
            round_params.num_queries,
            challenger,
        );

        proof.query_indices.push(stir_challenges_indexes.clone());
        let mut stir_statement = SelectStatement::initialize(num_variables);
        let mut queries = Vec::with_capacity(stir_challenges_indexes.len());
        let query_randomness = match variable_order {
            VariableOrder::Prefix => round_state.folding_randomness.clone(),
            VariableOrder::Suffix => round_state.folding_randomness.reversed(),
        };

        // Open Merkle proofs and evaluate folded polynomials at each queried position.
        match &round_state.round_data {
            RoundData::Base(data) => {
                self.prime_base_rows(&stir_challenges_indexes, data);
                for (&challenge, commitment) in stir_challenges_indexes.iter().zip({
                    let mmcs = &self.mmcs;
                    open_all(&stir_challenges_indexes, |c| mmcs.open_batch(c, data))
                }) {
                    let answer = commitment.opened_values[0].clone();

                    let eval = Poly::new(answer.clone()).eval_base(&query_randomness);
                    let var = round_params.folded_domain_gen.exp_u64(challenge as u64);
                    stir_statement.add_constraint(var, eval);

                    queries.push(QueryOpening::Base {
                        values: answer,
                        proof: commitment.opening_proof,
                    });
                }
            }
            RoundData::Ext(data) => {
                self.prime_ext_rows(&stir_challenges_indexes, data);
                for (&challenge, commitment) in stir_challenges_indexes.iter().zip({
                    let mmcs = &self.extension_mmcs;
                    open_all(&stir_challenges_indexes, |c| mmcs.open_batch(c, data))
                }) {
                    let answer = commitment.opened_values[0].clone();

                    let eval = Poly::new(answer.clone()).eval_ext::<F>(&query_randomness);
                    let var = round_params.folded_domain_gen.exp_u64(challenge as u64);
                    stir_statement.add_constraint(var, eval);

                    queries.push(QueryOpening::Extension {
                        values: answer,
                        proof: commitment.opening_proof,
                    });
                }
            }
        }

        proof.rounds[round_index].queries = queries;

        let constraint = Constraint::new(
            challenger.sample_algebra_element(),
            ood_statement,
            stir_statement,
        );

        // Run sumcheck and fold the polynomial.
        let mut sumcheck_data: SumcheckData<F, EF> = SumcheckData::default();
        // SPEED R4-G: one round per sub-round of the group, each at its own difficulty (`WhirConfig::round_fold_grinds`).
        let fold_grinds = self.round_fold_grinds(round_index);
        assert_eq!(fold_grinds.len(), folding_factor_next, "one proof-of-work difficulty per folded variable");
        let folding_randomness = round_state.sumcheck_prover.compute_sumcheck_polynomials_each(
            &mut sumcheck_data,
            challenger,
            &fold_grinds,
            Some(constraint),
        );
        proof.set_sumcheck_data_at(sumcheck_data, round_index);

        // Update round state for next iteration.
        round_state.folding_randomness = folding_randomness;
        round_state.round_data = RoundData::Ext(prover_data);
    }

    #[instrument(skip_all)]
    fn final_round(
        &self,
        round_index: usize,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        round_state: &mut WhirRoundState<EF, F, MT>,
    ) {
        // Send final polynomial coefficients in the clear.
        challenger.observe_algebra_slice(round_state.sumcheck_prover.evals().as_slice());
        proof.final_poly = Some(round_state.sumcheck_prover.evals());

        // PoW grinding for the final round.
        if self.final_pow_bits > 0 {
            proof.final_pow_witness = challenger.grind(self.final_pow_bits);
        }

        // Final STIR queries.
        let final_challenge_indexes = stir_queries_fixed_time::<Challenger, F, EF>(
            self.final_round_config().domain_size,
            self.params.folding_factor.at_round(round_index),
            self.final_queries,
            challenger,
        );
        proof.query_indices.push(final_challenge_indexes.clone());

        // Open Merkle proofs at the queried positions.
        match &round_state.round_data {
            RoundData::Base(data) => {
                self.prime_base_rows(&final_challenge_indexes, data);
                let mmcs = &self.mmcs;
                for commitment in open_all(&final_challenge_indexes, |c| mmcs.open_batch(c, data)) {
                    proof.final_queries.push(QueryOpening::Base {
                        values: commitment.opened_values[0].clone(),
                        proof: commitment.opening_proof,
                    });
                }
            }

            RoundData::Ext(data) => {
                self.prime_ext_rows(&final_challenge_indexes, data);
                let mmcs = &self.extension_mmcs;
                for commitment in open_all(&final_challenge_indexes, |c| mmcs.open_batch(c, data)) {
                    proof.final_queries.push(QueryOpening::Extension {
                        values: commitment.opened_values[0].clone(),
                        proof: commitment.opening_proof,
                    });
                }
            }
        }

        // Optional final sumcheck.
        if self.final_sumcheck_rounds > 0 {
            let mut sumcheck_data: SumcheckData<F, EF> = SumcheckData::default();
            round_state.sumcheck_prover.compute_sumcheck_polynomials(
                &mut sumcheck_data,
                challenger,
                self.final_sumcheck_rounds,
                self.final_folding_pow_bits,
                None,
            );
            proof.set_final_sumcheck_data(sumcheck_data);
        }
    }
}

use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::Debug;
use core::ops::Deref;
use core::slice::from_ref;

use errors::VerifierError;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_field::{ExtensionField, Field, HornerIter, PrimeField64, TwoAdicField};
use p3_matrix::Dimensions;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use tracing::instrument;

use super::committer::reader::ParsedCommitment;
use super::utils::stir_queries_fixed_time;
use crate::alloc::string::ToString;
use crate::constraints::Constraint;
use crate::constraints::statement::SelectStatement;
use crate::parameters::{RoundConfig, WhirConfig};
use crate::pcs::proof::{QueryOpening, WhirProof};
use crate::sumcheck::strategy::VariableOrder;
use crate::sumcheck::{SumcheckError, verify_final_sumcheck_rounds};

pub mod errors;

/// Replays a WHIR opening proof against a public commitment and the
/// constraint built by the layout adapter.
///
/// # Borrowing
///
/// - Config and Merkle scheme are borrowed for the lifetime of the check.
/// - Nothing is cloned across `verify`.
/// - Construction is `const`; spinning up a fresh verifier per proof is free.
///
/// # Variable order
///
/// Tag declared by the prover at commit time. Selects which way folding
/// randomness is consumed in the final identity and STIR unfold:
///
/// ```text
///     Prefix:  fold(rs)         -> final eval, query unfold
///     Suffix:  fold(rs.rev())   -> same checks, reversed binding
/// ```
#[derive(Debug)]
pub struct WhirVerifier<'a, EF, F, MT, Challenger>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Derived per-protocol parameters and per-round configuration.
    pub(crate) config: &'a WhirConfig<EF, F, Challenger>,
    /// Base-field Merkle commitment scheme used to authenticate STIR queries.
    pub(crate) mmcs: &'a MT,
    /// Binding direction used to interpret folding randomness.
    pub(crate) variable_order: VariableOrder,
    /// MonerousD C4 (2026-11-13): where to copy each STIR query group as the verifier saw it, when a caller asks
    /// ([`Self::recording`]): its root, the positions it drew, the folding point, each query's weight in the group's
    /// claim, the folds and the claim. A producer that aggregates the openings in-circuit needs exactly this, and a
    /// decoded proof does not carry the positions (`WhirProof::query_indices` is never on the wire). `None` (the
    /// default) changes nothing; the record never feeds back into the verdict.
    pub(crate) record: Option<&'a core::cell::RefCell<alloc::vec::Vec<StirGroupRecord<EF, MT::Commitment>>>>,
    /// MonerousD C4 stage A: verify a CORE — the proof with its query openings removed — against one claim per query
    /// group (rounds, then the final group) proven elsewhere. Each round group's claim enters `claimed_eval` where its
    /// folds would have (`combine_evals`); the final group's per-query checks become one combined check at a point drawn
    /// from a CLONE of the challenger, so the transcript is the full proof's. `None` (the default) verifies the openings.
    pub(crate) claims: Option<&'a [EF]>,
}

/// MonerousD C4: one STIR query group as the verifier saw it (rounds' groups in order, then the final group).
#[derive(Clone, Debug)]
pub struct StirGroupRecord<EF, C> {
    /// The commitment the group's queries open.
    pub root: C,
    /// The drawn positions, in proof order.
    pub indices: Vec<usize>,
    /// The number of leaves of the tree the group opens (`domain_size >> folding_factor`, the verifier's own number):
    /// its log is the path depth, and every position lies below it.
    pub leaves: usize,
    /// The folding point a query's opened row is evaluated at (`Poly::eval_ext`).
    pub point: Vec<EF>,
    /// Whether the opened rows are extension values (every round after the first commitment).
    pub extension: bool,
    /// Each query's weight in the group's claim: `α^(n_ood + j)` for a round group, `γ'^j` for the final group.
    pub coeffs: Vec<EF>,
    /// The folds (empty when verifying a core).
    pub folds: Vec<EF>,
    /// `Σ_j coeffs_j · folds_j`.
    pub claim: EF,
}

impl<'a, EF, F, MT, Challenger> WhirVerifier<'a, EF, F, MT, Challenger>
where
    F: TwoAdicField + p3_field::PrimeField64,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F> + Clone,
{
    /// Wraps the verifier-side dependencies into a single replay context.
    ///
    /// # Arguments
    ///
    /// - `config`         — derived per-protocol parameters and per-round configuration.
    /// - `mmcs`           — base-field Merkle commitment scheme used to authenticate STIR queries.
    /// - `variable_order` — binding direction the prover declared at commit time.
    pub const fn new(
        config: &'a WhirConfig<EF, F, Challenger>,
        mmcs: &'a MT,
        variable_order: VariableOrder,
    ) -> Self {
        Self {
            config,
            mmcs,
            variable_order,
            record: None,
            claims: None,
        }
    }

    /// The same verifier, copying every STIR query group into `record` (each round's group, then the final group) —
    /// the order `WhirProof::query_indices` has on the prover's side.
    #[must_use]
    pub const fn recording(mut self, record: &'a core::cell::RefCell<alloc::vec::Vec<StirGroupRecord<EF, MT::Commitment>>>) -> Self {
        self.record = Some(record);
        self
    }

    /// The same verifier, checking a CORE against one proven claim per query group (C4 stage A; see `claims`).
    #[must_use]
    pub const fn with_group_claims(mut self, claims: &'a [EF]) -> Self {
        self.claims = Some(claims);
        self
    }

    /// Verify a WHIR proof against a commitment and statement.
    ///
    /// Returns the folding randomness point on success.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_lines)]
    pub fn verify(
        &self,
        proof: &WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        parsed_commitment: &MT::Commitment,
        initial_constraint: Constraint<F, EF>,
        mut claimed_eval: EF,
    ) -> Result<Point<EF>, VerifierError>
    where
        Challenger: CanObserve<MT::Commitment>,
    {
        // Reject a proof that carries the wrong number of rounds before any
        // transcript work. The per-round commitment slot is checked further
        // down, where each round is parsed.
        let expected_rounds = self.n_rounds();
        // MonerousD C4: a core carries exactly one claim per query group (every round, then the final group).
        if let Some(c) = self.claims {
            if c.len() != expected_rounds + 1 {
                return Err(VerifierError::StirChallengeFailed {
                    challenge_id: 0,
                    details: "a core names another number of query groups".to_string(),
                });
            }
        }
        if proof.rounds.len() != expected_rounds {
            return Err(VerifierError::RoundCountMismatch {
                expected: expected_rounds,
                actual: proof.rounds.len(),
            });
        }

        let mut constraints = Vec::new();
        let mut round_folding_randomness = Vec::new();
        let mut prev_commitment = parsed_commitment.clone();

        constraints.push(initial_constraint);

        // Initial sumcheck rounds == first-round folding factor.
        let expected_initial_rounds = self.folding_factor(0);
        let actual_initial_rounds = proof.initial_sumcheck.polynomial_evaluations().len();
        if actual_initial_rounds != expected_initial_rounds {
            return Err(VerifierError::Sumcheck(SumcheckError::RoundCountMismatch {
                expected: expected_initial_rounds,
                actual: actual_initial_rounds,
            }));
        }
        // SPEED R4-G: each sub-round's own difficulty (`WhirConfig::starting_fold_grinds`: the group's one figure for
        // each, or the per-fold list of a configuration sized at the folded code) — the list the prover ground.
        let folding_randomness = proof.initial_sumcheck.verify_rounds_each(
            challenger,
            &mut claimed_eval,
            &self.starting_fold_grinds(),
        )?;
        round_folding_randomness.push(folding_randomness);

        // Verify each intermediate round.
        for round_index in 0..self.n_rounds() {
            let round_params = &self.round_parameters[round_index];

            // Index is in bounds thanks to the length check at function entry,
            // so only a missing commitment slot can fail here.
            let new_commitment = ParsedCommitment::<_, MT::Commitment>::parse_with_round(
                proof,
                challenger,
                round_params.num_variables,
                round_params.ood_samples,
                round_index,
            )?;

            // Verify STIR in-domain challenges against the previous commitment.
            let current_folding_randomness = round_folding_randomness
                .last()
                .ok_or(VerifierError::MissingFoldingRandomness { round: round_index })?;
            let stir_statement = self.verify_stir_challenges(
                proof,
                challenger,
                round_params,
                &prev_commitment,
                current_folding_randomness,
                round_index,
            )?;

            let alpha: EF = challenger.sample_algebra_element();
            let n_ood = new_commitment.ood_statement.len();
            let folds: Vec<EF> = stir_statement.iter().map(|(_, &e)| e).collect();
            let constraint = Constraint::new(alpha, new_commitment.ood_statement.clone(), stir_statement);
            // (verifying a core, the statement's evaluations are zero, so this adds the OOD part alone)
            constraint.combine_evals(&mut claimed_eval);
            // MonerousD C4: the group's claim, `Σ_j α^(n_ood + j) · fold_j` — what `combine_evals` added for the folds.
            let base = alpha.exp_u64(n_ood as u64);
            self.close_group(round_index, |j| base * alpha.exp_u64(j as u64), folds, &mut claimed_eval)?;
            constraints.push(constraint);

            // SPEED R4-G: one difficulty per sub-round (`WhirConfig::round_fold_grinds`); a proof whose round count is
            // not the schedule's is refused there.
            let folding_randomness = proof.rounds[round_index].sumcheck.verify_rounds_each(
                challenger,
                &mut claimed_eval,
                &self.round_fold_grinds(round_index),
            )?;
            round_folding_randomness.push(folding_randomness);

            prev_commitment = new_commitment.root;
        }

        // Final round: receive the polynomial in the clear.
        let final_evaluations = proof
            .final_poly
            .clone()
            .ok_or(VerifierError::MissingFinalPoly)?;
        let final_round_config = self.final_round_config();
        let expected_final_poly_len = 1usize << final_round_config.num_variables;
        let actual_final_poly_len = final_evaluations.num_evals();
        if actual_final_poly_len != expected_final_poly_len {
            return Err(VerifierError::FinalPolyLengthMismatch {
                expected: expected_final_poly_len,
                actual: actual_final_poly_len,
            });
        }
        challenger.observe_algebra_slice(final_evaluations.as_slice());

        // Verify final STIR challenges.
        let final_round_folding_randomness = round_folding_randomness.last().ok_or_else(|| {
            VerifierError::MissingFoldingRandomness {
                round: self.n_rounds(),
            }
        })?;
        let stir_statement = self.verify_stir_challenges(
            proof,
            challenger,
            &final_round_config,
            &prev_commitment,
            final_round_folding_randomness,
            self.n_rounds(),
        )?;

        // MonerousD C4: the final group's per-query checks `final_poly(z_j) == fold_j`, as one combined check at a point
        // drawn from a CLONE of the challenger (the transcript is untouched): `Σ_j γ'^j final_poly(z_j) == C_final`.
        // Verifying the full proof, the per-query checks run as before and the combined claim is only recorded.
        if self.claims.is_some() || self.record.is_some() {
            let gp: EF = challenger.clone().sample_algebra_element();
            let mut expected = EF::ZERO;
            let mut p = EF::ONE;
            for (&var, _) in stir_statement.iter() {
                expected += p * final_evaluations.iter().copied().horner::<EF, _>(var);
                p *= gp;
            }
            let folds: Vec<EF> = stir_statement.iter().map(|(_, &e)| e).collect();
            if let Some(claims) = self.claims {
                if claims.get(self.n_rounds()) != Some(&expected) {
                    return Err(VerifierError::StirChallengeFailed {
                        challenge_id: 0,
                        details: "the final group's claim is not the final polynomial at its query points".to_string(),
                    });
                }
            }
            let mut sink = EF::ZERO;
            self.close_group(self.n_rounds(), |j| gp.exp_u64(j as u64), folds, &mut sink)?;
        }
        if self.claims.is_none() {
            stir_statement
                .verify(&final_evaluations)
                .then_some(())
                .ok_or_else(|| VerifierError::StirChallengeFailed {
                    challenge_id: 0,
                    details: "STIR constraint verification failed on final polynomial".to_string(),
                })?;
        }

        let final_sumcheck_randomness = verify_final_sumcheck_rounds(
            proof.final_sumcheck.as_ref(),
            challenger,
            &mut claimed_eval,
            self.final_sumcheck_rounds,
            self.final_folding_pow_bits,
        )?;
        round_folding_randomness.push(final_sumcheck_randomness.clone());

        // Compute the full folding randomness across all rounds.
        let folding_randomness = Point::new(
            round_folding_randomness
                .into_iter()
                .flat_map(IntoIterator::into_iter)
                .collect(),
        );

        // Evaluate the constraint polynomial at the folding point.
        let evaluation_of_weights = self
            .variable_order
            .eval_constraints_poly(&constraints, &folding_randomness);

        // Final consistency check: claimed_eval == weight * f(r).
        let final_value = match self.variable_order {
            VariableOrder::Prefix => final_evaluations.eval_ext::<F>(&final_sumcheck_randomness),
            VariableOrder::Suffix => {
                final_evaluations.eval_ext::<F>(&final_sumcheck_randomness.reversed())
            }
        };
        if claimed_eval != evaluation_of_weights * final_value {
            return Err(VerifierError::SumcheckFailed {
                round: self.final_sumcheck_rounds,
                expected: (evaluation_of_weights * final_value).to_string(),
                actual: claimed_eval.to_string(),
            });
        }

        Ok(folding_randomness)
    }

    /// MonerousD C4: close query group `g` — its claim (`Σ_j coeff(j) · fold_j`, or the proven claim when verifying a
    /// core, which then enters `claimed_eval`), and its record's weights, folds and claim.
    fn close_group(&self, g: usize, coeff: impl Fn(usize) -> EF, folds: Vec<EF>, claimed_eval: &mut EF) -> Result<(), VerifierError> {
        let claim = match self.claims {
            Some(c) => *c.get(g).ok_or_else(|| VerifierError::StirChallengeFailed {
                challenge_id: g,
                details: "a query group has no proven claim".to_string(),
            })?,
            None => folds.iter().enumerate().fold(EF::ZERO, |acc, (j, &f)| acc + coeff(j) * f),
        };
        if self.claims.is_some() {
            *claimed_eval += claim;
        }
        if let Some(r) = self.record {
            let mut r = r.borrow_mut();
            let last = r.last_mut().ok_or_else(|| VerifierError::StirChallengeFailed {
                challenge_id: g,
                details: "a query group was closed before it was drawn".to_string(),
            })?;
            last.coeffs = (0..last.indices.len()).map(&coeff).collect();
            last.folds = if self.claims.is_some() { Vec::new() } else { folds };
            last.claim = claim;
        }
        Ok(())
    }

    /// Verify STIR in-domain queries and produce associated constraints.
    ///
    /// Checks PoW witness, generates query indices, verifies Merkle proofs,
    /// and evaluates folded polynomials at the queried positions.
    pub fn verify_stir_challenges(
        &self,
        proof: &WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        params: &RoundConfig<F>,
        commitment: &MT::Commitment,
        folding_randomness: &Point<EF>,
        round_index: usize,
    ) -> Result<SelectStatement<F, EF>, VerifierError> {
        // Verify PoW witness before generating challenges.
        let pow_witness = if round_index < self.n_rounds() {
            proof
                .get_pow_after_commitment(round_index)
                .ok_or(VerifierError::InvalidRoundIndex { index: round_index })?
        } else {
            proof.final_pow_witness
        };
        // A query grind is ONE word: `params.pow_bits` caps it at ≤ 24 bits in every config of this workspace, where
        // a 31-bit field holds ≥ 2^7 solutions (the folding grinds, up to 30 bits, are the two-word witnesses in the
        // sumcheck data).
        if params.pow_bits > 0 && !challenger.check_witness(params.pow_bits, pow_witness) {
            return Err(VerifierError::InvalidPowWitness);
        }
        // ⛔ CANONICAL WHEN NO GRINDING IS ASKED (2026-09-27, found by the decider's byte-flip census): with
        // `pow_bits == 0` the witness was never read, so its bytes were FREE on the wire — a proof stayed valid
        // under any value there. The prover leaves it zero; anything else is refused, so a proof has exactly one
        // encoding and no unchecked byte.
        if params.pow_bits == 0 && pow_witness != F::ZERO {
            return Err(VerifierError::InvalidPowWitness);
        }

        // Transcript checkpoint after PoW.
        if round_index < self.n_rounds() {
            challenger.sample();
        }

        // Sample STIR query positions.
        let stir_challenges_indexes = stir_queries_fixed_time::<Challenger, F, EF>(
            params.domain_size,
            params.folding_factor,
            params.num_queries,
            challenger,
        );

        let query_randomness = match self.variable_order {
            VariableOrder::Prefix => folding_randomness.clone(),
            VariableOrder::Suffix => folding_randomness.reversed(),
        };
        // MonerousD C4: the group as the verifier sees it; its weights and claim are filled in where they are drawn.
        if let Some(r) = self.record {
            r.borrow_mut().push(StirGroupRecord {
                root: commitment.clone(),
                indices: stir_challenges_indexes.clone(),
                leaves: params.domain_size >> params.folding_factor,
                point: query_randomness.as_slice().to_vec(),
                extension: round_index > 0,
                coeffs: Vec::new(),
                folds: Vec::new(),
                claim: EF::ZERO,
            });
        }
        // Evaluate folded polynomial at each queried position — or, verifying a CORE (C4 stage A), take none: the
        // openings are proven elsewhere and the group's claim enters in their place (`verify`), so the statement here
        // carries the query POINTS (the constraint polynomial's weights need them) with zero evaluations.
        let folds: Vec<EF> = if self.claims.is_some() {
            vec![EF::ZERO; stir_challenges_indexes.len()]
        } else {
            let dimensions = vec![Dimensions {
                height: params.domain_size >> params.folding_factor,
                width: 1 << params.folding_factor,
            }];
            let answers = self.verify_merkle_proof(
                proof,
                commitment,
                &stir_challenges_indexes,
                &dimensions,
                round_index,
            )?;
            answers
                .into_iter()
                .map(|answer| Poly::new(answer).eval_ext::<F>(&query_randomness))
                .collect()
        };

        let stir_constraints = stir_challenges_indexes
            .iter()
            .map(|&index| params.folded_domain_gen.exp_u64(index as u64))
            .collect();

        Ok(SelectStatement::new(
            params.num_variables,
            stir_constraints,
            folds,
        ))
    }

    /// Verify Merkle multi-opening proofs at the given indices.
    pub fn verify_merkle_proof(
        &self,
        proof: &WhirProof<F, EF, MT>,
        root: &MT::Commitment,
        indices: &[usize],
        dimensions: &[Dimensions],
        round_index: usize,
    ) -> Result<Vec<Vec<EF>>, VerifierError> {
        let extension_mmcs = ExtensionMmcs::new((*self.mmcs).clone());

        let queries = if round_index == self.n_rounds() {
            &proof.final_queries
        } else {
            &proof
                .rounds
                .get(round_index)
                .ok_or_else(|| VerifierError::MerkleProofInvalid {
                    position: 0,
                    reason: format!("Round {round_index} not found in proof"),
                })?
                .queries
        };

        if queries.len() != indices.len() {
            return Err(VerifierError::StirQueryCountMismatch {
                round_index,
                expected: indices.len(),
                actual: queries.len(),
            });
        }

        let mut results = Vec::with_capacity(indices.len());

        for (&index, query) in indices.iter().zip(queries.iter()) {
            let values_ef = match query {
                QueryOpening::Base { values, proof } => {
                    self.mmcs
                        .verify_batch(
                            root,
                            dimensions,
                            index,
                            BatchOpeningRef {
                                opened_values: from_ref(values),
                                opening_proof: proof,
                            },
                        )
                        .map_err(|_| VerifierError::MerkleProofInvalid {
                            position: index,
                            reason: "Base field Merkle proof verification failed".to_string(),
                        })?;

                    values.iter().map(|&f| f.into()).collect()
                }
                QueryOpening::Extension { values, proof } => {
                    extension_mmcs
                        .verify_batch(
                            root,
                            dimensions,
                            index,
                            BatchOpeningRef {
                                opened_values: from_ref(values),
                                opening_proof: proof,
                            },
                        )
                        .map_err(|_| VerifierError::MerkleProofInvalid {
                            position: index,
                            reason: "Extension field Merkle proof verification failed".to_string(),
                        })?;

                    values.clone()
                }
            };

            results.push(values_ef);
        }

        Ok(results)
    }
}

impl<EF, F, MT, Challenger> Deref for WhirVerifier<'_, EF, F, MT, Challenger>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    type Target = WhirConfig<EF, F, Challenger>;

    fn deref(&self) -> &Self::Target {
        self.config
    }
}

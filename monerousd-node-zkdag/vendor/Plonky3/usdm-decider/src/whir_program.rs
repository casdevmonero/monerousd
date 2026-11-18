//! The WHIR VERIFIER AS A PROGRAM for the universal row (`universal_row.rs`), emitted by `ProgramBuilder`
//! (`verifier_program.rs`): every step of `WhirVerifier::verify` — the initial sumcheck, each round's commitment
//! parse, STIR queries (draw, leaf, path, fold), α-combine and sumcheck, the final polynomial, the final queries'
//! Horner checks and the final sumcheck — laid onto rows with FIXED register conventions. The program depends only
//! on the PCS configuration; the stream on the proof.
//!
//! Register conventions (see each emitter): the claimed sum lives in `E3` (a query's level-1 folds write all of
//! `X0..X8`, so no `X` register survives a query); the newest folding coordinate is
//! `PT[0]` (each sumcheck round pushes its challenge); a leaf's level-1 folds land in `X0..X8`, level 2 in
//! `X0..X4`, level 3 in `X0, X1`, level 4 in `X0` (the levels read `PT[0]` after one rotation each, restored
//! by rotations up on the path rows); folds and OOD answers are pushed into `F` for the α-combine's Horner walk;
//! the final polynomial's coefficients are pushed two per absorbing row into `F`'s tail and read by rotations up;
//! every round query's `g^index` is pushed on the VB stack (`BANK_ABSORB`, H12 §12 C).
//!
//! ROOT-LAYER: the program is produced from the verifier's own control flow and the challenger's own buffer rules;
//! no value is inferred from the proof.
//! MEASURED: pin `the_whir_program_reproduces_the_native_verifiers_claimed_sums` — on a REAL committed Spartan
//! proof, `X7` equals the native `claimed` after the initial sumcheck, after every round's combine and sumcheck,
//! and after the final sumcheck; every path row's `H` equals the round's root; every final query's Horner value
//! equals its fold.
//! MUST-STAY-GREEN: the universal-row and program-builder pins.

use crate::hiding_decider::{Ea4, Fa4, Mmcs16};
use crate::spartan_gadgets::RATE;
use crate::universal_row::{flag, RowFlags, RowParams, NF, NPT, NROUNDS, NVB};
use crate::verifier_program::{After, ProgramBuilder};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_whir::pcs::proof::{QueryOpening, WhirProof};

/// One round's shape, read off the configuration.
#[derive(Clone, Debug)]
pub struct RoundShape {
    /// The round one-hot index (`RF + rf`): rounds `0..n`, the final round `n`.
    pub rf: usize,
    /// The fold INTO this round: the leaf width (`2^folding` values) of the commitment this round's queries open, and the
    /// depth of each query's leaf fold.
    pub folding: usize,
    /// The fold OUT of this round: how many variables the round's own sumcheck folds (= the next phase's factor). Equal to
    /// `folding` under a constant schedule; different under H12 path B's per-round schedule (MEASURED 2026-10-04 19:20: the
    /// first folding-5 proof has 1 sumcheck evaluation after a 5-value leaf fold, and the emitter asserted 5).
    pub next_folding: usize,
    pub num_queries: usize,
    pub ood_samples: usize,
    /// log2 of the folded domain (the Merkle depth and the STIR draw width).
    pub k: usize,
    /// Leaves hold base values (round 0) or extension values (later rounds).
    pub ext_leaf: bool,
    /// Proof-of-work bit counts: the round's sumcheck (`folding_pow_bits`) and its STIR queries (`pow_bits`).
    pub fold_pow: usize,
    pub query_pow: usize,
    /// The folded polynomial's variables at this round — the arity of the round's constraint (`eval_constraints_poly`
    /// reads the LAST `num_variables` folding coordinates for it).
    pub num_variables: usize,
}

/// The whole proof's shape.
#[derive(Clone, Debug)]
pub struct WhirShape {
    pub folding0: usize,
    /// The initial sumcheck's proof-of-work bit count (`starting_folding_pow_bits`).
    pub pow_init: usize,
    pub rounds: Vec<RoundShape>,
    pub final_round: RoundShape,
    pub final_sumcheck_rounds: usize,
    pub final_poly_len: usize,
}

impl WhirShape {
    /// From the decider's committed PCS configuration, its rounds at round-table slots `0..`.
    pub fn of(cfg: &p3_whir::parameters::whir::WhirConfig<Ea4, Fa4, crate::hiding_decider::Chl>) -> Self {
        Self::of_with_offset(cfg, 0)
    }
    /// [`Self::of`] with the rounds at round-table slots `rf_offset..` — the uniform certificate runs TWO WHIR
    /// verifications (the witness commitment's, then the fixed commitment's) on one row, so the second shape's
    /// rounds take the slots after the first's (`row_params_multi`).
    pub fn of_with_offset(cfg: &p3_whir::parameters::whir::WhirConfig<Ea4, Fa4, crate::hiding_decider::Chl>, rf_offset: usize) -> Self {
        let n = cfg.n_rounds();
        assert!(rf_offset + n + 1 <= NROUNDS, "the row's round tables hold {NROUNDS} rounds ({rf_offset} + {n} + 1 asked)");
        let rounds: Vec<RoundShape> = (0..n)
            .map(|r| {
                let rp = &cfg.round_parameters[r];
                RoundShape {
                    rf: rf_offset + r,
                    folding: rp.folding_factor,
                    next_folding: cfg.folding_factor(r + 1),
                    num_queries: rp.num_queries,
                    ood_samples: rp.ood_samples,
                    k: (rp.domain_size >> rp.folding_factor).trailing_zeros() as usize,
                    ext_leaf: r > 0,
                    fold_pow: rp.folding_pow_bits,
                    query_pow: rp.pow_bits,
                    num_variables: rp.num_variables,
                }
            })
            .collect();
        let fc = cfg.final_round_config();
        let final_round = RoundShape {
            rf: rf_offset + n,
            folding: fc.folding_factor,
            next_folding: cfg.final_sumcheck_rounds,
            num_queries: fc.num_queries,
            ood_samples: 0,
            k: (fc.domain_size >> fc.folding_factor).trailing_zeros() as usize,
            ext_leaf: n > 0,
            fold_pow: cfg.final_folding_pow_bits,
            query_pow: fc.pow_bits,
            num_variables: fc.num_variables,
        };
        WhirShape {
            folding0: cfg.folding_factor(0),
            pow_init: cfg.starting_folding_pow_bits,
            rounds,
            final_round,
            final_sumcheck_rounds: cfg.final_sumcheck_rounds,
            final_poly_len: 1 << fc.num_variables,
        }
    }
    /// The row constants this shape needs: per-round generators and draw widths.
    pub fn row_params(&self, cfg: &p3_whir::parameters::whir::WhirConfig<Ea4, Fa4, crate::hiding_decider::Chl>, pt_port: usize) -> RowParams {
        Self::row_params_multi(&[(self, cfg)], pt_port)
    }
    /// The row constants for several WHIR shapes run on one row (each at its own round-table slots, `of_with_offset`):
    /// the union of their round tables; a run's initial-sumcheck pow count sits at its first slot (MEASURED 2026-09-28:
    /// the 15-variable witness WHIR asks 14 bits, the 22-variable fixed WHIR 7 — `starting_folding_pow_bits` depends
    /// on the polynomial's size, so one row constant could not serve both).
    /// ROOT-LAYER: the round tables are row constants (`RowParams`), produced once per certificate shape — the union
    /// belongs where the tables are built, not at the two `emit_whir_verify` call sites that read `rf`.
    /// MEASURED: one shape (the M4a pin, slots 0..3) = the former `row_params`, 1087 rows GREEN; the two-shape union
    /// is measured by the uniform certificate pin (`fixed_program.rs`).
    /// MUST-STAY-GREEN: the WHIR-program, closing-identity and matrix-rows pins (single-shape callers).
    pub fn row_params_multi(shapes: &[(&WhirShape, &p3_whir::parameters::whir::WhirConfig<Ea4, Fa4, crate::hiding_decider::Chl>)], pt_port: usize) -> RowParams {
        assert!(!shapes.is_empty(), "at least one WHIR shape");
        let mut gens = [Fa4::ZERO; NROUNDS];
        let mut ks = [1usize; NROUNDS];
        let mut init_pow = [0usize; NROUNDS];
        let mut fold_pow = [0usize; NROUNDS];
        let mut query_pow = [0usize; NROUNDS];
        let mut taken = [false; NROUNDS];
        for (shape, cfg) in shapes {
            init_pow[shape.first_slot()] = shape.pow_init;
            let fc = cfg.final_round_config();
            let gens_of = cfg.round_parameters.iter().map(|rp| rp.folded_domain_gen).chain(core::iter::once(fc.folded_domain_gen));
            for (rs, gen) in shape.rounds.iter().chain(core::iter::once(&shape.final_round)).zip(gens_of) {
                assert!(!taken[rs.rf], "round-table slot {} used by two WHIR runs", rs.rf);
                taken[rs.rf] = true;
                gens[rs.rf] = gen;
                ks[rs.rf] = rs.k;
                fold_pow[rs.rf] = rs.fold_pow;
                query_pow[rs.rf] = rs.query_pow;
            }
        }
        RowParams::decider(gens, ks, pt_port).with_pow(init_pow, fold_pow, query_pow)
    }
    /// The round-table slots this shape occupies: `rounds + 1`.
    pub fn slots(&self) -> usize {
        self.rounds.len() + 1
    }
    /// The run's first round-table slot (its initial-sumcheck pow count lives there).
    pub fn first_slot(&self) -> usize {
        self.rounds.first().map(|r| r.rf).unwrap_or(self.final_round.rf)
    }
}

fn coeffs(e: Ea4) -> [Fa4; 4] {
    core::array::from_fn(|i| e.as_basis_coefficients_slice()[i])
}

/// Checkpoints the emitter reports: the row after which `E3` holds the named claimed sum.
#[derive(Clone, Debug, Default)]
pub struct WhirCheckpoints {
    pub after_initial_sumcheck: Option<After>,
    pub after_round_combine: Vec<After>,
    pub after_round_sumcheck: Vec<After>,
    /// Per round, per query: the row after the last path row (`H == R`).
    pub root_rows: Vec<Vec<After>>,
    /// Per final query: the row after the Horner check (`X0 == X4`).
    pub final_horner_rows: Vec<After>,
    pub after_final_sumcheck: Option<After>,
}

/// A sumcheck round's proof of work: `(kind flag, round one-hot, the two-word witness [hi, lo])`, `None` when the
/// configuration asks for no grinding (the native then observes and samples nothing). The row absorbs both words on
/// one duplexing row and pops the checked sample — `GrindingChallenger::check_witness_wide` as rows.
pub type PowCheck = Option<(usize, Option<usize>, [Fa4; 2])>;

/// The pow check of round `i` of a sumcheck with `bits` bits: the round's two witness words, or `None` with the
/// witness list asserted empty (the native refuses a witness nobody reads).
fn pow_for(witnesses: &[Fa4], i: usize, bits: usize, kind: usize, rf: Option<usize>) -> PowCheck {
    if bits == 0 {
        assert!(witnesses.is_empty(), "no pow witness when no grinding is asked");
        return None;
    }
    Some((kind, rf, [witnesses[2 * i], witnesses[2 * i + 1]]))
}

/// One `{0, 1, ∞}` sumcheck round on the claim in `E3` (`SumcheckData::verify_rounds` for one pair). Row A absorbs
/// `(h0, hinf)`. With a proof of work (`check_witness`: observe the witness, pop one sample with zero low bits, then
/// sample `r`) row A stages `X0 = X2 = h0, X1 = hinf`, a row absorbs the witness and pops the checked sample, and
/// the challenge row multiplies from `X`; without one the challenge row is row A and multiplies from the stream.
/// Rows B–G fold `claim' = h0 + r·claim − 2·r·h0 − r·hinf + r²·hinf` back into `E3` (via `X6`, `X3`) and push `r`
/// into `PT`.
pub fn emit_sumcheck_round(pb: &mut ProgramBuilder, h0: Ea4, hinf: Ea4, pow: PowCheck) -> After {
    assert_eq!(pb.pending_len(), 0, "a sumcheck round starts on an empty input buffer");
    // A fresh row: the `(h0, hinf)` duplexing would otherwise share the previous unit's closing row — the previous
    // round's `E3 ← X3` (row A's `E3 × CH` would read the STALE claim) or a final query's Horner check row (row A's
    // `X0 ← X4 ← r·h0` made `EXT_EQ` pass vacuously; MEASURED on the last final query).
    pb.new_row();
    pb.observe_ext(h0);
    pb.observe_ext(hinf);
    match pow {
        Some((kind, rf, witness)) => {
            {
                let r = pb.cur();
                r.xmove(0, flag::XM_CLR).xmove(0, flag::XM_ADD_D0); // h0
                r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_DA); // hinf = D_ext[1]
                r.xmove(2, flag::XM_CLR).xmove(2, flag::XM_ADD_D0); // h0
            }
            pb.observe(witness[0]);
            pb.observe(witness[1]);
            pb.pop_pow(kind, rf);
            pb.sample_ext();
            let r = pb.cur();
            r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_CH); // r·h0
            r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_CH); // r·hinf
            r.mul_a(3, flag::AM_E).mul_b(3, flag::BM_CH); // r·claim (the claim lives in E3)
            r.xmove(0, flag::XM_CLR).xmove(0, flag::XM_ADD_MUL);
            r.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_MUL);
            r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_MUL);
            r.xmove(7, flag::XM_CLR).xmove(7, flag::XM_ADD_MUL);
        }
        None => {
            pb.sample_ext();
            let r = pb.cur();
            r.mul_a(0, flag::AM_D).mul_b(0, flag::BM_CH); // r·h0
            r.mul_a(1, flag::AM_D).mul_b(1, flag::BM_CH); // r·hinf
            r.mul_a(3, flag::AM_E).mul_b(3, flag::BM_CH); // r·claim (the claim lives in E3)
            r.xmove(0, flag::XM_CLR).xmove(0, flag::XM_ADD_MUL);
            r.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_MUL);
            r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_MUL);
            r.xmove(2, flag::XM_CLR).xmove(2, flag::XM_ADD_D0);
            r.xmove(7, flag::XM_CLR).xmove(7, flag::XM_ADD_MUL);
        }
    }
    {
        let r = pb.row();
        r.set(flag::PT_PUSH);
        r.xmove(4, flag::XM_ADD_X2J); // 2·r·h0
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0); // r²·hinf
        r.xmove(5, flag::XM_CLR).xmove(5, flag::XM_ADD_MUL);
        r.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X); // E1 = r·hinf
    }
    {
        let r = pb.row();
        r.xmove(5, flag::XM_SUB_E).xmove(5, flag::XM_ADD_X2J); // X5 = r²·hinf − r·hinf + h0
        r.xmove(2, flag::XM_CLR).xmove(2, flag::XM_ADD_X2J); // X2 = 2·r·h0
    }
    {
        let r = pb.row();
        r.emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_X); // E2 = 2·r·h0
        r.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_NEXT); // X4 = partial
    }
    {
        let r = pb.row();
        r.xmove(6, flag::XM_CLR).xmove(6, flag::XM_ADD_X2J).xmove(6, flag::XM_SUB_E).xmove(6, flag::XM_ADD_NEXT); // claim'
    }
    {
        let r = pb.row();
        r.xmove(3, flag::XM_CLR).xmove(3, flag::XM_ADD_X2J); // X3 = claim' (X3's X2J source is X6)
    }
    {
        let r = pb.row();
        r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X); // E3 = claim'
    }
    After { row: pb.cur_row() }
}

/// Level-2..4 folds and the domain-generator stepping laid over the salt row and the first path rows; the level-1
/// folds are laid on the value rows by the caller. Requires `k ≥ 4` path levels.
fn fold_levels_on_path(pb: &mut ProgramBuilder, siblings: &[[Fa4; RATE]]) {
    assert!(siblings.len() >= 4, "the fold schedule needs at least four path levels");
    for (lvl, sib) in siblings.iter().enumerate() {
        pb.compress(sib, lvl + 1 == siblings.len());
        let r = pb.cur();
        r.set(flag::G_STEP);
        match lvl {
            0 => {
                // level 3 with PT[0] = r_{f−3}
                r.mul_a(0, flag::AM_ADJ).mul_b(0, flag::BM_PT0);
                r.xmove(0, flag::XM_ADD_MUL);
                r.mul_a(1, flag::AM_ADJ).mul_b(1, flag::BM_PT0);
                r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_X2J).xmove(1, flag::XM_ADD_MUL);
                r.set(flag::PT_ROT);
            }
            1 => {
                // level 4 with PT[0] = r_{f−4}: the fold lands in X0
                r.mul_a(0, flag::AM_ADJ).mul_b(0, flag::BM_PT0);
                r.xmove(0, flag::XM_ADD_MUL);
                r.set(flag::PT_ROT_UP);
            }
            2 => {
                r.set(flag::PT_ROT_UP);
            }
            3 => {
                r.set(flag::PT_ROT_UP);
            }
            _ => {}
        }
    }
}

/// One lane fold into one accumulator: lane `k` folds `(X[2k], X[2k+1])` by the head challenge, landing in `X[out]` as
/// `CLR + X[2·out mod 8] + MUL` — legal for `out ∈ {k, k + 4}`, where `X[2·out mod 8] = X[2k]` (for `out = 0` it is the
/// same value today's `X0 += MUL` form computes).
fn fold_pair(r: &mut RowFlags, k: usize, out: usize) {
    debug_assert!(out == k || out == k + 4, "lane {k} writes X{k} or X{}", k + 4);
    r.mul_a(k, flag::AM_ADJ).mul_b(k, flag::BM_PT0);
    r.xmove(out, flag::XM_CLR).xmove(out, flag::XM_ADD_X2J).xmove(out, flag::XM_ADD_MUL);
}

/// H12 path B — the 32-value leaf's levels 3–5 on the first three path rows (docs/H12 §10.4 rows 9–11), then four
/// `PT_ROT_UP`s to bring the head back to the first challenge for the next query, the fold pushed on the last of them.
/// Requires `k ≥ 7` path levels (the certificate has 19).
fn fold_levels_on_path_5(pb: &mut ProgramBuilder, siblings: &[[Fa4; RATE]]) {
    assert!(siblings.len() >= 7, "the folding-5 schedule needs at least seven path levels ({} given)", siblings.len());
    for (lvl, sib) in siblings.iter().enumerate() {
        pb.compress(sib, lvl + 1 == siblings.len());
        let r = pb.cur();
        r.set(flag::G_STEP);
        match lvl {
            0 => {
                // level 3 of (X6,X7) → X3 (head r3); head → r4
                fold_pair(r, 3, 3);
                r.set(flag::PT_ROT);
            }
            1 => {
                // level 4: (X0,X1) → X0, (X2,X3) → X1 (head r4); head → r5
                fold_pair(r, 0, 0);
                fold_pair(r, 1, 1);
                r.set(flag::PT_ROT);
            }
            2 => {
                // level 5: (X0,X1) → X0 (head r5) — the fold lands in X0; the head stays until the rotations below
                fold_pair(r, 0, 0);
            }
            3..=6 => {
                r.set(flag::PT_ROT_UP);
            }
            _ => {}
        }
    }
}

/// The level-2 fold on the salt row (`PT[0] = r_{f−2}`), then a rotation towards `r_{f−3}`.
fn level2_on_salt_row(pb: &mut ProgramBuilder) {
    let r = pb.cur();
    for k in 0..4 {
        r.mul_a(k, flag::AM_ADJ).mul_b(k, flag::BM_PT0);
    }
    r.xmove(0, flag::XM_ADD_MUL);
    for j in 1..4 {
        r.xmove(j, flag::XM_CLR).xmove(j, flag::XM_ADD_X2J).xmove(j, flag::XM_ADD_MUL);
    }
    r.set(flag::PT_ROT);
}

/// One STIR query: the draw, the leaf rows with the level-1 folds, the path rows with the remaining levels, the
/// fold pushed into `F` (non-final rounds). Returns the row after the last path row.
fn emit_query(pb: &mut ProgramBuilder, shape: &RoundShape, query: &QueryOpening<Fa4, Ea4, <Mmcs16 as p3_commit::Mmcs<Fa4>>::Proof>) -> After {
    // A fresh row first: a draw that fits the buffer would otherwise land on the previous query's last path row,
    // whose `G_STEP` this draw's `G_INIT` overrides (MEASURED: query 1 of round 0 read `VAR = 1`).
    pb.new_row();
    pb.draw(shape.rf);
    pb.cur().set(flag::G_INIT);
    assert!(!pb.cur().is_set(flag::G_STEP), "a draw's G_INIT must not share a G_STEP row");
    let (words, salts, siblings): (Vec<Fa4>, &Vec<Vec<Fa4>>, &Vec<[Fa4; RATE]>) = match query {
        QueryOpening::Base { values, proof } => (values.clone(), &proof.0, &proof.1),
        QueryOpening::Extension { values, proof } => (values.iter().flat_map(|&v| coeffs(v)).collect(), &proof.0, &proof.1),
    };
    assert_eq!(siblings.len(), shape.k, "one sibling per folded-domain level");
    let leaf: Vec<Fa4> = words.iter().chain(salts[0].iter()).copied().collect();
    let blocks: Vec<&[Fa4]> = leaf.chunks(RATE).collect();
    if shape.ext_leaf {
        // 2^folding extension values = 2 per block over 2^(folding−1) blocks, then the salt block
        let value_blocks = (1usize << shape.folding) / 2;
        assert_eq!(blocks.len(), value_blocks + 1);
        for (i, block) in blocks.iter().enumerate() {
            pb.leaf_block(block, i == 0);
            let r = pb.cur();
            if i < value_blocks {
                let k = i % 4;
                r.mul_a(k, flag::AM_PAIRDIFF).mul_b(k, flag::BM_PT0);
                r.xmove(i, flag::XM_CLR).xmove(i, flag::XM_ADD_D0).xmove(i, flag::XM_ADD_MUL);
                if i + 1 == value_blocks {
                    r.set(flag::PT_ROT);
                }
            }
        }
        level2_on_salt_row(pb);
    } else if 1usize << shape.folding == 2 * RATE {
        // 2^folding base values = 8 per block over 2 blocks, then the salt block (folding 4 — every live carrier)
        assert_eq!(blocks.len(), 3);
        for (i, block) in blocks.iter().enumerate() {
            pb.leaf_block(block, i == 0);
            let r = pb.cur();
            if i < 2 {
                for k in 0..4 {
                    r.mul_a(k, flag::AM_BASEPAIR).mul_b(k, flag::BM_PT0);
                    let j = 4 * i + k;
                    r.xmove(j, flag::XM_CLR).xmove(j, flag::XM_ADD_DBASE).xmove(j, flag::XM_ADD_MUL);
                }
                if i == 1 {
                    r.set(flag::PT_ROT);
                }
            }
        }
        level2_on_salt_row(pb);
    } else if 1usize << shape.folding == 4 * RATE {
        // ⭐ H12 PATH B — THE 32-VALUE BASE LEAF (folding 5: the certificate at T = 2^15, user ruling 2026-10-04). Sixteen
        // level-1 products do not fit the eight accumulators, so level-2 and level-3 folds interleave with the four value
        // blocks; the schedule is the minimum found MECHANICALLY by `h12_fold5_leaf_schedule_search` over the row's exact
        // fold algebra (docs/H12 §10.4): 4 inserted rows before the salt block, levels 3–5 on the first three path rows,
        // four `PT_ROT_UP`s after. Lane k folds `(X[2k], X[2k+1])` by the head challenge into `X[k]` or `X[k+4]` as
        // `CLR + X[2·out mod 8] + MUL` (for `out = 0` this equals today's `X0 += MUL`); a value row folds its own four
        // D-pairs; the one move is `X2 ← X3` (`XM_ADD_NEXT`). A compute-only row is opened explicitly, and a leaf block after
        // one opens its own row (`perm_row` would otherwise merge onto the compute row).
        assert_eq!(blocks.len(), 5, "a 32-value base leaf is four value blocks and the salt block");
        fn level1(r: &mut RowFlags, base: usize) {
            for k in 0..4 {
                r.mul_a(k, flag::AM_BASEPAIR).mul_b(k, flag::BM_PT0);
                let j = base + k;
                r.xmove(j, flag::XM_CLR).xmove(j, flag::XM_ADD_DBASE).xmove(j, flag::XM_ADD_MUL);
            }
        }
        // row 0: block 0 → X0..X3 (level 1, head r1)
        pb.leaf_block(blocks[0], true);
        level1(pb.cur(), 0);
        // row 1: block 1 → X4..X7; head → r2
        pb.leaf_block(blocks[1], false);
        level1(pb.cur(), 4);
        pb.cur().set(flag::PT_ROT);
        // row 2 (inserted): level 2 of all four pairs → X0..X3; head → r1
        pb.new_row();
        for k in 0..4 {
            fold_pair(pb.cur(), k, k);
        }
        pb.cur().set(flag::PT_ROT_UP);
        // row 3: block 2 → X4..X7; head → r2
        pb.new_row();
        pb.leaf_block(blocks[2], false);
        level1(pb.cur(), 4);
        pb.cur().set(flag::PT_ROT);
        // row 4 (inserted): level 2 of (X4,X5),(X6,X7) → X6, X7; head → r3
        pb.new_row();
        fold_pair(pb.cur(), 2, 6);
        fold_pair(pb.cur(), 3, 7);
        pb.cur().set(flag::PT_ROT);
        // row 5 (inserted): level 3 of half A → X0, X1 and of (X6,X7) → X3; head → r2
        pb.new_row();
        fold_pair(pb.cur(), 0, 0);
        fold_pair(pb.cur(), 1, 1);
        fold_pair(pb.cur(), 3, 3);
        pb.cur().set(flag::PT_ROT_UP);
        // row 6 (inserted): rotation only; head → r1
        pb.new_row();
        pb.cur().set(flag::PT_ROT_UP);
        // row 7: block 3 → X4..X7; head → r2
        pb.new_row();
        pb.leaf_block(blocks[3], false);
        level1(pb.cur(), 4);
        pb.cur().set(flag::PT_ROT);
        // row 8: the salt block; level 2 of (X4,X5),(X6,X7) → X6, X7; move X2 ← X3; head → r3
        pb.leaf_block(blocks[4], false);
        fold_pair(pb.cur(), 2, 6);
        fold_pair(pb.cur(), 3, 7);
        pb.cur().xmove(2, flag::XM_CLR).xmove(2, flag::XM_ADD_NEXT);
        pb.cur().set(flag::PT_ROT);
    } else {
        panic!("no base-leaf schedule for folding {} (4 and 5 are written)", shape.folding);
    }
    if 1usize << shape.folding == 4 * RATE {
        fold_levels_on_path_5(pb, siblings);
    } else {
        fold_levels_on_path(pb, siblings);
    }
    After { row: pb.cur_row() }
}

/// The whole `WhirVerifier::verify` as a program. Preconditions: `E3` holds the initial claimed sum, `R` holds
/// the commitment root, the builder's challenger model is at the transcript state where `verify` begins.
pub fn emit_whir_verify(pb: &mut ProgramBuilder, shape: &WhirShape, proof: &WhirProof<Fa4, Ea4, Mmcs16>) -> WhirCheckpoints {
    let mut cp = WhirCheckpoints::default();
    // the initial sumcheck
    let init = proof.initial_sumcheck.polynomial_evaluations();
    assert_eq!(init.len(), shape.folding0);
    let mut at = After { row: 0 };
    for (i, &[h0, hinf]) in init.iter().enumerate() {
        at = emit_sumcheck_round(pb, h0, hinf, pow_for(&proof.initial_sumcheck.pow_witnesses, i, shape.pow_init, flag::POW_INIT, Some(shape.first_slot())));
    }
    cp.after_initial_sumcheck = Some(at);
    for (r, rs) in shape.rounds.iter().enumerate() {
        let round = &proof.rounds[r];
        // parse_with_round: the root, then per OOD sample a challenge and its answer
        let root: [Fa4; RATE] = round.commitment.as_ref().expect("a round commitment").roots()[0];
        assert_eq!(pb.pending_len(), 0);
        pb.observe_slice(&root);
        pb.cur().set(flag::R_CAPTURE);
        assert_eq!(round.ood_answers.len(), rs.ood_samples);
        for &ans in &round.ood_answers {
            pb.sample_ext();
            pb.on_next(&[flag::Y_PUSH]);
            pb.observe_ext(ans);
            pb.on_duplex(&[flag::XMOVE + flag::XM_STRIDE * 0 + flag::XM_CLR, flag::XMOVE + flag::XM_STRIDE * 0 + flag::XM_ADD_D0]);
            pb.on_duplex_next(&[flag::F_PUSH1]);
        }
        // verify_stir_challenges: the query proof of work, the checkpoint sample, then the queries against the
        // PREVIOUS root
        if rs.query_pow > 0 {
            pb.observe(round.pow_witness);
            pb.pop_pow(flag::POW_QUERY, Some(rs.rf));
        } else {
            assert_eq!(round.pow_witness, Fa4::ZERO, "no pow witness when no grinding is asked");
        }
        pb.pop_discard();
        assert!(rs.ood_samples <= NF, "the F ring holds a round's OOD answers (its folds ride the FK stack)");
        assert!(shape.folding0 <= NPT);
        let mut roots = Vec::with_capacity(rs.num_queries);
        assert_eq!(round.queries.len(), rs.num_queries);
        for q in &round.queries {
            roots.push(emit_query(pb, rs, q));
            // the fold (in X0 since its level row) on the FK stack, then g^index on the VB stack
            pb.f_absorb();
            pb.bank_absorb();
        }
        cp.root_rows.push(roots);
        // pad the round's VB entries to a multiple of four (the closing identity's select groups are four slots of
        // ONE constraint): dummy pushes of the last query's VAR
        for _ in 0..(4 - rs.num_queries % 4) % 4 {
            pb.bank_absorb();
        }
        // α, then the combine: claimed += Σ_m α^m·[ood answers, folds] by a Horner walk from the newest push (the
        // highest power) down: the folds pop off the FK stack newest first (each unwind row reads its fold from
        // D_ext[1]), then one rotation up brings F's tail (the newest OOD answer) to F[0] and each read rotates again
        pb.new_row(); // never on the last query's path row (its registers are that query's checkpoint)
        pb.sample_ext();
        assert!(rs.num_queries > 0, "a WHIR round queries");
        for m in 0..rs.num_queries {
            pb.f_unwind();
            let r = pb.cur();
            if m == 0 {
                r.set(flag::Y_PUSH).set(flag::R_SHIFT);
                r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_DA);
            } else {
                r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
                r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_MUL).xmove(1, flag::XM_ADD_DA);
            }
            if m + 1 == rs.num_queries {
                r.set(flag::F_ROT_UP);
            }
        }
        for _ in 0..rs.ood_samples {
            let r = pb.row();
            r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
            r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_MUL).xmove(1, flag::XM_ADD_F0);
            r.set(flag::F_ROT_UP);
        }
        // claim' = claim + Σ: the sum walks X1 → X0 → X4 → X3 (X3 reads E3 and X4), then E3 ← X3
        pb.row().xmove(0, flag::XM_CLR).xmove(0, flag::XM_ADD_NEXT);
        pb.row().xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_X2J);
        pb.row().xmove(3, flag::XM_CLR).xmove(3, flag::XM_ADD_E).xmove(3, flag::XM_ADD_NEXT);
        pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        cp.after_round_combine.push(After { row: pb.cur_row() });
        // the round's sumcheck
        let evals = round.sumcheck.polynomial_evaluations();
        assert_eq!(evals.len(), rs.next_folding, "a round's sumcheck folds the NEXT phase's variables");
        for (i, &[h0, hinf]) in evals.iter().enumerate() {
            at = emit_sumcheck_round(pb, h0, hinf, pow_for(&round.sumcheck.pow_witnesses, i, rs.fold_pow, flag::POW_FOLD, Some(rs.rf)));
        }
        cp.after_round_sumcheck.push(at);
    }
    // the final polynomial: coefficient pairs absorbed and pushed into F's tail
    let final_poly = proof.final_poly.as_ref().expect("a final polynomial");
    let coeffs_v: Vec<Ea4> = final_poly.as_slice().to_vec();
    assert_eq!(coeffs_v.len(), shape.final_poly_len);
    assert!(coeffs_v.len() % 2 == 0 && coeffs_v.len() <= NF);
    assert_eq!(pb.pending_len(), 0);
    for pair in coeffs_v.chunks(2) {
        pb.observe_ext(pair[0]);
        pb.observe_ext(pair[1]);
        pb.cur().set(flag::F_PUSH2);
    }
    // the final queries against the last root, each checked against the final polynomial by Horner
    let fs = &shape.final_round;
    assert_eq!(proof.final_queries.len(), fs.num_queries);
    // verify_stir_challenges(final): the query proof of work, no checkpoint sample, then the draws
    if fs.query_pow > 0 {
        pb.observe(proof.final_pow_witness);
        pb.pop_pow(flag::POW_QUERY, Some(fs.rf));
    } else {
        assert_eq!(proof.final_pow_witness, Fa4::ZERO, "no pow witness when no grinding is asked");
    }
    let mut roots = Vec::with_capacity(fs.num_queries);
    let mut horner_rows = Vec::with_capacity(fs.num_queries);
    let n_coeffs = coeffs_v.len();
    for q in &proof.final_queries {
        roots.push(emit_query(pb, fs, q));
        // Horner: acc = c_{n−1}; acc = acc·var + c_i, reading F's tail upwards; VAR = this query's g^index (the final
        // round's values take part in no closing constraint, so they are never pushed). The previous
        // query's F restore must have finished before F is read again (a short query could otherwise overlap it).
        pb.drain_repeats();
        {
            let r = pb.row();
            r.set(flag::F_ROT_UP);
        }
        {
            let r = pb.row();
            r.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_F0);
            r.set(flag::F_ROT_UP);
        }
        for step in 1..n_coeffs {
            let r = pb.row();
            r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_VAR);
            r.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_MUL).xmove(4, flag::XM_ADD_F0);
            if step + 1 < n_coeffs {
                r.set(flag::F_ROT_UP);
            } else {
                r.set(flag::EXT_EQ);
            }
        }
        horner_rows.push(After { row: pb.cur_row() });
        // restore F over the following rows (the next query's rows do not read F)
        pb.repeat_on_next_rows(flag::F_ROT, n_coeffs);
    }
    cp.root_rows.push(roots);
    cp.final_horner_rows = horner_rows;
    // the final sumcheck
    if shape.final_sumcheck_rounds > 0 {
        let fsc = proof.final_sumcheck.as_ref().expect("final sumcheck data");
        let evals = fsc.polynomial_evaluations();
        assert_eq!(evals.len(), shape.final_sumcheck_rounds);
        for (i, &[h0, hinf]) in evals.iter().enumerate() {
            at = emit_sumcheck_round(pb, h0, hinf, pow_for(&fsc.pow_witnesses, i, fs.fold_pow, flag::POW_FOLD, Some(fs.rf)));
        }
    }
    cp.after_final_sumcheck = Some(at);
    cp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_air::CarrierParams;
    use crate::spartan_ccs::{committed_pcs_with, pcs_point, prove_committed_with, statement_hash, transcript, verify_committed_with, verify_core, verify_core_traced, SpartanCommittedProof};
    use crate::spartan_program::{emit_commitments, emit_core, emit_initial_ood, emit_pcs_claim, emit_statement, statement_words, SpartanCheckpoints, SpartanShape};
    use crate::spartan_gadgets::{poseidon2_constraints, poseidon2_permutation, P2Consts, R1csBuilder, WIDTH};
    use crate::universal_row::{emulate, first_unsatisfied_step, E_OFF, F_OFF, IO_LEN, H_OFF, NREG, O_OFF, RS_OFF, R_OFF, S_OFF, VAR_OFF, X_OFF, Y_OFF};
    use crate::whir_weights::{emit_closing_identity, InitialKind, InitialShape};
    use p3_multilinear_util::point::Point;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::constraints::Constraint;
    use p3_sumcheck::layout::{Layout, PrefixProver, Verifier as LayoutVerifier};
    use p3_sumcheck::table::TableShape;
    use p3_symmetric::Permutation;
    use p3_whir::pcs::committer::reader::ParsedCommitment;
    use p3_whir::pcs::verifier::WhirVerifier;

    /// The pin's carrier parameters: a higher rate so a round holds tens of queries (`F`/`VB` sized) — the
    /// certificate will run its own; the program is a function of whatever configuration it is given.
    const PIN_PARAMS: CarrierParams = CarrierParams::legacy(4, 0);

    fn reg_ext(regs: &[Fa4], off: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| regs[off + i])
    }


    /// ⭐ H12 PATH B — THE 32-VALUE BASE-LEAF SCHEDULE, FOUND MECHANICALLY (docs/H12 §10.3). The universal row folds a
    /// query's leaf with 4 multiplier lanes over `NX` accumulators: lane `k` folds the row's absorbed D-pair `k` (level 1)
    /// or the accumulator pair `(X[2k], X[2k+1])` (one level up), writing `X[k]` or `X[k+4]`; a slot may also take a MOVE
    /// from `X[j+4]`, `X[j−1]`, `X[j+1]` or `X[2j mod NX]`; every fold of one level reads the same PT head, which rotates
    /// by one per row. For folding 5 the 16 level-1 products do not fit the `NX` slots, and the lane→slot coupling makes
    /// every hand schedule end with a level-3 pair in non-adjacent slots — so the minimum-row schedule is SEARCHED here:
    /// states = (slot contents as fold-tree nodes, blocks absorbed, PT head); a row = an optional next leaf block, lane
    /// folds, moves, one rotation; cost = rows inserted between leaf blocks (the salt row and the path rows carry folds
    /// for free). Prints the schedule the base arm will hard-code, and asserts a schedule exists within 4 inserted rows.
    /// (The counts here are the ROW's lane and accumulator widths — `NX` accumulators, 4 lanes — never a block cover.)
    #[test]
    #[ignore]
    fn h12_fold5_leaf_schedule_search() {
        use crate::universal_row::NX;
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, HashMap};
        const NONE: u8 = 255;
        // a fold-tree node: level (0 = leaf … 5 = the whole leaf) × index; encoded level*32 + index
        fn node(level: u8, index: u8) -> u8 { level * 32 + index }
        fn level(n: u8) -> u8 { n / 32 }
        fn index(n: u8) -> u8 { n % 32 }
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        struct St { x: [u8; NX], absorbed: u8, head: u8, after: u8 }
        // a row, fixed-size: absorb (255 = none), 4 lanes × (kind: 0 none / 1 D / 2 X, out slot), one move (to, from; 255 = none), rot (+1 = 2, 0 = 1, −1 = 0)
        type Step = [u8; 12];
        // MEASURED 2026-10-04 18:37: the first form held 12M states with two heap Vecs each and a step per entry — the
        // job tree hit 10,240 MB and the runtime cap killed it. This form is an arena of fixed-size rows (~60 B/state).
        const BUDGET: u32 = 8; // inserted rows before the salt block
        const MAX_AFTER: u8 = 10; // path rows used after it (the certificate has 19)
        const MAX_STATES: usize = 6_000_000;
        let start = St { x: [NONE; NX], absorbed: 0, head: 0, after: 0 };
        let mut arena: Vec<(St, u32, Step)> = vec![(start, u32::MAX, [255; 12])];
        let mut best: HashMap<St, (u32, u32)> = HashMap::new(); // state → (cost, arena index)
        best.insert(start, (0, 0));
        let mut heap: BinaryHeap<Reverse<(u32, u32)>> = BinaryHeap::new(); // (cost, arena index)
        heap.push(Reverse((0, 0)));
        let mut goal: Option<u32> = None;
        let mut expanded = 0usize;
        let mut stop = String::from("heap exhausted");
        let mut deepest: (u8, usize, u32) = (0, 0, 0);
        while let Some(Reverse((cost, idx))) = heap.pop() {
            let st = arena[idx as usize].0;
            if best.get(&st).map(|(c, _)| *c) != Some(cost) { continue; }
            expanded += 1;
            let live = st.x.iter().filter(|&&n| n != NONE).count();
            if (st.absorbed, usize::MAX - live) > (deepest.0, usize::MAX - deepest.1) { deepest = (st.absorbed, live, cost); }
            if st.absorbed == 5 && live == 1 && st.x.contains(&node(5, 0)) { goal = Some(idx); break; }
            if cost > BUDGET * 100 + MAX_AFTER as u32 { stop = format!("cost {cost} over the budget"); break; }
            if arena.len() > MAX_STATES { stop = format!("{} states stored", arena.len()); break; }
            if st.absorbed == 5 && st.after >= MAX_AFTER { continue; }
            let absorb_opts: [Option<u8>; 2] = if st.absorbed < 5 { [Some(st.absorbed), None] } else { [None, None] };
            for (ai, absorb) in absorb_opts.into_iter().enumerate() {
                if ai == 1 && absorb_opts[0].is_none() { break; }
                let value_block = matches!(absorb, Some(b) if b < 4);
                // lane options: (kind, out, produced node)
                // a VALUE row must fold all four of its D-pairs on that row (the words exist only in D there) — so its lanes are
                // D-folds and nothing else, and it needs the head at level 1 (MEASURED: without this rule the search dropped
                // absorbed values silently — "3 blocks absorbed, 0 live nodes")
                if value_block && st.head != 0 { continue; }
                let lane_opts: Vec<Vec<(u8, usize, u8)>> = (0..4)
                    .map(|k| {
                        let mut v: Vec<(u8, usize, u8)> = Vec::new();
                        if value_block {
                            let out = node(1, 4 * absorb.expect("a value block") + k as u8);
                            v.push((1, k, out));
                            v.push((1, k + 4, out));
                            return v;
                        }
                        v.push((0, 0, NONE));
                        let (a, bb) = (st.x[2 * k], st.x[2 * k + 1]);
                        if a != NONE && bb != NONE && level(a) == level(bb) && level(a) == st.head && index(a) % 2 == 0 && index(bb) == index(a) + 1 {
                            let out = node(level(a) + 1, index(a) / 2);
                            v.push((2, k, out));
                            v.push((2, k + 4, out));
                        }
                        v
                    })
                    .collect();
                for c0 in &lane_opts[0] { for c1 in &lane_opts[1] { for c2 in &lane_opts[2] { for c3 in &lane_opts[3] {
                    let chosen = [c0, c1, c2, c3];
                    let mut written = [false; NX];
                    let mut consumed = [false; NX];
                    for (k, c) in chosen.iter().enumerate() {
                        if c.0 == 2 { consumed[2 * k] = true; consumed[2 * k + 1] = true; }
                    }
                    let mut ok = true;
                    for c in chosen {
                        if c.0 == 0 { continue; }
                        if written[c.1] || (st.x[c.1] != NONE && !consumed[c.1]) { ok = false; break; }
                        written[c.1] = true;
                    }
                    if !ok { continue; }
                    let mut nx = st.x;
                    for j in 0..NX { if consumed[j] { nx[j] = NONE; } }
                    for c in chosen { if c.0 != 0 { nx[c.1] = c.2; } }
                    // one move per row: into a slot empty after the folds, from a slot untouched this row
                    let mut move_opts: Vec<(u8, u8)> = vec![(255, 255)];
                    for j in 0..NX {
                        if written[j] || nx[j] != NONE { continue; }
                        for s in [(j + 4) % NX, (j + NX - 1) % NX, (j + 1) % NX, (2 * j) % NX] {
                            if s != j && st.x[s] != NONE && !written[s] && !consumed[s] { move_opts.push((j as u8, s as u8)); }
                        }
                    }
                    for mv in &move_opts {
                        let mut nx2 = nx;
                        if mv.0 != 255 { nx2[mv.0 as usize] = st.x[mv.1 as usize]; nx2[mv.1 as usize] = NONE; }
                        // conservation: every node survives except the two a fold consumes for the one it yields
                        let before = st.x.iter().filter(|&&n| n != NONE).count();
                        let after_n = nx2.iter().filter(|&&n| n != NONE).count();
                        let xf = chosen.iter().filter(|c| c.0 == 2).count();
                        let df = chosen.iter().filter(|c| c.0 == 1).count();
                        assert_eq!(after_n, before - xf + df, "a row must conserve every node");
                        for rot in [0i8, 1, -1] {
                            let nh = st.head as i8 + rot;
                            if !(0..=5).contains(&nh) { continue; }
                            let nabs = st.absorbed + u8::from(absorb.is_some());
                            let nafter = if st.absorbed == 5 { st.after + 1 } else { 0 };
                            let ns = St { x: nx2, absorbed: nabs, head: nh as u8, after: nafter };
                            let row_cost = if absorb.is_none() && st.absorbed < 5 { 100 } else if st.absorbed == 5 { 1 } else { 0 };
                            let nc = cost + row_cost;
                            let better = match best.get(&ns) { Some((c, _)) => nc < *c, None => true };
                            if better {
                                let mut step: Step = [255; 12];
                                step[0] = absorb.unwrap_or(255);
                                for (k, c) in chosen.iter().enumerate() { step[1 + 2 * k] = c.0; step[2 + 2 * k] = c.1 as u8; }
                                step[9] = mv.0; step[10] = mv.1; step[11] = (rot + 1) as u8;
                                let nidx = arena.len() as u32;
                                arena.push((ns, idx, step));
                                best.insert(ns, (nc, nidx));
                                heap.push(Reverse((nc, nidx)));
                            }
                        }
                    }
                }}}}
            }
        }
        if goal.is_none() {
            eprintln!("[fold5-search] NO schedule: stopped because {stop}; {expanded} states expanded, {} stored; deepest: {} block(s) absorbed, {} live node(s), cost {}", arena.len(), deepest.0, deepest.1, deepest.2);
        }
        let goal = goal.expect("⛔ no 32-value leaf schedule within the budget — read the stop reason above before concluding NX = 16 is needed");
        let total_cost = best[&arena[goal as usize].0].0;
        let mut path: Vec<u32> = Vec::new();
        let mut cur = goal;
        while cur != 0 { path.push(cur); cur = arena[cur as usize].1; }
        path.reverse();
        eprintln!("[fold5-search] expanded {expanded} states ({} stored); schedule cost {total_cost} = {} inserted row(s) before the salt × 100 + {} path rows after it; {} rows in all:", arena.len(), total_cost / 100, total_cost % 100, path.len());
        let kind = |k: u8| match k { 1 => "D", 2 => "X", _ => "-" };
        for (i, idx) in path.iter().enumerate() {
            let (st, _, step) = arena[*idx as usize];
            let slots: Vec<String> = st.x.iter().map(|&n| if n == NONE { "·".into() } else { format!("L{}#{}", level(n), index(n)) }).collect();
            let lanes: Vec<String> = (0..4).filter(|k| step[1 + 2 * k] != 0).map(|k| format!("lane{k}:{}→X{}", kind(step[1 + 2 * k]), step[2 + 2 * k])).collect();
            eprintln!(
                "  row {i:>2}: absorb {} | {} | move {} | rot {:+} → head {} | X = [{}]",
                if step[0] == 255 { "-".to_string() } else if step[0] == 4 { "salt".to_string() } else { format!("block{}", step[0]) },
                if lanes.is_empty() { "no folds".to_string() } else { lanes.join(" ") },
                if step[9] == 255 { "-".to_string() } else { format!("X{}←X{}", step[9], step[10]) },
                step[11] as i8 - 1,
                st.head,
                slots.join(" ")
            );
        }
        assert!(total_cost / 100 <= BUDGET, "the schedule inserts {} rows; the budget is {BUDGET}", total_cost / 100);
    }

    /// `n` chained production permutations with the chain's input and output public.
    fn perm_chain(n: usize) -> (crate::spartan_ccs::R1cs, Vec<Fa4>, Vec<Fa4>) {
        let x: [Fa4; WIDTH] = core::array::from_fn(|i| Fa4::from_u64(77 + 13 * i as u64));
        let perm = crate::pow_pq_air::production_perm();
        let mut y = x;
        for _ in 0..n {
            perm.permute_mut(&mut y);
        }
        let io: Vec<Fa4> = x.iter().chain(y.iter()).copied().collect();
        let cells = n * poseidon2_constraints();
        let n_vars = (2 * cells.next_power_of_two()).trailing_zeros() as usize;
        let mut b = R1csBuilder::new(n_vars, &io).expect("fits");
        let p2 = P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
        let mut s: [crate::spartan_gadgets::Lc; WIDTH] = core::array::from_fn(|i| b.io(i));
        for _ in 0..n {
            s = poseidon2_permutation(&mut b, &p2, &s);
        }
        for i in 0..WIDTH {
            let y_i = b.io(WIDTH + i);
            b.enforce_eq(&s[i], &y_i);
        }
        let (r1cs, w) = b.finish().expect("fits");
        (r1cs, w, io)
    }

    /// ⭐⭐⭐ THE PIN: the WHIR program's `X7` equals the native verifier's `claimed` at every checkpoint on a real
    /// committed Spartan proof (the transcript replayed natively up to `WhirVerifier::verify`), the last path
    /// row of every query leaves `H == R`, and every final query's Horner value equals its fold.
    #[test]
    fn the_whir_program_reproduces_the_native_verifiers_claimed_sums() {
        whir_program_pin(PIN_PARAMS);
    }

    /// ⭐ THE SAME PIN UNDER GRINDING: a 24-bit query grind and the DERIVED folding grinds (two-word witnesses,
    /// `grind_wide`), on a dense real proof — every proof-of-work row (`POW_INIT`, `POW_FOLD`, `POW_QUERY`) is
    /// exercised against the native verifier's transcript and the honest program must satisfy every row.
    /// MEASURED 2026-09-28 (fixpoint4): the certificate's rows refused the base step's proof at the first `POW_FOLD`
    /// row of the witness WHIR's round 0 (row 4171) while the native verifier accepted it, after the genesis proof
    /// had passed the same rows — this pin is the cheap reproduction of that class.
    #[test]
    fn the_whir_program_reproduces_the_native_verifier_with_grinding() {
        whir_program_pin(CarrierParams::legacy(4, 24));
    }

    /// The WHIR program at the CERTIFICATE'S OWN CARRIER (rate 1/2, 24-bit query grinds, the final polynomial sent
    /// at 7 variables): the query count per round is a function of the RATE, not the size — so this small proof has
    /// the certificate's ~80 queries per round, its VB pad, its 80-entry α Horner walk, and the `ConstantSendAt` fold
    /// schedule, on a dense proof, in seconds. The class fixpoint4 refused (row 4171) is exercised here if it is a
    /// function of the round's width; the fixpoint pin remains the proof at the release size.
    #[test]
    fn the_whir_program_reproduces_the_native_verifier_at_the_certificate_carrier() {
        whir_program_pin(crate::certificate_door::CERT_CARRIER);
    }

    /// ⭐ H12 PATH B — THE 32-VALUE BASE LEAF: the same pin at a FIRST FOLD OF FIVE with the gentler rate schedule the
    /// certificate moves to (docs/H12 §10.4). The prover lays 32-value leaves (the layout's folding block is the carrier's
    /// `first_fold`), the program folds them by the searched schedule (four inserted rows, levels 3–5 on the path, four
    /// rotations back), and every checkpoint must equal the native verifier's. RED until the schedule is right.
    #[test]
    fn the_whir_program_reproduces_the_native_verifier_at_a_first_fold_of_five() {
        whir_program_pin(CarrierParams { first_fold: 5, rate_growth: 2, ..CarrierParams::legacy(1, 8) });
    }

    fn whir_program_pin(carrier: CarrierParams) {
        // a real proof with at least one WHIR round
        let mut n = 8usize;
        let (r1cs, w, io) = loop {
            let c = perm_chain(n);
            if !committed_pcs_with(&c.0, carrier).config.round_parameters.is_empty() {
                break c;
            }
            n *= 2;
            assert!(n <= 256);
        };
        let bytes = prove_committed_with(&r1cs, &io, &w, carrier).expect("proves");
        let p: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let pcs = committed_pcs_with(&r1cs, carrier);
        let shape = WhirShape::of(&pcs.config);
        eprintln!(
            "[whir-program] {n} permutations, w_vars {}, {} round(s) + final: queries {:?}/{}, k {:?}/{}, final poly {}, final sumcheck {}",
            r1cs.w_vars(),
            shape.rounds.len(),
            shape.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            shape.final_round.num_queries,
            shape.rounds.iter().map(|r| r.k).collect::<Vec<_>>(),
            shape.final_round.k,
            shape.final_poly_len,
            shape.final_sumcheck_rounds
        );
        // the native prefix, replayed exactly as verify_committed runs it
        let mut ch = transcript(&r1cs, &io);
        ch.observe(p.commitment.clone());
        for mc in &p.open.hvzk_mask_commits {
            ch.observe(mc.clone());
        }
        let shapes = vec![TableShape::new(r1cs.w_vars(), 1)];
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
        for &eval in &p.open.initial_ood_answers {
            lv.add_virtual_eval(eval, &mut ch);
        }
        let r_y = verify_core(&mut ch, &r1cs, &io, &p.core).expect("the core verifies");
        let pt = pcs_point(&r_y[..r1cs.w_vars()]);
        lv.add_claim_at(0, &[0], &[p.core.w_eval], &pt, &mut ch);
        crate::spartan_ccs::absorb_claims_pad(&mut ch, 1);
        let alpha: Ea4 = ch.sample_algebra_element();
        let pcs_constraint = lv.constraint(alpha);
        let mut claimed = Ea4::ZERO;
        pcs_constraint.combine_evals(&mut claimed);
        // the native WHIR verifier, step by step, recording `claimed`
        let v = WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
        let mut nat = ch.clone();
        let cfg = &pcs.config;
        let mut want_claimed: Vec<Ea4> = Vec::new();
        let mut rfr = Vec::new();
        let mut prev_commitment = p.commitment.clone();
        let mut nat_claimed = claimed;
        let fr0 = p.open.initial_sumcheck.verify_rounds(&mut nat, &mut nat_claimed, cfg.starting_folding_pow_bits).expect("initial sumcheck");
        rfr.push(fr0);
        want_claimed.push(nat_claimed);
        let mut want_folds: Vec<Vec<(Fa4, Ea4)>> = Vec::new();
        let mut want_ood: Vec<Vec<Ea4>> = Vec::new();
        let mut want_alpha: Vec<Ea4> = Vec::new();
        let mut want_constraints: Vec<Constraint<Fa4, Ea4>> = Vec::new();
        for r in 0..cfg.n_rounds() {
            let rp = &cfg.round_parameters[r];
            let nc = ParsedCommitment::<Fa4, <Mmcs16 as Mmcs<Fa4>>::Commitment>::parse_with_round(&p.open, &mut nat, rp.num_variables, rp.ood_samples, r).expect("parse");
            let stir = v.verify_stir_challenges(&p.open, &mut nat, rp, &prev_commitment, rfr.last().unwrap(), r).expect("stir");
            want_folds.push(stir.iter().map(|(&var, &fold)| (var, fold)).collect::<Vec<(Fa4, Ea4)>>());
            want_ood.push(nc.ood_statement.evaluations.clone());
            let alpha_r: Ea4 = nat.sample_algebra_element();
            want_alpha.push(alpha_r);
            let c = Constraint::new(alpha_r, nc.ood_statement.clone(), stir);
            c.combine_evals(&mut nat_claimed);
            want_claimed.push(nat_claimed);
            want_constraints.push(c);
            let fr = p.open.rounds[r].sumcheck.verify_rounds(&mut nat, &mut nat_claimed, rp.folding_pow_bits).expect("round sumcheck");
            rfr.push(fr);
            want_claimed.push(nat_claimed);
            prev_commitment = nc.root;
        }
        let final_evaluations = p.open.final_poly.clone().expect("final poly");
        nat.observe_algebra_slice(final_evaluations.as_slice());
        let fc = cfg.final_round_config();
        let stir_final = v.verify_stir_challenges(&p.open, &mut nat, &fc, &prev_commitment, rfr.last().unwrap(), cfg.n_rounds()).expect("final stir");
        assert!(stir_final.verify(&final_evaluations), "the native final Horner checks hold");
        let final_folds: Vec<Ea4> = stir_final.iter().map(|(_, &e)| e).collect();
        let fsr = p3_sumcheck::verify_final_sumcheck_rounds(p.open.final_sumcheck.as_ref(), &mut nat, &mut nat_claimed, cfg.final_sumcheck_rounds, cfg.final_folding_pow_bits).expect("final sumcheck");
        rfr.push(fsr.clone());
        want_claimed.push(nat_claimed);

        // the program, from the same transcript state
        let params = shape.row_params(cfg, 0);
        let mut pb = ProgramBuilder::with_transcript_state(ch.input_buffer.clone(), ch.output_buffer.len());
        let cp = emit_whir_verify(&mut pb, &shape, &p.open);
        let ry = r_y.as_slice();
        let init = InitialShape { w: r1cs.w_vars(), n_vars: ry.len(), ood: p.open.initial_ood_answers.len(), rs_depth: 0, kind: InitialKind::Witness };
        let wcp = emit_closing_identity(&mut pb, &shape, &init);
        let (program, stream) = pb.finish();
        let mut regs0 = [Fa4::ZERO; NREG];
        regs0[S_OFF..S_OFF + WIDTH].copy_from_slice(&ch.sponge_state);
        for (k, &o) in ch.output_buffer.iter().enumerate() {
            regs0[O_OFF + k] = o;
        }
        regs0[R_OFF..R_OFF + RATE].copy_from_slice(&p.commitment.roots()[0]);
        regs0[E_OFF + 12..E_OFF + 16].copy_from_slice(&coeffs(claimed));
        // the prefix's pushes, as the Spartan core program will leave them: Y = [α_init, y_init_{m−1}, …, y_init_0]
        // (the initial constraint's eq points are [pt, ood_0, …]; an expanded OOD point's last coordinate is y),
        // RS = r_y newest-first
        let eq_points = &pcs_constraint.eq_statement.points;
        assert_eq!(eq_points.len(), 1 + init.ood, "the pcs point, then the initial OOD points");
        regs0[Y_OFF..Y_OFF + 4].copy_from_slice(&coeffs(alpha));
        for i in 0..init.ood {
            let y_i = eq_points[1 + i].as_slice()[init.w - 1];
            let at = Y_OFF + 4 * (init.ood - i);
            regs0[at..at + 4].copy_from_slice(&coeffs(y_i));
        }
        for k in 0..init.n_vars {
            let at = RS_OFF + 4 * k;
            regs0[at..at + 4].copy_from_slice(&coeffs(ry[init.n_vars - 1 - k]));
        }
        let io_row = vec![Fa4::ZERO; IO_LEN];
        let tr = emulate(&params, &io_row, regs0, &program, &stream);
        // the claimed sum lives in E3
        let x7 = |at: After| reg_ext(&tr.regs_after(at.row), E_OFF + 12);
        let mut k = 0usize;
        eprintln!(
            "[whir-program] pow bits: initial {} / round folding {:?} / round queries {:?} / final folding {} / final queries {}",
            shape.pow_init,
            shape.rounds.iter().map(|r| r.fold_pow).collect::<Vec<_>>(),
            shape.rounds.iter().map(|r| r.query_pow).collect::<Vec<_>>(),
            shape.final_round.fold_pow,
            shape.final_round.query_pow
        );
        assert_eq!(x7(cp.after_initial_sumcheck.unwrap()), want_claimed[k], "claimed after the initial sumcheck");
        k += 1;
        for r in 0..shape.rounds.len() {
            // every query of the round: the path ends at the round's root, g^index equals the native STIR variable,
            // the fold pushed into F equals the native fold; the OOD answers sit below the first fold
            for (j, at) in cp.root_rows[r].iter().enumerate() {
                let regs = tr.regs_after(at.row);
                assert_eq!(&regs[H_OFF..H_OFF + RATE], &regs[R_OFF..R_OFF + RATE], "round {r} query {j}: the path must end at the round's root");
                if regs[VAR_OFF] != want_folds[r][j].0 {
                    let first = at.row + 1 - shape.rounds[r].k;
                    let before = tr.regs_after(first - 1);
                    eprintln!(
                        "[whir-program] round {r} query {j}: rows {}..={} VAR {:?} G {:?}; before the path: G {:?} VAR {:?} B {:?}; native var {:?}; gens[{r}] {:?}",
                        first,
                        at.row,
                        regs[VAR_OFF],
                        regs[crate::universal_row::G_OFF],
                        before[crate::universal_row::G_OFF],
                        before[VAR_OFF],
                        &before[crate::universal_row::B_OFF..crate::universal_row::B_OFF + 12],
                        want_folds[r][j].0,
                        params.gens[r]
                    );
                    for row in first..=at.row {
                        let fl = &program[row];
                        eprintln!("  row {row}: M_MERKLE {} BSHIFT {} G_STEP {} G_INIT {} RF {:?}", fl.is_set(flag::M_MERKLE), fl.is_set(flag::BSHIFT), fl.is_set(flag::G_STEP), fl.is_set(flag::G_INIT), (0..NROUNDS).map(|q| fl.is_set(flag::rf(q))).collect::<Vec<_>>());
                    }
                }
                assert_eq!(regs[VAR_OFF], want_folds[r][j].0, "round {r} query {j}: g^index");
                assert_eq!(reg_ext(&regs, X_OFF), want_folds[r][j].1, "round {r} query {j}: the fold in X0, for the FK push");
                if j == 0 {
                    let nood = want_ood[r].len();
                    for i in 0..nood {
                        assert_eq!(reg_ext(&regs, F_OFF + 4 * (NF - 1 - i)), want_ood[r][nood - 1 - i], "round {r}: OOD answer {} at F's tail", nood - 1 - i);
                    }
                }
            }
            assert_eq!(reg_ext(&tr.regs_after(cp.after_round_combine[r].row), E_OFF), want_alpha[r], "round {r}: α in E0 at the combine");
            assert_eq!(x7(cp.after_round_combine[r]), want_claimed[k], "claimed after round {r}'s combine");
            k += 1;
            assert_eq!(x7(cp.after_round_sumcheck[r]), want_claimed[k], "claimed after round {r}'s sumcheck");
            k += 1;
        }
        for (j, at) in cp.root_rows[shape.rounds.len()].iter().enumerate() {
            let regs = tr.regs_after(at.row);
            assert_eq!(&regs[H_OFF..H_OFF + RATE], &regs[R_OFF..R_OFF + RATE], "final query {j}: the path must end at the last root");
            assert_eq!(regs[VAR_OFF], stir_final.iter().nth(j).map(|(&v, _)| v).unwrap(), "final query {j}: g^index");
        }
        for (j, at) in cp.final_horner_rows.iter().enumerate() {
            let regs = tr.regs_after(at.row);
            assert_eq!(reg_ext(&regs, X_OFF), final_folds[j], "final query {j}: the fold in X0");
            assert_eq!(reg_ext(&regs, X_OFF + 16), final_folds[j], "final query {j}: the Horner value in X4 equals the fold");
            // the check row hosts nothing of the next unit: no duplexing, no pops — a sumcheck row A sharing it
            // would rewrite X0 and X4 to the same value and make EXT_EQ pass vacuously (MEASURED)
            let fl = &program[at.row];
            assert!(fl.is_set(flag::EXT_EQ) && !fl.is_set(flag::M_ABSORB) && (0..4).all(|c| !fl.is_set(flag::POPU + flag::POPU_STRIDE * c + 3)), "final query {j}: the Horner check row is its own row");
        }
        assert_eq!(x7(cp.after_final_sumcheck.unwrap()), want_claimed[k], "claimed after the final sumcheck");

        // ⭐⭐ THE CLOSING IDENTITY (whir_weights.rs): E2 = f(r), every constraint's weight in E1 equals the native
        // `eval_constraints_poly` of that constraint alone, and D = claimed − Σ_c W_c·f(r) closes at zero.
        let fr_all = Point::new(rfr.iter().flat_map(|pt| pt.iter().copied()).collect::<Vec<Ea4>>());
        let final_value = final_evaluations.eval_ext::<Fa4>(&fsr);
        let order = PrefixProver::<Fa4, Ea4>::variable_order();
        let mut all_constraints = vec![pcs_constraint.clone()];
        all_constraints.extend(want_constraints.iter().cloned());
        assert_eq!(nat_claimed, order.eval_constraints_poly(&all_constraints, &fr_all) * final_value, "the native closing identity holds");
        let f_row = wcp.f_row.unwrap().row;
        eprintln!("[whir-program] closing identity rows {}..={}: f(r) at {f_row}, weights at {:?}", cp.after_final_sumcheck.unwrap().row + 1, wcp.close_row.unwrap().row, wcp.weights.iter().map(|(c, at)| (*c, at.row)).collect::<Vec<_>>());
        // f(r) stage by stage: c_0 at F[0] after the rotations; each chunk loaded into X0..X7 and folded to
        // f(t, p_1, p_2, p_3) = the chunk's own multilinear evaluation at the last three coordinates; the reload
        {
            let cv = final_evaluations.as_slice();
            let m = shape.final_sumcheck_rounds;
            let fsr_s = fsr.as_slice();
            let tail3 = Point::new(fsr_s[m - 3..].to_vec());
            for (name, row) in &wcp.f_stages {
                let regs = tr.regs_after(*row);
                if name == "rotated" {
                    assert_eq!(reg_ext(&regs, F_OFF), cv[0], "{name}: c_0 at F[0]");
                } else if let Some(t) = name.strip_prefix("chunk ").and_then(|s| s.strip_suffix(" loaded")).and_then(|s| s.parse::<usize>().ok()) {
                    for i in 0..8 {
                        assert_eq!(reg_ext(&regs, X_OFF + 4 * i), cv[8 * t + i], "{name}: X{i} = c_{}", 8 * t + i);
                    }
                } else if let Some(t) = name.strip_prefix("chunk ").and_then(|s| s.strip_suffix(" folded")).and_then(|s| s.parse::<usize>().ok()) {
                    let h_t = Poly::new(cv[8 * t..8 * t + 8].to_vec()).eval_ext::<Fa4>(&tail3);
                    assert_eq!(reg_ext(&regs, X_OFF), h_t, "{name}: X0 = the chunk's evaluation at the last three coordinates");
                } else if let Some(t) = name.strip_prefix("chunk ").and_then(|s| s.strip_suffix(" weighted")).and_then(|s| s.parse::<usize>().ok()) {
                    // E2 = Σ_{s≤t} h_s·w_s, w_s = Π_j (s_j ? r_{m−4−j} : 1 − r_{m−4−j}) (chunk bit j ↔ PT[3+j] = the
                    // (m−4−j)-th coordinate; PT[k] is the (m−1−k)-th)
                    let hi = shape.final_poly_len.trailing_zeros() as usize - 3;
                    let mut want = Ea4::ZERO;
                    for s_idx in 0..=t {
                        let h_s = Poly::new(cv[8 * s_idx..8 * s_idx + 8].to_vec()).eval_ext::<Fa4>(&tail3);
                        let w_s = (0..hi).fold(Ea4::ONE, |acc, j| {
                            let c = fsr_s[m - 4 - j];
                            acc * if (s_idx >> j) & 1 == 1 { c } else { Ea4::ONE - c }
                        });
                        want += h_s * w_s;
                    }
                    assert_eq!(reg_ext(&regs, E_OFF + 8), want, "{name}: E2 = the weighted chunk sum so far");
                }
            }
        }
        assert_eq!(reg_ext(&tr.regs_after(f_row), E_OFF + 8), final_value, "E2 = f(r), the final polynomial at the final sumcheck point");
        assert_eq!(wcp.weights.len(), all_constraints.len(), "one weight per constraint");
        for &(c, at) in &wcp.weights {
            let want = order.eval_constraints_poly(&[all_constraints[c].clone()], &fr_all);
            let got = reg_ext(&tr.regs_after(at.row), E_OFF + 4);
            if got != want {
                let cst = &all_constraints[c];
                eprintln!("[whir-program] constraint {c}: {} eq points, {} selects, {} variables; E1 {got:?} want {want:?}", cst.eq_statement.points.len(), cst.iter_sels().count(), cst.num_variables());
            }
            assert_eq!(got, want, "constraint {c}: its weight in E1 equals eval_constraints_poly");
        }
        let close = wcp.close_row.unwrap().row;
        assert_eq!(reg_ext(&tr.regs_after(close), E_OFF + 12), Ea4::ZERO, "D = claimed − Σ W_c·f(r) closes at zero");

        // ⭐ the lifted instance's verdict, step by step: the honest trace satisfies every row, and a flipped proof
        // word is REFUSED — a leaf value (ROOT_CHECK), a pow witness (POW_INIT), a Merkle sibling (ROOT_CHECK) and a
        // final-polynomial coefficient (the Horner EXT_EQ). A flipped sumcheck evaluation only moves the claim; the
        // closing identity (W3) is what refuses it.
        assert_eq!(first_unsatisfied_step(&params, &io_row, regs0, &program, &stream), None, "the honest WHIR program satisfies every row");
        let refuse = |which: &str, row: usize, slot: usize| {
            let mut bad = stream.clone();
            bad[row][slot] += Fa4::ONE;
            let at = first_unsatisfied_step(&params, &io_row, regs0, &program, &bad);
            assert!(at.is_some(), "{which}: a flipped stream word ({row}, {slot}) must be refused");
            assert!(at.unwrap() >= row, "{which}: the refusal is at or after the flipped row");
            eprintln!("[whir-program] tamper {which}: word ({row}, {slot}) flipped → refused at row {}", at.unwrap());
        };
        let root0 = cp.root_rows[0][0].row;
        // the LAST value row of query 0's leaf: the second `M_LEAF` row below its root check (the first is the salt
        // block) — layout-agnostic across the folding-4 and folding-5 base-leaf schedules (folding 5 inserts
        // compute-only rows between its value blocks; `root0 − k − 2` is one of them there, and a flipped stream word on
        // a row that absorbs nothing is rightly not refused — MEASURED 2026-10-04, third parity run)
        let leaf_rows: Vec<usize> = (0..root0).rev().filter(|&r| program[r].is_set(flag::M_LEAF) && !program[r].is_set(flag::M_MERKLE)).take(2).collect(); // a path compression row is `M_MERKLE ∧ M_LEAF`
        assert_eq!(leaf_rows.len(), 2, "query 0 has a salt row and at least one value row below its root check");
        refuse("leaf value", leaf_rows[1], 0);
        refuse("Merkle sibling", root0 - 3, 0);
        // any kind of pow row: a carrier whose initial sumcheck grinds 0 bits (the certificate's, at a small size)
        // still has query grinds
        let pow_row = program.iter().position(|fl| fl.is_set(flag::POW_INIT) || fl.is_set(flag::POW_FOLD) || fl.is_set(flag::POW_QUERY)).expect("a pow row");
        refuse("pow witness", pow_row, 0);
        let coeff_row = program.iter().position(|fl| fl.is_set(flag::F_PUSH2)).expect("a final coefficient row");
        refuse("final coefficient", coeff_row, 0);
        // a moved CLAIMED evaluation touches no transcript word: only the closing identity refuses it
        let mut regs_bad = regs0;
        regs_bad[E_OFF + 12] += Fa4::ONE;
        assert_eq!(first_unsatisfied_step(&params, &io_row, regs_bad, &program, &stream), Some(close), "a moved claim is refused at the closing row and nowhere else");
        let mut bad = stream.clone();
        bad[0][0] += Fa4::ONE;
        let at = first_unsatisfied_step(&params, &io_row, regs0, &program, &bad);
        assert!(at.is_some(), "a flipped sumcheck evaluation is refused");
        eprintln!("[whir-program] closing identity: f(r), {} weights and D == 0 equal native; a moved claim is refused at row {close} only; a flipped h0 is refused at row {}", wcp.weights.len(), at.unwrap());
        eprintln!("[whir-program] {} rows reproduce {} claimed checkpoints, {} path roots and {} final Horner checks", program.len(), want_claimed.len(), cp.root_rows.iter().map(|r| r.len()).sum::<usize>(), cp.final_horner_rows.len());
    }

    /// ⭐ M5 SIZING CENSUS (prints, asserts only shape sanity): the WHIR shapes of the certificate-scale polynomials
    /// — the witness half of a T-step row program (`n_vars − 1` = t_bits + V_BITS variables) and the fixed table
    /// (22) — at the carrier rates and grinding levels M5 chooses between, with the row-bank capacities they need
    /// (`F` holds a round's folds + OOD answers, `VB` every round's queries, `NROUNDS` both runs' slots).
    #[test]
    fn the_certificate_scale_whir_shapes_census() {
        use crate::committed_air::pcs_with;
        use crate::universal_row::{NF, NROUNDS, NVB, V_BITS};
        let mut worst_f = 0usize;
        for (rate, pow, send) in [(1usize, 0usize, 6usize), (1, 16, 6), (1, 20, 6), (1, 20, 7), (1, 20, 8), (2, 0, 6), (2, 20, 7), (4, 0, 6), (4, 16, 7)] {
            for t_bits in [13usize, 14, 15] {
                let w_vars = t_bits + V_BITS;
                for (name, vars) in [("witness", w_vars), ("fixed", 22usize)] {
                    // a configuration WhirConfig refuses is reported, not fatal: at folding 4 the two-adicity (24) caps
                    // `vars + log_inv_rate ≤ 28` (`log_folded_domain_size <= F::TWO_ADICITY`)
                    let Ok(cfg) = std::panic::catch_unwind(|| {
                        pcs_with(vars, CarrierParams { send_vars: send, ..CarrierParams::legacy(rate, pow) }).config
                    }) else {
                        eprintln!("[census] rate 1/{} pow {pow:>2} send {send} t_bits {t_bits} {name:>7} {vars:>2} vars: REFUSED by WhirConfig::new (vars + log_inv_rate > 28: the two-adicity cap)", 1usize << rate);
                        continue;
                    };
                    let shape = WhirShape::of(&cfg);
                    let queries: Vec<usize> = shape.rounds.iter().map(|r| r.num_queries).collect();
                    let f_need = shape.rounds.iter().map(|r| r.ood_samples).max().unwrap_or(0).max(shape.final_poly_len);
                    let vb_need: usize = shape.rounds.iter().chain(core::iter::once(&shape.final_round)).map(|r| r.num_queries.div_ceil(4) * 4).sum();
                    worst_f = worst_f.max(f_need);
                    eprintln!(
                        "[census] rate 1/{} pow {pow:>2} send {send} t_bits {t_bits} {name:>7} {vars:>2} vars: {} rounds queries {queries:?} final {} poly {} ood {} | init pow {} fold pow {:?} | F needs {f_need} (NF {NF}) VB needs {vb_need} (NVB {NVB}) slots {} (NROUNDS {NROUNDS})",
                        1usize << rate,
                        shape.rounds.len(),
                        shape.final_round.num_queries,
                        shape.final_poly_len,
                        cfg.commitment_ood_samples,
                        shape.pow_init,
                        shape.rounds.iter().map(|r| r.fold_pow).collect::<Vec<_>>(),
                        shape.slots()
                    );
                    assert!(shape.final_poly_len >= 8 && shape.final_poly_len <= NF, "the final polynomial fits emit_final_value and F");
                }
            }
        }
        eprintln!("[census] the largest per-round F need seen: {worst_f}");
    }

    /// ⭐⭐⭐ THE WHOLE COMMITTED VERIFIER AS ONE PROGRAM from a fresh transcript (`spartan_program.rs` + the WHIR
    /// program + the closing identity) on a REAL proof: the statement rows bind the inner statement to the public
    /// statement hash; every sumcheck claim, `eq(τ, r_x)`, `claim2`, `r_y` and `claimed` equal the native trace; D
    /// closes at zero; the honest program satisfies every row. REFUSALS: a flipped statement word (the statement
    /// ROOT_CHECK row), a flipped sumcheck-#1 coefficient (that round's EXT_EQ row), and a flipped `w_eval` — the ONE
    /// witness read — refused at the closing row and nowhere else.
    /// ⛔ FOUND 2026-09-28 16:0x: this pin had LOST its `#[test]` attribute — the M5 sizing census had been inserted
    /// between the attribute and the function, so the census carried two attributes and this pin ran nowhere; the
    /// "whole verifier as one program" claim rested on a test that could not run. Restored, and parameterized.
    #[test]
    fn the_whole_committed_verifier_runs_as_one_program() {
        whole_verifier_pin(PIN_PARAMS);
    }

    /// The whole verifier as one program UNDER GRINDING (24-bit query grinds, derived two-word folding grinds): the
    /// cheap reproduction of fixpoint4's row-4171 refusal class on a dense real proof, end to end.
    #[test]
    fn the_whole_committed_verifier_runs_as_one_program_with_grinding() {
        whole_verifier_pin(CarrierParams::legacy(4, 24));
    }

    /// The whole verifier as one program at the CERTIFICATE'S OWN CARRIER (see the WHIR-only variant above).
    #[test]
    fn the_whole_committed_verifier_runs_as_one_program_at_the_certificate_carrier() {
        whole_verifier_pin(crate::certificate_door::CERT_CARRIER);
    }

    fn whole_verifier_pin(carrier: CarrierParams) {
        let mut n = 8usize;
        let (r1cs, w, io) = loop {
            let c = perm_chain(n);
            if !committed_pcs_with(&c.0, carrier).config.round_parameters.is_empty() {
                break c;
            }
            n *= 2;
            assert!(n <= 256);
        };
        let bytes = prove_committed_with(&r1cs, &io, &w, carrier).expect("proves");
        assert!(verify_committed_with(&r1cs, &io, &bytes, carrier), "the native verifier accepts the proof");
        let p: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let pcs = committed_pcs_with(&r1cs, carrier);
        let shape = WhirShape::of(&pcs.config);
        let sshape = SpartanShape { m_vars: r1cs.m_vars, n_vars: r1cs.n_vars, w_vars: r1cs.w_vars(), io_len: io.len(), ood: p.open.initial_ood_answers.len() };
        // the native trace
        let mut ch = transcript(&r1cs, &io);
        ch.observe(p.commitment.clone());
        for mc in &p.open.hvzk_mask_commits {
            ch.observe(mc.clone());
        }
        let shapes = vec![TableShape::new(r1cs.w_vars(), 1)];
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
        for &eval in &p.open.initial_ood_answers {
            lv.add_virtual_eval(eval, &mut ch);
        }
        let (r_y, trace, _) = verify_core_traced(&mut ch, &r1cs, &io, &p.core, None).expect("the core verifies");
        let pt = pcs_point(&r_y[..r1cs.w_vars()]);
        lv.add_claim_at(0, &[0], &[p.core.w_eval], &pt, &mut ch);
        crate::spartan_ccs::absorb_claims_pad(&mut ch, 1);
        let alpha: Ea4 = ch.sample_algebra_element();
        let pcs_constraint = lv.constraint(alpha);
        let mut claimed = Ea4::ZERO;
        pcs_constraint.combine_evals(&mut claimed);
        // the program
        let sh = statement_hash(&r1cs, &io);
        let words = statement_words(&sshape, &io);
        let params = shape.row_params(&pcs.config, r1cs.m_vars - 1);
        let mut pb = ProgramBuilder::new();
        let st_row = emit_statement(&mut pb, &sh, &words);
        let mask_roots: Vec<[Fa4; RATE]> = p.open.hvzk_mask_commits.iter().map(|c| c.roots()[0]).collect();
        emit_commitments(&mut pb, &p.commitment.roots()[0], &mask_roots);
        emit_initial_ood(&mut pb, &p.open.initial_ood_answers);
        let mut scp = SpartanCheckpoints::default();
        emit_core(&mut pb, &sshape, &p.core, &mut scp);
        let claimed_row = emit_pcs_claim(&mut pb, p.core.w_eval, sshape.ood, 0);
        let cp = emit_whir_verify(&mut pb, &shape, &p.open);
        let init = InitialShape { w: r1cs.w_vars(), n_vars: r_y.len(), ood: sshape.ood, rs_depth: 0, kind: InitialKind::Witness };
        let wcp = emit_closing_identity(&mut pb, &shape, &init);
        let (program, stream) = pb.finish();
        let regs0 = [Fa4::ZERO; NREG];
        let mut io_row = vec![Fa4::ZERO; IO_LEN];
        io_row[crate::universal_row::io_block(1)].copy_from_slice(&sh);
        let tr = emulate(&params, &io_row, regs0, &program, &stream);
        let e3 = |row: usize| reg_ext(&tr.regs_after(row), E_OFF + 12);
        eprintln!(
            "[whole-program] {} rows: statement {} | core {}..={} | claimed {} | whir {}..={} | closing {}..={}",
            program.len(),
            st_row.row,
            scp.outer_claims[0].row,
            scp.inner_claims.last().unwrap().row,
            claimed_row.row,
            claimed_row.row + 1,
            cp.after_final_sumcheck.unwrap().row,
            wcp.f_row.unwrap().row,
            wcp.close_row.unwrap().row
        );
        {
            let regs = tr.regs_after(st_row.row);
            assert_eq!(&regs[H_OFF..H_OFF + RATE], &sh[..], "the statement words hash to the public statement hash");
            assert_eq!(&regs[R_OFF..R_OFF + RATE], &sh[..], "R holds the public statement hash");
        }
        assert_eq!(scp.outer_claims.len(), trace.outer_claims.len());
        for (i, at) in scp.outer_claims.iter().enumerate() {
            assert_eq!(e3(at.row), trace.outer_claims[i], "sumcheck #1 round {i}: the claim in E3");
        }
        assert_eq!(reg_ext(&tr.regs_after(scp.outer_claims.last().unwrap().row), E_OFF + 8), trace.eq, "eq(τ, r_x) in E2");
        assert_eq!(e3(scp.claim2_row.unwrap().row), trace.claim2, "claim2 = ra·a + rb·b + rc·c in E3");
        for (i, at) in scp.inner_claims.iter().enumerate() {
            assert_eq!(e3(at.row), trace.inner_claims[i], "sumcheck #2 round {i}: the claim in E3");
        }
        {
            let regs = tr.regs_after(scp.inner_claims.last().unwrap().row);
            for k in 0..r_y.len() {
                assert_eq!(reg_ext(&regs, RS_OFF + 4 * k), r_y[r_y.len() - 1 - k], "RS[{k}] = r_y newest-first");
            }
        }
        assert_eq!(e3(claimed_row.row), claimed, "claimed in E3 after the pcs claim");
        assert_eq!(reg_ext(&tr.regs_after(claimed_row.row), E_OFF), alpha, "α in E0");
        assert_eq!(reg_ext(&tr.regs_after(claimed_row.row), Y_OFF), alpha, "α at Y's head");
        let close = wcp.close_row.unwrap().row;
        assert_eq!(e3(close), Ea4::ZERO, "D closes at zero: the whole verifier accepts the proof");
        assert_eq!(first_unsatisfied_step(&params, &io_row, regs0, &program, &stream), None, "the whole program satisfies every row");
        // refusals
        let refused_at = |row: usize, slot: usize| {
            let mut bad = stream.clone();
            bad[row][slot] += Fa4::ONE;
            first_unsatisfied_step(&params, &io_row, regs0, &program, &bad)
        };
        let leaf0 = st_row.row + 1 - words.chunks(RATE).count();
        assert!(program[leaf0].is_set(flag::M_LEAF) && program[leaf0].is_set(flag::H_RESET));
        assert_eq!(refused_at(leaf0, 0), Some(st_row.row), "a flipped statement word is refused at the statement ROOT_CHECK row");
        let r1 = scp.outer_claims[0].row - 8;
        assert!(program[r1].is_set(flag::M_ABSORB), "the round's first duplexing row");
        assert_eq!(refused_at(r1, 0), Some(r1 + 2), "a flipped sumcheck-#1 coefficient is refused at that round's EXT_EQ row");
        // w_eval — the ONE witness read — is ABSORBED, so a flip moves the claim AND every later challenge: the first
        // proof-of-work row after it refuses the diverged transcript (MEASURED: row 229 = the WHIR program's first pow
        // row, two rows after `claimed`), long before the closing row would have refused the moved claim.
        let w_row = (0..claimed_row.row).rev().find(|&r| program[r].is_set(flag::XMOVE + flag::XM_STRIDE * 2 + flag::XM_ADD_D0) && program[r].is_set(flag::M_ABSORB)).expect("the w_eval duplexing row");
        let w_refused = refused_at(w_row, 0).expect("a flipped w_eval — the one witness read — must be refused");
        assert!(w_refused > w_row && w_refused <= close, "refused after the flip and no later than the closing row");
        eprintln!("[whole-program] GREEN: {} rows verify the committed Spartan proof end to end; statement flip → row {}, coefficient flip → row {}, w_eval flip → row {w_refused} (the first pow row after it; the closing row is {close})", program.len(), st_row.row, r1 + 2);
    }
}

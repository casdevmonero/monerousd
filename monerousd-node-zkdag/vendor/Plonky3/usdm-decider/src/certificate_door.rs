// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ THE CERTIFICATE DOOR (spec `docs/O1-OPENINGS-RECURSION-SPEC.md` § "M6 — the door") — the whole-chain
//! certificate as ONE Spartan-committed proof of the release's universal-row R1CS `U` per step.
//!
//! A step is a proof that the universal row, run for `T = 2^CERT_T_BITS` rows on the program `P`, accepted: `P` is
//! the verifier of an inner proof of the SAME shape (M4a–M4c rows) followed by the acc-step rows (M5) — so a step
//! proves "the step below verified, and this block's summary and work were folded onto its state". Its public io is
//! `[pad ‖ digest(P) ‖ statement_hash(inner io) ‖ F_ROOT ‖ state]` (`universal_row::io_block`): the program digest
//! pins WHICH rows ran (`FINAL`), the statement hash binds the whole inner io, `F_ROOT` is the fixed table's release
//! root the matrix argument opened against, and `state = state_hash(acc, work, tip_summary, tip_block_work)` is the
//! one number an adopter recomputes from the bundle. The base step's inner object is a proof of the GENESIS program
//! `G` (`acc_program::genesis_program`): any node can mint it, it is not a secret, and a step that verifies it is a
//! chain that starts at genesis with zero work (`IOCHK_BASE` admits exactly `digest(P)` or `digest(G)` as the inner
//! program).
//!
//! `digest(P)` is a function of the proof SHAPE alone (every emitter lays flags by shape and prover data by stream),
//! so it is a release constant: computed once from the program emitted for the genesis proof
//! (`certificate_program_digest`) and pinned equal across steps.
//!
//! §9.6 for this door (`verify_certificate_step`): 1 PoW — the header's, checked by the node's sync path as today;
//! the certificate adds none and removes none. 2 Proof — `verify_committed_uniform`: two sumchecks, the matrix
//! argument and two WHIR openings, native and O(1), over a statement whose io THIS door fixes (pad zero, block 0 =
//! `digest(P)`, block 2 = `F_ROOT`). 3 Conservation — none carried (no value moves). 4 Replay — a certificate is
//! bound to `(acc, work, tip_summary, tip_block_work)` through io block 3; re-presenting it for another tip fails the
//! adopter's recomputation. 5 Bounded work — one proof of one fixed shape; `CERT_BYTES_MAX` is measured, then
//! enforced by prover and verifier (no growth axis: the shape has no chain-length term). 6 Parity with
//! the one-table IVC door this REPLACED (`ivc_one_table`, deleted at source 2026-09-28), check for check: (a) decode + shape ✓
//! (`SpartanCommittedProof` fail-closed, the shape-only `R1cs`); (b) the base anchors at genesis with zero work ✓
//! (`IOCHK_BASE` + `G`'s io block 3 = the genesis state); (c) `acc' = fold(acc, summary)` ✓ (the M5 fold row);
//! (d) `work' = work + block_work` without wrap ✓ (limb rows + `RANGE24`, `AccStep::compute` refuses a `u128`
//! overflow natively too); (e) the recursion ✓ (the whole inner verifier as rows); (f) the outer bind ✓ (io block 3
//! + the statement hash, strictly more than the old door's `expected_chal` fold); (g) the byte cap ✓
//! (`CERT_BYTES_MAX`). A check the old door runs and this one does not: none identified.
//!
//! ROOT-LAYER: this module IS the producer and the verifier of the new certificate object; nothing upstream is
//! patched. MEASURED: see the fixpoint pin `a_certificate_step_verifies_the_step_below_it_at_the_fixpoint` (rows
//! used of T, prove time, bytes) and the `MEASURED` lines on the constants below. MUST-STAY-GREEN: every
//! `fixed_program` / `acc_program` / `spartan_ccs` pin (the emitters are shared); the node's `whole_chain_cert` door
//! until the swap lands.

use crate::acc_program::{emit_acc_step, genesis_program, genesis_state_hash, program_digest, AccRows, AccStep, AccStepIn};
use crate::committed_air::{pcs_with, CarrierParams, COMMITTED_FOLDING};
use crate::fixed_program::{emit_fixed_whir_prelude, emit_observe_claims, emit_pcs_claims, emit_summand_check, emit_zat_close, Banks, CertShape, RsIdx};
use crate::hiding_decider::{Ea4, Fa4, Mmcs16};
use crate::matrix_argument::{FixedColumns, MatrixProof};
use crate::matrix_program::emit_matrix_argument;
use crate::spartan_ccs::{committed_pcs_with, fixed_commitment_root, fixed_table, prove_committed_uniform_owned_profiled, statement_hash, verify_committed_uniform, R1cs, SpartanCommittedProof, SpartanCore};
use crate::spartan_gadgets::RATE;
use crate::spartan_program::{emit_commitments, emit_core, emit_fixed_commitment, emit_initial_ood, emit_statement, statement_words, SpartanCheckpoints, SpartanShape};
use crate::uniform_r1cs::UniformR1cs;
use crate::universal_row::{emulate, first_unsatisfied_step, flag, io_block, uniform_instance, RowFlags, RowParams, IO_LEN, IO_PAD, NREG, NSTREAM, V_BITS};
use crate::verifier_program::ProgramBuilder;
use crate::whir_program::{emit_whir_verify, RoundShape, WhirCheckpoints, WhirShape};
use crate::whir_weights::{emit_closing_identity, InitialKind, InitialShape};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_whir::pcs::proof::{QueryOpening, SumcheckData, WhirProof, WhirRoundProof};
use serde::{Deserialize, Serialize};

type Commitment = <Mmcs16 as Mmcs<Fa4>>::Commitment;

/// The certificate's height: `T = 2^15` rows (H12 path B, user ruling 2026-10-04: the Johnson bound at launch). The
/// verifier program of a certificate-shaped inner proof plus the acc-step rows must fit below `T − 2` (INIT at row 0,
/// FINAL at row T − 2) — the recursion FIXPOINT, MEASURED by the fixpoint pin (rows used printed there). A 2^15-step
/// instance is a 2^28-constraint R1CS whose witness (2^28 words, 28 variables) is committed at rate 1/2 with a first
/// fold of 5 — the two-adicity cap `vars + start_rate − first_fold ≤ 24` holds at equality. The JB query counts
/// (round 0 ≈ 170, ≈ 290 over the run) ride the BK/FK hash-chain stacks (§12 C, 7bb968b + 16320cd), not register
/// queues: docs/H12-WHIR-PROVEN-SOUNDNESS.md §10–12.
pub const CERT_T_BITS: usize = 15;
/// The witness carrier (H12 path B, docs/H12 §10): rate 1/2, the first fold 5 (32-value base leaves, the schedule of
/// §10.4), the inverse rate growing +2 per round, the final polynomial sent at 7 variables, sized under the JOHNSON
/// BOUND. `pow_bits` is 24 — the one-word grinder's ceiling `F::bits() − 7` (§11), derived from the field, not tuned.
/// Cons: the query count roughly doubles against the CapacityBound shape (≈ +3 KB step, rows measured by the fixpoint).
pub const CERT_CARRIER: CarrierParams = CarrierParams {
    start_rate: 1,
    pow_bits: 24,
    send_vars: 7,
    regime: p3_whir::parameters::SecurityAssumption::JohnsonBound,
    first_fold: 5,
    rate_growth: 2,
    max_fold_grind: crate::committed_air::FIELD_GRIND_LIMIT,
    // verified in a circuit whose grind table is written for one figure per folding group
    fold_grind_per_fold: false,
};
/// The fixed table's carrier: rate 1/32, 24 query-grinding bits, the inverse rate growing +2 per round, sized under
/// the JOHNSON BOUND — the table is release data and its commitment root is the release constant
/// `CertParams::fixed_root`. MEASURED 2026-10-23 (scratchpad/night/h12-fixed-r32g24.log): queries [32, 23, 18] + 14,
/// 100.0 JB bits (the CapacityBound `legacy(4, 16)` shape scored 54.0). Growth 3 asks a fold grind above the one-word
/// grinder's 24 bits; rate 1/128 breaks two-adicity. Cons: ≈ 47 rows per fixed-WHIR query, measured by the fixpoint.
pub const CERT_FIXED_CARRIER: CarrierParams = CarrierParams {
    regime: p3_whir::parameters::SecurityAssumption::JohnsonBound,
    rate_growth: 2,
    ..CarrierParams::legacy(5, 24)
};
/// ⭐ THE STEP-SIZE CAP, ENFORCED BY PROVER AND VERIFIER. A step's length is a function of its SHAPE alone: field words
/// serialize as fixed 4-byte arrays (`MontyField31::serialize`), every vector length is the shape's, so a real step is
/// byte-for-byte the length of the shape-only skeleton (MEASURED at T = 2^14: genesis 178,093 B = skeleton 178,093 B).
/// MEASURED 2026-10-24 (`the_release_digest_comes_from_the_shape_alone`): the T = 2^15 Johnson-bound step of 5bf5453 is
/// 377,393 B — over the old 262,144 cap, so no certificate of the release shape could be minted or verified. The cap is
/// 384 KiB: the measured step + 15,823 B (4.2%), 21.8% of the ≤ 1.8 MB sync-bundle budget. Cons: +131,072 B worst-case
/// per bundle and per persisted step vs the old cap (+199,300 B real vs the T = 2^14 step), constant at any height. A
/// step above it is refused, never carried; a shape that outgrows it fails the shape-only pin in seconds.
pub const CERT_BYTES_MAX: usize = 393_216;

/// `digest(P)`: the release's verifier-program digest at `CERT_T_BITS` / `CERT_CARRIER` / `CERT_FIXED_CARRIER` —
/// MEASURED 2026-10-24 02:03 by the shape-only emission (`release_program_digest`, M6-D) at T = 2^15 under the
/// Johnson-bound carriers (H12 path B; 30,278 of 32,768 rows); the fixpoint pin asserts the same digest over REAL proofs, and `whole_chain_cert::release_params` refuses to
/// start when the shape-derived digest is not this one. A shape change is a release act: it moves this constant on
/// purpose, never silently.
pub const CERT_PROGRAM_DIGEST: [Fa4; RATE] = Fa4::new_array([1_325_331_683, 1_662_763_261, 285_362_755, 521_843_478, 933_478_757, 816_335_037, 950_515_707, 1_968_205_626]);

/// One certificate step: the proof bytes and the public io they stand for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertStep {
    /// O1-FOOTPRINT-REVIEWED: bounded by `CERT_BYTES_MAX`; constant at any chain height.
    pub bytes: Vec<u8>,
    /// `IO_LEN` words: `[pad ‖ digest(P) ‖ statement_hash(inner io) ‖ F_ROOT ‖ state]`.
    pub io: Vec<Fa4>,
}

/// The release parameters of the certificate: built once per release from `(t_bits, carriers)` alone.
#[derive(Clone)]
pub struct CertParams {
    pub t_bits: usize,
    pub carrier: CarrierParams,
    pub fixed_carrier: CarrierParams,
    /// The row constants: the union of both WHIR shapes' round tables, the genesis digest as the base digest.
    pub row: RowParams,
    /// The universal-row instance at `T = 2^t_bits`.
    pub u: UniformR1cs,
    pub fixed: FixedColumns,
    /// The fixed table's stacked variable count (its WHIR's polynomial size).
    pub fixed_vars: usize,
    pub fixed_root: Commitment,
    pub shape_w: WhirShape,
    pub shape_f: WhirShape,
    /// `digest(G)`: the genesis program's digest at this `T`.
    pub base_digest: [Fa4; RATE],
    /// `digest(P)`: the verifier program's digest — `None` until `with_program_digest` (the release computes it once
    /// from the genesis proof's program, `certificate_program_digest`); a verifier without it accepts nothing.
    pub program_digest: Option<[Fa4; RATE]>,
}

/// The fixed table's stacked variable count under the committed layout.
fn fixed_vars_of(f: &FixedColumns) -> usize {
    PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(f)], COMMITTED_FOLDING).num_variables()
}

impl CertParams {
    /// The parameters from the height and the carriers. The row constants depend on the two WHIR shapes; the fixed
    /// shape depends on the fixed table's size, which depends on the template, which depends on the row constants —
    /// so the fixed shape is found as a FIXPOINT (the template's entry count moves by a handful of entries with the
    /// round tables; the stacked variable count is stable). `None` when no fixpoint appears within four rounds
    /// (fail closed: a release whose shapes do not settle has no certificate).
    #[must_use]
    pub fn new(t_bits: usize, carrier: CarrierParams, fixed_carrier: CarrierParams) -> Option<Self> {
        let (genesis_rows, _) = genesis_program(t_bits);
        let base_digest = program_digest(&genesis_rows);
        // the witness WHIR shape depends on the witness variable count alone: t_bits + V_BITS
        let w_shape_r1cs = R1cs { m_vars: 1, n_vars: 1 + t_bits + V_BITS, io_len: IO_LEN, a: Vec::new(), b: Vec::new(), c: Vec::new() };
        let cfg_w = committed_pcs_with(&w_shape_r1cs, carrier).config;
        let shape_w = WhirShape::of(&cfg_w);
        let mut fixed_vars_guess = 22;
        for _ in 0..4 {
            let cfg_f = pcs_with(fixed_vars_guess, fixed_carrier).config;
            let shape_f = WhirShape::of_with_offset(&cfg_f, shape_w.slots());
            // pt_port = m_vars − 1: the Spartan core's τ_i / r_x reads (the certificate pin's convention)
            let probe = uniform_instance(&WhirShape::row_params_multi(&[(&shape_w, &cfg_w), (&shape_f, &cfg_f)], 0), IO_LEN, t_bits);
            let m_vars = probe.m_vars();
            let row = WhirShape::row_params_multi(&[(&shape_w, &cfg_w), (&shape_f, &cfg_f)], m_vars - 1).with_base_digest(base_digest);
            let u = uniform_instance(&row, IO_LEN, t_bits);
            let fixed = FixedColumns::of(&u);
            let fixed_vars = fixed_vars_of(&fixed);
            if fixed_vars == fixed_vars_guess && u.m_vars() == m_vars {
                let fixed_root = fixed_commitment_root(&fixed, fixed_carrier);
                return Some(CertParams { t_bits, carrier, fixed_carrier, row, u, fixed, fixed_vars, fixed_root, shape_w, shape_f, base_digest, program_digest: None });
            }
            fixed_vars_guess = fixed_vars;
        }
        None
    }
    /// The release constant `digest(P)`.
    #[must_use]
    pub fn with_program_digest(mut self, d: [Fa4; RATE]) -> Self {
        self.program_digest = Some(d);
        self
    }
    /// The fixed table's release root as row words.
    fn fixed_root_words(&self) -> [Fa4; RATE] {
        self.fixed_root.roots()[0]
    }
}

/// A step's program, stream and public io, as emitted (before proving).
pub struct Emitted {
    pub program: Vec<RowFlags>,
    pub stream: Vec<[Fa4; NSTREAM]>,
    pub io: Vec<Fa4>,
    /// `digest(P)` of THIS program.
    pub digest: [Fa4; RATE],
    /// Rows emitted before the idle padding (the fixpoint margin is `T − 2 − rows_used`).
    pub rows_used: usize,
    pub acc_rows: AccRows,
    /// The two WHIR verifications' checkpoint rows (per round: the row after each query's path, the combine, the
    /// sumcheck) — the row MAP a refusal is read against (`first_unsatisfied_row` names a row; this names its section).
    pub witness_whir: WhirCheckpoints,
    pub fixed_whir: WhirCheckpoints,
}

/// The section of the witness (`w`) or fixed (`f`) WHIR verification that `row` falls in, as text — for a refusal
/// (`first_unsatisfied_row`) to be read as "round r, query q's path" rather than as a number. `None` outside both.
#[must_use]
pub fn whir_section_of(em: &Emitted, row: usize) -> Option<String> {
    for (name, cp) in [("w", &em.witness_whir), ("f", &em.fixed_whir)] {
        let init = cp.after_initial_sumcheck?.row;
        let first = cp.root_rows.first().and_then(|r| r.first()).map_or(init, |a| a.row);
        if row < first.min(init) {
            continue;
        }
        if row <= init {
            return Some(format!("{name}: initial sumcheck (ends {init})"));
        }
        for (r, roots) in cp.root_rows.iter().enumerate() {
            let combine = cp.after_round_combine.get(r).map(|a| a.row);
            let sc = cp.after_round_sumcheck.get(r).map(|a| a.row);
            for (q, a) in roots.iter().enumerate() {
                if row <= a.row {
                    return Some(format!("{name}: round {r} query {q} (path ends {}; round has {} queries)", a.row, roots.len()));
                }
            }
            if let Some(c) = combine {
                if row <= c {
                    return Some(format!("{name}: round {r} α-combine (ends {c})"));
                }
            }
            if let Some(s) = sc {
                if row <= s {
                    return Some(format!("{name}: round {r} sumcheck (ends {s})"));
                }
            }
        }
        if let Some(h) = cp.final_horner_rows.iter().position(|a| row <= a.row) {
            return Some(format!("{name}: final query {h} Horner (ends {})", cp.final_horner_rows[h].row));
        }
        if let Some(f) = cp.after_final_sumcheck {
            if row <= f.row {
                return Some(format!("{name}: final sumcheck (ends {})", f.row));
            }
        }
    }
    None
}

/// The verifier program for `inner` (a proof of `U` with public io `inner.io`) followed by the acc-step rows for
/// `step`, then INIT/FINAL and the idle padding to `T`; and the step's public io. `None` when the inner bytes do not
/// decode to the uniform proof shape, when the inner io is not `IO_LEN` words, or when the rows do not fit `T`
/// (fail closed — a program that does not fit has no certificate).
#[must_use]
pub fn emit_certificate_program(p: &CertParams, inner: &CertStep, step: &AccStep) -> Option<Emitted> {
    let pr: SpartanCommittedProof = postcard::from_bytes(&inner.bytes).ok()?;
    let mp = pr.matrix.as_ref()?;
    let fopen = pr.fixed_open.as_ref()?;
    if inner.io.len() != IO_LEN {
        return None;
    }
    let shape = p.u.shape();
    let f = &p.fixed;
    let n_cols = f.n_cols();
    let (ood_w, ood_f) = (pr.open.initial_ood_answers.len(), fopen.initial_ood_answers.len());
    let sshape = SpartanShape { m_vars: shape.m_vars, n_vars: shape.n_vars, w_vars: shape.w_vars(), io_len: IO_LEN, ood: ood_w };
    let cert = CertShape { n_vars: shape.n_vars, m_vars: shape.m_vars, ood_w, ood_f, nnz_bits: f.nnz_bits };
    let sh = statement_hash(&shape, &inner.io);
    let words = statement_words(&sshape, &inner.io);
    let froot = p.fixed_root_words();
    let mut pb = ProgramBuilder::new();
    // M4a–M4c: the inner verifier as rows, in the native verifier's order
    emit_statement(&mut pb, &sh, &words);
    let masks: Vec<[Fa4; RATE]> = pr.open.hvzk_mask_commits.iter().map(|c| c.roots()[0]).collect();
    emit_commitments(&mut pb, &pr.commitment.roots()[0], &masks);
    let fmasks: Vec<[Fa4; RATE]> = fopen.hvzk_mask_commits.iter().map(|c| c.roots()[0]).collect();
    emit_fixed_commitment(&mut pb, &froot, &fmasks);
    emit_initial_ood(&mut pb, &fopen.initial_ood_answers);
    emit_initial_ood(&mut pb, &pr.open.initial_ood_answers);
    let mut scp = SpartanCheckpoints::default();
    emit_core(&mut pb, &sshape, &pr.core, &mut scp);
    let mcp = emit_matrix_argument(&mut pb, f, mp);
    let mut banks = Banks::default();
    emit_observe_claims(&mut pb, pr.core.w_eval, &mp.openings);
    let srows = emit_summand_check(&mut pb, f, &cert, &mut banks);
    let prows = emit_pcs_claims(&mut pb, &cert, n_cols, &mut banks);
    let wcp = emit_whir_verify(&mut pb, &p.shape_w, &pr.open);
    let rs_idx = RsIdx { head: 3, nnz: f.nnz_bits, n_vars: shape.n_vars };
    let init_w = InitialShape { w: shape.w_vars(), n_vars: shape.n_vars, ood: ood_w, rs_depth: rs_idx.depth_above_ry(), kind: InitialKind::Witness };
    let ccp = emit_closing_identity(&mut pb, &p.shape_w, &init_w);
    let zrows = emit_zat_close(&mut pb, &cert, &sh, &words, &mut banks);
    // M5: the acc-step rows — the inner state (captured on the z̃ close's leaf row) folded with this block
    let acc_rows = emit_acc_step(&mut pb, step);
    // M4c: the fixed WHIR and its closing identity
    let pre = emit_fixed_whir_prelude(&mut pb, &froot, &mut banks);
    let fcp = emit_whir_verify(&mut pb, &p.shape_f, fopen);
    let n_sel = p.fixed_vars - f.nnz_bits;
    let init_f = InitialShape { w: p.fixed_vars, n_vars: f.nnz_bits, ood: ood_f, rs_depth: 0, kind: InitialKind::Fixed { n_sel, n_cols } };
    let fccp = emit_closing_identity(&mut pb, &p.shape_f, &init_f);
    let (mut program, mut stream) = pb.finish();
    // M4d: a COMPLETE statement — INIT on row 0, FINAL on row T − 2, idle rows between
    let t = 1usize << p.t_bits;
    let rows_used = program.len();
    // The row budget, section by section, printed on every emission so the fixpoint margin — and a refusal — is
    // legible: the section that grew is the lever. ROOT-LAYER: the rows are PRODUCED here, by the emitters in this
    // order; the count is read where it is made. MEASURED 2026-09-28 14:14 (the first fixpoint run): the emission for
    // a certificate-shaped inner proof refused silently — no count — after a 17-minute genesis proof; this line makes
    // the next refusal name its number. MUST-STAY-GREEN: the fixed_program certificate pin (same emitters).
    let row_of = |a: Option<crate::verifier_program::After>| -> String { a.map_or_else(|| "none".to_string(), |a| a.row.to_string()) };
    eprintln!(
        "[cert-door] program rows {rows_used} of T = {t}: argument ..={}, summand ..={}, claims ..={}, witness WHIR ..={}, closing ..={}, z̃ close {}, acc rows {}..={}, fixed prelude {}, fixed WHIR ..={}, fixed closing ..={}",
        row_of(mcp.round_claims.last().copied()),
        srows.check_row,
        prows.claimed_f_row,
        row_of(wcp.after_final_sumcheck),
        row_of(ccp.close_row),
        zrows.close_row,
        acc_rows.first,
        acc_rows.last,
        pre.row,
        row_of(fcp.after_final_sumcheck),
        row_of(fccp.close_row)
    );
    if rows_used + 2 > t {
        eprintln!("[cert-door] REFUSED: the verifier program needs {rows_used} rows + INIT/FINAL, above T = {t} — no certificate at this height");
        return None;
    }
    while program.len() < t {
        program.push(RowFlags::default());
        stream.push([Fa4::ZERO; NSTREAM]);
    }
    program[0].set(flag::INIT);
    program[t - 2].set(flag::FINAL);
    let digest = program_digest(&program);
    let mut io = vec![Fa4::ZERO; IO_LEN];
    io[io_block(0)].copy_from_slice(&digest);
    io[io_block(1)].copy_from_slice(&sh);
    io[io_block(2)].copy_from_slice(&froot);
    io[io_block(3)].copy_from_slice(&step.state);
    Some(Emitted { program, stream, io, digest, rows_used, acc_rows, witness_whir: wcp, fixed_whir: fcp })
}

/// `digest(P)` for this release: the program emitted for the genesis proof (any inner proof of the shape gives the
/// same flags). The base step is the natural place to read it; the pin asserts a later step's program has the same.
#[must_use]
pub fn certificate_program_digest(p: &CertParams, genesis: &CertStep) -> Option<[Fa4; RATE]> {
    let step = AccStep::base([0u64; crate::poseidon2_compress::DIGEST_LANES], 0)?;
    Some(emit_certificate_program(p, genesis, &step)?.digest)
}

/// The salt words a hiding Merkle leaf carries (`Mmcs16`'s `SALT_ELEMS`): the skeleton's openings must hold one
/// salt block so the leaf's block count is the real leaf's.
const SALT_WORDS: usize = 8;

/// A WHIR proof of `shape` with every value zero and every length the shape's (M6-D): what a row program's flags
/// are a function of. Every emitter lays flags by LENGTH and puts values on the stream, so the program emitted
/// over this object is the program emitted over any real proof of the shape. The lengths, in the emitters' order:
/// the initial sumcheck (`folding0` rounds, two witness words each when `pow_init > 0`), per round a root, the
/// OOD answers, one query witness word (zero when the round grinds 0 bits — `pow_for`'s rule), `num_queries`
/// openings of `2^folding` leaf values (base words in round 0, extension values after) with one salt block and `k`
/// siblings, the round's sumcheck; the final polynomial's `final_poly_len` coefficients, the final queries, and the
/// final sumcheck when the shape has one. Mask commitments: the decider's committed prover leaves
/// `hvzk_mask_commits` empty (no producer writes it — read 2026-09-28), so the skeleton carries none.
fn skeleton_whir(shape: &WhirShape, ood: usize) -> WhirProof<Fa4, Ea4, Mmcs16> {
    let sumcheck = |rounds: usize, pow_bits: usize| SumcheckData::<Fa4, Ea4> { polynomial_evaluations: vec![[Ea4::ZERO; 2]; rounds], pow_witnesses: vec![Fa4::ZERO; if pow_bits > 0 { 2 * rounds } else { 0 }] };
    let query = |rs: &RoundShape| -> QueryOpening<Fa4, Ea4, <Mmcs16 as Mmcs<Fa4>>::Proof> {
        let proof = (vec![vec![Fa4::ZERO; SALT_WORDS]], vec![[Fa4::ZERO; RATE]; rs.k]);
        if rs.ext_leaf {
            QueryOpening::Extension { values: vec![Ea4::ZERO; 1 << rs.folding], proof }
        } else {
            QueryOpening::Base { values: vec![Fa4::ZERO; 1 << rs.folding], proof }
        }
    };
    let fs = &shape.final_round;
    WhirProof {
        initial_ood_answers: vec![Ea4::ZERO; ood],
        initial_sumcheck: sumcheck(shape.folding0, shape.pow_init),
        rounds: shape
            .rounds
            .iter()
            .map(|rs| WhirRoundProof {
                commitment: Some(Commitment::new(vec![[Fa4::ZERO; RATE]])),
                ood_answers: vec![Ea4::ZERO; rs.ood_samples],
                pow_witness: Fa4::ZERO,
                queries: (0..rs.num_queries).map(|_| query(rs)).collect(),
                sumcheck: sumcheck(rs.next_folding, rs.fold_pow), // a round's sumcheck folds the NEXT phase's variables (≠ its leaf width once the first fold is 5)
            })
            .collect(),
        final_poly: Some(Poly::new(vec![Ea4::ZERO; shape.final_poly_len])),
        final_pow_witness: Fa4::ZERO,
        final_queries: (0..fs.num_queries).map(|_| query(fs)).collect(),
        final_sumcheck: if shape.final_sumcheck_rounds > 0 { Some(sumcheck(shape.final_sumcheck_rounds, fs.fold_pow)) } else { None },
        hvzk_mask_commits: Vec::new(),
        query_indices: Vec::new(),
    }
}

/// A certificate-shaped step with every value zero (M6-D): the release's proof SHAPE as bytes. The Spartan core
/// has `m_vars` outer rounds of four coefficients and `n_vars` inner rounds of three; the matrix argument
/// `nnz_bits` rounds of `degree + 1` coefficients and one opening per fixed column; the two WHIR openings are
/// [`skeleton_whir`] at the release shapes with the commitments' OOD sample counts from the same configurations
/// the prover builds. `None` when the shape does not serialize.
fn skeleton_step(p: &CertParams) -> Option<CertStep> {
    let shape = p.u.shape();
    let f = &p.fixed;
    let ood_w = committed_pcs_with(&shape, p.carrier).config.commitment_ood_samples;
    let ood_f = pcs_with(p.fixed_vars, p.fixed_carrier).config.commitment_ood_samples;
    let core = SpartanCore { outer: vec![vec![Ea4::ZERO; 4]; shape.m_vars], abc: [Ea4::ZERO; 3], inner: vec![vec![Ea4::ZERO; 3]; shape.n_vars], w_eval: Ea4::ZERO };
    let matrix = MatrixProof { m_at: Ea4::ZERO, rounds: vec![vec![Ea4::ZERO; f.degree() + 1]; f.nnz_bits], openings: vec![Ea4::ZERO; f.n_cols()] };
    let pr = SpartanCommittedProof {
        commitment: Commitment::new(vec![[Fa4::ZERO; RATE]]),
        core,
        open: skeleton_whir(&p.shape_w, ood_w),
        matrix: Some(matrix),
        fixed_open: Some(skeleton_whir(&p.shape_f, ood_f)),
    };
    Some(CertStep { bytes: postcard::to_allocvec(&pr).ok()?, io: vec![Fa4::ZERO; IO_LEN] })
}

/// `digest(P)` from the release parameters ALONE — no proof (M6-D, 2026-09-28): the program emitted over the
/// certificate-shaped skeleton, which is the program emitted over every real proof of the shape (the fixpoint pin
/// asserts the two digests equal; a skeleton that drifted from the proof structs shows there, never as a wrong
/// release constant). Seconds at `T = 2^14`, where a real proof is minutes. `None` when the program does not fit
/// `T` — the same refusal the real emission makes.
#[must_use]
pub fn release_program_digest(p: &CertParams) -> Option<[Fa4; RATE]> {
    certificate_program_digest(p, &skeleton_step(p)?)
}

/// The genesis proof's io — a pure function of the release parameters: `[pad ‖ digest(G) ‖ 0 ‖ F_ROOT ‖ genesis state]`.
/// ONE spelling, read by the prover and by [`verify_genesis_certificate`].
#[must_use]
pub fn genesis_io(p: &CertParams) -> Vec<Fa4> {
    let mut io = vec![Fa4::ZERO; IO_LEN];
    io[io_block(0)].copy_from_slice(&p.base_digest);
    io[io_block(2)].copy_from_slice(&p.fixed_root_words());
    io[io_block(3)].copy_from_slice(&genesis_state_hash());
    io
}

/// VERIFY a genesis proof (the base step's inner object) against the release parameters: its io is exactly
/// [`genesis_io`] and the uniform committed proof verifies against the shape-only instance and the release root — the
/// same check `verify_certificate_step` runs for a step, with block 0 = `digest(G)` instead of `digest(P)`. Fail-closed.
/// (Every base step re-verifies its inner in-circuit anyway; this is the direct check for a STORED genesis proof.)
#[must_use]
pub fn verify_genesis_certificate(p: &CertParams, step: &CertStep) -> bool {
    if step.bytes.is_empty() || step.bytes.len() > CERT_BYTES_MAX || step.io != genesis_io(p) {
        return false;
    }
    verify_committed_uniform(&p.u, &step.io, &step.bytes, p.carrier, p.fixed_carrier, &p.fixed_root)
}

/// The base step's inner object: a proof that the GENESIS program ran — io `[pad ‖ digest(G) ‖ 0 ‖ F_ROOT ‖ genesis
/// state]`. Not a certificate (`verify_certificate_step` refuses it: block 0 is `digest(G)`, not `digest(P)`); the
/// thing a base step verifies. Any node can mint it.
#[must_use]
pub fn prove_genesis_certificate(p: &CertParams) -> Option<CertStep> {
    let (program, stream) = genesis_program(p.t_bits);
    let io = genesis_io(p);
    let t0 = std::time::Instant::now();
    let trace = emulate(&p.row, &io, [Fa4::ZERO; NREG], &program, &stream);
    let t_emulate = t0.elapsed();
    // DB-371: the trace's witness is handed over, never copied beside itself (`prove_committed_uniform_owned_profiled`)
    let (bytes, profile) = prove_committed_uniform_owned_profiled(&p.u, &io, trace.w, p.carrier, p.fixed_carrier)?;
    eprintln!("[cert-door] genesis proved in {:.1?}: emulate {t_emulate:.1?}, {}; {} B", t0.elapsed(), profile.line(), bytes.len());
    Some(CertStep { bytes, io })
}

/// PROVE one step over the step below it. `inner` is the genesis proof (the base step) or the previous step;
/// `input` names the inner state this step consumes and this block's summary and work. Fail-closed: `None` when
/// the declared inner state is not the inner's io block 3, when the work sum leaves `u128`, when the program does
/// not fit `T`, when the emitted program's digest is not the release's, when the trace does not satisfy the rows
/// (`prove_committed_uniform` refuses it), or when the proof outgrows `CERT_BYTES_MAX`.
#[must_use]
pub fn prove_certificate_step(p: &CertParams, inner: &CertStep, input: AccStepIn) -> Option<CertStep> {
    let step = AccStep::compute(input)?;
    if inner.io.len() != IO_LEN || inner.io[io_block(3)] != step.state_prev[..] {
        return None;
    }
    let em = emit_certificate_program(p, inner, &step)?;
    if let Some(d) = p.program_digest {
        if em.digest != d {
            return None; // the shape drifted from the release: a step no verifier accepts is not minted
        }
    }
    let t0 = std::time::Instant::now();
    let trace = emulate(&p.row, &em.io, [Fa4::ZERO; NREG], &em.program, &em.stream);
    let t_emulate = t0.elapsed();
    // DB-371: the trace's witness is handed over, never copied beside itself (`prove_committed_uniform_owned_profiled`)
    let (bytes, profile) = prove_committed_uniform_owned_profiled(&p.u, &em.io, trace.w, p.carrier, p.fixed_carrier)?;
    // The step's cost by phase, once per step: the DSYNC certify cost is a list of named parts, never one number.
    eprintln!("[cert-door] step proved in {:.1?}: emulate {t_emulate:.1?}, {}; {} B", t0.elapsed(), profile.line(), bytes.len());
    if bytes.len() > CERT_BYTES_MAX {
        return None;
    }
    Some(CertStep { bytes, io: em.io })
}

/// The first row of the program that the trace does not satisfy — the diagnostic behind a refused prove.
#[must_use]
pub fn first_unsatisfied_row(p: &CertParams, em: &Emitted) -> Option<usize> {
    first_unsatisfied_step(&p.row, &em.io, [Fa4::ZERO; NREG], &em.program, &em.stream)
}

/// VERIFY one step (adopter side, O(1)): the pad is zero, block 0 is the release's `digest(P)`, block 2 is the
/// fixed table's release root, the bytes are within the cap, and the uniform committed proof verifies against the
/// shape-only instance and the release root. Fail-closed on everything, including a release without its program
/// digest.
#[must_use]
pub fn verify_certificate_step(p: &CertParams, step: &CertStep) -> bool {
    let Some(pd) = p.program_digest else {
        return false;
    };
    if step.bytes.is_empty() || step.bytes.len() > CERT_BYTES_MAX || step.io.len() != IO_LEN {
        return false;
    }
    if step.io[..IO_PAD].iter().any(|x| *x != Fa4::ZERO) || step.io[io_block(0)] != pd[..] || step.io[io_block(2)] != p.fixed_root_words()[..] {
        return false;
    }
    verify_committed_uniform(&p.u, &step.io, &step.bytes, p.carrier, p.fixed_carrier, &p.fixed_root)
}

/// io block 3: `state_hash(acc, work, tip_summary, tip_block_work)` — the adopter recomputes it from the bundle's
/// claimed `(acc, work)` and tip and compares.
#[must_use]
pub fn certificate_state(step: &CertStep) -> Option<[Fa4; RATE]> {
    (step.io.len() == IO_LEN).then(|| core::array::from_fn(|k| step.io[io_block(3)][k]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acc_program::state_hash;
    use crate::whole_chain_cert::WHOLE_CHAIN_GENESIS_ACC;

    /// The release parameters settle (the fixed shape's fixpoint) and match the census: the witness WHIR at rate 1/2
    /// with the final polynomial sent at 7 variables has 4 rounds and a 128-coefficient final polynomial; both shapes
    /// fit the row's round tables.
    #[test]
    fn the_certificate_parameters_settle_and_match_the_census() {
        let t0 = std::time::Instant::now();
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the shapes settle");
        assert_eq!(p.u.t_bits, CERT_T_BITS);
        assert_eq!(p.u.v_bits, V_BITS);
        assert_eq!(p.shape_w.rounds.len(), 4, "rate 1/2, send 7: four folding rounds over 27 variables");
        assert_eq!(p.shape_w.final_poly_len, 128, "the final polynomial at 7 variables");
        assert!(p.shape_w.slots() + p.shape_f.slots() <= crate::universal_row::NROUNDS);
        eprintln!(
            "[cert-door] params in {:.1?}: R = 2^{}, V = 2^{}, T = 2^{}; template {} entries → nnz_bits {}, {} fixed columns, fixed vars {}; witness WHIR queries {:?} final {} (pow_init {}); fixed WHIR queries {:?} final {}; digest(G) = {:?}",
            t0.elapsed(),
            p.u.r_bits,
            p.u.v_bits,
            p.u.t_bits,
            p.fixed.entries,
            p.fixed.nnz_bits,
            p.fixed.n_cols(),
            p.fixed_vars,
            p.shape_w.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            p.shape_w.final_round.num_queries,
            p.shape_w.pow_init,
            p.shape_f.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            p.shape_f.final_round.num_queries,
            p.base_digest
        );
    }

    /// THE EMULATOR at the release height (`#[ignore]`, run explicitly; no prove): `emulate` over the genesis program's
    /// 2^14 rows — the row trace the prover commits. MEASURED 2026-09-28 17:12 (recording builder per row): 79.9 s of
    /// a 338.5 s step; the values-only builder is scored here.
    #[test]
    #[ignore = "measurement at T = 2^14 (~1 min); run explicitly"]
    fn the_emulator_at_the_release_height() {
        let (program, stream) = genesis_program(CERT_T_BITS);
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the shapes settle");
        let mut io = vec![Fa4::ZERO; IO_LEN];
        io[io_block(0)].copy_from_slice(&p.base_digest);
        io[io_block(2)].copy_from_slice(&p.fixed_root_words());
        io[io_block(3)].copy_from_slice(&genesis_state_hash());
        let t0 = std::time::Instant::now();
        let trace = emulate(&p.row, &io, [Fa4::ZERO; NREG], &program, &stream);
        eprintln!("[cert-door] EMULATE at T = 2^{}: {} rows, {} trace words, in {:.1?}", CERT_T_BITS, trace.steps, trace.w.len(), t0.elapsed());
    }

    /// THE PROVER'S PHASE PROFILE at the release shape (heavy: one T = 2^14 prove, ~6 min; `#[ignore]`, run
    /// explicitly): proves the genesis step and prints `emulate`, `fixed_columns`, `commit_w`, `commit_f`, `ood`,
    /// `stream_abc`, `sumchecks`, `recommit`, `claims`, `open_w`, `open_f`, `encode` — the measurement every prover
    /// optimization is scored against (§9.1: the number, not the activity).
    #[test]
    #[ignore = "heavy: one T = 2^14 prove (~6 min); run explicitly for the prover's phase profile"]
    fn the_genesis_step_profile() {
        // the WHIR prover's own `#[instrument]` spans (prove_with_alpha → round → …; the Merkle tree's build at debug)
        // as a timed tree: the split of the witness opening into named parts (`RUST_LOG` narrows it)
        {
            use tracing_forest::util::LevelFilter;
            use tracing_forest::ForestLayer;
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            use tracing_subscriber::{EnvFilter, Registry};
            let env_filter = EnvFilter::builder().with_default_directive(LevelFilter::DEBUG.into()).from_env_lossy();
            let _ = Registry::default().with(env_filter).with(ForestLayer::default()).try_init();
        }
        // `MONEROUSD_PROFILE_T_BITS` (an instrument of THIS pin only): the same prove at a smaller T, so a prover
        // lever's memory and time can be A/B'd from one build without the production shape's RAM (user 2026-10-04:
        // prove it without relying on memory). Absent = the release shape; present and malformed = refused, never a
        // silent shape.
        // ROOT-LAYER: the shape a profile proves is chosen HERE, by the pin, and nowhere else — `CertParams`, the
        //   release prover and the certificate door read `CERT_T_BITS` untouched.
        // MEASURED: the release shape, 2026-10-04 11:18 — peak 6,137 MB, 431.9 s (scratchpad/db371-profile.tsv); the
        //   A/B rows at T = 2^12 are recorded beside it, labelled as A/B and never as the release number.
        // MUST-STAY-GREEN: `the_release_digest_comes_from_the_shape_alone` and every certificate pin at `CERT_T_BITS`;
        //   a profile line at another T says so in its first words.
        let t_bits = match std::env::var("MONEROUSD_PROFILE_T_BITS") {
            Err(_) => CERT_T_BITS,
            Ok(s) => s.trim().parse::<usize>().expect("MONEROUSD_PROFILE_T_BITS is a T exponent, e.g. 12"),
        };
        let t0 = std::time::Instant::now();
        let p = CertParams::new(t_bits, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the shapes settle");
        let t_params = t0.elapsed();
        let genesis = prove_genesis_certificate(&p).expect("the genesis proof");
        eprintln!(
            "[cert-door] PROFILE: T = 2^{t_bits}{}, params {t_params:.1?}, genesis step {} B, total {:.1?} (the phase line is printed by the prover)",
            if t_bits == CERT_T_BITS { " (the release shape)" } else { " (A/B shape — NOT the release number)" },
            genesis.bytes.len(),
            t0.elapsed()
        );
    }

    /// ⭐ THE RELEASE DIGEST FROM THE SHAPE ALONE (M6-D): the skeleton step decodes to the certificate shape, its
    /// program fits `T`, and its digest is a function of the shape — two skeletons emit one digest, and a skeleton
    /// whose witness WHIR lost a query does NOT (the digest sees the shape). Prints the digest and the rows: the
    /// tool that yields the release constant in seconds. Equality with a REAL proof's digest is the fixpoint pin's.
    #[test]
    fn the_release_digest_comes_from_the_shape_alone() {
        let t0 = std::time::Instant::now();
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the shapes settle");
        let sk = skeleton_step(&p).expect("the skeleton serializes");
        let decoded: SpartanCommittedProof = postcard::from_bytes(&sk.bytes).expect("the skeleton decodes to the proof shape");
        assert_eq!(decoded.open.rounds.len(), p.shape_w.rounds.len());
        assert_eq!(decoded.fixed_open.as_ref().unwrap().rounds.len(), p.shape_f.rounds.len());
        let step = AccStep::base([0u64; crate::poseidon2_compress::DIGEST_LANES], 0).unwrap();
        let em = emit_certificate_program(&p, &sk, &step).expect("the skeleton's program fits T");
        let d1 = release_program_digest(&p).expect("digest(P) from the shape");
        assert_eq!(d1, em.digest);
        assert_eq!(release_program_digest(&p), Some(d1), "deterministic");
        assert_eq!(d1, CERT_PROGRAM_DIGEST, "⛔ the release constant is not the shape's digest: the certificate program changed (a release act moves the constant on purpose)");
        // THE STEP FITS ITS CAP, FROM THE SHAPE: a real step's bytes are the skeleton's (fixed-width words — MEASURED
        // at T = 2^14: genesis 178,093 B = skeleton 178,093 B), so a shape whose step outgrows `CERT_BYTES_MAX` is a
        // certificate the prover refuses to mint and the door refuses to verify — caught here in seconds, not by a
        // 20-minute prove (MEASURED 2026-10-24: 5bf5453's T = 2^15 skeleton 377,393 B under a 262,144 cap).
        assert!(sk.bytes.len() <= CERT_BYTES_MAX, "⛔ the release step is {} B, above CERT_BYTES_MAX = {CERT_BYTES_MAX}: no certificate of this shape can be minted or verified", sk.bytes.len());
        // a skeleton with one witness query fewer emits a DIFFERENT program (the digest is the shape's)
        let mut fewer = decoded;
        fewer.open.rounds[0].queries.pop();
        let bytes = postcard::to_allocvec(&fewer).unwrap();
        let thinner = CertStep { bytes, io: vec![Fa4::ZERO; IO_LEN] };
        let r = std::panic::catch_unwind(|| emit_certificate_program(&p, &thinner, &step).map(|e| e.digest));
        assert!(!matches!(r, Ok(Some(d)) if d == d1), "⛔ a proof with a query fewer emitted the release program");
        eprintln!("[cert-door] M6-D shape-only digest in {:.1?}: program rows {} of {} (margin {}), skeleton {} B; digest(P) = {:?}", t0.elapsed(), em.rows_used, 1usize << p.t_bits, (1usize << p.t_bits) - 2 - em.rows_used, sk.bytes.len(), d1);
        // the row MAP: every WHIR section's row range, so a refusal's row reads as a section
        for (name, cp) in [("w", &em.witness_whir), ("f", &em.fixed_whir)] {
            let rounds: Vec<String> = cp
                .root_rows
                .iter()
                .enumerate()
                .map(|(r, roots)| {
                    format!(
                        "r{r}: {} queries rows {}..={} combine ..={} sumcheck ..={}",
                        roots.len(),
                        roots.first().map_or(0, |a| a.row),
                        roots.last().map_or(0, |a| a.row),
                        cp.after_round_combine.get(r).map_or(0, |a| a.row),
                        cp.after_round_sumcheck.get(r).map_or(0, |a| a.row)
                    )
                })
                .collect();
            eprintln!("[cert-door] {name} WHIR map: initial sumcheck ..={} | {} | final Horner ..={} | final sumcheck ..={}", cp.after_initial_sumcheck.map_or(0, |a| a.row), rounds.join(" | "), cp.final_horner_rows.last().map_or(0, |a| a.row), cp.after_final_sumcheck.map_or(0, |a| a.row));
        }
        let probe = std::env::var("CERT_ROW").ok().and_then(|s| s.parse::<usize>().ok());
        if let Some(row) = probe {
            eprintln!("[cert-door] row {row} is in section: {:?}", whir_section_of(&em, row));
        }
    }

    /// ⭐ THE PARALLEL GRIND IS THE SERIAL GRIND: the vendored challenger's proof-of-work search runs in parallel
    /// (rayon, chunked, minimum hit) and must return the SMALLEST valid witness — the element a serial scan meets
    /// first — so proof bytes never depend on the thread count (the workspace keeps `p3-maybe-rayon`'s `parallel`
    /// feature off for exactly this reason, §CA). Checked here against a serial scan on the decider's own challenger
    /// for several bit counts and transcript states; the search over 2^12 bits (~4,096 permutations) is measured.
    #[test]
    fn the_parallel_grind_returns_the_serial_witness() {
        use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
        use rand::SeedableRng;
        // states: `seed % 5 + 1` observed words (an input buffer 1..=5 deep), a sampled state (a non-empty output
        // buffer, the shape a WHIR round leaves) for seeds 6 and 8, and an input buffer at RATE − 1 (seed 7 observes
        // seven words) — the shapes the WHIR prover grinds from; bits up to the certificate's 24
        for (seed, bits) in [(1u64, 1usize), (2, 4), (3, 8), (4, 10), (5, 12), (6, 16), (7, 20), (8, 24)] {
            let perm = crate::hiding_decider::Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed));
            let mut ch = crate::hiding_decider::Chl::new(perm);
            let observed = if seed == 7 { 7 } else { seed % 5 + 1 };
            for k in 0..observed {
                ch.observe(Fa4::from_u64(1000 + 7 * k + seed));
            }
            if seed == 6 || seed == 8 {
                let _: Fa4 = ch.sample();
            }
            // the serial reference: the smallest witness whose check passes on a CLONE of the same state
            let serial = (0u64..)
                .map(Fa4::from_u64)
                .find(|&w| ch.clone().check_witness(bits, w))
                .expect("a witness exists");
            let t0 = std::time::Instant::now();
            let parallel = ch.clone().grind(bits);
            let dt = t0.elapsed();
            assert_eq!(parallel, serial, "seed {seed}, bits {bits}: the parallel grind must return the serial (smallest) witness");
            // and it is deterministic across two runs from the same state
            assert_eq!(ch.clone().grind(bits), parallel, "two grinds from one state agree");
            // the TWO-WORD grind: `[hi, lo]` with the smallest `hi` that admits a `lo` (0 at these depths), the same
            // `lo` a serial scan after observing `hi` meets first; the wide check accepts it, a moved word or a
            // one-word witness does not. TWO-PARTY-REVIEWED: the grinder (prover) and the checker (verifier) are the
            // two endpoints and the witness words are the bytes that cross between them — the verifier's clone
            // starts from the same public transcript state, as a remote verifier does from the same public proof.
            let wide = ch.clone().grind_wide(bits);
            assert_eq!(wide.len(), 2);
            let mut after_hi = ch.clone();
            after_hi.observe(wide[0]);
            let serial_lo = (0u64..).map(Fa4::from_u64).find(|&w| after_hi.clone().check_witness(bits, w)).expect("a lo exists");
            assert_eq!(wide[1], serial_lo, "the wide grind's lo is the serial scan's after hi");
            assert!(ch.clone().check_witness_wide(bits, &wide), "the wide check accepts the wide witness");
            let mut moved = wide.clone();
            moved[1] += Fa4::ONE;
            assert!(!ch.clone().check_witness_wide(bits, &moved), "a moved lo is refused");
            assert!(!ch.clone().check_witness_wide(bits, &wide[1..]), "a one-word witness is refused by the wide check");
            assert!(ch.clone().check_witness_wide(0, &[]) && !ch.clone().check_witness_wide(0, &wide), "at 0 bits only the empty witness is the encoding");
            eprintln!("[grind] seed {seed} bits {bits}: witness {} (serial == parallel), wide [{}, {}] in {dt:.1?}", p3_field::PrimeField64::as_canonical_u64(&parallel), p3_field::PrimeField64::as_canonical_u64(&wide[0]), p3_field::PrimeField64::as_canonical_u64(&wide[1]));
        }
        // the encoding invariant every live proof rests on: a zero-grind sumcheck's witness list is EMPTY — as it was
        // before the two-word folding witness (the field is 4 fixed bytes on the wire, so an empty list is NOT a zero
        // word: that is why the query grind stays one word and only the list-shaped folding witness widened)
        assert_eq!(postcard::to_allocvec(&Fa4::ZERO).unwrap().len(), 4, "a field word is 4 fixed bytes on the wire");
        assert_eq!(postcard::to_allocvec(&Vec::<Fa4>::new()).unwrap(), vec![0u8], "an empty witness list is one zero byte");
        assert!(crate::hiding_decider::Chl::new(crate::hiding_decider::Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(9))).grind_wide(0).is_empty(), "0 bits ⇒ the empty witness");
    }

    /// A committed proof WITH grinding end to end (the live carriers grind 0 bits, so the certificate is the first
    /// object whose proofs carry two-word witnesses): a small squaring chain at 8 query-grinding bits proves,
    /// verifies, and refuses a flipped byte in every stride — the wide witnesses are bound like every other byte.
    /// TWO-PARTY-REVIEWED: prover and verifier are the two endpoints of a proof system and the proof BYTES are the
    /// boundary they cross; the verifier here rebuilds everything from the public instance and those bytes, exactly
    /// as a verifier on another machine does — the same shape as every carrier pin in this crate.
    #[test]
    fn a_grinding_committed_proof_proves_verifies_and_has_no_free_byte() {
        use crate::spartan_ccs::{prove_committed_with, verify_committed_with, R1cs, Sparse};
        // x_{k+1} = x_k², 40 steps, public x0 and x_out (the shape of spartan_ccs's own pins)
        let steps = 40usize;
        let w_off = 1usize << crate::spartan_ccs::MIN_W_VARS;
        let (mut a, mut b, mut c): (Sparse, Sparse, Sparse) = (Vec::new(), Vec::new(), Vec::new());
        let mut cur = 1usize;
        let mut rows = 0usize;
        for k in 0..steps {
            let out = w_off + k;
            a.push((rows, cur, Fa4::ONE));
            b.push((rows, cur, Fa4::ONE));
            c.push((rows, out, Fa4::ONE));
            rows += 1;
            cur = out;
        }
        a.push((rows, cur, Fa4::ONE));
        b.push((rows, 0, Fa4::ONE));
        c.push((rows, 2, Fa4::ONE));
        rows += 1;
        let m_vars = rows.next_power_of_two().trailing_zeros() as usize;
        let r1cs = R1cs { m_vars, n_vars: crate::spartan_ccs::MIN_W_VARS + 1, io_len: 2, a, b, c };
        let x = Fa4::from_u64(3);
        let mut w = Vec::with_capacity(steps);
        let mut v = x;
        for _ in 0..steps {
            v = v * v;
            w.push(v);
        }
        let io = vec![x, v];
        let params = CarrierParams { send_vars: 6, ..CarrierParams::legacy(4, 8) };
        let t0 = std::time::Instant::now();
        let bytes = prove_committed_with(&r1cs, &io, &w, params).expect("the grinding proof proves");
        let t_prove = t0.elapsed();
        assert!(verify_committed_with(&r1cs, &io, &bytes, params), "the grinding proof verifies");
        let mut accepted = 0usize;
        let mut tried = 0usize;
        let mut m = bytes.clone();
        for i in (0..bytes.len()).step_by(61).chain(bytes.len().saturating_sub(64)..bytes.len()) {
            m[i] ^= 1u8 << (i % 8);
            tried += 1;
            if verify_committed_with(&r1cs, &io, &m, params) {
                accepted += 1;
            }
            m[i] = bytes[i];
        }
        eprintln!("[grind] grinding committed proof: {} B, prove {t_prove:.1?}, byte-flip {tried} positions, {accepted} accepted", bytes.len());
        assert_eq!(accepted, 0, "a flipped byte of a grinding proof was accepted");
    }

    /// ⭐⭐⭐ THE FIXPOINT (heavy: three T = 2^14 emulations and proofs). The genesis proof → the base step → a second
    /// step consuming the first: every step verifies at the door; the program digest is the SAME for both steps (a
    /// function of the shape, so a release constant); the state in io block 3 is what an adopter recomputes.
    /// Refused: the genesis proof presented as a certificate, a flipped byte of a step, a moved state word, a step
    /// whose declared inner state is not the inner's, a truncated step, a verifier without the release digest.
    #[test]
    fn a_certificate_step_verifies_the_step_below_it_at_the_fixpoint() {
        let t0 = std::time::Instant::now();
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the shapes settle");
        let genesis = prove_genesis_certificate(&p).expect("the genesis proof");
        let t_genesis = t0.elapsed();
        let digest_p = certificate_program_digest(&p, &genesis).expect("the program fits T");
        assert_eq!(release_program_digest(&p), Some(digest_p), "⛔ the SHAPE-ONLY digest (M6-D) is not the real proof's: the skeleton drifted from the proof structs");
        let p = p.with_program_digest(digest_p);
        assert!(!verify_certificate_step(&p, &genesis), "⛔ the genesis proof is NOT a certificate (block 0 is digest(G))");
        // the base step: block 1 over genesis
        let (summary1, bw1) = ([7u64, 11, 13, 17, 19, 23, 29, 31], (0x12_3456u128 << 24) + 0x54_3210);
        let base_in = AccStep::base(summary1, bw1).expect("a base step").input;
        let em1 = emit_certificate_program(&p, &genesis, &AccStep::compute(base_in).unwrap()).expect("fits");
        let t1 = std::time::Instant::now();
        let step1 = prove_certificate_step(&p, &genesis, base_in).unwrap_or_else(|| panic!("the base step proves (first unsatisfied row: {:?})", first_unsatisfied_row(&p, &em1)));
        let t_step1 = t1.elapsed();
        assert!(verify_certificate_step(&p, &step1), "the base step verifies at the door");
        let acc1 = crate::poseidon2_compress::compress(&WHOLE_CHAIN_GENESIS_ACC, &summary1);
        assert_eq!(certificate_state(&step1).unwrap(), state_hash(&acc1, bw1, &summary1, bw1), "io block 3 = the adopter's recomputation");
        // the second step: block 2 over step 1 — the recursion
        let (summary2, bw2) = ([101u64, 103, 107, 109, 113, 127, 131, 137], 0x77_7777u128);
        let in2 = AccStepIn { acc_prev: acc1, work_prev: bw1, summary_prev: summary1, bw_prev: bw1, summary: summary2, block_work: bw2 };
        let em2 = emit_certificate_program(&p, &step1, &AccStep::compute(in2).unwrap()).expect("fits");
        assert_eq!(em2.digest, digest_p, "⛔ the program digest is a function of the SHAPE: step 2's program must be step 1's");
        let t2 = std::time::Instant::now();
        let step2 = prove_certificate_step(&p, &step1, in2).unwrap_or_else(|| panic!("the second step proves (first unsatisfied row: {:?})", first_unsatisfied_row(&p, &em2)));
        let t_step2 = t2.elapsed();
        let t3 = std::time::Instant::now();
        assert!(verify_certificate_step(&p, &step2), "the second step verifies at the door");
        let t_verify = t3.elapsed();
        let acc2 = crate::poseidon2_compress::compress(&acc1, &summary2);
        assert_eq!(certificate_state(&step2).unwrap(), state_hash(&acc2, bw1 + bw2, &summary2, bw2));
        // refusals
        let mut wrong_in = in2;
        wrong_in.work_prev += 1;
        assert!(prove_certificate_step(&p, &step1, wrong_in).is_none(), "⛔ a step declaring an inner state the inner does not have was minted");
        let mut moved = step2.clone();
        moved.io[io_block(3)][0] += Fa4::ONE;
        assert!(!verify_certificate_step(&p, &moved), "⛔ a moved state word verified");
        let mut flipped = step2.clone();
        let mid = flipped.bytes.len() / 2;
        flipped.bytes[mid] ^= 0x10;
        assert!(!verify_certificate_step(&p, &flipped), "⛔ a flipped proof byte verified");
        let truncated = CertStep { bytes: step2.bytes[..step2.bytes.len() - 5].to_vec(), io: step2.io.clone() };
        assert!(!verify_certificate_step(&p, &truncated), "⛔ a truncated step verified");
        let blind = CertParams { program_digest: None, ..p.clone() };
        assert!(!verify_certificate_step(&blind, &step2), "a verifier without the release digest accepts nothing");
        // THE BYTE-FLIP CENSUS over a real step (`CERT_FLIP_STRIDE=<n>`: every n-th byte of step 2 flipped, each refused;
        // ≈ 0.2 s per verify at T = 2^14, so stride 61 over ~190 KB is ~10 min): the tool that says no byte of a
        // certificate is free — the same census that found the round-2 default tail on the settlement carriers.
        if let Some(stride) = std::env::var("CERT_FLIP_STRIDE").ok().and_then(|s| s.parse::<usize>().ok()).filter(|&s| s > 0) {
            let tc = std::time::Instant::now();
            let mut flips = 0usize;
            let mut at = 0usize;
            while at < step2.bytes.len() {
                let mut f = step2.clone();
                f.bytes[at] ^= 0x01 << (at % 8);
                assert!(!verify_certificate_step(&p, &f), "⛔ FREE BYTE: step 2 with byte {at} flipped verified");
                flips += 1;
                at += stride;
            }
            eprintln!("[cert-door] byte-flip census: {flips} flips at stride {stride} over {} B, every one refused, in {:.1?}", step2.bytes.len(), tc.elapsed());
        }
        eprintln!(
            "[cert-door] FIXPOINT at T = 2^{}: program rows {} of {} (margin {}), genesis proof {} B in {:.1?}, step 1 {} B in {:.1?}, step 2 {} B in {:.1?}, verify {:.1?}; digest(P) = {:?}",
            p.t_bits,
            em2.rows_used,
            1usize << p.t_bits,
            (1usize << p.t_bits) - 2 - em2.rows_used,
            genesis.bytes.len(),
            t_genesis,
            step1.bytes.len(),
            t_step1,
            step2.bytes.len(),
            t_step2,
            t_verify,
            digest_p
        );
    }
}

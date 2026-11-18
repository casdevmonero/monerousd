//! THE SPARTAN PREFIX AND CORE as universal-row instructions (`universal_row.rs`), emitted by `ProgramBuilder`:
//! everything `verify_committed_with` does before `WhirVerifier::verify` — the statement transcript, the commitment
//! and mask roots, the initial OOD claims, `verify_core` (τ, sumcheck #1, `abc`, `ra/rb/rc`, sumcheck #2) and the
//! pcs claim (`w_eval`, α, `claimed`) — laid onto rows so that the WHIR program (`whir_program.rs`) and the closing
//! identity (`whir_weights.rs`) can follow on the same transcript. The sumcheck round messages travel as MONOMIAL
//! COEFFICIENTS (`spartan_ccs.rs`, 2026-09-28): a round checks `2·c_0 + c_1 + … == claim` by `EXT_EQ` and folds the
//! claim by Horner — no Lagrange constants.
//!
//! Register conventions: the claim lives in `E3`; the running `eq(τ, r_x)` in `E2`; `a` in `E1`; `τ` then `r_x` are
//! pushed into `PT` (τ_i sits at the port `PT[m_vars − 1]` during round `i`); `ra, rb, rc` then `r_y` are pushed
//! into `RS` (newest first); the initial OOD univariates are pushed into `Y`, their answers into `F`'s tail; the
//! statement hash is bound to the public `io[8..16]` by `IOCHK_1` on every row that carries it and by a leaf hash of
//! the statement words checked against it (`ROOT_CHECK`).
//!
//! ROOT-LAYER: the schedule is the native verifier's own order of observes and samples; every value is read from
//! the stream at the row that absorbs it. MEASURED: pin `the_whole_committed_verifier_runs_as_one_program`
//! (whir_program.rs). MUST-STAY-GREEN: the universal-row, program-builder, WHIR-program and closing-identity pins.

use crate::hiding_decider::{Ea4, Fa4};
use crate::spartan_ccs::SpartanCore;
use crate::spartan_gadgets::RATE;
use crate::universal_row::{flag, RowFlags, NPT, NRS, NY};
use crate::verifier_program::{After, ProgramBuilder};

/// The inner statement's shape.
#[derive(Clone, Debug)]
pub struct SpartanShape {
    pub m_vars: usize,
    pub n_vars: usize,
    pub w_vars: usize,
    pub io_len: usize,
    /// The initial commitment's OOD samples.
    pub ood: usize,
}

/// Checkpoints: rows after which the named register holds the named value.
#[derive(Clone, Debug, Default)]
pub struct SpartanCheckpoints {
    /// The statement words' leaf hash equals `R` (the public statement hash) after this row.
    pub statement_row: Option<After>,
    /// `E3` = the claim after sumcheck #1 round `i`.
    pub outer_claims: Vec<After>,
    /// The `claim == eq(τ, r_x)·(a·b − c)` check row.
    pub abc_row: Option<After>,
    /// `E3 = claim2 = ra·a + rb·b + rc·c` after this row.
    pub claim2_row: Option<After>,
    /// `E3` = the claim after sumcheck #2 round `i`.
    pub inner_claims: Vec<After>,
    /// `E3 = claimed` (the pcs constraint's combined evaluation) after this row; `E0 = α`.
    pub claimed_row: Option<After>,
}

fn clr(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_CLR)
}

/// The statement: `R ← statement hash` (`IOCHK_1`), the transcript absorbs the hash (`IOCHK_1` again), and the
/// statement words are leaf-hashed and checked against `R`. The program starts here on a fresh transcript.
pub fn emit_statement(pb: &mut ProgramBuilder, statement_hash: &[Fa4; RATE], statement_words: &[Fa4]) -> After {
    assert_eq!(pb.pending_len(), 0);
    pb.capture_root(statement_hash);
    pb.cur().set(flag::IOCHK + 1);
    pb.observe_slice(statement_hash);
    pb.cur().set(flag::IOCHK + 1).set(flag::R_SHIFT);
    pb.leaf(statement_words);
    pb.cur().set(flag::ROOT_CHECK);
    After { row: pb.cur_row() }
}

/// The commitment root (kept in `R` for the WHIR program) and the hiding-mask roots.
pub fn emit_commitments(pb: &mut ProgramBuilder, commitment_root: &[Fa4; RATE], mask_roots: &[[Fa4; RATE]]) {
    assert_eq!(pb.pending_len(), 0);
    pb.observe_slice(commitment_root);
    pb.cur().set(flag::R_CAPTURE);
    pb.on_next(&[flag::R_SHIFT]);
    for root in mask_roots {
        pb.observe_slice(root);
    }
}

/// The FIXED commitment (a uniform instance): its root (the release constant, bound to the public `io[16..24]` by
/// `IOCHK_2` on the absorbing row) and its hiding-mask roots, absorbed right after the witness commitment as the
/// native prover does. `R` is not touched (the WHIR program needs the witness root there); the fixed WHIR program
/// captures the root again, `IOCHK_2`-checked, when its turn comes.
pub fn emit_fixed_commitment(pb: &mut ProgramBuilder, fixed_root: &[Fa4; RATE], mask_roots: &[[Fa4; RATE]]) {
    assert_eq!(pb.pending_len(), 0);
    pb.observe_slice(fixed_root);
    pb.cur().set(flag::IOCHK + 2);
    for root in mask_roots {
        pb.observe_slice(root);
    }
}

/// The initial OOD claims (`Layout::add_virtual_eval`): per answer a sampled univariate (pushed into `Y`) and the
/// answer (absorbed; pushed into `F`'s tail for the pcs claim's Horner).
pub fn emit_initial_ood(pb: &mut ProgramBuilder, answers: &[Ea4]) {
    for &ans in answers {
        pb.sample_ext();
        pb.on_next(&[flag::Y_PUSH]);
        pb.observe_ext(ans);
        pb.on_duplex(&[flag::XMOVE + flag::XM_STRIDE * 0 + flag::XM_CLR, flag::XMOVE + flag::XM_STRIDE * 0 + flag::XM_ADD_D0]);
        pb.on_duplex_next(&[flag::F_PUSH1]);
    }
}

/// `verify_core`: τ (pushed into `PT`), sumcheck #1 with the running `eq(τ, r_x)`, the `abc` check, `ra/rb/rc`
/// (pushed into `RS`), `claim2`, sumcheck #2 (r_y pushed into `RS`). Leaves `E3 = claim2` after the last round.
/// Requires `RowParams.pt_port == m_vars − 1`.
pub fn emit_core(pb: &mut ProgramBuilder, shape: &SpartanShape, core: &SpartanCore, cp: &mut SpartanCheckpoints) {
    assert!(shape.m_vars >= 1 && 2 * shape.m_vars <= NPT, "τ ‖ r_x fit PT");
    assert!(shape.n_vars + 3 <= NRS, "ra, rb, rc ‖ r_y fit RS");
    assert!(shape.ood + 1 <= NY);
    assert_eq!(core.outer.len(), shape.m_vars);
    assert_eq!(core.inner.len(), shape.n_vars);
    // the claim starts at ZERO (every constraint holds) and the eq accumulator at ONE
    {
        let r = pb.row();
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_ONE);
        clr(r, 3);
    }
    {
        let r = pb.row();
        r.emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_X);
        r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
    }
    // τ
    for _ in 0..shape.m_vars {
        pb.sample_ext();
        pb.on_next(&[flag::PT_PUSH]);
    }
    // sumcheck #1: four coefficients per round, nine rows
    for c in &core.outer {
        assert_eq!(c.len(), 4);
        pb.new_row();
        pb.observe_ext(c[0]);
        pb.observe_ext(c[1]);
        {
            let r = pb.cur(); // the (c0, c1) duplexing row
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_D0).xmove(0, flag::XM_ADD_DA); // 2·c0
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_DA); // c1
            clr(r, 7);
            r.xmove(7, flag::XM_ADD_D0); // c0
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_DA); // c1
        }
        pb.observe_ext(c[2]);
        pb.observe_ext(c[3]);
        pb.sample_ext(); // r, popped on the (c2, c3) duplexing row
        {
            let r = pb.cur();
            r.xmove(0, flag::XM_ADD_D0).xmove(0, flag::XM_ADD_NEXT); // + c2 + c1
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_DA); // c3
            clr(r, 6);
            r.set(flag::XM2_ADD_PREV + 6); // X6 = c1 (old X5)
            r.mul_a(1, flag::AM_D).mul_b(1, flag::BM_CH); // c3·r
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_MUL).xmove(5, flag::XM_ADD_D0); // acc = c3·r + c2
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_E); // the old claim
        }
        {
            let r = pb.row();
            r.xmove(0, flag::XM_ADD_NEXT); // S = 2c0 + c1 + c2 + c3
            r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0); // acc·r
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_MUL).xmove(5, flag::XM_ADD_NEXT); // + c1
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_NEXT); // X6 = c0 (old X7)
            clr(r, 4);
            r.set(flag::XM2_ADD_PREV + 4); // X4 = the old claim
            r.set(flag::EXT_EQ); // S == claim
        }
        {
            let r = pb.row();
            r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0);
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_MUL).xmove(5, flag::XM_ADD_NEXT); // claim' = acc·r + c0
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_ONE).xmove(4, flag::XM_SUB_E); // 1 − r
        }
        {
            let r = pb.row();
            clr(r, 0);
            r.set(flag::XM2_ADD_X4J).xmove(0, flag::XM_SUB_E); // 1 − 2r
        }
        {
            let r = pb.row();
            r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_PTM); // (1 − 2r)·τ_i
            r.xmove(4, flag::XM_SUB_MUL); // T = (1 − r) − τ_i(1 − 2r)
            r.set(flag::PT_PUSH); // r_i (the mul read τ_i before the push)
        }
        {
            let r = pb.row();
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_X2J); // X6 = T
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_NEXT); // X4 = claim'
        }
        {
            let r = pb.row();
            r.mul_a(2, flag::AM_E).mul_b(2, flag::BM_X4); // eq·T
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL);
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_NEXT); // X3 = claim'
        }
        {
            let r = pb.row();
            r.emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_X);
            r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        }
        cp.outer_claims.push(After { row: pb.cur_row() });
    }
    // abc: claim == eq·(a·b − c)  ⇔  claim + eq·(c − a·b) == 0; then ra, rb, rc and claim2
    let [a, b, c] = core.abc;
    pb.new_row();
    pb.observe_ext(a);
    pb.observe_ext(b);
    {
        let r = pb.cur();
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_D0); // a
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_DA); // b
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_D0); // a
    }
    {
        let r = pb.row();
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_NEXT); // X4 = b
        r.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X); // E1 = a
    }
    pb.new_row(); // the c duplexing must not share the row that writes X4 = b (its product reads X4)
    pb.observe_ext(c);
    pb.sample_ext(); // ra; the c duplexing row
    {
        let r = pb.cur();
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4); // a·b
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_D0).xmove(4, flag::XM_SUB_MUL); // c − a·b
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_D0); // c
    }
    pb.on_next(&[flag::RS_PUSH]); // ra
    {
        let r = pb.row();
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_X2J); // X6 = c − a·b
        r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_E0); // a·ra
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
    }
    {
        let r = pb.row();
        r.mul_a(2, flag::AM_E).mul_b(2, flag::BM_X4); // eq·(c − a·b)
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_MUL);
    }
    {
        let r = pb.row();
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E).set(flag::XM2_ADD_PREV + 3); // Z = claim + eq·(c − a·b)
    }
    {
        let r = pb.row();
        clr(r, 4);
        r.set(flag::XM2_ADD_PREV + 4); // X4 = Z
        clr(r, 0); // X0 = 0
        r.set(flag::EXT_EQ);
    }
    cp.abc_row = Some(After { row: pb.cur_row() });
    pb.sample_ext(); // rb
    pb.on_next(&[flag::RS_PUSH]);
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0); // b·rb
        r.xmove(1, flag::XM_ADD_MUL); // X1 = a·ra + b·rb
    }
    pb.sample_ext(); // rc
    pb.on_next(&[flag::RS_PUSH]);
    {
        let r = pb.row();
        clr(r, 2);
        r.set(flag::XM2_ADD_PREV + 2); // X2 = a·ra + b·rb
    }
    {
        let r = pb.row();
        r.mul_a(3, flag::AM_X4).mul_b(3, flag::BM_E0); // c·rc
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_MUL).set(flag::XM2_ADD_PREV + 3); // claim2
    }
    pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
    cp.claim2_row = Some(After { row: pb.cur_row() });
    // sumcheck #2: three coefficients per round, six rows
    for c in &core.inner {
        assert_eq!(c.len(), 3);
        pb.new_row();
        pb.observe_ext(c[0]);
        pb.observe_ext(c[1]);
        {
            let r = pb.cur();
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_D0).xmove(0, flag::XM_ADD_DA); // 2·c0
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_DA); // c1
            clr(r, 7);
            r.xmove(7, flag::XM_ADD_D0); // c0
        }
        pb.observe_ext(c[2]);
        pb.sample_ext(); // r on the c2 duplexing row
        {
            let r = pb.cur();
            r.xmove(0, flag::XM_ADD_D0).xmove(0, flag::XM_ADD_NEXT); // S = 2c0 + c1 + c2
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_D0); // c2
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_E); // the old claim
        }
        {
            let r = pb.row();
            clr(r, 4);
            r.set(flag::XM2_ADD_PREV + 4); // X4 = the old claim
            r.set(flag::EXT_EQ); // S == claim
            r.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_E0); // c2·r
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL).set(flag::XM2_ADD_PREV + 2); // acc = c2·r + c1
            clr(r, 3);
            r.set(flag::XM2_ADD_X4J + 3); // X3 = c0 (old X7)
            r.set(flag::RS_PUSH); // r_i
        }
        {
            let r = pb.row();
            r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_E0); // acc·r
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL).xmove(2, flag::XM_ADD_NEXT); // claim' = acc·r + c0
        }
        {
            let r = pb.row();
            clr(r, 3);
            r.set(flag::XM2_ADD_PREV + 3); // X3 = claim'
        }
        pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        cp.inner_claims.push(After { row: pb.cur_row() });
    }
}

/// The pcs claim (`Layout::add_claim_at` + α + `combine_evals`): `w_eval` absorbed, α sampled (pushed into `Y`),
/// `claimed = Σ_i α^{1+i}·ans_i + w_eval` by a Horner walk over `F`'s tail (the answers), left in `E3`.
/// `answers_tail_offset`: how many `F` entries sit ABOVE the newest OOD answer (0 when the answers are at the tail;
/// `f_survivors − ood` after the matrix argument parked its last round's coefficients at `F[0..30)`).
pub fn emit_pcs_claim(pb: &mut ProgramBuilder, w_eval: Ea4, ood: usize, answers_tail_offset: usize) -> After {
    pb.new_row(); // a fresh row: the w_eval duplexing must not share the last round's closing row
    pb.observe_ext(w_eval);
    pb.on_duplex(&[flag::XMOVE + flag::XM_STRIDE * 2 + flag::XM_CLR, flag::XMOVE + flag::XM_STRIDE * 2 + flag::XM_ADD_D0]); // X2 = w_eval
    for _ in 0..crate::spartan_ccs::claims_pad(1) {
        pb.observe_ext(<Ea4 as p3_field::PrimeCharacteristicRing>::ZERO); // the claims block is absorbed as whole pairs — one native protocol for both paths
    }
    pb.sample_ext(); // α
    pb.on_next(&[flag::Y_PUSH]);
    pb.new_row();
    pb.cur().set(flag::F_ROT_UP);
    for _ in 0..answers_tail_offset {
        pb.row().set(flag::F_ROT_UP);
    }
    {
        let r = pb.row();
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_F0).set(flag::F_ROT_UP); // ans_{m−1}
    }
    for _ in 1..ood {
        let r = pb.row();
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL).xmove(1, flag::XM_ADD_F0).set(flag::F_ROT_UP);
    }
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL).xmove(1, flag::XM_ADD_NEXT); // + w_eval
    }
    // E3 ← X1: X1 → X0 → X4 → X3
    pb.row().xmove(0, flag::XM_CLR).xmove(0, flag::XM_ADD_NEXT);
    pb.row().xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_X2J);
    pb.row().xmove(3, flag::XM_CLR).xmove(3, flag::XM_ADD_NEXT);
    pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
    After { row: pb.cur_row() }
}

/// The words the statement hash covers and the leaf rows hash — ONE function with the native side
/// (`spartan_ccs::statement_word_list`): the header block, then the public half of `z` padded to `STATEMENT_PUB_WORDS`.
pub fn statement_words(shape: &SpartanShape, io: &[Fa4]) -> Vec<Fa4> {
    crate::spartan_ccs::statement_word_list(shape.m_vars, shape.n_vars, shape.io_len, io)
}

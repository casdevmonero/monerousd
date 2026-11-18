//! THE MATRIX ARGUMENT AS UNIVERSAL-ROW INSTRUCTIONS (spec §Z3-M, M4): the sumcheck `matrix_argument::verify` runs
//! natively, laid onto rows by `ProgramBuilder` — `m_at` (one padded duplexing), then per round fifteen duplexing
//! rows that push their coefficient pair into `F` (`F_PUSH2`) while accumulating `S = 2·c_0 + Σ_k c_k` on lanes 0/1,
//! the challenge popped on the fifteenth, `S == claim` by `EXT_EQ`, the challenge pushed into `RS` (ρ), and the
//! claim folded by a Horner over `F`'s tail (thirty `F_ROT_UP`s, `X4 ← X4·r + F0`) into `E3`.
//!
//! `F` discipline: a round pushes thirty entries and rotates thirty up, so after it the round's coefficients sit at
//! `F[0..30)` and are exactly what the NEXT round's pushes drop; anything older (the pcs OOD answers, ≤ NF − 30 of
//! them) survives at `F[30..)` through every round. `claim2` (the claim the argument's `m_at` must close) is
//! moved to `E1` first.
//!
//! ROOT-LAYER: the schedule is `matrix_argument::verify`'s own order of observes and samples. MEASURED: pin
//! `the_matrix_argument_rows_reproduce_the_native_claims` (whir_program.rs). MUST-STAY-GREEN: the matrix-argument
//! and WHIR-program pins.

use crate::hiding_decider::Fa4;
use crate::matrix_argument::{FixedColumns, MatrixProof};
use crate::universal_row::{flag, RowFlags, NF};
use crate::verifier_program::{After, ProgramBuilder};
use p3_field::PrimeCharacteristicRing;

/// Checkpoints: `E1 = claim2` after `claim2_saved`; `E3` = the argument's claim after round `i` at `round_claims[i]`
/// (the last one is the final claim the summand must equal).
#[derive(Clone, Debug, Default)]
pub struct MatrixRowCheckpoints {
    pub claim2_saved: Option<After>,
    pub m_at_row: Option<After>,
    pub round_claims: Vec<After>,
}

fn clr(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_CLR)
}

/// The number of `F` entries below the argument's coefficients that survive every round.
pub fn f_survivors(f: &FixedColumns) -> usize {
    NF - crate::matrix_argument::padded_round_len(f)
}

/// Preconditions: `E3 = claim2`, the transcript right after sumcheck #2's last challenge, `F`'s tail holding at most
/// `f_survivors` older entries. Postconditions: `E1 = claim2`, `E3` = the argument's final claim, `RS` = ρ (newest
/// first) above `[m_at, claim2]` above what it held (`RS_PUSH`ed here: the z̃ close reads both back after the witness
/// WHIR has overwritten every E), `F[0..30)` = the last round's coefficients, the older entries at `F[30..)`.
pub fn emit_matrix_argument(pb: &mut ProgramBuilder, f: &FixedColumns, proof: &MatrixProof) -> MatrixRowCheckpoints {
    let n_real = f.degree() + 1;
    let n_coeffs = crate::matrix_argument::padded_round_len(f); // the native side absorbs the same zero pad
    assert!(n_coeffs % 2 == 0, "an even coefficient count: pairs ride duplexing rows");
    assert!(n_coeffs < NF, "the round's coefficients fit F with room for the pcs answers");
    assert_eq!(proof.rounds.len(), f.nnz_bits);
    let mut cp = MatrixRowCheckpoints::default();
    // claim2: E3 → X3 → X2 → X1 → E1, and E3 → X7 → X0 → E0 → RS (the z̃ close reads it back after the witness WHIR)
    pb.new_row();
    {
        let r = pb.row();
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E);
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_E);
    }
    {
        let r = pb.row();
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_NEXT);
        clr(r, 0);
        r.set(flag::XM2_ADD_PREV);
    }
    {
        let r = pb.row();
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT);
    }
    pb.row().emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X).emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X);
    cp.claim2_saved = Some(After { row: pb.cur_row() });
    pb.on_next(&[flag::RS_PUSH]); // claim2 (E0), on the m_at duplexing row
    // m_at ‖ four zeros: one duplexing; E3 ← m_at, and m_at → X7 → X0 → E0 → RS
    assert_eq!(pb.pending_len(), 0, "the argument starts on an empty input buffer");
    pb.observe_ext(proof.m_at);
    pb.observe_slice(&[Fa4::ZERO; 4]);
    {
        let r = pb.cur();
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_D0);
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_D0);
    }
    {
        let r = pb.row();
        r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        clr(r, 0);
        r.set(flag::XM2_ADD_PREV);
    }
    pb.row().emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X);
    pb.row().set(flag::RS_PUSH); // m_at
    cp.m_at_row = Some(After { row: pb.cur_row() });
    for c_real in &proof.rounds {
        assert_eq!(c_real.len(), n_real);
        let mut c = c_real.clone();
        c.resize(n_coeffs, Fa4::ZERO.into());
        pb.new_row();
        for (k, pair) in c.chunks(2).enumerate() {
            pb.observe_ext(pair[0]);
            pb.observe_ext(pair[1]);
            let r = pb.cur(); // this pair's duplexing row
            r.set(flag::F_PUSH2);
            if k == 0 {
                clr(r, 0);
                r.xmove(0, flag::XM_ADD_D0).xmove(0, flag::XM_ADD_DA); // 2·c_0
                clr(r, 1);
                r.xmove(1, flag::XM_ADD_DA); // c_1
            } else {
                r.xmove(0, flag::XM_ADD_D0); // + c_{2k}
                r.xmove(1, flag::XM_ADD_DA); // + c_{2k+1}
            }
        }
        pb.sample_ext(); // r, popped on the last duplexing row (aligned)
        {
            let r = pb.row();
            r.xmove(0, flag::XM_ADD_NEXT); // S = X0 + X1
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_E); // the claim
        }
        {
            let r = pb.row();
            clr(r, 4);
            r.set(flag::XM2_ADD_PREV + 4); // X4 = the claim
            r.set(flag::EXT_EQ); // S == claim
            r.set(flag::RS_PUSH); // ρ_i
        }
        // Horner from c_{n−1} (the tail) down to c_0, one rotation up per read: n_coeffs rotations in all
        pb.row().set(flag::F_ROT_UP);
        {
            let r = pb.row();
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_F0).set(flag::F_ROT_UP);
        }
        for step in 1..n_coeffs {
            let r = pb.row();
            r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_E0);
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_MUL).xmove(4, flag::XM_ADD_F0);
            if step + 1 < n_coeffs {
                r.set(flag::F_ROT_UP);
            }
        }
        {
            let r = pb.row();
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_NEXT); // X3 = claim'
        }
        pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        cp.round_claims.push(After { row: pb.cur_row() });
    }
    cp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_air::CarrierParams;
    use crate::hiding_decider::Ea4;
    use crate::spartan_ccs::{committed_pcs_with, fixed_commitment_root, pcs_point, prove_committed_uniform, statement_hash, transcript, verify_core_traced, SpartanCommittedProof};
    use crate::spartan_gadgets::RATE;
    use crate::fixed_program::{emit_observe_claims, emit_pcs_claims, emit_summand_check, Banks, CertShape};
    use crate::spartan_program::{emit_commitments, emit_core, emit_fixed_commitment, emit_initial_ood, emit_statement, statement_words, SpartanCheckpoints, SpartanShape};
    use crate::universal_row::{emulate, first_unsatisfied_step, uniform_instance, E_OFF, IO_LEN, NREG, NSTREAM, RS_OFF};
    use crate::whir_program::WhirShape;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::Mmcs;
    use p3_field::BasedVectorSpace;
    use p3_sumcheck::layout::{Layout, PrefixProver, Verifier as LayoutVerifier};
    use p3_sumcheck::table::TableShape;

    fn reg_ext(regs: &[Fa4], off: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| regs[off + i])
    }

    /// ⭐⭐⭐ M4a: on a REAL uniform committed proof (a 4-step row trace), the prefix + core + MATRIX ARGUMENT + pcs
    /// claim run as rows: `claim2` saved in `E1`, `m_at` in `E3`, every argument round's claim in `E3` equals the
    /// native trace, ρ sits in `RS` above `r_y`, `claimed` after the pcs claim equals native (the OOD answers
    /// survived the argument's `F` traffic), the honest rows satisfy, and a flipped argument coefficient is refused
    /// at that round's `EXT_EQ` row.
    #[test]
    fn the_matrix_argument_rows_reproduce_the_native_claims() {
        let p = crate::universal_row::tests::params();
        let t_bits = 2usize;
        let u = uniform_instance(&p, IO_LEN, t_bits);
        // the inner proof: a real trace (as the M3 pin)
        let mut pbt = ProgramBuilder::new();
        pbt.observe_slice(&(0..8).map(|i| Fa4::from_u64(300 + i)).collect::<Vec<_>>());
        pbt.sample_ext();
        pbt.on_next(&[flag::PT_PUSH]);
        let (mut program_t, mut stream_t) = pbt.finish();
        while program_t.len() < 1 << t_bits {
            program_t.push(RowFlags::default());
            stream_t.push([Fa4::ZERO; NSTREAM]);
        }
        let io_t = vec![Fa4::ZERO; IO_LEN];
        let trace_t = emulate(&p, &io_t, [Fa4::ZERO; NREG], &program_t, &stream_t);
        let params = CarrierParams::legacy(1, 0);
        let f = FixedColumns::of(&u);
        let froot = fixed_commitment_root(&f, params);
        let bytes = prove_committed_uniform(&u, &io_t, &trace_t.w, params, params).expect("proves");
        let pr: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let mp = pr.matrix.as_ref().expect("a matrix argument");
        let fopen = pr.fixed_open.as_ref().expect("a fixed opening");
        let r1cs = u.materialize();
        let sshape = SpartanShape { m_vars: r1cs.m_vars, n_vars: r1cs.n_vars, w_vars: r1cs.w_vars(), io_len: io_t.len(), ood: pr.open.initial_ood_answers.len() };
        // the native trace, in the verifier's own order
        let mut ch = transcript(&r1cs, &io_t);
        ch.observe(pr.commitment.clone());
        for m in &pr.open.hvzk_mask_commits {
            ch.observe(m.clone());
        }
        ch.observe(froot.clone());
        for m in &fopen.hvzk_mask_commits {
            ch.observe(m.clone());
        }
        // the OOD claims, the fixed commitment's first (the native order since M4b)
        let mut flv = LayoutVerifier::<Fa4, Ea4>::new(&[TableShape::new(f.nnz_bits, f.n_cols())], PrefixProver::<Fa4, Ea4>::strategy());
        for &e in &fopen.initial_ood_answers {
            flv.add_virtual_eval(e, &mut ch);
        }
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&[TableShape::new(r1cs.w_vars(), 1)], PrefixProver::<Fa4, Ea4>::strategy());
        for &e in &pr.open.initial_ood_answers {
            lv.add_virtual_eval(e, &mut ch);
        }
        let (r_y, trace, rho) = verify_core_traced(&mut ch, &r1cs, &io_t, &pr.core, Some((&f, mp))).expect("the core + argument verify");
        let rho = rho.expect("ρ");
        let pt = pcs_point(&r_y[..r1cs.w_vars()]);
        lv.add_claim_at(0, &[0], &[pr.core.w_eval], &pt, &mut ch);
        let cols: Vec<usize> = (0..f.n_cols()).collect();
        flv.add_claim_at(0, &cols, &mp.openings, &pcs_point(&rho), &mut ch);
        crate::spartan_ccs::absorb_claims_pad(&mut ch, 1 + f.n_cols());
        let alpha: Ea4 = ch.sample_algebra_element();
        let pcs_constraint = lv.constraint(alpha);
        let mut claimed = Ea4::ZERO;
        pcs_constraint.combine_evals(&mut claimed);
        // the program
        let sh = statement_hash(&r1cs, &io_t);
        let words = statement_words(&sshape, &io_t);
        let mut pb = ProgramBuilder::new();
        emit_statement(&mut pb, &sh, &words);
        let masks: Vec<[Fa4; RATE]> = pr.open.hvzk_mask_commits.iter().map(|c| c.roots()[0]).collect();
        emit_commitments(&mut pb, &pr.commitment.roots()[0], &masks);
        let fmasks: Vec<[Fa4; RATE]> = fopen.hvzk_mask_commits.iter().map(|c| c.roots()[0]).collect();
        emit_fixed_commitment(&mut pb, &froot.roots()[0], &fmasks);
        emit_initial_ood(&mut pb, &fopen.initial_ood_answers);
        emit_initial_ood(&mut pb, &pr.open.initial_ood_answers);
        let mut scp = SpartanCheckpoints::default();
        emit_core(&mut pb, &sshape, &pr.core, &mut scp);
        let mcp = emit_matrix_argument(&mut pb, &f, mp);
        // after the argument the OOD answers are back at F's tail (each round's rotations undo its pushes' shift); the
        // observe pushes w_eval and the openings above them, the summand check reads the openings, the pcs claims read
        // the answers back by their known depth
        let cert = CertShape { n_vars: r1cs.n_vars, m_vars: r1cs.m_vars, ood_w: sshape.ood, ood_f: fopen.initial_ood_answers.len(), nnz_bits: f.nnz_bits };
        let mut banks = Banks::default();
        emit_observe_claims(&mut pb, pr.core.w_eval, &mp.openings);
        emit_summand_check(&mut pb, &f, &cert, &mut banks);
        let prows = emit_pcs_claims(&mut pb, &cert, f.n_cols(), &mut banks);
        let claimed_row = After { row: prows.claimed_w_row };
        let (program, stream) = pb.finish();
        let cfg = committed_pcs_with(&r1cs, params).config;
        let params_row = WhirShape::of(&cfg).row_params(&cfg, r1cs.m_vars - 1);
        let mut io_row = vec![Fa4::ZERO; IO_LEN];
        io_row[crate::universal_row::io_block(1)].copy_from_slice(&sh);
        io_row[crate::universal_row::io_block(2)].copy_from_slice(&froot.roots()[0]);
        let regs0 = [Fa4::ZERO; NREG];
        let tr = emulate(&params_row, &io_row, regs0, &program, &stream);
        let e = |row: usize, lane: usize| reg_ext(&tr.regs_after(row), E_OFF + 4 * lane);
        eprintln!(
            "[matrix-rows] {} rows: core {}..={}, argument {}..={} ({} rounds), claimed {}",
            program.len(),
            scp.outer_claims[0].row,
            scp.inner_claims.last().unwrap().row,
            mcp.claim2_saved.unwrap().row,
            mcp.round_claims.last().unwrap().row,
            mcp.round_claims.len(),
            claimed_row.row
        );
        // the claim the argument's m_at must close is sumcheck #2's FINAL folded claim (the last inner claim), not
        // the initial ra·a + rb·b + rc·c
        assert_eq!(e(mcp.claim2_saved.unwrap().row, 1), *trace.inner_claims.last().unwrap(), "E1 = the final claim2");
        assert_eq!(e(mcp.m_at_row.unwrap().row, 3), mp.m_at, "E3 = m_at");
        assert_eq!(mcp.round_claims.len(), trace.matrix_claims.len());
        for (i, at) in mcp.round_claims.iter().enumerate() {
            assert_eq!(e(at.row, 3), trace.matrix_claims[i], "argument round {i}: the claim in E3");
        }
        {
            let regs = tr.regs_after(mcp.round_claims.last().unwrap().row);
            for k in 0..rho.len() {
                assert_eq!(reg_ext(&regs, RS_OFF + 4 * k), rho[rho.len() - 1 - k], "RS[{k}] = ρ newest-first");
            }
            // below ρ: m_at, claim2 (the stashes the z̃ close reads back), then r_y
            assert_eq!(reg_ext(&regs, RS_OFF + 4 * rho.len()), mp.m_at, "RS[16] = m_at");
            assert_eq!(reg_ext(&regs, RS_OFF + 4 * (rho.len() + 1)), *trace.inner_claims.last().unwrap(), "RS[17] = claim2");
            for j in 0..r_y.len() {
                assert_eq!(reg_ext(&regs, RS_OFF + 4 * (rho.len() + 2 + j)), r_y[r_y.len() - 1 - j], "r_y below the stashes");
            }
        }
        assert_eq!(e(claimed_row.row, 3), claimed, "claimed after the pcs claim: the OOD answers survived the argument's F traffic");
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs0, &program, &stream), None, "the honest rows satisfy");
        // a flipped argument coefficient (round 3's first pair row) is refused at that round's EXT_EQ row
        let r3_first = mcp.round_claims[2].row + 1;
        assert!(program[r3_first].is_set(flag::M_ABSORB) && program[r3_first].is_set(flag::F_PUSH2), "round 3's first pair row");
        let mut bad = stream.clone();
        bad[r3_first][0] += Fa4::ONE;
        let at = first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad).expect("a flipped coefficient must be refused");
        assert!(program[at].is_set(flag::EXT_EQ) && at > r3_first && at < mcp.round_claims[3].row, "refused at round 3's EXT_EQ row (row {at})");
        eprintln!("[matrix-rows] GREEN: {} argument rounds reproduce the native claims in {} rows; a flipped coefficient is refused at row {at}", mcp.round_claims.len(), mcp.round_claims.last().unwrap().row - mcp.claim2_saved.unwrap().row);
    }
}

//! THE UNIFORM CERTIFICATE'S POST-ARGUMENT ROWS (spec §Z3-M, M4b/M4c): everything the native uniform verifier
//! (`spartan_ccs::verify_committed_uniform`) does after the matrix argument, as universal-row instructions — the 34
//! observed claims (`w_eval`, the 33 column openings) pushed into `F` as they are absorbed, the closed form's
//! SUMMAND at the openings checked against the argument's final claim (`EXT_EQ`), both batching challenges and the
//! two folded pcs claims (`claimed_w → E3`, `claimed_f → RS`), the `claim2 == m_at·z̃(r_y)` close with the public
//! half re-hashed against the statement hash (after the witness WHIR, which frees `R`), and the fixed WHIR's prelude
//! (the release root recaptured under `IOCHK_2`, `claimed_f` and `α_f` read back from `RS`).
//!
//! Bank discipline. `RS` (head first) after the argument is `[ρ (16), m_at, claim2, r_y (n_vars, newest first), rc,
//! rb, ra]`; the observe pushes `w_eval`, the pcs claims push `α_f` then `claimed_f` ([`RsIdx`]). Every walk rotates
//! a bank and RESTORES it; the counters in [`Banks`] track the ORIGINAL index at each head so no rotation count is
//! hand-derived. `Y` holds the summand's three scratch values (`1`, `e_col_hi`, `P`) only until the endgame rotates
//! them to its tail, before α_w is pushed. `F` after the observe: `[older (NF−34), w_eval, open_0 … open_32]`, the
//! OOD answers sitting just below `w_eval` (the fixed commitment's below the witness's).
//!
//! The summand (`matrix_argument::summand`) as rows: `v = ra·o_va + rb·o_vb + rc·o_vc`; the row and column bit terms
//! `1 − r − bit + 2·bit·r` (`bit` an opening at `F[0]`, `r` a challenge at `PT[0]` or `E0`) each cost THREE rows
//! (`term_row`, `add_row`, `acc_row`); the transition scalars `e, sh, l_row, l_row·l_col, p_hi` walk `r_hi` (`PT`) and
//! `s_hi` (`RS`) together, seven rows per coordinate, `sh` by the running recurrence
//! `sh ← sh·eq_k + A·(1 − a_k)·b_k`, `A ← A·a_k·(1 − b_k)` (`uniform_r1cs::shift_closed_form`); the endgame
//! assembles `P·[e_col_hi·top·(loc·(e − t·l_row·l_col) + nxt·sh) + pub·p_hi·(1 − t·l_row)]` and `EXT_EQ`s it against
//! `E3`.
//!
//! ROOT-LAYER: the schedule is the native verifier's own order of observes and samples (`spartan_ccs.rs`, 2026-09-28:
//! `w_eval`, the openings, `α_w`, `α_f`, the witness WHIR, the fixed WHIR); every value is read from the stream at
//! the row that absorbs it, every challenge from the bank that holds it. MEASURED: pin
//! `the_uniform_certificate_rows_check_the_summand_and_close_z` (below). MUST-STAY-GREEN: the matrix-rows,
//! WHIR-program and closing-identity pins.

use crate::hiding_decider::{Ea4, Fa4};
use crate::matrix_argument::{FixedColumns, PUB_COL_BITS};
use crate::spartan_gadgets::RATE;
use crate::universal_row::{flag, RowFlags, NF, NPT, NRS};
use crate::verifier_program::{After, ProgramBuilder};

/// The certificate's inner shape the emitters need.
#[derive(Clone, Debug)]
pub struct CertShape {
    pub n_vars: usize,
    pub m_vars: usize,
    /// The witness and fixed commitments' OOD sample counts.
    pub ood_w: usize,
    pub ood_f: usize,
    /// The matrix argument's variables (ρ's length).
    pub nnz_bits: usize,
}

/// The original index at each bank head (`RS_ROT`/`F_ROT`/`PT_ROT` bring index `head + 1` to the head, the `_UP`
/// rotations bring `head − 1`). A walk that ends with every counter back at its start has restored the bank.
#[derive(Clone, Debug, Default)]
pub struct Banks {
    pub fpos: usize,
    pub rs_head: usize,
    pub pt_head: usize,
}

/// Original `RS` indices for `head` entries pushed above ρ (1 after the observe: `w_eval`; 3 after the pcs claims:
/// `claimed_f, α_f, w_eval`).
#[derive(Clone, Copy, Debug)]
pub struct RsIdx {
    pub head: usize,
    pub nnz: usize,
    pub n_vars: usize,
}

impl RsIdx {
    pub fn w_eval(&self) -> usize {
        assert!(self.head >= 1);
        self.head - 1
    }
    pub fn m_at(&self) -> usize {
        self.head + self.nnz
    }
    pub fn claim2(&self) -> usize {
        self.head + self.nnz + 1
    }
    pub fn ry(&self, j: usize) -> usize {
        assert!(j < self.n_vars);
        self.ra(); // the deepest index (ra) fits the bank, or the emission refuses
        self.head + self.nnz + 2 + (self.n_vars - 1 - j)
    }
    pub fn rc(&self) -> usize {
        self.head + self.nnz + 2 + self.n_vars
    }
    pub fn rb(&self) -> usize {
        self.rc() + 1
    }
    pub fn ra(&self) -> usize {
        let i = self.rc() + 2;
        assert!(i < NRS, "the RS bank holds {NRS} entries; this shape needs {}", i + 1);
        i
    }
    /// Entries above `r_y`'s newest coordinate — `InitialShape::rs_depth` for the witness closing identity.
    pub fn depth_above_ry(&self) -> usize {
        self.head + self.nnz + 2
    }
}

fn clr(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_CLR)
}
fn f_rot(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::F_ROT);
    b.fpos = (b.fpos + 1) % NF;
}
fn f_rot_up(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::F_ROT_UP);
    b.fpos = (b.fpos + NF - 1) % NF;
}
fn rs_up(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::RS_ROT_UP);
    b.rs_head = (b.rs_head + NRS - 1) % NRS;
}
fn rs_down(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::RS_ROT);
    b.rs_head = (b.rs_head + 1) % NRS;
}
fn pt_up(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::PT_ROT_UP);
    b.pt_head = (b.pt_head + NPT - 1) % NPT;
}
fn pt_down(r: &mut RowFlags, b: &mut Banks) {
    r.set(flag::PT_ROT);
    b.pt_head = (b.pt_head + 1) % NPT;
}
/// Standalone rows rotating `RS` until original index `target` heads it, the shorter way round.
fn rs_to(pb: &mut ProgramBuilder, b: &mut Banks, target: usize) {
    let downs = (target + NRS - b.rs_head) % NRS;
    let ups = (NRS - downs) % NRS;
    if downs == 0 {
        return;
    }
    if downs <= ups {
        for _ in 0..downs {
            rs_down(pb.row(), b);
        }
    } else {
        for _ in 0..ups {
            rs_up(pb.row(), b);
        }
    }
    assert_eq!(b.rs_head, target);
}
/// Standalone rows rotating `F` down until original index `target` heads it.
fn f_to(pb: &mut ProgramBuilder, b: &mut Banks, target: usize) {
    let downs = (target + NF - b.fpos) % NF;
    let ups = (NF - downs) % NF;
    if downs <= ups {
        for _ in 0..downs {
            f_rot(pb.row(), b);
        }
    } else {
        for _ in 0..ups {
            f_rot_up(pb.row(), b);
        }
    }
    assert_eq!(b.fpos, target);
}

/// The claims block's `F` footprint: `w_eval`, the `n_cols` openings, and the pad zero when their count is odd —
/// ONE function with the native `claims_pad`, so every `F` index below moves with the pad.
pub fn claims_block_len(n_cols: usize) -> usize {
    1 + n_cols + crate::spartan_ccs::claims_pad(1 + n_cols)
}
/// The original `F` index of column opening `c` after the observe (`w_eval` sits one below `open_0`; the pad zero,
/// when the block is odd, sits above `open_{n−1}` at `NF − 1`).
pub fn f_open(n_cols: usize, c: usize) -> usize {
    assert!(c < n_cols);
    NF - claims_block_len(n_cols) + 1 + c
}
pub fn f_w_eval(n_cols: usize) -> usize {
    NF - claims_block_len(n_cols)
}

/// `w_eval` and the column openings: `claims_block_len / 2` duplexing rows pushing each pair into `F` (`F_PUSH2`),
/// `w_eval` also read into `X0` on its row and pushed onto `RS` (the z̃ close reads it after the witness WHIR has
/// overwritten every E). An odd block ends with the native side's pad zero (`spartan_ccs::claims_pad`), absorbed
/// and pushed like any claim. Precondition: an empty input buffer (the argument's last challenge consumed it).
/// Postcondition: `F = [older, w_eval, open_0 … open_{n−1}, (0)]`, `RS = [w_eval, ρ, …]`, `banks` unchanged.
pub fn emit_observe_claims(pb: &mut ProgramBuilder, w_eval: Ea4, openings: &[Ea4]) -> After {
    assert_eq!(pb.pending_len(), 0, "the observe starts on an empty input buffer");
    let n_cols = openings.len();
    assert!(claims_block_len(n_cols) <= NF, "the claims fit F");
    pb.new_row();
    let pad = core::iter::repeat(<Ea4 as p3_field::PrimeCharacteristicRing>::ZERO).take(crate::spartan_ccs::claims_pad(1 + n_cols));
    let items: Vec<Ea4> = core::iter::once(w_eval).chain(openings.iter().copied()).chain(pad).collect();
    assert!(items.len() % 2 == 0, "w_eval, the openings and the pad ride duplexing rows in pairs");
    for (k, pair) in items.chunks(2).enumerate() {
        pb.observe_ext(pair[0]);
        pb.observe_ext(pair[1]);
        let r = pb.cur();
        r.set(flag::F_PUSH2);
        if k == 0 {
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_D0); // X0 = w_eval
        }
    }
    pb.row().emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X);
    pb.row().set(flag::RS_PUSH);
    After { row: pb.cur_row() }
}

/// Rows after which the pin reads the summand's intermediates (`X0 = v`; `X0 = v·e_row`; `X0 = v·e_row·e_col_lo,
/// X2 = e_col_hi, X3 = Π_{5≤b<v_bits}(1 − r_y[b])`; `X0 = e, X1 = sh, X2 = l_row, X3 = l_row·l_col, E1 = p_hi/(1 −
/// top), E0 = top`), and the `EXT_EQ` row.
#[derive(Clone, Debug, Default)]
pub struct SummandRows {
    pub v_row: usize,
    pub e_row_row: usize,
    pub e_col_row: usize,
    pub d_row: usize,
    pub check_row: usize,
}

/// `X4 ← 1 − r + bit·r`, `X5 ← bit·r − bit` (their sum is the bit term) with `bit = X4 = X5 = E1` and `r = PT[0]`
/// (`from_pt`) or `E0`; with `p_hi`, `X3 ← X3·(1 − E0)` too.
fn term_row(r: &mut RowFlags, from_pt: bool, p_hi: bool) {
    if from_pt {
        r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_PT0);
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_PT0);
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_ONE).xmove(4, flag::XM_SUB_PT0).xmove(4, flag::XM_ADD_MUL);
    } else {
        r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_E0);
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0);
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_ONE).xmove(4, flag::XM_SUB_E).xmove(4, flag::XM_ADD_MUL);
        if p_hi {
            r.mul_a(3, flag::AM_X).mul_b(3, flag::BM_E0);
            r.xmove(3, flag::XM_SUB_MUL);
        }
    }
    clr(r, 5);
    r.xmove(5, flag::XM_ADD_MUL).xmove(5, flag::XM_SUB_E); // mul[1] − E1
}
/// `X4 ← X4 + X5`, `X6 ← X4 + X5` (the term, twice), and the next bit into `X5` from `F[0]`.
fn add_row(r: &mut RowFlags, load: bool) {
    r.xmove(4, flag::XM_ADD_NEXT);
    clr(r, 6);
    r.xmove(6, flag::XM_ADD_X2J).set(flag::XM2_ADD_PREV + 6);
    if load {
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_F0);
    }
}
/// `X_into ← X_into · term` (`into` 0: `X0·X4`; 2: `X2·X6`); the next bit into `X4` from `F[0]` and `E1 ← X5`.
fn acc_row(r: &mut RowFlags, into: usize, load: bool) {
    match into {
        0 => {
            r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4);
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_MUL);
        }
        2 => {
            r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4);
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL);
        }
        _ => unreachable!("the accumulators are X0 and X2"),
    }
    if load {
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_F0);
        r.emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1);
    }
}

/// The summand check. Preconditions: right after [`emit_observe_claims`] (`banks` all zero: no bank rotated since
/// the core), `E3` = the argument's final claim, `PT = [r_x (newest first), τ…]`. Postconditions: `EXT_EQ` on
/// `S == E3`; `PT`, `RS`, `F` restored to their entry rotation (`F[0]` = the entry it held; the openings still in `F`
/// for the pcs claims); `Y = [y_w…, y_f…, junk…, 1, e_col_hi, P]` (three scratch entries at the tail).
pub fn emit_summand_check(pb: &mut ProgramBuilder, f: &FixedColumns, sh: &CertShape, banks: &mut Banks) -> SummandRows {
    let n_cols = f.n_cols();
    assert_eq!(sh.n_vars, 1 + f.t_bits + f.v_bits, "n_vars = 1 + t_bits + v_bits");
    assert_eq!(sh.m_vars, f.r_bits + f.t_bits, "m_vars = r_bits + t_bits");
    assert_eq!(sh.nnz_bits, f.nnz_bits);
    assert!(f.v_bits > PUB_COL_BITS && f.r_bits >= 1 && f.t_bits >= 1);
    assert_eq!((banks.fpos, banks.rs_head, banks.pt_head), (0, 0, 0), "the summand starts on unrotated banks");
    let rs = RsIdx { head: 1, nnz: f.nnz_bits, n_vars: sh.n_vars };
    let mut rows = SummandRows::default();

    // ── A. v = ra·o_va + rb·o_vb + rc·o_vc; F to open_0, RS to ra, PT down m_vars − 1 (PT[0] = r_x[0]) ──────────
    {
        let f_steps = (f_open(n_cols, 0) + NF - banks.fpos) % NF;
        let rs_ups = (banks.rs_head + NRS - rs.ra()) % NRS;
        let pt_downs = sh.m_vars - 1;
        let n = f_steps.max(rs_ups).max(pt_downs);
        for i in 0..n {
            let r = pb.row();
            if i < f_steps {
                f_rot(r, banks);
            }
            if i < rs_ups {
                rs_up(r, banks);
            }
            if i < pt_downs {
                pt_down(r, banks);
            }
            if i == 0 {
                clr(r, 2);
                r.xmove(2, flag::XM_ADD_ONE); // e_col_hi = 1
                clr(r, 3);
                r.xmove(3, flag::XM_ADD_ONE); // p_hi = 1
            }
        }
    }
    for lane in [1usize, 6, 7] {
        let r = pb.row();
        clr(r, lane);
        r.xmove(lane, flag::XM_ADD_F0);
        f_rot(r, banks);
    }
    assert_eq!(banks.fpos, f_open(n_cols, f.row_bit(0)));
    {
        let r = pb.row();
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // ra
        rs_up(r, banks);
    }
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0); // o_va·ra
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // rb
        rs_up(r, banks);
    }
    {
        let r = pb.row();
        r.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_E0); // o_vb·rb
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_MUL);
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // rc
        rs_up(r, banks);
    }
    {
        let r = pb.row();
        r.mul_a(3, flag::AM_X4).mul_b(3, flag::BM_E0); // o_vc·rc
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_MUL);
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // r_y[0]
        rs_up(r, banks);
    }
    {
        let r = pb.row();
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_NEXT).set(flag::XM2_ADD_PREV); // X1 + X7
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_X2J); // X7 = X6
    }
    pb.row().set(flag::XM2_ADD_PREV); // X0 += X7
    rows.v_row = pb.cur_row();
    assert_eq!(banks.rs_head, rs.ry(1));

    // ── B. e_row: the PT walk over r_x[0..r_bits) against the row-bit openings ─────────────────────────────────
    {
        let r = pb.row();
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_F0);
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_F0);
        f_rot(r, banks);
    }
    pb.row().emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1);
    for _ in 0..f.r_bits {
        term_row(pb.row(), true, false);
        add_row(pb.row(), true);
        {
            let r = pb.row();
            acc_row(r, 0, true);
            f_rot(r, banks);
            pt_up(r, banks);
        }
    }
    rows.e_row_row = pb.cur_row();
    assert_eq!(banks.fpos, f_open(n_cols, f.col_bit(1)));

    // ── C. e_col: the RS walk over r_y[0..v_bits) against the column-bit openings; p_hi from bit 5 ─────────────
    for b in 0..f.v_bits {
        let last = b + 1 == f.v_bits;
        term_row(pb.row(), false, b >= PUB_COL_BITS);
        add_row(pb.row(), !last);
        {
            let r = pb.row();
            acc_row(r, if b < PUB_COL_BITS { 0 } else { 2 }, !last);
            if !last {
                f_rot(r, banks);
                r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0);
                rs_up(r, banks);
            }
        }
    }
    rows.e_col_row = pb.cur_row();
    assert_eq!(banks.fpos, f_open(n_cols, f.loc()));
    assert_eq!(banks.rs_head, rs.ry(f.v_bits));

    // ── the stash (P, e_col_hi, 1 → Y) and the joint walk's registers ─────────────────────────────────────────
    {
        let r = pb.row();
        clr(r, 4);
        r.set(flag::XM2_ADD_X4J + 4); // X4 = X0 = P
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_X2J); // X5 = X2 = e_col_hi
        clr(r, 7);
        r.set(flag::XM2_ADD_X4J + 7); // X7 = X3 = p_hi
    }
    {
        let r = pb.row();
        r.emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = P
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_NEXT); // X4 = e_col_hi
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_NEXT); // X6 = p_hi
    }
    {
        let r = pb.row();
        r.set(flag::Y_PUSH); // P
        r.emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = e_col_hi
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_ONE);
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_NEXT); // X5 = p_hi
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_ONE);
    }
    {
        let r = pb.row();
        r.set(flag::Y_PUSH); // e_col_hi
        r.emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = 1
        r.emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1); // E1 = p_hi
        r.emove(2, flag::EM_CLR).set(flag::EM2_FROM_X4 + 2); // E2 = A = 1
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_ONE); // e = 1
        clr(r, 1); // sh = 0
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_ONE); // l_row = 1
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_ONE); // l_row·l_col = 1
    }
    {
        let r = pb.row();
        r.set(flag::Y_PUSH); // 1
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // s_hi[0]
        rs_up(r, banks);
    }

    // ── D. the joint walk over (r_hi[k] = PT[0], s_hi[k] = E0), seven rows per coordinate ─────────────────────
    for _ in 0..f.t_bits {
        {
            let r = pb.row(); // T1
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_PT0); // a
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_ONE).xmove(6, flag::XM_SUB_PT0); // 1 − a
            r.mul_a(3, flag::AM_PT0).mul_b(3, flag::BM_E0); // a·b
            clr(r, 7);
            r.xmove(7, flag::XM_ADD_MUL);
            r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_E0); // p_hi·b
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_E).xmove(5, flag::XM_SUB_MUL); // p_hi − p_hi·b
            r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_PT0); // l_row·a
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL);
        }
        {
            let r = pb.row(); // T2
            r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_E0); // a·b
            r.xmove(4, flag::XM_SUB_MUL); // w = a − a·b
            r.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_E0); // (1 − a)·b
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_MUL); // u
            r.mul_a(3, flag::AM_X).mul_b(3, flag::BM_X4); // (l_row·l_col)·(a·b)
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_MUL);
            r.emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1); // p_hi
        }
        {
            let r = pb.row(); // T3
            clr(r, 5);
            r.set(flag::XM2_ADD_PREV + 5).xmove(5, flag::XM_ADD_NEXT); // u + w
            r.mul_a(2, flag::AM_E).mul_b(2, flag::BM_X4); // A·u
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_MUL);
        }
        {
            let r = pb.row(); // T4
            r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_Y0); // (u + w)·1
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_ONE).xmove(5, flag::XM_SUB_MUL); // eq = 1 − u − w
        }
        {
            let r = pb.row(); // T5
            r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4); // sh·eq
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_MUL);
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_NEXT); // X4 = eq
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_NEXT); // X5 = A·u
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_X2J); // X6 = w
        }
        {
            let r = pb.row(); // T6
            r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4); // e·eq
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_MUL);
            r.set(flag::XM2_ADD_X4J + 1); // sh += A·u
            r.mul_a(2, flag::AM_E).mul_b(2, flag::BM_X4); // A·w
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_MUL);
        }
        {
            let r = pb.row(); // T7
            r.emove(2, flag::EM_CLR).set(flag::EM2_FROM_X4 + 2); // A
            r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // the next s_hi (top after the last)
            rs_up(r, banks);
            pt_up(r, banks);
        }
    }
    rows.d_row = pb.cur_row();
    assert_eq!(banks.pt_head, NPT - 1, "the PT walk covered r_x and one more");

    // ── E. the endgame: p_hi·(1 − top), the four kind/transition openings, inner, S, EXT_EQ ────────────────────
    assert_eq!(banks.fpos, f_open(n_cols, f.loc()));
    {
        let r = pb.row(); // G1
        r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_E0); // p_hi·top
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_E).xmove(5, flag::XM_SUB_MUL);
        f_rot(r, banks); // → nxt
        pt_down(r, banks); // PT restored
    }
    {
        let r = pb.row(); // G2
        r.emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1); // p_hi final
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_F0); // nxt
        f_rot(r, banks); // → pub
    }
    {
        let r = pb.row(); // G3
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_F0); // pub
        f_rot(r, banks); // → t
    }
    {
        let r = pb.row(); // G4
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_F0); // t
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_F0); // t
        f_rot_up(r, banks); // → pub
    }
    {
        let r = pb.row(); // G5
        r.mul_a(3, flag::AM_X).mul_b(3, flag::BM_X4); // (l_row·l_col)·t
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_MUL);
        r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4); // l_row·t
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_MUL);
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4); // sh·nxt
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
        f_rot_up(r, banks); // → nxt
    }
    {
        let r = pb.row(); // G6
        r.mul_a(3, flag::AM_X4).mul_b(3, flag::BM_Y0); // (t·l_row·l_col)·1
        clr(r, 7);
        r.xmove(7, flag::XM_SUB_MUL); // −t·l_row·l_col
        r.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_Y0); // (t·l_row)·1
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_ONE).xmove(6, flag::XM_SUB_MUL); // f_p = 1 − t·l_row
        clr(r, 5);
        r.set(flag::XM2_ADD_PREV + 5); // X5 = pub
        f_rot_up(r, banks); // → loc
    }
    {
        let r = pb.row(); // G7
        r.set(flag::XM2_ADD_PREV); // f_l = e − t·l_row·l_col
        r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_X4); // p_hi·pub
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_MUL);
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_F0); // loc
    }
    {
        let r = pb.row(); // G8
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4); // f_l·loc
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
        clr(r, 2);
        r.set(flag::XM2_ADD_X4J + 2); // X2 = f_p
        clr(r, 6);
        r.set(flag::XM2_ADD_PREV + 6); // X6 = p_hi·pub
    }
    {
        let r = pb.row(); // G9
        r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4); // f_p·p_hi·pub
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_MUL);
        r.xmove(0, flag::XM_ADD_NEXT); // loc·f_l + nxt·sh
        r.set(flag::Y_ROT); // Y[0] = e_col_hi
    }
    {
        let r = pb.row(); // G10
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_E0); // ·top
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT); // X1 = the pub term
    }
    {
        let r = pb.row(); // G11
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_Y0); // ·e_col_hi
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
        r.set(flag::Y_ROT); // Y[0] = P
    }
    pb.row().xmove(0, flag::XM_ADD_NEXT); // G12: inner
    {
        let r = pb.row(); // G13
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_Y0); // S = P·inner
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
        r.set(flag::Y_ROT); // the scratch entries are now Y's tail
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E); // X3 = E3 = the argument's final claim
    }
    {
        let r = pb.row(); // G14
        clr(r, 4);
        r.set(flag::XM2_ADD_PREV + 4); // X4 = X3
        r.set(flag::EXT_EQ); // S == claim
    }
    rows.check_row = pb.cur_row();
    // RS back to its entry rotation (the pcs claims and the closing identity index it from there)
    rs_to(pb, banks, 0);
    assert_eq!(banks.pt_head, 0);
    rows
}

/// Rows after which: `E0 = α_w` (Y-pushed on the next), `E3 = claimed_w`, `E0 = α_f` (RS-pushed on the next),
/// `RS[0] = claimed_f`.
#[derive(Clone, Debug, Default)]
pub struct PcsClaimRows {
    pub alpha_w_row: usize,
    pub claimed_w_row: usize,
    pub alpha_f_row: usize,
    pub claimed_f_row: usize,
}

/// One running-power accumulation step: `X0 += X4·F[0]`, `X4 ← X5`, `X5 ← X5·α` (`α` at `E0`, or at `E1` with
/// `alpha_in_e1`), `F` rotated down.
fn power_step(r: &mut RowFlags, alpha_in_e1: bool, banks: &mut Banks) {
    r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_F0);
    r.xmove(0, flag::XM_ADD_MUL);
    clr(r, 4);
    r.xmove(4, flag::XM_ADD_NEXT);
    r.mul_a(1, flag::AM_X4).mul_b(1, if alpha_in_e1 { flag::BM_E } else { flag::BM_E0 });
    clr(r, 5);
    r.xmove(5, flag::XM_ADD_MUL);
    f_rot(r, banks);
}

/// α_w, `claimed_w = Σ_i ans_w_i·α_w^{1+i} + w_eval` into `E3`; α_f (pushed onto `RS`), `claimed_f = Σ_c
/// open_c·α_f^c + Σ_i ans_f_i·α_f^{n_cols+i}` pushed onto `RS` — the weights `LayoutVerifier::constraint` assigns
/// (concrete claims first in column order, virtual claims after). Reads `F` by running powers from the LOW weight
/// up (`F` rotates DOWN through `ans_w, ans_f, w_eval, open_0 …` in original order), the `ans_f` parked in
/// `X6, X7, X1` until `α_f^{n_cols}` exists. Postcondition: `Y = [α_w, y_w…, y_f…, …]`, `RS = [claimed_f, α_f,
/// w_eval, ρ, …]`, `F` rotated (not needed again: the WHIR runs overwrite it).
pub fn emit_pcs_claims(pb: &mut ProgramBuilder, sh: &CertShape, n_cols: usize, banks: &mut Banks) -> PcsClaimRows {
    assert!(sh.ood_f <= 3, "up to three fixed OOD answers park in X6, X7, X1");
    assert!(sh.ood_w + sh.ood_f + claims_block_len(n_cols) <= NF, "the OOD answers survive the observe's pushes");
    assert_eq!(banks.rs_head, 0, "RS at its entry rotation (the pushes index from it)");
    let ans_w0 = f_w_eval(n_cols) - sh.ood_w;
    let ans_f0 = ans_w0 - sh.ood_f;
    let mut rows = PcsClaimRows::default();
    // α_w; F walks DOWN through [ans_f…, ans_w…, w_eval, open_0…] (the fixed OOD answers, pushed first, sit
    // lowest): park the fixed answers, fold the witness answers by rising powers, add w_eval
    rows.alpha_w_row = pb.sample_ext().row;
    pb.on_next(&[flag::Y_PUSH]);
    f_to(pb, banks, ans_f0);
    let park = [6usize, 7, 1];
    for i in 0..sh.ood_f {
        let r = pb.row();
        clr(r, park[i]);
        r.xmove(park[i], flag::XM_ADD_F0);
        f_rot(r, banks);
    }
    assert_eq!(banks.fpos, ans_w0, "F[0] = the first witness OOD answer");
    {
        let r = pb.row();
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_E); // α
        clr(r, 0);
    }
    pb.row().xmove(5, flag::XM_CLR).set(flag::XM2_ADD_PREV + 5); // X5 = α
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0); // α²
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_MUL);
    }
    for _ in 0..sh.ood_w {
        power_step(pb.row(), false, banks);
    }
    assert_eq!(banks.fpos, f_w_eval(n_cols), "F[0] = w_eval");
    {
        let r = pb.row();
        r.xmove(0, flag::XM_ADD_F0); // + w_eval
        f_rot(r, banks);
    }
    assert_eq!(banks.fpos, f_open(n_cols, 0), "F[0] = open_0");
    {
        let r = pb.row();
        clr(r, 4);
        r.set(flag::XM2_ADD_X4J + 4); // X4 = X0
    }
    pb.row().xmove(3, flag::XM_CLR).xmove(3, flag::XM_ADD_NEXT); // X3 = X4
    pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X); // E3 = claimed_w
    rows.claimed_w_row = pb.cur_row();
    // α_f
    rows.alpha_f_row = pb.sample_ext().row;
    pb.on_next(&[flag::RS_PUSH]);
    {
        let r = pb.row();
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_ONE); // α^0
        clr(r, 0);
    }
    pb.row().xmove(5, flag::XM_CLR).set(flag::XM2_ADD_PREV + 5); // X5 = 1
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0); // α
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_MUL);
    }
    pb.row().emove(1, flag::EM_CLR).set(flag::EM2_FROM_X4 + 1); // E1 = α_f (the power steps below read it)
    for _ in 0..n_cols {
        power_step(pb.row(), true, banks);
    }
    // X4 = α^{n_cols}, X5 = α^{n_cols+1}: the parked ans_f_i each ·α^{n_cols+i}
    for i in 0..sh.ood_f {
        pb.row().emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = X4
        let r = pb.row();
        match park[i] {
            6 => {
                r.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_E0);
                clr(r, 6);
                r.xmove(6, flag::XM_ADD_MUL);
            }
            7 => {
                r.mul_a(3, flag::AM_X4).mul_b(3, flag::BM_E0);
                clr(r, 7);
                r.xmove(7, flag::XM_ADD_MUL);
            }
            _ => {
                r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
                clr(r, 1);
                r.xmove(1, flag::XM_ADD_MUL);
            }
        }
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_NEXT); // X4 = X5
        if park[i] != 1 {
            r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E); // X5·α_f
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_MUL);
        }
    }
    if sh.ood_f >= 2 {
        pb.row().xmove(7, flag::XM_ADD_X2J); // X7 += X6
    } else if sh.ood_f == 1 {
        pb.row().xmove(7, flag::XM_CLR).xmove(7, flag::XM_ADD_X2J); // X7 = X6
    }
    if sh.ood_f >= 1 {
        pb.row().set(flag::XM2_ADD_PREV); // X0 += X7
    }
    if sh.ood_f == 3 {
        pb.row().xmove(0, flag::XM_ADD_NEXT); // X0 += X1
    }
    {
        let r = pb.row();
        clr(r, 4);
        r.set(flag::XM2_ADD_X4J + 4); // X4 = X0
    }
    pb.row().emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = claimed_f
    pb.row().set(flag::RS_PUSH);
    rows.claimed_f_row = pb.cur_row();
    rows
}

/// Rows after which `X7 = z̃`'s public part (`mle_eval(pub_half, r_y[..w_vars])`) and the `EXT_EQ` row of
/// `claim2 == m_at·z̃(r_y)`.
#[derive(Clone, Debug, Default)]
pub struct ZatRows {
    pub pub_row: usize,
    pub close_row: usize,
}

/// The `claim2 == m_at·z̃(r_y)` close, after the witness WHIR and its closing identity (they free `R` and every X/E).
/// `R ← statement hash` (`IOCHK_1`, bound to the public `io[8..16]`), the statement words re-hashed as leaf rows
/// (`ROOT_CHECK`) — the four public-half blocks fold their eight entries three levels on and after their own rows
/// against `r_y[0..3)` (`AM_BASEPAIR`/`XM_ADD_DBASE` read the hashed words), the four block values fold two more
/// levels against `r_y[3..5)`, then `Π_{5≤j<w_vars}(1 − r_y[j])`; `z̃ = pub·(1 − top) + w_eval·top` with `w_eval`,
/// `claim2`, `m_at` read back from `RS`. Precondition: `RS` at its entry rotation with `head` = 3 pushes above ρ;
/// `Y` as the witness closing identity leaves it. Postcondition: `RS` restored.
pub fn emit_zat_close(pb: &mut ProgramBuilder, sh: &CertShape, statement_hash: &[Fa4; RATE], statement_words: &[Fa4], banks: &mut Banks) -> ZatRows {
    let rs = RsIdx { head: 3, nnz: sh.nnz_bits, n_vars: sh.n_vars };
    let w_vars = sh.n_vars - 1;
    assert!(w_vars >= PUB_COL_BITS, "the public half spans {PUB_COL_BITS} variables");
    assert_eq!(PUB_COL_BITS, 6, "the fold below is laid for eight public-half blocks (two shift-register halves + one level)");
    assert_eq!(statement_words.len(), RATE + crate::spartan_ccs::STATEMENT_PUB_WORDS, "a header block and eight public-half blocks (io_len ≤ 63)");
    assert_eq!(banks.rs_head, 0);
    let mut rows = ZatRows::default();
    // R ← the statement hash: R_CAPTURE loads R2 on this row, R_SHIFT promotes it on the next (as emit_statement /
    // emit_commitments do — MEASURED without the shift the last leaf row's ROOT_CHECK read the witness WHIR's root)
    pb.new_row();
    pb.capture_root(statement_hash);
    pb.cur().set(flag::IOCHK + 1);
    pb.on_next(&[flag::R_SHIFT]);
    rs_to(pb, banks, rs.w_eval());
    pb.row().emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_RS0); // E2 = w_eval
    rs_to(pb, banks, rs.ry(0));
    for (k, block) in statement_words.chunks(RATE).enumerate() {
        pb.new_row();
        pb.leaf_block(block, k == 0);
        if k + 1 == statement_words.len() / RATE {
            pb.cur().set(flag::ROOT_CHECK);
        }
        // M5 — the INNER io rides these leaf rows 8-aligned (`universal_row::IO_PAD`): chunk 2 is the inner program
        // digest (this program's or the genesis program's: `IOCHK_BASE`), chunk 5 the inner state hash, captured into
        // `R2` for the acc-step rows (`acc_program::emit_acc_step` shifts it into `R` and re-derives it from the
        // inner `(acc, work, summary, block_work)`).
        if k == 1 + crate::universal_row::IO_PAD / RATE + 1 {
            pb.cur().set(flag::IOCHK_BASE);
        }
        if k == 1 + crate::universal_row::IO_PAD / RATE + 4 {
            pb.cur().set(flag::R_CAPTURE);
        }
        if k == 0 {
            continue;
        }
        {
            let r = pb.cur(); // level 1 on the leaf row: X_i = D[2i] + r_y[0]·(D[2i+1] − D[2i])
            for i in 0..4 {
                r.mul_a(i, flag::AM_BASEPAIR).set(flag::BM2_RS0 + i);
                clr(r, i);
                r.xmove(i, flag::XM_ADD_DBASE).xmove(i, flag::XM_ADD_MUL);
            }
            rs_up(r, banks);
        }
        {
            let r = pb.row(); // level 2 against r_y[1]
            r.mul_a(0, flag::AM_ADJ).set(flag::BM2_RS0);
            r.xmove(0, flag::XM_ADD_MUL);
            r.mul_a(1, flag::AM_ADJ).set(flag::BM2_RS0 + 1);
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_X2J).xmove(1, flag::XM_ADD_MUL); // X2 + r·(X3 − X2)
            rs_up(r, banks);
        }
        {
            let r = pb.row(); // level 3 against r_y[2]
            r.mul_a(0, flag::AM_ADJ).set(flag::BM2_RS0);
            r.xmove(0, flag::XM_ADD_MUL);
            rs_down(r, banks);
        }
        {
            let r = pb.row(); // the block value into the X4..X7 shift register
            for lane in 5..8 {
                clr(r, lane);
                r.set(flag::XM2_ADD_PREV + lane);
            }
            clr(r, 4);
            r.set(flag::XM2_ADD_X4J + 4);
            rs_down(r, banks);
        }
        assert_eq!(banks.rs_head, rs.ry(0));
        // ── after four public blocks: X4..X7 = v_3, v_2, v_1, v_0 (the newest first): level 4 against r_y[3], level 5
        // against r_y[4], the half's value in X7. Half 0 (blocks 0..4) parks in E3 (free until the fixed prelude re-sets
        // it); half 1 folds against it at level 6 below. The leaf rows stay consecutive for `H` (no row here permutes).
        if k == 4 || k == 8 {
            rs_to(pb, banks, rs.ry(3));
            {
                let r = pb.row();
                r.mul_a(3, flag::AM_ADJ).set(flag::BM2_RS0 + 3); // (X7 − X6)·r
                r.xmove(7, flag::XM_SUB_MUL); // v_0 + r·(v_1 − v_0)
                r.mul_a(2, flag::AM_ADJ).set(flag::BM2_RS0 + 2); // (X5 − X4)·r
                clr(r, 6);
                r.set(flag::XM2_ADD_PREV + 6).xmove(6, flag::XM_SUB_MUL); // v_2 + r·(v_3 − v_2)
                rs_up(r, banks);
            }
            {
                let r = pb.row();
                r.mul_a(3, flag::AM_ADJ).set(flag::BM2_RS0 + 3);
                r.xmove(7, flag::XM_SUB_MUL);
                rs_up(r, banks);
            }
            if k == 4 {
                pb.row().emove(3, flag::EM_CLR).set(flag::EM2_FROM_X4 + 3); // E3 = u_A (blocks 0..4)
                rs_to(pb, banks, rs.ry(0));
            }
        }
    }
    // level 6 against r_y[5]: pub = u_A + r·(u_B − u_A) with u_A in E3, u_B in X7 — two rows:
    // X7 ← E3 + r·X7 (the mul reads the OLD X7), then X7 −= r·E3
    assert_eq!(banks.rs_head, rs.ry(5));
    {
        let r = pb.row();
        r.mul_a(3, flag::AM_X4).set(flag::BM2_RS0 + 3); // X7·r
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_E).xmove(7, flag::XM_ADD_MUL); // E3 + r·u_B
    }
    {
        let r = pb.row();
        r.mul_a(3, flag::AM_E).set(flag::BM2_RS0 + 3); // E3·r
        r.xmove(7, flag::XM_SUB_MUL);
        rs_up(r, banks);
    }
    // Π_{6≤j<w_vars} (1 − r_y[j])
    for _ in PUB_COL_BITS..w_vars {
        let r = pb.row();
        r.mul_a(3, flag::AM_X4).set(flag::BM2_RS0 + 3);
        r.xmove(7, flag::XM_SUB_MUL);
        rs_up(r, banks);
    }
    rows.pub_row = pb.cur_row();
    assert_eq!(banks.rs_head, rs.ry(sh.n_vars - 1));
    {
        let r = pb.row(); // z̃ = pub·(1 − top) + w_eval·top
        r.mul_a(3, flag::AM_X4).set(flag::BM2_RS0 + 3);
        r.xmove(7, flag::XM_SUB_MUL);
        r.mul_a(2, flag::AM_E).set(flag::BM2_RS0 + 2); // E2·top
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_MUL);
        rs_up(r, banks);
    }
    assert_eq!(banks.rs_head, rs.claim2());
    {
        let r = pb.row();
        r.xmove(7, flag::XM_ADD_X2J); // X7 += X6
        r.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_RS0); // E1 = claim2
        rs_up(r, banks);
    }
    assert_eq!(banks.rs_head, rs.m_at());
    {
        let r = pb.row();
        r.mul_a(3, flag::AM_X4).set(flag::BM2_RS0 + 3); // z̃·m_at
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_MUL);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_E); // X1 = claim2
    }
    {
        let r = pb.row();
        clr(r, 4);
        r.set(flag::XM2_ADD_PREV + 4); // X4 = m_at·z̃
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_NEXT); // X0 = claim2
        r.set(flag::EXT_EQ);
    }
    rows.close_row = pb.cur_row();
    rs_to(pb, banks, 0);
    rows
}

/// The fixed WHIR's prelude: `R ← the release root` (`IOCHK_2`, bound to the public `io[16..24]`), `E3 ← claimed_f`
/// and `α_f → Y` from `RS` (their slots rotate to `RS`'s tail: ρ heads `RS` afterwards, `rs_depth = 0` for the fixed
/// closing identity), `Y` rotated once so the fixed OOD univariates sit right under α_f. Precondition: `RS` at its
/// entry rotation with `[claimed_f, α_f, w_eval]` above ρ; `Y[0]` = the witness closing identity's last OOD read.
pub fn emit_fixed_whir_prelude(pb: &mut ProgramBuilder, fixed_root: &[Fa4; RATE], banks: &mut Banks) -> After {
    assert_eq!(banks.rs_head, 0);
    pb.new_row();
    pb.capture_root(fixed_root);
    pb.cur().set(flag::IOCHK + 2);
    pb.on_next(&[flag::R_SHIFT]);
    {
        let r = pb.row();
        r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_RS0); // claimed_f
        rs_down(r, banks);
    }
    {
        let r = pb.row();
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // α_f
        rs_down(r, banks);
        r.set(flag::Y_ROT);
    }
    {
        let r = pb.row();
        r.set(flag::Y_PUSH);
        rs_down(r, banks); // w_eval to the tail: ρ heads RS
    }
    After { row: pb.cur_row() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_air::{pcs_with, CarrierParams, COMMITTED_FOLDING};
    use crate::matrix_argument::{scalars, MatrixPoint};
    use crate::matrix_program::emit_matrix_argument;
    use crate::spartan_ccs::{committed_pcs_with, fixed_commitment_root, fixed_table, mle_eval, pcs_point, prove_committed_uniform, statement_hash, transcript, verify_committed_uniform, verify_core_traced, SpartanCommittedProof};
    use crate::spartan_program::{emit_commitments, emit_core, emit_fixed_commitment, emit_initial_ood, emit_statement, statement_words, SpartanCheckpoints, SpartanShape};
    use crate::universal_row::{emulate, first_unsatisfied_step, uniform_instance, E_OFF, IO_LEN, NREG, NSTREAM, PS_OFF, RS_OFF, R_OFF, X_OFF, Y_OFF};
    use crate::whir_program::{emit_whir_verify, WhirShape};
    use crate::whir_weights::{emit_closing_identity, InitialKind, InitialShape};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::Mmcs;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_sumcheck::layout::{Layout, PrefixProver, Verifier as LayoutVerifier};
    use p3_sumcheck::table::TableShape;

    fn reg_ext(regs: &[Fa4], off: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| regs[off + i])
    }
    fn term(bit: Ea4, r: Ea4) -> Ea4 {
        bit * (r.double() - Ea4::ONE) + (Ea4::ONE - r)
    }

    /// ⭐⭐⭐ M4b: on a REAL uniform committed proof, the rows after the matrix argument reproduce the native
    /// verifier — `v`, `e_row`, `e_col_lo/hi`, `p_hi`, `e`, `sh`, `l_row`, `l_row·l_col`, `top` at their checkpoints,
    /// the summand `EXT_EQ` satisfied, `claimed_w` in `E3` and `claimed_f` at `RS[0]` equal to the layout's batched
    /// sums, the witness WHIR and its closing identity run through, `z̃`'s public part and the `claim2 == m_at·z̃`
    /// close satisfied — and a flipped column opening is refused at the summand's `EXT_EQ` row.
    #[test]
    fn the_uniform_certificate_rows_check_the_summand_and_close_z() {
        let p = crate::universal_row::tests::params();
        let t_bits = 2usize;
        let u = uniform_instance(&p, IO_LEN, t_bits);
        let mut pbt = ProgramBuilder::new();
        pbt.observe_slice(&(0..8).map(|i| Fa4::from_u64(300 + i)).collect::<Vec<_>>());
        pbt.sample_ext();
        pbt.on_next(&[flag::PT_PUSH]);
        let (mut program_t, mut stream_t) = pbt.finish();
        while program_t.len() < 1 << t_bits {
            program_t.push(RowFlags::default());
            stream_t.push([Fa4::ZERO; NSTREAM]);
        }
        // M5: the BASE CASE — the inner proof's io names the GENESIS program (block 0) and the genesis state (block 3);
        // this step folds from the genesis accumulator with zero work. The digest is a function of the genesis rows at
        // the certificate's own T (`program_digest`, native).
        let (genesis_rows, _genesis_stream) = crate::acc_program::genesis_program(14);
        let digest_g = crate::acc_program::program_digest(&genesis_rows);
        let mut io_t = vec![Fa4::ZERO; IO_LEN];
        io_t[crate::universal_row::io_block(0)].copy_from_slice(&digest_g);
        io_t[crate::universal_row::io_block(3)].copy_from_slice(&crate::acc_program::genesis_state_hash());
        let trace_t = emulate(&p, &io_t, [Fa4::ZERO; NREG], &program_t, &stream_t);
        // the recursion pins' rate (a round holds tens of queries, not hundreds: F holds a round's folds)
        let params = CarrierParams::legacy(4, 0);
        let f = FixedColumns::of(&u);
        let froot = fixed_commitment_root(&f, params);
        let bytes = prove_committed_uniform(&u, &io_t, &trace_t.w, params, params).expect("proves");
        assert!(verify_committed_uniform(&u, &io_t, &bytes, params, params, &froot), "the native uniform verifier accepts");
        let pr: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let mp = pr.matrix.as_ref().expect("a matrix argument");
        let fopen = pr.fixed_open.as_ref().expect("a fixed opening");
        let r1cs = u.materialize();
        let n_cols = f.n_cols();
        let sshape = SpartanShape { m_vars: r1cs.m_vars, n_vars: r1cs.n_vars, w_vars: r1cs.w_vars(), io_len: io_t.len(), ood: pr.open.initial_ood_answers.len() };
        let cert = CertShape { n_vars: r1cs.n_vars, m_vars: r1cs.m_vars, ood_w: pr.open.initial_ood_answers.len(), ood_f: fopen.initial_ood_answers.len(), nnz_bits: f.nnz_bits };
        // the native transcript, in the verifier's own order
        let mut ch = transcript(&r1cs, &io_t);
        ch.observe(pr.commitment.clone());
        for m in &pr.open.hvzk_mask_commits {
            ch.observe(m.clone());
        }
        ch.observe(froot.clone());
        for m in &fopen.hvzk_mask_commits {
            ch.observe(m.clone());
        }
        let mut flv = LayoutVerifier::<Fa4, Ea4>::new(&[TableShape::new(f.nnz_bits, n_cols)], PrefixProver::<Fa4, Ea4>::strategy());
        for &e in &fopen.initial_ood_answers {
            flv.add_virtual_eval(e, &mut ch);
        }
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&[TableShape::new(r1cs.w_vars(), 1)], PrefixProver::<Fa4, Ea4>::strategy());
        for &e in &pr.open.initial_ood_answers {
            lv.add_virtual_eval(e, &mut ch);
        }
        let (r_y, trace, rho) = verify_core_traced(&mut ch, &r1cs, &io_t, &pr.core, Some((&f, mp))).expect("the core + argument verify");
        let rho = rho.expect("ρ");
        let pt_w = pcs_point(&r_y[..r1cs.w_vars()]);
        lv.add_claim_at(0, &[0], &[pr.core.w_eval], &pt_w, &mut ch);
        let fpt = pcs_point(&rho);
        let cols: Vec<usize> = (0..n_cols).collect();
        flv.add_claim_at(0, &cols, &mp.openings, &fpt, &mut ch);
        crate::spartan_ccs::absorb_claims_pad(&mut ch, 1 + n_cols);
        let alpha_w: Ea4 = ch.sample_algebra_element();
        let alpha_f: Ea4 = ch.sample_algebra_element();
        let mut claimed_w = Ea4::ZERO;
        lv.constraint(alpha_w).combine_evals(&mut claimed_w);
        let mut claimed_f = Ea4::ZERO;
        flv.constraint(alpha_f).combine_evals(&mut claimed_f);
        // the native scalars and summand parts
        let [ra, rb, rc] = trace.rabc;
        let mpt = MatrixPoint { ra, rb, rc, r_x: trace.r_x.clone(), r_y: r_y.clone() };
        let sc = scalars(&f, &mpt);
        let o = &mp.openings;
        let v = ra * o[0] + rb * o[1] + rc * o[2];
        let e_row = (0..f.r_bits).fold(Ea4::ONE, |acc, b| acc * term(o[f.row_bit(b)], sc.r_lo[b]));
        let e_col_lo = (0..PUB_COL_BITS).fold(Ea4::ONE, |acc, b| acc * term(o[f.col_bit(b)], sc.s_lo[b]));
        let e_col_hi = (PUB_COL_BITS..f.v_bits).fold(Ea4::ONE, |acc, b| acc * term(o[f.col_bit(b)], sc.s_lo[b]));
        let p_hi_cols = (PUB_COL_BITS..f.v_bits).fold(Ea4::ONE, |acc, b| acc * (Ea4::ONE - r_y[b]));
        let p_hi_no_top = (PUB_COL_BITS..r1cs.n_vars - 1).fold(Ea4::ONE, |acc, b| acc * (Ea4::ONE - r_y[b]));
        // the program
        let shape_w = WhirShape::of(&committed_pcs_with(&r1cs, params).config);
        let fwitness_vars = PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(&f)], COMMITTED_FOLDING).num_variables();
        let fcfg = pcs_with(fwitness_vars, params).config;
        let shape_f = WhirShape::of_with_offset(&fcfg, shape_w.slots());
        eprintln!(
            "[cert-rows] witness WHIR: {} rounds (queries {:?}, final {}), final poly {}; fixed WHIR ({} vars): {} rounds (queries {:?}, final {}), final poly {}; ood w {} f {}",
            shape_w.rounds.len(),
            shape_w.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            shape_w.final_round.num_queries,
            shape_w.final_poly_len,
            fwitness_vars,
            shape_f.rounds.len(),
            shape_f.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            shape_f.final_round.num_queries,
            shape_f.final_poly_len,
            cert.ood_w,
            cert.ood_f
        );
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
        let mut banks = Banks::default();
        let observe_row = emit_observe_claims(&mut pb, pr.core.w_eval, &mp.openings);
        let srows = emit_summand_check(&mut pb, &f, &cert, &mut banks);
        let prows = emit_pcs_claims(&mut pb, &cert, n_cols, &mut banks);
        let wcp = emit_whir_verify(&mut pb, &shape_w, &pr.open);
        let rs_idx = RsIdx { head: 3, nnz: f.nnz_bits, n_vars: r1cs.n_vars };
        let init_w = InitialShape { w: r1cs.w_vars(), n_vars: r1cs.n_vars, ood: cert.ood_w, rs_depth: rs_idx.depth_above_ry(), kind: InitialKind::Witness };
        let ccp = emit_closing_identity(&mut pb, &shape_w, &init_w);
        let zrows = emit_zat_close(&mut pb, &cert, &sh, &words, &mut banks);
        // ── M5: the acc-step rows — the base step from the genesis state (the inner io's block 3, captured on the z̃
        // close's leaf row), this block's summary and work, the outer state into io block 3 ────────────────────────
        let step = crate::acc_program::AccStep::base([7u64, 11, 13, 17, 19, 23, 29, 31], (0x12_3456u128 << 24) + 0x54_3210).expect("a base step");
        let arows = crate::acc_program::emit_acc_step(&mut pb, &step);
        // ── M4c: the fixed WHIR (R ← the release root under IOCHK_2, E3 ← claimed_f, α_f → Y) and its closing
        // identity (33 column claims lifted through the layout's selector bits, OOD claims at γ^{33+i}) ────────
        let pre = emit_fixed_whir_prelude(&mut pb, &froot.roots()[0], &mut banks);
        let fcp = emit_whir_verify(&mut pb, &shape_f, fopen);
        let n_sel = fwitness_vars - f.nnz_bits;
        let init_f = InitialShape { w: fwitness_vars, n_vars: f.nnz_bits, ood: cert.ood_f, rs_depth: 0, kind: InitialKind::Fixed { n_sel, n_cols } };
        let fccp = emit_closing_identity(&mut pb, &shape_f, &init_f);
        let (mut program, mut stream) = pb.finish();
        // ── M4d: the program as a COMPLETE statement — INIT on row 0 (every state register zero), FINAL on row T−2
        // (the program digest, PS after that row, equals the public io[0..8]). T = 2^14 is the certificate's
        // production row count (spec §M5): the R = 2^14 template (34 columns, 32 padded coefficients × 16 rounds,
        // the 36-element claims block) emits 8,27x rows, MEASURED 2026-09-28, and the acc-step rows ride above them ──
        let t_cert = 1usize << 14;
        assert!(program.len() + 2 <= t_cert, "the certificate program fits T = {t_cert} rows ({} emitted)", program.len());
        while program.len() < t_cert {
            program.push(RowFlags::default());
            stream.push([Fa4::ZERO; NSTREAM]);
        }
        program[0].set(flag::INIT);
        program[t_cert - 2].set(flag::FINAL);
        let params_row = WhirShape::row_params_multi(&[(&shape_w, &committed_pcs_with(&r1cs, params).config), (&shape_f, &fcfg)], r1cs.m_vars - 1).with_base_digest(digest_g);
        let mut io_row = vec![Fa4::ZERO; IO_LEN];
        io_row[crate::universal_row::io_block(1)].copy_from_slice(&sh);
        io_row[crate::universal_row::io_block(2)].copy_from_slice(&froot.roots()[0]);
        io_row[crate::universal_row::io_block(3)].copy_from_slice(&step.state);
        let regs0 = [Fa4::ZERO; NREG];
        let tr = emulate(&params_row, &io_row, regs0, &program, &stream);
        // the program digest: PS after row T−2 (the register values do not depend on io, so one emulation serves)
        let digest: Vec<Fa4> = tr.regs_after(t_cert - 2)[PS_OFF..PS_OFF + RATE].to_vec();
        io_row[crate::universal_row::io_block(0)].copy_from_slice(&digest);
        let x = |row: usize, lane: usize| reg_ext(&tr.regs_after(row), X_OFF + 4 * lane);
        let e = |row: usize, lane: usize| reg_ext(&tr.regs_after(row), E_OFF + 4 * lane);
        let rs0 = |row: usize| reg_ext(&tr.regs_after(row), RS_OFF);
        eprintln!(
            "[cert-rows] {} rows: argument ..={}, observe {}, summand {}..={} (v {}, e_row {}, e_col {}, joint {}), claims w {} f {}, witness WHIR ..={}, closing ..={}, z̃ close {}, fixed prelude {}, fixed WHIR ..={}, fixed closing ..={}",
            program.len(),
            mcp.round_claims.last().unwrap().row,
            observe_row.row,
            observe_row.row + 1,
            srows.check_row,
            srows.v_row,
            srows.e_row_row,
            srows.e_col_row,
            srows.d_row,
            prows.claimed_w_row,
            prows.claimed_f_row,
            wcp.after_final_sumcheck.map(|a| a.row).unwrap_or(0),
            ccp.close_row.unwrap().row,
            zrows.close_row,
            pre.row,
            fcp.after_final_sumcheck.map(|a| a.row).unwrap_or(0),
            fccp.close_row.unwrap().row
        );
        // the summand's intermediates
        assert_eq!(x(srows.v_row, 0), v, "X0 = v after phase A");
        assert_eq!(x(srows.e_row_row, 0), v * e_row, "X0 = v·e_row after phase B");
        assert_eq!(x(srows.e_col_row, 0), v * e_row * e_col_lo, "X0 = v·e_row·e_col_lo after phase C");
        assert_eq!(x(srows.e_col_row, 2), e_col_hi, "X2 = e_col_hi after phase C");
        assert_eq!(x(srows.e_col_row, 3), p_hi_cols, "X3 = Π_{{5≤b<v_bits}}(1 − r_y[b]) after phase C");
        assert_eq!(x(srows.d_row, 0), sc.e, "X0 = e after the joint walk");
        assert_eq!(x(srows.d_row, 1), sc.sh, "X1 = sh after the joint walk");
        assert_eq!(x(srows.d_row, 2), sc.l_row, "X2 = l_row after the joint walk");
        assert_eq!(x(srows.d_row, 3), sc.l_row * sc.l_col, "X3 = l_row·l_col after the joint walk");
        assert_eq!(e(srows.d_row, 1), p_hi_no_top, "E1 = p_hi without the top factor after the joint walk");
        assert_eq!(e(srows.d_row, 0), sc.top, "E0 = top after the joint walk");
        assert_eq!(e(srows.check_row, 3), *trace.matrix_claims.last().unwrap(), "E3 = the argument's final claim at the check row");
        // the pcs claims
        assert_eq!(e(prows.alpha_w_row, 0), alpha_w, "E0 = α_w");
        assert_eq!(e(prows.claimed_w_row, 3), claimed_w, "E3 = claimed_w");
        assert_eq!(e(prows.alpha_f_row, 0), alpha_f, "E0 = α_f");
        assert_eq!(rs0(prows.claimed_f_row), claimed_f, "RS[0] = claimed_f");
        // the z̃ close
        let mut pub_half = vec![Fa4::ZERO; r1cs.w_off()];
        pub_half[0] = Fa4::ONE;
        pub_half[1..=io_t.len()].copy_from_slice(&io_t);
        assert_eq!(x(zrows.pub_row, 7), mle_eval(&pub_half, &r_y[..r1cs.w_vars()]), "X7 = the public half's MLE at r_y");
        assert_eq!(x(zrows.close_row, 4), trace.m_at * trace.z_at, "X4 = m_at·z̃ at the close row");
        assert_eq!(x(zrows.close_row, 0), *trace.inner_claims.last().unwrap(), "X0 = claim2 at the close row");
        // the fixed prelude hands the fixed WHIR its inputs; the fixed closing identity's D closes at 0
        assert_eq!(e(pre.row, 3), claimed_f, "E3 = claimed_f after the fixed prelude");
        assert_eq!(reg_ext(&tr.regs_after(pre.row), Y_OFF), alpha_f, "Y[0] = α_f after the fixed prelude");
        assert_eq!(&tr.regs_after(pre.row)[R_OFF..R_OFF + RATE], &froot.roots()[0][..], "R = the release root after the fixed prelude");
        assert_eq!(x(fccp.close_row.unwrap().row, 4), Ea4::ZERO, "the fixed closing identity's D closes at 0");
        // the honest rows satisfy every check (the summand EXT_EQ, both WHIR runs, both closing D == 0, the z̃ close)
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs0, &program, &stream), None, "the honest rows satisfy");
        // a flipped word of the fixed WHIR's final polynomial (its first F_PUSH2 row after the prelude) is refused at
        // or before the fixed closing row
        let ffinal_row = (pre.row..program.len()).find(|&i| program[i].is_set(flag::F_PUSH2)).expect("the fixed WHIR's first final-poly row");
        let mut bad_f = stream.clone();
        bad_f[ffinal_row][0] += Fa4::ONE;
        let at_f = first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad_f).expect("a flipped fixed final coefficient must be refused");
        assert!(at_f > ffinal_row && at_f <= fccp.close_row.unwrap().row, "refused inside the fixed WHIR or at its closing row (row {at_f})");
        // M4d refusals: one flag bit more on an idle row moves the digest → FINAL refuses at row T−2; a nonzero state
        // register at the start → INIT refuses at row 0
        let mut bad_p = program.clone();
        bad_p[t_cert - 10].set(flag::PT_ROT);
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs0, &bad_p, &stream), Some(t_cert - 2), "FINAL refuses a one-bit program change");
        let mut regs_bad = regs0;
        regs_bad[crate::universal_row::S_OFF] = Fa4::ONE;
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs_bad, &program, &stream), Some(0), "INIT refuses a nonzero state register");
        // the observe's pair rows: the first absorbs (w_eval, open_0), the third (open_3, open_4)
        let w_row = (mcp.round_claims.last().unwrap().row + 1..observe_row.row).find(|&i| program[i].is_set(flag::F_PUSH2)).expect("the first observe pair row");
        assert!(program[w_row].is_set(flag::M_ABSORB) && program[w_row].is_set(flag::XMOVE + flag::XM_CLR), "the w_eval row reads D0 into X0");
        // a flipped column opening (open_3: the third pair row's first word) is refused at the summand's EXT_EQ
        let flip_row = w_row + 2;
        assert!(program[flip_row].is_set(flag::M_ABSORB) && program[flip_row].is_set(flag::F_PUSH2), "an observe pair row");
        let mut bad = stream.clone();
        bad[flip_row][0] += Fa4::ONE;
        let at = first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad).expect("a flipped opening must be refused");
        assert_eq!(at, srows.check_row, "refused at the summand's EXT_EQ row");
        // a flipped w_eval changes claimed_w (and diverges the transcript): refused inside the witness WHIR — after
        // the pcs claim rows, before the witness closing row — never as late as the z̃ close
        let mut bad_w = stream.clone();
        bad_w[w_row][0] += Fa4::ONE;
        let at_w = first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad_w).expect("a flipped w_eval must be refused");
        assert!(at_w > prows.claimed_w_row && at_w < ccp.close_row.unwrap().row, "refused inside the witness WHIR (row {at_w})");
        // M5: the base case's two doors — the inner program digest (IOCHK_BASE on the z̃ leaf row carrying the inner
        // io's block 0) and the acc' copy (ROOT_CHECK on the fold row)
        let base_row = (0..program.len()).find(|&i| program[i].is_set(flag::IOCHK_BASE)).expect("the inner-digest leaf row");
        let mut bad_g = stream.clone();
        bad_g[base_row][2] += Fa4::ONE;
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad_g), Some(base_row), "⛔ an inner proof of a program that is neither this one nor the genesis program was accepted");
        let mut bad_acc = stream.clone();
        bad_acc[arows.acc_copy_row][1] += Fa4::ONE;
        assert_eq!(first_unsatisfied_step(&params_row, &io_row, regs0, &program, &bad_acc), Some(arows.fold_row), "⛔ a wrong acc' copy passed the fold row inside the certificate");
        assert_eq!(&tr.regs_after(arows.state_check_row)[R_OFF..R_OFF + RATE], &step.state[..], "R = the outer state at the acc-step's state check");
        eprintln!("[cert-rows] acc-step rows {}..={} ({} rows): inner check {}, fold {}, state check {}, sums ..={}", arows.first, arows.last, arows.last + 1 - arows.first, arows.inner_check_row, arows.fold_row, arows.state_check_row, arows.sum_rows[7]);
        eprintln!("[cert-rows] GREEN: summand, both pcs claims, the witness WHIR + closing, the z̃ close, the ACC STEP (base case: genesis program + genesis state → fold, work, state hash in io block 3), the fixed WHIR + closing as a COMPLETE statement at T = {t_cert} (INIT/FINAL/digest); a flipped opening is refused at row {at}, a flipped w_eval at row {at_w}, a flipped fixed final coefficient at row {at_f}, a one-bit program change at row {}, a foreign inner digest at row {base_row}, a wrong acc' copy at row {}", t_cert - 2, arows.fold_row);
    }
}

//! THE CLOSING IDENTITY of the WHIR verifier as universal-row instructions (spec §Z3-W3): after `emit_whir_verify`
//! has left the claimed sum in `E3`, the folding randomness in `PT`, every query's `g^index` in `VB`, the OOD
//! univariates and α's in `Y` and the final polynomial in `F`, this emitter computes `f(r)` (the final polynomial
//! at the final sumcheck point), every constraint's weight `Σ_i γ^i·eq(z_i, local) + Σ_q γ^{n_eq+q}·select(local,
//! v_q)` exactly as `eval_constraints_poly` does, subtracts `W_c · f(r)` from the claim per constraint, and closes
//! with `EXT_EQ` on `D == 0` — the row that REFUSES a proof whose sumcheck evaluations were altered.
//!
//! Register conventions here: `E3` = `D` (the claim, then the running difference), `E2` = `f(r)`, `E1` = the
//! current constraint's Horner accumulator `W`, `E0` = the constraint's α during its select part and the eq
//! univariate `u` (or the `r_y` coordinate `a`) during its eq walks; `X0..X3` = the four select accumulators (one
//! per `VB` slot) or the eq accumulator (`X2`), `X4..X7` = temporaries (`X5` = α during the eq walks).
//!
//! ROOT-LAYER: every walk pairs `PT[j]` with the `j`-th squaring of the univariate exactly as `Point::eq_poly`
//! on `expand_from_univariate` and `Point::select_poly` do (the last coordinate of `local` is `PT[0]`); the
//! constraint order (round `n−1` first, the initial constraint last) only permutes a sum.
//! MEASURED: pin `the_closing_identity_reproduces_the_native_weights_and_refuses_a_moved_claim` (whir_program.rs).
//! MUST-STAY-GREEN: the universal-row, program-builder and WHIR-program pins.

use crate::universal_row::{flag, RowFlags, NF, NPT, NRS, NVB, NY};
use crate::verifier_program::{After, ProgramBuilder};
use crate::whir_program::WhirShape;

/// What the initial constraint's concrete claims are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitialKind {
    /// The witness commitment: ONE evaluation (`w_eval`, weight γ⁰) at the pcs point `reversed(r_y[..w])`.
    Witness,
    /// The fixed commitment (a uniform certificate): `n_cols` column evaluations (the matrix argument's openings,
    /// weights γ⁰..γ^{n_cols−1} in column order) at the argument's point `reversed(ρ)`, each lifted through the
    /// layout's `n_sel` selector bits (`PrefixProver::strategy()`: `reverse_selectors`, so column `c`'s bit `i`
    /// sits at stacked coordinate `n_point + i`, i.e. `PT[n_sel − 1 − i]`). The OOD claims then take
    /// γ^{n_cols + i}. Requires `n_cols = 2^{n_sel−1} + 1` (the template's 33 columns), for which the column part
    /// of the weight has the closed form `(1 − q_{n_sel−1})·Π_{i<n_sel−1}(1 − q_i + q_i·γ^{2^i}) +
    /// q_{n_sel−1}·γ^{2^{n_sel−1}}·Π_{i<n_sel−1}(1 − q_i)`.
    Fixed { n_sel: usize, n_cols: usize },
}

/// The initial constraint's shape: the committed polynomial's variables `w` (the constraint's arity), the point's
/// arity `n_vars` (the Spartan core's `r_y` length, or ρ's 16; `RS` holds it newest-first), and the initial
/// commitment's OOD sample count (their univariates sit in `Y` below the α's, oldest deepest).
#[derive(Clone, Debug)]
pub struct InitialShape {
    pub w: usize,
    pub n_vars: usize,
    pub ood: usize,
    /// Entries pushed onto `RS` ABOVE the point's newest coordinate (the uniform certificate's stashes and ρ above
    /// `r_y`; 0 in the plain path): coordinate `j` sits at `RS[rs_depth + n_vars − 1 − j]`.
    pub rs_depth: usize,
    pub kind: InitialKind,
}

/// Checkpoints: the rows after which the named register holds the named value.
#[derive(Clone, Debug, Default)]
pub struct ClosingCheckpoints {
    /// `E2 = f(r)`.
    pub f_row: Option<After>,
    /// Per constraint in program order (round `n−1`, …, round `0`, the initial constraint): the native constraint
    /// index (`0` = initial, `r+1` = round `r`) and the row after which `E1` holds its weight.
    pub weights: Vec<(usize, After)>,
    /// The `EXT_EQ` row asserting `D == 0`.
    pub close_row: Option<After>,
    /// `f(r)` stages for the pin: ("rotated", row) — `F[0] = c_0`; ("chunk t loaded", row) — `X0..X7 = c_{8t..}`;
    /// ("chunk t folded", row) — `X0 = h_t`; ("chunk t weighted", row) — `E2 = Σ_{s≤t} h_s·w_s`.
    pub f_stages: Vec<(String, usize)>,
}

fn x2j(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_ADD_X2J)
}
fn clr(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_CLR)
}

/// `f(r)`: the final polynomial (`L = 2^m` coefficients at `F`'s tail, `c_{L−1}` last) at the final sumcheck point
/// (`PT[0..m)`, `PT[0]` the last coordinate, which folds adjacent pairs first — `Poly::eval_ext`). Chunks of eight
/// coefficients are loaded into `X0..X7` and folded three levels against `PT[0]`, `PT[1]`, `PT[2]` (`h_t`); the
/// chunk's weight `w_t = Π_j (t_j ? PT[3+j] : 1 − PT[3+j])` (chunk-index bit `j` ↔ coordinate `3 + j`) is then
/// walked down `PT` and `E2 += h_t·w_t` — a STREAMING multilinear evaluation over the chunk values, so no chunk value
/// is ever parked and any `L ≤ NF` fits (128: the certificate sends its final polynomial at 7 variables). The
/// `3 + hi` rotations a chunk leaves are undone on the next chunk's load rows (they read no `PT`), the last chunk's
/// on their own rows. Leaves `f` in `E2`; uses X0..X7, X1/X4/X5/X6 after each fold, E2.
fn emit_final_value(pb: &mut ProgramBuilder, l: usize, stages: &mut Vec<(String, usize)>) {
    assert!(l.is_power_of_two() && (8..=NF).contains(&l), "the final polynomial has 8..={NF} coefficients (got {l})");
    let nchunks = l / 8;
    let hi = l.trailing_zeros() as usize - 3; // chunk-index bits
    assert!(3 + hi <= 8, "a chunk's rotations restore on the next chunk's eight load rows");
    pb.drain_repeats();
    for _ in 0..l {
        pb.row().set(flag::F_ROT_UP);
    }
    stages.push(("rotated".into(), pb.cur_row()));
    // E2 = 0
    {
        let r = pb.row();
        clr(r, 6);
    }
    pb.row().emove(2, flag::EM_CLR).set(flag::EM2_FROM_X4 + 2);
    let mut owed_ups = 0usize;
    for t in 0..nchunks {
        for i in 0..8 {
            let r = pb.row();
            clr(r, i).xmove(i, flag::XM_ADD_F0);
            r.set(flag::F_ROT);
            if owed_ups > 0 {
                r.set(flag::PT_ROT_UP);
                owed_ups -= 1;
            }
        }
        debug_assert_eq!(owed_ups, 0);
        stages.push((format!("chunk {t} loaded"), pb.cur_row()));
        fold_three_levels(pb); // PT[0] = coordinate 1 afterwards (down twice, up once)
        stages.push((format!("chunk {t} folded"), pb.cur_row()));
        {
            let r = pb.row();
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_ONE); // w = 1
            r.set(flag::PT_ROT); // → coordinate 2
        }
        {
            let r = pb.row();
            clr(r, 4);
            r.set(flag::XM2_ADD_X4J + 4); // X4 = h_t
            r.set(flag::PT_ROT); // → coordinate 3 = chunk bit 0
        }
        for j in 0..hi {
            {
                let r = pb.row();
                clr(r, 5);
                if (t >> j) & 1 == 1 {
                    r.xmove(5, flag::XM_ADD_PT0);
                } else {
                    r.xmove(5, flag::XM_ADD_ONE).xmove(5, flag::XM_SUB_PT0);
                }
                r.set(flag::PT_ROT); // → coordinate 3 + j + 1
            }
            {
                let r = pb.row();
                r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4); // w·factor
                clr(r, 1);
                r.xmove(1, flag::XM_ADD_MUL);
                if j + 1 == hi {
                    clr(r, 5);
                    r.set(flag::XM2_ADD_PREV + 5); // X5 = h_t (the factor was read above)
                }
            }
        }
        if hi == 0 {
            let r = pb.row();
            clr(r, 5);
            r.set(flag::XM2_ADD_PREV + 5); // X5 = h_t
        }
        {
            let r = pb.row();
            r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4); // w·h_t
            clr(r, 5);
            r.xmove(5, flag::XM_ADD_MUL);
        }
        {
            let r = pb.row();
            clr(r, 6);
            r.xmove(6, flag::XM_ADD_E).set(flag::XM2_ADD_PREV + 6); // E2 + w·h_t
        }
        pb.row().emove(2, flag::EM_CLR).set(flag::EM2_FROM_X4 + 2);
        stages.push((format!("chunk {t} weighted"), pb.cur_row()));
        owed_ups = 3 + hi;
    }
    for _ in 0..owed_ups {
        pb.row().set(flag::PT_ROT_UP);
    }
}

/// Three fold levels over `X0..X7` against `PT[0]`, `PT[1]`, `PT[2]` (the query-fold pattern), rotating `PT`
/// down twice and up once (the caller restores the second rotation). Leaves the value in `X0`.
fn fold_three_levels(pb: &mut ProgramBuilder) {
    {
        let r = pb.row();
        for k in 0..4 {
            r.mul_a(k, flag::AM_ADJ).mul_b(k, flag::BM_PT0);
        }
        r.xmove(0, flag::XM_ADD_MUL);
        for j in 1..4 {
            clr(r, j);
            x2j(r, j).xmove(j, flag::XM_ADD_MUL);
        }
        r.set(flag::PT_ROT);
    }
    {
        let r = pb.row();
        r.mul_a(0, flag::AM_ADJ).mul_b(0, flag::BM_PT0);
        r.xmove(0, flag::XM_ADD_MUL);
        r.mul_a(1, flag::AM_ADJ).mul_b(1, flag::BM_PT0);
        clr(r, 1);
        x2j(r, 1).xmove(1, flag::XM_ADD_MUL);
        r.set(flag::PT_ROT);
    }
    {
        let r = pb.row();
        r.mul_a(0, flag::AM_ADJ).mul_b(0, flag::BM_PT0);
        r.xmove(0, flag::XM_ADD_MUL);
        r.set(flag::PT_ROT_UP);
    }
}

/// One eq-walk variable: `T = 2·PT0·u − PT0 − u + 1` with `u = E0`, `X2 ← X2·T`; with `square`, `E0 ← u²`; with
/// `rs_step`, `RS` rotates up and `E0 ← RS[0]` for the next variable (the pcs-point walk). `PT` rotates down once.
fn eq_step(pb: &mut ProgramBuilder, square: bool, rs_step: bool) {
    {
        let r = pb.row();
        r.mul_a(0, flag::AM_PT0).mul_b(0, flag::BM_E); // PT0·u (E0)
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_MUL).xmove(4, flag::XM_SUB_PT0).xmove(4, flag::XM_ADD_ONE).xmove(4, flag::XM_SUB_E);
    }
    {
        let r = pb.row();
        r.mul_a(2, flag::AM_PT0).mul_b(2, flag::BM_E0); // PT0·u again, on lane 2
        clr(r, 6);
        x2j(r, 6).xmove(6, flag::XM_ADD_MUL); // X6 = T
        if square {
            r.mul_a(0, flag::AM_E).mul_b(0, flag::BM_E); // u²
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_MUL);
        }
        r.set(flag::PT_ROT);
        if rs_step {
            r.set(flag::RS_ROT_UP);
        }
    }
    {
        let r = pb.row();
        r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4); // X2·X6
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_MUL);
        if square {
            r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X); // E0 = u²
        }
        if rs_step {
            r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0); // E0 = the next r_y coordinate
        }
    }
}

/// `W ← W·α + X2` (the Horner step of the eq part; α in `X5`, `W` in `E1`, the eq value in `X2`).
fn horner_eq(pb: &mut ProgramBuilder) {
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_X4); // E1·X5
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL).xmove(1, flag::XM_ADD_NEXT); // + X2
    }
    pb.row().emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X);
}

/// The fixed commitment's column-select weight `W_col = Σ_{c<n_cols} γ^c·Π_i (bit_i(c) ? q_i : 1 − q_i)` with
/// `q_i = PT[n_sel − 1 − i]` (see [`InitialKind::Fixed`]), for `n_cols = 2^k + r`, `k = n_sel − 1`, `r ∈ {1, 2}`:
/// `(1 − q_k)·Π_{i<k}(1 − q_i + q_i·γ^{2^i}) + q_k·γ^{2^k}·B` with `B = Π_{i<k}(1 − q_i)` for `r = 1` (column 2^k
/// alone) and `B = (1 − q_0 + q_0·γ)·Π_{1≤i<k}(1 − q_i)` for `r = 2` (columns 2^k and 2^k + 1). Walks `PT` down `k`
/// then up one per bit (restored). Precondition: `X4 = X5 = γ` (`alpha_into_x5`). Leaves `X7 = W_col`,
/// `X3 = γ^{n_cols}`; `X5 = γ` untouched; uses X0, X1, X2, X4, X6, E0.
fn emit_column_select_weight(pb: &mut ProgramBuilder, n_sel: usize, n_cols: usize) {
    let k = n_sel - 1;
    assert!(n_sel >= 2 && n_cols > (1usize << k) && n_cols <= (1usize << k) + 2, "the closed form covers n_cols = 2^(n_sel−1) + 1 or + 2 (got {n_cols} at {n_sel} bits)");
    let two_extra = n_cols == (1usize << k) + 2;
    let mut downs = k;
    // init: X0 = A = 1, X2 = B = 1, X3 = X7 = a_0 = γ (X4 = γ already)
    {
        let r = pb.row();
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_ONE);
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_ONE);
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_NEXT); // X3 = X4 = γ
        if downs > 0 {
            r.set(flag::PT_ROT);
            downs -= 1;
        }
    }
    {
        let r = pb.row();
        clr(r, 7);
        r.set(flag::XM2_ADD_X4J + 7); // X7 = X3 = γ
        if downs > 0 {
            r.set(flag::PT_ROT);
            downs -= 1;
        }
    }
    while downs > 0 {
        pb.row().set(flag::PT_ROT);
        downs -= 1;
    }
    // per bit i < k (PT0 = q_i): X4 = 1 − q_i + q_i·a_i; X3 = a_i² (X3·X7); B: X2 ·= 1 − q_i (or ·= the factor at
    // i = 0 with two extra columns); then A: X0 ·= X4, a_{i+1} into X4 and X7, PT up
    for i in 0..k {
        {
            let r = pb.row();
            r.mul_a(0, flag::AM_PT0).mul_b(0, flag::BM_X4); // q_i·a_i
            clr(r, 4);
            r.xmove(4, flag::XM_ADD_ONE).xmove(4, flag::XM_SUB_PT0).xmove(4, flag::XM_ADD_MUL);
            r.mul_a(3, flag::AM_X).mul_b(3, flag::BM_X4); // a_i·a_i (X3·X7)
            clr(r, 3);
            r.xmove(3, flag::XM_ADD_MUL);
            if !(two_extra && i == 0) {
                r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_PT0); // B·q_i
                r.xmove(2, flag::XM_SUB_MUL);
            }
        }
        {
            let r = pb.row();
            r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4); // A·factor
            clr(r, 0);
            r.xmove(0, flag::XM_ADD_MUL);
            if two_extra && i == 0 {
                clr(r, 6);
                r.xmove(6, flag::XM_ADD_X2J); // X6 = X4 = factor_0 (read before X4 is overwritten below)
            }
            clr(r, 7);
            r.set(flag::XM2_ADD_X4J + 7); // X7 = X3 = a_{i+1}
            clr(r, 4);
            r.set(flag::XM2_ADD_PREV + 4); // X4 = X3
            r.set(flag::PT_ROT_UP);
        }
        if two_extra && i == 0 {
            let r = pb.row();
            r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4); // B·factor_0 (X2·X6)
            clr(r, 2);
            r.xmove(2, flag::XM_ADD_MUL);
        }
    }
    // PT0 = q_k, X3 = X4 = X7 = a_k = γ^{2^k}: W_col = (1 − q_k)·A + q_k·a_k·B; γ^{n_cols} = a_k·γ^r
    {
        let r = pb.row();
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_PT0); // A·q_k
        r.xmove(0, flag::XM_SUB_MUL);
        r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_PT0); // B·q_k
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_MUL);
        r.emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = X4 = a_k
    }
    {
        let r = pb.row();
        r.mul_a(2, flag::AM_X).mul_b(2, flag::BM_E0); // B·q_k·a_k
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_MUL);
        r.mul_a(1, flag::AM_X4).mul_b(1, flag::BM_E0); // X5·E0 = γ·a_k = γ^{2^k + 1}
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
    }
    {
        let r = pb.row();
        clr(r, 6);
        r.set(flag::XM2_ADD_X4J + 6); // X6 = X2 = q_k·a_k·B
        if two_extra {
            r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4); // γ^{2^k + 1}·γ (X1·X5)
            clr(r, 1);
            r.xmove(1, flag::XM_ADD_MUL);
        }
    }
    {
        let r = pb.row();
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_X2J); // X7 = X6 (the B term)
    }
    pb.row().set(flag::XM2_ADD_PREV); // X0 += X7: W_col
    {
        let r = pb.row();
        clr(r, 7);
        r.xmove(7, flag::XM_ADD_NEXT); // X7 = X0 = W_col
        clr(r, 2);
        r.set(flag::XM2_ADD_PREV + 2); // X2 = X1 = γ^{n_cols}
    }
    {
        let r = pb.row();
        clr(r, 3);
        r.set(flag::XM2_ADD_PREV + 3); // X3 = X2
    }
}

/// Load α (`E0`) into `X5` for the eq walks: `X4 ← E0`, `X5 ← X4`.
fn alpha_into_x5(pb: &mut ProgramBuilder) {
    {
        let r = pb.row();
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_E);
    }
    pb.row().xmove(5, flag::XM_CLR).set(flag::XM2_ADD_PREV + 5);
}

/// One select group of four `VB` slots (slot `k` ↔ `VB[k]`), the participating slots `k0..4` all of one constraint
/// with `n_c` variables (the earlier slots of a padded group are dummies). Init `X0..X3 ← α³, α², α, 1` (α in `E0`),
/// walk `n_c` variables (two rows each: `X_{k+4} ← PT0·v + 1 − PT0`, `X_k ← X_k·X_{k+4}`; `VB_SQ4`, `PT_ROT`),
/// restore `PT`, sum the participating accumulators into `X0`, `W ← W·α^a + X0` (`a` participating slots), rotate
/// `VB` by four.
fn select_group(pb: &mut ProgramBuilder, k0: usize, n_c: usize) {
    assert!(k0 < 4);
    let a = 4 - k0;
    // load the group: four pops of the VB stack, newest first (slot k = the k-th newest push)
    for _ in 0..NVB {
        pb.bank_unwind();
    }
    // init: X3 = 1, X4 = α; X2 = α, X0 = α²; X1 = α², X0 = α³
    {
        let r = pb.row();
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_ONE);
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_E);
    }
    {
        let r = pb.row();
        clr(r, 2);
        x2j(r, 2);
        r.mul_a(0, flag::AM_X4).mul_b(0, flag::BM_E0);
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
    }
    {
        let r = pb.row();
        clr(r, 1);
        r.set(flag::XM2_ADD_PREV + 1);
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_E0);
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_MUL);
    }
    for _ in 0..n_c {
        {
            let r = pb.row();
            for k in k0..4 {
                r.mul_a(k, flag::AM_PT0).mul_b(k, flag::BM_VBK);
                clr(r, k + 4);
                r.xmove(k + 4, flag::XM_ADD_MUL).xmove(k + 4, flag::XM_ADD_ONE).xmove(k + 4, flag::XM_SUB_PT0);
            }
            r.set(flag::VB_SQ4).set(flag::PT_ROT);
        }
        {
            let r = pb.row();
            for k in k0..4 {
                r.mul_a(k, flag::AM_X).mul_b(k, flag::BM_X4);
                clr(r, k);
                r.xmove(k, flag::XM_ADD_MUL);
            }
        }
    }
    // restore PT; the first restore rows also sum the accumulators: X_{k−1} += X_k from the top down to X_{k0}
    let mut restore = n_c;
    let mut rows_used = 0usize;
    for k in (k0 + 1..4).rev() {
        let r = pb.row();
        r.xmove(k - 1, flag::XM_ADD_NEXT);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
        rows_used += 1;
    }
    // move X_{k0} down to X0 (X_{j−1} ← X_j)
    for j in (1..=k0).rev() {
        let r = pb.row();
        clr(r, j - 1);
        r.xmove(j - 1, flag::XM_ADD_NEXT);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
        rows_used += 1;
    }
    let _ = rows_used;
    // W ← W·α^a + X0: lane 1 from E1, then a−1 more products by α (E0), then + X0 (PREV), then E1 ← X1
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_E0);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
    }
    for _ in 1..a {
        let r = pb.row();
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_E0);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_MUL);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
    }
    {
        let r = pb.row();
        r.set(flag::XM2_ADD_PREV + 1);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
    }
    {
        let r = pb.row();
        r.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X);
        if restore > 0 {
            r.set(flag::PT_ROT_UP);
            restore -= 1;
        }
    }
    while restore > 0 {
        pb.row().set(flag::PT_ROT_UP);
        restore -= 1;
    }
}

/// `D ← D − W·f` (E3, E1, E2), six rows.
fn subtract_weight_times_f(pb: &mut ProgramBuilder) {
    {
        let r = pb.row();
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_E); // X1 = W
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_E); // X6 = f
    }
    {
        let r = pb.row();
        clr(r, 5);
        r.xmove(5, flag::XM_ADD_NEXT); // X5 = f
    }
    {
        let r = pb.row();
        r.mul_a(1, flag::AM_X).mul_b(1, flag::BM_X4);
        clr(r, 1);
        r.xmove(1, flag::XM_SUB_MUL); // X1 = −W·f
    }
    {
        let r = pb.row();
        clr(r, 2);
        r.set(flag::XM2_ADD_PREV + 2); // X2 = −W·f
    }
    {
        let r = pb.row();
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E).set(flag::XM2_ADD_PREV + 3); // X3 = D − W·f
    }
    pb.row().emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
}

/// The whole closing identity. Preconditions: the registers as `emit_whir_verify` leaves them (see the module
/// doc), `Y` holding below the rounds' entries the prefix's `[α_init, y_init_{m−1}, …, y_init_0]`, `RS` holding
/// `r_y` newest-first.
pub fn emit_closing_identity(pb: &mut ProgramBuilder, shape: &WhirShape, init: &InitialShape) -> ClosingCheckpoints {
    let mut cp = ClosingCheckpoints::default();
    let n = shape.rounds.len();
    assert!(init.w <= NPT && init.n_vars <= NRS && init.w >= 1);
    let y_entries = shape.rounds.iter().map(|r| 1 + r.ood_samples).sum::<usize>() + 1 + init.ood;
    assert!(y_entries <= NY, "the Y bank holds every α and OOD univariate ({y_entries} > {NY})");
    assert!(shape.final_poly_len <= NF);

    // (a) f(r) → E2
    let mut stages = Vec::new();
    emit_final_value(pb, shape.final_poly_len, &mut stages);
    cp.f_stages = stages;
    cp.f_row = Some(After { row: pb.cur_row() });

    // (b) the round constraints, newest first
    for r in (0..n).rev() {
        let rs = &shape.rounds[r];
        let n_c = rs.num_variables;
        // α_r: E0 ← Y0; W = 0: E1 ← 0
        {
            let row = pb.row();
            row.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_Y0);
            row.emove(1, flag::EM_CLR);
        }
        let groups = rs.num_queries.div_ceil(4);
        let pad = groups * 4 - rs.num_queries;
        for g in 0..groups {
            let k0 = if g == 0 { pad } else { 0 };
            select_group(pb, k0, n_c);
        }
        // the eq part: α into X5, then per OOD point (newest first): E0 ← Y0 (after a rotation), X2 = 1, walk, Horner
        alpha_into_x5(pb);
        for _ in 0..rs.ood_samples {
            {
                let row = pb.row();
                row.set(flag::Y_ROT);
            }
            {
                let row = pb.row();
                row.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_Y0);
                clr(row, 2);
                row.xmove(2, flag::XM_ADD_ONE);
            }
            for _ in 0..n_c {
                eq_step(pb, true, false);
            }
            for _ in 0..n_c {
                pb.row().set(flag::PT_ROT_UP);
            }
            horner_eq(pb);
        }
        // Y[0] → the next constraint's α
        pb.row().set(flag::Y_ROT);
        cp.weights.push((r + 1, After { row: pb.cur_row() }));
        subtract_weight_times_f(pb);
    }

    // (c) the initial constraint: α_init at Y[0]; eq points [the point claims at γ^0.., ood_i after] → Horner from
    // ood_{m−1}; a fixed commitment's column-select weight and γ^{n_cols} are computed first (X7, X3)
    {
        let row = pb.row();
        row.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_Y0);
        row.emove(1, flag::EM_CLR);
    }
    alpha_into_x5(pb);
    let (n_sel, n_cols) = match init.kind {
        InitialKind::Witness => (0, 1),
        InitialKind::Fixed { n_sel, n_cols } => (n_sel, n_cols),
    };
    let n_point = init.w - n_sel;
    assert!(n_point <= init.n_vars, "the point claims bind at most the point's coordinates");
    if n_sel > 0 {
        emit_column_select_weight(pb, n_sel, n_cols);
    }
    for _ in 0..init.ood {
        pb.row().set(flag::Y_ROT);
        {
            let row = pb.row();
            row.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_Y0);
            clr(row, 2);
            row.xmove(2, flag::XM_ADD_ONE);
        }
        for _ in 0..init.w {
            eq_step(pb, true, false);
        }
        for _ in 0..init.w {
            pb.row().set(flag::PT_ROT_UP);
        }
        horner_eq(pb);
    }
    // the pcs point: rotate RS down by rs_depth + n_vars − 1 so RS[0] = the point's coordinate 0, rotate the
    // selector coordinates (PT[0..n_sel)) out, then walk j = 0..n_point with RS rotating up (coordinate j sits at
    // RS[rs_depth + n_vars − 1 − j] and pairs with PT[n_sel + j])
    let down = init.rs_depth + init.n_vars - 1;
    assert!(down + 1 <= NRS && n_point <= down + 1, "the point fits RS below the entries pushed above it");
    for _ in 0..down {
        pb.row().set(flag::RS_ROT);
    }
    for _ in 0..n_sel {
        pb.row().set(flag::PT_ROT);
    }
    {
        let row = pb.row();
        row.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_RS0);
        clr(row, 2);
        row.xmove(2, flag::XM_ADD_ONE);
    }
    for _ in 0..n_point {
        eq_step(pb, false, true);
    }
    for _ in 0..init.w {
        pb.row().set(flag::PT_ROT_UP);
    }
    // RS back: it was rotated down `down` and up n_point
    if down >= n_point {
        for _ in 0..down - n_point {
            pb.row().set(flag::RS_ROT_UP);
        }
    } else {
        for _ in 0..n_point - down {
            pb.row().set(flag::RS_ROT);
        }
    }
    if n_sel > 0 {
        // eq(point)·W_col into X2, γ^{n_cols} into X5 for the Horner step
        {
            let row = pb.row();
            clr(row, 6);
            row.xmove(6, flag::XM_ADD_NEXT); // X6 = W_col (X7)
            clr(row, 4);
            row.set(flag::XM2_ADD_PREV + 4); // X4 = γ^{n_cols} (X3)
        }
        {
            let row = pb.row();
            row.mul_a(2, flag::AM_X).mul_b(2, flag::BM_X4); // X2·X6
            clr(row, 2);
            row.xmove(2, flag::XM_ADD_MUL);
            clr(row, 5);
            row.set(flag::XM2_ADD_PREV + 5); // X5 = X4
        }
    }
    horner_eq(pb);
    cp.weights.push((0, After { row: pb.cur_row() }));
    subtract_weight_times_f(pb);

    // (d) close: X3 ← D; X0 ← 0, X4 ← X3; EXT_EQ
    {
        let row = pb.row();
        clr(row, 3);
        row.xmove(3, flag::XM_ADD_E);
    }
    {
        let row = pb.row();
        clr(row, 0);
        clr(row, 4);
        row.set(flag::XM2_ADD_PREV + 4);
        row.set(flag::EXT_EQ);
    }
    cp.close_row = Some(After { row: pb.cur_row() });
    cp
}

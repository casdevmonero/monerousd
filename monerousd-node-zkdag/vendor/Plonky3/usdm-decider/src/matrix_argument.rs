//! THE MATRIX ARGUMENT (spec §Z3-M) — the native prover and verifier of `m_at = ra·Ã(r_x, r_y) + rb·B̃ + rc·C̃`
//! over the UNIFORM matrices (the row template lifted to `T` steps), the last value `verify_core` needs.
//!
//! The closed form (`UniformR1cs::eval`) writes each matrix as a sum over the template's nonzeros `k`; here the
//! template's sparse representation is FIXED release data laid as BIT COLUMNS over `k ∈ {0,1}^nnz_bits`:
//! `va, vb, vc` (the entry's value in A, B, C — an entry is a `(row, column)` position shared by the three),
//! the `r_bits` bits of its row, the `v_bits` bits of its column (a local/next index, or the public column `c < 32`),
//! the kind one-hot `loc, nxt, pub`, and the transition flag `t` of its row. The summand
//! `S(k) = (ra·va + rb·vb + rc·vc) · Π_b rowterm_b · Π_{b<5} colterm_b · [ loc·Π_{b≥5} colterm_b·top·(e − t·l_row·l_col)
//! + nxt·Π_{b≥5} colterm_b·top·sh + pub·p_hi·(1 − t·l_row) ]` with `rowterm_b = bit·(2·r_b − 1) + (1 − r_b)` (so
//! `Π = eq(r_lo, row)`) is a polynomial of degree `r_bits + v_bits + 3` per variable in the columns' multilinear
//! extensions, and `Σ_k S(k) = m_at`. ONE sumcheck of that degree over `nnz_bits` variables proves the sum; its
//! final claim is `S` at the columns' openings at `ρ`, which the fixed commitment's WHIR opening supplies (M3 —
//! here the verifier evaluates the release columns directly). No `E_row`/`E_col` witness, no lookups.
//!
//! ROOT-LAYER: `FixedColumns::of` is read off the template; the per-proof scalars `e, l_row, l_col, sh, top, p_hi`
//! are the closed form's own factors. MEASURED: pin `the_matrix_argument_reproduces_the_closed_form_and_refuses`.
//! MUST-STAY-GREEN: the uniform-R1CS pins.

use crate::hiding_decider::{Chl, Ea4, Fa4};
use crate::spartan_ccs::{coeffs_from_evals, fold_at, horner, mle_eval};
use crate::uniform_r1cs::{eq_bits, eq_points, shift_closed_form, Col, UniformR1cs};
use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Public columns (the constant and the io words) live below this power of two, so a public entry's column bits are
/// its low six and `eq(r_y, c)` factors as `Π_{b<6} colterm_b · Π_{b≥6} (1 − r_{y,b})`. Six since M5 (2026-09-28): the
/// certificate's io is 39 words (`universal_row::IO_LEN`, the 8-aligned four-block layout), so `[1, io…]` is 40 > 32
/// words; `spartan_ccs::STATEMENT_PUB_WORDS` is the same power of two.
pub const PUB_COL_BITS: usize = 6;

/// The template's sparse representation as fixed columns over `k ∈ {0,1}^nnz_bits` (release data).
#[derive(Clone, Debug)]
pub struct FixedColumns {
    pub r_bits: usize,
    pub v_bits: usize,
    pub t_bits: usize,
    pub nnz_bits: usize,
    /// Entries in use (`≤ 2^nnz_bits`); the rest of every column is zero.
    pub entries: usize,
    /// `[va, vb, vc, row bits (r_bits), column bits (v_bits), loc, nxt, pub, t]`.
    pub cols: Vec<Vec<Fa4>>,
}

impl FixedColumns {
    pub fn n_cols(&self) -> usize {
        3 + self.r_bits + self.v_bits + 4
    }
    pub(crate) fn row_bit(&self, b: usize) -> usize {
        3 + b
    }
    pub(crate) fn col_bit(&self, b: usize) -> usize {
        3 + self.r_bits + b
    }
    pub(crate) fn loc(&self) -> usize {
        3 + self.r_bits + self.v_bits
    }
    pub(crate) fn nxt(&self) -> usize {
        self.loc() + 1
    }
    pub(crate) fn pubk(&self) -> usize {
        self.loc() + 2
    }
    pub(crate) fn t(&self) -> usize {
        self.loc() + 3
    }
    /// The degree of the summand per variable: value (1) + row bits + column bits + kind (1) + transition (1).
    pub fn degree(&self) -> usize {
        self.r_bits + self.v_bits + 3
    }

    /// Read the columns off a uniform instance (no boundary entries). Entries are the `(row, column)` positions of
    /// the three matrices merged, sorted by `(row, kind, index)`; public columns must be below `2^PUB_COL_BITS`.
    pub fn of(u: &UniformR1cs) -> Self {
        assert!(u.a.boundary.is_empty() && u.b.boundary.is_empty() && u.c.boundary.is_empty(), "a uniform instance without boundary entries");
        // key: (row, kind 0 local / 1 next / 2 public, index)
        let mut map: BTreeMap<(usize, u8, usize), [Fa4; 3]> = BTreeMap::new();
        for (mi, m) in [&u.a, &u.b, &u.c].into_iter().enumerate() {
            for &(row, col, val) in &m.template {
                let key = match col {
                    Col::Local(j) => (row, 0u8, j),
                    Col::Next(j) => (row, 1u8, j),
                    Col::Public(c) => {
                        assert!(c < 1 << PUB_COL_BITS, "a public column below 2^{PUB_COL_BITS}, got {c}");
                        (row, 2u8, c)
                    }
                };
                map.entry(key).or_insert([Fa4::ZERO; 3])[mi] += val;
            }
        }
        let entries = map.len();
        assert!(entries >= 2, "a template with entries");
        let nnz_bits = (usize::BITS - (entries - 1).leading_zeros()) as usize;
        let n = 1usize << nnz_bits;
        let trans = u.transition_rows();
        let (r_bits, v_bits, t_bits) = (u.r_bits, u.v_bits, u.t_bits);
        let n_cols = 3 + r_bits + v_bits + 4;
        let mut cols = vec![vec![Fa4::ZERO; n]; n_cols];
        let this = FixedColumns { r_bits, v_bits, t_bits, nnz_bits, entries, cols: Vec::new() };
        for (k, ((row, kind, idx), vals)) in map.iter().enumerate() {
            cols[0][k] = vals[0];
            cols[1][k] = vals[1];
            cols[2][k] = vals[2];
            assert!(*row < 1 << r_bits && *idx < 1 << v_bits);
            for b in 0..r_bits {
                cols[this.row_bit(b)][k] = Fa4::from_u64(((row >> b) & 1) as u64);
            }
            for b in 0..v_bits {
                cols[this.col_bit(b)][k] = Fa4::from_u64(((idx >> b) & 1) as u64);
            }
            let kcol = match kind {
                0 => this.loc(),
                1 => this.nxt(),
                _ => this.pubk(),
            };
            cols[kcol][k] = Fa4::ONE;
            cols[this.t()][k] = Fa4::from_bool(trans[*row]);
        }
        FixedColumns { cols, ..this }
    }
}

/// The evaluation point: the Spartan core's `ra, rb, rc`, `r_x` (`m_vars = r_bits + t_bits`) and `r_y`
/// (`n_vars = 1 + t_bits + v_bits`).
#[derive(Clone, Debug)]
pub struct MatrixPoint {
    pub ra: Ea4,
    pub rb: Ea4,
    pub rc: Ea4,
    pub r_x: Vec<Ea4>,
    pub r_y: Vec<Ea4>,
}

/// The per-proof scalars of the closed form, computed once from the point.
#[derive(Clone, Debug)]
pub struct Scalars {
    pub r_lo: Vec<Ea4>,
    pub s_lo: Vec<Ea4>,
    pub e: Ea4,
    pub l_row: Ea4,
    pub l_col: Ea4,
    pub sh: Ea4,
    pub top: Ea4,
    pub p_hi: Ea4,
}

pub fn scalars(f: &FixedColumns, pt: &MatrixPoint) -> Scalars {
    let n_vars = 1 + f.t_bits + f.v_bits;
    assert_eq!(pt.r_x.len(), f.r_bits + f.t_bits, "row point arity");
    assert_eq!(pt.r_y.len(), n_vars, "column point arity");
    let r_hi = &pt.r_x[f.r_bits..];
    let s_hi = &pt.r_y[f.v_bits..f.v_bits + f.t_bits];
    let last = (1usize << f.t_bits) - 1;
    Scalars {
        r_lo: pt.r_x[..f.r_bits].to_vec(),
        s_lo: pt.r_y[..f.v_bits].to_vec(),
        e: eq_points(r_hi, s_hi),
        l_row: eq_bits(r_hi, last),
        l_col: eq_bits(s_hi, last),
        sh: shift_closed_form(r_hi, s_hi),
        top: pt.r_y[n_vars - 1],
        p_hi: pt.r_y[PUB_COL_BITS..].iter().fold(Ea4::ONE, |acc, &r| acc * (Ea4::ONE - r)),
    }
}

/// `S` at one point of the cube (or at the columns' multilinear extensions): `vals[i]` is column `i`'s value.
pub fn summand(f: &FixedColumns, vals: &[Ea4], pt: &MatrixPoint, sc: &Scalars) -> Ea4 {
    let v = pt.ra * vals[0] + pt.rb * vals[1] + pt.rc * vals[2];
    let term = |bit: Ea4, r: Ea4| bit * (r.double() - Ea4::ONE) + (Ea4::ONE - r);
    let e_row = (0..f.r_bits).fold(Ea4::ONE, |acc, b| acc * term(vals[f.row_bit(b)], sc.r_lo[b]));
    let e_col_lo = (0..PUB_COL_BITS).fold(Ea4::ONE, |acc, b| acc * term(vals[f.col_bit(b)], sc.s_lo[b]));
    let e_col_hi = (PUB_COL_BITS..f.v_bits).fold(Ea4::ONE, |acc, b| acc * term(vals[f.col_bit(b)], sc.s_lo[b]));
    let t = vals[f.t()];
    let f_l = sc.e - t * sc.l_row * sc.l_col;
    let f_p = Ea4::ONE - t * sc.l_row;
    let inner = vals[f.loc()] * e_col_hi * sc.top * f_l + vals[f.nxt()] * e_col_hi * sc.top * sc.sh + vals[f.pubk()] * sc.p_hi * f_p;
    v * e_row * e_col_lo * inner
}

/// The proof: `m_at` (the claimed sum, absorbed first), per round the `degree + 1` monomial coefficients, and the
/// columns' openings at the final point `ρ` — what the fixed commitment's WHIR opening proves (M3) and what a
/// verifier that holds the release columns also recomputes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixProof {
    pub m_at: Ea4,
    pub rounds: Vec<Vec<Ea4>>,
    pub openings: Vec<Ea4>,
}

fn absorb(ch: &mut Chl, e: Ea4) {
    ch.observe_algebra_element(e);
}
/// `m_at` padded to one duplexing (four zero words after its four): every round's thirty coefficients then start
/// 8-aligned in the challenger's buffer, so the row program absorbs them as fifteen whole pairs (`F_PUSH2`). The
/// zeros are observed by both sides — part of the transcript, never skipped.
fn absorb_claim(ch: &mut Chl, m_at: Ea4) {
    absorb(ch, m_at);
    for _ in 0..4 {
        p3_challenger::CanObserve::observe(ch, Fa4::ZERO);
    }
}
fn draw(ch: &mut Chl) -> Ea4 {
    ch.sample_algebra_element()
}
/// A round's coefficients, padded with ONE zero when their count is odd, so the row program absorbs every round as
/// whole pairs (`F_PUSH2` on 8-aligned duplexings). The pad is observed by both sides — part of the transcript,
/// never skipped — and folds as a zero top coefficient in the row's Horner. `degree() + 1` is odd exactly when
/// `r_bits + v_bits` is even (the template's 14 + 13 → 31 coefficients, 2026-09-28).
fn absorb_round(ch: &mut Chl, c: &[Ea4]) {
    for &e in c {
        absorb(ch, e);
    }
    if c.len() % 2 == 1 {
        absorb(ch, Ea4::ZERO);
    }
}
/// The coefficient count the row program absorbs per round: `degree() + 1` rounded up to even.
pub fn padded_round_len(f: &FixedColumns) -> usize {
    let n = f.degree() + 1;
    n + n % 2
}

/// Prove `m_at = Σ_k S(k)` on the caller's transcript. Returns the proof (with `m_at`) and the final point `ρ`.
pub fn prove(f: &FixedColumns, pt: &MatrixPoint, ch: &mut Chl) -> (MatrixProof, Vec<Ea4>) {
    let sc = scalars(f, pt);
    let n = 1usize << f.nnz_bits;
    let mut tables: Vec<Vec<Ea4>> = f.cols.iter().map(|c| c.iter().map(|&x| Ea4::from(x)).collect()).collect();
    let mut vals = vec![Ea4::ZERO; f.n_cols()];
    let mut m_at = Ea4::ZERO;
    for k in 0..n {
        for (i, t) in tables.iter().enumerate() {
            vals[i] = t[k];
        }
        m_at += summand(f, &vals, pt, &sc);
    }
    absorb_claim(ch, m_at);
    let deg = f.degree();
    let mut rounds = Vec::with_capacity(f.nnz_bits);
    let mut rho = Vec::with_capacity(f.nnz_bits);
    for _ in 0..f.nnz_bits {
        let half = tables[0].len() / 2;
        let mut h = vec![Ea4::ZERO; deg + 1];
        for (t, ht) in h.iter_mut().enumerate() {
            let te = Ea4::from_u64(t as u64);
            for i in 0..half {
                for (ci, col) in tables.iter().enumerate() {
                    vals[ci] = col[2 * i] + te * (col[2 * i + 1] - col[2 * i]);
                }
                *ht += summand(f, &vals, pt, &sc);
            }
        }
        let c = coeffs_from_evals(&h);
        absorb_round(ch, &c);
        let r = draw(ch);
        for t in tables.iter_mut() {
            *t = fold_at(t, r);
        }
        rounds.push(c);
        rho.push(r);
    }
    // after nnz_bits folds every table holds its multilinear extension at ρ
    let openings: Vec<Ea4> = tables.iter().map(|t| t[0]).collect();
    (MatrixProof { m_at, rounds, openings }, rho)
}

/// Verify on the caller's transcript against the release columns (their openings at `ρ` evaluated directly here;
/// the certificate's row program takes them from the fixed commitment's WHIR opening). Returns `m_at` and `ρ`.
pub fn verify(f: &FixedColumns, pt: &MatrixPoint, ch: &mut Chl, proof: &MatrixProof) -> Option<(Ea4, Vec<Ea4>)> {
    verify_traced(f, pt, ch, proof).map(|(m, rho, _)| (m, rho))
}

/// [`verify`] with the claim after every round (the row program's pin reads them).
pub fn verify_traced(f: &FixedColumns, pt: &MatrixPoint, ch: &mut Chl, proof: &MatrixProof) -> Option<(Ea4, Vec<Ea4>, Vec<Ea4>)> {
    let sc = scalars(f, pt);
    let deg = f.degree();
    if proof.rounds.len() != f.nnz_bits || proof.rounds.iter().any(|c| c.len() != deg + 1) {
        return None;
    }
    absorb_claim(ch, proof.m_at);
    let mut claim = proof.m_at;
    let mut rho = Vec::with_capacity(f.nnz_bits);
    let mut claims = Vec::with_capacity(f.nnz_bits);
    for c in &proof.rounds {
        // h(0) + h(1) = c_0 + Σ_k c_k
        if c[0] + c.iter().copied().sum::<Ea4>() != claim {
            return None;
        }
        absorb_round(ch, c);
        let r = draw(ch);
        claim = horner(c, r);
        rho.push(r);
        claims.push(claim);
    }
    // the openings the proof carries must be the release columns at ρ (a verifier without the columns — the row
    // program — takes them from the fixed commitment's WHIR opening instead) and must close the sumcheck
    if proof.openings.len() != f.n_cols() || f.cols.iter().zip(&proof.openings).any(|(col, &o)| mle_eval(col, &rho) != o) {
        return None;
    }
    (summand(f, &proof.openings, pt, &sc) == claim).then_some((proof.m_at, rho, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiding_decider::Perm16;
    use crate::universal_row::{uniform_instance, IO_LEN};
    use rand::SeedableRng;

    fn fresh(seed: u64) -> Chl {
        Chl::new(Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed)))
    }

    /// ⭐⭐ THE PIN: on the REAL row template (T = 8), the argument's `m_at` equals `ra·Ã + rb·B̃ + rc·C̃` from the
    /// closed form at a random point, the verifier accepts the honest proof, and it REFUSES a flipped `m_at`, a
    /// flipped round coefficient and a verifier whose release columns differ by one bit.
    #[test]
    fn the_matrix_argument_reproduces_the_closed_form_and_refuses() {
        let p = crate::universal_row::tests::params();
        let u = uniform_instance(&p, IO_LEN, 3);
        let f = FixedColumns::of(&u);
        eprintln!(
            "[matrix] template: {} entries over 2^{} (r_bits {}, v_bits {}, t_bits {}), {} columns, summand degree {}",
            f.entries,
            f.nnz_bits,
            f.r_bits,
            f.v_bits,
            f.t_bits,
            f.n_cols(),
            f.degree()
        );
        let mut rng_ch = fresh(0x4D41_5452_4958);
        let mut d = || rng_ch.sample_algebra_element::<Ea4>();
        let pt = MatrixPoint { ra: d(), rb: d(), rc: d(), r_x: (0..u.m_vars()).map(|_| d()).collect(), r_y: (0..u.n_vars()).map(|_| d()).collect() };
        let want = pt.ra * u.eval(&u.a, &pt.r_x, &pt.r_y) + pt.rb * u.eval(&u.b, &pt.r_x, &pt.r_y) + pt.rc * u.eval(&u.c, &pt.r_x, &pt.r_y);
        let t0 = std::time::Instant::now();
        let (proof, rho_p) = prove(&f, &pt, &mut fresh(7));
        let prove_ms = t0.elapsed().as_millis();
        assert_eq!(proof.m_at, want, "the argument's sum is the closed form's matrix evaluation");
        let t1 = std::time::Instant::now();
        let got = verify(&f, &pt, &mut fresh(7), &proof).expect("the honest proof verifies");
        let verify_ms = t1.elapsed().as_millis();
        assert_eq!(got.0, want);
        assert_eq!(got.1, rho_p, "the verifier's ρ is the prover's");
        // refusals
        let mut bad = proof.clone();
        bad.m_at += Ea4::ONE;
        assert!(verify(&f, &pt, &mut fresh(7), &bad).is_none(), "a moved m_at is refused by the first round's sum check");
        let mut bad = proof.clone();
        bad.rounds[5][3] += Ea4::ONE;
        assert!(verify(&f, &pt, &mut fresh(7), &bad).is_none(), "a flipped round coefficient is refused");
        let mut f_bad = f.clone();
        let c = f_bad.col_bit(2);
        f_bad.cols[c][17] = Fa4::ONE - f_bad.cols[c][17];
        assert!(verify(&f_bad, &pt, &mut fresh(7), &proof).is_none(), "release columns that differ by one bit refuse the proof");
        eprintln!(
            "[matrix] GREEN: m_at equals the closed form; {} rounds of {} coefficients ({} words), prove {prove_ms} ms, verify {verify_ms} ms; moved m_at / flipped coefficient / one wrong release bit refused",
            proof.rounds.len(),
            f.degree() + 1,
            proof.rounds.len() * (f.degree() + 1) * 4
        );
    }

    /// ⭐⭐⭐ M3: a committed Spartan proof over a UNIFORM instance (a real emulated 4-step trace of the row) carries
    /// the matrix argument and the fixed commitment's WHIR opening of the column values; the native verifier accepts
    /// it against the release root and REFUSES a flipped fixed opening, a flipped argument coefficient, the root of
    /// release columns that differ by one bit, and a truncated proof.
    #[test]
    fn a_uniform_committed_proof_carries_the_matrix_argument_and_the_fixed_opening() {
        use crate::committed_air::CarrierParams;
        use crate::spartan_ccs::{fixed_commitment_root, prove_committed_uniform, verify_committed_uniform, SpartanCommittedProof};
        use crate::universal_row::{emulate, flag, RowFlags, IO_LEN, NREG, NSTREAM};
        use crate::verifier_program::ProgramBuilder;
        let p = crate::universal_row::tests::params();
        let t_bits = 2usize;
        let u = uniform_instance(&p, IO_LEN, t_bits);
        // a real trace: eight observed words and one sample, its challenge pushed into PT, then idle rows
        let mut pb = ProgramBuilder::new();
        pb.observe_slice(&(0..8).map(|i| Fa4::from_u64(300 + i)).collect::<Vec<_>>());
        pb.sample_ext();
        pb.on_next(&[flag::PT_PUSH]);
        let (mut program, mut stream) = pb.finish();
        while program.len() < 1 << t_bits {
            program.push(RowFlags::default());
            stream.push([Fa4::ZERO; NSTREAM]);
        }
        assert_eq!(program.len(), 1 << t_bits, "the program fits T = 4");
        let io = vec![Fa4::ZERO; IO_LEN];
        let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
        let params = CarrierParams::legacy(1, 0);
        let f = FixedColumns::of(&u);
        let t0 = std::time::Instant::now();
        let root = fixed_commitment_root(&f, params);
        let root_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        let bytes = prove_committed_uniform(&u, &io, &tr.w, params, params).expect("the uniform committed proof proves");
        let prove_ms = t1.elapsed().as_millis();
        let t2 = std::time::Instant::now();
        assert!(verify_committed_uniform(&u, &io, &bytes, params, params, &root), "the native verifier accepts against the release root");
        let verify_ms = t2.elapsed().as_millis();
        let decoded: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let mp = decoded.matrix.as_ref().expect("a matrix argument");
        eprintln!(
            "[matrix] M3: {} bytes ({} argument rounds, {} openings), fixed root {root_ms} ms, prove {prove_ms} ms, verify {verify_ms} ms",
            bytes.len(),
            mp.rounds.len(),
            mp.openings.len()
        );
        // refusals
        let reencode = |q: SpartanCommittedProof| -> Vec<u8> { postcard::to_allocvec(&q).expect("encodes") };
        let mut q: SpartanCommittedProof = postcard::from_bytes(&bytes).unwrap();
        q.matrix.as_mut().unwrap().openings[4] += Ea4::ONE;
        assert!(!verify_committed_uniform(&u, &io, &reencode(q), params, params, &root), "a flipped fixed opening is refused");
        let mut q: SpartanCommittedProof = postcard::from_bytes(&bytes).unwrap();
        q.matrix.as_mut().unwrap().rounds[2][1] += Ea4::ONE;
        assert!(!verify_committed_uniform(&u, &io, &reencode(q), params, params, &root), "a flipped argument coefficient is refused");
        let mut f_bad = f.clone();
        let c = f_bad.col_bit(1);
        f_bad.cols[c][3] = Fa4::ONE - f_bad.cols[c][3];
        let wrong_root = fixed_commitment_root(&f_bad, params);
        assert_ne!(format!("{wrong_root:?}"), format!("{root:?}"), "one flipped release bit moves the root");
        assert!(!verify_committed_uniform(&u, &io, &bytes, params, params, &wrong_root), "the root of release columns that differ by one bit refuses the proof");
        assert!(!verify_committed_uniform(&u, &io, &bytes[..bytes.len() - 7], params, params, &root), "a truncated proof is refused");
        eprintln!("[matrix] M3 GREEN: the uniform committed proof carries the matrix argument + the fixed opening; flipped opening / flipped coefficient / wrong release root / truncation refused");
    }
}

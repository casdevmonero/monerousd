// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ THE O(1)-OPENINGS ARGUMENT — milestones 1 and 2 of the recursion that replaces `ivc_one_table`.
//!
//! See `docs/O1-OPENINGS-RECURSION-SPEC.md`. A same-shape recursive step over a W-column AIR has no fixpoint
//! because its verifier reads W openings; a Spartan-style argument over R1CS reads ONE witness evaluation, so a
//! step verifying a step of its own circuit is constant-size. Borrowed shape: Spartan (Setty 2019) — two
//! sumchecks — with the decider's own Poseidon2 Fiat–Shamir (`Chl`) and the hiding WHIR PCS already used by every
//! committed carrier (`committed_air`) for the single witness opening.
//!
//! ## The relation
//! `(A·z) ∘ (B·z) = C·z` over KoalaBear, `z = [1, io…, 0… | w…, 0…]`: 2^n entries, the top variable selects the
//! witness half, so the verifier evaluates the public half's multilinear itself and needs exactly one value
//! `w̃(r_y)` — read from the WHIR opening of the committed witness half.
//!
//! ## The argument (M2 order — the commitment comes FIRST, every challenge after it)
//! 0. The statement (shape, publics) and the witness COMMITMENT are absorbed; then the commitment's
//!    out-of-domain answers, exactly as `committed_air` does it.
//! 1. τ ← transcript. Sumcheck #1 (degree 3) over constraint index x: Σ_x eq(τ,x)·(Ã_z(x)·B̃_z(x) − C̃_z(x)) = 0,
//!    ending in prover-sent `a = Ã_z(r_x)`, `b`, `c` checked against the folded claim `eq(τ,r_x)·(a·b − c)`.
//! 2. r_A, r_B, r_C ← transcript. Sumcheck #2 (degree 2) over variable index y of
//!    `(r_A Ã(r_x,·) + r_B B̃(r_x,·) + r_C C̃(r_x,·))(y) · z̃(y)` with claim `r_A a + r_B b + r_C c`, ending in the
//!    verifier evaluating the matrix multilinears at `(r_x, r_y)` natively (closed-form for uniform circuits in
//!    M3) times `z̃(r_y) = (1 − r_y[n−1])·ĩo(r_y[..n−1]) + r_y[n−1]·w̃(r_y[..n−1])`.
//! 3. The claim `w̃(r_y[..n−1]) = w_eval` is registered against the commitment and the WHIR opening is verified.
//!
//! Why the order is the soundness: with the commitment absorbed before τ, a prover's `a,b,c` must be the true
//! `Ã_z(r_x)…` of the COMMITTED z (Schwartz–Zippel over r_A,r_B,r_C drawn after `a,b,c`), so the outer sumcheck's
//! zero claim forces the committed z to satisfy every constraint (over τ drawn after the commitment). Without the
//! commitment (the M1 shape, kept below as the calibration of exactly this) a prover chooses the last message
//! `w_eval` to satisfy the closing identity and proves anything.
//!
//! Variable order is LSB-first throughout this module: bit k of an index is variable k; the PCS layout's own
//! order is handled at the one point where the claim is registered (`pcs_point`).
//!
//! ROOT-LAYER: this module IS the producer of the new certificate's proof object — the argument itself, not a
//! reader of an existing one; nothing upstream is patched.
//! MEASURED: milestones 1 and 2 are scored by their own pins below (honest verifies; wrong public, unsatisfying
//! witness, a cheating prover, garbage, truncation and every flipped byte refused; the M1 forgery accepted by the
//! unbound core and REFUSED by the committed verifier); the numbers print in `an_honest_squaring_chain_…`.
//! MUST-STAY-GREEN: every existing decider path — nothing here is called by production yet (M5 wires the door).

use crate::committed_air::{pcs_with, CarrierParams, COMMITTED_FOLDING};
use crate::matrix_argument::{FixedColumns, MatrixPoint, MatrixProof};
use crate::uniform_r1cs::{Col, UniformMatrix, UniformR1cs};
use crate::hiding_decider::{Chl, Ea4, Fa4, Mmcs16, Perm16};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Mmcs;
use p3_field::{Algebra, Field, PrimeCharacteristicRing};
use rayon::prelude::*;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier as LayoutVerifier};
use p3_sumcheck::table::TableShape;
use p3_whir::pcs::proof::WhirProof;
use p3_whir::pcs::verifier::WhirVerifier;
use rand::{rngs::SmallRng, SeedableRng};
use serde::{Deserialize, Serialize};

/// A sparse matrix: `(row, col, value)` triples over a 2^m × 2^n grid.
pub type Sparse = Vec<(usize, usize, Fa4)>;
type Commitment = <Mmcs16 as Mmcs<Fa4>>::Commitment;

/// The least log-height of the committed witness half. The WHIR prefix prover packs the polynomial into SIMD
/// lanes and folds `COMMITTED_FOLDING` variables per round, so a polynomial below `folding + log2(packing width)`
/// variables cannot be committed at all (MEASURED: a 2^4 witness half panics inside `split_eq`). A circuit
/// smaller than 2^8 witness values pads up to it — the recursion's real circuits are 2^18 and beyond.
pub const MIN_W_VARS: usize = COMMITTED_FOLDING + 4;

/// One R1CS instance's PUBLIC part: the three matrices and the shape. `io_len` public inputs sit at `z[1..=io_len]`.
#[derive(Clone)]
pub struct R1cs {
    /// log2 of the number of constraints (rows).
    pub m_vars: usize,
    /// log2 of the length of `z` (columns). The top variable selects the witness half.
    pub n_vars: usize,
    pub io_len: usize,
    pub a: Sparse,
    pub b: Sparse,
    pub c: Sparse,
}

impl R1cs {
    pub fn rows(&self) -> usize {
        1 << self.m_vars
    }
    pub fn cols(&self) -> usize {
        1 << self.n_vars
    }
    /// The witness half starts here.
    pub fn w_off(&self) -> usize {
        self.cols() / 2
    }
    /// log2 of the witness half's length — the committed multilinear's variable count.
    pub fn w_vars(&self) -> usize {
        self.n_vars - 1
    }
    /// Lay `z` from public inputs and the witness: `[1, io…, 0… | w…, 0…]`. `None` when either does not fit.
    pub fn lay_z(&self, io: &[Fa4], w: &[Fa4]) -> Option<Vec<Fa4>> {
        if io.len() != self.io_len || 1 + io.len() > self.w_off() || w.len() > self.w_off() {
            return None;
        }
        let mut z = vec![Fa4::ZERO; self.cols()];
        z[0] = Fa4::ONE;
        z[1..=io.len()].copy_from_slice(io);
        z[self.w_off()..self.w_off() + w.len()].copy_from_slice(w);
        Some(z)
    }
    /// Native satisfaction check (a test oracle, and the prover's own refusal).
    /// The rows `z` does not satisfy (a diagnostic for a circuit's own pins: which gadget broke).
    pub fn unsatisfied_rows(&self, z: &[Fa4]) -> Vec<usize> {
        let az = mat_vec(&self.a, z, self.rows());
        let bz = mat_vec(&self.b, z, self.rows());
        let cz = mat_vec(&self.c, z, self.rows());
        (0..self.rows()).filter(|i| az[*i] * bz[*i] != cz[*i]).collect()
    }
    pub fn is_satisfied(&self, z: &[Fa4]) -> bool {
        let az = mat_vec(&self.a, z, self.rows());
        let bz = mat_vec(&self.b, z, self.rows());
        let cz = mat_vec(&self.c, z, self.rows());
        (0..self.rows()).all(|i| az[i] * bz[i] == cz[i])
    }
    fn shape_ok(&self) -> bool {
        self.m_vars >= 1
            && self.n_vars >= 2
            && self.m_vars <= 30
            && self.n_vars <= 30
            && 1 + self.io_len <= self.w_off()
            && [&self.a, &self.b, &self.c]
                .iter()
                .all(|m| m.iter().all(|&(r, c, _)| r < self.rows() && c < self.cols()))
    }
    /// The committed argument needs the witness half to be at least [`MIN_W_VARS`] tall.
    fn committable(&self) -> bool {
        self.shape_ok() && self.w_vars() >= MIN_W_VARS
    }
}

fn mat_vec(m: &Sparse, z: &[Fa4], rows: usize) -> Vec<Fa4> {
    let mut out = vec![Fa4::ZERO; rows];
    for &(r, c, v) in m {
        out[r] += v * z[c];
    }
    out
}

/// `eq(τ, x)` for every x ∈ {0,1}^k as a table (LSB-first).
pub(crate) fn eq_table(tau: &[Ea4]) -> Vec<Ea4> {
    // Variable k must land on BIT k of the index (LSB-first, the order `fold_at` binds), so each new variable
    // is appended as the HIGHEST bit so far: the table doubles by concatenation, never by interleaving.
    let mut t = vec![Ea4::ONE];
    for &tk in tau {
        let lo: Vec<Ea4> = t.iter().map(|&v| v * (Ea4::ONE - tk)).collect(); // new variable = 0
        let hi: Vec<Ea4> = t.iter().map(|&v| v * tk).collect(); // new variable = 1
        t = lo.into_iter().chain(hi).collect();
    }
    t
}

/// `eq(a, b)` for two points.
pub(crate) fn eq_point(a: &[Ea4], b: &[Ea4]) -> Ea4 {
    a.iter().zip(b).fold(Ea4::ONE, |acc, (&x, &y)| acc * (x * y + (Ea4::ONE - x) * (Ea4::ONE - y)))
}

/// Multilinear extension of a base-field table evaluated at an extension point (LSB-first).
pub fn mle_eval(v: &[Fa4], r: &[Ea4]) -> Ea4 {
    let mut t: Vec<Ea4> = v.iter().map(|&x| Ea4::from(x)).collect();
    for &rk in r {
        t = fold_at(&t, rk);
    }
    t[0]
}

/// Bind the lowest variable of a table to `r`: `t'[i] = t[2i] + r·(t[2i+1] − t[2i])`.
pub(crate) fn fold_at(t: &[Ea4], r: Ea4) -> Vec<Ea4> {
    (0..t.len() / 2).map(|i| t[2 * i] + r * (t[2 * i + 1] - t[2 * i])).collect()
}

/// The sparse matrix's multilinear at `(r_x, r_y)`: Σ_{(x,y,v)} v·eq(r_x,x)·eq(r_y,y). Native here; closed-form
/// for uniform circuits in M3.
pub(crate) fn sparse_mle(m: &Sparse, eq_x: &[Ea4], eq_y: &[Ea4]) -> Ea4 {
    m.iter().fold(Ea4::ZERO, |acc, &(r, c, v)| acc + eq_x[r] * eq_y[c] * Ea4::from(v))
}

pub(crate) fn transcript(r1cs: &R1cs, io: &[Fa4]) -> Chl {
    let mut rng = SmallRng::seed_from_u64(crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31);
    let perm = Perm16::new_from_rng_128(&mut rng);
    let mut ch = Chl::new(perm);
    // The statement first, as ONE aligned duplexing: the hash of `[m_vars, n_vars, io_len] ‖ io` — a divergent shape
    // or public diverges every challenge. The recursive verifier (DESIGN Z, 2026-09-28) absorbs the same eight words
    // from its stream on a row pinned to its public `statement_hash` (`IOCHK_1`) and leaf-hashes the statement words
    // against it (`ROOT_CHECK`), so the inner statement is bound to the certificate's statement by one hash both
    // sides compute; absorbing the words raw would leave the transcript copy unbound from the hashed copy.
    for f in statement_hash(r1cs, io) {
        ch.observe(f);
    }
    ch
}
/// `SpongeHash(statement_word_list)` with the committed-PCS (Merkle) permutation — the words the universal row's
/// leaf rows hash. RATE_WORDS words: one duplexing when absorbed.
pub fn statement_hash(r1cs: &R1cs, io: &[Fa4]) -> [Fa4; RATE_WORDS] {
    use p3_symmetric::CryptographicHasher;
    let mut rng = SmallRng::seed_from_u64(crate::committed_air::COMMITTED_AIR_SEED);
    let perm = Perm16::new_from_rng_128(&mut rng);
    let hasher = crate::hiding_decider::SpongeHash::new(perm);
    hasher.hash_iter(statement_word_list(r1cs.m_vars, r1cs.n_vars, r1cs.io_len, io))
}
/// The public half of `z` the verifier evaluates: `[1, io_0, …, io_{len−1}, 0, …]` (`z̃(r_y)`'s public part is its
/// multilinear extension), padded to at least [`STATEMENT_PUB_WORDS`] words — the certificate's inner statement
/// (`io_len` = 39, `universal_row::IO_LEN`) pads to exactly this many, which its z̃ rows fold as six variables
/// (`matrix_argument::PUB_COL_BITS`; the two constants are ONE power of two).
pub const STATEMENT_PUB_WORDS: usize = 1 << crate::matrix_argument::PUB_COL_BITS;
/// The public-half word count for `io_len`: the power of two ≥ `io_len + 1`, at least `STATEMENT_PUB_WORDS`.
pub fn statement_pub_words(io_len: usize) -> usize {
    (io_len + 1).next_power_of_two().max(STATEMENT_PUB_WORDS)
}
/// The statement words both sides hash: a header block `[m_vars, n_vars, io_len, 0, 0, 0, 0, 0]` (one RATE), then the
/// public half of `z` padded to `statement_pub_words(io_len)` — so the certificate's leaf rows that re-hash the
/// statement carry the public half eight consecutive entries per row and fold `z̃`'s public part on the same rows
/// (`fixed_program::emit_zat_close`).
pub fn statement_word_list(m_vars: usize, n_vars: usize, io_len: usize, io: &[Fa4]) -> Vec<Fa4> {
    assert_eq!(io.len(), io_len);
    let mut words = vec![Fa4::from_u64(m_vars as u64), Fa4::from_u64(n_vars as u64), Fa4::from_u64(io_len as u64)];
    words.resize(RATE_WORDS, Fa4::ZERO);
    words.push(Fa4::ONE);
    words.extend_from_slice(io);
    words.resize(RATE_WORDS + statement_pub_words(io_len), Fa4::ZERO);
    words
}
/// The challenger's duplexing rate in base words (`DuplexChallenger<_, _, 16, 8>`).
const RATE_WORDS: usize = 8;

fn absorb(ch: &mut Chl, e: Ea4) {
    ch.observe_algebra_element(e);
}
/// The claims block — `w_eval`, then the fixed table's `n_cols` openings when one rides — is absorbed as an EVEN
/// count of extension elements: an odd count is followed by ONE zero. ROOT LAYER: the certificate's duplexing rows
/// absorb two extension elements each and `F_PUSH2` pushes the pair into `F`; a half-full final row would push a
/// stale state lane beside the last opening. A constant absorb moves no soundness (both sides absorb it, the prover
/// chooses nothing) and costs one row. MEASURED 2026-09-28: the R = 2^14 template's 34 columns made the block 35.
pub(crate) const fn claims_pad(n_claims: usize) -> usize {
    n_claims % 2
}
/// The native side of [`claims_pad`]: prover, verifier and every transcript replay call it right after the claims.
pub(crate) fn absorb_claims_pad(ch: &mut Chl, n_claims: usize) {
    for _ in 0..claims_pad(n_claims) {
        absorb(ch, Ea4::ZERO);
    }
}
fn draw(ch: &mut Chl) -> Ea4 {
    ch.sample_algebra_element()
}

/// The sumcheck messages. On its own (M1) this is an argument whose one witness read `w_eval` is unbound; inside
/// [`SpartanCommittedProof`] that read is the value the WHIR opening proves.
#[derive(Clone, Serialize, Deserialize)]
pub struct SpartanCore {
    /// Sumcheck #1: per round the 4 MONOMIAL COEFFICIENTS `c_0..=c_3` of the degree-3 round polynomial (the
    /// verifier checks `h(0) + h(1) = 2·c_0 + c_1 + c_2 + c_3` and folds by Horner — recursion-friendly).
    pub outer: Vec<Vec<Ea4>>,
    /// `Ã_z(r_x), B̃_z(r_x), C̃_z(r_x)`.
    pub abc: [Ea4; 3],
    /// Sumcheck #2: per round the 3 monomial coefficients `c_0..=c_2` of the degree-2 round polynomial.
    pub inner: Vec<Vec<Ea4>>,
    /// `w̃(r_y[..n−1])`.
    pub w_eval: Ea4,
}

/// The committed argument: the witness half's WHIR commitment, the sumchecks, and the opening at `r_y`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SpartanCommittedProof {
    pub commitment: Commitment,
    pub core: SpartanCore,
    pub open: WhirProof<Fa4, Ea4, Mmcs16>,
    /// The matrix argument (spec §Z3-M) and the fixed commitment's WHIR opening of its column values — present
    /// exactly when the instance is UNIFORM (`prove_committed_uniform`); the plain path evaluates the matrices itself.
    pub matrix: Option<MatrixProof>,
    pub fixed_open: Option<WhirProof<Fa4, Ea4, Mmcs16>>,
}

/// One sumcheck round for a product of tables: `h(t) = Σ_i Π_j f_j(t at i)` at `t = 0..=deg`, where the tables'
/// lowest variable is set to `t` by linear interpolation.
fn round_evals(tables: &[&[Ea4]], deg: usize) -> Vec<Ea4> {
    let half = tables[0].len() / 2;
    (0..=deg)
        .map(|t| {
            let t_e = Ea4::from_u64(t as u64);
            (0..half).fold(Ea4::ZERO, |acc, i| {
                acc + tables.iter().fold(Ea4::ONE, |p, f| p * (f[2 * i] + t_e * (f[2 * i + 1] - f[2 * i])))
            })
        })
        .collect()
}

/// The monomial coefficients of the degree-`d` polynomial through `(t, h[t])`, `t = 0..=d` (each Lagrange basis
/// polynomial expanded by convolution). The round messages travel in THIS basis (2026-09-28, DESIGN Z): the
/// verifier folds the claim by Horner and checks `h(0) + h(1) = 2·c_0 + c_1 + … + c_d` — no Lagrange constants,
/// for which a recursive verifier has no operand.
pub(crate) fn coeffs_from_evals(h: &[Ea4]) -> Vec<Ea4> {
    let d = h.len() - 1;
    let mut c = vec![Ea4::ZERO; d + 1];
    for (j, &hj) in h.iter().enumerate() {
        let mut num = vec![Ea4::ONE]; // Π_{m≠j} (x − m), lowest degree first
        let mut den = Ea4::ONE;
        for m in 0..=d {
            if m == j {
                continue;
            }
            let me = Ea4::from_u64(m as u64);
            let mut next = vec![Ea4::ZERO; num.len() + 1];
            for (k, &nk) in num.iter().enumerate() {
                next[k + 1] += nk;
                next[k] -= nk * me;
            }
            num = next;
            den *= Ea4::from_u64(j as u64) - me;
        }
        let scale = hj * p3_field::Field::inverse(&den);
        for (k, &nk) in num.iter().enumerate() {
            c[k] += nk * scale;
        }
    }
    c
}
/// `Σ_k c_k·r^k` by Horner.
pub(crate) fn horner(c: &[Ea4], r: Ea4) -> Ea4 {
    c.iter().rev().fold(Ea4::ZERO, |acc, &ck| acc * r + ck)
}

/// The two sumchecks on an already-laid `z`, driven on the caller's transcript. Returns the messages and `r_y`.
/// Split out so a pin can run a CHEATING prover — one that skips the satisfaction refusal — against the verifier.
fn run_core(ch: &mut Chl, r1cs: &R1cs, z: &[Fa4], fixed: Option<&FixedColumns>) -> (SpartanCore, Vec<Ea4>, Option<(MatrixProof, Vec<Ea4>)>) {
    let abc = [mat_vec(&r1cs.a, z, r1cs.rows()), mat_vec(&r1cs.b, z, r1cs.rows()), mat_vec(&r1cs.c, z, r1cs.rows())];
    run_core_from(ch, r1cs, z, abc, |eq_rx, coef| stored_mr(r1cs, &eq_rx, coef), fixed)
}

/// `M_r(y) = Σ_x eq(r_x, x)·(ra·A + rb·B + rc·C)[x][y]` over the stored matrices.
fn stored_mr(r1cs: &R1cs, eq_rx: &[Ea4], [ra, rb, rc]: [Ea4; 3]) -> Vec<Ea4> {
    let mut mr = vec![Ea4::ZERO; r1cs.cols()];
    for (mat, coef) in [(&r1cs.a, ra), (&r1cs.b, rb), (&r1cs.c, rc)] {
        for &(r, c, v) in mat {
            mr[c] += eq_rx[r] * coef * Ea4::from(v);
        }
    }
    mr
}

/// ⭐ THE CORE over the products `abc = [A·z, B·z, C·z]` (each `rows()` long) and the `M_r` its caller forms from `eq(r_x, ·)`
/// and `(ra, rb, rc)` — the stored matrices' ([`run_core`]) or a streamed replay's ([`prove_committed_streamed`]). Only the
/// shape of `r1cs` is read here. `A·z` is a function of `z` alone, so taking it before τ is drawn moves no challenge.
fn run_core_from(
    ch: &mut Chl,
    r1cs: &R1cs,
    z: &[Fa4],
    abc: [Vec<Fa4>; 3],
    mr_of: impl FnOnce(Vec<Ea4>, [Ea4; 3]) -> Vec<Ea4>,
    fixed: Option<&FixedColumns>,
) -> (SpartanCore, Vec<Ea4>, Option<(MatrixProof, Vec<Ea4>)>) {
    let tau: Vec<Ea4> = (0..r1cs.m_vars).map(|_| draw(ch)).collect();
    let to_ext = |v: Vec<Fa4>| -> Vec<Ea4> { v.into_iter().map(Ea4::from).collect() };
    let mut eq_t = eq_table(&tau);
    let [az, bz, cz] = abc;
    let mut az = to_ext(az);
    let mut bz = to_ext(bz);
    let mut cz = to_ext(cz);
    // Sumcheck #1: g = eq·(a·b − c) is not one product, so its round polynomial is the difference of two:
    // h(t) = [Σ eq·a·b](t) − [Σ eq·c](t), degree 3.
    let mut outer = Vec::with_capacity(r1cs.m_vars);
    let mut r_x = Vec::with_capacity(r1cs.m_vars);
    for _ in 0..r1cs.m_vars {
        let eab = round_evals(&[&eq_t, &az, &bz], 3);
        let ec = round_evals(&[&eq_t, &cz], 3);
        let h: Vec<Ea4> = eab.iter().zip(&ec).map(|(x, y)| *x - *y).collect();
        let h = coeffs_from_evals(&h);
        for &e in &h {
            absorb(ch, e);
        }
        let r = draw(ch);
        eq_t = fold_at(&eq_t, r);
        az = fold_at(&az, r);
        bz = fold_at(&bz, r);
        cz = fold_at(&cz, r);
        outer.push(h);
        r_x.push(r);
    }
    let abc = [az[0], bz[0], cz[0]];
    for e in abc {
        absorb(ch, e);
    }
    let (ra, rb, rc) = (draw(ch), draw(ch), draw(ch));
    // Sumcheck #2 over y: M_r(y) = Σ_x eq(r_x,x)·(ra·A + rb·B + rc·C)[x][y], times z̃(y).
    let eq_rx = eq_table(&r_x);
    let mut mr = mr_of(eq_rx, [ra, rb, rc]);
    let mut zt = to_ext(z.to_vec());
    let mut inner = Vec::with_capacity(r1cs.n_vars);
    let mut r_y = Vec::with_capacity(r1cs.n_vars);
    for _ in 0..r1cs.n_vars {
        let h = coeffs_from_evals(&round_evals(&[&mr, &zt], 2));
        for &e in &h {
            absorb(ch, e);
        }
        let r = draw(ch);
        mr = fold_at(&mr, r);
        zt = fold_at(&zt, r);
        inner.push(h);
        r_y.push(r);
    }
    // the matrix argument (uniform instances): m_at proven by its own sumcheck on this transcript, ρ for the opening
    let matrix = fixed.map(|f| {
        let pt = MatrixPoint { ra, rb, rc, r_x: r_x.clone(), r_y: r_y.clone() };
        crate::matrix_argument::prove(f, &pt, ch)
    });
    let w_eval = mle_eval(&z[r1cs.w_off()..], &r_y[..r1cs.w_vars()]);
    (SpartanCore { outer, abc, inner, w_eval }, r_y, matrix)
}

// ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
// §M6-P — the prover of a UNIFORM instance that never lays a matrix, `z`, `eq` or `M_r` in full
// (docs/O1-OPENINGS-RECURSION-SPEC.md § "M6-P", 2026-09-28).
// ROOT-LAYER: the constraint matrices are DEFINED by the template (`uniform_r1cs`), so `A·z, B·z, C·z` are
// produced HERE from the template and the witness; the materialized `R1cs` was a derived view of the same
// definition, and this prover reads the definition directly instead of that view. Every function below computes
// the SAME field expression as `run_core` on the materialized instance, re-associated along the instance's product
// structure (`eq(τ, (g, i)) = eq_lo[i]·eq_hi[g]`; a witness column's `M_r` entry as
// `ex_hi[g]·L_j − [g = last]·ex_hi[last]·LT_j + [g ≥ 1]·ex_hi[g−1]·N_j`), so every round message is the same
// element and the transcript is the same.
// MEASURED (before, 2026-09-28 m5l run): the certificate instance is ALWAYS T = 2^14 steps of the R = 2^13
// universal-row template (2^27 constraints, 2^28 columns); `materialize()` is ≈ 10^9 entries and the pin
// `the_uniform_certificate_rows_check_the_summand_and_close_z` took 868.58 s with the machine at 6.2 GB of its 7 GB
// swap (the harness was SIGKILLed after its ok line). After: the small-T pin below holds the messages byte-equal
// between the two provers; the T = 2^14 numbers are recorded in the spec's §M6-P "MEASURED" line when that run lands.
// MUST-STAY-GREEN: every `spartan_ccs` pin (plain path untouched: `run_core` still drives it), the uniform pins in
// `fixed_program`, `matrix_program`, `matrix_argument`, `spartan_program`, `whir_program` (their transcript replays
// read the same `SpartanCore`), and `verify_committed_uniform` on proofs of either prover.
// ───────────────────────────────────────────────────────────────────────────────────────────────────────────────

/// `A·z`, `B·z`, `C·z` of a uniform instance STREAMED from its template, ONE STEP AT A TIME — never three tables of 2^m
/// words. Entry `(i, col, val)` of step `g` lands on constraint `g·R + i` with `z(Public c) = [1, io…][c]`,
/// `z(Local j) = w[g·V + j]`, `z(Next j) = w[(g+1)·V + j]`; every entry of a transition row is skipped at the last
/// step (exactly `UniformR1cs::materialize`'s rule); the boundary entries follow, filed by the step they land in.
///
/// ⛔ DB-371 (lane stable 2026-11-02) — THE THREE BASE TABLES WERE THE CERTIFICATE PROVER'S LARGEST LIVE OBJECTS. Laid in
/// full they were 3 × 2^m × 4 B — 3 GiB at the release shape (r_bits 13, t_bits 15) — held from the core's start until the
/// depth-`OUTER_BASE_ROUNDS` fold. MEASURED (`heap` on the profile pin's process, T = 2^15): three 1 GiB malloc blocks live at
/// the core, the profile's lifetime peak (core 7,826 MB footprint; a real node's two certificate proves overran the 4,096 MB
/// journey cap, docs/LAUNCH-BLOCKERS-20261027.md R4). Every reader takes them one step chunk (`R` rows) at a time — the
/// satisfaction check, the first `kb` outer rounds and the depth-`kb` fold — so each regenerates its step from the template
/// and the witness instead: the same field values in the same order, so the round polynomials and the transcript are
/// byte-identical (`the_streaming_prover_equals_the_materialized_prover`). cons: the step rows are computed once per reader
/// pass (the check, `kb` rounds, the fold: `kb + 2` passes where the table was laid once) — MEASURED below in the profile
/// line's `stream_abc` + `sumchecks`; RAM −3 GiB at the release shape (one `R`-row buffer per worker instead).
struct AbcSource<'a> {
    u: &'a UniformR1cs,
    pubs: Vec<Fa4>,
    w: &'a [Fa4],
    trans: Vec<bool>,
    /// per matrix (A, B, C): the boundary entries as `(step, row in step, value of the entry's z)` — a handful (O(1))
    boundary: [Vec<(usize, usize, Fa4)>; 3],
}

impl AbcSource<'_> {
    fn steps(&self) -> usize {
        self.u.steps()
    }

    fn rows_per_step(&self) -> usize {
        1usize << self.u.r_bits
    }

    /// Step `g`'s rows of `A·z`, `B·z`, `C·z` written into `out` (three slices of `R` words each, overwritten).
    fn step_into(&self, g: usize, out: [&mut [Fa4]; 3]) {
        let v_bits = self.u.v_bits;
        let last = g + 1 == self.steps();
        for ((m, chunk), bnd) in [&self.u.a, &self.u.b, &self.u.c].into_iter().zip(out).zip(&self.boundary) {
            chunk.fill(Fa4::ZERO);
            for &(i, col, val) in &m.template {
                if last && self.trans[i] {
                    continue; // a transition row is absent at the last step (no step g+1 exists)
                }
                let zv = match col {
                    Col::Public(c) => self.pubs[c],
                    Col::Local(j) => self.w[(g << v_bits) + j],
                    Col::Next(j) => self.w[((g + 1) << v_bits) + j],
                };
                chunk[i] += val * zv;
            }
            for &(step, i, zv) in bnd {
                if step == g {
                    chunk[i] += zv;
                }
            }
        }
    }

    /// `(A·z) ∘ (B·z) == C·z` on every constraint — the prover's own refusal of an unsatisfying witness.
    fn satisfied(&self) -> bool {
        let r = self.rows_per_step();
        (0..self.steps()).into_par_iter().all(|g| {
            let (mut a, mut b, mut c) = (vec![Fa4::ZERO; r], vec![Fa4::ZERO; r], vec![Fa4::ZERO; r]);
            self.step_into(g, [&mut a, &mut b, &mut c]);
            (0..r).all(|x| a[x] * b[x] == c[x])
        })
    }

    /// The three tables folded `k = log2(wgt.len())` times at once, as [`fold_base_to_ext`] folds a laid table: entry
    /// `g·(R >> k) + i` is `Σ_b wgt[b]·t[g·R + (i << k) + b]`.
    fn fold_to_ext(&self, wgt: &[Ea4]) -> [Vec<Ea4>; 3] {
        let r = self.rows_per_step();
        let k = wgt.len().trailing_zeros() as usize;
        let per = r >> k;
        let n = self.steps() * per;
        let (mut fa, mut fb, mut fc) = (vec![Ea4::ZERO; n], vec![Ea4::ZERO; n], vec![Ea4::ZERO; n]);
        fa.par_chunks_mut(per)
            .zip(fb.par_chunks_mut(per))
            .zip(fc.par_chunks_mut(per))
            .enumerate()
            .for_each_init(
                || (vec![Fa4::ZERO; r], vec![Fa4::ZERO; r], vec![Fa4::ZERO; r]),
                |(a, b, c), (g, ((oa, ob), oc))| {
                    self.step_into(g, [a, b, c]);
                    for i in 0..per {
                        oa[i] = folded_base(a, wgt, i);
                        ob[i] = folded_base(b, wgt, i);
                        oc[i] = folded_base(c, wgt, i);
                    }
                },
            );
        [fa, fb, fc]
    }
}

/// `[1, io…]` zero-padded to the power of two ≥ `io_len + 1`: the span of z's public half that can be nonzero.
fn pub_table(io: &[Fa4]) -> Vec<Fa4> {
    let mut p = vec![Fa4::ZERO; (io.len() + 1).next_power_of_two()];
    p[0] = Fa4::ONE;
    p[1..=io.len()].copy_from_slice(io);
    p
}

/// `w` is the witness half IN FULL (`w_off` words). `None` when an entry of the instance lies outside its shape,
/// or a PUBLIC column lies past the public table: the structured `M_r` of [`run_core_uniform`] holds the public
/// half as that table, so an instance referencing a public column beyond it is REFUSED rather than proven with a
/// wrong `M_r` (fail closed; `FixedColumns::of` refuses the same instances at circuit-build time).
fn stream_abc<'a>(u: &'a UniformR1cs, io: &[Fa4], w: &'a [Fa4]) -> Option<AbcSource<'a>> {
    let pubs = pub_table(io);
    let (steps, v_bits, w_off) = (u.steps(), u.v_bits, u.w_off());
    let (r, rows, cols) = (1usize << u.r_bits, 1usize << u.m_vars(), 1usize << u.n_vars());
    let (v, pw) = (1usize << v_bits, pubs.len());
    if w.len() != w_off || pw > w_off {
        return None;
    }
    for m in [&u.a, &u.b, &u.c] {
        let template_ok = m.template.iter().all(|&(i, col, _)| {
            i < r
                && match col {
                    Col::Public(c) => c < pw,
                    Col::Local(j) | Col::Next(j) => j < v,
                }
        });
        let boundary_ok = m.boundary.iter().all(|&(row, col, _)| row < rows && col < cols && (col >= w_off || col < pw));
        if !template_ok || !boundary_ok {
            return None;
        }
    }
    let r_bits = u.r_bits;
    let boundary = [&u.a, &u.b, &u.c].map(|m| {
        m.boundary
            .iter()
            .map(|&(row, col, val)| (row >> r_bits, row & (r - 1), val * if col < w_off { pubs[col] } else { w[col - w_off] }))
            .collect::<Vec<_>>()
    });
    let _ = (rows, cols);
    Some(AbcSource { u, trans: u.transition_rows(), pubs, w, boundary })
}

/// [`fold_at`] of a table of either field into the extension: `t'[i] = t[2i] + r·(t[2i+1] − t[2i])` — the element
/// `fold_at` produces on the extension image of `t`. Elementwise, parallel.
fn fold_par<F: Field>(t: &[F], r: Ea4) -> Vec<Ea4>
where
    Ea4: Algebra<F>,
{
    (0..t.len() / 2).into_par_iter().map(|i| Ea4::from(t[2 * i]) + r * (t[2 * i + 1] - t[2 * i])).collect()
}

/// Send one round: the monomial coefficients of `h` (given at `t = 0..=deg`) are absorbed, the challenge drawn —
/// exactly [`run_core`]'s per-round order.
fn send_round(ch: &mut Chl, h: &[Ea4], msgs: &mut Vec<Vec<Ea4>>, rs: &mut Vec<Ea4>) -> Ea4 {
    let c = coeffs_from_evals(h);
    for &e in &c {
        absorb(ch, e);
    }
    let r = draw(ch);
    msgs.push(c);
    rs.push(r);
    r
}

/// The eq weights of the challenges bound so far over the LOW bits of an index: `wgt[b] = Π_j (b_j ? r_j : 1 − r_j)`
/// (bit `j` of `b` ↔ the `j`-th challenge). Doubling by concatenation appends the newest challenge as the highest
/// bit — the order `fold_at` binds.
fn extend_weights(wgt: &[Ea4], r: Ea4) -> Vec<Ea4> {
    wgt.iter().map(|&w| w * (Ea4::ONE - r)).chain(wgt.iter().map(|&w| w * r)).collect()
}

/// Entry `i` of a base table folded `k = log2(wgt.len())` times, WITHOUT the folds materialized:
/// `Σ_b wgt[b]·t[(i << k) + b]` — the element `k` successive `fold_at`s produce.
fn folded_base(t: &[Fa4], wgt: &[Ea4], i: usize) -> Ea4 {
    let base = i << wgt.len().trailing_zeros();
    wgt.iter().enumerate().fold(Ea4::ZERO, |acc, (b, &w)| acc + w * t[base + b])
}

/// The base table folded `k = log2(wgt.len())` times at once (parallel) — [`fold_par`] applied `k` times.
fn fold_base_to_ext(t: &[Fa4], wgt: &[Ea4]) -> Vec<Ea4> {
    let k = wgt.len().trailing_zeros() as usize;
    (0..t.len() >> k).into_par_iter().map(|i| folded_base(t, wgt, i)).collect()
}

/// DB-371 step 4 — the fold depth at which the prover's two base-field tables MATERIALIZE in the extension: the
/// A·z/B·z/C·z tables of sumcheck #1 (`fold_base_to_ext` after `OUTER_BASE_ROUNDS` weighted rounds) and the witness
/// half of sumcheck #2 (after `WITNESS_BASE_ROUNDS`). Depth `k` materializes 2^(bits − k) × 16 B. MEASURED at the
/// certificate shape (r_bits 13, t_bits 14, v_bits 13; `[core-mem]` marks, 2026-10-04 11:18): the three outer tables
/// were 768 MiB at depth 3 (the +769 MB step), the witness 1 GiB at depth 0 (the +1,028 MB step that SET the 6,137 MB
/// lifetime peak); at depth 4 they are 384 MiB and 128 MiB. The cost of depth `k`: round `k` reads every base word
/// through 2^k weights (outer round 3: 3 × 2^27 × 8 Ea4·Fa4 products ≈ 1–2 s on four threads; a deeper depth doubles
/// it for half the bytes — 4 is where the saving stops setting the peak, the open-witness phase's own transient does).
/// Prover-internal: the round polynomials are the same field values and the transcript is byte-identical, pinned by
/// `the_streaming_prover_equals_the_materialized_prover` (depths 0, 2 and 4 through its three shapes).
const OUTER_BASE_ROUNDS: usize = 4;
const WITNESS_BASE_ROUNDS: usize = 4;

/// The two depths as the prover reads them. In the TEST build only, `MONEROUSD_PROFILE_BASE_ROUNDS="<outer>,<witness>"`
/// overrides them, so the profile pin can A/B a depth at one shape from one build without free RAM for the production
/// shape (user 2026-10-04: prove it without relying on memory). An instrument: the transcript is the same at every
/// depth — `the_streaming_prover_equals_the_materialized_prover` asserts it — and the release prover reads the
/// constants and nothing else.
fn base_rounds() -> (usize, usize) {
    #[cfg(test)]
    if let Ok(s) = std::env::var("MONEROUSD_PROFILE_BASE_ROUNDS") {
        if let Some((a, b)) = s.split_once(',') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                return (a, b);
            }
        }
    }
    (OUTER_BASE_ROUNDS, WITNESS_BASE_ROUNDS)
}

/// [`outer_round_split`] read straight off the unfolded BASE tables at fold depth `k = log2(wgt.len())`: the first
/// rounds of sumcheck #1. RAM (§M6-P): three extension tables at 2^26 are 3 GB; the base tables are 1.5 GB and stay
/// until the folds have shrunk them to 1/2^k (`run_core_uniform` materializes at depth `OUTER_BASE_ROUNDS`). `az/bz/cz` are the
/// step-major base tables with `eq_lo.len() << k` entries per step; a folded pair value is [`folded_base`] over `wgt`.
/// The same field sums as `outer_round_split` on the materialized folds.
fn outer_round_split_base(eq_lo: &[Ea4], eq_hi: &[Ea4], src: &AbcSource<'_>, wgt: &[Ea4]) -> Vec<Ea4> {
    let k = wgt.len().trailing_zeros() as usize;
    let per_step = eq_lo.len() << k;
    debug_assert_eq!(per_step, src.rows_per_step(), "a step's chunk is its R rows");
    let half = eq_lo.len() / 2;
    let eq_lo_t: Vec<[Ea4; 4]> = (0..half)
        .map(|i| {
            let (a, d) = (eq_lo[2 * i], eq_lo[2 * i + 1] - eq_lo[2 * i]);
            [a, a + d, a + d + d, a + d + d + d]
        })
        .collect();
    let sums = (0..src.steps())
        .into_par_iter()
        .fold(
            || ([Ea4::ZERO; 8], vec![Fa4::ZERO; per_step], vec![Fa4::ZERO; per_step], vec![Fa4::ZERO; per_step]),
            |(mut acc, mut ag, mut bg, mut cg), g| {
                src.step_into(g, [&mut ag, &mut bg, &mut cg]);
                let (mut ab, mut c) = ([Ea4::ZERO; 4], [Ea4::ZERO; 4]);
                for i in 0..half {
                    let (a0, a1) = (folded_base(&ag, wgt, 2 * i), folded_base(&ag, wgt, 2 * i + 1));
                    let (b0, b1) = (folded_base(&bg, wgt, 2 * i), folded_base(&bg, wgt, 2 * i + 1));
                    let (c0, c1) = (folded_base(&cg, wgt, 2 * i), folded_base(&cg, wgt, 2 * i + 1));
                    let (mut at, da) = (a0, a1 - a0);
                    let (mut bt, db) = (b0, b1 - b0);
                    let (mut ct, dc) = (c0, c1 - c0);
                    for t in 0..4 {
                        ab[t] += eq_lo_t[i][t] * (at * bt);
                        c[t] += eq_lo_t[i][t] * ct;
                        at += da;
                        bt += db;
                        ct += dc;
                    }
                }
                for t in 0..4 {
                    acc[t] += eq_hi[g] * ab[t];
                    acc[4 + t] += eq_hi[g] * c[t];
                }
                (acc, ag, bg, cg)
            },
        )
        .map(|(acc, _, _, _)| acc)
        .reduce(|| [Ea4::ZERO; 8], |x, y| core::array::from_fn(|k| x[k] + y[k]));
    (0..4).map(|t| sums[t] - sums[4 + t]).collect()
}

/// One round of sumcheck #1 while the template-ROW variables are being bound: with `eq(τ, x) = eq_lo[i]·eq_hi[g]`,
/// `h_ab(t) = Σ_g eq_hi[g] · Σ_{i'} eq_lo(i'; t)·az(g, i'; t)·bz(g, i'; t)` and `h_c(t)` likewise with `cz` — the
/// flat `round_evals` over `eq_lo ⊗ eq_hi` re-associated, never a 2^m eq table. `az/bz/cz` are laid step-major
/// with `eq_lo.len()` entries per step (the extension tables materialized at depth `OUTER_BASE_ROUNDS` by `run_core_uniform`). Returns
/// `h = h_ab − h_c` at `t = 0..=3`.
fn outer_round_split<F: Field>(eq_lo: &[Ea4], eq_hi: &[Ea4], az: &[F], bz: &[F], cz: &[F]) -> Vec<Ea4>
where
    Ea4: Algebra<F>,
{
    let per_step = eq_lo.len();
    let half = per_step / 2;
    let eq_lo_t: Vec<[Ea4; 4]> = (0..half)
        .map(|i| {
            let (a, d) = (eq_lo[2 * i], eq_lo[2 * i + 1] - eq_lo[2 * i]);
            [a, a + d, a + d + d, a + d + d + d]
        })
        .collect();
    let sums = az
        .par_chunks(per_step)
        .zip(bz.par_chunks(per_step))
        .zip(cz.par_chunks(per_step))
        .enumerate()
        .fold(
            || [Ea4::ZERO; 8],
            |mut acc, (g, ((ag, bg), cg))| {
                let (mut ab, mut c) = ([Ea4::ZERO; 4], [Ea4::ZERO; 4]);
                for i in 0..half {
                    let (mut at, da) = (ag[2 * i], ag[2 * i + 1] - ag[2 * i]);
                    let (mut bt, db) = (bg[2 * i], bg[2 * i + 1] - bg[2 * i]);
                    let (mut ct, dc) = (cg[2 * i], cg[2 * i + 1] - cg[2 * i]);
                    for t in 0..4 {
                        ab[t] += eq_lo_t[i][t] * (at * bt);
                        c[t] += eq_lo_t[i][t] * ct;
                        at += da;
                        bt += db;
                        ct += dc;
                    }
                }
                for t in 0..4 {
                    acc[t] += eq_hi[g] * ab[t];
                    acc[4 + t] += eq_hi[g] * c[t];
                }
                acc
            },
        )
        .reduce(|| [Ea4::ZERO; 8], |x, y| core::array::from_fn(|k| x[k] + y[k]));
    (0..4).map(|t| sums[t] - sums[4 + t]).collect()
}

/// One round of sumcheck #1 over the STEP variables (the row variables bound; `eq` is `eq_lo(r_x[..r_bits])·eq_hi`
/// folded): the flat `round_evals` of `[eq, az, bz]` and `[eq, cz]` at degree 3 in one parallel pass. `F` is the
/// extension — or the base field when the template has no row variable at all.
fn outer_round_flat<F: Field>(eq: &[Ea4], az: &[F], bz: &[F], cz: &[F]) -> Vec<Ea4>
where
    Ea4: Algebra<F>,
{
    let half = eq.len() / 2;
    let sums = (0..half)
        .into_par_iter()
        .fold(
            || [Ea4::ZERO; 8],
            |mut acc, i| {
                let (mut et, de) = (eq[2 * i], eq[2 * i + 1] - eq[2 * i]);
                let (mut at, da) = (az[2 * i], az[2 * i + 1] - az[2 * i]);
                let (mut bt, db) = (bz[2 * i], bz[2 * i + 1] - bz[2 * i]);
                let (mut ct, dc) = (cz[2 * i], cz[2 * i + 1] - cz[2 * i]);
                for t in 0..4 {
                    acc[t] += et * (at * bt);
                    acc[4 + t] += et * ct;
                    et += de;
                    at += da;
                    bt += db;
                    ct += dc;
                }
                acc
            },
        )
        .reduce(|| [Ea4::ZERO; 8], |x, y| core::array::from_fn(|k| x[k] + y[k]));
    (0..4).map(|t| sums[t] - sums[4 + t]).collect()
}

/// The PUBLIC half of `M_r` and of `z̃` in sumcheck #2 as the compact tables over the public span. The flat half is
/// zero beyond them, so once they fold to one entry every further fold of the flat half is the pair `(s, 0)`:
/// `s ← s − r·s`, and the pair's round contribution `(s_m − t·s_m)·(s_z − t·s_z)` is `[s_m·s_z, 0, s_m·s_z]`.
struct PubHalf {
    m: Vec<Ea4>,
    z: Vec<Ea4>,
}
impl PubHalf {
    fn round(&self) -> Vec<Ea4> {
        if self.m.len() >= 2 {
            round_evals(&[&self.m, &self.z], 2)
        } else {
            let s = self.m[0] * self.z[0];
            vec![s, Ea4::ZERO, s]
        }
    }
    fn fold(&mut self, r: Ea4) {
        if self.m.len() >= 2 {
            self.m = fold_at(&self.m, r);
            self.z = fold_at(&self.z, r);
        } else {
            self.m[0] = self.m[0] - r * self.m[0];
            self.z[0] = self.z[0] - r * self.z[0];
        }
    }
}

/// A witness-half boundary entry of `M_r` at the current fold level: `(g, j, δ)` adds `δ` at local index `j` of
/// step `g`. Folding the lowest bit at `r` sends it to `(g, j/2)` as `δ − r·δ` (even `j`) or `r·δ` (odd `j`).
fn fold_corrections(corr: &mut [(usize, usize, Ea4)], r: Ea4) {
    for (_, j, d) in corr.iter_mut() {
        *d = if *j % 2 == 1 { *d * r } else { *d - r * *d };
        *j /= 2;
    }
}

/// One round of sumcheck #2 while the LOCAL-variable bits are being bound, the witness half of `M_r` in its
/// structured form `mr(g, j) = ex_hi[g]·L_j − [g = last]·ex_hi[last]·LT_j + [g ≥ 1]·ex_hi[g−1]·N_j + corrections`:
/// `Σ_{g,j'} mr(g, j'; t)·w(g, j'; t) = Σ_{j'} L(j'; t)·W1(j'; t) + N(j'; t)·W2(j'; t) − ex_hi[last]·LT(j'; t)·w(last, j'; t)
/// + Σ_corr`, with `W1(j'; t) = Σ_g ex_hi[g]·w(g, j'; t)` and `W2(j'; t) = Σ_{g ≥ 1} ex_hi[g−1]·w(g, j'; t)` — the
/// flat `round_evals` of `[mr, w]` re-associated, never a 2^(t+v) `mr` table. `w` is laid step-major with
/// `l.len()` entries per step (the base field on the first round, the extension after); a correction contributes
/// `δ·(1 − t)` (even `j`) or `δ·t` (odd `j`) at pair `(g, j/2)`.
fn inner_round_local<F: Field>(ex_hi: &[Ea4], l: &[Ea4], lt: &[Ea4], nn: &[Ea4], w: &[F], corr: &[(usize, usize, Ea4)]) -> Vec<Ea4>
where
    Ea4: Algebra<F>,
{
    let per_step = l.len();
    let half = per_step / 2;
    let last = ex_hi.len() - 1;
    let interp = |t: &[Ea4], i: usize| -> [Ea4; 3] {
        let (a, d) = (t[2 * i], t[2 * i + 1] - t[2 * i]);
        [a, a + d, a + d + d]
    };
    let (w1, w2) = w
        .par_chunks(per_step)
        .enumerate()
        .fold(
            || (vec![Ea4::ZERO; 3 * half], vec![Ea4::ZERO; 3 * half]),
            |(mut w1, mut w2), (g, wg)| {
                let e = ex_hi[g];
                let ep = (g >= 1).then(|| ex_hi[g - 1]);
                for i in 0..half {
                    let (mut wt, dw) = (wg[2 * i], wg[2 * i + 1] - wg[2 * i]);
                    for t in 0..3 {
                        w1[t * half + i] += e * wt;
                        if let Some(ep) = ep {
                            w2[t * half + i] += ep * wt;
                        }
                        wt += dw;
                    }
                }
                (w1, w2)
            },
        )
        .reduce(
            || (vec![Ea4::ZERO; 3 * half], vec![Ea4::ZERO; 3 * half]),
            |(a1, a2), (b1, b2)| {
                (a1.iter().zip(&b1).map(|(x, y)| *x + *y).collect(), a2.iter().zip(&b2).map(|(x, y)| *x + *y).collect())
            },
        );
    let wl = &w[last * per_step..];
    let mut h = vec![Ea4::ZERO; 3];
    for i in 0..half {
        let (li, ni, lti) = (interp(l, i), interp(nn, i), interp(lt, i));
        let (mut wt, dw) = (wl[2 * i], wl[2 * i + 1] - wl[2 * i]);
        for t in 0..3 {
            h[t] += li[t] * w1[t * half + i] + ni[t] * w2[t * half + i] - ex_hi[last] * lti[t] * wt;
            wt += dw;
        }
    }
    for &(g, j, d) in corr {
        let wg = &w[g * per_step..];
        let (i, odd) = (j / 2, j % 2 == 1);
        let (mut wt, dw) = (wg[2 * i], wg[2 * i + 1] - wg[2 * i]);
        for t in 0..3 {
            let te = Ea4::from_u64(t as u64);
            let ct = if odd { d * te } else { d * (Ea4::ONE - te) };
            h[t] += ct * wt;
            wt += dw;
        }
    }
    h
}

/// [`inner_round_local`] read straight off the unfolded BASE witness at fold depth `k = log2(wgt.len())` — the first
/// `kw ≤ WITNESS_BASE_ROUNDS` local rounds of sumcheck #2 (DB-371 step 4). `w` is the caller's witness half, laid
/// step-major with `l.len() << k` base words per step; a folded pair value is [`folded_base`] over `wgt`, so the
/// round-0 extension image of the witness (2^(n−2) × 16 B — 1 GiB at the certificate shape, the measured +1,028 MB
/// that set the lifetime peak) is never built: the witness materializes in the extension at depth `kw`
/// (`fold_base_to_ext`). The same field sums as `inner_round_local` on the materialized folds — the fold is linear,
/// so `Σ_b wgt[b]·w[(i << k) + b]` IS the entry `k` successive `fold_at`s produce.
fn inner_round_local_base(ex_hi: &[Ea4], l: &[Ea4], lt: &[Ea4], nn: &[Ea4], w: &[Fa4], wgt: &[Ea4], corr: &[(usize, usize, Ea4)]) -> Vec<Ea4> {
    let k = wgt.len().trailing_zeros() as usize;
    let per_step = l.len();
    let base_per_step = per_step << k;
    let half = per_step / 2;
    let last = ex_hi.len() - 1;
    let interp = |t: &[Ea4], i: usize| -> [Ea4; 3] {
        let (a, d) = (t[2 * i], t[2 * i + 1] - t[2 * i]);
        [a, a + d, a + d + d]
    };
    // the folded pair `(w(2i), w(2i+1) − w(2i))` of one step at depth `k`
    let pair = |wg: &[Fa4], i: usize| -> (Ea4, Ea4) {
        let w0 = folded_base(wg, wgt, 2 * i);
        (w0, folded_base(wg, wgt, 2 * i + 1) - w0)
    };
    let (w1, w2) = w
        .par_chunks(base_per_step)
        .enumerate()
        .fold(
            || (vec![Ea4::ZERO; 3 * half], vec![Ea4::ZERO; 3 * half]),
            |(mut w1, mut w2), (g, wg)| {
                let e = ex_hi[g];
                let ep = (g >= 1).then(|| ex_hi[g - 1]);
                for i in 0..half {
                    let (mut wt, dw) = pair(wg, i);
                    for t in 0..3 {
                        w1[t * half + i] += e * wt;
                        if let Some(ep) = ep {
                            w2[t * half + i] += ep * wt;
                        }
                        wt += dw;
                    }
                }
                (w1, w2)
            },
        )
        .reduce(
            || (vec![Ea4::ZERO; 3 * half], vec![Ea4::ZERO; 3 * half]),
            |(a1, a2), (b1, b2)| {
                (a1.iter().zip(&b1).map(|(x, y)| *x + *y).collect(), a2.iter().zip(&b2).map(|(x, y)| *x + *y).collect())
            },
        );
    let wl = &w[last * base_per_step..];
    let mut h = vec![Ea4::ZERO; 3];
    for i in 0..half {
        let (li, ni, lti) = (interp(l, i), interp(nn, i), interp(lt, i));
        let (mut wt, dw) = pair(wl, i);
        for t in 0..3 {
            h[t] += li[t] * w1[t * half + i] + ni[t] * w2[t * half + i] - ex_hi[last] * lti[t] * wt;
            wt += dw;
        }
    }
    for &(g, j, d) in corr {
        let wg = &w[g * base_per_step..];
        let (i, odd) = (j / 2, j % 2 == 1);
        let (mut wt, dw) = pair(wg, i);
        for t in 0..3 {
            let te = Ea4::from_u64(t as u64);
            let ct = if odd { d * te } else { d * (Ea4::ONE - te) };
            h[t] += ct * wt;
            wt += dw;
        }
    }
    h
}

/// One round of sumcheck #2 over the STEP variables (the local variables bound; `mr` is the per-step table): the
/// flat `round_evals` of `[mr, w]` at degree 2, parallel. `F` is the extension — or the base field when the
/// template has one local variable and no local bit was folded.
fn inner_round_flat<F: Field>(mr: &[Ea4], w: &[F]) -> Vec<Ea4>
where
    Ea4: Algebra<F>,
{
    let half = mr.len() / 2;
    let sums = (0..half)
        .into_par_iter()
        .fold(
            || [Ea4::ZERO; 3],
            |mut acc, i| {
                let (mut mt, dm) = (mr[2 * i], mr[2 * i + 1] - mr[2 * i]);
                let (mut wt, dw) = (w[2 * i], w[2 * i + 1] - w[2 * i]);
                for t in 0..3 {
                    acc[t] += mt * wt;
                    mt += dm;
                    wt += dw;
                }
                acc
            },
        )
        .reduce(|| [Ea4::ZERO; 3], |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]]);
    sums.to_vec()
}

/// The witness half of `z̃` through sumcheck #2: the caller's base-field slice until the first fold, then the
/// extension table it folds into.
enum WitnessTable<'a> {
    Base(&'a [Fa4]),
    Ext(Vec<Ea4>),
}
impl WitnessTable<'_> {
    fn scalar(&self) -> Ea4 {
        match self {
            WitnessTable::Base(t) => Ea4::from(t[0]),
            WitnessTable::Ext(t) => t[0],
        }
    }
}

/// The two sumchecks of a UNIFORM instance without laying `z`, `eq`, a matrix or `M_r` in full: the same transcript
/// and the same round polynomials as [`run_core`] on the materialized instance. `w` is the witness half in full
/// (`w_off` words); `tables` are its streamed `A·z, B·z, C·z`.
fn run_core_uniform(ch: &mut Chl, u: &UniformR1cs, io: &[Fa4], w: &[Fa4], src: AbcSource<'_>, fixed: Option<&FixedColumns>) -> (SpartanCore, Vec<Ea4>, Option<(MatrixProof, Vec<Ea4>)>) {
    let (r_bits, v_bits) = (u.r_bits, u.v_bits);
    let (m_vars, n_vars, steps, w_off) = (u.m_vars(), u.n_vars(), u.steps(), u.w_off());
    assert_eq!(w.len(), w_off, "the witness half in full");
    core_mem_mark("core start (A·z/B·z/C·z streamed per step — no base table held)");
    let tau: Vec<Ea4> = (0..m_vars).map(|_| draw(ch)).collect();
    // Sumcheck #1 — the row variables under the split eq: the first `kb ≤ OUTER_BASE_ROUNDS` rounds read the base
    // tables at their fold depth (RAM: the extension tables are materialized only at 1/2^kb of their round-0 size),
    // the remaining row rounds fold the extension tables, then the step rounds.
    let mut eq_lo = eq_table(&tau[..r_bits]);
    let eq_hi = eq_table(&tau[r_bits..]);
    let mut outer = Vec::with_capacity(m_vars);
    let mut r_x = Vec::with_capacity(m_vars);
    let (outer_depth, witness_depth) = base_rounds();
    let kb = r_bits.min(outer_depth);
    let mut wgt = vec![Ea4::ONE];
    for _ in 0..kb {
        let h = outer_round_split_base(&eq_lo, &eq_hi, &src, &wgt);
        let r = send_round(ch, &h, &mut outer, &mut r_x);
        eq_lo = fold_at(&eq_lo, r);
        wgt = extend_weights(&wgt, r);
    }
    let [mut az, mut bz, mut cz] = src.fold_to_ext(&wgt);
    drop(src);
    let mut eq_g: Option<Vec<Ea4>> = None;
    for k in kb..m_vars {
        let h = if k < r_bits {
            outer_round_split(&eq_lo, &eq_hi, &az, &bz, &cz)
        } else {
            // the row variables are bound: eq(τ, x) = eq_lo(r_x[..r_bits]) · eq_hi[g], folded from here on
            let eq_g = eq_g.get_or_insert_with(|| eq_hi.iter().map(|&e| eq_lo[0] * e).collect());
            outer_round_flat(eq_g, &az, &bz, &cz)
        };
        let r = send_round(ch, &h, &mut outer, &mut r_x);
        if k < r_bits {
            eq_lo = fold_at(&eq_lo, r);
        } else if let Some(g) = eq_g.as_mut() {
            *g = fold_at(g, r);
        }
        az = fold_par(&az, r);
        bz = fold_par(&bz, r);
        cz = fold_par(&cz, r);
    }
    let abc = [az[0], bz[0], cz[0]];
    for e in abc {
        absorb(ch, e);
    }
    core_mem_mark("outer sumcheck done (folded ext tables still held)");
    drop((az, bz, cz));
    core_mem_mark("outer tables dropped");
    let (ra, rb, rc) = (draw(ch), draw(ch), draw(ch));
    // Sumcheck #2 — M_r in its structured form (spec §M6-P item 3).
    let ex_lo = eq_table(&r_x[..r_bits]);
    let ex_hi = eq_table(&r_x[r_bits..]);
    let (v, last, r_mask) = (1usize << v_bits, steps - 1, (1usize << r_bits) - 1);
    let trans = u.transition_rows();
    let pub_z: Vec<Ea4> = pub_table(io).into_iter().map(Ea4::from).collect();
    let mut pubs = PubHalf { m: vec![Ea4::ZERO; pub_z.len()], z: pub_z };
    let (mut l, mut lt, mut nn) = (vec![Ea4::ZERO; v], vec![Ea4::ZERO; v], vec![Ea4::ZERO; v]);
    let mut corr: Vec<(usize, usize, Ea4)> = Vec::new();
    for (mat, coef) in [(&u.a, ra), (&u.b, rb), (&u.c, rc)] {
        for &(i, col, val) in &mat.template {
            let wgt = ex_lo[i] * coef * Ea4::from(val);
            match col {
                Col::Local(j) => {
                    l[j] += wgt;
                    if trans[i] {
                        lt[j] += wgt;
                    }
                }
                Col::Next(j) => nn[j] += wgt,
                // Σ_g ex_hi[g] = 1, less the last step's term on a transition row
                Col::Public(c) => pubs.m[c] += if trans[i] { wgt - wgt * ex_hi[last] } else { wgt },
            }
        }
        for &(row, col, val) in &mat.boundary {
            let e = ex_lo[row & r_mask] * ex_hi[row >> r_bits] * coef * Ea4::from(val);
            if col < w_off {
                pubs.m[col] += e;
            } else {
                corr.push(((col - w_off) >> v_bits, (col - w_off) & (v - 1), e));
            }
        }
    }
    let mut inner = Vec::with_capacity(n_vars);
    let mut r_y = Vec::with_capacity(n_vars);
    // DB-371 step 4 — the witness half stays the caller's BASE slice through the first `kw ≤ WITNESS_BASE_ROUNDS`
    // local rounds, read at its fold depth through `wwgt` (as the outer base tables are), and materializes in the
    // extension at depth `kw` (2^(n−1−kw) × 16 B) instead of at depth 0 (2^(n−2) × 16 B — the 1 GiB that set the
    // certificate's lifetime peak). `kw ≤ v_bits`: the fold lands inside the local rounds or exactly at their end.
    let kw = v_bits.min(witness_depth);
    let mut wwgt = vec![Ea4::ONE];
    let mut wt = WitnessTable::Base(w);
    let mut mr_g: Vec<Ea4> = Vec::new();
    for k in 0..n_vars - 1 {
        if k == v_bits {
            // the local variables are bound: the witness half of M_r is one entry per step
            mr_g = (0..steps)
                .map(|g| {
                    let mut m = ex_hi[g] * l[0];
                    if g == last {
                        m -= ex_hi[last] * lt[0];
                    }
                    if g >= 1 {
                        m += ex_hi[g - 1] * nn[0];
                    }
                    m
                })
                .collect();
            for &(g, _, d) in &corr {
                mr_g[g] += d;
            }
        }
        let h_w = match (&wt, k < v_bits) {
            (WitnessTable::Base(t), true) => inner_round_local_base(&ex_hi, &l, &lt, &nn, t, &wwgt, &corr),
            (WitnessTable::Ext(t), true) => inner_round_local(&ex_hi, &l, &lt, &nn, t, &corr),
            (WitnessTable::Base(t), false) => {
                // only when the template has no local variable (`kw = 0`): the base slice is read unfolded
                debug_assert_eq!(wwgt.len(), 1, "a base witness past the local rounds is read at depth 0");
                inner_round_flat(&mr_g, t)
            }
            (WitnessTable::Ext(t), false) => inner_round_flat(&mr_g, t),
        };
        let h: Vec<Ea4> = h_w.iter().zip(pubs.round()).map(|(a, b)| *a + b).collect();
        let r = send_round(ch, &h, &mut inner, &mut r_y);
        if k < v_bits {
            l = fold_at(&l, r);
            lt = fold_at(&lt, r);
            nn = fold_at(&nn, r);
            fold_corrections(&mut corr, r);
        } else {
            mr_g = fold_at(&mr_g, r);
        }
        pubs.fold(r);
        wt = match wt {
            WitnessTable::Base(t) => {
                wwgt = extend_weights(&wwgt, r);
                if wwgt.len() < (1 << kw) {
                    WitnessTable::Base(t)
                } else {
                    let ext = WitnessTable::Ext(fold_base_to_ext(t, &wwgt));
                    core_mem_mark("witness materialized in the extension (lazy fold at depth kw)");
                    ext
                }
            }
            WitnessTable::Ext(t) => WitnessTable::Ext(fold_par(&t, r)),
        };
    }
    core_mem_mark("inner sumcheck done");
    // the top variable: the two halves' scalars
    let (m_p, z_p, m_w, z_w) = (pubs.m[0], pubs.z[0], mr_g[0], wt.scalar());
    let h: Vec<Ea4> = (0..3u64)
        .map(|t| {
            let te = Ea4::from_u64(t);
            (m_p + te * (m_w - m_p)) * (z_p + te * (z_w - z_p))
        })
        .collect();
    send_round(ch, &h, &mut inner, &mut r_y);
    let matrix = fixed.map(|f| {
        let pt = MatrixPoint { ra, rb, rc, r_x: r_x.clone(), r_y: r_y.clone() };
        crate::matrix_argument::prove(f, &pt, ch)
    });
    core_mem_mark("matrix argument done (core end)");
    (SpartanCore { outer, abc, inner, w_eval: z_w }, r_y, matrix)
}

/// Replay the two sumchecks against the public instance. `Some(r_y)` when every identity holds with the core's
/// `w_eval` taken at its word; the committed verifier then binds that word to the commitment. Fail-closed.
/// What `verify_core` computes on the way: the claim after every round of both sumchecks, `eq(τ, r_x)` and
/// `claim2` — the values a row-by-row recursive verifier must reproduce (its pin reads them).
#[derive(Clone, Debug, Default)]
pub struct CoreTrace {
    pub outer_claims: Vec<Ea4>,
    pub eq: Ea4,
    pub claim2: Ea4,
    pub inner_claims: Vec<Ea4>,
    /// The matrix argument's claim after every round (uniform instances; empty on the plain path).
    pub matrix_claims: Vec<Ea4>,
    /// `m_at` and `z_at` of the final check `claim2 == m_at·z_at`.
    pub m_at: Ea4,
    pub z_at: Ea4,
    /// The challenges the row program reads back from its banks (the certificate pins check its scalars).
    pub r_x: Vec<Ea4>,
    pub rabc: [Ea4; 3],
}

pub(crate) fn verify_core(ch: &mut Chl, r1cs: &R1cs, io: &[Fa4], core: &SpartanCore) -> Option<Vec<Ea4>> {
    verify_core_traced(ch, r1cs, io, core, None).map(|(r_y, _, _)| r_y)
}

/// `verify_core` with its intermediate values (see [`CoreTrace`]).
/// With `matrix`, `m_at` comes from the matrix argument (a uniform instance) and the final point `ρ` is returned
/// for the fixed commitment's opening; without it the verifier evaluates the matrices directly.
pub(crate) fn verify_core_traced(ch: &mut Chl, r1cs: &R1cs, io: &[Fa4], core: &SpartanCore, matrix: Option<(&FixedColumns, &MatrixProof)>) -> Option<(Vec<Ea4>, CoreTrace, Option<Vec<Ea4>>)> {
    verify_core_src(ch, r1cs, io, core, matrix, &|eq_x, eq_y, coef| Some(stored_mle(r1cs, &eq_x, &eq_y, coef)))
}

/// `ra·Ã(r_x, r_y) + rb·B̃ + rc·C̃` over the stored matrices.
fn stored_mle(r1cs: &R1cs, eq_x: &[Ea4], eq_y: &[Ea4], [ra, rb, rc]: [Ea4; 3]) -> Ea4 {
    ra * sparse_mle(&r1cs.a, eq_x, eq_y) + rb * sparse_mle(&r1cs.b, eq_x, eq_y) + rc * sparse_mle(&r1cs.c, eq_x, eq_y)
}

/// The matrices' evaluation a plain verifier takes: `(eq(r_x, ·), eq(r_y, ·), (ra, rb, rc)) ↦ ra·Ã + rb·B̃ + rc·C̃` at
/// `(r_x, r_y)` — the stored matrices', or a streamed replay's (`None`: the replay could not form; the proof is refused).
pub type MleOf<'a> = &'a dyn Fn(Vec<Ea4>, Vec<Ea4>, [Ea4; 3]) -> Option<Ea4>;

/// [`verify_core_traced`] with the plain instance's matrix evaluation taken from `mle_of`.
fn verify_core_src(ch: &mut Chl, r1cs: &R1cs, io: &[Fa4], core: &SpartanCore, matrix: Option<(&FixedColumns, &MatrixProof)>, mle_of: MleOf<'_>) -> Option<(Vec<Ea4>, CoreTrace, Option<Vec<Ea4>>)> {
    let mut trace = CoreTrace::default();
    if core.outer.len() != r1cs.m_vars || core.inner.len() != r1cs.n_vars {
        return None;
    }
    if core.outer.iter().any(|h| h.len() != 4) || core.inner.iter().any(|h| h.len() != 3) {
        return None;
    }
    let tau: Vec<Ea4> = (0..r1cs.m_vars).map(|_| draw(ch)).collect();
    // Sumcheck #1: the claimed sum is ZERO (every constraint holds); each round folds the claim through h.
    let mut claim = Ea4::ZERO;
    let mut r_x = Vec::with_capacity(r1cs.m_vars);
    for c in &core.outer {
        // h(0) + h(1) = c_0 + Σ_k c_k
        if c[0] + c.iter().copied().sum::<Ea4>() != claim {
            return None;
        }
        for &e in c {
            absorb(ch, e);
        }
        let r = draw(ch);
        claim = horner(c, r);
        trace.outer_claims.push(claim);
        r_x.push(r);
    }
    let [a, b, c] = core.abc;
    for e in core.abc {
        absorb(ch, e);
    }
    trace.eq = eq_point(&tau, &r_x);
    if claim != trace.eq * (a * b - c) {
        return None;
    }
    let (ra, rb, rc) = (draw(ch), draw(ch), draw(ch));
    let mut claim2 = ra * a + rb * b + rc * c;
    trace.claim2 = claim2;
    trace.r_x = r_x.clone();
    trace.rabc = [ra, rb, rc];
    let mut r_y = Vec::with_capacity(r1cs.n_vars);
    for c in &core.inner {
        if c[0] + c.iter().copied().sum::<Ea4>() != claim2 {
            return None;
        }
        for &e in c {
            absorb(ch, e);
        }
        let r = draw(ch);
        claim2 = horner(c, r);
        trace.inner_claims.push(claim2);
        r_y.push(r);
    }
    let (m_at, rho) = match matrix {
        Some((f, mp)) => {
            let pt = MatrixPoint { ra, rb, rc, r_x: r_x.clone(), r_y: r_y.clone() };
            let (m, rho, claims) = crate::matrix_argument::verify_traced(f, &pt, ch, mp)?;
            trace.matrix_claims = claims;
            (m, Some(rho))
        }
        None => (mle_of(eq_table(&r_x), eq_table(&r_y), [ra, rb, rc])?, None),
    };
    // z̃(r_y): the public half `[1, io…, 0…]` evaluated by the verifier over its nonzero span (the power of two ≥
    // io_len + 1), every higher variable contributing `(1 − r)` — the flat half's multilinear at the same point
    // in O(io_len), never a 2^w_vars table (§M6-P: at the certificate's shape that table is 2^27 words); the
    // witness half from the ONE read.
    let pw = (io.len() + 1).next_power_of_two();
    let pb = pw.trailing_zeros() as usize;
    if pb > r1cs.w_vars() {
        return None;
    }
    let mut pub_half = vec![Fa4::ZERO; pw];
    pub_half[0] = Fa4::ONE;
    pub_half[1..=io.len()].copy_from_slice(io);
    let mut pub_at = mle_eval(&pub_half, &r_y[..pb]);
    for &rk in &r_y[pb..r1cs.w_vars()] {
        pub_at *= Ea4::ONE - rk;
    }
    let top = r_y[r1cs.n_vars - 1];
    let z_at = (Ea4::ONE - top) * pub_at + top * core.w_eval;
    trace.m_at = m_at;
    trace.z_at = z_at;
    (claim2 == m_at * z_at).then_some((r_y, trace, rho))
}

/// The PCS point for the witness claim. The sumcheck layout binds its variables in the order
/// `PrefixProver::variable_order()` says; this module is LSB-first, and the two are reconciled HERE, once, so
/// `w_eval` registered against the commitment is the same number `mle_eval` computes.
pub(crate) fn pcs_point(r_w: &[Ea4]) -> Point<Ea4> {
    let mut v: Vec<Ea4> = r_w.to_vec();
    v.reverse();
    Point::new(v)
}

/// PROVE the committed argument. `None` when the instance is malformed, too small to commit, or the witness does
/// not satisfy it — a prover that cannot prove says so instead of producing bytes a verifier must refuse.
#[must_use]
pub fn prove_committed(r1cs: &R1cs, io: &[Fa4], w: &[Fa4]) -> Option<Vec<u8>> {
    prove_committed_with(r1cs, io, w, CarrierParams::LIVE)
}

/// [`prove_committed`] at explicit carrier parameters (the recursive certificate runs its own rate and grinding;
/// the recursion pins run at a higher rate so a round holds tens of queries, not hundreds).
pub fn prove_committed_with(r1cs: &R1cs, io: &[Fa4], w: &[Fa4], params: CarrierParams) -> Option<Vec<u8>> {
    if !r1cs.committable() {
        return None;
    }
    let z = r1cs.lay_z(io, w)?;
    if !r1cs.is_satisfied(&z) {
        return None;
    }
    let w_half = z[r1cs.w_off()..].to_vec();
    let mut profile = ProveProfile::default();
    prove_committed_inner(r1cs, io, w_half, params, None, |ch, _w| Some(run_core(ch, r1cs, &z, None)), &mut profile)
}

/// The prover's phase profile: `(phase, elapsed)` in run order — so a five-minute certificate step reads as a list
/// of named costs, not one number. Bounded: one entry per phase of one prove.
#[derive(Clone, Debug, Default)]
pub struct ProveProfile {
    pub phases: Vec<(&'static str, std::time::Duration)>,
    /// ⛔ DB-371 (docs/DB-371-PHONE-CLASS-PROVER-MEMORY.md) — with `MONEROUSD_PROVE_MEM=1`, the process's physical
    /// footprint and its LIFETIME PEAK (MB) at the END of each phase: the phase where the peak jumps holds the memory.
    /// ROOT-LAYER: the memory is PRODUCED inside the prover's phases (the 2^28-point codeword, its tree, the fold buffers),
    /// so the reading is taken at the phase boundaries of the prover itself, not from outside the process.
    /// MEASURED why: a node building its DSYNC certificate went 42 MB → 6,416 MB footprint while RSS read 2,195 MB, so
    /// RSS cannot name the culprit; the solo `whole_chain_cert::` prove peaked at 7,585 MB.
    /// MUST-STAY-GREEN: the certificate bytes and verdicts (an instrument only: read under the flag, decides nothing).
    /// Read with the OS `footprint` tool (macOS); empty when the flag is unset or the tool is absent. Bounded: one entry
    /// per phase of one prove (a fixed list of phase names), never per row or per query.
    pub mem: Vec<(&'static str, u64, u64)>,
    /// ⭐ DB-371 series (2026-10-04): with `MONEROUSD_PROVE_MEM_SERIES=1`, a sampler thread reads the footprint every
    /// 250 ms for the whole prove, and each phase's row carries the MAX `cur` seen INSIDE that phase — a transient the
    /// end-of-phase reading cannot see (MEASURED: open_w ends at 1,520 MB with the lifetime peak at 6,130, so 4.6 GB of
    /// transient lived somewhere inside it). The raw series prints at the end (`[prove-mem-series] ms cur`), one line
    /// per sample. Bounded: 4 samples per second of one prove; an instrument only, read under the flag, decides nothing.
    pub series: std::sync::Arc<std::sync::Mutex<Vec<(std::time::Instant, u64)>>>,
    pub series_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub series_max: Vec<(&'static str, u64)>,
}

/// DB-371 — this process's `(phys_footprint, phys_footprint_peak)` in MB, from the OS `footprint` tool. `None` when the
/// tool is absent or a line does not parse (no unit, no number): an INSTRUMENT, read only under `MONEROUSD_PROVE_MEM=1`.
/// DB-371 — a footprint reading INSIDE the core phase (`run_core_uniform`'s sub-phases), printed under
/// `MONEROUSD_PROVE_MEM=1` as `[core-mem] <label>: <cur>/<peak> MB`. The phase table reads the core as one 4.5 s number
/// (+2,065 MB, the certificate's lifetime peak); these marks say which sub-phase holds it. An instrument: decides nothing.
pub(crate) fn core_mem_mark(label: &str) {
    if std::env::var("MONEROUSD_PROVE_MEM").ok().as_deref() != Some("1") {
        return;
    }
    if let Some((cur, peak)) = process_footprint_mb() {
        eprintln!("[core-mem] {label}: {cur}/{peak} MB");
    }
    // `MONEROUSD_PROVE_HEAP=1` (with the flag above): the live malloc blocks of ≥ 32 MiB at this mark, largest first, from the
    // OS `heap` tool — which allocation holds the footprint, by size. An instrument: decides nothing.
    if std::env::var("MONEROUSD_PROVE_HEAP").ok().as_deref() == Some("1") {
        if let Ok(out) = std::process::Command::new("heap")
            .args(["-s", "-H", "--noContent", "--addresses=malloc[32M-]", &std::process::id().to_string()])
            .output()
        {
            for l in String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.contains("bytes:") || l.contains("malloc[") || l.contains("TOTAL") || l.contains("MALLOC")) {
                eprintln!("[core-heap] {label}: {l}");
            }
        }
    }
}

pub(crate) fn process_footprint_mb() -> Option<(u64, u64)> {
    let out = std::process::Command::new("footprint").arg("-p").arg(std::process::id().to_string()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| -> Option<u64> {
        text.lines().find_map(|l| {
            let mut it = l.trim().strip_prefix(key)?.split_whitespace();
            let n: f64 = it.next()?.parse().ok()?;
            match it.next()? {
                "KB" => Some((n / 1024.0) as u64),
                "MB" => Some(n as u64),
                "GB" => Some((n * 1024.0) as u64),
                _ => None,
            }
        })
    };
    Some((field("phys_footprint:")?, field("phys_footprint_peak:")?))
}

impl ProveProfile {
    /// Start the DB-371 footprint sampler (a detached thread; it ends when `finish_series` raises the stop flag). A no-op
    /// unless `MONEROUSD_PROVE_MEM_SERIES=1`.
    pub(crate) fn start_series(&mut self) {
        if std::env::var("MONEROUSD_PROVE_MEM_SERIES").ok().as_deref() != Some("1") {
            return;
        }
        let samples = self.series.clone();
        let stop = self.series_stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some((cur, _peak)) = process_footprint_mb() {
                    if let Ok(mut s) = samples.lock() {
                        s.push((std::time::Instant::now(), cur));
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        });
    }

    /// Stop the sampler and print the raw series (ms since the first sample, cur MB), one line per sample.
    pub(crate) fn finish_series(&self) {
        self.series_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let Ok(s) = self.series.lock() else { return };
        let Some((t0, _)) = s.first() else { return };
        for (t, cur) in s.iter() {
            eprintln!("[prove-mem-series] {} {}", t.duration_since(*t0).as_millis(), cur);
        }
    }

    fn mark(&mut self, name: &'static str, since: &mut std::time::Instant) {
        let now = std::time::Instant::now();
        self.phases.push((name, now.duration_since(*since)));
        if std::env::var("MONEROUSD_PROVE_MEM").ok().as_deref() == Some("1") {
            if let Some((cur, peak)) = process_footprint_mb() {
                self.mem.push((name, cur, peak));
            }
        }
        if let Ok(s) = self.series.lock() {
            let max_in_phase = s.iter().filter(|(t, _)| *t >= *since && *t <= now).map(|(_, c)| *c).max();
            if let Some(m) = max_in_phase {
                self.series_max.push((name, m));
            }
        }
        *since = now;
    }
    /// One line, `commit_w 41.2s, core 88.0s, …` — and, under `MONEROUSD_PROVE_MEM=1`, `… | mem MB (now/peak): commit_w
    /// 3120/4410, …`.
    #[must_use]
    pub fn line(&self) -> String {
        let t = self.phases.iter().map(|(n, d)| format!("{n} {d:.1?}")).collect::<Vec<_>>().join(", ");
        if self.mem.is_empty() {
            return t;
        }
        let m = self.mem.iter().map(|(n, c, p)| format!("{n} {c}/{p}")).collect::<Vec<_>>().join(", ");
        if self.series_max.is_empty() {
            return format!("{t} | mem MB (now/peak): {m}");
        }
        let s = self.series_max.iter().map(|(n, c)| format!("{n} {c}")).collect::<Vec<_>>().join(", ");
        format!("{t} | mem MB (now/peak): {m} | max INSIDE each phase (sampled): {s}")
    }
    /// The sum of every phase.
    #[must_use]
    pub fn total(&self) -> std::time::Duration {
        self.phases.iter().map(|(_, d)| *d).sum()
    }
}

/// [`prove_committed_with`] over a UNIFORM instance: the matrices are proven by the matrix argument against the
/// FIXED commitment of the template's columns (its root is the release constant `fixed_commitment_root`), opened
/// at the argument's final point by a second WHIR proof at `fixed_params`. The instance is never materialized
/// (§M6-P): `A·z, B·z, C·z` are streamed from the template, satisfaction is checked on those tables, and the
/// sumchecks run in [`run_core_uniform`].
pub fn prove_committed_uniform(u: &UniformR1cs, io: &[Fa4], w: &[Fa4], params: CarrierParams, fixed_params: CarrierParams) -> Option<Vec<u8>> {
    prove_committed_uniform_profiled(u, io, w, params, fixed_params).map(|(bytes, _)| bytes)
}

/// [`prove_committed_uniform`] with the prover's phase profile beside the bytes: `fixed_columns`, `commit_w`,
/// `commit_f`, `ood`, `stream_abc`, `sumchecks` (the two sumchecks and the matrix argument), `recommit`, `claims`,
/// `open_w`, `open_f`, `encode` — what the certificate step prints, so the DSYNC certify cost has named parts.
pub fn prove_committed_uniform_profiled(u: &UniformR1cs, io: &[Fa4], w: &[Fa4], params: CarrierParams, fixed_params: CarrierParams) -> Option<(Vec<u8>, ProveProfile)> {
    prove_committed_uniform_owned_profiled(u, io, w.to_vec(), params, fixed_params)
}

/// [`prove_committed_uniform_profiled`] over a witness the caller hands over.
/// ⛔ DB-371 (lane stable 2026-11-02) — THE WITNESS IS MOVED IN, NEVER COPIED. The certificate prover emulated its program into a
/// `Trace` and proved `&trace.w`, which this function then copied (`to_vec`) into the half it commits: the caller's trace
/// (2^28 words, 1 GiB at the release shape) stayed alive beside the copy for the WHOLE prove. MEASURED (release-shape
/// profile under the node's allocator, stable/prof5.log): `fixed_columns` already at 2,088 MB — two copies of the
/// witness before the first commit. The certificate door now hands its trace over (`prove_certificate_step`,
/// `prove_genesis_certificate`); the borrowed form above still copies for callers that keep their witness. cons: none.
pub fn prove_committed_uniform_owned_profiled(u: &UniformR1cs, io: &[Fa4], w: Vec<Fa4>, params: CarrierParams, fixed_params: CarrierParams) -> Option<(Vec<u8>, ProveProfile)> {
    let shape = u.shape();
    if !shape.committable() || io.len() != shape.io_len || w.len() > shape.w_off() {
        return None;
    }
    let mut profile = ProveProfile::default();
    let mut since = std::time::Instant::now();
    let mut w_half = w;
    w_half.resize(shape.w_off(), Fa4::ZERO);
    let f = FixedColumns::of(u);
    let fref = &f;
    profile.mark("fixed_columns", &mut since);
    // The tables are streamed INSIDE the core driver — after the commitment (whose codeword and tree are dropped by
    // then) — so they never coexist with the commit's working set. An unsatisfying witness is refused there, after
    // one commit's work; the honest path never pays that. RAM: MEASURED 2026-09-28 14:41 (fixpoint run 2, the tables
    // streamed before the commit): peak RSS 5.19 GB at T = 2^14; the three base tables (1.5 GB) sat beside the
    // commit's codeword, tree and witness copy. MUST-STAY-GREEN: the equality pin (the sumcheck math is untouched).
    let core_phases: std::cell::RefCell<Vec<(&'static str, std::time::Duration)>> = std::cell::RefCell::new(Vec::new());
    let core_ref = &core_phases;
    let bytes = prove_committed_inner(
        &shape,
        io,
        w_half,
        params,
        Some((fref, fixed_params)),
        move |ch, w| {
            let t0 = std::time::Instant::now();
            let tables = stream_abc(u, io, w)?;
            if !tables.satisfied() {
                return None;
            }
            let t1 = std::time::Instant::now();
            let out = run_core_uniform(ch, u, io, w, tables, Some(fref));
            core_ref.borrow_mut().extend([("stream_abc", t1.duration_since(t0)), ("sumchecks", t1.elapsed())]);
            Some(out)
        },
        &mut profile,
    )?;
    // the core's own split replaces its one entry
    if let Some(pos) = profile.phases.iter().position(|(n, _)| *n == "core") {
        let sub = core_phases.into_inner();
        profile.phases.splice(pos..=pos, sub);
    }
    Some((bytes, profile))
}

/// The fixed columns as one table (one polynomial per column) — the polynomial the fixed commitment commits to.
pub fn fixed_table(f: &FixedColumns) -> Table<Fa4> {
    Table::new(f.cols.iter().map(|c| Poly::<Fa4>::new(c.clone())).collect())
}

/// The release constant: the fixed commitment's root at `fixed_params`. The fixed table is PUBLIC release data, so its
/// salts come from the one public salt source (`committed_air::fixed_table_salts`, DB-382) and the root is the same on
/// every machine; the transcript used here is a throwaway — the root does not depend on it.
pub fn fixed_commitment_root(f: &FixedColumns, fixed_params: CarrierParams) -> Commitment {
    let fwitness = PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(f)], fixed_params.first_fold);
    let fpcs = crate::committed_air::pcs_with_salts(fwitness.num_variables(), fixed_params, crate::committed_air::fixed_table_salts());
    let mut throwaway = Chl::new(Perm16::new_from_rng_128(&mut SmallRng::seed_from_u64(crate::committed_air::COMMITTED_AIR_SEED)));
    PrefixProver::<Fa4, Ea4>::commit(&fpcs.dft, &fpcs.mmcs, &mut throwaway, fwitness, fixed_params.first_fold, fixed_params.start_rate).1
}

/// The committed argument around a core driver: `w_half` is the witness half in full (`w_off` words, already
/// checked to satisfy the instance by the caller), `core` runs the two sumchecks on the transcript after the
/// commitments, reading the witness half it is handed ([`run_core`] on a laid `z` for a plain instance,
/// [`run_core_uniform`] streamed for a uniform one).
///
/// RAM (§M6-P): the witness commitment is made from a COPY of the witness half, and that copy, the codeword and the
/// Merkle tree are DROPPED once the commitment and its OOD answers are on the transcript; they are rebuilt for the
/// opening after the sumchecks. A fresh PCS built from the SAME per-prove SECRET seed (DB-382: `fresh_prover_seed`, 256 OS
/// bits drawn once at step 0 — never
/// a public constant) draws the same salts, so the rebuilt root must equal the absorbed one — checked, fail-closed —
/// and the OOD claims are re-registered on a clone of the transcript taken before they were first drawn, and must
/// yield the same answers — checked. ROOT-LAYER: the prover's memory is spent HERE, where the commitment is held;
/// the rebuild costs one extra LDE + tree (seconds at 2^27) and changes no byte of the transcript or the proof.
/// MEASURED 2026-09-28 (run m6p14, T = 2^14): with the codeword + tree held through the sumchecks the prover peaked
/// at 3.97 GB RSS and was killed by memory pressure on the 16 GB machine beside a five-daemon run; the rebuilt-commit
/// path's peak is measured by run m6p14b. MUST-STAY-GREEN: every committed-proof pin (plain and uniform), byte-flip
/// included — the proof bytes are unchanged by construction.
fn prove_committed_inner(
    r1cs: &R1cs,
    io: &[Fa4],
    w_half: Vec<Fa4>,
    params: CarrierParams,
    fixed: Option<(&FixedColumns, CarrierParams)>,
    core: impl FnOnce(&mut Chl, &[Fa4]) -> Option<(SpartanCore, Vec<Ea4>, Option<(MatrixProof, Vec<Ea4>)>)>,
    profile: &mut ProveProfile,
) -> Option<Vec<u8>> {
    if !r1cs.committable() || io.len() != r1cs.io_len || w_half.len() != r1cs.w_off() {
        eprintln!("[spartan] REFUSED: the instance is not committable, or the io / witness-half lengths do not match its shape");
        return None;
    }
    let mut since = std::time::Instant::now();
    profile.start_series(); // DB-371: the footprint sampler for the whole prove (a no-op without its flag)
    // 0. The witness half as ONE multilinear, committed before any challenge exists.
    // ⛔ DB-371 (lane stable 2026-11-02) — MOVED IN, TAKEN BACK, NEVER COPIED. This committed `w_half.clone()` and kept the
    // original beside it until the OOD answers: two copies of the 2^28-word witness (1 GiB each at the release shape) next
    // to the layout's stacked polynomial and the tree — MEASURED (`heap` on the profile pin, T = 2^15, inside `commit_w`):
    // three live 1 GiB blocks. The words now go into the commit and come back out of the spent layout
    // (`PrefixProver::into_tables`) once the OOD claims are registered — the same words, so the core, the rebuild and every
    // byte of the proof are unchanged. cons: none — one fewer 1 GiB copy from `commit_w` through `ood`, no time added.
    let w_len = w_half.len();
    let table = Table::new(vec![Poly::<Fa4>::new(w_half)]);
    // H12 path B: the layout's folding block is the carrier's FIRST fold (the WHIR prover asserts it equals the config's round-0 factor)
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    // DB-382: ONE secret seed per prove — this commitment and its rebuild at 2' draw the same salts from it
    let salt_seed = crate::whir_rec_block::fresh_prover_seed();
    let pcs = crate::committed_air::pcs_with_salts(witness.num_variables(), params, SmallRng::from_seed(salt_seed));
    let mut ch = transcript(r1cs, io);
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut ch, witness, params.first_fold, params.start_rate);
    profile.mark("commit_w", &mut since);
    // 0'. The FIXED commitment (uniform instances): the template's columns, committed on the same transcript right
    // after the witness (its root is the release constant the verifier observes here).
    let mut fixed_ctx = fixed.map(|(f, fp)| {
        let fwitness = PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(f)], fp.first_fold);
        // the fixed table is public release data: its salts are the one public salt source, so its root is the
        // release constant the verifier observes (`committed_air::fixed_table_salts`)
        let fpcs = crate::committed_air::pcs_with_salts(fwitness.num_variables(), fp, crate::committed_air::fixed_table_salts());
        let (flayout, _froot, fdata) = PrefixProver::<Fa4, Ea4>::commit(&fpcs.dft, &fpcs.mmcs, &mut ch, fwitness, fp.first_fold, fp.start_rate);
        let fopen = fpcs.config.empty_proof();
        (f, fpcs, flayout, fdata, fopen)
    });
    profile.mark("commit_f", &mut since);
    // The OOD claims: the FIXED commitment's first (its univariates sit deepest in the certificate's `Y` bank, where
    // the witness WHIR's closing identity leaves them for the fixed WHIR's), then the witness's.
    if let Some((_, fpcs, flayout, _, fopen)) = fixed_ctx.as_mut() {
        fopen.initial_ood_answers = (0..fpcs.config.commitment_ood_samples).map(|_| flayout.add_virtual_eval(&mut ch)).collect();
    }
    let mut open = pcs.config.empty_proof();
    let ch_before_ood = ch.clone();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut ch)).collect();
    drop((merkle_data, pcs));
    // the words back out of the spent layout (its stacked polynomial is dropped here); the commit padded nothing
    let w_half: Vec<Fa4> = layout.into_tables().into_iter().next()?.into_polys().into_iter().next()?.into_vec();
    if w_half.len() != w_len {
        eprintln!("[spartan] REFUSED: the committed witness came back with a different length (the commit padded it)");
        return None;
    }
    core_mem_mark("ood: the witness commitment dropped");
    profile.mark("ood", &mut since);
    // 1–2. The sumchecks (and the matrix argument), on challenges drawn after the commitments.
    let (mut core, r_y, matrix) = core(&mut ch, &w_half)?;
    profile.mark("core", &mut since);
    // 2'. The witness commitment rebuilt for the opening: the same words, a fresh PCS from the SAME secret salt seed
    // (DB-382), a throwaway challenger — the root must be the one the transcript absorbed, and the OOD claims
    // re-registered on the pre-OOD clone must be the answers already sent. Either mismatch is refused (no proof is emitted).
    let table = Table::new(vec![Poly::<Fa4>::new(w_half)]);
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = crate::committed_air::pcs_with_salts(witness.num_variables(), params, SmallRng::from_seed(salt_seed));
    let mut throwaway = Chl::new(Perm16::new_from_rng_128(&mut SmallRng::seed_from_u64(crate::committed_air::COMMITTED_AIR_SEED)));
    let (mut layout, rebuilt_root, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut throwaway, witness, params.first_fold, params.start_rate);
    // Every refusal below names itself: a prover that returns `None` silently cost a bisection on 2026-09-28 (the
    // determinism pin's first prove refused under two different parallel trees with no line saying which check).
    if postcard::to_allocvec(&rebuilt_root).ok()? != postcard::to_allocvec(&commitment).ok()? {
        eprintln!("[spartan] REFUSED: the rebuilt witness commitment's root differs from the absorbed one (the commit is not a function of the words alone)");
        return None;
    }
    let mut ch_ood = ch_before_ood;
    let ood_again: Vec<Ea4> = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut ch_ood)).collect();
    if ood_again != open.initial_ood_answers {
        eprintln!("[spartan] REFUSED: the re-registered OOD answers differ from the ones sent");
        return None;
    }
    profile.mark("recommit", &mut since);
    // 3. The ONE witness claim, at the sumcheck's own point, registered against the commitment; then the fixed
    // commitment's `n_cols` claims at the matrix argument's point (34 on the R = 2^14 template); the block padded to
    // an even count (`claims_pad`); then BOTH batching challenges (`α_w`, `α_f`) before either opening runs — the
    // certificate folds both claimed sums while the openings and OOD answers are still in its `F` bank (the witness
    // WHIR's traffic then overwrites them).
    let n_claims = 1 + fixed.map_or(0, |(f, _)| f.n_cols());
    let pt = pcs_point(&r_y[..r1cs.w_vars()]);
    let evals = layout.eval_at(0, &[0], &pt, &mut ch);
    let claimed = *evals.first()?;
    if claimed != core.w_eval {
        eprintln!("[spartan] REFUSED: the layout's witness evaluation differs from the core's w_eval (a convention fault on the point)");
        return None;
    }
    core.w_eval = claimed;
    let fixed_ctx = match fixed_ctx {
        Some((f, fpcs, mut flayout, fdata, fopen)) => {
            let (mp, rho) = matrix?;
            let fpt = pcs_point(&rho);
            let cols: Vec<usize> = (0..f.n_cols()).collect();
            let fevals = flayout.eval_at(0, &cols, &fpt, &mut ch);
            if fevals != mp.openings {
                eprintln!("[spartan] REFUSED: the fixed layout's column evaluations differ from the matrix argument's openings");
                return None;
            }
            Some((mp, fpcs, flayout, fdata, fopen))
        }
        None => None,
    };
    absorb_claims_pad(&mut ch, n_claims);
    let alpha_w: Ea4 = ch.sample_algebra_element();
    let alpha_f: Option<Ea4> = fixed_ctx.as_ref().map(|_| ch.sample_algebra_element());
    profile.mark("claims", &mut since);
    // 4. The witness opening, then the fixed commitment's opening (the second WHIR proof).
    pcs.prove_with_alpha(alpha_w, &mut open, &mut ch, layout, merkle_data);
    profile.mark("open_w", &mut since);
    let (matrix, fixed_open) = match fixed_ctx {
        Some((mp, fpcs, flayout, fdata, mut fopen)) => {
            fpcs.prove_with_alpha(alpha_f?, &mut fopen, &mut ch, flayout, fdata);
            (Some(mp), Some(fopen))
        }
        None => (None, None),
    };
    profile.mark("open_f", &mut since);
    let bytes = postcard::to_allocvec(&SpartanCommittedProof { commitment, core, open, matrix, fixed_open }).ok();
    profile.mark("encode", &mut since);
    profile.finish_series(); // DB-371: stop the sampler and print the raw series (under its flag)
    bytes
}

/// VERIFY the committed argument against the public instance `(r1cs, io)`. Fail-closed on any decode, shape,
/// transcript, identity or opening mismatch. A byte string that is not a proof is REFUSED (the decode failure is
/// the refusal, exactly as every carrier verifier in this crate behaves).
/// The PCS a committed Spartan proof over `r1cs` is verified with: the witness half's stacked variable count
/// under `PrefixProver`'s layout, at the live carrier parameters. ONE derivation, shared by the native verifier
/// and the recursive verifier's gadget pins (which read `config.round_parameters` from it).
pub(crate) fn committed_pcs(r1cs: &R1cs) -> crate::committed_air::Pcs {
    committed_pcs_with(r1cs, CarrierParams::LIVE)
}
pub(crate) fn committed_pcs_with(r1cs: &R1cs, params: CarrierParams) -> crate::committed_air::Pcs {
    let t = Table::new(vec![Poly::<Fa4>::new(vec![Fa4::ZERO; r1cs.w_off()])]);
    let stacked = PrefixProver::<Fa4, Ea4>::new_witness(vec![t], params.first_fold).num_variables();
    pcs_with(stacked, params)
}

#[must_use]
pub fn verify_committed(r1cs: &R1cs, io: &[Fa4], bytes: &[u8]) -> bool {
    verify_committed_with(r1cs, io, bytes, CarrierParams::LIVE)
}

/// [`verify_committed`] at explicit carrier parameters — the pair of [`prove_committed_with`].
#[must_use]
pub fn verify_committed_with(r1cs: &R1cs, io: &[Fa4], bytes: &[u8], params: CarrierParams) -> bool {
    verify_committed_inner(r1cs, io, bytes, params, None, &|eq_x, eq_y, coef| Some(stored_mle(r1cs, &eq_x, &eq_y, coef)))
}

/// ⭐ VERIFY A PLAIN INSTANCE WHOSE MATRICES ARE NEVER LAID (lane vaults, 2026-11-15): `shape` carries only the instance's
/// dimensions, and `mle_of` folds `ra·Ã(r_x, r_y) + rb·B̃ + rc·C̃` from a replay of the circuit's own builder
/// (`spartan_gadgets::Sink::Mle`) — the same value the stored matrices give, so a proof verifies here exactly when it
/// verifies against the laid instance (`the_streamed_argument_equals_the_stored_one`). RAM: the two `eq` tables and the
/// replay's assignment, never the entries (MEASURED: one custody audit's matrices are 3.1 GB, 133 M entries).
#[must_use]
pub fn verify_committed_streamed(shape: &R1cs, io: &[Fa4], bytes: &[u8], mle_of: MleOf<'_>) -> bool {
    shape.a.is_empty() && shape.b.is_empty() && shape.c.is_empty() && verify_committed_inner(shape, io, bytes, CarrierParams::LIVE, None, mle_of)
}

/// ⭐ PROVE A PLAIN INSTANCE WHOSE MATRICES ARE NEVER LAID (lane vaults, 2026-11-15): `shape` carries only the dimensions,
/// `abc` the products `A·z`, `B·z`, `C·z` a streaming build folded as it made each entry (`spartan_gadgets::Sink::Abc`),
/// `w` the witness half, and `mr_of` replays the circuit into `M_r` from `eq(r_x, ·)` and `(ra, rb, rc)`
/// (`spartan_gadgets::Sink::Mr`; `None`: the replay could not form). The core, the commitment and the openings are
/// [`prove_committed`]'s: the same round messages over the same field values. Refused when a row does not hold
/// (`(A·z)·(B·z) ≠ C·z`), exactly where the stored prover refuses an unsatisfied instance.
/// RAM: the products, the witness and the core's tables — never the entries. cons: the caller builds the circuit a second
/// time for `M_r` (MEASURED below in the custody audit's pin).
#[must_use]
pub fn prove_committed_streamed(shape: &R1cs, io: &[Fa4], w: &[Fa4], abc: [Vec<Fa4>; 3], mr_of: impl FnOnce(Vec<Ea4>, [Ea4; 3]) -> Option<Vec<Ea4>>) -> Option<Vec<u8>> {
    if !shape.committable() || !(shape.a.is_empty() && shape.b.is_empty() && shape.c.is_empty()) {
        return None;
    }
    let rows = shape.rows();
    if abc.iter().any(|t| t.len() != rows) {
        eprintln!("[spartan] REFUSED: a streamed product does not span the instance's rows");
        return None;
    }
    if (0..rows).any(|r| abc[0][r] * abc[1][r] != abc[2][r]) {
        return None;
    }
    let z = shape.lay_z(io, w)?;
    let w_half = z[shape.w_off()..].to_vec();
    let cols = shape.cols();
    let mut profile = ProveProfile::default();
    prove_committed_inner(
        shape,
        io,
        w_half,
        CarrierParams::LIVE,
        None,
        |ch, _w| {
            let mut failed = false;
            let core = run_core_from(
                ch,
                shape,
                &z,
                abc,
                |eq_rx, coef| match mr_of(eq_rx, coef).filter(|m| m.len() == cols) {
                    Some(m) => m,
                    None => {
                        failed = true;
                        vec![Ea4::ZERO; cols]
                    }
                },
                None,
            );
            if failed {
                eprintln!("[spartan] REFUSED: the streamed replay of M_r did not form");
                return None;
            }
            Some(core)
        },
        &mut profile,
    )
}

/// [`verify_committed_with`] over a UNIFORM instance against the release root of the template's fixed
/// commitment — the pair of [`prove_committed_uniform`].
#[must_use]
pub fn verify_committed_uniform(u: &UniformR1cs, io: &[Fa4], bytes: &[u8], params: CarrierParams, fixed_params: CarrierParams, fixed_root: &Commitment) -> bool {
    // the SHAPE only: the verifier reads `m_vars/n_vars/io_len` and the closed form — never a materialized matrix
    // (§M6-P; MEASURED before it: `verify_core_traced` also laid a 2^w_vars public half, 2^27 words at T = 2^14)
    let r1cs = u.shape();
    let f = FixedColumns::of(u);
    verify_committed_inner(&r1cs, io, bytes, params, Some((&f, fixed_params, fixed_root)), &|_, _, _| None)
}

fn verify_committed_inner(r1cs: &R1cs, io: &[Fa4], bytes: &[u8], params: CarrierParams, fixed: Option<(&FixedColumns, CarrierParams, &Commitment)>, mle_of: MleOf<'_>) -> bool {
    let p: SpartanCommittedProof = match postcard::from_bytes(bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !r1cs.committable() || io.len() != r1cs.io_len {
        return false;
    }
    let pcs = committed_pcs_with(r1cs, params);
    let mut ch = transcript(r1cs, io);
    ch.observe(p.commitment.clone());
    for mask_commit in &p.open.hvzk_mask_commits {
        ch.observe(mask_commit.clone());
    }
    // the fixed commitment: exactly when the instance is uniform, its root (the release constant) and its opening
    let fixed_ctx = match fixed {
        Some((f, fp, froot)) => {
            let (Some(mp), Some(fopen)) = (&p.matrix, &p.fixed_open) else {
                return false;
            };
            let fwitness_vars = PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(f)], fp.first_fold).num_variables();
            let fpcs = pcs_with(fwitness_vars, fp);
            ch.observe(froot.clone());
            for mask_commit in &fopen.hvzk_mask_commits {
                ch.observe(mask_commit.clone());
            }
            Some((f, fpcs, froot, mp, fopen))
        }
        None => {
            if p.matrix.is_some() || p.fixed_open.is_some() {
                return false; // a plain instance carries no matrix argument: one encoding
            }
            None
        }
    };
    // the OOD claims, the fixed commitment's first (the prover's order; see `prove_committed_inner`)
    let mut flv = fixed_ctx.as_ref().map(|(f, _, _, _, _)| {
        let fshapes = vec![TableShape::new(f.nnz_bits, f.n_cols())];
        LayoutVerifier::<Fa4, Ea4>::new(&fshapes, PrefixProver::<Fa4, Ea4>::strategy())
    });
    if let (Some((_, fpcs, _, _, fopen)), Some(flv)) = (fixed_ctx.as_ref(), flv.as_mut()) {
        if fopen.initial_ood_answers.len() != fpcs.config.commitment_ood_samples {
            return false;
        }
        for &eval in &fopen.initial_ood_answers {
            flv.add_virtual_eval(eval, &mut ch);
        }
    }
    let shapes = vec![TableShape::new(r1cs.w_vars(), 1)];
    let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
    if p.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples {
        return false;
    }
    for &eval in &p.open.initial_ood_answers {
        lv.add_virtual_eval(eval, &mut ch);
    }
    let Some((r_y, _trace, rho)) = verify_core_src(&mut ch, r1cs, io, &p.core, fixed_ctx.as_ref().map(|(f, _, _, mp, _)| (*f, *mp)), mle_of) else {
        return false;
    };
    // the witness claim, the fixed claims, the block's pad, then BOTH batching challenges before either opening is
    // verified
    let n_claims = 1 + fixed_ctx.as_ref().map_or(0, |(f, _, _, _, _)| f.n_cols());
    let pt = pcs_point(&r_y[..r1cs.w_vars()]);
    lv.add_claim_at(0, &[0], &[p.core.w_eval], &pt, &mut ch);
    let fixed_ready = match (fixed_ctx, flv.as_mut(), rho) {
        (Some((f, fpcs, froot, mp, fopen)), Some(flv), Some(rho)) => {
            let fpt = pcs_point(&rho);
            let cols: Vec<usize> = (0..f.n_cols()).collect();
            if mp.openings.len() != cols.len() {
                return false;
            }
            flv.add_claim_at(0, &cols, &mp.openings, &fpt, &mut ch);
            Some((fpcs, froot, fopen))
        }
        (None, None, None) => None,
        _ => return false,
    };
    absorb_claims_pad(&mut ch, n_claims);
    let alpha_w: Ea4 = ch.sample_algebra_element();
    let alpha_f: Option<Ea4> = fixed_ready.as_ref().map(|_| ch.sample_algebra_element());
    let pcs_constraint = lv.constraint(alpha_w);
    let mut claimed = Ea4::ZERO;
    pcs_constraint.combine_evals(&mut claimed);
    let v = WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
    if v.verify(&p.open, &mut ch, &p.commitment, pcs_constraint, claimed).is_err() {
        return false;
    }
    match (fixed_ready, flv, alpha_f) {
        (Some((fpcs, froot, fopen)), Some(flv), Some(alpha_f)) => {
            let fconstraint = flv.constraint(alpha_f);
            let mut fclaimed = Ea4::ZERO;
            fconstraint.combine_evals(&mut fclaimed);
            let fv = WhirVerifier::new(&fpcs.config, &fpcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
            fv.verify(fopen, &mut ch, froot, fconstraint, fclaimed).is_ok()
        }
        (None, None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::Field;

    /// A tiny R1CS builder: multiplication gates over variables; `z[0]` is the constant one.
    struct Builder {
        a: Sparse,
        b: Sparse,
        c: Sparse,
        rows: usize,
        next_var: usize,
    }
    impl Builder {
        fn new(first_var: usize) -> Self {
            Builder { a: Vec::new(), b: Vec::new(), c: Vec::new(), rows: 0, next_var: first_var }
        }
        /// z[out] = z[x] · z[y]
        fn mul(&mut self, x: usize, y: usize) -> usize {
            let out = self.next_var;
            self.next_var += 1;
            self.a.push((self.rows, x, Fa4::ONE));
            self.b.push((self.rows, y, Fa4::ONE));
            self.c.push((self.rows, out, Fa4::ONE));
            self.rows += 1;
            out
        }
        /// z[x] · 1 = z[y]  (an equality gate)
        fn eq(&mut self, x: usize, y: usize) {
            self.a.push((self.rows, x, Fa4::ONE));
            self.b.push((self.rows, 0, Fa4::ONE));
            self.c.push((self.rows, y, Fa4::ONE));
            self.rows += 1;
        }
    }

    fn log2_ceil(n: usize) -> usize {
        (usize::BITS - (n.max(1) - 1).leading_zeros()) as usize
    }

    /// x_{k+1} = x_k², `steps` times, from public x_0 to public x_out; every intermediate is witness.
    /// z = [1, x0, x_out, 0… | x_1 … x_{steps}, 0…]; the witness half is at least 2^COMMITTED_FOLDING tall.
    fn squaring_chain(steps: usize) -> (R1cs, Vec<Fa4>, Vec<Fa4>) {
        let half = (1usize << log2_ceil(steps.max(3) + 1)).max(1 << MIN_W_VARS);
        let n_vars = log2_ceil(half) + 1;
        let w_off = half;
        let mut b = Builder::new(w_off);
        let (x0, x_out) = (1usize, 2usize);
        let mut cur = x0;
        for _ in 0..steps {
            cur = b.mul(cur, cur);
        }
        b.eq(cur, x_out);
        let m_vars = log2_ceil(b.rows).max(1);
        let r1cs = R1cs { m_vars, n_vars, io_len: 2, a: b.a, b: b.b, c: b.c };
        let x = Fa4::from_u64(3);
        let mut vals = Vec::with_capacity(steps);
        let mut v = x;
        for _ in 0..steps {
            v = v * v;
            vals.push(v);
        }
        (r1cs, vec![x, v], vals)
    }

    /// M1's core alone: verify the sumchecks with `w_eval` taken at its word (the unbound shape, test-only).
    fn verify_core_only(r1cs: &R1cs, io: &[Fa4], core: &SpartanCore) -> bool {
        let mut ch = transcript(r1cs, io);
        verify_core(&mut ch, r1cs, io, core).is_some()
    }
    fn prove_core_only(r1cs: &R1cs, io: &[Fa4], z: &[Fa4]) -> SpartanCore {
        let mut ch = transcript(r1cs, io);
        run_core(&mut ch, r1cs, z, None).0
    }

    #[test]
    fn the_sumcheck_core_alone_verifies_an_honest_chain_and_refuses_a_wrong_public() {
        for steps in [3usize, 40, 200] {
            let (r1cs, io, w) = squaring_chain(steps);
            let z = r1cs.lay_z(&io, &w).expect("lays");
            assert!(r1cs.is_satisfied(&z), "calibration: the honest assignment satisfies the R1CS");
            let core = prove_core_only(&r1cs, &io, &z);
            assert!(verify_core_only(&r1cs, &io, &core), "M1 core: the honest messages verify (steps {steps})");
            let mut other_io = io.clone();
            other_io[1] += Fa4::ONE;
            assert!(!verify_core_only(&r1cs, &other_io, &core), "a moved public input must refuse");
            // a cheating prover that runs the protocol on an unsatisfying witness is refused by the outer sumcheck
            let mut bad_w = w.clone();
            bad_w[steps / 2] += Fa4::ONE;
            let z_bad = r1cs.lay_z(&io, &bad_w).expect("lays");
            assert!(!r1cs.is_satisfied(&z_bad));
            assert!(!verify_core_only(&r1cs, &io, &prove_core_only(&r1cs, &io, &z_bad)), "⛔ an unsatisfying witness verified");
        }
    }

    #[test]
    fn an_honest_squaring_chain_proves_and_verifies_committed() {
        for steps in [20usize, 40, 200] {
            let (r1cs, io, w) = squaring_chain(steps);
            let bytes = prove_committed(&r1cs, &io, &w).expect("the honest chain proves on the committed argument");
            assert!(verify_committed(&r1cs, &io, &bytes), "the committed proof verifies (steps {steps})");
            eprintln!(
                "[spartan-m2] steps {steps}: {} constraints (2^{}), z 2^{}, witness 2^{} committed, proof {} B",
                r1cs.rows(),
                r1cs.m_vars,
                r1cs.n_vars,
                r1cs.w_vars(),
                bytes.len()
            );
        }
    }

    #[test]
    fn the_committed_argument_refuses_a_wrong_public_a_bad_witness_garbage_and_a_truncation() {
        let (r1cs, io, w) = squaring_chain(40);
        let bytes = prove_committed(&r1cs, &io, &w).expect("proves");
        let mut other_io = io.clone();
        other_io[1] += Fa4::ONE;
        assert!(!verify_committed(&r1cs, &other_io, &bytes), "a moved public input must refuse");
        let mut bad_w = w.clone();
        bad_w[7] += Fa4::ONE;
        assert!(prove_committed(&r1cs, &io, &bad_w).is_none(), "the prover refuses an unsatisfying witness");
        assert!(!verify_committed(&r1cs, &io, &[]), "an empty proof is refused");
        assert!(!verify_committed(&r1cs, &io, &bytes[..bytes.len() / 2]), "a truncated proof is refused");
        assert!(!verify_committed(&r1cs, &io, &vec![0xA5u8; bytes.len()]), "garbage is refused");
    }

    /// The cheater's messages: ZERO outer tables (0·0 − 0 = 0 satisfies the zero claim at every round, so `abc` is
    /// (0,0,0) and the inner claim is 0), then a witness half chosen AFTER the challenges so that
    /// Σ_y M_r(y)·z(y) = 0 — one linear equation in one free witness cell — and an honest inner sumcheck over
    /// that z. Every identity the core checks holds; no constraint of the R1CS does.
    fn forge_core_on(ch: &mut Chl, r1cs: &R1cs, io: &[Fa4]) -> (SpartanCore, Vec<Fa4>) {
        let tau: Vec<Ea4> = (0..r1cs.m_vars).map(|_| draw(ch)).collect();
        let zero_tab = vec![Ea4::ZERO; r1cs.rows()];
        let mut eq_t = eq_table(&tau);
        let (mut az, mut bz, mut cz) = (zero_tab.clone(), zero_tab.clone(), zero_tab);
        let mut outer = Vec::new();
        let mut r_x = Vec::new();
        for _ in 0..r1cs.m_vars {
            let eab = round_evals(&[&eq_t, &az, &bz], 3);
            let ec = round_evals(&[&eq_t, &cz], 3);
            let h: Vec<Ea4> = eab.iter().zip(&ec).map(|(x, y)| *x - *y).collect();
            let h = coeffs_from_evals(&h);
            for &e in &h {
                absorb(ch, e);
            }
            let r = draw(ch);
            eq_t = fold_at(&eq_t, r);
            az = fold_at(&az, r);
            bz = fold_at(&bz, r);
            cz = fold_at(&cz, r);
            outer.push(h);
            r_x.push(r);
        }
        let abc = [az[0], bz[0], cz[0]];
        for e in abc {
            absorb(ch, e);
        }
        let (ra, rb, rc) = (draw(ch), draw(ch), draw(ch));
        let eq_rx = eq_table(&r_x);
        let mut mr = vec![Ea4::ZERO; r1cs.cols()];
        for (mat, coef) in [(&r1cs.a, ra), (&r1cs.b, rb), (&r1cs.c, rc)] {
            for &(r, c, v) in mat {
                mr[c] += eq_rx[r] * coef * Ea4::from(v);
            }
        }
        // Σ_y mr(y)·z(y) must be 0 = claim2. The public half is fixed; solve ONE witness cell for it. The cell must
        // be a BASE-field value while mr is an extension value, so pick a cell k whose mr(k) is a base-field scalar
        // multiple… in general none is; the cheater instead needs Σ over the witness half to hit an extension
        // target with base cells: 4 base cells against 4 extension coordinates — a small linear system the
        // cheater solves natively. Here: pick 4 witness cells and solve.
        let w_off = r1cs.w_off();
        let pub_sum: Ea4 = (0..w_off).fold(Ea4::ZERO, |acc, y| {
            let zy = if y == 0 { Fa4::ONE } else if y <= io.len() { io[y - 1] } else { Fa4::ZERO };
            acc + mr[y] * Ea4::from(zy)
        });
        // target: Σ_{k<4} mr[w_off+k]·w_k = −pub_sum, w_k ∈ Fa4. Gaussian elimination over Fa4 on the 4×4 system
        // whose columns are the base-coordinate vectors of mr[w_off+k].
        let coords = |e: Ea4| -> [Fa4; 4] {
            let s = <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&e);
            [s[0], s[1], s[2], s[3]]
        };
        let mut m: Vec<Vec<Fa4>> = (0..4).map(|row| (0..4).map(|k| coords(mr[w_off + k])[row]).collect()).collect();
        let neg = -pub_sum;
        let mut rhs: Vec<Fa4> = coords(neg).to_vec();
        for col in 0..4 {
            let piv = (col..4).find(|&r| m[r][col] != Fa4::ZERO).expect("the 4 witness columns are independent for this instance");
            m.swap(col, piv);
            rhs.swap(col, piv);
            let inv = m[col][col].inverse();
            for i in 0..4 {
                m[col][i] *= inv;
            }
            rhs[col] *= inv;
            for r in 0..4 {
                if r != col {
                    let f = m[r][col];
                    if f != Fa4::ZERO {
                        for i in 0..4 {
                            let v = m[col][i];
                            m[r][i] -= f * v;
                        }
                        let rc_ = rhs[col];
                        rhs[r] -= f * rc_;
                    }
                }
            }
        }
        let w_cheat: Vec<Fa4> = rhs;
        let z_cheat = r1cs.lay_z(io, &w_cheat).expect("lays");
        let mut zt: Vec<Ea4> = z_cheat.iter().map(|&v| Ea4::from(v)).collect();
        let mut inner = Vec::new();
        let mut r_y = Vec::new();
        for _ in 0..r1cs.n_vars {
            let h = coeffs_from_evals(&round_evals(&[&mr, &zt], 2));
            for &e in &h {
                absorb(ch, e);
            }
            let r = draw(ch);
            mr = fold_at(&mr, r);
            zt = fold_at(&zt, r);
            inner.push(h);
            r_y.push(r);
        }
        let w_eval = mle_eval(&z_cheat[w_off..], &r_y[..r1cs.w_vars()]);
        (SpartanCore { outer, abc, inner, w_eval }, w_cheat)
    }

    /// ⭐⭐⭐ THE REASON M2 EXISTS, MEASURED. Without a commitment the witness is chosen AFTER the challenges: zero
    /// outer tables satisfy the zero claim, and one small linear system picks a witness half that makes the inner
    /// claim hold — the core accepts a statement with no satisfying witness behind it (CALIBRATION: the attack is
    /// armed). With the commitment absorbed before τ, the cheater must fix the witness half FIRST; the equation it
    /// later needs to satisfy is then already lost, and the opening proves the committed value, not the solved
    /// one (REFUTATION).
    #[test]
    fn the_unbound_witness_read_is_what_the_commitment_closes() {
        let (r1cs, io, _w) = squaring_chain(40);
        // CALIBRATION — the unbound core.
        let mut ch = transcript(&r1cs, &io);
        let (forged, w_cheat) = forge_core_on(&mut ch, &r1cs, &io);
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &w_cheat).unwrap()), "calibration: the forged witness satisfies nothing");
        assert!(
            verify_core_only(&r1cs, &io, &forged),
            "calibration: the M1 core must accept the post-challenge witness forgery, or M2 refutes nothing"
        );
        // REFUTATION — the same cheater under the commitment. It commits to the only witness half it can before
        // seeing anything (zeros), derives the challenges from that transcript, forges as above, and opens.
        let params = CarrierParams::LIVE;
        let committed_w = vec![Fa4::ZERO; r1cs.w_off()];
        let table = Table::new(vec![Poly::<Fa4>::new(committed_w)]);
        let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], COMMITTED_FOLDING);
        let pcs = pcs_with(witness.num_variables(), params);
        let mut ch2 = transcript(&r1cs, &io);
        let (mut layout, commitment, merkle_data) =
            PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut ch2, witness, COMMITTED_FOLDING, params.start_rate);
        let mut open = pcs.config.empty_proof();
        open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut ch2)).collect();
        let (forged2, _w2) = forge_core_on(&mut ch2, &r1cs, &io);
        // the inner sumcheck's point, replayed the way the verifier will derive it
        let mut chk = transcript(&r1cs, &io);
        chk.observe(commitment.clone());
        for e in &open.initial_ood_answers {
            let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&[TableShape::new(r1cs.w_vars(), 1)], PrefixProver::<Fa4, Ea4>::strategy());
            lv.add_virtual_eval(*e, &mut chk);
        }
        let r_y2 = verify_core(&mut chk, &r1cs, &io, &forged2).expect("the forged core passes the unbound identities under this transcript too");
        let pt = pcs_point(&r_y2[..r1cs.w_vars()]);
        let _ = layout.eval_at(0, &[0], &pt, &mut ch2);
        absorb_claims_pad(&mut ch2, 1); // the forgery follows the honest transcript exactly: refused on substance
        pcs.prove(&mut open, &mut ch2, layout, merkle_data);
        let bytes = postcard::to_allocvec(&SpartanCommittedProof { commitment, core: forged2, open, matrix: None, fixed_open: None }).unwrap();
        assert!(!verify_committed(&r1cs, &io, &bytes), "⛔ the committed verifier accepted a witness-free proof");
    }

    /// ⭐⭐⭐ §M6-P — the STREAMING prover (no materialized matrix, no laid `z`, split eq, structured `M_r`) sends
    /// the SAME messages as the materializing prover on the same transcript: (1) a template with every column kind,
    /// transition rows and boundary entries in BOTH halves at T ∈ {2, 4, 8}; (2) a one-row, one-local template (no
    /// row variable, no local variable: the flat-from-base paths) at T = 2^10; (3) the certificate's own
    /// universal-row template at T = 4 with the matrix argument riding. Checked per instance: the `SpartanCore`
    /// bytes, `r_y`, the matrix proof bytes and `ρ`, one further challenge drawn from each transcript, and that the
    /// streamed tables decide satisfaction exactly as the laid instance does.
    #[test]
    fn the_streaming_prover_equals_the_materialized_prover() {
        use crate::uniform_r1cs::{tests::sample_uniform, Col, UniformMatrix, UniformR1cs};
        fn w_of(seed: u64, n: usize) -> Vec<Fa4> {
            (0..n as u64).map(|i| Fa4::from_u64((seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ i.wrapping_mul(0xD1B5_4A32_D192_ED03)) >> 3)).collect()
        }
        fn compare(name: &str, u: &UniformR1cs, io: &[Fa4], w: &[Fa4], fixed: Option<&FixedColumns>) {
            let r1cs = u.materialize();
            let shape = u.shape();
            assert_eq!((shape.m_vars, shape.n_vars, shape.io_len), (r1cs.m_vars, r1cs.n_vars, r1cs.io_len), "{name}: shape");
            let mut wf = w.to_vec();
            wf.resize(u.w_off(), Fa4::ZERO);
            let z = r1cs.lay_z(io, &wf).expect("lays");
            let mut ch_old = transcript(&r1cs, io);
            let (core_old, ry_old, mat_old) = run_core(&mut ch_old, &r1cs, &z, fixed);
            let tables = stream_abc(u, io, &wf).expect("streams");
            assert_eq!(tables.satisfied(), r1cs.is_satisfied(&z), "{name}: the streamed tables must decide satisfaction as the laid instance does");
            let mut ch_new = transcript(&shape, io);
            let (core_new, ry_new, mat_new) = run_core_uniform(&mut ch_new, u, io, &wf, tables, fixed);
            assert_eq!(postcard::to_allocvec(&core_old).unwrap(), postcard::to_allocvec(&core_new).unwrap(), "{name}: the SpartanCore bytes differ");
            assert_eq!(ry_old, ry_new, "{name}: r_y differs");
            match (mat_old, mat_new) {
                (Some((mp_old, rho_old)), Some((mp_new, rho_new))) => {
                    assert_eq!(postcard::to_allocvec(&mp_old).unwrap(), postcard::to_allocvec(&mp_new).unwrap(), "{name}: the matrix proof differs");
                    assert_eq!(rho_old, rho_new, "{name}: ρ differs");
                }
                (None, None) => {}
                _ => panic!("{name}: one prover ran the matrix argument and the other did not"),
            }
            assert_eq!(draw(&mut ch_old), draw(&mut ch_new), "{name}: the transcripts diverge after the core");
            eprintln!(
                "[m6p] {name}: 2^{} constraints × 2^{} columns — core, r_y{} and the transcript are equal (satisfied: {})",
                r1cs.m_vars,
                r1cs.n_vars,
                if fixed.is_some() { ", matrix proof, ρ" } else { "" },
                r1cs.is_satisfied(&z)
            );
        }
        // (1) every column kind, transition rows, boundaries in the public half (the sample's) and the witness half
        for t_bits in [1usize, 2, 3] {
            let mut u = sample_uniform(t_bits);
            let steps = u.steps();
            u.a.boundary.push((u.row(0, 3), u.var(1, 3), Fa4::from_u64(29))); // step 1, local 3 (an odd index)
            u.c.boundary.push((u.row(steps - 1, 3), u.var(steps - 1, 0), Fa4::from_u64(31))); // the last step, local 0
            let io = vec![Fa4::from_u64(5), Fa4::from_u64(6)];
            let w = w_of(t_bits as u64, u.w_off());
            compare(&format!("all column kinds + both-half boundaries, T = 2^{t_bits}"), &u, &io, &w, None);
        }
        // (2) no row variable and no local variable: x_{g+1} = x_g · x_g on one template row
        {
            let one = Fa4::ONE;
            let t_bits = 10usize;
            let mut u = UniformR1cs { r_bits: 0, v_bits: 0, t_bits, io_len: 1, a: UniformMatrix::default(), b: UniformMatrix::default(), c: UniformMatrix::default() };
            u.a.template.push((0, Col::Local(0), one));
            u.b.template.push((0, Col::Local(0), one));
            u.c.template.push((0, Col::Next(0), one));
            let io = vec![Fa4::from_u64(3)];
            let mut w = vec![Fa4::ZERO; u.w_off()];
            w[0] = io[0];
            for g in 1..u.steps() {
                w[g] = w[g - 1] * w[g - 1];
            }
            compare("one row, one local (no row/local variable), T = 2^10", &u, &io, &w, None);
        }
        // (3) the certificate's template at T = 4, the matrix argument riding — the pin's own inner instance
        {
            use crate::universal_row::{emulate, flag, uniform_instance, RowFlags, IO_LEN, NREG, NSTREAM};
            use crate::verifier_program::ProgramBuilder;
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
            let (genesis_rows, _) = crate::acc_program::genesis_program(14);
            let digest_g = crate::acc_program::program_digest(&genesis_rows);
            let mut io_t = vec![Fa4::ZERO; IO_LEN];
            io_t[crate::universal_row::io_block(0)].copy_from_slice(&digest_g);
            io_t[crate::universal_row::io_block(3)].copy_from_slice(&crate::acc_program::genesis_state_hash());
            let trace_t = emulate(&p, &io_t, [Fa4::ZERO; NREG], &program_t, &stream_t);
            let f = FixedColumns::of(&u);
            compare("the universal-row template, T = 4, with the matrix argument", &u, &io_t, &trace_t.w, Some(&f));
        }
    }

    /// ⭐⭐⭐ DETERMINISM UNDER `parallel` (§M6-T, 2026-09-28): the same statement proven on the global rayon pool
    /// (10 workers here) and inside a ONE-thread pool (`ThreadPoolBuilder::num_threads(1)`; rayon runs nested parallel
    /// iterators on the pool that `install`s them, so every `par_iter` in Plonky3's DFT, Merkle, sumcheck and WHIR
    /// paths runs serially there) must yield the SAME BYTES — for a grinding plain instance (the two-word folding
    /// grinds, the one-word query grinds) and a uniform instance (the matrix argument and the fixed WHIR riding).
    /// Two nodes that cannot agree byte-for-byte cannot agree on a block: §CA (2026-09-15) measured exactly that with
    /// the feature on (same length, different bytes), attributed to Plonky3's `find_any` grind, since replaced by the
    /// chunked `min_by_key` grind. A red here turns the feature back off the same hour.
    #[test]
    fn a_parallel_prove_is_byte_identical_to_a_one_thread_prove() {
        let params = CarrierParams::legacy(4, 8);
        let one_thread = rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("a one-thread pool");
        assert!(rayon::current_num_threads() > 1, "the global pool has more than one worker on this machine ({})", rayon::current_num_threads());
        // (1) a grinding plain instance (`squaring_chain` returns `(r1cs, io, w)` — the first cut of this pin swapped
        // the last two and read the resulting `None` as a parallelism refusal for a whole afternoon; the prover now
        // names its refusals, and this pin's expectations name the check)
        let (r1cs, io, w) = squaring_chain(40);
        // DB-382: the blinding is fresh per prove in production; this pin measures the PROVER's determinism, so it pins
        // one seed for all three proves and releases it after.
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([7u8; 32]));
        let par1 = prove_committed_with(&r1cs, &io, &w, params).expect("proves (global pool)");
        let ser = one_thread.install(|| prove_committed_with(&r1cs, &io, &w, params).expect("proves (one thread)"));
        let par2 = prove_committed_with(&r1cs, &io, &w, params).expect("proves again (global pool)");
        assert_eq!(par1.len(), ser.len(), "plain: the proof lengths differ");
        assert!(par1 == ser, "⛔ NONDETERMINISTIC PROVING: the plain proof's bytes differ between the global pool and one thread ({} B)", par1.len());
        assert!(par1 == par2, "⛔ NONDETERMINISTIC PROVING: two proves on the global pool differ ({} B)", par1.len());
        assert!(verify_committed_with(&r1cs, &io, &par1, params));
        // The UNIFORM path (the streamed tables and the matrix argument, the decider's other direct-rayon loops) is
        // pinned byte-identical to the serial materialized prover by `the_streaming_prover_equals_the_materialized_prover`;
        // it is not repeated here on one thread because its fixed table's derived 29-bit folding grinds take ~10 minutes
        // on a single core (MEASURED 2026-09-28: the first cut of this pin ran past its 15-minute alarm there).
        eprintln!("[m6t] byte-identical on {} workers and on one thread: plain grinding instance {} B", rayon::current_num_threads(), par1.len());
    }

    /// MEASUREMENT, not a claim (run explicitly): the streaming prover on the certificate's template at
    /// `T = 2^M6P_T_BITS` (default 10; the fixpoint is 14) — the prove wall time, the proof bytes, and the native
    /// verify time against the shape-only verifier. Run under `/usr/bin/time -l` for the peak RSS.
    #[test]
    #[ignore]
    fn m6p_prover_at_the_certificate_template() {
        use crate::universal_row::{emulate, uniform_instance, RowFlags, IO_LEN, NREG, NSTREAM};
        let t_bits: usize = std::env::var("M6P_T_BITS").ok().and_then(|s| s.parse().ok()).unwrap_or(10); // the default the doc above names
        let p = crate::universal_row::tests::params();
        let u = uniform_instance(&p, IO_LEN, t_bits);
        let steps = 1usize << t_bits;
        let program: Vec<RowFlags> = (0..steps).map(|_| RowFlags::default()).collect();
        let stream = vec![[Fa4::ZERO; NSTREAM]; steps];
        let io = vec![Fa4::ZERO; IO_LEN];
        let t0 = std::time::Instant::now();
        let trace = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
        let t_emulate = t0.elapsed();
        // the certificate's carriers — ONE definition, the door's (`certificate_door`): the witness at rate 1/2 (the
        // two-adicity cap: 27 vars + log_inv_rate ≤ 28) with the final polynomial sent at 7 variables, the fixed
        // table at rate 1/16; the query-grinding bits are the door's release constants
        let params = crate::certificate_door::CERT_CARRIER;
        let fixed_params = crate::certificate_door::CERT_FIXED_CARRIER;
        let f = FixedColumns::of(&u);
        let froot = fixed_commitment_root(&f, fixed_params);
        let shape_w = crate::whir_program::WhirShape::of(&committed_pcs_with(&u.shape(), params).config);
        let fvars = PrefixProver::<Fa4, Ea4>::new_witness(vec![fixed_table(&f)], COMMITTED_FOLDING).num_variables();
        let shape_f = crate::whir_program::WhirShape::of_with_offset(&pcs_with(fvars, fixed_params).config, shape_w.slots());
        eprintln!(
            "[m6p-measure] shapes: witness WHIR {} rounds, queries {:?}, final {} queries, final poly {}, pow_init {}; fixed WHIR ({fvars} vars, nnz_bits {}) {} rounds, queries {:?}, final {}; template {} entries, {} fixed columns",
            shape_w.rounds.len(),
            shape_w.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            shape_w.final_round.num_queries,
            shape_w.final_poly_len,
            shape_w.pow_init,
            f.nnz_bits,
            shape_f.rounds.len(),
            shape_f.rounds.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            shape_f.final_round.num_queries,
            f.entries,
            f.n_cols()
        );
        let t1 = std::time::Instant::now();
        let bytes = prove_committed_uniform(&u, &io, &trace.w, params, fixed_params).expect("proves");
        let t_prove = t1.elapsed();
        let t2 = std::time::Instant::now();
        assert!(verify_committed_uniform(&u, &io, &bytes, params, fixed_params, &froot), "the shape-only verifier accepts");
        let t_verify = t2.elapsed();
        eprintln!(
            "[m6p-measure] T = 2^{t_bits}: 2^{} constraints × 2^{} columns; emulate {:.1?}, PROVE {:.1?}, verify {:.1?}, proof {} B",
            u.m_vars(),
            u.n_vars(),
            t_emulate,
            t_prove,
            t_verify,
            bytes.len()
        );
    }

    /// THE WIRE: every byte of an honest committed proof flipped (head, stride, tail) → refused.
    #[test]
    fn no_byte_of_a_committed_spartan_proof_is_free() {
        let (r1cs, io, w) = squaring_chain(40);
        let bytes = prove_committed(&r1cs, &io, &w).expect("proves");
        assert!(verify_committed(&r1cs, &io, &bytes), "CONTROL");
        let positions: Vec<usize> = if bytes.len() <= 12_000 {
            (0..bytes.len()).collect()
        } else {
            let mut v: Vec<usize> = (0..1024).collect();
            v.extend((1024..bytes.len()).step_by(97));
            v.extend(bytes.len().saturating_sub(512)..bytes.len());
            v.sort_unstable();
            v.dedup();
            v
        };
        let mut accepted: Vec<usize> = Vec::new();
        let mut m = bytes.clone();
        for &i in &positions {
            m[i] ^= 1u8 << (i % 8);
            if verify_committed(&r1cs, &io, &m) {
                accepted.push(i);
            }
            m[i] = bytes[i];
        }
        eprintln!("[spartan-m2] byte-flip: {} B, {} positions tried, {} accepted", bytes.len(), positions.len(), accepted.len());
        assert!(accepted.is_empty(), "free bytes at {accepted:?}");
    }
}

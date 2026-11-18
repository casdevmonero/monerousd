//! Uniform R1CS — `T` identical steps of one constraint TEMPLATE over (this step, the next step, the public
//! half) plus a short list of boundary entries. The verifier evaluates the constraint matrices' multilinear
//! extensions at a random point from the TEMPLATE alone — `eq·M_local + shift·M_next + M_boundary` — in
//! O(nnz(template) + log T), never O(nnz(circuit)). This is what lets a recursive verifier of FIXED size check a
//! proof about a circuit of `T·R` constraints (the uniform-R1CS closed form of Jolt/Lasso, borrowed and cited;
//! `docs/O1-OPENINGS-RECURSION-SPEC.md` § "DESIGN Z").
//!
//! Layout (the same `z = [1, io, 0… | w]` as `spartan_ccs`, LSB-first variables): constraint `g·R + i` is
//! template row `i` at step `g`; witness variable `w_off + g·V + j` is local variable `j` at step `g`. A template
//! row that references the NEXT step is a TRANSITION row: it exists for steps `0..T−1` and is absent (an all-zero
//! constraint) at the last step, exactly as an AIR's transition constraint. Boundary entries are absolute
//! `(row, col, val)` triples laid into otherwise-empty rows.
//!
//! ROOT-LAYER: the matrices are DEFINED here, at the template; a materialized sparse `R1cs` is a derived view
//! (the prover's tables and the pins), never the definition.
//! MEASURED: the closed form equals `sparse_mle` of the materialized matrices at random points for T ∈ {2, 4, 8}
//! and every column kind (pin `the_closed_form_equals_the_materialized_matrices`).
//! MUST-STAY-GREEN: `spartan_ccs` committed proofs over materialized uniform instances; the gadget pins.

use crate::hiding_decider::{Ea4, Fa4};
use crate::spartan_ccs::{R1cs, Sparse};
use p3_field::PrimeCharacteristicRing;

/// Where a template entry's column points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Col {
    /// An absolute column of the public half: `0` is the constant one, `1 + i` is public input `i`.
    Public(usize),
    /// Local variable `j` of the same step.
    Local(usize),
    /// Local variable `j` of the NEXT step; makes its row a transition row.
    Next(usize),
}

/// One template entry: (template row, column, coefficient).
pub type TemplateEntry = (usize, Col, Fa4);

/// One constraint matrix: its per-step template and its boundary entries.
#[derive(Clone, Debug, Default)]
pub struct UniformMatrix {
    // O1-INFINITY-REVIEWED: the template is the fixed circuit's per-step constraint set — a constant of the
    // release, independent of T and of every chain total.
    pub template: Vec<TemplateEntry>,
    // O1-INFINITY-REVIEWED: a handful of absolute entries (initial state, final checks) — O(1) by design.
    pub boundary: Sparse,
}

/// `T = 2^t_bits` steps of a template with `R = 2^r_bits` rows and `V = 2^v_bits` local variables.
#[derive(Clone, Debug)]
pub struct UniformR1cs {
    pub r_bits: usize,
    pub v_bits: usize,
    pub t_bits: usize,
    pub io_len: usize,
    pub a: UniformMatrix,
    pub b: UniformMatrix,
    pub c: UniformMatrix,
}

impl UniformR1cs {
    pub fn m_vars(&self) -> usize {
        self.r_bits + self.t_bits
    }
    /// One more than the witness half's variables: the top variable selects the half.
    pub fn n_vars(&self) -> usize {
        1 + self.t_bits + self.v_bits
    }
    pub fn steps(&self) -> usize {
        1usize << self.t_bits
    }
    pub fn w_off(&self) -> usize {
        1usize << (self.n_vars() - 1)
    }
    /// The variable index of local variable `j` at step `g`.
    pub fn var(&self, g: usize, j: usize) -> usize {
        self.w_off() + (g << self.v_bits) + j
    }
    /// The constraint index of template row `i` at step `g`.
    pub fn row(&self, g: usize, i: usize) -> usize {
        (g << self.r_bits) + i
    }
    /// Template rows holding a `Next` reference in ANY of the three matrices.
    pub fn transition_rows(&self) -> Vec<bool> {
        let mut t = vec![false; 1usize << self.r_bits];
        for m in [&self.a, &self.b, &self.c] {
            for &(i, col, _) in &m.template {
                if matches!(col, Col::Next(_)) {
                    t[i] = true;
                }
            }
        }
        t
    }

    /// The instance's SHAPE as an `R1cs` with EMPTY matrices — what the prover and verifier of a uniform proof read
    /// (`m_vars`, `n_vars`, `io_len` and the offsets derived from them). The matrices are streamed from the template
    /// by the prover (`spartan_ccs::stream_abc`) and proven by the matrix argument against the fixed commitment on
    /// the verifier's side — never materialized on the production path (spec §M6-P, 2026-09-28: at the
    /// certificate's T = 2^14 a materialization is ≈ 10^9 entries). O(1).
    pub fn shape(&self) -> R1cs {
        R1cs { m_vars: self.m_vars(), n_vars: self.n_vars(), io_len: self.io_len, a: Vec::new(), b: Vec::new(), c: Vec::new() }
    }

    /// The instance as a plain sparse `R1cs` — O(T · nnz(template)); the small-T pins and the differential pin of
    /// the streaming prover against this laid form.
    pub fn materialize(&self) -> R1cs {
        let trans = self.transition_rows();
        let steps = self.steps();
        let lay = |m: &UniformMatrix| -> Sparse {
            // O1-INFINITY-REVIEWED: T · nnz(template) entries of a FIXED circuit — a derived view, not node state.
            let mut out: Sparse = m.boundary.clone();
            for g in 0..steps {
                for &(i, col, val) in &m.template {
                    if trans[i] && g + 1 == steps {
                        continue;
                    }
                    let c = match col {
                        Col::Public(c) => c,
                        Col::Local(j) => self.var(g, j),
                        Col::Next(j) => self.var(g + 1, j),
                    };
                    out.push((self.row(g, i), c, val));
                }
            }
            out
        };
        R1cs {
            m_vars: self.m_vars(),
            n_vars: self.n_vars(),
            io_len: self.io_len,
            a: lay(&self.a),
            b: lay(&self.b),
            c: lay(&self.c),
        }
    }

    /// `M̃(r_x, r_y)` from the template — the closed form. `r_x` has `m_vars` LSB-first coordinates (`r_lo` the
    /// template row, `r_hi` the step), `r_y` has `n_vars` (`s_lo` the local variable, `s_hi` the step, `top` the
    /// half). Per entry: a `Local` reference sums `eq(r_hi, g)·eq(s_hi, g)` over its steps (`eq(r_hi, s_hi)`, less
    /// the last step's term for a transition row); a `Next` reference sums `eq(r_hi, g)·eq(s_hi, g+1)` (the
    /// shift); a `Public` reference sums `eq(r_hi, g)` alone (`1`, less the last step for a transition row).
    pub fn eval(&self, m: &UniformMatrix, r_x: &[Ea4], r_y: &[Ea4]) -> Ea4 {
        assert_eq!(r_x.len(), self.m_vars(), "row point arity");
        assert_eq!(r_y.len(), self.n_vars(), "column point arity");
        let (r_lo, r_hi) = (&r_x[..self.r_bits], &r_x[self.r_bits..]);
        let s_lo = &r_y[..self.v_bits];
        let s_hi = &r_y[self.v_bits..self.v_bits + self.t_bits];
        let top = r_y[self.n_vars() - 1];
        let eq_row = eq_table_of(r_lo);
        let eq_col = eq_table_of(s_lo);
        let last = self.steps() - 1;
        let e = eq_points(r_hi, s_hi);
        let l_row = eq_bits(r_hi, last);
        let l_col = eq_bits(s_hi, last);
        let sh = shift_closed_form(r_hi, s_hi);
        let trans = self.transition_rows();
        let mut acc = Ea4::ZERO;
        for &(i, col, val) in &m.template {
            let w = eq_row[i] * val;
            let t = trans[i];
            acc += match col {
                Col::Local(j) => w * eq_col[j] * top * if t { e - l_row * l_col } else { e },
                Col::Next(j) => w * eq_col[j] * top * sh,
                Col::Public(c) => w * eq_bits(r_y, c) * if t { Ea4::ONE - l_row } else { Ea4::ONE },
            };
        }
        for &(row, col, val) in &m.boundary {
            acc += eq_bits(r_x, row) * eq_bits(r_y, col) * val;
        }
        acc
    }
}

impl UniformR1cs {
    /// Read a template off an ordinary `R1cs` built by `R1csBuilder` for ONE step: witness columns
    /// `[w_off, w_off + V)` are this step's locals (the first `nreg` of them the registers), columns
    /// `[w_off + V, w_off + V + nreg)` are the placeholders for the NEXT step's registers, the public half is
    /// shared. Refuses (panics at circuit-build time, never at verify time) a column outside those ranges or an
    /// empty template. The result has `T = 2^t_bits` steps and no boundary entries yet (the caller lays those).
    ///
    /// With `one_local = Some(j)`, every reference to the constant column (`Public(0)` — every `Lc` constant and
    /// every `enforce_eq`'s right-hand `1`) is routed through the step's local `j`, which the caller allocates
    /// holding ONE, and one constraint `local_j · 1 = 1` is appended (the only `Public(0)` references left). The
    /// matrix argument (spec §Z3-M) then meets the public kind only at the io reads and this pin — the constants'
    /// thousands of entries become ordinary local entries.
    pub fn from_template(step: &R1cs, v_bits: usize, nreg: usize, t_bits: usize, one_local: Option<usize>) -> Self {
        let v = 1usize << v_bits;
        assert!(nreg <= v, "the registers are the first locals");
        let w_off = step.w_off();
        assert!(w_off >= v + nreg, "the step's witness half must hold the locals and the next-step placeholders");
        if let Some(j) = one_local {
            assert!(j >= nreg && j < v, "the ONE local sits among the step's locals, after the registers");
        }
        let col_of = |c: usize| -> Col {
            if c < w_off {
                assert!(c <= step.io_len, "a template may read only the constant and the public inputs, got column {c}");
                match (c, one_local) {
                    (0, Some(j)) => Col::Local(j),
                    _ => Col::Public(c),
                }
            } else if c < w_off + v {
                Col::Local(c - w_off)
            } else if c < w_off + v + nreg {
                Col::Next(c - w_off - v)
            } else {
                panic!("template column {c} is past the next-step placeholders");
            }
        };
        let rows = step
            .a
            .iter()
            .chain(&step.b)
            .chain(&step.c)
            .map(|&(r, _, _)| r + 1)
            .max()
            .expect("a template has at least one constraint");
        let total_rows = rows + usize::from(one_local.is_some());
        let r_bits = total_rows.next_power_of_two().trailing_zeros() as usize;
        let lift = |m: &Sparse| UniformMatrix {
            template: m.iter().map(|&(r, c, val)| (r, col_of(c), val)).collect(),
            boundary: Vec::new(),
        };
        let (mut a, mut b, mut c) = (lift(&step.a), lift(&step.b), lift(&step.c));
        if let Some(j) = one_local {
            // local_j · 1 = 1, the pin that makes every routed constant a constant
            a.template.push((rows, Col::Local(j), Fa4::ONE));
            b.template.push((rows, Col::Public(0), Fa4::ONE));
            c.template.push((rows, Col::Public(0), Fa4::ONE));
        }
        UniformR1cs { r_bits, v_bits, t_bits, io_len: step.io_len, a, b, c }
    }
}

/// `eq(r, idx)` for the boolean point `idx` (LSB-first over `r.len()` coordinates).
pub fn eq_bits(r: &[Ea4], idx: usize) -> Ea4 {
    r.iter().enumerate().map(|(k, &x)| if (idx >> k) & 1 == 1 { x } else { Ea4::ONE - x }).product()
}

/// `eq(a, b)` for two points of equal arity.
pub fn eq_points(a: &[Ea4], b: &[Ea4]) -> Ea4 {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| x * y + (Ea4::ONE - x) * (Ea4::ONE - y)).product()
}

/// `[eq(r, i)]_{i < 2^len}`, LSB-first.
pub fn eq_table_of(r: &[Ea4]) -> Vec<Ea4> {
    // O1-INFINITY-REVIEWED: 2^r_bits or 2^v_bits entries — the template's own dimensions, fixed constants.
    let mut t = vec![Ea4::ONE];
    for &x in r {
        let mut next = Vec::with_capacity(t.len() * 2);
        for &v in &t {
            next.push(v * (Ea4::ONE - x));
        }
        for &v in &t {
            next.push(v * x);
        }
        t = next;
    }
    t
}

/// `Σ_{g=0}^{T−2} eq(a, g)·eq(b, g+1)` for LSB-first points of `t` coordinates: `g` ends in `k` ones and `g+1` in
/// `k` zeros after the flipped bit `k`, the higher bits agree —
/// `Σ_k Π_{i<k} a_i·(1−b_i) · (1−a_k)·b_k · Π_{i>k} eq(a_i, b_i)`; `k = t` (the wrap of `T−1`) is excluded.
pub fn shift_closed_form(a: &[Ea4], b: &[Ea4]) -> Ea4 {
    assert_eq!(a.len(), b.len());
    let t = a.len();
    let mut acc = Ea4::ZERO;
    for k in 0..t {
        let mut term = (Ea4::ONE - a[k]) * b[k];
        for i in 0..k {
            term *= a[i] * (Ea4::ONE - b[i]);
        }
        for i in k + 1..t {
            term *= a[i] * b[i] + (Ea4::ONE - a[i]) * (Ea4::ONE - b[i]);
        }
        acc += term;
    }
    acc
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::spartan_ccs::{eq_table, sparse_mle};
    use p3_field::BasedVectorSpace;

    fn ea(s: u64) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|j| {
            Fa4::from_u64(s.wrapping_mul(0x9E37_79B9) ^ (j as u64 + 1).wrapping_mul(0x51_7CC1_B727))
        })
    }
    pub(crate) fn rand_point(seed: u64, n: usize) -> Vec<Ea4> {
        (0..n as u64).map(|i| ea(seed * 1000 + i)).collect()
    }

    #[test]
    fn the_shift_closed_form_equals_the_sum() {
        for t in 1..=4 {
            let a = rand_point(1, t);
            let b = rand_point(2, t);
            let n = 1usize << t;
            let want: Ea4 = (0..n - 1).map(|g| eq_bits(&a, g) * eq_bits(&b, g + 1)).sum();
            assert_eq!(shift_closed_form(&a, &b), want, "t={t}");
        }
    }

    /// R = 4 template rows, V = 4 local variables, 2 public inputs; rows 0, 1, 2 are transition rows (a `Next`
    /// reference in some matrix), row 3 local; every column kind appears; one boundary entry per A and C (both in
    /// the public half; `spartan_ccs`'s streaming-prover pin adds witness-half boundaries on top).
    pub(crate) fn sample_uniform(t_bits: usize) -> UniformR1cs {
        let f = Fa4::from_u64;
        let steps = 1usize << t_bits;
        let a = UniformMatrix {
            template: vec![
                (0, Col::Local(0), f(3)),
                (0, Col::Public(1), f(5)),
                (1, Col::Next(2), f(7)),
                (2, Col::Local(1), f(11)),
                (3, Col::Public(0), f(13)),
                (3, Col::Local(3), f(17)),
            ],
            boundary: vec![(0, 1, f(19))],
        };
        let b = UniformMatrix {
            template: vec![
                (0, Col::Public(0), f(1)),
                (1, Col::Local(1), f(2)),
                (2, Col::Next(3), f(4)),
                (3, Col::Public(0), f(1)),
            ],
            boundary: Vec::new(),
        };
        let c = UniformMatrix {
            template: vec![
                (0, Col::Next(1), f(1)),
                (1, Col::Local(0), f(6)),
                (2, Col::Local(2), f(1)),
                (3, Col::Public(2), f(9)),
            ],
            boundary: vec![(steps * 4 - 1, 2, f(23))],
        };
        UniformR1cs { r_bits: 2, v_bits: 2, t_bits, io_len: 2, a, b, c }
    }

    /// ⭐⭐⭐ THE PIN: at T ∈ {2, 4, 8} and three random points, the template closed form equals `sparse_mle` of the
    /// materialized matrices for A, B and C — a wrong shift or last-step convention fails here at T = 2.
    #[test]
    fn the_closed_form_equals_the_materialized_matrices() {
        for t_bits in [1usize, 2, 3] {
            let u = sample_uniform(t_bits);
            let r1cs = u.materialize();
            assert_eq!(r1cs.m_vars, u.m_vars());
            assert_eq!(r1cs.n_vars, u.n_vars());
            for seed in [1u64, 2, 3] {
                let r_x = rand_point(10 + seed, u.m_vars());
                let r_y = rand_point(20 + seed, u.n_vars());
                let (ex, ey) = (eq_table(&r_x), eq_table(&r_y));
                for (name, m, s) in [("A", &u.a, &r1cs.a), ("B", &u.b, &r1cs.b), ("C", &u.c, &r1cs.c)] {
                    assert_eq!(
                        u.eval(m, &r_x, &r_y),
                        sparse_mle(s, &ex, &ey),
                        "{name} at T = 2^{t_bits}, point seed {seed}"
                    );
                }
            }
            eprintln!(
                "[uniform] T = 2^{t_bits}: closed form == materialized for A/B/C at 3 points ({} materialized entries)",
                r1cs.a.len() + r1cs.b.len() + r1cs.c.len()
            );
        }
    }

    /// Z2's shape in miniature: a row function written against `R1csBuilder` (registers `x`, `y`; stream word `d`;
    /// `x' = x·x + d`, `y' = x·d`) is run ONCE for the template and once PER STEP with real values for the trace;
    /// the template lifts to a uniform instance whose materialization the trace satisfies, and a stream word moved
    /// at one step is refused.
    #[test]
    fn a_row_function_lifts_to_a_template_and_its_emulated_trace_satisfies() {
        use crate::spartan_gadgets::{Lc, R1csBuilder};
        const NREG: usize = 2;
        const V_BITS: usize = 3; // 8 locals: x, y, d, x·x, x·d, (spare)
        fn row(b: &mut R1csBuilder, x: Fa4, y: Fa4, d: Fa4) -> (Fa4, Fa4) {
            let xw = b.witness(x);
            let _yw = b.witness(y);
            let dw = b.witness(d);
            let xx = b.mul(&xw, &xw);
            let xd = b.mul(&xw, &dw);
            let w_off = b.assignment().len() / 2;
            let v = 1usize << V_BITS;
            // this step's outputs must equal the next step's registers (placeholder columns w_off + V + j)
            b.enforce_eq(&xx.add(&dw), &Lc::var(w_off + v));
            b.enforce_eq(&xd, &Lc::var(w_off + v + 1));
            (x * x + d, x * d)
        }
        let t_bits = 2usize;
        let steps = 1usize << t_bits;
        let io: Vec<Fa4> = vec![Fa4::from_u64(3)];
        // the template: one symbolic run (values irrelevant to the structure)
        let mut tb = R1csBuilder::new(5, &io).expect("fits");
        row(&mut tb, Fa4::ZERO, Fa4::ZERO, Fa4::ZERO);
        let (step, _) = tb.finish().expect("fits");
        let u = UniformR1cs::from_template(&step, V_BITS, NREG, t_bits, None);
        assert_eq!(u.r_bits, 2, "4 template rows: two products, two register hand-offs");
        let inst = u.materialize();
        // the trace: run the row per step with real values, collecting each step's locals
        let ds: Vec<Fa4> = (0..steps as u64).map(|g| Fa4::from_u64(100 + g)).collect();
        let (mut x, mut y) = (io[0], Fa4::ZERO);
        let mut w = vec![Fa4::ZERO; steps << V_BITS];
        for g in 0..steps {
            let mut b = R1csBuilder::new(5, &io).expect("fits");
            let (nx, ny) = row(&mut b, x, y, ds[g]);
            let z = b.assignment().to_vec();
            let w_off = z.len() / 2;
            w[g << V_BITS..(g + 1) << V_BITS].copy_from_slice(&z[w_off..w_off + (1 << V_BITS)]);
            (x, y) = (nx, ny);
        }
        let z = inst.lay_z(&io, &w).unwrap();
        assert!(inst.is_satisfied(&z), "the emulated trace satisfies the lifted template");
        let mut broken = w.clone();
        broken[(2 << V_BITS) + 2] += Fa4::ONE; // step 2's stream word
        assert!(!inst.is_satisfied(&inst.lay_z(&io, &broken).unwrap()), "a moved stream word is refused");
        let r_x = rand_point(31, u.m_vars());
        let r_y = rand_point(32, u.n_vars());
        let (ex, ey) = (eq_table(&r_x), eq_table(&r_y));
        for (m, s) in [(&u.a, &inst.a), (&u.b, &inst.b), (&u.c, &inst.c)] {
            assert_eq!(u.eval(m, &r_x, &r_y), sparse_mle(s, &ex, &ey), "closed form on the lifted template");
        }
        eprintln!("[uniform] row function lifted: R = 2^{}, V = 2^{V_BITS}, T = {steps}; trace satisfies, tamper refused, closed form agrees", u.r_bits);
    }

    /// A counter: `x_{g+1} = x_g + 1` (transition row 0), `y_g = x_g²` (local row 1), boundaries `x_0 = io[0]` and
    /// `x_{T−1} = io[1]` in the empty template rows 2 and 3 of step 0. The honest trace satisfies the materialized
    /// instance; a trace off by one at one step and a wrong final public value are refused.
    #[test]
    fn a_uniform_trace_satisfies_its_instance_and_a_broken_step_is_refused() {
        let one = Fa4::ONE;
        let t_bits = 3usize;
        let steps = 1usize << t_bits;
        let mut u = UniformR1cs {
            r_bits: 2,
            v_bits: 1,
            t_bits,
            io_len: 2,
            a: UniformMatrix::default(),
            b: UniformMatrix::default(),
            c: UniformMatrix::default(),
        };
        // row 0: (x_g + 1) · 1 = x_{g+1}
        u.a.template.push((0, Col::Local(0), one));
        u.a.template.push((0, Col::Public(0), one));
        u.b.template.push((0, Col::Public(0), one));
        u.c.template.push((0, Col::Next(0), one));
        // row 1: x_g · x_g = y_g
        u.a.template.push((1, Col::Local(0), one));
        u.b.template.push((1, Col::Local(0), one));
        u.c.template.push((1, Col::Local(1), one));
        // boundaries in the empty rows 2 and 3 of step 0: x_0 · 1 = io[0]; x_{T−1} · 1 = io[1]
        u.a.boundary.push((u.row(0, 2), u.var(0, 0), one));
        u.b.boundary.push((u.row(0, 2), 0, one));
        u.c.boundary.push((u.row(0, 2), 1, one));
        u.a.boundary.push((u.row(0, 3), u.var(steps - 1, 0), one));
        u.b.boundary.push((u.row(0, 3), 0, one));
        u.c.boundary.push((u.row(0, 3), 2, one));
        let r1cs = u.materialize();
        let x0 = Fa4::from_u64(40);
        let io = vec![x0, x0 + Fa4::from_u64((steps - 1) as u64)];
        let mut w = vec![Fa4::ZERO; steps << u.v_bits];
        for g in 0..steps {
            let x = x0 + Fa4::from_u64(g as u64);
            w[g << u.v_bits] = x;
            w[(g << u.v_bits) + 1] = x * x;
        }
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).unwrap()), "the honest counter trace satisfies");
        let mut broken = w.clone();
        broken[3 << u.v_bits] += one;
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &broken).unwrap()), "a step off by one is refused");
        let wrong_io = vec![x0, x0 + Fa4::from_u64(steps as u64)];
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&wrong_io, &w).unwrap()), "a wrong final public value is refused");
        // and the closed form agrees on this instance too
        let r_x = rand_point(7, u.m_vars());
        let r_y = rand_point(8, u.n_vars());
        let (ex, ey) = (eq_table(&r_x), eq_table(&r_y));
        for (m, s) in [(&u.a, &r1cs.a), (&u.b, &r1cs.b), (&u.c, &r1cs.c)] {
            assert_eq!(u.eval(m, &r_x, &r_y), sparse_mle(s, &ex, &ey));
        }
        eprintln!("[uniform] counter over {steps} steps: {} constraints laid, honest satisfies, two tampers refused", r1cs.rows());
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ R1CS GADGETS FOR THE O(1)-OPENINGS VERIFIER — milestone 3 of `docs/O1-OPENINGS-RECURSION-SPEC.md`.
//!
//! The recursive verifier (M4) is a circuit; `spartan_ccs` proves circuits given as R1CS. This module is the
//! synthesizer that turns the verifier's arithmetic into R1CS rows AND the honest witness at once — one code path,
//! so the constraint system a verifier rebuilds from public parameters is the one the prover satisfied. Every
//! wire is a LINEAR COMBINATION of variables (linear layers cost no constraints in R1CS); only multiplications
//! allocate.
//!
//! O1-INFINITY-REVIEWED: a constraint system's rows and variables are a function of the FIXED circuit (the
//! verifier's gadget count, itself f(λ, the decider's parameters)), never of chain height, block count or note
//! count. A builder lives for one proof and is dropped; no node retains it. The recursion this serves is exactly
//! the structure that keeps the certificate constant-size at any height.
//!
//! ## Poseidon2-16, the gadget everything else is made of
//! The Fiat–Shamir sponge and every Merkle compression of a WHIR opening are this one permutation
//! (`hiding_decider::Perm16`). Its schedule is `p3_poseidon2_air::generation`'s, mirrored exactly: an initial
//! external linear layer, `HALF_FULL` full rounds (add constants, cube every lane, external layer), `PARTIAL`
//! partial rounds (add a constant to lane 0, cube lane 0, internal layer), `HALF_FULL` full rounds. The round
//! constants come from `sponge_chain_air::raw_constants_for_seed` — the SAME draw the AIR's `RoundConstants` are
//! built from, one definition — and the two linear layers are read off the production layer code by applying it
//! to unit vectors, never re-typed. A cube is two multiplications, so a permutation costs
//! `2·(2·HALF_FULL·16 + PARTIAL)` constraints and as many witness variables.
//!
//! The differential pin (`the_poseidon2_gadget_matches_the_production_permutation`) is the tool the user asked for
//! at this layer: the gadget's output wires must equal `production_perm().permute(input)` — the AIR, the native
//! permutation and the R1CS are three views of one function, and any drift between them is a refusal here.
//!
//! ROOT-LAYER: this is the producer of the recursive verifier's constraint system — the gadgets are written here
//! once and every M4 circuit is composed from them; nothing downstream is patched.
//! MEASURED: by the pins below — the gadget equals the production permutation on 3 inputs wire for wire, a moved
//! public output and a moved intermediate are unsatisfiable, and one permutation proves and verifies on
//! `spartan_ccs::prove_committed` (constraint count and proof bytes print in the run).
//! MUST-STAY-GREEN: `poseidon2_air_parity`, `sponge_chain_air` and `pow_pq_air` (this module reads their constants
//! and layers, changes none of them); every `spartan_ccs` pin.

use crate::hiding_decider::{Ea4, Fa4};
use crate::spartan_ccs::{R1cs, Sparse};
use crate::sponge_chain_air::raw_constants_for_seed;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2::GenericPoseidon2LinearLayers;

/// The permutation width; the sponge's and the compressor's.
pub const WIDTH: usize = crate::pow_pq_air::WIDTH;

/// A linear combination of variables plus a constant (the constant rides on `z[0] = 1`).
/// O1-INFINITY-REVIEWED: at most one term per circuit variable of a FIXED circuit; built per proof.
#[derive(Clone, Debug, Default)]
pub struct Lc {
    pub terms: Vec<(usize, Fa4)>,
    pub constant: Fa4,
}

impl Lc {
    pub fn var(v: usize) -> Lc {
        Lc { terms: vec![(v, Fa4::ONE)], constant: Fa4::ZERO }
    }
    pub fn constant(c: Fa4) -> Lc {
        Lc { terms: Vec::new(), constant: c }
    }
    pub fn add(&self, other: &Lc) -> Lc {
        let mut out = self.clone();
        for &(v, k) in &other.terms {
            match out.terms.iter_mut().find(|(w, _)| *w == v) {
                Some(t) => t.1 += k,
                None => out.terms.push((v, k)),
            }
        }
        out.constant += other.constant;
        out.terms.retain(|(_, k)| *k != Fa4::ZERO);
        out
    }
    pub fn scale(&self, k: Fa4) -> Lc {
        if k == Fa4::ZERO {
            return Lc::default();
        }
        Lc { terms: self.terms.iter().map(|&(v, c)| (v, c * k)).collect(), constant: self.constant * k }
    }
    pub fn add_const(&self, c: Fa4) -> Lc {
        let mut out = self.clone();
        out.constant += c;
        out
    }
    pub fn eval(&self, z: &[Fa4]) -> Fa4 {
        self.terms.iter().fold(self.constant, |acc, &(v, k)| acc + k * z[v])
    }
}

/// ⭐ WHERE A BUILDER'S MATRIX ENTRIES GO (lane vaults, 2026-11-15). `Store` lays the three matrices (every circuit before
/// this, unchanged). The streaming sinks never lay them: each entry `(matrix, row, col, value)` is folded into what the
/// prover or the verifier reads from the matrices, in ONE pass — `Abc` the products `A·z`, `B·z`, `C·z` (the build's own `z`),
/// `Mr` the inner sumcheck's `M_r(y) = Σ_x eq(r_x, x)·(ra·A + rb·B + rc·C)[x][y]`, `Mle` the verifier's
/// `ra·Ã(r_x, r_y) + rb·B̃ + rc·C̃`. The same field values the stored matrices give (`spartan_ccs::mat_vec`, the core's `M_r`
/// loop, `sparse_mle`), so every round message and the transcript are unchanged.
/// MEASURED why (`br15_one_custodians_audit_is_measured_for_its_size_and_its_prove_peak`, 2026-11-15): one custodian's audit is
/// 2^23 rows and 133 M entries — 3.1 GB of stored matrices out of a 4.0 GB prove peak, and every verifying node laid the same
/// 3.1 GB again for each part. SAFE AT SCALE: the sinks hold O(rows + cols) words whatever the entry count. cons: a streamed
/// prove builds the circuit twice (once for `A·z`, once for `M_r`) where a stored one builds it once.
#[derive(Debug, Default)]
pub enum Sink {
    #[default]
    Store,
    Abc([Vec<Fa4>; 3]),
    Mr { eq: Vec<Ea4>, coef: [Ea4; 3], out: Vec<Ea4> },
    Mle { eq_x: Vec<Ea4>, eq_y: Vec<Ea4>, coef: [Ea4; 3], acc: Ea4 },
}

/// Builds the constraint system and the honest assignment together. Public inputs are given up front; every
/// multiplication allocates one witness variable in the witness half.
/// O1-INFINITY-REVIEWED: the three matrices and `z` are sized by the FIXED circuit (`2^n_vars` declared up front,
/// `finish` refuses an overflow); the builder is dropped with the proof it produced.
pub struct R1csBuilder {
    a: Sparse,
    b: Sparse,
    c: Sparse,
    rows: usize,
    n_vars: usize,
    io_len: usize,
    next_var: usize,
    z: Vec<Fa4>,
    /// §M6-E (2026-09-28): `true` for a VALUES-ONLY run. The cells are allocated and the assignment written exactly
    /// as in a recording run (same `next_var` order, so `z`'s layout is the builder's by construction), but `mul` and
    /// `witness` hand back a CONSTANT wire holding the value instead of a variable, so every downstream `Lc` is
    /// term-free and the linear algebra (`add`, `scale`: a clone of an EMPTY term list) costs field operations only;
    /// no matrix entry is pushed. MEASURED 2026-09-28: skipping the pushes alone (variables kept) was 87.6 s against
    /// 79.9 s for the 2^14-row emulation — the cost was the term algebra, which this removes. `finish` refuses a
    /// values-only builder (no instance to hand out); `constraints()` still counts, so the per-row count check holds.
    values_only: bool,
    /// where the entries go ([`Sink`]): laid in `a`, `b`, `c`, or folded as they are made
    sink: Sink,
}

impl R1csBuilder {
    /// `n_vars` is log2 of `z`'s length; the caller sizes it so `1 + io` fits the public half and every
    /// multiplication fits the witness half (`finish` refuses otherwise).
    pub fn new(n_vars: usize, io: &[Fa4]) -> Option<Self> {
        Self::with_mode(n_vars, io, false)
    }
    /// The VALUES-ONLY builder (§M6-E, see `values_only`): the trace, not the instance.
    pub fn new_values_only(n_vars: usize, io: &[Fa4]) -> Option<Self> {
        Self::with_mode(n_vars, io, true)
    }
    fn with_mode(n_vars: usize, io: &[Fa4], values_only: bool) -> Option<Self> {
        let cols = 1usize << n_vars;
        if 1 + io.len() > cols / 2 {
            return None;
        }
        let mut z = vec![Fa4::ZERO; cols];
        z[0] = Fa4::ONE;
        z[1..=io.len()].copy_from_slice(io);
        Some(R1csBuilder { a: Vec::new(), b: Vec::new(), c: Vec::new(), rows: 0, n_vars, io_len: io.len(), next_var: cols / 2, z, values_only, sink: Sink::Store })
    }
    /// ⭐ A STREAMING builder ([`Sink`]): the same constraints and assignment as [`R1csBuilder::new`], its entries folded into
    /// `sink` as they are made instead of laid. Read the result with [`R1csBuilder::finish_stream`].
    pub fn new_streaming(n_vars: usize, io: &[Fa4], sink: Sink) -> Option<Self> {
        let mut b = Self::with_mode(n_vars, io, false)?;
        b.sink = sink;
        Some(b)
    }
    /// One entry `(matrix, row, col, value)` into the sink: laid (`Store`), or folded.
    fn put1(&mut self, m: usize, row: usize, col: usize, v: Fa4) {
        match &mut self.sink {
            Sink::Store => match m {
                0 => self.a.push((row, col, v)),
                1 => self.b.push((row, col, v)),
                _ => self.c.push((row, col, v)),
            },
            Sink::Abc(t) => {
                let r = &mut t[m.min(2)];
                if r.len() <= row {
                    r.resize(row + 1, Fa4::ZERO);
                }
                r[row] += v * self.z.get(col).copied().unwrap_or(Fa4::ZERO);
            }
            Sink::Mr { eq, coef, out } => {
                if let (Some(e), Some(o)) = (eq.get(row), out.get_mut(col)) {
                    *o += *e * coef[m.min(2)] * Ea4::from(v);
                }
            }
            Sink::Mle { eq_x, eq_y, coef, acc } => {
                if let (Some(ex), Some(ey)) = (eq_x.get(row), eq_y.get(col)) {
                    *acc += coef[m.min(2)] * *ex * *ey * Ea4::from(v);
                }
            }
        }
    }
    /// The entries of combination `x` in row `row` of matrix `m`; the constant lands on column 0.
    fn put(&mut self, m: usize, row: usize, x: &Lc) {
        for &(v, k) in &x.terms {
            self.put1(m, row, v, k);
        }
        if x.constant != Fa4::ZERO {
            self.put1(m, row, 0, x.constant);
        }
    }
    /// ⭐ A streaming build's result: the instance's SHAPE (its matrices empty — the sink held their image), the sink with what
    /// it folded (`Abc`'s three products padded to the instance's rows), and the witness half. `None` exactly where
    /// [`R1csBuilder::finish`] refuses.
    pub fn finish_stream(self) -> Option<(R1cs, Sink, Vec<Fa4>)> {
        let cols = 1usize << self.n_vars;
        if self.values_only || self.next_var > cols || self.rows == 0 || matches!(self.sink, Sink::Store) {
            return None;
        }
        let m_vars = ((usize::BITS - (self.rows - 1).leading_zeros()) as usize).max(1);
        let shape = R1cs { m_vars, n_vars: self.n_vars, io_len: self.io_len, a: Vec::new(), b: Vec::new(), c: Vec::new() };
        let mut sink = self.sink;
        if let Sink::Abc(t) = &mut sink {
            for r in t.iter_mut() {
                r.resize(1usize << m_vars, Fa4::ZERO);
            }
        }
        let w = self.z[cols / 2..].to_vec();
        Some((shape, sink, w))
    }
    /// The wire of public input `i`.
    pub fn io(&self, i: usize) -> Lc {
        if self.values_only {
            return Lc::constant(self.z[1 + i]); // §M6-E: term-free, like every other wire of a values-only run
        }
        Lc::var(1 + i)
    }
    /// The index of the most recently allocated cell — the same in a recording and a values-only run, since both
    /// allocate in the same order (§M6-E). A layout check reads this, never a wire's term list, which a values-only
    /// wire does not carry.
    pub fn last_var(&self) -> usize {
        self.next_var - 1
    }
    /// `out = x · y`: one constraint, one new witness variable holding the product. Past the witness half the
    /// variable is still allocated (so `finish` can refuse the overflow) but no value is written.
    pub fn mul(&mut self, x: &Lc, y: &Lc) -> Lc {
        let out = self.next_var;
        self.next_var += 1;
        let v = x.eval(&self.z) * y.eval(&self.z);
        if out < self.z.len() {
            self.z[out] = v;
        }
        self.rows += 1;
        if self.values_only {
            return Lc::constant(v); // §M6-E: a term-free wire carrying the value
        }
        let row = self.rows - 1;
        self.put(0, row, x);
        self.put(1, row, y);
        self.put1(2, row, out, Fa4::ONE);
        Lc::var(out)
    }
    /// A fresh witness wire holding `v` — a value the prover computes off-circuit (a bit, a quotient) that the
    /// constraints then pin. Past the witness half the variable is allocated but no value is written (as `mul`).
    pub fn witness(&mut self, v: Fa4) -> Lc {
        let out = self.next_var;
        self.next_var += 1;
        if out < self.z.len() {
            self.z[out] = v;
        }
        if self.values_only {
            return Lc::constant(v); // §M6-E
        }
        Lc::var(out)
    }
    /// The value of a wire under the assignment built so far.
    pub fn value_of(&self, x: &Lc) -> Fa4 {
        x.eval(&self.z)
    }
    /// `x · y == z` for wires that already exist: one constraint, no allocation.
    pub fn constrain(&mut self, x: &Lc, y: &Lc, z: &Lc) {
        if !self.values_only {
            let row = self.rows;
            self.put(0, row, x);
            self.put(1, row, y);
            self.put(2, row, z);
        }
        self.rows += 1;
    }
    /// `x == y`: one constraint `(x)·(1) = (y)`.
    pub fn enforce_eq(&mut self, x: &Lc, y: &Lc) {
        if !self.values_only {
            let row = self.rows;
            self.put(0, row, x);
            self.put1(1, row, 0, Fa4::ONE);
            self.put(2, row, y);
        }
        self.rows += 1;
    }
    pub fn constraints(&self) -> usize {
        self.rows
    }
    /// The assignment built so far (`z`), for pins that compare wire values with a native computation.
    pub fn assignment(&self) -> &[Fa4] {
        &self.z
    }
    /// The instance and the witness half. `None` when the witness overflowed its half or no constraint exists —
    /// a circuit that does not fit its declared shape is refused, never truncated.
    pub fn finish(self) -> Option<(R1cs, Vec<Fa4>)> {
        let cols = 1usize << self.n_vars;
        if self.values_only || self.next_var > cols || self.rows == 0 {
            return None; // a values-only builder holds no instance: refused, never an empty one (§M6-E)
        }
        let m_vars = (usize::BITS - (self.rows - 1).leading_zeros()) as usize;
        let r1cs = R1cs { m_vars: m_vars.max(1), n_vars: self.n_vars, io_len: self.io_len, a: self.a, b: self.b, c: self.c };
        let w = self.z[cols / 2..].to_vec();
        Some((r1cs, w))
    }
}

/// The 16×16 matrix of a linear layer, read off the production code by applying it to the unit vectors.
fn layer_matrix(apply: fn(&mut [Fa4; WIDTH])) -> [[Fa4; WIDTH]; WIDTH] {
    let mut m = [[Fa4::ZERO; WIDTH]; WIDTH];
    for j in 0..WIDTH {
        let mut e = [Fa4::ZERO; WIDTH];
        e[j] = Fa4::ONE;
        apply(&mut e);
        for i in 0..WIDTH {
            m[i][j] = e[i];
        }
    }
    m
}
fn external_matrix() -> [[Fa4; WIDTH]; WIDTH] {
    layer_matrix(|s| GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(s))
}
fn internal_matrix() -> [[Fa4; WIDTH]; WIDTH] {
    layer_matrix(|s| GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(s))
}
fn apply_linear(m: &[[Fa4; WIDTH]; WIDTH], s: &[Lc; WIDTH]) -> [Lc; WIDTH] {
    core::array::from_fn(|i| (0..WIDTH).fold(Lc::default(), |acc, j| acc.add(&s[j].scale(m[i][j]))))
}
fn cube(b: &mut R1csBuilder, x: &Lc) -> Lc {
    let sq = b.mul(x, x);
    b.mul(&sq, x)
}

/// The round constants of ONE Poseidon2-16 instance. The decider runs several instances that differ only by
/// seed — `production_perm()` (the block kernel and the plain `Chl`), the Spartan transcript
/// (`REC_DECIDER_SEED ^ 0x5041_5254_4E31`), the committed-carrier PCS Merkle hash + compress and its challenger
/// (`COMMITTED_AIR_SEED`) — and the recursive verifier mirrors each with ITS constants: the same
/// `raw_constants_for_seed` derivation `Perm16::new_from_rng_128(SmallRng::seed_from_u64(seed))` runs.
#[derive(Clone, Debug)]
pub struct P2Consts {
    initial: [[Fa4; WIDTH]; crate::sponge_chain_air::HALF_FULL_ROUNDS],
    terminal: [[Fa4; WIDTH]; crate::sponge_chain_air::HALF_FULL_ROUNDS],
    internal: [Fa4; crate::sponge_chain_air::PARTIAL_ROUNDS],
    pub seed: u64,
}

impl P2Consts {
    pub fn for_seed(seed: u64) -> Self {
        let (initial, terminal, internal) = raw_constants_for_seed(seed);
        P2Consts { initial, terminal, internal, seed }
    }
}

/// Poseidon2-16 on wires, `p3_poseidon2_air::generation`'s schedule exactly, with `p2`'s constants.
pub fn poseidon2_permutation(b: &mut R1csBuilder, p2: &P2Consts, state: &[Lc; WIDTH]) -> [Lc; WIDTH] {
    let (initial, terminal, internal) = (&p2.initial, &p2.terminal, &p2.internal);
    let (m_ext, m_int) = (external_matrix(), internal_matrix());
    let mut s = apply_linear(&m_ext, state);
    for round in initial.iter() {
        for i in 0..WIDTH {
            s[i] = cube(b, &s[i].add_const(round[i]));
        }
        s = apply_linear(&m_ext, &s);
    }
    for &c in internal.iter() {
        s[0] = cube(b, &s[0].add_const(c));
        s = apply_linear(&m_int, &s);
    }
    for round in terminal.iter() {
        for i in 0..WIDTH {
            s[i] = cube(b, &s[i].add_const(round[i]));
        }
        s = apply_linear(&m_ext, &s);
    }
    s
}

/// Poseidon2-16 on wires whose round constants are a FLAG-WEIGHTED BLEND of several instances: the effective
/// constant of every round is `Σ_i weight_i · c_i` with the weights linear combinations of flag wires (the
/// universal row selects the transcript's or the Merkle hash's instance per row). Same schedule, same cost as
/// [`poseidon2_permutation`]; the blend is linear, so it adds no constraint.
pub fn poseidon2_permutation_blend(b: &mut R1csBuilder, blend: &[(&P2Consts, Lc)], state: &[Lc; WIDTH]) -> [Lc; WIDTH] {
    assert!(!blend.is_empty(), "a blend names at least one instance");
    let (m_ext, m_int) = (external_matrix(), internal_matrix());
    let half = blend[0].0.initial.len();
    let partial = blend[0].0.internal.len();
    let full_const = |round: usize, i: usize, terminal: bool| -> Lc {
        blend.iter().fold(Lc::default(), |acc, (p2, w)| {
            let c = if terminal { p2.terminal[round][i] } else { p2.initial[round][i] };
            acc.add(&w.scale(c))
        })
    };
    let partial_const = |round: usize| -> Lc {
        blend.iter().fold(Lc::default(), |acc, (p2, w)| acc.add(&w.scale(p2.internal[round])))
    };
    let mut s = apply_linear(&m_ext, state);
    for round in 0..half {
        for i in 0..WIDTH {
            s[i] = cube(b, &s[i].add(&full_const(round, i, false)));
        }
        s = apply_linear(&m_ext, &s);
    }
    for round in 0..partial {
        s[0] = cube(b, &s[0].add(&partial_const(round)));
        s = apply_linear(&m_int, &s);
    }
    for round in 0..half {
        for i in 0..WIDTH {
            s[i] = cube(b, &s[i].add(&full_const(round, i, true)));
        }
        s = apply_linear(&m_ext, &s);
    }
    s
}

/// `flag ? if1 : if0` for a boolean wire: `if0 + flag·(if1 − if0)`, one product.
pub fn sel(b: &mut R1csBuilder, flag: &Lc, if1: &Lc, if0: &Lc) -> Lc {
    let d = if1.add(&if0.scale(-Fa4::ONE));
    if0.add(&b.mul(flag, &d))
}

/// `Σ_i flag_i · menu_i` over extension wires — a one-hot selection when exactly one flag is set, a sum when
/// several are (the program decides; the flags are bound by its hash). Four products per menu entry.
pub fn select_ext(b: &mut R1csBuilder, flags: &[Lc], menu: &[ExtLc]) -> ExtLc {
    assert_eq!(flags.len(), menu.len());
    flags.iter().zip(menu).fold(ExtLc::zero(), |acc, (f, m)| acc.add(&ext_scale_wire(b, m, f)))
}

/// Constraints one permutation costs — a public function of the round numbers, never a literal.
pub fn poseidon2_constraints() -> usize {
    let (initial, terminal, internal) = raw_constants_for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
    2 * ((initial.len() + terminal.len()) * WIDTH + internal.len())
}

// ── Ea4 arithmetic on wires: the recursive verifier's challenges and sumcheck messages live in the extension ──

use p3_field::{BasedVectorSpace, Field};

/// An extension element as four base-field wires, in the field's own basis order.
#[derive(Clone, Debug)]
pub struct ExtLc(pub [Lc; 4]);

fn coeffs(e: Ea4) -> [Fa4; 4] {
    let s = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&e);
    [s[0], s[1], s[2], s[3]]
}

impl ExtLc {
    pub fn zero() -> ExtLc {
        ExtLc(core::array::from_fn(|_| Lc::default()))
    }
    pub fn constant(e: Ea4) -> ExtLc {
        let c = coeffs(e);
        ExtLc(core::array::from_fn(|i| Lc::constant(c[i])))
    }
    /// Four consecutive public inputs starting at `first`.
    pub fn io(b: &R1csBuilder, first: usize) -> ExtLc {
        ExtLc(core::array::from_fn(|i| b.io(first + i)))
    }
    pub fn add(&self, o: &ExtLc) -> ExtLc {
        ExtLc(core::array::from_fn(|i| self.0[i].add(&o.0[i])))
    }
    pub fn sub(&self, o: &ExtLc) -> ExtLc {
        ExtLc(core::array::from_fn(|i| self.0[i].add(&o.0[i].scale(-Fa4::ONE))))
    }
    pub fn scale_base(&self, k: Fa4) -> ExtLc {
        ExtLc(core::array::from_fn(|i| self.0[i].scale(k)))
    }
    pub fn eval(&self, z: &[Fa4]) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| self.0[i].eval(z))
    }
    /// Multiply by a CONSTANT extension element — linear on the wires, no constraint.
    pub fn mul_const(&self, k: Ea4) -> ExtLc {
        let w = binomial_w();
        let c = coeffs(k);
        let x = &self.0;
        let t = |i: usize, j: usize| x[i].scale(c[j]);
        ExtLc([
            t(0, 0).add(&t(1, 3).add(&t(2, 2)).add(&t(3, 1)).scale(w)),
            t(0, 1).add(&t(1, 0)).add(&t(2, 3).add(&t(3, 2)).scale(w)),
            t(0, 2).add(&t(1, 1)).add(&t(2, 0)).add(&t(3, 3).scale(w)),
            t(0, 3).add(&t(1, 2)).add(&t(2, 1)).add(&t(3, 0)),
        ])
    }
}

/// The binomial's constant `W` in `X⁴ = W`, read off the field itself at build time — never typed. The check
/// that the cube of the generator's power has no other coordinate is what makes this the right formula.
fn binomial_w() -> Fa4 {
    let x = Ea4::from_basis_coefficients_fn(|i| if i == 1 { Fa4::ONE } else { Fa4::ZERO });
    let x4 = x * x * x * x;
    let c = coeffs(x4);
    assert!(c[1] == Fa4::ZERO && c[2] == Fa4::ZERO && c[3] == Fa4::ZERO, "the extension is not binomial in this basis");
    c[0]
}

/// `x · y` in the extension: 16 base products, then the binomial reduction as linear combinations.
pub fn ext_mul(b: &mut R1csBuilder, x: &ExtLc, y: &ExtLc) -> ExtLc {
    let w = binomial_w();
    let mut p: Vec<Vec<Lc>> = Vec::with_capacity(4);
    for i in 0..4 {
        let mut row = Vec::with_capacity(4);
        for j in 0..4 {
            row.push(b.mul(&x.0[i], &y.0[j]));
        }
        p.push(row);
    }
    ExtLc([
        p[0][0].add(&p[1][3].add(&p[2][2]).add(&p[3][1]).scale(w)),
        p[0][1].add(&p[1][0]).add(&p[2][3].add(&p[3][2]).scale(w)),
        p[0][2].add(&p[1][1]).add(&p[2][0]).add(&p[3][3].scale(w)),
        p[0][3].add(&p[1][2]).add(&p[2][1]).add(&p[3][0]),
    ])
}

pub fn ext_enforce_eq(b: &mut R1csBuilder, x: &ExtLc, y: &ExtLc) {
    for i in 0..4 {
        b.enforce_eq(&x.0[i], &y.0[i]);
    }
}

/// Coefficients of the Lagrange basis over the points `0..=d`: `L_j(X) = Σ_k coef[j][k]·X^k`. Base-field
/// constants of the circuit, computed natively (never typed) from the same points `air_zerocheck::lagrange_eval`
/// interpolates over.
fn lagrange_basis_coefficients(d: usize) -> Vec<Vec<Fa4>> {
    (0..=d)
        .map(|j| {
            // numerator Π_{m≠j} (X − m) as a coefficient vector, low degree first
            let mut num: Vec<Fa4> = vec![Fa4::ONE];
            let mut den = Fa4::ONE;
            for m in 0..=d {
                if m == j {
                    continue;
                }
                let m_f = Fa4::from_u64(m as u64);
                let mut next = vec![Fa4::ZERO; num.len() + 1];
                for (k, &c) in num.iter().enumerate() {
                    next[k + 1] += c; // ·X
                    next[k] -= c * m_f; // ·(−m)
                }
                num = next;
                den *= Fa4::from_u64(j as u64) - m_f;
            }
            let inv = den.inverse();
            num.into_iter().map(|c| c * inv).collect()
        })
        .collect()
}

/// `h(r)` for a polynomial given by its evaluations at `0..=d` — the in-circuit twin of
/// `air_zerocheck::lagrange_eval`. `d − 1` products for the powers of `r`, `d + 1` for the basis.
pub fn lagrange_at(b: &mut R1csBuilder, h: &[ExtLc], r: &ExtLc) -> ExtLc {
    let d = h.len() - 1;
    let mut pow: Vec<ExtLc> = vec![ExtLc::constant(Ea4::ONE), r.clone()];
    for _ in 2..=d {
        let last = pow.last().cloned().expect("at least two powers");
        pow.push(ext_mul(b, &last, r));
    }
    let coef = lagrange_basis_coefficients(d);
    let mut acc = ExtLc::zero();
    for j in 0..=d {
        let lj = (0..=d).fold(ExtLc::zero(), |a, k| a.add(&pow[k].scale_base(coef[j][k])));
        acc = acc.add(&ext_mul(b, &h[j], &lj));
    }
    acc
}

/// One sumcheck round in-circuit: `h(0) + h(1) == claim` enforced, `h(r)` returned as the next claim.
pub fn sumcheck_round(b: &mut R1csBuilder, claim: &ExtLc, h: &[ExtLc], r: &ExtLc) -> ExtLc {
    let sum = h[0].add(&h[1]);
    ext_enforce_eq(b, &sum, claim);
    lagrange_at(b, h, r)
}

/// `eq(τ, r) = Π_k (τ_k·r_k + (1−τ_k)(1−r_k))` in-circuit: three products per variable.
pub fn eq_at(b: &mut R1csBuilder, tau: &[ExtLc], r: &[ExtLc]) -> ExtLc {
    let one = ExtLc::constant(Ea4::ONE);
    let mut prod = ExtLc::constant(Ea4::ONE);
    for (t, rk) in tau.iter().zip(r) {
        let tr = ext_mul(b, t, rk);
        let nt_nr = ext_mul(b, &one.sub(t), &one.sub(rk));
        prod = ext_mul(b, &prod, &tr.add(&nt_nr));
    }
    prod
}

// ── The Fiat–Shamir sponge on wires: `DuplexChallenger<Fa4, Perm16, 16, 8>` with a STATIC schedule ────────

/// The duplex challenger's rate.
pub const RATE: usize = 8;

/// `hiding_decider::Chl` (`DuplexChallenger<Fa4, Perm16, 16, 8>`) as wires. The verifier's absorb/sample schedule
/// is a fixed function of the circuit, so every duplexing is a plain `poseidon2_permutation` call and every
/// buffer index is static — no selectors, unlike `sponge_chain_air`, which had to accept a variable schedule.
/// Semantics mirrored from `p3_challenger::duplex_challenger` exactly: `observe` clears the output buffer, pushes
/// into the input buffer and duplexes when it holds `RATE`; `duplexing` OVERWRITES the first `k` rate slots with
/// the `k` buffered inputs (the rest of the state carries), permutes, and refills the output buffer with
/// `state[..RATE]`; `sample` duplexes when the input buffer is non-empty or the output buffer is empty, then POPS
/// from the END of the output buffer. An extension element is observed and sampled as its four basis
/// coefficients, coefficient 0 first.
pub struct SpongeWires {
    state: [Lc; WIDTH],
    input: Vec<Lc>,
    output: Vec<Lc>,
    p2: P2Consts,
}

impl SpongeWires {
    /// The all-zero starting state, as `Chl::new` begins, over the permutation `seed` derives.
    pub fn new(seed: u64) -> Self {
        SpongeWires {
            state: core::array::from_fn(|_| Lc::default()),
            input: Vec::new(),
            output: Vec::new(),
            p2: P2Consts::for_seed(seed),
        }
    }
    fn duplex(&mut self, b: &mut R1csBuilder) {
        for (i, v) in self.input.drain(..).enumerate() {
            self.state[i] = v;
        }
        self.state = poseidon2_permutation(b, &self.p2, &self.state);
        self.output = self.state[..RATE].to_vec();
    }
    pub fn observe(&mut self, b: &mut R1csBuilder, v: &Lc) {
        self.output.clear();
        self.input.push(v.clone());
        if self.input.len() == RATE {
            self.duplex(b);
        }
    }
    pub fn observe_ext(&mut self, b: &mut R1csBuilder, e: &ExtLc) {
        for i in 0..4 {
            self.observe(b, &e.0[i]);
        }
    }
    pub fn sample(&mut self, b: &mut R1csBuilder) -> Lc {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplex(b);
        }
        self.output.pop().expect("a duplexing refills the output buffer with RATE wires")
    }
    pub fn sample_ext(&mut self, b: &mut R1csBuilder) -> ExtLc {
        let c0 = self.sample(b);
        let c1 = self.sample(b);
        let c2 = self.sample(b);
        let c3 = self.sample(b);
        ExtLc([c0, c1, c2, c3])
    }
}

// ── M4 gadgets: the WHIR verifier's pieces, each the twin of one native function ─────────────────────────

/// One `{0, 1, ∞}` sumcheck round — `SumcheckData::verify_rounds`: observe `(h(0), h(∞))`, sample `r`, and fold
/// `claim ← h(0)·(1−r) + (claim − h(0))·r + h(∞)·r·(r−1)` (`lagrange_weights_01inf`). Three extension products.
/// Returns the folded claim and the challenge.
pub fn sumcheck_round_01inf(b: &mut R1csBuilder, sponge: &mut SpongeWires, claim: &ExtLc, h0: &ExtLc, hinf: &ExtLc) -> (ExtLc, ExtLc) {
    sponge.observe_ext(b, h0);
    sponge.observe_ext(b, hinf);
    let r = sponge.sample_ext(b);
    let one = ExtLc::constant(Ea4::ONE);
    let h1 = claim.sub(h0);
    let t_inf = ext_mul(b, hinf, &r.sub(&one)); // h(∞)·(r−1)
    let t_r = ext_mul(b, &h1.add(&t_inf), &r); // r·(h(1) + h(∞)·(r−1))
    let t_0 = ext_mul(b, h0, &one.sub(&r)); // h(0)·(1−r)
    (t_0.add(&t_r), r)
}

/// `Point::expand_from_univariate(y, n)`: big-endian powers `[y^(2^(n−1)), …, y², y]` — `n − 1` squarings.
pub fn expand_from_univariate(b: &mut R1csBuilder, y: &ExtLc, n: usize) -> Vec<ExtLc> {
    let mut res: Vec<ExtLc> = vec![ExtLc::zero(); n];
    let mut cur = y.clone();
    for i in (0..n).rev() {
        res[i] = cur.clone();
        if i > 0 {
            cur = ext_mul(b, &cur, &cur);
        }
    }
    res
}

/// One out-of-domain claim a round's commitment carries: the expanded point and the prover's answer.
pub struct OodClaim {
    pub point: Vec<ExtLc>,
    pub eval: ExtLc,
}

/// `ParsedCommitment::parse_with_round` on wires: observe the root's eight elements, then for each OOD sample draw
/// a univariate point, expand it, and observe the answer. The answers are prover wires; the points are transcript.
pub fn parse_commitment(b: &mut R1csBuilder, sponge: &mut SpongeWires, root: &[Lc; RATE], ood_answers: &[ExtLc], num_variables: usize) -> Vec<OodClaim> {
    for w in root {
        sponge.observe(b, w);
    }
    ood_answers
        .iter()
        .map(|ans| {
            let y = sponge.sample_ext(b);
            let point = expand_from_univariate(b, &y, num_variables);
            sponge.observe_ext(b, ans);
            OodClaim { point, eval: ans.clone() }
        })
        .collect()
}

/// `PaddingFreeSponge<Perm16, 16, 8, 8>::hash_iter` on wires — the MMCS leaf hash: overwrite up to `RATE` slots per
/// block, permute after every full block and after a trailing partial block, squeeze the first eight.
pub fn sponge_hash(b: &mut R1csBuilder, p2: &P2Consts, input: &[Lc]) -> [Lc; RATE] {
    let mut state: [Lc; WIDTH] = core::array::from_fn(|_| Lc::default());
    let mut idx = 0usize;
    loop {
        let mut i = 0usize;
        while i < RATE && idx < input.len() {
            state[i] = input[idx].clone();
            idx += 1;
            i += 1;
        }
        if i < RATE {
            if i != 0 {
                state = poseidon2_permutation(b, p2, &state);
            }
            break;
        }
        state = poseidon2_permutation(b, p2, &state);
    }
    core::array::from_fn(|k| state[k].clone())
}

/// `TruncatedPermutation<Perm16, 2, 8, 16>::compress`: state = left ‖ right, permute, first eight.
pub fn merkle_compress(b: &mut R1csBuilder, p2: &P2Consts, left: &[Lc; RATE], right: &[Lc; RATE]) -> [Lc; RATE] {
    let state: [Lc; WIDTH] = core::array::from_fn(|k| if k < RATE { left[k].clone() } else { right[k - RATE].clone() });
    let out = poseidon2_permutation(b, p2, &state);
    core::array::from_fn(|k| out[k].clone())
}

/// A Merkle path from a leaf digest: at each level the index BIT (a boolean wire, enforced) puts the running node
/// on the left (bit 0) or the right (bit 1) of its sibling — `left = node + bit·(sib − node)`, `right = node + sib
/// − left` — then one compression. Eight products and one booleanity row per level.
pub fn merkle_root_from_path(b: &mut R1csBuilder, p2: &P2Consts, leaf: [Lc; RATE], siblings: &[[Lc; RATE]], bits: &[Lc]) -> [Lc; RATE] {
    let mut node = leaf;
    for (sib, bit) in siblings.iter().zip(bits) {
        b.constrain(bit, bit, bit); // bit ∈ {0, 1}
        let mut left: [Lc; RATE] = core::array::from_fn(|_| Lc::default());
        let mut right: [Lc; RATE] = core::array::from_fn(|_| Lc::default());
        for k in 0..RATE {
            let diff = sib[k].add(&node[k].scale(-Fa4::ONE));
            let sel = b.mul(bit, &diff);
            left[k] = node[k].add(&sel);
            right[k] = node[k].add(&sib[k]).add(&left[k].scale(-Fa4::ONE));
        }
        node = merkle_compress(b, p2, &left, &right);
    }
    node
}

// ── Bits, indices, domain powers and the folding arithmetic: the STIR-query gadgets ─────────────────────────────
// Every gadget here REFUSES an empty input with an assert (fail closed) instead of returning an identity: a STIR
// query always has ≥ 1 index bit, a constraint point ≥ 1 coordinate, a final polynomial ≥ 1 coefficient.

/// KoalaBear: `p = 2^31 − 2^24 + 1`, so a canonical element has 31 bits and `p ≡ 1 (mod 2^24)`.
const P_BITS: usize = 31;
const P_LOW_ONE_BITS: usize = 24;

/// The 31 canonical bits of a base wire, LSB first: each bit boolean, their weighted sum equal to `x`, and the
/// value below `p` — when the top seven bits are all one the low 24 bits must all be zero (`p − 1 = 0x7F00_0000`),
/// which pins ONE decomposition per element (the alias `x + p` also fits 31 bits whenever `x < 2^24`, and the
/// range rows are what refuse it). 31 booleanity rows + 1 sum row + 6 chain products + 1 range row.
pub fn canonical_bits(b: &mut R1csBuilder, x: &Lc) -> Vec<Lc> {
    use p3_field::PrimeField64;
    let v = b.value_of(x).as_canonical_u64();
    let bits: Vec<Lc> = (0..P_BITS).map(|i| b.witness(Fa4::from_u64((v >> i) & 1))).collect();
    let mut sum = Lc::default();
    for (i, bit) in bits.iter().enumerate() {
        b.constrain(bit, bit, bit);
        sum = sum.add(&bit.scale(Fa4::from_u64(1u64 << i)));
    }
    b.enforce_eq(&sum, x);
    let mut top = bits[P_LOW_ONE_BITS].clone();
    for bit in &bits[P_LOW_ONE_BITS + 1..P_BITS] {
        top = b.mul(&top, bit);
    }
    let low = bits[..P_LOW_ONE_BITS].iter().fold(Lc::default(), |acc, bit| acc.add(bit));
    b.constrain(&top, &low, &Lc::default());
    bits
}

/// One STIR query index — `draw_below(2^k)` on wires, `k ≤ 24`. The native draws `DRAW_ELEMS` base samples and
/// folds them as `((f0·p + f1)·p + f2)·p + f3 mod 2^k`; since `p ≡ 1 (mod 2^24)` that is `(f0 + f1 + f2 + f3) mod
/// 2^k`, so the gadget takes each sample's canonical low `k` bits, sums them (an integer below `2^(k+2)`, no
/// wrap) and decomposes the sum into `k + 2` bits whose low `k` are the index, LSB first. Returns `(bits, index)`.
/// The domain size is a circuit constant, never a wire.
pub fn stir_index(b: &mut R1csBuilder, sponge: &mut SpongeWires, log_folded_domain: usize) -> (Vec<Lc>, Lc) {
    use p3_field::PrimeField64;
    use p3_whir::pcs::utils::DRAW_ELEMS;
    assert!(log_folded_domain <= P_LOW_ONE_BITS, "draw_below on wires needs a domain of at most 2^24");
    assert!(log_folded_domain >= 1, "a one-element domain has no STIR query to select");
    let k = log_folded_domain;
    let mut total = Lc::default();
    let mut total_v = 0u64;
    for _ in 0..DRAW_ELEMS {
        let f = sponge.sample(b);
        let fv = b.value_of(&f).as_canonical_u64();
        let bits = canonical_bits(b, &f);
        for (j, bit) in bits.iter().take(k).enumerate() {
            total = total.add(&bit.scale(Fa4::from_u64(1u64 << j)));
        }
        total_v += fv & ((1u64 << k) - 1);
    }
    let tbits: Vec<Lc> = (0..k + 2).map(|j| b.witness(Fa4::from_u64((total_v >> j) & 1))).collect();
    let mut sum = Lc::default();
    for (j, t) in tbits.iter().enumerate() {
        b.constrain(t, t, t);
        sum = sum.add(&t.scale(Fa4::from_u64(1u64 << j)));
    }
    b.enforce_eq(&sum, &total);
    let index = tbits[..k].iter().enumerate().fold(Lc::default(), |acc, (j, t)| acc.add(&t.scale(Fa4::from_u64(1u64 << j))));
    (tbits[..k].to_vec(), index)
}

/// `folded_domain_gen.exp_u64(index)` on wires: square-and-multiply over the index bits (LSB first). Each factor
/// `1 + bit_j·(g^(2^j) − 1)` is linear in its bit, so `k − 1` products.
pub fn domain_gen_pow(b: &mut R1csBuilder, gen: Fa4, bits: &[Lc]) -> Lc {
    assert!(!bits.is_empty(), "an index has at least one bit");
    let mut g = gen;
    let mut acc = bits[0].scale(g - Fa4::ONE).add_const(Fa4::ONE);
    for bit in &bits[1..] {
        g = g.square();
        let factor = bit.scale(g - Fa4::ONE).add_const(Fa4::ONE);
        acc = b.mul(&acc, &factor);
    }
    acc
}

/// An extension wire times a base wire: four products.
pub fn ext_scale_wire(b: &mut R1csBuilder, e: &ExtLc, w: &Lc) -> ExtLc {
    ExtLc(core::array::from_fn(|i| b.mul(&e.0[i], w)))
}

/// `Poly::new(values).eval_ext(point)` — the multilinear evaluation of `2^m` extension values at an `m`-coordinate
/// point, coordinate 0 MOST significant (`eval_multilinear_recursive`): pairs fold by the last coordinate first,
/// `e0 + x·(e1 − e0)`. `2^m − 1` extension products.
pub fn fold_at_point(b: &mut R1csBuilder, values: &[ExtLc], point: &[ExtLc]) -> ExtLc {
    assert!(!point.is_empty(), "a fold needs at least one coordinate");
    assert_eq!(values.len(), 1usize << point.len(), "2^m values for an m-coordinate point");
    let mut cur: Vec<ExtLc> = values.to_vec();
    for x in point.iter().rev() {
        cur = cur
            .chunks(2)
            .map(|pair| {
                let d = pair[1].sub(&pair[0]);
                pair[0].add(&ext_mul(b, &d, x))
            })
            .collect();
    }
    cur.swap_remove(0)
}

/// `Point::select_poly(var)`: `Π_i (1 − r_i + r_i·var^(2^(n−1−i)))` for the point `r` (coordinate 0 most
/// significant) and a base wire `var` — the powers by squaring the wire, each term four products, the product
/// `n − 1` extension products.
pub fn select_poly_at(b: &mut R1csBuilder, point: &[ExtLc], var: &Lc) -> ExtLc {
    assert!(!point.is_empty(), "a select weight needs at least one coordinate");
    let one = ExtLc::constant(Ea4::ONE);
    let n = point.len();
    let mut pw = var.clone();
    let mut acc = ext_scale_wire(b, &point[n - 1], &pw.add_const(-Fa4::ONE)).add(&one); // r·(var − 1) + 1
    for r in point[..n - 1].iter().rev() {
        pw = b.mul(&pw, &pw);
        let term = ext_scale_wire(b, r, &pw.add_const(-Fa4::ONE)).add(&one);
        acc = ext_mul(b, &acc, &term);
    }
    acc
}

/// `Σ_i c_i·var^i` — the Horner evaluation `SelectStatement::verify` runs on the final polynomial's coefficients
/// at a base wire: `n − 1` steps of four products.
pub fn horner_at(b: &mut R1csBuilder, coeffs: &[ExtLc], var: &Lc) -> ExtLc {
    assert!(!coeffs.is_empty(), "a polynomial has at least one coefficient");
    let n = coeffs.len();
    let mut acc = coeffs[n - 1].clone();
    for c in coeffs[..n - 1].iter().rev() {
        acc = ext_scale_wire(b, &acc, var).add(c);
    }
    acc
}

/// `Constraint::combine_evals` and `eval_constraints_poly`'s shape: `Σ_i γ^i·eq_i + Σ_j γ^(|eq|+j)·sel_j` over
/// extension terms with one running power of `γ` — one product per term past the first, one per power.
pub fn gamma_combine(b: &mut R1csBuilder, gamma: &ExtLc, eq_terms: &[ExtLc], sel_terms: &[ExtLc]) -> ExtLc {
    let terms: Vec<&ExtLc> = eq_terms.iter().chain(sel_terms.iter()).collect();
    assert!(!terms.is_empty(), "a constraint carries at least one claim");
    let mut acc = terms[0].clone();
    let mut pw = gamma.clone();
    for (i, t) in terms.iter().enumerate().skip(1) {
        acc = acc.add(&ext_mul(b, &pw, t));
        if i + 1 < terms.len() {
            pw = ext_mul(b, &pw, gamma);
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spartan_ccs::{prove_committed, verify_committed};
    use p3_symmetric::Permutation;

    fn input(seed: u64) -> [Fa4; WIDTH] {
        core::array::from_fn(|i| Fa4::from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03)))
    }

    /// One permutation as a circuit whose 16 inputs AND 16 outputs are public: the output wires are pinned to the
    /// public outputs, so a verifier of this instance learns "these outputs are the permutation of these inputs".
    fn perm_circuit(x: [Fa4; WIDTH], y: [Fa4; WIDTH]) -> (R1cs, Vec<Fa4>, [Lc; WIDTH]) {
        let io: Vec<Fa4> = x.iter().chain(y.iter()).copied().collect();
        // witness: 2 per cube; 2^10 columns hold 512 witness cells ≥ 2·(8·16 + 20) = 296
        let mut b = R1csBuilder::new(10, &io).expect("33 publics fit a 512-wide public half");
        let state: [Lc; WIDTH] = core::array::from_fn(|i| b.io(i));
        let out = poseidon2_permutation(&mut b, &P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED), &state);
        for i in 0..WIDTH {
            let y_i = b.io(WIDTH + i);
            b.enforce_eq(&out[i], &y_i);
        }
        let (r1cs, w) = b.finish().expect("296 witness cells fit a 512-wide witness half");
        (r1cs, w, out)
    }

    /// ⭐⭐⭐ THE DIFFERENTIAL PIN: the gadget IS the production permutation, wire for wire.
    #[test]
    fn the_poseidon2_gadget_matches_the_production_permutation() {
        let perm = crate::pow_pq_air::production_perm();
        for seed in [1u64, 2, 0xDEAD_BEEF] {
            let x = input(seed);
            let y = perm.permute(x);
            let (r1cs, w, out) = perm_circuit(x, y);
            let io: Vec<Fa4> = x.iter().chain(y.iter()).copied().collect();
            let z = r1cs.lay_z(&io, &w).expect("lays");
            for i in 0..WIDTH {
                assert_eq!(out[i].eval(&z), y[i], "output lane {i} of the gadget is the production permutation's (seed {seed})");
            }
            assert!(r1cs.is_satisfied(&z), "the honest witness satisfies every constraint");
            // a wrong OUTPUT claimed publicly is unsatisfiable with the honest witness
            let mut y_bad = y;
            y_bad[3] += Fa4::ONE;
            let io_bad: Vec<Fa4> = x.iter().chain(y_bad.iter()).copied().collect();
            let z_bad = r1cs.lay_z(&io_bad, &w).expect("lays");
            assert!(!r1cs.is_satisfied(&z_bad), "a moved public output is refused by the equality rows");
            // a moved intermediate (one cube's square) breaks its own constraint
            let mut w_bad = w.clone();
            w_bad[40] += Fa4::ONE;
            let z_bad2 = r1cs.lay_z(&io, &w_bad).expect("lays");
            assert!(!r1cs.is_satisfied(&z_bad2), "a moved intermediate is refused");
        }
        let (r, _, _) = perm_circuit(input(1), input(2));
        eprintln!(
            "[gadget] Poseidon2-16: {} constraints per permutation (= 2·(2·HALF_FULL·16 + PARTIAL)), {} rows laid (2^{})",
            poseidon2_constraints(),
            r.rows(),
            r.m_vars
        );
    }

    /// One real permutation proven and verified on the committed argument — the first production primitive to ride
    /// the O(1)-openings verifier.
    #[test]
    fn a_poseidon2_permutation_proves_and_verifies_on_the_committed_argument() {
        let perm = crate::pow_pq_air::production_perm();
        let x = input(7);
        let y = perm.permute(x);
        let (r1cs, w, _) = perm_circuit(x, y);
        let io: Vec<Fa4> = x.iter().chain(y.iter()).copied().collect();
        let bytes = prove_committed(&r1cs, &io, &w).expect("the permutation proves");
        assert!(verify_committed(&r1cs, &io, &bytes), "the permutation's proof verifies");
        let mut io_bad = io.clone();
        io_bad[WIDTH + 5] += Fa4::ONE;
        assert!(!verify_committed(&r1cs, &io_bad, &bytes), "another output claimed for the same proof is refused");
        eprintln!(
            "[gadget] Poseidon2-16 on the committed argument: {} constraints (2^{}), z 2^{}, proof {} B",
            r1cs.rows(),
            r1cs.m_vars,
            r1cs.n_vars,
            bytes.len()
        );
    }

    fn ext(seed: u64) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| Fa4::from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03)))
    }

    /// ⭐ DIFFERENTIAL: the extension multiply, the Lagrange evaluation and `eq` on wires equal their native twins
    /// (`Ea4::mul`, `air_zerocheck::lagrange_eval`, `spartan_ccs::eq_point`), and each is unsatisfiable under a
    /// moved output — the pins every later gadget composes on.
    #[test]
    fn extension_arithmetic_gadgets_match_their_native_twins() {
        for seed in [3u64, 11, 0xC0FFEE] {
            let (x, y) = (ext(seed), ext(seed + 1));
            let native = x * y;
            let io: Vec<Fa4> = coeffs(x).iter().chain(coeffs(y).iter()).chain(coeffs(native).iter()).copied().collect();
            let mut b = R1csBuilder::new(9, &io).expect("12 publics fit");
            let (xw, yw, want) = (ExtLc::io(&b, 0), ExtLc::io(&b, 4), ExtLc::io(&b, 8));
            let prod = ext_mul(&mut b, &xw, &yw);
            ext_enforce_eq(&mut b, &prod, &want);
            let muls = b.constraints();
            let (r1cs, w) = b.finish().expect("fits");
            let z = r1cs.lay_z(&io, &w).expect("lays");
            assert_eq!(prod.eval(&z), native, "ext_mul equals Ea4 multiplication (seed {seed})");
            assert!(r1cs.is_satisfied(&z));
            assert_eq!(muls, 16 + 4, "16 base products + 4 equality rows");
            let mut io_bad = io.clone();
            io_bad[8] += Fa4::ONE;
            assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io_bad, &w).unwrap()), "a moved product is refused");
            // a constant multiply is linear: no constraints, same value
            let mut b2 = R1csBuilder::new(9, &io).expect("fits");
            let xw2 = ExtLc::io(&b2, 0);
            let kc = xw2.mul_const(y);
            assert_eq!(b2.constraints(), 0);
            let (r2, w2) = { b2.enforce_eq(&kc.0[0], &kc.0[0]); b2.finish().expect("fits") };
            assert_eq!(kc.eval(&r2.lay_z(&io, &w2).unwrap()), native, "mul_const equals Ea4 multiplication");
        }
        // Lagrange over 0..=3 and 0..=2 against the native evaluator
        for (d, seed) in [(3usize, 21u64), (2, 22)] {
            let h: Vec<Ea4> = (0..=d).map(|j| ext(seed + j as u64)).collect();
            let r = ext(seed + 100);
            let native = crate::air_zerocheck::lagrange_eval(&h, r);
            let mut io: Vec<Fa4> = Vec::new();
            for e in h.iter().chain(core::iter::once(&r)).chain(core::iter::once(&native)) {
                io.extend_from_slice(&coeffs(*e));
            }
            let mut b = R1csBuilder::new(9, &io).expect("fits");
            let hw: Vec<ExtLc> = (0..=d).map(|j| ExtLc::io(&b, 4 * j)).collect();
            let rw = ExtLc::io(&b, 4 * (d + 1));
            let want = ExtLc::io(&b, 4 * (d + 2));
            let got = lagrange_at(&mut b, &hw, &rw);
            ext_enforce_eq(&mut b, &got, &want);
            let n = b.constraints();
            let (r1cs, w) = b.finish().expect("fits");
            let z = r1cs.lay_z(&io, &w).expect("lays");
            assert_eq!(got.eval(&z), native, "lagrange_at equals air_zerocheck::lagrange_eval (d = {d})");
            assert!(r1cs.is_satisfied(&z));
            assert_eq!(n, 16 * (d - 1 + d + 1) + 4, "(d−1) power products + (d+1) basis products, 16 each, + 4 rows");
        }
        // eq over 3 variables against the native product
        let tau: Vec<Ea4> = (0..3).map(|k| ext(40 + k)).collect();
        let r: Vec<Ea4> = (0..3).map(|k| ext(50 + k)).collect();
        let native = crate::spartan_ccs::eq_point(&tau, &r);
        let mut io: Vec<Fa4> = Vec::new();
        for e in tau.iter().chain(r.iter()).chain(core::iter::once(&native)) {
            io.extend_from_slice(&coeffs(*e));
        }
        let mut b = R1csBuilder::new(9, &io).expect("fits");
        let tw: Vec<ExtLc> = (0..3).map(|k| ExtLc::io(&b, 4 * k)).collect();
        let rw: Vec<ExtLc> = (0..3).map(|k| ExtLc::io(&b, 12 + 4 * k)).collect();
        let want = ExtLc::io(&b, 24);
        let got = eq_at(&mut b, &tw, &rw);
        ext_enforce_eq(&mut b, &got, &want);
        let (r1cs, w) = b.finish().expect("fits");
        let z = r1cs.lay_z(&io, &w).expect("lays");
        assert_eq!(got.eval(&z), native, "eq_at equals spartan_ccs::eq_point");
        assert!(r1cs.is_satisfied(&z));
        eprintln!("[gadget] ext_mul 16 constraints; lagrange d=3: {}; eq per variable: 48", 16 * 6);
    }

    /// ⭐⭐⭐ DIFFERENTIAL: the sponge on wires produces the SAME challenges as the decider's own `Chl` on the same
    /// absorb/sample script — including a partial-rate absorb before a sample (the carried slots), a multi-pop
    /// extension sample, and observes that clear a half-used output buffer. A challenge derived in-circuit that
    /// differs from the native one by a single element would make every recursive check assert the wrong thing.
    #[test]
    fn the_sponge_gadget_matches_the_deciders_challenger() {
        use p3_challenger::{CanObserve, CanSample, FieldChallenger};
        let mut native = crate::hiding_decider::Chl::new(crate::pow_pq_air::production_perm().clone());
        // 12 public inputs: what the script observes (their values are irrelevant to the wiring, only the schedule)
        let io: Vec<Fa4> = (0..12).map(|i| Fa4::from_u64(1000 + 7 * i as u64)).collect();
        let mut b = R1csBuilder::new(12, &io).expect("fits");
        let mut sponge = SpongeWires::new(crate::whir_rec_block::REC_DECIDER_SEED);
        let mut drawn: Vec<(Lc, Fa4)> = Vec::new();
        // script: 5 observes, one extension sample (4 pops, one duplexing), 3 observes, 2 base samples (a second
        // duplexing with 3 carried rate slots), an extension observe, one more sample
        for i in 0..5 {
            native.observe(io[i]);
            let wire = b.io(i);
            sponge.observe(&mut b, &wire);
        }
        let e_native: Ea4 = native.sample_algebra_element();
        let e_wire = sponge.sample_ext(&mut b);
        for (k, c) in coeffs(e_native).iter().enumerate() {
            drawn.push((e_wire.0[k].clone(), *c));
        }
        for i in 5..8 {
            native.observe(io[i]);
            let wire = b.io(i);
            sponge.observe(&mut b, &wire);
        }
        for _ in 0..2 {
            let n: Fa4 = native.sample();
            let w = sponge.sample(&mut b);
            drawn.push((w, n));
        }
        let ext_in = Ea4::from_basis_coefficients_fn(|k| io[8 + k]);
        native.observe_algebra_element(ext_in);
        let ext_wire = ExtLc::io(&b, 8);
        sponge.observe_ext(&mut b, &ext_wire);
        let n: Fa4 = native.sample();
        let w = sponge.sample(&mut b);
        drawn.push((w, n));
        let z = b.assignment().to_vec();
        for (i, (wire, want)) in drawn.iter().enumerate() {
            assert_eq!(wire.eval(&z), *want, "challenge {i}: the wire sponge and Chl disagree");
        }
        let perms = b.constraints() / poseidon2_constraints();
        assert_eq!(b.constraints() % poseidon2_constraints(), 0, "the sponge costs whole permutations only");
        eprintln!("[gadget] sponge script: {} duplexings, {} constraints, {} challenges matched", perms, b.constraints(), drawn.len());
        assert_eq!(perms, 3, "the script duplexes exactly three times (5 observes+sample, 3 observes+sample, 4 observes+sample)");
    }

    // ── M4 differential pins: each WHIR-verifier gadget against the native function it mirrors ───────────────

    /// `n` chained production permutations with the chain's input and output public: `n · 296` witness cells,
    /// the witness half sized to hold them. Returns `(r1cs, witness, io)`.
    fn perm_chain_circuit(n: usize, x: [Fa4; WIDTH]) -> (R1cs, Vec<Fa4>, Vec<Fa4>) {
        let perm = crate::pow_pq_air::production_perm();
        let mut y = x;
        for _ in 0..n {
            perm.permute_mut(&mut y);
        }
        let io: Vec<Fa4> = x.iter().chain(y.iter()).copied().collect();
        let cells = n * poseidon2_constraints();
        let n_vars = (2 * cells.next_power_of_two()).trailing_zeros() as usize; // witness half = 2^(n_vars-1) ≥ cells
        let mut b = R1csBuilder::new(n_vars, &io).expect("33 publics fit the public half");
        let p2 = P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED);
        let mut s: [Lc; WIDTH] = core::array::from_fn(|i| b.io(i));
        for _ in 0..n {
            s = poseidon2_permutation(&mut b, &p2, &s);
        }
        for i in 0..WIDTH {
            let y_i = b.io(WIDTH + i);
            b.enforce_eq(&s[i], &y_i);
        }
        let (r1cs, w) = b.finish().expect("the cells fit the witness half");
        (r1cs, w, io)
    }

    fn perm_for(seed: u64) -> crate::hiding_decider::Perm16 {
        use rand::SeedableRng;
        crate::hiding_decider::Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed))
    }
    fn ea(s: u64) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|j| Fa4::from_u64(s.wrapping_mul(0x9E37_79B9) ^ (j as u64 + 1).wrapping_mul(0x51_7CC1_B727)))
    }

    /// Gadget 1 — `SumcheckData::verify_rounds` with no grinding: the folded claim and every challenge agree, the
    /// circuit is satisfied by its own assignment, and a moved public claim is refused with the honest witness.
    #[test]
    fn the_sumcheck_round_gadget_matches_verify_rounds() {
        use p3_sumcheck::SumcheckData;
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31; // the Spartan transcript's permutation
        let k = 3usize;
        let claim0 = ea(1);
        let evals: Vec<[Ea4; 2]> = (0..k as u64).map(|i| [ea(10 + i), ea(20 + i)]).collect();
        let mut io: Vec<Fa4> = coeffs(claim0).to_vec();
        for [h0, hinf] in &evals {
            io.extend(coeffs(*h0));
            io.extend(coeffs(*hinf));
        }
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        let data = SumcheckData::<Fa4, Ea4> { polynomial_evaluations: evals.clone(), pow_witnesses: Vec::new() };
        let mut claim_native = claim0;
        let point = data.verify_rounds(&mut native, &mut claim_native, 0).expect("honest rounds verify natively");

        let mut b = R1csBuilder::new(13, &io).expect("fits");
        let mut sponge = SpongeWires::new(seed);
        let mut claim = ExtLc::io(&b, 0);
        let mut rs = Vec::new();
        for i in 0..k {
            let h0 = ExtLc::io(&b, 4 + 8 * i);
            let hinf = ExtLc::io(&b, 8 + 8 * i);
            let (next, r) = sumcheck_round_01inf(&mut b, &mut sponge, &claim, &h0, &hinf);
            claim = next;
            rs.push(r);
        }
        let z = b.assignment().to_vec();
        assert_eq!(claim.eval(&z), claim_native, "the folded claim differs from verify_rounds");
        for (i, r) in rs.iter().enumerate() {
            assert_eq!(r.eval(&z), point.as_slice()[i], "challenge {i} differs from verify_rounds");
        }
        let constraints = b.constraints();
        let (r1cs, w) = b.finish().expect("fits");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).unwrap()), "the honest assignment satisfies the circuit");
        let mut moved = io.clone();
        moved[0] += Fa4::ONE;
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&moved, &w).unwrap()), "a moved public claim must be refused with the honest witness");
        eprintln!("[gadget] sumcheck rounds: {k} rounds, {constraints} constraints, claim + {k} challenges matched");
    }

    /// Gadget 2 — `Point::expand_from_univariate` alone, then `ParsedCommitment::parse_with_round` on a REAL
    /// committed Spartan proof's first round: the OOD points, the OOD evaluations and the challenger state after
    /// parsing (one further sample) agree.
    #[test]
    fn the_parse_commitment_gadget_matches_parse_with_round() {
        use crate::hiding_decider::Mmcs16;
        use crate::spartan_ccs::{committed_pcs, SpartanCommittedProof};
        use p3_challenger::FieldChallenger;
        use p3_commit::Mmcs;
        use p3_multilinear_util::point::Point;
        use p3_whir::pcs::committer::reader::ParsedCommitment;
        let y = ea(77);
        let want = Point::expand_from_univariate(y, 6);
        let mut b = R1csBuilder::new(8, &coeffs(y)).expect("fits");
        let yw = ExtLc::io(&b, 0);
        let got = expand_from_univariate(&mut b, &yw, 6);
        let z = b.assignment().to_vec();
        for j in 0..6 {
            assert_eq!(got[j].eval(&z), want.as_slice()[j], "power {j} differs from expand_from_univariate");
        }

        // a real proof whose PCS has at least one WHIR round (a 512-cell witness folds straight to the final
        // polynomial and carries NO round commitment — measured 23:11: `round_parameters` empty at 2^9 cells)
        let mut n = 8usize;
        let (r1cs, w, io) = loop {
            let c = perm_chain_circuit(n, input(5));
            if !committed_pcs(&c.0).config.round_parameters.is_empty() {
                break c;
            }
            assert!(n < 1024, "no WHIR round even at {n} chained permutations");
            n *= 2;
        };
        let bytes = prove_committed(&r1cs, &io, &w).expect("a real committed proof");
        let p: SpartanCommittedProof = postcard::from_bytes(&bytes).expect("decodes");
        let pcs = committed_pcs(&r1cs);
        assert!(!pcs.config.round_parameters.is_empty(), "the pin needs a round commitment to parse");
        eprintln!(
            "[gadget] parse_commitment pin: {n} chained permutations, w_vars {}, {} WHIR round(s), proof {} B",
            r1cs.w_vars(),
            pcs.config.round_parameters.len(),
            bytes.len()
        );
        let rp = &pcs.config.round_parameters[0];
        let seed = 0xC0DE_u64; // the differential is about the schedule: native and wires run the same permutation
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        let parsed = ParsedCommitment::<Fa4, <Mmcs16 as Mmcs<Fa4>>::Commitment>::parse_with_round(
            &p.open,
            &mut native,
            rp.num_variables,
            rp.ood_samples,
            0,
        )
        .expect("parses natively");
        let root: [Fa4; RATE] = p.open.rounds[0].commitment.as_ref().expect("round 0 carries a root").roots()[0];
        let answers = &p.open.rounds[0].ood_answers;
        assert_eq!(answers.len(), rp.ood_samples);
        let mut io2: Vec<Fa4> = root.to_vec();
        for a in answers {
            io2.extend(coeffs(*a));
        }
        let mut b = R1csBuilder::new(13, &io2).expect("fits");
        let root_w: [Lc; RATE] = core::array::from_fn(|k| b.io(k));
        let ans_w: Vec<ExtLc> = (0..answers.len()).map(|i| ExtLc::io(&b, RATE + 4 * i)).collect();
        let mut sponge = SpongeWires::new(seed);
        let claims = parse_commitment(&mut b, &mut sponge, &root_w, &ans_w, rp.num_variables);
        let n_after: Ea4 = native.sample_algebra_element();
        let w_after = sponge.sample_ext(&mut b);
        let z = b.assignment().to_vec();
        let native_claims: Vec<_> = parsed.ood_statement.iter().collect();
        assert_eq!(native_claims.len(), claims.len());
        for (i, ((pt, ev), c)) in native_claims.iter().zip(&claims).enumerate() {
            assert_eq!(c.point.len(), rp.num_variables);
            for j in 0..rp.num_variables {
                assert_eq!(c.point[j].eval(&z), pt.as_slice()[j], "ood {i} point variable {j}");
            }
            assert_eq!(c.eval.eval(&z), **ev, "ood {i} evaluation");
        }
        assert_eq!(w_after.eval(&z), n_after, "the challenger state after parsing differs");
        eprintln!(
            "[gadget] parse_commitment: {} OOD sample(s) over {} variables, {} constraints",
            rp.ood_samples,
            rp.num_variables,
            b.constraints()
        );
    }

    /// Gadget 4 — the leaf sponge at every padding shape, the truncated compression, and a full Merkle path against
    /// the committed carrier's OWN MMCS (`Mmcs16`, salted leaves, `COMMITTED_AIR_SEED` permutation): the wire root
    /// equals the commitment at four indices, and a flipped path bit is refused with the honest witness.
    #[test]
    fn the_merkle_path_gadget_matches_the_pcs_mmcs() {
        use crate::hiding_decider::{CompressHash, Mmcs16, SpongeHash};
        use p3_commit::{BatchOpeningRef, Mmcs};
        use p3_matrix::{dense::RowMajorMatrix, Dimensions};
        use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
        use rand::SeedableRng;
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        let perm = perm_for(seed);
        let (hash, compress) = (SpongeHash::new(perm.clone()), CompressHash::new(perm.clone()));
        let mmcs = Mmcs16::new(hash.clone(), compress.clone(), 0, rand::rngs::SmallRng::seed_from_u64(seed + 7));
        let p2 = P2Consts::for_seed(seed);
        for len in [0usize, 1, 7, 8, 9, 16, 17, 20] {
            let row: Vec<Fa4> = (0..len).map(|i| Fa4::from_u64(i as u64 * 31 + 11)).collect();
            let want = hash.hash_iter(row.iter().copied());
            let mut b = R1csBuilder::new(11, &row).expect("fits");
            let wires: Vec<Lc> = (0..len).map(|i| b.io(i)).collect();
            let got = sponge_hash(&mut b, &p2, &wires);
            let z = b.assignment().to_vec();
            for k in 0..RATE {
                assert_eq!(got[k].eval(&z), want[k], "leaf hash lane {k} at len {len}");
            }
            let perms = if len == 0 { 0 } else { len.div_ceil(RATE) };
            assert_eq!(b.constraints(), perms * poseidon2_constraints(), "len {len} costs ceil(len/8) permutations");
        }
        {
            let l: [Fa4; RATE] = core::array::from_fn(|k| Fa4::from_u64(k as u64 + 1));
            let r: [Fa4; RATE] = core::array::from_fn(|k| Fa4::from_u64(100 + k as u64));
            let want = compress.compress([l, r]);
            let io: Vec<Fa4> = l.iter().chain(r.iter()).copied().collect();
            let mut b = R1csBuilder::new(10, &io).expect("fits");
            let lw: [Lc; RATE] = core::array::from_fn(|k| b.io(k));
            let rw: [Lc; RATE] = core::array::from_fn(|k| b.io(RATE + k));
            let got = merkle_compress(&mut b, &p2, &lw, &rw);
            let z = b.assignment().to_vec();
            for k in 0..RATE {
                assert_eq!(got[k].eval(&z), want[k], "compress lane {k}");
            }
        }
        // a real tree: 64 salted rows of width 4, the shape in which the PCS commits a folded evaluation table
        let (height, width) = (1usize << 6, 4usize);
        let values: Vec<Fa4> = (0..height * width).map(|i| Fa4::from_u64(i as u64 * 7 + 3)).collect();
        let (commit, pd) = mmcs.commit(vec![RowMajorMatrix::new(values, width)]);
        let want_root: [Fa4; RATE] = commit.roots()[0];
        for index in [0usize, 1, 37, 63] {
            let opening = mmcs.open_batch(index, &pd);
            let dims = [Dimensions { height, width }];
            mmcs.verify_batch(
                &commit,
                &dims,
                index,
                BatchOpeningRef { opened_values: &opening.opened_values, opening_proof: &opening.opening_proof },
            )
            .expect("the native MMCS accepts its own opening");
            let (salts, siblings) = &opening.opening_proof;
            assert_eq!(siblings.len(), 6, "64 leaves, arity 2, cap height 0");
            let row: Vec<Fa4> = opening.opened_values[0].iter().chain(salts[0].iter()).copied().collect();
            assert_eq!(row.len(), width + 8, "opened values ‖ 8 salt elements");
            let n_sib = siblings.len();
            let mut io: Vec<Fa4> = row.clone();
            for s in siblings {
                io.extend_from_slice(s);
            }
            io.extend((0..n_sib).map(|l| Fa4::from_u64(((index >> l) & 1) as u64)));
            let mut b = R1csBuilder::new(13, &io).expect("fits");
            let row_w: Vec<Lc> = (0..row.len()).map(|i| b.io(i)).collect();
            let leaf = sponge_hash(&mut b, &p2, &row_w);
            let sib_w: Vec<[Lc; RATE]> =
                (0..n_sib).map(|l| core::array::from_fn(|k| b.io(row.len() + RATE * l + k))).collect();
            let bit_w: Vec<Lc> = (0..n_sib).map(|l| b.io(row.len() + RATE * n_sib + l)).collect();
            let root = merkle_root_from_path(&mut b, &p2, leaf, &sib_w, &bit_w);
            let z = b.assignment().to_vec();
            for k in 0..RATE {
                assert_eq!(root[k].eval(&z), want_root[k], "root lane {k} at index {index}");
            }
            let constraints = b.constraints();
            let (r1cs, w) = b.finish().expect("fits");
            assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).unwrap()));
            let mut flipped = io.clone();
            let bit0 = row.len() + RATE * n_sib;
            flipped[bit0] = Fa4::ONE - flipped[bit0];
            assert!(
                !r1cs.is_satisfied(&r1cs.lay_z(&flipped, &w).unwrap()),
                "a flipped path bit must be refused with the honest witness"
            );
            eprintln!("[gadget] merkle path index {index}: {} permutations, {constraints} constraints, root matched", 2 + n_sib);
        }
    }

    /// Gadget 3a — canonical bits: eight values' bits match their integers and satisfy the circuit; the alias
    /// `5 + p` (31 bits too) is REFUSED with every product wire recomputed honestly from the alias bits.
    #[test]
    fn the_canonical_bits_gadget_pins_one_decomposition_per_element() {
        use p3_field::PrimeField64;
        let p = Fa4::ORDER_U64;
        for v in [0u64, 1, 5, p - 1, (1 << 24) - 1, 0x7F00_0000, 0x1234_5678, p - (1 << 24)] {
            let x = Fa4::from_u64(v);
            let mut b = R1csBuilder::new(8, &[x]).expect("fits");
            let xw = b.io(0);
            let bits = canonical_bits(&mut b, &xw);
            let z = b.assignment().to_vec();
            for (i, bit) in bits.iter().enumerate() {
                assert_eq!(bit.eval(&z), Fa4::from_u64((v >> i) & 1), "bit {i} of {v}");
            }
            assert_eq!(b.constraints(), P_BITS + 1 + 6 + 1, "31 booleans + sum + 6 chain products + range");
            let (r1cs, w) = b.finish().expect("fits");
            assert!(r1cs.is_satisfied(&r1cs.lay_z(&[x], &w).unwrap()), "honest bits of {v} satisfy");
        }
        let x = Fa4::from_u64(5);
        let mut b = R1csBuilder::new(8, &[x]).expect("fits");
        let xw = b.io(0);
        let bits = canonical_bits(&mut b, &xw);
        let first = bits[0].terms[0].0;
        let (r1cs, mut w) = b.finish().expect("fits");
        let off = r1cs.w_off();
        let alias = 5 + p;
        assert!(alias < (1u64 << 31), "the alias fits 31 bits — only the range rows can refuse it");
        for i in 0..P_BITS {
            w[first + i - off] = Fa4::from_u64((alias >> i) & 1);
        }
        let mut prod = (alias >> 24) & 1;
        for k in 0..6 {
            prod &= (alias >> (25 + k)) & 1;
            w[first + P_BITS + k - off] = Fa4::from_u64(prod);
        }
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&[x], &w).unwrap()), "the alias 5 + p must be refused");
    }

    /// Gadget 3 — `draw_below(2^k)` on wires equals the native draw from the same sponge state, k ∈ {1, 4, 12, 24}.
    #[test]
    fn the_stir_index_gadget_matches_draw_below() {
        use p3_challenger::CanObserve;
        use p3_whir::pcs::utils::draw_below;
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        for k in [1usize, 4, 12, 24] {
            let io: Vec<Fa4> = (0..3).map(|i| Fa4::from_u64(900 + k as u64 * 3 + i)).collect();
            let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
            for &v in &io {
                native.observe(v);
            }
            let want: Vec<usize> = (0..3).map(|_| draw_below::<_, Fa4>(&mut native, 1usize << k)).collect();
            let mut b = R1csBuilder::new(12, &io).expect("fits");
            let mut sponge = SpongeWires::new(seed);
            for i in 0..3 {
                let wire = b.io(i);
                sponge.observe(&mut b, &wire);
            }
            let got: Vec<(Vec<Lc>, Lc)> = (0..3).map(|_| stir_index(&mut b, &mut sponge, k)).collect();
            let z = b.assignment().to_vec();
            for (q, (bits, idx)) in got.iter().enumerate() {
                assert_eq!(idx.eval(&z), Fa4::from_u64(want[q] as u64), "k={k} query {q} index");
                assert_eq!(bits.len(), k);
                for (j, bit) in bits.iter().enumerate() {
                    assert_eq!(bit.eval(&z), Fa4::from_u64(((want[q] >> j) & 1) as u64), "k={k} query {q} bit {j}");
                }
            }
            let constraints = b.constraints();
            let (r1cs, w) = b.finish().expect("fits");
            assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).unwrap()));
            eprintln!("[gadget] stir_index k={k}: {constraints} constraints for 3 queries (incl. the sponge)");
        }
    }

    /// Gadgets 5–8 — `exp_u64` by bits, the multilinear fold, `select_poly`, Horner (through
    /// `SelectStatement::verify`), and `Constraint::combine_evals` / `eval_constraints_poly`.
    #[test]
    fn the_folding_gadgets_match_their_native_twins() {
        use p3_field::TwoAdicField;
        use p3_multilinear_util::{point::Point, poly::Poly};
        use p3_sumcheck::constraints::statement::{EqStatement, SelectStatement};
        use p3_sumcheck::constraints::Constraint;
        use p3_sumcheck::strategy::VariableOrder;
        let g = Fa4::two_adic_generator(10);
        for index in [0usize, 1, 513, 1023] {
            let bits: Vec<Fa4> = (0..10).map(|j| Fa4::from_u64(((index >> j) & 1) as u64)).collect();
            let mut b = R1csBuilder::new(8, &bits).expect("fits");
            let bw: Vec<Lc> = (0..10).map(|j| b.io(j)).collect();
            let got = domain_gen_pow(&mut b, g, &bw);
            assert_eq!(got.eval(b.assignment()), g.exp_u64(index as u64), "g^{index}");
            assert_eq!(b.constraints(), 9, "k − 1 products");
        }
        let values: Vec<Ea4> = (0..16u64).map(|i| ea(300 + i)).collect();
        let point: Vec<Ea4> = (0..4u64).map(|i| ea(400 + i)).collect();
        let want = Poly::new(values.clone()).eval_ext::<Fa4>(&Point::new(point.clone()));
        let mut io: Vec<Fa4> = Vec::new();
        for v in &values {
            io.extend(coeffs(*v));
        }
        for r in &point {
            io.extend(coeffs(*r));
        }
        let mut b = R1csBuilder::new(10, &io).expect("fits");
        let vw: Vec<ExtLc> = (0..16).map(|i| ExtLc::io(&b, 4 * i)).collect();
        let pw: Vec<ExtLc> = (0..4).map(|i| ExtLc::io(&b, 64 + 4 * i)).collect();
        let got = fold_at_point(&mut b, &vw, &pw);
        assert_eq!(got.eval(b.assignment()), want, "fold_at_point vs Poly::eval_ext");
        assert_eq!(b.constraints(), 15 * 16, "2^m − 1 extension products");

        let var = Fa4::from_u64(0x0F0F_1234);
        let nv = 4usize;
        let r: Vec<Ea4> = (0..nv as u64).map(|i| ea(500 + i)).collect();
        let rp = Point::new(r.clone());
        let final_poly: Vec<Ea4> = (0..8u64).map(|i| ea(600 + i)).collect();
        let mut io: Vec<Fa4> = vec![var];
        for x in &r {
            io.extend(coeffs(*x));
        }
        for c in &final_poly {
            io.extend(coeffs(*c));
        }
        let mut b = R1csBuilder::new(10, &io).expect("fits");
        let varw = b.io(0);
        let rw: Vec<ExtLc> = (0..nv).map(|i| ExtLc::io(&b, 1 + 4 * i)).collect();
        let cw: Vec<ExtLc> = (0..8).map(|i| ExtLc::io(&b, 1 + 4 * nv + 4 * i)).collect();
        let sel = select_poly_at(&mut b, &rw, &varw);
        let hor = horner_at(&mut b, &cw, &varw);
        let z = b.assignment().to_vec();
        assert_eq!(sel.eval(&z), rp.select_poly(var), "select_poly_at vs Point::select_poly");
        let hv = hor.eval(&z);
        let statement = SelectStatement::<Fa4, Ea4>::new(3, vec![var], vec![hv]);
        assert!(statement.verify(&Poly::new(final_poly.clone())), "SelectStatement::verify accepts the wire Horner value");
        let wrong = SelectStatement::<Fa4, Ea4>::new(3, vec![var], vec![hv + Ea4::ONE]);
        assert!(!wrong.verify(&Poly::new(final_poly.clone())), "and refuses a moved one");

        let eq_pts: Vec<Point<Ea4>> =
            (0..2u64).map(|i| Point::new((0..nv as u64).map(|j| ea(700 + 10 * i + j)).collect())).collect();
        let eq_evals: Vec<Ea4> = (0..2u64).map(|i| ea(800 + i)).collect();
        let sel_vars: Vec<Fa4> = vec![Fa4::from_u64(77), Fa4::from_u64(0x7A00_0001)];
        let sel_evals: Vec<Ea4> = (0..2u64).map(|i| ea(900 + i)).collect();
        let gamma = ea(1000);
        let mut eqs = EqStatement::<Ea4>::initialize(nv);
        for (pt, e) in eq_pts.iter().zip(&eq_evals) {
            eqs.add_evaluated_constraint(pt.clone(), *e);
        }
        let sels = SelectStatement::<Fa4, Ea4>::new(nv, sel_vars.clone(), sel_evals.clone());
        let constraint = Constraint::new(gamma, eqs, sels);
        let mut want_combined = Ea4::ZERO;
        constraint.combine_evals(&mut want_combined);
        let want_weights = VariableOrder::Prefix.eval_constraints_poly(&[constraint], &rp);
        let mut io: Vec<Fa4> = Vec::new();
        for x in &r {
            io.extend(coeffs(*x)); // 0..16
        }
        for pt in &eq_pts {
            for x in pt.as_slice() {
                io.extend(coeffs(*x)); // 16..48
            }
        }
        for e in &eq_evals {
            io.extend(coeffs(*e)); // 48..56
        }
        io.extend(&sel_vars); // 56..58
        for e in &sel_evals {
            io.extend(coeffs(*e)); // 58..66
        }
        io.extend(coeffs(gamma)); // 66..70
        let mut b = R1csBuilder::new(12, &io).expect("fits");
        let rw: Vec<ExtLc> = (0..nv).map(|i| ExtLc::io(&b, 4 * i)).collect();
        let eq_pw: Vec<Vec<ExtLc>> =
            (0..2).map(|i| (0..nv).map(|j| ExtLc::io(&b, 16 + 16 * i + 4 * j)).collect()).collect();
        let eq_ew: Vec<ExtLc> = (0..2).map(|i| ExtLc::io(&b, 48 + 4 * i)).collect();
        let sel_vw: Vec<Lc> = (0..2).map(|i| b.io(56 + i)).collect();
        let sel_ew: Vec<ExtLc> = (0..2).map(|i| ExtLc::io(&b, 58 + 4 * i)).collect();
        let gw = ExtLc::io(&b, 66);
        let combined = gamma_combine(&mut b, &gw, &eq_ew, &sel_ew);
        let eq_terms: Vec<ExtLc> = eq_pw.iter().map(|pt| eq_at(&mut b, pt, &rw)).collect();
        let sel_terms: Vec<ExtLc> = sel_vw.iter().map(|v| select_poly_at(&mut b, &rw, v)).collect();
        let weights = gamma_combine(&mut b, &gw, &eq_terms, &sel_terms);
        let z = b.assignment().to_vec();
        assert_eq!(combined.eval(&z), want_combined, "gamma_combine vs Constraint::combine_evals");
        assert_eq!(weights.eval(&z), want_weights, "weights vs eval_constraints_poly");
        eprintln!(
            "[gadget] folding: fold 2^4 = 240 constraints; select over {nv} vars + Horner over 8 coefficients matched; γ-combine of 2 eq + 2 sel claims and their weights matched eval_constraints_poly ({} constraints)",
            b.constraints()
        );
    }

    /// ⭐⭐ THE STREAMED ARGUMENT EQUALS THE STORED ONE (lane vaults, 2026-11-15): one circuit (chained products, witnesses,
    /// equalities, constants on column 0) built laid and streamed. The streamed `A·z`, `B·z`, `C·z` equal the laid matrices'
    /// products, its `M_r` replay and its `Mle` replay equal the laid entries' sums at a random point, and the witness half is
    /// the same; a proof of either prover verifies under BOTH verifiers. TAMPER: a moved public is refused by both verifiers,
    /// for both proofs; an unsatisfied streamed witness has no proof.
    #[test]
    fn the_streamed_argument_equals_the_stored_one() {
        use crate::spartan_ccs::{prove_committed, prove_committed_streamed, verify_committed, verify_committed_streamed, MIN_W_VARS};
        let io = vec![Fa4::from_u64(3), Fa4::from_u64(5)];
        let nv = (MIN_W_VARS + 1).max(14);
        let build = |mut b: R1csBuilder, bad: bool| -> R1csBuilder {
            let (x, y) = (b.io(0), b.io(1));
            let mut acc = b.mul(&x, &y);
            for k in 0..3_000u64 {
                let wk = b.witness(Fa4::from_u64(k + 1 + u64::from(bad && k == 1_234)));
                acc = b.mul(&acc.add(&wk), &x.add(&Lc::constant(Fa4::from_u64(k))));
                // wk·1 = k + 1: a constant on column 0 in C
                b.constrain(&wk, &Lc::constant(Fa4::ONE), &Lc::constant(Fa4::from_u64(k + 1)));
            }
            b.enforce_eq(&acc, &acc.add(&Lc::constant(Fa4::ZERO)));
            b
        };
        let (laid, w) = build(R1csBuilder::new(nv, &io).expect("builder"), false).finish().expect("lays");
        let (shape, sink, w2) = build(R1csBuilder::new_streaming(nv, &io, Sink::Abc(Default::default())).expect("builder"), false).finish_stream().expect("streams");
        assert_eq!(w, w2, "the same witness half");
        assert_eq!((shape.m_vars, shape.n_vars, shape.io_len), (laid.m_vars, laid.n_vars, laid.io_len), "the same shape");
        let Sink::Abc(abc) = sink else { panic!("an Abc sink") };
        let z = laid.lay_z(&io, &w).expect("lays z");
        for (t, m) in abc.iter().zip([&laid.a, &laid.b, &laid.c]) {
            let mut want = vec![Fa4::ZERO; laid.rows()];
            for &(r, c, v) in m {
                want[r] += v * z[c];
            }
            assert_eq!(*t, want, "⛔ a streamed product differs from the laid matrix's");
        }
        // a random point: M_r and the MLE by replay against the laid entries
        let mut s = 0x5EED_u64;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            Ea4::from(Fa4::from_u64(s % 2_000_000_000))
        };
        let eq_x: Vec<Ea4> = (0..laid.rows()).map(|_| rnd()).collect();
        let eq_y: Vec<Ea4> = (0..laid.cols()).map(|_| rnd()).collect();
        let coef = [rnd(), rnd(), rnd()];
        let (mut want_mr, mut want_mle) = (vec![Ea4::ZERO; laid.cols()], Ea4::ZERO);
        for (k, m) in [&laid.a, &laid.b, &laid.c].into_iter().enumerate() {
            for &(r, c, v) in m {
                want_mr[c] += eq_x[r] * coef[k] * Ea4::from(v);
                want_mle += coef[k] * eq_x[r] * eq_y[c] * Ea4::from(v);
            }
        }
        let replay = |sink: Sink| build(R1csBuilder::new_streaming(nv, &io, sink).expect("builder"), false).finish_stream().expect("streams").1;
        let Sink::Mr { out, .. } = replay(Sink::Mr { eq: eq_x.clone(), coef, out: vec![Ea4::ZERO; laid.cols()] }) else { panic!("an Mr sink") };
        assert_eq!(out, want_mr, "⛔ the streamed M_r differs from the laid entries'");
        let Sink::Mle { acc, .. } = replay(Sink::Mle { eq_x, eq_y, coef, acc: Ea4::ZERO }) else { panic!("an Mle sink") };
        assert_eq!(acc, want_mle, "⛔ the streamed MLE differs from the laid entries'");
        // proofs of both provers, verified by both verifiers
        let mr_of = |eq: Vec<Ea4>, coef: [Ea4; 3]| match replay(Sink::Mr { eq, coef, out: vec![Ea4::ZERO; laid.cols()] }) {
            Sink::Mr { out, .. } => Some(out),
            _ => None,
        };
        let mle_of = |eq_x: Vec<Ea4>, eq_y: Vec<Ea4>, coef: [Ea4; 3]| match replay(Sink::Mle { eq_x, eq_y, coef, acc: Ea4::ZERO }) {
            Sink::Mle { acc, .. } => Some(acc),
            _ => None,
        };
        let stored = prove_committed(&laid, &io, &w).expect("the laid instance proves");
        let streamed = prove_committed_streamed(&shape, &io, &w, abc, mr_of).expect("the streamed instance proves");
        for (what, p) in [("stored", &stored), ("streamed", &streamed)] {
            assert!(verify_committed(&laid, &io, p), "⛔ the {what} proof fails the laid verifier");
            assert!(verify_committed_streamed(&shape, &io, p, &mle_of), "⛔ the {what} proof fails the streamed verifier");
            let mut moved = io.clone();
            moved[1] += Fa4::ONE;
            assert!(!verify_committed(&laid, &moved, p), "⛔ TAMPER: the {what} proof verified a moved public (laid)");
            assert!(!verify_committed_streamed(&shape, &moved, p, &mle_of), "⛔ TAMPER: the {what} proof verified a moved public (streamed)");
        }
        // an unsatisfied witness: its streamed products miss a row, so it has no proof
        let (bshape, bsink, bw) = build(R1csBuilder::new_streaming(nv, &io, Sink::Abc(Default::default())).expect("builder"), true).finish_stream().expect("streams");
        let Sink::Abc(babc) = bsink else { panic!("an Abc sink") };
        assert!(prove_committed_streamed(&bshape, &io, &bw, babc, |_, _| None).is_none(), "⛔ an unsatisfied streamed witness proved");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ LANE AGG, THE TREE, STEP 1 (2026-11-15) — A CARRIER GATE AS A STRAIGHT-LINE PROGRAM.
//!
//! WHY. A proof that verifies another proof must evaluate the inner AIR's constraint at the inner proof's opened row
//! (`claim_last == eq(z, r) · C_γ(opened)`, `recursion_bound`). Composition (the inner gate applied row-locally on cells
//! of the outer row) costs ~4× the inner width a level and has no fixpoint (`O1-OPENINGS-RECURSION-SPEC`: "W' ≥ 4·W' has
//! no fixpoint"), so a tree of proofs must evaluate the inner gate by ARITHMETIC ROWS. That needs the gate as a program.
//!
//! HOW. The three payment-carrier gates (`SpendValidityGate`, `MemberPathGate`, `CoverOrSpendGate`) and every helper they
//! call are generic over the field their row lives in, with the type parameter NAMED `Ea4` so each body is byte-for-byte
//! the body that runs in production (the precedent: `pow_pq_air::push_perm_residuals`, generic since 2026-09-29). This
//! module's [`Sym`] is a `Copy` ring element that records every operation into a thread-local DAG instead of computing
//! it; running a gate's residual list on `Sym` inputs yields that list as a [`GateProgram`]. The production
//! instantiation (`Ea4`) is unchanged code: monomorphisation emits the same machine code it always did.
//!
//! WHAT A PROGRAM IS. Inputs, then ops (`Konst`, `Add`, `Sub`, `Mul`, `Neg`, each operand an EARLIER op), then the
//! outputs in the gate's own residual order. Built with constant folding, the ring identities `x+0`, `x·1`, `x·0`, and
//! hash-consing (one op per distinct operation), then dead code removed. Every rewrite is an identity in any
//! commutative ring containing the base field, so the program computes exactly the gate's residuals: the pin
//! `agg_t1_every_carrier_gate_is_its_program` demands equality on random extension rows for all three classes, folded
//! and unfolded, with one tampered op that must disagree.
//!
//! §9.6: not a door (no outside bytes enter; a program is built from this crate's own gate code). (5) work: one pass
//! over the gate's ops. (7) scale: a constant per carrier class. (8) protected by (b) code, held to (a) by the pin.
//! cons: none at runtime (the `Ea4` instantiation is the code that ran before); +1 module; a program lives only while a
//! caller holds it (the spend gate's: NOT MEASURED until the pin prints it).

use std::cell::RefCell;
use std::collections::HashMap;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use p3_field::{Algebra, PrimeCharacteristicRing};

use crate::hiding_decider::{Ea4, Fa4};

/// What a gate body needs of the field its row lives in: the ring operations over the base field, by value.
/// `Ea4` (production), `Fa4` (a zerocheck's base-field round) and [`Sym`] (the tracer) all satisfy it.
pub trait GateAlg: Algebra<Fa4> + Copy + Send + Sync + 'static {}
impl<T: Algebra<Fa4> + Copy + Send + Sync + 'static> GateAlg for T {}

/// One operation of a [`GateProgram`]; every operand names an EARLIER op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GOp {
    /// The program's `i`-th input.
    Input(u32),
    /// A constant (the gates' constants are base-field values, lifted).
    Konst(Ea4),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    Neg(u32),
    /// Residual `k` of OPAQUE permutation block `block` (`GateProgram::perm_blocks`): a traced gate's Poseidon2 block
    /// kept as one unit, so a circuit can check it with a dedicated row instead of its ~3,000-op tape.
    PermOut { block: u32, k: u32 },
}

/// An opaque permutation block: the op ids of its `P2_COLS` cells, and the seed of its constants (`None` = the
/// production constants `push_perm_residuals` uses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermBlock {
    pub cells: Vec<u32>,
    pub seed: Option<u64>,
}

struct Arena {
    ops: Vec<GOp>,
    memo: HashMap<GOp, u32>,
    konst: HashMap<Ea4, u32>,
    blocks: Vec<PermBlock>,
}

thread_local! {
    static ARENA: RefCell<Option<Arena>> = const { RefCell::new(None) };
    /// Set by [`trace_opaque`]: permutation blocks are recorded as units, not inlined.
    static OPAQUE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// The hook `pow_pq_air::push_perm_residuals{,_seeded}` call first. It does anything only when the row's field IS
/// [`Sym`] (a compile-time `TypeId` comparison: for `Ea4` and `Fa4` the branch is dead code, so the prover's code is
/// unchanged) and an opaque trace is running; then the block's residuals are `PermOut` nodes.
pub fn opaque_perm<E: Copy + 'static>(local: &crate::air_zerocheck::Row<'_, E>, base: usize, seed: Option<u64>) -> Option<Vec<E>> {
    if core::any::TypeId::of::<E>() != core::any::TypeId::of::<Sym>() || !OPAQUE.with(core::cell::Cell::get) {
        return None;
    }
    let p2 = crate::pow_pq_air::P2_COLS;
    // SAFETY: `E` is `Sym` (the TypeIds are equal), so these copies are of one type to itself.
    let cells: Vec<u32> = (0..p2).map(|k| unsafe { core::mem::transmute_copy::<E, Sym>(&local[base + k]) }.0).collect();
    let n = match seed {
        Some(sd) => crate::pow_pq_air::perm_residual_count_seeded(sd),
        None => crate::pow_pq_air::perm_residual_count(),
    };
    let outs: Vec<Sym> = with_arena(|a| {
        let block = a.blocks.len() as u32;
        a.blocks.push(PermBlock { cells, seed });
        (0..n as u32).map(|k| intern(a, GOp::PermOut { block, k })).collect()
    });
    // SAFETY: as above, `Sym` to `E` where they are one type.
    Some(outs.into_iter().map(|s| unsafe { core::mem::transmute_copy::<Sym, E>(&s) }).collect())
}

/// The ids every arena reserves for the ring's named constants, so `Sym::ZERO` … `Sym::NEG_ONE` can be `const`.
const ID_ZERO: u32 = 0;
const ID_ONE: u32 = 1;
const ID_TWO: u32 = 2;
const ID_NEG_ONE: u32 = 3;

/// A traced ring element: an index into the thread's DAG. Only meaningful inside [`trace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sym(u32);

fn with_arena<R>(f: impl FnOnce(&mut Arena) -> R) -> R {
    ARENA.with(|a| f(a.borrow_mut().as_mut().expect("a Sym is used only inside gate_trace::trace")))
}

fn konst_of(a: &Arena, s: Sym) -> Option<Ea4> {
    match a.ops[s.0 as usize] {
        GOp::Konst(c) => Some(c),
        _ => None,
    }
}

fn intern(a: &mut Arena, op: GOp) -> Sym {
    if let GOp::Konst(c) = op {
        if let Some(&id) = a.konst.get(&c) {
            return Sym(id);
        }
        let id = a.ops.len() as u32;
        a.ops.push(op);
        a.konst.insert(c, id);
        return Sym(id);
    }
    if let Some(&id) = a.memo.get(&op) {
        return Sym(id);
    }
    let id = a.ops.len() as u32;
    a.ops.push(op);
    a.memo.insert(op, id);
    Sym(id)
}

fn konst(c: Ea4) -> Sym {
    with_arena(|a| intern(a, GOp::Konst(c)))
}

fn add(x: Sym, y: Sym) -> Sym {
    with_arena(|a| match (konst_of(a, x), konst_of(a, y)) {
        (Some(p), Some(q)) => intern(a, GOp::Konst(p + q)),
        (Some(p), None) if p == Ea4::ZERO => y,
        (None, Some(q)) if q == Ea4::ZERO => x,
        _ => intern(a, GOp::Add(x.0.min(y.0), x.0.max(y.0))),
    })
}

fn sub(x: Sym, y: Sym) -> Sym {
    with_arena(|a| match (konst_of(a, x), konst_of(a, y)) {
        (Some(p), Some(q)) => intern(a, GOp::Konst(p - q)),
        (None, Some(q)) if q == Ea4::ZERO => x,
        _ if x == y => Sym(ID_ZERO),
        _ => intern(a, GOp::Sub(x.0, y.0)),
    })
}

fn mul(x: Sym, y: Sym) -> Sym {
    with_arena(|a| match (konst_of(a, x), konst_of(a, y)) {
        (Some(p), Some(q)) => intern(a, GOp::Konst(p * q)),
        (Some(p), _) if p == Ea4::ZERO => Sym(ID_ZERO),
        (_, Some(q)) if q == Ea4::ZERO => Sym(ID_ZERO),
        (Some(p), None) if p == Ea4::ONE => y,
        (None, Some(q)) if q == Ea4::ONE => x,
        _ => intern(a, GOp::Mul(x.0.min(y.0), x.0.max(y.0))),
    })
}

fn neg(x: Sym) -> Sym {
    with_arena(|a| match konst_of(a, x) {
        Some(p) => intern(a, GOp::Konst(-p)),
        None => intern(a, GOp::Neg(x.0)),
    })
}

impl Default for Sym {
    fn default() -> Self {
        Sym(ID_ZERO)
    }
}
impl Add for Sym {
    type Output = Sym;
    fn add(self, o: Sym) -> Sym {
        add(self, o)
    }
}
impl Sub for Sym {
    type Output = Sym;
    fn sub(self, o: Sym) -> Sym {
        sub(self, o)
    }
}
impl Mul for Sym {
    type Output = Sym;
    fn mul(self, o: Sym) -> Sym {
        mul(self, o)
    }
}
impl Neg for Sym {
    type Output = Sym;
    fn neg(self) -> Sym {
        neg(self)
    }
}
impl AddAssign for Sym {
    fn add_assign(&mut self, o: Sym) {
        *self = add(*self, o);
    }
}
impl SubAssign for Sym {
    fn sub_assign(&mut self, o: Sym) {
        *self = sub(*self, o);
    }
}
impl MulAssign for Sym {
    fn mul_assign(&mut self, o: Sym) {
        *self = mul(*self, o);
    }
}
impl Sum for Sym {
    fn sum<I: Iterator<Item = Sym>>(it: I) -> Sym {
        it.fold(Sym(ID_ZERO), add)
    }
}
impl Product for Sym {
    fn product<I: Iterator<Item = Sym>>(it: I) -> Sym {
        it.fold(Sym(ID_ONE), mul)
    }
}
impl From<Fa4> for Sym {
    fn from(f: Fa4) -> Sym {
        konst(Ea4::from(f))
    }
}
impl Add<Fa4> for Sym {
    type Output = Sym;
    fn add(self, f: Fa4) -> Sym {
        add(self, Sym::from(f))
    }
}
impl Sub<Fa4> for Sym {
    type Output = Sym;
    fn sub(self, f: Fa4) -> Sym {
        sub(self, Sym::from(f))
    }
}
impl Mul<Fa4> for Sym {
    type Output = Sym;
    fn mul(self, f: Fa4) -> Sym {
        mul(self, Sym::from(f))
    }
}
impl AddAssign<Fa4> for Sym {
    fn add_assign(&mut self, f: Fa4) {
        *self = add(*self, Sym::from(f));
    }
}
impl SubAssign<Fa4> for Sym {
    fn sub_assign(&mut self, f: Fa4) {
        *self = sub(*self, Sym::from(f));
    }
}
impl MulAssign<Fa4> for Sym {
    fn mul_assign(&mut self, f: Fa4) {
        *self = mul(*self, Sym::from(f));
    }
}
impl PrimeCharacteristicRing for Sym {
    type PrimeSubfield = Fa4;
    const ZERO: Self = Sym(ID_ZERO);
    const ONE: Self = Sym(ID_ONE);
    const TWO: Self = Sym(ID_TWO);
    const NEG_ONE: Self = Sym(ID_NEG_ONE);
    fn from_prime_subfield(f: Fa4) -> Self {
        Sym::from(f)
    }
}
impl Algebra<Fa4> for Sym {}

/// A gate's residual list as a straight-line program over its inputs (module doc).
#[derive(Clone, Debug)]
pub struct GateProgram {
    pub n_inputs: usize,
    pub ops: Vec<GOp>,
    /// The op whose value is each residual, in the gate's own order.
    pub outputs: Vec<u32>,
    /// The opaque permutation blocks `PermOut` ops name (empty unless traced with [`with_opaque_perms`]).
    pub perm_blocks: Vec<PermBlock>,
}

/// Run `f` with permutation blocks recorded as units ([`opaque_perm`]); restored on every exit.
pub fn with_opaque_perms<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            OPAQUE.with(|c| c.set(self.0));
        }
    }
    let _r = Restore(OPAQUE.with(|c| c.replace(true)));
    f()
}

/// The residuals of an opaque block, natively, from its cells' values.
fn block_residuals(b: &PermBlock, cells: &[Ea4]) -> Vec<Ea4> {
    let oob = crate::air_zerocheck::OobLatch::new();
    let row = crate::air_zerocheck::Row::new(cells, &oob);
    let mut rs = Vec::new();
    match b.seed {
        Some(sd) => crate::pow_pq_air::push_perm_residuals_seeded(sd, &row, 0, &mut rs),
        None => crate::pow_pq_air::push_perm_residuals(&row, 0, &mut rs),
    }
    rs
}

/// Op counts, for a cost statement: `(adds + subs + negs, muls, constants, inputs read)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramCost {
    pub linear: usize,
    pub muls: usize,
    pub konsts: usize,
    pub inputs_read: usize,
    /// Residuals of opaque permutation blocks (each block's are checked as one unit).
    pub perm_outs: usize,
}

impl GateProgram {
    /// Run the program on extension inputs: the residuals, in order.
    #[must_use]
    pub fn eval(&self, inputs: &[Ea4]) -> Option<Vec<Ea4>> {
        if inputs.len() != self.n_inputs {
            return None; // fail-closed: a program read past its inputs has no value
        }
        let mut v: Vec<Ea4> = Vec::with_capacity(self.ops.len());
        let mut done: HashMap<u32, Vec<Ea4>> = HashMap::new();
        for op in &self.ops {
            v.push(match *op {
                GOp::Input(i) => inputs[i as usize],
                GOp::Konst(c) => c,
                GOp::Add(a, b) => v[a as usize] + v[b as usize],
                GOp::Sub(a, b) => v[a as usize] - v[b as usize],
                GOp::Mul(a, b) => v[a as usize] * v[b as usize],
                GOp::Neg(a) => -v[a as usize],
                GOp::PermOut { block, k } => {
                    let blk = self.perm_blocks.get(block as usize)?;
                    let rs = done.entry(block).or_insert_with(|| {
                        let cells: Vec<Ea4> = blk.cells.iter().map(|&c| v[c as usize]).collect();
                        block_residuals(blk, &cells)
                    });
                    *rs.get(k as usize)?
                }
            });
        }
        Some(self.outputs.iter().map(|&o| v[o as usize]).collect())
    }
    /// The γ-batched value every carrier gate's `eval` returns: `Σ_i γ^i · r_i` (ascending powers, the gates' own fold).
    #[must_use]
    pub fn eval_folded(&self, inputs: &[Ea4], gamma: Ea4) -> Option<Ea4> {
        let rs = self.eval(inputs)?;
        let (mut acc, mut pw) = (Ea4::ZERO, Ea4::ONE);
        for r in rs {
            acc += pw * r;
            pw *= gamma;
        }
        Some(acc)
    }
    #[must_use]
    pub fn cost(&self) -> ProgramCost {
        let mut c = ProgramCost::default();
        for op in &self.ops {
            match op {
                GOp::Input(_) => c.inputs_read += 1,
                GOp::Konst(_) => c.konsts += 1,
                GOp::Mul(..) => c.muls += 1,
                GOp::PermOut { .. } => c.perm_outs += 1,
                _ => c.linear += 1,
            }
        }
        c
    }
}

/// Trace `f` over `n_inputs` symbolic inputs: the residuals it returns, as a program (module doc). Re-entrant calls are
/// refused (a trace inside a trace would share one DAG), and the arena is dropped on every exit.
#[must_use]
pub fn trace(n_inputs: usize, f: impl FnOnce(&[Sym]) -> Vec<Sym>) -> Option<GateProgram> {
    let fresh = ARENA.with(|a| {
        let mut a = a.borrow_mut();
        if a.is_some() {
            return false;
        }
        let mut ar = Arena { ops: Vec::new(), memo: HashMap::new(), konst: HashMap::new(), blocks: Vec::new() };
        for c in [Ea4::ZERO, Ea4::ONE, Ea4::TWO, Ea4::NEG_ONE] {
            intern(&mut ar, GOp::Konst(c));
        }
        *a = Some(ar);
        true
    });
    if !fresh {
        return None;
    }
    struct Drop0;
    impl Drop for Drop0 {
        fn drop(&mut self) {
            ARENA.with(|a| *a.borrow_mut() = None);
        }
    }
    let _guard = Drop0;
    let inputs: Vec<Sym> = (0..n_inputs as u32).map(|i| with_arena(|a| intern(a, GOp::Input(i)))).collect();
    let outs = f(&inputs);
    let ops = with_arena(|a| core::mem::take(&mut a.ops));
    let blocks = with_arena(|a| core::mem::take(&mut a.blocks));
    // Dead code: keep only what an output reads, in the original (topological) order.
    let mut live = vec![false; ops.len()];
    let mut stack: Vec<u32> = outs.iter().map(|s| s.0).collect();
    while let Some(i) = stack.pop() {
        if live[i as usize] {
            continue;
        }
        live[i as usize] = true;
        match ops[i as usize] {
            GOp::Add(a, b) | GOp::Sub(a, b) | GOp::Mul(a, b) => {
                stack.push(a);
                stack.push(b);
            }
            GOp::Neg(a) => stack.push(a),
            GOp::PermOut { block, .. } => stack.extend(blocks[block as usize].cells.iter().copied()),
            _ => {}
        }
    }
    // A block is kept iff an output reads one of its residuals; kept blocks are renumbered in order.
    let mut bmap = vec![u32::MAX; blocks.len()];
    let mut nb = 0u32;
    for (i, op) in ops.iter().enumerate() {
        if let (true, GOp::PermOut { block, .. }) = (live[i], op) {
            if bmap[*block as usize] == u32::MAX {
                bmap[*block as usize] = nb;
                nb += 1;
            }
        }
    }
    let mut remap = vec![u32::MAX; ops.len()];
    let mut kept = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        if !live[i] {
            continue;
        }
        let r = |x: u32| remap[x as usize];
        let op2 = match *op {
            GOp::Add(a, b) => GOp::Add(r(a), r(b)),
            GOp::Sub(a, b) => GOp::Sub(r(a), r(b)),
            GOp::Mul(a, b) => GOp::Mul(r(a), r(b)),
            GOp::Neg(a) => GOp::Neg(r(a)),
            GOp::PermOut { block, k } => GOp::PermOut { block: bmap[block as usize], k },
            other => other,
        };
        remap[i] = kept.len() as u32;
        kept.push(op2);
    }
    let outputs = outs.iter().map(|s| remap[s.0 as usize]).collect();
    let mut perm_blocks: Vec<Option<PermBlock>> = vec![None; nb as usize];
    for (b, blk) in blocks.into_iter().enumerate() {
        if bmap[b] != u32::MAX {
            perm_blocks[bmap[b] as usize] = Some(PermBlock { cells: blk.cells.iter().map(|&c| remap[c as usize]).collect(), seed: blk.seed });
        }
    }
    let perm_blocks = perm_blocks.into_iter().collect::<Option<Vec<_>>>()?;
    Some(GateProgram { n_inputs, ops: kept, outputs, perm_blocks })
}

/// Where each kind of input sits in a carrier gate program's input vector: the opened row, then the next-row values of
/// the shifted columns (a chained carrier's), then the zerocheck point `x`, then the gate's public values in field order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateInputs {
    pub width: usize,
    /// The columns whose next-row value the gate reads, in order; input `width + k` is column `shifted[k]`'s.
    pub shifted: Vec<usize>,
    pub nvars: usize,
    pub publics: usize,
}

impl GateInputs {
    #[must_use]
    pub fn total(&self) -> usize {
        self.width + self.shifted.len() + self.nvars + self.publics
    }
    #[must_use]
    pub fn x_at(&self) -> usize {
        self.width + self.shifted.len()
    }
    #[must_use]
    pub fn publics_at(&self) -> usize {
        self.x_at() + self.nvars
    }
    /// Assemble the input vector the program reads from a verifier's values.
    #[must_use]
    pub fn assemble(&self, opened: &[Ea4], next: &[Ea4], x: &[Ea4], publics: &[Ea4]) -> Option<Vec<Ea4>> {
        if opened.len() != self.width || next.len() != self.shifted.len() || x.len() != self.nvars || publics.len() != self.publics {
            return None;
        }
        let mut v = Vec::with_capacity(self.total());
        v.extend_from_slice(opened);
        v.extend_from_slice(next);
        v.extend_from_slice(x);
        v.extend_from_slice(publics);
        Some(v)
    }
}

/// Run a gate body over traced inputs laid as [`GateInputs`]: `body(row, at, x, publics)`.
fn trace_gate(
    lay: &GateInputs,
    body: impl FnOnce(&crate::air_zerocheck::Row<'_, Sym>, &dyn Fn(usize, &[Sym]) -> Sym, &[Sym], &[Sym]) -> Vec<Sym>,
) -> Option<GateProgram> {
    let oob = crate::air_zerocheck::OobLatch::new();
    let (w, sh) = (lay.width, lay.shifted.clone());
    let p = trace(lay.total(), |ins| {
        let row = crate::air_zerocheck::Row::new(&ins[..w], &oob);
        let next: Vec<Sym> = ins[w..w + sh.len()].to_vec();
        let at = |c: usize, _p: &[Sym]| -> Sym {
            // The verifier's `at` answers a shifted column's next-row opening; any other read is a gate bug.
            match sh.iter().position(|&s| s == c) {
                Some(k) => next[k],
                None => {
                    oob.record(c, 0);
                    Sym::ZERO
                }
            }
        };
        let x = &ins[lay.x_at()..lay.publics_at()];
        let publics = &ins[lay.publics_at()..];
        body(&row, &at, x, publics)
    })?;
    if oob.hit() {
        return None; // fail-closed: a gate that read past its row (or an unshifted next row) has no program
    }
    Some(p)
}

fn digest_of(p: &[Sym], k: usize) -> [Sym; crate::poseidon2_compress::DIGEST_LANES] {
    core::array::from_fn(|c| p[k * crate::poseidon2_compress::DIGEST_LANES + c])
}

/// The note-spend class: `SpendValidityGate` with `g`'s option SHAPE (which of bond, fee, claim tag and vault clock are
/// present), its public values as inputs in field order: out0_cm, out1_cm, nullifier, leaf_commit, then bond (4), fee
/// (4), tag1 (8), clock (1) for each one present.
#[must_use]
pub fn spend_validity_program(g: &crate::whir_rec_block::SpendValidityGate, width: usize, nvars: usize) -> Option<(GateProgram, GateInputs)> {
    use crate::poseidon2_compress::DIGEST_LANES as D;
    let sc = crate::whir_rec_block::SC_LIMBS;
    let publics = 4 * D + g.bond_amount.map_or(0, |_| sc) + g.fee_amount.map_or(0, |_| sc) + g.tag1.map_or(0, |_| D) + g.vault.map_or(0, |_| 1);
    let lay = GateInputs { width, shifted: Vec::new(), nvars, publics };
    let shape = (g.bond_amount.is_some(), g.fee_amount.is_some(), g.tag1.is_some(), g.vault.is_some());
    let prog = trace_gate(&lay, |row, _at, _x, p| {
        let mut k = 4 * D;
        let mut take = |n: usize| {
            let s = &p[k..k + n];
            k += n;
            s.to_vec()
        };
        let bond = shape.0.then(|| take(sc));
        let fee = shape.1.then(|| take(sc));
        let tag1 = shape.2.then(|| take(D));
        let vault = shape.3.then(|| take(1)[0]);
        let sg = crate::whir_rec_block::SpendValidityGate::<Sym> {
            gamma: Sym::ZERO,
            out0_cm: digest_of(p, 0),
            out1_cm: digest_of(p, 1),
            nullifier: digest_of(p, 2),
            leaf_commit: digest_of(p, 3),
            bond_amount: bond.map(|v| core::array::from_fn(|i| v[i])),
            fee_amount: fee.map(|v| core::array::from_fn(|i| v[i])),
            tag1: tag1.map(|v| core::array::from_fn(|i| v[i])),
            vault,
        };
        sg.residuals(row)
    })?;
    Some((prog, lay))
}

/// [`spend_validity_program`]'s public inputs, read off a concrete gate in the same order.
#[must_use]
pub fn spend_validity_publics(g: &crate::whir_rec_block::SpendValidityGate) -> Vec<Ea4> {
    let mut v: Vec<Ea4> = Vec::new();
    for d in [&g.out0_cm, &g.out1_cm, &g.nullifier, &g.leaf_commit] {
        v.extend_from_slice(d);
    }
    if let Some(b) = &g.bond_amount {
        v.extend_from_slice(b);
    }
    if let Some(f) = &g.fee_amount {
        v.extend_from_slice(f);
    }
    if let Some(t) = &g.tag1 {
        v.extend_from_slice(t);
    }
    if let Some(c) = g.vault {
        v.push(c);
    }
    v
}

/// The member-leg class: `MemberPathGate`, publics leaf_commit, binder, root.
#[must_use]
pub fn member_path_program(width: usize, nvars: usize) -> Option<(GateProgram, GateInputs)> {
    use crate::poseidon2_compress::DIGEST_LANES as D;
    let (lo, run) = crate::member_path_gate::member_shifted_run();
    let lay = GateInputs { width, shifted: (lo..lo + run).collect(), nvars, publics: 3 * D };
    let prog = trace_gate(&lay, |row, at, x, p| {
        let g = crate::member_path_gate::MemberPathGate::<Sym> {
            gamma: Sym::ZERO,
            leaf_commit: digest_of(p, 0),
            binder: digest_of(p, 1),
            root: digest_of(p, 2),
        };
        g.build(row, at, x)
    })?;
    Some((prog, lay))
}

#[must_use]
pub fn member_path_publics(g: &crate::member_path_gate::MemberPathGate) -> Vec<Ea4> {
    [g.leaf_commit, g.binder, g.root].concat()
}

/// The cover-arm class: `CoverOrSpendGate`, public the tag digest.
#[must_use]
pub fn cover_or_spend_program(width: usize, nvars: usize) -> Option<(GateProgram, GateInputs)> {
    use crate::poseidon2_compress::DIGEST_LANES as D;
    let shifted = crate::nf_sparse_air::cover_shifted_cols();
    let lay = GateInputs { width, shifted, nvars, publics: D };
    let prog = trace_gate(&lay, |row, at, x, p| {
        let g = crate::nf_sparse_air::CoverOrSpendGate::<Sym> { gamma: Sym::ZERO, tag_digest: digest_of(p, 0) };
        g.build_residuals(row, at, x)
    })?;
    Some((prog, lay))
}

#[must_use]
pub fn cover_or_spend_publics(g: &crate::nf_sparse_air::CoverOrSpendGate) -> Vec<Ea4> {
    g.tag_digest.to_vec()
}

/// A payment carrier's statement as its door states it: the public bind, the gate's public values (in the program's
/// input order), the gate, and the door's LAID shape `(variables, columns)` (blinded doors double the laid rows).
pub struct CarrierStatement<G> {
    pub bind: Vec<Fa4>,
    pub publics: Vec<Ea4>,
    pub gate: G,
    pub laid_shape: (usize, usize),
}

/// The note-spend door's statement, line for line `whir_rec_block::verify_note_spend_bytes` (its two refusals included,
/// so a statement that door refuses has none here either).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn note_spend_statement(
    out0_cm: crate::poseidon2_compress::Digest,
    out1_cm: crate::poseidon2_compress::Digest,
    nullifier: crate::poseidon2_compress::Digest,
    leaf_commit: crate::poseidon2_compress::Digest,
    clue_digest: crate::poseidon2_compress::Digest,
    tag1: crate::poseidon2_compress::Digest,
    fee: u64,
    clock_h: u64,
) -> Option<CarrierStatement<crate::whir_rec_block::SpendValidityGate>> {
    use crate::poseidon2_compress::DIGEST_LANES as D;
    if leaf_commit == crate::poseidon2_compress::ZERO_DIGEST || tag1 == crate::poseidon2_compress::ZERO_DIGEST {
        return None;
    }
    let f = |d: &crate::poseidon2_compress::Digest| -> [Fa4; D] { crate::whir_rec_block::to_f(d) };
    let e = |d: &[Fa4; D]| -> [Ea4; D] { core::array::from_fn(|i| d[i].into()) };
    let (o0, o1, nfv, lc, t1) = (f(&out0_cm), f(&out1_cm), f(&nullifier), f(&leaf_commit), f(&tag1));
    let gate = crate::whir_rec_block::SpendValidityGate {
        leaf_commit: e(&lc),
        gamma: Ea4::ZERO,
        out0_cm: e(&o0),
        out1_cm: e(&o1),
        nullifier: e(&nfv),
        bond_amount: None,
        fee_amount: Some(crate::whir_rec_block::fee_limbs(fee)),
        tag1: Some(e(&t1)),
        vault: Some(crate::whir_rec_block::clock_const(clock_h)),
    };
    let bind = crate::whir_rec_block::note_spend_public_bind(&[o0, o1], &nfv, &lc, &f(&clue_digest), &t1, clock_h);
    Some(CarrierStatement {
        publics: spend_validity_publics(&gate),
        gate,
        bind,
        laid_shape: (crate::whir_rec_block::LIGHT_CARRIER_ROWS.trailing_zeros() as usize, crate::whir_rec_block::note_spend_row_width()),
    })
}

/// The member leg's statement, line for line `member_path_gate::verify_member_path_carrier`.
#[must_use]
pub fn member_statement(t: &crate::member_path_gate::MemberTuple) -> CarrierStatement<crate::member_path_gate::MemberPathGate> {
    let gate = crate::member_path_gate::member_path_gate(t)(Ea4::ZERO);
    CarrierStatement {
        publics: member_path_publics(&gate),
        gate,
        bind: t.bind(),
        laid_shape: (crate::member_path_gate::MEMBER_PATH_DEPTH.trailing_zeros() as usize, crate::member_path_gate::MEMBER_PATH_COLS),
    }
}

/// The cover arm's statement, line for line `nf_sparse_air::verify_spend_or_decoy_bytes` (its refusals included).
#[must_use]
pub fn cover_statement(tags: &[crate::poseidon2_compress::Digest]) -> Option<CarrierStatement<crate::nf_sparse_air::CoverOrSpendGate>> {
    if tags.is_empty() || !tags.len().is_power_of_two() {
        return None;
    }
    let gate = crate::nf_sparse_air::CoverOrSpendGate { gamma: Ea4::ZERO, tag_digest: crate::nf_sparse_air::cover_tag_digest_ea(tags) };
    Some(CarrierStatement {
        publics: cover_or_spend_publics(&gate),
        gate,
        bind: crate::nf_sparse_air::cover_tag_statement_bind(tags),
        laid_shape: (tags.len().trailing_zeros() as usize, crate::nf_sparse_air::CR_COLS),
    })
}

/// ⭐ V2 (b) PIECE 3 — the tree ledger's STEP table (`tree_ledger::TreeLedgerAir::Step`: the slot-ledger laws, the clock law,
/// the zero digests) as a program, so a circuit evaluates it at the ledger proof's opened step row. Row-local (no next row);
/// publics: the block's seed commitment (8 lanes), then its clock constant.
#[must_use]
pub fn tree_ledger_step_program(nvars: usize) -> Option<(GateProgram, GateInputs)> {
    use crate::poseidon2_compress::DIGEST_LANES as D;
    let lay = GateInputs { width: crate::tree_ledger::TL_STEP_COLS, shifted: Vec::new(), nvars, publics: D + 1 };
    let prog = trace_gate(&lay, |row, _at, _x, p| {
        let sc: [Sym; D] = core::array::from_fn(|c| p[c]);
        crate::tree_ledger::TreeLedgerAir::step_residuals(row, &sc, p[D])
    })?;
    Some((prog, lay))
}

/// ⭐ V2 (b) PIECE 3 — a sponge-chain table's gate (`sponge_chain_air::SpongeChainConstraint`: the Poseidon2 tape, the
/// chaining laws, the last-row challenge equality) as a program; the tree ledger's CHAIN table is one. Its next-row reads
/// are the gate's own declared set (`shifted_cols`); its one public input is the expected challenge fold. The gate folds by
/// Horner (the FIRST residual carries the HIGHEST power of γ), the programs fold ascending ([`GateProgram::eval_folded`]),
/// so the program's outputs are the gate's residual list REVERSED: the two folds are then the same polynomial in γ.
#[must_use]
pub fn sponge_chain_program(c: &crate::sponge_chain_air::SpongeChainConstraint, width: usize, nvars: usize) -> Option<(GateProgram, GateInputs)> {
    use crate::air_zerocheck::AirConstraint;
    let shifted = c.shifted_cols()?;
    let lay = GateInputs { width, shifted, nvars, publics: 1 };
    let prog = trace_gate(&lay, |row, at, x, p| {
        let at1 = |col: usize| at(col, &[]);
        let mut r = c.residuals_in_order(row, &at1, x, p[0]);
        r.reverse();
        r
    })?;
    Some((prog, lay))
}

/// [`tree_ledger_step_program`]'s public inputs, in its order.
#[must_use]
pub fn tree_ledger_step_publics(seed_commit: &[Ea4; crate::poseidon2_compress::DIGEST_LANES], block_clock: Ea4) -> Vec<Ea4> {
    let mut v = seed_commit.to_vec();
    v.push(block_clock);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_zerocheck::{AirConstraint, Row, RowGuard};
    use p3_field::PrimeField64;
    use rand::SeedableRng;

    fn rand_ea(rng: &mut rand::rngs::SmallRng) -> Ea4 {
        let l: [Fa4; 4] = core::array::from_fn(|_| Fa4::from_u64(rand::RngExt::random::<u64>(rng) % Fa4::ORDER_U64));
        <Ea4 as p3_field::BasedVectorSpace<Fa4>>::from_basis_coefficients_slice(&l).expect("four limbs")
    }

    /// Compare a concrete gate's residuals (and its folded `eval`) with its traced program at random extension rows,
    /// then tamper one op of the program and demand a disagreement. Returns the program's cost.
    fn hold<C: AirConstraint>(name: &str, gate: &C, prog: &GateProgram, lay: &GateInputs, publics: &[Ea4], gamma: Ea4) {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0xA66_7_1);
        for trial in 0..3 {
            let opened: Vec<Ea4> = (0..lay.width).map(|_| rand_ea(&mut rng)).collect();
            let next: Vec<Ea4> = (0..lay.shifted.len()).map(|_| rand_ea(&mut rng)).collect();
            let x: Vec<Ea4> = (0..lay.nvars).map(|_| rand_ea(&mut rng)).collect();
            let g = RowGuard::new();
            let row: Row<'_> = g.row(&opened);
            let sh = lay.shifted.clone();
            let nx = next.clone();
            let at = move |c: usize, _p: &[Ea4]| sh.iter().position(|&s| s == c).map_or(Ea4::ZERO, |k| nx[k]);
            let want = gate.residuals(&row, &at, &x);
            let ins = lay.assemble(&opened, &next, &x, publics).expect("the layout");
            let got = prog.eval(&ins).expect("the program runs");
            assert_eq!(got.len(), want.len(), "{name}: the program has another residual count");
            for (i, (a, b)) in got.iter().zip(&want).enumerate() {
                assert_eq!(a, b, "{name} trial {trial}: residual {i} differs");
            }
            assert_eq!(prog.eval_folded(&ins, gamma), Some(gate.eval(&row, &at, &x)), "{name}: the folded value differs");
            assert!(!row.out_of_range(), "{name}: the gate read past its row");
        }
        // A tampered program must disagree: flip the first Mul to an Add.
        let mut bad = prog.clone();
        let k = bad.ops.iter().position(|o| matches!(o, GOp::Mul(..))).expect("a gate multiplies");
        if let GOp::Mul(a, b) = bad.ops[k] {
            bad.ops[k] = GOp::Add(a, b);
        }
        let opened: Vec<Ea4> = (0..lay.width).map(|_| rand_ea(&mut rng)).collect();
        let next: Vec<Ea4> = (0..lay.shifted.len()).map(|_| rand_ea(&mut rng)).collect();
        let x: Vec<Ea4> = (0..lay.nvars).map(|_| rand_ea(&mut rng)).collect();
        let ins = lay.assemble(&opened, &next, &x, publics).expect("the layout");
        assert_ne!(bad.eval(&ins), prog.eval(&ins), "{name}: a tampered program must disagree");
        let c = prog.cost();
        println!(
            "[agg-t1] {name}: width {} shifted {} nvars {} publics {} → {} residuals, {} ops ({} mul, {} linear, {} konst, {} inputs read, {} perm blocks / {} residuals opaque)",
            lay.width,
            lay.shifted.len(),
            lay.nvars,
            lay.publics,
            prog.outputs.len(),
            prog.ops.len(),
            c.muls,
            c.linear,
            c.konsts,
            c.inputs_read,
            prog.perm_blocks.len(),
            c.perm_outs
        );
    }

    #[test]
    fn agg_t1_every_carrier_gate_is_its_program() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(7);
        let gamma = rand_ea(&mut rng);
        let d = |rng: &mut rand::rngs::SmallRng| -> [Ea4; crate::poseidon2_compress::DIGEST_LANES] { core::array::from_fn(|_| rand_ea(rng)) };
        // 1. the note spend, in the shape `verify_note_spend_bytes` builds (fee, claim tag, vault clock; no bond)
        let sg = crate::whir_rec_block::SpendValidityGate {
            gamma,
            out0_cm: d(&mut rng),
            out1_cm: d(&mut rng),
            nullifier: d(&mut rng),
            leaf_commit: d(&mut rng),
            bond_amount: None,
            fee_amount: Some(core::array::from_fn(|_| rand_ea(&mut rng))),
            tag1: Some(d(&mut rng)),
            vault: Some(rand_ea(&mut rng)),
        };
        let w = crate::whir_rec_block::note_spend_row_width();
        let nv = crate::whir_rec_block::LIGHT_CARRIER_ROWS.trailing_zeros() as usize;
        let (p, lay) = spend_validity_program(&sg, w, nv).expect("the spend gate traces");
        hold("note-spend", &sg, &p, &lay, &spend_validity_publics(&sg), gamma);
        let (p, lay) = with_opaque_perms(|| spend_validity_program(&sg, w, nv)).expect("the spend gate traces opaque");
        assert!(!p.perm_blocks.is_empty(), "the spend gate's permutation blocks are opaque");
        hold("note-spend/opaque", &sg, &p, &lay, &spend_validity_publics(&sg), gamma);
        // and the bond shape (no claim tag, no vault), so the option walk is held both ways
        let sb = crate::whir_rec_block::SpendValidityGate { bond_amount: Some(core::array::from_fn(|_| rand_ea(&mut rng))), tag1: None, vault: None, ..sg.clone() };
        let (p, lay) = spend_validity_program(&sb, w, nv).expect("the bond shape traces");
        hold("bond-spend", &sb, &p, &lay, &spend_validity_publics(&sb), gamma);
        // 2. the member leg
        let mg = crate::member_path_gate::MemberPathGate { gamma, leaf_commit: d(&mut rng), binder: d(&mut rng), root: d(&mut rng) };
        let (mw, mn) = crate::member_path_gate::member_path_shape();
        let (p, lay) = member_path_program(mw, mn).expect("the member gate traces");
        hold("member-leg", &mg, &p, &lay, &member_path_publics(&mg), gamma);
        let (p, lay) = with_opaque_perms(|| member_path_program(mw, mn)).expect("the member gate traces opaque");
        hold("member-leg/opaque", &mg, &p, &lay, &member_path_publics(&mg), gamma);
        // 3. the cover arm
        let cg = crate::nf_sparse_air::CoverOrSpendGate { gamma, tag_digest: d(&mut rng) };
        let (cw, cn) = crate::nf_sparse_air::cover_or_spend_shape(32);
        let (p, lay) = cover_or_spend_program(cw, cn).expect("the cover gate traces");
        hold("cover-arm", &cg, &p, &lay, &cover_or_spend_publics(&cg), gamma);
        let (p, lay) = with_opaque_perms(|| cover_or_spend_program(cw, cn)).expect("the cover gate traces opaque");
        hold("cover-arm/opaque", &cg, &p, &lay, &cover_or_spend_publics(&cg), gamma);
        // 4. V2 (b): the tree ledger's step table, the gate a block's ledger proof opens
        let (sc, bc) = (d(&mut rng), rand_ea(&mut rng));
        let tg = crate::tree_ledger::TreeLedgerAir::Step { seed_commit: sc, block_clock: bc, gamma };
        let nv = crate::settlement_delta::LEDGER_ROWS.trailing_zeros() as usize;
        let (p, lay) = tree_ledger_step_program(nv).expect("the tree ledger's step gate traces");
        hold("tree-ledger-step", &tg, &p, &lay, &tree_ledger_step_publics(&sc, bc), gamma);
        let (p, lay) = with_opaque_perms(|| tree_ledger_step_program(nv)).expect("the step gate traces opaque");
        hold("tree-ledger-step/opaque", &tg, &p, &lay, &tree_ledger_step_publics(&sc, bc), gamma);
        println!("[v2-ledger] tree ledger step gate: {:?}; opaque: {} permutation block(s)", p.cost(), p.perm_blocks.len());
        // 5. V2 (b): the tree ledger's chain table (a sponge chain under the committed seed, expected fold zero). Its gate folds
        // by Horner, so the program is held by its FOLD (and a moved next-row value and a tampered op must disagree).
        let cc = crate::sponge_chain_air::make_constraint_with_seed(crate::committed_air::COMMITTED_AIR_SEED, Fa4::ZERO)(gamma);
        let cw = crate::sponge_chain_air::ROW_COLS;
        let (p, lay) = sponge_chain_program(&cc, cw, 6).expect("the chain gate traces");
        let exp = [Ea4::ZERO];
        for trial in 0..3 {
            let opened: Vec<Ea4> = (0..cw).map(|_| rand_ea(&mut rng)).collect();
            let next: Vec<Ea4> = (0..lay.shifted.len()).map(|_| rand_ea(&mut rng)).collect();
            let x: Vec<Ea4> = (0..6).map(|_| rand_ea(&mut rng)).collect();
            let g = RowGuard::new();
            let row: Row<'_> = g.row(&opened);
            let (sh, nx) = (lay.shifted.clone(), next.clone());
            let at = move |c: usize, _p: &[Ea4]| sh.iter().position(|&s| s == c).map_or(Ea4::ZERO, |k| nx[k]);
            let ins = lay.assemble(&opened, &next, &x, &exp).expect("the layout");
            assert_eq!(p.eval_folded(&ins, gamma), Some(cc.eval(&row, &at, &x)), "chain trial {trial}: the program's fold is not the gate's");
            let mut moved = next.clone();
            if let Some(v) = moved.first_mut() {
                *v += Ea4::ONE;
                let ins2 = lay.assemble(&opened, &moved, &x, &exp).expect("the layout");
                assert_ne!(p.eval_folded(&ins2, gamma), Some(cc.eval(&row, &at, &x)), "chain trial {trial}: a moved next-row value changed nothing");
            }
        }
        println!("[v2-ledger] tree ledger chain gate ({} next-row reads): {:?}", lay.shifted.len(), p.cost());
        let _ = Fa4::from_u64(0).as_canonical_u64();
    }
}

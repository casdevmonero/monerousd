// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! STEP 4 — AN INNER GATE EVALUATED IN CIRCUIT (spec §12): `C_γ(opened, next, x, publics) = Σ γ^i · r_i`.
//!
//! An inner proof's zerocheck closes with `claim_last == eq(z, r) · C_γ(opened)`; a circuit verifying it must compute
//! the right side from the opened row its transcript absorbed. A gate's residuals are of two kinds (`gate_trace`,
//! traced with opaque permutation blocks):
//!
//! * PERMUTATION BLOCKS (most of every carrier: the note spend's 2,561 residuals are ~15 blocks of 148) — the chip
//!   evaluates each round while the inner transcript absorbs the block's cells (`decorate`), reading them from the
//!   window, so they cost no extra row. A block's start power `γ^{o_b}` is set from binary powers before its `Init`
//!   (the residual order is the gate's, not the column order).
//! * EVERYTHING ELSE (welds, conservation, bits) — a short ALU program run in PASS 2 over READS of the inputs it needs.
//!   Reads are checked against the absorbed values by logUp: the TABLE terms ride the absorption rows (one per input
//!   value, multiplicity = how often pass 2 reads it); the READ terms ride the pass-2 rows (multiplicity −1). The
//!   challenges ρ, β are drawn from the circuit's own sponge after PASS 1 hashed every read value, and pass 2 hashes the
//!   same values again and must land on the same sponge state — so the reads are fixed before ρ, β exist, and the
//!   values pass 2 computes with ARE the hashed ones.
//!
//! The gate's public values are CONSTANTS of the program (a leaf's program is a function of its statement, which the
//! root's verifier holds; `vm::program_claim_holds` rebuilds it), so they need no read.
//!
//! REGISTER CONTRACT: the caller keeps `X[0..4]` across these calls; pass 2 uses `X[4..20]`; the evaluator's own
//! registers are `X[20..48]` (isa doc).

use std::collections::HashMap;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use usdm_decider::gate_trace::{GOp, GateInputs, GateProgram};
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::isa::*;

/// A program under construction and its stream.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    pub prog: Vec<Instr>,
    pub stream: Vec<[Fa4; ND]>,
}

impl Builder {
    pub fn push(&mut self, i: Instr, w: [Fa4; ND]) -> usize {
        self.prog.push(i);
        self.stream.push(w);
        self.prog.len() - 1
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.prog.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prog.is_empty()
    }
}

fn lanes(e: Ea4) -> [Fa4; 4] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

fn alu(a: SrcA, b: SrcB, c: Option<SrcC>, wr: Option<u8>, zero: bool, kc: Ea4) -> Alu {
    Alu { a, b, c, wr, zero, kc }
}

/// One permutation block of the gate, in column order.
#[derive(Clone, Debug)]
pub struct BlockPlan {
    /// First column of the block in the opened row.
    pub base: usize,
    /// The γ power its first residual takes in the gate's fold.
    pub offset: usize,
    pub seed: Option<u64>,
}

/// One pass-2 step.
#[derive(Clone, Debug)]
enum Step {
    /// Read input `idx` into `X[reg]`.
    Read { idx: u32, reg: u8 },
    Op(Alu),
}

/// The compiled evaluation of one inner gate (module doc).
#[derive(Clone, Debug)]
pub struct GateEval {
    pub lay: GateInputs,
    pub blinded: bool,
    pub blocks: Vec<BlockPlan>,
    /// Input indices pass 1 and pass 2 read, in order.
    pub reads: Vec<u32>,
    /// How often pass 2 reads each input (the table multiplicity).
    pub mult: HashMap<u32, u32>,
    steps: Vec<Step>,
    /// The read groups both passes absorb, one duplexing each: indices into `reads` (one or two).
    groups: Vec<Vec<usize>>,
    /// The perm-block constants per block (production or seeded).
    rc: Vec<&'static p3_poseidon2_air::RoundConstants<Fa4, WIDTH, 4, 20>>,
}

const R_SUM: u8 = 19;
const R_P: u8 = 18;
const R_LO: u8 = 4;
const R_HI: u8 = 18;

/// The registers holding γ^(16·2^i): `γ¹⁶` then `γ^(32·2^i)`.
fn bin_reg(i: usize) -> Option<u8> {
    if i == 0 {
        Some(X_G16 as u8)
    } else if i - 1 < NGBIN {
        Some((X_GBIN + i - 1) as u8)
    } else {
        None
    }
}

/// `dst = src · γ^e` as a chain of single products (`dst` may equal `src`): γ^(e mod 16) from Γ, then the binary
/// powers of γ¹⁶. Returns the ALU ops, one a row (each reads the previous).
fn times_gamma_pow(dst: u8, src: Option<u8>, e: usize) -> Option<Vec<Alu>> {
    let mut ops = Vec::new();
    let lo = e % 16;
    let mut hi = e / 16;
    let first_src = match src {
        Some(s) => SrcA::X(s),
        None => SrcA::One,
    };
    ops.push(alu(first_src, SrcB::X((X_GAMMA_POW + lo) as u8), None, Some(dst), false, Ea4::ZERO));
    let mut i = 0;
    while hi > 0 {
        if hi & 1 == 1 {
            ops.push(alu(SrcA::X(dst), SrcB::X(bin_reg(i)?), None, Some(dst), false, Ea4::ZERO));
        }
        hi >>= 1;
        i += 1;
    }
    Some(ops)
}

struct Compiler<'a> {
    g: &'a GateProgram,
    free: Vec<u8>,
    /// How many more consumers each live register's value has (a shared subexpression is freed after its LAST use).
    refs: HashMap<u8, u32>,
    steps: Vec<Step>,
    reads: Vec<u32>,
}

/// A value during pass-2 compilation: in a register, or a constant.
#[derive(Clone, Copy, Debug)]
enum Val {
    Reg(u8),
    K(Ea4),
}

impl Compiler<'_> {
    fn alloc(&mut self, uses: u32) -> Option<u8> {
        let r = self.free.pop()?;
        self.refs.insert(r, uses.max(1));
        Some(r)
    }
    /// One consumer is done with `v`.
    fn release(&mut self, v: Val) {
        if let Val::Reg(r) = v {
            if let Some(n) = self.refs.get_mut(&r) {
                *n -= 1;
                if *n == 0 {
                    self.refs.remove(&r);
                    self.free.push(r);
                }
            }
        }
    }
    /// Evaluate op `id` into a value; `total[id]` is how many consumers it has within this residual, and `memo` holds
    /// every node already computed (its register stays live until its last consumer releases it).
    fn eval(&mut self, id: u32, memo: &mut HashMap<u32, Val>, total: &HashMap<u32, u32>) -> Option<Val> {
        if let Some(&v) = memo.get(&id) {
            return Some(v);
        }
        let uses = total.get(&id).copied().unwrap_or(1);
        let v = match self.g.ops[id as usize] {
            GOp::Konst(c) => Val::K(c),
            GOp::Input(i) => {
                let r = self.alloc(uses)?;
                self.steps.push(Step::Read { idx: i, reg: r });
                self.reads.push(i);
                Val::Reg(r)
            }
            GOp::Neg(a) => {
                let va = self.eval(a, memo, total)?;
                match va {
                    Val::K(c) => Val::K(-c),
                    Val::Reg(ra) => {
                        let r = self.alloc(uses)?;
                        self.steps.push(Step::Op(alu(SrcA::X(ra), SrcB::Kc, None, Some(r), false, -Ea4::ONE)));
                        self.release(va);
                        Val::Reg(r)
                    }
                }
            }
            GOp::Add(a, b) | GOp::Sub(a, b) | GOp::Mul(a, b) => {
                let op = self.g.ops[id as usize];
                let va = self.eval(a, memo, total)?;
                let vb = self.eval(b, memo, total)?;
                match (op, va, vb) {
                    (GOp::Add(..), Val::K(x), Val::K(y)) => Val::K(x + y),
                    (GOp::Sub(..), Val::K(x), Val::K(y)) => Val::K(x - y),
                    (GOp::Mul(..), Val::K(x), Val::K(y)) => Val::K(x * y),
                    _ => {
                        let r = self.alloc(uses)?;
                        let step = match (op, va, vb) {
                            (GOp::Add(..), Val::Reg(x), Val::Reg(y)) => alu(SrcA::One, SrcB::X(x), Some(SrcC::X(y)), Some(r), false, Ea4::ZERO),
                            (GOp::Add(..), Val::Reg(x), Val::K(c)) | (GOp::Add(..), Val::K(c), Val::Reg(x)) => alu(SrcA::One, SrcB::X(x), Some(SrcC::Kc), Some(r), false, c),
                            (GOp::Sub(..), Val::Reg(x), Val::Reg(y)) => alu(SrcA::X(y), SrcB::Kc, Some(SrcC::X(x)), Some(r), false, -Ea4::ONE),
                            (GOp::Sub(..), Val::Reg(x), Val::K(c)) => alu(SrcA::One, SrcB::X(x), Some(SrcC::Kc), Some(r), false, -c),
                            (GOp::Sub(..), Val::K(c), Val::Reg(y)) => {
                                // c − y = (−1)·y + c: one product, then one sum (a unit holds one constant)
                                self.steps.push(Step::Op(alu(SrcA::X(y), SrcB::Kc, None, Some(r), false, -Ea4::ONE)));
                                alu(SrcA::One, SrcB::X(r), Some(SrcC::Kc), Some(r), false, c)
                            }
                            (GOp::Mul(..), Val::Reg(x), Val::Reg(y)) => alu(SrcA::X(x), SrcB::X(y), None, Some(r), false, Ea4::ZERO),
                            (GOp::Mul(..), Val::Reg(x), Val::K(c)) | (GOp::Mul(..), Val::K(c), Val::Reg(x)) => alu(SrcA::X(x), SrcB::Kc, None, Some(r), false, c),
                            _ => return None,
                        };
                        self.steps.push(Step::Op(step));
                        self.release(va);
                        self.release(vb);
                        Val::Reg(r)
                    }
                }
            }
            GOp::PermOut { .. } => return None, // a block residual inside another residual's expression: not this shape
        };
        memo.insert(id, v);
        Some(v)
    }
}

impl GateEval {
    /// Compile `g` (traced with opaque permutation blocks, `gate_trace::with_opaque_perms`) laid as `lay`. `blinded`:
    /// the door wraps the gate in `Blinded` (`C = (1 − x₀)·C_inner`). Refuses (`Err`) any shape it cannot evaluate
    /// soundly: a block whose cells are not one contiguous run of the opened row, a block whose residuals are not one
    /// contiguous run of the fold, a block residual used inside another expression, more live values than registers.
    pub fn compile(g: &GateProgram, lay: &GateInputs, blinded: bool) -> Result<GateEval, &'static str> {
        Self::compile_with_combo(g, lay, blinded, &[])
    }

    /// [`Self::compile`] plus a COMBINATION `Σ_j β^j · input[combo[j]]` left in `X[18]` after pass 2 — a merge's deferred
    /// program claim over its child's opened flag cells (`vm::program_claim_holds` checks it at the root). The inputs
    /// are ordinary reads: pass 1 hashed them, so β was drawn after them.
    pub fn compile_with_combo(g: &GateProgram, lay: &GateInputs, blinded: bool, combo: &[u32]) -> Result<GateEval, &'static str> {
        // the blocks: cells contiguous opened columns; residuals contiguous in the fold
        let mut blocks = Vec::new();
        let mut rcs = Vec::new();
        for (b, blk) in g.perm_blocks.iter().enumerate() {
            let base = match g.ops.get(blk.cells[0] as usize) {
                Some(GOp::Input(i)) => *i as usize,
                _ => return Err("a block's first cell is not an input"),
            };
            for (k, &c) in blk.cells.iter().enumerate() {
                if g.ops.get(c as usize) != Some(&GOp::Input((base + k) as u32)) || base + k >= lay.width {
                    return Err("a block's cells are not one run of the opened row");
                }
            }
            let first = g
                .outputs
                .iter()
                .position(|&o| matches!(g.ops[o as usize], GOp::PermOut { block, k } if block as usize == b && k == 0))
                .ok_or("a block's first residual is not an output")?;
            let n = usdm_decider::pow_pq_air::perm_residual_count();
            for k in 0..n {
                if !matches!(g.ops.get(*g.outputs.get(first + k).ok_or("a block runs past the fold")? as usize), Some(GOp::PermOut { block, k: kk }) if *block as usize == b && *kk as usize == k) {
                    return Err("a block's residuals are not one run of the fold");
                }
            }
            blocks.push(BlockPlan { base, offset: first, seed: blk.seed });
            rcs.push(match blk.seed {
                Some(sd) => usdm_decider::pow_pq_air::constants_for_seed_cached(sd),
                None => production_constants_cached(),
            });
        }
        let mut order: Vec<usize> = (0..blocks.len()).collect();
        order.sort_by_key(|&i| blocks[i].base);
        let blocks: Vec<BlockPlan> = order.iter().map(|&i| blocks[i].clone()).collect();
        let rc: Vec<_> = order.iter().map(|&i| rcs[i]).collect();
        for w in blocks.windows(2) {
            if w[0].base + P2 > w[1].base {
                return Err("two blocks overlap");
            }
        }
        // pass 2: every non-block residual, in fold order, with its power
        let mut c = Compiler { g, free: (R_LO..R_HI).rev().collect(), refs: HashMap::new(), steps: Vec::new(), reads: Vec::new() };
        // P = 1, SUM = 0
        c.steps.push(Step::Op(alu(SrcA::One, SrcB::One, None, Some(R_P), false, Ea4::ZERO)));
        c.steps.push(Step::Op(alu(SrcA::One, SrcB::Kc, None, Some(R_SUM), false, Ea4::ZERO)));
        let mut p_exp = 0usize;
        // per-residual use counts of each node (shared subexpressions within one residual)
        for (i, &o) in g.outputs.iter().enumerate() {
            if matches!(g.ops[o as usize], GOp::PermOut { .. }) {
                continue;
            }
            let mut uses: HashMap<u32, u32> = HashMap::new();
            count_uses(g, o, &mut uses);
            let mut memo = HashMap::new();
            let v = c.eval(o, &mut memo, &uses).ok_or("a residual needs more registers than pass 2 holds")?;
            if i > p_exp {
                for op in times_gamma_pow(R_P, Some(R_P), i - p_exp).ok_or("a power past the binary table")? {
                    c.steps.push(Step::Op(op));
                }
                p_exp = i;
            }
            match v {
                Val::K(k) if k == Ea4::ZERO => {}
                Val::K(k) => c.steps.push(Step::Op(alu(SrcA::X(R_P), SrcB::Kc, Some(SrcC::X(R_SUM)), Some(R_SUM), false, k))),
                Val::Reg(r) => {
                    c.steps.push(Step::Op(alu(SrcA::X(R_P), SrcB::X(r), Some(SrcC::X(R_SUM)), Some(R_SUM), false, Ea4::ZERO)));
                    c.release(v);
                }
            }
        }
        // the total: CACC (the blocks, at absolute powers) + SUM, times (1 − x₀) when blinded
        c.steps.push(Step::Op(alu(SrcA::One, SrcB::Cacc, Some(SrcC::X(R_SUM)), Some(R_SUM), false, Ea4::ZERO)));
        if blinded {
            if lay.nvars == 0 {
                return Err("a blinded gate with no point");
            }
            let x0 = (lay.width + lay.shifted.len()) as u32;
            let r = c.alloc(2).ok_or("no register for x₀")?;
            c.steps.push(Step::Read { idx: x0, reg: r });
            c.reads.push(x0);
            // r = 1 − x₀ ; SUM = SUM · r
            c.steps.push(Step::Op(alu(SrcA::X(r), SrcB::Kc, Some(SrcC::One), Some(r), false, -Ea4::ONE)));
            c.steps.push(Step::Op(alu(SrcA::X(r), SrcB::X(R_SUM), None, Some(R_SUM), false, Ea4::ZERO)));
        }
        if !combo.is_empty() {
            // P' = 1, COMBO = 0, then COMBO += P'·v; P' *= β per input (X[18] = COMBO, X[17] = P')
            let (rc, rp) = (R_P, R_P - 1);
            c.steps.push(Step::Op(alu(SrcA::One, SrcB::One, None, Some(rp), false, Ea4::ZERO)));
            c.steps.push(Step::Op(alu(SrcA::One, SrcB::Kc, None, Some(rc), false, Ea4::ZERO)));
            c.free.retain(|&r| r != rc && r != rp);
            for &idx in combo {
                let r = c.alloc(1).ok_or("no register for a combination read")?;
                c.steps.push(Step::Read { idx, reg: r });
                c.reads.push(idx);
                c.steps.push(Step::Op(alu(SrcA::X(rp), SrcB::X(r), Some(SrcC::X(rc)), Some(rc), false, Ea4::ZERO)));
                c.steps.push(Step::Op(alu(SrcA::X(rp), SrcB::X(X_BETA as u8), None, Some(rp), false, Ea4::ZERO)));
                c.release(Val::Reg(r));
            }
        }
        let mut mult: HashMap<u32, u32> = HashMap::new();
        for &r in &c.reads {
            *mult.entry(r).or_default() += 1;
        }
        for &r in &c.reads {
            if r as usize >= lay.publics_at() {
                return Err("a public value is read (publics are the program's constants)");
            }
        }
        // the read groups: consecutive Read steps two at a time — pass 1 absorbs the same groups pass 2 emits
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut n = 0usize;
        let mut k = 0usize;
        while k < c.steps.len() {
            if matches!(c.steps[k], Step::Read { .. }) {
                let two = matches!(c.steps.get(k + 1), Some(Step::Read { .. }));
                groups.push(if two { vec![n, n + 1] } else { vec![n] });
                n += if two { 2 } else { 1 };
                k += if two { 2 } else { 1 };
            } else {
                k += 1;
            }
        }
        Ok(GateEval { lay: lay.clone(), blinded, blocks, reads: c.reads, mult, steps: c.steps, groups, rc })
    }

    /// PASS 1 (before the inner transcript's replay): hash every read value into the circuit's own sponge, draw ρ and
    /// β, clear the logUp sum. `inputs` is the gate's whole input vector (the prover's), or all zero when only the
    /// program is being built.
    pub fn emit_pass1(&self, b: &mut Builder, inputs: &[Ea4]) {
        let val = |n: usize| inputs.get(self.reads[n] as usize).copied().unwrap_or(Ea4::ZERO);
        for (gi, g) in self.groups.iter().enumerate() {
            let mut w = [Fa4::ZERO; ND];
            for (q, &n) in g.iter().enumerate() {
                w[4 * q..4 * q + 4].copy_from_slice(&lanes(val(n)));
            }
            let kind = if gi == 0 { Kind::FsReset } else { Kind::FsDup };
            b.push(Instr { kind: Some(kind), am: 0xFF, lclr: gi == 0, ..Default::default() }, w);
        }
        if self.groups.is_empty() {
            b.push(Instr { kind: Some(Kind::FsReset), am: 0, lclr: true, ..Default::default() }, [Fa4::ZERO; ND]);
        }
        let mut i = Instr::default();
        i.alu[0] = Some(alu(SrcA::One, SrcB::Cf(0), None, Some(X_RHO as u8), false, Ea4::ZERO));
        i.alu[1] = Some(alu(SrcA::One, SrcB::Cf(4), None, Some(X_BETA as u8), false, Ea4::ZERO));
        b.push(i, [Fa4::ZERO; ND]);
    }

    /// The challenges pass 1 draws, natively: the circuit's own sponge over the read groups, then ρ = Cf(0), β = Cf(4).
    #[must_use]
    pub fn challenges(&self, inputs: &[Ea4]) -> (Ea4, Ea4) {
        use p3_symmetric::Permutation;
        let perm = usdm_decider::sponge_chain_air::perm_for_seed(SEED);
        let mut st = [Fa4::ZERO; WIDTH];
        let val = |n: usize| inputs.get(self.reads[n] as usize).copied().unwrap_or(Ea4::ZERO);
        if self.groups.is_empty() {
            perm.permute_mut(&mut st);
        }
        for (gi, g) in self.groups.iter().enumerate() {
            if gi == 0 {
                st = [Fa4::ZERO; WIDTH];
            }
            let mut w = [Fa4::ZERO; RATE];
            for (q, &n) in g.iter().enumerate() {
                w[4 * q..4 * q + 4].copy_from_slice(&lanes(val(n)));
            }
            st[..RATE].copy_from_slice(&w);
            perm.permute_mut(&mut st);
        }
        let ch = |j: usize| ea(&core::array::from_fn::<Fa4, 4, _>(|l| st[7 - j - l]));
        (ch(0), ch(4))
    }

    /// Once the inner γ is in `X[gamma_reg]`: keep it in `X[20]` until pass 2, lay Γ = (1, γ, …, γ¹⁵), γ¹⁶ and the binary
    /// powers, and clear the chip.
    pub fn emit_gamma(&self, b: &mut Builder, gamma_reg: u8) {
        let mut i = Instr { cclr: true, ..Default::default() };
        i.alu[0] = Some(alu(SrcA::One, SrcB::X(gamma_reg), None, Some(X_GAMMA as u8), false, Ea4::ZERO));
        b.push(i, [Fa4::ZERO; ND]);
        lay_gamma_powers(b, X_GAMMA as u8);
    }

    /// The opened (and, for a chained door, next-row) values' absorption: given which absorbed lane each WSH row
    /// carried (`stream[k] = (row, lane index into `limbs`, or None for a lane that is not one of these values)`), set the
    /// chip's rounds, each block's start power, and the table terms on the rows after. `base_value` numbers the values
    /// `limbs` holds (0 = opened column 0; the next-row values follow the opened row: `width + k`).
    pub fn decorate(&self, b: &mut Builder, wsh_rows: &[(usize, [Option<usize>; RATE])], base_value: usize, n_values: usize) -> Result<(), &'static str> {
        // the stream position of every value's last limb, and the row after which it is complete
        let mut pos_of_limb: HashMap<usize, usize> = HashMap::new();
        for (k, (_, lanes)) in wsh_rows.iter().enumerate() {
            for (l, lane) in lanes.iter().enumerate() {
                if let Some(li) = lane {
                    pos_of_limb.insert(*li, RATE * k + l);
                }
            }
        }
        let complete_after = |v: usize| -> Option<(usize, usize)> {
            // (index into wsh_rows of the row that carried the value's last limb, that limb's stream position)
            let p = *pos_of_limb.get(&(4 * v + 3))?;
            for t in 0..3 {
                if *pos_of_limb.get(&(4 * v + t))? + 3 - t != p {
                    return None; // a value's limbs are not consecutive in the stream
                }
            }
            Some((p / RATE, p))
        };
        // the row a decoration rides: the row after the carrier of position p; off = lanes between p and the window's end
        let site = |p: usize| -> Option<(usize, u8)> {
            let k = p / RATE;
            let row = wsh_rows.get(k)?.0 + 1;
            let end = RATE * k + RATE - 1;
            let off = end - p;
            (off < NOFF).then_some((row, off as u8))
        };
        let mut chip_rows: HashMap<usize, (Chip, [Fa4; WIDTH], u8)> = HashMap::new();
        let mut gp_before: Vec<(usize, usize)> = Vec::new(); // (Init row, exponent)
        for (bi, blk) in self.blocks.iter().enumerate() {
            let lo = blk.base;
            if lo < base_value || lo + P2 > base_value + n_values {
                continue; // a block of another region (opened vs next)
            }
            let v = |c: usize| c - base_value;
            let group_end = |last_col: usize| -> Result<(usize, u8), &'static str> {
                let (_, p) = complete_after(v(last_col)).ok_or("a block's values are not in the stream")?;
                site(p).ok_or("a group's last value is past the window")
            };
            let rc = self.rc[bi];
            let (r_init, off) = group_end(lo + 15)?;
            chip_rows.insert(r_init, (Chip::Init, [Fa4::ZERO; WIDTH], off));
            gp_before.push((r_init, blk.offset));
            for j in 0..4 {
                let (r, off) = group_end(lo + 16 + 16 * j + 15)?;
                chip_rows.insert(r, (Chip::Full, rc.beginning_full_round_constants[j], off));
            }
            for k in 0..10 {
                let (r, off) = group_end(lo + 80 + 2 * k + 1)?;
                let mut c = [Fa4::ZERO; WIDTH];
                c[0] = rc.partial_round_constants[2 * k];
                c[1] = rc.partial_round_constants[2 * k + 1];
                if chip_rows.insert(r, (Chip::Part, c, off)).is_some() {
                    return Err("two chip rounds on one row");
                }
            }
            for j in 0..4 {
                let (r, off) = group_end(lo + 100 + 16 * j + 15)?;
                if chip_rows.insert(r, (Chip::Full, rc.ending_full_round_constants[j], off)).is_some() {
                    return Err("two chip rounds on one row");
                }
            }
        }
        // table terms: a WSH row completes two values (four-limb values, eight lanes); the row after it reads that pair
        // from the window at the unit's own anchor, slot 0 the earlier value, slot 1 the later
        let mut lu_rows: HashMap<usize, ([Option<Lu>; 2], u8)> = HashMap::new();
        let mut by_row: HashMap<usize, Vec<(usize, usize)>> = HashMap::new(); // wsh index → (value, last position)
        for vi in 0..n_values {
            if let Some((k, p)) = complete_after(vi) {
                by_row.entry(k).or_default().push((vi, p));
            }
        }
        for (k, mut vs) in by_row {
            vs.sort_by_key(|&(_, p)| p);
            let (v_last, p_last) = *vs.last().expect("a row's values");
            let (row, loff) = site(p_last).ok_or("a read value is past the window")?;
            let term = |v: usize| -> Option<Lu> {
                let idx = (base_value + v) as u32;
                self.mult.get(&idx).map(|&m| Lu { addr: Fa4::from_u64(u64::from(idx)), mult: Fa4::from_u64(u64::from(m)) })
            };
            let mut slots = [None, term(v_last)];
            if vs.len() == 2 {
                if vs[0].0 + 1 != v_last {
                    return Err("a row's two values are not consecutive");
                }
                slots[0] = term(vs[0].0);
            } else if vs.len() > 2 {
                return Err("a row completes more than two values");
            } else if v_last > 0 && self.mult.contains_key(&((base_value + v_last - 1) as u32)) {
                // the earlier value completed on another row and is read there
            }
            if slots.iter().any(Option::is_some) {
                lu_rows.insert(row, (slots, loff));
            }
            let _ = k;
        }
        // every read value of this region has a term
        for vi in 0..n_values {
            let idx = (base_value + vi) as u32;
            if self.mult.contains_key(&idx) && complete_after(vi).is_none() {
                return Err("a read value is not in the stream");
            }
        }
        // set the decorations; block start powers on the rows before each Init (units are this evaluator's there)
        for (row, (c, rc, off)) in &chip_rows {
            let i = b.prog.get_mut(*row).ok_or("a chip row past the program")?;
            if i.chip.is_some() {
                return Err("a chip row already holds a round");
            }
            i.chip = Some(*c);
            i.rc = *rc;
            i.off = *off;
        }
        for (row, (lu, loff)) in &lu_rows {
            let i = b.prog.get_mut(*row).ok_or("a table row past the program")?;
            if i.lu.iter().any(Option::is_some) {
                return Err("a table row is already used");
            }
            i.lu = *lu;
            i.luw = true;
            i.loff = *loff;
        }
        for (init_row, e) in gp_before {
            let ops = times_gamma_pow(X_GP as u8, None, e).ok_or("a block power past the binary table")?;
            if ops.len() > init_row {
                return Err("no rows before a block for its start power");
            }
            for (n, op) in ops.iter().enumerate() {
                let r = init_row - ops.len() + n;
                let i = b.prog.get_mut(r).ok_or("a power row past the program")?;
                let free = i.alu.iter().position(Option::is_none).ok_or("no free unit for a block's start power")?;
                i.alu[free] = Some(*op);
            }
        }
        Ok(())
    }

    /// A zerocheck point coordinate `x_k`, now in `X[reg]` with value `value` (the prover's): its table term, on a row
    /// of its own (the row's stream is the value; a unit asserts it equals the register).
    pub fn emit_x_term(&self, b: &mut Builder, k: usize, reg: u8, value: Ea4) {
        let idx = (self.lay.x_at() + k) as u32;
        let Some(&m) = self.mult.get(&idx) else { return };
        let mut w = [Fa4::ZERO; ND];
        w[..4].copy_from_slice(&lanes(value));
        let mut i = Instr::default();
        i.lu[0] = Some(Lu { addr: Fa4::from_u64(u64::from(idx)), mult: Fa4::from_u64(u64::from(m)) });
        i.alu[0] = Some(alu(SrcA::X(reg), SrcB::Kc, Some(SrcC::Dx(0)), None, true, -Ea4::ONE));
        b.push(i, w);
    }

    /// PASS 2 (after the replay): re-hash the reads (the sponge must land where pass 1 did), their read terms, the
    /// non-block residuals, the logUp balance; leaves `C_γ` in `X[19]`.
    pub fn emit_pass2(&self, b: &mut Builder, inputs: &[Ea4]) {
        // the verifier program may have used X[23..48] since the chip ran: lay the powers again from the kept γ
        lay_gamma_powers(b, X_GAMMA as u8);
        let mut n_read = 0usize;
        let mut pending: Vec<Alu> = Vec::new();
        let flush = |b: &mut Builder, pending: &mut Vec<Alu>| {
            for pair in pending.chunks(1) {
                let mut i = Instr::default();
                i.alu[0] = Some(pair[0]);
                b.push(i, [Fa4::ZERO; ND]);
            }
            pending.clear();
        };
        let mut k = 0;
        while k < self.steps.len() {
            match &self.steps[k] {
                Step::Op(a) => {
                    pending.push(*a);
                    k += 1;
                }
                Step::Read { .. } => {
                    flush(b, &mut pending);
                    // a pair of reads (this one and, when the next step is also a read, that one)
                    let mut pair: Vec<(u32, u8)> = Vec::new();
                    if let Step::Read { idx, reg } = self.steps[k] {
                        pair.push((idx, reg));
                    }
                    if let Some(Step::Read { idx, reg }) = self.steps.get(k + 1) {
                        pair.push((*idx, *reg));
                    }
                    k += pair.len();
                    let mut w = [Fa4::ZERO; ND];
                    let mut i = Instr { kind: Some(if n_read == 0 { Kind::FsReset } else { Kind::FsDup }), am: 0xFF, ..Default::default() };
                    for (q, (idx, reg)) in pair.iter().enumerate() {
                        let v = inputs.get(*idx as usize).copied().unwrap_or(Ea4::ZERO);
                        w[4 * q..4 * q + 4].copy_from_slice(&lanes(v));
                        i.lu[q] = Some(Lu { addr: Fa4::from_u64(u64::from(*idx)), mult: Fa4::NEG_ONE });
                        i.alu[q] = Some(alu(SrcA::One, SrcB::Dx(q as u8), None, Some(*reg), false, Ea4::ZERO));
                    }
                    n_read += pair.len();
                    // pass 1 grouped the reads two at a time in the same order: the same words, the same sponge
                    b.push(i, w);
                }
            }
        }
        flush(b, &mut pending);
        // the sponge is where pass 1 left it (t = Cf, then −t + ρ = 0), and the logUp sum is zero
        let mut i = Instr::default();
        i.alu[0] = Some(alu(SrcA::One, SrcB::Cf(0), None, Some(R_LO), false, Ea4::ZERO));
        i.alu[1] = Some(alu(SrcA::One, SrcB::Cf(4), None, Some(R_LO + 1), false, Ea4::ZERO));
        b.push(i, [Fa4::ZERO; ND]);
        let mut i = Instr::default();
        i.alu[0] = Some(alu(SrcA::X(R_LO), SrcB::Kc, Some(SrcC::X(X_RHO as u8)), None, true, -Ea4::ONE));
        i.alu[1] = Some(alu(SrcA::X(R_LO + 1), SrcB::Kc, Some(SrcC::X(X_BETA as u8)), None, true, -Ea4::ONE));
        b.push(i, [Fa4::ZERO; ND]);
        let mut i = Instr::default();
        i.alu[0] = Some(alu(SrcA::One, SrcB::Lacc, None, None, true, Ea4::ZERO));
        b.push(i, [Fa4::ZERO; ND]);
    }
}

/// Γ = (1, γ, …, γ¹⁵) into `X[24..40]`, γ¹⁶ into `X[40]`, γ^(32·2^i) into `X[41..48]`, from `X[gamma_reg]` (23 rows).
fn lay_gamma_powers(b: &mut Builder, gamma_reg: u8) {
    let one = |dst: usize| alu(SrcA::One, SrcB::One, None, Some(dst as u8), false, Ea4::ZERO);
    let row = |b: &mut Builder, a0: Alu, a1: Option<Alu>| {
        let mut i = Instr::default();
        i.alu[0] = Some(a0);
        i.alu[1] = a1;
        b.push(i, [Fa4::ZERO; ND]);
    };
    row(b, one(X_GAMMA_POW), Some(alu(SrcA::One, SrcB::X(gamma_reg), None, Some((X_GAMMA_POW + 1) as u8), false, Ea4::ZERO)));
    for k in 2..16 {
        row(b, alu(SrcA::X((X_GAMMA_POW + k - 1) as u8), SrcB::X(gamma_reg), None, Some((X_GAMMA_POW + k) as u8), false, Ea4::ZERO), None);
    }
    row(b, alu(SrcA::X((X_GAMMA_POW + 15) as u8), SrcB::X(gamma_reg), None, Some(X_G16 as u8), false, Ea4::ZERO), None);
    row(b, alu(SrcA::X(X_G16 as u8), SrcB::X(X_G16 as u8), None, Some(X_GBIN as u8), false, Ea4::ZERO), None);
    for i in 1..NGBIN {
        let prev = (X_GBIN + i - 1) as u8;
        row(b, alu(SrcA::X(prev), SrcB::X(prev), None, Some((X_GBIN + i) as u8), false, Ea4::ZERO), None);
    }
}

/// The program with inputs `from..` replaced by constants (a gate's public values: the program is then a function of
/// its statement, which every verifier of the root holds).
#[must_use]
pub fn with_publics(g: &GateProgram, from: usize, vals: &[Ea4]) -> GateProgram {
    let mut h = g.clone();
    for op in &mut h.ops {
        if let GOp::Input(i) = *op {
            if i as usize >= from {
                *op = GOp::Konst(vals.get(i as usize - from).copied().unwrap_or(Ea4::ZERO));
            }
        }
    }
    h
}

fn count_uses(g: &GateProgram, root: u32, uses: &mut HashMap<u32, u32>) {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        let e = uses.entry(n).or_insert(0);
        *e += 1;
        if *e > 1 {
            continue;
        }
        match g.ops[n as usize] {
            GOp::Add(a, b) | GOp::Sub(a, b) | GOp::Mul(a, b) => {
                stack.push(a);
                stack.push(b);
            }
            GOp::Neg(a) => stack.push(a),
            _ => {}
        }
    }
}

fn production_constants_cached() -> &'static p3_poseidon2_air::RoundConstants<Fa4, WIDTH, 4, 20> {
    static C: std::sync::OnceLock<p3_poseidon2_air::RoundConstants<Fa4, WIDTH, 4, 20>> = std::sync::OnceLock::new();
    C.get_or_init(usdm_decider::pow_pq_air::production_constants)
}

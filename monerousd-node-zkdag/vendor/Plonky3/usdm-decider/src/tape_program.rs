//! ⭐ THE COMPILED TAPE'S REGISTER PROGRAM (speed lane R8, 2026-11-10) — the same straight-line program
//! [`crate::whole_chain::CompiledTape`] always was, laid out so one evaluation costs what its arithmetic costs.
//!
//! MEASURED (macOS `sample`, two real nodes on one binary, 9.6 minutes, 2026-11-10): the tape evaluator was the largest
//! term of a block's proof CPU — 31.5 % of on-CPU samples (`eval_into_in` 20.5 %, `eval` 11.0 %). Read from the code, three
//! things made one evaluation dearer than its arithmetic:
//!
//! 1. **One slot per op.** Every evaluation allocated a slot for each of the tape's ops (the permutation's tape: about
//!    3,000 slots, 48 KB in the extension field) and wrote each once. Here a value lives in a REGISTER that is handed
//!    to the next value the moment its last reader has run, so the working set is the program's widest live set.
//! 2. **A round constant multiplied as an extension element.** Every constant of these AIRs is a base-field value, and
//!    an extension element times a base element is 4 base multiplies where the general product is 16. Of the
//!    permutation's 616 multiplies, 320 are by a constant (the internal layer's diagonal).
//! 3. **A square taken as a general product.** The S-box cubes `x`; its `x·x` is a square.
//!
//! ⛔ IT COMPUTES EXACTLY THE SAME VALUES. The program is derived mechanically from the reference op list by rewrites that
//! are identities in any field containing the base field: `a·k` for a base constant `k` (the algebra's own scalar
//! product), `a·a = a²`, `a − k = a + (−k)`, a constant-only subtree folded in the base field, and a renaming of slots to
//! registers. The verifier evaluates its final point through this same program, so a wrong rewrite would be a wrong
//! STATEMENT, not a slow prover — which is why the reference interpreter and the recursive walker are kept, and
//! `speed_r8_the_register_program_gives_the_reference_values_in_both_fields` demands exact equality against both, on full
//! extension elements, with one tampered op that must disagree.
//!
//! BORROWED: straight-line-program evaluation with last-use register reuse (linear-scan register allocation, Poletto &
//! Sarkar 1999) and the base-scalar product of an extension element (Plonky3's `Algebra<F>`, the shape its own constraint
//! folders evaluate round constants with).
//!
//! FOOTPRINT: three boxed slices fixed at compile time, sized by the AIR's constraint DAG alone — 16 bytes per op, one
//! base element per distinct constant, one entry per constraint. Nothing here grows with height, blocks or notes.
//! cons: +16 bytes of RAM per tape op while a tape lives (the permutation's tape: about 50 KB for the process's
//! lifetime); one more linear pass at tape compile. No wire, proof or statement change.

use p3_field::{Algebra, Field, PrimeCharacteristicRing, PrimeField32};

use crate::hiding_decider::Fa4;
use crate::whole_chain::TapeOp;

/// One step of the register program. Every operand is a register index except `src` (a slot of the caller's row
/// buffer) and `k` (an index into the program's base-field constant table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegOp {
    /// `regs[dst] = bl[src]`
    Load { dst: u32, src: u32 },
    /// `regs[dst] = consts[k]`, lifted — only where a constant is itself a value some op reads whole.
    Konst { dst: u32, k: u32 },
    Add { dst: u32, a: u32, b: u32 },
    Sub { dst: u32, a: u32, b: u32 },
    Mul { dst: u32, a: u32, b: u32 },
    /// `regs[dst] = regs[a]²`
    Sq { dst: u32, a: u32 },
    Neg { dst: u32, a: u32 },
    /// `regs[dst] = regs[a] + consts[k]` (also `a − k`, with `−k` in the table)
    AddK { dst: u32, a: u32, k: u32 },
    /// `regs[dst] = consts[k] − regs[a]`
    KSub { dst: u32, a: u32, k: u32 },
    /// `regs[dst] = regs[a] · consts[k]` — the algebra's scalar product
    MulK { dst: u32, a: u32, k: u32 },
}

/// Where one constraint's value is read once the program has run.
#[derive(Clone, Copy, Debug)]
enum Root {
    Reg(u32),
    /// A constraint that is a constant of the AIR (it reads no cell).
    Konst(Fa4),
}

/// What an operand of a reference op is, once constants are known.
#[derive(Clone, Copy)]
enum Operand {
    Reg(u32),
    K(Fa4),
}

/// The register program of one compiled tape. See the module doc.
#[derive(Clone, Debug)]
pub(crate) struct RegProgram {
    ops: Box<[RegOp]>,
    consts: Box<[Fa4]>,
    roots: Box<[Root]>,
    regs: usize,
}

impl RegProgram {
    /// Derive the register program from the reference op list (`ops[i]` writes slot `i`; `roots` name the slots the
    /// constraints land in). Total: every op list the tape compiler can emit has a program, with no refused shape.
    pub(crate) fn compile(ops: &[TapeOp], roots: &[u32]) -> Self {
        let n = ops.len();
        // 0. VALUE NUMBERS. The reference list shares a sub-expression only when two readers hold the SAME allocation
        //    (its memo is keyed by pointer), and a symbolic `x.clone() * x.clone()` or a cloned sum is a fresh top node
        //    over shared children — so the list computes many values twice and never shows a square as one slot read
        //    twice. MEASURED on the permutation's tape (2026-11-10): 4,588 slots, 362 loads of 164 columns, 488 general
        //    products where the S-boxes hold 148 squares and 148 products, 0 squares found. Two slots with the same op
        //    over the same operand VALUES hold the same value (`+` and `·` in either operand order), so each slot is
        //    numbered by the first slot that computes its value and every later step reads that one.
        #[derive(Hash, PartialEq, Eq)]
        enum Key {
            Load(u32),
            Konst(u32),
            Add(u32, u32),
            Sub(u32, u32),
            Mul(u32, u32),
            Neg(u32),
        }
        let mut canon: Vec<u32> = Vec::with_capacity(n);
        let mut first: std::collections::HashMap<Key, u32> = std::collections::HashMap::new();
        for (i, op) in ops.iter().enumerate() {
            let c = |s: u32| canon[s as usize];
            let key = match *op {
                TapeOp::Load(j) => Key::Load(j),
                TapeOp::Const(v, _) => Key::Konst(v.as_canonical_u32()),
                TapeOp::Add(a, b) => Key::Add(c(a).min(c(b)), c(a).max(c(b))),
                TapeOp::Sub(a, b) => Key::Sub(c(a), c(b)),
                TapeOp::Mul(a, b) => Key::Mul(c(a).min(c(b)), c(a).max(c(b))),
                TapeOp::Neg(a) => Key::Neg(c(a)),
            };
            let v = *first.entry(key).or_insert(i as u32);
            canon.push(v);
        }
        // the list every later step reads: each op over its operands' value numbers; a slot that repeats an earlier
        // value is `live == false` and is never emitted or read
        let live: Vec<bool> = canon.iter().enumerate().map(|(i, &v)| v as usize == i).collect();
        let ops: Vec<TapeOp> = ops
            .iter()
            .map(|op| match *op {
                TapeOp::Load(j) => TapeOp::Load(j),
                TapeOp::Const(v, e) => TapeOp::Const(v, e),
                TapeOp::Add(a, b) => TapeOp::Add(canon[a as usize], canon[b as usize]),
                TapeOp::Sub(a, b) => TapeOp::Sub(canon[a as usize], canon[b as usize]),
                TapeOp::Mul(a, b) => TapeOp::Mul(canon[a as usize], canon[b as usize]),
                TapeOp::Neg(a) => TapeOp::Neg(canon[a as usize]),
            })
            .collect();
        let roots: Vec<u32> = roots.iter().map(|&r| canon[r as usize]).collect();
        let (ops, roots) = (&ops[..], &roots[..]);
        // 1. Which slots are constants of the AIR, and their values — exact base-field arithmetic.
        let mut konst: Vec<Option<Fa4>> = Vec::with_capacity(n);
        for op in ops {
            let both = |a: u32, b: u32, f: fn(Fa4, Fa4) -> Fa4| match (konst[a as usize], konst[b as usize]) {
                (Some(x), Some(y)) => Some(f(x, y)),
                _ => None,
            };
            let v = match *op {
                TapeOp::Load(_) => None,
                TapeOp::Const(c, _) => Some(c),
                TapeOp::Add(a, b) => both(a, b, |x, y| x + y),
                TapeOp::Sub(a, b) => both(a, b, |x, y| x - y),
                TapeOp::Mul(a, b) => both(a, b, |x, y| x * y),
                TapeOp::Neg(a) => konst[a as usize].map(|x| -x),
            };
            konst.push(v);
        }
        // 2. Each computed slot's last reader. A root is read after the last op, so it is never handed on.
        const NEVER: usize = usize::MAX;
        let mut last: Vec<usize> = vec![0; n];
        for (i, op) in ops.iter().enumerate() {
            if !live[i] || konst[i].is_some() {
                continue;
            }
            match *op {
                TapeOp::Load(_) | TapeOp::Const(..) => {}
                TapeOp::Add(a, b) | TapeOp::Sub(a, b) | TapeOp::Mul(a, b) => {
                    last[a as usize] = i;
                    last[b as usize] = i;
                }
                TapeOp::Neg(a) => last[a as usize] = i,
            }
        }
        for &r in roots {
            last[r as usize] = NEVER;
        }
        // 3. Emit, handing a register on at its value's last read (so an op may write over its own operand: every
        //    op reads its operands before it writes).
        let mut consts: Vec<Fa4> = Vec::new();
        let mut const_at: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        let mut kidx = |c: Fa4| -> u32 {
            *const_at.entry(c.as_canonical_u32()).or_insert_with(|| {
                consts.push(c);
                (consts.len() - 1) as u32
            })
        };
        let mut reg_of: Vec<u32> = vec![u32::MAX; n];
        // Freed registers are handed out OLDEST FIRST. The count is the same either way (a new register is opened only
        // when none is free); what differs is how soon a location is written again. MEASURED on the first cut
        // (newest-first, base field, one run beside another test at load 95): 3.5 ns an op against the slot
        // interpreter's 2.3 ns, whose every store goes to a fresh address. NOT measured: why. The reading taken here is
        // that newest-first rewrites a location a few ops after its last read, so loads keep sitting behind an
        // in-flight store to their own address; `speed_r8_one_evaluation_measured_under_both_engines` reads both
        // engines again, alone, and that number — not this sentence — says whether the order mattered.
        let mut free: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
        let mut regs: u32 = 0;
        let mut out: Vec<RegOp> = Vec::with_capacity(n);
        for (i, op) in ops.iter().enumerate() {
            if !live[i] || konst[i].is_some() {
                continue;
            }
            let operand = |s: u32| match konst[s as usize] {
                Some(c) => Operand::K(c),
                None => Operand::Reg(reg_of[s as usize]),
            };
            let reads: [Option<u32>; 2] = match *op {
                TapeOp::Load(_) | TapeOp::Const(..) => [None, None],
                TapeOp::Add(a, b) | TapeOp::Sub(a, b) | TapeOp::Mul(a, b) => [Some(a), if a == b { None } else { Some(b) }],
                TapeOp::Neg(a) => [Some(a), None],
            };
            // the operands' registers are read off BEFORE any is handed on
            let (x, y) = match *op {
                TapeOp::Add(a, b) | TapeOp::Sub(a, b) | TapeOp::Mul(a, b) => (Some(operand(a)), Some(operand(b))),
                TapeOp::Neg(a) => (Some(operand(a)), None),
                TapeOp::Load(_) | TapeOp::Const(..) => (None, None),
            };
            for s in reads.into_iter().flatten() {
                if konst[s as usize].is_none() && last[s as usize] == i {
                    free.push_back(reg_of[s as usize]);
                }
            }
            let dst = free.pop_front().unwrap_or_else(|| {
                regs += 1;
                regs - 1
            });
            reg_of[i] = dst;
            let rop = match (op.clone(), x, y) {
                (TapeOp::Load(src), ..) => RegOp::Load { dst, src },
                (TapeOp::Const(c, _), ..) => RegOp::Konst { dst, k: kidx(c) },
                (TapeOp::Add(..), Some(Operand::Reg(a)), Some(Operand::Reg(b))) => RegOp::Add { dst, a, b },
                (TapeOp::Add(..), Some(Operand::Reg(a)), Some(Operand::K(k))) | (TapeOp::Add(..), Some(Operand::K(k)), Some(Operand::Reg(a))) => {
                    RegOp::AddK { dst, a, k: kidx(k) }
                }
                (TapeOp::Sub(..), Some(Operand::Reg(a)), Some(Operand::Reg(b))) => RegOp::Sub { dst, a, b },
                (TapeOp::Sub(..), Some(Operand::Reg(a)), Some(Operand::K(k))) => RegOp::AddK { dst, a, k: kidx(-k) },
                (TapeOp::Sub(..), Some(Operand::K(k)), Some(Operand::Reg(a))) => RegOp::KSub { dst, a, k: kidx(k) },
                (TapeOp::Mul(p, q), Some(Operand::Reg(a)), Some(Operand::Reg(b))) => {
                    if p == q {
                        RegOp::Sq { dst, a }
                    } else {
                        RegOp::Mul { dst, a, b }
                    }
                }
                (TapeOp::Mul(..), Some(Operand::Reg(a)), Some(Operand::K(k))) | (TapeOp::Mul(..), Some(Operand::K(k)), Some(Operand::Reg(a))) => {
                    RegOp::MulK { dst, a, k: kidx(k) }
                }
                (TapeOp::Neg(_), Some(Operand::Reg(a)), _) => RegOp::Neg { dst, a },
                // Constant-only operands: step 1 folds every such op, so none reaches here; each arm still lays the
                // op's exact value, so the function is total without a refusal.
                (TapeOp::Add(..), Some(Operand::K(p)), Some(Operand::K(q))) => RegOp::Konst { dst, k: kidx(p + q) },
                (TapeOp::Sub(..), Some(Operand::K(p)), Some(Operand::K(q))) => RegOp::Konst { dst, k: kidx(p - q) },
                (TapeOp::Mul(..), Some(Operand::K(p)), Some(Operand::K(q))) => RegOp::Konst { dst, k: kidx(p * q) },
                (TapeOp::Neg(_), Some(Operand::K(p)), _) => RegOp::Konst { dst, k: kidx(-p) },
                // An arithmetic op always has its operands (set above from the op itself); zero is the value of an
                // empty sum, laid only so the match is total.
                (TapeOp::Add(..) | TapeOp::Sub(..) | TapeOp::Mul(..) | TapeOp::Neg(_), ..) => RegOp::Konst { dst, k: kidx(Fa4::ZERO) },
            };
            out.push(rop);
        }
        let roots: Vec<Root> = roots
            .iter()
            .map(|&r| match konst[r as usize] {
                Some(c) => Root::Konst(c),
                None => Root::Reg(reg_of[r as usize]),
            })
            .collect();
        Self { ops: out.into_boxed_slice(), consts: consts.into_boxed_slice(), roots: roots.into_boxed_slice(), regs: regs as usize }
    }

    /// Registers one evaluation needs — the program's widest live set.
    #[must_use]
    pub(crate) fn registers(&self) -> usize {
        self.regs
    }

    /// Ops in the program (the reference list less its folded constants).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.ops.len()
    }

    /// Constraints the program lands.
    #[must_use]
    pub(crate) fn roots(&self) -> usize {
        self.roots.len()
    }

    /// Run the program over `bl` in `regs` (at least [`Self::registers`] long; contents on entry are irrelevant —
    /// every register is written before it is read).
    #[inline]
    // Ring operations only (lane agg 2026-11-15): `gate_trace::Sym` runs this program too; Ea4/Fa4 compile as before.
    pub(crate) fn run<G: Algebra<Fa4> + Copy>(&self, bl: &[G], regs: &mut [G]) {
        let ks = &self.consts;
        for op in self.ops.iter() {
            match *op {
                RegOp::Load { dst, src } => regs[dst as usize] = bl[src as usize],
                RegOp::Konst { dst, k } => regs[dst as usize] = G::from(ks[k as usize]),
                RegOp::Add { dst, a, b } => regs[dst as usize] = regs[a as usize] + regs[b as usize],
                RegOp::Sub { dst, a, b } => regs[dst as usize] = regs[a as usize] - regs[b as usize],
                RegOp::Mul { dst, a, b } => regs[dst as usize] = regs[a as usize] * regs[b as usize],
                RegOp::Sq { dst, a } => regs[dst as usize] = regs[a as usize].square(),
                RegOp::Neg { dst, a } => regs[dst as usize] = -regs[a as usize],
                RegOp::AddK { dst, a, k } => regs[dst as usize] = regs[a as usize] + ks[k as usize],
                RegOp::KSub { dst, a, k } => regs[dst as usize] = G::from(ks[k as usize]) - regs[a as usize],
                RegOp::MulK { dst, a, k } => regs[dst as usize] = regs[a as usize] * ks[k as usize],
            }
        }
    }

    /// The `j`-th constraint's value after [`Self::run`].
    #[inline]
    pub(crate) fn root<G: Algebra<Fa4> + Copy>(&self, j: usize, regs: &[G]) -> G {
        match self.roots[j] {
            Root::Reg(r) => regs[r as usize],
            Root::Konst(c) => G::from(c),
        }
    }

    /// How many ops of each kind the program holds: `(loads, general multiplies, squares, constant multiplies, the
    /// rest)` — the figures the module doc's arithmetic is counted from.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn census(&self) -> (usize, usize, usize, usize, usize) {
        let count = |f: fn(&RegOp) -> bool| self.ops.iter().filter(|o| f(o)).count();
        let loads = count(|o| matches!(o, RegOp::Load { .. }));
        let muls = count(|o| matches!(o, RegOp::Mul { .. }));
        let sqs = count(|o| matches!(o, RegOp::Sq { .. }));
        let mulks = count(|o| matches!(o, RegOp::MulK { .. }));
        (loads, muls, sqs, mulks, self.ops.len() - loads - muls - sqs - mulks)
    }

    /// TEST ONLY: the same program with its `nth` constant multiply's constant moved by one — the tampered program
    /// the differential pin must see disagree. `None` when the program has fewer constant multiplies.
    #[cfg(test)]
    pub(crate) fn with_a_constant_multiply_moved(&self, nth: usize) -> Option<Self> {
        let at = self.ops.iter().enumerate().filter(|(_, o)| matches!(o, RegOp::MulK { .. })).map(|(i, _)| i).nth(nth)?;
        let mut t = self.clone();
        let mut consts = t.consts.to_vec();
        let mut ops = t.ops.to_vec();
        if let RegOp::MulK { dst, a, k } = ops[at] {
            consts.push(consts[k as usize] + Fa4::ONE);
            ops[at] = RegOp::MulK { dst, a, k: (consts.len() - 1) as u32 };
        }
        t.consts = consts.into_boxed_slice();
        t.ops = ops.into_boxed_slice();
        Some(t)
    }

    /// TEST ONLY: the same program with its `nth` subtraction's operands exchanged — an operand-order defect of the
    /// kind a wrong rewrite would be. `None` when the program has fewer subtractions.
    #[cfg(test)]
    pub(crate) fn with_a_subtraction_reversed(&self, nth: usize) -> Option<Self> {
        let at = self.ops.iter().enumerate().filter(|(_, o)| matches!(o, RegOp::Sub { .. })).map(|(i, _)| i).nth(nth)?;
        let mut t = self.clone();
        let mut ops = t.ops.to_vec();
        if let RegOp::Sub { dst, a, b } = ops[at] {
            ops[at] = RegOp::Sub { dst, a: b, b: a };
        }
        t.ops = ops.into_boxed_slice();
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiding_decider::Ea4;
    use crate::whole_chain::{eval_base_expr_lifted, CompiledTape, SymLeafLayout};
    use p3_field::BasedVectorSpace;

    /// A deterministic mixer rather than an RNG: a disagreement here is a soundness bug, and "it failed once on some
    /// seed" is not a bug report.
    fn mix(a: u64, b: u64) -> u64 {
        let mut x = a.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ b.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 31;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        (x ^ (x >> 29)) % 0x7F00_0001
    }
    fn base_at(draw: u64, i: usize) -> Fa4 {
        Fa4::from_u64(mix(draw, i as u64))
    }
    /// A FULL extension element — every coefficient drawn. A lifted base value (three zero coefficients) would let a
    /// wrong extension product, square or scalar product pass.
    fn ext_at(draw: u64, i: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|j| Fa4::from_u64(mix(draw.wrapping_add(0x1000 * (j as u64 + 1)), i as u64)))
    }
    fn run_program<G: Field + Algebra<Fa4>>(p: &RegProgram, bl: &[G]) -> Vec<G> {
        let mut regs = vec![G::ZERO; p.registers()];
        p.run(bl, &mut regs);
        (0..p.roots()).map(|j| p.root(j, &regs)).collect()
    }
    fn reference<G: Field + From<Fa4>>(t: &CompiledTape, bl: &[G]) -> Vec<G> {
        let mut out = Vec::new();
        t.eval_into_in_reference(bl, &mut out);
        out
    }
    fn perm_tape() -> (Vec<p3_air::symbolic::SymbolicExpression<Fa4>>, SymLeafLayout, CompiledTape, usize) {
        let base = crate::pow_pq_air::perm_symbolic_constraints();
        let ll = SymLeafLayout { w: crate::pow_pq_air::P2_COLS, preproc_w: 0, npub: 0 };
        let tape = CompiledTape::compile(&base, &ll);
        (base, SymLeafLayout { w: crate::pow_pq_air::P2_COLS, preproc_w: 0, npub: 0 }, tape, 2 * crate::pow_pq_air::P2_COLS + 3)
    }

    /// One hand-laid tape that takes EVERY arm of the compiler: constant-only subtrees of each op, a constant on either
    /// side of each binary op, a square, one slot read twice by one op, a value read long after its neighbours were
    /// handed on, and every kind of root (computed, constant-only, a bare constant, a bare load, a slot later ops also
    /// read, one slot named twice).
    fn every_arm_tape() -> CompiledTape {
        use TapeOp::{Add, Const, Load, Mul, Neg, Sub};
        let k = |v: u64| Const(Fa4::from_u64(v), Ea4::from_u64(v));
        let ops = vec![
            /*  0 */ Load(0),
            /*  1 */ Load(1),
            /*  2 */ k(7),
            /*  3 */ k(11),
            /*  4 */ Add(2, 3), // constant-only
            /*  5 */ Mul(4, 2), // constant-only
            /*  6 */ Neg(5), // constant-only
            /*  7 */ Sub(3, 2), // constant-only
            /*  8 */ Add(0, 1),
            /*  9 */ Add(8, 2), // value + constant
            /* 10 */ Add(3, 9), // constant + value
            /* 11 */ Sub(10, 0),
            /* 12 */ Sub(11, 6), // value − constant
            /* 13 */ Sub(7, 12), // constant − value
            /* 14 */ Mul(13, 13), // a square
            /* 15 */ Mul(14, 1),
            /* 16 */ Mul(15, 5), // value · constant
            /* 17 */ Mul(2, 16), // constant · value
            /* 18 */ Neg(17),
            /* 19 */ Add(18, 18), // one slot, read twice
            /* 20 */ Load(2),
            /* 21 */ Mul(20, 19),
            /* 22 */ Sub(21, 14), // reads slot 14 long after its neighbours were handed on
        ];
        CompiledTape::from_parts(ops, vec![22, 6, 2, 0, 14, 22, 19])
    }

    /// ⭐ THE DIFFERENTIAL GATE of the register program: on the REAL Poseidon2 AIR's tape (the one every gate of a
    /// block proof evaluates) and on a tape that takes every arm of the compiler, the program's values equal the slot
    /// interpreter's at every constraint, in the base field and on full extension elements, through the tape's own
    /// entry points too — and the extension values equal the recursive walker's, the reference the slot interpreter
    /// itself is held to.
    #[test]
    fn speed_r8_the_register_program_gives_the_reference_values_in_both_fields() {
        let (base, ll, perm, nl) = perm_tape();
        let hand = every_arm_tape();
        let draws = [1u64, 2, 3, 5, 8, 13, 21, 34];
        for (name, tape, width) in [("the permutation's tape", &perm, nl), ("the every-arm tape", &hand, 3)] {
            let (ops, roots) = tape.parts();
            let prog = RegProgram::compile(ops, roots);
            assert_eq!(prog.roots(), roots.len(), "{name}: one value per constraint");
            for draw in draws {
                let be: Vec<Fa4> = (0..width).map(|i| base_at(draw, i)).collect();
                let ee: Vec<Ea4> = (0..width).map(|i| ext_at(draw, i)).collect();
                let (want_b, want_e) = (reference(tape, &be), reference(tape, &ee));
                assert_eq!(run_program(&prog, &be), want_b, "⛔ {name}: the base-field values differ from the reference (draw {draw})");
                assert_eq!(run_program(&prog, &ee), want_e, "⛔ {name}: the extension values differ from the reference (draw {draw})");
                let (mut via_b, mut via_e, mut via_c) = (Vec::new(), Vec::new(), Vec::new());
                tape.eval_into_in(&be, &mut via_b);
                tape.eval_into_in(&ee, &mut via_e);
                tape.eval_into(&ee, &mut via_c);
                assert_eq!(via_b, want_b, "⛔ {name}: `eval_into_in` (base) differs from the reference (draw {draw})");
                assert_eq!(via_e, want_e, "⛔ {name}: `eval_into_in` (extension) differs from the reference (draw {draw})");
                assert_eq!(via_c, want_e, "⛔ {name}: `eval_into` differs from the reference (draw {draw})");
                let gamma = ext_at(draw, 0xFFFF);
                let horner = want_e.iter().fold(Ea4::ZERO, |acc, r| acc * gamma + *r);
                assert_eq!(tape.eval(&ee, gamma), horner, "⛔ {name}: `eval` differs from the reference's Horner fold (draw {draw})");
            }
        }
        for draw in [1u64, 2, 3] {
            let ee: Vec<Ea4> = (0..nl).map(|i| ext_at(draw, i)).collect();
            let mut got = Vec::new();
            perm.eval_into_in(&ee, &mut got);
            assert_eq!(got.len(), base.len());
            for (j, c) in base.iter().enumerate() {
                assert_eq!(got[j], eval_base_expr_lifted(c, &ee, &ll), "⛔ constraint {j}: the program differs from the recursive walker (draw {draw})");
            }
        }
        let (ops, roots) = perm.parts();
        let prog = RegProgram::compile(ops, roots);
        let (loads, muls, sqs, mulks, rest) = prog.census();
        eprintln!(
            "[r8] the permutation's tape: {} reference slots -> {} ops in {} registers ({loads} loads, {muls} products, {sqs} squares, \
             {mulks} constant products, {rest} other), {} constraints",
            ops.len(),
            prog.len(),
            prog.registers(),
            prog.roots()
        );
        // The module doc's arithmetic is counted from these: the rewrites must actually have fired on the real tape.
        assert!(mulks > 0 && sqs > 0, "the permutation's tape has constant products and squares; the program found {mulks} and {sqs}");
        assert!(prog.len() < ops.len(), "constants are folded out of the program ({} ops from {} slots)", prog.len(), ops.len());
    }

    /// ⛔ THE TAMPER HALF: a program one op away from the right one DISAGREES with the reference — in both fields, on
    /// every draw. A differential gate that a wrong program passes would be an assertion that cannot fail.
    #[test]
    fn speed_r8_a_program_one_op_from_the_right_one_disagrees_with_the_reference() {
        let (_base, _ll, perm, nl) = perm_tape();
        let (ops, roots) = perm.parts();
        let prog = RegProgram::compile(ops, roots);
        let (_, _, _, mulks, _) = prog.census();
        let mut tampered: Vec<(String, RegProgram)> = Vec::new();
        for nth in [0, mulks / 2, mulks - 1] {
            tampered.push((format!("constant product {nth} with its constant moved by one"), prog.with_a_constant_multiply_moved(nth).expect("the program has that constant product")));
        }
        for nth in [0usize, 5, 50] {
            tampered.push((format!("subtraction {nth} with its operands exchanged"), prog.with_a_subtraction_reversed(nth).expect("the program has that subtraction")));
        }
        for (what, bad) in &tampered {
            for draw in [1u64, 2, 3, 5] {
                let be: Vec<Fa4> = (0..nl).map(|i| base_at(draw, i)).collect();
                let ee: Vec<Ea4> = (0..nl).map(|i| ext_at(draw, i)).collect();
                assert_ne!(run_program(bad, &be), reference(&perm, &be), "⛔ {what}: the base-field values still equal the reference (draw {draw})");
                assert_ne!(run_program(bad, &ee), reference(&perm, &ee), "⛔ {what}: the extension values still equal the reference (draw {draw})");
            }
        }
        // the control: the untampered program on the same draws
        for draw in [1u64, 2, 3, 5] {
            let ee: Vec<Ea4> = (0..nl).map(|i| ext_at(draw, i)).collect();
            assert_eq!(run_program(&prog, &ee), reference(&perm, &ee));
        }
    }

    /// MEASUREMENT (the equality it also asserts can fail; the times are printed, never asserted): one evaluation of
    /// the permutation's constraints under each engine, in each field.
    #[test]
    fn speed_r8_one_evaluation_measured_under_both_engines() {
        let (_base, _ll, perm, nl) = perm_tape();
        const N: usize = 4000;
        let be: Vec<Fa4> = (0..nl).map(|i| base_at(9, i)).collect();
        let ee: Vec<Ea4> = (0..nl).map(|i| ext_at(9, i)).collect();
        fn timed<G: Field + Algebra<Fa4>>(perm: &CompiledTape, bl: &[G], reference_engine: bool) -> (G, u128) {
            let mut acc = G::ZERO;
            let mut out: Vec<G> = Vec::new();
            let t0 = std::time::Instant::now();
            for _ in 0..N {
                out.clear();
                if reference_engine {
                    perm.eval_into_in_reference(bl, &mut out);
                } else {
                    perm.eval_into_in(bl, &mut out);
                }
                acc += out[out.len() / 2];
            }
            (acc, t0.elapsed().as_nanos() / N as u128)
        }
        let (rb, rb_ns) = timed(&perm, &be, true);
        let (pb, pb_ns) = timed(&perm, &be, false);
        let (re, re_ns) = timed(&perm, &ee, true);
        let (pe, pe_ns) = timed(&perm, &ee, false);
        assert_eq!(rb, pb, "⛔ the engines disagree in the base field");
        assert_eq!(re, pe, "⛔ the engines disagree in the extension field");
        eprintln!(
            "[r8] one evaluation of the permutation's constraints — base field: slot interpreter {rb_ns} ns, register program {pb_ns} ns; \
             extension: slot interpreter {re_ns} ns, register program {pe_ns} ns"
        );
    }
}

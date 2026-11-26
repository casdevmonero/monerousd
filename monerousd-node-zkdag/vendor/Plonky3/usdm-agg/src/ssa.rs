// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE SSA ROW (docs/LEVEL-AGGREGATE-SPEC-20261115.md §13) — the tree's verifier machine, shaped so the tree CLOSES.
//!
//! MEASURED WHY (agg_w1): the register machine before it (isa.rs, 1,454 committed columns, one-hot selection over 52
//! registers) holds 2^15 rows a proof while one payment's three WHIR openings take 37,582 rows and a stacked-24 child
//! 35,683. BORROWED SHAPE: SP1's recursion machine — a straight-line program whose every value is written ONCE at an
//! address and read by multiplicity through a logUp memory bus — with the bus's sum proven by GKR (`gkr.rs`), so one
//! commitment carries it.
//!
//! THE ROW (one table, ROW-LOCAL — no register carries, so no next-row binding):
//! * `PERM` (cols `0..P2`): one Poseidon2-16 permutation under `COMMITTED_AIR_SEED` (the committed door's challenger,
//!   sponge hash and compression); input lanes `0..16`, output lanes `POUT..P2`.
//! * `U0 … U3` (`NUNIT` units of 16 cols each): an extension multiply-add `o = a·b + c` over four base lanes each
//!   (`a 0..4, b 4..8, c 8..12, o 12..16`). MEASURED why four (`[ssa-census]`, 2026-11-16): a leaf is 90,651 multiply-adds and 11,258
//!   permutations, a merge of two leaves 99,097 and 22,639 with 173,606 loaded lanes — at two units a row both fill
//!   2^16 (52,836 and 65,044 rows); at four they fit 2^15 inside the same 256-slot commitment (229 of 256 columns),
//!   which halves the commitment, the opening and the zerocheck of every proof in the tree.
//! * `WALK` (20 cols, `W0..`): a Merkle level's `cur ‖ sib` (16), `idx`, `var`, `idx'`, `var'`; a halving's `idx` /
//!   `idx'`; a Bits row's sample (in `idx`) and its low-`k` value (in `idx'`). MEASURED why its own block (pin t4,
//!   2026-11-16): borrowing `U0` / `U1` for these blocked two multiply-add units on every Merkle-level row and one on
//!   every Bits and halving row (~17k units in a merge of two merges), which pushed that merge 41 rows past 2^15; with
//!   its own 20 columns (249 of 256: the same commitment) no unit is ever blocked.
//! * `DCOL`: a Merkle level's or a halving's direction bit. A `Bits` row lays the sampled lane's 31 bits in
//!   `PERM[0..31]` and the canonical-check products in `PERM[31..34]`.
//!
//! MEMORY: a fixed map of `NSLOT` (96) TERM SLOTS to columns (`slot_col`): slots `0..16` the permutation's input lanes,
//! `16..32` its output lanes, `32 + 16u .. 48 + 16u` unit `u`. The bus's GKR runs over `BUS_SLOTS` (128) slots a row;
//! the 32 past `NSLOT` are the constant fraction `0 / 1`, which every verifier adds itself. Each slot on each row has a PREPROCESSED address and signed
//! multiplicity: a write carries `+reads`, a read `−1`, an idle slot `0`. The bus balances iff every read sees the value
//! written at its address: `Σ m / (ρ − (addr + β·v)) + Σ_public m / (ρ − (addr + β·v)) = 0`. Public addresses
//! (`ZERO`, `ONE`, the program's constants, the statement's values) are written by the VERIFIER. Order is irrelevant to
//! the bus, so the packer places operations freely.
//!
//! THE PROGRAM IS PREPROCESSED: the selectors, the Bits masks, every slot's address and multiplicity — `NFIXED` columns
//! the prover never commits. A verifier evaluates their multilinear extension itself (`Program::fixed_at`), natively at
//! the root, and a merge defers that claim upward. The gate (`ssa_residuals`) is UNIVERSAL: one AIR for every program.
//!
//! AI RESISTANT: (a) — a value is what the bus balance and the gate force; a program is what the verifier rebuilds.
//! SAFE AT SCALE: rows are a function of the program alone; nothing grows with height, nodes or notes.

use std::collections::HashMap;

use p3_field::extension::BinomiallyExtendable;
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use usdm_decider::air_zerocheck::{AirConstraint, Row};
use usdm_decider::hiding_decider::{Ea4, Fa4};

pub const SEED: u64 = usdm_decider::committed_air::COMMITTED_AIR_SEED;
pub const WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const P2: usize = usdm_decider::pow_pq_air::P2_COLS;
pub const POUT: usize = usdm_decider::pow_pq_air::PERM_OUT;
/// Multiply-add units a row.
pub const NUNIT: usize = 4;
/// Unit `u`'s first column.
#[must_use]
pub const fn unit(u: usize) -> usize {
    P2 + 16 * u
}
pub const U0: usize = unit(0);
/// The walk block: a Merkle level's, a halving's or a Bits row's own lanes (module doc).
pub const W0: usize = unit(NUNIT);
pub const W_CUR: usize = W0;
pub const W_SIB: usize = W0 + RATE;
pub const W_IDX: usize = W0 + 2 * RATE;
pub const W_VAR: usize = W_IDX + 1;
pub const W_IDX2: usize = W_IDX + 2;
pub const W_VAR2: usize = W_IDX + 3;
pub const DCOL: usize = W_IDX + 4;
/// Committed columns.
pub const NCOMMIT: usize = DCOL + 1;
/// Term slots a row: the permutation's 32 lanes, every unit's 16 and the walk's 20 (slot `t ≥ 16` is column
/// `POUT + t − 16`: the output lanes, the units and the walk are one run of columns).
pub const NSLOT: usize = 32 + 16 * NUNIT + 2 * RATE + 4;
/// The walk's first slot.
pub const SW: usize = 32 + 16 * NUNIT;
const _: () = assert!(P2 == POUT + 16 && W0 == POUT + SW - 16, "slots 16.. must be one contiguous run of columns");
/// The bus's slots a row as its GKR sees them (a power of two; the ones past `NSLOT` are the constant fraction 0 / 1).
pub const BUS_SLOTS: usize = NSLOT.next_power_of_two();
const _: () = assert!(NCOMMIT <= 256, "the row must stay inside a 256-slot commitment");
/// Bits a `Bits` row decomposes (a canonical KoalaBear element has 31).
pub const NBITS: usize = 31;
/// How many low bits a `Bits` row may assert zero or sum (KoalaBear: p ≡ 1 mod 2^24).
pub const NLOW: usize = 24;

// preprocessed (fixed) columns, offsets inside the fixed block
pub const S_PERM: usize = 0;
pub const S_COMP: usize = 1;
pub const S_HALVE: usize = 2;
/// Unit `u`'s selector is `S_ALU0 + u`.
pub const S_ALU0: usize = 3;
pub const S_BITS: usize = S_ALU0 + NUNIT;
pub const F_ZB: usize = S_BITS + 1;
pub const F_LW: usize = F_ZB + NLOW;
pub const F_ADDR: usize = F_LW + NLOW;
pub const F_MULT: usize = F_ADDR + NSLOT;
/// A Merkle level's generator power `g^(2^level)`: the walk carries `var' = var·(1 + d·(G − 1))` = `g^index`.
pub const F_G: usize = F_MULT + NSLOT;
pub const NFIXED: usize = F_G + 1;

/// The reserved public addresses.
pub const ZERO: Addr = 0;
pub const ONE: Addr = 1;

pub type Addr = u32;

/// The committed column a term slot reads or writes.
#[must_use]
pub const fn slot_col(t: usize) -> usize {
    if t < 16 {
        t
    } else {
        POUT + (t - 16)
    }
}

/// An extension value: four base-lane addresses, limb 0 first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ext(pub [Addr; 4]);

impl Ext {
    pub const ZERO: Ext = Ext([ZERO; 4]);
    pub const ONE: Ext = Ext([ONE, ZERO, ZERO, ZERO]);
}

/// Where an operation's result lane goes: a new value, or a CHECK that it equals one already written (the slot then
/// reads the address instead of writing it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dst {
    W(Addr),
    R(Addr),
    /// computed and discarded (an idle slot)
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AluOp {
    pub a: Ext,
    pub b: Ext,
    pub c: Ext,
    pub o: [Dst; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `out = perm(inp)`.
    Perm { inp: [Addr; WIDTH], out: [Dst; WIDTH] },
    /// One Merkle level: `inp = d ? (sib ‖ cur) : (cur ‖ sib)` with `idx = 2·idx' + d`, `out[..8] = perm(inp)[..8]`, and
    /// the query point carried: `var' = var·(1 + d·(g − 1))` (`g = g₀^(2^level)`, preprocessed).
    Comp { cur: [Addr; RATE], sib: [Addr; RATE], idx: Addr, idx2: Dst, out: [Dst; RATE], var: Addr, var2: Dst, g: Fa4 },
    /// `idx = 2·idx' + d`, `d` boolean (the walk's carry levels).
    Halve { idx: Addr, idx2: Dst },
    Alu(AluOp),
    /// Decompose `v` into its canonical bits; the low `zb` bits are zero; `low = v mod 2^k`.
    Bits { v: Addr, zb: u8, k: u8, low: Dst },
    /// Values the proof supplies (the stream), written at these addresses.
    Load { lanes: Vec<Addr> },
}

/// A program under construction: its operations, every address's value (computed natively as it builds; the prover's
/// values, or zeros when the program is built from the statement alone), and the public addresses.
#[derive(Clone, Debug)]
pub struct Builder {
    pub ops: Vec<Op>,
    pub vals: Vec<Fa4>,
    /// Public addresses and their values (`ZERO`, `ONE`, constants, the statement).
    pub public: Vec<(Addr, Fa4)>,
    /// The statement's addresses, in order (a subset of `public`: the values a parent supplies, not constants).
    pub statement: Vec<Addr>,
    konsts: HashMap<u32, Addr>,
    /// A read-check whose value disagreed while building with real values (the prover's own lie, caught early).
    pub mismatch: Option<String>,
    /// What the emitters are laying now (named in a mismatch: the address of a red).
    pub phase: String,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

fn lanes_of(e: Ea4) -> [Fa4; 4] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}

fn ext_of(l: [Fa4; 4]) -> Ea4 {
    Ea4::from_basis_coefficients_slice(&l).expect("four limbs")
}

/// `W` with `x⁴ = W` in the committed door's quartic extension.
#[must_use]
pub fn ext_w() -> Fa4 {
    <Fa4 as BinomiallyExtendable<4>>::W
}

/// ⭐ PERFECT-CHAIN B1 — ONE MERKLE LEVEL NATIVELY, exactly what [`Builder::comp`] constrains: the first [`RATE`] lanes of the
/// width-16 permutation over `left ‖ right`. One definition, so a tree built here and a path checked in circuit cannot drift.
#[must_use]
pub fn comp_native(left: &[Fa4; RATE], right: &[Fa4; RATE]) -> [Fa4; RATE] {
    let mut st = [Fa4::ZERO; WIDTH];
    st[..RATE].copy_from_slice(left);
    st[RATE..].copy_from_slice(right);
    perm16().permute_mut(&mut st);
    let mut out = [Fa4::ZERO; RATE];
    out.copy_from_slice(&st[..RATE]);
    out
}

fn perm16() -> &'static usdm_decider::hiding_decider::Perm16 {
    static P: std::sync::OnceLock<usdm_decider::hiding_decider::Perm16> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(SEED);
        usdm_decider::hiding_decider::Perm16::new_from_rng_128(&mut rng)
    })
}

impl Builder {
    #[must_use]
    pub fn new() -> Self {
        let mut b = Builder { ops: Vec::new(), vals: vec![Fa4::ZERO, Fa4::ONE], public: vec![(ZERO, Fa4::ZERO), (ONE, Fa4::ONE)], statement: Vec::new(), konsts: HashMap::new(), mismatch: None, phase: String::new() };
        b.konsts.insert(0, ZERO);
        b.konsts.insert(1, ONE);
        b
    }

    fn fresh(&mut self, v: Fa4) -> Addr {
        self.vals.push(v);
        (self.vals.len() - 1) as Addr
    }

    #[must_use]
    pub fn val(&self, a: Addr) -> Fa4 {
        self.vals[a as usize]
    }

    #[must_use]
    pub fn ext_val(&self, e: Ext) -> Ea4 {
        ext_of(e.0.map(|a| self.val(a)))
    }

    fn dst(&mut self, v: Fa4, check: Option<Addr>) -> (Addr, Dst) {
        match check {
            Some(a) => {
                if self.val(a) != v && self.mismatch.is_none() {
                    self.mismatch = Some(format!("[{}] a checked lane is {v:?}, its address {a} holds {:?}", self.phase, self.val(a)));
                }
                (a, Dst::R(a))
            }
            None => {
                let a = self.fresh(v);
                (a, Dst::W(a))
            }
        }
    }

    /// A public base constant (deduplicated; the verifier writes it).
    pub fn konst(&mut self, v: Fa4) -> Addr {
        let key = v.as_canonical_u64() as u32;
        if let Some(&a) = self.konsts.get(&key) {
            return a;
        }
        let a = self.fresh(v);
        self.public.push((a, v));
        self.konsts.insert(key, a);
        a
    }

    pub fn konst_ext(&mut self, v: Ea4) -> Ext {
        let l = lanes_of(v);
        Ext(l.map(|x| self.konst(x)))
    }

    /// Statement values: public addresses whose values the verifier supplies.
    pub fn public_vals(&mut self, vals: &[Fa4]) -> Vec<Addr> {
        vals.iter()
            .map(|&v| {
                let a = self.fresh(v);
                self.public.push((a, v));
                self.statement.push(a);
                a
            })
            .collect()
    }

    /// Values from the proof's stream (`vals` the prover's, or zeros).
    pub fn load(&mut self, vals: &[Fa4]) -> Vec<Addr> {
        let lanes: Vec<Addr> = vals.iter().map(|&v| self.fresh(v)).collect();
        self.ops.push(Op::Load { lanes: lanes.clone() });
        lanes
    }

    pub fn load_ext(&mut self, v: Ea4) -> Ext {
        let l = self.load(&lanes_of(v));
        Ext([l[0], l[1], l[2], l[3]])
    }

    /// `o = a·b + c`, written fresh (or each lane CHECKED against `check`).
    pub fn mul_add_into(&mut self, a: Ext, b: Ext, c: Ext, check: Option<Ext>) -> Ext {
        let v = self.ext_val(a) * self.ext_val(b) + self.ext_val(c);
        let l = lanes_of(v);
        let mut o = [Dst::Drop; 4];
        let mut out = [ZERO; 4];
        for i in 0..4 {
            let (ad, d) = self.dst(l[i], check.map(|e| e.0[i]));
            o[i] = d;
            out[i] = ad;
        }
        self.ops.push(Op::Alu(AluOp { a, b, c, o }));
        Ext(out)
    }

    pub fn mul_add(&mut self, a: Ext, b: Ext, c: Ext) -> Ext {
        self.mul_add_into(a, b, c, None)
    }
    pub fn mul(&mut self, a: Ext, b: Ext) -> Ext {
        self.mul_add(a, b, Ext::ZERO)
    }
    pub fn add(&mut self, a: Ext, c: Ext) -> Ext {
        self.mul_add(a, Ext::ONE, c)
    }
    /// `a − c` (a constant −1 product).
    pub fn sub(&mut self, a: Ext, c: Ext) -> Ext {
        let m1 = self.konst_ext(-Ea4::ONE);
        self.mul_add(c, m1, a)
    }
    /// `a·k + c` for a constant `k`.
    pub fn mul_k_add(&mut self, a: Ext, k: Ea4, c: Ext) -> Ext {
        let kk = self.konst_ext(k);
        self.mul_add(a, kk, c)
    }
    /// Assert `a·b + c == 0` (each lane read back from `ZERO`).
    pub fn assert_mul_add_zero(&mut self, a: Ext, b: Ext, c: Ext) {
        self.mul_add_into(a, b, c, Some(Ext::ZERO));
    }
    /// Assert `a == b`.
    pub fn assert_eq(&mut self, a: Ext, b: Ext) {
        let m1 = self.konst_ext(-Ea4::ONE);
        self.assert_mul_add_zero(b, m1, a);
    }

    /// `perm(inp)`, every output lane written fresh.
    pub fn perm(&mut self, inp: [Addr; WIDTH]) -> [Addr; WIDTH] {
        self.perm_check(inp, [None; WIDTH])
    }

    /// `perm(inp)`, an output lane CHECKED where `check` names it.
    pub fn perm_check(&mut self, inp: [Addr; WIDTH], check: [Option<Addr>; WIDTH]) -> [Addr; WIDTH] {
        let mut st: [Fa4; WIDTH] = inp.map(|a| self.val(a));
        perm16().permute_mut(&mut st);
        let mut out = [Dst::Drop; WIDTH];
        let mut addrs = [ZERO; WIDTH];
        for i in 0..WIDTH {
            let (a, d) = self.dst(st[i], check[i]);
            out[i] = d;
            addrs[i] = a;
        }
        self.ops.push(Op::Perm { inp, out });
        addrs
    }

    /// One Merkle level: the walk's current digest `cur`, the sibling `sib`, the remaining index `idx` (its low bit is
    /// the direction: 1 puts the current digest on the RIGHT), the query point so far `var` and this level's generator
    /// power `g`. Returns the parent digest, `idx >> 1` and `var·g^d`. With `root`, the parent is CHECKED against it.
    pub fn comp(&mut self, cur: [Addr; RATE], sib: [Addr; RATE], idx: Addr, var: Addr, g: Fa4, root: Option<[Addr; RATE]>) -> ([Addr; RATE], Addr, Addr) {
        let iv = self.val(idx).as_canonical_u64();
        let d = iv & 1;
        let mut st = [Fa4::ZERO; WIDTH];
        for l in 0..RATE {
            let (c, s) = (self.val(cur[l]), self.val(sib[l]));
            if d == 1 {
                st[l] = s;
                st[RATE + l] = c;
            } else {
                st[l] = c;
                st[RATE + l] = s;
            }
        }
        perm16().permute_mut(&mut st);
        let mut out = [Dst::Drop; RATE];
        let mut addrs = [ZERO; RATE];
        for l in 0..RATE {
            let (a, dd) = self.dst(st[l], root.map(|r| r[l]));
            out[l] = dd;
            addrs[l] = a;
        }
        let (i2, d2) = self.dst(Fa4::from_u64(iv >> 1), None);
        let vv = if d == 1 { self.val(var) * g } else { self.val(var) };
        let (v2, dv) = self.dst(vv, None);
        self.ops.push(Op::Comp { cur, sib, idx, idx2: d2, out, var, var2: dv, g });
        (addrs, i2, v2)
    }

    /// `idx >> 1` (a walk's carry level); with `last`, the result is CHECKED to be zero.
    pub fn halve(&mut self, idx: Addr, last: bool) -> Addr {
        let iv = self.val(idx).as_canonical_u64();
        let (a, d) = self.dst(Fa4::from_u64(iv >> 1), last.then_some(ZERO));
        self.ops.push(Op::Halve { idx, idx2: d });
        a
    }

    /// The canonical bits of `v`: the low `zb` asserted zero, and `v mod 2^k` (k ≤ 24) written (when `k > 0`).
    pub fn bits(&mut self, v: Addr, zb: u8, k: u8) -> Option<Addr> {
        assert!(zb as usize <= NLOW && k as usize <= NLOW, "a Bits row masks at most {NLOW} bits");
        let x = self.val(v).as_canonical_u64();
        if x & ((1u64 << zb) - 1) != 0 && self.mismatch.is_none() {
            self.mismatch = Some(format!("[{}] a proof-of-work sample has a low bit set ({x:#x}, {zb} bits)", self.phase));
        }
        let (low, d) = if k > 0 {
            let (a, d) = self.dst(Fa4::from_u64(x & ((1u64 << k) - 1)), None);
            (Some(a), d)
        } else {
            (None, Dst::Drop)
        };
        self.ops.push(Op::Bits { v, zb, k, low: d });
        low
    }
}

/// THE CHALLENGER, MIRRORED: `p3_challenger::DuplexChallenger<_, _, 16, 8>` (the committed door's `Chl`) over addresses.
/// `observe` clears the output and pushes; eight pending duplex; `sample` duplexes when anything is pending or nothing
/// is left, then pops the LAST output lane (challenger/src/duplex_challenger.rs). An extension challenge is four samples,
/// limb 0 first. The state starts at zero.
#[derive(Clone, Debug)]
pub struct Chal {
    pub state: [Addr; WIDTH],
    pending: Vec<Addr>,
    out: Vec<Addr>,
}

impl Default for Chal {
    fn default() -> Self {
        Self::new()
    }
}

impl Chal {
    #[must_use]
    pub fn new() -> Self {
        Chal { state: [ZERO; WIDTH], pending: Vec::new(), out: Vec::new() }
    }
    fn duplex(&mut self, b: &mut Builder) {
        let mut inp = self.state;
        for (i, &v) in self.pending.iter().enumerate() {
            inp[i] = v;
        }
        self.pending.clear();
        self.state = b.perm(inp);
        self.out = self.state[..RATE].to_vec();
    }
    pub fn observe(&mut self, b: &mut Builder, v: Addr) {
        self.out.clear();
        self.pending.push(v);
        if self.pending.len() == RATE {
            self.duplex(b);
        }
    }
    pub fn observe_all(&mut self, b: &mut Builder, vs: &[Addr]) {
        for &v in vs {
            self.observe(b, v);
        }
    }
    pub fn observe_ext(&mut self, b: &mut Builder, e: Ext) {
        self.observe_all(b, &e.0);
    }
    pub fn sample(&mut self, b: &mut Builder) -> Addr {
        if !self.pending.is_empty() || self.out.is_empty() {
            self.duplex(b);
        }
        self.out.pop().expect("a duplexing refills the output")
    }
    pub fn sample_ext(&mut self, b: &mut Builder) -> Ext {
        Ext(core::array::from_fn(|_| self.sample(b)))
    }
    /// `check_witness(bits, w)`: observe the witness, then the next sample's low `bits` are zero.
    pub fn check_witness(&mut self, b: &mut Builder, witness: Addr, bits: u8) {
        self.observe(b, witness);
        let s = self.sample(b);
        b.bits(s, bits, 0);
    }
    /// A sample drawn and not used (`sample_bits(0)`).
    pub fn sample_unused(&mut self, b: &mut Builder) {
        let _ = self.sample(b);
    }
    /// `draw_below(2^k)` for `k ≤ 24` (whir/src/pcs/utils.rs): four samples, `(f0 + f1 + f2 + f3) mod 2^k`; KoalaBear's
    /// `p ≡ 1 mod 2^24` makes the index the low `k` bits of the sum of each sample's low `k` bits. Returns the SUM (below
    /// 2^(k+2)); its walk takes the low `k` bits and two carry levels.
    pub fn draw_index_sum(&mut self, b: &mut Builder, k: u8) -> Addr {
        assert!(k as usize <= NLOW);
        let lows: Vec<Addr> = (0..4).map(|_| {
            let s = self.sample(b);
            b.bits(s, 0, k).expect("k > 0")
        }).collect();
        let e = |a: Addr| Ext([a, ZERO, ZERO, ZERO]);
        let s01 = b.add(e(lows[0]), e(lows[1]));
        let s012 = b.add(s01, e(lows[2]));
        let s = b.add(s012, e(lows[3]));
        s.0[0]
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// LAYOUT: the packer and the executor.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

/// One laid row: what it does and the address + multiplicity of each slot (0 = idle).
#[derive(Clone, Debug)]
pub struct RowPlan {
    perm: Option<usize>,  // op index of a Perm or Comp
    comp: bool,           // the permutation is a Merkle level (its walk lanes: cur ‖ sib, idx, var, idx', var')
    bits: Option<usize>,  // op index of a Bits
    halve: Option<usize>, // op index of a Halve
    alu: [Option<usize>; NUNIT],
    /// per slot: (address, +1 write / −1 read)
    slot: [Option<(Addr, i8)>; NSLOT],
}

impl Default for RowPlan {
    fn default() -> Self {
        RowPlan { perm: None, comp: false, bits: None, halve: None, alu: [None; NUNIT], slot: [None; NSLOT] }
    }
}

impl RowPlan {
    fn perm_block_free(&self) -> bool {
        self.perm.is_none() && self.bits.is_none()
    }
    /// Is unit `u` free (no multiply-add on it)?
    fn unit_free(&self, u: usize) -> bool {
        self.alu[u].is_none()
    }
    /// Is the walk block free (no Merkle level, halving or Bits row using it)?
    fn walk_free(&self) -> bool {
        !self.comp && self.bits.is_none() && self.halve.is_none()
    }
    /// Can a load write slot `t` here (its column read by no active law)?
    fn load_ok(&self, t: usize) -> bool {
        self.slot[t].is_none()
            && if t < 32 {
                self.perm_block_free()
            } else if t < SW {
                self.unit_free((t - 32) / 16)
            } else {
                self.walk_free()
            }
    }
}

/// A laid program: the trace columns the prover commits and the preprocessed columns every verifier rebuilds.
#[derive(Clone, Debug)]
pub struct Program {
    /// Rows laid (before the power-of-two pad).
    pub rows: usize,
    /// `T = 2^nvars` (NOP rows pad: every selector and multiplicity zero).
    pub nvars: usize,
    /// `fixed[c][row]`, `NFIXED` columns.
    pub fixed: Vec<Vec<Fa4>>,
    /// Public addresses, values and multiplicities (how many slots read each).
    pub public: Vec<(Addr, Fa4, u64)>,
    /// The statement's addresses, in order (`Builder::statement`).
    pub statement: Vec<Addr>,
    /// ⭐ A-F114 — a BLINDED program's placement ([`place_row`]): every laid row in the quarter whose first AND last row bits are 0,
    /// every other row free for randomness. `false`: every program the door has always laid.
    pub quarter: bool,
}

/// ⭐ A-F114 — WHERE LAID ROW `li` SITS. Plain: [`row_at`] (bit-reversed over the table). QUARTER (a blinded program, the
/// published spend wrapper): bit-reversed over `nvars − 2` bits, then shifted up one, so the row's position has its FIRST
/// bit 0 (the half the zerocheck binds first, `air_zerocheck` folds the high variable: its first round pairs every real row
/// with a random one) AND its LAST bit 0 (the GKR's bottom layer adds leaves `2j`, `2j + 1`: every bottom pair holds a random
/// leaf). READ why both (2026-11-22): the half-table blinding put randomness only on the last bit, which masked the GKR and
/// left the zerocheck's first n − 1 rounds summing real rows alone; the spend carrier's §BE-1 split masks the first bit only
/// because the light decider has no GKR.
#[must_use]
pub fn place_row(li: usize, nvars: usize, quarter: bool) -> usize {
    if quarter && nvars >= 2 {
        row_at(li, nvars - 2) << 1
    } else {
        row_at(li, nvars)
    }
}

/// The smallest trace the committed door proves (its folding floor).
pub const MIN_NVARS: usize = 4;

/// The first row at or after `*start` where `ok` holds (a new row when none does); `*start` moves to it — every row
/// before it fails `ok` for every op of this kind, and placing only consumes resources.
fn place<F: Fn(&RowPlan) -> bool>(rows: &mut Vec<RowPlan>, start: &mut usize, ok: F) -> usize {
    while *start < rows.len() && !ok(&rows[*start]) {
        *start += 1;
    }
    if *start == rows.len() {
        rows.push(RowPlan::default());
    }
    *start
}

fn dst_slot(d: Dst) -> Option<(Addr, i8)> {
    match d {
        Dst::W(a) => Some((a, 1)),
        Dst::R(a) => Some((a, -1)),
        Dst::Drop => None,
    }
}

/// Lay `b`'s operations into rows (a function of the operation list alone, never of values) and count every
/// address's reads. `Err` if a program reads an address nobody writes.
pub fn lay(b: &Builder) -> Result<(Vec<RowPlan>, Program), String> {
    lay_min(b, MIN_NVARS)
}

/// ⭐ A-F114 — `lay` at no fewer than `2^min_nvars` rows. A function of the operation list alone, like `lay`.
pub fn lay_at(b: &Builder, min_nvars: usize) -> Result<(Vec<RowPlan>, Program), String> {
    lay_min(b, min_nvars.max(MIN_NVARS))
}

/// ⭐ A-F114 — a BLINDED program's lay: at no fewer than `2^min_nvars` rows and at least four times its laid rows, every
/// laid row placed in the quarter [`place_row`] names. A function of the operation list alone, like `lay`.
pub fn lay_at_quarter(b: &Builder, min_nvars: usize) -> Result<(Vec<RowPlan>, Program), String> {
    lay_min_placed(b, min_nvars.max(MIN_NVARS), true)
}

/// The first address a padding public entry takes (above any builder's count, below the field's modulus).
pub const PAD_ADDR_BASE: u32 = 2_000_000_000;

/// ⭐ A-F114 — THE UNIFORM LAY of a universal program's child (`absence_ssa`): `lay`, at least `2^min_nvars` rows, with the
/// public list in CANONICAL order (the statement's entries first, in statement order, then the rest in builder order) and
/// padded to exactly `pub_len` entries with ones nothing reads (multiplicity zero, value zero, addresses from
/// [`PAD_ADDR_BASE`]). Prover and verifier both read `Program.public`, so the order is the program's own; a padded entry
/// adds a zero bus term and a zero observed value. `Err` if the program's own list is longer than `pub_len`.
pub fn lay_uniform(b: &Builder, min_nvars: usize, pub_len: usize) -> Result<(Vec<RowPlan>, Program), String> {
    let (rows, mut prog) = lay_min(b, min_nvars.max(MIN_NVARS))?;
    let mut out: Vec<(Addr, Fa4, u64)> = Vec::with_capacity(prog.public.len());
    for a in &prog.statement {
        let e = prog.public.iter().find(|p| p.0 == *a).ok_or("a statement address is not public")?;
        out.push(*e);
    }
    out.extend(prog.public.iter().filter(|p| !prog.statement.contains(&p.0)).copied());
    if out.len() > pub_len {
        return Err(format!("the program has {} public entries, more than the uniform {pub_len}", out.len()));
    }
    let mut i = 0u32;
    while out.len() < pub_len {
        out.push((PAD_ADDR_BASE + i, Fa4::ZERO, 0));
        i += 1;
    }
    prog.public = out;
    Ok((rows, prog))
}

fn lay_min(b: &Builder, min_nvars: usize) -> Result<(Vec<RowPlan>, Program), String> {
    lay_min_placed(b, min_nvars, false)
}

fn lay_min_placed(b: &Builder, min_nvars: usize, quarter: bool) -> Result<(Vec<RowPlan>, Program), String> {
    let mut rows: Vec<RowPlan> = Vec::new();
    // 1. permutations and Merkle levels: one a row, in order
    for (i, op) in b.ops.iter().enumerate() {
        match op {
            Op::Perm { inp, out } => {
                let mut r = RowPlan { perm: Some(i), ..Default::default() };
                for l in 0..WIDTH {
                    r.slot[l] = Some((inp[l], -1));
                    r.slot[16 + l] = dst_slot(out[l]);
                }
                rows.push(r);
            }
            Op::Comp { cur, sib, idx, idx2, out, var, var2, .. } => {
                let mut r = RowPlan { perm: Some(i), comp: true, ..Default::default() };
                for l in 0..RATE {
                    r.slot[SW + l] = Some((cur[l], -1));
                    r.slot[SW + RATE + l] = Some((sib[l], -1));
                    r.slot[16 + l] = dst_slot(out[l]);
                }
                r.slot[SW + 2 * RATE] = Some((*idx, -1));
                r.slot[SW + 2 * RATE + 1] = Some((*var, -1));
                r.slot[SW + 2 * RATE + 2] = dst_slot(*idx2);
                r.slot[SW + 2 * RATE + 3] = dst_slot(*var2);
                rows.push(r);
            }
            _ => {}
        }
    }
    // 2. Bits rows hold the permutation block and the walk's idx / idx' lanes
    let mut cursor = 0usize;
    for (i, op) in b.ops.iter().enumerate() {
        if let Op::Bits { v, low, .. } = op {
            let k = place(&mut rows, &mut cursor, |r| r.perm_block_free() && r.walk_free());
            rows[k].bits = Some(i);
            rows[k].slot[SW + 2 * RATE] = Some((*v, -1));
            rows[k].slot[SW + 2 * RATE + 2] = dst_slot(*low);
        }
    }
    // 3. halvings: DCOL and the walk's idx / idx' lanes on a row with no Merkle level and no Bits
    let mut cursor = 0usize;
    for (i, op) in b.ops.iter().enumerate() {
        if let Op::Halve { idx, idx2 } = op {
            let k = place(&mut rows, &mut cursor, RowPlan::walk_free);
            rows[k].halve = Some(i);
            rows[k].slot[SW + 2 * RATE] = Some((*idx, -1));
            rows[k].slot[SW + 2 * RATE + 2] = dst_slot(*idx2);
        }
    }
    // 4. ALU operations into free units
    let mut cursor = 0usize;
    for (i, op) in b.ops.iter().enumerate() {
        if let Op::Alu(a) = op {
            let k = place(&mut rows, &mut cursor, |r| (0..NUNIT).any(|u| r.unit_free(u)));
            let u = (0..NUNIT).find(|&u| rows[k].unit_free(u)).expect("placed on a row with a free unit");
            let base = 32 + 16 * u;
            rows[k].alu[u] = Some(i);
            for l in 0..4 {
                rows[k].slot[base + l] = Some((a.a.0[l], -1));
                rows[k].slot[base + 4 + l] = Some((a.b.0[l], -1));
                rows[k].slot[base + 8 + l] = Some((a.c.0[l], -1));
                rows[k].slot[base + 12 + l] = dst_slot(a.o[l]);
            }
        }
    }
    // 5. loads into free slots whose column no active law reads on that row
    let mut cursor = 0usize;
    for op in &b.ops {
        if let Op::Load { lanes } = op {
            for &a in lanes {
                loop {
                    if cursor == rows.len() {
                        rows.push(RowPlan::default());
                    }
                    if let Some(t) = (0..NSLOT).find(|&t| rows[cursor].load_ok(t)) {
                        rows[cursor].slot[t] = Some((a, 1));
                        break;
                    }
                    cursor += 1;
                }
            }
        }
    }
    // multiplicities: reads per address
    let mut reads: HashMap<Addr, u64> = HashMap::new();
    let mut written: HashMap<Addr, ()> = HashMap::new();
    for r in &rows {
        for (a, m) in r.slot.iter().flatten() {
            if *m < 0 {
                *reads.entry(*a).or_default() += 1;
            } else if written.insert(*a, ()).is_some() {
                return Err(format!("address {a} is written twice"));
            }
        }
    }
    let public_set: HashMap<Addr, Fa4> = b.public.iter().copied().collect();
    for a in reads.keys() {
        if !written.contains_key(a) && !public_set.contains_key(a) {
            return Err(format!("address {a} is read and never written"));
        }
    }
    for (a, _) in &b.public {
        if written.contains_key(a) {
            return Err(format!("public address {a} is also written by the trace"));
        }
    }
    let nrows = rows.len();
    let t = (if quarter { 4 * nrows } else { nrows }).max(1 << min_nvars).next_power_of_two();
    let nvars = t.trailing_zeros() as usize;
    let mut fixed = vec![vec![Fa4::ZERO; t]; NFIXED];
    for (li, r) in rows.iter().enumerate() {
        let ri = place_row(li, nvars, quarter);
        if let Some(i) = r.perm {
            fixed[S_PERM][ri] = Fa4::ONE;
            if let Op::Comp { g, .. } = b.ops[i] {
                fixed[S_COMP][ri] = Fa4::ONE;
                fixed[F_G][ri] = g;
            }
        }
        if r.halve.is_some() {
            fixed[S_HALVE][ri] = Fa4::ONE;
        }
        for u in 0..NUNIT {
            if r.alu[u].is_some() {
                fixed[S_ALU0 + u][ri] = Fa4::ONE;
            }
        }
        if let Some(i) = r.bits {
            fixed[S_BITS][ri] = Fa4::ONE;
            if let Op::Bits { zb, k, .. } = b.ops[i] {
                for l in 0..NLOW {
                    if l < zb as usize {
                        fixed[F_ZB + l][ri] = Fa4::ONE;
                    }
                    if l < k as usize {
                        fixed[F_LW + l][ri] = Fa4::from_u64(1u64 << l);
                    }
                }
            }
        }
        for tt in 0..NSLOT {
            if let Some((a, m)) = r.slot[tt] {
                fixed[F_ADDR + tt][ri] = Fa4::from_u64(u64::from(a));
                fixed[F_MULT + tt][ri] = if m < 0 { Fa4::NEG_ONE } else { Fa4::from_u64(reads.get(&a).copied().unwrap_or(0)) };
            }
        }
    }
    let public = b.public.iter().map(|&(a, v)| (a, v, reads.get(&a).copied().unwrap_or(0))).collect();
    Ok((rows, Program { rows: nrows, nvars, fixed, public, statement: b.statement.clone(), quarter }))
}

/// The committed columns of a laid program from the builder's values: `committed[c][row]`.
pub fn execute(b: &Builder, rows: &[RowPlan], prog: &Program) -> Result<Vec<Vec<Fa4>>, String> {
    if let Some(m) = &b.mismatch {
        return Err(format!("the program's own values disagree: {m}"));
    }
    let t = 1usize << prog.nvars;
    let mut cols = vec![vec![Fa4::ZERO; t]; NCOMMIT];
    let mut row = vec![Fa4::ZERO; NCOMMIT];
    for (ri, r) in rows.iter().enumerate() {
        row.iter_mut().for_each(|c| *c = Fa4::ZERO);
        // every slot's column holds its address's value (reads and writes alike)
        for tt in 0..NSLOT {
            if let Some((a, _)) = r.slot[tt] {
                row[slot_col(tt)] = b.val(a);
            }
        }
        if let Some(i) = r.perm {
            let inp: [Fa4; WIDTH] = match &b.ops[i] {
                Op::Perm { inp, .. } => inp.map(|a| b.val(a)),
                Op::Comp { cur, sib, idx, .. } => {
                    let d = b.val(*idx).as_canonical_u64() & 1;
                    row[DCOL] = Fa4::from_u64(d);
                    core::array::from_fn(|l| {
                        let (c, s) = (b.val(cur[l % RATE]), b.val(sib[l % RATE]));
                        match (l < RATE, d == 1) {
                            (true, false) | (false, true) => c,
                            _ => s,
                        }
                    })
                }
                _ => unreachable!("a permutation row holds a Perm or a Comp"),
            };
            let out = usdm_decider::pow_pq_air::lay_perm_row_seeded(&mut row, 0, SEED, inp);
            // the output lanes a slot names must be the permutation's
            for l in 0..WIDTH {
                if let Some((a, _)) = r.slot[16 + l] {
                    if b.val(a) != out[l] {
                        return Err(format!("row {ri}: output lane {l} is not the permutation's"));
                    }
                }
            }
        }
        // a multiply-add's output lanes are its arithmetic (a dropped lane still satisfies the law)
        for u in 0..NUNIT {
            let base = unit(u);
            if r.alu[u].is_some() {
                let e = |o: usize| ext_of(core::array::from_fn(|i| row[base + o + i]));
                let v = lanes_of(e(0) * e(4) + e(8));
                row[base + 12..base + 16].copy_from_slice(&v);
            }
        }
        if let Some(i) = r.halve {
            if let Op::Halve { idx, .. } = &b.ops[i] {
                row[DCOL] = Fa4::from_u64(b.val(*idx).as_canonical_u64() & 1);
            }
        }
        if let Some(i) = r.bits {
            if let Op::Bits { v, .. } = &b.ops[i] {
                let x = b.val(*v).as_canonical_u64();
                for l in 0..NBITS {
                    row[l] = Fa4::from_u64(x >> l & 1);
                }
                let bit = |l: usize| Fa4::from_u64(x >> l & 1);
                let p1 = bit(24) * bit(25) * bit(26);
                let p2 = p1 * bit(27) * bit(28);
                row[31] = p1;
                row[32] = p2;
                row[33] = p2 * bit(29) * bit(30);
            }
        }
        let at = place_row(ri, prog.nvars, prog.quarter);
        for (c, v) in row.iter().enumerate() {
            cols[c][at] = *v;
        }
    }
    Ok(cols)
}

/// The builder's operations by kind, for the prover's progress lines: `(permutations, Merkle levels, multiply-adds,
/// Bits rows, halvings, loaded lanes)`.
#[must_use]
pub fn census(b: &Builder) -> (usize, usize, usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0, 0, 0);
    for op in &b.ops {
        match op {
            Op::Perm { .. } => c.0 += 1,
            Op::Comp { .. } => c.1 += 1,
            Op::Alu(_) => c.2 += 1,
            Op::Bits { .. } => c.3 += 1,
            Op::Halve { .. } => c.4 += 1,
            Op::Load { lanes } => c.5 += lanes.len(),
        }
    }
    c
}

/// The table index of laid row `li` in a table of `2^nvars` rows: its `nvars`-bit reversal. The gate is row-local and
/// the bus is a sum over rows, so any one-to-one placement proves the same statement; this one keeps each row type's
/// share of the table the same in every zerocheck round. The zerocheck folds the top row bit first, so a folded entry
/// mixes the rows that agree on the low bits; laid rows `[0, k)` sit at indices whose low bits are the reversal of a
/// number below `k`, and after `j` folds the entries any of them reaches are `⌈k / 2^j⌉` of `2^(nvars − j)` — the
/// share `k / T` again (the permutation rows, laid first, are ~21 % of a leaf). In the natural order a pair of rows
/// half a table apart already mixes a permutation row with a non-permutation row in round 0, and by round 2 nearly
/// every entry carries the permutation's laws. Prover work only: the same rows, the same proof bytes for the same
/// placement, the verifier reads the placement from the program it lays itself.
#[must_use]
pub fn row_at(li: usize, nvars: usize) -> usize {
    if nvars == 0 {
        0
    } else {
        li.reverse_bits() >> (usize::BITS as usize - nvars)
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// THE GATE: universal, row-local, over (committed ‖ fixed).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

/// Every law of the row, each times its selector (module doc). `row` holds `NCOMMIT` committed values then `NFIXED`.
pub fn ssa_residuals<E: Algebra<Fa4> + Copy + 'static>(row: &Row<'_, E>) -> Vec<E> {
    ssa_residuals_with(row, &|_| true)
}

/// [`ssa_residuals`], skipping each selector group's laws (pushing their zeros, so every later law keeps its γ power)
/// where `live(selector)` says that group's selector is zero — exact, since every law of a group is its selector times
/// a residual (the permutation: `S_PERM`; the mux and halving pair: `S_COMP + S_HALVE`; the Merkle mux and the query
/// point: `S_COMP`; each multiply-add: its unit's selector; a Bits row: `S_BITS`). The prover's evaluation calls it with
/// "nonzero"; the tracer never skips. With rows laid at bit-reversed indices ([`row_at`]) a group's selector stays
/// exactly zero on all but its own share of the folded table in every zerocheck round, not only in round 0.
pub fn ssa_residuals_with<E: Algebra<Fa4> + Copy + 'static>(row: &Row<'_, E>, live: &dyn Fn(E) -> bool) -> Vec<E> {
    let c = |k: usize| row[k];
    let f = |k: usize| row[NCOMMIT + k];
    let one = E::ONE;
    let two = E::from(Fa4::TWO);
    let mut rs: Vec<E> = Vec::with_capacity(320);
    // the permutation
    let sp = f(S_PERM);
    if live(sp) {
        let mut pr: Vec<E> = Vec::new();
        usdm_decider::pow_pq_air::push_perm_residuals_seeded(SEED, row, 0, &mut pr);
        rs.extend(pr.into_iter().map(|r| sp * r));
    } else {
        rs.resize(perm_laws(), E::ZERO);
    }
    // a Merkle level and a halving: d boolean, idx = 2·idx' + d; the level's mux
    let (comp, halve) = (f(S_COMP), f(S_HALVE));
    let ch = comp + halve;
    let d = c(DCOL);
    if live(ch) {
        rs.push(ch * d * (one - d));
        rs.push(ch * (c(W_IDX) - two * c(W_IDX2) - d));
    } else {
        rs.resize(rs.len() + 2, E::ZERO);
    }
    if live(comp) {
        for l in 0..RATE {
            let (cur, sib) = (c(W_CUR + l), c(W_SIB + l));
            rs.push(comp * (c(l) - cur - d * (sib - cur)));
            rs.push(comp * (c(RATE + l) - sib - d * (cur - sib)));
        }
        // the query point: var' = var·(1 + d·(G − 1))
        rs.push(comp * (c(W_VAR2) - c(W_VAR) * (one + d * (f(F_G) - one))));
    } else {
        rs.resize(rs.len() + 2 * RATE + 1, E::ZERO);
    }
    // the two multiply-adds, in the quartic extension x⁴ = W
    let w = E::from(ext_w());
    for k in 0..NUNIT {
        let (u, sel) = (unit(k), f(S_ALU0 + k));
        if !live(sel) {
            rs.resize(rs.len() + 4, E::ZERO);
            continue;
        }
        let a: [E; 4] = core::array::from_fn(|i| c(u + i));
        let b: [E; 4] = core::array::from_fn(|i| c(u + 4 + i));
        for k in 0..4 {
            let mut acc = c(u + 8 + k);
            for i in 0..4 {
                let j = (k + 4 - i) % 4;
                let term = a[i] * b[j];
                acc += if i + j >= 4 { w * term } else { term };
            }
            rs.push(sel * (c(u + 12 + k) - acc));
        }
    }
    // a Bits row
    let sb = f(S_BITS);
    if !live(sb) {
        rs.resize(rs.len() + bits_laws(), E::ZERO);
        return rs;
    }
    let mut sum = E::ZERO;
    let mut low24 = E::ZERO;
    let mut pw = E::ONE;
    for l in 0..NBITS {
        let bl = c(l);
        rs.push(sb * bl * (one - bl));
        sum += pw * bl;
        if l < NLOW {
            low24 += pw * bl;
        }
        pw = pw * two;
    }
    rs.push(sb * (c(W_IDX) - sum));
    let (p1, p2, p3) = (c(31), c(32), c(33));
    rs.push(sb * (p1 - c(24) * c(25) * c(26)));
    rs.push(sb * (p2 - p1 * c(27) * c(28)));
    rs.push(sb * (p3 - p2 * c(29) * c(30)));
    rs.push(sb * p3 * low24);
    let mut low = E::ZERO;
    for l in 0..NLOW {
        rs.push(sb * f(F_ZB + l) * c(l));
        low += f(F_LW + l) * c(l);
    }
    rs.push(sb * (c(W_IDX2) - low));
    rs
}

/// A Bits row's law count: one boolean law a bit, the sum, three canonical products and their zero, a zero bit a low
/// lane, the low sum.
const fn bits_laws() -> usize {
    NBITS + 1 + 4 + NLOW + 1
}

/// `γ^0 … γ^(n−1)` for the gate's fold, computed once a γ on each prover thread (the zerocheck evaluates the gate at
/// every sample point of every round with the same γ).
fn gamma_powers(gamma: Ea4, n: usize) -> std::rc::Rc<Vec<Ea4>> {
    thread_local! {
        static POW: std::cell::RefCell<Option<(Ea4, std::rc::Rc<Vec<Ea4>>)>> = const { std::cell::RefCell::new(None) };
    }
    POW.with(|p| {
        let mut p = p.borrow_mut();
        if let Some((g, v)) = p.as_ref() {
            if *g == gamma && v.len() >= n {
                return v.clone();
            }
        }
        let mut v = Vec::with_capacity(n);
        let mut pw = Ea4::ONE;
        for _ in 0..n {
            v.push(pw);
            pw *= gamma;
        }
        let v = std::rc::Rc::new(v);
        *p = Some((gamma, v.clone()));
        v
    })
}

fn perm_laws() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| usdm_decider::pow_pq_air::perm_residual_count_seeded(SEED))
}

/// The row's gate as the committed door scores it: `Σ γ^i · residual_i`.
#[derive(Clone, Copy, Debug)]
pub struct SsaGate {
    pub gamma: Ea4,
}

impl AirConstraint for SsaGate {
    fn degree(&self, _nvars: usize) -> usize {
        // the permutation's S-box (3) times its selector; a Bits product of three bits times its selector
        usdm_decider::pow_pq_air::P2_CONSTRAINT_DEGREE + 1
    }
    fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let rs = ssa_residuals_with(local, &|s| s != Ea4::ZERO);
        let pw = gamma_powers(self.gamma, rs.len());
        // a skipped law is an exact zero: adding nothing for it is the same sum
        rs.iter().zip(pw.iter()).filter(|(r, _)| **r != Ea4::ZERO).map(|(r, p)| *p * *r).sum()
    }
    fn residuals(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        ssa_residuals(local)
    }
    /// The laws are generic over the row's field, so round 0 of the zerocheck evaluates them on base rows (the same
    /// value `eval` gives on the lifted row: byte-identical proofs).
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, _at: &dyn Fn(usize) -> Fa4, _x: &[Fa4]) -> Ea4 {
        let rs = ssa_residuals_with(local, &|s| s != Fa4::ZERO);
        let pw = gamma_powers(self.gamma, rs.len());
        rs.iter().zip(pw.iter()).filter(|(r, _)| **r != Fa4::ZERO).map(|(r, p)| *p * *r).sum()
    }
    fn is_row_local(&self) -> bool {
        true
    }
}

impl Program {
    /// The preprocessed columns' multilinear extensions at `x` (big-endian row bits), all `NFIXED` of them: the
    /// verifier's own evaluation of the program. `O(T · NFIXED)`.
    #[must_use]
    pub fn fixed_at(&self, x: &[Ea4]) -> Vec<Ea4> {
        let eq = crate::gkr::eq_table(x);
        self.fixed
            .iter()
            .map(|col| col.iter().zip(&eq).filter(|(v, _)| **v != Fa4::ZERO).map(|(v, e)| *e * *v).sum())
            .collect()
    }

    /// The public part of the bus: `Σ_public m / (ρ − (addr + β·v))`.
    #[must_use]
    pub fn public_sum(&self, rho: Ea4, beta: Ea4) -> Option<Ea4> {
        let mut s = Ea4::ZERO;
        for &(a, v, m) in &self.public {
            if m == 0 {
                continue;
            }
            let q = rho - Ea4::from(Fa4::from_u64(u64::from(a))) - beta * Ea4::from(v);
            s += Ea4::from(Fa4::from_u64(m)) * p3_field::Field::try_inverse(&q)?;
        }
        Some(s)
    }
}

/// The bus's leaves for a laid program: leaf `slot·T + row` is `(m, ρ − (addr + β·v))` with `v` the slot column's value,
/// and `(0, 1)` for the pad slots `NSLOT..BUS_SLOTS`.
#[must_use]
pub fn bus_leaves(prog: &Program, committed: &[Vec<Fa4>], rho: Ea4, beta: Ea4) -> (Vec<Ea4>, Vec<Ea4>) {
    let t = 1usize << prog.nvars;
    let mut p = Vec::with_capacity(BUS_SLOTS * t);
    let mut q = Vec::with_capacity(BUS_SLOTS * t);
    for s in 0..NSLOT {
        let (ac, mc, vc) = (&prog.fixed[F_ADDR + s], &prog.fixed[F_MULT + s], &committed[slot_col(s)]);
        for r in 0..t {
            p.push(Ea4::from(mc[r]));
            q.push(rho - Ea4::from(ac[r]) - beta * Ea4::from(vc[r]));
        }
    }
    // the pad slots: the fraction 0 / 1, a constant every verifier adds itself
    p.resize(BUS_SLOTS * t, Ea4::ZERO);
    q.resize(BUS_SLOTS * t, Ea4::ONE);
    (p, q)
}

/// The value each address holds as an extension element helper for emitters.
#[must_use]
pub fn ext_lanes(e: Ea4) -> [Fa4; 4] {
    lanes_of(e)
}

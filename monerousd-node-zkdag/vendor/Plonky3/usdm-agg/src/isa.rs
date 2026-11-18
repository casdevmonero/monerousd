// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE VERIFIER ROW — column map, instruction set and native executor (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12).
//!
//! One row = one Poseidon2-16 permutation under `COMMITTED_AIR_SEED`'s constants (the committed door's challenger, sponge
//! hash and 2-to-1 compression are all that one permutation: committed_air.rs `challenger`, `mmcs_with`), `NU` extension
//! multiply-add units, a permutation-evaluation CHIP, and a logUp unit, over a register file carried by next-row
//! constraints.
//!
//! REGISTERS (carried; the chained door's shifted columns are `SHIFT_LO..SHIFT_HI`, the stream `D` included):
//! * `S[16]`, `OS[8]` the inner proof's transcript sponge state after its last duplexing, and the rate lanes before it.
//! * `H[16]`  a leaf sponge (`PaddingFreeSponge`, overwrite absorb) or a Merkle walk's running digest.
//! * `B[31]`, `G`, `VAR` a sampled element's bits, a query's domain generator power and `g^index`.
//! * `BK[8]`  the stack's hash chain; `IO[16]` the statement sponge (its digest is the proof's public value).
//! * `X[NX]`  extension registers: `X[0..20]` the verifier program's; the gate evaluator's: `X[20]` = the inner γ,
//!   `X[21]` = ρ, `X[22]` = β, `X[23]` = the γ power a block starts at, `X[24..40]` = (1, γ, …, γ¹⁵), `X[40]` = γ¹⁶,
//!   `X[41..48]` = γ^(32·2^i) (see `X_FREE`).
//! * `TSUM`   a query index's running sum: WHIR draws an index as `(f0+f1+f2+f3) mod 2^k` over four pops
//!   (`whir/src/pcs/utils.rs` draw_below; p ≡ 1 mod 2^24), each `Bits` row with `ACC` adds its sample's low bits.
//! * `R0`, `R1` two latched roots (a round opens the PREVIOUS commitment while the new one is already absorbed).
//! * `FS[16]` this circuit's OWN Fiat–Shamir sponge (the logUp challenges are drawn from it, after what they test).
//! * `CS[16]` the chip's Poseidon2 state (extension lanes), `CACC` its accumulated `Σ γ^i · r_i`, `CGP` its γ power.
//! * `LACC`   the logUp sum: Σ multiplicity/(ρ − addr − β·v) over table terms, minus the same over reads; zero iff the
//!   reads are the table's values.
//! * `WL[80]` the last 80 base lanes the inner transcript absorbed (rows with `WSH`), so the chip and the table-side
//!   logUp terms read the inner proof's opened row as it streams, with no memory.
//!
//! PER ROW also: the permutation block `PERM`, the stream `D[16]`, three canonical-check cells, the chip's mid-row
//! partial-round state `CS2[16]`, and the instruction FLAGS (committed; checked at `r` against the program, `vm`).

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear as LL;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use usdm_decider::hiding_decider::{Ea4, Fa4};

pub const P2: usize = usdm_decider::pow_pq_air::P2_COLS;
pub const PERM_OUT: usize = usdm_decider::pow_pq_air::PERM_OUT;
pub const WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const NX: usize = 52;
pub const NU: usize = 2;
pub const ND: usize = 16;
pub const NWL: usize = 80;
pub const SEED: u64 = usdm_decider::committed_air::COMMITTED_AIR_SEED;
/// The stack compression's domain lane (lane 12): "AGGS".
pub const STACK_TAG: u64 = 0x4147_4753;
/// Register conventions (module doc).
/// `X[0..20]` are the verifier program's. The gate evaluator keeps `X[20]` = the inner γ, `X[21]` = ρ, `X[22]` = β from
/// its pass 1 / `emit_gamma` until its pass 2; `X[23..48]` are its own while the chip runs (from `emit_gamma` to the last
/// decorated row) and the verifier program's otherwise (pass 2 lays them again from `X[20]`); `X[48..52]` are the
/// verifier program's always.
pub const X_FREE: usize = 20;
pub const X_GAMMA: usize = 20;
pub const X_RHO: usize = 21;
pub const X_BETA: usize = 22;
pub const X_GP: usize = 23;
pub const X_GAMMA_POW: usize = 24;
pub const X_G16: usize = 40;
/// `X[41 + i]` = γ^(32·2^i), i < 7: any power below 2^12 in at most a dozen products.
pub const X_GBIN: usize = 41;
pub const NGBIN: usize = 7;

// ── registers ────────────────────────────────────────────────────────────────────────────────────────────────────
pub const PERM: usize = 0;
pub const S: usize = P2;
pub const OS: usize = S + WIDTH;
pub const H: usize = OS + RATE;
pub const NB: usize = 31;
pub const B: usize = H + WIDTH;
pub const G: usize = B + NB;
pub const VAR: usize = G + 1;
pub const BK: usize = VAR + 1;
pub const IO: usize = BK + RATE;
pub const X: usize = IO + WIDTH;
pub const FS: usize = X + 4 * NX;
pub const CS: usize = FS + WIDTH;
pub const CACC: usize = CS + 4 * WIDTH;
pub const CGP: usize = CACC + 4;
pub const LACC: usize = CGP + 4;
pub const WL: usize = LACC + 4;
pub const TSUM: usize = WL + NWL;
pub const R0: usize = TSUM + 1;
pub const R1: usize = R0 + RATE;
/// The second stack's hash chain (a `Push`/`Pop` with `bank2`): a round's query points wait here for the final weights
/// while its folds come off the first stack at the round's combine.
pub const BK2: usize = R1 + RATE;
pub const REG_LO: usize = S;
pub const REG_HI: usize = BK2 + RATE;
pub const D: usize = REG_HI;
pub const SHIFT_LO: usize = REG_LO;
pub const SHIFT_HI: usize = D + ND;
// ── per-row witness ──────────────────────────────────────────────────────────────────────────────────────────────
pub const AUX: usize = SHIFT_HI;
pub const CS2: usize = AUX + 3;
// ── flags ────────────────────────────────────────────────────────────────────────────────────────────────────────
pub const FLAGS: usize = CS2 + 4 * WIDTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The inner challenger's `duplexing()`: rate lanes `AM` overwritten from `D`, the rest kept; `S' = perm`, `OS' = S`.
    Duplex,
    /// A fresh inner challenger's first duplexing (state from zero).
    Reset,
    /// One Merkle level, direction `B[0]`, sibling `D[..8]`; `H' = perm(left ‖ right)`; `B` shifts; `VAR *= B0 ? G : 1`; `G = G²`.
    Comp,
    /// A leaf sponge's first chunk (state from zero) and later chunks (overwrite absorb).
    Leaf0,
    LeafN,
    /// Push `X[PX]`; pop (the executor lays `D[..8]` = the previous digest, `D[8..12]` = the value).
    Push,
    Pop,
    /// Decompose `S[BSEL]` into canonical bits `B'`, assert `ZB` bits zero; with `acc`, `TSUM += Σ_{l in AMK} 2^l·B'_l`.
    Bits,
    /// Start a query walk: `B'` = the bits of `TSUM` (below 2^26, so unique), `G' = KG`, `VAR' = 1`, `TSUM' = 0`.
    Draw,
    /// Absorb `D` lanes `AM` into the statement sponge.
    Io,
    /// This circuit's own sponge: fresh, and a duplexing (`AM` lanes overwritten).
    FsReset,
    FsDup,
}
pub const KINDS: [Kind; 12] = [
    Kind::Duplex,
    Kind::Reset,
    Kind::Comp,
    Kind::Leaf0,
    Kind::LeafN,
    Kind::Push,
    Kind::Pop,
    Kind::Bits,
    Kind::Io,
    Kind::FsReset,
    Kind::FsDup,
    Kind::Draw,
];

pub const NZB: usize = 24;
/// Window read anchors: a chip or table read ends `s` lanes before the window's end, `s < NOFF`.
pub const NOFF: usize = 8;
pub const F_KIND: usize = FLAGS;
pub const F_AM: usize = F_KIND + KINDS.len();
pub const F_BSEL: usize = F_AM + RATE;
pub const F_ZB: usize = F_BSEL + RATE;
pub const F_KG: usize = F_ZB + NZB;
pub const F_PX: usize = F_KG + 1;
pub const F_CLR: usize = F_PX + NX;
pub const F_STMT: usize = F_CLR + 1;
pub const F_TIE: usize = F_STMT + 1;
pub const F_WSH: usize = F_TIE + 1;
// chip
pub const F_CINIT: usize = F_WSH + 1;
pub const F_CFULL: usize = F_CINIT + 1;
pub const F_CPART: usize = F_CFULL + 1;
pub const F_CCLR: usize = F_CPART + 1;
pub const F_COFF: usize = F_CCLR + 1;
pub const F_RC: usize = F_COFF + NOFF;
// logUp
pub const F_LU: usize = F_RC + WIDTH;
pub const F_LUW: usize = F_LU + 2;
/// The logUp unit's own window anchor (a table pair and a chip round on one row may end at different lanes).
pub const F_LOFF: usize = F_LUW + 1;
pub const F_LA: usize = F_LOFF + NOFF;
pub const F_LM: usize = F_LA + 2;
pub const F_LCLR: usize = F_LM + 2;
/// `ACC` (a `Bits` row adds its masked low bits to `TSUM`) and the mask `AMK[24]`.
pub const F_ACC: usize = F_LCLR + 1;
pub const F_AMK: usize = F_ACC + 1;
/// `LATCH0/1` (`R_r' = D[..8]`, on the row that absorbs a root) and `HEQ0/1` (assert `H[..8] = R_r`).
pub const F_LATCH: usize = F_AMK + NZB;
pub const F_HEQ: usize = F_LATCH + 2;
pub const F_BANK2: usize = F_HEQ + 2;
/// `LATW0/1`: latch a root from the WINDOW (the eight lanes ending `loff` before its end) — a commitment that does not
/// begin a duplexing (it follows an odd-length bind) is read where the window holds it. Never on a row with `luw`.
pub const F_LATW: usize = F_BANK2 + 1;
pub const F_UNIT: usize = F_LATW + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcA {
    X(u8),
    One,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcB {
    X(u8),
    Dx(u8),
    Kc,
    One,
    /// The inner challenger's next extension challenge with `j` base pops already taken: limbs `S[7-j-l]`.
    Ch(u8),
    /// A challenge split across a duplexing: limbs `OS[m-1-l]` for `l < m`, then `S[7-(l-m)]`.
    Chs(u8),
    Var,
    /// This circuit's own challenge off `FS`, `j` pops taken: limbs `FS[7-j-l]`.
    Cf(u8),
    Cacc,
    Lacc,
    /// A base lane of the stream as an extension element: `(D[l], 0, 0, 0)`, `l < 8` (a base-field leaf's value).
    Db(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcC {
    X(u8),
    Dx(u8),
    Kc,
    One,
    Cacc,
    Lacc,
    Db(u8),
}
pub const NSA: usize = NX + 1;
pub const NSB: usize = NX + 4 + 1 + 1 + 5 + 3 + 1 + 5 + 2 + RATE;
pub const NSC: usize = NX + 4 + 1 + 1 + 2 + RATE;
pub const U_SA: usize = 0;
pub const U_SB: usize = U_SA + NSA;
pub const U_SC: usize = U_SB + NSB;
pub const U_WR: usize = U_SC + NSC;
pub const U_Z: usize = U_WR + NX;
pub const U_KC: usize = U_Z + 1;
pub const UNIT_W: usize = U_KC + 4;
pub const WIDTH_VM: usize = F_UNIT + NU * UNIT_W;

#[must_use]
pub fn sa_index(s: SrcA) -> usize {
    match s {
        SrcA::X(k) => k as usize,
        SrcA::One => NX,
    }
}
#[must_use]
pub fn sb_index(s: SrcB) -> usize {
    match s {
        SrcB::X(k) => k as usize,
        SrcB::Dx(q) => NX + q as usize,
        SrcB::Kc => NX + 4,
        SrcB::One => NX + 5,
        SrcB::Ch(j) => NX + 6 + j as usize,
        SrcB::Chs(m) => NX + 11 + (m as usize - 1),
        SrcB::Var => NX + 14,
        SrcB::Cf(j) => NX + 15 + j as usize,
        SrcB::Cacc => NX + 20,
        SrcB::Lacc => NX + 21,
        SrcB::Db(l) => NX + 22 + l as usize,
    }
}
#[must_use]
pub fn sc_index(s: SrcC) -> usize {
    match s {
        SrcC::X(k) => k as usize,
        SrcC::Dx(q) => NX + q as usize,
        SrcC::Kc => NX + 4,
        SrcC::One => NX + 5,
        SrcC::Cacc => NX + 6,
        SrcC::Lacc => NX + 7,
        SrcC::Db(l) => NX + 8 + l as usize,
    }
}

/// One multiply-add: `R = A·B + C`, written to `X[wr]` on the next row and/or asserted zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alu {
    pub a: SrcA,
    pub b: SrcB,
    pub c: Option<SrcC>,
    pub wr: Option<u8>,
    pub zero: bool,
    pub kc: Ea4,
}

/// The chip's operation on a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    /// `CS' = M_E(in)` with `in` the 16 values ending `off` lanes before the window's end; `CGP' = X[X_GP]`.
    Init,
    /// A full round: `post` = the 16 values ending `off` lanes before the end; round constants `rc`.
    Full,
    /// Two partial rounds: the two values ending `off` lanes before the end; constants `rc[0]`, `rc[1]`.
    Part,
}

/// One logUp term: `(ρ − addr − β·v)·w = mult`, `w` laid by the executor in `D[8+4i..]`. `v` is `D[4i..4i+4]`, or,
/// with `luw`, the window's value `i` of the pair ending `loff` lanes before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lu {
    pub addr: Fa4,
    pub mult: Fa4,
}

/// One row of a program: everything the flags say. The stream `D` is the prover's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instr {
    pub kind: Option<Kind>,
    pub am: u8,
    pub bsel: Option<u8>,
    pub zb: u32,
    pub kg: Fa4,
    pub px: Option<u8>,
    pub clr: bool,
    pub stmt: bool,
    pub tie: bool,
    pub wsh: bool,
    pub chip: Option<Chip>,
    pub cclr: bool,
    pub off: u8,
    pub rc: [Fa4; WIDTH],
    pub lu: [Option<Lu>; 2],
    pub luw: bool,
    pub loff: u8,
    /// a `Bits` row's draw accumulation: `Some(k)` adds the low `k` bits to `TSUM`
    pub acc: Option<u8>,
    /// latch the root absorbed on this row into `R0`/`R1`; assert `H[..8]` equals `R0`/`R1`
    pub latch: [bool; 2],
    pub heq: [bool; 2],
    /// a `Push`/`Pop` on the second stack
    pub bank2: bool,
    /// latch root bank `r` from the window at `loff`
    pub latw: [bool; 2],
    pub lclr: bool,
    pub alu: [Option<Alu>; NU],
}

impl Default for Instr {
    fn default() -> Self {
        Instr {
            kind: None,
            am: 0,
            bsel: None,
            zb: 0,
            kg: Fa4::ZERO,
            px: None,
            clr: false,
            stmt: false,
            tie: false,
            wsh: false,
            chip: None,
            cclr: false,
            off: 0,
            rc: [Fa4::ZERO; WIDTH],
            lu: [None; 2],
            luw: false,
            loff: 0,
            acc: None,
            latch: [false; 2],
            heq: [false; 2],
            bank2: false,
            latw: [false; 2],
            lclr: false,
            alu: [None; NU],
        }
    }
}

/// The committed flag cells of one instruction, `WIDTH_VM - FLAGS` of them.
#[must_use]
pub fn flag_cells(i: &Instr) -> Vec<Fa4> {
    let mut f = vec![Fa4::ZERO; WIDTH_VM - FLAGS];
    let at = |c: usize| c - FLAGS;
    let mut set = |c: usize, v: Fa4| f[at(c)] = v;
    if let Some(k) = i.kind {
        set(F_KIND + KINDS.iter().position(|&q| q == k).expect("a kind of KINDS"), Fa4::ONE);
    }
    for l in 0..RATE {
        if i.am >> l & 1 == 1 {
            set(F_AM + l, Fa4::ONE);
        }
    }
    if let Some(l) = i.bsel {
        set(F_BSEL + l as usize, Fa4::ONE);
    }
    for b in 0..NZB {
        if i.zb >> b & 1 == 1 {
            set(F_ZB + b, Fa4::ONE);
        }
    }
    set(F_KG, i.kg);
    if let Some(k) = i.px {
        set(F_PX + k as usize, Fa4::ONE);
    }
    for (c, on) in [(F_CLR, i.clr), (F_STMT, i.stmt), (F_TIE, i.tie), (F_WSH, i.wsh), (F_CCLR, i.cclr), (F_LUW, i.luw), (F_LCLR, i.lclr), (F_BANK2, i.bank2)] {
        if on {
            set(c, Fa4::ONE);
        }
    }
    if let Some(c) = i.chip {
        set(match c { Chip::Init => F_CINIT, Chip::Full => F_CFULL, Chip::Part => F_CPART }, Fa4::ONE);
    }
    if i.chip.is_some() {
        set(F_COFF + i.off as usize, Fa4::ONE);
    }
    if i.luw {
        set(F_LOFF + i.loff as usize, Fa4::ONE);
    }
    for l in 0..WIDTH {
        set(F_RC + l, i.rc[l]);
    }
    if let Some(k) = i.acc {
        set(F_ACC, Fa4::ONE);
        for l in 0..(k as usize).min(NZB) {
            set(F_AMK + l, Fa4::ONE);
        }
    }
    for r in 0..2 {
        if i.latch[r] {
            set(F_LATCH + r, Fa4::ONE);
        }
        if i.heq[r] {
            set(F_HEQ + r, Fa4::ONE);
        }
        if i.latw[r] {
            set(F_LATW + r, Fa4::ONE);
        }
    }
    if i.latw.iter().any(|&b| b) && !i.luw {
        set(F_LOFF + i.loff as usize, Fa4::ONE);
    }
    for (t, lu) in i.lu.iter().enumerate() {
        if let Some(lu) = lu {
            set(F_LU + t, Fa4::ONE);
            set(F_LA + t, lu.addr);
            set(F_LM + t, lu.mult);
        }
    }
    for (u, a) in i.alu.iter().enumerate() {
        let Some(a) = a else { continue };
        let base = F_UNIT + u * UNIT_W;
        set(base + U_SA + sa_index(a.a), Fa4::ONE);
        set(base + U_SB + sb_index(a.b), Fa4::ONE);
        if let Some(c) = a.c {
            set(base + U_SC + sc_index(c), Fa4::ONE);
        }
        if let Some(w) = a.wr {
            set(base + U_WR + w as usize, Fa4::ONE);
        }
        if a.zero {
            set(base + U_Z, Fa4::ONE);
        }
        let kc = a.kc.as_basis_coefficients_slice();
        for t in 0..4 {
            set(base + U_KC + t, kc[t]);
        }
    }
    f
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecError {
    pub row: usize,
    pub why: &'static str,
}

#[must_use]
pub fn ea(l: &[Fa4]) -> Ea4 {
    Ea4::from_basis_coefficients_slice(l).expect("four limbs")
}

/// The window's 16 values ending `off` lanes before its end (a full round's group).
#[must_use]
pub fn win16(wl: &[Fa4], off: usize) -> [Ea4; WIDTH] {
    let start = NWL - 64 - off;
    core::array::from_fn(|l| ea(&wl[start + 4 * l..start + 4 * l + 4]))
}
/// The window's two values ending `off` lanes before its end (a partial pair, or a table pair).
#[must_use]
pub fn win2(wl: &[Fa4], off: usize) -> [Ea4; 2] {
    let start = NWL - 8 - off;
    [ea(&wl[start..start + 4]), ea(&wl[start + 4..start + 8])]
}

/// The executor's registers.
#[derive(Clone, Debug)]
pub struct Regs {
    pub s: [Fa4; WIDTH],
    pub os: [Fa4; RATE],
    pub h: [Fa4; WIDTH],
    pub b: [Fa4; NB],
    pub g: Fa4,
    pub var: Fa4,
    pub bk: [Fa4; RATE],
    pub io: [Fa4; WIDTH],
    pub x: [Ea4; NX],
    pub fs: [Fa4; WIDTH],
    pub cs: [Ea4; WIDTH],
    pub cacc: Ea4,
    pub cgp: Ea4,
    pub lacc: Ea4,
    pub wl: [Fa4; NWL],
    pub tsum: Fa4,
    pub r0: [Fa4; RATE],
    pub r1: [Fa4; RATE],
    pub bk2: [Fa4; RATE],
    pub written: [bool; NX],
    /// Executor-only: the stack's (previous digest, value) entries, so a pop's witness is laid, never supplied.
    pub stack: Vec<([Fa4; RATE], Ea4)>,
    pub stack2: Vec<([Fa4; RATE], Ea4)>,
}

impl Default for Regs {
    fn default() -> Self {
        Regs {
            s: [Fa4::ZERO; WIDTH],
            os: [Fa4::ZERO; RATE],
            h: [Fa4::ZERO; WIDTH],
            b: [Fa4::ZERO; NB],
            g: Fa4::ZERO,
            var: Fa4::ZERO,
            bk: [Fa4::ZERO; RATE],
            io: [Fa4::ZERO; WIDTH],
            x: [Ea4::ZERO; NX],
            fs: [Fa4::ZERO; WIDTH],
            cs: [Ea4::ZERO; WIDTH],
            cacc: Ea4::ZERO,
            cgp: Ea4::ZERO,
            lacc: Ea4::ZERO,
            wl: [Fa4::ZERO; NWL],
            tsum: Fa4::ZERO,
            r0: [Fa4::ZERO; RATE],
            r1: [Fa4::ZERO; RATE],
            bk2: [Fa4::ZERO; RATE],
            written: [false; NX],
            stack: Vec::new(),
            stack2: Vec::new(),
        }
    }
}

fn lanes_ch(src: &[Fa4], j: usize) -> Ea4 {
    ea(&core::array::from_fn::<Fa4, 4, _>(|l| src[7 - j - l]))
}

fn src_b(r: &Regs, d: &[Fa4; ND], s: SrcB, kc: Ea4) -> Ea4 {
    match s {
        SrcB::X(k) => r.x[k as usize],
        SrcB::Dx(q) => ea(&d[4 * q as usize..4 * q as usize + 4]),
        SrcB::Kc => kc,
        SrcB::One => Ea4::ONE,
        SrcB::Ch(j) => lanes_ch(&r.s, j as usize),
        SrcB::Chs(m) => {
            let m = m as usize;
            ea(&core::array::from_fn::<Fa4, 4, _>(|l| if l < m { r.os[m - 1 - l] } else { r.s[7 - (l - m)] }))
        }
        SrcB::Var => Ea4::from(r.var),
        SrcB::Cf(j) => lanes_ch(&r.fs, j as usize),
        SrcB::Cacc => r.cacc,
        SrcB::Lacc => r.lacc,
        SrcB::Db(l) => Ea4::from(d[l as usize]),
    }
}

fn src_c(r: &Regs, d: &[Fa4; ND], s: Option<SrcC>, kc: Ea4) -> Ea4 {
    match s {
        None => Ea4::ZERO,
        Some(SrcC::X(k)) => r.x[k as usize],
        Some(SrcC::Dx(q)) => ea(&d[4 * q as usize..4 * q as usize + 4]),
        Some(SrcC::Kc) => kc,
        Some(SrcC::One) => Ea4::ONE,
        Some(SrcC::Cacc) => r.cacc,
        Some(SrcC::Lacc) => r.lacc,
        Some(SrcC::Db(l)) => Ea4::from(d[l as usize]),
    }
}

fn perm_input(k: Kind, r: &Regs, i: &Instr, d: &[Fa4; ND]) -> [Fa4; WIDTH] {
    let am = |l: usize| i.am >> l & 1 == 1;
    let mut p = [Fa4::ZERO; WIDTH];
    let overwrite = |base: &[Fa4; WIDTH], p: &mut [Fa4; WIDTH]| {
        for l in 0..WIDTH {
            p[l] = if l < RATE && am(l) { d[l] } else { base[l] };
        }
    };
    match k {
        Kind::Duplex => overwrite(&r.s, &mut p),
        Kind::LeafN => overwrite(&r.h, &mut p),
        Kind::Io => overwrite(&r.io, &mut p),
        Kind::FsDup => overwrite(&r.fs, &mut p),
        Kind::Reset | Kind::Leaf0 | Kind::FsReset => overwrite(&[Fa4::ZERO; WIDTH], &mut p),
        Kind::Comp => {
            let right = r.b[0] == Fa4::ONE;
            for l in 0..RATE {
                p[l] = if right { d[l] } else { r.h[l] };
                p[RATE + l] = if right { r.h[l] } else { d[l] };
            }
        }
        Kind::Push => {
            let v = i.px.map_or(Ea4::ZERO, |k| r.x[k as usize]);
            p[..RATE].copy_from_slice(if i.bank2 { &r.bk2 } else { &r.bk });
            p[RATE..RATE + 4].copy_from_slice(v.as_basis_coefficients_slice());
            p[RATE + 4] = Fa4::from_u64(STACK_TAG);
        }
        Kind::Pop => {
            p[..12].copy_from_slice(&d[..12]);
            p[RATE + 4] = Fa4::from_u64(STACK_TAG);
        }
        Kind::Bits | Kind::Draw => {}
    }
    p
}

/// The chip's step, natively (the constraint states the same, `vm::VmGate`): `(CS', CACC', CGP', CS2)`.
#[must_use]
pub fn chip_step(c: Chip, i: &Instr, r: &Regs) -> ([Ea4; WIDTH], Ea4, Ea4, [Ea4; WIDTH]) {
    let rc: [Ea4; WIDTH] = core::array::from_fn(|l| Ea4::from(i.rc[l]));
    let gpow = |k: usize| r.x[X_GAMMA_POW + k];
    match c {
        Chip::Init => {
            let mut st = win16(&r.wl, i.off as usize);
            LL::external_linear_layer(&mut st);
            (st, r.cacc, r.x[X_GP], [Ea4::ZERO; WIDTH])
        }
        Chip::Full => {
            let post = win16(&r.wl, i.off as usize);
            let mut st: [Ea4; WIDTH] = core::array::from_fn(|l| {
                let t = r.cs[l] + rc[l];
                t * t * t
            });
            LL::external_linear_layer(&mut st);
            // the AIR's residual is `assert_eq(state, post)` = state − post (poseidon2-air/src/air.rs eval_full_round)
            let dot = (0..WIDTH).fold(Ea4::ZERO, |acc, l| acc + gpow(l) * (st[l] - post[l]));
            (post, r.cacc + r.cgp * dot, r.cgp * r.x[X_G16], [Ea4::ZERO; WIDTH])
        }
        Chip::Part => {
            let [v1, v2] = win2(&r.wl, i.off as usize);
            let t1 = r.cs[0] + rc[0];
            let r1 = t1 * t1 * t1 - v1; // assert_eq(state[0], post_sbox) = state[0] − post_sbox (eval_partial_round)
            let mut s2 = r.cs;
            s2[0] = v1;
            LL::internal_linear_layer(&mut s2);
            let t2 = s2[0] + rc[1];
            let r2 = t2 * t2 * t2 - v2;
            let mut s3 = s2;
            s3[0] = v2;
            LL::internal_linear_layer(&mut s3);
            (s3, r.cacc + r.cgp * r1 + r.cgp * gpow(1) * r2, r.cgp * gpow(2), s2)
        }
    }
}

impl Regs {
    /// The register VALUES (what the trace holds), for the wrap's fixpoint.
    fn same_values(&self, o: &Regs) -> bool {
        self.s == o.s && self.os == o.os && self.h == o.h && self.b == o.b && self.g == o.g && self.var == o.var && self.bk == o.bk
            && self.io == o.io && self.x == o.x && self.fs == o.fs && self.cs == o.cs && self.cacc == o.cacc && self.cgp == o.cgp
            && self.lacc == o.lacc && self.wl == o.wl && self.tsum == o.tsum && self.r0 == o.r0 && self.r1 == o.r1 && self.bk2 == o.bk2
    }
    fn values_only(&self) -> Regs {
        Regs { written: [false; NX], stack: Vec::new(), stack2: Vec::new(), ..self.clone() }
    }
}

/// Run `prog` on the stream `d`: the trace's columns (`T = (rows + 1).max(min).next_power_of_two()`, NOP rows pad), the
/// statement digest the `STMT` row fixed, or the first row that cannot run. The executor LAYS the derived witness lanes
/// (a pop's previous digest and value, a logUp term's inverse) and checks every assertion the constraint makes.
///
/// THE WRAP. The constraint has no row selector, so the last row (a NOP: everything holds) carries into row 0: row 0's
/// registers ARE the final ones. A program writes every register before it reads it (the executor refuses a read of an
/// unwritten extension register; every sponge starts with its reset, the chip with `Init`/`cclr`, the logUp sum with
/// `lclr`), so row 0's registers are free and the executor lays them at the final values, iterating to that fixpoint.
pub fn execute(prog: &[Instr], d: &[[Fa4; ND]], min_rows: usize) -> Result<(Vec<Vec<Fa4>>, [Fa4; RATE]), ExecError> {
    let r = execute_settled(prog, d, min_rows);
    if let Err(e) = &r {
        if std::env::var("AGG_TRACE").is_ok() {
            // a failing row, its neighbours and what each did: the address of a red
            for k in e.row.saturating_sub(3)..(e.row + 2).min(prog.len()) {
                eprintln!("[agg-trace] row {k}{}: {:?}", if k == e.row { " ⛔" } else { "" }, prog[k]);
            }
            eprintln!("[agg-trace] row {}: {}", e.row, e.why);
        }
    }
    r
}

fn execute_settled(prog: &[Instr], d: &[[Fa4; ND]], min_rows: usize) -> Result<(Vec<Vec<Fa4>>, [Fa4; RATE]), ExecError> {
    let mut init = Regs::default();
    // the window WL shifts 8 lanes a WSH row and nothing clears it, so a program with k < NWL/8 such rows reaches the
    // wrap's fixpoint only after ⌈NWL/(8k)⌉ passes (lane aggc's region pin, 2026-11-15: two rows needed five)
    for _ in 0..(NWL / RATE + 2) {
        let (cols, stmt, fin) = execute_from(prog, d, min_rows, init.clone())?;
        if fin.same_values(&init) {
            return Ok((cols, stmt));
        }
        init = fin.values_only();
    }
    Err(ExecError { row: 0, why: "row 0's registers do not settle at the final ones (a register read before it is written?)" })
}

fn execute_from(prog: &[Instr], d: &[[Fa4; ND]], min_rows: usize, init: Regs) -> Result<(Vec<Vec<Fa4>>, [Fa4; RATE], Regs), ExecError> {
    if d.len() != prog.len() {
        return Err(ExecError { row: 0, why: "the stream is not one word a row" });
    }
    if !prog.first().is_some_and(|i| i.clr) {
        return Err(ExecError { row: 0, why: "a program starts by clearing its stack and statement sponge" });
    }
    if prog.iter().filter(|i| i.stmt).count() != 1 || !prog.last().is_some_and(|i| i.stmt) {
        return Err(ExecError { row: prog.len(), why: "a program states its digest exactly once, on its last row" });
    }
    let mut stmt = [Fa4::ZERO; RATE];
    let t = (prog.len() + 1).max(min_rows).next_power_of_two();
    let mut cols = vec![vec![Fa4::ZERO; t]; WIDTH_VM];
    let mut r = init;
    let nop = Instr::default();
    let mut row_buf = vec![Fa4::ZERO; WIDTH_VM];
    let mut laid: Vec<[Fa4; ND]> = d.to_vec();
    for row in 0..t {
        let i = if row < prog.len() { &prog[row] } else { &nop };
        let mut dw = if row < prog.len() { laid[row] } else { [Fa4::ZERO; ND] };
        // derived witness lanes
        if i.kind == Some(Kind::Pop) {
            let st = if i.bank2 { &r.stack2 } else { &r.stack };
            let (prev, v) = st.last().cloned().ok_or(ExecError { row, why: "a pop of an empty stack" })?;
            dw[..RATE].copy_from_slice(&prev);
            dw[RATE..RATE + 4].copy_from_slice(v.as_basis_coefficients_slice());
        }
        if i.lu.iter().any(Option::is_some) {
            let (rho, beta) = (r.x[X_RHO], r.x[X_BETA]);
            for (q, lu) in i.lu.iter().enumerate() {
                let Some(lu) = lu else { continue };
                let v = if i.luw { win2(&r.wl, i.loff as usize)[q] } else { ea(&dw[4 * q..4 * q + 4]) };
                let den = rho - Ea4::from(lu.addr) - beta * v;
                let inv = den.try_inverse().ok_or(ExecError { row, why: "a logUp denominator is zero" })?;
                let w = inv * Ea4::from(lu.mult);
                dw[8 + 4 * q..12 + 4 * q].copy_from_slice(w.as_basis_coefficients_slice());
            }
        }
        if row < prog.len() {
            laid[row] = dw;
        }
        if i.tie && (row + 1 >= prog.len() || laid[row + 1][..RATE] != dw[..RATE]) {
            return Err(ExecError { row, why: "a tied row's next stream differs" });
        }
        row_buf.iter_mut().for_each(|c| *c = Fa4::ZERO);
        row_buf[S..S + WIDTH].copy_from_slice(&r.s);
        row_buf[OS..OS + RATE].copy_from_slice(&r.os);
        row_buf[H..H + WIDTH].copy_from_slice(&r.h);
        row_buf[B..B + NB].copy_from_slice(&r.b);
        row_buf[G] = r.g;
        row_buf[VAR] = r.var;
        row_buf[BK..BK + RATE].copy_from_slice(&r.bk);
        row_buf[IO..IO + WIDTH].copy_from_slice(&r.io);
        for k in 0..NX {
            row_buf[X + 4 * k..X + 4 * k + 4].copy_from_slice(r.x[k].as_basis_coefficients_slice());
        }
        row_buf[FS..FS + WIDTH].copy_from_slice(&r.fs);
        for l in 0..WIDTH {
            row_buf[CS + 4 * l..CS + 4 * l + 4].copy_from_slice(r.cs[l].as_basis_coefficients_slice());
        }
        row_buf[CACC..CACC + 4].copy_from_slice(r.cacc.as_basis_coefficients_slice());
        row_buf[CGP..CGP + 4].copy_from_slice(r.cgp.as_basis_coefficients_slice());
        row_buf[LACC..LACC + 4].copy_from_slice(r.lacc.as_basis_coefficients_slice());
        row_buf[WL..WL + NWL].copy_from_slice(&r.wl);
        row_buf[TSUM] = r.tsum;
        row_buf[R0..R0 + RATE].copy_from_slice(&r.r0);
        row_buf[R1..R1 + RATE].copy_from_slice(&r.r1);
        row_buf[BK2..BK2 + RATE].copy_from_slice(&r.bk2);
        row_buf[D..D + ND].copy_from_slice(&dw);
        let fl = flag_cells(i);
        row_buf[FLAGS..].copy_from_slice(&fl);
        let mut next = r.clone();
        let pin = i.kind.map_or([Fa4::ZERO; WIDTH], |k| perm_input(k, &r, i, &dw));
        let pout = usdm_decider::pow_pq_air::lay_perm_row_seeded(&mut row_buf, PERM, SEED, pin);
        match i.kind {
            Some(Kind::Duplex | Kind::Reset) => {
                next.os.copy_from_slice(&r.s[..RATE]);
                next.s = pout;
            }
            Some(Kind::Comp) => {
                let bit = r.b[0];
                next.h = pout;
                for l in 0..NB - 1 {
                    next.b[l] = r.b[l + 1];
                }
                next.b[NB - 1] = Fa4::ZERO;
                next.var = r.var * (Fa4::ONE + bit * (r.g - Fa4::ONE));
                next.g = r.g * r.g;
            }
            Some(Kind::Leaf0 | Kind::LeafN) => next.h = pout,
            Some(Kind::Push) => {
                let k = i.px.ok_or(ExecError { row, why: "a push names no register" })? as usize;
                if !r.written[k] {
                    return Err(ExecError { row, why: "a push reads an unwritten register" });
                }
                if i.bank2 {
                    next.stack2.push((r.bk2, r.x[k]));
                    next.bk2.copy_from_slice(&pout[..RATE]);
                } else {
                    next.stack.push((r.bk, r.x[k]));
                    next.bk.copy_from_slice(&pout[..RATE]);
                }
            }
            Some(Kind::Pop) => {
                let top = if i.bank2 { r.bk2 } else { r.bk };
                if pout[..RATE] != top {
                    return Err(ExecError { row, why: "a pop's value is not the stack's top" });
                }
                if i.bank2 {
                    next.stack2.pop();
                    next.bk2.copy_from_slice(&dw[..RATE]);
                } else {
                    next.stack.pop();
                    next.bk.copy_from_slice(&dw[..RATE]);
                }
            }
            Some(Kind::Bits) => {
                let lane = i.bsel.ok_or(ExecError { row, why: "a Bits row names no lane" })? as usize;
                let v = r.s[lane].as_canonical_u64();
                for l in 0..NB {
                    next.b[l] = Fa4::from_u64(v >> l & 1);
                }
                for z in 0..NZB {
                    if i.zb >> z & 1 == 1 && v >> z & 1 == 1 {
                        return Err(ExecError { row, why: "a proof-of-work bit is not zero" });
                    }
                }
                if let Some(k) = i.acc {
                    next.tsum = r.tsum + Fa4::from_u64(v & ((1u64 << k.min(24)) - 1));
                }
                let bitv = |l: usize| Fa4::from_u64(v >> l & 1);
                let p1 = bitv(24) * bitv(25) * bitv(26);
                let p2 = p1 * bitv(27) * bitv(28);
                row_buf[AUX] = p1;
                row_buf[AUX + 1] = p2;
                row_buf[AUX + 2] = p2 * bitv(29) * bitv(30);
            }
            Some(Kind::Draw) => {
                let v = r.tsum.as_canonical_u64();
                if v >= 1 << 26 {
                    return Err(ExecError { row, why: "a draw's sum is past 2^26" });
                }
                for l in 0..NB {
                    next.b[l] = Fa4::from_u64(v >> l & 1);
                }
                next.g = i.kg;
                next.var = Fa4::ONE;
                next.tsum = Fa4::ZERO;
            }
            Some(Kind::Io) => next.io = pout,
            Some(Kind::FsReset | Kind::FsDup) => next.fs = pout,
            None => {}
        }
        if i.wsh {
            for l in 0..NWL - RATE {
                next.wl[l] = r.wl[l + RATE];
            }
            next.wl[NWL - RATE..].copy_from_slice(&dw[..RATE]);
        }
        if let Some(c) = i.chip {
            if matches!(c, Chip::Full | Chip::Part) && (0..WIDTH).any(|k| !r.written[X_GAMMA_POW + k]) || c == Chip::Full && !r.written[X_G16] || c == Chip::Init && !r.written[X_GP] {
                return Err(ExecError { row, why: "the chip reads an unwritten γ register" });
            }
            let (cs, cacc, cgp, cs2) = chip_step(c, i, &r);
            next.cs = cs;
            next.cacc = cacc;
            next.cgp = cgp;
            for l in 0..WIDTH {
                row_buf[CS2 + 4 * l..CS2 + 4 * l + 4].copy_from_slice(cs2[l].as_basis_coefficients_slice());
            }
        }
        if i.cclr {
            next.cacc = Ea4::ZERO;
        }
        if i.latch[0] {
            next.r0.copy_from_slice(&dw[..RATE]);
        }
        if i.latch[1] {
            next.r1.copy_from_slice(&dw[..RATE]);
        }
        let w8: [Fa4; RATE] = core::array::from_fn(|l| r.wl[NWL - RATE - i.loff as usize + l]);
        if i.latw[0] {
            next.r0 = w8;
        }
        if i.latw[1] {
            next.r1 = w8;
        }
        for (q, bank) in [r.r0, r.r1].iter().enumerate() {
            if i.heq[q] && r.h[..RATE] != bank[..] {
                return Err(ExecError { row, why: "a Merkle walk does not end at its root" });
            }
        }
        if i.lu.iter().any(Option::is_some) {
            if !r.written[X_RHO] || !r.written[X_BETA] {
                return Err(ExecError { row, why: "a logUp term reads an unwritten challenge" });
            }
            let mut acc = r.lacc;
            for q in 0..2 {
                if i.lu[q].is_some() {
                    acc += ea(&dw[8 + 4 * q..12 + 4 * q]);
                }
            }
            next.lacc = acc;
        }
        if i.lclr {
            next.lacc = Ea4::ZERO;
        }
        let mut wrote = std::collections::BTreeSet::new();
        for a in i.alu.iter().flatten() {
            for k in [Some(a.a).and_then(|s| if let SrcA::X(k) = s { Some(k) } else { None }), if let SrcB::X(k) = a.b { Some(k) } else { None }, if let Some(SrcC::X(k)) = a.c { Some(k) } else { None }].into_iter().flatten() {
                if !r.written[k as usize] {
                    return Err(ExecError { row, why: "a unit reads an unwritten register" });
                }
            }
            let av = match a.a {
                SrcA::X(k) => r.x[k as usize],
                SrcA::One => Ea4::ONE,
            };
            let res = av * src_b(&r, &dw, a.b, a.kc) + src_c(&r, &dw, a.c, a.kc);
            if a.zero && res != Ea4::ZERO {
                if std::env::var("AGG_TRACE").is_ok() {
                    eprintln!("[agg-trace] row {row}: asserted {res:?} = A {av:?} · B {:?} + C {:?}; LACC {:?}", src_b(&r, &dw, a.b, a.kc), src_c(&r, &dw, a.c, a.kc), r.lacc);
                }
                return Err(ExecError { row, why: "an asserted value is not zero" });
            }
            if let Some(w) = a.wr {
                if !wrote.insert(w) {
                    return Err(ExecError { row, why: "two units write one register" });
                }
                next.x[w as usize] = res;
                next.written[w as usize] = true;
            }
        }
        if i.clr {
            next.bk = [Fa4::ZERO; RATE];
            next.bk2 = [Fa4::ZERO; RATE];
            next.io = [Fa4::ZERO; WIDTH];
            next.stack.clear();
            next.stack2.clear();
        }
        if i.stmt {
            stmt.copy_from_slice(&next.io[..RATE]);
        }
        for (c, v) in row_buf.iter().enumerate() {
            cols[c][row] = *v;
        }
        if row + 1 < t {
            r = next;
        }
    }
    Ok((cols, stmt, r))
}

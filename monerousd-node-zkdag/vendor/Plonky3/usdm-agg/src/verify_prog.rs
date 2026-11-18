// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE VERIFIER, AS A PROGRAM FOR THE VERIFIER ROW (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12, step 3; piece C, lane aggc).
//!
//! A committed-door proof is verified by a fixed sequence of transcript steps (absorb, squeeze, grind checks, index
//! draws), hashes (leaf sponges, Merkle levels) and extension-field arithmetic. This module lays that sequence as rows of
//! `isa::Instr` with the stream word each row reads. The PROGRAM is fixed by the proof's shape (the PCS parameters and the
//! gate); the STREAM is the proof.
//!
//! LAYER 1 (this file's first part) — [`Asm`]: the transcript, exactly as the committed door's challenger keeps it.
//! `p3_challenger::DuplexChallenger<_, _, 16, 8>` (`hiding_decider::Chl`) holds an input buffer and an output buffer:
//! * `observe(v)` clears the output buffer, pushes `v`, and duplexes when eight are pending
//!   (challenger/src/duplex_challenger.rs:148);
//! * `sample()` duplexes first when anything is pending or no output is left, then pops the LAST output lane
//!   (the rate lanes 7, 6, … 0 in that order);
//! * `duplexing()` overwrites the first `pending` rate lanes, permutes, and refills the output from the eight rate lanes
//!   (duplex_challenger.rs:86);
//! * an extension challenge is four `sample()`s, limb 0 first (challenger/src/lib.rs:126).
//! [`Asm`] keeps the same two counters and emits a `Reset`/`Duplex` row at exactly the points the challenger duplexes,
//! so a challenge is read from the registers at the alignment the row's `Ch(j)` / `Chs(m)` sources name. The pin
//! `c1_the_assembler_s_transcript_is_the_real_challenger_s` holds every challenge and every sampled word to the real
//! challenger over random schedules: a transcript step this file gets wrong reads a different challenge there.
//!
//! AI RESISTANT: (a) — a wrong program is a different statement; the flags are committed and checked against the
//! program (`vm::program_claim_holds`).

use p3_field::PrimeCharacteristicRing;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::isa::{Alu, Instr, Kind, SrcA, SrcB, SrcC, ND, NZB, RATE, X_FREE};

/// The extension registers this module may write: `X[0..NXC]`. `X[X_FREE..]` are the gate evaluator's (isa.rs v2).
pub const NXC: usize = X_FREE;

/// Where a `Pop` row's popped value sits in its own stream: lanes 8..12, one extension element (isa.rs `Kind::Pop`).
pub const POPPED: SrcC = SrcC::Dx(2);

/// The assembler: a program and the stream it reads (`gate_eval::Builder`, the one builder the tree's pieces share:
/// the gate evaluator lays its rows into `b` between this module's), with the transcript's two counters.
#[derive(Clone, Debug, Default)]
pub struct Asm {
    pub b: crate::gate_eval::Builder,
    /// Observed words not yet duplexed (at most seven: the eighth duplexes).
    pending: Vec<Fa4>,
    /// Output lanes of the last duplexing not yet popped (the next pop reads rate lane `out - 1`).
    out: usize,
    /// A duplexing has happened on this challenger (its first is a `Reset`: the state starts at zero).
    started: bool,
    /// Extension values among the pending words that the absorbing row must also load into a register:
    /// (the value's first lane in the pending word, the register). At most two a row (lanes 0 and 4).
    loads: Vec<(usize, u8)>,
    /// The root bank the next duplexing latches its eight lanes into ([`Asm::observe_root`]).
    latch: Option<usize>,
    /// REGION mode ([`Asm::region_begin`]): the next region index a word observed now takes; `None` outside a region.
    region: Option<usize>,
    /// The region index of each pending word (`None` for a word observed outside a region), parallel to `pending`.
    tags: Vec<Option<usize>>,
    /// Every duplexing that carried a region word: its row and, per rate lane, the word's region index. The gate
    /// evaluator reads these (`gate_eval::GateEval::decorate`). Such a row's units, chip and logUp slots are left empty.
    pub region_rows: Vec<(usize, [Option<usize>; RATE])>,
}

/// The registers one query uses (all distinct): for each folding coordinate `k` (0 = the first sampled) `X[r[k]]` holds
/// `r_k` and `X[q[k]]` holds `1 − r_k`; `w` (at least `2^(f−1)`) takes the fold's values, `p` two products, `gidx` the
/// query point `g^index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRegs {
    pub r: Vec<u8>,
    pub q: Vec<u8>,
    pub w: Vec<u8>,
    pub p: [u8; 2],
    pub gidx: u8,
}

/// The registers one sumcheck round uses (all in `X[0..NXC]`, all distinct).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SumcheckRegs {
    /// The running claimed sum: read and rewritten by every round.
    pub claim: u8,
    /// The round's challenge, left here for the caller.
    pub r: u8,
    /// The round polynomial's two stated values and three temporaries.
    pub c0: u8,
    pub cinf: u8,
    pub t: [u8; 3],
}

/// How a row's unit reads an extension challenge that the transcript has just produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeRead {
    pub src: SrcB,
}

impl Asm {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Continue a program another piece began (the gate evaluator's first pass comes before the inner transcript's
    /// first row): the transcript starts fresh on top of the rows `b` already holds.
    #[must_use]
    pub fn over(b: crate::gate_eval::Builder) -> Self {
        Asm { b, ..Self::default() }
    }

    /// The rows laid so far (the next row's index).
    #[must_use]
    pub fn len(&self) -> usize {
        self.b.prog.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.b.prog.is_empty()
    }

    /// Append a row with its stream word; the program's first row clears the stack and the statement sponge.
    pub fn row(&mut self, mut i: Instr, d: [Fa4; ND]) -> usize {
        if self.b.prog.is_empty() {
            i.clr = true;
        }
        self.b.push(i, d)
    }

    /// A row that only runs units (no permutation's output is read).
    pub fn units(&mut self, a: Option<Alu>, b: Option<Alu>) -> usize {
        self.row(Instr { alu: [a, b], ..Default::default() }, [Fa4::ZERO; ND])
    }

    /// `X[wr] = a·b + c`.
    #[must_use]
    pub fn mul_add(a: SrcA, b: SrcB, c: Option<SrcC>, wr: u8) -> Option<Alu> {
        Some(Alu { a, b, c, wr: Some(wr), zero: false, kc: Ea4::ZERO })
    }

    /// Start a fresh challenger (a child proof's own transcript): its first duplexing is a `Reset`.
    pub fn fresh_transcript(&mut self) {
        self.pending.clear();
        self.tags.clear();
        self.out = 0;
        self.started = false;
    }

    /// The transcript's `duplexing()`: one `Reset` (first) or `Duplex` row absorbing what is pending.
    fn duplex(&mut self) -> usize {
        debug_assert!(self.pending.len() <= RATE);
        let mut w = [Fa4::ZERO; ND];
        let mut am = 0u8;
        for (l, v) in self.pending.drain(..).enumerate() {
            w[l] = v;
            am |= 1 << l;
        }
        let mut lanes = [None; RATE];
        for (l, t) in self.tags.drain(..).enumerate() {
            lanes[l] = t;
        }
        let wsh = lanes.iter().any(Option::is_some);
        assert!(!(wsh && !self.loads.is_empty()), "a region row's units are the gate evaluator's: no register load may ride it");
        let kind = if self.started { Kind::Duplex } else { Kind::Reset };
        self.started = true;
        self.out = RATE;
        // the values this word carries that a register must hold: read off the row's own stream, `Dx(lane / 4)`
        let mut alu = [None, None];
        for (slot, (lane, wr)) in self.loads.drain(..).enumerate() {
            debug_assert!(lane % 4 == 0 && lane < RATE && slot < 2);
            alu[slot] = Self::mul_add(SrcA::One, SrcB::Dx((lane / 4) as u8), None, wr);
        }
        let mut latch = [false; 2];
        if let Some(bank) = self.latch.take() {
            latch[bank] = true;
        }
        let row = self.row(Instr { kind: Some(kind), am, alu, latch, wsh, ..Default::default() }, w);
        if wsh {
            self.region_rows.push((row, lanes));
        }
        row
    }

    /// Begin a REGION: every word observed until [`Self::region_end`] takes the next region index (0, 1, …), and every
    /// duplexing that carries one is marked `wsh` with its lane map in [`Self::region_rows`] — the opened row's absorb
    /// (`add_claim_at`'s `observe_algebra_slice`: index `4·column + limb`) and the chained door's next-row absorb, which the
    /// gate evaluator reads as they stream. A sample that duplexes a region word is such a row too.
    pub fn region_begin(&mut self) {
        self.region = Some(0);
    }

    /// End the region; the words already observed keep their indices until their duplexing.
    pub fn region_end(&mut self) {
        self.region = None;
    }

    /// The transcript's `observe_algebra_element`: the value's four limbs, in basis order. `load` names a register the
    /// absorbing row also writes the value to (readable from the row after that duplexing). The value must start on a
    /// lane the stream can read as one extension element (0 or 4); every extension value the committed door and WHIR
    /// absorb does (each follows a squeeze, an eight-word digest or another extension value) — a schedule that does
    /// not is refused here, never laid misaligned.
    pub fn observe_ext(&mut self, v: Ea4, load: Option<u8>) {
        assert!(self.pending.len() % 4 == 0, "an extension value absorbed off the four-lane grid cannot be loaded from the stream");
        if let Some(wr) = load {
            assert!((wr as usize) < NXC, "X{wr} is not one of this module's registers");
            self.loads.push((self.pending.len(), wr));
        }
        let limbs: [Fa4; 4] = core::array::from_fn(|l| p3_field::BasedVectorSpace::<Fa4>::as_basis_coefficients_slice(&v)[l]);
        self.observe(&limbs);
    }

    /// `X[wr] = a·k + c` for a program constant `k`.
    #[must_use]
    pub fn mul_k(a: SrcA, k: Ea4, c: Option<SrcC>, wr: u8) -> Option<Alu> {
        Some(Alu { a, b: SrcB::Kc, c, wr: Some(wr), zero: false, kc: k })
    }

    /// ⭐ LAYER 2 — ONE SUMCHECK ROUND, as `SumcheckData::verify_rounds_each` runs it (sumcheck/src/data.rs:122):
    /// absorb the round polynomial's two stated values `[c0, c_inf]`; when the round grinds, absorb the two witness
    /// words and require the next sample's low `bits` to be zero (`check_witness_wide`: observe hi, observe lo,
    /// `sample_bits(bits) == 0`); squeeze the challenge `r`; then
    /// `claim ← c0·(1 − r) + (claim − c0)·r + c_inf·r·(r − 1)` (`extrapolate_01inf`, sumcheck/src/lagrange.rs:57),
    /// laid as `c0 + r·(claim − 2·c0 − c_inf) + c_inf·r²` in four unit rows. `X[regs.claim]` must hold the claim; on
    /// return it holds the new one and `X[regs.r]` the challenge (both readable from the row after the last one laid).
    pub fn sumcheck_round(&mut self, c0: Ea4, c_inf: Ea4, grind: Option<(usize, [Fa4; 2])>, regs: SumcheckRegs) {
        let SumcheckRegs { claim, r, c0: xc0, cinf: xci, t } = regs;
        self.observe_ext(c0, Some(xc0));
        self.observe_ext(c_inf, Some(xci));
        if let Some((bits, witness)) = grind {
            self.observe(&witness);
            self.sample_bits(bits);
        }
        let ch = self.challenge();
        let (m1, m2) = (-Ea4::ONE, -(Ea4::ONE + Ea4::ONE));
        // r ; t0 = claim − 2·c0
        self.units(Self::mul_add(SrcA::One, ch.src, None, r), Self::mul_k(SrcA::X(xc0), m2, Some(SrcC::X(claim)), t[0]));
        // t1 = claim − 2·c0 − c_inf ; t2 = c_inf·r
        self.units(Self::mul_k(SrcA::X(xci), m1, Some(SrcC::X(t[0])), t[1]), Self::mul_add(SrcA::X(xci), SrcB::X(r), None, t[2]));
        // t0 = c0 + r·t1 ; t1 = r·(c_inf·r)
        self.units(Self::mul_add(SrcA::X(r), SrcB::X(t[1]), Some(SrcC::X(xc0)), t[0]), Self::mul_add(SrcA::X(r), SrcB::X(t[2]), None, t[1]));
        // claim = t0 + t1
        self.units(Self::mul_add(SrcA::One, SrcB::X(t[0]), Some(SrcC::X(t[1])), claim), None);
    }

    /// The transcript's `observe` of base words, in order.
    pub fn observe(&mut self, vals: &[Fa4]) {
        for v in vals {
            self.out = 0;
            self.pending.push(*v);
            self.tags.push(self.region);
            if let Some(i) = self.region.as_mut() {
                *i += 1;
            }
            if self.pending.len() == RATE {
                self.duplex();
            }
        }
    }

    /// One `sample()`: the rate lane the pop reads (after the duplexing it needed, if any).
    fn pop_lane(&mut self) -> usize {
        if !self.pending.is_empty() || self.out == 0 {
            self.duplex();
        }
        self.out -= 1;
        self.out
    }

    /// The transcript's extension challenge (four pops): the source a unit on ANY row after this call and before the
    /// next duplexing reads it by. Emits the duplexing rows the challenger performs, and nothing else.
    pub fn challenge(&mut self) -> ChallengeRead {
        if !self.pending.is_empty() || self.out == 0 {
            self.duplex();
        }
        if self.out >= 4 {
            let j = (RATE - self.out) as u8;
            self.out -= 4;
            return ChallengeRead { src: SrcB::Ch(j) };
        }
        // the output runs out mid-challenge: `m` limbs from the lanes left (m-1 down to 0), a duplexing with nothing
        // pending, and the rest from the new output's top
        let m = self.out;
        self.out = 0;
        self.duplex();
        self.out = RATE - (4 - m);
        ChallengeRead { src: SrcB::Chs(m as u8) }
    }

    /// The transcript's extension challenge, written to `X[wr]` by a unit row of its own.
    pub fn challenge_into(&mut self, wr: u8) -> usize {
        assert!((wr as usize) < NXC, "X{wr} is not one of this module's registers");
        let c = self.challenge();
        self.units(Self::mul_add(SrcA::One, c.src, None, wr), None)
    }

    /// One base `sample()` decomposed into canonical bits (a `Bits` row). The low `zero_bits` are asserted zero — the
    /// grind check, `check_witness`: after the witness is observed, `sample_bits(bits) == 0`
    /// (challenger/src/grinding_challenger.rs:95). `zero_bits = 0` is a sample that is drawn and not used (the
    /// checkpoint sample `verify_stir_challenges` takes before a round's draws).
    pub fn sample_bits(&mut self, zero_bits: usize) -> usize {
        assert!(zero_bits <= NZB, "a grind of more than {NZB} bits is not a row this machine has");
        let lane = self.pop_lane() as u8;
        let zb = if zero_bits == 0 { 0 } else { (1u32 << zero_bits) - 1 };
        self.row(Instr { kind: Some(Kind::Bits), bsel: Some(lane), zb, ..Default::default() }, [Fa4::ZERO; ND])
    }

    /// ⭐ LAYER 3b — ONE QUERY INDEX, as `draw_below(2^k)` draws it (whir/src/pcs/utils.rs): four base samples
    /// `f0..f3`, `x = f0·p³ + f1·p² + f2·p + f3`, `index = x mod 2^k`. KoalaBear's `p = 2³¹ − 2²⁴ + 1` is 1 modulo 2²⁴,
    /// so for `k ≤ 24` the index is `(f0 + f1 + f2 + f3) mod 2^k`, which is the low `k` bits of the sum of each sample's
    /// low `k` bits. Four `Bits` rows add those to `TSUM` (each after the duplexing its pop needs, exactly where the
    /// challenger duplexes), and a `Draw` row spells the sum in bits and starts the query's walk from the generator `kg`
    /// (`VAR = 1`). The walk's `k` Merkle levels consume the low `k` bits; the two carry bits above them are never walked.
    /// Returns the `Draw` row (the index's bits are readable from the row after it).
    pub fn draw_index(&mut self, k: usize, kg: Fa4) -> usize {
        assert!(k <= 24, "an index of more than 24 bits is not (f0+f1+f2+f3) mod 2^k: p is 1 modulo 2^24 only");
        for _ in 0..4 {
            let lane = self.pop_lane() as u8;
            self.row(Instr { kind: Some(Kind::Bits), bsel: Some(lane), acc: Some(k as u8), ..Default::default() }, [Fa4::ZERO; ND]);
        }
        self.row(Instr { kind: Some(Kind::Draw), kg, ..Default::default() }, [Fa4::ZERO; ND])
    }

    /// The transcript's `observe` of a commitment root (eight base words), LATCHED into the root bank `bank` on the row
    /// that absorbs it: the transcript and the latch read the same eight lanes, so there is no copy to trust. A root is
    /// always absorbed on a full word of its own (`parse_with_round` observes it right after a squeeze; the door
    /// observes its commitment at a word boundary) — anything else is refused here.
    pub fn observe_root(&mut self, root: &[Fa4; RATE], bank: usize) -> usize {
        assert!(self.pending.is_empty(), "a root absorbed off a word boundary cannot be latched from its row");
        assert!(bank < 2, "there are two root banks");
        self.latch = Some(bank);
        self.observe(root);
        self.len() - 1
    }

    /// ⭐ LAYER 3c — ONE STIR QUERY, as `verify_stir_challenges` + `verify_merkle_proof` run it for one index
    /// (whir/src/pcs/verifier/mod.rs): draw the index ([`Self::draw_index`]); hash the opened leaf with its salt
    /// (`MerkleTreeHidingMmcs::verify_batch`: the leaf's preimage is `values ‖ salt`, hashed by `PaddingFreeSponge` —
    /// eight lanes overwritten a permutation, a short last block permuted too; an extension leaf's values are their four
    /// limbs each, `ExtensionMmcs`); walk the `k` Merkle levels with the index's bits (`perm(left ‖ right)[..8]`, the
    /// current node on the right when its bit is 1) and require the end to be the latched root `bank`; and fold the
    /// leaf's `2^f` values at the folding point (`Poly::eval_ext`, multilinear-util/src/poly.rs:657: the LAST coordinate
    /// folds adjacent pairs first), each pair as `(1 − r)·lo + r·hi`.
    ///
    /// The fold's first level reads the values off the leaf rows themselves: `P = (1 − r)·lo` on one row and
    /// `W = r·hi + P` on the next, which is TIED to it (the same stream word), so a row of eight base values (four
    /// pairs) takes the leaf row and three tied rows, and a row of two extension values (one pair) the leaf row and
    /// one. The upper levels run on registers the same way.
    ///
    /// `values` are the leaf's opened values as stream words (base: one a value; extension: four a value), `salt` the
    /// leaf's salt, `siblings` the path bottom-up. Returns the registers holding the fold and `g^index`
    /// (`regs.w[0]`, `regs.gidx`), readable from the row after the last one laid.
    #[allow(clippy::too_many_arguments)]
    pub fn query(&mut self, k: usize, kg: Fa4, f: usize, ext_leaf: bool, bank: usize, values: &[Fa4], salt: &[Fa4], siblings: &[[Fa4; RATE]], regs: &QueryRegs) -> (u8, u8) {
        let per = if ext_leaf { 4 } else { 1 };
        assert_eq!(values.len(), per << f, "a leaf holds 2^f values");
        assert_eq!(siblings.len(), k, "a path has one sibling a level");
        assert!(f >= 1 && regs.r.len() >= f && regs.q.len() >= f && regs.w.len() >= 1 << (f - 1), "the fold's registers");
        self.draw_index(k, kg);
        // the leaf, values then salt, eight lanes a row; level 1 of the fold rides the rows that hold values
        let words: Vec<Fa4> = values.iter().chain(salt).copied().collect();
        let (r1, q1) = (regs.r[f - 1], regs.q[f - 1]);
        for (i, chunk) in words.chunks(RATE).enumerate() {
            let mut w = [Fa4::ZERO; ND];
            w[..chunk.len()].copy_from_slice(chunk);
            let am = ((1u16 << chunk.len()) - 1) as u8;
            let kind = if i == 0 { Kind::Leaf0 } else { Kind::LeafN };
            // the pairs this row holds whole: (lo source, hi source, the pair's index)
            let mut pairs: Vec<(SrcB, SrcB, usize)> = Vec::new();
            if ext_leaf {
                if RATE * i + RATE <= values.len() {
                    pairs.push((SrcB::Dx(0), SrcB::Dx(1), i));
                }
            } else {
                for lane in (0..chunk.len()).step_by(2) {
                    if RATE * i + lane + 1 < values.len() {
                        pairs.push((SrcB::Db(lane as u8), SrcB::Db(lane as u8 + 1), (RATE * i + lane) / 2));
                    }
                }
            }
            let batches: Vec<&[(SrcB, SrcB, usize)]> = pairs.chunks(2).collect();
            let rows = (2 * batches.len()).max(1);
            for row in 0..rows {
                let batch = batches.get(row / 2).copied().unwrap_or(&[]);
                let unit = |slot: usize| -> Option<Alu> {
                    let &(lo, hi, j) = batch.get(slot)?;
                    let p = regs.p[slot];
                    if row % 2 == 0 {
                        Self::mul_add(SrcA::X(q1), lo, None, p)
                    } else {
                        Self::mul_add(SrcA::X(r1), hi, Some(SrcC::X(p)), regs.w[j])
                    }
                };
                let instr = Instr { kind: (row == 0).then_some(kind), am: if row == 0 { am } else { 0 }, tie: row + 1 < rows, alu: [unit(0), unit(1)], ..Default::default() };
                self.row(instr, w);
            }
        }
        // the upper levels, on registers: level l folds with coordinate f − l
        for lvl in 2..=f {
            let (r, q) = (regs.r[f - lvl], regs.q[f - lvl]);
            let n = 1usize << (f - lvl);
            for j0 in (0..n).step_by(2) {
                let js: Vec<usize> = (j0..n.min(j0 + 2)).collect();
                let lo = |s: usize| js.get(s).and_then(|&j| Self::mul_add(SrcA::X(q), SrcB::X(regs.w[2 * j]), None, regs.p[s]));
                let hi = |s: usize| js.get(s).and_then(|&j| Self::mul_add(SrcA::X(r), SrcB::X(regs.w[2 * j + 1]), Some(SrcC::X(regs.p[s])), regs.w[j]));
                self.units(lo(0), lo(1));
                self.units(hi(0), hi(1));
            }
        }
        // the path, then the root: H holds the walk's end from the row after the last level
        for s in siblings {
            let mut w = [Fa4::ZERO; ND];
            w[..RATE].copy_from_slice(s);
            self.row(Instr { kind: Some(Kind::Comp), ..Default::default() }, w);
        }
        let mut heq = [false; 2];
        heq[bank] = true;
        self.row(Instr { heq, alu: [Self::mul_add(SrcA::One, SrcB::Var, None, regs.gidx), None], ..Default::default() }, [Fa4::ZERO; ND]);
        (regs.w[0], regs.gidx)
    }

    /// Push `X[k]` on the stack (the hash chain `BK`): the value is readable again only by the pop that takes it.
    pub fn push(&mut self, k: u8) -> usize {
        self.row(Instr { kind: Some(Kind::Push), px: Some(k), ..Default::default() }, [Fa4::ZERO; ND])
    }

    /// Pop the stack's top. The executor lays the popped value in the row's stream; a unit ON THIS ROW reads it as
    /// [`POPPED`]. The row's two units are the caller's.
    pub fn pop_with(&mut self, a: Option<Alu>, b: Option<Alu>) -> usize {
        self.row(Instr { kind: Some(Kind::Pop), alu: [a, b], ..Default::default() }, [Fa4::ZERO; ND])
    }

    /// ⭐ LAYER 3a — A ROUND'S α-COMBINE, as `Constraint::combine_evals` runs it (sumcheck/src/constraints/mod.rs:154):
    /// `claim += Σ_i α^i·ood_i + Σ_j α^(n+j)·fold_j` (eq.rs:364 `dot_product(evaluations, α.powers())`; select.rs:577, the
    /// same shifted by the `n` out-of-domain answers). `X[alpha]` holds α; the `n` out-of-domain answers are in the
    /// registers `ood` (in order); the `m` query folds are the stack's top `m` entries, pushed in query order — popped
    /// here newest first by a reverse Horner (`R ← R·α + popped`), which is why they are on a stack at all: they exist
    /// before α does. `X[claim]` is read and rewritten; `t` is two temporaries. Lays `m + n + 3` rows.
    pub fn alpha_combine(&mut self, claim: u8, alpha: u8, ood: &[u8], m: usize, t: [u8; 2]) {
        let (r, o) = (t[0], t[1]);
        // R = 0 ; O = the last out-of-domain answer (or 0 when there is none)
        let o_init = match ood.last() {
            Some(&k) => Self::mul_add(SrcA::One, SrcB::X(k), None, o),
            None => Self::mul_k(SrcA::One, Ea4::ZERO, None, o),
        };
        self.units(Self::mul_k(SrcA::One, Ea4::ZERO, None, r), o_init);
        // the folds, newest first: R = Σ_j α^j·fold_j
        for _ in 0..m {
            self.pop_with(Self::mul_add(SrcA::X(r), SrcB::X(alpha), Some(POPPED), r), None);
        }
        // R·α^n beside the out-of-domain Horner O = Σ_i α^i·ood_i (the last answer is already in O)
        let n = ood.len();
        for step in 0..n {
            let shift = Self::mul_add(SrcA::X(r), SrcB::X(alpha), None, r);
            let horner = (step + 1 < n).then(|| Self::mul_add(SrcA::X(o), SrcB::X(alpha), Some(SrcC::X(ood[n - 2 - step])), o)).flatten();
            self.units(shift, horner);
        }
        // claim += O + R
        self.units(Self::mul_add(SrcA::One, SrcB::X(o), Some(SrcC::X(r)), o), None);
        self.units(Self::mul_add(SrcA::One, SrcB::X(o), Some(SrcC::X(claim)), claim), None);
    }

    /// Close the program: its last row states the digest of everything the statement sponge absorbed.
    pub fn finish(mut self) -> (Vec<Instr>, Vec<[Fa4; ND]>) {
        self.row(Instr { kind: Some(Kind::Io), stmt: true, ..Default::default() }, [Fa4::ZERO; ND]);
        (self.b.prog, self.b.stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{ea, execute, B, NB, X};
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_field::PrimeField64;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;
    use usdm_decider::hiding_decider::{Chl, Perm16};

    fn real_challenger() -> Chl {
        // the committed door's own: committed_air.rs `challenger()` (a public constant permutation)
        let mut rng = SmallRng::seed_from_u64(usdm_decider::committed_air::COMMITTED_AIR_SEED);
        Chl::new(Perm16::new_from_rng_128(&mut rng))
    }

    /// ⭐ LAYER 1's PIN — the assembler's transcript IS the committed door's challenger. Random schedules of observes
    /// (runs of 1 to 19 words), extension challenges and base samples, run on the real `Chl` and through the assembler +
    /// the verifier row's executor; every challenge the program writes and every sampled word's bits must be the real
    /// challenger's, in order. Covers the three alignments a challenge can have: whole inside a duplexing (`Ch`), split
    /// across one (`Chs`, the output running out mid-challenge), and after a partial absorb.
    #[test]
    fn c1_the_assembler_s_transcript_is_the_real_challenger_s() {
        let mut seed: u64 = 0xC1_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let (mut whole, mut split, mut bits_rows) = (0usize, 0usize, 0usize);
        for _schedule in 0..40 {
            let mut real = real_challenger();
            let mut asm = Asm::new();
            // (the row a value is readable on, its register, the real value)
            let mut want_x: Vec<(usize, u8, Ea4)> = Vec::new();
            let mut want_bits: Vec<(usize, u64)> = Vec::new();
            for step in 0..60 {
                match next() % 3 {
                    0 => {
                        let n = 1 + (next() % 19) as usize;
                        let vals: Vec<Fa4> = (0..n).map(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)).collect();
                        for v in &vals {
                            real.observe(*v);
                        }
                        asm.observe(&vals);
                    }
                    1 => {
                        let want: Ea4 = real.sample_algebra_element();
                        let wr = (step % NXC) as u8;
                        let row = asm.challenge_into(wr);
                        match asm.b.prog[row].alu[0].expect("a challenge read").b {
                            SrcB::Ch(_) => whole += 1,
                            SrcB::Chs(_) => split += 1,
                            other => panic!("a challenge read by {other:?}"),
                        }
                        want_x.push((row + 1, wr, want));
                    }
                    _ => {
                        let v: Fa4 = real.sample();
                        let row = asm.sample_bits(0);
                        want_bits.push((row + 1, v.as_canonical_u64()));
                        bits_rows += 1;
                    }
                }
            }
            let (prog, d) = asm.finish();
            let (cols, _io) = execute(&prog, &d, 8).expect("the transcript program runs");
            for (row, wr, want) in want_x {
                let got = ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols[X + 4 * wr as usize + t][row]));
                assert_eq!(got, want, "⛔ a challenge the program read is not the real challenger's (row {row}, X{wr})");
            }
            for (row, want) in want_bits {
                let got: u64 = (0..NB).map(|l| cols[B + l][row].as_canonical_u64() << l).sum();
                assert_eq!(got, want, "⛔ a sampled word's bits are not the real challenger's sample (row {row})");
            }
        }
        assert!(whole > 100 && split > 20 && bits_rows > 100, "CALIBRATION: every alignment was exercised ({whole} whole, {split} split, {bits_rows} base samples)");
    }

    /// ⭐ LAYER 3b's PIN — a query index IS `draw_below`'s. For k = 4, 12, 20 and 24, sixty draws each on one transcript
    /// with observes of random length between them (so the four pops of a draw fall inside one duplexing, across one,
    /// and after partial absorbs), the bits the `Draw` row lays — read as the low k bits of `B` on the next row — are the
    /// index `p3_whir::pcs::utils::draw_below(2^k)` returns on the real challenger; and the walk starts at `VAR = 1`
    /// with the generator named. The sum's carry bits (above k) are present and never part of the index.
    #[test]
    fn c4_a_query_index_is_draw_below_s() {
        use crate::isa::{G, VAR};
        use p3_whir::pcs::utils::draw_below;
        let mut seed: u64 = 0xC4_5EED;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let mut carried = 0usize;
        for k in [4usize, 12, 20, 24] {
            let mut real = real_challenger();
            let mut asm = Asm::new();
            let mut want: Vec<(usize, usize)> = Vec::new();
            let kg = Fa4::from_u64(7 + k as u64);
            for _ in 0..60 {
                let n = (next() % 11) as usize; // 0 to 10 words between draws
                let vals: Vec<Fa4> = (0..n).map(|_| Fa4::from_u64(next() % Fa4::ORDER_U64)).collect();
                for v in &vals {
                    real.observe(*v);
                }
                asm.observe(&vals);
                let index = draw_below::<_, Fa4>(&mut real, 1usize << k);
                let row = asm.draw_index(k, kg);
                want.push((row + 1, index));
            }
            let (prog, d) = asm.finish();
            let (cols, _io) = execute(&prog, &d, 8).expect("the draws run");
            for (row, index) in want {
                let bits: u64 = (0..NB).map(|l| cols[B + l][row].as_canonical_u64() << l).sum();
                assert_eq!((bits & ((1u64 << k) - 1)) as usize, index, "⛔ k = {k}: the program's index is not draw_below's (row {row})");
                assert!(bits < 4u64 << k, "⛔ k = {k}: the sum of four k-bit samples is past 4·2^k");
                carried += usize::from(bits >> k != 0);
                assert_eq!(cols[VAR][row], Fa4::ONE, "the walk starts at g^0");
                assert_eq!(cols[G][row], kg, "the walk starts from the round's generator");
            }
        }
        assert!(carried > 60, "CALIBRATION: sums that carry past bit k were drawn ({carried}), so the mask is exercised");
    }

    /// REGION mode's pin: words observed in a region carry their indices to the duplexing that absorbs them (a full word,
    /// a word that shares lanes with non-region words, and a sample-triggered duplexing), every such row is `wsh`, and no
    /// other row is. (It does not execute the program: a `wsh` row shifts the window `WL`, which nothing resets, and the
    /// executor's four-iteration fixpoint for the wrap does not settle a window shifted by only two rows — the gate
    /// evaluator's programs fill it before they read it.)
    #[test]
    fn c9_a_region_marks_the_rows_that_absorb_it() {
        let w = |n: u64| -> Vec<Fa4> { (0..n).map(Fa4::from_u64).collect() };
        let mut asm = Asm::new();
        asm.observe(&w(3)); // three words outside the region
        asm.region_begin();
        asm.observe(&w(9)); // five fill the first word (lanes 3..8 = indices 0..5), four go on
        asm.region_end();
        asm.observe(&w(1));
        let _ = asm.challenge(); // a sample duplexes the five pending words (indices 5..9 in lanes 0..4)
        let rows = asm.region_rows.clone();
        assert_eq!(rows.len(), 2, "two duplexings carried region words");
        assert_eq!(rows[0].1, [None, None, None, Some(0), Some(1), Some(2), Some(3), Some(4)]);
        assert_eq!(rows[1].1, [Some(5), Some(6), Some(7), Some(8), None, None, None, None]);
        for (i, ins) in asm.b.prog.iter().enumerate() {
            assert_eq!(ins.wsh, rows.iter().any(|(r, _)| *r == i), "row {i}: wsh is set exactly on the region's rows");
        }
    }

    /// ⭐ LAYER 3a's PIN — the α-combine is `Constraint::combine_evals`' sum, for every shape WHIR uses: no, one and
    /// three out-of-domain answers beside 0 to 9 query folds. The folds are pushed in query order and the program's claim
    /// must be `claim + Σ α^i·ood_i + Σ α^(n+j)·fold_j` — the formula read from eq.rs:364 and select.rs:577, computed
    /// here term by term. A fold moved after it was pushed changes the claim (the lie's control).
    #[test]
    fn c3_the_alpha_combine_is_combine_evals_sum() {
        let mut seed: u64 = 0xC3_5EED;
        let mut rnd = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((seed >> (7 * i)) % Fa4::ORDER_U64));
            ea(&l)
        };
        // registers: claim 0, alpha 1, out-of-domain 2..5, a scratch for the value being pushed 6, temporaries 7, 8
        for (n, m) in [(0usize, 0usize), (0, 4), (1, 0), (1, 1), (1, 9), (3, 5)] {
            let (claim0, alpha) = (rnd(), rnd());
            let oods: Vec<Ea4> = (0..n).map(|_| rnd()).collect();
            let folds: Vec<Ea4> = (0..m).map(|_| rnd()).collect();
            let mut want = claim0;
            let mut p = Ea4::ONE;
            for v in oods.iter().chain(&folds) {
                want += p * *v;
                p *= alpha;
            }
            let run = |folds: &[Ea4]| {
                let mut asm = Asm::new();
                asm.observe(&[Fa4::ZERO; RATE]);
                asm.units(Asm::mul_k(SrcA::One, claim0, None, 0), Asm::mul_k(SrcA::One, alpha, None, 1));
                for (i, v) in oods.iter().enumerate() {
                    asm.units(Asm::mul_k(SrcA::One, *v, None, 2 + i as u8), None);
                }
                for v in folds {
                    asm.units(Asm::mul_k(SrcA::One, *v, None, 6), None);
                    asm.push(6);
                }
                let ood_regs: Vec<u8> = (0..n).map(|i| 2 + i as u8).collect();
                asm.alpha_combine(0, 1, &ood_regs, m, [7, 8]);
                let end = asm.len();
                let (prog, d) = asm.finish();
                let (cols, _io) = execute(&prog, &d, 8).expect("the combine runs");
                ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols[X + t][end]))
            };
            assert_eq!(run(&folds), want, "⛔ ({n} out-of-domain, {m} folds): the program's claim is not combine_evals' sum");
            if m > 0 {
                let mut moved = folds.clone();
                moved[m / 2] += Ea4::ONE;
                assert_ne!(run(&moved), want, "⛔ ({n}, {m}): a moved fold left the claim unchanged");
            }
        }
    }

    /// ⭐ LAYER 2's PIN — the sumcheck rounds ARE the native verifier's. A real `SumcheckData` (random round
    /// polynomials; rounds 1 and 3 grind 9 and 12 bits with witnesses the real challenger found) is verified by
    /// `verify_rounds_each` and by the program: after every round the program's claim and challenge registers hold the
    /// native verifier's values. Then the lies: a moved witness word, and a moved stated value, are refused by the
    /// executor (the grind's low bits, or a claim that no longer matches) — the first by a row that cannot run.
    #[test]
    fn c2_the_sumcheck_rounds_are_the_native_verifiers() {
        use p3_challenger::GrindingChallenger;
        use p3_sumcheck::SumcheckData;
        let mut seed: u64 = 0xC2_5EED;
        let mut rnd = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let l: [Fa4; 4] = core::array::from_fn(|i| Fa4::from_u64((seed >> (7 * i)) % Fa4::ORDER_U64));
            ea(&l)
        };
        let bits = [0usize, 9, 0, 12, 0];
        let evals: Vec<[Ea4; 2]> = bits.iter().map(|_| [rnd(), rnd()]).collect();
        let claim0 = rnd();
        let regs = SumcheckRegs { claim: 0, r: 1, c0: 2, cinf: 3, t: [4, 5, 6] };
        let build = |evals: &[[Ea4; 2]], witnesses: &[Fa4]| {
            let mut asm = Asm::new();
            // the transcript opens with a word of its own (a program's first row clears), then the claim is stated
            asm.observe(&[Fa4::ZERO; RATE]);
            asm.units(Asm::mul_k(SrcA::One, claim0, None, regs.claim), None);
            let mut w = witnesses.iter();
            let mut ends = Vec::new();
            for (e, &b) in evals.iter().zip(&bits) {
                let g = (b > 0).then(|| (b, [*w.next().expect("a witness"), *w.next().expect("a witness")]));
                asm.sumcheck_round(e[0], e[1], g, regs);
                ends.push(asm.len());
            }
            let (prog, d) = asm.finish();
            (prog, d, ends)
        };
        // the prover's side of the transcript (it opens with the same word the program's does): the grind witnesses,
        // found on the real challenger
        let mut prover2 = real_challenger();
        prover2.observe_slice(&[Fa4::ZERO; RATE]);
        let mut witnesses2: Vec<Fa4> = Vec::new();
        for (e, &b) in evals.iter().zip(&bits) {
            prover2.observe_algebra_slice(&e[..]);
            witnesses2.extend(prover2.grind_wide(b));
            let _: Ea4 = prover2.sample_algebra_element();
        }
        // the native verifier: the same call the WHIR verifier makes
        let data2 = SumcheckData::<Fa4, Ea4> { polynomial_evaluations: evals.clone(), pow_witnesses: witnesses2.clone() };
        let mut native3 = real_challenger();
        native3.observe_slice(&[Fa4::ZERO; RATE]);
        let mut claim3 = claim0;
        let rs3 = data2.verify_rounds_each(&mut native3, &mut claim3, &bits).expect("the native verifier accepts the reground proof");
        let mut want: Vec<(Ea4, Ea4)> = Vec::new();
        let mut c = claim0;
        for (e, r) in evals.iter().zip(rs3.as_slice()) {
            c = e[0] * (Ea4::ONE - *r) + (c - e[0]) * *r + e[1] * *r * (*r - Ea4::ONE);
            want.push((c, *r));
        }
        assert_eq!(c, claim3, "CALIBRATION: the trajectory's last claim is the native verifier's");
        let (prog, d, ends) = build(&evals, &witnesses2);
        let (cols, _io) = execute(&prog, &d, 8).expect("the honest sumcheck runs");
        let x = |k: u8, row: usize| ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols[X + 4 * k as usize + t][row]));
        for (i, (end, (wc, wr))) in ends.iter().zip(&want).enumerate() {
            assert_eq!(x(regs.r, *end), *wr, "⛔ round {i}: the program's challenge is not the native verifier's");
            assert_eq!(x(regs.claim, *end), *wc, "⛔ round {i}: the program's claim is not the native verifier's");
        }
        println!("[agg-c2] {} sumcheck rounds (two grinding): {} rows", bits.len(), prog.len());
        // LIE 1 — a moved grind witness: the native verifier refuses it, and the program's Bits row cannot run
        let mut bad_w = witnesses2.clone();
        bad_w[1] += Fa4::ONE;
        let bad_data = SumcheckData::<Fa4, Ea4> { polynomial_evaluations: evals.clone(), pow_witnesses: bad_w.clone() };
        let mut n4 = real_challenger();
        n4.observe_slice(&[Fa4::ZERO; RATE]);
        let mut c4 = claim0;
        if bad_data.verify_rounds_each(&mut n4, &mut c4, &bits).is_err() {
            let (p4, d4, _) = build(&evals, &bad_w);
            assert!(execute(&p4, &d4, 8).is_err(), "⛔ LIE 1: a grind witness the native verifier refuses ran");
        }
        // LIE 2 — a moved stated value: every later challenge and the claim differ from the honest run's
        let mut bad_e = evals.clone();
        bad_e[2][0] += Ea4::ONE;
        let (p5, d5, ends5) = build(&bad_e, &witnesses2);
        match execute(&p5, &d5, 8) {
            Err(_) => {} // the next grinding round's witness no longer fits the moved transcript
            Ok((cols5, _)) => {
                let last = *ends5.last().expect("rounds");
                let got = ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols5[X + 4 * regs.claim as usize + t][last]));
                assert_ne!(got, want.last().expect("rounds").0, "⛔ LIE 2: a moved round value left the claim unchanged");
            }
        }
    }
}

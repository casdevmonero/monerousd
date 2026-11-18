//! The UNIVERSAL ROW — one step of the recursive verifier as a fixed constraint template, `T` copies of which
//! form a uniform R1CS (`uniform_r1cs.rs`) whose matrices the verifier evaluates in closed form. Every row runs
//! the same operations on a register file carried step to step; a per-row FLAG WORD set (the instruction) routes
//! operands, and the flag words are absorbed into a PROGRAM SPONGE whose digest is checked against the statement —
//! the schedule is bound by a hash chain, never trusted (`docs/O1-OPENINGS-RECURSION-SPEC.md` § "Z2"). The proof
//! being verified enters as a STREAM of words (`D`), one row's worth per step, in the order the program fixes;
//! Fiat–Shamir absorbs bind the words the transcript saw, registers bind the rest, `IOCHK` rows bind stream copies
//! of the statement to the public inputs.
//!
//! Row operations (always executed; flags select operands; a flag that is off computes on zeros; registers HOLD
//! unless a flag moves them):
//! 1. ONE Poseidon2-16 permutation with the round constants blended between the transcript's and the Merkle
//!    hash's seeded instances by the mode flags; input routed for a transcript duplexing (rate slots overwritten
//!    by stream words where `A_k`), a Merkle compression (`bit ? D ‖ H : H ‖ D`) or a leaf absorb (`H` reset);
//!    output routed back to `S` or `H`.
//! 2. The transcript output buffer `O` refilled on a duplexing; four POP UNITS each read one `O` slot named by
//!    three bits and an active bit (any alignment), `ch_ext = (u_0, u_1, u_2, u_3)` is the row's Ea4 challenge,
//!    and four latches assemble a challenge split across a duplexing into `E[0]` over two rows.
//! 3. Four Ea4 multiplications with 8-/10-way operand menus (including the adjacent-pair differences a
//!    multilinear fold needs at every level and per-mul reads of the `VB` bank so four queries advance per row);
//!    eight Ea4 accumulators with 13 additive move terms; four Ea4 environment registers; five banks: `PT` (the
//!    folding randomness — and, before it, the Spartan core's `τ ‖ r_x` read at the port `PT[pt_port]` — newest at
//!    the head, pushed from `E[0]`, rotated both ways), `F` (this round's folds and OOD answers pushed one at a
//!    time from `E[0]` for the α-combine's Horner walk, then the final polynomial pushed two at a time from the
//!    stream, rotated either way for the select Horner), `VB` (each query's `g^index`, base, four squared in
//!    place, rotated by four), `Y` (the OOD univariates), `RS` (`r_y`, pushed as sampled, for the claim point's eq
//!    weight and `s_lo`).
//! 4. Four canonical 31-bit decompositions of the pop units masked to the round's `k` low bits (the mask is a
//!    function of the round one-hot and the round table), summed into the carried `TSUM` — `draw_below(2^k)` on
//!    wires, a draw split across a duplexing included; the index bits move into `B`, which a Merkle row shifts.
//! 5. The running domain-generator power `G` and `VAR = g^index` (`domain_gen_pow`, one level per Merkle row).
//! 6. The observed root `R2` (captured while the previous root `R` still guards this round's paths; `R_SHIFT`
//!    promotes it), the root assertion `H[..8] == R`, and four `X'_k == X'_{k+4}` assertions.
//! 7. The program sponge `PS' = P_program(PS ← flag words)`; `INIT` zeroes the state registers (row 0); `FINAL`
//!    pins `PS'` to `io[0..8]` (row `T − 2`, whose flags the digest covers); `IOCHK_p` pins `D[0..8]` to `io[8p..]`.
//! 8. The hand-off: every output register equals the NEXT step's register (uniform `Next` references).
//!
//! ROOT-LAYER: the row IS the verifier's instruction set; its template is the definition every step shares.
//! MEASURED: pins below — transcript rows equal `Chl` (aligned, unaligned and split samples), Merkle rows equal
//! `Mmcs16`'s root, STIR rows equal `draw_below`, product/move/bank rows equal native arithmetic, and a one-bit
//! program change moves the program hash.
//! MUST-STAY-GREEN: `uniform_r1cs` pins; `spartan_gadgets` pins; `verifier_program` pins.
//! O1-DEFINITION-REVIEWED: the row's constraint count is a constant of this file (shape 1: f(fixed template)).

use crate::hiding_decider::{Ea4, Fa4};
use crate::spartan_ccs::R1cs;
use crate::spartan_gadgets::{
    canonical_bits, ext_mul, ext_scale_wire, poseidon2_permutation_blend, sel, select_ext, ExtLc, Lc, P2Consts,
    R1csBuilder, RATE, WIDTH,
};
use crate::uniform_r1cs::UniformR1cs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

// ── the register file (this step's first locals; the next step's registers are the `Next` placeholders) ─────────
pub const S_OFF: usize = 0; // transcript sponge state (16)
pub const O_OFF: usize = S_OFF + WIDTH; // transcript output buffer (8)
pub const H_OFF: usize = O_OFF + RATE; // Merkle hash state (16)
pub const PS_OFF: usize = H_OFF + WIDTH; // program sponge state (16)
pub const R_OFF: usize = PS_OFF + WIDTH; // the root this round's paths are checked against (8)
pub const R2_OFF: usize = R_OFF + RATE; // the root observed this round, promoted by R_SHIFT (8)
pub const NX: usize = 8; // Ea4 accumulators
pub const X_OFF: usize = R2_OFF + RATE;
pub const NE: usize = 4; // Ea4 environment
pub const E_OFF: usize = X_OFF + 4 * NX;
pub const NB: usize = 24; // index bits (a folded domain of at most 2^24)
pub const B_OFF: usize = E_OFF + 4 * NE;
pub const G_OFF: usize = B_OFF + NB; // running g^(2^level)
pub const VAR_OFF: usize = G_OFF + 1; // running g^index
pub const TSUM_OFF: usize = VAR_OFF + 1; // the STIR draw's running masked sum
/// H12 §12 C: the VB stack's chain digest (8) — `BANK_ABSORB` pushes `VAR` (`BK ← compress(BK ‖ VAR)`), `BANK_UNWIND`
/// pops it back (the stream supplies the previous digest and the value; the row checks they compress to `BK`), so the
/// closing re-reads every g^index without a register per query. INIT zeroes it: the empty stack is the zero digest.
pub const BK_OFF: usize = TSUM_OFF + 1;
/// H12 §12 C: the bank compression's lane-9 domain tag ("VBNK"); the digest never enters a transcript or a root.
pub const BANK_TAG: u64 = 0x5642_4E4B;
/// H12 §12 C (F half): the fold stack's chain digest (8) — a bank row with `FBANK` works FK instead of BK:
/// absorb pushes the round fold `X[0]` (`FK ← compress(FK ‖ X[0] ‖ FBANK_TAG)`), unwind pops it (`D[8..16]` the
/// previous digest, `D_ext[1]` the fold), so a round's α-combine reads any number of folds without an F slot each.
/// INIT zeroes it: the empty stack is the zero digest.
pub const FK_OFF: usize = BK_OFF + RATE;
/// The fold stack's compression domain tag ("FBNK", lane 12); the digest never enters a transcript or a root.
pub const FBANK_TAG: u64 = 0x4642_4E4B;
/// The state registers `INIT` zeroes: everything before the banks.
pub const NSTATE: usize = FK_OFF + RATE;
pub const NPT: usize = 60; // the folding randomness bank; the Spartan core's τ ‖ r_x (2·m_vars ≤ 60: m_vars ≤ 30) with the port PT[pt_port]
pub const PT_OFF: usize = NSTATE;
/// The select group's four working g^index slots, loaded by four `BANK_UNWIND` pops (H12 §12 C: the 160-slot queue
/// that capped the query count is deleted — any number of queries rides the BK stack).
pub const NVB: usize = 4;
pub const VB_OFF: usize = PT_OFF + 4 * NPT;
pub const NY: usize = 20; // the OOD univariates and the per-round α's
pub const Y_OFF: usize = VB_OFF + NVB;
/// ra, rb, rc, then r_y (n_vars) pushed as sampled, then the uniform certificate's stashes: claim2, m_at, the matrix
/// argument's ρ (16), w_eval, α_f, claimed_f — 24 + n_vars entries, so n_vars ≤ 29 (t_bits ≤ 15 at V_BITS 13: the
/// certificate's T = 2^15, H12 path B). `RsIdx` refuses an index past the bank at emission.
pub const NRS: usize = 53;
pub const RS_OFF: usize = Y_OFF + 4 * NY;
/// This round's folds + OOD answers (the α-combine walk: the certificate witness's first round at rate 1/2 has 91
/// queries with 20 grinding bits, 108 without — census 2026-09-28), the final polynomial (Horner; up to 128
/// coefficients — the certificate sends at 7 variables), and the certificate's 34 observed claims.
pub const NF: usize = 128;
pub const F_OFF: usize = RS_OFF + 4 * NRS;
pub const NREG: usize = F_OFF + 4 * NF;
// ── the per-step inputs after the registers ─────────────────────────────────────────────────────────────────────
pub const NSTREAM: usize = 16;
pub const D_OFF: usize = NREG;
pub const NFLAG_WORDS: usize = 10;
pub const FW_OFF: usize = D_OFF + NSTREAM;
pub const NINPUTS: usize = FW_OFF + NFLAG_WORDS;
/// The local holding the constant ONE (allocated right after the inputs): the template routes every `Lc` constant
/// through it (`UniformR1cs::from_template(.., Some(ONE_LOCAL))`), so the matrix argument meets the public kind
/// only at the io reads and the single `one · 1 = 1` pin.
pub const ONE_LOCAL: usize = NINPUTS;
pub const FLAG_BITS: usize = 31 * NFLAG_WORDS; // 310
/// log2 of a step's local variables: registers + stream + flag words + every intermediate the row allocates.
pub const V_BITS: usize = 13;
/// Rounds the domain tables hold (WHIR rounds plus the final round, for BOTH the witness and the fixed commitment's
/// WHIR runs of a uniform certificate): a round one-hot selects the entry. Slots `0..6` are the `RF` bits, slots
/// `6..10` the `RF2` bits (`flag::rf`).
pub const NROUNDS: usize = 10;
pub const NPOPU: usize = 4;
/// The statement the row reads: `pad (7) ‖ program_hash (8) ‖ statement_hash (8) ‖ matrix_root (8) ‖ state_hash (8)`.
/// The 7-word pad 8-ALIGNS every io block with a statement leaf row's `D`: the hashed statement words are `[1, io…]`,
/// so block `p` of the io is exactly leaf row `p + 1`'s eight words — which lets the certificate read the INNER io's
/// program digest and state hash with one-block flags (`IOCHK_BASE`, `R_CAPTURE`) on the z̃ close's leaf rows (M5).
pub const IO_PAD: usize = 7;
pub const IO_LEN: usize = IO_PAD + 4 * RATE;
/// The io words of statement block `p` (0 = program digest, 1 = statement hash, 2 = matrix root, 3 = state hash).
pub const fn io_block(p: usize) -> core::ops::Range<usize> {
    IO_PAD + RATE * p..IO_PAD + RATE * (p + 1)
}

/// Flag indices inside the unpacked flag bits.
pub mod flag {
    pub const M_ABSORB: usize = 0;
    pub const M_MERKLE: usize = 1;
    pub const M_LEAF: usize = 2;
    pub const H_RESET: usize = 3;
    /// 8: overwrite rate slot `k` of the permutation input with stream word `k`.
    pub const A: usize = 4;
    /// 4 units × (3 slot bits + 1 active bit): pop unit `c` reads `O[slot]` when active.
    pub const POPU: usize = 12;
    pub const POPU_STRIDE: usize = 4;
    /// 4: write pop unit `c` into coefficient `c` of `E[0]`.
    pub const LATCH: usize = 28;
    /// Finalize a STIR draw: `B ← bits of TSUM'`.
    pub const STIR: usize = 32;
    /// Reset `TSUM` before adding this row's masked samples.
    pub const TCLEAR: usize = 33;
    /// This row consumes `B[0]` (a Merkle level): `B' = B >> 1`.
    pub const BSHIFT: usize = 34;
    /// 6: round one-hot — selects `folded_domain_gen` and `k` from the round tables.
    pub const RF: usize = 35;
    /// 4 muls × (8 a-menu + 10 b-menu).
    pub const MUL: usize = 41;
    pub const MUL_STRIDE: usize = 18;
    pub const A_MENU: usize = 8;
    pub const AM_X: usize = 0; // X[k]
    pub const AM_X4: usize = 1; // X[k+4]
    pub const AM_D: usize = 2; // D_ext[k]
    pub const AM_E: usize = 3; // E[k]
    pub const AM_PAIRDIFF: usize = 4; // D_ext[1] − D_ext[0] (the one Ea4 pair a leaf row absorbs)
    pub const AM_BASEPAIR: usize = 5; // D[2k+1] − D[2k], base
    pub const AM_PT0: usize = 6;
    pub const AM_ADJ: usize = 7; // X[2k+1] − X[2k]
    pub const BM_X4: usize = 0; // X[k+4]
    pub const BM_E: usize = 1; // E[k]
    pub const BM_E0: usize = 2;
    pub const BM_CH: usize = 3;
    pub const BM_PT0: usize = 4;
    pub const BM_F0: usize = 5;
    pub const BM_PTM: usize = 6; // PT[pt_port]
    pub const BM_Y0: usize = 7;
    pub const BM_VBK: usize = 8; // VB[k], base
    pub const BM_VAR: usize = 9; // VAR, base (the final round's Horner reads its query's g^index in place)
    /// 8 accumulators × 14 (CLR + 13 additive terms).
    pub const XMOVE: usize = 113;
    pub const XM_STRIDE: usize = 14;
    pub const XM_CLR: usize = 0;
    pub const XM_ADD_MUL: usize = 1;
    pub const XM_SUB_MUL: usize = 2;
    pub const XM_ADD_DA: usize = 3; // + D_ext[j mod 4]
    pub const XM_ADD_D0: usize = 4; // + D_ext[0]
    pub const XM_ADD_DBASE: usize = 5; // + D[2(j mod 4)] (base, embedded)
    pub const XM_ADD_NEXT: usize = 6; // + X[(j+1) mod 8]
    pub const XM_ADD_E: usize = 7; // + E[j mod 4]
    pub const XM_SUB_E: usize = 8;
    pub const XM_ADD_PT0: usize = 9;
    pub const XM_SUB_PT0: usize = 10;
    pub const XM_ADD_ONE: usize = 11;
    pub const XM_ADD_X2J: usize = 12; // + X[2j mod 8]
    pub const XM_ADD_F0: usize = 13;
    /// 4 environments × 6 (CLR, FROM_X, FROM_CH, FROM_Y0, FROM_E0, FROM_RS0).
    pub const EMOVE: usize = 225;
    pub const EM_STRIDE: usize = 6;
    pub const EM_CLR: usize = 0;
    pub const EM_FROM_X: usize = 1;
    pub const EM_FROM_CH: usize = 2;
    pub const EM_FROM_Y0: usize = 3;
    pub const EM_FROM_E0: usize = 4;
    pub const EM_FROM_RS0: usize = 5;
    pub const PT_PUSH: usize = 249; // push E[0]
    pub const PT_ROT: usize = 250; // head ← next
    pub const PT_ROT_UP: usize = 251; // head ← tail
    pub const F_ROT: usize = 252; // head ← next
    /// H12 §12 C (F half): set with `BANK_ABSORB` / `BANK_UNWIND`, the bank row works the FK fold stack instead of
    /// BK (absorb `X[0]`; unwind `D[8..16] ‖ D_ext[1]`) and leaves BK and VB untouched.
    pub const FBANK: usize = 253;
    pub const F_PUSH2: usize = 254; // push D_ext[0], D_ext[1] at the tail
    pub const F_ROT_UP: usize = 255; // head ← tail
    pub const F_PUSH1: usize = 277; // push X[0] at the tail
    /// H12 §12 C: `BK ← compress_prod(BK ‖ VAR ‖ BANK_TAG)` — push this query's g^index on the VB stack (a row of
    /// its own: it takes the row's permutation).
    pub const BANK_ABSORB: usize = 256;
    /// H12 §12 C: pop the VB stack — `compress_prod(D[0..8] ‖ D[8] ‖ BANK_TAG) == BK`, `BK' = D[0..8]`, and `D[8]` is
    /// pushed at VB's tail (four pops load a select group). A forged value needs a second preimage of the compression.
    pub const BANK_UNWIND: usize = 257;
    pub const VB_SQ4: usize = 258; // VB[0..4] ← VB[0..4]²
    pub const Y_PUSH: usize = 259; // push E[0]
    pub const Y_ROT: usize = 260;
    pub const RS_PUSH: usize = 261; // push E[0]
    pub const RS_ROT: usize = 262;
    pub const ROOT_CHECK: usize = 263;
    /// Assert `X'_0 == X'_4`.
    pub const EXT_EQ: usize = 264;
    /// The proof-of-work check on pop unit 0 (`GrindingChallenger::check_witness`: the witness was absorbed, ONE
    /// sample popped, its low `bits` must all be zero). `bits` is the row constant `pow_init`, or the round
    /// one-hot's table entry `fold_pow[rf]` / `query_pow[rf]`.
    pub const POW_INIT: usize = 265;
    pub const POW_FOLD: usize = 266;
    pub const POW_QUERY: usize = 267;
    pub const R_CAPTURE: usize = 268; // R2 ← D[0..8]
    pub const R_SHIFT: usize = 269; // R ← R2
    /// Load `G` from the round table and `VAR = 1`.
    pub const G_INIT: usize = 270;
    /// `VAR *= 1 + B[0]·(G − 1)`, then `G = G²`.
    pub const G_STEP: usize = 271;
    /// Every state register is zero (the program's first row).
    pub const INIT: usize = 272;
    /// `PS' == io[0..8]` — the program digest (the program's row `T − 2`).
    pub const FINAL: usize = 273;
    /// 3 (+ `IOCHK_3`): `D[0..8] == io[IO_PAD + 8p ..]` — statement block `p`; every reader goes through [`iochk`].
    pub const IOCHK: usize = 274;
    /// M5: `TSUM' := held + samples + X0[0]` (the register's base coefficient) and `tbits[24] = tbits[25] = 0` — a
    /// 24-bit RANGE CHECK riding the row's existing 26-bit decomposition (used with `TCLEAR` and no pops: `TSUM' =
    /// X0[0] < 2^24`). Reads the REGISTER so the checked value is the one the row loaded or computed, never a second
    /// stream copy.
    pub const RANGE24: usize = 278;
    // ── the 10th flag word (2026-09-28): the moves the weight walks and the Spartan core need ──────────────────
    /// 8: `X_j += X_{(j+4) mod 8}` — the other half's register.
    pub const XM2_ADD_X4J: usize = 279;
    /// 8: `X_j += X_{(j+7) mod 8}` — the previous register.
    pub const XM2_ADD_PREV: usize = 287;
    /// 4: mul `k` takes `RS[0]` on its b side (an eleventh b-menu entry, one-hot with the other ten).
    pub const BM2_RS0: usize = 295;
    /// 4: `E_k ← X_{k+4}`.
    pub const EM2_FROM_X4: usize = 299;
    /// M5: the FOURTH statement block (`io[IO_PAD + 24 ..]`, the state hash) — bit 303 was `Y_ROT_UP`, a bank move
    /// no emitter ever set (deleted 2026-09-28; the row is not a library of unused moves).
    pub const IOCHK_3: usize = 303;
    /// `RS` rotated up (head ← tail).
    pub const RS_ROT_UP: usize = 304;
    /// M5: the base-case statement check on the leaf row carrying the INNER program digest: `(D_k − io_k)·(D_k −
    /// G_k) = 0` per lane with `G = RowParams::base_digest` (the genesis program's digest) and `io_k` the OUTER
    /// program digest — the inner proof is a proof of THIS program or of the genesis program, nothing else. Bit 305
    /// was `VB_ROT1` (never set by an emitter; deleted 2026-09-28).
    pub const IOCHK_BASE: usize = 305;
    /// 4: round one-hot slots `6..10` (the `RF` block holds `0..6`); every reader goes through [`rf`].
    pub const RF2: usize = 306;
    /// The last flag in use (310 ≤ FLAG_BITS).
    pub const LAST: usize = 309;

    /// The one-hot flag of round-table slot `rr` (`RF + rr` below six, `RF2 + rr − 6` above).
    pub const fn rf(rr: usize) -> usize {
        assert!(rr < super::NROUNDS);
        if rr < 6 {
            RF + rr
        } else {
            RF2 + rr - 6
        }
    }
    /// The statement-block check flag of io block `p` (`IOCHK + p` below three, `IOCHK_3` for the state hash).
    pub const fn iochk(p: usize) -> usize {
        assert!(p < 4);
        if p < 3 {
            IOCHK + p
        } else {
            IOCHK_3
        }
    }
}

/// One row's instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowFlags(pub [bool; FLAG_BITS]);

impl Default for RowFlags {
    fn default() -> Self {
        RowFlags([false; FLAG_BITS])
    }
}

impl RowFlags {
    pub fn set(&mut self, i: usize) -> &mut Self {
        self.0[i] = true;
        self
    }
    pub fn is_set(&self, i: usize) -> bool {
        self.0[i]
    }
    /// Pop unit `c` reads `O[slot]`: three slot bits plus the active bit.
    pub fn pop(&mut self, c: usize, slot: usize) -> &mut Self {
        assert!(slot < RATE);
        let base = flag::POPU + flag::POPU_STRIDE * c;
        for i in 0..3 {
            if (slot >> i) & 1 == 1 {
                self.set(base + i);
            }
        }
        self.set(base + 3)
    }
    /// Pop units `0..4` read `O[start], O[start−1], O[start−2], O[start−3]` — an aligned-or-not Ea4 challenge.
    pub fn pop_ext(&mut self, start: usize) -> &mut Self {
        for c in 0..NPOPU {
            self.pop(c, start - c);
        }
        self
    }
    pub fn mul_a(&mut self, k: usize, entry: usize) -> &mut Self {
        self.set(flag::MUL + flag::MUL_STRIDE * k + entry)
    }
    pub fn mul_b(&mut self, k: usize, entry: usize) -> &mut Self {
        self.set(flag::MUL + flag::MUL_STRIDE * k + flag::A_MENU + entry)
    }
    pub fn xmove(&mut self, j: usize, term: usize) -> &mut Self {
        self.set(flag::XMOVE + flag::XM_STRIDE * j + term)
    }
    pub fn emove(&mut self, i: usize, term: usize) -> &mut Self {
        self.set(flag::EMOVE + flag::EM_STRIDE * i + term)
    }
    /// The flag words the row absorbs: bit `j` of word `w` is flag `31·w + j`.
    pub fn words(&self) -> [Fa4; NFLAG_WORDS] {
        core::array::from_fn(|w| {
            let mut v = 0u64;
            for j in 0..31 {
                if self.0[31 * w + j] {
                    v |= 1 << j;
                }
            }
            Fa4::from_u64(v)
        })
    }
}

/// The row's circuit constants: the three Poseidon2 instances, the per-round domain tables, the PT read port.
#[derive(Clone, Debug)]
pub struct RowParams {
    pub transcript: P2Consts,
    pub merkle: P2Consts,
    pub program: P2Consts,
    /// Per round: `folded_domain_gen` and `k = log2(folded domain size)` (≤ 24).
    pub gens: [Fa4; NROUNDS],
    pub ks: [usize; NROUNDS],
    /// The constant `PT` read index (`m_vars − 1` for the Spartan core's `τ_i` at round `i`).
    pub pt_port: usize,
    /// Proof-of-work bit counts (`check_witness`, each `< 31`), per round-table slot: a WHIR run's initial sumcheck
    /// (at the run's FIRST slot — a uniform certificate runs two WHIRs whose initial counts differ), and per round the
    /// sumcheck's and the STIR queries' (the final round at the run's last slot). Zero: no witness is sent or checked.
    pub init_pow: [usize; NROUNDS],
    pub fold_pow: [usize; NROUNDS],
    pub query_pow: [usize; NROUNDS],
    /// M5: the GENESIS program's digest — the one other program an inner proof may be of (`IOCHK_BASE`). Zero until
    /// [`RowParams::with_base_digest`]: no program's digest is the all-zero word block (a permutation chain output), so
    /// a row program that checks against zero accepts only its own digest.
    pub base_digest: [Fa4; RATE],
}

impl RowParams {
    /// The genesis program's digest (`program_digest` of the genesis rows at the same `T`).
    pub fn with_base_digest(mut self, base_digest: [Fa4; RATE]) -> Self {
        self.base_digest = base_digest;
        self
    }
    /// The decider's instances: the Spartan transcript seed, the committed PCS seed (Merkle hash), and the
    /// production permutation for the program sponge.
    pub fn decider(gens: [Fa4; NROUNDS], ks: [usize; NROUNDS], pt_port: usize) -> Self {
        assert!(ks.iter().all(|&k| k <= NB), "a folded domain of at most 2^24");
        assert!(pt_port < NPT);
        RowParams {
            transcript: P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31),
            merkle: P2Consts::for_seed(crate::committed_air::COMMITTED_AIR_SEED),
            program: P2Consts::for_seed(crate::whir_rec_block::REC_DECIDER_SEED),
            gens,
            ks,
            pt_port,
            init_pow: [0; NROUNDS],
            fold_pow: [0; NROUNDS],
            query_pow: [0; NROUNDS],
            base_digest: [Fa4::ZERO; RATE],
        }
    }
    /// The proof-of-work tables. Each count is below 31 (`sample_bits` needs `2^bits < p`).
    pub fn with_pow(mut self, init_pow: [usize; NROUNDS], fold_pow: [usize; NROUNDS], query_pow: [usize; NROUNDS]) -> Self {
        assert!(init_pow.iter().chain(fold_pow.iter()).chain(query_pow.iter()).all(|&b| b < 31), "a pow count below 31 bits");
        self.init_pow = init_pow;
        self.fold_pow = fold_pow;
        self.query_pow = query_pow;
        self
    }
}

/// One step's inputs as values.
#[derive(Clone, Debug)]
pub struct RowIn {
    pub regs: [Fa4; NREG],
    pub d: [Fa4; NSTREAM],
    pub fw: [Fa4; NFLAG_WORDS],
}

impl RowIn {
    pub fn zero() -> Self {
        RowIn { regs: [Fa4::ZERO; NREG], d: [Fa4::ZERO; NSTREAM], fw: [Fa4::ZERO; NFLAG_WORDS] }
    }
}

fn ext_at(regs: &[Lc], off: usize) -> ExtLc {
    ExtLc(core::array::from_fn(|i| regs[off + i].clone()))
}
fn base_ext(x: &Lc) -> ExtLc {
    ExtLc([x.clone(), Lc::default(), Lc::default(), Lc::default()])
}
/// `cur + flag·(alt − cur)` per coefficient: a flagged Ea4 move, four products.
fn ext_sel(b: &mut R1csBuilder, flag: &Lc, alt: &ExtLc, cur: &ExtLc) -> ExtLc {
    ExtLc(core::array::from_fn(|i| sel(b, flag, &alt.0[i], &cur.0[i])))
}

/// Build one step. The inputs are allocated first, in the fixed local order (registers, stream, flag words);
/// every output register is pinned to the next step's placeholder column. Returns the next registers' values.
pub fn universal_row(b: &mut R1csBuilder, p: &RowParams, input: &RowIn) -> [Fa4; NREG] {
    let zero = Lc::default();
    let one = Lc::constant(Fa4::ONE);
    let regs: Vec<Lc> = input.regs.iter().map(|&v| b.witness(v)).collect();
    let d: Vec<Lc> = input.d.iter().map(|&v| b.witness(v)).collect();
    let fw: Vec<Lc> = input.fw.iter().map(|&v| b.witness(v)).collect();
    // the ONE local (see `ONE_LOCAL`): allocated before any intermediate so its index is fixed; pinned to 1 by the
    // template's appended constraint, never by anything here
    let _one_local = b.witness(Fa4::ONE);
    // §M6-E: the layout check reads the builder's allocation cursor, not the wire's terms (a values-only wire has none)
    assert_eq!(b.last_var(), b.assignment().len() / 2 + ONE_LOCAL, "the ONE local sits at ONE_LOCAL");
    let mut flags: Vec<Lc> = Vec::with_capacity(FLAG_BITS);
    for w in &fw {
        flags.extend(canonical_bits(b, w));
    }
    let f = |i: usize| flags[i].clone();
    let io_w: Vec<Lc> = (0..IO_LEN).map(|c| b.io(c)).collect();
    let io = |c: usize| io_w[c].clone();
    let s: Vec<Lc> = regs[S_OFF..S_OFF + WIDTH].to_vec();
    let o: Vec<Lc> = regs[O_OFF..O_OFF + RATE].to_vec();
    let h: Vec<Lc> = regs[H_OFF..H_OFF + WIDTH].to_vec();
    let ps: Vec<Lc> = regs[PS_OFF..PS_OFF + WIDTH].to_vec();
    let r: Vec<Lc> = regs[R_OFF..R_OFF + RATE].to_vec();
    let r2: Vec<Lc> = regs[R2_OFF..R2_OFF + RATE].to_vec();
    let x: Vec<ExtLc> = (0..NX).map(|k| ext_at(&regs, X_OFF + 4 * k)).collect();
    let e: Vec<ExtLc> = (0..NE).map(|k| ext_at(&regs, E_OFF + 4 * k)).collect();
    let bbits: Vec<Lc> = regs[B_OFF..B_OFF + NB].to_vec();
    let g = regs[G_OFF].clone();
    let var = regs[VAR_OFF].clone();
    let tsum = regs[TSUM_OFF].clone();
    let bk: Vec<Lc> = regs[BK_OFF..BK_OFF + RATE].to_vec();
    let fk: Vec<Lc> = regs[FK_OFF..FK_OFF + RATE].to_vec();
    let pt: Vec<ExtLc> = (0..NPT).map(|k| ext_at(&regs, PT_OFF + 4 * k)).collect();
    let vb: Vec<Lc> = regs[VB_OFF..VB_OFF + NVB].to_vec();
    let y: Vec<ExtLc> = (0..NY).map(|k| ext_at(&regs, Y_OFF + 4 * k)).collect();
    let rs: Vec<ExtLc> = (0..NRS).map(|k| ext_at(&regs, RS_OFF + 4 * k)).collect();
    let fb: Vec<ExtLc> = (0..NF).map(|k| ext_at(&regs, F_OFF + 4 * k)).collect();
    let d_ext: Vec<ExtLc> = (0..4).map(|k| ext_at(&d, 4 * k)).collect();

    // 1. the permutation: input routing by mode, constants blended by mode, output routing by mode
    let (m_absorb, m_merkle, m_leaf, h_reset) = (f(flag::M_ABSORB), f(flag::M_MERKLE), f(flag::M_LEAF), f(flag::H_RESET));
    let bit0 = bbits[0].clone();
    let mut t_in: Vec<Lc> = s.clone();
    for k in 0..RATE {
        t_in[k] = sel(b, &f(flag::A + k), &d[k], &s[k]);
    }
    let hz: Vec<Lc> = (0..WIDTH).map(|k| sel(b, &h_reset, &zero, &h[k])).collect();
    let mut l_in: Vec<Lc> = hz.clone();
    for k in 0..RATE {
        l_in[k] = sel(b, &f(flag::A + k), &d[k], &hz[k]);
    }
    let mut m_in: Vec<Lc> = Vec::with_capacity(WIDTH);
    for k in 0..RATE {
        m_in.push(sel(b, &bit0, &d[k], &h[k]));
    }
    for k in 0..RATE {
        m_in.push(sel(b, &bit0, &h[k], &d[k]));
    }
    // M5: `M_MERKLE ∧ M_LEAF` (an otherwise meaningless combination) is the PRODUCTION mode — the chain-wide
    // `compress(left, right)` = `production_perm([left ‖ right])[0..8]` (`poseidon2_compress`), whose 16 data lanes
    // are `[X0 ‖ X1 (eight base coefficients) ‖ D[0..8]]` here. With `mp = m_merkle·m_leaf` every weight below is
    // linear in locals; no flag bit is spent.
    let mp = b.mul(&m_merkle, &m_leaf);
    let prod_in: Vec<Lc> = (0..WIDTH)
        .map(|k| if k < 4 { x[0].0[k].clone() } else if k < RATE { x[1].0[k - 4].clone() } else { d[k - RATE].clone() })
        .collect();
    let (w_merkle, w_leaf) = (m_merkle.add(&mp.scale(-Fa4::ONE)), m_leaf.add(&mp.scale(-Fa4::ONE)));
    let perm_in: [Lc; WIDTH] = core::array::from_fn(|k| {
        let base = t_in[k].clone();
        let dm = b.mul(&w_merkle, &m_in[k].add(&base.scale(-Fa4::ONE)));
        let dl = b.mul(&w_leaf, &l_in[k].add(&base.scale(-Fa4::ONE)));
        let dp = b.mul(&mp, &prod_in[k].add(&base.scale(-Fa4::ONE)));
        base.add(&dm).add(&dl).add(&dp)
    });
    // H12 §12 C: the bank mode — the production compression over `[BK ‖ VAR ‖ TAG ‖ 0…]` (absorb) or
    // `[D[0..8] ‖ D[8] ‖ TAG ‖ 0…]` (unwind); the emitter gives a bank row no other permutation mode
    let (bank_absorb, bank_unwind) = (f(flag::BANK_ABSORB), f(flag::BANK_UNWIND));
    let fbank = f(flag::FBANK);
    let (f_absorb, f_unwind) = (b.mul(&fbank, &bank_absorb), b.mul(&fbank, &bank_unwind));
    let (vb_absorb, vb_unwind) = (bank_absorb.add(&f_absorb.scale(-Fa4::ONE)), bank_unwind.add(&f_unwind.scale(-Fa4::ONE)));
    let w_bank = bank_absorb.add(&bank_unwind);
    // FK's input `[FK ‖ X[0] ‖ 0…] / [D[8..16] ‖ D_ext[1] ‖ 0…]` and BK's `[BK ‖ VAR ‖ TAG ‖ 0…] / [D[0..8] ‖ D[8] ‖
    // TAG ‖ 0…]`; FK's tag rides lane 12 (`fbank·FBANK_TAG`, linear), BK's lane 9
    let perm_in: [Lc; WIDTH] = core::array::from_fn(|k| {
        let bank_in = if k < RATE {
            let src = sel(b, &fbank, &fk[k], &bk[k]);
            let dsrc = sel(b, &fbank, &d[RATE + k], &d[k]);
            sel(b, &bank_absorb, &src, &dsrc)
        } else if k == RATE {
            let src = sel(b, &fbank, &x[0].0[0], &var);
            let dsrc = sel(b, &fbank, &d[4], &d[RATE]);
            sel(b, &bank_absorb, &src, &dsrc)
        } else if k < RATE + 4 {
            let w = k - RATE;
            let fv = sel(b, &bank_absorb, &x[0].0[w], &d[4 + w]);
            let vb_lane = if k == RATE + 1 { Lc::constant(Fa4::from_u64(BANK_TAG)) } else { zero.clone() };
            sel(b, &fbank, &fv, &vb_lane)
        } else if k == RATE + 4 {
            fbank.scale(Fa4::from_u64(FBANK_TAG))
        } else {
            zero.clone()
        };
        let db = b.mul(&w_bank, &bank_in.add(&perm_in[k].scale(-Fa4::ONE)));
        perm_in[k].add(&db)
    });
    let hash_mode = m_merkle.add(&m_leaf).add(&mp.scale(-Fa4::ONE));
    let blend = [
        (&p.transcript, one.add(&hash_mode.scale(-Fa4::ONE)).add(&w_bank.scale(-Fa4::ONE))),
        (&p.merkle, hash_mode.add(&mp.scale(-Fa4::ONE))),
        (&p.program, mp.add(&w_bank)),
    ];
    let p_out = poseidon2_permutation_blend(b, &blend, &perm_in);
    let bk_next: Vec<Lc> = (0..RATE)
        .map(|k| {
            b.constrain(&vb_unwind, &p_out[k].add(&bk[k].scale(-Fa4::ONE)), &zero);
            let popped = sel(b, &vb_unwind, &d[k], &bk[k]);
            sel(b, &vb_absorb, &p_out[k], &popped)
        })
        .collect();
    let fk_next: Vec<Lc> = (0..RATE)
        .map(|k| {
            b.constrain(&f_unwind, &p_out[k].add(&fk[k].scale(-Fa4::ONE)), &zero);
            let popped = sel(b, &f_unwind, &d[RATE + k], &fk[k]);
            sel(b, &f_absorb, &p_out[k], &popped)
        })
        .collect();
    let s_next: Vec<Lc> = (0..WIDTH).map(|k| sel(b, &m_absorb, &p_out[k], &s[k])).collect();
    let h_next: Vec<Lc> = (0..WIDTH).map(|k| sel(b, &hash_mode, &p_out[k], &hz[k])).collect();

    // 2. the output buffer, the pop units and the challenge
    let o_next: Vec<Lc> = (0..RATE).map(|k| sel(b, &m_absorb, &p_out[k], &o[k])).collect();
    let units: Vec<Lc> = (0..NPOPU)
        .map(|c| {
            let base = flag::POPU + flag::POPU_STRIDE * c;
            let bits: [Lc; 3] = core::array::from_fn(|i| f(base + i));
            let active = f(base + 3);
            let mut acc = zero.clone();
            for sl in 0..RATE {
                let lit = |i: usize| if (sl >> i) & 1 == 1 { bits[i].clone() } else { one.add(&bits[i].scale(-Fa4::ONE)) };
                let t01 = b.mul(&lit(0), &lit(1));
                let t = b.mul(&t01, &lit(2));
                acc = acc.add(&b.mul(&t, &o_next[sl]));
            }
            b.mul(&active, &acc)
        })
        .collect();
    let ch_ext = ExtLc(core::array::from_fn(|c| units[c].clone()));

    // 3. the multiplications, the moves, the banks
    let pairdiff = |_k: usize| -> ExtLc { d_ext[1].sub(&d_ext[0]) };
    let basepair = |k: usize| -> ExtLc { base_ext(&d[2 * k + 1].add(&d[2 * k].scale(-Fa4::ONE))) };
    let muls: Vec<ExtLc> = (0..4)
        .map(|k| {
            let a_menu = [
                x[k].clone(),
                x[k + 4].clone(),
                d_ext[k].clone(),
                e[k].clone(),
                pairdiff(k),
                basepair(k),
                pt[0].clone(),
                x[2 * k + 1].sub(&x[2 * k]),
            ];
            let b_menu = [
                x[k + 4].clone(),
                e[k].clone(),
                e[0].clone(),
                ch_ext.clone(),
                pt[0].clone(),
                fb[0].clone(),
                pt[p.pt_port].clone(),
                y[0].clone(),
                base_ext(&vb[k]),
                base_ext(&var),
            ];
            let base = flag::MUL + flag::MUL_STRIDE * k;
            let a_sel = select_ext(b, &flags[base..base + flag::A_MENU], &a_menu);
            let b_sel = select_ext(b, &flags[base + flag::A_MENU..base + flag::MUL_STRIDE], &b_menu);
            let b_sel = b_sel.add(&ext_scale_wire(b, &rs[0], &flags[flag::BM2_RS0 + k])); // the eleventh entry
            ext_mul(b, &a_sel, &b_sel)
        })
        .collect();
    let one_ext = ExtLc::constant(Ea4::ONE);
    let x_next: Vec<ExtLc> = (0..NX)
        .map(|j| {
            let fl = |t: usize| flags[flag::XMOVE + flag::XM_STRIDE * j + t].clone();
            let held = ext_scale_wire(b, &x[j], &one.add(&fl(flag::XM_CLR).scale(-Fa4::ONE)));
            let m = muls[j % 4].clone();
            let terms: [(Lc, ExtLc); 15] = [
                (flags[flag::XM2_ADD_X4J + j].clone(), x[(j + 4) % NX].clone()),
                (flags[flag::XM2_ADD_PREV + j].clone(), x[(j + NX - 1) % NX].clone()),
                (fl(flag::XM_ADD_MUL), m.clone()),
                (fl(flag::XM_SUB_MUL), m.scale_base(-Fa4::ONE)),
                (fl(flag::XM_ADD_DA), d_ext[j % 4].clone()),
                (fl(flag::XM_ADD_D0), d_ext[0].clone()),
                (fl(flag::XM_ADD_DBASE), base_ext(&d[2 * (j % 4)])),
                (fl(flag::XM_ADD_NEXT), x[(j + 1) % NX].clone()),
                (fl(flag::XM_ADD_E), e[j % 4].clone()),
                (fl(flag::XM_SUB_E), e[j % 4].scale_base(-Fa4::ONE)),
                (fl(flag::XM_ADD_PT0), pt[0].clone()),
                (fl(flag::XM_SUB_PT0), pt[0].scale_base(-Fa4::ONE)),
                (fl(flag::XM_ADD_ONE), one_ext.clone()),
                (fl(flag::XM_ADD_X2J), x[(2 * j) % NX].clone()),
                (fl(flag::XM_ADD_F0), fb[0].clone()),
            ];
            terms.iter().fold(held, |acc, (fl, t)| acc.add(&ext_scale_wire(b, t, fl)))
        })
        .collect();
    let mut e_next: Vec<ExtLc> = (0..NE)
        .map(|i| {
            let fl = |t: usize| flags[flag::EMOVE + flag::EM_STRIDE * i + t].clone();
            let held = ext_scale_wire(b, &e[i], &one.add(&fl(flag::EM_CLR).scale(-Fa4::ONE)));
            let terms: [(Lc, ExtLc); 6] = [
                (flags[flag::EM2_FROM_X4 + i].clone(), x[i + 4].clone()),
                (fl(flag::EM_FROM_X), x[i].clone()),
                (fl(flag::EM_FROM_CH), ch_ext.clone()),
                (fl(flag::EM_FROM_Y0), y[0].clone()),
                (fl(flag::EM_FROM_E0), e[0].clone()),
                (fl(flag::EM_FROM_RS0), rs[0].clone()),
            ];
            terms.iter().fold(held, |acc, (fl, t)| acc.add(&ext_scale_wire(b, t, fl)))
        })
        .collect();
    // the latches: pop unit c into coefficient c of E[0]
    e_next[0] = ExtLc(core::array::from_fn(|c| sel(b, &f(flag::LATCH + c), &units[c], &e_next[0].0[c])));
    // PT: pushed from E[0]; rotated down (head ← next) or up (head ← tail)
    let (pt_push, pt_rot, pt_rot_up) = (f(flag::PT_PUSH), f(flag::PT_ROT), f(flag::PT_ROT_UP));
    let pt_next: Vec<ExtLc> = (0..NPT)
        .map(|i| {
            let down = ext_sel(b, &pt_rot, &pt[(i + 1) % NPT], &pt[i]);
            let up = ext_sel(b, &pt_rot_up, &pt[(i + NPT - 1) % NPT], &down);
            let pushed = if i == 0 { e[0].clone() } else { pt[i - 1].clone() };
            ext_sel(b, &pt_push, &pushed, &up)
        })
        .collect();
    // F: two stream coefficients pushed at the tail; rotated up (head ← tail) for Horner
    let (f_push2, f_push1, f_rot_up, f_rot) = (f(flag::F_PUSH2), f(flag::F_PUSH1), f(flag::F_ROT_UP), f(flag::F_ROT));
    let f_next: Vec<ExtLc> = (0..NF)
        .map(|i| {
            let down = ext_sel(b, &f_rot, &fb[(i + 1) % NF], &fb[i]);
            let up = ext_sel(b, &f_rot_up, &fb[(i + NF - 1) % NF], &down);
            let src2 = if i + 2 < NF { fb[i + 2].clone() } else { d_ext[i + 2 - NF].clone() };
            let after2 = ext_sel(b, &f_push2, &src2, &up);
            let src1 = if i + 1 < NF { fb[i + 1].clone() } else { x[0].clone() };
            ext_sel(b, &f_push1, &src1, &after2)
        })
        .collect();
    // VB: the select group's four g^index values — squared in place, loaded at the tail by the bank's pops
    let vb_sq4 = f(flag::VB_SQ4);
    let vb_next: Vec<Lc> = (0..NVB)
        .map(|i| {
            let sq = b.mul(&vb[i], &vb[i]);
            let squared = sel(b, &vb_sq4, &sq, &vb[i]);
            let loaded = if i + 1 < NVB { vb[i + 1].clone() } else { d[RATE].clone() };
            sel(b, &vb_unwind, &loaded, &squared)
        })
        .collect();
    // Y: pushed from E[0], rotated down
    let (y_push, y_rot) = (f(flag::Y_PUSH), f(flag::Y_ROT));
    let y_next: Vec<ExtLc> = (0..NY)
        .map(|i| {
            let rotated = ext_sel(b, &y_rot, &y[(i + 1) % NY], &y[i]);
            let pushed = if i == 0 { e[0].clone() } else { y[i - 1].clone() };
            ext_sel(b, &y_push, &pushed, &rotated)
        })
        .collect();
    // RS: pushed from E[0], rotated down
    let (rs_push, rs_rot, rs_rot_up) = (f(flag::RS_PUSH), f(flag::RS_ROT), f(flag::RS_ROT_UP));
    let rs_next: Vec<ExtLc> = (0..NRS)
        .map(|i| {
            let rotated = ext_sel(b, &rs_rot, &rs[(i + 1) % NRS], &rs[i]);
            let up = ext_sel(b, &rs_rot_up, &rs[(i + NRS - 1) % NRS], &rotated);
            let pushed = if i == 0 { e[0].clone() } else { rs[i - 1].clone() };
            ext_sel(b, &rs_push, &pushed, &up)
        })
        .collect();

    // 4. the STIR draw: four canonical decompositions of the pop units, masked to the round's k bits, into TSUM
    let kmask: Vec<Lc> = (0..NB)
        .map(|j| (0..NROUNDS).filter(|&rr| j < p.ks[rr]).fold(zero.clone(), |acc, rr| acc.add(&f(flag::rf(rr)))))
        .collect();
    let kmask_v: Vec<bool> = (0..NB).map(|j| b.value_of(&kmask[j]) == Fa4::ONE).collect();
    let mut t_row = zero.clone();
    let mut t_row_v = 0u64;
    let mut unit_bits: Vec<Vec<Lc>> = Vec::with_capacity(NPOPU);
    for unit in units.iter() {
        let sv = b.value_of(unit).as_canonical_u64();
        let bits = canonical_bits(b, unit);
        for j in 0..NB {
            let m = b.mul(&kmask[j], &bits[j]);
            t_row = t_row.add(&m.scale(Fa4::from_u64(1u64 << j)));
            if kmask_v[j] {
                t_row_v += sv & (1u64 << j);
            }
        }
        unit_bits.push(bits);
    }
    // 4b. the proof of work (`GrindingChallenger::check_witness`): the witness was absorbed, ONE sample was popped
    // into unit 0, and its low `bits` must all be zero — a sum of booleans is zero iff each is. `bits` is a row
    // constant selected by the round one-hot: the run's initial count at its first slot (`POW_INIT`), or the slot's
    // sumcheck / query count. Skipping this would accept an un-ground proof; the pow bits are part of the PCS's
    // security budget (`folding_pow_bits = security − min(error terms)`). The one-hot also selects `kmask`, so the
    // popped sample's masked value enters `t_row` on this row: a pow row carries `TCLEAR` (the builder's `pop_pow`),
    // or the sum carried from the last draw overflows the 26-bit decomposition below (FOUND 2026-09-28, k = 24).
    {
        let low_sum = |n: usize| unit_bits[0][..n].iter().fold(zero.clone(), |acc, bit| acc.add(bit));
        for rr in 0..NROUNDS {
            let pi = b.mul(&f(flag::POW_INIT), &f(flag::rf(rr)));
            b.constrain(&pi, &low_sum(p.init_pow[rr]), &zero);
            let pf = b.mul(&f(flag::POW_FOLD), &f(flag::rf(rr)));
            b.constrain(&pf, &low_sum(p.fold_pow[rr]), &zero);
            let pq = b.mul(&f(flag::POW_QUERY), &f(flag::rf(rr)));
            b.constrain(&pq, &low_sum(p.query_pow[rr]), &zero);
        }
    }
    let tclear = f(flag::TCLEAR);
    let held = b.mul(&one.add(&tclear.scale(-Fa4::ONE)), &tsum);
    // M5 `RANGE24`: `X0`'s base coefficient joins the sum, and the decomposition's two top bits must be zero —
    // `X0[0] < 2^24`. The register, not a stream word: a value range-checked here was LOADED from the row that also
    // hashes it (or computed), so no second stream copy has to be bound to the first.
    let range24 = f(flag::RANGE24);
    let range_word = b.mul(&range24, &x[0].0[0]);
    let tsum_next = held.add(&t_row).add(&range_word);
    let tsum_v = if b.value_of(&tclear) == Fa4::ONE { 0 } else { b.value_of(&tsum).as_canonical_u64() }
        + t_row_v
        + if b.value_of(&range24) == Fa4::ONE { b.value_of(&x[0].0[0]).as_canonical_u64() } else { 0 };
    let tbits: Vec<Lc> = (0..NB + 2).map(|j| b.witness(Fa4::from_u64((tsum_v >> j) & 1))).collect();
    let mut tsum_bits = zero.clone();
    for (j, t) in tbits.iter().enumerate() {
        b.constrain(t, t, t);
        tsum_bits = tsum_bits.add(&t.scale(Fa4::from_u64(1u64 << j)));
    }
    b.enforce_eq(&tsum_bits, &tsum_next);
    b.constrain(&range24, &tbits[NB].add(&tbits[NB + 1]), &zero);
    let idx_bits: Vec<Lc> = (0..NB).map(|j| b.mul(&kmask[j], &tbits[j])).collect();
    let (stir, bshift) = (f(flag::STIR), f(flag::BSHIFT));
    let b_next: Vec<Lc> = (0..NB)
        .map(|j| {
            let shifted = if j + 1 < NB { bbits[j + 1].clone() } else { zero.clone() };
            let base = sel(b, &bshift, &shifted, &bbits[j]);
            sel(b, &stir, &idx_bits[j], &base)
        })
        .collect();

    // 5. the domain-generator power and g^index
    let gen_const = (0..NROUNDS).fold(zero.clone(), |acc, rr| acc.add(&f(flag::rf(rr)).scale(p.gens[rr])));
    let (g_init, g_step) = (f(flag::G_INIT), f(flag::G_STEP));
    let g_sq = b.mul(&g, &g);
    let g_after = sel(b, &g_step, &g_sq, &g);
    let g_next = sel(b, &g_init, &gen_const, &g_after);
    let factor = one.add(&b.mul(&bit0, &g.add_const(-Fa4::ONE)));
    let var_stepped = b.mul(&var, &factor);
    let var_after = sel(b, &g_step, &var_stepped, &var);
    let var_next = sel(b, &g_init, &one, &var_after);

    // 6. the roots and the assertions
    let r2_next: Vec<Lc> = (0..RATE).map(|k| sel(b, &f(flag::R_CAPTURE), &d[k], &r2[k])).collect();
    let r_next: Vec<Lc> = (0..RATE).map(|k| sel(b, &f(flag::R_SHIFT), &r2[k], &r[k])).collect();
    for k in 0..RATE {
        b.constrain(&f(flag::ROOT_CHECK), &h_next[k].add(&r_next[k].scale(-Fa4::ONE)), &zero);
    }
    for c in 0..4 {
        b.constrain(&f(flag::EXT_EQ), &x_next[0].0[c].add(&x_next[4].0[c].scale(-Fa4::ONE)), &zero);
    }

    // 7. the program sponge and the statement rows
    let mut ps_in: [Lc; WIDTH] = core::array::from_fn(|k| ps[k].clone());
    for i in 0..NFLAG_WORDS {
        ps_in[i] = fw[i].clone();
    }
    let ps_next = poseidon2_permutation_blend(b, &[(&p.program, one.clone())], &ps_in);
    let init = f(flag::INIT);
    for reg in regs.iter().take(NSTATE) {
        b.constrain(&init, reg, &zero);
    }
    let final_ = f(flag::FINAL);
    for k in 0..RATE {
        b.constrain(&final_, &ps_next[k].add(&io(IO_PAD + k).scale(-Fa4::ONE)), &zero);
    }
    for pch in 0..4 {
        let chk = f(flag::iochk(pch));
        for k in 0..RATE {
            b.constrain(&chk, &d[k].add(&io(IO_PAD + RATE * pch + k).scale(-Fa4::ONE)), &zero);
        }
    }
    // M5 `IOCHK_BASE`: the inner program digest is this program's (io block 0) or the genesis program's.
    let base_chk = f(flag::IOCHK_BASE);
    for k in 0..RATE {
        let own = b.mul(&base_chk, &d[k].add(&io(IO_PAD + k).scale(-Fa4::ONE)));
        b.constrain(&own, &d[k].add_const(-p.base_digest[k]), &zero);
    }

    // 8. the hand-off
    let mut outs: Vec<Lc> = Vec::with_capacity(NREG);
    outs.extend(s_next);
    outs.extend(o_next);
    outs.extend(h_next);
    outs.extend(ps_next);
    outs.extend(r_next);
    outs.extend(r2_next);
    for xk in &x_next {
        outs.extend(xk.0.iter().cloned());
    }
    for ek in &e_next {
        outs.extend(ek.0.iter().cloned());
    }
    outs.extend(b_next);
    outs.push(g_next);
    outs.push(var_next);
    outs.push(tsum_next);
    outs.extend(bk_next);
    outs.extend(fk_next);
    for v in pt_next.iter() {
        outs.extend(v.0.iter().cloned());
    }
    outs.extend(vb_next);
    for v in y_next.iter().chain(rs_next.iter()).chain(f_next.iter()) {
        outs.extend(v.0.iter().cloned());
    }
    assert_eq!(outs.len(), NREG);
    let w_off = b.assignment().len() / 2;
    let v = 1usize << V_BITS;
    for (j, out) in outs.iter().enumerate() {
        b.enforce_eq(out, &Lc::var(w_off + v + j));
    }
    core::array::from_fn(|j| b.value_of(&outs[j]))
}

/// The builder shape a step needs: a public half for the statement and a witness half holding the locals and
/// the next-step placeholders.
pub fn step_builder(io: &[Fa4]) -> R1csBuilder {
    assert!(io.len() >= IO_LEN, "the row reads a {IO_LEN}-word statement");
    // witness half = 2^(n_vars − 1) ≥ V + NREG
    let n_vars = V_BITS + 2;
    R1csBuilder::new(n_vars, io).expect("the statement fits the public half")
}

/// [`step_builder`] in VALUES-ONLY mode (§M6-E): the same cells in the same order, every wire a term-free constant, no
/// matrix entries — what `emulate` runs per row (it reads the assignment alone; the instance is the template, built once).
pub fn step_builder_values_only(io: &[Fa4]) -> R1csBuilder {
    assert!(io.len() >= IO_LEN, "the row reads a {IO_LEN}-word statement");
    R1csBuilder::new_values_only(V_BITS + 2, io).expect("the statement fits the public half")
}

/// The template: one symbolic run of the row (values irrelevant to the structure).
pub fn template(p: &RowParams, io_len: usize) -> R1cs {
    let io = vec![Fa4::ZERO; io_len];
    let mut b = step_builder(&io);
    universal_row(&mut b, p, &RowIn::zero());
    b.finish().expect("the row fits its declared shape").0
}

/// The trace of a program: run the row per step with real values and collect each step's locals.
pub struct Trace {
    /// `T` steps × `2^V_BITS` locals, laid as the uniform instance's witness half.
    pub w: Vec<Fa4>,
    pub final_regs: [Fa4; NREG],
    pub steps: usize,
}

impl Trace {
    /// The registers AFTER row `r`: the locals of step `r + 1`, or the final registers after the last row.
    pub fn regs_after(&self, r: usize) -> Vec<Fa4> {
        let v = 1usize << V_BITS;
        if r + 1 < self.steps {
            self.w[(r + 1) * v..(r + 1) * v + NREG].to_vec()
        } else {
            self.final_regs.to_vec()
        }
    }
}

/// Emulate `program` over `stream` (one row of words per step) from `regs0`. `io` is the statement the row may
/// read. Every step's constraint count is asserted equal to the template's — a data-dependent shape is refused.
pub fn emulate(p: &RowParams, io: &[Fa4], regs0: [Fa4; NREG], program: &[RowFlags], stream: &[[Fa4; NSTREAM]]) -> Trace {
    assert_eq!(program.len(), stream.len(), "one stream row per program row");
    let v = 1usize << V_BITS;
    let mut w = vec![Fa4::ZERO; program.len() * v];
    let mut regs = regs0;
    let mut rows_seen: Option<usize> = None;
    let mut bank = BankStack::default();
    if std::env::var_os("USDM_F_LIVENESS").is_some() {
        eprintln!("[f-liveness] rows {} {:?}", program.len(), f_liveness(program));
    }
    for (g, (flags, d)) in program.iter().zip(stream).enumerate() {
        let mut d = *d;
        bank.supply(flags, &regs, &mut d);
        // §M6-E: values only — the trace is the assignment; the constraints are the template's, built once elsewhere
        let mut b = step_builder_values_only(io);
        let next = universal_row(&mut b, p, &RowIn { regs, d, fw: flags.words() });
        match rows_seen {
            None => rows_seen = Some(b.constraints()),
            Some(n) => assert_eq!(n, b.constraints(), "step {g} laid a different number of constraints"),
        }
        let z = b.assignment();
        let w_off = z.len() / 2;
        w[g * v..(g + 1) * v].copy_from_slice(&z[w_off..w_off + v]);
        regs = next;
    }
    Trace { w, final_regs: regs, steps: program.len() }
}

/// The lifted instance's verdict without materializing it: run `program` over `stream` like `emulate` and return
/// the first step whose row constraints are NOT satisfied (`None` when every step is). A step's template with its
/// next-register placeholders bound to the computed next state is exactly the instance's slice for that step, and
/// `emulate` feeds each step the previous step's outputs, so the steps' verdicts compose to the instance's.
pub fn first_unsatisfied_step(p: &RowParams, io: &[Fa4], regs0: [Fa4; NREG], program: &[RowFlags], stream: &[[Fa4; NSTREAM]]) -> Option<usize> {
    first_unsatisfied_step_of(p, io, regs0, program, stream, true)
}

/// [`first_unsatisfied_step`] over the stream EXACTLY as given — the bank pops are not re-supplied, so a tampered
/// popped value (H12 §12 C) is judged as the prover sent it.
pub fn first_unsatisfied_step_supplied(p: &RowParams, io: &[Fa4], regs0: [Fa4; NREG], program: &[RowFlags], stream: &[[Fa4; NSTREAM]]) -> Option<usize> {
    first_unsatisfied_step_of(p, io, regs0, program, stream, false)
}

/// The honest prover's bank stream: `stream` with every `BANK_UNWIND` row's words supplied from the VB stack.
pub fn supply_bank_stream(p: &RowParams, io: &[Fa4], regs0: [Fa4; NREG], program: &[RowFlags], stream: &[[Fa4; NSTREAM]]) -> Vec<[Fa4; NSTREAM]> {
    let mut regs = regs0;
    let mut bank = BankStack::default();
    // O1-INFINITY-REVIEWED: one entry per program row — the fixed verifier program, f(the proof SHAPE).
    let mut out = Vec::with_capacity(stream.len());
    for (flags, d) in program.iter().zip(stream) {
        let mut d = *d;
        bank.supply(flags, &regs, &mut d);
        let mut b = step_builder_values_only(io);
        regs = universal_row(&mut b, p, &RowIn { regs, d, fw: flags.words() });
        out.push(d);
    }
    out
}

/// H12 §12 C: the honest prover's VB stack — a `BANK_ABSORB` row pushes `(BK, VAR)` as the row reads them, a
/// `BANK_UNWIND` row takes its stream words `D[0..9]` from the pop (the emitter cannot know a g^index before the
/// program runs). An unwind of an empty stack keeps the given words: the row's check then refuses them.
#[derive(Default)]
struct BankStack(Vec<[Fa4; RATE + 1]>, Vec<[Fa4; RATE + 4]>);

impl BankStack {
    fn supply(&mut self, flags: &RowFlags, regs: &[Fa4; NREG], d: &mut [Fa4; NSTREAM]) {
        if flags.is_set(flag::FBANK) {
            // the FK fold stack: absorb pushes (FK, X[0]); unwind supplies D[8..16] ‖ D_ext[1]
            if flags.is_set(flag::BANK_ABSORB) {
                let mut e = [Fa4::ZERO; RATE + 4];
                e[..RATE].copy_from_slice(&regs[FK_OFF..FK_OFF + RATE]);
                e[RATE..].copy_from_slice(&regs[X_OFF..X_OFF + 4]);
                // O1-INFINITY-REVIEWED: one entry per pushed round fold of the program being run — f(the proof SHAPE).
                self.1.push(e);
            }
            if flags.is_set(flag::BANK_UNWIND) {
                if let Some(e) = self.1.pop() {
                    d[RATE..2 * RATE].copy_from_slice(&e[..RATE]);
                    d[4..8].copy_from_slice(&e[RATE..]);
                }
            }
            return;
        }
        if flags.is_set(flag::BANK_ABSORB) {
            let mut e = [Fa4::ZERO; RATE + 1];
            e[..RATE].copy_from_slice(&regs[BK_OFF..BK_OFF + RATE]);
            e[RATE] = regs[VAR_OFF];
            // O1-INFINITY-REVIEWED: one entry per pushed query of the program being run — f(the proof SHAPE).
            self.0.push(e);
        }
        if flags.is_set(flag::BANK_UNWIND) {
            if let Some(e) = self.0.pop() {
                d[..RATE + 1].copy_from_slice(&e);
            }
        }
    }
}

/// H12 §12 C (F half): how a program uses the F ring, measured from its flags alone. Each pushed ext is one id; a
/// read is a row whose multiplier b-menu takes `BM_F0` or whose accumulator adds `XM_ADD_F0` (both read `F[0]`).
/// `max_live` = most ids pushed and still to be read at one row — the working window F needs; `non_lifo` = reads of
/// an id that is not the newest live one; `overwritten_live` = pushes that drop a head still to be read. The `_single`
/// fields judge only ids read exactly once (the fold class a hash-chain stack can carry: `non_lifo_single` = 0 means
/// they pop LIFO among themselves), the `_reread` field only ids read more than once (the window a ring must keep).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FLiveness {
    pub pushes: usize,
    pub reads: usize,
    pub rereads: usize,
    pub dead_pushes: usize,
    pub max_live: usize,
    pub non_lifo: usize,
    pub overwritten_live: usize,
    pub single_ids: usize,
    pub reread_ids: usize,
    pub max_live_single: usize,
    pub max_live_reread: usize,
    pub non_lifo_single: usize,
}

pub fn f_liveness(program: &[RowFlags]) -> FLiveness {
    let reads_f0 = |fl: &RowFlags| {
        (0..4).any(|k| fl.is_set(flag::MUL + flag::MUL_STRIDE * k + flag::A_MENU + flag::BM_F0))
            || (0..NX).any(|j| fl.is_set(flag::XMOVE + flag::XM_STRIDE * j + flag::XM_ADD_F0))
    };
    // pass 1: the ring of ids, row by row, exactly as `universal_row`'s f_next selects (push1 > push2 > up > down)
    let mut ring: [Option<usize>; NF] = [None; NF];
    // O1-INFINITY-REVIEWED: one entry per F push of the fixed program — f(the proof SHAPE).
    let mut pushed_at: Vec<usize> = Vec::new();
    let mut last_read: Vec<Option<usize>> = Vec::new();
    let mut read_count: Vec<usize> = Vec::new();
    let mut read_log: Vec<(usize, usize)> = Vec::new();
    let mut dropped: Vec<(usize, usize)> = Vec::new();
    let mut out = FLiveness::default();
    for (r, fl) in program.iter().enumerate() {
        if reads_f0(fl) {
            if let Some(id) = ring[0] {
                out.reads += 1;
                if last_read[id].is_some() {
                    out.rereads += 1;
                }
                last_read[id] = Some(r);
                read_count[id] += 1;
                read_log.push((r, id));
            }
        }
        let mut fresh = |n: usize| -> Vec<usize> {
            (0..n)
                .map(|_| {
                    pushed_at.push(r);
                    last_read.push(None);
                    read_count.push(0);
                    pushed_at.len() - 1
                })
                .collect()
        };
        let next: [Option<usize>; NF] = if fl.is_set(flag::F_PUSH1) {
            let t = fresh(1);
            core::array::from_fn(|i| if i + 1 < NF { ring[i + 1] } else { Some(t[0]) })
        } else if fl.is_set(flag::F_PUSH2) {
            let t = fresh(2);
            core::array::from_fn(|i| if i + 2 < NF { ring[i + 2] } else { Some(t[i + 2 - NF]) })
        } else if fl.is_set(flag::F_ROT_UP) {
            core::array::from_fn(|i| ring[(i + NF - 1) % NF])
        } else if fl.is_set(flag::F_ROT) {
            core::array::from_fn(|i| ring[(i + 1) % NF])
        } else {
            ring
        };
        let pushes = fl.is_set(flag::F_PUSH1) as usize + 2 * (!fl.is_set(flag::F_PUSH1) && fl.is_set(flag::F_PUSH2)) as usize;
        dropped.extend(ring.iter().take(pushes).flatten().map(|&id| (r, id)));
        ring = next;
    }
    out.pushes = pushed_at.len();
    out.overwritten_live = dropped.iter().filter(|&&(r, id)| last_read[id].is_some_and(|lr| lr > r)).count();
    // pass 2: live = pushed before r and read at or after r; LIFO = the read id is the newest live id
    let mut live = std::collections::BTreeSet::new();
    let mut live_single = std::collections::BTreeSet::new();
    let mut live_reread = 0usize;
    let mut ev = 0usize;
    for id in 0..out.pushes {
        match read_count[id] {
            0 => out.dead_pushes += 1,
            1 => out.single_ids += 1,
            _ => out.reread_ids += 1,
        }
    }
    let mut next_push = 0usize;
    for r in 0..program.len() {
        while next_push < out.pushes && pushed_at[next_push] < r {
            if last_read[next_push].is_some_and(|lr| lr >= r) {
                live.insert(next_push);
                if read_count[next_push] == 1 {
                    live_single.insert(next_push);
                } else {
                    live_reread += 1;
                }
            }
            next_push += 1;
        }
        out.max_live = out.max_live.max(live.len());
        out.max_live_single = out.max_live_single.max(live_single.len());
        out.max_live_reread = out.max_live_reread.max(live_reread);
        while ev < read_log.len() && read_log[ev].0 == r {
            let id = read_log[ev].1;
            if live.iter().next_back() != Some(&id) {
                out.non_lifo += 1;
            }
            if read_count[id] == 1 && live_single.iter().next_back() != Some(&id) {
                out.non_lifo_single += 1;
            }
            if last_read[id] == Some(r) {
                live.remove(&id);
                if read_count[id] == 1 {
                    live_single.remove(&id);
                } else {
                    live_reread -= 1;
                }
            }
            ev += 1;
        }
    }
    out
}

fn first_unsatisfied_step_of(p: &RowParams, io: &[Fa4], regs0: [Fa4; NREG], program: &[RowFlags], stream: &[[Fa4; NSTREAM]], supply: bool) -> Option<usize> {
    assert_eq!(program.len(), stream.len(), "one stream row per program row");
    let mut regs = regs0;
    let mut bank = BankStack::default();
    for (g, (flags, d)) in program.iter().zip(stream).enumerate() {
        let mut d = *d;
        if supply {
            bank.supply(flags, &regs, &mut d);
        }
        let mut b = step_builder(io);
        let next = universal_row(&mut b, p, &RowIn { regs, d, fw: flags.words() });
        let mut z = b.assignment().to_vec();
        // the next-step placeholders alias the next step's registers in the lifted instance; bind them here
        let (w_off, v) = (z.len() / 2, 1usize << V_BITS);
        for (j, &n) in next.iter().enumerate() {
            z[w_off + v + j] = n;
        }
        let (r1cs, _) = b.finish().expect("the row fits its declared shape");
        if !r1cs.is_satisfied(&z) {
            return Some(g);
        }
        regs = next;
    }
    None
}

/// The uniform instance for `2^t_bits` steps of the row. No boundary entries: the initial state is pinned by the
/// program's `INIT` row, the digest by its `FINAL` row, the statement copies by `IOCHK` rows — all template rows.
pub fn uniform_instance(p: &RowParams, io_len: usize, t_bits: usize) -> UniformR1cs {
    let step = template(p, io_len);
    UniformR1cs::from_template(&step, V_BITS, NREG, t_bits, Some(ONE_LOCAL))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;

    fn ea(s: u64) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|j| {
            Fa4::from_u64(s.wrapping_mul(0x9E37_79B9) ^ (j as u64 + 1).wrapping_mul(0x51_7CC1_B727))
        })
    }
    fn coeffs(e: Ea4) -> [Fa4; 4] {
        core::array::from_fn(|i| e.as_basis_coefficients_slice()[i])
    }
    pub(crate) fn params() -> RowParams {
        RowParams::decider(core::array::from_fn(|r| Fa4::from_u64(1000 + r as u64)), [12, 20, 8, 4, 1, 24, 6, 6, 6, 6], 3)
    }
    fn perm_for(seed: u64) -> crate::hiding_decider::Perm16 {
        use rand::SeedableRng;
        crate::hiding_decider::Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed))
    }
    fn word_row(words: &[Fa4]) -> [Fa4; NSTREAM] {
        let mut d = [Fa4::ZERO; NSTREAM];
        d[..words.len()].copy_from_slice(words);
        d
    }
    fn set_all(fl: &mut RowFlags, base: usize, n: usize) {
        for k in 0..n {
            fl.set(base + k);
        }
    }
    fn reg_ext(regs: &[Fa4], off: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| regs[off + i])
    }
    fn put_ext(regs: &mut [Fa4; NREG], off: usize, e: Ea4) {
        regs[off..off + 4].copy_from_slice(&coeffs(e));
    }
    const IO: [Fa4; IO_LEN] = [Fa4::ZERO; IO_LEN];
    fn idle(n: usize) -> (Vec<RowFlags>, Vec<[Fa4; NSTREAM]>) {
        ((0..n).map(|_| RowFlags::default()).collect(), (0..n).map(|_| [Fa4::ZERO; NSTREAM]).collect())
    }

    /// The template's size, reported and bounded: the locals fit the declared half.
    #[test]
    fn the_row_fits_its_declared_shape() {
        let p = params();
        let mut b = step_builder(&IO);
        universal_row(&mut b, &p, &RowIn::zero());
        let constraints = b.constraints();
        let (step, w) = b.finish().expect("fits");
        let used = w.iter().rposition(|&x| x != Fa4::ZERO).map_or(0, |i| i + 1);
        let u = UniformR1cs::from_template(&step, V_BITS, NREG, 1, Some(ONE_LOCAL));
        eprintln!(
            "[row] {constraints} constraints (R = 2^{}), {NREG} registers, locals used ≤ {used} of 2^{V_BITS}, template nnz {}, {} flags in {NFLAG_WORDS} words",
            u.r_bits,
            u.a.template.len() + u.b.template.len() + u.c.template.len(),
            flag::LAST
        );
        // the matrix argument's census: per matrix the nonzeros by kind, the distinct public columns, the rows that
        // reference a public column, the transition rows
        for (name, m) in [("A", &u.a), ("B", &u.b), ("C", &u.c)] {
            let (mut local, mut next, mut public) = (0usize, 0usize, 0usize);
            let mut pub_cols = std::collections::BTreeSet::new();
            let mut pub_rows = std::collections::BTreeSet::new();
            let mut max_abs_row = 0usize;
            for &(i, col, _) in &m.template {
                match col {
                    crate::uniform_r1cs::Col::Local(_) => local += 1,
                    crate::uniform_r1cs::Col::Next(_) => next += 1,
                    crate::uniform_r1cs::Col::Public(c) => {
                        public += 1;
                        pub_cols.insert(c);
                        pub_rows.insert(i);
                    }
                }
                max_abs_row = max_abs_row.max(i);
            }
            eprintln!(
                "[row] matrix {name}: nnz {} = local {local} + next {next} + public {public}; public columns {:?} over {} rows; max row {max_abs_row}",
                m.template.len(),
                pub_cols,
                pub_rows.len()
            );
        }
        eprintln!("[row] transition rows: {}", u.transition_rows().iter().filter(|&&t| t).count());
        assert!(constraints <= 1 << u.r_bits);
        assert!(flag::LAST < FLAG_BITS, "every flag fits the {NFLAG_WORDS} flag words");
    }

    /// Transcript rows equal the decider's `Chl`: absorb 8 and sample an Ea4 (aligned, slots 7..4); absorb 3 and
    /// pop one base sample in the duplexing row (slot 7); sample an Ea4 from the carried buffer UNALIGNED (slots
    /// 6..3); then an Ea4 SPLIT across a duplexing (slots 2, 1, 0 latched, then a bare duplexing and slot 7).
    #[test]
    fn transcript_rows_match_the_deciders_challenger() {
        use p3_challenger::{CanObserve, CanSample, FieldChallenger};
        let p = params();
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31;
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        let w8: Vec<Fa4> = (0..8).map(|i| Fa4::from_u64(500 + i)).collect();
        let w3: Vec<Fa4> = (0..3).map(|i| Fa4::from_u64(900 + i)).collect();
        for &v in &w8 {
            native.observe(v);
        }
        let n_ch1: Ea4 = native.sample_algebra_element();
        for &v in &w3 {
            native.observe(v);
        }
        let n_base: Fa4 = native.sample();
        let n_ch2: Ea4 = native.sample_algebra_element();
        let n_ch3: Ea4 = native.sample_algebra_element();

        let mut r0 = RowFlags::default();
        r0.set(flag::M_ABSORB);
        set_all(&mut r0, flag::A, 8);
        let mut r1 = RowFlags::default();
        r1.pop_ext(7).emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_CH);
        let mut r2 = RowFlags::default();
        r2.set(flag::M_ABSORB);
        set_all(&mut r2, flag::A, 3);
        r2.pop(0, 7).emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_CH);
        let mut r3 = RowFlags::default();
        r3.pop_ext(6).emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_CH);
        let mut r4 = RowFlags::default();
        r4.pop(0, 2).pop(1, 1).pop(2, 0).set(flag::LATCH).set(flag::LATCH + 1).set(flag::LATCH + 2);
        let mut r5 = RowFlags::default();
        r5.set(flag::M_ABSORB).pop(3, 7).set(flag::LATCH + 3);
        let program = vec![r0, r1, r2, r3, r4, r5];
        let stream = vec![word_row(&w8), word_row(&[]), word_row(&w3), word_row(&[]), word_row(&[]), word_row(&[])];
        let tr = emulate(&p, &IO, [Fa4::ZERO; NREG], &program, &stream);
        assert_eq!(reg_ext(&tr.final_regs, E_OFF + 4), n_ch1, "aligned Ea4 challenge");
        assert_eq!(reg_ext(&tr.final_regs, E_OFF + 8), Ea4::from(n_base), "the base sample popped in the duplexing row");
        assert_eq!(reg_ext(&tr.final_regs, E_OFF + 12), n_ch2, "unaligned Ea4 challenge from the carried buffer");
        assert_eq!(reg_ext(&tr.final_regs, E_OFF), n_ch3, "Ea4 challenge split across a duplexing");
        eprintln!("[row] transcript: 6 rows reproduce Chl's aligned, unaligned and split Ea4 challenges and a base sample");
    }

    /// Merkle rows reproduce `Mmcs16`'s root on a 64×4 salted tree: two leaf rows (8 + 4 words), six
    /// compressions consuming `B`, the root observed into `R2`, promoted to `R`, and asserted on the last level;
    /// a wrong sibling leaves the trace unsatisfiable against the lifted template.
    #[test]
    fn merkle_rows_reproduce_the_pcs_root_and_a_wrong_sibling_is_refused() {
        use crate::hiding_decider::{CompressHash, Mmcs16, SpongeHash};
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use rand::SeedableRng;
        let p = params();
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        let perm = perm_for(seed);
        let mmcs = Mmcs16::new(SpongeHash::new(perm.clone()), CompressHash::new(perm), 0, rand::rngs::SmallRng::seed_from_u64(seed + 7));
        let (height, width) = (1usize << 6, 4usize);
        let values: Vec<Fa4> = (0..height * width).map(|i| Fa4::from_u64(i as u64 * 7 + 3)).collect();
        let (commit, pd) = mmcs.commit(vec![RowMajorMatrix::new(values, width)]);
        let root: [Fa4; RATE] = commit.roots()[0];
        let index = 37usize;
        let opening = mmcs.open_batch(index, &pd);
        let (salts, siblings) = &opening.opening_proof;
        let row: Vec<Fa4> = opening.opened_values[0].iter().chain(salts[0].iter()).copied().collect();
        assert_eq!(row.len(), 12);
        let mut program = Vec::new();
        let mut stream = Vec::new();
        let mut cap = RowFlags::default();
        cap.set(flag::R_CAPTURE);
        program.push(cap);
        stream.push(word_row(&root));
        let mut l0 = RowFlags::default();
        l0.set(flag::M_LEAF).set(flag::H_RESET).set(flag::R_SHIFT);
        set_all(&mut l0, flag::A, 8);
        program.push(l0);
        stream.push(word_row(&row[..8]));
        let mut l1 = RowFlags::default();
        l1.set(flag::M_LEAF);
        set_all(&mut l1, flag::A, 4);
        program.push(l1);
        stream.push(word_row(&row[8..12]));
        for (lvl, sib) in siblings.iter().enumerate() {
            let mut c = RowFlags::default();
            c.set(flag::M_MERKLE).set(flag::BSHIFT);
            if lvl + 1 == siblings.len() {
                c.set(flag::ROOT_CHECK);
            }
            program.push(c);
            stream.push(word_row(sib));
        }
        let mut regs0 = [Fa4::ZERO; NREG];
        for l in 0..NB {
            regs0[B_OFF + l] = Fa4::from_u64(((index >> l) & 1) as u64);
        }
        let tr = emulate(&p, &IO, regs0, &program, &stream);
        for k in 0..RATE {
            assert_eq!(tr.final_regs[H_OFF + k], root[k], "root lane {k}");
            assert_eq!(tr.final_regs[R_OFF + k], root[k], "R promoted from R2");
        }
        let t_bits = 4usize;
        let steps = 1usize << t_bits;
        let (mut program_full, mut stream_full) = (program.clone(), stream.clone());
        let (pad_p, pad_s) = idle(steps - program.len());
        program_full.extend(pad_p);
        stream_full.extend(pad_s);
        let inst = uniform_instance(&p, IO.len(), t_bits).materialize();
        let tr = emulate(&p, &IO, regs0, &program_full, &stream_full);
        assert!(inst.is_satisfied(&inst.lay_z(&IO, &tr.w).unwrap()), "the honest Merkle trace satisfies");
        let mut bad_stream = stream_full.clone();
        bad_stream[5][0] += Fa4::ONE;
        let bad = emulate(&p, &IO, regs0, &program_full, &bad_stream);
        assert!(!inst.is_satisfied(&inst.lay_z(&IO, &bad.w).unwrap()), "a wrong sibling must be refused");
        eprintln!("[row] merkle: 9 rows reproduce the PCS root at index {index}; the lifted 16-step instance ({} constraints) accepts the trace and refuses a wrong sibling", inst.rows());
    }

    /// STIR rows equal `draw_below(2^k)` with `k` taken from the round table: a draw inside one row (round 0,
    /// k = 12) and a draw SPLIT across a duplexing (round 1, k = 20).
    #[test]
    fn stir_rows_match_draw_below_within_and_across_a_duplexing() {
        use p3_challenger::{CanObserve, CanSample};
        use p3_whir::pcs::utils::draw_below;
        let p = params();
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31;
        let w8: Vec<Fa4> = (0..8).map(|i| Fa4::from_u64(700 + i)).collect();
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        for &v in &w8 {
            native.observe(v);
        }
        let (k1, k2) = (p.ks[0], p.ks[1]);
        let want1 = draw_below::<_, Fa4>(&mut native, 1usize << k1);
        let _skip: Fa4 = native.sample();
        let _skip: Fa4 = native.sample();
        let want2 = draw_below::<_, Fa4>(&mut native, 1usize << k2);
        let mut r0 = RowFlags::default();
        r0.set(flag::M_ABSORB);
        set_all(&mut r0, flag::A, 8);
        let mut r1 = RowFlags::default();
        r1.pop_ext(7).set(flag::TCLEAR).set(flag::STIR).set(flag::RF);
        let tr = emulate(&p, &IO, [Fa4::ZERO; NREG], &[r0.clone(), r1], &[word_row(&w8), word_row(&[])]);
        let read_b = |regs: &[Fa4]| -> usize {
            (0..NB).fold(0usize, |acc, l| {
                let bit = regs[B_OFF + l];
                assert!(bit == Fa4::ZERO || bit == Fa4::ONE);
                acc | ((bit == Fa4::ONE) as usize) << l
            })
        };
        assert_eq!(read_b(&tr.final_regs), want1, "the one-row draw differs from draw_below");
        let mut r2 = RowFlags::default();
        r2.pop(0, 1).pop(1, 0).set(flag::TCLEAR).set(flag::RF + 1);
        let mut r3 = RowFlags::default();
        r3.set(flag::M_ABSORB).pop(2, 7).pop(3, 6).set(flag::STIR).set(flag::RF + 1);
        let tr2 = emulate(&p, &IO, tr.final_regs, &[r2, r3], &[word_row(&[]), word_row(&[])]);
        assert_eq!(read_b(&tr2.final_regs), want2, "the split draw differs from draw_below");
        eprintln!("[row] stir: {want1} over 2^{k1} in one row and {want2} over 2^{k2} across a duplexing equal draw_below");
    }

    /// Product, move and bank rows compute what they name — row 1: `X'_0 = X_0 + X_0·X_4`, `X'_1 = D_1·E_0`,
    /// `X'_2 = PT_0·F_0 − E_2 + 1`, `X'_3 = E_3·(VB_3 − 1)`, `X'_5 = X_6`, `X'_6 = X_6·VB_2 + F_0`, `E'_3 = X_3`,
    /// `E'_2 = Y_0`, `E'_1 = RS_0`, pushes into PT, F, VB, Y, RS, `G_INIT`; row 2: `PT`/`Y`/`RS` rotations,
    /// `VB_SQ4`, `F_PUSH2`, the adjacent-pair fold `X'_5 = X_2 + (X_3 − X_2)·E_0`, `X'_4 = X_0·PT[port]`,
    /// `E'_1 = E_0`, `G_STEP`; row 3: `PT_ROT_UP`, `F_ROT`, and `EXT_EQ` refusing unequal halves.
    #[test]
    fn product_move_and_bank_rows_compute_their_named_arithmetic() {
        let p = params();
        let mut regs0 = [Fa4::ZERO; NREG];
        for k in 0..NX {
            put_ext(&mut regs0, X_OFF + 4 * k, ea(10 + k as u64));
        }
        for k in 0..NE {
            put_ext(&mut regs0, E_OFF + 4 * k, ea(20 + k as u64));
        }
        for k in 0..NPT {
            put_ext(&mut regs0, PT_OFF + 4 * k, ea(100 + k as u64));
        }
        for k in 0..NVB {
            regs0[VB_OFF + k] = Fa4::from_u64(300 + k as u64);
        }
        for k in 0..NY {
            put_ext(&mut regs0, Y_OFF + 4 * k, ea(400 + k as u64));
        }
        for k in 0..NRS {
            put_ext(&mut regs0, RS_OFF + 4 * k, ea(600 + k as u64));
        }
        for k in 0..NF {
            put_ext(&mut regs0, F_OFF + 4 * k, ea(700 + k as u64));
        }
        regs0[VAR_OFF] = Fa4::from_u64(77);
        regs0[B_OFF] = Fa4::ONE;
        let d1 = ea(30);
        let mut d = [Fa4::ZERO; NSTREAM];
        d[4..8].copy_from_slice(&coeffs(d1));
        let mut r = RowFlags::default();
        r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4); // X0 · X4
        r.mul_a(1, flag::AM_D).mul_b(1, flag::BM_E0); // D1 · E0
        r.mul_a(2, flag::AM_PT0).mul_b(2, flag::BM_F0); // PT0 · F0
        r.mul_a(3, flag::AM_E).mul_b(3, flag::BM_VAR); // E3 · VAR
        r.xmove(0, flag::XM_ADD_MUL);
        r.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_MUL);
        r.xmove(2, flag::XM_CLR).xmove(2, flag::XM_ADD_MUL).xmove(2, flag::XM_SUB_E).xmove(2, flag::XM_ADD_ONE);
        r.xmove(3, flag::XM_CLR).xmove(3, flag::XM_ADD_MUL);
        r.xmove(5, flag::XM_CLR).xmove(5, flag::XM_ADD_NEXT);
        r.emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X);
        r.emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_Y0);
        r.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_RS0);
        r.set(flag::PT_PUSH).set(flag::F_PUSH1).set(flag::Y_PUSH).set(flag::RS_PUSH);
        r.set(flag::G_INIT).set(flag::RF + 2);
        let tr = emulate(&p, &IO, regs0, &[r], &[d]);
        let x = |k: usize| reg_ext(&regs0, X_OFF + 4 * k);
        let e = |k: usize| reg_ext(&regs0, E_OFF + 4 * k);
        let fr = &tr.final_regs;
        assert_eq!(reg_ext(fr, X_OFF), x(0) + x(0) * x(4));
        assert_eq!(reg_ext(fr, X_OFF + 4), d1 * e(0));
        assert_eq!(reg_ext(fr, X_OFF + 8), ea(100) * ea(700) - e(2) + Ea4::ONE);
        assert_eq!(reg_ext(fr, X_OFF + 12), e(3) * Ea4::from(regs0[VAR_OFF]));
        assert_eq!(reg_ext(fr, X_OFF + 20), x(6));
        assert_eq!(reg_ext(fr, E_OFF + 12), x(3));
        assert_eq!(reg_ext(fr, E_OFF + 8), ea(400));
        assert_eq!(reg_ext(fr, E_OFF + 4), ea(600));
        assert_eq!(reg_ext(fr, PT_OFF), e(0), "PT head = the pushed E[0]");
        assert_eq!(reg_ext(fr, PT_OFF + 4), ea(100), "PT[1] = the old head");
        assert_eq!(reg_ext(fr, F_OFF + 4 * (NF - 1)), x(0), "F tail = the pushed X[0]");
        assert_eq!(reg_ext(fr, F_OFF), ea(701), "F shifted down by one on a push");
        assert_eq!(fr[VB_OFF], Fa4::from_u64(300), "VB untouched (pushes ride the BK stack)");
        assert_eq!(fr[VB_OFF + 1], Fa4::from_u64(301));
        assert_eq!(reg_ext(fr, Y_OFF), e(0), "Y head = the pushed E[0]");
        assert_eq!(reg_ext(fr, RS_OFF), e(0), "RS head = the pushed E[0]");
        assert_eq!(reg_ext(fr, RS_OFF + 4), ea(600));
        assert_eq!(fr[G_OFF], p.gens[2]);
        assert_eq!(fr[VAR_OFF], Fa4::ONE);
        // row 2
        let mut r2 = RowFlags::default();
        r2.set(flag::PT_ROT).set(flag::Y_ROT).set(flag::RS_ROT).set(flag::VB_SQ4).set(flag::F_PUSH2).set(flag::G_STEP);
        r2.mul_a(1, flag::AM_ADJ).mul_b(1, flag::BM_E0); // (X3 − X2) · E0
        r2.xmove(5, flag::XM_CLR).xmove(5, flag::XM_ADD_X2J).xmove(5, flag::XM_ADD_MUL); // X_2 + mul_1
        r2.mul_a(0, flag::AM_X).mul_b(0, flag::BM_PTM); // X0 · PT[port]
        r2.xmove(4, flag::XM_CLR).xmove(4, flag::XM_ADD_MUL);
        r2.mul_a(2, flag::AM_X4).mul_b(2, flag::BM_VBK); // X6 · VB2
        r2.xmove(6, flag::XM_CLR).xmove(6, flag::XM_ADD_MUL).xmove(6, flag::XM_ADD_F0); // X6·VB2 + F0
        r2.emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_E0);
        let mut d2 = [Fa4::ZERO; NSTREAM];
        for c in 0..2 {
            d2[4 * c..4 * c + 4].copy_from_slice(&coeffs(ea(500 + c as u64)));
        }
        let tr2 = emulate(&p, &IO, tr.final_regs, &[r2], &[d2]);
        let fr2 = &tr2.final_regs;
        let x1 = |k: usize| reg_ext(fr, X_OFF + 4 * k);
        let e1 = |k: usize| reg_ext(fr, E_OFF + 4 * k);
        assert_eq!(reg_ext(fr2, X_OFF + 20), x1(2) + (x1(3) - x1(2)) * e1(0), "the adjacent-pair fold X_2 + (X_3 − X_2)·E_0");
        assert_eq!(reg_ext(fr2, X_OFF + 16), x1(0) * reg_ext(fr, PT_OFF + 4 * p.pt_port), "X_0 · PT[port]");
        assert_eq!(reg_ext(fr2, X_OFF + 24), x1(6) * Ea4::from(fr[VB_OFF + 2]) + reg_ext(fr, F_OFF), "X_6·VB_2 + F_0");
        assert_eq!(reg_ext(fr2, E_OFF + 4), e1(0), "E_1 ← E_0");
        assert_eq!(reg_ext(fr2, PT_OFF), ea(100), "PT head after one rotation down = the old head");
        assert_eq!(reg_ext(fr2, PT_OFF + 4 * (NPT - 1)), e(0), "PT wraps");
        assert_eq!(reg_ext(fr2, Y_OFF), ea(400), "Y head after one rotation");
        assert_eq!(reg_ext(fr2, RS_OFF), ea(600), "RS head after one rotation");
        for k in 0..NVB {
            assert_eq!(fr2[VB_OFF + k], fr[VB_OFF + k] * fr[VB_OFF + k], "VB squared in place");
        }
        for i in 0..NF - 2 {
            assert_eq!(reg_ext(fr2, F_OFF + 4 * i), reg_ext(fr, F_OFF + 4 * (i + 2)), "F shifted by two");
        }
        for c in 0..2 {
            assert_eq!(reg_ext(fr2, F_OFF + 4 * (NF - 2 + c)), ea(500 + c as u64), "F tail = the pushed coefficients");
        }
        assert_eq!(fr2[VAR_OFF], p.gens[2]);
        assert_eq!(fr2[G_OFF], p.gens[2] * p.gens[2]);
        // row 3: rotations up; EXT_EQ on unequal halves is refused by the lifted instance (T = 4, idle rows after)
        let mut r3 = RowFlags::default();
        r3.set(flag::PT_ROT_UP).set(flag::F_ROT).set(flag::EXT_EQ);
        let (mut prog3, mut str3) = idle(4);
        prog3[0] = r3;
        str3[0] = [Fa4::ZERO; NSTREAM];
        let tr3 = emulate(&p, &IO, tr2.final_regs, &prog3, &str3);
        let after3 = tr3.regs_after(0);
        assert_eq!(reg_ext(&after3, PT_OFF), reg_ext(fr2, PT_OFF + 4 * (NPT - 1)), "PT head after one rotation up = the old tail");
        assert_eq!(reg_ext(&after3, F_OFF), reg_ext(fr2, F_OFF + 4), "F head after one rotation down = the old F[1]");
        let inst = uniform_instance(&p, IO.len(), 2).materialize();
        assert!(!inst.is_satisfied(&inst.lay_z(&IO, &tr3.w).unwrap()), "EXT_EQ with X_0 != X_4 must be refused");
        eprintln!("[row] arithmetic: products, moves, six banks, the adjacent-pair fold, G/VAR stepping equal native arithmetic; EXT_EQ refuses unequal halves");
    }

    /// The extended moves and rotations (the 10th flag word): `X_j += X_{j+4}`, `X_j += X_{j−1}`, `E_k ← X_{k+4}`,
    /// a mul on `RS[0]`, `Y`/`RS` rotated UP (head ← tail) and `VB` rotated down by ONE equal native arithmetic.
    /// H12 §12 C: four g^index pushes on the BK stack pop back newest first into VB's four slots and leave the
    /// zero digest; a popped value or digest word the prover changes, and a pop of the empty stack, are REFUSED.
    #[test]
    fn the_bank_stack_pops_every_push_back_and_refuses_a_forged_pop() {
        let p = params();
        let mut regs0 = [Fa4::ZERO; NREG];
        regs0[B_OFF] = Fa4::ONE;
        let mut program = Vec::new();
        let mut r = RowFlags::default();
        r.set(flag::G_INIT).set(flag::RF + 2);
        program.push(r);
        for _ in 0..4 {
            let mut st = RowFlags::default();
            st.set(flag::G_STEP);
            program.push(st);
            let mut ab = RowFlags::default();
            ab.set(flag::BANK_ABSORB);
            program.push(ab);
        }
        let first_pop = program.len();
        for _ in 0..NVB {
            let mut un = RowFlags::default();
            un.set(flag::BANK_UNWIND);
            program.push(un);
        }
        let given = vec![[Fa4::ZERO; NSTREAM]; program.len()];
        let stream = supply_bank_stream(&p, &IO, regs0, &program, &given);
        assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &program, &stream), None, "the honest pops satisfy every row");
        assert_eq!(first_unsatisfied_step(&p, &IO, regs0, &program, &given), None);
        let tr = emulate(&p, &IO, regs0, &program, &given);
        let g = p.gens[2];
        let pw = |e: u64| (0..e).fold(Fa4::ONE, |a, _| a * g);
        let fr = &tr.final_regs;
        for (k, e) in [15u64, 7, 3, 1].into_iter().enumerate() {
            assert_eq!(fr[VB_OFF + k], pw(e), "slot {k} = the {k}-th newest push");
        }
        assert!(tr.regs_after(first_pop - 1)[BK_OFF..BK_OFF + RATE].iter().any(|&w| w != Fa4::ZERO), "four pushes move the digest");
        assert!(fr[BK_OFF..BK_OFF + RATE].iter().all(|&w| w == Fa4::ZERO), "every pop back: the empty stack's zero digest");
        for (row, word) in [(first_pop, RATE), (first_pop + 2, RATE), (first_pop + 1, 3)] {
            let mut forged = stream.clone();
            forged[row][word] += Fa4::ONE;
            assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &program, &forged), Some(row), "a forged pop (row {row}, word {word}) is refused");
        }
        let mut over = program.clone();
        let mut un = RowFlags::default();
        un.set(flag::BANK_UNWIND);
        over.push(un);
        let over_stream = supply_bank_stream(&p, &IO, regs0, &over, &vec![[Fa4::ZERO; NSTREAM]; over.len()]);
        assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &over, &over_stream), Some(over.len() - 1), "a pop of the empty stack is refused");
    }

    /// H12 §12 C (F half): three round folds absorbed on the FK stack pop back newest first through `D_ext[1]` into
    /// `X_1`, leave the zero digest and never touch BK or VB; a forged fold or digest word, and a pop of the empty
    /// stack, are REFUSED.
    #[test]
    fn the_fold_stack_pops_every_fold_back_and_refuses_a_forged_pop() {
        let p = params();
        let mut regs0 = [Fa4::ZERO; NREG];
        put_ext(&mut regs0, X_OFF, ea(5));
        let mut program = Vec::new();
        for i in 0..3 {
            if i > 0 {
                let mut inc = RowFlags::default();
                inc.xmove(0, flag::XM_ADD_ONE);
                program.push(inc);
            }
            let mut ab = RowFlags::default();
            ab.set(flag::BANK_ABSORB).set(flag::FBANK);
            program.push(ab);
        }
        let first_pop = program.len();
        for _ in 0..3 {
            let mut un = RowFlags::default();
            un.set(flag::BANK_UNWIND).set(flag::FBANK);
            un.xmove(1, flag::XM_CLR).xmove(1, flag::XM_ADD_DA);
            program.push(un);
        }
        let given = vec![[Fa4::ZERO; NSTREAM]; program.len()];
        let stream = supply_bank_stream(&p, &IO, regs0, &program, &given);
        assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &program, &stream), None, "the honest pops satisfy every row");
        let tr = emulate(&p, &IO, regs0, &program, &given);
        for k in 0..3 {
            let want = ea(5) + Ea4::from(Fa4::from_u64(2 - k as u64));
            assert_eq!(reg_ext(&tr.regs_after(first_pop + k), X_OFF + 4), want, "pop {k} = the {k}-th newest fold");
        }
        assert!(tr.regs_after(first_pop - 1)[FK_OFF..FK_OFF + RATE].iter().any(|&w| w != Fa4::ZERO), "three pushes move the digest");
        let fr = &tr.final_regs;
        assert!(fr[FK_OFF..FK_OFF + RATE].iter().all(|&w| w == Fa4::ZERO), "every pop back: the empty stack's zero digest");
        assert!(fr[BK_OFF..BK_OFF + RATE].iter().chain(&fr[VB_OFF..VB_OFF + NVB]).all(|&w| w == Fa4::ZERO), "FK rows leave BK and VB alone");
        for (row, word) in [(first_pop, 4), (first_pop + 1, 7), (first_pop + 2, RATE), (first_pop + 1, 2 * RATE - 1)] {
            let mut forged = stream.clone();
            forged[row][word] += Fa4::ONE;
            assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &program, &forged), Some(row), "a forged pop (row {row}, word {word}) is refused");
        }
        let mut over = program.clone();
        let mut un = RowFlags::default();
        un.set(flag::BANK_UNWIND).set(flag::FBANK);
        over.push(un);
        let over_stream = supply_bank_stream(&p, &IO, regs0, &over, &vec![[Fa4::ZERO; NSTREAM]; over.len()]);
        assert_eq!(first_unsatisfied_step_supplied(&p, &IO, regs0, &over, &over_stream), Some(over.len() - 1), "a pop of the empty stack is refused");
    }

    #[test]
    fn the_extended_moves_compute_their_named_arithmetic() {
        let p = params();
        let mut regs0 = [Fa4::ZERO; NREG];
        for k in 0..NX {
            put_ext(&mut regs0, X_OFF + 4 * k, ea(10 + k as u64));
        }
        for k in 0..NE {
            put_ext(&mut regs0, E_OFF + 4 * k, ea(20 + k as u64));
        }
        for i in 0..NY {
            put_ext(&mut regs0, Y_OFF + 4 * i, ea(100 + i as u64));
        }
        for i in 0..NRS {
            put_ext(&mut regs0, RS_OFF + 4 * i, ea(200 + i as u64));
        }
        for i in 0..NVB {
            regs0[VB_OFF + i] = Fa4::from_u64(300 + i as u64);
        }
        let mut r = RowFlags::default();
        r.xmove(1, flag::XM_CLR).set(flag::XM2_ADD_X4J + 1); // X1 = X5
        r.xmove(2, flag::XM_CLR).set(flag::XM2_ADD_PREV + 2); // X2 = X1 (old)
        r.set(flag::XM2_ADD_X4J + 6); // X6 += X2 (old)
        r.mul_a(3, flag::AM_X).set(flag::BM2_RS0 + 3); // X3 · RS0
        r.xmove(7, flag::XM_CLR).xmove(7, flag::XM_ADD_MUL); // X7 = X3 · RS0
        r.emove(0, flag::EM_CLR).set(flag::EM2_FROM_X4); // E0 = X4
        r.set(flag::RS_ROT_UP);
        let tr = emulate(&p, &IO, regs0, &[r], &[[Fa4::ZERO; NSTREAM]]);
        let fr = &tr.final_regs;
        let x = |k: usize| reg_ext(&regs0, X_OFF + 4 * k);
        assert_eq!(reg_ext(fr, X_OFF + 4), x(5), "X1 = X5");
        assert_eq!(reg_ext(fr, X_OFF + 8), x(1), "X2 = X1");
        assert_eq!(reg_ext(fr, X_OFF + 24), x(6) + x(2), "X6 += X2");
        assert_eq!(reg_ext(fr, X_OFF + 28), x(3) * ea(200), "X7 = X3 · RS0");
        assert_eq!(reg_ext(fr, E_OFF), x(4), "E0 = X4");
        assert_eq!(reg_ext(fr, Y_OFF), ea(100), "Y untouched (Y_ROT_UP was deleted 2026-09-28: no emitter set it)");
        assert_eq!(reg_ext(fr, RS_OFF), ea(200 + NRS as u64 - 1), "RS head ← tail");
        assert_eq!(fr[VB_OFF], Fa4::from_u64(300), "VB untouched (VB_ROT1 was deleted 2026-09-28: no emitter set it)");
        assert!(inst_refuses_flag_word_10_change(&p), "the 10th flag word is inside the program digest");
        eprintln!("[row] extended moves: X4J, PREV, E ← X4, a mul on RS0, RS rotated up equal native arithmetic; the 10th word is digested");
    }

    /// The program digest covers the 10th flag word: the same program with one bit of word 10 flipped on a hashed
    /// row has a different `PS` after the row.
    fn inst_refuses_flag_word_10_change(p: &RowParams) -> bool {
        let regs0 = [Fa4::ZERO; NREG];
        let mut a = RowFlags::default();
        a.set(flag::IOCHK_3);
        let mut b = RowFlags::default();
        b.set(flag::RS_ROT_UP);
        let d = [[Fa4::ZERO; NSTREAM]];
        let ta = emulate(p, &IO, regs0, &[a], &d);
        let tb = emulate(p, &IO, regs0, &[b], &d);
        ta.final_regs[PS_OFF..PS_OFF + RATE] != tb.final_regs[PS_OFF..PS_OFF + RATE]
    }

    /// ⭐ The proof-of-work check (`check_witness`): a ground witness — absorbed, one sample popped into unit 0 —
    /// passes `POW_INIT` (4 bits) and `POW_QUERY` through the round one-hot (8 bits), the Ea4 sampled after each
    /// equals the native's, and the lifted instance REFUSES a witness whose sample has a low bit set (an un-ground
    /// proof). The program is the same for both witnesses: only the stream differs.
    #[test]
    fn the_pow_check_accepts_a_ground_witness_and_refuses_an_unground_one() {
        use crate::verifier_program::ProgramBuilder;
        use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
        let p = params().with_pow([4, 0, 0, 0, 0, 0, 0, 0, 0, 0], [9, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31;
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        let prefix: Vec<Fa4> = (0..3).map(|i| Fa4::from_u64(700 + i)).collect();
        for &v in &prefix {
            native.observe(v);
        }
        // the first witness whose sample has `bits` zero low bits (`want`), or the first whose sample has not
        let find = |native: &crate::hiding_decider::Chl, bits: usize, want: bool| -> Fa4 {
            (0u64..).map(Fa4::from_u64).find(|&w| native.clone().check_witness(bits, w) == want).expect("a witness")
        };
        let w_good = find(&native, 4, true);
        let w_bad = find(&native, 4, false);
        assert!(native.check_witness(4, w_good));
        let r_native: Ea4 = native.sample_algebra_element();
        let w_q = find(&native, 8, true);
        assert!(native.check_witness(8, w_q));
        let r2_native: Ea4 = native.sample_algebra_element();

        let build = |w0: Fa4| -> (Vec<RowFlags>, Vec<[Fa4; NSTREAM]>, usize, usize) {
            let mut pb = ProgramBuilder::new();
            pb.observe_slice(&prefix);
            pb.observe(w0);
            pb.pop_pow(flag::POW_INIT, Some(0));
            let a1 = pb.sample_ext();
            pb.observe(w_q);
            pb.pop_pow(flag::POW_QUERY, Some(0));
            let a2 = pb.sample_ext();
            let (program, stream) = pb.finish();
            (program, stream, a1.row, a2.row)
        };
        let (program, stream, a1, a2) = build(w_good);
        let regs0 = [Fa4::ZERO; NREG];
        let tr = emulate(&p, &IO, regs0, &program, &stream);
        assert_eq!(reg_ext(&tr.regs_after(a1), E_OFF), r_native, "the challenge after the initial pow check");
        assert_eq!(reg_ext(&tr.regs_after(a2), E_OFF), r2_native, "the challenge after the query pow check");
        let t_bits = 3usize;
        let steps = 1usize << t_bits;
        assert!(program.len() <= steps, "{} rows fit T = {steps}", program.len());
        let pad = |program: &[RowFlags], stream: &[[Fa4; NSTREAM]]| {
            let (pp, ps) = idle(steps - program.len());
            let mut p2 = program.to_vec();
            p2.extend(pp);
            let mut s2 = stream.to_vec();
            s2.extend(ps);
            (p2, s2)
        };
        let inst = uniform_instance(&p, IO.len(), t_bits).materialize();
        let (pf, sf) = pad(&program, &stream);
        let tr = emulate(&p, &IO, regs0, &pf, &sf);
        assert!(inst.is_satisfied(&inst.lay_z(&IO, &tr.w).unwrap()), "a ground witness passes the pow check");
        let (program_b, stream_b, _, _) = build(w_bad);
        assert_eq!(program_b, program, "the program is a function of the shape, not of the witness");
        let (pb2, sb2) = pad(&program_b, &stream_b);
        let bad = emulate(&p, &IO, regs0, &pb2, &sb2);
        assert!(!inst.is_satisfied(&inst.lay_z(&IO, &bad.w).unwrap()), "an un-ground witness must be refused");
        eprintln!("[row] pow: {} rows pass POW_INIT(4) + POW_QUERY(8) on ground witnesses and reproduce both challenges; the lifted {steps}-step instance refuses an un-ground witness", program.len());
    }

    /// §M6-E: the VALUES-ONLY emulation (`step_builder_values_only`, every wire a term-free constant) lays the same trace
    /// and the same final registers as a recording run of the same rows, and a values-only builder refuses to `finish`.
    /// Rows: a transcript absorb, a STIR draw at k = 24, a two-word pow row, an Ea4 sample (pops, decompositions, the
    /// permutation, banks) — plus a real emitted program (the WHIR pins run `emulate` on every emitter, so a drift shows
    /// there too).
    #[test]
    fn the_values_only_emulation_equals_the_recording_one() {
        use crate::verifier_program::ProgramBuilder;
        let slot = 5usize;
        let mut fold = [0usize; NROUNDS];
        fold[slot] = 1;
        let p = params().with_pow([0; NROUNDS], fold, [0; NROUNDS]);
        let mut pb = ProgramBuilder::new();
        pb.observe_slice(&(0..8).map(|i| Fa4::from_u64(900 + i)).collect::<Vec<_>>());
        pb.draw(slot);
        pb.observe(Fa4::ZERO);
        pb.observe(Fa4::from_u64(6));
        pb.pop_pow(flag::POW_FOLD, Some(slot));
        pb.sample_ext();
        let (program, stream) = pb.finish();
        let regs0 = [Fa4::ZERO; NREG];
        let fast = emulate(&p, &IO, regs0, &program, &stream);
        let v = 1usize << V_BITS;
        let mut regs = regs0;
        let mut w = vec![Fa4::ZERO; program.len() * v];
        for (g, (flags, d)) in program.iter().zip(&stream).enumerate() {
            let mut b = step_builder(&IO);
            let next = universal_row(&mut b, &p, &RowIn { regs, d: *d, fw: flags.words() });
            let z = b.assignment();
            let w_off = z.len() / 2;
            w[g * v..(g + 1) * v].copy_from_slice(&z[w_off..w_off + v]);
            regs = next;
        }
        assert_eq!(fast.w, w, "the values-only trace differs from the recording one");
        assert_eq!(fast.final_regs, regs, "the values-only final registers differ");
        let mut vo = step_builder_values_only(&IO);
        universal_row(&mut vo, &p, &RowIn { regs: regs0, d: stream[0], fw: program[0].words() });
        assert!(vo.finish().is_none(), "a values-only builder must refuse to hand out an instance");
        eprintln!("[row] values-only emulation of {} rows equals the recording one", program.len());
    }

    /// ⛔⛔⛔ FOUND 2026-09-28 (fixpoint4, row 4171 — the certificate's first `POW_FOLD` row after an 82-query round at
    /// k = 24): the STIR running sum `TSUM` is carried across rows and only a `TCLEAR` row zeroes it; a proof-of-work
    /// row carries the round one-hot (its bit count is a round-table entry), so `kmask` is that round's `k` bits there
    /// and the popped sample's masked value is ADDED to the sum — after a draw at k = 24 (four masked values, up to
    /// 2^26 − 4) the fifth addend overflows the row's 26-bit decomposition and the HONEST row is refused (≈ 1/120 at
    /// the first pow row after a draw, ≈ 1/2 by the fourth; the small-k pins never reach it: 4·2^12 ≪ 2^26). An honest
    /// certificate step therefore failed to prove with probability ≈ 1/2 — the genesis step passed by luck, the
    /// recursion's step 2 did not. FIX: a pow row CLEARS the sum (`TCLEAR`): it needs no running sum, and every draw
    /// starts with its own `TCLEAR`. RED-FIRST: measured refused at the pow row before the fix.
    /// This pin: a k = 24 draw whose masked sum lies in the top range, then a pow row whose ground sample pushes the
    /// sum past 2^26 — satisfied, and the sum after the pow row is that sample's masked value alone.
    #[test]
    fn a_pow_row_after_a_wide_draw_does_not_overflow_the_running_sum() {
        use crate::verifier_program::ProgramBuilder;
        use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
        // slot 5 draws at k = 24 (`params()`); its sumcheck grinds ONE bit, so every transcript state has a witness
        let slot = 5usize;
        let mut fold = [0usize; NROUNDS];
        fold[slot] = 1;
        let p = params().with_pow([0; NROUNDS], fold, [0; NROUNDS]);
        assert_eq!(p.ks[slot], NB, "the wide slot draws over the full index width");
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31;
        let mask = (1u64 << NB) - 1;
        // a prefix word whose draw sums four masked samples to at least 3.5·2^24
        let (prefix, sum4) = (0u64..)
            .map(|i| {
                let mut ch = crate::hiding_decider::Chl::new(perm_for(seed));
                ch.observe(Fa4::from_u64(i));
                let s: u64 = (0..4)
                    .map(|_| {
                        let f: Fa4 = ch.sample();
                        f.as_canonical_u64() & mask
                    })
                    .sum();
                (Fa4::from_u64(i), s)
            })
            .find(|&(_, s)| s >= 7 * (1u64 << (NB - 1)))
            .expect("a wide draw");
        // the native transcript: the prefix, the draw (four samples), then the two-word pow — hi = 0 and the first lo
        // whose sample has a zero low bit AND whose masked value pushes the sum past 2^26
        let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
        native.observe(prefix);
        for _ in 0..4 {
            let _: Fa4 = native.sample();
        }
        let need = (1u64 << (NB + 2)) - sum4;
        let (lo, u) = (0u64..)
            .map(Fa4::from_u64)
            .find_map(|w| {
                let mut probe = native.clone();
                probe.observe(Fa4::ZERO);
                probe.observe(w);
                let s: Fa4 = probe.sample();
                let v = s.as_canonical_u64();
                (v & 1 == 0 && (v & mask) >= need).then_some((w, v & mask))
            })
            .expect("a ground witness in the overflowing range");
        assert!(native.clone().check_witness_wide(1, &[Fa4::ZERO, lo]), "the native accepts the ground witness");
        let mut pb = ProgramBuilder::new();
        pb.observe(prefix);
        pb.draw(slot);
        pb.observe(Fa4::ZERO);
        pb.observe(lo);
        pb.pop_pow(flag::POW_FOLD, Some(slot));
        let (program, stream) = pb.finish();
        let pow_row = program.iter().position(|fl| fl.is_set(flag::POW_FOLD)).expect("the pow row");
        let regs0 = [Fa4::ZERO; NREG];
        assert_eq!(
            first_unsatisfied_step(&p, &IO, regs0, &program, &stream),
            None,
            "⛔ an honest pow row after a wide draw is REFUSED: the running sum overflowed its decomposition (draw sum {sum4} + sample {u} ≥ 2^26)"
        );
        let tr = emulate(&p, &IO, regs0, &program, &stream);
        assert_eq!(tr.final_regs[TSUM_OFF], Fa4::from_u64(u), "after the pow row the sum is its own sample's masked value alone");
        eprintln!("[row] pow after a k = 24 draw: draw sum {sum4} + sample {u} = {} ≥ 2^26 = {} — satisfied, the pow row clears the sum", sum4 + u, 1u64 << (NB + 2));
    }

    /// The statement rows: `INIT` on row 0 refuses a nonzero initial state register and accepts zeros; `FINAL` on
    /// row `T − 2` pins the program digest to io block 0 (a one-flag-bit program change is refused); `IOCHK_p` pins
    /// a stream copy of an io block (a moved word is refused) — block 3 through the M5 `IOCHK_3` bit.
    #[test]
    fn the_statement_rows_bind_init_digest_and_io_copies() {
        let p = params();
        let t_bits = 2usize;
        let steps = 1usize << t_bits;
        let io_words: Vec<Fa4> = (0..IO_LEN as u64).map(|i| Fa4::from_u64(4000 + i)).collect();
        let (mut prog, mut stream) = idle(steps);
        prog[0].set(flag::INIT).set(flag::M_ABSORB);
        prog[1].set(flag::iochk(1)).set(flag::iochk(3)); // D[0..8] == io block 1 AND == io block 3: refused below
        stream[1] = word_row(&io_words[io_block(1)]);
        prog[steps - 2].set(flag::FINAL).pop(0, 3);
        // the digest: PS after row T−2 = the absorption of rows 0..T−2
        let tr0 = emulate(&p, &io_words, [Fa4::ZERO; NREG], &prog, &stream);
        let digest: Vec<Fa4> = tr0.regs_after(steps - 2)[PS_OFF..PS_OFF + RATE].to_vec();
        let mut io = io_words.clone();
        io[io_block(0)].copy_from_slice(&digest);
        {
            // both block flags on one row demand D equal two different blocks: refused; block 3 alone accepts its copy
            let inst = uniform_instance(&p, io.len(), t_bits).materialize();
            let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &prog, &stream);
            assert!(!inst.is_satisfied(&inst.lay_z(&io, &tr.w).unwrap()), "IOCHK_1 + IOCHK_3 on one copy row refuse a copy of block 1 alone");
            let mut prog3 = prog.clone();
            prog3[1] = RowFlags::default();
            prog3[1].set(flag::iochk(3));
            let mut stream3 = stream.clone();
            stream3[1] = word_row(&io_words[io_block(3)]);
            let tr3 = emulate(&p, &io, [Fa4::ZERO; NREG], &prog3, &stream3);
            let mut io3 = io.clone();
            io3[io_block(0)].copy_from_slice(&tr3.regs_after(steps - 2)[PS_OFF..PS_OFF + RATE]);
            let tr3 = emulate(&p, &io3, [Fa4::ZERO; NREG], &prog3, &stream3);
            assert!(inst.is_satisfied(&inst.lay_z(&io3, &tr3.w).unwrap()), "IOCHK_3 accepts a copy of io block 3 (the state hash)");
        }
        prog[1] = RowFlags::default();
        prog[1].set(flag::iochk(1));
        let tr0 = emulate(&p, &io_words, [Fa4::ZERO; NREG], &prog, &stream);
        io[io_block(0)].copy_from_slice(&tr0.regs_after(steps - 2)[PS_OFF..PS_OFF + RATE]);
        let inst = uniform_instance(&p, io.len(), t_bits).materialize();
        let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &prog, &stream);
        assert!(inst.is_satisfied(&inst.lay_z(&io, &tr.w).unwrap()), "INIT + FINAL + IOCHK accept the honest program");
        // a nonzero initial state register under INIT
        let mut regs_bad = [Fa4::ZERO; NREG];
        regs_bad[X_OFF + 5] = Fa4::ONE;
        let tr_bad = emulate(&p, &io, regs_bad, &prog, &stream);
        assert!(!inst.is_satisfied(&inst.lay_z(&io, &tr_bad.w).unwrap()), "INIT refuses a nonzero state register");
        // one flag bit more in a hashed row → the digest moves → FINAL refuses
        let mut prog_b = prog.clone();
        prog_b[1].pop(1, 2);
        let tr_b = emulate(&p, &io, [Fa4::ZERO; NREG], &prog_b, &stream);
        assert!(!inst.is_satisfied(&inst.lay_z(&io, &tr_b.w).unwrap()), "FINAL refuses a one-bit program change");
        // a moved io copy word
        let mut stream_c = stream.clone();
        stream_c[1][3] += Fa4::ONE;
        let tr_c = emulate(&p, &io, [Fa4::ZERO; NREG], &prog, &stream_c);
        assert!(!inst.is_satisfied(&inst.lay_z(&io, &tr_c.w).unwrap()), "IOCHK refuses a moved statement word");
        eprintln!("[row] statement rows: INIT/FINAL/IOCHK accept the honest program ({} constraints at T = {steps}) and refuse a nonzero init register, a one-bit program change and a moved io word", inst.rows());
    }

    /// H12 §12 C (F half): the F-ring liveness census reads a Horner (three pushes popped newest first) as pure
    /// LIFO with three live, and counts an out-of-order read (the older of two pushes read first) as non-LIFO.
    #[test]
    fn the_f_liveness_census_tells_a_lifo_horner_from_an_out_of_order_read() {
        let row = |f: &[usize], read: bool| {
            let mut r = RowFlags::default();
            for &i in f {
                r.set(i);
            }
            if read {
                r.xmove(0, flag::XM_ADD_F0);
            }
            r
        };
        let horner = vec![
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_ROT_UP], false),
            row(&[flag::F_ROT_UP], true),
            row(&[flag::F_ROT_UP], true),
            row(&[], true),
        ];
        let h = f_liveness(&horner);
        assert_eq!((h.pushes, h.reads, h.rereads, h.dead_pushes, h.max_live, h.non_lifo, h.overwritten_live), (3, 3, 0, 0, 3, 0, 0), "{h:?}");
        let ooo = vec![
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_ROT_UP], false),
            row(&[flag::F_ROT_UP], false),
            row(&[flag::F_ROT], true),
            row(&[], true),
        ];
        let o = f_liveness(&ooo);
        assert_eq!((o.pushes, o.reads, o.max_live, o.non_lifo), (2, 2, 2, 1), "{o:?}");
        assert_eq!((h.single_ids, h.reread_ids, h.max_live_single, h.max_live_reread, h.non_lifo_single), (3, 0, 3, 0, 0), "{h:?}");
        assert_eq!((o.single_ids, o.non_lifo_single), (2, 1), "{o:?}");
        // a reread id parked under a LIFO pair of folds: the folds stay LIFO among themselves, the parked id is the window
        let mixed = vec![
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_PUSH1], false),
            row(&[flag::F_ROT_UP], false),
            row(&[flag::F_ROT_UP], true),
            row(&[flag::F_ROT_UP], true),
            row(&[], true),
            row(&[], true),
        ];
        let m = f_liveness(&mixed);
        assert_eq!((m.single_ids, m.reread_ids, m.max_live_reread, m.non_lifo_single), (2, 1, 1, 0), "{m:?}");
        eprintln!("[f-liveness] census: LIFO Horner {h:?}; out-of-order {o:?}");
    }
}

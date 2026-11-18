// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CERTIFICATE'S ACC-STEP ROWS (spec §M5 "acc-step rows — the mechanism", 2026-09-28): the universal-row
//! instructions that turn the verified INNER step into THIS step — `acc' = compress(acc, summary)`, `work' = work +
//! block_work` limb by limb without wrap, and the STATE HASH the door reads from `io` block 3.
//!
//! The statement, in rows. The z̃ close's leaf rows hashed the inner io; two of them carry the inner PROGRAM DIGEST
//! (`IOCHK_BASE`: this program's or the genesis program's) and the inner STATE HASH (`R_CAPTURE`). These rows then:
//! 1. re-derive the inner state hash from stream words `acc_prev, work_prev, summary_prev, bw_prev` and `ROOT_CHECK`
//!    it against the captured block — so those four are PROVEN to be the inner step's state;
//! 2. fold `acc' = compress(acc_prev, summary)` on ONE production-mode row (`M_MERKLE ∧ M_LEAF`, the left half from
//!    `X0 ‖ X1`, the right from the stream) and bind a stream copy of `acc'` to it (`R_CAPTURE` before, `ROOT_CHECK`
//!    on the fold row);
//! 3. hash the OUTER state `M(M(P(acc' ‖ work') ‖ summary) ‖ bw)` into `H` and `ROOT_CHECK` it against io block 3
//!    (`IOCHK_3` on the capture row) — the door's number;
//! 4. prove `work' = work_prev + bw` as EIGHT 24-bit limbs: every limb vector is LOADED into the registers on the very
//!    row that hashes it (no second stream copy), folded into a queue of eight sums in the `F` bank (`S_k = w'_k − w_k
//!    − b_k + 2^24·c_k − c_{k−1}`, one pass per vector), the carries proven boolean (`EXT_EQ` on `c² = c`), the new
//!    limbs proven `< 2^24` (`RANGE24` as each passes through `X0`), the top carry proven zero, and every `S_k`
//!    proven zero at the end. Why the range check is mandatory even though the adopter limbs the tip canonically:
//!    without it a prover sets `c_k = 1` on a small sum, injecting `p·2^{24k}` of work that later carries normalise
//!    back into a canonical tip vector (spec §M5 item 7).
//!
//! ONE native definition per value: [`state_hash`], [`AccStep::compute`], `acc_step_air::work_limbs`. The rows never
//! restate a constant the native side computes.
//!
//! §9.6 parity (against the one-table IVC door this replaced, deleted at source 2026-09-28): (b) the base step is the GENESIS PROGRAM
//! ([`genesis_program`]) whose only statement is `io block 3 == the genesis state hash`, accepted through
//! `IOCHK_BASE` — no `is_base` selector over the verifier rows; (c) the fold row; (d) the limb passes; (f) the state
//! hash in io block 3 with the inner io bound by the statement hash and its digest pinned by `IOCHK_BASE`.
//!
//! ROOT-LAYER: the row constants these rows depend on (`RANGE24` reads `X0[0]`; `IOCHK_3`, `IOCHK_BASE`; the production
//! blend under `M_MERKLE ∧ M_LEAF`) are `universal_row`'s; the emitter tracks the register file's rotation itself.
//! MEASURED: the pins below (an isolated program at T = 2^9, every tamper refused at its own row). MUST-STAY-GREEN:
//! `acc_program::tests::*`, `fixed_program::tests::the_uniform_certificate_rows_check_the_summand_and_close_z`.

use crate::acc_step_air::{work_limbs, WORK_BITS, WORK_LIMBS};
use crate::hiding_decider::Fa4;
use crate::poseidon2_compress::{compress, Digest, DIGEST_LANES};
use crate::spartan_gadgets::RATE;
use crate::universal_row::{flag, RowFlags};
use crate::verifier_program::{After, ProgramBuilder};
use crate::whole_chain_cert::WHOLE_CHAIN_GENESIS_ACC;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;

const _: () = assert!(WORK_LIMBS == RATE && DIGEST_LANES == RATE, "a limb vector and a digest are each one stream block");
const _: () = assert!(WORK_BITS == crate::universal_row::NB, "RANGE24 is the row's 24-bit decomposition: the limb width must be it");

/// The genesis SUMMARY the base step's inner state hashes over — the empty fold's companion to
/// [`WHOLE_CHAIN_GENESIS_ACC`] (an all-zero digest): a public constant no party chooses.
pub const GENESIS_SUMMARY: Digest = [0u64; DIGEST_LANES];

fn words(d: &Digest) -> [Fa4; RATE] {
    core::array::from_fn(|k| Fa4::from_u64(d[k]))
}
fn limb_words(v: u128) -> [Fa4; RATE] {
    words(&work_limbs(v))
}
fn lanes(w: &[Fa4; RATE]) -> Digest {
    core::array::from_fn(|k| w[k].as_canonical_u64())
}

/// `M(x ‖ y)`: the row's MERKLE-constant permutation (the committed carrier's `COMMITTED_AIR_SEED`) over `[x ‖ y]`,
/// truncated to eight lanes — the state-hash chain's link.
fn merkle_compress(x: &[Fa4; RATE], y: &[Fa4; RATE]) -> [Fa4; RATE] {
    let mut st = [Fa4::ZERO; 2 * RATE];
    st[..RATE].copy_from_slice(x);
    st[RATE..].copy_from_slice(y);
    crate::sponge_chain_air::perm_for_seed(crate::committed_air::COMMITTED_AIR_SEED).permute_mut(&mut st);
    core::array::from_fn(|k| st[k])
}

/// THE STATE HASH the door reads: `M(M(P(acc ‖ work) ‖ summary) ‖ block_work)` with `P = compress` (the production
/// permutation, `acc` on the left) and `M` the merkle-constant compression; `work` and `block_work` as their
/// [`WORK_LIMBS`] 24-bit limbs. ONE definition: the rows compute exactly this (a PROD row, then two MERKLE rows).
#[must_use]
pub fn state_hash(acc: &Digest, work: u128, summary: &Digest, block_work: u128) -> [Fa4; RATE] {
    let h1 = words(&compress(acc, &work_limbs(work)));
    let h2 = merkle_compress(&h1, &words(summary));
    merkle_compress(&h2, &limb_words(block_work))
}

/// The base step's inner state: the genesis accumulator, zero work, the genesis summary, zero block work.
#[must_use]
pub fn genesis_state_hash() -> [Fa4; RATE] {
    state_hash(&WHOLE_CHAIN_GENESIS_ACC, 0, &GENESIS_SUMMARY, 0)
}

/// One step's inputs: the inner step's state and this block's summary and work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccStepIn {
    pub acc_prev: Digest,
    pub work_prev: u128,
    pub summary_prev: Digest,
    pub bw_prev: u128,
    pub summary: Digest,
    pub block_work: u128,
}

/// The step, computed natively — what the rows must reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccStep {
    pub input: AccStepIn,
    pub acc: Digest,
    pub work: u128,
    /// `c_k`: the carry out of limb `k` of `work_prev + block_work` (all within `u128`, so `c_7 = 0`).
    pub carries: [u64; WORK_LIMBS],
    pub state_prev: [Fa4; RATE],
    pub state: [Fa4; RATE],
}

impl AccStep {
    /// `None` when the work sum leaves `u128` — a chain nobody can have mined; fail-closed rather than wrapped.
    #[must_use]
    pub fn compute(input: AccStepIn) -> Option<Self> {
        let work = input.work_prev.checked_add(input.block_work)?;
        let (wp, bw) = (work_limbs(input.work_prev), work_limbs(input.block_work));
        let mut carries = [0u64; WORK_LIMBS];
        let mut carry = 0u64;
        for k in 0..WORK_LIMBS {
            let s = wp[k] + bw[k] + carry;
            carry = s >> WORK_BITS;
            carries[k] = carry;
        }
        if carry != 0 {
            return None;
        }
        Some(AccStep {
            input,
            acc: compress(&input.acc_prev, &input.summary),
            work,
            carries,
            state_prev: state_hash(&input.acc_prev, input.work_prev, &input.summary_prev, input.bw_prev),
            state: state_hash(&compress(&input.acc_prev, &input.summary), work, &input.summary, input.block_work),
        })
    }
    /// The base step from the genesis state.
    #[must_use]
    pub fn base(summary: Digest, block_work: u128) -> Option<Self> {
        Self::compute(AccStepIn {
            acc_prev: WHOLE_CHAIN_GENESIS_ACC,
            work_prev: 0,
            summary_prev: GENESIS_SUMMARY,
            bw_prev: 0,
            summary,
            block_work,
        })
    }
}

/// Rows the pins read: where each check sits (a tamper of that value is refused on that row) and the stream rows
/// that carry each prover-chosen block.
#[derive(Clone, Debug, Default)]
pub struct AccRows {
    pub first: usize,
    pub last: usize,
    /// The stream row holding `acc_prev` (the inner chain's left operand).
    pub acc_prev_row: usize,
    /// The inner chain's `ROOT_CHECK` row (the recomputed inner state against the captured one).
    pub inner_check_row: usize,
    /// The stream row holding the `acc'` copy, and the fold row that `ROOT_CHECK`s it.
    pub acc_copy_row: usize,
    pub fold_row: usize,
    /// The outer PROD row carrying `work'` (the range pass follows it).
    pub work_row: usize,
    pub range_rows: [usize; WORK_LIMBS],
    /// The outer MERKLE row carrying the SECOND summary copy and the two `EXT_EQ` rows binding it to the fold's copy.
    pub summary_row: usize,
    pub summary_bind_rows: [usize; 2],
    /// The outer MERKLE row carrying `block_work`.
    pub bw_row: usize,
    /// The io-block-3 capture row (`IOCHK_3`) and its `ROOT_CHECK` row.
    pub state_capture_row: usize,
    pub state_check_row: usize,
    /// The two stream rows carrying the carries (`c_0..c_3`, `c_4..c_7`), the eight booleanity `EXT_EQ` rows, the
    /// top-carry check row and the eight final `S_k == 0` rows.
    pub carry_rows: [usize; 2],
    pub bool_rows: [usize; WORK_LIMBS],
    pub top_carry_row: usize,
    pub sum_rows: [usize; WORK_LIMBS],
}

fn clr(r: &mut RowFlags, j: usize) -> &mut RowFlags {
    r.xmove(j, flag::XM_CLR)
}
/// Rotate the register file down by one: `X_j ← X_{j+1}`, `X_7 ← X_0`.
fn rot_all(r: &mut RowFlags) {
    for j in 0..8 {
        clr(r, j);
        r.xmove(j, flag::XM_ADD_NEXT);
    }
}
/// Load a stream block into the file: lanes `0..4` take the even words (`XM_ADD_DBASE`: `D[2j]`), lanes `4..8` the
/// odd words (`D[2j] + (D[2j+1] − D[2j])·E0` with `E0 = 1`). The file order is then `[v0, v2, v4, v6, v1, v3, v5, v7]`.
fn load_limbs(r: &mut RowFlags) {
    for j in 0..4 {
        clr(r, j);
        r.xmove(j, flag::XM_ADD_DBASE);
        clr(r, 4 + j);
        r.xmove(4 + j, flag::XM_ADD_DBASE).xmove(4 + j, flag::XM_ADD_MUL);
        r.mul_a(j, flag::AM_BASEPAIR).mul_b(j, flag::BM_E0);
    }
}
/// The file position of limb `k` after [`load_limbs`].
const fn limb_pos(k: usize) -> usize {
    if k % 2 == 0 { k / 2 } else { 4 + k / 2 }
}

/// One QUEUE PASS over a loaded limb vector, in NATURAL limb order (rotating the file to `limb_pos(k)` before each
/// step): `S_k ← (init ? 0 : F[0]) + sign·v_k`, pushed to `F`'s tail. Precondition: the queue's eight entries head
/// `F` (or `init`), `E0 = 1` when `sign < 0`. Postcondition: the file back at rotation 0, the queue's eight new entries
/// at `F`'s tail (`realign_queue` brings them to the head).
fn queue_pass(pb: &mut ProgramBuilder, init: bool, negative: bool) {
    let mut rho = 0usize;
    for k in 0..WORK_LIMBS {
        let target = limb_pos(k);
        while rho != target {
            rot_all(pb.row());
            rho = (rho + 1) % 8;
        }
        {
            let r = pb.row(); // X0 = v_k: S_k' = (F0) ± v_k
            if negative {
                clr(r, 0);
                r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_E0); // v_k · 1
                r.xmove(0, flag::XM_SUB_MUL);
            }
            if !init {
                r.xmove(0, flag::XM_ADD_F0);
            }
        }
        let r = pb.row(); // push S_k' (the OLD X0 of this row), rotate
        r.set(flag::F_PUSH1);
        rot_all(r);
        rho = (rho + 1) % 8;
    }
    while rho != 0 {
        rot_all(pb.row());
        rho = (rho + 1) % 8;
    }
}
/// Bring the queue's eight tail entries to the head.
fn realign_queue(pb: &mut ProgramBuilder) {
    for _ in 0..WORK_LIMBS {
        pb.row().set(flag::F_ROT_UP);
    }
}

/// THE ACC-STEP ROWS. Preconditions (the z̃ close's, [`crate::fixed_program::emit_zat_close`]): `R2` holds the inner
/// state hash (captured on the inner io's block-3 leaf row), `R` is free (its `ROOT_CHECK` done), `X`, `E0`, `E1`,
/// `E2`, `E3`, `H` and the `F` ring are free, no stream words pending. Postconditions: `H` = the outer state hash,
/// `R` = the same (checked against io block 3), `E0 = c_7 = 0`, `E1 = 2^24`, `E2 ‖ E3` = the summary, `F` rotated
/// (the fixed WHIR pushes its own entries), `B = 0`, `TSUM` cleared; `RS`, `PT`, `Y`, `VB`, `S` untouched.
pub fn emit_acc_step(pb: &mut ProgramBuilder, step: &AccStep) -> AccRows {
    assert_eq!(pb.pending_len(), 0, "the acc-step rows start on an empty input buffer");
    let inp = &step.input;
    let mut rows = AccRows::default();
    // ── constants: R ← the inner state hash, B ← 0, E0 = 1, E1 = 2^24 ─────────────────────────────────────────────
    pb.new_row();
    rows.first = pb.cur_row();
    {
        let r = pb.cur();
        r.set(flag::R_SHIFT).set(flag::TCLEAR).set(flag::STIR);
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_ONE);
    }
    {
        let r = pb.row();
        r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X); // E0 = 1
        r.xmove(0, flag::XM_ADD_X2J); // X0 = 2
    }
    for _ in 1..WORK_BITS {
        pb.row().xmove(0, flag::XM_ADD_X2J); // X0 doubles: 2^24 after 24 doublings
    }
    {
        let r = pb.row();
        clr(r, 1);
        r.set(flag::XM2_ADD_PREV + 1); // X1 = X0 = 2^24
    }
    pb.row().emove(1, flag::EM_CLR).emove(1, flag::EM_FROM_X); // E1 = 2^24
    // ── the inner chain: state_prev = M(M(P(acc_prev ‖ work_prev) ‖ summary_prev) ‖ bw_prev) == R ─────────────────
    pb.stream_words(&words(&inp.acc_prev));
    rows.acc_prev_row = pb.cur_row();
    {
        let r = pb.cur();
        for j in [0usize, 1, 4, 5] {
            clr(r, j);
            r.xmove(j, flag::XM_ADD_DA); // X0 ‖ X1 = acc_prev, and X4 ‖ X5 = acc_prev (parked next)
        }
    }
    {
        let r = pb.row(); // X6 = acc_prev hi
        clr(r, 6);
        r.set(flag::XM2_ADD_PREV + 6);
    }
    {
        let r = pb.row(); // X7 = acc_prev hi, X6 = acc_prev lo
        clr(r, 7);
        r.set(flag::XM2_ADD_PREV + 7);
        clr(r, 6);
        r.xmove(6, flag::XM_ADD_X2J);
    }
    pb.row().emove(2, flag::EM_CLR).set(flag::EM2_FROM_X4 + 2).emove(3, flag::EM_CLR).set(flag::EM2_FROM_X4 + 3); // E2 = X6 = lo, E3 = X7 = hi
    pb.prod_block(&limb_words(inp.work_prev)); // H = P(acc_prev ‖ work_prev); load work_prev
    load_limbs(pb.cur());
    queue_pass(pb, true, true); // S_k = −w_k
    pb.merkle_block(&words(&inp.summary_prev));
    pb.merkle_block(&limb_words(inp.bw_prev));
    pb.cur().set(flag::ROOT_CHECK);
    rows.inner_check_row = pb.cur_row();
    // ── the fold: acc' = P(acc_prev ‖ summary), its stream copy bound on the fold row ──────────────────────────────
    {
        let r = pb.row(); // X2 ‖ X3 = acc_prev (from E2 ‖ E3)
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_E);
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E);
    }
    {
        let r = pb.row(); // X1 = lo, X2 = hi
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT);
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_NEXT);
    }
    {
        let r = pb.row(); // X0 = lo, X1 = hi
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_NEXT);
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT);
    }
    pb.stream_words(&words(&step.acc)); // the acc' copy: R2 ← D, X4 ‖ X5 ← D
    rows.acc_copy_row = pb.cur_row();
    {
        let r = pb.cur();
        r.set(flag::R_CAPTURE);
        for j in [4usize, 5] {
            clr(r, j);
            r.xmove(j, flag::XM_ADD_DA);
        }
    }
    pb.row().set(flag::R_SHIFT); // R = the acc' copy
    pb.prod_block(&words(&inp.summary)); // H = P(acc_prev ‖ summary) = acc'; ROOT_CHECK: H[0..8] == R
    rows.fold_row = pb.cur_row();
    {
        let r = pb.cur();
        r.set(flag::ROOT_CHECK);
        for j in [0usize, 1] {
            clr(r, j);
            r.xmove(j, flag::XM_ADD_DA); // X0 ‖ X1 = the summary (copy A) — read after the permutation input
        }
    }
    // park copy A in E2 ‖ E3: X2 = hi, X3 = hi, X1 = lo, X2 = lo
    {
        let r = pb.row();
        clr(r, 2);
        r.set(flag::XM2_ADD_PREV + 2); // X2 = X1 = A hi
    }
    {
        let r = pb.row();
        clr(r, 3);
        r.set(flag::XM2_ADD_PREV + 3); // X3 = A hi
        clr(r, 1);
        r.set(flag::XM2_ADD_PREV + 1); // X1 = X0 = A lo
    }
    {
        let r = pb.row();
        clr(r, 2);
        r.set(flag::XM2_ADD_PREV + 2); // X2 = A lo
    }
    pb.row().emove(2, flag::EM_CLR).emove(2, flag::EM_FROM_X).emove(3, flag::EM_CLR).emove(3, flag::EM_FROM_X); // E2 = A lo, E3 = A hi
    {
        let r = pb.row(); // X0 ‖ X1 = acc' (from the bound copy in X4 ‖ X5)
        clr(r, 0);
        r.set(flag::XM2_ADD_X4J);
        clr(r, 1);
        r.set(flag::XM2_ADD_X4J + 1);
    }
    // ── the outer chain: state = M(M(P(acc' ‖ work') ‖ summary) ‖ bw) ─────────────────────────────────────────────
    pb.prod_block(&limb_words(step.work)); // H = P(acc' ‖ work'); load work'
    rows.work_row = pb.cur_row();
    load_limbs(pb.cur());
    for k in 0..WORK_LIMBS {
        // RANGE24 on X0 (the file's head: limbs in file order), then rotate — after eight rows the file is back
        {
            let r = pb.row();
            r.set(flag::TCLEAR).set(flag::RANGE24);
            rot_all(r);
        }
        rows.range_rows[k] = pb.cur_row();
    }
    realign_queue(pb);
    queue_pass(pb, false, false); // S_k += w'_k
    pb.merkle_block(&words(&inp.summary)); // H = M(h1 ‖ summary) — copy B, bound to copy A below
    rows.summary_row = pb.cur_row();
    {
        let r = pb.cur();
        for j in [4usize, 5] {
            clr(r, j);
            r.xmove(j, flag::XM_ADD_DA); // X4 ‖ X5 = copy B
        }
    }
    {
        let r = pb.row(); // X2 = A lo, X3 = A hi
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_E);
        clr(r, 3);
        r.xmove(3, flag::XM_ADD_E);
    }
    {
        let r = pb.row(); // X1 = A lo
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT);
    }
    {
        let r = pb.row(); // X0 = A lo; EXT_EQ X0 == X4 (B lo)
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_NEXT);
        r.set(flag::EXT_EQ);
        rows.summary_bind_rows[0] = pb.cur_row();
    }
    {
        let r = pb.row(); // X4 = B hi, X2 = A hi
        clr(r, 4);
        r.xmove(4, flag::XM_ADD_NEXT);
        clr(r, 2);
        r.xmove(2, flag::XM_ADD_NEXT);
    }
    {
        let r = pb.row(); // X1 = A hi
        clr(r, 1);
        r.xmove(1, flag::XM_ADD_NEXT);
    }
    {
        let r = pb.row(); // X0 = A hi; EXT_EQ X0 == X4 (B hi)
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_NEXT);
        r.set(flag::EXT_EQ);
        rows.summary_bind_rows[1] = pb.cur_row();
    }
    pb.merkle_block(&limb_words(inp.block_work)); // H = state; load bw
    rows.bw_row = pb.cur_row();
    load_limbs(pb.cur());
    // io block 3 == the state: capture the public copy, check H against it
    pb.stream_words(&step.state);
    rows.state_capture_row = pb.cur_row();
    pb.cur().set(flag::R_CAPTURE).set(flag::IOCHK_3);
    pb.row().set(flag::R_SHIFT).set(flag::ROOT_CHECK);
    rows.state_check_row = pb.cur_row();
    realign_queue(pb);
    queue_pass(pb, false, true); // S_k −= b_k
    // ── the carries: S_k += 2^24·c_k − c_{k−1}, c_k boolean, c_7 = 0 ─────────────────────────────────────────────
    realign_queue(pb);
    pb.row().emove(0, flag::EM_CLR); // E0 = c_{−1} = 0 (the loads are done; E0 now carries the previous carry)
    let c = step.carries;
    for half in 0..2 {
        // four carries per half in NATURAL order at lanes 0..4 (even stream words), lanes 4..8 dead or scratch
        let mut d = [Fa4::ZERO; RATE];
        for j in 0..4 {
            d[2 * j] = Fa4::from_u64(c[4 * half + j]);
        }
        pb.stream_words(&d);
        rows.carry_rows[half] = pb.cur_row();
        {
            let r = pb.cur();
            for j in 0..4 {
                clr(r, j);
                r.xmove(j, flag::XM_ADD_DBASE);
            }
        }
        for j in 0..4 {
            let k = 4 * half + j;
            {
                let r = pb.row(); // X4 = c
                clr(r, 4);
                r.set(flag::XM2_ADD_X4J + 4);
            }
            {
                let r = pb.row(); // X4 = c·c; EXT_EQ X0 == X4: c is boolean
                r.mul_a(0, flag::AM_X).mul_b(0, flag::BM_X4);
                clr(r, 4);
                r.xmove(4, flag::XM_ADD_MUL);
                r.set(flag::EXT_EQ);
                rows.bool_rows[k] = pb.cur_row();
            }
            {
                let r = pb.row(); // X4 = c again
                clr(r, 4);
                r.set(flag::XM2_ADD_X4J + 4);
            }
            {
                let r = pb.row(); // X5 = c
                clr(r, 5);
                r.set(flag::XM2_ADD_PREV + 5);
            }
            {
                let r = pb.row(); // X5 = 2^24·c
                r.mul_a(1, flag::AM_E).mul_b(1, flag::BM_X4); // E1 · X5
                clr(r, 5);
                r.xmove(5, flag::XM_ADD_MUL);
            }
            {
                let r = pb.row(); // X4 = 2^24·c
                clr(r, 4);
                r.xmove(4, flag::XM_ADD_NEXT);
            }
            {
                let r = pb.row(); // X0 = F0 + 2^24·c_k − c_{k−1}; E0 ← c_k (the OLD X0, read before the move) for the next limb
                clr(r, 0);
                r.xmove(0, flag::XM_ADD_F0).set(flag::XM2_ADD_X4J).xmove(0, flag::XM_SUB_E);
                r.emove(0, flag::EM_CLR).emove(0, flag::EM_FROM_X);
            }
            {
                let r = pb.row(); // push S_k', rotate the file
                r.set(flag::F_PUSH1);
                rot_all(r);
            }
        }
    }
    // the top carry: E0 = c_7 must be zero
    {
        let r = pb.row();
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_E);
        clr(r, 4);
        r.set(flag::EXT_EQ);
        rows.top_carry_row = pb.cur_row();
    }
    // ── every S_k == 0 ────────────────────────────────────────────────────────────────────────────────────────────
    realign_queue(pb);
    for k in 0..WORK_LIMBS {
        let r = pb.row();
        clr(r, 0);
        r.xmove(0, flag::XM_ADD_F0);
        clr(r, 4);
        r.set(flag::EXT_EQ).set(flag::F_ROT);
        rows.sum_rows[k] = pb.cur_row();
    }
    rows.last = pb.cur_row();
    rows
}

/// The GENESIS PROGRAM: the one other program an inner proof may be of (`IOCHK_BASE`). Its whole statement is `io
/// block 3 == the genesis state hash` (`IOCHK_3` on row 1, the words in its stream), `INIT` on row 0 and `FINAL` on
/// row `T − 2`; every other row is idle. A base step verifies a proof of THIS program exactly as it verifies a proof of
/// itself, and reads the genesis state from its io.
#[must_use]
pub fn genesis_program(t_bits: usize) -> (Vec<RowFlags>, Vec<[Fa4; crate::universal_row::NSTREAM]>) {
    let t = 1usize << t_bits;
    assert!(t >= 4, "a program needs INIT, the statement row, FINAL and the idle tail");
    let mut program = vec![RowFlags::default(); t];
    let mut stream = vec![[Fa4::ZERO; crate::universal_row::NSTREAM]; t];
    program[0].set(flag::INIT);
    program[1].set(flag::iochk(3));
    stream[1][..RATE].copy_from_slice(&genesis_state_hash());
    program[t - 2].set(flag::FINAL);
    (program, stream)
}

/// A program's digest: `PS` after row `T − 2` — the value `FINAL` pins to io block 0 — computed NATIVELY as the row's
/// program sponge does it (`universal_row`: the flag words overwrite the first `NFLAG_WORDS` lanes, the capacity
/// lanes carry, one production permutation per row; `PS` starts at zero by `INIT`). A function of the flags alone —
/// no stream, no io, no other row parameter — so the release constant costs milliseconds, not an emulation. Pinned
/// equal to the emulator's `PS` in `the_genesis_program_pins_the_genesis_state_and_has_one_digest`.
#[must_use]
pub fn program_digest(program: &[RowFlags]) -> [Fa4; RATE] {
    assert!(program.len() >= 2, "a program has a FINAL row at T − 2");
    let perm = crate::sponge_chain_air::production_perm();
    let mut st = [Fa4::ZERO; 2 * RATE];
    for flags in &program[..program.len() - 1] {
        let fw = flags.words();
        st[..crate::universal_row::NFLAG_WORDS].copy_from_slice(&fw);
        perm.permute_mut(&mut st);
    }
    core::array::from_fn(|k| st[k])
}

/// The last row of a builder's program (for callers that stitch the acc rows after other emitters).
pub fn after(pb: &ProgramBuilder) -> After {
    After { row: pb.cur_row() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiding_decider::Ea4;
    use crate::universal_row::{emulate, first_unsatisfied_step, io_block, E_OFF, H_OFF, IO_LEN, NREG, NSTREAM, PS_OFF, R_OFF, X_OFF};
    use p3_field::BasedVectorSpace;

    fn params() -> crate::universal_row::RowParams {
        crate::universal_row::RowParams::decider(core::array::from_fn(|r| Fa4::from_u64(1000 + r as u64)), [12, 20, 8, 4, 1, 24, 6, 6, 6, 6], 3)
    }
    fn reg_ext(regs: &[Fa4], off: usize) -> Ea4 {
        Ea4::from_basis_coefficients_fn(|i| regs[off + i])
    }

    /// The native state hash IS the rows' chain: one PROD row and two MERKLE rows reproduce it in `H`.
    #[test]
    fn the_state_hash_is_one_prod_row_and_two_merkle_rows() {
        let step = AccStep::base([7u64, 11, 13, 17, 19, 23, 29, 31], 1u128 << 40).expect("a base step");
        let p = params();
        let mut pb = ProgramBuilder::new();
        pb.new_row();
        pb.cur().set(flag::TCLEAR).set(flag::STIR); // B = 0
        pb.stream_words(&words(&step.acc));
        {
            let r = pb.cur();
            for j in [0usize, 1] {
                clr(r, j);
                r.xmove(j, flag::XM_ADD_DA);
            }
        }
        pb.prod_block(&limb_words(step.work));
        let prod_row = pb.cur_row();
        pb.merkle_block(&words(&step.input.summary));
        pb.merkle_block(&limb_words(step.input.block_work));
        let last = pb.cur_row();
        let (program, stream) = pb.finish();
        let io = vec![Fa4::ZERO; IO_LEN];
        let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
        let h = |row: usize| -> [Fa4; RATE] { core::array::from_fn(|k| tr.regs_after(row)[H_OFF + k]) };
        assert_eq!(h(prod_row), words(&compress(&step.acc, &work_limbs(step.work))), "the PROD row is `compress(acc, work)`");
        assert_eq!(h(last), step.state, "three rows reproduce `state_hash`");
        eprintln!("[acc-rows] ⭐ the state hash: PROD row = compress (production constants), two MERKLE rows = the chain");
    }

    /// THE STEP AS ROWS (an isolated program at T = 2^9): the honest rows satisfy with the inner state captured, the
    /// registers hold the native values at the named rows, and every tamper is refused at its own row.
    #[test]
    fn the_acc_step_rows_fold_add_and_hash_and_refuse_every_tamper() {
        let t_bits = 9usize;
        let t = 1usize << t_bits;
        let step = AccStep::compute(AccStepIn {
            acc_prev: [101u64, 202, 303, 404, 505, 606, 707, 808],
            work_prev: (1u128 << 100) + (0xFF_FFFFu128 << 24) + 0xAB_CDEF,
            summary_prev: [1u64, 2, 3, 4, 5, 6, 7, 8],
            bw_prev: 1u128 << 30,
            summary: [9u64, 8, 7, 6, 5, 4, 3, 2],
            block_work: (0x12_3456u128 << 24) + 0x54_3210,
        })
        .expect("a step");
        assert!(step.carries.iter().any(|&c| c == 1), "the fixture carries at least once (limb 0: 0xABCDEF + 0x543210 ≥ 2^24)");
        let p = params();
        let build = |step: &AccStep| {
            let mut pb = ProgramBuilder::new();
            pb.new_row();
            pb.cur().set(flag::INIT);
            pb.capture_root(&step.state_prev); // stands in for the z̃ leaf row's R_CAPTURE of the inner io block 3
            let rows = emit_acc_step(&mut pb, step);
            let (mut program, mut stream) = pb.finish();
            assert!(program.len() + 2 <= t, "the acc step fits T = {t} rows ({} emitted)", program.len());
            while program.len() < t {
                program.push(RowFlags::default());
                stream.push([Fa4::ZERO; NSTREAM]);
            }
            program[t - 2].set(flag::FINAL);
            (program, stream, rows)
        };
        let (program, stream, rows) = build(&step);
        let mut io = vec![Fa4::ZERO; IO_LEN];
        io[io_block(3)].copy_from_slice(&step.state);
        let tr0 = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
        io[io_block(0)].copy_from_slice(&tr0.regs_after(t - 2)[PS_OFF..PS_OFF + RATE]);
        let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
        let h = |row: usize| -> [Fa4; RATE] { core::array::from_fn(|k| tr.regs_after(row)[H_OFF + k]) };
        let r = |row: usize| -> [Fa4; RATE] { core::array::from_fn(|k| tr.regs_after(row)[R_OFF + k]) };
        assert_eq!(h(rows.inner_check_row), step.state_prev, "the inner chain re-derives the inner state hash");
        assert_eq!(r(rows.inner_check_row), step.state_prev, "against the captured block");
        assert_eq!(h(rows.fold_row), words(&step.acc), "the fold row is `compress(acc_prev, summary)`");
        assert_eq!(r(rows.fold_row), words(&step.acc), "the acc' copy sits in R on the fold row");
        let x = |row: usize, lane: usize| reg_ext(&tr.regs_after(row), X_OFF + 4 * lane);
        let acc_lo = Ea4::from_basis_coefficients_fn(|i| Fa4::from_u64(step.acc[i]));
        let acc_hi = Ea4::from_basis_coefficients_fn(|i| Fa4::from_u64(step.acc[4 + i]));
        assert_eq!((x(rows.work_row - 1, 0), x(rows.work_row - 1, 1)), (acc_lo, acc_hi), "X0 ‖ X1 = acc' entering the outer PROD row");
        let h1 = words(&compress(&step.acc, &work_limbs(step.work)));
        assert_eq!(h(rows.work_row), h1, "the outer PROD row is `compress(acc', work')`");
        let h2 = merkle_compress(&h1, &words(&step.input.summary));
        assert_eq!(h(rows.summary_row), h2, "the summary MERKLE row");
        assert_eq!(h(rows.bw_row), step.state, "the block_work MERKLE row closes the state hash");
        assert_eq!(h(rows.state_check_row), step.state, "the outer chain is the state hash");
        assert_eq!(reg_ext(&tr.regs_after(rows.first + 1), E_OFF), Ea4::ONE, "E0 = 1");
        assert_eq!(reg_ext(&tr.regs_after(rows.first + 2 + WORK_BITS), E_OFF + 4), Ea4::from_u64(1 << WORK_BITS), "E1 = 2^24");
        for k in 0..WORK_LIMBS {
            assert_eq!(x(rows.sum_rows[k], 0), Ea4::ZERO, "S_{k} == 0 at its check row");
        }
        assert_eq!(first_unsatisfied_step(&p, &io, [Fa4::ZERO; NREG], &program, &stream), None, "the honest acc-step rows satisfy");
        eprintln!(
            "[acc-rows] {} rows ({}..={}): inner check {}, fold {}, work {}, summary bind {:?}, bw {}, state check {}, carries {:?}, top carry {}, sums {:?}",
            rows.last + 1 - rows.first,
            rows.first,
            rows.last,
            rows.inner_check_row,
            rows.fold_row,
            rows.work_row,
            rows.summary_bind_rows,
            rows.bw_row,
            rows.state_check_row,
            rows.carry_rows,
            rows.top_carry_row,
            rows.sum_rows
        );
        // TAMPERS — each a single stream word or io word, each refused at the row that checks it.
        let refused_at = |stream_t: &Vec<[Fa4; NSTREAM]>, io_t: &Vec<Fa4>| first_unsatisfied_step(&p, io_t, [Fa4::ZERO; NREG], &program, stream_t);
        {
            let mut s = stream.clone(); // the inner state's preimage: a moved acc_prev word
            s[rows.acc_prev_row][3] += Fa4::ONE;
            assert_eq!(refused_at(&s, &io), Some(rows.inner_check_row), "⛔ a wrong inner accumulator passed the inner state check");
        }
        {
            let mut s = stream.clone(); // the acc' copy
            s[rows.acc_copy_row][0] += Fa4::ONE;
            assert_eq!(refused_at(&s, &io), Some(rows.fold_row), "⛔ a wrong acc' copy passed the fold's ROOT_CHECK");
        }
        {
            let mut s = stream.clone(); // the second summary copy
            s[rows.summary_row][5] += Fa4::ONE;
            let at = refused_at(&s, &io).expect("⛔ a summary copy that differs from the fold's was accepted");
            assert!(at <= rows.summary_bind_rows[1], "the copy binding refuses it by row {} (got {at})", rows.summary_bind_rows[1]);
        }
        {
            let mut io_t = io.clone(); // the public state
            io_t[io_block(3).start] += Fa4::ONE;
            assert_eq!(refused_at(&stream, &io_t), Some(rows.state_capture_row), "⛔ a wrong public state hash passed IOCHK_3");
        }
        {
            let mut s = stream.clone(); // a block_work limb: the state hash moves AND the sum breaks
            s[rows.bw_row][0] += Fa4::ONE;
            let at = refused_at(&s, &io).expect("⛔ a wrong block_work limb was accepted");
            assert!(at <= rows.state_check_row, "refused by the state check (got {at})");
        }
        {
            let mut s = stream.clone(); // a carry of 2 (limb 0): not boolean
            s[rows.carry_rows[0]][0] = Fa4::from_u64(2);
            assert_eq!(refused_at(&s, &io), Some(rows.bool_rows[0]), "⛔ a non-boolean carry passed the booleanity check");
        }
        {
            // a limb out of range: work'_0 raised by 2^24 with the carry lowered to keep the sum — refused by RANGE24
            let mut s = stream.clone();
            s[rows.work_row][0] += Fa4::from_u64(1 << WORK_BITS);
            s[rows.carry_rows[0]][0] -= Fa4::ONE;
            let at = refused_at(&s, &io).expect("⛔ a work limb ≥ 2^24 with an adjusted carry was accepted");
            assert!(at <= rows.range_rows[WORK_LIMBS - 1] || at == rows.state_check_row, "refused by the range pass or the state check (got {at})");
        }
        eprintln!("[acc-rows] ⭐ GREEN: honest rows satisfy; a wrong inner acc, acc' copy, summary copy, public state, bw limb, carry and out-of-range limb are each refused");
    }

    /// The genesis program: its digest is a function of its rows alone, its statement pins io block 3 to the genesis
    /// state, and a proof of it is what `IOCHK_BASE` admits beside this program.
    #[test]
    fn the_genesis_program_pins_the_genesis_state_and_has_one_digest() {
        let p = params();
        let (g, gs) = genesis_program(9);
        let d1 = program_digest(&g);
        assert_ne!(d1, [Fa4::ZERO; RATE], "never the zero block");
        // the native digest IS the emulator's PS after row T − 2
        let tr = emulate(&p, &vec![Fa4::ZERO; IO_LEN], [Fa4::ZERO; NREG], &g, &gs);
        assert_eq!(&tr.regs_after(g.len() - 2)[PS_OFF..PS_OFF + RATE], &d1[..], "the native program digest equals the row's PS");
        let mut io = vec![Fa4::ZERO; IO_LEN];
        io[io_block(0)].copy_from_slice(&d1);
        io[io_block(3)].copy_from_slice(&genesis_state_hash());
        assert_eq!(first_unsatisfied_step(&p, &io, [Fa4::ZERO; NREG], &g, &gs), None, "the genesis program accepts its io");
        let mut bad = io.clone();
        bad[io_block(3).start] += Fa4::ONE;
        assert_eq!(first_unsatisfied_step(&p, &bad, [Fa4::ZERO; NREG], &g, &gs), Some(1), "⛔ a genesis proof over another state passed");
        eprintln!("[acc-rows] ⭐ genesis program: digest {:?}…, refuses any other io block 3", d1[0]);
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE ACCUMULATOR RECURRENCE AS CONSTRAINTS — `acc_out == fold(acc_in, summary)` anchored at the
//! genesis constant, and the ACCUMULATED WORK that makes the anchor cost something.
//!
//! ## Where this sits
//!
//! [`crate::transcript_bind_air`] made the recursion's inner STATEMENT unforgeable: the challenges are
//! Poseidon-derived under constraint and welded to the committed carrier, so a bound step proves *"I
//! verified a real proof of THIS statement."* It does not prove *"and that statement chains back to
//! genesis"*, and it says nothing about what the chain COST. This module is both halves of that.
//!
//! ## ⛔ THE FOLD CHANGES SHAPE HERE, DELIBERATELY — AND THE OBJECTION IS ANSWERED, NOT IGNORED
//!
//! `whole_chain_cert`'s own comment records a LIVE MEASUREMENT for keeping the accumulator commutative:
//! "nodes apply the same block in DIFFERENT ORDERS … an order-dependent accumulator would make two nodes
//! holding the identical chain advertise different certificates (A `295b894e…` vs B `3668356a…`)". That
//! measurement is real and it is about the MEMBERSHIP fold, where notes genuinely arrive in arbitrary
//! order and no canonical order exists. A CHAIN is different: GHOSTDAG gives every node the same blue
//! ordering from the same DAG, and a RECURSIVE certificate must fold in a deterministic order regardless
//! — you cannot un-prove a step, so commutativity buys nothing back on a reorg either (both shapes
//! re-fold the reordered suffix from a checkpoint, which is what Bitcoin does). Order-binding is the
//! proven shape; the requirement it creates is that the certificate steps in CANONICAL order, never
//! arrival order, and that is a node-wiring obligation recorded here so it cannot be forgotten.
//!
//!
//! `whole_chain_cert`'s ORIGINAL fold was a COMMUTATIVE u64 add-with-carry over
//! a domain-separated Poseidon leaf. Two problems, both real:
//!   * a commutative ADD commits the SET of summaries and never the ORDER — a standing open item in this
//!     tree's launch-readiness cardinal ("acc is COMMUTATIVE ⇒ never binds order"). A chain is an ORDERED
//!     object; a set accumulator cannot separate two histories that applied the same blocks in different
//!     orders;
//!   * u64 add-with-carry is a *binary* operation asked to live in a 31-bit prime field. In circuit it
//!     costs bit decomposition and carry chains for no benefit at all.
//! So the IVC fold is the SEQUENTIAL hash chain [`acc_step_fold_native`]:
//! `acc_out = poseidon_pair(acc_in, summary)` — the tree's own one-round `pre = l + 7·r`, `out = MDS·pre⁷`
//! ([`crate::nullifier_insert_air::poseidon_pair_native`], reused verbatim, no new primitive). It binds
//! order by construction and is DEGREE 3 in committed cells once the S-box is staged.
//!
//! ## ⭐ WHY WORK IS IN THE SAME STEP, AND NOT A SEPARATE CHECK
//!
//! The accumulator recurrence makes a LONG chain unforgeable. On its own it does nothing about a SHORT
//! one: a party holding no chain sets the base flag, folds ONE invented summary from the genesis
//! constant, and produces a step every constraint accepts. Two verifying certificates then look alike and
//! an adopter has no ground to prefer the real chain — which is `pin_d2b`'s attacker exactly, whose shell
//! carried `work = 1`. So the step ALSO advances an accumulated-work counter, and fork choice is by that
//! counter. Bitcoin's rule, borrowed rather than re-derived: a one-step claim carries one block's work.
//!
//! ⛔⛔⛔ AND THE COUNTER IS NOT YET SOUND ON ITS OWN — READ THIS BEFORE TRUSTING IT. The counter binds the
//! ADDITION (a total nobody added is refused, gated below); it does NOT bind the per-step `block_work`,
//! which is a free public input. A party can declare any block's work and the arithmetic will happily
//! accumulate it. The obvious fix — verify the block's PoW in circuit — is MEASURED IMPOSSIBLE here:
//! `pow_pq_kernel` costs 32,768 + 2,048 = **34,816 Poseidon2-16 permutations per hash** over a 2 MB
//! DATA-DEPENDENT scratchpad, i.e. 5,709,824 trace cells for ONE block against the 32 rows a whole IVC
//! step takes today. Memory-hardness exists to make exactly that re-execution expensive, so a memory-hard
//! PoW and a succinct recursive proof of cumulative work are mutually exclusive. The closing move is
//! FlyClient-style SAMPLING of the work claims against an inclusion-proving accumulator — see kill list
//! §AB, which also records why the hash-CHAIN fold below must become a Merkle Mountain Range for that.
//!
//! Work is a 192-bit integer in [`WORK_LIMBS`] limbs of base 2^[`WORK_BITS`], added with BOOLEAN carries,
//! and every output limb is recomposed from its own bits — which is what proves it stayed in range
//! without any lookup argument. `2^24 + 2^24 < p` for KoalaBear, so no addition here can wrap the field
//! and no carry can be hidden.
//!
//! ## COST (arithmetic, not assurance — this adds NO cardinal-class cost)
//!
//! Every quantity below is f(fixed constants). Nothing in this file has a term in chain height, block
//! count, note count, peer count or DAG width, and no loop here walks history:
//!   * **TRACE**: [`ACC_COLS`] = 257 columns × 32 rows (the WHIR `nvars ≥ 5` floor) = **8,224 field cells
//!     per step, constant**. The 257 breaks down as 8 digest groups × 4 limbs = 32, one base selector,
//!     4 work vectors × 8 limbs = 32, and 8 × 24 = 192 range bits. A chain of height 1 and a chain of
//!     height 10^18 lay out the identical table.
//!   * **CONSTRAINTS**: 1 selector + 4 limbs × 5 fold residuals + 4 MDS rows + 8 limbs × 27 work
//!     residuals + 1 final carry + 257 replication = **499 residuals, constant**.
//!   * **VERIFY**: one `verify_air_direct_light_decider_selfcontained_bytes` over that fixed shape — the
//!     same work at any height, no per-block data read. This is the number the adopt path cares about.
//!   * **PROVE**: one step as ONE block is applied. Per-step work is constant, so a single operation's
//!     cost is f(blocks applied THIS run) — Mina's per-block prover model — never f(chain length).
//!   * **WIRE**: the work total adds [`WORK_LIMBS`] = 8 limbs × 4 B = **32 bytes** to a step's statement.
//!   * **WORK WIDTH**: 192 bits is the width of a NUMBER, never a bound on how far a chain may reach. At
//!     2^30 work per block and one block per second a chain accumulates ≈ 2^55 per year, so 2^192 is
//!     ≈ 2^137 years of headroom. The circuit is WIDER than the native `u128` total (a compile-time
//!     assert holds that), and [`build_acc_trace`] fails closed on a `u128` overflow rather than wrapping.
//! Cons: none in any cardinal. The one real cost is 257 columns where the transition alone would have
//! taken 33, and that is the price of range-checking work without a lookup argument — paid once per step,
//! flat forever.
//!
//! ## Everything is a COLUMN, nothing is a circuit constant
//!
//! `summary`, `acc_out`, the per-block work and the inherited work are all committed columns, welded by
//! cross-tie to either the outer statement's public IO (at the top, where the adopter names them) or the
//! inner bind's absorbed cells (inside the recursion, where they must stay witness). Baking them into the
//! circuit instead would have been simpler and WRONG: a recursive verifier cannot rebuild a circuit whose
//! constants are values it is not allowed to know. Recorded because the first draft of this file did
//! exactly that.
//!
//! ROOT-LAYER: the transition is constrained where it HAPPENS — between the inherited accumulator and the
//! new one — not re-checked by a reader afterwards. A reader-side check sees numbers a prover chose.
//!
//! MUST-STAY-GREEN: `nullifier_insert_air`'s Poseidon pin (this module reuses its primitive and its
//! `SPEND_MDS`), and `transcript_bind_air`'s four gates.

// ONE digest width for the whole tree — 8 lanes x 31 bits = 248 bits (kill list §AG).
use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};
use crate::nullifier_insert_air::{kred, poseidon_pair_native};
use crate::whole_chain_cert::WHOLE_CHAIN_GENESIS_ACC;
use p3_field::PrimeCharacteristicRing;

/// Limbs in one accumulator or summary digest — the shape of every fold in this crate, never a count of
/// blocks or notes.
pub const D: usize = crate::poseidon2_compress::DIGEST_LANES;

/// Bits per work limb. `2^24 + 2^24 < p` for KoalaBear (`p = 2^31 − 2^24 + 1`), so a limb sum plus a
/// carry can never wrap the field and hide itself.
pub const WORK_BITS: usize = 24;
/// Limbs of accumulated work: 8 × 24 = 192 bits — the width of a NUMBER, fixed for the life of the
/// circuit, with the headroom arithmetic written in the COST section above.
pub const WORK_LIMBS: usize = 8;

/// Column layout of one accumulator-step row.
pub const ACC_IN: usize = 0;
pub const SUMMARY: usize = ACC_IN + D;
pub const ACC_OUT: usize = SUMMARY + D;
pub const ACC_EFF: usize = ACC_OUT + D;
/// The fold's permutation block. ⛔ WAS four staged S-box column groups (`pre/psq/p4/pre7`) over the
/// 1-round `MDS·(l+7r)⁷` — the fold kill list §AG measured as invertible, which let a chainless party SOLVE
/// for a `summary` that lands on any accumulator it wanted. The fold is now a whole Poseidon2 permutation.
pub const FOLD_P2: usize = ACC_EFF + D;
pub const IS_BASE: usize = FOLD_P2 + crate::pow_pq_air::P2_COLS;
pub const WORK_IN: usize = IS_BASE + 1;
pub const WORK_ADD: usize = WORK_IN + WORK_LIMBS;
pub const WORK_OUT: usize = WORK_ADD + WORK_LIMBS;
pub const WORK_CARRY: usize = WORK_OUT + WORK_LIMBS;
pub const WORK_BIT: usize = WORK_CARRY + WORK_LIMBS;
/// Total committed width of one accumulator-step row.
pub const ACC_COLS: usize = WORK_BIT + WORK_LIMBS * WORK_BITS;

/// The circuit must be at least as wide as the native work type, or [`work_limbs`] would silently drop
/// the high bits of a total the caller handed it. Checked at COMPILE time so the two cannot drift.
const _: () = assert!(
    WORK_BITS * WORK_LIMBS >= u128::BITS as usize,
    "the work limbs must cover every bit of the native u128 total"
);

/// The S-box multiplier of the tree's one-round Poseidon pair (`pre = left + 7·right`), taken from
/// [`crate::nullifier_insert_air::poseidon_pair_native`] rather than restated as a new constant.
const PAIR_MULT: u64 = 7;

/// The IVC accumulator fold: `acc_out = poseidon_pair(acc_in, summary)`. ORDER-BINDING by construction —
/// the same summaries applied in a different order give a different accumulator, which a commutative add
/// cannot do. ONE definition; the circuit below constrains exactly this function.
#[must_use]
pub fn acc_step_fold_native(acc_in: [u64; D], summary: [u64; D]) -> [u64; D] {
    poseidon_pair_native(acc_in, summary)
}

/// The accumulator this step folds from: the genesis constant at the base of the chain, the inherited one
/// everywhere else. Mirrors the circuit's `acc_eff` exactly.
#[must_use]
pub fn acc_effective(acc_in: [u64; D], is_base: bool) -> [u64; D] {
    if is_base {
        WHOLE_CHAIN_GENESIS_ACC
    } else {
        acc_in
    }
}

/// Split a work total into limbs of [`WORK_BITS`] bits, least significant first.
#[must_use]
pub fn work_limbs(total: u128) -> [u64; WORK_LIMBS] {
    let mask = (1u128 << WORK_BITS) - 1;
    // The circuit is WIDER than `u128` on purpose, so the top limbs lie beyond what the native type can
    // express and are zero by definition. Shifting a u128 by 128 or more is a panic, not zero, which is
    // why this is written as a branch rather than left to the shift.
    core::array::from_fn(|k| {
        let sh = WORK_BITS * k;
        if sh >= u128::BITS as usize {
            0
        } else {
            ((total >> sh) & mask) as u64
        }
    })
}

/// Recompose limbs into the integer they denote — the inverse of [`work_limbs`], and what fork choice
/// compares.
#[must_use]
pub fn work_total(limbs: [u64; WORK_LIMBS]) -> u128 {
    limbs.iter().enumerate().fold(0u128, |t, (k, &v)| {
        let sh = WORK_BITS * k;
        if sh >= u128::BITS as usize {
            // A limb past the native width can only be zero on any total this API can have produced;
            // anything else is a caller error, and saturating is the fail-loud reading of it.
            if v == 0 { t } else { u128::MAX }
        } else {
            t + ((v as u128) << sh)
        }
    })
}

/// The work this step inherits: zero at the base, the carried total everywhere else.
#[must_use]
pub fn work_effective(work_in: u128, is_base: bool) -> u128 {
    if is_base {
        0
    } else {
        work_in
    }
}

/// Lay one accumulator step as a trace, replicated to `rows`. The replication is this crate's own carrier
/// shape (`LIGHT_CARRIER_ROWS`) — a fixed circuit height with no term in chain length. `None` when the
/// work total would exceed the fixed 192-bit width: fail-closed, never a silent wrap.
#[must_use]
pub fn build_acc_trace(
    acc_in: [u64; D],
    summary: [u64; D],
    work_in: u128,
    block_work: u128,
    is_base: bool,
    rows: usize,
) -> Option<Vec<Vec<Fa4>>> {
    let eff = acc_effective(acc_in, is_base);
    let acc_out = acc_step_fold_native(eff, summary);
    let w_eff = work_effective(work_in, is_base);
    // Fail-closed on the only overflow that can actually occur: the NATIVE total is a u128 and the
    // circuit carries 192 bits, so a u128 total always fits the limbs — the const assert below is what
    // keeps that true if either width is ever changed.
    let w_out = w_eff.checked_add(block_work)?;
    let f = |v: u64| Fa4::from_u64(kred(v));
    let mut row = vec![Fa4::ZERO; ACC_COLS];
    for c in 0..D {
        row[ACC_IN + c] = f(acc_in[c]);
        row[SUMMARY + c] = f(summary[c]);
        row[ACC_OUT + c] = f(acc_out[c]);
        row[ACC_EFF + c] = f(eff[c]);
    }
    crate::pow_pq_air::lay_perm_row_flat(&mut row, FOLD_P2, crate::pow_pq_air::pair_state(&eff, &summary));
    row[IS_BASE] = if is_base { Fa4::ONE } else { Fa4::ZERO };

    let (l_in, l_add, l_out) = (work_limbs(work_in), work_limbs(block_work), work_limbs(w_out));
    let l_eff = work_limbs(w_eff);
    let mut carry = 0u64;
    for k in 0..WORK_LIMBS {
        let t = l_eff[k] + l_add[k] + carry;
        carry = t >> WORK_BITS;
        row[WORK_IN + k] = f(l_in[k]);
        row[WORK_ADD + k] = f(l_add[k]);
        row[WORK_OUT + k] = f(l_out[k]);
        row[WORK_CARRY + k] = Fa4::from_u64(carry);
        let bits = l_out[k];
        for j in 0..WORK_BITS {
            row[WORK_BIT + k * WORK_BITS + j] = Fa4::from_u64((bits >> j) & 1);
        }
    }
    Some(row.iter().map(|&v| vec![v; rows]).collect())
}

/// The accumulator-step gate. Every value it reasons about is a COMMITTED COLUMN — nothing is a circuit
/// constant, so a recursive verifier can rebuild this circuit without knowing the step's statement.
pub struct AccStepConstraint {
    pub gamma: Ea4,
}

impl AirConstraint for AccStepConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // The tallest residual is `pre7 − p4·psq·pre`, degree 3 in committed cells. 8 matches every other
        // table this crate batches, so one shape covers the batch. Over-declaring costs evaluation points
        // and is sound; under-declaring is not.
        8
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;
        let g = self.gamma;
        let mut acc = Ea4::ZERO;
        let mut push = |a: &mut Ea4, r: Ea4| *a = *a * g + r;

        // BOOLEANITY — an unconstrained selector lets a prover blend the base and inherited branches and
        // land on an accumulator neither of them yields.
        let b = local[IS_BASE];
        push(&mut acc, b * (Ea4::ONE - b));

        let mult = Ea4::from_u64(PAIR_MULT);
        for c in 0..D {
            let a_eff = local[ACC_EFF + c];
            // THE BASE ANCHOR: at the base of the chain the step folds from the GENESIS constant every
            // honest node on this network computes; everywhere else, from what it inherited.
            let gen = Ea4::from_u64(kred(WHOLE_CHAIN_GENESIS_ACC[c]));
            push(&mut acc, a_eff - (b * gen + (Ea4::ONE - b) * local[ACC_IN + c]));
        }
        // THE FOLD ITSELF — a whole permutation over `(acc_eff ‖ summary)`, welded at both ends.
        //
        // ⛔ THIS IS THE STEP THE JOIN DOOR TURNS ON. Under the 1-round fold a chainless party could
        // SOLVE for a `summary` that carried any `acc_in` to any `acc_out` it liked, so the accumulator
        // recurrence constrained nothing: `sib = ((MDS⁻¹·target)^{1/7} − node)/7`. There is no algebraic
        // route back through a permutation.
        // `push` folds one residual into the running γ-accumulator, so the block's residuals are
        // collected first and then folded individually — each gets its OWN γ power, which is what the
        // batching soundness argument requires.
        let mut perm_rs: Vec<Ea4> = Vec::new();
        crate::pow_pq_air::push_perm_residuals(local, FOLD_P2, &mut perm_rs);
        for r in perm_rs {
            push(&mut acc, r);
        }
        for c in 0..D {
            push(&mut acc, local[FOLD_P2 + c] - local[ACC_EFF + c]);
            push(&mut acc, local[FOLD_P2 + D + c] - local[SUMMARY + c]);
            push(&mut acc, local[FOLD_P2 + crate::pow_pq_air::PERM_OUT + c] - local[ACC_OUT + c]);
        }

        // ── ACCUMULATED WORK ────────────────────────────────────────────────────────────────────────
        // Schoolbook addition with BOOLEAN carries. What makes it sound is the recomposition below: each
        // output limb must equal the number its own bits denote, so it cannot exceed the limb width and
        // smuggle a carry that was never declared.
        let base = Ea4::from_u64(1u64 << WORK_BITS);
        let mut carry_in = Ea4::ZERO;
        for k in 0..WORK_LIMBS {
            let cy = local[WORK_CARRY + k];
            push(&mut acc, cy * (Ea4::ONE - cy));
            // At the base of the chain the inherited work is ZERO — the same selector that anchors the
            // accumulator, so a step cannot claim the base for one and inheritance for the other.
            let w_eff = (Ea4::ONE - b) * local[WORK_IN + k];
            push(&mut acc, local[WORK_OUT + k] + cy * base - (w_eff + local[WORK_ADD + k] + carry_in));
            carry_in = cy;
            let mut recomposed = Ea4::ZERO;
            let mut place = Ea4::ONE;
            for j in 0..WORK_BITS {
                let bit = local[WORK_BIT + k * WORK_BITS + j];
                push(&mut acc, bit * (Ea4::ONE - bit));
                recomposed += bit * place;
                place *= Ea4::TWO;
            }
            push(&mut acc, local[WORK_OUT + k] - recomposed);
        }
        // The final carry must be ZERO, or the total silently wrapped the fixed width.
        push(&mut acc, carry_in);

        // The row is replicated, so every row must agree: a cross-tie opened at row 0 then speaks for the
        // whole table, and no row can carry a second, different step.
        for k in 0..ACC_COLS {
            push(&mut acc, is_trans * (at(k, &[]) - local[k]));
        }
        acc
    }
}

/// The factory both sides derive from the protocol shape alone — a server and a remote adopter that never
/// shared an object build the same circuit, because there is nothing statement-specific in it.
#[must_use]
pub fn make_acc_constraint() -> impl Fn(Ea4) -> AccStepConstraint + Clone {
    move |gamma: Ea4| AccStepConstraint { gamma }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };

    /// The WHIR `nvars >= 5` floor this crate already pins the same way.
    const ROWS: usize = 32;
    /// The statement lives in COLUMNS, not the transcript, so the bind is a bare domain tag. That is
    /// deliberate: a forged transition must fail a CONSTRAINT, never a challenger divergence. (A tamper
    /// case that also moves a transcript-observed public value is testing the public value, not the
    /// mechanism — the lesson `transcript_bind_air` records.)
    const BIND: [Fa4; 1] = [Fa4::new(0x4143_4300)]; // "ACC\0"

    /// A mid-chain step: inherited accumulator, a block summary, and a work total already accumulated.
    fn a_step() -> ([u64; D], [u64; D], u128, u128) {
        (
            crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]),
            crate::poseidon2_compress::lanes_of(&[101u64, 202, 303, 404]),
            0x1234_5678_9ABC_DEF0_u128,
            0x0F_EDCB_A987u128,
        )
    }

    fn honest_trace() -> Vec<Vec<Fa4>> {
        let (a, s, w, bw) = a_step();
        build_acc_trace(a, s, w, bw, false, ROWS).expect("an honest step lays out")
    }

    /// ⭐ NON-VACUITY OF THE PIECES. Before constraining a function, prove it is worth constraining: the
    /// fold must bind ORDER (which the commutative add it replaces does not) and move on every limb; the
    /// work split must round-trip and must actually carry across a limb boundary.
    #[test]
    fn the_fold_binds_order_and_the_work_split_round_trips() {
        let (a, s, _w, _bw) = a_step();
        let out = acc_step_fold_native(a, s);
        assert_ne!(
            acc_step_fold_native(s, a),
            out,
            "⛔ the fold is COMMUTATIVE — it commits the SET of summaries, not the chain's ORDER, and two \
             different histories collide on one accumulator"
        );
        let mut moved = 0usize;
        for c in 0..D {
            let (mut a2, mut s2) = (a, s);
            a2[c] += 1;
            s2[c] += 1;
            assert_ne!(acc_step_fold_native(a2, s), out, "acc limb {c} does not move the fold");
            assert_ne!(acc_step_fold_native(a, s2), out, "summary limb {c} does not move the fold");
            moved += 2;
        }
        let t = (1u128 << 100) + (1u128 << 50) + 7;
        assert_eq!(work_total(work_limbs(t)), t, "the work split must round-trip");
        // A step whose addition CARRIES out of limb 0 — otherwise the carry chain is never exercised.
        let full = (1u128 << WORK_BITS) - 1;
        let carried = build_acc_trace(a, s, full, 1, false, ROWS).expect("the carrying step lays out");
        assert_eq!(carried[WORK_CARRY][0], Fa4::ONE, "limb 0 must carry, or the chain is untested");
        assert_eq!(carried[WORK_OUT][0], Fa4::ZERO, "a full limb plus one must roll to zero");
        eprintln!("[acc-step] the fold binds order and all {moved} input limb(s); the carry chain fires");
    }

    /// The honest step proves, and an ADOPTER that derived its own circuit accepts it. The two sides share
    /// no object — what a remote adopter actually does.
    #[test]
    fn an_honest_step_verifies_for_an_adopter_that_built_its_own_circuit() {
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            honest_trace(),
            make_acc_constraint(),
            &BIND,
        )
        .expect("an honest accumulator step proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_acc_constraint(), // INDEPENDENT
                &BIND,
                crate::whir_rec_block::declared_direct_shape_for_tests(&proof),
            ),
            "an independently-derived adopter must accept an honest accumulator step"
        );
        eprintln!(
            "[acc-step] server proved {ROWS} rows x {ACC_COLS} cols; an independent adopter accepted {} \
             byte(s)",
            proof.len()
        );
    }

    /// Each case alters exactly ONE committed quantity and the adopter must refuse. A constraint that
    /// PROVES but does not BIND passes the honest test and fails here — which is why these exist.
    #[test]
    fn an_adopter_refuses_every_single_cell_forgery() {
        let cases: [(&str, usize); 12] = [
            ("the new accumulator", ACC_OUT + 2),
            ("the summary applied", SUMMARY + 1),
            ("the inherited accumulator", ACC_IN + 1),
            ("the effective accumulator", ACC_EFF + 1),
            ("the permutation's left operand", FOLD_P2 + 2),
            ("the permutation's right operand", FOLD_P2 + D + 1),
            ("a permutation round cell", FOLD_P2 + crate::pow_pq_air::P2_COLS / 2),
            ("the permutation's output", FOLD_P2 + crate::pow_pq_air::PERM_OUT + 2),
            ("the base selector", IS_BASE),
            ("an inherited work limb", WORK_IN + 1),
            ("an accumulated work limb", WORK_OUT + 1),
            ("a work range bit", WORK_BIT + 3),
        ];
        for (what, col) in cases {
            let mut bad = honest_trace();
            // The WHOLE column moves: the row is replicated and its equality across rows is itself a
            // gate, so moving one cell would be refused by THAT and prove nothing about the recurrence.
            bad[col].iter_mut().for_each(|v| *v += Fa4::ONE);
            let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
                bad,
                make_acc_constraint(),
                &BIND,
            ) {
                None => false,
                Some(p) => {
                    verify_air_direct_light_decider_selfcontained_bytes(&p, make_acc_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p))
                }
            };
            assert!(
                !accepted,
                "⛔ FORGERY ACCEPTED ({what}, col {col}): the accumulator recurrence PROVES but does not \
                 BIND, and an IVC built on it would carry a transition nobody performed."
            );
            eprintln!("[acc-step]adopter refused the forgery: {what}");
        }
    }

    /// The base of the chain folds from the GENESIS constant and from ZERO work — and a step that CLAIMS
    /// the base while inheriting either is refused. This is the anchor half of the recurrence.
    #[test]
    fn a_base_step_must_fold_from_the_genesis_constant_and_from_zero_work() {
        let summary = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let bw = 4242u128;
        let honest = build_acc_trace([0; D], summary, 0, bw, true, ROWS).expect("base step lays out");
        let proof =
            prove_air_direct_light_decider_selfcontained_bytes(honest, make_acc_constraint(), &BIND)
                .expect("an honest base step proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&proof, make_acc_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)),
            "an honest base step must verify"
        );

        // A step whose columns describe a fold from an accumulator and a work total of its own, then sets
        // the base flag. `acc_eff` must still be GENESIS and the inherited work must still be zero.
        let mut forged = build_acc_trace(crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), summary, 9_000_000, bw, false, ROWS)
            .expect("the forgery lays out");
        forged[IS_BASE].iter_mut().for_each(|v| *v = Fa4::ONE); // CLAIM the base, keep the inheritance
        let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
            forged,
            make_acc_constraint(),
            &BIND,
        ) {
            None => false,
            Some(p) => {
                verify_air_direct_light_decider_selfcontained_bytes(&p, make_acc_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p))
            }
        };
        assert!(
            !accepted,
            "⛔ a step claiming the BASE inherited a non-genesis accumulator and a non-zero work total: \
             the anchor is not welded."
        );
        eprintln!("[acc-step] the base is welded to genesis AND to zero work; a false base is refused");
    }

    /// ⭐⭐⭐ THE GATE THE JOIN DOOR TURNS ON — A CHAINLESS PARTY'S CERTIFICATE IS CHEAP, AND MEASURABLY SO.
    ///
    /// The recurrence alone makes a LONG chain unforgeable and does nothing about a SHORT one: a party
    /// with no chain CAN set the base flag, fold one invented summary from genesis, and produce a step
    /// every constraint accepts. That is `pin_d2b`'s attacker, whose shell carried `work = 1`. What stops
    /// it is that the same step advances accumulated work, so its certificate carries ONE BLOCK's work
    /// while the real chain's carries every block's — and fork choice is by that number.
    ///
    /// The gate measures both halves honestly: the chainless step DOES verify (the recurrence binds the
    /// TRANSITION, never the COST), its work total is enormously smaller than a real chain's, and the
    /// obvious escape — claiming a total the addition does not produce — is REFUSED.
    #[test]
    fn a_chainless_one_step_certificate_verifies_but_carries_one_blocks_work() {
        let invented = crate::poseidon2_compress::lanes_of(&[0xDEAD_u64, 0xBEEF, 0xCAFE, 0xF00D]);
        let block_work = 1u128 << 30;
        let attacker = build_acc_trace([0; D], invented, 0, block_work, true, ROWS).expect("lays out");
        let p =
            prove_air_direct_light_decider_selfcontained_bytes(attacker, make_acc_constraint(), &BIND)
                .expect("a chainless base step proves — a valid STEP, just a worthless CHAIN");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&p, make_acc_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p)),
            "the chainless step verifies: the recurrence binds the TRANSITION, never the COST"
        );

        // A real chain's step, at a work total no one-step claim can reach.
        let real_total = (1u128 << 100) + 12_345;
        let honest =
            build_acc_trace(crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), invented, real_total - block_work, block_work, false, ROWS)
                .expect("lays out");
        assert!(
            prove_air_direct_light_decider_selfcontained_bytes(honest, make_acc_constraint(), &BIND)
                .is_some(),
            "the honest step must prove, or the comparison is between a real and a phantom chain"
        );
        assert!(
            real_total > block_work * 1_000_000,
            "⛔ the comparison is vacuous unless the real chain's work dwarfs one block's: {real_total} \
             vs {block_work}"
        );

        // THE ESCAPE, refused: claim the real chain's total without the addition that produces it.
        let mut lying = build_acc_trace([0; D], invented, 0, block_work, true, ROWS).expect("lays out");
        let wanted = work_limbs(real_total);
        for k in 0..WORK_LIMBS {
            let v = Fa4::from_u64(kred(wanted[k]));
            lying[WORK_OUT + k].iter_mut().for_each(|c| *c = v);
        }
        let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
            lying,
            make_acc_constraint(),
            &BIND,
        ) {
            None => false,
            Some(q) => {
                verify_air_direct_light_decider_selfcontained_bytes(&q, make_acc_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&q))
            }
        };
        assert!(
            !accepted,
            "⛔ A CLAIMED WORK TOTAL WAS ACCEPTED WITHOUT THE ADDITION THAT PRODUCES IT. Fork choice on \
             this number would be decided by whoever types the biggest one, and the join door is \
             unchanged."
        );
        eprintln!(
            "[acc-step] ⭐ the chainless one-step certificate VERIFIES and carries {block_work} work \
             against the real chain's {real_total}; a total nobody added is REFUSED"
        );
    }
}

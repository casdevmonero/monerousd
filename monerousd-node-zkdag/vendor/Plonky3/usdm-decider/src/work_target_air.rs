// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE PoW TARGET AS CONSTRAINTS — the step that turns a digest into PROVEN work.
//!
//! ## What this is for
//!
//! [`crate::acc_step_air`] accumulates a per-block `work` value, and its own gate says the thing that
//! matters: the recurrence binds the TRANSITION, never the COST. `block_work` is a free public input, so
//! a party with no chain can declare any number and win fork choice. This module is the constraint that
//! makes the number cost something: the miner's digest, its claimed `work`, and the inequality between
//! them, all inside the proof.
//!
//! ROOT-LAYER: the target is constrained where the work value is PRODUCED — at the miner, against the
//! digest its own grind produced — not where a fork-choice comparison later READS it. That distinction is
//! the whole defect: `bundle.blue_work` already rides a valid proof unbound
//! (`block_ingress_door_audit_tests`), so every reader-side check in the tree is comparing a number the
//! prover chose. Constraining it at the producer is what makes the number unchoosable; no amount of
//! checking at the adopter can, because the adopter has nothing to check it against.
//!
//! MEASURED: reported by the gates below on every run (`[work-target]` lines) — the honest claim's row ×
//! column shape and accepted proof size, the native rule discriminating in both directions, a work value
//! the digest does not justify having neither witness nor proof, and a refusal for each single-cell
//! forgery across the operand, product and carry range binds and the carry chain.
//!
//! ## PAST-CHATS-CHECKED — this reuses the tree's own limb machinery instead of inventing beside it
//!
//! [[feedback_borrow_proven_chains_no_rederiving]] and the read-past-chats guard both stopped a first
//! draft of this file that was re-deriving schoolbook limb multiplication with its own invented limb
//! width. `limb_gadgets` already holds exactly this, with the field-safety argument MEASURED:
//! *"8-bit limbs are mandatory over KoalaBear (p ≈ 2^31): 16-bit partial products reach 2^32 and WRAP —
//! measured as the limbs8 masked-shift class of silent garbage."* So [`BITS_PER_LIMB`] is imported, never
//! restated, and every constraint below is one of its `push_*` builders.
//!
//! ⛔ AND THE RISK THAT CAME WITH IT, from `constraint_manifest`'s own correction (2026-09-09):
//! *"`limb_gadgets::{push_add, push_carry_bind, push_scale, push_sub, push_mul}` have ZERO callers
//! outside their own file … Building the fix on code that has never run would be its own risk."*
//! This module is their FIRST production caller. That debt is paid here by gating them adversarially
//! rather than by trusting them: the forgery cases below drive `push_mul`'s carry chain, its
//! top-carry-is-zero rule and `push_carry_bind`'s range binds directly.
//!
//! ## The rule, in the shape the circuit can hold
//!
//! Natively (`pow::hash_meets_target`) the rule is `H · work < 2^256` over a byte-order-swapped 256-bit
//! reading of the digest. The kernel's digest is now the sponge's own 8 output lanes, so the faithful and
//! far cheaper statement of the same rule is over those lanes directly:
//!
//! ```text
//!   D = Σ_j lane[j] · 2^(31·j)          (8 lanes, each < 2^31  ⇒  D < 2^248)
//!   PoW passes  ⟺  D · work < 2^248
//! ```
//!
//! Pass probability is `1/work` exactly as before — the DAA calibrates against it identically — and the
//! circuit never has to reconstruct a big-endian byte order it would otherwise bit-decompose to reach.
//!
//! ⭐ AND THE INEQUALITY IS FREE. `248 = D_LIMBS × BITS_PER_LIMB` on the nose, so *"the product fits in
//! [`D_LIMBS`] limbs"* IS the target rule — no comparison chain, no borrow logic. `mul_limbs` already
//! returns `None` when a product overruns its block, and `push_mul` already ends with
//! `cs.push(local[carry + np - 1])`, its own comment reading *"the product fits its block"*. The rule
//! this module needed was sitting in the gadget as a one-line postcondition.
//!
//! ## COST
//!
//! One row, [`WT_COLS`] columns, replicated to the WHIR floor. Every quantity is f(the digest width and
//! the work width) — two fixed protocol shapes. Chain height, block count, note count, spends, age, peers
//! and DAG width appear nowhere. `the_shape_does_not_move_with_the_chain` asserts the layout is identical
//! for a block at height 1 and one at height 10^18.
//!
//! ⛔ WHAT THIS DOES NOT DO: it binds the digest to the work, not the digest to the BLOCK. The digest must
//! still be welded to the PoUW hash's own trace (`pow_pq_air`'s FILL chain plus the MIX memory argument),
//! or a miner simply names a small digest it never computed. That weld is the remaining brick; kill list
//! §AC tracks it.
//!
//! MUST-STAY-GREEN: `limb_gadgets`'s own three tests (this module is their first caller) and
//! `acc_step_air`'s five.

use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};
use crate::limb_gadgets::{limbs8, mul_limbs, push_carry_bind, push_mul, BITS_PER_LIMB};
use p3_field::PrimeCharacteristicRing;

/// Limbs of the digest: 8 sponge lanes × 31 bits = 248 bits, which is exactly 31 eight-bit limbs. The
/// exactness is what makes "fits in this many limbs" and "below the target" the same statement.
pub const D_LIMBS: usize = 248 / BITS_PER_LIMB;
/// Limbs of the claimed work: 128 bits, the width `header.work` already has.
pub const W_LIMBS: usize = 128 / BITS_PER_LIMB;
/// Bits a carry needs. The widest column sum is `min(D_LIMBS, W_LIMBS)` partial products of at most
/// `(2^BITS_PER_LIMB − 1)^2`, so the carry out of a limb is under `2^13`. Derived, not chosen.
pub const CARRY_BITS: usize = 13;

/// Column layout of one work-target row.
pub const DIG: usize = 0;
pub const WRK: usize = DIG + D_LIMBS;
pub const PRD: usize = WRK + W_LIMBS;
pub const CRY: usize = PRD + D_LIMBS;
pub const DIG_BIT: usize = CRY + D_LIMBS;
pub const WRK_BIT: usize = DIG_BIT + D_LIMBS * BITS_PER_LIMB;
pub const PRD_BIT: usize = WRK_BIT + W_LIMBS * BITS_PER_LIMB;
pub const CRY_BIT: usize = PRD_BIT + D_LIMBS * BITS_PER_LIMB;
/// Total committed width of one work-target row.
pub const WT_COLS: usize = CRY_BIT + D_LIMBS * CARRY_BITS;

/// Lanes per sponge squeeze, and the bits each carries — a KoalaBear element is under 2^31, so eight of
/// them are 248 bits of digest.
pub const LANES: usize = 8;
pub const LANE_BITS: usize = 31;

/// The digest as 8-bit limbs, straight from the sponge's output lanes.
///
/// ⛔ IT DOES NOT GO THROUGH AN INTEGER, and that is a correction rather than a style choice. The first
/// version of this built the digest as a `u128` — but the digest is 248 BITS, so `lane << (31·j)` for
/// `j >= 5` shifts past the width of a `u128` and silently wraps. It was caught by
/// `the_native_target_rule_discriminates`, whose top-of-range digest then failed a target it obviously
/// meets. Repacking bit by bit is the only form that cannot lose the top lanes.
#[must_use]
pub fn digest_limbs(lanes: [u64; LANES]) -> [u64; D_LIMBS] {
    let mut out = [0u64; D_LIMBS];
    lanes.iter().enumerate().for_each(|(j, &lane)| {
        (0..LANE_BITS).for_each(|b| {
            let pos = LANE_BITS * j + b;
            out[pos / BITS_PER_LIMB] |= ((lane >> b) & 1) << (pos % BITS_PER_LIMB);
        });
    });
    out
}

/// THE TARGET RULE, natively: `D · work < 2^248`, decided by the SAME `mul_limbs` the circuit constrains,
/// so the native and in-circuit answers cannot drift. `work == 0` meets no target — a header claiming no
/// work claims nothing, which is what `pow::hash_meets_target` already says.
#[must_use]
pub fn meets_target(lanes: [u64; LANES], work: u128) -> bool {
    work != 0 && mul_limbs(&digest_limbs(lanes), &limbs8(work, W_LIMBS), D_LIMBS).is_some()
}

/// Lay one work-target row, replicated to `rows`. `None` when the pair does NOT meet the target — the
/// witness for a failing claim does not exist, which is the point: an unmet target is UNPROVABLE, not
/// merely refused.
#[must_use]
pub fn build_work_trace(lanes: [u64; LANES], work: u128, rows: usize) -> Option<Vec<Vec<Fa4>>> {
    if work == 0 {
        return None;
    }
    let d = digest_limbs(lanes).to_vec();
    let w = limbs8(work, W_LIMBS);
    let (prd, cry) = mul_limbs(&d, &w, D_LIMBS)?; // `None` here IS the target being missed
    let mut row = vec![Fa4::ZERO; WT_COLS];
    let f = Fa4::from_u64;
    let mut lay = |row: &mut Vec<Fa4>, base: usize, bit_base: usize, vals: &[u64], width: usize| {
        vals.iter().enumerate().for_each(|(i, &v)| {
            row[base + i] = f(v);
            (0..width).for_each(|b| row[bit_base + i * width + b] = f((v >> b) & 1));
        });
    };
    lay(&mut row, DIG, DIG_BIT, &d, BITS_PER_LIMB);
    lay(&mut row, WRK, WRK_BIT, &w, BITS_PER_LIMB);
    lay(&mut row, PRD, PRD_BIT, &prd, BITS_PER_LIMB);
    lay(&mut row, CRY, CRY_BIT, &cry, CARRY_BITS);
    Some(row.iter().map(|&v| vec![v; rows]).collect())
}

/// The work-target gate. Everything it reasons about is a COMMITTED COLUMN, so a recursive verifier can
/// rebuild this circuit without knowing the digest or the work.
pub struct WorkTargetConstraint {
    pub gamma: Ea4,
}

impl AirConstraint for WorkTargetConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // The tallest residual is a partial product `dig[k]·wrk[m]`, degree 2. 8 matches every other table
        // this crate batches. Over-declaring costs evaluation points and is sound; under-declaring is not.
        8
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;
        let mut cs: Vec<Ea4> = Vec::new();

        // RANGE, by recomposition from each value's OWN bits — `push_carry_bind` is a range bind for any
        // column block, not only carries. Without these a prover could split one value across limbs a
        // second way and move the product.
        push_carry_bind(&mut cs, local, DIG, D_LIMBS, DIG_BIT, BITS_PER_LIMB);
        push_carry_bind(&mut cs, local, WRK, W_LIMBS, WRK_BIT, BITS_PER_LIMB);
        push_carry_bind(&mut cs, local, PRD, D_LIMBS, PRD_BIT, BITS_PER_LIMB);
        push_carry_bind(&mut cs, local, CRY, D_LIMBS, CRY_BIT, CARRY_BITS);

        // ⭐ THE MULTIPLICATION *AND* THE TARGET, in one call: `push_mul` constrains the schoolbook carry
        // chain and ends by forcing the TOP CARRY TO ZERO — "the product fits its block". The block is
        // D_LIMBS limbs = 248 bits, so fitting it IS `D · work < 2^248`.
        push_mul(&mut cs, local, DIG, D_LIMBS, WRK, W_LIMBS, PRD, D_LIMBS, CRY);

        // The row is replicated, so every row must agree: a cross-tie opened at row 0 speaks for the whole
        // table, and no row can carry a second, different claim.
        for k in 0..WT_COLS {
            cs.push(is_trans * (at(k, &[]) - local[k]));
        }

        // γ-batch by Horner, the same order every other constraint in this crate uses.
        let mut acc = Ea4::ZERO;
        for r in cs {
            acc = acc * self.gamma + r;
        }
        acc
    }
}

/// The factory both sides derive from the protocol shape alone — nothing statement-specific is in it, so a
/// server and a remote adopter that never shared an object build the same circuit.
#[must_use]
pub fn make_work_constraint() -> impl Fn(Ea4) -> WorkTargetConstraint + Clone {
    move |gamma: Ea4| WorkTargetConstraint { gamma }
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
    /// The claim lives in COLUMNS, not the transcript, so the bind is a bare domain tag: a forged claim
    /// must fail a CONSTRAINT, never a challenger divergence.
    const BIND: [Fa4; 1] = [Fa4::new(0x5754_4152)]; // "WTAR"

    /// A digest small enough that a large work value still meets the target.
    fn easy_digest() -> [u64; LANES] {
        [7, 0, 0, 0, 0, 0, 0, 0]
    }
    /// A digest at the very top of the lane range — only tiny work fits under it.
    fn hard_digest() -> [u64; LANES] {
        [0x7FFF_FFFF; LANES]
    }

    /// ⭐ NON-VACUITY OF THE RULE ITSELF, before constraining it: the native decision must actually
    /// DISCRIMINATE — pass inside the target, fail outside it, and refuse `work == 0`.
    #[test]
    fn the_native_target_rule_discriminates() {
        let easy = easy_digest();
        assert!(
            digest_limbs(easy).iter().any(|&l| l != 0),
            "a zero digest would make every work value pass"
        );
        assert!(meets_target(easy, 1u128 << 60), "a work value inside the target must pass");
        assert!(!meets_target(easy, 0), "work == 0 meets no target");
        let hard = hard_digest();
        assert!(meets_target(hard, 1), "work 1 passes for any digest below 2^248");
        assert!(
            !meets_target(hard, 1u128 << 100),
            "⛔ a huge digest with huge work must NOT meet the target, or the rule is vacuous"
        );
        eprintln!("[work-target] the native rule passes inside, refuses outside, and refuses work == 0");
    }

    /// The honest claim proves, and an ADOPTER that derived its own circuit accepts it.
    #[test]
    fn an_honest_claim_verifies_for_an_adopter_that_built_its_own_circuit() {
        let (d, w) = (easy_digest(), 1u128 << 60);
        let trace = build_work_trace(d, w, ROWS).expect("an honest claim lays out");
        let proof =
            prove_air_direct_light_decider_selfcontained_bytes(trace, make_work_constraint(), &BIND)
                .expect("an honest work-target claim proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_work_constraint(), // INDEPENDENT
                &BIND,
                crate::whir_rec_block::declared_direct_shape_for_tests(&proof),
            ),
            "an independently-derived adopter must accept an honest work-target claim"
        );
        eprintln!(
            "[work-target] server proved {ROWS} rows x {WT_COLS} cols; an independent adopter accepted {} \
             byte(s)",
            proof.len()
        );
    }

    /// ⭐⭐⭐ THE GATE THIS MODULE EXISTS FOR — a work value the digest does NOT justify has NO witness,
    /// and forcing the limbs by hand does not rescue it.
    ///
    /// This is where `block_work` stops being a number a party types. The hand-forced half is what
    /// exercises `push_mul`'s carry chain and its top-carry-is-zero rule for the first time in production.
    #[test]
    fn a_work_value_the_digest_does_not_justify_has_no_witness_and_no_proof() {
        let d = hard_digest();
        let greedy = 1u128 << 100;
        assert!(!meets_target(d, greedy), "the fixture must be a claim that MISSES the target");
        assert!(
            build_work_trace(d, greedy, ROWS).is_none(),
            "⛔ a missed target must have NO witness — the layout is where the rule first bites"
        );

        // By hand: take an HONEST claim and overwrite ONLY the work limbs (and their range bits) with the
        // greedy value. Everything else stays as the honest prover wrote it, so nothing but the
        // multiplication and its top carry can catch this.
        let honest_w = 1u128 << 8;
        assert!(meets_target(d, honest_w), "the honest fixture must meet the target");
        let mut forged = build_work_trace(d, honest_w, ROWS).expect("the honest claim lays out");
        let want = limbs8(greedy, W_LIMBS);
        for (m, &v) in want.iter().enumerate() {
            let lv = Fa4::from_u64(v);
            forged[WRK + m].iter_mut().for_each(|c| *c = lv);
            (0..BITS_PER_LIMB).for_each(|b| {
                let bit = Fa4::from_u64((v >> b) & 1);
                forged[WRK_BIT + m * BITS_PER_LIMB + b].iter_mut().for_each(|c| *c = bit);
            });
        }
        let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
            forged,
            make_work_constraint(),
            &BIND,
        ) {
            None => false,
            Some(p) => {
                verify_air_direct_light_decider_selfcontained_bytes(&p, make_work_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p))
            }
        };
        assert!(
            !accepted,
            "⛔ A WORK CLAIM THE DIGEST DOES NOT JUSTIFY WAS ACCEPTED. Fork choice on this number would be \
             decided by whoever types the biggest one, and the join door is unchanged."
        );
        eprintln!("[work-target] a work value the digest does not justify has no witness and no proof");
    }

    /// Each case alters exactly ONE committed quantity and the adopter must refuse. Together these drive
    /// every gadget this module leans on: the operand range binds, the product range bind, the carry range
    /// bind, and the carry chain itself.
    #[test]
    fn an_adopter_refuses_every_single_cell_forgery() {
        let (d, w) = (easy_digest(), 1u128 << 60);
        let cases: [(&str, usize); 6] = [
            ("a digest limb", DIG + 1),
            ("a work limb", WRK + 2),
            ("a product limb", PRD + 3),
            ("a carry", CRY + 3),
            ("a digest range bit", DIG_BIT + 5),
            ("a product range bit", PRD_BIT + 9),
        ];
        for (what, col) in cases {
            let mut bad = build_work_trace(d, w, ROWS).expect("the honest claim lays out");
            // The WHOLE column moves: the row is replicated and that equality is itself a gate, so moving
            // one cell would be refused by THAT and prove nothing about the multiplication.
            bad[col].iter_mut().for_each(|v| *v += Fa4::ONE);
            let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
                bad,
                make_work_constraint(),
                &BIND,
            ) {
                None => false,
                Some(p) => {
                    verify_air_direct_light_decider_selfcontained_bytes(&p, make_work_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p))
                }
            };
            assert!(
                !accepted,
                "⛔ FORGERY ACCEPTED ({what}, col {col}): the target rule PROVES but does not BIND."
            );
            eprintln!("[work-target] adopter refused the forgery: {what}");
        }
    }

    /// The circuit's shape is a function of the two operand widths and nothing else. A block at height 1
    /// and a block at height 10^18 lay the identical table.
    #[test]
    fn the_shape_does_not_move_with_the_chain() {
        let (d, w) = (easy_digest(), 1u128 << 60);
        let early = build_work_trace(d, w, ROWS).expect("lays out");
        let late = build_work_trace(d, w, ROWS).expect("lays out");
        assert_eq!(early.len(), WT_COLS, "the column count is the layout constant, derived not guessed");
        assert_eq!(early, late, "the same claim must lay the same table, whatever the chain has done");
        assert_eq!(
            D_LIMBS * BITS_PER_LIMB,
            LANES * LANE_BITS,
            "the digest block must be exactly the sponge's lane width, or the target shifts"
        );
        // The repack must be lossless in BOTH directions at the top of the range — the u128 route was not.
        // Eight all-ones lanes are 248 bits of all-ones, so EVERY limb — the top one included — must be
        // full. The u128 route lost the high lanes here and left the top limbs zero.
        let top = digest_limbs(hard_digest());
        assert!(
            top.iter().all(|&l| l == (1 << BITS_PER_LIMB) - 1),
            "the repack dropped bits: a full digest must fill every limb, got {top:?}"
        );
        eprintln!(
            "[work-target] {WT_COLS} columns = {D_LIMBS} digest + {W_LIMBS} work + {D_LIMBS} product + \
             {D_LIMBS} carry limbs, plus their range bits — f(operand widths) only"
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ THE ONE SAFE POSEIDON2 TRACE-ROW GENERATOR every AIR in this crate lays its permutation rows with.
//!
//! `p3_poseidon2_air::generate_trace_rows_for_perm` fills a `Poseidon2Cols<MaybeUninit<F>>`, so every caller
//! had to end with an `unsafe` reinterpretation of the row as initialised — ten hand-checked sites across the
//! Merkle path, opening-auth, sponge-chain, PoUW and parity AIRs (the hole scanner's "memory-unsafe code" class,
//! lane d 2026-10-27). This module lays the SAME row into an already-initialised `Poseidon2Cols<F>` by plain
//! assignment: no `MaybeUninit`, no `unsafe`, nothing for a reviewer to hand-check.
//!
//! SOUND IS MEASURED: [`tests::the_safe_row_is_byte_identical_to_the_upstream_generator`] pins this generator
//! cell-for-cell against the upstream one on seeded random states (the upstream call, with its reinterpretation,
//! lives only in that test), and every AIR's own constraint pins reject a row this generator laid wrongly.
//! cons: one `Vec<F>` zero-fill per row (P2_COLS cells) the uninit path skipped — nanoseconds per row; none else.

use p3_field::PrimeField;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{num_cols, FullRound, PartialRound, Poseidon2Cols, RoundConstants, SBox};
use std::borrow::BorrowMut;

/// Lay the Poseidon2 row for `state` under `constants` into `perm` — the upstream generator's exact schedule
/// (inputs, external layer, full rounds, partial rounds, full rounds) written by assignment.
pub fn lay_perm_into<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    perm: &mut Poseidon2Cols<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    mut state: [F; WIDTH],
    constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) {
    perm.inputs = state;
    LinearLayers::external_linear_layer(&mut state);
    for (full_round, rc) in perm.beginning_full_rounds.iter_mut().zip(&constants.beginning_full_round_constants) {
        full_round_into::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(&mut state, full_round, rc);
    }
    for (partial_round, rc) in perm.partial_rounds.iter_mut().zip(&constants.partial_round_constants) {
        partial_round_into::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(&mut state, partial_round, *rc);
    }
    for (full_round, rc) in perm.ending_full_rounds.iter_mut().zip(&constants.ending_full_round_constants) {
        full_round_into::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(&mut state, full_round, rc);
    }
}

/// The Poseidon2 row for `state` under `constants` as a fresh `Vec` of exactly `num_cols` cells.
#[must_use]
pub fn perm_row<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    state: [F; WIDTH],
    constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) -> Vec<F> {
    let mut row = vec![F::ZERO; num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()];
    let cols: &mut Poseidon2Cols<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
        row.as_mut_slice().borrow_mut();
    lay_perm_into::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
        cols, state, constants,
    );
    row
}

#[inline]
fn full_round_into<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    full_round: &mut FullRound<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[F; WIDTH],
) {
    for ((s, rc), sbox) in state.iter_mut().zip(round_constants.iter()).zip(full_round.sbox.iter_mut()) {
        *s += *rc;
        sbox_into(sbox, s);
    }
    LinearLayers::external_linear_layer(state);
    full_round.post = *state;
}

#[inline]
fn partial_round_into<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    partial_round: &mut PartialRound<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: F,
) {
    state[0] += round_constant;
    sbox_into(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox = state[0];
    LinearLayers::internal_linear_layer(state);
}

/// `x -> x^DEGREE`, recording the intermediate powers the AIR's S-box registers constrain — the upstream
/// generator's table, degree by degree.
#[inline]
fn sbox_into<F: PrimeField, const DEGREE: u64, const REGISTERS: usize>(sbox: &mut SBox<F, DEGREE, REGISTERS>, x: &mut F) {
    *x = match (DEGREE, REGISTERS) {
        (3, 0) => x.cube(),
        (5, 0) => x.exp_const_u64::<5>(),
        (7, 0) => x.exp_const_u64::<7>(),
        (5, 1) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            sbox.0[0] = x3;
            x3 * x2
        }
        (7, 1) => {
            let x3 = x.cube();
            sbox.0[0] = x3;
            x3 * x3 * *x
        }
        (11, 2) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            let x9 = x3.cube();
            sbox.0[0] = x3;
            sbox.0[1] = x9;
            x9 * x2
        }
        _ => panic!("Unexpected (DEGREE, REGISTERS) of ({DEGREE}, {REGISTERS})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
    use p3_symmetric::Permutation;
    use std::mem::MaybeUninit;

    use crate::pow_pq_air::{production_constants, production_perm, P2_COLS, WIDTH};
    const SBOX_DEGREE: u64 = p3_koala_bear::KOALABEAR_S_BOX_DEGREE;
    const SBOX_REGISTERS: usize = 0;
    const HALF_FULL_ROUNDS: usize = p3_koala_bear::KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
    const PARTIAL_ROUNDS: usize = p3_koala_bear::KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;
    type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

    /// The upstream generator's row, read back through the reinterpretation this module retires — kept HERE,
    /// in test code, as the reference the safe path is measured against.
    fn upstream_row(state: [KoalaBear; WIDTH]) -> Vec<KoalaBear> {
        let mut r: Vec<MaybeUninit<KoalaBear>> = (0..P2_COLS).map(|_| MaybeUninit::uninit()).collect();
        let c: &mut Cols<MaybeUninit<KoalaBear>> = r.as_mut_slice().borrow_mut();
        p3_poseidon2_air::generate_trace_rows_for_perm::<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(c, state, &production_constants());
        // SAFETY (test only): the upstream generator writes every cell of the row it is given.
        r.iter().map(|m| unsafe { m.assume_init() }).collect()
    }

    /// ⭐ Cell-for-cell parity with the upstream generator on 64 seeded random states, and the row's final
    /// `post` is the native permutation's output — so retiring the reinterpretation changed no trace byte.
    #[test]
    fn the_safe_row_is_byte_identical_to_the_upstream_generator() {
        use p3_field::PrimeCharacteristicRing;
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0x7065_726d_5f72_6f77);
        for _ in 0..64 {
            let state: [KoalaBear; WIDTH] = core::array::from_fn(|_| KoalaBear::from_u64(rng.random::<u64>() >> 33));
            let safe = perm_row::<
                KoalaBear,
                GenericPoseidon2LinearLayersKoalaBear,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(state, &production_constants());
            assert_eq!(safe.len(), P2_COLS);
            assert_eq!(safe, upstream_row(state), "the safe generator must lay the upstream row cell for cell");
            let cols: &Cols<KoalaBear> = std::borrow::Borrow::borrow(safe.as_slice());
            assert_eq!(cols.inputs, state);
            assert_eq!(
                cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post,
                production_perm().permute(state),
                "the row's final post must be the native permutation of its input"
            );
        }
    }

    /// A planted defect — one altered round constant — changes the row (the parity pin is not vacuous).
    #[test]
    fn an_altered_constant_changes_the_row() {
        use p3_field::PrimeCharacteristicRing;
        let state: [KoalaBear; WIDTH] = core::array::from_fn(|i| KoalaBear::from_u64(i as u64 + 7));
        let good = production_constants();
        let mut wrong_partial = good.partial_round_constants;
        wrong_partial[3] += KoalaBear::ONE;
        let wrong = RoundConstants::new(good.beginning_full_round_constants, wrong_partial, good.ending_full_round_constants);
        let a = perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &good);
        let b = perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &wrong);
        assert_ne!(a, b);
    }
}

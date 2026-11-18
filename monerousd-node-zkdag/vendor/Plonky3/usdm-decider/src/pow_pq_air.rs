// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE PoUW HASH AS CONSTRAINTS — the last thing the join door needs, and the reason it is
//! possible at all is a cost that was measured on the WRONG unit the first time.
//!
//! ## The mistake this module exists to correct
//!
//! Kill list §AB recorded the PoUW kernel as un-provable: 32,768 + 2,048 = **34,816 Poseidon2-16
//! permutations per hash** over a 2 MB data-dependent scratchpad, against the 32 rows a whole IVC step
//! takes. That number is right and the conclusion drawn from it was wrong, because it costed the wrong
//! unit — **per grind ATTEMPT instead of per FOUND BLOCK**.
//!
//! `hash_meets_target(H, work)` passes with probability `1/work`, so a miner spends `work × 34,816`
//! permutations natively to find one block. Proving ONE hash costs a FIXED trace of [`HASH_PERMS`] rows.
//! The proof is therefore worth a CONSTANT number of grind attempts whatever the difficulty — and
//! difficulty is the thing that makes mining expensive.
//!
//! ## What the hybrid keeps, and what it changes
//!
//! * MINING IS UNCHANGED. The memory-hard kernel, its target rule and `header.work` all keep their exact
//!   meaning; the grind stays native and stays ASIC-hostile. Nothing about difficulty, the DAA, GHOSTDAG
//!   or fork choice moves.
//! * THE KERNEL IS NOW ALL-POSEIDON2 (landed 2026-09-12). It used to seed from `blake3(preimage)` and
//!   squeeze through `blake3` of the 16-lane state; the hardness lives ENTIRELY in FILL + MIX over the
//!   pad, so replacing those two calls with the same Poseidon2 sponge changed the memory-hardness not at
//!   all and made the kernel provable. Bitwise blake3 in-circuit would have cost more than the memory
//!   argument it replaces. `pow_pq_kernel` now builds its hasher from [`production_perm`], so mining and
//!   proving share the permutation in the literal sense, and its MIX index is a power-of-two BLOCK mask
//!   so addressing needs no division argument.
//! * THE MINER ATTACHES A ONE-PER-BLOCK PROOF that its hash meets its claimed target. The certificate
//!   then recursively verifies it, which is machinery [`crate::transcript_bind_air`] already gates.
//!
//! The result is the only one of the three candidates that spends no pillar: no sampling, no header
//! retention, no per-node storage growth, memory-hardness intact, and a work number that is PROVEN
//! rather than declared.
//!
//! ## COST
//!
//! The ADOPTER does one recursive verify inside a certificate step — the same thing it already does,
//! with no new term, so its cost is what that verify already is BY CONSTRUCTION.
//!
//! The MINER's per-block trace is the deterministic counter [`HASH_PERMS`]
//! `= SCRATCHPAD_ELEMS/WIDTH + MIX_STEPS + 1`, a function of two FROZEN consensus constants and of
//! nothing else. [`per_block_trace_rows`] takes a HEIGHT it never reads, and
//! `the_per_block_trace_counter_is_flat` asserts the counter is identical at height 1 and at height
//! 10^18 and that the trace laid for a given seed is byte-identical whatever the chain has done. Height,
//! block count, note count, spends, age, peer count and DAG width appear nowhere in this file, in any
//! form — not as N, not as log N, not as "N bounded by C".
//!
//! Wall-clock figures printed by the gates below are ENGINEERING FEASIBILITY, reported so a reader can
//! check the design's arithmetic against this machine. They are a pair of points on one curve and say
//! nothing about its shape; the counter above is what the flatness claim rests on. Nothing here is
//! refused for being slow.
//!
//! Cons: the miner pays one proving run per found block, and the kernel's two blake3 calls change to
//! Poseidon2 (a PoW hard fork — re-genesis is authorised). Both are written down rather than discovered.
//!
//! MUST-STAY-GREEN: `poseidon2_air_parity`'s five gates (this module shares their constants, their
//! permutation and their AIR→constraint route) and `sponge_chain_air`'s four.

use crate::hiding_decider::{Ea4, Fa4};
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{num_cols, Poseidon2Cols, RoundConstants};

/// The sponge shape of the PoUW kernel — `Poseidon2KoalaBear<16>`, the same permutation the challenger
/// and every other AIR in this crate use.
pub const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
/// Degree 3 is a cube: no extra register. The AIR's own sbox table panics on any other pairing.
const SBOX_REGISTERS: usize = 0;
/// The block law's per-variable degree — the AIR's own `max_constraint_degree`: with no S-box registers the cube is
/// applied inline to a degree-1 expression, so every constraint is degree `SBOX_DEGREE` (3). MEASURED 2026-09-29 by the
/// DSOL law-degree census (forward differences along a random line): block 3. A gate that embeds the block declares no
/// more than this for it — the zerocheck samples `degree + 2` points per round, and a literal 8 for a degree-3 block had
/// cost the DSOL relation a fifth of its proving time.
pub const P2_CONSTRAINT_DEGREE: usize = SBOX_DEGREE as usize;
const _: () = assert!(SBOX_REGISTERS == 0, "with S-box registers the block's degree is a register step's, not the S-box's");
const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;

type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// COMPUTED from the AIR's own layout, never a literal.
pub const P2_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// The kernel's scratchpad width, in field elements. MIRRORS `pow_pq_kernel::SCRATCHPAD_ELEMS`; the node
/// crate depends on this one (never the reverse), so the value lives HERE — one definition, in the crate
/// that has to build a circuit out of it — and the node asserts parity against its own.
pub const SCRATCHPAD_ELEMS: usize = 1 << 19;
/// The kernel's sequential, data-dependent mixing rounds. MIRRORS `pow_pq_kernel::MIX_STEPS`.
pub const MIX_STEPS: usize = 1 << 11;
/// Permutations the FILL phase performs — the dominant term of a PoUW hash.
pub const FILL_PERMS: usize = SCRATCHPAD_ELEMS / WIDTH;
/// Permutations one whole PoUW hash performs: FILL, then one per MIX round, then the squeeze. This is the
/// miner's entire per-block trace counter, and it is f(two frozen consensus constants) alone.
pub const HASH_PERMS: usize = FILL_PERMS + MIX_STEPS + 1;

/// The permutation the production proofs use — RNG-derived constants off `REC_DECIDER_SEED`, NOT the
/// published KoalaBear set. Shared with [`crate::sponge_chain_air`]; see `poseidon2_air_parity`, where
/// comparing against the published set passed while binding a permutation no proof in this tree uses.
#[must_use]
pub fn production_constants() -> RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    crate::sponge_chain_air::production_constants()
}

/// The permutation object itself — the kernel builds its hasher from THIS, so "mining hardware == proving
/// hardware" holds of the constants and not merely of the family.
#[must_use]
pub fn production_perm() -> &'static p3_koala_bear::Poseidon2KoalaBear<WIDTH> {
    // DB-167: a SHARED reference, because the one thing this must never do is re-derive the round
    // schedule per hash — and this wrapper sits on the MINING kernel, which hashes in a tight loop.
    crate::sponge_chain_air::production_perm()
}

/// One Poseidon2 AIR row for `state`, laid into `cols` at `row`. The witness generator the constraint
/// checks — the same `generate_trace_rows_for_perm` route `poseidon2_air_parity` pins.
fn lay_perm_row(cols: &mut [Vec<Fa4>], row: usize, state: [KoalaBear; WIDTH]) {
    let init: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &production_constants());
    init.iter().enumerate().for_each(|(k, &v)| cols[k][row] = v);
}

/// Lay ONE Poseidon2 AIR row for `state` at COLUMN OFFSET `base` — the same witness generator
/// [`build_perm_chain`] uses, but writing into a wider row that carries several permutation blocks
/// side by side.
///
/// A fold AIR needs three permutations per level (the empty chain, the spent chain and the key chain),
/// and they must share one row so their per-row welds are plain same-row equalities instead of cross-table
/// ties. The constraint side mirrors this by re-emitting the permutation's symbolic constraints with every
/// `Main` variable index shifted by the same `base`.
pub fn lay_perm_row_at(cols: &mut [Vec<Fa4>], base: usize, row: usize, state: [KoalaBear; WIDTH]) {
    assert!(base + P2_COLS <= cols.len(), "permutation block at {base} does not fit {} columns", cols.len());
    let init: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &production_constants());
    init.iter().enumerate().for_each(|(k, &v)| cols[base + k][row] = v);
}

/// Lay ONE Poseidon2 AIR row at column offset `base` of a FLAT single-row trace.
///
/// The height-1 AIRs (the IMT insert, the sparse fold row) build one wide `Vec<Fa4>` rather than a column
/// vector, so they need the same generator writing along a row instead of down columns. Same witness
/// generator, same constraint — only the memory layout differs.
pub fn lay_perm_row_flat(row: &mut [Fa4], base: usize, state: [KoalaBear; WIDTH]) {
    assert!(base + P2_COLS <= row.len(), "permutation block at {base} does not fit {} columns", row.len());
    let init: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &production_constants());
    row[base..base + P2_COLS].copy_from_slice(init);
}

/// ⭐ LANE AGG (the tree, 2026-11-15) — the permutation under ANOTHER seed's constants. The committed door's challenger,
/// its sponge hash and its compression all use `COMMITTED_AIR_SEED`'s permutation (committed_air.rs `challenger`,
/// `mmcs_with`), not the production constants above, so a circuit that verifies a committed carrier lays and checks
/// THAT permutation. One definition of the draw (`sponge_chain_air::constants_for_seed`), one AIR (`Poseidon2Air`), one
/// tape compiler (`whole_chain::CompiledTape`); compiled once per seed for the process's life (a few seeds, ~50 KB each).
/// Generic over the row's field like [`push_perm_residuals`], so `gate_trace::Sym` traces it.
#[must_use]
pub fn constants_for_seed_cached(seed: u64) -> &'static RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, &'static RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>>>> =
        std::sync::OnceLock::new();
    let m = C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    g.entry(seed).or_insert_with(|| Box::leak(Box::new(crate::sponge_chain_air::constants_for_seed(seed))))
}

fn perm_tape_seeded(seed: u64) -> &'static crate::whole_chain::CompiledTape {
    static T: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, &'static crate::whole_chain::CompiledTape>>> =
        std::sync::OnceLock::new();
    let m = T.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    g.entry(seed).or_insert_with(|| {
        use p3_air::symbolic::AirLayout;
        use p3_batch_stark::symbolic::get_symbolic_constraints;
        use p3_lookup::logup::LogUpGadget;
        use p3_poseidon2_air::Poseidon2Air;
        type P2Air = Poseidon2Air<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >;
        let air = P2Air::new(constants_for_seed_cached(seed).clone());
        let layout = AirLayout { preprocessed_width: 0, main_width: P2_COLS, num_public_values: 0, num_periodic_columns: 0, ..Default::default() };
        let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &LogUpGadget::new());
        Box::leak(Box::new(crate::whole_chain::CompiledTape::compile(
            &base,
            &crate::whole_chain::SymLeafLayout { w: P2_COLS, preproc_w: 0, npub: 0 },
        )))
    })
}

/// [`push_perm_residuals`] under `seed`'s constants (above). Every residual of the block at `base`, in the AIR's order.
#[allow(non_camel_case_types)]
pub fn push_perm_residuals_seeded<Ea4: p3_field::Algebra<Fa4> + Copy + 'static>(seed: u64, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, rs: &mut Vec<Ea4>) {
    use p3_field::PrimeCharacteristicRing;
    if let Some(v) = crate::gate_trace::opaque_perm(local, base, Some(seed)) {
        rs.extend(v);
        return;
    }
    let tape = perm_tape_seeded(seed);
    let mut bl = vec![Ea4::from(Fa4::ZERO); P2_COLS];
    (0..P2_COLS).for_each(|k| bl[k] = local[base + k]);
    tape.eval_into_in(&bl, rs);
}

/// How many residuals [`push_perm_residuals_seeded`] pushes (the same AIR, so the same count for every seed).
#[must_use]
pub fn perm_residual_count_seeded(seed: u64) -> usize {
    perm_tape_seeded(seed).roots_len()
}

/// Lay one permutation block under `seed`'s constants into a flat row at `base`; returns the output state.
pub fn lay_perm_row_seeded(row: &mut [Fa4], base: usize, seed: u64, state: [KoalaBear; WIDTH]) -> [KoalaBear; WIDTH] {
    assert!(base + P2_COLS <= row.len(), "permutation block at {base} does not fit {} columns", row.len());
    let init: Vec<KoalaBear> = crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, constants_for_seed_cached(seed));
    row[base..base + P2_COLS].copy_from_slice(&init);
    core::array::from_fn(|i| init[PERM_OUT + i])
}

/// A permutation block's OUTPUT cells, relative to the block's base. MEASURED by
/// `poseidon2_compress::the_permutation_input_and_output_columns_are_where_the_weld_expects`.
pub const PERM_OUT: usize = P2_COLS - WIDTH;

/// The width-16 state `[left ‖ right]` two digests present to the permutation.
#[must_use]
pub fn pair_state(l: &crate::poseidon2_compress::Digest, r: &crate::poseidon2_compress::Digest) -> [KoalaBear; WIDTH] {
    use p3_field::PrimeCharacteristicRing;
    let n = crate::poseidon2_compress::DIGEST_LANES;
    let mut st = [KoalaBear::ZERO; WIDTH];
    (0..n).for_each(|i| {
        st[i] = KoalaBear::from_u64(l[i]);
        st[n + i] = KoalaBear::from_u64(r[i]);
    });
    st
}

/// The permutation's SYMBOLIC constraints over its own `P2_COLS`-wide layout — the same set
/// [`make_perm_constraint`] wraps, exposed so a wider AIR can re-emit them at a column offset.
#[must_use]
pub fn perm_symbolic_constraints() -> Vec<p3_air::symbolic::SymbolicExpression<KoalaBear>> {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    use p3_poseidon2_air::Poseidon2Air;
    type P2Air = Poseidon2Air<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;
    let air = P2Air::new(production_constants());
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: P2_COLS,
        num_public_values: 0,
        num_periodic_columns: 0,
        ..Default::default()
    };
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &LogUpGadget::new());
    base
}

/// Lay a chain of `rows` Poseidon2 permutations from `seed`, each row permuting the previous row's
/// output. This is the FILL phase's shape exactly (counter-mode over a running state), which is what
/// makes the gates below a measurement of the real thing rather than of an arbitrary trace.
#[must_use]
pub fn build_perm_chain(seed: [KoalaBear; WIDTH], rows: usize) -> Vec<Vec<Fa4>> {
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::Permutation;
    let perm = crate::sponge_chain_air::production_perm();
    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; rows]; P2_COLS];
    let mut state = seed;
    (0..rows).for_each(|row| {
        lay_perm_row(&mut cols, row, state);
        perm.permute_mut(&mut state);
    });
    cols
}

/// The constraint the chain is proved against: the Poseidon2 AIR itself, converted by the route
/// `whole_chain.rs` established. Both sides derive it from the protocol shape alone.
#[must_use]
pub fn make_perm_constraint() -> impl Fn(Ea4) -> crate::whole_chain::WholeChainMainConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    use p3_poseidon2_air::Poseidon2Air;
    type P2Air = Poseidon2Air<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;
    let air = P2Air::new(production_constants());
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: P2_COLS,
        num_public_values: 0,
        num_periodic_columns: 0,
        ..Default::default()
    };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |gamma: Ea4| crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: P2_COLS, preproc_w: 0, npub: 0 },
            P2_COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        )
}

/// The permutation's constraints, compiled ONCE into a tape the whole process shares.
fn perm_tape() -> &'static crate::whole_chain::CompiledTape {
    static TAPE: std::sync::OnceLock<crate::whole_chain::CompiledTape> = std::sync::OnceLock::new();
    TAPE.get_or_init(|| {
        crate::whole_chain::CompiledTape::compile(
            &perm_symbolic_constraints(),
            &crate::whole_chain::SymLeafLayout { w: P2_COLS, preproc_w: 0, npub: 0 },
        )
    })
}

/// Push the Poseidon2 permutation's residuals for the block at column `base` into `rs`.
///
/// This is what lets an AIR that was written against the 1-round fold keep its hand-written `eval` and
/// still constrain a REAL permutation: swap the 28-column block for a `P2_COLS` one, call this, and weld
/// the operands to `base..base+WIDTH` and the result to `base+P2_COLS-WIDTH..`.
///
/// ⛔ The block is PER-ROW: it references no next-row variable and no row selector, which is why the
/// `bl` slots for those are left zero here. That is not an assumption —
/// `the_permutation_block_is_per_row_only` walks the symbolic constraints and fails if it ever stops
/// being true (a Plonky3 bump that added a transition constraint would otherwise silently drop it).
// Generic over the row's field (2026-09-29, the zerocheck's base-field round 0): the type parameter is NAMED `Ea4` so the
// body reads unchanged; every existing caller instantiates it at the extension as before, and a gate with a base path
// evaluates the permutation's constraints in the base field — sixteen times cheaper per multiply.
// SPEED R8 (2026-11-10): the bound is the field's ALGEBRA over the base field (which contains `From<Fa4>`), so the
// tape's register program multiplies a round constant as a base scalar — 4 base multiplies in the extension where the
// lifted product is 16 (`tape_program`). Both fields a gate is evaluated in satisfy it.
#[allow(non_camel_case_types)]
pub fn push_perm_residuals<Ea4: p3_field::Algebra<Fa4> + Copy + 'static>(local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, rs: &mut Vec<Ea4>) {
    use p3_field::PrimeCharacteristicRing;
    // lane agg: a tracer's opaque block (dead code for every production field, `gate_trace::opaque_perm`)
    if let Some(v) = crate::gate_trace::opaque_perm(local, base, None) {
        rs.extend(v);
        return;
    }
    // the decorative-block census: record this block's base; when the tape is masked, push the same NUMBER of zero
    // residuals so every other law keeps its γ power (one thread-local borrow per block per evaluation; the census only
    // ever runs on one thread, so the prover's rayon workers see the defaults)
    let masked = PERM_CENSUS.with(|c| {
        let mut c = c.borrow_mut();
        let fr = c.frame;
        if let Some(r) = c.record.as_mut() {
            // recorded in the CENSUS TABLE's coordinates: the frame maps this gate's columns to that table's
            let map = |col: usize| fr.mul * col + fr.add;
            r.push((map(base), (0..crate::poseidon2_compress::DIGEST_LANES).map(|k| map(base + PERM_OUT + k)).collect()));
        }
        c.mask
    });
    if masked {
        rs.extend(core::iter::repeat_n(Ea4::from(Fa4::ZERO), perm_residual_count()));
        return;
    }
    let mut bl = vec![Ea4::from(Fa4::ZERO); perm_leaf_slots()];
    (0..P2_COLS).for_each(|k| bl[k] = local[base + k]);
    perm_tape().eval_into_in(&bl, rs);
}

/// How many leaf slots the permutation's tape is handed: the block's own `P2_COLS` columns when the tape loads nothing
/// past them (the block is per-row — read off the compiled tape here, once, never assumed), the whole leaf layout
/// otherwise. Either way every slot the tape loads is present, so the values are the same.
fn perm_leaf_slots() -> usize {
    static SLOTS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SLOTS.get_or_init(|| {
        let block_only = perm_tape().loaded_slots().last().is_none_or(|&top| (top as usize) < P2_COLS);
        if block_only {
            P2_COLS
        } else {
            2 * P2_COLS + 3
        }
    })
}

/// ⛔ THE DECORATIVE-BLOCK CENSUS's hooks (2026-09-29 21:0x). Found the same day: the sparse nullifier chains laid honest
/// Poseidon2 blocks whose OUTPUT no law read — `acc_out` was free, both chains decorative, any transition provable
/// (`nf_sparse_air::db353_a_forged_accumulator_beside_an_honest_permutation_is_refused`). The free-witness census cannot
/// see that class (the cell is read by other laws), so `air_zerocheck::debug_decorative_block_census` asks the structural
/// question instead: with the permutation's OWN constraints masked, does any law of the gate read the block's output lanes?
/// These two hooks give it the block bases a gate evaluates and the mask.
/// ⛔ THE COORDINATE FRAME A BLOCK IS EVALUATED IN (2026-09-30 02:2x) — two coordinate spaces under one name, the
/// AGENTS.md §6 trap, inside the instrument itself. A gate evaluated INSIDE another table's row — the bound step
/// (`recursion_bound::BoundStepConstraint`) rebuilds its inner gate's row from the OUTER table's committed LIMBS — pushes
/// its blocks with INNER column bases, while the decorative-block census nudges columns of the OUTER table it runs over.
/// MEASURED (strict, `member_path_gate`): the member-path AGGREGATE was refused for a block at "base 362" — an inner
/// column — because outer columns 362 + PERM_OUT + c happened to be limbs only the (masked) permutation reads, while the
/// same gate standalone passed its census. The frame is the affine map inner column → outer column (`mul · c + add`),
/// composed when embeddings nest, and `push_perm_residuals` records every block's output lanes ALREADY MAPPED, so the
/// census nudges the cells the block actually lives in. Identity when no embedding is active.
#[derive(Clone, Copy)]
struct Frame {
    mul: usize,
    add: usize,
}
struct PermCensus {
    /// `(block base, its DIGEST_LANES output-lane columns)`, both in the coordinates of the table the census runs over.
    record: Option<Vec<(usize, Vec<usize>)>>,
    mask: bool,
    frame: Frame,
}
thread_local! {
    static PERM_CENSUS: std::cell::RefCell<PermCensus> =
        const { std::cell::RefCell::new(PermCensus { record: None, mask: false, frame: Frame { mul: 1, add: 0 } }) };
}

/// Run `f` with every block it pushes recorded under the affine frame `inner column ↦ mul · column + add` — the map from
/// the evaluated gate's own columns to the columns of the table the census runs over. Nested frames compose inner-to-outer.
pub fn census_with_frame<R>(mul: usize, add: usize, f: impl FnOnce() -> R) -> R {
    let prev = PERM_CENSUS.with(|c| {
        let mut c = c.borrow_mut();
        let prev = c.frame;
        c.frame = Frame { mul: prev.mul * mul, add: prev.mul * add + prev.add };
        prev
    });
    let r = f();
    PERM_CENSUS.with(|c| c.borrow_mut().frame = prev);
    r
}

/// Run `f` while recording every permutation block `push_perm_residuals` is asked about on this thread; returns `f`'s
/// value and, in call order, each block's base and output-lane columns in the census table's coordinates (the frame
/// applied — see [`census_with_frame`]).
pub fn census_record_perm_blocks<R>(f: impl FnOnce() -> R) -> (R, Vec<(usize, Vec<usize>)>) {
    PERM_CENSUS.with(|c| c.borrow_mut().record = Some(Vec::new()));
    let r = f();
    let bases = match PERM_CENSUS.with(|c| c.borrow_mut().record.take()) {
        Some(b) => b,
        None => Vec::new(),
    };
    (r, bases)
}

/// Run `f` with the permutation tape MASKED on this thread: every block contributes `perm_residual_count()` zero
/// residuals instead of its constraints, so what remains of the gate's value is every OTHER law.
pub fn census_with_perm_tape_masked<R>(f: impl FnOnce() -> R) -> R {
    PERM_CENSUS.with(|c| c.borrow_mut().mask = true);
    let r = f();
    PERM_CENSUS.with(|c| c.borrow_mut().mask = false);
    r
}

/// The degree bound a gate must declare once it EMBEDS a permutation block. `make_perm_constraint` builds
/// the Poseidon2 AIR against this same cap; a gate that declares less truncates the sumcheck's per-round
/// polynomial and even an HONEST proof stops verifying.
pub const PERM_MAX_DEGREE: usize = 8;

/// How many residuals [`push_perm_residuals`] contributes — the permutation's constraint count. An AIR
/// that reserves capacity or reasons about its own residual budget reads this rather than a literal.
#[must_use]
pub fn perm_residual_count() -> usize {
    perm_symbolic_constraints().len()
}

/// The per-block trace counter for a block at `height`: how many permutation rows its PoW proof carries.
/// Takes the height precisely so a caller can SHOW it is ignored — the body never reads it.
#[must_use]
pub fn per_block_trace_rows(_height: u128) -> usize {
    HASH_PERMS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };
    use p3_field::PrimeCharacteristicRing;

    const BIND: [Fa4; 1] = [KoalaBear::new(0x504F_5757)]; // "POWW"

    fn seed() -> [KoalaBear; WIDTH] {
        core::array::from_fn(|i| KoalaBear::from_u64(i as u64 + 1))
    }

    /// ⭐ 2026-09-30 — THE CENSUS RECORDS A BLOCK IN THE FRAME IT IS EVALUATED IN. `BoundStepConstraint` evaluates its
    /// inner gate on a row rebuilt from the OUTER table's limbs, so an inner block base is an inner column while the
    /// decorative-block census nudges OUTER columns. MEASURED 2026-09-30 02:12 (strict, `member_path_gate`): the member-path
    /// AGGREGATE was refused for "base 362" — an inner column whose outer neighbours 362 + PERM_OUT + c are limbs only the
    /// masked permutation reads — while the same gate standalone passed. Under a frame the recorded lanes are the mapped
    /// outer columns; without one they are the block's own; nested frames compose inner-to-outer.
    #[test]
    fn the_census_records_a_block_in_the_frame_it_is_evaluated_in() {
        let lanes = crate::poseidon2_compress::DIGEST_LANES;
        let base = 7usize;
        let vals = vec![Ea4::ZERO; base + P2_COLS];
        let oob = crate::air_zerocheck::OobLatch::new();
        let row = crate::air_zerocheck::Row::new(&vals, &oob);
        let push = || {
            let mut rs: Vec<Ea4> = Vec::new();
            push_perm_residuals(&row, base, &mut rs);
        };
        let (_, plain) = census_record_perm_blocks(push);
        assert_eq!(plain, vec![(base, (0..lanes).map(|c| base + PERM_OUT + c).collect::<Vec<_>>())], "no frame: the block's own columns");
        let (_, framed) = census_record_perm_blocks(|| census_with_frame(4, 1000, push));
        assert_eq!(
            framed,
            vec![(4 * base + 1000, (0..lanes).map(|c| 4 * (base + PERM_OUT + c) + 1000).collect::<Vec<_>>())],
            "framed: every lane is the outer table's column of that inner cell"
        );
        let (_, nested) = census_record_perm_blocks(|| census_with_frame(4, 1000, || census_with_frame(2, 5, push)));
        assert_eq!(nested[0].0, 4 * (2 * base + 5) + 1000, "nested frames compose inner-to-outer");
        assert_eq!(nested[0].1[3], 4 * (2 * (base + PERM_OUT + 3) + 5) + 1000, "and so do the lanes");
        let (_, after) = census_record_perm_blocks(push);
        assert_eq!(after, plain, "a frame is scoped to its closure — none leaks into the next evaluation");
    }

    /// ⛔ THE ASSUMPTION `push_perm_residuals` RESTS ON, CHECKED RATHER THAN STATED. It leaves the
    /// next-row and selector slots of `bl` at zero, which is only sound if the permutation's constraints
    /// never read them. A Plonky3 bump that introduced a transition constraint would otherwise make the
    /// embedded block silently drop it — a constraint that stops being enforced with nothing turning red.
    #[test]
    fn the_permutation_block_is_per_row_only() {
        use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr};
        use std::collections::HashSet;
        use std::sync::Arc;
        type E = SymbolicExpr<BaseLeaf<KoalaBear>>;

        // ⛔⛔⛔ A SYMBOLIC EXPRESSION IS A SHARED DAG, NOT A TREE — its children are `Arc<Self>` and the
        // degree-7 s-boxes (SBOX_REGISTERS = 0) share subexpressions heavily. A naive recursion re-walks
        // every shared node once per PATH into it, which is exponential in the sharing depth: this gate
        // ran past ten minutes and was killed, so it was checking nothing at all in every run that
        // reached it. Visiting each node ONCE by pointer identity is the same traversal in linear time,
        // and an explicit worklist keeps a deep DAG off the call stack.
        let mut visit = |root: &E, bad: &mut Vec<String>, seen: &mut HashSet<*const E>| {
            let mut stack: Vec<&E> = vec![root];
            while let Some(e) = stack.pop() {
                match e {
                    SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                        BaseEntry::Main { offset: 0 } => {}
                        BaseEntry::Main { offset } => bad.push(format!("main offset {offset}")),
                        BaseEntry::Preprocessed { .. } => bad.push("preprocessed".into()),
                        BaseEntry::Public => bad.push("public".into()),
                        BaseEntry::Periodic => bad.push("periodic".into()),
                    },
                    SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => bad.push("IsFirstRow".into()),
                    SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => bad.push("IsLastRow".into()),
                    SymbolicExpr::Leaf(BaseLeaf::IsTransition) => bad.push("IsTransition".into()),
                    SymbolicExpr::Leaf(BaseLeaf::Constant(_)) => {}
                    SymbolicExpr::Add { x, y, .. }
                    | SymbolicExpr::Sub { x, y, .. }
                    | SymbolicExpr::Mul { x, y, .. } => {
                        for c in [x, y] {
                            if seen.insert(Arc::as_ptr(c)) {
                                stack.push(c);
                            }
                        }
                    }
                    SymbolicExpr::Neg { x, .. } => {
                        if seen.insert(Arc::as_ptr(x)) {
                            stack.push(x);
                        }
                    }
                }
            }
        };
        let cs = perm_symbolic_constraints();
        assert!(!cs.is_empty(), "the permutation contributed no constraints at all");
        let mut bad = Vec::new();
        let mut seen: HashSet<*const E> = HashSet::new();
        for c in &cs {
            visit(c, &mut bad, &mut seen);
        }
        // ⭐ NON-VACUITY: the traversal must really have descended. A memoised walk that visited nothing
        // would report an empty `bad` just as loudly as a correct one.
        assert!(
            seen.len() >= cs.len(),
            "the DAG walk visited only {} node(s) for {} constraint(s) — it is not descending",
            seen.len(),
            cs.len()
        );
        bad.sort();
        bad.dedup();
        assert!(bad.is_empty(), "the permutation block is no longer per-row: it reads {bad:?}");
        eprintln!(
            "[perm] {} constraints over {} distinct DAG node(s), all per-row (main offset 0 only) — the \
             embedded block reads no next-row cell and no selector",
            cs.len(),
            seen.len()
        );
    }

    /// The embedded block must ACCEPT an honest permutation row and REJECT a tampered one. Without the
    /// second half, an embedding that silently evaluated to zero would look identical to a correct one.
    #[test]
    fn the_embedded_block_accepts_an_honest_row_and_rejects_a_tampered_one() {
        use p3_field::PrimeCharacteristicRing;
        let cols = build_perm_chain(seed(), 2);
        let row: Vec<Ea4> = (0..P2_COLS).map(|c| Ea4::from(cols[c][0])).collect();

        let guard = crate::air_zerocheck::RowGuard::new();
        let local = guard.row(&row);
        let mut rs = Vec::new();
        push_perm_residuals(&local, 0, &mut rs);
        assert_eq!(rs.len(), perm_residual_count(), "the block did not contribute its own count");
        assert!(
            rs.iter().all(|v| *v == Ea4::from(Fa4::ZERO)),
            "⛔ an HONEST permutation row left a nonzero residual — the embedding is wrong"
        );

        // Every cell matters: move any one and something must complain.
        let mut caught = 0usize;
        for c in [0usize, 7, 15, P2_COLS / 2, P2_COLS - 16, P2_COLS - 1] {
            let mut t = row.clone();
            t[c] += Ea4::from(Fa4::ONE);
            let g2 = crate::air_zerocheck::RowGuard::new();
            let l2 = g2.row(&t);
            let mut r2 = Vec::new();
            push_perm_residuals(&l2, 0, &mut r2);
            if r2.iter().any(|v| *v != Ea4::from(Fa4::ZERO)) {
                caught += 1;
            }
        }
        assert_eq!(caught, 6, "only {caught}/6 single-cell tampers were caught by the embedded block");
        eprintln!(
            "[perm] embedded block: honest row → {} zero residuals, 6/6 single-cell tampers rejected",
            perm_residual_count()
        );
    }

    /// ⭐⭐⭐ THE FLATNESS EVIDENCE, AS A DETERMINISTIC COUNTER — not a ratio, not a clock.
    ///
    /// The miner's per-block proving trace must be a function of the two frozen consensus constants and
    /// of NOTHING else. This asserts the counter is identical at height 1 and at height 10^18, and that
    /// the trace laid for a given seed is byte-identical however much chain has gone by — so no history
    /// quantity can have leaked into the shape.
    #[test]
    fn the_per_block_trace_counter_is_flat() {
        let early = 1u128;
        let late = 1_000_000_000_000_000_000u128;
        assert_eq!(
            per_block_trace_rows(early),
            per_block_trace_rows(late),
            "⛔ the per-block trace depends on HEIGHT — that is a growth axis, and the whole design rests \
             on it not being one"
        );
        assert_eq!(
            HASH_PERMS,
            SCRATCHPAD_ELEMS / WIDTH + MIX_STEPS + 1,
            "the counter must be derived from the frozen constants, never a literal"
        );
        let rows = 64usize;
        assert_eq!(
            build_perm_chain(seed(), rows),
            build_perm_chain(seed(), rows),
            "the same seed must lay the same trace, whatever the chain has done"
        );
        eprintln!(
            "[pow-air] per-block trace = {HASH_PERMS} permutation row(s) = {FILL_PERMS} FILL + \
             {MIX_STEPS} MIX + 1 squeeze, IDENTICAL at height {early} and height {late}"
        );
    }

    /// ⭐⭐ ENGINEERING FEASIBILITY — real Poseidon2 chains, proved and verified at three fixed scales.
    ///
    /// ⛔ THE CLOCK DECIDES NOTHING. No case is refused for being slow: the timings are REPORTED so the
    /// hybrid's arithmetic can be checked against this machine, and the only things asserted are that
    /// every chain PROVES and VERIFIES. The flatness claim rests on the counter above, never on these.
    #[test]
    fn real_poseidon2_chains_prove_and_verify_at_growing_scale() {
        let mut points: Vec<(usize, u128, usize)> = Vec::new();
        for rows in [64usize, 256, 1024] {
            let started = std::time::Instant::now();
            let trace = build_perm_chain(seed(), rows);
            let proof =
                prove_air_direct_light_decider_selfcontained_bytes(trace, make_perm_constraint(), &BIND)
                    .expect("a real Poseidon2 chain proves at every scale");
            let ms = started.elapsed().as_millis();
            assert!(
                verify_air_direct_light_decider_selfcontained_bytes(
                    &proof,
                    make_perm_constraint(),
                    &BIND,
                    crate::whir_rec_block::declared_direct_shape_for_tests(&proof),
                ),
                "an independently-derived verifier must accept the chain at {rows} rows"
            );
            eprintln!(
                "[pow-air] {rows} permutation row(s) x {P2_COLS} cols: proved+verified in {ms} ms, \
                 {} proof byte(s)",
                proof.len()
            );
            points.push((rows, ms, proof.len()));
        }
        let (r_small, _, _) = points[0];
        let (r_big, ms_big, bytes_big) = points[points.len() - 1];
        assert!(r_big > r_small, "the sweep must actually grow: {r_small} -> {r_big} rows");
        eprintln!(
            "[pow-air] reference point for the design's arithmetic: {r_big} rows in {ms_big} ms at \
             {bytes_big} proof byte(s); one whole PoUW hash is {HASH_PERMS} row(s)"
        );
    }

    /// A forged permutation row must be refused — the chain proves the REAL function or it proves
    /// nothing, and a PoW proof built on a constraint that does not bind would let a miner claim a digest
    /// it never computed for a preimage it never hashed.
    #[test]
    fn a_tampered_permutation_row_is_refused() {
        let rows = 64usize;
        let mut bad = build_perm_chain(seed(), rows);
        bad[WIDTH + 1][7] += KoalaBear::ONE;
        let accepted = match prove_air_direct_light_decider_selfcontained_bytes(
            bad,
            make_perm_constraint(),
            &BIND,
        ) {
            None => false,
            Some(p) => {
                verify_air_direct_light_decider_selfcontained_bytes(&p, make_perm_constraint(), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p))
            }
        };
        assert!(
            !accepted,
            "⛔ a tampered permutation row was ACCEPTED: the PoUW hash would not be bound, and a miner \
             could claim any digest it liked for any preimage."
        );
        eprintln!("[pow-air] a tampered permutation row is refused");
    }

    /// ⭐⭐⭐ THE DIFFERENTIAL GATE — the compiled tape must equal the reference evaluator, exactly.
    ///
    /// `whole_chain::CompiledTape` replaced a recursive `Arc`-walking evaluator on the hot path. A faster
    /// evaluator that is subtly DIFFERENT is not a speedup, it is a soundness bug: a prover and a verifier
    /// would disagree about a valid proof, and the failure would look like flakiness. So this takes a REAL
    /// Poseidon2 AIR's constraints — the same ones every gate in this module proves — feeds both
    /// evaluators the same random openings, and demands exact equality on every draw.
    #[test]
    fn the_tape_agrees_with_the_reference_evaluator() {
        use crate::whole_chain::{eval_base_expr_lifted, CompiledTape, SymLeafLayout};
        use p3_air::symbolic::AirLayout;
        use p3_batch_stark::symbolic::get_symbolic_constraints;
        use p3_lookup::logup::LogUpGadget;
        use p3_poseidon2_air::Poseidon2Air;
        type P2Air = Poseidon2Air<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >;
        let air = P2Air::new(production_constants());
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: P2_COLS,
            num_public_values: 0,
            num_periodic_columns: 0,
            ..Default::default()
        };
        let lg = LogUpGadget::new();
        let (base, _ext) =
            get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
        assert!(base.len() > 100, "a real Poseidon2 AIR must carry many constraints, saw {}", base.len());
        let ll = SymLeafLayout { w: P2_COLS, preproc_w: 0, npub: 0 };
        let tape = CompiledTape::compile(&base, &ll);

        // A deterministic mixer rather than an RNG: the draws must be reproducible, because a
        // disagreement here is a soundness bug and "it failed once on some seed" is not a bug report.
        let mix = |a: u64, b: u64| -> u64 {
            let mut x = a.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ b.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x ^= x >> 31;
            x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
            (x ^ (x >> 29)) % 0x7F00_0001
        };
        let nl = 2 * P2_COLS + 3;
        let mut checked = 0usize;
        for draw in [1u64, 2, 3, 5, 8, 13, 21, 34] {
            let bl: Vec<Ea4> = (0..nl).map(|i| Ea4::from_u64(mix(draw, i as u64))).collect();
            let gamma = Ea4::from_u64(mix(draw, 0xFFFF));
            // The reference: Horner over the recursive walker, exactly as `eval` used to do it.
            let mut want = Ea4::ZERO;
            for c in &base {
                want = want * gamma + eval_base_expr_lifted(c, &bl, &ll);
            }
            assert_eq!(
                tape.eval(&bl, gamma),
                want,
                "⛔ THE TAPE AND THE REFERENCE EVALUATOR DISAGREE. The compiled path is not the same \
                 function, so a prover and a verifier would disagree about a valid proof."
            );
            checked += 1;
        }
        assert_eq!(checked, 8, "every draw must be compared");
        eprintln!(
            "[pow-air] the compiled tape reproduces the reference evaluator on {checked} deterministic draw(s): \
             {} constraint(s) flattened to {} op(s) — {:.1}x fewer nodes than walking each DAG apart",
            base.len(),
            tape.len(),
            tape.len() as f64 / base.len() as f64
        );
    }
}

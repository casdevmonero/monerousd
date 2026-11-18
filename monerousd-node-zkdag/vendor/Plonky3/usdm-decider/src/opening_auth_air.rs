// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.


//! ⭐⭐⭐ THE OPENING'S AUTHENTICATION, IN ONE TABLE — §BD-2 part (c), the half that makes the path
//! mean something.
//!
//! ⛔⛔⛔ WHY ONE TABLE AND NOT TWO. `crate::merkle_path_air` proves "leaf L reaches root R". That is a
//! free-floating gadget until L is tied to the values part (b) evaluates the inner AIR on. The obvious
//! wiring — prove the leaf hash in one AIR, the path in another, and declare the leaf a public input of
//! both — is exactly the CROSS-TIE that §AJ measured failing: an outer proof stood over an object its
//! own verifier refused, because a tie that lives between two proofs is a tie the recursion drops. §AJ's
//! fix was to put the step in ONE table with every tie row-local, and that is what this module does.
//!
//! ## The relation, exactly
//! A `MerkleTreeHidingMmcs` leaf is `PaddingFreeSponge<Perm16, 16, 8, 8>` over the opened row's values
//! (with the hiding salt appended), and a level of the path is
//! `TruncatedPermutation<Perm16, 2, 8, 16>` ordered by the query index's bit. Both are the SAME
//! Poseidon2-16 permutation, so ONE table can carry both: rows `0..s` absorb, rows `s..n` climb, and the
//! join is a single row-local residual — "whenever the NEXT row is a path row, its node is THIS row's
//! permutation output". At the boundary that says `first node == sponge output == the leaf`; inside the
//! path it says the chain continues. One residual, both jobs, nothing between proofs.
//!
//! ⭐ WHAT A VERIFIER BRINGS. Three publics: the `root` (the MMCS commitment the opening claims), a
//! `fold_point`, and `open_fold` — the Horner fold of the absorbed sequence AT that point. The fold is
//! how the opened VALUES enter the statement without riding a second proof: part (b) already holds
//! `opened`, folds it the same way, and the two agree or the last row's residual is non-zero.
//!
//! ⛔⛔⛔ THE FOLD POINT MUST BE TRANSCRIPT-DRAWN, AND THIS IS NOT A DETAIL. A Horner fold at a FIXED
//! point is a LINEAR map, so a prover who knows the point can produce a second sequence with the same
//! fold by hand — change two cells by `d` and `-d * z^(i-j)` and the fold does not move. It would then
//! absorb the REAL opened row here (matching the public fold honestly) while part (b) evaluated the
//! inner AIR on a DIFFERENT row with the same fold, and the two halves would agree on a number while
//! disagreeing on the row. `the_fold_is_forgeable_at_a_point_the_prover_knows` constructs exactly that
//! collision, and `a_transcript_drawn_point_separates_the_colliding_sequences` shows the fix works.
//! So `fold_point` MUST come from a transcript that has already absorbed the trace commitment — which
//! is one more reason the production carriers have to be on `committed_air` (item 1).
//!
//! ⛔ SCALE, MEASURED NOT ASSUMED. One committed-carrier opening is 2,471 Merkle siblings and 6,336 leaf
//! field elements across 160 query openings (§BJ, `committed_air::bj_opening_cost`) — about 2,471 + 792
//! permutations, which is why this is sized to one 4,096-row table.
//!
//! ⛔ ROW-SHIFTED BY CONSTRUCTION, so this AIR must NOT be used with the §BE-1 blinding wrapper
//! (`committed_air::prove_air_blinded_bytes`), for the reason that wrapper's own doc gives.

use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};
use crate::merkle_path_air::{PathStep, CARRIER_SEED, DIGEST};
use crate::sponge_chain_air::{constants_for_seed, perm_for_seed, OUTPUT_OFF, P2_COLS, RATE, WIDTH};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols};
use p3_symmetric::Permutation;

const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;
type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;
type P2Air = Poseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// The permutation's input block starts at column 0 (mirroring `sponge_chain_air`).
const INPUT_OFF: usize = 0;
/// 0 = this row is a leaf-sponge absorption, 1 = it is a path level. Constrained boolean AND
/// non-decreasing, so the table is exactly one sponge prefix followed by one path suffix.
pub const MODE_OFF: usize = P2_COLS;
/// The values absorbed into the rate on this row.
pub const ABS_OFF: usize = MODE_OFF + 1;
/// Which rate slots this row actually OVERWROTE. `PaddingFreeSponge` leaves the rest carrying the
/// previous permutation output — the partial-block case a "just zero the tail" circuit gets wrong.
pub const OW_OFF: usize = ABS_OFF + RATE;
/// The running Horner fold of every absorbed value, one cell per rate slot so each step stays degree 2.
pub const AF_OFF: usize = OW_OFF + RATE;
/// The running node climbing the path.
pub const NODE_OFF: usize = AF_OFF + RATE;
/// The sibling at this level.
pub const SIB_OFF: usize = NODE_OFF + DIGEST;
/// The query index's bit at this level: 0 = the node is the LEFT input, 1 = the RIGHT.
pub const BIT_OFF: usize = SIB_OFF + DIGEST;
/// 1 on the LAST path row of a query opening — the row whose permutation output is the ROOT. A real
/// WHIR opening is 480 of these, not one (§BJ), so the table is a sequence of segments and this is what
/// separates them.
pub const SEG_OFF: usize = BIT_OFF + 1;
/// 1 while the table still carries real work. The row count is a power of two and the opening's is not,
/// so the tail is idle. ⛔ IT IS A PREFIX AND IT CANNOT HIDE AN OMISSION: `live` is constrained monotone
/// decreasing, and the PUBLIC value fold at the last row pins the whole absorbed sequence — a prover who
/// shortens the live prefix to drop a query opening moves the fold and is refused.
pub const LIVE_OFF: usize = SEG_OFF + 1;
/// Total committed columns per row.
pub const ROW_COLS: usize = LIVE_OFF + 1;

/// One query opening: the leaf's values and the authentication path they climb.
///
/// ⛔ NOT A NODE STORE — a transient witness for ONE proof, held only while that proof is laid. Both
/// lengths are fixed by the WHIR CONFIGURATION, which `committed_air::bj_opening_cost` measures: §BJ
/// found them IDENTICAL for a 201x2048 and a 12,885x32 trace, so neither is a function of the trace, the
/// chain height, the block count or the note count.
#[derive(Clone, Debug)]
pub struct Opening {
    /// The opened row's field elements — 6,336 across all 480 openings at the committed shape, ~13 each.
    /// O1-FOOTPRINT-REVIEWED: bounded by COMMITTED_FOLDING (the opened row width the WHIR config fixes).
    pub values: Vec<KoalaBear>,
    /// One step per Merkle level.
    /// O1-FOOTPRINT-REVIEWED: bounded by COMMITTED_FOLDING — at most `log2(domain_size >>
    /// COMMITTED_FOLDING)` levels, 11 at the committed carrier's shape.
    pub path: Vec<PathStep>,
}

impl Opening {
    /// Rows this opening occupies: its sponge block count plus one row per path level.
    #[must_use]
    pub fn rows(&self) -> usize {
        sponge_rows(self.values.len()) + self.path.len()
    }
}

/// Fold an opened value sequence the way the circuit folds it, at the verifier's point. A verifier
/// holding `opened` calls THIS — there is one definition, so the two sides cannot drift.
///
/// ⛔ `point` IS A CHALLENGE, NOT A CONSTANT. See the module header: at a point the prover knows in
/// advance this map is linear and a colliding sequence is a two-line computation.
#[must_use]
pub fn open_fold_at(point: KoalaBear, values: &[KoalaBear]) -> KoalaBear {
    values.iter().fold(KoalaBear::ZERO, |acc, v| acc * point + *v)
}

/// The leaf digest `MerkleTreeHidingMmcs` computes for an opened row, natively.
///
/// ⛔ OVERWRITE MODE, NOT ZERO-PADDING. A partial final block leaves the untouched rate slots holding
/// the PREVIOUS permutation output. A circuit that zeroed them would agree with this function only when
/// the length happens to be a multiple of `RATE`.
#[must_use]
pub fn leaf_hash(seed: u64, values: &[KoalaBear]) -> [KoalaBear; DIGEST] {
    let perm = perm_for_seed(seed);
    let mut state = [KoalaBear::ZERO; WIDTH];
    let mut i = 0usize;
    while i < values.len() {
        let take = RATE.min(values.len() - i);
        state[..take].copy_from_slice(&values[i..i + take]);
        state = perm.permute(state);
        i += take;
    }
    let mut out = [KoalaBear::ZERO; DIGEST];
    out.copy_from_slice(&state[..DIGEST]);
    out
}

/// How many sponge rows a value sequence of this length needs.
#[must_use]
pub const fn sponge_rows(n: usize) -> usize {
    n.div_ceil(RATE)
}

/// Lay the whole table: the leaf sponge, then the path, then the statement's endpoints.
///
/// Returns the trace, the leaf the sponge produced, and the root the path reached — a caller uses the
/// last two as the publics, and `leaf` is returned for gates rather than for the statement (the
/// statement never names it, which is the point: it is a WITNESS shared row-locally).
///
/// ⛔ PADDING CONTINUES THE FOLD, IT DOES NOT REPEAT A ROW — a repeated row would break the very
/// chaining residual this AIR enforces. Path rows past the real depth fold with a zero sibling.
/// Lay the whole table: one SEGMENT per query opening — its leaf sponge, then its path — followed by an
/// idle tail. Returns the trace and the root every segment reached.
///
/// ⛔ EVERY SEGMENT CLIMBS TO THE SAME ROOT, which is what makes this a real opening rather than a
/// gadget: 480 query openings all authenticate against the ONE commitment the inner proof made.
///
/// ⛔ THE IDLE TAIL IS NOT A HOLE. A power-of-two table cannot match an opening's natural row count, so
/// the remainder is idle. `live` is constrained monotone decreasing and every residual is gated on it —
/// and a prover cannot shorten the prefix to drop an opening, because the PUBLIC value fold at the last
/// row pins the entire absorbed sequence across every segment.
#[must_use]
pub fn build_trace_multi(
    seed: u64,
    fold_point: KoalaBear,
    openings: &[Opening],
    rows: usize,
) -> Option<(Vec<Vec<Fa4>>, [KoalaBear; DIGEST])> {
    if !rows.is_power_of_two() || openings.is_empty() {
        return None;
    }
    let need: usize = openings.iter().map(Opening::rows).sum();
    if need == 0 || need > rows {
        return None; // fail-closed: the shape is public and must be stateable
    }
    for o in openings {
        // A segment needs at least one sponge row and at least one path row, or its leaf never climbs.
        if o.values.is_empty() || o.path.is_empty() {
            return None;
        }
    }
    let consts = constants_for_seed(seed);
    let perm = perm_for_seed(seed);

    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; rows]; ROW_COLS];
    let mut fold = KoalaBear::ZERO;
    let mut root = [KoalaBear::ZERO; DIGEST];
    let mut slot = 0usize;

    for o in openings {
        let s = sponge_rows(o.values.len());
        let mut state = [KoalaBear::ZERO; WIDTH];
        let mut node = [KoalaBear::ZERO; DIGEST];
        for k in 0..o.rows() {
            let is_path = k >= s;
            if is_path {
                let st = o.path[k - s];
                let (l, r) = if st.bit { (st.sibling, node) } else { (node, st.sibling) };
                state = [KoalaBear::ZERO; WIDTH];
                state[..DIGEST].copy_from_slice(&l);
                state[DIGEST..].copy_from_slice(&r);
                cols[MODE_OFF][slot] = KoalaBear::ONE;
                for j in 0..DIGEST {
                    cols[NODE_OFF + j][slot] = node[j];
                    cols[SIB_OFF + j][slot] = st.sibling[j];
                }
                cols[BIT_OFF][slot] = if st.bit { KoalaBear::ONE } else { KoalaBear::ZERO };
                if k + 1 == o.rows() {
                    cols[SEG_OFF][slot] = KoalaBear::ONE;
                }
            } else {
                let base = k * RATE;
                let take = RATE.min(o.values.len() - base);
                // A segment's sponge starts from the ALL-ZERO state, so each leaf is hashed on its own.
                if k == 0 {
                    state = [KoalaBear::ZERO; WIDTH];
                }
                for c in 0..take {
                    state[c] = o.values[base + c];
                    cols[ABS_OFF + c][slot] = o.values[base + c];
                    cols[OW_OFF + c][slot] = KoalaBear::ONE;
                }
                for c in 0..RATE {
                    if c < take {
                        fold = fold * fold_point + o.values[base + c];
                    }
                    cols[AF_OFF + c][slot] = fold;
                }
            }
            if is_path {
                for c in 0..RATE {
                    cols[AF_OFF + c][slot] = fold;
                }
            }
            cols[LIVE_OFF][slot] = KoalaBear::ONE;

            let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &consts);
            for (col, v) in filled.iter().enumerate() {
                cols[col][slot] = *v;
            }

            state = perm.permute(state);
            if k + 1 >= s {
                node.copy_from_slice(&state[..DIGEST]);
            }
            slot += 1;
        }
        // Every segment must reach the SAME root, or the openings are not of one commitment.
        if root == [KoalaBear::ZERO; DIGEST] {
            root = node;
        } else if root != node {
            return None;
        }
    }
    // ⛔ AN IDLE ROW STILL HAS TO BE A REAL PERMUTATION ROW. Every residual ABOVE is gated on `live`,
    // but the Poseidon2 block is not — it applies to every row of the table, because gating it would
    // hand a prover a switch that turns the permutation off. So the tail carries the honest permutation
    // of the all-zero state: inert, valid, and costing the prover nothing it could exploit.
    // (Laying zeros here is what made the first draft of this generalisation fail its own control gate.)
    if slot < rows {
        let zero = [KoalaBear::ZERO; WIDTH];
        let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(zero, &consts);
        for t in slot..rows {
            for (col, v) in filled.iter().enumerate() {
                cols[col][t] = *v;
            }
            // The tail carries the fold forward so the public equality still lands on the last row.
            for c in 0..RATE {
                cols[AF_OFF + c][t] = fold;
            }
        }
    }
    Some((cols, root))
}

/// One opening, as a call into [`build_trace_multi`]. Kept so the single-segment gates exercise the very
/// same code the 480-segment production shape runs — one definition, never a second path.
#[must_use]
pub fn build_trace(
    seed: u64,
    fold_point: KoalaBear,
    values: &[KoalaBear],
    path: &[PathStep],
    rows: usize,
) -> Option<(Vec<Vec<Fa4>>, [KoalaBear; DIGEST], [KoalaBear; DIGEST])> {
    let o = Opening { values: values.to_vec(), path: path.to_vec() };
    let leaf = leaf_hash(seed, values);
    let (cols, root) = build_trace_multi(seed, fold_point, core::slice::from_ref(&o), rows)?;
    Some((cols, leaf, root))
}

/// The opening-authentication relation as an AIR. The publics are the `root` the path must reach and
/// the `open_fold` of the value sequence the leaf was hashed from — nothing else. The LEAF is
/// deliberately not a public: it is a witness two groups of rows share row-locally, which is the whole
/// reason this is one table (§AJ).
pub struct OpeningAuthConstraint {
    pub gamma: Ea4,
    /// The same wrapper `sponge_chain_air` uses — see its note; delegating keeps ONE definition of the
    /// permutation rather than a second hand-written copy.
    pub p2: crate::whole_chain::WholeChainMainConstraint,
    pub root: [Fa4; DIGEST],
    /// ⛔ A CHALLENGE, NOT A CONSTANT — see the module header.
    pub fold_point: Fa4,
    pub open_fold: Fa4,
}

impl AirConstraint for OpeningAuthConstraint {
    fn degree(&self, nvars: usize) -> usize {
        // Every residual below is at most degree 4 in the committed cells; the permutation's own bound
        // dominates, exactly as in `sponge_chain_air`.
        self.p2.degree(nvars)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = self.p2.eval(local, at, x);
        let g = self.gamma;
        let push = |acc: &mut Ea4, r: Ea4| {
            *acc = *acc * g + r;
        };
        // Boundary selectors, functions of the zerocheck's OWN point — nothing here a prover can move.
        let mut is_first = Ea4::ONE;
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_first *= Ea4::ONE - xk;
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;

        let md = local[MODE_OFF];
        let mdn = at(MODE_OFF, &[]);
        let seg = local[SEG_OFF];
        let lv = local[LIVE_OFF];
        let lvn = at(LIVE_OFF, &[]);
        let m = Ea4::from(self.fold_point);
        let one = Ea4::ONE;

        // ── 1. THE TABLE'S SHAPE ───────────────────────────────────────────────────────────────────
        push(&mut acc, md * (one - md));
        push(&mut acc, seg * (one - seg));
        push(&mut acc, lv * (one - lv));
        // `live` is a PREFIX: it never rises. Row 0 is live; the last row is live-or-idle.
        push(&mut acc, is_trans * (one - lv) * lvn);
        push(&mut acc, is_first * (one - lv));
        // ⛔ AN IDLE ROW IS INERT. Without this a prover parks real work in the tail where the residuals
        // below are gated off, and the fold would still have to match — but the permutation columns
        // would be free to carry a second, unconstrained sponge.
        push(&mut acc, (one - lv) * md);
        push(&mut acc, (one - lv) * seg);
        // A segment ENDS on a path row, and only a live row can end one.
        push(&mut acc, seg * (one - md));
        push(&mut acc, seg * (one - lv));
        // ⛔ THE LAST LIVE ROW MUST CLOSE ITS SEGMENT — otherwise a prover stops mid-climb and the final
        // partial path is never checked against the root. Stated for both shapes: a table that ends live,
        // and a table whose live prefix ends before the tail.
        push(&mut acc, is_last * lv * (one - seg));
        push(&mut acc, is_trans * lv * (one - lvn) * (one - seg));
        // WITHIN a segment the mode is a prefix: sponge rows, then path rows, never back. The segment
        // boundary is the one place it may fall, which is what `(1 - seg)` allows.
        push(&mut acc, is_trans * (one - seg) * lvn * md * (one - mdn));

        // ── 2. THE LEAF SPONGE ─────────────────────────────────────────────────────────────────────
        // `PaddingFreeSponge` in OVERWRITE mode: an absorbed rate slot takes the new value, an untouched
        // one CARRIES the previous permutation output, and the capacity always carries. The carry is
        // what a "zero the tail" circuit gets wrong on every partial final block.
        for k in 0..RATE {
            let ow = local[OW_OFF + k];
            push(&mut acc, ow * (one - ow));
            // A path row absorbs nothing, and neither does an idle row — otherwise the public fold could
            // be advanced during the climb or in the tail.
            push(&mut acc, md * ow);
            push(&mut acc, (one - lv) * ow);
        }
        for j in 0..WIDTH {
            let next_in = at(INPUT_OFF + j, &[]);
            let cur_out = local[OUTPUT_OFF + j];
            let n_ow = if j < RATE { at(OW_OFF + j, &[]) } else { Ea4::ZERO };
            let n_abs = if j < RATE { at(ABS_OFF + j, &[]) } else { Ea4::ZERO };
            let want = if j < RATE { n_ow * n_abs + (one - n_ow) * cur_out } else { cur_out };
            // Continue the sponge only INSIDE a segment: not across a segment boundary (the next leaf
            // starts from zero) and not into the idle tail.
            push(&mut acc, is_trans * lvn * (one - seg) * (one - mdn) * (next_in - want));
        }
        // A SEGMENT STARTS FROM THE ALL-ZERO STATE — on row 0, and on every row after a segment closes.
        // Without this each leaf would inherit the previous leaf's state and no leaf would be the hash of
        // its own opened row.
        for j in 0..WIDTH {
            let cur_in = local[INPUT_OFF + j];
            let start = if j < RATE { cur_in - local[OW_OFF + j] * local[ABS_OFF + j] } else { cur_in };
            push(&mut acc, is_first * start);
            let n_in = at(INPUT_OFF + j, &[]);
            let n_start = if j < RATE {
                n_in - at(OW_OFF + j, &[]) * at(ABS_OFF + j, &[])
            } else {
                n_in
            };
            push(&mut acc, is_trans * seg * lvn * n_start);
        }
        // The row after a segment closes is a SPONGE row, never a path row.
        push(&mut acc, is_trans * seg * lvn * mdn);

        // ── 3. THE JOIN — ONE RESIDUAL DOING BOTH JOBS ─────────────────────────────────────────────
        // "Whenever the NEXT row is a path row, its node is THIS row's permutation output." At a
        // segment's mode boundary that reads `first node == sponge output == THE LEAF`; inside the path
        // it is the climb. ⛔ This is the tie a two-proof design would carry as a public BETWEEN
        // circuits — the shape §AJ measured the recursion dropping. Here it is one row-local residual.
        for j in 0..DIGEST {
            push(&mut acc, is_trans * lvn * mdn * (at(NODE_OFF + j, &[]) - local[OUTPUT_OFF + j]));
        }

        // ── 4. THE PATH ────────────────────────────────────────────────────────────────────────────
        let b = local[BIT_OFF];
        push(&mut acc, b * (one - b));
        // ⛔ THE ORDER IS THE WHOLE POINT: a fold that ignored the bit would accept the same siblings on
        // the wrong side, which is a DIFFERENT leaf position reaching the claimed root.
        for j in 0..DIGEST {
            let node = local[NODE_OFF + j];
            let sib = local[SIB_OFF + j];
            push(&mut acc, md * (local[INPUT_OFF + j] - ((one - b) * node + b * sib)));
            push(&mut acc, md * (local[INPUT_OFF + DIGEST + j] - ((one - b) * sib + b * node)));
        }
        // ⭐ EVERY SEGMENT REACHES THE PUBLIC ROOT. This is what makes 480 openings authenticate ONE
        // commitment rather than 480 unrelated trees.
        for j in 0..DIGEST {
            push(&mut acc, seg * (local[OUTPUT_OFF + j] - Ea4::from(self.root[j])));
        }

        // ── 5. THE VALUE FOLD — how `opened` enters the statement ──────────────────────────────────
        // One degree-2 step per rate slot, advancing exactly on the OVERWRITTEN slots, so a partial final
        // block folds the values it really absorbed and nothing more. It runs across EVERY segment and
        // through the idle tail, so the single public equality below pins the whole opened sequence.
        for k in 1..RATE {
            let ow = local[OW_OFF + k];
            let prev = local[AF_OFF + k - 1];
            push(&mut acc, local[AF_OFF + k] - (ow * (prev * m + local[ABS_OFF + k]) + (one - ow) * prev));
        }
        {
            let ow = local[OW_OFF];
            push(&mut acc, is_first * (local[AF_OFF] - ow * local[ABS_OFF]));
        }
        {
            let prev = local[AF_OFF + RATE - 1];
            let n_ow = at(OW_OFF, &[]);
            let n_af = at(AF_OFF, &[]);
            let n_abs = at(ABS_OFF, &[]);
            push(&mut acc, is_trans * (n_af - (n_ow * (prev * m + n_abs) + (one - n_ow) * prev)));
        }
        // THE EQUALITY. `open_fold` is not read from the trace, so a prover cannot move it: the leaves
        // were hashed from the sequence the verifier holds, or this residual is non-zero. ⛔ THIS IS ALSO
        // WHAT MAKES THE IDLE TAIL SAFE — shortening the live prefix to drop an opening drops its values
        // from the fold, and the fold is public.
        push(&mut acc, is_last * (local[AF_OFF + RATE - 1] - Ea4::from(self.open_fold)));
        acc
    }
}

/// Build the constraint for a public statement. Both sides call this, so the circuit a prover satisfies
/// is the circuit a verifier rebuilds.
#[must_use]
pub fn make_constraint(
    seed: u64,
    root: [KoalaBear; DIGEST],
    fold_point: KoalaBear,
    open_fold: KoalaBear,
) -> impl Fn(Ea4) -> OpeningAuthConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;

    let air = P2Air::new(constants_for_seed(seed));
    // The permutation AIR's own width is `P2_COLS`; `SymLeafLayout { w: ROW_COLS }` re-maps its variable
    // indices into the wider committed row. Identical to `sponge_chain_air` and `merkle_path_air`.
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: P2_COLS,
        num_public_values: 0,
        num_periodic_columns: 0,
        ..Default::default()
    };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |gamma: Ea4| OpeningAuthConstraint {
        gamma,
        p2: crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: ROW_COLS, preproc_w: 0, npub: 0 },
            ROW_COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        ),
        root,
        fold_point,
        open_fold,
    }
}

/// The seed every production call uses — the committed carrier's, since that is the MMCS whose openings
/// part (c) authenticates. Re-exported so callers never have to remember which family they are in.
pub const SEED: u64 = CARRIER_SEED;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path_air::fold_path;
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };

    const BIND: [Fa4; 1] = [KoalaBear::new(0x4f_50_4e_41)]; // "OPNA"
    const ROWS: usize = 32;
    /// ⛔ DELIBERATELY NOT A MULTIPLE OF `RATE`. A length that divided evenly would never exercise the
    /// partial-final-block CARRY, which is the one place a "zero the tail" circuit silently disagrees
    /// with `PaddingFreeSponge`.
    const NVALS: usize = 21;
    const DEPTH: usize = 12;

    fn kb(v: u64) -> KoalaBear {
        KoalaBear::from_u64(v)
    }
    fn values() -> Vec<KoalaBear> {
        (0..NVALS).map(|i| kb(0x9000 + 37 * i as u64)).collect()
    }
    /// Mixed index bits — all-zero bits would make the left/right selector untestable.
    fn path() -> Vec<PathStep> {
        (0..DEPTH)
            .map(|k| PathStep {
                sibling: core::array::from_fn(|i| kb(4000 + 13 * k as u64 + i as u64)),
                bit: k % 3 == 1 || k % 4 == 2,
            })
            .collect()
    }
    /// Stands in for the transcript-drawn fold point. In production this comes from a challenger that
    /// has already absorbed the trace commitment; in a gate it only has to be a value the FIXTURES do
    /// not get to choose after the fact.
    fn point() -> KoalaBear {
        kb(0x2b_1d_55_07)
    }
    fn honest() -> (Vec<Vec<Fa4>>, [KoalaBear; DIGEST], [KoalaBear; DIGEST], KoalaBear) {
        let (t, leaf, root) =
            build_trace(SEED, point(), &values(), &path(), ROWS).expect("the shape is stateable");
        (t, leaf, root, open_fold_at(point(), &values()))
    }

    /// ⭐⭐⭐ CALIBRATION #1 — the leaf this module hashes is the leaf the CARRIER'S MMCS hashes. Without
    /// this every gate below is about a hash nothing in this tree computes; `sponge_chain_air`'s header
    /// records the identical trap being paid for once already.
    #[test]
    fn the_leaf_hash_is_exactly_the_carriers_mmcs_leaf_hash() {
        use p3_symmetric::CryptographicHasher;
        let sponge = crate::hiding_decider::SpongeHash::new(perm_for_seed(SEED).clone());
        // Lengths around and across the rate boundary: a partial block, an exact block, a partial
        // second block. The exact-multiple case alone would hide the carry semantics.
        for n in [1usize, 7, 8, 9, 16, 21, 40] {
            let v: Vec<KoalaBear> = (0..n).map(|i| kb(11 + 5 * i as u64)).collect();
            let mine = leaf_hash(SEED, &v);
            let theirs: [KoalaBear; DIGEST] = sponge.hash_iter(v.iter().copied());
            assert_eq!(
                mine, theirs,
                "⛔ THE CIRCUIT'S LEAF HASH IS NOT THE MMCS'S LEAF HASH at n={n}"
            );
        }
        // And the MMCS really does hash a concatenation of slices, which is what lets one absorb chain
        // stand for a multi-matrix opened row.
        let a = [kb(1), kb(2), kb(3)];
        let b = [kb(4), kb(5)];
        let split: [KoalaBear; DIGEST] = sponge.hash_iter_slices([a.as_slice(), b.as_slice()]);
        assert_eq!(split, leaf_hash(SEED, &[kb(1), kb(2), kb(3), kb(4), kb(5)]));
        eprintln!("[opening-auth] leaf hash == carrier MMCS leaf hash, partial blocks and slices");
    }

    /// ⭐⭐ THE CARRY IS NOT DECORATIVE. A circuit that zeroed the untouched rate slots of a partial final
    /// block would pass every honest test whose length happened to divide by `RATE`. Prove the two
    /// semantics actually diverge, so the residual that implements the carry is load-bearing.
    #[test]
    fn overwrite_carry_and_zero_padding_are_different_hashes() {
        let v: Vec<KoalaBear> = (0..NVALS).map(|i| kb(3 + i as u64)).collect();
        let mut padded = v.clone();
        padded.resize(v.len().next_multiple_of(RATE), KoalaBear::ZERO);
        assert_ne!(
            leaf_hash(SEED, &v),
            leaf_hash(SEED, &padded),
            "⛔ overwrite-carry and zero-padding agree here — the partial-block residual is untested"
        );
        eprintln!("[opening-auth] overwrite-carry differs from zero-padding, as it must");
    }

    /// CALIBRATION #2 — the table's own leaf and root are the native ones, so the trace and the
    /// reference are one fold rather than two spellings (§AO).
    #[test]
    fn the_laid_table_matches_the_native_leaf_and_path() {
        let (_, leaf, root, _) = honest();
        assert_eq!(leaf, leaf_hash(SEED, &values()), "⛔ the table's leaf is not the native leaf hash");
        // ⭐ THE ROOT IS THE PATH'S OWN ROOT NOW. The single-segment draft folded extra padding levels to
        // fill the table, so the "root" moved with the table HEIGHT — an artifact no real opening has.
        // Segments plus an idle tail removed that: the table stops climbing when the path ends.
        assert_eq!(root, fold_path(SEED, leaf, &path()), "⛔ the table's root is not the native fold");
        assert_ne!(
            root,
            fold_path(SEED, leaf, &crate::merkle_path_air::padded_path(&path(), ROWS)),
            "the root must NOT be the height-padded fold — that was the artifact this removed"
        );
        eprintln!("[opening-auth] table leaf/root == native leaf hash / native path fold");
    }

    /// CONTROL. An honest opening proves, and a verifier sharing NO object with the prover accepts.
    #[test]
    fn an_honest_opening_proves_and_an_independently_built_verifier_accepts() {
        let (trace, _, root, fold) = honest();
        let proof =
            prove_air_direct_light_decider_selfcontained_bytes(trace, make_constraint(SEED, root, point(), fold), &BIND)
                .expect("an honest opening authentication proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_constraint(SEED, root, point(), fold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)
            ),
            "an independently-derived verifier must accept an honest opening authentication"
        );
        eprintln!(
            "[opening-auth] {NVALS} values ({} sponge rows) + {DEPTH} levels in {ROWS} rows x {ROW_COLS} \
             cols; verifier accepted {} byte(s)",
            sponge_rows(NVALS),
            proof.len()
        );
    }

    /// ⭐⭐⭐ THE REASON THIS MODULE EXISTS. `merkle_path_air` alone proves "SOME leaf reaches this root".
    /// Here the verifier also holds the VALUE FOLD, so the statement is "the leaf hashed from THESE
    /// values reaches this root". The forger is honest — it builds a perfect table for a DIFFERENT value
    /// sequence and proves it — and a verifier holding the true fold must still refuse. A design that
    /// carried the leaf as a public between two proofs is exactly what §AJ measured being dropped.
    #[test]
    fn a_verifier_holding_the_true_fold_refuses_a_perfect_proof_of_different_values() {
        let (_, _, root, fold) = honest();
        let mut other = values();
        other[5] += KoalaBear::ONE; // ONE value differs — the weakest possible perturbation
        let ofold = open_fold_at(point(), &other);
        assert_ne!(ofold, fold, "the counterfactual fold must differ, or this pin proves nothing");
        let (ft, _, froot) =
            build_trace(SEED, point(), &other, &path(), ROWS).expect("the shape is stateable");
        assert_ne!(froot, root, "a different leaf must reach a different root");
        // The forgery is a REAL proof of its OWN statement — otherwise the refusal below is trivial.
        let fproof = prove_air_direct_light_decider_selfcontained_bytes(
            ft,
            make_constraint(SEED, froot, point(), ofold),
            &BIND,
        )
        .expect("the forger's own statement is honest and proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(SEED, froot, point(), ofold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "the forgery must really prove its own statement"
        );
        // THE GATE, three ways: the true statement, the true root with the wrong fold, and the true fold
        // with the wrong root. All three must refuse, or the leaf is not welded to the values.
        for (what, r, f) in [
            ("the true (root, fold)", root, fold),
            ("the true root, the forger's fold", root, ofold),
            ("the forger's root, the true fold", froot, fold),
        ] {
            assert!(
                !verify_air_direct_light_decider_selfcontained_bytes(
                    &fproof,
                    make_constraint(SEED, r, point(), f),
                    &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
                ),
                "⛔ THE LEAF IS NOT WELDED TO THE OPENED VALUES: a verifier holding {what} accepted a \
                 proof built from a different value sequence."
            );
        }
        eprintln!("[opening-auth] a real proof of different values was refused three ways");
    }

    /// ⭐⭐ THE ORDER GATE, carried through from `merkle_path_air`: the same leaf and the same siblings on
    /// the OTHER side is a different position in the tree, and must not pass for the true root.
    #[test]
    fn flipping_the_index_bits_is_refused_against_the_true_root() {
        let (_, _, root, fold) = honest();
        let flipped: Vec<PathStep> =
            path().iter().map(|s| PathStep { sibling: s.sibling, bit: !s.bit }).collect();
        let (ft, _, froot) =
            build_trace(SEED, point(), &values(), &flipped, ROWS).expect("shape is stateable");
        assert_ne!(froot, root, "flipping the bits must move the root, or the selector is decorative");
        let fproof =
            prove_air_direct_light_decider_selfcontained_bytes(ft, make_constraint(SEED, froot, point(), fold), &BIND)
                .expect("the flipped path is internally honest");
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(SEED, root, point(), fold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "⛔ INDEX ORDER IS NOT BOUND: the same leaf with siblings on the other side was accepted"
        );
        eprintln!("[opening-auth] a bit-flipped path was refused against the true root");
    }

    /// ⭐⭐⭐ THE MODE-PREFIX GATE. If a prover could re-enter sponge mode after the climb began, it
    /// could absorb MORE values — moving the public fold — after it already knew where the path lands.
    /// That would let one root stand for any sequence, which is the whole binding gone. The forger lays
    /// a table that is internally honest in every other respect and only interleaves the modes.
    #[test]
    fn re_entering_sponge_mode_after_the_climb_is_refused() {
        let (mut bad, _, root, fold) = honest();
        let s = sponge_rows(NVALS);
        // Row `s` is the first path row. Flip the row AFTER it back to sponge mode — a 1 -> 0 fall, and
        // nothing else touched, so only the monotonicity residual can catch it.
        assert!(s + 1 < ROWS, "the table must have room for a second path row");
        assert_eq!(bad[MODE_OFF][s], KoalaBear::ONE, "row s must be a path row to begin with");
        bad[MODE_OFF][s + 1] = KoalaBear::ZERO;
        let accepted =
            prove_air_direct_light_decider_selfcontained_bytes(bad, make_constraint(SEED, root, point(), fold), &BIND)
                .is_some_and(|b| {
                    verify_air_direct_light_decider_selfcontained_bytes(
                        &b,
                        make_constraint(SEED, root, point(), fold),
                        &BIND,
                        crate::whir_rec_block::declared_direct_shape_for_tests(&b),
                    )
                });
        assert!(
            !accepted,
            "⛔ THE MODE IS NOT A PREFIX: a table that fell back into sponge mode mid-climb was accepted, \
             so a prover can keep absorbing after it knows the root."
        );
        eprintln!("[opening-auth] a mode fall-back mid-climb was refused");
    }

    /// The §BD-3 vacuity shape: a homogeneous AIR accepts a trace of zeros and certifies nothing. This
    /// one is non-homogeneous by construction — the public root and fold sit inside its own residuals.
    #[test]
    fn the_all_zero_trace_is_refused() {
        let (_, _, root, fold) = honest();
        let zeros: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; ROWS]; ROW_COLS];
        let accepted = prove_air_direct_light_decider_selfcontained_bytes(
            zeros,
            make_constraint(SEED, root, point(), fold),
            &BIND,
        )
        .is_some_and(|b| {
            verify_air_direct_light_decider_selfcontained_bytes(&b, make_constraint(SEED, root, point(), fold), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&b))
        });
        assert!(
            !accepted,
            "⛔ THE ZERO TRACE VERIFIES — this AIR is homogeneous and says nothing, the §BD-3 break"
        );
        eprintln!("[opening-auth] the all-zero trace was refused");
    }

    /// Every single-cell alteration a forger would want, in BOTH halves of the table and on the join
    /// itself. Weaker evidence than the fresh forgeries above (§BG), but it localises which residual is
    /// doing the work so a later edit that deletes one is caught here rather than in production.
    #[test]
    fn every_single_cell_forgery_is_refused() {
        let s = sponge_rows(NVALS);
        let cases: [(&str, usize, usize); 10] = [
            ("an absorbed value", ABS_OFF + 2, 0),
            ("an absorbed value in the PARTIAL final block", ABS_OFF + 4, s - 1),
            ("an overwrite selector", OW_OFF + 6, s - 1),
            ("a value-fold cell", AF_OFF + 3, 1),
            ("the final value-fold cell", AF_OFF + RATE - 1, s - 1),
            ("the leaf, at the join", NODE_OFF, s),
            ("the running node mid-climb", NODE_OFF + 2, s + 3),
            ("a sibling", SIB_OFF + 5, s + 4),
            ("an index bit", BIT_OFF, s + 2),
            ("the mode flag on a sponge row", MODE_OFF, 0),
        ];
        for (what, col, row) in cases {
            let (mut bad, _, root, fold) = honest();
            bad[col][row] += KoalaBear::ONE;
            let accepted = prove_air_direct_light_decider_selfcontained_bytes(
                bad,
                make_constraint(SEED, root, point(), fold),
                &BIND,
            )
            .is_some_and(|b| {
                verify_air_direct_light_decider_selfcontained_bytes(
                    &b,
                    make_constraint(SEED, root, point(), fold),
                    &BIND,
                    crate::whir_rec_block::declared_direct_shape_for_tests(&b),
                )
            });
            assert!(!accepted, "⛔ a forgery of {what} (col {col}, row {row}) was ACCEPTED");
            eprintln!("[opening-auth] refused a forgery of {what}");
        }
    }

    /// ⭐⭐⭐ THE HOLE THIS MODULE'S FIRST DRAFT HAD, KEPT AS A GATE. The fold was Horner at a FIXED
    /// constant, and a Horner fold at a point the prover knows is a LINEAR map: change cell `i` by `d`
    /// and cell `j` by `-d * z^(i-j)` and the fold does not move. A prover would then absorb the REAL
    /// opened row here — matching the public fold honestly — while part (b) evaluated the inner AIR on
    /// the COLLIDING row. Both halves agree on a number and disagree on the row, which is the weld gone.
    ///
    /// This constructs the collision explicitly. It is the calibration for the gate below: if the two
    /// sequences did not really collide, that gate would prove nothing.
    #[test]
    fn the_fold_is_forgeable_at_a_point_the_prover_knows() {
        let z = kb(7); // the constant the first draft used — a point any prover can compute with
        let v = values();
        let (i, j) = (3usize, 9usize);
        assert!(i < j && j < v.len());
        // The fold weights cell k by z^(n-1-k), so a change `d` at i is cancelled by `-d * z^(j-i)` at j.
        let d = kb(12345);
        let mut w = v.clone();
        w[i] += d;
        w[j] -= d * z.exp_u64((j - i) as u64);
        assert_ne!(w, v, "the forged sequence must actually differ");
        assert_eq!(
            open_fold_at(z, &w),
            open_fold_at(z, &v),
            "⛔ the collision construction is wrong, so the gate below would prove nothing"
        );
        eprintln!("[opening-auth] a fold collision at a known point is a two-line computation, as feared");
    }

    /// ⭐⭐⭐ THE FIX, PROBED AGAINST THAT ATTACK. At a point the prover could not predict, the same two
    /// sequences fold apart — so a verifier that draws its point from the transcript refuses the
    /// colliding row instead of agreeing with it.
    #[test]
    fn a_transcript_drawn_point_separates_the_colliding_sequences() {
        let z = kb(7);
        let v = values();
        let (i, j) = (3usize, 9usize);
        let d = kb(12345);
        let mut w = v.clone();
        w[i] += d;
        w[j] -= d * z.exp_u64((j - i) as u64);
        assert_eq!(open_fold_at(z, &w), open_fold_at(z, &v), "calibration: they collide at z");
        // A collision is a root of a fixed non-zero polynomial of degree < n, so it survives at most
        // `n - 1` points. Sweep a spread of points and demand the overwhelming majority separate them.
        let mut separated = 0usize;
        let trials = 64usize;
        for t in 0..trials {
            let pt = kb(0x51_23_00_00 + 977 * t as u64);
            if open_fold_at(pt, &w) != open_fold_at(pt, &v) {
                separated += 1;
            }
        }
        assert_eq!(
            separated, trials,
            "⛔ a colliding pair survived a transcript-drawn point — the fold point is not doing its job"
        );
        // And the circuit itself refuses: an honest table for `v` checked against `w`'s fold.
        let (trace, _, root) =
            build_trace(SEED, point(), &v, &path(), ROWS).expect("the shape is stateable");
        let wfold = open_fold_at(point(), &w);
        assert_ne!(wfold, open_fold_at(point(), &v), "the two folds must differ at the drawn point");
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(SEED, root, point(), open_fold_at(point(), &v)),
            &BIND,
        )
        .expect("the honest table proves");
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_constraint(SEED, root, point(), wfold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)
            ),
            "⛔ the circuit accepted the colliding sequence's fold at the drawn point"
        );
        eprintln!("[opening-auth] {separated}/{trials} points separate the collision; the circuit refused it");
    }

    // ── MULTI-SEGMENT: A REAL OPENING IS 480 QUERIES, NOT ONE ───────────────────────────────────────

    /// `n` openings that all authenticate ONE commitment.
    ///
    /// ⛔ WHY THEY SHARE A LEAF AND A PATH. Every segment must land on the same root. Giving each
    /// opening its own leaf and solving for a sibling that still lands there means INVERTING the
    /// compression, which is exactly what a hash forbids — so a fixture cannot manufacture distinct
    /// leaves under one root without a real tree. Repeating one real opening is legitimate (a WHIR proof
    /// genuinely opens a position more than once across rounds) and it drives every segment residual:
    /// the sponge restart, the mode fall at the boundary, the per-segment root check and the fold that
    /// runs across all of them. `build_trace_multi` fails closed if any segment's climb ever diverges.
    fn many_same_root(n: usize) -> Vec<Opening> {
        let values: Vec<KoalaBear> = (0..13).map(|i| kb(0x8100 + 7 * i as u64)).collect();
        let path: Vec<PathStep> = (0..6)
            .map(|k| PathStep {
                sibling: core::array::from_fn(|i| kb(2200 + 19 * k as u64 + i as u64)),
                bit: k % 3 != 0,
            })
            .collect();
        (0..n).map(|_| Opening { values: values.clone(), path: path.clone() }).collect()
    }

    #[test]
    fn many_openings_of_one_commitment_prove_and_verify() {
        const N: usize = 5;
        let os = many_same_root(N);
        let fold = open_fold_at(point(), &os.iter().flat_map(|o| o.values.clone()).collect::<Vec<_>>());
        let (trace, root) =
            build_trace_multi(SEED, point(), &os, 128).expect("the multi-segment shape is stateable");
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(SEED, root, point(), fold),
            &BIND,
        )
        .expect("an honest multi-opening authentication proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_constraint(SEED, root, point(), fold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)
            ),
            "an independently-derived verifier must accept {N} openings of one commitment"
        );
        eprintln!(
            "[opening-auth] {N} segments ({} rows of work) in 128 rows x {ROW_COLS} cols; accepted {} B",
            os.iter().map(Opening::rows).sum::<usize>(),
            proof.len()
        );
    }

    /// ⭐⭐⭐ THE GATE THE IDLE TAIL EXISTS TO SURVIVE. A power-of-two table cannot match an opening's
    /// natural row count, so the remainder is idle and `live` is a prefix. The obvious attack is to
    /// SHORTEN that prefix and simply not authenticate some of the queries — which is the whole
    /// soundness of a query-based PCS. The forger here is honest: it lays a perfect table for FOUR of
    /// the five openings and proves it. A verifier holding the five-opening fold must refuse.
    #[test]
    fn dropping_a_query_opening_is_refused_by_the_public_fold() {
        const N: usize = 5;
        let all = many_same_root(N);
        let flat = |os: &[Opening]| -> Vec<KoalaBear> {
            os.iter().flat_map(|o| o.values.clone()).collect()
        };
        let full_fold = open_fold_at(point(), &flat(&all));
        let short = &all[..N - 1];
        let short_fold = open_fold_at(point(), &flat(short));
        assert_ne!(short_fold, full_fold, "dropping an opening must move the fold, or this proves nothing");

        let (st, sroot) = build_trace_multi(SEED, point(), short, 128).expect("stateable");
        let (_, froot) = build_trace_multi(SEED, point(), &all, 128).expect("stateable");
        assert_eq!(sroot, froot, "the ROOT is unchanged — only the fold can catch this");

        // CALIBRATION: the forgery is a REAL proof of its own (shorter) statement.
        let fproof = prove_air_direct_light_decider_selfcontained_bytes(
            st,
            make_constraint(SEED, sroot, point(), short_fold),
            &BIND,
        )
        .expect("the four-opening table is internally honest");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(SEED, sroot, point(), short_fold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "the forgery must really prove its own statement, or the refusal below is trivial"
        );
        // THE GATE.
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(SEED, froot, point(), full_fold),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "⛔ A QUERY OPENING CAN BE DROPPED: the live prefix was shortened by one segment and a \
             verifier holding the full statement accepted it. Every query a prover may skip is soundness \
             the PCS does not have."
        );
        eprintln!("[opening-auth] dropping one of {N} openings was refused by the public fold");
    }

    /// ⛔ THE IDLE TAIL MUST BE INERT. Every residual is gated on `live`, so the tail is where a prover
    /// would park a second, unconstrained sponge if the gates did not forbid it outright.
    #[test]
    fn work_parked_in_the_idle_tail_is_refused() {
        let os = many_same_root(3);
        let used: usize = os.iter().map(Opening::rows).sum();
        let fold = open_fold_at(point(), &os.iter().flat_map(|o| o.values.clone()).collect::<Vec<_>>());
        let cases: [(&str, usize); 4] = [
            ("the mode flag", MODE_OFF),
            ("the segment-end flag", SEG_OFF),
            ("an overwrite selector", OW_OFF + 1),
            ("the live flag itself", LIVE_OFF),
        ];
        for (what, col) in cases {
            let (mut bad, root) = build_trace_multi(SEED, point(), &os, 128).expect("stateable");
            assert!(used + 2 < 128, "the fixture must leave an idle tail");
            bad[col][used + 1] += KoalaBear::ONE;
            let accepted = prove_air_direct_light_decider_selfcontained_bytes(
                bad,
                make_constraint(SEED, root, point(), fold),
                &BIND,
            )
            .is_some_and(|b| {
                verify_air_direct_light_decider_selfcontained_bytes(
                    &b,
                    make_constraint(SEED, root, point(), fold),
                    &BIND,
                    crate::whir_rec_block::declared_direct_shape_for_tests(&b),
                )
            });
            assert!(!accepted, "⛔ {what} was writable in the idle tail (col {col})");
            eprintln!("[opening-auth] the idle tail refused {what}");
        }
    }

    /// ⛔ A SEGMENT THAT LANDS SOMEWHERE ELSE IS REFUSED. `seg * (output - root)` is what makes 480
    /// openings authenticate ONE commitment; without it each segment would be its own unrelated tree.
    #[test]
    fn a_segment_that_reaches_a_different_root_is_refused() {
        let os = many_same_root(4);
        let fold = open_fold_at(point(), &os.iter().flat_map(|o| o.values.clone()).collect::<Vec<_>>());
        let (mut bad, root) = build_trace_multi(SEED, point(), &os, 128).expect("stateable");
        // Move the LAST sibling of the second segment: its climb now ends somewhere else entirely, while
        // every other segment still lands on the root.
        let seg1 = os[0].rows();
        let last_of_seg1 = seg1 + os[1].rows() - 1;
        assert_eq!(bad[SEG_OFF][last_of_seg1], KoalaBear::ONE, "that row must close segment 1");
        bad[SIB_OFF][last_of_seg1] += KoalaBear::ONE;
        let accepted = prove_air_direct_light_decider_selfcontained_bytes(
            bad,
            make_constraint(SEED, root, point(), fold),
            &BIND,
        )
        .is_some_and(|b| {
            verify_air_direct_light_decider_selfcontained_bytes(
                &b,
                make_constraint(SEED, root, point(), fold),
                &BIND,
                crate::whir_rec_block::declared_direct_shape_for_tests(&b),
            )
        });
        assert!(!accepted, "⛔ a segment reaching a DIFFERENT root was accepted");
        eprintln!("[opening-auth] a segment landing off the root was refused");
    }

    /// ⭐⭐ THE COST AT THE REAL OPENING SCALE, MEASURED ON THIS CIRCUIT. §BJ counted 2,471 Merkle
    /// siblings and 6,336 leaf field elements in one committed-carrier opening; this runs both halves at
    /// that size and prints what they cost together. `#[ignore]` because it is a measurement, and a gate
    /// that takes minutes stops being run.
    #[test]
    #[ignore = "measurement: run with --ignored"]
    fn the_cost_of_a_real_opening_is_measured() {
        // §BJ, measured on a real committed carrier: 160 query openings per round over 3 rounds, 2,471
        // Merkle siblings and 6,336 leaf field elements in total.
        const QUERIES: usize = 480;
        const SIBS: usize = 2471;
        const VALS: usize = 6336;
        // 3,360 rows of real work, so the smallest power-of-two table that holds it is 4,096 — half the
        // first draft's 8,192, and the prover pays for the table, not for the work.
        const BIG: usize = 4096;
        let per_vals = VALS / QUERIES;
        let per_path = SIBS / QUERIES;
        let values: Vec<KoalaBear> = (0..per_vals).map(|i| kb(0x9000 + 3 * i as u64)).collect();
        let path: Vec<PathStep> = (0..per_path.max(1))
            .map(|k| PathStep {
                sibling: core::array::from_fn(|i| kb(5000 + 11 * k as u64 + i as u64)),
                bit: k % 2 == 1,
            })
            .collect();
        let os: Vec<Opening> =
            (0..QUERIES).map(|_| Opening { values: values.clone(), path: path.clone() }).collect();
        let used: usize = os.iter().map(Opening::rows).sum();
        let fold = open_fold_at(point(), &os.iter().flat_map(|o| o.values.clone()).collect::<Vec<_>>());

        let t0 = std::time::Instant::now();
        let (trace, root) = build_trace_multi(SEED, point(), &os, BIG).expect("the shape is stateable");
        let lay = t0.elapsed();
        let t1 = std::time::Instant::now();
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(SEED, root, point(), fold),
            &BIND,
        )
        .expect("an opening-scale authentication proves");
        let prove = t1.elapsed();
        let t2 = std::time::Instant::now();
        let ok = verify_air_direct_light_decider_selfcontained_bytes(
            &proof,
            make_constraint(SEED, root, point(), fold),
            &BIND,
            crate::whir_rec_block::declared_direct_shape_for_tests(&proof),
        );
        let ver = t2.elapsed();
        assert!(ok, "the opening-scale authentication must verify");
        eprintln!(
            "[opening-auth §BJ] {QUERIES} query openings ({used} rows of work) in {BIG} rows x \
             {ROW_COLS} cols — lay {lay:?}, prove {prove:?}, verify {ver:?}, {} byte(s)",
            proof.len()
        );
    }
}

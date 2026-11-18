// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// Protocol: MonerousD — post-quantum private block-DAG. Module: SPEED C4, verifier steps V4 + V5 + the round combine.

//! ⭐ ONE WHIR QUERY GROUP, VERIFIED IN ONE TABLE: every query's leaf sponge and Merkle path (V4), its fold at the round's
//! folding point (V5), and the γ-combination of the folds into the round's claim — `WhirVerifier::verify_stir_challenges`
//! followed by `Constraint::combine_evals`, as rows.
//!
//! WHY ONE TABLE. The fold must read the very values the leaf hashed, so the tie is row-local (§AJ: a tie between two
//! proofs is a tie the recursion drops). A query's segment is its absorb rows (the opened row, then its 8-word salt, as
//! the hiding MMCS hashes it) followed by its path rows; the fold accumulates on the absorb rows; the segment's last path
//! row reaches the round's root and adds `γ^(shift + m) · fold_m` to the running claim.
//!
//! ⭐ THE STRUCTURE IS PUBLIC, AND IS CHECKED AS SUCH. Every query of a group has the same leaf length and path depth, so
//! WHICH rows absorb, which climb, where a segment starts and ends, which rate slots are overwritten, the path BIT at
//! every level (the bits of the positions the verifier drew) and the fold WEIGHT of every absorbed word (`eq(i, r)` at the
//! round's folding point, times the extension basis for a flattened extension value) are functions of the statement
//! alone. They are committed like any column, and the verifier recomputes each one's multilinear evaluation at the
//! zerocheck point and requires it to equal the opened value ([`verify_group`]). The point is drawn after the
//! commitment, so a column that differs from its public vector anywhere is refused except with probability
//! `rows / |Ea4|` (Schwartz–Zippel). That binds the positions EXACTLY — a linear fold of the positions at a point the
//! prover knows would leave a small-integer collision for a lattice to find.
//!
//! WHAT IS STATED, for every group of the table (a block's table holds the groups of every carrier it carries, back to
//! back): "the group's `q` openings at its public positions authenticate against its `root`, and their folds at its
//! public weights, combined as `Σ_m γ^(shift + m) · fold_m`, equal its `claim`". The root, coefficients and claim are
//! public columns too (ROOT and COEF on each segment's last row, GEND and GCLAIM on each group's last row), so one
//! relation serves every statement, and each group's claim is checked EXACTLY at its own last row, with no random
//! combination across groups. The statements are the peer's own records of verifying each carrier's core
//! (`committed_air::verify_blinded_chained_core`): the root, the positions, the folding point, γ and the claim the
//! WHIR verifier itself drew or took.
//!
//! SCALE (SAFE AT SCALE): rows = Σ over groups of queries × (leaf blocks + depth), constants of the WHIR configuration
//! per carrier, so a block's table grows with the payments it carries and never with the bonded set or height. The
//! verifier's extra work is one walk over the public cells against one eq table, O(rows).
//! AI RESISTANT: (a) a proof every verifier checks; a lying prover's table either breaks a residual (a moved value, a
//! moved sibling, a wrong fold) or a public column's evaluation (a moved bit, a moved weight, a shortened table).

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::sponge_chain_air::{constants_for_seed, perm_for_seed, OUTPUT_OFF, P2_COLS, RATE, WIDTH};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::Poseidon2Air;
use p3_symmetric::Permutation;

const DIGEST: usize = RATE;
const INPUT_OFF: usize = 0;
const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;
type P2Air = Poseidon2Air<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;
/// The hiding MMCS's salt, appended to every opened row before it is hashed.
pub const SALT_WORDS: usize = 8;
/// Extension limbs.
const L: usize = 4;

// ── the row ────────────────────────────────────────────────────────────────────────────────────────────────────────
/// 1 on a path row (public).
pub const MODE_OFF: usize = P2_COLS;
/// The words absorbed on this row (witness).
pub const ABS_OFF: usize = MODE_OFF + 1;
/// Which rate slots this row overwrote (public).
pub const OW_OFF: usize = ABS_OFF + RATE;
/// The running node climbing the path (witness).
pub const NODE_OFF: usize = OW_OFF + RATE;
/// The sibling at this level (witness).
pub const SIB_OFF: usize = NODE_OFF + DIGEST;
/// The position's bit at this level (public).
pub const BIT_OFF: usize = SIB_OFF + DIGEST;
/// 1 on a segment's last row, whose permutation output is the root (public).
pub const SEG_OFF: usize = BIT_OFF + 1;
/// 1 on a segment's first row, which starts the sponge from zero (public).
pub const START_OFF: usize = SEG_OFF + 1;
/// 1 while the table carries real work (public).
pub const LIVE_OFF: usize = START_OFF + 1;
/// Each slot's fold weight, an extension element in `L` limbs (public).
pub const W_OFF: usize = LIVE_OFF + 1;
/// The segment's running fold (witness, `L` limbs).
pub const ACC_OFF: usize = W_OFF + RATE * L;
/// The current group's running claim (witness, `L` limbs): `Σ γ^(shift + m) · fold_m` over the group's segments that
/// have ended at or before this row; it restarts from zero after each group's last row.
pub const CLAIM_OFF: usize = ACC_OFF + L;
/// The segment's round root, on the segment's last row (public).
pub const ROOT_OFF: usize = CLAIM_OFF + L;
/// The segment's combine coefficient `γ_g^(shift_g + m)`, on the segment's last row (public, `L` limbs).
pub const COEF_OFF: usize = ROOT_OFF + DIGEST;
/// 1 on a group's last row (public).
pub const GEND_OFF: usize = COEF_OFF + L;
/// The group's claim, on the group's last row (public, `L` limbs).
pub const GCLAIM_OFF: usize = GEND_OFF + 1;
/// Columns per row.
pub const ROW_COLS: usize = GCLAIM_OFF + L;

/// The public columns.
#[must_use]
pub fn public_column_ids() -> Vec<usize> {
    let mut v = vec![MODE_OFF];
    v.extend(OW_OFF..OW_OFF + RATE);
    v.extend([BIT_OFF, SEG_OFF, START_OFF, LIVE_OFF]);
    v.extend(W_OFF..W_OFF + RATE * L);
    v.extend(ROOT_OFF..ROW_COLS);
    v
}

/// One query opening: the opened row's words (base words, an extension row flattened to its coefficients), its salt,
/// and the siblings from the leaf up.
#[derive(Clone, Debug)]
pub struct QueryOpening {
    pub words: Vec<Fa4>,
    pub salt: [Fa4; SALT_WORDS],
    pub siblings: Vec<[Fa4; DIGEST]>,
}

/// One group's statement: what the verifier knows before it reads the table.
#[derive(Clone, Debug)]
pub struct GroupStatement {
    pub root: [Fa4; DIGEST],
    /// Words in each opened row (16 for a base round at fold 4, 64 for an extension round).
    pub row_words: usize,
    /// Path depth.
    pub depth: usize,
    /// The drawn positions, one per query, in proof order.
    pub positions: Vec<usize>,
    /// The fold weight of each opened word: `eq(i, r)` for base word `i`, `eq(⌊t/4⌋, r) · e_(t mod 4)` for flattened
    /// extension word `t`.
    pub weights: Vec<Ea4>,
    /// The round's combination challenge and its starting power `γ^shift` (`shift` = the round's OOD count).
    pub gamma: Ea4,
    pub gamma_shift: Ea4,
    /// `Σ_m γ^(shift + m) · fold_m`.
    pub claim: Ea4,
}

impl GroupStatement {
    fn absorb_rows(&self) -> usize {
        (self.row_words + SALT_WORDS).div_ceil(RATE)
    }
    fn seg_rows(&self) -> usize {
        self.absorb_rows() + self.depth
    }
    /// The table's height for this group alone.
    #[must_use]
    pub fn rows(&self) -> usize {
        table_rows(std::slice::from_ref(self))
    }
    pub fn work_rows(&self) -> usize {
        self.positions.len() * self.seg_rows()
    }
    /// A statement the table can lay: at least one query, one weight per opened word, a root path deep enough to
    /// carry every position's bits.
    fn well_formed(&self) -> bool {
        !self.positions.is_empty()
            && self.row_words > 0
            && self.weights.len() == self.row_words
            && self.depth > 0
            && self.depth < usize::BITS as usize
            && self.positions.iter().all(|&p| p >> self.depth == 0)
    }
}

/// A block's openings table: the segments of every group, back to back, padded to a power of two (at least 32 rows).
#[must_use]
pub fn table_rows(groups: &[GroupStatement]) -> usize {
    groups.iter().map(GroupStatement::work_rows).sum::<usize>().next_power_of_two().max(32)
}

/// Every public cell of the table for `groups`, as `f(row, column, value)` — the one walk both the prover's layout and
/// the verifier's evaluation read, so the two cannot describe different tables. Cells it does not name are zero.
fn walk_public(groups: &[GroupStatement], mut f: impl FnMut(usize, usize, Fa4)) {
    let mut slot = 0usize;
    for st in groups {
        let total = st.row_words + SALT_WORDS;
        let a = st.absorb_rows();
        let q = st.positions.len();
        let mut coef = st.gamma_shift;
        for (m, &pos) in st.positions.iter().enumerate() {
            for k in 0..st.seg_rows() {
                f(slot, LIVE_OFF, Fa4::ONE);
                if k == 0 {
                    f(slot, START_OFF, Fa4::ONE);
                }
                if k < a {
                    let base = k * RATE;
                    for c in 0..RATE.min(total - base) {
                        f(slot, OW_OFF + c, Fa4::ONE);
                        if base + c < st.row_words {
                            for (l, v) in limbs_of(st.weights[base + c]).into_iter().enumerate() {
                                f(slot, W_OFF + c * L + l, v);
                            }
                        }
                    }
                } else {
                    let level = k - a;
                    f(slot, MODE_OFF, Fa4::ONE);
                    if (pos >> level) & 1 == 1 {
                        f(slot, BIT_OFF, Fa4::ONE);
                    }
                    if k + 1 == st.seg_rows() {
                        f(slot, SEG_OFF, Fa4::ONE);
                        for (j, &v) in st.root.iter().enumerate() {
                            f(slot, ROOT_OFF + j, v);
                        }
                        for (l, v) in limbs_of(coef).into_iter().enumerate() {
                            f(slot, COEF_OFF + l, v);
                        }
                        if m + 1 == q {
                            f(slot, GEND_OFF, Fa4::ONE);
                            for (l, v) in limbs_of(st.claim).into_iter().enumerate() {
                                f(slot, GCLAIM_OFF + l, v);
                            }
                        }
                    }
                }
                slot += 1;
            }
            coef *= st.gamma;
        }
    }
}

/// The fold weights of a round: `eq(i, r)` for each of the `2^k` opened values, at `point` (the round's folding
/// randomness in the verifier's order), computed exactly as `Poly::eval_ext` weighs them; an extension row's flattened
/// word `t` takes `eq(⌊t/4⌋, r) · e_(t mod 4)`.
#[must_use]
pub fn fold_weights(point: &p3_multilinear_util::point::Point<Ea4>, extension: bool) -> Vec<Ea4> {
    let n = 1usize << point.num_variables();
    let eq: Vec<Ea4> = (0..n)
        .map(|i| {
            let mut unit = vec![Ea4::ZERO; n];
            unit[i] = Ea4::ONE;
            p3_multilinear_util::poly::Poly::new(unit).eval_ext::<Fa4>(point)
        })
        .collect();
    if !extension {
        return eq;
    }
    let mut out = Vec::with_capacity(n * L);
    for w in eq {
        for l in 0..L {
            let mut basis = [Fa4::ZERO; L];
            basis[l] = Fa4::ONE;
            out.push(w * <Ea4 as BasedVectorSpace<Fa4>>::from_basis_coefficients_slice(&basis).expect("a basis element"));
        }
    }
    out
}

fn limbs_of(e: Ea4) -> [Fa4; L] {
    let s = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&e);
    [s[0], s[1], s[2], s[3]]
}

/// The verifier's evaluation of every public column's multilinear extension at `r`, in [`public_column_ids`] order:
/// `Σ_row eq(row, r) · cell`, one pass over the table's public cells (no dense column is built).
#[must_use]
pub fn public_evals(groups: &[GroupStatement], r: &[Ea4]) -> Vec<Ea4> {
    let ids = public_column_ids();
    let mut at = [usize::MAX; ROW_COLS];
    for (i, &id) in ids.iter().enumerate() {
        at[id] = i;
    }
    let eq = crate::air_zerocheck::eq_z_hypercube(r);
    let mut out = vec![Ea4::ZERO; ids.len()];
    walk_public(groups, |row, col, v| out[at[col]] += eq[row] * Ea4::from(v));
    out
}

/// PROVER: lay ONE group's table. See [`build_table`].
#[must_use]
pub fn build_trace(seed: u64, st: &GroupStatement, openings: &[QueryOpening]) -> Option<Vec<Vec<Fa4>>> {
    build_table(seed, std::slice::from_ref(st), &[openings.to_vec()])
}

/// PROVER: lay the openings table for `groups` (any mix of rounds and carriers, back to back) from each group's
/// openings. `None` (fail-closed) when a statement is malformed, an opening is not of its group's shape, a path does
/// not reach its group's root, or a group's folds do not combine to its stated claim.
#[must_use]
pub fn build_table(seed: u64, groups: &[GroupStatement], openings: &[Vec<QueryOpening>]) -> Option<Vec<Vec<Fa4>>> {
    if groups.is_empty() || openings.len() != groups.len() || !groups.iter().all(GroupStatement::well_formed) {
        return None;
    }
    let perm = perm_for_seed(seed);
    let consts = constants_for_seed(seed);
    let n = table_rows(groups);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; n]; ROW_COLS];
    walk_public(groups, |row, col, v| cols[col][row] = v);
    let mut slot = 0usize;
    for (st, os) in groups.iter().zip(openings) {
        if os.len() != st.positions.len() {
            return None;
        }
        let mut claim = Ea4::ZERO;
        let mut coef = st.gamma_shift;
        for (m, o) in os.iter().enumerate() {
            if o.words.len() != st.row_words || o.siblings.len() != st.depth {
                return None;
            }
            let mut words = o.words.clone();
            words.extend_from_slice(&o.salt);
            let mut state = [KoalaBear::ZERO; WIDTH];
            let mut node = [KoalaBear::ZERO; DIGEST];
            let mut fold = Ea4::ZERO;
            let a = st.absorb_rows();
            for k in 0..st.seg_rows() {
                if k < a {
                    let base = k * RATE;
                    let take = RATE.min(words.len() - base);
                    if k == 0 {
                        state = [KoalaBear::ZERO; WIDTH];
                    }
                    for c in 0..take {
                        state[c] = words[base + c];
                        cols[ABS_OFF + c][slot] = words[base + c];
                        if base + c < st.row_words {
                            fold += st.weights[base + c] * Ea4::from(words[base + c]);
                        }
                    }
                } else {
                    let level = k - a;
                    let bit = (st.positions[m] >> level) & 1 == 1;
                    let sib = o.siblings[level];
                    let (l, r) = if bit { (sib, node) } else { (node, sib) };
                    state = [KoalaBear::ZERO; WIDTH];
                    state[..DIGEST].copy_from_slice(&l);
                    state[DIGEST..].copy_from_slice(&r);
                    for j in 0..DIGEST {
                        cols[NODE_OFF + j][slot] = node[j];
                        cols[SIB_OFF + j][slot] = sib[j];
                    }
                }
                for (l, v) in limbs_of(fold).into_iter().enumerate() {
                    cols[ACC_OFF + l][slot] = v;
                }
                let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &consts);
                for (col, v) in filled.iter().enumerate() {
                    cols[col][slot] = *v;
                }
                state = perm.permute(state);
                if k + 1 >= a {
                    node.copy_from_slice(&state[..DIGEST]);
                }
                if k + 1 == st.seg_rows() {
                    if node != st.root {
                        return None; // the path does not reach the group's root
                    }
                    claim += coef * fold;
                    coef *= st.gamma;
                }
                for (l, v) in limbs_of(claim).into_iter().enumerate() {
                    cols[CLAIM_OFF + l][slot] = v;
                }
                slot += 1;
            }
        }
        if claim != st.claim {
            return None; // the group's folds do not combine to the claim its statement names
        }
    }
    // ⛔ AN IDLE ROW IS A REAL PERMUTATION ROW (the block is not gated on `live`): its fold carries forward, its claim is
    // zero (the last group ended on the row before), every public cell is zero.
    let zero = [KoalaBear::ZERO; WIDTH];
    let filled: Vec<KoalaBear> = crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(zero, &consts).to_vec();
    let carry: Vec<Fa4> = (ACC_OFF..ACC_OFF + L).map(|c| cols[c][slot - 1]).collect();
    for t in slot..n {
        for (col, v) in filled.iter().enumerate() {
            cols[col][t] = *v;
        }
        for (i, c) in (ACC_OFF..ACC_OFF + L).enumerate() {
            cols[c][t] = carry[i];
        }
    }
    Some(cols)
}

/// The table's relation — the same for every statement: everything a statement names (roots, positions, weights,
/// coefficients, claims) is a public column checked by [`verify_table`]; these residuals tie the witness to it.
pub struct StirGroupConstraint {
    pub gamma_batch: Ea4,
    pub p2: crate::whole_chain::WholeChainMainConstraint,
}

impl AirConstraint for StirGroupConstraint {
    fn degree(&self, nvars: usize) -> usize {
        self.p2.degree(nvars)
    }
    /// The columns this gate reads on the NEXT row: every `nxt(…)` of [`Self::eval`] (the sponge's input, overwrite and
    /// absorb cells, the mode/live/start/segment flags, the climbing node, the fold, claim and coefficient limbs, the
    /// fold weights), UNIONED with what the forwarded Poseidon2 half declares — composed, never hand-listed for the half
    /// it forwards to (`sponge_chain_air`'s lesson). A read outside this set aborts the prove under the prover's asserts.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let mut v: Vec<usize> = (0..WIDTH).map(|j| INPUT_OFF + j).collect();
        v.extend(OW_OFF..OW_OFF + RATE);
        v.extend(ABS_OFF..ABS_OFF + RATE);
        v.extend([MODE_OFF, LIVE_OFF, START_OFF, SEG_OFF]);
        v.extend(NODE_OFF..NODE_OFF + DIGEST);
        v.extend(W_OFF..W_OFF + RATE * L);
        v.extend(ACC_OFF..ACC_OFF + L);
        v.extend(CLAIM_OFF..CLAIM_OFF + L);
        v.extend(COEF_OFF..COEF_OFF + L);
        v.extend(self.p2.shifted_cols()?);
        v.sort_unstable();
        v.dedup();
        Some(v)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = self.p2.eval(local, at, x);
        let g = self.gamma_batch;
        let push = |acc: &mut Ea4, r: Ea4| *acc = *acc * g + r;
        let one = Ea4::ONE;
        let mut is_first = one;
        let mut is_last = one;
        for &xk in x {
            is_first *= one - xk;
            is_last *= xk;
        }
        let is_trans = one - is_last;
        let ext = |f: &dyn Fn(usize) -> Ea4, off: usize| -> Ea4 {
            let mut e = Ea4::ZERO;
            for l in 0..L {
                let mut basis = [Fa4::ZERO; L];
                basis[l] = Fa4::ONE;
                e += f(off + l) * <Ea4 as BasedVectorSpace<Fa4>>::from_basis_coefficients_slice(&basis).expect("basis");
            }
            e
        };
        let cur = |c: usize| local[c];
        let nxt = |c: usize| at(c, &[]);

        let (md, lv, st) = (local[MODE_OFF], local[LIVE_OFF], local[START_OFF]);
        let (mdn, lvn, stn) = (nxt(MODE_OFF), nxt(LIVE_OFF), nxt(START_OFF));
        let seg = local[SEG_OFF];

        // ── 1. THE LEAF SPONGE (overwrite mode, from zero at every segment start) ─────────────────────────────────
        for j in 0..WIDTH {
            let cur_in = local[INPUT_OFF + j];
            let start = if j < RATE { cur_in - local[OW_OFF + j] * local[ABS_OFF + j] } else { cur_in };
            push(&mut acc, st * start);
            let next_in = nxt(INPUT_OFF + j);
            let cur_out = local[OUTPUT_OFF + j];
            let want = if j < RATE { nxt(OW_OFF + j) * nxt(ABS_OFF + j) + (one - nxt(OW_OFF + j)) * cur_out } else { cur_out };
            push(&mut acc, is_trans * lvn * (one - stn) * (one - mdn) * (next_in - want));
        }
        // ── 2. THE JOIN: a path row's node is the previous row's output (the leaf, then each parent) ─────────────────
        for j in 0..DIGEST {
            push(&mut acc, is_trans * lvn * mdn * (nxt(NODE_OFF + j) - local[OUTPUT_OFF + j]));
        }
        // ── 3. THE PATH, ordered by the PUBLIC bit, every segment reaching its group's PUBLIC root ───────────────────
        let b = local[BIT_OFF];
        for j in 0..DIGEST {
            let (node, sib) = (local[NODE_OFF + j], local[SIB_OFF + j]);
            push(&mut acc, md * (local[INPUT_OFF + j] - ((one - b) * node + b * sib)));
            push(&mut acc, md * (local[INPUT_OFF + DIGEST + j] - ((one - b) * sib + b * node)));
            push(&mut acc, seg * (local[OUTPUT_OFF + j] - local[ROOT_OFF + j]));
        }
        // ── 4. THE FOLD: Σ weight · word over the segment's absorbed words, carried through its path rows ────────────
        let w_dot = |f: &dyn Fn(usize) -> Ea4| -> Ea4 {
            let mut s = Ea4::ZERO;
            for c in 0..RATE {
                s += ext(f, W_OFF + c * L) * f(ABS_OFF + c);
            }
            s
        };
        let acc_cur = ext(&cur, ACC_OFF);
        let acc_nxt = ext(&nxt, ACC_OFF);
        push(&mut acc, st * (acc_cur - w_dot(&cur)));
        push(&mut acc, is_trans * (one - stn) * (acc_nxt - acc_cur - w_dot(&nxt)));
        // ── 5. THE COMBINE: on each segment's last row the group's claim takes its PUBLIC coefficient γ^(shift+m) times
        //       the segment's fold; on the group's last row the claim must equal the group's PUBLIC claim, and the next
        //       row starts the next group from zero ────────────────────────────────────────────────────────────────
        let claim_cur = ext(&cur, CLAIM_OFF);
        let claim_nxt = ext(&nxt, CLAIM_OFF);
        let (segn, gend) = (nxt(SEG_OFF), local[GEND_OFF]);
        push(&mut acc, is_first * (claim_cur - seg * ext(&cur, COEF_OFF) * acc_cur));
        push(&mut acc, is_trans * (claim_nxt - (one - gend) * claim_cur - segn * ext(&nxt, COEF_OFF) * acc_nxt));
        push(&mut acc, gend * (claim_cur - ext(&cur, GCLAIM_OFF)));
        // ── 6. IDLE ROWS carry nothing new (their public columns are zero; the running values carry by 4–5) ─────────
        push(&mut acc, (one - lv) * md);
        acc
    }
}

/// The table's constraint (one for every statement; the statement lives in the public columns).
#[must_use]
pub fn make_constraint(seed: u64) -> impl Fn(Ea4) -> StirGroupConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    let air = P2Air::new(constants_for_seed(seed));
    let layout = AirLayout { preprocessed_width: 0, main_width: P2_COLS, num_public_values: 0, num_periodic_columns: 0, ..Default::default() };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |g: Ea4| StirGroupConstraint {
        gamma_batch: g,
        p2: crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: ROW_COLS, preproc_w: 0, npub: 0 },
            ROW_COLS,
            0,
            0,
            Vec::new(),
            g,
            8,
            false,
        ),
    }
}

/// The statement's public bind, what the light proof's transcript absorbs before any challenge: a tag, the group count,
/// the table's height and a Poseidon2 digest of the WHOLE statement — every group's shape, root, positions, weights,
/// γ, shift and claim, each group length-prefixed so the encoding is injective (BORROWED: strong Fiat–Shamir, the full
/// statement in the transcript). Constant size whatever the table holds.
#[must_use]
pub fn table_bind(seed: u64, groups: &[GroupStatement]) -> Vec<Fa4> {
    let perm = perm_for_seed(seed);
    let mut words: Vec<Fa4> = Vec::new();
    for st in groups {
        words.extend([st.row_words, st.depth, st.positions.len()].map(|v| Fa4::from_u64(v as u64)));
        words.extend_from_slice(&st.root);
        for e in [st.gamma, st.gamma_shift, st.claim] {
            words.extend_from_slice(&limbs_of(e));
        }
        words.extend(st.positions.iter().map(|&p| Fa4::from_u64(p as u64)));
        for &w in &st.weights {
            words.extend_from_slice(&limbs_of(w));
        }
    }
    let mut state = [KoalaBear::ZERO; WIDTH];
    state[RATE] = Fa4::from_u64(0x5354_4754); // domain: the C4 openings table
    for chunk in words.chunks(RATE) {
        state[..chunk.len()].copy_from_slice(chunk);
        state = perm.permute(state);
    }
    let mut b = vec![Fa4::from_u64(0x5354_4754), Fa4::from_u64(groups.len() as u64), Fa4::from_u64(table_rows(groups) as u64)];
    b.extend_from_slice(&state[..DIGEST]);
    b
}

/// ONE group's bind (the table of that group alone).
#[must_use]
pub fn statement_bind(seed: u64, st: &GroupStatement) -> Vec<Fa4> {
    table_bind(seed, std::slice::from_ref(st))
}

/// PROVE an openings table for `groups` on the BOUND engine (`whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes`,
/// DB-452): the table is committed before any challenge, and the zerocheck's opened row and next-row values are claims
/// the engine's WHIR opening proves against that commitment.
///
/// ⛔ NEVER THE DIRECT ENGINE (`prove_air_direct_light_decider_selfcontained_bytes`). MEASURED 2026-11-13 while building
/// this table: the direct engine does not bind its zerocheck's opened row to the trace (DB-452 link 78:
/// `forge_direct_light_decider_for_tests` accepted, 28,012 B), and every check [`verify_table`] makes of the public
/// columns reads that row — so on the direct engine a lying prover sends the statement's own column values as its
/// opened row and proves any claim. The trace here is not hidden, and needs no hiding: it holds query openings and
/// siblings a full carrier sent in the clear.
#[must_use]
pub fn prove_table(seed: u64, groups: &[GroupStatement], openings: &[Vec<QueryOpening>]) -> Option<Vec<u8>> {
    let cols = build_table(seed, groups, openings)?;
    let mk = make_constraint(seed);
    crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes(vec![cols], move |_, g| mk(g), &table_bind(seed, groups))
}

/// VERIFY an openings table: the bound light proof against the table's relation and the statement's bind, then every
/// public column's evaluation at the zerocheck point against the statement's own cells ([`public_evals`]) — the opened
/// row a claim the proof's own opening binds to the committed table. Fail-closed.
///
/// NEW-DOOR CHECKLIST (§9.6), as a peer meets a block's table: (1) proof of work — not this door's (the block's header
/// door); (2) the table's own light proof, verified here, plus the public-column check; (3) value — none moves here: the
/// table proves only that the claims a core was verified against are the folds of authenticated openings, so a forged
/// table would let a false core through, which (2) refuses; (4) replay — the statement is the peer's own record of the
/// cores it verified, so a replayed table proves nothing about another block's cores; (5) work — one light verify plus
/// one walk over the table's public cells, `O(rows)`, rows bounded by the cores' own WHIR configuration; (6) parity —
/// the door it replaces is WHIR's own query phase (`verify_stir_challenges`: Merkle-open each query, fold it, combine);
/// each of its checks is a residual here (sponge, path, root, fold, combine) and each value it reads from its own
/// transcript (root, positions, folding point, γ, claim) is a public column; (7) scale — rows grow with the payments
/// the block carries, never with the bonded set or height; (8) AI RESISTANT: (a) a proof every node checks.
#[must_use]
pub fn verify_table(seed: u64, groups: &[GroupStatement], proof: &[u8]) -> bool {
    if groups.is_empty() || !groups.iter().all(GroupStatement::well_formed) {
        return false;
    }
    let nvars = table_rows(groups).trailing_zeros() as usize;
    let mk = make_constraint(seed);
    if !crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes(proof, move |_, g| mk(g), &table_bind(seed, groups), &[(nvars, ROW_COLS)]) {
        return false;
    }
    let Ok(b) = postcard::from_bytes::<crate::whir_rec_block::AirBatchBusBundle>(proof) else { return false };
    let [zc] = b.zcs.as_slice() else { return false };
    if zc.r.len() != nvars || zc.opened.len() != ROW_COLS {
        return false;
    }
    public_column_ids().into_iter().zip(public_evals(groups, &zc.r)).all(|(id, e)| e == zc.opened[id])
}

/// PROVE one group's table.
#[must_use]
pub fn prove_group(seed: u64, st: &GroupStatement, openings: &[QueryOpening]) -> Option<Vec<u8>> {
    prove_table(seed, std::slice::from_ref(st), &[openings.to_vec()])
}

/// VERIFY one group's table.
#[must_use]
pub fn verify_group(seed: u64, st: &GroupStatement, proof: &[u8]) -> bool {
    verify_table(seed, std::slice::from_ref(st), proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opening_auth_air::SEED;
    use p3_field::Field;

    /// A real member carrier's openings, grouped, with the positions its verifier drew.
    fn real_groups() -> Vec<(crate::c4_openings::GroupOpenings, Vec<usize>)> {
        use crate::member_path_gate::{member_path_gate, prove_member_path_carrier, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(100 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| (0x5A3C_96E1u64 >> (i % 32)) & 1 == 1).collect();
        let (bytes, t) = (prove_member_path_carrier(d(1), &siblings, &dirs, d(2), d(3), d(4))).expect("the member path proves");
        let shape = (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS);
        let drawn = crate::committed_air::drawn_queries_of_blinded_chained_carrier(&bytes, member_path_gate(&t), &t.bind(), shape).expect("verifies");
        let (_, groups) = crate::c4_openings::chained_carrier_openings(&bytes, member_path_gate(&t), &t.bind(), shape).expect("extracts");
        groups.into_iter().zip(drawn).collect()
    }

    fn statement_of(g: &crate::c4_openings::GroupOpenings, positions: &[usize], k: usize, extension: bool, seed_pt: u64) -> (GroupStatement, Vec<QueryOpening>) {
        let pt: Vec<Ea4> = (0..k).map(|i| Ea4::from(Fa4::from_u64(seed_pt + 7 * i as u64 + 3)) + Ea4::from_basis_coefficients_slice(&[Fa4::ZERO, Fa4::from_u64(i as u64 + 11), Fa4::ZERO, Fa4::ZERO]).unwrap()).collect();
        let weights = fold_weights(&p3_multilinear_util::point::Point::new(pt), extension);
        let row_words = weights.len();
        let openings: Vec<QueryOpening> = g
            .openings
            .iter()
            .map(|o| {
                let (words, salt) = o.values.split_at(o.values.len() - SALT_WORDS);
                QueryOpening { words: words.to_vec(), salt: salt.try_into().expect("8"), siblings: o.path.iter().map(|p| p.sibling).collect() }
            })
            .collect();
        let gamma = Ea4::from(Fa4::from_u64(0x6A3)) + Ea4::from_basis_coefficients_slice(&[Fa4::ZERO, Fa4::ZERO, Fa4::from_u64(5), Fa4::ZERO]).unwrap();
        let gamma_shift = gamma * gamma;
        let mut claim = Ea4::ZERO;
        let mut p = gamma_shift;
        for o in &openings {
            let f: Ea4 = o.words.iter().zip(&weights).map(|(&v, &w)| w * Ea4::from(v)).sum();
            claim += p * f;
            p *= gamma;
        }
        let st = GroupStatement { root: g.root, row_words, depth: g.openings[0].path.len(), positions: positions.to_vec(), weights, gamma, gamma_shift, claim };
        (st, openings)
    }

    /// ⭐ C4 V4+V5 AGAINST THE VERIFIER'S OWN NUMBERS: every query group of a REAL member carrier, stated with the WHIR
    /// verifier's own record — its root, the positions it drew, its folding point, each query's weight and the group's
    /// claim (`StirGroupRecord`) — proves and verifies as one table. This is what ties the table's fold weights and γ
    /// combine to `Poly::eval_ext` and `combine_evals` exactly as WHIR runs them; a claim moved by one is refused.
    #[test]
    fn c4_every_group_of_a_real_carrier_proves_against_the_verifiers_own_claims() {
        use crate::member_path_gate::{member_path_gate, prove_member_path_carrier, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(300 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| (0x1F3C_96A5u64 >> (i % 32)) & 1 == 1).collect();
        let (bytes, t) = (prove_member_path_carrier(d(5), &siblings, &dirs, d(6), d(7), d(8))).expect("the member path proves");
        let shape = (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS);
        let recs = crate::committed_air::stir_groups_of_blinded_chained_carrier(&bytes, member_path_gate(&t), &t.bind(), shape).expect("verifies");
        let (_, groups) = crate::c4_openings::chained_carrier_openings(&bytes, member_path_gate(&t), &t.bind(), shape).expect("extracts");
        assert_eq!(recs.len(), groups.len(), "CALIBRATION: one record per query group");
        for (gi, (rec, g)) in recs.iter().zip(&groups).enumerate() {
            let point = p3_multilinear_util::point::Point::new(rec.point.clone());
            let weights = fold_weights(&point, rec.extension);
            let openings: Vec<QueryOpening> = g
                .openings
                .iter()
                .map(|o| {
                    let (words, salt) = o.values.split_at(o.values.len() - SALT_WORDS);
                    QueryOpening { words: words.to_vec(), salt: salt.try_into().expect("8"), siblings: o.path.iter().map(|p| p.sibling).collect() }
                })
                .collect();
            // native control: the table's weights reproduce the verifier's own folds
            for (j, o) in openings.iter().enumerate() {
                let f: Ea4 = o.words.iter().zip(&weights).fold(Ea4::ZERO, |a, (&v, &w)| a + w * Ea4::from(v));
                assert_eq!(f, rec.folds[j], "⛔ group {gi} query {j}: the fold weights are not WHIR's eval_ext");
            }
            let gamma_shift = rec.coeffs[0];
            let gamma = if rec.coeffs.len() > 1 { rec.coeffs[1] * rec.coeffs[0].inverse() } else { Ea4::ONE };
            let st = GroupStatement {
                root: g.root,
                row_words: weights.len(),
                depth: g.openings[0].path.len(),
                positions: rec.indices.clone(),
                weights,
                gamma,
                gamma_shift,
                claim: rec.claim,
            };
            let t0 = std::time::Instant::now();
            let proof = prove_group(SEED, &st, &openings).expect("⛔ a real group did not prove against the verifier's claim");
            assert!(verify_group(SEED, &st, &proof), "⛔ group {gi}: refused against the verifier's own claim");
            eprintln!("[c4-v45-real] group {gi} ({}): {} queries, {} rows, {} ms, {} B", if rec.extension { "extension" } else { "base" }, st.positions.len(), st.rows(), t0.elapsed().as_millis(), proof.len());
            let mut bad = st.clone();
            bad.claim += Ea4::ONE;
            assert!(!verify_group(SEED, &bad, &proof), "⛔ group {gi}: a claim moved by one verified");
        }
    }

    /// ⭐⭐ C4 STAGE A, ONE CARRIER END TO END: the peer receives the carrier's CORE (no query openings) and one claim per
    /// group; it verifies the core with the unchanged WHIR verifier taking those claims (`verify_blinded_chained_core`),
    /// and its OWN record of that verification is the statement each group table must prove; the producer proves the
    /// tables from the openings it holds; the peer verifies them. A moved claim (a round group's or the final group's), a
    /// missing claim, and a table proved for another group are each refused. Prints the core's bytes against the carrier's.
    #[test]
    fn c4_stage_a_a_peer_accepts_a_real_carrier_from_its_core_and_the_group_tables_alone() {
        use crate::member_path_gate::{member_path_gate, prove_member_path_carrier, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(500 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| (0x2B3C_9651u64 >> (i % 32)) & 1 == 1).collect();
        let (bytes, t) = (prove_member_path_carrier(d(9), &siblings, &dirs, d(10), d(11), d(12))).expect("the member path proves");
        let shape = (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS);
        // the producer: the full carrier's groups, its claims, its openings
        let full = crate::committed_air::stir_groups_of_blinded_chained_carrier(&bytes, member_path_gate(&t), &t.bind(), shape).expect("verifies");
        let claims: Vec<Ea4> = full.iter().map(|r| r.claim).collect();
        let (_, groups) = crate::c4_openings::chained_carrier_openings(&bytes, member_path_gate(&t), &t.bind(), shape).expect("extracts");
        // the peer: the core and the claims
        let core = crate::committed_air::core_of_chained_carrier(&bytes).expect("a core");
        let seen = crate::committed_air::verify_blinded_chained_core(&core, member_path_gate(&t), &t.bind(), shape, &claims)
            .expect("⛔ the peer refused an honest core against its honest claims");
        eprintln!("[c4-stage-a] carrier {} B -> core {} B + {} group claims ({} B)", bytes.len(), core.len(), claims.len(), claims.len() * 16);
        assert_eq!(seen.len(), full.len(), "CALIBRATION: the peer sees every group");
        for (a, b) in seen.iter().zip(&full) {
            assert_eq!((a.indices.clone(), a.point.clone(), a.coeffs.clone(), a.extension, a.claim), (b.indices.clone(), b.point.clone(), b.coeffs.clone(), b.extension, b.claim), "⛔ the peer's view of a group is not the full verifier's");
        }
        // the producer proves each group to the PEER's statement; the peer verifies
        let mut tables = Vec::new();
        for (gi, (rec, g)) in seen.iter().zip(&groups).enumerate() {
            let weights = fold_weights(&p3_multilinear_util::point::Point::new(rec.point.clone()), rec.extension);
            let openings: Vec<QueryOpening> = g
                .openings
                .iter()
                .map(|o| {
                    let (words, salt) = o.values.split_at(o.values.len() - SALT_WORDS);
                    QueryOpening { words: words.to_vec(), salt: salt.try_into().expect("8"), siblings: o.path.iter().map(|p| p.sibling).collect() }
                })
                .collect();
            let gamma = if rec.coeffs.len() > 1 { rec.coeffs[1] * rec.coeffs[0].inverse() } else { Ea4::ONE };
            let root = *rec.root.roots().first().expect("one root");
            let st = GroupStatement { root, row_words: weights.len(), depth: g.openings[0].path.len(), positions: rec.indices.clone(), weights, gamma, gamma_shift: rec.coeffs[0], claim: rec.claim };
            let p = prove_group(SEED, &st, &openings).expect("⛔ the producer could not prove a group to the peer's statement");
            assert!(verify_group(SEED, &st, &p), "⛔ group {gi}: the peer refused an honest group table");
            tables.push((st, p));
        }
        // the lies
        for g in 0..claims.len() {
            let mut bad = claims.clone();
            bad[g] += Ea4::ONE;
            assert!(crate::committed_air::verify_blinded_chained_core(&core, member_path_gate(&t), &t.bind(), shape, &bad).is_none(), "⛔ a core verified with group {g}'s claim moved");
        }
        assert!(crate::committed_air::verify_blinded_chained_core(&core, member_path_gate(&t), &t.bind(), shape, &claims[..claims.len() - 1]).is_none(), "⛔ a core verified with a claim missing");
        if tables.len() >= 2 {
            assert!(!verify_group(SEED, &tables[1].0, &tables[0].1), "⛔ a group table verified for another group's statement");
        }
    }

    /// The peer's side of one carrier: (its core, its claims, the peer's own statements from verifying the core) and the
    /// producer's openings per group.
    fn peer_statements_of_carrier(salt: u64) -> (Vec<GroupStatement>, Vec<Vec<QueryOpening>>, usize, usize) {
        use crate::member_path_gate::{member_path_gate, prove_member_path_carrier, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(salt + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| ((salt ^ 0x3C5A_96E1) >> (i % 32)) & 1 == 1).collect();
        let (bytes, t) = (prove_member_path_carrier(d(salt + 1), &siblings, &dirs, d(salt + 2), d(salt + 3), d(salt + 4))).expect("the member path proves");
        let shape = (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS);
        let full = crate::committed_air::stir_groups_of_blinded_chained_carrier(&bytes, member_path_gate(&t), &t.bind(), shape).expect("verifies");
        let claims: Vec<Ea4> = full.iter().map(|r| r.claim).collect();
        let (_, groups) = crate::c4_openings::chained_carrier_openings(&bytes, member_path_gate(&t), &t.bind(), shape).expect("extracts");
        let core = crate::committed_air::core_of_chained_carrier(&bytes).expect("a core");
        let seen = crate::committed_air::verify_blinded_chained_core(&core, member_path_gate(&t), &t.bind(), shape, &claims).expect("the peer accepts the core");
        let mut sts = Vec::new();
        let mut ops = Vec::new();
        for (rec, g) in seen.iter().zip(&groups) {
            let weights = fold_weights(&p3_multilinear_util::point::Point::new(rec.point.clone()), rec.extension);
            let gamma = if rec.coeffs.len() > 1 { rec.coeffs[1] * rec.coeffs[0].inverse() } else { Ea4::ONE };
            let root = *rec.root.roots().first().expect("one root");
            sts.push(GroupStatement { root, row_words: weights.len(), depth: g.openings[0].path.len(), positions: rec.indices.clone(), weights, gamma, gamma_shift: rec.coeffs[0], claim: rec.claim });
            ops.push(
                g.openings
                    .iter()
                    .map(|o| {
                        let (words, salt) = o.values.split_at(o.values.len() - SALT_WORDS);
                        QueryOpening { words: words.to_vec(), salt: salt.try_into().expect("8"), siblings: o.path.iter().map(|p| p.sibling).collect() }
                    })
                    .collect(),
            );
        }
        (sts, ops, bytes.len(), core.len())
    }

    /// ⭐⭐ C4 STAGE A, ONE TABLE PER BLOCK: the query groups of SEVERAL real carriers — base and extension rounds, different
    /// roots, depths and row widths — prove as ONE openings table against the peer's own statements, each group's
    /// claim checked exactly at its own last row. Refused: a moved claim in any one group, two groups' claims swapped,
    /// a group dropped, a group from another carrier substituted, the groups reordered, and a LYING PROVER whose table
    /// moves one group's running claim (the honest bytes, one witness cell moved after laying). Prints the block's
    /// bytes: the cores, the claims and the one table, against the carriers.
    #[test]
    fn c4_stage_a_one_openings_table_proves_every_group_of_a_block_and_every_lie_is_refused() {
        let carriers = 3usize;
        let mut groups = Vec::new();
        let mut openings = Vec::new();
        let (mut full_b, mut core_b) = (0usize, 0usize);
        for c in 0..carriers {
            let (s, o, fb, cb) = peer_statements_of_carrier(700 + 97 * c as u64);
            groups.extend(s);
            openings.extend(o);
            full_b += fb;
            core_b += cb;
        }
        let t0 = std::time::Instant::now();
        let proof = prove_table(SEED, &groups, &openings).expect("⛔ an honest block table did not prove");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_table(SEED, &groups, &proof), "⛔ the peer refused an honest block table");
        let verify_ms = t1.elapsed().as_millis();
        let claims_b = groups.len() * 16;
        eprintln!(
            "[c4-table] {carriers} carriers, {} groups, {} rows: prove {prove_ms} ms, verify {verify_ms} ms, table {} B | carriers {full_b} B -> cores {core_b} B + claims {claims_b} B + table {} B = {} B ({:.1} KB per carrier)",
            groups.len(),
            table_rows(&groups),
            proof.len(),
            proof.len(),
            core_b + claims_b + proof.len(),
            (core_b + claims_b + proof.len()) as f64 / carriers as f64 / 1024.0
        );
        for g in 0..groups.len() {
            let mut bad = groups.clone();
            bad[g].claim += Ea4::ONE;
            assert!(!verify_table(SEED, &bad, &proof), "⛔ a table verified with group {g}'s claim moved");
            assert!(build_table(SEED, &bad, &openings).is_none(), "⛔ the builder laid group {g}'s moved claim");
        }
        let mut bad = groups.clone();
        let (c0, c1) = (bad[0].claim, bad[1].claim);
        bad[0].claim = c1;
        bad[1].claim = c0;
        assert!(!verify_table(SEED, &bad, &proof), "⛔ a table verified with two groups' claims swapped");
        let mut bad = groups.clone();
        bad.pop();
        assert!(!verify_table(SEED, &bad, &proof), "⛔ a table verified with a group dropped");
        let mut bad = groups.clone();
        bad[0] = peer_statements_of_carrier(9_001).0.remove(0);
        assert!(!verify_table(SEED, &bad, &proof), "⛔ a table verified with another carrier's group substituted");
        let mut bad = groups.clone();
        bad.swap(0, 3);
        assert!(!verify_table(SEED, &bad, &proof), "⛔ a table verified with the groups reordered");
        // the LYING PROVER: an honest block table with one group's running claim moved on its last row
        let mut cols = build_table(SEED, &groups, &openings).expect("honest");
        let gend_row = (0..cols[GEND_OFF].len()).find(|&r| cols[GEND_OFF][r] == Fa4::ONE).expect("a group end");
        cols[CLAIM_OFF][gend_row] += Fa4::ONE;
        let mk = make_constraint(SEED);
        let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes(vec![cols], move |_, g| mk(g), &table_bind(SEED, &groups))
        }))
        .ok()
        .flatten();
        assert!(forged.map_or(true, |p| !verify_table(SEED, &groups, &p)), "⛔ a lying prover's moved group claim verified");
        // the LYING PROVER of the class the direct engine let through (DB-452): the honest table committed, zero
        // zerocheck rounds, and an opened row SOLVED to satisfy the gate at the rounds' point — the row every public
        // column is read from. CONTROL first: the same forger with no lie verifies, so its refusal is the binding.
        let honest_cols = build_table(SEED, &groups, &openings).expect("honest");
        let mk = make_constraint(SEED);
        let control = crate::whir_rec_block::forge_batch_opened_light_decider_for_tests(vec![honest_cols.clone()], move |_, g| mk(g), Vec::new(), &table_bind(SEED, &groups), false)
            .expect("CALIBRATION: the forger's honest path proves");
        assert!(verify_table(SEED, &groups, &control), "CALIBRATION: the forger's honest path must verify, or its refusal proves nothing");
        let mk = make_constraint(SEED);
        let solved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::whir_rec_block::forge_batch_opened_light_decider_for_tests(vec![honest_cols], move |_, g| mk(g), Vec::new(), &table_bind(SEED, &groups), true)
        }))
        .ok()
        .flatten();
        assert!(solved.map_or(true, |p| !verify_table(SEED, &groups, &p)), "⛔ a table whose opened row the prover SOLVED verified (the DB-452 class)");
    }

    /// ⭐ C4 V4+V5 PIN: each query group of a REAL member carrier proves as one table — leaves, paths, folds and the γ
    /// combination — and verifies with its public columns; a lying prover is refused at every part: a moved word, a moved
    /// sibling, a moved position bit, a moved weight, a wrong claim, a foreign root, a dropped query.
    #[test]
    fn c4_a_real_query_group_proves_its_openings_folds_and_claim_and_every_lie_is_refused() {
        let groups = real_groups();
        for (gi, (g, positions)) in groups.iter().enumerate() {
            let row = g.openings[0].values.len() - SALT_WORDS;
            let (extension, k) = if row == 16 { (false, 4) } else { (true, (row / L).trailing_zeros() as usize) };
            let (st, openings) = statement_of(g, positions, k, extension, 0x900 + gi as u64);
            // native control: the fold weights reproduce Poly::eval_ext on a real opened row
            let t0 = std::time::Instant::now();
            let proof = prove_group(SEED, &st, &openings).expect("⛔ an honest group did not prove");
            let ms = t0.elapsed().as_millis();
            assert!(verify_group(SEED, &st, &proof), "⛔ group {gi}: an honest group proof was refused");
            eprintln!("[c4-v45] group {gi}: {} queries, {} rows ({} of work), {ms} ms, {} B", st.positions.len(), st.rows(), st.positions.len() * st.seg_rows(), proof.len());
            // a wrong claim: the honest prover refuses to lay it, and the honest proof does not verify against it
            let mut bad = st.clone();
            bad.claim += Ea4::ONE;
            assert!(build_trace(SEED, &bad, &openings).is_none(), "⛔ the builder laid a claim the folds do not make");
            assert!(!verify_group(SEED, &bad, &proof), "⛔ a proof verified against a moved claim");
            // a foreign root
            let mut bad = st.clone();
            bad.root[0] += Fa4::ONE;
            assert!(!verify_group(SEED, &bad, &proof), "⛔ a proof verified against a foreign root");
            // a moved position (public bit column) and a moved weight (public weight column)
            let mut bad = st.clone();
            bad.positions[0] ^= 1;
            assert!(!verify_group(SEED, &bad, &proof), "⛔ a proof verified at a moved position");
            let mut bad = st.clone();
            bad.weights[0] += Ea4::ONE;
            assert!(!verify_group(SEED, &bad, &proof), "⛔ a proof verified under a moved fold weight");
            // the LYING PROVER: an honest table with one absorbed word, one sibling, or one public bit moved after laying
            for (what, col, row) in [("absorbed word", ABS_OFF, 0usize), ("sibling", SIB_OFF, st.absorb_rows()), ("public bit", BIT_OFF, st.absorb_rows())] {
                let mut cols = build_trace(SEED, &st, &openings).expect("honest");
                cols[col][row] += Fa4::ONE;
                let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mk = make_constraint(SEED);
                    crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes(vec![cols], move |_, g| mk(g), &statement_bind(SEED, &st))
                }))
                .ok()
                .flatten();
                assert!(forged.map_or(true, |p| !verify_group(SEED, &st, &p)), "⛔ group {gi}: a lying prover's moved {what} verified");
            }
            // a dropped query: the statement with one position fewer is not what the table proves
            let mut bad = st.clone();
            bad.positions.pop();
            assert!(!verify_group(SEED, &bad, &proof), "⛔ a proof verified for a statement with a query dropped");
        }
    }
}

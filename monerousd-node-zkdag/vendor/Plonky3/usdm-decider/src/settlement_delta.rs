// Copyright (c) 2026 MonerousD contributors. SPDX-License-Identifier: Apache-2.0

//! §BA/§BB — THE BOUND NOTE-TRANSITION AGGREGATE.
//!
//! ⛔⛔⛔ THE HOLE THIS EXISTS TO CLOSE. `Node::graft_admitted_notes` is a DENY-list: a note is
//! received unless some RESOLVED transaction refuses it. Under the constant-256 cover a peer holds
//! almost none of a block's bodies, so a note whose transaction the peer never pooled is judged by
//! nothing and applied on the producer's word. Measured live: `[§BA] peer RECORDED it=true · peer holds
//! it UNSPENT=true`, and the mirror `[§BB] peer root moved=true` for a burn.
//!
//! §BO traced four local closes and refuted every one. They fail for a single reason: **the peer has no
//! O(1) evidence about notes whose bodies it does not hold.** The nullifier transition solved the same
//! problem with a recursive carrier; the note transition has none.
//!
//! ⭐ WHAT THIS IS. One proof over the block's DELTA. Per spent note it carries a BOUND recursion step
//! — `cf == eq(z,r) · C_tuple(opened)` where `C_tuple` is the spend gate **built from that row's own
//! public cells** — plus a Poseidon2 chain over those cells ending at a single public `rows_digest`.
//! The block publishes the tuple list beside the aggregate; a peer recomputes `rows_digest`, verifies
//! once, and then checks every `output_notes` chunk and every `del_set` cm against that list before
//! receiving anything.
//!
//! ⛔ WHY IT COULD NOT BE BUILT ON `settlement_aggregate_from_bundles`. That aggregate verifies each
//! carrier's zerocheck ALGEBRA and never evaluates the spend gate at all — §BD/§BD-2: those constraints
//! are HOMOGENEOUS, so an aggregate over ZERO ROWS with no inner carrier proves and verifies. An
//! aggregate that certifies nothing cannot certify a delta.
//!
//! ⭐ WHY IT IS REACHABLE EVEN THOUGH THE WELD IS NOT A FIXPOINT. §BU-1 measured that a bound step's
//! width is about four times its inner's, so the weld cannot be ITERATED (that is §BD-3's blocker).
//! This aggregate is ONE level over `n` carriers — never a step standing on a step — so the growth
//! factor is paid once and the fixpoint question does not arise here.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::committed_air::{committed_schedule_lens, committed_schedule_params, EXT_LIMBS};
use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::DIGEST_LANES;
use crate::recursion_bound::{BoundLayout, BoundStepConstraint};
use crate::sponge_chain_air::SpongeChainConstraint;
use crate::transcript_bind_air::{plan, CrossTieSpec};
use p3_field::PrimeCharacteristicRing;

/// The digests a spend's public bind publishes, in the order `validity_public_bind_with_commit` writes them:
/// `out0_cm`, `out1_cm`, `nullifier`, `leaf_commit`, then (DB-351, 2026-09-28) the CLUE DIGEST `D` — the payment's
/// discovery data, hashed by the wallet and recomputed by every door — and three ZERO digests, the stated padding:
/// `chain_stride_is_exact` needs a power-of-two duplexing count per row (5 digests = 40 words would be refused at
/// layout time), so the bind and the tuple both close at 8 digests. A peer publishes the five real digests per slot
/// and pads the same way; the zero digests are never on the wire. The root is NOT among them — with the membership
/// cross-bind present it constrains nothing and is deliberately out of the bind. Cons, quantified: the chain table
/// spends 8 duplexings per row (was 4); +32 B published per slot per block (D); the aggregate's size moves by the
/// log-height term only.
pub const DIGESTS_PER_TUPLE: usize = 8;

/// One row's public tuple, in FIELD ELEMENTS. 64 values, and `sponge_chain_air::RATE` is 8, so the
/// chain spends eight duplexings per row — ⛔ NOT a Horner fold at a fixed point, which §BK-4 measured
/// forgeable in two lines.
pub const DELTA_TUPLE_VALS: usize = DIGESTS_PER_TUPLE * DIGEST_LANES;

/// The minimum height of the chain table, so a one-row delta still has a power-of-two trace.
const CHAIN_MIN_ROWS: usize = 32;

/// ⛔⛔⛔ THE BLOCK'S SLOT COUNT — A PROTOCOL CONSTANT, NEVER A FUNCTION OF HOW MANY SPENDS WERE REAL.
///
/// This MUST equal the node's `cover::BLOCK_FIXED_TX_COUNT`, and `the_decider_and_the_node_agree_on_the_block_slot_count`
/// in the node crate holds the two together.
///
/// ⭐ WHY IT IS A CONSTANT AND NOT `n.next_power_of_two()`. MEASURED: the same aggregate is 443,723 B
/// at 16 rows and 446,551 B at 256 — the log-height term. Sizing the table from the real carrier count
/// would therefore make the proof's SIZE a readout of how busy the block was, which is precisely the
/// Pillar-1 break `cover.rs` names ("an observer could then count real outputs per block"). Padding the
/// carriers is not enough; the SHAPE has to be padded, and it has to be padded to a number nobody
/// derives from the data.
pub const DELTA_FIXED_SLOTS: usize = 256;

/// The floor a TEST may use instead of [`DELTA_FIXED_SLOTS`] — the committed prover's folding floor
/// (`COMMITTED_FOLDING = 4`), so a small fixture still commits a legal shape. Production passes
/// `DELTA_FIXED_SLOTS`; anything else is a fixture, and the slot count is an explicit argument
/// precisely so that choice is visible at the call site rather than inferred from the data.
pub const DELTA_MIN_SLOTS: usize = 16;

/// Where the STEP table's columns live. `bound` is the same layout every carrier of a given shape
/// produces; `n` is how many of the table's rows are REAL (the rest replicate the last real row, which
/// satisfies the same row-local equation and is tied to nothing).
#[derive(Clone, Copy, Debug)]
pub struct DeltaLayout {
    pub bound: BoundLayout,
    pub n: usize,
    /// log2 of the rows ONE carrier's transcript walk occupies in the shared sponge table.
    pub seg_log: usize,
    /// The block's SLOT COUNT — the padded row count, a protocol constant. ⛔ Never derived from `n`:
    /// see [`DELTA_FIXED_SLOTS`] for the measurement that makes deriving it a Pillar-1 break.
    pub slots: usize,
    /// ⭐ HOW MANY FIELD VALUES THE PER-ROW PUBLIC TUPLE HOLDS. Was the global [`DELTA_TUPLE_VALS`]
    /// baked into `step_cols`, which fixed every aggregate at FOUR digests per row — one nullifier per
    /// carrier. That is the whole of DB-83: a constant-width spend-or-decoy carrier states 32 tags, and
    /// a layout that can only hold one cannot state it, so a multi-input spend is refused at the door
    /// (`MULTI_INPUT_NOT_STATEABLE_YET`) to keep the other real inputs from going unstated and therefore
    /// un-deleted, i.e. double-spendable.
    ///
    /// ⛔ NOT A GROWTH AXIS: it is a per-CLASS protocol constant (4 digests for a single spend, the cover
    /// width for a spend-or-decoy carrier), identical at height 1 and height 10^12. No history quantity
    /// enters it.
    pub tuple_vals: usize,
}

impl DeltaLayout {
    /// First column of the per-row public tuple — immediately after the bound step's own limbs.
    #[must_use]
    pub fn tuple_off(&self) -> usize {
        EXT_LIMBS * self.bound.values()
    }
    /// Total columns of THE step table — one, holding every carrier as a row.
    ///
    /// ⭐⭐⭐ γ LIVES IN CELLS HERE, AND `BoundLayout::powers` IS WHAT MAKES THAT SAFE. The first cut put
    /// γ in cells with no power chain: the inner gate folds `acc += gp*res; gp *= gamma`, so a γ read
    /// from a COLUMN made the k-th residual degree k for k in the hundreds. The declared degree — probed
    /// on an EMPTY row, where γ is zero — stayed small, the sumcheck truncated, and the proof PROVED and
    /// did not VERIFY.
    ///
    /// ⛔ IT PASSED AT n=1 AND FAILED AT n=2, AND THAT IS THE GENERAL LESSON: with ONE replicated row
    /// every column's MLE is a CONSTANT, so no degree can ever show itself. A single-row table cannot
    /// test degree.
    ///
    /// With `γ^0 … γ^{K-1}` carried as cells under the row-local chain `γ^k == γ^{k-1}·γ`, every
    /// residual multiplies a DEGREE-1 cell, the fold costs one degree total, and all carriers become
    /// rows of one table — which is what makes the proof's size independent of how many spends were
    /// real.
    #[must_use]
    pub fn step_cols(&self) -> usize {
        self.tuple_off() + self.tuple_vals
    }
    /// ⭐⭐⭐ THREE TABLES, FOREVER, WHATEVER `n` IS. Table 0 holds every carrier's bound step as a ROW;
    /// table 1 holds every carrier's Fiat–Shamir walk as a SEGMENT; table 2 is the chain that ends at
    /// `rows_digest`. Nothing here is per-carrier, so the COLUMN count — which is what proof size
    /// follows — does not move with how many spends a block carried.
    #[must_use]
    pub fn step_table(&self) -> usize { 0 }
    #[must_use]
    pub fn sponge_table(&self) -> usize { 1 }
    #[must_use]
    pub fn chain_table(&self) -> usize { 2 }
    /// The PADDED carrier count — the row count of the step table, and the SEGMENT count of the sponge
    /// table. Both must agree so a column tie's high variables mean "carrier index" in both.
    ///
    /// In production this is [`DELTA_FIXED_SLOTS`] and never moves: a block always carries that many tx
    /// slots, real and cover alike, so the aggregate's shape is a constant of the protocol rather than a
    /// function of how busy the block was.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.slots
    }
    /// Rows per sponge segment — a power of two, so the segment boundary is "the low `seg_log` bits of
    /// the row index are zero" and the circuit reads it off the point with no extra column.
    #[must_use]
    pub fn seg_rows(&self) -> usize { 1 << self.seg_log }
    /// Column of value `j` of row-tuple digest `d`.
    #[must_use]
    pub fn tuple_at(&self, d: usize, j: usize) -> usize {
        self.tuple_off() + d * DIGEST_LANES + j
    }
}

/// The per-table circuit. Table 0 is the bound steps; table `1 + i` is carrier `i`'s transcript sponge;
/// the LAST table is the chain that folds every row's tuple into `rows_digest`.
pub enum SettlementDeltaAir<C, F>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    /// Table 0 — one BOUND step per spent note, each closing against a gate built from its OWN cells.
    Rows {
        gamma: Ea4,
        layout: BoundLayout,
        /// The per-row public tuple's width (`DeltaLayout::tuple_vals`), carried so the gate can name the tuple's cells
        /// as free with respect to its own laws (they are bound by the rows-digest cross-tie).
        tuple_vals: usize,
        inner: F,
    },
    /// Tables 1..=n — the sponge that DERIVES row `i`'s challenges from row `i`'s carrier transcript.
    Sponge(SpongeChainConstraint),
}

impl<C, F> AirConstraint for SettlementDeltaAir<C, F>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Rows { gamma, layout, inner, .. } => {
                BoundStepConstraint { gamma: *gamma, layout: *layout, inner: inner.clone() }
                    .degree(nvars)
            }
            Self::Sponge(c) => c.degree(nvars),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Rows { gamma, layout, inner, .. } => {
                BoundStepConstraint { gamma: *gamma, layout: *layout, inner: inner.clone() }
                    .eval(local, at, x)
            }
            Self::Sponge(c) => c.eval(local, at, x),
        }
    }
    /// ⭐ THE STEP TABLE IS THE WIDE ONE, AND IT IS ROW-LOCAL — so the prover never builds or folds a
    /// rotation for it. The sponge chains rows and is not; it says so itself.
    fn is_row_local(&self) -> bool {
        match self {
            Self::Rows { gamma, layout, inner, .. } => {
                BoundStepConstraint { gamma: *gamma, layout: *layout, inner: inner.clone() }
                    .is_row_local()
            }
            Self::Sponge(c) => c.is_row_local(),
        }
    }
    /// The sponge tables run round 0 in the base field; a step row's bound step packs its limbs into the extension and does not.
    fn has_base_eval(&self) -> bool {
        match self {
            Self::Rows { .. } => false,
            Self::Sponge(c) => c.has_base_eval(),
        }
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            Self::Rows { .. } => unreachable!("eval_base is called only when has_base_eval() is true"),
            Self::Sponge(c) => c.eval_base(local, at, x),
        }
    }
    /// Forwarded, so the sponge tables fold 35 shifted columns instead of all 196.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Rows { .. } => Some(Vec::new()),
            Self::Sponge(c) => c.shifted_cols(),
        }
    }
    /// Forwarded and extended: a step row's cells that no law of THIS table reads are (a) the bound step's inner
    /// shifted openings, bound by the WHIR opening (`BoundStepConstraint::free_columns`), and (b) the row's PUBLIC TUPLE
    /// (`tuple_off .. tuple_off + tuple_vals`): its digests are bound by the CROSS-TIE to the rows-digest chain (table 2),
    /// and a class's factory reads the ones it needs into the inner gate's constants — the `outs` digest, for one, is
    /// bound only by that tie. MEASURED 2026-09-29: the census refused the node lane's member-transition pin on the
    /// tuple's `outs` lanes (columns 2132, 2133) until the tuple was declared. The sponge tables declare their own.
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Rows { gamma, layout, tuple_vals, inner } => {
                let step = BoundStepConstraint { gamma: *gamma, layout: *layout, inner: inner.clone() };
                let mut free = match step.free_columns() {
                    Some(cells) => cells,
                    None => unreachable!("the bound step always declares its shifted cells"),
                };
                // the tuple starts right after the bound step's limbs (`DeltaLayout::tuple_off`)
                let tuple = crate::committed_air::EXT_LIMBS * layout.values();
                free.extend(tuple..tuple + *tuple_vals);
                Some(free)
            }
            Self::Sponge(c) => c.free_columns(),
        }
    }
}

/// The outer statement — everything a PEER holds. `n`, the two transition roots and `rows_digest` are
/// what it checks the block against; the per-carrier challenge folds make each row's sponge that row's
/// carrier's sponge; the domain tag is the constant every spend bind opens with, here so the tie that
/// pins it names a public cell rather than trusting a committed one.
#[must_use]
pub fn settlement_delta_bind(
    n: usize,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(n as u64), domain];
    b.extend_from_slice(output_notes_root);
    b.extend_from_slice(del_set_root);
    b.extend_from_slice(rows_digest);
    b
}

/// Where the spend-bind domain tag sits in [`settlement_delta_bind`]'s output.
pub const DELTA_DOMAIN_OFF: usize = 1;

/// Where `rows_digest` sits, given the two transition roots' lengths.
#[must_use]
pub fn delta_digest_off(onr_len: usize, dsr_len: usize) -> usize {
    2 + onr_len + dsr_len
}

/// Tie a run of sponge cells to a run of step columns, ONE TIE PER SPONGE ROW.
///
/// ⭐ EVERY TIE COSTS AN OPENING PAIR IN THE PROOF (`cross_tie_openings`), so the tie COUNT is a size
/// axis. A tie's `cols` is a VECTOR at one row, and a sponge absorbs `RATE` elements per row — so
/// grouping cells by their row turns `RATE` ties into one without changing a single equality.
pub(crate) fn tie_run(
    ties: &mut Vec<crate::whir_rec_block::ColumnTieSpec>,
    cells: &[(usize, usize)],
    sponge: usize,
    seg_log: usize,
    step: usize,
    step_base: usize,
) {
    let mut i = 0;
    while i < cells.len() {
        let row = cells[i].0;
        let mut j = i;
        while j < cells.len() && cells[j].0 == row {
            j += 1;
        }
        // The sponge endpoint pins the LOW `seg_log` bits to this cell's row INSIDE the segment; the
        // step endpoint has no low bits because its rows ARE the carriers. The high variables are the
        // carrier index in both, so this ONE tie states the equality for every carrier at once.
        ties.push((
            (sponge, cells[i..j].iter().map(|c| c.1).collect(), seg_log, row),
            (step, (i..j).map(|k| step_base + k).collect(), 0usize, 0usize),
        ));
        i = j;
    }
}

/// The CROSS-TIES — why a row's tuple is not a cell the prover chose.
///
/// Per spent note `i`, with its transcript sponge at table `1 + i`:
/// 1. **THE TUPLE IS WHAT THE CARRIER'S TRANSCRIPT ABSORBED.** `validity_public_bind_with_commit`
///    writes `[DOMAIN, out0_cm, out1_cm, nullifier, leaf_commit]`, and those are the first elements the
///    carrier's challenger absorbs. Tying them to row `i`'s tuple cells makes the tuple the statement
///    the proof was actually raised over — ⭐ this is the tie that turns "a producer's word" into
///    evidence, and everything else here exists to make it mean something.
/// 2. **THE ROUND EVALS** are the carrier's, so the step cannot invent a claim chain.
/// 3. **THE CHALLENGES** are the sponge's squeezes, so `r` is not a free cell and a prover does not
///    choose the batching scalar Schwartz–Zippel assumes it cannot (the residual §BD-2 named).
///
/// Then, once over the whole table: every row's tuple is also absorbed by the CHAIN, whose final state
/// is the public `rows_digest`. That is what lets a peer holding only the tuple list judge the block.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn settlement_delta_ties(
    layout: DeltaLayout,
    pb_len: usize,
    domain_bind_off: usize,
    digest_bind_off: usize,
) -> Option<(Vec<CrossTieSpec>, Vec<crate::whir_rec_block::ColumnTieSpec>)> {
    settlement_delta_ties_masked(layout, pb_len, domain_bind_off, digest_bind_off, u8::MAX)
}

/// The same ties, group by group. The mask exists so a bisect can ask WHICH group disagrees — when the
/// whole weld failed, every part verified alone and only the composition broke (§BU).
#[allow(clippy::too_many_lines)]
pub(crate) fn settlement_delta_ties_masked(
    layout: DeltaLayout,
    pb_len: usize,
    domain_bind_off: usize,
    digest_bind_off: usize,
    mask: u8,
) -> Option<(Vec<CrossTieSpec>, Vec<crate::whir_rec_block::ColumnTieSpec>)> {
    let bound = layout.bound;
    let (ood, cap_elems) = committed_schedule_params(bound.nvars, bound.width)?;
    let (lens, samples) = committed_schedule_lens(bound.nvars, bound.per, pb_len, ood, cap_elems)?;
    let (absorbed, squeezed, _steps) = plan(&lens, &samples)?;
    // ⛔ WAS THE GLOBAL. A ties routine that checks the bind against a CONSTANT while the layout carries
    // its own width silently disagrees with the trace it is tying — so it reads the layout.
    if pb_len != 1 + layout.tuple_vals {
        return None; // fail-closed: the bind must be the domain tag plus exactly one tuple
    }
    let mut cross: Vec<CrossTieSpec> = Vec::new();
    let mut cols: Vec<crate::whir_rec_block::ColumnTieSpec> = Vec::new();
    let evals_off = pb_len + cap_elems + ood * EXT_LIMBS;
    let r_off = EXT_LIMBS * bound.nvars * bound.per;
    let z_off = EXT_LIMBS * (bound.nvars * bound.per + bound.nvars);
    let tail = squeezed.len().checked_sub(EXT_LIMBS * bound.nvars)?;
    let (sp, st, sl) = (layout.sponge_table(), layout.step_table(), layout.seg_log);

    // 1) THE DOMAIN TAG. A PUBLIC constant, and the same one for every carrier — so it is the one tie
    //    that is a plain cross-tie: it names the statement, not a per-carrier cell.
    //    ⛔ It is checked on carrier 0's segment only. Every other carrier's tag is forced by the TUPLE
    //    tie plus the sponge's own chain: the first burst is one absorb of `pb_len` elements, so a row
    //    whose tag differed would change its walk and break the γ/z/r ties below.
    if mask & 1 != 0 {
        let (row0, col0) = *absorbed.first()?;
        cross.push((
            (sp, vec![col0], row0),
            (crate::whir_rec_block::PUBLIC_BIND_TABLE, vec![domain_bind_off], 0usize),
        ));
    }
    // 2) THE TUPLE IS WHAT THE CARRIER'S TRANSCRIPT ABSORBED — the tie that turns a producer's word into
    //    evidence, and everything else here exists to make it mean something.
    if mask & 2 != 0 {
        let cells: Vec<(usize, usize)> = absorbed.iter().skip(1).take(layout.tuple_vals).copied().collect();
        tie_run(&mut cols, &cells, sp, sl, st, layout.tuple_off());
    }
    // 3) THE ROUND EVALS, so the step cannot invent a claim chain.
    if mask & 4 != 0 {
        let cells: Vec<(usize, usize)> = absorbed
            .iter()
            .skip(evals_off)
            .take(bound.nvars * bound.per * EXT_LIMBS)
            .copied()
            .collect();
        tie_run(&mut cols, &cells, sp, sl, st, 0);
    }
    // 4) THE CHALLENGES `r` — the residual §BD-2 named: without them `r` is a free cell and a prover
    //    chooses the batching scalar Schwartz–Zippel assumes it cannot.
    if mask & 8 != 0 {
        let cells: Vec<(usize, usize)> = squeezed.iter().skip(tail).copied().collect();
        tie_run(&mut cols, &cells, sp, sl, st, r_off);
    }
    // 5) THE OOD POINT `z`. Without it the closing equation is SOLVABLE — pick any `opened`, then set
    //    z_0 = (cf/(C(opened)·Π_{k>0} eq_k) − (1−r_0))/(2r_0 − 1). One division. The weld shipped with
    //    exactly this hole and it measured `proves=true verifies=true` (§BU-2).
    if mask & 16 != 0 {
        let cells: Vec<(usize, usize)> = squeezed
            .iter()
            .skip(EXT_LIMBS * (ood + 1))
            .take(EXT_LIMBS * bound.nvars)
            .copied()
            .collect();
        tie_run(&mut cols, &cells, sp, sl, st, z_off);
    }
    // 6) γ — each row's own batching scalar, tied to the squeeze that produced it. It is the cell
    //    `power_at(1)`, and the step's power chain forces every other power from it.
    if mask & 32 != 0 {
        let cells: Vec<(usize, usize)> =
            squeezed.iter().skip(EXT_LIMBS * ood).take(EXT_LIMBS).copied().collect();
        tie_run(&mut cols, &cells, sp, sl, st, EXT_LIMBS * bound.power_at(1));
    }
    // 7) THE CHAIN. Every row's tuple is absorbed by the chain whose final state is `rows_digest` — the
    //    one public value a peer holding only the tuple list can judge the block by. The chain absorbs
    //    `layout.tuple_vals` per carrier, so its segment is the tuple and its high bits are the carrier.
    let chain = layout.chain_table();
    let rows = layout.rows();
    let (c_absorbed, _c_sq, c_steps) =
        plan(&vec![layout.tuple_vals; rows], &vec![0usize; rows])?;
    if c_steps % rows != 0 {
        return None; // fail-closed: the chain's segment must be the same height for every carrier
    }
    let c_seg_log = (c_steps / rows).next_power_of_two().trailing_zeros() as usize;
    if mask & 64 != 0 {
        let per: Vec<(usize, usize)> = c_absorbed.iter().take(layout.tuple_vals).copied().collect();
        tie_run(&mut cols, &per, chain, c_seg_log, st, layout.tuple_off());
    }
    // 8) ⛔ THE DIGEST IS THE SPONGE'S STATE, NOT A FOLD OF IT. `SpongeChainConstraint`'s own `chal` is a
    //    Horner fold with a fixed multiplier — fine for binding challenges the sponge already
    //    constrains, FATAL as a digest: a 31-bit fold of four values is grindable in 2^31 (§BK-4).
    if mask & 128 != 0 {
        let last = c_steps.checked_sub(1)?;
        for j in 0..DIGEST_LANES {
            cross.push((
                (chain, vec![crate::sponge_chain_air::OUTPUT_OFF + j], last),
                (crate::whir_rec_block::PUBLIC_BIND_TABLE, vec![digest_bind_off + j], 0usize),
            ));
        }
    }
    Some((cross, cols))
}


/// ⭐⭐⭐ THE PRODUCTION FACTORY — the spend gate rebuilt per row from that row's OWN public cells.
///
/// This is §BO's keystone as a shipped API rather than a fixture. A constraint field holds ONE value
/// for every row, but every carrier has its own publics, so the gate cannot be a constant handed to the
/// circuit: its four digests are READ FROM THE ROW — the very cells the row's transcript absorbed and
/// the chain hashes. A row that lies about its tuple is closed against a different gate and its
/// equation stops holding.
///
/// ⛔ γ IS NOT A CELL HERE, and that is not an oversight: the gate batches residuals by γ-POWERS, so a
/// γ read from a column makes the k-th residual degree k (§BW). The row carries the γ LADDER instead and
/// `BoundStepConstraint` folds against it; this gate's own `gamma` field never enters the circuit.
///
/// `depth` is the spend gate's membership-path length, and it is 0 on every carrier the chain now
/// builds — that path is anchored to nothing and was pure width (§BY).
#[must_use]
pub fn spend_delta_factory(
    layout: DeltaLayout,
) -> impl Fn(&Row<'_>) -> crate::committed_air::Blinded<crate::whir_rec_block::SpendValidityGate> + Clone
{
    move |row: &Row<'_>| {
        let d = |off: usize| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|j| row[off + j]) };
        crate::committed_air::Blinded {
            inner: crate::whir_rec_block::SpendValidityGate {
                gamma: Ea4::ZERO,
                // (2026-09-30) no root and no depth: the spend gate is one constant shape; see `whir_rec_block::SV_OB`.
                out0_cm: d(layout.tuple_at(0, 0)),
                out1_cm: d(layout.tuple_at(1, 0)),
                nullifier: d(layout.tuple_at(2, 0)),
                bond_amount: None,
                // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
                fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
                leaf_commit: d(layout.tuple_at(3, 0)),
                // DB-329 §7e: the claim tag is the bind's sixth digest (after D at 4) — read from the row's OWN tuple.
                tag1: Some(d(layout.tuple_at(5, 0))),
                // Spec §9.1: the clock is the bind's seventh digest — read from the row's OWN tuple, like every public.
                vault: Some(d(layout.tuple_at(6, 0))[0]),
            },
        }
    }
}

/// ⭐ HOW MANY TAGS A SPEND-OR-DECOY ROW STATES — the per-tx constant width.
///
/// ⛔ THIS IS THE NUMBER DB-83 WAS MISSING. `DIGESTS_PER_TUPLE` = 4 fixed every aggregate row at ONE
/// nullifier, so a tx spending k > 1 real notes had k-1 real tags go UNSTATED: they never entered the
/// allow-list, their deletions were refused, and those notes stayed spendable. The submit door refuses
/// multi-input spends (`MULTI_INPUT_NOT_STATEABLE_YET`) precisely to keep that from happening — a
/// correct fail-closed guard, not an oversight.
///
/// It is the COVER width, not a real input count: every tx already pads to it
/// (`cover::TX_FIXED_NULLIFIER_COUNT`), and `CoverOrSpendGate` hides how many were real behind a witness
/// selector. So a row states the whole constant-width tag set and reveals nothing about k.
///
/// ⛔ PARITY: the node asserts this equals `cover::TX_FIXED_NULLIFIER_COUNT` — two crates cannot hold two
/// ideas of one protocol width (the depth-mismatch class, DB-73/74/75).
pub const COVER_TAGS_PER_TUPLE: usize = 8;

/// The row-tuple width for a spend-or-decoy transition: ONE digest — the tag set's chained commitment.
///
/// ⛔⛔⛔ WAS `COVER_TAGS_PER_TUPLE * DIGEST_LANES` (256 values), AND THAT MADE THE CLASS UNSTATEABLE.
/// `settlement_delta_ties` emits one COLUMN TIE per sponge row a tuple's cells span (rate 8) — twice, in
/// the transcript sponge and in the `rows_digest` chain — so the tie count tracked the tag count:
/// 4 digests -> 56 ties, 32 digests -> 112, against a `COLUMN_TIES_MAX` of 64.
///
/// The cap was NOT moved. Its own doc is the diagnosis: *a column tie is a property of the CIRCUIT — one
/// per relation the AIR states between two tables — so a correct circuit names a handful and never more,
/// whatever the tables hold.* The circuit was stating 33 relations where it should state one. The tags
/// now live in the carrier's OWN columns, chained in-circuit to this digest
/// (`nf_sparse_air::cover_tag_set_digest`), so a row ties 8 values on one sponge row however many tags
/// it carries — at 32, at 256, at any width this protocol ever picks.
pub const COVER_TUPLE_VALS: usize = DIGEST_LANES;

/// ⛔⛔⛔ THE ZEROCHECK ARITY A SPEND-OR-DECOY CARRIER MUST HAVE — the protocol's tx width, in the
/// only place the aggregate can still see it now that the carrier is ONE TAG PER ROW.
///
/// `COVER_TAGS_PER_TUPLE` rows, doubled by `committed_air::Blinded`, is `1 + log2(W)` variables. While
/// every tag sat in ONE row the width was enforced by the gate's own `slots` list; with one tag per
/// row the gate is width-agnostic by construction, so the ARITY is what says how many tags a carrier
/// carries — and a block that could state a NARROWER carrier would publish the tx's real input count
/// in the shape of its own rows, which is exactly what the count-hiding disjunction exists to prevent.
/// Derived from the protocol constant; never written as a number.
pub const COVER_CARRIER_NVARS: usize = 1 + COVER_TAGS_PER_TUPLE.trailing_zeros() as usize;

/// The per-row gate for a SPEND-OR-DECOY transition — the count-hiding twin of [`spend_delta_factory`].
///
/// Reads the row's constant-width tag set out of its tuple cells and rebuilds
/// [`crate::nf_sparse_air::CoverOrSpendGate`] over it, so the aggregate proves the same disjunction the
/// submit door verified: every carried tag is EITHER a real spend's nullifier `Poseidon(sk, leaf)` OR a
/// decoy `Poseidon(bound, m_slot)`, with the selector a WITNESS column. The real-input count never
/// appears in the statement, which is what lets a k-input consolidation and a 1-input send be the same
/// shape on the wire.
///
/// `slots` are positional `0..W`, matching what the wallet derives — the same spelling the `cover_ok`
/// route in `rpc_http` already passes, never a second one.
#[must_use]
pub fn cover_delta_factory(
    layout: DeltaLayout,
) -> impl Fn(&Row<'_>) -> crate::committed_air::Blinded<crate::nf_sparse_air::CoverOrSpendGate> + Clone {
    move |row: &Row<'_>| {
        // ONE digest out of the row's tuple cells — the tag set's chained commitment. The tags themselves
        // are the carrier's own columns, welded to this digest by the gate's `COS_CHAIN` block, so the
        // aggregate reads eight values here whatever the tag count is.
        let tag_digest: [Ea4; DIGEST_LANES] = core::array::from_fn(|j| row[layout.tuple_at(0, j)]);
        crate::committed_air::Blinded {
            inner: crate::nf_sparse_air::CoverOrSpendGate {
                // Unused here: the aggregate folds `residuals()` against γ-power COLUMNS, exactly as
                // `spend_delta_factory` does — a γ read from a cell is what truncates a sumcheck.
                gamma: Ea4::ZERO,
                tag_digest,
            },
        }
    }
}

/// The shape a VERIFIER needs and cannot derive, because it holds no carrier. Small and constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaShape {
    pub nvars: usize,
    pub per: usize,
    pub width: usize,
    pub powers: usize,
    pub power_lo: usize,
    pub seg_log: usize,
    pub slots: usize,
    pub n: usize,
}

impl DeltaShape {
    /// Rebuild the layout this shape names. Fail-closed on anything unstateable.
    #[must_use]
    pub fn layout(&self) -> Option<DeltaLayout> {
        if self.n == 0 || self.n > self.slots || !self.slots.is_power_of_two() || self.powers == 0 {
            return None;
        }
        // ⛔ DB-213b — one committed slot count (see `rows_digest_of`); a verifier's layout never takes another.
        if self.slots != DELTA_FIXED_SLOTS {
            return None;
        }
        Some(DeltaLayout {
            // The wire shape names the SINGLE-SPEND class, so its tuple width is that class's constant.
            // A spend-or-decoy transition carries its own shape and sets its own width; this one is
            // untouched, which is why no existing block's bytes move.
            tuple_vals: DELTA_TUPLE_VALS,
            bound: BoundLayout {
                nvars: self.nvars,
                per: self.per,
                width: self.width,
                powers: self.powers,
                power_lo: self.power_lo,
                // ⛔ NOT ON THE WIRE, AND DELIBERATELY SO. Which inner columns are ROTATED is a
                // property of the CLASS's circuit, not of a prover's object — a shifted run read off
                // the wire would be a free parameter, and a prover naming an empty one would switch
                // off every constraint the rotation carries (here, the whole tag-set chain link).
                // A class whose gate is row-shifted overrides these from its OWN gate, exactly as it
                // overrides `tuple_vals`; the single-spend class is row-local and takes the default.
                shifted_lo: 0,
                shifted: 0,
            },
            n: self.n,
            seg_log: self.seg_log,
            slots: self.slots,
        })
    }
}

/// ⛔⛔⛔ DB-213b — THE CLASS FIXES THE SHAPE; THE BLOCK NEVER DOES.
///
/// A [`DeltaShape`] rides the block (`note_transition::shape_from_wire`), and every field of it sizes or
/// steers something in the verifier: `per` is how many evals each inner round carries (a `per` of 1 leaves
/// `h[0] + h[1]` reading past the end), `nvars`·`width` size the committed schedule, `powers` sizes the probe
/// row, `seg_log` sets where every tie's low row lands, `depth` sets the gate's walk and `slots` pads the tuple
/// list. None of them is the producer's to choose. The inner carrier CLASS fixes `nvars`/`per`/`width` (its
/// committed trace is the blinded row replicated to `LIGHT_CARRIER_ROWS`), the class's own gate fixes
/// `powers`, the public schedule fixes `power_lo`/`seg_log`, and `DELTA_FIXED_SLOTS` fixes `slots` — so the
/// whole shape is a function of `(depth, n)`, derived HERE by both the producer and the peer, and a block
/// naming any other shape is refused before its layout is built.
///
/// `n` is the block's own spend count (bounded by `slots`); `depth` is the class's carrier depth, bounded by
/// the tree it walks ([`crate::whir_rec_block::spend_validity_row_width`]) before it sizes anything.
#[must_use]
pub fn note_class_shape(n: usize) -> Option<DeltaShape> {
    let nvars = (2 * crate::whir_rec_block::LIGHT_CARRIER_ROWS).trailing_zeros() as usize;
    // the note class lays the vault region after the plain spend row (spec §9.1)
    let width = crate::whir_rec_block::note_spend_row_width();
    let zero = [Ea4::ZERO; DIGEST_LANES];
    let inner = crate::committed_air::Blinded {
        inner: crate::whir_rec_block::SpendValidityGate {
            gamma: Ea4::ZERO,
            out0_cm: zero,
            out1_cm: zero,
            nullifier: zero,
            bond_amount: None,
            // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
            fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
            leaf_commit: zero,
            tag1: Some(zero), // the note class carries the claim (DB-329 §7e): its residuals count in the shape
            vault: Some(crate::whir_rec_block::clock_const(0)), // and the vault region (spec §9.1): likewise
        },
    };
    let base = BoundLayout {
        nvars,
        per: inner.degree(nvars) + 2,
        width,
        shifted_lo: 0,
        shifted: 0,
        powers: 0,
        power_lo: 0,
    };
    let probe = spend_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: DELTA_TUPLE_VALS,
    });
    let powers = class_residual_count(&probe, base);
    let layout = delta_layout(base, powers, n, DELTA_FIXED_SLOTS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS)?;
    Some(shape_of_layout(layout))
}

/// The spend-or-decoy class's shape — [`note_class_shape`]'s twin. The carrier proves no membership path, so its
/// depth is 0; its committed trace is the blinded one-tag-per-row table at `COVER_CARRIER_NVARS` × `CR_COLS`.
#[must_use]
pub fn cover_class_shape(n: usize) -> Option<DeltaShape> {
    let (base, powers) = cover_class_base();
    let layout = delta_layout(base, powers, n, DELTA_FIXED_SLOTS, 1 + COVER_TUPLE_VALS, COVER_TUPLE_VALS)?;
    Some(shape_of_layout(layout))
}

/// The cover class's bound base and residual count from CONSTANTS alone (no carrier in hand) — the one spelling
/// [`cover_class_shape`] and the tag ledger (`crate::tag_ledger::tag_ledger_layout`, padding spec §18) both build from,
/// as `member_path_gate::member_class_base` is for the member class.
#[must_use]
pub fn cover_class_base() -> (BoundLayout, usize) {
    let nvars = COVER_CARRIER_NVARS;
    let inner = crate::committed_air::Blinded {
        inner: crate::nf_sparse_air::CoverOrSpendGate { gamma: Ea4::ZERO, tag_digest: [Ea4::ZERO; DIGEST_LANES] },
    };
    let (shifted_lo, shifted) = crate::nf_sparse_air::cover_shifted_run();
    let base = BoundLayout {
        nvars,
        per: inner.degree(nvars) + 2,
        width: crate::nf_sparse_air::CR_COLS,
        shifted_lo,
        shifted,
        powers: 0,
        power_lo: 0,
    };
    let probe = cover_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: COVER_TUPLE_VALS,
    });
    let powers = class_residual_count(&probe, base);
    (base, powers)
}

/// How many residuals a class's per-row gate emits — the probe BOTH producers already ran, in ONE place.
fn class_residual_count<G: AirConstraint, P: Fn(&Row<'_>) -> G>(probe: &P, base: BoundLayout) -> usize {
    let oob = crate::air_zerocheck::OobLatch::new();
    let vals = vec![Ea4::ZERO; base.width];
    probe(&Row::new(&vals, &oob))
        .residuals(&Row::new(&vals, &oob), &|_c: usize, _p: &[Ea4]| Ea4::ZERO, &vec![Ea4::ZERO; base.nvars])
        .len()
}

/// ⛔ DB-223 Q4 (2026-09-27) — A TUPLE WIDTH THE CHAIN CAN STRIDE EXACTLY.
///
/// The chain spends `tuple_vals / RATE` duplexings per carrier and lays them BACK TO BACK
/// (`settlement_delta_tables`, `rows_digest_of`), while the ties locate carrier `i`'s cells at
/// `i · (tuple_vals / RATE).next_power_of_two()`. The two agree only when the per-carrier count is itself a
/// power of two. MEASURED: a three-digest membership tuple (24 values, 3 duplexings, stride 4) proved without
/// complaint and the honest aggregate FAILED to verify: every carrier after the first was checked at the wrong
/// rows. Fail-closed but silent, and a class that can never verify is a class nobody can use. So the width is
/// refused at layout time, legibly, on BOTH sides. Every width the protocol states today passes (spend: 4
/// duplexings; spend-or-decoy: 1).
fn chain_stride_is_exact(tuple_vals: usize) -> bool {
    let rate = crate::sponge_chain_air::RATE;
    tuple_vals != 0 && tuple_vals % rate == 0 && (tuple_vals / rate).is_power_of_two()
}

/// ⛔ DB-213b — the THREE tables a delta proof commits, from its layout alone: the bound-step table (one row per
/// slot), the sponge table (one `seg_rows` segment per slot) and the chain (every slot's tuple, `tuple_vals / RATE`
/// duplexings each, rounded to a power of two). `settlement_delta_tables` lays exactly these.
pub(crate) fn settlement_delta_table_shapes(layout: DeltaLayout) -> Option<Vec<(usize, usize)>> {
    let rows = layout.rows();
    let rate = crate::sponge_chain_air::RATE;
    if !rows.is_power_of_two() || !chain_stride_is_exact(layout.tuple_vals) {
        return None;
    }
    let lr = rows.trailing_zeros() as usize;
    let c_seg = (layout.tuple_vals / rate).checked_next_power_of_two()?;
    Some(vec![
        (lr, layout.step_cols()),
        (lr.checked_add(layout.seg_log)?, crate::sponge_chain_air::ROW_COLS),
        (rows.checked_mul(c_seg)?.trailing_zeros() as usize, crate::sponge_chain_air::ROW_COLS),
    ])
}

/// The wire shape a layout states — every class in this file and `member_path_gate` states its shape through it.
pub(crate) fn shape_of_layout(layout: DeltaLayout) -> DeltaShape {
    DeltaShape {
        nvars: layout.bound.nvars,
        per: layout.bound.per,
        width: layout.bound.width,
        powers: layout.bound.powers,
        power_lo: layout.bound.power_lo,
        seg_log: layout.seg_log,
        slots: layout.slots,
        n: layout.n,
    }
}

/// ⭐⭐⭐ THE DIGEST A PEER RECOMPUTES — and it is the SAME code the circuit's chain is built from.
///
/// The peer holds the block's tuple list and nothing else. It must arrive at the identical
/// `rows_digest` the aggregate was proved over, or it is checking a different statement. So this is not
/// a second implementation: `settlement_delta_tables` calls it too, which makes "the list a peer reads"
/// and "the list the circuit hashed" ONE object rather than two that agree today (§AO — a note having
/// two spellings is exactly how a fund-loss hole hides).
///
/// Padding is part of the definition: a block with `n < slots` spends pads by REPLICATING the last
/// tuple, so a peer pads the same way and the committed shape stays the protocol constant (§BW).
#[must_use]
pub fn rows_digest_of(tuples: &[Vec<Fa4>], slots: usize, tuple_vals: usize) -> Option<Vec<Fa4>> {
    // ⛔ DB-213b — `slots` arrives off the block (`note_transition::shape_from_wire`) and this pads the
    // tuple list to it BEFORE any proof is checked: a block naming 2^31 slots made every peer allocate
    // 2^31 tuples. No layout this protocol defines has more slots than the committed `DELTA_FIXED_SLOTS`,
    // so a larger count names no transition and is refused before anything is allocated. (The EXACT slot
    // count a block may state is the class's — `note_class_shape` / `cover_class_shape`, checked by both
    // peer verifiers; this function also serves the prover's smaller research layouts, `DELTA_MIN_SLOTS`.)
    if slots > DELTA_FIXED_SLOTS {
        return None;
    }
    if tuples.is_empty() || tuples.len() > slots || !slots.is_power_of_two() {
        return None;
    }
    // ⛔ THE WIDTH IS THE CLASS'S, AND IT IS AN ARGUMENT NOW. Hard-coding four digests meant a peer
    // recomputing the digest of a spend-or-decoy transition would refuse it before reading a byte — one
    // more place DB-83 was baked in. The CALLER names the class; this stays fail-closed on any tuple
    // that is not exactly that width.
    if tuples.iter().any(|t| t.len() != tuple_vals) {
        return None;
    }
    let padded: Vec<Vec<Fa4>> =
        (0..slots).map(|i| tuples[i.min(tuples.len() - 1)].clone()).collect();
    let steps = crate::sponge_chain_air::replay_with_seed(
        crate::committed_air::COMMITTED_AIR_SEED,
        &padded,
        &vec![0usize; slots],
    );
    if steps.len() % slots != 0 {
        return None;
    }
    let ch = slots * (steps.len() / slots).next_power_of_two();
    if steps.len() > ch {
        return None;
    }
    // ⭐ PERF (lane stable 2026-11-01): the digest is the LAST duplexing's permutation output — `replay_with_seed` already
    // computed it (`SpongeStep::output`, the state `perm.permute_mut` left), and the trace's `OUTPUT_OFF` columns are that
    // same permutation's output laid round by round (`perm_row` over the same seeded constants). Building the whole trace —
    // every round's columns for every row up to the padded height — to read one row's last WIDTH cells was the peer's
    // per-block cost of this door. MEASURED (stable/relay2.sample.txt, a 15 s sample of three nodes' steps): the trace
    // build ~2,630 of 13,999 node-step samples, under `verify_ledger_on_wire_with` and the member door. Equality is pinned
    // (`rows_digest_reads_the_last_duplexing_output_the_trace_lays`) against the trace form on production-shape inputs.
    // cons: none — the same value, no state.
    let last = steps.last()?;
    Some((0..DIGEST_LANES).map(|j| last.output[j]).collect())
}

/// The trace form of [`rows_digest_of`] — the digest read off the laid sponge-chain trace, as the peer computed it before
/// the native read. Test reference only: the equality pin compares the two on production-shape inputs.
#[cfg(test)]
pub(crate) fn rows_digest_of_by_trace(tuples: &[Vec<Fa4>], slots: usize) -> Option<Vec<Fa4>> {
    let padded: Vec<Vec<Fa4>> = (0..slots).map(|i| tuples[i.min(tuples.len() - 1)].clone()).collect();
    let steps = crate::sponge_chain_air::replay_with_seed(crate::committed_air::COMMITTED_AIR_SEED, &padded, &vec![0usize; slots]);
    let ch = slots * (steps.len() / slots).next_power_of_two();
    let (cols, _fold) = crate::sponge_chain_air::build_trace_with_seed(crate::committed_air::COMMITTED_AIR_SEED, &steps, ch);
    let last = steps.len().checked_sub(1)?;
    Some((0..DIGEST_LANES).map(|j| cols[crate::sponge_chain_air::OUTPUT_OFF + j][last]).collect())
}

/// PRODUCER: lay a block's note-transition aggregate from the spends it selected.
///
/// `carriers` is one `(carrier bytes, public bind)` per REAL spend — the bind being exactly what
/// `validity_public_bind_with_commit` produced for that spend, which is what its transcript absorbed.
/// Returns the proof, the shape a peer needs, and the `rows_digest` the peer will recompute.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_note_transition(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_note_transition_with(carriers, domain, output_notes_root, del_set_root, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_note_transition`] with the BOUND template double ([`delta_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_note_transition_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_note_transition_with(carriers, domain, output_notes_root, del_set_root, true)
}

#[allow(clippy::type_complexity)]
fn prove_block_note_transition_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    bound: bool,
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    let base = delta_base_layout(carriers, DELTA_TUPLE_VALS, domain)?; // the SINGLE-SPEND class, by width AND domain word
    let probe = spend_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: DELTA_TUPLE_VALS,
    });
    let oob = crate::air_zerocheck::OobLatch::new();
    let vals = vec![Ea4::ZERO; base.width];
    let powers = probe(&Row::new(&vals, &oob)).residuals(
        &Row::new(&vals, &oob),
        &|_c: usize, _p: &[Ea4]| Ea4::ZERO,
        &vec![Ea4::ZERO; base.nvars],
    )
    .len();
    let layout = delta_layout(base, powers, carriers.len(), DELTA_FIXED_SLOTS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS)?;
    let (bytes, rows_digest) = delta_prove(
        carriers,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        spend_delta_factory(layout),
        bound,
    )?;
    let shape = shape_of_layout(layout);
    // ⛔ DB-213b — the producer states only the shape its class fixes; carriers that laid anything else are
    // not this class, and a peer would refuse the block, so it is never emitted.
    if note_class_shape(layout.n) != Some(shape) {
        return None;
    }
    Some((bytes, shape, rows_digest))
}

/// ⭐⭐⭐ LAY A SPEND-OR-DECOY BLOCK TRANSITION — the half DB-83 was missing.
///
/// Same three tables, same constant shape, same `DELTA_FIXED_SLOTS`; the ONLY difference from
/// [`prove_block_note_transition`] is the per-row gate and the tuple width. Each carrier's bind is
/// `domain ‖ W ‖ tags`, so the tuple is everything after TWO scalars — which is exactly why the width is
/// an argument to `delta_layout` and not derived from the bind length.
///
/// What this buys: a row now states a tx's WHOLE constant-width tag set instead of `nullifiers[0]`, so a
/// k-real-input spend has all k real tags stated, all k enter the allow-list, and all k are deleted. That
/// is the precondition for lifting `MULTI_INPUT_NOT_STATEABLE_YET`.
pub fn prove_block_cover_transition(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_cover_transition_with(carriers, domain, output_notes_root, del_set_root, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_cover_transition`] with the BOUND template double ([`delta_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_cover_transition_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_cover_transition_with(carriers, domain, output_notes_root, del_set_root, true)
}

#[allow(clippy::type_complexity)]
fn prove_block_cover_transition_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    bound: bool,
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    let base = delta_base_layout_cover(carriers)?;
    let probe = cover_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: COVER_TUPLE_VALS,
    });
    let oob = crate::air_zerocheck::OobLatch::new();
    let vals = vec![Ea4::ZERO; base.width];
    let powers = probe(&Row::new(&vals, &oob))
        .residuals(&Row::new(&vals, &oob), &|_c: usize, _p: &[Ea4]| Ea4::ZERO, &vec![Ea4::ZERO; base.nvars])
        .len();
    let layout = delta_layout(
        base,
        powers,
        carriers.len(),
        DELTA_FIXED_SLOTS,
        1 + COVER_TUPLE_VALS, // `domain ‖ tag-set digest` — one rule for every class
        COVER_TUPLE_VALS,
    )?;
    let (bytes, rows_digest) = delta_prove(
        carriers,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        cover_delta_factory(layout),
        bound,
    )?;
    // a spend-or-decoy carrier proves no membership path; membership lives in the spend carrier's cross-bind.
    let shape = shape_of_layout(layout);
    if cover_class_shape(layout.n) != Some(shape) {
        return None; // ⛔ DB-213b — not this class's shape; a peer would refuse it
    }
    Some((bytes, shape, rows_digest))
}

/// PHASE 1 for the cover class — its bind carries TWO scalars before the tags.
#[must_use]
pub fn delta_base_layout_cover(carriers: &[(Vec<u8>, Vec<Fa4>)]) -> Option<BoundLayout> {
    let (bytes, pb) = carriers.first()?;
    // Class separation by the carrier's own domain word (`cover_transition_domain()`, the word `cover_tag_statement_bind`
    // opens with) and width, for EVERY carrier — the same check `delta_base_layout` runs for the spend and bond classes
    // (2026-09-28, §9.6 parity: a width coincidence is not a class check). MEASURED: the first cut named the block
    // carrier's word (`NF_SPARSE_BLOCK_DOMAIN`) and refused every honest cover carrier — the two cover pins caught it.
    let cover_domain = crate::nf_sparse_air::cover_transition_domain();
    for (_, pb_i) in carriers {
        if pb_i.len() != 1 + COVER_TUPLE_VALS || pb_i[0] != cover_domain {
            return None;
        }
    }
    // ⛔ ROW-SHIFTED INNER GATE. One tag per row means the tag-set chain links row to row, so the
    // aggregate must carry the rotation of exactly the columns the gate declares.
    let (lo, n) = crate::nf_sparse_air::cover_shifted_run();
    let base = crate::recursion_bound::bound_step_row_committed(bytes, pb, lo, n)?.1;
    if base.nvars != COVER_CARRIER_NVARS || base.width != crate::nf_sparse_air::CR_COLS {
        return None; // fail-closed: not this class's tx width — see `COVER_CARRIER_NVARS`
    }
    Some(base)
}

/// PEER: verify a block's SPEND-OR-DECOY transition. Fail-closed on a shape that is not this class's.
#[must_use]
pub fn verify_block_cover_transition(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_cover_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_cover_transition`] on an ARMED door: it accepts the bound template double's bytes
/// ([`delta_bound`]) and nothing else.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_block_cover_transition_bound(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_cover_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, true)
}

fn verify_block_cover_transition_with(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    bound: bool,
) -> bool {
    // ⛔ DB-213b — the class fixes the shape ([`cover_class_shape`]); nothing below may read a wire field first.
    if cover_class_shape(shape.n) != Some(shape) {
        return false;
    }
    let Some(mut layout) = shape.layout() else { return false };
    // `DeltaShape` names the single-spend class on the wire; this class states its own shape, so both
    // the tuple width and the ROTATED RUN are restated here from this class's own circuit rather than
    // inferred — a peer must never guess which class it is verifying, and must never take either from
    // the prover.
    layout.tuple_vals = COVER_TUPLE_VALS;
    let (lo, n) = crate::nf_sparse_air::cover_shifted_run();
    layout.bound.shifted_lo = lo;
    layout.bound.shifted = n;
    if layout.bound.nvars != COVER_CARRIER_NVARS || layout.bound.width != crate::nf_sparse_air::CR_COLS
    {
        return false; // fail-closed: the statement does not name this class's tx width
    }
    delta_verify(
        bytes,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        rows_digest,
        cover_delta_factory(layout),
        bound,
    )
}

/// ⭐⭐ DB-313 §3 — THE BOND CLASS: a WELDED spend stated in its own block aggregate, the third class beside the single
/// spend and the spend-or-decoy.
///
/// READ: a bond carrier is the SAME `SpendValidityGate` over the SAME row as a spend
/// (`whir_rec_block::prove_bond_validity_carrier_with_commit_bytes`), plus the public weld `bond_amount: Some(W)` — the
/// gate's residual G, `out0_value − W` — and its transcript bind is `BOND_VALIDITY_DOMAIN ‖ out0_cm ‖ out1_cm ‖ nullifier
/// ‖ W0..W3 ‖ leaf_commit ‖ zero pad` (DB-340: W as its four 16-bit limbs, welded limb-wise — exact u64 equality, never
/// the mod-p residue; the pad makes the width a legal chain stride, `chain_stride_is_exact`). So a bond row's tuple is
/// those `whir_rec_block::BOND_BIND_TUPLE_VALS` values after the domain, and its gate is the spend gate with
/// `bond_amount` BUILT FROM THE ROW'S OWN W LIMB CELLS: C_tuple from the row's own public cells, the rule every class
/// obeys, and no new circuit.
/// MEASURED (DB-313 §1, [gatepf] 9/27; gate Q16 step 10): before this class the template re-verified every welded
/// carrier with the PLAIN spend verifier and evicted it, so no USDm bond could be laid on any chain — the submit door
/// admitted what no block could state.
/// The tuple follows the bind: digests 0, 1, 2 are out0, out1 and the nullifier; W is its limbs; the leaf_commit digest
/// follows W; zeros pad to the width. ONE definition: the carrier's own bind width.
/// Cons (measured 2026-09-28): 64 cells per bond row where a spend row states 32 (8 chain duplexings, not 4); the
/// aggregate at the committed 256 slots is 416,369 B, constant — carried only by a block that lays a bond.
pub const BOND_TUPLE_VALS: usize = crate::whir_rec_block::BOND_BIND_TUPLE_VALS;

/// How many limbs state W — the gate's own count (`bond_limbs`), never a second spelling of it.
fn bond_limb_count() -> usize {
    crate::whir_rec_block::bond_limbs(0).len()
}

/// The bond row's first W limb cell, immediately after the nullifier digest (the bind's own order).
fn bond_w_at(layout: &DeltaLayout) -> usize {
    layout.tuple_at(3, 0)
}

/// Lane `j` of the bond row's leaf_commit digest, immediately after W's limbs.
fn bond_lc_at(layout: &DeltaLayout, j: usize) -> usize {
    layout.tuple_at(3, 0) + bond_limb_count() + j
}

/// The per-row gate of the bond class: the spend gate, welded to the row's OWN W. A row whose W is not the value its
/// carrier welded breaks the closing equation `cf == eq(z,r) · C_tuple(opened)` exactly as a re-pointed digest does.
pub fn bond_delta_factory(
    layout: DeltaLayout,
) -> impl Fn(&Row<'_>) -> crate::committed_air::Blinded<crate::whir_rec_block::SpendValidityGate> + Clone {
    move |row: &Row<'_>| {
        let d = |off: usize| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|j| row[off + j]) };
        crate::committed_air::Blinded {
            inner: crate::whir_rec_block::SpendValidityGate {
                gamma: Ea4::ZERO,
                // (2026-09-30) no root and no depth: one constant spend shape.
                out0_cm: d(layout.tuple_at(0, 0)),
                out1_cm: d(layout.tuple_at(1, 0)),
                nullifier: d(layout.tuple_at(2, 0)),
                // DB-340: the weld reads W's LIMBS from the row — four cells, exact u64 equality in the gate.
                bond_amount: Some(core::array::from_fn(|i| row[bond_w_at(&layout) + i])),
                // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
                fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
                leaf_commit: core::array::from_fn(|j| row[bond_lc_at(&layout, j)]),
                tag1: None, vault: None, // the bond class publishes no claim (DB-329 §7e) and lays no vault region (spec §9.1)
            },
        }
    }
}

/// The bond class's shape — [`note_class_shape`]'s twin, with the weld's residual counted and W in the tuple.
#[must_use]
pub fn bond_class_shape(n: usize) -> Option<DeltaShape> {
    let nvars = (2 * crate::whir_rec_block::LIGHT_CARRIER_ROWS).trailing_zeros() as usize;
    let width = crate::whir_rec_block::spend_validity_row_width();
    let zero = [Ea4::ZERO; DIGEST_LANES];
    let inner = crate::committed_air::Blinded {
        inner: crate::whir_rec_block::SpendValidityGate {
            gamma: Ea4::ZERO,
            out0_cm: zero,
            out1_cm: zero,
            nullifier: zero,
            bond_amount: Some(crate::whir_rec_block::bond_limbs(0)),
            // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
            fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
            leaf_commit: zero,
            tag1: None, vault: None, // the bond class publishes no claim (DB-329 §7e) and lays no vault region (spec §9.1)
        },
    };
    let base = BoundLayout {
        nvars,
        per: inner.degree(nvars) + 2,
        width,
        shifted_lo: 0,
        shifted: 0,
        powers: 0,
        power_lo: 0,
    };
    let probe = bond_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: BOND_TUPLE_VALS,
    });
    let powers = class_residual_count(&probe, base);
    let layout = delta_layout(base, powers, n, DELTA_FIXED_SLOTS, 1 + BOND_TUPLE_VALS, BOND_TUPLE_VALS)?;
    Some(shape_of_layout(layout))
}

/// PRODUCER: lay a block's BOND transition from the welded spends it selected — [`prove_block_note_transition`]'s twin.
/// `carriers` is one `(carrier bytes, public bind)` per REAL bond, the bind exactly what the bond carrier's transcript
/// absorbed (`BOND_VALIDITY_DOMAIN ‖ out0 ‖ out1 ‖ nf ‖ W ‖ leaf_commit`).
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_bond_transition(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_bond_transition_with(carriers, domain, output_notes_root, del_set_root, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_bond_transition`] with the BOUND template double ([`delta_bound`]).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_bond_transition_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_bond_transition_with(carriers, domain, output_notes_root, del_set_root, true)
}

#[allow(clippy::type_complexity)]
fn prove_block_bond_transition_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    bound: bool,
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    let base = delta_base_layout(carriers, BOND_TUPLE_VALS, domain)?; // the BOND class: 1 + BOND_TUPLE_VALS bind values per carrier, opening with the bond domain word
    let probe = bond_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: DELTA_FIXED_SLOTS,
        tuple_vals: BOND_TUPLE_VALS,
    });
    let powers = class_residual_count(&probe, base);
    let layout = delta_layout(base, powers, carriers.len(), DELTA_FIXED_SLOTS, 1 + BOND_TUPLE_VALS, BOND_TUPLE_VALS)?;
    let (bytes, rows_digest) = delta_prove(
        carriers,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        bond_delta_factory(layout),
        bound,
    )?;
    let shape = shape_of_layout(layout);
    // ⛔ DB-213b — the producer states only the shape its class fixes.
    if bond_class_shape(layout.n) != Some(shape) {
        return None;
    }
    Some((bytes, shape, rows_digest))
}

/// PEER: verify a block's BOND transition. Fail-closed on a shape that is not this class's; the tuple width is restated
/// from this class, never read off the wire (the cover class's rule).
#[must_use]
pub fn verify_block_bond_transition(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_bond_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_bond_transition`] on an ARMED door: it accepts the bound template double's bytes
/// ([`delta_bound`]) and nothing else.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_block_bond_transition_bound(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_bond_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, true)
}

fn verify_block_bond_transition_with(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    bound: bool,
) -> bool {
    if bond_class_shape(shape.n) != Some(shape) {
        return false;
    }
    let Some(mut layout) = shape.layout() else { return false };
    layout.tuple_vals = BOND_TUPLE_VALS;
    delta_verify(
        bytes,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        rows_digest,
        bond_delta_factory(layout),
        bound,
    )
}

/// ⛔⛔⛔ THE FOLD FOR THIS CLASS IS GONE, AND ITS ABSENCE IS THE POINT (2026-09-23).
///
/// A `prove_block_cover_transition_folded` lived here: a Poseidon tuple chain plus per-carrier fold
/// steps, built because the FLAT aggregate refused this class at 112 column ties against a cap of 64.
/// The measurement that sent me to a fold was real; the conclusion was not. The cap's own doc had the
/// diagnosis: *a column tie is a property of the CIRCUIT — one per relation the AIR states between two
/// tables — so a correct circuit names a handful and never more, whatever the tables hold.* 112 was
/// the circuit stating 33 relations where it should state ONE, because the carrier's bind carried 256
/// raw tag values. Committing them to one digest (`nf_sparse_air::cover_tag_set_digest`) took the
/// count to 50 and the flat path proves and verifies.
///
/// So the fold was deleted rather than kept beside it. Two ways to state ONE class is §AO — the shape
/// a fund-loss hole hides in — and the two were not even equivalent: the flat aggregate re-checks
/// `cf == eq(z,r)·C(opened)` in circuit, while the fold's lift carries the round evals and the WHIR
/// opening and never re-evaluates the inner AIR at all.

/// PEER: verify a block's note-transition aggregate against the statement the block publishes.
///
/// Holds NO carrier — every input here is public: the shape, both transition roots, and the
/// `rows_digest` the peer recomputed itself from the block's tuple list.
#[must_use]
pub fn verify_block_note_transition(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_note_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_note_transition`] on an ARMED door: it accepts the bound template double's bytes
/// ([`delta_bound`]) and nothing else.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_block_note_transition_bound(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_note_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, true)
}

fn verify_block_note_transition_with(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    bound: bool,
) -> bool {
    // ⛔ DB-213b — the class fixes the shape ([`note_class_shape`]); a block naming any other is refused
    // before its layout is built, before a byte of the proof is read, and before any field sizes anything.
    if note_class_shape(shape.n) != Some(shape) {
        return false;
    }
    let Some(layout) = shape.layout() else { return false };
    delta_verify(
        bytes,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        rows_digest,
        spend_delta_factory(layout),
        bound,
    )
}

/// PHASE 1 of laying an aggregate: the shape every carrier must share, read from the carriers
/// themselves. `powers` is 0 here — it is a property of the GATE, not of the carriers.
///
/// ⛔ CLASS SEPARATION IS A CHECK, NOT A WIDTH (2026-09-28, found by `db313_the_bond_class_states_a_welded_spend_and_
/// its_weight_is_load_bearing` the minute DB-351 widened the spend bind to eight digests): until then a plain spend was
/// kept out of the BOND class only because its bind was 33 words where a bond's is 65 — the moment both binds closed
/// at 65 words a plain spend LAID as a bond. Every carrier's bind must now open with THIS class's domain word
/// (`SPEND_VALIDITY_DOMAIN` / `BOND_VALIDITY_DOMAIN`, the word the verifier absorbs first) and have this class's
/// width — checked for EVERY carrier, not the first alone. ROOT-LAYER: the class is decided where the layout is read.
/// MEASURED: the DB-313 class-separation assert went RED at the widening and GREEN with this check. MUST-STAY-GREEN:
/// every aggregate pin (spend, bond, cover), `the_production_entry_points_prove_and_verify_a_block_note_transition`.
#[must_use]
pub fn delta_base_layout(carriers: &[(Vec<u8>, Vec<Fa4>)], tuple_vals: usize, domain: Fa4) -> Option<BoundLayout> {
    let (bytes, pb) = carriers.first()?;
    for (_, pb_i) in carriers {
        if pb_i.len() != 1 + tuple_vals || pb_i[0] != domain {
            return None; // not this class's carrier: another width, or another class's domain word
        }
    }
    // Row-LOCAL inner gate (`SpendValidityGate`): there is no rotation for this class to carry.
    Some(crate::recursion_bound::bound_step_row_committed(bytes, pb, 0, 0)?.1)
}

/// PHASE 2: how many γ-POWER cells the inner gate needs — its residual count.
///
/// ⛔ COUNTED FROM THE GATE, NEVER GUESSED. A row carrying fewer powers than the gate has residuals
/// would DROP the tail, leaving every residual past `powers` unchecked. `BoundStepConstraint` fails
/// closed in circuit if that ever happens, but the honest path must get it right here.
#[must_use]
pub fn delta_residual_count<C: AirConstraint + Sync>(gate: &C, base: BoundLayout) -> usize {
    let vals = vec![Ea4::ZERO; base.width];
    let oob = crate::air_zerocheck::OobLatch::new();
    let probe = Row::new(&vals, &oob);
    let zero_at = |_c: usize, _p: &[Ea4]| -> Ea4 { Ea4::ZERO };
    let r_pt = vec![Ea4::ZERO; base.nvars];
    gate.residuals(&probe, &zero_at, &r_pt).len()
}

/// PHASE 2b: the HIGHEST COLUMN the inner gate actually reads.
///
/// ⭐⭐⭐ THE OPENED ROW IS THE WIDEST THING IN THE TABLE, AND MOST OF IT IS NEVER LOOKED AT. The step
/// row carries `width` opened values so the gate can be evaluated on them — 1,986 for the blinded spend
/// carrier, 93% of the table. But the closing equation is `cf == eq(z,r) · C(opened)`, and `C` reads
/// only the columns its own map names. Every opened value the gate never indexes contributes NOTHING to
/// that equation, so carrying it is pure width.
///
/// ⛔ AND DROPPING IT CHANGES NO VALUE. `cf` is the carrier's own claim, which its verifier computed as
/// `eq(z,r)·C(full opened)`; since `C` never reads the tail, `C(prefix) == C(full)` identically. This is
/// not an approximation of the equation — it is the same equation with the unread cells removed.
///
/// Measured by asking the gate: evaluate it against a row of width `w` under an [`OobLatch`] and shrink
/// `w` until the latch fires. The answer is a property of the CIRCUIT, so it is stable for a given gate
/// and depth, and a gate that later reads further simply reports a larger number here.
#[must_use]
pub fn delta_read_width<C: AirConstraint + Sync>(gate: &C, base: BoundLayout) -> usize {
    let probe = |w: usize| -> bool {
        let vals = vec![Ea4::ZERO; w];
        let oob = crate::air_zerocheck::OobLatch::new();
        let row = Row::new(&vals, &oob);
        let zero_at = |_c: usize, _p: &[Ea4]| -> Ea4 { Ea4::ZERO };
        let r_pt = vec![Ea4::ZERO; base.nvars];
        let _ = gate.residuals(&row, &zero_at, &r_pt);
        oob.hit()
    };
    if probe(base.width) {
        return base.width; // the gate reads past its own carrier's width — carry everything, fail later
    }
    // Binary search the smallest width the gate does not read past.
    let (mut lo, mut hi) = (0usize, base.width);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if probe(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// PHASE 3: the finished layout, which the row factory CAPTURES so it knows which columns hold the
/// tuple. Explicit rather than ambient — the factory runs during table construction, before any
/// statement exists to read it from.
#[must_use]
pub fn delta_layout(
    base: BoundLayout,
    residuals: usize,
    n: usize,
    slots: usize,
    pb_len: usize,
    tuple_vals: usize,
) -> Option<DeltaLayout> {
    if n == 0 || n > slots || !slots.is_power_of_two() {
        return None; // fail-closed: the carriers must fit the block's slots, and the shape be committable
    }
    if !chain_stride_is_exact(tuple_vals) {
        return None; // fail-closed at LAYOUT time: see `chain_stride_is_exact` — the prover must refuse, not ship
    }
    // ⭐ TWO RUNGS AT ~√K. A flat ladder is one cell per residual — 2,004 for the blinded spend gate,
    // wider than the opened row it folds. `γ^k = (γ^C)^a · γ^b` needs only `C + ceil(K/C)` cells, and
    // that is minimised at `C ≈ √K`.
    let lo = (residuals as f64).sqrt().ceil() as usize;
    let lo = lo.max(2);
    let hi = residuals.div_ceil(lo).max(2);
    let powers = lo + hi;
    // How tall ONE carrier's walk is, from PUBLIC numbers only — the verifier derives the same segment
    // size the prover laid, so the boundary is not something a prover chooses.
    let (ood, cap_elems) = committed_schedule_params(base.nvars, base.width)?;
    let (lens, samples) = committed_schedule_lens(base.nvars, base.per, pb_len, ood, cap_elems)?;
    let (_a, _s, planned) = plan(&lens, &samples)?;
    let seg_log = planned.next_power_of_two().max(CHAIN_MIN_ROWS).trailing_zeros() as usize;
    // ⛔ THE WIDTH IS AN ARGUMENT, NOT A DERIVATION. My first cut derived it as `pb_len - 1` on the rule
    // "a bind is `domain ‖ tuple`". That holds for the single-spend class and NOT for the spend-or-decoy
    // one, whose bind is `domain ‖ W ‖ tags` — deriving would have silently mis-sized every cover row by
    // one scalar. The classes genuinely differ, so the caller names the width and the layout carries it.
    Some(DeltaLayout {
        bound: BoundLayout { powers, power_lo: lo, ..base },
        n,
        seg_log,
        slots,
        tuple_vals,
    })
}

/// The factory BOTH sides derive from public parameters alone. Table 0 is the bound steps; table `1+i`
/// is carrier `i`'s transcript sponge, pinned to that carrier's own challenge fold; the last table is
/// the chain whose final state is `rows_digest`.
#[must_use]
pub fn make_settlement_delta_constraint<C, F>(
    layout: DeltaLayout,
    inner: F,
) -> impl Fn(usize, Ea4) -> SettlementDeltaAir<C, F> + Clone
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    let seed = crate::committed_air::COMMITTED_AIR_SEED;
    let segmented = crate::sponge_chain_air::make_segmented_constraint_with_seed(seed, layout.seg_log);
    let chain = crate::sponge_chain_air::make_constraint_with_seed(seed, Fa4::ZERO);
    move |table: usize, gamma: Ea4| {
        if table == layout.step_table() {
            // ⭐ ONE circuit for EVERY carrier. The row supplies its own tuple AND its own γ (as the
            // power chain), so there is nothing per-carrier left for the circuit to know.
            return SettlementDeltaAir::Rows { gamma, layout: layout.bound, tuple_vals: layout.tuple_vals, inner: inner.clone() };
        }
        if table == layout.sponge_table() {
            // ⭐ ONE circuit for EVERY transcript: `n` independent sponges as segments of one table.
            return SettlementDeltaAir::Sponge(segmented(gamma));
        }
        // The chain carries no squeezes, so its fold stays zero and the equality against zero holds.
        SettlementDeltaAir::Sponge(chain(gamma))
    }
}

/// What a prover assembles and a verifier never sees: the tables, plus the PUBLIC values the statement
/// carries. Fail-closed on any carrier that does not describe the same shape as the first.
#[allow(clippy::type_complexity)]
pub fn settlement_delta_tables(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    layout: DeltaLayout,
) -> Option<(Vec<Vec<Vec<Fa4>>>, Vec<Fa4>)> {
    let n = carriers.len();
    if n == 0 || n != layout.n || layout.bound.powers == 0 {
        return None; // fail-closed: an empty delta certifies nothing, and §BD is what that looks like
    }
    let mut bound: Option<BoundLayout> = None;
    let mut parts: Vec<(Vec<Fa4>, Ea4)> = Vec::with_capacity(n);
    let mut sponges: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(n);
    let mut tuples: Vec<Vec<Fa4>> = Vec::with_capacity(n);
    // ⭐ §FAST (lane c, 2026-10-27) — ONE PARSE PER DISTINCT CARRIER. Every per-carrier term below is a pure function of
    // (bytes, pb, layout): the bound step row, the transcript replay, the sponge segment. A slot-ledger aggregate lays
    // `LEDGER_ROWS` rows and every cover row REPLICATES `carriers[0]` (§2.6), so the same proof bytes were parsed and
    // replayed once per row — MEASURED (scratchpad/lane-c/crf4.sample.txt, an armed quiet producer): 54 % of both ledger
    // proves was this loop re-reading one carrier. A repeat of an earlier carrier (equal bytes AND equal bind) now reuses
    // that carrier's results; its shape check, its refusals and every table are byte-identical to the per-row form (a
    // refused carrier refuses at its first copy, exactly as before). Real and bound forms alike; nothing is stored across
    // calls. `sponge_of[i]` is the distinct sponge segment row `i` reads.
    let mut sponge_of: Vec<usize> = Vec::with_capacity(n);

    for (i, (bytes, pb)) in carriers.iter().enumerate() {
        if pb.len() != 1 + layout.tuple_vals {
            return None; // fail-closed: this bind is not `domain ‖ tuple` at this class's width
        }
        if let Some(j) = carriers[..i].iter().position(|(b, p)| b == bytes && p == pb) {
            let (limbs, gamma) = parts[j].clone();
            parts.push((limbs, gamma));
            tuples.push(pb[1..].to_vec());
            sponge_of.push(sponge_of[j]);
            continue;
        }
        let (limbs, l, gamma) = crate::recursion_bound::bound_step_row_committed(
            bytes,
            pb,
            layout.bound.shifted_lo,
            layout.bound.shifted,
        )?;
        match bound {
            None => bound = Some(l),
            // ⛔ ONE SHAPE PER AGGREGATE. Rows of one table share a circuit; a carrier of another shape
            // would be checked by the wrong equation, which is how a forged row gets in wearing a
            // neighbour's clothes.
            Some(b) if b.nvars == l.nvars && b.per == l.per && b.width == l.width => {}
            Some(_) => return None,
        }
        parts.push((limbs, gamma));
        tuples.push(pb[1..].to_vec());

        // This carrier's own transcript, replayed under the COMMITTED permutation (§BU: under the direct
        // one it reproduces the schedule element for element and lands on challenges nobody drew).
        let (ood, cap_elems) = committed_schedule_params(l.nvars, l.width)?;
        let (lens, samples) = committed_schedule_lens(l.nvars, l.per, pb.len(), ood, cap_elems)?;
        // one layout per class (`recursion_bound::bound_step_row_committed`): a next-row class's carrier is a chained one
        let absorbs = if layout.bound.shifted == 0 {
            crate::committed_air::committed_absorb_bursts(bytes, pb)?
        } else {
            crate::committed_air::chained_absorb_bursts(bytes, pb)?
        };
        if absorbs.iter().map(Vec::len).collect::<Vec<_>>() != lens {
            return None; // fail-closed: the public plan and the real walk must be the same walk
        }
        let steps = crate::sponge_chain_air::replay_with_seed(
            crate::committed_air::COMMITTED_AIR_SEED,
            &absorbs,
            &samples,
        );
        // EVERY segment is exactly `seg_rows` tall — the boundary must be a power-of-two row index or
        // the circuit cannot read it off the point. `build_trace_with_seed` pads by CONTINUING the
        // sponge, so the filler rows satisfy the same carry rule the real ones do.
        if steps.len() > layout.seg_rows() {
            return None; // fail-closed: the walk does not fit the segment the statement declares
        }
        let (cols, _chal) = crate::sponge_chain_air::build_trace_with_seed(
            crate::committed_air::COMMITTED_AIR_SEED,
            &steps,
            layout.seg_rows(),
        );
        sponge_of.push(sponges.len());
        sponges.push(cols);
    }
    let base = bound?;
    if base.nvars != layout.bound.nvars || base.per != layout.bound.per || base.width != layout.bound.width {
        return None; // fail-closed: the statement's shape is not the carriers' shape
    }
    let powers = layout.bound.powers;

    // ── ONE STEP TABLE, ONE ROW PER CARRIER. Each row carries its own γ-power chain, so the circuit is
    // the SAME for every row and the table's COLUMN count — which is what the proof size follows — does
    // not move with how many carriers there are.
    let rows: Vec<Vec<Fa4>> = parts
        .iter()
        .zip(&tuples)
        .map(|((limbs, gamma), tuple)| {
            let mut row = limbs.clone();
            let c = layout.bound.power_lo;
            let mut put = |row: &mut Vec<Fa4>, v: Ea4| {
                row.extend_from_slice(
                    &<Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&v)[..EXT_LIMBS],
                );
            };
            // LOW rung γ^0..γ^{C-1}, then HIGH rung (γ^C)^0..(γ^C)^{A-1}.
            let mut gp = Ea4::ONE;
            for _ in 0..c {
                put(&mut row, gp);
                gp *= *gamma;
            }
            let gc = gp; // γ^C
            let mut qp = Ea4::ONE;
            for _ in 0..(powers - c) {
                put(&mut row, qp);
                qp *= gc;
            }
            row.extend_from_slice(tuple);
            row
        })
        .collect();
    let h = layout.rows();
    // Padding REPLICATES the last real row: it satisfies the same row-local equation, and it is tied to
    // nothing, so it adds no claim. Zeros would not do — the closing equation is not homogeneous in
    // `eq(z,r)`. In production every slot is filled by a real carrier, cover spends included, because
    // `BLOCK_FIXED_TX_COUNT` is a constant of the block shape (see `DELTA_FIXED_ROWS`).
    let step: Vec<Vec<Fa4>> = (0..layout.step_cols())
        .map(|c| (0..h).map(|r| rows[r.min(n - 1)][c]).collect())
        .collect();

    // ── THE CHAIN. Every row's tuple in row order; no squeezes, because its output is a STATE, not a
    // fold. It is padded to `rows()` bursts exactly as the step table is, so its HIGH variables are the
    // carrier index too and one column tie reaches every carrier's tuple.
    let padded: Vec<Vec<Fa4>> = (0..layout.rows()).map(|i| tuples[i.min(n - 1)].clone()).collect();
    let chain_cols = chain_table_of(&padded)?;
    // ⛔ ONE SPELLING: the digest a PEER recomputes is this SAME function, never a twin that agrees
    // today and drifts tomorrow (§AO — a note having two spellings is how a fund-loss hole hides).
    let rows_digest = rows_digest_of(&tuples, layout.rows(), layout.tuple_vals)?;

    // ── ONE SPONGE TABLE, `n` SEGMENTS. Stacked, then padded to a power of two by REPEATING the last
    // segment — a repeat is itself a valid `seg_rows` walk from the all-zero state, so every padded
    // segment satisfies the same constraint a real one does and none of them is tied to anything.
    let seg = layout.seg_rows();
    let total = layout.rows() * seg;
    let width = sponges[0].len();
    let sponge: Vec<Vec<Fa4>> = (0..width)
        .map(|c| (0..total).map(|r| sponges[sponge_of[(r / seg).min(n - 1)]][c][r % seg]).collect())
        .collect();

    Some((vec![step, sponge, chain_cols], rows_digest))
}

/// THE CHAIN TABLE over one tuple per row, already padded to the table's row count: no squeezes (its output is a STATE,
/// not a fold), the same duplexing count per row so its HIGH variables are the row index and one column tie reaches every
/// row's tuple. ONE builder for every class — the note aggregate hashes the ABSORBED tuples, the slot-ledger aggregate
/// the PUBLISHED rows — and `rows_digest_of` is the same chain's final state.
pub(crate) fn chain_table_of(padded: &[Vec<Fa4>]) -> Option<Vec<Vec<Fa4>>> {
    let rows = padded.len();
    if rows == 0 {
        return None;
    }
    let chain_steps = crate::sponge_chain_air::replay_with_seed(
        crate::committed_air::COMMITTED_AIR_SEED,
        padded,
        &vec![0usize; rows],
    );
    if chain_steps.len() % rows != 0 {
        return None; // fail-closed: the chain must spend the same number of duplexings per carrier
    }
    let c_seg = (chain_steps.len() / rows).next_power_of_two();
    let ch = rows * c_seg;
    if chain_steps.len() > ch {
        return None;
    }
    let (chain_cols, _zero_fold) =
        crate::sponge_chain_air::build_trace_with_seed(crate::committed_air::COMMITTED_AIR_SEED, &chain_steps, ch);
    Some(chain_cols)
}

/// PROVE the block's note transition. Returns the bytes plus every PUBLIC value the block must publish
/// beside them: the shape, the per-carrier challenge folds, and `rows_digest`.
#[allow(clippy::type_complexity)]
pub fn prove_settlement_delta_bytes<C, F>(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    layout: DeltaLayout,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    inner: F,
) -> Option<(Vec<u8>, Vec<Fa4>)>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    let (tables, rows_digest) = settlement_delta_tables(carriers, layout)?;
    let bind = settlement_delta_bind(layout.n, domain, output_notes_root, del_set_root, &rows_digest);
    // ⛔ WAS `1 + DELTA_TUPLE_VALS` — HARDCODED, on BOTH the prove and the verify side. The ties then
    // checked the bind against the SINGLE-spend width while the layout carried the class's own, so a
    // cover transition died here with the tables already built. Fifth and last blocker of DB-83, and the
    // same class as the first: a constant standing in for a value the layout already knows.
    let (cross, cols) = settlement_delta_ties(
        layout,
        1 + layout.tuple_vals,
        DELTA_DOMAIN_OFF,
        delta_digest_off(output_notes_root.len(), del_set_root.len()),
    )?;
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_settlement_delta_constraint(layout, inner),
        Vec::new(),
        cross,
        cols,
        &bind,
    )?;
    Some((bytes, rows_digest))
}

/// VERIFY it. Every structural input is PUBLIC — the shape, both roots, the digest and the folds — so
/// the circuit and the ties are rebuilt from the statement, never from the prover's object.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_settlement_delta_bytes<C, F>(
    bytes: &[u8],
    layout: DeltaLayout,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    inner: F,
) -> bool
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    if rows_digest.len() != DIGEST_LANES {
        return false; // fail-closed: the statement must name a full digest
    }
    // ⛔ THE VERIFY-SIDE TWIN of the prove-side width. Both were `1 + DELTA_TUPLE_VALS`; a verifier that
    // rebuilds the ties at the SINGLE-spend width while the statement names another class checks a
    // different circuit than the one that was proved.
    let Some((cross, cols)) = settlement_delta_ties(
        layout,
        1 + layout.tuple_vals,
        DELTA_DOMAIN_OFF,
        delta_digest_off(output_notes_root.len(), del_set_root.len()),
    ) else {
        return false;
    };
    let bind = settlement_delta_bind(layout.n, domain, output_notes_root, del_set_root, rows_digest);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_settlement_delta_constraint(layout, inner),
        cross,
        cols,
        &bind,
        &match settlement_delta_table_shapes(layout) { Some(s) => s, None => return false }, &[],
    )
}

/// THE ONE PROVE SITE every delta class reaches (note, cover, bond here; member in `member_path_gate`): the real WHIR
/// aggregate, or — when `bound`, which only a test build's `_bound` entry passes — the bound template double
/// ([`delta_bound`]). One site, so no class can drift from the others in which form it lays.
#[allow(clippy::type_complexity)]
pub(crate) fn delta_prove<C, F>(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    layout: DeltaLayout,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    inner: F,
    bound: bool,
) -> Option<(Vec<u8>, Vec<Fa4>)>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    if bound {
        return delta_bound::prove(carriers, layout, domain, output_notes_root, del_set_root);
    }
    prove_settlement_delta_bytes(carriers, layout, domain, output_notes_root, del_set_root, inner)
}

/// THE ONE VERIFY SITE every delta class reaches — [`delta_prove`]'s twin. An armed door verifies the bound double ONLY:
/// it never falls back to the real verifier, and the real verifier never accepts the double's bytes.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(crate) fn delta_verify<C, F>(
    bytes: &[u8],
    layout: DeltaLayout,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    inner: F,
    bound: bool,
) -> bool
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    if bound {
        return delta_bound::verify(bytes, layout, domain, output_notes_root, del_set_root, rows_digest);
    }
    verify_settlement_delta_bytes(bytes, layout, domain, output_notes_root, del_set_root, rows_digest, inner)
}

/// ⭐⭐⭐ THE BOUND TEMPLATE DOUBLE — the test double of every delta-class PROVER (note, cover, bond, member), the band
/// double's law (`nf_compact_air::compact_band_bound`) applied to the block template's transitions (spec
/// `docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md`). The prove side builds the SAME tables the real prover builds
/// ([`settlement_delta_tables`] — every carrier parsed as a bound step of one shape, its transcript replayed, the walk
/// fitted to its segment, `rows_digest` from the one spelling a peer recomputes) and the same ties; it then drops ONLY the
/// WHIR prove, sealing the real verifier's whole public statement — the layout the circuit is rebuilt from and the bind
/// `n ‖ domain ‖ output_notes_root ‖ del_set_root ‖ rows_digest` — under a domain-separated blake3. So a moved root, a
/// different list (its digest), another class (its domain word or layout) or a flipped byte is REFUSED exactly as the
/// real door refuses it. 32 bytes never parse as a WHIR proof, and a WHIR proof is never these 32 bytes, so the two forms
/// cannot cross doors. Test builds only: outside them the prove side lays nothing and the verify side accepts nothing.
/// ⛔ NOT A SOUNDNESS DOOR, exactly as the band double is not: the tag is a hash of PUBLIC values, so an armed door trusts
/// the producer for what the aggregate's recursion would prove (each carrier verified under its bind). An HONEST producer
/// node verifies every carrier natively at its own door before stating it (the pool door, the template's
/// `carrier_verifies`), so an honest armed mesh lays and admits exactly what a real one does; a simulation with a ROGUE
/// producer must never arm it, and this crate's real-aggregate pins (never bound) carry the soundness.
mod delta_bound {
    use super::{DeltaLayout, Fa4};

    #[cfg(any(test, feature = "test-support"))]
    fn bytes(layout: &DeltaLayout, bind: &[Fa4]) -> Vec<u8> {
        seal(b"MUSD/test-bound-settlement-delta/v1", layout, bind)
    }

    /// The seal over a statement: the class's domain tag ‖ the layout words the circuit is rebuilt from ‖ the bind.
    #[cfg(any(test, feature = "test-support"))]
    fn seal(tag: &[u8], layout: &DeltaLayout, bind: &[Fa4]) -> Vec<u8> {
        use p3_field::PrimeField64;
        let mut h = blake3::Hasher::new();
        h.update(tag);
        let b = &layout.bound;
        for v in [
            layout.n,
            layout.seg_log,
            layout.slots,
            layout.tuple_vals,
            b.nvars,
            b.per,
            b.width,
            b.shifted_lo,
            b.shifted,
            b.powers,
            b.power_lo,
        ] {
            h.update(&(v as u64).to_le_bytes());
        }
        h.update(&(bind.len() as u64).to_le_bytes());
        for x in bind {
            h.update(&x.as_canonical_u64().to_le_bytes());
        }
        h.finalize().as_bytes().to_vec()
    }

    /// The statement both sides seal, built the way the real prove and verify build theirs: the ties must exist for this
    /// layout (`settlement_delta_ties`) or neither side has a circuit to stand for.
    #[cfg(any(test, feature = "test-support"))]
    fn statement(
        layout: DeltaLayout,
        domain: Fa4,
        output_notes_root: &[Fa4],
        del_set_root: &[Fa4],
        rows_digest: &[Fa4],
    ) -> Option<Vec<u8>> {
        super::settlement_delta_ties(
            layout,
            1 + layout.tuple_vals,
            super::DELTA_DOMAIN_OFF,
            super::delta_digest_off(output_notes_root.len(), del_set_root.len()),
        )?;
        super::settlement_delta_table_shapes(layout)?;
        let bind = super::settlement_delta_bind(layout.n, domain, output_notes_root, del_set_root, rows_digest);
        Some(bytes(&layout, &bind))
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn prove(
        carriers: &[(Vec<u8>, Vec<Fa4>)],
        layout: DeltaLayout,
        domain: Fa4,
        output_notes_root: &[Fa4],
        del_set_root: &[Fa4],
    ) -> Option<(Vec<u8>, Vec<Fa4>)> {
        #[cfg(any(test, feature = "test-support"))]
        {
            let (_tables, rows_digest) = super::settlement_delta_tables(carriers, layout)?;
            let b = statement(layout, domain, output_notes_root, del_set_root, &rows_digest)?;
            Some((b, rows_digest))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (carriers, layout, domain, output_notes_root, del_set_root);
            None
        }
    }

    pub(super) fn verify(
        b: &[u8],
        layout: DeltaLayout,
        domain: Fa4,
        output_notes_root: &[Fa4],
        del_set_root: &[Fa4],
        rows_digest: &[Fa4],
    ) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            if rows_digest.len() != crate::poseidon2_compress::DIGEST_LANES {
                return false; // the real verifier's first refusal, kept
            }
            statement(layout, domain, output_notes_root, del_set_root, rows_digest).is_some_and(|s| s.as_slice() == b)
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (b, layout, domain, output_notes_root, del_set_root, rows_digest);
            false
        }
    }

    /// THE LEDGER CLASS's double: its own domain tag over the ledger's layout and its whole bind (the note bind at the
    /// constant `n = LEDGER_ROWS` ‖ the header seed's commitment). The caller has already built the same ties and table
    /// shapes the real ledger prover and verifier build. `None` outside test builds: nothing is laid, nothing admitted.
    pub(super) fn ledger(layout: &DeltaLayout, bind: &[Fa4]) -> Option<Vec<u8>> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Some(seal(b"MUSD/test-bound-ledger/v1", layout, bind))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (layout, bind);
            None
        }
    }

    /// THE MEMBER LEDGER CLASS's double (`member_ledger`): its own domain tag over the member layout and its whole bind
    /// (the ledger bind ‖ the ring domain ‖ the `ring_digest`), so a member seal never stands for a note ledger's and a
    /// moved ring is refused. `None` outside test builds.
    pub(super) fn member_ledger(layout: &DeltaLayout, bind: &[Fa4]) -> Option<Vec<u8>> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Some(seal(b"MUSD/test-bound-member-ledger/v1", layout, bind))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (layout, bind);
            None
        }
    }

    pub(super) fn tag_ledger(layout: &DeltaLayout, bind: &[Fa4]) -> Option<Vec<u8>> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Some(seal(b"MUSD/test-bound-tag-ledger/v1", layout, bind))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = (layout, bind);
            None
        }
    }
}

/// The member ledger's bound seal ([`delta_bound`]'s member class), for `member_ledger`'s `_bound` entries: the caller
/// has built the same statement, ties and shapes the real member prover and verifier build. `None` outside test builds.
pub(crate) fn member_ledger_bound_seal(layout: &DeltaLayout, bind: &[Fa4]) -> Option<Vec<u8>> {
    delta_bound::member_ledger(layout, bind)
}

/// The tag ledger's bound double (padding spec §18) — the member ledger's rule, its own tag.
pub(crate) fn tag_ledger_bound_seal(layout: &DeltaLayout, bind: &[Fa4]) -> Option<Vec<u8>> {
    delta_bound::tag_ledger(layout, bind)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// PADDING v2 — THE SLOT-LEDGER CLASS (docs/NOTE-TRANSITION-TUPLE-PADDING-SPEC.md §2 / §2.6; lane-recursion 2026-09-30)
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// ⛔ THE LEAK: the note class publishes `n` tuples and states `n` twice more — the bind's first word and the wire
// shape's `n` — so every block tells the world its real spend count. The ledger class publishes a CONSTANT list of
// `LEDGER_ROWS` rows in canonical order (ascending `tag0`), every row 8 digests, and nothing in the list, the shape or
// the bind is a function of the real count.
//
// HOW (§2.6 — replicate the step, publish separately): every step row is still one carrier's bound WHIR step with the
// ABSORBED tuple its transcript took (tie 2 unchanged). A cover row is a REPLICA of `carriers[0]`'s step. Each row
// carries the slot-ledger extension (`slot_ledger`) whose laws select what the row PUBLISHES from its absorbed tuple
// (a spend) or from cover / justified cells, and the CHAIN — whose final state is `rows_digest` — hashes the PUBLISHED
// block instead of the absorbed one (tie 7 moved). The bind's `n` word is the constant `LEDGER_ROWS`, and the header
// seed's commitment is the one new public word.

/// The ledger class's constant row count — the list length, the step table's height and the bind's `n` word.
pub const LEDGER_ROWS: usize = crate::slot_ledger::SLOT_LEDGER_ROWS;
const _: () = assert!(
    crate::slot_ledger::PUB_DIGESTS * DIGEST_LANES == DELTA_TUPLE_VALS,
    "a published row has the absorbed tuple's width, so the chain's stride is unchanged"
);

/// One published row — `tag0 ‖ tag1 ‖ out0 ‖ out1 ‖ lc ‖ D ‖ flags ‖ 0`.
pub type LedgerPublished = [crate::poseidon2_compress::Digest; crate::slot_ledger::PUB_DIGESTS];

/// One row of the producer's plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    /// `Some(i)`: this row is the spend of `carriers[i]` (a spend witness). `None`: a cover row — a replica of
    /// `carriers[0]`'s step that publishes only cover and justified cells.
    pub spend_of: Option<usize>,
    pub witness: crate::slot_ledger::SlotLedgerWitness,
}

fn ledger_e8(d: &crate::poseidon2_compress::Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| Ea4::from(Fa4::from_u64(d[c])))
}

pub(crate) fn ledger_published_vals(p: &LedgerPublished) -> Vec<Fa4> {
    p.iter().flat_map(|d| d.iter().map(|v| Fa4::from_u64(*v))).collect()
}

/// The PRODUCER's one spelling of a block's rows: `n_spends` spend rows (carriers `0..n_spends`, each with a cover
/// `tag1`), then the block's justified NOTES and justified TAGS in the cells of cover rows, every other cell cover over
/// distinct slots. `None` when the block cannot be stated (more spends than rows, or more justified cells than the cover
/// rows hold). The node's header tags and note slots are derived from the SAME plan (the published cells ARE the
/// header's), which is why the plan is the decider's. ⛔ No device-slot claim is planned here: the producer must never
/// hold a claim's `(slot_key, d)` (DB-329 §7b, refuted 05:38) — the claim is the SPENDER's carrier law.
#[must_use]
pub fn plan_ledger_rows(
    seed: crate::poseidon2_compress::Digest,
    n_spends: usize,
    justified_notes: &[crate::poseidon2_compress::Digest],
    justified_tags: &[crate::poseidon2_compress::Digest],
    filing_d: &dyn Fn(&crate::poseidon2_compress::Digest, &crate::poseidon2_compress::Digest) -> Option<crate::poseidon2_compress::Digest>,
) -> Option<Vec<LedgerRow>> {
    plan_ledger_rows_with_tails(seed, n_spends, &[], justified_notes, justified_tags, filing_d)
}

/// ⭐ padding spec §18 — [`plan_ledger_rows`] with every stated spend's TAIL rows: `tails` holds, per tail row, the
/// spend's tag pair (`tags[2p], tags[2p+1]`, `p ≥ 1`; the head row publishes `tags[0], tags[1]` from its carrier) —
/// `n_spends × (PAIRS − 1)` entries, laid as hidden tail rows between the spend rows and the cover rows. The tail rows'
/// notes are cover notes at slots of their own; nothing on them is justified. `None` when the spends, their tails and
/// the justified cells do not fit the constant `LEDGER_ROWS`.
#[must_use]
pub fn plan_ledger_rows_with_tails(
    seed: crate::poseidon2_compress::Digest,
    n_spends: usize,
    tails: &[[crate::poseidon2_compress::Digest; 2]],
    justified_notes: &[crate::poseidon2_compress::Digest],
    justified_tags: &[crate::poseidon2_compress::Digest],
    filing_d: &dyn Fn(&crate::poseidon2_compress::Digest, &crate::poseidon2_compress::Digest) -> Option<crate::poseidon2_compress::Digest>,
) -> Option<Vec<LedgerRow>> {
    use crate::slot_ledger::{cover_note_native, SlotLedgerWitness, CELLS_PER_ROW};
    if n_spends > LEDGER_ROWS || tails.len() > LEDGER_ROWS - n_spends {
        return None;
    }
    let cover_rows = LEDGER_ROWS - n_spends - tails.len();
    if justified_notes.len() > CELLS_PER_ROW * cover_rows || justified_tags.len() > CELLS_PER_ROW * cover_rows {
        return None;
    }
    let (mut tag_slot, mut note_slot) = (0u64, 0u64);
    let mut rows = Vec::with_capacity(LEDGER_ROWS);
    for i in 0..n_spends {
        // DB-329 §7e: both of a spend row's tags are its carrier's statement (nullifier, proven claim) — no cover slot
        rows.push(LedgerRow { spend_of: Some(i), witness: SlotLedgerWitness::spend(seed) });
    }
    for (k, pair) in tails.iter().enumerate() {
        note_slot += 2;
        let mut w = SlotLedgerWitness::tail(seed, *pair, [note_slot - 1, note_slot]);
        w.slot_lc = (n_spends + k) as u64 + 1;
        let n0 = cover_note_native(seed, note_slot - 1);
        let n1 = cover_note_native(seed, note_slot);
        w.cover_d = filing_d(&n0, &n1)?;
        rows.push(LedgerRow { spend_of: None, witness: w });
    }
    let lc_base = n_spends + tails.len();
    for r in 0..cover_rows {
        let mut w = SlotLedgerWitness::cover(seed, [0; 4]);
        for k in 0..CELLS_PER_ROW {
            match justified_tags.get(CELLS_PER_ROW * r + k) {
                Some(t) => {
                    w.t[k] = true;
                    w.just_t[k] = *t;
                }
                None => {
                    tag_slot += 1;
                    w.slots[k] = tag_slot;
                }
            }
            match justified_notes.get(CELLS_PER_ROW * r + k) {
                Some(j) => {
                    w.j[k] = true;
                    w.just_n[k] = *j;
                }
                None => {
                    note_slot += 1;
                    w.slots[CELLS_PER_ROW + k] = note_slot;
                }
            }
        }
        // ⭐ padding v2 §9 — a cover row's `lc` is the cover law at a slot of its own (never shared, never zero-shaped)
        // and its `D` is the SAME public filing function a spend row's carrier bound over its own notes, so neither
        // column's content tells the classes apart (the content census in `ledger_tests`).
        w.slot_lc = (lc_base + r) as u64 + 1;
        let note = |k: usize| if w.j[k] { w.just_n[k] } else { cover_note_native(seed, w.slots[CELLS_PER_ROW + k]) };
        // a row whose notes have no filing digest (the filing function refuses them) states no D: the block is unstateable
        w.cover_d = filing_d(&note(0), &note(1))?;
        rows.push(LedgerRow { spend_of: None, witness: w });
    }
    Some(rows)
}

/// The structural checks a peer runs on a published list BEFORE any proof work: exactly `LEDGER_ROWS` rows, strictly
/// ascending `tag0` (the canonical order — a set, never a sequence the producer chose), flag lanes 0–3 boolean and the
/// rest zero, the last digest zero.
#[must_use]
pub fn ledger_list_is_canonical(published: &[LedgerPublished]) -> bool {
    use crate::slot_ledger::{PUB_DIGESTS, PUB_FLAGS, PUB_TAG0};
    if published.len() != LEDGER_ROWS {
        return false;
    }
    if published.windows(2).any(|w| w[0][PUB_TAG0] >= w[1][PUB_TAG0]) {
        return false;
    }
    published.iter().all(|p| {
        p[PUB_FLAGS].iter().take(4).all(|v| *v <= 1)
            && p[PUB_FLAGS].iter().skip(4).all(|v| *v == 0)
            && p[PUB_DIGESTS - 1].iter().all(|v| *v == 0)
    })
}

/// The ledger class's layout, from its constants alone — the spend carrier's committed shape at `LEDGER_ROWS` rows.
/// A verifier builds it; the producer's carriers must lay exactly it.
#[must_use]
pub fn ledger_class_layout() -> Option<DeltaLayout> {
    let nvars = (2 * crate::whir_rec_block::LIGHT_CARRIER_ROWS).trailing_zeros() as usize;
    // the ledger replicates the note-class step, which lays the vault region (spec §9.1)
    let width = crate::whir_rec_block::note_spend_row_width();
    let zero = [Ea4::ZERO; DIGEST_LANES];
    let inner = crate::committed_air::Blinded {
        inner: crate::whir_rec_block::SpendValidityGate {
            gamma: Ea4::ZERO,
            out0_cm: zero,
            out1_cm: zero,
            nullifier: zero,
            bond_amount: None,
            // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
            fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
            leaf_commit: zero,
            tag1: Some(zero), // the ledger replicates the note-class step, claim included (DB-329 §7e)
            vault: Some(crate::whir_rec_block::clock_const(0)), // and its vault region (spec §9.1)
        },
    };
    let base = BoundLayout { nvars, per: inner.degree(nvars) + 2, width, shifted_lo: 0, shifted: 0, powers: 0, power_lo: 0 };
    let probe = spend_delta_factory(DeltaLayout {
        bound: base,
        n: 1,
        seg_log: 0,
        slots: LEDGER_ROWS,
        tuple_vals: DELTA_TUPLE_VALS,
    });
    let powers = class_residual_count(&probe, base);
    delta_layout(base, powers, LEDGER_ROWS, LEDGER_ROWS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS)
}

/// The ledger statement: the note class's bind at the CONSTANT `n = LEDGER_ROWS`, then the header seed's commitment.
pub(crate) fn ledger_bind(
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    seed_commit: &crate::poseidon2_compress::Digest,
) -> Vec<Fa4> {
    let mut b = settlement_delta_bind(LEDGER_ROWS, domain, output_notes_root, del_set_root, rows_digest);
    b.extend(seed_commit.iter().map(|v| Fa4::from_u64(*v)));
    b
}

/// Index of the CLOCK digest in a row's absorbed tuple: the seventh digest a note-class spend's transcript absorbs
/// (`whir_rec_block::note_spend_public_bind`), never published.
pub const LEDGER_ABS_CLOCK: usize = 6;
const _: () = assert!(LEDGER_ABS_CLOCK < DIGESTS_PER_TUPLE);

/// ⭐ THE NOTE LEDGER's statement (spec §9.1): [`ledger_bind`], then THE BLOCK'S CLOCK. Every row of the ledger proves
/// its carrier's clock is at or before this value (`LedgerDeltaAir`), and the door checks this value against the
/// chain's own clock, so no spend is stated under a clock the chain has not reached and no per-spend time is published.
pub(crate) fn note_ledger_bind(
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    seed_commit: &crate::poseidon2_compress::Digest,
    block_clock_h: u64,
) -> Vec<Fa4> {
    let mut b = ledger_bind(domain, output_notes_root, del_set_root, rows_digest, seed_commit);
    b.extend(crate::whir_rec_block::clock_lanes(block_clock_h).iter().map(|v| Fa4::from_u64(*v)));
    b
}

/// The ledger's ties: every note-class tie EXCEPT the chain's (group 7), which moves from the ABSORBED tuple to the
/// PUBLISHED block of the extension — so `rows_digest` is the digest of what the wire carries.
fn ledger_delta_ties(
    layout: DeltaLayout,
    onr_len: usize,
    dsr_len: usize,
) -> Option<(Vec<CrossTieSpec>, Vec<crate::whir_rec_block::ColumnTieSpec>)> {
    ledger_delta_ties_at(layout, onr_len, dsr_len, layout.step_cols() + crate::slot_ledger::SL_PUB)
}

/// The class's ties for a statement with NO chain (the tag ledger, whose rows tie directly to the note ledger's): groups 7 and 8
/// state the chain and its digest, and there is neither.
pub(crate) fn ledger_delta_ties_no_chain(
    layout: DeltaLayout,
    onr_len: usize,
    dsr_len: usize,
) -> Option<(Vec<CrossTieSpec>, Vec<crate::whir_rec_block::ColumnTieSpec>)> {
    settlement_delta_ties_masked(layout, 1 + layout.tuple_vals, DELTA_DOMAIN_OFF, delta_digest_off(onr_len, dsr_len), u8::MAX ^ 64 ^ 128)
}

/// THE ONE LEDGER TIE SITE (note ledger and member ledger): the class's ties with the chain's group re-pointed at the
/// step table's PUBLISHED block, `layout.tuple_vals` cells starting at column `pub_col`.
pub(crate) fn ledger_delta_ties_at(
    layout: DeltaLayout,
    onr_len: usize,
    dsr_len: usize,
    pub_col: usize,
) -> Option<(Vec<CrossTieSpec>, Vec<crate::whir_rec_block::ColumnTieSpec>)> {
    let (cross, mut cols) = settlement_delta_ties_masked(
        layout,
        1 + layout.tuple_vals,
        DELTA_DOMAIN_OFF,
        delta_digest_off(onr_len, dsr_len),
        u8::MAX ^ 64,
    )?;
    let rows = layout.rows();
    let (c_absorbed, _c_sq, c_steps) = plan(&vec![layout.tuple_vals; rows], &vec![0usize; rows])?;
    if c_steps % rows != 0 {
        return None;
    }
    let c_seg_log = (c_steps / rows).next_power_of_two().trailing_zeros() as usize;
    let per: Vec<(usize, usize)> = c_absorbed.iter().take(layout.tuple_vals).copied().collect();
    tie_run(
        &mut cols,
        &per,
        layout.chain_table(),
        c_seg_log,
        layout.step_table(),
        pub_col,
    );
    Some((cross, cols))
}

/// The three table shapes, the step table widened by the extension.
fn ledger_table_shapes(layout: DeltaLayout) -> Option<Vec<(usize, usize)>> {
    let mut s = settlement_delta_table_shapes(layout)?;
    s[layout.step_table()].1 = layout.step_cols() + crate::slot_ledger::SL_EXT_COLS + crate::whir_rec_block::CLOCK_LE_WIDTH;
    Some(s)
}

/// The ledger aggregate's per-table circuit: the note class's circuit, plus — on the step table — the slot-ledger laws
/// over the row's extension, reading the row's ABSORBED tuple as the spend statement.
///
/// ⛔ THE BATCHING OFFSET. The bound step folds its residuals as `Σ γ^i r_i` for `i < R`, with
/// `R ≤ 2·nvars + powers + 6` (the round chain, the committed end, the capacity guard, the power ladder's two rungs, the
/// latch and the close). The ledger laws are folded from `γ^K` with `K = 2·nvars + powers + 16 > R`, so the two sets'
/// coefficients never share a power of γ and a violation in one cannot be cancelled by a chosen violation in the other.
pub struct LedgerDeltaAir<C, F>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    base: SettlementDeltaAir<C, F>,
    step: bool,
    ext: usize,
    tuple_off: usize,
    seed_commit: [Ea4; DIGEST_LANES],
    /// The block's clock in chain hours (spec §9.1): the verifier's value, on every row.
    block_clock: Ea4,
    offset: u64,
    gamma: Ea4,
}

impl<C, F> AirConstraint for LedgerDeltaAir<C, F>
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    fn degree(&self, nvars: usize) -> usize {
        let b = self.base.degree(nvars);
        if self.step {
            b.max(crate::slot_ledger::slot_ledger_law_degree())
        } else {
            b
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let b = self.base.eval(local, at, x);
        if !self.step {
            return b;
        }
        let mut rs: Vec<Ea4> = Vec::new();
        let tuple_off = self.tuple_off;
        let abs = |k: usize, c: usize| local[tuple_off + k * DIGEST_LANES + c];
        crate::slot_ledger::push_slot_ledger_laws(&mut rs, local, self.ext, &abs, &self.seed_commit);
        // ⭐ THE CLOCK LAW (spec §9.1), on EVERY row, spend or cover (a cover row replicates a real step, clock included):
        // the row's absorbed clock is at or before the block's, and its digest is the canonical four limbs.
        crate::whir_rec_block::push_clock_le(&mut rs, local, self.ext + crate::slot_ledger::SL_EXT_COLS, abs(LEDGER_ABS_CLOCK, 0), self.block_clock);
        for c in 1..DIGEST_LANES {
            rs.push(abs(LEDGER_ABS_CLOCK, c));
        }
        let mut acc = Ea4::ZERO;
        let mut gp = self.gamma.exp_u64(self.offset);
        for r in rs {
            acc += gp * r;
            gp *= self.gamma;
        }
        b + acc
    }
    fn has_base_eval(&self) -> bool {
        !self.step && self.base.has_base_eval()
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        self.base.eval_base(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        self.base.is_row_local()
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        self.base.shifted_cols()
    }
    /// The note class's declaration (the absorbed tuple is bound by its sponge tie, never by a law of this table); the
    /// extension declares nothing — every one of its columns is read (`slot_ledger::slot_ledger_free_columns`).
    fn free_columns(&self) -> Option<Vec<usize>> {
        self.base.free_columns()
    }
}

/// The ledger constraint factory BOTH sides derive from public values: the layout, the class's per-row gate and the
/// header seed's commitment.
pub fn make_ledger_delta_constraint<C, F>(
    layout: DeltaLayout,
    inner: F,
    seed_commit: [Ea4; DIGEST_LANES],
    block_clock_h: u64,
) -> impl Fn(usize, Ea4) -> LedgerDeltaAir<C, F> + Clone
where
    C: AirConstraint + Clone + Sync,
    F: Fn(&Row<'_>) -> C + Clone + Sync,
{
    let base = make_settlement_delta_constraint(layout, inner);
    let offset = (2 * layout.bound.nvars + layout.bound.powers + 16) as u64;
    let block_clock = crate::whir_rec_block::clock_const(block_clock_h);
    move |table: usize, gamma: Ea4| LedgerDeltaAir {
        base: base(table, gamma),
        step: table == layout.step_table(),
        ext: layout.step_cols(),
        tuple_off: layout.tuple_off(),
        seed_commit,
        block_clock,
        offset,
        gamma,
    }
}

/// The ledger class's public shape, from its constants alone ([`ledger_class_layout`]) — the one value the node writes
/// in a ledger transition's `shape` field and its door requires, the same for a quiet and a busy block.
#[must_use]
pub fn ledger_class_shape() -> Option<DeltaShape> {
    ledger_class_layout().map(shape_of_layout)
}

/// THE NULL CARRIER — the replica source for a block with no spend. A spend carrier over a synthetic zero-value note
/// (conservation F = 0 + 0 + F, §BR-14) with every key, the cross-bind's blinding and the filing digest fresh from the OS CSPRNG,
/// so its absorbed statement is fresh digests. Its row publishes as cover (`is_spend = 0`): nothing it states reaches
/// the wire or any set. `None` when the OS source refuses — a producer with no replica source lays no ledger.
#[must_use]
pub fn null_spend_carrier() -> Option<(Vec<u8>, Vec<Fa4>)> {
    let r = crate::whir_rec_block::fresh_lc_blind;
    // §BR-14: the null carrier pays the protocol fee out of its synthetic input (in = F = 0 + F), as every row the
    // aggregate welds must; its outputs stay zero-value, and nothing it states reaches a set or the pools.
    let w = crate::whir_rec_block::SpendValidityWitness {
        value_in: crate::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        owner: crate::whir_rec_block::NoteOwner { ask: r()?, nk: r()?, seed: r()? },
        value_out: 0,
        fee: crate::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        lc_blind: r()?,
        out0_value: 0,
        out0_opening: r()?,
        out1_value: 0,
        out1_opening: r()?,
    };
    let d = r()?;
    let (bytes, cms, nf, lc) = crate::whir_rec_block::prove_spend_validity_carrier_with_commit_bytes(&w, d)?;
    let tag1 = crate::whir_rec_block::spend_tag1(&w);
    let f = |x: crate::poseidon2_compress::Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|c| Fa4::from_u64(x[c])) };
    let pb = crate::whir_rec_block::validity_public_bind_with_commit(&[f(cms[0]), f(cms[1])], &f(nf), &f(lc), &f(d), &f(tag1));
    Some((bytes, pb))
}

/// PRODUCER — lay a block's slot ledger. `carriers` are the block's real spend carriers (or ONE null carrier for a
/// block with no spend); `rows` is exactly `LEDGER_ROWS` rows (`plan_ledger_rows`). Returns the proof, the PUBLISHED list
/// in canonical order (ascending `tag0`) and `rows_digest`. `None` on anything unstateable: a carrier spent twice, a
/// spend row with a cover witness or the reverse, a witness under another seed, two rows publishing one tag, carriers of
/// another shape than the class's.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_ledger_transition(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    prove_block_ledger_transition_at(carriers, rows, domain, output_notes_root, del_set_root, seed, 0)
}

/// [`prove_block_ledger_transition`] under THE BLOCK'S CLOCK `block_clock_h` (spec §9.1): every carrier's clock must be
/// at or before it, or the ledger is unstateable (`None`). The unclocked entry is this at clock 0, which states only
/// carriers proven against clock 0.
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn prove_block_ledger_transition_at(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
    block_clock_h: u64,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    prove_block_ledger_transition_with(carriers, rows, domain, output_notes_root, del_set_root, seed, block_clock_h, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_ledger_transition`] with the BOUND template double ([`delta_bound`]): the same
/// row checks, the same canonical order, the same tables, ties and bind, then a 32-byte seal in place of the WHIR prove.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_ledger_transition_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    prove_block_ledger_transition_bound_at(carriers, rows, domain, output_notes_root, del_set_root, seed, 0)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_ledger_transition_bound`] under the block's clock.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn prove_block_ledger_transition_bound_at(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
    block_clock_h: u64,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    prove_block_ledger_transition_with(carriers, rows, domain, output_notes_root, del_set_root, seed, block_clock_h, true)
}

/// THE ONE LEDGER PROVE SITE — real, or (only from a test build's `_bound` entry) the bound double. Both forms lay from
/// the same checks and tables, so no ledger refusal can live in one form only.
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn prove_block_ledger_transition_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
    block_clock_h: u64,
    bound: bool,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    let l = lay_block_ledger(carriers, rows, domain, output_notes_root, del_set_root, seed, block_clock_h)?;
    if bound {
        ledger_table_shapes(l.layout)?;
        return Some((delta_bound::ledger(&l.layout, &l.bind)?, l.published, l.rows_digest));
    }
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        l.tables,
        make_ledger_delta_constraint(l.layout, spend_delta_factory(l.layout), ledger_e8(&l.seed_commit), block_clock_h),
        Vec::new(),
        l.cross,
        l.cols,
        &l.bind,
    )?;
    Some((bytes, l.published, l.rows_digest))
}

/// ⭐ R4 lever 4 — the note ledger as ONE STATEMENT of a joined light-decider batch (`light_batch_merge`): the same lay,
/// constraint, ties and bind [`prove_block_ledger_transition`] hands the engine, handed to the merge instead; the published
/// list and rows digest exactly as that prove returns them.
#[allow(clippy::type_complexity)]
pub fn lay_block_ledger_statement(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
) -> Option<(crate::light_batch_merge::LaidStatement<'static>, Vec<LedgerPublished>, Vec<Fa4>)> {
    lay_block_ledger_statement_at(carriers, rows, domain, output_notes_root, del_set_root, seed, 0)
}

/// [`lay_block_ledger_statement`] under THE BLOCK'S CLOCK (spec §9.1) — the form a producer lays.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn lay_block_ledger_statement_at(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
    block_clock_h: u64,
) -> Option<(crate::light_batch_merge::LaidStatement<'static>, Vec<LedgerPublished>, Vec<Fa4>)> {
    let l = lay_block_ledger(carriers, rows, domain, output_notes_root, del_set_root, seed, block_clock_h)?;
    let mk = make_ledger_delta_constraint(l.layout, spend_delta_factory(l.layout), ledger_e8(&l.seed_commit), block_clock_h);
    let statement = crate::light_batch_merge::LaidStatement {
        tables: l.tables,
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        buses: Vec::new(),
        cross: l.cross,
        cols: l.cols,
        joint: Vec::new(),
        bind: l.bind,
    };
    Some((statement, l.published, l.rows_digest))
}

/// ⭐ R4 lever 4 — the note ledger's statement for a joined VERIFY, derived from the peer's own inputs exactly as
/// [`verify_block_ledger_transition`] derives them (the canonical-list check included).
#[must_use]
pub fn block_ledger_stated_statement(
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
) -> Option<crate::light_batch_merge::StatedStatement<'static>> {
    block_ledger_stated_statement_at(domain, output_notes_root, del_set_root, seed_commit, published, 0)
}

/// [`block_ledger_stated_statement`] under THE BLOCK'S CLOCK (spec §9.1) — the form a door derives; the door checks
/// `block_clock_h` against the chain's clock before it calls this.
#[must_use]
pub fn block_ledger_stated_statement_at(
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
) -> Option<crate::light_batch_merge::StatedStatement<'static>> {
    if !ledger_list_is_canonical(published) {
        return None;
    }
    let layout = ledger_class_layout()?;
    let pvals: Vec<Vec<Fa4>> = published.iter().map(ledger_published_vals).collect();
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, DELTA_TUPLE_VALS)?;
    let (cross, cols) = ledger_delta_ties(layout, output_notes_root.len(), del_set_root.len())?;
    let constraint_shapes = ledger_table_shapes(layout)?;
    let bind = note_ledger_bind(domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, block_clock_h);
    let mk = make_ledger_delta_constraint(layout, spend_delta_factory(layout), ledger_e8(&seed_commit), block_clock_h);
    Some(crate::light_batch_merge::StatedStatement {
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        cross,
        cols,
        joint: Vec::new(),
        bind,
        constraint_shapes,
        bus_shapes: Vec::new(),
    })
}

/// One laid note ledger: everything a prove (real, bound or joined) needs.
struct LedgerLay {
    tables: Vec<Vec<Vec<Fa4>>>,
    layout: DeltaLayout,
    cross: Vec<crate::whir_rec_block::CrossTieSpec>,
    cols: Vec<crate::whir_rec_block::ColumnTieSpec>,
    bind: Vec<Fa4>,
    seed_commit: crate::poseidon2_compress::Digest,
    published: Vec<LedgerPublished>,
    rows_digest: Vec<Fa4>,
}

/// The note ledger's lay — the ONE site every prove form reads (the row checks, the canonical order, the tables, the
/// ties and the bind), so no ledger refusal can live in one form only.
fn lay_block_ledger(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: crate::poseidon2_compress::Digest,
    block_clock_h: u64,
) -> Option<LedgerLay> {
    use crate::slot_ledger as sl;
    use p3_field::PrimeField64;
    if carriers.is_empty() || rows.len() != LEDGER_ROWS {
        return None;
    }
    let mut spent = vec![false; carriers.len()];
    for r in rows {
        if r.witness.seed != seed || !r.witness.is_well_formed() {
            return None;
        }
        match r.spend_of {
            Some(i) => {
                if i >= carriers.len() || spent[i] || !r.witness.is_spend {
                    return None;
                }
                spent[i] = true;
            }
            None => {
                if r.witness.is_spend {
                    return None;
                }
            }
        }
    }
    let abs_of = |pb: &[Fa4]| -> Option<[crate::poseidon2_compress::Digest; sl::ABS_DIGESTS]> {
        if pb.len() != 1 + DELTA_TUPLE_VALS {
            return None;
        }
        Some(core::array::from_fn(|k| core::array::from_fn(|c| pb[1 + k * DIGEST_LANES + c].as_canonical_u64())))
    };
    // the clock a carrier's transcript absorbed (its seventh digest): an hour count in lane 0, the other lanes zero
    let clock_of = |pb: &[Fa4]| -> Option<u64> {
        if pb.len() != 1 + DELTA_TUPLE_VALS {
            return None;
        }
        let d: crate::poseidon2_compress::Digest =
            core::array::from_fn(|c| pb[1 + LEDGER_ABS_CLOCK * DIGEST_LANES + c].as_canonical_u64());
        crate::whir_rec_block::clock_of_lanes(&d)
    };
    let ext_cols = sl::SL_EXT_COLS + crate::whir_rec_block::CLOCK_LE_WIDTH;
    // each row: its SOURCE carrier (the spend's own, or the replica source), its extension and what it publishes
    let mut laid: Vec<(usize, Vec<Fa4>, LedgerPublished)> = Vec::with_capacity(LEDGER_ROWS);
    for r in rows {
        let src = match r.spend_of {
            Some(i) => i,
            None => 0,
        };
        let abs = abs_of(&carriers[src].1)?;
        let mut ext = vec![Fa4::ZERO; ext_cols];
        let p = sl::lay_slot_ledger_row(&mut ext, 0, &abs, &r.witness);
        // spec §9.1: the row's clock block. A carrier proven against a clock past the block's is unstateable here.
        crate::whir_rec_block::fill_clock_le(&mut ext, sl::SL_EXT_COLS, clock_of(&carriers[src].1)?, block_clock_h)?;
        laid.push((src, ext, p));
    }
    // THE CANONICAL ORDER: ascending tag0, strictly — two rows publishing one tag state nothing a set can hold
    laid.sort_by(|a, b| a.2[sl::PUB_TAG0].cmp(&b.2[sl::PUB_TAG0]));
    if laid.windows(2).any(|w| w[0].2[sl::PUB_TAG0] == w[1].2[sl::PUB_TAG0]) {
        return None;
    }
    let expanded: Vec<(Vec<u8>, Vec<Fa4>)> = laid.iter().map(|(s, _, _)| carriers[*s].clone()).collect();
    // the carriers must lay exactly the class's layout
    let base = delta_base_layout(&expanded, DELTA_TUPLE_VALS, domain)?;
    let probe = spend_delta_factory(DeltaLayout { bound: base, n: 1, seg_log: 0, slots: LEDGER_ROWS, tuple_vals: DELTA_TUPLE_VALS });
    let powers = class_residual_count(&probe, base);
    let layout = delta_layout(base, powers, LEDGER_ROWS, LEDGER_ROWS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS)?;
    if Some(shape_of_layout(layout)) != ledger_class_layout().map(shape_of_layout) {
        return None;
    }
    let (mut tables, _absorbed_digest) = settlement_delta_tables(&expanded, layout)?;
    let step = layout.step_table();
    for c in 0..ext_cols {
        tables[step].push(laid.iter().map(|(_, e, _)| e[c]).collect());
    }
    let published: Vec<LedgerPublished> = laid.iter().map(|x| x.2).collect();
    let pvals: Vec<Vec<Fa4>> = published.iter().map(ledger_published_vals).collect();
    tables[layout.chain_table()] = chain_table_of(&pvals)?;
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, DELTA_TUPLE_VALS)?;
    let seed_commit = sl::seed_commit_native(seed);
    let bind = note_ledger_bind(domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, block_clock_h);
    let (cross, cols) = ledger_delta_ties(layout, output_notes_root.len(), del_set_root.len())?;
    Some(LedgerLay { tables, layout, cross, cols, bind, seed_commit, published, rows_digest })
}

/// PEER — verify a block's slot ledger from what the block carries: the proof, the header seed's commitment and the
/// published list. The layout is the class's (no shape rides the wire), `rows_digest` is recomputed from the list, and
/// the list's structure is checked before any proof work.
#[must_use]
pub fn verify_block_ledger_transition(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
) -> bool {
    verify_block_ledger_transition_at(bytes, domain, output_notes_root, del_set_root, seed_commit, published, 0)
}

/// [`verify_block_ledger_transition`] under THE BLOCK'S CLOCK (spec §9.1). A ledger proven under one clock verifies under
/// no other; the door checks `block_clock_h` against the chain's clock.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_block_ledger_transition_at(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
) -> bool {
    verify_block_ledger_transition_with(bytes, domain, output_notes_root, del_set_root, seed_commit, published, block_clock_h, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_ledger_transition`] on an ARMED door: it accepts the bound double's bytes and
/// nothing else (never a real proof, never a fallback to the real verifier).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_block_ledger_transition_bound(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
) -> bool {
    verify_block_ledger_transition_bound_at(bytes, domain, output_notes_root, del_set_root, seed_commit, published, 0)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_ledger_transition_bound`] under the block's clock.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_block_ledger_transition_bound_at(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
) -> bool {
    verify_block_ledger_transition_with(bytes, domain, output_notes_root, del_set_root, seed_commit, published, block_clock_h, true)
}

/// THE ONE LEDGER VERIFY SITE — [`prove_block_ledger_transition_with`]'s twin: every structural check runs before the
/// form is chosen, so an armed door refuses exactly what a real one refuses.
#[must_use]
#[allow(clippy::too_many_arguments)]
fn verify_block_ledger_transition_with(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: crate::poseidon2_compress::Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
    bound: bool,
) -> bool {
    if bytes.is_empty() || !ledger_list_is_canonical(published) {
        return false;
    }
    let Some(layout) = ledger_class_layout() else { return false };
    let pvals: Vec<Vec<Fa4>> = published.iter().map(ledger_published_vals).collect();
    let Some(rows_digest) = rows_digest_of(&pvals, LEDGER_ROWS, DELTA_TUPLE_VALS) else { return false };
    let Some((cross, cols)) = ledger_delta_ties(layout, output_notes_root.len(), del_set_root.len()) else {
        return false;
    };
    let Some(shapes) = ledger_table_shapes(layout) else { return false };
    let bind = note_ledger_bind(domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, block_clock_h);
    if bound {
        return delta_bound::ledger(&layout, &bind).is_some_and(|s| s.as_slice() == bytes);
    }
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_ledger_delta_constraint(layout, spend_delta_factory(layout), ledger_e8(&seed_commit), block_clock_h),
        cross,
        cols,
        &bind,
        &shapes,
        &[],
    )
}

#[cfg(test)]
mod rows_digest_native_tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    /// ⭐ PERF EQUALITY (lane stable 2026-11-01) — `rows_digest_of` reads the last duplexing's output; the trace form laid
    /// every round to read the same cells. They must agree on every production shape a peer recomputes: the ledger
    /// (`LEDGER_ROWS` rows of `DELTA_TUPLE_VALS`), a short and a full list, distinct and repeated tuples. A planted
    /// difference (one tuple value changed) must change the digest, so the equality is not of two constants.
    #[test]
    fn rows_digest_reads_the_last_duplexing_output_the_trace_lays() {
        let tuple = |seed: u64, w: usize| -> Vec<Fa4> { (0..w as u64).map(|i| Fa4::from_u64(seed.wrapping_mul(1_000_003) + i * 7 + 1)).collect() };
        for (slots, w) in [(LEDGER_ROWS, DELTA_TUPLE_VALS), (16, DELTA_TUPLE_VALS), (8, DIGEST_LANES * 2)] {
            for real in [1usize, 3, slots] {
                let tuples: Vec<Vec<Fa4>> = (0..real as u64).map(|s| tuple(s + 11, w)).collect();
                let native = rows_digest_of(&tuples, slots, w).expect("a digest");
                let traced = rows_digest_of_by_trace(&tuples, slots).expect("the trace digest");
                assert_eq!(native, traced, "⛔ the native digest differs from the trace's at slots {slots}, width {w}, {real} real");
                let mut planted = tuples.clone();
                planted[0][0] += Fa4::ONE;
                assert_ne!(rows_digest_of(&planted, slots, w).expect("a digest"), native, "CALIBRATION: a changed tuple changes the digest");
            }
        }
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;
    use crate::poseidon2_compress::{lanes_of, Digest};
    use crate::slot_ledger::{cover_note_native, cover_tag_native, seed_commit_native, PUB_FLAGS, PUB_LC, PUB_OUT0, PUB_OUT1, PUB_TAG0, PUB_TAG1};
    use crate::whir_rec_block::SPEND_VALIDITY_DOMAIN;

    // PRODUCTION-SCALE-REVIEWED: every block these pins prove IS the production ledger — LEDGER_ROWS = 128 rows,
    // 256 tag cells and 256 note cells, the constant the class fixes; the spend counts below are how many of those
    // production rows are real, which is the variable the pins are about.

    fn roots() -> (Vec<Fa4>, Vec<Fa4>) {
        (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4])
    }
    fn seed() -> Digest {
        lanes_of(&[0x5eed, 0x1ed6, 3, 4])
    }
    /// The test filing function: a Poseidon pair of the row's two notes. The node's is `oli::filing_d` (blake3 over the
    /// block's `oli_tags`), which this crate cannot spell; the decider only carries what the producer computed.
    fn test_filing_d(out0: &Digest, out1: &Digest) -> Option<Digest> {
        Some(crate::nullifier_insert_air::poseidon_pair_native(*out0, *out1))
    }
    fn abs_nf_out(pb: &[Fa4]) -> (Digest, Digest, Digest) {
        use p3_field::PrimeField64;
        let d = |k: usize| -> Digest { core::array::from_fn(|c| pb[1 + k * DIGEST_LANES + c].as_canonical_u64()) };
        (d(crate::slot_ledger::ABS_NULLIFIER), d(crate::slot_ledger::ABS_OUT0), d(crate::slot_ledger::ABS_OUT1))
    }

    /// ⭐ V2 PIECE 2 — THE TREE LEDGER on the production ledger (LEDGER_ROWS rows, two real spends), beside today's ledger on
    /// the SAME block: it lays the SAME published list and rows digest, it verifies, its bytes are printed against today's,
    /// and its door refuses every statement change today's door refuses — a swapped list, another seed commitment, a moved
    /// root, a later block clock, one flipped byte — and it never crosses with today's proof (each door refuses the other's).
    #[test]
    fn tree_ledger_states_the_same_list_in_fewer_bytes_and_refuses_every_tamper() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let sc = seed_commit_native(s);
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2u64).map(super::tests::spend).collect();
        let rows = plan_ledger_rows(s, carriers.len(), &[], &[], &test_filing_d).expect("the block is stateable");
        let t = std::time::Instant::now();
        let (rb, rp, rd) = prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).expect("today's ledger proves");
        let today_ms = t.elapsed().as_millis();
        let pbs: Vec<Vec<Fa4>> = carriers.iter().map(|c| c.1.clone()).collect();
        let t = std::time::Instant::now();
        let (tb, tp, td) = crate::tree_ledger::prove_tree_ledger(&pbs, &rows, dom, &onr, &dsr, s, 0).expect("the tree ledger proves");
        let tree_ms = t.elapsed().as_millis();
        eprintln!(
            "[tree-ledger] today's note ledger {} B in {today_ms} ms; the tree ledger {} B in {tree_ms} ms ({:.1} % of today's bytes)",
            rb.len(),
            tb.len(),
            100.0 * tb.len() as f64 / rb.len() as f64
        );
        assert_eq!((&tp, &td), (&rp, &rd), "the tree ledger lays today's published list and rows digest, byte for byte");
        let v = |b: &[u8], onr: &[Fa4], sc: Digest, p: &[LedgerPublished], clock: u64| {
            crate::tree_ledger::verify_tree_ledger(b, dom, onr, &dsr, sc, p, clock)
        };
        assert!(v(&tb, &onr, sc, &tp, 0), "CALIBRATION: the tree ledger's door takes the honest proof");
        let mut swapped = tp.clone();
        let (a, b) = (swapped[0][PUB_OUT0], swapped[1][PUB_OUT0]);
        assert_ne!(a, b, "CALIBRATION: the two rows publish different outputs");
        swapped[0][PUB_OUT0] = b;
        swapped[1][PUB_OUT0] = a;
        assert!(!v(&tb, &onr, sc, &swapped, 0), "⛔ the tree ledger over a swapped list");
        assert!(!v(&tb, &onr, seed_commit_native(lanes_of(&[9, 9, 9, 9])), &tp, 0), "⛔ the tree ledger under another seed commit");
        assert!(!v(&tb, &vec![Fa4::from_u64(0xC3); onr.len()], sc, &tp, 0), "⛔ the tree ledger under a moved root");
        assert!(!v(&tb, &onr, sc, &tp, 1), "⛔ the tree ledger under another block clock");
        let mut flipped = tb.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        assert!(!v(&flipped, &onr, sc, &tp, 0), "⛔ the tree ledger with a flipped byte");
        assert!(!v(&rb, &onr, sc, &rp, 0), "⛔ the tree ledger's door accepted TODAY's proof");
        assert!(!verify_block_ledger_transition(&tb, dom, &onr, &dsr, sc, &tp), "⛔ today's door accepted a TREE ledger proof");
    }

    /// ⛔ THE LEDGER BOUND DOUBLE (sim-speed spec `docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md`, the ledger class).
    /// CALIBRATION: an armed door admits the honest double and the list is the real prover's list, byte for byte. Then
    /// every statement change a real door refuses is REFUSED by the armed door — a moved root, another header seed's
    /// commitment, two rows' outputs exchanged, one flipped byte — and the two forms never cross: the real verifier
    /// refuses the 32 B, the armed verifier refuses a real proof.
    #[test]
    fn the_ledger_bound_double_admits_the_honest_ledger_and_refuses_every_tamper() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let sc = seed_commit_native(s);
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2u64).map(super::tests::spend).collect();
        let rows = plan_ledger_rows(s, carriers.len(), &[], &[], &test_filing_d).expect("the block is stateable");
        let t = std::time::Instant::now();
        let (bb, bp, bd) =
            prove_block_ledger_transition_bound(&carriers, &rows, dom, &onr, &dsr, s).expect("the double lays the ledger");
        eprintln!("[ledger-bound] {} B, prove {} ms", bb.len(), t.elapsed().as_millis());
        assert_eq!(bb.len(), 32, "the double is a 32 B seal");
        assert_eq!(bp.len(), LEDGER_ROWS, "the double's list is the class's constant list");
        assert!(verify_block_ledger_transition_bound(&bb, dom, &onr, &dsr, sc, &bp), "CALIBRATION: an armed door takes the double");
        let other_onr = vec![Fa4::from_u64(0xC3); onr.len()];
        assert!(!verify_block_ledger_transition_bound(&bb, dom, &other_onr, &dsr, sc, &bp), "⛔ the double under a moved root");
        let other_sc = seed_commit_native(lanes_of(&[9, 9, 9, 9]));
        assert!(!verify_block_ledger_transition_bound(&bb, dom, &onr, &dsr, other_sc, &bp), "⛔ the double under another seed commit");
        let mut swapped = bp.clone();
        let (a, b) = (swapped[0][PUB_OUT0], swapped[1][PUB_OUT0]);
        assert_ne!(a, b, "CALIBRATION: the two rows publish different outputs");
        swapped[0][PUB_OUT0] = b;
        swapped[1][PUB_OUT0] = a;
        assert!(!verify_block_ledger_transition_bound(&bb, dom, &onr, &dsr, sc, &swapped), "⛔ the double over a swapped list");
        let mut flipped = bb.clone();
        flipped[7] ^= 1;
        assert!(!verify_block_ledger_transition_bound(&flipped, dom, &onr, &dsr, sc, &bp), "⛔ the double with a flipped byte");
        assert!(!verify_block_ledger_transition(&bb, dom, &onr, &dsr, sc, &bp), "⛔ a REAL door accepted the 32 B double");
        let (rb, rp, rd) = prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).expect("the real ledger proves");
        assert_eq!((&rp, &rd), (&bp, &bd), "the double lays the real prover's list and digest");
        assert!(verify_block_ledger_transition(&rb, dom, &onr, &dsr, sc, &rp), "CALIBRATION: the real door takes the real proof");
        assert!(!verify_block_ledger_transition_bound(&rb, dom, &onr, &dsr, sc, &rp), "⛔ an ARMED door accepted a real proof");
    }

    /// ⭐ PADDING SPEC v2 §8–§9 — THE CONTENT CENSUS. A constant LENGTH hides nothing if a column's content still splits
    /// the classes (§8 measured it: `PUB_LC`/`PUB_D` zero on every cover row, so `n` = the rows with `lc ≠ 0`). For every
    /// published statement column and every predicate a reader can compute from the list alone — "is zero", "repeats
    /// another cell of the list" — the census names the column if the predicate holds on ALL spend rows and fails on ALL
    /// cover rows, or the reverse. Empty = no such column. (The block-level predicates "is filed in `oli_tags`" and
    /// "equals the public filing function of the row's notes" are the node door's census, §10 C1/C2: the decider holds
    /// neither the filing set nor blake3.)
    fn content_census(published: &[LedgerPublished], spend_rows: &[bool]) -> Vec<String> {
        use crate::slot_ledger::PUB_D;
        let mut cells: std::collections::BTreeMap<Digest, usize> = std::collections::BTreeMap::new();
        for p in published {
            for k in PUB_TAG0..=PUB_D {
                *cells.entry(p[k]).or_default() += 1;
            }
        }
        let mut split = Vec::new();
        for k in PUB_TAG0..=PUB_D {
            let preds: [(&str, &dyn Fn(&Digest) -> bool); 2] =
                [("is zero", &|d| *d == [0; DIGEST_LANES]), ("repeats", &|d| cells[d] > 1)];
            for (name, pred) in preds {
                let on = |want: bool| -> Vec<bool> {
                    published.iter().zip(spend_rows).filter(|(_, s)| **s == want).map(|(p, _)| pred(&p[k])).collect()
                };
                let (sp, cv) = (on(true), on(false));
                let uniform = |v: &[bool]| -> Option<bool> { v.first().filter(|f| v.iter().all(|x| x == *f)).copied() };
                if let (Some(a), Some(b)) = (uniform(&sp), uniform(&cv)) {
                    if a != b {
                        split.push(format!("column {k} '{name}': spend rows {a}, cover rows {b}"));
                    }
                }
            }
        }
        split
    }

    /// ⭐ padding spec §18 — THE TAIL CLASS: one stated spend laid as its head row plus 15 TAIL rows carrying its other 30
    /// constant-width tags as free tag cells (no public bit), beside cover rows; the ledger proves and verifies at the
    /// class's constant shape, every tail tag is a published tag cell with ZERO flags, and the content census over the
    /// published list (head rows vs every other row) names no column. RED-FIRST: before §18 a tail's tags could ride only
    /// as JUSTIFIED cells, whose bits the census pin on the node measured (quiet Σt 0 · one spend Σt 30).
    #[test]
    fn s18_a_spends_tail_rows_publish_its_tags_under_no_public_bit_and_split_no_column() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = vec![super::tests::spend(0)];
        let tail_tags = crate::tag_ledger::null_cover_tags(crate::poseidon2_compress::lanes_of(&[0x5441_494c, 1, 2, 3, 4, 5, 6, 7]));
        let tails: Vec<[Digest; 2]> = (1..crate::tag_ledger::PAIRS_PER_SPEND).map(|p| [tail_tags[2 * p], tail_tags[2 * p + 1]]).collect();
        // RE-MEASURED 2026-11-10: the tail count is the spend width's (603d215e narrowed a spend from 32 tags to 8, so
        // 15 tail rows became 3; the literals here kept 15 and the pin read RED from that day).
        let tail_rows = crate::tag_ledger::PAIRS_PER_SPEND - 1;
        assert_eq!(tails.len(), tail_rows, "calibration: one tail row per pair after the head's");
        assert!(tail_rows >= 1, "calibration: a spend has at least one tail row, or this pin measures no tail class");
        let rows = plan_ledger_rows_with_tails(s, 1, &tails, &[], &[], &test_filing_d).expect("the block is stateable");
        assert_eq!(rows.iter().filter(|r| r.witness.is_tail).count(), tail_rows, "the plan lays every tail row");
        let t = std::time::Instant::now();
        let (bytes, published, _digest) =
            prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).expect("the ledger with tails proves");
        eprintln!("[ledger-tails] {} B proof, prove {} ms", bytes.len(), t.elapsed().as_millis());
        assert!(
            verify_block_ledger_transition(&bytes, dom, &onr, &dsr, seed_commit_native(s), &published),
            "⛔ the peer refused the honest ledger with tail rows"
        );
        for pair in &tails {
            let row = published.iter().find(|p| p[PUB_TAG0] == pair[0] || p[PUB_TAG1] == pair[0]).expect("a tail tag is a published tag cell");
            assert_eq!((row[PUB_TAG0], row[PUB_TAG1]), (pair[0], pair[1]), "a tail row publishes its pair in order");
            assert_eq!(row[PUB_FLAGS], [0; DIGEST_LANES], "⛔ a tail row carries a public bit");
        }
        let (nf, _, _) = abs_nf_out(&carriers[0].1);
        let spend_rows: Vec<bool> = published.iter().map(|p| p[PUB_TAG0] == nf).collect();
        let split = content_census(&published, &spend_rows);
        assert!(split.is_empty(), "⛔ R5: the published list splits head rows from the rest: {split:?}");
        // the same list with every tail row read as a spend row of its own: still no column splits head+tails from cover
        let pair_rows: Vec<bool> =
            published.iter().map(|p| p[PUB_TAG0] == nf || tails.iter().any(|t| t[0] == p[PUB_TAG0])).collect();
        let split = content_census(&published, &pair_rows);
        assert!(split.is_empty(), "⛔ R5: the published list splits a spend's head and tail rows from the cover rows: {split:?}");
    }

    /// ⛔⛔ RED-FIRST CALIBRATION + THE CLOSE. The note class states the real spend count on its wire shape (`n` differs
    /// between a 1-spend and a 2-spend block — the leak, armed). The ledger class states NOTHING that moves with it: both
    /// blocks publish `LEDGER_ROWS` rows, verify under a layout no wire field chooses, and every real spend's nullifier and
    /// outputs are among the published cells while every cover row publishes no cross-bind and no filing digest.
    #[test]
    fn db_padding_the_published_list_is_constant_and_the_spend_count_is_on_no_field() {
        assert_ne!(note_class_shape(1), note_class_shape(2), "CALIBRATION: the note class's wire shape names n — the leak");
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let mut lens = Vec::new();
        for n in [1usize, 3] {
            let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..n as u64).map(super::tests::spend).collect();
            let rows = plan_ledger_rows(s, n, &[], &[], &test_filing_d).expect("the block is stateable");
            let t = std::time::Instant::now();
            let (bytes, published, _digest) =
                prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).expect("the ledger proves");
            eprintln!("[ledger] n={n}: {} B proof, {} published rows, prove {} ms", bytes.len(), published.len(), t.elapsed().as_millis());
            assert!(
                verify_block_ledger_transition(&bytes, dom, &onr, &dsr, seed_commit_native(s), &published),
                "⛔ the peer refused the producer's honest ledger at n={n}"
            );
            assert_eq!(published.len(), LEDGER_ROWS, "the list is constant");
            for (_, pb) in &carriers {
                let (nf, o0, o1) = abs_nf_out(pb);
                let row = published.iter().find(|p| p[PUB_TAG0] == nf).expect("every real nullifier is a published tag0");
                assert_eq!((row[PUB_OUT0], row[PUB_OUT1]), (o0, o1), "and its own outputs ride the same row");
            }
            let spend_rows: Vec<bool> = published
                .iter()
                .map(|p| carriers.iter().any(|(_, pb)| abs_nf_out(pb).0 == p[PUB_TAG0]))
                .collect();
            let split = content_census(&published, &spend_rows);
            assert!(split.is_empty(), "⛔ n={n}: these published columns tell a spend row from a cover row: {split:?}");
            lens.push(published.len());
        }
        assert_eq!(lens[0], lens[1], "one list length at n = 1 and n = 3");
    }

    /// ⛔ The peer's checks are load-bearing: a moved cell of any row, a list out of canonical order, another seed
    /// commitment, another root — each refused.
    #[test]
    fn db_padding_a_tampered_published_cell_order_seed_or_root_is_refused() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let carriers = vec![super::tests::spend(7)];
        let rows = plan_ledger_rows(s, 1, &[], &[], &test_filing_d).expect("stateable");
        let (bytes, published, _) = prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).expect("proves");
        let sc = seed_commit_native(s);
        assert!(verify_block_ledger_transition(&bytes, dom, &onr, &dsr, sc, &published), "CALIBRATION");
        let (nf, _, _) = abs_nf_out(&carriers[0].1);
        let spend_at = published.iter().position(|p| p[PUB_TAG0] == nf).expect("the spend row");
        let mut moved = published.clone();
        moved[spend_at][PUB_OUT0][0] ^= 1;
        assert!(!verify_block_ledger_transition(&bytes, dom, &onr, &dsr, sc, &moved), "⛔ a spend's moved output verified");
        let cover_at = (spend_at + 1) % LEDGER_ROWS;
        let mut planted = published.clone();
        planted[cover_at][PUB_TAG1] = lanes_of(&[0x9999, 1, 1, 1]);
        assert!(!verify_block_ledger_transition(&bytes, dom, &onr, &dsr, sc, &planted), "⛔ a planted cover tag verified");
        let mut swapped = published.clone();
        swapped.swap(0, 1);
        assert!(!ledger_list_is_canonical(&swapped), "a list out of canonical order is refused before proof work");
        assert!(!verify_block_ledger_transition(&bytes, dom, &onr, &dsr, sc, &swapped));
        assert!(!verify_block_ledger_transition(&bytes, dom, &onr, &dsr, seed_commit_native(lanes_of(&[1, 2, 3, 4])), &published), "⛔ another seed verified");
        assert!(!verify_block_ledger_transition(&bytes, dom, &vec![Fa4::from_u64(0xA2); 4], &dsr, sc, &published), "⛔ another root verified");
    }

    /// A spend proven against the chain clock `clock_h` (chain hours), with the bind its transcript absorbed (spec §9.1).
    fn clocked_spend(i: u64, clock_h: u64) -> (Vec<u8>, Vec<Fa4>) {
        use crate::whir_rec_block::{note_spend_public_bind, prove_note_spend_bytes, test_clue_digest, NoteSpendExtras, PROTOCOL_FEE_ATOMIC};
        let sk = lanes_of(&[0xC10C + i, 12, 13, 14]);
        let w = crate::whir_rec_block::SpendValidityWitness {
            value_in: 800 + i + PROTOCOL_FEE_ATOMIC,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + i,
            fee: PROTOCOL_FEE_ATOMIC,
            lc_blind: lanes_of(&[0x363, i, 2, 3]),
            out0_value: 750 + i,
            out0_opening: lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let d = test_clue_digest(i);
        let (bytes, cms, nf, lc, tag1) =
            prove_note_spend_bytes(&w, &NoteSpendExtras::plain(clock_h), d, w.lc_blind, 0).expect("the clocked spend proves");
        let f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|j| Fa4::from_u64(d[j])) };
        (bytes, note_spend_public_bind(&[f(cms[0]), f(cms[1])], &f(nf), &f(lc), &f(d), &f(tag1), clock_h))
    }

    /// ⭐ spec §9.1 — THE BLOCK'S CLOCK. A ledger states a spend only under a block clock at or past the clock the spend
    /// was proven against, verifies under that one block clock and no other, and publishes no clock of any row.
    #[test]
    fn a_ledger_states_a_spend_only_at_or_after_its_clock_and_publishes_no_row_clock() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let sc = seed_commit_native(s);
        let hour = 1u64; // clocks are chain hours
        let spend_clock = 500_000u64; // about the year 2027
        let carriers = vec![clocked_spend(1, spend_clock)];
        let rows = plan_ledger_rows(s, 1, &[], &[], &test_filing_d).expect("stateable");
        // a block clock BEFORE the spend's clock: no ledger states the spend
        assert!(
            prove_block_ledger_transition_at(&carriers, &rows, dom, &onr, &dsr, s, spend_clock - 1).is_none(),
            "⛔ a ledger stated a spend proven against a clock the block has not reached"
        );
        assert!(prove_block_ledger_transition(&carriers, &rows, dom, &onr, &dsr, s).is_none(), "the unclocked ledger is the ledger at clock 0");
        // the block one hour later states it
        let block = spend_clock + hour;
        let (bytes, published, _) =
            prove_block_ledger_transition_at(&carriers, &rows, dom, &onr, &dsr, s, block).expect("the ledger proves at a later block clock");
        assert!(verify_block_ledger_transition_at(&bytes, dom, &onr, &dsr, sc, &published, block), "CALIBRATION: it verifies at its block clock");
        assert!(!verify_block_ledger_transition_at(&bytes, dom, &onr, &dsr, sc, &published, block + 1), "⛔ it verified under a later block clock");
        assert!(!verify_block_ledger_transition_at(&bytes, dom, &onr, &dsr, sc, &published, spend_clock - 1), "⛔ it verified under an earlier block clock");
        assert!(!verify_block_ledger_transition(&bytes, dom, &onr, &dsr, sc, &published), "⛔ it verified with no block clock");
        // nothing published is the spend's clock: no lane of the list holds its hour count
        assert!(
            published.iter().all(|row| row.iter().all(|d| d.iter().all(|lane| *lane != spend_clock))),
            "⛔ a published row carries the spend's clock"
        );
        // a producer that states the carrier under a clock it was NOT proven against (0, so any block clock would do)
        let (blob, _) = &carriers[0];
        let (_, honest_zero_bind) = clocked_spend(1, 0);
        let lied = vec![(blob.clone(), honest_zero_bind)];
        let forged = prove_block_ledger_transition_at(&lied, &rows, dom, &onr, &dsr, s, 0);
        assert!(
            forged.is_none_or(|(b, p, _)| !verify_block_ledger_transition_at(&b, dom, &onr, &dsr, sc, &p, 0)),
            "⛔ a carrier was stated under a clock its transcript never absorbed"
        );
    }

    /// A block with NO spend proves over the null carrier and publishes nothing of it (all cells cover); a block whose
    /// producer leaves a REAL carrier's row unspent publishes nothing of that carrier either — all-or-nothing per row.
    #[test]
    fn db_padding_the_null_carrier_block_verifies_and_an_unspent_carrier_publishes_nothing_of_itself() {
        let (onr, dsr) = roots();
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let s = seed();
        let rows = plan_ledger_rows(s, 0, &[], &[], &test_filing_d).expect("an empty block is stateable");
        for (label, carrier) in [
            ("null carrier", null_spend_carrier().expect("the OS source answers and the zero-value spend proves")),
            ("real carrier left unspent", super::tests::spend(9)),
        ] {
            let (bytes, published, _) =
                prove_block_ledger_transition(&[carrier.clone()], &rows, dom, &onr, &dsr, s).expect("proves");
            assert!(verify_block_ledger_transition(&bytes, dom, &onr, &dsr, seed_commit_native(s), &published), "{label}: verifies");
            let (nf, o0, o1) = abs_nf_out(&carrier.1);
            assert!(
                published.iter().all(|p| p[PUB_TAG0] != nf && p[PUB_TAG1] != nf && p[PUB_OUT0] != o0 && p[PUB_OUT1] != o1),
                "⛔ {label}: a statement no row spent reached the published list"
            );
            let law: std::collections::BTreeSet<Digest> =
                (1..=LEDGER_ROWS as u64).map(|k| crate::slot_ledger::cover_lc_native(s, k)).collect();
            assert!(
                published.iter().all(|p| law.contains(&p[PUB_LC])),
                "{label}: every row's cross-bind is the cover law (padding v2 §9) — none is the carrier's"
            );
            assert!(published.iter().any(|p| p[PUB_TAG0] == cover_tag_native(s, 1) || p[PUB_TAG1] == cover_tag_native(s, 1)));
            assert!(published.iter().any(|p| p[PUB_OUT0] == cover_note_native(s, 1) || p[PUB_OUT1] == cover_note_native(s, 1)));
        }
    }

    /// Justified cells: the door's notes and tags ride cover rows with their public bits set; the plan refuses more
    /// justified cells than the cover rows hold.
    #[test]
    fn db_padding_justified_notes_and_tags_ride_cover_cells_with_their_bits_and_capacity_is_refused_past_the_rows() {
        let s = seed();
        let jn: Vec<Digest> = vec![lanes_of(&[0x3a5, 1, 1, 1]), lanes_of(&[0x3a5, 2, 1, 1]), lanes_of(&[0x3a5, 3, 1, 1])];
        let jt: Vec<Digest> = vec![lanes_of(&[0x7a6, 1, 2, 2]), lanes_of(&[0x7a6, 2, 2, 2])];
        let rows = plan_ledger_rows(s, 1, &jn, &jt, &test_filing_d).expect("stateable");
        let mut seen = (0usize, 0usize);
        for r in &rows {
            seen.0 += r.witness.j.iter().filter(|b| **b).count();
            seen.1 += r.witness.t.iter().filter(|b| **b).count();
            assert!(r.witness.is_well_formed(), "every planned row is well-formed");
        }
        assert_eq!(seen, (jn.len(), jt.len()), "each justified note and tag is placed exactly once");
        let cap = crate::slot_ledger::CELLS_PER_ROW * (LEDGER_ROWS - 1);
        let too_many: Vec<Digest> = (0..=cap as u64).map(|i| lanes_of(&[i, 9])).collect();
        assert!(plan_ledger_rows(s, 1, &too_many, &[], &test_filing_d).is_none(), "more justified notes than cover cells is unstateable");
        assert!(plan_ledger_rows(s, LEDGER_ROWS + 1, &[], &[], &test_filing_d).is_none(), "more spends than rows is unstateable");
    }
}

#[cfg(test)]
mod cover_transition_tests {
    use super::*;
    use crate::nf_sparse_air::{
        cover_tag_native, cover_transition_domain, prove_spend_or_decoy_bytes, TagWitness,
    };
    use crate::nullifier_insert_air::poseidon_pair_native;

    /// Build a spend-or-decoy carrier with `k` REAL inputs out of `w` tags, at the protocol width.
    pub(super) fn carrier(k: usize, seed: u64) -> (Vec<u8>, Vec<Fa4>) {
        let w = COVER_TAGS_PER_TUPLE;
        let slots: Vec<u64> = (0..w as u64).collect();
        let bound = crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]);
        let mut tags = Vec::with_capacity(w);
        let mut wit = Vec::with_capacity(w);
        for j in 0..w {
            if j < k {
                let sk = crate::poseidon2_compress::lanes_of(&[100 + seed + j as u64, 2, 3, 4]);
                let leaf = crate::poseidon2_compress::lanes_of(&[200 + seed + j as u64, 5, 6, 7]);
                tags.push(poseidon_pair_native(sk, leaf));
                wit.push(TagWitness::RealSpend { key: sk, leaf });
            } else {
                tags.push(cover_tag_native(bound, slots[j]));
                wit.push(TagWitness::Decoy);
            }
        }
        let p = prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("the carrier proves");
        (p, crate::nf_sparse_air::cover_tag_statement_bind(&tags))
    }



    /// ⭐⭐⭐ DB-83 CLOSED: A BLOCK STATES A FIVE-REAL-INPUT SPEND, AND EVERY TAMPER IS REFUSED.
    ///
    /// The thing the submit door has been refusing since 2026-09-19 (`MULTI_INPUT_NOT_STATEABLE_YET`):
    /// a transaction spending more than one real note could not be STATED by any block, so the other
    /// real inputs would have gone un-deleted and stayed spendable. Two carriers at k=1 and k=5 real
    /// inputs — identical constant width, so the statement cannot tell a plain send from a
    /// consolidation — aggregated into ONE proof a peer judges against values it already holds.
    ///
    /// ⛔ THE REFUTATIONS ARE THE POINT. A transition that verifies but does not BIND is worthless.
    #[test]
    fn a_block_transition_states_a_five_real_input_spend_and_refuses_tampering() {
        let carriers = vec![carrier(1, 0), carrier(5, 1_000)];
        let onr: Vec<Fa4> = vec![Fa4::from_u64(7); DIGEST_LANES];
        let dsr: Vec<Fa4> = vec![Fa4::from_u64(11); DIGEST_LANES];
        let domain = cover_transition_domain();

        let t = std::time::Instant::now();
        let (proof, shape, rows_digest) = prove_block_cover_transition(&carriers, domain, &onr, &dsr)
            .expect("⛔ DB-83: a block must be able to state a spend-or-decoy carrier");
        eprintln!(
            "[db83] {} carriers (k=1 and k=5 REAL inputs, width {}) -> {} B in {} ms",
            carriers.len(),
            COVER_TAGS_PER_TUPLE,
            proof.len(),
            t.elapsed().as_millis()
        );

        assert!(
            verify_block_cover_transition(&proof, shape, domain, &onr, &dsr, &rows_digest),
            "⛔ the honest transition must verify"
        );

        // ⛔ 1. A DIFFERENT TUPLE — a peer recomputes `rows_digest` from its OWN tag list, so a proof
        //    standing over other spends must not open under it.
        let mut bad = rows_digest.clone();
        bad[0] += Fa4::from_u64(1);
        assert!(
            !verify_block_cover_transition(&proof, shape, domain, &onr, &dsr, &bad),
            "⛔⛔ A TAMPERED TAG SET VERIFIED — the transition does not bind the spends it stands over"
        );

        // ⛔ 2. A DIFFERENT OUTPUT-NOTES ROOT — the proof must not stand over a delta the block does
        //    not apply, or a producer settles one thing and publishes another.
        let mut bad_onr = onr.clone();
        bad_onr[0] += Fa4::from_u64(1);
        assert!(
            !verify_block_cover_transition(&proof, shape, domain, &bad_onr, &dsr, &rows_digest),
            "⛔⛔ A TAMPERED OUTPUT-NOTES ROOT VERIFIED"
        );

        // ⛔ 3. A DIFFERENT DELETION-SET ROOT — §BB: a producer must not burn a victim's note and
        //    still show a valid delta.
        let mut bad_dsr = dsr.clone();
        bad_dsr[0] += Fa4::from_u64(1);
        assert!(
            !verify_block_cover_transition(&proof, shape, domain, &onr, &bad_dsr, &rows_digest),
            "⛔⛔ A TAMPERED DELETION-SET ROOT VERIFIED"
        );

        // ⛔ 4. ANOTHER CLASS'S DOMAIN. The aggregate cross-ties the sponge's first absorb to the
        //    statement's domain, so a spend-or-decoy proof must not open as some other class.
        assert!(
            !verify_block_cover_transition(
                &proof,
                shape,
                domain + Fa4::from_u64(1),
                &onr,
                &dsr,
                &rows_digest
            ),
            "⛔⛔ THE PROOF OPENED UNDER ANOTHER DOMAIN — one class's transition could pose as another"
        );

        // ⛔ 5. A DROPPED CARRIER. `rows_digest` is a function of the whole tuple list, so stating one
        //    spend while settling two must not verify.
        let one = vec![carriers[0].1[1..].to_vec()];
        let short = rows_digest_of(&one, shape.slots, COVER_TUPLE_VALS).expect("digest of one row");
        assert!(
            !verify_block_cover_transition(&proof, shape, domain, &onr, &dsr, &short),
            "⛔⛔ A DROPPED CARRIER VERIFIED — the statement does not bind the carrier COUNT"
        );
    }

    /// ⭐⭐⭐ THE TIE COUNT NO LONGER TRACKS THE TAG COUNT — the measurement that decided the design.
    ///
    /// ⛔ WHAT THIS PIN IS. Not a feature test — a DESIGN DECISION, pinned so it cannot be quietly
    /// reversed by widening a bind again. `settlement_delta_ties` emits one COLUMN TIE per sponge ROW
    /// a tuple's cells span (rate 8), in the transcript sponge (g2) AND in the `rows_digest` chain
    /// (g7). When the carrier's bind carried every tag, both tracked the TAG COUNT:
    ///
    /// ```text
    ///   BIND = domain ‖ every tag        4 digests  g2= 5 g7= 4 total  56   cap 64
    ///                                   32 digests  g2=33 g7=32 total 112   cap 64  ⛔ UNSTATEABLE
    ///   BIND = domain ‖ tag-set DIGEST  any width   g2= 2 g7= 1 total  50   cap 64  ⭐ CONSTANT
    /// ```
    ///
    /// ⛔ `COLUMN_TIES_MAX` WAS NOT MOVED, and its own doc is why: *a column tie is a property of the
    /// CIRCUIT — one per relation the AIR states between two tables — so a correct circuit names a
    /// handful and never more, whatever the tables hold.* 112 was the circuit stating 33 relations
    /// where it should state one. The cap was right and the circuit was wrong.
    ///
    /// So this asserts the property, not the numbers: the two tuple-borne groups must not grow when
    /// the tag count does, at any width this protocol might later pick.
    #[test]
    fn the_tie_count_does_not_track_the_tag_count() {
        let base = BoundLayout { nvars: 6, per: 11, width: 22_312, powers: 296, power_lo: 148, shifted_lo: 0, shifted: 0 };
        let ties_at = |tv: usize| -> (usize, usize, usize) {
            let layout =
                DeltaLayout { bound: base, n: 2, seg_log: 6, slots: DELTA_FIXED_SLOTS, tuple_vals: tv };
            let g = |mask: u8| {
                settlement_delta_ties_masked(
                    layout,
                    1 + tv,
                    DELTA_DOMAIN_OFF,
                    delta_digest_off(DIGEST_LANES, DIGEST_LANES),
                    mask,
                )
                .map_or(usize::MAX, |(_c, k)| k.len())
            };
            let all = settlement_delta_ties(
                layout,
                1 + tv,
                DELTA_DOMAIN_OFF,
                delta_digest_off(DIGEST_LANES, DIGEST_LANES),
            )
            .map_or(usize::MAX, |(_c, k)| k.len());
            (g(2), g(64), all)
        };
        let cap = crate::whir_rec_block::COLUMN_TIES_MAX;

        // What the ENUMERATING bind (`domain ‖ every tag`) costs at this width, and at eight times it.
        let enumerated_now = ties_at(COVER_TAGS_PER_TUPLE * DIGEST_LANES);
        let enumerated_8x = ties_at(COVER_TAGS_PER_TUPLE * DIGEST_LANES * 8);
        // What the COMMITTING bind (`domain ‖ tag-set digest`) costs — the shipped design.
        let committed = ties_at(COVER_TUPLE_VALS);
        eprintln!(
            "[db83-decision] enumerating bind: {} tags -> total {} | {} tags -> total {}                COMMITTING bind: total {} (g2={} g7={}) at ANY tag count (cap {cap})",
            COVER_TAGS_PER_TUPLE,
            enumerated_now.2,
            COVER_TAGS_PER_TUPLE * 8,
            enumerated_8x.2,
            committed.2,
            committed.0,
            committed.1
        );

        // ⭐ THE PROPERTY: the bind commits to the tag set rather than enumerating it, so neither
        //   tuple-borne group can see the tag count at all.
        assert_eq!(
            COVER_TUPLE_VALS, DIGEST_LANES,
            "⛔⛔⛔ THE BIND IS ENUMERATING TAGS AGAIN. Its width is the whole of this defect: the              aggregate emits one column tie per sponge ROW a tuple spans, twice, so a bind that grows              with the tag count makes the tie count grow with it — and at 32 tags that was 112 against              a cap of {cap}, i.e. no block could state the class."
        );
        assert!(
            committed.2 <= cap,
            "⛔⛔⛔ the spend-or-decoy transition needs {} column ties against a cap of {cap} — it              cannot be stated by any block, which is DB-83 reopening",
            committed.2
        );
        // ⛔ AND THE OLD SHAPE REALLY IS THE ONE THAT TRACKS THE TAG COUNT — so this is a measurement, not a preference.
        // RE-MEASURED 2026-11-10 (the pin asked for it: it went red when 603d215e narrowed the spend width 32 → 8):
        //   enumerating bind   8 tags total  64 (exactly the cap, zero headroom)
        //                     32 tags total 112 ⛔   64 tags total 176 ⛔     (two ties per tag)
        //   committing bind   any width total 50
        // The old assertion compared the enumerating bind at TODAY's width against the cap, which states a fact about
        // the width, not about the bind. What decided the design is that the enumerating bind grows with the tag count
        // and passes the cap at widths this chain has run at; both are asserted, with the growth rate.
        let enumerated_32 = ties_at(32 * DIGEST_LANES);
        assert!(
            enumerated_32.2 > cap && enumerated_8x.2 > cap,
            "the enumerating bind is recorded here as the thing that did not fit at 32 tags ({}) or at eight times today's \
             width ({}); if it now fits, the tie schedule changed and this pin's numbers need re-measuring, not deleting",
            enumerated_32.2,
            enumerated_8x.2
        );
        assert_eq!(
            enumerated_8x.2 - enumerated_now.2,
            2 * (COVER_TAGS_PER_TUPLE * 8 - COVER_TAGS_PER_TUPLE),
            "the enumerating bind costs two column ties per tag (one per sponge row in each tuple-borne group)"
        );
        assert!(
            committed.2 < enumerated_now.2,
            "the committing bind ({}) must cost less than the enumerating one at today's width ({})",
            committed.2,
            enumerated_now.2
        );
    }

    /// ⛔⛔⛔ THE WIRE SHAPE GATE MUST ADMIT EVERY TABLE THIS PROTOCOL LAYS.
    ///
    /// `AIR_DIRECT_MAX_WIDTH` exists to refuse a remote sender's allocation, and its doc promises it is
    /// *by construction the widest carrier the protocol defines*. MEASURED 2026-09-23: it had gone
    /// stale — it named ONE carrier's constant while the widest table this protocol lays is an
    /// AGGREGATE STEP ROW (the inner carrier's opened row as committed columns, 90,780 against a cap of
    /// 9,156), so the gate SILENTLY REFUSED every honest spend-or-decoy transition before a single
    /// number of it was used. A bound whose derivation is a pointer to one object goes stale the day a
    /// second object is bigger; this pin lays the real tables and fails when one outgrows the gate, so
    /// it cannot happen quietly again.
    #[test]
    fn every_table_this_protocol_lays_fits_the_wire_shape_gate() {
        let carriers = vec![carrier(1, 0), carrier(5, 1_000)];
        let base = delta_base_layout_cover(&carriers).expect("the class's base layout");
        let probe = cover_delta_factory(DeltaLayout {
            bound: base,
            n: 1,
            seg_log: 0,
            slots: DELTA_FIXED_SLOTS,
            tuple_vals: COVER_TUPLE_VALS,
        });
        let oob = crate::air_zerocheck::OobLatch::new();
        let vals = vec![Ea4::ZERO; base.width];
        let powers = probe(&Row::new(&vals, &oob))
            .residuals(&Row::new(&vals, &oob), &|_c: usize, _p: &[Ea4]| Ea4::ZERO, &vec![
                Ea4::ZERO;
                base.nvars
            ])
            .len();
        let layout = delta_layout(
            base,
            powers,
            carriers.len(),
            DELTA_FIXED_SLOTS,
            1 + COVER_TUPLE_VALS,
            COVER_TUPLE_VALS,
        )
        .expect("the class's layout");
        let t0 = std::time::Instant::now();
        let (tables, _rd) = settlement_delta_tables(&carriers, layout).expect("the tables build");
        let tables_ms = t0.elapsed().as_millis();
        let cap = crate::whir_rec_block::AIR_DIRECT_MAX_WIDTH;
        for (i, t) in tables.iter().enumerate() {
            eprintln!("[shape-gate] table {i}: width={} rows={} (cap {cap})", t.len(), t[0].len());
            assert!(
                t.len() <= cap,
                "⛔⛔⛔ TABLE {i} IS {} COLUMNS AGAINST A WIRE SHAPE GATE OF {cap} — every honest \
                 proof of this class is refused before it is read",
                t.len()
            );
        }
        let cells: usize = tables.iter().map(|t| t.len() * t[0].len()).sum();
        eprintln!(
            "[shape-gate] carrier row = {} columns, residuals = {powers}, tables built in {tables_ms} ms, \
             {} total cells (step {}, sponge {}, chain {})",
            base.width,
            cells,
            tables[0].len() * tables[0][0].len(),
            tables[1].len() * tables[1][0].len(),
            tables[2].len() * tables[2][0].len(),
        );
    }

    /// ⛔ A CARRIER AT ANY OTHER TAG WIDTH IS REFUSED. `COVER_TAGS_PER_TUPLE` is the protocol's
    /// constant tx width — it is what makes a 1-input send and a 5-input consolidation the same shape
    /// on the wire. A block that could state a NARROWER carrier would publish the real-input count by
    /// the shape of the row itself, so this must fail closed rather than verify.
    #[test]
    fn a_carrier_at_another_tag_width_cannot_be_stated() {
        let nw = 16usize; // a provable width (nvars >= COMMITTED_FOLDING) that is NOT the protocol's
        let sl: Vec<u64> = (0..nw as u64).collect();
        let bound = crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]);
        let mut tags = Vec::new();
        let mut wit = Vec::new();
        for j in 0..nw {
            tags.push(cover_tag_native(bound, sl[j]));
            wit.push(TagWitness::Decoy);
        }
        let p = prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("a narrow carrier proves");
        let cs = vec![(p, crate::nf_sparse_air::cover_tag_statement_bind(&tags))];
        let (onr, dsr) = (vec![Fa4::from_u64(7); DIGEST_LANES], vec![Fa4::from_u64(11); DIGEST_LANES]);
        let domain = cover_transition_domain();
        let stated = prove_block_cover_transition(&cs, domain, &onr, &dsr).is_some_and(
            |(bytes, shape, rd)| verify_block_cover_transition(&bytes, shape, domain, &onr, &dsr, &rd),
        );
        assert!(
            !stated,
            "⛔⛔⛔ A BLOCK STATED A NARROW COVER CARRIER — the row's own shape then publishes how many \
             inputs were real, which is exactly what the count-hiding disjunction exists to prevent"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        asset_note_cm, prove_spend_validity_carrier_with_commit_bytes,
        validity_public_bind_with_commit, SpendValidityGate, SpendValidityWitness,
        SPEND_VALIDITY_DOMAIN, USDM_ASSET_TAG,
    };
    use crate::poseidon2_compress::{lanes_of, Digest};

    const DEPTH: usize = 0;

    /// `i` distinct REAL spends — the production carrier, on the production committed path.
    pub(crate) fn spend(i: u64) -> (Vec<u8>, Vec<Fa4>) {
        let sk = lanes_of(&[11 + i, 12, 13, 14]);
        // ⭐ §BY — THE PATHLESS SHAPE IS THE PRODUCTION SHAPE. The gate's membership path is anchored to
        // nothing (a garbage sibling verifies), so carrying one only widened every carrier and every
        // aggregate over it. Membership is proven by the note-membership carrier over the accumulator,
        // cross-bound here by `Poseidon(leaf, nullifier) == leaf_commit`.
        let w = SpendValidityWitness {
            value_in: 800 + i + crate::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14: in == out + the protocol fee
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + i,
            fee: crate::whir_rec_block::PROTOCOL_FEE_ATOMIC,
            lc_blind: lanes_of(&[0x363, i, 2, 3]),
            out0_value: 750 + i,
            out0_opening: lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let (bytes, cms, nf, lc) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(i)).expect("the production spend proves");
        let f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|j| Fa4::from_u64(d[j])) };
        let pb = validity_public_bind_with_commit(
            &[f(cms[0]), f(cms[1])],
            &f(nf),
            &f(lc),
            &f(crate::whir_rec_block::test_clue_digest(i)),
            &f(crate::whir_rec_block::spend_tag1(&w)),
        );
        (bytes, pb)
    }

    /// ⭐⭐⭐ THE PER-ROW FACTORY — §BO's keystone, and the reason this aggregate can exist at all.
    ///
    /// A constraint field holds ONE value for every row, but every carrier has its OWN publics. So the
    /// gate is not a constant handed to the circuit: its four digests are BUILT FROM THE ROW, out of the
    /// very cells the row's transcript absorbed and the chain hashes. A row that lies about its tuple is
    /// closed against a different gate and its equation stops holding.
    ///
    /// ⛔ γ IS THE EXCEPTION, AND IT IS NOT AN OVERSIGHT. The gate batches residuals by γ-powers, so a γ
    /// read from a column would make the k-th residual degree k — see `DeltaLayout::step_cols`. γ comes
    /// from the public statement, tied to this table's sponge.
    pub(crate) fn factory(lay: DeltaLayout) -> impl Fn(&Row<'_>) -> crate::committed_air::Blinded<SpendValidityGate> + Clone {
        move |row: &Row<'_>| {
            let d = |off: usize| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|j| row[off + j]) };
            crate::committed_air::Blinded {
                inner: SpendValidityGate {
                    // ⛔ UNUSED BY THE AGGREGATE, ON PURPOSE. `residuals()` never folds, so this field
                    // never enters the circuit here; the row's own γ-power chain does the folding.
                    gamma: Ea4::ZERO,
                    out0_cm: d(lay.tuple_at(0, 0)),
                    out1_cm: d(lay.tuple_at(1, 0)),
                    nullifier: d(lay.tuple_at(2, 0)),
                    bond_amount: None,
                    // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
                    fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
                    leaf_commit: d(lay.tuple_at(3, 0)),
                    tag1: Some(d(lay.tuple_at(5, 0))), // DB-329 §7e, as `spend_delta_factory`
                    vault: Some(d(lay.tuple_at(6, 0))[0]), // spec §9.1, likewise
                },
            }
        }
    }

    /// The gate with no row behind it — only its SHAPE is read, to count residuals.
    pub(crate) fn probe_gate() -> crate::committed_air::Blinded<SpendValidityGate> {
        crate::committed_air::Blinded {
            inner: SpendValidityGate {
                gamma: Ea4::ZERO,
                out0_cm: [Ea4::ZERO; DIGEST_LANES],
                out1_cm: [Ea4::ZERO; DIGEST_LANES],
                nullifier: [Ea4::ZERO; DIGEST_LANES],
                bond_amount: None,
                // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
                fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
                leaf_commit: [Ea4::ZERO; DIGEST_LANES],
                tag1: Some([Ea4::ZERO; DIGEST_LANES]),
                vault: Some(crate::whir_rec_block::clock_const(0)),
            },
        }
    }

    /// The three phases in one call, as a caller would do it.
    pub(crate) fn lay_slots(carriers: &[(Vec<u8>, Vec<Fa4>)], slots: usize) -> DeltaLayout {
        let base = delta_base_layout(carriers, DELTA_TUPLE_VALS, Fa4::from_u64(SPEND_VALIDITY_DOMAIN)).expect("the carriers share a shape");
        let powers = delta_residual_count(&probe_gate(), base);
        let read = delta_read_width(&probe_gate(), base);
        delta_layout(
            BoundLayout { width: read, ..base },
            powers,
            carriers.len(),
            slots,
            1 + DELTA_TUPLE_VALS,
            DELTA_TUPLE_VALS,
        )
        .expect("the layout lays")
    }

    /// The fixture slot count. ⛔ A FIXTURE, and named as one: production passes `DELTA_FIXED_SLOTS`.
    pub(crate) fn lay(carriers: &[(Vec<u8>, Vec<Fa4>)]) -> DeltaLayout {
        lay_slots(carriers, DELTA_MIN_SLOTS)
    }

    /// CONTROL, and ⭐⭐⭐ THE O(1) GATE — the proof must be BYTE-IDENTICAL however many spends are real.
    ///
    /// This is a PRIVACY gate before it is a cost one. `cover.rs`: "letting the per-block served-note
    /// count VARY with real activity is a hard Pillar-1 violation — an observer could then count real
    /// outputs per block." A per-block proof whose SIZE tracked the real spend count would hand out
    /// exactly that number, and no amount of cover padding elsewhere would take it back.
    ///
    /// So the assertion is equality, not a bound: every `n` up to the shape's row count must produce the
    /// same number of bytes, to the byte.
    #[test]
    fn the_proof_is_byte_identical_however_many_spends_are_real() {
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let mut sizes: Vec<(usize, usize, u128, u128)> = Vec::new();
        for n in [1usize, 2, 4, 8] {
            let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..n as u64).map(spend).collect();
            let layout = lay(&carriers);
            let t0 = std::time::Instant::now();
            let (bytes, digest) =
                prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout))
                    .expect("the honest note transition proves");
            let prove_ms = t0.elapsed().as_millis();
            let t1 = std::time::Instant::now();
            let ok = verify_settlement_delta_bytes(&bytes, layout, dom, &onr, &dsr, &digest, factory(layout));
            let verify_ms = t1.elapsed().as_millis();
            assert!(ok, "⛔ THE CONTROL FAILED at n={n} — an honest note transition must verify");
            eprintln!(
                "[delta] n={n} rows={} seg={} step_cols={} — prove {prove_ms} ms, verify {verify_ms} ms, {} byte(s)",
                layout.rows(), layout.seg_rows(), layout.step_cols(), bytes.len()
            );
            sizes.push((n, bytes.len(), prove_ms, verify_ms));
        }
        let first = sizes[0].1;
        for &(n, sz, _, _) in &sizes {
            assert_eq!(
                sz, first,
                "⛔⛔⛔ THE PROOF SIZE MOVES WITH THE REAL SPEND COUNT: {first} byte(s) at n={} but {sz} \
                 at n={n}. That is a Pillar-1 break — the block's proof would let an observer count real \
                 spends — before it is a cost one. Whatever was added scales per CARRIER; find it and \
                 state it over every carrier at once (a ColumnTieSpec) or fold it into a shared table.",
                sizes[0].0
            );
        }
        eprintln!(
            "[delta] ⭐⭐⭐ O(1): {} byte(s) at every n in {:?} — byte-identical, and prove time flat at ~{} ms",
            first,
            sizes.iter().map(|s| s.0).collect::<Vec<_>>(),
            sizes[0].2
        );
    }

    /// ⭐ SPEED R8 — ONE REAL PROOF, BOTH ENGINES, THE SAME BYTES. The settlement delta's gate evaluates the
    /// permutation's tape through both of its doors (`push_perm_residuals` and the sponge chain's Horner fold), in the
    /// base field (the zerocheck's round 0) and in the extension. With the blinding seed pinned, a proof made through
    /// the reference slot interpreter and one made through the register program (`tape_program`) are the same bytes
    /// with the same digest, and that proof verifies under BOTH engines — the verifier evaluates its final point through
    /// the same tape — while a proof with one byte moved is refused under both.
    /// TWO-PARTY-REVIEWED: prover and verifier are the two parties here; every assertion is on what the verifier
    /// accepts or on the bytes it would be handed.
    #[test]
    fn speed_r8_a_real_proof_is_the_same_bytes_under_the_register_program_and_the_reference() {
        use std::sync::atomic::Ordering::SeqCst;
        struct BackToTheProgram;
        impl Drop for BackToTheProgram {
            fn drop(&mut self) {
                crate::whole_chain::REFERENCE_ENGINE.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2u64).map(spend).collect();
        let layout = lay(&carriers);
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x58u8; 32]));
        let _back = BackToTheProgram;
        let prove = |reference: bool| {
            crate::whole_chain::REFERENCE_ENGINE.store(reference, SeqCst);
            prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout)).expect("the honest note transition proves")
        };
        let (ref_bytes, ref_digest) = prove(true);
        let (new_bytes, new_digest) = prove(false);
        let (again_bytes, _) = prove(false);
        assert!(new_bytes == again_bytes, "the control: two proves under one engine and one pinned seed are the same bytes");
        assert!(
            ref_bytes == new_bytes,
            "⛔ THE TWO ENGINES LAY DIFFERENT PROOFS ({} and {} byte(s)): the register program evaluates a different value \
             somewhere than the reference slot interpreter — a wrong STATEMENT, not a slow prover",
            ref_bytes.len(),
            new_bytes.len()
        );
        assert!(ref_digest == new_digest, "⛔ the two engines bind different digests");
        for reference in [true, false] {
            crate::whole_chain::REFERENCE_ENGINE.store(reference, SeqCst);
            assert!(
                verify_settlement_delta_bytes(&new_bytes, layout, dom, &onr, &dsr, &new_digest, factory(layout)),
                "⛔ the proof is refused when the verifier evaluates through {}",
                if reference { "the reference slot interpreter" } else { "the register program" }
            );
            let mut moved = new_bytes.clone();
            let mid = moved.len() / 2;
            moved[mid] ^= 1;
            assert!(
                !verify_settlement_delta_bytes(&moved, layout, dom, &onr, &dsr, &new_digest, factory(layout)),
                "⛔ a proof with one byte moved VERIFIES (reference engine: {reference})"
            );
        }
        eprintln!("[r8] one settlement proof, {} byte(s): the same bytes under both engines, accepted under both", new_bytes.len());
    }

    /// ⭐⭐⭐ THE PRODUCTION SHAPE — `BLOCK_FIXED_TX_COUNT` slots, not a shrunken cover.
    ///
    /// A block carries a CONSTANT 256 tx slots, real and cover alike, so the aggregate a block ships is
    /// always 256 rows. Every other measurement here runs below the row floor and proves the size does
    /// not MOVE; this one says what the constant actually IS, at the shape the chain will run.
    ///
    /// ⛔ Ignored by default: it proves 256 real carriers, which is minutes of work. Run it with
    /// `--ignored` when the shape or the gate changes.
    #[test]
    #[ignore = "production shape: proves BLOCK_FIXED_TX_COUNT carriers, minutes of work"]
    fn the_aggregate_at_the_blocks_real_slot_count() {
        let t_c = std::time::Instant::now();
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> =
            (0..DELTA_FIXED_SLOTS as u64).map(spend).collect();
        let carrier_ms = t_c.elapsed().as_millis();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let layout = lay_slots(&carriers, DELTA_FIXED_SLOTS);
        let t0 = std::time::Instant::now();
        let (bytes, digest) =
            prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout))
                .expect("the production-shape aggregate proves");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        let ok = verify_settlement_delta_bytes(&bytes, layout, dom, &onr, &dsr, &digest, factory(layout));
        let verify_ms = t1.elapsed().as_millis();
        eprintln!(
            "[delta-slots] {} carriers: build {carrier_ms} ms · AGGREGATE prove {prove_ms} ms, \
             verify {verify_ms} ms, {} byte(s) · rows={} seg={} step_cols={}",
            DELTA_FIXED_SLOTS, bytes.len(), layout.rows(), layout.seg_rows(), layout.step_cols()
        );
        assert!(ok, "⛔ the production-shape aggregate must verify");
    }

    /// ⛔⛔⛔ THE SHAPE MUST NOT BE A READOUT OF THE DATA — the second half of the same privacy hole.
    ///
    /// §BW made the proof byte-identical across `n`. It was still sized from `n.next_power_of_two()`,
    /// so a block with 8 real spends and one with 256 shipped DIFFERENT-sized proofs — MEASURED 443,723
    /// B at 16 rows against 446,551 B at 256. Padding the carriers is not enough when the padding
    /// TARGET is computed from the carriers.
    ///
    /// So the slot count is an explicit argument and a protocol constant. This asserts it: the layout
    /// for any `n` must name the same rows, the same segment, the same columns.
    #[test]
    fn the_shape_is_fixed_by_the_protocol_not_by_the_spend_count() {
        let base = delta_base_layout(&[spend(0)], DELTA_TUPLE_VALS, Fa4::from_u64(SPEND_VALIDITY_DOMAIN)).expect("shape");
        let powers = delta_residual_count(&probe_gate(), base);
        let read = delta_read_width(&probe_gate(), base);
        let of = |n: usize| {
            delta_layout(BoundLayout { width: read, ..base }, powers, n, DELTA_FIXED_SLOTS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS)
                .expect("the layout lays")
        };
        let one = of(1);
        for n in [1usize, 2, 7, 64, 255, 256] {
            let l = of(n);
            assert_eq!(
                (l.rows(), l.seg_rows(), l.step_cols()),
                (one.rows(), one.seg_rows(), one.step_cols()),
                "⛔⛔⛔ THE COMMITTED SHAPE MOVES WITH THE REAL SPEND COUNT at n={n}: rows/seg/cols \
                 {:?} vs {:?}. Every committed dimension is a readout of how busy the block was, and \
                 the proof's size follows them — the same Pillar-1 break §BW closed one level up.",
                (l.rows(), l.seg_rows(), l.step_cols()),
                (one.rows(), one.seg_rows(), one.step_cols())
            );
        }
        // And a delta that does not FIT its block cannot be stated at all.
        assert!(
            delta_layout(base, powers, DELTA_FIXED_SLOTS + 1, DELTA_FIXED_SLOTS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS).is_none(),
            "⛔ more carriers than the block has slots was accepted"
        );
        assert!(
            delta_layout(base, powers, 1, 100, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS).is_none(),
            "⛔ a non-power-of-two slot count was accepted — the committed table could not be laid"
        );
        eprintln!(
            "[delta] ⭐ shape is protocol-fixed: rows={} seg={} step_cols={} for every n in 1..={}",
            one.rows(), one.seg_rows(), one.step_cols(), DELTA_FIXED_SLOTS
        );
    }

    /// ⛔⛔⛔ §BA — A NOTE A PRODUCER PLANTS. The tuple a row publishes must be the statement its carrier
    /// was actually proved over. Re-point one row's tuple at a note nobody spent and the aggregate must
    /// die: the tuple is tied to the sponge that absorbed it AND to the chain that hashes it, so a
    /// producer cannot name an output note without a proof standing behind it.
    #[test]
    fn a_row_claiming_a_note_its_carrier_never_proved_is_refused() {
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(spend).collect();
        let layout = lay(&carriers);
        let (bytes, digest) =
            prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout)).expect("proves");
        assert!(
            verify_settlement_delta_bytes(&bytes, layout, dom, &onr, &dsr, &digest, factory(layout)),
            "CONTROL: the honest aggregate must verify before a forgery of it means anything"
        );
        // THE PLANTED NOTE: the same proof, presented as certifying a DIFFERENT output commitment.
        let mut forged = digest.clone();
        forged[0] += Fa4::ONE;
        assert!(
            !verify_settlement_delta_bytes(&bytes, layout, dom, &onr, &dsr, &forged, factory(layout)),
            "⛔⛔⛔ §BA LIVES: an aggregate verified against a `rows_digest` that is not the chain's own \
             output, so the tuple list a peer judges the block by is not the list the proof stands over."
        );
        // And the transition roots the peer checks are part of the statement, not decoration.
        let other = vec![Fa4::from_u64(0xA2); 4];
        assert!(
            !verify_settlement_delta_bytes(&bytes, layout, dom, &other, &dsr, &digest, factory(layout)),
            "⛔⛔⛔ the aggregate accepted a DIFFERENT output-notes root — the delta it certifies is not \
             pinned to the block it rode in on"
        );
        assert!(
            !verify_settlement_delta_bytes(&bytes, layout, dom, &onr, &other, &digest, factory(layout)),
            "⛔⛔⛔ §BB LIVES: the aggregate accepted a DIFFERENT del_set root, so a producer may burn a \
             victim's note and still show a valid delta"
        );
        eprintln!("[delta] ⭐ a re-pointed rows_digest and both re-pointed transition roots were all REFUSED");
    }

    /// ⭐⭐ EVERY TIE GROUP ACTUALLY TIES SOMETHING.
    ///
    /// Each group is built by `skip(..).take(..)` over a schedule derived from PUBLIC numbers. If an
    /// offset lands past the end, the iterator yields NOTHING — no error, no panic, just a group that
    /// constrains nothing while the aggregate goes on verifying. That is the shape of a silent hole,
    /// and it is why the mask exists: this counts each group and demands it be non-empty and grow with
    /// `n`, so a schedule change that quietly empties one is caught by arithmetic rather than by a
    /// forgery nobody thought to write.
    #[test]
    fn no_tie_group_is_silently_empty() {
        let names = ["domain", "tuple", "evals", "r", "z", "gamma", "chain", "digest"];
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(spend).collect();
        let layout = lay(&carriers);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let counts: Vec<usize> = (0..8u8)
            .map(|bit| {
                settlement_delta_ties_masked(
                    layout,
                    1 + DELTA_TUPLE_VALS,
                    DELTA_DOMAIN_OFF,
                    delta_digest_off(onr.len(), dsr.len()),
                    1u8 << bit,
                )
                .map_or(0, |(c, k)| c.len() + k.len())
            })
            .collect();
        for (g, &c) in counts.iter().enumerate() {
            assert!(
                c > 0,
                "⛔⛔⛔ TIE GROUP '{}' PRODUCED ZERO TIES — it constrains nothing, and the aggregate \
                 still verifies without it. An offset walked off the end of the schedule.",
                names[g]
            );
        }
        // The whole is the sum of its parts: a group double-counted or dropped by the full build would
        // show up here and nowhere else.
        let (ac, ak) = settlement_delta_ties(
            layout,
            1 + DELTA_TUPLE_VALS,
            DELTA_DOMAIN_OFF,
            delta_digest_off(onr.len(), dsr.len()),
        )
        .expect("the full tie set builds");
        let all = ac.len() + ak.len();
        assert_eq!(
            all,
            counts.iter().sum::<usize>(),
            "⛔ the full tie set is not the union of its groups"
        );
        eprintln!(
            "[delta] tie groups {names:?} = {counts:?} — {} cross + {} COLUMN ties at n={} (column ties \
             state the same equalities over EVERY carrier at one point, so this list does not grow)",
            ac.len(), ak.len(), layout.n
        );
    }

    /// ⛔⛔⛔ IS THE PROVER DETERMINISTIC UNDER PARALLELISM? Two identical proves, byte-compared.
    ///
    /// Two nodes must produce the same proof from the same inputs or the chain does not converge, so
    /// this is a consensus property, not a nicety. Field addition is exactly associative and commutative
    /// and there is no floating point here, so a map-reduce over independent rows MUST land on the same
    /// sum whatever order the workers finish in. This checks that claim rather than asserting it.
    #[test]
    fn two_identical_proves_are_byte_identical() {
        // DB-382: the blinding is fresh per prove in production (two honest proves of one statement DIFFER by design —
        // `two_unpinned_proves_of_one_statement_differ_in_their_hiding_commitments_and_both_verify`); this pin measures the
        // PROVER's determinism, so it pins one seed for both proves and releases it with the guard.
        let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x82u8; 32]));
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..4).map(spend).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let layout = lay(&carriers);
        let a = prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout))
            .expect("first prove");
        let b = prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, factory(layout))
            .expect("second prove");
        eprintln!("[delta] determinism: {} B vs {} B, equal={}", a.0.len(), b.0.len(), a.0 == b.0);
        assert_eq!(
            a.0, b.0,
            "⛔⛔⛔ THE PROVER IS NOT DETERMINISTIC: two identical proves produced different bytes. Two \
             nodes cannot agree on a block, so this is a consensus break, not a performance note."
        );
        assert_eq!(a.1, b.1, "⛔ the rows_digest differed between two identical proves");
    }

    /// ⛔ WHERE DOES THE PROVE TIME ACTUALLY GO? One gate evaluation, timed.
    ///
    /// The sumcheck evaluates the bound step at `per_evals` sample points for each of `2^nvars - 1`
    /// folded rows. Divide the wall clock by that count and you get the cost of ONE evaluation — and
    /// that number decides whether the next optimisation should attack the COUNT (the constraint's
    /// degree, which sets `per_evals`) or the COST (what the inner gate does per call).
    #[test]
    fn where_the_prove_time_goes() {
        let (bytes, pb) = spend(0);
        let base = delta_base_layout(&[(bytes.clone(), pb.clone())], DELTA_TUPLE_VALS, Fa4::from_u64(SPEND_VALIDITY_DOMAIN)).expect("shape");
        let powers = delta_residual_count(&probe_gate(), base);
        let layout = delta_layout(base, powers, 1, DELTA_FIXED_SLOTS, 1 + DELTA_TUPLE_VALS, DELTA_TUPLE_VALS).expect("lay");
        let b: crate::committed_air::CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        let oob = crate::air_zerocheck::OobLatch::new();
        let row = Row::new(&b.zc.opened, &oob);
        let zero_at = |_c: usize, _p: &[Ea4]| -> Ea4 { Ea4::ZERO };
        let r_pt = vec![Ea4::ZERO; base.nvars];
        let gate = probe_gate();

        // The INNER gate alone — what `BoundStepConstraint` calls once per evaluation.
        let n = 200;
        let t = std::time::Instant::now();
        let mut k = 0usize;
        for _ in 0..n {
            k += gate.residuals(&row, &zero_at, &r_pt).len();
        }
        let inner_us = t.elapsed().as_micros() as f64 / n as f64;

        let per_evals = layout.bound.per.max(2) + 2;
        let evals = (per_evals as u64) * ((1u64 << layout.bound.nvars) - 1) * layout.rows() as u64;
        // How tall is ONE carrier's walk, and how much of its segment is padding?
        let (ood, cap) = committed_schedule_params(base.nvars, base.width).expect("params");
        let (lens, samples) =
            committed_schedule_lens(base.nvars, base.per, 1 + DELTA_TUPLE_VALS, ood, cap).expect("sched");
        let (_a, _s, planned) = plan(&lens, &samples).expect("plan");
        eprintln!(
            "[cost] ONE carrier walk = {planned} duplexings -> segment {} rows ({} wasted, {:.0}%) · \
             total sponge rows {} for {} slots",
            layout.seg_rows(),
            layout.seg_rows() - planned,
            100.0 * (layout.seg_rows() - planned) as f64 / layout.seg_rows() as f64,
            layout.rows() * layout.seg_rows(),
            layout.rows()
        );
        eprintln!(
            "[cost] residuals={} powers={powers} · ONE inner-gate eval = {inner_us:.0} us · \
             step-table evals ~= {evals} · so the gate alone is ~{:.1} s of CPU",
            k / n,
            inner_us * evals as f64 / 1e6
        );
        assert!(k > 0, "the gate must produce residuals");
    }

    /// ⭐⭐⭐ THE PRODUCTION ENTRY POINTS — what a block actually calls, end to end.
    ///
    /// Every other gate here drives the aggregate through a test fixture's factory. This one goes
    /// through `prove_block_note_transition` / `verify_block_note_transition`, which is what a producer
    /// and a peer will run: the verifier is handed only the SHAPE, the two transition roots and a
    /// `rows_digest` — no carrier, no layout it did not rebuild itself.

    #[test]
    fn the_production_entry_points_prove_and_verify_a_block_note_transition() {
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..3).map(spend).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let (bytes, shape, digest) =
            prove_block_note_transition(&carriers, dom, &onr, &dsr).expect("the block proves");
        eprintln!(
            "[delta] production path: n={} slots={} {} byte(s), shape rebuilds={}",
            shape.n,
            shape.slots,
            bytes.len(),
            shape.layout().is_some()
        );
        assert!(
            verify_block_note_transition(&bytes, shape, dom, &onr, &dsr, &digest),
            "⛔ the production verify refused a proof the production prover made"
        );
        // ⛔ AND THE STATEMENT IS LOAD-BEARING ON EVERY AXIS A PEER CHECKS.
        let other = vec![Fa4::from_u64(0xA2); 4];
        let mut bad_digest = digest.clone();
        bad_digest[0] += Fa4::ONE;
        assert!(
            !verify_block_note_transition(&bytes, shape, dom, &other, &dsr, &digest),
            "⛔ a DIFFERENT output-notes root was accepted"
        );
        assert!(
            !verify_block_note_transition(&bytes, shape, dom, &onr, &other, &digest),
            "⛔ a DIFFERENT del_set root was accepted"
        );
        assert!(
            !verify_block_note_transition(&bytes, shape, dom, &onr, &dsr, &bad_digest),
            "⛔ a rows_digest that is not the chain's own output was accepted"
        );
        // A shape that does not describe a stateable delta is refused before anything is allocated.
        let mut bad = shape;
        bad.n = shape.slots + 1;
        assert!(bad.layout().is_none(), "⛔ more carriers than slots was stateable");
        assert!(
            !verify_block_note_transition(&bytes, bad, dom, &onr, &dsr, &digest),
            "⛔ an unstateable shape was accepted"
        );
    }

    /// ⭐⭐⭐ THE BOUND TEMPLATE DOUBLE (docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md §3 — §9.6 parity with the band
    /// double): it states the SAME shape and `rows_digest` the real aggregate states, an armed door takes the honest block,
    /// and every axis the real door checks — both transition roots, the list (its digest), the shape, the class's domain
    /// word, the bytes — is refused on the armed door too. And the two forms never cross: the REAL door refuses the double's
    /// bytes, and an armed door refuses a real proof. The producer's refusals are the real prover's (another class's carrier
    /// is laid by neither).
    #[test]
    fn bound_note_transition_double_pins_the_same_statement_and_only_an_armed_door_takes_it() {
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..3).map(spend).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let t0 = std::time::Instant::now();
        let (bb, bshape, bdigest) =
            prove_block_note_transition_bound(&carriers, dom, &onr, &dsr).expect("the bound double lays the block");
        let bound_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        let (rb, rshape, rdigest) = prove_block_note_transition(&carriers, dom, &onr, &dsr).expect("the real aggregate lays");
        eprintln!(
            "[template-double] note class n=3: bound {} B in {bound_ms} ms · real {} B in {} ms",
            bb.len(),
            rb.len(),
            t1.elapsed().as_millis()
        );
        assert_eq!(bshape, rshape, "⛔ the double states another shape than the real aggregate");
        assert_eq!(bdigest, rdigest, "⛔ the double states another rows_digest than the real aggregate");
        assert!(
            verify_block_note_transition_bound(&bb, bshape, dom, &onr, &dsr, &bdigest),
            "CALIBRATION: an armed door takes the honest double"
        );
        assert!(
            verify_block_note_transition(&rb, rshape, dom, &onr, &dsr, &rdigest),
            "CALIBRATION: the real door takes the real aggregate"
        );
        // ⛔ THE FORMS NEVER CROSS.
        assert!(
            !verify_block_note_transition(&bb, bshape, dom, &onr, &dsr, &bdigest),
            "⛔⛔⛔ the REAL door accepted the bound double's bytes"
        );
        assert!(
            !verify_block_note_transition_bound(&rb, rshape, dom, &onr, &dsr, &rdigest),
            "⛔ an armed door accepted a real proof — an armed hub must never mix the two forms"
        );
        // ⛔ EVERY AXIS THE REAL DOOR CHECKS, THE ARMED DOOR CHECKS.
        let other = vec![Fa4::from_u64(0xA2); 4];
        let mut bad_digest = bdigest.clone();
        bad_digest[0] += Fa4::ONE;
        let refuses = |b: &[u8], s: DeltaShape, d: Fa4, o: &[Fa4], x: &[Fa4], g: &[Fa4]| {
            !verify_block_note_transition_bound(b, s, d, o, x, g)
        };
        assert!(refuses(&bb, bshape, dom, &other, &dsr, &bdigest), "⛔ a DIFFERENT output-notes root was accepted");
        assert!(refuses(&bb, bshape, dom, &onr, &other, &bdigest), "⛔ a DIFFERENT del_set root was accepted");
        assert!(refuses(&bb, bshape, dom, &onr, &dsr, &bad_digest), "⛔ a rows_digest the list does not hash to was accepted");
        assert!(refuses(&bb, bshape, dom, &onr, &dsr, &bdigest[..DIGEST_LANES - 1]), "⛔ a torn rows_digest was accepted");
        assert!(refuses(&bb, bshape, dom + Fa4::ONE, &onr, &dsr, &bdigest), "⛔ another class's domain word was accepted");
        let other_n = note_class_shape(2).expect("the class states n = 2");
        assert!(refuses(&bb, other_n, dom, &onr, &dsr, &bdigest), "⛔ the block's statement at another spend count was accepted");
        let mut unstateable = bshape;
        unstateable.n = bshape.slots + 1;
        assert!(refuses(&bb, unstateable, dom, &onr, &dsr, &bdigest), "⛔ an unstateable shape was accepted");
        for at in [0, bb.len() / 2, bb.len() - 1] {
            let mut f = bb.clone();
            f[at] ^= 1;
            assert!(refuses(&f, bshape, dom, &onr, &dsr, &bdigest), "⛔ a flipped byte {at} was accepted");
        }
        assert!(refuses(&[], bshape, dom, &onr, &dsr, &bdigest), "⛔ empty bytes were accepted");
        // ⛔ THE PRODUCER'S REFUSALS ARE THE REAL PROVER'S: carriers of another class (their domain word) are laid by neither.
        assert!(prove_block_note_transition(&carriers, dom + Fa4::ONE, &onr, &dsr).is_none(), "CALIBRATION: the real prover refuses");
        assert!(
            prove_block_note_transition_bound(&carriers, dom + Fa4::ONE, &onr, &dsr).is_none(),
            "⛔ the double laid carriers the real prover refuses"
        );
        eprintln!("[template-double] ⭐ note class: one statement, every tamper refused on the armed door, the forms never cross");
    }

    /// The bound double for the COVER and BOND classes — the same law through the same shared site (`delta_prove` /
    /// `delta_verify`): one statement with the real aggregate, the forms never cross, a moved root or digest is refused.
    #[test]
    fn bound_cover_and_bond_doubles_pin_the_same_statement_and_never_cross_the_real_door() {
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let other = vec![Fa4::from_u64(0xA2); 4];
        // BOND
        let bonds: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(bond).collect();
        let bdom = bonds[0].1[0];
        let (bb, bs, bd) = prove_block_bond_transition_bound(&bonds, bdom, &onr, &dsr).expect("the bond double lays");
        let (rb, rs, rd) = prove_block_bond_transition(&bonds, bdom, &onr, &dsr).expect("the real bond aggregate lays");
        assert_eq!((bs, &bd), (rs, &rd), "⛔ the bond double states another statement than the real aggregate");
        assert!(verify_block_bond_transition_bound(&bb, bs, bdom, &onr, &dsr, &bd), "CALIBRATION: an armed door takes the bond double");
        assert!(!verify_block_bond_transition(&bb, bs, bdom, &onr, &dsr, &bd), "⛔⛔ the REAL bond door accepted the double's bytes");
        assert!(!verify_block_bond_transition_bound(&rb, rs, bdom, &onr, &dsr, &rd), "⛔ an armed bond door accepted a real proof");
        assert!(!verify_block_bond_transition_bound(&bb, bs, bdom, &other, &dsr, &bd), "⛔ the bond double under a moved root");
        // a note-class door handed the bond double: another class's statement (shape and domain) is refused
        assert!(
            !verify_block_note_transition_bound(&bb, bs, bdom, &onr, &dsr, &bd),
            "⛔ a note-class armed door accepted the BOND double"
        );
        // COVER
        let covers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(|i| super::cover_transition_tests::carrier(5, 40 + i)).collect();
        let cdom = covers[0].1[0];
        let (cb, cs, cd) = prove_block_cover_transition_bound(&covers, cdom, &onr, &dsr).expect("the cover double lays");
        let (crb, crs, crd) = prove_block_cover_transition(&covers, cdom, &onr, &dsr).expect("the real cover aggregate lays");
        assert_eq!((cs, &cd), (crs, &crd), "⛔ the cover double states another statement than the real aggregate");
        assert!(verify_block_cover_transition_bound(&cb, cs, cdom, &onr, &dsr, &cd), "CALIBRATION: an armed door takes the cover double");
        assert!(!verify_block_cover_transition(&cb, cs, cdom, &onr, &dsr, &cd), "⛔⛔ the REAL cover door accepted the double's bytes");
        assert!(!verify_block_cover_transition_bound(&crb, crs, cdom, &onr, &dsr, &crd), "⛔ an armed cover door accepted a real proof");
        let mut cbad = cd.clone();
        cbad[1] += Fa4::ONE;
        assert!(!verify_block_cover_transition_bound(&cb, cs, cdom, &onr, &dsr, &cbad), "⛔ the cover double under a moved digest");
        eprintln!("[template-double] ⭐ cover + bond classes: one statement each, the forms never cross");
    }

    /// `i` distinct REAL welded bonds — the production bond carrier on the production committed path, pathless (the
    /// class's production depth, DB-313 R5), each bind rebuilt in the carrier's own order.
    /// ⛔ DB-376 — THE EMPIRICAL TEST of the strict free-witness census's refusal on the bond class step table (692
    /// undeclared live columns from 8168, measured 2026-10-03 by the one-sweep scanner's circuit pass).
    /// HYPOTHESIS: they are OPENED cells (the inner bond carrier's row at the random point) of inner columns the bond
    /// configuration's gate NEVER READS — live only because `Blinded` fills half the inner trace with randomness.
    /// TEST: (1) every refused column lies in the step row's `opened` region; (2) the inner gate's residual on a
    /// generic row is unchanged when that inner column is nudged (an unread column leaves it IDENTICALLY unchanged; a
    /// read one moves it with overwhelming probability). A failure here REFUTES the hypothesis and names the read ones.
    #[test]
    fn db376_the_refused_bond_step_columns_are_opened_cells_the_inner_gate_never_reads() {
        use crate::air_zerocheck::{OobLatch, Row};
        let shape = bond_class_shape(3).expect("the bond class shape");
        let limbs = crate::committed_air::EXT_LIMBS;
        let opened_off = shape.nvars * shape.per + 3 * shape.nvars + 1; // values: evals | r | z | claim | cf | opened
        let (lo, hi) = (limbs * opened_off, limbs * (opened_off + shape.width));
        let refused: Vec<usize> = (8168..8168 + 692).collect();
        eprintln!(
            "[db376] opened region = limb columns {lo}..{hi} ({} inner values); refused {}..={}",
            shape.width,
            refused[0],
            refused[refused.len() - 1]
        );
        let outside: Vec<usize> = refused.iter().copied().filter(|c| *c < lo || *c >= hi).collect();
        assert!(outside.is_empty(), "⛔ DB-376 hypothesis REFUTED: {} refused column(s) lie OUTSIDE the opened region: {:?}", outside.len(), &outside[..outside.len().min(16)]);
        let zero = [Ea4::ZERO; DIGEST_LANES];
        let gate = crate::committed_air::Blinded {
            inner: crate::whir_rec_block::SpendValidityGate {
                gamma: Ea4::ZERO,
                out0_cm: zero,
                out1_cm: zero,
                nullifier: zero,
                bond_amount: Some(crate::whir_rec_block::bond_limbs(0)),
                // §BR-14: every block-level spend row pays the protocol's flat fee — the aggregate welds it as the carriers do
                fee_amount: Some(crate::whir_rec_block::fee_limbs(crate::whir_rec_block::PROTOCOL_FEE_ATOMIC)),
                leaf_commit: zero,
                tag1: None,
                vault: None,
            },
        };
        // a generic row and point (splitmix values: no relation the gate could vanish on by accident)
        let mix = |i: u64| -> Fa4 {
            let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            Fa4::from_u64((z ^ (z >> 31)) % 2_130_706_433)
        };
        let row: Vec<Ea4> = (0..shape.width as u64).map(|i| Ea4::from(mix(i))).collect();
        let x: Vec<Ea4> = (0..shape.nvars as u64).map(|i| Ea4::from(mix(1_000_000 + i))).collect();
        let eval = |r: &[Ea4]| -> Ea4 {
            let oob = OobLatch::new();
            let at = |_c: usize, _p: &[Ea4]| -> Ea4 { Ea4::ZERO };
            let v = gate.eval(&Row::new(r, &oob), &at, &x);
            assert!(!oob.hit(), "the inner gate read past its row");
            v
        };
        let base = eval(&row);
        let inner_cols: std::collections::BTreeSet<usize> = refused.iter().map(|c| c / limbs - opened_off).collect();
        let read: Vec<usize> = inner_cols
            .iter()
            .copied()
            .filter(|&ic| {
                let mut nudged = row.clone();
                nudged[ic] += Ea4::ONE;
                eval(&nudged) != base
            })
            .collect();
        eprintln!("[db376] {} inner column(s) behind the refused cells: {:?}..; read by the bond gate: {}", inner_cols.len(), inner_cols.iter().next(), read.len());
        assert!(
            read.is_empty(),
            "⛔ DB-376 hypothesis REFUTED: the bond configuration's inner gate READS {} of the refused columns' inner \
             cells ({:?}) — the census found live cells a law DOES read through the opening, so this is not a \
             declaration gap",
            read.len(),
            &read[..read.len().min(16)]
        );
    }

    fn bond(i: u64) -> (Vec<u8>, Vec<Fa4>) {
        let sk = lanes_of(&[31 + i, 32, 33, 34]);
        let weight = 700 + i;
        let w = SpendValidityWitness {
            value_in: 800 + i + crate::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14: in == out + the protocol fee
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + i,
            fee: crate::whir_rec_block::PROTOCOL_FEE_ATOMIC,
            lc_blind: lanes_of(&[0x363, i, 3, 4]),
            out0_value: weight,
            out0_opening: lanes_of(&[8, 8, 8, 8]),
            out1_value: 800 + i - weight,
            out1_opening: sk,
        };
        let (bytes, cms, nf, lc) =
            crate::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, weight).expect("the production bond proves");
        let f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|j| Fa4::from_u64(d[j])) };
        // The carrier's OWN bind through the decider's one bind function (DB-340: W as four limbs, padded to the width).
        let pb = crate::whir_rec_block::bond_validity_public_bind_with_commit(
            &[f(cms[0]), f(cms[1])],
            &f(nf),
            weight,
            &f(lc),
        );
        (bytes, pb)
    }

    /// ⛔⛔ DB-313 §3 — THE BOND CLASS STATES A WELDED SPEND, AND ITS WEIGHT IS LOAD-BEARING.
    /// Before this class no aggregate could state a bond carrier (the template's plain verifier evicted every one), so a
    /// USDm bond could never land. CALIBRATION: the honest proof verifies and the peer's digest is the circuit's. TAMPERS
    /// (each REJECTS): a row whose W was moved; a row whose nullifier was swapped; a lying row whose W its carrier never
    /// welded (the inflation shape: weight claimed beyond the locked value); a plain spend stated as a bond; the bond
    /// proof read as a note transition.
    #[test]
    fn db313_the_bond_class_states_a_welded_spend_and_its_weight_is_load_bearing() {
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..3).map(bond).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(crate::whir_rec_block::BOND_VALIDITY_DOMAIN);
        let (bytes, shape, digest) = prove_block_bond_transition(&carriers, dom, &onr, &dsr)
            .expect("⛔ DB-313: the bond class could not state three real welded bonds");
        eprintln!("[db313] bond class: n={} slots={} {} byte(s)", shape.n, shape.slots, bytes.len());
        assert_eq!(bond_class_shape(3), Some(shape), "the shape is the class's, never the block's");
        assert!(
            verify_block_bond_transition(&bytes, shape, dom, &onr, &dsr, &digest),
            "⛔ CONTROL: the bond class refused the proof its own prover made"
        );
        let tuples: Vec<Vec<Fa4>> = carriers.iter().map(|(_, pb)| pb[1..].to_vec()).collect();
        assert_eq!(
            rows_digest_of(&tuples, shape.slots, BOND_TUPLE_VALS).expect("the digest a peer recomputes"),
            digest,
            "CALIBRATION: the digest a peer recomputes from the block's bond tuples is the circuit's"
        );
        // TAMPER 1 — a MOVED WEIGHT in the tuple list the peer judges the block by.
        let mut moved = tuples.clone();
        moved[1][3 * DIGEST_LANES] += Fa4::ONE;
        let moved = rows_digest_of(&moved, shape.slots, BOND_TUPLE_VALS).expect("digest");
        assert!(
            !verify_block_bond_transition(&bytes, shape, dom, &onr, &dsr, &moved),
            "⛔⛔ DB-313: a bond row whose weight was moved verified"
        );
        // TAMPER 2 — a SWAPPED NULLIFIER.
        let mut swapped = tuples.clone();
        swapped[0][2 * DIGEST_LANES] += Fa4::ONE;
        let swapped = rows_digest_of(&swapped, shape.slots, BOND_TUPLE_VALS).expect("digest");
        assert!(
            !verify_block_bond_transition(&bytes, shape, dom, &onr, &dsr, &swapped),
            "⛔⛔ DB-313: a bond row whose nullifier was swapped verified"
        );
        // TAMPER 3 — A LYING ROW: the carrier welded W, the row states W + 1 (validator weight beyond the locked value).
        let mut lying = carriers.clone();
        lying[0].1[1 + 3 * DIGEST_LANES] += Fa4::ONE;
        let laid = prove_block_bond_transition(&lying, dom, &onr, &dsr);
        assert!(
            laid.as_ref().map_or(true, |(b, s, d)| !verify_block_bond_transition(b, *s, dom, &onr, &dsr, d)),
            "⛔⛔⛔ DB-313: an aggregate stated a weight its carrier never welded — validator weight could be inflated"
        );
        // TAMPER 4 — A NON-ZERO PAD: the pad is bound (the carrier absorbed zeros; the peer recomputes with zeros).
        let mut padded = tuples.clone();
        padded[2][BOND_TUPLE_VALS - 1] += Fa4::ONE;
        let padded = rows_digest_of(&padded, shape.slots, BOND_TUPLE_VALS).expect("digest");
        assert!(
            !verify_block_bond_transition(&bytes, shape, dom, &onr, &dsr, &padded),
            "⛔⛔ DB-313: a bond row with a non-zero pad cell verified"
        );
        // TAMPER 5 — THE MOD-p ALIAS (DB-340): a row stating the limbs of W + p. CALIBRATION: the alias is real — the
        // two weights are ONE field element — so only the limb-wise weld can tell them apart.
        let p = 0x7f00_0001u64;
        let aliased = 700u64 + p; // bond(0)'s weight + p
        assert_eq!(Fa4::from_u64(aliased), Fa4::from_u64(700), "CALIBRATION: W + p aliases W in the field");
        let mut alias = carriers.clone();
        for i in 0..bond_limb_count() {
            alias[0].1[1 + 3 * DIGEST_LANES + i] = Fa4::from_u64((aliased >> (16 * i)) & 0xffff);
        }
        let laid = prove_block_bond_transition(&alias, dom, &onr, &dsr);
        assert!(
            laid.as_ref().map_or(true, |(b, s, d)| !verify_block_bond_transition(b, *s, dom, &onr, &dsr, d)),
            "⛔⛔⛔ DB-340 × DB-313: a bond row stating W + p verified — the class would bind the weight only mod p"
        );
        // CLASS SEPARATION — a plain spend is not a bond, and a bond aggregate is not a note transition.
        let plain: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(spend).collect();
        assert!(
            prove_block_bond_transition(&plain, dom, &onr, &dsr).is_none(),
            "⛔ DB-313: a plain spend (no weld) was stated in the bond class"
        );
        assert!(
            !verify_block_note_transition(&bytes, shape, Fa4::from_u64(SPEND_VALIDITY_DOMAIN), &onr, &dsr, &digest),
            "⛔ DB-313: a bond aggregate verified as a plain note transition"
        );
    }

    /// ⛔⛔⛔ DB-213b ON THE INGEST PATH — every field of the wire `DeltaShape` was the producer's to choose.
    ///
    /// CALIBRATION: each lever below passes the gate a peer ran before the pin (`DeltaShape::layout`, plus
    /// `rows_digest_of`'s own power-of-two test for `slots`) — so the shape reached the layout, the schedule
    /// sizing and the per-round eval reads. REFUTATION: the pinned verifier refuses every one, and the class
    /// derivation equals, field for field, the shape the producer laid from REAL carriers.
    #[test]
    fn db213b_the_note_transition_shape_is_the_classes_never_the_blocks() {
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..3).map(spend).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let (bytes, shape, digest) =
            prove_block_note_transition(&carriers, dom, &onr, &dsr).expect("the block proves");
        assert_eq!(
            note_class_shape(shape.n),
            Some(shape),
            "the class derivation must equal the shape the producer laid from real carriers"
        );
        assert!(verify_block_note_transition(&bytes, shape, dom, &onr, &dsr, &digest), "honest control");
        let levers: Vec<(&str, DeltaShape)> = vec![
            ("per = 1", DeltaShape { per: 1, ..shape }),
            ("per + 1", DeltaShape { per: shape.per + 1, ..shape }),
            ("nvars + 1", DeltaShape { nvars: shape.nvars + 1, ..shape }),
            ("nvars = 32", DeltaShape { nvars: 32, ..shape }),
            ("width + 1", DeltaShape { width: shape.width + 1, ..shape }),
            ("powers + 1", DeltaShape { powers: shape.powers + 1, ..shape }),
            ("power_lo + 1", DeltaShape { power_lo: shape.power_lo + 1, ..shape }),
            ("seg_log - 1", DeltaShape { seg_log: shape.seg_log - 1, ..shape }),
            ("slots = 2^31", DeltaShape { slots: 1 << 31, ..shape }),
        ];
        for (name, bad) in levers {
            // The pre-pin gate: `layout()` minus the slot pin it now carries, i.e. exactly what a peer ran.
            let old_gate = bad.n != 0 && bad.n <= bad.slots && bad.slots.is_power_of_two() && bad.powers != 0;
            let refused = !verify_block_note_transition(&bytes, bad, dom, &onr, &dsr, &digest);
            println!("[DB-213b delta] {name}: pre-pin gate passed = {old_gate}; pinned verify refused = {refused}");
            assert!(old_gate, "calibration: `{name}` must have passed the pre-pin gate, or it measures nothing");
            assert!(refused, "⛔ `{name}` — a block-chosen shape field reached the verifier");
        }
        // The peer pads the tuple list to `slots` BEFORE the proof: that padding must refuse, not allocate.
        let one = vec![vec![Fa4::ONE; DELTA_TUPLE_VALS]];
        let t = std::time::Instant::now();
        let padded = rows_digest_of(&one, 1 << 31, DELTA_TUPLE_VALS);
        let us = t.elapsed().as_micros();
        println!(
            "[DB-213b delta] rows_digest_of(1 tuple, slots = 2^31) = {:?} in {us} us",
            padded.as_ref().map(|d| d.len())
        );
        assert!(padded.is_none(), "⛔ a block-chosen slot count was padded to");
        assert!(rows_digest_of(&one, DELTA_FIXED_SLOTS, DELTA_TUPLE_VALS).is_some(), "the protocol slot count digests");
    }

    /// ⛔⛔⛔ §BD's SHAPE — AN AGGREGATE OVER NOTHING. `settlement_aggregate_from_bundles` verifies over
    /// ZERO ROWS with no inner carrier, which is why it could never certify a delta. This one refuses to
    /// be stated at all without carriers, and refuses carriers of mixed shape.
    #[test]
    fn an_aggregate_over_no_carriers_or_mixed_shapes_cannot_be_stated() {
        assert!(
            settlement_delta_tables(&[], DeltaLayout { bound: BoundLayout { nvars: 4, per: 11, width: 1986, powers: 1, power_lo: 0, shifted_lo: 0, shifted: 0 }, n: 0, seg_log: 8, slots: 16, tuple_vals: DELTA_TUPLE_VALS }).is_none(),
            "⛔⛔⛔ an aggregate over ZERO carriers was stateable — that is §BD exactly: a proof that \
             certifies nothing, adopted as if it certified a block"
        );
        // A bind that is not a spend bind is refused before any allocation.
        let (bytes, _pb) = spend(0);
        assert!(
            settlement_delta_tables(&[(bytes, vec![Fa4::ONE; 3])], lay(&[spend(0)])).is_none(),
            "⛔ a carrier whose bind is not (domain + four digests) was accepted"
        );
        eprintln!("[delta] ⭐ an empty delta and a mis-shaped bind are both unstateable");
    }
}

/// ⭐ DB-223 Q4 — the chain-stride rule the member-path class (`crate::member_path_gate`, LANDED 2026-09-28 from the
/// measurement that lived here) rests on, pinned beside the private `chain_stride_is_exact` it reads.
#[cfg(test)]
mod db223_chain_stride_tests {
    use super::*;
    use crate::member_path_gate::{member_class_base, MEMBER_TUPLE_VALS};

    /// ⛔ A tuple the chain cannot stride exactly is refused at LAYOUT time, on the prover's side — instead of a
    /// proof no honest verifier can accept. MEASURED before the rule: the three-digest version of the member class
    /// proved without complaint and its honest aggregate failed to verify (every carrier after the first was checked
    /// at the wrong chain rows). Every width the protocol states today must still lay.
    #[test]
    fn db223_q4_a_tuple_width_the_chain_cannot_stride_is_refused_at_layout_time() {
        let (base, powers) = member_class_base();
        for digests in 1..=8usize {
            let tv = digests * DIGEST_LANES;
            let laid = delta_layout(base, powers, 1, DELTA_MIN_SLOTS, 1 + tv, tv).is_some();
            let exact = (tv / crate::sponge_chain_air::RATE).is_power_of_two() && tv % crate::sponge_chain_air::RATE == 0;
            assert_eq!(
                laid, exact,
                "⛔ a {digests}-digest tuple ({tv} values): laid={laid}, but the chain strides it exactly={exact}"
            );
        }
        for (name, tv) in [
            ("spend", DELTA_TUPLE_VALS),
            ("spend-or-decoy", COVER_TUPLE_VALS),
            ("bond", BOND_TUPLE_VALS),
            ("membership", MEMBER_TUPLE_VALS),
        ] {
            assert!(chain_stride_is_exact(tv), "⛔ the {name} class's width ({tv}) must still lay");
        }
        eprintln!("[db223-q4] ⭐ widths 1/2/4/8 digests lay; 3/5/6/7 are refused at layout time; all four classes stride exactly");
    }
}

#[cfg(test)]
mod db452_forgery_tests {
    use super::*;
    use crate::whir_rec_block::SPEND_VALIDITY_DOMAIN;

    /// ⛔⛔⛔ DB-452 — DOES A BLOCK'S NOTE TRANSITION BIND THE SPENDS IT STATES?
    ///
    /// A peer that grafts a block admits its output notes on the strength of the note transition alone (the block carries
    /// tx ids, not carriers). So the question is whether a producer holding valid carriers for spends A can publish a
    /// transition the production door accepts for a DIFFERENT tuple list B — here A with one output commitment replaced
    /// by one the producer chose, i.e. a note no carrier ever proved. The adversary
    /// (`forge_public_tie_light_decider_for_tests`) runs the honest prover over A's tables and tells exactly ONE lie: the
    /// chain's final state, tied to B's public `rows_digest`, is SENT as B's digest. CONTROL: the same forger with no lie,
    /// under A's own statement, must verify (so a forger that merely desynchronises cannot read as a hole).
    #[test]
    fn db452_a_note_transition_stating_spends_no_carrier_proved_is_refused() {
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); DIGEST_LANES], vec![Fa4::from_u64(0xB2); DIGEST_LANES]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let honest: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(super::tests::spend).collect();
        let (_bytes, shape, digest_a) = prove_block_note_transition(&honest, dom, &onr, &dsr).expect("the honest block proves");
        let layout = shape.layout().expect("the note shape lays");
        let mk = || make_settlement_delta_constraint(layout, spend_delta_factory(layout));
        let ties = || {
            settlement_delta_ties(layout, 1 + layout.tuple_vals, DELTA_DOMAIN_OFF, delta_digest_off(onr.len(), dsr.len()))
                .expect("the note ties")
        };

        // CONTROL — the forger's code path with no lie, under A's own statement.
        let (tables, d) = settlement_delta_tables(&honest, layout).expect("A's tables");
        assert_eq!(d, digest_a, "A's tables state A's digest");
        let (cross, cols) = ties();
        let bind_a = settlement_delta_bind(layout.n, dom, &onr, &dsr, &digest_a);
        let control = crate::whir_rec_block::forge_public_tie_light_decider_for_tests(tables, mk(), &cross, &cols, &bind_a, false)
            .expect("the control proves");
        assert!(
            verify_block_note_transition(&control, shape, dom, &onr, &dsr, &digest_a),
            "CONTROL: the forger's honest path must verify — otherwise a refusal below means nothing"
        );

        // THE FORGERY — B = A with spend 1's first output commitment replaced by a note the producer chose.
        let mut tuples: Vec<Vec<Fa4>> = honest.iter().map(|(_, pb)| pb[1..].to_vec()).collect();
        for (j, lane) in tuples[1][..DIGEST_LANES].iter_mut().enumerate() {
            *lane = Fa4::from_u64(0x0BAD_C0DE + j as u64);
        }
        let digest_b = rows_digest_of(&tuples, layout.rows(), layout.tuple_vals).expect("B's digest");
        assert_ne!(digest_b, digest_a, "B states a different tuple list");
        let (tables, _) = settlement_delta_tables(&honest, layout).expect("A's tables again");
        let bind_b = settlement_delta_bind(layout.n, dom, &onr, &dsr, &digest_b);
        let (cross, cols) = ties();
        let forged = crate::whir_rec_block::forge_public_tie_light_decider_for_tests(tables, mk(), &cross, &cols, &bind_b, true)
            .expect("the forger produces bytes");
        let accepted = verify_block_note_transition(&forged, shape, dom, &onr, &dsr, &digest_b);
        eprintln!(
            "[db452] control (A, no lie) verifies = true · forged transition for B (an output commitment no carrier \
             proved, {} B) verifies = {accepted}",
            forged.len()
        );
        assert!(
            !accepted,
            "⛔⛔⛔ DB-452: a note transition stating an output note NO CARRIER PROVED passes the production door — the \
             light decider binds no opening to a committed trace (no trace commitment; the masked sumcheck's final target \
             is dropped), so a producer can admit any note it likes: INFLATION"
        );
    }

    /// MEASURE (P13 / DB-452 cons): the production 256-slot note transition on the committed opening — bytes by field,
    /// prove ms, verify ms — and the honest proof through the production door.
    #[test]
    fn db452_b_note_transition_bytes_and_times_on_the_committed_opening() {
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); DIGEST_LANES], vec![Fa4::from_u64(0xB2); DIGEST_LANES]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let honest: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(super::tests::spend).collect();
        let t = std::time::Instant::now();
        let (bytes, shape, digest) = prove_block_note_transition(&honest, dom, &onr, &dsr).expect("the honest block proves");
        let prove_ms = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let ok = verify_block_note_transition(&bytes, shape, dom, &onr, &dsr, &digest);
        let verify_ms = t.elapsed().as_millis();
        assert!(ok, "the honest note transition verifies through the production door");
        let b: crate::whir_rec_block::AirBatchBusBundle = postcard::from_bytes(&bytes).expect("decodes");
        let sz =|x: &dyn Fn() -> Vec<u8>| x().len();
        eprintln!(
            "[db452-b] note transition {} B (prove {prove_ms} ms, verify {verify_ms} ms) · round1 commitment+WHIR {} B · zcs {} B · ties {} B + {} B · shift binds {} ({} B) · shapes {:?}",
            bytes.len(),
            sz(&|| postcard::to_allocvec(&b.round1).unwrap()),
            sz(&|| postcard::to_allocvec(&b.zcs).unwrap()),
            sz(&|| postcard::to_allocvec(&b.cross_tie_openings).unwrap()),
            sz(&|| postcard::to_allocvec(&b.column_tie_openings).unwrap()),
            b.shift_binds.len(),
            sz(&|| postcard::to_allocvec(&b.shift_binds).unwrap()),
            b.shapes,
        );
    }
}

#[cfg(test)]
mod producer_forgery_tests {
    use super::*;
    use crate::poseidon2_compress::{lanes_of, Digest};
    use crate::whir_rec_block::{
        clock_const, fee_limbs, note_spend_row_width, validity_public_bind_with_commit, verify_spend_validity_carrier_bytes,
        SpendValidityGate, LIGHT_CARRIER_ROWS, PROTOCOL_FEE_ATOMIC, SPEND_VALIDITY_DOMAIN,
    };

    /// A SPEND NOBODY PROVED, as a block producer would make it: six public digests it simply chose (an output note of
    /// any value, a tag of its liking) and a "carrier" for them made with no witness at all
    /// (`committed_air::forge_blinded_opened_row_for_tests`: a garbage commitment, zero rounds, one opened cell solved).
    /// Returns the bytes, the statement's public bind, and the digests `(out0, out1, nullifier, leaf_commit, clue, tag1)`.
    /// CALIBRATION, asserted here for every user: the per-transaction door REFUSES these bytes.
    fn a_spend_nobody_proved() -> (Vec<u8>, Vec<Fa4>, [Digest; 6]) {
        let d = |a: u64| -> Digest { crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[a, 1, 2, 3]), lanes_of(&[a, 4, 5, 6])) };
        let (o0, o1, nf, lc, clue, tag1) = (d(1), d(2), d(3), d(4), d(5), d(6));
        let f = |x: &Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|i| Fa4::from_u64(x[i])) };
        let e = |x: &Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| Fa4::from_u64(x[i]).into()) };
        let (o0e, o1e, nfe, lce, t1e) = (e(&o0), e(&o1), e(&nf), e(&lc), e(&tag1));
        let make = move |g: Ea4| SpendValidityGate {
            leaf_commit: lce,
            gamma: g,
            out0_cm: o0e,
            out1_cm: o1e,
            nullifier: nfe,
            bond_amount: None,
            fee_amount: Some(fee_limbs(PROTOCOL_FEE_ATOMIC)),
            tag1: Some(t1e),
            vault: Some(clock_const(0)),
        };
        let bind = validity_public_bind_with_commit(&[f(&o0), f(&o1)], &f(&nf), &f(&lc), &f(&clue), &f(&tag1));
        let cols: Vec<Vec<Fa4>> = (0..note_spend_row_width())
            .map(|c| (0..LIGHT_CARRIER_ROWS).map(|r| Fa4::from_u64((c as u64) * 131 + (r as u64) * 7 + 1)).collect())
            .collect();
        let forged = crate::committed_air::forge_blinded_opened_row_for_tests(cols, make, &bind)
            .expect("CALIBRATION: the spend gate reads some opened cell affinely, so one cell solves it");
        assert!(
            !verify_spend_validity_carrier_bytes(&forged, o0, o1, nf, lc, clue, tag1, PROTOCOL_FEE_ATOMIC),
            "CALIBRATION 1: the per-transaction door must refuse a carrier whose opened row is not its commitment's"
        );
        (forged, bind, [o0, o1, nf, lc, clue, tag1])
    }

    /// ⛔⛔⛔ AUDIT 2026-11-10 (F14) — A BLOCK'S AGGREGATE ALONE IS NO EVIDENCE OF A SPEND. PINNED AS A LIMIT.
    ///
    /// The aggregate lays each spend's carrier as a bound step from the carrier's BYTES
    /// (`recursion_bound::bound_step_row_committed`): the opened row, the round values and the point are read from the
    /// bundle, the challenges are replayed, and the inner gate is evaluated on that opened row. Nothing in it checks the
    /// carrier's opening proof, the one thing that ties an opened row to the carrier's commitment (`recursion_bound.rs`
    /// says so in its own header: part (c), "bound to its inner STATEMENT but not to the inner PCS opening"). The slot
    /// ledger, the class production blocks are laid in, lays its spend rows through the same bound step.
    ///
    /// MEASURED 2026-11-10 12:09: the block that states a spend nobody proved beside an honest spend
    /// "lays = true and VERIFIES = Some(true)". Checking every opening inside the block proof is about ten thousand
    /// Poseidon rows per carrier (about 180 times today's block proof at a full block), so the REFUSAL DOES NOT LIVE
    /// HERE: it lives at the node's block door, where every node verifies every stated spend's transaction itself
    /// (`usdmd-node` `spend_evidence`, pinned on two nodes by
    /// `node::a_block_states_only_spends_its_peers_verified_tests`). This pin keeps that fact from being forgotten: it
    /// asserts the calibrations (the per-transaction door refuses the bytes; an honest block verifies) and that the
    /// aggregate, on its own, still accepts the forged statement. THE DAY IT READS FALSE, part (c) has landed in circuit:
    /// delete this assertion, and say in `spend_evidence.rs` that the node door is then defence in depth.
    #[test]
    fn the_block_aggregate_alone_accepts_a_spend_nobody_proved_so_every_node_verifies_each_spend_itself() {
        let (forged, bind_b, _) = a_spend_nobody_proved();
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); DIGEST_LANES], vec![Fa4::from_u64(0xB2); DIGEST_LANES]);
        let dom = Fa4::from_u64(SPEND_VALIDITY_DOMAIN);
        let honest: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(super::tests::spend).collect();
        let (hb, hshape, hdigest) = prove_block_note_transition(&honest, dom, &onr, &dsr).expect("the honest block proves");
        assert!(
            verify_block_note_transition(&hb, hshape, dom, &onr, &dsr, &hdigest),
            "CALIBRATION 2: an honest block must verify through this door, or the verdict below means nothing"
        );
        let stated = vec![honest[0].clone(), (forged.clone(), bind_b)];
        let laid = prove_block_note_transition(&stated, dom, &onr, &dsr);
        let accepted = laid.as_ref().map(|(b, shape, digest)| verify_block_note_transition(b, *shape, dom, &onr, &dsr, digest));
        eprintln!(
            "[producer-forgery] NOTE TRANSITION: a carrier nobody proved ({} B): the per-transaction door refuses it; the \
             block that states it lays = {} and the AGGREGATE ALONE verifies = {accepted:?} (the node's block door is the refusal)",
            forged.len(),
            laid.is_some()
        );
        assert_eq!(
            accepted,
            Some(true),
            "the aggregate now REFUSES a carrier nobody proved: part (c) landed in circuit. Delete this pinned limit and \
             record in usdmd-node's spend_evidence.rs that the node door is defence in depth"
        );
    }
}

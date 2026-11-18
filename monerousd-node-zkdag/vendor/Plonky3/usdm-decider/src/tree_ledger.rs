// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ V2 PIECE 2 — THE TREE LEDGER STATEMENT (docs/LEVEL-AGGREGATE-SPEC-20261115.md §15.5).
//!
//! WHY. Today's note ledger (`settlement_delta::lay_block_ledger`) proves, in ONE wide step row per ledger row, two things:
//! the carrier's verification re-done in circuit (the BOUND STEP, `SettlementDeltaAir::Rows`, with its transcript in a
//! SPONGE table and ties 1–6 of `settlement_delta_ties_masked`) and the ledger's own laws (`push_slot_ledger_laws`, the clock
//! law). A block in TREE form already verifies every payment's carriers in its leaves (`usdm_agg::tree_ssa`, one root every
//! node checks). So the tree ledger states ONLY the ledger: a step row of `tuple ‖ slot-ledger extension ‖ clock`, the
//! CHAIN table over the published rows, the chain↔published tie and the chain's output in the public bind — no bound step,
//! no sponge table. What tied a row to its carrier in circuit (tie 2, "the tuple is what the carrier's transcript
//! absorbed") becomes a NATIVE equality at the block door: a spend row publishes its tuple (law B8: `pub = s·abs + …`), the
//! door derives the published list and every tree-form payment's statement from the SAME block, and refuses a block whose
//! spend rows are not exactly its tree statements (the node's half, `spend_evidence`).
//!
//! §9.6 (this statement's door, `verify_tree_ledger`): (1) PoW — the block's; (2) the proof by the light decider over the
//! verifier's OWN statement (shapes, ties, bind rebuilt from the published list); (3) value — the ledger's laws, unchanged
//! and in circuit (every cover cell is P(domain ‖ slot, seed); a spend's cells are its tuple); (4) replay — the nullifier
//! set, unchanged; (5) work — one light-decider verify of a constant shape; (6) parity with `verify_block_ledger_transition`:
//! every check it makes except the bound step and its sponge, whose content is the tree's leaf; (7) SCALE: a constant shape
//! (`LEDGER_ROWS` rows) per block; (8) AI RESISTANT (a): a proof every node checks, and the native tuple equality.
//! cons: a second ledger statement shape beside today's (FULL blocks keep theirs). Bytes: MEASURED by the pin in
//! `settlement_delta::ledger_tests`.

use p3_field::PrimeCharacteristicRing;

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::settlement_delta::{
    chain_table_of, ledger_published_vals, note_ledger_bind, rows_digest_of, tie_run, LedgerPublished, LedgerRow,
    DELTA_TUPLE_VALS, LEDGER_ABS_CLOCK, LEDGER_ROWS,
};
use crate::slot_ledger as sl;
use crate::whir_rec_block::{ColumnTieSpec, CrossTieSpec, CLOCK_LE_WIDTH, PUBLIC_BIND_TABLE};

/// The step table (one row per ledger row) and the chain table (the rows digest).
pub const TL_STEP: usize = 0;
pub const TL_CHAIN: usize = 1;
/// The step row: the tuple at 0, the slot-ledger extension after it, the clock law's cells last.
const TL_EXT: usize = DELTA_TUPLE_VALS;
const TL_CLOCK: usize = TL_EXT + sl::SL_EXT_COLS;
/// Columns of the step table.
pub const TL_STEP_COLS: usize = TL_CLOCK + CLOCK_LE_WIDTH;
/// Where a step row's PUBLISHED block starts — what another statement's joint tie names (`tag_ledger::note_tags_tie`).
pub const TL_PUB: usize = TL_EXT + sl::SL_PUB;
/// The tuple's LAST digest, which no law reads (the absorbed digests and the clock are read): laid zero and forced zero.
const TL_UNREAD_DIGEST: usize = DELTA_TUPLE_VALS / DIGEST_LANES - 1;
const _: () = assert!(sl::ABS_DIGESTS <= LEDGER_ABS_CLOCK && LEDGER_ABS_CLOCK < TL_UNREAD_DIGEST);

/// The tree ledger's constraint, per table.
pub enum TreeLedgerAir {
    Step { seed_commit: [Ea4; DIGEST_LANES], block_clock: Ea4, gamma: Ea4 },
    Chain(crate::sponge_chain_air::SpongeChainConstraint),
}

impl TreeLedgerAir {
    /// The step row's residuals, generic over the field its row lives in (V2 (b) piece 3: `gate_trace::Sym` traces this
    /// body into the program the tree runs in circuit; the `Ea4` instantiation is the production body).
    pub(crate) fn step_residuals<E: crate::gate_trace::GateAlg>(local: &Row<'_, E>, seed_commit: &[E; DIGEST_LANES], block_clock: E) -> Vec<E> {
        let mut rs: Vec<E> = Vec::new();
        let abs = |k: usize, c: usize| local[k * DIGEST_LANES + c];
        sl::push_slot_ledger_laws(&mut rs, local, TL_EXT, &abs, seed_commit);
        // the clock law on every row (spend or cover), as `LedgerDeltaAir`: the absorbed clock is at or before the block's,
        // and its digest is the canonical four limbs
        crate::whir_rec_block::push_clock_le(&mut rs, local, TL_CLOCK, abs(LEDGER_ABS_CLOCK, 0), block_clock);
        for c in 1..DIGEST_LANES {
            rs.push(abs(LEDGER_ABS_CLOCK, c));
        }
        // the one unread tuple digest is zero, so no cell of the row is free
        for c in 0..DIGEST_LANES {
            rs.push(abs(TL_UNREAD_DIGEST, c));
        }
        rs
    }
}

impl AirConstraint for TreeLedgerAir {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Step { .. } => sl::slot_ledger_law_degree().max(crate::pow_pq_air::PERM_MAX_DEGREE).max(2),
            Self::Chain(c) => c.degree(nvars),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Step { seed_commit, block_clock, gamma } => {
                let mut acc = Ea4::ZERO;
                let mut gp = Ea4::ONE;
                for r in Self::step_residuals(local, seed_commit, *block_clock) {
                    acc += gp * r;
                    gp *= *gamma;
                }
                acc
            }
            Self::Chain(c) => c.eval(local, at, x),
        }
    }
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        match self {
            Self::Step { seed_commit, block_clock, .. } => Self::step_residuals(local, seed_commit, *block_clock),
            Self::Chain(c) => c.residuals(local, at, x),
        }
    }
    fn has_base_eval(&self) -> bool {
        matches!(self, Self::Chain(c) if c.has_base_eval())
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            Self::Step { .. } => unreachable!("eval_base is called only when has_base_eval() is true"),
            Self::Chain(c) => c.eval_base(local, at, x),
        }
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Step { .. } => Some(Vec::new()),
            Self::Chain(c) => c.free_columns(),
        }
    }
    fn is_row_local(&self) -> bool {
        match self {
            Self::Step { .. } => true,
            Self::Chain(c) => c.is_row_local(),
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Step { .. } => Some(Vec::new()),
            Self::Chain(c) => c.shifted_cols(),
        }
    }
}

fn e8(d: &Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| Ea4::from(Fa4::from_u64(d[c])))
}

/// The constraint for table `t` at batching scalar `gamma`.
fn make(seed_commit: [Ea4; DIGEST_LANES], block_clock_h: u64) -> impl Fn(usize, Ea4) -> TreeLedgerAir + Clone {
    let chain = crate::sponge_chain_air::make_constraint_with_seed(crate::committed_air::COMMITTED_AIR_SEED, Fa4::ZERO);
    let block_clock = crate::whir_rec_block::clock_const(block_clock_h);
    move |t: usize, gamma: Ea4| {
        if t == TL_STEP {
            TreeLedgerAir::Step { seed_commit, block_clock, gamma }
        } else {
            TreeLedgerAir::Chain(chain(gamma))
        }
    }
}

/// The chain's plan over the ledger's published rows: (its per-row absorbed cells, its total steps, its segment's log).
fn chain_plan() -> Option<(Vec<(usize, usize)>, usize, usize)> {
    let rows = LEDGER_ROWS;
    let (absorbed, _sq, steps) = crate::transcript_bind_air::plan(&vec![DELTA_TUPLE_VALS; rows], &vec![0usize; rows])?;
    if steps % rows != 0 {
        return None;
    }
    let seg_log = (steps / rows).next_power_of_two().trailing_zeros() as usize;
    Some((absorbed.iter().take(DELTA_TUPLE_VALS).copied().collect(), steps, seg_log))
}

/// The ties: the step row's PUBLISHED cells are what the chain absorbs (so the rows digest is the digest of what the wire
/// carries), and the chain's final state is the digest in the public bind.
fn ties(onr_len: usize, dsr_len: usize) -> Option<(Vec<CrossTieSpec>, Vec<ColumnTieSpec>)> {
    let (per, steps, seg_log) = chain_plan()?;
    let mut cols: Vec<ColumnTieSpec> = Vec::new();
    tie_run(&mut cols, &per, TL_CHAIN, seg_log, TL_STEP, TL_EXT + sl::SL_PUB);
    let last = steps.checked_sub(1)?;
    let off = crate::settlement_delta::delta_digest_off(onr_len, dsr_len);
    let cross: Vec<CrossTieSpec> = (0..DIGEST_LANES)
        .map(|j| ((TL_CHAIN, vec![crate::sponge_chain_air::OUTPUT_OFF + j], last), (PUBLIC_BIND_TABLE, vec![off + j], 0usize)))
        .collect();
    Some((cross, cols))
}

/// The constant shapes `(nvars, width)` of the two tables (the chain's measured from a laid chain of zero rows, once).
fn shapes() -> Option<Vec<(usize, usize)>> {
    static CHAIN: std::sync::OnceLock<Option<(usize, usize)>> = std::sync::OnceLock::new();
    let chain = *CHAIN.get_or_init(|| {
        let t = chain_table_of(&vec![vec![Fa4::ZERO; DELTA_TUPLE_VALS]; LEDGER_ROWS])?;
        let h = t.first()?.len();
        h.is_power_of_two().then(|| (h.trailing_zeros() as usize, t.len()))
    });
    Some(vec![(LEDGER_ROWS.trailing_zeros() as usize, TL_STEP_COLS), chain?])
}

/// ⭐ V2 (b) — the statement's constant PLAN, for a circuit that verifies a tree ledger proof (`usdm_agg::ledger_ssa`): the
/// two tables' shapes, each table's next-row set (`air_zerocheck::shifted_set` of its own constraint), the cross ties and
/// the column ties. `onr_len`/`dsr_len` place the rows digest in the bind, as [`tree_ledger_stated`] does. A read of the
/// statement's own functions; nothing here is a second derivation.
#[must_use]
pub fn tree_ledger_plan(onr_len: usize, dsr_len: usize) -> Option<TreeLedgerPlan> {
    let shapes = shapes()?;
    let mk = make([Ea4::ZERO; DIGEST_LANES], 0);
    let sets: Vec<Vec<usize>> = shapes.iter().enumerate().map(|(t, &(_, w))| crate::air_zerocheck::shifted_set(&mk(t, Ea4::ZERO), w)).collect();
    let degrees: Vec<usize> = shapes.iter().enumerate().map(|(t, &(nv, _))| mk(t, Ea4::ZERO).degree(nv)).collect();
    let (cross, cols) = ties(onr_len, dsr_len)?;
    Some(TreeLedgerPlan { shapes, sets, degrees, cross, cols })
}

/// [`tree_ledger_plan`]'s answer: per table its shape, next-row set and constraint degree (a zerocheck round sends
/// `degree + 2` values), then the statement's cross and column ties.
pub struct TreeLedgerPlan {
    pub shapes: Vec<(usize, usize)>,
    pub sets: Vec<Vec<usize>>,
    pub degrees: Vec<usize>,
    pub cross: Vec<CrossTieSpec>,
    pub cols: Vec<ColumnTieSpec>,
}

/// PRODUCER — lay the tree ledger. `pbs[i]` is payment `i`'s public bind (the domain tag then its tuple, as its spend carrier
/// binds it), `rows` the block's plan (`settlement_delta::plan_ledger_rows`). Returns the statement, the published list and
/// the rows digest; `None` for a plan this statement cannot state (the same refusals `lay_block_ledger` makes).
#[allow(clippy::type_complexity)]
pub fn lay_tree_ledger(
    pbs: &[Vec<Fa4>],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
    block_clock_h: u64,
) -> Option<(crate::light_batch_merge::LaidStatement<'static>, Vec<LedgerPublished>, Vec<Fa4>)> {
    use p3_field::PrimeField64;
    if pbs.is_empty() || rows.len() != LEDGER_ROWS || pbs.iter().any(|pb| pb.len() != 1 + DELTA_TUPLE_VALS) {
        return None;
    }
    let mut spent = vec![false; pbs.len()];
    for r in rows {
        if r.witness.seed != seed || !r.witness.is_well_formed() {
            return None;
        }
        match r.spend_of {
            Some(i) if i < pbs.len() && !spent[i] && r.witness.is_spend => spent[i] = true,
            Some(_) => return None,
            None if r.witness.is_spend => return None,
            None => {}
        }
    }
    let digest_at = |pb: &[Fa4], k: usize| -> Digest { core::array::from_fn(|c| pb[1 + k * DIGEST_LANES + c].as_canonical_u64()) };
    let mut laid: Vec<(Vec<Fa4>, LedgerPublished)> = Vec::with_capacity(LEDGER_ROWS);
    for r in rows {
        let pb = &pbs[r.spend_of.unwrap_or(0)];
        let abs: [Digest; sl::ABS_DIGESTS] = core::array::from_fn(|k| digest_at(pb, k));
        let clock = crate::whir_rec_block::clock_of_lanes(&digest_at(pb, LEDGER_ABS_CLOCK))?;
        let mut row = vec![Fa4::ZERO; TL_STEP_COLS];
        // the tuple: its read digests as the carrier binds them; the unread digest stays zero
        row[..TL_UNREAD_DIGEST * DIGEST_LANES].copy_from_slice(&pb[1..1 + TL_UNREAD_DIGEST * DIGEST_LANES]);
        let p = sl::lay_slot_ledger_row(&mut row, TL_EXT, &abs, &r.witness);
        crate::whir_rec_block::fill_clock_le(&mut row, TL_CLOCK, clock, block_clock_h)?;
        laid.push((row, p));
    }
    laid.sort_by(|a, b| a.1[sl::PUB_TAG0].cmp(&b.1[sl::PUB_TAG0]));
    if laid.windows(2).any(|w| w[0].1[sl::PUB_TAG0] == w[1].1[sl::PUB_TAG0]) {
        return None;
    }
    let step: Vec<Vec<Fa4>> = (0..TL_STEP_COLS).map(|c| laid.iter().map(|(r, _)| r[c]).collect()).collect();
    let published: Vec<LedgerPublished> = laid.iter().map(|x| x.1).collect();
    let pvals: Vec<Vec<Fa4>> = published.iter().map(ledger_published_vals).collect();
    let chain = chain_table_of(&pvals)?;
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, DELTA_TUPLE_VALS)?;
    let seed_commit = sl::seed_commit_native(seed);
    let bind = note_ledger_bind(domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, block_clock_h);
    let (cross, cols) = ties(output_notes_root.len(), del_set_root.len())?;
    let mk = make(e8(&seed_commit), block_clock_h);
    let statement = crate::light_batch_merge::LaidStatement {
        tables: vec![step, chain],
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        buses: Vec::new(),
        cross,
        cols,
        joint: Vec::new(),
        bind,
    };
    Some((statement, published, rows_digest))
}

/// PEER — the tree ledger's statement as the verifier builds it from the block alone (the published list it carries).
#[must_use]
pub fn tree_ledger_stated(
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
) -> Option<crate::light_batch_merge::StatedStatement<'static>> {
    if published.len() != LEDGER_ROWS || !crate::settlement_delta::ledger_list_is_canonical(published) {
        return None;
    }
    let pvals: Vec<Vec<Fa4>> = published.iter().map(ledger_published_vals).collect();
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, DELTA_TUPLE_VALS)?;
    let (cross, cols) = ties(output_notes_root.len(), del_set_root.len())?;
    let bind = note_ledger_bind(domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, block_clock_h);
    let mk = make(e8(&seed_commit), block_clock_h);
    Some(crate::light_batch_merge::StatedStatement {
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        cross,
        cols,
        joint: Vec::new(),
        bind,
        constraint_shapes: shapes()?,
        bus_shapes: Vec::new(),
    })
}

/// PRODUCER — prove the tree ledger alone (one statement). Returns (proof bytes, published list, rows digest).
#[allow(clippy::type_complexity)]
pub fn prove_tree_ledger(
    pbs: &[Vec<Fa4>],
    rows: &[LedgerRow],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
    block_clock_h: u64,
) -> Option<(Vec<u8>, Vec<LedgerPublished>, Vec<Fa4>)> {
    let (st, published, rows_digest) = lay_tree_ledger(pbs, rows, domain, output_notes_root, del_set_root, seed, block_clock_h)?;
    let laid_shapes: Vec<(usize, usize)> =
        st.tables.iter().map(|t| (t.first().map_or(0, Vec::len).trailing_zeros() as usize, t.len())).collect();
    if Some(laid_shapes) != shapes() {
        return None; // the laid tables must be the constant shape the verifier states
    }
    let bytes = crate::light_batch_merge::prove_joined(vec![st])?;
    Some((bytes, published, rows_digest))
}

/// PEER — verify a tree ledger proof against the verifier's own statement.
#[must_use]
pub fn verify_tree_ledger(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[LedgerPublished],
    block_clock_h: u64,
) -> bool {
    match tree_ledger_stated(domain, output_notes_root, del_set_root, seed_commit, published, block_clock_h) {
        Some(st) => crate::light_batch_merge::verify_joined(bytes, vec![st]),
        None => false,
    }
}

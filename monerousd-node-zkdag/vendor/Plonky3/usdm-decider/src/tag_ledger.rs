// Copyright (c) 2026 MonerousD contributors. SPDX-License-Identifier: Apache-2.0

//! MonerousD Protocol — THE TAG LEDGER: the pair-row class's tag table (padding spec §18, lane funds, 2026-10-27).
//!
//! ⛔ THE LEAK THIS CLOSES (spec §18, F2-red-found-20261027k): the note ledger's published row carries PUBLIC flags
//! `j0 j1 t0 t1`, and the producer files a spend's other `TX_FIXED_NULLIFIER_COUNT − 2 = 30` constant-width tags as
//! JUSTIFIED cells, so `Σ t` over the 128 rows is `30 · spends` — the real spend count read off the list's CONTENT while
//! its SIZE is constant (MEASURED quiet Σt 0 · one spend Σt 30, `rf3_the_published_ledgers_flags_do_not_count_the_
//! blocks_real_spends`). A spend's 32 tags are ONE statement (its spend-or-decoy carrier, `cover_tag_statement_bind`:
//! `domain ‖ cover_tag_set_digest(tags)`); they belong to the spend's own rows, under no public bit.
//!
//! THE SHAPE — the member ledger's twin ([`crate::member_ledger`], §12 shape (D)): exactly [`LEDGER_ROWS`] rows, row `r`
//! the spend-or-decoy carrier's bound step for note-ledger row `r` (a cover row replicates `carriers[0]`'s step — the
//! null cover carrier on a quiet block). A stated spend occupies `W/2 = 16` PAIR rows: pair row `p` holds the carrier's
//! tags `2p, 2p+1` as hidden witnesses. ⭐ ROW `r`'S TWO TAGS ARE NOTE ROW `r`'S PUBLISHED TAGS BY A COLUMN TIE ACROSS THE JOINED
//! BATCH ([`note_tags_tie`], 2026-11-03). It replaced one Poseidon2 block per row, a published pair-digest block and a chain
//! table over them (47,104 cells) that said the same thing through a hash, which is what brought the joined proof from arity
//! 24 to 23. A standalone tag proof states no such tie, so it is no door: it exists for the laws' own pins. The 16 rows are welded to their carrier by re-chaining its tag set with the
//! carrier's own spelling ([`crate::nf_sparse_air::cover_tag_set_digest`]: one Poseidon2 pair per tag) and linking the
//! chain across rows on a LogUp bus (DB-159's tied bus; the member ring's shape): row `p` EMITS `(D_tags, chain_out)` and
//! CONSUMES `(D_tags, chain_in)`; the HEAD row (`p = 0`) consumes nothing and starts at the chain's zero IV; the LAST row
//! (`p = 15`) emits nothing and closes on the `D_tags` absorbed from the carrier's bind. The bus balances only over the
//! carrier's whole chain — 16 rows, its 32 tags, in order.
//!
//! SOUND, each arm a refusing pin: (1) a pair row's tags are the carrier's (any other pair breaks the chain — a Poseidon2
//! collision otherwise); (2) a head without its 15 tails leaves an emit unconsumed; (3) tails without a head start no
//! chain at the IV and never close on `D_tags`; (4) two rows publishing one pair collide on the note ledger's strictly
//! ascending `tag0`; (5) the head row's pair is `(nullifier, claim)` — the note ledger's spend row publishes those from
//! the SPEND carrier's bind, and the door's per-row equality welds the two carriers through them (the wallet lays its
//! list `nullifier ‖ claim ‖ decoys…`, `cover::pad_tx_nullifiers_to_fixed`). PRIVATE: no public bit, count or position
//! names a spend's rows; the chain states live in the witness; the bus is a sum under a post-commit challenge.
//!
//! NEW-DOOR CHECKLIST (AGENTS.md §9.6) — a sub-statement the note ledger's door inherits: (1) PoW — the block door's.
//! (2) the object's proof — [`verify_tag_ledger_bytes`], WHIR light decider, bus challenge drawn after the trace.
//! (3) value — none moves here; the rows state which tags a spend's carrier chained, the note ledger states the spend.
//! (4) replay — every published tag enters the spent SET at the note ledger's door; a repeat is refused there.
//! (5) hostile work — the shapes are the class's ([`tag_ledger_table_shapes`]), checked before any allocation; the
//! published list is derived from the note list the door already decoded. (6) parity — the statement it replaces is
//! `Block::cover_transition` (`prove_block_cover_transition`, the same carrier class at `DELTA_FIXED_SLOTS`): its
//! per-carrier tag-set digest tie is this table's absorbed tuple; its public tag list becomes the note ledger's cells.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::nf_sparse_air::cover_transition_domain;
use crate::nullifier_insert_air::poseidon_pair_native;
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::pow_pq_air::{lay_perm_row_flat, pair_state, push_perm_residuals, P2_COLS, PERM_OUT};
use crate::settlement_delta::{
    cover_class_base, cover_delta_factory, delta_layout, ledger_bind, ledger_delta_ties_no_chain,
    make_settlement_delta_constraint, rows_digest_of, settlement_delta_table_shapes, settlement_delta_tables,
    DeltaLayout, COVER_TUPLE_VALS, LEDGER_ROWS,
};
use crate::whir_rec_block::{merge_column_ties, ColumnTieSpec, CrossTieSpec, COLUMN_TIES_MAX, EXT_D, REC_DECIDER_FOLDING};
use p3_field::PrimeCharacteristicRing;

/// Pair rows per spend — the constant transaction width over two tags per row. Pinned against the node's width.
pub const PAIRS_PER_SPEND: usize = crate::settlement_delta::COVER_TAGS_PER_TUPLE / 2;
const _: () = assert!(PAIRS_PER_SPEND * 2 == crate::settlement_delta::COVER_TAGS_PER_TUPLE, "two tags per row");

// ── The step row EXTENSION, offsets relative to its base ─────────────────────────────────────────────────────────
/// A zero column — the bus's `idx` lane ties to it (the ring's `M_ZERO` shape).
pub const X_ZERO: usize = 0;
/// `is_pair` (hidden): this row holds a carrier's tag pair.
pub const X_PAIR: usize = 1;
/// `is_head` (hidden): the carrier's pair 0 — the chain starts here at the IV.
pub const X_HEAD: usize = 2;
/// `is_last` (hidden): the carrier's last pair (`PAIRS_PER_SPEND - 1`) — the chain closes here on the absorbed `D_tags`.
pub const X_LAST: usize = 3;
/// The emit multiplicity `is_pair · (1 − is_last)` (a round-1 column: `BusMult::Column`'s rule).
pub const X_MEMIT: usize = 4;
/// The consume multiplicity, NEGATIVE: `−is_pair · (1 − is_head)` — so one bus balances emits against consumes.
pub const X_MCONS: usize = 5;
/// The row's two tags (hidden witnesses): a pair row's carrier tags; a cover row's note-ledger cover tags.
pub const X_T0: usize = 6;
pub const X_T1: usize = X_T0 + DIGEST_LANES;
/// The chain state entering this row (hidden; zero on a head row and on a cover row).
pub const X_CIN: usize = X_T1 + DIGEST_LANES;
/// Two whole Poseidon2 blocks: the chain's first absorb, the chain's second absorb.
pub const X_B_C0: usize = X_CIN + DIGEST_LANES;
pub const X_B_C1: usize = X_B_C0 + P2_COLS;
/// The extension's width.
pub const X_COLS: usize = X_B_C1 + P2_COLS;

/// The chain bus — numbered after the two constraint tables, as the batch prover indexes it.
pub const T_BUS: usize = 2;
/// Bus table columns: `idx | key (D_tags ‖ state) | mult`.
pub const B_IDX: usize = 0;
pub const B_VAL: usize = 1;
pub const B_KEY: usize = 2 * DIGEST_LANES;
pub const B_MULT: usize = B_VAL + B_KEY;
const _: () = assert!(B_KEY <= crate::postcommit_bus::BUS_MAX_KEY_COLS, "the chain key is two digests");

/// The cover class at the ledger's constant row count — the one layout both sides build, from constants alone.
#[must_use]
pub fn tag_ledger_layout() -> Option<DeltaLayout> {
    let (base, powers) = cover_class_base();
    delta_layout(base, powers, LEDGER_ROWS, LEDGER_ROWS, 1 + COVER_TUPLE_VALS, COVER_TUPLE_VALS)
}

/// `(constraint table shapes, bus shapes)`: the class's tables with the step widened by the extension; the chain bus
/// of `2 · LEDGER_ROWS` rows (even rows emit, odd rows consume).
#[must_use]
#[allow(clippy::type_complexity)]
pub fn tag_ledger_table_shapes(layout: DeltaLayout) -> Option<(Vec<(usize, usize)>, Vec<(usize, usize)>)> {
    let mut s = settlement_delta_table_shapes(layout)?;
    s.truncate(layout.chain_table()); // the step and sponge tables: the rows tie to the note ledger, no chain states them
    if s.len() != T_BUS {
        return None;
    }
    s[layout.step_table()].1 = layout.step_cols() + X_COLS;
    let bus_nv = (LEDGER_ROWS.trailing_zeros() as usize + 1).max(REC_DECIDER_FOLDING);
    Some((s, vec![(bus_nv, 2 + B_KEY + EXT_D)]))
}

/// The statement's ties: the class's (chain re-pointed at the published cell, same-point ties merged) and the bus's two
/// — even bus rows ↔ `(zero, D_tags, chain_out, memit)`, odd bus rows ↔ `(zero, D_tags, chain_in, mcons)` of step row
/// `r`. ⛔ EVERY BUS ROW IS TIED (the ring's law): a row no tie reaches is a prover's free balance.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn tag_ledger_ties(layout: DeltaLayout, onr_len: usize, dsr_len: usize) -> Option<(Vec<CrossTieSpec>, Vec<ColumnTieSpec>)> {
    let ext = layout.step_cols();
    let (cross, cols) = ledger_delta_ties_no_chain(layout, onr_len, dsr_len)?;
    let mut cols = merge_column_ties(cols);
    let st = layout.step_table();
    let mut bus_cols = vec![B_IDX];
    bus_cols.extend(B_VAL..B_VAL + B_KEY);
    bus_cols.push(B_MULT);
    let d_tags: Vec<usize> = (0..DIGEST_LANES).map(|c| layout.tuple_at(0, c)).collect();
    let mut emit = vec![ext + X_ZERO];
    emit.extend(d_tags.iter().copied());
    emit.extend((0..DIGEST_LANES).map(|c| ext + X_B_C1 + PERM_OUT + c));
    emit.push(ext + X_MEMIT);
    let mut cons = vec![ext + X_ZERO];
    cons.extend(d_tags);
    cons.extend((0..DIGEST_LANES).map(|c| ext + X_CIN + c));
    cons.push(ext + X_MCONS);
    cols.push(((T_BUS, bus_cols.clone(), 1, 0), (st, emit, 0, 0)));
    cols.push(((T_BUS, bus_cols, 1, 1), (st, cons, 0, 0)));
    (cols.len() <= COLUMN_TIES_MAX).then_some((cross, cols))
}

/// The batch position of the note ledger, the statement the tag rows tie to (`note_transition::prove_ledger_joined`'s order).
pub const NOTE_STATEMENT: usize = 0;

/// ⭐ THE TAG ROWS ARE THE NOTE ROWS: `(t0, t1)` of tag row `r` == `(PUB_TAG0, PUB_TAG1)` of note row `r`, every row, one opening
/// pair at a random point drawn after the commitment. Both cells are public on the note row, so the tie reveals nothing the list
/// does not. `None` when the note class has no layout. MEASURED on the wire: the pin `a_tag_row_that_is_not_its_note_row_…`.
#[must_use]
pub fn note_tags_tie(layout: DeltaLayout) -> Option<crate::light_batch_merge::JointTie> {
    use crate::slot_ledger::{PUB_TAG0, PUB_TAG1};
    // ⭐ V2 (speed5, 2026-11-16): the note statement is the TREE LEDGER (`crate::tree_ledger`), so its published block is
    // read from THAT layout — the joint tie names the active note statement's columns, never another shape's (main
    // 7ab7d34f swapped the note statement and kept this tie on the old layout: reverted by 3fded1d8).
    let (ne, te) = (crate::tree_ledger::TL_PUB, layout.step_cols());
    let lanes = |base: usize| (0..DIGEST_LANES).map(move |c| base + c);
    let note_cols = lanes(ne + PUB_TAG0 * DIGEST_LANES).chain(lanes(ne + PUB_TAG1 * DIGEST_LANES)).collect();
    let tag_cols = lanes(te + X_T0).chain(lanes(te + X_T1)).collect();
    Some((NOTE_STATEMENT, ((crate::tree_ledger::TL_STEP, note_cols, 0, 0), (layout.step_table(), tag_cols, 0, 0))))
}

/// The tag ledger's per-table circuit: the cover class's tables, the tag laws on its step rows.
pub enum TagLedgerAir<B: AirConstraint> {
    Class(B),
    Step { base: B, ext: usize, tuple_off: usize, offset: u64, gamma: Ea4 },
}

/// The laws of one step row, as residuals (`p = is_pair`, `h = is_head`, `l = is_last`):
/// L1 `p, h, l ∈ {0,1}`, `h ≤ p`, `l ≤ p`, the zero lane is zero; L2 `memit = p·(1−l)`, `mcons = −p·(1−h)`;
/// L3 two Poseidon2 blocks welded to their inputs — `mid = P(cin ‖ t0)`, `out = P(mid ‖ t1)`
/// (the carrier's own chain spelling, `cover_tag_set_digest`); L4 a head row's `cin` is the zero IV, and a cover row's
/// `cin` is forced zero (C1: an unread witness is never free); L5 a last row's `out` is the absorbed `D_tags`.
/// ⭐ V2 (a) (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16) — generic over the field its row lives in, the type parameter
/// NAMED `Ea4` so the body is byte for byte the production body (lane agg's pattern, `gate_trace` module doc): the native
/// instantiation is unchanged machine code, and `gate_trace::Sym` traces the same laws into a program the tree runs in circuit.
pub(crate) fn push_tag_ledger_laws<Ea4: p3_field::Algebra<Fa4> + Copy + 'static>(rs: &mut Vec<Ea4>, local: &Row<'_, Ea4>, ext: usize, tuple_off: usize) {
    let x = |off: usize| local[ext + off];
    let abs = |c: usize| local[tuple_off + c];
    let one = Ea4::ONE;
    let out = PERM_OUT;
    let (p, h, l) = (x(X_PAIR), x(X_HEAD), x(X_LAST));
    rs.push(x(X_ZERO));
    rs.push(p * (p - one));
    rs.push(h * (h - one));
    rs.push(l * (l - one));
    rs.push(h * (one - p));
    rs.push(l * (one - p));
    rs.push(x(X_MEMIT) - (p - p * l));
    rs.push(x(X_MCONS) + (p - p * h));
    for blk in [X_B_C0, X_B_C1] {
        push_perm_residuals(local, ext + blk, rs);
    }
    for c in 0..DIGEST_LANES {
        rs.push(x(X_B_C0 + c) - x(X_CIN + c));
        rs.push(x(X_B_C0 + DIGEST_LANES + c) - x(X_T0 + c));
        rs.push(x(X_B_C1 + c) - x(X_B_C0 + out + c));
        rs.push(x(X_B_C1 + DIGEST_LANES + c) - x(X_T1 + c));
        rs.push(h * x(X_CIN + c));
        rs.push((one - p) * x(X_CIN + c));
        rs.push(l * (x(X_B_C1 + out + c) - abs(c)));
    }
}

impl<B: AirConstraint> AirConstraint for TagLedgerAir<B> {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Class(b) => b.degree(nvars),
            Self::Step { base, .. } => base.degree(nvars).max(crate::pow_pq_air::PERM_MAX_DEGREE).max(2),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Class(b) => b.eval(local, at, x),
            Self::Step { base, ext, tuple_off, offset, gamma } => {
                let mut rs = Vec::new();
                push_tag_ledger_laws(&mut rs, local, *ext, *tuple_off);
                let mut acc = Ea4::ZERO;
                let mut gp = gamma.exp_u64(*offset);
                for r in rs {
                    acc += gp * r;
                    gp *= *gamma;
                }
                base.eval(local, at, x) + acc
            }
        }
    }
    fn has_base_eval(&self) -> bool {
        matches!(self, Self::Class(b) if b.has_base_eval())
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            Self::Class(b) => b.eval_base(local, at, x),
            Self::Step { .. } => unreachable!("eval_base is called only when has_base_eval() is true"),
        }
    }
    fn is_row_local(&self) -> bool {
        match self {
            Self::Class(b) | Self::Step { base: b, .. } => b.is_row_local(),
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Class(b) | Self::Step { base: b, .. } => b.shifted_cols(),
        }
    }
    /// The class's declaration only: every extension cell is read by a law above (the tags by two welds and the note tie, the
    /// chain state by a weld and two selectors, the multiplicities by L2 and the bus ties).
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Class(b) | Self::Step { base: b, .. } => b.free_columns(),
        }
    }
}

/// The constraint factory BOTH sides derive from public values: the layout and the class's table factory
/// (`make_settlement_delta_constraint(layout, cover_delta_factory(layout))`).
pub fn make_tag_ledger_constraint<B, G>(layout: DeltaLayout, class: G) -> impl Fn(usize, Ea4) -> TagLedgerAir<B> + Clone
where
    B: AirConstraint,
    G: Fn(usize, Ea4) -> B + Clone,
{
    let offset = (2 * layout.bound.nvars + layout.bound.powers + 16) as u64;
    move |table: usize, gamma: Ea4| {
        if table == layout.step_table() {
            TagLedgerAir::Step { base: class(table, gamma), ext: layout.step_cols(), tuple_off: layout.tuple_off(), offset, gamma }
        } else {
            TagLedgerAir::Class(class(table, gamma))
        }
    }
}

/// One row of the producer's plan: `pair_of = Some((i, p))` — pair `p` of carrier `i`'s tag set; `None` — a cover row.
/// `tags` are the row's two tags: a pair row's are its carrier's `tags[2p], tags[2p+1]` (checked against the carrier's
/// absorbed digest by re-chaining); a cover row's are the note ledger row's two cover tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagRow {
    pub pair_of: Option<(usize, usize)>,
    pub tags: [Digest; 2],
}

/// The published pair digest — the ONE spelling the producer lays and the door recomputes from the note row.
#[must_use]
pub fn pair_digest_native(tag0: &Digest, tag1: &Digest) -> Digest {
    poseidon_pair_native(*tag0, *tag1)
}

fn digest_vals(d: &Digest) -> Vec<Fa4> {
    d.iter().map(|v| Fa4::from_u64(*v)).collect()
}

fn digest_of_pb(pb: &[Fa4]) -> Option<Digest> {
    use p3_field::PrimeField64;
    (pb.len() == 1 + COVER_TUPLE_VALS).then(|| core::array::from_fn(|c| pb[1 + c].as_canonical_u64()))
}

/// What the producer proves.
struct LaidTagLedger {
    tables: Vec<Vec<Vec<Fa4>>>,
    bus: (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>),
    bind: Vec<Fa4>,
    cross: Vec<CrossTieSpec>,
    cols: Vec<ColumnTieSpec>,
}

/// The chain states of every carrier's 16 pairs, natively: `None` when a carrier's pairs are not exactly `0..16` once
/// each, or their chain does not close on the carrier's absorbed digest — the producer refuses, never lays a chain that
/// cannot balance (the ring's rule).
fn chain_states(carriers: &[(Vec<u8>, Vec<Fa4>)], rows: &[TagRow]) -> Option<Vec<Option<(Digest, Digest)>>> {
    let mut pairs: Vec<Vec<Option<[Digest; 2]>>> = vec![vec![None; PAIRS_PER_SPEND]; carriers.len()];
    for r in rows {
        if let Some((i, p)) = r.pair_of {
            let slot = pairs.get_mut(i)?.get_mut(p)?;
            if slot.is_some() {
                return None;
            }
            *slot = Some(r.tags);
        }
    }
    let mut states: Vec<Vec<(Digest, Digest)>> = Vec::with_capacity(carriers.len());
    for (i, ps) in pairs.iter().enumerate() {
        let used = ps.iter().filter(|p| p.is_some()).count();
        if used == 0 {
            states.push(Vec::new());
            continue;
        }
        if used != PAIRS_PER_SPEND {
            return None;
        }
        let mut acc = crate::poseidon2_compress::zero_digest();
        let mut st = Vec::with_capacity(PAIRS_PER_SPEND);
        for p in ps.iter().flatten() {
            let cin = acc;
            acc = poseidon_pair_native(poseidon_pair_native(acc, p[0]), p[1]);
            st.push((cin, acc));
        }
        if acc != digest_of_pb(&carriers[i].1)? {
            return None;
        }
        states.push(st);
    }
    Some(rows.iter().map(|r| r.pair_of.map(|(i, p)| states[i][p])).collect())
}

#[allow(clippy::type_complexity)]
fn lay_tag_ledger(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[TagRow],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(LaidTagLedger, Vec<Digest>)> {
    if carriers.is_empty() || rows.len() != LEDGER_ROWS {
        return None;
    }
    let layout = tag_ledger_layout()?;
    let states = chain_states(carriers, rows)?;
    let src = |r: &TagRow| r.pair_of.map_or(0, |(i, _)| i);
    let expanded: Vec<(Vec<u8>, Vec<Fa4>)> = rows.iter().map(|r| carriers[src(r)].clone()).collect();
    let (mut tables, _absorbed) = settlement_delta_tables(&expanded, layout)?;
    let d_tags: Vec<Digest> = expanded.iter().map(|(_, pb)| digest_of_pb(pb)).collect::<Option<_>>()?;
    let mut exts = vec![vec![Fa4::ZERO; X_COLS]; LEDGER_ROWS];
    let mut published = Vec::with_capacity(LEDGER_ROWS);
    let n = 2 * LEDGER_ROWS;
    let (mut idx, mut vals, mut mult) = (vec![Fa4::ZERO; n], vec![vec![Fa4::ZERO; n]; B_KEY], vec![Fa4::ZERO; n]);
    for (r, (row, e)) in rows.iter().zip(exts.iter_mut()).enumerate() {
        let (pair, head, last) = match row.pair_of {
            Some((_, p)) => (true, p == 0, p + 1 == PAIRS_PER_SPEND),
            None => (false, false, false),
        };
        let (cin, cout) = states[r].unwrap_or((crate::poseidon2_compress::zero_digest(), crate::poseidon2_compress::zero_digest()));
        let b = |v: bool| if v { Fa4::ONE } else { Fa4::ZERO };
        e[X_PAIR] = b(pair);
        e[X_HEAD] = b(head);
        e[X_LAST] = b(last);
        e[X_MEMIT] = b(pair && !last);
        e[X_MCONS] = -b(pair && !head);
        let pubd = pair_digest_native(&row.tags[0], &row.tags[1]);
        for c in 0..DIGEST_LANES {
            e[X_T0 + c] = Fa4::from_u64(row.tags[0][c]);
            e[X_T1 + c] = Fa4::from_u64(row.tags[1][c]);
            e[X_CIN + c] = Fa4::from_u64(cin[c]);
        }
        let mid = poseidon_pair_native(cin, row.tags[0]);
        lay_perm_row_flat(e, X_B_C0, pair_state(&cin, &row.tags[0]));
        lay_perm_row_flat(e, X_B_C1, pair_state(&mid, &row.tags[1]));
        debug_assert!(!pair || {
            use p3_field::PrimeField64;
            (0..DIGEST_LANES).all(|c| e[X_B_C1 + PERM_OUT + c].as_canonical_u64() == cout[c])
        });
        published.push(pubd);
        // the bus: even row emits (D_tags ‖ out), odd row consumes (D_tags ‖ in). ⛔ EVERY bus cell is a COLUMN TIE to the
        // step row (opened at one point), so a cover row's emit value is the chain block's REAL output over its zero `cin`
        // (`P(P(0 ‖ t0) ‖ t1)`, never a zero the row does not hold); its multiplicity is zero, so it balances nothing.
        // MEASURED 2026-10-28 (decider-55/57.log): a zero laid here refused every honest ledger at the tie.
        let (ev, od) = (2 * r, 2 * r + 1);
        idx[ev] = Fa4::ZERO;
        idx[od] = Fa4::ZERO;
        for c in 0..DIGEST_LANES {
            vals[c][ev] = Fa4::from_u64(d_tags[r][c]);
            vals[c][od] = Fa4::from_u64(d_tags[r][c]);
            vals[DIGEST_LANES + c][ev] = e[X_B_C1 + PERM_OUT + c];
            vals[DIGEST_LANES + c][od] = e[X_CIN + c];
        }
        mult[ev] = e[X_MEMIT];
        mult[od] = e[X_MCONS];
    }
    let step = layout.step_table();
    for c in 0..X_COLS {
        tables[step].push(exts.iter().map(|e| e[c]).collect());
    }
    let pvals: Vec<Vec<Fa4>> = published.iter().map(digest_vals).collect();
    tables.truncate(layout.chain_table());
    if tables.len() != T_BUS {
        return None;
    }
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, COVER_TUPLE_VALS)?;
    let seed_commit = crate::slot_ledger::seed_commit_native(seed);
    let bind = ledger_bind(cover_transition_domain(), output_notes_root, del_set_root, &rows_digest, &seed_commit);
    let (cross, cols) = tag_ledger_ties(layout, output_notes_root.len(), del_set_root.len())?;
    Some((LaidTagLedger { tables, bus: (idx, vals, mult), bind, cross, cols }, published))
}

/// PRODUCER — lay and prove a block's tag ledger. `carriers` are the block's spend-or-decoy carriers (`carriers[0]` is
/// also the replica source of every cover row — [`null_cover_carrier`] on a block with no spend); `rows` is exactly
/// [`LEDGER_ROWS`] entries in the NOTE ledger's canonical order. Returns the proof and the published pair digests (a
/// function of the note ledger's list; a peer derives them and never reads them off the wire).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_tag_ledger_bytes(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[TagRow],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(Vec<u8>, Vec<Digest>)> {
    prove_tag_ledger_with(carriers, rows, output_notes_root, del_set_root, seed, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_tag_ledger_bytes`] with the BOUND template double: the same lay, the WHIR prove
/// dropped and the statement sealed in its place (the member ledger's armed form). Never a soundness door.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_tag_ledger_bytes_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[TagRow],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(Vec<u8>, Vec<Digest>)> {
    prove_tag_ledger_with(carriers, rows, output_notes_root, del_set_root, seed, true)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::type_complexity)]
fn prove_tag_ledger_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[TagRow],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
    bound: bool,
) -> Option<(Vec<u8>, Vec<Digest>)> {
    let (laid, published) = lay_tag_ledger(carriers, rows, output_notes_root, del_set_root, seed)?;
    let layout = tag_ledger_layout()?;
    if bound {
        tag_ledger_table_shapes(layout)?;
        return Some((crate::settlement_delta::tag_ledger_bound_seal(&layout, &laid.bind)?, published));
    }
    let mk = make_tag_ledger_constraint(layout, make_settlement_delta_constraint(layout, cover_delta_factory(layout)));
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        laid.tables,
        mk,
        vec![laid.bus],
        laid.cross,
        laid.cols,
        &laid.bind,
    )?;
    Some((bytes, published))
}

/// PEER — verify a block's tag ledger from the proof, the header seed's commitment and the pair digests the peer
/// DERIVED from the note ledger's published rows (`P(PUB_TAG0 ‖ PUB_TAG1)` per row). Layout and shapes are the class's.
/// ⭐ R4 lever 4 — the tag ledger as ONE STATEMENT of a joined light-decider batch (`light_batch_merge`): the same lay,
/// constraint, bus, ties and bind [`prove_tag_ledger_bytes`] hands the engine; the published pair digests as it returns them.
#[allow(clippy::type_complexity)]
pub fn lay_tag_ledger_statement(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[TagRow],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(crate::light_batch_merge::LaidStatement<'static>, Vec<Digest>)> {
    let (laid, published) = lay_tag_ledger(carriers, rows, output_notes_root, del_set_root, seed)?;
    let layout = tag_ledger_layout()?;
    let mk = make_tag_ledger_constraint(layout, make_settlement_delta_constraint(layout, cover_delta_factory(layout)));
    let statement = crate::light_batch_merge::LaidStatement {
        tables: laid.tables,
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        buses: vec![laid.bus],
        cross: laid.cross,
        cols: laid.cols,
        joint: vec![note_tags_tie(layout)?],
        bind: laid.bind,
    };
    Some((statement, published))
}

/// ⭐ R4 lever 4 — the tag ledger's statement for a joined VERIFY, derived from the peer's own inputs exactly as
/// [`verify_tag_ledger_bytes`] derives them.
#[must_use]
pub fn tag_ledger_stated_statement(
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[Digest],
) -> Option<crate::light_batch_merge::StatedStatement<'static>> {
    if published.len() != LEDGER_ROWS {
        return None;
    }
    let layout = tag_ledger_layout()?;
    let pvals: Vec<Vec<Fa4>> = published.iter().map(digest_vals).collect();
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, COVER_TUPLE_VALS)?;
    let bind = ledger_bind(cover_transition_domain(), output_notes_root, del_set_root, &rows_digest, &seed_commit);
    let (cross, cols) = tag_ledger_ties(layout, output_notes_root.len(), del_set_root.len())?;
    let (constraint_shapes, bus_shapes) = tag_ledger_table_shapes(layout)?;
    let mk = make_tag_ledger_constraint(layout, make_settlement_delta_constraint(layout, cover_delta_factory(layout)));
    Some(crate::light_batch_merge::StatedStatement {
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        cross,
        cols,
        joint: vec![note_tags_tie(layout)?],
        bind,
        constraint_shapes,
        bus_shapes,
    })
}

#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_tag_ledger_bytes(
    bytes: &[u8],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[Digest],
) -> bool {
    verify_tag_ledger_with(bytes, output_notes_root, del_set_root, seed_commit, published, false)
}

/// ⛔ TEST BUILDS ONLY — the ARMED door: accepts the bound double's seal and nothing else.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_tag_ledger_bytes_bound(
    bytes: &[u8],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[Digest],
) -> bool {
    verify_tag_ledger_with(bytes, output_notes_root, del_set_root, seed_commit, published, true)
}

#[cfg(any(test, feature = "test-support"))]
fn verify_tag_ledger_with(
    bytes: &[u8],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[Digest],
    bound: bool,
) -> bool {
    if bytes.is_empty() || published.len() != LEDGER_ROWS {
        return false;
    }
    let Some(layout) = tag_ledger_layout() else { return false };
    let pvals: Vec<Vec<Fa4>> = published.iter().map(digest_vals).collect();
    let Some(rows_digest) = rows_digest_of(&pvals, LEDGER_ROWS, COVER_TUPLE_VALS) else { return false };
    let bind = ledger_bind(cover_transition_domain(), output_notes_root, del_set_root, &rows_digest, &seed_commit);
    let Some((cross, cols)) = tag_ledger_ties(layout, output_notes_root.len(), del_set_root.len()) else { return false };
    let Some((shapes, bus)) = tag_ledger_table_shapes(layout) else { return false };
    if bound {
        return crate::settlement_delta::tag_ledger_bound_seal(&layout, &bind).is_some_and(|s| s.as_slice() == bytes);
    }
    let mk = make_tag_ledger_constraint(layout, make_settlement_delta_constraint(layout, cover_delta_factory(layout)));
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(bytes, mk, cross, cols, &bind, &shapes, &bus)
}

/// THE NULL COVER CARRIER — the replica source for a block with no spend: one spend-or-decoy carrier whose 32 tags are
/// all decoys under a secret nobody else holds. Nothing of it is published (cover rows publish the note ledger's cover
/// tags); its absorbed digest sits in cover rows' tuple cells, hidden by the aggregate. `None` when the prover refuses.
#[must_use]
pub fn null_cover_carrier(secret: Digest) -> Option<(Vec<u8>, Vec<Fa4>)> {
    use crate::nf_sparse_air::{cover_tag_native, cover_tag_statement_bind, prove_spend_or_decoy_bytes, TagWitness};
    let w = crate::settlement_delta::COVER_TAGS_PER_TUPLE;
    let tags: Vec<Digest> = (0..w as u64).map(|s| cover_tag_native(secret, s)).collect();
    let wit = vec![TagWitness::Decoy; w];
    let bytes = prove_spend_or_decoy_bytes(secret, &tags, &wit)?;
    Some((bytes, cover_tag_statement_bind(&tags)))
}

/// The tags of a decoy-only carrier under `secret` — what [`null_cover_carrier`] chained, for the rows that cite it.
#[must_use]
pub fn null_cover_tags(secret: Digest) -> Vec<Digest> {
    (0..crate::settlement_delta::COVER_TAGS_PER_TUPLE as u64).map(|s| crate::nf_sparse_air::cover_tag_native(secret, s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nf_sparse_air::cover_tag_set_digest;
    use crate::poseidon2_compress::lanes_of;

    fn secret(tag: u64) -> Digest {
        lanes_of(&[0x5441_474c, tag, 7, 11, 13, 17, 19, 23]) // "TAGL"
    }

    /// A block with ONE stated spend (carrier 1, all-decoy — the tag table does not care which tags are real) laid on
    /// 16 pair rows among 112 cover rows, in a fixed order; carrier 0 the null replica source.
    fn honest_rows(seed: Digest, spend_tags: &[Digest]) -> Vec<TagRow> {
        use crate::slot_ledger::cover_tag_native as ledger_cover;
        let mut rows = Vec::with_capacity(LEDGER_ROWS);
        let mut slot = 1u64;
        for r in 0..LEDGER_ROWS {
            if r % 8 == 3 && rows.iter().filter(|x: &&TagRow| x.pair_of.is_some()).count() < PAIRS_PER_SPEND {
                let p = rows.iter().filter(|x: &&TagRow| x.pair_of.is_some()).count();
                rows.push(TagRow { pair_of: Some((1, p)), tags: [spend_tags[2 * p], spend_tags[2 * p + 1]] });
            } else {
                rows.push(TagRow { pair_of: None, tags: [ledger_cover(seed, slot), ledger_cover(seed, slot + 1)] });
                slot += 2;
            }
        }
        assert_eq!(rows.iter().filter(|x| x.pair_of.is_some()).count(), PAIRS_PER_SPEND, "calibration: 16 pair rows");
        rows
    }

    /// §18 pins (1)–(3) at the producer and the whole statement round trip: the honest tag ledger over one spend proves and
    /// the peer accepts it from the derived digests; a chain missing a pair, a chain closing on another carrier's digest and
    /// a duplicated pair are refused BEFORE any proving work; a swapped published digest is refused by the door.
    #[test]
    fn tag_ledger_round_trips_over_one_spend_and_every_broken_chain_is_refused() {
        let started = std::time::Instant::now();
        let null = null_cover_carrier(secret(0)).expect("the null cover carrier proves");
        let spend = null_cover_carrier(secret(1)).expect("the spend's cover carrier proves");
        let spend_tags = null_cover_tags(secret(1));
        assert_eq!(
            digest_of_pb(&spend.1).expect("bind"),
            cover_tag_set_digest(&spend_tags),
            "calibration: the carrier's bind is its tag set's chain digest"
        );
        let seed = secret(9);
        let (onr, dsr) = (vec![Fa4::from_u64(3); DIGEST_LANES], vec![Fa4::from_u64(5); DIGEST_LANES]);
        let rows = honest_rows(seed, &spend_tags);
        let carriers = vec![null.clone(), spend.clone()];
        let (bytes, published) = prove_tag_ledger_bytes(&carriers, &rows, &onr, &dsr, seed).expect("the honest tag ledger proves");
        let commit = crate::slot_ledger::seed_commit_native(seed);
        eprintln!("[tag-ledger] proved in {} ms, {} B, {} published digests", started.elapsed().as_millis(), bytes.len(), published.len());
        let derived: Vec<Digest> = rows.iter().map(|r| pair_digest_native(&r.tags[0], &r.tags[1])).collect();
        assert_eq!(published, derived, "the published list is a function of the rows' tags (the note ledger's cells)");
        // DIAGNOSTIC: the shapes the carrier declares against the statement's (DB-213b is the first gate a verifier runs).
        let layout = tag_ledger_layout().expect("layout");
        let (want_c, want_b) = tag_ledger_table_shapes(layout).expect("shapes");
        let (got_c, got_b) = crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes);
        eprintln!("[tag-ledger] constraint shapes declared {got_c:?} expected {want_c:?} · bus declared {got_b:?} expected {want_b:?}");
        let (cross, cols) = tag_ledger_ties(layout, onr.len(), dsr.len()).expect("ties");
        eprintln!("[tag-ledger] {} cross ties, {} column ties (max {})", cross.len(), cols.len(), COLUMN_TIES_MAX);
        assert!(verify_tag_ledger_bytes(&bytes, &onr, &dsr, commit, &published), "⛔ the peer refuses the honest tag ledger");
        // TAMPER (door): one pair row's digest swapped with a cover row's — a different list, the same proof.
        let mut swapped = published.clone();
        let (i, j) = (3usize, 0usize);
        swapped.swap(i, j);
        assert!(!verify_tag_ledger_bytes(&bytes, &onr, &dsr, commit, &swapped), "⛔ a swapped published cell was accepted");
        // TAMPER (producer): a chain missing its last pair — the emit of the pair before it has no consumer.
        let mut missing = rows.clone();
        let last = missing.iter().position(|r| r.pair_of == Some((1, PAIRS_PER_SPEND - 1))).expect("the last pair");
        missing[last] = TagRow { pair_of: None, tags: missing[last].tags };
        assert!(prove_tag_ledger_bytes(&carriers, &missing, &onr, &dsr, seed).is_none(), "⛔ a chain one row short was laid");
        // TAMPER (producer): the chain closes on another carrier's digest (carrier 1's rows cite carrier 0's tags).
        let foreign = honest_rows(seed, &null_cover_tags(secret(0)));
        assert!(prove_tag_ledger_bytes(&carriers, &foreign, &onr, &dsr, seed).is_none(), "⛔ a chain closing on a foreign digest was laid");
        // TAMPER (producer): a pair laid twice.
        let mut twice = rows.clone();
        // RE-MEASURED 2026-11-10: two neighbouring pairs in the middle of the chain at ANY spend width (the literals 7
        // and 8 named pairs of the 32-tag width; 603d215e narrowed a spend to 8 tags, four pairs, and the pin read RED).
        let (mid_a, mid_b) = (PAIRS_PER_SPEND / 2 - 1, PAIRS_PER_SPEND / 2);
        assert!(mid_a != mid_b && mid_b < PAIRS_PER_SPEND, "calibration: two different pairs of this chain");
        let p7 = twice.iter().position(|r| r.pair_of == Some((1, mid_a))).expect("the first middle pair");
        let p8 = twice.iter().position(|r| r.pair_of == Some((1, mid_b))).expect("the second middle pair");
        twice[p8] = twice[p7].clone();
        assert!(prove_tag_ledger_bytes(&carriers, &twice, &onr, &dsr, seed).is_none(), "⛔ a duplicated pair was laid");
        eprintln!("[tag-ledger] round trip + 4 refusals in {} ms", started.elapsed().as_millis());
    }

    /// A quiet block: every row a cover row on the null carrier — the same statement shape, nothing of the carrier
    /// published; and the armed double verifies on the armed door only.
    #[test]
    fn a_quiet_tag_ledger_lays_on_the_null_carrier_and_the_armed_forms_never_cross() {
        use crate::slot_ledger::cover_tag_native as ledger_cover;
        let null = null_cover_carrier(secret(2)).expect("null");
        let seed = secret(4);
        let rows: Vec<TagRow> =
            (0..LEDGER_ROWS as u64).map(|r| TagRow { pair_of: None, tags: [ledger_cover(seed, 2 * r + 1), ledger_cover(seed, 2 * r + 2)] }).collect();
        let (onr, dsr) = (vec![Fa4::from_u64(1); DIGEST_LANES], vec![Fa4::from_u64(2); DIGEST_LANES]);
        let commit = crate::slot_ledger::seed_commit_native(seed);
        let (armed, published) = prove_tag_ledger_bytes_bound(&[null.clone()], &rows, &onr, &dsr, seed).expect("the armed quiet ledger lays");
        assert!(verify_tag_ledger_bytes_bound(&armed, &onr, &dsr, commit, &published), "the armed door accepts the double");
        assert!(!verify_tag_ledger_bytes(&armed, &onr, &dsr, commit, &published), "⛔ the real door accepted the double");
        let (real, published2) = prove_tag_ledger_bytes(&[null], &rows, &onr, &dsr, seed).expect("the quiet ledger proves");
        assert_eq!(published, published2, "one lay, one list");
        assert!(verify_tag_ledger_bytes(&real, &onr, &dsr, commit, &published), "the real door accepts the quiet ledger");
        assert!(!verify_tag_ledger_bytes_bound(&real, &onr, &dsr, commit, &published), "⛔ the armed door accepted a real proof");
    }
}

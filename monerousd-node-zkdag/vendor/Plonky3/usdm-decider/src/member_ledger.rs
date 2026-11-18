//! MonerousD Protocol — THE PADDED MEMBER LEDGER'S SHAPE (§RF-3 spec §12–§12.2, lane a, 2026-10-24).
//!
//! The member ledger is the note ledger's twin for the member-path class: exactly [`LEDGER_ROWS`] rows per block, row
//! `r` the member statement of note-ledger row `r`, so the list never says how many spends the block holds. A row
//! publishes `lc' ‖ binder' ‖ 0 ‖ outs'` — the anchor's lane is a ZERO the gate forces, never the anchor (spec §12: a
//! per-row anchor splits the rows into "a real spend used it" and "cover", leaking `n`); each spend row's absorbed
//! anchor is looked up in the public ring instead ([`crate::member_ring`], shape (D)).
//!
//! THIS STEP lands the statement's SHAPE from constants alone — the class layout at `LEDGER_ROWS` slots, the step
//! table's extension columns, the constraint tables and the bus, and the joint tie list — so the producer and the
//! peer derive one shape and the tie budget ([`COLUMN_TIES_MAX`]) is measured before any law is written (§9.3: refute
//! the spec before the diff). The laws and the prove/verify pair build on exactly these offsets.
//!
//! The published block keeps the class's `tuple_vals` (4 digests) so the chain's tie and the `rows_digest` plan are
//! the note ledger's own ([`ledger_delta_ties_at`], one shared site); the zero lane never travels — a peer recomputes
//! `rows_digest` with it inserted, so the wire carries 3 digests per row.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::member_path_gate::{member_class_base, MEMBER_TUPLE_VALS};
use crate::member_ring::{make_member_ring_constraint, member_ring_shapes, ring_lookup_column_ties, MemberRingAir, RingLayout};
use p3_field::PrimeCharacteristicRing;
use crate::poseidon2_compress::{lanes_of, Digest, DIGEST_LANES};
use crate::settlement_delta::{
    chain_table_of, delta_layout, ledger_bind, ledger_delta_ties_at, make_settlement_delta_constraint, rows_digest_of,
    settlement_delta_table_shapes, settlement_delta_tables, DeltaLayout, LEDGER_ROWS,
};
use crate::whir_rec_block::{merge_column_ties, ColumnTieSpec, CrossTieSpec, COLUMN_TIES_MAX};

/// Extension column: `is_spend ∈ {0,1}` (the ring step's send multiplicity).
pub const X_SPEND: usize = 0;
/// Extension block: the PUBLISHED row `lc' ‖ binder' ‖ 0 ‖ outs'`, `MEMBER_TUPLE_VALS` cells.
pub const X_PUB: usize = 1;
/// The published block's zero lane (the anchor's position) — also the ring step's `zero` column.
pub const X_ZERO: usize = X_PUB + 2 * DIGEST_LANES;
/// The row's note-ledger cover slot `slot_lc` (the cover law's input; one cell, as the note ledger's `SL_SLOT_LC`).
pub const X_SLOT_LC: usize = X_PUB + MEMBER_TUPLE_VALS;
/// The header seed (the cover law's key), bound to the block's public seed commitment by [`X_B_SEED`].
pub const X_SEED: usize = X_SLOT_LC + 1;
/// The cover law's Poseidon2 block: `P(COVER_LC_DOMAIN ‖ slot_lc ‖ 0…, seed)`.
pub const X_B_LC: usize = X_SEED + DIGEST_LANES;
/// The seed's Poseidon2 block: `P(HEADER_SEED_DOMAIN ‖ 0…, seed) == seed_commit` (the note ledger's own commit).
pub const X_B_SEED: usize = X_B_LC + crate::pow_pq_air::P2_COLS;
/// Extension width.
pub const X_COLS: usize = X_B_SEED + crate::pow_pq_air::P2_COLS;

/// Table indexes, in the batch's order: the class's step, sponge and chain tables, then the ring's MULT table.
pub const T_MULT: usize = 3;
/// The ring's sponge chain (its final state is the public `ring_digest`), the next table.
pub const T_RING_CHAIN: usize = T_MULT + 1;
/// The ring's LogUp bus — numbered after the constraint tables, as the batch prover indexes it.
pub const T_BUS: usize = T_RING_CHAIN + 1;

/// The member class at the ledger's constant row count — the one layout both sides build.
#[must_use]
pub fn member_ledger_layout() -> Option<DeltaLayout> {
    let (base, powers) = member_class_base();
    delta_layout(base, powers, LEDGER_ROWS, LEDGER_ROWS, 1 + MEMBER_TUPLE_VALS, MEMBER_TUPLE_VALS)
}

/// The ring lookup's shape: one step per ledger row against the protocol ring.
#[must_use]
pub fn member_ledger_ring() -> Option<RingLayout> {
    let rl = RingLayout::production()?;
    (rl.steps() == LEDGER_ROWS).then_some(rl)
}

/// `(constraint table shapes, bus shapes)`: the class's tables with the step widened by the extension, then the
/// ring's MULT and CHAIN; the ring's bus.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn member_ledger_table_shapes(layout: DeltaLayout) -> Option<(Vec<(usize, usize)>, Vec<(usize, usize)>)> {
    let rl = member_ledger_ring()?;
    let mut s = settlement_delta_table_shapes(layout)?;
    if s.len() != T_MULT {
        return None;
    }
    s[layout.step_table()].1 = layout.step_cols() + X_COLS;
    let (ring, bus) = member_ring_shapes(rl);
    s.extend(ring.into_iter().skip(1)); // the ring's own step table IS the ledger's step table
    Some((s, bus))
}

/// The statement's ties: the class's (chain re-pointed at the published block, same-point ties merged) and the ring
/// lookup's, the step's `(zero, anchor, is_spend)` read off the ledger row. `None` when the joint list exceeds
/// [`COLUMN_TIES_MAX`] — MEASURED 2026-10-24: 55 merged class ties + 4 ring ties = 59.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn member_ledger_ties(
    layout: DeltaLayout,
    onr_len: usize,
    dsr_len: usize,
) -> Option<(Vec<CrossTieSpec>, Vec<ColumnTieSpec>)> {
    let ext = layout.step_cols();
    let (cross, cols) = ledger_delta_ties_at(layout, onr_len, dsr_len, ext + X_PUB)?;
    let mut cols = merge_column_ties(cols);
    let step = (layout.step_table(), ext + X_ZERO, layout.tuple_at(2, 0), ext + X_SPEND);
    cols.extend(ring_lookup_column_ties(member_ledger_ring()?, step, T_MULT, T_RING_CHAIN, T_BUS)?);
    (cols.len() <= COLUMN_TIES_MAX).then_some((cross, cols))
}

/// The member ledger's per-table circuit: the member class's tables, the ledger laws on its step rows, the ring's
/// MULT and CHAIN tables. The ledger laws are folded from `γ^K`, `K = 2·nvars + powers + 16` — the note ledger's
/// batching offset ([`crate::settlement_delta::LedgerDeltaAir`]), past every power the class's bound step uses.
pub enum MemberLedgerAir<B: AirConstraint> {
    Class(B),
    Step { base: B, ext: usize, tuple_off: usize, seed_commit: [Ea4; DIGEST_LANES], offset: u64, gamma: Ea4 },
    Ring(MemberRingAir),
}

/// The ledger laws of one step row, as residuals. `s = is_spend`:
/// L1 `s ∈ {0,1}` (the ring step's send multiplicity); L2 the published anchor lane is zero (the anchor never
/// travels — it is looked up in the ring); L3 a spend publishes its absorbed `lc ‖ binder ‖ outs`; L4 a cover row's
/// `lc'` is `P(COVER_LC_DOMAIN ‖ slot_lc, seed)` under the header seed commitment — a cover `lc'` equal to a real
/// carrier's `lc` is a cross-domain Poseidon2 collision, so a note-ledger spend row is matched only by a real path.
/// ⭐ V2 (a) (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16): generic over the field its row lives in, the type parameter
/// NAMED `Ea4` so the body is the production body (lane agg's `gate_trace` pattern; native code unchanged).
pub(crate) fn push_member_ledger_laws<Ea4: p3_field::Algebra<Fa4> + Copy + 'static>(
    rs: &mut Vec<Ea4>,
    local: &Row<'_, Ea4>,
    ext: usize,
    tuple_off: usize,
    seed_commit: &[Ea4; DIGEST_LANES],
) {
    use crate::slot_ledger::{COVER_LC_DOMAIN, HEADER_SEED_DOMAIN};
    let x = |off: usize| local[ext + off];
    let abs = |k: usize, c: usize| local[tuple_off + k * DIGEST_LANES + c];
    let pubc = |k: usize, c: usize| x(X_PUB + k * DIGEST_LANES + c);
    let dom = |v: u64| -> Ea4 { Ea4::from(Fa4::from_u64(v)) };
    let out = crate::pow_pq_air::PERM_OUT;
    let s = x(X_SPEND);
    rs.push(s * (s - Ea4::ONE));
    for c in 0..DIGEST_LANES {
        rs.push(x(X_ZERO + c));
        for k in [0usize, 1, 3] {
            rs.push(s * (pubc(k, c) - abs(k, c)));
        }
        rs.push((Ea4::ONE - s) * (pubc(0, c) - x(X_B_LC + out + c)));
    }
    for (blk, lane0, lane1) in [(X_B_LC, COVER_LC_DOMAIN, Some(X_SLOT_LC)), (X_B_SEED, HEADER_SEED_DOMAIN, None)] {
        crate::pow_pq_air::push_perm_residuals(local, ext + blk, rs);
        for c in 0..DIGEST_LANES {
            let left = match (c, lane1) {
                (0, _) => dom(lane0),
                (1, Some(o)) => x(o),
                _ => Ea4::ZERO,
            };
            rs.push(x(blk + c) - left);
            rs.push(x(blk + DIGEST_LANES + c) - x(X_SEED + c));
        }
    }
    for c in 0..DIGEST_LANES {
        rs.push(x(X_B_SEED + out + c) - seed_commit[c]);
    }
}

impl<B: AirConstraint> AirConstraint for MemberLedgerAir<B> {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Class(b) => b.degree(nvars),
            Self::Step { base, .. } => base.degree(nvars).max(crate::pow_pq_air::PERM_MAX_DEGREE).max(2),
            Self::Ring(r) => r.degree(nvars),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Class(b) => b.eval(local, at, x),
            Self::Step { base, ext, tuple_off, seed_commit, offset, gamma } => {
                let mut rs = Vec::new();
                push_member_ledger_laws(&mut rs, local, *ext, *tuple_off, seed_commit);
                let mut acc = Ea4::ZERO;
                let mut gp = gamma.exp_u64(*offset);
                for r in rs {
                    acc += gp * r;
                    gp *= *gamma;
                }
                base.eval(local, at, x) + acc
            }
            Self::Ring(r) => r.eval(local, at, x),
        }
    }
    fn has_base_eval(&self) -> bool {
        match self {
            Self::Class(b) => b.has_base_eval(),
            Self::Step { .. } => false,
            Self::Ring(r) => r.has_base_eval(),
        }
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            Self::Class(b) => b.eval_base(local, at, x),
            Self::Step { .. } => unreachable!("eval_base is called only when has_base_eval() is true"),
            Self::Ring(r) => r.eval_base(local, at, x),
        }
    }
    fn is_row_local(&self) -> bool {
        match self {
            Self::Class(b) | Self::Step { base: b, .. } => b.is_row_local(),
            Self::Ring(r) => r.is_row_local(),
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Class(b) | Self::Step { base: b, .. } => b.shifted_cols(),
            Self::Ring(r) => r.shifted_cols(),
        }
    }
    /// The class's declaration, plus the extension's published `binder'` and `outs'` lanes: L3 reads them only on a
    /// spend row (`s·(pub − abs)`), so on a cover row they are the prover's fresh padding (spec §12) — bound to the
    /// wire by the chain table's column tie into `rows_digest`, read by no law (MEASURED 2026-10-24: the strict
    /// free-witness census named exactly these 16 columns). Every other extension cell is read by a law above.
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Class(b) => b.free_columns(),
            Self::Step { base, ext, .. } => {
                let mut v = base.free_columns().unwrap_or_default();
                for k in [1usize, 3] {
                    v.extend((0..DIGEST_LANES).map(|c| ext + X_PUB + k * DIGEST_LANES + c));
                }
                Some(v)
            }
            Self::Ring(r) => r.free_columns(),
        }
    }
}

/// The member ledger's constraint factory BOTH sides derive from public values: the layout, the class's table
/// factory (`make_settlement_delta_constraint(layout, member_delta_factory(layout))`) and the header seed commit.
pub fn make_member_ledger_constraint<B, G>(
    layout: DeltaLayout,
    class: G,
    seed_commit: [Ea4; DIGEST_LANES],
) -> Option<impl Fn(usize, Ea4) -> MemberLedgerAir<B> + Clone>
where
    B: AirConstraint,
    G: Fn(usize, Ea4) -> B + Clone,
{
    let ring = make_member_ring_constraint(member_ledger_ring()?);
    let offset = (2 * layout.bound.nvars + layout.bound.powers + 16) as u64;
    Some(move |table: usize, gamma: Ea4| {
        if table >= T_MULT {
            MemberLedgerAir::Ring(ring(table - T_MULT + 1, gamma))
        } else if table == layout.step_table() {
            MemberLedgerAir::Step {
                base: class(table, gamma),
                ext: layout.step_cols(),
                tuple_off: layout.tuple_off(),
                seed_commit,
                offset,
                gamma,
            }
        } else {
            MemberLedgerAir::Class(class(table, gamma))
        }
    })
}

/// A member ledger row as the wire carries it: `lc' ‖ binder' ‖ outs'` — the zero anchor lane never travels; a peer
/// inserts it to recompute `rows_digest`.
pub type MemberPublished = [Digest; 3];

const TUPLE_DIGESTS: usize = MEMBER_TUPLE_VALS / DIGEST_LANES;

fn member_published_vals(p: &MemberPublished) -> Vec<Fa4> {
    [p[0], p[1], [0; DIGEST_LANES], p[2]].iter().flat_map(|d| d.iter().map(|&v| Fa4::from_u64(v))).collect()
}

/// Lay one step row's extension ([`X_COLS`] cells) and return what the row publishes. A spend publishes its absorbed
/// `lc ‖ binder ‖ outs`; a cover row publishes `P(COVER_LC_DOMAIN ‖ slot_lc, seed)` and, for the law-free `binder'` and
/// `outs'`, fresh CSPRNG digests — so a cover row reads as a real row's fresh digests. `None` when the OS source refuses.
fn lay_member_ledger_ext(
    ext: &mut [Fa4],
    is_spend: bool,
    abs: &[Digest; TUPLE_DIGESTS],
    slot_lc: u64,
    seed: Digest,
    cover: Option<[Digest; 2]>,
) -> Option<MemberPublished> {
    use crate::pow_pq_air::{lay_perm_row_flat, pair_state};
    use crate::slot_ledger::{cover_lc_native, COVER_LC_DOMAIN, HEADER_SEED_DOMAIN};
    if ext.len() != X_COLS {
        return None;
    }
    let published: MemberPublished = if is_spend {
        [abs[0], abs[1], abs[3]]
    } else {
        let r = crate::whir_rec_block::fresh_lc_blind;
        match cover {
            Some([b, o]) => [cover_lc_native(seed, slot_lc), b, o], // the note ledger's own cover cells (§12.1)
            None => [cover_lc_native(seed, slot_lc), r()?, r()?],
        }
    };
    ext[X_SPEND] = if is_spend { Fa4::ONE } else { Fa4::ZERO };
    for (i, v) in member_published_vals(&published).into_iter().enumerate() {
        ext[X_PUB + i] = v;
    }
    ext[X_SLOT_LC] = Fa4::from_u64(slot_lc);
    for c in 0..DIGEST_LANES {
        ext[X_SEED + c] = Fa4::from_u64(seed[c]);
    }
    lay_perm_row_flat(ext, X_B_LC, pair_state(&lanes_of(&[COVER_LC_DOMAIN, slot_lc]), &seed));
    lay_perm_row_flat(ext, X_B_SEED, pair_state(&lanes_of(&[HEADER_SEED_DOMAIN]), &seed));
    Some(published)
}

/// The statement both sides derive: the note ledger's bind (`settlement_delta_bind ‖ seed_commit`) then
/// `RING_DOMAIN ‖ ring_digest`; the joint ties plus the ring chain's output tied at the ring digest's bind offset.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn member_ledger_statement(
    layout: DeltaLayout,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    seed_commit: &Digest,
    ring_digest: &[Fa4],
) -> Option<(Vec<Fa4>, Vec<CrossTieSpec>, Vec<ColumnTieSpec>)> {
    if ring_digest.len() != DIGEST_LANES {
        return None;
    }
    let mut bind = ledger_bind(domain, output_notes_root, del_set_root, rows_digest, seed_commit);
    bind.push(Fa4::from_u64(crate::member_ring::RING_DOMAIN));
    let off = bind.len();
    bind.extend_from_slice(ring_digest);
    let (mut cross, cols) = member_ledger_ties(layout, output_notes_root.len(), del_set_root.len())?;
    cross.extend(crate::member_ring::member_ring_cross_ties_at(member_ledger_ring()?, T_RING_CHAIN, off));
    Some((bind, cross, cols))
}

fn seed_commit_e8(d: &Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| Ea4::from(Fa4::from_u64(d[c])))
}

/// PRODUCER — lay and prove a block's member ledger. `carriers` are the block's real member-path carriers (or ONE
/// [`crate::member_path_gate::null_member_carrier`] for a block with no spend); `rows` is exactly [`LEDGER_ROWS`]
/// `(spend_of, slot_lc)` in the NOTE ledger's canonical order (row `r` ↔ note-ledger row `r`); `ring` is the public
/// anchor ring. Cover rows replicate `carriers[0]` (its anchor is never sent: `is_spend = 0`). Returns the proof, the
/// published rows and the `ring_digest`. `None` on anything unstateable: a carrier spent twice or out of range, a
/// carrier of another class, a spend whose anchor is not in the ring (refused before any proving work).
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_member_ledger_bytes(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    ring: &[[Fa4; DIGEST_LANES]],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(Vec<u8>, Vec<MemberPublished>, Vec<Fa4>)> {
    prove_member_ledger_with(carriers, rows, None, ring, member_domain(), output_notes_root, del_set_root, seed, false)
}

/// ⭐ §RF-3 §12.1 PRODUCER — [`prove_member_ledger_bytes`] with every COVER row's law-free `binder' ‖ outs'` taken from
/// `cover_cells[r]` (the note ledger row `r`'s `PUB_TAG0` and its outputs' digest) instead of fresh randomness, so the
/// member rows are a function of the note ledger's list and never ride the wire. Spend rows ignore their entry (they
/// publish what their carrier absorbed). MEASURED 2026-10-24: with fresh cover cells, a peer deriving the rows from the
/// note list refuses every honest block.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_member_ledger_over_notes(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    cover_cells: &[[Digest; 2]],
    ring: &[[Fa4; DIGEST_LANES]],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(Vec<u8>, Vec<MemberPublished>, Vec<Fa4>)> {
    if cover_cells.len() != LEDGER_ROWS {
        return None;
    }
    prove_member_ledger_with(carriers, rows, Some(cover_cells), ring, member_domain(), output_notes_root, del_set_root, seed, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_member_ledger_over_notes`] with the BOUND template double (`settlement_delta`'s
/// `delta_bound`, member class): the SAME lay (ring tables, every carrier's step, the cover cells, the published rows,
/// the statement) with only the WHIR prove dropped and the whole public statement sealed in its place. So an armed sim
/// produces ledger blocks at template speed, and a peer's armed door refuses exactly what the real door refuses on the
/// statement. ⛔ NOT A SOUNDNESS DOOR: the real-prove pin above carries the soundness; a ROGUE producer never arms it.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_member_ledger_over_notes_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    cover_cells: &[[Digest; 2]],
    ring: &[[Fa4; DIGEST_LANES]],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(Vec<u8>, Vec<MemberPublished>, Vec<Fa4>)> {
    if cover_cells.len() != LEDGER_ROWS {
        return None;
    }
    prove_member_ledger_with(carriers, rows, Some(cover_cells), ring, member_domain(), output_notes_root, del_set_root, seed, true)
}

/// The statement's domain tag is the CLASS's — the tag every member-path carrier's transcript absorbs (the class's
/// domain cross-tie checks it) — so no producer chooses it and one block has one encoding. MEASURED 2026-10-24: a
/// statement made under any other tag fails that cross-tie at verify.
fn member_domain() -> Fa4 {
    Fa4::from_u64(crate::member_path_gate::MEMBER_PATH_DOMAIN)
}

#[allow(clippy::type_complexity)]
fn prove_member_ledger_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    cover_cells: Option<&[[Digest; 2]]>,
    ring: &[[Fa4; DIGEST_LANES]],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
    bound: bool,
) -> Option<(Vec<u8>, Vec<MemberPublished>, Vec<Fa4>)> {
    let (laid, published, ring_digest) =
        lay_member_ledger(carriers, rows, cover_cells, ring, domain, output_notes_root, del_set_root, seed)?;
    if bound {
        let layout = member_ledger_layout()?;
        member_ledger_table_shapes(layout)?;
        let b = crate::settlement_delta::member_ledger_bound_seal(&layout, &laid.bind)?;
        return Some((b, published, ring_digest));
    }
    Some((prove_laid(laid)?, published, ring_digest))
}

fn prove_laid(laid: LaidMemberLedger) -> Option<Vec<u8>> {
    let layout = member_ledger_layout()?;
    let mk = make_member_ledger_constraint(
        layout,
        make_settlement_delta_constraint(layout, crate::member_path_gate::member_delta_factory(layout)),
        seed_commit_e8(&laid.seed_commit),
    )?;
    crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        laid.tables,
        mk,
        vec![laid.bus],
        laid.cross,
        laid.cols,
        &laid.bind,
    )
}

/// What the producer proves: the tables, the ring's bus and the statement.
/// ⭐ R4 lever 4 — the member ledger as ONE STATEMENT of a joined light-decider batch (`light_batch_merge`): the same
/// lay, constraint, bus, ties and bind `prove_laid` hands the engine, handed to the merge instead. Returns the statement,
/// the published rows and the ring digest exactly as [`prove_member_ledger_over_notes`] does.
#[allow(clippy::type_complexity)]
pub fn lay_member_ledger_statement_over_notes(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    cover_cells: &[[Digest; 2]],
    ring: &[[Fa4; DIGEST_LANES]],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(crate::light_batch_merge::LaidStatement<'static>, Vec<MemberPublished>, Vec<Fa4>)> {
    if cover_cells.len() != LEDGER_ROWS {
        return None;
    }
    let (laid, published, ring_digest) =
        lay_member_ledger(carriers, rows, Some(cover_cells), ring, member_domain(), output_notes_root, del_set_root, seed)?;
    let layout = member_ledger_layout()?;
    let mk = make_member_ledger_constraint(
        layout,
        make_settlement_delta_constraint(layout, crate::member_path_gate::member_delta_factory(layout)),
        seed_commit_e8(&laid.seed_commit),
    )?;
    let statement = crate::light_batch_merge::LaidStatement {
        tables: laid.tables,
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        buses: vec![laid.bus],
        cross: laid.cross,
        cols: laid.cols,
        joint: Vec::new(),
        bind: laid.bind,
    };
    Some((statement, published, ring_digest))
}

/// ⭐ R4 lever 4 — the member ledger's statement for a joined VERIFY: every part derived from the peer's own inputs, exactly
/// as [`verify_member_ledger_bytes`] derives them.
#[must_use]
pub fn member_ledger_stated_statement(
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[MemberPublished],
    ring_digest: &[Fa4],
) -> Option<crate::light_batch_merge::StatedStatement<'static>> {
    if published.len() != LEDGER_ROWS {
        return None;
    }
    let layout = member_ledger_layout()?;
    let pvals: Vec<Vec<Fa4>> = published.iter().map(member_published_vals).collect();
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, MEMBER_TUPLE_VALS)?;
    let (bind, cross, cols) =
        member_ledger_statement(layout, member_domain(), output_notes_root, del_set_root, &rows_digest, &seed_commit, ring_digest)?;
    let (constraint_shapes, bus_shapes) = member_ledger_table_shapes(layout)?;
    let mk = make_member_ledger_constraint(
        layout,
        make_settlement_delta_constraint(layout, crate::member_path_gate::member_delta_factory(layout)),
        seed_commit_e8(&seed_commit),
    )?;
    Some(crate::light_batch_merge::StatedStatement {
        make: Box::new(move |t, e| -> crate::light_batch_merge::BoxedConstraint<'static> { Box::new(mk(t, e)) }),
        cross,
        cols,
        joint: Vec::new(),
        bind,
        constraint_shapes,
        bus_shapes,
    })
}

struct LaidMemberLedger {
    tables: Vec<Vec<Vec<Fa4>>>,
    bus: crate::member_ring::TiedBus,
    bind: Vec<Fa4>,
    cross: Vec<CrossTieSpec>,
    cols: Vec<ColumnTieSpec>,
    seed_commit: Digest,
}

#[allow(clippy::type_complexity)]
fn lay_member_ledger(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    rows: &[(Option<usize>, u64)],
    cover_cells: Option<&[[Digest; 2]]>,
    ring: &[[Fa4; DIGEST_LANES]],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed: Digest,
) -> Option<(LaidMemberLedger, Vec<MemberPublished>, Vec<Fa4>)> {
    use p3_field::PrimeField64;
    if carriers.is_empty() || rows.len() != LEDGER_ROWS {
        return None;
    }
    let mut spent = vec![false; carriers.len()];
    for (s, _) in rows {
        if let Some(i) = *s {
            if i >= carriers.len() || spent[i] {
                return None;
            }
            spent[i] = true;
        }
    }
    let layout = member_ledger_layout()?;
    let rl = member_ledger_ring()?;
    let abs_of = |pb: &[Fa4]| -> Option<[Digest; TUPLE_DIGESTS]> {
        (pb.len() == 1 + MEMBER_TUPLE_VALS)
            .then(|| core::array::from_fn(|k| core::array::from_fn(|c| pb[1 + k * DIGEST_LANES + c].as_canonical_u64())))
    };
    let abs: Vec<[Digest; TUPLE_DIGESTS]> = carriers.iter().map(|c| abs_of(&c.1)).collect::<Option<_>>()?;
    let src = |s: &Option<usize>| s.unwrap_or(0);
    let steps: Vec<([Fa4; DIGEST_LANES], bool)> = rows
        .iter()
        .map(|(s, _)| (core::array::from_fn(|c| Fa4::from_u64(abs[src(s)][2][c])), s.is_some()))
        .collect();
    let (ring_tables, bus, ring_digest) = crate::member_ring::member_ring_tables(rl, ring, &steps)?;
    let expanded: Vec<(Vec<u8>, Vec<Fa4>)> = rows.iter().map(|(s, _)| carriers[src(s)].clone()).collect();
    let (mut tables, _absorbed_digest) = settlement_delta_tables(&expanded, layout)?;
    let mut exts = vec![vec![Fa4::ZERO; X_COLS]; LEDGER_ROWS];
    let mut published = Vec::with_capacity(LEDGER_ROWS);
    for (r, ((s, slot_lc), e)) in rows.iter().zip(exts.iter_mut()).enumerate() {
        let cover = cover_cells.map(|c| c.get(r).copied()).map_or(Some(None), |c| c.map(Some))?;
        published.push(lay_member_ledger_ext(e, s.is_some(), &abs[src(s)], *slot_lc, seed, cover)?);
    }
    let step = layout.step_table();
    for c in 0..X_COLS {
        tables[step].push(exts.iter().map(|e| e[c]).collect());
    }
    let pvals: Vec<Vec<Fa4>> = published.iter().map(member_published_vals).collect();
    tables[layout.chain_table()] = chain_table_of(&pvals)?;
    tables.extend(ring_tables.into_iter().skip(1)); // the ring's step IS the ledger's step
    if tables.len() != T_BUS {
        return None;
    }
    let rows_digest = rows_digest_of(&pvals, LEDGER_ROWS, MEMBER_TUPLE_VALS)?;
    let seed_commit = crate::slot_ledger::seed_commit_native(seed);
    let (bind, cross, cols) =
        member_ledger_statement(layout, domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, &ring_digest)?;
    Some((LaidMemberLedger { tables, bus, bind, cross, cols, seed_commit }, published, ring_digest))
}

/// PEER — verify a block's member ledger from what the block carries (the proof, the published rows, the header seed's
/// commitment) and the `ring_digest` the peer computed from its OWN ring. The layout and shapes are the class's (no
/// shape rides the wire); `rows_digest` is recomputed from the rows with the zero lane inserted.
#[must_use]
pub fn verify_member_ledger_bytes(
    bytes: &[u8],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[MemberPublished],
    ring_digest: &[Fa4],
) -> bool {
    verify_member_ledger_with(bytes, member_domain(), output_notes_root, del_set_root, seed_commit, published, ring_digest, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_member_ledger_bytes`] on an ARMED door: it accepts the bound double's seal and nothing
/// else (never a real proof's bytes; the real door never accepts the seal).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_member_ledger_bytes_bound(
    bytes: &[u8],
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[MemberPublished],
    ring_digest: &[Fa4],
) -> bool {
    verify_member_ledger_with(bytes, member_domain(), output_notes_root, del_set_root, seed_commit, published, ring_digest, true)
}

fn verify_member_ledger_with(
    bytes: &[u8],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    seed_commit: Digest,
    published: &[MemberPublished],
    ring_digest: &[Fa4],
    bound: bool,
) -> bool {
    if bytes.is_empty() || published.len() != LEDGER_ROWS {
        return false;
    }
    let Some(layout) = member_ledger_layout() else { return false };
    let pvals: Vec<Vec<Fa4>> = published.iter().map(member_published_vals).collect();
    let Some(rows_digest) = rows_digest_of(&pvals, LEDGER_ROWS, MEMBER_TUPLE_VALS) else { return false };
    let Some((bind, cross, cols)) =
        member_ledger_statement(layout, domain, output_notes_root, del_set_root, &rows_digest, &seed_commit, ring_digest)
    else {
        return false;
    };
    let Some((shapes, bus)) = member_ledger_table_shapes(layout) else { return false };
    if bound {
        return crate::settlement_delta::member_ledger_bound_seal(&layout, &bind).is_some_and(|s| s.as_slice() == bytes);
    }
    let Some(mk) = make_member_ledger_constraint(
        layout,
        make_settlement_delta_constraint(layout, crate::member_path_gate::member_delta_factory(layout)),
        seed_commit_e8(&seed_commit),
    ) else {
        return false;
    };
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(bytes, mk, cross, cols, &bind, &shapes, &bus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Digest {
        crate::whir_rec_block::fresh_lc_blind().expect("OS CSPRNG")
    }

    /// A real member-path carrier and its anchor (the ring's entry).
    fn spend_carrier() -> ((Vec<u8>, Vec<Fa4>), crate::member_path_gate::MemberTuple) {
        let sib: Vec<Digest> = (0..crate::member_path_gate::MEMBER_PATH_DEPTH).map(|_| fresh()).collect();
        let dirs: Vec<bool> = sib.iter().map(|s| s[1] & 1 == 1).collect();
        let (bytes, t) = crate::member_path_gate::prove_member_path_carrier(fresh(), &sib, &dirs, fresh(), fresh(), fresh())
            .expect("member path carrier");
        ((bytes, t.bind()), t)
    }

    /// THE MEMBER LEDGER END TO END (§RF-3 §12): one spend at row 3 of [`LEDGER_ROWS`], its anchor in the ring. The
    /// honest proof verifies; the spend row publishes its absorbed `lc ‖ binder ‖ outs`, every cover row the seed's
    /// `cover_lc`. Every tamper REJECTS: an anchor outside the ring (the producer refuses), a wrong seed commit, a wrong
    /// ring digest, a cover `lc'` copied from the spend's `lc`, a spend row's binder swapped, a statement
    /// under a domain the carriers never absorbed, a nonzero anchor lane on the spend row (the ring lookup's zero).
    #[test]
    fn the_member_ledger_proves_one_spend_and_every_tamper_rejects() {
        let (c, t) = spend_carrier();
        let anchor: [Fa4; DIGEST_LANES] = core::array::from_fn(|k| Fa4::from_u64(t.anchor[k]));
        let rows: Vec<(Option<usize>, u64)> = (0..LEDGER_ROWS).map(|i| ((i == 3).then_some(0), i as u64)).collect();
        let seed = fresh();
        let onr = vec![Fa4::from_u64(11); DIGEST_LANES];
        let dsr = vec![Fa4::from_u64(13); DIGEST_LANES];
        let decoy = [Fa4::from_u64(99); DIGEST_LANES];
        let carriers = vec![c];
        assert!(
            prove_member_ledger_bytes(&carriers, &rows, &[decoy], &onr, &dsr, seed).is_none(),
            "an anchor outside the ring is refused"
        );
        let ring = [decoy, anchor];
        let t0 = std::time::Instant::now();
        let (bytes, published, rd) = prove_member_ledger_bytes(&carriers, &rows, &ring, &onr, &dsr, seed).expect("honest");
        eprintln!("member ledger: proved {} rows in {:?} · {} bytes", LEDGER_ROWS, t0.elapsed(), bytes.len());
        let expected = member_ledger_table_shapes(member_ledger_layout().expect("layout")).expect("shapes");
        assert_eq!(crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes), expected, "the proof declares the peer's shapes");
        assert_eq!(published[3], [t.leaf_commit, t.binder, t.outs], "a spend publishes its absorbed tuple");
        for (i, p) in published.iter().enumerate().filter(|(i, _)| *i != 3) {
            assert_eq!(p[0], crate::slot_ledger::cover_lc_native(seed, i as u64), "cover row {i} lc'");
        }
        let sc = crate::slot_ledger::seed_commit_native(seed);
        let domain = member_domain();
        let ok = |b: &[u8], d: Fa4, sc: Digest, p: &[MemberPublished], rd: &[Fa4]| verify_member_ledger_with(b, d, &onr, &dsr, sc, p, rd, false);
        assert!(verify_member_ledger_bytes(&bytes, &onr, &dsr, sc, &published, &rd), "honest member ledger verifies");
        assert!(!ok(&bytes, domain, crate::slot_ledger::seed_commit_native(fresh()), &published, &rd), "wrong seed commit");
        let mut rd2 = rd.clone();
        rd2[0] += Fa4::ONE;
        assert!(!ok(&bytes, domain, sc, &published, &rd2), "wrong ring digest");
        let mut p2 = published.clone();
        p2[0][0] = published[3][0];
        assert!(!ok(&bytes, domain, sc, &p2, &rd), "a cover lc' copied from the spend's lc");
        let mut p3 = published.clone();
        p3[3][1] = fresh();
        assert!(!ok(&bytes, domain, sc, &p3, &rd), "a spend row's binder swapped");
        assert!(!ok(&bytes, domain + Fa4::ONE, sc, &published, &rd), "wrong domain");
        assert!(!ok(&bytes, domain, sc, &published[1..], &rd), "a short row list");
        // a statement made under a tag the carriers never absorbed: the class's domain cross-tie refuses it
        let other = domain + Fa4::ONE;
        let (b2, p4, rd4) = prove_member_ledger_with(&carriers, &rows, None, &ring, other, &onr, &dsr, seed, false).expect("proves");
        assert!(!ok(&b2, other, sc, &p4, &rd4), "a statement under a domain the carriers never absorbed");
        assert!(!verify_member_ledger_bytes(&b2, &onr, &dsr, sc, &p4, &rd4), "the same proof under the class's domain");
        // the spend row's zero lane set nonzero in the trace (the wire never carries it; the peer inserts zero)
        let (mut laid, p5, rd5) = lay_member_ledger(&carriers, &rows, None, &ring, domain, &onr, &dsr, seed).expect("lay");
        let layout = member_ledger_layout().expect("layout");
        laid.tables[layout.step_table()][layout.step_cols() + X_ZERO][3] = Fa4::ONE;
        let b5 = prove_laid(laid);
        assert!(
            !b5.is_some_and(|b| verify_member_ledger_bytes(&b, &onr, &dsr, sc, &p5, &rd5)),
            "a nonzero anchor lane on the spend row"
        );
    }

    /// THE MEMBER LEDGER BOUND DOUBLE (§RF-3, armed sims): the double lays the SAME published rows and ring digest the
    /// real prover lays over one note list; the armed door admits its seal; the real door refuses the seal and the
    /// armed door refuses the real proof's bytes (the two forms never cross doors); every statement tamper the real door
    /// refuses — seed commit, ring digest, a cover lc', a spend's binder, a short list, a flipped seal byte — the armed
    /// door refuses; an anchor outside the ring is refused before anything is sealed.
    #[test]
    fn the_member_ledger_bound_double_admits_the_honest_statement_and_refuses_every_tamper() {
        let (c, t) = spend_carrier();
        let anchor: [Fa4; DIGEST_LANES] = core::array::from_fn(|k| Fa4::from_u64(t.anchor[k]));
        let rows: Vec<(Option<usize>, u64)> = (0..LEDGER_ROWS).map(|i| ((i == 5).then_some(0), i as u64)).collect();
        let seed = fresh();
        let cells: Vec<[Digest; 2]> = (0..LEDGER_ROWS).map(|_| [fresh(), fresh()]).collect();
        let onr = vec![Fa4::from_u64(11); DIGEST_LANES];
        let dsr = vec![Fa4::from_u64(13); DIGEST_LANES];
        let decoy = [Fa4::from_u64(99); DIGEST_LANES];
        let carriers = vec![c];
        assert!(
            prove_member_ledger_over_notes_bound(&carriers, &rows, &cells, &[decoy], &onr, &dsr, seed).is_none(),
            "an anchor outside the ring is refused"
        );
        assert!(
            prove_member_ledger_over_notes_bound(&carriers, &rows, &cells[1..], &[decoy, anchor], &onr, &dsr, seed).is_none(),
            "a short cover-cell list"
        );
        let ring = [decoy, anchor];
        let t0 = std::time::Instant::now();
        let (bb, pb, rdb) =
            prove_member_ledger_over_notes_bound(&carriers, &rows, &cells, &ring, &onr, &dsr, seed).expect("the double lays");
        eprintln!("[member-ledger-bound] {} B, prove {} ms", bb.len(), t0.elapsed().as_millis());
        let (rb, pr, rdr) =
            prove_member_ledger_over_notes(&carriers, &rows, &cells, &ring, &onr, &dsr, seed).expect("the real prove");
        assert_eq!(pb, pr, "the double publishes the real prover's rows");
        assert_eq!(rdb, rdr, "the double's ring digest is the real prover's");
        let sc = crate::slot_ledger::seed_commit_native(seed);
        let armed = |b: &[u8], sc: Digest, p: &[MemberPublished], rd: &[Fa4]| verify_member_ledger_bytes_bound(b, &onr, &dsr, sc, p, rd);
        assert!(armed(&bb, sc, &pb, &rdb), "the armed door admits the honest seal");
        assert!(verify_member_ledger_bytes(&rb, &onr, &dsr, sc, &pr, &rdr), "the real door admits the real proof");
        assert!(!verify_member_ledger_bytes(&bb, &onr, &dsr, sc, &pb, &rdb), "the real door refuses the seal");
        assert!(!armed(&rb, sc, &pr, &rdr), "the armed door refuses a real proof's bytes");
        assert!(!armed(&bb, crate::slot_ledger::seed_commit_native(fresh()), &pb, &rdb), "wrong seed commit");
        let mut rd2 = rdb.clone();
        rd2[0] += Fa4::ONE;
        assert!(!armed(&bb, sc, &pb, &rd2), "wrong ring digest");
        let mut p2 = pb.clone();
        p2[0][0] = pb[5][0];
        assert!(!armed(&bb, sc, &p2, &rdb), "a cover lc' copied from the spend's lc");
        let mut p3 = pb.clone();
        p3[5][1] = fresh();
        assert!(!armed(&bb, sc, &p3, &rdb), "a spend row's binder swapped");
        assert!(!armed(&bb, sc, &pb[1..], &rdb), "a short row list");
        assert!(!verify_member_ledger_bytes_bound(&bb, &dsr, &dsr, sc, &pb, &rdb), "a moved output-notes root");
        let mut b2 = bb.clone();
        b2[0] ^= 1;
        assert!(!armed(&b2, sc, &pb, &rdb), "a flipped seal byte");
        let lay = member_ledger_layout().expect("layout");
        let nb = crate::settlement_delta::member_ledger_bound_seal(&lay, &[Fa4::ZERO]).expect("seal");
        assert!(!armed(&nb, sc, &pb, &rdb), "a seal over another statement");
    }

    /// ⭐ C2 (SPEED, 2026-11-12) — A LIGHT PROOF SENDS THE NEXT-ROW OPENINGS ITS GATES READ, AND NOTHING ELSE IS ADMITTED.
    /// The honest member ledger verifies with every row-shifted table's `shifted_opened` at its gate's public
    /// `shifted_set` (CALIBRATION: at least one table's set is narrower than its width, or this measures nothing; the
    /// pre-C2 proof was 459,181 B, `r4_…bytes_by_part` 2026-11-12 17:10). REFUSED, each on the real door: one next-row
    /// value flipped; one value too many (the length is the set's, one encoding); one value too few; a shift-bind
    /// opening flipped.
    #[test]
    fn c2_a_light_proof_sends_only_the_next_row_columns_its_gates_read_and_every_other_length_is_refused() {
        use crate::whir_rec_block::AirBatchBusBundle;
        let (c, t) = spend_carrier();
        let anchor: [Fa4; DIGEST_LANES] = core::array::from_fn(|k| Fa4::from_u64(t.anchor[k]));
        let rows: Vec<(Option<usize>, u64)> = (0..LEDGER_ROWS).map(|i| ((i == 3).then_some(0), i as u64)).collect();
        let onr = vec![Fa4::from_u64(11); DIGEST_LANES];
        let dsr = vec![Fa4::from_u64(13); DIGEST_LANES];
        let ring = [[Fa4::from_u64(99); DIGEST_LANES], anchor];
        let seed = fresh();
        let (bytes, published, rd) = prove_member_ledger_bytes(&[c], &rows, &ring, &onr, &dsr, seed).expect("honest");
        let sc = crate::slot_ledger::seed_commit_native(seed);
        assert!(verify_member_ledger_bytes(&bytes, &onr, &dsr, sc, &published, &rd), "⛔ the honest C2 member ledger is refused");
        let b: AirBatchBusBundle = postcard::from_bytes(&bytes).expect("a bundle");
        let mut narrower = 0usize;
        for (i, zc) in b.zcs.iter().enumerate() {
            let width = b.shapes[i].1;
            eprintln!("[c2] table {i}: {} column(s), {} next-row opening(s) sent", width, zc.shifted_opened.len());
            if !zc.shifted_opened.is_empty() && zc.shifted_opened.len() < width {
                narrower += 1;
            }
        }
        eprintln!("[c2] member ledger {} B (pre-C2 459,181 B)", bytes.len());
        assert!(narrower >= 1, "CALIBRATION: no row-shifted table sends fewer next-row openings than its width");
        let t = b.zcs.iter().position(|z| !z.shifted_opened.is_empty()).expect("a row-shifted table");
        let refused = |m: &dyn Fn(&mut AirBatchBusBundle)| -> bool {
            let mut x = b.clone();
            m(&mut x);
            let w = postcard::to_allocvec(&x).expect("encodes");
            !verify_member_ledger_bytes(&w, &onr, &dsr, sc, &published, &rd)
        };
        assert!(refused(&|x| x.zcs[t].shifted_opened[0] += Ea4::ONE), "⛔ a flipped next-row value verified");
        assert!(refused(&|x| x.zcs[t].shifted_opened.push(Ea4::ONE)), "⛔ a next-row vector one longer than the set verified");
        assert!(refused(&|x| { x.zcs[t].shifted_opened.pop(); }), "⛔ a next-row vector one shorter than the set verified");
        assert!(refused(&|x| x.shift_binds[0].opened[0] += Ea4::ONE), "⛔ a flipped shift-bind opening verified");
    }

    /// SHAPE FACTS (rule 5d: seconds, no proving) — the layout, shapes and joint ties exist from constants alone, at
    /// the production `LEDGER_ROWS` and the production ring.
    /// R4 MEASUREMENT — where the member ledger's bytes go (it rides every block at a constant shape, one spend or none).
    /// SPEED MEASURE (ignored; run alone): a block's member ledger — a real block-size light proof — proved three times
    /// with the GPU accelerators ON and three times OFF, interleaved in one process so both see the same machine; every
    /// proof verifies. Prints each time, the GPU passes taken, and the medians.
    /// TWO-PARTY-REVIEWED: a prover-side TIMING instrument. The cross-party claim — a peer that never ran the GPU
    /// verifying GPU-made proofs — is the real-node run (lane speed4, 2026-11-12 07:15-08:07: every GPU-made block was
    /// accepted by its peer); here each proof also passes the same native verifier every peer runs.
    #[test]
    #[ignore]
    fn measure_the_member_ledger_proof_with_the_gpu_on_and_off() {
        assert!(crate::gpu_grind::install_blocking().starts_with("on"), "install must succeed on this machine");
        let (c, t) = spend_carrier();
        let anchor: [Fa4; DIGEST_LANES] = core::array::from_fn(|k| Fa4::from_u64(t.anchor[k]));
        let rows: Vec<(Option<usize>, u64)> = (0..LEDGER_ROWS).map(|i| ((i == 3).then_some(0), i as u64)).collect();
        let onr = vec![Fa4::from_u64(11); DIGEST_LANES];
        let dsr = vec![Fa4::from_u64(13); DIGEST_LANES];
        let ring = [[Fa4::from_u64(99); DIGEST_LANES], anchor];
        // every combination of the three parts, interleaved round by round so each sees the same machine
        let configs: [(&str, bool, bool, bool); 5] = [
            ("off", false, false, false),
            ("grind", true, false, false),
            ("merkle", false, true, false),
            ("dft", false, false, true),
            ("all", true, true, true),
        ];
        let mut times: Vec<Vec<f64>> = vec![Vec::new(); configs.len()];
        for round in 0..3 {
            for (k, (name, g, m, d)) in configs.iter().enumerate() {
                crate::gpu_grind::set_parts(*g, *m, *d);
                let (m0, d0) = (crate::gpu_grind::gpu_merkle_passes(), crate::gpu_grind::gpu_dft_passes());
                let seed = fresh();
                let t0 = std::time::Instant::now();
                let (bytes, published, rd) = prove_member_ledger_bytes(&[c.clone()], &rows, &ring, &onr, &dsr, seed).expect("honest");
                let ms = t0.elapsed().as_secs_f64() * 1e3;
                let sc = crate::slot_ledger::seed_commit_native(seed);
                assert!(verify_member_ledger_bytes(&bytes, &onr, &dsr, sc, &published, &rd), "the proof verifies");
                eprintln!(
                    "[gpu-ab] round {round} {name:>6}: {ms:.0} ms, {} bytes, GPU Merkle passes {}, GPU transforms {}",
                    bytes.len(),
                    crate::gpu_grind::gpu_merkle_passes() - m0,
                    crate::gpu_grind::gpu_dft_passes() - d0
                );
                times[k].push(ms);
            }
        }
        crate::gpu_grind::set_enabled(true);
        for (k, (name, ..)) in configs.iter().enumerate() {
            times[k].sort_by(f64::total_cmp);
            eprintln!("[gpu-ab] member ledger median {name:>6}: {:.0} ms", times[k][1]);
        }
    }

    #[test]
    fn r4_the_member_ledger_proof_prints_its_bytes_by_part() {
        let (c, t) = spend_carrier();
        let anchor: [Fa4; DIGEST_LANES] = core::array::from_fn(|k| Fa4::from_u64(t.anchor[k]));
        let rows: Vec<(Option<usize>, u64)> = (0..LEDGER_ROWS).map(|i| ((i == 3).then_some(0), i as u64)).collect();
        let onr = vec![Fa4::from_u64(11); DIGEST_LANES];
        let dsr = vec![Fa4::from_u64(13); DIGEST_LANES];
        let ring = [[Fa4::from_u64(99); DIGEST_LANES], anchor];
        let (bytes, _, _) = prove_member_ledger_bytes(&[c], &rows, &ring, &onr, &dsr, fresh()).expect("honest");
        crate::whir_rec_block::print_light_bundle_breakdown_for_tests("member ledger", &bytes);
    }

    #[test]
    fn the_member_ledger_shape_derives_from_constants_and_fits_the_tie_budget() {
        let layout = member_ledger_layout().expect("member class lays at LEDGER_ROWS");
        assert_eq!(layout.rows(), LEDGER_ROWS);
        let rl = member_ledger_ring().expect("ring");
        assert_eq!(rl.steps(), LEDGER_ROWS);
        let (shapes, bus) = member_ledger_table_shapes(layout).expect("shapes");
        assert_eq!(shapes.len(), T_BUS);
        assert_eq!(bus.len(), 1);
        assert_eq!(shapes[layout.step_table()].1, layout.step_cols() + X_COLS);
        assert_eq!(1usize << shapes[layout.step_table()].0, LEDGER_ROWS);
        // the anchor read is in the absorbed tuple, the zero lane and spend flag in the extension — disjoint
        assert!(layout.tuple_at(2, 0) + DIGEST_LANES <= layout.step_cols());
        let class = ledger_delta_ties_at(layout, DIGEST_LANES, DIGEST_LANES, layout.step_cols() + X_PUB).map(|t| t.1.len());
        let ring = ring_lookup_column_ties(rl, (0, 0, 0, 0), T_MULT, T_RING_CHAIN, T_BUS).map(|t| t.len());
        eprintln!("member ledger: class column ties {class:?} · ring column ties {ring:?} · max {COLUMN_TIES_MAX}");
        // CACHE-ONLY: a test-only count of the circuit's tie groups from constants; no state moves.
        let groups: Vec<(u8, usize)> = [2u8, 4, 8, 16, 32]
            .iter()
            .map(|&m| {
                let n = crate::settlement_delta::settlement_delta_ties_masked(
                    layout,
                    1 + layout.tuple_vals,
                    crate::settlement_delta::DELTA_DOMAIN_OFF,
                    crate::settlement_delta::delta_digest_off(DIGEST_LANES, DIGEST_LANES),
                    m,
                )
                .map_or(usize::MAX, |t| t.1.len());
                (m, n)
            })
            .collect();
        eprintln!(
            "member ledger: class groups (mask, ties) {groups:?} · bound nvars {} per {} · seg_log {} · tuple_vals {}",
            layout.bound.nvars, layout.bound.per, layout.seg_log, layout.tuple_vals
        );
        let (_, all) = ledger_delta_ties_at(layout, DIGEST_LANES, DIGEST_LANES, layout.step_cols() + X_PUB).expect("class");
        let cells = |t: &[ColumnTieSpec]| -> Vec<(usize, usize, usize, usize, usize, usize, usize, usize)> {
            let mut v: Vec<_> = t
                .iter()
                .flat_map(|((t1, c1, l1, r1), (t2, c2, l2, r2))| {
                    c1.iter().zip(c2).map(move |(a, b)| (*t1, *a, *l1, *r1, *t2, *b, *l2, *r2))
                })
                .collect();
            v.sort_unstable();
            v
        };
        let merged = merge_column_ties(all.clone());
        // the merge states every cell equality the class stated, and nothing else
        assert_eq!(cells(&merged), cells(&all), "merging changes no cell pairing");
        eprintln!("member ledger: class ties merged {} of {}", merged.len(), all.len());
        let (_, cols) = member_ledger_ties(layout, DIGEST_LANES, DIGEST_LANES).expect("joint ties fit COLUMN_TIES_MAX");
        let ring_only = ring_lookup_column_ties(rl, (0, 0, 0, 0), T_MULT, T_RING_CHAIN, T_BUS).expect("ring ties").len();
        assert!(cols.len() > ring_only, "the class's ties are present beside the ring's");
        eprintln!("member ledger: step width {} · tables {shapes:?} · bus {bus:?} · column ties {}/{COLUMN_TIES_MAX}", shapes[0].1, cols.len());
    }
}

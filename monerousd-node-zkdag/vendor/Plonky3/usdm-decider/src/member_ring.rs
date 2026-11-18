// Copyright (c) 2026 MonerousD contributors. SPDX-License-Identifier: Apache-2.0

//! MonerousD Protocol — THE MEMBER LEDGER'S RING LOOKUP (§RF-3 spec §12.2 shape (D), lane a, 2026-10-24).
//!
//! ⛔ THE LEAK THIS CLOSES (spec §12): a member-ledger row that publishes the anchor its spend proved membership under
//! splits the padded ledger's rows into "names an anchor a real spend used" and "cover", so the list leaks the real
//! spend count `n`. The anchor therefore never leaves the proof; the block publishes ONE `ring_digest` over the anchor
//! ring every node already holds (`Node::anchor_ring_len_of`, K = 3600 ≤ [`MEMBER_RING_ROWS`]), and each spend row's
//! absorbed anchor is LOOKED UP in that ring inside the proof.
//!
//! §12.2 refuted a one-hot selector (K = 3600 columns per step row). Shape (D), borrowed from LogUp lookups (Haböck
//! 2022, the multiplicity form; this crate's DB-159 post-commit bus):
//!
//! - the RING TABLE is a Poseidon2 sponge chain absorbing one anchor (8 lanes = RATE) per row, its final state the
//!   public `ring_digest` — the `rows_digest` pattern of `settlement_delta` (padding replicates the last anchor, §BW);
//! - the MULT TABLE (`R` rows) carries each ring row's receive multiplicity `negm` (free: the bus balance binds it) and
//!   a SEND lane `(0, anchor, is_spend)`: row `i·2^(L−1)` is step row `i`'s send (a stride tie), every other row's
//!   `is_spend` is forced ZERO by a selector read off the zerocheck's point, so a cover row sends nothing;
//! - the STEP TABLE's rows hold `(0, anchor, is_spend)`, the ledger row's own cells;
//! - ONE LogUp bus `Σ mult / (α − keyfold) = 0` of `2·R` rows: odd row `2j+1` is ring row `j`'s receive, even row `2j`
//!   is the mult table's send lane row `j` (`L = log2(2R/S)`).
//!
//! ⛔⛔⛔ EVERY BUS ROW IS TIED. The bus table is committed in round 2, after α, so a row no column tie reaches is a
//! prover's free choice: a fabricated `(anchor', −1)` there balances a send of an anchor outside the ring. Two ties
//! cover all `2R` rows (odd → receive, even → send lane), and the send lane's selector law closes the rows no step owns;
//! `a_free_bus_row_cannot_balance_a_foreign_anchor` is the adversarial pin. Their free anchor cells carry `mult = 0`,
//! and a key is base-field while α is extension-field, so `α − key ≠ 0` and a zero-mult row contributes nothing.
//!
//! ⛔ WAS one zero-mult tie per off-stride even row: `2^(L−1) − 1` = 31 ties at the production shape — a tie count that
//! tracked the ring-to-ledger ratio, the very growth `COLUMN_TIES_MAX` refuses (MEASURED 2026-10-24: 34 ring ties beside
//! the member class's 63 = 97 > 64). The stride lane states the relation ONCE: 4 ties at any `R/S`.
//!
//! NEW-DOOR CHECKLIST (AGENTS.md §9.6) — this is a sub-statement, not a door; the member ledger's door inherits it:
//! (1) PoW — not here (the block door). (2) the object's proof — [`verify_member_ring_bytes`], WHIR light decider.
//! (3) value creation — none: it moves no value, it proves membership of an already-proven anchor. (4) replay — n/a
//! (the nullifier set refuses a replayed spend). (5) hostile work — the verifier's shapes are the statement's
//! ([`member_ring_shapes`]), checked before any allocation. (6) parity — the anchor binding it replaces was the
//! public per-row anchor of spec §12; the ring digest is recomputed by the peer from its own ring, never read off the
//! wire.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::DIGEST_LANES;
use crate::sponge_chain_air::{SpongeChainConstraint, OUTPUT_OFF, ROW_COLS};
use crate::whir_rec_block::{ColumnTieSpec, CrossTieSpec, EXT_D, PUBLIC_BIND_TABLE};
use p3_field::PrimeCharacteristicRing;

/// The ring table's height — a protocol constant. The node's anchor ring (`anchor_ring_len_of` = max(merge depth cap
/// 3600, spine 64)) must fit; a shorter ring pads by replicating its last anchor, so the shape never names K.
pub const MEMBER_RING_ROWS: usize = 4096;

/// The member ledger's step rows — the note ledger's, row for row (§12.1).
pub const MEMBER_STEP_ROWS: usize = crate::settlement_delta::LEDGER_ROWS;

/// The bind's domain separator ("MRIN"), so a ring digest can never be read as another statement's digest.
pub(crate) const RING_DOMAIN: u64 = 0x4d52_494e;
const RING_DIGEST_OFF: usize = 1;

// Step table columns (in the member ledger these are the step table's own cells; standalone they are the whole row).
pub const S_ZERO: usize = 0;
pub const S_ANCHOR: usize = 1;
pub const S_SPEND: usize = S_ANCHOR + DIGEST_LANES;
pub const S_COLS: usize = S_SPEND + 1;
// Mult table columns: zero | negm | the send lane's anchor | the send lane's is_spend.
const M_ZERO: usize = 0;
const M_NEGM: usize = 1;
const M_SANCHOR: usize = 2;
const M_SSPEND: usize = M_SANCHOR + DIGEST_LANES;
const M_COLS: usize = M_SSPEND + 1;
// Bus table columns: idx | val[DIGEST_LANES] | mult (the decider appends h[EXT_D]).
const B_IDX: usize = 0;
const B_VAL: usize = 1;
const B_MULT: usize = B_VAL + DIGEST_LANES;

/// The standalone statement's tables, in commit order (indices, not counts).
#[derive(Clone, Copy)]
enum Tab {
    Step,
    Mult,
    Chain,
    Bus,
}

impl Tab {
    const fn at(self) -> usize {
        self as usize
    }
}

/// The lookup's shape: step rows `2^s_log`, ring rows `2^r_log`, `s_log ≤ r_log`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingLayout {
    pub s_log: usize,
    pub r_log: usize,
}

impl RingLayout {
    /// The production shape: the ledger's step rows against the protocol ring.
    #[must_use]
    pub fn production() -> Option<Self> {
        Self::new(MEMBER_STEP_ROWS, MEMBER_RING_ROWS)
    }
    #[must_use]
    pub fn new(steps: usize, ring: usize) -> Option<Self> {
        if !steps.is_power_of_two() || !ring.is_power_of_two() || steps > ring || steps < 2 {
            return None;
        }
        Some(Self { s_log: steps.trailing_zeros() as usize, r_log: ring.trailing_zeros() as usize })
    }
    #[must_use]
    pub fn steps(&self) -> usize {
        1 << self.s_log
    }
    #[must_use]
    pub fn ring(&self) -> usize {
        1 << self.r_log
    }
    /// Low bits of a bus row that place a step send: the bus is `2R` rows, the step table `S`.
    #[must_use]
    pub fn send_low_bits(&self) -> usize {
        self.r_log + 1 - self.s_log
    }
    /// Low bits of a mult-table row that place a step send (the stride): `R / S = 2^stride_bits`.
    #[must_use]
    pub fn stride_bits(&self) -> usize {
        self.r_log - self.s_log
    }
}

/// The per-table circuit.
pub enum MemberRingAir {
    /// `zero == 0`, `is_spend ∈ {0,1}`; the anchor is bound by the bus and the member ledger's own ties.
    Step { gamma: Ea4 },
    /// `zero == 0`; `negm` is bound by the bus balance; `(1 − on_stride(x)) · s_spend == 0`, `on_stride` the indicator
    /// that the point's low `stride_bits` variables are zero — a function of the POINT, nothing a prover chooses.
    /// `law = false` exists for ONE calibration pin only (the free-row forgery verifies without it).
    Mult { gamma: Ea4, stride_bits: usize, law: bool },
    /// The ring's sponge chain, ending at the public `ring_digest`.
    Chain(SpongeChainConstraint),
}

impl AirConstraint for MemberRingAir {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Step { .. } => 2,
            // The selector is multilinear in the point (one factor per LOW variable), times one cell: degree 2 in each
            // low variable. The degree census walks `x[0]` (the high variable) and so reads 1 here; the low rounds
            // are the ones the selector lifts. MEASURED 2026-10-24: declared 1, the honest lookup fails to verify.
            Self::Mult { law: true, .. } => 2,
            Self::Mult { law: false, .. } => 1,
            Self::Chain(c) => c.degree(nvars),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Step { gamma } => {
                let s = local[S_SPEND];
                local[S_ZERO] + *gamma * s * (Ea4::ONE - s)
            }
            Self::Mult { gamma, stride_bits, law } => {
                if !*law {
                    return local[M_ZERO];
                }
                // `x[last]` is the row index's LOW bit (`x[0]` the high one, as `Blinded` reads it).
                let mut on_stride = Ea4::ONE;
                for &xk in x.iter().rev().take(*stride_bits) {
                    on_stride *= Ea4::ONE - xk;
                }
                local[M_ZERO] + *gamma * (Ea4::ONE - on_stride) * local[M_SSPEND]
            }
            Self::Chain(c) => c.eval(local, at, x),
        }
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        match self {
            Self::Step { .. } => Some((S_ANCHOR..S_ANCHOR + DIGEST_LANES).collect()),
            // The lane's anchor and `is_spend` are the step's own cells on stride rows (the stride tie; the step gate
            // forces the bit), so no law of THIS gate reads them there; off them the anchor carries `mult = 0` and the
            // stride law forces `is_spend` to zero.
            Self::Mult { .. } => Some(
                std::iter::once(M_NEGM).chain(M_SANCHOR..M_SANCHOR + DIGEST_LANES).chain(std::iter::once(M_SSPEND)).collect(),
            ),
            Self::Chain(c) => c.free_columns(),
        }
    }
    fn is_row_local(&self) -> bool {
        match self {
            Self::Chain(c) => c.is_row_local(),
            _ => true,
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            Self::Chain(c) => c.shifted_cols(),
            _ => Some(Vec::new()),
        }
    }
}

/// The factory BOTH sides derive from public parameters alone.
pub fn make_member_ring_constraint(layout: RingLayout) -> impl Fn(usize, Ea4) -> MemberRingAir + Clone {
    make_member_ring_constraint_with(layout, true)
}

fn make_member_ring_constraint_with(layout: RingLayout, law: bool) -> impl Fn(usize, Ea4) -> MemberRingAir + Clone {
    let chain = crate::sponge_chain_air::make_constraint_with_seed(crate::committed_air::COMMITTED_AIR_SEED, Fa4::ZERO);
    let stride_bits = layout.stride_bits();
    move |table: usize, gamma: Ea4| {
        if table == Tab::Step.at() {
            MemberRingAir::Step { gamma }
        } else if table == Tab::Mult.at() {
            MemberRingAir::Mult { gamma, stride_bits, law }
        } else {
            // The chain carries no squeezes, so its fold stays zero (the `rows_digest` chain's shape).
            MemberRingAir::Chain(chain(gamma))
        }
    }
}

/// The ring padded to the layout: replicate the last anchor (§BW). `None` on an empty or oversized ring.
fn padded_ring(anchors: &[[Fa4; DIGEST_LANES]], layout: RingLayout) -> Option<Vec<Vec<Fa4>>> {
    if anchors.is_empty() || anchors.len() > layout.ring() {
        return None;
    }
    Some((0..layout.ring()).map(|j| anchors[j.min(anchors.len() - 1)].to_vec()).collect())
}

/// The ring's sponge table and its final state. One duplexing per anchor, so row `j` absorbed anchor `j`.
fn ring_chain(anchors: &[[Fa4; DIGEST_LANES]], layout: RingLayout) -> Option<(Vec<Vec<Fa4>>, Vec<Fa4>)> {
    let padded = padded_ring(anchors, layout)?;
    let rows = layout.ring();
    let seed = crate::committed_air::COMMITTED_AIR_SEED;
    let steps = crate::sponge_chain_air::replay_with_seed(seed, &padded, &vec![0usize; rows]);
    if steps.len() != rows {
        return None; // fail-closed: the ties assume one duplexing per ring row
    }
    let (cols, _zero_fold) = crate::sponge_chain_air::build_trace_with_seed(seed, &steps, rows);
    let digest = (0..DIGEST_LANES).map(|j| cols[OUTPUT_OFF + j][rows - 1]).collect();
    Some((cols, digest))
}

/// PEER and PRODUCER — the ONE definition of the ring digest (the node computes it from its own ring with this): the last
/// duplexing's output over the padded ring, the cells [`ring_chain`]'s trace lays at row `rows − 1` (lanes `OUTPUT_OFF..`).
/// Read straight off the replay, never by laying every round's columns to read one row. MEASURED (stable/relay2.sample.txt):
/// the trace build under `ring_chain` held ~1,360 of a node step's samples on the member door. Equality with the trace
/// form is pinned (`the_native_ring_digest_is_the_one_the_trace_lays` and every prove test's digest check).
/// cons: none — the same value, no state.
#[must_use]
pub fn ring_digest_of(anchors: &[[Fa4; DIGEST_LANES]], layout: RingLayout) -> Option<Vec<Fa4>> {
    let padded = padded_ring(anchors, layout)?;
    let rows = layout.ring();
    let steps = crate::sponge_chain_air::replay_with_seed(crate::committed_air::COMMITTED_AIR_SEED, &padded, &vec![0usize; rows]);
    if steps.len() != rows {
        return None; // the same fail-closed shape as `ring_chain`
    }
    let last = steps.last()?;
    Some((0..DIGEST_LANES).map(|j| last.output[j]).collect())
}

fn member_ring_bind(ring_digest: &[Fa4]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(RING_DOMAIN)];
    b.extend_from_slice(ring_digest);
    b
}

/// The ring row's absorbed cells, read from the transcript planner rather than assumed.
fn absorb_cols(layout: RingLayout) -> Option<Vec<usize>> {
    let rows = layout.ring();
    let (absorbed, _sq, steps) =
        crate::transcript_bind_air::plan(&vec![DIGEST_LANES; rows], &vec![0usize; rows])?;
    if steps != rows || absorbed.len() < DIGEST_LANES {
        return None;
    }
    let first: Vec<(usize, usize)> = absorbed.iter().take(DIGEST_LANES).copied().collect();
    if first.iter().any(|&(r, _)| r != 0) {
        return None;
    }
    Some(first.into_iter().map(|(_, c)| c).collect())
}

/// ⛔⛔⛔ THE TIES THAT WELD EVERY BUS ROW. Odd rows → the ring (mult table's receive + chain absorb cells); even rows
/// → the mult table's send lane; the lane's stride rows `i·2^(L−1)` → step row `i`'s `zero | anchor | is_spend`. `step`
/// names the step table and those columns, so the member ledger reuses this with its own indices. Four ties at any
/// ring-to-ledger ratio.
#[must_use]
pub fn ring_lookup_column_ties(
    layout: RingLayout,
    step: (usize, usize, usize, usize),
    mult: usize,
    chain: usize,
    bus: usize,
) -> Option<Vec<ColumnTieSpec>> {
    let (st, s_zero, s_anchor, s_spend) = step;
    if layout.send_low_bits() == 0 {
        return None;
    }
    let mut bus_send = vec![B_IDX];
    bus_send.extend(B_VAL..B_VAL + DIGEST_LANES);
    bus_send.push(B_MULT);
    let mut lane = vec![M_ZERO];
    lane.extend(M_SANCHOR..M_SANCHOR + DIGEST_LANES);
    lane.push(M_SSPEND);
    let mut step_send = vec![s_zero];
    step_send.extend(s_anchor..s_anchor + DIGEST_LANES);
    step_send.push(s_spend);
    let ties: Vec<ColumnTieSpec> = vec![
        ((bus, bus_send, 1, 0), (mult, lane.clone(), 0, 0)),
        ((mult, lane, layout.stride_bits(), 0), (st, step_send, 0, 0)),
        ((bus, vec![B_IDX, B_MULT], 1, 1), (mult, vec![M_ZERO, M_NEGM], 0, 0)),
        ((bus, (B_VAL..B_VAL + DIGEST_LANES).collect(), 1, 1), (chain, absorb_cols(layout)?, 0, 0)),
    ];
    (ties.len() <= crate::whir_rec_block::COLUMN_TIES_MAX).then_some(ties)
}

fn standalone_ties(layout: RingLayout) -> Option<Vec<ColumnTieSpec>> {
    ring_lookup_column_ties(layout, (Tab::Step.at(), S_ZERO, S_ANCHOR, S_SPEND), Tab::Mult.at(), Tab::Chain.at(), Tab::Bus.at())
}

fn member_ring_cross_ties(layout: RingLayout) -> Vec<CrossTieSpec> {
    member_ring_cross_ties_at(layout, Tab::Chain.at(), RING_DIGEST_OFF)
}

/// THE ONE RING-DIGEST TIE SITE: the chain table's last row output (lanes `OUTPUT_OFF..`) equals the public bind's
/// `ring_digest` at `bind_off` — standalone at [`RING_DIGEST_OFF`], inside the member ledger past the ledger's bind.
pub(crate) fn member_ring_cross_ties_at(layout: RingLayout, chain_table: usize, bind_off: usize) -> Vec<CrossTieSpec> {
    let last = layout.ring() - 1;
    (0..DIGEST_LANES)
        .map(|j| ((chain_table, vec![OUTPUT_OFF + j], last), (PUBLIC_BIND_TABLE, vec![bind_off + j], 0usize)))
        .collect()
}

/// The statement's table shapes `(nvars, width)`: constraint tables, then the bus.
#[must_use]
pub fn member_ring_shapes(layout: RingLayout) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let bus_nv = (layout.r_log + 1).max(crate::whir_rec_block::REC_DECIDER_FOLDING);
    (
        vec![(layout.s_log, S_COLS), (layout.r_log, M_COLS), (layout.r_log, ROW_COLS)],
        vec![(bus_nv, 2 + DIGEST_LANES + EXT_D)],
    )
}

pub(crate) type TiedBus = (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>);

/// The honest bus: ring receives with `negm = −(sends of that anchor)` on its FIRST ring row, step sends gated by
/// `is_spend`, zero elsewhere. `None` when a spend's anchor is not in the ring (the producer refuses; it never lays a
/// lookup that cannot balance).
fn honest_bus(layout: RingLayout, ring: &[Vec<Fa4>], steps: &[([Fa4; DIGEST_LANES], bool)]) -> Option<(Vec<Fa4>, TiedBus)> {
    let mut negm = vec![Fa4::ZERO; layout.ring()];
    for (a, s) in steps {
        if *s {
            let j = ring.iter().position(|r| r.as_slice() == a.as_slice())?;
            negm[j] -= Fa4::ONE;
        }
    }
    let n = 2 * layout.ring();
    let l = layout.send_low_bits();
    let idx = vec![Fa4::ZERO; n];
    let mut vals = vec![vec![Fa4::ZERO; n]; DIGEST_LANES];
    let mut mult = vec![Fa4::ZERO; n];
    for (j, r) in ring.iter().enumerate() {
        for k in 0..DIGEST_LANES {
            vals[k][2 * j + 1] = r[k];
        }
        mult[2 * j + 1] = negm[j];
    }
    for (i, (a, s)) in steps.iter().enumerate() {
        let row = i << l;
        for k in 0..DIGEST_LANES {
            vals[k][row] = a[k];
        }
        mult[row] = if *s { Fa4::ONE } else { Fa4::ZERO };
    }
    Some((negm, (idx, vals, mult)))
}

pub(crate) fn member_ring_tables(
    layout: RingLayout,
    anchors: &[[Fa4; DIGEST_LANES]],
    steps: &[([Fa4; DIGEST_LANES], bool)],
) -> Option<(Vec<Vec<Vec<Fa4>>>, TiedBus, Vec<Fa4>)> {
    if steps.len() != layout.steps() {
        return None;
    }
    let (chain, digest) = ring_chain(anchors, layout)?;
    let ring = padded_ring(anchors, layout)?;
    let (negm, bus) = honest_bus(layout, &ring, steps)?;
    let mut step = vec![vec![Fa4::ZERO; layout.steps()]; S_COLS];
    for (i, (a, s)) in steps.iter().enumerate() {
        for k in 0..DIGEST_LANES {
            step[S_ANCHOR + k][i] = a[k];
        }
        step[S_SPEND][i] = if *s { Fa4::ONE } else { Fa4::ZERO };
    }
    let mut mult = vec![vec![Fa4::ZERO; layout.ring()]; M_COLS];
    mult[M_NEGM] = negm;
    for (i, (a, s)) in steps.iter().enumerate() {
        let j = i << layout.stride_bits();
        for k in 0..DIGEST_LANES {
            mult[M_SANCHOR + k][j] = a[k];
        }
        mult[M_SSPEND][j] = if *s { Fa4::ONE } else { Fa4::ZERO };
    }
    Some((vec![step, mult, chain], bus, digest))
}

fn prove_raw(layout: RingLayout, tables: Vec<Vec<Vec<Fa4>>>, bus: TiedBus, ring_digest: &[Fa4]) -> Option<Vec<u8>> {
    crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_member_ring_constraint(layout),
        vec![bus],
        member_ring_cross_ties(layout),
        standalone_ties(layout)?,
        &member_ring_bind(ring_digest),
    )
}

/// PRODUCER — prove every `is_spend` step's anchor is in the ring. Returns the proof and the `ring_digest` a peer
/// recomputes from its own ring. `steps` is the ledger's full padded row list (cover rows carry `false`).
#[must_use]
pub fn prove_member_ring_bytes(
    layout: RingLayout,
    anchors: &[[Fa4; DIGEST_LANES]],
    steps: &[([Fa4; DIGEST_LANES], bool)],
) -> Option<(Vec<u8>, Vec<Fa4>)> {
    let (tables, bus, digest) = member_ring_tables(layout, anchors, steps)?;
    let bytes = prove_raw(layout, tables, bus, &digest)?;
    Some((bytes, digest))
}

/// PEER — verify against the ring digest the peer computed from its OWN ring ([`ring_digest_of`]).
#[must_use]
pub fn verify_member_ring_bytes(bytes: &[u8], layout: RingLayout, ring_digest: &[Fa4]) -> bool {
    if bytes.is_empty() || ring_digest.len() != DIGEST_LANES {
        return false;
    }
    let Some(cols) = standalone_ties(layout) else { return false };
    let (shapes, bus_shapes) = member_ring_shapes(layout);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_member_ring_constraint(layout),
        member_ring_cross_ties(layout),
        cols,
        &member_ring_bind(ring_digest),
        &shapes,
        &bus_shapes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(seed: u64) -> [Fa4; DIGEST_LANES] {
        core::array::from_fn(|k| Fa4::from_u64(seed * 1_000 + k as u64 + 7))
    }

    fn layout() -> RingLayout {
        RingLayout::production().expect("production layout")
    }

    /// The node's ring at its production length (merge depth cap 3600), padded by the layout to 4096.
    fn ring() -> Vec<[Fa4; DIGEST_LANES]> {
        (0..3600u64).map(|j| anchor(j + 1)).collect()
    }

    /// `spends` names the ring index each real spend proved under; the rest of the ledger's rows are cover.
    fn steps(ring: &[[Fa4; DIGEST_LANES]], spends: &[usize]) -> Vec<([Fa4; DIGEST_LANES], bool)> {
        (0..layout().steps())
            .map(|i| match spends.get(i) {
                Some(&j) => (ring[j], true),
                None => (anchor(90_000 + i as u64), false), // a cover row's absorbed cells: anything, sent with 0
            })
            .collect()
    }

    /// The round-2 forgery laid so every TIE holds: step row 0 and the lane's stride row 0 send `(foreign, 1)`, the
    /// lane's off-stride row 1 (bus row 2) receives `(foreign, −1)`. Only the lane's selector law can refuse it.
    fn forge_free_row(tables: &mut [Vec<Vec<Fa4>>], vals: &mut [Vec<Fa4>], mult: &mut [Fa4], foreign: [Fa4; DIGEST_LANES]) {
        for k in 0..DIGEST_LANES {
            tables[Tab::Step.at()][S_ANCHOR + k][0] = foreign[k];
            tables[Tab::Mult.at()][M_SANCHOR + k][0] = foreign[k];
            tables[Tab::Mult.at()][M_SANCHOR + k][1] = foreign[k];
            vals[k][0] = foreign[k];
            vals[k][2] = foreign[k];
        }
        tables[Tab::Step.at()][S_SPEND][0] = Fa4::ONE;
        tables[Tab::Mult.at()][M_SSPEND][0] = Fa4::ONE;
        tables[Tab::Mult.at()][M_SSPEND][1] = -Fa4::ONE;
        mult[0] = Fa4::ONE;
        mult[2] = -Fa4::ONE;
    }

    fn rejects(tables: Vec<Vec<Vec<Fa4>>>, bus: TiedBus, d: &[Fa4]) -> bool {
        prove_raw(layout(), tables, bus, d).map_or(true, |b| !verify_member_ring_bytes(&b, layout(), d))
    }

    /// Shape facts, no proving: the production layout's tie count fits the cap and every bus row's mult is tied once.
    #[test]
    fn production_layout_ties_every_bus_row_once() {
        let layout = layout();
        assert_eq!(layout.ring(), MEMBER_RING_ROWS);
        assert!(3600 <= layout.ring(), "the node's ring (merge depth cap 3600) must fit");
        let ties = standalone_ties(layout).expect("ties");
        assert!(ties.len() <= crate::whir_rec_block::COLUMN_TIES_MAX, "{} ties", ties.len());
        let n = 2 * layout.ring();
        let mut hit = vec![0u32; n];
        assert_eq!(ties.len(), 4, "the lookup states each relation once, at any R/S");
        for ((t, cols, low_bits, low_row), _) in &ties {
            if *t != Tab::Bus.at() {
                assert_eq!(*t, Tab::Mult.at(), "the one non-bus tie is the send lane's stride");
                continue;
            }
            if !cols.contains(&B_MULT) {
                continue; // a values-only tie re-covers rows whose mult another tie binds
            }
            for (row, h) in hit.iter_mut().enumerate() {
                if row & ((1 << low_bits) - 1) == *low_row {
                    *h += 1;
                }
            }
        }
        assert!(hit.iter().all(|&h| h == 1), "every bus row's mult is tied exactly once");
    }

    /// ⭐ SOUND IS MEASURED: the mult gate (the stride law reads the POINT) and the step gate under the crate's three
    /// structural censuses on the honest tables — degree measured, every column bound or named free, no decorative block.
    #[test]
    fn the_ring_step_and_mult_gates_pass_the_three_censuses() {
        let r = ring();
        let (tables, _bus, _d) = member_ring_tables(layout(), &r, &steps(&r, &[5, 9])).expect("tables");
        let make = make_member_ring_constraint(layout());
        for (t, nvars) in [(Tab::Step.at(), layout().s_log), (Tab::Mult.at(), layout().r_log)] {
            let gate = make(t, Ea4::from(Fa4::from_u64(0x4d52)));
            let cols = &tables[t];
            crate::air_zerocheck::debug_degree_census(cols, &gate, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_free_witness_census(cols, &gate, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_decorative_block_census(cols, &gate, nvars, true, &Some(Vec::new()));
        }
    }

    /// ⭐ PERF EQUALITY (lane stable 2026-11-01) — the native digest equals the trace's last-row output on the production
    /// layout, for a full ring, a short ring (padded by the layout) and a one-anchor ring; a changed anchor changes it.
    #[test]
    fn the_native_ring_digest_is_the_one_the_trace_lays() {
        for len in [3600usize, 17, 1] {
            let r: Vec<[Fa4; DIGEST_LANES]> = (0..len as u64).map(|j| anchor(j + 3)).collect();
            let native = ring_digest_of(&r, layout()).expect("a digest");
            let (_, traced) = ring_chain(&r, layout()).expect("the trace digest");
            assert_eq!(native, traced, "⛔ the native ring digest differs from the trace's at ring length {len}");
            let mut planted = r.clone();
            planted[len - 1] = anchor(424_242);
            assert_ne!(ring_digest_of(&planted, layout()).expect("a digest"), native, "CALIBRATION: a changed anchor changes the digest");
        }
    }

    #[test]
    fn honest_lookups_verify_at_zero_one_and_three_spends() {
        let r = ring();
        for spends in [vec![], vec![5usize], vec![3, 3, 3599]] {
            let (bytes, digest) = prove_member_ring_bytes(layout(), &r, &steps(&r, &spends)).expect("honest prove");
            assert_eq!(Some(digest.clone()), ring_digest_of(&r, layout()));
            assert!(verify_member_ring_bytes(&bytes, layout(), &digest), "honest lookup ({spends:?}) must verify");
        }
    }

    /// ⭐ R4 lever 4 — TWO member-ring statements (two rings, two spend sets) proved as ONE light-decider batch
    /// (`light_batch_merge`): the joined proof verifies against both statements in order and is smaller than the two
    /// proofs apart; and it is refused against the statements swapped, the first alone, a ring digest the peer does not
    /// hold for the second half, and a forged second half (a free-row foreign anchor) under an honest first.
    #[test]
    fn r4_two_member_ring_statements_prove_as_one_batch_and_every_half_is_still_bound() {
        use crate::light_batch_merge::{prove_joined, verify_joined, BoxedConstraint, LaidStatement, MakeConstraint, StatedStatement};
        let l = layout();
        let make = || -> MakeConstraint<'static> {
            Box::new(move |t, e| -> BoxedConstraint<'static> { Box::new(make_member_ring_constraint(l)(t, e)) })
        };
        let laid = |tables: Vec<Vec<Vec<Fa4>>>, bus: TiedBus, d: &[Fa4]| LaidStatement {
            tables,
            make: make(),
            buses: vec![bus],
            cross: member_ring_cross_ties(l),
            cols: standalone_ties(l).expect("ties"),
            joint: Vec::new(),
            bind: member_ring_bind(d),
        };
        let stated = |d: &[Fa4]| {
            let (constraint_shapes, bus_shapes) = member_ring_shapes(l);
            StatedStatement {
                make: make(),
                cross: member_ring_cross_ties(l),
                cols: standalone_ties(l).expect("ties"),
                joint: Vec::new(),
                bind: member_ring_bind(d),
                constraint_shapes,
                bus_shapes,
            }
        };
        let r1 = ring();
        let mut r2 = ring();
        r2[1717] = anchor(777_777);
        let (t1, b1, d1) = member_ring_tables(l, &r1, &steps(&r1, &[5])).expect("tables");
        let (t2, b2, d2) = member_ring_tables(l, &r2, &steps(&r2, &[3, 3599])).expect("tables");
        assert_ne!(d1, d2, "CALIBRATION: two rings, two digests");
        let joined = prove_joined(vec![laid(t1, b1, &d1), laid(t2, b2, &d2)]).expect("the joined batch proves");
        let (a, _) = prove_member_ring_bytes(l, &r1, &steps(&r1, &[5])).expect("first alone");
        let (b, _) = prove_member_ring_bytes(l, &r2, &steps(&r2, &[3, 3599])).expect("second alone");
        eprintln!("[light-merge] two member-ring proofs apart: {} + {} = {} B; joined: {} B", a.len(), b.len(), a.len() + b.len(), joined.len());
        assert!(joined.len() < a.len() + b.len(), "the joined batch shares its WHIR rounds");
        assert!(verify_joined(&joined, vec![stated(&d1), stated(&d2)]), "the joined proof verifies against both statements");
        assert!(!verify_joined(&joined, vec![stated(&d2), stated(&d1)]), "⛔ the statements in another order");
        assert!(!verify_joined(&joined, vec![stated(&d1)]), "⛔ the first statement alone");
        let mut r3 = ring();
        r3[42] = anchor(4_242);
        let theirs = ring_digest_of(&r3, l).expect("digest");
        assert!(!verify_joined(&joined, vec![stated(&d1), stated(&theirs)]), "⛔ a ring digest the peer does not hold for the second half");
        let (t1, b1, d1) = member_ring_tables(l, &r1, &steps(&r1, &[5])).expect("tables");
        let (mut tf, (idx, mut vals, mut mult), df) = member_ring_tables(l, &r2, &steps(&r2, &[])).expect("tables");
        forge_free_row(&mut tf, &mut vals, &mut mult, anchor(4_242_424));
        let forged = prove_joined(vec![laid(t1, b1, &d1), laid(tf, (idx, vals, mult), &df)]);
        assert!(
            forged.map_or(true, |f| !verify_joined(&f, vec![stated(&d1), stated(&df)])),
            "⛔ a forged second half was carried by an honest first"
        );
    }

    #[test]
    fn a_ring_digest_the_peer_does_not_hold_is_refused() {
        let r = ring();
        let (bytes, _) = prove_member_ring_bytes(layout(), &r, &steps(&r, &[2])).expect("honest prove");
        let mut other = r.clone();
        other[1717] = anchor(777_777);
        let theirs = ring_digest_of(&other, layout()).expect("digest");
        assert!(!verify_member_ring_bytes(&bytes, layout(), &theirs));
    }

    #[test]
    fn an_anchor_outside_the_ring_is_refused() {
        let r = ring();
        let mut st = steps(&r, &[4]);
        st[0].0 = anchor(5_555_555);
        assert!(prove_member_ring_bytes(layout(), &r, &st).is_none(), "the producer refuses");
        // A prover that lays it anyway (the ring receive still names ring[4]) cannot balance the bus.
        let (mut tables, (idx, mut vals, mult), d) = member_ring_tables(layout(), &r, &steps(&r, &[4])).expect("tables");
        for k in 0..DIGEST_LANES {
            tables[Tab::Step.at()][S_ANCHOR + k][0] = anchor(5_555_555)[k];
            tables[Tab::Mult.at()][M_SANCHOR + k][0] = anchor(5_555_555)[k];
            vals[k][0] = anchor(5_555_555)[k];
        }
        assert!(rejects(tables, (idx, vals, mult), &d));
    }

    /// ⛔ The round-2 forgery: send a foreign anchor and balance it with a receive on an even row no step owns.
    #[test]
    fn a_free_bus_row_cannot_balance_a_foreign_anchor() {
        let r = ring();
        let (mut tables, (idx, mut vals, mut mult), d) = member_ring_tables(layout(), &r, &steps(&r, &[])).expect("tables");
        let foreign = anchor(4_242_424);
        forge_free_row(&mut tables, &mut vals, &mut mult, foreign);
        assert!(rejects(tables, (idx, vals, mult), &d));
    }

    /// REFUTATION BEFORE GREEN: the SAME forgery, proved and verified with the lane's selector law left out, is
    /// ACCEPTED — so the refusal above is the law's doing, not an accident of the fixture.
    #[test]
    fn calibration_the_free_row_forgery_verifies_without_the_stride_law() {
        let r = ring();
        let (mut tables, (idx, mut vals, mut mult), d) = member_ring_tables(layout(), &r, &steps(&r, &[])).expect("tables");
        let foreign = anchor(4_242_424);
        forge_free_row(&mut tables, &mut vals, &mut mult, foreign);
        let open = standalone_ties(layout()).expect("ties");
        let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables,
            make_member_ring_constraint_with(layout(), false),
            vec![(idx, vals, mult)],
            member_ring_cross_ties(layout()),
            open.clone(),
            &member_ring_bind(&d),
        )
        .expect("the forgery proves");
        let (shapes, bus_shapes) = member_ring_shapes(layout());
        assert!(
            crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &bytes,
                make_member_ring_constraint_with(layout(), false),
                member_ring_cross_ties(layout()),
                open,
                &member_ring_bind(&d),
                &shapes,
                &bus_shapes,
            ),
            "without the stride law a foreign anchor balances on a free row"
        );
    }

    #[test]
    fn a_non_boolean_spend_bit_is_refused() {
        let r = ring();
        let (mut tables, (idx, vals, mut mult), d) = member_ring_tables(layout(), &r, &steps(&r, &[6])).expect("tables");
        // is_spend = 2 with the ring receive doubled: balanced, but not a bit.
        tables[Tab::Step.at()][S_SPEND][0] = Fa4::from_u64(2);
        mult[0] = Fa4::from_u64(2);
        tables[Tab::Mult.at()][M_NEGM][6] = -Fa4::from_u64(2);
        tables[Tab::Mult.at()][M_SSPEND][0] = Fa4::from_u64(2);
        mult[2 * 6 + 1] = -Fa4::from_u64(2);
        assert!(rejects(tables, (idx, vals, mult), &d));
    }
}

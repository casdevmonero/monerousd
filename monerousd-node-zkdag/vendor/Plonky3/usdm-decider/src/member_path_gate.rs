// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-223 — THE MEMBER-PATH CLASS: a block PROVES every spend input EXISTS under an anchor it names.
//!
//! READ. A spend's validity carrier proves the spend is well-formed; nothing in the block proved that its INPUT
//! note sits under an anchor the chain holds — the block took the wallet's anchor at its word (DB-223: "a block
//! must prove its inputs exist"). This class closes that. The WALLET proves one membership statement per input: the
//! full spend-tree path ([`MEMBER_PATH_DEPTH`] levels, the production `SPEND_TREE_DEPTH`) refolds the note's leaf to
//! the anchor, and the leaf commitment `H(leaf ‖ binder)` ties the statement to ONE spend (the binder is the spend's
//! nullifier) — as a blinded committed carrier (`committed_air::prove_air_blinded_bytes`, the leaf and every sibling
//! private). The BLOCK folds every such carrier into ONE settlement-delta aggregate beside its note transition
//! (`settlement_delta`), the fourth class beside the single spend, the spend-or-decoy and the bond. A peer verifies
//! the aggregate against the block's tuple list and never sees a path, a leaf or a sibling.
//!
//! THE STATEMENT (one per input, [`MemberTuple`]): `MEMBER_PATH_DOMAIN ‖ leaf_commit ‖ binder ‖ anchor ‖ outs` —
//! FOUR digests, so the chain strides a carrier's tuple at a power of two duplexings
//! (`settlement_delta::chain_stride_is_exact`; MEASURED 2026-09-27: a three-digest tuple proved and its honest
//! aggregate did NOT verify — every carrier after the first was checked at the wrong chain rows). `outs` is the
//! digest of the spend's outputs, so one statement ties input membership AND the outputs it may lay (DB-315's slot).
//!
//! THE GATE ([`MemberPathGate`]) is `note_membership_air`'s one-step relation over the full path, with the three
//! properties a block-level class needs, each named by the defect it avoids:
//! 1. its boundary masks read the DATA half of the point (`x[1..]`): the carrier is BLINDED, so the trace doubles
//!    and `x[0]` selects the random half — a mask over all of `x` would put the root weld on a random row;
//! 2. `residuals()` is UNFOLDED: the aggregate lays one γ-power cell per residual (a folded single value would drop
//!    every residual after the first — the DB-83 blocker `CoverOrSpendGate::build_residuals` records);
//! 3. `shifted_cols()` declares the rotated run `ACC_IN ‖ ACC_OUT ‖ DIR ‖ ACTIVE ‖ WLEAF` the chain link reads, so
//!    the aggregate lays exactly that rotation ([`member_shifted_run`], ONE definition for gate and layout).
//!
//! §9.6 NEW-DOOR ANSWERS (the aggregate is verified where the block's other transitions are; this class adds no
//! door of its own). 1 PoW — the header's, unchanged. 2 Proof — the aggregate is a WHIR-verified settlement delta
//! whose per-row inner gate is this class's; every wallet carrier inside it was proved against the same gate and is
//! re-verified by the aggregate's bound step. 3 Conservation — this class creates no value; it REFUSES a spend whose
//! input is under no anchor the block names. 4 Replay — `leaf_commit = H(leaf ‖ binder)` with the spend's nullifier
//! as binder binds a carrier to ONE spend, and the nullifier set refuses that spend's second use. 5 Bounded work —
//! `DELTA_FIXED_SLOTS` rows, constant; the layout is rebuilt from `n` alone by [`member_class_shape`] and any other
//! shape is refused before allocation (DB-213b). 6 Parity with the bond class
//! (`settlement_delta::prove_block_bond_transition`): class-fixed shape ✓, tuple width restated from the class ✓,
//! rotated run restated from the class (the cover class's rule) ✓, producer fail-closed on a shape its class does not
//! fix ✓, `rows_digest` recomputed by the peer ✓, one named depth for the class ✓ (the bond takes its depth as an
//! argument; this class has exactly one tree to walk).
//!
//! ROOT-LAYER: the trace is `note_membership_air::member_path_cols` (one builder for the 8-row block step and the
//! [`MEMBER_PATH_DEPTH`]-row spend path); the domain, the tuple width and the rotated run are constants of this
//! file and read nowhere else. MEASURED 2026-09-28 (pins below): the control verifies through the production door
//! at the committed 256 slots; a forged digest, a re-pointed anchor, a broken path and every wire-shape tamper are
//! refused; no byte of a carrier or of an aggregate is free. MUST-STAY-GREEN: `member_path_gate::tests::*` and
//! `settlement_delta`'s chain-stride pin.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::committed_air::Blinded;
use crate::hiding_decider::{Ea4, Fa4};
use crate::note_membership_air::{
    member_path_cols, note_leaf_commitment, refold_in_block, MEMBER_STEP_SHAPE, MS_ACC_IN, MS_ACC_OUT, MS_ACTIVE,
    MS_BLIND, MS_COMMIT, MS_COMMIT2, MS_DIR, MS_FOLD, MS_SIB, MS_WLEAF,
};
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::recursion_bound::BoundLayout;
use crate::settlement_delta::{
    delta_layout, delta_prove, delta_residual_count, delta_verify, shape_of_layout, DeltaLayout, DeltaShape,
    DELTA_FIXED_SLOTS,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// This class's domain tag ("NM_PATH3"): distinct from the one-step membership carrier's and from every other fold, so
/// a proof about a spend path can never be replayed as a proof about anything else.
pub const MEMBER_PATH_DOMAIN: u64 = 0x4e4d_5f50_4154_4833;
/// The class's ONE depth: the full spend path, `NF_DEPTH` — the node's `SPEND_TREE_DEPTH` (64), the same constant the
/// spend-validity and nullifier-insert gates are bounded by. A path shorter than the tree cannot refold to a tree root
/// without a preimage, so soundness rests on the anchor; this constant sizes the trace, and no other depth is stated
/// for this class anywhere (a wire shape naming another is refused).
pub const MEMBER_PATH_DEPTH: usize = crate::nullifier_insert_air::NF_DEPTH;
/// `leaf_commit ‖ binder ‖ anchor ‖ outs`.
pub const MEMBER_TUPLE_DIGESTS: usize = 4;
/// Field values in one row's public tuple.
pub const MEMBER_TUPLE_VALS: usize = MEMBER_TUPLE_DIGESTS * DIGEST_LANES;
/// The carrier's row width — the production one-step trace, unchanged.
pub const MEMBER_PATH_COLS: usize = MEMBER_STEP_SHAPE.1;

/// The public tuple of one membership statement — what the block's tuple list holds for this input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberTuple {
    /// `H(leaf ‖ binder)` — the note, committed under this spend's binder (never the leaf itself).
    pub leaf_commit: Digest,
    /// The spend's nullifier: scopes the statement to ONE spend.
    pub binder: Digest,
    /// The spend-tree root the path refolds to; the node checks it against the chain's anchor set.
    pub anchor: Digest,
    /// The digest of the spend's outputs.
    pub outs: Digest,
}

impl MemberTuple {
    fn digests(&self) -> [Digest; MEMBER_TUPLE_DIGESTS] {
        [self.leaf_commit, self.binder, self.anchor, self.outs]
    }
    /// The carrier's public bind — exactly what its transcript absorbs: `MEMBER_PATH_DOMAIN ‖ the four digests`.
    #[must_use]
    pub fn bind(&self) -> Vec<Fa4> {
        let mut b = Vec::with_capacity(1 + MEMBER_TUPLE_VALS);
        b.push(Fa4::from_u64(MEMBER_PATH_DOMAIN));
        for d in self.digests() {
            b.extend(d.iter().map(|&v| Fa4::from_u64(v)));
        }
        b
    }
    /// The tuple a bind states; `None` unless the bind is this class's (its domain and its width). Fail-closed.
    #[must_use]
    pub fn from_bind(pb: &[Fa4]) -> Option<Self> {
        if pb.len() != 1 + MEMBER_TUPLE_VALS || pb[0] != Fa4::from_u64(MEMBER_PATH_DOMAIN) {
            return None;
        }
        let d = |k: usize| -> Digest { core::array::from_fn(|c| pb[1 + k * DIGEST_LANES + c].as_canonical_u64()) };
        Some(MemberTuple { leaf_commit: d(0), binder: d(1), anchor: d(2), outs: d(3) })
    }
}

/// The per-row constraint: the one-step membership relation over a [`MEMBER_PATH_DEPTH`]-row trace, with the
/// blinded-boundary masks, unfolded residuals and declared rotation the module doc names.
/// Generic over the field its public values live in (lane agg 2026-11-15, `gate_trace`); the default is production's.
#[derive(Clone)]
pub struct MemberPathGate<Ea4 = crate::hiding_decider::Ea4> {
    pub gamma: Ea4,
    pub leaf_commit: [Ea4; DIGEST_LANES],
    pub binder: [Ea4; DIGEST_LANES],
    pub root: [Ea4; DIGEST_LANES],
}

/// The member leg's committed shape on its blinded chained door: `(columns, variables)`, the blinding rows' variable
/// included (`committed_air::prove_air_blinded_chained_bytes` doubles the laid table).
#[must_use]
pub fn member_path_shape() -> (usize, usize) {
    (MEMBER_PATH_COLS, MEMBER_PATH_DEPTH.trailing_zeros() as usize + 1)
}

impl<Ea4: crate::gate_trace::GateAlg> MemberPathGate<Ea4> {
    pub(crate) fn build(&self, local: &Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let one = Ea4::ONE;
        let out = crate::pow_pq_air::PERM_OUT;
        let mut rs: Vec<Ea4> = Vec::new();
        crate::pow_pq_air::push_perm_residuals(local, MS_FOLD, &mut rs);
        crate::pow_pq_air::push_perm_residuals(local, MS_COMMIT, &mut rs);
        crate::pow_pq_air::push_perm_residuals(local, MS_COMMIT2, &mut rs); // DB-363: the outer cross-bind block
        let (dir, active) = (local[MS_DIR], local[MS_ACTIVE]);
        rs.push(active * (active - one));
        rs.push(active * dir * (dir - one));
        for c in 0..DIGEST_LANES {
            let (a, s) = (local[MS_ACC_IN + c], local[MS_SIB + c]);
            rs.push(active * (local[MS_FOLD + c] - (a + dir * (s - a))));
            rs.push(active * (local[MS_FOLD + DIGEST_LANES + c] - (s + dir * (a - s))));
            rs.push(active * (local[MS_ACC_OUT + c] - local[MS_FOLD + out + c]));
            rs.push((one - active) * (local[MS_ACC_OUT + c] - a));
        }
        // DB-363: `leaf_commit == P(P(wleaf, binder), blind)` — two chained blocks, the blinding a hiding witness
        for c in 0..DIGEST_LANES {
            rs.push(local[MS_COMMIT + c] - local[MS_WLEAF + c]);
            rs.push(local[MS_COMMIT + DIGEST_LANES + c] - self.binder[c]);
            rs.push(local[MS_COMMIT2 + c] - local[MS_COMMIT + out + c]);
            rs.push(local[MS_COMMIT2 + DIGEST_LANES + c] - local[MS_BLIND + c]);
            rs.push(local[MS_COMMIT2 + out + c] - self.leaf_commit[c]);
        }
        // (1) THE DATA HALF: `x[0]` is the blinding MSB.
        let data = &x[1..];
        let is_first = data.iter().fold(one, |p, xk| p * (one - *xk));
        let is_last = data.iter().fold(one, |p, xk| p * *xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LANES {
            rs.push(is_first * (local[MS_ACC_IN + c] - local[MS_WLEAF + c]));
            rs.push(is_last * (local[MS_ACC_OUT + c] - self.root[c]));
            rs.push(not_last * (at(MS_ACC_IN + c, &sigma) - local[MS_ACC_OUT + c]));
            rs.push(not_last * (at(MS_WLEAF + c, &sigma) - local[MS_WLEAF + c]));
        }
        rs
    }
}

impl AirConstraint for MemberPathGate {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let (mut acc, mut pw) = (Ea4::ZERO, Ea4::ONE);
        for r in self.build(local, at, x) {
            acc = acc + pw * r;
            pw = pw * self.gamma;
        }
        acc
    }
    /// (2) Unfolded, so the aggregate lays one γ-power per residual.
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        self.build(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        false
    }
    /// (3) The rotated columns the chain link reads, as ONE contiguous run — [`member_shifted_run`].
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let (lo, n) = member_shifted_run();
        Some((lo..lo + n).collect())
    }
    /// DB-363: the blinding lanes are a HIDING witness, bound only through the outer cross-bind block.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((MS_BLIND..MS_BLIND + DIGEST_LANES).collect())
    }
}

/// The rotated run the chain link reads — `ACC_IN ‖ ACC_OUT ‖ DIR ‖ ACTIVE ‖ WLEAF` — as `(first column, count)`.
/// ONE definition: the gate's `shifted_cols` and every layout of this class read it here.
#[must_use]
pub fn member_shifted_run() -> (usize, usize) {
    (MS_ACC_IN, MS_WLEAF + DIGEST_LANES - MS_ACC_IN)
}

fn ea(d: Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| Fa4::from_u64(d[c]).into())
}

/// The gate a tuple states, at the carrier's own γ — the wallet proves against it, the node verifies against it.
#[must_use]
pub fn member_path_gate(t: &MemberTuple) -> impl Fn(Ea4) -> MemberPathGate + Clone {
    let (lc, b, r) = (ea(t.leaf_commit), ea(t.binder), ea(t.anchor));
    move |g: Ea4| MemberPathGate { gamma: g, leaf_commit: lc, binder: b, root: r }
}

/// The wrapped gate on an all-zero statement — the shape probes (residual count, degree) read it.
fn probe_gate() -> Blinded<MemberPathGate> {
    let z = [Ea4::ZERO; DIGEST_LANES];
    Blinded { inner: MemberPathGate { gamma: Ea4::ZERO, leaf_commit: z, binder: z, root: z } }
}

/// WALLET: prove one input's membership — `refold(leaf, siblings, dirs) == anchor` over the full spend path, the
/// leaf and every sibling private. Returns the carrier and the tuple the block states for it: the anchor is the
/// path's own refold (the node checks it against the chain's anchor set; the aggregate proves the path reaches it).
/// `None` unless the path is exactly this class's shape ([`MEMBER_PATH_DEPTH`] levels).
#[must_use]
/// THE NULL MEMBER CARRIER — the member class's twin of [`crate::settlement_delta::null_spend_carrier`]: a real member
/// path proof whose leaf, siblings, binder, blinding and outputs are all fresh from the OS CSPRNG, so its absorbed tuple
/// is fresh digests and its anchor is in no ring. It sources the member ledger's cover rows (`is_spend = 0`): the ring
/// lookup never sends its anchor and nothing it states is published. `None` when the OS source refuses.
#[must_use]
pub fn null_member_carrier() -> Option<(Vec<u8>, Vec<Fa4>)> {
    let r = crate::whir_rec_block::fresh_lc_blind;
    let mut siblings = Vec::with_capacity(MEMBER_PATH_DEPTH);
    let mut dirs = Vec::with_capacity(MEMBER_PATH_DEPTH);
    for _ in 0..MEMBER_PATH_DEPTH {
        let s = r()?;
        dirs.push(s[0] & 1 == 1);
        siblings.push(s);
    }
    let (bytes, t) = prove_member_path_carrier(r()?, &siblings, &dirs, r()?, r()?, r()?)?;
    Some((bytes, t.bind()))
}

pub fn prove_member_path_carrier(
    leaf: Digest,
    siblings: &[Digest],
    dirs: &[bool],
    binder: Digest,
    blind: Digest,
    outs: Digest,
) -> Option<(Vec<u8>, MemberTuple)> {
    if siblings.len() != MEMBER_PATH_DEPTH || dirs.len() != MEMBER_PATH_DEPTH {
        return None; // fail-closed: a partial walk cannot reach a spend-tree root and is not this class's trace
    }
    let t = MemberTuple {
        leaf_commit: note_leaf_commitment(leaf, binder, blind),
        binder,
        anchor: refold_in_block(leaf, siblings, dirs),
        outs,
    };
    let cols = member_path_cols(MEMBER_PATH_DEPTH, leaf, siblings, dirs, binder, blind);
    // ⛔ THE CHAINED DOOR (2026-11-10): the path's chain link reads the next row (`member_shifted_run`), and the plain
    // blinded door binds only the row at `r`, so a next-row value was the sender's own number and a note in no tree
    // verified (`a_forged_next_row_opening_cannot_prove_a_note_is_in_the_tree`). Here they are the commitment's own.
    let bytes = crate::committed_air::prove_air_blinded_chained_bytes(cols, member_path_gate(&t), &t.bind())?;
    Some((bytes, t))
}

/// NODE (at the door) and WALLET (self-check): verify one membership carrier against the tuple it states. The laid
/// shape is this class's constant, never read from the carrier (DB-213b).
#[must_use]
pub fn verify_member_path_carrier(bytes: &[u8], t: &MemberTuple) -> bool {
    crate::committed_air::verify_air_blinded_chained_bytes(
        bytes,
        member_path_gate(t),
        &t.bind(),
        (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS),
    )
}

/// The per-row gate of the class, built from the row's OWN tuple cells (`leaf_commit`, `binder`, `anchor`): a row
/// whose cells are not what its carrier's transcript bound breaks the closing equation exactly as a re-pointed
/// digest does — C_tuple from the row's own public cells, the rule every class obeys.
#[must_use]
pub fn member_delta_factory(layout: DeltaLayout) -> impl Fn(&Row<'_>) -> Blinded<MemberPathGate> + Clone {
    move |row: &Row<'_>| {
        let d = |off: usize| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|j| row[off + j]) };
        Blinded {
            inner: MemberPathGate {
                gamma: Ea4::ZERO, // unused: the row's own γ-power chain folds `residuals()`
                leaf_commit: d(layout.tuple_at(0, 0)),
                binder: d(layout.tuple_at(1, 0)),
                root: d(layout.tuple_at(2, 0)),
            },
        }
    }
}

/// The class's bound-step base and γ-power count from CONSTANTS alone (no carrier): the blinded carrier is the
/// [`MEMBER_PATH_DEPTH`]-row trace doubled (`nvars = log2(2·depth)`), `per` the wrapped gate's degree + 2, the width
/// the one-step row, the rotated run the gate's own.
pub(crate) fn member_class_base() -> (BoundLayout, usize) {
    let nvars = (2 * MEMBER_PATH_DEPTH).trailing_zeros() as usize;
    let inner = probe_gate();
    let (lo, run) = member_shifted_run();
    let base = BoundLayout {
        nvars,
        per: inner.degree(nvars) + 2,
        width: MEMBER_PATH_COLS,
        shifted_lo: lo,
        shifted: run,
        powers: 0,
        power_lo: 0,
    };
    let powers = delta_residual_count(&inner, base);
    (base, powers)
}

/// ⛔ DB-213b — THE CLASS FIXES THE SHAPE; the block never does. The whole shape is a function of `n` alone (the
/// depth is this class's constant), derived here by the producer and the peer alike; a block naming any other shape
/// is refused before its layout is built.
#[must_use]
pub fn member_class_shape(n: usize) -> Option<DeltaShape> {
    let (base, powers) = member_class_base();
    let layout = delta_layout(base, powers, n, DELTA_FIXED_SLOTS, 1 + MEMBER_TUPLE_VALS, MEMBER_TUPLE_VALS)?;
    Some(shape_of_layout(layout))
}

/// The bound-step base a block's carriers state — fail-closed on a first carrier whose bind is not this class's. The
/// producer then refuses any base that is not the class's own ([`member_class_shape`] equality).
pub(crate) fn member_base_layout(carriers: &[(Vec<u8>, Vec<Fa4>)]) -> Option<BoundLayout> {
    let (bytes, pb) = carriers.first()?;
    MemberTuple::from_bind(pb)?;
    let (lo, run) = member_shifted_run();
    Some(crate::recursion_bound::bound_step_row_committed(bytes, pb, lo, run)?.1)
}

/// PRODUCER: fold a block's membership carriers — one `(carrier bytes, bind)` per REAL spend input — into the class's
/// aggregate at the committed slot count. Returns the bytes, the shape the block publishes and `rows_digest`.
/// Fail-closed on a shape the class does not fix (checked BEFORE the tables are built).
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_member_transition(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_member_transition_with(carriers, domain, output_notes_root, del_set_root, false)
}

/// ⛔ TEST BUILDS ONLY — [`prove_block_member_transition`] with the BOUND template double (`settlement_delta::delta_bound`).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_block_member_transition_bound(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    prove_block_member_transition_with(carriers, domain, output_notes_root, del_set_root, true)
}

#[allow(clippy::type_complexity)]
fn prove_block_member_transition_with(
    carriers: &[(Vec<u8>, Vec<Fa4>)],
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    bound: bool,
) -> Option<(Vec<u8>, DeltaShape, Vec<Fa4>)> {
    let base = member_base_layout(carriers)?;
    let powers = delta_residual_count(&probe_gate(), base);
    let layout = delta_layout(base, powers, carriers.len(), DELTA_FIXED_SLOTS, 1 + MEMBER_TUPLE_VALS, MEMBER_TUPLE_VALS)?;
    let shape = shape_of_layout(layout);
    if member_class_shape(layout.n) != Some(shape) {
        return None; // the carriers state a shape this class does not fix
    }
    let (bytes, rows_digest) = delta_prove(
        carriers,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        member_delta_factory(layout),
        bound,
    )?;
    Some((bytes, shape, rows_digest))
}

/// PEER: verify a block's membership transition. The shape must be this class's for the block's `n` (its depth this
/// class's constant); the tuple width and the rotated run are restated from the class, never read off the wire.
#[must_use]
pub fn verify_block_member_transition(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_member_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, false)
}

/// ⛔ TEST BUILDS ONLY — [`verify_block_member_transition`] on an ARMED door: it accepts the bound template double's bytes
/// and nothing else.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn verify_block_member_transition_bound(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
) -> bool {
    verify_block_member_transition_with(bytes, shape, domain, output_notes_root, del_set_root, rows_digest, true)
}

fn verify_block_member_transition_with(
    bytes: &[u8],
    shape: DeltaShape,
    domain: Fa4,
    output_notes_root: &[Fa4],
    del_set_root: &[Fa4],
    rows_digest: &[Fa4],
    bound: bool,
) -> bool {
    if member_class_shape(shape.n) != Some(shape) {
        return false;
    }
    let Some(mut layout) = shape.layout() else { return false };
    layout.tuple_vals = MEMBER_TUPLE_VALS;
    let (lo, run) = member_shifted_run();
    layout.bound.shifted_lo = lo;
    layout.bound.shifted = run;
    delta_verify(
        bytes,
        layout,
        domain,
        output_notes_root,
        del_set_root,
        rows_digest,
        member_delta_factory(layout),
        bound,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔⛔⛔ AUDIT 2026-11-10, RED-FIRST — THE PROOF THAT A SPENT NOTE EXISTS READS THE NEXT ROW THROUGH A DOOR THAT DOES
    /// NOT BIND IT. This class's gate chains the path (`next.acc_in == this.acc_out`, the walked leaf carried down the
    /// rows) and its carrier WENT through `prove_air_blinded_bytes` / `verify_air_blinded_bytes`, which absorbed next-row
    /// openings without tying them to the commitment (audit F1, measured for two other gates the same day). So the
    /// adversary's carrier (a garbage table honestly committed and opened, all-zero rounds, ONE next-row opening moved
    /// until the gate reads zero) must be REFUSED for a statement nobody walked: a leaf commitment, a binder and an
    /// anchor it simply chose. If it verifies, any wallet proves membership of a note that is in no tree.
    /// CALIBRATION: the adversary must find the next-row cell this gate reads (else it proves nothing about this door).
    #[test]
    fn a_forged_next_row_opening_cannot_prove_a_note_is_in_the_tree() {
        use crate::poseidon2_compress::lanes_of;
        let d = |a: u64| crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[a, 1, 2, 3]), lanes_of(&[a, 4, 5, 6]));
        let t = MemberTuple { leaf_commit: d(11), binder: d(12), anchor: d(13), outs: d(14) };
        let cols: Vec<Vec<Fa4>> = (0..MEMBER_PATH_COLS)
            .map(|c| (0..MEMBER_PATH_DEPTH).map(|r| Fa4::from_u64((c as u64) * 131 + (r as u64) * 7 + 1)).collect())
            .collect();
        let forged = crate::committed_air::forge_blinded_next_row_for_tests(cols.clone(), member_path_gate(&t), &t.bind());
        let Some(bytes) = forged else {
            panic!("CALIBRATION: the adversary found no next-row cell this gate reads affinely, but the path chain reads one");
        };
        let accepted = verify_member_path_carrier(&bytes, &t);
        eprintln!("[member-path-forgery] a membership carrier over a GARBAGE trace ({} B) for a statement nobody walked VERIFIES = {accepted}", bytes.len());
        assert!(
            !accepted,
            "⛔⛔⛔ a membership carrier over a GARBAGE trace verified for a leaf, a binder and an anchor the prover chose: \
             its next-row openings are not bound to its commitment, so a note in no tree is proven a member"
        );
        // THE SAME LIE AGAINST THE DOOR THIS CLASS NOW USES: the adversary of the chained door, which sends the moved
        // next-row value and lies through the shift bind as far as a prover can. The bind's last line refuses it.
        let chained = crate::committed_air::forge_blinded_chained_for_tests(cols, member_path_gate(&t), &t.bind());
        let Some(bytes) = chained else {
            panic!("CALIBRATION: the chained door's adversary found no next-row value to move, but the path chain reads one");
        };
        let accepted = verify_member_path_carrier(&bytes, &t);
        eprintln!("[member-path-forgery] the chained door's adversary ({} B) VERIFIES = {accepted}", bytes.len());
        assert!(!accepted, "⛔⛔⛔ a moved next-row value passed the chained door: the shift bind does not bind it");
    }
    use crate::poseidon2_compress::lanes_of;
    use crate::settlement_delta::{prove_settlement_delta_bytes, verify_settlement_delta_bytes, DELTA_MIN_SLOTS};

    /// Wallet `i`'s full spend path: a distinct note, [`MEMBER_PATH_DEPTH`] siblings, its nullifier as the binder.
    fn path(i: u64) -> (Digest, Vec<Digest>, Vec<bool>, Digest) {
        let leaf = lanes_of(&[1_000 + i, 3, 5, 7]);
        let binder = lanes_of(&[2_000 + i, 11, 13, 17]);
        let sibs: Vec<Digest> = (0..MEMBER_PATH_DEPTH as u64).map(|k| lanes_of(&[i, k, 19, 23])).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|k| (i >> (k % 64)) & 1 == 1 || k % 3 == 0).collect();
        (leaf, sibs, dirs, binder)
    }

    /// Wallet `i`'s per-send blinding of its commitment (DB-363) — a fixture value; production draws it from the OS.
    fn blind(i: u64) -> Digest {
        lanes_of(&[4_000 + i, 41, 43, 47])
    }

    /// Wallet `i`'s carrier and the tuple it states. The anchors differ per wallet — each tuple carries its own, as a
    /// block whose spends name different anchors does.
    fn wallet(i: u64) -> ((Vec<u8>, Vec<Fa4>), MemberTuple) {
        let (leaf, sibs, dirs, binder) = path(i);
        let outs = lanes_of(&[3_000 + i, 29, 31, 37]);
        let (bytes, t) = prove_member_path_carrier(leaf, &sibs, &dirs, binder, blind(i), outs).expect("an honest full-depth path proves");
        ((bytes, t.bind()), t)
    }

    /// A FIXTURE layout at `slots` (the production door is [`prove_block_member_transition`] at `DELTA_FIXED_SLOTS`).
    fn fixture_layout(carriers: &[(Vec<u8>, Vec<Fa4>)], slots: usize) -> DeltaLayout {
        let base = member_base_layout(carriers).expect("the membership carrier lays as a bound step");
        let powers = delta_residual_count(&probe_gate(), base);
        delta_layout(base, powers, carriers.len(), slots, 1 + MEMBER_TUPLE_VALS, MEMBER_TUPLE_VALS).expect("the layout lays")
    }

    /// Head, a stride and the tail — every byte when the object is small.
    fn flip_positions(len: usize, stride: usize) -> Vec<usize> {
        if len <= 12_000 {
            return (0..len).collect();
        }
        let mut v: Vec<usize> = (0..256).collect();
        v.extend((256..len).step_by(stride));
        v.extend(len.saturating_sub(256)..len);
        v.sort_unstable();
        v.dedup();
        v
    }

    /// ⭐ THE PRODUCTION DOOR AT THE COMMITTED 256 SLOTS: the control verifies; a forged digest, a re-pointed anchor
    /// (DB-223 itself — an input claimed under a root it is not under), a broken path and every wire-shape tamper
    /// are refused.
    #[test]
    fn the_member_class_control_verifies_and_every_forgery_is_refused_through_the_production_door() {
        let dom = Fa4::from_u64(MEMBER_PATH_DOMAIN);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let t0 = std::time::Instant::now();
        let ws: Vec<((Vec<u8>, Vec<Fa4>), MemberTuple)> = (0..2).map(wallet).collect();
        let carrier_ms = t0.elapsed().as_millis();
        for w in &ws {
            assert!(verify_member_path_carrier(&w.0 .0, &w.1), "CONTROL: each wallet's carrier verifies alone");
            assert_eq!(MemberTuple::from_bind(&w.0 .1), Some(w.1), "the bind round-trips to its tuple");
        }
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = ws.iter().map(|w| w.0.clone()).collect();
        let t1 = std::time::Instant::now();
        let (bytes, shape, digest) = prove_block_member_transition(&carriers, dom, &onr, &dsr).expect("the block proves");
        let prove_ms = t1.elapsed().as_millis();
        assert_eq!(shape, member_class_shape(2).expect("the class shape at n = 2"), "the producer states the class's shape");
        let t2 = std::time::Instant::now();
        assert!(
            verify_block_member_transition(&bytes, shape, dom, &onr, &dsr, &digest),
            "CONTROL: the honest membership aggregate must verify before a forgery of it means anything"
        );
        let verify_ms = t2.elapsed().as_millis();

        // TAMPER 1 — the tuple list: the same proof, presented over a different rows digest.
        let mut forged = digest.clone();
        forged[0] += Fa4::ONE;
        assert!(
            !verify_block_member_transition(&bytes, shape, dom, &onr, &dsr, &forged),
            "⛔ the membership aggregate verified against a tuple list it does not stand over"
        );
        // TAMPER 2 — the wire shape: any field the class does not fix at this `n`.
        for (name, bad) in [
            ("n", DeltaShape { n: shape.n + 1, ..shape }),
            ("powers", DeltaShape { powers: shape.powers + 1, ..shape }),
            ("per", DeltaShape { per: shape.per + 1, ..shape }),
            ("width", DeltaShape { width: shape.width + 1, ..shape }),
        ] {
            assert!(
                !verify_block_member_transition(&bytes, bad, dom, &onr, &dsr, &digest),
                "⛔ a wire shape with a foreign `{name}` was accepted"
            );
        }
        // TAMPER 3 — a row naming an anchor its carrier never proved: wallet 1's carrier stated over wallet 0's anchor.
        let root_off = 1 + 2 * DIGEST_LANES;
        let mut lie = carriers.clone();
        for c in 0..DIGEST_LANES {
            lie[1].1[root_off + c] = carriers[0].1[root_off + c];
        }
        let accepted = prove_block_member_transition(&lie, dom, &onr, &dsr)
            .is_some_and(|(b, s, d)| verify_block_member_transition(&b, s, dom, &onr, &dsr, &d));
        assert!(
            !accepted,
            "⛔⛔⛔ DB-223 LIVES IN THE AGGREGATE: a row named an anchor its membership carrier never proved and the \
             block's aggregate still verified — a spend could claim any root"
        );
        // TAMPER 4 — a note NOT under the claimed anchor: one sibling changed, the honest tuple still claimed.
        let (leaf, mut sibs, dirs, binder) = path(0);
        sibs[5] = lanes_of(&[9, 9, 9, 9]);
        let t = ws[0].1;
        let cols = member_path_cols(MEMBER_PATH_DEPTH, leaf, &sibs, &dirs, binder, blind(0));
        let made = crate::committed_air::prove_air_blinded_chained_bytes(cols, member_path_gate(&t), &t.bind());
        assert!(
            !made.is_some_and(|b| verify_member_path_carrier(&b, &t)),
            "⛔⛔⛔ a path that does not refold to the anchor produced a membership proof that verifies"
        );
        // TAMPER 5 — a partial walk is not this class's trace.
        assert!(prove_member_path_carrier(leaf, &sibs[..8], &dirs[..8], binder, blind(0), t.outs).is_none(), "⛔ a partial path proved");
        eprintln!(
            "[member-path] ⭐ GREEN through the production door: carrier {} B ({carrier_ms} ms for 2), aggregate {} B at \
             {DELTA_FIXED_SLOTS} slots (n = 2): prove {prove_ms} ms, verify {verify_ms} ms; a forged digest, five \
             foreign shapes, a re-pointed anchor, a broken path and a partial walk are refused",
            ws[0].0 .0.len(),
            bytes.len()
        );
    }

    /// ⭐⭐⭐ THE BOUND TEMPLATE DOUBLE for the MEMBER class (docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md, brick 2): the
    /// same shared site as the delta classes (`settlement_delta::delta_prove` / `delta_verify`) — one statement with the real
    /// aggregate, an armed door takes the honest block and refuses a moved digest, root or shape, and the forms never cross.
    #[test]
    fn bound_member_transition_double_pins_the_same_statement_and_only_an_armed_door_takes_it() {
        let dom = Fa4::from_u64(MEMBER_PATH_DOMAIN);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = (0..2).map(|i| wallet(i).0).collect();
        let (bb, bs, bd) = prove_block_member_transition_bound(&carriers, dom, &onr, &dsr).expect("the member double lays");
        let (rb, rs, rd) = prove_block_member_transition(&carriers, dom, &onr, &dsr).expect("the real member aggregate lays");
        assert_eq!((bs, &bd), (rs, &rd), "⛔ the member double states another statement than the real aggregate");
        assert!(verify_block_member_transition_bound(&bb, bs, dom, &onr, &dsr, &bd), "CALIBRATION: an armed door takes the double");
        assert!(verify_block_member_transition(&rb, rs, dom, &onr, &dsr, &rd), "CALIBRATION: the real door takes the real aggregate");
        assert!(!verify_block_member_transition(&bb, bs, dom, &onr, &dsr, &bd), "⛔⛔⛔ the REAL member door accepted the double's bytes");
        assert!(!verify_block_member_transition_bound(&rb, rs, dom, &onr, &dsr, &rd), "⛔ an armed member door accepted a real proof");
        let mut forged = bd.clone();
        forged[0] += Fa4::ONE;
        assert!(!verify_block_member_transition_bound(&bb, bs, dom, &onr, &dsr, &forged), "⛔ a forged rows digest was accepted");
        let other = vec![Fa4::from_u64(0xA2); 4];
        assert!(!verify_block_member_transition_bound(&bb, bs, dom, &other, &dsr, &bd), "⛔ a moved output-notes root was accepted");
        assert!(!verify_block_member_transition_bound(&bb, bs, dom, &onr, &other, &bd), "⛔ a moved del_set root was accepted");
        let n3 = member_class_shape(3).expect("the class states n = 3");
        assert!(!verify_block_member_transition_bound(&bb, n3, dom, &onr, &dsr, &bd), "⛔ the statement at another count was accepted");
        let mut flipped = bb.clone();
        flipped[3] ^= 1;
        assert!(!verify_block_member_transition_bound(&flipped, bs, dom, &onr, &dsr, &bd), "⛔ a flipped byte was accepted");
        // a double laid under another domain word is not this class's statement
        if let Some((b, s, d)) = prove_block_member_transition_bound(&carriers, dom + Fa4::ONE, &onr, &dsr) {
            assert!(!verify_block_member_transition_bound(&b, s, dom, &onr, &dsr, &d), "⛔ another domain word's double verified");
        }
        eprintln!("[template-double] ⭐ member class: one statement, every tamper refused on the armed door, the forms never cross");
    }

    /// THE WIRE: bytes of an honest carrier and of an honest aggregate flipped (head, stride, tail) → refused.
    #[test]
    fn no_byte_of_a_member_carrier_or_of_its_aggregate_is_free() {
        let dom = Fa4::from_u64(MEMBER_PATH_DOMAIN);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let ws: Vec<((Vec<u8>, Vec<Fa4>), MemberTuple)> = (0..2).map(wallet).collect();
        // the carrier
        let (cb, t) = (&ws[0].0 .0, ws[0].1);
        assert!(verify_member_path_carrier(cb, &t), "CONTROL");
        let cpos = flip_positions(cb.len(), 97);
        let mut free: Vec<usize> = Vec::new();
        for &i in &cpos {
            let mut b = cb.clone();
            b[i] = b[i].wrapping_add(1);
            if verify_member_path_carrier(&b, &t) {
                free.push(i);
            }
        }
        eprintln!("[member-path] carrier byte-flip: {} B, {} positions, {} accepted", cb.len(), cpos.len(), free.len());
        assert!(free.is_empty(), "⛔ free carrier bytes at {free:?}");
        // the aggregate (fixture slots: the wire format is the production one, the row count is the fixture's)
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = ws.iter().map(|w| w.0.clone()).collect();
        let layout = fixture_layout(&carriers, DELTA_MIN_SLOTS);
        let (ab, digest) =
            prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, member_delta_factory(layout)).expect("proves");
        assert!(verify_settlement_delta_bytes(&ab, layout, dom, &onr, &dsr, &digest, member_delta_factory(layout)), "CONTROL");
        let apos = flip_positions(ab.len(), 1009);
        let mut afree: Vec<usize> = Vec::new();
        for &i in &apos {
            let mut b = ab.clone();
            b[i] = b[i].wrapping_add(1);
            if verify_settlement_delta_bytes(&b, layout, dom, &onr, &dsr, &digest, member_delta_factory(layout)) {
                afree.push(i);
            }
        }
        eprintln!("[member-path] aggregate byte-flip: {} B, {} positions, {} accepted", ab.len(), apos.len(), afree.len());
        assert!(afree.is_empty(), "⛔ free aggregate bytes at {afree:?}");
    }

    /// ⛔ THE UNREAD-WIRE-VALUE CLASS (lane speed4, 2026-11-12): a sent value the verifier never reads is a second encoding
    /// of the same proof. MEASURED: a cross-tie endpoint on the PUBLIC statement carried the public values and the verifier
    /// compared against `public_bind` itself, so 144 bytes of this aggregate took any value and verified (byte 59,787). The
    /// census here flips EVERY byte of the aggregate's small sections — the next-row openings, the shift binds and the
    /// ties — where the stride census above samples one byte in 1,009; and a public endpoint that sends a value is refused.
    #[test]
    fn no_byte_of_the_member_aggregates_openings_shift_binds_or_ties_is_free() {
        use crate::whir_rec_block::{AirBatchBusBundle, PUBLIC_BIND_TABLE};
        let _ = PUBLIC_BIND_TABLE;
        let dom = Fa4::from_u64(MEMBER_PATH_DOMAIN);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let ws: Vec<((Vec<u8>, Vec<Fa4>), MemberTuple)> = (0..2).map(wallet).collect();
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = ws.iter().map(|w| w.0.clone()).collect();
        let layout = fixture_layout(&carriers, DELTA_MIN_SLOTS);
        let (ab, digest) =
            prove_settlement_delta_bytes(&carriers, layout, dom, &onr, &dsr, member_delta_factory(layout)).expect("proves");
        let verify = |x: &[u8]| verify_settlement_delta_bytes(x, layout, dom, &onr, &dsr, &digest, member_delta_factory(layout));
        assert!(verify(&ab), "CONTROL");
        let b: AirBatchBusBundle = postcard::from_bytes(&ab).expect("decodes as the bus bundle");
        assert_eq!(postcard::to_allocvec(&b).expect("re-encodes"), ab, "CONTROL: one encoding round-trips");
        // the byte span of the small sections: from the first zerocheck's next-row openings to the column ties' end
        let sz = |v: postcard::Result<Vec<u8>>| v.map(|x| x.len()).unwrap_or(0);
        let head = sz(postcard::to_allocvec(&b.shapes)) + 1;
        let mut at = head;
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for z in &b.zcs {
            at += sz(postcard::to_allocvec(&z.round_evals)) + sz(postcard::to_allocvec(&z.opened)) + sz(postcard::to_allocvec(&z.r));
            let l = sz(postcard::to_allocvec(&z.shifted_opened));
            spans.push((at, at + l));
            at += l;
        }
        let tail_start = at;
        let tail_len = sz(postcard::to_allocvec(&b.tied_buses))
            + sz(postcard::to_allocvec(&b.n_constraint))
            + sz(postcard::to_allocvec(&b.shift_binds))
            + sz(postcard::to_allocvec(&b.cross_tie_openings));
        spans.push((tail_start, tail_start + tail_len));
        let mut free = Vec::new();
        let mut flipped = 0usize;
        for (lo, hi) in spans {
            for i in lo..hi.min(ab.len()) {
                let mut x = ab.clone();
                x[i] = x[i].wrapping_add(1);
                flipped += 1;
                if verify(&x) {
                    free.push(i);
                }
            }
        }
        eprintln!("[member-path] small-section census: {flipped} bytes flipped, {} accepted", free.len());
        assert!(flipped > 1_000, "CALIBRATION: the census must cover the sections it names");
        assert!(free.is_empty(), "⛔ free aggregate bytes at {:?}", &free[..free.len().min(32)]);
        // a public endpoint sends nothing; one that sends a value is a second encoding and is refused
        let empty = b.cross_tie_openings.iter().position(|(v1, v2)| v1.is_empty() != v2.is_empty());
        let k = empty.expect("CALIBRATION: this aggregate welds a cell to its public statement");
        let mut forged: AirBatchBusBundle = postcard::from_bytes(&ab).unwrap();
        let (v1, v2) = &mut forged.cross_tie_openings[k];
        let (filled, open) = if v1.is_empty() { (v2.clone(), v1) } else { (v1.clone(), v2) };
        *open = filled; // the very values the statement holds, sent anyway
        assert!(!verify(&postcard::to_allocvec(&forged).unwrap()), "⛔ a public endpoint that sends its values verified");
    }

    /// The class shape is a function of `n` alone and refuses what no block can carry; a bind that is not this
    /// class's is refused before any digest is read.
    #[test]
    fn the_class_shape_is_a_function_of_n_alone_and_a_foreign_bind_is_refused() {
        assert!(member_class_shape(0).is_none(), "⛔ an aggregate over no carriers was stateable");
        assert!(member_class_shape(DELTA_FIXED_SLOTS + 1).is_none(), "⛔ more carriers than slots was stateable");
        let s1 = member_class_shape(1).expect("n = 1");
        let s256 = member_class_shape(DELTA_FIXED_SLOTS).expect("n = 256");
        assert_eq!((s1.slots, s256.slots), (DELTA_FIXED_SLOTS, DELTA_FIXED_SLOTS));
        assert_eq!(s1.width, MEMBER_PATH_COLS);
        assert_eq!(s1.nvars, (2 * MEMBER_PATH_DEPTH).trailing_zeros() as usize, "the blinded trace doubles the rows");
        assert_eq!(DeltaShape { n: 1, ..s256 }, s1, "only `n` moves between the two shapes");
        let t = MemberTuple {
            leaf_commit: lanes_of(&[1, 2, 3]),
            binder: lanes_of(&[4, 5, 6]),
            anchor: lanes_of(&[7, 8, 9]),
            outs: lanes_of(&[10, 11, 12]),
        };
        let pb = t.bind();
        assert_eq!(pb.len(), 1 + MEMBER_TUPLE_VALS);
        assert_eq!(MemberTuple::from_bind(&pb), Some(t));
        let mut foreign = pb.clone();
        foreign[0] = Fa4::from_u64(crate::whir_rec_block::SPEND_VALIDITY_DOMAIN);
        assert!(MemberTuple::from_bind(&foreign).is_none(), "⛔ a spend-validity bind read as a membership tuple");
        assert!(MemberTuple::from_bind(&pb[..pb.len() - 1]).is_none(), "⛔ a truncated bind read as a membership tuple");
        assert!(member_base_layout(&[(vec![0u8; 8], foreign)]).is_none(), "⛔ a foreign first carrier laid a member base");
        let (lo, run) = member_shifted_run();
        assert_eq!(probe_gate().shifted_cols(), Some((lo..lo + run).collect::<Vec<_>>()), "gate and layout name ONE run");
        eprintln!("[member-path] ⭐ shape(n): n = 1 and n = {DELTA_FIXED_SLOTS} differ only in n; 0 and 257 are unstateable; foreign binds refused");
    }

    /// ⭐ Q5 — the WALLET's cost of one membership carrier at the class depth.
    #[test]
    #[ignore = "measurement: one membership carrier at MEMBER_PATH_DEPTH, prove + verify ms"]
    fn db223_q5_one_membership_carrier_at_the_class_depth() {
        let t0 = std::time::Instant::now();
        let ((bytes, _pb), t) = wallet(0);
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        let ok = verify_member_path_carrier(&bytes, &t);
        eprintln!(
            "[db223-q5] depth {MEMBER_PATH_DEPTH}: carrier {} byte(s), prove {prove_ms} ms, verify {} ms, verified {ok}",
            bytes.len(),
            t1.elapsed().as_millis()
        );
        assert!(ok, "⛔ an honest carrier at depth {MEMBER_PATH_DEPTH} must verify");
    }

    /// ⭐ Q4 MEASURED — n = 1, 16 and 256 real statements through the production door at the committed slot count:
    /// the aggregate's bytes, prove ms and verify ms, and the wallet carrier this class folds.
    #[test]
    #[ignore = "DB-223 Q4 measurement: 256 depth-64 carriers and three production-shape aggregates, minutes"]
    fn db223_q4_folding_depth_64_membership_statements_into_one_block_aggregate() {
        let dom = Fa4::from_u64(MEMBER_PATH_DOMAIN);
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let t_c = std::time::Instant::now();
        let ws: Vec<((Vec<u8>, Vec<Fa4>), MemberTuple)> = (0..DELTA_FIXED_SLOTS as u64).map(wallet).collect();
        let built_ms = t_c.elapsed().as_millis();
        let t_v = std::time::Instant::now();
        assert!(verify_member_path_carrier(&ws[0].0 .0, &ws[0].1), "CONTROL: one wallet's carrier verifies alone");
        eprintln!(
            "[db223-q4] wallet carrier: {} byte(s), ~{} ms prove each ({DELTA_FIXED_SLOTS} built in {built_ms} ms), verify {} ms",
            ws[0].0 .0.len(),
            built_ms / DELTA_FIXED_SLOTS as u128,
            t_v.elapsed().as_millis()
        );
        let carriers: Vec<(Vec<u8>, Vec<Fa4>)> = ws.iter().map(|w| w.0.clone()).collect();
        for n in [1usize, 16, DELTA_FIXED_SLOTS] {
            let cs = &carriers[..n];
            let t0 = std::time::Instant::now();
            let (bytes, shape, digest) = prove_block_member_transition(cs, dom, &onr, &dsr).expect("⛔ the membership aggregate must prove");
            let prove_ms = t0.elapsed().as_millis();
            let t1 = std::time::Instant::now();
            let ok = verify_block_member_transition(&bytes, shape, dom, &onr, &dsr, &digest);
            let verify_ms = t1.elapsed().as_millis();
            eprintln!(
                "[db223-q4] n={n} of {DELTA_FIXED_SLOTS} slots: AGGREGATE {} byte(s), prove {prove_ms} ms, verify {verify_ms} ms · shape {shape:?}",
                bytes.len()
            );
            assert!(ok, "⛔ the honest membership aggregate must verify at n={n}");
        }
    }
}

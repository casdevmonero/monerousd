// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-223 — THE BLOCK'S MEMBERSHIP TRANSITION: EVIDENCE THAT EVERY SPEND'S INPUT EXISTS, WITHOUT NAMING IT.
//!
//! ⛔ THE HOLE (docs/DB-223-A-BLOCK-MUST-PROVE-ITS-INPUTS-EXIST.md). The spend carrier is PATHLESS
//! (no Merkle path at all since gate D's deletion): it proves the nullifier, the outputs and conservation, and nothing about
//! whether its input note is a leaf of the chain's spend tree. The only membership check ran at the SUBMIT door, on
//! the node that pooled the transaction, against a record the spend NAMED (`membership_tip.named_record`, a which-item
//! leak). A peer grafting the block judged no membership at all — measured RED by
//! `a_peer_does_not_credit_the_outputs_of_a_spend_whose_input_never_existed`.
//!
//! ⭐ THIS IS THE BLOCK FIELD THAT CLOSES IT (Q5, decided and refuted). One aggregate over the block's member-path
//! carriers (`usdm_decider::member_path_gate`, one per real spend input, proved by the WALLET over its own depth-64
//! path), plus the tuple list it stands over. Each tuple is `leaf_commit ‖ binder ‖ anchor ‖ outs`:
//!   * `leaf_commit` and `binder` (the spend's nullifier) are the SAME values the spend's note-transition tuple states,
//!     so the member statement is tied to exactly one spend ([`cross_binds`]);
//!   * `anchor` is the spend-tree root the path refolds to — the door requires it to be one of the roots THIS node's
//!     own fold produced (the anchor ring), never a value read off the block;
//!   * `outs` is the digest of the spend's two outputs ([`outs_digest`], ONE definition for node and wallet).
//!
//! A peer: recomputes `rows_digest` from the list, verifies the aggregate once against the block's roots and that
//! digest, and then admits a spend's outputs only if its input's tuple verified and its anchor is in its ring.
//! Nothing here names a record, an ordinal or a note: `leaf_commit = H(leaf ‖ nf)` hides the leaf, and `binder` is the
//! nullifier the block already carries in the clear.
//!
//! ⛔ WHAT THIS IS NOT: it decides whether this node ACCEPTS a spend's outputs, never whether the spend happened (only
//! inclusion does that); and it says nothing about canonicity by itself — the anchor's canonicity is the ring lookup the
//! door runs (Q5 refutation 1).

use crate::spend_frontier::Digest4;
use p3_field::PrimeCharacteristicRing;
use usdm_decider::hiding_decider::Fa4;
use usdm_decider::member_path_gate::{MemberTuple, MEMBER_PATH_DOMAIN, MEMBER_TUPLE_VALS};

/// Bytes of one tuple on the wire: `leaf_commit ‖ binder ‖ anchor ‖ outs`, each the canonical 32-byte digest form.
pub const MEMBER_TUPLE_BYTES: usize = 4 * 32;

/// The domain word of [`outs_digest`] ("MEMBOUTS").
const OUTS_DOMAIN: u64 = 0x4d45_4d42_4f55_5453;

/// ⭐ DB-223 — the block's membership transition: ONE aggregate plus the tuple list it proves, in the block's own spend
/// order, and the circuit's public shape.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberTransition {
    /// The aggregate proof.
    pub agg: Vec<u8>,
    /// `n × MEMBER_TUPLE_BYTES`.
    pub tuples: Vec<u8>,
    /// The circuit's public shape, in `note_transition`'s wire form.
    pub shape: [u32; 8],
}

/// ⭐ DB-223 — the ONE definition of a spend's `outs` slot: a domain-separated Poseidon2 fold of its two output
/// commitments. The wallet puts it in the member carrier's statement; the node recomputes it from the spend's own
/// note-transition tuple, so a member statement cannot vouch for outputs other than its own spend's.
#[must_use]
pub fn outs_digest(out0_cm: &[u8; 32], out1_cm: &[u8; 32]) -> Option<Digest4> {
    let o0 = crate::spend_frontier::cm_bytes_to_root(out0_cm)?;
    let o1 = crate::spend_frontier::cm_bytes_to_root(out1_cm)?;
    let d = usdm_decider::poseidon2_compress::lanes_of(&[OUTS_DOMAIN]);
    let left = usdm_decider::poseidon2_compress::compress(&d, &o0);
    Some(usdm_decider::poseidon2_compress::compress(&left, &o1))
}

/// ⭐ §RF-3 §12.1 — the member ledger's public rows `lc' ‖ binder' ‖ outs'`, derived ROW FOR ROW from the block's
/// slot-ledger list (NOTE-TRANSITION-TUPLE-PADDING-SPEC §12): `lc' = PUB_LC`, `binder' = PUB_TAG0`,
/// `outs' = outs_digest(PUB_OUT0, PUB_OUT1)` — the door's one rule, every row, no class learned. Because every cell is a
/// function of the note list, the member list is NEVER on the wire: the producer and the door both derive it here and
/// the member proof is verified against it, so it can leak nothing the note list does not (0 B, today 128 B per spend).
/// This is a derivation, not a door; the door that verifies the member proof against these rows answers §9.6.
/// `None` on a list that is not `LEDGER_ROWS` rows or a cell that is not a canonical digest.
#[must_use]
pub fn ledger_member_rows(published: &[usdm_decider::settlement_delta::LedgerPublished]) -> Option<Vec<[Digest4; 3]>> {
    use usdm_decider::slot_ledger::{PUB_LC, PUB_OUT0, PUB_OUT1, PUB_TAG0};
    if published.len() != usdm_decider::settlement_delta::LEDGER_ROWS {
        return None;
    }
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    published.iter().map(|p| Some([p[PUB_LC], p[PUB_TAG0], outs_digest(&b(p[PUB_OUT0]), &b(p[PUB_OUT1]))?])).collect()
}

/// ⭐ §RF-3 §12 — the member ledger's row plan, `(spend_of, slot_lc)` per row in the NOTE ledger's order: the block's
/// `n_spends` spend rows first, then cover row `r` at cover slot `r + 1` — the projection of
/// `settlement_delta::plan_ledger_rows` (pinned equal by `the_member_plan_is_the_note_plan_projection`), which no
/// justified cell moves. `None` on more spends than rows.
#[must_use]
pub fn ledger_member_plan(n_spends: usize) -> Option<Vec<(Option<usize>, u64)>> {
    let rows = usdm_decider::settlement_delta::LEDGER_ROWS;
    // A cover row's slot counts on from the spends (`settlement_delta::plan_ledger_rows_with_tails`: `slot_lc = lc_base + r + 1`,
    // `lc_base = n_spends + tails` since aa2fd74's §18 tail class) — the projection states the producer's numbering.
    (n_spends <= rows)
        .then(|| (0..n_spends).map(|i| (Some(i), 0)).chain((0..rows - n_spends).map(|r| (None, (n_spends + r) as u64 + 1))).collect())
}

/// ⭐ §RF-3 — the member ledger's `(spend_of, slot_lc)` per row IN THE NOTE LEDGER'S PUBLISHED ORDER (its canonical sort),
/// read off each published row: a row whose `lc ‖ tag0` is carrier `i`'s `leaf_commit ‖ binder` is spend `i`; any
/// other row's `lc` is `cover_lc_native(seed, s)` for exactly one cover slot `s`. [`ledger_member_plan`] is the same
/// multiset in PLAN order (spends first); the door derives the member rows from the SORTED list, so a member proof laid
/// in plan order is refused by every honest peer.
/// MEASURED 2026-10-24 (RED, scratchpad/night/rf3-door1-r3.log): a produced quiet block's member ledger laid in plan
/// order did not verify over its own ring (`node::pins::rf3_the_one_block_door_admits_a_ledger_only_with_its_member_ledger`);
/// the unit pin passed only because its hand-made list was already in plan order.
/// `None` when a row matches no carrier and no cover slot, or a carrier is matched twice or never.
/// cons: `LEDGER_ROWS` native cover-lc derives + one map lookup per row, per block; nothing stored.
#[must_use]
pub fn ledger_member_rows_in_list_order(
    carriers: &[(Vec<u8>, MemberTuple)],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    seed: Digest4,
) -> Option<Vec<(Option<usize>, u64)>> {
    use usdm_decider::slot_ledger::{cover_lc_native, PUB_LC, PUB_TAG0};
    let n = usdm_decider::settlement_delta::LEDGER_ROWS;
    if note_published.len() != n {
        return None;
    }
    let slots: std::collections::HashMap<Digest4, u64> = (1..=n as u64).map(|s| (cover_lc_native(seed, s), s)).collect();
    let mut used = vec![false; carriers.len()];
    let rows: Vec<(Option<usize>, u64)> = note_published
        .iter()
        .map(|p| {
            if let Some(i) = carriers.iter().position(|(_, t)| t.leaf_commit == p[PUB_LC] && t.binder == p[PUB_TAG0]) {
                (!std::mem::replace(&mut used[i], true)).then_some((Some(i), 0))
            } else {
                slots.get(&p[PUB_LC]).map(|s| (None, *s))
            }
        })
        .collect::<Option<_>>()?;
    used.iter().all(|u| *u).then_some(rows)
}

/// ⭐ V2 (speed5, 2026-11-16) — THE PRODUCER'S MEMBER CHECK, NATIVE. With no member statement in the joined proof the producer
/// still refuses, before any proving work, exactly what laying the member ledger refused: a stated spend row with no member
/// carrier (every published row is a carrier's — its `leaf_commit ‖ binder` — or a cover slot, and every carrier is used:
/// [`ledger_member_rows_in_list_order`]), and a member whose anchor is not in the producer's ring. A block that fails either
/// would be refused by every peer's door or fold; this keeps the producer from laying it. AI RESISTANT: (b) code, the peers'
/// native checks being the (a)/(b) that decide. SCALE: ≤ `LEDGER_ROWS` rows and the ring, once per template.
#[must_use]
pub fn members_state_the_spends(
    carriers: &[(Vec<u8>, MemberTuple)],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring: &[Digest4],
    seed: Digest4,
) -> bool {
    ledger_member_rows_in_list_order(carriers, note_published, seed).is_some() && carriers.iter().all(|(_, t)| ring.contains(&t.anchor))
}

fn ring_lanes(ring: &[Digest4]) -> Vec<[Fa4; usdm_decider::poseidon2_compress::DIGEST_LANES]> {
    ring.iter().map(|d| core::array::from_fn(|c| Fa4::from_u64(d[c]))).collect()
}

/// ⭐ §RF-3 §12 PRODUCER — a block's member ledger: ONE proof over `LEDGER_ROWS` rows whatever the real spend count.
/// `carriers` are the block's real member carriers in spend order (none: the null member carrier states every row as
/// cover); `note_published` the block's note-ledger list (cover rows take its cells); `ring` is the producer's anchor ring; `seed` the header seed. Only the proof rides the wire — the rows are
/// [`ledger_member_rows`] of the note ledger's list, and the ring digest is each peer's own. `None` on anything
/// unstateable (a carrier of another class, an anchor outside `ring`, more spends than rows).
/// O1-FOOTPRINT-REVIEWED: `LEDGER_ROWS` rows and one constant-size proof, built and dropped per block.
/// cons: one member-ledger prove per block (3.2 s measured on the decider pin), the same quiet or busy; a quiet block
/// carries the class's full proof where it carried 0 B (the price of one shape).
#[must_use]
pub fn build_member_ledger(
    carriers: &[(Vec<u8>, MemberTuple)],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring: &[Digest4],
    output_notes_root: &crate::hash::Hash32,
    seed: Digest4,
) -> Option<Vec<u8>> {
    build_member_ledger_with(carriers, note_published, ring, output_notes_root, seed, false)
}

/// [`build_member_ledger`] through the one member-ledger switch: on an ARMED test node (`bound`) the decider's bound
/// member-ledger double (`prove_member_ledger_over_notes_bound`) — the same lay, rows, ring and statement, a 32 B seal in
/// place of the WHIR prove — as `build_ledger_with` does for the note ledger. A node binary has no bound branch.
#[must_use]
pub fn build_member_ledger_with(
    carriers: &[(Vec<u8>, MemberTuple)],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring: &[Digest4],
    output_notes_root: &crate::hash::Hash32,
    seed: Digest4,
    bound: bool,
) -> Option<Vec<u8>> {
    let cover_cells: Vec<[Digest4; 2]> = ledger_member_rows(note_published)?.iter().map(|r| [r[1], r[2]]).collect();
    let mut binds: Vec<(Vec<u8>, Vec<Fa4>)> = carriers.iter().map(|(b, t)| (b.clone(), t.bind())).collect();
    if binds.is_empty() {
        binds.push(null_carrier_for(bound)?);
    }
    let rows = ledger_member_rows_in_list_order(carriers, note_published, seed)?;
    let (onr, dsr) = crate::note_transition::roots(output_notes_root);
    let ring = ring_lanes(ring);
    #[cfg(test)]
    {
        if bound {
            return usdm_decider::member_ledger::prove_member_ledger_over_notes_bound(&binds, &rows, &cover_cells, &ring, &onr, &dsr, seed)
                .and_then(|(p, _, _)| crate::note_transition::bound_weight::pad(p, crate::note_transition::bound_weight::MEMBER_LEDGER)); // R4
        }
    }
    let _ = bound;
    usdm_decider::member_ledger::prove_member_ledger_over_notes(&binds, &rows, &cover_cells, &ring, &onr, &dsr, seed).map(|(p, _, _)| p)
}

/// A no-spend block's null member carrier. The BOUND double (test builds only) reuses ONE per process: it lays the same
/// rows and seals the same bind shape, and the carrier is a real WHIR carrier prove (`null_member_carrier`) that the
/// double would otherwise pay on every armed block (MEASURED 2026-10-24, rf3 door pin: first lay 2,585 ms, the next
/// 300 ms). A real ledger proves a fresh one per block (fresh blinds).
fn null_carrier_for(bound: bool) -> Option<(Vec<u8>, Vec<Fa4>)> {
    #[cfg(test)]
    {
        if bound {
            static NULL: std::sync::OnceLock<Option<(Vec<u8>, Vec<Fa4>)>> = std::sync::OnceLock::new();
            return NULL.get_or_init(usdm_decider::member_path_gate::null_member_carrier).clone();
        }
    }
    let _ = bound;
    static POOL: crate::note_transition::CarrierPool = crate::note_transition::CarrierPool::new();
    POOL.take(usdm_decider::member_path_gate::null_member_carrier)
}

/// ⭐ §RF-3 §12 PEER — verify a block's member ledger proof against the note ledger's verified list (the rows are
/// derived from it, never read off the wire), the header's seed commitment, and the ring digest THIS node computes from
/// its OWN anchor ring.
///
/// NEW-DOOR CHECKLIST (AGENTS.md §9.6) — the padded twin of [`verify_with`]:
/// (1) PoW: not this step's; the block door calls it after the header's grind check, as it calls `verify_with`.
/// (2) Proof: `verify_member_ledger_bytes` over the class's fixed layout and domain, under the header seed commitment
///     (bound in the block id), `rows_digest` of the derived rows and this node's ring digest.
/// (3) Value: it creates none — it only gates whether a spend row's outputs are admitted; a cover row's `lc'` is the
///     seed's cover law, which no input note opens.
/// (4) Replay: the spend's nullifier is the row's `binder'`, the note ledger's tag cell, refused by the spent SET there.
/// (5) Bounded work: `LEDGER_ROWS` derived rows, one ring digest over the fixed ring layout, one constant-size verify.
/// (6) Parity with `verify_with`: tuple decode → rows derived from the verified note list (stronger: nothing to forge);
///     per-spend cross-bind → `lc'`/`binder'`/`outs'` ARE the note row's cells; anchor ∈ this node's ring → the ring
///     lookup inside the proof against this node's own ring digest.
#[must_use]
pub fn verify_member_ledger(
    proof: &[u8],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring: &[Digest4],
    output_notes_root: &crate::hash::Hash32,
    seed_commit: Digest4,
) -> bool {
    let Some(ring_commit) = ring_commit_of(ring) else { return false };
    verify_member_ledger_under(proof, note_published, &ring_commit, output_notes_root, seed_commit)
}

/// §RF-3 — THE ONE SPELLING of an anchor ring as the header's `member_ring_commit`: the 8 canonical lanes of
/// `usdm_decider::member_ring::ring_digest_of` over the class's fixed ring layout, as u32 LE (the spelling of
/// `block::cover_seed_commit_of`). The producer writes it, every node records it per fold step, and the door reads it
/// back with [`verify_member_ledger_under`]. `None` when the ring does not state under the layout.
#[must_use]
pub fn ring_commit_of(ring: &[Digest4]) -> Option<crate::hash::Hash32> {
    use p3_field::PrimeField64;
    let layout = usdm_decider::member_ledger::member_ledger_ring()?;
    let d = usdm_decider::member_ring::ring_digest_of(&ring_lanes(ring), layout)?;
    if d.len() != usdm_decider::poseidon2_compress::DIGEST_LANES {
        return None;
    }
    let mut b = [0u8; 32];
    for (c, v) in d.iter().enumerate() {
        b[4 * c..4 * c + 4].copy_from_slice(&(v.as_canonical_u64() as u32).to_le_bytes());
    }
    Some(crate::hash::Hash32(b))
}

/// §RF-3 §12 PEER, the header-anchored form (Zcash Sapling: the spend names its anchor; the FOLD checks that anchor
/// against the canonical history, never this call): verify under the ring digest the header's `member_ring_commit`
/// names, so a peer at another fold position admits an honest block. A non-canonical lane refuses (one encoding).
/// NEW-DOOR CHECKLIST: as [`verify_member_ledger`], except (6) anchor ∈ ring moves to the fold's history check.
#[must_use]
pub fn verify_member_ledger_under(
    proof: &[u8],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring_commit: &crate::hash::Hash32,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: Digest4,
) -> bool {
    verify_member_ledger_under_with(proof, note_published, ring_commit, output_notes_root, seed_commit, false)
}

/// ⭐ R4 lever 4 step C2 — the member ledger as ONE STATEMENT of the block's joined light-decider batch: the same carriers,
/// rows, cover cells and ring [`build_member_ledger_with`] proves over, laid for `light_batch_merge::prove_joined`.
#[must_use]
pub fn lay_member_ledger_statement(
    carriers: &[(Vec<u8>, MemberTuple)],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring: &[Digest4],
    output_notes_root: &crate::hash::Hash32,
    seed: Digest4,
) -> Option<usdm_decider::light_batch_merge::LaidStatement<'static>> {
    let cover_cells: Vec<[Digest4; 2]> = ledger_member_rows(note_published)?.iter().map(|r| [r[1], r[2]]).collect();
    let mut binds: Vec<(Vec<u8>, Vec<Fa4>)> = carriers.iter().map(|(b, t)| (b.clone(), t.bind())).collect();
    if binds.is_empty() {
        binds.push(null_carrier_for(false)?);
    }
    let rows = ledger_member_rows_in_list_order(carriers, note_published, seed)?;
    let (onr, dsr) = crate::note_transition::roots(output_notes_root);
    let ring = ring_lanes(ring);
    usdm_decider::member_ledger::lay_member_ledger_statement_over_notes(&binds, &rows, &cover_cells, &ring, &onr, &dsr, seed)
        .map(|(s, _, _)| s)
}

/// ⭐ R4 lever 4 step C2 — the member ledger's statement for the joined VERIFY, derived from the block alone (the note list,
/// the header's ring commit and seed commit) exactly as [`verify_member_ledger_under_with`] derives it.
#[must_use]
pub fn member_ledger_stated(
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring_commit: &crate::hash::Hash32,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: Digest4,
) -> Option<usdm_decider::light_batch_merge::StatedStatement<'static>> {
    let rows = ledger_member_rows(note_published)?;
    let lanes = crate::block::cover_seed_commit_lanes(ring_commit)?;
    let ring_digest: Vec<Fa4> = lanes.iter().map(|v| Fa4::from_u64(*v)).collect();
    let (onr, dsr) = crate::note_transition::roots(output_notes_root);
    usdm_decider::member_ledger::member_ledger_stated_statement(&onr, &dsr, seed_commit, &rows, &ring_digest)
}

/// [`verify_member_ledger_under`] through the one member-ledger switch: an ARMED test door (`bound`) verifies the bound
/// member-ledger double ONLY (`verify_member_ledger_bytes_bound`; never a fallback to the real verifier, which never
/// takes the double's bytes). Every check above the proof runs in both forms. A node binary has no bound branch.
#[must_use]
pub fn verify_member_ledger_under_with(
    proof: &[u8],
    note_published: &[usdm_decider::settlement_delta::LedgerPublished],
    ring_commit: &crate::hash::Hash32,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: Digest4,
    bound: bool,
) -> bool {
    let Some(rows) = ledger_member_rows(note_published) else { return false };
    let Some(lanes) = crate::block::cover_seed_commit_lanes(ring_commit) else { return false };
    let ring_digest: Vec<Fa4> = lanes.iter().map(|v| Fa4::from_u64(*v)).collect();
    let (onr, dsr) = crate::note_transition::roots(output_notes_root);
    #[cfg(test)]
    {
        if bound {
            return crate::note_transition::bound_weight::unpad(proof, crate::note_transition::bound_weight::MEMBER_LEDGER)
                .is_some_and(|seal| {
                    usdm_decider::member_ledger::verify_member_ledger_bytes_bound(seal, &onr, &dsr, seed_commit, &rows, &ring_digest)
                }); // R4: the seal back out of the real proof's weight
        }
    }
    let _ = bound;
    usdm_decider::member_ledger::verify_member_ledger_bytes(proof, &onr, &dsr, seed_commit, &rows, &ring_digest)
}

/// Write one tuple in its wire form.
pub fn write_tuple(t: &MemberTuple, out: &mut Vec<u8>) {
    for d in [t.leaf_commit, t.binder, t.anchor, t.outs] {
        out.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(d));
    }
}

/// Read one tuple from its wire form; `None` unless every digest is canonical. Fail-closed.
#[must_use]
pub fn read_tuple(b: &[u8]) -> Option<MemberTuple> {
    if b.len() != MEMBER_TUPLE_BYTES {
        return None;
    }
    let d = |k: usize| -> Option<Digest4> {
        let mut c = [0u8; 32];
        c.copy_from_slice(&b[32 * k..32 * (k + 1)]);
        crate::spend_frontier::cm_bytes_to_root(&c)
    };
    Some(MemberTuple { leaf_commit: d(0)?, binder: d(1)?, anchor: d(2)?, outs: d(3)? })
}

/// The member class's domain tag every carrier's bind opens with.
fn domain() -> Fa4 {
    Fa4::from_u64(MEMBER_PATH_DOMAIN)
}

/// PRODUCER: fold the block's member carriers — one `(carrier bytes, tuple)` per REAL spend input, in the block's
/// spend order — into the class's aggregate at the committed slot count. `None` when there is nothing to prove or the
/// carriers do not state this class's shape (fail-closed: a block with spends and no transition carries no evidence,
/// and its spends' outputs are not admitted by any peer).
#[must_use]
pub fn build(carriers: &[(Vec<u8>, MemberTuple)], output_notes_root: &crate::hash::Hash32) -> Option<MemberTransition> {
    build_with(carriers, output_notes_root, false)
}

/// [`build`] on a producer that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn build_with(carriers: &[(Vec<u8>, MemberTuple)], output_notes_root: &crate::hash::Hash32, bound: bool) -> Option<MemberTransition> {
    if carriers.is_empty() || carriers.len() > crate::cover::BLOCK_FIXED_TX_COUNT {
        return None;
    }
    let mut binds: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(carriers.len());
    let mut tuples = Vec::with_capacity(carriers.len() * MEMBER_TUPLE_BYTES);
    for (bytes, t) in carriers {
        binds.push((bytes.clone(), t.bind()));
        write_tuple(t, &mut tuples);
    }
    let (onr, dsr) = crate::note_transition::roots(output_notes_root);
    let (agg, shape, _digest) = crate::note_transition::TemplateClass::Member.prove(&binds, domain(), &onr, &dsr, bound)?;
    Some(MemberTransition { agg, tuples, shape: crate::note_transition::shape_to_wire(shape) })
}

/// PEER: verify a block's membership transition against the block's own `output_notes_root`, recomputing
/// `rows_digest` from the carried list. Returns the verified tuples (in the block's spend order), or `None`.
/// The tuples are PROVEN statements; what they are worth is decided by [`cross_binds`] and the anchor ring.
#[must_use]
pub fn verify(mt: &MemberTransition, output_notes_root: &crate::hash::Hash32) -> Option<Vec<MemberTuple>> {
    verify_with(mt, output_notes_root, false)
}

/// [`verify`] on a door that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn verify_with(mt: &MemberTransition, output_notes_root: &crate::hash::Hash32, bound: bool) -> Option<Vec<MemberTuple>> {
    let shape = crate::note_transition::shape_from_wire(mt.shape);
    if shape.n == 0 || shape.n > crate::cover::BLOCK_FIXED_TX_COUNT || mt.tuples.len() != shape.n * MEMBER_TUPLE_BYTES {
        return None; // fail-closed: the list must be exactly the `n` the statement declares
    }
    let parsed: Vec<MemberTuple> = mt.tuples.chunks_exact(MEMBER_TUPLE_BYTES).map(read_tuple).collect::<Option<_>>()?;
    // ⭐ the verified-transition cache (`crate::verify_cache`): these exact bytes, once TRUE, are not re-derived or re-proved
    let key = crate::verify_cache::key_on_door(
        crate::verify_cache::Verifier::MemberTransition,
        mt.shape,
        &[mt.agg.as_slice(), mt.tuples.as_slice(), output_notes_root.as_bytes().as_slice()],
        bound,
    );
    if !crate::verify_cache::verified(key, || {
        let proven = || -> Option<bool> {
            // The row the chain hashes is the bind minus its domain tag: exactly the four digests.
            let rows: Vec<Vec<Fa4>> = parsed.iter().map(|t| t.bind()[1..].to_vec()).collect();
            if rows.iter().any(|r| r.len() != MEMBER_TUPLE_VALS) {
                return None;
            }
            let digest = usdm_decider::settlement_delta::rows_digest_of(&rows, shape.slots, MEMBER_TUPLE_VALS)?;
            let (onr, dsr) = crate::note_transition::roots(output_notes_root);
            Some(crate::note_transition::TemplateClass::Member.verify(&mt.agg, shape, domain(), &onr, &dsr, &digest, bound))
        };
        proven().unwrap_or(false)
    }) {
        return None;
    }
    Some(parsed)
}

/// ⭐⭐⭐ DB-223 Q7 — A SPEND COUNTS ONLY WHEN THE BLOCK PROVES ITS INPUT EXISTS. The ONE rule every site that justifies
/// a spend reads (the ingest door, the graft door `Node::graft_admitted_notes`, the fold's `Node::lane_justified`): the
/// note transition verifies (validity, conservation, filing — unchanged), AND the block's member transition verifies,
/// states exactly one tuple per spend tuple, and tuple `i` cross-binds spend `i` ([`cross_binds`]: the input's leaf under
/// the spend's own nullifier and blinding, into the spend's own outputs). Returns the note transition's admissions and
/// the member tuples in spend order (their ANCHORS are judged at the fold, against the canonical ring — Q1), or `None`.
/// MEASURED (Q7): before, the block path admitted a spend on the note transition alone, whose membership path is a free
/// witness, so a producer laid a spend of a note that never existed and a peer recorded its 999,999,000-unit output
/// (`a_peer_does_not_credit_the_outputs_of_a_spend_whose_input_never_existed`, RED on main 2026-10-02).
#[must_use]
pub fn spends_proven_with_members(
    nt: &crate::note_transition::NoteTransition,
    mt: Option<&MemberTransition>,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
) -> Option<(crate::note_transition::Admissible, Vec<MemberTuple>)> {
    spends_proven_with_members_with(nt, mt, output_notes_root, oli_tags, false)
}

/// [`spends_proven_with_members`] on a door that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn spends_proven_with_members_with(
    nt: &crate::note_transition::NoteTransition,
    mt: Option<&MemberTransition>,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
    bound: bool,
) -> Option<(crate::note_transition::Admissible, Vec<MemberTuple>)> {
    let admit = crate::note_transition::verify_with(nt, output_notes_root, oli_tags, bound)?;
    let spends = crate::note_transition::spend_tuples(nt)?;
    let members = verify_with(mt?, output_notes_root, bound)?;
    (members.len() == spends.len() && members.iter().zip(&spends).all(|(m, s)| cross_binds(m, s)))
        .then_some((admit, members))
}

/// §RF-3 — what a block CARRIES that its slot-ledger door reads beyond the legacy door's inputs: its real notes (the
/// header slots are derived from them, `note_transition::header_note_cms_of_bodies`), its 256 padded tags
/// (`nullifier_proof.padded_tags`) and the header's seed and ring commitments. Every field is header-bound.
#[derive(Clone, Copy)]
pub struct LedgerDoor<'a> {
    /// `None` = the body is not held here (`Block::output_notes` never travels, DB-165): the spend verdict never reads
    /// it, and the block's notes are received only where it is held and its out cells are its header slots.
    pub real_notes: Option<&'a [u8]>,
    /// §20.2 — the record's cover key beside the held body (it rides with the reals on every node route); `None` with
    /// a held body is a body this node cannot bind (fail-closed on the notes, never a spend verdict).
    pub cover_key: Option<crate::cover::CoverKey>,
    pub padded_tags: &'a [[u8; 32]],
    pub seed_commit: &'a crate::hash::Hash32,
    pub ring_commit: &'a crate::hash::Hash32,
}

impl<'a> LedgerDoor<'a> {
    /// The door's inputs from a whole block.
    #[must_use]
    pub fn of_block(b: &'a crate::block::Block) -> Self {
        Self::of_parts(&b.header, &b.output_notes, &b.nullifier_proof.padded_tags, b.cover_key)
    }

    /// The door's inputs from a header and the carried parts (the graft carry holds no `Block`).
    #[must_use]
    /// An empty body is a body NOT HELD: every honest block carries ≥ 1 real note (its reward or seed note).
    pub fn of_parts(
        h: &'a crate::block::BlockHeader,
        real_notes: &'a [u8],
        padded_tags: &'a [[u8; 32]],
        cover_key: Option<crate::cover::CoverKey>,
    ) -> Self {
        let real_notes = (!real_notes.is_empty()).then_some(real_notes);
        Self { real_notes, cover_key, padded_tags, seed_commit: &h.cover_seed_commit, ring_commit: &h.member_ring_commit }
    }
}

/// ⭐ §RF-3 — THE ONE BLOCK SPEND DOOR every site that justifies a spend reads (graft, fold, lane justify, held-header
/// graft): a note transition of the slot-ledger class (`Some(nt.shape) == ledger_shape_wire()`) is judged by the
/// ledger door, every other by [`spends_proven_with_members_with`] unchanged. One rule, so no caller can admit a ledger
/// by the legacy door or the reverse.
///
/// The ledger arm: `note_transition::verify_ledger_with` over the header slots derived from the carried real notes,
/// the padded tags, the seed commit and `oli_tags`, WITH the block's member ledger as the third statement of the same
/// joined proof (R4 lever 4 C2: its list derived from the note ledger's — never carried, spec §12.1, so `mt.tuples` and
/// `mt.agg` must be empty and `mt.shape` the ledger class word — under the header's `member_ring_commit`,
/// [`member_ledger_stated`]). A ledger block with no member
/// ledger is refused WHOLE: its spend rows cannot be told from its cover rows, so no row may count until every row's
/// input is proven (DB-223 Q7 on the padded shape). The ring commit's canonicity is the fold's
/// (`Node::member_anchors_at_fold`), as the legacy anchors are. Returns no member tuples for a ledger: no anchor is
/// published (spec §12 (C)).
///
/// NEW-DOOR CHECKLIST (AGENTS.md §9.6) — a dispatch, not a new door: (1) PoW — the callers', unchanged; (2) proofs —
/// the ONE joined note + tag + member ledger proof, every statement required; (3) value — a ledger row counts only with its input
/// proven by the member ledger (a cover `lc'` matches no path); (4) replay — every admitted tag enters the spent SET
/// at the caller, as the legacy nullifiers do; (5) bounded work — ≤ 256 cm derives, the fixed-length ledger decode, ONE
/// constant-size joined verify; (6) parity with the legacy arm — its transition verify → `verify_ledger_with`; its member
/// verify + per-spend cross-bind → the member ledger over rows derived from the note list (the cross-bind IS the
/// derivation); its anchor → the header's ring commit, judged at the fold. `ledger: None` (a caller without the
/// block's parts) admits no ledger, fail-closed on the block's notes only. The verdict (`Some`/`None`) reads only what
/// travels; `LedgerDoor::real_notes` (the body, held or not) decides only whether the block's notes are received — a
/// held body whose out cells are not its header slots receives none, as a body off its `output_notes_root` does.
/// cons: none on bytes; the ≤ 256 slot derives move from every door call to the calls that hold the body.
#[must_use]
pub fn spends_proven_on_block_with(
    nt: &crate::note_transition::NoteTransition,
    mt: Option<&MemberTransition>,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
    ledger: Option<LedgerDoor<'_>>,
    bound: bool,
    ledger_bound: bool,
) -> Option<(crate::note_transition::Admissible, Vec<MemberTuple>)> {
    let class = crate::note_transition::ledger_shape_wire();
    if Some(nt.shape) != class {
        return spends_proven_with_members_with(nt, mt, output_notes_root, oli_tags, bound);
    }
    let p = ledger?;
    let mt = mt?;
    if !mt.tuples.is_empty() || Some(mt.shape) != class {
        return None; // one encoding: the member list is derived from the note ledger, never carried (§12.1)
    }
    let published = crate::note_transition::decode_ledger_published(&nt.tuples)?;
    let seed = crate::block::cover_seed_commit_lanes(p.seed_commit)?;
    // ⭐ V2 (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16) — NO MEMBER STATEMENT: the joined ledger proof (`nt.agg`) is the
    // tree-ledger note statement alone. What the member ledger proved is judged natively on every path: each spend's member
    // carrier by the block door from the carried transaction (or in the tree's leaves), its cross-bind to the spend in
    // `spend_evidence::evidence_fields`, its anchor at the fold against this node's own recent roots after the header's ring
    // commit is checked against this chain's ring history (`Node::member_anchors_at_fold`). `mt.agg` travels EMPTY (one
    // encoding). The armed double keeps its own 32 B member seal (`bound_weight::MEMBER_LEDGER`), judged here as before.
    // ⭐ A-F114 (B′): under the constant chain no member ledger rides (each spend's wrapper is its membership), armed or not
    if ledger_bound && !crate::params::canon_live() {
        if !verify_member_ledger_under_with(&mt.agg, &published, p.ring_commit, output_notes_root, seed, true) {
            return None;
        }
    } else if !mt.agg.is_empty() {
        return None; // one encoding: no member proof travels beside the joined one
    }
    let mut admit = crate::note_transition::verify_ledger_on_wire_with(
        nt,
        output_notes_root,
        p.seed_commit,
        oli_tags,
        p.padded_tags,
        ledger_bound,
    )?;
    // The body bind (spec §3.2), only where the body is held: out cells that are not the header slots derived from it
    // (or a body no slots derive from) receive none of this block's notes — on every node that holds it, whenever it
    // is held. Never a spend verdict: that would split a holder from a node the body never reached.
    if let Some(body) = p.real_notes {
        // §20.2: the header slots follow the record's cover key; a held body without its key cannot be bound (refused).
        let bound_body = p.cover_key.is_some_and(|k| {
            crate::note_transition::header_note_cms_of_bodies(body, &k)
                .is_some_and(|hc| crate::note_transition::ledger_outs_are_the_header_slots(&published, &hc))
        });
        if !bound_body {
            admit.refuse_notes();
        }
    }
    Some((admit, Vec::new()))
}

/// §RF-3 — a ledger block's rows as the spends a refused ring commit strips at the fold: every row whose four cells
/// the ledger itself states (flags all zero — a spend row or a cover row; the two cannot be told apart, so a block
/// whose ring commit is not canonical has NO row counted). A row carrying a justified cell is another object's, judged
/// by that object. `None` on a list that does not decode.
#[must_use]
pub fn ledger_rows_as_spends(nt: &crate::note_transition::NoteTransition) -> Option<Vec<crate::note_transition::SpendTuple>> {
    use usdm_decider::slot_ledger::{PUB_FLAGS, PUB_LC, PUB_OUT0, PUB_OUT1, PUB_TAG0, PUB_TAG1};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let rows = crate::note_transition::decode_ledger_published(&nt.tuples)?;
    Some(
        rows.iter()
            .filter(|p| p[PUB_FLAGS][..4].iter().all(|f| *f == 0))
            .map(|p| crate::note_transition::SpendTuple {
                out0_cm: b(p[PUB_OUT0]),
                out1_cm: b(p[PUB_OUT1]),
                nullifier: b(p[PUB_TAG0]),
                leaf_commit: b(p[PUB_LC]),
                tag1: b(p[PUB_TAG1]),
            })
            .collect(),
    )
}

/// ⛔⛔ DB-329 §7e × §RF-3 — the rows a note transition STATES as spends, in either of its two wire layouts: a ledger
/// block's list ([`ledger_rows_as_spends`], 7 × 32 B rows) or a legacy tuple list (`spend_tuples`, 5 × 32 B). The
/// fold's re-spend contest reads its items here, so two sibling claims of one slot are ONE contest whichever layout
/// laid them. MEASURED 2026-10-24: the contest chunked a ledger list as 5 × 32 B tuples, read no claim tag, and each
/// node kept its OWN producer's claim (`db329_two_claims_…` A `[true,false]`, B `[false,true]`). `None` on a list
/// that decodes in neither layout.
#[must_use]
pub fn stated_spend_rows(nt: &crate::note_transition::NoteTransition) -> Option<Vec<crate::note_transition::SpendTuple>> {
    if Some(nt.shape) == crate::note_transition::ledger_shape_wire() {
        return ledger_rows_as_spends(nt);
    }
    crate::note_transition::spend_tuples(nt)
}

/// ⭐ DB-223 — THE CROSS-BIND: the member tuple speaks for EXACTLY this spend. Its `binder` is the spend's nullifier,
/// its `leaf_commit` is the spend's own (the value the spend carrier already proved), and its `outs` is the digest of
/// the spend's two outputs. A member statement proved for one spend therefore cannot vouch for another's input or
/// another's outputs.
#[must_use]
pub fn cross_binds(member: &MemberTuple, spend: &crate::note_transition::SpendTuple) -> bool {
    let Some(nf) = crate::spend_frontier::cm_bytes_to_root(&spend.nullifier) else { return false };
    let Some(lc) = crate::spend_frontier::cm_bytes_to_root(&spend.leaf_commit) else { return false };
    let Some(outs) = outs_digest(&spend.out0_cm, &spend.out1_cm) else { return false };
    member.binder == nf && member.leaf_commit == lc && member.outs == outs
}

/// TESTS: one wallet input's full depth-64 path (distinct per `i`) and its member carrier — the one fixture every
/// membership pin builds from, so no two pins disagree on what an honest carrier is.
#[cfg(test)]
pub fn test_member_carrier(i: u64) -> (Vec<u8>, MemberTuple) {
    let lanes = usdm_decider::poseidon2_compress::lanes_of;
    let leaf = lanes(&[1_000 + i, 3, 5, 7]);
    let sibs: Vec<Digest4> =
        (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH as u64).map(|l| lanes(&[l, i, 11])).collect();
    let dirs: Vec<bool> = (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH).map(|l| (l as u64 + i) % 3 == 0).collect();
    let binder = lanes(&[2_000 + i, 13]);
    let outs = lanes(&[3_000 + i, 17]);
    usdm_decider::member_path_gate::prove_member_path_carrier(leaf, &sibs, &dirs, binder, crate::spend_frontier::TEST_LC_BLIND, outs)
        .expect("an honest full-depth path proves")
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn tuple(i: u64) -> MemberTuple {
        let l = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, i, 7, 9]);
        MemberTuple { leaf_commit: l(1), binder: l(2), anchor: l(3), outs: l(4) }
    }

    fn carrier(i: u64) -> (Vec<u8>, MemberTuple) {
        test_member_carrier(i)
    }

    /// ⭐ DB-223 — THE BLOCK'S MEMBERSHIP TRANSITION CROSSES THE WIRE AND A PEER VERIFIES IT FROM THE BYTES ALONE, and
    /// every tamper of what it stands over is refused: an anchor flipped in the list, two tuples reordered, a tuple
    /// dropped, and the same aggregate presented for ANOTHER block's notes root.
    /// TWO-PARTY-REVIEWED: the PRODUCER side builds and encodes; the PEER side decodes the postcard bytes into a fresh
    /// value and verifies with nothing shared but those bytes and the block's header root — the boundary a real graft
    /// crosses. The two-Node pin (one node produces the block, a second grafts it and admits the spend) is the graft
    /// door's, added with the block field.
    /// CALIBRATION: the honest transition verifies on the peer and returns exactly the carriers' tuples, in order.
    /// ⭐ THE VERIFIED-TRANSITION CACHE (`crate::verify_cache`, Bitcoin's script-execution cache) — the fold re-verifies a
    /// block's member transition the graft already verified; a second verify of BYTE-IDENTICAL inputs must answer what the
    /// verifier answered without re-running it, and every tamper must still be verified in full and refused.
    /// TAMPER: the cached transition presented for another block's root, and with one proof byte flipped — both refused, each
    /// by a real verifier run; a refusal is never cached (the same tamper runs the verifier again).
    #[test]
    fn a_verified_member_transition_is_not_re_proved_and_every_tamper_is_still_refused_in_full() {
        let runs = crate::verify_cache::runs_on_this_thread;
        let carriers = vec![carrier(41), carrier(42)];
        let root = crate::hash::Hash32::hash(b"verify-cache-mt-root");
        let mt = build(&carriers, &root).expect("the producer folds two member carriers");
        let r0 = runs();
        let first = verify(&mt, &root).expect("calibration: the honest transition verifies");
        assert_eq!(runs() - r0, 1, "calibration: the first verify ran the verifier");
        let second = verify(&mt, &root).expect("the honest transition verifies again");
        assert_eq!(first, second, "a hit answers what the verifier answered");
        assert_eq!(runs() - r0, 1, "a second verify of byte-identical inputs re-ran the verifier — the cache is not consulted");
        let other = crate::hash::Hash32::hash(b"verify-cache-mt-other-root");
        assert!(verify(&mt, &other).is_none(), "⛔ TAMPER: the cached transition presented for ANOTHER block's root was admitted");
        assert_eq!(runs() - r0, 2, "the other root is a different statement: a full verify");
        let mut bad = mt.clone();
        let i = bad.agg.len() / 2;
        bad.agg[i] ^= 1;
        assert!(verify(&bad, &root).is_none(), "⛔ TAMPER: a flipped proof byte was admitted");
        assert_eq!(runs() - r0, 3, "a flipped proof byte is a different key: a full verify");
        assert!(verify(&bad, &root).is_none(), "⛔ TAMPER: a flipped proof byte was admitted on its second presentation");
        assert_eq!(runs() - r0, 4, "⛔ a REFUSAL was cached: the same tamper did not run the verifier again");
    }

    /// §RF-3 (R5) — the membership aggregate is ONE size whatever the real spend count (the Block::member_transition
    /// register row). The count leak is only the tuple list (n × MEMBER_TUPLE_BYTES) and the shape's n word; the
    /// aggregate itself is the floor every block with a spend pays (DB-378 cost attribution).
    #[test]
    fn the_member_aggregate_is_one_size_whatever_the_real_spend_count() {
        let root = crate::hash::Hash32::hash(b"rf3-mt-agg-root");
        let one = build(&[carrier(1)], &root).expect("the producer folds one member carrier");
        let two = build(&[carrier(1), carrier(2)], &root).expect("the producer folds two member carriers");
        eprintln!(
            "[§RF-3 magg] n=1 agg={} B tuples={} B · n=2 agg={} B tuples={} B",
            one.agg.len(),
            one.tuples.len(),
            two.agg.len(),
            two.tuples.len()
        );
        assert!(verify(&one, &root).is_some() && verify(&two, &root).is_some(), "both transitions verify");
        assert_eq!(one.agg.len(), two.agg.len(), "⛔ the member aggregate's size tracks the real spend count");
        assert_eq!(
            (one.tuples.len(), two.tuples.len()),
            (MEMBER_TUPLE_BYTES, 2 * MEMBER_TUPLE_BYTES),
            "n × MEMBER_TUPLE_BYTES tuples"
        );
        let differing: Vec<usize> = (0..8).filter(|&i| one.shape[i] != two.shape[i]).collect();
        assert_eq!(differing, vec![7], "⛔ a shape word other than n tracks the real spend count");
    }

    #[test]
    fn db223_a_membership_transition_verifies_and_refuses_every_tamper_of_its_list() {
        // PRODUCER.
        let carriers = vec![carrier(1), carrier(2)];
        let root = crate::hash::Hash32::hash(b"db223-mt-notes-root");
        let wire = postcard::to_allocvec(&build(&carriers, &root).expect("the producer folds two member carriers"))
            .expect("the transition encodes");
        // PEER: only the bytes and the header root.
        let peer = |bytes: &[u8]| -> Option<Vec<MemberTuple>> {
            let mt: MemberTransition = crate::chain_object::decode_exact(bytes)?;
            verify(&mt, &root)
        };
        let got = peer(&wire).expect("CALIBRATION: the honest transition verifies on the peer");
        assert_eq!(got, carriers.iter().map(|(_, t)| *t).collect::<Vec<_>>(), "it returns exactly the proven tuples");

        let mt: MemberTransition = postcard::from_bytes(&wire).expect("decodes");
        let enc = |m: &MemberTransition| postcard::to_allocvec(m).expect("encodes");
        let mut flipped = mt.clone();
        flipped.tuples[2 * 32] ^= 1; // tuple 0's anchor, first byte
        assert!(peer(&enc(&flipped)).is_none(), "⛔ a list whose anchor was re-pointed verified on the peer");

        let mut swapped = mt.clone();
        let (a, b) = swapped.tuples.split_at_mut(MEMBER_TUPLE_BYTES);
        a.swap_with_slice(&mut b[..MEMBER_TUPLE_BYTES]);
        assert!(peer(&enc(&swapped)).is_none(), "⛔ a list with two tuples reordered verified on the peer");

        let mut dropped = mt.clone();
        dropped.tuples.truncate(MEMBER_TUPLE_BYTES);
        assert!(peer(&enc(&dropped)).is_none(), "⛔ a list with a tuple dropped verified on the peer");

        let other = crate::hash::Hash32::hash(b"db223-mt-another-block");
        assert!(verify(&mt, &other).is_none(), "⛔ a membership transition verified for ANOTHER block's notes");
    }

    /// The wire form round-trips exactly, and a truncated or non-canonical tuple is refused (fail-closed).
    #[test]
    fn db223_a_member_tuple_round_trips_and_a_malformed_one_is_refused() {
        let t = tuple(5);
        let mut b = Vec::new();
        write_tuple(&t, &mut b);
        assert_eq!(b.len(), MEMBER_TUPLE_BYTES);
        assert_eq!(read_tuple(&b), Some(t), "the wire form round-trips");
        assert_eq!(read_tuple(&b[..MEMBER_TUPLE_BYTES - 1]), None, "a truncated tuple is refused");
        let mut bad = b.clone();
        bad[31] = 0xff; // the top byte of a canonical digest is 0 (eight 31-bit lanes)
        assert_eq!(read_tuple(&bad), None, "a non-canonical digest is refused");
    }

    /// `outs` binds BOTH outputs, in order: swapping them or changing one changes the digest.
    #[test]
    fn db223_outs_digest_binds_both_outputs_in_order() {
        let c = |v: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[v, 1, 2]));
        let (a, b) = (c(11), c(12));
        let ab = outs_digest(&a, &b).expect("canonical outputs");
        assert_ne!(Some(ab), outs_digest(&b, &a), "the order of the outputs is bound");
        assert_ne!(Some(ab), outs_digest(&a, &c(13)), "the second output is bound");
        assert_ne!(Some(ab), outs_digest(&c(10), &b), "the first output is bound");
    }

    /// ⛔ The cross-bind refuses a member tuple for ANOTHER spend: a different nullifier, a different leaf commitment,
    /// or different outputs. CALIBRATION: the tuple built from the spend's own values binds.
    #[test]
    fn db223_a_member_tuple_binds_only_its_own_spend() {
        let c = |v: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[v, 3, 4]));
        let spend = crate::note_transition::SpendTuple { out0_cm: c(21), out1_cm: c(22), nullifier: c(23), leaf_commit: c(24), tag1: c(25) };
        let root = |b: &[u8; 32]| crate::spend_frontier::cm_bytes_to_root(b).expect("canonical");
        let honest = MemberTuple {
            leaf_commit: root(&spend.leaf_commit),
            binder: root(&spend.nullifier),
            anchor: usdm_decider::poseidon2_compress::lanes_of(&[99]),
            outs: outs_digest(&spend.out0_cm, &spend.out1_cm).expect("canonical"),
        };
        assert!(cross_binds(&honest, &spend), "CALIBRATION: the spend's own member tuple binds");
        let mut t = honest;
        t.binder = root(&c(30));
        assert!(!cross_binds(&t, &spend), "⛔ a member tuple scoped to ANOTHER nullifier bound this spend");
        let mut t = honest;
        t.leaf_commit = root(&c(31));
        assert!(!cross_binds(&t, &spend), "⛔ a member tuple for ANOTHER leaf bound this spend");
        let mut t = honest;
        t.outs = outs_digest(&c(22), &c(21)).expect("canonical");
        assert!(!cross_binds(&t, &spend), "⛔ a member tuple vouching for OTHER outputs bound this spend");
    }

    /// §RF-3 §12 — the member plan is the note plan's projection `(spend_of, slot_lc)`, for any spend count and any
    /// justified cells (the producer derives one from the other; a drift would lay a member row against the wrong note row).
    #[test]
    fn the_member_plan_is_the_note_plan_projection() {
        let seed = usdm_decider::poseidon2_compress::lanes_of(&[0x5eed, 1]);
        let j = |k: u64| usdm_decider::poseidon2_compress::lanes_of(&[0x77, k]);
        let filing = |_: &Digest4, _: &Digest4| Some(usdm_decider::poseidon2_compress::lanes_of(&[0xd]));
        for (n, js) in [(0usize, 0u64), (1, 0), (5, 3), (usdm_decider::settlement_delta::LEDGER_ROWS, 0)] {
            let jn: Vec<Digest4> = (0..js).map(j).collect();
            let plan = usdm_decider::settlement_delta::plan_ledger_rows(seed, n, &jn, &jn, &filing).expect("plans");
            let proj: Vec<(Option<usize>, u64)> = plan.iter().map(|r| (r.spend_of, r.witness.slot_lc)).collect();
            assert_eq!(Some(proj), ledger_member_plan(n), "n = {n}, justified = {js}");
        }
        assert!(ledger_member_plan(usdm_decider::settlement_delta::LEDGER_ROWS + 1).is_none());
    }

    /// ⭐ §RF-3 §12 (R5, Block::member_transition) — A QUIET AND A BUSY BLOCK CARRY MEMBER PROOFS OF ONE LENGTH, and a
    /// peer verifies each from the note ledger's list, the header seed commitment and ITS OWN ring alone. Every tamper
    /// rejects: the busy proof under the quiet list, a peer whose ring lacks the anchor, a flipped spend nullifier cell,
    /// another seed commit. TWO-PARTY-REVIEWED: the producer side is `build_member_ledger`; the peer side is
    /// `verify_member_ledger`, sharing nothing but the proof bytes, the list and the public roots.
    #[test]
    fn a_quiet_and_a_busy_member_ledger_are_one_length_and_every_tamper_rejects() {
        use usdm_decider::settlement_delta::{LedgerPublished, LEDGER_ROWS};
        use usdm_decider::slot_ledger::{cover_lc_native, seed_commit_native, PUB_DIGESTS, PUB_LC, PUB_OUT0, PUB_OUT1, PUB_TAG0};
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let (o0, o1) = (lanes(&[0x0a, 1]), lanes(&[0x0a, 2]));
        let b = crate::spend_frontier::leaf_to_cm_bytes;
        let outs = outs_digest(&b(o0), &b(o1)).expect("canonical outputs");
        let sibs: Vec<Digest4> = (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH as u64).map(|l| lanes(&[l, 9, 11])).collect();
        let dirs: Vec<bool> = (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH).map(|l| l % 3 == 0).collect();
        let binder = lanes(&[0x0b, 13]);
        let carrier = usdm_decider::member_path_gate::prove_member_path_carrier(
            lanes(&[0x1e, 3, 5, 7]), &sibs, &dirs, binder, crate::spend_frontier::TEST_LC_BLIND, outs,
        )
        .expect("an honest path proves");
        let t = carrier.1;
        let seed = lanes(&[0x5eed, 2]);
        let row = |lc: Digest4, k: u64| -> LedgerPublished {
            let mut p = [[0u64; usdm_decider::poseidon2_compress::DIGEST_LANES]; PUB_DIGESTS];
            (p[PUB_LC], p[PUB_TAG0], p[PUB_OUT0], p[PUB_OUT1]) = (lc, lanes(&[0xc0, k]), lanes(&[0xc1, k]), lanes(&[0xc2, k]));
            p
        };
        let quiet: Vec<LedgerPublished> = (0..LEDGER_ROWS).map(|r| row(cover_lc_native(seed, r as u64 + 1), r as u64)).collect();
        let mut busy: Vec<LedgerPublished> = (0..LEDGER_ROWS).map(|r| row(cover_lc_native(seed, r as u64), r as u64)).collect();
        (busy[0][PUB_LC], busy[0][PUB_TAG0], busy[0][PUB_OUT0], busy[0][PUB_OUT1]) = (t.leaf_commit, binder, o0, o1);
        let ring = [lanes(&[0xdec0]), t.anchor];
        let onr = crate::hash::Hash32::hash(b"rf3-member-onr");
        let commit = seed_commit_native(seed);
        let bp = build_member_ledger(&[carrier.clone()], &busy, &ring, &onr, seed).expect("the busy ledger proves");
        let qp = build_member_ledger(&[], &quiet, &ring, &onr, seed).expect("the quiet ledger proves");
        eprintln!("[rf3-member] busy {} B · quiet {} B", bp.len(), qp.len());
        assert_eq!(bp.len(), qp.len(), "⛔ the member proof's length moves with the real spend count");
        assert!(verify_member_ledger(&bp, &busy, &ring, &onr, commit), "the peer admits the honest busy ledger");
        assert!(verify_member_ledger(&qp, &quiet, &ring, &onr, commit), "the peer admits the honest quiet ledger");
        assert!(!verify_member_ledger(&bp, &quiet, &ring, &onr, commit), "⛔ the busy proof under the quiet list");
        assert!(!verify_member_ledger(&bp, &busy, &[ring[0], lanes(&[0xdec1])], &onr, commit), "⛔ a ring without the anchor");
        let mut nf = busy.clone();
        nf[0][PUB_TAG0] = lanes(&[0x0b, 14]);
        assert!(!verify_member_ledger(&bp, &nf, &ring, &onr, commit), "⛔ a flipped spend nullifier cell");
        assert!(!verify_member_ledger(&bp, &busy, &ring, &onr, seed_commit_native(lanes(&[1]))), "⛔ another seed commit");
        // §RF-3: the header-anchored door — a peer holding NO ring admits under the producer's commit, refuses another
        // ring's commit and a non-canonical word naming the same lanes.
        let rc = ring_commit_of(&ring).expect("the ring states");
        assert!(verify_member_ledger_under(&bp, &busy, &rc, &onr, commit), "the peer admits under the header's ring commit");
        let foreign = ring_commit_of(&[ring[0], lanes(&[0xdec1])]).expect("a foreign ring states");
        assert_ne!(rc, foreign, "two rings, one commit");
        assert!(!verify_member_ledger_under(&bp, &busy, &foreign, &onr, commit), "⛔ a foreign ring commit");
        let mut bad = rc;
        bad.0[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!verify_member_ledger_under(&bp, &busy, &bad, &onr, commit), "⛔ a non-canonical ring commit lane");
        assert!(build_member_ledger(&[carrier.clone()], &busy, &ring[..1], &onr, seed).is_none(), "⛔ an anchor outside the producer's ring");
        // THE ARMED SWITCH (sim speed): the bound double lays the same statement; the armed door admits it and refuses
        // the real proof, the real door refuses the seal, and every statement tamper above is refused on the armed door.
        let bb = build_member_ledger_with(&[carrier.clone()], &busy, &ring, &onr, seed, true).expect("the double lays");
        let qb = build_member_ledger_with(&[], &quiet, &ring, &onr, seed, true).expect("the quiet double lays");
        assert_eq!(bb.len(), qb.len(), "⛔ the double's length moves with the real spend count");
        let armed = |p: &[u8], l: &[usdm_decider::settlement_delta::LedgerPublished], rc: &crate::hash::Hash32, sc: Digest4| {
            verify_member_ledger_under_with(p, l, rc, &onr, sc, true)
        };
        assert!(armed(&bb, &busy, &rc, commit) && armed(&qb, &quiet, &rc, commit), "the armed door admits the honest doubles");
        assert!(!armed(&bp, &busy, &rc, commit), "⛔ the armed door admitted a real proof (the forms crossed doors)");
        assert!(!verify_member_ledger_under(&bb, &busy, &rc, &onr, commit), "⛔ the real door admitted the seal");
        assert!(!armed(&bb, &quiet, &rc, commit), "⛔ armed: the busy seal under the quiet list");
        assert!(!armed(&bb, &nf, &rc, commit), "⛔ armed: a flipped spend nullifier cell");
        assert!(!armed(&bb, &busy, &foreign, commit), "⛔ armed: a foreign ring commit");
        assert!(!armed(&bb, &busy, &bad, commit), "⛔ armed: a non-canonical ring commit lane");
        assert!(!armed(&bb, &busy, &rc, seed_commit_native(lanes(&[1]))), "⛔ armed: another seed commit");
        assert!(build_member_ledger_with(&[carrier], &busy, &ring[..1], &onr, seed, true).is_none(), "⛔ armed: an anchor outside the ring");
    }
}
// Moved here from `impl Node` (stage A of the node split, lane dcash 2026-11-11): a pure constant / function the lower modules read;
// `Node` keeps an alias so every existing caller resolves.
/// Is `len` a membership endpoint's width: the one-step form's, or the ring-anchored member leg's tuple (§19, 2026-10-28).
#[must_use]
pub fn membership_endpoint_len_ok(len: usize) -> bool {
    const SLOT: usize = crate::spend_frontier::DIGEST_LANE_BYTES;
    len == 4 * SLOT + 8 || len == MEMBER_TUPLE_BYTES
}


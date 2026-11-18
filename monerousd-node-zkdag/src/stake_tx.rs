// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-237 — THE PRIVATE STAKE IS ONE CHAIN OBJECT: STAKE, CLAIM AND UNSTAKE, WIRE-IDENTICAL.
//!
//! A staked note is an ordinary note whose commitment carries the stake tag (`whir_rec_block::stake_tag(e0)`), so it is
//! indistinguishable from any other note. ONE gate (`whir_rec_block::StakeGate`) moves value into, along and out of a
//! stake, so the object below states the same fields for all three:
//!   * the input note's nullifier (the replay key — the SPENT SET refuses a second use, DB-353's lane tag);
//!   * the two output commitments (the principal, staked from `e_now` or returned as USDm; the change or the reward);
//!   * the membership cross-bind (the input note's record, re-verified at the `MemberDoor::Fold` door);
//!   * `reward_commit` = `solvency_commit_256(r, r_blind)` — the reward, exactly `floor(v·rate·Δ/D)`, never on the wire;
//!   * `new_minted_commit` + the yield SUPPLY carrier: the committed USDm supply grows by exactly that reward, inside the
//!     reserve's over-collateralization (`confidential_solvency::verify_yield_mint_carrier`, opening `reward_commit`);
//!   * `sealed`: `(r, r_blind)` sealed to each bonded custodian, so every custodian advances its private opening of the
//!     supply (the peg classes' DB-58 leg). Nothing else learns `r`.
//!
//! ⛔ RULES EVERY NODE CHECKS AT THE FOLD (`apply_chain_stake`), from the object's bytes and its own state alone:
//!   * `e_now` IS the epoch of the carrying block's header timestamp — a principal can be (re-)staked only from NOW, so
//!     no stake backdates its start and no claim pays an interval twice;
//!   * `rate_bps` IS this chain's governance rate (`ChainParams::stake_reward_apr_bps`) — the amount is derived by every
//!     node, never declared;
//!   * the membership cross-bind names a record folded before this block (`MemberDoor::Fold`).
//!
//! What it replaced (DB-237): a yield claim bound to a stake frontier nothing bound (any note harvested, each principal
//! re-harvested), a rate nothing set, a stake published as `cm ‖ amount ‖ future nullifier` (DB-327) — and a frontier
//! appended by the producer alone.

use crate::chain_object::{decode_exact, unframe, Class};
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// The fixed-width head of a stake object: everything the gates decide on. No amount, no key, no start epoch.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StakeHeader {
    /// The input note's nullifier, canonical bytes.
    pub nullifier: [u8; 32],
    /// The epoch the principal is (re-)staked from: the carrying block's epoch.
    pub e_now: u64,
    /// The governance rate the reward was computed at.
    pub rate_bps: u32,
    pub out0_cm: Digest4,
    pub out1_cm: Digest4,
    pub leaf_commit: Digest4,
    pub reward_commit: Digest4,
    /// ⭐ §BR-3 17.6 (stakers' half): the committed TOTAL the stakers' pool has paid out, after this reward. The reward is
    /// paid from the pool's fees (already out of circulation), so the USDm supply commitment does not move.
    /// The bound `paid ≤ inflow` is read by every node against its own epoch-`e_now` pool snapshot
    /// (`PegLedger::stakers_pool_snapshot`): no field here states the pool (the pools are served to nobody).
    pub new_paid_commit: Digest4,
}

/// The EXACT payload type: header, the stake carrier, the supply carrier, the membership carrier, the membership tip, the
/// two output notes, their two owner clues, and the sealed reward legs `(custodian id, envelope)`.
pub type StakePayload = (
    StakeHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    // O1-FOOTPRINT-REVIEWED: exactly STAKE_NOTE_COUNT clues of at most OWNER_CLUE_MAX each (`decode` refuses others).
    Vec<Vec<u8>>,
    // O1-FOOTPRINT-REVIEWED: at most PEG_ATTEST_SEALED_MAX envelopes, one per bonded custodian (`decode` refuses more).
    Vec<([u8; 32], Vec<u8>)>,
);

/// The notes a stake object credits: the principal and the second output — one owner clue each.
pub const STAKE_NOTE_COUNT: usize = 2;

/// A decoded stake object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeDecoded {
    pub h: StakeHeader,
    pub stake_carrier: Vec<u8>,
    pub supply_carrier: Vec<u8>,
    pub membership_carrier: Vec<u8>,
    pub membership_tip: Vec<u8>,
    pub out0: Vec<u8>,
    pub out1: Vec<u8>,
    pub owner_clues: Vec<Vec<u8>>,
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
}

/// The canonical payload bytes (unframed). Postcard into a `Vec` of plain structs, byte vectors and fixed arrays has no
/// failing case (no map, no non-serializable type, no fixed buffer to overflow), so a failure here is a broken build.
#[must_use]
pub fn encode(d: &StakeDecoded) -> Vec<u8> {
    crate::fixed::encode_plain(&(
        &d.h,
        &d.stake_carrier,
        &d.supply_carrier,
        &d.membership_carrier,
        &d.membership_tip,
        &d.out0,
        &d.out1,
        &d.owner_clues,
        &d.sealed,
    ))
}

/// The FRAMED blob — the one form this object travels in (under the `YieldClaim` class tag).
#[must_use]
pub fn wire(d: &StakeDecoded) -> Vec<u8> {
    crate::chain_object::frame(Class::YieldClaim, &encode(d))
}

// CHAIN-PUBLISH-REVIEWED: a wire-field parser (bytes → typed object); it moves nothing.
/// Refuses rather than guesses; strict full-consumption decode. The bounds live HERE: a stake object with no carrier, no
/// membership, an all-zero cross-bind, an owner clue missing or oversized, a carried note the statement does not name,
/// or more sealed legs than custodians is not an object at all.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<StakeDecoded> {
    let (h, stake_carrier, supply_carrier, membership_carrier, membership_tip, out0, out1, owner_clues, sealed) =
        decode_exact::<StakePayload>(payload)?;
    if owner_clues.len() != STAKE_NOTE_COUNT
        || owner_clues.iter().any(|c| c.is_empty() || c.len() > crate::peg_in_tx::OWNER_CLUE_MAX)
    {
        return None;
    }
    if stake_carrier.is_empty() || supply_carrier.is_empty() || membership_carrier.is_empty() {
        return None;
    }
    if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest()
        || sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX
    {
        return None;
    }
    if crate::spend_frontier::note_cm_of(&out0) != Some(h.out0_cm) || crate::spend_frontier::note_cm_of(&out1) != Some(h.out1_cm) {
        return None; // a carried note the stake carrier never bound
    }
    Some(StakeDecoded { h, stake_carrier, supply_carrier, membership_carrier, membership_tip, out0, out1, owner_clues, sealed })
}

/// The stake carrier's public statement, rebuilt from the header (`reward` / `out1_value` are private and unread).
#[must_use]
pub fn statement(h: &StakeHeader) -> Option<usdm_decider::whir_rec_block::StakeOutputs> {
    Some(usdm_decider::whir_rec_block::StakeOutputs {
        out_cms: [h.out0_cm, h.out1_cm],
        nullifier: crate::spend_frontier::cm_bytes_to_root(&h.nullifier)?,
        leaf_commit: h.leaf_commit,
        reward_commit: h.reward_commit,
        reward: 0,
        out1_value: 0,
    })
}

/// ⭐ §BR-3 17.6 — THE STAKE REQUEST'S PUBLIC PARTS, as the custodial request lane carries them (`peg_attest::PegRequest`
/// of kind `PEG_REQUEST_STAKE`): `id` = the input's nullifier; `recipient` = `e_now (8 LE) ‖ rate_bps (4 LE) ‖ 0…`;
/// `note_payload` = the two output notes (each `PQ_NOTE_BYTES`) then their OLI clue records (`cm ‖ len ‖ clue`, the one
/// clue-list codec, keyed to the two notes in order); `carrier` = the stake carrier; `delta_commit` = the reward commitment.
/// The reward and its blind ride sealed per custodian (`value_a`, `d_blind`). One builder and one reader, so the lane and
/// the door agree byte for byte.
#[must_use]
pub fn request_public(
    h: &StakeHeader,
    out0: &[u8],
    out1: &[u8],
    clues: &[Vec<u8>],
) -> Option<([u8; 32], Vec<u8>)> {
    let n = crate::cover::PQ_NOTE_BYTES;
    if out0.len() != n || out1.len() != n || clues.len() != 2 {
        return None;
    }
    let mut recipient = [0u8; 32];
    recipient[..8].copy_from_slice(&h.e_now.to_le_bytes());
    recipient[8..12].copy_from_slice(&h.rate_bps.to_le_bytes());
    let recs: Vec<([u8; 32], Vec<u8>)> = [out0, out1]
        .iter()
        .zip(clues)
        .map(|(note, clue)| <[u8; 32]>::try_from(&note[..32]).map(|cm| (cm, clue.clone())))
        .collect::<Result<_, _>>()
        .ok()?;
    let mut payload = Vec::with_capacity(2 * n + 256);
    payload.extend_from_slice(out0);
    payload.extend_from_slice(out1);
    payload.extend_from_slice(&crate::oli::encode_note_clue_records(&recs));
    Some((recipient, payload))
}

/// The reader paired with [`request_public`]: the stake header (its paid-out commitment zero — the executing custodian's
/// supply step fills it), the two notes and their clues. `None` on any width, codec or key mismatch.
#[must_use]
pub fn request_parts(req: &crate::peg_attest::PegRequest) -> Option<(StakeHeader, Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let n = crate::cover::PQ_NOTE_BYTES;
    if req.kind != crate::peg_attest::PEG_REQUEST_STAKE || req.note_payload.len() < 2 * n {
        return None;
    }
    let (out0, rest) = req.note_payload.split_at(n);
    let (out1, recs) = rest.split_at(n);
    let recs = crate::oli::parse_note_clue_records(recs)?;
    if recs.len() != 2 || recs[0].0[..] != out0[..32] || recs[1].0[..] != out1[..32] {
        return None;
    }
    if req.recipient[12..].iter().any(|b| *b != 0) {
        return None;
    }
    let e_now = u64::from_le_bytes(req.recipient[..8].try_into().ok()?);
    let rate_bps = u32::from_le_bytes(req.recipient[8..12].try_into().ok()?);
    let h = StakeHeader {
        nullifier: req.id,
        e_now,
        rate_bps,
        out0_cm: req.out0_cm,
        out1_cm: req.out1_cm,
        leaf_commit: req.leaf_commit,
        reward_commit: req.delta_commit,
        new_paid_commit: usdm_decider::poseidon2_compress::zero_digest(),
    };
    Some((h, out0.to_vec(), out1.to_vec(), recs.into_iter().map(|(_, c)| c).collect()))
}

/// What applying a stake object did.
#[derive(PartialEq, Eq, Debug)]
pub enum StakeApply {
    /// Not a stake object — left entirely alone.
    NotStake,
    /// The input spent, the supply advanced and both notes credited on THIS node, from the bytes.
    Applied,
    /// Refused before anything moved; a fixed reason.
    Refused(&'static str),
}

// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the object at its block's canonical fold — the publish half is
// `Node::execute_stake`, which frames the object and admits it.

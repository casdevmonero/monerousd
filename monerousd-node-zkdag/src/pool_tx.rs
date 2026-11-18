// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ LIQUIDATION SPEC §10 — A STABILITY-POOL DEPOSIT IS A CHAIN OBJECT.
//!
//! A USDm holder moves `d` into one PSM's stability pool (Liquity's shape): the pool's committed USDm total `T` grows by
//! exactly `d`, and the depositor receives a RECEIPT note keyed to the pool's snapshot at that moment
//! (`whir_rec_block::receipt_spend_key`). The object carries every proof a node needs, from its own bytes:
//!   * the DEPOSIT carrier (`verify_pool_deposit_bytes`): the depositor spent a USDm note of `v`, the receipt holds `d`, the
//!     change holds `v − d`, and `dv = commit(d)` — no amount on the wire;
//!   * the SNAPSHOT carrier (`verify_pool_snapshot_bytes`): the receipt's `(PD, SD)` re-randomize the pool's CURRENT
//!     `(P, S)` words — an executor cannot key a receipt to a snapshot it invented (a tiny `P_dep` would drain the pool);
//!   * the pool TRANSITION (`verify_transition_carrier`, `StabilityPool`): `T + d = T′` over the SAME `dv`;
//!   * the membership cross-bind of the spent note (`MemberDoor::Fold`);
//!   * `sealed`: `(d, dv_blind)` per bonded custodian, so each advances its private opening of `T`.
//!
//! §9.6 for this door: (1) PoW — rides a block; (2) proof — the three carriers + membership, verified at the fold on every
//! node; (3) conservation — the deposit carrier's in-circuit `v = d + change` and the transition's `T + d = T′` over one `dv`;
//! (4) replay — the spent note's nullifier is the object's own lane tag (the spent SET); (5) bounded work — three
//! constant-size carriers, at most `PEG_ATTEST_SEALED_MAX` sealed legs; (6) parity — the stake object's door (§DB-237):
//! membership at the fold door, carriers against this node's own words, the owner clues and notes bound by `decode`.

use crate::chain_object::{decode_exact, unframe, Class};
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// The fixed-width head of a pool deposit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PoolDepositHeader {
    pub asset_id: u32,
    pub epoch: u64,
    pub nullifier: [u8; 32],
    pub leaf_commit: Digest4,
    pub receipt_cm: Digest4,
    pub change_cm: Digest4,
    pub dv: Digest4,
    pub pd: Digest4,
    pub sd: Digest4,
    /// The pool's committed USDm total after the deposit.
    pub new_t: Digest4,
}

/// The decoded object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolDepositDecoded {
    pub h: PoolDepositHeader,
    pub deposit_carrier: Vec<u8>,
    pub snapshot_carrier: Vec<u8>,
    pub transition_carrier: Vec<u8>,
    pub membership_carrier: Vec<u8>,
    pub membership_tip: Vec<u8>,
    pub receipt: Vec<u8>,
    pub change: Vec<u8>,
    pub owner_clues: Vec<Vec<u8>>,
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
}

/// The EXACT payload type.
pub type PoolDepositPayload = (
    PoolDepositHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    // O1-FOOTPRINT-REVIEWED: exactly POOL_DEPOSIT_NOTE_COUNT clues of at most OWNER_CLUE_MAX each.
    Vec<Vec<u8>>,
    // O1-FOOTPRINT-REVIEWED: at most PEG_ATTEST_SEALED_MAX envelopes, one per bonded custodian.
    Vec<([u8; 32], Vec<u8>)>,
);

/// The notes a deposit credits: the receipt and the change.
pub const POOL_DEPOSIT_NOTE_COUNT: usize = 2;

/// The canonical payload bytes. Postcard into a `Vec` of plain structs and byte vectors has no failing case.
#[must_use]
pub fn encode(d: &PoolDepositDecoded) -> Vec<u8> {
    crate::fixed::encode_plain(&(
        &d.h,
        &d.deposit_carrier,
        &d.snapshot_carrier,
        &d.transition_carrier,
        &d.membership_carrier,
        &d.membership_tip,
        &d.receipt,
        &d.change,
        &d.owner_clues,
        &d.sealed,
    ))
}

/// The FRAMED blob.
#[must_use]
pub fn wire(d: &PoolDepositDecoded) -> Vec<u8> {
    crate::chain_object::frame(Class::PoolDeposit, &encode(d))
}

// CHAIN-PUBLISH-REVIEWED: a wire-field parser (bytes → typed object); it moves nothing.
/// Strict full-consumption decode; the bounds live here.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<PoolDepositDecoded> {
    let (h, deposit_carrier, snapshot_carrier, transition_carrier, membership_carrier, membership_tip, receipt, change, owner_clues, sealed) =
        decode_exact::<PoolDepositPayload>(payload)?;
    if owner_clues.len() != POOL_DEPOSIT_NOTE_COUNT
        || owner_clues.iter().any(|c| c.is_empty() || c.len() > crate::peg_in_tx::OWNER_CLUE_MAX)
    {
        return None;
    }
    if deposit_carrier.is_empty() || snapshot_carrier.is_empty() || transition_carrier.is_empty() || membership_carrier.is_empty() {
        return None;
    }
    if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest()
        || sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX
    {
        return None;
    }
    if crate::spend_frontier::note_cm_of(&receipt) != Some(h.receipt_cm) || crate::spend_frontier::note_cm_of(&change) != Some(h.change_cm) {
        return None;
    }
    Some(PoolDepositDecoded {
        h,
        deposit_carrier,
        snapshot_carrier,
        transition_carrier,
        membership_carrier,
        membership_tip,
        receipt,
        change,
        owner_clues,
        sealed,
    })
}

/// The deposit carrier's statement from the header.
#[must_use]
pub fn deposit_statement(h: &PoolDepositHeader) -> Option<usdm_decider::whir_rec_block::PoolDepositStatement> {
    Some(usdm_decider::whir_rec_block::PoolDepositStatement {
        nullifier: crate::spend_frontier::cm_bytes_to_root(&h.nullifier)?,
        leaf_commit: h.leaf_commit,
        receipt_cm: h.receipt_cm,
        change_cm: h.change_cm,
        dv: h.dv,
        pd: h.pd,
        sd: h.sd,
        asset_id: h.asset_id,
        epoch: h.epoch,
    })
}

/// What applying a pool deposit did.
#[derive(PartialEq, Eq, Debug)]
pub enum PoolDepositApply {
    NotPoolDeposit,
    Applied,
    Refused(&'static str),
}

// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the object at its block's canonical fold — the publish half is
// `Node::execute_pool_deposit`.

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐⭐ LIQUIDATION SPEC §10.2 increment 2 — A STABILITY-POOL WITHDRAWAL IS A CHAIN OBJECT.
//
// The receipt's holder spends it (the RECEIPT carrier: the snapshot, `d` and the key all hidden, re-randomized
// commitments published — §10.4) and receives the compounded USDm note `u`; the custodian proves the WITHDRAW carrier
// (`compounded·P_dep + r = d·P_now`) over those re-randomized commitments and the pool's CURRENT `(P, S)` words, and the
// pool transition `T − u`. The collateral GAIN is `d·(S_now − S_dep)/P_dep`; `S` moves only at a liquidation, and the gain
// leg (a reserve release to the holder's sealed destination) lands with the liquidation object, so until then this
// object REQUIRES a zero gain — its gain commitment opens to 0 under the blind the executor names.
//
// §9.6: (1) PoW — rides a block; (2) proof — the receipt carrier, the epoch bridge (over the source words the node reads
// from its OWN ledger), the withdraw carrier over the bridged pair, the transition and the receipt's membership at the
// fold; (3) conservation — `T − u = T′` over the same `du` the receipt carrier binds to the credited note, and `u` is the
// withdraw carrier's rounded-down quotient against the bridged words — a closed epoch's receipt keeps absorbing the next
// epoch's retires through them (H11 §2.5), so the pool never owes more than it holds; (4) replay — the receipt's
// nullifier is the object's own lane tag; (5) bounded work — four constant-size carriers; (6) parity — the deposit's door,
// check for check.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// The fixed-width head of a pool withdrawal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PoolWithdrawHeader {
    pub asset_id: u32,
    pub epoch: u64,
    pub nullifier: [u8; 32],
    pub leaf_commit: Digest4,
    pub out_cm: Digest4,
    pub dd: Digest4,
    pub du: Digest4,
    pub pd: Digest4,
    pub sd: Digest4,
    /// The HIDDEN collateral gain the withdraw carrier proves (`d · (S_now − S_dep) / P_dep`, rounded down): the
    /// depositor's share of every liquidation's seized collateral since its deposit. Opened only by the bonded custodians.
    pub gain_commit: Digest4,
    /// LIQUIDATION §10.2 — the commitment to where the gain is paid (`peg::redeem_commit(redeem_to, r_blind)`, DB-110's
    /// shape): the destination rides only the sealed gain legs, never the wire.
    pub redeem_commit: [u8; 32],
    pub new_t: Digest4,
    /// H11 §2.5 — the BRIDGED `(P, S)` the withdraw carrier settles against (`cs::pool_bridge` of the receipt epoch's
    /// words and the next epoch's, docs/SP-EPOCH-BRIDGE-SPEC-20261022.md): the bridge carrier welds them to the two
    /// source pairs every node reads from its OWN ledger (`PegLedger::receipt_bridge_words`).
    pub pb: Digest4,
    pub sb: Digest4,
}

/// The decoded withdrawal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolWithdrawDecoded {
    pub h: PoolWithdrawHeader,
    pub receipt_carrier: Vec<u8>,
    /// The epoch-bridge carrier (`cs::prove_pool_bridge_carrier`): every withdrawal carries one — a live receipt's is the
    /// identity bridge through the public opening — so the object has ONE shape whatever its receipt's epoch.
    pub bridge_carrier: Vec<u8>,
    pub withdraw_carrier: Vec<u8>,
    pub transition_carrier: Vec<u8>,
    pub membership_carrier: Vec<u8>,
    pub membership_tip: Vec<u8>,
    pub out: Vec<u8>,
    pub owner_clues: Vec<Vec<u8>>,
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
    /// One sealed GAIN leg per bonded custodian (`peg_attest::PegOutDelta`: the gain, the destination and its blind):
    /// what the custodians pay out through the payout book. Sealed even at a zero gain, so no withdrawal is told apart.
    pub gain_sealed: Vec<([u8; 32], Vec<u8>)>,
}

/// The EXACT payload type.
pub type PoolWithdrawPayload = (
    PoolWithdrawHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    // O1-FOOTPRINT-REVIEWED: exactly one clue of at most OWNER_CLUE_MAX bytes.
    Vec<Vec<u8>>,
    // O1-FOOTPRINT-REVIEWED: at most PEG_ATTEST_SEALED_MAX envelopes, one per bonded custodian.
    Vec<([u8; 32], Vec<u8>)>,
    // O1-FOOTPRINT-REVIEWED: the gain legs — at most PEG_ATTEST_SEALED_MAX envelopes, one per bonded custodian.
    Vec<([u8; 32], Vec<u8>)>,
);

/// The canonical payload bytes. Postcard into a `Vec` of plain structs and byte vectors has no failing case.
#[must_use]
pub fn encode_withdraw(d: &PoolWithdrawDecoded) -> Vec<u8> {
    crate::fixed::encode_plain(&(
        &d.h,
        &d.receipt_carrier,
        &d.bridge_carrier,
        &d.withdraw_carrier,
        &d.transition_carrier,
        &d.membership_carrier,
        &d.membership_tip,
        &d.out,
        &d.owner_clues,
        &d.sealed,
        &d.gain_sealed,
    ))
}

/// The FRAMED blob.
#[must_use]
pub fn wire_withdraw(d: &PoolWithdrawDecoded) -> Vec<u8> {
    crate::chain_object::frame(Class::PoolWithdraw, &encode_withdraw(d))
}

// CHAIN-PUBLISH-REVIEWED: a wire-field parser (bytes → typed object); it moves nothing.
/// Strict full-consumption decode; the bounds live here.
#[must_use]
pub fn decode_withdraw(payload: &[u8]) -> Option<PoolWithdrawDecoded> {
    let (h, receipt_carrier, bridge_carrier, withdraw_carrier, transition_carrier, membership_carrier, membership_tip, out, owner_clues, sealed, gain_sealed) =
        decode_exact::<PoolWithdrawPayload>(payload)?;
    if gain_sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX {
        return None;
    }
    if owner_clues.len() != 1 || owner_clues[0].is_empty() || owner_clues[0].len() > crate::peg_in_tx::OWNER_CLUE_MAX {
        return None;
    }
    if receipt_carrier.is_empty() || bridge_carrier.is_empty() || withdraw_carrier.is_empty() || transition_carrier.is_empty() || membership_carrier.is_empty() {
        return None;
    }
    if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest()
        || sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX
        || crate::spend_frontier::note_cm_of(&out) != Some(h.out_cm)
    {
        return None;
    }
    Some(PoolWithdrawDecoded {
        h,
        receipt_carrier,
        bridge_carrier,
        withdraw_carrier,
        transition_carrier,
        membership_carrier,
        membership_tip,
        out,
        owner_clues,
        sealed,
        gain_sealed,
    })
}

/// The receipt carrier's statement from the header.
#[must_use]
pub fn receipt_statement(h: &PoolWithdrawHeader) -> Option<usdm_decider::whir_rec_block::PoolReceiptStatement> {
    Some(usdm_decider::whir_rec_block::PoolReceiptStatement {
        nullifier: crate::spend_frontier::cm_bytes_to_root(&h.nullifier)?,
        leaf_commit: h.leaf_commit,
        out_cm: h.out_cm,
        dd: h.dd,
        du: h.du,
        pd: h.pd,
        sd: h.sd,
        asset_id: h.asset_id,
        epoch: h.epoch,
    })
}

/// What applying a pool withdrawal did.
#[derive(PartialEq, Eq, Debug)]
pub enum PoolWithdrawApply {
    NotPoolWithdraw,
    Applied,
    Refused(&'static str),
}

// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the object at its block's canonical fold — the publish half is
// `Node::execute_pool_withdraw`.

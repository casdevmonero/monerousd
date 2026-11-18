// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::sat_bond_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `sat_bond_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::sat_bond_tx::*;
use crate::hash::Hash32;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// ⛔⛔⛔ THE NODE HALF, SPLIT IN TWO (2026-10-07) — DECIDED at the block's OBJECTS step, SEATED at its BOND step.
///
/// The objects step is retried whenever the record fold behind it refuses (its record bytes are not held yet), and a
/// reorg rewinds it; what it un-does is the peg ledger (`unwind_objects_step`, the C1 before-image). The seat it used to
/// write here — the validator set, the locked note, the lock height — lives OUTSIDE that image, so a retried step met its
/// own first attempt's seat, answered `AlreadyBonded`, stripped the bond's change note from the record and left its
/// nullifier unadmitted, ON THAT NODE ONLY. MEASURED sim-20261007-043933 (fast journey T3): block eaafb9f3 at fold ordinal
/// 744 SEATED, its fold refused (record not held), the retry printed `refused … AlreadyBonded` + `1 note(s) … left this
/// block's record`; the member ring then held two roots at ordinal 744 (n0 vs n2), and the unspent bond input was
/// re-carried 79 times. The lock height was the folding node's own TIP (`tip_height()`), so the unbond's maturity was a
/// fact about arrival: released on n2, refused on n0 and n1 ([4000000, 4000000, 0]).
///
/// The shape is the one the chain already has (DB-274 P2 §8.7, C4): the validator set is the step's FROZEN pre-state
/// while the objects decide, and it moves only in the bond step, whose journal holds every touched validator's
/// before-state for both the refused-fold unwind and the reorg rewind. The lock height is the CARRYING block's blue score
/// (DB-257), a function of the chain.
///
/// Decides: the signature, the weld, the spent note's membership against this node's own record roots, the spent set,
/// and the seat rule (`ValidatorSet::admit_refusal` / `rebond_refusal` — the same rule the seat applies) over the frozen
/// pre-state plus the seats this step already decided (`decided_in_step`: one validator seats once per block). Refused ⇒
/// nothing moves and the fold strips the change note like any refused object's.
#[must_use]
pub fn decide_chain_sat_bond(
    node: &crate::node::Node,
    blob: &[u8],
    decided_in_step: &std::collections::HashSet<[u8; 32]>,
) -> SatBondApply {
    let Some((crate::chain_object::Class::SatBond, payload)) = crate::chain_object::unframe(blob) else {
        return SatBondApply::NotSatBond;
    };
    let Some(t) = SatBondTx::decode(payload) else {
        return SatBondApply::Refused("the payload is not a SAT bond");
    };
    if decided_in_step.contains(&t.vid) {
        return SatBondApply::Refused("a second bond for one validator in one block");
    }
    if let Some(why) = sat_bond_refusal(node, &t, crate::respend::MemberDoor::Fold) {
        eprintln!("[sat-bond] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason
        return SatBondApply::Refused(why);
    }
    SatBondApply::Decided(SatSeat {
        vid: t.vid,
        weight: u128::from(t.weight),
        locked_note: t.notes[0].clone(),
        rebond: t.rebond.is_some(),
    })
}

/// The SEAT, run by the bond step for every bond its block's objects step decided, at the carrying block's blue score
/// `at_blue`. The change note is NOT credited here: it rides the carrying block's own output notes, recorded by the one
/// record writer (a credit staged here would ride this node's NEXT block with no justifying object — a note every peer's
/// graft door refuses and this producer's own record keeps, DB-354). `false` only if the frozen-state decision and the set
/// disagree, which the shared rule makes impossible; it is printed, never silent.
/// SAFE AT SCALE: `seat_entropy` is the id of the block whose fold seats the bond — the chain randomness the new
/// custodian's custody seat is drawn under (`custody_vaults::draw_seat`), which the bonder does not choose.
/// `at_tick` is the carrying block's chain tick (`Node::chain_tick_at`): the anchor the stake lock, a time, is read from
/// (A-F60 — never a blue score read as if blocks came at the target pace).
pub fn seat_sat_bond(node: &mut crate::node::Node, s: &SatSeat, at_tick: u64, seat_entropy: &[u8; 32]) -> bool {
    let seated = if s.rebond {
        // §9: the locked note was consumed into the new one — the seat's custody weight becomes the new total
        node.rebond_validator(s.vid, s.weight).map(|_| ())
    } else {
        node.admit_validator_active_from(s.vid, s.weight, 0, node.seat_active_from(), seat_entropy) // G2b: active from landing + D
    };
    if let Err(e) = seated {
        eprintln!("[sat-bond] ⛔ a bond the objects step decided was refused by the set — {e:?}"); // a static reason
        return false;
    }
    node.lock_bond_note(s.vid, s.locked_note.clone(), at_tick);
    eprintln!("[sat-bond] a SAT custody bond SEATED from the block"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string
    true
}

/// Every reason a bond is refused, at either door; `None` = admissible here.
pub(crate) fn sat_bond_refusal(node: &crate::node::Node, t: &SatBondTx, door: crate::respend::MemberDoor) -> Option<&'static str> {
    if !t.is_authorised(&crate::pqauth::MlDsaVerifier) {
        return Some("the bond is not signed by the key it seats");
    }
    if !t.weld_is_authorised() {
        return Some("the carrier does not lock exactly the stated weight in SAT");
    }
    let Some(binder) = t.nullifier_digest() else {
        return Some("the spent note's nullifier is not a canonical digest");
    };
    // §19: a tuple-bearing bond carries the member leg — judged by the ONE dispatcher (`bond_membership_verdict`, the
    // asset door's `asset_member_leg_verdict`); a tuple-less one is the one-step form (a fixture's) until batch 16.
    let member_ok = if t.member_tuple.is_empty() {
        node.verify_membership_carrier_one_step(
            &t.membership_carrier,
            t.leaf_commit,
            binder,
            t.tip_prev,
            t.tip_root,
            t.tip_acc,
            t.named_record,
            door,
        )
    } else {
        match node.asset_member_leg_verdict(&t.membership_carrier, &t.member_tuple, t.leaf_commit, binder, door) {
            crate::node::MemberVerdict::Member => true,
            // the record the leg anchors to has not folded HERE yet: a wait the pool retries, never "invalid"
            crate::node::MemberVerdict::Pending => return Some(crate::asset_tx::ASSET_SPEND_PENDING),
            crate::node::MemberVerdict::Refused => false,
        }
    };
    if !member_ok {
        return Some("the bonded note's membership does not verify against this node's own record roots");
    }
    let already_spent = match door {
        crate::respend::MemberDoor::Admit => node.sparse_spent_verdict(&t.nullifier) == crate::nf_sparse::SpentVerdict::Spent,
        crate::respend::MemberDoor::Fold => node.fold_point_spent_set().holds(&t.nullifier),
    };
    if already_spent {
        return Some("the bonded note is already spent");
    }
    // THE SEAT RULE, the one the bond step applies (`ValidatorSet::admit_refusal` / `rebond_refusal`), asked at BOTH doors:
    // at the pool door a first seat for a validator already seated is refused (an applied bond never re-enters the pool and
    // is never re-laid — Bitcoin: a transaction whose inputs the chain spent never enters the mempool), and at the fold it
    // is the canonical verdict over the step's frozen pre-state.
    if t.rebond.is_none() {
        if let Some(e) = node.validators().admit_refusal(&t.vid, u128::from(t.weight), 0) {
            return Some(match e {
                crate::validator::ValidatorError::AlreadyBonded => "the validator already holds a custody seat",
                crate::validator::ValidatorError::Slashed => "the validator is slashed",
                _ => "the bond is below the seat floor",
            });
        }
    }
    // ⭐ SATOSHI §9 — THE RE-BOND'S LOCKED INPUT. It has no membership path (it was never a balance); it is real only if it IS
    // this validator's locked note — the same attestation `Class::Unbond` trusts to return it — and unspent in the SET.
    if let Some(leg) = &t.rebond {
        // ⛔ §9.3 R1 (lane-harness, CRITICAL): conservation alone lets the change absorb the LOCKED value (locked 1,000 +
        // fresh 1 → weight 1, change 1,000): an instant exit that skips the unbond window and leaves a slash nothing to burn.
        // The new weight must exceed the seated one; both are public, and the seated weight IS the locked note's value
        // (the weld bound it when it seated), so this forces change ≤ the fresh note.
        if node.validators().bond_of(&t.vid) == 0 {
            return Some("a re-bond names a validator with no custody seat");
        }
        match node.validators().rebond_refusal(&t.vid, u128::from(t.weight)) {
            None => {}
            Some(crate::validator::ValidatorError::Slashed) => return Some("the validator is slashed"),
            Some(_) => return Some("a re-bond must raise the custody weight (its change can come only from the fresh note)"),
        }
        match node.bond_locked_note(&t.vid) {
            Some(n) if n.get(..32) == Some(&leg.locked_cm[..]) => {}
            _ => return Some("the re-bond's locked input is not this validator's locked note"),
        }
        let locked_spent = match door {
            crate::respend::MemberDoor::Admit => node.sparse_spent_verdict(&leg.nullifier_locked) == crate::nf_sparse::SpentVerdict::Spent,
            crate::respend::MemberDoor::Fold => node.fold_point_spent_set().holds(&leg.nullifier_locked),
        };
        if locked_spent {
            return Some("the re-bond's locked note is already spent");
        }
    }
    None
}

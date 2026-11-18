// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::membership_bond_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `membership_bond_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::membership_bond_tx::*;
use crate::chain_object::decode_exact;
use serde::{Deserialize, Serialize};

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that admits the block runs this, so the seat lands on ALL of
/// them, from the same bytes, in the same block order. This is what makes "the first nodes to bond" a
/// fact every peer agrees on rather than one each peer invents.
///
/// Total and deliberately dumb: bytes that are not a membership bond return `NotMembershipBond`, so it
/// can be called on every carried bond entry with no type tag on the wire.
///
/// ⛔ The block itself still grafts on refusal (no-chain-halts: refuse the ITEM, never the block).
pub fn apply_chain_membership_bond(
    node: &mut crate::node::Node,
    blob: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
    // ⛔ DB-258b — the carrying block's header-bound nullifier lane (`nullifier_proof.padded_tags`).
    lane: &[[u8; 32]],
) -> MembershipApply {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return MembershipApply::NotMembershipBond;
    };
    if class != crate::chain_object::Class::MembershipBond {
        return MembershipApply::NotMembershipBond;
    }
    let Some((header, pubkey, sig)) = decode(payload) else {
        return MembershipApply::Refused("the payload is not a membership bond");
    };
    // ⛔ THE SIGNATURE IS CHECKED ON EVERY NODE, not once on the submitter.
    if !is_authorised(&header, &pubkey, &sig, v) {
        return MembershipApply::Refused("the seat is not signed by the key it names");
    }
    // ⛔⛔⛔ DB-258b — THE BLOCK MUST RETIRE THIS REQUEST'S ONE-SHOT RIGHT. The bond set is a lane SEPARATE from the
    // block's nullifier lane, so a producer could re-carry an old seat object here without its right. The block's
    // nullifier proof proves every tag of its lane NEW, so a request carried WITH its right seats once and a re-carried
    // one is refused by the set; carried WITHOUT it, it is refused here. Fail-closed on the object, never the block.
    if !lane.contains(&seat_right_nf(&validator_id(&pubkey), &header)) {
        return MembershipApply::Refused(
            "the block does not retire this seat request's one-shot right (a re-carried or forged request)",
        );
    }
    // ⛔⛔⛔ FREE ONLY WHILE THE REQUIRED BOND IS ZERO — i.e. while the reserve is zero. This is the
    // adaptive rule evaluated at its zero point, decided from CHAIN STATE (the peg ledger's persisted
    // commitment) identically on every node. Once any deposit has been applied, a seat needs collateral
    // and rides the collateral-bond lane instead; this door refuses it.
    // ⛔⛔ DB-369: AND ONLY FOR THE FIRST `FREE_FOUNDING_SEATS` MEMBERS. Unbounded, a costless seat flood grew every node's
    // validator set and every deposit's sealed width (MEASURED: 1,321 B per seat per deposit). One rule, one spelling
    // (`Node::free_seat_open`), read from chain state at the fold, identical on every node.
    if !node.free_seat_open() {
        return MembershipApply::Refused(
            "a free seat needs a zero reserve and an open founding slot; post collateral to join",
        );
    }
    node.apply_membership_seat(validator_id(&pubkey), header.secp33, header.ed32, header.kem_ek)
}

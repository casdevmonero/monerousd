// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::unbond_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `unbond_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::unbond_tx::*;
use crate::chain_object::decode_exact;
use serde::{Deserialize, Serialize};

/// ⭐⭐ DB-258 — THE ONE STATEFUL DOOR: `Ok(V)` iff the signature is V's over this object's own statement AND the
/// bonding it names is V's LIVE bonding on this node. The publish door, the §BA return-note door and the release all
/// read this, so they can never disagree about which unbond is valid.
pub fn authorised_for(
    node: &crate::node::Node,
    header: &UnbondHeader,
    pubkey: &[u8],
    sig: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
) -> Result<[u8; 32], &'static str> {
    if !is_authorised(header, pubkey, sig, v) {
        return Err("the unbond is not signed by the key this bond belongs to, over this statement");
    }
    let id = validator_id(pubkey);
    if node.bond_instance_of(&id) != Some(header.bond_instance) {
        return Err("the unbond names another bonding of this validator (a replayed or stale authorisation)");
    }
    Ok(id)
}

/// ⭐⭐ DB-258d — THE BLOCK-SIDE DOOR: [`authorised_for`] AND the carrying block retires this unbond's own one-shot right
/// ([`unbond_right_nf`] ∈ `lane`, the block's header-bound `nullifier_proof.padded_tags`). The release and the §BA
/// return-note door both read this, so a block can never return a bond note for an unbond it does not release.
/// Fail-closed on the object, never on the block.
pub fn authorised_in_block(
    node: &crate::node::Node,
    header: &UnbondHeader,
    pubkey: &[u8],
    sig: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
    lane: &[[u8; 32]],
) -> Result<[u8; 32], &'static str> {
    let id = authorised_for(node, header, pubkey, sig, v)?;
    if !lane.contains(&unbond_right_nf(&id, header)) {
        return Err("the carrying block does not retire this unbond's own one-shot right (a re-carried or replayed unbond)");
    }
    Ok(id)
}

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that admits the block runs this, so the weight leaves the
/// denominator and the note is returned on ALL of them, from the same bytes.
///
/// Total and deliberately dumb: bytes that are not an unbond return `NotUnbond` untouched, so it can be
/// called on every transaction with no type tag on the wire.
///
/// ⛔ A node that never admitted this validator answers `Refused` and moves nothing — the honest answer,
/// and fail-closed. The block itself still grafts (no-chain-halts: refuse the ITEM, never the block).
pub fn apply_chain_unbond(
    node: &mut crate::node::Node,
    blob: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
    // DB-257: the CARRYING block's blue score — the release is judged on the block. DB-274 P2 (§8.7): it is applied
    // at the block's FOLD step, and the collateral note never rides the block (it is released after the window).
    at_blue: u64,
    // A-F60: the CARRYING block's chain tick — the stake lock and the unbonding window are times, read on it.
    at_tick: u64,
    // DB-258d: the CARRYING block's header-bound lane — the release requires this unbond's own right in it.
    lane: &[[u8; 32]],
) -> UnbondApply {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return UnbondApply::NotUnbond;
    };
    if class != crate::chain_object::Class::Unbond {
        return UnbondApply::NotUnbond;
    }
    let Some((header, pubkey, sig, owner_clue)) = decode(payload) else {
        return UnbondApply::Refused("the payload is not an unbond");
    };
    // ⛔ THE SIGNATURE IS CHECKED ON EVERY NODE, not once on the submitter. A node that trusted the
    // publishing node's verdict would release a bond on that node's say-so — which is the whole defect
    // this class exists to close, reintroduced one layer up.
    let id = match authorised_in_block(node, &header, &pubkey, &sig, v, lane) {
        Ok(id) => id,
        Err(why) => return UnbondApply::Refused(why),
    };
    match node.apply_unbond_release(id, owner_clue, at_blue, at_tick) {
        Some(freed) => UnbondApply::Released(freed),
        None => UnbondApply::Refused("no matured bond for this validator here"),
    }
}

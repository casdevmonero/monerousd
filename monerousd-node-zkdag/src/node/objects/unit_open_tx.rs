// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::unit_open_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `unit_open_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::unit_open_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::debt_units::UnitTerms;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE UNIT OPEN (`today` = the carrying block's day): the unit's exact checks first (nothing moves on a refusal),
/// then the peg-in's own apply (custody's threshold, the solvency and mint carriers, the deposit-id set), then the unit opens,
/// the base deposit is spent and the unit note is recorded.
pub fn apply_chain_unit_open(node: &mut crate::node::Node, blob: &[u8], today: Option<u64>, verifier: &dyn crate::pqauth::PqVerifier) -> UnitOpenApply {
    let Some((Class::UnitOpen, payload)) = unframe(blob) else {
        return UnitOpenApply::NotUnitOpen;
    };
    // fail closed: a unit is dated by its carrying block, and a fold step with no carrying block dates nothing
    let Some(today) = today else {
        return UnitOpenApply::Refused("no carrying block to date the unit by");
    };
    let Some(t) = UnitOpenTx::decode(payload) else {
        return UnitOpenApply::Refused("not one canonical, bounded unit open whose deposit id binds its unit");
    };
    if !t.unit_carrier_verifies() {
        return UnitOpenApply::Refused("the unit note does not open to its unit's size and tag");
    }
    if node.peg().deposit_minted(&t.base_deposit_id) {
        return UnitOpenApply::Refused("this Bitcoin deposit already backs a mint or a unit");
    }
    // parity with the custodian's rule (`UnitClaim::covered`): no unit is born under its own 110 % at the chain's price
    match node.peg().reference_price(crate::peg::NATIVE_PEG_ASSET_ID) {
        Some(p) if p >= crate::debt_units::band_price_word(usize::from(t.terms.k)) => {}
        Some(_) => return UnitOpenApply::Refused("the band's floor is above the chain's reference price: the unit would be born under 110 %"),
        None => return UnitOpenApply::Refused("the chain holds no reference price"),
    }
    let mut probe = node.peg().unit_book().clone();
    if let Err(why) = probe.open_unit(&t.terms, today) {
        return UnitOpenApply::Refused(why);
    }
    let Some((h, peg_carrier, mint_carrier, backstop, attestors, note, sealed, _clue)) = crate::peg_in_tx::decode(&t.peg_in) else {
        return UnitOpenApply::Refused("the peg-in inside does not decode");
    };
    let outcome = node.apply_peg_in_attested(
        h.deposit_id,
        &peg_carrier,
        h.new_reserve_commit,
        h.new_minted_commit,
        h.recipient,
        h.proposal_nonce,
        &backstop,
        verifier,
        &attestors,
        h.delta_commit,
        &mint_carrier,
        &note,
        &sealed,
        Some((&t.terms, t.base_deposit_id)),
    );
    if !matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted) {
        return UnitOpenApply::Refused("the unit's peg-in was refused (custody threshold, carriers or replay)");
    }
    node.open_unit_after_peg_in(&t, today);
    UnitOpenApply::Opened
}

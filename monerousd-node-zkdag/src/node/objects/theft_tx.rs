// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::theft_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `theft_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::theft_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;

/// ⭐⭐⭐ THE FOLD-SIDE DOOR. Every node applies a carried theft object here, inside `apply_bond_set` at the block's
/// fold step.
/// 1. The object decodes strictly.
/// 2. Its certificate is ≥2/3 of the step's PRE-state weight (`pre`, the set as the step found it) over the v2
///    message, so the offenders are signed.
/// 3. Each offender that is bonded or unbonding here is slashed through the ONE shared slash function.
///
/// A replay finds every offender already slashed and barred, so it is a no-op (`Refused`, nothing moves).
///
/// §9.6:
/// 1. PoW — the carrying block's.
/// 2. Proof — `verify_threshold` over the v2 message, against the pre-state set.
/// 3. Conservation — a slash only removes weight and drops unbonding entries; the removed SAT moves into the repayment pot
///    (one word), so SAT is conserved (§BR-13's three doors: the pot's SAT re-enters circulation only by a sale at the floor).
/// 4. Replay — the slashed/barred SET.
/// 5. Bounded work — decode's constant caps, before any verify.
/// 6. Parity with `Class::Equivocation` — the same lane, the same fold step and the same slash function.
pub fn apply_chain_reserve_theft(
    node: &mut crate::node::Node,
    blob: &[u8],
    pre: &dyn crate::psm::BondQuorum,
    v: &dyn PqVerifier,
) -> TheftApply {
    let Some((class, payload)) = unframe(blob) else {
        return TheftApply::NotTheft;
    };
    if class != Class::ReserveTheft {
        return TheftApply::NotTheft;
    }
    let Some((statement, offenders, loss_sats, cert)) = decode(payload) else {
        return TheftApply::Refused("the evidence is not one canonical, bounded theft object");
    };
    if !crate::bond_tally::verify_threshold(&crate::theft_tx::theft_msg_at(&statement, &offenders, loss_sats, node.theft_statement_seq()), &cert, pre, v) {
        return TheftApply::Refused("no ≥2/3 of the step's pre-state weight signs this theft, these offenders and this loss");
    }
    let burned: u128 = offenders
        .iter()
        .filter_map(|id| node.apply_slash(*id))
        .fold(0u128, u128::saturating_add);
    if burned == 0 {
        return TheftApply::Refused("no named offender is bonded or unbonding here (already slashed, or never bonded)");
    }
    // A-F114: the counter steps with every theft applied, so this certificate is never valid again
    node.step_theft_seq();
    // ⭐ §BR-3 17.5 layer 1: the slashed SAT is not destroyed — it moves into the repayment pot (sold at the floor, its
    // proceeds retired), and the loss is booked once per theft for the repayment ladder (`Class::TheftRepayment`).
    let closed_decoy = node.close_decoy_by_theft(&statement, &offenders); // §BR-8: an unreturned decoy's certificate closes its obligation
    // ⭐ A-F114: from the network upgrade a DECOY theft's loss is booked only by the certificate that closed its open decoy;
    // a second certificate for one decoy closes nothing and books nothing (no key is kept to refuse it). A statement that is
    // no decoy statement keeps the key path.
    // The slashed SAT moves into the pot in every case (conservation); only the LOSS booking is skipped.
    let decoy_statement = statement.starts_with(b"MUSD/decoy-unreturned/v1");
    let skip_loss = crate::params::canon_live() && decoy_statement && !closed_decoy;
    if !node.book_theft_loss(burned, loss_sats, &theft_loss_key(&statement), closed_decoy, skip_loss) {
        eprintln!("[bond-apply] reserve-theft slash applied; its loss was already booked (one theft books once)");
    }
    TheftApply::Slashed(burned)
}

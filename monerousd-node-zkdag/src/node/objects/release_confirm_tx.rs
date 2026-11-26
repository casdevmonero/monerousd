// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A-F114 — the node half of `crate::release_confirm_tx`: its apply at the fold (increment 3 of its build). A payout's
//! release takes the owed burns it names out of `PegLedger::spent_burns` on every node alike (`PegLedger::release_confirm`).
//! Admitted only under the network upgrade (`chain_object::admissible`), so on today's chain no block carries one.

use crate::chain_object::{unframe, Class};
use crate::release_confirm_tx::ReleaseConfirmTx;

/// What the fold did with a blob offered to this class.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseApply {
    /// Not this class's object.
    NotRelease,
    /// Applied: the named burns left the owed book.
    Applied,
    /// Refused on the item (the block still grafts): a threshold short, or a burn it names not owed.
    Refused(crate::peg::PegOutcome),
}

/// APPLY a block-carried release: FAIL-CLOSED on the item.
pub fn apply_chain_release_confirm(node: &mut crate::node::Node, blob: &[u8], verifier: &dyn crate::pqauth::PqVerifier) -> ReleaseApply {
    let Some((Class::ReleaseConfirm, payload)) = unframe(blob) else { return ReleaseApply::NotRelease };
    if !crate::params::canon_live() {
        return ReleaseApply::Refused(crate::peg::PegOutcome::BadRequest);
    }
    let Some(t) = ReleaseConfirmTx::decode(payload) else { return ReleaseApply::Refused(crate::peg::PegOutcome::BadRequest) };
    let msg = t.statement();
    let atts = t.attestors();
    match node.apply_release_confirm(t.ledger, &t.released, &t.swept, &msg, verifier, &atts) {
        crate::peg::PegOutcome::ConfidentialRedeemed => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a ledger id and a count only; no nullifier, txid or amount.
            eprintln!("[release] a release folded: ledger {:#x}, {} owed burn(s) paid, {} deposit(s) swept", t.ledger, t.released.len(), t.swept.len());
            ReleaseApply::Applied
        }
        other => {
            eprintln!("[release] refused: {other:?}");
            ReleaseApply::Refused(other)
        }
    }
}

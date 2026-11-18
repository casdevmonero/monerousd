// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-9a step (c) — `Class::EpochKeyFraud`: A DEALER WHO SHARED ANOTHER SEED IS SLASHED (spec §19.3).
//!
//! The evidence is `epoch_release::FraudProof`: t shares of one dealer's seed for one epoch, each under the commitment the
//! dealer itself signed to its recipient (recorded in the epoch-key ledger), whose seed re-derives a public part other than
//! the one the dealer published. It is SELF-VERIFYING against the ledger alone — no signature, no quorum, no trusted
//! party: any node that holds the epoch's round checks it (`epoch_release::fraud_proof_holds`), and the bond step slashes
//! the dealer through the ONE shared slash function, exactly as `Class::Equivocation` does. A dealer can only be convicted
//! by shares it signed itself, so an honest dealer (whose shares all lie on its seed's polynomial) never can be.
//!
//! §9.6: (1) PoW — the carrying block's. (2) The object's own proof — `fraud_proof_holds`: each share under the dealer's
//! signed commitment, from a roster member, and t of them rebuilding another public part. (3) Value — it creates none; a
//! slash only removes the dealer's weight (burned). (4) Replay — the slashed set: a convicted dealer is barred, so a second
//! proof slashes nothing. (5) Bounded work — exactly t ≤ 256 shares of 33 bytes, one Shamir combine and one public-part
//! derivation (30 ring products). (6) Parity with `Class::Equivocation`: the same bond lane, the same bond step, the same
//! slash function. Its window: the round is held while its epoch has not passed (one hour from the release).
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: the proof reveals only the convicted dealer's seed for that epoch, whose contribution is
//! void (its epoch's tickets stay in their owners' escrow); it names no note, amount or user.

use crate::chain_object::{unframe, Class};
use crate::epoch_release::FraudProof;

/// One canonical encoding: shares sorted by recipient, distinct, each 33 bytes, at most `PEG_ATTEST_SEALED_MAX`.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<FraudProof> {
    let p: FraudProof = crate::chain_object::decode_exact(payload)?;
    let shaped = !p.shares.is_empty()
        && p.shares.len() <= crate::peg_attest::PEG_ATTEST_SEALED_MAX
        && p.shares.iter().all(|(_, s)| s.len() == crate::epoch_deal_tx::SHARE_BYTES)
        && p.shares.windows(2).all(|w| w[0].0 < w[1].0);
    shaped.then_some(p)
}

/// Frame the proof as a `Class::EpochKeyFraud` object, its shares in canonical (recipient) order.
#[must_use]
pub fn wire(p: &FraudProof) -> Option<Vec<u8>> {
    let mut p = p.clone();
    p.shares.sort_by(|a, b| a.0.cmp(&b.0));
    let payload = crate::fixed::encode_plain(&p);
    decode(&payload)?;
    Some(crate::chain_object::frame(Class::EpochKeyFraud, &payload))
}

/// What applying the evidence did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FraudApply {
    NotFraud,
    /// The dealer was bonded here and is now slashed: its bond burned, its id barred.
    Slashed(u128),
    Refused(&'static str),
}


// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-3 17.5 — `Class::TheftRepayment`: A CUSTODY THEFT IS REPAID IN LAYERS, AS A CHAIN OBJECT
//! (docs/BR-3-17-5-LAYERED-REPAYMENT-SPEC-20261029.md).
//!
//! BORROWED: Liquity's stability-pool offset (the pool burns depositors' USDm pro rata, `P ·= 1 − C/T`) and MakerDAO's surplus
//! buffer (the protocol's own fee surplus absorbs a loss before any holder does). Built on the liquidation object's shape
//! (`liquidation_tx`): a fixed-width header, WHIR legs welded by equal commitments, the ≥2/3 bonded tally, the object's own
//! one-time nullifier, one door in the peg ledger (`PegLedger::repay_theft_confidential`).
//!
//! The ladder, for a booked theft of `loss_sats` (public — it is a Bitcoin transaction anyone can see), valued at the BTC
//! 7-day TWAP (`L`):
//!   1. the repayment pot (the offenders' slashed SAT) at the floor `min(twap7, low30)(SAT) × haircut` books `V1 ≤ L` — owed
//!      to the supply by the pot's later sales (`repayment_owed_atomic`);
//!   2. the surplus buffer retires `B = min(buffer, L − V1)` (public amount; the supply falls by `B`);
//!   3. the stability pool burns `C = min(T, L − V1 − B)` with Liquity's product update (the supply falls by `C`);
//!   4. any remainder `R` is shared by every holder: a public haircut event (`haircut_remainder_atomic`).
//! At the same fold the seize leg books the stolen sats out of the committed reserve, so the chain's reserve matches what
//! custody holds again.
//!
//! What the legs prove (every node, against its own state):
//!   seize        `[new_reserve, Pub(loss_sats), reserve]` (Seize)
//!   retire_b     `[mid_minted, Pub(B), minted]` (Retire) — absent iff `B = 0` (then `mid = minted`)
//!   pool legs    `[new_T, DC, T]` (StabilityPool), `[T, DC, Pub(0), P, P', S, S']` (pool step, no collateral to the pool),
//!                `[new_minted, DC, mid]` (Retire) — absent iff `L − V1 − B = 0`
//!   case A (`R = 0`): `DC = Pub(C)`, `C = L − V1 − B` — the pool's `T` stays hidden (only `T ≥ C` is proven);
//!   case B (`R > 0`): `new_T = Pub(0)` (the pool is exhausted) and `remainder` `[Pub(R), DC, Pub(L − V1 − B)]` (Retire):
//!                `R = L − V1 − B − C ≥ 0` with `C = T` — a pool that runs out is disclosed by the haircut it causes.
//! `Pub(x)` is the solvency commitment of a PUBLIC amount under the protocol's public blind: every node recomputes it.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: the loss, the pot, the buffer and the haircut are public facts (a Bitcoin theft, public
//! bonds, the protocol's own surplus); the reserve, the supply and the pool stay commitments; no holder's value appears.

use serde::{Deserialize, Serialize};

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use crate::spend_frontier::Digest4;

/// Attestors per object: the producing set's bound, as for a liquidation.
pub const MAX_THEFT_REPAY_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The fixed-width header: every public amount the ladder decides and every commitment the legs move the chain to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TheftRepaymentHeader {
    /// The one-time id: a function of the chain state the repayment moves (`peg::theft_repay_id`), so one state repays once.
    pub repay_id: [u8; 32],
    /// The booked stolen sats this repayment books out of the reserve (≤ the open loss).
    pub loss_sats: u64,
    /// `[L, V1, B, rest = L − V1 − B]` in USDm atomic — every node recomputes them from its own ledger.
    pub split: [u64; 4],
    /// `C` in case A (the pool covers `rest`); 0 in case B (the pool is exhausted and `C = T` stays a commitment).
    pub pool_c: u64,
    /// `R`, the remainder every holder shares (0 in case A).
    pub remainder: u64,
    /// `DC`, the pool's burn.
    pub pool_retired_commit: Digest4,
    pub new_reserve_commit: Digest4,
    /// The supply after the buffer's retire (= the current supply when `B = 0`).
    pub mid_minted_commit: Digest4,
    pub new_minted_commit: Digest4,
    pub new_pool_t: Digest4,
    pub new_pool_p: Digest4,
    pub new_pool_s: Digest4,
    pub pool_close: bool,
}

/// The legs; an absent leg is empty (which ones must be present is the door's rule, from the header's public amounts).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TheftRepaymentLegs {
    pub seize: Vec<u8>,
    pub retire_buffer: Vec<u8>,
    pub pool_transition: Vec<u8>,
    pub pool_step: Vec<u8>,
    pub retire_pool: Vec<u8>,
    pub remainder: Vec<u8>,
}

impl TheftRepaymentLegs {
    fn each(&self) -> [&Vec<u8>; 6] {
        [&self.seize, &self.retire_buffer, &self.pool_transition, &self.pool_step, &self.retire_pool, &self.remainder]
    }
}

pub type TheftRepaymentPayload = (TheftRepaymentHeader, TheftRepaymentLegs, Vec<(Vec<u8>, Vec<u8>)>);

#[must_use]
pub fn encode(h: &TheftRepaymentHeader, legs: &TheftRepaymentLegs, attestors: &[MintAttestor]) -> Vec<u8> {
    let att: Vec<(&[u8], &[u8])> = attestors.iter().map(|a| (a.pubkey.as_slice(), a.sig.as_slice())).collect();
    postcard::to_stdvec(&(h, legs, &att)).unwrap_or_default()
}

#[must_use]
pub fn wire(h: &TheftRepaymentHeader, legs: &TheftRepaymentLegs, attestors: &[MintAttestor]) -> Vec<u8> {
    frame(Class::TheftRepayment, &encode(h, legs, attestors))
}

/// The one decode: one encoding, every leg within the constant WHIR bound (an absent leg is empty), the seize leg present,
/// and a non-empty attestation list within the producing set.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<(TheftRepaymentHeader, TheftRepaymentLegs, Vec<MintAttestor>)> {
    let (h, legs, pairs) = decode_exact::<TheftRepaymentPayload>(payload)?;
    if legs.each().iter().any(|l| l.len() > crate::solvency::SolvencyProof::MAX_PROOF_BYTES) || legs.seize.is_empty() {
        return None;
    }
    if pairs.is_empty() || pairs.len() > MAX_THEFT_REPAY_ATTESTORS || h.loss_sats == 0 {
        return None;
    }
    Some((h, legs, pairs.into_iter().map(|(pubkey, sig)| MintAttestor { pubkey, sig }).collect()))
}

/// The pool transaction that carries one repayment (the liquidation's builder shape: blob + anti-spam stamp; its own
/// nullifier is laid by the publisher through `lay_object_lane`).
#[must_use]
pub fn as_pq_tx(h: &TheftRepaymentHeader, legs: &TheftRepaymentLegs, attestors: &[MintAttestor], stamp_bits: u32) -> crate::mempool::PqTx {
    let blob = wire(h, legs, attestors);
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: Vec::new(),
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(),
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() >= stamp_bits {
            break;
        }
        s = s.wrapping_add(1);
    }
    tx
}

/// ONE bonded custodian's signature over a due repayment's message — the unit of the attestation lane
/// (`WireMsg::TheftRepaySig`), the liquidation lane's shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TheftRepaySig {
    pub header: TheftRepaymentHeader,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl TheftRepaySig {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: TheftRepaySig = decode_exact(bytes)?;
        let ok = |f: &Vec<u8>| !f.is_empty() && f.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX;
        (ok(&s.pubkey) && ok(&s.sig)).then_some(s)
    }
}

/// What applying a carried repayment did.
#[derive(Debug, PartialEq, Eq)]
pub enum TheftRepayApply {
    NotRepayment,
    Repaid,
    Refused(crate::peg::PegOutcome),
}


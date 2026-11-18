// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-112 — THE PQ PEG POOL, EXIT LEG: A REDEEM LEAVES CUSTODY IN A CROWD, NOT ALONE.
//!
//! USER 2026-09-19: "my goal is for the transparent chain peg out assets to also be unlinkable to the person
//! cashing them out … lets make our version of tornado cash pq."
//!
//! MonerousD is ALREADY the pool in the middle: USDm between a mint and a burn is shielded, and DB-110 took
//! the destination address off the peg-out object and out of the attested statement. What remains is the
//! BITCOIN edge: a Bitcoin payment is public by construction, so it can only be made AMBIGUOUS.
//! `authorize_reserve_release` makes it as unambiguous as possible — ONE burn to ONE destination, for the
//! exact amount burned, in the sequence it was burned. Amount, cardinality and sequence each identify the
//! redeemer on their own. Three things take those three away:
//!
//! 1. **FIXED DENOMINATIONS** ([`PAYOUT_DENOMS`]) — every leg is a ladder unit, so an output's amount says
//!    only "one of the ladder". Enforced by [`ReleaseBatch::verdict`]'s `NotADenomination` arm.
//! 2. **BATCHED UNIFORM PAYOUTS** — one custody transaction pays B redeemers with B EQUAL outputs (the
//!    CoinJoin shape), so an observer choosing among the legs has a 1-in-B chance.
//! 3. **DERIVED PAYOUT SEQUENCE** ([`payout_order_key`]) — batches are assembled in the sequence of a key
//!    derived from each burn's own nullifier and the epoch seed, so the payout sequence is not the burn
//!    sequence, and the assembler cannot choose who rides with whom (which is how a hostile assembler would
//!    seat one target among its own addresses).
//!
//! A redeem is payable as soon as its batch has [`BATCH_MIN`] legs. What it waits for is company.
//!
//! Everything here is COMPUTED from what the chain already carries — an order key from the burn nullifier
//! the chain published, an epoch seed from the asset and the epoch number. No schedule, no pending store and
//! no per-redeem row: a batch is a WIRE OBJECT, built and judged on the spot.
//!
//! This module declares no key material and calls no signer: every reserve output stays under the bonded set's k-of-n custody (the bond-weighted multisig tally)
//! threshold-custodied, and a batch is authorised by the same ≥2/3 threshold certificate a single release
//! needs, over the BATCH statement instead of a single destination.
//!
//! HONEST LIMIT, the same one Tornado has: privacy equals the anonymity-set size. Monero never faces this
//! because it has no native peg-out to a transparent chain; any XMR↔BTC bridge has exactly this problem.

use crate::spend_frontier::Digest4;

/// The payout ladder, in satoshis: powers of ten from 0.0001 BTC to 1000 BTC.
pub const PAYOUT_DENOMS: [u64; 8] = [
    10_000,          // 0.0001 BTC
    100_000,         // 0.001  BTC
    1_000_000,       // 0.01   BTC
    10_000_000,      // 0.1    BTC
    100_000_000,     // 1      BTC
    1_000_000_000,   // 10     BTC
    10_000_000_000,  // 100    BTC
    100_000_000_000, // 1000   BTC
];

/// The smallest anonymity set a batch may pay. A batch of one IS a single release, and BY CONSTRUCTION
/// [`ReleaseBatch::verdict`] answers `TooSmall` under this count, so such a batch reaches no signature and
/// no coin. Four is the smallest B at which an observer's 1-in-B chance is worse than a coin flip.
pub const BATCH_MIN: usize = 4;

/// How many legs one batch carries. The Bitcoin transaction has to fit and be relayed, so a batch is a PAGE
/// of the payout queue: the assembler emits successive batches until the queue is empty, and a redeem that
/// does not fit in this batch is in the next one.
pub const BATCH_MAX: usize = 64;

/// Split `amount_sats` into ladder legs, largest first, taking as many as the amount actually needs.
///
/// Returns `(legs, remainder)`. `remainder` is what is left below the smallest ladder unit — the ladder's
/// granularity — and the redeemer keeps it as USDm, which is shielded. Exactness at every size is pinned by
/// `a_redeem_of_any_size_settles_in_ladder_units_and_the_sum_is_exact`.
#[must_use]
pub fn split_to_denoms(amount_sats: u64) -> (Vec<u64>, u64) {
    let mut legs: Vec<u64> = Vec::new();
    let mut left = amount_sats;
    // Largest first: fewer, larger outputs join a bigger crowd than many small ones.
    for d in PAYOUT_DENOMS.iter().rev() {
        while left >= *d {
            legs.push(*d);
            left -= *d;
        }
    }
    (legs, left)
}

/// Is `sats` exactly one ladder unit? The batch door refuses any leg that is not.
#[must_use]
pub fn is_denom(sats: u64) -> bool {
    PAYOUT_DENOMS.contains(&sats)
}

/// USDm atomic units per dollar (8 decimals; `liquidation::PRICE_SCALE` prices one external atomic unit in them).
pub const USDM_ATOMIC_PER_DOLLAR: u64 = 100_000_000;

/// ⭐⭐ §19.4 / §19.5 item 1 (lane defi, 2026-11-01) — THE CASH-OUT LADDER, in USDm atomic units: powers of ten from $10 to
/// $1,000,000. A cash-out piece BURNS exactly one rung and releases it at the paying ledger's reference price AT ITS BATCH
/// (`PegLedger::peg_out_release`), so every piece of one rung in one batch pays the same amount on Bitcoin and on Monero —
/// the batch's crowd (§3.4) — and the burn the wallet proves in advance never depends on a price it cannot know (the §19.4
/// claim is pre-built hours before its batch). A satoshi ladder needed the price at proving time, which only the custody
/// that burned the escrow (B5-d) had — and so custody knew the note.
pub const USD_DENOMS: [u64; 6] = [
    10 * USDM_ATOMIC_PER_DOLLAR,
    100 * USDM_ATOMIC_PER_DOLLAR,
    1_000 * USDM_ATOMIC_PER_DOLLAR,
    10_000 * USDM_ATOMIC_PER_DOLLAR,
    100_000 * USDM_ATOMIC_PER_DOLLAR,
    1_000_000 * USDM_ATOMIC_PER_DOLLAR,
];

/// Is `burn_atomic` exactly one rung of the cash-out ladder? Every peg-out door refuses a burn that is not.
#[must_use]
pub fn is_usd_denom(burn_atomic: u64) -> bool {
    USD_DENOMS.contains(&burn_atomic)
}

/// ⭐ §18.14 — A COIN NOTE'S CASH-OUT RUNGS, in the coin's own atoms: powers of ten from about $10, so every piece of one rung pays the same amount and joins the same crowd on its chain.
pub const COIN_BTC_DENOMS: [u64; 6] = [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000];
pub const COIN_XMR_DENOMS: [u64; 6] = [10_000_000_000, 100_000_000_000, 1_000_000_000_000, 10_000_000_000_000, 100_000_000_000_000, 1_000_000_000_000_000];

/// The rungs of a coin ledger.
#[must_use]
pub fn coin_denoms(coin: u32) -> &'static [u64; 6] {
    if coin == crate::peg::COIN_XMR_ASSET_ID { &COIN_XMR_DENOMS } else { &COIN_BTC_DENOMS }
}

/// Split a coin amount into rungs, largest first; the remainder below the smallest stays a coin note.
#[must_use]
pub fn split_to_coin_denoms(coin: u32, amount: u64) -> (Vec<u64>, u64) {
    let mut legs = Vec::new();
    let mut left = amount;
    for d in coin_denoms(coin).iter().rev() {
        while left >= *d {
            legs.push(*d);
            left -= *d;
        }
    }
    (legs, left)
}

/// Split a USDm amount into cash-out rungs, largest first; the remainder below $10 stays USDm (a private balance, §3.2).
#[must_use]
pub fn split_to_usd_denoms(amount_atomic: u64) -> (Vec<u64>, u64) {
    let mut legs: Vec<u64> = Vec::new();
    let mut left = amount_atomic;
    for d in USD_DENOMS.iter().rev() {
        while left >= *d {
            legs.push(*d);
            left -= *d;
        }
    }
    (legs, left)
}

/// The batch epoch's public seed — the value [`payout_order_key`] sorts against. Derived from the asset and
/// the epoch number so every custodian holds it without exchanging anything, and it takes the epoch as
/// input so a later epoch sorts the same burns differently.
#[must_use]
pub fn epoch_seed(asset: &str, epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/peg-pool/epoch-seed/v1");
    let a = asset.as_bytes();
    h.update(&(a.len() as u64).to_le_bytes());
    h.update(a);
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

/// This burn's place in the payout sequence — derived at every call, never stored and never coordinated.
///
/// `epoch_seed` is the batch epoch's public seed and `burn_nullifier` is the burn's own; both are known to
/// every custodian, so all of them sort pending legs identically with no exchange of any kind. The key is a
/// hash of the nullifier, so the sequence it produces is not the sequence the burns happened in. It decides
/// POSITION only, and reads only what the chain has already published.
#[must_use]
pub fn payout_order_key(burn_nullifier: &[u8; 32], epoch_seed: &[u8; 32]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/peg-pool/payout-order/v1");
    h.update(epoch_seed);
    h.update(burn_nullifier);
    let d = *h.finalize().as_bytes();
    let mut head = [0u8; 8];
    head.copy_from_slice(&d[..8]);
    u64::from_le_bytes(head)
}

/// One redeemer's leg inside a batch: WHICH burn is released, and a COMMITMENT to where it pays. The
/// destination itself is never here — DB-110 put it in the per-custodian sealed opening. Two fixed digests
/// and nothing else, so a leg is a constant 64 bytes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PayoutLeg {
    /// The burned USDm nullifier this leg releases against — the conservation key, already public.
    pub burn_nullifier: [u8; 32],
    /// `peg::redeem_commit(address, blind)`, exactly as the peg-out object carries it.
    pub redeem_commit: [u8; 32],
}

/// Order `legs` the way every custodian will, so all of them assemble the SAME batch from the same pending
/// set with no coordination round. The sort key is `(order key, nullifier)`, and the nullifier is unique per
/// burn, so the ordering is TOTAL rather than merely usually-agreed.
#[must_use]
pub fn order_legs(mut legs: Vec<PayoutLeg>, epoch_seed: &[u8; 32]) -> Vec<PayoutLeg> {
    legs.sort_by_key(|l| (payout_order_key(&l.burn_nullifier, epoch_seed), l.burn_nullifier));
    legs
}

/// A CoinJoin-shaped custody payout: B redeemers, ONE denomination, one Bitcoin transaction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseBatch {
    /// Which reserve asset this batch pays out of.
    pub asset: String,
    /// The ONE denomination every leg pays, in satoshis. Must satisfy [`is_denom`].
    pub denom_sats: u64,
    /// The batch epoch — the same replay-scoping a single release's statement carries.
    pub epoch: u64,
    /// The redeemers this one transaction pays, in the derived sequence.
    /// O1-FOOTPRINT-REVIEWED: bounded by BATCH_MAX, a protocol constant — `ReleaseBatch::decode` returns
    /// `None` past it and `verdict()` answers `TooLarge`, so no door reads a wider batch. This is a WIRE
    /// object, never node state: it is one PAGE of the payout queue, and the assembler emits successive
    /// batches until the queue is empty rather than ever holding a longer one.
    pub legs: Vec<PayoutLeg>,
}

/// Why a batch was refused. Every arm refuses the WHOLE batch, never a partial payout: a batch that pays
/// some legs and drops others is exactly the linkage this module exists to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchVerdict {
    /// Under [`BATCH_MIN`] legs — this would pay a redeemer in a crowd too small to hide in.
    TooSmall,
    /// Over [`BATCH_MAX`] legs — more than one page of the payout queue.
    TooLarge,
    /// The denomination is not a ladder unit, so the outputs would not be uniform.
    NotADenomination,
    /// The same burn appears twice in one batch — it would pay one redeem two legs.
    DuplicateBurn,
    /// The legs are not in the derived payout sequence, so this batch was hand-picked, not assembled.
    OutOfSequence,
    /// Accepted shape. It still needs the ≥2/3 threshold certificate and the per-burn release checks.
    WellFormed,
}

impl ReleaseBatch {
    /// Build a batch from a pending set, putting the legs in the derived sequence. Every custodian calling
    /// this with the same pending set gets byte-identical bytes, which is what lets them sign one statement
    /// without a coordination round.
    #[must_use]
    pub fn assemble(asset: &str, denom_sats: u64, epoch: u64, legs: Vec<PayoutLeg>) -> Self {
        let seed = epoch_seed(asset, epoch);
        Self { asset: asset.to_string(), denom_sats, epoch, legs: order_legs(legs, &seed) }
    }

    /// The SHAPE rules, before any signature is checked and before any coin moves. Fail-closed: anything
    /// not provably a uniform, large-enough, duplicate-free, correctly-sequenced batch is refused.
    #[must_use]
    pub fn verdict(&self) -> BatchVerdict {
        if self.legs.len() < BATCH_MIN {
            return BatchVerdict::TooSmall;
        }
        if self.legs.len() > BATCH_MAX {
            return BatchVerdict::TooLarge;
        }
        if !is_denom(self.denom_sats) {
            return BatchVerdict::NotADenomination;
        }
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.legs.len());
        for l in &self.legs {
            if seen.contains(&l.burn_nullifier) {
                return BatchVerdict::DuplicateBurn;
            }
            seen.push(l.burn_nullifier);
        }
        // ⭐ THE SEQUENCE IS PART OF THE SHAPE. Without it an executor picks WHICH redeems ride together,
        // which is how you seat one target in a batch with three of your own addresses and learn which
        // output was theirs. The derived sequence takes that choice away from whoever assembles it.
        let seed = epoch_seed(&self.asset, self.epoch);
        if order_legs(self.legs.clone(), &seed) != self.legs {
            return BatchVerdict::OutOfSequence;
        }
        BatchVerdict::WellFormed
    }

    /// The exact bytes the ≥2/3 quorum signs. Binds the asset, the denomination, the epoch, the leg count
    /// and every `(burn_nullifier, redeem_commit)` pair IN SEQUENCE, so a signature over one batch does not
    /// verify over a batch with a leg added, removed, resequenced, re-pointed or re-denominated — pinned by
    /// `a_gathered_signature_cannot_be_moved_to_another_batch`.
    #[must_use]
    pub fn statement(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(48 + self.legs.len() * 64);
        m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.pool.release-batch.v1"));
        let a = self.asset.as_bytes();
        m.extend_from_slice(&(a.len() as u64).to_le_bytes());
        m.extend_from_slice(a);
        m.extend_from_slice(&self.denom_sats.to_le_bytes());
        m.extend_from_slice(&self.epoch.to_le_bytes());
        m.extend_from_slice(&(self.legs.len() as u64).to_le_bytes());
        for l in &self.legs {
            m.extend_from_slice(&l.burn_nullifier);
            m.extend_from_slice(&l.redeem_commit);
        }
        m
    }

    /// A commitment to this batch, for a custodian binding it into another statement without carrying its
    /// legs. Derived from `statement()`, so both spellings of "this batch" come from ONE definition. `None`
    /// when the digest is not a canonical field element — the caller refuses; there is no second way to
    /// name a batch.
    #[must_use]
    pub fn commit(&self) -> Option<Digest4> {
        let d = blake3::hash(&self.statement());
        crate::spend_frontier::cm_bytes_to_root(d.as_bytes())
    }

    /// The canonical bytes, or `None` if this batch does not encode. The caller refuses rather than sending
    /// a shorter spelling of the same object, so a batch travels in exactly one form or not at all.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }

    /// Bounded decode — the page size is enforced HERE, so nothing downstream reads a batch wider than one
    /// transaction carries.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let b: Self = crate::chain_object::decode_exact(bytes)?;
        if b.legs.len() > BATCH_MAX {
            return None;
        }
        Some(b)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    const ASSET: &str = "BTC";
    const EPOCH: u64 = 7;
    const DENOM: u64 = 1_000_000;

    fn leg(n: u8) -> PayoutLeg {
        PayoutLeg { burn_nullifier: [n; 32], redeem_commit: [n.wrapping_add(100); 32] }
    }

    fn batch_of(n: u8) -> ReleaseBatch {
        ReleaseBatch::assemble(ASSET, DENOM, EPOCH, (0..n).map(leg).collect())
    }

    #[test]
    fn a_redeem_of_any_size_settles_in_ladder_units_and_the_sum_is_exact() {
        for amount in [13_700_000u64, 9_999, 10_000, 99 * 1_000_000_000, 4_321 * 100_000_000, u64::MAX / 4] {
            let (legs, rem) = split_to_denoms(amount);
            assert!(legs.iter().all(|l| is_denom(*l)), "every leg is a ladder unit at {amount}");
            assert_eq!(
                legs.iter().map(|l| *l as u128).sum::<u128>() + rem as u128,
                amount as u128,
                "the split is exact at {amount}"
            );
            assert!(rem < PAYOUT_DENOMS[0], "the remainder is under the ladder's smallest unit at {amount}");
        }
        // A redeem under the smallest unit pays out nothing and keeps all of it as USDm — a dust payout is
        // the easiest fingerprint there is, and it is still the holder's, shielded.
        let (small, small_rem) = split_to_denoms(9_999);
        assert!(small.is_empty());
        assert_eq!(small_rem, 9_999);
    }

    #[test]
    fn a_batch_that_would_not_hide_anyone_is_refused_not_quietly_paid() {
        // ⭐ THE WHOLE POINT. A batch of one IS a single release, the linkage this module exists to remove.
        for n in 0..BATCH_MIN as u8 {
            assert_eq!(batch_of(n).verdict(), BatchVerdict::TooSmall, "a batch of {n} pays someone alone");
        }
        assert_eq!(batch_of(BATCH_MIN as u8).verdict(), BatchVerdict::WellFormed);

        // ⛔ NON-UNIFORM OUTPUTS: an amount off the ladder makes one output distinguishable, which names its
        // redeemer inside the crowd. Refused on the shape alone, before any signature is looked at.
        let mut odd = batch_of(8);
        odd.denom_sats = 1_234_567;
        assert_eq!(odd.verdict(), BatchVerdict::NotADenomination);

        // ⛔ ONE BURN, TWO LEGS: this both over-releases the reserve and makes that redeemer the only one
        // with two outputs.
        let mut dup = batch_of(8);
        dup.legs[5].burn_nullifier = dup.legs[2].burn_nullifier;
        assert_eq!(dup.verdict(), BatchVerdict::DuplicateBurn);

        // ⛔ A HAND-PICKED CROWD IS NOT A CROWD: an assembler choosing who rides together seats one target
        // among its own addresses and reads the answer off the block.
        let mut picked = batch_of(8);
        picked.legs.swap(0, 7);
        assert_eq!(picked.verdict(), BatchVerdict::OutOfSequence);

        // ⛔ WIDER THAN ONE PAGE: refused here, and never decoded at all.
        let mut huge = batch_of(8);
        huge.legs = (0..=(BATCH_MAX as u32))
            .map(|i| {
                let mut nf = [0u8; 32];
                nf[..4].copy_from_slice(&i.to_le_bytes());
                PayoutLeg { burn_nullifier: nf, redeem_commit: [0u8; 32] }
            })
            .collect();
        assert_eq!(huge.verdict(), BatchVerdict::TooLarge);
        let wire = huge.encode().expect("encodes");
        assert!(ReleaseBatch::decode(&wire).is_none(), "a decode never yields a batch past the page");
    }

    #[test]
    fn a_gathered_signature_cannot_be_moved_to_another_batch() {
        let base = batch_of(8);
        let s = base.statement();

        let mut resequenced = base.clone();
        resequenced.legs.swap(1, 6);
        assert_ne!(resequenced.statement(), s, "⛔ legs could be resequenced under gathered signatures");

        let mut repointed = base.clone();
        repointed.legs[3].redeem_commit = [0xaa; 32];
        assert_ne!(repointed.statement(), s, "⛔ a leg's destination could be swapped after gathering");

        let mut dropped = base.clone();
        dropped.legs.pop();
        assert_ne!(dropped.statement(), s, "⛔ a leg could be removed after gathering");

        let mut redenom = base.clone();
        redenom.denom_sats = 100_000_000;
        assert_ne!(redenom.statement(), s, "⛔ the denomination could be raised after gathering");

        let mut reepoch = base.clone();
        reepoch.epoch += 1;
        assert_ne!(reepoch.statement(), s, "⛔ a batch could be replayed into another epoch");

        let back = ReleaseBatch::decode(&base.encode().expect("encodes")).expect("round trips");
        assert_eq!(back, base);
        assert_eq!(back.statement(), s);
        assert_eq!(back.commit(), base.commit());
    }

    #[test]
    fn the_payout_sequence_is_derived_agreed_and_unrelated_to_burn_sequence() {
        let seed = epoch_seed(ASSET, EPOCH);
        let burned: Vec<PayoutLeg> = (0..32u8).map(leg).collect();
        let paid = order_legs(burned.clone(), &seed);

        // Every custodian sorts identically from the same pending set — no coordination round, no oracle.
        assert_eq!(paid, order_legs(burned.clone(), &seed));
        // Sequencing is a permutation: every redeem that went in comes out.
        assert_eq!(paid.len(), burned.len());
        for l in &burned {
            assert!(paid.contains(l), "⛔ a redeem is missing from the payout sequence");
        }
        // ⭐ AND IT IS NOT THE BURN SEQUENCE — if these matched, an observer holding both chains could line
        // "the Nth burn" up with "the Nth payout".
        assert_ne!(paid, burned, "⛔ payouts would be paid in the sequence they were burned");

        // A later epoch sorts the same burns differently, so two epochs do not repeat a schedule.
        assert_ne!(order_legs(burned, &epoch_seed(ASSET, EPOCH + 1)), paid);
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ DB-124 — THE PRICE MARK: WHAT ONE EXTERNAL ATOMIC UNIT IS WORTH, DECIDED BY THE BONDED SET.
//!
//! WHAT WAS WRONG, AND WHY IT IS AN INFLATION BUG AND NOT A DISPLAY BUG. The peg had NO price. It counted
//! ONE atomic unit of the deposited asset as ONE USDm atomic unit, for every asset, and the 150%
//! over-collateralization check ([`crate::liquidation::aggregate_solvent`]) compared those raw counts. The
//! ratio check itself is sound; the UNIT it compared was not, and it breaks differently per asset by orders
//! of magnitude:
//!
//! ```text
//!   deposit   atomic units     mintable at 150%      real value
//!   1 BTC     1e8 sats         ~$666,666             ~$60-100k      (over-issues ~7-10x)
//!   1 XMR     1e12 piconero    ~$6.67 BILLION        ~$150          (over-issues ~4e7x)
//! ```
//!
//! A single XMR deposit could mint on the order of $10^9 of USDm against $150 of collateral. Every holder's
//! USDm is backed by that reserve, so this is a direct, unbounded theft of every other holder's money — the
//! sharpest funds-loss hole in the tree, and it was open on both legs on testnet exactly as on mainnet.
//!
//! ROOT-LAYER: the price is PRODUCED here, as a block-carried object the bonded set attests, and consumed
//! at the one door that decides solvency ([`crate::liquidation::aggregate_solvent`], whose inputs become
//! PRICED values). Patching a read site — the wallet's Buy card, an RPC summary, a per-test helper — is
//! exactly the defect DB-124 already recorded once: the screen was corrected on 2026-09-21 to quote the
//! node's own atomic figure, and the LEDGER stayed unpriced, so the inflation was untouched and only became
//! harder to see. There is one definition of what a unit is worth and it lives at the layer that decides
//! issuance.
//!
//! MEASURED: census of the live tree on 2026-09-22, before this module existed — searching production for
//! `attested_price|price_attest|PriceAttest|attested_rate|mark_to_market` returned ZERO hits, so the
//! attested-price object the design called for did not exist at all; `liquidation.rs:126` is `#[cfg(test)]`
//! and the priced `PositionBook` (`prices: [u128; KINDS]`, `collateral_value = units * prices[kind] /
//! PRICE_SCALE`) sits at line 254 INSIDE it, so the priced model was a simulation only; production's two
//! callers at `peg.rs:2946` and `peg.rs:2952` pass `new_r`/`new_m`, which are raw atomic counts; and
//! `rpc_http.rs:5328` and `:5574` take BOTH `deposit_value` and `mint` from the request body while the
//! custodian verify at `node.rs:16441` checks only `confirmed >= delta.deposit_value`, so nothing tied the
//! mint to the deposit's VALUE by any price. After this module the same census names one producer
//! (`mark_price_attested`) and one consumer (the priced solvency read), and the unpriced path is gone.
//!
//! MUST-STAY-GREEN: the peg's funds-safety theorems (`confidential_peg_in_verify_gate`,
//! `custodian_orchestrates_confidential_mint_and_redeem_from_its_opening`,
//! `redeem_two_tier_floor_sells_below_150_but_never_below_100`,
//! `wrapped_asset_per_asset_ratio_stablecoin_exempt_from_150`, `confidential_peg_in_out_wire_path_e2e`,
//! `confidential_reserve_yield_claim_gate`), the psm threshold tests, the chain-action carriage census, the
//! no-growth census and the wire-malleability family. This module ADDS an object and a door and relaxes
//! none of theirs: an asset with no mark behaves exactly as before at every door except the mint, which
//! refuses rather than minting against an unpriced unit.
//!
//! ── WHY EACH ATTESTOR SIGNS ITS OWN NUMBER ────────────────────────────────────────────────────────────
//! Every other attested class in this tree ([`crate::wrapped_asset_tx`], [`crate::liquidation_tx`]) tallies
//! >=2/3 of bonded weight over ONE domain-separated message, because a ratio or an id is a value every
//! honest node reports IDENTICALLY. A PRICE is not: two honest custodians reading the market a second apart
//! report different numbers, so an identical-bytes tally would find a quorum only by coincidence, and
//! quantizing to a shared bucket splits the quorum whenever the market sits on a bucket boundary — a
//! liveness hole on the door that gates all issuance.
//!
//! So each attestor signs ITS OWN price, the object carries the quotes, and the door reduces them to one
//! number with a BOND-WEIGHTED MEDIAN. Every node applying the same object computes the same median from the
//! same bytes, so the mark is deterministic and consensus-safe without anyone agreeing in advance.
//!
//! ── THE SOUNDNESS BOUND, STATED BEFORE THE TEST SO THE RESULT CANNOT BE REINTERPRETED AFTER IT ─────────
//! Let `t` be the byzantine share of TOTAL bonded weight and `a` the share that attested. The door requires
//! `a >= 2/3`. The byzantine share OF THE ATTESTING SET is then at most `t/a`. Under the same `t < 1/3`
//! assumption the whole quorum already rests on:
//!
//! ```text
//!     t/a  <  (1/3) / (2/3)  =  1/2
//! ```
//!
//! A weighted median is the value at which cumulative weight first reaches half the attesting weight, so it
//! is bracketed by values whose weight from each end exceeds half. Byzantine weight is STRICTLY less than
//! half of the attesting set, so it cannot reach that point from either end: the median always lands inside
//! the range of HONEST quotes. Liars can move the mark only within the honest spread — never outside it.
//!
//! That is the guarantee AND its one boundary, stated honestly: it assumes `t < 1/3` of BONDED weight, which
//! is the identical assumption [`crate::peg::threshold_ok`] already makes for every reserve movement. A
//! majority-bonded adversary defeats this exactly as it defeats every other door, and no price mechanism can
//! do better. An ARITHMETIC MEAN would NOT have this property — one attestor quoting `u128::MAX` drags the
//! mean arbitrarily far — which is precisely why this is a median, and why
//! `one_extreme_liar_cannot_move_the_bond_weighted_median` measures it rather than asserting it.
//!
//! ── LIVENESS: THE BOND MAY NEVER BLOCK ISSUANCE OR WITHDRAWAL (CARDINAL) ──────────────────────────────
//! A missing or stale mark refuses THAT ASSET'S MINT and nothing else — the chain never halts, no other
//! asset is touched, and blocks keep being produced (a price mark is a governance-scale object, never
//! something a block or a note produces). REDEMPTION is deliberately NOT gated on freshness: a holder
//! redeeming uses the last accepted mark however old it is, because a holder must always be able to get
//! their money out. Gating withdrawal on a fresh quorum would hand the bonded set a way to trap funds,
//! which the cardinal forbids.
//! WHERE EACH HALF IS ENFORCED: a missing mark leaves the mint no backing at any door; a STALE one — the standing mark
//! misses the last closed price epoch — holds every honest custodian's attestation of new issuance
//! (`PegLedger::mint_price_stale`, read by `Node::issuance_hold_for`). Finding A-F69 (2026-11-15) measured that the first
//! sentence of this paragraph had been true only of a missing mark.
//!
//! ── COST — no pillar traded ───────────────────────────────────────────────────────────────────────────
//! PRIVACY: a price is public market data. No amount, owner, note or key is on this wire, and the mint
//! amount it gates stays committed (DB-80) — the mark says what a unit is worth, never who moved one.
//! NO-GROWTH: one mark per REGISTERED asset, a governance-scale set with no term in height, blocks, notes or
//! spends; the quote list is bounded by the bonded set at decode. SOUNDNESS: the mark moves no value by
//! itself; it is an input the mint door measures against, and every mint still proves its own carrier.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The quote list is bounded by the same protocol constant every other attested class uses — the bonded set
/// cannot exceed [`crate::params::DAG_WIDTH_CEILING`]. Entries beyond it are pure padding, so [`decode`]
/// refuses them before a single signature is verified (the bounded-work rule [`crate::peg::threshold_ok`]
/// carries, applied one layer earlier).
pub const MAX_PRICE_QUOTES: usize = crate::params::DAG_WIDTH_CEILING;

/// ⛔ A PRICE OF ZERO IS REFUSED AT THE WIRE, NOT CLAMPED. A zero mark makes every deposit worth nothing,
/// which would make every outstanding USDm instantly unbacked and every position instantly liquidatable.
/// It is not a value any honest attestor produces, so it is refused where bytes become this object.
pub const MIN_QUOTE_PRICE: u128 = 1;

/// The FIXED-WIDTH header of a block-carried price mark: which epoch and which asset. The price itself is
/// NOT here — it is derived from the quotes by [`bond_weighted_median`], so no publisher can assert a number
/// the attestors did not individually sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceMarkHeader {
    /// The epoch this mark belongs to. STRICTLY MONOTONE per asset at the door: that is the whole replay
    /// guard, and it needs no new state because the accepted mark already records the epoch it came from.
    pub epoch_id: u64,
    /// Which asset's PSM this marks — [`crate::peg::NATIVE_PEG_ASSET_ID`] or a registered wrapped asset.
    pub asset_id: u32,
}

/// ONE custodian's signed opinion of what one external ATOMIC unit is worth, in USDm-atomic units scaled by
/// [`crate::liquidation::PRICE_SCALE`]. Signed over [`crate::peg::PegLedger::price_mark_msg`] with THIS
/// quote's own price, so a quote cannot be lifted off one mark and replayed onto another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceQuote {
    /// USDm-atomic per external atomic unit, times `PRICE_SCALE`. Worked example at BTC = $60,000 with
    /// USDm at 8 decimals: 1 BTC = 1e8 sats = 6e12 USDm-atomic, so one sat is 60,000 USDm-atomic and the
    /// quote is `60_000 * PRICE_SCALE = 6e10`. At XMR = $150: one piconero is 0.015 USDm-atomic, quote
    /// `15_000`. Both are exact integers at this scale, which is why the scale exists.
    pub price: u128,
    /// O1-FOOTPRINT-REVIEWED: bounded by the same ceiling the peg's attestation lists use (enforced at decode).
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded as above.
    pub sig: Vec<u8>,
}

/// The accepted mark this node stands on for one asset: the median the door derived, and the epoch it came
/// from. Fixed-width; one per registered asset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceMark {
    /// USDm-atomic per external atomic unit, times [`crate::liquidation::PRICE_SCALE`].
    pub price: u128,
    /// The epoch of the object that set it — the monotone replay guard AND the staleness read.
    pub epoch_id: u64,
}

/// ⭐ DB-245 — A PRICE'S RANK WITHIN ITS EPOCH: the tiebreak that makes the standing mark a function of the
/// chain, not of graft order.
///
/// Two valid marks can exist for one `(epoch, asset)`: every quorate node publishes (DB-240), and two 2/3
/// subsets can have two different medians. Blocks graft in arrival order, so "the first mark of the epoch" is a
/// different mark on different nodes. The door instead keeps the MAXIMUM of one total order: a later epoch
/// wins, and within an epoch the SMALLER rank wins. A maximum does not depend on arrival order, which is
/// Kaspa's selected-parent rule (most blue work, then hash) applied to marks.
///
/// The rank hashes the PRICE, never the object's bytes:
///   * the standing mark's rank is recomputed from the `(price, epoch)` it already stores, so there is no new
///     state and no snapshot change;
///   * one price has exactly one rank, so a publisher cannot reorder quotes or swap signatures to make its
///     object win.
#[must_use]
pub fn price_rank(epoch_id: u64, asset_id: u32, price: u128) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD-price-mark-rank-v1");
    h.update(&epoch_id.to_le_bytes());
    h.update(&asset_id.to_le_bytes());
    h.update(&price.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Does a same-epoch `candidate` price outrank the `standing` one? Strictly smaller rank wins. An equal rank is
/// the same price, so a re-broadcast of the standing mark never outranks it.
#[must_use]
pub fn outranks(epoch_id: u64, asset_id: u32, candidate: u128, standing: u128) -> bool {
    price_rank(epoch_id, asset_id, candidate) < price_rank(epoch_id, asset_id, standing)
}

/// ⭐ THE BOND-WEIGHTED MEDIAN — the one reduction from many signed opinions to the single number consensus
/// stands on. See the module header for the `t < 1/3` bound this satisfies and why a mean would not.
///
/// Sorts by price and walks accumulating weight, returning the first price at which cumulative weight
/// reaches half the total. Deterministic for a given multiset of `(price, weight)` pairs regardless of the
/// order they arrived in, which is what makes two nodes applying the same object reach the same mark
/// (`the_median_is_independent_of_quote_order`).
///
/// ⛔ NEVER GUESSES A PRICE. `None` for an empty or zero-weight set, and `None` again if the walk somehow
/// completes without crossing the half-weight point. An earlier draft of this function fell back to the
/// LAST price there, with a comment arguing the branch was unreachable. It is unreachable — `acc` ends
/// equal to `total` and `total > 0` is checked above — which is exactly why returning a price from it was
/// indefensible: a branch that cannot be reached cannot be tested, so the one thing it must never do is
/// hand a door a number nobody attested. A caller with no median gets no mark, and the mint refuses.
#[must_use]
pub fn bond_weighted_median(quotes: &mut [(u128, u128)]) -> Option<u128> {
    let total: u128 = quotes.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w));
    if total == 0 {
        return None;
    }
    // Sort by PRICE. Ties keep whatever relative order they had; identical prices are interchangeable for
    // the result, so no tie-break rule can change the median.
    quotes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut acc: u128 = 0;
    for (price, weight) in quotes.iter() {
        acc = acc.saturating_add(*weight);
        // `2*acc >= total` is the half-weight point without dividing (no rounding to disagree about).
        if acc.saturating_mul(2) >= total {
            return Some(*price);
        }
    }
    None
}

/// The canonical payload bytes (unframed). An encoding failure yields EMPTY bytes rather than a panic, and
/// that empty vector is NOT a silent rescue — it does not `unframe` into a decodable object, so [`decode`]
/// refuses it, [`crate::chain_object::admissible`] refuses it, and [`apply_chain_price_mark`] reports
/// `NotPriceMark`. The failure surfaces as a refusal on the offending object alone instead of taking a node
/// down mid-block — the identical fail-closed contract [`crate::wrapped_asset_tx::encode`] and
/// [`crate::liquidation_tx::encode`] both carry, for the same reason, and deliberately not a second one.
pub fn encode(header: &PriceMarkHeader, quotes: &[PriceQuote]) -> Vec<u8> {
    postcard::to_stdvec(&(header, quotes)).unwrap_or_default()
}

/// The EXACT payload type this class's bytes deserialize to. Named so the wire-malleability fuzz family can
/// name the real type this arm decodes rather than approximate it.
pub type PriceMarkPayload = (PriceMarkHeader, Vec<PriceQuote>);

/// The ONE wire encoding: the canonical payload framed under this object's own class.
pub fn wire(header: &PriceMarkHeader, quotes: &[PriceQuote]) -> Vec<u8> {
    frame(Class::PriceMark, &encode(header, quotes))
}

/// THE ONE DECODE, and the ONE place this class's bounds live.
///
/// Goes through the shared [`decode_exact`], so `encode(x) || junk` is REFUSED rather than decoding to the
/// same object under a different content id — the wire-malleability hole the 2026-09-06 red team confirmed
/// at every class decoder. Then the bounds, BEFORE any signature is touched: a non-empty quote list at most
/// [`MAX_PRICE_QUOTES`] long, and every quote priced at or above [`MIN_QUOTE_PRICE`], so an object that
/// could only ever be refused never reaches a verify.
///
/// ROOT-LAYER: the bounds are produced HERE, where bytes become this object, not at each reader — a
/// per-reader check is how a fourth reader written tomorrow silently gets none.
pub fn decode(payload: &[u8]) -> Option<(PriceMarkHeader, Vec<PriceQuote>)> {
    let (header, quotes) = decode_exact::<PriceMarkPayload>(payload)?;
    if quotes.is_empty() || quotes.len() > MAX_PRICE_QUOTES {
        return None;
    }
    if quotes.iter().any(|q| q.price < MIN_QUOTE_PRICE) {
        return None;
    }
    // The same key/signature ceilings the peg's attestation lists carry, applied before a verify.
    if quotes.iter().any(|q| {
        q.pubkey.len() > crate::peg_attest::PEG_ATTEST_PUBKEY_MAX
            || q.sig.len() > crate::peg_attest::PEG_ATTEST_SIG_MAX
    }) {
        return None;
    }
    Some((header, quotes))
}

/// The quotes as the attestor shape the door's tally consumes, paired with the price each one signed.
#[must_use]
pub fn as_attestors(quotes: &[PriceQuote]) -> Vec<(u128, MintAttestor)> {
    quotes
        .iter()
        .map(|q| (q.price, MintAttestor { pubkey: q.pubkey.clone(), sig: q.sig.clone() }))
        .collect()
}

/// Wrap this object as the transaction that carries it into a block. A price mark mints nothing and burns
/// nothing, so it publishes no note, no nullifier, no bond and no stake: every list is empty, which is what
/// [`crate::chain_object::wrapper_binds_object`] requires for this class.
pub fn as_pq_tx(header: &PriceMarkHeader, quotes: &[PriceQuote], stamp_bits: u32) -> crate::mempool::PqTx {
    let blob = wire(header, quotes);
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
    // Grind the anti-spam stamp exactly as a real submit does — the measured reason
    // [`crate::wrapped_asset_tx::as_pq_tx`] records: a bare blob with `pow_stamp 0` is refused at the door
    // and at the floor, so a publishing route that skipped this would emit objects every node refuses.
    // Bounded BY CONSTRUCTION: 2^stamp_bits expected tries (~256 at the live 8-bit floor).
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

/// What the block-apply loop learned from one blob.
#[derive(Debug, PartialEq, Eq)]
pub enum PriceMarkApply {
    /// The blob is not a framed, in-bounds price mark — nothing to do, and nothing was touched.
    NotPriceMark,
    /// The door set this asset's mark to the derived median.
    Marked(u128),
    /// The door refused it (no >=2/3 weight, a bad signature that could have counted, or a non-advancing
    /// epoch). Nothing was touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::bridge::Custodian;

    fn header() -> PriceMarkHeader {
        PriceMarkHeader { epoch_id: 7, asset_id: crate::peg::NATIVE_PEG_ASSET_ID }
    }

    fn quote_from(seed: u8, h: &PriceMarkHeader, price: u128) -> PriceQuote {
        let msg = crate::peg::PegLedger::price_mark_msg(h.epoch_id, h.asset_id, price);
        let a = Custodian::generate(&[seed; 32]).attest(&msg);
        PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
    }

    /// The wire is ONE encoding, and a tolerated tail is refused — the shared `decode_exact` contract.
    /// Without it, `encode(x) || junk` would decode to the SAME object under a DIFFERENT content id.
    #[test]
    fn the_wire_round_trips_under_its_own_class_and_refuses_a_trailing_tail() {
        let h = header();
        let q = vec![quote_from(1, &h, 6_000)];
        let blob = wire(&h, &q);
        let (class, payload) = unframe(&blob).expect("it frames");
        assert_eq!(class, Class::PriceMark, "it frames under its own class");
        let (got, got_q) = decode(payload).expect("it decodes");
        assert_eq!(got, h, "the header survives the round trip");
        assert_eq!(got_q.len(), 1, "the quote survives the round trip");

        let mut tailed = payload.to_vec();
        tailed.push(0u8);
        assert!(decode(&tailed).is_none(), "a trailing tail is REFUSED, not tolerated");
    }

    /// ⛔ A ZERO PRICE WOULD MAKE EVERY DEPOSIT WORTHLESS AND EVERY POSITION LIQUIDATABLE. Refused where
    /// bytes become this object, so no door ever has to special-case it.
    #[test]
    fn a_zero_price_quote_is_refused_at_the_wire() {
        let h = header();
        let q = vec![quote_from(1, &h, 0)];
        let blob = wire(&h, &q);
        let (_class, payload) = unframe(&blob).expect("it frames");
        assert!(decode(payload).is_none(), "a zero-priced quote never decodes");
    }

    /// An empty quote list carries no opinion at all, and an over-long one is padding an attacker chose.
    #[test]
    fn an_empty_or_overlong_quote_list_is_refused_before_any_verify() {
        let h = header();
        let blob = wire(&h, &[]);
        let (_c, payload) = unframe(&blob).expect("it frames");
        assert!(decode(payload).is_none(), "an empty quote list is refused");

        let many: Vec<PriceQuote> =
            (0..=MAX_PRICE_QUOTES).map(|i| quote_from(i as u8, &h, 6_000)).collect();
        let blob = wire(&h, &many);
        let (_c, payload) = unframe(&blob).expect("it frames");
        assert!(decode(payload).is_none(), "a quote list past the bonded ceiling is refused");
    }

    /// ⭐ THE MEDIAN IS THE POINT — one liar quoting `u128::MAX` must NOT move the mark. This is the
    /// property an arithmetic mean does not have, stated as a test rather than as a claim.
    #[test]
    fn one_extreme_liar_cannot_move_the_bond_weighted_median() {
        let mut q = vec![(6_000u128, 10u128), (6_010, 10), (5_990, 10), (u128::MAX, 10)];
        let m = bond_weighted_median(&mut q).expect("a median exists");
        assert!((5_990..=6_010).contains(&m), "the median stays inside the honest spread, got {m}");
    }

    /// The median must not depend on the order quotes arrived in, or two nodes applying the SAME object
    /// would stand on different marks — a consensus split dressed as a rounding difference.
    #[test]
    fn the_median_is_independent_of_quote_order() {
        let base = [(5_000u128, 3u128), (7_000, 1), (6_000, 2), (9_000, 4)];
        let mut a = base.to_vec();
        let mut b = base.to_vec();
        b.reverse();
        let mut c = vec![base[2], base[0], base[3], base[1]];
        let ma = bond_weighted_median(&mut a).expect("median");
        let mb = bond_weighted_median(&mut b).expect("median");
        let mc = bond_weighted_median(&mut c).expect("median");
        assert_eq!(ma, mb, "reversing the quotes cannot move the mark");
        assert_eq!(ma, mc, "shuffling the quotes cannot move the mark");
    }

    /// Weight decides, not headcount: a single heavily-bonded honest attestor outvotes many tiny liars,
    /// which is what makes this a BOND-weighted median rather than a plain one.
    #[test]
    fn weight_decides_the_median_not_headcount() {
        let mut q = vec![(1u128, 1u128), (1, 1), (1, 1), (6_000, 100)];
        assert_eq!(bond_weighted_median(&mut q), Some(6_000), "the heavily-bonded quote carries the median");
    }

    /// An empty or zero-weight set has no median, and inventing one would be a price nobody attested.
    #[test]
    fn no_counted_weight_yields_no_median() {
        assert_eq!(bond_weighted_median(&mut []), None, "an empty set has no median");
        assert_eq!(
            bond_weighted_median(&mut [(6_000, 0), (7_000, 0)]),
            None,
            "zero total weight has no median"
        );
    }
}

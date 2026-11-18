// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE SWAP QUOTE — type an amount, see exactly what you get, click once.**
//!
//! This is what makes IonSwap feel like Uniswap while being a private order book underneath. A Uniswap
//! user does not think about orders: they choose a pair, type a number, and a quote appears. That
//! experience is produced here by WALKING RESTING ORDERS best-price-first, instead of evaluating a curve.
//!
//! ⭐⭐⭐ THE QUOTE IS EXACT, AND THAT IS STRICTLY BETTER THAN A CURVE. On an AMM the price moves
//! continuously as your own trade executes, so the number you were shown is an estimate and the
//! difference is price impact you discover afterwards. Here every rung is a FIXED price: taking three
//! rungs costs exactly those three prices. "Price impact" becomes visible and exact — it is simply
//! reaching further down the book — and the total is arithmetic, not a projection.
//!
//! ⛔ THE BOOK MAY MOVE BETWEEN QUOTE AND CLICK, AND THAT IS WHAT `min_out` IS FOR. A rung can be filled
//! by somebody else while a user is reading the screen. The plan built here is checked against the
//! user's own floor before anything is submitted, and a plan that no longer clears it is REFUSED rather
//! than quietly filled at a worse price. No retry, no counter: the user's order simply rests, or they
//! re-quote.
//!
//! ⛔ A PARTIAL FILL IS NAMED A PARTIAL FILL. If the book cannot cover the whole amount, `complete` is
//! false and the shortfall is stated. Silently filling less than asked, and letting the user discover it
//! from their balance, is the shape this project treats as a fund-visibility failure.

use usdm_decider::whir_rec_block::OrderTerms;
// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 149 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;

/// One resting order as the book serves it. `maker_payout_note` is the maker's own pre-built payout,
/// carried through a fill verbatim — the taker records those bytes and never has to trust them, because
/// the maker's half of the proof already attested what they contain.
#[derive(Clone, Debug)]
pub struct RestingOrder {
    /// The maker's half-proof, as published.
    pub maker_carrier: Vec<u8>,
    /// The maker's published nullifier / cross-bind / payout commitment.
    pub maker_nullifier: Digest4,
    pub maker_leaf_commit: Digest4,
    pub maker_payout_cm: Digest4,
    /// The maker's pre-built payout note bytes.
    pub maker_payout_note: Vec<u8>,
    /// ⭐ DB-150 — the maker's MEMBERSHIP cross-bind, as the book serves it: the recursive proof that the
    /// maker's own lot note is in the chain's note frontier, plus the endpoint it folded to. A fill carries
    /// both halves' binds, and only the maker can build theirs — so it travels with the offer.
    /// O1-FOOTPRINT-REVIEWED: bounded by usdmd_node::order_fill_tx::ORDER_FILL_MEMBERSHIP_CARRIER_MAX —
    /// the node refuses a wider order at the post door, so nothing wider can ever be served to a wallet.
    pub maker_membership_carrier: Vec<u8>,
    /// The endpoint of the bind above.
    /// O1-FOOTPRINT-REVIEWED: bounded by usdmd_node::order_fill_tx::ORDER_FILL_MEMBERSHIP_TIP_MAX — the
    /// node refuses any other endpoint width at the post door.
    pub maker_membership_tip: Vec<u8>,
    /// The terms this order rests at.
    pub terms: OrderTerms,
    /// ⛔ THE SETTLEMENT FEE RATE THE SERVING NODE WILL ENFORCE ON THIS FILL, as served with the level.
    ///
    /// It rides on the order rather than living in a constant because it is governance-tunable at
    /// runtime: a compiled-in copy silently diverges the moment governance moves it, and every wallet
    /// still holding the old number starts building halves the chain refuses. Carried per-order, the
    /// rate a taker prices against, affords against and PROVES against is the one that came back with
    /// the offer it is filling.
    pub fill_fee_bps: u64,
}

impl RestingOrder {
    /// What a taker RECEIVES from this rung, in `asset_a` units.
    pub fn receives(&self) -> u64 {
        self.terms.lot
    }
    /// What a taker PAYS to take this rung, in `asset_b` units — the maker's price PLUS the settlement
    /// fee the chain will take.
    ///
    /// ⛔⛔⛔ THE FEE IS PART OF THE COST, NOT A FOOTNOTE. Every consumer of this number is deciding
    /// affordability: which of my notes can take this rung, does the budget stretch to it, what does the
    /// quote total. `value_in == pay_b + fee + change` is the constraint the taker half is proved
    /// against, so a `costs()` that omitted the fee would qualify notes that cannot actually fill —
    /// the plan builds rung by rung and then dies on the last one with "insufficient", after the user
    /// was quoted a swap the wallet had already decided they could afford.
    pub fn costs(&self) -> u64 {
        // `saturating_add` rather than a wrap: a rung priced near u64::MAX is unaffordable either way,
        // and a wrapped total would read as CHEAP and be chosen first.
        self.terms.pay_b.saturating_add(self.terms.protocol_fee(self.fill_fee_bps))
    }
}

/// A quote: exactly which rungs to take and what it totals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuote {
    /// Indices into the book, in the order they will be taken (best price first).
    pub take: Vec<usize>,
    /// Total paid, in `asset_b`.
    pub total_in: u64,
    /// Total received, in `asset_a`.
    pub total_out: u64,
    /// True when the request was satisfied in full.
    pub complete: bool,
    /// How much of the request could NOT be met — 0 when `complete`.
    pub shortfall: u64,
}

impl SwapQuote {
    /// The effective price actually paid, in `asset_b` per whole unit of `asset_a`, scaled by `scale` so
    /// a caller can render decimals without floating point anywhere near a value.
    ///
    /// `None` on an empty quote: there is no price for a trade that does not happen, and returning 0
    /// would render as "free".
    pub fn effective_price(&self, scale: u64) -> Option<u64> {
        if self.total_out == 0 {
            return None;
        }
        let n = u128::from(self.total_in).checked_mul(u128::from(scale))?;
        u64::try_from(n / u128::from(self.total_out)).ok()
    }

    /// True when nothing could be taken at all.
    pub fn is_empty(&self) -> bool {
        self.take.is_empty()
    }
}

/// Why a quote could not become a submittable plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteError {
    /// No resting order matches this pair/direction.
    NoLiquidity,
    /// The book moved, or the request was never satisfiable at the user's floor.
    BelowMinimumOut,
    /// The request itself is not a trade.
    MalformedRequest,
}

impl QuoteError {
    /// What to show a user. Each states a fact; none says "try again".
    pub fn reason(self) -> &'static str {
        match self {
            QuoteError::NoLiquidity => "no resting orders for this pair right now",
            QuoteError::BelowMinimumOut => {
                "the book moved — this fill would land below the minimum you set, so nothing was submitted"
            }
            QuoteError::MalformedRequest => "that request is not a trade",
        }
    }
}

/// The rungs of `book` that trade `asset_a` for `asset_b`, BEST PRICE FIRST.
///
/// ⭐ BEST-PRICE-FIRST IS THE WHOLE OF "GOOD EXECUTION" HERE. A taker should always consume the cheapest
/// rung available, exactly as an AMM always trades at the current marginal price. Sorting by cost-per-lot
/// rather than by posting order is what makes that true regardless of how the book arrived.
fn matching_rungs(book: &[RestingOrder], asset_a: [u64; 3], asset_b: [u64; 3]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..book.len())
        .filter(|&i| book[i].terms.asset_a == asset_a && book[i].terms.asset_b == asset_b)
        .collect();
    // Cheapest per unit received first. Cross-multiplied so no division and no rounding decides
    // ordering — a rounded comparison can rank a worse rung first and quietly cost the taker money.
    idx.sort_by(|&x, &y| {
        let lhs = u128::from(book[x].costs()) * u128::from(book[y].receives());
        let rhs = u128::from(book[y].costs()) * u128::from(book[x].receives());
        lhs.cmp(&rhs).then(book[x].costs().cmp(&book[y].costs()))
    });
    idx
}

/// ⭐ QUOTE A BUY: "spend up to `budget` of `asset_b`, receive as much `asset_a` as that buys."
///
/// This is the Uniswap swap box. The walk takes whole rungs while the budget covers them — a rung is one
/// lot and is all-or-nothing, which is what makes the quote exact and the disclosure uniform.
pub fn quote_buy(
    book: &[RestingOrder],
    asset_a: [u64; 3],
    asset_b: [u64; 3],
    budget: u64,
) -> SwapQuote {
    let mut take = Vec::new();
    let (mut total_in, mut total_out) = (0u64, 0u64);
    if asset_a != asset_b && budget > 0 {
        for i in matching_rungs(book, asset_a, asset_b) {
            let cost = book[i].costs();
            let Some(next) = total_in.checked_add(cost) else { break };
            if next > budget {
                break; // the next rung is past the budget; stop rather than partially taking a lot
            }
            let Some(out) = total_out.checked_add(book[i].receives()) else { break };
            total_in = next;
            total_out = out;
            take.push(i);
        }
    }
    let shortfall = budget.saturating_sub(total_in);
    SwapQuote {
        take,
        total_in,
        total_out,
        // A buy is "complete" when no further rung could be afforded — i.e. the budget is spent as far
        // as the book allows. Leftover budget with rungs still available would mean the walk stopped early.
        complete: total_out > 0,
        shortfall,
    }
}

/// ⭐ QUOTE AN EXACT-OUTPUT BUY: "I want exactly `want_out` of `asset_a`, what does it cost?"
///
/// The other half of the Uniswap box (typing in the receive field). Reports a SHORTFALL when the book
/// cannot cover the amount, rather than returning a cheaper quote for less than was asked.
pub fn quote_for_exact_out(
    book: &[RestingOrder],
    asset_a: [u64; 3],
    asset_b: [u64; 3],
    want_out: u64,
) -> SwapQuote {
    let mut take = Vec::new();
    let (mut total_in, mut total_out) = (0u64, 0u64);
    if asset_a != asset_b && want_out > 0 {
        for i in matching_rungs(book, asset_a, asset_b) {
            if total_out >= want_out {
                break;
            }
            let (Some(nin), Some(nout)) = (
                total_in.checked_add(book[i].costs()),
                total_out.checked_add(book[i].receives()),
            ) else {
                break;
            };
            total_in = nin;
            total_out = nout;
            take.push(i);
        }
    }
    SwapQuote {
        take,
        total_in,
        total_out,
        complete: total_out >= want_out && want_out > 0,
        shortfall: want_out.saturating_sub(total_out),
    }
}

/// ⛔ THE SUBMIT GATE — re-check a quote against the user's own floor before anything is built.
///
/// A quote is a snapshot; the book is shared. Between rendering and clicking, another taker can consume
/// the rung this plan depends on. `min_out` is the user's stated floor, and a plan that no longer clears
/// it is REFUSED — never silently filled at whatever the book now offers, which is the failure a slippage
/// setting exists to prevent.
pub fn accept_quote(quote: &SwapQuote, min_out: u64) -> Result<(), QuoteError> {
    if quote.is_empty() || quote.total_out == 0 {
        return Err(QuoteError::NoLiquidity);
    }
    if quote.total_out < min_out {
        return Err(QuoteError::BelowMinimumOut);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The properties a trader's money depends on: best price first, an exact quote, an honest partial,
    //! and a floor that actually refuses.

    use super::*;
    use usdm_decider::whir_rec_block::wrapped_asset_tag_u32;

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag_u32(1)
    }
    fn usdm() -> [u64; 3] {
        crate::pq::USDM_ASSET_TAG
    }

    /// These tests isolate the QUOTE LADDER — ordering, greedy rung selection, shortfall reporting — so
    /// their rungs rest at a zero settlement rate and `costs()` is exactly the maker's price. That keeps
    /// each total here about the ladder and nothing else. The fee is not left untested by that choice:
    /// `execute_tests` runs the whole fill path at the chain's real rate — see
    /// `a_note_that_covers_the_price_but_not_the_fee_does_not_fund_the_rung`, where the fee decides what a
    /// note can fund and what the sealed change note ends up containing.
    const NO_FEE: u64 = 0;

    /// A resting ask: gives one lot of wBTC, wants `price` USDm.
    fn ask(lot: u64, price: u64) -> RestingOrder {
        RestingOrder {
            maker_carrier: vec![1u8; 8],
            maker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[price, 0, 0, 0]),
            maker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            maker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            maker_payout_note: vec![0u8; 1153],
            maker_membership_carrier: vec![2u8; 8],
            maker_membership_tip: vec![3u8; 8],
            fill_fee_bps: NO_FEE,
            terms: OrderTerms {
                lot,
                pay_b: price,
                asset_a: wbtc(),
                asset_b: usdm(),
                expires_at_height: 1_000_000,
            },
        }
    }

    /// ⭐⭐⭐ BEST PRICE FIRST — a taker always consumes the cheapest rung available, whatever order the
    /// book arrived in. Taking a dearer rung while a cheaper one rests is money out of the user's pocket.
    #[test]
    fn a_buy_always_takes_the_cheapest_rungs_first() {
        // Deliberately posted worst-first.
        let book = vec![ask(100, 700), ask(100, 500), ask(100, 600)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_200);
        assert_eq!(q.take, vec![1, 2], "the 500 and 600 rungs, in that order");
        assert_eq!((q.total_in, q.total_out), (1_100, 200));
    }

    /// ⭐ THE QUOTE IS EXACT — the total is the sum of the rungs taken, with no estimate anywhere. This is
    /// the property an AMM cannot offer, where the shown price moves as your own trade executes.
    #[test]
    fn the_quote_totals_exactly_the_rungs_it_takes() {
        let book = vec![ask(100, 500), ask(100, 550), ask(100, 600)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_100);
        assert_eq!(q.take.len(), 2);
        let paid: u64 = q.take.iter().map(|&i| book[i].costs()).sum();
        let got: u64 = q.take.iter().map(|&i| book[i].receives()).sum();
        assert_eq!((q.total_in, q.total_out), (paid, got), "totals are the rungs, not a projection");
        assert_eq!(q.effective_price(1), Some(5), "1050 paid for 200 out = 5 per unit");
    }

    /// ⛔ A RUNG IS ALL-OR-NOTHING: a budget that covers two rungs and part of a third takes TWO. A
    /// partial lot would make size informative again and break the uniform disclosure.
    #[test]
    fn a_budget_that_half_covers_a_rung_does_not_take_it() {
        let book = vec![ask(100, 500), ask(100, 500), ask(100, 500)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_400); // covers 2 rungs + 400 of a third
        assert_eq!(q.take.len(), 2, "no partial rung is taken");
        assert_eq!(q.total_in, 1_000);
        assert_eq!(q.shortfall, 400, "and the unspent budget is reported, not hidden");
    }

    /// ⛔⛔⛔ AN EXACT-OUT REQUEST THE BOOK CANNOT COVER IS A NAMED SHORTFALL, never a quieter quote for
    /// less than was asked. A user discovering a short fill from their balance is discovering it too late.
    #[test]
    fn an_exact_out_beyond_the_books_depth_reports_its_shortfall() {
        let book = vec![ask(100, 500), ask(100, 600)];
        let q = quote_for_exact_out(&book, wbtc(), usdm(), 500);
        assert!(!q.complete, "the book cannot cover 500");
        assert_eq!(q.total_out, 200, "it offers what it has");
        assert_eq!(q.shortfall, 300, "and states exactly what is missing");
    }

    /// ⭐ AN EXACT-OUT REQUEST THE BOOK CAN COVER stops as soon as it is covered — never over-buying.
    #[test]
    fn an_exact_out_request_stops_once_it_is_covered() {
        let book = vec![ask(100, 500), ask(100, 550), ask(100, 600)];
        let q = quote_for_exact_out(&book, wbtc(), usdm(), 200);
        assert!(q.complete);
        assert_eq!(q.take.len(), 2, "two rungs cover it; the third is not taken");
        assert_eq!(q.total_out, 200);
    }

    /// ⛔⛔⛔ THE FLOOR ACTUALLY REFUSES. If the book moved and the plan no longer clears the user's
    /// minimum, it is refused — not filled at whatever price the book now offers.
    #[test]
    fn a_plan_below_the_users_floor_is_refused_not_filled() {
        let book = vec![ask(100, 500), ask(100, 600)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_100);
        assert_eq!(q.total_out, 200);
        assert!(accept_quote(&q, 200).is_ok(), "meeting the floor exactly is acceptable");
        let e = accept_quote(&q, 300).unwrap_err();
        assert_eq!(e, QuoteError::BelowMinimumOut);
        assert!(e.reason().contains("nothing was submitted"), "and the user is told nothing happened");
    }

    /// ⛔ AN EMPTY BOOK QUOTES NOTHING AND SAYS SO — never a zero-priced or free-looking fill.
    #[test]
    fn an_empty_book_refuses_with_no_liquidity() {
        let q = quote_buy(&[], wbtc(), usdm(), 1_000);
        assert!(q.is_empty());
        assert_eq!(q.effective_price(1), None, "there is no price for a trade that does not happen");
        assert_eq!(accept_quote(&q, 1).unwrap_err(), QuoteError::NoLiquidity);
    }

    /// ⛔ RUNGS OF ANOTHER PAIR ARE NEVER TAKEN — a wETH ask cannot fill a wBTC buy however cheap it is.
    #[test]
    fn rungs_of_a_different_pair_are_never_matched() {
        let mut foreign = ask(100, 1); // absurdly cheap, wrong asset
        foreign.terms.asset_a = wrapped_asset_tag_u32(2);
        let book = vec![foreign, ask(100, 500)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_000);
        assert_eq!(q.take, vec![1], "only the wBTC rung is eligible");
        assert_eq!(q.total_in, 500);
    }

    /// ⛔ AN ASSET CANNOT BE SWAPPED FOR ITSELF, and a zero budget buys nothing.
    #[test]
    fn a_self_swap_or_a_zero_budget_quotes_nothing() {
        let book = vec![ask(100, 500)];
        assert!(quote_buy(&book, wbtc(), wbtc(), 1_000).is_empty());
        assert!(quote_buy(&book, wbtc(), usdm(), 0).is_empty());
    }
}

// ===================================================================================================
// ONE CLICK, MANY RUNGS — turning an accepted quote into the fills that execute it.
// ===================================================================================================

/// One rung of an accepted quote, built and ready to submit.
#[derive(Clone, Debug)]
pub struct PlannedFill {
    /// Index into the book this fill consumes.
    pub book_index: usize,
    /// The taker half, built from this wallet's own note.
    pub fill: crate::pq_order::BuiltFill,
    /// ⭐ DB-150 — THE NOTE THIS RUNG SPENDS. A fill must prove its input note is in the chain's note
    /// frontier, and that proof is about THIS note; without remembering which one was chosen the caller
    /// cannot build it. (Keys stay in the wallet: this is the same `LotNote` the caller already owns.)
    pub spent: crate::pq_ladder::LotNote,
}

/// ⭐⭐⭐ EXECUTE A QUOTE — build a taker half for every rung it takes.
///
/// A Uniswap swap is one click even when it crosses several ticks; this is the same. The user accepted
/// ONE quote, so they get ONE outcome: either every rung in it is built, or the swap does not happen.
///
/// ⛔⛔⛔ ALL OR NOTHING, AND THE REASON IS FUND SAFETY, NOT TIDINESS. Submitting a subset would fill the
/// user at a price they never agreed to — they accepted the AVERAGE of the whole plan, and the cheap
/// rungs are exactly the ones most likely to be taken by someone else first. Returning "here are 3 of
/// your 5 fills" hands the caller a decision the user already made, so a rung that cannot be built
/// aborts the whole plan and NOTHING is submitted.
///
/// `pay_notes` are notes of `asset_b` this wallet holds — one per rung, each holding exactly that rung's
/// cost, since a fill consumes a whole note and returns the remainder as change.
pub fn execute_quote(
    my_ek: &[u8],
    // DB-395: this wallet's own spend key — each rung's payout and change are sealed to it.
    my_spk: &Digest4,
    book: &[RestingOrder],
    quote: &SwapQuote,
    min_out: u64,
    pay_notes: &[crate::pq_ladder::LotNote],
) -> Result<Vec<PlannedFill>, QuoteError> {
    execute_quote_with_records(my_ek, my_spk, book, quote, min_out, pay_notes, None)
}

/// [`execute_quote`]'s one body. ⭐ DB-288 §9: `payout_records = Some((out_sk, indices))` seals rung `r`'s payout at its
/// reserved `(chg, indices[r])` with the record of the input that rung consumes; a list shorter than the plan refuses
/// the whole plan (all or nothing, as every other rung failure does).
pub fn execute_quote_with_records(
    my_ek: &[u8],
    my_spk: &Digest4,
    book: &[RestingOrder],
    quote: &SwapQuote,
    min_out: u64,
    pay_notes: &[crate::pq_ladder::LotNote],
    payout_records: Option<(&[u8; 32], &[u64])>,
) -> Result<Vec<PlannedFill>, QuoteError> {
    accept_quote(quote, min_out)?;
    if payout_records.is_some_and(|(_, idx)| idx.len() < quote.take.len()) {
        return Err(QuoteError::MalformedRequest);
    }
    let mut available: Vec<crate::pq_ladder::LotNote> = pay_notes.to_vec();
    let mut planned = Vec::with_capacity(quote.take.len());
    for (rung, &i) in quote.take.iter().enumerate() {
        let Some(order) = book.get(i) else {
            return Err(QuoteError::MalformedRequest);
        };
        // A note of the paying asset that covers this rung. Cheapest sufficient note first, so a large
        // note is not consumed for a small rung while a small one sits idle.
        let mut candidates: Vec<usize> = (0..available.len())
            .filter(|&k| {
                available[k].asset == order.terms.asset_b && available[k].amount >= order.costs()
            })
            .collect();
        candidates.sort_by_key(|&k| available[k].amount);
        let Some(&pick) = candidates.first() else {
            return Err(QuoteError::NoLiquidity);
        };
        let note = available.remove(pick);
        // The rate proved against is the one that came back WITH this offer — the same value the node
        // serving it enforces at settlement. Never a wallet-side constant, which would be a copy of a
        // runtime-tunable number and wrong the first time governance moves it.
        match crate::pq_order::fill_order_with_record(
            my_ek,
            my_spk,
            note.owner,
            note.amount,
            &order.maker_payout_note,
            &order.terms,
            order.fill_fee_bps,
            payout_records.map(|(out_sk, idx)| (out_sk, idx[rung])),
        ) {
            Ok(fill) => planned.push(PlannedFill { book_index: i, fill, spent: note }),
            // A rung that cannot be built aborts the PLAN — see the all-or-nothing note above.
            Err(_) => return Err(QuoteError::MalformedRequest),
        }
    }
    Ok(planned)
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use crate::pq_ladder::LotNote;
    use usdm_decider::whir_rec_block::wrapped_asset_tag_u32;

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag_u32(1)
    }
    fn usdm() -> [u64; 3] {
        crate::pq::USDM_ASSET_TAG
    }
    fn ek() -> Vec<u8> {
        crate::pq::derive_keys(&[3u8; 32]).scan_ek.clone()
    }
    /// DB-395: the same wallet's note keys — its `spk` seals the payouts and change, its `(ask, nk)` owns the notes.
    fn keys() -> crate::pq::NoteKeys {
        crate::pq::derive_keys(&[3u8; 32]).note_keys()
    }

    /// ⛔ THE CHAIN'S REAL RATE. This module builds actual fills — real proofs, real sealed change — so
    /// it runs at the live default rather than a convenient zero. At this rate a rung priced 500 costs a
    /// taker 501, and a 500-unit note no longer funds it: that is precisely the case a fee-blind wallet
    /// would have accepted and then failed to prove.
    const FEE: u64 = 10;

    fn ask(lot: u64, price: u64) -> RestingOrder {
        RestingOrder {
            maker_carrier: vec![1u8; 8],
            maker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[price, 0, 0, 0]),
            maker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            maker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            maker_payout_note: vec![0u8; 1153],
            maker_membership_carrier: vec![2u8; 8],
            maker_membership_tip: vec![3u8; 8],
            fill_fee_bps: FEE,
            terms: OrderTerms {
                lot,
                pay_b: price,
                asset_a: wbtc(),
                asset_b: usdm(),
                expires_at_height: 1_000_000,
            },
        }
    }

    fn note(amount: u64, seed0: u64) -> LotNote {
        LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[seed0, 2, 3, 4])), amount, asset: usdm() }
    }

    /// ⭐⭐⭐ ONE CLICK CROSSES SEVERAL RUNGS — a swap that walks three levels builds three fills from one
    /// accepted quote, exactly as a Uniswap swap crossing three ticks is still one action.
    #[test]
    fn one_accepted_quote_builds_a_fill_for_every_rung_it_crosses() {
        // 501 + 551 + 601: each rung costs the maker's price PLUS the fee the chain takes, and the
        // budget has to reach the fee-inclusive total or the third rung is simply not offered.
        let book = vec![ask(100, 500), ask(100, 550), ask(100, 600)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_653);
        assert_eq!(q.take.len(), 3, "the quote crosses three rungs");
        let notes = vec![note(501, 11), note(551, 22), note(601, 33)];
        let plan = execute_quote(&ek(), &keys().spk, &book, &q, q.total_out, &notes).expect("the swap builds");
        assert_eq!(plan.len(), 3, "one fill per rung");
        assert_eq!(
            plan.iter().map(|p| p.book_index).collect::<Vec<_>>(),
            q.take,
            "and they are the rungs the user was quoted, in order"
        );
    }

    /// ⛔⛔⛔ A PLAN THAT CANNOT BE FULLY BUILT SUBMITS NOTHING. Filling a subset would execute the user
    /// at a price they never agreed to — they accepted the AVERAGE of the whole plan, and the cheapest
    /// rungs are the first to disappear.
    #[test]
    fn a_plan_that_cannot_be_fully_funded_submits_nothing_at_all() {
        let book = vec![ask(100, 500), ask(100, 550)];
        let q = quote_buy(&book, wbtc(), usdm(), 1_052);
        assert_eq!(q.take.len(), 2);
        // Only one note: the second rung cannot be funded.
        let notes = vec![note(501, 11)];
        assert!(
            execute_quote(&ek(), &keys().spk, &book, &q, q.total_out, &notes).is_err(),
            "a partially fundable plan is refused whole"
        );
    }

    /// ⛔ THE FLOOR IS RE-CHECKED AT EXECUTE, not only at quote time — the book can move while the user
    /// reads the screen, and nothing is built when the plan no longer clears their minimum.
    #[test]
    fn the_floor_is_enforced_again_at_execution() {
        let book = vec![ask(100, 500)];
        let q = quote_buy(&book, wbtc(), usdm(), 501);
        let notes = vec![note(501, 11)];
        let e = execute_quote(&ek(), &keys().spk, &book, &q, 999, &notes).unwrap_err();
        assert_eq!(e, QuoteError::BelowMinimumOut);
    }

    /// ⭐ THE SMALLEST SUFFICIENT NOTE FUNDS EACH RUNG, so a large note is not spent on a small rung
    /// while a small one sits idle — the same reason a cashier does not break a 100 for a 5.
    #[test]
    fn each_rung_is_funded_by_the_smallest_note_that_covers_it() {
        let book = vec![ask(100, 500)];
        let q = quote_buy(&book, wbtc(), usdm(), 501);
        // ⛔ THE 500 NOTE NO LONGER COVERS A RUNG PRICED 500 — the fee is part of what a taker pays, so
        // the smallest SUFFICIENT note is 501. A fee-blind picker would have chosen the 500 and then
        // failed to build the very fill it had already committed the plan to.
        let notes = vec![note(10_000, 99), note(500, 11), note(501, 77)];
        let plan = execute_quote(&ek(), &keys().spk, &book, &q, q.total_out, &notes).expect("builds");
        assert_eq!(plan.len(), 1);
        // The 501 note was chosen: it covers price-plus-fee exactly, so the change note holds nothing.
        let (_amt, _seed, _asset) = crate::pq::scan_note_full_asset(
            &plan[0].fill.change_note,
            &crate::pq::derive_keys(&[3u8; 32]).scan_dk.to_vec(),
            &keys().spk,
        )
        .expect("our change");
        assert_eq!(_amt, 0, "the exact-fit note was used, leaving no change");
    }

    /// ⛔⛔⛔ A NOTE THAT COVERS THE PRICE BUT NOT THE FEE CANNOT FUND A RUNG. This is the whole reason
    /// `costs()` is fee-inclusive: the picker's affordability test and the prover's conservation
    /// constraint have to be the same question, or the plan qualifies a note that cannot fill and dies
    /// mid-build — after the user was quoted a swap the wallet had already told them they could afford.
    #[test]
    fn a_note_that_covers_the_price_but_not_the_fee_does_not_fund_the_rung() {
        let book = vec![ask(100, 500)];
        assert_eq!(book[0].costs(), 501, "the taker pays the price plus the chain's fee");
        let q = quote_buy(&book, wbtc(), usdm(), 501);
        assert_eq!(q.take.len(), 1, "the rung is affordable at 501");
        assert_eq!(
            execute_quote(&ek(), &keys().spk, &book, &q, q.total_out, &vec![note(500, 11)]).unwrap_err(),
            QuoteError::NoLiquidity,
            "and 500 — the maker's price exactly — does not fund it"
        );
    }
}

// ===================================================================================================
// THE LIVE BOOK FEED — reading real resting orders from a node, so a quote is of the real market.
// ===================================================================================================

/// Decode one `/book_level` entry into a `RestingOrder` this wallet can quote and fill against.
///
/// ⛔ EVERY FIELD IS REQUIRED, AND A MISSING ONE DROPS THE ENTRY RATHER THAN DEFAULTING IT. A defaulted
/// commitment is a value every forger can produce, and a defaulted payout note is an order that looks
/// fillable in the UI and is refused at settlement — a user spending effort, and possibly a race, on an
/// offer that was never real. An entry that does not decode in full is not shown.
pub fn decode_book_entry(
    entry: &serde_json::Value,
    asset_a: [u64; 3],
    asset_b: [u64; 3],
    fill_fee_bps: u64,
) -> Option<RestingOrder> {
    let hexf = |k: &str| -> Option<Vec<u8>> {
        hex::decode(entry.get(k)?.as_str()?).ok()
    };
    let limbs4 = |k: &str| -> Option<Digest4> {
        let b = hexf(k)?;
        if b.len() != 32 {
            return None;
        }
        // ONE codec per wire family (§AG/§AO, 2026-09-13): a served 32-byte commitment is the node's canonical
        // lane form — decoded by the node crate's own reader, never re-derived here (the retired 4×LE-u64 read
        // of this closure sliced 40 bytes from a 32-byte field once the digest went to eight lanes).
        let arr: [u8; 32] = b.as_slice().try_into().ok()?;
        usdmd_node::spend_frontier::cm_bytes_to_root(&arr)
    };
    let num = |k: &str| -> Option<u64> { entry.get(k)?.as_u64() };
    let payout_note = hexf("payout_note_hex")?;
    // A note too short to carry its own commitment can never satisfy the settlement binding.
    if payout_note.len() < 32 {
        return None;
    }
    let order = RestingOrder {
        maker_carrier: hexf("maker_bytes_hex")?,
        maker_nullifier: limbs4("nullifier")?,
        maker_leaf_commit: limbs4("leaf_commit")?,
        maker_payout_cm: limbs4("payout_cm")?,
        maker_payout_note: payout_note,
        // DB-150: a served order without its bind is unfillable — parse it, and let the fill refuse.
        maker_membership_carrier: hexf("membership_carrier_hex").unwrap_or_default(),
        maker_membership_tip: hexf("membership_tip_hex").unwrap_or_default(),
        terms: OrderTerms {
            lot: num("lot")?,
            pay_b: num("pay_b")?,
            asset_a,
            asset_b,
            expires_at_height: num("expires_at_height")?,
        },
        fill_fee_bps,
    };
    // ⛔⛔⛔ REFUSE AN OFFER WHOSE NOTE DOES NOT OPEN TO ITS OWN PUBLISHED COMMITMENT. The settlement gate
    // binds the credited note to `payout_cm`, so such an entry is a TRAP: it renders as a fillable offer
    // and is refused after the taker has committed effort and possibly lost a race for it. Checking here
    // means a bad offer never reaches a user's screen.
    let want = crate::pq_spend::cm_limbs_to_bytes(order.maker_payout_cm);
    if order.maker_payout_note[..32] != want[..] {
        return None;
    }
    Some(order)
}

/// Decode a whole `/book_level` response into the orders it serves.
///
/// ⭐ THE RESPONSE SHAPE IS CONSTANT BY DESIGN — `slots` is fixed and `empty` is the remainder — so a
/// busy level and an untouched one answer identically and polling reveals neither depth nor activity.
/// This reads only the entries; it never reports the padding as liquidity.
pub fn decode_book_level(
    body: &serde_json::Value,
    asset_a: [u64; 3],
    asset_b: [u64; 3],
) -> Vec<RestingOrder> {
    // ⛔⛔⛔ NO RATE, NO ORDERS. The settlement fee is what the taker half is PROVED against; without it
    //    this wallet would have to guess, and a guess that is wrong seals a change note for a different
    //    amount than the proof commits to — change that lands on-chain and can never be opened. There is
    //    no safe default here: `0` is not "unknown", it is a specific wrong answer that loses exactly the
    //    fee on every fill. So a level that does not publish its rate reads as EMPTY, exactly like a
    //    level that could not be reached — the DEX shows less depth, and never an unfillable offer.
    let Some(fill_fee_bps) = body.get("fill_fee_bps").and_then(|v| v.as_u64()) else {
        return Vec::new();
    };
    body.get("orders")
        .and_then(|o| o.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| decode_book_entry(e, asset_a, asset_b, fill_fee_bps))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod feed_tests {
    use super::*;
    use usdm_decider::whir_rec_block::wrapped_asset_tag_u32;

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag_u32(1)
    }
    fn usdm() -> [u64; 3] {
        crate::pq::USDM_ASSET_TAG
    }

    fn hex4(v: Digest4) -> String {
        hex::encode(crate::pq_spend::cm_limbs_to_bytes(v))
    }

    /// A well-formed entry as `/book_level` serves it, with a note that opens to its own commitment.
    fn entry(lot: u64, pay_b: u64, cm: Digest4) -> serde_json::Value {
        let mut note = vec![0u8; 1153];
        note[..32].copy_from_slice(&crate::pq_spend::cm_limbs_to_bytes(cm));
        serde_json::json!({
            "lot": lot,
            "pay_b": pay_b,
            "expires_at_height": 1_000_000u64,
            "nullifier": hex4(usdm_decider::poseidon2_compress::lanes_of(&[7, 0, 0, 0])),
            "leaf_commit": hex4(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])),
            "payout_cm": hex4(cm),
            "maker_bytes_hex": hex::encode([1u8, 2, 3, 4]),
            "payout_note_hex": hex::encode(&note),
        })
    }

    /// ⭐⭐⭐ A LIVE LEVEL DECODES INTO QUOTABLE ORDERS — the feed, end to end.
    #[test]
    fn a_served_level_decodes_into_orders_a_quote_can_walk() {
        // The rate the serving node will enforce travels with the level, exactly as `/book_level`
        // sends it — decoding is what stamps it onto every order the quote then prices against.
        let body = serde_json::json!({
            "status": "OK", "level": 12, "slots": 64, "empty": 62, "fill_fee_bps": 10,
            "orders": [entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0])), entry(100, 600, usdm_decider::poseidon2_compress::lanes_of(&[11, 0, 0, 0]))],
        });
        let book = decode_book_level(&body, wbtc(), usdm());
        assert_eq!(book.len(), 2, "both real entries decode");
        assert_eq!(book[0].fill_fee_bps, 10, "and each carries the rate it will settle under");
        // 501 + 601: the quote a user sees is what the fill will actually cost them, fee included.
        let q = quote_buy(&book, wbtc(), usdm(), 1_102);
        assert_eq!(q.total_out, 200, "and they are immediately quotable");
        assert_eq!(q.total_in, 1_102);
    }

    /// ⛔⛔⛔ A LEVEL THAT DOES NOT PUBLISH ITS SETTLEMENT RATE SERVES NO ORDERS. The rate is what the
    /// taker half is PROVED against; guessing it seals a change note for a different amount than the
    /// proof commits to, and that change lands on-chain unopenable. There is no safe default — `0` is
    /// not "unknown", it is a specific wrong answer that loses exactly the fee on every fill — so the
    /// level reads as empty, like one that could not be reached at all.
    #[test]
    fn a_level_that_does_not_publish_its_rate_yields_no_orders() {
        let with_rate = serde_json::json!({
            "status": "OK", "fill_fee_bps": 10,
            "orders": [entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]))],
        });
        assert_eq!(
            decode_book_level(&with_rate, wbtc(), usdm()).len(),
            1,
            "control: this identical entry DOES decode when the rate is published"
        );
        let no_rate = serde_json::json!({
            "status": "OK",
            "orders": [entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]))],
        });
        assert!(
            decode_book_level(&no_rate, wbtc(), usdm()).is_empty(),
            "and without the rate the very same offer is not shown at all"
        );
    }

    /// ⛔⛔⛔ THE WALLET PRICES AT THE RATE THE NODE SERVED, NOT AT THE DEFAULT IT WAS COMPILED WITH.
    /// The rate is governance-tunable at runtime, so the day it is retuned every wallet holding a
    /// compiled-in copy starts building halves the chain refuses — and the user sees refusals with no
    /// visible cause, on a book that looks perfectly normal.
    ///
    /// The two arms are each other's CONTROL: the same entry, decoded from two levels that differ only
    /// in the rate they publish, must price differently. A wallet that substituted a constant anywhere
    /// between `decode_book_level` and `costs()` would make both arms report the same number and fail
    /// here — which is the only way this seam can be checked, since every other test in this file uses
    /// the default and would pass unchanged.
    #[test]
    fn the_wallet_prices_at_the_served_rate_and_not_at_a_compiled_in_default() {
        let level = |bps: u64| {
            serde_json::json!({
                "status": "OK", "fill_fee_bps": bps,
                "orders": [entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]))],
            })
        };
        // The chain's current default, and a RETUNED rate governance could move to tomorrow.
        let at_default = decode_book_level(&level(10), wbtc(), usdm());
        let at_retuned = decode_book_level(&level(37), wbtc(), usdm());
        assert_eq!((at_default.len(), at_retuned.len()), (1, 1), "the same offer decodes either way");

        // ceil(500 * 10 / 10_000) = 1 and ceil(500 * 37 / 10_000) = 2 — the arithmetic is the decider's
        // own `protocol_fee`, not a second formula written here.
        assert_eq!(at_default[0].fill_fee_bps, 10);
        assert_eq!(at_retuned[0].fill_fee_bps, 37);
        assert_eq!(at_default[0].costs(), 501, "priced at the rate THIS level published");
        assert_eq!(at_retuned[0].costs(), 502, "and re-priced when the level publishes another");
        assert_ne!(
            at_default[0].costs(),
            at_retuned[0].costs(),
            "a wallet that used a constant instead of the served rate would price these identically"
        );
    }

    /// ⛔⛔⛔ AN OFFER WHOSE NOTE DOES NOT MATCH ITS COMMITMENT NEVER REACHES THE USER. It would render
    /// as fillable and be refused at settlement, after the taker had committed effort and maybe lost a
    /// race for it.
    #[test]
    fn an_offer_whose_note_contradicts_its_commitment_is_dropped_before_display() {
        let mut bad = entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]));
        let mut wrong = vec![0u8; 1153];
        wrong[..32].copy_from_slice(&[0xAB; 32]);
        bad["payout_note_hex"] = serde_json::json!(hex::encode(&wrong));
        let body =
            serde_json::json!({ "fill_fee_bps": 10, "orders": [bad, entry(100, 600, usdm_decider::poseidon2_compress::lanes_of(&[11, 0, 0, 0]))] });
        let book = decode_book_level(&body, wbtc(), usdm());
        assert_eq!(book.len(), 1, "the trap entry is dropped, the honest one kept");
        assert_eq!(book[0].costs(), 601, "the survivor prices at 600 plus its settlement fee");
    }

    /// ⛔ A MISSING FIELD DROPS THE ENTRY — never a defaulted commitment (a value every forger can
    /// produce) and never a defaulted note (an order that is refused at settlement).
    #[test]
    fn an_entry_missing_any_field_is_dropped_not_defaulted() {
        for missing in ["payout_note_hex", "maker_bytes_hex", "payout_cm", "nullifier", "lot"] {
            let mut e = entry(100, 500, usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]));
            e.as_object_mut().unwrap().remove(missing);
            let body = serde_json::json!({ "fill_fee_bps": 10, "orders": [e] });
            assert!(
                decode_book_level(&body, wbtc(), usdm()).is_empty(),
                "an entry without {missing} must not be shown as tradeable"
            );
        }
    }

    /// ⛔ THE CONSTANT-SHAPE PADDING IS NEVER COUNTED AS LIQUIDITY — an empty level quotes nothing.
    #[test]
    fn an_empty_level_offers_no_liquidity_despite_its_constant_shape() {
        let body = serde_json::json!({
            "status": "OK", "slots": 64, "empty": 64, "fill_fee_bps": 10, "orders": []
        });
        let book = decode_book_level(&body, wbtc(), usdm());
        assert!(book.is_empty());
        let q = quote_buy(&book, wbtc(), usdm(), 10_000);
        assert_eq!(accept_quote(&q, 1).unwrap_err(), QuoteError::NoLiquidity);
    }
}

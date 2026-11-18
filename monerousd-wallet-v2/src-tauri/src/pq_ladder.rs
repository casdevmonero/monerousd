// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **LIQUIDITY PROVISION WITHOUT A POOLED CELL — the auto-ladder.**
//!
//! An LP deposits, earns passively, withdraws later, and stays offline throughout. None of that needs a
//! shared pool. What the retired AMM got wrong was never "LPs earn fees" — it was ONE SHARED MUTABLE
//! SECRET CELL that every trade of a pair serialised through, and whose reserves had to be either public
//! (disclosing every position) or held by somebody (a censor). Delete the cell and the LP keeps all four
//! properties.
//!
//! **AN LP POSITION IS A LADDER OF RESTING ORDERS OVER THE LP'S OWN NOTES.** Adding liquidity splits the
//! deposit into fixed lots and posts orders across the price lattice, both sides of mid. The funds never
//! leave the LP's own notes and are never commingled with anyone's.
//!
//! ⭐ WHAT THE LP GETS, AND WHY IT IS BETTER THAN A POOL RATHER THAN A CONSOLATION:
//! * **Yield is the spread, from real fills** — buy below mid, sell above — not an emission that dilutes.
//! * **No impermanent loss from forced trading.** A pool's formula makes an LP trade against informed
//!   flow at a stale price (loss-versus-rebalancing). Here the LP chooses their own levels, and a level
//!   they never posted can never fill.
//! * **Withdrawal is instant.** Removing liquidity CANCELS unfilled orders by self-spending those notes —
//!   there is no pro-rata burn, no exit queue and no lock, because there is no pot to redeem a share of.
//! * **Offline is the normal state.** Orders rest; takers fill them; the LP is never consulted.
//!
//! ⭐⭐⭐ DEPTH AGGREGATES AT THE BOOK, NOT IN A CELL. A large trade consumes MANY LPs' orders in ONE
//! multi-input settlement, so traders see deep one-click liquidity while the protocol holds no shared
//! state. That is what a pool always was economically — aggregate depth — and aggregating it at the book
//! keeps fills parallel across the DAG instead of serialising them through one hot cell.
//!
//! ⛔ EVERY RUNG IS ONE LOT, BECAUSE SIZE MUST NOT BE INFORMATION. The book is world-readable, so an
//! order must tell prospective takers its size to be fillable. Fixed lots make that disclosure carry
//! nothing: a fill says "one lot at level L", which the tape already said. A ladder's DEPTH is its rung
//! COUNT, and per-level counts are cover-padded — so an LP's total position stays hidden even though
//! every individual order is public.

use usdm_decider::whir_rec_block::OrderTerms;
// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 149 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;

use crate::pq_order::{post_order, OrderError, PostedOrder};

/// One side of a ladder. A maker gives `asset_a` and wants `asset_b`, so an ASK ladder sells the token
/// for USDm and a BID ladder buys it — the same primitive with the assets swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// Selling `base` (giving base, wanting quote).
    Ask,
    /// Buying `base` (giving quote, wanting base).
    Bid,
}

/// What an LP asks for. Prices are LATTICE LEVELS, never free-form numbers: a distinctive price is an
/// identifier, and repeated distinctive prices link one maker's orders into a profile — the exact
/// identity leak the whole design exists to prevent.
#[derive(Clone, Copy, Debug)]
pub struct LadderPlan {
    /// The asset being made a market in.
    pub base: [u64; 3],
    /// What it trades against (USDm, by convention).
    pub quote: [u64; 3],
    /// One rung's size, in atomic units of `base`. A governance constant, identical for every LP.
    pub lot: u64,
    /// The mid level on the lattice, as `quote` atomic units per lot of `base`.
    pub mid_price_per_lot: u64,
    /// Spacing between rungs, in atomic `quote` units per lot. The lattice step.
    pub step: u64,
    /// How many rungs on EACH side. Total orders posted is `2 × rungs`.
    pub rungs: u32,
    /// The last height these orders may be filled at — the LP's own term.
    pub expires_at_height: u64,
    /// ⭐ THE LADDER COVER SEED (2026-10-28, hole scanner T1 `Serve::order_book_terms`): a per-ladder secret the wallet
    /// draws from its CSPRNG and never writes anywhere. Every rung takes its posting offset and its expiry extension
    /// from it (see [`LADDER_SPREAD_BLOCKS`]), so nothing a ladder emits says which rungs are one LP's.
    pub cover_seed: [u8; 32],
}

/// ⭐ THE LADDER COVER (2026-10-28, hole scanner T1 `Serve::order_book_terms`). Every public term of a rung is already a
/// protocol grid value (DEX-GRID C1–C3); what could still join one LP's rungs was the PATTERN of their arrival: posted
/// in one block, expiring in one epoch, in rung order. From the ladder's secret seed every rung takes (1) a DISTINCT
/// posting offset in `[0, LADDER_SPREAD_BLOCKS)` — a seeded shuffle, so no two rungs of one ladder enter the book in one
/// block and the arrival order is not the rung order — and (2) an expiry extension of `0..=LADDER_EXPIRY_EXTEND_EPOCHS`
/// epochs past the LP's term, never shorter (the LP's "fill until H" holds; cancelling is spending, at any time).
/// BORROWED: uniform wallet behaviour as the privacy mechanism — Monero's wallet-side decoy selection and Bitcoin
/// Core's wallet anti-fingerprinting rules: the node cannot know which rungs are one LP's, so the wallet behaves so
/// that nothing it emits says so. MEASURED by `a_ladders_rungs_arrive_in_distinct_blocks_in_no_rung_order_and_expire_in_different_epochs`.
/// cons: an LP's depth arrives over ≤ 32 blocks (16 s at the 500 ms target) instead of one block; a rung may rest up to
/// 4 epochs (256 blocks) past its term unless cancelled.
pub const LADDER_SPREAD_BLOCKS: u64 = 32;
pub const LADDER_EXPIRY_EXTEND_EPOCHS: u64 = 4;

impl LadderPlan {
    /// The `quote` price of rung `i` (0-based, outward from mid) on a given side.
    ///
    /// ⛔ AN ASK IS NEVER PLACED BELOW MID AND A BID IS NEVER PLACED ABOVE IT. Crossing your own mid
    /// means posting an order you would immediately want to take yourself: the LP pays the spread to
    /// somebody instead of earning it, on every rung, silently. The arithmetic is what prevents it —
    /// asks step UP from mid, bids step DOWN.
    fn rung_price(&self, side: Side, i: u32) -> Option<u64> {
        let offset = self.step.checked_mul(u64::from(i) + 1)?;
        match side {
            Side::Ask => self.mid_price_per_lot.checked_add(offset),
            // A bid below zero is not a price; the ladder simply stops there rather than wrapping.
            Side::Bid => self.mid_price_per_lot.checked_sub(offset),
        }
    }

    /// The terms of one rung. `None` when the rung falls off the bottom of the lattice.
    pub fn rung_terms(&self, side: Side, i: u32) -> Option<OrderTerms> {
        // DEX-GRID (C3): every public term through the ONE snap helper the node's fixtures use — price and lot rounded
        // DOWN onto the grid, expiry rounded UP to its epoch — so an LP's ladder carries no distinctive term and every
        // node's post door admits it.
        let price = usdmd_node::order_book::snap_to_grid(self.rung_price(side, i)?);
        let lot = usdmd_node::order_book::snap_to_grid(self.lot);
        // THE LADDER COVER: this rung's own epoch, `0..=LADDER_EXPIRY_EXTEND_EPOCHS` past the LP's term (never before it).
        let extend = self.cover_draw("expiry", side, i) % (LADDER_EXPIRY_EXTEND_EPOCHS + 1);
        let expires_at_height = usdmd_node::order_book::snap_expiry(self.expires_at_height)
            .saturating_add(extend.saturating_mul(usdmd_node::order_book::EXPIRY_EPOCH));
        if price == 0 || lot == 0 {
            return None; // a zero price or a zero lot is not a trade
        }
        Some(match side {
            // Selling the base: give one lot of base, receive `price` of quote.
            Side::Ask => OrderTerms {
                lot,
                pay_b: price,
                asset_a: self.base,
                asset_b: self.quote,
                expires_at_height,
            },
            // Buying the base: give `price` of quote, receive one lot of base. The assets swap, which is
            // why one primitive serves both sides.
            Side::Bid => OrderTerms {
                lot: price,
                pay_b: lot,
                asset_a: self.quote,
                asset_b: self.base,
                expires_at_height,
            },
        })
    }

    /// One draw of the ladder's cover stream, keyed by domain, side and rung index.
    fn cover_draw(&self, domain: &str, side: Side, i: u32) -> u64 {
        let mut h = blake3::Hasher::new_derive_key("MUSD/ladder-cover/v1");
        h.update(&self.cover_seed);
        h.update(domain.as_bytes());
        h.update(&[match side {
            Side::Ask => 0u8,
            Side::Bid => 1u8,
        }]);
        h.update(&i.to_le_bytes());
        u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().expect("8 bytes"))
    }

    /// THE LADDER COVER — each rung's posting offset from the height the LP commits at, in blocks: a seeded shuffle of
    /// `0..LADDER_SPREAD_BLOCKS`, so the offsets of one ladder are pairwise distinct while it has at most that many rungs
    /// (a wider ladder reuses the window in a second pass — stated here, not hidden). Rung order and arrival order are
    /// independent.
    #[must_use]
    pub fn post_offsets(&self) -> Vec<((Side, u32), u64)> {
        let rungs = self.rungs();
        let mut order: Vec<u64> = (0..LADDER_SPREAD_BLOCKS).collect();
        for k in (1..order.len()).rev() {
            let j = (self.cover_draw("shuffle", Side::Ask, k as u32) % (k as u64 + 1)) as usize;
            order.swap(k, j);
        }
        rungs.iter().enumerate().map(|(n, (side, i, _))| ((*side, *i), order[n % order.len()])).collect()
    }

    /// Every rung this plan describes, nearest-to-mid first on each side, as `(side, index, terms)`.
    /// Rungs that fall off the lattice are omitted rather than clamped — a clamped rung would silently
    /// stack several orders on one level, which is both a worse market and a size disclosure.
    pub fn rungs(&self) -> Vec<(Side, u32, OrderTerms)> {
        let mut out: Vec<(Side, u32, OrderTerms)> = Vec::with_capacity(self.rungs as usize * 2);
        for i in 0..self.rungs {
            for side in [Side::Ask, Side::Bid] {
                if let Some(t) = self.rung_terms(side, i) {
                    // DEX-GRID: a step finer than the grid snaps two rungs onto ONE price. Stacking them would be the
                    // size disclosure the off-the-bottom rule above already refuses, so a collapsed rung is OMITTED.
                    if out.iter().any(|(s, _, u)| *s == side && u.lot == t.lot && u.pay_b == t.pay_b) {
                        continue;
                    }
                    out.push((side, i, t));
                }
            }
        }
        out
    }

    /// What this plan will actually lock up, per asset: `(base_atomic, quote_atomic)`. The UI must show
    /// this BEFORE the LP commits — an LP who does not know what a ladder costs cannot consent to it.
    pub fn capital_required(&self) -> Option<(u64, u64)> {
        let (mut base, mut quote) = (0u64, 0u64);
        for (side, _, t) in self.rungs() {
            match side {
                Side::Ask => base = base.checked_add(t.lot)?,
                Side::Bid => quote = quote.checked_add(t.lot)?,
            }
        }
        Some((base, quote))
    }
}

/// A note this wallet can devote to a rung: its OWNER (DB-395: this wallet's `(ask, nk)` and the note's seed — what a
/// spend of it proves) and what it holds. Transient: built from the owned set when a ladder or fill is assembled.
#[derive(Clone, Copy, Debug)]
pub struct LotNote {
    pub owner: usdm_decider::whir_rec_block::NoteOwner,
    pub amount: u64,
    pub asset: [u64; 3],
}

impl LotNote {
    /// ⭐ DB-323 — THIS NOTE'S COMMITMENT, over its OWN asset tag, in the canonical byte form a membership bind names.
    /// The one place a spent lot's commitment is computed: `pq_spend::note_commitment` is the USDm-tagged one, so a
    /// bind built from it names a DIFFERENT note for every wrapped asset (for USDm the two are byte-identical).
    #[must_use]
    pub fn cm_bytes(&self) -> [u8; 32] {
        crate::pq_spend::cm_limbs_to_bytes(usdm_decider::whir_rec_block::asset_note_cm(
            self.amount,
            self.asset,
            self.owner.opening(),
        ))
    }
}

/// One rung that was actually posted.
#[derive(Clone, Debug)]
pub struct LadderRung {
    pub side: Side,
    pub index: u32,
    pub order: PostedOrder,
    /// ⭐ DB-318: the note this rung rests on (exactly `terms.lot` of `terms.asset_a`). The book refuses an order
    /// without the maker's membership cross-bind (DB-150), and that bind proves THIS note's commitment is on chain, so
    /// the poster needs the note itself, not only the order it funded.
    pub lot: LotNote,
}

/// The outcome of building a ladder. `posted` are live orders; `unfunded` are rungs the wallet had no
/// lot-sized note for.
///
/// ⛔ A PARTIAL LADDER IS REPORTED, NEVER HIDDEN. An LP who asked for ten rungs and got six has a
/// different position from the one they asked for, and finding that out from a thinner-than-expected
/// fill rate is finding out too late.
#[derive(Clone, Debug)]
pub struct BuiltLadder {
    pub posted: Vec<LadderRung>,
    pub unfunded: Vec<(Side, u32)>,
}

impl BuiltLadder {
    /// True when every rung the plan described was funded and posted.
    pub fn is_complete(&self) -> bool {
        self.unfunded.is_empty()
    }
}

/// ⭐ BUILD THE LADDER — post one resting order per rung, each over one of this wallet's own notes.
///
/// `lots` is the set of notes the LP is devoting. A rung is funded by a note of the RIGHT ASSET holding
/// EXACTLY the rung's `lot`; each note funds at most one rung, since a note spent twice is a note spent
/// once and refused the second time.
///
/// ⛔ NOTHING IS TRANSFERRED ANYWHERE. Each rung is an authorisation over a note that stays in this
/// wallet. There is no deposit address, no custodian and no pot — so there is no state in which an LP's
/// funds have left but their position does not yet exist.
pub fn build_ladder(
    my_ek: &[u8],
    // DB-395: this wallet's own spend key — every rung's payout note is sealed to it.
    my_spk: &Digest4,
    plan: &LadderPlan,
    lots: &[LotNote],
) -> Result<BuiltLadder, OrderError> {
    let mut available: Vec<LotNote> = lots.to_vec();
    let mut posted = Vec::new();
    let mut unfunded = Vec::new();

    for (side, index, terms) in plan.rungs() {
        // A rung gives `terms.lot` of `terms.asset_a`, so it needs a note of exactly that, in that asset.
        let pick = available
            .iter()
            .position(|n| n.asset == terms.asset_a && n.amount == terms.lot);
        let Some(pos) = pick else {
            unfunded.push((side, index));
            continue;
        };
        let note = available.remove(pos);
        match post_order(my_ek, my_spk, note.owner, &terms) {
            Ok(order) => posted.push(LadderRung { side, index, order, lot: note }),
            Err(OrderError::MalformedTerms) => unfunded.push((side, index)),
            // A seal or prove failure is a real fault, not a funding gap: surface it rather than
            // silently degrading the LP's position into a thinner one.
            Err(e) => return Err(e),
        }
    }
    Ok(BuiltLadder { posted, unfunded })
}

/// ⭐ WITHDRAW — the notes an LP must self-spend to cancel their unfilled rungs.
///
/// Cancelling IS spending: each resting order authorises consumption of one note, so spending that note
/// yourself burns the nullifier the order depends on and the order becomes unfillable. There is no
/// cancel message, no queue and nothing to acknowledge — which is why withdrawal cannot be censored,
/// delayed or front-run.
///
/// Returns the nullifiers of the rungs being cancelled, so the caller can spend exactly those notes.
pub fn cancel_nullifiers(ladder: &BuiltLadder) -> Vec<Digest4> {
    ladder.posted.iter().map(|r| r.order.public.nullifier).collect()
}

#[cfg(test)]
mod tests {
    //! A ladder is an LP's whole position, so the failures that matter are the ones that would quietly
    //! cost them money: a self-crossing rung, a rung funded by the wrong asset, and a partial build
    //! reported as complete.

    use super::*;
    use usdm_decider::whir_rec_block::wrapped_asset_tag_u32;

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag_u32(1)
    }
    fn usdm() -> [u64; 3] {
        crate::pq::USDM_ASSET_TAG
    }

    fn plan() -> LadderPlan {
        // DEX-GRID (C3): the fixture's lot and expiry are produced snapped, exactly as the wallet's commands produce them.
        LadderPlan {
            base: wbtc(),
            quote: usdm(),
            lot: usdmd_node::order_book::snap_to_grid(100_000),
            mid_price_per_lot: 6_500_000,
            step: 50_000,
            rungs: 3,
            expires_at_height: usdmd_node::order_book::snap_expiry(1_000_000),
            cover_seed: [7u8; 32],
        }
    }

    /// ⭐ THE LADDER COVER, MEASURED (hole scanner T1 `Serve::order_book_terms`): over 64 ladders, no two rungs of one
    /// ladder share a posting height; every rung's expiry is on the epoch grid, never before the LP's term and at most
    /// `LADDER_EXPIRY_EXTEND_EPOCHS` past it; the arrival order is not the rung order (a monotone arrival in at most 2 of
    /// 64 — for six rungs one shuffle in 720 is monotone); and the rungs of one ladder do not all share one epoch.
    #[test]
    fn a_ladders_rungs_arrive_in_distinct_blocks_in_no_rung_order_and_expire_in_different_epochs() {
        let epoch = usdmd_node::order_book::EXPIRY_EPOCH;
        let (mut monotone, mut one_epoch) = (0u32, 0u32);
        for s in 0..64u8 {
            let p = LadderPlan { cover_seed: [s; 32], ..plan() };
            let offs = p.post_offsets();
            assert_eq!(offs.len(), 6, "three rungs a side");
            let mut seen = std::collections::HashSet::new();
            for (_, o) in &offs {
                assert!(*o < LADDER_SPREAD_BLOCKS, "an offset outside the window");
                assert!(seen.insert(*o), "⛔ two rungs of one ladder enter the book in one block");
            }
            if offs.windows(2).all(|w| w[0].1 < w[1].1) {
                monotone += 1;
            }
            let exps: Vec<u64> = p.rungs().iter().map(|(_, _, t)| t.expires_at_height).collect();
            for e in &exps {
                assert_eq!(e % epoch, 0, "an expiry off the epoch grid");
                assert!(*e >= p.expires_at_height, "⛔ a rung expires before the LP's term");
                assert!(*e <= p.expires_at_height + LADDER_EXPIRY_EXTEND_EPOCHS * epoch, "past the stated extension");
            }
            if exps.iter().all(|e| *e == exps[0]) {
                one_epoch += 1;
            }
        }
        assert!(monotone <= 2, "⛔ arrival order follows rung order in {monotone}/64 ladders");
        assert!(one_epoch <= 8, "⛔ all rungs share one epoch in {one_epoch}/64 ladders");
        // refutation: the cover is the seed's — two seeds, two schedules
        assert_ne!(
            LadderPlan { cover_seed: [1u8; 32], ..plan() }.post_offsets(),
            LadderPlan { cover_seed: [2u8; 32], ..plan() }.post_offsets()
        );
    }

    fn ek() -> Vec<u8> {
        crate::pq::derive_keys(&[9u8; 32]).scan_ek.clone()
    }
    /// DB-395: the same wallet's note keys — its `spk` seals every rung's payout, its `(ask, nk)` owns every lot.
    fn keys() -> crate::pq::NoteKeys {
        crate::pq::derive_keys(&[9u8; 32]).note_keys()
    }

    /// ⛔⛔⛔ THE LADDER NEVER CROSSES ITS OWN MID. An ask below mid (or a bid above it) is an order the
    /// LP would immediately want to take themselves — they would pay the spread on every rung instead of
    /// earning it, silently, forever.
    #[test]
    fn asks_sit_above_mid_and_bids_below_and_never_cross() {
        let p = plan();
        for i in 0..p.rungs {
            let ask = p.rung_terms(Side::Ask, i).unwrap();
            let bid = p.rung_terms(Side::Bid, i).unwrap();
            // An ask asks MORE quote per lot than mid; a bid offers LESS.
            assert!(ask.pay_b > p.mid_price_per_lot, "ask rung {i} must be above mid");
            assert!(bid.lot < p.mid_price_per_lot, "bid rung {i} must be below mid");
            assert!(bid.lot < ask.pay_b, "a bid must never reach an ask — that is a self-cross");
        }
    }

    /// ⭐ RUNGS STEP OUTWARD, one lattice step at a time, on both sides.
    #[test]
    fn rungs_step_outward_from_mid_on_the_lattice() {
        let p = plan();
        let a: Vec<u64> = (0..p.rungs).map(|i| p.rung_terms(Side::Ask, i).unwrap().pay_b).collect();
        let b: Vec<u64> = (0..p.rungs).map(|i| p.rung_terms(Side::Bid, i).unwrap().lot).collect();
        // DECLARED AMENDMENT (DEX-GRID, 2026-09-30): each rung's price is its step-out value SNAPPED onto the protocol
        // grid; the claim (rungs step outward from mid, strictly) is unchanged.
        let snap = usdmd_node::order_book::snap_to_grid;
        assert_eq!(a, [6_550_000, 6_600_000, 6_650_000].map(snap).to_vec());
        assert_eq!(b, [6_450_000, 6_400_000, 6_350_000].map(snap).to_vec());
        assert!(a.windows(2).all(|w| w[0] < w[1]) && b.windows(2).all(|w| w[0] > w[1]), "strictly outward");
    }

    /// ⛔ A RUNG THAT FALLS OFF THE BOTTOM IS OMITTED, NOT CLAMPED. Clamping would stack several orders
    /// on one level — a worse market, and a disclosure of how much the LP wanted to place there.
    #[test]
    fn rungs_below_the_lattice_floor_are_omitted_not_clamped() {
        let p = LadderPlan { mid_price_per_lot: 100_000, step: 50_000, rungs: 4, ..plan() };
        let bids: Vec<u64> =
            (0..p.rungs).filter_map(|i| p.rung_terms(Side::Bid, i)).map(|t| t.lot).collect();
        // DECLARED AMENDMENT (DEX-GRID): the surviving rung's price is its step-out value snapped onto the grid.
        assert_eq!(bids, vec![usdmd_node::order_book::snap_to_grid(50_000)], "only the rung that fits remains");
        assert!(p.rung_terms(Side::Bid, 1).is_none(), "a zero price is not a rung");
        assert!(p.rung_terms(Side::Bid, 2).is_none(), "and neither is an underflowed one");
    }

    /// ⭐ AN LP IS TOLD WHAT THE LADDER COSTS, PER ASSET, BEFORE COMMITTING.
    #[test]
    fn the_capital_a_ladder_locks_is_stated_up_front() {
        let p = plan();
        let (base, quote) = p.capital_required().unwrap();
        assert_eq!(base, p.lot * 3, "three ask rungs, one lot of base each");
        // DECLARED AMENDMENT (DEX-GRID): each bid rung's price is snapped onto the grid.
        let snap = usdmd_node::order_book::snap_to_grid;
        assert_eq!(quote, snap(6_450_000) + snap(6_400_000) + snap(6_350_000), "three bid rungs at their own prices");
    }

    /// ⭐⭐⭐ A FUNDED LADDER POSTS EVERY RUNG, each over one of the LP's OWN notes, and the orders are
    /// distinct — one note per rung, so no two rungs depend on the same nullifier.
    #[test]
    fn a_fully_funded_ladder_posts_every_rung_over_its_own_note() {
        let p = plan();
        let mut lots: Vec<LotNote> = Vec::new();
        for i in 0..p.rungs {
            lots.push(LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[i as u64 + 1, 2, 3, 4])), amount: p.lot, asset: wbtc() });
            let bid = p.rung_terms(Side::Bid, i).unwrap();
            lots.push(LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[i as u64 + 100, 2, 3, 4])), amount: bid.lot, asset: usdm() });
        }
        let built = build_ladder(&ek(), &keys().spk, &p, &lots).expect("a funded ladder builds");
        assert!(built.is_complete(), "no rung is left unfunded: {:?}", built.unfunded);
        assert_eq!(built.posted.len(), 6, "three rungs a side");

        let nfs = cancel_nullifiers(&built);
        let uniq: std::collections::BTreeSet<_> = nfs.iter().collect();
        assert_eq!(uniq.len(), nfs.len(), "every rung rests on a DIFFERENT note");
    }

    /// ⛔⛔⛔ A PARTIAL LADDER IS REPORTED AS PARTIAL. An LP who asked for six rungs and got two has a
    /// different position from the one they asked for, and learning that from a thin fill rate is
    /// learning it too late.
    #[test]
    fn an_underfunded_ladder_names_exactly_which_rungs_did_not_post() {
        let p = plan();
        let lots = vec![
            LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), amount: p.lot, asset: wbtc() },
            // DECLARED AMENDMENT (DEX-GRID): the note that funds bid rung 0 holds exactly that rung's (snapped) price.
            LotNote {
                owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])),
                amount: p.rung_terms(Side::Bid, 0).unwrap().lot,
                asset: usdm(),
            },
        ];
        let built = build_ladder(&ek(), &keys().spk, &p, &lots).unwrap();
        assert!(!built.is_complete(), "an underfunded ladder is NOT complete");
        assert_eq!(built.posted.len(), 2, "only the two funded rungs posted");
        assert_eq!(built.unfunded.len(), 4, "and the other four are named");
    }

    /// ⛔ A NOTE OF THE WRONG ASSET NEVER FUNDS A RUNG — a wBTC note cannot back a bid that must pay
    /// USDm, however convenient its number looks.
    #[test]
    fn a_note_of_the_wrong_asset_never_funds_a_rung() {
        let p = plan();
        // A wBTC note numerically equal to the bid price — the wrong asset, right number.
        let lots = vec![LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), amount: 6_450_000, asset: wbtc() }];
        let built = build_ladder(&ek(), &keys().spk, &p, &lots).unwrap();
        assert!(built.posted.is_empty(), "no rung is funded by the wrong asset");
        assert_eq!(built.unfunded.len(), 6);
    }

    /// ⛔ ONE NOTE FUNDS AT MOST ONE RUNG. Reusing a note across rungs would post two orders on the same
    /// nullifier: the first fill kills the second, so half the ladder would be a phantom.
    #[test]
    fn one_note_cannot_fund_two_rungs() {
        let p = LadderPlan { rungs: 2, ..plan() };
        let lots = vec![LotNote { owner: keys().owner(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), amount: p.lot, asset: wbtc() }];
        let built = build_ladder(&ek(), &keys().spk, &p, &lots).unwrap();
        assert_eq!(built.posted.len(), 1, "the single note funds exactly one rung");
        assert!(built.unfunded.len() >= 1, "the rest are honestly unfunded");
    }
}

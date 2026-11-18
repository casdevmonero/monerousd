// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! What a shipped, protected purchase pays, to whom, on each event (spec sections 16.1, 16.4, 17).
//!
//! These are the rules the wallet shows before the tap and the defaults the vault will carry. They are
//! written once, here, in integer arithmetic. Two properties hold on every path and are tested on every
//! path: nothing is paid twice, and everything that was locked is paid out.
//!
//! The user's rule (2026-11-09): delivery to the address the buyer gave completes the sale. A wrong,
//! abandoned or undeliverable address "should not be on the seller".
//!
//! cons: none. Pure arithmetic over one purchase's terms. Nothing is stored, sent or logged.
//!
//! TWO-PARTY-REVIEWED: this file is integer arithmetic over one purchase's terms. It has no endpoint, no
//! message and no state, so there is no second side to disagree with: both wallets call this same function
//! on the same signed offer (one encoding, `offer.rs`). The two-party check, a buyer's wallet and a seller's
//! wallet on two real nodes holding the same payout, belongs to the vault's real-node check (spec section
//! 12, step 1) and is not claimed here.

use crate::offer::ReturnPolicy;

const BPS: u128 = 10_000;

/// The money terms of one shipped purchase, in atomic units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The goods, without postage.
    pub goods: u64,
    /// Postage one way.
    pub shipping: u64,
    /// The buyer's prompt deposit, in basis points of the goods.
    pub deposit_bps: u16,
    /// The seller's delivery bond, in basis points of the goods.
    pub bond_bps: u16,
    pub returns: ReturnPolicy,
}

/// What is locked when the purchase opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locked {
    /// Goods plus postage, from the buyer.
    pub price: u64,
    /// From the buyer; back when the buyer confirms.
    pub deposit: u64,
    /// From the seller; back when delivery is confirmed or proven.
    pub bond: u64,
}

impl Locked {
    pub fn total(&self) -> u64 {
        self.price + self.deposit + self.bond
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    AwaitingDelivery,
    /// Delivered; the price is held until the return window ends.
    ReturnWindow,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    // --- while awaiting delivery
    /// The buyer's wallet confirmed (by a tap, or by itself on the seller's proof).
    Confirmed,
    /// The buyer did not confirm; the seller proved the carrier's signed delivery notice.
    DeliveryProven,
    /// No confirmation and no proof by the deadline.
    DeadlinePassed,
    /// The carrier's signed notice says the parcel is coming back (refused, abandoned, undeliverable).
    ReturnedToSender,
    /// The carrier's signed notice admits the parcel was lost or destroyed in its hands.
    CarrierAdmitsLoss,
    /// The seller cancelled before the ship-by date.
    CancelledBeforeShipBy,
    // --- in the return window
    WindowEnded,
    /// A wrong-or-faulty claim: the carrier's signed notice of the return parcel.
    ReturnProven,
    /// A change of mind: a returns buyer checked the item at a counter and bought it.
    ReturnBought,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    pub to_seller: u64,
    pub to_buyer: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// The terms overflow, or the goods are worth nothing.
    Terms,
    /// The purchase is closed, or the event does not belong to this stage.
    NotNow,
    /// The merchant's return policy does not offer this.
    NotOffered,
}

fn share(amount: u64, bps: u16) -> u64 {
    // floor(amount * bps / 10_000): never more than `amount` because bps <= 10_000 is checked by the caller
    (u128::from(amount) * u128::from(bps) / BPS) as u64
}

impl Terms {
    pub fn locked(&self) -> Result<Locked, RuleError> {
        if self.goods == 0 || u128::from(self.deposit_bps) > BPS || u128::from(self.bond_bps) > BPS {
            return Err(RuleError::Terms);
        }
        let price = self.goods.checked_add(self.shipping).ok_or(RuleError::Terms)?;
        let deposit = share(self.goods, self.deposit_bps);
        let bond = share(self.goods, self.bond_bps);
        price.checked_add(deposit).and_then(|x| x.checked_add(bond)).ok_or(RuleError::Terms)?;
        Ok(Locked { price, deposit, bond })
    }
}

/// One shipped purchase. `held` is what is still locked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Purchase {
    pub terms: Terms,
    pub locked: Locked,
    pub stage: Stage,
    pub held: u64,
}

impl Purchase {
    pub fn open(terms: Terms) -> Result<Self, RuleError> {
        let locked = terms.locked()?;
        Ok(Purchase { terms, locked, stage: Stage::AwaitingDelivery, held: locked.total() })
    }

    fn pay(&mut self, to_seller: u64, to_buyer: u64, next: Stage) -> Payout {
        debug_assert!(to_seller + to_buyer <= self.held);
        self.held -= to_seller + to_buyer;
        self.stage = next;
        if next == Stage::Closed {
            debug_assert_eq!(self.held, 0);
        }
        Payout { to_seller, to_buyer }
    }

    /// Apply one event. An event that does not belong to the current stage changes nothing.
    pub fn apply(&mut self, event: Event) -> Result<Payout, RuleError> {
        let Locked { price, deposit, bond } = self.locked;
        let Terms { goods, shipping, returns, .. } = self.terms;
        match (self.stage, event) {
            (Stage::AwaitingDelivery, Event::Confirmed) | (Stage::AwaitingDelivery, Event::DeliveryProven) => {
                // the deposit goes back to a buyer who confirmed, and to the seller that had to prove delivery
                let (seller_extra, buyer_back) =
                    if event == Event::Confirmed { (0, deposit) } else { (deposit, 0) };
                if returns == ReturnPolicy::Final {
                    Ok(self.pay(price + bond + seller_extra, buyer_back, Stage::Closed))
                } else {
                    Ok(self.pay(bond + seller_extra, buyer_back, Stage::ReturnWindow))
                }
            }
            (Stage::AwaitingDelivery, Event::DeadlinePassed) => Ok(self.pay(0, price + deposit + bond, Stage::Closed)),
            (Stage::AwaitingDelivery, Event::ReturnedToSender) => {
                // the seller keeps the postage out and takes the postage back, never more than the goods
                let trip_back = shipping.min(goods);
                Ok(self.pay(bond + shipping + trip_back, goods - trip_back + deposit, Stage::Closed))
            }
            (Stage::AwaitingDelivery, Event::CarrierAdmitsLoss)
            | (Stage::AwaitingDelivery, Event::CancelledBeforeShipBy) => {
                Ok(self.pay(bond, price + deposit, Stage::Closed))
            }
            (Stage::ReturnWindow, Event::WindowEnded) => Ok(self.pay(price, 0, Stage::Closed)),
            (Stage::ReturnWindow, Event::ReturnProven) => match returns {
                ReturnPolicy::ReturnProof { .. } => Ok(self.pay(0, price, Stage::Closed)),
                _ => Err(RuleError::NotOffered),
            },
            (Stage::ReturnWindow, Event::ReturnBought) => {
                // a change of mind returns the goods; the postage out was spent and stays with the seller
                Ok(self.pay(shipping, goods, Stage::Closed))
            }
            _ => Err(RuleError::NotNow),
        }
    }
}

/// The loyalty gate (spec section 17.3): how much more this buyer may claim as wrong or faulty by return
/// proof, given what it has ALREADY paid this merchant before this order and what it has already claimed.
pub fn claim_room(paid_this_merchant_before: u64, already_claimed: u64, gate_bps: u16) -> u64 {
    if u128::from(gate_bps) > BPS {
        return 0;
    }
    share(paid_this_merchant_before, gate_bps).saturating_sub(already_claimed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOODS: u64 = 12_000_000_000; // $120.00 at 1e8 atomic units per dollar
    const POST: u64 = 720_000_000; //   $7.20

    fn terms(returns: ReturnPolicy) -> Terms {
        Terms { goods: GOODS, shipping: POST, deposit_bps: 200, bond_bps: 500, returns }
    }

    const PROOF: ReturnPolicy = ReturnPolicy::ReturnProof { window_ms: 1, gate_bps: 300 };
    const ALL_EVENTS: [Event; 9] = [
        Event::Confirmed,
        Event::DeliveryProven,
        Event::DeadlinePassed,
        Event::ReturnedToSender,
        Event::CarrierAdmitsLoss,
        Event::CancelledBeforeShipBy,
        Event::WindowEnded,
        Event::ReturnProven,
        Event::ReturnBought,
    ];

    #[test]
    fn the_sheet_shows_the_deposit_the_spec_shows() {
        let l = terms(PROOF).locked().unwrap();
        assert_eq!(l.price, 12_720_000_000); // $127.20
        assert_eq!(l.deposit, 240_000_000); //   $2.40
        assert_eq!(l.bond, 600_000_000); //      $6.00
    }

    /// Every sequence of events, on every policy: nothing is paid twice and nothing is left locked.
    #[test]
    fn every_path_pays_out_exactly_what_was_locked() {
        let policies = [
            ReturnPolicy::Final,
            PROOF,
            ReturnPolicy::Counter { window_ms: 1 },
            ReturnPolicy::SealedPackCounter { window_ms: 1 },
        ];
        let mut closed_paths = 0;
        for policy in policies {
            for first in ALL_EVENTS {
                for second in ALL_EVENTS {
                    for third in ALL_EVENTS {
                        let mut p = Purchase::open(terms(policy)).unwrap();
                        let total = p.locked.total();
                        let mut paid = 0u64;
                        for e in [first, second, third] {
                            if let Ok(out) = p.apply(e) {
                                paid += out.to_seller + out.to_buyer;
                            }
                        }
                        assert_eq!(paid + p.held, total, "{policy:?} {first:?} {second:?} {third:?}");
                        if p.stage == Stage::Closed {
                            assert_eq!(p.held, 0);
                            assert_eq!(paid, total);
                            closed_paths += 1;
                            for e in ALL_EVENTS {
                                assert_eq!(p.apply(e), Err(RuleError::NotNow), "a closed purchase pays nothing more");
                            }
                        }
                    }
                }
            }
        }
        assert!(closed_paths > 1000);
    }

    #[test]
    fn an_honest_sale_gives_the_seller_the_price_and_everyone_their_own_money_back() {
        let mut p = Purchase::open(terms(PROOF)).unwrap();
        assert_eq!(p.apply(Event::Confirmed), Ok(Payout { to_seller: 600_000_000, to_buyer: 240_000_000 }));
        assert_eq!(p.stage, Stage::ReturnWindow);
        assert_eq!(p.apply(Event::WindowEnded), Ok(Payout { to_seller: 12_720_000_000, to_buyer: 0 }));
    }

    #[test]
    fn a_buyer_who_will_not_confirm_a_delivered_parcel_loses_the_deposit_and_nothing_else() {
        let mut p = Purchase::open(terms(ReturnPolicy::Final)).unwrap();
        let out = p.apply(Event::DeliveryProven).unwrap();
        assert_eq!(out.to_buyer, 0);
        assert_eq!(out.to_seller, 12_720_000_000 + 600_000_000 + 240_000_000);
    }

    #[test]
    fn a_seller_that_proves_nothing_by_the_deadline_refunds_and_loses_its_bond() {
        let mut p = Purchase::open(terms(PROOF)).unwrap();
        let out = p.apply(Event::DeadlinePassed).unwrap();
        assert_eq!(out, Payout { to_seller: 0, to_buyer: 12_720_000_000 + 240_000_000 + 600_000_000 });
    }

    /// The user's rule: an address the parcel cannot be delivered to is not the seller's loss.
    #[test]
    fn a_parcel_that_comes_back_repays_the_sellers_postage_both_ways() {
        let mut p = Purchase::open(terms(PROOF)).unwrap();
        let out = p.apply(Event::ReturnedToSender).unwrap();
        assert_eq!(out.to_seller, 600_000_000 + 2 * POST, "its bond, and the postage out and back");
        assert_eq!(out.to_buyer, GOODS - POST + 240_000_000, "the goods less the trip back, and the deposit");
        // postage dearer than the goods never takes more than the goods
        let mut cheap = Purchase::open(Terms { goods: 100, shipping: 500, ..terms(PROOF) }).unwrap();
        let out = cheap.apply(Event::ReturnedToSender).unwrap();
        assert_eq!((out.to_seller, out.to_buyer), (cheap.locked.bond + 500 + 100, cheap.locked.deposit));
    }

    #[test]
    fn a_loss_the_carrier_admits_or_an_early_cancel_costs_the_seller_no_bond() {
        for e in [Event::CarrierAdmitsLoss, Event::CancelledBeforeShipBy] {
            let mut p = Purchase::open(terms(PROOF)).unwrap();
            assert_eq!(p.apply(e), Ok(Payout { to_seller: 600_000_000, to_buyer: 12_720_000_000 + 240_000_000 }));
        }
    }

    #[test]
    fn a_wrong_or_faulty_return_refunds_the_whole_price_only_where_the_merchant_offers_it() {
        let mut p = Purchase::open(terms(PROOF)).unwrap();
        p.apply(Event::Confirmed).unwrap();
        assert_eq!(p.apply(Event::ReturnProven), Ok(Payout { to_seller: 0, to_buyer: 12_720_000_000 }));
        for policy in [ReturnPolicy::Counter { window_ms: 1 }, ReturnPolicy::SealedPackCounter { window_ms: 1 }] {
            let mut p = Purchase::open(terms(policy)).unwrap();
            p.apply(Event::Confirmed).unwrap();
            assert_eq!(p.apply(Event::ReturnProven), Err(RuleError::NotOffered));
            assert_eq!(p.stage, Stage::ReturnWindow, "a refused event changes nothing");
        }
    }

    #[test]
    fn a_change_of_mind_returns_the_goods_and_leaves_the_postage_with_the_seller() {
        let mut p = Purchase::open(terms(ReturnPolicy::Counter { window_ms: 1 })).unwrap();
        p.apply(Event::Confirmed).unwrap();
        assert_eq!(p.apply(Event::ReturnBought), Ok(Payout { to_seller: POST, to_buyer: GOODS }));
    }

    #[test]
    fn a_final_sale_has_no_return_window() {
        let mut p = Purchase::open(terms(ReturnPolicy::Final)).unwrap();
        p.apply(Event::Confirmed).unwrap();
        assert_eq!(p.stage, Stage::Closed);
        assert_eq!(p.apply(Event::ReturnProven), Err(RuleError::NotNow));
    }

    #[test]
    fn terms_that_overflow_or_sell_nothing_are_refused() {
        assert_eq!(Purchase::open(Terms { goods: 0, ..terms(PROOF) }), Err(RuleError::Terms));
        assert_eq!(Purchase::open(Terms { goods: u64::MAX, ..terms(PROOF) }), Err(RuleError::Terms));
        assert_eq!(Purchase::open(Terms { deposit_bps: 10_001, ..terms(PROOF) }), Err(RuleError::Terms));
        // price fits, price + deposit fits, price + deposit + bond does not
        let big = Terms { goods: u64::MAX / 2, shipping: 0, deposit_bps: 10_000, bond_bps: 10_000, returns: PROOF };
        assert_eq!(Purchase::open(big), Err(RuleError::Terms));
        assert!(Purchase::open(Terms { bond_bps: 0, ..big }).is_ok());
    }

    #[test]
    fn the_loyalty_gate_counts_only_what_was_already_paid_and_never_goes_negative() {
        // $1,000 already paid this merchant at a 3 % gate: $30 of claims
        assert_eq!(claim_room(100_000_000_000, 0, 300), 3_000_000_000);
        assert_eq!(claim_room(100_000_000_000, 2_000_000_000, 300), 1_000_000_000);
        assert_eq!(claim_room(100_000_000_000, 9_000_000_000, 300), 0);
        assert_eq!(claim_room(0, 0, 300), 0, "a first order has no room");
        assert_eq!(claim_room(u64::MAX, 0, 10_000), u64::MAX);
        assert_eq!(claim_room(u64::MAX, 0, 10_001), 0);
    }
}

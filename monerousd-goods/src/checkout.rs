// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! One shipped order, from the offer to the last payout (spec sections 16.1 and 26.3).
//!
//! This is the order as both wallets and the merchant's checkout helper track it: which step it is at, what
//! each event does, and what the helper tells the shop (its webhooks). It joins the other three modules:
//! an [`crate::offer::Offer`] opens it, a carrier's [`crate::notice::Fact`] moves it, [`crate::rules`] pays it.
//!
//! The order of steps is enforced here, not left to the caller:
//! - nothing ships before the buyer's wallet has pinned ONE tracking number;
//! - a carrier notice counts only for the pinned parcel and only if the carrier signed it after the pin;
//! - a notice that the parcel came back, or was lost, ends the order the way spec section 16.4 says.
//!
//! cons: none. A pure state machine over one order. It stores, sends and logs nothing; a caller that keeps
//! orders keeps one fixed-size record per OPEN order and drops it when the order closes.
//!
//! TWO-PARTY-REVIEWED: a pure state machine with no endpoint. The buyer's wallet and the seller's helper each
//! run this same code on the same signed offer and the same carrier-signed notice, so there is no second
//! implementation to disagree with. Two wallets on two real nodes reaching the same payout is the vault's
//! real-node check (spec section 12 step 1) and is not claimed here.

use crate::notice::{Fact, Status};
use crate::offer::{Delivery, Offer};
use crate::rules::{Event, Payout, Purchase, RuleError, Stage, Terms};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The buyer's money is locked. Nothing may ship yet.
    Locked,
    /// The buyer's wallet accepted one tracking number.
    Pinned,
    /// The seller recorded the hand-over to the carrier.
    Shipped,
    /// Delivered and settled; the price is held for the return window.
    InReturnWindow,
    Closed,
}

/// What moves an order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// The buyer's wallet accepted this tracking number at this time (spec section 16.3).
    Pin { tracking: String, at_s: u64 },
    /// The seller handed the pinned parcel to the carrier.
    Ship,
    /// The buyer's wallet confirmed delivery.
    Confirm,
    /// A carrier-signed notice, already verified and read (`notice::verify`, `notice::read`).
    Notice(Fact),
    /// The delivery deadline passed with no confirmation and no proof.
    Deadline,
    /// The seller cancelled. Accepted only before the parcel shipped.
    Cancel,
    /// The return window ended.
    WindowEnd,
    /// A carrier-signed notice for the RETURN parcel (the seller's own return label).
    ReturnNotice(Fact),
    /// A returns buyer checked the item at a counter and bought it.
    ReturnBought,
}

/// What the checkout helper tells the shop (spec section 26.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Webhook {
    OrderPinned,
    OrderShipped,
    OrderDelivered,
    OrderPaid,
    OrderRefunded,
    OrderCancelled,
    ReturnRefunded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    /// The offer is not a shipped sale, or its terms cannot be locked.
    NotShipped,
    /// The input does not belong to this step. Nothing changed.
    NotNow,
    /// The notice is about another parcel, or the carrier signed it before the pin. Nothing changed.
    NotThisParcel,
    /// The tracking number is not one a carrier writes.
    Tracking,
    Rule(RuleError),
}

/// The pinned return parcel: the seller's own return label, fixed in the offer's terms at the order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnLabel {
    pub tracking: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub step: Step,
    pub purchase: Purchase,
    /// The one parcel this order is about, and when the buyer's wallet accepted it.
    pub pinned: Option<(String, u64)>,
    pub return_label: Option<ReturnLabel>,
    /// When the return window opened, so a return notice older than that is refused.
    pub delivered_at_s: Option<u64>,
}

fn carrier_tracking(s: &str) -> bool {
    (8..=34).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

impl Order {
    /// Open an order from a verified offer, once the buyer's money is seen locked.
    pub fn open(offer: &Offer, return_label: Option<ReturnLabel>) -> Result<Self, OrderError> {
        let Delivery::Shipped { returns, deposit_bps, bond_bps, shipping, .. } = &offer.delivery else {
            return Err(OrderError::NotShipped);
        };
        let goods = offer.total.checked_sub(*shipping).ok_or(OrderError::NotShipped)?;
        let terms = Terms { goods, shipping: *shipping, deposit_bps: *deposit_bps, bond_bps: *bond_bps, returns: *returns };
        if let Some(label) = &return_label {
            if !carrier_tracking(&label.tracking) {
                return Err(OrderError::Tracking);
            }
        }
        Ok(Order {
            step: Step::Locked,
            purchase: Purchase::open(terms).map_err(OrderError::Rule)?,
            pinned: None,
            return_label,
            delivered_at_s: None,
        })
    }

    fn settle(&mut self, event: Event) -> Result<Payout, OrderError> {
        let out = self.purchase.apply(event).map_err(OrderError::Rule)?;
        self.step = match self.purchase.stage {
            Stage::ReturnWindow => Step::InReturnWindow,
            Stage::Closed => Step::Closed,
            Stage::AwaitingDelivery => self.step,
        };
        Ok(out)
    }

    fn about_pinned(&self, fact: &Fact) -> bool {
        self.pinned.as_ref().map(|(t, at)| fact.settles(t, *at)).unwrap_or(false)
    }

    /// Apply one input. Returns what was paid (if anything) and what the helper tells the shop.
    /// An input that is refused changes nothing.
    pub fn apply(&mut self, input: Input) -> Result<(Option<Payout>, Option<Webhook>), OrderError> {
        match (self.step, input) {
            (Step::Locked, Input::Pin { tracking, at_s }) => {
                if !carrier_tracking(&tracking) {
                    return Err(OrderError::Tracking);
                }
                // the return label is the seller's own parcel number: it can never also be the outbound one
                if self.return_label.as_ref().map(|l| l.tracking == tracking).unwrap_or(false) {
                    return Err(OrderError::Tracking);
                }
                self.pinned = Some((tracking, at_s));
                self.step = Step::Pinned;
                Ok((None, Some(Webhook::OrderPinned)))
            }
            (Step::Pinned, Input::Ship) => {
                self.step = Step::Shipped;
                Ok((None, Some(Webhook::OrderShipped)))
            }
            (Step::Locked, Input::Cancel) | (Step::Pinned, Input::Cancel) => {
                let out = self.settle(Event::CancelledBeforeShipBy)?;
                Ok((Some(out), Some(Webhook::OrderCancelled)))
            }
            (Step::Locked, Input::Deadline) | (Step::Pinned, Input::Deadline) | (Step::Shipped, Input::Deadline) => {
                let out = self.settle(Event::DeadlinePassed)?;
                Ok((Some(out), Some(Webhook::OrderRefunded)))
            }
            (Step::Shipped, Input::Confirm) => {
                // the buyer confirms on its own tap, or its wallet does on the seller's forwarded notice;
                // the window is dated from the pin, the latest time this code can vouch for
                let at = self.pinned.as_ref().map(|(_, at)| *at).unwrap_or(0);
                self.delivered_at_s = Some(at);
                let out = self.settle(Event::Confirmed)?;
                Ok((Some(out), Some(self.after_delivery())))
            }
            (Step::Shipped, Input::Notice(fact)) => {
                if !self.about_pinned(&fact) {
                    return Err(OrderError::NotThisParcel);
                }
                let (event, hook) = match fact.status {
                    Status::Delivered => (Event::DeliveryProven, None),
                    Status::ReturnedToSender => (Event::ReturnedToSender, Some(Webhook::OrderRefunded)),
                    Status::Lost => (Event::CarrierAdmitsLoss, Some(Webhook::OrderRefunded)),
                };
                if fact.status == Status::Delivered {
                    self.delivered_at_s = Some(fact.signed_at_s);
                }
                let out = self.settle(event)?;
                Ok((Some(out), Some(hook.unwrap_or_else(|| self.after_delivery()))))
            }
            (Step::InReturnWindow, Input::WindowEnd) => {
                let out = self.settle(Event::WindowEnded)?;
                Ok((Some(out), Some(Webhook::OrderPaid)))
            }
            (Step::InReturnWindow, Input::ReturnNotice(fact)) => {
                // the return parcel is the seller's own label; the carrier must have taken it after delivery
                let label = self.return_label.as_ref().ok_or(OrderError::NotThisParcel)?;
                let since = self.delivered_at_s.ok_or(OrderError::NotThisParcel)?;
                if !fact.settles(&label.tracking, since) || fact.status != Status::Delivered {
                    return Err(OrderError::NotThisParcel);
                }
                let out = self.settle(Event::ReturnProven)?;
                Ok((Some(out), Some(Webhook::ReturnRefunded)))
            }
            (Step::InReturnWindow, Input::ReturnBought) => {
                let out = self.settle(Event::ReturnBought)?;
                Ok((Some(out), Some(Webhook::ReturnRefunded)))
            }
            _ => Err(OrderError::NotNow),
        }
    }

    fn after_delivery(&self) -> Webhook {
        if self.step == Step::Closed { Webhook::OrderPaid } else { Webhook::OrderDelivered }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offer::{Item, ReturnPolicy, Route, DAY_MS, OFFER_VERSION};

    const OUT: &str = "1Z999AA10123456784";
    const BACK: &str = "1Z999AA10999999993";
    const PIN_AT: u64 = 1_800_000_000;

    fn offer(returns: ReturnPolicy) -> Offer {
        Offer {
            version: OFFER_VERSION,
            offer_id: [7; 32],
            merchant_name: "Blue Finch Coffee".into(),
            merchant_key: vec![0; fips204::ml_dsa_65::PK_LEN],
            pay_address: vec![1; 96],
            asset: 0,
            items: vec![Item { name: "Burr grinder".into(), quantity: 1, amount: 12_000_000_000 }],
            total: 12_720_000_000,
            delivery: Delivery::Shipped {
                ship_by_ms: 2 * DAY_MS,
                deliver_by_ms: 11 * DAY_MS,
                route: Route::BuyerLabel,
                returns,
                deposit_bps: 200,
                bond_bps: 500,
                shipping: 720_000_000,
            },
            created_ms: 1,
            expires_ms: DAY_MS,
            channel: b"merchant-channel".to_vec(),
        }
    }

    const PROOF: ReturnPolicy = ReturnPolicy::ReturnProof { window_ms: 14 * DAY_MS, gate_bps: 300 };

    fn fact(status: Status, tracking: &str, at: u64) -> Fact {
        Fact { carrier: "Parcels Example".into(), status, tracking: tracking.into(), signed_at_s: at }
    }

    fn shipped(returns: ReturnPolicy) -> Order {
        let mut o = Order::open(&offer(returns), Some(ReturnLabel { tracking: BACK.into() })).unwrap();
        assert_eq!(o.apply(Input::Pin { tracking: OUT.into(), at_s: PIN_AT }).unwrap().1, Some(Webhook::OrderPinned));
        assert_eq!(o.apply(Input::Ship).unwrap().1, Some(Webhook::OrderShipped));
        o
    }

    #[test]
    fn nothing_ships_before_the_buyer_has_pinned_one_parcel() {
        let mut o = Order::open(&offer(PROOF), None).unwrap();
        assert_eq!(o.apply(Input::Ship), Err(OrderError::NotNow));
        assert_eq!(o.apply(Input::Notice(fact(Status::Delivered, OUT, PIN_AT + 1))), Err(OrderError::NotNow));
        assert_eq!(o.apply(Input::Pin { tracking: "not a number".into(), at_s: PIN_AT }), Err(OrderError::Tracking));
        assert!(o.apply(Input::Pin { tracking: OUT.into(), at_s: PIN_AT }).is_ok());
        assert_eq!(o.apply(Input::Pin { tracking: BACK.into(), at_s: PIN_AT }), Err(OrderError::NotNow), "one pin per order");
    }

    #[test]
    fn the_carriers_notice_pays_the_seller_when_the_buyer_stays_silent() {
        let mut o = shipped(ReturnPolicy::Final);
        let (paid, hook) = o.apply(Input::Notice(fact(Status::Delivered, OUT, PIN_AT + 500))).unwrap();
        let paid = paid.unwrap();
        assert_eq!(paid.to_buyer, 0, "the buyer who made the seller prove it loses the deposit");
        assert_eq!(paid.to_seller, o.purchase.locked.total());
        assert_eq!((hook, o.step), (Some(Webhook::OrderPaid), Step::Closed));
    }

    #[test]
    fn a_notice_for_another_parcel_or_from_before_the_pin_moves_nothing() {
        let mut o = shipped(PROOF);
        let before = o.clone();
        for wrong in [
            fact(Status::Delivered, "1Z999AA10123456785", PIN_AT + 500),
            fact(Status::Delivered, OUT, PIN_AT),
            fact(Status::Delivered, OUT, PIN_AT - 10_000_000),
            fact(Status::Delivered, BACK, PIN_AT + 500),
        ] {
            assert_eq!(o.apply(Input::Notice(wrong)), Err(OrderError::NotThisParcel));
            assert_eq!(o, before);
        }
    }

    #[test]
    fn a_confirmed_delivery_returns_the_deposit_and_opens_the_window() {
        let mut o = shipped(PROOF);
        let (paid, hook) = o.apply(Input::Confirm).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 600_000_000, to_buyer: 240_000_000 });
        assert_eq!((hook, o.step), (Some(Webhook::OrderDelivered), Step::InReturnWindow));
        let (paid, hook) = o.apply(Input::WindowEnd).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 12_720_000_000, to_buyer: 0 });
        assert_eq!((hook, o.step), (Some(Webhook::OrderPaid), Step::Closed));
    }

    #[test]
    fn a_parcel_that_comes_back_or_is_lost_ends_the_order_by_the_users_rule() {
        let mut back = shipped(PROOF);
        let (paid, hook) = back.apply(Input::Notice(fact(Status::ReturnedToSender, OUT, PIN_AT + 900))).unwrap();
        assert_eq!(paid.unwrap().to_seller, 600_000_000 + 2 * 720_000_000, "the seller's bond and its postage both ways");
        assert_eq!((hook, back.step), (Some(Webhook::OrderRefunded), Step::Closed));
        let mut lost = shipped(PROOF);
        let (paid, _) = lost.apply(Input::Notice(fact(Status::Lost, OUT, PIN_AT + 900))).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 600_000_000, to_buyer: 12_720_000_000 + 240_000_000 });
    }

    #[test]
    fn a_seller_may_cancel_only_before_it_ships() {
        let mut early = Order::open(&offer(PROOF), None).unwrap();
        early.apply(Input::Pin { tracking: OUT.into(), at_s: PIN_AT }).unwrap();
        let (paid, hook) = early.apply(Input::Cancel).unwrap();
        assert_eq!(paid.unwrap().to_seller, 600_000_000, "its bond comes back");
        assert_eq!(hook, Some(Webhook::OrderCancelled));
        let mut late = shipped(PROOF);
        assert_eq!(late.apply(Input::Cancel), Err(OrderError::NotNow));
    }

    #[test]
    fn no_proof_and_no_confirmation_by_the_deadline_refunds_the_buyer_with_the_bond() {
        let mut o = shipped(PROOF);
        let (paid, hook) = o.apply(Input::Deadline).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 0, to_buyer: o.purchase.locked.total() });
        assert_eq!(hook, Some(Webhook::OrderRefunded));
        assert_eq!(o.apply(Input::Notice(fact(Status::Delivered, OUT, PIN_AT + 500))), Err(OrderError::NotNow));
    }

    #[test]
    fn a_return_is_refunded_only_on_the_sellers_own_label_taken_after_delivery() {
        let mut o = shipped(PROOF);
        o.apply(Input::Notice(fact(Status::Delivered, OUT, PIN_AT + 500))).unwrap();
        assert_eq!(o.step, Step::InReturnWindow);
        let before = o.clone();
        for wrong in [
            fact(Status::Delivered, OUT, PIN_AT + 900),         // the outbound parcel is not a return
            fact(Status::Delivered, BACK, PIN_AT + 500),        // signed at the delivery, not after it
            fact(Status::Delivered, BACK, PIN_AT + 100),        // an old notice for a reused number
            fact(Status::ReturnedToSender, BACK, PIN_AT + 900), // the return did not arrive
        ] {
            assert_eq!(o.apply(Input::ReturnNotice(wrong)), Err(OrderError::NotThisParcel));
            assert_eq!(o, before);
        }
        let (paid, hook) = o.apply(Input::ReturnNotice(fact(Status::Delivered, BACK, PIN_AT + 900))).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 0, to_buyer: 12_720_000_000 });
        assert_eq!((hook, o.step), (Some(Webhook::ReturnRefunded), Step::Closed));
    }

    #[test]
    fn a_return_proof_is_refused_where_the_merchant_sells_final_or_by_counter() {
        let mut counter = shipped(ReturnPolicy::Counter { window_ms: DAY_MS });
        counter.apply(Input::Confirm).unwrap();
        let before = counter.clone();
        let refused = counter.apply(Input::ReturnNotice(fact(Status::Delivered, BACK, PIN_AT + 900)));
        assert_eq!(refused, Err(OrderError::Rule(RuleError::NotOffered)));
        assert_eq!(counter, before);
        let (paid, _) = counter.apply(Input::ReturnBought).unwrap();
        assert_eq!(paid.unwrap(), Payout { to_seller: 720_000_000, to_buyer: 12_000_000_000 });
    }

    #[test]
    fn every_order_pays_out_exactly_what_was_locked() {
        let inputs = || {
            vec![
                Input::Pin { tracking: OUT.into(), at_s: PIN_AT },
                Input::Ship,
                Input::Confirm,
                Input::Notice(fact(Status::Delivered, OUT, PIN_AT + 500)),
                Input::Notice(fact(Status::ReturnedToSender, OUT, PIN_AT + 500)),
                Input::Notice(fact(Status::Lost, OUT, PIN_AT + 500)),
                Input::Deadline,
                Input::Cancel,
                Input::WindowEnd,
                Input::ReturnNotice(fact(Status::Delivered, BACK, PIN_AT + 900)),
                Input::ReturnBought,
            ]
        };
        let n = inputs().len();
        let mut closed = 0;
        for policy in [ReturnPolicy::Final, PROOF, ReturnPolicy::Counter { window_ms: DAY_MS }] {
            // every sequence of four inputs
            for code in 0..n.pow(4) {
                let mut o = Order::open(&offer(policy), Some(ReturnLabel { tracking: BACK.into() })).unwrap();
                let total = o.purchase.locked.total();
                let mut paid = 0u64;
                let mut c = code;
                for _ in 0..4 {
                    if let Ok((Some(out), _)) = o.apply(inputs()[c % n].clone()) {
                        paid += out.to_seller + out.to_buyer;
                    }
                    c /= n;
                }
                assert_eq!(paid + o.purchase.held, total);
                if o.step == Step::Closed {
                    assert_eq!(paid, total);
                    closed += 1;
                }
            }
        }
        assert!(closed > 1000);
    }

    #[test]
    fn an_offer_that_is_not_a_shipped_sale_opens_no_order() {
        let mut pos = offer(PROOF);
        pos.delivery = Delivery::PaidNow;
        assert_eq!(Order::open(&pos, None), Err(OrderError::NotShipped));
        let bad_label = Order::open(&offer(PROOF), Some(ReturnLabel { tracking: "x".into() }));
        assert_eq!(bad_label, Err(OrderError::Tracking));
    }
}

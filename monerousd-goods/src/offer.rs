// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The offer: one merchant-signed description of a sale (spec section 27).
//!
//! One object serves the point-of-sale charge, every protected purchase and the subscription of
//! `PRIVATE-SUBSCRIPTIONS-SPEC-20261109.md` (lane dcash agreed on the bus, 2026-11-09). It has ONE
//! encoding: a decode that leaves a byte over, or that would re-encode differently, is refused.
//! It is signed with ML-DSA-65 under its own context string, so the signature is good for nothing else.
//!
//! cons: none. This module writes nothing to disk, holds no state and sends nothing. A signed offer is at
//! most `MAX_ENCODED_BYTES` = 16 KiB, a fixed constant (ML-DSA-65 key 1,952 B + signature 3,309 B + the
//! sale's lines), held only by the two wallets of that sale and never by a node or the chain.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};

pub const OFFER_VERSION: u8 = 1;
/// FIPS 204 context string. An offer signature cannot be replayed as any other MonerousD signature.
pub const SIGN_CONTEXT: &[u8] = b"monerousd/offer/v1";
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_ITEM_NAME_CHARS: usize = 128;
pub const MAX_ITEMS: usize = 64;
pub const MAX_ADDRESS_BYTES: usize = 4096;
/// The largest encoded signed offer a wallet will read.
pub const MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const DAY_MS: u64 = 86_400_000;
const BPS: u16 = 10_000;

/// One line of the sale. `amount` is the line's total in atomic units.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    pub quantity: u32,
    pub amount: u64,
}

/// What a shipped order does about returns (spec section 17.1). The merchant picks; the buyer sees it.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnPolicy {
    /// The sale is complete at delivery.
    Final,
    /// A wrong-or-faulty claim is refunded on the carrier's signed notice of the return, up to `gate_bps`
    /// of what this buyer has already paid this merchant. A change of mind goes to a counter.
    ReturnProof { window_ms: u64, gate_bps: u16 },
    /// A returns buyer checks the opened item at a counter and buys it.
    Counter { window_ms: u64 },
    /// The goods ship in a clear tamper-evident pack. Breaking the seal is acceptance.
    SealedPackCounter { window_ms: u64 },
}

/// How the parcel is bound to the buyer's door before it moves (spec section 16.3).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The carrier's signed ship notice states the delivery address.
    CarrierShipNotice,
    /// The buyer's wallet buys the label.
    BuyerLabel,
    /// The parcel goes to a relay and is handed over there.
    Relay,
}

/// How the thing sold reaches the buyer. This is what the wallet reads to pick the protection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Paid on the spot: today's point-of-sale charge.
    PaidNow,
    /// Handed over in person against the buyer's code.
    InPerson { hand_over_by_ms: u64, grace_ms: u64 },
    /// Shipped by a carrier. `shipping` is the postage one way, in atomic units, and is part of `total`.
    Shipped {
        ship_by_ms: u64,
        deliver_by_ms: u64,
        route: Route,
        returns: ReturnPolicy,
        deposit_bps: u16,
        bond_bps: u16,
        shipping: u64,
    },
    /// A file, licence, ticket or code, released by the seller's content key.
    Download { content_root: [u8; 32], cipher_root: [u8; 32], deliver_by_ms: u64 },
    /// A service paid tick by tick. Either side stops whenever it likes.
    Ticks { tick_amount: u64, period_ms: u64, max_ticks: u32, pay_first: bool },
    /// The subscription of PRIVATE-SUBSCRIPTIONS-SPEC Phase A, field for field.
    Subscription {
        sub_id: [u8; 32],
        amount_per_period: u64,
        period_ms: u64,
        first_charge_ms: u64,
        /// 0 means "until `end_ms`".
        max_periods: u32,
        /// 0 means "until `max_periods`".
        end_ms: u64,
        grace_ms: u64,
        misses_before_cancel: u8,
    },
}

/// The offer. Amounts are atomic units of `asset` (0 is USDm).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub version: u8,
    /// 32 random bytes drawn by the merchant for this one sale.
    pub offer_id: [u8; 32],
    pub merchant_name: String,
    /// The merchant's ML-DSA-65 public key.
    pub merchant_key: Vec<u8>,
    pub pay_address: Vec<u8>,
    pub asset: u32,
    pub items: Vec<Item>,
    pub total: u64,
    pub delivery: Delivery,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// The merchant's private channel back (its onion or letter address): tracking, notices, cancel.
    pub channel: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedOffer {
    pub offer: Offer,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferError {
    Version,
    Name,
    Key,
    Address,
    Items,
    /// `total` is not what the items (and the postage) add up to, or the sum overflows.
    Total,
    Dates,
    Expired,
    Terms,
    Encoding,
    Signature,
    Link,
}

impl std::fmt::Display for OfferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OfferError::Version => "this offer is a version this wallet does not read",
            OfferError::Name => "the merchant or item name is empty, too long or holds control characters",
            OfferError::Key => "the merchant key is not an ML-DSA-65 public key",
            OfferError::Address => "the pay address or the channel is empty or too long",
            OfferError::Items => "the offer lists no items, too many, or an item with quantity zero",
            OfferError::Total => "the total is not what the lines add up to",
            OfferError::Dates => "the offer's dates are out of order",
            OfferError::Expired => "the offer has expired",
            OfferError::Terms => "the delivery terms are not valid",
            OfferError::Encoding => "the bytes are not one canonical offer",
            OfferError::Signature => "the merchant's signature does not verify",
            OfferError::Link => "the link is not a MonerousD offer link",
        })
    }
}

impl std::error::Error for OfferError {}

fn plain_text(s: &str, max_chars: usize) -> bool {
    let n = s.chars().count();
    n >= 1 && n <= max_chars && !s.chars().any(char::is_control) && s.trim() == s
}

impl Offer {
    /// The sum of the lines, or `None` on overflow.
    pub fn lines_total(&self) -> Option<u64> {
        self.items.iter().try_fold(0u64, |acc, i| acc.checked_add(i.amount))
    }

    /// Everything a wallet checks before it shows the offer, apart from the signature.
    pub fn check(&self, now_ms: u64) -> Result<(), OfferError> {
        if self.version != OFFER_VERSION {
            return Err(OfferError::Version);
        }
        if !plain_text(&self.merchant_name, MAX_NAME_CHARS) {
            return Err(OfferError::Name);
        }
        if self.merchant_key.len() != ml_dsa_65::PK_LEN {
            return Err(OfferError::Key);
        }
        if self.pay_address.is_empty() || self.pay_address.len() > MAX_ADDRESS_BYTES {
            return Err(OfferError::Address);
        }
        if self.channel.is_empty() || self.channel.len() > MAX_ADDRESS_BYTES {
            return Err(OfferError::Address);
        }
        if self.items.len() > MAX_ITEMS {
            return Err(OfferError::Items);
        }
        for item in &self.items {
            if item.quantity == 0 {
                return Err(OfferError::Items);
            }
            if !plain_text(&item.name, MAX_ITEM_NAME_CHARS) {
                return Err(OfferError::Name);
            }
        }
        if self.created_ms >= self.expires_ms {
            return Err(OfferError::Dates);
        }
        if now_ms >= self.expires_ms {
            return Err(OfferError::Expired);
        }
        let lines = self.lines_total().ok_or(OfferError::Total)?;
        let goods_listed = || if self.items.is_empty() { Err(OfferError::Items) } else { Ok(()) };
        match &self.delivery {
            Delivery::PaidNow => {
                goods_listed()?;
                if self.total != lines {
                    return Err(OfferError::Total);
                }
            }
            Delivery::InPerson { hand_over_by_ms, grace_ms } => {
                goods_listed()?;
                if self.total != lines {
                    return Err(OfferError::Total);
                }
                if *hand_over_by_ms <= self.created_ms || *grace_ms == 0 {
                    return Err(OfferError::Dates);
                }
            }
            Delivery::Shipped { ship_by_ms, deliver_by_ms, returns, deposit_bps, bond_bps, shipping, .. } => {
                goods_listed()?;
                if lines == 0 || lines.checked_add(*shipping) != Some(self.total) {
                    return Err(OfferError::Total);
                }
                if !(self.created_ms < *ship_by_ms && ship_by_ms < deliver_by_ms) {
                    return Err(OfferError::Dates);
                }
                if *deposit_bps > BPS || *bond_bps > BPS {
                    return Err(OfferError::Terms);
                }
                match returns {
                    ReturnPolicy::Final => {}
                    ReturnPolicy::ReturnProof { window_ms, gate_bps } => {
                        if *window_ms == 0 || *gate_bps > BPS {
                            return Err(OfferError::Terms);
                        }
                    }
                    ReturnPolicy::Counter { window_ms } | ReturnPolicy::SealedPackCounter { window_ms } => {
                        if *window_ms == 0 {
                            return Err(OfferError::Terms);
                        }
                    }
                }
            }
            Delivery::Download { deliver_by_ms, .. } => {
                goods_listed()?;
                if self.total != lines {
                    return Err(OfferError::Total);
                }
                if *deliver_by_ms <= self.created_ms {
                    return Err(OfferError::Dates);
                }
            }
            Delivery::Ticks { tick_amount, period_ms, max_ticks, .. } => {
                if *tick_amount == 0 || *period_ms == 0 || *max_ticks == 0 {
                    return Err(OfferError::Terms);
                }
                if tick_amount.checked_mul(u64::from(*max_ticks)) != Some(self.total) {
                    return Err(OfferError::Total);
                }
            }
            Delivery::Subscription {
                amount_per_period, period_ms, first_charge_ms, max_periods, end_ms, misses_before_cancel, ..
            } => {
                if *amount_per_period == 0 || *period_ms < DAY_MS || *misses_before_cancel == 0 {
                    return Err(OfferError::Terms);
                }
                if self.total != *amount_per_period {
                    return Err(OfferError::Total);
                }
                if *first_charge_ms < self.created_ms {
                    return Err(OfferError::Dates);
                }
                if *max_periods == 0 && *end_ms <= *first_charge_ms {
                    return Err(OfferError::Terms);
                }
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, OfferError> {
        postcard::to_stdvec(self).map_err(|_| OfferError::Encoding)
    }

    /// Sign the offer. The result is verified before it is returned, so a secret key that does not belong
    /// to `merchant_key` can never produce a signed offer.
    pub fn sign(self, secret_key: &[u8], now_ms: u64) -> Result<SignedOffer, OfferError> {
        self.check(now_ms)?;
        let sk_bytes: [u8; ml_dsa_65::SK_LEN] = secret_key.try_into().map_err(|_| OfferError::Key)?;
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).map_err(|_| OfferError::Key)?;
        let signature = sk.try_sign(&self.encode()?, SIGN_CONTEXT).map_err(|_| OfferError::Signature)?;
        let signed = SignedOffer { offer: self, signature: signature.to_vec() };
        signed.verify(now_ms)?;
        Ok(signed)
    }
}

impl SignedOffer {
    /// The checks of [`Offer::check`], then the merchant's signature.
    pub fn verify(&self, now_ms: u64) -> Result<&Offer, OfferError> {
        self.offer.check(now_ms)?;
        let pk_bytes: [u8; ml_dsa_65::PK_LEN] =
            self.offer.merchant_key.as_slice().try_into().map_err(|_| OfferError::Key)?;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|_| OfferError::Key)?;
        let sig: [u8; ml_dsa_65::SIG_LEN] =
            self.signature.as_slice().try_into().map_err(|_| OfferError::Signature)?;
        if pk.verify(&self.offer.encode()?, &sig, SIGN_CONTEXT) {
            Ok(&self.offer)
        } else {
            Err(OfferError::Signature)
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, OfferError> {
        postcard::to_stdvec(self).map_err(|_| OfferError::Encoding)
    }

    /// Decode the one canonical encoding. A trailing byte, or bytes that would re-encode differently, are refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OfferError> {
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err(OfferError::Encoding);
        }
        let (signed, rest): (SignedOffer, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| OfferError::Encoding)?;
        if !rest.is_empty() || signed.to_bytes()?.as_slice() != bytes {
            return Err(OfferError::Encoding);
        }
        Ok(signed)
    }

    /// The hash a link names. It covers the signature, so a link names exactly one signed offer.
    pub fn hash(&self) -> Result<[u8; 32], OfferError> {
        Ok(*blake3::hash(&self.to_bytes()?).as_bytes())
    }

    /// The short link for a button or a QR code. The wallet fetches the signed offer over `fetch` (the
    /// merchant's private channel) and takes it only if it answers the link.
    pub fn link(&self) -> Result<OfferLink, OfferError> {
        Ok(OfferLink { offer_id: self.offer.offer_id, hash: self.hash()?, fetch: self.offer.channel.clone() })
    }

    pub fn answers(&self, link: &OfferLink) -> bool {
        self.offer.offer_id == link.offer_id && self.hash().map(|h| h == link.hash).unwrap_or(false)
    }
}

/// `monerousd:offer?id=<64 hex>&h=<64 hex>&at=<base64url>`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferLink {
    pub offer_id: [u8; 32],
    pub hash: [u8; 32],
    pub fetch: Vec<u8>,
}

const LINK_PREFIX: &str = "monerousd:offer?";

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl OfferLink {
    pub fn to_text(&self) -> String {
        use base64::Engine;
        let at = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.fetch);
        format!("{LINK_PREFIX}id={}&h={}&at={}", hex32(&self.offer_id), hex32(&self.hash), at)
    }

    /// Exactly the three fields, in order, once each. Anything else is not an offer link.
    pub fn parse(text: &str) -> Result<Self, OfferError> {
        use base64::Engine;
        let rest = text.strip_prefix(LINK_PREFIX).ok_or(OfferError::Link)?;
        let mut parts = rest.split('&');
        let id = parts.next().and_then(|p| p.strip_prefix("id=")).and_then(unhex32).ok_or(OfferError::Link)?;
        let hash = parts.next().and_then(|p| p.strip_prefix("h=")).and_then(unhex32).ok_or(OfferError::Link)?;
        let at = parts.next().and_then(|p| p.strip_prefix("at=")).ok_or(OfferError::Link)?;
        if parts.next().is_some() {
            return Err(OfferError::Link);
        }
        let fetch = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(at).map_err(|_| OfferError::Link)?;
        if fetch.is_empty() || fetch.len() > MAX_ADDRESS_BYTES {
            return Err(OfferError::Link);
        }
        let link = OfferLink { offer_id: id, hash, fetch };
        // one spelling per link: a link that would print differently is refused
        if link.to_text() != text {
            return Err(OfferError::Link);
        }
        Ok(link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::KeyGen;

    const NOW: u64 = 1_800_000_000_000;

    fn merchant(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
    }

    fn shipped(pk: &[u8]) -> Offer {
        Offer {
            version: OFFER_VERSION,
            offer_id: [7; 32],
            merchant_name: "Blue Finch Coffee".into(),
            merchant_key: pk.to_vec(),
            pay_address: vec![1; 96],
            asset: 0,
            items: vec![Item { name: "Burr grinder".into(), quantity: 1, amount: 12_000_000_000 }],
            total: 12_720_000_000,
            delivery: Delivery::Shipped {
                ship_by_ms: NOW + 2 * DAY_MS,
                deliver_by_ms: NOW + 11 * DAY_MS,
                route: Route::BuyerLabel,
                returns: ReturnPolicy::ReturnProof { window_ms: 14 * DAY_MS, gate_bps: 300 },
                deposit_bps: 200,
                bond_bps: 500,
                shipping: 720_000_000,
            },
            created_ms: NOW - 1000,
            expires_ms: NOW + DAY_MS,
            channel: b"merchant-channel".to_vec(),
        }
    }

    #[test]
    fn a_signed_offer_survives_its_one_encoding_and_verifies() {
        let (pk, sk) = merchant(1);
        let signed = shipped(&pk).sign(&sk, NOW).unwrap();
        let bytes = signed.to_bytes().unwrap();
        let back = SignedOffer::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.verify(NOW).unwrap().merchant_name, "Blue Finch Coffee");
    }

    #[test]
    fn any_changed_field_voids_the_signature() {
        let (pk, sk) = merchant(1);
        let signed = shipped(&pk).sign(&sk, NOW).unwrap();
        let mut price = signed.clone();
        price.offer.items[0].amount -= 1;
        price.offer.total -= 1;
        assert_eq!(price.verify(NOW), Err(OfferError::Signature));
        let mut payee = signed.clone();
        payee.offer.pay_address[0] ^= 1;
        assert_eq!(payee.verify(NOW), Err(OfferError::Signature));
        let mut terms = signed.clone();
        if let Delivery::Shipped { bond_bps, .. } = &mut terms.offer.delivery {
            *bond_bps = 0;
        }
        assert_eq!(terms.verify(NOW), Err(OfferError::Signature));
        let mut sig = signed;
        sig.signature[10] ^= 1;
        assert_eq!(sig.verify(NOW), Err(OfferError::Signature));
    }

    #[test]
    fn another_merchants_key_cannot_sign_or_be_swapped_in() {
        let (pk, sk) = merchant(1);
        let (other_pk, other_sk) = merchant(2);
        assert_eq!(shipped(&pk).sign(&other_sk, NOW), Err(OfferError::Signature));
        let mut swapped = shipped(&pk).sign(&sk, NOW).unwrap();
        swapped.offer.merchant_key = other_pk;
        assert_eq!(swapped.verify(NOW), Err(OfferError::Signature));
    }

    #[test]
    fn a_total_that_is_not_the_lines_plus_postage_is_refused() {
        let (pk, _) = merchant(1);
        let mut o = shipped(&pk);
        o.total += 1;
        assert_eq!(o.check(NOW), Err(OfferError::Total));
        let mut overflow = shipped(&pk);
        overflow.items.push(Item { name: "x".into(), quantity: 1, amount: u64::MAX });
        assert_eq!(overflow.check(NOW), Err(OfferError::Total));
    }

    #[test]
    fn an_expired_or_misdated_offer_is_refused() {
        let (pk, _) = merchant(1);
        let o = shipped(&pk);
        assert_eq!(o.check(o.expires_ms), Err(OfferError::Expired));
        let mut late_ship = shipped(&pk);
        if let Delivery::Shipped { ship_by_ms, deliver_by_ms, .. } = &mut late_ship.delivery {
            *ship_by_ms = *deliver_by_ms;
        }
        assert_eq!(late_ship.check(NOW), Err(OfferError::Dates));
    }

    #[test]
    fn a_name_with_a_control_character_or_padding_is_refused() {
        let (pk, _) = merchant(1);
        for bad in ["", " Blue Finch", "Blue\u{0007}Finch", "Blue Finch\n"] {
            let mut o = shipped(&pk);
            o.merchant_name = bad.into();
            assert_eq!(o.check(NOW), Err(OfferError::Name), "{bad:?}");
        }
    }

    #[test]
    fn a_trailing_byte_or_a_second_spelling_is_not_an_offer() {
        let (pk, sk) = merchant(1);
        let bytes = shipped(&pk).sign(&sk, NOW).unwrap().to_bytes().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(SignedOffer::from_bytes(&trailing), Err(OfferError::Encoding));
        // postcard writes the version byte as one byte; the same value padded to two bytes must be refused
        let mut padded = bytes.clone();
        assert_eq!(padded[0], OFFER_VERSION);
        padded[0] |= 0x80;
        padded.insert(1, 0x00);
        assert_eq!(SignedOffer::from_bytes(&padded), Err(OfferError::Encoding));
        assert_eq!(SignedOffer::from_bytes(&bytes[..bytes.len() - 1]), Err(OfferError::Encoding));
    }

    #[test]
    fn a_link_names_exactly_one_signed_offer() {
        let (pk, sk) = merchant(1);
        let signed = shipped(&pk).sign(&sk, NOW).unwrap();
        let link = signed.link().unwrap();
        let text = link.to_text();
        assert!(text.starts_with("monerousd:offer?id=0707"));
        assert_eq!(OfferLink::parse(&text).unwrap(), link);
        assert!(signed.answers(&link));
        let mut other = shipped(&pk);
        other.offer_id = [8; 32];
        assert!(!other.sign(&sk, NOW).unwrap().answers(&link));
        let mut same_id_other_price = shipped(&pk);
        same_id_other_price.items[0].amount += 1;
        same_id_other_price.total += 1;
        assert!(!same_id_other_price.sign(&sk, NOW).unwrap().answers(&link));
    }

    #[test]
    fn a_link_with_an_extra_field_or_another_spelling_is_refused() {
        let (pk, sk) = merchant(1);
        let text = shipped(&pk).sign(&sk, NOW).unwrap().link().unwrap().to_text();
        assert_eq!(OfferLink::parse(&format!("{text}&x=1")), Err(OfferError::Link));
        assert_eq!(OfferLink::parse(&text.to_uppercase()), Err(OfferError::Link));
        assert_eq!(OfferLink::parse(&text.replace("monerousd:", "monerousd://")), Err(OfferError::Link));
        assert_eq!(OfferLink::parse(&format!("{text}=")), Err(OfferError::Link));
    }

    #[test]
    fn the_subscription_carries_phase_a_field_for_field() {
        let (pk, sk) = merchant(3);
        let mut o = shipped(&pk);
        o.items.clear();
        o.total = 999_000_000;
        o.delivery = Delivery::Subscription {
            sub_id: [9; 32],
            amount_per_period: 999_000_000,
            period_ms: 30 * DAY_MS,
            first_charge_ms: NOW,
            max_periods: 0,
            end_ms: NOW + 365 * DAY_MS,
            grace_ms: 3 * DAY_MS,
            misses_before_cancel: 3,
        };
        let signed = o.clone().sign(&sk, NOW).unwrap();
        assert_eq!(SignedOffer::from_bytes(&signed.to_bytes().unwrap()).unwrap().offer, o);
        let mut short = o.clone();
        if let Delivery::Subscription { period_ms, .. } = &mut short.delivery {
            *period_ms = DAY_MS - 1;
        }
        assert_eq!(short.check(NOW), Err(OfferError::Terms));
        let mut endless = o;
        if let Delivery::Subscription { end_ms, .. } = &mut endless.delivery {
            *end_ms = 0;
        }
        assert_eq!(endless.check(NOW), Err(OfferError::Terms));
    }

    #[test]
    fn a_point_of_sale_charge_and_a_tick_service_are_the_same_object() {
        let (pk, sk) = merchant(4);
        let mut pos = shipped(&pk);
        pos.delivery = Delivery::PaidNow;
        pos.total = 12_000_000_000;
        assert!(pos.sign(&sk, NOW).is_ok());
        let mut ticks = shipped(&pk);
        ticks.items.clear();
        ticks.delivery = Delivery::Ticks { tick_amount: 2_500_000_000, period_ms: 3_600_000, max_ticks: 8, pay_first: true };
        ticks.total = 20_000_000_000;
        assert!(ticks.clone().sign(&sk, NOW).is_ok());
        ticks.total += 1;
        assert_eq!(ticks.check(NOW), Err(OfferError::Total));
    }
}

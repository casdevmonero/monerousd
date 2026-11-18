// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-240 — THE PRICE-QUOTE LANE: how a bonded validator's own observation becomes a chain `PriceMark`.
//!
//! **The failure this closes (measured 2026-09-26).** DB-124's rule is live: `Node::attest_peg_in` refuses
//! any mint not covered by a ≥2/3-attested `PriceMark`. But no production code ever built a quote or
//! published a mark — every `PriceQuote` construction was in a test. So on a production chain no mark can
//! exist, every peg-in attestation is refused, and nothing issues through the peg.
//!
//! **The chain half already existed and is reused, never re-encoded:**
//! - the message, [`crate::peg::PegLedger::price_mark_msg`];
//! - the ≥2/3 bonded tally, `crate::peg::tally_attestors` — the ONE tally `mark_price_attested` runs;
//! - the bond-weighted median and the monotone epoch rule, `mark_price_attested`;
//! - the framed object and its wrapper, [`crate::price_mark_tx::as_pq_tx`], applied at graft on every node
//!   (DB-224's carried set).
//!
//! **This module adds only the reporter and the gatherer (the medianizer shape of MakerDAO's Median /
//! Chainlink OCR):**
//! - [`sign_quote`] — a bonded validator signs its OWN observation for (epoch, asset);
//! - [`SignedQuote`] — the one wire form the attestation lane gossips, decoded strictly (`decode_exact`,
//!   the same size bounds a mark's quotes carry);
//! - [`QuoteBook`] — at most one quote per bonded key, for the current epoch only;
//! - [`QuoteBook::quorum_quotes`] — the quotes a publisher may put in a mark, returned only when the SAME
//!   tally the door runs says ≥2/3 of bonded weight has quoted.
//!
//! **The price source is each validator's own sample of the onion price relays, never a person's hand and never the
//! binary's** (§21, `crate::price_relay`): no operator types a price, and no feed is baked in. A validator whose relays do not
//! agree (≥ 3 within 2 %, both networks) quotes nothing, so mints fail closed, the chain keeps producing, and redemptions are
//! untouched (`priced_value` never checks a mark's age).

use crate::peg::PegLedger;
use crate::pqauth::PqVerifier;
use crate::price_mark_tx::PriceQuote;
use crate::psm::BondQuorum;
use std::collections::BTreeMap;

/// How long one price epoch lasts: the oracle HEARTBEAT, ten minutes of the CHAIN'S CLOCK (median-time-past, BIP113,
/// `Node::chain_time_ms`). That is the Median / OSM cadence class (minutes, not seconds), which bounds the lane's cost:
/// - cons: one quote per validator per asset per epoch, about 5.3 KB each, on the gossip lane;
/// - cons: one mark per asset per epoch, about 5.3 KB × the quoting validators, on the block wire;
/// - cons: 0 B at rest.
/// ⛔ A TIME, NEVER A COUNT OF BLOCKS (finding A-F60's class, user 2026-11-15: "the chain needs to be honest and work at its real
/// pace"): this was 1,200 blocks, ten minutes only at a 500 ms block, and on real nodes it was hours.
pub const PRICE_EPOCH_MS: u64 = 600_000;

/// The price epoch at chain time `chain_ms` — a pure function of the chain (its median-time-past only rises along a selected
/// chain, so epochs never go back), identical on every node holding the same tip.
#[must_use]
pub fn price_epoch(chain_ms: u64) -> u64 {
    chain_ms / PRICE_EPOCH_MS
}

/// Domain tag of the quote's wire form, so a quote can never be read as any other lane's bytes.
const QUOTE_WIRE_TAG: &[u8; 16] = b"MUSD-price-q-v1\0";

/// One bonded validator's signed observation for (epoch, asset) — exactly what the attestation lane gossips.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedQuote {
    pub epoch_id: u64,
    pub asset_id: u32,
    pub quote: PriceQuote,
}

impl SignedQuote {
    /// The ONE wire encoding: the domain tag, then postcard of the struct. `None` when the body cannot be
    /// encoded — the caller sends nothing, rather than bytes that are not this quote.
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        let body = postcard::to_allocvec(self).ok()?;
        let mut out = QUOTE_WIRE_TAG.to_vec();
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Strict decode: the tag, an exact postcard body (a trailing tail is refused — one object, one
    /// encoding), and the same pubkey / signature bounds a mark's quotes are held to at its own decode.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<SignedQuote> {
        let body = bytes.strip_prefix(QUOTE_WIRE_TAG.as_slice())?;
        let q: SignedQuote = crate::chain_object::decode_exact(body)?;
        if q.quote.price < crate::price_mark_tx::MIN_QUOTE_PRICE
            || q.quote.pubkey.is_empty()
            || q.quote.pubkey.len() > crate::peg_attest::PEG_ATTEST_PUBKEY_MAX
            || q.quote.sig.is_empty()
            || q.quote.sig.len() > crate::peg_attest::PEG_ATTEST_SIG_MAX
        {
            return None;
        }
        Some(q)
    }
}

/// Sign this validator's OWN observation `price` for (epoch, asset) over the chain's own quote message.
#[must_use]
pub fn sign_quote(epoch_id: u64, asset_id: u32, price: u128, pk: &[u8], sk: &[u8]) -> Option<SignedQuote> {
    let sig = crate::pqauth::ml_dsa_sign(&PegLedger::price_mark_msg(epoch_id, asset_id, price), sk)?;
    Some(SignedQuote { epoch_id, asset_id, quote: PriceQuote { price, pubkey: pk.to_vec(), sig } })
}

/// The gatherer's book: at most one quote per bonded key per asset, for ONE epoch at a time.
///
/// BOUNDED BY CONSTRUCTION: it holds the bonded set × the registered assets for the current epoch. A quote
/// for any other epoch is not kept, and moving to a new epoch clears the book. Nothing here grows with
/// height, block count or history.
#[derive(Debug, Default)]
pub struct QuoteBook {
    epoch: u64,
    by_asset: BTreeMap<u32, BTreeMap<[u8; 32], PriceQuote>>,
    /// The publication this node has travelling per asset in this epoch, so a quote arriving after the quorum does not publish a second,
    /// different mark while the first is still in the pool. A publication that left the pool with no mark on the chain is published again.
    published: std::collections::BTreeMap<u32, crate::hash::Hash32>,
}

impl QuoteBook {
    /// The epoch this book is gathering.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The pool id of the mark this node published for `asset_id` in this epoch, if it did.
    #[must_use]
    pub fn published(&self, asset_id: u32) -> Option<crate::hash::Hash32> {
        self.published.get(&asset_id).copied()
    }

    /// Record that this node published a mark for `asset_id` in this epoch, as pool id `id`.
    pub fn mark_published(&mut self, asset_id: u32, id: crate::hash::Hash32) {
        self.published.insert(asset_id, id);
    }

    /// Is `(pubkey, msg, sig)` exactly a quote this book already VERIFIED? True only for byte-identical
    /// signature, key and message: the message is rebuilt from the stored `(epoch, asset, price)`, so a quote
    /// replayed under another price, asset or epoch is never a hit.
    #[must_use]
    pub fn holds(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let id = crate::pqauth::pubkey_id(pubkey);
        self.by_asset.iter().any(|(asset, slot)| {
            slot.get(&id).is_some_and(|q| {
                q.sig == sig && q.pubkey == pubkey && PegLedger::price_mark_msg(self.epoch, *asset, q.price) == msg
            })
        })
    }
}

/// ⭐ DB-245 — A QUOTE THIS NODE ALREADY VERIFIED IS NEVER VERIFIED AGAIN (the borrowed shape: Bitcoin Core's
/// signature cache).
///
/// A mark's quotes sign `(epoch, asset, price)`, never the mark, so anyone can copy the genuine quotes off the lane
/// into as many objects as they like. Since DB-245 a same-epoch mark is tallied rather than refused on its epoch
/// alone, so an object of copied genuine quotes plus one forgery placed last would cost every grafting node one
/// verify per quote. Through this verifier it costs one verify: the forgery. That is the same price a forged
/// attestation costs at every other attested door.
///
/// It changes no verdict. A hit is a triple this node's book verified at ingest; everything else goes to the
/// real verifier.
pub struct BookVerifier<'a> {
    /// The gathered, already-verified quotes of the current epoch.
    pub book: &'a QuoteBook,
    /// The real verifier, for everything the book does not hold.
    pub inner: &'a dyn PqVerifier,
}

impl PqVerifier for BookVerifier<'_> {
    fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        self.book.holds(pubkey, msg, sig) || self.inner.verify(pubkey, msg, sig)
    }
}

impl QuoteBook {

    /// Admit one signed quote. Returns `true` only when it is NEW, which is the re-gossip signal (the
    /// finality-vote shape: dedup on the signer).
    ///
    /// Refused, and nothing written, for any of:
    /// - a quote for another epoch;
    /// - a signer with no bonded weight;
    /// - a signature that does not verify over the chain's own quote message;
    /// - a second quote from a key that already quoted this asset this epoch — one validator, one voice,
    ///   and the first stands.
    pub fn ingest(
        &mut self,
        sq: &SignedQuote,
        current_epoch: u64,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> bool {
        if sq.epoch_id != current_epoch || sq.quote.price < crate::price_mark_tx::MIN_QUOTE_PRICE {
            return false;
        }
        if self.epoch != current_epoch {
            self.by_asset.clear();
            self.published.clear();
            self.epoch = current_epoch;
        }
        let id = crate::pqauth::pubkey_id(&sq.quote.pubkey);
        if quorum.bond_of(&id) == 0 {
            return false;
        }
        // One voice per key, checked BEFORE the verify: a re-sent quote (the same one, or a second one from a key
        // that already quoted) cannot change the book, so it must not cost a signature check. Without this, every
        // re-gossip of a genuine quote cost each hearer one ML-DSA verify.
        if self.by_asset.get(&sq.asset_id).is_some_and(|slot| slot.contains_key(&id)) {
            return false;
        }
        let msg = PegLedger::price_mark_msg(sq.epoch_id, sq.asset_id, sq.quote.price);
        if !verifier.verify(&sq.quote.pubkey, &msg, &sq.quote.sig) {
            return false;
        }
        self.by_asset.entry(sq.asset_id).or_default().insert(id, sq.quote.clone());
        true
    }

    /// The quotes a publisher may put in a `PriceMark` for `asset_id`: `Some` only when the SAME tally
    /// `mark_price_attested` runs at the door says ≥2/3 of bonded weight has quoted this epoch. Because it is
    /// the door's own tally, a mark this returns is a mark every node accepts.
    #[must_use]
    pub fn quorum_quotes(
        &self,
        asset_id: u32,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> Option<Vec<PriceQuote>> {
        let quotes: Vec<PriceQuote> = self.by_asset.get(&asset_id)?.values().cloned().collect();
        if quotes.is_empty() || quotes.len() > crate::price_mark_tx::MAX_PRICE_QUOTES {
            return None;
        }
        let attestors = crate::price_mark_tx::as_attestors(&quotes);
        let only: Vec<crate::psm::MintAttestor> = attestors.iter().map(|(_, a)| a.clone()).collect();
        let prices: Vec<u128> = attestors.iter().map(|(p, _)| *p).collect();
        let epoch = self.epoch;
        let tally = crate::peg::tally_attestors(quorum, verifier, &only, &|i| {
            PegLedger::price_mark_msg(epoch, asset_id, prices[i])
        })?;
        // DB-387: the publisher clears the SAME strict threshold the apply does — never publish a mark every node refuses
        crate::peg::mark_tally_clears(&tally, quorum.total_bond()).then_some(quotes)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A bonded set of `n` equal-weight validators, with their keys.
    fn bonded(n: usize) -> (crate::validator::ValidatorSet, Vec<(Vec<u8>, Vec<u8>)>) {
        let mut vs = crate::validator::ValidatorSet::new();
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        for (pk, _) in &keys {
            vs.admit(crate::pqauth::pubkey_id(pk), 10_000, 0).expect("a bond admits");
        }
        (vs, keys)
    }

    #[test]
    fn a_quote_round_trips_its_one_encoding_and_refuses_a_tail_and_a_foreign_tag() {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let q = sign_quote(3, 0, 15_000, &pk, &sk).expect("signs");
        let wire = q.wire().expect("encodes");
        assert_eq!(SignedQuote::decode(&wire), Some(q.clone()), "the one encoding round-trips");
        let mut tail = wire.clone();
        tail.push(0);
        assert_eq!(SignedQuote::decode(&tail), None, "⛔ a trailing tail is a second encoding of one quote");
        let mut foreign = wire;
        foreign[0] ^= 1;
        assert_eq!(SignedQuote::decode(&foreign), None, "⛔ another lane's bytes are not a quote");
    }

    #[test]
    fn only_a_bonded_signer_with_a_valid_signature_is_gathered_once_for_the_current_epoch() {
        let (vs, keys) = bonded(3);
        let v = crate::pqauth::MlDsaVerifier;
        let mut book = QuoteBook::default();
        let q0 = sign_quote(7, 0, 15_000, &keys[0].0, &keys[0].1).expect("signs");
        assert!(book.ingest(&q0, 7, &vs, &v), "a bonded, valid quote for this epoch is gathered");
        assert!(!book.ingest(&q0, 7, &vs, &v), "⛔ the same quote again is not new");
        let again = sign_quote(7, 0, 99_000, &keys[0].0, &keys[0].1).expect("signs");
        assert!(!book.ingest(&again, 7, &vs, &v), "⛔ one validator, one voice: a second price is refused");
        let (stranger_pk, stranger_sk) = crate::pqauth::ml_dsa_keypair();
        let unbonded = sign_quote(7, 0, 15_000, &stranger_pk, &stranger_sk).expect("signs");
        assert!(!book.ingest(&unbonded, 7, &vs, &v), "⛔ a key with no bond does not quote");
        let mut forged = sign_quote(7, 0, 15_000, &keys[1].0, &keys[1].1).expect("signs");
        forged.quote.price = 16_000; // the signature covered 15,000
        assert!(!book.ingest(&forged, 7, &vs, &v), "⛔ a quote whose price its signature does not cover is refused");
        let stale = sign_quote(6, 0, 15_000, &keys[2].0, &keys[2].1).expect("signs");
        assert!(!book.ingest(&stale, 7, &vs, &v), "⛔ a quote for another epoch is not gathered");
    }

    #[test]
    fn a_mark_is_publishable_only_at_two_thirds_of_bonded_weight_and_the_door_accepts_exactly_it() {
        // DB-387 (user ruling): "two thirds" is STRICTLY more than 2/3 for a mark — the book (publisher) and the door (apply)
        // read the one predicate `peg::mark_tally_clears`, so whatever the book returns the door accepts, and nothing else.
        let (vs, keys) = bonded(3);
        let v = crate::pqauth::MlDsaVerifier;
        let mut book = QuoteBook::default();
        let prices = [14_000u128, 15_000, 90_000];
        let q = |i: usize| sign_quote(1, 0, prices[i], &keys[i].0, &keys[i].1).expect("signs");
        assert!(book.ingest(&q(0), 1, &vs, &v));
        assert_eq!(book.quorum_quotes(0, &vs, &v), None, "⛔ one of three is not a quorum");
        assert!(book.ingest(&q(1), 1, &vs, &v));
        assert_eq!(book.quorum_quotes(0, &vs, &v), None, "⛔ DB-387: two of three equal bonds is EXACTLY 2/3 — the book must not publish what the door refuses");
        let two: Vec<crate::price_mark_tx::PriceQuote> = [q(0), q(1)].iter().map(|s| s.quote.clone()).collect();
        assert!(
            matches!(PegLedger::new(15_000).mark_price_attested(1, 0, &two, &vs, &v), crate::peg::PegOutcome::InsufficientThreshold),
            "CALIBRATION: the door refuses the exact-2/3 pair the book now withholds"
        );
        // A third, outlying quote cannot drag the mark: the median of the counted quotes stands.
        assert!(book.ingest(&q(2), 1, &vs, &v));
        let all = book.quorum_quotes(0, &vs, &v).expect("three of three is strictly above 2/3");
        let mut fresh = PegLedger::new(15_000);
        assert!(
            matches!(fresh.mark_price_attested(1, 0, &all, &vs, &v), crate::peg::PegOutcome::PriceMarked(15_000)),
            "⛔ the median of 14,000 / 15,000 / 90,000 is 15,000 — a single outlier must not move it"
        );
    }

    /// ⭐ BOUNDED WORK on the lane and at the door (DB-245):
    /// - a re-sent quote costs no signature check;
    /// - a quote the book verified is a cache hit for `BookVerifier`;
    /// - a triple the book does not hold byte for byte (another price, a changed signature) still goes to the
    ///   real verifier.
    #[test]
    fn a_resent_quote_and_a_quote_the_book_holds_cost_no_signature_check() {
        struct Counting(std::cell::Cell<usize>);
        impl PqVerifier for Counting {
            fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
                self.0.set(self.0.get() + 1);
                crate::pqauth::MlDsaVerifier.verify(pubkey, msg, sig)
            }
        }
        let (vs, keys) = bonded(3);
        let counting = Counting(std::cell::Cell::new(0));
        let mut book = QuoteBook::default();
        let q0 = sign_quote(7, 0, 15_000, &keys[0].0, &keys[0].1).expect("signs");
        assert!(book.ingest(&q0, 7, &vs, &counting), "PRECONDITION: gathered");
        assert_eq!(counting.0.get(), 1, "the first hearing pays one verify");
        for _ in 0..5 {
            assert!(!book.ingest(&q0, 7, &vs, &counting), "a re-sent quote is not new");
        }
        assert_eq!(counting.0.get(), 1, "⛔ five re-sends of a gathered quote must cost no signature check");

        let reuse = BookVerifier { book: &book, inner: &counting };
        let msg = PegLedger::price_mark_msg(7, 0, 15_000);
        assert!(reuse.verify(&q0.quote.pubkey, &msg, &q0.quote.sig), "the book's own quote verifies");
        assert_eq!(counting.0.get(), 1, "⛔ a quote the book verified must be a cache hit");
        let other_price = PegLedger::price_mark_msg(7, 0, 15_001);
        assert!(!reuse.verify(&q0.quote.pubkey, &other_price, &q0.quote.sig), "⛔ the signature covers 15,000 only");
        assert_eq!(counting.0.get(), 2, "a message the book does not hold goes to the real verifier");
        let mut bent = q0.quote.sig.clone();
        bent[0] ^= 1;
        assert!(!reuse.verify(&q0.quote.pubkey, &msg, &bent), "⛔ a changed signature is not the book's");
        assert_eq!(counting.0.get(), 3, "a signature the book does not hold goes to the real verifier");
    }

    #[test]
    fn moving_to_the_next_epoch_clears_the_book() {
        let (vs, keys) = bonded(1);
        let v = crate::pqauth::MlDsaVerifier;
        let mut book = QuoteBook::default();
        assert!(book.ingest(&sign_quote(4, 0, 15_000, &keys[0].0, &keys[0].1).expect("signs"), 4, &vs, &v));
        assert!(book.quorum_quotes(0, &vs, &v).is_some());
        assert!(book.ingest(&sign_quote(5, 0, 16_000, &keys[0].0, &keys[0].1).expect("signs"), 5, &vs, &v));
        assert_eq!(book.epoch(), 5);
        let only = book.quorum_quotes(0, &vs, &v).expect("the new epoch's own quote");
        assert_eq!(only.len(), 1, "⛔ the old epoch's quote must not survive into the new epoch's mark");
        assert_eq!(only[0].price, 16_000);
    }
}

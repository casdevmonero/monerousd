// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A FILL IS A TRANSACTION.** The canonical on-chain form of a DEX trade.
//!
//! WHAT THIS FIXES, measured 2026-09-03 by `dex_cross_party_scenarios`: a maker rested an order, it
//! gossiped, party B filled it and settled — and party A then settled THE SAME ORDER AGAIN from the same
//! bytes. The maker lot paid out twice against one note. Not a race and not a window:
//! `execute_order_fill` mutated only the node that received it (burn into that node own sparse tree, order
//! out of that node own book, three notes at that node own tip) and NONE of that was a message. The order
//! set gossips. The settlement did not.
//!
//! THE RULE THE CODE ALREADY KNEW. `node.rs` states it for account targets and padded tags: the
//! Bitcoin/Kaspa invariant — a block must carry what is needed to apply it. A SEND obeys it: its burns
//! reach the chain as `tx.nullifiers`, ride the block that includes the tx, and every node applies them at
//! graft. A FILL did not, and that single difference is the double-spend.
//!
//! SELF-VERIFICATION IS NOT CONSENSUS. Both parties self-verified that fill against their own state and
//! both were RIGHT to accept it; they still ended with two ledgers. Self-verification decides whether a
//! node ACCEPTS a transition. Only inclusion in the chain decides whether it HAPPENED. Every value-moving
//! transition must therefore be a chain object, and this module is the DEX one.
//!
//! WHAT IS HERE: the payload every node hashes, verifies and applies — identical bytes, identical gates,
//! identical outcome. What is NOT here: how it is submitted, mined or applied, which is the block path.

use serde::{Deserialize, Serialize};
use usdm_decider::whir_rec_block::{MakerHalfPublic, OrderTerms, TakerHalfPublic};

/// ⭐ DB-150 — THE BOUND ON A FILL'S MEMBERSHIP CARRIER. One recursive `AnchorMembershipCarrier`, the same
/// artifact an ordinary send carries; the door refuses anything wider so the field can never become a
/// channel. Mirrors `peg_attest::PEG_ATTEST_CARRIER_MAX`, which bounds the same artifact on the peg lane.
pub const ORDER_FILL_MEMBERSHIP_CARRIER_MAX: usize = 2 * 1024 * 1024;

/// The bound on a fill's membership ENDPOINT bytes: the widest shape `Node::membership_endpoint_len_ok`
/// admits (`4 * DIGEST_LANE_BYTES + 8`). Anything else is not an endpoint this chain can read.
pub const ORDER_FILL_MEMBERSHIP_TIP_MAX: usize = 4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8;

/// The complete fill, as it travels. Everything a node needs to run EVERY gate itself: it never trusts the
/// submitter verdict, only these bytes.
///
/// The three notes are positional and stay positional — maker payout, taker payout, taker change. Swapping
/// the maker payout with the taker change would use only proven notes and still steal the lot, which is
/// why the payout-note binding compares them slot by slot rather than as a set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderFillTx {
    pub lot: u64,
    pub pay_b: u64,
    pub asset_a: [u64; 3],
    pub asset_b: [u64; 3],
    pub expires_at_height: u64,
    pub maker_nullifier: crate::spend_frontier::Digest4,
    pub maker_leaf_commit: crate::spend_frontier::Digest4,
    pub maker_payout_cm: crate::spend_frontier::Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE maker half-proof carrier, the fixed-size
    /// output of `prove_order_maker_half`. Not a store: this value is the transaction itself, it is bounded
    /// by the mempool admit and it is released with the transaction.
    pub maker_bytes: Vec<u8>,
    pub taker_nullifier: crate::spend_frontier::Digest4,
    pub taker_leaf_commit: crate::spend_frontier::Digest4,
    pub taker_payout_cm: crate::spend_frontier::Digest4,
    pub taker_change_cm: crate::spend_frontier::Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE taker half-proof carrier, the fixed-size
    /// output of `prove_order_taker_half`; released with the transaction.
    pub taker_bytes: Vec<u8>,
    /// maker payout · taker payout · taker change, in that order and never re-ordered.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant 3 — exactly three notes, each one
    /// `PQ_NOTE_BYTES`; a settlement creates no other output.
    pub notes: [Vec<u8>; 3],
    /// ⭐ DB-273 §19.6 L3 — each note's OWNER, same order as `notes`: its OLI clue, never a static `(bucket, ek)`.
    /// Slot 0 (the maker's payout) is copied by the node's fill door from the resting order the MAKER posted
    /// (`RestingOrder::payout_clue`), never taken from the taker; slots 1–2 are the taker's own. Every node files the
    /// three from the object itself (`chain_object::object_owner_clue_records`).
    /// Named residual until lane-recursion's half-proof binds land (DB-273 §19.6 review): these are bound by the
    /// object's bytes, not yet by the maker/taker proofs (`payout_clue_digest` / `taker_clues_digest` public binds).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant 3 × `peg_in_tx::OWNER_CLUE_MAX` — `decode` refuses an
    /// empty or wider clue.
    pub owner_clues: [Vec<u8>; 3],
    /// ⭐⭐⭐ DB-150 — THE MAKER'S MEMBERSHIP CROSS-BIND: the recursive carrier proving the maker's INPUT
    /// note is in this chain's append-only note frontier. It rides the chain object because EVERY node
    /// re-checks it when the block applies — a bind only the submitter's node saw is the local-verification
    /// trap the cardinal names.
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_CARRIER_MAX (`decode` refuses wider);
    /// released with the transaction, never stored.
    pub maker_membership_carrier: Vec<u8>,
    /// The maker bind's endpoint bytes (see `maker_membership_carrier`).
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_TIP_MAX (`decode` refuses wider).
    pub maker_membership_tip: Vec<u8>,
    /// The taker's half of the same bind (see `maker_membership_carrier`).
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_CARRIER_MAX (`decode` refuses wider).
    pub taker_membership_carrier: Vec<u8>,
    /// The taker bind's endpoint bytes (see `maker_membership_tip`).
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_TIP_MAX (`decode` refuses wider).
    pub taker_membership_tip: Vec<u8>,
}

impl OrderFillTx {
    pub fn terms(&self) -> OrderTerms {
        OrderTerms {
            lot: self.lot,
            pay_b: self.pay_b,
            asset_a: self.asset_a,
            asset_b: self.asset_b,
            expires_at_height: self.expires_at_height,
        }
    }

    pub fn maker(&self) -> MakerHalfPublic {
        MakerHalfPublic {
            nullifier: self.maker_nullifier,
            leaf_commit: self.maker_leaf_commit,
            payout_cm: self.maker_payout_cm,
        }
    }

    pub fn taker(&self) -> TakerHalfPublic {
        TakerHalfPublic {
            nullifier: self.taker_nullifier,
            leaf_commit: self.taker_leaf_commit,
            change_cm: self.taker_change_cm,
            payout_cm: self.taker_payout_cm,
        }
    }

    /// The two burns this fill publishes, in the shape `PqTx::nullifiers` carries and a block commits to.
    /// THIS is what makes the fill final everywhere: the pair rides the chain, so a second taker on any
    /// other node meets an already-spent note instead of a fillable offer.
    pub fn nullifier_tags(&self) -> Vec<crate::hash::Hash32> {
        [self.maker_nullifier, self.taker_nullifier]
            .iter()
            .map(|nf| crate::hash::Hash32(crate::spend_frontier::leaf_to_cm_bytes(*nf)))
            .collect()
    }

    /// The bytes every node hashes. Deterministic and canonical: two nodes handed the same fill must
    /// produce the same id, or the same trade would occupy two mempool slots and two block entries.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// The bytes a transaction carries: the encoding, FRAMED with its class so a receiver judges it by the
    /// right rule. Publishers and tests both go through here — a hand-rolled `encode()` on the wire is an
    /// object nobody can classify, which is how the graft door started answering `NotDex` to a real fill.
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::OrderFill, &self.encode())
    }

    /// Refuses rather than guesses: a payload that does not decode is not a fill, and a fill whose terms
    /// are nonsense (a zero lot, a zero price, one asset traded for itself) never reaches a gate.
    pub fn decode(bytes: &[u8]) -> Option<OrderFillTx> {
        let f: OrderFillTx = crate::chain_object::decode_exact(bytes)?;
        if f.lot == 0 || f.pay_b == 0 || f.asset_a == f.asset_b {
            return None;
        }
        if f.notes.iter().any(|n| n.len() < 32) {
            return None; // a note too short to carry a commitment cannot be credited to anyone
        }
        // DB-273 §19.6 L3: every note names its owner — a settlement note filed for nobody is money no seed restore finds.
        if f.owner_clues.iter().any(|c| c.is_empty() || c.len() > crate::peg_in_tx::OWNER_CLUE_MAX) {
            return None;
        }
        // DB-150: the membership binds are bounded at the door, so a wide field is not a transaction.
        if f.maker_membership_carrier.len() > ORDER_FILL_MEMBERSHIP_CARRIER_MAX
            || f.taker_membership_carrier.len() > ORDER_FILL_MEMBERSHIP_CARRIER_MAX
            || f.maker_membership_tip.len() > ORDER_FILL_MEMBERSHIP_TIP_MAX
            || f.taker_membership_tip.len() > ORDER_FILL_MEMBERSHIP_TIP_MAX
        {
            return None;
        }
        Some(f)
    }
}

/// What a block's canonical fold did with one carried fill (DB-368).
#[derive(Debug, PartialEq, Eq)]
pub enum FillFoldApply {
    /// Not a fill — another class's arm judges it.
    NotFill,
    /// The fill passed the one fill rule. Its notes ride the carrying block and its burns ride the lane; nothing else is
    /// written here.
    Settled,
    /// The payload does not decode as a fill.
    Malformed,
    /// The carrying block has no blue score on this node, so expiry cannot be judged. Fail-closed.
    ScoreUnknown,
    /// The one fill rule refused it, for this reason.
    Refused(OrderFillOutcome),
}


/// What a block's transaction turned out to be, once a node looked at its bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum DexApply {
    /// Not a DEX object — an ordinary transaction, untouched by this path.
    NotDex,
    /// An order joined this node's book at the given lattice level.
    OrderRested(u32),
    /// An order was refused; the reason is the book's own.
    OrderRefused(crate::order_book::PostRefusal),
    /// A fill was applied, or refused, by the same gates the submitter ran.
    Fill(OrderFillOutcome),
}


/// ⭐⭐⭐ THE GAP EDIT — RETIRE EVERY ORDER THE BLOCK'S BURNS KILLED, ON EVERY NODE, USING ONLY WHAT THE
/// BLOCK ALREADY CARRIES.
///
/// WHY THIS AND NOT THE OBVIOUS THING. The obvious call site walks the block's transactions and applies
/// each DEX object. It cannot work: `Block` carries `tx_ids` — CONTENT HASHES — and no tx-body field, so a
/// grafting node reconstructs bodies from its OWN mempool. On the node that pooled the fill the bodies are
/// there and the object applies; on a node that received the block by gossip and never pooled that tx, the
/// set is empty and nothing applies. Two nodes, same block, different state — the very defect class we are
/// closing, wearing the other hat. connect-90 caught that before it landed and they were right.
///
/// WHAT THE BLOCK DOES CARRY IS ENOUGH. A fill's two burns ride in `nullifier_proof.padded_tags`, bound
/// into the block id, and every node already applies them. A resting order is identified by its maker's
/// nullifier — the very note the fill burns. So a node does not need the fill's bytes to know the order is
/// dead: it needs only to notice that the order's note was spent, which the block told it.
///
/// That makes the book a FUNCTION OF THE CHAIN rather than of gossip: any node holding the block retires
/// the same orders, whether or not it ever saw the fill, the order post, or the taker.
///
/// The cover tags are indistinguishable from real ones by construction and simply match nothing — the
/// lane is padded to a constant `BLOCK_FIXED_NULLIFIER_COUNT`, and that padding is what keeps an observer
/// from counting real spends. Passing them through changes nothing and reveals nothing.
///
/// ⛔⛔⛔ THE TAG IS A DIGEST THE CARRIER PRODUCED — DECODE IT, NEVER HASH IT (kill list §AG/§AI class).
/// The book keys an order by `maker.nullifier`, the `Digest4` `prove_order_maker_half` emitted, and the
/// fill publishes that same digest as `leaf_to_cm_bytes(nullifier)` (`OrderFillTx::nullifier_tags`) — the
/// canonical injective encoding. This looked the tag up with `cm_bytes_to_leaf`, which §AG made a HASH,
/// so the key it computed was `hash(bytes(nullifier))`, a value no book ever held. MEASURED 2026-09-13
/// for the order in `a_block_s_burns_retire_the_orders_they_killed_on_a_node_that_saw_nothing_else`:
/// book key `[350739501, 523631800, ..]`, retirement key `[860069340, 898947488, ..]`, decode
/// `Some([350739501, 523631800, ..])` — the block applied on every node and retired NOTHING, which is the
/// red both cross-party settlement pins showed ("the block's burns retire the order from B's book").
/// `cm_bytes_to_root` is the inverse of `leaf_to_cm_bytes`; a cover tag (blake3 fill) is either not a
/// canonical encoding (`None`, skipped) or decodes to a digest no order rests under — it matches nothing
/// either way, exactly as before, so the constant lane still hides the real count.
///
/// Returns how many orders were retired, so a caller can log a number rather than a hope.
pub fn retire_orders_burned_by(
    book: &mut crate::order_book::OrderBook,
    padded_tags: &[[u8; 32]],
) -> usize {
    let mut retired = 0usize;
    for tag in padded_tags {
        let Some(nullifier) = crate::spend_frontier::cm_bytes_to_root(tag) else {
            continue; // not a canonical digest encoding ⇒ cannot name any resting order
        };
        if book.remove_by_nullifier(nullifier) {
            retired += 1;
        }
    }
    retired
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::OrderFillTx;

    fn a_fill() -> OrderFillTx {
        OrderFillTx {
            lot: 100_000_000,
            pay_b: 250_000,
            asset_a: [0, 0, 0],
            asset_b: [1, 0, 0],
            expires_at_height: 1_000_000,
            maker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            maker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            maker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
            maker_bytes: vec![0xAA; 96],
            taker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[13, 14, 15, 16]),
            taker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[17, 18, 19, 20]),
            taker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]),
            taker_change_cm: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]),
            taker_bytes: vec![0xBB; 96],
            maker_membership_carrier: Vec::new(),
            maker_membership_tip: Vec::new(),
            taker_membership_carrier: Vec::new(),
            taker_membership_tip: Vec::new(),
            notes: [vec![1u8; 64], vec![2u8; 64], vec![3u8; 64]],
            owner_clues: [vec![0xA0; 8], vec![0xA1; 8], vec![0xA2; 8]],
        }
    }

    /// The same fill must encode to the same bytes on every node, or one trade occupies two mempool slots.
    #[test]
    fn a_fill_encodes_canonically_and_round_trips() {
        let f = a_fill();
        let b = f.encode();
        assert_eq!(b, f.encode(), "encoding must be deterministic");
        assert_eq!(OrderFillTx::decode(&b).expect("round trips"), f);
    }

    /// THE POINT OF THE WHOLE MODULE: the pair burn is published, so a second taker anywhere meets a spent
    /// note. Both nullifiers, in the shape a block commits to.
    #[test]
    fn a_fill_publishes_both_burns_for_the_block_to_carry() {
        let tags = a_fill().nullifier_tags();
        assert_eq!(tags.len(), 2, "a fill burns the maker note AND the taker note — both must travel");
        assert_ne!(tags[0], tags[1], "the two burns are distinct notes");
    }

    /// Malformed or absurd fills are refused before any gate runs — a zero lot, a zero price, an asset
    /// traded for itself, a note too short to carry a commitment, and outright garbage.
    #[test]
    fn a_malformed_fill_is_refused_rather_than_half_understood() {
        assert!(OrderFillTx::decode(&[0xFF; 24]).is_none(), "garbage is not a fill");
        for mutate in [
            (|f: &mut OrderFillTx| f.lot = 0) as fn(&mut OrderFillTx),
            |f: &mut OrderFillTx| f.pay_b = 0,
            |f: &mut OrderFillTx| f.asset_b = f.asset_a,
            |f: &mut OrderFillTx| f.notes[1] = vec![0u8; 8],
        ] {
            let mut f = a_fill();
            mutate(&mut f);
            assert!(
                OrderFillTx::decode(&f.encode()).is_none(),
                "a fill that cannot be applied must be refused at decode, never half-understood"
            );
        }
    }

    /// ⭐ DB-273 §19.6 L3 (c) — A FILL NAMES AN OWNER FOR EVERY NOTE, AND EVERY NODE FILES THEM FROM THE OBJECT IN SLOT
    /// ORDER. Replaces the account-target encoder pin (the encoder is deleted: no fill carries a `(bucket, ek)` any more).
    /// - a fill whose any slot names NO owner, or an over-wide one, is not a fill (a note filed for nobody is money no
    ///   seed restore finds);
    /// - the records a node files are exactly (maker payout, taker payout, taker change) × their own clues, in that order,
    ///   so a drift that files the maker's payout under the taker's clue (or the reverse) reds here.
    #[test]
    fn db273_s19_l3_a_fill_names_every_notes_owner_and_is_filed_from_the_object_in_slot_order() {
        let f = a_fill();
        let recs = crate::chain_object::object_owner_clue_records(&f.wire()).expect("a fill is an owner-named object");
        let want: Vec<([u8; 32], Vec<u8>)> = f
            .notes
            .iter()
            .zip(f.owner_clues.iter())
            .map(|(n, c)| (<[u8; 32]>::try_from(&n[..32]).expect("a 32-byte front"), c.clone()))
            .collect();
        assert_eq!(recs, want, "⛔ the fill's owners are not filed as (note, its own clue) in slot order");
        for slot in 0..3 {
            let mut ownerless = a_fill();
            ownerless.owner_clues[slot] = Vec::new();
            assert!(OrderFillTx::decode(&ownerless.encode()).is_none(), "⛔ a fill with no owner at slot {slot} decoded");
            let mut wide = a_fill();
            wide.owner_clues[slot] = vec![0xA9; crate::peg_in_tx::OWNER_CLUE_MAX + 1];
            assert!(OrderFillTx::decode(&wide.encode()).is_none(), "⛔ a fill with an over-wide owner at slot {slot} decoded");
        }
    }

    /// ⭐ RED-TEAM HOLE-CLOSURE PIN (2026-09-06) — WIRE MALLEABILITY, fill class: one settlement under
    /// MANY distinct byte encodings blinds the pool's by-id dedup, so one trade could occupy unbounded
    /// pool slots and be carried by a block more than once — the double-settlement class this whole
    /// module exists to kill, re-entered through the byte tail.
    ///
    /// ROOT-LAYER: `OrderFillTx::decode` — `postcard::from_bytes` deserializes a prefix and IGNORES
    /// trailing bytes, so `encode(f) || junk` decodes to the SAME fill while `PqTx::content_id`
    /// (blake3 of the whole blob) names a DIFFERENT transaction. The fix is the shared strict
    /// full-consumption decode (`chain_object::decode_exact`).
    /// MEASURED: 7 trailing bytes appended after the postcard payload; the padded bytes differ from
    /// the canonical encoding and MUST refuse to decode. First run 2026-09-06 decides RED or GREEN — a
    /// RED is the confirmed malleability hole and this pin specifies the decode-strictness fix.
    /// MUST-STAY-GREEN: a fill carrying trailing bytes is not a second fill.
    #[test]
    fn a_fill_with_trailing_bytes_is_not_a_second_fill() {
        let f = a_fill();
        let canonical = f.encode();
        assert!(OrderFillTx::decode(&canonical).is_some(), "PRECONDITION: the canonical bytes decode");
        let mut padded = canonical.clone();
        padded.extend_from_slice(&[0xEE; 7]);
        assert_ne!(padded, canonical, "the padded bytes are genuinely different bytes");
        assert!(
            OrderFillTx::decode(&padded).is_none(),
            "FORGERY: the same fill under a second byte encoding must be refused — one object, ONE \
             encoding; a tolerated tail is how one settlement rides multiple block carriages"
        );
    }

    /// The note slots are POSITIONAL. Swapping the maker payout with the taker change uses only proven
    /// notes, so nothing downstream would notice — the encoding must preserve the order it was given.
    #[test]
    fn the_note_slots_are_positional_and_survive_the_round_trip() {
        let mut f = a_fill();
        f.notes.swap(0, 2);
        let back = OrderFillTx::decode(&f.encode()).expect("round trips");
        assert_eq!(back.notes[0], f.notes[0], "slot 0 must still be slot 0");
        assert_ne!(back.notes[0], a_fill().notes[0], "the swap survived — slots are not a set");
    }
    /// ⭐ THE GAP CLOSED: a node that never saw the fill, never pooled the tx and never saw the order post
    /// still retires the order, because the BLOCK told it the maker's note was spent.
    #[test]
    fn a_block_s_burns_retire_the_orders_they_killed_on_a_node_that_saw_nothing_else() {
        use crate::order_book::{OrderBook, RestingOrder};
        use usdm_decider::whir_rec_block::{
            prove_order_maker_half, wrapped_asset_tag_u32, MakerHalfWitness, OrderTerms, USDM_ASSET_TAG,
        };
        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: USDM_ASSET_TAG,
            asset_b: wrapped_asset_tag_u32(1),
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        };
        let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5_001, 5_002, 5_003, 5_004])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[5_011, 5_012, 5_013, 5_014]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let (mc, mp) = prove_order_maker_half(&mw, &t).expect("maker half proves");
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm));
        let order = RestingOrder { terms: t, maker: mp, maker_bytes: mc, payout_note: note , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };

        let mut book = OrderBook::new();
        book.post(order.clone(), 0).expect("the order rests on a node that only ever saw the post");
        assert_eq!(book.len(), 1, "PRECONDITION: the book serves it");

        // A block whose nullifier lane carries the maker's burn among cover tags — exactly the shape a
        // padded lane has on the wire, and all this node ever receives.
        let mut tags: Vec<[u8; 32]> = (0..8u8).map(|i| [i; 32]).collect();
        let burn = crate::spend_frontier::leaf_to_cm_bytes(order.maker.nullifier);
        tags.insert(3, burn);

        // ⛔ THE KEY PIN (measured 2026-09-13): the tag on the wire is the canonical encoding of the digest
        // the book keys on, so only the injective decode reproduces that key — the §AG HASH does not. A
        // regression back to `cm_bytes_to_leaf` fails HERE, with both keys printed, instead of as a
        // cross-party settlement that "applied the block and retired nothing".
        assert_eq!(
            crate::spend_frontier::cm_bytes_to_root(&burn),
            Some(order.maker.nullifier),
            "the burn tag must DECODE back to the very digest the book holds"
        );
        assert_ne!(
            crate::spend_frontier::cm_bytes_to_leaf(&burn),
            order.maker.nullifier,
            "⛔ `cm_bytes_to_leaf` is a HASH — if it ever reproduces the book key, the §AG contract changed \
             under this module and the retirement's decode must be re-audited"
        );

        let retired = super::retire_orders_burned_by(&mut book, &tags);
        assert_eq!(retired, 1, "the block's burn must retire exactly the order whose note it spent");
        assert_eq!(
            book.len(),
            0,
            "⛔ the order survived a block that spent its maker's note — then a taker on this node would \
             build a fill against a burned note and be refused, and this node's book is its own"
        );
        // Cover tags match nothing, so a quiet block retires nothing.
        assert_eq!(
            super::retire_orders_burned_by(&mut book, &(0..8u8).map(|i| [i; 32]).collect::<Vec<_>>()),
            0,
            "cover tags must retire nothing — the padded lane is what hides the real count"
        );
    }

}

impl OrderFillTx {
}
/// Why an order fill was admitted or refused. Every arm is a REFUSAL WITH A REASON — a caller can always
/// say which gate rejected the fill, and none of them is a silent skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderFillOutcome {
    /// Both halves verified, both inputs burned, all three notes credited.
    Settled,
    /// DEX-GRID: the terms' lot, price or expiry is off the protocol grid — a distinctive term would fingerprint the
    /// maker. Refused before anything burns, at every door, through one check (`order_book::on_grid`).
    OffGrid,
    /// Past the maker's own `expires_at_height`.
    Expired,
    /// The two halves do not compose into one trade at these terms.
    ProofRefused,
    /// One note presented as both sides of its own trade.
    SelfDealing,
    /// A credit with no owner would be undiscoverable money.
    MissingOwner,
    /// The maker's note is already spent — the order was filled by someone else, or cancelled.
    OrderAlreadyFilled,
    /// The taker's own input is already spent.
    TakerNoteSpent,
    /// ⛔ A supplied note payload does not carry the commitment its slot was PROVEN to hold. The proof is
    /// about three specific notes; these are not those notes. Refused BEFORE anything burns, so the maker
    /// keeps their resting lot — the alternative is a burned lot paid into a note its owner cannot open.
    PayoutNoteMismatch,
    /// The settlement could not be ADMITTED as a transaction, so nothing was written. A fill that cannot
    /// travel is a fill that would settle on this node alone — the double-fill shape — so it is refused
    /// outright rather than applied locally and reported OK.
    NotPublished,
    /// ⛔⛔⛔ DB-150 — A HALF DID NOT PROVE ITS INPUT NOTE IS ON THIS CHAIN.
    ///
    /// The half-proofs attest a trade between two notes; they say nothing about whether the chain ever
    /// held those notes. Until Z1 the DELETION TRANSITION answered that — the fill had to find both
    /// inputs present in the unspent tree — and retiring that tree took the check with it. Its
    /// replacement is Zcash's own pairing: a spend proves MEMBERSHIP of its note in the append-only
    /// frontier AND non-membership of its nullifier. This is the membership half; without it a
    /// settlement can be composed from notes that never existed.
    MembershipRefused,
    /// A half's membership proof is otherwise valid but names a record this node has not FOLDED (or does not hold) yet —
    /// a race, not a wrong submission: nothing burned, and the same fill is admitted after the fold ([`MemberVerdict`]).
    MembershipPending,
}


// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **THE ORDER BOOK — resting orders in DA/gossip, never consensus state.**
//!
//! A maker posts a conditional spend authorisation and goes offline. A taker fills it unilaterally. The
//! CHAIN sees only the resulting burn-2/create-3 settlement ([`crate::node::Node::execute_order_fill`]);
//! it never sees an unfilled order at all. This module is where those resting orders live in the
//! meantime: a bounded, self-expiring set that every node serves identically.
//!
//! ⛔⛔⛔ ZERO PER-ORDER CHAIN STATE. Nothing here is persisted to the snapshot, folded into an
//! accumulator, or bound into a block id. That is what makes the book free: the pool AMM was retired
//! because a pool is shared mutable state every fill serialises through, and a book that became consensus
//! state would reintroduce exactly that, plus a growth axis in orders. An order is an OFFER, and an offer
//! nobody has accepted has no business on a ledger.
//!
//! ⛔ THE PRICE LATTICE IS PROTOCOL-FIXED, NOT MAKER-CHOSEN. Every order rests at a level drawn from one
//! public grid, at one fixed lot. If makers picked their own prices, a distinctive limit would be an
//! IDENTIFIER: repeated distinctive prices link a maker's orders across time into a profile, which is the
//! identity leak this whole design exists to prevent. A shared grid makes every order at a level
//! indistinguishable from every other one there. Governance may retune the grid at a version boundary
//! where every node moves together; a maker may not, and neither may one node — either re-opens the
//! fingerprint through the back door, and a per-node grid would split the book outright.
//!
//! WHY A FLAT VEC AND NOT A MAP: the book's whole capacity is [`BOOK_CAPACITY`] = 64 x 32 = 2,048 orders,
//! a fixed protocol shape. At that size a scan IS the index — 2,048 comparisons of a 4-word nullifier is
//! nothing beside the WHIR verify each post already pays — and one flat structure with a hard total bound
//! cannot develop the per-key growth a nested map invites.
//!
//! cons: none, and the arithmetic rather than the claim. SIZE: 2,048 orders max, each a maker half plus
//! its proof — the ceiling is f(fixed constants), never f(chain height, order history or fill count), and
//! expiry drains it continuously instead of accumulating. The book rides the checkpoint (`NodeSnapshot::resting_orders`,
//! v46: a whole-mesh restart left no node to re-flood from) and every entry re-enters through `post` at boot. TIME: every
//! operation is one pass over at most 2,048 entries — no walk over blocks, records, notes or history —
//! so the cost of the ten-thousandth post equals the cost of the first.

use usdm_decider::whir_rec_block::{verify_order_maker_half, MakerHalfPublic, OrderTerms};

/// How many price levels the public grid holds.
///
/// PAST-CHATS-CHECKED: the DEX completion plan specifies "fixed price lattice x fixed lot as governance
/// constants" and the user's ruling bans a maker-tunable grid — but neither names a NUMBER, so this is
/// DERIVED, not tuned. The grid is logarithmic in the price ratio `pay_b / lot`, both u64, so 64
/// doublings is exactly the span of the representable ratio range (`log2(u64::MAX) = 64`). One level
/// fewer leaves prices unreachable at the top of the range; one more addresses a ratio a u64 cannot hold.
pub const LATTICE_LEVELS: u32 = 64;

/// Orders held per (pair, level) — and the number of slots each level SERVES.
///
/// PAST-CHATS-CHECKED: reuses the EXISTING served-set cover width `protocol::TX_REQ_FIXED_COUNT` instead
/// of inventing a second constant beside it, and for the same stated reason that one already carries —
/// it is the fixed width of a SERVED set, sized so a response never encodes how much the responder
/// actually holds. A book level is exactly that shape again, so it takes exactly that number.
pub const LEVEL_SLOTS: usize = crate::protocol::TX_REQ_FIXED_COUNT;

/// The book's whole capacity — the grid times the slot width, both fixed above. Named so the bound is
/// checkable in one place rather than inferred at each use.
pub const BOOK_CAPACITY: usize = LATTICE_LEVELS as usize * LEVEL_SLOTS;

/// ⭐ DEX-GRID (docs/DEX-GRID-ENFORCEMENT-SPEC.md §2b, GO'd 2026-09-30) — the significant bits a grid value may carry.
///
/// A value is ON THE GRID iff it is `m · 2^e` with `m < 2^GRID_MANTISSA_BITS`: the low `bits − GRID_MANTISSA_BITS`
/// bits are zero. `GRID_MANTISSA_BITS = B + 1` with `B = ceil(log2(10_000 / fee_bps))`. Consecutive grid values then
/// differ by at most 2^-B of their size (9.77 bps at 10 bps), EXACT by construction, so snapping a price to the grid
/// never costs a taker more than the fee they already pay. The check is O(1) and exact, and needs no origin.
/// C2: derived from the GENESIS fee (`ORDER_FILL_FEE_BPS_DEFAULT`), never the live-retunable rate. A mid-flight retune
/// would make every resting order off-grid and unsettleable (stranded lots).
pub const GRID_MANTISSA_BITS: u32 = grid_mantissa_bits(crate::params::ORDER_FILL_FEE_BPS_DEFAULT);

const fn grid_mantissa_bits(fee_bps: u64) -> u32 {
    let ratio = 10_000 / fee_bps;
    let mut b = 0u32;
    while (1u64 << b) < ratio {
        b += 1;
    }
    b + 1
}

/// The expiry bucket: an order's `expires_at_height` must be a multiple of it, so expiry is drawn from a public
/// cadence and cannot fingerprint a maker. It reuses the network's existing public cadence (the OLI index epoch), so it
/// adds no new constant. It is not the fold depth: that is a runtime parameter (0 in tests) and could not be a divisor.
pub const EXPIRY_EPOCH: u64 = crate::oli::EPOCH_BLOCKS;

/// Whether `v` is a grid value (see [`GRID_MANTISSA_BITS`]). Zero is not a value.
#[must_use]
pub fn on_grid_value(v: u64) -> bool {
    v != 0 && 64 - v.leading_zeros() - v.trailing_zeros() <= GRID_MANTISSA_BITS
}

/// ⭐ THE ONE SNAP (C3): `v` rounded DOWN to the grid. The wallet ladder and every fixture go through it, so no caller
/// hand-picks an on-grid-looking value.
#[must_use]
pub fn snap_to_grid(v: u64) -> u64 {
    let bits = 64 - v.leading_zeros();
    if bits <= GRID_MANTISSA_BITS {
        return v;
    }
    let s = bits - GRID_MANTISSA_BITS;
    (v >> s) << s
}

/// An expiry rounded UP to the next [`EXPIRY_EPOCH`] boundary, so snapping never shortens a maker's order.
#[must_use]
pub fn snap_expiry(h: u64) -> u64 {
    h.div_ceil(EXPIRY_EPOCH).saturating_mul(EXPIRY_EPOCH)
}

/// ⭐ THE ONE GRID CHECK (C1): the book's post door and the settlement engine every node runs at graft both call it.
/// Every public term is a protocol value, so no order can carry a distinctive price, lot or expiry.
#[must_use]
pub fn on_grid(t: &OrderTerms) -> bool {
    on_grid_value(t.lot) && on_grid_value(t.pay_b) && t.expires_at_height % EXPIRY_EPOCH == 0
}

/// A pair, named by its two asset tags in a canonical orientation so both sides of a market index the
/// same book. `asset_a` is what a maker gives and `asset_b` what they want, but the PAIR is
/// orientation-free: a bid and an ask on one market share a key, so a taker sees both sides at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairKey([u64; 6]);

impl PairKey {
    pub fn of(asset_a: [u64; 3], asset_b: [u64; 3]) -> PairKey {
        let (lo, hi) = if asset_a <= asset_b {
            (asset_a, asset_b)
        } else {
            (asset_b, asset_a)
        };
        PairKey([lo[0], lo[1], lo[2], hi[0], hi[1], hi[2]])
    }
}

/// One resting order: the maker's public half plus the terms it was proved against. Exactly what a taker
/// needs to build a fill and nothing more — no maker identity, no key, no note bytes, no contact path.
/// The maker is offline from the moment they post.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestingOrder {
    pub terms: OrderTerms,
    pub maker: MakerHalfPublic,
    /// The maker's half-proof, carried verbatim so a taker can verify an offer before spending effort on
    /// it, and a node can refuse a forgery before it ever reaches a book.
    pub maker_bytes: Vec<u8>,
    /// ⭐⭐⭐ THE MAKER'S PRE-BUILT PAYOUT NOTE — WITHOUT THIS AN ORDER IS UNFILLABLE.
    ///
    /// The settlement gate binds the credited note to `maker.payout_cm`, and only the MAKER can produce
    /// these bytes: they sealed the note to their own one-time key when they posted. A taker holding
    /// just the commitment has a number they cannot turn into a note, so every honest fill would be
    /// refused. MEASURED 2026-08-31: the book served `payout_cm` and not these bytes, and the whole
    /// trade path was a dead end while the node half and the wallet half were each green in isolation —
    /// neither suite could see it, because each tested only its own side of the seam.
    ///
    /// PRIVACY: publishing these leaks nothing new. It is an ML-KEM ciphertext only the maker can open,
    /// its commitment is already public as `payout_cm`, and the bytes must reach the chain verbatim when
    /// the fill settles. Publishing at post time only moves an already-public value earlier.
    pub payout_note: Vec<u8>,
    /// ⭐⭐⭐ DB-150 — THE MAKER'S MEMBERSHIP CROSS-BIND, POSTED WITH THE ORDER.
    ///
    /// A fill is two spends, so it needs two proofs that the notes being spent are on this chain. Only
    /// the MAKER can build theirs (it is a proof about their own note's position), and they build it when
    /// they post — so it rests with the order and every taker and every node reads the same bytes. A
    /// resting order without it can never settle, which is the honest outcome: an offer nobody can prove
    /// is backed by a real note is not an offer.
    ///
    /// PRIVACY: a membership carrier is a recursive proof over PUBLIC per-block anchors, binding a
    /// commitment already published as `maker.leaf_commit`. It reveals no position, amount, key or owner,
    /// and it is the same artifact an ordinary send already publishes.
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_CARRIER_MAX — the book refuses a wider
    /// order at `post`, and the order is released when it fills or expires.
    pub membership_carrier: Vec<u8>,
    /// The endpoint the maker's carrier folded to (see `membership_carrier`).
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_TIP_MAX — the book refuses a wider order
    /// at `post`.
    pub membership_tip: Vec<u8>,
    /// ⭐ DB-273 §19.6 L3 — THE MAKER'S PAYOUT OWNER: the payout note's OLI clue, chosen by the MAKER at post (a fresh
    /// reserved `chg` index, never reused across orders) and carried by the order. The node's fill door copies it into
    /// the settlement's slot 0 from the book — the taker never names the maker's owner. It links the payout only to its
    /// own order, which the fill already does, so serving it with the order's public terms reveals nothing new.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX` — the book refuses an empty or
    /// wider clue at `post`, and the order is released when it fills or expires.
    pub payout_clue: Vec<u8>,
}

impl RestingOrder {
    /// The grid level this order rests at, DERIVED from its own terms and never declared.
    ///
    /// Derived matters: a declared level would let a maker file an order under a price it does not have,
    /// sitting invisible to the takers looking where its price says it should be. The top level ABSORBS
    /// everything above it rather than wrapping, because a wrap would alias a very high price onto a very
    /// low one and show two orders as crossing when they do not.
    pub fn level(&self) -> u32 {
        if self.terms.lot == 0 {
            return 0;
        }
        let ratio = self.terms.pay_b / self.terms.lot.max(1);
        let mut level = 0u32;
        let mut bound = 1u64;
        while level + 1 < LATTICE_LEVELS && ratio >= bound {
            bound = bound.saturating_mul(2);
            level += 1;
        }
        level
    }

    /// The market this order belongs to.
    pub fn pair(&self) -> PairKey {
        PairKey::of(self.terms.asset_a, self.terms.asset_b)
    }
}

/// ⭐ THE FROZEN WIRE SHAPE OF A RESTING ORDER — what peers exchange, owned HERE and never borrowed from
/// the decider's live types.
///
/// The frozen-door incident is the reason this is its own struct: a legacy decoder that referenced live
/// consensus types rotted the instant one of them gained a field, and every door in the tree broke at once.
/// A gossip payload has exactly the same exposure — peers on two binaries must agree on the bytes — so the
/// wire form is written out in plain arrays and nothing upstream can reach it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrderWire {
    pub lot: u64,
    pub pay_b: u64,
    pub asset_a: [u64; 3],
    pub asset_b: [u64; 3],
    pub expires_at_height: u64,
    pub nullifier: crate::spend_frontier::Digest4,
    pub leaf_commit: crate::spend_frontier::Digest4,
    pub payout_cm: crate::spend_frontier::Digest4,
    pub maker_bytes: Vec<u8>,
    pub payout_note: Vec<u8>,
    /// DB-150: the maker's membership cross-bind travels with the order (see `RestingOrder`).
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_CARRIER_MAX at the book door.
    pub membership_carrier: Vec<u8>,
    /// DB-150: the endpoint of the bind above.
    /// O1-FOOTPRINT-REVIEWED: bounded by ORDER_FILL_MEMBERSHIP_TIP_MAX at the book door.
    pub membership_tip: Vec<u8>,
    /// DB-273 §19.6 L3: the maker's payout owner clue travels with the order (see `RestingOrder::payout_clue`).
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX` at the book door.
    pub payout_clue: Vec<u8>,
}

impl OrderWire {
    pub fn of(o: &RestingOrder) -> OrderWire {
        OrderWire {
            lot: o.terms.lot,
            pay_b: o.terms.pay_b,
            asset_a: o.terms.asset_a,
            asset_b: o.terms.asset_b,
            expires_at_height: o.terms.expires_at_height,
            nullifier: o.maker.nullifier,
            leaf_commit: o.maker.leaf_commit,
            payout_cm: o.maker.payout_cm,
            maker_bytes: o.maker_bytes.clone(),
            payout_note: o.payout_note.clone(),
            // ⛔⛔⛔ DB-401 — THE MAKER'S MEMBERSHIP BIND TRAVELS WITH THE ORDER, on BOTH lanes this one shape feeds (the
            // gossip arm and the `Class::OrderPost` object a block carries). Both fields were written `Vec::new()` here and
            // in `into_order`, so every book but the posting node's held the offer WITHOUT the maker's bind, and a taker on
            // any other node submitted an empty maker bind that the fill door refuses (DB-150).
            // MEASURED sim-20261006-190157 (eco T2): W1 rested a SIMT rung through node 0, node 1's book served it, W2's
            // `swapexec` through node 1 → `[order-fill] ⛔ REFUSED: a half did not prove its input note is in this chain's
            // note frontier` with NO `[membership-1step]` line (the carrier was empty, so no verify ran); W2's 3.0 USDm
            // never moved. Pin: `dex_cross_party_scenarios::db401_…`.
            membership_carrier: o.membership_carrier.clone(),
            membership_tip: o.membership_tip.clone(),
            // DB-273 §19.6 L3: the maker's payout owner TRAVELS with the order, so every book that holds it can copy it.
            payout_clue: o.payout_clue.clone(),
        }
    }

    /// Rebuild the order a peer sent. NOTHING here is trusted: the caller hands the result to
    /// [`OrderBook::post`], which re-verifies the maker half and re-derives the level, so a peer can put
    /// nothing into our book that it could not have posted directly.
    pub fn into_order(self) -> RestingOrder {
        RestingOrder {
            terms: OrderTerms {
                lot: self.lot,
                pay_b: self.pay_b,
                asset_a: self.asset_a,
                asset_b: self.asset_b,
                expires_at_height: self.expires_at_height,
            },
            maker: MakerHalfPublic {
                nullifier: self.nullifier,
                leaf_commit: self.leaf_commit,
                payout_cm: self.payout_cm,
            },
            maker_bytes: self.maker_bytes,
            payout_note: self.payout_note,
            // DB-401: the bind the wire carried (see `OrderWire::of`); `OrderBook::post` bounds it.
            membership_carrier: self.membership_carrier,
            membership_tip: self.membership_tip,
            payout_clue: self.payout_clue,
        }
    }
}

/// Why an order was refused a place in the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostRefusal {
    /// The maker's half does not verify against its own terms — a forgery, or terms it was not proved
    /// against. Refused HERE so a forgery never reaches a taker at all.
    ProofRefused,
    /// Already past its own expiry at the height it was offered.
    AlreadyExpired,
    /// Terms outside the protocol's shape (zero lot, zero payment, one asset traded for itself, or a lot, price
    /// or expiry off the protocol grid — DEX-GRID).
    MalformedTerms,
    /// This exact resting note is already offered — one note is one offer.
    Duplicate,
    /// DB-384 (rogue-role census, OrderPost × replay): the maker's lot is already SPENT in the posting node's view — the
    /// order was filled or cancelled — so the offer is dead and never re-rests, whoever re-carries its post.
    MakerSpent,
    /// This (pair, level) already holds its full complement.
    LevelFull,
    /// ⛔ The maker's payout NOTE does not carry the commitment the maker's own half proved. Such an
    /// order is UNFILLABLE: the settlement gate binds the credited note to `maker.payout_cm`, so every
    /// taker who read it would build a fill, pay the proving cost, submit, and be refused. Refusing at
    /// POST is strictly kinder than letting each taker discover it at fill, and it is the same
    /// denial-of-service-on-takers class the maker-half verify above exists to prevent.
    PayoutNoteMismatch,
    /// ⛔ DB-273 §19.6 L3: the order names no payout owner (or an over-wide one). Its payout would be filed for nobody —
    /// money no seed restore finds — so it is refused at post, never defaulted to an owner the maker did not choose.
    MissingPayoutOwner,
    /// ⛔ DB-401: the order carries no maker membership bind (or an over-wide or wrong-length one). It can never settle
    /// (DB-150), so it is refused at post on every lane, never rested for takers to discover at fill.
    MissingMembershipBind,
}

/// The node's live book (checkpointed as wires, re-posted at boot — `Node::restore_resting_orders`).
#[derive(Clone, Debug, Default)]
pub struct OrderBook {
    orders: Vec<RestingOrder>,
}

impl OrderBook {
    pub fn new() -> OrderBook {
        OrderBook { orders: Vec::new() }
    }

    /// ⭐ ONE RE-FLOOD PAGE of the resting book: up to `n` orders' wire encodings starting at
    /// `cursor` (wrapping), plus the next cursor.
    ///
    /// ROOT-LAYER: an accepted order is gossiped EXACTLY ONCE at post time, and a ~21KB multi-cell
    /// message on the paced lane is the measured single-shot-loss class (the letter incident: "a
    /// stalled Tor writer at that instant used to lose the letter for good"). Delivery retries can
    /// only live on a periodic sender, so the book re-offers itself the way the letter ring does —
    /// receivers refuse a repeat as `Duplicate` and do not re-forward, so the flood still
    /// terminates and no seen-set exists anywhere.
    /// MEASURED: 2026-09-02 gate run 26 step 8 (scratch musd-ecocheck-riraYT): W1's ask rested on
    /// n1 (level 0, nullifier b52f5f09…) and n2's book served 0 orders for the full 150s budget —
    /// the one-shot OrderPost never arrived, and `verify_order_maker_half` is a pure function of
    /// the carried bytes so arrival IS acceptance. -> with the re-flood tick the order re-queues
    /// every pass until the peer's book holds it (asserted by the gate's step-8 cross-node read).
    /// MUST-STAY-GREEN: the order-book suite (post/dedup/expiry unchanged), the gossip flood
    /// terminating at the second hop, letter re-flood cadence.
    /// cons: none new on the wire — the paced lane is constant-rate by construction (real cells
    /// displace cover), and the page is a fixed `n` over a book already bounded by BOOK_CAPACITY.
    pub fn reflood_page(&self, cursor: usize, n: usize) -> (Vec<Vec<u8>>, usize) {
        if self.orders.is_empty() {
            return (Vec::new(), 0);
        }
        let len = self.orders.len();
        let start = cursor % len;
        let mut out = Vec::new();
        for i in 0..n.min(len) {
            let o = &self.orders[(start + i) % len];
            if let Ok(b) = postcard::to_stdvec(&OrderWire::of(o)) {
                out.push(b);
            }
        }
        (out, (start + n.min(len)) % len)
    }

    /// Offer an order to the book at `now_height`.
    ///
    /// ⛔ THE PROOF IS CHECKED HERE, NOT ONLY AT FILL. A book that accepted unverified offers would serve
    /// forgeries to every taker who read it: each builds a fill, pays the proving cost, submits, and is
    /// refused at the node — a free denial-of-service on every taker, and a book whose contents mean
    /// nothing. Verifying at post makes an entry's presence a statement the node stands behind.
    pub fn post(&mut self, order: RestingOrder, now_height: u64) -> Result<u32, PostRefusal> {
        // DEX-GRID: off-grid terms are outside the protocol's shape; they would fingerprint their maker.
        if order.terms.lot == 0
            || order.terms.pay_b == 0
            || order.terms.asset_a == order.terms.asset_b
            || !on_grid(&order.terms)
        {
            return Err(PostRefusal::MalformedTerms);
        }
        if now_height > order.terms.expires_at_height {
            return Err(PostRefusal::AlreadyExpired);
        }
        if order.payout_clue.is_empty() || order.payout_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return Err(PostRefusal::MissingPayoutOwner);
        }
        // ⛔ DB-401 — THE MAKER'S MEMBERSHIP BIND, bounded and present, at the ONE door all three admission lanes share
        // (`/post_order`, the gossip arm, the block-carried `Class::OrderPost`). The route door required it; the other two
        // ran only this function, so an order with no bind rested there and every taker who read it built a fill the fill
        // door refuses (DB-150) — the denial-of-service-on-takers class the maker-half verify below exists to prevent.
        // Bounded by the fill object's own caps: the book now STORES these bytes for every order it holds.
        // §9.6 (this door's admission changed): (1) PoW — none here; a block-carried post rides its block's checked grind,
        // a pooled one its stamp. (2) Proof — the maker half verifies below; the bind is shape-checked here and VERIFIED at
        // the fill door (`check_bond_membership`, Admit and Fold), the only place it can move value. (3) Conservation —
        // the book moves nothing. (4) Replay — `Duplicate` by nullifier (this book) and `MakerSpent` (`Node::post_order`).
        // (5) Bounded work — carrier ≤ ORDER_FILL_MEMBERSHIP_CARRIER_MAX, tip exactly the one-step width, ≤ LEVEL_SLOTS per
        // (pair, level). (6) Parity — `/post_order`'s parse demands a non-empty carrier and a one-step tip; this door now
        // runs that check (plus the upper bound the route left to its body limit) for the gossip and block lanes too.
        if order.membership_carrier.is_empty()
            || order.membership_carrier.len() > crate::order_fill_tx::ORDER_FILL_MEMBERSHIP_CARRIER_MAX
            || !crate::member_transition::membership_endpoint_len_ok(order.membership_tip.len())
        {
            return Err(PostRefusal::MissingMembershipBind);
        }
        // The resting NULLIFIER identifies the order: one note is one offer, and a re-post of an
        // identical order is the same offer rather than a second one. Checked before the proof so a
        // duplicate costs no verification.
        if self
            .orders
            .iter()
            .any(|o| o.maker.nullifier == order.maker.nullifier)
        {
            return Err(PostRefusal::Duplicate);
        }
        let level = order.level();
        let pair = order.pair();
        let mut at_level = 0usize;
        for o in &self.orders {
            if o.pair() == pair && o.level() == level {
                at_level += 1;
            }
        }
        if at_level >= LEVEL_SLOTS {
            return Err(PostRefusal::LevelFull);
        }
        // ⛔⛔⛔ THE PAYOUT NOTE MUST CARRY THE COMMITMENT THE MAKER PROVED.
        //
        // Only the maker can produce these bytes — they sealed the note to their own one-time key at post
        // time — so the book must publish them or no taker can ever build a fill. But publishing them is
        // not enough: bytes that do not open to `maker.payout_cm` make the order UNFILLABLE, because the
        // settlement gate binds the credited note to that commitment. Every taker who read such an order
        // would build a fill, pay the proving cost, submit, and be refused. Checked BEFORE the maker-half
        // verify because it is a 32-byte compare against a WHIR verification.
        //
        // ONE CONVERSION, THE CANONICAL ONE: `leaf_to_cm_bytes`, the same function the settlement gate
        // uses, so the book and the chain agree on what "this note carries that commitment" means. Two
        // spellings would let an order pass here and fail there, which is the seam this closes.
        //
        // A note too SHORT to carry a commitment is refused, never skipped — that is the shape a length
        // check waves through and an unfillable order rides in on.
        if order.payout_note.len() < 32
            || order.payout_note[..32]
                != crate::spend_frontier::leaf_to_cm_bytes(order.maker.payout_cm)
        {
            return Err(PostRefusal::PayoutNoteMismatch);
        }
        if !verify_order_maker_half(&order.maker_bytes, &order.terms, &order.maker) {
            return Err(PostRefusal::ProofRefused);
        }
        self.orders.push(order);
        Ok(level)
    }

    /// Drop every order whose own expiry has passed, and return how many left.
    ///
    /// Expiry is the maker's OWN term, so this refuses nobody's reach — it retires offers their authors
    /// already declared finished. It is what keeps the book bounded without capping anything a
    /// participant cares about, and what makes two nodes converge on the same contents from the same
    /// height instead of drifting apart by arrival order.
    pub fn expire(&mut self, now_height: u64) -> usize {
        let before = self.orders.len();
        self.orders
            .retain(|o| now_height <= o.terms.expires_at_height);
        before.saturating_sub(self.orders.len())
    }

    /// Retire one order by its resting nullifier — what a FILL and a CANCEL both do. A cancel is the
    /// maker self-spending the note, which burns the same nullifier, so both use this one door.
    /// ⭐ DB-273 §19.6 L3 — the payout owner the MAKER posted for the order resting on `nullifier`: what the fill door
    /// copies into a settlement's slot 0. `None` when this book holds no such order (the door then refuses the fill here
    /// rather than take the maker's owner from anyone else).
    /// CHAIN-OBJECT: `Class::OrderPost` — the maker's own order object carries the clue, and the book is filled from it;
    /// the door only COPIES it into the `Class::OrderFill` object, which every node applies from its own bytes. No node
    /// decides anything from this read: a door without the order refuses the submission, and the chain carries the copy.
    #[must_use]
    pub fn payout_clue_of(&self, nullifier: crate::spend_frontier::Digest4) -> Option<Vec<u8>> {
        self.orders.iter().find(|o| o.maker.nullifier == nullifier).map(|o| o.payout_clue.clone())
    }

    /// Does an order rest under this maker nullifier? A read: the cheap question a producer asks before it pays to judge a block.
    #[must_use]
    pub fn holds_nullifier(&self, nullifier: crate::spend_frontier::Digest4) -> bool {
        self.orders.iter().any(|o| o.maker.nullifier == nullifier)
    }

    pub fn remove_by_nullifier(&mut self, nullifier: crate::spend_frontier::Digest4) -> bool {
        let before = self.orders.len();
        self.orders.retain(|o| o.maker.nullifier != nullifier);
        self.orders.len() != before
    }

    /// What one (pair, level) SERVES: its real orders, and the number of slots left empty.
    ///
    /// ⚠️ WHAT THE CONSTANT SHAPE HIDES AND WHAT IT DOES NOT — stated plainly, because an overstated
    /// privacy claim is worse than none:
    ///   * HIDDEN from anyone reading the book's SHAPE: how many orders actually rest here. Every level
    ///     answers with the same number of slots, so polling reveals neither depth nor activity — a level
    ///     that gained three orders looks exactly like one that gained none.
    ///   * NOT HIDDEN from a caller who reads the ENTRIES: a real order is a verifiable maker half and an
    ///     empty slot is not, so a fetcher can count what is fillable. That is inherent to a book being
    ///     fillable — a taker must see what they can trade against — and it matches the design's own
    ///     boundary: the only party who learns a maker's trade is the counterparty who takes it. It is
    ///     NOT closed by stuffing empty slots with fakes: a forged maker half fails verification (so it
    ///     is distinguishable anyway), and a real-but-unfillable one would burn a taker's fill attempt
    ///     for nothing — buying no privacy and costing liveness.
    pub fn level(&self, pair: PairKey, level: u32) -> (Vec<RestingOrder>, usize) {
        let mut real: Vec<RestingOrder> = Vec::new();
        for o in &self.orders {
            if real.len() >= LEVEL_SLOTS {
                break;
            }
            if o.pair() == pair && o.level() == level {
                real.push(o.clone());
            }
        }
        let empty = LEVEL_SLOTS.saturating_sub(real.len());
        (real, empty)
    }

    /// Total resting orders — a node-local health figure, never served (it is exactly the depth the
    /// constant slot shape exists to withhold).
    /// ⛔ SELF-PROOF ONLY — a book entry that no block accounts for.
    ///
    /// Exists for ONE purpose: to build the violating state that makes the order-book half of
    /// `I-CP STATE-NOT-DERIVABLE-FROM-THE-CHAIN` fire, so that branch is proven reachable rather than
    /// assumed. It bypasses `post`'s validation deliberately — a VALID order is not the violation; an
    /// order the chain never carried is. That is the 2026-09-03 shape: a maker's lot alive on one node
    /// and retired on another, paying out twice while both nodes self-verify correctly.
    ///
    /// Nothing but the refutation lane may call it, and the name says so at every call site.
    #[cfg(test)]
    pub fn insert_selfproof_entry(&mut self, order: RestingOrder) {
        self.orders.push(order);
    }

    /// ⛔ AUDIT ONLY — WHICH LOTS ARE STILL LIVE, as a deterministic sorted census.
    ///
    /// [`Self::len`] answers HOW MANY and that is what `Sim::cold_peer_verdict` compares today
    /// (`order_book_len_for_audit`). A count cannot see two nodes each holding ONE order that is a
    /// DIFFERENT one — and the 2026-09-03 double payout is exactly an identity question: a maker's lot
    /// retired on the node that saw the fill and still live everywhere else. The resting nullifier IS
    /// that identity (one note is one offer), so the census is the nullifiers and nothing more: no
    /// terms, no proof bytes, no payout note. Sorted, so arrival order can never make two books
    /// holding the same offers look different.
    ///
    /// Read by `harness::fuzz::authority_book`, which is where the comparison and its refutation live.
    #[cfg(test)]
    pub fn resting_census_for_audit(&self) -> Vec<crate::spend_frontier::Digest4> {
        let mut v: Vec<crate::spend_frontier::Digest4> = self.orders.iter().map(|o| o.maker.nullifier).collect();
        v.sort_unstable();
        v
    }

    pub fn len(&self) -> usize {
        self.orders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }
}

/// DB-273 §19.6 L3 — a fixture's maker payout owner: a real `omr::Clue`-width value, so a test order rests on the book
/// (which refuses an empty clue) without every fixture restating the width.
#[cfg(test)]
#[must_use]
pub fn test_payout_clue() -> Vec<u8> {
    vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]
}

/// DB-401 — a book-only fixture's maker membership bind `(carrier, tip)`: shaped so the book door takes it (a non-empty
/// carrier, a one-step-width tip). It proves nothing, so a fill that needs it verified builds a real one
/// (`dex_cross_party_scenarios::trade_binds`).
#[cfg(test)]
#[must_use]
pub fn test_membership_bind() -> (Vec<u8>, Vec<u8>) {
    (vec![0xc3; 64], vec![0x3c; crate::order_fill_tx::ORDER_FILL_MEMBERSHIP_TIP_MAX])
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use usdm_decider::whir_rec_block::{
        prove_order_maker_half, wrapped_asset_tag_u32, MakerHalfWitness, USDM_ASSET_TAG,
    };

    const EXPIRES: u64 = 10_000;

    /// ⭐ DEX-GRID (spec §5 pins 1–3 at the post door, and pin 5) — RED against the pre-grid book, which admitted any
    /// non-zero lot and price at any expiry. A REAL maker half proved over off-grid terms is refused as
    /// `MalformedTerms` before its proof is verified. And the snap's rounding never costs more than the genesis fee:
    /// `(v − snap(v)) / v < 2^-(GRID_MANTISSA_BITS − 1)` ≤ 10 bps.
    /// TWO-PARTY-REVIEWED: this is one book's admission rule; the cross-node half is the settlement pin in
    /// `dex_cross_party_scenarios` (the engine every node's graft door runs refuses the same off-grid terms).
    #[test]
    fn dex_grid_the_post_door_refuses_off_grid_terms_and_the_snap_costs_at_most_the_fee() {
        let rest = |t: OrderTerms| {
            let (bytes, maker) = prove_order_maker_half(
                &MakerHalfWitness {
                    owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[9_100, 9_101, 9_102, 9_103])),
                    payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_110, 9_111, 9_112, 9_113]),
                    lc_blind: crate::spend_frontier::TEST_LC_BLIND,
                },
                &t,
            )
            .expect("a maker half proves over any terms — the grid is the door's rule, not the proof's");
            let mut payout_note = vec![0u8; 1153];
            payout_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));
            RestingOrder {
                terms: t,
                maker,
                maker_bytes: bytes,
                payout_note,
                membership_carrier: crate::order_book::test_membership_bind().0,
                membership_tip: crate::order_book::test_membership_bind().1,
                payout_clue: test_payout_clue(),
            }
        };
        let on = terms_at(250_000, EXPIRES);
        assert!(on_grid(&on), "PRECONDITION: the snapped fixture is on the grid");
        assert!(OrderBook::new().post(rest(on), 1).is_ok(), "CALIBRATION: the snapped order rests");
        for (what, t) in [
            ("price", OrderTerms { pay_b: on.pay_b + 1, ..on }),
            ("lot", OrderTerms { lot: on.lot + 1, ..on }),
            ("expiry", OrderTerms { expires_at_height: on.expires_at_height + 1, ..on }),
        ] {
            assert!(!on_grid(&t), "CALIBRATION: the {what} nudge is off the grid");
            assert_eq!(
                OrderBook::new().post(rest(t), 1),
                Err(PostRefusal::MalformedTerms),
                "⛔ DEX-GRID: an off-grid {what} rested — its distinctive term fingerprints the maker"
            );
        }
        // Pin 5: the rounding bound, over a spread of magnitudes.
        let bound = 1.0 / f64::from(1u32 << (GRID_MANTISSA_BITS - 1));
        for v in [1u64, 999, 2_047, 2_049, 250_000, 6_500_000, 100_000_000, u64::MAX / 3, u64::MAX] {
            let s = snap_to_grid(v);
            assert!(on_grid_value(s) && s <= v, "snap({v}) = {s} is on the grid and never rounds up");
            assert!(((v - s) as f64) / (v as f64) < bound, "snap({v}) costs more than one grid step");
        }
        assert!(bound <= crate::params::ORDER_FILL_FEE_BPS_DEFAULT as f64 / 10_000.0, "one grid step ≤ the genesis fee");
    }

    fn terms_at(pay_b: u64, expires: u64) -> OrderTerms {
        // DEX-GRID (C3): every fixture snaps through the ONE helper, so no test hand-picks an on-grid-looking value.
        OrderTerms {
            lot: snap_to_grid(100_000),
            pay_b: snap_to_grid(pay_b),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: snap_expiry(expires),
        }
    }

    /// A REAL resting order, proved by a real maker half — never a hand-rolled entry, because holding
    /// offers that verify is the book's whole job.
    fn order(seed: u64, pay_b: u64, expires: u64) -> RestingOrder {
        let t = terms_at(pay_b, expires);
        let (bytes, maker) = prove_order_maker_half(
            &MakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[seed, seed + 1, seed + 2, seed + 3])),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[seed + 10, seed + 11, seed + 12, seed + 13]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            &t,
        )
        .expect("maker half proves");
        // The payout note as a MAKER really builds it: its commitment first, then the sealed ciphertext.
        // An all-zero note here would model something no honest maker can produce, and every test posting
        // through this helper would be proving that unfillable orders rest happily.
        let mut payout_note = vec![0u8; 1153];
        payout_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));
        RestingOrder { terms: t, maker, maker_bytes: bytes, payout_note , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() }
    }

    #[test]
    fn an_order_rests_at_the_level_its_own_price_puts_it_on() {
        let mut b = OrderBook::new();
        let cheap = order(100, 150_000, EXPIRES);
        let dear = order(200, 6_400_000, EXPIRES);
        let lc = b.post(cheap.clone(), 1).expect("cheap order rests");
        let ld = b.post(dear.clone(), 1).expect("dear order rests");
        assert_ne!(lc, ld, "different prices must land on different grid levels");
        assert_eq!(lc, cheap.level(), "the level is DERIVED from the terms, never declared");
        assert!(ld > lc, "a higher price sits higher on the grid");
    }

    /// ⛔ A FORGED OFFER MUST NEVER REACH A TAKER. If the book served unverified entries, every taker who
    /// read one would build a fill, pay the proving cost and be refused at the node — a free
    /// denial-of-service on takers, and a book whose contents mean nothing.
    #[test]
    fn a_forged_or_mismatched_maker_half_is_refused_a_place() {
        let mut b = OrderBook::new();
        let good = order(300, 200_000, EXPIRES);

        let mut corrupt = good.clone();
        corrupt.maker_bytes[0] ^= 0xFF;
        assert_eq!(b.post(corrupt, 1), Err(PostRefusal::ProofRefused));

        let mut empty = good.clone();
        empty.maker_bytes = Vec::new();
        assert_eq!(b.post(empty, 1), Err(PostRefusal::ProofRefused));

        // A real proof against terms it was never proved for — a maker claiming a better price than the
        // one they committed to.
        // DECLARED AMENDMENT (DEX-GRID): the better price is DOUBLED, not +1. Doubling keeps it on the grid (the
        // mantissa is unchanged), so this still exercises the PROOF refusal rather than the grid check that now
        // precedes it.
        let mut better_price = good.clone();
        better_price.terms.pay_b *= 2;
        assert!(on_grid(&better_price.terms), "CALIBRATION: the claimed price is on the grid");
        assert_eq!(b.post(better_price, 1), Err(PostRefusal::ProofRefused));

        let mut forged = good.clone();
        forged.maker.nullifier = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        assert_eq!(b.post(forged, 1), Err(PostRefusal::ProofRefused));

        assert!(b.is_empty(), "not one forgery reached the book");
        assert!(b.post(good, 1).is_ok(), "and the honest order still rests");
    }

    #[test]
    fn malformed_terms_and_already_expired_orders_are_refused() {
        let mut b = OrderBook::new();
        let o = order(400, 200_000, EXPIRES);

        let mut zero_lot = o.clone();
        zero_lot.terms.lot = 0;
        assert_eq!(b.post(zero_lot, 1), Err(PostRefusal::MalformedTerms));

        let mut zero_pay = o.clone();
        zero_pay.terms.pay_b = 0;
        assert_eq!(b.post(zero_pay, 1), Err(PostRefusal::MalformedTerms));

        let mut self_pair = o.clone();
        self_pair.terms.asset_b = self_pair.terms.asset_a;
        assert_eq!(b.post(self_pair, 1), Err(PostRefusal::MalformedTerms));

        // DECLARED AMENDMENT (DEX-GRID): one height past the order's OWN (epoch-snapped) expiry, not the fixture literal.
        let past = o.terms.expires_at_height + 1;
        assert_eq!(
            b.post(o, past),
            Err(PostRefusal::AlreadyExpired),
            "an order that could never be filled must not occupy a slot"
        );
        assert!(b.is_empty());
    }

    /// ⛔⛔⛔ AN UNFILLABLE ORDER MUST NOT REST. The settlement gate binds the credited note to
    /// `maker.payout_cm`, so a payout note carrying anything else makes the order impossible to fill —
    /// every taker who read it would build a fill, pay the proving cost, submit, and be refused. Refusing
    /// at POST is what turns that from a tax on every taker into one refusal for the maker who caused it.
    ///
    /// MEASURED 2026-08-31: the book gained the payout-note FIELD without this gate, and the test helper
    /// posted an all-zero note — so the suite was demonstrating that unfillable orders rest happily.
    #[test]
    fn a_payout_note_that_does_not_carry_its_proven_commitment_is_refused_a_place() {
        let mut b = OrderBook::new();
        let good = order(1_400, 200_000, EXPIRES);

        // A note that carries somebody else's commitment.
        let mut stranger = good.clone();
        stranger.payout_note = vec![0u8; 1153];
        stranger.payout_note[..32].copy_from_slice(&[0x5Cu8; 32]);
        assert_eq!(
            b.post(stranger, 1),
            Err(PostRefusal::PayoutNoteMismatch),
            "a payout note the maker's own half never proved must not rest"
        );

        // The all-zero note the helper used to build — no honest maker can produce it.
        let mut zeroed = good.clone();
        zeroed.payout_note = vec![0u8; 1153];
        assert_eq!(b.post(zeroed, 1), Err(PostRefusal::PayoutNoteMismatch));

        // A note too SHORT to carry a commitment is refused, never waved through.
        let mut short = good.clone();
        short.payout_note = vec![0u8; 31];
        assert_eq!(b.post(short, 1), Err(PostRefusal::PayoutNoteMismatch));

        let mut empty = good.clone();
        empty.payout_note = Vec::new();
        assert_eq!(b.post(empty, 1), Err(PostRefusal::PayoutNoteMismatch));

        // ONE FLIPPED BIT is still a different note — the comparison is exact, not a prefix.
        let mut flipped = good.clone();
        flipped.payout_note[31] ^= 0x01;
        assert_eq!(b.post(flipped, 1), Err(PostRefusal::PayoutNoteMismatch));

        assert!(b.is_empty(), "not one unfillable order reached the book");
        assert!(b.post(good, 1).is_ok(), "and the honest order — whose note DOES carry it — still rests");
    }

    #[test]
    fn the_same_resting_note_cannot_be_offered_twice() {
        let mut b = OrderBook::new();
        let o = order(500, 200_000, EXPIRES);
        assert!(b.post(o.clone(), 1).is_ok());
        assert_eq!(
            b.post(o, 1),
            Err(PostRefusal::Duplicate),
            "one note is one offer — a re-post is the same order, not a second one"
        );
        assert_eq!(b.len(), 1);
    }

    /// ⛔ EXPIRY KEEPS THE BOOK BOUNDED WITHOUT CAPPING ANYONE'S REACH — it retires offers their own
    /// authors declared finished, and must leave everything still live untouched.
    #[test]
    fn expiry_drops_exactly_the_finished_orders_and_keeps_the_live_ones() {
        let mut b = OrderBook::new();
        let short = order(600, 200_000, 100);
        let long = order(700, 200_000, 9_000);
        // DECLARED AMENDMENT (DEX-GRID): heights derive from each order's OWN epoch-snapped expiry, not the literals.
        let (se, le) = (short.terms.expires_at_height, long.terms.expires_at_height);
        assert!(se < le, "PRECONDITION: the short order finishes first");
        b.post(short, 1).expect("short rests");
        b.post(long.clone(), 1).expect("long rests");
        assert_eq!(b.len(), 2);

        assert_eq!(b.expire(se), 0, "AT its expiry an order is still live");
        assert_eq!(b.len(), 2);

        assert_eq!(b.expire(se + 1), 1, "one height past, exactly the finished one leaves");
        let (served, _) = b.level(long.pair(), long.level());
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].maker.nullifier, long.maker.nullifier, "the LIVE order survived");

        assert_eq!(b.expire(le + 1), 1, "and the long one goes when its own term passes");
        assert!(b.is_empty());
    }

    /// A fill and a cancel retire an order through ONE door — the resting nullifier — because a cancel IS
    /// the maker self-spending that note.
    #[test]
    fn removing_by_nullifier_retires_exactly_one_order() {
        let mut b = OrderBook::new();
        let a = order(800, 200_000, EXPIRES);
        let c = order(900, 200_000, EXPIRES);
        b.post(a.clone(), 1).expect("a rests");
        b.post(c.clone(), 1).expect("c rests");

        assert!(b.remove_by_nullifier(a.maker.nullifier));
        assert_eq!(b.len(), 1);
        assert!(!b.remove_by_nullifier(a.maker.nullifier), "removing twice is a no-op");
        assert!(b.remove_by_nullifier(c.maker.nullifier));
        assert!(b.is_empty());
    }

    /// ⛔ EVERY LEVEL ANSWERS WITH THE SAME SHAPE. Polling the book must reveal neither depth nor
    /// activity: a level holding one order and a level nobody ever touched serve the same slot total.
    #[test]
    fn every_level_serves_a_constant_number_of_slots() {
        let mut b = OrderBook::new();
        let o = order(1_000, 200_000, EXPIRES);
        let pair = o.pair();
        let lvl = o.level();

        let (er, ep) = b.level(pair, lvl);
        assert_eq!(er.len() + ep, LEVEL_SLOTS, "an untouched level serves the full shape");

        b.post(o, 1).expect("rests");
        let (r1, p1) = b.level(pair, lvl);
        assert_eq!(
            r1.len() + p1,
            LEVEL_SLOTS,
            "a level with an order serves the SAME total shape as an empty one"
        );
        assert_eq!(r1.len(), 1);

        let (r2, p2) = b.level(pair, lvl + 1);
        assert_eq!(r2.len() + p2, LEVEL_SLOTS, "and so does a level nobody has touched");
    }

    /// Both sides of one market must share ONE book — otherwise a bid and an ask on the same pair never
    /// see each other and nothing ever trades.
    #[test]
    fn a_pair_is_orientation_free_so_both_sides_share_one_book() {
        let a = wrapped_asset_tag_u32(1);
        let u = USDM_ASSET_TAG;
        assert_eq!(
            PairKey::of(a, u),
            PairKey::of(u, a),
            "give-wBTC-for-USDm and give-USDm-for-wBTC are the same market"
        );
        assert_ne!(
            PairKey::of(a, u),
            PairKey::of(wrapped_asset_tag_u32(2), u),
            "different pairs are different books"
        );
    }

    /// ⛔⛔⛔ AN ORDER MUST CROSS THE NODE BOUNDARY, OR THERE IS NO EXCHANGE.
    ///
    /// MEASURED 2026-08-31 by audit, and it was MY OWN GAP: `/post_order` put an order into the receiving
    /// node's book and NOTHING propagated it. A maker posting to node A was invisible to a taker on node
    /// B, so a trade could only happen if both parties had picked the SAME node — which is not an
    /// exchange, and it breaks decentralization outright.
    ///
    /// ⚠️ AND MY OWN P2 TEST COULD NOT SEE IT: `two_independent_books_..._expire_together` feeds BOTH
    /// books the same orders by hand. That proves they CONVERGE given the same inputs; it assumes a
    /// delivery mechanism that did not exist. This test asserts the delivery itself — the peer's book is
    /// fed ONLY by the wire form, exactly as the gossip arm feeds it.
    #[test]
    fn an_order_gossiped_from_one_node_rests_and_verifies_on_another() {
        let mut maker_node = OrderBook::new();
        let mut taker_node = OrderBook::new();
        let o = order(5_000, 200_000, EXPIRES);
        maker_node.post(o.clone(), 1).expect("rests where it was posted");

        // THE WIRE IS THE ONLY CHANNEL. The peer never sees the original struct — it gets the bytes and
        // rebuilds, which is what makes this a delivery test rather than a second hand-fed book.
        let bytes = postcard::to_stdvec(&OrderWire::of(&o)).expect("order encodes");
        let rebuilt = postcard::from_bytes::<OrderWire>(&bytes)
            .expect("a peer decodes the wire form")
            .into_order();
        assert_eq!(rebuilt, o, "the wire form round-trips an order byte-for-byte");

        // The peer runs the SAME gate — nothing is trusted because it arrived over the wire.
        taker_node.post(rebuilt, 1).expect("the gossiped order rests on the peer");

        let (served, _) = taker_node.level(o.pair(), o.level());
        assert_eq!(served.len(), 1, "a taker on the OTHER node can see the offer");
        assert_eq!(
            served[0].maker.nullifier, o.maker.nullifier,
            "and it is the same offer, not a lookalike"
        );
        assert!(
            !served[0].payout_note.is_empty(),
            "the gossiped order carries the payout note — without it the taker cannot build a fill and \
             the offer is unfillable on every node but the one it was posted to"
        );

        // ⛔ FLOOD CONTROL WITH NO NEW STATE: the second copy is refused, so a re-broadcast loop dies at
        // its second hop. This is why the gossip arm needs no seen-set (which would be a growth axis).
        let again = postcard::from_bytes::<OrderWire>(&bytes)
            .expect("decodes")
            .into_order();
        assert_eq!(
            taker_node.post(again, 1),
            Err(PostRefusal::Duplicate),
            "a re-delivered order must be refused — that refusal IS the flood control"
        );

        // ⛔ AND A FORGERY DOES NOT PROPAGATE: the peer's gate refuses it exactly as a local post would,
        // so a malicious peer cannot inject an unfillable or fake offer into anyone else's book.
        let mut forged = OrderWire::of(&o);
        forged.maker_bytes[0] ^= 0xFF;
        forged.nullifier = usdm_decider::poseidon2_compress::lanes_of(&[7, 7, 7, 7]); // a different note, so it is not caught as a duplicate
        assert_eq!(
            taker_node.post(forged.into_order(), 1),
            Err(PostRefusal::ProofRefused),
            "a forged order arriving over gossip must be refused by the receiving node's own gate"
        );
    }

    /// ⭐⭐⭐ TWO NODES, ONE BOOK — the P2 exit criterion. Two independent books fed the SAME orders serve
    /// identical contents, and the same expiry height retires the same order on both with no coordination
    /// between them. This is what a taker depends on: whichever node you ask, the offer you can fill is
    /// there. Gossip arrives in OPPOSITE order on the two nodes, because a real mesh has no shared
    /// arrival order and a book that depended on one would diverge.
    #[test]
    fn two_independent_books_fed_the_same_orders_serve_the_same_contents_and_expire_together() {
        let mut node_a = OrderBook::new();
        let mut node_b = OrderBook::new();
        let live = order(3_000, 200_000, 9_000);
        let doomed = order(3_100, 200_000, 100);

        node_a.post(live.clone(), 1).expect("a: live");
        node_a.post(doomed.clone(), 1).expect("a: doomed");
        node_b.post(doomed.clone(), 1).expect("b: doomed");
        node_b.post(live.clone(), 1).expect("b: live");

        let pair = live.pair();
        let lvl = live.level();
        let (mut ra, pa) = node_a.level(pair, lvl);
        let (mut rb, pb) = node_b.level(pair, lvl);
        assert_eq!(pa, pb, "both nodes serve the same slot shape");
        ra.sort_unstable_by_key(|o| o.maker.nullifier);
        rb.sort_unstable_by_key(|o| o.maker.nullifier);
        assert_eq!(ra, rb, "two nodes fed the same orders serve the SAME book");

        // DECLARED AMENDMENT (DEX-GRID): one height past the doomed order's OWN epoch-snapped expiry.
        let past = doomed.terms.expires_at_height + 1;
        assert!(past <= live.terms.expires_at_height, "PRECONDITION: the live order is still live then");
        assert_eq!(node_a.expire(past), 1);
        assert_eq!(node_b.expire(past), 1);
        let (mut ra2, _) = node_a.level(pair, lvl);
        let (mut rb2, _) = node_b.level(pair, lvl);
        ra2.sort_unstable_by_key(|o| o.maker.nullifier);
        rb2.sort_unstable_by_key(|o| o.maker.nullifier);
        assert_eq!(ra2, rb2, "an expired order is gone from BOTH books");
        assert_eq!(ra2.len(), 1);
        assert_eq!(ra2[0].maker.nullifier, live.maker.nullifier);
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod book_produces_a_submittable_fill_tests {
    //! ⛔⛔⛔ THE SEAM NEITHER SIDE'S SUITE COULD SEE. The node's settlement tests build their own
    //! maker/taker halves; the wallet's tests build theirs. Both were green while the BOOK served a
    //! `payout_cm` and not the note bytes behind it, so a real taker reading a real book had a
    //! commitment they could not turn into a note and every honest fill was refused. This test crosses
    //! the seam on purpose: it posts through the book, reads back ONLY what the book serves, and settles
    //! from that alone.

    use super::*;
    use usdm_decider::whir_rec_block::{
        asset_note_cm, prove_order_maker_half, wrapped_asset_tag_u32, MakerHalfWitness, OrderTerms,
    };

    fn terms() -> OrderTerms {
        OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000),
            pay_b: crate::order_book::snap_to_grid(6_500_000),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        }
    }

    /// ⭐⭐⭐ WHAT THE BOOK SERVES IS ENOUGH TO SETTLE. A taker who has ONLY the book entry can produce
    /// the payload the settlement gate demands — that is the definition of a working feed.
    #[test]
    fn what_the_book_serves_is_enough_to_build_the_payload_settlement_demands() {
        let t = terms();
        let payout_sk = usdm_decider::poseidon2_compress::lanes_of(&[10, 11, 12, 13]);
        let w = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: payout_sk, lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let (bytes, maker) = prove_order_maker_half(&w, &t).expect("maker half proves");

        // The maker seals their OWN payout note and posts it with the order.
        let payout_cm = asset_note_cm(t.pay_b, t.asset_b, payout_sk);
        assert_eq!(payout_cm, maker.payout_cm, "the note the maker built IS the one they proved");
        let mut payout_note = vec![0u8; 1153];
        payout_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(payout_cm));

        let mut book = OrderBook::new();
        let order = RestingOrder { terms: t, maker, maker_bytes: bytes, payout_note: payout_note.clone() , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };
        let level = order.level();
        book.post(order, 1).expect("the order rests");

        // A TAKER NOW READS THE BOOK AND HAS NOTHING ELSE.
        let (served, _empty) = book.level(PairKey::of(t.asset_a, t.asset_b), level);
        assert_eq!(served.len(), 1, "the order is served at its own level");
        let entry = &served[0];

        // ⛔ THE PROPERTY THAT WAS BROKEN: the served bytes must satisfy the settlement gate's binding,
        // `payload[..32] == leaf_to_cm_bytes(payout_cm)`. Serving only the commitment made this
        // unsatisfiable for anyone but the maker.
        assert!(!entry.payout_note.is_empty(), "the book carries the note, not just its commitment");
        assert_eq!(
            entry.payout_note[..32],
            crate::spend_frontier::leaf_to_cm_bytes(entry.maker.payout_cm)[..],
            "what the book serves opens to what the book proved — a taker can settle from this alone"
        );
    }

    /// ⛔ AN ORDER WHOSE NOTE DOES NOT MATCH ITS OWN COMMITMENT IS A TRAP FOR THE TAKER — it looks
    /// fillable in the book and is refused at settlement. Catching the mismatch is what makes the book's
    /// offers trustworthy.
    #[test]
    fn a_note_that_does_not_open_to_its_own_commitment_is_detectable_in_the_book() {
        let t = terms();
        let w = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[10, 11, 12, 13]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let (bytes, maker) = prove_order_maker_half(&w, &t).unwrap();
        let mut wrong = vec![0u8; 1153];
        wrong[..32].copy_from_slice(&[0xAB; 32]); // not the payout commitment

        let entry = RestingOrder { terms: t, maker, maker_bytes: bytes, payout_note: wrong , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };
        assert_ne!(
            entry.payout_note[..32],
            crate::spend_frontier::leaf_to_cm_bytes(entry.maker.payout_cm)[..],
            "a mismatched note is visibly wrong from the book entry alone, before any taker spends effort"
        );
    }
}

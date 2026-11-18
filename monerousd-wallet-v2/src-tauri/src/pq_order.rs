// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE WALLET'S SIDE OF THE ORDER BOOK — resting an order, and filling someone else's.**
//!
//! IonSwap has no pool. A pool is shared mutable secret state, and every pillar it broke traced to that
//! one property: held privately it is a censor, published it discloses every reserve and trade size, and
//! either way every trade of a pair serialises through one cell — a throughput ceiling on a chain whose
//! GHOSTDAG width exists for parallelism. Instead a MAKER rests an order over ONE OF THEIR OWN NOTES and
//! goes offline; a TAKER fills it. Fills touch disjoint state, so they settle in parallel exactly like
//! ordinary sends.
//!
//! ⛔⛔⛔ THE MAKER'S SPEND KEY NEVER LEAVES THIS MACHINE. The order is proven in TWO HALVES precisely so
//! that it cannot: a single proof built by the taker would need the maker's `sk` in the taker's witness,
//! so a resting order would have to PUBLISH it — and anyone reading the book could then spend the
//! maker's note through the ORDINARY spend path, never touching the order gate at all. The maker proves
//! their half once, here, at post time.
//!
//! ⭐⭐⭐ THE MAKER PRE-BUILDS THEIR OWN PAYOUT NOTE, AND THAT IS WHAT MAKES OFFLINE FILLING SOUND. The
//! taker cannot prove what the maker's payout note contains — they do not hold its key. If nobody proved
//! it, a maker could publish a payout commitment opening to ZERO and a taker's conservation would then
//! let them pay nothing and still take a lot: value from nothing. So the maker seals the payout note to
//! their OWN one-time key here and proves its opening in their half; the taker records those bytes
//! verbatim and never has to trust them.
//!
//! ⭐ FIXED LOT × FIXED PRICE LATTICE IS WHAT MAKES SIZE STOP BEING INFORMATION. A world-readable book
//! must tell takers an order's size to be fillable, so any-size orders would publish every size. Both
//! grid dimensions are consensus constants: every order at a level trades EXACTLY one lot, so a fill
//! discloses "one lot at level L" — which the tape already said — and nothing about anyone's position.
//! It is the chain's own cash-denomination pattern (one note is one bill) applied to the book.


// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 170 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;

use usdm_decider::whir_rec_block::{
    prove_order_maker_half, prove_order_taker_half, MakerHalfPublic, MakerHalfWitness, OrderTerms,
    TakerHalfPublic, TakerHalfWitness,
};

/// A resting order this wallet posted: everything the book publishes, plus the payout note bytes the
/// filler must record verbatim.
#[derive(Clone, Debug)]
pub struct PostedOrder {
    /// The maker-half proof.
    pub carrier: Vec<u8>,
    /// What the book publishes: the maker's nullifier, membership cross-bind and payout commitment.
    pub public: MakerHalfPublic,
    /// The maker's PRE-BUILT payout note, sealed to a one-time key only this wallet can open. The taker
    /// records these bytes; nobody has to trust them, because the maker's half proves what they contain.
    pub payout_note: Vec<u8>,
    /// The terms, exactly as proven. A book entry that disagrees with these does not verify.
    pub terms: OrderTerms,
    /// DB-363: the blinding this half's cross-bind was proven with — the lot note's membership carrier must be built
    /// with the SAME value (`order_post_body` does), or the node's door reads two proofs about two objects. Redacted
    /// `Debug`; lives only for the post call.
    pub lc_blind: crate::pq_spend::LcBlind,
}

/// A fill this wallet built against someone else's resting order.
#[derive(Clone, Debug)]
pub struct BuiltFill {
    pub carrier: Vec<u8>,
    pub public: TakerHalfPublic,
    /// DB-363: the blinding this half's cross-bind was proven with — the paying note's membership carrier must be
    /// built with the SAME value (the fill loop does). Redacted `Debug`; lives only for the fill call.
    pub lc_blind: crate::pq_spend::LcBlind,
    /// The note paying the maker is the maker's OWN pre-built one — carried through unchanged.
    pub maker_payout_note: Vec<u8>,
    /// This wallet's two new notes: the lot it bought, and its change.
    pub payout_note: Vec<u8>,
    pub change_note: Vec<u8>,
    /// The change note's value — the SAME number sealed into `change_note` and committed as `change_cm`.
    /// DB-273 §14: a zero change takes a throwaway `void` locator, a non-zero one a dense `chg` index, so the
    /// fill door must know which without opening its own note.
    pub change_value: u64,
}

/// Why an order could not be built. Every arm is a REFUSAL with a reason — never a silent no-op, and
/// never a half-built order that looks postable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    /// This wallet cannot cover the price.
    Insufficient,
    /// The terms are not a trade (an asset for itself, a zero lot, or a zero price).
    MalformedTerms,
    /// A note could not be sealed to this wallet's own key.
    SealFailed,
    /// The proof could not be built from an otherwise-valid witness.
    ProveFailed,
    /// DB-363: the OS random source refused the per-object blinding draw. Nothing is built — a half proven under a
    /// blinding from any weaker source would be a linkable commitment.
    BlindingUnavailable,
}

impl OrderError {
    /// What a user should be told. Each says what is true, and none says "try again" — a retry is what
    /// this design removed.
    pub fn reason(self) -> &'static str {
        match self {
            OrderError::Insufficient => "this wallet does not hold enough to pay this order's price",
            OrderError::MalformedTerms => "those terms are not a trade",
            OrderError::SealFailed => "could not seal a note to this wallet's own key",
            OrderError::ProveFailed => "the order proof could not be built",
            OrderError::BlindingUnavailable => "the OS random source refused a blinding draw — nothing was built",
        }
    }
}

/// A trade needs two DIFFERENT assets, nonzero amounts of both, and — DEX-GRID — every public term on the protocol grid
/// (`usdmd_node::order_book::on_grid`, the SAME check the node's post door and settlement engine run), so the wallet
/// never builds an order whose distinctive term would fingerprint its maker or that every node would refuse.
fn terms_are_sane(t: &OrderTerms) -> bool {
    t.asset_a != t.asset_b && t.lot > 0 && t.pay_b > 0 && usdmd_node::order_book::on_grid(t)
}

/// ⭐ REST AN ORDER over a note this wallet already holds.
///
/// `lot_owner` is the OWNER of a note holding EXACTLY `terms.lot` of `terms.asset_a` (DB-395: this wallet's `(ask, nk)`
/// and the note's seed). The caller picks it from the wallet's owned set, which is why this takes the owner rather than
/// searching: note selection belongs where the owned set and its per-asset split live.
///
/// The payout note is sealed to `(my_ek, my_spk)` — this wallet's own scan and spend keys — so the maker finds and
/// spends it later by ordinary scanning, with no new discovery path to get wrong.
pub fn post_order(
    my_ek: &[u8],
    my_spk: &Digest4,
    lot_owner: usdm_decider::whir_rec_block::NoteOwner,
    terms: &OrderTerms,
) -> Result<PostedOrder, OrderError> {
    if !terms_are_sane(terms) {
        return Err(OrderError::MalformedTerms);
    }
    // Seal the payout FIRST: the maker's half proves what this note contains, so it must exist before
    // the proof does. A one-time ML-KEM encapsulation to our own keys yields the note the taker will record and its
    // opening (what the maker's half binds); this wallet spends it later with its `(ask, nk)`.
    let (payout_note, payout_opening) = crate::pq::seal_note_full_asset(my_ek, my_spk, terms.pay_b, terms.asset_b)
        .ok_or(OrderError::SealFailed)?;
    // DB-363: ONE blinding draw where the order is assembled; the half and the lot note's membership carrier share it.
    let lc_blind = usdm_decider::whir_rec_block::fresh_lc_blind().ok_or(OrderError::BlindingUnavailable)?;
    let w = MakerHalfWitness { owner: lot_owner, payout_opening, lc_blind };
    let (carrier, public) = prove_order_maker_half(&w, terms).ok_or(OrderError::ProveFailed)?;
    Ok(PostedOrder {
        carrier,
        public,
        payout_note: payout_note.to_vec(),
        terms: *terms,
        lc_blind: crate::pq_spend::LcBlind(lc_blind),
    })
}

/// ⭐ FILL someone else's resting order.
///
/// `pay_owner`/`pay_value` are a note of `terms.asset_b` this wallet holds (DB-395: its owner); `maker_payout_note` is
/// the maker's own pre-built note, carried through untouched. Both of this wallet's new notes are sealed to
/// `(my_ek, my_spk)`, so they are found by ordinary scanning like any other receive.
pub fn fill_order(
    my_ek: &[u8],
    my_spk: &Digest4,
    pay_owner: usdm_decider::whir_rec_block::NoteOwner,
    pay_value: u64,
    maker_payout_note: &[u8],
    terms: &OrderTerms,
    fee_bps: u64,
) -> Result<BuiltFill, OrderError> {
    fill_order_with_record(my_ek, my_spk, pay_owner, pay_value, maker_payout_note, terms, fee_bps, None)
}

/// [`fill_order`]'s one body. ⭐ DB-288 §9: with `payout_record = Some((out_sk, j))` the taker's PAYOUT note (the lot it
/// buys, always non-zero) is sealed at its reserved `(chg, j)` with the record of the input this fill consumes, so a
/// seed-only restore that finds the payout reads that input back as spent with no node ask. `None` seals as before.
#[allow(clippy::too_many_arguments)]
pub fn fill_order_with_record(
    my_ek: &[u8],
    my_spk: &Digest4,
    pay_owner: usdm_decider::whir_rec_block::NoteOwner,
    pay_value: u64,
    maker_payout_note: &[u8],
    terms: &OrderTerms,
    fee_bps: u64,
    payout_record: Option<(&[u8; 32], u64)>,
) -> Result<BuiltFill, OrderError> {
    if !terms_are_sane(terms) {
        return Err(OrderError::MalformedTerms);
    }
    // ⛔⛔⛔ THE CHANGE THIS WALLET SEALS AND THE CHANGE THE CIRCUIT COMMITS TO ARE ONE NUMBER, DERIVED
    //    ONCE. The taker constraint is `value_in == pay_b + fee + change`; if this line subtracted only
    //    `pay_b` while the circuit subtracted `pay_b + fee`, the note sealed below would carry a
    //    different amount than `change_cm` inside the proof — the wallet would record change it cannot
    //    open, which is silent fund loss of exactly the fee on every fill. So the fee comes from the
    //    SAME `protocol_fee` the prover calls, on the same terms, and never from a second formula.
    //
    // `fee_bps` is threaded in rather than compiled in because it is governance-tunable at runtime: it
    // is read from the node that will verify this fill, so the rate proved against is the rate enforced.
    let fee = terms.protocol_fee(fee_bps);
    // Refuse here rather than letting the prover fail: "you cannot afford this" is a fact about this
    // wallet, and a user deserves it as such instead of a proof error. Two `checked_sub`s, so a note
    // that covers the payment but not the fee is caught as INSUFFICIENT and not wrapped into a huge
    // change value.
    let change_value = pay_value
        .checked_sub(terms.pay_b)
        .and_then(|v| v.checked_sub(fee))
        .ok_or(OrderError::Insufficient)?;
    let (payout_note, payout_opening) = match payout_record {
        Some((out_sk, j)) => crate::pq::seal_self_note_with_record(
            my_ek,
            my_spk,
            terms.lot,
            terms.asset_a,
            out_sk,
            &crate::pq_spend::note_nullifier_asset(pay_value, &pay_owner, terms.asset_b),
            "chg",
            j,
        ),
        None => crate::pq::seal_note_full_asset(my_ek, my_spk, terms.lot, terms.asset_a),
    }
    .ok_or(OrderError::SealFailed)?;
    let (change_note, change_opening) =
        crate::pq::seal_note_full_asset(my_ek, my_spk, change_value, terms.asset_b)
            .ok_or(OrderError::SealFailed)?;
    // DB-363: ONE blinding draw where the fill is assembled; the half and the paying note's membership carrier share it.
    let lc_blind = usdm_decider::whir_rec_block::fresh_lc_blind().ok_or(OrderError::BlindingUnavailable)?;
    let w = TakerHalfWitness { value_in: pay_value, owner: pay_owner, change_opening, payout_opening, lc_blind };
    let (carrier, public) =
        prove_order_taker_half(&w, terms, fee_bps).ok_or(OrderError::ProveFailed)?;
    Ok(BuiltFill {
        carrier,
        public,
        lc_blind: crate::pq_spend::LcBlind(lc_blind),
        maker_payout_note: maker_payout_note.to_vec(),
        payout_note: payout_note.to_vec(),
        change_note: change_note.to_vec(),
        change_value,
    })
}

#[cfg(test)]
mod tests {
    //! Two wallets sharing no state: a maker rests an order and goes away, a stranger fills it, and the
    //! settlement verifies as ONE trade. The failures that matter are the ones where value could be
    //! created or misdirected.

    use super::*;
    use usdm_decider::whir_rec_block::{asset_note_cm, verify_order_fill, wrapped_asset_tag_u32};

    const WBTC_ID: u32 = 1;

    /// The settlement rate these tests build and verify against — the chain's own live default, so the
    /// arithmetic here is the arithmetic a real fill performs. It is deliberately NOT zero: a zero rate
    /// would make every fee assertion below pass whether or not the fee is honoured anywhere, which is
    /// the exact shape of a test that measures nothing.
    const FEE: u64 = 10;

    /// A test wallet: its scan keys and its NOTE keys (DB-395 — `spk` seals to it, `(ask, nk)` spends its notes).
    fn wallet(seed: u8) -> (Vec<u8>, Vec<u8>, crate::pq::NoteKeys) {
        let k = crate::pq::derive_keys(&[seed; 32]);
        (k.scan_ek.clone(), k.scan_dk.to_vec(), k.note_keys())
    }

    /// The owner of one of `keys`' notes, at a test seed.
    fn lot_of(keys: &crate::pq::NoteKeys, seed: &[u64]) -> usdm_decider::whir_rec_block::NoteOwner {
        keys.owner(usdm_decider::poseidon2_compress::lanes_of(seed))
    }

    fn terms() -> OrderTerms {
        // DEX-GRID (C3): through the one snap helper.
        OrderTerms {
            lot: usdmd_node::order_book::snap_to_grid(100_000),
            pay_b: usdmd_node::order_book::snap_to_grid(6_500_000),
            asset_a: wrapped_asset_tag_u32(WBTC_ID),
            asset_b: crate::pq::USDM_ASSET_TAG,
            expires_at_height: usdmd_node::order_book::snap_expiry(1_000_000),
        }
    }

    /// ⭐⭐ DB-288 §9 — A TAKER'S PAYOUT RECORDS THE INPUT ITS RUNG CONSUMES, AND THE FILL STILL VERIFIES.
    /// The payout sealed at its reserved `(chg, 5)` opens, under the taker's own key, to the nullifier of the note the
    /// rung spends; it is still an ordinary output (the taker's scan reads the lot it bought) and the two halves still
    /// compose into one verified settlement. CALIBRATION: the same fill built without a record never reads as it.
    #[test]
    fn db288_s9_a_fills_payout_records_the_consumed_input_and_the_fill_still_verifies() {
        // TWO-PARTY-REVIEWED: the record is written and read by the taker alone, for itself; the settlement's two-party
        // proof (a peer applying the fill from the wire) is the node's db224 fill pin, unchanged by a payout's KEM message.
        // CROSS-NODE-REVIEWED: db224_a_fill_whose_inputs_a_real_chain_funded_settles_on_a_peer_fed_only_the_wire
        let t = terms();
        let (maker_ek, _maker_dk, maker) = wallet(1);
        let (taker_ek, taker_dk, taker) = wallet(2);
        let order = post_order(&maker_ek, &maker.spk, lot_of(&maker, &[11, 22, 33, 44]), &t)
            .expect("the maker rests an order");
        let pay_owner = lot_of(&taker, &[55, 66, 77, 88]);
        let out_sk = [0x3Cu8; 32];
        let fill =
            fill_order_with_record(&taker_ek, &taker.spk, pay_owner, 10_000_000, &order.payout_note, &t, FEE, Some((&out_sk, 5)))
                .expect("a stranger fills it, recording its input");
        assert!(
            verify_order_fill(&order.carrier, &order.public, &fill.carrier, &fill.public, &t, FEE),
            "a record-carrying payout is an ordinary output: the settlement still verifies"
        );
        let nf_in = crate::pq_spend::note_nullifier_asset(10_000_000, &pay_owner, t.asset_b);
        assert_eq!(
            crate::pq::open_self_note_record(&fill.payout_note, &taker_dk, &taker.spk, &out_sk, "chg", 5),
            Some(nf_in),
            "the payout records the note this rung consumed"
        );
        assert_eq!(
            crate::pq::scan_note_full_asset(&fill.payout_note, &taker_dk, &taker.spk).map(|(a, _, asset)| (a, asset)),
            Some((t.lot, t.asset_a)),
            "the taker's own scan reads the lot it bought"
        );
        let plain = fill_order(&taker_ek, &taker.spk, pay_owner, 10_000_000, &order.payout_note, &t, FEE)
            .expect("fills without a record");
        assert_ne!(
            crate::pq::open_self_note_record(&plain.payout_note, &taker_dk, &taker.spk, &out_sk, "chg", 5),
            Some(nf_in),
            "CALIBRATION: an unrecorded payout never reads as the input's record"
        );
    }

    /// ⭐⭐⭐ THE WHOLE TRADE, BETWEEN STRANGERS. The maker posts and is never consulted again; the taker
    /// builds their half alone; the two halves compose into one verified settlement.
    #[test]
    fn a_maker_rests_an_order_and_a_stranger_fills_it() {
        let t = terms();
        let (maker_ek, maker_dk, maker) = wallet(1);
        let (taker_ek, taker_dk, taker) = wallet(2);

        let order = post_order(&maker_ek, &maker.spk, lot_of(&maker, &[11, 22, 33, 44]), &t).expect("the maker rests an order");
        let fill = fill_order(&taker_ek, &taker.spk, lot_of(&taker, &[55, 66, 77, 88]), 10_000_000, &order.payout_note, &t, FEE)
            .expect("a stranger fills it");

        assert!(
            verify_order_fill(&order.carrier, &order.public, &fill.carrier, &fill.public, &t, FEE),
            "the two halves compose into ONE verified settlement"
        );

        // ⛔ CONTROL — THE RATE IS BOUND INTO THE PROOF, not a number checked beside it. Verifying the
        // SAME bytes under a different rate must fail; without this the assertions below would hold just
        // as well if the fee were ignored end to end, and the test would be measuring nothing.
        assert!(
            !verify_order_fill(
                &order.carrier,
                &order.public,
                &fill.carrier,
                &fill.public,
                &t,
                FEE + 1
            ),
            "a fill proved at one rate must NOT verify at another"
        );

        // Each side can actually FIND and OPEN what it received — a note nobody can open is fund loss.
        let (m_amt, _m_seed, m_asset) = crate::pq::scan_note_full_asset(&order.payout_note, &maker_dk, &maker.spk)
            .expect("the maker opens its payout");
        assert_eq!((m_amt, m_asset), (t.pay_b, t.asset_b), "the maker is paid the price, in USDm");
        let (t_amt, _t_seed, t_asset) = crate::pq::scan_note_full_asset(&fill.payout_note, &taker_dk, &taker.spk)
            .expect("the taker opens its lot");
        assert_eq!((t_amt, t_asset), (t.lot, t.asset_a), "the taker receives one lot of wBTC");
        let (c_amt, _c_seed, c_asset) = crate::pq::scan_note_full_asset(&fill.change_note, &taker_dk, &taker.spk)
            .expect("the taker opens its change");
        // ⛔⛔⛔ THE CHANGE THE TAKER CAN OPEN IS THE CHANGE THE PROOF COMMITTED TO. This is the fund-loss
        // assertion: the note is opened with the taker's own key and its amount is checked against
        // `value_in - pay_b - fee`, the circuit's conservation constraint. If this wallet sealed change
        // on any other formula, the note would either be unopenable or would carry an amount the
        // settlement did not credit — and `verify_order_fill` above would not have passed.
        let fee = t.protocol_fee(FEE);
        assert!(fee > 0, "a zero fee would make every fee assertion in this test vacuous");
        assert_eq!(
            (c_amt, c_asset),
            (10_000_000 - t.pay_b - fee, t.asset_b),
            "and keeps the rest, less the settlement fee the chain takes"
        );
    }

    /// ⛔ THE MAKER'S PAYOUT NOTE IS OPENABLE ONLY BY THE MAKER. A taker who could open it would be able
    /// to spend what they just paid.
    #[test]
    fn the_makers_payout_note_cannot_be_opened_by_the_taker() {
        let t = terms();
        let (maker_ek, _maker_dk, maker) = wallet(1);
        let (_taker_ek, taker_dk, taker) = wallet(2);
        let order = post_order(&maker_ek, &maker.spk, lot_of(&maker, &[11, 22, 33, 44]), &t).unwrap();
        assert!(
            crate::pq::scan_note_full_asset(&order.payout_note, &taker_dk, &taker.spk).is_none()
                && crate::pq::scan_note_full_asset(&order.payout_note, &taker_dk, &maker.spk).is_none(),
            "the payout note belongs to the maker alone"
        );
    }

    /// ⛔ A TAKER WHO CANNOT COVER THE PRICE IS TOLD SO — no proof is built, so nothing postable exists.
    #[test]
    fn a_taker_who_cannot_afford_it_is_refused_with_a_reason() {
        let t = terms();
        let (taker_ek, _dk, taker) = wallet(2);
        // ⛔ THE AFFORDABILITY LINE IS `pay_b + fee`, NOT `pay_b`. A taker holding the price exactly can
        // no longer fill: the constraint is `value_in == pay_b + fee + change`, so the fee has to come
        // from somewhere, and a wallet that said "yes" here would hand the prover an impossible witness
        // and fail with a proof error instead of a fact the user can act on.
        let need = t.pay_b + t.protocol_fee(FEE);
        assert!(need > t.pay_b, "a zero fee would make this boundary the same test as before");
        let short = fill_order(&taker_ek, &taker.spk, lot_of(&taker, &[1, 2, 3, 4]), need - 1, &[0u8; 1153], &t, FEE)
            .expect_err("one unit short of price-plus-fee cannot build a fill");
        assert_eq!(short, OrderError::Insufficient);
        assert!(short.reason().contains("does not hold enough"), "and says so in words a user can act on");
        // Holding the price BUT NOT THE FEE is refused for the same reason — this is the case a
        // fee-blind wallet would have accepted, so it is the one worth naming.
        assert_eq!(
            fill_order(&taker_ek, &taker.spk, lot_of(&taker, &[1, 2, 3, 4]), t.pay_b, &[0u8; 1153], &t, FEE).unwrap_err(),
            OrderError::Insufficient,
            "the price alone no longer covers a fill"
        );
        // Paying EXACTLY price-plus-fee, with zero change, is honest and must still build.
        assert!(fill_order(&taker_ek, &taker.spk, lot_of(&taker, &[1, 2, 3, 4]), need, &[0u8; 1153], &t, FEE).is_ok());
    }

    /// ⛔ MALFORMED TERMS NEVER REACH A BOOK: an asset traded for itself, a zero lot, or a zero price.
    #[test]
    fn malformed_terms_are_refused_on_both_sides() {
        let (ek, _dk, keys) = wallet(1);
        let same = OrderTerms { asset_b: terms().asset_a, ..terms() };
        assert_eq!(post_order(&ek, &keys.spk, lot_of(&keys, &[1, 2, 3, 4]), &same).unwrap_err(), OrderError::MalformedTerms);
        let zero_lot = OrderTerms { lot: 0, ..terms() };
        assert_eq!(post_order(&ek, &keys.spk, lot_of(&keys, &[1, 2, 3, 4]), &zero_lot).unwrap_err(), OrderError::MalformedTerms);
        let zero_price = OrderTerms { pay_b: 0, ..terms() };
        assert_eq!(
            fill_order(&ek, &keys.spk, lot_of(&keys, &[1, 2, 3, 4]), 10, &[0u8; 1153], &zero_price, FEE).unwrap_err(),
            OrderError::MalformedTerms
        );
    }

    /// ⛔⛔⛔ A FILL BUILT FOR DIFFERENT TERMS DOES NOT COMPOSE. This is what stops a taker paying less
    /// than the maker offered: both halves name the terms, so they verify together only when they
    /// describe the SAME trade.
    #[test]
    fn a_fill_built_at_a_cheaper_price_does_not_compose_with_the_order() {
        let t = terms();
        let (maker_ek, _md, maker) = wallet(1);
        let (taker_ek, _td, taker) = wallet(2);
        let order = post_order(&maker_ek, &maker.spk, lot_of(&maker, &[11, 22, 33, 44]), &t).unwrap();
        let cheap = OrderTerms { pay_b: t.pay_b / 2, ..t };
        let fill =
            fill_order(&taker_ek, &taker.spk, lot_of(&taker, &[55, 66, 77, 88]), 10_000_000, &order.payout_note, &cheap, FEE)
            .expect("it builds for ITS OWN terms");
        assert!(
            !verify_order_fill(&order.carrier, &order.public, &fill.carrier, &fill.public, &t, FEE),
            "a half-price fill must NOT settle against the maker's order"
        );
        assert!(
            !verify_order_fill(&order.carrier, &order.public, &fill.carrier, &fill.public, &cheap, FEE),
            "nor by re-labelling the settlement with the cheaper terms"
        );
    }

    /// ⭐ THE PAYOUT COMMITMENT THE BOOK PUBLISHES IS THE NOTE'S OWN. If these could differ, the maker's
    /// half would prove something about a note the taker does not record.
    #[test]
    fn the_published_payout_commitment_matches_the_note_bytes() {
        let t = terms();
        let (maker_ek, maker_dk, maker) = wallet(1);
        let order = post_order(&maker_ek, &maker.spk, lot_of(&maker, &[11, 22, 33, 44]), &t).unwrap();
        let (amt, seed, asset) =
            crate::pq::scan_note_full_asset(&order.payout_note, &maker_dk, &maker.spk).expect("ours");
        assert_eq!(asset_note_cm(amt, asset, maker.view().opening(&seed)), order.public.payout_cm);
    }
}

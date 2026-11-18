// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE DEX HAS NEVER TRADED BETWEEN TWO PARTIES. This is the case that says whether it can.**
//!
//! What is already proven, in-process and on one node: an order rests, a fill settles, and every gate that
//! protects a fill refuses what it should — expiry, proof, self-deal, owner-present, the payout-note
//! binding before the burns, the atomic pair-burn. What is proven on the live pair: an order posted on one
//! node is READ from the other's book, which is gossip.
//!
//! Nobody has ever taken it. `execute_order_fill` mutates the state of the node that receives the fill —
//! it burns both nullifiers into that node's sparse tree, drops the order from that node's book, and
//! records three notes at that node's tip height. None of that is a message. So the question this file
//! exists to answer is the one an exchange lives or dies on:
//!
//!   **after a fill on one party, does the OTHER party reach the same state — and by what mechanism?**
//!
//! If the answer is "when the filler next produces a block", then a filler that stops producing leaves the
//! network holding two different books and two different unspent sets, which is a launch blocker. If the
//! answer is "never", it is a worse one. Either way it is cheaper to learn here than in a gate run.
//!
//! ⛔ SCOPE: in-process island. The order crosses by the SAME wire type the runtime gossips
//! (`OrderWire` → `postcard` → `post_order`), and the block crosses by `ingest_block`, but no transport,
//! no timing and no scale are exercised. The live pair gate and the multi-device run at the scale floor
//! remain the only network proofs and are a follow-on to every run here.

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn party() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        // ⭐ DB-150 — FOLD AT THE TIP, as `Node::new_folding_at_tip_for_test` does. A membership carrier
        // folds the roots a node has FOLDED, so a party whose fold trails its own tip can serve none and
        // no trade could ever prove its inputs are on chain. Same node, one block closer to its own state.
        p.record_fold_depth = 0;
        let g = Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: crate::block::genesis_header_for_network(&p.genesis_parity_commit),
            tx_ids: vec![],
            pow_proof: Vec::new(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        };
        Node::with_params(g, p).expect("a testnet party builds")
    }
    use crate::block::Block;
    use crate::hash::Hash32;
    use crate::node::{Node, OrderFillOutcome};
    use crate::order_book::{OrderWire, RestingOrder};
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::relay::RelayOutcome;
    use usdm_decider::whir_rec_block::{
        asset_note_cm, prove_order_maker_half, prove_order_taker_half, wrapped_asset_tag_u32,
        MakerHalfWitness, OrderTerms, TakerHalfWitness, USDM_ASSET_TAG,
    };

    pub(crate) fn terms() -> OrderTerms {
        // DEX-GRID (C3): through the one snap helper.
        OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: USDM_ASSET_TAG,
            asset_b: wrapped_asset_tag_u32(1),
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        }
    }

    pub(crate) fn note_for(cm: crate::spend_frontier::Digest4) -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        n
    }

    /// DB-273 §19.6 L3: a fill slot's owner is an OLI clue; a distinct non-empty value per seed.
    pub(crate) fn owner(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// The order the maker rests, and the halves the taker needs to fill it. Real proofs on both sides —
    /// the same calls the wallet makes.
    #[allow(clippy::type_complexity)]
    /// ⭐ DB-150 — the two INPUT note commitments ride out with the trade. A fill must prove both notes
    /// are in the chain's note frontier, and a fixture that cannot name them cannot put them there. They
    /// are derived with the decider's own `asset_note_cm`, never a local formula.
    fn trade_input_cms(
        t: &OrderTerms,
        mw: &MakerHalfWitness,
        tw: &TakerHalfWitness,
    ) -> ([u8; 32], [u8; 32]) {
        let cm = |v: u64, asset: [u64; 3], sk: crate::spend_frontier::Digest4| -> [u8; 32] {
            crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
                v, asset, sk,
            ))
        };
        (cm(t.lot, t.asset_a, mw.owner.opening()), cm(tw.value_in, t.asset_b, tw.owner.opening()))
    }

    /// Deliver the blocks a plant produced to a peer and let it FOLD them. A membership bind is checked
    /// against the accumulator a node has FOLDED, so a peer that merely holds the block cannot yet verify
    /// a carrier that names it — which reads as a refused settlement for a reason that is about timing.
    pub(crate) fn deliver_planted(blocks: &[crate::block::Block], to: &mut Node, now_ms: u64) {
        for blk in blocks {
            to.ingest_block(blk.clone(), now_ms);
        }
        let _ = to.fold_canonical_records();
    }

    /// Put BOTH input notes on `n`'s chain and build the two membership cross-binds a fill must carry.
    /// This is what a real maker and taker each do before they trade: receive on chain, then prove where.
    pub(crate) fn trade_binds(
        n: &mut Node,
        t: &OrderTerms,
        maker: &usdm_decider::whir_rec_block::MakerHalfPublic,
        taker: &usdm_decider::whir_rec_block::TakerHalfPublic,
        now_ms: u64,
    ) -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>), Vec<crate::block::Block>) {
        let (mw, tw) = witnesses();
        let (maker_cm, taker_cm) = trade_input_cms(t, &mw, &tw);
        // ⛔ THE BINDER IS THE SPEND'S NULLIFIER, NOT ITS LEAF COMMITMENT. The carrier yields
        // `note_leaf_commitment(leaf, binder, blind)`, and the value the gate compares that against IS the half's
        // `leaf_commit` — so binding by the commitment would prove a different claim about the same note.
        let (mc, mt, mb) = n
            .plant_note_and_bind_for_test(&maker_cm, maker.nullifier, b"dex-maker-note", now_ms)
            .expect("the maker's input note lands on chain and its membership proves");
        let (kc, kt, kb) = n
            .plant_note_and_bind_for_test(&taker_cm, taker.nullifier, b"dex-taker-note", now_ms + 400)
            .expect("the taker's input note lands on chain and its membership proves");
        ((mc, mt), (kc, kt), vec![mb, kb])
    }

    /// The two half-witnesses `a_real_trade` proves with — named once so the input commitments above and
    /// the halves below can never drift apart.
    fn witnesses() -> (MakerHalfWitness, TakerHalfWitness) {
        (
            MakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[7_001, 7_002, 7_003, 7_004])),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[7_011, 7_012, 7_013, 7_014]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            TakerHalfWitness {
                value_in: 10_000_000,
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[8_001, 8_002, 8_003, 8_004])),
                change_opening: usdm_decider::poseidon2_compress::lanes_of(&[8_011, 8_012, 8_013, 8_014]),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[8_021, 8_022, 8_023, 8_024]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
        )
    }

    pub(crate) fn a_real_trade() -> (
        OrderTerms,
        RestingOrder,
        (Vec<u8>, usdm_decider::whir_rec_block::TakerHalfPublic),
        [Vec<u8>; 3],
    ) {
        let t = terms();
        let (mw, tw) = witnesses();
        let (mc, mp) = prove_order_maker_half(&mw, &t).expect("the maker half proves");
        let (tc, tp) =
            prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).expect("the taker half proves");
        let notes = [note_for(mp.payout_cm), note_for(tp.payout_cm), note_for(tp.change_cm)];
        let resting = RestingOrder { terms: t, maker: mp, maker_bytes: mc, payout_note: notes[0].clone() , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };
        (t, resting, (tc, tp), notes)
    }

    /// Gossip the order exactly as the runtime does: the same wire type, the same encoding, the same
    /// admission call. If this ever diverges from `node_runtime`'s `WireMsg::OrderPost` arm, the case is
    /// lying about how an order travels.
    pub(crate) fn gossip_order(from: &RestingOrder, to: &mut Node) -> u32 {
        let bytes = postcard::to_allocvec(&OrderWire::of(from)).expect("the order serialises");
        let wire: OrderWire = postcard::from_bytes(&bytes).expect("the order deserialises");
        to.post_order(wire.into_order()).expect("the peer admits the gossiped order")
    }

    /// The settlement transaction the submitter PUBLISHED for this trade, read back from its own pool
    /// by the canonical content id of the framed wire bytes — so no test can drift from what actually
    /// travelled. ONE reconstruction of the fill, shared by every pin that needs the published tx.
    /// (A read-back of an already-published object — it moves nothing itself.)
    fn published_fill_tx(
        submitter: &Node,
        t: &OrderTerms,
        resting: &RestingOrder,
        tc: &[u8],
        tp: &usdm_decider::whir_rec_block::TakerHalfPublic,
        notes: &[Vec<u8>; 3],
        // DB-150: the binds the fill was SUBMITTED with — they ride the object, so the content id the
        // pool keys on includes them. A reconstruction that omitted them would name a different tx.
        binds: (&(Vec<u8>, Vec<u8>), &(Vec<u8>, Vec<u8>)),
    ) -> crate::mempool::PqTx {
        let fill = crate::order_fill_tx::OrderFillTx {
            lot: t.lot,
            pay_b: t.pay_b,
            asset_a: t.asset_a,
            asset_b: t.asset_b,
            expires_at_height: t.expires_at_height,
            maker_nullifier: resting.maker.nullifier,
            maker_leaf_commit: resting.maker.leaf_commit,
            maker_payout_cm: resting.maker.payout_cm,
            maker_bytes: resting.maker_bytes.clone(),
            taker_nullifier: tp.nullifier,
            taker_leaf_commit: tp.leaf_commit,
            taker_payout_cm: tp.payout_cm,
            taker_change_cm: tp.change_cm,
            taker_bytes: tc.to_vec(),
            maker_membership_carrier: binds.0 .0.clone(),
            maker_membership_tip: binds.0 .1.clone(),
            taker_membership_carrier: binds.1 .0.clone(),
            taker_membership_tip: binds.1 .1.clone(),
            notes: notes.clone(),
            owner_clues: [owner(1), owner(2), owner(3)],
        };
        let tx_id = crate::mempool::PqTx::content_id(&fill.wire());
        submitter
            .mempool()
            .get(&tx_id)
            .cloned()
            .expect("the settlement was PUBLISHED into the submitter's pool as a framed transaction")
    }

    /// ⭐ RED-FIRST HOLE-CLOSURE PIN (2026-09-06) — THE COPATH-ONLY FILL ADMISSION LANE.
    ///
    /// Today's absence-gate fix left exactly one shape admitted on carried copaths alone:
    /// `Class::OrderFill` (the class arm in `tx_nullifiers_absent_by_fold`). A copath's authority is
    /// `sparse_acc`, and the gate's own text records why that root can miss a settlement (a
    /// non-folding copath is dropped silently; a jump-adopted root has no index behind it) — so a
    /// fill stripped of its recursive absence carrier must be REFUSED at the pool door on EVERY
    /// party, exactly like any other spend that carries no carrier.
    ///
    /// MEASURED: the first run 2026-09-06 decides RED or GREEN. A RED is the confirmed admission
    /// hole; the fix is the fill submitter attaching the self-built carrier
    /// (`Node::self_build_publish_absence_witness`) and the class arm DELETED — one admission rule
    /// per object kind.
    /// MUST-STAY-GREEN beside it:
    /// a_fill_submitted_on_one_party_settles_on_a_second_exactly_once_from_the_block_alone — the
    /// carrier-bearing fill still settles exactly once.
    /// ⭐ DEX-GRID (spec §5 pins 1–3 at SETTLEMENT; C1 parity) — the grid gate is step 0 of the ONE settlement
    /// engine that the RPC door and every node's graft door (`apply_chain_dex_object`) run, so off-grid terms answer
    /// `OffGrid` on BOTH parties before any proof or burn. RED against the pre-grid engine, which never asked:
    /// the nudged terms reached the composed-proof check and answered `ProofRefused` — a refusal that names the
    /// wrong gate, and one an out-of-band pair of halves proved over off-grid terms would PASS.
    #[test]
    fn dex_grid_off_grid_terms_are_refused_first_by_the_settlement_engine_on_both_parties() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        assert!(crate::order_book::on_grid(&t), "PRECONDITION: the honest trade's terms are on the grid");
        let off = OrderTerms { pay_b: t.pay_b + 1, ..t };
        for who in ["A", "B"] {
            let mut n = party();
            let v = n.execute_order_fill(
                &resting.maker_bytes,
                &resting.maker,
                &tc,
                &tp,
                &off,
                &n0,
                &n1,
                &n2,
                [owner(1), owner(2), owner(3)],
                [None, None],
            );
            assert_eq!(
                v,
                OrderFillOutcome::OffGrid,
                "⛔ DEX-GRID: party {who}'s settlement engine did not refuse off-grid terms first"
            );
        }
    }

    #[test]
    fn a_copath_only_fill_without_the_recursive_carrier_is_refused_on_both_parties() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party(); // settles and publishes the honest fill
        let mut c = party(); // pool peer one — never saw the RPC
        let mut d = party(); // pool peer two — "both parties" is measured, never assumed

        let _ = a.post_order(resting.clone()).expect("rests on A");
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp, 70_000);
        deliver_planted(&planted_a, &mut c, 70_000);
        deliver_planted(&planted_a, &mut d, 70_000);
        assert_eq!(
            a.execute_order_fill(
                &resting.maker_bytes,
                &resting.maker,
                &tc,
                &tp,
                &t,
                &n0,
                &n1,
                &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "PRECONDITION: the honest fill settles on the submitter"
        );
        let tx = published_fill_tx(&a, &t, &resting, &tc, &tp, &[n0, n1, n2], (&mb_a, &tb_a));

        // The attack shape: the SAME settlement bytes with the recursive absence carrier stripped,
        // leaving only the sparse copaths. The content id does not cover the carrier, so this is not
        // a second transaction — it is the same fill knocking with weaker evidence.
        let mut bare = tx;
        bare.nullifier_absence.clear();
        assert!(
            c.ingest_tx(bare.clone()).is_err(),
            "⛔ ADMISSION HOLE: a copath-only fill (no recursive absence carrier) was ADMITTED — the \
             OrderFill class arm is the one lane left standing on the sparse root alone"
        );
        assert!(
            d.ingest_tx(bare).is_err(),
            "⛔ the second party admitted the copath-only fill — the door must be one rule on every \
             node, or admission depends on which peer a tx happens to reach"
        );
    }

    /// ⭐⭐⭐ THE QUESTION. A rests an order, B reads it by gossip and FILLS it. B has settled. What does A
    /// hold? This case does not assume an answer — it records the one the code gives, and asserts the only
    /// outcome an exchange can survive: once B's block carrying the fill reaches A, BOTH parties agree the
    /// order is gone and both hold the settlement's notes.
    /// ⭐⭐⭐ THE BOOK CHANGES ONLY BY CHAIN EVENTS (2026-11-03, c11-journey.log T2): a fill PUBLISHED on B is an in-flight
    /// overlay, not a book change. While it is pooled, B's served level excludes the rung (a taker is not offered a note
    /// with a fill in flight); when the pooled fill leaves the pool (stranded, dropped, evicted) the rung is served again
    /// on B — it never left B's book; A's book never moved. RED-first: before, the publication removed the order from B's
    /// book for good, and a stranded fill left B with no rung and A with one. TWO-PARTY-REVIEWED: both books asserted.
    #[test]
    fn a_published_fill_that_leaves_the_pool_re_exposes_the_rung_on_the_publisher_and_never_moved_the_peers_book() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let mut b = party();
        let level = a.post_order(resting.clone()).expect("the maker's order rests on A");
        let pair = resting.pair();
        let b_level = gossip_order(&resting, &mut b);
        assert_eq!(b.book_level(pair, b_level).0.len(), 1, "PRECONDITION: B serves the same order");
        let (mb_b, tb_b, planted_b) = trade_binds(&mut b, &t, &resting.maker, &tp, 71_000);
        deliver_planted(&planted_b, &mut a, 71_000);
        assert_eq!(
            b.execute_order_fill(&resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)], [Some(mb_b.clone()), Some(tb_b.clone())]),
            OrderFillOutcome::Settled,
            "PRECONDITION: the fill publishes on B"
        );
        let served = b.book_level(pair, b_level);
        assert!(served.0.is_empty(), "the in-flight overlay hides the rung on B while its fill is pooled");
        assert_eq!(served.1, 1 + b.order_book_level_empty_for_test(pair, b_level), "the served width stays constant: the hidden rung is an empty slot");
        assert_eq!(a.book_level(pair, level).0.len(), 1, "A's book never moved: nothing travelled yet");
        // the published fill is stranded: it leaves B's pool (a drop, an eviction, a refused carriage)
        let tx = published_fill_tx(&b, &t, &resting, &tc, &tp, &[n0, n1, n2], (&mb_b, &tb_b));
        b.mempool_mut().remove(&[tx.id]);
        assert_eq!(b.book_level(pair, b_level).0.len(), 1, "⛔ the rung is served again on B once its fill left the pool — it never left the book");
        assert_eq!(a.book_level(pair, level).0.len(), 1, "A still serves it");
    }

    #[test]
    fn an_order_rested_on_one_party_and_filled_on_the_other_leaves_both_agreeing() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let mut b = party();

        let level = a.post_order(resting.clone()).expect("the maker's order rests on A");
        let pair = resting.pair();
        assert_eq!(a.book_level(pair, level).0.len(), 1, "PRECONDITION: A serves the resting order");
        let b_level = gossip_order(&resting, &mut b);
        assert_eq!(b_level, level, "the gossiped order rests at the same lattice level on both parties");
        assert_eq!(b.book_level(pair, b_level).0.len(), 1, "PRECONDITION: B serves the same order");
        let (mb_b, tb_b, planted_b) = trade_binds(&mut b, &t, &resting.maker, &tp, 71_000);
        deliver_planted(&planted_b, &mut a, 71_000);

        // B TAKES IT. Every gate that protects a fill runs here, on B.
        assert_eq!(
            b.execute_order_fill(
                &resting.maker_bytes,
                &resting.maker,
                &tc,
                &tp,
                &t,
                &n0,
                &n1,
                &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_b.clone()), Some(tb_b.clone())]),
            OrderFillOutcome::Settled,
            "the gossiped order fills on the party that read it"
        );
        assert!(b.book_level(pair, b_level).0.is_empty(), "the filled order leaves B's book");

        // ⛔ THE SEAM. Nothing about that fill was a message, so A still serves an order whose maker note
        // B has already burned. A taker on A would build a fill against a spent note and be refused — the
        // dead-offer window, measured rather than assumed.
        let a_still_serves = !a.book_level(pair, level).0.is_empty();

        // The only mechanism that carries it: B produces, A grafts.
        let now = b
            .dag()
            .get(&b.selected_tip().expect("tip"))
            .expect("header")
            .header
            .timestamp
            + b.params().target_spacing_ms;
        let blk = b
            .produce(now, Hash32::hash(b"dex-settle"), Hash32::hash(b"miner"))
            .expect("B produces the block that carries its settlement");
        assert!(
            matches!(a.ingest_block(blk, now + 1), RelayOutcome::Added(_)),
            "A grafts B's block"
        );

        let a_serves_after = !a.book_level(pair, level).0.is_empty();
        assert!(
            !a_serves_after,
            "⛔ LAUNCH BLOCKER: A is STILL serving an order that B filled{}. A taker on A builds a fill \
             against a note that is already burned and is refused; the two parties hold different books. \
             (Before B's block: A served it = {a_still_serves}.) A fill must reach every party, or the \
             exchange is one book per node.",
            if a_still_serves { " even after grafting B's block" } else { "" }
        );

        // …and the settlement's notes must exist on A too, or the maker's payout lives on one node only.
        let maker_cm = crate::spend_frontier::leaf_to_cm_bytes(resting.maker.payout_cm);
        assert!(
            a.holds_record_with_cm(&maker_cm),
            "⛔ the maker's payout note is not on A after the settlement crossed — a payout that exists on \
             one party is not a payout"
        );
    }

    /// ⛔⛔⛔ DB-401 — A TAKER ON ANOTHER NODE SETTLES WITH THE MAKER'S BIND THAT NODE'S BOOK SERVES.
    ///
    /// Every other case here hands `execute_order_fill` a maker bind the TEST built on the filling party, so none could see
    /// that the bind never travelled: `OrderWire::of` / `into_order` wrote it `Vec::new()`, every book but the posting
    /// node's held the offer without it, and a real taker (the wallet reads the maker's bind from the book it trades
    /// through) submitted an empty bind that the fill door refuses (DB-150). MEASURED sim-20261006-190157 (eco T2): W2's
    /// fill through node 1 → `[order-fill] ⛔ REFUSED: a half did not prove its input note is in this chain's note
    /// frontier`, with no `[membership-1step]` line, and nothing settled.
    ///
    /// The maker builds its bind on A (its node) and posts it there; the offer reaches B by the runtime's gossip arm and C
    /// as the `Class::OrderPost` object a block carries. Each peer's book must SERVE the bind byte for byte; the taker on B
    /// fills with ONLY what B served; and A, the maker's node, must then hold the settlement B's block carries.
    #[test]
    fn db401_a_taker_on_another_node_settles_with_the_makers_bind_that_nodes_book_serves() {
        let (t, mut resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        // The maker's and the taker's input notes land on A's chain; the maker proves its own there (what its wallet does
        // before `/post_order`), and the blocks reach the peers, which fold them.
        let (mb, tb, planted) = trade_binds(&mut a, &t, &resting.maker, &tp, 74_000);
        resting.membership_carrier = mb.0.clone();
        resting.membership_tip = mb.1.clone();
        let level = a.post_order(resting.clone()).expect("the maker's order rests on A with its bind");
        let pair = resting.pair();
        let mut b = party();
        deliver_planted(&planted, &mut b, 74_000);
        let mut c = party();
        deliver_planted(&planted, &mut c, 74_000);
        // Lane 1: the gossip arm, exactly as the runtime runs it. Lane 2: the block-carried object, through its apply seam.
        assert_eq!(gossip_order(&resting, &mut b), level, "B admits the gossiped offer at the same level");
        assert_eq!(
            crate::node::objects::order_post_tx::apply_chain_order_post(&mut c, &crate::order_post_tx::encode(&resting)),
            crate::order_post_tx::OrderPostApply::Posted(level),
            "C admits the block-carried offer at the same level"
        );
        let wire_len = postcard::to_allocvec(&OrderWire::of(&resting)).expect("the offer encodes").len();
        eprintln!(
            "[db401] the maker's bind: carrier {} B, tip {} B; the offer's whole wire {wire_len} B",
            mb.0.len(),
            mb.1.len()
        );
        for (lane, peer) in [("gossip", &b), ("block-carried object", &c)] {
            let served = peer.book_level(pair, level).0;
            assert_eq!(served.len(), 1, "PRECONDITION: the {lane} peer serves the offer");
            assert!(
                served[0].membership_carrier == mb.0 && served[0].membership_tip == mb.1,
                "⛔ DB-401: the {lane} peer's book serves the offer WITHOUT the maker's membership bind (carrier {} B, tip {} \
                 B; the maker posted {} B / {} B) — a taker there can only submit a fill the fill door refuses (DB-150)",
                served[0].membership_carrier.len(),
                served[0].membership_tip.len(),
                mb.0.len(),
                mb.1.len()
            );
        }
        // The taker on B has ONLY what B's book served.
        let served = b.book_level(pair, level).0.remove(0);
        let served_bind = (served.membership_carrier.clone(), served.membership_tip.clone());
        assert_eq!(
            b.execute_order_fill(
                &served.maker_bytes,
                &served.maker,
                &tc,
                &tp,
                &t,
                &n0,
                &n1,
                &n2,
                [owner(1), owner(2), owner(3)],
                [Some(served_bind), Some(tb.clone())]
            ),
            OrderFillOutcome::Settled,
            "⛔ the taker on B could not settle with the maker's bind B's book served"
        );
        // Assert what the PEER holds: B's block carries the settlement to A, the maker's node.
        let now = b.dag().get(&b.selected_tip().expect("tip")).expect("header").header.timestamp
            + b.params().target_spacing_ms;
        let blk = b
            .produce(now, Hash32::hash(b"db401-settle"), Hash32::hash(b"miner"))
            .expect("B produces the block that carries its settlement");
        assert!(matches!(a.ingest_block(blk, now + 1), RelayOutcome::Added(_)), "A grafts B's block");
        assert!(
            a.book_level(pair, level).0.is_empty(),
            "⛔ the filled offer still rests on A after B's settlement crossed"
        );
        assert!(
            a.holds_record_with_cm(&crate::spend_frontier::leaf_to_cm_bytes(resting.maker.payout_cm)),
            "⛔ the maker's payout is not on A — a settlement that exists on one node only"
        );
    }

    /// The dead-offer window, named and measured: between a fill on one party and the block that carries
    /// it, the other party still serves the order. This case does not fail on the window — it FAILS if the
    /// window never closes, which is the difference between latency and divergence.
    #[test]
    fn two_parties_racing_the_same_order_pay_the_maker_s_lot_exactly_once() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let mut b = party();
        let level = a.post_order(resting.clone()).expect("rests on A");
        let _ = gossip_order(&resting, &mut b);
        let (mb_b, tb_b, planted_b) = trade_binds(&mut b, &t, &resting.maker, &tp, 72_000);
        deliver_planted(&planted_b, &mut a, 72_000);
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp, 73_000);
        deliver_planted(&planted_a, &mut b, 73_000);
        assert_eq!(
            b.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_b.clone()), Some(tb_b.clone())]),
            OrderFillOutcome::Settled,
            "B fills it first"
        );
        // ⛔ WHAT A SECOND PARTY CAN AND CANNOT KNOW. A has received nothing: no block, no message. There
        // is no ledger in existence in which a node refuses a transaction it has never heard anything
        // about, so A settles too, and that is not the bug. THE BUG WOULD BE BOTH SETTLEMENTS SURVIVING.
        let second = a.execute_order_fill(
            &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
            [owner(1), owner(2), owner(3)],
         [Some(mb_a.clone()), Some(tb_a.clone())]);
        assert_eq!(
            second,
            OrderFillOutcome::Settled,
            "PRECONDITION: A has heard nothing yet, so it settles — the race is real and must be RESOLVED, \
             not wished away (got {second:?})"
        );

        // ⭐⭐⭐ NOW THE TWO SETTLEMENTS MEET. Each party's fill reaches the other as the bytes a block
        // carries, through the ONE graft-side door. Exactly one may survive on each node: the note was
        // already burned there, so the competing trade must be REFUSED — not credited a second time.
        //
        // This is the invariant an exchange actually lives by. "Neither node ever settles twice" is
        // unreachable without a message; "the maker's lot is paid once no matter which order the two
        // blocks arrive in" is reachable, and it is the one that protects the money.
        let fill = crate::order_fill_tx::OrderFillTx {
            lot: t.lot,
            pay_b: t.pay_b,
            asset_a: t.asset_a,
            asset_b: t.asset_b,
            expires_at_height: t.expires_at_height,
            maker_nullifier: resting.maker.nullifier,
            maker_leaf_commit: resting.maker.leaf_commit,
            maker_payout_cm: resting.maker.payout_cm,
            maker_bytes: resting.maker_bytes.clone(),
            taker_nullifier: tp.nullifier,
            taker_leaf_commit: tp.leaf_commit,
            taker_payout_cm: tp.payout_cm,
            taker_change_cm: tp.change_cm,
            taker_bytes: tc.clone(),
            // DB-150: a replay of an honest settlement carries the SAME binds the original did, or the
            // membership gate refuses it before the already-filled gate this pin is measuring can speak.
            maker_membership_carrier: mb_a.0.clone(),
            maker_membership_tip: mb_a.1.clone(),
            taker_membership_carrier: tb_a.0.clone(),
            taker_membership_tip: tb_a.1.clone(),
            notes: [n0.clone(), n1.clone(), n2.clone()],
            owner_clues: [owner(1), owner(2), owner(3)],
        };
        for (who, node) in [("A", &mut a), ("B", &mut b)] {
            let applied = crate::node::objects::order_fill_tx::apply_chain_dex_object(node, &fill.wire());
            assert_eq!(
                applied,
                crate::order_fill_tx::DexApply::Fill(OrderFillOutcome::OrderAlreadyFilled),
                "⛔ FUND SAFETY: {who} credited the competing settlement of the SAME order a second time \
                 (got {applied:?}). The maker's note is already burned on {who}, so the only sound verdict \
                 is a refusal — otherwise one lot pays out twice the moment two honest nodes race."
            );
        }
        let _ = level;
    }
    /// ⭐⭐⭐ THE CONTRACT THE NODE HALF MUST MEET. Party A settles a fill; the fill's BYTES then reach party
    /// B the way a block's transactions do, and B is driven through the single graft-side door. After that
    /// both parties must agree: the order is gone from both books and neither will settle it again.
    ///
    /// This is the shape `execute_order_fill` needs to be called in — once, from one place, on every node —
    /// rather than being applied by whoever happened to receive the request.
    /// ⛔⛔⛔ §AQ — CAN A SETTLEMENT BE PUBLISHED BY A NODE THAT HAS SEEN A BLOCK?
    ///
    /// Every scenario in this file settles on a party that has produced and grafted NOTHING. A real node
    /// has grafted thousands of blocks before anyone submits anything, so this asks the production
    /// question directly: produce ONE block first, then run the identical fill.
    ///
    /// The dependency under test is shared by every on-node publisher — `execute_order_fill` and
    /// `execute_asset_spend` alike — namely `da_sparse_copath`, which sources each tag's non-membership
    /// witness from an index the node deliberately does not maintain (mirroring it cost ~2.5 MB/block and
    /// was reverted). MEASURED: a fresh node answers `Unspent` for an unseen nullifier; after ONE produce
    /// **or one ingest** it answers `Unprovable` for every nullifier.
    ///
    /// ⭐ If this test fails, the fill path cannot publish on any live node and its nine green cross-party
    /// scenarios pass only because they run on nodes that have never seen a block.
    /// DIAGNOSTIC — WHERE does the copath source stop describing the authority? Four points, measured,
    /// so the §AQ fix is aimed at the step that actually breaks rather than at the symptom.
    #[test]
    fn diag_where_does_the_sparse_copath_source_stop_describing_the_authority() {
        let mut a = party();
        let say = |who: &str, n: &Node| {
            let (acc, work, probe) = n.sparse_lockstep_for_test();
            eprintln!(
                "[lockstep] {who}: acc={} work={} lockstep={} fresh_tag_provable={}",
                hex4(&acc),
                work.map(|w| hex4(&w)).unwrap_or_else(|| "NONE".into()),
                work.map(|w| w == acc).unwrap_or(false),
                probe
            );
        };
        say("fresh", &a);
        let need = a.mempool().required_stamp_bits();
        let tx = crate::node::tests::grind_tx(
            b"diag-warm",
            1_000,
            vec![crate::hash::Hash32::hash(b"diag-warm-nf")],
            need,
        );
        a.ingest_tx_unverified(tx).expect("pooled");
        say("after ingest", &a);
        let _ = a
            .produce(5_000, crate::hash::Hash32::hash(b"fr"), crate::hash::Hash32::hash(b"mc"))
            .expect("the warming block is produced");
        say("after produce", &a);
    }

    fn hex4(b: &[u8; 32]) -> String {
        b[..4].iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_fill_is_still_settleable_on_a_party_that_has_already_produced_a_block() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();

        // ONE block, the way a live node reaches its normal state.
        let need = a.mempool().required_stamp_bits();
        let tx = crate::node::tests::grind_tx(
            b"dex-warm",
            1_000,
            vec![crate::hash::Hash32::hash(b"dex-warm-nf")],
            need,
        );
        a.ingest_tx_unverified(tx).expect("pooled");
        let _ = a
            .produce(5_000, crate::hash::Hash32::hash(b"fr"), crate::hash::Hash32::hash(b"mc"))
            .expect("the warming block is produced");

        let _level = a.post_order(resting.clone()).expect("rests on A");
        // ⛔ DB-150 REFUTATION ARM — NO MEMBERSHIP BIND ON PURPOSE. The halves prove a consistent trade
        // over notes the chain never recorded, which is exactly the settlement that must be refused.
        let outcome = a.execute_order_fill(
            &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
            [owner(1), owner(2), owner(3)],
         [None, None]);
        eprintln!("[aq] a fill on a party that has produced ONE block: {outcome:?}");

        // ⭐⭐⭐ §AQ IS CLOSED, AND THIS REFUSAL IS NOW THE CORRECT ANSWER — NOT A SYMPTOM.
        //
        // This pin used to record `OrderAlreadyFilled` as the §AQ hole: a freshly posted order nobody had
        // filled, refused on a node that had produced one block. The refusal is unchanged, but its MEANING
        // is: `a_real_trade()` proves the two halves and builds the PAYOUT notes, and nothing ever puts the
        // notes being SPENT on chain. A settlement whose inputs the chain has no record of MUST be refused,
        // and the sibling pin `a_fill_settles_on_a_produced_node_when_its_inputs_are_in_the_live_unspent_
        // tree` is that same trade with its inputs carried on chain first — it answers `Settled` on a node
        // that has produced.
        //
        // ⭐ SO THIS IS NOW THE REFUTATION ARM, kept because the two together are what make either mean
        // anything: inputs on chain ⇒ settles; inputs never on chain ⇒ refused. A single green "it
        // settles" could just mean the gate stopped asking.
        // ⛔⛔⛔ DB-150 (2026-09-22, found by the Z-build): THIS ARM IS RED ON PURPOSE AND MUST STAY RED
        // UNTIL THE MEMBERSHIP LANE ANSWERS IT.
        //
        // The refusal this asserts was produced by the DELETION TRANSITION: the fill had to find both input
        // notes PRESENT in the live unspent tree, and a trade whose inputs the chain never recorded had no
        // such entry. Z1 retired that tree — a spend is now authorised by its NULLIFIER being unspent, and a
        // note the chain never recorded has an unspent nullifier by construction, so the pool door admits it.
        //
        // The check that MUST replace it is MEMBERSHIP: the fill's halves carry `leaf_commit` and a
        // membership carrier, and no settlement may pass whose inputs are not in the chain's append-only
        // note frontier. Until that is enforced on this path, a fill can settle against notes that were
        // never on chain — value created from notes that do not exist. Measured: `Settled`.
        assert_ne!(
            outcome,
            OrderFillOutcome::Settled,
            "⛔⛔⛔ DB-150: A SETTLEMENT WHOSE INPUTS THE CHAIN NEVER HELD WAS ADMITTED. The deletion \
             transition used to refuse it; with the deletion tree retired (Z1) the membership lane must, \
             and this pin stays RED until it does."
        );
        assert_eq!(
            outcome,
            OrderFillOutcome::MembershipRefused,
            "⛔ THE REFUSAL HAS CHANGED SHAPE — re-measure before trusting any conclusion about this path. \
             DB-150: the refusal used to come from the deletion transition (the inputs were not in the \
             unspent tree); with that tree retired it comes from the MEMBERSHIP lane, which is the check \
             that replaced it. Same verdict, a reason that still exists."
        );
    }

    // ⛔ (2026-10-03) THIS PIN HAD NO `#[test]` AND HAD NEVER RUN — found by the surface census's hollow-pin check
    // (an asserting test fn nothing calls). Restored; its first recorded verdict is in scratchpad/pin-results.tsv.
    #[test]
    fn a_fill_applied_through_the_graft_door_leaves_both_parties_agreeing() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let mut b = party();
        let level = a.post_order(resting.clone()).expect("rests on A");
        let b_level = gossip_order(&resting, &mut b);
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp, 74_000);
        deliver_planted(&planted_a, &mut b, 74_000);
        let (mb_b, tb_b) = (mb_a.clone(), tb_a.clone());
        assert_eq!(
            a.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "A settles the fill it received"
        );

        // The bytes that travel. Exactly what `/submit_order_fill` now admits as a transaction blob.
        let fill = crate::order_fill_tx::OrderFillTx {
            lot: t.lot,
            pay_b: t.pay_b,
            asset_a: t.asset_a,
            asset_b: t.asset_b,
            expires_at_height: t.expires_at_height,
            maker_nullifier: resting.maker.nullifier,
            maker_leaf_commit: resting.maker.leaf_commit,
            maker_payout_cm: resting.maker.payout_cm,
            maker_bytes: resting.maker_bytes.clone(),
            taker_nullifier: tp.nullifier,
            taker_leaf_commit: tp.leaf_commit,
            taker_payout_cm: tp.payout_cm,
            taker_change_cm: tp.change_cm,
            taker_bytes: tc.clone(),
            // DB-150: a replay of an honest settlement carries the SAME binds the original did, or the
            // membership gate refuses it before the already-filled gate this pin is measuring can speak.
            maker_membership_carrier: mb_a.0.clone(),
            maker_membership_tip: mb_a.1.clone(),
            taker_membership_carrier: tb_a.0.clone(),
            taker_membership_tip: tb_a.1.clone(),
            notes: [n0.clone(), n1.clone(), n2.clone()],
            owner_clues: [owner(1), owner(2), owner(3)],
        };
        let applied = crate::node::objects::order_fill_tx::apply_chain_dex_object(&mut b, &fill.wire());
        assert_eq!(
            applied,
            crate::order_fill_tx::DexApply::Fill(OrderFillOutcome::Settled),
            "B applies the SAME fill from the SAME bytes through the graft door — got {applied:?}"
        );

        assert!(a.book_level(resting.pair(), level).0.is_empty(), "the order left A's book");
        assert!(b.book_level(resting.pair(), b_level).0.is_empty(), "the order left B's book too");
        let second_on_b = b.execute_order_fill(
            &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
            [owner(1), owner(2), owner(3)],
         [Some(mb_b.clone()), Some(tb_b.clone())]);
        assert_ne!(
            second_on_b, OrderFillOutcome::Settled,
            "⛔ B settled the same order a SECOND time after applying it once (got {second_on_b:?}) — the \
             published burn must make a fill final on every node, not merely applied on each"
        );
    }

    /// ⭐ THE BRIDGE AVAILABILITY CLAIM, TESTED RATHER THAN ASSERTED.
    ///
    /// I read the code and said a bridged credit "rides the next block THIS node produces", so a deposit
    /// accepted by a node that never mines exists on one node and nowhere else. That is a root cause stated
    /// from reading, and reading is not evidence. This measures it in three steps:
    ///   1. A accepts a credit the way `execute_peg_in` / `execute_wrapped_mint` end — `record_note_payload`.
    ///   2. A does NOT produce. B must not hold it. If B somehow does, my claim was wrong.
    ///   3. A produces once and B grafts. B must now hold it — which pins that the mechanism works and that
    ///      PRODUCTION, not verification, is the thing standing between a user and their deposit.
    #[test]
    fn a_bridge_credit_reaches_a_peer_only_once_the_accepting_node_produces() {
        let mut a = party();
        let mut b = party();
        let cm = *Hash32::hash(b"bridge-deposit-note").as_bytes();
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&cm);

        let h = a.tip_height();
        a.record_note_payload(h, &note);
        // ⭐ §BA — AND THE OBJECT THAT JUSTIFIES IT, which is what the production path stages too.
        //
        // This step's doc says it models "the way `execute_peg_in` / `execute_wrapped_mint` end". Those
        // paths PUBLISH a `BridgeCreditTx` and unstage the local copy; only a REFUSED publish leaves the
        // staged note, and that arm now stages the object beside it (`rpc_http`, the peg-in fallback).
        // Staging the note ALONE models a credit nothing justifies — the §BA plant — so without this the
        // fixture would be asserting that the hole is still open.
        a.stage_credit_justifier(
            crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id: cm,
                asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                amount: 1_000,
                note: note.clone(),
                owner_clue: Vec::new(),
                attestors: Vec::new(),
            }
            .wire(),
        );
        assert!(
            !b.holds_record_with_cm(&cm),
            "setup: B cannot already hold a note A has only just accepted"
        );

        // STEP 2 — A stays quiet, as a joiner or a freshly restarted node does.
        assert!(
            !b.holds_record_with_cm(&cm),
            "a bridged credit reached the peer with NO block produced — then my reading was wrong and the \
             credit travels by some other path; find it before trusting this claim"
        );

        // STEP 3 — one block from A, and only now does the deposit exist for anyone else.
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a
            .produce(now, Hash32::hash(b"bridge-carry"), Hash32::hash(b"miner"))
            .expect("A produces the block that carries its staged credit");
        assert!(
            matches!(b.ingest_block(blk, now + 1), RelayOutcome::Added(_)),
            "B grafts A's block"
        );
        assert!(
            b.holds_record_with_cm(&cm),
            "⛔ the credit did NOT reach B even after A produced and B grafted — then bridged deposits do \
             not travel at all, which is worse than the availability gap I claimed"
        );
    }

    /// ⭐⭐⭐ WHAT "BRIDGE LAUNCH READY" MEANS — AND IT IS NO LONGER A FAILING PIN (2026-09-16).
    ///
    /// A user's deposit must exist for the NETWORK once the gates pass — not once the particular node that
    /// happened to accept it gets around to mining. This pin was `#[ignore]`d with the reason *"fails until
    /// a bridge credit is a transaction any producer can include"*, and it stayed ignored after that became
    /// true, because **the pin exercised the wrong door**: it called `record_note_payload` — the raw
    /// `pending_credit_notes` staging — which by construction only ever rides the accepting node's own
    /// block. `bridge_credit_tx` exists, `/faucet_drip` and both peg execute routes publish through it
    /// (*"nothing was staged and nothing rides a block"* on refusal), and no test asked whether the
    /// published shape actually travels.
    ///
    /// ⛔ THAT IS THE §AK SHAPE AGAIN, in the harness instead of the product: a class filed UNPROVEN for a
    /// blocker that had already been removed, kept there by a pin measuring a path nobody uses. An
    /// `#[ignore]` with a SPEC reason is a promise to re-measure when the spec lands, and nothing re-read
    /// it. The pin now drives the door a real deposit drives.
    ///
    /// THE PROPERTY, stated as the test asserts it: **A accepts and stays quiet; B produces; the deposit
    /// exists for everyone.** A never mines. If this goes red, a confirmed deposit again depends on which
    /// node wins a block, which is what a user experiences as money that is not there.
    #[test]
    fn a_bridge_credit_reaches_the_network_without_the_accepting_node_producing() {
        let mut a = party();
        let mut b = party();
        let cm = *Hash32::hash(b"bridge-deposit-must-travel").as_bytes();
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&cm);

        // The gates have passed; the deposit is real. A accepts it THE WAY THE BRIDGE DOES — as a published
        // transaction, never as a local staging. `/faucet_drip`, `/peg_in_execute` and `/peg_out_execute`
        // all build exactly this object and hand it to `ingest_tx`.
        let credit = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: *Hash32::hash(b"bridge-deposit-id").as_bytes(),
            asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            amount: 1_000,
            note: note.clone(),
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        let bits = a.mempool().required_stamp_bits();
        let tx = credit.as_pq_tx(bits);
        a.ingest_tx(tx.clone()).expect("A admits the deposit it accepted");
        assert!(
            !a.holds_record_with_cm(&cm),
            "a POOLED credit is not yet money — it becomes money when a block carries it, on every node              at once. If A holds it already, the credit was staged as well as published and the accepting              node's producer will skip its own transaction ([assemble-dup])."
        );

        // The tx reaches B the way every transaction does. A NEVER MINES from here on.
        b.ingest_tx(tx).expect("B admits the same deposit from the pool");

        // B PRODUCES, not A.
        let now = b.dag().get(&b.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + b.params().target_spacing_ms;
        let blk = b
            .produce(now, Hash32::hash(b"any-producer"), Hash32::hash(b"miner"))
            .expect("B produces a block carrying a deposit it did not accept");
        assert!(
            matches!(a.ingest_block(blk, now + 1), RelayOutcome::Added(_)),
            "A grafts the block that carries its own user's deposit"
        );

        assert!(
            b.holds_record_with_cm(&cm),
            "⛔ FUND SAFETY: the producer that included the deposit does not hold it. A user's deposit              exists only on the node that accepted it — a quiet node holds funds the network cannot see,              which is what a user experiences as a confirmed deposit that is not there."
        );
        assert!(
            a.holds_record_with_cm(&cm),
            "⛔ FUND SAFETY: the ACCEPTING node does not hold the deposit after grafting the block that              carries it. Publishing instead of staging must not cost the acceptor its own user's money."
        );
    }

    /// ⭐ THE SAFETY QUESTION THAT DECIDES THE BRIDGE FIX, MEASURED BEFORE I BUILD ON IT.
    ///
    /// The fix for the availability gap is to publish a bridge credit as a transaction so ANY producer can
    /// include it. The trap: the accepting node has ALSO staged that note locally, so the same commitment
    /// could arrive twice — once from its own staging and once from a peer's block. If note application is
    /// not idempotent by commitment, that is inflation, and inflation is the one bug worth more than the
    /// availability it fixes.
    ///
    /// So: record the same note twice on one node and demand it be held ONCE.
    #[test]
    fn crediting_the_same_note_commitment_twice_credits_it_once() {
        let mut a = party();
        let cm = *Hash32::hash(b"a-note-that-must-not-double").as_bytes();
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&cm);

        let h = a.tip_height();
        a.record_note_payload(h, &note);
        a.record_note_payload(h, &note); // the same deposit, arriving a second way

        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a
            .produce(now, Hash32::hash(b"dup-credit"), Hash32::hash(b"miner"))
            .expect("A produces the block carrying its staged credits");

        // Count how many times this commitment appears in what the block actually publishes.
        let mut seen = 0usize;
        let mut off = 0usize;
        while off + 32 <= blk.output_notes.len() {
            if blk.output_notes[off..off + 32] == cm[..] {
                seen += 1;
            }
            off += crate::cover::PQ_NOTE_BYTES;
        }
        assert_eq!(
            seen, 1,
            "⛔ INFLATION RISK: one deposit's commitment rides the block {seen} times. Publishing a bridge \
             credit as a transaction while it is ALSO staged locally would mint it twice — the fix must \
             publish INSTEAD of staging, not as well as."
        );
    }

    /// How many times `cm` exists in this node's RECORDS — the exactly-once meter for a settlement's
    /// credit. Counts OCCURRENCES, not records: one block carrying a commitment twice is the same
    /// inflation as two blocks carrying it once each, and a per-record bool would read both as "1".
    pub(crate) fn cm_occurrences(node: &Node, cm: &[u8; 32]) -> usize {
        node.records_containing_cm(cm)
            .iter()
            .map(|(_, notes, _)| {
                notes
                    .chunks(crate::cover::PQ_NOTE_BYTES)
                    .filter(|n| n.len() >= 32 && n[..32] == cm[..])
                    .count()
            })
            .sum()
    }

    /// ⭐⭐⭐ THE TIER-2 SETTLEMENT PIN — a fill submitted on ONE party settles on a SECOND exactly once,
    /// from the block's own carried set, with the block authored by a THIRD party that never saw the RPC.
    ///
    /// This is the 2026-09-03 double-payout law run end to end on the tx path: the settlement must ride a
    /// FRAMED chain object (`OrderFillTx::wire`) through the mempool, be includable by ANY producer, and
    /// apply on a node that pooled NOTHING — notes from `Block::output_notes`, burns from the padded tag
    /// lane, owner filing from the block's carried account targets, order retirement from the burns. A
    /// replay of the same framed fill must then be REFUSED by the spent-position set on the node that only
    /// ever grafted.
    ///
    /// RED 2026-09-06, run before the fix (both halves measured, this test, this assertion order):
    ///   * the settlement tx A published carried ZERO account-target bytes, so producer C staged nothing
    ///     and B's bucket answer for the maker was byte-identical to a bucket nobody ever used — the
    ///     maker's payout settled unfindable off the settling node;
    ///   * A staged the three payout notes (`record_note_payload` → `stage_credit_note`) BESIDE the
    ///     published tx that already carried them, so A's next produced block carried the maker's
    ///     commitment AGAIN and B's records held it TWICE — the same measured inflation class item 8(c)
    ///     closed for bridge credits, open for fills.
    /// GREEN with the fill tx carrying its targets (`carried_account_targets`) and the staging removed —
    /// the transaction is the ONE carriage.
    /// ⭐ §BR-14 item 4 — the trade with the assets SWAPPED: the maker sells the wrapped token for USDm, so the taker's fee
    /// (`ceil(pay_b × bps / 10,000)`) is paid in USDm and joins the pools.
    fn a_usdm_paid_trade() -> (OrderTerms, RestingOrder, (Vec<u8>, usdm_decider::whir_rec_block::TakerHalfPublic), [Vec<u8>; 3]) {
        let t = OrderTerms { asset_a: wrapped_asset_tag_u32(1), asset_b: USDM_ASSET_TAG, ..terms() };
        let (mw, tw) = witnesses();
        let (mc, mp) = prove_order_maker_half(&mw, &t).expect("the maker half proves");
        let (tc, tp) =
            prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).expect("the taker half proves");
        let notes = [note_for(mp.payout_cm), note_for(tp.payout_cm), note_for(tp.change_cm)];
        let resting = RestingOrder { terms: t, maker: mp, maker_bytes: mc, payout_note: notes[0].clone(), membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };
        (t, resting, (tc, tp), notes)
    }

    /// One trade settled on A, carried in C's block, grafted by B, then one more block so every party folds it. Returns
    /// each party's fee-pool total before the fill block and after it folded: (A, B, C).
    fn pools_around_a_settled_fill(
        trade: (OrderTerms, RestingOrder, (Vec<u8>, usdm_decider::whir_rec_block::TakerHalfPublic), [Vec<u8>; 3]),
    ) -> [(u128, u128); 3] {
        let (t, resting, (tc, tp), [n0, n1, n2]) = trade;
        let (mut a, mut b, mut c) = (party(), party(), party());
        let _ = a.post_order(resting.clone()).expect("rests on A");
        let _ = gossip_order(&resting, &mut b);
        let _ = gossip_order(&resting, &mut c);
        let (mb, tb, planted) = trade_binds(&mut a, &t, &resting.maker, &tp, 75_000);
        deliver_planted(&planted, &mut b, 75_000);
        deliver_planted(&planted, &mut c, 75_000);
        let before = [a.peg().fee_pools().total(), b.peg().fee_pools().total(), c.peg().fee_pools().total()];
        assert_eq!(
            a.execute_order_fill(&resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)], [Some(mb.clone()), Some(tb.clone())]),
            OrderFillOutcome::Settled,
            "A settles the fill"
        );
        let tx = published_fill_tx(&a, &t, &resting, &tc, &tp, &[n0.clone(), n1.clone(), n2.clone()], (&mb, &tb));
        c.ingest_tx(tx).expect("C pools the gossiped settlement");
        let now = c.dag().get(&c.selected_tip().expect("tip")).expect("hdr").header.timestamp + c.params().target_spacing_ms;
        let blk = c.produce(now, Hash32::hash(b"br14-dex-carry"), Hash32::hash(b"miner-c")).expect("C carries the fill");
        assert!(matches!(b.ingest_block(blk.clone(), now + 1), RelayOutcome::Added(_)), "B grafts C's block");
        assert!(matches!(a.ingest_block(blk, now + 1), RelayOutcome::Added(_)), "A grafts C's block");
        // one more block so the fill's block folds on every party (fold at the tip)
        let next = c.produce(now + 600, Hash32::hash(b"br14-dex-next"), Hash32::hash(b"miner-c")).expect("C lays the next block");
        let _ = b.ingest_block(next.clone(), now + 601);
        let _ = a.ingest_block(next, now + 601);
        for n in [&mut a, &mut b, &mut c] {
            let _ = n.fold_canonical_records();
        }
        let after = [a.peg().fee_pools().total(), b.peg().fee_pools().total(), c.peg().fee_pools().total()];
        [(before[0], after[0]), (before[1], after[1]), (before[2], after[2])]
    }

    /// ⭐⭐⭐ §BR-14 item 4 — A DEX TAKER FEE PAID IN USDm JOINS THE POOLS, ON EVERY PARTY. The same trade settled twice: paid
    /// in a wrapped token (CONTROL — the fee stays burned in that asset, the pools take only what the rest of the step
    /// credits) and paid in USDm. On A (the settler), B (fed only the block) and C (the carrying producer) the USDm-paid
    /// step credits EXACTLY `ceil(pay_b × bps / 10,000)` more than the control, and the three parties agree.
    /// TWO-PARTY-REVIEWED: every number is read from each party's own pools.
    #[test]
    fn br14_a_usdm_paid_dex_fee_joins_the_four_pools_on_every_party() {
        let control = pools_around_a_settled_fill(a_real_trade());
        let usdm = pools_around_a_settled_fill(a_usdm_paid_trade());
        let t = a_usdm_paid_trade().0;
        let fee = (u128::from(t.pay_b) * u128::from(crate::params::ORDER_FILL_FEE_BPS_DEFAULT)).div_ceil(10_000);
        assert!(fee > 0, "CALIBRATION: the trade's fee is not zero");
        eprintln!("[br14-dex] control (token-paid) pools {control:?} · USDm-paid {usdm:?} · fee {fee}");
        for (who, (c, u)) in ["A", "B", "C"].iter().zip(control.iter().zip(usdm.iter())) {
            assert_eq!(c.0, u.0, "CALIBRATION: {who} starts both runs at the same pools");
            assert_eq!(
                (u.1 - u.0) - (c.1 - c.0),
                fee,
                "⛔ §BR-14 item 4: on {who} a USDm-paid DEX fee did not join the pools exactly (control delta {}, USDm delta {})",
                c.1 - c.0,
                u.1 - u.0
            );
        }
        assert!(usdm.iter().all(|p| p.1 == usdm[0].1), "⛔ the parties disagree on the pools after the USDm-paid fill: {usdm:?}");
    }

    #[test]
    fn a_fill_submitted_on_one_party_settles_on_a_second_exactly_once_from_the_block_alone() {
        // Three parties, and every value assertion below reads what a PEER holds — two nodes that never
        // saw the fill submission (`b` grafts only, `c` pools and produces), never the submitting node's
        // own return values.
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party(); // receives the fill submission and settles
        let mut b = party(); // never sees the RPC, never pools the tx — applies the BLOCK alone
        let mut c = party(); // never sees the RPC either — it only POOLS the gossiped tx and produces

        let _level = a.post_order(resting.clone()).expect("rests on A");
        let b_level = gossip_order(&resting, &mut b);
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp, 75_000);
        deliver_planted(&planted_a, &mut b, 75_000);
        deliver_planted(&planted_a, &mut c, 75_000);
        assert_eq!(
            a.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "A settles the submitted fill"
        );

        // The settlement A published, taken from A's own pool by its canonical id — the id is the content
        // id of the framed wire bytes, so the test cannot drift from what actually travelled.
        let tx = published_fill_tx(&a, &t, &resting, &tc, &tp, &[n0.clone(), n1.clone(), n2.clone()], (&mb_a, &tb_a));
        // ⭐ HOLE-CLOSURE EXTENSION (2026-09-06): the settlement carries its self-built recursive
        // absence carrier — the SAME admission authority every spend class is judged by. Without it
        // the pool door refuses the fill on every party (the RED-first pin above), so its presence
        // here is what the exactly-once settlement below rides on.
        assert_eq!(
            tx.nullifier_absence.len(),
            1,
            "⛔ the settlement tx carries no recursive absence carrier — the pool door judges every \
             class by it, and a carrier-less fill is refused on every party"
        );
        // DECLARED AMENDMENT (DB-273 §19.6 L3): this asserted the tx carried ACCOUNT TARGETS. The invariant — the owners
        // travel with the settlement, so a block authored anywhere files the maker's payout — is now carried by the
        // OBJECT itself (`OrderFillTx::owner_clues`, filed by every node through `object_owner_clue_records`).
        assert_eq!(
            crate::chain_object::object_owner_clue_records(&tx.blob).map(|r| r.len()),
            Some(3),
            "⛔ the settlement object names no owners — only the settling node could file the maker's payout, so a \
             block authored anywhere else settles the money unfindable (the measured 'findability depends on who won \
             authorship' class)"
        );

        // The tx GOSSIPS: C admits it through the same door a runtime peer does, judged by its class.
        c.ingest_tx(tx.clone())
            .expect("a gossiped settlement is admissible on a node that never saw the RPC");
        let now = c
            .dag()
            .get(&c.selected_tip().expect("tip"))
            .expect("hdr")
            .header
            .timestamp
            + c.params().target_spacing_ms;
        let blk = c
            .produce(now, Hash32::hash(b"third-party-carry"), Hash32::hash(b"miner-c"))
            .expect("C — not the settling node — produces the block that carries the settlement");
        let maker_cm = crate::spend_frontier::leaf_to_cm_bytes(resting.maker.payout_cm);
        let carried = blk
            .output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .filter(|n| n.len() >= 32 && n[..32] == maker_cm[..])
            .count();
        assert_eq!(carried, 1, "the block carries the maker's payout exactly once");

        // B applies the BLOCK ALONE: its pool is empty before and after, so nothing it does here can have
        // come from its own mempool or its own book's opinion of the order.
        assert_eq!(b.mempool().len(), 0, "PRECONDITION: B pooled nothing");
        assert!(
            matches!(b.ingest_block(blk.clone(), now + 1), RelayOutcome::Added(_)),
            "B grafts C's block"
        );
        assert_eq!(b.mempool().len(), 0, "B applied the block without ever pooling the settlement");
        assert!(
            b.book_level(resting.pair(), b_level).0.is_empty(),
            "the block's burns retire the order from B's book — B needed none of the fill's bytes"
        );
        assert_eq!(
            cm_occurrences(&b, &maker_cm),
            1,
            "⛔ B must credit the maker EXACTLY once from the block"
        );
        // …and the credit is FINDABLE on B: the maker's bucket answer differs from a bucket nobody ever
        // used (buckets are cover-padded, so presence alone would measure nothing — the content is the
        // claim). The target could only have come from the BLOCK, because C staged it from the tx alone.
        let on_b = b.account_bucket_blob(&[1u8; 32]); // owner(1) — the maker's payout slot
        let cover_only = b.account_bucket_blob(&[0xABu8; 32]);
        assert_ne!(
            on_b, cover_only,
            "⛔ B holds NO filed target for the maker's payout — the settlement crossed but the money is \
             unfindable on every node except the one that took the fill"
        );

        // REPLAY, both doors, on the node that only grafted. The graft door meets the spent position set;
        // the pool door meets the witness gate against B's advanced accumulator.
        let replay = crate::node::objects::order_fill_tx::apply_chain_dex_object(&mut b, &tx.blob);
        assert_eq!(
            replay,
            crate::order_fill_tx::DexApply::Fill(OrderFillOutcome::OrderAlreadyFilled),
            "⛔ FUND SAFETY: B accepted a REPLAY of a settlement it already applied (got {replay:?}) — the \
             maker's lot would pay out twice"
        );
        assert!(
            b.ingest_tx(tx.clone()).is_err(),
            "⛔ B's pool re-admitted the settled fill — its burns are in the spent set, so the carried \
             witnesses must refuse"
        );

        // ⭐ THE STAGED-DUPLICATE AXIS. A converges on C's block and then produces its OWN next block. If
        // the settling node kept a second, staged copy of the payout notes beside the published tx, it
        // rides HERE — and B, grafting it, would credit the maker a second time at a second address.
        assert!(
            matches!(a.ingest_block(blk, now + 1), RelayOutcome::Added(_)),
            "A grafts C's block too, so its next produce follows the carried settlement"
        );
        let now2 = now + a.params().target_spacing_ms;
        let blk2 = a
            .produce(now2, Hash32::hash(b"a-next"), Hash32::hash(b"miner-a"))
            .expect("A produces its next block after the settlement was already carried");
        let _ = b.ingest_block(blk2, now2 + 1);
        assert_eq!(
            cm_occurrences(&b, &maker_cm),
            1,
            "⛔ INFLATION: the settling node carried the maker's payout AGAIN in its next block — the \
             published transaction and a locally staged copy are TWO carriages of one credit"
        );
    }

    /// ⭐⭐⭐ RED-TEAM TAMPER PIN (2026-09-06) — ONE SETTLEMENT, ONE CARRIAGE: when the SETTLING node
    /// itself produces the next block, each payout note must still ride the chain EXACTLY once.
    /// TWO PARTIES, both consulted: the fill settles on `node_a`, `node_a` produces, the block
    /// crosses to `node_b` by `ingest_block`, and the exactly-once verdict is read on BOTH nodes'
    /// record stores.
    ///
    /// CONFIRMED INFLATION CARRIAGE, MEASURED 2026-09-06 by this shape's first run: `assertion
    /// left == right failed: the maker payout must ride the chain EXACTLY once — left: 2, right: 1`,
    /// on the PEER. Mechanism, read at the two sites: `execute_order_fill` step 7 (node.rs:14483)
    /// calls `record_note_payload(h, payload)` for each payout note, and `record_note_payload`
    /// (node.rs:3707) is pure STAGING — `stage_credit_note` per note — so the three notes ride the
    /// settling node's NEXT produced block IN ADDITION to the published settlement transaction whose
    /// `output_notes` already carry them. One settlement, two carriages of each payout; every node
    /// (peer included) records the payout twice. This is the staged-duplicate half the tier-2 pin
    /// above documents as fixed ("GREEN with ... the staging removed") — that half is NOT in this
    /// tree: the tier-2 pin itself is RED at its line-622 assertion (measured this session).
    ///
    /// Why this is a funds hazard: the DA IS the ledger — a note recorded at two addresses is
    /// re-receivable at the second address once the first copy is spent (the resurrection seam
    /// pinned in node.rs `a_spent_credit_replayed_in_a_later_block_does_not_resurrect_into_the_
    /// unspent_set`), and the doubled carriage is on-chain inflation of the settlement's notes.
    ///
    /// THIS PIN STAYS RED AS THE SPECIFICATION OF THE FIX (consensus lane, node.rs): delete the
    /// step-7 staging — the published transaction is the ONE carriage (the same law item 8(c)
    /// enforces for bridge credits). Never fix it by weakening these assertions — this pin weakens
    /// no gate and skips nothing: it only READS both nodes' record stores.
    ///
    /// cons: none — test-only code (#[cfg(test)] mod): two in-memory testnet nodes, one block,
    /// persists nothing; every count is f(this one settlement's fixed 3-note shape), no history term.
    #[test]
    fn a_settlements_notes_are_recorded_exactly_once_on_the_settling_node_too() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut node_a = party(); // settles the fill AND grafts the block that carries it
        let mut node_b = party(); // the peer — the exactly-once baseline node_a must match

        let _ = node_a.post_order(resting.clone()).expect("rests on node_a");
        let _ = gossip_order(&resting, &mut node_b);
        let (mb_a, tb_a, planted_a) = trade_binds(&mut node_a, &t, &resting.maker, &tp, 76_000);
        deliver_planted(&planted_a, &mut node_b, 76_000);
        assert_eq!(
            node_a.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "the fill settles on node_a"
        );
        let ts = node_a.dag().get(&node_a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + node_a.params().target_spacing_ms;
        let blk = node_a
            .produce(ts, Hash32::hash(b"once-f"), Hash32::hash(b"once-m"))
            .expect("node_a produces the block carrying its own settlement");
        assert!(
            matches!(node_b.ingest_block(blk, ts + 1), RelayOutcome::Added(_)),
            "node_b grafts"
        );

        for (what, cm) in [
            ("maker payout", crate::spend_frontier::leaf_to_cm_bytes(resting.maker.payout_cm)),
            ("taker payout", crate::spend_frontier::leaf_to_cm_bytes(tp.payout_cm)),
            ("taker change", crate::spend_frontier::leaf_to_cm_bytes(tp.change_cm)),
        ] {
            for (name, n) in [("node_a", &node_a), ("node_b", &node_b)] {
                assert_eq!(
                    cm_occurrences(n, &cm),
                    1,
                    "⛔ DOUBLE CARRIAGE: {name} holds the {what} more than once — the settlement \
                     tx's output_notes AND the step-7 staged copy both rode the block; the \
                     published transaction must be the ONE carriage"
                );
            }
        }
    }

    /// The race both DB-358 fill pins below share (two parties, lane-db224-carriage, 2026-09-30).
    ///
    /// A DEX fill is a TWO-real-tag item: the maker's lot nullifier and the taker's spend nullifier. A's pool fills
    /// the lot with taker 1 and B's pool with taker 2, and each lays its fill in its own block, X and Y, siblings. Both
    /// parties then graft both blocks and fold.
    ///
    /// `sibling_fold_depth` is the record fold lag in force once the inputs are planted (they plant at the tip, because
    /// a membership bind names a FOLDED record):
    /// - `2`, production's shape in miniature: the two sibling blocks meet while BOTH are unfolded;
    /// - `0`: each producer folds its own block before its sibling arrives — DB-358 residual 4's regime (a lane met
    ///   after the fold, decided from an arrival-time memo).
    ///
    /// Returns the parties, the two takers' payout cms and the two takers' input nullifiers.
    fn db358_fill_race(sibling_fold_depth: u64) -> (Node, Node, [[u8; 32]; 2], [Hash32; 2]) {
        let (t, resting, (tc1, tp1), [n0, n1a, n1b]) = a_real_trade();
        let tw2 = TakerHalfWitness {
            value_in: 10_000_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[9_001, 9_002, 9_003, 9_004])),
            change_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_011, 9_012, 9_013, 9_014]),
            payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_021, 9_022, 9_023, 9_024]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        let (tc2, tp2) = prove_order_taker_half(&tw2, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT)
            .expect("the second taker's half proves");
        let (n2a, n2b) = (note_for(tp2.payout_cm), note_for(tp2.change_cm));
        let mut a = party();
        let mut b = party();
        let _ = a.post_order(resting.clone()).expect("rests on A");
        let _ = gossip_order(&resting, &mut b);
        // Both parties hold every input note on chain: the maker's and taker 1's (planted on A), taker 2's (on B).
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp1, 72_000);
        deliver_planted(&planted_a, &mut b, 72_000);
        let (mb_b, _taker1_bind_on_b, mut planted_b) = trade_binds(&mut b, &t, &resting.maker, &tp1, 73_000);
        let taker2_cm = crate::spend_frontier::leaf_to_cm_bytes(asset_note_cm(tw2.value_in, t.asset_b, tw2.owner.opening()));
        let (k2c, k2t, k2b) = b
            .plant_note_and_bind_for_test(&taker2_cm, tp2.nullifier, b"dex-taker2-note", 73_800)
            .expect("taker 2's input note lands on chain and its membership proves");
        planted_b.push(k2b);
        deliver_planted(&planted_b, &mut a, 74_000);
        for n in [&mut a, &mut b] {
            let mut p = n.params().clone();
            p.record_fold_depth = sibling_fold_depth;
            n.set_params(p);
        }
        assert_eq!(
            a.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc1, &tp1, &t, &n0, &n1a, &n1b,
                [owner(1), owner(2), owner(3)],
                [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "PRECONDITION: A publishes taker 1's fill"
        );
        assert_eq!(
            b.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc2, &tp2, &t, &n0, &n2a, &n2b,
                [owner(1), owner(4), owner(5)],
                [Some(mb_b.clone()), Some((k2c, k2t))]),
            OrderFillOutcome::Settled,
            "PRECONDITION: B, having heard nothing of A's fill, publishes taker 2's"
        );
        let next = |n: &Node| {
            n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
        };
        let (ts_a, ts_b) = (next(&a), next(&b));
        let x = a.produce(ts_a, Hash32::hash(b"r5-x"), Hash32::hash(b"r5-miner-a")).expect("A lays taker 1's fill");
        let y = b.produce(ts_b, Hash32::hash(b"r5-y"), Hash32::hash(b"r5-miner-b")).expect("B lays taker 2's fill");
        let now = ts_a.max(ts_b) + 400;
        assert!(matches!(a.ingest_block(y, now), RelayOutcome::Added(_)), "A grafts B's sibling block");
        assert!(matches!(b.ingest_block(x, now), RelayOutcome::Added(_)), "B grafts A's sibling block");
        let _ = a.fold_past_for_test(&mut [&mut b], now, b"r5-fold");

        let payouts = [
            crate::spend_frontier::leaf_to_cm_bytes(tp1.payout_cm),
            crate::spend_frontier::leaf_to_cm_bytes(tp2.payout_cm),
        ];
        let inputs = [
            Hash32(crate::spend_frontier::leaf_to_cm_bytes(tp1.nullifier)),
            Hash32(crate::spend_frontier::leaf_to_cm_bytes(tp2.nullifier)),
        ];
        let paid = |n: &Node, cm: &[u8; 32]| cm_occurrences(n, cm) >= 1;
        eprintln!(
            "[db358-fill-race] paid: A t1={} t2={} | B t1={} t2={}; input spent: A t1={} t2={} | B t1={} t2={}",
            paid(&a, &payouts[0]), paid(&a, &payouts[1]), paid(&b, &payouts[0]), paid(&b, &payouts[1]),
            a.is_nullifier_spent(&inputs[0]), a.is_nullifier_spent(&inputs[1]),
            b.is_nullifier_spent(&inputs[0]), b.is_nullifier_spent(&inputs[1])
        );
        (a, b, payouts, inputs)
    }

    /// ⛔⛔⛔ DB-358, THE FILL CLASS (census gap, found 2026-09-30) — TWO FILLS OF ONE LOT IN SIBLING BLOCKS PAY THE LOT
    /// EXACTLY ONCE, ON BOTH PARTIES.
    ///
    /// Two parties; the verdict is read from what each PEER holds (`db358_fill_race`).
    /// - Canonical order must pick ONE winner of the lot tag.
    /// - DB-358's fold revokes the loser's outputs — but only for ITEMS, and an item is a spend tuple or a credit-set
    ///   object with own nullifiers (`object_own_nullifiers`), which had no `OrderFill` arm.
    ///
    /// MEASURED RED 08:43 without it: `paid: A t1=true t2=true | B t1=true t2=true`. The maker's one lot paid out
    /// twice on both parties — the 2026-09-03 class, through the concurrent-block path.
    ///
    /// The claims: exactly one taker is paid on each party, and it is the SAME taker on both (one record).
    #[test]
    fn db358_two_fills_of_one_lot_in_sibling_blocks_pay_the_lot_exactly_once_on_both_parties() {
        let (a, b, payouts, _inputs) = db358_fill_race(2);
        let paid = |n: &Node, cm: &[u8; 32]| cm_occurrences(n, cm) >= 1;
        assert_eq!(
            u8::from(paid(&a, &payouts[0])) + u8::from(paid(&a, &payouts[1])),
            1,
            "⛔⛔⛔ A paid both takers of ONE lot"
        );
        assert_eq!(
            u8::from(paid(&b, &payouts[0])) + u8::from(paid(&b, &payouts[1])),
            1,
            "⛔⛔⛔ the peer B paid both takers of ONE lot"
        );
        assert_eq!(paid(&a, &payouts[0]), paid(&b, &payouts[0]), "⛔⛔ A and the peer B paid DIFFERENT takers");
    }

    /// ⛔⛔⛔ DB-358 RESIDUAL 5 (filed 2026-09-30, docs/DB-329 §7g) — THE LOSING TAKER KEEPS ITS INPUT, ON BOTH
    /// PARTIES.
    ///
    /// Two parties; the verdict is read from what each PEER holds (`db358_fill_race`).
    /// - The fold revokes the loser's OUTPUTS. But at graft the spent-set view folds the GRAFTED block's whole padded
    ///   lane (`adopt_sparse_via_block_fold`, one constant-width lane per graft), and `mined_tx_nfs` records every
    ///   mined tx's nullifiers. Neither knows the later fold verdict.
    /// - So the loser's FRESH spend nullifier reads as spent with no output to show for it. Losing a race costs the
    ///   loser its input: the single-node twin's rule
    ///   (`the_second_taker_to_race_one_order_is_refused_and_loses_nothing`), broken across a block race.
    ///
    /// EXPECTED RED until the band is the spent-set authority and every spent-set reader excludes a losing item's tags
    /// (DB-353 landing 2: `band_note_fold_step(…, &losers)`). It is that landing's acceptance pin, and §7e's claim
    /// sends wait for it.
    #[test]
    fn db358_r5_the_losing_taker_of_a_sibling_block_fill_race_keeps_its_input_on_both_parties() {
        let (a, b, payouts, inputs) = db358_fill_race(2);
        let paid = |n: &Node, cm: &[u8; 32]| cm_occurrences(n, cm) >= 1;
        for i in 0..2 {
            assert!(
                paid(&a, &payouts[i]) || !a.is_nullifier_spent(&inputs[i]),
                "⛔⛔⛔ DB-358 r5: on A, unpaid taker {}'s input is spent",
                i + 1
            );
            assert!(paid(&b, &payouts[i]) || !b.is_nullifier_spent(&inputs[i]), "⛔⛔⛔ r5: on the peer B, taker {}", i + 1);
        }
    }

    /// ⛔⛔⛔ DB-358 RESIDUAL 4, FOR FILLS — A LOT RACE MET AFTER EACH PRODUCER FOLDED ITS OWN BLOCK PAYS ONE TAKER ON BOTH
    /// PARTIES.
    ///
    /// Two parties; the verdict is read from what each PEER holds (`db358_fill_race(0)`).
    /// - With a zero fold lag each producer folds its own fill before its sibling arrives.
    /// - The sibling's first-contact memo then finds the lot tag already HELD, and marks it `old`. That is an
    ///   arrival-time fact, not canonical order.
    /// - So each party keeps ITS OWN taker. MEASURED 08:5x with the fill arm: `paid: A t1=true t2=false | B t1=false
    ///   t2=true`, i.e. one payout per party, but two different records.
    ///
    /// DB-358 names this residual 4 ("a reorg deeper than the fold lag") and its close: the canonical FOLD-POINT
    /// nullifier set, DB-353 band landing 2. EXPECTED RED until that lands. In production the lag is 32 blocks, so the
    /// common race meets both lanes unfolded (`…pay_the_lot_exactly_once…`, lag 2).
    #[test]
    fn db358_r4_a_fill_race_met_after_both_producers_folded_pays_the_same_taker_on_both_parties() {
        let (a, b, payouts, _inputs) = db358_fill_race(0);
        let paid = |n: &Node, cm: &[u8; 32]| cm_occurrences(n, cm) >= 1;
        assert_eq!(
            u8::from(paid(&a, &payouts[0])) + u8::from(paid(&a, &payouts[1])),
            1,
            "A pays exactly one taker"
        );
        assert_eq!(
            u8::from(paid(&b, &payouts[0])) + u8::from(paid(&b, &payouts[1])),
            1,
            "the peer B pays exactly one taker"
        );
        assert_eq!(paid(&a, &payouts[0]), paid(&b, &payouts[0]), "⛔⛔ r4: A and the peer B paid DIFFERENT takers");
    }

    /// The block a producer lays carrying `fill` exactly as a producer seals one: its three notes in the block's notes and
    /// committed by the note carrier, the object in CARRIAGE form in the credit set (DB-224), its two burns in the lane —
    /// every root resealed, so the block passes every structural door. ONE recipe for the control and the rogue below.
    pub(crate) fn a_block_carrying_the_fill(producer: &mut Node, fill: &crate::order_fill_tx::OrderFillTx, at: u64) -> Block {
        let mut blk = producer
            .produce(at, Hash32::hash(b"carried-fill"), Hash32::hash(b"carried-fill-m"))
            .expect("the producer lays a block");
        blk.output_notes = fill.notes.concat();
        blk.header.output_notes_root = crate::block::da_notes_root_of(&blk.output_notes);
        blk.note_commitments = producer.note_commitment_carrier_for_test(&blk.output_notes);
        blk.header.note_commitments_root = Hash32::hash(&blk.note_commitments);
        let carriage = crate::chain_object::carriage_of(&fill.wire()).expect("a fill has a carriage form");
        (blk.credit_set, blk.wide_objects) = crate::block::seal_carriages(&[carriage], &crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).expect("the fixture block carries its cover key")).expect("the fixture's objects fit the sealed width");
        blk.header.credit_set_root = crate::block::credit_set_root_of(&blk.credit_set);
        for tag in fill.nullifier_tags() {
            blk.nullifier_proof.padded_tags.push(tag.0);
        }
        blk.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&blk.nullifier_proof.padded_tags);
        let own: Vec<[u8; 32]> = fill.nullifier_tags().iter().map(|t| t.0).collect();
        crate::node::tests::lay_tag_evidence_for_test(producer, &mut blk, &own);
        blk
    }

    /// ⛔⛔⛔ ROGUE-ROLE CENSUS (auditor protocol, 2026-10-03) — A ROGUE PRODUCER CARRIES A FILL WHOSE INPUTS NEVER EXISTED.
    ///
    /// DB-150 pinned the PUBLISHER door: `execute_order_fill` refuses a fill whose halves cannot show their input notes are
    /// on this chain. A PEER never runs that door for a block-carried fill (DB-224 skips the fill arm at graft); the fill's
    /// three notes are justified at `graft_admitted_notes` by `chain_object::admissible`, which re-verifies the COMPOSED
    /// PROOF only, and `OrderFill` is not a fold-applied class. A producer that frames the fill itself — both halves proven
    /// over notes no chain ever recorded, no membership binds — skips the one door that asks whether its inputs exist.
    ///
    /// CONTROL (same recipe, same trade): the two inputs are planted on chain first and the fill carries their real binds
    /// — the peer credits all three notes. ROGUE: the inputs never existed — the peer must credit NONE of the three.
    /// TWO-PARTY-REVIEWED: in each world R produces and B is the honest peer fed only R's blocks; every assertion is on B.
    #[test]
    fn a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_rogue_producer_carries_it() {
        // CROSS-NODE-REVIEWED: db224_a_fill_whose_inputs_a_real_chain_funded_settles_on_a_peer_fed_only_the_wire
        let (t, resting, (tc, tp), notes) = a_real_trade();
        let fill_with = |binds: [(Vec<u8>, Vec<u8>); 2]| {
            let [(mc, mt), (kc, kt)] = binds;
            crate::order_fill_tx::OrderFillTx {
                lot: t.lot,
                pay_b: t.pay_b,
                asset_a: t.asset_a,
                asset_b: t.asset_b,
                expires_at_height: t.expires_at_height,
                maker_nullifier: resting.maker.nullifier,
                maker_leaf_commit: resting.maker.leaf_commit,
                maker_payout_cm: resting.maker.payout_cm,
                maker_bytes: resting.maker_bytes.clone(),
                taker_nullifier: tp.nullifier,
                taker_leaf_commit: tp.leaf_commit,
                taker_payout_cm: tp.payout_cm,
                taker_change_cm: tp.change_cm,
                taker_bytes: tc.clone(),
                maker_membership_carrier: mc,
                maker_membership_tip: mt,
                taker_membership_carrier: kc,
                taker_membership_tip: kt,
                notes: notes.clone(),
                owner_clues: [owner(1), owner(2), owner(3)],
            }
        };
        let cms: Vec<[u8; 32]> = notes.iter().map(|n| <[u8; 32]>::try_from(&n[..32]).expect("a note leads with its cm")).collect();
        let credited = |n: &Node| cms.iter().filter(|cm| n.holds_record_with_cm(cm)).count();

        // CONTROL: the inputs are on chain, the fill carries their binds.
        let mut r1 = party();
        let mut b1 = party();
        let (mb, tb, planted) = trade_binds(&mut r1, &t, &resting.maker, &tp, 74_000);
        deliver_planted(&planted, &mut b1, 74_000);
        let honest = fill_with([mb, tb]);
        assert!(
            crate::chain_object::admissible(&honest.wire(), b1.params().order_fill_fee_bps, 0, false),
            "CALIBRATION: the fill is admissible at the peer's fee rate"
        );
        let blk = a_block_carrying_the_fill(&mut r1, &honest, 80_000);
        let out = b1.ingest_block_preverified(blk, 80_500);
        assert!(matches!(out, RelayOutcome::Added(_)), "CALIBRATION: the honest carriage is accepted: {out:?}");
        let _ = b1.fold_canonical_records();
        assert_eq!(credited(&b1), 3, "CALIBRATION: the recipe credits a fill whose inputs exist — all three notes on the peer");

        // ROGUE (substitute): the SAME honest fill — real inputs, real binds, a valid composed proof — with its taker payout
        // swapped for a note the proof never attested (a commitment the rogue chose, i.e. any value it likes). The publisher
        // door refuses this (`PayoutNoteMismatch`); the peer must not credit it either.
        let mut r3 = party();
        let mut b3 = party();
        let (mb3, tb3, planted3) = trade_binds(&mut r3, &t, &resting.maker, &tp, 74_000);
        deliver_planted(&planted3, &mut b3, 74_000);
        let mut swapped = fill_with([mb3, tb3]);
        let mut forged_note = notes[1].clone();
        forged_note[..32].copy_from_slice(Hash32::hash(b"a commitment the taker's proof never attested").as_bytes());
        swapped.notes[1] = forged_note.clone();
        assert!(
            crate::chain_object::admissible(&swapped.wire(), b3.params().order_fill_fee_bps, 0, false),
            "CALIBRATION: the swapped fill is admissible on its proof alone — the substitution is armed"
        );
        let blk = a_block_carrying_the_fill(&mut r3, &swapped, 80_000);
        let out = b3.ingest_block_preverified(blk, 80_500);
        eprintln!("[rogue-fill-swap] the peer's outcome for a block carrying a fill with a substituted payout: {out:?}");
        let _ = b3.fold_canonical_records();
        let forged_cm = <[u8; 32]>::try_from(&forged_note[..32]).expect("32 bytes");
        let swap_credited = b3.holds_record_with_cm(&forged_cm); // asserted below, after BOTH rogue arms are measured

        // ROGUE: the same trade, its inputs never on any chain, no binds.
        let mut r2 = party();
        let mut b2 = party();
        let rogue = fill_with([(Vec::new(), Vec::new()), (Vec::new(), Vec::new())]);
        assert!(
            crate::chain_object::admissible(&rogue.wire(), b2.params().order_fill_fee_bps, 0, false),
            "CALIBRATION: the rogue fill is admissible on its proof alone — the hole this pin asks about is armed"
        );
        let blk = a_block_carrying_the_fill(&mut r2, &rogue, 80_000);
        let out = b2.ingest_block_preverified(blk, 80_500);
        eprintln!("[rogue-fill] the peer's outcome for a block carrying a fill of notes that never existed: {out:?}");
        let _ = b2.fold_canonical_records();
        eprintln!(
            "[rogue-fill] MEASURED on the peers: a substituted payout credited = {swap_credited}; notes credited from a fill of \
             inputs that never existed = {}/3",
            credited(&b2)
        );
        assert!(
            !swap_credited,
            "⛔⛔⛔ ROGUE PRODUCER: the peer credited a fill note the proof never attested — a payout of any value the producer chose"
        );
        assert_eq!(
            credited(&b2),
            0,
            "⛔⛔⛔ ROGUE PRODUCER: the peer credited a fill whose inputs never existed — value minted from nothing \
             (maker payout, taker payout, taker change)"
        );
    }
}

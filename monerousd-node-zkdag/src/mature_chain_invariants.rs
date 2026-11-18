// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE INVARIANTS DECADES-OLD CHAINS ENFORCE, AS EXECUTABLE CHECKS AGAINST OUR LIVE CODE.**
//!
//! Not a reading list. Each test below encodes one rule that Bitcoin, Zcash or Ethereum enforces because
//! violating it cost somebody money, and asserts it against THIS node. A test that fails is a proven gap,
//! not an opinion — the same method that proved the DEX double-fill in 227 seconds after forty-five gate
//! runs missed it.
//!
//! THE COMMON ROOT we are testing for, in one sentence: **the chain is the only ledger, and a node's local
//! state is a cache derived from it.** Every reliability failure this project has chased — per-node
//! ordinals, per-node readiness, per-node heal, the per-node burn — is a place where local state was
//! treated as truth. These checks look for the remaining ones.
//!
//! SCOPE: in-process, real `Node` values, production genesis path. An island, as always: the live pair gate
//! and the multi-device run remain the network proofs and are a follow-on to every run here.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    fn party() -> Node {
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
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            credit_set: Vec::new(),
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
        prove_order_maker_half, prove_order_taker_half, wrapped_asset_tag_u32, MakerHalfWitness,
        OrderTerms, TakerHalfWitness, USDM_ASSET_TAG,
    };

    fn note_for(cm: crate::spend_frontier::Digest4) -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        n
    }
    /// DB-273 §19.6 L3: a fill slot's owner is an OLI clue; a distinct non-empty value per seed.
    fn owner(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    #[allow(clippy::type_complexity)]
    /// ⭐ DB-150 — the two INPUT note commitments of this fixture's trade, and the binds that prove them.
    /// A fill must show both notes are in the chain's note frontier; a fixture that cannot name them
    /// cannot put them there, so it would be asserting over a trade between notes that do not exist.
    fn trade_witnesses() -> (MakerHalfWitness, TakerHalfWitness) {
        (
            MakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[9_001, 9_002, 9_003, 9_004])),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_011, 9_012, 9_013, 9_014]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            TakerHalfWitness {
                value_in: 10_000_000,
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[9_101, 9_102, 9_103, 9_104])),
                change_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_111, 9_112, 9_113, 9_114]),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[9_121, 9_122, 9_123, 9_124]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
        )
    }

    /// Put BOTH input notes on `n`'s chain and build the two membership cross-binds the fill carries.
    fn trade_binds(
        n: &mut Node,
        t: &OrderTerms,
        maker: &usdm_decider::whir_rec_block::MakerHalfPublic,
        taker: &usdm_decider::whir_rec_block::TakerHalfPublic,
        now_ms: u64,
    ) -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>), Vec<crate::block::Block>) {
        let (mw, tw) = trade_witnesses();
        let cm = |v: u64, asset: [u64; 3], sk: crate::spend_frontier::Digest4| -> [u8; 32] {
            crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
                v, asset, sk,
            ))
        };
        let (mc, mt, mb) = n
            .plant_note_and_bind_for_test(
                &cm(t.lot, t.asset_a, mw.owner.opening()),
                maker.nullifier,
                b"mature-maker-note",
                now_ms,
            )
            .expect("the maker's input note lands on chain and its membership proves");
        let (kc, kt, kb) = n
            .plant_note_and_bind_for_test(
                &cm(tw.value_in, t.asset_b, tw.owner.opening()),
                taker.nullifier,
                b"mature-taker-note",
                now_ms + 400,
            )
            .expect("the taker's input note lands on chain and its membership proves");
        ((mc, mt), (kc, kt), vec![mb, kb])
    }

    /// Deliver a plant's blocks to a peer and let it FOLD them — a bind is checked against folded state.
    fn deliver_planted(blocks: &[crate::block::Block], to: &mut Node, now_ms: u64) {
        for blk in blocks {
            to.ingest_block(blk.clone(), now_ms);
        }
        let _ = to.fold_canonical_records();
    }

    fn a_real_trade() -> (
        OrderTerms,
        RestingOrder,
        (Vec<u8>, usdm_decider::whir_rec_block::TakerHalfPublic),
        [Vec<u8>; 3],
    ) {
        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: USDM_ASSET_TAG,
            asset_b: wrapped_asset_tag_u32(1),
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        };
        let (mw, tw) = trade_witnesses();
        let (mc, mp) = prove_order_maker_half(&mw, &t).expect("maker half proves");
        let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT)
            .expect("taker half proves");
        let notes = [note_for(mp.payout_cm), note_for(tp.payout_cm), note_for(tp.change_cm)];
        let resting = RestingOrder { terms: t, maker: mp, maker_bytes: mc, payout_note: notes[0].clone() , membership_carrier: crate::order_book::test_membership_bind().0, membership_tip: crate::order_book::test_membership_bind().1, payout_clue: crate::order_book::test_payout_clue() };
        (t, resting, (tc, tp), notes)
    }

    /// ⭐ BITCOIN / ZCASH: **a note is spent ONCE, and a second attempt is refused by the ledger, not by
    /// luck.** Bitcoin refuses a duplicate input; Zcash refuses a nullifier already in the set. This is the
    /// same-node form of the check — the cross-node form is `dex_cross_party_scenarios`.
    #[test]
    fn the_same_order_cannot_be_filled_twice_on_one_node() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let (mb_a, tb_a, _planted) = trade_binds(&mut a, &t, &resting.maker, &tp, 82000);
        a.post_order(resting.clone()).expect("rests");
        assert_eq!(
            a.execute_order_fill(&resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)], [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "the first fill settles"
        );
        let second = a.execute_order_fill(&resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
            [owner(1), owner(2), owner(3)], [Some(mb_a.clone()), Some(tb_a.clone())]);
        assert_ne!(
            second, OrderFillOutcome::Settled,
            "⛔ FUND SAFETY: the same order filled twice on ONE node (got {second:?}) — the burn did not \
             stop the replay, which is the invariant every ledger since Bitcoin enforces first"
        );
    }

    /// ⭐ ETHEREUM / BITCOIN: **state is a function of the chain** — applied to the half of an exchange
    /// where it belongs, which is not the half I first assumed.
    ///
    /// ⛔ I WROTE THIS TEST DEMANDING THE WRONG THING, AND IT IS WORTH SAYING SO IN THE SOURCE. Its first
    /// form posted an offer on A by a side channel, gave B every block A produced, and required B to serve
    /// that offer. Passing it would mean every quote and every cancel is a block object. No exchange works
    /// that way and no chain should: quotes are the highest-volume, lowest-value message an exchange
    /// carries, they are traffic analysis material, and settling them would spend the block space that the
    /// trades themselves need. Serum put a book on chain and paid for it in exactly that coin.
    ///
    /// THE REAL SPLIT, and it is the same one Bitcoin makes between "an offer to sell" and "a transaction":
    ///
    ///   AN OFFER IS ADVISORY. It travels by gossip, it is verified from the maker's own half before any
    ///   node will serve it, and a node that has not heard it simply does not show it. Nothing is at risk
    ///   in a book that lags — a taker acting on a stale quote is REFUSED, they do not lose money.
    ///
    ///   WHICH OFFERS ARE DEAD IS CHAIN STATE, and that is the half that protects funds. It is derived
    ///   from the burns a block carries, on every node, with no message and no book gossip — see
    ///   `order_fill_tx::retire_orders_burned_by`. A book cannot serve an offer whose note the chain says
    ///   is spent, which is the only way a book can mislead anyone.
    ///
    /// So this asserts both halves: the offer converges by gossip, and the RETIREMENT is derived from the
    /// chain alone — proved on a node that received the block and nothing else.
    #[test]
    fn an_offer_travels_by_gossip_but_its_death_is_derived_from_the_chain() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let mut b = party();
        let (mb_a, tb_a, planted_a) = trade_binds(&mut a, &t, &resting.maker, &tp, 84000);
        deliver_planted(&planted_a, &mut b, 84000);
        let level = a.post_order(resting.clone()).expect("rests on A");

        // HALF ONE — the offer converges by gossip, and only by gossip.
        assert!(
            b.book_level(resting.pair(), level).0.is_empty(),
            "PRECONDITION: B has not heard the offer yet, and shows nothing rather than guessing"
        );
        let wire = postcard::to_allocvec(&crate::order_book::OrderWire::of(&resting))
            .expect("the offer serialises");
        let got: crate::order_book::OrderWire =
            postcard::from_bytes(&wire).expect("the offer deserialises");
        let b_level = b.post_order(got.into_order()).expect("B admits the gossiped offer on its own proof");
        assert_eq!(b_level, level, "both parties derive the same lattice level from the same terms");
        assert!(
            !b.book_level(resting.pair(), b_level).0.is_empty(),
            "once the offer has travelled, B serves it too"
        );

        // HALF TWO — its DEATH needs no book message at all. A settles the trade and produces; B is handed
        // that block and NOTHING else — no fill bytes, no cancel, no gossip — and must stop serving it.
        assert_eq!(
            a.execute_order_fill(
                &resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)],
             [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "A settles the trade it was serving"
        );
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a
            .produce(now, Hash32::hash(b"offer-death"), Hash32::hash(b"miner"))
            .expect("A produces the block carrying the settlement's burns");
        assert!(
            matches!(b.ingest_block(blk, now + 1), RelayOutcome::Added(_)),
            "B grafts the block"
        );
        assert!(
            b.book_level(resting.pair(), b_level).0.is_empty(),
            "⛔ A DEAD OFFER IS STILL SERVED: B holds the block whose burns spent this maker's note and \
             still advertises the order. That is the only way an advisory book can cost anyone money — \
             every taker who acts on it builds a fill that can only ever be refused."
        );
    }

    /// ⭐ BITCOIN: **applying the same block twice must not credit twice.** Re-delivery is normal on a
    /// gossip network; an apply that is not idempotent turns a duplicate packet into inflation.
    #[test]
    fn applying_the_same_block_twice_does_not_change_the_state_twice() {
        let mut a = party();
        let mut b = party();
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a.produce(now, Hash32::hash(b"idem"), Hash32::hash(b"m")).expect("produces");
        assert!(matches!(b.ingest_block(blk.clone(), now + 1), RelayOutcome::Added(_)), "first apply grafts");
        let (root_after_first, seq_after_first) = (b.spend_frontier_root(), b.served_seq());
        let _ = b.ingest_block(blk, now + 2); // the duplicate a real network always delivers
        assert_eq!(
            (b.spend_frontier_root(), b.served_seq()),
            (root_after_first, seq_after_first),
            "⛔ a re-delivered block changed the state again — on a gossip network that is inflation by \
             duplicate packet"
        );
    }

    /// ⭐ BITCOIN / ZCASH: **the chain is the ledger, so what a node applies must be derivable from what a
    /// block carries.** A fill applied out of band leaves no trace a peer can replay — this asserts the
    /// settlement is reachable from the block, which is the property `order_fill_tx` exists to give it.
    #[test]
    fn a_settlement_is_reachable_from_the_block_a_peer_receives() {
        let (t, resting, (tc, tp), [n0, n1, n2]) = a_real_trade();
        let mut a = party();
        let (mb_a, tb_a, _planted) = trade_binds(&mut a, &t, &resting.maker, &tp, 88000);
        a.post_order(resting.clone()).expect("rests");
        assert_eq!(
            a.execute_order_fill(&resting.maker_bytes, &resting.maker, &tc, &tp, &t, &n0, &n1, &n2,
                [owner(1), owner(2), owner(3)], [Some(mb_a.clone()), Some(tb_a.clone())]),
            OrderFillOutcome::Settled,
            "A settles the fill"
        );
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a.produce(now, Hash32::hash(b"carry"), Hash32::hash(b"m")).expect("A produces after the fill");
        // `padded_tags` are raw 32-byte tags, so compare in that shape — the same conversion the
        // nullifier lane itself uses.
        let maker_nf = crate::spend_frontier::leaf_to_cm_bytes(resting.maker.nullifier);
        let carried = blk.nullifier_proof.padded_tags.iter().any(|tag| *tag == maker_nf);
        assert!(
            carried,
            "⛔ THE SETTLEMENT IS NOT ON CHAIN: the block A produced after settling carries none of the \
             fill's burns, so no peer can reach the same state from the chain. This is the invariant our \
             own source states for account targets — a block must carry what is needed to apply it."
        );
    }

    /// ⭐ EVERY CHAIN: **a consensus object has ONE encoding.** Two encodings of the same object is a
    /// consensus split waiting for the first disagreement.
    #[test]
    fn a_consensus_object_has_exactly_one_encoding() {
        let (_t, resting, _h, _n) = a_real_trade();
        let a = postcard::to_allocvec(&OrderWire::of(&resting)).expect("encodes");
        let b = postcard::to_allocvec(&OrderWire::of(&resting)).expect("encodes");
        assert_eq!(a, b, "the same order encoded to two different byte strings");
        let back: OrderWire = postcard::from_bytes(&a).expect("decodes");
        assert_eq!(
            postcard::to_allocvec(&back).expect("re-encodes"),
            a,
            "⛔ encode(decode(x)) != x — a peer that re-serialises what it received would compute a \
             different id for the same object"
        );
    }


}

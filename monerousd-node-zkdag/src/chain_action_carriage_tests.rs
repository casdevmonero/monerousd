// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ CHAIN-ACTION **CARRIAGE** — the half the static sweep cannot see.
//!
//! [`crate::chain_action_manifest_tests`] proves a route PUBLISHES something. It cannot prove the
//! published object carries the WHOLE transition the handler performed, and that gap is not theoretical:
//! `/wrapped_mint_execute` PASSES the static sweep and still leaks state, because
//! `bridge_credit_tx::BridgeCreditTx` carries `{deposit_id, asset_tag, amount, note, owner}` and has NO
//! field for the peg's new reserve/minted commitments, while `apply_chain_bridge_credit` never advances
//! them. The minted NOTE travels; the COMMITMENT ADVANCE stays on whichever node answered the request.
//!
//! THIS FILE IS THE OTHER HALF, and it is a RUNTIME differential rather than a source scan: drive the
//! action on node A exactly as the production route drives it, hand node B **only what A published**, and
//! demand that B derives the same replicated state. That is the cold-peer question the whole tree is
//! built on — *a node fed only blocks must reach the same state* — asked of one route at a time.
//!
//! It reuses the comparison the harness already owns,
//! [`crate::harness::fuzz::authority_peg::peg_divergences`], rather than hand-picking fields: that
//! function compares the reserve/minted/HWM commitments, every ratio, the collateral-ratio census, the
//! per-wrapped-asset commitments and HWMs, the burn set and the deposit-id count. Its own module doc
//! says wiring it to a cold replay "is the next brick and is" not done — this is that brick. Picking
//! fields by hand is how the mint's commitment advance stayed invisible while a peg oracle sat beside it.
//!
//! ⛔ WHAT A GREEN RUN HERE MEANS: for the routes covered below, everything the peg ledger can tell two
//! nodes apart by travels on the chain. It says nothing about routes not covered — coverage is the whole
//! game for a runtime oracle, and the uncovered ones are named in `docs/FUNDS-LOSS-KILL-LIST.md` §V.

#[cfg(test)]
pub(crate) mod tests {
    use crate::harness::fuzz::authority_peg::peg_divergences;
    use crate::node::tests::genesis_block;
    use crate::node::Node;
    use crate::psm::MintAttestor;

    pub(crate) const ASSET: u32 = 11;
    /// The asset a PRICE MARK prices in these pins: the Bitcoin bridge ledger (USDm minted against a Bitcoin deposit).
    /// RE-MEASURED 2026-11-10: the two price-mark pins priced the registered wrapped asset [`ASSET`], and since the
    /// bridge's unit-for-unit rule (`PegLedger::reference_price`, 2026-11-08) a registered wrapped asset is one atom
    /// per atom whatever any mark says, so their CONTROL ("with no mark the deposit counts for nothing") read RED
    /// from that day. A mark still decides what a bridge ledger's deposit is worth; that is what they measure now.
    pub(crate) const PRICED: u32 = crate::peg::NATIVE_PEG_ASSET_ID;

    /// DB-273 §19 L1: a mint's owner is its note's OLI clue (one full-width clue), never a (bucket, ek) pair.
    pub(crate) fn owner_clue() -> Vec<u8> {
        vec![0xC1u8; crate::peg_in_tx::OWNER_CLUE_MAX]
    }

    /// DB-273 §19 L1: the recipient a mint of `deposit_id` names — the commitment to [`owner_clue`] the quorum signs.
    pub(crate) fn recipient_of(deposit_id: &[u8; 32]) -> [u8; 32] {
        crate::peg::peg_in_recipient(deposit_id, &owner_clue())
    }

    /// Two nodes on one genesis, each holding the SAME bonded quorum and the SAME registered asset —
    /// and the asset is registered through the CHAIN OBJECT on both, because that path is already proven
    /// to carry (`wrapped_asset_tx`). Anything that diverges after this point diverged because of the
    /// action under test, not because the parties started apart.
    pub(crate) fn pair() -> (Node, Node, Vec<u8>, Vec<u8>) {
        let (mut v, pk, sk) = parties(2);
        let b = v.pop().expect("two parties");
        let a = v.pop().expect("two parties");
        (a, b, pk, sk)
    }

    /// `n` parties on one genesis — the same bonded quorum and the same registered asset on every one, so
    /// a divergence after this point is the action's, not the fixture's. (DB-224 needs a THIRD party: one
    /// that pooled the object, beside the one that never did.)
    fn parties(n: usize) -> (Vec<Node>, Vec<u8>, Vec<u8>) {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        // The TESTNET genesis, because `chain_object::admissible` gates the credit class on
        // `genesis_mint_allowance()` and a bare `genesis_block()` has none — on that fixture the peer
        // refuses the published credit as `NotCredit`, and the pin would then be comparing a peer that
        // never received the note at all. The divergence under test is the PEG advance, so the peer must
        // be given every byte the chain really carries before it is asked what it is missing.
        let node = || {
            let mut p = crate::params::ChainParams::default();
            p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
            p.net_prefix_len = p.genesis_parity_commit.len();
            // ⭐ DB-274 P4b increment 2: a class object's effects (the peg ledger, the marks, the wrapped registry) apply at
            // the CANONICAL FOLD, so both parties fold at the tip — the production depth only DELAYS the same decision
            // (the DB-358 pins' rule; `canonical_record_fold_tests` pin that depth). A carriage claim is about what the
            // peer holds once the block applies, and it now applies at its fold.
            p.record_fold_depth = 0;
            let mut g = genesis_block();
            g.header = crate::block::genesis_header_for_network(
                &crate::params::network_genesis_prefix("testnet"),
            );
            let mut n = Node::with_params(g, p).expect("a testnet node builds");
            n.set_reward_recipient(None); // this module's premise: a block carries only the action under test (see `testnet_node`)
            n
        };
        let mut v: Vec<Node> = (0..n).map(|_| node()).collect();
        for p in v.iter_mut() {
            p.admit_validator(crate::pqauth::pubkey_id(&pk), 20_000, 0).unwrap();
        }
        let h = crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
            epoch_id: 1,
            asset_id: ASSET,
            prev_ratio_bps: 0,
            ratio_bps: 15_000,
        };
        let msg = crate::peg::PegLedger::wrapped_register_msg(
            h.epoch_id,
            h.asset_id,
            h.prev_ratio_bps,
            h.ratio_bps,
        );
        let att = vec![MintAttestor {
            pubkey: pk.clone(),
            sig: crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded validator signs"),
        }];
        let blob = crate::wrapped_asset_tx::wire(&h, &att);
        for p in v.iter_mut() {
            assert_eq!(
                crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(
                    p,
                    &blob,
                    &crate::pqauth::MlDsaVerifier
                ),
                crate::wrapped_asset_tx::RegisterApply::Registered,
                "every party adopts the registration from the same object"
            );
        }
        for p in v.iter().skip(1) {
            assert!(
                peg_divergences(p.peg(), v[0].peg(), &[]).is_empty(),
                "precondition: the parties start on identical peg state"
            );
        }
        (v, pk, sk)
    }

    /// ⛔⛔⛔ THE BLIND-SPOT PIN: a wrapped mint must leave a node fed ONLY the published object holding
    /// the same peg state as the node that performed it.
    ///
    /// This drives the production sequence from `POST /wrapped_mint_execute` exactly: execute the mint on
    /// A, build the `BridgeCreditTx` the route builds, and apply it to B through the real
    /// `apply_chain_bridge_credit` seam. Then ask the peg oracle whether the two agree.
    ///
    /// RED WHILE THE COMMITMENT ADVANCE IS UNCARRIED — that is the point of the pin. It is expected to
    /// name `wrapped asset commitments` (A advanced them inside `execute_wrapped_mint`; B never saw
    /// them), and it stays RED until the mint carries its own transition the way `liquidation_tx` carries
    /// a re-mark. Deleting or weakening it would restore exactly the invisibility that let this ship.
    #[test]
    fn a_wrapped_mint_carries_its_peg_transition_to_a_node_fed_only_the_chain() {
        let (mut a, mut b, pk, sk) = pair();
        let addr = "bc1pcarriageprobe";
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x80, 0xb, 0x4]); // DB-80b: the requester's blind
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(2000, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        // The one production note layout: `leaf_to_cm_bytes(cm)` at the front, as every producer writes it.
        let mut note = vec![0u8; 1153];
        note[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(wcm));
        let deposit_id = [1u8; 32];

        // The custodian half of the gate, and a CONFIRMED foreign deposit — the same two facts the live
        // route needs before it will mint at all.
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);

        // DB-77: publish on A (verify-only + pool), carry it in A's OWN block (the producer applies its own
        // block through the object seam, §DA), graft that block on B — a node fed ONLY the chain.
        let outcome = a.publish_wrapped_mint(
            ASSET,
            deposit_id,
            3000,
            2000,
            recipient_of(&deposit_id),
            &note,
            &wcarrier,
            addr,
            &pk,
            &sk,
            &[],
            &crate::pqauth::MlDsaVerifier,
            &owner_clue(),
            wdb,
        );
        assert_eq!(
            outcome,
            crate::peg::PegOutcome::ConfidentialPublished,
            "precondition: the mint must PUBLISH on A, or this pin proves nothing about carriage"
        );
        let b_mint = a
            .produce(4_500, crate::hash::Hash32::hash(b"fr"), crate::hash::Hash32::hash(b"mc"))
            .expect("the block carrying the wrapped mint");
        assert!(
            a.peg().wrapped_deposit_minted(ASSET, &deposit_id),
            "A applies its OWN block's wrapped mint through the object seam (§DA)"
        );
        let applied = b.ingest_block(b_mint, 9_000);
        eprintln!("[carriage] peer grafted the block carrying the published mint object: {applied:?}");
        assert!(
            b.peg().wrapped_deposit_minted(ASSET, &deposit_id),
            "FAIRNESS PRECONDITION: the peer must actually RECEIVE and APPLY what the chain carries, or \
             a divergence below would only prove the object never arrived"
        );
        assert!(
            b.holds_record_with_cm(&crate::spend_frontier::leaf_to_cm_bytes(wcm)),
            "⛔⛔⛔ FUND SAFETY (DB-77): the peer does not hold the wrapped note after the block that carries \
             it — before DB-77 the apply ignored the note and a wrapped-asset note existed on one node only"
        );
        let diffs = peg_divergences(b.peg(), a.peg(), &[]);
        assert!(
            diffs.is_empty(),
            "⛔ THE MINT DID NOT CARRY ITS OWN TRANSITION. A node fed ONLY the published object holds \
             different peg state from the node that performed the mint:\n  {}\n\n\
             The minted NOTE rides the chain (`BridgeCreditTx`), but the peg commitment advance that \
             `execute_wrapped_mint` performed does not — `BridgeCreditTx` has no field for it and \
             `apply_chain_bridge_credit` never applies one. Two nodes therefore end with the same notes \
             and different reserve/minted digests, which is what solvency, every later mint and every \
             liquidation are measured against. FIX: carry the transition on the object the way \
             `liquidation_tx` carries a re-mark — the new commitments + the carrier + the attestations — \
             and advance the peg at the apply seam on EVERY node, not in the handler on one.",
            diffs.join("\n  ")
        );
    }

    /// CALIBRATION — the oracle is proven able to SEE a divergence, so a green run above is a real
    /// statement rather than a comparison that never fires. Advancing one node's peg without telling the
    /// other is exactly the shape the pin exists to catch.
    /// ⭐⭐⭐ DB-219 — THE WRAPPED HOLDER JOURNEY: a bridged note is MINTED to a holder, the block carries it
    /// to B, and the holder then MOVES it — and B, fed only blocks, retires it and holds the outputs.
    /// The `WrappedMint` row of the value-class register (criterion 1). Its first assertion is the one that
    /// matters most: the wrapped mint is a COMMITTED mint (DB-80b blind), so the spend's input opening must
    /// reproduce the minted commitment or no bridged asset could ever be moved.
    #[test]
    fn a_wrapped_note_minted_to_a_holder_is_moved_and_a_node_fed_only_blocks_retires_it() {
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::whir_rec_block::{
            asset_spend_input_leaf, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness,
        };
        let (mut a, mut b, pk, sk) = pair();
        let addr = "bc1pwrappedholder";
        const MINTED: u64 = 2_000;
        let note_sk_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]));
        let note_sk = note_sk_owner.opening(); // DB-395: the note's opening, under its owner
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x219, 0xb, 0x4]);
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(MINTED, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        let note_of = |cm: usdm_decider::poseidon2_compress::Digest| -> Vec<u8> {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
            n
        };
        let deposit_id = [0x19u8; 32];
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        let outcome = a.publish_wrapped_mint(
            ASSET, deposit_id, 3000, MINTED as u128, recipient_of(&deposit_id), &note_of(wcm), &wcarrier, addr, &pk, &sk,
            &[], &crate::pqauth::MlDsaVerifier, &owner_clue(), wdb,
        );
        assert_eq!(outcome, crate::peg::PegOutcome::ConfidentialPublished, "PRECONDITION: the wrapped mint publishes on A");
        let mint_blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db219-fr-1"), crate::hash::Hash32::hash(b"db219-mc-1"))
            .expect("the block carrying the wrapped mint");
        let mint_id = mint_blk.id();
        let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(wcm);
        // CONTROL (the register's first): B must NOT hold the note before the block carries it — or B's
        // holding it afterwards would prove nothing about the block.
        assert!(
            !b.holds_record_with_cm(&cm_bytes),
            "CONTROL: B holds the wrapped note before any block carried it"
        );
        assert!(
            matches!(b.ingest_block(mint_blk, 9_000), crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: B grafts the mint block"
        );
        assert!(b.holds_record_with_cm(&cm_bytes), "PRECONDITION: B holds the wrapped note from the block alone");
        // DB-358 (1): the move spends the minted note, so the fold passes the mint block first (a wallet waits the same
        // way). Idle blocks at 20 ms steps stay below the move block's 5,500.
        crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 4_500, 20);

        // ── The minted note, as B derives it from the block.
        let rid = Node::da_record_id_for_block(&mint_id, 0);
        let want_leaf = crate::spend_frontier::note_leaf_of(&cm_bytes);
        let rec = b.da_block_leaves(rid).expect("B holds the mint block's record");
        let slot = rec.iter().position(|l| *l == want_leaf).expect("the wrapped note sits in its block's record on B") as u8;
        let (sibs, dirs, root) = b.da_note_copath_in_block(rid, slot).expect("B serves the in-record copath");

        // ── The holder moves it: 700 to a recipient, the rest back as change, one (wrapped) asset throughout.
        let build = |out0: u64| -> crate::asset_tx::AssetSpendTx {
            let w = AssetSpendValidityWitness {
                value_in: MINTED,
                owner: note_sk_owner,
                value_out: MINTED,
                fee: 0,
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
                out0_value: out0,
                out0_opening: usdm_decider::poseidon2_compress::lanes_of(&[61, 62, 63, 64]),
                out1_value: MINTED - out0,
                out1_opening: usdm_decider::poseidon2_compress::lanes_of(&[71, 72, 73, 74]),
                asset: wtag,
            };
            assert_eq!(
                asset_spend_input_leaf(&w).expect("the input opens"),
                want_leaf,
                "⛔⛔⛔ THE HOLDER'S SPEND DOES NOT OPEN THE NOTE THE WRAPPED MINT CREATED. The mint is COMMITTED \
                 (DB-80b blind) and the transfer opens (value, sk, asset) only, so the two derive different \
                 leaves: every bridged note is unspendable by its holder."
            );
            let (validity_carrier, cms, nf, lc) =
                prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
            let mut mc = NoteMembershipCarrier::new(want_leaf, root, Node::MEMBERSHIP_GENESIS_ACC, nf, crate::spend_frontier::TEST_LC_BLIND);
            assert!(mc.attach_membership(want_leaf, &sibs, &dirs), "the record copath reaches the record root");
            assert!(mc.step(root), "the one fold step proves");
            let (membership_carrier, tip_acc, tip_prev, tip_root) = mc.finalize_one_step().expect("certifies");
            assert_eq!(mc.leaf_commitment(), lc, "both carriers name the same note");
            crate::asset_tx::AssetSpendTx {
                notes: [note_of(cms[0]), note_of(cms[1])],
                nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
                leaf_commit: lc,
                validity_carrier,
                membership_carrier,
                member_tuple: Vec::new(),
                named_record: rid,
                tip_prev,
                tip_root,
                tip_acc,
                owner_clues: vec![vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]; crate::asset_tx::ASSET_SPEND_OUTPUTS],
                slot_tag: None,
            }
        };
        let t = build(700);
        let cms = t.output_commitments().expect("canonical output fronts");
        // CONTROL (the register's second): neither party may hold the spend's outputs before the spend is
        // published — or holding them afterwards would prove nothing about the transfer.
        for (i, out) in cms.iter().enumerate() {
            let out_cm = crate::spend_frontier::leaf_to_cm_bytes(*out);
            assert!(
                !a.holds_record_with_cm(&out_cm) && !b.holds_record_with_cm(&out_cm),
                "CONTROL: a party holds output {i} of the transfer before it was published"
            );
        }
        let (a_nf_before, b_nf_before) = (a.nullifier_root(), b.nullifier_root());
        let published = a.execute_asset_spend(&t);
        assert!(
            matches!(published, crate::node::AssetSpendOutcome::Published),
            "⛔ a holder cannot move the wrapped note it was minted. Outcome: {published:?}"
        );
        let xfer_blk = a
            .produce(5_500, crate::hash::Hash32::hash(b"db219-fr-2"), crate::hash::Hash32::hash(b"db219-mc-2"))
            .expect("the block carrying the transfer");
        let xfer_id = xfer_blk.id();
        let outcome = b.ingest_block(xfer_blk, 9_500);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused the transfer block: {outcome:?}");
        assert_ne!(a.nullifier_root(), a_nf_before, "PRECONDITION: the transfer retired its input on A");
        assert_ne!(b.nullifier_root(), b_nf_before, "⛔ B grafted the transfer and its spent set did not move");
        assert_eq!(b.nullifier_root(), a.nullifier_root(), "⛔ the two nodes disagree about what is spent");
        let rec3 = b.da_block_leaves(Node::da_record_id_for_block(&xfer_id, 0)).expect("B holds the transfer block's record");
        for (i, out) in cms.iter().enumerate() {
            let leaf = crate::spend_frontier::note_leaf_of(&crate::spend_frontier::leaf_to_cm_bytes(*out));
            assert!(rec3.contains(&leaf), "⛔ output {i} of the wrapped transfer is not in B's record");
        }
        // A SECOND spend of the same wrapped note — new outputs, same nullifier — refused on both.
        let t2 = build(1_000);
        assert_ne!(t2.wire(), t.wire(), "PRECONDITION: a different object");
        assert_eq!(t2.nullifier, t.nullifier, "PRECONDITION: of the same note");
        let on_b = b.execute_asset_spend(&t2);
        assert!(!matches!(on_b, crate::node::AssetSpendOutcome::Published), "⛔⛔⛔ B re-admitted a spent wrapped note: {on_b:?}");
        let on_a = a.execute_asset_spend(&t2);
        assert!(!matches!(on_a, crate::node::AssetSpendOutcome::Published), "⛔⛔⛔ A re-admitted a spent wrapped note: {on_a:?}");
    }

    /// ⭐⭐⭐ DB-220 — A PRICE MARK TRAVELS, AND THE PEER PRICES A MINT BY IT. The `PriceMark` row of the
    /// value-class register (criterion 1): DB-124 built the object and its gate; nothing carried one to a
    /// peer and showed that peer pricing a mint by it.
    ///
    /// The control is the point: BEFORE the block, B holds no mark for the asset and refuses to count the
    /// deposit at all (fail-closed — `priced_value` is `None`). AFTER grafting the block, and fed nothing
    /// else, B holds the same mark as A and a mint the priced deposit covers is covered while one it does not
    /// cover is not. A mark that only moved A's pricing would leave B refusing both.
    #[test]
    fn a_price_mark_travels_in_a_block_and_the_peer_prices_a_mint_by_it() {
        crate::peg::unprice_fixtures_for_test(); // the CONTROL measures the unpriced door
        let (mut a, mut b, pk, sk) = pair();
        const PRICE: u128 = 15_000; // USDm-atomic per external atomic unit, scaled by PRICE_SCALE
        const DEPOSIT: u128 = 1_000_000;
        // The largest mint the priced deposit covers at the registered 150% ratio, and one unit more.
        let covered = |n: &Node, mint: u128| n.peg().mint_is_covered_by_priced_deposit(PRICED, DEPOSIT, mint);
        let priced = DEPOSIT.saturating_mul(PRICE) / crate::liquidation::PRICE_SCALE;
        let ratio = b.peg().required_ratio_bps(PRICED).expect("PRECONDITION: the bridge ledger has its mint ratio") as u128;
        let max_mint = priced.saturating_mul(10_000) / ratio;
        assert!(max_mint > 0, "PRECONDITION: the deposit prices to a non-zero mint");

        // CONTROL — B has no mark yet, so it prices nothing.
        assert_eq!(b.price_mark_for(PRICED), None, "PRECONDITION: B starts with no mark for the asset");
        assert!(!covered(&b, max_mint), "CONTROL: with no mark B must refuse to count the deposit at all");

        // The bonded validator attests the quote; A admits the mark as a transaction and produces.
        let header = crate::price_mark_tx::PriceMarkHeader { epoch_id: 1, asset_id: PRICED };
        let quote = crate::price_mark_tx::PriceQuote {
            price: PRICE,
            pubkey: pk.clone(),
            sig: crate::pqauth::ml_dsa_sign(&crate::peg::PegLedger::price_mark_msg(1, PRICED, PRICE), &sk)
                .expect("the bonded validator signs its quote"),
        };
        let tx = crate::price_mark_tx::as_pq_tx(&header, &[quote], a.mempool().required_stamp_bits());
        a.ingest_tx(tx).expect("PRECONDITION: the mark is admitted as a transaction on A");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db220-fr"), crate::hash::Hash32::hash(b"db220-mc"))
            .expect("A produces the block carrying the mark");
        assert_eq!(
            a.price_mark_for(PRICED).map(|m| m.price),
            Some(PRICE),
            "PRECONDITION: A applies the mark its own block carries"
        );
        let outcome = b.ingest_block(blk, 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused the block: {outcome:?}");

        // ON B'S OWN STATE: the mark arrived, and B now prices by it.
        assert_eq!(
            b.price_mark_for(PRICED),
            a.price_mark_for(PRICED),
            "⛔ B grafted the block and holds a different mark (or none) — the price did not travel"
        );
        assert!(
            covered(&b, max_mint),
            "⛔ B holds the mark but a mint the priced deposit covers is still not covered on B"
        );
        assert!(
            !covered(&b, max_mint + 1),
            "⛔ B counts a mint BEYOND what the priced deposit covers — the mark is not bounding it"
        );
    }

    #[test]
    fn the_carriage_oracle_detects_a_peg_advance_that_never_travelled() {
        let (mut a, b, _pk, _sk) = pair();
        assert!(
            peg_divergences(b.peg(), a.peg(), &[]).is_empty(),
            "the pair starts equal"
        );
        // A learns something B never hears about — a second asset registered locally.
        a.register_wrapped_asset(ASSET + 1, 15_000);
        let diffs = peg_divergences(b.peg(), a.peg(), &[]);
        assert!(
            !diffs.is_empty(),
            "the oracle MUST see a peg change that did not travel, or the pin above is vacuous"
        );
        eprintln!("[carriage] calibration saw: {}", diffs.join(" | "));
    }

    // ═════════════════════════════════════════════════════════════════════════════════════════════════
    // ⭐⭐⭐ DB-224 — THE CREDIT SET CROSSES THE WIRE, IN CARRIAGE FORM.
    //
    // Every pin above hands the peer the Block STRUCT, in process — and a struct is not what a peer
    // receives. Since DB-165 `output_notes` and (until DB-224) `credit_set` were `#[serde(skip)]`, so the
    // in-process pins were measuring a block no real peer ever saw. These pins put the block through its
    // OWN wire codec first (`over_the_wire`) and then ask the peer — which never pooled the object — what
    // it holds.
    // ═════════════════════════════════════════════════════════════════════════════════════════════════

    /// The bytes a peer REALLY receives: the block through its own postcard codec, exactly as the relay
    /// and the bundle lanes encode it. Every `#[serde(skip)]` field arrives empty.
    /// A block as a PEER receives it over gossip: the wire form plus the cover key the §22 envelope carries
    /// (`block::gossip_encode`); the Block's own encoding stays key-less.
    fn over_the_wire(b: &crate::block::Block) -> crate::block::Block {
        crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("a block decodes from its own gossip envelope")
    }

    /// A note shaped like a real sealed one: the canonical commitment in front, a high-entropy ciphertext
    /// behind it — so "no payload byte on the wire" is tested against bytes that could not match by chance.
    fn sealed_note(front: &[u8; 32], seed: &[u8]) -> Vec<u8> {
        let mut n = front.to_vec();
        let mut ctr = 0u64;
        while n.len() < crate::cover::PQ_NOTE_BYTES {
            let mut b = seed.to_vec();
            b.extend_from_slice(&ctr.to_le_bytes());
            n.extend_from_slice(crate::hash::Hash32::hash(&b).as_bytes());
            ctr += 1;
        }
        n.truncate(crate::cover::PQ_NOTE_BYTES);
        n
    }

    /// Does `hay` contain `needle` anywhere? (The privacy search; calibrated where it is used.)
    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    fn a_price_mark_tx(a: &Node, pk: &[u8], sk: &[u8], epoch: u64, price: u128) -> crate::mempool::PqTx {
        a_price_mark_tx_for(a, pk, sk, ASSET, epoch, price)
    }

    fn a_price_mark_tx_for(a: &Node, pk: &[u8], sk: &[u8], asset: u32, epoch: u64, price: u128) -> crate::mempool::PqTx {
        let header = crate::price_mark_tx::PriceMarkHeader { epoch_id: epoch, asset_id: asset };
        let quote = crate::price_mark_tx::PriceQuote {
            price,
            pubkey: pk.to_vec(),
            sig: crate::pqauth::ml_dsa_sign(&crate::peg::PegLedger::price_mark_msg(epoch, asset, price), sk)
                .expect("the bonded validator signs its quote"),
        };
        crate::price_mark_tx::as_pq_tx(&header, &[quote], a.mempool().required_stamp_bits())
    }

    /// ⭐⭐⭐ DB-224 — A PRICE MARK CROSSES THE WIRE TO A PEER THAT NEVER POOLED IT.
    ///
    /// The DB-220 pin above is the calibration: it was RED because `rehydrate_block_body` rebuilt the
    /// credit set from B's EMPTY pool and installed nothing, and it did that even to a set that arrived in
    /// process (its only early return keys on `output_notes`). This pin asks the stronger question — the
    /// block through the wire, a peer with an empty pool — and also pins the overwrite on its own.
    #[test]
    fn db224_a_price_mark_crosses_the_wire_to_a_peer_that_never_pooled_it() {
        crate::peg::unprice_fixtures_for_test(); // the CONTROL measures the unpriced door
        let (mut a, mut b, pk, sk) = pair();
        const PRICE: u128 = 15_000;
        a.ingest_tx(a_price_mark_tx_for(&a, &pk, &sk, PRICED, 1, PRICE)).expect("PRECONDITION: A pools the mark");
        assert!(b.mempool().is_empty(), "PRECONDITION: B never pooled the mark — the block is all it gets");
        assert_eq!(b.price_mark_for(PRICED), None, "CONTROL: B holds no mark before the block");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db224-pm-fr"), crate::hash::Hash32::hash(b"db224-pm-mc"))
            .expect("A produces the block carrying the mark");
        assert_eq!(a.price_mark_for(PRICED).map(|m| m.price), Some(PRICE), "PRECONDITION: A applied its own block");
        let wire = over_the_wire(&blk);
        assert!(!wire.credit_set.is_empty(), "⛔ DB-224: the credit set must ride the wire");
        assert_eq!(wire.credit_set, blk.credit_set, "the carried set arrives byte-identical");
        // §22c: the envelope carries the block's real notes beside the body, the body the header commits …
        assert_eq!(wire.output_notes, blk.output_notes, "the envelope delivers exactly the block's own notes");
        // … while the block's OWN encoding still carries none (DB-165: a note ciphertext on the block's wire regenerates its cover)
        let bare: crate::block::Block = postcard::from_bytes(&postcard::to_allocvec(&blk).expect("the block encodes")).expect("and decodes");
        assert!(bare.output_notes.is_empty(), "⛔ the block's own encoding carries note bytes");

        // THE OVERWRITE, pinned on its own: a notes-free block's carried set survives rehydration on a
        // node whose pool holds nothing — the old rebuild replaced it with an empty set here.
        let mut rehydrated = wire.clone();
        let _ = b.rehydrate_block_body(&mut rehydrated);
        assert_eq!(
            rehydrated.credit_set, wire.credit_set,
            "⛔ rehydrate_block_body replaced a carried credit set with its own pool's rebuild"
        );

        // CONTROL on B's own state: with no mark it refuses to count a deposit at all.
        const DEPOSIT: u128 = 1_000_000;
        let covered = |n: &Node, mint: u128| n.peg().mint_is_covered_by_priced_deposit(PRICED, DEPOSIT, mint);
        let priced = DEPOSIT.saturating_mul(PRICE) / crate::liquidation::PRICE_SCALE;
        let ratio = b.peg().required_ratio_bps(PRICED).expect("PRECONDITION: the bridge ledger has its mint ratio") as u128;
        let max_mint = priced.saturating_mul(10_000) / ratio;
        assert!(max_mint > 0, "PRECONDITION: the deposit prices to a non-zero mint");
        assert!(!covered(&b, max_mint), "CONTROL: with no mark B must refuse to count the deposit at all");

        let outcome = b.ingest_block(wire, 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused the wire block: {outcome:?}");
        assert_eq!(
            b.price_mark_for(PRICED),
            a.price_mark_for(PRICED),
            "⛔⛔⛔ DB-224: B grafted the block from the wire and holds a different mark (or none) — the \
             object did not travel with the block that applies it"
        );
        // …and B now PRICES by it, from the wire block alone: the largest mint the priced deposit covers
        // is covered, one unit more is not.
        assert!(covered(&b, max_mint), "⛔ B holds the mark but a mint the priced deposit covers is not covered");
        assert!(!covered(&b, max_mint + 1), "⛔ B counts a mint BEYOND what the priced deposit covers");
    }

    /// ⭐⭐⭐ §22b — A WIDE OBJECT RIDES BESIDE THE BLOCK (BIP152's shape), AND NO RELAY CAN STRIP, FORGE OR PAD IT.
    ///
    /// A wrapped mint's carriage (~396 KB, MEASURED) is wider than `CREDIT_INLINE_MAX`, so the sealed credit set carries a
    /// 40-byte reference naming its hash and the bytes travel in the gossip envelope beside the cover key. What must hold:
    ///   * the sealed set is the ONE width on this block and on a quiet one (no length says a wide object rode);
    ///   * the envelope round-trips the wide bytes; a peer that pooled the payload applies the mint from the wire;
    ///   * an envelope STRIPPED of the wide bytes, or carrying a FORGED copy (one byte flipped), is refused as an
    ///     incomplete body (`CreditSetWideMissing`) — and that refusal does not poison the honest copy of the same id;
    ///   * bytes the set does not name are DROPPED at decode (a relay cannot pad a block's envelope with junk);
    ///   * a malformed envelope tail decodes to nothing, never to a block with a guessed set.
    #[test]
    fn s22b_a_wide_object_rides_beside_the_block_and_a_stripped_forged_or_padded_envelope_changes_nothing() {
        let (mut v, pk, sk) = parties(3);
        let mut c = v.pop().expect("three parties");
        let mut b = v.pop().expect("three parties");
        let mut a = v.pop().expect("three parties");
        let addr = "bc1ps22bwide";
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0x22b, 0x4, 0x5, 0x6]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0x22bu64, 0x224, 0xb, 0x4]);
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(2000, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        let cm = crate::spend_frontier::leaf_to_cm_bytes(wcm);
        let note = sealed_note(&cm, b"s22b-wrapped-ciphertext");
        let deposit_id = [0x2bu8; 32];
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        let outcome = a.publish_wrapped_mint(
            ASSET, deposit_id, 3000, 2000, recipient_of(&deposit_id), &note, &wcarrier, addr, &pk, &sk, &[],
            &crate::pqauth::MlDsaVerifier, &owner_clue(), wdb,
        );
        assert_eq!(outcome, crate::peg::PegOutcome::ConfidentialPublished, "PRECONDITION: the mint publishes on A");
        let wm = a
            .mempool()
            .all_tx_ids()
            .iter()
            .filter_map(|id| a.mempool().get(&crate::hash::Hash32(*id)))
            .find(|t| crate::chain_object::unframe(&t.blob).map(|(k, _)| k) == Some(crate::chain_object::Class::WrappedMint))
            .cloned()
            .expect("PRECONDITION: A's pool holds the published wrapped mint");
        c.ingest_tx(wm).expect("PRECONDITION: C pools the object as gossip would");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"s22b-fr"), crate::hash::Hash32::hash(b"s22b-mc"))
            .expect("the block carrying the wrapped mint");
        assert!(a.peg().wrapped_deposit_minted(ASSET, &deposit_id), "PRECONDITION: A applied its own block");

        // ── THE SHAPE: one width; the object is a reference inside it, its bytes beside the body.
        assert_eq!(blk.credit_set.len(), crate::block::CREDIT_SET_SEALED_BYTES, "the sealed set has its one width");
        let mint_carriage = blk
            .wide_objects
            .iter()
            .find(|w| crate::chain_object::unframe(w).map(|(k, _)| k) == Some(crate::chain_object::Class::WrappedMint))
            .cloned()
            .expect("the mint's carriage rides beside the body");
        assert!(mint_carriage.len() > crate::block::CREDIT_INLINE_MAX, "CALIBRATION: the mint's carriage is wide");
        let key = crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref());
        let frames = crate::block::credit_set_frames(&blk.credit_set, key.as_ref()).expect("the producer opens its own set");
        let named: Vec<[u8; 32]> = frames.iter().filter_map(|f| crate::block::wide_ref_hash(f)).collect();
        let held: Vec<[u8; 32]> = blk.wide_objects.iter().map(|w| crate::block::wide_carriage_hash(w)).collect();
        assert_eq!(named, held, "the set names exactly the bytes beside the body, in order");
        assert!(named.contains(&crate::block::wide_carriage_hash(&mint_carriage)), "the set names the mint's carriage");
        let quiet = a
            .produce(5_500, crate::hash::Hash32::hash(b"s22b-q-fr"), crate::hash::Hash32::hash(b"s22b-q-mc"))
            .expect("A produces a quiet block");
        assert!(
            quiet.wide_objects.iter().all(|w| crate::chain_object::unframe(w).map(|(k, _)| k) != Some(crate::chain_object::Class::WrappedMint)),
            "CALIBRATION: the quiet block carries no mint (only its reward rides beside it)"
        );
        assert_eq!(quiet.credit_set.len(), blk.credit_set.len(), "⛔ the sealed set's width says a wide object rode");

        // ── THE ENVELOPE round-trips the bytes, and refuses a malformed tail.
        let env = crate::block::gossip_encode(&blk);
        assert_eq!(over_the_wire(&blk).wide_objects, blk.wide_objects, "the envelope carries the wide bytes");
        let mut tail = env.clone();
        tail.push(0);
        assert!(crate::block::gossip_decode(&tail).is_none(), "⛔ a trailing byte after the wide list decoded to a block");

        // ── STRIPPED, then FORGED: refused as incomplete bodies on B.
        let mut stripped = blk.clone();
        stripped.wide_objects.clear();
        let got = b.ingest_block(over_the_wire(&stripped), 9_000);
        assert!(
            matches!(got, crate::relay::RelayOutcome::Invalid(crate::consensus::ConsensusError::CreditSetWideMissing)),
            "⛔ an envelope STRIPPED of its wide bytes was not refused as incomplete: {got:?}"
        );
        let mut forged = blk.clone();
        let mi = forged.wide_objects.iter().position(|w| *w == mint_carriage).expect("the mint beside the body");
        forged.wide_objects[mi][200] ^= 1;
        let fw = over_the_wire(&forged);
        assert_eq!(fw.wide_objects.len(), blk.wide_objects.len() - 1, "a forged copy names nothing the set names — dropped at decode");
        let got = b.ingest_block(fw, 9_000);
        assert!(
            matches!(got, crate::relay::RelayOutcome::Invalid(crate::consensus::ConsensusError::CreditSetWideMissing)),
            "⛔ an envelope carrying a FORGED wide object was not refused: {got:?}"
        );

        // ── PADDED: junk the set does not name is dropped; the honest copy of the SAME id then grafts (no poisoning).
        let mut padded = blk.clone();
        padded.wide_objects.push(vec![7u8; 20_000]);
        let pw = over_the_wire(&padded);
        assert_eq!(pw.wide_objects, blk.wide_objects, "⛔ unnamed bytes were kept beside the body");
        let got = b.ingest_block(pw, 9_000);
        assert!(
            matches!(got, crate::relay::RelayOutcome::Added(_)),
            "⛔ the honest block was refused after its stripped/forged copies were: {got:?}"
        );

        // ── APPLIES: C, which pooled the payload, applies the mint from the wire alone.
        let got = c.ingest_block(over_the_wire(&blk), 9_000);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "⛔ C refused the wire block: {got:?}");
        assert!(c.peg().wrapped_deposit_minted(ASSET, &deposit_id), "⛔ C did not apply the mint whose bytes rode beside the block");
        assert!(peg_divergences(c.peg(), a.peg(), &[]).is_empty(), "⛔ C diverges from A");
    }

    /// ⭐⭐⭐ DB-224 — A NOTE-CARRYING OBJECT CROSSES THE WIRE WITHOUT ITS PAYLOAD, AND STILL APPLIES.
    ///
    /// A wrapped mint on A. B NEVER pooled it; C pooled it as gossip would deliver it. Both are handed
    /// only the WIRE block. What must hold:
    ///   * no byte of the minted note's payload is on the wire (the DB-165 cover-secret attack stays shut);
    ///   * B's peg state equals A's — the transition travelled on the carriage alone;
    ///   * C, which holds the payload, records the note, justified BYTE-EXACTLY by the carried reference.
    #[test]
    fn db224_a_wrapped_mint_crosses_the_wire_without_its_payload_and_moves_the_peg_on_a_peer_that_never_pooled_it() {
        let (mut v, pk, sk) = parties(3);
        let mut c = v.pop().expect("three parties");
        let mut b = v.pop().expect("three parties");
        let mut a = v.pop().expect("three parties");
        let addr = "bc1pdb224wire";
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0x22, 0x4, 0x5, 0x6]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x224, 0xb, 0x4]);
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(2000, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        let cm = crate::spend_frontier::leaf_to_cm_bytes(wcm);
        let note = sealed_note(&cm, b"db224-wrapped-ciphertext");
        let deposit_id = [0x24u8; 32];
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        let outcome = a.publish_wrapped_mint(
            ASSET, deposit_id, 3000, 2000, recipient_of(&deposit_id), &note, &wcarrier, addr, &pk, &sk, &[],
            &crate::pqauth::MlDsaVerifier, &owner_clue(), wdb,
        );
        assert_eq!(outcome, crate::peg::PegOutcome::ConfidentialPublished, "PRECONDITION: the mint publishes on A");
        // C pools A's object exactly as gossip would deliver it; B never sees it.
        let wm = a
            .mempool()
            .all_tx_ids()
            .iter()
            .filter_map(|id| a.mempool().get(&crate::hash::Hash32(*id)))
            .find(|t| {
                crate::chain_object::unframe(&t.blob).map(|(k, _)| k)
                    == Some(crate::chain_object::Class::WrappedMint)
            })
            .cloned()
            .expect("PRECONDITION: A's pool holds the published wrapped mint");
        c.ingest_tx(wm).expect("PRECONDITION: C pools the object as gossip would");
        assert!(b.mempool().is_empty(), "PRECONDITION: B never pooled it");

        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db224-wm-fr"), crate::hash::Hash32::hash(b"db224-wm-mc"))
            .expect("the block carrying the wrapped mint");
        assert!(a.peg().wrapped_deposit_minted(ASSET, &deposit_id), "PRECONDITION: A applied its own block");

        // ── PRIVACY, measured on the bytes: calibrate the search on the struct, then run it on the wire.
        assert!(
            contains(&blk.output_notes, &note),
            "CALIBRATION: the in-memory block holds the payload, so the search below can find one"
        );
        let wire_bytes = postcard::to_allocvec(&blk).expect("the block encodes");
        assert!(
            !contains(&wire_bytes, &note[32..96]),
            "⛔⛔⛔ A NOTE CIPHERTEXT RIDES THE BLOCK WIRE — the only secret input of \
             `cover::block_cover_secret` (DB-165's regeneration attack)"
        );
        let carried = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("the carried set parses");
        assert_eq!(carried.len(), 1, "the block carries exactly the one object it selected");
        assert!(crate::chain_object::is_carriage(&carried[0]), "and carries it in carriage form");
        let refs = crate::chain_object::carriage_note_refs(&carried[0]).expect("the carriage names its note");
        assert_eq!(
            refs,
            vec![(cm, *crate::hash::Hash32::hash(&note).as_bytes())],
            "the reference is exactly (cm, blake3(payload))"
        );
        eprintln!(
            "[db224] wire: block {} B, credit_set {} B (the object's carriage), note payload 0 B on the wire",
            wire_bytes.len(),
            blk.credit_set.len()
        );

        // ── B: never pooled, fed only the wire block.
        let outcome = b.ingest_block(over_the_wire(&blk), 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused the wire block: {outcome:?}");
        // B's claim — the mint applied, the peg equal to A's — is asserted at the END, over the hub: since DB-274 P4b the
        // object's effects land at the block's FOLD, the fold needs the block's RECORD, and the wire never carries it
        // (DB-224). A wire-fed node gets the record by id over the DA lane from a peer that holds it, as the live nodes do.

        // ── C: pooled the payload, fed only the wire block — the carried reference justifies it.
        let outcome = c.ingest_block(over_the_wire(&blk), 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ C refused the wire block: {outcome:?}");
        assert!(c.peg().wrapped_deposit_minted(ASSET, &deposit_id), "⛔ C did not apply the carried mint");
        assert!(
            c.holds_record_with_cm(&cm),
            "⛔⛔⛔ C holds the payload and the block carries its reference, yet C did not record the note — \
             the §BA door refused a note the block justifies byte-exactly"
        );
        assert!(peg_divergences(c.peg(), a.peg(), &[]).is_empty(), "⛔ C diverges from A");

        // ── ONE NOTE, ONE CREDIT. Before DB-224 every node that applied the FULL object re-staged its note
        // into its OWN next block (`record_note_payload` inside the apply doors), although the note had
        // already ridden the object's own block — so A and C each ended holding it in TWO records. From a
        // carriage the apply re-stages nothing, on every node alike. Both parties produce again and each
        // grafts the other's block; the note must sit in exactly ONE record on each — not two, not zero.
        let a_next = a
            .produce(5_500, crate::hash::Hash32::hash(b"db224-wm-fr-2"), crate::hash::Hash32::hash(b"db224-wm-mc-2"))
            .expect("A produces again");
        let _ = c.ingest_block(over_the_wire(&a_next), 9_500);
        let c_next = c
            .produce(6_500, crate::hash::Hash32::hash(b"db224-wm-fr-3"), crate::hash::Hash32::hash(b"db224-wm-mc-3"))
            .expect("C produces its own block");
        let _ = a.ingest_block(over_the_wire(&c_next), 9_900);
        assert_eq!(
            a.records_containing_cm(&cm).len(),
            1,
            "⛔⛔⛔ A holds the minted note in more than one record — the apply re-staged a note its own block \
             already carried"
        );
        assert_eq!(
            c.records_containing_cm(&cm).len(),
            1,
            "⛔⛔⛔ C holds the minted note in more than one record — C's own next block re-carried it"
        );

        // ── B, over the hub: B holds the wire block (above) and never pooled the object. A and B now run their real
        // runtimes on the hub (cells + the bulk lane): B's fold wants the block's record, asks for it by id, A serves it,
        // and B's fold applies the carried mint. What B holds is asserted — never what a call returned.
        // §22c (2026-11-10): the gossip envelope now carries the block's real notes beside the body (a peer judges every
        // stated spend of a block itself and tells a stated cell from a cover cell by them), taken ONLY when they are the
        // body the header commits (`output_notes_root`). So B, fed only the envelope, already holds the record its fold
        // needs and has applied the carried mint; before §22c it waited for the DA lane here, and the old calibration
        // asserted exactly that wait. The block's OWN encoding still carries no note byte (asserted above on
        // `wire_bytes`). The hub below still runs both real runtimes and asserts what B holds.
        assert!(
            b.peg().wrapped_deposit_minted(ASSET, &deposit_id),
            "⛔ B, fed the block's own gossip envelope, did not apply the carried mint: the envelope's notes did not \
             reach its fold"
        );
        // TAMPER: an envelope whose notes are not the body the header commits delivers NO note (a relay's other bytes are
        // dropped; the peer then asks the DA lane as before).
        let mut other_body = blk.clone();
        let flip = other_body.output_notes.len() / 2;
        other_body.output_notes[flip] ^= 1;
        assert!(
            over_the_wire(&other_body).output_notes.is_empty(),
            "⛔ a gossip envelope delivered notes the block's header does not commit"
        );
        let mut s = crate::mesh_runtime_scenarios::tests::RtSim::with_nodes(vec![a, b], 0x224_0b_2026_1002);
        s.arm_deadline(std::time::Duration::from_secs(300));
        let applied = s.rounds_until(120, |s| s.node(1).peg().wrapped_deposit_minted(ASSET, &deposit_id));
        assert!(
            applied,
            "⛔⛔⛔ DB-224: B grafted the wire block and did not apply the wrapped mint it carries — the \
             object applied only where its tx was pooled"
        );
        let diffs = peg_divergences(s.node(1).peg(), s.node(0).peg(), &[]);
        assert!(
            diffs.is_empty(),
            "⛔⛔⛔ DB-224: B, fed only the wire block, holds different peg state from A:\n  {}",
            diffs.join("\n  ")
        );
        assert!(
            s.node(1).holds_record_with_cm(&cm),
            "⛔ B applied the mint but holds no record of its note — the DA lane delivered nothing"
        );
    }

    /// ⭐⭐⭐ DB-224 — A CARRIAGE IS NOT A TRANSACTION, AT ANY DOOR (one encoding, the review's item 2).
    ///
    /// `carriage_of` is the ONE encoder of note references and `wrapper_binds_object` the ONE rule every
    /// door asks of a framed transaction — the pool door (`ingest_tx`), note assembly and the graft door's
    /// resolved-tx arm. A carriage-form object wrapped as a transaction is refused at the pool door; planted
    /// past it (the rogue-producer model: the raw pool hook), assembly carries none of its reference-width
    /// "notes", the block stays whole-note aligned, and the producer's own sealed set drops the object
    /// (its note is in no block) — so the block passes the rule every peer applies.
    #[test]
    fn db224_a_carriage_is_not_a_transaction_at_any_door() {
        let mut a = testnet_node();
        let note = sealed_note(crate::hash::Hash32::hash(b"db224-door-tx-cm").as_bytes(), b"db224-door-tx-ct");
        let bits = a.mempool().required_stamp_bits();
        let full = credit_for(&note).as_pq_tx(bits);
        let mut carried = full.clone();
        carried.blob = crate::chain_object::carriage_of(&full.blob).expect("carriable");
        carried.output_notes = crate::chain_object::note_ref(&note).expect("a reference");
        carried.id = crate::mempool::PqTx::content_id(&carried.blob);
        carried.weight = carried.blob.len() as u32;
        let mut s = 0u64;
        loop {
            carried.pow_stamp = s;
            if carried.stamp_work() >= bits {
                break;
            }
            s = s.wrapping_add(1);
        }
        // THE POOL DOOR.
        assert!(a.ingest_tx(carried.clone()).is_err(), "⛔⛔⛔ the pool door admitted a CARRIAGE as a transaction");
        // CALIBRATION: the same object in full form is admitted by a fresh node.
        let mut b = testnet_node();
        assert!(b.ingest_tx(full).is_ok(), "CALIBRATION: the full object is an admissible transaction");
        // THE ASSEMBLY DOOR — planted past the pool door, it still rides nothing.
        a.ingest_tx_unverified(carried.clone()).expect("the raw pool hook plants it (the rogue-producer model)");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db224-door-tx-fr"), crate::hash::Hash32::hash(b"db224-door-tx-mc"))
            .expect("A still produces");
        assert!(
            !contains(&blk.output_notes, &carried.output_notes),
            "⛔⛔⛔ assembly carried a carriage's reference-width note into the block"
        );
        assert_eq!(
            blk.output_notes.len() % crate::cover::PQ_NOTE_BYTES,
            0,
            "⛔ the block's notes are no longer whole-note aligned"
        );
        assert!(
            crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("parses").is_empty(),
            "⛔ the producer sealed an object whose note its block does not carry"
        );
        assert_eq!(crate::consensus::credit_set_is_carried_with_its_subjects(&blk, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), false), Ok(()));
    }

    /// ⭐⭐⭐ DB-224 TAMPER — A RELAY THAT STRIPS OR EXTENDS THE CARRIED SET IS REFUSED.
    ///
    /// The set travels now, so the DB-191 conditional ("empty means not yet rehydrated") would be a strip
    /// door. Both a stripped and an extended set must be refused as `CreditSetRootMismatch`, while the
    /// honest wire block still grafts (the calibration that makes the refusals mean something).
    #[test]
    fn db224_a_relay_that_strips_or_extends_the_carried_credit_set_is_refused() {
        let (mut a, mut b, pk, sk) = pair();
        a.ingest_tx(a_price_mark_tx(&a, &pk, &sk, 1, 15_000)).expect("PRECONDITION: A pools the mark");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db224-t-fr"), crate::hash::Hash32::hash(b"db224-t-mc"))
            .expect("A produces");
        assert!(!blk.credit_set.is_empty(), "PRECONDITION: the block carries a set to tamper with");

        let mut stripped = over_the_wire(&blk);
        stripped.credit_set.clear();
        let got = b.ingest_block(stripped, 9_000);
        assert!(
            matches!(
                got,
                crate::relay::RelayOutcome::Invalid(crate::consensus::ConsensusError::CreditSetRootMismatch)
            ),
            "⛔ a STRIPPED credit set was not refused as a root mismatch: {got:?}"
        );

        let mut extended = over_the_wire(&blk);
        let extra = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("parses");
        let mut doubled = extra.clone();
        doubled.extend(extra);
        (extended.credit_set, extended.wide_objects) = crate::node::tests::sealed_credit_parts(&blk, &doubled); // §22: sealed, so the width is right and only the root refuses it
        let got = b.ingest_block(extended, 9_000);
        assert!(
            matches!(
                got,
                crate::relay::RelayOutcome::Invalid(crate::consensus::ConsensusError::CreditSetRootMismatch)
            ),
            "⛔ an EXTENDED credit set was not refused as a root mismatch: {got:?}"
        );

        let got = b.ingest_block(over_the_wire(&blk), 9_000);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "CALIBRATION: the honest block grafts: {got:?}");
        assert_eq!(b.price_mark_for(ASSET), a.price_mark_for(ASSET), "and applies");
    }

    /// A testnet node (the genesis whose open-mint allowance admits a small credit without a quorum).
    fn testnet_node() -> Node {
        let mut p = crate::params::ChainParams::default();
        p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        let mut g = genesis_block();
        g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
        let mut n = Node::with_params(g, p).expect("a testnet node builds");
        // THIS MODULE'S PREMISE: a block carries only the chain action under test. Its pins deliver blocks `over_the_wire`
        // (the wire form, which carries no note payload — records ride the bulk lane, which no in-process pair has). Since
        // SATOSHI increment 1 every produced block carries its mining reward note, and a receiver that never gets that
        // record cannot place the block: MEASURED 2026-10-05 (db274_p2 solo) — the evidence block's step was applied,
        // unwound and retried 292 times. A node with no reward recipient lays no reward (a real configuration), which
        // restores the premise for every pin here; the rewards' own carriage is pinned by `satoshi_pins`.
        n.set_reward_recipient(None);
        n
    }

    fn credit_for(note: &[u8]) -> crate::bridge_credit_tx::BridgeCreditTx {
        let mut deposit_id = [0u8; 32];
        deposit_id.copy_from_slice(&note[..32]);
        crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id,
            asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            amount: 1_000,
            note: note.to_vec(),
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        }
    }

    /// ⭐⭐⭐ DB-224 — THE TWO BLOCK-VALIDITY RULES, EACH REFUSING, EACH CALIBRATED.
    ///
    /// (1) Carriage form: a credit set that carries a note PAYLOAD is refused (`CreditSetNotCarriage`) —
    ///     "no payload byte rides a block" is a rule of the chain, not a courtesy of the producer.
    /// (2) The subject rule: a carried object naming a note the block's own carrier does not commit is
    ///     refused (`CreditObjectWithoutSubject`) — otherwise a producer could move a peg-in's ledger on
    ///     every node while leaving its minted note out of the block.
    /// And the producer's half: a justifier staged WITHOUT its note never rides (`carriable_credit_set`).
    #[test]
    fn db224_a_credit_set_carrying_a_payload_or_a_note_its_block_does_not_commit_is_refused() {
        use crate::consensus::{credit_set_is_carried_with_its_subjects, ConsensusError};
        // The WHOLE-BODY door (the gossip door every applied block passes).
        let rules = |b: &crate::block::Block| credit_set_is_carried_with_its_subjects(b, crate::block::credit_seal_key(&b.header, b.cover_key.as_ref()).as_ref(), false);
        let mut a = testnet_node();
        let note = sealed_note(crate::hash::Hash32::hash(b"db224-rules-cm").as_bytes(), b"db224-rules-ct");
        let (blk, _) = a.carry_notes_in_a_block_for_test(4_500, &note);
        assert_eq!(rules(&blk), Ok(()), "CALIBRATION: the honest block passes both rules");
        let honest = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("parses");
        assert_eq!(honest.len(), 1, "PRECONDITION: the honest block carries its one justifier");
        assert_eq!(
            honest[0],
            crate::chain_object::carriage_of(&credit_for(&note).wire()).expect("carriable"),
            "the producer carries exactly the carriage of the object it staged"
        );

        // (1) the FULL object where its carriage belongs.
        let mut with_payload = blk.clone();
        (with_payload.credit_set, with_payload.wide_objects) = crate::node::tests::sealed_credit_parts(&blk, &[credit_for(&note).wire()]);
        assert_eq!(
            rules(&with_payload),
            Err(ConsensusError::CreditSetNotCarriage),
            "⛔⛔⛔ a credit set carrying a NOTE PAYLOAD was not refused"
        );
        // …and a set that does not even parse.
        let mut garbage = blk.clone();
        garbage.credit_set = vec![0xff, 0xff, 0xff, 0x7f, 1, 2, 3];
        assert_eq!(rules(&garbage), Err(ConsensusError::CreditSetNotCarriage), "⛔ an unparseable set was not refused");

        // (2) a carriage naming a note this block does not commit.
        let other = sealed_note(crate::hash::Hash32::hash(b"db224-orphan-cm").as_bytes(), b"db224-orphan-ct");
        let orphan = crate::chain_object::carriage_of(&credit_for(&other).wire()).expect("carriable");
        let mut without_subject = blk.clone();
        (without_subject.credit_set, without_subject.wide_objects) = crate::node::tests::sealed_credit_parts(&blk, &[orphan]);
        assert_eq!(
            rules(&without_subject),
            Err(ConsensusError::CreditObjectWithoutSubject),
            "⛔⛔⛔ a carried object whose note the block does not commit was not refused"
        );
        // …and the same object where the carrier is missing entirely: nothing commits it.
        let mut no_carrier = blk.clone();
        no_carrier.note_commitments.clear();
        assert_eq!(
            rules(&no_carrier),
            Err(ConsensusError::CreditObjectWithoutSubject),
            "⛔ a note-naming set was admitted with no carrier to commit its notes"
        );
        // THE REDUCED-CARRIER DOOR: a DSYNC bundle's tip and a fold-carry block ship WITHOUT their note
        // carrier by design, and their set only justifies notes byte-exactly (it applies no object). An
        // absent carrier there skips the subject rule — or every bundle whose tip carried a credit would be
        // refused and no node could join — while the CARRIAGE rule still refuses a payload.
        assert_eq!(
            credit_set_is_carried_with_its_subjects(&no_carrier, crate::block::credit_seal_key(&no_carrier.header, no_carrier.cover_key.as_ref()).as_ref(), true),
            Ok(()),
            "⛔ the reduced-carrier door refused a carrier-less carried block — DSYNC adopts would fail"
        );
        assert_eq!(
            credit_set_is_carried_with_its_subjects(&with_payload, crate::block::credit_seal_key(&with_payload.header, with_payload.cover_key.as_ref()).as_ref(), true),
            Err(ConsensusError::CreditSetNotCarriage),
            "⛔⛔⛔ the reduced-carrier door let a NOTE PAYLOAD ride"
        );
        // …but a carrier that IS present is judged on that door too.
        assert_eq!(
            credit_set_is_carried_with_its_subjects(&without_subject, crate::block::credit_seal_key(&without_subject.header, without_subject.cover_key.as_ref()).as_ref(), true),
            Err(ConsensusError::CreditObjectWithoutSubject),
            "⛔ the reduced-carrier door ignored a present carrier that does not commit the named note"
        );

        // The producer's half: a justifier staged WITHOUT its note never rides.
        let mut p = testnet_node();
        p.stage_credit_justifier(credit_for(&other).wire());
        let blk2 = p
            .produce(5_500, crate::hash::Hash32::hash(b"db224-orphan-fr"), crate::hash::Hash32::hash(b"db224-orphan-mc"))
            .expect("the producer still produces");
        assert!(
            crate::block::credit_set_iter(&blk2.credit_set, crate::block::credit_seal_key(&blk2.header, blk2.cover_key.as_ref()).as_ref(), &blk2.wide_objects).expect("parses").is_empty(),
            "⛔ the producer sealed an object whose note its own block does not carry"
        );
        assert_eq!(rules(&blk2), Ok(()), "and its block passes the rule every peer applies");
    }

    /// ⭐⭐⭐ DB-224 TAMPER AT THE §BA DOOR — A REFERENCE MUST MATCH ITS NOTE BYTE-EXACTLY.
    ///
    /// The door used to justify by `cm` alone, which excused ANY ciphertext behind a justified commitment.
    /// It now needs `(cm, blake3(payload))`. Driven through `graft_admitted_notes` itself: the honest
    /// carriage admits the note; a reference with a swapped commitment, and one with a swapped payload
    /// hash, admit nothing.
    #[test]
    fn db224_a_reference_that_does_not_match_its_note_byte_exactly_justifies_nothing() {
        let mut a = testnet_node();
        let note = sealed_note(crate::hash::Hash32::hash(b"db224-door-cm").as_bytes(), b"db224-door-ct");
        let (blk, _) = a.carry_notes_in_a_block_for_test(4_500, &note);
        let gid = blk.id();
        assert_eq!(
            a.graft_admitted_notes(&gid, &note, blk.cover_key, None, None, None, &blk.credit_set, &blk.wide_objects, &blk.bond_set, &blk.nullifier_proof.padded_tags, &blk.oli_tags),
            note,
            "CALIBRATION: the honest carried reference justifies its note"
        );
        let honest = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("parses").remove(0);
        let (_, payload) = crate::chain_object::unframe(&honest).expect("framed");
        let reference = crate::bridge_credit_tx::BridgeCreditTx::decode(payload).expect("decodes").note;
        assert_eq!(reference.len(), crate::chain_object::NOTE_REF_BYTES, "PRECONDITION: the carriage holds a reference");
        for (what, forged_ref) in [
            ("a commitment that is not the payload's front", {
                let mut r = reference.clone();
                r[..32].copy_from_slice(crate::hash::Hash32::hash(b"db224-other-cm").as_bytes());
                r
            }),
            ("a payload hash that is not the payload's", {
                let mut r = reference.clone();
                r[32..].copy_from_slice(crate::hash::Hash32::hash(b"db224-other-ct").as_bytes());
                r
            }),
        ] {
            let mut c = crate::bridge_credit_tx::BridgeCreditTx::decode(payload).expect("decodes");
            c.note = forged_ref;
            let forged = crate::node::tests::sealed_credit_parts(&blk, &[c.wire()]);
            assert!(
                a.graft_admitted_notes(&gid, &note, blk.cover_key, None, None, None, &forged.0, &forged.1, &blk.bond_set, &blk.nullifier_proof.padded_tags, &blk.oli_tags)
                    .is_empty(),
                "⛔⛔⛔ a reference with {what} still justified the note at the graft door"
            );
        }
    }

    /// ⭐⭐⭐ DB-224 (found in the rehydrate seam) — A PEER THAT POOLED ONLY PART OF A BLOCK STILL GRAFTS IT.
    ///
    /// `rehydrate_block_body` installed whatever subset of the block's notes this node's pool could
    /// derive, and `validate_structural` then checked that non-empty subset against the header's
    /// `output_notes_root` and REFUSED the block — so a node that pooled a gossiped credit but could never
    /// pool the note the producer staged beside it refused a perfectly valid block. A pool gap must never
    /// be a consensus failure; the partial body is now installed as nothing, like a node that pooled none.
    #[test]
    fn db224_a_peer_that_pooled_only_part_of_a_blocks_notes_still_grafts_it() {
        let mut a = testnet_node();
        let mut c = testnet_node();
        let n1 = sealed_note(crate::hash::Hash32::hash(b"db224-part-1").as_bytes(), b"db224-part-ct-1");
        let n2 = sealed_note(crate::hash::Hash32::hash(b"db224-part-2").as_bytes(), b"db224-part-ct-2");
        // n1 rides a PUBLISHED credit, which C pools as gossip would deliver it…
        let tx = credit_for(&n1).as_pq_tx(a.mempool().required_stamp_bits());
        a.ingest_tx(tx.clone()).expect("PRECONDITION: A pools the published credit");
        c.ingest_tx(tx).expect("PRECONDITION: C pools it too");
        // …n2 is STAGED on A, so no other node can ever pool it.
        a.stage_credit_note(n2.clone());
        a.stage_credit_justifier(credit_for(&n2).wire());
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db224-part-fr"), crate::hash::Hash32::hash(b"db224-part-mc"))
            .expect("A produces");
        assert!(
            contains(&blk.output_notes, &n1) && contains(&blk.output_notes, &n2),
            "PRECONDITION: the block commits BOTH notes, and C can derive only one of them"
        );
        assert_eq!(
            crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("parses").len(),
            2,
            "PRECONDITION: both justifiers ride the block, each with its subject"
        );
        let outcome = c.ingest_block(over_the_wire(&blk), 9_000);
        assert!(
            matches!(outcome, crate::relay::RelayOutcome::Added(_)),
            "⛔⛔⛔ a peer that pooled PART of the block's notes refused the block: {outcome:?} — a pool gap \
             became a consensus failure"
        );
    }

    /// ⭐⭐⭐ DB-224 — A WRAPPED PSM GOES FROM COVERED TO UNCOVERED ON A PEER FED ONLY THE WIRE, NO LIQUIDATION IS DUE
    /// ABOVE ITS DUE LINE, AND A FORGED LIQUIDATION A REAL BLOCK CARRIES MOVES NOTHING.
    ///
    /// Every object — the wrapped mint that opens the position, two price marks, and a forged v2 liquidation — rides a
    /// block A produces, and B, whose pool never holds any of them, is handed each block through its own wire codec:
    ///   * after the mint: the position's committed reserve/supply, equal to what the custodian's opening says;
    ///   * after the first mark: the position COVERED; after the second: NOT covered for a mint (135 % < 150 %);
    ///   * at 135 % (over the 125 % due line) the one amount rule plans NO liquidation, even against a full pool;
    ///   * a forged v2 object A's block carries leaves A and B on the pre-liquidation pair.
    /// The applied v2 journey is `a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool`.
    #[test]
    fn db224_a_wrapped_psm_goes_uncovered_on_a_wire_fed_peer_and_a_forged_liquidation_a_block_carries_moves_nothing() {
        use crate::peg::PegLedger;
        use crate::mesh_runtime_scenarios::tests::RtSim;
        const DEPOSIT: u128 = 3_000;
        const MINTED: u128 = 2_000;
        // A (party 0) and B (party 1) run their real runtimes on the hub (cells + the bulk lane): since DB-274 P4b every
        // object of this journey applies at its block's FOLD, the fold needs the block's RECORD, and the wire never
        // carries it (DB-224) — B fetches it by id over the DA lane from A, as the live nodes do.
        let (a0, b0, pk, sk) = pair();
        let mut s = RtSim::with_nodes(vec![a0, b0], 0x224_1a_2026_1002);
        s.arm_deadline(std::time::Duration::from_secs(600));
        // A lays the block (stamped past the hub's clock), B is handed it through its wire codec, and the hub drains until
        // B's fold has passed it — so every assertion on B below reads a block B has APPLIED.
        fn ship(s: &mut RtSim, tag: &[u8], last_ts: &mut u64) -> crate::block::Block {
            // strictly after the previous ship's block, whatever the hub's clock did in between (the MTP rule)
            let ts = (s.now() + 1_000).max(*last_ts + 1_000);
            *last_ts = ts;
            let blk = s
                .node_mut(0)
                .produce(ts, crate::hash::Hash32::hash(tag), crate::hash::Hash32::hash(b"db224-liq-mc"))
                .expect("A produces");
            let outcome = s.node_mut(1).ingest_block(over_the_wire(&blk), ts + 400);
            assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused a wire block: {outcome:?}");
            let id = blk.id();
            // BOTH parties past the block's fold: a reorg on the hub can send A back through its own block's re-fold, and
            // every assertion below reads A as well as B.
            assert!(
                s.rounds_until(120, |s| {
                    s.node(0).block_record_folded_for_test(&id) && s.node(1).block_record_folded_for_test(&id)
                }),
                "⛔ the shipped block was not folded on both parties in 120 rounds — B's DA lane did not deliver its \
                 record, or A's re-fold never passed it"
            );
            assert!(
                !s.node(0).band_door_is_stale() && !s.node(1).band_door_is_stale(),
                "⛔ a party's band went stale over the hub — its pool can prove no spend from here"
            );
            blk
        }

        // ── 1. THE POSITION OPENS: a wrapped mint of 2,000 against a 3,000-unit deposit (150%).
        let addr = "bc1pdb224liquidation";
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0x71, 0x72, 0x73, 0x74]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x224, 0x11, 0x4]);
        let (wcarrier, wcm, _wdc) = usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(
            MINTED as u64,
            wtag,
            &note_sk,
            &wdb,
        )
        .expect("an authorized amount proves its own commitment in its own asset");
        let note = sealed_note(&crate::spend_frontier::leaf_to_cm_bytes(wcm), b"db224-liq-note");
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        assert_eq!(
            s.node_mut(0).publish_wrapped_mint(
                ASSET, [0x71u8; 32], DEPOSIT, MINTED, recipient_of(&[0x71u8; 32]), &note, &wcarrier, addr, &pk, &sk,
                &[], &crate::pqauth::MlDsaVerifier, &owner_clue(), wdb,
            ),
            crate::peg::PegOutcome::ConfidentialPublished,
            "PRECONDITION: the position's mint publishes on A"
        );
        let mut last_ts = 0u64;
        ship(&mut s, b"db224-liq-fr-1", &mut last_ts);
        // The custodian's opening after that mint is a pure function of the genesis opening — so this pin
        // KNOWS the values and blinds the chain committed to, and proves that it does before relying on it.
        let (genesis_rb, genesis_mb) = crate::peg::psm_genesis_blinds(ASSET);
        let (r_val, r_blind, m_val, m_blind) = PegLedger::opening_after_wrapped_mint(
            0,
            genesis_rb,
            0,
            genesis_mb,
            DEPOSIT,
            MINTED,
            &wdb,
        );
        let opened = PegLedger::commits_of_opening(r_val, r_blind, m_val, m_blind);
        assert_eq!(
            s.node(1).peg().wrapped_asset_commits(ASSET),
            Some(opened),
            "PRECONDITION: B holds the position's committed pair from the block, and it opens to the custodian's values"
        );
        assert_eq!(s.node(0).peg().wrapped_asset_commits(ASSET), Some(opened), "…and so does A");
        let hwm = s.node(1).peg().wrapped_asset_hwm_commit(ASSET).expect("the wrapped PSM has a high-water mark");
        assert_eq!(hwm, opened.0, "PRECONDITION: the mint raised the PSM's HWM to its reserve");

        // ── 2. THE PRICE MOVES — two marks, each on the wire, each read on B.
        let covered = |n: &Node| n.peg().mint_is_covered_by_priced_deposit(ASSET, DEPOSIT, MINTED);
        let hi = crate::liquidation::PRICE_SCALE * 12 / 10;
        let lo = crate::liquidation::PRICE_SCALE * 9 / 10;
        let mark = a_price_mark_tx(s.node(0), &pk, &sk, 1, hi);
        s.node_mut(0).ingest_tx(mark).expect("PRECONDITION: the first mark pools on A");
        ship(&mut s, b"db224-liq-fr-2", &mut last_ts);
        assert!(covered(s.node(1)), "⛔ at 1.2x the position must be COVERED on B (over-collateralized)");
        // Coverage reads the 7-day time-weighted price (spec §BR-4 TWAP; a mark folds into the history when a later epoch's
        // mark supersedes it). A dip that lasts one epoch moves nothing — a one-block price push cannot uncover a position…
        let mark = a_price_mark_tx(s.node(0), &pk, &sk, 2, lo);
        s.node_mut(0).ingest_tx(mark).expect("PRECONDITION: the second mark pools on A");
        ship(&mut s, b"db224-liq-fr-3", &mut last_ts);
        assert!(covered(s.node(1)), "⛔ a one-epoch dip to 0.9x uncovered the position on B (the TWAP must absorb it)");
        // …and a dip that STANDS does: 0.9x through epoch 30, folded by epoch 31's mark → TWAP (1.2·1 + 0.9·28) / 29 ≈ 0.91x
        for (epoch, tag) in [(30u64, &b"db224-liq-fr-3b"[..]), (31, &b"db224-liq-fr-3c"[..])] {
            let mark = a_price_mark_tx(s.node(0), &pk, &sk, epoch, lo);
            s.node_mut(0).ingest_tx(mark).expect("PRECONDITION: the standing dip's mark pools on A");
            ship(&mut s, tag, &mut last_ts);
        }
        // RE-MEASURED 2026-11-10: a registered wrapped asset is one atom per atom since the bridge's unit-for-unit rule
        // (`PegLedger::reference_price`, 2026-11-08: its minted total counts wrapped notes of the SAME coin, never USDm),
        // so no mark prices its cover and a standing dip uncovers nothing. The old assertion here (uncovered at a
        // standing 0.9x) read RED from that day. What still has to hold on the wire-fed peer: the marks travelled, and the
        // position's cover is the same on both nodes.
        assert_eq!(
            s.node(1).price_mark_for(ASSET),
            s.node(0).price_mark_for(ASSET),
            "⛔ the standing mark did not travel: B holds a different mark from A"
        );
        assert!(
            covered(s.node(1)) && covered(s.node(0)),
            "⛔ a wrapped position's cover moved with a price mark: it is unit for unit and no mark prices it"
        );

        // ── 3. NOT DUE (spec §10): at 0.9× the PSM backs its supply 135 % — under its 150 % MINT ratio (new mints are
        //       refused, above) but over its 125 % due line, so the ONE amount rule plans NO liquidation, whatever the pool
        //       holds (the v1 re-mark door that closed it here regardless is deleted). The applied journey — a due PSM, a
        //       funded pool, the five legs, a peer holding one peg and one pool — is
        //       `a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool`.
        let _ = hwm;
        let rule = s.node(1).peg().liquidation_rule(ASSET).expect("B derives the PSM's rule from the wire-carried mark");
        let full_pool = crate::peg::LiquidationOpening {
            reserve: r_val,
            reserve_blind: r_blind,
            minted: m_val,
            minted_blind: m_blind,
            pool_t: m_val,
            pool_t_blind: crate::peg::GENESIS_POOL_T_BLIND,
            pool_p: crate::peg::POOL_P_SCALE,
            pool_p_blind: crate::peg::GENESIS_POOL_P_BLIND,
            pool_s: [0; 4],
            pool_s_blind: crate::peg::GENESIS_POOL_S_BLIND,
        };
        assert!(
            crate::peg::plan_liquidation(&full_pool, &rule).is_none(),
            "⛔ a PSM above its due line planned a liquidation — a free seizure"
        );
        // A FORGED v2 object (legs that prove nothing, the bonded key's signature over its message) carried by A's block on
        // the wire moves nothing on B.
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let forged_h = crate::liquidation_tx::LiquidationHeader {
            epoch_id: 1,
            asset_id: ASSET,
            position_id: [0x7Au8; 32],
            retired_commit: l(&[0x81, 1, 1, 1]),
            seized_commit: l(&[0x82, 2, 2, 2]),
            new_reserve_commit: l(&[0x83, 3, 3, 3]),
            new_minted_commit: l(&[0x84, 4, 4, 4]),
            new_pool_t: l(&[0x85, 5, 5, 5]),
            new_pool_p: l(&[0x86, 6, 6, 6]),
            new_pool_s: l(&[0x87, 7, 7, 7]),
            pool_close: false,
        };
        let junk = crate::liquidation_tx::LiquidationLegs {
            amount: vec![1u8; 64],
            pool_transition: vec![2u8; 64],
            pool_step: vec![3u8; 64],
            retire: vec![4u8; 64],
            seize: vec![5u8; 64],
        };
        let msg = s.node(0).peg().liquidation_attest_msg(&forged_h).expect("the wrapped PSM is priced");
        let att = vec![MintAttestor { pubkey: pk.clone(), sig: crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded key signs") }];
        s.node_mut(0).publish_liquidation(&forged_h, &junk, &att).expect("PRECONDITION: the bytes are admissible as bytes");
        assert!(s.node(1).mempool().is_empty(), "PRECONDITION: B never pooled any object of this journey");
        let liq_blk = ship(&mut s, b"db224-liq-fr-4", &mut last_ts);

        assert_eq!(crate::block::credit_set_iter(&liq_blk.credit_set, crate::block::credit_seal_key(&liq_blk.header, liq_blk.cover_key.as_ref()).as_ref(), &liq_blk.wide_objects).expect("parses").len(), 1, "PRECONDITION: the block carries it");
        for (who, n) in [("A", s.node(0)), ("B", s.node(1))] {
            assert_eq!(n.peg().wrapped_asset_commits(ASSET), Some(opened), "⛔⛔⛔ {who} applied a forged liquidation");
        }
        let diffs = peg_divergences(s.node(1).peg(), s.node(0).peg(), &[]);
        assert!(diffs.is_empty(), "⛔ B and A disagree after the forged liquidation:\n  {}", diffs.join("\n  "));
    }

    /// ⭐⭐⭐ DB-224 — A FILL WHOSE INPUTS A REAL CHAIN ROUTE FUNDED SETTLES ON A PEER FED ONLY THE WIRE.
    ///
    /// The register's `OrderFill` row is Unproven for one measured reason: every settlement pin put its
    /// inputs on chain through a test-only door, so no journey showed a fill over notes a real route
    /// created. Here both inputs arrive the way a user's do:
    ///   * the maker's USDm lot — a BRIDGE CREDIT published as a transaction (the faucet's own wrapper,
    ///     `BridgeCreditTx::as_pq_tx`) crediting EXACTLY the lot its note commits to;
    ///   * the taker's wrapped-asset input — a real WRAPPED MINT (`publish_wrapped_mint`) whose mint
    ///     carrier proves the taker's own note.
    /// A produces the blocks that carry them, and B and C receive each of them through its wire codec.
    /// The chain runs at the production record depth, not a fixture's fold-at-tip. Each input's membership
    /// bind is built from A's own served record — the in-record copath and the one-step carrier a wallet
    /// builds — never planted.
    ///
    /// A settles the fill; C pools the gossiped settlement and produces the block that carries it; B never
    /// pools anything. What must hold:
    ///   * on B, from the wire block alone: the order is gone from its book, and a replay of the settlement
    ///     is refused by its pool and by its DEX door (never `Settled` twice);
    ///   * no byte of the maker's payout ciphertext is on the wire (the DB-224 carriage);
    ///   * on C, which holds the payloads: the maker's payout is recorded exactly once.
    #[test]
    fn db224_a_fill_whose_inputs_a_real_chain_funded_settles_on_a_peer_fed_only_the_wire() {
        use crate::chain_object::Class;
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::{
            asset_note_cm, prove_order_maker_half, prove_order_taker_half, MakerHalfWitness, OrderTerms,
            TakerHalfWitness, USDM_ASSET_TAG,
        };
        let (mut v, pk, sk) = parties(3);
        let mut c = v.pop().expect("three parties");
        let mut b = v.pop().expect("three parties");
        let mut a = v.pop().expect("three parties");
        let ship = |blk: &crate::block::Block, to: &mut Node, at: u64| {
            let out = to.ingest_block(over_the_wire(blk), at);
            assert!(matches!(out, crate::relay::RelayOutcome::Added(_)), "⛔ a wire block was refused: {out:?}");
        };
        let mut ts = 4_500u64;
        let mut next_ts = || {
            ts += 1_000;
            ts
        };

        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: USDM_ASSET_TAG,
            asset_b: wtag,
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        };
        let mw = MakerHalfWitness {
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[7_101, 7_102, 7_103, 7_104])),
            payout_opening: lanes_of(&[7_111, 7_112, 7_113, 7_114]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        let tw = TakerHalfWitness {
            value_in: 1_000_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[8_101, 8_102, 8_103, 8_104])),
            change_opening: lanes_of(&[8_111, 8_112, 8_113, 8_114]),
            payout_opening: lanes_of(&[8_121, 8_122, 8_123, 8_124]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        let (maker_bytes, mp) = prove_order_maker_half(&mw, &t).expect("the maker half proves");
        let (taker_bytes, tp) =
            prove_order_taker_half(&tw, &t, a.params().order_fill_fee_bps).expect("the taker half proves");
        let cm_of = |value: u64, tag: [u64; 3], key: crate::spend_frontier::Digest4| -> [u8; 32] {
            crate::spend_frontier::leaf_to_cm_bytes(asset_note_cm(value, tag, key))
        };
        let (maker_in, taker_in) = (cm_of(t.lot, t.asset_a, mw.owner.opening()), cm_of(tw.value_in, t.asset_b, tw.owner.opening()));

        // ── 1. THE MAKER'S LOT: a bridge credit PUBLISHED as a transaction, crediting exactly the lot.
        let credit = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: *crate::hash::Hash32::hash(b"db224-fill-maker-deposit").as_bytes(),
            asset_tag: USDM_ASSET_TAG,
            amount: t.lot,
            note: sealed_note(&maker_in, b"db224-fill-maker-lot"),
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        a.ingest_tx(credit.as_pq_tx(a.mempool().required_stamp_bits()))
            .expect("PRECONDITION: the credit pools on A, as a faucet drip's does");
        let now = next_ts();
        let credit_blk = a
            .produce(now, crate::hash::Hash32::hash(b"db224-fill-fr-1"), crate::hash::Hash32::hash(b"db224-fill-mc"))
            .expect("A produces the credit block");
        ship(&credit_blk, &mut b, now + 400);
        ship(&credit_blk, &mut c, now + 400);
        assert!(a.holds_record_with_cm(&maker_in), "PRECONDITION: the maker's lot is on A's chain");

        // ── 2. THE TAKER'S INPUT: a real wrapped mint over the taker's own note, in asset b.
        let wdb = lanes_of(&[0xdbu64, 0x224, 0xf1, 0x11]);
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(tw.value_in, wtag, &tw.owner.opening(), &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        assert_eq!(
            crate::spend_frontier::leaf_to_cm_bytes(wcm),
            taker_in,
            "PRECONDITION: the wrapped mint creates exactly the note the taker's half spends"
        );
        let addr = "bc1pdb224fillmint";
        crate::btc_watch::inject_confirmed_for_test(addr, 10_000_000);
        assert_eq!(
            a.publish_wrapped_mint(
                ASSET, [0xF1u8; 32], 2 * tw.value_in as u128, tw.value_in as u128, recipient_of(&[0xF1u8; 32]),
                &sealed_note(&taker_in, b"db224-fill-taker-input"), &wcarrier, addr, &pk, &sk, &[],
                &crate::pqauth::MlDsaVerifier, &owner_clue(), wdb,
            ),
            crate::peg::PegOutcome::ConfidentialPublished,
            "PRECONDITION: the taker's wrapped mint publishes on A"
        );
        let now = next_ts();
        let mint_blk = a
            .produce(now, crate::hash::Hash32::hash(b"db224-fill-fr-2"), crate::hash::Hash32::hash(b"db224-fill-mc"))
            .expect("A produces the mint block");
        ship(&mint_blk, &mut b, now + 400);
        ship(&mint_blk, &mut c, now + 400);
        assert!(a.holds_record_with_cm(&taker_in), "PRECONDITION: the taker's input is on A's chain");

        // ── 3. ADVANCE PAST THE PRODUCTION RECORD DEPTH (a fixed protocol constant, 32), so both records
        //       have entered the accumulator every party checks a bind against.
        for i in 0..=a.params().record_fold_depth {
            let now = next_ts();
            let blk = a
                .produce(now, crate::hash::Hash32::hash(&i.to_le_bytes()), crate::hash::Hash32::hash(b"db224-fill-mc"))
                .expect("A produces past the record depth");
            ship(&blk, &mut b, now + 400);
            ship(&blk, &mut c, now + 400);
        }
        for n in [&mut a, &mut b, &mut c] {
            let _ = n.fold_canonical_records();
        }

        // ── 4. EACH INPUT'S MEMBERSHIP BIND, built from A's own served record — never planted.
        let bind = |n: &Node, blk: &crate::block::Block, cm: &[u8; 32], binder: crate::spend_frontier::Digest4| {
            let rid = n.record_addr_for_block_or_canonical(&blk.id());
            let notes = n.da_record_notes(rid).expect("A holds the block's record");
            let slot = notes
                .chunks(crate::cover::PQ_NOTE_BYTES)
                .position(|x| x.len() >= 32 && x[..32] == cm[..])
                .expect("the input sits in its own block's record") as u8;
            let leaf = n
                .da_block_leaves(rid)
                .and_then(|l| l.get(slot as usize).copied())
                .expect("a frontier leaf at the note's own slot");
            let (sibs, dirs, root) = n.da_note_copath_in_block(rid, slot).expect("A serves the in-record copath");
            let mut carrier =
                NoteMembershipCarrier::new(leaf, root, Node::MEMBERSHIP_GENESIS_ACC, binder, crate::spend_frontier::TEST_LC_BLIND);
            assert!(carrier.attach_membership(leaf, &sibs, &dirs), "the record copath reaches the record root");
            let (proof, acc, tip_prev, tip_root) = carrier.finalize_one_step().expect("the one-step carrier certifies");
            let mut tip = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
            for d in [Node::MEMBERSHIP_GENESIS_ACC, tip_prev, tip_root, acc] {
                tip.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
            }
            tip.extend_from_slice(&rid.to_le_bytes());
            (proof, tip)
        };
        let maker_bind = bind(&a, &credit_blk, &maker_in, mp.nullifier);
        let taker_bind = bind(&a, &mint_blk, &taker_in, tp.nullifier);
        // DB-273 §19.6 L3: each party's owner clue at ITS OWN `chg` locator — nothing the chain links to a wallet.
        let clue_at = |seed: &[u8]| {
            let loc_sk = crate::oli::derive_loc_sk(blake3::hash(seed).as_bytes());
            let salt = crate::oli::address_salt(&loc_sk, "chg", 0);
            crate::oli::tag_clue_bytes_v2(
                &crate::oli::locator_at(&loc_sk, "chg", 0),
                &salt,
                &crate::oli::address_index_hint(&loc_sk, &salt, 0),
            )
        };
        let maker_payout_clue = clue_at(b"db273-l3-maker-owner");

        // ── 5. THE ORDER RESTS ON A AND REACHES B AND C AS THE RUNTIME GOSSIPS IT.
        let resting = crate::order_book::RestingOrder {
            terms: t,
            maker: mp.clone(),
            maker_bytes: maker_bytes.clone(),
            payout_note: sealed_note(&crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm), b"db224-fill-maker-payout"),
            membership_carrier: crate::order_book::test_membership_bind().0,
            membership_tip: crate::order_book::test_membership_bind().1,
            // DB-273 §19.6 L3: the MAKER's own payout owner — a real OLI clue at its own `chg` locator.
            payout_clue: maker_payout_clue.clone(),
        };
        let gossiped = || -> crate::order_book::RestingOrder {
            let bytes = postcard::to_allocvec(&crate::order_book::OrderWire::of(&resting)).expect("the order encodes");
            postcard::from_bytes::<crate::order_book::OrderWire>(&bytes).expect("the order decodes").into_order()
        };
        a.post_order(resting.clone()).expect("PRECONDITION: the order rests on A");
        let level_b = b.post_order(gossiped()).expect("PRECONDITION: B admits the gossiped order");
        c.post_order(gossiped()).expect("PRECONDITION: C admits the gossiped order");
        assert!(
            !b.book_level(resting.pair(), level_b).0.is_empty(),
            "CONTROL: B's book holds the order before any settlement"
        );

        // ── 6. A SETTLES THE FILL over the two funded inputs.
        let maker_payout = resting.payout_note.clone();
        let taker_payout = sealed_note(&crate::spend_frontier::leaf_to_cm_bytes(tp.payout_cm), b"db224-fill-taker-payout");
        let taker_change = sealed_note(&crate::spend_frontier::leaf_to_cm_bytes(tp.change_cm), b"db224-fill-taker-change");
        // DB-273 §19.6 L3: slot 0 is what the fill DOOR copies — the maker's clue from the order resting in A's book
        // (never the taker's word); slots 1–2 are the taker's own clues.
        let slot0 = a.order_payout_clue(mp.nullifier).expect("PRECONDITION: A's book holds the maker's payout owner");
        assert_eq!(slot0, maker_payout_clue, "PRECONDITION: the book serves the clue the maker posted");
        let (taker_payout_clue, taker_change_clue) = (clue_at(b"db273-l3-taker-payout"), clue_at(b"db273-l3-taker-change"));
        assert_eq!(
            a.execute_order_fill(
                &maker_bytes, &mp, &taker_bytes, &tp, &t, &maker_payout, &taker_payout, &taker_change,
                [slot0, taker_payout_clue.clone(), taker_change_clue.clone()], [Some(maker_bind), Some(taker_bind)],
            ),
            crate::node::OrderFillOutcome::Settled,
            "⛔ A refused a fill whose inputs a real chain route funded"
        );
        let settle_tx = a
            .mempool()
            .all_tx_ids()
            .into_iter()
            .filter_map(|id| a.mempool().get(&crate::hash::Hash32(id)).cloned())
            .find(|tx| crate::chain_object::unframe(&tx.blob).map(|(k, _)| k) == Some(Class::OrderFill))
            .expect("A published the settlement as a transaction");

        // ── 7. C pools the gossiped settlement and PRODUCES; B receives only the wire block.
        c.ingest_tx(settle_tx.clone()).expect("PRECONDITION: the gossiped settlement is admissible on C");
        // DB-273 §19.6 L3, hop 1: C — which heard no request — staged the MAKER's owner from the gossiped OBJECT.
        assert_eq!(
            c.note_clue(&crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm)),
            Some(&maker_payout_clue[..]),
            "⛔ DB-273 §19.6 L3: C did not stage the maker's payout owner from the settlement object it pooled"
        );
        assert!(b.mempool().is_empty(), "PRECONDITION: B never pooled anything in this journey");
        let now = next_ts();
        let settle_blk = c
            .produce(now, crate::hash::Hash32::hash(b"db224-fill-fr-3"), crate::hash::Hash32::hash(b"db224-fill-mc-c"))
            .expect("C produces the block carrying the settlement");
        // DB-273 §19.6 L3, hop 2: the block C authored carries the maker's payout tag (cm ‖ k) for every peer.
        let tag_w = 32 + crate::oli::K_BYTES;
        let maker_tag_carried = settle_blk.oli_tags.chunks(tag_w).any(|t| {
            t.len() == tag_w
                && t[..32] == crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm)
                && t[32..] == crate::oli::index_key(&maker_payout_clue)[..]
        });
        eprintln!(
            "[db273-l3] C's settlement block: {} tag(s); the maker's payout tag carried = {maker_tag_carried}",
            settle_blk.oli_tags.len() / tag_w
        );
        assert!(maker_tag_carried, "⛔ DB-273 §19.6 L3: the block C authored does not carry the maker's payout tag");
        let wire = postcard::to_allocvec(&settle_blk).expect("the block encodes");
        assert!(
            contains(&postcard::to_allocvec(&settle_tx).expect("the tx encodes"), &maker_payout[32..]),
            "calibration: the search finds the payout ciphertext where it really is"
        );
        assert!(!contains(&wire, &maker_payout[32..]), "⛔ DB-224: the maker payout's ciphertext is on the block wire");
        ship(&settle_blk, &mut b, now + 400);

        // ── WHAT B HOLDS, from the wire block alone.
        assert!(
            b.book_level(resting.pair(), level_b).0.is_empty(),
            "⛔⛔⛔ B still rests the order after the block that settled it — the settlement did not travel"
        );
        assert!(
            b.ingest_tx(settle_tx.clone()).is_err(),
            "⛔ FUND SAFETY: B's pool re-admitted a settlement its chain already carried — the inputs are spent"
        );
        // The DEX door must not settle the same fill twice. MEASURED 2026-09-26: on a peer fed ONLY the wire
        // it answers `MembershipRefused` — B holds the input blocks but not their note payloads (those reach
        // a peer through the record lane, which does not run in process), so the inputs' binds cannot verify
        // there, and that check precedes the book's `OrderAlreadyFilled`. Either refusal keeps the maker's lot
        // from paying twice; `Settled` is the one answer that would not.
        let replay = crate::node::objects::order_fill_tx::apply_chain_dex_object(&mut b, &settle_tx.blob);
        eprintln!(
            "[db224-fill] B's DEX door on the replay: {replay:?} (B holds the maker's input payload: {})",
            b.holds_record_with_cm(&maker_in)
        );
        assert!(
            !matches!(replay, crate::order_fill_tx::DexApply::Fill(crate::node::OrderFillOutcome::Settled)),
            "⛔ FUND SAFETY: B's DEX door SETTLED a replay of a settlement its chain already carried: {replay:?}"
        );
        // …and C, which holds the payloads, recorded the maker's payout exactly once.
        let maker_payout_cm = crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm);
        assert_eq!(
            c.records_containing_cm(&maker_payout_cm).len(),
            1,
            "⛔ C must record the maker's payout exactly once"
        );

        // ⭐⭐⭐ DB-273 §19.6 L3 (a) — hops 1 and 2 are asserted above: C, which never heard the fill request, staged the
        // MAKER's owner from the gossiped object, and the block C authored carries the maker's payout tag. RED-run: with
        // `Class::OrderFill` removed from `object_owner_clue_records`, hop 1 fails (a fill's sidecar is empty and ignored).
        // ⭐ DB-366 ACCEPTANCE (lane-db224-carriage's §3 text, verbatim): every fill output is FILED by the carrying block's
        // tags AND recorded in that block's own record — RED on main before L3c (0 of 3 filed), GREEN with it.
        let carried_rid = crate::node::Node::da_record_id_for_block(&settle_blk.id(), 0);
        let filed = crate::note_transition::filed_keys(&settle_blk.oli_tags).expect("the block's tags are whole records");
        for (what, cm) in [
            ("maker payout", crate::spend_frontier::leaf_to_cm_bytes(mp.payout_cm)),
            ("taker payout", crate::spend_frontier::leaf_to_cm_bytes(tp.payout_cm)),
            ("taker change", crate::spend_frontier::leaf_to_cm_bytes(tp.change_cm)),
        ] {
            assert!(filed.contains_key(&cm), "⛔ DB-366: the settlement block files no locator key for the fill's {what}");
            let rids: Vec<u64> = c.records_containing_cm(&cm).iter().map(|r| r.0).collect();
            assert_eq!(rids, vec![carried_rid], "⛔ DB-366: the fill's {what} is recorded outside the block whose tags name it");
        }
    }

    /// ⭐⭐⭐ DB-240 — A PRICE QUORUM GATHERED OVER THE LANE PUBLISHES ONE MARK, AND A PEER APPLIES IT FROM
    /// THE WIRE.
    ///
    /// Three bonded validators of equal weight sit on both parties. Their quotes cross the lane in the ONE
    /// wire form (`SignedQuote::wire` → `decode`).
    ///   * B hears one quote (1/3 of bonded weight) and must NOT publish.
    ///   * A hears two (2/3), publishes exactly one `Class::PriceMark`, and does not publish it twice.
    ///   * The mark rides A's block; B, which never published, holds A's mark from the wire block alone.
    /// CONTROL: B holds no mark before the block. Before DB-240 nothing in production built a quote at all.
    #[test]
    fn db240_a_price_quorum_gathered_over_the_lane_publishes_one_mark_a_peer_applies_from_the_wire() {
        use crate::price_quote::{sign_quote, SignedQuote};
        let v = crate::pqauth::MlDsaVerifier;
        let (mut parties_v, pk0, sk0) = parties(2);
        let mut b = parties_v.pop().expect("two parties");
        let mut a = parties_v.pop().expect("two parties");
        // DB-387 (user ruling): the mark needs STRICTLY more than 2/3 — 2f+1 of 3f+1. Four equal custodians (f = 1): three quotes.
        let extra: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        for n in [&mut a, &mut b] {
            for (pk, _) in &extra {
                n.admit_validator(crate::pqauth::pubkey_id(pk), 20_000, 0).expect("an equal bond admits");
            }
        }
        let signers = [(pk0, sk0), extra[0].clone(), extra[1].clone(), extra[2].clone()];
        let epoch = a.current_price_epoch();
        assert_eq!(epoch, b.current_price_epoch(), "PRECONDITION: one chain, one epoch");
        let prices = [14_000u128, 15_000, 16_000, 15_500];
        let over_the_lane = |i: usize| -> SignedQuote {
            let q = sign_quote(epoch, ASSET, prices[i], &signers[i].0, &signers[i].1).expect("a bonded key signs");
            SignedQuote::decode(&q.wire().expect("encodes")).expect("the lane's one wire form decodes")
        };

        // B hears ONE quote — a quarter of bonded weight — and must not publish.
        assert!(b.price_quote_ingest(&over_the_lane(2), &v), "B gathers the quote it heard");
        assert_eq!(b.publish_price_marks_if_quorum(&v), 0, "⛔ a quarter of bonded weight is not a quorum");

        // A hears two (one half: no), then three (three quarters, strictly above 2/3) and publishes exactly one mark, once.
        assert!(a.price_quote_ingest(&over_the_lane(0), &v));
        assert_eq!(a.publish_price_marks_if_quorum(&v), 0, "CONTROL: one quote alone publishes nothing");
        assert!(a.price_quote_ingest(&over_the_lane(1), &v));
        assert_eq!(a.publish_price_marks_if_quorum(&v), 0, "⛔ DB-387: half of bonded weight published a mark");
        assert!(a.price_quote_ingest(&over_the_lane(3), &v));
        assert_eq!(a.publish_price_marks_if_quorum(&v), 1, "⛔ A holds a strict 2/3 quorum and published no mark");
        assert_eq!(a.publish_price_marks_if_quorum(&v), 0, "⛔ a node publishes one mark per asset per epoch");
        // A publication that left the pool with no mark on the chain travels again (a mark refused at its fold once left every node mute for the epoch).
        a.drop_published_mark_for_test(ASSET);
        assert_eq!(a.publish_price_marks_if_quorum(&v), 1, "⛔ a mark that left the pool unapplied was never published again");
        assert_eq!(a.publish_price_marks_if_quorum(&v), 0, "⛔ a node publishes one mark while one is travelling");

        // The mark rides A's block; B applies it from the wire alone.
        assert_eq!(b.price_mark_for(ASSET), None, "CONTROL: B holds no mark before the block");
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db240-fr"), crate::hash::Hash32::hash(b"db240-mc"))
            .expect("A produces the block carrying the mark");
        let mark_a = a.price_mark_for(ASSET).expect("PRECONDITION: A applied its own block's mark");
        assert_eq!(mark_a.epoch_id, epoch);
        let outcome = b.ingest_block(over_the_wire(&blk), 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "⛔ B refused the wire block: {outcome:?}");
        assert_eq!(
            b.price_mark_for(ASSET),
            Some(mark_a),
            "⛔⛔⛔ DB-240: B grafted the block and does not hold the mark the quorum published"
        );
        assert!(
            (14_000..=15_500).contains(&mark_a.price),
            "the mark is the bond-weighted median of the three counted quotes, not an outlier: {}",
            mark_a.price
        );
    }

    /// ⭐ DB-240 / §21 — the relays' answers, through the node's real reporter, across two nodes: validator A quotes Bitcoin
    /// at what its relays agree on and nothing for an asset no relay prices (the wrapped test asset, SAT); node B's gather
    /// door takes A's quote as a new bonded quote for the epoch; stale answers quote nothing; an unbonded key quotes nothing.
    #[test]
    fn db240_a_validator_quotes_only_what_its_relays_agree_on_and_a_peer_gathers_it() {
        let (mut parties_v, pk, sk) = parties(2);
        let mut b = parties_v.pop().expect("party B");
        let mut a = parties_v.pop().expect("party A");
        const NOW: u64 = 1_730_250_000_000;
        let answers: Vec<crate::price_relay::Answer> = (0..crate::price_relay::RELAYS.len())
            .filter_map(|i| {
                let r = &crate::price_relay::RELAYS[i];
                crate::price_relay::parse(r.network, &crate::price_relay::sim_body(i, 15_000.0, 150.0, NOW))
            })
            .collect();
        a.set_relay_answers(answers);
        let quotes = a.own_price_quotes(&pk, &sk, NOW);
        let btc: Vec<_> = quotes.iter().filter(|q| q.asset_id == crate::peg::NATIVE_PEG_ASSET_ID).collect();
        assert_eq!(btc.len(), 1, "Bitcoin is quoted once: {quotes:?}");
        assert_eq!(btc[0].quote.price, 15_000 * crate::liquidation::PRICE_SCALE);
        assert_eq!(btc[0].epoch_id, a.current_price_epoch());
        assert!(quotes.iter().all(|q| q.asset_id != ASSET && q.asset_id != crate::peg::SAT_PRICE_ASSET_ID), "⛔ no relay prices these");
        assert!(b.price_quote_ingest(btc[0], &crate::pqauth::MlDsaVerifier), "the peer gathers A's quote as a new bonded quote");
        assert!(!b.price_quote_ingest(btc[0], &crate::pqauth::MlDsaVerifier), "and only once");
        assert!(a.own_price_quotes(&pk, &sk, NOW + crate::price_relay::FRESH_MS + 1).is_empty(), "⛔ stale answers quote nothing");
        let (stranger_pk, stranger_sk) = crate::pqauth::ml_dsa_keypair();
        assert!(a.own_price_quotes(&stranger_pk, &stranger_sk, NOW).is_empty(), "⛔ an unbonded key must not produce a quote");
    }

    /// ⛔⛔⛔ DB-245 — TWO VALID MARKS FOR ONE EPOCH MUST LEAVE EVERY NODE ON THE SAME PRICE, IN EITHER ORDER.
    ///
    /// DB-240 lets every node that gathers ≥2/3 of the quotes publish, so two quorate nodes can publish two
    /// valid marks for one `(epoch, asset)` over different subsets, with different medians. At DAG width > 1
    /// they ride concurrent blocks, and each peer grafts them in arrival order. The door kept the FIRST mark of
    /// an epoch, so the price a node stood on was its arrival order.
    ///
    /// A and B apply the same two marks through `apply_chain_price_mark`, the seam graft calls, in OPPOSITE
    /// orders.
    /// CONTROL: each mark alone sets a different price.
    /// CLAIM: both nodes end on the same mark, and re-applying either mark moves neither.
    /// TAMPERS:
    ///   * a same-epoch mark whose price WOULD outrank, carried by 1/3 of the weight, is refused;
    ///   * an earlier-epoch mark is refused before its price is considered.
    #[test]
    fn db245_two_marks_for_one_epoch_leave_every_node_on_the_same_price_in_either_order() {
        use crate::node::objects::price_mark_tx::apply_chain_price_mark as apply;
        use crate::price_mark_tx::PriceMarkApply;
        let v = crate::pqauth::MlDsaVerifier;
        let (mut parties_v, pk0, sk0) = parties(2);
        let mut b = parties_v.pop().expect("two parties");
        let mut a = parties_v.pop().expect("two parties");
        // DB-387 (user ruling): a mark needs STRICTLY more than 2/3 — four equal custodians, three quotes per mark.
        let extra: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        for n in [&mut a, &mut b] {
            for (pk, _) in &extra {
                n.admit_validator(crate::pqauth::pubkey_id(pk), 20_000, 0).expect("an equal bond admits");
            }
        }
        let signers = [(pk0, sk0), extra[0].clone(), extra[1].clone(), extra[2].clone()];
        let epoch = a.current_price_epoch() + 1;
        let quote = |e: u64, i: usize, price: u128| -> crate::price_mark_tx::PriceQuote {
            crate::price_quote::sign_quote(e, ASSET, price, &signers[i].0, &signers[i].1)
                .expect("a bonded key signs its quote")
                .quote
        };
        let mark = |e: u64, quotes: &[crate::price_mark_tx::PriceQuote]| -> Vec<u8> {
            crate::price_mark_tx::wire(&crate::price_mark_tx::PriceMarkHeader { epoch_id: e, asset_id: ASSET }, quotes)
        };
        // Two honest gatherers that heard different validators first: two 3-of-4 subsets, two medians.
        let m1 = mark(epoch, &[quote(epoch, 0, 14_000), quote(epoch, 1, 14_500), quote(epoch, 3, 14_200)]);
        let m2 = mark(epoch, &[quote(epoch, 1, 14_500), quote(epoch, 2, 16_000), quote(epoch, 3, 15_800)]);

        let first_a = apply(&mut a, &m1, &v);
        let first_b = apply(&mut b, &m2, &v);
        let (PriceMarkApply::Marked(p1), PriceMarkApply::Marked(p2)) = (&first_a, &first_b) else {
            panic!("PRECONDITION: both marks are valid strict-2/3 marks (A: {first_a:?}, B: {first_b:?})");
        };
        assert_ne!(p1, p2, "CONTROL: the two marks set DIFFERENT prices, or the order could not matter");
        let second_a = apply(&mut a, &m2, &v);
        let second_b = apply(&mut b, &m1, &v);
        let (ma, mb) = (a.price_mark_for(ASSET), b.price_mark_for(ASSET));
        eprintln!(
            "[db245] A applied m1 ({p1}) then m2: {second_a:?} -> {ma:?}; B applied m2 ({p2}) then m1: \
             {second_b:?} -> {mb:?}"
        );
        assert_eq!(
            ma, mb,
            "⛔⛔⛔ DB-245: two honest nodes grafted the SAME two marks in opposite orders and stand on different \
             prices — the mark is a function of arrival order, not of the chain"
        );
        let standing = ma.expect("a mark stands");
        let winner = if crate::price_mark_tx::outranks(epoch, ASSET, *p2, *p1) { *p2 } else { *p1 };
        assert_eq!(standing.price, winner, "the standing mark is the maximum of the one total order");

        // Re-applying either mark moves neither node.
        for (n, who) in [(&mut a, "A"), (&mut b, "B")] {
            for m in [&m1, &m2] {
                let again = apply(n, m, &v);
                assert_eq!(
                    again,
                    PriceMarkApply::Refused(crate::peg::PegOutcome::Replay),
                    "⛔ {who}: a mark this node already weighed must be refused on re-application"
                );
            }
            assert_eq!(n.price_mark_for(ASSET), Some(standing), "⛔ {who}: a refused re-application moved the mark");
        }

        // TAMPER 1: a same-epoch price that WOULD outrank, carried by one third of the weight, is refused.
        let outranking = (1..=10_000u128)
            .map(|d| standing.price + d)
            .find(|p| crate::price_mark_tx::outranks(epoch, ASSET, *p, standing.price))
            .expect("some nearby price outranks the standing one (a uniform hash)");
        let thin = mark(epoch, &[quote(epoch, 2, outranking)]);
        assert_eq!(
            apply(&mut a, &thin, &v),
            PriceMarkApply::Refused(crate::peg::PegOutcome::InsufficientThreshold),
            "⛔ a one-third mark must never replace the standing one, whatever its rank"
        );
        assert_eq!(a.price_mark_for(ASSET), Some(standing), "⛔ the refused tamper moved A's mark");

        // TAMPER 2: an earlier epoch is refused before its price is considered.
        let stale = mark(epoch - 1, &[quote(epoch - 1, 0, outranking), quote(epoch - 1, 1, outranking)]);
        assert_eq!(
            apply(&mut b, &stale, &v),
            PriceMarkApply::Refused(crate::peg::PegOutcome::Replay),
            "⛔ an earlier epoch must not re-mark"
        );
        assert_eq!(b.price_mark_for(ASSET), Some(standing), "⛔ the refused stale mark moved B's mark");
    }

    /// ⭐ DB-245 — BOUNDED WORK: A QUOTE THIS NODE ALREADY VERIFIED IS NEVER VERIFIED AGAIN.
    ///
    /// Quotes sign `(epoch, asset, price)`, never the mark, so anyone can copy the genuine quotes off the lane into
    /// any number of objects. Since DB-245 a same-epoch object is tallied instead of refused on its epoch alone.
    /// Without reuse, an object of copied genuine quotes plus one forgery placed LAST costs every grafting node one
    /// verify per quote, in every block that carries one.
    ///
    /// A gathered the three genuine quotes off the lane. It must pay ONE real verify for such an object: the
    /// forgery. CALIBRATION: B gathered nothing and pays all three, so the reuse is what bounds it. Both refuse the
    /// object, and neither moves its mark.
    #[test]
    fn db245_a_mark_of_copied_quotes_and_one_forgery_costs_a_gathering_node_one_verify() {
        struct Counting(std::cell::Cell<usize>);
        impl crate::pqauth::PqVerifier for Counting {
            fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
                self.0.set(self.0.get() + 1);
                crate::pqauth::MlDsaVerifier.verify(pubkey, msg, sig)
            }
        }
        let v = crate::pqauth::MlDsaVerifier;
        let (mut parties_v, pk0, sk0) = parties(2);
        let mut b = parties_v.pop().expect("two parties");
        let mut a = parties_v.pop().expect("two parties");
        let extra: Vec<(Vec<u8>, Vec<u8>)> = (0..2).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        for n in [&mut a, &mut b] {
            for (pk, _) in &extra {
                n.admit_validator(crate::pqauth::pubkey_id(pk), 20_000, 0).expect("an equal bond admits");
            }
        }
        let signers = [(pk0, sk0), extra[0].clone(), extra[1].clone()];
        let epoch = a.current_price_epoch();
        let genuine: Vec<crate::price_quote::SignedQuote> = [14_000u128, 15_000, 16_000]
            .iter()
            .enumerate()
            .map(|(i, p)| {
                crate::price_quote::sign_quote(epoch, ASSET, *p, &signers[i].0, &signers[i].1).expect("a bonded key signs")
            })
            .collect();
        for q in &genuine {
            assert!(a.price_quote_ingest(q, &v), "PRECONDITION: A gathers every genuine quote off the lane");
        }
        // Two copied genuine quotes, and a forgery in validator 2's name placed LAST (where it costs most).
        let mut forged = genuine[2].quote.clone();
        forged.price = 15_500;
        forged.sig = vec![0x5Au8; forged.sig.len()];
        let object = [genuine[0].quote.clone(), genuine[1].quote.clone(), forged];

        let at_a = Counting(std::cell::Cell::new(0));
        let ra = a.mark_price_attested(epoch, ASSET, &object, &at_a);
        let at_b = Counting(std::cell::Cell::new(0));
        let rb = b.mark_price_attested(epoch, ASSET, &object, &at_b);
        eprintln!("[db245-work] A (gathered): {ra:?} after {} real verifies; B (empty book): {rb:?} after {}", at_a.0.get(), at_b.0.get());
        assert_eq!(ra, crate::peg::PegOutcome::InsufficientThreshold, "⛔ A must refuse the forged object");
        assert_eq!(rb, crate::peg::PegOutcome::InsufficientThreshold, "⛔ B must refuse the forged object");
        assert_eq!(at_b.0.get(), 3, "CALIBRATION: a node that gathered nothing verifies every quote");
        assert_eq!(
            at_a.0.get(),
            1,
            "⛔ DB-245 BOUNDED WORK: A re-verified quotes it had already verified off the lane — copied genuine \
             quotes make every forged mark cost one verify per quote"
        );
        assert_eq!((a.price_mark_for(ASSET), b.price_mark_for(ASSET)), (None, None), "⛔ a refused object moved a mark");
    }

    /// ⭐⭐⭐ DB-224 — PER CLASS: THE CARRIAGE IS JUDGED EXACTLY AS THE OBJECT IS, AND HOLDS NO PAYLOAD.
    ///
    /// For every note-carrying class whose admission is decided at the blob door without a live proof,
    /// plus the note-free ones: `admissible(carriage) == admissible(full)` at both allowance values, the
    /// carriage is idempotent and is its own carriage, every note became `(cm, blake3(payload))`, and no
    /// ciphertext byte survives. (The proof-verifying classes — AssetMint, AssetSpend, OrderFill — read
    /// `note_cm_of` only and are exercised end to end by their travel pins through the same seam.)
    #[test]
    fn db224_every_carriage_is_judged_as_its_object_and_holds_no_payload() {
        use crate::chain_object::{admissible, carriage_note_refs, carriage_of, is_carriage};
        let lanes = |x: u64| usdm_decider::poseidon2_compress::lanes_of(&[x, x + 1, x + 2, x + 3]);
        let att = vec![MintAttestor { pubkey: vec![1u8; 8], sig: vec![2u8; 8] }];
        let n = |tag: &[u8]| sealed_note(crate::hash::Hash32::hash(tag).as_bytes(), tag);
        let (n1, n3) = (n(b"db224-class-1"), n(b"db224-class-3"));
        // DB-365: a class that binds its credited notes' COMMITMENTS carries notes whose fronts are those commitments.
        let cn = |x: u64, tag: &[u8]| sealed_note(&crate::spend_frontier::leaf_to_cm_bytes(lanes(x)), tag);
        let (pout_change, y_principal, y_change) =
            (cn(61, b"db365-pout-change"), cn(39, b"db365-y-principal"), cn(43, b"db365-y-change"));
        let wm = crate::wrapped_mint_tx::wire(
            &crate::wrapped_mint_tx::WrappedMintHeader {
                asset_id: ASSET,
                deposit_id: [1u8; 32],
                recipient: recipient_of(&[1u8; 32]),
                new_reserve_commit: lanes(1),
                new_minted_commit: lanes(5),
                delta_commit: lanes(9),
            },
            &[3u8; 16],
            &[4u8; 16],
            &att,
            &n1,
            &[],
            &owner_clue(),
        );
        let pin = crate::peg_in_tx::wire(
            &crate::peg_in_tx::PegInHeader {
                deposit_id: [3u8; 32],
                recipient: recipient_of(&[3u8; 32]),
                new_reserve_commit: lanes(11),
                new_minted_commit: lanes(15),
                delta_commit: lanes(19),
                proposal_nonce: [5u8; 32],
            },
            &[6u8; 16],
            &[7u8; 16],
            &[],
            &att,
            &n1,
            &[],
            &owner_clue(),
        );
        let pout_hdr = crate::peg_out_tx::PegOutHeader {
            usdm_nullifier: [8u8; 32],
            new_reserve_commit: lanes(21),
            new_minted_commit: lanes(25),
            proposal_nonce: [9u8; 32],
            leaf_commit: lanes(29),
            // DB-273 §19.3 L2: the change's owner digest, signed in the v4 statement.
            change_owner: crate::peg_out_tx::change_owner_of(&owner_clue()),
            // DB-365: the change note's commitment, signed in the v5 statement.
            change_cm: crate::spend_frontier::leaf_to_cm_bytes(lanes(61)),
        };
        let pout = crate::peg_out_tx::wire(&pout_hdr, &[10u8; 16], &[11u8; 32], &att, &pout_change, &[], &owner_clue(), &crate::peg_out_tx::ticket_parts_for_test());
        // No change note: no clue, and a zero change owner (the one encoding `decode` admits).
        let pout_no_change_hdr = crate::peg_out_tx::PegOutHeader { change_owner: [0u8; 32], ..pout_hdr };
        let pout_no_change =
            crate::peg_out_tx::wire(&pout_no_change_hdr, &[10u8; 16], &[11u8; 32], &att, &[], &[], &[], &crate::peg_out_tx::ticket_parts_for_test());
        // DB-237: the stake object (stake / claim / unstake) carries TWO notes — the principal and the second output.
        let yc =crate::stake_tx::wire(&crate::stake_tx::StakeDecoded {
            h: crate::stake_tx::StakeHeader {
                nullifier: [12u8; 32],
                e_now: 5,
                rate_bps: 500,
                out0_cm: lanes(39),
                out1_cm: lanes(43),
                leaf_commit: lanes(47),
                reward_commit: lanes(31),
                new_paid_commit: lanes(35),
            },
            stake_carrier: vec![13u8; 16],
            supply_carrier: vec![14u8; 16],
            membership_carrier: vec![15u8; 16],
            membership_tip: vec![16u8; 16],
            out0: y_principal.clone(),
            out1: y_change.clone(),
            // DB-273 §19.3 L2: one owner clue per credited note.
            owner_clues: vec![owner_clue(), owner_clue()],
            sealed: Vec::new(),
        });
        let bc = credit_for(&n3).wire();
        let wr = crate::wrapped_asset_tx::wire(
            &crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
                epoch_id: 1,
                asset_id: ASSET,
                prev_ratio_bps: 0,
                ratio_bps: 15_000,
            },
            &att,
        );
        let cases: Vec<(&str, Vec<u8>, Vec<Vec<u8>>)> = vec![
            ("WrappedMint", wm, vec![n1.clone()]),
            ("PegIn", pin, vec![n1.clone()]),
            ("PegOut", pout, vec![pout_change.clone()]),
            ("PegOut without change", pout_no_change, vec![]),
            ("YieldClaim", yc, vec![y_principal.clone(), y_change.clone()]),
            ("BridgeCredit", bc, vec![n3.clone()]),
            ("WrappedAssetRegister", wr, vec![]),
        ];
        for (name, full, notes) in cases {
            let carriage = carriage_of(&full).unwrap_or_else(|| panic!("⛔ {name}: no carriage form"));
            assert!(is_carriage(&carriage), "⛔ {name}: the carriage is not its own carriage");
            assert_eq!(carriage_of(&carriage), Some(carriage.clone()), "⛔ {name}: the carriage is not idempotent");
            assert_eq!(
                is_carriage(&full),
                notes.is_empty(),
                "⛔ {name}: a full object that carries a payload must NOT pass as a carriage"
            );
            for allowance in [0, crate::params::TESTNET_OPEN_MINT_ALLOWANCE] {
                for attested in [false, true] {
                    assert_eq!(
                        admissible(&carriage, 10, allowance, attested),
                        admissible(&full, 10, allowance, attested),
                        "⛔⛔⛔ {name}: the carriage is judged differently from its object \
                         (allowance {allowance}, attested {attested})"
                    );
                }
            }
            let want: Vec<([u8; 32], [u8; 32])> = notes
                .iter()
                .map(|p| {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&p[..32]);
                    (cm, *crate::hash::Hash32::hash(p).as_bytes())
                })
                .collect();
            assert_eq!(carriage_note_refs(&carriage), Some(want.clone()), "⛔ {name}: wrong references");
            assert_eq!(carriage_note_refs(&full), Some(want), "⛔ {name}: full and carriage name different notes");
            for p in &notes {
                assert!(contains(&full, &p[32..96]), "CALIBRATION ({name}): the full object holds the ciphertext");
                assert!(!contains(&carriage, &p[32..96]), "⛔⛔⛔ {name}: a ciphertext byte survived into the carriage");
            }
        }
        // A note that is neither a payload nor a reference cannot be carried.
        let mut odd = credit_for(&n1);
        odd.note = vec![7u8; 100];
        assert_eq!(carriage_of(&odd.wire()), None, "⛔ a 100-byte 'note' was given a carriage form");
        // ⛔ A carriage is not a transaction: the pool door refuses one.
        let mut tx = credit_for(&n1).as_pq_tx(0);
        tx.blob = carriage_of(&tx.blob).expect("carriable");
        tx.output_notes = crate::chain_object::note_ref(&n1).expect("a reference");
        assert!(
            !crate::chain_object::wrapper_binds_object(&tx),
            "⛔⛔⛔ a CARRIAGE passed the pool door — a re-published carriage would be mined with \
             reference-width output_notes"
        );
    }

    // ── DB-246 — THE ABSENCE DOOR JUDGES A STALE CARRIER EXACTLY (docs/DB-246-ABSENCE-DOOR-RECENT-ANCHOR.md) ──

    /// A wallet-shaped absence carrier: fold the span `n` SERVES (its `/get_nf_fold_inputs` page, from its
    /// certified base), finalize, and carry the span's tips. This is exactly what `nf_carrier` does, off the same
    /// node functions the route calls.
    fn db246_wallet_carrier(n: &Node, nfs: &[[u8; 32]]) -> crate::nf_sparse::NfAbsenceWitness {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, NfAbsenceBatchCarrier};
        let (base, _) = n.nf_fold_base();
        let limbs = nfs.iter().map(nf_to_limbs).collect();
        let mut c = NfAbsenceBatchCarrier::new(limbs, base);
        for (_, pre, tags) in n.nf_fold_inputs_page(0, 16_384) {
            assert!(c.step(&tags, pre), "PRECONDITION: no input is in any served block");
        }
        let (proof, acc, tip_prev, tip_bp, tip_td) = c.finalize().expect("the carrier finalizes");
        assert_eq!(acc, n.nf_unspent_acc(), "PRECONDITION: the carrier stands on the serving node's live tip");
        crate::nf_sparse::NfAbsenceWitness {
            proof,
            tip_prev,
            tip_bp,
            tip_td,
            base_acc: base,
            tips: n.nf_fold_span_tips().into_iter().map(|id| id.0).collect(),
        }
    }

    /// A spend of `nfs` carrying the absence carrier `w` beside the per-tag copaths a real spend carries, built by the
    /// node it is handed to (`Node::spend_lane_evidence`, what every publish door calls).
    /// RE-MEASURED 2026-11-10: these pins carried the absence carrier ALONE, and since 9387f06d (2026-11-06) a spend with
    /// no copath is judged by the node's own set and an absence carrier on that path is refused outright (nothing reads
    /// it there, so its bytes would be free to change) — every `PRECONDITION: a fresh carrier is admitted` read RED from
    /// that day. The carrier's tip rule (DB-246) is still what admits or refuses a spend that DOES carry its copaths,
    /// which is the spend a wallet sends; that is the path measured here.
    fn db246_spend(n: &Node, nfs: &[[u8; 32]], w: &crate::nf_sparse::NfAbsenceWitness) -> crate::mempool::PqTx {
        crate::mempool::PqTx {
            clock_ms: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            id: crate::hash::Hash32::hash(&[nfs.concat(), b"db246".to_vec()].concat()),
            blob: Vec::new(),
            weight: 1,
            nullifiers: nfs.iter().map(|n| crate::hash::Hash32(*n)).collect(),
            pow_stamp: 0,
            output_notes: Vec::new(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: n.spend_lane_evidence(nfs).0,
            nullifier_absence: vec![w.clone()],
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        }
    }

    fn db246_produce(n: &mut Node, ts: u64, tag: &str) -> crate::block::Block {
        n.produce(
            ts,
            crate::hash::Hash32::hash(format!("db246-fr-{tag}").as_bytes()),
            crate::hash::Hash32::hash(format!("db246-mc-{tag}").as_bytes()),
        )
        .expect("the node produces")
    }

    /// ⭐⭐⭐ DB-246 pin 1 — A CARRIER A FEW BLOCKS STALE IS ADMITTED BY THE NODE THAT SERVED IT.
    ///
    /// MEASURED before DB-246: every real send was refused, 3 of 3, taking 3.8–68.7 s. The door admitted only
    /// `claimed_tip == live`, and A_tip moves every block. CONTROL: the same witness without its tips, which is
    /// what a pre-DB-246 wallet sends, is still refused, so the admission is the tips' doing.
    #[test]
    fn db246_a_carrier_a_few_blocks_stale_is_admitted_by_the_node_that_served_it() {
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        for i in 0..3u64 {
            db246_produce(&mut a, 5_000 + i * 3_000, &format!("p1-{i}"));
        }
        let nf = *crate::hash::Hash32::hash(b"db246-pin1-unspent-note").as_bytes();
        let w = db246_wallet_carrier(&a, &[nf]);
        assert!(!w.tips.is_empty(), "PRECONDITION: the span has tips");
        assert!(a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &w)), "PRECONDITION: a fresh carrier is admitted");
        for i in 3..5u64 {
            db246_produce(&mut a, 5_000 + i * 3_000, &format!("p1-{i}"));
        }
        let mut bare = w.clone();
        bare.tips.clear();
        assert!(
            !a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &bare)),
            "CONTROL: with no tips, a carrier two blocks stale is refused exactly as before DB-246"
        );
        assert!(
            a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &w)),
            "⛔⛔⛔ DB-246: an honest carrier two blocks short of the live tip was REFUSED — every real send \
             dies on this"
        );
    }

    /// ⭐⭐⭐ DB-246 pin 2 — …AND BY A SECOND NODE THAT NEVER HELD THE STATE THE CARRIER CLAIMS.
    ///
    /// Two siblings a2 and c2 are built on a1. B folds a1, a2 and serves its span; the carrier's claimed A_tip is
    /// the sum over {a1, a2}. D accepts a1, then c2, then a2, then produces d3: D never held the set {a1, a2}
    /// alone, so no ring of A_tip VALUES could admit this carrier on D. The tips coordinate (`{a2}`) does:
    /// D's gap is {c2, d3} by block id.
    #[test]
    fn db246_a_stale_carrier_is_admitted_by_a_second_node_that_never_held_its_claimed_state() {
        let (mut v, _pk, _sk) = parties(4);
        let mut d = v.pop().expect("four parties");
        let mut c = v.pop().expect("four parties");
        let mut b = v.pop().expect("four parties");
        let mut a = v.pop().expect("four parties");
        let a1 = db246_produce(&mut a, 5_000, "p2-a1");
        for n in [&mut b, &mut c, &mut d] {
            assert!(
                matches!(n.ingest_block(a1.clone(), 6_000), crate::relay::RelayOutcome::Added(_)),
                "PRECONDITION: a1 lands everywhere"
            );
        }
        let a2 = db246_produce(&mut a, 8_000, "p2-a2");
        let c2 = db246_produce(&mut c, 8_100, "p2-c2");
        assert_eq!(a2.header.parents, c2.header.parents, "PRECONDITION: a2 and c2 are siblings");
        assert!(matches!(b.ingest_block(a2.clone(), 9_000), crate::relay::RelayOutcome::Added(_)));
        let nf = *crate::hash::Hash32::hash(b"db246-pin2-unspent-note").as_bytes();
        let w = db246_wallet_carrier(&b, &[nf]);
        assert_eq!(w.tips, vec![a2.id().0], "PRECONDITION: B's span {{a1, a2}} closes over the tip a2");
        assert!(matches!(d.ingest_block(c2.clone(), 9_100), crate::relay::RelayOutcome::Added(_)));
        assert!(matches!(d.ingest_block(a2.clone(), 9_200), crate::relay::RelayOutcome::Added(_)));
        let d3 = db246_produce(&mut d, 11_000, "p2-d3");
        assert_eq!(d3.header.parents.len(), 2, "PRECONDITION: d3 merges both siblings");
        assert_ne!(
            d.nf_unspent_acc(),
            b.nf_unspent_acc(),
            "PRECONDITION: D stands on a different set than the carrier's"
        );
        let mut bare = w.clone();
        bare.tips.clear();
        assert!(
            !d.tx_nullifiers_absent_by_fold(&db246_spend(&d, &[nf], &bare)),
            "CONTROL: without the tips coordinate D cannot relate the carrier's sum to its own"
        );
        assert!(
            d.tx_nullifiers_absent_by_fold(&db246_spend(&d, &[nf], &w)),
            "⛔⛔⛔ DB-246: a node that accepted the same blocks in another order REFUSED the honest carrier — \
             admission would depend on which node a spend reaches"
        );
    }

    /// ⛔ DB-246 pin 3 — A TAG THAT SETTLED AFTER THE CARRIER IS REFUSED.
    ///
    /// The carrier is honest about its own span. The input then settles in a later block, inside the gap. Today
    /// DB-217's positive-Unspent check refuses it first. The gap sweep refuses the same case when the carrier
    /// becomes the authority. Either way, it must never be admitted.
    #[test]
    fn db246_a_tag_settled_after_the_carrier_is_refused() {
        let (mut v, _pk, _sk) = parties(2);
        let mut b = v.pop().expect("two parties");
        let mut a = v.pop().expect("two parties");
        let b1 = db246_produce(&mut a, 5_000, "p3-1");
        assert!(matches!(b.ingest_block(b1.clone(), 6_000), crate::relay::RelayOutcome::Added(_)));
        let b2 = db246_produce(&mut a, 8_000, "p3-2");
        // A tag the LATER block settles — B does not hold that block yet, so B's carrier over {b1} is honest.
        let settled = b2.nullifier_proof.padded_tags[0];
        assert!(
            !b1.nullifier_proof.padded_tags.contains(&settled),
            "PRECONDITION: the tag is not in the carrier's span"
        );
        let w = db246_wallet_carrier(&b, &[settled]);
        assert!(matches!(b.ingest_block(b2, 9_000), crate::relay::RelayOutcome::Added(_)));
        assert!(
            !b.tx_nullifiers_absent_by_fold(&db246_spend(&b, &[settled], &w)),
            "⛔⛔⛔ DB-246: a tag that settled AFTER the carrier (inside its gap) was ADMITTED — a double spend"
        );
    }

    /// ⛔ DB-246 pin 4 — A TIP THE NODE DOES NOT HOLD IS REFUSED.
    #[test]
    fn db246_a_tip_the_node_does_not_hold_is_refused() {
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        db246_produce(&mut a, 5_000, "p4-0");
        let nf = *crate::hash::Hash32::hash(b"db246-pin4-unspent-note").as_bytes();
        let mut w = db246_wallet_carrier(&a, &[nf]);
        db246_produce(&mut a, 8_000, "p4-1");
        let honest = w.clone();
        assert!(a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &honest)), "CALIBRATION: the honest tips admit");
        w.tips = vec![*crate::hash::Hash32::hash(b"db246-a-block-nobody-mined").as_bytes()];
        assert!(
            !a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &w)),
            "⛔ DB-246: a carrier naming a tip this node does not hold was admitted"
        );
    }

    /// ⛔ DB-246 pin 5 — A CARRIER OLDER THAN THE RING IS REFUSED: its gap is not all in the ring, so the
    /// accounting cannot close.
    #[test]
    fn db246_a_carrier_older_than_the_ring_is_refused() {
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        db246_produce(&mut a, 5_000, "p5-0");
        let nf = *crate::hash::Hash32::hash(b"db246-pin5-unspent-note").as_bytes();
        let w = db246_wallet_carrier(&a, &[nf]);
        for i in 1..=(crate::nf_sparse::NF_RECENT_BLOCKS as u64 + 2) {
            db246_produce(&mut a, 5_000 + i * 3_000, &format!("p5-{i}"));
        }
        assert!(
            !a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &w)),
            "⛔ DB-246: a carrier whose gap is longer than the ring was admitted — its accounting cannot close"
        );
    }

    /// ⭐⭐ DB-252 — THE INCREMENTAL FOLD PAGE: a page above a blue-score cursor carries exactly the span blocks
    /// scored above it. A carrier built from a full page plus such a page (skipping ids it already holds, as the
    /// follower does) stands on the live A_tip exactly as one built from a single full page.
    ///
    /// Both cursors a follower can hold are exercised:
    ///   * its exact caught-up score: the page carries only the new blocks;
    ///   * a LOWER quantum boundary: the page repeats entries the carrier already holds, and they are skipped by id.
    #[test]
    fn db252_a_page_above_a_cursor_carries_exactly_the_blocks_scored_above_it_and_folds_to_the_live_tip() {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, NfAbsenceBatchCarrier};
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        for i in 0..3u64 {
            db246_produce(&mut a, 5_000 + i * 3_000, &format!("q1-{i}"));
        }
        let nf = *crate::hash::Hash32::hash(b"db252-pin-unspent-note").as_bytes();
        let (base, _) = a.nf_fold_base();
        let mut carrier = NfAbsenceBatchCarrier::new(vec![nf_to_limbs(&nf)], base);
        let mut held: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (id, pre, tags) in a.nf_fold_inputs_page(0, 16_384) {
            assert!(carrier.step(&tags, pre));
            held.insert(id.0);
        }
        let caught_up_score = a.selected_tip_blue_score().expect("the chain has a tip");
        let new: Vec<[u8; 32]> = (3..5u64)
            .map(|i| db246_produce(&mut a, 5_000 + i * 3_000, &format!("q1-{i}")).id().0)
            .collect();
        let exact = a.nf_fold_inputs_above(caught_up_score).expect("a cursor inside the span is served");
        let exact_ids: Vec<[u8; 32]> = exact.iter().map(|(id, _, _)| id.0).collect();
        assert_eq!(exact_ids, new, "⛔ DB-252: the page above the caught-up score must carry exactly the new blocks");
        // A LOWER boundary: entries between it and the caught-up score come again and are skipped by id.
        let lower = a.nf_fold_inputs_above(caught_up_score.saturating_sub(2)).expect("still inside the span");
        assert!(lower.len() > exact.len(), "PRECONDITION: the lower cursor repeats entries the carrier already holds");
        for (id, pre, tags) in lower {
            if held.insert(id.0) {
                assert!(carrier.step(&tags, pre));
            }
        }
        let (_, acc, _, _, _) = carrier.finalize().expect("finalizes");
        assert_eq!(acc, a.nf_unspent_acc(), "⛔ DB-252: a full page + an incremental page must reach the live A_tip");
    }

    /// ⛔ DB-252 — A CALLER MISSING AN ENTRY AT OR UNDER ITS CURSOR CANNOT STAND ON THE LIVE TIP.
    ///
    /// The page does not repeat that entry, so the caller's sum stays short of `a_tip` and it must ask for the full
    /// span. The incremental page can make a follower slower, never wrong.
    #[test]
    fn db252_a_caller_that_missed_a_block_under_its_cursor_cannot_stand_on_the_live_tip() {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, NfAbsenceBatchCarrier};
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        for i in 0..3u64 {
            db246_produce(&mut a, 5_000 + i * 3_000, &format!("q2-{i}"));
        }
        let nf = *crate::hash::Hash32::hash(b"db252-pin-short").as_bytes();
        let (base, _) = a.nf_fold_base();
        let mut short = NfAbsenceBatchCarrier::new(vec![nf_to_limbs(&nf)], base);
        let page = a.nf_fold_inputs_page(0, 16_384);
        // The caller took the served page minus its last entry...
        for (_, pre, tags) in &page[..page.len() - 1] {
            assert!(short.step(tags, *pre));
        }
        // ...then a page above the CURRENT score, which does not repeat the entry it missed.
        let score = a.selected_tip_blue_score().expect("a tip");
        db246_produce(&mut a, 20_000, "q2-next");
        for (_, pre, tags) in a.nf_fold_inputs_above(score).expect("served") {
            assert!(short.step(&tags, pre));
        }
        let (_, acc, _, _, _) = short.finalize().expect("finalizes");
        assert_ne!(
            acc,
            a.nf_unspent_acc(),
            "⛔ DB-252: a caller missing an entry under its cursor must NOT stand on the live A_tip — it re-asks the full span"
        );
    }

    /// ⛔ DB-246 pin 6 — A LYING TIP SET IS REFUSED: a set that closes over MORE than the carrier folded (an
    /// extra later block), or LESS (a parent instead of the tip), fails the exact accounting.
    #[test]
    fn db246_a_lying_tip_set_is_refused() {
        let (mut v, _pk, _sk) = parties(1);
        let mut a = v.pop().expect("one party");
        let b1 = db246_produce(&mut a, 5_000, "p6-1");
        db246_produce(&mut a, 8_000, "p6-2");
        let nf = *crate::hash::Hash32::hash(b"db246-pin6-unspent-note").as_bytes();
        let honest = db246_wallet_carrier(&a, &[nf]);
        let b3 = db246_produce(&mut a, 11_000, "p6-3");
        db246_produce(&mut a, 14_000, "p6-4");
        assert!(a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &honest)), "CALIBRATION: the honest tips admit");
        let mut too_far = honest.clone();
        too_far.tips = vec![b3.id().0];
        assert!(
            !a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &too_far)),
            "⛔ DB-246: tips closing over a block the carrier never folded were admitted"
        );
        let mut too_short = honest.clone();
        too_short.tips = vec![b1.id().0];
        assert!(
            !a.tx_nullifiers_absent_by_fold(&db246_spend(&a, &[nf], &too_short)),
            "⛔ DB-246: tips closing over less than the carrier folded were admitted"
        );
    }

    /// ⛔⛔⛔ DB-257 pin 1 — A BLOCK THAT RETURNS A STILL-BONDED NOTE WITHOUT ITS UNBOND IS REFUSED BY THE PEER.
    ///
    /// A validator's collateral note is LOCKED at bond time (`bond_locked`, never a spendable leaf), so its value
    /// backs the weight. The graft door used to justify a carried note by `bonded_cms`: ANY commitment the peer
    /// holds as bonded. It never asked whether the block releases that bond. `bond_locked` is chain-derived, so
    /// every producer knows every locked note's exact bytes. One block carrying V's locked note therefore made
    /// it a spendable leaf on every peer while V kept its full weight. The collateral leaves and the weight
    /// stays: slashing burns a note that is already spent, and the bond-weighted tally counts weight with
    /// nothing behind it.
    /// CALIBRATION: an honest credit in the SAME block (a bridge credit with its justifier) IS recorded by the
    /// peer, so the refusal is not a door that refuses everything.
    #[test]
    fn db257_a_block_that_returns_a_still_bonded_note_without_its_unbond_is_refused_by_the_peer() {
        let mut a = testnet_node();
        let mut b = testnet_node();
        let vid = [0x57u8; 32];
        let locked = sealed_note(crate::hash::Hash32::hash(b"db257-locked-cm").as_bytes(), b"db257-locked-ct");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        }
        assert_eq!(b.validators().bond_of(&vid), 50_000, "PRECONDITION: the peer holds V's weight");
        assert!(!b.holds_record_with_cm(&cm), "PRECONDITION: the locked note is no leaf on the peer");
        // The attack: the producer carries V's locked note, and no unbond rides with it.
        a.stage_credit_note(locked.clone());
        // The calibration: an honest credit rides the same block beside its justifier.
        let honest = sealed_note(crate::hash::Hash32::hash(b"db257-honest-cm").as_bytes(), b"db257-honest-ct");
        let mut hcm = [0u8; 32];
        hcm.copy_from_slice(&honest[..32]);
        a.stage_credit_note(honest.clone());
        a.stage_credit_justifier(credit_for(&honest).wire());
        let blk = a
            .produce(4_500, crate::hash::Hash32::hash(b"db257-fr"), crate::hash::Hash32::hash(b"db257-mc"))
            .expect("A produces");
        assert!(contains(&blk.output_notes, &locked), "PRECONDITION: the block carries V's locked note");
        // THE PEER HOLDS THE PAYLOAD. Under DB-224 no note payload rides the wire; a peer gets it from the DA
        // record path or its own pool, and the §BA door decides what it RECORDS. That record is what its
        // membership root folds and what the certified accumulator is built from. So the full block is handed
        // over, exactly as `bridge_credit_tx`'s peer pins do. `over_the_wire` would hand B no payload at all,
        // and "B did not record it" would then be true of every note and prove nothing about the door.
        let outcome = b.ingest_block(blk.clone(), 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "the block grafts: {outcome:?}");
        assert!(b.holds_record_with_cm(&hcm), "CALIBRATION: the peer records the honest credit from the same block");
        assert_eq!(b.validators().bond_of(&vid), 50_000, "no unbond rode: V keeps its weight on the peer");
        assert!(
            !b.holds_record_with_cm(&cm),
            "⛔⛔⛔ DB-257: the peer RECORDED V's locked collateral note as a spendable leaf while V keeps its full \
             weight, and no unbond rode this block. The collateral can be spent and the weight kept."
        );
    }

    /// ⛔⛔⛔ DB-274 P2 (§8.12 R / §8.13, lane-review's pin) — A RESTART MUST NOT DROP A SIDE BLOCK'S BOND STEP.
    ///
    /// A restart carries every unfolded SIDE block as a bodiless header shell (`unfolded_carry`, DB-117b), and
    /// `bond_step_at_fold` applies a block's `bond_set` only from a body. Here node B builds side block S carrying V's
    /// unbond, restarts before S folds, and folds S after node A merges it; A never restarts. A applies the unbond at S's
    /// fold; the restarted B's shell carries no `bond_set`, so B keeps V's weight: two validator sets on one chain.
    /// EXPECTED RED today (latent only because bonds are paused); GREEN once the shell carries its fold inputs (§8.13).
    /// Two parties; each asserts it FOLDED S before its validator set is read, and the verdict is what each PEER holds.
    #[test]
    fn db274_p2_a_restart_with_an_unfolded_side_block_folds_its_bond_step_like_the_peer() {
        fn next_ts(n: &Node) -> u64 {
            n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
        }
        fn shape(n: &mut Node) {
            let mut gp = n.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            gp.record_fold_depth = 4;
            n.set_params(gp);
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        shape(&mut node_a);
        shape(&mut node_b);
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let locked = sealed_note(crate::hash::Hash32::hash(b"p2-restart-locked").as_bytes(), b"p2-restart-ct");
        node_a.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        node_b.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        // 1. B carries V's unbond in side block S, and withholds S.
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"p2-restart-owner");
        let (sig, nonce) = node_b.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            node_b.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: V's authenticated unbond enters B's pool"
        );
        let s = node_b
            .produce(next_ts(&node_b), crate::hash::Hash32::hash(b"p2-s"), crate::hash::Hash32::hash(b"p2-ms"))
            .expect("B produces S");
        let s_id = s.id();
        assert!(!s.bond_set.is_empty(), "PRECONDITION: S carries the unbond in its bond set");
        // 2. A builds the chain X -> X2 without S; B receives both, so S is a SIDE tip on B.
        let ts_x = next_ts(&node_a);
        let x = node_a.produce(ts_x, crate::hash::Hash32::hash(b"p2-x"), crate::hash::Hash32::hash(b"p2-mx")).expect("X");
        let ts_x2 = next_ts(&node_a);
        let x2 = node_a.produce(ts_x2, crate::hash::Hash32::hash(b"p2-x2"), crate::hash::Hash32::hash(b"p2-mx2")).expect("X2");
        let _ = node_b.ingest_block(x, ts_x2 + 300);
        let _ = node_b.ingest_block(x2, ts_x2 + 400);
        assert_ne!(node_b.selected_tip(), Some(s_id), "PRECONDITION: S is a SIDE block on B");
        assert!(!node_b.block_record_folded_for_test(&s_id), "PRECONDITION: S has not folded on B before the restart");
        // 3. B restarts from its checkpoint — the snapshot AND its fold record, through the ONE resume a boot runs (since
        // DB-353 landing 2 the band rides the fold record; a snapshot-only restore is a path no node takes).
        let (snap, fold) = node_b.checkpoint_for_test().expect("B exports its checkpoint");
        let mut node_b = testnet_node();
        shape(&mut node_b);
        assert!(node_b.resume_from_checkpoint_for_test(snap, fold), "PRECONDITION: B resumes from its checkpoint");
        // A restarted node holds no nullifier view; its runtime warms one from a peer before its fold can decide a
        // respend (DB-353 §13.6). The same door, in process.
        if let Err(why) = node_b.warm_view_from_for_test(&node_a) {
            panic!("PRECONDITION: the restarted B warms its view from A — {why}");
        }
        // 4. A receives S and merges it; B receives the merge; both fold past it.
        let ts_s = next_ts(&node_a);
        let _ = node_a.ingest_block(s, ts_s);
        let ts_m = next_ts(&node_a);
        let m = node_a.produce(ts_m, crate::hash::Hash32::hash(b"p2-m"), crate::hash::Hash32::hash(b"p2-mm")).expect("M");
        assert!(m.header.parents.contains(&s_id), "PRECONDITION: A's next block merges S");
        let _ = node_b.ingest_block(m, ts_m + 400);
        let _ = node_a.fold_past_for_test(&mut [&mut node_b], ts_m + 400, b"p2-restart-fold");
        assert!(node_a.block_record_folded_for_test(&s_id), "PRECONDITION: S FOLDED on A");
        assert!(node_b.block_record_folded_for_test(&s_id), "PRECONDITION: S FOLDED on the restarted B");
        let (on_a, on_b) = (node_a.validators().bond_of(&vid), node_b.validators().bond_of(&vid));
        eprintln!("[db274-p2-restart] V's weight after S's unbond folded: A={on_a} B={on_b}");
        assert_eq!(
            on_a, on_b,
            "⛔⛔⛔ DB-274 P2 (§8.12 R): the node that RESTARTED holds a different validator set than the node that did \
             not — its checkpoint carried S as a bodiless shell, so its fold could not apply S's bond step"
        );
        assert_eq!(on_a, 0, "⛔ S's unbond folded: V holds no weight on either node");
    }

    /// ⛔⛔⛔ DB-257 pin 2 — AN HONEST UNBOND RETURNS ITS BONDED NOTE ON EVERY NODE, AND THE PAIR STILL AGREES.
    ///
    /// The release staged the returned note into the NEXT block each node produces. Every peer grafts the unbond
    /// block BEFORE any later block (a block's parents come first), and the release has already removed the bond
    /// from `bond_locked`. So the returned note arrives at a door that no longer justifies it. The producer
    /// records its own block without the door. The owner's collateral then exists on the producer only, and the
    /// two honest nodes hold different records for one block.
    /// CONTROL: the unbond itself travelled; the weight left BOTH nodes.
    #[test]
    fn db257_an_honest_unbond_returns_its_bonded_note_on_every_node_and_the_pair_agrees() {
        let mut a = testnet_node();
        let mut b = testnet_node();
        for n in [&mut a, &mut b] {
            let mut gp = n.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            // DB-274 P2 (§8.7): a short unbonding window (merge depth + fold depth); its length is not the subject.
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            n.set_params(gp);
        }
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let locked = sealed_note(crate::hash::Hash32::hash(b"db257-return-cm").as_bytes(), b"db257-return-ct");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        }
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db257-owner");
        let (sig, sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the authenticated unbond is admitted to A's pool"
        );
        // The unbond's block and the two after it. The returned note rides whichever of them the producer
        // carries it in. B is handed each FULL block: the peer holds the payload (DA path or pool), and its §BA
        // door decides what it records (see pin 1 for why the wire codec would make this vacuous).
        let mut ts = 4_500u64;
        for tag in [b"db257-u".as_slice(), b"db257-p".as_slice(), b"db257-q".as_slice()] {
            ts += 1_000;
            let blk = a
                .produce(ts, crate::hash::Hash32::hash(tag), crate::hash::Hash32::hash(b"db257-mc"))
                .expect("A produces");
            let got = b.ingest_block(blk.clone(), ts + 400);
            assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts A's block: {got:?}");
        }
        // DB-274 P2 (§8.7): the unbond applies at its block's FOLD; the note returns when its window closes.
        let ts = a.fold_past_for_test(&mut [&mut b], ts + 400, b"db257-fold");
        assert_eq!(a.validators().bond_of(&vid), 0, "CONTROL: the unbond released V's weight on A");
        assert_eq!(b.validators().bond_of(&vid), 0, "CONTROL: the unbond travelled, and the weight left B too");
        let _ = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"db257-window");
        // Both sides are read before either is asserted, so the failure names exactly where the note went: the
        // producer's own graft runs the same door (`graft_admitted_notes` on its mined block), so a staged return
        // can be refused on the producer as well as on the peer.
        let (on_a, on_b) = (a.holds_record_with_cm(&cm), b.holds_record_with_cm(&cm));
        eprintln!("[db257] after the unbond's window closed and folded, the returned note is recorded on A={on_a} B={on_b}");
        assert!(
            on_a && on_b,
            "⛔⛔⛔ DB-257: the unbond released V's weight on both nodes, but the returned collateral note is recorded \
             on A={on_a} B={on_b} after its unbonding window closed. The owner's bond is not returned where it should be."
        );
        assert_eq!(
            (a.records_containing_cm(&cm).len(), b.records_containing_cm(&cm).len()),
            (1, 1),
            "⛔⛔⛔ DB-274 P2: the collateral must return EXACTLY once on each node"
        );
        assert_eq!(
            a.membership_acc(),
            b.membership_acc(),
            "⛔⛔⛔ DB-257: two honest nodes that grafted the same blocks hold DIFFERENT note-membership \
             accumulators after an honest unbond"
        );
    }

    /// A pair of testnet nodes that both hold validator V's bond, locked behind `locked`, with a zero lock delay.
    /// DB-274 P2 (§8.7): and a short merge depth, so the unbonding window (merge depth + the production fold depth) is
    /// short enough to cross in a pin; the window's LENGTH is not these pins' subject, its release and burn are.
    pub(crate) fn db257_bonded_pair(tag: &[u8]) -> (Node, Node, Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>) {
        let mut a = testnet_node();
        let mut b = testnet_node();
        for n in [&mut a, &mut b] {
            let mut gp = n.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            n.set_params(gp);
        }
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let mut front = tag.to_vec();
        front.extend_from_slice(b"-cm");
        let locked = sealed_note(crate::hash::Hash32::hash(&front).as_bytes(), tag);
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        }
        (a, b, pk, sk, vid, locked)
    }

    /// ⛔⛔⛔ DB-272 — AN UNBOND FOR AN IDENTITY THAT HOLDS NO BOND IS REFUSED AT THE DOOR, NOT PUBLISHED.
    ///
    /// The wallet bonds onto its NODE's vote identity and unbonded with its OWN spend key: the object names an id that
    /// holds nothing, the door admitted it, the answer said PUBLISHED, and every node refused it at graft — the user's
    /// bonded note stayed locked with no error anywhere. The door must say so.
    /// CALIBRATION: V's own unbond, signed by V's key, is published.
    #[test]
    fn db272_an_unbond_for_an_identity_that_holds_no_bond_is_refused_at_the_door() {
        let (mut a, _b, pk, sk, vid, _locked) = db257_bonded_pair(b"db272-door");
        let (wallet_pk, wallet_sk) = crate::pqauth::ml_dsa_keypair();
        let wallet_id = crate::pqauth::pubkey_id(&wallet_pk);
        assert_ne!(wallet_id, vid, "PRECONDITION: the wallet's key is not the node's vote key");
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db272-wallet");
        // The wallet's id holds no bonding, so it has no instance: the zero instance stands in, and the door refuses on
        // the missing bond before any instance is read.
        let wallet_sig_nonce = crate::unbond_tx::fresh_unbond_nonce();
        let wallet_sig = crate::pqauth::ml_dsa_sign(
            &crate::pqauth::validator_unbond_msg(
                &wallet_id,
                &[0u8; 32],
                &crate::oli::owner_clue_digest(&crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek)),
                &wallet_sig_nonce,
            ),
            &wallet_sk,
        )
        .expect("the wallet signs");
        let got = a.publish_unbond(&wallet_pk, &wallet_sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),wallet_sig_nonce);
        assert!(
            !matches!(got, crate::node::AssetSpendOutcome::Published),
            "⛔⛔⛔ DB-272: an unbond for an identity that holds NO bond was PUBLISHED — it will release nothing on any \\
             node, and the caller was told it succeeded"
        );
        let (own_sig, own_sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &own_sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),own_sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "CALIBRATION: V's own unbond is published"
        );
    }

    /// ⭐⭐⭐ DB-272 — THE NODE'S OWN UNBOND RELEASES THE BOND A WALLET MADE ONTO ITS VOTE IDENTITY, ON EVERY NODE.
    ///
    /// The wallet's unbond now asks its own node to sign with the vote key (`publish_own_unbond`, the loopback
    /// `/unbond_validator {"own":true}`). The block that carries it releases V on the PEER too, and the returned note
    /// rides that same block (DB-257).
    #[test]
    fn db272_the_nodes_own_unbond_releases_the_bond_made_onto_its_vote_identity_on_every_node() {
        let (mut a, mut b, pk, sk, vid, locked) = db257_bonded_pair(b"db272-own");
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db272-own-wallet");
        assert_eq!(
            a.publish_own_unbond(&pk, &sk, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek)),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the node's own unbond is admitted"
        );
        let u = a
            .produce(5_500, crate::hash::Hash32::hash(b"db272-u"), crate::hash::Hash32::hash(b"db272-mc"))
            .expect("A produces the unbond's block");
        assert!(!contains(&u.output_notes, &locked), "DB-274 P2: the note no longer rides the unbond's block");
        let got = b.ingest_block(u, 6_000);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts the unbond's block: {got:?}");
        // DB-274 P2 (§8.7): the unbond applies at its block's FOLD, on both nodes alike.
        let ts = a.fold_past_for_test(&mut [&mut b], 6_000, b"db272-fold");
        assert_eq!(a.validators().bond_of(&vid), 0, "the unbond released V on its producer");
        assert_eq!(
            b.validators().bond_of(&vid),
            0,
            "⛔⛔⛔ DB-272: the node's own unbond did not release V's bond on the peer"
        );
        let _ = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"db272-window");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        assert!(
            a.holds_record_with_cm(&cm) && b.holds_record_with_cm(&cm),
            "⛔⛔⛔ DB-272/DB-274 P2: the collateral bonded onto the node's identity did not return on both nodes"
        );
    }

    /// ⛔⛔⛔ DB-257 pin 3, RE-STATED BY DB-274 P2 (§8.7) — THE WEIGHT NEVER LEAVES WITHOUT THE COLLATERAL BEING KEPT.
    ///
    /// DB-257's concern: a producer must not be able to drop the owner's collateral while the validator's weight
    /// leaves. Its rule was "the unbond's block must carry the note". Under P2 the note never rides a block: the
    /// release moves it into `unbonding` from CHAIN STATE, whatever the block carries, and the fold writes it into a
    /// record when the window closes. So the same bond set applied with NO carried notes releases the weight AND keeps
    /// the collateral for its owner; a producer's omission cannot drop it.
    /// CALIBRATION: applied with the note carried, the result is the same (the carriage no longer matters).
    #[test]
    fn db257_an_unbond_whose_block_does_not_carry_its_note_releases_nothing() {
        let (mut a, mut c, pk, sk, vid, locked) = db257_bonded_pair(b"db257-subject");
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db257-subject-owner");
        let (sig, sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the unbond is admitted to A's pool"
        );
        let u = a
            .produce(5_500, crate::hash::Hash32::hash(b"db257-s-u"), crate::hash::Hash32::hash(b"db257-mc"))
            .expect("A produces the unbond's block");
        assert!(
            !contains(&u.output_notes, &locked),
            "DB-274 P2: the producer no longer carries the locked note in the unbond's block"
        );
        c.apply_bond_set(&u.bond_set, 1, &[], &u.nullifier_proof.padded_tags, None);
        assert_eq!(c.validators().bond_of(&vid), 0, "the unbond released the weight with no note carried");
        assert!(
            c.unbonding_due(&vid).is_some(),
            "⛔ DB-257/DB-274 P2: the weight left and the owner's collateral is not held for release — it would be gone \
             with it"
        );
        // CALIBRATION: A (whose fold has not reached U yet, so V is still bonded there) applies the SAME bond set WITH
        // the note carried, and holds the identical release — the carriage no longer decides anything.
        assert_eq!(a.validators().bond_of(&vid), 50_000, "PRECONDITION: U has not folded on A");
        let mut carried = u.output_notes.clone();
        carried.extend_from_slice(&locked);
        a.apply_bond_set(&u.bond_set, 1, &carried, &u.nullifier_proof.padded_tags, None);
        assert_eq!(a.validators().bond_of(&vid), 0, "CALIBRATION: the carried application releases the weight too");
        assert_eq!(
            a.unbonding_due(&vid),
            c.unbonding_due(&vid),
            "CALIBRATION: with or without the note carried, the collateral is held for release at the same score"
        );
    }

    /// ⛔⛔⛔ DB-257 pin 4 — A RETURNED NOTE CARRIED AGAIN BY A LATER BLOCK IS REFUSED BY THE PEER.
    ///
    /// Once the unbond's block has returned the note, the bond map no longer holds it, so no later block can
    /// justify a second copy. The peer holds exactly one record of it.
    /// PRECONDITION: the honest return landed on the peer from the unbond's own block.
    #[test]
    fn db257_a_returned_note_carried_again_by_a_later_block_is_refused_by_the_peer() {
        let (mut a, mut b, pk, sk, vid, locked) = db257_bonded_pair(b"db257-again");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db257-again-owner");
        let (sig, sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the unbond is admitted to A's pool"
        );
        let u = a
            .produce(5_500, crate::hash::Hash32::hash(b"db257-a-u"), crate::hash::Hash32::hash(b"db257-mc"))
            .expect("A produces the unbond's block");
        let got = b.ingest_block(u.clone(), 5_900);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts the unbond's block: {got:?}");
        // DB-274 P2 (§8.7): the unbond applies at its fold and the note returns when its window closes.
        let ts = a.fold_past_for_test(&mut [&mut b], 5_900, b"db257-again-fold");
        let ts = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"db257-again-window");
        assert!(b.holds_record_with_cm(&cm), "PRECONDITION: the honest return landed on B when the window closed");
        assert_eq!(b.validators().bond_of(&vid), 0, "PRECONDITION: and the weight left B");
        // The replay: a producer carries the same returned note again, in a block with no unbond.
        a.stage_credit_note(locked.clone());
        let p = a
            .produce(ts + 600, crate::hash::Hash32::hash(b"db257-a-p"), crate::hash::Hash32::hash(b"db257-mc"))
            .expect("A produces the replaying block");
        assert!(contains(&p.output_notes, &locked), "PRECONDITION: the later block carries the note again");
        let got = b.ingest_block(p.clone(), ts + 1_000);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "the block itself grafts: {got:?}");
        let _ = a.fold_past_for_test(&mut [&mut b], ts + 1_000, b"db257-again-replay");
        assert_eq!(
            b.records_containing_cm(&cm).len(),
            1,
            "⛔⛔⛔ DB-257: a returned note carried AGAIN by a later block was recorded a second time on the peer"
        );
    }

    /// ⛔⛔⛔ DB-258 pin 1 — AN OLD UNBOND DOES NOT RELEASE A NEW BOND.
    ///
    /// The v1 unbond statement signed the validator id and NOTHING about which bond it releases. Every unbond
    /// object is public: it rides the bond set with its pubkey and signature. So after V unbonds and bonds
    /// again, anyone can re-carry V's OLD unbond, and it releases V's NEW bond, forcing V out of the ≥2/3 tally
    /// against its will.
    /// CALIBRATION: the old object released the FIRST bond (so it is a real, authorised unbond).
    #[test]
    fn db258_an_old_unbond_does_not_release_a_new_bond() {
        let (mut a, mut b, pk, sk, vid, _locked) = db257_bonded_pair(b"db258-replay");
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db258-replay-owner");
        let (sig, sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: V's own unbond is admitted"
        );
        let u = a
            .produce(5_500, crate::hash::Hash32::hash(b"db258-r-u"), crate::hash::Hash32::hash(b"db258-mc"))
            .expect("A produces the unbond's block");
        let got = b.ingest_block(u.clone(), 5_900);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts it: {got:?}");
        // DB-274 P2 (§8.7): the unbond applies at its block's FOLD.
        let _ = a.fold_past_for_test(&mut [&mut b], 5_900, b"db258-fold");
        assert_eq!(b.validators().bond_of(&vid), 0, "CALIBRATION: the old unbond released V's FIRST bond");
        // V bonds AGAIN: a new instance, with a new locked note.
        let locked2 = sealed_note(crate::hash::Hash32::hash(b"db258-second-bond-cm").as_bytes(), b"db258-second");
        b.admit_bond_unverified(vid, 50_000, locked2.clone(), 7);
        assert_eq!(b.validators().bond_of(&vid), 50_000, "PRECONDITION: V is bonded again");
        // The replay: the OLD unbond's public bytes (the first block's bond set), in a later block that also
        // carries the NEW bond's note (DB-257's subject rule would otherwise refuse it on the note alone).
        b.apply_bond_set(&u.bond_set, 40, &locked2, &u.nullifier_proof.padded_tags, None);
        assert_eq!(
            b.validators().bond_of(&vid),
            50_000,
            "⛔⛔⛔ DB-258: V's OLD unbond released its NEW bond. The authorisation names no bond instance, so every \
             past unbond of V (all public) replays against V's next bond."
        );
    }

    /// ⛔⛔⛔ DB-258 pin 2 — AN UNBOND WHOSE OWNER BUCKET WAS REWRITTEN IN FLIGHT RELEASES NOTHING.
    ///
    /// `owner_bucket` and `owner_ek` ride the object UNSIGNED. A relayer or producer can rewrite them on an
    /// honest unbond. The returned note stays sealed to its owner, but it gets FILED under someone else's account
    /// bucket: on chain, and unlocatable from the owner's seed.
    /// CALIBRATION: the honest, unmodified object releases.
    #[test]
    fn db258_an_unbond_whose_owner_bucket_was_rewritten_releases_nothing() {
        let (_a, mut b, pk, sk, vid, locked) = db257_bonded_pair(b"db258-owner");
        // DECLARED FIXTURE AMENDMENT (DB-273 §19.3 L2, assertions unchanged): the owner is the returned note's OLI clue,
        // signed as its digest in the header; "rewriting the owner" is now re-pointing that digest (with a matching clue,
        // so the object still decodes) — the signature must refuse it, exactly the property this pin measures.
        let honest_clue = crate::unbond_tx::unbond_clue_for_test(&[0x58u8; 32], b"db258-honest-owner");
        let (sig, sig_nonce) = b.sign_unbond_for_test(&sk, &vid, &honest_clue);
        let instance = b.bond_instance_of(&vid).expect("V's live bonding on B");
        let honest_h = crate::unbond_tx::UnbondHeader {
            owner_clue_digest: crate::oli::owner_clue_digest(&honest_clue),
            bond_instance: instance,
            nonce: sig_nonce,
        };
        let honest = crate::unbond_tx::wire(&honest_h, &pk, &sig, &honest_clue).expect("the honest object encodes");
        let thief_clue = crate::unbond_tx::unbond_clue_for_test(&[0x59u8; 32], b"db258-someone-else");
        let rewritten_h = crate::unbond_tx::UnbondHeader {
            owner_clue_digest: crate::oli::owner_clue_digest(&thief_clue),
            bond_instance: instance,
            nonce: sig_nonce,
        };
        let rewritten = crate::unbond_tx::wire(&rewritten_h, &pk, &sig, &thief_clue).expect("the rewritten object encodes");
        // A clue swapped under the HONEST header is not even an unbond: `decode` refuses a clue its signed digest does not name.
        let swapped = crate::unbond_tx::wire(&honest_h, &pk, &sig, &thief_clue).expect("the swapped object encodes");
        assert!(
            matches!(
                crate::node::objects::unbond_tx::apply_chain_unbond(
                    &mut b,
                    &swapped,
                    &crate::pqauth::MlDsaVerifier,
                    10,
                    10,
                    &[crate::unbond_tx::unbond_right_nf(&vid, &honest_h)],
                ),
                crate::unbond_tx::UnbondApply::Refused(_)
            ),
            "⛔⛔⛔ DB-273 §19.3 L2: an unbond whose owner clue was SWAPPED under its signed digest was admitted"
        );
        // DB-258d (DECLARED FIXTURE AMENDMENT, assertions unchanged): each object is applied with ITS OWN right in the
        // lane, so the rewritten one is refused by its signature alone — exactly the property this pin measures.
        let got = crate::node::objects::unbond_tx::apply_chain_unbond(
            &mut b,
            &rewritten,
            &crate::pqauth::MlDsaVerifier,
            10,
            10,
            &[crate::unbond_tx::unbond_right_nf(&vid, &rewritten_h)],
        );
        assert!(
            !matches!(got, crate::unbond_tx::UnbondApply::Released(_)),
            "⛔⛔⛔ DB-258: an unbond whose owner was REWRITTEN in flight released the bond ({got:?}). Its returned note \
             is filed where its owner cannot find it."
        );
        let got = crate::node::objects::unbond_tx::apply_chain_unbond(
            &mut b,
            &honest,
            &crate::pqauth::MlDsaVerifier,
            10,
            10,
            &[crate::unbond_tx::unbond_right_nf(&vid, &honest_h)],
        );
        assert!(
            matches!(got, crate::unbond_tx::UnbondApply::Released(_)),
            "CALIBRATION: the honest, unmodified object releases: {got:?}"
        );
    }

    /// ⭐ DB-266 (apply half) — EQUIVOCATION EVIDENCE CARRIED BY A BLOCK SLASHES THE VALIDATOR ON EVERY NODE, AND A
    /// FORGED ONE SLASHES NOBODY.
    ///
    /// The evidence is two finality votes by one key at one height for two different blocks. It is published once,
    /// rides the producer's next block in the bond set, and every grafting node verifies it from the object's own
    /// bytes and slashes the voter.
    /// TAMPER (refused at the publish door, nothing moves): one block twice, two different keys, a forged signature.
    /// CONTROL: before the evidence's block, the peer still counts V's weight.
    #[test]
    fn db266_equivocation_evidence_carried_by_a_block_slashes_the_validator_on_every_node() {
        let mut a = testnet_node();
        let mut b = testnet_node();
        let x = a
            .produce(4_500, crate::hash::Hash32::hash(b"db266e-x"), crate::hash::Hash32::hash(b"db266e-mc"))
            .expect("A produces X");
        let y = b
            .produce(4_600, crate::hash::Hash32::hash(b"db266e-y"), crate::hash::Hash32::hash(b"db266e-mc"))
            .expect("B produces Y");
        assert!(matches!(a.ingest_block(over_the_wire(&y), 5_000), crate::relay::RelayOutcome::Added(_)), "A holds Y");
        assert!(matches!(b.ingest_block(over_the_wire(&x), 5_000), crate::relay::RelayOutcome::Added(_)), "B holds X");
        let h = a.dag().get(&x.id()).map(|n| n.blue_score).expect("X in A's DAG");
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(crate::hash::Hash32::hash(b"db266e-locked").as_bytes());
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        }
        let vote = |blk: &crate::block::Block, key: &[u8], secret: &[u8]| crate::validator::VoteCert {
            pubkey: key.to_vec(),
            block: blk.id(),
            height: h,
            sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&blk.id(), h), secret)
                .expect("a finality vote signs"),
        };
        let (vx, vy) = (vote(&x, &pk, &sk), vote(&y, &pk, &sk));
        let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        let by_another_key = vote(&y, &pk2, &sk2);
        let mut forged = vy.clone();
        forged.sig[10] ^= 1;
        for (what, p, q) in [("one block twice", &vx, &vx), ("two different keys", &vx, &by_another_key), ("a forged signature", &vx, &forged)] {
            assert!(
                !matches!(a.publish_equivocation(p, q), crate::node::AssetSpendOutcome::Published),
                "⛔ DB-266: evidence with {what} was PUBLISHED"
            );
        }
        assert_eq!(b.validators().bond_of(&vid), 50_000, "CONTROL: nothing has slashed V on the peer yet");
        assert_eq!(
            a.publish_equivocation(&vx, &vy),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: honest evidence is admitted"
        );
        let blk = a
            .produce(6_000, crate::hash::Hash32::hash(b"db266e-p"), crate::hash::Hash32::hash(b"db266e-mc"))
            .expect("A produces the evidence's block");
        assert!(!blk.bond_set.is_empty(), "PRECONDITION: the evidence rides the validator-object lane");
        let got = b.ingest_block(over_the_wire(&blk), 6_500);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts the evidence's block: {got:?}");
        // DB-274 P2 (§8.7): the slash applies at the evidence block's FOLD, on both nodes alike.
        let _ = a.fold_past_for_test(&mut [&mut b], 6_500, b"db266e-fold");
        assert_eq!(a.validators().bond_of(&vid), 0, "the evidence's block slashed V on its producer");
        assert_eq!(
            b.validators().bond_of(&vid),
            0,
            "⛔⛔⛔ DB-266: equivocation evidence carried by a block did not slash V on the peer — the validator \
             sets differ between honest nodes"
        );
    }

    /// ⭐⭐⭐ §22 5 — EQUIVOCATION BURNS THE OPERATOR'S OWN BOND AND RETURNS DELEGATED SAT, ON EVERY NODE. V holds 50,000 of
    /// its own and 30,000 delegated; its equivocation rides A's block and folds on A and B. On both: V weighs nothing and is
    /// barred, exactly its own 50,000 is burned, the 30,000 delegated word survives, an undelegation of all of it is admitted
    /// (the ordinary 21-day return) while a yield claim on the slashed seat is refused. CONTROL on both nodes: a reserve
    /// theft's slash (`apply_slash`, fail-closed until SAT is priced) still burns the delegations.
    #[test]
    fn equivocation_burns_the_operators_own_bond_and_returns_delegated_sat() {
        let mut a = testnet_node();
        let mut b = testnet_node();
        let x = a.produce(4_500, crate::hash::Hash32::hash(b"s22-x"), crate::hash::Hash32::hash(b"s22-mc")).expect("A produces X");
        let y = b.produce(4_600, crate::hash::Hash32::hash(b"s22-y"), crate::hash::Hash32::hash(b"s22-mc")).expect("B produces Y");
        assert!(matches!(a.ingest_block(over_the_wire(&y), 5_000), crate::relay::RelayOutcome::Added(_)), "A holds Y");
        assert!(matches!(b.ingest_block(over_the_wire(&x), 5_000), crate::relay::RelayOutcome::Added(_)), "B holds X");
        let h = a.dag().get(&x.id()).map(|n| n.blue_score).expect("X in A's DAG");
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(crate::hash::Hash32::hash(b"s22-locked").as_bytes());
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
            n.validators_mut_for_test().delegate(vid, 30_000).expect("a delegation to V");
            assert_eq!(n.validators().bond_of(&vid), 80_000, "PRECONDITION: V weighs its own bond and the delegation");
        }
        let burned_before = [a.validators().slashed_bond_burned(), b.validators().slashed_bond_burned()];
        let vote = |blk: &crate::block::Block| crate::validator::VoteCert {
            pubkey: pk.clone(),
            block: blk.id(),
            height: h,
            sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&blk.id(), h), &sk).expect("a finality vote signs"),
        };
        assert_eq!(a.publish_equivocation(&vote(&x), &vote(&y)), crate::node::AssetSpendOutcome::Published, "PRECONDITION");
        let blk = a.produce(6_000, crate::hash::Hash32::hash(b"s22-p"), crate::hash::Hash32::hash(b"s22-mc")).expect("evidence block");
        assert!(matches!(b.ingest_block(over_the_wire(&blk), 6_500), crate::relay::RelayOutcome::Added(_)), "B grafts it");
        let _ = a.fold_past_for_test(&mut [&mut b], 6_500, b"s22-fold");
        for (i, (name, n)) in [("A", &a), ("B", &b)].into_iter().enumerate() {
            let v = n.validators();
            assert_eq!(v.bond_of(&vid), 0, "{name}: V weighs nothing");
            assert_eq!(v.slashed_bond_burned() - burned_before[i], 50_000, "⛔ {name}: the burn is not exactly V's own bond");
            assert_eq!(v.delegated_to(&vid), 30_000, "⛔ {name}: the delegators' SAT was burned with the operator");
            assert_eq!(v.undelegate_refusal(&vid, 30_000), None, "⛔ {name}: the delegators cannot take their SAT back");
            assert!(v.claim_refusal(&vid, 30_000).is_some(), "⛔ {name}: a slashed seat's delegations still earn");
            assert!(v.delegate_refusal(&vid, 1).is_some(), "{name}: nobody delegates to a slashed seat");
        }
        // CONTROL — on both nodes, the theft slash keeps burning delegations (fail closed until SAT is priced).
        let (pk2, _) = crate::pqauth::ml_dsa_keypair();
        let thief = crate::pqauth::pubkey_id(&pk2);
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(thief, 10_000, locked.clone(), 0);
            n.validators_mut_for_test().delegate(thief, 5_000).expect("a delegation to the thief");
            assert_eq!(n.apply_slash(thief), Some(15_000), "the theft slash burns the whole seat");
        }
        assert_eq!(b.validators().delegated_to(&thief), 0, "the peer burned the thief's delegations with it");
        assert_eq!(a.validators().delegated_to(&thief), b.validators().delegated_to(&thief));
    }

    /// ⛔⛔⛔ DB-266 — AN EQUIVOCATION SEEN BY ONE NODE SLASHES THE VALIDATOR ON EVERY NODE.
    ///
    /// Both vote doors slash LOCALLY on `VoteRecord::Equivocation`, and the mesh door does not re-gossip the
    /// conflicting vote. So an equivocator that sends its second vote to a SUBSET of nodes is slashed on exactly
    /// that subset. The validator set, and every ≥2/3 denominator measured against it, then differs between
    /// honest nodes. The same shape as §AS: a value-moving transition (burning a bond) applied as a local
    /// mutation, not a chain object every node applies from a block.
    /// CALIBRATION: A really saw an equivocation (its own door slashed V).
    #[test]
    fn db266_an_equivocation_seen_by_one_node_slashes_the_validator_on_every_node() {
        let mut a = testnet_node();
        let mut b = testnet_node();
        for n in [&mut a, &mut b] {
            n.set_finality_verifier(Box::new(crate::pqauth::MlDsaVerifier));
        }
        // Two conflicting blocks at ONE height, held by BOTH nodes: A's child of genesis and B's.
        let x = a
            .produce(4_500, crate::hash::Hash32::hash(b"db266-x"), crate::hash::Hash32::hash(b"db266-mc"))
            .expect("A produces X");
        let y = b
            .produce(4_600, crate::hash::Hash32::hash(b"db266-y"), crate::hash::Hash32::hash(b"db266-mc"))
            .expect("B produces Y");
        assert!(matches!(a.ingest_block(over_the_wire(&y), 5_000), crate::relay::RelayOutcome::Added(_)), "A holds Y");
        assert!(matches!(b.ingest_block(over_the_wire(&x), 5_000), crate::relay::RelayOutcome::Added(_)), "B holds X");
        let h = a.dag().get(&x.id()).map(|n| n.blue_score).expect("X in A's DAG");
        assert_eq!(a.dag().get(&y.id()).map(|n| n.blue_score), Some(h), "PRECONDITION: X and Y share one height");
        // V is bonded on both.
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(crate::hash::Hash32::hash(b"db266-locked").as_bytes());
        for n in [&mut a, &mut b] {
            n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        }
        let vote = |blk: &crate::block::Block| crate::validator::VoteCert {
            pubkey: pk.clone(),
            block: blk.id(),
            height: h,
            sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&blk.id(), h), &sk)
                .expect("V signs a finality vote"),
        };
        // V equivocates: A sees both votes, B sees only the first.
        let (vx, vy) = (vote(&x), vote(&y));
        let _ = a.submit_finality_vote(vx.clone());
        let second = a.submit_finality_vote(vy);
        assert!(
            matches!(second, crate::validator::FinalityVoteOutcome::Equivocation),
            "CALIBRATION: A's door caught the equivocation: {second:?}"
        );
        assert_eq!(
            a.validators().bond_of(&vid),
            50_000,
            "⛔ DB-266: A's door slashed V LOCALLY — a bond moved with no block carrying why"
        );
        let _ = b.submit_finality_vote(vx.clone());
        // The runtime's half in miniature: pair the queued cert with the first cert it remembered, and publish.
        let queued = a.take_pending_equivocations();
        assert_eq!(queued.len(), 1, "PRECONDITION: the door queued exactly the conflicting cert");
        assert_eq!(
            a.publish_equivocation(&vx, &queued[0]),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the evidence is admitted to A's pool"
        );
        let blk = a
            .produce(6_000, crate::hash::Hash32::hash(b"db266-p"), crate::hash::Hash32::hash(b"db266-mc"))
            .expect("A produces the evidence's block");
        let got = b.ingest_block(over_the_wire(&blk), 6_500);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "B grafts the evidence's block: {got:?}");
        // DB-274 P2 (§8.7): the slash applies at the evidence block's FOLD, on both nodes alike.
        let _ = a.fold_past_for_test(&mut [&mut b], 6_500, b"db266-fold");
        assert_eq!(a.validators().bond_of(&vid), 0, "the evidence's block slashed V on A");
        assert_eq!(
            b.validators().bond_of(&vid),
            a.validators().bond_of(&vid),
            "⛔⛔⛔ DB-266: an equivocation seen by ONE node slashed V there and nowhere else. The honest pair now \
             disagrees on V's weight and on every ≥2/3 denominator measured against it."
        );
    }

    /// ⛔⛔⛔ DB-274 P2 (§8.7) — AN UNBOND AND A SLASH OF ONE VALIDATOR, GRAFTED IN OPPOSITE ORDERS BY TWO NODES, LEAVE
    /// ONE VALIDATOR SET AND ONE RECORD.
    ///
    /// U (V's unbond, produced by A) and E (evidence of V's equivocation, produced by C) are SIBLINGS. A holds U then
    /// E; B grafts E then U. Applied at graft (arrival order), A released V (collateral returned, the slash found no
    /// bond) while B slashed V (collateral burned, the unbond refused): the honest pair disagreed on V's weight AND on
    /// a record — the order an equivocating validator controls (§8, B19). Applied at the canonical FOLD, both nodes run
    /// the same order: whichever comes first, V ends slashed and the collateral never returns (a slash reaches an
    /// unbonding entry inside its window). RED on the graft-time tree.
    /// Both parties read before any assertion, so a failure names both states.
    #[test]
    fn db274_p2_an_unbond_and_a_slash_grafted_in_opposite_orders_leave_one_set_and_one_record() {
        let (mut a, mut b, pk, sk, vid, locked) = db257_bonded_pair(b"db274-us");
        let mut c = testnet_node();
        {
            let mut gp = c.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            c.set_params(gp);
        }
        c.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        // U: V's unbond, on A.
        let (owner_ek, _dk) = crate::pqkem::keypair();
        let bucket = crate::account_da::bucket_id(b"db274-us-owner");
        let (sig, sig_nonce) = a.sign_unbond_for_test(&sk, &vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
        assert_eq!(
            a.publish_unbond(&pk, &sig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),sig_nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: V's unbond is admitted on A"
        );
        let u = a
            .produce(5_000, crate::hash::Hash32::hash(b"db274-us-u"), crate::hash::Hash32::hash(b"db274-us-mc"))
            .expect("A produces U");
        // E: evidence of V's equivocation, on C (a sibling of U: both children of genesis).
        let vote = |blk: crate::block::BlockId| crate::validator::VoteCert {
            pubkey: pk.clone(),
            block: blk,
            height: 1,
            sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&blk, 1), &sk).expect("V signs"),
        };
        let (vx, vy) = (vote(crate::hash::Hash32::hash(b"db274-us-x")), vote(crate::hash::Hash32::hash(b"db274-us-y")));
        assert_eq!(
            c.publish_equivocation(&vx, &vy),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: the evidence is admitted on C"
        );
        let e = c
            .produce(5_100, crate::hash::Hash32::hash(b"db274-us-e"), crate::hash::Hash32::hash(b"db274-us-mc"))
            .expect("C produces E");
        assert!(!u.bond_set.is_empty() && !e.bond_set.is_empty(), "PRECONDITION: both objects ride the bond lane");
        // Opposite arrival orders: A holds U (its own) then E; B grafts E then U.
        assert!(matches!(a.ingest_block(over_the_wire(&e), 5_500), crate::relay::RelayOutcome::Added(_)), "A grafts E");
        assert!(matches!(b.ingest_block(over_the_wire(&e), 5_500), crate::relay::RelayOutcome::Added(_)), "B grafts E");
        assert!(matches!(b.ingest_block(over_the_wire(&u), 5_600), crate::relay::RelayOutcome::Added(_)), "B grafts U");
        // A merges both and every later block folds them, on both nodes.
        let mut ts = a.fold_past_for_test(&mut [&mut b], 5_600, b"db274-us-fold");
        // Past the whole unbonding window too, so a return that was merely late would have landed.
        // (this fixture governs the time half to 0: the evidence horizon is the whole wait)
        for i in 0..=a.unbond_horizon_blue() {
            ts += 1_000;
            let blk = a
                .produce(ts, crate::hash::Hash32::hash(&i.to_le_bytes()), crate::hash::Hash32::hash(b"db274-us-w"))
                .expect("A produces through the window");
            assert!(matches!(b.ingest_block(blk, ts + 400), crate::relay::RelayOutcome::Added(_)), "B grafts it");
        }
        let _ = a.fold_past_for_test(&mut [&mut b], ts + 400, b"db274-us-final");
        let state = |n: &Node| {
            (
                n.validators().bond_of(&vid),
                n.validators().is_slashed(&vid),
                n.unbonding_due(&vid),
                n.records_containing_cm(&cm).len(),
            )
        };
        let (sa, sb) = (state(&a), state(&b));
        eprintln!("[db274-us] A (weight, slashed, unbonding, records) = {sa:?}   B = {sb:?}");
        assert_eq!(
            sa, sb,
            "⛔⛔⛔ DB-274: two honest nodes that grafted one unbond and one slash of V in opposite orders hold \
             DIFFERENT validator state or records for V"
        );
        assert_eq!(sa.0, 0, "V holds no weight");
        assert!(sa.1, "V is slashed: the evidence burns it whichever object folds first");
        assert_eq!(sa.3, 0, "⛔⛔⛔ the slashed validator's collateral returned");
    }

    /// ⭐⭐⭐ DB-273 §19 L1 — A MINT'S OWNER RIDES ITS SIGNED OBJECT, AND A PEER FED ONLY THE CHAIN FINDS IT BY OLI.
    ///
    /// Two nodes on one chain. `node_a` publishes a wrapped mint whose owner is a REAL OLI clue (a wallet's own `chg`
    /// locator, index 0) and lays the block; `node_b` learns everything from that block. Pins §19 L1 (a) and (b):
    /// - (a) a copy whose clue a relay STRIPPED or REPLACED justifies nothing at `node_b`'s graft door (the object as
    ///   A's block carries it, re-framed with the forged clue). CALIBRATION, the attack is armed: the quorum's
    ///   signatures verify over the forged copy's header unchanged, so only the recipient's commitment to the clue
    ///   refuses it.
    /// - (b) the honest object files its OWN clue on `node_b`, though the transaction's relay-mutable sidecar carried
    ///   none: the key a seed-only restore derives from the locator secret alone finds the note in B's OLI index.
    /// TWO-PARTY-REVIEWED: the refusal and the finding are both asserted on `node_b`, which never saw A's pool.
    /// RED-run: with `wrapped_mint_tx::decode`'s recipient-commitment refusal removed, (a) fails (the forged copy
    /// justifies the note); with the object-derived record removed from `carried_clue_records`, (b) fails (no key).
    #[test]
    fn db273_s19_l1_a_mint_owner_rides_its_signed_object_and_a_chain_fed_peer_finds_it_by_oli() {
        let (mut node_a, mut node_b, pk, sk) = pair();
        let addr = "bc1pdb273s19l1";
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0x19, 0x273, 1, 1]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x273, 0x19, 0x1]);
        let (wcarrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(2000, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        let cm = crate::spend_frontier::leaf_to_cm_bytes(wcm);
        let note = sealed_note(&cm, b"db273-s19-l1-note");
        // The owner a wallet sends: the note's clue at ITS OWN locator — nothing the chain could link to a wallet.
        let loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"db273-s19-l1-owner-seed").as_bytes());
        let clue_at = |loc_sk: &[u8; 32]| {
            let salt = crate::oli::address_salt(loc_sk, "chg", 0);
            crate::oli::tag_clue_bytes_v2(
                &crate::oli::locator_at(loc_sk, "chg", 0),
                &salt,
                &crate::oli::address_index_hint(loc_sk, &salt, 0),
            )
        };
        let clue = clue_at(&loc_sk);
        let deposit_id = [0x73u8; 32];
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        assert_eq!(
            node_a.publish_wrapped_mint(
                ASSET, deposit_id, 3000, 2000, crate::peg::peg_in_recipient(&deposit_id, &clue), &note, &wcarrier, addr,
                &pk, &sk, &[], &crate::pqauth::MlDsaVerifier, &clue, wdb,
            ),
            crate::peg::PegOutcome::ConfidentialPublished,
            "PRECONDITION: the owner-named mint publishes on A"
        );
        let blk = node_a
            .produce(4_500, crate::hash::Hash32::hash(b"db273-s19-fr"), crate::hash::Hash32::hash(b"db273-s19-mc"))
            .expect("A lays the block carrying the mint");
        let gid = blk.id();
        let carried = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects)
            .expect("the credit set parses")
            .into_iter()
            .find(|o| matches!(crate::chain_object::unframe(o), Some((crate::chain_object::Class::WrappedMint, _))))
            .expect("PRECONDITION: A's block carries the wrapped mint object");
        let (_, payload) = crate::chain_object::unframe(&carried).expect("framed");
        let (h, c, mc, att, note_ref, sealed, carried_clue) =
            crate::wrapped_mint_tx::decode(payload).expect("the honest object decodes");
        assert_eq!(carried_clue, clue, "PRECONDITION: the object carries the owner's clue");
        assert!(
            matches!(node_b.ingest_block(blk.clone(), 9_000), crate::relay::RelayOutcome::Added(_)),
            "node_b grafts A's block"
        );
        assert!(node_b.holds_record_with_cm(&cm), "FAIRNESS PRECONDITION: node_b credits the honest mint from the block");

        // (a) THE RELAY'S COPIES, judged by node_b's own graft door with the object as A's block carries it.
        let honest_set = crate::node::tests::sealed_credit_parts(&blk, &[carried.clone()]);
        let judged = |peer: &Node, set: &(Vec<u8>, Vec<Vec<u8>>)| {
            peer.graft_admitted_notes(&gid, &note, blk.cover_key, None, None, None, &set.0, &set.1, &blk.bond_set, &blk.nullifier_proof.padded_tags, &blk.oli_tags)
        };
        assert_eq!(judged(&node_b, &honest_set), note, "CALIBRATION: node_b's door justifies the honest object's note");
        // v3 (F-LEG, 2026-11-11): the quorum signs the recipient bound to the sealed legs the object carries — the forged
        // copies below keep both, so the signatures still verify over them and the clue alone is what refuses them.
        let msg = crate::peg::wrapped_mint_confidential_msg(
            h.asset_id,
            &h.deposit_id,
            &h.new_reserve_commit,
            &h.new_minted_commit,
            &h.delta_commit,
            &crate::peg::peg_in_signed_recipient(&h.recipient, &sealed),
        );
        for (what, forged_clue) in [
            ("STRIPPED", Vec::new()),
            ("REPLACED with another wallet's", clue_at(&crate::oli::derive_loc_sk(blake3::hash(b"db273-thief").as_bytes()))),
        ] {
            let forged = crate::wrapped_mint_tx::wire(&h, &c, &mc, &att, &note_ref, &sealed, &forged_clue);
            assert!(
                att.iter().all(|x| crate::pqauth::ml_dsa_verify(&msg, &x.pubkey, &x.sig)),
                "CALIBRATION ({what}): the quorum's signatures still verify over the forged copy's unchanged header"
            );
            assert!(
                judged(&node_b, &crate::node::tests::sealed_credit_parts(&blk, &[forged])).is_empty(),
                "⛔⛔⛔ DB-273 §19 L1 (a): a mint whose clue a relay {what} still justified its note on node_b — the \
                 owner is not under the quorum's signatures"
            );
        }

        // (b) node_b, fed only the chain, files the object's OWN clue: the key a seed-only restore derives finds it.
        let _ = node_a.fold_past_for_test(&mut [&mut node_b], 9_500, b"db273-s19-fold");
        let k = crate::oli::index_key(&clue_at(&loc_sk));
        let idx = node_b.oli_build_index();
        let found = crate::oli::table_candidates(&idx.shard_table(crate::oli::shard_of(&k, idx.shard_bits)), &k);
        assert!(
            !found.is_empty(),
            "⛔⛔⛔ DB-273 §19 L1 (b): node_b does not index the minted note under its owner's key — a seed-only \
             restore through node_b cannot find it"
        );
    }

    /// ⭐⭐⭐ DB-273 §19.3 L2 (c) — A RETURNED BOND IS FOUND BY ITS OWNER'S KEY ON BOTH NODES.
    ///
    /// V unbonds naming a REAL OLI clue (its own `chg` locator). No block carries the returned note — the fold releases it
    /// from the certified unbonding entry after the window — so its tag must be placed by the fold itself, identically on
    /// every node. Both nodes, fed the same blocks, must hold the returned note AND index it under the key a seed-only
    /// restore derives from the locator secret alone.
    /// TWO-PARTY-REVIEWED: asserted on `node_a` (the producer) and `node_b` (fed only A's blocks).
    /// RED-run: with the fold release's tag placement removed, both nodes hold the note and neither indexes it.
    #[test]
    fn db273_s19_l2_a_returned_bond_is_indexed_under_its_owners_clue_on_both_nodes() {
        let (mut node_a, mut node_b, pk, sk, vid, locked) = db257_bonded_pair(b"db273-l2-return");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&locked[..32]);
        let loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"db273-l2-return-owner").as_bytes());
        let salt = crate::oli::address_salt(&loc_sk, "chg", 0);
        let clue = crate::oli::tag_clue_bytes_v2(
            &crate::oli::locator_at(&loc_sk, "chg", 0),
            &salt,
            &crate::oli::address_index_hint(&loc_sk, &salt, 0),
        );
        let (sig, nonce) = node_a.sign_unbond_for_test(&sk, &vid, &clue);
        assert_eq!(
            node_a.publish_unbond(&pk, &sig, &clue, nonce),
            crate::node::AssetSpendOutcome::Published,
            "PRECONDITION: V's unbond, naming its owner clue, is admitted on node_a"
        );
        let u = node_a
            .produce(5_000, crate::hash::Hash32::hash(b"db273-l2-u"), crate::hash::Hash32::hash(b"db273-l2-mc"))
            .expect("node_a produces the unbond's block");
        assert!(
            matches!(node_b.ingest_block(over_the_wire(&u), 5_500), crate::relay::RelayOutcome::Added(_)),
            "node_b grafts the unbond's block"
        );
        let mut ts = node_a.fold_past_for_test(&mut [&mut node_b], 5_600, b"db273-l2-fold");
        // (this fixture governs the time half to 0: the evidence horizon is the whole wait)
        for i in 0..=node_a.unbond_horizon_blue() {
            ts += 1_000;
            let blk = node_a
                .produce(ts, crate::hash::Hash32::hash(&i.to_le_bytes()), crate::hash::Hash32::hash(b"db273-l2-w"))
                .expect("node_a produces through the window");
            assert!(
                matches!(node_b.ingest_block(blk, ts + 400), crate::relay::RelayOutcome::Added(_)),
                "node_b grafts it"
            );
        }
        let _ = node_a.fold_past_for_test(&mut [&mut node_b], ts + 400, b"db273-l2-final");
        let k = crate::oli::index_key(&clue);
        for (who, n) in [("node_a", &node_a), ("node_b", &node_b)] {
            assert!(
                !n.records_containing_cm(&cm).is_empty(),
                "FAIRNESS PRECONDITION: {who} holds the returned bond after the unbonding window"
            );
            let idx = n.oli_build_index();
            let found = crate::oli::table_candidates(&idx.shard_table(crate::oli::shard_of(&k, idx.shard_bits)), &k);
            assert!(
                !found.is_empty(),
                "⛔⛔⛔ DB-273 §19.3 L2 (c): {who} does not index the returned bond under its owner's key — a seed-only \
                 restore cannot find the collateral it just got back"
            );
        }
        // The two nodes agree on WHERE the returned bond sits: the fold placed it in the same record on both, so a
        // restore through either finds the same position (the release is chain-derived, never a local choice).
        let rids = |n: &Node| n.records_containing_cm(&cm).iter().map(|r| r.0).collect::<Vec<u64>>();
        assert_eq!(rids(&node_b), rids(&node_a), "⛔ DB-273 §19.3 L2: node_b holds the returned bond in a different record than node_a");
    }
}

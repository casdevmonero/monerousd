// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ DB-358 (1): A SPEND MAY CONSUME ONLY A FOLDED RECORD. This is the door half of docs/DB-358 §5b.
//!
//! **Why a staged record is not yet a fact.** The record fold decides which of two spends of one nullifier
//! counts: the first spender in canonical order ([`crate::respend::decide_at_fold`]). A losing spend's outputs leave its
//! block's staged record BEFORE the record takes its position. So until the fold reaches a record, an output in it
//! can still be revoked.
//!
//! **The attack this closes.** Suppose a door admits a spend that names a staged record. A wallet can then spend
//! output o1 of its own spend X1 while it also races a second spend X2 of X1's input.
//! - If X2 precedes X1 canonically, the fold revokes o1.
//! - The child spend of o1 has already been admitted, and keeps o1's value.
//! - The winner X2 pays the same input out again.
//! That is inflation, and the spender drives it alone. No producer has to misbehave.
//!
//! **What this file pins, at the production doors, with the production fold depth.**
//! - A one-step membership that names a record the fold has not reached is REFUSED.
//! - The same carrier is ADMITTED once the fold passes the record.
//! - The refusal is a wait, never a verdict: the carrier is byte-identical before and after.
//!
//! This is Bitcoin's confirmations, for spends only: the fold lag.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;
    use crate::node::tests::{genesis_block, grind_tx};
    use crate::node::Node;

    /// ⛔⛔⛔ DB-358 (1), RED-first: THE DOOR MUST REFUSE A SPEND THAT NAMES A RECORD THE FOLD HAS NOT REACHED, AND
    /// ADMIT THE SAME BYTES ONCE IT HAS.
    ///
    /// **Construction.** Both parties run the production fold depth ([`crate::params::RECORD_FOLD_DEPTH_DEFAULT`]
    /// chain blocks):
    /// - one block carries a pooled tx, and the verifier grafts it, so the block's record is STAGED here;
    /// - a genuine one-step carrier is built for slot 0 of that record, exactly as a wallet builds one;
    /// - the door is asked before the fold and again after it.
    ///
    /// **Calibration.** Without it, a green result would be vacuous:
    /// - the record is held and has no position row before the fold (so it really is staged);
    /// - it has a position row after the fold;
    /// - the carrier's root equals the record's root at both points (the fold revoked nothing, since there was no
    ///   conflict).
    ///
    /// TWO-PARTY-REVIEWED: the producer lays the blocks, and the verifier is fed only the blocks. Both parties'
    /// doors are asked after the fold. The claim is each door's own verdict on the same bytes.
    ///
    /// cons: none. This is a `#[test]` pin: no production code and no stored state. It prints nothing that names a
    /// note, leaf, amount or key. Its cost is two in-process nodes plus RECORD_FOLD_DEPTH_DEFAULT + 2 idle blocks.
    #[test]
    fn a_door_refuses_a_spend_naming_a_record_the_fold_has_not_reached_and_admits_the_same_bytes_after_it() {
        use usdm_decider::note_membership_air::NoteMembershipCarrier;

        let mut producer = Node::new(genesis_block()).unwrap();
        let mut verifier = Node::new(genesis_block()).unwrap();
        let need = producer.mempool().required_stamp_bits();
        let tx = grind_tx(b"db358-door", 1_000, vec![Hash32::hash(b"db358-door-nf")], need);
        producer.ingest_tx_unverified(tx).expect("pooled");
        let blk = producer
            .produce(5_000, Hash32::hash(b"db358-door-fr"), Hash32::hash(b"db358-door-mc"))
            .expect("produced");
        let _ = verifier.ingest_block(blk.clone(), 9_000);

        let ours = Node::da_record_id_for_block(&blk.id(), 0);
        let slot = 0u8;
        let leaf = verifier.da_block_leaves(ours).expect("CALIBRATION: the verifier holds the staged record")
            [slot as usize];
        assert!(
            verifier.da_record_ordinal(ours).is_none(),
            "CALIBRATION: before the fold the record has NO position row here — it is staged, not folded"
        );
        let (sibs, dirs, want_root) =
            verifier.da_note_copath_in_block(ours, slot).expect("in-block copath served");
        let tx_binder = crate::spend_frontier::cm_bytes_to_leaf(Hash32::hash(b"db358-door-tx-nf").as_bytes());
        let mut carrier =
            NoteMembershipCarrier::new(leaf, want_root, Node::MEMBERSHIP_GENESIS_ACC, tx_binder, crate::spend_frontier::TEST_LC_BLIND);
        assert!(carrier.attach_membership(leaf, &sibs, &dirs), "copath attaches");
        assert!(carrier.step(want_root), "the ONE fold step proves");
        let (proof, acc, tip_prev, tip_root) = carrier.finalize_one_step().expect("certifies");
        let commit = carrier.leaf_commitment();
        assert_eq!(tip_root, want_root, "CALIBRATION: the carrier folds exactly the staged record's root");

        let admit = crate::respend::MemberDoor::Admit;
        // The FOLD door refuses the same unplaced record too: at a block's fold, a record not yet folded is not before that
        // block in the canonical order. (The carrier's validity is calibrated below: the SAME bytes pass once the fold has
        // placed the record, under an unchanged root.)
        assert!(
            !verifier.verify_membership_carrier_one_step(
                &proof,
                commit,
                tx_binder,
                tip_prev,
                tip_root,
                acc,
                ours,
                crate::respend::MemberDoor::Fold,
            ),
            "⛔⛔⛔ the FOLD door accepted a record the fold has not placed — its verdict would depend on what this node holds"
        );
        assert!(
            !verifier.verify_membership_carrier_one_step(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, admit),
            "⛔⛔⛔ DB-358 (1): THE DOOR ADMITTED A SPEND NAMING A RECORD THE FOLD HAS NOT REACHED. Until the fold decides \
             the record, a losing spend's outputs can still leave it (`respend_decide_at_fold`). A child admitted now \
             keeps an output the fold may revoke, while the winner pays the same input out again: inflation, driven \
             by the spender alone."
        );
        // ⭐ THE WAIT IS TOLD APART FROM A FORGERY (`MemberVerdict`, Bitcoin Core's missing-inputs vs invalid): the same bytes
        // before the fold are PENDING at the Admit door (a retry admits them) and REFUSED at the Fold door (no wait in the
        // canonical order), and a FORGED root on the same unfolded record is REFUSED — every forgery check runs before the
        // wait, so `Pending` is never told to a forgery. MEASURED why: sim-20261006-221807 T2, a fill whose lot was simply
        // not folded yet answered 422 MEMBERSHIP_REFUSED and the taker stopped.
        use crate::node::MemberVerdict;
        let fold = crate::respend::MemberDoor::Fold;
        assert_eq!(
            verifier.membership_carrier_verdict(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, admit),
            MemberVerdict::Pending,
            "⛔ an otherwise-valid carrier naming a staged record must be told to WAIT at the Admit door"
        );
        assert_eq!(
            verifier.membership_carrier_verdict(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, fold),
            MemberVerdict::Refused,
            "⛔ the Fold door never waits: its verdict is the canonical order's"
        );
        let mut forged_root = tip_root;
        forged_root[0] ^= 1;
        let forged_acc = usdm_decider::note_membership_air::note_membership_step_new_acc(tip_prev, forged_root);
        assert_eq!(
            verifier.membership_carrier_verdict(&proof, commit, tx_binder, tip_prev, forged_root, forged_acc, ours, admit),
            MemberVerdict::Refused,
            "⛔⛔⛔ a FORGED root on an unfolded record was told to wait — a forgery must be refused before any wait"
        );

        // Drive the fold past the record: the production depth, plus margin, of idle chain blocks.
        for i in 0..crate::params::RECORD_FOLD_DEPTH_DEFAULT + 2 {
            let b = producer
                .produce(5_500 + i * 500, Hash32::hash(b"db358-door-fr"), Hash32::hash(b"db358-door-mc"))
                .expect("an idle block produces");
            let _ = verifier.ingest_block(b, 9_500 + i * 500);
        }
        assert!(
            verifier.da_record_ordinal(ours).is_some(),
            "CALIBRATION: the fold has placed the record on the verifier — otherwise the second ask proves nothing"
        );
        assert_eq!(
            verifier.da_note_copath_in_block(ours, slot).map(|(_, _, r)| r),
            Some(want_root),
            "CALIBRATION: the folded record's root is the staged one, so the fold revoked nothing and the same bytes \
             must now pass"
        );
        assert!(
            verifier.verify_membership_carrier_one_step(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, admit),
            "the SAME carrier is admitted once the fold has placed its record — the refusal was a wait, not a verdict"
        );
        assert_eq!(
            verifier.membership_carrier_verdict(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, admit),
            MemberVerdict::Member,
            "the wait resolves to a member once the fold has placed the record"
        );
        assert!(
            producer.verify_membership_carrier_one_step(&proof, commit, tx_binder, tip_prev, tip_root, acc, ours, admit),
            "and the producer's door agrees on the same bytes"
        );
    }

    /// ⛔⛔⛔ DB-358 increment 2, RED-first: A RESTART MUST NOT FORGET THAT A TAG WAS ALREADY SPENT.
    ///
    /// **Why it can.** Increment 1 decides a re-spend at the fold from the lane's first-contact memo, and that memo was
    /// RAM-only. A resumed node grafts its checkpoint carry with nothing re-applied, so a lane it met BEFORE a restart
    /// and folds AFTER it has no memo. "No contest known" then credits the re-spend on the restarted node alone:
    /// inflation there, and a record divergence from every peer that did not restart.
    ///
    /// **Construction.** The fold depth is 2, so a block can be grafted before the restart and folded after it.
    /// 1. `node_a` lays spend #1 of input N. `node_b` grafts it and folds it (idle blocks on top).
    /// 2. `node_a` lays spend #2 of the SAME nullifier past its own door. `node_b` grafts it, and `node_b`'s memo marks
    ///    the tag OLD.
    /// 3. `node_b` restarts the production way BEFORE spend #2's block folds. It writes its checkpoint as a clean
    ///    shutdown does (`persist_blocking`), the process ends, and a fresh process boots from the same datadir
    ///    (`enable_persist`).
    /// 4. The restarted process folds spend #2's block on further idle blocks, and must NOT hold its output.
    ///
    /// **Calibration.**
    /// - `node_c`, fed every block `node_b` saw and never restarted, refuses the re-spend on the same blocks. So the pin
    ///   measures the restart, not the rule.
    /// - The restarted process really folded the re-spend's block, and it holds spend #1's output.
    ///
    /// TWO-PARTY-REVIEWED: `node_a` is the producer that skips its own door. `node_b` (and the process it restarts
    /// into) and `node_c` are fed only `node_a`'s blocks. The claim is what the restarted process holds.
    ///
    /// cons: none. This is a `#[test]` pin: no production code and no stored state. Its prints name only outcome
    /// variants. Its cost is three in-process nodes and two proofs.
    #[test]
    fn a_restart_between_graft_and_fold_does_not_credit_a_re_spend_of_an_old_nullifier() {
        use crate::block::Block;
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::{prove_spend_validity_carrier_with_commit_bytes, SpendValidityWitness};

        // DB-223 Q7: both inputs are FUNDED on chain — the testnet identity admits the funding credit (DB-354).
        let mut node_a = crate::node::tests::testnet_party_with_fold_depth(2);
        let mut node_b = crate::node::tests::testnet_party_with_fold_depth(2);
        let mut node_c = crate::node::tests::testnet_party_with_fold_depth(2);
        // The PRODUCTION restart path: node_b checkpoints to its datadir, and the process it restarts into boots from that
        // same datadir only after node_b has ended (two live processes never share one datadir — the 68 GB twin lesson).
        let path_b = std::env::temp_dir().join(format!("musd-db358-restart-b-{}.snap", std::process::id()));
        let _ = std::fs::remove_file(&path_b);
        assert_eq!(node_b.enable_persist(path_b.clone()), Ok(false), "node_b boots fresh, with no checkpoint yet");
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let witness = |out0: [u64; 4]| SpendValidityWitness {
            value_in: 1_000_000_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x358, 0x0e, 2, 2])),
            value_out: (1_000_000_000) - 100000,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            // per-send blinding (DB-329 §7f): the two spends share the INPUT's nullifier, never a claim tag, so the
            // refusal this pin measures is the nullifier's
            lc_blind: lanes_of(&[0x363, out0[0], out0[1], 3]),
            out0_value: (999_999_000) - 100000,
            out0_opening: lanes_of(&out0),
            out1_value: 1_000,
            out1_opening: lanes_of(&[7, out0[0], out0[1], out0[2]]),
        };
        let spend = |node: &Node, w: &SpendValidityWitness, pad: &str| {
            let (blob, cms, nf, lc, _d) =
                crate::note_transition::prove_wallet_spend(w).expect("an honest validity proof");
            let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
            for cm in cms {
                let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
                n[..32].copy_from_slice(&b32(cm));
                output_notes.extend_from_slice(&n);
            }
            let nfs = crate::node::tests::note_of_witness_for_test(w);
            let input = nfs.1;
            let nfs = crate::note_transition::test_spend_tag_list(nf, w, pad);
            let mut tx = grind_tx(&blob, blob.len() as u32, nfs, node.mempool().required_stamp_bits());
            tx.output_notes = output_notes;
            tx.note_clues = crate::note_transition::fixture_note_clues(&cms);
            tx.membership_leaf_commit = b32(lc);
            // DB-223 Q7: every spend proves its (funded) input exists — the member leg from the spender's node's stream.
            crate::node::tests::attach_member_leg_for_test(node, &mut tx, &input, w, nf, &cms);
            (tx, b32(cms[0]), b32(nf))
        };
        // DB-223 Q7: both inputs (the twice-spent one and the control's) EXIST — funded in one block all three nodes fold
        // (node_a lays it plus `record_fold_depth` more, before this pin's own timeline).
        {
            let mut control_input = witness([3, 3, 3, 3]);
            control_input.owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x358, 0x0f, 3, 3]));
            let respent = witness([1, 1, 1, 1]);
            let _ = crate::node::tests::fund_inputs_for_test(
                &mut node_a,
                &mut [&mut node_b, &mut node_c],
                &[&respent, &control_input],
                2_000,
            );
            for i in 0..2u64 {
                let t = 2_500 + 500 * i;
                let blk = node_a.produce(t, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"db358r-fund-fold")).expect("lays");
                let _ = node_b.ingest_block(blk.clone(), t + 1);
                let _ = node_c.ingest_block(blk, t + 1);
            }
        }
        let mut ts = 5_000u64;
        let mut lay = |producer: &mut Node, tag: &str| -> Block {
            ts += 500;
            producer
                .produce(ts, Hash32::hash(tag.as_bytes()), Hash32::hash(b"db358-restart-mc"))
                .expect("node_a lays a block")
        };

        let (tx1, out1, nf1) = spend(&node_a, &witness([1, 1, 1, 1]), "db358r-first");
        let (tx2, out2, nf2) = spend(&node_a, &witness([2, 2, 2, 2]), "db358r-second");
        assert_eq!(nf1, nf2, "CALIBRATION: both spends reveal ONE nullifier — the same input spent twice");
        assert_ne!(out1, out2, "CALIBRATION: the two spends pay different notes");
        // The CONTROL: a spend of a DIFFERENT input, riding the re-spend's block — the restarted process must credit it,
        // so its refusal of the re-spend is the contested tag's and never a fold that credits nothing.
        let mut fresh = witness([3, 3, 3, 3]);
        fresh.owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x358, 0x0f, 3, 3]));
        let (tx3, out3, nf3) = spend(&node_a, &fresh, "db358r-control");
        assert_ne!(nf3, nf1, "CALIBRATION: the control reveals a fresh nullifier");

        node_a.ingest_tx_unverified(tx1).expect("node_a pools the first spend");
        let blk1 = lay(&mut node_a, "db358r-1");
        let _ = node_b.ingest_block(blk1.clone(), 9_000);
        let _ = node_c.ingest_block(blk1, 9_000);
        for i in 0..4u64 {
            let idle = lay(&mut node_a, "db358r-idle-a");
            let _ = node_b.ingest_block(idle.clone(), 9_100 + i);
            let _ = node_c.ingest_block(idle, 9_100 + i);
        }
        assert!(node_b.holds_record_with_cm(&out1), "CALIBRATION: node_b folded spend #1 and holds its output");

        node_a.ingest_tx_unverified(tx2).expect("node_a pools the second spend of the same input past its own door");
        node_a.ingest_tx_unverified(tx3).expect("node_a pools the control spend");
        let blk2 = lay(&mut node_a, "db358r-2");
        let rid2 = Node::da_record_id_for_block(&blk2.id(), 0);
        let _ = node_b.ingest_block(blk2.clone(), 9_200);
        let _ = node_c.ingest_block(blk2, 9_200);
        assert!(
            node_b.da_record_ordinal(rid2).is_none(),
            "CALIBRATION: the re-spend's block is grafted but NOT folded when node_b checkpoints"
        );

        // ⭐ DB-353 §13.6 RESTATED THE ARMED ARM (2026-10-02). It used to restart a second process from a checkpoint WITHOUT
        // the respend carry and require it to CREDIT the re-spend — measuring the first-contact memo. §13.6 DELETED that
        // memo: the fold decides from the canonical fold-point set, so no carry-less restart credits it any more (measured
        // red at 3aa8041), and that arm measured a mechanism that no longer exists. The attack stays armed by the CONTROL:
        // the same block carries a fresh-nullifier spend the restarted process must credit, so its refusal of the
        // re-spend is the contested tag's, never a fold that credits nothing.

        // The restart: node_b writes its checkpoint as a clean shutdown does and its process ends; a FRESH process on the
        // same parameters boots from the same datadir.
        node_b.persist_blocking();
        drop(node_b);
        let mut node_b_restarted = crate::node::tests::testnet_party_with_fold_depth(2);
        assert_eq!(
            node_b_restarted.enable_persist(path_b.clone()),
            Ok(true),
            "the restarted process resumes from node_b's checkpoint"
        );
        // A restarted node either resumes its view from its own cache (DB-397 fix A: installed only at the band root) or
        // holds none; its runtime warms from a peer ONLY in the second case (`sparse_pivot`, node_runtime's warm). The same
        // door, in process, from node_c (which never restarted). MEASURED 2026-10-23: the cache resumes here, so the old
        // unconditional warm asked for a pivot a viewed node never stands on — a precondition no runtime path meets.
        if !node_b_restarted.nf_view_held() {
            if let Err(why) = node_b_restarted.warm_view_from_for_test(&node_c) {
                panic!("PRECONDITION: the viewless restarted process warms its view from node_c — {why}");
            }
        }
        assert!(
            node_b_restarted.is_nullifier_spent(&Hash32(nf1)),
            "the restarted process holds spend #1's nullifier as spent before the re-spend's block folds"
        );

        for i in 0..4u64 {
            let idle = lay(&mut node_a, "db358r-idle-b");
            let _ = node_c.ingest_block(idle.clone(), 9_300 + i);
            let _ = node_b_restarted.ingest_block(idle, 9_300 + i);
        }
        assert!(
            node_b_restarted.holds_record_with_cm(&out3),
            "CALIBRATION (the attack is armed): the restarted process credits the FRESH control spend in the re-spend's block"
        );
        assert!(
            node_b_restarted.da_record_ordinal(rid2).is_some(),
            "CALIBRATION: the restarted process FOLDED the re-spend's block — otherwise it was never asked"
        );
        assert!(
            node_b_restarted.holds_record_with_cm(&out1),
            "CALIBRATION: the restarted process holds spend #1's output"
        );
        assert!(
            node_c.da_record_ordinal(rid2).is_some() && !node_c.holds_record_with_cm(&out2),
            "CALIBRATION: node_c, which never restarted, folded the re-spend's block and refused it (the increment-1 rule)"
        );
        let credited_after_restart = node_b_restarted.holds_record_with_cm(&out2);
        drop(node_b_restarted);
        let _ = std::fs::remove_file(&path_b);
        assert!(
            !credited_after_restart,
            "⛔⛔⛔ THE RESTARTED NODE CREDITED A DOUBLE SPEND: it met the re-spend's lane before the restart, lost the \
             first-contact memo with it, and folded the block with no contest known. It now holds a 999,999,000-unit \
             output that every node which did not restart revoked."
        );
    }

    /// ⛔⛔ DB-407, RED-first: ONE SPEND CARRIED BY TWO PARALLEL BLOCKS IS FILED, ON EVERY NODE, AT THE ONE RECORD THE FOLD
    /// KEEPS IT IN.
    ///
    /// **Construction.** Two producers each pool the SAME spend and each lay a block before either has seen the other's:
    /// the DAG's ordinary width > 1. Each grafts the other's block, then the fold runs past both. The fold keeps the copy
    /// first in the canonical order and strips the other copy's outputs (DB-358; Kaspa's mergeset accepts a transaction
    /// once). Each node met a DIFFERENT copy first, so arrival order and canonical order disagree on one of them.
    ///
    /// **The claim**, asserted on BOTH nodes: the note's `cm → record` filing (what `/note_ordinal_by_cm` serves every
    /// carrier builder) names the record that still carries it. MEASURED why: sim-20261007-011239 T2 — a maker's lot cut
    /// rode two blocks, the bind was built at the duplicate's record, and the fold stripped it (422 MEMBERSHIP_REFUSED).
    ///
    /// **Calibration:** each block's record held the output before the cross-graft (both copies were real), and after the
    /// fold exactly one record holds it, the same one on both nodes (the strip ran, and the nodes agree on its verdict).
    ///
    /// TWO-PARTY-REVIEWED: both parties lay a block, each is fed the other's block only, and the claim is each node's own
    /// index. cons: none — a `#[test]` pin; it prints no note, leaf, amount or key.
    #[test]
    fn db407_a_spend_carried_by_two_parallel_blocks_is_filed_at_the_record_the_fold_keeps_on_every_node() {
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::SpendValidityWitness;

        let mut node_a = crate::node::tests::testnet_party_with_fold_depth(2);
        let mut node_b = crate::node::tests::testnet_party_with_fold_depth(2);
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let w = SpendValidityWitness {
            value_in: 1_000_000_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x407, 0x0a, 2, 2])),
            value_out: (1_000_000_000) - 100000,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            lc_blind: lanes_of(&[0x407, 1, 1, 3]),
            out0_value: (999_999_000) - 100000,
            out0_opening: lanes_of(&[4, 0, 7, 1]),
            out1_value: 1_000,
            out1_opening: lanes_of(&[7, 4, 0, 7]),
        };
        let _ = crate::node::tests::fund_inputs_for_test(&mut node_a, &mut [&mut node_b], &[&w], 2_000);
        for i in 0..2u64 {
            let t = 2_500 + 500 * i;
            let blk = node_a.produce(t, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"db407-fund-fold")).expect("lays");
            let _ = node_b.ingest_block(blk, t + 1);
        }
        let (blob, cms, nf, lc, _d) = crate::note_transition::prove_wallet_spend(&w).expect("an honest validity proof");
        let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
        for cm in cms {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(&b32(cm));
            output_notes.extend_from_slice(&n);
        }
        let input = crate::node::tests::note_of_witness_for_test(&w).1;
        let tags = crate::note_transition::test_spend_tag_list(nf, &w, "db407-twice");
        let mut tx = grind_tx(&blob, blob.len() as u32, tags, node_a.mempool().required_stamp_bits());
        tx.output_notes = output_notes;
        tx.note_clues = crate::note_transition::fixture_note_clues(&cms);
        tx.membership_leaf_commit = b32(lc);
        crate::node::tests::attach_member_leg_for_test(&node_a, &mut tx, &input, &w, nf, &cms);
        let out0 = b32(cms[0]);

        // THE DAG'S WIDTH: both producers pool the one spend and each lays a block before seeing the other's.
        node_a.ingest_tx_unverified(tx.clone()).expect("node_a pools the spend");
        node_b.ingest_tx_unverified(tx).expect("node_b pools the same spend");
        let x = node_a.produce(5_000, Hash32::hash(b"db407-x"), Hash32::hash(b"db407-mc")).expect("node_a lays X");
        let y = node_b.produce(5_000, Hash32::hash(b"db407-y"), Hash32::hash(b"db407-mc")).expect("node_b lays Y");
        let (rx, ry) = (Node::da_record_id_for_block(&x.id(), 0), Node::da_record_id_for_block(&y.id(), 0));
        assert_ne!(rx, ry, "CALIBRATION: two blocks, two records");
        assert!(
            node_a.records_containing_cm(&out0).iter().any(|r| r.0 == rx)
                && node_b.records_containing_cm(&out0).iter().any(|r| r.0 == ry),
            "CALIBRATION: each producer's own block carries the spend's output — two real copies of one transaction"
        );
        let _ = node_a.ingest_block(y, 5_100);
        let _ = node_b.ingest_block(x, 5_100);
        for i in 0..6u64 {
            let t = 6_000 + 500 * i;
            let idle = node_a.produce(t, Hash32::hash(b"db407-idle"), Hash32::hash(b"db407-mc")).expect("an idle block");
            let _ = node_b.ingest_block(idle, t + 1);
        }
        let held = |n: &Node| -> Vec<u64> { n.records_containing_cm(&out0).iter().map(|r| r.0).collect() };
        let (held_a, held_b) = (held(&node_a), held(&node_b));
        assert!(
            node_a.da_record_ordinal(rx).is_some() && node_a.da_record_ordinal(ry).is_some(),
            "CALIBRATION: node_a folded both copies' records — otherwise the fold never decided between them"
        );
        assert_eq!(held_a.len(), 1, "CALIBRATION: after the fold exactly ONE record keeps the output on node_a: {held_a:?}");
        assert_eq!(held_a, held_b, "CALIBRATION: both nodes keep it in the SAME record (one canonical verdict)");
        let keeper = held_a[0];
        for (who, n) in [("node_a", &node_a), ("node_b", &node_b)] {
            let (filed, _pending, real_there) = n.note_filing_for_test(&out0);
            assert!(
                filed == Some(keeper) && real_there,
                "⛔⛔ DB-407: on {who} the spend's output is filed at {filed:?} (holds it: {real_there}), not at the record the \
                 fold kept ({keeper}) — every membership carrier built through `/note_ordinal_by_cm` names a root the fold \
                 stripped, or no record at all, and the note cannot be spent or rested"
            );
        }
    }
}

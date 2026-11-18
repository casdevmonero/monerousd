// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A RESTART MUST NOT CHANGE WHAT A NODE HOLDS, NOR HOW FAR ITS RECORD SPACE REACHES — ON BOTH SIDES
//! OF A PAIR.**
//!
//! Every block writes a DA record; a block that carried no real notes writes ONE seed note derived from
//! PUBLIC data alone (`"MUSD-da-seed-note-v2-public" || seq || ctr`, see `record_note_payload_inner`) plus
//! deterministic cover, so its bytes are identical on every node: the producer and a peer that merely
//! INGESTED the block must hold the same record for the same seq, before and after either restarts.
//!
//! MEASURED on the live pair 2026-09-02 after the fee deploy's rolling restart: both nodes resumed
//! NOT_READY, each registered wants for a handful of records, the origin "asked 32 by id every tick",
//! and every wallet on the pair read PENDING (user-level probe: drip recorded, note detected, presence
//! mask unanswered for 240 s). One deterministic cause found here (8 of 8 runs): `restore_snapshot`
//! refilled the ordinal maps but never rebuilt `da_ord_top`, so a resumed node's record-ordinal ceiling
//! was 1 whatever it restored, and `span_closes_to_target` refused every span past ordinal 1 — a
//! restarted node could not accept a by-id record it fetched, so it re-asked forever.
//!
//! Two parties in every test — `node_a` PRODUCES, `node_b` INGESTS — and the assertions are that they
//! hold or derive the SAME thing, across the restart the deploy performs.
//!
//! cons: none — every assertion is an indexed read over a FIXED two-block, two-node fixture; nothing
//! here scales with the chain. The ceiling under test is one max over ordinals already being restored,
//! and a seed-only record is one keyed-PRF fill of a fixed 1153-byte note plus a deterministic 256-slot
//! cover = f(constants); no history walk, no growth in any cardinal.

#[cfg(test)]
mod tests {
    use crate::block::Block;
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::relay::RelayOutcome;
    use crate::params::{network_genesis_prefix, ChainParams};

    /// A TESTNET node, exactly as the persist door tests build one — the fixtures and the live pair are
    /// testnet, and a default-params node is a MAINNET node whose genesis-parity check refuses them.
    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 0; // this file's subject is not the fold delay: fold at the tip, canonical order
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        Node::with_params(g, p).expect("a testnet node builds")
    }

    /// `node_a` produces one EMPTY block (no transactions); `node_b` INGESTS it as a peer would. Returns
    /// the block and the canonical id of the DA record it wrote. Self-checked on BOTH parties before any
    /// later assertion, so a later `None` can only mean "forgotten", never "never written".
    fn produce_and_ingest_empty_block(
        node_a: &mut Node,
        node_b: &mut Node,
        ts: u64,
        tag: &[u8],
    ) -> (Block, u64) {
        let blk = node_a
            .produce(ts, Hash32::hash(tag), Hash32::hash(b"miner"))
            .expect("an empty block produces");
        assert!(
            matches!(node_b.ingest_block(blk.clone(), ts + 1_000), RelayOutcome::Added(_)),
            "setup: the peer grafts the producer's block"
        );
        let seq = Node::da_record_id_for_block(&blk.id(), 0);
        let a = node_a.da_record_notes(seq).expect("setup: the producer holds the record it wrote");
        let b = node_b.da_record_notes(seq).expect("setup: the peer holds the record it derived");
        assert_eq!(a, b, "setup: producer and peer derive the SAME seed-only record for {seq}");
        (blk, seq)
    }

    /// Restart = the SAME checkpoint path the daemon takes: export, then restore into a fresh process
    /// image that holds nothing in memory.
    fn restart(node: &Node) -> Node {
        let snap = node.export_snapshot().expect("export");
        let mut fresh = testnet_node();
        assert!(fresh.restore_snapshot(snap), "the fresh node accepts the checkpoint");
        fresh
    }

    /// ⭐⭐⭐ DB-194 — THE SPENT STATE SURVIVES A RESTART **ON THE PEER**, WHICH IS THE ONLY PLACE IT
    /// COUNTS.
    ///
    /// `harness::e2e_claims` carries `restart_persistence` as `Unproven`: the Z-build (2026-09-22)
    /// deleted the pin that carried this claim to a peer and nothing replaced it. Unlike the asset
    /// classes — where writing the replacement showed the MECHANISM was never wired
    /// ([[project_db193_assets_cannot_be_created_at_all]]) — the restore path here is real, so the pin
    /// can be written and the claim re-promoted honestly.
    ///
    /// ⛔ WHY IT MUST BE THE PEER THAT RESTARTS. A producer that restarts and still remembers its own
    /// work proves nothing about the chain: it has its own blocks. The failure that loses money is a
    /// RECEIVER forgetting what it grafted — a node that comes back having lost the spent set would
    /// re-admit a nullifier the chain already settled, which is the double spend the whole lane exists
    /// to refuse. So B never produces; it only grafts A's block, then restarts.
    ///
    /// ⭐ AND THE NULLIFIER ROOT IS THE RIGHT WITNESS, not a balance readout. It is the CONSENSUS
    /// spent-state commitment (the order-free A_tip projection every node re-derives), so "B's root
    /// after the restart still equals A's" is the chain's own statement that B's spent set survived
    /// intact — not a local cache agreeing with itself.
    ///
    /// ⛔ NON-VACUITY, BOTH DIRECTIONS: a THIRD node that never saw the block must hold a DIFFERENT root
    /// (otherwise the roots are constant and this asserts nothing), and B's root must have MOVED off its
    /// pre-graft value (otherwise grafting did nothing and the restart preserved an empty state).
    #[test]
    fn a_peer_that_restarts_still_holds_the_spent_state_it_grafted() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let untouched = testnet_node(); // never sees the block — the non-vacuity control

        let root_before = node_b.nullifier_root();
        assert_eq!(
            root_before,
            untouched.nullifier_root(),
            "PRECONDITION: three fresh nodes agree on the same spent-state root"
        );

        // A produces; B GRAFTS it. B never produces, so everything it knows came off the wire.
        let (_blk, _seq) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_000, b"restart-1");

        let a_root = node_a.nullifier_root();
        let b_root = node_b.nullifier_root();
        assert_ne!(
            b_root, root_before,
            "⛔ NON-VACUITY: grafting the block must MOVE the peer's spent-state root, or the restart \
             below would be preserving nothing"
        );
        assert_eq!(
            a_root, b_root,
            "the producer and the peer agree on the spent state before any restart"
        );
        assert_ne!(
            b_root,
            untouched.nullifier_root(),
            "⛔ NON-VACUITY: a node that never saw the block must hold a DIFFERENT root — otherwise the \
             root is a constant and every assertion here is vacuous"
        );

        // ── THE RESTART. B goes through a real snapshot round trip: export, fresh process, restore.
        let b2 = restart(&node_b);

        assert_eq!(
            b2.nullifier_root(),
            b_root,
            "⛔ THE PEER FORGOT WHAT IT GRAFTED. A node that comes back having lost the spent set will \
             re-admit a nullifier the chain already settled — the double spend this lane exists to \
             refuse — and every balance denominated against it is unsafe."
        );
        assert_eq!(
            b2.nullifier_root(),
            a_root,
            "and the restarted peer still agrees with the producer, which is the chain's own statement \
             that its spent set survived intact"
        );
        assert_ne!(
            b2.nullifier_root(),
            untouched.nullifier_root(),
            "the restarted peer is still distinguishable from a node that never saw the block"
        );
    }

    /// ⛔⛔⛔ THE LIVE DEFECT, ON A PAIR. Both parties restart; both must still answer for the seed-only
    /// record, byte-identical to what they held and to each other, and their 256 leaves must fold the
    /// same on both sides of the restart.
    #[test]
    fn both_parties_still_answer_for_the_seed_only_record_after_each_resumes_from_its_snapshot() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let (_blk, seq) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_000, b"empty-1");
        let before = node_a.da_record_notes(seq).expect("held before the restart");
        let leaves_before = node_a.da_block_leaves(seq).expect("leaves before the restart");

        let a2 = restart(&node_a);
        let b2 = restart(&node_b);
        for (who, n) in [("producer", &a2), ("peer", &b2)] {
            let after = n.da_record_notes(seq);
            assert!(
                after.is_some(),
                "{who}: a resumed node must answer for a seed-only record it held — the bytes are \
                 public-derivable, so forgetting them turns a restart into a copath hole (seq {seq})"
            );
            assert_eq!(after.unwrap(), before, "{who}: regenerated bytes equal the bytes originally held");
            assert_eq!(
                n.da_block_leaves(seq).expect("leaves after the restart"),
                leaves_before,
                "{who}: its 256 leaves fold identically on both sides of the restart"
            );
        }
    }

    /// ⛔ CONTROL — NEVER FABRICATE. A node that cannot PROVE a record was seed-only must not answer with
    /// a seed-only candidate. A third node that never saw the block holds no committed root or
    /// accumulator step for it, so the honest answer stays `None` (the want/backfill machinery is the
    /// reporter). Without this, regeneration would be a way to forge an "empty" record for a block that
    /// carried money.
    #[test]
    fn a_node_that_cannot_prove_a_record_was_seed_only_does_not_fabricate_one() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let (_blk, seq) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_000, b"empty-2");
        let stranger = testnet_node();
        assert!(
            stranger.da_record_notes(seq).is_none(),
            "a node with no committed evidence for seq {seq} must not invent a seed-only record for it"
        );
    }

    /// ⛔⛔⛔ THE RESUMED NODE MUST KNOW HOW FAR ITS OWN RECORD SPACE REACHES. `restore_snapshot` refills
    /// `da_ord_mem` / `da_ord_rev_mem` per record but never rebuilt `da_ord_top` — its only writer is
    /// `da_store_ordinal` at write time — so `da_record_ordinal_top()` answered 1 after EVERY resume no
    /// matter how many records came back (MEASURED 8/8: producer ordinal_top=2, resumed ordinal_top=1).
    /// `span_closes_to_target` uses that value as its ceiling and fails closed for any span past it, so
    /// after a restart a node could no longer accept a by-id record it fetched — it re-asked forever.
    /// Both parties must resume with the ceiling they had, and agree with each other.
    ///
    /// cons: none — the ceiling is derived from the ordinals already restored (one max over the loop);
    /// nothing is persisted, nothing is walked, nothing grows.
    #[test]
    fn both_parties_resume_knowing_their_record_ordinal_top_so_span_verification_reaches_every_record() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let (_b1, s1) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_000, b"top-1");
        let (_b2, s2) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_500, b"top-2");
        let top_a = node_a.da_record_ordinal_top();
        let top_b = node_b.da_record_ordinal_top();
        // ⭐ THE CEILING COUNTS GENESIS. This literal was `2`, written before genesis occupied a record
        // ordinal of its own; the two produced blocks now fold at ordinals 1 and 2 above it (visible in
        // the run's `[record-fold] … ordinal=1` / `ordinal=2` lines), so three records exist and the
        // EXCLUSIVE ceiling is three. Two independent places in the tree state that invariant directly:
        // `fold_canonical_records`'s base-position comment — "genesis holds ordinal 0 and contributes NO
        // leaves, so a record at ordinal k occupies leaves [(k-1)·256, k·256)" — and the runtime scenario
        // verdict, which fails a party with "has no record at ordinal 0 — the genesis row was evicted".
        //
        // ⛔ THIS IS A STALE CONSTANT, NOT A WEAKENED ASSERTION. Nothing this test exists to protect is
        // relaxed: the defect it pins is a RESUME LOSING THE CEILING (measured 8/8: producer 2, resumed
        // 1), and that is checked by the two parties agreeing here, by each resumed node matching its own
        // pre-restart value below, and by both resumed parties agreeing at the end — none of which is a
        // hard-coded number. Only the setup's expected record COUNT moves, and it moves to the value the
        // fold log shows the node actually producing.
        assert_eq!(
            top_a, 3,
            "setup: genesis plus two produced records give the producer an ordinal space of three"
        );
        assert_eq!(top_b, top_a, "setup: the ingesting peer's ordinal space matches the producer's");

        let a2 = restart(&node_a);
        let b2 = restart(&node_b);
        for (who, n, top) in [("producer", &a2, top_a), ("peer", &b2, top_b)] {
            assert_eq!(
                n.da_record_ordinal_top(),
                top,
                "{who}: the resumed node's record-ordinal ceiling must equal what it had — a ceiling of 1 \
                 makes span verification refuse every record past the first, so fetched records can never \
                 be accepted after a restart"
            );
            for seq in [s1, s2] {
                let ord = n.da_record_ordinal(seq).expect("restored record keeps its ordinal");
                assert!(ord < n.da_record_ordinal_top(), "{who}: its ordinal lies under the ceiling");
            }
        }
        assert_eq!(
            a2.da_record_ordinal_top(),
            b2.da_record_ordinal_top(),
            "and the two resumed parties agree on how far the record space reaches"
        );
    }

    /// ⭐ The property the live pair needs end to end: after the restart, neither party may need a record
    /// it cannot fold — every record either party wrote or derived is still foldable on both sides.
    #[test]
    fn both_resumed_parties_still_fold_every_record_so_no_want_is_ever_registered_for_them() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let (_b1, s1) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_000, b"empty-3a");
        let (_b2, s2) = produce_and_ingest_empty_block(&mut node_a, &mut node_b, 5_500, b"empty-3b");
        let a2 = restart(&node_a);
        let b2 = restart(&node_b);
        for (who, n) in [("producer", &a2), ("peer", &b2)] {
            for seq in [s1, s2] {
                assert!(
                    n.da_block_leaves(seq).is_some(),
                    "{who}: the resumed node must still fold the leaves of record {seq}"
                );
            }
        }
        // And the two sides fold the SAME leaves for the same record — the cross-node agreement the
        // copath climb depends on.
        for seq in [s1, s2] {
            assert_eq!(a2.da_block_leaves(seq), b2.da_block_leaves(seq), "leaves agree across the pair for {seq}");
        }
    }

    /// A producer that has already produced `n` blocks, spaced at the target interval from the genesis
    /// timestamp, and the timestamp its NEXT block must carry. Shared by the restart/adopt pins below.
    fn producer_with_blocks(n: u64, tag: &str, mut peer: Option<&mut Node>) -> (Node, u64) {
        let mut node_a = testnet_node();
        let spacing = node_a.params().target_spacing_ms;
        let genesis_ts = node_a
            .dag()
            .get(&node_a.selected_tip().expect("setup: genesis tip"))
            .expect("setup: genesis header")
            .header
            .timestamp;
        let mut now = genesis_ts + spacing;
        for i in 0..n {
            let blk = node_a
                .produce(now, Hash32::hash(format!("{tag}-{i}").as_bytes()), Hash32::hash(b"miner"))
                .expect("setup: the producer produces");
            now += spacing;
            if let Some(p) = peer.as_mut() {
                assert!(matches!(p.ingest_block(blk, now), RelayOutcome::Added(_)), "setup: the peer grafts");
            }
        }
        (node_a, now)
    }

    /// The producer pools a production-shaped transaction that CARRIES a real receive (two output notes:
    /// recipient and change, the faucet's own shape) and produces the block that carries it, so the receive
    /// rides in a block and every party folds it on its live path — never an out-of-band record.
    fn produce_block_with_real_receive(node_a: &mut Node, now: u64, tag: &str, nf_seed: u8) -> Block {
        const N: usize = crate::cover::PQ_NOTE_BYTES;
        let need = node_a.mempool().required_stamp_bits();
        let nfs: Vec<Hash32> = (0..crate::cover::TX_FIXED_NULLIFIER_COUNT)
            .map(|i| Hash32::hash(&[nf_seed, i as u8]))
            .collect();
        let base = crate::node::tests::grind_tx(tag.as_bytes(), 1000, nfs, need);
        // ⭐ §BA — "PRODUCTION-SHAPED" NOW HAS TO MEAN PROVEN, NOT JUST THE RIGHT FIELDS FILLED IN.
        //
        // Hand-filled `output_notes` + `nullifiers` over a grind blob satisfy `lay_note_transition`'s
        // SHAPE check and then fail its PROVE, so the block shipped notes with no transition and every
        // peer refused them while the producer recorded them — measured here as `setup: one root with the
        // receive folded` failing on two roots that should be equal. `test_receive_tx` proves a real
        // carrier and reads the nullifier, both outputs and the cross-bind off the proof.
        let _ = N;
        let tx = Node::test_receive_tx(u64::from(nf_seed), base, need)
            .expect("the production prover states this receive");
        node_a.ingest_tx_unverified(tx).expect("the pool accepts the production-shaped receive");
        node_a
            .produce(now, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner"))
            .expect("the block that carries the receive")
    }

}

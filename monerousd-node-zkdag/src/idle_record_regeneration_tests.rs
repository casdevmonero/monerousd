// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **AN IDLE RECORD IS NEVER FETCHED AND NEVER KEPT — A NODE THAT HOLDS ITS COORDINATES REGENERATES
//! ITS BYTES, AND A NODE THAT CANNOT PROVE IT IDLE FABRICATES NOTHING.**
//!
//! An idle block (no real notes) files a record made of ONE seed note plus deterministic cover, and
//! that seed is a pure function of the record's address (`cover::public_idle_seed_note`). Nothing about
//! the record needs to be stored or moved: any node that holds the record's coordinates — its ordinal
//! row plus certified evidence for that ordinal (a ladder/run root, or its own accumulator step) —
//! regenerates the bytes on demand and folds the same 256 leaves. The seed is cover, never a receive.
//!
//! ROOT-LAYER: a record's bytes are PRODUCED in `record_note_payload_inner` from
//! `cover::public_idle_seed_note(seq)` — the ONE derivation. The regeneration lives in
//! `Node::da_record_notes`, the single reader every serve, fold, root derivation and want retirement
//! goes through, and it calls that same producer; nothing is patched at a read site, no second
//! derivation exists (the dead per-node `carried_less_idle_seed_note` arm was deleted with this).
//! MEASURED: gate 40 (2026-09-03, scratch 5SXlpu), BEFORE — after BOTH nodes of a pair restarted,
//! neither held the bytes of the idle records below ordinal ~134 (the resumed node never persists seed
//! rows, zero disk; the jumped node had adopted their rows from sidecar pages, coordinates only), so
//! every by-id want for them was unfillable from ANY peer: `[record-miss] … NEITHER key holds bytes`
//! fired ~2,900 times on one side and ~1,000 on the other (1-in-64 sampled), missing_records 9/17,
//! sidecar_gap 1233/16, both sides NOT READY at the deadline. AFTER (this tree, 2026-09-03 09:12 run):
//! da_seed_regen_tests 8/8 GREEN, orphaned_prerestart_records_tests 1/1, canonical_ordinal_after_resume
//! 4/4, an_idle_block_records_identical_bytes 1/1 — and the pins below: bytes and root identical on
//! both sides with the row bytes gone, byte wants 3 -> 1 (the real record's) on both nodes with no
//! fetch. The live claim is gate 41's step 3: both READY, gap 0, `[record-miss]` = 0.
//! MUST-STAY-GREEN: da_seed_regen_tests (both parties answer after a resume; a stranger fabricates
//! nothing), orphaned_prerestart_records_tests, canonical_ordinal_after_resume_tests,
//! an_idle_block_records_identical_bytes_on_the_producer_and_the_ingester, every record/copath/ladder
//! test, and the `drop_record_bytes_if_unreferenced` retention rule (a real receive still keeps bytes).
//!
//! Two parties in every test — `node_a` PRODUCES, `node_b` INGESTS — and every assertion is that they
//! hold, derive or refuse the SAME thing once neither holds the bytes.
//!
//! cons: none — the regeneration is f(fixed constants): one 256-leaf fold per asked record, nothing
//! persisted, nothing queued. It REMOVES a cost: the 1,153 B seed row per idle record (× 172,800
//! blocks/day = 199 MB/day) that no node has to keep on disk, hold in RAM past the span, or move over
//! Tor after a restart. The fixture writes here are two in-memory records per node of a two-node test;
//! every assertion is an indexed read plus one fixed fold.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::relay::RelayOutcome;

    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 0; // this file's subject is not the fold delay: fold at the tip, canonical order
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        let mut n = Node::with_params(g, p).expect("a testnet node builds");
        // This file's subject is an IDLE record. Since SATOSHI increment 1 a node with a provisioned reward recipient lays a
        // reward note in EVERY block it produces, so no block of such a producer is idle; these parties run without one —
        // a real configuration (no operator wallet provisioned), exactly the producer whose blocks are idle.
        n.set_reward_recipient(None);
        n
    }

    fn genesis_ts(n: &Node) -> u64 {
        n.dag().get(&n.selected_tip().expect("tip")).expect("header").header.timestamp
    }

    /// `node_a` produces one idle block, `node_b` ingests it: both hold the same seed-only record at the
    /// same ordinal.
    fn idle_pair() -> (Node, Node, u64, u64) {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let ts = genesis_ts(&node_a) + 60_000;
        // §RF-3 §14: an honest producer seeds every note-free block, so the idle record here is a producer that omits the
        // seed — still admitted by every peer (the door requires none), so its record must still regenerate.
        crate::node::PRODUCE_OMITS_SEED_NOTE_FOR_TEST.with(|c| c.set(true));
        let blk = node_a.produce(ts, Hash32::hash(b"idle-block"), Hash32::hash(b"miner"));
        crate::node::PRODUCE_OMITS_SEED_NOTE_FOR_TEST.with(|c| c.set(false));
        let blk = blk.expect("an idle block produces");
        assert!(blk.output_notes.is_empty(), "setup: the block carries no note");
        assert!(
            matches!(node_b.ingest_block(blk.clone(), ts + 1_000), RelayOutcome::Added(_)),
            "setup: the peer grafts the producer's block"
        );
        let seq = Node::da_record_id_for_block(&blk.id(), 0);
        let ord = node_a.da_record_ordinal(seq).expect("setup: the producer filed the record");
        assert_eq!(node_b.da_record_ordinal(seq), Some(ord), "setup: the peer filed it at the same ordinal");
        (node_a, node_b, seq, ord)
    }

    /// The same one-note REAL record on a node: a real receive names its commitment, and the accumulator
    /// step at its ordinal was taken over ITS root — an in-memory fixture record, never persisted.
    fn real_one_note_record(n: &mut Node, tag: &[u8]) -> u64 {
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        let cm = *Hash32::hash(tag).as_bytes();
        note[..32].copy_from_slice(&cm);
        let seq = n.record_note_payload_for(Some(Hash32::hash(tag)), 7, &note, Some(crate::cover::TEST_COVER_KEY));
        assert!(n.da_record_notes(seq).is_some(), "setup: the real record is held");
        seq
    }

    #[test]
    fn both_sides_of_a_pair_regenerate_an_idle_record_whose_bytes_are_gone_byte_identically() {
        let (mut node_a, mut node_b, seq, ord) = idle_pair();
        let before = node_a.da_record_notes(seq).expect("setup: held before the bytes go");
        let root_before = node_a.block_root_at_ordinal(ord).expect("setup: the root derives");
        assert_eq!(node_b.da_record_notes(seq).expect("setup: the peer holds it"), before);
        for (who, n) in [("producer", &mut node_a), ("ingester", &mut node_b)] {
            assert!(n.test_drop_record_bytes(seq), "{who}: setup — the bytes were held and are now gone");
            let after = n.da_record_notes(seq);
            assert!(after.is_some(), "{who}: the coordinates alone regenerate the record — no fetch");
            assert_eq!(after.unwrap(), before, "{who}: regenerated bytes are the bytes held before");
            assert_eq!(
                n.block_root_at_ordinal(ord),
                Some(root_before),
                "{who}: the regenerated record folds to the same 256-leaf root"
            );
        }
    }

    #[test]
    fn neither_party_fabricates_a_one_note_real_record_of_the_same_shape() {
        let (mut node_a, mut node_b, _seq, _ord) = idle_pair();
        let seq_a = real_one_note_record(&mut node_a, b"a real commitment");
        let seq_b = real_one_note_record(&mut node_b, b"a real commitment");
        assert_eq!(seq_a, seq_b, "setup: the same real record on both parties");
        for (who, n) in [("producer", &mut node_a), ("ingester", &mut node_b)] {
            assert!(n.test_drop_record_bytes(seq_a), "{who}: setup — the real bytes are gone");
            assert!(
                n.da_record_notes(seq_a).is_none(),
                "{who}: a real receive and an accumulator step over the real root refuse the seed — no \
                 bytes are invented"
            );
        }
    }

    #[test]
    fn byte_wants_for_a_regenerable_record_retire_on_both_parties_without_any_fetch_while_a_real_ones_stay(
    ) {
        let (mut node_a, mut node_b, seq, ord) = idle_pair();
        for (who, n) in [("producer", &mut node_a), ("ingester", &mut node_b)] {
            let seq_real = real_one_note_record(n, b"another real commitment");
            assert!(n.test_drop_record_bytes(seq));
            assert!(n.test_drop_record_bytes(seq_real));
            n.test_want_record_by_id(seq);
            n.test_want_record_by_ordinal(ord);
            n.test_want_record_by_id(seq_real);
            assert_eq!(n.test_byte_wants(), (2, 1), "{who}: setup — two by-id wants, one by-ordinal");
            n.retire_held_record_ids();
            assert_eq!(
                n.test_byte_wants(),
                (1, 0),
                "{who}: the idle record's wants (by id AND by ordinal) retire on regeneration; the real \
                 record's stays"
            );
        }
    }

    #[test]
    fn a_held_ladder_root_that_disagrees_refuses_the_regeneration_on_both_parties_and_one_that_agrees_admits_it(
    ) {
        let (mut node_a, mut node_b, seq, ord) = idle_pair();
        for (who, n) in [("producer", &mut node_a), ("ingester", &mut node_b)] {
            assert!(n.test_drop_record_bytes(seq));
            let right = n
                .block_root_at_ordinal(ord)
                .expect("regenerates while no ladder root is held");
            let mut wrong = right;
            wrong[0] ^= 1;
            n.test_plant_ladder_root(ord, wrong);
            assert!(
                n.da_record_notes(seq).is_none(),
                "{who}: a certified root this node holds that the regenerated leaves do not fold to \
                 refuses the bytes"
            );
            n.test_plant_ladder_root(ord, right);
            assert!(
                n.da_record_notes(seq).is_some(),
                "{who}: the certified root the leaves fold to admits the regeneration"
            );
        }
        assert_eq!(
            node_a.da_record_notes(seq),
            node_b.da_record_notes(seq),
            "producer and ingester regenerate the identical bytes under their certified roots"
        );
    }
}

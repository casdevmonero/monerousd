// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ DB-354 — THE CARRY FIXTURE MODELS WHAT THE CHAIN ADMITS.
//!
//! DB-354 found that the three PRODUCE-side record writers record a block's RAW `output_notes` while every graft
//! writer records what the §BA door admits (`graft_admitted_notes`). So a producer whose block carries a note its own
//! credit set cannot justify holds that note, and every peer holds the public seed. MEASURED at record
//! `seq=132108828213732244` by `rpc_http::tests::note_copath_serves_the_append_ordinal…`.
//!
//! The WRITER half landed at 07:34 on 2026-09-28 and was REVERTED at 07:58 (self-inflicted, §9.2). Fourteen
//! order-fill and settlement tests proved membership against notes their fixture (`plant_note_and_bind_for_test`,
//! amount 1 on a genesis with no open-mint allowance) staged with an inadmissible credit. Those notes existed only in
//! the producer's raw record. The writer half re-lands after every fixture that models that plant is migrated and the
//! full staging set is measured (docs/DB-354 §8).
//!
//! What stays is the FIXTURE half, pinned here. `Node::carry_notes_in_a_block_for_test` asserts that its chain admits
//! the credit that justifies the note it carries, and fails loudly otherwise, instead of silently modelling the plant.
//!
//! TWO PARTIES in every pin: `producer` builds its block through the production `produce` path, and `peer`
//! receives the whole block through `ingest_block`.
//!
//! cons: none — two nodes and one block per pin; nothing here scales with the chain.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;
    use crate::node::Node;

    fn party() -> Node {
        crate::node::tests::testnet_party_folding_at_tip()
    }

    /// A note shaped like a real sealed one: a commitment in front and a high-entropy ciphertext behind it, so a
    /// byte search cannot match by chance.
    fn sealed(front: &[u8], seed: &[u8]) -> Vec<u8> {
        let mut n = Hash32::hash(front).as_bytes().to_vec();
        let mut ctr = 0u64;
        while n.len() < crate::cover::PQ_NOTE_BYTES {
            let mut b = seed.to_vec();
            b.extend_from_slice(&ctr.to_le_bytes());
            n.extend_from_slice(Hash32::hash(&b).as_bytes());
            ctr += 1;
        }
        n.truncate(crate::cover::PQ_NOTE_BYTES);
        n
    }

    fn cm_of(note: &[u8]) -> [u8; 32] {
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[..32]);
        cm
    }

    /// ⛔ DB-354 — THE CARRY FIXTURE NO LONGER MODELS THE PLANT IN SILENCE.
    ///
    /// `Node::carry_notes_in_a_block_for_test` pairs each note with a bridge credit, and every peer refuses the note
    /// unless its chain ADMITS that credit. On a genesis with no open-mint allowance, where no bonded quorum attests
    /// the credit, the chain refuses it, and the helper used to build the block anyway. 17 tests modelled the §BA
    /// plant that way while their names claimed a payment arrives. Here the producer and its peer share such a
    /// chain, and the helper must refuse before either node holds anything.
    #[test]
    #[should_panic(expected = "FIXTURE (DB-354)")]
    fn db354_the_carry_fixture_refuses_a_chain_that_would_refuse_its_credit() {
        let mut producer = Node::new_folding_at_tip_for_test(crate::block::genesis_block()).expect("a party builds");
        let mut peer = Node::new_folding_at_tip_for_test(crate::block::genesis_block()).expect("a party builds");
        let note = sealed(b"db354-fixture-cm", b"db354-fixture-ct");
        let (blk, _) = producer.carry_notes_in_a_block_for_test(5_000, &note);
        // Unreachable when the guard holds: had the helper built the block, the peer would refuse its note.
        let _ = peer.ingest_block(blk, 9_000);
    }

    /// CALIBRATION of the guard above. On the testnet identity the same fixture carries its note to a peer, and both
    /// nodes hold one record for the block, byte for byte.
    #[test]
    fn db354_the_carry_fixture_carries_an_admitted_note_to_a_peer_on_the_testnet_identity() {
        let mut producer = party();
        let mut peer = party();
        let note = sealed(b"db354-fixture-cm", b"db354-fixture-ct");
        let (blk, rid) = producer.carry_notes_in_a_block_for_test(5_000, &note);
        let outcome = peer.ingest_block(blk.clone(), 9_000);
        assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "the peer grafts the block: {outcome:?}");
        assert!(peer.holds_record_with_cm(&cm_of(&note)), "the peer records the fixture's note");
        assert!(producer.holds_record_with_cm(&cm_of(&note)), "the producer records it too");
        assert_eq!(
            producer.da_record_notes(rid),
            peer.da_record_notes(rid),
            "one block, one record, on both nodes"
        );
    }
}

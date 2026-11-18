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

//! **A WANT MUST NAME A RECORD THE NODE CAN PLACE — DB-227 (2026-09-26), superseding the gate-32 rule.**
//!
//! GATE 32 (2026-09-03) found the `[copath-coord]` arm PRINTING "a want is registered" and registering
//! nothing; the fix filed the value into the by-ID want set. GATE I (2026-09-26, scratch
//! musd-ecocheck-2rTkuw) measured what that filed: 297 distinct ~1e17 record ADDRESSES that
//! `accept_fetched_record` had passed in the ORDINAL parameter (its `None => seq` substitution), and —
//! through `want_record_at_id` — the wallet's COVER ordinals, none of which any peer's by-id serve can
//! place (`asked 32, hold 0`). The by-id set sat at its cap, `missing_record_count` never reached 0, and
//! the restarted node was never ready. The law now: an unplaced record is refused before any
//! position-keyed read and wants nothing; a placed record with no bytes is wanted by its ADDRESS through
//! the one resolver that knows it is real. Two parties: `node_a` produces, `node_b` is handed the record
//! the way a page does.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;
    use crate::node::Node;

    /// ROOT-LAYER: `accept_fetched_record` chooses the coordinate every authority is read in, and
    /// `want_record_at_id` turns an outside value into a want — both are pinned at those doors.
    /// MEASURED: before — gate I node 1, 594 `[copath-coord] ordinal <1e17>` lines (297 distinct page
    /// records whose bytes were in hand) and `missing_by_record_id` pinned at 32 for 7 minutes.
    /// MUST-STAY-GREEN: the placed-record arm below — a real byte debt stays wanted and counted.
    #[test]
    fn db227_an_unplaced_fetched_record_wants_nothing_and_a_placed_one_is_wanted_by_its_address() {
        // Both parties fold at their tip, so a produced record is PLACED (has its ordinal row) at once —
        // the default node folds a finality depth behind its tip, which would leave `rid` unplaced on the
        // producer too and test nothing about the peer.
        let genesis = crate::node::tests::genesis_block();
        let mut node_a = Node::new_folding_at_tip_for_test(genesis.clone()).expect("node_a");
        let blk = node_a
            .produce(5000, Hash32::hash(b"cw-fr"), Hash32::hash(b"cw-mc"))
            .expect("block");
        let rid = Node::da_record_id_for_block(&blk.id(), 0);
        let bytes = node_a.da_record_notes(rid).expect("node_a holds the record");
        let ord_a = node_a.da_record_ordinal(rid).expect("node_a placed its own record");

        let mut node_b = Node::new_folding_at_tip_for_test(genesis).expect("node_b");
        assert_eq!(node_b.missing_record_count(), 0, "precondition: nothing wanted yet");

        // UNPLACED: node_b holds no ordinal row for `rid`. No position-keyed relation can judge it, so it
        // is refused — and it must want NOTHING (the pre-DB-227 door read `rid` as an ordinal and filed it).
        assert!(
            !node_b.accept_fetched_record(rid, &bytes, Some(node_a.cover_key_of(rid))),
            "a record this node cannot place cannot be verified by any relation keyed by position"
        );
        assert_eq!(
            node_b.missing_record_count(),
            0,
            "an unplaced fetched record must not become a want no peer can answer (gate I: 32 pinned)"
        );
        assert!(
            node_b.da_wanted_ids_for_test().is_empty(),
            "nothing is filed in the by-id set for an address read as an ordinal"
        );

        // PLACED: the sidecar row lands (the lane that places records on a node that did not fold them).
        // Now the record is real to node_b and its bytes are owed: wanted, by ADDRESS, and counted.
        assert!(node_b.adopt_sidecar_row(ord_a, rid), "the row files at the peer's free slot");
        node_b.want_record_at_id(rid);
        assert!(
            node_b.missing_record_count() >= 1,
            "⛔ CALIBRATION: a placed record with no bytes is a REAL debt and must stay visible"
        );
        assert!(
            node_b.wanted_record_ids().contains(&rid),
            "the debt is wanted by the record's ADDRESS — the key a peer's by-id serve can answer"
        );
    }
}

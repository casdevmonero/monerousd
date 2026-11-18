// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::fetched_record_sidecars_are_adopted_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! PINS EXISTING BEHAVIOUR (2026-09-03). While hunting gate 31's loop the page-apply loop was suspected
//! of dropping the sidecars the server puts on the wire — it does not: `apply_backfilled_notes` adopts
//! `recv_cms`/`del_cms` and folds them. These two-party tests keep that true: node_a produces and
//! serves; node_b fetches the page exactly as the server assembles it and must hold the SAME sidecars
//! and fold to the SAME root. If anyone ever removes that adoption, this is the red that catches it.
use super::*;
use super::tests::genesis_block;

fn page_entry_as_served(node: &Node, rid: u64) -> crate::protocol::LedgerRecord {
    crate::protocol::LedgerRecord::assemble(
        rid,
        (
            node.da_record_notes(rid).expect("producer holds the record"),
            node.da_load_account_targets(rid),
            node.da_tags_wire(rid),
            Vec::new(),
            node.da_letters_wire(rid),
        ),
        node.da_cover_key(rid),
    )
}

fn producer_with_credit_note(tag: &[u8]) -> (Node, u64) {
    let mut node_a = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(blake3::hash(tag).as_bytes());
    node_a.pending_credit_notes.push(note);
    let blk = node_a
        .produce(5000, Hash32::hash(&[b"fs-fr".as_slice(), tag].concat()), Hash32::hash(b"fs-mc"))
        .expect("the block that carries the credit note");
    let rid = Node::da_record_id_for_block(&blk.id(), 0);
    assert!(node_a.da_record_notes(rid).is_some(), "the producer recorded the block's notes at apply");
    (node_a, rid)
}


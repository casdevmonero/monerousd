// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::fetched_page_keying_and_deletion_sidecar_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! PINS EXISTING BEHAVIOUR (2026-09-03). In the instrumented scratch run (LhBDUT) 36 of 52 fetched
//! pages were refused ("0/N verified against roots we hold") while the peer applied 78 of 894 blocks'
//! payloads. Mis-keying the canonical id as an ordinal was suspected and is NOT the cause: a peer that
//! holds the block accepts a page entry named by its canonical id (first test). The refusals therefore
//! belong to a peer that does not yet hold the block — a throughput/ordering question, handed to the
//! transport lane with the numbers. The second test pins that a deletion sidecar, which cannot be
//! derived from notes, arrives with the page. Two parties throughout.
use super::*;
use super::tests::genesis_block;

fn served(node: &Node, rid: u64) -> crate::protocol::LedgerRecord {
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

/// ⛔⛔⛔ A PAGE ENTRY KEYED BY ITS CANONICAL ID IS ACCEPTED BY A PEER THAT HOLDS THE BLOCK. node_b has
/// ingested node_a's blocks (it holds the DAG and the ordinal index); the record is re-served by its
/// canonical id, as every page does. Refusing it is the "0/N verified" that starves the backfill.
#[test]
fn a_page_entry_named_by_canonical_id_is_accepted_by_a_peer_holding_the_block() {
    // ⭐ §BA — BOTH PARTIES ARE TESTNET PARTIES AND THE NOTE RIDES WITH ITS JUSTIFICATION. This fixture
    // pushed a bare credit note on a default-genesis pair: node_a recorded it, node_b's graft door
    // REFUSED it (nothing justified it — and on a default genesis there is no open-mint allowance to
    // admit a justifier either) and wrote the seed record for that block instead, so the two parties
    // held DIFFERENT records at the same ordinal and the page entry was refused on the "a root THIS
    // NODE FILED disagrees" branch. MEASURED 2026-09-26: `[graft-door] ⛔ §BA REFUSED a note this
    // block carries that NOTHING justifies` then `[admit] ⛔ REFUSE BridgeCredit … exceeds this chain's
    // genesis-derived open-mint allowance` on node_b — a fixture that predates §BA, not the canonical-id
    // keying this pin exists for. `carry_notes_in_a_block_for_test` is the one helper that carries a
    // note the way production does; the testnet prefix's allowance admits its object on the peer.
    let mut node_a = super::tests::testnet_party_folding_at_tip();
    let mut node_b = super::tests::testnet_party_folding_at_tip();
    let mut rid = 0u64;
    for i in 0..4u8 {
        let ts = 5_000 + i as u64 * 1_000;
        let blk = if i == 2 {
            let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            note[..32].copy_from_slice(blake3::hash(b"keyed-page-drip").as_bytes());
            let (blk, seq) = node_a.carry_notes_in_a_block_for_test(ts, &note);
            rid = seq;
            blk
        } else {
            node_a.produce(ts, Hash32::hash(&[b"kp".as_slice(), &[i]].concat()), Hash32::hash(b"m")).expect("block")
        };
        assert!(matches!(node_b.ingest_block(blk.clone(), 6_000 + i as u64 * 1_000), RelayOutcome::Added(_)));
    }
    assert_ne!(node_b.da_record_ordinal(rid), None, "the peer indexed the record's ordinal");
    assert_ne!(Some(rid), node_b.da_record_ordinal(rid), "canonical id and dense ordinal are different spaces here");
    let entry = served(&node_a, rid);
    // A peer that holds the WHOLE block holds its record (v32: the block carries the notes that apply it, and the
    // graft writes the record), so the re-served entry changes nothing — `AlreadyHeld` is the one correct exit
    // (DB-350), never a mis-keyed root lookup. MEASURED 2026-10-27 (scratchpad/night/regs5.log): this pin's old
    // `accept == true` premise read that exit as a refusal.
    assert_eq!(
        node_b.accept_fetched_record_judged(entry.rid, &entry.notes, entry.key()),
        Err(FetchRefusal::AlreadyHeld),
        "a record the peer already holds is answered as held, not re-admitted and not mis-keyed"
    );
    // THE BACKFILL SHAPE this pin exists for: the peer holds the block and its ordinal row but not the bytes (the
    // retention release, or a window block carried without its payload). The page entry, named by its canonical
    // id, must then be ACCEPTED — keying the root lookup by the canonical id refuses it ('0/N verified') and
    // starves the backfill.
    assert!(node_b.test_drop_record_bytes(rid), "the peer held the bytes before the release");
    assert_ne!(node_b.da_record_ordinal(rid), None, "the ordinal row survives the byte release");
    let verdict = node_b.accept_fetched_record_judged(entry.rid, &entry.notes, entry.key());
    assert!(
        verdict.is_ok(),
        "a correct page entry, named by its canonical id, must be ACCEPTED by a peer that holds the block but \
         not the bytes; refused as {}",
        verdict.err().map(|e| e.name()).unwrap_or("-")
    );
    assert!(node_b.da_record_held(rid), "the accepted entry is held again");
}


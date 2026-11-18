// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::targeted_record_fetch_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::genesis_block;
use super::Node;

/// ⭐⭐⭐ THE RECIPIENT'S O(1) FETCH REPLACES THE STREAM WALK.
///
/// A wallet finds its own note in ONE account-bucket lookup, which hands back the record's ORDINAL. If its
/// node lacks that record, the node must ask for THAT record — not crawl the note stream toward it.
///
/// Measured on two live peered nodes, the crawl provably never arrives: a record is 256x1153 = ~295 KB and
/// a page must fit ONE transport cell, so `[da-backfill] parsed 1 entr(ies) from a peer page (295216
/// bytes)` — one record per round-trip — while the chain adds ~2 records/second. The recipient node sat at
/// `applied 324` against `tip 6478` and gained +132 records/min against its peer's +157, falling further
/// behind every minute. Its payment is in a RECENT block, which a forward walk reaches last, if ever. That
/// is why a send settled on the payer (5.0 -> 4.0 USDm) and the recipient still showed 0.
/// RE-FIXTURED 2026-10-27 (lane funds; NEVER-PASSED since 10/05) ON THE LANE THE DESIGN SETTLED: a wallet's bucket lookup
/// hands back a record ADDRESS, and the ONE resolver (`da_record_notes`, read by `want_record_at_id`) raises the by-id byte
/// want only for an address this node PLACES — its ordinal row exists and round-trips — with no bytes held; an address it
/// cannot place raises nothing, because the record reaches every node the same way: its block, then its ordinal row (the
/// sidecar lane), then the miss arm names the byte debt. The old fixture named ordinal 4,242 on a genesis node through the
/// by-RANGE lane, which (a) the §9.6 stream bound refuses past `top + TX_REQ_FIXED_COUNT` and (b) names only ordinals whose
/// coordinate row exists — two settled doors, not a hole. So: node B holds the block as a SHELL (the DB-276b shape: placed,
/// bytes absent), the wallet names the record, the by-id want names it, a holder never asks, and the want drains when the
/// bytes arrive and never before.
#[test]
fn a_node_asks_for_the_exact_record_its_wallet_named_and_the_want_drains_when_it_arrives() {
    let mut a = super::tests::testnet_party_folding_at_tip().with_band_prover_for_test();
    let real_cm = *blake3::hash(b"targeted-fetch-real").as_bytes();
    let mut real = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    real[..32].copy_from_slice(&real_cm);
    let (blk, addr) = a.carry_notes_in_a_block_for_test(5_000, &real);
    assert!(a.da_record_held(addr), "PRECONDITION: the producer holds its own record");

    // B holds the block from its WIRE bytes (a postcard round trip: the wire shape since DB-165 carries no record), placed
    // by its fold, its record bytes owed (`payload_gap`) — the recipient whose payment was just mined by someone else,
    // before the by-id lane brought the bytes.
    let mut b = super::tests::testnet_party_folding_at_tip().with_band_prover_for_test();
    let wire: crate::block::Block = postcard::from_bytes(&postcard::to_allocvec(&blk).expect("a block serializes"))
        .expect("the wire bytes deserialize");
    let got = b.ingest_block(wire, 5_100);
    assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "PRECONDITION: B grafts the block from its wire bytes: {got:?}");
    assert!(!b.da_record_held(addr), "PRECONDITION: B does not hold the record's bytes");

    // The wallet names the record: the want names THAT record, never a stream walk toward it.
    b.want_record_at_id(addr);
    assert!(b.has_wanted_records(), "the node must record that its wallet needs this exact record");
    assert!(b.wanted_record_ids().contains(&addr), "the by-id request must name the record the wallet asked for");

    // A record already held is never requested — otherwise every wallet read would emit traffic.
    a.want_record_at_id(addr);
    assert!(!a.wanted_record_ids().contains(&addr), "a record already held must not be requested");

    // The want survives a drain pass while the bytes are still missing …
    b.clear_satisfied_wants();
    assert!(
        b.wanted_record_ids().contains(&addr),
        "still missing, so it must still be wanted — a want that clears without the record arriving would silently drop \
         the recipient's payment"
    );
    // … and DRAINS once the bytes land, so this is a transient queue and not a growing store.
    assert!(b.accept_fetched_record(addr, &blk.output_notes, blk.cover_key), "the served bytes verify against the block root B holds");
    b.clear_satisfied_wants();
    assert!(b.da_record_held(addr), "B holds the record now");
    assert!(!b.wanted_record_ids().contains(&addr), "the want drained when the record arrived");
}

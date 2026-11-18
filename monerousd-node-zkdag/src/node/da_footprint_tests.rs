// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::da_footprint_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::genesis_block;
use super::Node;

/// ⛔⛔⛔ WHAT A RUNNING NODE ACTUALLY COSTS, PER BLOCK, WITH EVERY MAP COUNTED.
///
/// user 2026-07-29: *"Operating monerousd nodes should only require a few kb."* / *"Does our DA grow with
/// time?"* — this test is the honest answer, measured rather than asserted.
///
/// The on-disk store that hit 54 MILLION inodes and filled the boot volume is deleted at source, so this
/// measures the structures that remain. It does NOT assert a few KB, because that is not true yet and a
/// test that claimed it would be the cheat this project keeps paying for. It asserts what IS true and
/// pins the number, so the fold work that follows has a baseline to beat and cannot silently regress.
///
/// TWO PARTIES: producer and verifier grow independently — a verifying node holding records it never
/// produced is the case that made the disk swarm unbounded on peers, not just producers.
#[test]
fn a_running_nodes_per_record_footprint_is_measured_and_attributed_not_assumed() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let mut verifier = Node::new(genesis_block()).unwrap();
    producer.set_decider_verifier(Box::new(super::tests::AcceptDecider));
    verifier.set_decider_verifier(Box::new(super::tests::AcceptDecider));

    let (_, _, blocks0, bytes0, _) = producer.mem_attrib();

    const N: u64 = 24;
    for i in 0..N {
        let blk = producer
            .produce(
                5_000 + i,
                crate::hash::Hash32::hash(b"f"),
                crate::hash::Hash32::hash(b"r"),
            )
            .expect("the producer mined a block");
        verifier.ingest_block(blk, 9_000);
    }

    let (_, _, blocks1, bytes1, _) = producer.mem_attrib();
    let (_, _, vblocks, vbytes, _) = verifier.mem_attrib();

    // THE MEASUREMENT — printed so the number is auditable, not just a pass/fail.
    eprintln!(
        "[footprint] producer entries {blocks0} -> {blocks1}, bytes {bytes0} -> {bytes1}"
    );
    eprintln!("[footprint] verifier entries {vblocks}, bytes {vbytes}");
    for (name, n, b) in producer.da_entry_census_named() {
        if n > 0 {
            eprintln!("[footprint]   producer {name}: {n} entries, {b} bytes");
        }
    }

    // The census must SEE the growth. Before this, `mem_attrib` read one map of twelve, so a node whose
    // per-record state was climbing could report a flat number — a growth test built on it would pass
    // while the node grew without bound.
    assert!(
        blocks1 > blocks0,
        "the census must observe per-record entries appearing as blocks are produced ({blocks0} -> \
         {blocks1}); a census that cannot see growth makes every footprint test vacuous"
    );
    assert!(
        bytes1 > bytes0,
        "the census must observe bytes growing too ({bytes0} -> {bytes1} over {N} blocks)"
    );

    // A VERIFYING node accumulates the same per-record state as the producer — this is why the disk swarm
    // was unbounded on peers, and it is the axis the recursive fold has to remove next.
    assert!(
        vblocks > 0,
        "a verifying node that never produced a block still accumulates per-record state ({vblocks} \
         entries) — the growth axis is not producer-only"
    );

    // Attribution must name a real map, or a future failure cannot say WHICH structure grew.
    let named = producer.da_entry_census_named();
    // 12 after `da_nf_node_mem` — the sparse COPATH INDEX — was finally listed. It had been absent from
    // this census entirely, so the one map that a settle path writes was the one map no footprint run
    // could attribute. Listing it immediately measured what it costs: mirroring block tags into it ran to
    // 1,502,330 entries / 60,093,200 bytes at TWENTY-FOUR blocks (~2.5 MB per block) against ~278 KB for
    // every other map combined. That mirror is reverted; the number is why.
    //
    // This count is asserted so ADDING a per-record map without listing it fails HERE rather than silently
    // hiding a growth axis. It is a floor to drive DOWN, never up: every one of these 12 is a per-item
    // store, and the standing direction is to replace them with proofs, not to keep them measured.
    // 12 = the 8 that were listed + the 4 that were NOT (`unspent_path_nodes`, `da_leafstart_mem`,
    // `da_del_mem`, `da_recv_mem`). This number is not a magic constant to be nudged when it fails: it
    // is the count of per-record maps on `Node`, and a mismatch means a map was added without being
    // attributed. If you add one, census it and raise this — never lower it to match.
    //
    // 33 (2026-09-05): the census was made TOTAL — the 2026-09-04 no-growth audit measured 5.7 GB of
    // RSS against 21.8 KB attributed because the census covered 8 of the struct's collection fields,
    // so 24 could grow unseen. The 21 rows added and now pinned: `da_ladder_mem` (span blobs, bounded
    // by referenced spans), `da_nf_mem` + `mined_tx_nfs` (per-record/per-tx nullifier copies — a
    // growth axis the census must SEE so the proofs-not-storage direction can be judged),
    // `note_target_addr` (one per note), (`nf_fold_pending` retired 2026-09-30), the four want sets (`wanted_ordinals`,
    // `wanted_buckets`, `wanted_record_ids`, `wanted_cms` — transient queues, drained on arrival),
    // `payload_gap`, `uns_recent_roots` (fixed 64-ring), `pending_tags`, `account_buckets` +
    // `pending_bucket` (per-account filing), `folded_floor`, `note_clues` + `note_clue_fifo`,
    // `bond_locked` + `bond_height`, `evicted_by_block`, `wrapped_opening_seals`. Raised per this
    // pin's own rule: census it and raise this — never lower it to match.
    //
    // 34 (2026-09-06): `dag_record_key_index` — the O(1) record-address inversion index that
    // replaced `block_for_record_addr`'s full-DAG scan. It lives on the DAG (bounded by the same
    // prune horizon as the block store it mirrors) and is censused the day it was added, per this
    // pin's own rule. RED actually run before listing it: this assertion at 34 against the
    // pre-listing census failed with `left: 33`.
    // 34 → 33 (2026-09-11): `da_nf_mem` and `da_nacc_rev_mem` DELETED (D-41: the three-keyed
    // per-block nullifier shard and the spend-gate sweep's acc→seq index); `uns_deleted_while_owing`
    // ADDED (D-43c: deletions applied while a record is still owed — bounded by ONE sync window and
    // cleared when nothing is owed, censused so a window that fails to close is attributable).
    // 33 → 28 (Z1, 2026-09-22): the DELETION MODEL and every per-record map it owned are gone at
    // source — `da_recv_mem` and `da_del_mem` (the receive/deletion sidecars), `unspent_path_nodes`
    // (256 stored path levels per note, ~16 KB each: the largest growth axis this census ever
    // measured), `uns_recent_roots` (the fixed 64-ring that let a late deletion still verify) and
    // `uns_deleted_while_owing` (deletions applied while a record was still owed). A spend is now
    // authorised by its NULLIFIER, which is O(1) state, so none of these have a replacement to
    // census. This is a LOWERING because the maps were DELETED, not because they were dropped from
    // the list — the rule this pin states ("census it and raise this — never lower it to match")
    // guards against the second, and the file's own 34 → 33 entry is the precedent for the first.
    // 28 → 27 (DB-350, 2026-09-28): `wanted_cms` DELETED with the by-commitment record ask it fed — the lane
    // named a wallet's note to a peer and could land nothing the by-id lane does not. A LOWERING because the
    // map was DELETED at source, never dropped from the list (the 34 → 33 and 33 → 28 precedents above).
    // 27 → 28 (db333-r, 7208ed5 2026-10-24, raised here by lane stable 2026-11-01): `dsync_covered` — the blocks an adopted
    // state already counts that this node does not hold yet (bounded by the bundle's `covered` list, 48 B an entry, drained
    // at the ingest door). Its commit added it to the census and left this number at 27, so this pin read 28 ≠ 27 from
    // that day; the census was right and the number is raised per this pin's own rule. (Diffed: 7208ed5 adds exactly
    // that one name to `da_entry_census_named`.)
    assert_eq!(
        named.len(),
        28,
        "every per-record map must be listed in the census"
    );
    assert!(
        named.iter().any(|(_, n, _)| *n > 0),
        "at least one named map must hold the entries the total reports — a total with no attributable \
         source means the census is summing nothing"
    );
}

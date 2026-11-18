// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::bucket_position_is_canonical_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{genesis_block, grind_tx};
use super::Node;
use crate::hash::Hash32;

/// ⭐⭐⭐ THE POSITION FILED IN AN ACCOUNT BUCKET MUST NAME THE SAME BLOCK ON EVERY NODE.
///
/// TEST-ARCHITECTURE-REVIEWED: this reads the FILED value back (`account_bucket_positions_for_test`) and
/// resolves it on the OTHER node. Three earlier attempts asserted on block-derived addresses that were
/// already correct, so the `AccountEntry::at(..)` argument never entered the assertion and each passed
/// with the defect deliberately restored. Reading the filed value is the only thing that can catch a bug
/// in what is filed. The tamper case is: file `append_ordinal` instead of `ident`.
///
/// This is the exact path a recipient's wallet takes — read the bucket, get a position, ask its own node
/// to resolve it. Two mining nodes each write their OWN blocks before their peer's, so a local write
/// counter names a different block on each. Measured live: 7 of 7 sampled ordinals disagreed across two
/// peered nodes, including ordinal 100.
#[test]
fn a_filed_bucket_position_resolves_to_the_same_block_on_a_second_mining_node() {
    let mut a = Node::new(genesis_block()).unwrap();
    let mut b = Node::new(genesis_block()).unwrap();

    // THE PAYMENT PATH, EXACTLY AS THE FAUCET DRIVES IT: register the note's account target, then record
    // the note payload that carries it. `record_note_payload` drains pending targets while assembling the
    // block's 256 slots, so the target must be registered FIRST — the same order `/faucet/drip` uses.
    //
    // No `produce` here on purpose: producing records a DIFFERENT payload (the block's own selected txs),
    // which drains the pending target against commitments this test never registered. That is why an
    // earlier version filed nothing and tripped its own anti-vacuity assertion.
    // ⛔⛔⛔ GIVE EACH NODE A REAL DA STORE. `da_dir()` derives from `persist_path`, which is None for a
    // bare `Node::new(..)` — so a record written by such a node lands nowhere and `da_block_leaves` resolves
    // NOTHING, whatever coordinate the bucket filed. That is why this assertion failed identically for
    // `ident` AND `addr`: the lookup could not have succeeded either way, and the failure looked like a
    // naming defect for several rounds. A production node always has a DA store; a test without one is
    // measuring a configuration that cannot exist.
    let tmp = std::env::temp_dir().join(format!("musd-bp-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    a.enable_persist(tmp.join("a.node")).expect("the persist door");
    b.enable_persist(tmp.join("b.node")).expect("the persist door");

    let bucket = crate::account_da::bucket_id(b"bp-recipient-account");
    // ⛔ A REAL ML-KEM-768 ENCAPSULATION KEY, NEVER A 32-BYTE PLACEHOLDER. `seal_entry_to` encapsulates to
    // this key, and an ML-KEM-768 public key is 1,184 bytes — a 32-byte stand-in makes every seal FAIL, so
    // the filing loop restored each target to pending and wrote nothing. The test then tripped its own
    // anti-vacuity assertion (`no bucket position was filed`) while looking like a protocol defect.
    // MEASURED: `[bucket-file] SEAL FAILED for an account entry (ek_len=32)` on every one of the 12 loops.
    // A fixture that cannot succeed tests nothing; use the real keygen the production path uses.
    let (recipient_ek, _recipient_dk) = crate::pqkem::keypair();

    // ⛔ BOTH NODES MUST APPLY THE SAME BLOCK. This gave node A `bp-cm-a-{i}` and node B `bp-cm-b-{i}` at
    // the same heights, so the two nodes held DIFFERENT notes at the "same" position and their block roots
    // could never match — the assertion failed on the test's own premise, not on a protocol defect.
    // MEASURED: `6 of 6 FILED bucket positions name a different block on node B`, unchanged whether the
    // entry filed `ident` or `addr`, because the leaves themselves differed.
    //
    // Two mining nodes on ONE chain record the SAME block. That is the property under test: the same
    // block, applied on both, must yield the same filed position resolving to the same root.
    // ⛔ NAME THE BLOCK, AS PRODUCE AND GRAFT DO. The bare `record_note_payload` derives its address from
    // HEIGHT, and a height cannot name a block in a DAG — so two nodes derive different addresses for the
    // same credit and the filed position resolves to nothing on the peer. That is the real defect, and it
    // is exactly why this test failed identically whether the entry filed `ident` or `addr`.
    //
    // The production paths thread a block id (`record_note_payload_for(Some(block.id()), ..)` on produce,
    // `Some(grafting_block_id)` on graft), so this test must too — otherwise it measures a path no block
    // ever takes. Both nodes apply the SAME block id, which is what two miners on one chain do.
    for i in 0..6u32 {
        let cm = *Hash32::hash(format!("bp-cm-shared-{i}").as_bytes()).as_bytes();
        let block_id = Hash32::hash(format!("bp-block-{i}").as_bytes());
        // ⛔ CARRY THE WHOLE BLOCK PAYLOAD, AS A REAL BLOCK DOES. A short payload makes each node fill the
        // remaining cover slots from ITS OWN DA secret, so the 256 leaves — and therefore the block root —
        // differ per node even for an identical real note. That is by design (the fill must be
        // unpredictable to an observer) and it is why this assertion failed even once the address was
        // block-derived and identical on both sides.
        //
        // A produced block ships its fill inside `output_notes`, so every grafting node derives the same
        // leaves. Replicate that here: one identical payload, applied on both nodes.
        let mut payload = vec![0u8; 1153 * crate::cover::BLOCK_FIXED_NOTE_COUNT as usize];
        payload[..32].copy_from_slice(&cm);
        for (slot, chunk) in payload.chunks_mut(1153).enumerate().skip(1) {
            let filler = Hash32::hash(format!("bp-fill-{i}-{slot}").as_bytes());
            chunk[..32].copy_from_slice(filler.as_bytes());
        }
        for node in [&mut a, &mut b] {
            node.record_account_target(cm, bucket, recipient_ek.clone(), None);
            node.record_note_payload_for(Some(block_id), 5_000 + i as u64, &payload, Some(crate::cover::TEST_COVER_KEY));
        }
    }
    // Every position node A filed, resolved on node B. These are block ROOTS, so equality means "the same
    // block", which is what the wallet actually needs.
    let filed = a.account_bucket_positions_for_test(&_recipient_dk);
    let mut checked = 0usize;
    let mut diverged = Vec::new();
    for (_bucket, seq) in &filed {
        let ra = a.da_note_copath_in_block(*seq, 0).map(|(_, _, root)| root);
        let rb = b.da_note_copath_in_block(*seq, 0).map(|(_, _, root)| root);
        checked += 1;
        // ⛔ SEPARATE "A CANNOT RESOLVE ITS OWN FILED POSITION" FROM "THE TWO NODES DISAGREE". They need
        // opposite fixes — the first is a coordinate mismatch inside ONE node (the bucket files a value its
        // own resolver does not accept), the second is a genuine cross-node divergence. Reported as one
        // condition, this assertion sent me through three fixture corrections without telling me which
        // failure I was looking at.
        if ra.is_none() {
            // Isolate WHICH step fails: is the record absent at that address, or present but unable to
            // regenerate its 256 leaves? Those are different defects and the combined message hid it.
            let notes_here = a.da_record_notes(*seq).map(|n| n.len());
            let leaves_here = a.da_block_leaves(*seq).map(|l| l.len());
            let ord_here = a.da_record_ordinal(*seq);
            // The addresses the store ACTUALLY holds. Comparing them against the filed value names the
            // mismatch outright instead of leaving it to be guessed one coordinate at a time.
            let stored: Vec<u64> = a
                .da_recorded_notes()
                .iter()
                .map(|(addr, _)| *addr)
                .collect();
            panic!(
                "node A cannot resolve the position it FILED ITSELF (seq {seq}). \
                 da_record_notes={notes_here:?} da_block_leaves={leaves_here:?} da_record_ordinal={ord_here:?}. \
                 The store holds {} record address(es): {:?}. A wallet hands the filed value straight back \
                 to its own node, so the note is unspendable on the very node that indexed it.",
                stored.len(),
                &stored[..stored.len().min(8)]
            );
        }
        if ra != rb {
            diverged.push(*seq);
        }
    }

    // A run that filed nothing would satisfy every assertion below without testing anything.
    assert!(
        checked > 0,
        "no bucket position was filed — the test would pass vacuously"
    );
    assert!(
        diverged.is_empty(),
        "{} of {checked} FILED bucket positions name a different block on node B (first: {:?}). A \
         recipient's wallet reads its position from this bucket and asks its OWN node to resolve it — so \
         the payment settles on chain and stays invisible to its owner. The filed value must be the \
         block-derived canonical address, never this node's local write counter.",
        diverged.len(), diverged.first()
    );
}

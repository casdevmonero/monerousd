// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `cover::tests` — the tests of `cover` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `cover` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`cover::tests::…`), and `use super::*` reaches `cover`'s items through the node's re-export.

// the imports of `cover` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::hash::Hash32;
#[allow(unused_imports)]
use crate::mempool::PqTx;
#[allow(unused_imports)]
use crate::pqkem;

/// ⭐⭐⭐ THE ASSEMBLY MUST PRESERVE EVERY REAL NOTE, BYTE FOR BYTE **AND IN ORDER**.
///
/// Order is not cosmetic — it is the coordinate the whole send path stands on. A note's POSITION in the
/// payload IS its offset from the record's first leaf in `spend_frontier`, so a reorder (the retired
/// permutation) or a dropped/split note makes the money arrive at a leaf its owner computes wrongly:
/// the witness folds to a root the chain never held, and the spend is refused with the funds plainly
/// visible. Live symptom this pins: the payment reached the recipient's node and both parties scanned
/// 0 owned while seal→detect passed in isolation.
#[test]
fn the_assembly_preserves_every_real_note_byte_for_byte_and_in_order() {
    const N: usize = PQ_NOTE_BYTES;
    // Two reals, exactly as a transfer produces (recipient + change), each distinctly patterned.
    let mut reals = vec![0u8; 2 * N];
    for (i, b) in reals.iter_mut().enumerate() {
        *b = ((i % 251) + 1) as u8;
    }
    let first: Vec<u8> = reals[..N].to_vec();
    let second: Vec<u8> = reals[N..].to_vec();

    for seq in [0u64, 1, 98, 207, 4095] {
        let out = assemble_fixed_note_payload(&reals, seq, &TEST_COVER_KEY);
        assert_eq!(
            out.len(),
            BLOCK_FIXED_NOTE_COUNT * N,
            "seq {seq}: COVER IS REQUIRED (reinstated 2026-08-16) — every block wears the fixed shape, \
             so an idle block is indistinguishable from a busy one. The reals still lead the payload; \
             only the cover tail differs."
        );
        let slots: Vec<&[u8]> = out.chunks_exact(N).collect();
        assert_eq!(
            slots[0], first.as_slice(),
            "seq {seq}: real note 0 must land at POSITION 0 — position is the note's leaf offset, so a \
             reorder mis-indexes every later leaf and makes the note unspendable"
        );
        assert_eq!(
            slots[1], second.as_slice(),
            "seq {seq}: real note 1 must land at POSITION 1 — losing or moving one silently drops either \
             the payment or the sender's change"
        );
    }
}
use super::*;
use std::collections::HashSet;

#[test]
fn cover_note_is_well_shaped_and_fresh() {
    let a = cover_note().expect("cover note");
    let b = cover_note().expect("cover note");
    assert_eq!(a.len(), PQ_NOTE_BYTES);
    assert_ne!(a, b, "each cover note is fresh (independent randomness)");
    assert_ne!(
        &a[CT_OFF..CT_OFF + CT_LEN],
        &b[CT_OFF..CT_OFF + CT_LEN],
        "a fresh REAL ML-KEM ciphertext each time"
    );
}

/// The det assembler must be a PURE function of the reals — record == serve, leaf for leaf, on every node.
#[test]
fn det_assembly_is_pure_at_a_fixed_seq_and_wears_the_cover_shape() {
    let mut reals = vec![0x11u8; PQ_NOTE_BYTES];
    reals.extend_from_slice(&vec![0x22u8; PQ_NOTE_BYTES]);

    // PURITY AT A FIXED seq is the record==serve contract and still holds exactly.
    let a = assemble_fixed_note_payload(&reals, 7, &TEST_COVER_KEY);
    let b = assemble_fixed_note_payload(&reals, 7, &TEST_COVER_KEY);
    assert_eq!(
        a, b,
        "det assembler is a pure function of (reals, seq) — record==serve"
    );

    // The payload is the FIXED shape, with the reals LEADING it. (The old assertion `a == reals` was
    // the retirement's "no fill" contract; the cover was reinstated 2026-08-16.)
    assert_eq!(
        a.len(),
        BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES,
        "every block wears the fixed cover shape"
    );
    assert_eq!(
        &a[..2 * PQ_NOTE_BYTES],
        &reals[..],
        "real notes lead the payload, byte-for-byte, in order"
    );

    // ⚠️ THE PAYLOAD *DOES* VARY WITH seq NOW, AND THAT IS THE POINT. The per-block cover secret folds
    // `seq`, so two blocks holding identical reals do NOT share a cover tail — otherwise an observer
    // could correlate blocks by matching cover bytes. The old assertion demanded the opposite.
    let at8 = assemble_fixed_note_payload(&reals, 8, &TEST_COVER_KEY);
    assert_ne!(
        at8, a,
        "identical reals at a DIFFERENT seq must not reproduce the same cover — shared cover bytes \
         across blocks would be a correlation handle"
    );
    assert_eq!(
        &at8[..2 * PQ_NOTE_BYTES],
        &reals[..],
        "…while the reals still lead, unchanged"
    );

    // An idle block wears the FULL shape too — the whole point of the reinstatement.
    assert_eq!(
        assemble_fixed_note_payload(&[], 99, &TEST_COVER_KEY).len(),
        BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES,
        "an idle block regenerates as the FULL cover shape, never as nothing"
    );
}

/// §20.2 — the per-record secret is a function of the record's COVER KEY (the producer's draw), never of a public
/// index and never of the reals: two keys at one address give two secrets and two covers; the reals do not enter at
/// all (a secret derived from them was recomputable by anyone who could guess them, `C(256, k)` tries).
#[test]
fn the_per_record_secret_is_keyed_on_the_cover_key_not_on_the_reals_or_a_public_index() {
    let seq = 42u64;
    let (k1, k2): (CoverKey, CoverKey) = ([0xAA; 32], [0xBB; 32]);
    let s1 = record_cover_secret(seq, &k1);
    let s2 = record_cover_secret(seq, &k2);
    assert_ne!(s1, s2, "different cover keys ⇒ different per-record secret (NOT f(seq) alone)");
    assert_ne!(cover_note_det(&s1, 5), cover_note_det(&s2, 5), "anything derived from the secret follows the key");
    assert_ne!(record_cover_secret(43, &k1), s1, "and the address enters too");
    let reals_a = vec![0xAAu8; PQ_NOTE_BYTES];
    let reals_b = vec![0xBBu8; PQ_NOTE_BYTES];
    assert_eq!(
        assemble_fixed_note_payload(&reals_a, seq, &k1)[PQ_NOTE_BYTES + 32..],
        assemble_fixed_note_payload(&reals_b, seq, &k1)[PQ_NOTE_BYTES + 32..],
        "the cover BODIES are the key's alone — the reals never enter the secret"
    );
    assert_ne!(fresh_cover_key(), fresh_cover_key(), "a fresh key is fresh");
    assert_ne!(idle_cover_key(1), idle_cover_key(2), "the one public key is per address");
}

/// An empty block now records an EMPTY payload on every node — there is no node-local seed note.
///
/// This asserted the opposite until today. A locally-minted seed note was a PRF of THIS NODE'S private DA
/// secret written into a record every node must agree on byte-for-byte: two nodes each recorded "one
/// note", each its own, so they derived different leaves, different block roots and different
/// `spend_frontier_root`s — a wallet's witness verified only on the node it happened to ask. That was a
/// cross-node send failure by construction.
#[test]
fn an_idle_block_records_the_full_cover_shape_identically_on_every_node() {
    let seq = 5u64;
    let pa = assemble_fixed_note_payload(&[], seq, &TEST_COVER_KEY);
    let pb = assemble_fixed_note_payload(&[], seq, &TEST_COVER_KEY);
    assert_eq!(
        pa.len(),
        BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES,
        "an IDLE block wears the FULL fixed shape (reinstated 2026-08-16) — recording nothing is what \
         made an empty block observably empty, and made `da_record_notes` answer None for it forever"
    );
    assert_eq!(pa, pb, "two independent derivations agree byte-for-byte, which is what lets two nodes converge");

    // ⭐⭐⭐ TWO REAL PARTIES — the name says "identically on EVERY NODE", so prove it with NODES.
    // Calling the pure fn twice in one process proves determinism, not convergence: it cannot catch a
    // cover keyed on anything node-local (a private DA secret, an append counter), which is exactly the
    // cross-node divergence this cover has produced before. `test_standard::every_chain_state_test_has_
    // two_parties` flagged this test for that reason and it was right to.
    {
        use crate::node::{tests::genesis_block, Node};
        let mut a = Node::new(genesis_block()).unwrap();
        let mut b = Node::new(genesis_block()).unwrap();
        // The SAME idle block (no real notes) recorded independently on each node.
        let addr_a = a.record_note_payload_for(None, seq, &[], None);
        let addr_b = b.record_note_payload_for(None, seq, &[], None);
        assert_eq!(
            addr_a, addr_b,
            "an idle block lands at the SAME canonical address on both nodes"
        );

        let la = a
            .da_block_leaves(addr_a)
            .expect("node A regenerates the idle block's shape");
        let lb = b
            .da_block_leaves(addr_b)
            .expect("node B regenerates it from its own state");
        assert_eq!(
            la.len(),
            BLOCK_FIXED_NOTE_COUNT,
            "an idle block serves the FULL fixed shape on a real node, not just in the pure fn"
        );
        assert_eq!(
            la, lb,
            "two INDEPENDENT nodes must derive byte-identical leaves for one idle block — if they do \
             not, the cover is keyed on something node-local and the two have silently forked"
        );
    }

    // The seed-note primitive still yields fresh high-entropy notes for the callers that legitimately mint
    // one (never the record path) — a regression to a deterministic value here would be a real leak.
    let a = fresh_seed_note();
    let b = fresh_seed_note();
    assert_eq!(
        a.len(),
        PQ_NOTE_BYTES,
        "seed note is a well-shaped 1153-byte note"
    );
    assert_ne!(
        a, b,
        "each seed note is fresh high-entropy (unique per call)"
    );
}

#[test]
fn cover_txs_are_unique_valueless_and_id_bound() {
    let mut ids = HashSet::new();
    for _ in 0..8 {
        let tx = cover_tx(4).expect("cover tx");
        assert!(
            tx.nullifiers.is_empty(),
            "cover tx spends nothing (value 0)"
        );
        assert_eq!(tx.id, PqTx::content_id(&tx.blob), "id binds the body");
        assert!(
            tx.stamp_work() >= 4,
            "cover tx carries a real anti-spam stamp (same gate as a real tx)"
        );
        assert!(
            ids.insert(tx.id),
            "cover tx ids are unique (fresh randomness)"
        );
    }
}

#[test]
fn cover_padding_tops_every_block_up_to_the_constant_and_never_over() {
    // REINSTATED 2026-08-16. The retired version of this test asserted the exact opposite ("no block is
    // topped up") and passed because `pad_to_fixed_shape` short-circuited with `return Vec::new()` over
    // an intact fill loop. That is why `tx_ids.len()` still tracked real activity: an observer could
    // count a block's real payments off the tx list even once the NOTE layer was covered.
    assert_eq!(
        pad_to_fixed_shape(0, 0).len(),
        BLOCK_FIXED_TX_COUNT,
        "an IDLE block must still present the full constant tx shape — otherwise emptiness is visible"
    );
    assert_eq!(
        pad_to_fixed_shape(BLOCK_FIXED_TX_COUNT / 2, 0).len(),
        BLOCK_FIXED_TX_COUNT - BLOCK_FIXED_TX_COUNT / 2,
        "a partial block is topped up to exactly the constant, never past it"
    );
    // NO-HALTS: consensus CAPS the count and never DEMANDS cover, so an over-full block adds nothing
    // rather than being rejected. That half of the retired test was always correct and is kept.
    assert!(
        pad_to_fixed_shape(BLOCK_FIXED_TX_COUNT + 5, 0).is_empty(),
        "an over-full block adds nothing — cover is a cap, never a requirement (no-halts)"
    );
}

/// ⭐ THE PAYLOAD MEMO IS EXACT: for the same `(real_notes, seq)` it returns the fill's own bytes, a repeat is served by
/// the memo, and a one-bit change of a real note or a different `seq` is the fill of THOSE inputs (a memo keyed by
/// less than the whole input — the seq alone, a prefix — fails the last two).
#[test]
fn the_payload_memo_returns_the_fills_bytes_for_exactly_the_inputs_asked() {
    let mut reals = fresh_seed_note().to_vec();
    reals.extend_from_slice(&fresh_seed_note());
    let a = assemble_fixed_note_payload(&reals, 41, &TEST_COVER_KEY);
    assert_eq!(a, assemble_fixed_note_payload_computed(&reals, 41, &TEST_COVER_KEY), "a first assembly is the fill's own bytes");
    let ld = |k: usize| payload_memo::COUNTS[k].load(std::sync::atomic::Ordering::Relaxed);
    let (l0, m0) = (ld(0), ld(1));
    assert_eq!(assemble_fixed_note_payload(&reals, 41, &TEST_COVER_KEY), a, "a repeat is the same bytes");
    assert!(ld(0) - l0 > ld(1) - m0, "the repeat was served by the memo");
    assert_eq!(
        assemble_fixed_note_payload(&reals, 42, &TEST_COVER_KEY),
        assemble_fixed_note_payload_computed(&reals, 42, &TEST_COVER_KEY),
        "another seq is the fill of that seq"
    );
    reals[700] ^= 1;
    let b = assemble_fixed_note_payload(&reals, 41, &TEST_COVER_KEY);
    assert_ne!(b, a, "a one-bit change of a real note is another payload");
    assert_eq!(b, assemble_fixed_note_payload_computed(&reals, 41, &TEST_COVER_KEY), "and it is the fill of the changed note");
}

/// ⭐ THE COVER LANES STAMP UNDER THE ASKING PROCESS'S NETWORK. A simulated daemon runs on its own network
/// (`params::set_thread_network_for_test`); `pad_to_fixed_shape` mints on helper threads, and each cover's anti-spam
/// stamp hashes the network id. Every cover it returns must clear the stamp bar AS READ BY THE ASKING THREAD — the
/// mempool's admission. A lane that stamped under the default network would clear it ~1/64 of the time at 6 bits,
/// and the template's `accept` would silently drop the rest (a thin block). Also: all covers are distinct (each its own
/// fresh note) and the count is exact.
#[test]
fn the_cover_lanes_stamp_under_the_asking_processs_network() {
    crate::params::set_thread_network_for_test(b"cover-lanes-sim-net");
    let bits = 6;
    let covers = pad_to_fixed_shape(0, bits);
    assert_eq!(covers.len(), BLOCK_FIXED_TX_COUNT, "an idle template is topped up to the constant");
    let short = covers.iter().filter(|c| c.stamp_work() < bits).count();
    assert_eq!(short, 0, "⛔ {short} cover(s) were stamped under another network than the asking process's");
    let ids: std::collections::HashSet<_> = covers.iter().map(|c| c.id).collect();
    assert_eq!(ids.len(), covers.len(), "every cover is its own fresh note");
}

#[test]
fn block_tx_cap_rejects_only_over_cap() {
    assert!(within_block_tx_cap(0)); // empty block valid (no-halts)
    assert!(within_block_tx_cap(BLOCK_FIXED_TX_COUNT)); // exactly full valid
    assert!(!within_block_tx_cap(BLOCK_FIXED_TX_COUNT + 1)); // over cap rejected (fail-closed)
}

/// ⛔⛔⛔ THE NULLIFIER-SIDE 256 COVER IS REQUIRED. This test asserted the OPPOSITE until 2026-08-17.
///
/// It was written for the 2026-08-10 retirement and asserted "one real spend ⇒ a one-element tag set",
/// i.e. that a block's tag vector LENGTH equals its real spend count. The user reinstated the cover on
/// 2026-08-16 ("a privacy necessity"), which makes that assertion a live volume leak with a green test
/// guarding it. The retirement's own argument — "the note count already reveals output volume, so
/// padding the input side hides nothing" — expired when the NOTE-side cover came back.
///
/// `block_nullifier_set` is GONE rather than fixed: `nullifier_wire_fill` already was the constant-shape
/// block tag set, and keeping both meant two definitions of "what a block contains" — the exact defect
/// family that made cross-node sends fail.
#[test]
fn a_blocks_tag_set_is_the_constant_cover_shape_whatever_it_settles() {
    let secret = [7u8; 32];
    let one = [[1u8; 32]];
    let five = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];

    // CONSTANT SHAPE: 1 real and 5 reals produce the SAME length, so the vector is not a volume gauge.
    assert_eq!(
        nullifier_wire_fill(&one, &secret).len(),
        BLOCK_FIXED_NULLIFIER_COUNT,
        "a 1-spend block must still ship the fixed cover shape"
    );
    assert_eq!(
        nullifier_wire_fill(&five, &secret).len(),
        nullifier_wire_fill(&one, &secret).len(),
        "tag-vector LENGTH must not track the real spend count — that is per-block volume metadata"
    );

    // NEVER DROP A REAL SPEND: every real tag survives the fill, in order.
    let filled = nullifier_wire_fill(&five, &secret);
    assert_eq!(
        &filled[..5],
        &five[..],
        "the reals lead the vector unchanged"
    );

    // DETERMINISTIC in (reals, secret): every node derives the byte-identical vector, so there is never
    // a second definition of the block's contents.
    assert_eq!(
        nullifier_wire_fill(&five, &secret),
        nullifier_wire_fill(&five, &secret),
        "pure function of (reals, secret)"
    );

    // SECRET-SEEDED, not a public index function: a different secret yields a different cover, so the
    // fill cannot be recomputed and stripped by an observer who lacks the block's confidential payload.
    assert_ne!(
        nullifier_wire_fill(&one, &secret),
        nullifier_wire_fill(&one, &[8u8; 32]),
        "the cover must depend on the SECRET — a public-index cover is readable by any observer"
    );
}

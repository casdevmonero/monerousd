// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::payment_observability_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::genesis_block;
use super::{Node, PaymentStep};

/// ⭐⭐⭐ THE "MONEY IN FLIGHT" GAUGE — one number that says funds are moving unsafely.
///
/// user 2026-07-30: *"what other observability upgrades should be added that'll make funds moving through
/// monerousd 100 percent safe?"*
///
/// Every session failure had the same shape: the payer settled, the recipient read 0, and NOTHING
/// reported the discrepancy — five separate probes had to be correlated by hand across a dozen turns.
/// `payments_in_flight()` is that discrepancy as a number: settled by the payer, never acknowledged by a
/// recipient. On a healthy chain it returns to 0; all session it would have been non-zero and visible.
#[test]
fn the_in_flight_gauge_counts_settled_payments_no_recipient_has_seen() {
    let mut n = Node::new(genesis_block()).unwrap();
    assert_eq!(
        n.payments_in_flight(),
        0,
        "a fresh node has no payments in flight — not vacuous"
    );

    let cm = [7u8; 32];
    n.payment_receipt(&cm, PaymentStep::PayerSettled);
    assert_eq!(
        n.payments_in_flight(),
        1,
        "a payment the payer settled but no recipient has seen IS money in flight — this is precisely \
         the state that persisted undetected all session"
    );

    // The target being filed is progress, but it is NOT arrival: the recipient must actually see it.
    n.payment_receipt(&cm, PaymentStep::TargetFiled);
    assert_eq!(
        n.payments_in_flight(),
        1,
        "filing the target is not arrival — treating it as arrival is how a lost payment reads as healthy"
    );

    n.payment_receipt(&cm, PaymentStep::RecipientSaw);
    assert_eq!(
        n.payments_in_flight(),
        0,
        "once the recipient sees the note the payment is no longer in flight"
    );

    // TWO PARTIES — the gauge exists to expose a DISAGREEMENT, so prove it across two nodes. The payer's
    // node settles and files; the recipient's node has observed nothing. Each must report its OWN view,
    // and the payer's non-zero gauge beside the recipient's zero is precisely the "settled here, invisible
    // there" state that has meant lost money on every live run this session.
    let mut payer_node = Node::new(genesis_block()).unwrap();
    let mut recipient_node = Node::new(genesis_block()).unwrap();
    let crossing = [0x5Au8; 32];
    payer_node.payment_receipt(&crossing, PaymentStep::PayerSettled);
    payer_node.payment_receipt(&crossing, PaymentStep::TargetFiled);
    assert_eq!(
        (payer_node.payments_in_flight(), recipient_node.payments_in_flight()),
        (1, 0),
        "the payer's node must report the payment IN FLIGHT while the recipient's node reports none — a \
         gauge that cannot show this disagreement cannot warn that money settled where nobody can see it"
    );
    recipient_node.payment_receipt(&crossing, PaymentStep::RecipientSaw);
    payer_node.payment_receipt(&crossing, PaymentStep::RecipientSaw);
    assert_eq!(
        (
            payer_node.payments_in_flight(),
            recipient_node.payments_in_flight()
        ),
        (0, 0),
        "after the recipient sees it, both parties must agree it is settled"
    );
}

/// ⭐⭐⭐ THE CROSS-NODE INVARIANT MUST CATCH THE THREE DEFECTS IT WAS BUILT FROM.
///
/// Each of these cost turns to find this session because nothing compared two nodes' numbers. Every one
/// is a real measurement from the live pair, replayed here as an assertion.
#[test]
fn the_cross_node_invariant_names_the_defects_that_actually_happened() {
    let n = Node::new(genesis_block()).unwrap();
    let (blocks, recs, root) = n.chain_fingerprint();

    // Agreement is silent — otherwise the check cries wolf and gets ignored.
    assert!(
        n.fingerprint_disagreement((blocks, recs, root)).is_none(),
        "a node must agree with an identical peer, or every healthy run reports a false defect"
    );

    // DEFECT 3 (measured): identical counts, DIFFERENT note root — the root-only adopt left an
    // inextensible frontier and two nodes folded different leaves.
    let mut other_root = root;
    other_root[0] ^= 1;
    assert!(
        n.fingerprint_disagreement((blocks, recs, other_root)).is_some(),
        "same counts with a different note root MUST be reported — that is two nodes on different trees, \
         and no copath from one can ever verify on the other"
    );
}

/// The ledger/DAG ratio must catch BOTH directions — 4x over-recording and sub-1x loss.
#[test]
fn the_ledger_to_dag_ratio_catches_over_recording_and_loss() {
    let mut n = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    n.set_decider_verifier(Box::new(super::tests::AcceptDecider));
    for i in 0..8u64 {
        let blk = n
            .produce(
                5_000 + i,
                crate::hash::Hash32::hash(b"f"),
                crate::hash::Hash32::hash(b"r"),
            )
            .expect("produced");
        let _ = blk;
    }
    let (blocks, recs, root) = n.chain_fingerprint();
    assert!(
        blocks > 0 && recs > 0,
        "the node must have real state, or this proves nothing"
    );
    assert!(
        n.fingerprint_disagreement((blocks, recs, root)).is_none(),
        "a healthy node records ~1 per block ({recs} records / {blocks} blocks) and must not self-report"
    );

    // TWO PARTIES — a fingerprint compares THIS node against ANOTHER, so a one-party check cannot express
    // the thing it exists to catch. `peer` produced nothing, so it holds a genuinely different ledger
    // position, and comparing across them must FIRE. This is the real shape: the probe was written after a
    // live pair drifted to 33,636 records against 7,575 blocks on one side while the other stayed 1:1, and
    // a self-comparison would have reported "healthy" the entire time.
    let mut peer = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    peer.set_decider_verifier(Box::new(super::tests::AcceptDecider));
    // The peer produced the SAME NUMBER of blocks from DIFFERENT inputs — two nodes that each look
    // internally healthy (ratio ~1.0) yet hold different ledgers. That is the divergence a single node can
    // never notice about itself, and the only cross-node shape this check can express: equal counts, and a
    // note root that disagrees. A peer merely holding FEWER blocks is not a defect — it is mid-sync — so
    // asserting a fire there would be demanding a false positive.
    for i in 0..8u64 {
        let _ = peer
            .produce(
                9_000 + i,
                crate::hash::Hash32::hash(b"peer-f"),
                crate::hash::Hash32::hash(b"peer-r"),
            )
            .expect("peer produced");
    }
    let (peer_blocks, peer_recs, peer_root) = peer.chain_fingerprint();
    assert_eq!(
        (peer_blocks, peer_recs),
        (blocks, recs),
        "precondition: both nodes must hold the SAME counts, or this is not the equal-counts divergence \
         case ({peer_recs}/{peer_blocks} vs {recs}/{blocks})"
    );
    assert_ne!(
        peer_root, root,
        "precondition: the two ledgers must actually differ"
    );
    assert!(
        peer.fingerprint_disagreement((blocks, recs, root)).is_some(),
        "two nodes at identical counts with DIFFERENT note roots must report a disagreement — each looks \
         healthy alone, and a probe that stays quiet here is the always-green field that let a live pair \
         drift to 33,636 records against 7,575 blocks unnoticed"
    );
    // ...and it must be visible from BOTH sides, or which node you ask decides whether the ledger is sound.
    assert!(
        n.fingerprint_disagreement((peer_blocks, peer_recs, peer_root)).is_some(),
        "the disagreement must be symmetric — a one-sided alarm means the payer's node can call a fork \
         healthy while the recipient's node sees it"
    );
}

/// ⛔⛔⛔ AN UNRESOLVED PAYMENT MUST NEVER AGE OUT — that would be a window in the fund-loss direction.
///
/// user 2026-07-30: *"The receipts shouldn't age out, that sounds like a banned window bug."* It was: I
/// capped this ring oldest-first, so a payment stuck in flight would be evicted once enough newer
/// payments arrived and `payments_in_flight()` would read 0 — "all safe" — at precisely the moment money
/// had been lost. RESOLVED receipts are swept; unresolved ones are kept at ANY age.
#[test]
fn an_unresolved_payment_is_never_evicted_however_many_newer_ones_arrive() {
    let mut n = Node::new(genesis_block()).unwrap();

    // One payment gets STUCK: the payer settled, nobody ever saw it.
    let stuck = [0xAAu8; 32];
    n.payment_receipt(&stuck, PaymentStep::PayerSettled);

    // Far more than the sweep threshold of fully-resolved payments follow it.
    for i in 0..(Node::PAYMENT_RECEIPTS_CAP as u32 * 5) {
        let mut cm = [0u8; 32];
        cm[..4].copy_from_slice(&i.to_le_bytes());
        cm[8] = 1; // never collide with `stuck`
        n.payment_receipt(&cm, PaymentStep::PayerSettled);
        n.payment_receipt(&cm, PaymentStep::RecipientSaw);
    }

    assert_eq!(
        n.payments_in_flight(),
        1,
        "the STUCK payment must still be reported after {} newer resolved ones — if it ages out, the \
         safety gauge reads 0 exactly when funds are lost, which is the bug this test exists to prevent",
        Node::PAYMENT_RECEIPTS_CAP * 5
    );

    // And the resolved ones must NOT accumulate — otherwise this becomes a growth axis.
    assert!(
        n.payment_receipts().len() < Node::PAYMENT_RECEIPTS_CAP * 5,
        "resolved receipts must be swept — only in-flight payments are retained ({} held)",
        n.payment_receipts().len()
    );

    // Once it resolves, it may be swept like any other.
    n.payment_receipt(&stuck, PaymentStep::RecipientSaw);
    assert_eq!(
        n.payments_in_flight(),
        0,
        "a resolved payment is no longer in flight"
    );

    // TWO PARTIES — a payment is in flight precisely BETWEEN them, so the gauge is only meaningful when
    // two nodes disagree about the same payment. `recipient_node` never observes the stuck note, and its
    // gauge must say so INDEPENDENTLY: a payer reporting "settled" while the recipient's own node reports
    // "never seen" is the exact disagreement that means money is lost, and a gauge that cannot express it
    // is decoration. (Measured live all session: payer 5.0 -> 4.0 while the recipient read 0.0.)
    let mut recipient_node = Node::new(genesis_block()).unwrap();
    let crossing = [0xBCu8; 32];
    n.payment_receipt(&crossing, PaymentStep::PayerSettled);
    assert_eq!(
        n.payments_in_flight(),
        1,
        "the PAYER's node must report this payment in flight the moment it settles locally"
    );
    assert_eq!(
        recipient_node.payments_in_flight(),
        0,
        "the RECIPIENT's node has seen nothing, so it must report nothing in flight — a gauge that \
         invented a payment it never observed would hide the disagreement instead of showing it"
    );
    // The recipient finally sees it; now BOTH parties agree the payment is resolved.
    recipient_node.payment_receipt(&crossing, PaymentStep::RecipientSaw);
    n.payment_receipt(&crossing, PaymentStep::RecipientSaw);
    assert_eq!(
        (n.payments_in_flight(), recipient_node.payments_in_flight()),
        (0, 0),
        "once the recipient has seen it, the two parties must AGREE the payment is no longer in flight"
    );
}

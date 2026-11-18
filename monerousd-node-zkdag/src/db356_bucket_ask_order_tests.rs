// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ DB-356 — THE ACCOUNT-BUCKET ASK'S SLOTS CARRY NO ORDER.
//!
//! `Node::wanted_buckets_padded` built the `BucketReq` as the real wants FIRST and the secret-seeded decoys after them,
//! so a peer reading one ask knew the leading slots were the real ones (READ in code; the privacy census filed the
//! surface `Ordering::Reveals`). The set is now one canonical ascending set, so a slot's position is a function of the
//! id's value alone — the shape DB-350 gave the by-id ask.
//!
//! NOT closed here: a hash decoy names no account, so a peer holding a real bucket's entries still tells it from a
//! decoy by existence (the census's Linkage axis). DB-273 (C) deletes buckets, this ask and its route.
//!
//! cons: one sort of TX_REQ_FIXED_COUNT × 32 B per ask; 0 B on the wire, 0 B stored.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::node::Node;

    /// RED on the pre-DB-356 order (real wants first, decoys after): the highest real want sat in a leading slot and
    /// the set was not ascending. GREEN only when the whole padded set is one strictly ascending set.
    #[test]
    fn db356_the_bucket_ask_is_one_ascending_set_so_no_slot_says_which_want_is_real() {
        // TWO-PARTY-REVIEWED: the claim is about the bytes ONE node puts on the wire; a peer reads exactly those bytes,
        // and the serving arm answers per bucket id, never by position (node_runtime `WireMsg::BucketReq`).
        let mut n = Node::new_folding_at_tip_for_test(crate::block::genesis_block()).expect("a node builds");
        let low = [0x00u8; 32];
        let mut mid = [0u8; 32];
        mid[0] = 0x80;
        let high = [0xffu8; 32];
        for b in [high, low, mid] {
            n.want_account_bucket(b);
        }
        let set = n.wanted_buckets_padded();
        assert_eq!(set.len(), crate::protocol::TX_REQ_FIXED_COUNT, "calibration: the ask is padded to its constant width");
        for b in [low, mid, high] {
            assert!(set.contains(&b), "calibration: every real want rides the ask");
        }
        assert!(
            set.windows(2).all(|w| w[0] < w[1]),
            "⛔ DB-356: the padded ask is not one strictly ascending set — slot order still carries which want is real"
        );
        assert_eq!(set.first(), Some(&low), "the lowest id leads, whatever it is");
        assert_eq!(set.last(), Some(&high), "⛔ DB-356: the highest REAL want must sit in the last slot, not a leading one");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::bucket_fetch_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::genesis_block;
use super::Node;
use crate::hash::Hash32;

/// ⭐⭐⭐ THE OTHER HALF OF THE RECIPIENT'S O(1) PATH.
///
/// A wallet finds its note through its ACCOUNT BUCKET, which hands back the record's ordinal; the
/// targeted record fetch then pulls that one record. But the bucket is DA-resident too — a node that
/// never recorded the payment holds no entries, so the wallet learns nothing, never names an ordinal, and
/// the record fetch never fires. That is exactly why settles were INTERMITTENT: five cross-node sends
/// settled and the sixth did not, with the payer's node holding the bucket and the recipient's not.
///
/// A node must therefore be able to go and GET a bucket it holds nothing for.
#[test]
fn a_node_with_an_empty_bucket_asks_for_it_and_adopts_what_a_peer_serves() {
    let mut holder = Node::new(genesis_block()).unwrap();
    let mut asker = Node::new(genesis_block()).unwrap();
    let bucket = *Hash32::hash(b"bucket-fetch-account").as_bytes();
    let entry = vec![7u8; 96];

    // The holder has the bucket; the asker does not.
    holder.adopt_account_bucket(bucket, vec![entry.clone()]);
    assert!(
        !holder.account_bucket_entries(&bucket).is_empty(),
        "holder must hold it"
    );
    assert!(
        asker.account_bucket_entries(&bucket).is_empty(),
        "asker must start empty"
    );

    // The asker records the want and emits a CONSTANT-width request.
    asker.want_account_bucket(bucket);
    assert!(
        asker.has_wanted_buckets(0),
        "an empty bucket a wallet asked for must be wanted"
    );
    let req = asker.wanted_buckets_padded();
    assert_eq!(
        req.len(),
        crate::protocol::TX_REQ_FIXED_COUNT,
        "a bucket id names an ACCOUNT — the request must be constant width, or its size leaks how many \
         accounts this node is looking for"
    );
    assert!(req.contains(&bucket), "the real want must be in the set");
    // ...and the padding must be DECOYS, not repeats of the real id, or the real one is trivially spotted.
    let distinct: std::collections::BTreeSet<_> = req.iter().collect();
    assert!(
        distinct.len() > 1,
        "the cover set must contain distinct decoys, not the real id repeated"
    );

    // A peer answers from what it holds; the asker adopts and can now serve the wallet.
    let served = holder.account_bucket_entries(&bucket);
    assert!(
        !served.is_empty(),
        "the peer must answer for a bucket it holds"
    );
    asker.adopt_account_bucket(bucket, served);
    assert!(
        !asker.account_bucket_entries(&bucket).is_empty(),
        "after adopting, the asker must be able to answer its wallet — otherwise the wallet never learns \
         its note's ordinal and the payment stays invisible to the recipient"
    );
    assert!(
        !asker.has_wanted_buckets(0),
        "the want must DRAIN once satisfied, not accumulate"
    );

    // Not trivially true: a bucket nobody holds stays empty and stays wanted.
    let unknown = *Hash32::hash(b"bucket-nobody-has").as_bytes();
    asker.want_account_bucket(unknown);
    asker.adopt_account_bucket(unknown, holder.account_bucket_entries(&unknown));
    assert!(
        asker.has_wanted_buckets(10_000),
        "an unanswered want must persist (re-ask due), never silently clear"
    );
}

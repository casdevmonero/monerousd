// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `account_da::tests` — the tests of `account_da` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `account_da` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`account_da::tests::…`), and `use super::*` reaches `account_da`'s items through the node's re-export.

// the imports of `account_da` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::fixed::FixedBytes;
#[allow(unused_imports)]
use crate::hash::Hash32;

use super::*;

/// FRESH CSPRNG entropy via the crate's own idiom — both halves of a throwaway ML-KEM-768 keypair are
/// CSPRNG-minted, so hashing them yields uniform bytes with no extra dependency. This is exactly how the
/// node mints its own DA secret. A test must never run on a fixed identity: a hard-coded value would make
/// these properties hold for one arbitrary key rather than for keys in general.
fn fresh32(domain: &[u8]) -> [u8; 32] {
    let (ek, dk) = crate::pqkem::keypair();
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/account-da/test-entropy/v1");
    h.update(domain);
    h.update(&ek);
    h.update(&dk);
    let out = *h.finalize().as_bytes();
    assert!(
        out.iter().any(|&b| b != 0),
        "CSPRNG entropy came back all-zero — refuse to test on it"
    );
    out
}

fn fresh_nonce(domain: &[u8]) -> [u8; NONCE_BYTES] {
    let s = fresh32(domain);
    let n: [u8; NONCE_BYTES] = s[..NONCE_BYTES]
        .try_into()
        .expect("32 covers the nonce width");
    assert!(
        n.iter().any(|&b| b != 0),
        "a nonce came back all-zero — refuse to seal with it"
    );
    n
}

fn entry(base: &[u8; 32], i: u8) -> AccountEntry {
    let mut h = blake3::Hasher::new_keyed(base);
    h.update(&[i]);
    AccountEntry::at(*h.finalize().as_bytes(), 1000 + i as u64, i)
}

#[test]
fn two_nodes_that_apply_the_same_writes_in_different_orders_commit_the_same_root() {
    // Nodes DO apply in different orders: the producer folds a note as it mines it, a peer folds the same
    // note when it arrives by backfill or by adopting a tip. An order-dependent fold therefore makes two
    // nodes holding identical state commit different roots, which turns the header commitment into noise
    // — measured live before this fix, `d323753f…` on the producer against `78e10db3…` on its peer.
    let base = fresh32(b"cms");
    let writes: Vec<([u8; 32], [u8; 32])> = (0..6u8)
        .map(|i| (bucket_id(&[i]), entry(&base, i).note_cm))
        .collect();

    let fwd = writes
        .iter()
        .fold(Hash32::ZERO, |a, (b, c)| fold_account_acc(a, b, c));
    let rev = writes
        .iter()
        .rev()
        .fold(Hash32::ZERO, |a, (b, c)| fold_account_acc(a, b, c));
    assert_eq!(
        fwd, rev,
        "the accumulator must commit the SET of writes, not the order they arrived in"
    );

    // An interleaving, as a backfill would produce.
    let mut shuffled = writes.clone();
    shuffled.swap(0, 4);
    shuffled.swap(1, 3);
    let mixed = shuffled
        .iter()
        .fold(Hash32::ZERO, |a, (b, c)| fold_account_acc(a, b, c));
    assert_eq!(fwd, mixed, "any arrival order must reach the same root");

    // It must still be a real commitment: a DIFFERENT set of writes must not collide with this one.
    let missing = writes[..5]
        .iter()
        .fold(Hash32::ZERO, |a, (b, c)| fold_account_acc(a, b, c));
    assert_ne!(fwd, missing, "dropping a write must change the root");
    let swapped_owner = {
        let mut w = writes.clone();
        w[2].0 = bucket_id(b"somebody-else");
        w.iter()
            .fold(Hash32::ZERO, |a, (b, c)| fold_account_acc(a, b, c))
    };
    assert_ne!(
        fwd, swapped_owner,
        "filing a note under a different owner must change the root"
    );
}

#[test]
fn a_full_bucket_spills_to_the_next_link_and_never_drops_a_note() {
    // CAPS AND WINDOWS ARE CHEATS. The first version evicted the oldest entry when a bucket filled, which
    // reads like tidy bounded state and is actually fund loss: the wallet still owns that note, and once
    // the linear sweep is deleted nothing can find it again. A bucket keeps its constant width by SPILLING
    // into the next link, so what grows is only what the account genuinely holds.
    let base = fresh32(b"cms");
    let b0 = bucket_id(b"acct");
    let b1 = next_bucket(&b0);
    assert_ne!(b0, b1, "the chain advances to a distinct bucket");
    assert_eq!(
        b1,
        next_bucket(&b0),
        "the wallet re-derives the same chain deterministically"
    );
    assert_ne!(
        next_bucket(&b1),
        b0,
        "the chain does not loop back on itself"
    );

    // TWO PARTIES, AND THE REAL APPEND. This used to re-implement the spill against a local HashMap, so
    // it proved that a hand-written copy of the loop kept every note — not that the NODE does, and not
    // that a peer agrees. Those are the two things the owner's money actually depends on: the production
    // path must keep the note, and a second node must reach the identical chain from the replicated
    // entries, or the note is findable on exactly one machine.
    let (owner_ek, owner_dk) = crate::pqkem::keypair();
    let mut producer = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
    let mut verifier = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();

    let total = BUCKET_CAPACITY * 3 + 5; // deliberately far past one bucket
    let mut sealed_stream: Vec<Vec<u8>> = Vec::with_capacity(total);
    for i in 0..total {
        let e = entry(&base, (i % 251) as u8);
        let sealed =
            seal_entry_to(&owner_ek, &e).expect("the payer seals to the owner's public key");
        sealed_stream.push(sealed.clone());
        producer.account_bucket_append(b0, sealed);
    }
    // The verifier replicates the same sealed entries, in the same order the stream carries them.
    for sealed in &sealed_stream {
        verifier.account_bucket_append(b0, sealed.clone());
    }

    // What the OWNER can actually find, walking the chain from its own seed-derived id — on each node
    // independently. Nothing but the served blobs and the owner's scan key is used.
    let walk = |n: &crate::node::Node| -> Vec<AccountEntry> {
        let mut found = Vec::new();
        let mut at = b0;
        loop {
            let blob = n.account_bucket_blob(&at);
            let opened: Vec<AccountEntry> = blob
                .chunks(sealed_entry_bytes())
                .filter_map(|c| open_entry(&owner_dk, c))
                .collect();
            let n_here = opened.len();
            found.extend(opened);
            if n_here < BUCKET_CAPACITY {
                return found; // a link that is not full ends the chain
            }
            at = next_bucket(&at);
        }
    };
    let on_producer = walk(&producer);
    let on_verifier = walk(&verifier);

    assert_eq!(
        on_producer.len(),
        total,
        "EVERY note kept its position on the producer — {total} written, {} found",
        on_producer.len()
    );
    assert_eq!(
        on_producer, on_verifier,
        "the owner must find the SAME notes on a node that only REPLICATED them — a note findable on one \
         machine is a note the other machine cannot let its owner spend"
    );
    // The spill was genuinely exercised: the first link is full and the chain extended past it.
    assert_eq!(
        producer
            .account_bucket_blob(&b0)
            .chunks(sealed_entry_bytes())
            .filter_map(|c| open_entry(&owner_dk, c))
            .count(),
        BUCKET_CAPACITY,
        "the first link filled"
    );
    assert!(
        producer
            .account_bucket_blob(&next_bucket(&b1))
            .chunks(sealed_entry_bytes())
            .any(|c| open_entry(&owner_dk, c).is_some()),
        "the chain extended to a third link rather than overwriting the first"
    );
}

#[test]
fn a_reused_address_leaks_nothing_because_every_bucket_is_the_same_size() {
    // THE reuse property. An account address may be handed to a thousand payers and every one of them can
    // compute `bucket_id` — unavoidable, since the recipient must derive it from its seed alone or a
    // restore could find nothing. What must NOT follow is that any of them learn something. A
    // stream-shaped DA leaks here by construction (how many notes, when they arrived); a constant-size
    // sealed bucket leaks nothing, no matter how many times the address is used.
    let seed = fresh32(b"owner");
    let base = fresh32(b"cms");
    let nonce = fresh_nonce(b"n");
    let empty = seal_bucket(&seed, &nonce, &[]);
    let one = seal_bucket(&seed, &nonce, &[entry(&base, 1)]);
    let full = seal_bucket(
        &seed,
        &nonce,
        &(0..BUCKET_CAPACITY as u8)
            .map(|i| entry(&base, i))
            .collect::<Vec<_>>(),
    );

    assert_eq!(
        empty.len(),
        BUCKET_BYTES,
        "an EMPTY account is still a full-size bucket"
    );
    assert_eq!(one.len(), BUCKET_BYTES);
    assert_eq!(
        full.len(),
        BUCKET_BYTES,
        "a FULL account is the same size as an empty one"
    );
    assert_eq!(
        empty.len(),
        full.len(),
        "occupancy must never be readable from the length"
    );

    // Same size must not mean same bytes, or equality becomes its own oracle.
    assert_ne!(empty, full);
}

#[test]
fn only_the_owner_can_read_a_bucket_even_knowing_exactly_where_it_is() {
    // Property 3: knowing WHERE to look must not be knowing WHAT is there. That is what lets the bucket
    // id be derived from a published account tag without the derivation being a privacy hole.
    let owner = fresh32(b"owner");
    let stranger = fresh32(b"stranger");
    let base = fresh32(b"cms");
    let entries = vec![entry(&base, 1), entry(&base, 2), entry(&base, 3)];
    let sealed = seal_bucket(
        &owner,
        &bucket_nonce(&fresh32(b"da"), &bucket_id(b"acct"), 0),
        &entries,
    );

    let got = open_bucket(&owner, &sealed).expect("owner opens its own bucket");
    assert_eq!(
        got, entries,
        "the owner recovers exactly its notes' positions"
    );

    // A stranger holding both the id and the blob recovers nothing that matches.
    let theirs = open_bucket(&stranger, &sealed)
        .expect("a wrong key must not error — that would be an oracle");
    assert_ne!(
        theirs, entries,
        "a stranger must not recover the owner's entries"
    );
    assert!(
        theirs.iter().all(|x| !entries.contains(x)),
        "not one entry may survive decryption under a foreign key"
    );
}

#[test]
fn two_writes_of_identical_content_are_not_byte_identical() {
    // Without a per-write nonce an observer diffing successive fetches sees "changed" vs "unchanged" and
    // recovers exactly the payment timing the sealing exists to hide.
    let seed = fresh32(b"owner");
    let base = fresh32(b"cms");
    let b = bucket_id(b"acct");
    let da = fresh32(b"da");
    let first = seal_bucket(&seed, &bucket_nonce(&da, &b, 0), &[entry(&base, 1)]);
    let again = seal_bucket(&seed, &bucket_nonce(&da, &b, 1), &[entry(&base, 1)]);
    assert_ne!(
        first, again,
        "re-sealing identical content must not reproduce identical bytes"
    );
    assert_eq!(
        open_bucket(&seed, &first).unwrap(),
        open_bucket(&seed, &again).unwrap(),
        "...while still opening to the same entries"
    );
}

#[test]
fn distinct_accounts_land_in_distinct_buckets_and_a_restore_reads_exactly_one() {
    // The Ethereum property: a restore is ONE lookup at a seed-derived address, so its cost does not move
    // when the chain grows. This pins the addressing that makes that possible.
    let a = bucket_id(b"account-a");
    let b = bucket_id(b"account-b");
    assert_ne!(a, b, "two accounts must not share a bucket");
    assert_eq!(
        a,
        bucket_id(b"account-a"),
        "a bucket id is stable — a wallet re-derives it from its seed"
    );
}

#[test]
fn an_unused_bucket_serves_exactly_like_a_full_one() {
    // What an observer sees is the SERVE, so that is what must be invariant. If an unused bucket came
    // back short — or empty — then merely fetching an address's bucket would answer "has this person
    // ever been paid", which is the question reuse-safety exists to refuse.
    let da = fresh32(b"da");
    let (ek, dk) = crate::pqkem::keypair();
    let base = fresh32(b"cms");
    let mine = entry(&base, 3);
    let sealed = seal_entry_to(&ek, &mine).expect("write");

    let unused = serve_bucket(&[], &da, &bucket_id(b"never-paid"));
    let used = serve_bucket(&[sealed.clone()], &da, &bucket_id(b"paid-once"));
    let full = serve_bucket(
        &vec![sealed.clone(); BUCKET_CAPACITY],
        &da,
        &bucket_id(b"busy"),
    );

    let want = BUCKET_CAPACITY * sealed_entry_bytes();
    assert_eq!(
        unused.len(),
        want,
        "an unused bucket serves the FULL constant width"
    );
    assert_eq!(used.len(), want);
    assert_eq!(
        full.len(),
        want,
        "a full bucket serves no more than an unused one"
    );

    // The owner still finds its entry inside the cover, at a constant decapsulation cost.
    let w = sealed_entry_bytes();
    let found: Vec<AccountEntry> = used.chunks(w).filter_map(|c| open_entry(&dk, c)).collect();
    assert_eq!(
        found,
        vec![mine],
        "the owner recovers exactly its own entry out of the cover"
    );

    // ...and nothing is recoverable from a bucket that only ever held cover.
    assert!(
        unused
            .chunks(w)
            .filter_map(|c| open_entry(&dk, c))
            .next()
            .is_none(),
        "cover must never open as a real entry"
    );
}

#[test]
fn anyone_holding_the_address_can_write_the_bucket_and_only_the_owner_can_read_it() {
    // The asymmetry the whole account-indexed shape depends on, and the reason reuse is safe.
    //
    // A node has to write a recipient's bucket when it records a credit, but must never hold that
    // recipient's secret. A KEM splits the capability exactly where it needs splitting: the address
    // carries the PUBLIC `ek`, so every payer — a thousand of them, reusing the same address forever —
    // can WRITE, and not one can READ. Reading needs `dk`, which never leaves the wallet.
    let (ek, dk) = crate::pqkem::keypair();
    let (_other_ek, other_dk) = crate::pqkem::keypair();
    let base = fresh32(b"cms");
    let mine = entry(&base, 7);

    let sealed =
        seal_entry_to(&ek, &mine).expect("a payer holding the address can always write");
    let got = open_entry(&dk, &sealed).expect("the owner opens its own entry");
    assert_eq!(
        got, mine,
        "the owner recovers the exact note position written for it"
    );

    // The decisive one: holding the address (hence `ek`) grants no read.
    assert!(
        open_entry(&other_dk, &sealed).is_none(),
        "a different wallet must not open an entry written to someone else's address"
    );

    // Two writes of the SAME entry differ, so an observer diffing a bucket learns nothing from equality.
    let again = seal_entry_to(&ek, &mine).expect("write again");
    assert_ne!(
        sealed, again,
        "a fresh encapsulation per write — no repeated ciphertext"
    );
    assert_eq!(
        open_entry(&dk, &again).unwrap(),
        mine,
        "...both still open to the same entry"
    );

    // Every sealed entry is the same width, so an entry never reveals which kind it is.
    assert_eq!(
        sealed.len(),
        again.len(),
        "sealed entries are a constant width"
    );
}

#[test]
fn a_block_rewrites_the_same_number_of_buckets_whether_it_paid_anyone_or_not() {
    // The write-side twin of the constant bucket size. Sealing hides WHAT changed; only a constant write
    // count hides THAT something changed. Anyone holding an address knows its bucket_id, so if a block
    // touched only real recipients they could watch that id and read off payment timing — recovering by
    // observation exactly the metadata the encryption removed.
    let da = fresh32(b"da");
    let idle = plan_bucket_writes(&[], &da, 100, BUCKET_WRITES_PER_BLOCK);
    let one = plan_bucket_writes(&[bucket_id(b"alice")], &da, 100, BUCKET_WRITES_PER_BLOCK);
    let busy: Vec<[u8; 32]> = (0..40u8).map(|i| bucket_id(&[i])).collect();
    let heavy = plan_bucket_writes(&busy, &da, 100, BUCKET_WRITES_PER_BLOCK);

    assert_eq!(
        idle.len(),
        BUCKET_WRITES_PER_BLOCK,
        "an IDLE block still rewrites the full cover width"
    );
    assert_eq!(one.len(), BUCKET_WRITES_PER_BLOCK);
    assert_eq!(
        heavy.len(),
        BUCKET_WRITES_PER_BLOCK,
        "a BUSY block rewrites no more than an idle one"
    );

    // Every real recipient is genuinely in the write set — cover must never displace a real payment.
    assert!(
        one.contains(&bucket_id(b"alice")),
        "the real recipient's bucket must actually be written"
    );
    for b in &busy {
        assert!(
            heavy.contains(b),
            "every real recipient must be written, not crowded out by cover"
        );
    }

    // Sorted, so position never encodes which were real.
    assert!(
        heavy.windows(2).all(|w| w[0] < w[1]),
        "writes go out sorted, reals not first"
    );
}

#[test]
fn cover_writes_are_secret_seeded_so_they_cannot_be_recomputed_and_subtracted() {
    // If cover were a public function of the height, an observer could regenerate the cover set, remove
    // it from the block's writes, and be left holding exactly the real recipients — the whole scheme
    // reduced to a directory of who got paid.
    let ours = fresh32(b"da-a");
    let theirs = fresh32(b"da-b");
    let a = plan_bucket_writes(&[bucket_id(b"alice")], &ours, 100, 32);
    let b = plan_bucket_writes(&[bucket_id(b"alice")], &theirs, 100, 32);
    assert_ne!(
        a, b,
        "cover must depend on the node's SECRET, never on the height alone"
    );

    // ...and it must still move between blocks under the same secret, or the cover set becomes a fixed
    // backdrop that an observer learns once and subtracts forever.
    let later = plan_bucket_writes(&[bucket_id(b"alice")], &ours, 101, 32);
    assert_ne!(a, later, "the cover set must not repeat block to block");
}

#[test]
fn an_over_full_bucket_never_widens_the_wire_shape() {
    // A shape constant must hold under pressure, or a heavy account becomes identifiable by its size.
    let seed = fresh32(b"owner");
    let base = fresh32(b"cms");
    let too_many: Vec<AccountEntry> = (0..(BUCKET_CAPACITY as u8 + 9))
        .map(|i| entry(&base, i))
        .collect();
    let sealed = seal_bucket(&seed, &fresh_nonce(b"n"), &too_many);
    assert_eq!(
        sealed.len(),
        BUCKET_BYTES,
        "overflow must not widen the bucket"
    );
    assert_eq!(
        open_bucket(&seed, &sealed).unwrap().len(),
        BUCKET_CAPACITY,
        "it holds capacity — the caller must roll over to a fresh bucket rather than silently drop notes"
    );
}

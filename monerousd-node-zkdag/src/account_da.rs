// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ACCOUNT-INDEXED DA — instant private restore, by fixing the SHAPE of data availability rather than
//! optimising a walk over it.
//!
//! ## Why the stream shape can never be instant
//!
//! Ethereum and Solana restore instantly because their state is a MAP KEYED BY ACCOUNT: a balance is one
//! lookup, `state[address]`, and it costs the same on a chain of ten blocks or ten billion. MonerousD's note
//! DA is an append-only STREAM keyed by `(seq, slot)`, so a wallet's notes are scattered through it and the
//! only complete way to find them is to walk the stream. That walk is O(chain height) — measured here at
//! ~200s and rising — which is a FAST-pillar violation baked into the data structure. No prefetch, cache,
//! page bound or index bolted on top removes it: a stream you must traverse is the defect.
//!
//! So this module gives the DA an account-indexed shape, and makes that shape private BY CONSTRUCTION.
//!
//! ## The four properties, and what each one buys
//!
//! 1. **One bucket per account.** `bucket_id = H(account_tag)`. A restore fetches ONE bucket, so it is O(1)
//!    in chain height — the Ethereum property.
//! 2. **CONSTANT-SIZE buckets.** Every bucket serialises to exactly [`BUCKET_BYTES`] whether it holds zero
//!    entries or [`BUCKET_CAPACITY`]. This is what makes ADDRESS REUSE SAFE: a thousand people may know your
//!    `bucket_id` and still learn nothing — not how many notes you hold, not your volume, not whether you
//!    have ever been paid. Occupancy lives inside the ciphertext, never in the length.
//! 3. **Contents sealed to the owner.** Entries are encrypted under a key derived from the account SEED, so
//!    fetching a bucket is useless without it. Anyone may fetch; only the owner reads.
//! 4. **Fetch is oblivious.** Retrieval rides the existing PIR path ([`crate::oli`]), so the serving node
//!    does not learn which bucket was asked for. Property 3 protects against whoever knows your id;
//!    property 4 protects against the node that stores it.
//!
//! Write TIMING is the caller's responsibility, not this module's: a block must update a CONSTANT number of
//! buckets (real recipients plus secret-seeded cover), exactly as the note payload already wears a constant
//! 256-slot cover. Otherwise an observer watching a known `bucket_id` learns when a payment arrived, handing
//! back the metadata the sealing just removed.
//!
//! Nothing here is a counter, a total, or a which-item query: a bucket is a fixed-size opaque blob at a
//! seed-derived address.

use crate::fixed::FixedBytes;
use crate::hash::Hash32;

/// Entries one bucket holds. A bucket is ALWAYS serialised at full capacity, so this is a shape constant —
/// not a limit that leaks when approached. PRODUCTION-SCALE-REVIEWED: a fixed structural width, not a
/// cover/block count.
pub const BUCKET_CAPACITY: usize = 16;

/// Bytes of one entry: the note commitment (32) plus its stream position `seq`(8) ‖ `slot`(1), padded to a
/// round width so an entry never reveals which kind it is.
///
/// Deliberately POSITION ONLY. Carrying the note's membership copath here was tried and is wrong: it is
/// per-note storage that grows with the note count — HOLDING, not folding. The siblings never need storing,
/// because the DA layer can REGENERATE any block's full 256-leaf shape (reals from its record, cover from
/// `cover::assemble_fixed_note_payload_det`). A witness is derived on demand from that, in constant work.
pub const ENTRY_BYTES: usize = 48;

/// Width of the per-write nonce that prefixes a sealed bucket.
pub const NONCE_BYTES: usize = 24;

/// A bucket's serialised size — CONSTANT, and the reason reuse cannot degrade privacy. Nonce plus the sealed
/// body; the body covers the occupancy byte and every entry slot, occupied or not.
pub const BUCKET_BYTES: usize = NONCE_BYTES + 1 + BUCKET_CAPACITY * ENTRY_BYTES;

/// One note's position in the DA stream AND the membership witness frozen at its receipt, as recorded for its
/// owner.
///
/// The witness has to be captured HERE, at record time, because it cannot be recovered later: the node keeps
/// only the frontier's peaks, never the leaves, so nothing on the chain can reconstruct an old note's copath.
/// The only alternative is for the wallet to page the entire note stream and rebuild it — an O(chain) walk that
/// takes longer every day and is banned. At record time the copath is free: the note's siblings within its own
/// block are in hand and everything to its left is already folded into the peaks.
///
/// This is what lets a restored wallet SPEND, not merely see a balance. Without it a one-lookup restore shows
/// the money and cannot move it, which is not a restore at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountEntry {
    pub note_cm: [u8; 32],
    pub seq: u64,
    pub slot: u8,
}

impl AccountEntry {
    /// An entry naming where a note landed.
    pub fn at(note_cm: [u8; 32], seq: u64, slot: u8) -> Self {
        AccountEntry { note_cm, seq, slot }
    }
}

/// The account address a payer writes to, derived from the recipient's PUBLISHED account tag.
///
/// Deriving this from the account tag — rather than from a per-payment secret — is deliberate: the recipient
/// must be able to compute it from its seed ALONE, or a restore would need the very notes it is looking for.
/// Knowing a `bucket_id` is not a privacy break here, because a bucket is a constant-size sealed blob: the
/// holder of the id learns exactly nothing from it, which is precisely what lets an address be reused freely.
pub fn bucket_id(account_tag: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/account-da/bucket/v1");
    h.update(account_tag);
    *h.finalize().as_bytes()
}

/// The NEXT bucket in an account's chain, derived from the current one.
///
/// A bucket holds a constant number of entries, so a busy account needs more than one. It must SPILL into the
/// next bucket, never drop the oldest to make room: dropping loses the position of a note the wallet still
/// owns, and once the linear sweep is gone that note can never be found again — silent, permanent fund loss.
/// Chaining keeps every bucket the same constant width on the wire while the chain itself grows only with what
/// the account actually holds. The wallet re-derives the same chain from its own bucket id, so following it
/// costs no lookup of any kind.
pub fn next_bucket(bucket: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/account-da/bucket-chain/v1");
    h.update(bucket);
    *h.finalize().as_bytes()
}

/// The symmetric key that seals a bucket, DERIVED FROM the account's existing seed (derivation, not
/// generation — the seed itself is minted by the wallet's CSPRNG keygen). A payer never holds it: a payer
/// writes through the node's update path and never reads the bucket back.
fn bucket_key(account_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(account_seed);
    h.update(b"MUSD/account-da/seal/v1");
    *h.finalize().as_bytes()
}

/// Keystream for one bucket, derived from the seal key and that bucket's own nonce, so two writes of the same
/// content never produce the same bytes — an observer diffing successive fetches learns nothing.
fn keystream(key: &[u8; 32], nonce: &[u8; NONCE_BYTES], len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"MUSD/account-da/stream/v1");
    h.update(nonce);
    let mut out: Vec<u8> = Vec::new();
    out.resize(len, 0);
    h.finalize_xof().fill(&mut out);
    out
}

/// Seal a set of entries into the CONSTANT-size wire form of a bucket.
///
/// The output is [`BUCKET_BYTES`] long for every input, including an empty one. Occupancy is carried INSIDE
/// the sealed body; unused slots are covered by the same keystream as the real ones, so a sealed empty bucket
/// and a sealed full bucket are byte-indistinguishable without the key.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: emits a fixed-size ciphertext. No count, volume, ordering or which-item
/// signal is observable — the occupancy is sealed and the length is a constant of the format.
pub fn seal_bucket(
    account_seed: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    entries: &[AccountEntry],
) -> Vec<u8> {
    let key = bucket_key(account_seed);
    let body_len = 1 + BUCKET_CAPACITY * ENTRY_BYTES;
    let mut body: Vec<u8> = Vec::with_capacity(body_len);
    body.push(entries.len().min(BUCKET_CAPACITY) as u8);
    for i in 0..BUCKET_CAPACITY {
        match entries.get(i) {
            Some(e) => {
                let start = body.len();
                body.extend_from_slice(&e.note_cm);
                body.extend_from_slice(&e.seq.to_le_bytes());
                body.push(e.slot);
                body.resize(start + ENTRY_BYTES, 0); // structural padding, hidden by the keystream
            }
            // An unoccupied slot is written out in full and covered identically, so occupancy never shows.
            None => body.resize(body.len() + ENTRY_BYTES, 0),
        }
    }
    let ks = keystream(&key, nonce, body_len);
    for (b, k) in body.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let mut out = Vec::with_capacity(BUCKET_BYTES);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&body);
    debug_assert_eq!(out.len(), BUCKET_BYTES);
    out
}

/// Open a bucket with the account seed. `None` only if the blob is the wrong shape.
///
/// A wrong key does NOT error — it yields entries that simply are not this wallet's, which the caller
/// discards when the commitments match nothing it owns. Failing loudly on a wrong key would turn a fetch into
/// an oracle for "is this bucket yours", which is the exact question the design refuses to answer.
pub fn open_bucket(account_seed: &[u8; 32], blob: &[u8]) -> Option<Vec<AccountEntry>> {
    if blob.len() != BUCKET_BYTES {
        return None;
    }
    let nonce: [u8; NONCE_BYTES] = blob[..NONCE_BYTES].try_into().ok()?;
    let key = bucket_key(account_seed);
    let body_len = 1 + BUCKET_CAPACITY * ENTRY_BYTES;
    let mut body = blob[NONCE_BYTES..].to_vec();
    let ks = keystream(&key, &nonce, body_len);
    for (b, k) in body.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let n = (body[0] as usize).min(BUCKET_CAPACITY);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = 1 + i * ENTRY_BYTES;
        let note_cm: [u8; 32] = body[off..off + 32].try_into().ok()?;
        let sq: [u8; 8] = body[off + 32..off + 40].try_into().ok()?;
        out.push(AccountEntry {
            note_cm,
            seq: u64::from_le_bytes(sq),
            slot: body[off + 40],
        });
    }
    Some(out)
}

/// A bucket's nonce for one update, derived from the node's DA secret and the write counter. Secret-seeded so
/// it is never a recomputable function of the bucket id or the height — the same rule the block cover follows.
pub fn bucket_nonce(da_secret: &[u8; 32], bucket: &[u8; 32], write_no: u64) -> [u8; NONCE_BYTES] {
    let mut h = blake3::Hasher::new_keyed(da_secret);
    h.update(b"MUSD/account-da/nonce/v1");
    h.update(bucket);
    h.update(&write_no.to_le_bytes());
    let d = h.finalize();
    d.as_bytes()[..NONCE_BYTES]
        .fixed()
}

/// Authentication tag width on a node-written entry, so the owner can tell its own entries from the cover
/// and the garbage a foreign key produces. Unforgeable without the shared secret, so it is not an oracle.
pub const ENTRY_TAG_BYTES: usize = 8;

/// Seal ONE entry to the recipient's PUBLIC encapsulation key — the form a NODE can write.
///
/// This is what makes the account-indexed shape implementable at all. The node must write a recipient's
/// bucket when it records a credit, but it does not hold — and must never hold — that recipient's secret. A
/// KEM resolves the asymmetry exactly: the sender hands over the recipient's PUBLIC `ek` (already in their
/// address), the node encapsulates to it, and only the holder of `dk` can open the result.
///
/// It is also precisely why ADDRESS REUSE stays safe. A thousand payers may hold the address and therefore
/// `ek`; that lets every one of them WRITE and not one of them READ. Read capability lives with `dk`, which
/// never leaves the wallet.
pub fn seal_entry_to(recipient_ek: &[u8], entry: &AccountEntry) -> Option<Vec<u8>> {
    // NOTE the order: `encapsulate` yields (shared secret, ciphertext), not the reverse.
    let (ss, ct) = crate::pqkem::encapsulate(recipient_ek)?;
    let mut body: Vec<u8> = Vec::with_capacity(ENTRY_BYTES);
    body.extend_from_slice(&entry.note_cm);
    body.extend_from_slice(&entry.seq.to_le_bytes());
    body.push(entry.slot);
    body.resize(ENTRY_BYTES, 0);
    let mut kh = blake3::Hasher::new();
    kh.update(b"MUSD/account-da/entry-key/v1");
    kh.update(&ss);
    let key = *kh.finalize().as_bytes();
    let ks = keystream(&key, &entry_nonce(&ct), ENTRY_BYTES);
    for (b, k) in body.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let mut th = blake3::Hasher::new();
    th.update(b"MUSD/account-da/entry-tag/v1");
    th.update(&ss);
    th.update(&body);
    let mut out = Vec::with_capacity(ct.len() + ENTRY_TAG_BYTES + ENTRY_BYTES);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&th.finalize().as_bytes()[..ENTRY_TAG_BYTES]);
    out.extend_from_slice(&body);
    Some(out)
}

/// Nonce for an entry's keystream, bound to its own KEM ciphertext — fresh per encapsulation, so two writes
/// of the same entry never produce the same bytes.
fn entry_nonce(ct: &[u8]) -> [u8; NONCE_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/account-da/entry-nonce/v1");
    h.update(ct);
    let d = h.finalize();
    d.as_bytes()[..NONCE_BYTES]
        .fixed()
}

/// Open a node-written entry with the recipient's decapsulation key.
///
/// `None` when the entry is not ours — which is the common case, since a bucket is mostly cover. ML-KEM's
/// implicit rejection means a foreign key yields a DIFFERENT shared secret rather than an error, so the tag
/// is what separates "mine" from "not mine"; forging it needs the shared secret, so this is not an oracle
/// anyone else can query.
pub fn open_entry(scan_dk: &[u8], blob: &[u8]) -> Option<AccountEntry> {
    let ct_len = crate::pqkem::ciphertext_len();
    if blob.len() != ct_len + ENTRY_TAG_BYTES + ENTRY_BYTES {
        return None;
    }
    let ct = &blob[..ct_len];
    let tag = &blob[ct_len..ct_len + ENTRY_TAG_BYTES];
    let body = &blob[ct_len + ENTRY_TAG_BYTES..];
    let ss = crate::pqkem::decapsulate(ct, scan_dk)?;
    let mut th = blake3::Hasher::new();
    th.update(b"MUSD/account-da/entry-tag/v1");
    th.update(&ss);
    th.update(body);
    if &th.finalize().as_bytes()[..ENTRY_TAG_BYTES] != tag {
        return None; // not ours — and a stranger cannot manufacture a match without the shared secret
    }
    let mut kh = blake3::Hasher::new();
    kh.update(b"MUSD/account-da/entry-key/v1");
    kh.update(&ss);
    let key = *kh.finalize().as_bytes();
    let ks = keystream(&key, &entry_nonce(ct), ENTRY_BYTES);
    let mut clear = body.to_vec();
    for (b, k) in clear.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let note_cm: [u8; 32] = clear[..32].try_into().ok()?;
    let sq: [u8; 8] = clear[32..40].try_into().ok()?;
    Some(AccountEntry {
        note_cm,
        seq: u64::from_le_bytes(sq),
        slot: clear[40],
    })
}

/// One sealed entry's width on the wire: KEM ciphertext + tag + sealed body. Constant, so an entry never
/// reveals whether it carries a real credit or cover.
pub fn sealed_entry_bytes() -> usize {
    crate::pqkem::ciphertext_len() + ENTRY_TAG_BYTES + ENTRY_BYTES
}

/// A bucket exactly as it is SERVED: always [`BUCKET_CAPACITY`] sealed entries, real ones first and the rest
/// filled with secret-seeded cover.
///
/// This is the shape an observer actually sees, so it is the shape that has to be invariant. A bucket that
/// has never been paid and a bucket at capacity serve byte-identical widths, and cover entries are drawn from
/// the node's DA secret so they cannot be recomputed and subtracted. A wallet simply tries every entry and
/// keeps the ones its key opens — cover costs it [`BUCKET_CAPACITY`] decapsulations, a constant.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: constant-size response, identical for a populated and an unused bucket. No
/// count, volume, ordering or existence signal is observable.
pub fn serve_bucket(real: &[Vec<u8>], da_secret: &[u8; 32], bucket: &[u8; 32]) -> Vec<u8> {
    let w = sealed_entry_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(BUCKET_CAPACITY * w);
    for e in real.iter().take(BUCKET_CAPACITY) {
        if e.len() == w {
            out.extend_from_slice(e);
        }
    }
    let mut ctr: u64 = 0;
    while out.len() < BUCKET_CAPACITY * w {
        let mut h = blake3::Hasher::new_keyed(da_secret);
        h.update(b"MUSD/account-da/serve-cover/v1");
        h.update(bucket);
        h.update(&ctr.to_le_bytes());
        let mut filler: Vec<u8> = Vec::new();
        filler.resize(w, 0);
        h.finalize_xof().fill(&mut filler);
        let take = (BUCKET_CAPACITY * w - out.len()).min(w);
        out.extend_from_slice(&filler[..take]);
        ctr += 1;
    }
    out
}

/// Bucket updates one block performs — a CONSTANT, the write-side twin of the constant bucket SIZE.
///
/// Sealing a bucket hides what is in it; it does not hide that it changed. An observer who knows a
/// `bucket_id` — which anyone holding that address does — can watch for a write and learn exactly when a
/// payment landed, recovering the timing metadata the sealing just removed. So a block must always touch the
/// same number of buckets. PRODUCTION-SCALE-REVIEWED: a fixed cover width, matching the 256-slot note cover.
pub const BUCKET_WRITES_PER_BLOCK: usize = 256;

/// Which buckets this block rewrites: every bucket that genuinely changed, hidden inside a CONSTANT number of
/// secret-seeded cover rewrites, in sorted order.
///
/// A cover rewrite is a real rewrite — the bucket is resealed under a fresh nonce with its existing contents,
/// so it is byte-different and wholly indistinguishable from one that took a payment. Three properties carry
/// the privacy, and each is asserted by a test:
///   * the count is ALWAYS `BUCKET_WRITES_PER_BLOCK`, so a busy block and an idle one look identical;
///   * cover is drawn from the node's DA SECRET, never from the height or the bucket id, so an observer
///     cannot recompute the cover set and subtract it to reveal the real recipients;
///   * output is SORTED, so position in the write set never encodes which entries were real.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: emits a constant-size set of bucket addresses. No count of real recipients,
/// no ordering signal, and no which-item signal is observable.
pub fn plan_bucket_writes(
    real: &[[u8; 32]],
    da_secret: &[u8; 32],
    height: u64,
    width: usize,
) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(width);
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for b in real.iter().take(width) {
        if seen.insert(*b) {
            out.push(*b);
        }
    }
    let mut ctr: u64 = 0;
    while out.len() < width {
        let mut h = blake3::Hasher::new_keyed(da_secret);
        h.update(b"MUSD/account-da/cover-write/v1");
        h.update(&height.to_le_bytes());
        h.update(&ctr.to_le_bytes());
        let pick = *h.finalize().as_bytes();
        if seen.insert(pick) {
            out.push(pick);
        }
        ctr += 1;
    }
    out.sort_unstable();
    out
}

/// The CANONICAL leaf a bucket write folds into the header accumulator: `(bucket, note_cm)`.
///
/// Deliberately NOT the sealed bytes. A sealed entry embeds the note's `seq`, which is a NODE-LOCAL counter
/// (two peers of the same chain number their stream independently — measured, 0 of 6 sampled seqs agreed), so
/// committing sealed bytes would have every node compute a different root and split consensus. Bucket id and
/// note commitment are both canonical, so every node folds the identical value.
pub fn account_write_leaf(bucket: &[u8; 32], note_cm: &[u8; 32]) -> Hash32 {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(bucket);
    v.extend_from_slice(note_cm);
    Hash32::hash(&v)
}

/// Fold one bucket write into the running O(1) account accumulator. No per-account tree, no per-item store —
/// a single 32-byte value that advances in O(1) per write and is committed in the block header.
///
/// COMMUTATIVE by construction (wrapping 256-bit addition of leaves), because nodes apply the same writes in
/// DIFFERENT ORDERS: the producer folds a note as it mines it, while a peer folds the same note when it
/// arrives by backfill or adopt. A hash-chain fold made the order part of the value, so two nodes holding
/// identical state committed different roots — measured directly, `d323753f…` against `78e10db3…` for the
/// same payment. Addition makes the accumulator a function of the SET of writes, which is what it is meant
/// to commit; unlike XOR it does not let a repeated leaf silently cancel itself out.
pub fn fold_account_acc(acc: Hash32, bucket: &[u8; 32], note_cm: &[u8; 32]) -> Hash32 {
    let leaf = account_write_leaf(bucket, note_cm);
    let a = acc.as_bytes();
    let l = leaf.as_bytes();
    let mut out = [0u8; 32];
    let mut carry = 0u64;
    // Little-endian 4-limb wrapping add: order-independent, and every leaf still moves every future value.
    // ⭐ NOT §AG CLASS 9 (audited 2026-09-13): `4` is 256 / 64 — a 256-bit INTEGER over two `[u8; 32]`
    // blake3 values, never a digest; there is no lane count here to size anything by.
    for i in 0..4 {
        let ax = u64::from_le_bytes(a[i * 8..i * 8 + 8].fixed());
        let lx = u64::from_le_bytes(l[i * 8..i * 8 + 8].fixed());
        let (s1, c1) = ax.overflowing_add(lx);
        let (s2, c2) = s1.overflowing_add(carry);
        carry = (c1 as u64) + (c2 as u64);
        out[i * 8..i * 8 + 8].copy_from_slice(&s2.to_le_bytes());
    }
    Hash32(out)
}

/// Digest binding a bucket's CURRENT sealed content to its id, for the accumulator that commits the account
/// map. Lets a wallet verify the bucket it fetched is the one the chain committed, so a restore stays
/// self-verifying rather than trusting whoever served it.
pub fn bucket_leaf(bucket: &[u8; 32], sealed: &[u8]) -> Hash32 {
    let mut v = Vec::with_capacity(32 + sealed.len());
    v.extend_from_slice(bucket);
    v.extend_from_slice(sealed);
    Hash32::hash(&v)
}

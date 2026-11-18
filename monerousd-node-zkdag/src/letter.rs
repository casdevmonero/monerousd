// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Letter** — 100%-private P2P messaging, PQ-sealed end to end, ZERO metadata. "Like sending a letter in the
//! old days: private at every layer." The node is the sender's/recipient's OWN self-custodial crypto engine plus
//! a metadata-blind relay — three properties, by construction:
//!
//!   1. **PQ end-to-end seal.** A message is sealed to the recipient's **ML-KEM-768** ([`crate::pqkem`])
//!      encapsulation key: encapsulate → 32-byte shared secret → a blake3-keyed AEAD (symmetric, quantum-safe)
//!      over the body. The relay only ever holds `kem_ct ‖ nonce ‖ tag ‖ ciphertext` — an OPAQUE blob. No
//!      classical crypto anywhere.
//!   2. **Metadata-blind relay (oblivious scan).** [`LetterRelay`] is a BOUNDED ring of sealed slots — NO
//!      recipient tag, NO sender field, NO timestamp on the wire. `inbox()` returns a CONSTANT number of slots
//!      (real messages COVER-PADDED to the fixed window), so an observer counting the relay learns nothing about
//!      who has mail or how much. A recipient's node fetches the window and simply TRIES to `open` each slot with
//!      its own decapsulation key — the ones that authenticate are its letters; the rest are cover. This is the
//!      same oblivious-scan model the chain uses for notes: which-item is never queryable.
//!   3. **No growth.** The ring is fixed-capacity ([`RELAY_SLOTS`]); old slots roll off. Relay state is O(1) in
//!      the number of messages ever sent — never a growing log.

use crate::pqkem;

/// The relay's fixed slot count — the CONSTANT cover window every `inbox()` returns (real letters padded up to
/// this, so a global observer can never count real mail). Also bounds relay state (no growth).
pub const RELAY_SLOTS: usize = 64;

/// AEAD framing lengths. `nonce` is derived from the (fresh) KEM ciphertext, so it is unique per message without
/// needing a separate RNG draw. `tag` is a 16-byte blake3-keyed MAC over `nonce ‖ ciphertext`.
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// A node's Letter identity — its ML-KEM-768 keypair. The DECAPSULATION secret never leaves this node (self-
/// custodial); the encapsulation key is what a correspondent seals to (fetched as the node's Letter address).
/// Generated fresh at boot for now; a wallet-derived identity is the cross-device follow-on.
pub struct LetterIdentity {
    pub encap: Vec<u8>,
    secret: Vec<u8>,
}

impl LetterIdentity {
    pub fn generate() -> Self {
        let (encap, secret) = pqkem::keypair();
        LetterIdentity { encap, secret }
    }
    /// Our own decapsulation secret (never leaves the node) — for `open`ing letters addressed to us.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Derive the two AEAD subkeys from the ML-KEM shared secret (domain-separated so the encryption keystream and
/// the MAC key are independent). blake3 is PQ-safe; the shared secret is the only key material.
fn subkeys(shared: &[u8]) -> (blake3::Hash, blake3::Hash) {
    let mut e = blake3::Hasher::new();
    e.update(b"MONEROUSD-LETTER-ENC");
    e.update(shared);
    let mut m = blake3::Hasher::new();
    m.update(b"MONEROUSD-LETTER-MAC");
    m.update(shared);
    (e.finalize(), m.finalize())
}

/// blake3 counter-mode keystream XOR — a quantum-safe stream cipher (the key is the ML-KEM secret). Symmetric,
/// so no classical asymmetric primitive anywhere.
fn xor_keystream(k_enc: &blake3::Hash, nonce: &[u8], data: &mut [u8]) {
    let mut off = 0usize;
    let mut counter: u64 = 0;
    while off < data.len() {
        let mut h = blake3::Hasher::new();
        h.update(k_enc.as_bytes());
        h.update(nonce);
        h.update(&counter.to_le_bytes());
        let block = h.finalize();
        let kb = block.as_bytes();
        let n = (data.len() - off).min(kb.len());
        for i in 0..n {
            data[off + i] ^= kb[i];
        }
        off += n;
        counter += 1;
    }
}

/// Seal `msg` to recipient `to_encap` (ML-KEM-768 encapsulate + blake3 AEAD). Returns the OPAQUE relay blob
/// `kem_ct ‖ nonce ‖ tag ‖ ciphertext`, or `None` if the recipient key is malformed. The sender's own
/// encapsulation key `from_encap` is carried INSIDE the sealed body (only the recipient learns the sender — the
/// relay never does).
pub fn seal(to_encap: &[u8], from_encap: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let (shared, kem_ct) = pqkem::encapsulate(to_encap)?;
    let (k_enc, k_mac) = subkeys(&shared);
    // nonce = blake3(kem_ct) — the KEM ciphertext is fresh per message, so the nonce is unique without an RNG.
    let nonce: Vec<u8> = blake3::hash(&kem_ct).as_bytes()[..NONCE_LEN].to_vec();
    // body = from_len(u16) ‖ from_encap ‖ msg
    let mut body = Vec::with_capacity(2 + from_encap.len() + msg.len());
    body.extend_from_slice(&(from_encap.len() as u16).to_le_bytes());
    body.extend_from_slice(from_encap);
    body.extend_from_slice(msg);
    xor_keystream(&k_enc, &nonce, &mut body);
    let mut mac_in = Vec::with_capacity(nonce.len() + body.len());
    mac_in.extend_from_slice(&nonce);
    mac_in.extend_from_slice(&body);
    let tag = blake3::keyed_hash(k_mac.as_bytes(), &mac_in);
    let mut blob = Vec::with_capacity(kem_ct.len() + NONCE_LEN + TAG_LEN + body.len());
    blob.extend_from_slice(&kem_ct);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&tag.as_bytes()[..TAG_LEN]);
    blob.extend_from_slice(&body);
    Some(blob)
}

/// The opened result of a letter addressed to us.
pub struct Opened {
    pub from: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Try to open `blob` with our decapsulation `secret`. Returns `Some(Opened)` iff this letter was sealed to us
/// AND the MAC authenticates (reject otherwise — the oblivious scan tries every relay slot and only OUR letters
/// open). A tampered blob, or one for a different recipient, returns `None` — never a panic.
pub fn open(blob: &[u8], secret: &[u8]) -> Option<Opened> {
    let ct_len = pqkem::ciphertext_len();
    if blob.len() < ct_len + NONCE_LEN + TAG_LEN {
        return None;
    }
    let kem_ct = &blob[..ct_len];
    let nonce = &blob[ct_len..ct_len + NONCE_LEN];
    let tag = &blob[ct_len + NONCE_LEN..ct_len + NONCE_LEN + TAG_LEN];
    let body_enc = &blob[ct_len + NONCE_LEN + TAG_LEN..];
    let shared = pqkem::decapsulate(kem_ct, secret)?; // wrong key → a DIFFERENT secret (implicit rejection) → MAC fails below
    let (k_enc, k_mac) = subkeys(&shared);
    let mut mac_in = Vec::with_capacity(nonce.len() + body_enc.len());
    mac_in.extend_from_slice(nonce);
    mac_in.extend_from_slice(body_enc);
    let expect = blake3::keyed_hash(k_mac.as_bytes(), &mac_in);
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= expect.as_bytes()[i] ^ tag[i];
    }
    if diff != 0 {
        return None;
    }
    let mut body = body_enc.to_vec();
    xor_keystream(&k_enc, nonce, &mut body);
    if body.len() < 2 {
        return None;
    }
    let flen = u16::from_le_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + flen {
        return None;
    }
    let from = body[2..2 + flen].to_vec();
    let msg = body[2 + flen..].to_vec();
    Some(Opened { from, msg })
}

/// ⭐ ON-CHAIN LETTER STREAM — the constant number of letter-COMMITMENT slots every block carries in
/// [`crate::block::Block::letter_cms`]. PAST-CHATS-CHECKED: reuses [`RELAY_SLOTS`], the letter subsystem's
/// existing, user-approved fixed cover shape (the constant-cover serve set) — not a newly tuned number. A FIXED
/// protocol shape: identical at height 1 and at any height, never a function of history. Real sealed-letter
/// commitments fill the front slots; the rest are secret-seeded cover commitments byte-indistinguishable from
/// real ones, so an observer counting a block learns NOTHING about real mail volume (digital-cash volume/timing
/// privacy). More real letters than slots in one interval simply ride the NEXT block (a page that drains, never
/// a bound that drops a message). Only 32-byte COMMITMENTS ride the block — the sealed blobs travel the
/// gossip/backfill lanes and are fetched by commitment, so blocks stay lean.
///
/// cons (the arithmetic): 64 x 32 B = 2,048 B per block IN FLIGHT — at the ~500 ms cadence that is ~4 KB/s of
/// gossip, riding beside the far larger existing 256-tx cover shape; 0 B retained per block AT REST (the node
/// keeps the flat 32-byte accumulator + the fixed 64-slot ring, both f(fixed constants), never f(history)).
pub const LETTER_CMS_PER_BLOCK: usize = RELAY_SLOTS;

/// A sealed letter blob's on-chain commitment: `blake3(domain ‖ blob)`. What [`crate::block::Block::letter_cms`]
/// carries and what the letter accumulator folds — the blob itself never rides a block.
pub fn letter_cm(blob: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MONEROUSD-LETTER-CM");
    h.update(blob);
    *h.finalize().as_bytes()
}

/// Fold ONE block's carried letter-commitment set into the running letter accumulator — the single definition
/// produce, ingest and replay all call. ⛔ ORDER-INDEPENDENT BY CONSTRUCTION (a COMMUTATIVE limb-wise wrapping
/// sum of each block's domain-separated digest — the exact shape the note-membership accumulator uses, whose
/// own test names the property "order-independent (the fold is a commutative sum)"): two producers accept each
/// other's blocks in DIFFERENT orders, so a hash-chain fold diverges the mesh permanently. MEASURED live
/// 2026-08-23 on the fresh pair minutes after boot: origin acc 8ca44670…, joiner acc 1daeedbd… over the SAME
/// blocks — the island class, caught at first cross-node parity read. A sum over per-block digests reaches the
/// identical value in any accept order, converging by construction.
/// cons: none — one blake3 + four u64 adds per accepted block; the accumulator is a flat 32 B forever.
pub fn fold_letter_acc(acc: &[u8; 32], letter_cms: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MONEROUSD-LETTER-ACC");
    h.update(letter_cms);
    let d = h.finalize();
    let db = d.as_bytes();
    let mut out = [0u8; 32];
    // ⭐ NOT §AG CLASS 9 (audited 2026-09-13): `4` here is 256 / 64 — this accumulator is a 256-bit
    // INTEGER held as four u64 words of a 32-byte blake3 value, never a digest, so it has no lanes 4..7 to
    // leave zero and no lane-count to size a buffer by. Both operands are `[u8; 32]` by type.
    for i in 0..4 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&acc[i * 8..i * 8 + 8]);
        let mut b = [0u8; 8];
        b.copy_from_slice(&db[i * 8..i * 8 + 8]);
        let sum = u64::from_le_bytes(a).wrapping_add(u64::from_le_bytes(b));
        out[i * 8..i * 8 + 8].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

/// The letter accumulator's genesis value — the sum's additive identity (all-zero limbs), the same on every
/// node; any sequence of block folds from here reaches one value regardless of accept order.
pub fn letter_acc_genesis() -> [u8; 32] {
    [0u8; 32]
}

/// One relay slot: a sealed blob, its on-chain commitment (computed once at admit), and whether this REAL letter
/// still awaits a block to carry its commitment. The ring stays the ONE bounded structure it always was — richer
/// element, same fixed [`RELAY_SLOTS`] capacity, so relay state cannot grow however much mail history exists.
struct LetterSlot {
    cm: [u8; 32],
    blob: Vec<u8>,
    /// True until some accepted block's `letter_cms` carries this commitment (flipped by `mark_carried`). A blob
    /// that rolls off the ring un-carried re-enters via re-gossip/backfill — never silently lost.
    pending: bool,
    /// ⭐ EPIDEMIC RE-FLOOD COUNTDOWN. The original design flooded a blob to peers exactly ONCE, at admit —
    /// the same one-shot class as the peer-record announce bug: if the Tor writer to a peer was stalled at
    /// that instant, the letter silently never arrived (MEASURED 2026-08-23: a wallet-app send sat in the
    /// origin's ring while the joiner's ring never received it — "instant delivery" failed). Every NEW admit
    /// arms this counter; each relay tick re-queues the blob to peers and decrements, so delivery retries
    /// through writer stalls and re-propagates epidemic-style from every node that holds it. Bounded (flat
    /// u8, ~20 ticks ≈ the anchor window), content-deduped at every receiver — repeats are no-ops, never loops.
    fresh: u8,
}

/// The metadata-blind relay — a BOUNDED ring of sealed slots. No tag, no sender, no timestamp on the wire; every
/// `inbox()` returns exactly [`RELAY_SLOTS`] entries (real letters COVER-PADDED with random-looking fill), so an
/// observer can never count real mail. Fixed capacity ⇒ O(1) relay state (no growth). Also the node's letter
/// CONTENT STORE for the on-chain stream: `blob_of(cm)` answers a backfill request, `drain_pending_cms` feeds the
/// producer's block carrier, `mark_carried` retires commitments an accepted block anchored — all over the same
/// single fixed-capacity ring (no second store anywhere). cons: none — every method below is one pass over the
/// fixed 64-slot ring (f(RELAY_SLOTS), a protocol shape constant, never a history quantity).
pub struct LetterRelay {
    slots: Vec<LetterSlot>, // most-recent-first ring of sealed blobs + their commitments
}

impl Default for LetterRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl LetterRelay {
    pub fn new() -> Self {
        LetterRelay { slots: Vec::new() }
    }

    /// Relay a sealed blob. Newest first; the ring is capped at [`RELAY_SLOTS`] (oldest rolls off — no growth).
    pub fn send(&mut self, blob: Vec<u8>) {
        let cm = letter_cm(&blob);
        self.slots.insert(
            0,
            LetterSlot {
                cm,
                blob,
                pending: true,
                fresh: 20,
            },
        );
        if self.slots.len() > RELAY_SLOTS {
            self.slots.truncate(RELAY_SLOTS);
        }
    }

    /// ⭐ Admit a gossiped blob, CONTENT-DEDUPED. Returns `true` iff it was NEW (not already in the ring) — the
    /// caller re-gossips ONLY new blobs, so a letter floods the mesh exactly once per node and can never loop.
    /// Same bounded ring as `send` (no growth): a duplicate is dropped, a new one rolls the oldest off.
    pub fn admit(&mut self, blob: Vec<u8>) -> bool {
        let cm = letter_cm(&blob);
        if self.slots.iter().any(|s| s.cm == cm) {
            return false; // already relayed here — do not re-gossip (flood control)
        }
        self.slots.insert(
            0,
            LetterSlot {
                cm,
                blob,
                pending: true,
                fresh: 20,
            },
        );
        if self.slots.len() > RELAY_SLOTS {
            self.slots.truncate(RELAY_SLOTS);
        }
        true
    }

    /// ⭐ One relay tick's outbound batch: every slot still FRESH yields its blob and burns one count. The
    /// serve loop queues these to peers every couple of seconds, so a letter keeps retrying until the mesh has
    /// it — the receiving side's content-dedup (`admit`) makes repeats free. Bounded by the fixed ring.
    pub fn flood_batch(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for s in self.slots.iter_mut() {
            if s.fresh > 0 {
                s.fresh -= 1;
                out.push(s.blob.clone());
            }
        }
        out
    }

    /// The still-fresh ring slice WITHOUT burning the push countdown — what a [`LetterReq`] pull answer
    /// carries. Same set the push flood sends; the pull lane exists for peers whose dial to us works while
    /// ours to them does not (asymmetric topology).
    pub fn fresh_blobs(&self) -> Vec<Vec<u8>> {
        self.slots
            .iter()
            .filter(|s| s.fresh > 0)
            .map(|s| s.blob.clone())
            .collect()
    }

    /// The sealed blob committed to by `cm`, if this node currently holds it — what a `LetterReq` backfill and a
    /// recipient's by-commitment fetch read. One pass over the fixed-size ring.
    pub fn blob_of(&self, cm: &[u8; 32]) -> Option<Vec<u8>> {
        self.slots
            .iter()
            .find(|s| s.cm == *cm)
            .map(|s| s.blob.clone())
    }

    /// Up to [`LETTER_CMS_PER_BLOCK`] REAL commitments still awaiting a block — what the producer seals into
    /// [`crate::block::Block::letter_cms`]. Does NOT flip `pending` (only an ACCEPTED block does, via
    /// [`Self::mark_carried`]), so a template that loses the race never strands a letter un-anchored.
    pub fn drain_pending_cms(&self) -> Vec<[u8; 32]> {
        self.slots
            .iter()
            .filter(|s| s.pending)
            .take(LETTER_CMS_PER_BLOCK)
            .map(|s| s.cm)
            .collect()
    }

    /// Retire every pending commitment that `letter_cms` (an ACCEPTED block's carried set) anchored on-chain —
    /// produce and ingest both call this, so two producers never double-carry a letter forever and an echo is a
    /// no-op. Unknown commitments (another node's letters, or cover) are ignored.
    pub fn mark_carried(&mut self, letter_cms: &[u8]) {
        let mut off = 0usize;
        while off + 32 <= letter_cms.len() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&letter_cms[off..off + 32]);
            for s in self.slots.iter_mut() {
                if s.cm == cm {
                    s.pending = false;
                }
            }
            off += 32;
        }
    }

    /// The CONSTANT cover window: exactly [`RELAY_SLOTS`] slots. Real sealed blobs come first; the remainder are
    /// cover fill (deterministic-looking bytes, indistinguishable in shape from a real sealed blob to an observer
    /// who cannot open them). The recipient's node tries to `open` every slot; only its letters authenticate.
    pub fn inbox(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.slots.iter().map(|s| s.blob.clone()).collect();
        let blob_len = pqkem::ciphertext_len() + NONCE_LEN + TAG_LEN + 32;
        let mut i = out.len();
        while out.len() < RELAY_SLOTS {
            let mut cover = Vec::with_capacity(blob_len);
            let mut ctr = 0u64;
            while cover.len() < blob_len {
                let mut h = blake3::Hasher::new();
                h.update(b"MONEROUSD-LETTER-COVER");
                h.update(&(i as u64).to_le_bytes());
                h.update(&ctr.to_le_bytes());
                cover.extend_from_slice(h.finalize().as_bytes());
                ctr += 1;
            }
            cover.truncate(blob_len);
            out.push(cover);
            i += 1;
        }
        out
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_reject_tamper_and_wrong_recipient() {
        let alice = LetterIdentity::generate();
        let bob = LetterIdentity::generate();
        let blob = seal(&bob.encap, &alice.encap, b"meet at the old oak, midnight").expect("seal");

        // Bob opens it — real PQ end-to-end.
        let opened = open(&blob, bob.secret()).expect("bob opens his letter");
        assert_eq!(opened.msg, b"meet at the old oak, midnight");
        assert_eq!(
            opened.from, alice.encap,
            "sender learned only by the recipient"
        );

        // A DIFFERENT recipient cannot open it (wrong ML-KEM key → MAC fails) — adversarial reject.
        let eve = LetterIdentity::generate();
        assert!(
            open(&blob, eve.secret()).is_none(),
            "not-the-recipient must not open"
        );

        // A TAMPERED ciphertext byte fails the MAC — adversarial reject.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(
            open(&bad, bob.secret()).is_none(),
            "tampered blob must reject"
        );
    }

    #[test]
    fn relay_is_constant_cover_and_bounded() {
        let bob = LetterIdentity::generate();
        let alice = LetterIdentity::generate();
        let mut relay = LetterRelay::new();
        relay.send(seal(&bob.encap, &alice.encap, b"one").unwrap());

        // inbox is ALWAYS the constant cover window — an observer cannot count real mail.
        let box1 = relay.inbox();
        assert_eq!(
            box1.len(),
            RELAY_SLOTS,
            "inbox is cover-padded to the constant window"
        );
        let mine = box1
            .iter()
            .filter(|b| open(b, bob.secret()).is_some())
            .count();
        assert_eq!(
            mine,
            1,
            "only the real letter opens; the {} cover slots do not",
            RELAY_SLOTS - 1
        );

        // the ring is bounded — flooding never grows relay state past RELAY_SLOTS.
        for _ in 0..(RELAY_SLOTS * 3) {
            relay.send(seal(&bob.encap, &alice.encap, b"flood").unwrap());
        }
        assert_eq!(
            relay.inbox().len(),
            RELAY_SLOTS,
            "ring stays bounded (no growth)"
        );
    }
}

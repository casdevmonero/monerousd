// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! Authenticated CLUE-KEY directory — maps a wallet's address spend-tag `b = H(spend_pk)` to its PUBLIC
//! packed-LWE OMR detection clue key (an opaque blob). A SENDER building a note for a recipient looks up the
//! recipient's clue key by the `b` already carried in their address, then attaches the note's detection clue so
//! the recipient can find it on cold restore in `O(owned)` (see the wallet's `omr` module +
//! `pq::clue_accelerated_recover`). The clue key is PUBLIC: it only lets a sender TAG a note for detection; it
//! CANNOT decrypt — that needs the recipient's SECRET, which never leaves the wallet. So serving it leaks
//! nothing (no scan key, no linkage). Registration is authenticated by an ML-DSA-65 signature over
//! [`crate::pqauth::clue_register_msg`]; the slot key IS `H(pubkey)`, so only the address owner can set or
//! update THEIR OWN clue key — owner-continuity by construction, no squat surface.
use std::collections::BTreeMap;

/// ⭐ G2c (lane a 2026-10-23) — the clue directory's anti-entropy buckets: a [`WireMsg::ClueDigest`] carries one 8-byte
/// digest per bucket (`owner[0]`), so a peer whose directory differs re-pushes only the registrations of the buckets that
/// differ, never the whole directory.
///
/// [`WireMsg::ClueDigest`]: crate::protocol::WireMsg::ClueDigest
pub const CLUE_DIGEST_BUCKETS: usize = 256;
/// Bytes of one bucket's digest (truncated blake3 — it detects divergence; the adopt re-verifies every pushed record).
pub const CLUE_DIGEST_BUCKET_BYTES: usize = 8;
/// The one fixed width of a `ClueDigest` payload: 256 × 8 = 2,048 B, one cell, whatever the directory holds.
pub const CLUE_DIGEST_WIRE_BYTES: usize = CLUE_DIGEST_BUCKETS * CLUE_DIGEST_BUCKET_BYTES;

/// A node's live set of published clue keys, keyed by owner id `b = H(spend_pk)` → the VERIFIED registration (the owner's
/// pubkey, the opaque clue-key blob and its ML-DSA signature — kept whole so anti-entropy can re-push what a peer lacks
/// and the peer re-verifies it; a bare blob could not be re-proven).
pub struct ClueRegistry {
    keys: BTreeMap<[u8; 32], ClueGossip>,
    /// The bucket digests of `keys`, recomputed on the first read after a change (`None` = stale).
    digest: Option<Vec<u8>>,
}

impl ClueRegistry {
    pub fn new() -> Self {
        ClueRegistry {
            keys: BTreeMap::new(),
            digest: None,
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Resolve the clue-key blob for an address owner id `b = H(spend_pk)`, if published.
    pub fn resolve(&self, owner: &[u8; 32]) -> Option<&[u8]> {
        self.keys.get(owner).map(|g| g.clue_pk.as_slice())
    }

    /// Adopt a clue-key registration whose ML-DSA signature the caller has ALREADY verified (`owner` = H(g.pubkey)). The
    /// slot is keyed by the owner id, so this only ever sets the OWNER'S OWN clue key (no squat surface). Returns whether
    /// the directory CHANGED — an identical or losing re-adopt returns false so the gossip layer does NOT re-broadcast it.
    ///
    /// ⭐ G2c — ONE ORDER-FREE RULE PER OWNER: between two validly signed keys for one owner the one with the SMALLER
    /// blake3(clue_pk) stands, so every node holding the same registrations holds the same directory in any arrival order
    /// (a set refuses by content, never by luck — the fast-eco replica census measured `clues` 1 vs 2 after a lost
    /// one-shot gossip, scratchpad/night/eco-census-20261023-161849.log). Last-writer-wins would let an owner who signed
    /// two keys flip every node's slot on each anti-entropy push forever. The wallet derives its clue key from its seed
    /// (`pq.rs` clue keypair), so an honest owner signs one key. Con: an owner can never rotate to a key with a larger hash.
    pub fn adopt(&mut self, owner: [u8; 32], g: ClueGossip) -> bool {
        if let Some(cur) = self.keys.get(&owner) {
            if cur.clue_pk == g.clue_pk
                || blake3::hash(&cur.clue_pk).as_bytes() <= blake3::hash(&g.clue_pk).as_bytes()
            {
                return false; // identical or losing registration — no change, do not re-gossip
            }
        }
        self.keys.insert(owner, g);
        self.digest = None;
        true
    }

    /// One 32-byte digest of the whole directory's content (every owner ‖ blake3(clue_pk) in owner order) — what the
    /// replica census compares across nodes (a count would read two different directories as the same).
    pub fn content_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (owner, g) in &self.keys {
            h.update(owner);
            h.update(blake3::hash(&g.clue_pk).as_bytes());
        }
        *h.finalize().as_bytes()
    }

    fn bucket_of(owner: &[u8; 32]) -> usize {
        owner[0] as usize
    }

    /// The anti-entropy digest: per bucket, blake3 over that bucket's `owner ‖ blake3(clue_pk)` in owner order, truncated
    /// to [`CLUE_DIGEST_BUCKET_BYTES`] (an empty bucket is all zero). One function of the directory's CONTENT, so two
    /// nodes holding the same registrations send the same bytes. O(directory) once per change, cached.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: digests of the PUBLIC clue directory every node already gossips whole (owner pubkey
    /// + public clue key) — no note, amount, scan key or linkage; fixed width whatever the directory holds.
    pub fn digest(&mut self) -> &[u8] {
        if self.digest.is_none() {
            let mut out = vec![0u8; CLUE_DIGEST_WIRE_BYTES];
            let mut cur: Option<(usize, blake3::Hasher)> = None;
            let flush = |out: &mut Vec<u8>, b: usize, h: blake3::Hasher| {
                let at = b * CLUE_DIGEST_BUCKET_BYTES;
                out[at..at + CLUE_DIGEST_BUCKET_BYTES].copy_from_slice(&h.finalize().as_bytes()[..CLUE_DIGEST_BUCKET_BYTES]);
            };
            for (owner, g) in &self.keys {
                let b = Self::bucket_of(owner);
                if cur.as_ref().map(|(cb, _)| *cb) != Some(b) {
                    if let Some((cb, h)) = cur.take() {
                        flush(&mut out, cb, h);
                    }
                    cur = Some((b, blake3::Hasher::new()));
                }
                if let Some((_, h)) = cur.as_mut() {
                    h.update(owner);
                    h.update(blake3::hash(&g.clue_pk).as_bytes());
                }
            }
            if let Some((cb, h)) = cur.take() {
                flush(&mut out, cb, h);
            }
            self.digest = Some(out);
        }
        self.digest.as_deref().unwrap_or(&[])
    }

    /// The verified registrations of every bucket whose digest differs from a peer's `ClueDigest` payload — what that
    /// peer may lack. A payload of the wrong width answers nothing (fail-closed). Bounded by the directory: the pushes
    /// are re-verified and deduped by [`ClueRegistry::adopt`] on the receiver, so nothing loops.
    pub fn differing(&mut self, peer_digest: &[u8]) -> Vec<ClueGossip> {
        if peer_digest.len() != CLUE_DIGEST_WIRE_BYTES {
            return Vec::new();
        }
        let mine = self.digest().to_vec();
        let differs = |b: usize| {
            let at = b * CLUE_DIGEST_BUCKET_BYTES;
            mine[at..at + CLUE_DIGEST_BUCKET_BYTES] != peer_digest[at..at + CLUE_DIGEST_BUCKET_BYTES]
        };
        self.keys
            .iter()
            .filter(|(o, _)| differs(Self::bucket_of(o)))
            .map(|(_, g)| g.clone())
            .collect()
    }
}

/// A gossiped clue-key registration — the wire form the clue directory REPLICATES across the mesh so a SENDER on
/// any node can resolve a recipient's clue key to attach an OMR detection clue (oblivious cold-restore across the
/// WHOLE mesh, not just the node the recipient happened to publish on). It carries the SAME fields a
/// `/register_clue_key` RPC would; a receiver re-runs the AUTHENTICATED adopt (ML-DSA sig over `clue_register_msg`,
/// keyed by H(pubkey)) before accepting, so a peer can never forge or squat another wallet's clue slot. The clue
/// key is PUBLIC (it only lets a sender TAG a note for detection; it cannot decrypt).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClueGossip {
    pub pubkey: Vec<u8>,
    pub clue_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl ClueGossip {
    /// Postcard wire bytes (the [`crate::protocol::WireMsg::Clue`] payload).
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Decode a received frame; a corrupt/truncated one returns `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<ClueGossip> {
        crate::chain_object::decode_exact(bytes)
    }
}

// ⛔ DB-330: the per-note clue GOSSIP payload (`NoteClueGossip`) is deleted with its lane. A per-note clue is filed
// only by the transaction that carries its note (`Node::carried_clue_records`); `WireMsg::NoteClue` is never sent
// and a received frame is dropped. The "money-safe because `pq::full_recover` decaps every note" argument it rested
// on cites a function with no production caller.

impl Default for ClueRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn resolve_after_adopt_and_owner_updates_own_slot() {
        let mut r = ClueRegistry::new();
        let owner = [1u8; 32];
        assert!(r.resolve(&owner).is_none(), "unpublished → None");
        let g = |c: Vec<u8>| ClueGossip { pubkey: vec![1], clue_pk: c, sig: vec![2] };
        let (k1, k2) = (vec![9u8; 16], vec![7u8; 24]);
        let (lo, hi) = if blake3::hash(&k1).as_bytes() < blake3::hash(&k2).as_bytes() { (k1, k2) } else { (k2, k1) };
        assert!(r.adopt(owner, g(hi.clone())), "a first registration is adopted");
        assert_eq!(r.resolve(&owner), Some(hi.as_slice()), "resolves the published blob");
        assert!(!r.adopt(owner, g(hi.clone())), "an identical re-registration changes nothing");
        assert!(r.adopt(owner, g(lo.clone())), "the smaller-hash key replaces the larger");
        assert!(!r.adopt(owner, g(hi.clone())), "the larger-hash key never displaces the smaller (order-free)");
        assert_eq!(r.resolve(&owner), Some(lo.as_slice()));
        assert_eq!(r.len(), 1, "one slot per owner");
        // the other arrival order lands on the same slot
        let mut r2 = ClueRegistry::new();
        r2.adopt(owner, g(lo.clone()));
        r2.adopt(owner, g(hi.clone()));
        assert_eq!(r.digest().to_vec(), r2.digest().to_vec(), "either arrival order → one directory, one digest");
        // a different owner has an independent slot; only its bucket differs
        let other = [2u8; 32];
        assert!(r.adopt(other, g(vec![5u8; 8])));
        assert_eq!(r.resolve(&other), Some(&[5u8; 8][..]));
        assert_eq!(r.resolve(&owner), Some(lo.as_slice()), "owners do not clobber each other");
        let peer = r2.digest().to_vec();
        let push = r.differing(&peer);
        assert_eq!(push.len(), 1, "only the differing bucket's registration is re-pushed");
        assert_eq!(push[0].clue_pk, vec![5u8; 8]);
        assert!(r.differing(&peer[..10]).is_empty(), "a wrong-width digest answers nothing (fail-closed)");
    }
}

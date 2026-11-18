// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Sphinx-style multi-hop onion mix (greenfield — NOT ported from the levin-derived mixnet).
//!
//! Sender-anonymous routing: a message is wrapped in one authenticated layer per hop. Each hop peels
//! EXACTLY its own layer — learning only the NEXT hop, never the origin or final destination — and
//! forwards the remainder. So no single hop links sender to recipient. Every layer is encrypt-then-MAC
//! (blake3 keystream + blake3 keyed-MAC): a flipped byte anywhere fails the MAC and the packet is
//! DROPPED (the Sphinx anti-tagging property), so an adversary cannot mark + trace a packet.
//!
//! Each hop's layer key is established by REAL post-quantum KEM: the sender ML-KEM-768-encapsulates to
//! the hop's public key ([`MixHop::kem_pubkey`], [`crate::pqkem`]), carrying the resulting ciphertext
//! in that hop's layer; the hop decapsulates it with its secret key ([`peel`]) to recover the same
//! 32-byte shared secret, which keys that layer. No classical Diffie-Hellman — key establishment is
//! post-quantum end to end, and each layer uses a fresh per-packet secret (no keystream reuse).
//! Peeled packets ride inside fixed-size cells ([`crate::net`]), so per-hop size changes never reach
//! the wire — SIZE stays hidden.

use crate::net::{NetError, OnionAddr};
use crate::pqkem;

/// Max hops in a route — a no-growth bound on mix work + packet size.
pub const MAX_HOPS: usize = 8;

const TAG_FORWARD: u8 = 1;
const TAG_DELIVER: u8 = 2;
/// Per-layer MAC length (full blake3 keyed hash).
const MAC_LEN: usize = 32;

/// One hop on a mix route: its onion address + its ML-KEM-768 public key. The sender encapsulates to
/// `kem_pubkey` to establish the per-hop layer key.
#[derive(Clone)]
pub struct MixHop {
    pub onion: OnionAddr,
    pub kem_pubkey: Vec<u8>,
}

/// The result of a mix peeling its layer.
#[derive(Debug, PartialEq, Eq)]
pub enum Peeled {
    /// Forward the remaining packet to `next`.
    Forward { next: OnionAddr, rest: Vec<u8> },
    /// This node is the exit: deliver `payload`.
    Deliver { payload: Vec<u8> },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MixError {
    #[error("empty route")]
    EmptyRoute,
    #[error("route exceeds MAX_HOPS ({0})")]
    TooManyHops(usize),
    #[error("malformed mix packet")]
    Malformed,
    #[error("layer MAC mismatch — tampered or wrong key (dropped)")]
    Tampered,
    #[error("invalid layer tag")]
    BadTag,
    #[error("PQ KEM encapsulation/decapsulation failed (malformed key or ciphertext)")]
    BadKem,
    #[error("invalid onion in layer: {0}")]
    BadOnion(#[from] NetError),
}

/// Derive the (encrypt, mac) subkeys for a layer from its 32-byte KEM shared secret.
fn subkeys(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        blake3::derive_key("musdm-mix-layer-enc-v1", shared_secret),
        blake3::derive_key("musdm-mix-layer-mac-v1", shared_secret),
    )
}

/// XOR `buf` with a blake3 keystream derived from `enc_key` (one layer = one fresh per-packet secret,
/// so there is no keystream reuse).
fn xor_keystream(enc_key: &[u8; 32], buf: &mut [u8]) {
    let mut reader = blake3::Hasher::new_keyed(enc_key).finalize_xof();
    let mut ks = vec![0u8; buf.len()];
    reader.fill(&mut ks);
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

/// Wrap one layer for a hop: `[kem_ct][MAC(32)][ciphertext]`, where `kem_ct` is the ML-KEM
/// encapsulation to the hop and `ciphertext` = keystream ⊕ `[tag][onion_len:u16][onion][inner]`,
/// keyed by the encapsulated shared secret. Fails if the hop's KEM key is malformed.
fn wrap_layer(
    kem_pubkey: &[u8],
    tag: u8,
    next: Option<&str>,
    inner: &[u8],
) -> Result<Vec<u8>, MixError> {
    let (ss, kem_ct) = pqkem::encapsulate(kem_pubkey).ok_or(MixError::BadKem)?;
    let onion = next.map(|s| s.as_bytes()).unwrap_or(&[]);
    let mut pt = Vec::with_capacity(3 + onion.len() + inner.len());
    pt.push(tag);
    pt.extend_from_slice(&(onion.len() as u16).to_le_bytes());
    pt.extend_from_slice(onion);
    pt.extend_from_slice(inner);

    let (ek, mk) = subkeys(&ss);
    xor_keystream(&ek, &mut pt);
    let mac = blake3::keyed_hash(&mk, &pt);

    let mut layer = Vec::with_capacity(kem_ct.len() + MAC_LEN + pt.len());
    layer.extend_from_slice(&kem_ct);
    layer.extend_from_slice(mac.as_bytes());
    layer.extend_from_slice(&pt);
    Ok(layer)
}

/// Build a mix packet: `payload` delivered at the last hop, routed through every hop in order,
/// encapsulating a fresh ML-KEM secret to each hop. The first hop's key peels the outermost layer.
pub fn wrap(payload: &[u8], hops: &[MixHop]) -> Result<Vec<u8>, MixError> {
    if hops.is_empty() {
        return Err(MixError::EmptyRoute);
    }
    if hops.len() > MAX_HOPS {
        return Err(MixError::TooManyHops(hops.len()));
    }
    let mut packet = payload.to_vec();
    for i in (0..hops.len()).rev() {
        let (tag, next) = if i == hops.len() - 1 {
            (TAG_DELIVER, None)
        } else {
            (TAG_FORWARD, Some(hops[i + 1].onion.as_str()))
        };
        packet = wrap_layer(&hops[i].kem_pubkey, tag, next, &packet)?;
    }
    Ok(packet)
}

/// Peel this hop's layer with its ML-KEM secret key: decapsulate the layer's KEM ciphertext to
/// recover the shared secret, verify the layer MAC (a tampered / wrong-key packet is DROPPED), then
/// return the next hop + remainder, or the delivered payload at the exit.
pub fn peel(packet: &[u8], kem_secret: &[u8]) -> Result<Peeled, MixError> {
    let ct_len = pqkem::ciphertext_len();
    if packet.len() < ct_len + MAC_LEN + 3 {
        return Err(MixError::Malformed);
    }
    let (kem_ct, rest) = packet.split_at(ct_len);
    let (mac, ct) = rest.split_at(MAC_LEN);
    let ss = pqkem::decapsulate(kem_ct, kem_secret).ok_or(MixError::BadKem)?;
    let (ek, mk) = subkeys(&ss);
    // MAC over the ciphertext — anti-tagging: any bit flip (or a wrong-key mismatched secret) fails.
    if blake3::keyed_hash(&mk, ct).as_bytes() != mac {
        return Err(MixError::Tampered);
    }
    let mut pt = ct.to_vec();
    xor_keystream(&ek, &mut pt);

    let tag = pt[0];
    let onion_len = u16::from_le_bytes([pt[1], pt[2]]) as usize;
    if 3 + onion_len > pt.len() {
        return Err(MixError::Malformed);
    }
    let onion_bytes = &pt[3..3 + onion_len];
    let inner = pt[3 + onion_len..].to_vec();
    match tag {
        TAG_DELIVER => Ok(Peeled::Deliver { payload: inner }),
        TAG_FORWARD => {
            let onion_str = std::str::from_utf8(onion_bytes).map_err(|_| MixError::Malformed)?;
            let next = OnionAddr::parse(onion_str)?; // rejects any non-onion / IP, even inside the mix
            Ok(Peeled::Forward { next, rest: inner })
        }
        _ => Err(MixError::BadTag),
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    // A hop with a REAL ML-KEM-768 keypair. Returns (the sender-side MixHop, the hop's secret key for
    // peeling). The onion label is 56 base32 chars derived from the seed (distinct per hop).
    fn hop(seed: u8) -> (MixHop, Vec<u8>) {
        let label: String = (0..56)
            .map(|i| (b'a' + (((seed as usize + i) % 26) as u8)) as char)
            .collect();
        let onion = OnionAddr::parse(&format!("{label}.onion")).unwrap();
        let (pk, sk) = pqkem::keypair();
        (
            MixHop {
                onion,
                kem_pubkey: pk,
            },
            sk,
        )
    }

    #[test]
    fn three_hop_route_delivers_end_to_end() {
        let (h1, s1) = hop(1);
        let (h2, s2) = hop(2);
        let (h3, s3) = hop(3);
        let route = [h1.clone(), h2.clone(), h3.clone()];
        let payload = b"a sender-anonymous private tx";
        let packet = wrap(payload, &route).unwrap();

        // hop 1 decapsulates + sees only hop 2 as the next hop.
        let rest1 = match peel(&packet, &s1).unwrap() {
            Peeled::Forward { next, rest } => {
                assert_eq!(next, h2.onion);
                rest
            }
            _ => panic!("expected forward"),
        };
        // hop 2 sees only hop 3.
        let rest2 = match peel(&rest1, &s2).unwrap() {
            Peeled::Forward { next, rest } => {
                assert_eq!(next, h3.onion);
                rest
            }
            _ => panic!("expected forward"),
        };
        // hop 3 is the exit: delivers the payload.
        match peel(&rest2, &s3).unwrap() {
            Peeled::Deliver { payload: got } => assert_eq!(got, payload),
            _ => panic!("expected deliver"),
        }
    }

    #[test]
    fn tampered_or_wrong_key_is_dropped() {
        let (h1, s1) = hop(7);
        let (h2, _s2) = hop(8);
        let route = [h1.clone(), h2];
        let mut packet = wrap(b"secret", &route).unwrap();
        // a single flipped byte in hop 1's MAC region fails the layer MAC (anti-tagging).
        let ct_len = pqkem::ciphertext_len();
        packet[ct_len + 5] ^= 0x01;
        assert_eq!(peel(&packet, &s1).unwrap_err(), MixError::Tampered);
        // a WRONG secret key decapsulates to a different secret (implicit reject) -> MAC fails -> drop.
        let good = wrap(b"secret", &route).unwrap();
        let (_hw, wrong_sk) = hop(99);
        assert_eq!(peel(&good, &wrong_sk).unwrap_err(), MixError::Tampered);
    }

    #[test]
    fn route_bounds_enforced() {
        assert_eq!(wrap(b"x", &[]).unwrap_err(), MixError::EmptyRoute);
        let long: Vec<MixHop> = (0..(MAX_HOPS as u8 + 1)).map(|i| hop(i).0).collect();
        assert!(matches!(
            wrap(b"x", &long).unwrap_err(),
            MixError::TooManyHops(_)
        ));
    }
}

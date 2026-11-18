// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The link between two neighbouring nodes: an ephemeral ML-KEM-768 exchange, the RESPONDER's ML-DSA-65 identity (the dialler proves
//! nothing: the responder names it only by its one-time KEM key, `anonymous_link_id`), then fixed-size encrypted frames. Every
//! frame is the same 9,032 bytes, whatever it carries. (Corrected 2026-11-15, lane af57: this line said "identities on both ends",
//! which the code has not done since the anonymous link; the code wins.)
//!
//! BORROWED: the initiator-pays handshake order from Tor proposal 327 (work before the responder's expensive step), the
//! ephemeral-KEM-plus-signature shape of PQ-KEM-DSA in Tor proposal 355 and of Katzenpost's PQ wire protocol.
//!
//! Forward secrecy comes from the ephemeral KEM key, thrown away after the handshake. An observer of a link sees that two
//! machines talk at a rate, and nothing of what the frames are.

use super::packet::{NodeId, KEM_CT, KEM_PK};
use super::record::{id_of, id_pow_valid, leading_zero_bits, DSA_PK, DSA_SIG, ID_POW_BITS};
use super::rng::Rng;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

pub const FRAME_PLAIN: usize = 9000;
const FRAME_MAC: usize = 32;
pub const FRAME_WIRE: usize = FRAME_PLAIN + FRAME_MAC;
/// The most a frame carries: `type 1 | len 2 | body`.
pub const FRAME_BODY: usize = FRAME_PLAIN - 3;

/// Work a dialer pays before this node does anything expensive.
const PUZZLE_BASE_BITS: u32 = 12;
const PUZZLE_MAX_BITS: u32 = 24;
const HANDSHAKE_SECS: u64 = 15;

/// The puzzle grows one bit per handshake already pending: an idle node asks for almost nothing and a flooded one asks for
/// more with every attempt. BORROWED: the effort rising with load in Tor's onion-service proof of work, on a plain hash.
pub fn puzzle_bits(pending: usize) -> u32 {
    (PUZZLE_BASE_BITS + pending.min((PUZZLE_MAX_BITS - PUZZLE_BASE_BITS) as usize) as u32).min(PUZZLE_MAX_BITS)
}

fn puzzle_hash(challenge: &[u8], eph_ek: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 link puzzle");
    h.update(challenge);
    h.update(eph_ek);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn puzzle_solved(challenge: &[u8], eph_ek: &[u8], nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&puzzle_hash(challenge, eph_ek, nonce)) >= bits
}

pub struct LinkKeys {
    send_stream: [u8; 32],
    send_mac: [u8; 32],
    recv_stream: [u8; 32],
    recv_mac: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
    /// The same 32 bytes on both ends of this one link and on no other link: what a hop signs to register with its gateway
    /// over THIS link (O5, `runtime.rs` F_HOP_PROOF), so a record copied off the network cannot be registered by anyone else.
    /// Derived from the shared secret and the transcript; it reveals neither.
    pub binding: [u8; 32],
}

impl Drop for LinkKeys {
    fn drop(&mut self) {
        self.send_stream.zeroize();
        self.send_mac.zeroize();
        self.recv_stream.zeroize();
        self.recv_mac.zeroize();
    }
}

/// The highest link version this node speaks, and the lowest it still accepts. The responder names its own in the first
/// message and the initiator answers at the lower of the two, so nodes upgrade one at a time with no flag day (the
/// project's Bitcoin model for upgrades). The runbook has the plan.
pub const LINK_VERSION: u8 = 2;
const LINK_VERSION_MIN: u8 = 2;

fn link_keys(ss: &[u8], transcript: &[u8; 32], initiator: bool) -> LinkKeys {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 link keys");
    h.update(ss);
    h.update(transcript);
    let mut o = [0u8; 128];
    h.finalize_xof().fill(&mut o);
    let k = |i: usize| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&o[i * 32..(i + 1) * 32]);
        a
    };
    let (a, b, c, d) = (k(0), k(1), k(2), k(3));
    let mut bh = blake3::Hasher::new_derive_key("monerousd mix v1 link binding");
    bh.update(ss);
    bh.update(transcript);
    let binding = *bh.finalize().as_bytes();
    if initiator {
        LinkKeys { send_stream: a, send_mac: b, recv_stream: c, recv_mac: d, send_ctr: 0, recv_ctr: 0, binding }
    } else {
        LinkKeys { send_stream: c, send_mac: d, recv_stream: a, recv_mac: b, send_ctr: 0, recv_ctr: 0, binding }
    }
}

fn frame_stream(key: &[u8; 32], ctr: u64, out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&ctr.to_le_bytes());
    let mut ks = vec![0u8; out.len()];
    h.finalize_xof().fill(&mut ks);
    for (b, x) in out.iter_mut().zip(ks.iter()) {
        *b ^= x;
    }
}

/// `blake3::Hash` compares in constant time.
fn frame_mac(key: &[u8; 32], ctr: u64, ct: &[u8]) -> blake3::Hash {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&ctr.to_le_bytes());
    h.update(ct);
    h.finalize()
}

/// A frame ready for the wire. The counter is implicit, so a replayed, reordered or dropped frame breaks the MAC.
pub fn seal(keys: &mut LinkKeys, kind: u8, body: &[u8], rng: &mut Rng) -> Option<Vec<u8>> {
    if body.len() > FRAME_BODY {
        return None;
    }
    let mut plain = vec![0u8; FRAME_PLAIN];
    plain[0] = kind;
    plain[1..3].copy_from_slice(&(body.len() as u16).to_le_bytes());
    plain[3..3 + body.len()].copy_from_slice(body);
    rng.fill(&mut plain[3 + body.len()..]);
    frame_stream(&keys.send_stream, keys.send_ctr, &mut plain);
    let tag = frame_mac(&keys.send_mac, keys.send_ctr, &plain);
    keys.send_ctr += 1;
    plain.extend_from_slice(tag.as_bytes());
    Some(plain)
}

/// Opens one frame. `None` means the link is finished: a frame with the wrong MAC has no recovery on a counter-keyed link.
pub fn open(keys: &mut LinkKeys, wire: &[u8]) -> Option<(u8, Vec<u8>)> {
    if wire.len() != FRAME_WIRE {
        return None;
    }
    let (ct, tag) = wire.split_at(FRAME_PLAIN);
    if frame_mac(&keys.recv_mac, keys.recv_ctr, ct) != *tag {
        return None;
    }
    let mut plain = ct.to_vec();
    frame_stream(&keys.recv_stream, keys.recv_ctr, &mut plain);
    keys.recv_ctr += 1;
    let len = u16::from_le_bytes([plain[1], plain[2]]) as usize;
    if len > FRAME_BODY {
        return None;
    }
    Some((plain[0], plain[3..3 + len].to_vec()))
}

/// The frame door on hostile bytes, for the fuzz targets: keys no one holds, so nothing should ever open. No state is kept.
pub fn hostile_frame(bytes: &[u8]) -> bool {
    let mut k = link_keys(&[7u8; 32], &[9u8; 32], false);
    open(&mut k, bytes).is_some()
}

/// What each side proves about itself in the handshake.
pub struct Me<'a> {
    pub dsa_pk: &'a [u8],
    pub dsa_sk: &'a [u8],
    pub pow_nonce: u64,
}

fn peer_id_checked(dsa_pk: &[u8], pow_nonce: u64) -> Option<NodeId> {
    id_pow_valid(dsa_pk, pow_nonce, ID_POW_BITS).then(|| id_of(dsa_pk))
}

fn transcript(challenge: &[u8], bits: u32, nonce: u64, eph_ek: &[u8], ct: &[u8], responder_pk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 link transcript");
    h.update(challenge);
    h.update(&bits.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    h.update(eph_ek);
    h.update(ct);
    h.update(responder_pk);
    *h.finalize().as_bytes()
}

const RESP_SIG_DOMAIN: &[u8] = b"monerousd mix v1 link responder";

/// What the answering side calls a link it did not dial: a name made from the dialler's one-time key, so it means nothing outside
/// this link and two dials from one machine look like two strangers. User 2026-11-07: no path from a hidden address to an IP.
/// This is the first hop's whole knowledge of who dialled: an IP and this.
fn anonymous_link_id(eph_ek: &[u8]) -> NodeId {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v2 anonymous link");
    h.update(eph_ek);
    *h.finalize().as_bytes()
}

fn sign_with(domain: &[u8], t: &[u8; 32], sk: &[u8]) -> Option<Vec<u8>> {
    let mut m = domain.to_vec();
    m.extend_from_slice(t);
    crate::pqauth::ml_dsa_sign(&m, sk)
}

fn verify_with(domain: &[u8], t: &[u8; 32], pk: &[u8], sig: &[u8]) -> bool {
    let mut m = domain.to_vec();
    m.extend_from_slice(t);
    crate::pqauth::ml_dsa_verify(&m, pk, sig)
}

/// The dialing side. `expect` is the id this node meant to reach, when it knows one. A seed is an address with no id yet.
/// The dialler proves nothing about itself: it checks who it reached, and the far end learns only that someone dialled.
pub async fn initiate<S>(s: &mut S, expect: Option<NodeId>) -> Option<(NodeId, LinkKeys)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    tokio::time::timeout(std::time::Duration::from_secs(HANDSHAKE_SECS), initiate_inner(s, expect)).await.ok()?
}

async fn initiate_inner<S>(s: &mut S, expect: Option<NodeId>) -> Option<(NodeId, LinkKeys)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut hello = [0u8; 34];
    s.read_exact(&mut hello).await.ok()?;
    let (challenge, bits) = (&hello[..32], hello[32] as u32);
    // A responder cannot ask for more than the protocol's ceiling: it would only hang the dialer.
    if bits > PUZZLE_MAX_BITS || hello[33].min(LINK_VERSION) < LINK_VERSION_MIN {
        return None;
    }
    let (eph_pk, eph_sk) = mlkem768::keypair();
    let eph_ek = eph_pk.as_bytes().to_vec();
    let mut nonce = 0u64;
    while !puzzle_solved(challenge, &eph_ek, nonce, bits) {
        nonce += 1;
        if nonce % 4096 == 0 {
            tokio::task::yield_now().await;
        }
    }
    let mut out = Vec::with_capacity(8 + KEM_PK);
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(&eph_ek);
    s.write_all(&out).await.ok()?;

    let mut reply = vec![0u8; KEM_CT + DSA_PK + 8 + DSA_SIG];
    s.read_exact(&mut reply).await.ok()?;
    let ct_bytes = &reply[..KEM_CT];
    let peer_pk = &reply[KEM_CT..KEM_CT + DSA_PK];
    let mut n = [0u8; 8];
    n.copy_from_slice(&reply[KEM_CT + DSA_PK..KEM_CT + DSA_PK + 8]);
    let peer_nonce = u64::from_le_bytes(n);
    let sig = &reply[KEM_CT + DSA_PK + 8..];

    let t = transcript(challenge, bits, nonce, &eph_ek, ct_bytes, peer_pk);
    let peer = peer_id_checked(peer_pk, peer_nonce)?;
    if let Some(want) = expect {
        if want != peer {
            return None;
        }
    }
    if !verify_with(RESP_SIG_DOMAIN, &t, peer_pk, sig) {
        return None;
    }
    let ct = mlkem768::Ciphertext::from_bytes(ct_bytes).ok()?;
    let ss = mlkem768::decapsulate(&ct, &eph_sk);
    s.flush().await.ok()?;
    Some((peer, link_keys(ss.as_bytes(), &t, true)))
}

/// The answering side. `bits` is this node's current puzzle; nothing costly happens until it is solved.
pub async fn respond<S>(s: &mut S, me: &Me<'_>, bits: u32, rng: &mut Rng) -> Option<(NodeId, LinkKeys)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let challenge = rng.bytes32();
    tokio::time::timeout(std::time::Duration::from_secs(HANDSHAKE_SECS), respond_inner(s, me, bits, challenge)).await.ok()?
}

async fn respond_inner<S>(s: &mut S, me: &Me<'_>, bits: u32, challenge: [u8; 32]) -> Option<(NodeId, LinkKeys)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut hello = [0u8; 34];
    hello[..32].copy_from_slice(&challenge);
    hello[32] = bits as u8;
    hello[33] = LINK_VERSION;
    s.write_all(&hello).await.ok()?;
    let mut req = vec![0u8; 8 + KEM_PK];
    s.read_exact(&mut req).await.ok()?;
    let mut n = [0u8; 8];
    n.copy_from_slice(&req[..8]);
    let nonce = u64::from_le_bytes(n);
    let eph_ek = &req[8..];
    if !puzzle_solved(&challenge, eph_ek, nonce, bits) {
        return None;
    }
    let pk = mlkem768::PublicKey::from_bytes(eph_ek).ok()?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    let t = transcript(&challenge, bits, nonce, eph_ek, ct.as_bytes(), me.dsa_pk);
    let sig = sign_with(RESP_SIG_DOMAIN, &t, me.dsa_sk)?;
    let mut out = Vec::with_capacity(KEM_CT + DSA_PK + 8 + DSA_SIG);
    out.extend_from_slice(ct.as_bytes());
    out.extend_from_slice(me.dsa_pk);
    out.extend_from_slice(&me.pow_nonce.to_le_bytes());
    out.extend_from_slice(&sig);
    s.write_all(&out).await.ok()?;
    s.flush().await.ok()?;
    Some((anonymous_link_id(eph_ek), link_keys(ss.as_bytes(), &t, false)))
}

// TWO-PARTY-REVIEWED: two independent ends over a real in-memory duplex, each with its own identity and keys. Real TCP between
// real processes is `mix_cut.py` and `mix_attack`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqmix::record::Identity;

    fn identity(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("mix-link-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = Identity::load_or_mint(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        id
    }

    fn me(i: &Identity) -> Me<'_> {
        Me { dsa_pk: &i.dsa_pk, dsa_sk: &i.dsa_sk, pow_nonce: i.pow_nonce }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn the_dialler_learns_who_it_reached_and_the_far_end_learns_nothing_about_the_dialler() {
        let (a, b) = (identity("a1"), identity("b1"));
        rt().block_on(async {
            let (mut x, mut y) = tokio::io::duplex(64 * 1024);
            let mut rng = Rng::new();
            let mb = me(&b);
            let (ra, rb) = tokio::join!(initiate(&mut x, Some(b.id)), respond(&mut y, &mb, 4, &mut rng));
            let (peer_of_a, mut ka) = ra.unwrap();
            let (peer_of_b, mut kb) = rb.unwrap();
            assert_eq!(peer_of_a, b.id);
            assert_ne!(peer_of_b, a.id, "the far end must not learn the dialler's identity");
            // A second dial from the same machine reads as a stranger.
            let (mut x2, mut y2) = tokio::io::duplex(64 * 1024);
            let (ra2, rb2) = tokio::join!(initiate(&mut x2, Some(b.id)), respond(&mut y2, &mb, 4, &mut rng));
            assert!(ra2.is_some());
            assert_ne!(rb2.unwrap().0, peer_of_b, "two dials must not be linkable by the name the far end gives them");
            let mut r = Rng::new();
            let f = seal(&mut ka, 1, b"hello", &mut r).unwrap();
            assert_eq!(f.len(), FRAME_WIRE, "every frame is one size");
            assert_eq!(open(&mut kb, &f).unwrap(), (1, b"hello".to_vec()));
            let g = seal(&mut kb, 2, &vec![7u8; FRAME_BODY], &mut r).unwrap();
            assert_eq!(g.len(), FRAME_WIRE, "a full frame is the same size as a short one");
            assert_eq!(open(&mut ka, &g).unwrap(), (2, vec![7u8; FRAME_BODY]));
        });
    }

    #[test]
    fn a_dialer_refuses_a_responder_with_the_wrong_identity() {
        let b = identity("b2");
        rt().block_on(async {
            let (mut x, mut y) = tokio::io::duplex(64 * 1024);
            let mut rng = Rng::new();
            let wanted = [9u8; 32];
            let mb = me(&b);
            let (ra, _rb) = tokio::join!(initiate(&mut x, Some(wanted)), async {
                let r = respond(&mut y, &mb, 4, &mut rng).await;
                drop(y);
                r
            });
            assert!(ra.is_none(), "a node impersonating the wanted id must not get a link");
        });
    }

    #[test]
    fn a_frame_replayed_reordered_or_changed_is_refused() {
        let b = identity("b3");
        rt().block_on(async {
            let (mut x, mut y) = tokio::io::duplex(64 * 1024);
            let mut rng = Rng::new();
            let mb = me(&b);
            let (ra, rb) = tokio::join!(initiate(&mut x, None), respond(&mut y, &mb, 4, &mut rng));
            let (_, mut ka) = ra.unwrap();
            let (_, mut kb) = rb.unwrap();
            let mut r = Rng::new();
            let f0 = seal(&mut ka, 1, b"zero", &mut r).unwrap();
            let f1 = seal(&mut ka, 1, b"one", &mut r).unwrap();
            assert!(open(&mut kb, &f1).is_none(), "a frame out of order is refused");
            assert!(open(&mut kb, &f0).is_some());
            assert!(open(&mut kb, &f0).is_none(), "a repeated frame is refused");
            let mut bad = f1.clone();
            bad[100] ^= 1;
            assert!(open(&mut kb, &bad).is_none(), "a changed frame is refused");
            assert!(open(&mut kb, &f1).is_some(), "the honest frame still opens: a refusal consumes nothing");
        });
    }

    #[test]
    fn an_unsolved_puzzle_gets_no_signature() {
        let b = identity("b4");
        rt().block_on(async {
            let (mut x, mut y) = tokio::io::duplex(64 * 1024);
            let mut rng = Rng::new();
            let attacker = async {
                let mut hello = [0u8; 34];
                x.read_exact(&mut hello).await.unwrap();
                let (pk, _) = mlkem768::keypair();
                // Search for a nonce that fails at this difficulty.
                let nonce = (0u64..).find(|n| !puzzle_solved(&hello[..32], pk.as_bytes(), *n, hello[32] as u32)).unwrap();
                let mut out = nonce.to_le_bytes().to_vec();
                out.extend_from_slice(pk.as_bytes());
                x.write_all(&out).await.unwrap();
                let mut one = [0u8; 1];
                x.read(&mut one).await.unwrap_err_or_zero()
            };
            let mb = me(&b);
            // The responder's end closes when it refuses, as a real connection does, so the attacker's read ends.
            let responder = async {
                let r = respond(&mut y, &mb, 16, &mut rng).await;
                drop(y);
                r
            };
            let (n, r) = tokio::join!(attacker, responder);
            assert!(r.is_none());
            assert_eq!(n, 0, "the responder sent {n} bytes to a dialer who paid nothing");
        });
    }

    trait ZeroOnErr {
        fn unwrap_err_or_zero(self) -> usize;
    }
    impl ZeroOnErr for std::io::Result<usize> {
        fn unwrap_err_or_zero(self) -> usize {
            match self {
                Ok(n) => n,
                Err(_) => 0,
            }
        }
    }

    #[test]
    fn the_puzzle_rises_with_pending_handshakes_and_stops_at_its_ceiling() {
        assert_eq!(puzzle_bits(0), PUZZLE_BASE_BITS);
        assert_eq!(puzzle_bits(3), PUZZLE_BASE_BITS + 3);
        assert_eq!(puzzle_bits(1_000_000), PUZZLE_MAX_BITS);
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The mix packet: KEM Sphinx over ML-KEM-768, one constant size, a hop never learns its position.
//!
//! BORROWED: Sphinx (Danezis & Goldberg 2009) for the header layering and filler, KEM Sphinx (Stainton 2023, Katzenpost)
//! for the KEM ciphertext standing in the group element's place, LIONESS (Anderson & Biham 1996) for the wide-block body,
//! a replay set per key epoch (Katzenpost). Layout and costs: docs/PQ-MIX-LAYER-SPEC-20261106.md §2.1.
//!
//! A hop decapsulates, checks the MAC over `ct || beta`, refuses a replay, then reads its slot and shifts. Modifying any
//! header byte fails the next honest MAC. Modifying any body byte scrambles the whole body and fails the final zero tag,
//! so a relay cannot tag a packet and recognise it further on.

use super::rng::Rng;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::Zeroize;

/// Every route is exactly this long: 2 relays and the destination, the 3 hops the spec names (§4) and Tor and Loopix use. Each hop
/// costs a 1,088-byte ML-KEM ciphertext in every packet's header, so the fourth hop took 1,156 B of each 8,960-byte packet and
/// left 4.2 KB of payload. MEASURED: a 414 KB payment push took 52 s and 60 s at the standby rate. Three hops carry about 27 %
/// more per packet at the same bandwidth and the same cover rate. Any one honest relay on a route still unlinks it.
pub const HOPS: usize = 3;
pub const KEM_CT: usize = 1088;
pub const KEM_PK: usize = 1184;
pub const MAC: usize = 32;
/// `cmd 1 | delay_ms 3 | next id 32`.
pub const ROUTE: usize = 36;
pub const SLOT: usize = ROUTE + KEM_CT + MAC;
pub const BETA: usize = (HOPS - 1) * SLOT + ROUTE;
pub const HEADER: usize = KEM_CT + MAC + BETA;
pub const PACKET: usize = 8960;
pub const BODY: usize = PACKET - HEADER;
const ZERO_TAG: usize = 32;
/// What one packet can carry to its destination.
pub const INNER: usize = BODY - ZERO_TAG;

const CMD_FORWARD: u8 = 0;
const CMD_DELIVER: u8 = 1;
/// The longest delay a route byte field can name; a sender's exponential draw is cut here (about 4.6 hours is never reached).
const DELAY_MAX_MS: u32 = (1 << 24) - 1;

pub type NodeId = [u8; 32];

struct HopKeys {
    mac: [u8; 32],
    stream: [u8; 32],
    body: [u8; 32],
    replay: [u8; 32],
}

impl Drop for HopKeys {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.stream.zeroize();
        self.body.zeroize();
        self.replay.zeroize();
    }
}

/// A KEM secret key held only in RAM, overwritten when it is dropped, so a seized machine holds no key older than the
/// previous epoch. The library's type gives no mutable access, so it is overwritten whole with a volatile write. A copy the
/// library made during key generation is outside this reach; the spec lists that for the audit.
pub struct KemSecret(mlkem768::SecretKey);

impl Drop for KemSecret {
    fn drop(&mut self) {
        if let Ok(blank) = mlkem768::SecretKey::from_bytes(&[0u8; mlkem768::secret_key_bytes()]) {
            // SAFETY: `self.0` is a valid, exclusively borrowed `SecretKey`, and `blank` is a value of the same type.
            unsafe { std::ptr::write_volatile(&mut self.0, blank) };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Wipes a shared secret the same way once its keys are derived.
fn wipe_shared_secret(mut ss: mlkem768::SharedSecret) {
    if let Ok(blank) = mlkem768::SharedSecret::from_bytes(&[0u8; mlkem768::shared_secret_bytes()]) {
        // SAFETY: `ss` is a valid value this function owns, and `blank` is a value of the same type.
        unsafe { std::ptr::write_volatile(&mut ss, blank) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Binds the shared secret to the ciphertext that produced it, so a hop's keys are specific to this one encapsulation.
fn hop_keys(ss: &[u8], ct: &[u8]) -> HopKeys {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 hop keys");
    h.update(ss);
    h.update(ct);
    let mut out = [0u8; 128];
    h.finalize_xof().fill(&mut out);
    let take = |i: usize| {
        let mut k = [0u8; 32];
        k.copy_from_slice(&out[i * 32..(i + 1) * 32]);
        k
    };
    HopKeys { mac: take(0), stream: take(1), body: take(2), replay: take(3) }
}

fn xor_stream(key: &[u8; 32], out: &mut [u8]) {
    let mut ks = vec![0u8; out.len()];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut ks);
    for (b, k) in out.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

/// `blake3::Hash` compares in constant time, so a forger learns nothing from how long a refusal takes.
fn header_mac(key: &[u8; 32], ct: &[u8], beta: &[u8]) -> blake3::Hash {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(ct);
    h.update(beta);
    h.finalize()
}

/// Four-round Feistel over the whole body, so one flipped bit becomes noise everywhere.
fn lioness_round_keys(key: &[u8; 32]) -> [[u8; 32]; 4] {
    let mut out = [0u8; 128];
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 lioness");
    h.update(key);
    h.finalize_xof().fill(&mut out);
    let mut ks = [[0u8; 32]; 4];
    for (i, k) in ks.iter_mut().enumerate() {
        k.copy_from_slice(&out[i * 32..(i + 1) * 32]);
    }
    ks
}

fn lioness_stream_round(k: &[u8; 32], left: &[u8], right: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(k);
    h.update(left);
    let mut ks = vec![0u8; right.len()];
    h.finalize_xof().fill(&mut ks);
    for (b, x) in right.iter_mut().zip(ks.iter()) {
        *b ^= x;
    }
}

fn lioness_hash_round(k: &[u8; 32], right: &[u8], left: &mut [u8]) {
    let d = blake3::keyed_hash(k, right);
    for (b, x) in left.iter_mut().zip(d.as_bytes().iter()) {
        *b ^= x;
    }
}

fn lioness_encrypt(key: &[u8; 32], body: &mut [u8]) {
    let ks = lioness_round_keys(key);
    let (l, r) = body.split_at_mut(32);
    lioness_stream_round(&ks[0], l, r);
    lioness_hash_round(&ks[1], r, l);
    lioness_stream_round(&ks[2], l, r);
    lioness_hash_round(&ks[3], r, l);
}

fn lioness_decrypt(key: &[u8; 32], body: &mut [u8]) {
    let ks = lioness_round_keys(key);
    let (l, r) = body.split_at_mut(32);
    lioness_hash_round(&ks[3], r, l);
    lioness_stream_round(&ks[2], l, r);
    lioness_hash_round(&ks[1], r, l);
    lioness_stream_round(&ks[0], l, r);
}

/// One hop of a route the sender chose.
pub struct Hop {
    pub id: NodeId,
    pub kem_pk: Vec<u8>,
    pub delay_ms: u32,
}

/// Build one packet. The first hop is who it is handed to; the last is who reads `inner`, which is padded with random
/// bytes to the constant size. `None` if a key is malformed or the route is not exactly [`HOPS`] long.
pub fn build(route: &[Hop], inner: &[u8], rng: &mut Rng) -> Option<Vec<u8>> {
    if route.len() != HOPS || inner.len() > INNER {
        return None;
    }
    let mut cts: Vec<Vec<u8>> = Vec::with_capacity(HOPS);
    let mut keys: Vec<HopKeys> = Vec::with_capacity(HOPS);
    for hop in route {
        let pk = mlkem768::PublicKey::from_bytes(&hop.kem_pk).ok()?;
        let (ss, ct) = mlkem768::encapsulate(&pk);
        let ct = ct.as_bytes().to_vec();
        keys.push(hop_keys(ss.as_bytes(), &ct));
        wipe_shared_secret(ss);
        cts.push(ct);
    }
    // The filler: what a hop's shift appends, so every later MAC verifies over bytes the sender already knows.
    let mut filler: Vec<u8> = Vec::new();
    for k in keys.iter().take(HOPS - 1) {
        filler.extend_from_slice(&[0u8; SLOT]);
        let mut ks = vec![0u8; BETA + SLOT];
        blake3::Hasher::new_keyed(&k.stream).finalize_xof().fill(&mut ks);
        let start = BETA + SLOT - filler.len();
        for (b, x) in filler.iter_mut().zip(ks[start..].iter()) {
            *b ^= x;
        }
    }
    // The last hop: its route is plain under its own stream, then the filler. Its slot after the route is never read.
    let mut last_route = [0u8; ROUTE];
    last_route[0] = CMD_DELIVER;
    last_route[1..4].copy_from_slice(&route[HOPS - 1].delay_ms.min(DELAY_MAX_MS).to_le_bytes()[..3]);
    rng.fill(&mut last_route[4..]);
    let mut beta = vec![0u8; BETA];
    beta[..ROUTE].copy_from_slice(&last_route);
    let mut ks = vec![0u8; BETA + SLOT];
    blake3::Hasher::new_keyed(&keys[HOPS - 1].stream).finalize_xof().fill(&mut ks);
    for (b, x) in beta[..ROUTE].iter_mut().zip(ks.iter()) {
        *b ^= x;
    }
    beta[ROUTE..].copy_from_slice(&filler);
    let mut gamma = *header_mac(&keys[HOPS - 1].mac, &cts[HOPS - 1], &beta).as_bytes();
    // Inward from the last hop to the first.
    for i in (0..HOPS - 1).rev() {
        let mut plain = vec![0u8; BETA];
        plain[0] = CMD_FORWARD;
        plain[1..4].copy_from_slice(&route[i].delay_ms.min(DELAY_MAX_MS).to_le_bytes()[..3]);
        plain[4..ROUTE].copy_from_slice(&route[i + 1].id);
        plain[ROUTE..ROUTE + KEM_CT].copy_from_slice(&cts[i + 1]);
        plain[ROUTE + KEM_CT..SLOT].copy_from_slice(&gamma);
        plain[SLOT..].copy_from_slice(&beta[..BETA - SLOT]);
        xor_stream(&keys[i].stream, &mut plain);
        beta = plain;
        gamma = *header_mac(&keys[i].mac, &cts[i], &beta).as_bytes();
    }
    // The body: zero tag, the message, random fill; layered so every hop strips one wide-block layer.
    let mut body = vec![0u8; BODY];
    body[ZERO_TAG..ZERO_TAG + inner.len()].copy_from_slice(inner);
    rng.fill(&mut body[ZERO_TAG + inner.len()..]);
    for k in keys.iter().rev() {
        lioness_encrypt(&k.body, &mut body);
    }
    let mut pkt = Vec::with_capacity(PACKET);
    pkt.extend_from_slice(&cts[0]);
    pkt.extend_from_slice(&gamma);
    pkt.extend_from_slice(&beta);
    pkt.extend_from_slice(&body);
    Some(pkt)
}

/// What a hop does with a packet after peeling one layer.
#[derive(Debug, PartialEq, Eq)]
pub enum Peeled {
    Forward { next: NodeId, delay_ms: u32, packet: Vec<u8> },
    /// `inner` is [`INNER`] bytes long: the message followed by the sender's random fill. Framing it is the caller's job.
    Deliver { delay_ms: u32, inner: Vec<u8> },
}

/// Why a packet was refused. A packet refused here goes nowhere, and nothing about it is sent back.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Refused {
    WrongSize,
    /// The MAC failed under every held key: a forged or modified header, or a key this hop has destroyed.
    BadMac,
    Replay,
    /// The last hop's zero tag failed: the body was modified on the way.
    Tagged,
}

/// A replay set, one per KEM key. It must never forget a tag it has seen and may report a tag it has not.
pub trait ReplaySet {
    /// True the first time a tag is seen. A later call with the same tag answers false.
    fn insert_new(&mut self, tag: &[u8; 32]) -> bool;
}

/// One key this hop can decapsulate with, and that key's replay set. Current first.
pub struct HopKey<'a, R: ReplaySet> {
    pub sk: &'a KemSecret,
    pub replay: &'a mut R,
}

/// Peel one layer under the current or previous epoch key. ML-KEM's implicit rejection gives a wrong ciphertext a
/// random secret, so the MAC is what decides: it runs before the replay check, so junk cannot fill the set.
pub fn peel<R: ReplaySet>(packet: &[u8], held: &mut [HopKey<'_, R>]) -> Result<Peeled, Refused> {
    if packet.len() != PACKET {
        return Err(Refused::WrongSize);
    }
    let ct_bytes = &packet[..KEM_CT];
    let gamma = &packet[KEM_CT..KEM_CT + MAC];
    let beta = &packet[KEM_CT + MAC..HEADER];
    let ct = mlkem768::Ciphertext::from_bytes(ct_bytes).map_err(|_| Refused::BadMac)?;
    for key in held.iter_mut() {
        let ss = mlkem768::decapsulate(&ct, &key.sk.0);
        let k = hop_keys(ss.as_bytes(), ct_bytes);
        wipe_shared_secret(ss);
        if header_mac(&k.mac, ct_bytes, beta) != *gamma {
            continue;
        }
        if !key.replay.insert_new(&k.replay) {
            return Err(Refused::Replay);
        }
        let mut ext = vec![0u8; BETA + SLOT];
        ext[..BETA].copy_from_slice(beta);
        xor_stream(&k.stream, &mut ext);
        let delay_ms = u32::from_le_bytes([ext[1], ext[2], ext[3], 0]);
        let mut body = packet[HEADER..].to_vec();
        lioness_decrypt(&k.body, &mut body);
        return match ext[0] {
            CMD_DELIVER => {
                if body[..ZERO_TAG].iter().any(|b| *b != 0) {
                    return Err(Refused::Tagged);
                }
                Ok(Peeled::Deliver { delay_ms, inner: body[ZERO_TAG..].to_vec() })
            }
            CMD_FORWARD => {
                let mut next = [0u8; 32];
                next.copy_from_slice(&ext[4..ROUTE]);
                let mut out = Vec::with_capacity(PACKET);
                out.extend_from_slice(&ext[ROUTE..ROUTE + KEM_CT]);
                out.extend_from_slice(&ext[ROUTE + KEM_CT..SLOT]);
                out.extend_from_slice(&ext[SLOT..SLOT + BETA]);
                out.extend_from_slice(&body);
                Ok(Peeled::Forward { next, delay_ms, packet: out })
            }
            // The MAC passed, so the sender wrote this byte itself: a malformed route, refused the same way.
            _ => Err(Refused::BadMac),
        };
    }
    Err(Refused::BadMac)
}

/// A KEM keypair as the mix holds it. Secrets stay in RAM: a restart mints a new one, and forward secrecy needs that.
pub fn kem_keypair() -> (Vec<u8>, KemSecret) {
    let (pk, sk) = mlkem768::keypair();
    (pk.as_bytes().to_vec(), KemSecret(sk))
}

/// A record's key must parse before any route is built on it.
pub fn kem_pk_is_valid(pk: &[u8]) -> bool {
    pk.len() == KEM_PK && mlkem768::PublicKey::from_bytes(pk).is_ok()
}

// TWO-PARTY-REVIEWED: every test here carries a packet through separate per-hop keys, and each hop holds only its own secret.
// The real crossing between processes is `mix_cut.py` and the attack rows in scratchpad/net/attacks.txt.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqmix::replay::ReplayBloom;

    struct Node {
        id: NodeId,
        pk: Vec<u8>,
        sk: KemSecret,
        replay: ReplayBloom,
    }

    fn nodes(n: usize) -> Vec<Node> {
        (0..n)
            .map(|i| {
                let (pk, sk) = kem_keypair();
                Node { id: [i as u8 + 1; 32], pk, sk, replay: ReplayBloom::new() }
            })
            .collect()
    }

    fn route(ns: &[Node]) -> Vec<Hop> {
        ns.iter().map(|n| Hop { id: n.id, kem_pk: n.pk.clone(), delay_ms: 7 }).collect()
    }

    fn at<'a>(n: &'a mut Node) -> [HopKey<'a, ReplayBloom>; 1] {
        [HopKey { sk: &n.sk, replay: &mut n.replay }]
    }

    /// Walks a packet through every hop; the destination must read the message.
    fn carry(ns: &mut [Node], mut pkt: Vec<u8>) -> Result<Vec<u8>, Refused> {
        for i in 0..HOPS {
            assert_eq!(pkt.len(), PACKET, "the packet keeps one size at every hop");
            match peel(&pkt, &mut at(&mut ns[i]))? {
                Peeled::Forward { next, delay_ms, packet } => {
                    assert_eq!(next, ns[i + 1].id, "hop {i} forwards to the hop the sender chose");
                    assert_eq!(delay_ms, 7);
                    pkt = packet;
                }
                Peeled::Deliver { delay_ms, inner } => {
                    assert_eq!(i, HOPS - 1, "only the last hop delivers");
                    assert_eq!(delay_ms, 7);
                    return Ok(inner);
                }
            }
        }
        panic!("the route ended with no delivery");
    }

    #[test]
    fn a_packet_crosses_every_hop_and_the_destination_reads_it() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"a message", &mut rng).unwrap();
        let inner = carry(&mut ns, pkt).unwrap();
        assert_eq!(&inner[..9], b"a message");
        assert_eq!(inner.len(), INNER);
    }

    #[test]
    fn a_hop_cannot_tell_its_position_from_the_format() {
        // Same length at each hop, and the bytes change at every hop: no field a relay or link observer could match.
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let mut pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        for n in ns.iter_mut().take(HOPS - 1) {
            let Peeled::Forward { packet, .. } = peel(&pkt, &mut at(n)).unwrap() else { panic!() };
            assert_eq!(packet.len(), pkt.len());
            let same = pkt.iter().zip(packet.iter()).filter(|(a, b)| a == b).count();
            assert!(same < PACKET / 64, "{same} of {PACKET} bytes survive a hop unchanged: a link observer could match them");
            pkt = packet;
        }
    }

    #[test]
    fn a_replayed_packet_is_refused_at_the_hop_that_saw_it() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        assert!(peel(&pkt, &mut at(&mut ns[0])).is_ok());
        assert_eq!(peel(&pkt, &mut at(&mut ns[0])).unwrap_err(), Refused::Replay);
    }

    #[test]
    fn a_replayed_packet_is_refused_further_on_too() {
        // A relay replaying the packet it forwarded: the next hop has already seen it.
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        let Peeled::Forward { packet, .. } = peel(&pkt, &mut at(&mut ns[0])).unwrap() else { panic!() };
        assert!(peel(&packet, &mut at(&mut ns[1])).is_ok());
        assert_eq!(peel(&packet, &mut at(&mut ns[1])).unwrap_err(), Refused::Replay);
    }

    #[test]
    fn a_tagged_body_is_refused_at_the_destination_for_every_hop_that_could_tag_it() {
        for tagger in 0..HOPS - 1 {
            let mut ns = nodes(HOPS);
            let mut rng = Rng::new();
            let mut pkt = build(&route(&ns), b"secret", &mut rng).unwrap();
            for i in 0..=tagger {
                let Peeled::Forward { packet, .. } = peel(&pkt, &mut at(&mut ns[i])).unwrap() else { panic!() };
                pkt = packet;
            }
            pkt[HEADER + 100] ^= 1; // one bit, as a tagging attack flips
            let mut res = None;
            for n in ns.iter_mut().skip(tagger + 1) {
                match peel(&pkt, &mut at(n)) {
                    Ok(Peeled::Forward { packet, .. }) => pkt = packet,
                    other => {
                        res = Some(other);
                        break;
                    }
                }
            }
            assert_eq!(res, Some(Err(Refused::Tagged)), "a body tagged after hop {tagger} must fail the final tag");
        }
    }

    #[test]
    fn a_body_tagged_in_the_last_32_bytes_is_refused_as_well() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let mut pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        for n in ns.iter_mut().take(HOPS - 1) {
            let Peeled::Forward { packet, .. } = peel(&pkt, &mut at(n)).unwrap() else { panic!() };
            pkt = packet;
        }
        pkt[PACKET - 1] ^= 1;
        assert_eq!(peel(&pkt, &mut at(&mut ns[HOPS - 1])).unwrap_err(), Refused::Tagged);
    }

    #[test]
    fn a_forged_route_header_is_refused_wherever_it_is_changed() {
        // Each region of the header, and each hop's view of it.
        for region in [0usize, KEM_CT - 1, KEM_CT, KEM_CT + MAC - 1, KEM_CT + MAC, KEM_CT + MAC + SLOT, HEADER - 1] {
            let mut ns = nodes(HOPS);
            let mut rng = Rng::new();
            let mut pkt = build(&route(&ns), b"x", &mut rng).unwrap();
            pkt[region] ^= 1;
            assert_eq!(peel(&pkt, &mut at(&mut ns[0])).unwrap_err(), Refused::BadMac, "first hop, byte {region}");
            // A relay rewriting the header it forwards fails at the next honest MAC.
            let mut ns = nodes(HOPS);
            let mut rng = Rng::new();
            let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
            let Peeled::Forward { mut packet, .. } = peel(&pkt, &mut at(&mut ns[0])).unwrap() else { panic!() };
            packet[region] ^= 1;
            assert_eq!(peel(&packet, &mut at(&mut ns[1])).unwrap_err(), Refused::BadMac, "second hop, byte {region}");
        }
    }

    #[test]
    fn a_header_built_from_nothing_is_refused() {
        let mut ns = nodes(1);
        let mut rng = Rng::new();
        let mut junk = vec![0u8; PACKET];
        rng.fill(&mut junk);
        assert_eq!(peel(&junk, &mut at(&mut ns[0])).unwrap_err(), Refused::BadMac);
    }

    #[test]
    fn a_packet_for_another_key_is_refused_and_leaves_the_replay_set_unspent() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        // The wrong key first: implicit rejection gives it a random secret, the MAC fails, and the right key still works.
        let Node { sk: wrong, replay: rwrong, .. } = &mut nodes(1).remove(0);
        assert_eq!(peel(&pkt, &mut [HopKey { sk: wrong, replay: rwrong }]).unwrap_err(), Refused::BadMac);
        assert!(peel(&pkt, &mut at(&mut ns[0])).is_ok());
    }

    #[test]
    fn the_previous_epoch_key_still_opens_a_packet_built_before_the_turn() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        let (_, newer) = kem_keypair();
        let mut newer_replay = ReplayBloom::new();
        let n = &mut ns[0];
        let mut held = [HopKey { sk: &newer, replay: &mut newer_replay }, HopKey { sk: &n.sk, replay: &mut n.replay }];
        assert!(matches!(peel(&pkt, &mut held), Ok(Peeled::Forward { .. })));
    }

    #[test]
    fn a_destroyed_key_cannot_open_an_old_packet() {
        // Forward secrecy: once a key leaves the held set, a stored packet is noise.
        let ns = nodes(HOPS);
        let mut rng = Rng::new();
        let pkt = build(&route(&ns), b"x", &mut rng).unwrap();
        let (_, a) = kem_keypair();
        let (_, b) = kem_keypair();
        let (mut ra, mut rb) = (ReplayBloom::new(), ReplayBloom::new());
        let mut held = [HopKey { sk: &a, replay: &mut ra }, HopKey { sk: &b, replay: &mut rb }];
        assert_eq!(peel(&pkt, &mut held).unwrap_err(), Refused::BadMac);
    }

    #[test]
    fn hostile_bytes_fail_closed_at_every_parser_in_this_layer() {
        use crate::pqmix::carrier::CarrierAddr;
        let mut ns = nodes(1);
        let mut rng = Rng::new();
        let (a, b) = (crate::pqmix::record::verify_record(&[], None), CarrierAddr::decode(1, &[]));
        assert!(a.is_err() && b.is_none());
        let mut buf = vec![0u8; PACKET + 64];
        for round in 0..3000usize {
            let len = rng.below(buf.len());
            rng.fill(&mut buf[..len]);
            let bytes = &buf[..len];
            assert!(peel(bytes, &mut at(&mut ns[0])).is_err());
            assert!(crate::pqmix::record::verify_record(bytes, None).is_err());
            assert!(crate::pqmix::record::verify_record(bytes, Some(round as u64)).is_err());
            if len >= 3 {
                let body = std::str::from_utf8(&bytes[3..]);
                if body.is_err() {
                    assert!(CarrierAddr::decode(bytes[0], &bytes[3..]).is_none());
                }
            }
            crate::pqmix::runtime::hostile_inner_parse(bytes);
        }
        // A full-size packet of noise reaches the MAC and stops there.
        let mut p = vec![0u8; PACKET];
        for _ in 0..200 {
            rng.fill(&mut p);
            assert_eq!(peel(&p, &mut at(&mut ns[0])).unwrap_err(), Refused::BadMac);
        }
    }

    #[test]
    fn wrong_sizes_are_refused() {
        let mut ns = nodes(1);
        assert_eq!(peel(&vec![0u8; PACKET - 1], &mut at(&mut ns[0])).unwrap_err(), Refused::WrongSize);
        let mut rng = Rng::new();
        let ns = nodes(HOPS + 1);
        assert!(build(&route(&ns[..HOPS]), &vec![0u8; INNER + 1], &mut rng).is_none());
        assert!(build(&route(&ns[..HOPS - 1]), b"x", &mut rng).is_none(), "a route one hop short is refused");
        assert!(build(&route(&ns), b"x", &mut rng).is_none(), "a route one hop long is refused");
        assert!(build(&route(&ns[..HOPS]), b"x", &mut rng).is_some(), "CALIBRATION: a route of the right length builds");
    }

    /// Prints what a hop costs on this machine, solo; the spec's CPU line comes from this.
    #[test]
    fn one_hop_cost_is_measured_and_printed() {
        let mut ns = nodes(HOPS);
        let mut rng = Rng::new();
        let t = std::time::Instant::now();
        let mut pkts = Vec::new();
        for _ in 0..200 {
            pkts.push(build(&route(&ns), b"x", &mut rng).unwrap());
        }
        let build_us = t.elapsed().as_micros() / 200;
        let t = std::time::Instant::now();
        for p in &pkts {
            peel(p, &mut at(&mut ns[0])).unwrap();
        }
        let peel_us = t.elapsed().as_micros() / 200;
        println!("[mix] build {build_us} us, peel {peel_us} us per packet");
        assert!(build_us > 0 && peel_us > 0, "a real ML-KEM operation takes time");
    }
}

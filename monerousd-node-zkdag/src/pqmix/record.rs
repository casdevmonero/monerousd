// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! A node's signed mix record and long-term identity. BORROWED: S/Kademlia's crypto puzzle on the node id, AnonBoot's and
//! Margolin & Levine's recurring cost per identity, Bitcoin's `addr` relay for how records travel. There is no authority: a
//! record is believed because its own key signed it and its id and epoch cost work, and anyone can check all three.
//!
//! A record holds no IP. [`CarrierAddr`] has no variant that could: see `carrier.rs`.

use super::carrier::CarrierAddr;
use super::packet::{kem_pk_is_valid, NodeId, KEM_PK};

pub const DSA_PK: usize = 1952;
pub const DSA_SIG: usize = 3309;
pub const CARRIERS_MAX: usize = 2;
/// A key lives one epoch, plus one more for packets built just before the turn. Longer means more exposure if a node is
/// seized, shorter means more gossip; an hour is Nym's epoch length.
pub const EPOCH_SECS: u64 = 3600;
/// About 2^24 blake3 calls for one identity: seconds on a laptop, a minute on a phone, once per node.
pub const ID_POW_BITS: u32 = 24;
/// About 2^22 calls per identity per epoch: the rent that makes keeping an identity cost something. With no IP there is no
/// address block to count by, so cost and age are what remain against a Sybil. See `view.rs` for what they do not stop.
pub const EPOCH_POW_BITS: u32 = 22;

pub fn id_of(dsa_pk: &[u8]) -> NodeId {
    *blake3::hash(dsa_pk).as_bytes()
}

pub fn epoch_now(now_ms: u64) -> u64 {
    now_ms / 1000 / EPOCH_SECS
}

/// Both works run over the 32-byte id, not the 1,952-byte key. The id commits to the key, and the cost of a try stays one
/// short hash, so the bits below say what they cost. MEASURED: over the whole key, 2^24 tries took about a minute.
fn id_pow_hash(id: &NodeId, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 identity work");
    h.update(id);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

fn epoch_pow_hash(id: &NodeId, epoch: u64, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 epoch work");
    h.update(id);
    h.update(&epoch.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

pub fn id_pow_valid(dsa_pk: &[u8], nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&id_pow_hash(&id_of(dsa_pk), nonce)) >= bits
}

pub fn epoch_pow_valid(dsa_pk: &[u8], epoch: u64, nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&epoch_pow_hash(&id_of(dsa_pk), epoch, nonce)) >= bits
}

/// The epoch's work for this identity. Under a second on a laptop, so a caller on an async runtime runs it on a blocking
/// thread.
pub fn mine_epoch_work(dsa_pk: &[u8], epoch: u64) -> u64 {
    let id = id_of(dsa_pk);
    let mut n = 0u64;
    while leading_zero_bits(&epoch_pow_hash(&id, epoch, n)) < EPOCH_POW_BITS {
        n += 1;
    }
    n
}

fn mine_id_work(dsa_pk: &[u8]) -> u64 {
    let id = id_of(dsa_pk);
    let mut n = 0u64;
    while leading_zero_bits(&id_pow_hash(&id, n)) < ID_POW_BITS {
        n += 1;
    }
    n
}

/// This node's long-term identity: an ML-DSA-65 key and the work that makes its id costly.
pub struct Identity {
    pub id: NodeId,
    pub dsa_pk: Vec<u8>,
    /// Overwritten when dropped.
    pub dsa_sk: zeroize::Zeroizing<Vec<u8>>,
    pub pow_nonce: u64,
}

impl Identity {
    /// Load this node's identity, or mint one and do its work once. A file that does not parse mints a new identity: this
    /// is a transport key (geth's `nodekey` shape) and no funds depend on it.
    pub fn load_or_mint(state_dir: &std::path::Path) -> Identity {
        let path = state_dir.join("mix-identity.key");
        // O1-INFINITY-REVIEWED: this node's own transport key, one ~6 KB file of fixed size; no chain state is read from it.
        if let Some(i) = std::fs::read(&path).ok().and_then(|b| Identity::from_file_bytes(&b)) {
            return i;
        }
        let i = Identity::mint();
        let _ = std::fs::create_dir_all(state_dir);
        save_secret(&path, &i.file_bytes(), "the mix identity");
        i
    }

    /// A fresh identity with its work done (about 2^24 blake3 calls on 40 bytes, a second or two). Blocking: a caller on an async
    /// runtime runs it on a blocking thread.
    pub fn mint() -> Identity {
        let (dsa_pk, dsa_sk) = crate::pqauth::ml_dsa_keypair();
        let dsa_sk = zeroize::Zeroizing::new(dsa_sk);
        let pow_nonce = mine_id_work(&dsa_pk);
        Identity { id: id_of(&dsa_pk), dsa_pk, dsa_sk, pow_nonce }
    }

    /// `dsa_pk ‖ pow_nonce LE ‖ dsa_sk`, the file form. Holds the secret: written only through [`save_secret`].
    pub fn file_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(self.dsa_pk.clone());
        out.extend_from_slice(&self.pow_nonce.to_le_bytes());
        out.extend_from_slice(&self.dsa_sk);
        out
    }

    /// The file form back, refused unless its work is valid and its secret key signs.
    pub fn from_file_bytes(b: &[u8]) -> Option<Identity> {
        if b.len() <= DSA_PK + 8 {
            return None;
        }
        let dsa_pk = b[..DSA_PK].to_vec();
        let mut n = [0u8; 8];
        n.copy_from_slice(&b[DSA_PK..DSA_PK + 8]);
        let pow_nonce = u64::from_le_bytes(n);
        let dsa_sk = zeroize::Zeroizing::new(b[DSA_PK + 8..].to_vec());
        (id_pow_valid(&dsa_pk, pow_nonce, ID_POW_BITS) && crate::pqauth::ml_dsa_sign(b"check", &dsa_sk).is_some())
            .then(|| Identity { id: id_of(&dsa_pk), dsa_pk, dsa_sk, pow_nonce })
    }
}

/// Writes a secret only this node holds, owner-readable only.
pub fn save_secret(path: &std::path::Path, bytes: &[u8], what: &str) {
    // LOCAL-STORAGE-REQUIRED: a transport secret only this node holds (an ML-DSA key and its work); no proof, DA record or wire
    // field can carry a node's own private key, and it is the same class as `mlkem-identity.key`.
    // bound: two fixed-size files at most (`mix-identity.key`, `mix-hop.key`), about 6 KB each, rewritten in place — never a
    // term in height, blocks or notes.
    match std::fs::write(path, bytes) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Err(e) => eprintln!("[mix] {what} could not be saved ({e}); it will not survive a restart"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub dsa_pk: Vec<u8>,
    pub epoch: u64,
    pub kem_pk: Vec<u8>,
    pub carriers: Vec<CarrierAddr>,
    pub seq: u64,
    pub pow_nonce: u64,
    pub epoch_nonce: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecordRefused {
    Malformed,
    NoWork,
    StaleEpoch,
    BadKey,
    BadSignature,
}

const DOMAIN: &[u8] = b"monerousd mix v1 record";

fn signed_part(r: &Record) -> Vec<u8> {
    let mut m = Vec::with_capacity(4096);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&r.dsa_pk);
    m.extend_from_slice(&r.epoch.to_le_bytes());
    m.extend_from_slice(&r.kem_pk);
    m.push(r.carriers.len() as u8);
    for c in &r.carriers {
        c.encode_into(&mut m);
    }
    m.extend_from_slice(&r.seq.to_le_bytes());
    m.extend_from_slice(&r.pow_nonce.to_le_bytes());
    m.extend_from_slice(&r.epoch_nonce.to_le_bytes());
    m
}

/// Sign and encode. The encoding is the signed bytes and the signature: one object, one encoding.
pub fn encode_signed(r: &Record, dsa_sk: &[u8]) -> Option<Vec<u8>> {
    let mut m = signed_part(r);
    let sig = crate::pqauth::ml_dsa_sign(&m, dsa_sk)?;
    m.extend_from_slice(&sig);
    Some(m)
}

struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }
}

fn parse(c: &mut Cur) -> Option<Record> {
    if c.take(DOMAIN.len())? != DOMAIN {
        return None;
    }
    let dsa_pk = c.take(DSA_PK)?.to_vec();
    let epoch = c.u64()?;
    let kem_pk = c.take(KEM_PK)?.to_vec();
    let n = c.u8()? as usize;
    if n > CARRIERS_MAX {
        return None;
    }
    let mut carriers = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = c.u8()?;
        let l = c.take(2)?;
        let len = u16::from_le_bytes([l[0], l[1]]) as usize;
        let body = c.take(len)?;
        carriers.push(CarrierAddr::decode(kind, body)?);
    }
    let seq = c.u64()?;
    let pow_nonce = c.u64()?;
    let epoch_nonce = c.u64()?;
    Some(Record { dsa_pk, epoch, kem_pk, carriers, seq, pow_nonce, epoch_nonce })
}

/// The record's one door. Cheapest checks first: exact shape, then work, then epoch, then the signature. `now_epoch` is
/// `None` when reading this node's own bounded file back at boot: an old record's key cannot route, but its address can
/// still be dialled, and a new record arrives over that link.
pub fn verify_record(bytes: &[u8], now_epoch: Option<u64>) -> Result<Record, RecordRefused> {
    let mut c = Cur { b: bytes, at: 0 };
    let r = parse(&mut c).ok_or(RecordRefused::Malformed)?;
    let signed_len = c.at;
    let sig = c.take(DSA_SIG).ok_or(RecordRefused::Malformed)?;
    if c.at != bytes.len() {
        return Err(RecordRefused::Malformed);
    }
    if !id_pow_valid(&r.dsa_pk, r.pow_nonce, ID_POW_BITS) || !epoch_pow_valid(&r.dsa_pk, r.epoch, r.epoch_nonce, EPOCH_POW_BITS) {
        return Err(RecordRefused::NoWork);
    }
    if let Some(now) = now_epoch {
        if r.epoch + 1 < now || r.epoch > now + 1 {
            return Err(RecordRefused::StaleEpoch);
        }
    }
    if !kem_pk_is_valid(&r.kem_pk) {
        return Err(RecordRefused::BadKey);
    }
    if !crate::pqauth::ml_dsa_verify(&bytes[..signed_len], &r.dsa_pk, sig) {
        return Err(RecordRefused::BadSignature);
    }
    Ok(r)
}

// TWO-PARTY-REVIEWED: the signer and the verifier here are separate calls sharing no state but the bytes. Records crossing
// between real processes are exercised by `mix_cut.py`, which cannot route at all until they do.
#[cfg(test)]
mod tests {
    use super::*;

    fn identity(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("mix-id-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = Identity::load_or_mint(&dir);
        let again = Identity::load_or_mint(&dir);
        assert_eq!(id.id, again.id, "an identity survives a restart");
        let _ = std::fs::remove_dir_all(&dir);
        id
    }

    fn record(i: &Identity, epoch: u64) -> Record {
        let (kem_pk, _) = crate::pqmix::packet::kem_keypair();
        Record {
            dsa_pk: i.dsa_pk.clone(),
            epoch,
            kem_pk,
            carriers: vec![CarrierAddr::Unix("/tmp/a.sock".into())],
            seq: 1,
            pow_nonce: i.pow_nonce,
            epoch_nonce: mine_epoch_work(&i.dsa_pk, epoch),
        }
    }

    #[test]
    fn a_record_verifies_and_every_forgery_is_refused() {
        let i = identity("forgery-a");
        let r = record(&i, 100);
        let enc = encode_signed(&r, &i.dsa_sk).unwrap();
        assert_eq!(verify_record(&enc, Some(100)).unwrap(), r);
        assert!(enc.len() <= crate::pqmix::link::FRAME_BODY, "a record is {} bytes and must fit a link frame", enc.len());

        // Any changed byte is refused, wherever it lands.
        for at in [24, 23 + DSA_PK + 3, 23 + DSA_PK + 8 + 5, enc.len() - 2] {
            let mut bad = enc.clone();
            bad[at] ^= 1;
            assert!(verify_record(&bad, Some(100)).is_err(), "a change at byte {at} was believed");
        }
        // A truncation or an extension is refused: one object has one encoding.
        assert_eq!(verify_record(&enc[..enc.len() - 1], Some(100)), Err(RecordRefused::Malformed));
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(verify_record(&long, Some(100)), Err(RecordRefused::Malformed));

        // Another key's signature over this key's record.
        let other = identity("forgery-b");
        let forged = encode_signed(&r, &other.dsa_sk).unwrap();
        assert_eq!(verify_record(&forged, Some(100)), Err(RecordRefused::BadSignature));
    }

    #[test]
    fn a_record_from_another_epoch_is_refused_for_routing_and_read_back_for_dialling() {
        let i = identity("epoch");
        let enc = encode_signed(&record(&i, 100), &i.dsa_sk).unwrap();
        assert!(verify_record(&enc, Some(99)).is_ok());
        assert!(verify_record(&enc, Some(101)).is_ok());
        assert_eq!(verify_record(&enc, Some(102)), Err(RecordRefused::StaleEpoch));
        assert_eq!(verify_record(&enc, Some(98)), Err(RecordRefused::StaleEpoch));
        assert!(verify_record(&enc, None).is_ok(), "this node's own file keeps an old address dialable");
    }

    #[test]
    fn an_identity_or_epoch_with_no_work_is_refused() {
        let i = identity("work");
        let mut r = record(&i, 100);
        let good_nonce = r.pow_nonce;
        // Search for a nonce that fails the work, which nearly every nonce does.
        r.pow_nonce = (0..).find(|n| !id_pow_valid(&i.dsa_pk, *n, ID_POW_BITS)).unwrap();
        assert_eq!(verify_record(&encode_signed(&r, &i.dsa_sk).unwrap(), Some(100)), Err(RecordRefused::NoWork));
        r.pow_nonce = good_nonce;
        r.epoch_nonce = (0..).find(|n| !epoch_pow_valid(&i.dsa_pk, 100, *n, EPOCH_POW_BITS)).unwrap();
        assert_eq!(verify_record(&encode_signed(&r, &i.dsa_sk).unwrap(), Some(100)), Err(RecordRefused::NoWork));
    }

    #[test]
    fn last_epochs_work_does_not_pay_for_this_epoch() {
        // Rent, not a one-time fee: the work is bound to the epoch.
        let i = identity("rent");
        let mut r = record(&i, 100);
        let n = r.epoch_nonce;
        r.epoch = 101;
        // Unless this nonce happens to also solve the next epoch, which is a 1 in 2^22 event.
        assert!(!epoch_pow_valid(&i.dsa_pk, 101, n, EPOCH_POW_BITS));
        assert_eq!(verify_record(&encode_signed(&r, &i.dsa_sk).unwrap(), Some(101)), Err(RecordRefused::NoWork));
    }

    #[test]
    fn identity_and_epoch_rent_are_measured_and_printed() {
        let (pk, _) = crate::pqauth::ml_dsa_keypair();
        let t = std::time::Instant::now();
        for e in 0..16u64 {
            mine_epoch_work(&pk, e);
        }
        let ms = t.elapsed().as_millis() / 16;
        println!(
            "[mix] epoch work {ms} ms per identity on this machine: 1,000 Sybil identities cost {:.2} cores continuously",
            1000.0 * ms as f64 / 3_600_000.0
        );
        assert!(ms > 0);
    }
}

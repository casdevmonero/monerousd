// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE CUSTODY KEYSTORE — every secret a node keeps, sealed at rest under the operator's passphrase.
//!
//! USER 2026-09-28: "add custody key safety to the score", then: "We are building a public blockchain that everyone
//! will use like btc and eth are used with a wallet". And: "yes i approve the keystore".
//!
//! **The borrowed shape is Ethereum's EIP-2335 validator keystore** (and Bitcoin Core's encrypted wallet). The key
//! file is encrypted under a passphrase the operator chooses. A memory-hard KDF makes guessing the passphrase
//! expensive, and an authenticated cipher makes a tampered file refuse to open. The node reads the passphrase at
//! start from a password file (`MONEROUSD_KEYSTORE_PASSWORD_FILE`), as an Ethereum validator client does. This works
//! on every platform; an OS keystore is an optional extra, never a requirement.
//!
//! **Post-quantum.** Everything here is symmetric (blake3). A 256-bit key keeps 128-bit security against Grover, and
//! no public-key primitive is involved.
//! * **KDF:** Balloon hashing (Boneh, Corrigan-Gibbs, Schechter, 2016): provably memory-hard, built from any
//!   cryptographic hash. It is instantiated with blake3 and a domain context.
//! * **AEAD:** encrypt-then-MAC. The stream is blake3's keyed XOF over the nonce; the tag is keyed blake3 over the
//!   header and the ciphertext. The two keys are derived separately from the Balloon output.
//!
//! **Format** (binary, one self-describing file): `MAGIC(8) ‖ space_log2(1) ‖ time(1) ‖ salt(32) ‖ nonce(24) ‖
//! ciphertext ‖ tag(32)`. The KDF parameters live in the header, so they can be raised later without breaking old
//! files. A header asking for more than [`MAX_SPACE_LOG2`] / [`MAX_TIME`] is refused before any memory is allocated.
//!
//! **Policy: OPT-IN, and it never costs liveness.** USER 2026-09-28: "the node key file passphrase seems like it needs
//! to be an opt in choice rather than being chosen for the user because the validating node not starting due to
//! passphrase could cause liveness issues".
//! * The ROOT of key safety is the operator's SEED: a bonded node's value keys are derived from it
//!   (`validator::derive_validator_keys`, the EIP-2333/2334 shape), so no lost file and no lost passphrase can strand
//!   a bond. This keystore is only EIP-2335's optional at-rest wrapper on top of that.
//! * With a passphrase configured (the operator's choice), every key write seals, and every unsealed key read is
//!   migrated (sealed in place) on first read.
//! * Without one, keys stay owner-only and unsealed (the umask set first in `main`). That is a supported
//!   configuration, not an error.
//! * ⛔ NOTHING here may stop a node from starting. A sealed key that will not open (missing or wrong passphrase)
//!   turns off only the ROLE that key serves: the validator refuses to bind value to an identity it cannot sign for.
//!   The node itself runs. And [`write_key_file`] never overwrites a sealed file it cannot open, so a locked key is
//!   never destroyed by the node that could not read it.
//!
//! ROOT-LAYER: the at-rest form of a key is PRODUCED where the key file is written, so the seal lives in the one
//! writer every key site calls ([`write_key_file`]), and the one reader ([`read_key_file`]) is where a pre-keystore
//! file is migrated. No key site keeps its own read or write of a key file.
//! MEASURED: before, on the live home (2026-09-28): the validator ML-DSA key, the custody ML-KEM key, the custodian
//! openings, the custody book and the onion seed were all stored unsealed, and all were `-rw-r--r--` until the umask
//! change. After: the two pins below (a sealed key opens only under its passphrase, every tamper refuses; an unsealed
//! key is sealed in place on first read), run in the landing gate that lands this file.
//! MUST-STAY-GREEN: without a passphrase every key site behaves exactly as before (the same bytes in and out), so
//! every existing validator, bond, custody and onion pin is unchanged; `harness::custody`'s census.
//!
//! Cons, in f(fixed constants), none in history:
//! * DISK: a sealed file is its key + 98 fixed bytes (66 header + 32 tag). About 5 key files per node gives about
//!   490 B once, never per block. No new file persists: the temp name is renamed over the key.
//! * RAM: 8 MiB transient per open (2^18 × 32 B), freed and zeroed on return.
//! * TIME: 2^18 × (1 + 4 × 10) ≈ 10.7 M blake3 calls per derivation, MEASURED at 2.7 s (dev profile, this
//!   machine), and only with a passphrase configured. A node's key files share one salt under one passphrase, so a
//!   start pays ONE derivation for all of them. Rewrites and reopens reuse the unlock, so it is never paid per
//!   block.
//! * PRIVACY: none. Nothing is served or logged except the file path. A key's bytes never reach a log.

use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"MUSDKS01";
const HEADER_LEN: usize = 8 + 1 + 1 + 32 + 24;
const TAG_LEN: usize = 32;
/// Production KDF cost: 2^18 blocks of 32 B (8 MiB) × 4 passes.
pub const SPACE_LOG2: u8 = 18;
pub const TIME: u8 = 4;
/// The largest cost a file may ask for: 2^22 blocks (128 MiB) × 10 passes. Past that, the file is refused unread.
pub const MAX_SPACE_LOG2: u8 = 22;
pub const MAX_TIME: u8 = 10;
const DELTA: u32 = 3;
/// Where the operator's passphrase file is named (one line; a trailing newline is ignored).
pub const PASSWORD_FILE_ENV: &str = "MONEROUSD_KEYSTORE_PASSWORD_FILE";
const BALLOON_CTX: &str = "MUSD/keystore/v1/balloon";
const ENC_CTX: &str = "MUSD/keystore/v1/enc";
const MAC_CTX: &str = "MUSD/keystore/v1/mac";

/// Why a sealed key did not open. Every variant refuses the WHOLE file; nothing partial is ever returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreError {
    /// Not a keystore file, or too short to hold one.
    Malformed,
    /// The header asks for a KDF cost above the cap.
    CostTooHigh,
    /// Wrong passphrase, or the file was altered.
    Refused,
    /// The system RNG could not be read.
    NoEntropy,
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(BALLOON_CTX);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// Balloon hashing, Algorithm 1 of the paper (sequential), over `2^space_log2` 32-byte blocks and `time` passes.
fn balloon(pass: &[u8], salt: &[u8; 32], space_log2: u8, time: u8) -> [u8; 32] {
    let s = 1usize << space_log2;
    let mut cnt: u64 = 0;
    let next = |c: &mut u64| {
        let v = *c;
        *c += 1;
        v.to_le_bytes()
    };
    let mut buf = vec![[0u8; 32]; s];
    buf[0] = h(&[&next(&mut cnt), pass, salt]);
    for m in 1..s {
        buf[m] = h(&[&next(&mut cnt), &buf[m - 1]]);
    }
    for t in 0..u64::from(time) {
        for m in 0..s {
            let prev = buf[(m + s - 1) % s];
            buf[m] = h(&[&next(&mut cnt), &prev, &buf[m]]);
            for i in 0..u64::from(DELTA) {
                let idx_block = h(&[&t.to_le_bytes(), &(m as u64).to_le_bytes(), &i.to_le_bytes()]);
                let r = h(&[&next(&mut cnt), salt, &idx_block]);
                let mut w = [0u8; 8];
                w.copy_from_slice(&r[..8]);
                let other = (u64::from_le_bytes(w) % s as u64) as usize;
                let o = buf[other];
                buf[m] = h(&[&next(&mut cnt), &buf[m], &o]);
            }
        }
    }
    let out = buf[s - 1];
    for b in &mut buf {
        b.zeroize();
    }
    out
}

thread_local! {
    /// How many Balloon derivations this thread ran (the unlock-once pin reads it; threads never share it).
    static BALLOON_RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn keys(pass: &[u8], salt: &[u8; 32], space_log2: u8, time: u8) -> ([u8; 32], [u8; 32]) {
    BALLOON_RUNS.with(|c| c.set(c.get() + 1));
    let mut master = balloon(pass, salt, space_log2, time);
    let enc = blake3::derive_key(ENC_CTX, &master);
    let mac = blake3::derive_key(MAC_CTX, &master);
    master.zeroize();
    (enc, mac)
}

/// One unlock this process holds: a salt and KDF cost, and the two keys they derive under the passphrase whose
/// digest is `pass`. EIP-2335 derives its key once per unlock and holds it, and so does this.
/// * An unlocked file reopens and reseals (fresh nonce, same salt) with no second Balloon run. The custodian openings
///   and the custody book are rewritten whenever the chain advances them, so this is what keeps a write cheap.
/// * Every key file this process seals under one passphrase takes the SAME salt, so a start runs ONE derivation for
///   all of them. MEASURED (pin below, dev profile): one production derivation is 2.7 s, so six key files cost
///   ≈ 2.7 s at start instead of ≈ 16 s. A salt defeats precomputation across different passphrases. Files of one
///   node under one passphrase fall together to whoever learns that passphrase anyway, so sharing it among them
///   loses nothing.
/// * The derived keys protect no more than the key bytes the process already holds in RAM once it has read them.
///
/// Cons: none, f(fixed constants): one 97-byte entry per distinct (passphrase, salt), normally ONE per node. It is
/// never keyed by path, block or height.
struct Unlocked {
    pass: [u8; 32],
    salt: [u8; 32],
    space_log2: u8,
    time: u8,
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Drop for Unlocked {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
        self.pass.zeroize();
    }
}

/// One entry per distinct (passphrase, salt, cost) the process unlocks: normally one per node, never per path,
/// block or height.
static UNLOCKED: std::sync::Mutex<Vec<Unlocked>> = std::sync::Mutex::new(Vec::new());

fn pass_digest(pass: &[u8]) -> [u8; 32] {
    blake3::derive_key("MUSD/keystore/v1/pass-digest", pass)
}

/// The keys this process holds for `pass` with exactly this salt and cost (opening), or with any salt at the
/// production cost (sealing a new file, which then shares that salt). A poisoned lock (a thread panicked holding it)
/// answers "not unlocked", so the caller derives again: slower, never wrong.
fn unlocked_keys(pass: &[u8], want: Option<([u8; 32], u8, u8)>) -> Option<([u8; 32], [u8; 32], [u8; 32], u8, u8)> {
    let digest = pass_digest(pass);
    let Ok(held) = UNLOCKED.lock() else { return None };
    held.iter()
        .find(|u| {
            u.pass == digest
                && match want {
                    Some((salt, l, t)) => u.salt == salt && u.space_log2 == l && u.time == t,
                    None => u.space_log2 == SPACE_LOG2 && u.time == TIME,
                }
        })
        .map(|u| (u.enc, u.mac, u.salt, u.space_log2, u.time))
}

fn remember_unlocked(pass: &[u8], salt: [u8; 32], space_log2: u8, time: u8, enc: [u8; 32], mac: [u8; 32]) {
    let entry = Unlocked { pass: pass_digest(pass), salt, space_log2, time, enc, mac };
    let Ok(mut held) = UNLOCKED.lock() else { return };
    if !held.iter().any(|u| u.pass == entry.pass && u.salt == salt && u.space_log2 == space_log2 && u.time == time) {
        held.push(entry);
    }
}

/// Seal `data` under already-derived keys, with a fresh nonce.
fn seal_under(enc: &[u8; 32], mac: &[u8; 32], salt: &[u8; 32], space_log2: u8, time: u8, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let nonce: [u8; 24] = entropy()?;
    let mut out = Vec::with_capacity(HEADER_LEN + data.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.push(space_log2);
    out.push(time);
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    let ct_start = out.len();
    out.extend_from_slice(data);
    xor_stream(enc, &nonce, &mut out[ct_start..]);
    let tag = tag_of(mac, &out);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// The header of a sealed file: `(salt, space_log2, time)`, with the cost cap checked before anything is derived.
fn header_of(sealed: &[u8]) -> Result<([u8; 32], u8, u8), KeystoreError> {
    if !is_sealed(sealed) {
        return Err(KeystoreError::Malformed);
    }
    let (space_log2, time) = (sealed[8], sealed[9]);
    if space_log2 > MAX_SPACE_LOG2 || time > MAX_TIME || time == 0 {
        return Err(KeystoreError::CostTooHigh);
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&sealed[10..42]);
    Ok((salt, space_log2, time))
}

/// Open a sealed file under already-derived keys. The tag decides; nothing partial is returned.
fn open_under(enc: &[u8; 32], mac: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let nonce = &sealed[42..HEADER_LEN];
    let (body, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let want = tag_of(mac, body);
    // Constant-time comparison: the tag decides, and its bytes must not leak through timing.
    let diff = want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(KeystoreError::Refused);
    }
    let mut out = body[HEADER_LEN..].to_vec();
    xor_stream(enc, nonce, &mut out);
    Ok(out)
}

fn xor_stream(enc: &[u8; 32], nonce: &[u8], data: &mut [u8]) {
    let mut ks = vec![0u8; data.len()];
    blake3::Hasher::new_keyed(enc).update(nonce).finalize_xof().fill(&mut ks);
    for (d, k) in data.iter_mut().zip(&ks) {
        *d ^= k;
    }
    ks.zeroize();
}

fn tag_of(mac: &[u8; 32], authenticated: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(mac, authenticated).as_bytes()
}

fn entropy<const N: usize>() -> Result<[u8; N], KeystoreError> {
    use std::io::Read as _;
    let mut out = [0u8; N];
    crate::oscall::os_random(&mut out).map_err(|_| KeystoreError::NoEntropy)?;
    Ok(out)
}

/// Seal `plaintext` under `pass` at the given KDF cost (the production cost is [`SPACE_LOG2`] / [`TIME`]).
pub fn seal_with(pass: &[u8], plaintext: &[u8], space_log2: u8, time: u8) -> Result<Vec<u8>, KeystoreError> {
    if space_log2 > MAX_SPACE_LOG2 || time > MAX_TIME || time == 0 {
        return Err(KeystoreError::CostTooHigh);
    }
    let salt: [u8; 32] = entropy()?;
    let (enc, mac) = keys(pass, &salt, space_log2, time);
    seal_under(&enc, &mac, &salt, space_log2, time, plaintext)
}

/// Is this a sealed keystore file (by its magic)?
#[must_use]
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN + TAG_LEN && &bytes[..8] == MAGIC
}

/// Open a sealed file. Refuses the whole file on a wrong passphrase, any altered byte, a truncation, or a header cost
/// above the cap (checked before anything is allocated).
pub fn open(pass: &[u8], sealed: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let (salt, space_log2, time) = header_of(sealed)?;
    let (enc, mac) = keys(pass, &salt, space_log2, time);
    open_under(&enc, &mac, sealed)
}

/// Open a sealed file, reusing the keys this process already holds for its (passphrase, salt, cost), and deriving
/// (then remembering) them otherwise. Keys are remembered only after the tag verified.
fn open_at(pass: &[u8], sealed: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let (salt, space_log2, time) = header_of(sealed)?;
    if let Some((enc, mac, ..)) = unlocked_keys(pass, Some((salt, space_log2, time))) {
        return open_under(&enc, &mac, sealed);
    }
    let (enc, mac) = keys(pass, &salt, space_log2, time);
    let out = open_under(&enc, &mac, sealed)?;
    remember_unlocked(pass, salt, space_log2, time, enc, mac);
    Ok(out)
}

/// Seal `bytes` under the unlock this process already holds for `pass` at the production cost (its salt, a fresh
/// nonce), or under a fresh salt and one Balloon run, which is then remembered.
fn seal_at(pass: &[u8], bytes: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if let Some((enc, mac, salt, l, t)) = unlocked_keys(pass, None) {
        return seal_under(&enc, &mac, &salt, l, t, bytes);
    }
    let salt: [u8; 32] = entropy()?;
    let (enc, mac) = keys(pass, &salt, SPACE_LOG2, TIME);
    let out = seal_under(&enc, &mac, &salt, SPACE_LOG2, TIME, bytes)?;
    remember_unlocked(pass, salt, SPACE_LOG2, TIME, enc, mac);
    Ok(out)
}

/// The operator's passphrase, if one is configured and readable. An unreadable password file is reported loudly and
/// treated as no passphrase, so a sealed key then refuses to open (it never opens under a guess).
fn passphrase() -> Option<Vec<u8>> {
    let path = std::env::var_os(PASSWORD_FILE_ENV)?;
    let mut p = match std::fs::read(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[keystore] ⛔ {PASSWORD_FILE_ENV} is set but its file cannot be read ({e}): no passphrase");
            return None;
        }
    };
    while matches!(p.last(), Some(b'\n' | b'\r')) {
        p.pop();
    }
    if p.is_empty() {
        eprintln!("[keystore] ⛔ the keystore password file is empty: no passphrase");
        return None;
    }
    Some(p)
}

/// Is this `read_key_file` error a LOCKED key (sealed, and the configured passphrase is absent or does not open it)?
/// A locked key turns off the role it serves; the caller must never replace it (and [`write_key_file`] refuses to).
#[must_use]
pub fn is_locked(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

fn note_unsealed_once() {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        eprintln!(
            "[keystore] keys are owner-only and unsealed at rest (sealing is opt-in: set {PASSWORD_FILE_ENV}). \
             A bonded identity is recovered from the operator's seed, never from these files."
        );
    });
}

fn locked(path: &std::path::Path, why: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{}: sealed, {why}", path.display()))
}

/// Read a key file: open it if sealed; if it is unsealed and a passphrase is configured, seal it in place first.
pub fn read_key_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    read_key_file_with(path, passphrase().as_deref())
}

/// [`read_key_file`] with an explicit passphrase (tests pass one; production reads the password file).
pub fn read_key_file_with(path: &std::path::Path, pass: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
    // O1-INFINITY-REVIEWED: one fixed-size key file (a key, never chain state); the read existed before this change.
    let bytes = std::fs::read(path)?;
    if is_sealed(&bytes) {
        let Some(pass) = pass else {
            return Err(locked(path, &format!("and no passphrase is configured ({PASSWORD_FILE_ENV})")));
        };
        return open_at(pass, &bytes).map_err(|e| locked(path, &format!("and the passphrase does not open it ({e:?})")));
    }
    if pass.is_some() {
        write_key_file_with(path, &bytes, pass)?;
        eprintln!("[keystore] sealed a pre-keystore key file in place: {}", path.display());
    } else {
        note_unsealed_once();
    }
    Ok(bytes)
}

/// Write a key file: sealed when a passphrase is configured, owner-only unsealed otherwise. Atomic.
pub fn write_key_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    write_key_file_with(path, bytes, passphrase().as_deref())
}

/// Write a TRANSPORT identity (the onion seed): owner-only, atomic, and NEVER sealed, whatever the operator opted into.
/// A transport identity moves no value (geth's `nodekey` shape), and a sealed one could lock a node out of the mesh on
/// a lost passphrase — key safety must never cost liveness (user 2026-09-28).
pub fn write_key_file_unsealed(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    write_key_file_with(path, bytes, None)
}

/// [`write_key_file`] with an explicit passphrase. The file is written to a sibling temp name and renamed into place,
/// so a crash leaves the previous key, never a torn one; the umask set first in `main` makes it owner-only.
/// ⛔ A SEALED file this call cannot open under `pass` is never overwritten ([`is_locked`] error): a node whose
/// passphrase is missing or wrong must not destroy, or re-seal under a different passphrase, the key it could not read.
pub fn write_key_file_with(path: &std::path::Path, bytes: &[u8], pass: Option<&[u8]>) -> std::io::Result<()> {
    // O1-INFINITY-REVIEWED: reads back the ONE fixed-size key file about to be replaced, to refuse clobbering a sealed
    // key it cannot open; a key, never chain state, and bounded by the node's handful of key files.
    if let Ok(existing) = std::fs::read(path) {
        if is_sealed(&existing) && !pass.is_some_and(|p| open_at(p, &existing).is_ok()) {
            return Err(locked(path, "cannot be opened here, so it is not overwritten"));
        }
    }
    let out = match pass {
        Some(p) => seal_at(p, bytes).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("keystore seal failed: {e:?}"))
        })?,
        None => {
            note_unsealed_once();
            bytes.to_vec()
        }
    };
    let Some(name) = path.file_name() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "a key file path must name a file"));
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".keystore-tmp");
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, &out)?;
    std::fs::rename(&tmp, path)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// TWO-PARTY-REVIEWED: a keystore seals one node's own secret on its own disk; no boundary is crossed, so there is
    /// no second endpoint. The adversary here is whoever holds a copy of the file, and every tamper below refuses.
    #[test]
    fn a_sealed_key_opens_only_under_its_passphrase_and_every_tamper_refuses() {
        let secret = b"validator ML-DSA secret key bytes".to_vec();
        let sealed = seal_with(b"correct horse", &secret, 10, 2).expect("seals");
        assert!(is_sealed(&sealed));
        assert!(!sealed.windows(secret.len()).any(|w| w == secret.as_slice()), "the key bytes must not appear");
        assert_eq!(open(b"correct horse", &sealed), Ok(secret.clone()), "the right passphrase opens it");
        assert_eq!(open(b"wrong horse", &sealed), Err(KeystoreError::Refused), "a wrong passphrase is refused");
        for at in [8usize, 12, 50, HEADER_LEN, sealed.len() - 1] {
            let mut t = sealed.clone();
            t[at] ^= 1;
            assert!(open(b"correct horse", &t).is_err(), "a flipped byte at {at} is refused");
        }
        assert!(open(b"correct horse", &sealed[..sealed.len() - 1]).is_err(), "a truncation is refused");
        let mut greedy = sealed.clone();
        greedy[8] = MAX_SPACE_LOG2 + 1;
        assert_eq!(open(b"correct horse", &greedy), Err(KeystoreError::CostTooHigh), "an oversized cost is refused unrun");
        let again = seal_with(b"correct horse", &secret, 10, 2).expect("seals");
        assert_ne!(again, sealed, "fresh salt and nonce every seal: two seals of one key never match");
        // The production cost, measured (the cons line in the module doc cites this number).
        let t0 = std::time::Instant::now();
        let prod = seal_with(b"correct horse", &secret, SPACE_LOG2, TIME).expect("seals at the production cost");
        let seal_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert_eq!(open(b"correct horse", &prod), Ok(secret));
        eprintln!("[keystore-cost] production seal {seal_ms} ms, open {} ms", t1.elapsed().as_millis());
    }

    /// The migration path: an unsealed key read with a passphrase is sealed in place, and reads back unchanged.
    /// TWO-PARTY-REVIEWED: as above, one node's own disk.
    #[test]
    fn a_plaintext_key_is_sealed_in_place_on_first_read_with_a_passphrase() {
        let dir = std::env::temp_dir().join(format!("musd-keystore-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("validator-1.key");
        let secret = b"a key an older binary wrote".to_vec();
        write_key_file_with(&path, &secret, None).expect("unsealed write");
        assert_eq!(std::fs::read(&path).expect("read"), secret, "without a passphrase the file is unsealed");
        assert_eq!(read_key_file_with(&path, Some(b"pw")).expect("read + migrate"), secret);
        assert!(is_sealed(&std::fs::read(&path).expect("read")), "the first read with a passphrase sealed it");
        assert_eq!(read_key_file_with(&path, Some(b"pw")).expect("read sealed"), secret, "and it opens unchanged");
        assert!(read_key_file_with(&path, None).is_err(), "a sealed key never opens without the passphrase");
        assert!(read_key_file_with(&path, Some(b"other")).is_err(), "nor under another one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unlock once, as EIP-2335 does: after the first seal, rewrites and reopens of the same file run NO further
    /// Balloon derivation (the custody book and openings are rewritten as the chain advances them). A file altered
    /// on disk still refuses under the held keys, and a wrong passphrase never reuses them.
    /// TWO-PARTY-REVIEWED: as above, one node's own disk.
    #[test]
    fn a_key_file_is_unlocked_once_and_every_later_write_and_read_reuses_it() {
        // A passphrase no other test uses: the unlock table is process-wide.
        let pw: &[u8] = b"pw-unlock-once-pin";
        let dir = std::env::temp_dir().join(format!("musd-keystore-once-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let book = dir.join("custody-book-1.bin");
        let kem = dir.join("validator-1.kem");
        let runs = || BALLOON_RUNS.with(std::cell::Cell::get);
        let before = runs();
        write_key_file_with(&book, b"book v1", Some(pw)).expect("first seal");
        assert_eq!(runs(), before + 1, "the first seal derives once");
        write_key_file_with(&kem, b"kem key", Some(pw)).expect("second file");
        assert_eq!(runs(), before + 1, "a second key file under the same passphrase shares the unlock");
        for v in 2..6u8 {
            write_key_file_with(&book, &[b'v', v], Some(pw)).expect("reseal");
            assert_eq!(read_key_file_with(&book, Some(pw)).expect("reopen"), vec![b'v', v]);
        }
        assert_eq!(read_key_file_with(&kem, Some(pw)).expect("reopen"), b"kem key".to_vec());
        assert_eq!(runs(), before + 1, "rewrites and reads of both files ran no further derivation");
        // A restart: nothing held. Opening the first file derives once; the second, sharing its salt, derives zero.
        forget_unlocks_of(pw);
        let restart = runs();
        assert_eq!(read_key_file_with(&book, Some(pw)).expect("open after restart"), vec![b'v', 5]);
        assert_eq!(read_key_file_with(&kem, Some(pw)).expect("open after restart"), b"kem key".to_vec());
        assert_eq!(runs(), restart + 1, "a start opens every key file of one passphrase with ONE derivation");
        let mut t = std::fs::read(&book).expect("read");
        let last = t.len() - 1;
        t[last] ^= 1;
        std::fs::write(&book, &t).expect("tamper");
        assert!(read_key_file_with(&book, Some(pw)).is_err(), "a file altered on disk refuses under the held keys");
        assert!(read_key_file_with(&kem, Some(b"other")).is_err(), "a wrong passphrase never reuses them");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔ A LOCKED key is never destroyed by the node that cannot read it. Sealing is opt-in and must never cost
    /// liveness, so a missing or wrong passphrase makes the key LOCKED (`is_locked`: the role it serves turns off),
    /// and neither an unsealed write nor a write under the wrong passphrase may replace it.
    /// TWO-PARTY-REVIEWED: one node's own disk, no boundary crossed; the adversary is a misconfigured restart.
    #[test]
    fn a_locked_key_is_never_overwritten_and_names_itself_locked() {
        let pw: &[u8] = b"pw-locked-pin";
        let dir = std::env::temp_dir().join(format!("musd-keystore-locked-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("validator-9.key");
        write_key_file_with(&path, b"the real identity", Some(pw)).expect("sealed under the operator's choice");
        let no_pass = read_key_file_with(&path, None).expect_err("sealed, no passphrase");
        assert!(is_locked(&no_pass), "a missing passphrase reads as LOCKED");
        let wrong = read_key_file_with(&path, Some(b"wrong")).expect_err("sealed, wrong passphrase");
        assert!(is_locked(&wrong), "a wrong passphrase reads as LOCKED");
        let clobber = write_key_file_with(&path, b"a fresh random key", None).expect_err("no unsealed overwrite");
        assert!(is_locked(&clobber), "⛔ an unsealed write must not replace a locked key");
        assert!(
            write_key_file_with(&path, b"a fresh random key", Some(b"wrong")).is_err(),
            "⛔ a write under the wrong passphrase must not re-seal over a key it cannot open"
        );
        assert_eq!(
            read_key_file_with(&path, Some(pw)).expect("the right passphrase still opens it"),
            b"the real identity".to_vec(),
            "the locked key survived every refused write intact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drop every unlock held for `pass`: what a process restart does to the table.
    fn forget_unlocks_of(pass: &[u8]) {
        let digest = pass_digest(pass);
        UNLOCKED.lock().expect("unlock table").retain(|u| u.pass != digest);
    }
}

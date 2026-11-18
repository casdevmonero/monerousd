// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Letter (wallet side)** — the SELF-CUSTODIAL crypto engine for MoneroUSD's private messenger. Sealing and
//! opening happen HERE, in the wallet, with the seed-derived keys the wallet already holds — the node is only a
//! metadata-blind relay and NEVER sees a Letter secret. Three properties, by construction:
//!
//!   1. **PQ end-to-end seal.** A letter is sealed to the recipient's **ML-KEM-768** encapsulation key (the same
//!      `scan_ek` inside their wallet address — one identity for money AND messages): encapsulate → 32-byte
//!      shared secret → a blake3-keyed AEAD over the body. No classical crypto anywhere.
//!   2. **Authenticated sealed-sender.** The body carries the sender's **ML-DSA-65** verification key + a
//!      signature over `recipient_ek ‖ msg`, so the recipient AUTHENTICATES who wrote it (no impersonation) and
//!      a letter sealed to one person cannot be replayed to another. The sender identity lives INSIDE the seal —
//!      only the recipient learns it; the relay never does.
//!   3. **Identity from the seed, not a phone/email/IP.** The Letter address IS the wallet address (seed-derived,
//!      restorable from the 24 words, stable across restarts and devices). Nothing to register, no server to ask.
//!
//! The wire blob framing (`kem_ct ‖ nonce ‖ tag ‖ ciphertext`) matches the node's `crate::letter` relay, so the
//! node relays it opaquely and never needs a Letter key of its own.

use blake3;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MLKEM_CT_LEN: usize = 1088; // ML-KEM-768 ciphertext bytes
const MLDSA_PK_LEN: usize = fips204::ml_dsa_65::PK_LEN; // 1952
const MLDSA_SIG_LEN: usize = fips204::ml_dsa_65::SIG_LEN; // 3309

/// Two AEAD subkeys from the ML-KEM shared secret (domain-separated). Byte-identical to the node's
/// `crate::letter::subkeys`, so a wallet-sealed blob and a node-sealed blob interoperate.
fn subkeys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut e = blake3::Hasher::new();
    e.update(b"MONEROUSD-LETTER-ENC");
    e.update(shared);
    let mut m = blake3::Hasher::new();
    m.update(b"MONEROUSD-LETTER-MAC");
    m.update(shared);
    (*e.finalize().as_bytes(), *m.finalize().as_bytes())
}

/// blake3 counter-mode keystream XOR — a quantum-safe stream cipher keyed by the ML-KEM shared secret.
fn xor_keystream(k_enc: &[u8; 32], nonce: &[u8], data: &mut [u8]) {
    let mut off = 0usize;
    let mut counter: u64 = 0;
    while off < data.len() {
        let mut h = blake3::Hasher::new();
        h.update(k_enc);
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

/// fips203 ML-KEM-768 encapsulate to `ek_bytes` (recipient's scan_ek). Returns `(shared_secret[32], ct[1088])`.
fn encaps(ek_bytes: &[u8]) -> Option<([u8; 32], [u8; MLKEM_CT_LEN])> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(ek_bytes).ok()?).ok()?;
    let (ss, ct) = ek.try_encaps().ok()?;
    Some((ss.into_bytes(), ct.into_bytes()))
}

/// fips203 ML-KEM-768 decapsulate `ct` with our `dk_bytes` (scan_dk). A wrong key yields a different secret
/// (implicit rejection) → the MAC below fails, so a not-for-us blob simply does not open.
fn decaps(ct_bytes: &[u8], dk_bytes: &[u8]) -> Option<[u8; 32]> {
    use fips203::traits::{Decaps as _, SerDes as _};
    let dk = fips203::ml_kem_768::DecapsKey::try_from_bytes(<[u8; 2400]>::try_from(dk_bytes).ok()?).ok()?;
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(<[u8; MLKEM_CT_LEN]>::try_from(ct_bytes).ok()?).ok()?;
    Some(dk.try_decaps(&ct).ok()?.into_bytes())
}

/// SEAL `msg` from us (`my`) to recipient address `to_addr`. Returns the opaque relay blob
/// `kem_ct ‖ nonce ‖ tag ‖ ciphertext`, or `None` on a malformed address/keys. The sealed body is
/// `spend_pk ‖ sig ‖ fromlen ‖ from_addr ‖ msg`, where `sig = ML-DSA(recipient_ek ‖ msg)` — authenticated,
/// non-replayable, sealed-sender.
pub fn seal(to_addr: &str, my: &crate::pq::WalletKeys, my_from_addr: &str, msg: &[u8]) -> Option<Vec<u8>> {
    let (_tag, _b, to_ek) = crate::pq::parse_address(to_addr)?;
    let (shared, kem_ct) = encaps(&to_ek)?;
    let (k_enc, k_mac) = subkeys(&shared);
    let nonce: Vec<u8> = blake3::hash(&kem_ct).as_bytes()[..NONCE_LEN].to_vec();

    // sig binds BOTH the recipient (anti-replay to another person) and the message.
    let mut signed = Vec::with_capacity(to_ek.len() + msg.len());
    signed.extend_from_slice(&to_ek);
    signed.extend_from_slice(msg);
    let sig = crate::pq::sign_spend(my, &signed)?;
    if sig.len() != MLDSA_SIG_LEN || my.spend_pk.len() != MLDSA_PK_LEN {
        return None;
    }
    let fa = my_from_addr.as_bytes();
    let mut body = Vec::with_capacity(MLDSA_PK_LEN + MLDSA_SIG_LEN + 2 + fa.len() + msg.len());
    body.extend_from_slice(&my.spend_pk);
    body.extend_from_slice(&sig);
    body.extend_from_slice(&(fa.len() as u16).to_le_bytes());
    body.extend_from_slice(fa);
    body.extend_from_slice(msg);
    xor_keystream(&k_enc, &nonce, &mut body);
    let mut mac_in = Vec::with_capacity(nonce.len() + body.len());
    mac_in.extend_from_slice(&nonce);
    mac_in.extend_from_slice(&body);
    let tag = blake3::keyed_hash(&k_mac, &mac_in);
    let mut blob = Vec::with_capacity(kem_ct.len() + NONCE_LEN + TAG_LEN + body.len());
    blob.extend_from_slice(&kem_ct);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&tag.as_bytes()[..TAG_LEN]);
    blob.extend_from_slice(&body);
    Some(blob)
}

/// An opened, AUTHENTICATED letter.
pub struct Opened {
    pub from_addr: String,
    pub msg: Vec<u8>,
}

/// Open AND fully authenticate `blob`: decrypt with `my_scan_dk`, then verify the sender's ML-DSA signature
/// over `my_scan_ek ‖ msg` and that `blake3(spend_pk)` matches the claimed `from_addr`'s spend tag. Returns
/// `Some` ONLY for a letter that is genuinely OURS and genuinely FROM the address it claims — the oblivious
/// scan tries every relay slot and only these open. A tampered blob, a wrong recipient, or a forged sender all
/// return `None`. Never a panic.
pub fn open_authenticated(blob: &[u8], my_scan_ek: &[u8], my_scan_dk: &[u8]) -> Option<Opened> {
    if blob.len() < MLKEM_CT_LEN + NONCE_LEN + TAG_LEN {
        return None;
    }
    let kem_ct = &blob[..MLKEM_CT_LEN];
    let nonce = &blob[MLKEM_CT_LEN..MLKEM_CT_LEN + NONCE_LEN];
    let tag = &blob[MLKEM_CT_LEN + NONCE_LEN..MLKEM_CT_LEN + NONCE_LEN + TAG_LEN];
    let body_enc = &blob[MLKEM_CT_LEN + NONCE_LEN + TAG_LEN..];
    let shared = decaps(kem_ct, my_scan_dk)?;
    let (k_enc, k_mac) = subkeys(&shared);
    let mut mac_in = Vec::with_capacity(nonce.len() + body_enc.len());
    mac_in.extend_from_slice(nonce);
    mac_in.extend_from_slice(body_enc);
    let expect = blake3::keyed_hash(&k_mac, &mac_in);
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= expect.as_bytes()[i] ^ tag[i];
    }
    if diff != 0 {
        return None; // not sealed to us (or tampered) — implicit rejection
    }
    let mut body = body_enc.to_vec();
    xor_keystream(&k_enc, nonce, &mut body);
    if body.len() < MLDSA_PK_LEN + MLDSA_SIG_LEN + 2 {
        return None;
    }
    let spend_pk = body[..MLDSA_PK_LEN].to_vec();
    let sig = body[MLDSA_PK_LEN..MLDSA_PK_LEN + MLDSA_SIG_LEN].to_vec();
    let rest = &body[MLDSA_PK_LEN + MLDSA_SIG_LEN..];
    let flen = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + flen {
        return None;
    }
    let from_addr = String::from_utf8_lossy(&rest[2..2 + flen]).to_string();
    let msg = rest[2 + flen..].to_vec();

    // (a) authenticate the signature over (our ek ‖ msg) — proves the sender sealed THIS message to US.
    let mut signed = Vec::with_capacity(my_scan_ek.len() + msg.len());
    signed.extend_from_slice(my_scan_ek);
    signed.extend_from_slice(&msg);
    if !crate::pq::verify_spend(&spend_pk, &signed, &sig) {
        return None; // forged / tampered sender — reject
    }
    // (b) bind the signing key to the claimed from_addr (its spend tag b == blake3(spend_pk)).
    match crate::pq::parse_address(&from_addr) {
        Some((_t, b, _ek)) if *blake3::hash(&spend_pk).as_bytes() == b => {}
        _ => return None, // spend_pk does not match the claimed sender address
    }
    Some(Opened { from_addr, msg })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq;

    #[test]
    fn seal_open_authenticated_roundtrip_and_reject_forgery_tamper_wrong_recipient() {
        let alice = pq::derive_keys(&[7u8; 32]);
        let bob = pq::derive_keys(&[9u8; 32]);
        let eve = pq::derive_keys(&[13u8; 32]);

        let blob = seal(&bob.handle_address, &alice, &alice.handle_address, b"meet at the old oak").expect("seal");

        // Bob opens + authenticates — real PQ end-to-end, sender proven.
        let opened = open_authenticated(&blob, &bob.scan_ek, &bob.scan_dk).expect("bob opens");
        assert_eq!(opened.msg, b"meet at the old oak");
        assert_eq!(opened.from_addr, alice.handle_address, "recipient learns the authenticated sender");

        // A DIFFERENT recipient cannot open (wrong ML-KEM key → MAC fails).
        assert!(open_authenticated(&blob, &eve.scan_ek, &eve.scan_dk).is_none(), "wrong recipient must not open");

        // A TAMPERED byte fails the MAC.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(open_authenticated(&bad, &bob.scan_ek, &bob.scan_dk).is_none(), "tampered blob must reject");

        // A FORGED sender: Eve seals to Bob but stamps Alice's from_addr — the signature is Eve's key, whose
        // blake3 != Alice's spend tag, so authentication rejects (no impersonation).
        let forged = seal(&bob.handle_address, &eve, &alice.handle_address, b"send me 100").expect("seal");
        assert!(
            open_authenticated(&forged, &bob.scan_ek, &bob.scan_dk).is_none(),
            "a letter claiming a from_addr it cannot sign for must be REJECTED"
        );
    }
}

#[cfg(test)]
mod dir_interop_tests {
    /// The wallet SIGNS directory entries with fips204; the node VERIFIES with pqcrypto (PQClean). If the
    /// two ML-DSA-65 implementations disagree on the detached-signature encoding, every wallet-signed
    /// sign-up is refused at submit — exactly the live `[dir-submit] REFUSED — signature invalid` symptom.
    #[test]
    fn wallet_fips204_signature_verifies_under_the_node_pqcrypto_verifier() {
        use usdmd_node::pqauth::PqVerifier as _;
        let mut ent = [7u8; 32];
        ent[0] = 42;
        let keys = crate::pq::derive_keys(&ent);
        let msg = usdmd_node::directory::dir_register_msg(
            usdmd_node::directory::KIND_PROFILE,
            &keys.handle_address,
            &keys.handle_address,
            "Cas",
            "bio\u{1f}2000000",
        );
        let sig = crate::pq::sign_spend(&keys, &msg).expect("sign");
        assert!(
            usdmd_node::pqauth::MlDsaVerifier.verify(&keys.spend_pk, &msg, &sig),
            "fips204 signature must verify under the node's pqcrypto ML-DSA-65 verifier"
        );
        assert!(
            usdmd_node::directory::profile_binding_ok(&usdmd_node::directory::DirEntry {
                kind: usdmd_node::directory::KIND_PROFILE,
                key: keys.handle_address.clone(),
                address: keys.handle_address.clone(),
                name: "Cas".into(),
                topic: "bio\u{1f}2000000".into(),
                pubkey: keys.spend_pk.clone(),
                sig,
                pic: None,
            }),
            "the wallet's own handle address must pass the profile binding"
        );
    }
}

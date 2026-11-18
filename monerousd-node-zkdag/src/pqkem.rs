// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Post-quantum key encapsulation — **ML-KEM-768** (FIPS 203, NIST security level 3).
//!
//! This is the real PQ key-establishment the Sphinx mix ([`crate::mix`]) uses for its per-hop shared
//! secret: the sender ENCAPSULATES to each hop's ML-KEM public key, getting a `(shared_secret,
//! ciphertext)` pair; the ciphertext rides in that hop's layer, and the hop DECAPSULATES it with its
//! secret key to recover the same shared secret, which keys the layer. No classical Diffie-Hellman —
//! key establishment is post-quantum end to end. `pubkey`/`secret`/`ciphertext` are the ML-KEM-768
//! encoded bytes; the shared secret is 32 bytes.

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

/// A fresh ML-KEM-768 keypair as bytes: `(encapsulation public key, decapsulation secret key)`.
pub fn keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mlkem768::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// The fixed ML-KEM-768 ciphertext length in bytes — used to frame a per-hop KEM ciphertext inside a
/// Sphinx mix layer ([`crate::mix`]).
pub fn ciphertext_len() -> usize {
    mlkem768::ciphertext_bytes()
}

/// Encapsulate to `pubkey`. Returns `(shared_secret, ciphertext)`, or `None` if the key is malformed
/// (never a panic). The ciphertext travels to the hop; the shared secret keys its mix layer.
pub fn encapsulate(pubkey: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let pk = mlkem768::PublicKey::from_bytes(pubkey).ok()?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    Some((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// Decapsulate `ciphertext` with `secret`. Returns the shared secret, or `None` on malformed input.
/// Equals the encapsulator's shared secret iff the matching secret key is used; a wrong key yields a
/// different secret (ML-KEM's IND-CCA implicit rejection — it never signals which).
pub fn decapsulate(ciphertext: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    let ct = mlkem768::Ciphertext::from_bytes(ciphertext).ok()?;
    let sk = mlkem768::SecretKey::from_bytes(secret).ok()?;
    Some(mlkem768::decapsulate(&ct, &sk).as_bytes().to_vec())
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_encap_decap_roundtrip_and_reject_wrong_key() {
        let (pk, sk) = keypair();
        let (ss_enc, ct) = encapsulate(&pk).expect("encapsulate");
        let ss_dec = decapsulate(&ct, &sk).expect("decapsulate");
        // the encapsulated + decapsulated shared secrets agree — real PQ key establishment.
        assert_eq!(ss_enc, ss_dec, "shared secrets match");
        assert_eq!(ss_enc.len(), 32, "ML-KEM-768 shared secret is 32 bytes");

        // a DIFFERENT secret key recovers a DIFFERENT secret (implicit rejection, not an error).
        let (_pk2, sk2) = keypair();
        let ss_wrong = decapsulate(&ct, &sk2).expect("decapsulate runs under a wrong key");
        assert_ne!(
            ss_enc, ss_wrong,
            "wrong key yields a different shared secret"
        );

        // malformed inputs return None (never panic).
        assert!(encapsulate(b"too-short").is_none());
        assert!(decapsulate(b"too-short", &sk).is_none());
        assert!(decapsulate(&ct, b"too-short").is_none());
    }

    #[test]
    fn independent_encapsulations_differ() {
        // two encapsulations to the same key produce independent secrets + ciphertexts (fresh
        // randomness) — so a per-hop key is never reused across packets.
        let (pk, _sk) = keypair();
        let (ss1, ct1) = encapsulate(&pk).unwrap();
        let (ss2, ct2) = encapsulate(&pk).unwrap();
        assert_ne!(ss1, ss2);
        assert_ne!(ct1, ct2);
    }
}

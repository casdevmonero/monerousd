// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The check of the signature an outside carrier puts on its own mail.
//!
//! User 2026-11-09: "we dont control external companies classical crypto". A carrier signs its notices with
//! the pre-quantum scheme its mail system uses. This file only VERIFIES that signature, at the external
//! endpoint, exactly as the bridge verifies a foreign chain's. Nothing of ours is signed, keyed or proven
//! with it: MonerousD's own keys, signatures and proofs stay post-quantum.
//!
//! The check is the strict one: the signature is raised to the public exponent, and the result must equal
//! the one correctly padded encoding of the digest, byte for byte. Nothing is parsed out of the result, so
//! the forgeries that fool a lenient parser have nothing to fool.
//!
//! cons: none. A pure function of three byte strings.

use num_bigint::BigUint;

/// The DER prefix of a SHA-256 DigestInfo (RFC 8017 section 9.2, note 1).
const DIGEST_INFO_SHA256: [u8; 19] =
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
/// The object identifier of the carrier's key type inside a SubjectPublicKeyInfo: 1.2.840.113549.1.1.1.
const KEY_TYPE_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// A mail key shorter than this is refused (RFC 8301 section 3.2).
const MIN_MODULUS_BITS: u64 = 1024;

/// Read one DER element: its tag, its contents and what follows it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

fn expect(der: &[u8], want_tag: u8) -> Option<(&[u8], &[u8])> {
    let (tag, body, rest) = element(der)?;
    (tag == want_tag).then_some((body, rest))
}

/// The modulus and public exponent out of a SubjectPublicKeyInfo. Anything unexpected is no key.
fn key_parts(spki_der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (spki, after) = expect(spki_der, 0x30)?;
    if !after.is_empty() {
        return None;
    }
    let (algorithm, key_bits) = expect(spki, 0x30)?;
    let (oid, _params) = expect(algorithm, 0x06)?;
    if oid != KEY_TYPE_OID {
        return None;
    }
    let (bits, after) = expect(key_bits, 0x03)?;
    if !after.is_empty() {
        return None;
    }
    let (&unused, key) = bits.split_first()?;
    if unused != 0 {
        return None;
    }
    let (pair, after) = expect(key, 0x30)?;
    if !after.is_empty() {
        return None;
    }
    let (n, rest) = expect(pair, 0x02)?;
    let (e, after) = expect(rest, 0x02)?;
    if !after.is_empty() || n.is_empty() || e.is_empty() {
        return None;
    }
    Some((BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)))
}

/// True when `signature` is the carrier key's signature over the SHA-256 `digest`.
pub fn valid(spki_der: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    let Some((n, e)) = key_parts(spki_der) else { return false };
    let one = BigUint::from(1u8);
    if n.bits() < MIN_MODULUS_BITS || e <= one || (&e & &one) != one {
        return false;
    }
    let k = ((n.bits() + 7) / 8) as usize;
    if signature.len() != k || k < 3 + 8 + DIGEST_INFO_SHA256.len() + digest.len() {
        return false;
    }
    let s = BigUint::from_bytes_be(signature);
    if s >= n {
        return false;
    }
    let raised = s.modpow(&e, &n).to_bytes_be();
    if raised.len() > k {
        return false;
    }
    let mut got = vec![0u8; k - raised.len()];
    got.extend_from_slice(&raised);
    let mut want = Vec::with_capacity(k);
    want.extend_from_slice(&[0x00, 0x01]);
    want.resize(k - 1 - DIGEST_INFO_SHA256.len() - digest.len(), 0xff);
    want.push(0x00);
    want.extend_from_slice(&DIGEST_INFO_SHA256);
    want.extend_from_slice(digest);
    got == want
}

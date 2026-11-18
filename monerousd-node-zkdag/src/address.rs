// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! PQ stealth-address codec — the byte-for-byte encoder the wallet's `decodeAddr` (pq-address.cjs)
//! round-trips. A MonerousD PQ address is `base58( varint(tag) ‖ B(32) ‖ mlkem_ek(1184) ‖ keccak256(blob)[0..4] )`,
//! where `B` is the 32-byte spend tag and `mlkem_ek` is the ML-KEM-768 encapsulation key the sender
//! encapsulates a per-output shared secret to (POST-QUANTUM: the address carries an ML-KEM key, never a
//! classical curve point). The node emits these for the per-epoch confidential-fee target
//! (`get_pq_epoch_address`), so a wallet building a `pq_create_transfer` can address its fee output (out3).
//!
//! Every primitive here is post-quantum: the block-base58 is pure encoding, and the 4-byte checksum is
//! **Keccak-256** — a hash (Grover-only, ~128-bit PQ preimage security, the same posture as the blake3
//! the DAG uses for block ids) and the very permutation ML-KEM / ML-DSA are built on. Keccak (not blake3)
//! is used ONLY because the wallet's codec checksums with Keccak; matching it is what makes the address
//! decode wallet-side. No classical public-key crypto enters this path.

use sha3::{Digest, Keccak256};

/// Monero-style block-base58 alphabet (58 chars, no 0/O/I/l).
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Encoded-char count for a block of 0..=8 raw bytes (the cnBase58 size table).
const ENC_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK: usize = 8;

/// Network address tags (varint-prefixed), identical to the wallet's `PQ_ADDR_TAG`.
pub const PQ_ADDR_TAG_TESTNET: u64 = 0x315054;
pub const PQ_ADDR_TAG_STAGENET: u64 = 0x315053;
pub const PQ_ADDR_TAG_MAINNET: u64 = 0x31504d;

/// ML-KEM-768 encapsulation-key length — the address's `mlkem` field width.
pub const MLKEM_EK_LEN: usize = 1184;

/// Keccak-256 over `data` (original Keccak padding — matches the wallet's `@noble` `keccak_256`, NOT NIST SHA3).
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&out);
    o
}

/// LEB128 varint encode (identical to the wallet's `varintEncode`).
fn varint_encode(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

/// Encode one base58 block of `data.len()` (1..=8) raw bytes into its fixed cnBase58 char count.
fn b58_encode_block(data: &[u8]) -> String {
    let mut num: u128 = 0;
    for &b in data {
        num = (num << 8) | b as u128;
    }
    let enc_len = ENC_BLOCK_SIZES[data.len()];
    let mut out = vec![ALPHABET[0]; enc_len];
    let mut i = enc_len;
    while num > 0 && i > 0 {
        i -= 1;
        out[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    // ALPHABET is ASCII → always valid UTF-8.
    String::from_utf8_lossy(&out).into_owned()
}

/// cnBase58 encode: full 8-byte blocks (→11 chars) then a trailing partial block.
fn b58_encode(buf: &[u8]) -> String {
    let mut res = String::new();
    let full = buf.len() / FULL_BLOCK;
    let last = buf.len() % FULL_BLOCK;
    for i in 0..full {
        res.push_str(&b58_encode_block(
            &buf[i * FULL_BLOCK..(i + 1) * FULL_BLOCK],
        ));
    }
    if last > 0 {
        res.push_str(&b58_encode_block(&buf[full * FULL_BLOCK..]));
    }
    res
}

/// `base58( varint(tag) ‖ data ‖ keccak256(varint(tag) ‖ data)[0..4] )` — the wallet's `encodeAddr`.
pub fn encode_addr(tag: u64, data: &[u8]) -> String {
    let mut blob = varint_encode(tag);
    blob.extend_from_slice(data);
    let cksum = keccak256(&blob);
    blob.extend_from_slice(&cksum[0..4]);
    b58_encode(&blob)
}

/// Encode a full PQ stealth address from its spend tag `b` (32 bytes) and ML-KEM-768 encapsulation key
/// `mlkem` (1184 bytes). Returns `None` if `mlkem` is not exactly 1184 bytes (a malformed key would
/// produce an address the wallet rejects — fail-closed, never fabricate).
pub fn pq_stealth_address(tag: u64, b: &[u8; 32], mlkem: &[u8]) -> Option<String> {
    if mlkem.len() != MLKEM_EK_LEN {
        return None;
    }
    let mut data = Vec::with_capacity(32 + MLKEM_EK_LEN);
    data.extend_from_slice(b);
    data.extend_from_slice(mlkem);
    Some(encode_addr(tag, &data))
}

// ── Address DECODE — byte-identical to the wallet's `pq::parse_address`, the exact inverse of the encoder above,
//    so the node can read a wallet's OWN receive address back into its (network_tag, spend_tag, ML-KEM ek) parts. ──
const DEC_BLOCK_SIZES: [u8; 12] = [0, 0xFF, 1, 2, 0xFF, 3, 4, 5, 0xFF, 6, 7, 8];
fn b58_char_val(c: u8) -> Option<u128> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u128)
}
fn b58_decode_block(chars: &[u8]) -> Option<Vec<u8>> {
    if chars.len() >= DEC_BLOCK_SIZES.len() {
        return None;
    }
    let blen = DEC_BLOCK_SIZES[chars.len()];
    if blen == 0xFF {
        return None;
    }
    let blen = blen as usize;
    let mut num: u128 = 0;
    for &c in chars {
        num = num.checked_mul(58)?.checked_add(b58_char_val(c)?)?;
    }
    if blen < 16 && num >= (1u128 << (8 * blen)) {
        return None; // reject a non-canonical encoding whose value exceeds the block's byte width
    }
    let mut out = vec![0u8; blen];
    for i in 0..blen {
        out[blen - 1 - i] = (num & 0xff) as u8;
        num >>= 8;
    }
    Some(out)
}
fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let full = bytes.len() / 11;
    let rest = bytes.len() % 11;
    for i in 0..full {
        out.extend_from_slice(&b58_decode_block(&bytes[i * 11..(i + 1) * 11])?);
    }
    if rest > 0 {
        out.extend_from_slice(&b58_decode_block(&bytes[full * 11..])?);
    }
    Some(out)
}
fn varint_decode(data: &[u8]) -> Option<(u64, usize)> {
    let mut n: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        n |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((n, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}
/// Decode a MonerousD receive address into `(network_tag, spend_tag_b, ML-KEM-768 ek)`. `None` (fail-closed) on a
/// bad checksum / length / char — the node NEVER seals a note to a malformed address. `ek` is the ML-KEM
/// encapsulation key a note is sealed to; the recipient's scan SECRET never appears here.
pub fn parse_address(addr: &str) -> Option<(u64, [u8; 32], Vec<u8>)> {
    let p = parse_address_full(addr)?;
    Some((p.tag, p.b, p.mlkem))
}

/// A decoded receive address. `locator` is present only on a v2 address.
pub struct ParsedAddress {
    pub tag: u64,
    pub b: [u8; 32],
    pub mlkem: Vec<u8>,
    /// The one-time OLI locator this address hands out, if it is a v2 address. A sender shapes it into
    /// the note's clue-channel tag so the recipient can LOOK UP that note later instead of scanning for
    /// it. Opaque to the sender: a PRF output that only the recipient can reproduce or link.
    pub locator: Option<[u8; crate::oli::LOC_BYTES]>,
    /// The owner-minted `(salt, hint)` a v3 address carries alongside its locator.
    ///
    /// ⭐ THIS IS WHAT MAKES INFINITE SUBADDRESSES SAFE. Without it a recipient could only recognise its own
    /// tag by GUESSING the subaddress index and stopping somewhere — and wherever it stopped, a payment past
    /// that point was invisible forever. The owner masks the index into `hint` at address-creation time; the
    /// payer copies these two fields verbatim, learns nothing (the mask is a PRF only the owner can compute),
    /// and the recipient recovers the index in ONE step at ANY index.
    /// ([[project_oli_gap_limit_fund_loss]] · [[feedback_no_windows_no_caps_cardinal]])
    pub loc_salt: Option<[u8; 8]>,
    pub loc_hint: Option<[u8; 8]>,
    /// ⛔⛔⛔ DB-395 — the recipient's SPEND KEY `spk = P(ask, nk)` (a canonical digest), present only on a v4 address. A
    /// sealer commits the note to `o = P(spk, seed)`, so only the holder of `(ask, nk)` can spend it and only `nk` can
    /// compute its nullifier — the sender holds neither. An address WITHOUT it (v1/v2/v3) is never a send target: every
    /// sealer takes `spk` in its signature, so a send to one has nothing to seal with and is refused before a note exists.
    pub spk: Option<crate::spend_frontier::Digest4>,
}

/// ⛔ DB-395 — the version byte that opens a v4 address body. v4 is v1 or v3 with the spend key appended, and without this
/// byte a v4 HANDLE (`b ‖ mlkem ‖ spk`, 1,248 B) would be the same length as a v3 address (`b ‖ mlkem ‖ loc ‖ salt ‖ hint`,
/// 1,248 B): an old v3 address would parse as a handle whose "spk" is its locator, and a note sealed to it could never be
/// spent. The byte makes every v4 length distinct from every older one (1,249 and 1,281 against 1,216 / 1,232 / 1,248).
pub const ADDR_V4: u8 = 4;
/// The spend key's wire width: one canonical digest, `spend_frontier::leaf_to_cm_bytes`.
pub const SPK_BYTES: usize = 32;

/// Decode either address version. ONE parser for both, so v1 and v2 can never disagree about the parts
/// they share. The body LENGTH alone selects the version, and any other length is refused outright — a
/// malformed address fails closed instead of being read as the other version.
pub fn parse_address_full(addr: &str) -> Option<ParsedAddress> {
    let blob = b58_decode(addr)?;
    if blob.len() < 4 {
        return None;
    }
    let (body, cksum) = blob.split_at(blob.len() - 4);
    if keccak256(body)[0..4] != *cksum {
        return None;
    }
    let (tag, used) = varint_decode(body)?;
    let data = &body[used..];
    const V1_LEN: usize = 32 + MLKEM_EK_LEN;
    const V2_LEN: usize = 32 + MLKEM_EK_LEN + crate::oli::LOC_BYTES;
    const V3_LEN: usize = V2_LEN + 16;
    // DB-395: v4 = the version byte, then a v1 body (a HANDLE) or a v3 body (a RECEIVE address), then the spend key.
    const V4_HANDLE_LEN: usize = 1 + V1_LEN + SPK_BYTES;
    const V4_RECEIVE_LEN: usize = 1 + V3_LEN + SPK_BYTES;
    let mut b = [0u8; 32];
    match data.len() {
        V4_HANDLE_LEN | V4_RECEIVE_LEN if data[0] == ADDR_V4 => {
            let body = &data[1..data.len() - SPK_BYTES];
            let spk_bytes: [u8; SPK_BYTES] = data[data.len() - SPK_BYTES..].try_into().ok()?;
            // the injective decode — a non-canonical spend key is refused, never reduced into some other key
            let spk = crate::spend_frontier::cm_bytes_to_root(&spk_bytes)?;
            b.copy_from_slice(&body[0..32]);
            let (locator, loc_salt, loc_hint) = if body.len() == V3_LEN {
                let loc: [u8; crate::oli::LOC_BYTES] = body[V1_LEN..V2_LEN].try_into().ok()?;
                let salt: [u8; 8] = body[V2_LEN..V2_LEN + 8].try_into().ok()?;
                let hint: [u8; 8] = body[V2_LEN + 8..].try_into().ok()?;
                (Some(loc), Some(salt), Some(hint))
            } else {
                (None, None, None)
            };
            Some(ParsedAddress { tag, b, mlkem: body[32..V1_LEN].to_vec(), locator, loc_salt, loc_hint, spk: Some(spk) })
        }
        V1_LEN => {
            b.copy_from_slice(&data[0..32]);
            Some(ParsedAddress {
                tag,
                b,
                mlkem: data[32..].to_vec(),
                locator: None,
                loc_salt: None,
                loc_hint: None,
                spk: None,
            })
        }
        V2_LEN => {
            b.copy_from_slice(&data[0..32]);
            let loc: [u8; crate::oli::LOC_BYTES] = data[V1_LEN..].try_into().ok()?;
            Some(ParsedAddress {
                tag,
                b,
                mlkem: data[32..V1_LEN].to_vec(),
                locator: Some(loc),
                loc_salt: None,
                loc_hint: None,
                spk: None,
            })
        }
        // v3 = v2 plus the owner-minted (salt, hint). Every earlier length still parses exactly as before, so
        // an address already in someone's hands keeps working — a format change must never orphan funds.
        V3_LEN => {
            b.copy_from_slice(&data[0..32]);
            let loc: [u8; crate::oli::LOC_BYTES] = data[V1_LEN..V2_LEN].try_into().ok()?;
            let salt: [u8; 8] = data[V2_LEN..V2_LEN + 8].try_into().ok()?;
            let hint: [u8; 8] = data[V2_LEN + 8..].try_into().ok()?;
            Some(ParsedAddress {
                tag,
                b,
                mlkem: data[32..V1_LEN].to_vec(),
                locator: Some(loc),
                loc_salt: Some(salt),
                loc_hint: Some(hint),
                spk: None,
            })
        }
        _ => None,
    }
}

/// ⭐ DB-395 — encode a v4 address: the version byte, `b ‖ mlkem`, the receive locator triple when it is a RECEIVE address
/// (`None` for a published HANDLE), and the spend key `spk = P(ask, nk)` as its canonical 32 bytes. Fail-closed on a
/// malformed `mlkem`.
pub fn pq_stealth_address_v4(
    tag: u64,
    b: &[u8; 32],
    mlkem: &[u8],
    receive: Option<(&[u8; crate::oli::LOC_BYTES], &[u8; 8], &[u8; 8])>,
    spk: &crate::spend_frontier::Digest4,
) -> Option<String> {
    if mlkem.len() != MLKEM_EK_LEN {
        return None;
    }
    let mut data = Vec::with_capacity(1 + 32 + MLKEM_EK_LEN + crate::oli::LOC_BYTES + 16 + SPK_BYTES);
    data.push(ADDR_V4);
    data.extend_from_slice(b);
    data.extend_from_slice(mlkem);
    if let Some((locator, salt, hint)) = receive {
        data.extend_from_slice(locator);
        data.extend_from_slice(salt);
        data.extend_from_slice(hint);
    }
    data.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(*spk));
    Some(encode_addr(tag, &data))
}

/// Encode a v2 receive address: the v1 body plus the one-time OLI locator this address hands out.
/// Handing the locator to the payer IS the mechanism — it is the only channel that lets a sender tag a
/// note for a recipient who is offline, without letting any observer predict or link that tag.
pub fn pq_stealth_address_v2(
    tag: u64,
    b: &[u8; 32],
    mlkem: &[u8],
    locator: &[u8; crate::oli::LOC_BYTES],
) -> Option<String> {
    if mlkem.len() != MLKEM_EK_LEN {
        return None;
    }
    let mut data = Vec::with_capacity(32 + MLKEM_EK_LEN + crate::oli::LOC_BYTES);
    data.extend_from_slice(b);
    data.extend_from_slice(mlkem);
    data.extend_from_slice(locator);
    Some(encode_addr(tag, &data))
}

/// Encode a v3 receive address: v2 plus the owner-minted `(salt, hint)` that lets the recipient recognise a
/// payment to ANY subaddress index in one step.
///
/// ⛔ WHY THIS EXISTS. A v2 address hands out only the locator, and a locator is a pure PRF of its index — so
/// recognising a tag meant guessing the index and giving up after a fixed number of tries. Hand out 30
/// subaddresses, have only the 26th pay you, and that payment was invisible forever. Carrying the owner's own
/// masked index retires the guess entirely; there is no bound left to exceed.
pub fn pq_stealth_address_v3(
    tag: u64,
    b: &[u8; 32],
    mlkem: &[u8],
    locator: &[u8; crate::oli::LOC_BYTES],
    loc_salt: &[u8; 8],
    loc_hint: &[u8; 8],
) -> Option<String> {
    if mlkem.len() != MLKEM_EK_LEN {
        return None;
    }
    let mut data = Vec::with_capacity(32 + MLKEM_EK_LEN + crate::oli::LOC_BYTES + 16);
    data.extend_from_slice(b);
    data.extend_from_slice(mlkem);
    data.extend_from_slice(locator);
    data.extend_from_slice(loc_salt);
    data.extend_from_slice(loc_hint);
    Some(encode_addr(tag, &data))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn a_v3_address_carries_the_owner_index_hint_and_every_older_form_still_parses() {
        // ⛔ THE FUND LOSS THIS RETIRES. A v2 address hands out only the locator, and a locator is a pure PRF
        // of its subaddress index — so a recipient could only recognise its own tag by GUESSING the index and
        // giving up after a fixed number of tries. Hand out 30 subaddresses, have only the 26th pay you, and
        // that payment was invisible forever.
        //
        // user 2026-07-27: "the user should be able to generate an infinite amount of subaddresses and they
        // all work and aggregate funds forever. There should be no 20 address limit as that can cause funds
        // loss."
        let b = [7u8; 32];
        let mlkem = vec![0x5Au8; MLKEM_EK_LEN];
        let loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"MUSD/address/v3/owner").as_bytes());

        // A subaddress index FAR past anything an enumeration would ever reach.
        let j = 1_000_000u64;
        let loc = crate::oli::locator_at(&loc_sk, "recv", j);
        let salt = crate::oli::address_salt(&loc_sk, "recv", j);
        let hint = crate::oli::address_index_hint(&loc_sk, &salt, j);

        let addr = pq_stealth_address_v3(1, &b, &mlkem, &loc, &salt, &hint).expect("v3 encodes");
        let p = parse_address_full(&addr).expect("v3 parses");
        assert_eq!(p.b, b);
        assert_eq!(p.mlkem, mlkem);
        assert_eq!(
            p.locator,
            Some(loc),
            "the locator must survive the round trip"
        );
        assert_eq!(
            p.loc_salt,
            Some(salt),
            "the salt must survive — without it the hint cannot be unmasked"
        );
        assert_eq!(
            p.loc_hint,
            Some(hint),
            "the hint must survive — it IS the retired guess"
        );

        // ⭐ AND THE POINT: a payer that copies these fields into a tag produces one the OWNER recognises in
        // ONE step, at an index no enumeration would have reached.
        let tag = crate::oli::tag_clue_bytes_v2(
            &p.locator.unwrap(),
            &p.loc_salt.unwrap(),
            &p.loc_hint.unwrap(),
        );
        assert_eq!(
            crate::oli::owns_tag(&loc_sk, &["recv", "chg"], &tag),
            Some(("recv".to_string(), j)),
            "a payment to subaddress {j} must be recognised from the ADDRESS ALONE — no index guessing"
        );

        // ⛔ BACK-COMPAT IS NOT OPTIONAL: an address already in someone's hands must keep working, or a
        // format change orphans funds. v1 and v2 must parse exactly as before, and report no hint.
        let v1 = pq_stealth_address(1, &b, &mlkem).expect("v1 encodes");
        let p1 = parse_address_full(&v1).expect("v1 still parses");
        assert_eq!((p1.locator, p1.loc_salt, p1.loc_hint), (None, None, None));
        let v2 = pq_stealth_address_v2(1, &b, &mlkem, &loc).expect("v2 encodes");
        let p2 = parse_address_full(&v2).expect("v2 still parses");
        assert_eq!(p2.locator, Some(loc));
        assert_eq!(
            (p2.loc_salt, p2.loc_hint),
            (None, None),
            "v2 carries no hint, and must not invent one"
        );

        // The three forms are distinct strings and a tampered v3 is rejected by the checksum.
        assert!(v1 != v2 && v2 != addr);
        let mut bad = addr.clone();
        let last = bad.pop().expect("non-empty");
        bad.push(if last == '1' { '2' } else { '1' });
        assert!(
            parse_address_full(&bad).is_none(),
            "a tampered v3 address must be refused"
        );
    }

    /// The decoder is the exact inverse of the encoder (round-trip) and rejects a checksum-tampered address, so the
    /// node reads a real wallet address back to its ek AND fail-closes on a bad one (never seals to garbage).
    #[test]
    fn parse_address_round_trips_and_rejects_tamper() {
        let b = [7u8; 32];
        let ek = vec![9u8; MLKEM_EK_LEN];
        let addr = pq_stealth_address(PQ_ADDR_TAG_TESTNET, &b, &ek).expect("encode");
        let (tag, gb, gek) = parse_address(&addr).expect("decode a valid address");
        assert_eq!(tag, PQ_ADDR_TAG_TESTNET);
        assert_eq!(gb, b);
        assert_eq!(gek, ek, "recovers the exact ML-KEM ek to seal to");
        let mut bad = addr.clone();
        bad.pop();
        bad.push(if addr.ends_with('A') { 'B' } else { 'A' });
        assert!(
            parse_address(&bad).is_none(),
            "a tampered address must fail-closed (no note sealed)"
        );
    }

    #[test]
    fn encode_addr_matches_wallet_ground_truth() {
        // Ground-truth vector produced by the wallet's own codec (core/pq-address.cjs encodeAddr):
        //   encodeAddr(0x315054, [1,2,3,4]) === "cZkxwKA2vtB5RfAN2"
        // A match proves the base58 + varint + Keccak-256-checksum are byte-identical to the wallet, so a
        // node-served epoch address round-trips through the wallet's decodeAddr.
        assert_eq!(
            encode_addr(PQ_ADDR_TAG_TESTNET, &[1, 2, 3, 4]),
            "cZkxwKA2vtB5RfAN2"
        );
    }

    #[test]
    fn full_address_has_the_wallet_shape() {
        // B = 0..31, mlkem = 1184 zero bytes → the wallet encodes a 1683-char address whose data decodes
        // to 1216 bytes (32 + 1184). Assert the same length + head so the field layout matches.
        let b: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mlkem = vec![0u8; MLKEM_EK_LEN];
        let addr = pq_stealth_address(PQ_ADDR_TAG_TESTNET, &b, &mlkem).expect("valid mlkem len");
        assert_eq!(addr.len(), 1683);
        assert!(addr.starts_with("cZkxwK8Yc3U1fzjTfjCiMg31"));
        // wrong mlkem length is fail-closed
        assert!(pq_stealth_address(PQ_ADDR_TAG_TESTNET, &b, &[0u8; 100]).is_none());
    }

    /// ⭐ KNOWN-ANSWER TEST (KAT) — the surface census's row "primitive with no known-answer test: SHA3 / Keccak".
    /// `keccak256` is the ORIGINAL Keccak-256 (pad 0x01), the hash every address checksum is verified against on the
    /// wallet (`@noble` `keccak_256`); a wrong permutation, rate or padding would pass every round-trip test in this
    /// module and silently split node-served addresses from the wallet's codec. The reference vectors are the Keccak
    /// team's published Keccak-256 digests (the Ethereum "empty hash" among them); the NIST SHA3-256 digest of the
    /// empty string is asserted DIFFERENT, because SHA3's 0x06 domain padding is the one thing this helper must NOT be.
    #[test]
    fn keccak256_matches_the_reference_vectors_kat_and_is_not_nist_sha3() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
        }
        let vectors: [(&[u8], &str); 3] = [
            (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
            (
                b"The quick brown fox jumps over the lazy dog",
                "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
            ),
        ];
        for (msg, want) in vectors {
            assert_eq!(keccak256(msg).to_vec(), unhex(want), "Keccak-256 reference vector for {} byte(s)", msg.len());
        }
        // NIST SHA3-256("") — the domain-separated variant this helper must not be (the wallet checksums with Keccak).
        let nist_sha3_256_empty = unhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_ne!(keccak256(b"").to_vec(), nist_sha3_256_empty, "Keccak-256 and SHA3-256 differ in padding; the helper is Keccak");
        // the rate boundary (r = 1088 bits = 136 bytes for a 256-bit output): a message straddling it hashes to the same
        // digest whether absorbed whole or in two updates — the sponge state carries over the block boundary
        let long: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let whole = keccak256(&long);
        let mut h = Keccak256::new();
        h.update(&long[..137]);
        h.update(&long[137..]);
        let mut split = [0u8; 32];
        split.copy_from_slice(&h.finalize());
        assert_eq!(whole, split, "absorbing across the 136-byte rate boundary in two updates equals one update");
    }
}

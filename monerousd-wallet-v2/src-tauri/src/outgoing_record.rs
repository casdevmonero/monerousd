// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! DB-288 — THE SELF-NOTE'S OUTGOING RECORD: the nullifiers the transaction that made a note consumed, sealed into
//! that note's own clue tail, so a seed-only restore recovers this wallet's spent set without naming a single
//! nullifier to any node (the shape of Zcash Sapling's `out_ciphertext`, which lets a restored wallet recover what it
//! sent). Every tx this wallet builds that consumes a note emits a note to itself (a change, a payout, a receipt;
//! zero-value when needed) whose clue carries this record; a restore that finds the note opens the record.
//!
//! PILLAR-SAFE BY CONSTRUCTION:
//! - PRIVACY: the tail is `tag ‖ ciphertext`, pseudorandom under a key only this wallet can derive, so it is
//!   indistinguishable from the XOF bytes of any other clue's tail — a real record and a cover clue look alike.
//! - MISUSE-RESISTANT (SIV, review of DB-288 point A): the keystream is keyed by a MAC of the plaintext itself, so two
//!   DIFFERENT records sealed for the same note (a retry at the same dense index with the same change amount) leak
//!   only that they differ, never their XOR. The key is also bound to the carrying note's own commitment.
//! - POST-QUANTUM: blake3 only (`derive_key`, keyed hash, keyed XOF). No classical primitive anywhere.
//! - SOUND: a record informs this wallet's own display only. It moves no value and no node reads it. A record that
//!   does not open is simply absent: the note it would have covered stays listed for one chain answer (DB-279's rule
//!   for any note the own log does not cover), and it is never read as "unspent".
//! - FAST / NO GROWTH: fixed 560-byte tail, one keyed hash and one 544-byte XOF per seal or open; no term in history.

/// The clue bytes after its fixed 48-byte prefix (`salt ‖ hint ‖ XOF[..32]`): the part a record may occupy.
pub const TAIL_BYTES: usize = 560;
/// The synthetic IV: a truncated keyed MAC of the plaintext.
pub const TAG_BYTES: usize = 16;
/// `⌊(560 − 16 − 1) / 32⌋`: nullifiers one record carries. Every spend has ONE input today (DB-83).
pub const MAX_NULLIFIERS: usize = 16; // PRODUCTION-SCALE-REVIEWED: this record's own production capacity, derived from the fixed 560-B clue tail; not a block or cover count
const PLAIN_BYTES: usize = TAIL_BYTES - TAG_BYTES; // count(1) ‖ nf × 32 ‖ zero pad

/// The two per-note keys: bound to this wallet's outgoing seed AND the carrying note's own commitment.
fn keys(out_seed: &[u8; 32], cm_self: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(out_seed);
    m[32..].copy_from_slice(cm_self);
    (
        blake3::derive_key("MonerousD 2026-09-27 self-note outgoing record MAC v1", &m),
        blake3::derive_key("MonerousD 2026-09-27 self-note outgoing record ENC v1", &m),
    )
}

fn keystream(k_enc: &[u8; 32], tag: &[u8]) -> [u8; PLAIN_BYTES] {
    let mut ks = [0u8; PLAIN_BYTES];
    blake3::Hasher::new_keyed(k_enc).update(tag).finalize_xof().fill(&mut ks);
    ks
}

/// Seal `nfs` for the note whose commitment is `cm_self`. `None` when the record would not fit (> 16 nullifiers):
/// the caller splits the spend (the multi-note send already sequences single-input spends, DB-83).
pub fn seal(out_seed: &[u8; 32], cm_self: &[u8; 32], nfs: &[[u8; 32]]) -> Option<[u8; TAIL_BYTES]> {
    if nfs.len() > MAX_NULLIFIERS {
        return None;
    }
    let mut pt = [0u8; PLAIN_BYTES];
    pt[0] = nfs.len() as u8;
    for (i, nf) in nfs.iter().enumerate() {
        pt[1 + 32 * i..33 + 32 * i].copy_from_slice(nf);
    }
    let (k_mac, k_enc) = keys(out_seed, cm_self);
    let mac = blake3::keyed_hash(&k_mac, &pt);
    let tag = &mac.as_bytes()[..TAG_BYTES];
    let ks = keystream(&k_enc, tag);
    let mut out = [0u8; TAIL_BYTES];
    out[..TAG_BYTES].copy_from_slice(tag);
    for i in 0..PLAIN_BYTES {
        out[TAG_BYTES + i] = pt[i] ^ ks[i];
    }
    Some(out)
}

/// Open the record in `tail` for the note `cm_self`. `None` unless the tag verifies under this wallet's key for THIS
/// note, the count is within capacity and the padding is canonical (all zero): anything else is not a record.
pub fn open(out_seed: &[u8; 32], cm_self: &[u8; 32], tail: &[u8; TAIL_BYTES]) -> Option<Vec<[u8; 32]>> {
    let (k_mac, k_enc) = keys(out_seed, cm_self);
    let (tag, ct) = tail.split_at(TAG_BYTES);
    let ks = keystream(&k_enc, tag);
    let mut pt = [0u8; PLAIN_BYTES];
    for i in 0..PLAIN_BYTES {
        pt[i] = ct[i] ^ ks[i];
    }
    let mac = blake3::keyed_hash(&k_mac, &pt);
    // Constant-time over the 16 tag bytes: the comparison's timing says nothing about where they differ.
    let diff = mac.as_bytes()[..TAG_BYTES].iter().zip(tag).fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        return None;
    }
    let n = pt[0] as usize;
    if n > MAX_NULLIFIERS || pt[1 + 32 * n..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(
        (0..n)
            .map(|i| {
                let mut nf = [0u8; 32];
                nf.copy_from_slice(&pt[1 + 32 * i..33 + 32 * i]);
                nf
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(label: &str, i: u64) -> [u8; 32] {
        let mut hs = blake3::Hasher::new();
        hs.update(label.as_bytes()).update(&i.to_le_bytes());
        *hs.finalize().as_bytes()
    }

    /// The outgoing secret is what a seed-only restore needs to open its records: the same entropy derives the same
    /// secret, another entropy a different one, and it is never the locator secret (a separate domain).
    #[test]
    fn db288_the_outgoing_secret_is_seed_derived_and_separate_from_the_locator_secret() {
        let (a, b) = (h("entropy", 1), h("entropy", 2));
        let (ka, ka2, kb) = (crate::pq::derive_keys(&a), crate::pq::derive_keys(&a), crate::pq::derive_keys(&b));
        assert_eq!(ka.out_sk, ka2.out_sk, "a restore from the same seed derives the same outgoing secret");
        assert_ne!(ka.out_sk, kb.out_sk, "another seed, another secret");
        assert_ne!(ka.out_sk, ka.loc_sk, "never the locator secret");
        let cm = h("cm", 9);
        let tail = seal(&ka.out_sk, &cm, &[h("nf", 9)]).expect("fits");
        assert_eq!(open(&ka2.out_sk, &cm, &tail), Some(vec![h("nf", 9)]), "the restored wallet opens its own record");
        assert_eq!(open(&kb.out_sk, &cm, &tail), None, "another wallet does not");
    }

    /// A record round-trips at 0, 1 and the full capacity; one past capacity does not fit and is refused, never cut.
    #[test]
    fn db288_a_record_round_trips_and_an_over_capacity_one_is_refused() {
        let (seed, cm) = (h("seed", 0), h("cm", 0));
        for n in [0usize, 1, MAX_NULLIFIERS] {
            let nfs: Vec<[u8; 32]> = (0..n as u64).map(|i| h("nf", i)).collect();
            let tail = seal(&seed, &cm, &nfs).expect("fits");
            assert_eq!(open(&seed, &cm, &tail), Some(nfs), "{n} nullifiers round-trip");
        }
        let too_many: Vec<[u8; 32]> = (0..=MAX_NULLIFIERS as u64).map(|i| h("nf", i)).collect();
        assert!(seal(&seed, &cm, &too_many).is_none(), "one past capacity is refused, never silently cut");
    }

    /// TAMPERS, each REFUSED: another note's commitment, another wallet's seed, one flipped ciphertext bit, one
    /// flipped tag bit. A record is readable only by its own wallet, for its own note, byte-exact.
    #[test]
    fn db288_a_record_opens_only_for_its_own_wallet_and_note_and_only_untouched() {
        let (seed, cm) = (h("seed", 1), h("cm", 1));
        let nfs = vec![h("nf", 7)];
        let tail = seal(&seed, &cm, &nfs).expect("fits");
        assert_eq!(open(&seed, &cm, &tail), Some(nfs), "calibration: the untouched record opens");
        assert_eq!(open(&seed, &h("cm", 2), &tail), None, "sealed for another note's commitment");
        assert_eq!(open(&h("seed", 2), &cm, &tail), None, "another wallet's seed");
        for byte in [0usize, TAG_BYTES - 1, TAG_BYTES, TAG_BYTES + 40, TAIL_BYTES - 1] {
            let mut bad = tail;
            bad[byte] ^= 0x01;
            assert_eq!(open(&seed, &cm, &bad), None, "a flipped bit at byte {byte} is refused");
        }
    }

    /// REVIEW POINT (A), KEY REUSE: two DIFFERENT records sealed for the SAME note (a retry at the same dense index
    /// with the same change amount) carry different synthetic IVs, so their ciphertexts have NO XOR relation to the
    /// plaintexts. Equal records seal identically: equality is the only thing a reuse reveals.
    #[test]
    fn db288_two_records_for_one_note_leak_only_equality_never_their_xor() {
        let (seed, cm) = (h("seed", 3), h("cm", 3));
        let (p1, p2) = (vec![h("nf", 1)], vec![h("nf", 2)]);
        let (t1, t2) = (seal(&seed, &cm, &p1).expect("fits"), seal(&seed, &cm, &p2).expect("fits"));
        assert_ne!(t1[..TAG_BYTES], t2[..TAG_BYTES], "different records, different synthetic IVs");
        let ct_xor: Vec<u8> = t1[TAG_BYTES..TAG_BYTES + 33].iter().zip(&t2[TAG_BYTES..]).map(|(a, b)| a ^ b).collect();
        let mut pt1 = vec![1u8];
        pt1.extend_from_slice(&p1[0]);
        let mut pt2 = vec![1u8];
        pt2.extend_from_slice(&p2[0]);
        let pt_xor: Vec<u8> = pt1.iter().zip(&pt2).map(|(a, b)| a ^ b).collect();
        assert_ne!(ct_xor, pt_xor, "a stream reused across the two would make these equal: nf1 ⊕ nf2 public");
        assert_eq!(seal(&seed, &cm, &p1), Some(t1), "an equal record seals identically (deterministic)");
    }

    /// The tail is uniform: 200 seals (empty records among them, whose plaintext is almost all zero bytes) give a
    /// byte histogram whose chi-square over 255 degrees of freedom sits far below 400 (mean 255, sd ≈ 22.6, so a
    /// uniform source exceeds 400 with probability ≈ 1e-9). A leak of the zero padding would blow straight past it.
    #[test]
    fn db288_a_sealed_tail_is_uniform_like_a_cover_clue_tail() {
        let mut counts = [0u64; 256];
        for i in 0..200u64 {
            let n = (i % 3) as usize; // 0, 1 or 2 nullifiers: mostly zero padding underneath
            let nfs: Vec<[u8; 32]> = (0..n as u64).map(|k| h("nf-u", i * 16 + k)).collect();
            let tail = seal(&h("seed-u", i), &h("cm-u", i), &nfs).expect("fits");
            for b in tail {
                counts[b as usize] += 1;
            }
        }
        let total: u64 = counts.iter().sum();
        let expect = total as f64 / 256.0;
        let chi2: f64 = counts.iter().map(|c| (*c as f64 - expect).powi(2) / expect).sum();
        assert!(chi2 < 400.0, "chi-square {chi2:.1} over {total} bytes: the tail is not uniform");
    }
}

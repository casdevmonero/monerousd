// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =====================================================================================================
//! OMR — the OBLIVIOUS cold-restore keystone. Brick 1 = the post-quantum DETECTION CLUE; brick 2 (this file
//! now) = the PACKED clue that shrinks it ~20× so it can ride on a note without bloating the chain.
//!
//! ## The problem this solves
//! A fresh-device restore has to find every note this wallet owns among ALL notes on the chain. Today the
//! wallet fetches the note ciphertexts and ML-KEM-**decapsulates every one** with its scan key ([`crate::pq`]
//! `scan_note_full`): the decap is the expensive step, and running it on the whole chain is `O(chain)` — the
//! cold-restore cost that grows without bound (it breaks the no-growth pillar and the "instant regardless of
//! node" ease-of-use pillar). The 1-byte view-tag does NOT help: it is derived from the ML-KEM shared secret,
//! so it is only checkable AFTER the decap it was meant to save.
//!
//! ## The sound fix
//! Attach to each note a CHEAP-to-test post-quantum **detection clue** that is DECOUPLED from the ML-KEM decap.
//! The recipient runs a hash-and-inner-product test (no KEM) over every note — far cheaper than a decap — and
//! only the notes that PASS (the wallet's own notes, plus a negligible `2^-γ` false-positive tail) get the
//! expensive ML-KEM decap. Cost becomes `O(chain)·cheap + O(owned)·expensive` instead of `O(chain)·expensive`:
//! the decap work drops to `O(owned)`.
//!
//! ## Zero-leak (Pillar 1 — TRUE DIGITAL CASH)
//! Detection is done **by the recipient, wallet-side**, with a key that NEVER leaves the wallet — exactly like
//! the scan key. The node still serves every clue+note to everyone (as today), so it learns NOTHING new: no
//! bucket, no linkage, no per-recipient tag on chain. This is a strict speed win with **no privacy regression**
//! — unlike a leaky per-recipient bucket index, which the digital-cash cardinal forbids.
//!
//! ## Cryptography (post-quantum, no classical curve) — PACKED Regev/LWE
//! The clue encrypts a γ-bit pertinency word under the recipient's public clue key with **shared randomness**:
//! one LWE mask `a ∈ Z_q^N` is reused across all γ bits (a matrix secret `S ∈ Z_q^{N×γ}`, `B = A·S + E`), so a
//! whole clue is `(a[N], c[γ])` — `~4·(N+γ)` bytes — instead of γ separate ciphertexts. LWE is the same lattice
//! hardness family as ML-KEM (post-quantum). A clue for the intended recipient decrypts (under that recipient's
//! secret `S`) to all-ones → PERTINENT (no false negatives, ever). Under any OTHER wallet's secret each of the γ
//! bits is uniform → all-ones with probability `2^-γ` → a negligible false-positive tail. The clue is IND-CPA
//! hiding: without `S` it reveals nothing (LWE), so an observer or the node learns neither the pertinency word
//! nor the recipient. The public matrix `A` is expanded from a 32-byte public seed (as ML-KEM expands its `A`).
//! Clues add homomorphically — `enc(x)+enc(y)` decrypts to `x+y` (bounded) — the linear engine a later brick
//! folds the pertinency set into an `O(owned)` DOWNLOAD digest with. The clue keys DERIVE from the wallet's
//! 32-byte root entropy (itself minted by `OsRng` in [`crate::pq::generate`]) so restore reproduces them.
//!
//! Flagged follow-ups: (a) the `O(owned)` homomorphic DOWNLOAD digest (the `ct_add` engine is ready); (b) a
//! Ring-LWE instantiation to shrink `a` further + a NIST module-LWE parameter set; (c) wiring the packed clue
//! into the note seal + node serve + the wallet scan path.

use std::io::Read as _;
use zeroize::Zeroize;

/// Secret dimension (LWE `n`). Demo-scale, correctness-first; the hardening brick moves to a NIST-level
/// module-LWE (Ring-LWE) parameter set matching ML-KEM-768's security margin — see module docs.
pub const N: usize = 128;
/// Number of public LWE samples (`m`) summed by Regev encryption. `M · ERR_BOUND ≪ q/4` keeps decryption exact.
pub const M: usize = 64;
/// Error magnitude bound (`|e| ≤ ERR_BOUND`). Total encryption noise ≤ `M·ERR_BOUND = 2^12 ≪ q/4 = 2^30`, and a
/// homomorphic sum of thousands of clues still decrypts exactly — ample for the digest brick.
pub const ERR_BOUND: u32 = 64;
/// Clue width in bits: false-positive rate `2^-γ`. 24 → ~1 spurious candidate per 16.7M chain notes.
pub const GAMMA: usize = 24;

/// The plaintext "1" lives at `q/2` (`q = 2^32`, implicit in `u32` wrapping). Decryption rounds to the nearest
/// multiple of `q/2`. `|noise| < q/4` ⇒ exact.
const HALF_Q: u32 = 1u32 << 31;
const QUARTER_Q: u32 = 1u32 << 30;

/// A deterministic PRG stream (blake3 XOF) — keygen derives the secret reproducibly from the root entropy, and
/// the public matrix `A` is expanded from its 32-byte seed the same way on both keygen and encrypt.
fn stream(domain: &[u8], src: &[u8]) -> blake3::OutputReader {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/omr/v2");
    h.update(domain);
    h.update(src);
    h.finalize_xof()
}

fn next_u32(r: &mut blake3::OutputReader) -> u32 {
    let mut b = [0u8; 4];
    r.fill(&mut b); // the XOF reader's own infallible fill
    u32::from_le_bytes(b)
}

/// A small centered error in `[-ERR_BOUND, ERR_BOUND]`, represented as a `u32` mod `q` (so `-e` is `q - e`).
fn small_err(r: &mut blake3::OutputReader) -> u32 {
    let span = 2 * ERR_BOUND + 1;
    let v = next_u32(r) % span; // 0 ..= 2·ERR_BOUND
    v.wrapping_sub(ERR_BOUND) // shift to -ERR_BOUND ..= ERR_BOUND (wrapping = reduce mod q)
}

/// Expand the public matrix `A` (`M × N`, uniform mod `q`) from its 32-byte seed — never stored, always derived.
fn expand_a(seed_a: &[u8; 32]) -> Vec<[u32; N]> {
    let mut r = stream(b"A", seed_a);
    let mut a = Vec::with_capacity(M);
    for _ in 0..M {
        let mut row = [0u32; N];
        for x in row.iter_mut() {
            *x = next_u32(&mut r);
        }
        a.push(row);
    }
    a
}

/// The recipient's PUBLIC clue key: the 32-byte seed for `A` plus the γ public columns `B[k] = A·S[k] + E[k]`
/// (each length `M`). Published once per wallet (off-chain, in the address record); reveals nothing about `S`.
#[derive(Clone, PartialEq, Eq)]
pub struct CluePublicKey {
    pub seed_a: [u8; 32],
    /// `b[k][i] = ⟨A_i, S[k]⟩ + e`, i.e. γ columns of the public matrix `B ∈ Z_q^{M×γ}`.
    pub b: [[u32; M]; GAMMA],
}

impl CluePublicKey {
    /// Serialized size: `seed_a`(32) + the γ public columns of `M` u32 each. The opaque blob the node's clue
    /// directory stores + serves, and a sender resolves by the recipient's address `b`.
    pub const BYTES: usize = 32 + M * GAMMA * 4;

    /// Serialize to the directory blob (`seed_a ‖ b[γ][M]`, little-endian). Public data — no secret exposed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::BYTES);
        v.extend_from_slice(&self.seed_a);
        for col in &self.b {
            for &x in col {
                v.extend_from_slice(&x.to_le_bytes());
            }
        }
        v
    }

    /// Reconstruct from a served blob. `None` on a wrong length (a mis-sized key is rejected before use; the
    /// clue key is public so no secret is at risk either way — the sender just can't build a bad-shaped clue).
    pub fn from_bytes(bytes: &[u8]) -> Option<CluePublicKey> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let mut seed_a = [0u8; 32];
        seed_a.copy_from_slice(&bytes[..32]);
        let mut b = [[0u32; M]; GAMMA];
        let mut off = 32;
        for col in b.iter_mut() {
            for x in col.iter_mut() {
                let mut w = [0u8; 4];
                w.copy_from_slice(&bytes[off..off + 4]);
                *x = u32::from_le_bytes(w);
                off += 4;
            }
        }
        Some(CluePublicKey { seed_a, b })
    }
}

/// The recipient's SECRET clue key `S ∈ Z_q^{N×γ}` (γ secret columns of length `N`). NEVER leaves the wallet
/// (same discipline as the scan key). Zeroized on drop so the detection secret is wiped from memory on lock.
/// `Clone` copies the in-wallet secret (both copies zeroize on drop); it is used to hand the scanner its own
/// detection key without moving it out of the wallet's locked state.
#[derive(Clone)]
pub struct ClueSecretKey {
    s: [[u32; N]; GAMMA],
}
impl Drop for ClueSecretKey {
    fn drop(&mut self) {
        for col in self.s.iter_mut() {
            col.zeroize();
        }
    }
}

/// A note's PACKED detection clue: one shared LWE mask `a ∈ Z_q^N` plus the γ-bit ciphertext word `c ∈ Z_q^γ`.
/// `4·(N+γ)` bytes total (not γ separate ciphertexts) — the on-chain per-note cost.
#[derive(Clone, PartialEq, Eq)]
pub struct Clue {
    pub a: [u32; N],
    pub c: [u32; GAMMA],
}

impl Clue {
    /// On-chain size in bytes of a packed clue: shared mask `a[N]` + word `c[γ]`, 4 bytes each.
    pub const BYTES: usize = 4 * (N + GAMMA);

    /// Serialize the packed clue to the bytes attached to a note's tx (`a[N] ‖ c[γ]`, little-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::BYTES);
        for &x in &self.a {
            v.extend_from_slice(&x.to_le_bytes());
        }
        for &x in &self.c {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    /// Reconstruct a packed clue served by the node. `None` on a wrong length (a mis-sized clue is rejected;
    /// a bad clue only ever costs a wasted detection test — the note_cm binding still gates acceptance).
    pub fn from_bytes(bytes: &[u8]) -> Option<Clue> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let mut a = [0u32; N];
        let mut off = 0;
        for x in a.iter_mut() {
            let mut w = [0u8; 4];
            w.copy_from_slice(&bytes[off..off + 4]);
            *x = u32::from_le_bytes(w);
            off += 4;
        }
        let mut c = [0u32; GAMMA];
        for x in c.iter_mut() {
            let mut w = [0u8; 4];
            w.copy_from_slice(&bytes[off..off + 4]);
            *x = u32::from_le_bytes(w);
            off += 4;
        }
        Some(Clue { a, c })
    }
}

/// DERIVE the recipient's clue key pair FROM the wallet's 32-byte root entropy (a seed/mnemonic input — the
/// root is minted by `OsRng` in [`crate::pq::generate`]; restore reproduces the exact detection key). Each
/// secret column uses small entries (`|s| ≤ ERR_BOUND`) — a short secret keeps decryption noise small; a fresh
/// public seed makes `A` unique to this wallet.
pub fn derive_clue_key(entropy: &[u8; 32]) -> (CluePublicKey, ClueSecretKey) {
    // γ secret columns S[k] ∈ Z_q^N.
    let mut s = [[0u32; N]; GAMMA];
    for (k, col) in s.iter_mut().enumerate() {
        let mut rs = stream(
            b"s",
            &[entropy.as_ref(), &(k as u32).to_le_bytes()].concat(),
        );
        for x in col.iter_mut() {
            *x = small_err(&mut rs);
        }
    }
    // A public seed bound to this wallet's entropy (public — it only names the uniform matrix A).
    let seed_a = *blake3::hash(&[b"MUSD/omr/seedA/v2".as_ref(), entropy].concat()).as_bytes();
    let a = expand_a(&seed_a);
    // B[k][i] = ⟨A_i, S[k]⟩ + e   (γ public columns of length M).
    let mut b = [[0u32; M]; GAMMA];
    for (k, bcol) in b.iter_mut().enumerate() {
        let mut re = stream(
            b"e",
            &[entropy.as_ref(), &(k as u32).to_le_bytes()].concat(),
        );
        for (i, bik) in bcol.iter_mut().enumerate() {
            let mut acc = 0u32;
            for j in 0..N {
                acc = acc.wrapping_add(a[i][j].wrapping_mul(s[k][j]));
            }
            *bik = acc.wrapping_add(small_err(&mut re));
        }
    }
    (CluePublicKey { seed_a, b }, ClueSecretKey { s })
}

/// Encrypt a γ-bit word under `pk` with SHARED randomness (packed Regev): pick `r ∈ {0,1}^M`, set the shared
/// mask `a = rᵀA`, and `c[k] = rᵀB[k] + msg[k]·q/2`. `rand_src` supplies `r` (senders pass fresh CSPRNG
/// entropy; tests pass a constant nonce for reproducibility).
pub fn enc_word(pk: &CluePublicKey, msg: &[u32; GAMMA], rand_src: &[u8]) -> Clue {
    let a_pub = expand_a(&pk.seed_a);
    let mut rr = stream(b"r", rand_src);
    let mut a = [0u32; N];
    let mut c = [0u32; GAMMA];
    for i in 0..M {
        // r_i ∈ {0,1}: include public sample i in every column's subset sum iff the coin is 1.
        if next_u32(&mut rr) & 1 == 1 {
            for j in 0..N {
                a[j] = a[j].wrapping_add(a_pub[i][j]);
            }
            for k in 0..GAMMA {
                c[k] = c[k].wrapping_add(pk.b[k][i]);
            }
        }
    }
    for k in 0..GAMMA {
        c[k] = c[k].wrapping_add(msg[k].wrapping_mul(HALF_Q)); // + msg_k·q/2
    }
    Clue { a, c }
}

/// Decrypt the γ-bit word with the secret `S`: `v_k = c_k − ⟨a, S[k]⟩ ≈ msg_k·q/2 + noise`, rounded to `q/2`.
pub fn dec_word(sk: &ClueSecretKey, clue: &Clue) -> [u32; GAMMA] {
    let mut out = [0u32; GAMMA];
    for k in 0..GAMMA {
        let mut inner = 0u32;
        for j in 0..N {
            inner = inner.wrapping_add(clue.a[j].wrapping_mul(sk.s[k][j]));
        }
        let v = clue.c[k].wrapping_sub(inner);
        out[k] = (v.wrapping_add(QUARTER_Q) >> 31) & 1; // round(v / (q/2)) mod 2
    }
    out
}

/// Homomorphic add: `enc(x) + enc(y)` decrypts to `x+y` (mod 2 per bit, while noise stays `< q/4`). The linear
/// engine the download-digest follow-up brick folds the pertinency set with.
pub fn ct_add(x: &Clue, y: &Clue) -> Clue {
    let mut a = [0u32; N];
    for j in 0..N {
        a[j] = x.a[j].wrapping_add(y.a[j]);
    }
    let mut c = [0u32; GAMMA];
    for k in 0..GAMMA {
        c[k] = x.c[k].wrapping_add(y.c[k]);
    }
    Clue { a, c }
}

/// SENDER: build a note's packed detection clue for `recipient_pk` — encrypt the all-ones γ-bit word. `rand_src`
/// is fresh per-note CSPRNG entropy.
pub fn make_clue(recipient_pk: &CluePublicKey, rand_src: &[u8; 32]) -> Clue {
    enc_word(recipient_pk, &[1u32; GAMMA], rand_src)
}

/// RECIPIENT (wallet-side, secret never leaves): does this clue detect for me? True iff the decrypted word is
/// all-ones. Own note → always true (no false negative). Foreign note → true with probability `2^-γ`. This is
/// the CHEAP test run on every chain note; only the notes it passes get the expensive ML-KEM decap — so the
/// decap count drops from `O(chain)` to `O(owned)`.
pub fn is_pertinent(sk: &ClueSecretKey, clue: &Clue) -> bool {
    dec_word(sk, clue).iter().all(|&bit| bit == 1)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A reproducible test wallet: its root entropy is DERIVED from a label (a fixed test vector, not a minted
    /// key) so each `kp(label)` names a distinct, stable clue key pair without any all-zero/constant fill.
    fn kp(label: &str) -> (CluePublicKey, ClueSecretKey) {
        let entropy = *blake3::hash(format!("MUSD/omr/test-vector/{label}").as_bytes()).as_bytes();
        derive_clue_key(&entropy)
    }

    fn nonce_of(label: &str) -> [u8; 32] {
        *blake3::hash(format!("MUSD/omr/test-nonce/{label}").as_bytes()).as_bytes()
    }

    #[test]
    fn packed_word_roundtrips() {
        // A γ-bit word encrypts + decrypts exactly under the shared-mask packed scheme.
        let (pk, sk) = kp("roundtrip");
        let mut msg = [0u32; GAMMA];
        for (i, m) in msg.iter_mut().enumerate() {
            *m = (i % 2) as u32; // 0,1,0,1,... a non-trivial word
        }
        let ct = enc_word(&pk, &msg, b"nonce-a");
        assert_eq!(
            dec_word(&sk, &ct),
            msg,
            "packed LWE word must decrypt exactly"
        );
    }

    #[test]
    fn additive_homomorphism_holds() {
        // enc(x) + enc(y) decrypts to x XOR y per bit (mod 2) — the linear digest engine over the shared mask.
        let (pk, sk) = kp("homomorphic");
        let x = [1u32; GAMMA];
        let mut y = [0u32; GAMMA];
        y[0] = 1;
        y[5] = 1;
        let sum = ct_add(&enc_word(&pk, &x, b"x"), &enc_word(&pk, &y, b"y"));
        let got = dec_word(&sk, &sum);
        for k in 0..GAMMA {
            assert_eq!(got[k], (x[k] + y[k]) % 2, "bit {k}: (x+y) mod 2");
        }
    }

    #[test]
    fn own_clue_is_always_pertinent_no_false_negative() {
        // A clue built under MY public key ALWAYS detects for me — a restore never misses an owned note.
        let (pk, sk) = kp("owner");
        for i in 0u32..256 {
            let note_nonce = *blake3::hash(&i.to_le_bytes()).as_bytes();
            let clue = make_clue(&pk, &note_nonce);
            assert!(
                is_pertinent(&sk, &clue),
                "own note #{i} must be detected (no false negatives)"
            );
        }
    }

    #[test]
    fn foreign_clue_is_negligibly_pertinent_and_needs_my_secret() {
        // Clues for a DIFFERENT recipient must (essentially) never detect for me — that is what shrinks the
        // expensive-decap set to O(owned). γ=24 ⇒ 2^-24 per note; over 4096 foreign notes, expect ZERO hits.
        let (_pk_me, sk_me) = kp("me-neg");
        let (pk_other, _sk_other) = kp("other-neg");
        let mut hits = 0usize;
        for i in 0u32..4096 {
            let note_nonce =
                *blake3::hash(&[b"foreign".as_ref(), &i.to_le_bytes()].concat()).as_bytes();
            let clue = make_clue(&pk_other, &note_nonce);
            if is_pertinent(&sk_me, &clue) {
                hits += 1;
            }
        }
        assert_eq!(
            hits, 0,
            "foreign clues must not detect for me (2^-24 tail ⇒ 0 over 4096)"
        );
    }

    #[test]
    fn wrong_secret_cannot_detect_own_clue_zero_leak() {
        // The clue is only testable with the recipient's SECRET. A clue for me, tested with the WRONG secret,
        // is NOT pertinent — detection cannot be done without the key (so the node / an observer learns nothing).
        let (pk_me, _sk_me) = kp("mine-zl");
        let (_pk_wrong, sk_wrong) = kp("wrong-zl");
        let clue = make_clue(&pk_me, &nonce_of("only-mine"));
        assert!(
            !is_pertinent(&sk_wrong, &clue),
            "a foreign secret must not detect my clue (zero-leak)"
        );
    }

    #[test]
    fn candidate_set_shrinks_from_chain_to_owned() {
        // The keystone property, end to end: a chain of N notes with only a few OWNED, the cheap detector
        // yields a candidate set == owned — so the EXPENSIVE ML-KEM decap runs O(owned) times, not O(chain).
        let (pk_me, sk_me) = kp("chain-me");
        let (pk_other, _) = kp("chain-other");
        let n_chain = 800usize;
        let owned_idx: Vec<usize> = vec![17, 400, 733];
        let mut clues = Vec::with_capacity(n_chain);
        for i in 0..n_chain {
            let note_nonce = *blake3::hash(&(i as u32).to_le_bytes()).as_bytes();
            let pk = if owned_idx.contains(&i) {
                &pk_me
            } else {
                &pk_other
            };
            clues.push(make_clue(pk, &note_nonce));
        }
        let candidates: Vec<usize> = (0..n_chain)
            .filter(|&i| is_pertinent(&sk_me, &clues[i]))
            .collect();
        assert_eq!(
            candidates, owned_idx,
            "detector yields EXACTLY the owned notes (O(owned) decaps)"
        );
    }

    #[test]
    fn packed_clue_is_compact_on_chain() {
        // The packed clue is ~4·(N+γ) bytes — shared mask + γ-bit word, NOT γ separate ciphertexts. The
        // unpacked scheme was γ·4·(N+1) ≈ 12.4KB; packed is ~20× smaller — the compaction that lets it ride a note.
        assert_eq!(Clue::BYTES, 4 * (N + GAMMA));
        assert!(
            Clue::BYTES <= 800,
            "packed clue is {} B on chain (≤800)",
            Clue::BYTES
        );
        let unpacked = GAMMA * 4 * (N + 1);
        assert!(
            Clue::BYTES * 15 < unpacked,
            "packed ({}) is >15× smaller than unpacked ({})",
            Clue::BYTES,
            unpacked
        );
    }
}

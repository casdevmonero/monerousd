// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE NOTICE PROOF — "a company's own mail key signed a notice whose signed lines include exactly these"
//! (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §16: the doorstep; a carrier's delivery notice as the fact
//! neither side of a sale controls).
//!
//! A carrier signs every notification email with its mail key (DKIM, RFC 6376): an RSA signature over the SHA-256
//! hash of the email's signed header lines. A seller holding the carrier's "delivered" notice for a parcel proves,
//! to the buyer's wallet, that the carrier's key signed header lines that include the subject line naming that
//! parcel as delivered and the notice's date line. NOTHING ELSE OF THE EMAIL IS SHOWN: not the seller's mailbox, not
//! the message id, not another header, not the body.
//!
//! CLASSICAL-CRYPTO-EXEMPT: this file VERIFIES an outside company's own classical signature (RSA-2048 with SHA-256)
//! over that company's own data, at the external endpoint. The user's ruling of 2026-11-09 ("we dont control external
//! companies classical crypto") puts exactly this inside the post-quantum pillar's carve-out, beside the verify of a
//! foreign chain's signature. Nothing of ours is signed, keyed or secured by it: the proof system around it is the
//! chain's own (WHIR, Poseidon2), and a broken carrier key can do no more than let a seller lie about its own
//! deliveries to its own buyers.
//!
//! THE STATEMENT. Public: the signer's modulus `N` (the buyer's wallet takes it from the carrier's own published
//! mail key, never from the seller), how many 64-byte blocks were hashed, and the WINDOWS: runs of bytes at stated
//! places in the hashed data. Private: every other hashed byte, and the signature. The table has one row per hashed
//! block and, beside it on the same rows, one step of the signature check:
//!
//! ```text
//! row b, left:   one SHA-256 compression of block b, chained from row b-1 (the first from the standard start)
//!                the bytes a window names are the public ones; the hash after the last block is kept in a column
//! row i, right:  row 0:  nothing (zeros: see THE FIRST ROW below)
//!                row 1:  r = 1 · s  mod N          (loads the signature s, range-bound)
//!                2..17:  r = r_prev²  mod N
//!                row 18: r = r_prev · s  mod N      (= s^65537), and r is the PKCS#1 v1.5 padding of the kept hash
//! ```
//!
//! THE DOOR, AND THE FIRST ROW. Rows are chained (a row's hash state, the kept hash, a step's operand and the
//! signature are read from the row before), so the proof goes through the CHAINED door
//! (`committed_air::prove_air_blinded_chained_bytes`): the next-row values the gate reads are bound to the commitment
//! by the shift bind, never taken from the prover (through the plain blinded door a prover that lies only in those
//! values proves any notice: measured, and pinned). The door opens no row in the clear. The gate keeps its FIRST row
//! free of secrets in the chained cells all the same: the hash state there is the standard start, and the kept hash,
//! the operand and the signature cells are zero by law (the signature is loaded on row 1 and the kept hash rides from
//! row 1 on; the data is at least two blocks, so the hash is never taken on row 0).
//!
//! WHY NO PADDING RULE IS LAID. The hash chain runs over whatever blocks the prover lays. A carrier's signature
//! covers the hash of ITS data with the standard padding; any other block sequence reaching that same hash is a
//! collision. So the signature itself forces the blocks to be the carrier's padded data, and a window's bytes are
//! the carrier's bytes at that place.
//!
//! INTEGERS, NOT RESIDUES. A 32-bit word is two 16-bit limbs of bit cells, every sum is far below the field, and its
//! carry is bit cells. A 2048-bit number is 187 limbs with weight 2^11; one multiplication is `a·b = q·N + r` checked
//! coefficient by coefficient. A quotient's or a result's limb is seven base-three digits (below 3^7 = 2,187) and a
//! carry is twelve base-three digits and one bit (below 2·3^12, laid with an offset of 3^12): a digit's law
//! `t(t-1)(t-2)` is a cube like the hash's own laws, and a range costs 7 and 13 cells where bits cost 11 and 20.
//! With every limb below 2,187 and the modulus's below 2,048 each equation's value lies strictly inside
//! (-p, p) (the bound is a compile-time assert below), so an equation that holds in the field holds over the integers.
//! A limb above 2,047 is another way to write the same number; the last step's result is compared limb by limb with
//! the padded hash, whose limbs are below 2,048, so the number shown is exactly it.
//!
//! WHAT A PROOF COSTS, AND WHY IT IS THIS LITTLE. The 373 coefficient laws of a step are batched with consecutive
//! powers of the challenge `γ`, and `Σ γ^c · coefficient_c` of a product of two limb polynomials IS the product of
//! their two values at `γ`: the prover and the verifier evaluate `A(γ)·B(γ) - Q(γ)·N(γ) - R(γ) + (γ - 2^11)·C(γ)`,
//! about 1,100 products where the coefficient sums are 70,000 ([`NoticeGate::step_at_gamma`]; `residuals` still
//! lists every coefficient law for the censuses, and a pin holds the two equal on arbitrary rows). Weights of two and
//! three are doublings, never products. The declared degree is the MEASURED one (3; a next-row read is a rotated
//! column of degree one).
//!
//! WHAT THE BUYER'S WALLET DOES WITH THE WINDOWS is its own, outside this file: a window must be a whole header line
//! (it begins after a line end and ends with one), the subject must be the carrier's "delivered" wording with the
//! pinned tracking number, the date must be after the pin.
//!
//! WHAT IT SHOWS BEYOND THE WINDOWS, plainly: where each window sits in the hashed data and how many blocks there
//! are. Those are two lengths of the notice's signed headers.
//!
//! cons: none on the chain; no node ever sees a proof. Off the chain the table is 32 rows (64 for headers past 2 KB)
//! by [`NOTICE_WIDTH`] columns. Bytes and milliseconds are measured by `notice_tests::the_notice_proof_is_measured`.

use super::*;

/// Domain word of a notice proof's public bind ("NTCE").
pub const NOTICE_DOMAIN: u64 = 0x4E54_4345;
/// Bytes of one hashed block.
// PRODUCTION-SCALE-REVIEWED: SHA-256's own block size, not a limit.
pub const NOTICE_BLOCK_BYTES: usize = 64;
/// The most blocks one proof hashes (4 KB of signed header lines; a carrier's notice signs well under 2 KB).
// PRODUCTION-SCALE-REVIEWED: a bound on ONE off-chain statement's table (2^6 rows); a notice with longer signed
// headers has no proof and its sale is confirmed by the buyer, as any sale is.
pub const NOTICE_MAX_BLOCKS: usize = 64;
/// The algorithm tag a mail signature must state for this proof to cover it (RFC 6376 §3.3), in one place for every
/// caller that reads a notice.
pub const NOTICE_SIGNATURE_ALGORITHM: &str = "rsa-sha256"; // CLASSICAL-CRYPTO-EXEMPT: the name of the OUTSIDE COMPANY's own signature algorithm, read from its mail; verify only (user 2026-11-09)
/// Bytes of the modulus and of a signature: RSA-2048.
// PRODUCTION-SCALE-REVIEWED: the key size the carriers' mail keys use; a key of another size has no proof here.
pub const NOTICE_KEY_BYTES: usize = 256;

// ---- the hash's own constants (FIPS 180-4)
const SHA_IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
/// The DigestInfo prefix PKCS#1 v1.5 puts before a SHA-256 hash (RFC 8017 §9.2).
const DIGEST_INFO: [u8; 19] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

const WORD: usize = 32;
const HALF: usize = 16;
const ROUNDS: usize = 64;
/// Limb width of a 2048-bit number, and how many limbs hold one.
// PRODUCTION-SCALE-REVIEWED: the widest limb whose 187-term product sums stay below the 31-bit field (see the module doc).
const LIMB_BITS: usize = 11;
const LIMBS: usize = (8 * NOTICE_KEY_BYTES).div_ceil(LIMB_BITS);
/// Coefficients of a product of two numbers, and the carries between them.
const COEFFS: usize = 2 * LIMBS - 1;
const CARRIES: usize = COEFFS - 1;
/// Base-three digits of one limb of a quotient or a result: 3^7 covers an 11-bit limb.
// PRODUCTION-SCALE-REVIEWED: a digit count fixed by the limb's range, not a bound on anything laid.
const LIMB_TRITS: usize = 7;
/// What a limb of digits is below.
const LIMB_REACH: u64 = 3u64.pow(LIMB_TRITS as u32);
/// Cells of one carry: twelve base-three digits, then one bit above them.
// PRODUCTION-SCALE-REVIEWED: a carry's range (an honest one is below 2^18.6 either way), not a count.
const CARRY_TRITS: usize = 12;
const CARRY_CELLS: usize = CARRY_TRITS + 1;
/// The offset that makes a laid carry non-negative: a carry is its cells' value less this, so it is in
/// `[-3^12, 3^12)`.
const CARRY_OFFSET: u64 = 3u64.pow(CARRY_TRITS as u32);
/// The row that loads the signature. Not row 0: the first row holds nothing secret in the chained cells.
const LOAD_ROW: usize = 1;
/// The row that multiplies by the signature again: after the load and sixteen squarings.
const MUL_ROW: usize = LOAD_ROW + 17;
/// Bits of the hash, and the hash as limbs of the number it is: 23 whole limbs and its top three bits.
const HASH_BITS: usize = 8 * WORD;
const DIG_LIMBS: usize = HASH_BITS.div_ceil(LIMB_BITS);

// "Every equation holds over the integers", checked where the numbers are. One coefficient's equation is
// `Σ a·b - Σ q·n - r + carry_in - 2^11·carry_out = 0` in the field; with a, b, q, r below LIMB_REACH, n below 2^11
// and a carry in [-CARRY_OFFSET, CARRY_OFFSET), its value is above `-low` and below `high`, both inside the field's
// size, so a zero in the field is a zero. And an honest carry (every limb below 2^11) fits the range.
const _: () = {
    let (reach, two11, p) = (LIMB_REACH - 1, 1u64 << LIMB_BITS, 0x7f00_0001u64);
    let high = LIMBS as u64 * reach * reach + (CARRY_OFFSET - 1) + two11 * CARRY_OFFSET;
    let low = LIMBS as u64 * reach * (two11 - 1) + reach + CARRY_OFFSET + two11 * (CARRY_OFFSET - 1);
    assert!(high < p && low < p);
    let honest = (LIMBS as u64 * (two11 - 1) * (two11 - 1) + two11 + CARRY_OFFSET) / two11 + 1;
    assert!(honest < CARRY_OFFSET);
};

// ---- the row. Left: one compression.
/// `A[-3..=64]`: the working variable `a` before each round and after the last, each 32 bit cells, low bit first.
const SH_A: usize = 0;
/// `E[-3..=64]`.
const SH_E: usize = SH_A + (ROUNDS + 4) * WORD;
/// `W[0..64]`: the block's sixteen words, then the schedule.
const SH_W: usize = SH_E + (ROUNDS + 4) * WORD;
/// Carries of the 48 schedule sums: two bits for the low half, two for the high.
const SH_WC: usize = SH_W + ROUNDS * WORD;
/// Carries of each round's two sums: three bits each for `a` low, `a` high, `e` low, `e` high.
const SH_RC: usize = SH_WC + (ROUNDS - 16) * 4;
/// The hash state after this block: eight words of bit cells.
const SH_OUT: usize = SH_RC + ROUNDS * 12;
/// Carries of the eight closing sums: one bit low, one bit high.
const SH_OC: usize = SH_OUT + 8 * WORD;
/// The hash state before this block, as sixteen limbs (what the row before hands on).
const SH_CVIN: usize = SH_OC + 16;
/// The hash after the LAST block, as [`DIG_LIMBS`] limbs of the hash read as one number (limb 0 its low 11 bits).
const SH_DIG: usize = SH_CVIN + 16;
// Right: one step of the signature check. The first operand and the signature as limb cells; the quotient and the
// result as base-three digits, low digit first; the carries as digits and a bit.
const RS_A: usize = SH_DIG + DIG_LIMBS;
const RS_SIG: usize = RS_A + LIMBS;
const RS_Q: usize = RS_SIG + LIMBS;
const RS_R: usize = RS_Q + LIMBS * LIMB_TRITS;
const RS_C: usize = RS_R + LIMBS * LIMB_TRITS;
/// The row's width.
pub const NOTICE_WIDTH: usize = RS_C + CARRIES * CARRY_CELLS;

/// What a notice proof states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeStatement {
    /// The signer's modulus, big-endian, [`NOTICE_KEY_BYTES`] bytes.
    pub modulus: Vec<u8>,
    /// How many 64-byte blocks were hashed.
    pub blocks: usize,
    /// The windows: where each starts in the hashed data, and its bytes. In the order of their starts. Two may share
    /// bytes (two header lines one after the other share the line end between them) and must then agree on them.
    pub windows: Vec<(usize, Vec<u8>)>,
    /// What the proof answers: the sale it is for.
    pub context: Digest,
}

impl NoticeStatement {
    fn well_formed(&self) -> bool {
        // at least two blocks: the hash is kept from the row it is finished on, and that row is never the first
        // (the first row's chained cells hold nothing secret; a mail signature's own header alone is longer than one block)
        if self.modulus.len() != NOTICE_KEY_BYTES || !(2..=NOTICE_MAX_BLOCKS).contains(&self.blocks) {
            return false;
        }
        // one public byte per place: windows in the order of their starts, inside the data, agreeing where they meet
        let size = self.blocks * NOTICE_BLOCK_BYTES;
        let mut stated: Vec<Option<u8>> = vec![None; size];
        let mut from = 0usize;
        let windows = self.windows.iter().all(|(at, bytes)| {
            let placed = *at >= from && !bytes.is_empty() && at.checked_add(bytes.len()).is_some_and(|end| end <= size);
            from = *at;
            placed && bytes.iter().enumerate().all(|(i, b)| stated[at + i].replace(*b).is_none_or(|was| was == *b))
        });
        windows
            && self.modulus[0] & 0x80 != 0
            && self.modulus[NOTICE_KEY_BYTES - 1] & 1 == 1
            && self.context.iter().all(|v| *v < <Fa4 as p3_field::PrimeField64>::ORDER_U64)
    }

    /// The rows the table lays: enough for the blocks and for the signature steps (rows 1 to 18), a power of two.
    fn laid(&self) -> usize {
        self.blocks.max(MUL_ROW + 1).next_power_of_two()
    }
}

// ---- numbers as limbs (trace side and the gate's constants)

/// A big-endian number as [`LIMBS`] limbs of [`LIMB_BITS`] bits, low limb first.
fn limbs_of_be(bytes: &[u8]) -> [u64; LIMBS] {
    let bit = |i: usize| -> u64 { bytes.len().checked_sub(1 + i / 8).map_or(0, |at| u64::from((bytes[at] >> (i % 8)) & 1)) };
    core::array::from_fn(|k| (0..LIMB_BITS).fold(0u64, |v, b| v | (bit(k * LIMB_BITS + b) << b)))
}

/// Little-endian 32-bit words of a limb-coefficient list (each coefficient any size below 2^53), carried.
fn words_of_coeffs(coeffs: &[u64]) -> Vec<u32> {
    let mut out = vec![0u32; (coeffs.len() * LIMB_BITS).div_ceil(32) + 3];
    for (k, c) in coeffs.iter().enumerate() {
        let (word, shift) = (k * LIMB_BITS / 32, k * LIMB_BITS % 32);
        let mut carry = u128::from(*c) << shift;
        let mut at = word;
        while carry != 0 {
            let sum = u128::from(out[at]) + (carry & 0xFFFF_FFFF);
            out[at] = sum as u32;
            carry = (carry >> 32) + (sum >> 32);
            at += 1;
        }
    }
    out
}

fn limbs_of_words(words: &[u32], count: usize) -> Vec<u64> {
    let bit = |i: usize| -> u64 { words.get(i / 32).map_or(0, |w| u64::from((w >> (i % 32)) & 1)) };
    (0..count).map(|k| (0..LIMB_BITS).fold(0u64, |v, b| v | (bit(k * LIMB_BITS + b) << b))).collect()
}

fn words_ge(a: &[u32], b: &[u32]) -> bool {
    for i in (0..a.len().max(b.len())).rev() {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    true
}

/// `(a·b) div n` and `(a·b) mod n`, each as limbs: schoolbook product, then one bit of quotient at a time.
fn mul_divmod(a: &[u64; LIMBS], b: &[u64; LIMBS], n: &[u64; LIMBS]) -> ([u64; LIMBS], [u64; LIMBS]) {
    let mut coeffs = vec![0u64; COEFFS];
    for i in 0..LIMBS {
        for j in 0..LIMBS {
            coeffs[i + j] += a[i] * b[j];
        }
    }
    let product = words_of_coeffs(&coeffs);
    let n_words = words_of_coeffs(n);
    let bits = product.len() * 32;
    let mut rem = vec![0u32; n_words.len() + 1];
    let mut quot = vec![0u32; product.len()];
    for i in (0..bits).rev() {
        // rem = rem·2 + the next bit of the product
        let mut carry = (product[i / 32] >> (i % 32)) & 1;
        for w in rem.iter_mut() {
            let next = *w >> 31;
            *w = (*w << 1) | carry;
            carry = next;
        }
        if words_ge(&rem, &n_words) {
            let mut borrow = 0i64;
            for (k, w) in rem.iter_mut().enumerate() {
                let d = i64::from(*w) - i64::from(n_words.get(k).copied().unwrap_or(0)) - borrow;
                *w = d.rem_euclid(1 << 32) as u32;
                borrow = i64::from(d < 0);
            }
            quot[i / 32] |= 1 << (i % 32);
        }
    }
    let to = |words: &[u32]| -> [u64; LIMBS] {
        let v = limbs_of_words(words, LIMBS);
        core::array::from_fn(|k| v[k])
    };
    (to(&quot), to(&rem))
}

/// The number PKCS#1 v1.5 pads a SHA-256 hash to, for a [`NOTICE_KEY_BYTES`]-byte key, big-endian.
fn padded_hash(hash: &[u8; 32]) -> Vec<u8> {
    let mut em = vec![0xFFu8; NOTICE_KEY_BYTES];
    em[0] = 0;
    em[1] = 1;
    let t = NOTICE_KEY_BYTES - 32 - DIGEST_INFO.len();
    em[t - 1] = 0;
    em[t..t + DIGEST_INFO.len()].copy_from_slice(&DIGEST_INFO);
    em[NOTICE_KEY_BYTES - 32..].copy_from_slice(hash);
    em
}

// ---- the hash, natively: every value the row lays

struct Compression {
    a: Vec<u32>,
    e: Vec<u32>,
    w: [u32; ROUNDS],
    out: [u32; 8],
}

fn compress(cv: &[u32; 8], block: &[u8]) -> Compression {
    let mut w = [0u32; ROUNDS];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([block[4 * t], block[4 * t + 1], block[4 * t + 2], block[4 * t + 3]]);
    }
    for t in 16..ROUNDS {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
    }
    // a[i] is A[i - 3]: a[3] = a, a[2] = b, a[1] = c, a[0] = d before round 0
    let mut a = vec![cv[3], cv[2], cv[1], cv[0]];
    let mut e = vec![cv[7], cv[6], cv[5], cv[4]];
    for t in 0..ROUNDS {
        let (av, bv, cvv, dv) = (a[t + 3], a[t + 2], a[t + 1], a[t]);
        let (ev, fv, gv, hv) = (e[t + 3], e[t + 2], e[t + 1], e[t]);
        let s1 = ev.rotate_right(6) ^ ev.rotate_right(11) ^ ev.rotate_right(25);
        let ch = (ev & fv) ^ (!ev & gv);
        let t1 = hv.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA_K[t]).wrapping_add(w[t]);
        let s0 = av.rotate_right(2) ^ av.rotate_right(13) ^ av.rotate_right(22);
        let maj = (av & bv) ^ (av & cvv) ^ (bv & cvv);
        a.push(t1.wrapping_add(s0).wrapping_add(maj));
        e.push(dv.wrapping_add(t1));
    }
    let fin = [a[67], a[66], a[65], a[64], e[67], e[66], e[65], e[64]];
    Compression { a, e, w, out: core::array::from_fn(|j| cv[j].wrapping_add(fin[j])) }
}

/// SHA-256 of `data` with the standard padding, and the padded data: what a prover lays.
#[must_use]
pub fn notice_padded(data: &[u8]) -> Vec<u8> {
    let mut m = data.to_vec();
    m.push(0x80);
    while m.len() % NOTICE_BLOCK_BYTES != NOTICE_BLOCK_BYTES - 8 {
        m.push(0);
    }
    m.extend_from_slice(&(8 * data.len() as u64).to_be_bytes());
    m
}

/// The hash of already-padded data (a whole number of blocks).
#[must_use]
pub fn notice_hash_of_padded(padded: &[u8]) -> Option<[u8; 32]> {
    if padded.is_empty() || padded.len() % NOTICE_BLOCK_BYTES != 0 {
        return None;
    }
    let mut cv = SHA_IV;
    for block in padded.chunks_exact(NOTICE_BLOCK_BYTES) {
        cv = compress(&cv, block).out;
    }
    let mut out = [0u8; 32];
    for (j, word) in cv.iter().enumerate() {
        out[4 * j..4 * j + 4].copy_from_slice(&word.to_be_bytes());
    }
    Some(out)
}

/// Does `signature` verify for already-padded `padded` under `modulus` (exponent 65537), natively? What the proof
/// shows in zero knowledge, and what a prover checks before it lays a table.
#[must_use]
pub fn notice_signature_ok(modulus: &[u8], padded: &[u8], signature: &[u8]) -> bool {
    let Some(hash) = notice_hash_of_padded(padded) else { return false };
    if modulus.len() != NOTICE_KEY_BYTES || signature.len() != NOTICE_KEY_BYTES {
        return false;
    }
    let (n, s) = (limbs_of_be(modulus), limbs_of_be(signature));
    let mut one = [0u64; LIMBS];
    one[0] = 1;
    let mut r = mul_divmod(&one, &s, &n).1;
    for _ in 0..16 {
        r = mul_divmod(&r, &r, &n).1;
    }
    mul_divmod(&r, &s, &n).1 == limbs_of_be(&padded_hash(&hash))
}

// ---- the gate

#[derive(Clone)]
struct NoticeGate {
    gpow: Vec<Ea4>,
    data_vars: usize,
    blocks: usize,
    modulus: [Fa4; LIMBS],
    /// Per laid row and block byte: is the byte a window's, and its value when it is (zero when not).
    mask: Vec<[Fa4; NOTICE_BLOCK_BYTES]>,
    value: Vec<[Fa4; NOTICE_BLOCK_BYTES]>,
    /// The limbs of the padded hash with the hash itself zeroed: constants of the last step.
    pad: [Fa4; LIMBS],
    /// The modulus's limb polynomial at `γ`: `Σ γ^j · n_j`.
    modulus_at_gamma: Ea4,
}

/// How many laws the row has before a step's coefficient laws: [`NoticeGate::lay`] pushes exactly these.
fn laid_law_count() -> usize {
    let cells = (2 * (ROUNDS + 4) + ROUNDS + 8) * WORD + (ROUNDS - 16) * 4 + ROUNDS * 12 + 16 + 2 * LIMBS * LIMB_TRITS + CARRIES * CARRY_CELLS;
    let sums = (ROUNDS - 16) * 2 + ROUNDS * 4 + 8 * 2;
    let chain = 16 * 3 + DIG_LIMBS * 3 + NOTICE_BLOCK_BYTES;
    let step = 6 * LIMBS + LIMBS;
    cells + sums + chain + step
}

/// How many laws the row has: those, then the [`COEFFS`] coefficient laws of the step, last.
fn law_count() -> usize {
    laid_law_count() + COEFFS
}

/// What a step's coefficient laws read, in the row's own field.
struct Step<F> {
    a: Vec<F>,
    sig: Vec<F>,
    q: Vec<F>,
    r: Vec<F>,
    carry: Vec<F>,
    /// One on the two rows whose second operand is the signature, zero on a squaring row.
    by_sig: F,
}

impl NoticeGate {
    fn of(st: &NoticeStatement, gamma: Ea4) -> Self {
        let f = Fa4::from_u64;
        let laid = st.laid();
        let (mut mask, mut value) = (vec![[Fa4::ZERO; NOTICE_BLOCK_BYTES]; laid], vec![[Fa4::ZERO; NOTICE_BLOCK_BYTES]; laid]);
        for (at, bytes) in &st.windows {
            for (i, b) in bytes.iter().enumerate() {
                let (row, k) = ((at + i) / NOTICE_BLOCK_BYTES, (at + i) % NOTICE_BLOCK_BYTES);
                if row < laid {
                    mask[row][k] = Fa4::ONE;
                    value[row][k] = f(u64::from(*b));
                }
            }
        }
        let n = limbs_of_be(&st.modulus);
        let pad = limbs_of_be(&padded_hash(&[0u8; 32]));
        let mut gpow = Vec::with_capacity(law_count());
        let mut gp = Ea4::ONE;
        for _ in 0..law_count() {
            gpow.push(gp);
            gp *= gamma;
        }
        let modulus: [Fa4; LIMBS] = core::array::from_fn(|k| f(n[k]));
        let modulus_at_gamma = modulus.iter().zip(&gpow).fold(Ea4::ZERO, |acc, (limb, g)| acc + *g * *limb);
        NoticeGate { gpow, data_vars: laid.trailing_zeros() as usize, blocks: st.blocks, modulus, mask, value, pad: core::array::from_fn(|k| f(pad[k])), modulus_at_gamma }
    }

    /// Every law of the row but a step's coefficient laws, unbatched, in the row's own field, and what those
    /// coefficient laws read. `x[0]` is the blinding half's variable; the rest index the laid rows, high bit first.
    /// `next(c)` is column `c` on the row after. `None` for a point of another shape.
    #[allow(clippy::too_many_lines)]
    fn lay<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, local: &crate::air_zerocheck::Row<'_, F>, next: &dyn Fn(usize) -> F, x: &[F]) -> Option<(Vec<F>, Step<F>)> {
        if x.len() != self.data_vars + 1 || self.mask.len() != (1usize << self.data_vars) {
            return None;
        }
        let k = |v: u64| -> F { F::from(Fa4::from_u64(v)) };
        let one = F::ONE;
        // the row's public values at this point: which row it is, and its window bytes
        let (shift, low, w) = super::content_gate::row_weights(&x[1..]);
        let at_row = |row: usize| -> F { if row & ((1 << shift) - 1) == low { w.get(row >> shift).copied().unwrap_or(F::ZERO) } else { F::ZERO } };
        let rows = self.mask.len();
        let (is_first, is_load, is_mul, sha_last, not_last) = (at_row(0), at_row(LOAD_ROW), at_row(MUL_ROW), at_row(self.blocks - 1), one - at_row(rows - 1));
        // the kept hash, a step's operand and the signature ride from row 1 on: the first row's cells of them are zero
        let rides = not_last - is_first;
        let (mut mask, mut value) = ([F::ZERO; NOTICE_BLOCK_BYTES], [F::ZERO; NOTICE_BLOCK_BYTES]);
        for (h, wh) in w.iter().enumerate() {
            let row = (h << shift) | low;
            for b in 0..NOTICE_BLOCK_BYTES {
                mask[b] += *wh * F::from(self.mask[row][b]);
                value[b] += *wh * F::from(self.value[row][b]);
            }
        }

        let mut rs: Vec<F> = Vec::with_capacity(laid_law_count());
        // 1. every cell of a range is in it: a bit, or a base-three digit
        let two = k(2);
        for c in SH_A..SH_CVIN {
            let b = local[c];
            rs.push(b * (b - one));
        }
        for c in RS_Q..RS_C {
            let t = local[c];
            rs.push(t * (t - one) * (t - two));
        }
        for c in 0..CARRIES {
            let base = RS_C + c * CARRY_CELLS;
            for j in 0..CARRY_TRITS {
                let t = local[base + j];
                rs.push(t * (t - one) * (t - two));
            }
            let b = local[base + CARRY_TRITS];
            rs.push(b * (b - one));
        }
        let bit = |base: usize, i: usize| local[base + i];
        // a run of bit cells as the number it is, low cell first: weights of two are doublings, the high cell first
        let run = |base: usize, cells: usize| (0..cells).rev().fold(F::ZERO, |s, b| s.double() + local[base + b]);
        let half = |base: usize, h: usize| run(base + h * HALF, HALF);
        let xor2 = |p: F, q: F| p + q - (p * q).double();
        let xor3 = |p: F, q: F, r: F| xor2(xor2(p, q), r);
        let two16 = k(1 << HALF);
        let (word_a, word_e, word_w) = (|t: isize| SH_A + (t + 3) as usize * WORD, |t: isize| SH_E + (t + 3) as usize * WORD, |t: usize| SH_W + t * WORD);

        // 2. the schedule: W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
        for t in 16..ROUNDS {
            let (w15, w2) = (word_w(t - 15), word_w(t - 2));
            let mut carry = F::ZERO;
            for h in 0..2 {
                let mut sigmas = F::ZERO;
                for b in (0..HALF).rev() {
                    let i = h * HALF + b;
                    let s0 = if i + 3 < WORD { xor3(bit(w15, (i + 7) % WORD), bit(w15, (i + 18) % WORD), bit(w15, i + 3)) } else { xor2(bit(w15, (i + 7) % WORD), bit(w15, (i + 18) % WORD)) };
                    let s1 = if i + 10 < WORD { xor3(bit(w2, (i + 17) % WORD), bit(w2, (i + 19) % WORD), bit(w2, i + 10)) } else { xor2(bit(w2, (i + 17) % WORD), bit(w2, (i + 19) % WORD)) };
                    sigmas = sigmas.double() + s0 + s1;
                }
                let out = run(SH_WC + (t - 16) * 4 + h * 2, 2);
                rs.push(half(word_w(t - 16), h) + half(word_w(t - 7), h) + sigmas + carry - half(word_w(t), h) - two16 * out);
                carry = out;
            }
        }
        // 3. the rounds
        for t in 0..ROUNDS {
            let ti = t as isize;
            let (a, b, c, d) = (word_a(ti), word_a(ti - 1), word_a(ti - 2), word_a(ti - 3));
            let (e, f, g, hh) = (word_e(ti), word_e(ti - 1), word_e(ti - 2), word_e(ti - 3));
            let (mut carry_a, mut carry_e) = (F::ZERO, F::ZERO);
            for h in 0..2 {
                let (mut t1, mut t2) = (F::ZERO, F::ZERO);
                for bb in (0..HALF).rev() {
                    let i = h * HALF + bb;
                    let s1 = xor3(bit(e, (i + 6) % WORD), bit(e, (i + 11) % WORD), bit(e, (i + 25) % WORD));
                    let ch = bit(e, i) * (bit(f, i) - bit(g, i)) + bit(g, i);
                    let s0 = xor3(bit(a, (i + 2) % WORD), bit(a, (i + 13) % WORD), bit(a, (i + 22) % WORD));
                    let (ai, bi, ci) = (bit(a, i), bit(b, i), bit(c, i));
                    let ab = ai * bi;
                    let maj = ab + ci * (ai + bi - ab.double());
                    t1 = t1.double() + s1 + ch;
                    t2 = t2.double() + s0 + maj;
                }
                let t1 = t1 + half(hh, h) + half(word_w(t), h) + k(u64::from(SHA_K[t] >> (h * HALF)) & 0xFFFF);
                let base = SH_RC + t * 12 + h * 3;
                let (out_a, out_e) = (run(base, 3), run(base + 6, 3));
                rs.push(t1 + t2 + carry_a - half(word_a(ti + 1), h) - two16 * out_a);
                rs.push(half(d, h) + t1 + carry_e - half(word_e(ti + 1), h) - two16 * out_e);
                (carry_a, carry_e) = (out_a, out_e);
            }
        }
        // 4. the state after the block, and its chain to the next row and to the kept hash
        let cv_in = [word_a(0), word_a(-1), word_a(-2), word_a(-3), word_e(0), word_e(-1), word_e(-2), word_e(-3)];
        let fin = [word_a(64), word_a(63), word_a(62), word_a(61), word_e(64), word_e(63), word_e(62), word_e(61)];
        for j in 0..8 {
            let mut carry = F::ZERO;
            for h in 0..2 {
                let out = local[SH_OC + j * 2 + h];
                rs.push(half(cv_in[j], h) + half(fin[j], h) + carry - half(SH_OUT + j * WORD, h) - two16 * out);
                carry = out;
            }
        }
        for j in 0..8 {
            for h in 0..2 {
                let limb = local[SH_CVIN + j * 2 + h];
                rs.push(limb - half(cv_in[j], h));
                rs.push(is_first * (limb - k(u64::from(SHA_IV[j] >> (h * HALF)) & 0xFFFF)));
                rs.push(not_last * (next(SH_CVIN + j * 2 + h) - half(SH_OUT + j * WORD, h)));
            }
        }
        // bit `i` of the hash read as one number: word 7 is its low word
        let out_bit = |i: usize| local[SH_OUT + (7 - i / WORD) * WORD + i % WORD];
        for m in 0..DIG_LIMBS {
            let dig = local[SH_DIG + m];
            let from_out = (0..LIMB_BITS).rev().filter(|j| m * LIMB_BITS + j < HASH_BITS).fold(F::ZERO, |s, j| s.double() + out_bit(m * LIMB_BITS + j));
            rs.push(is_first * dig);
            rs.push(rides * (next(SH_DIG + m) - dig));
            rs.push(sha_last * (dig - from_out));
        }
        // 5. the windows: a byte a window names is the public one
        for b in 0..NOTICE_BLOCK_BYTES {
            let byte = run(word_w(b / 4) + 8 * (3 - b % 4), 8);
            rs.push(mask[b] * byte - value[b]);
        }

        // 6. one step of the signature check: what `a·b = q·N + r` reads, and the welds around it
        // a run of base-three digits as the number it is: weights of three are a doubling and an addition
        let digits = |base: usize, cells: usize| (0..cells).rev().fold(F::ZERO, |s, j| s.double() + s + local[base + j]);
        let a: Vec<F> = (0..LIMBS).map(|i| local[RS_A + i]).collect();
        let sig: Vec<F> = (0..LIMBS).map(|i| local[RS_SIG + i]).collect();
        let q: Vec<F> = (0..LIMBS).map(|i| digits(RS_Q + i * LIMB_TRITS, LIMB_TRITS)).collect();
        let r: Vec<F> = (0..LIMBS).map(|i| digits(RS_R + i * LIMB_TRITS, LIMB_TRITS)).collect();
        // a carry is its digits, its bit at the digits' top weight, less the offset (the same number as that weight)
        let offset = k(CARRY_OFFSET);
        let carry: Vec<F> = (0..CARRIES)
            .map(|c| {
                let base = RS_C + c * CARRY_CELLS;
                digits(base, CARRY_TRITS) + (local[base + CARRY_TRITS] - one) * offset
            })
            .collect();
        for i in 0..LIMBS {
            // the first row holds no operand and no signature: its chained cells are public zeros
            rs.push(is_first * a[i]);
            rs.push(is_first * sig[i]);
            // the load row's first operand is 1 and its result IS the signature (so the signature is range-bound)
            rs.push(is_load * (a[i] - if i == 0 { one } else { F::ZERO }));
            rs.push(is_load * (sig[i] - r[i]));
            // from the load row on, each row's result is the next row's first operand and the signature rides
            rs.push(rides * (next(RS_A + i) - r[i]));
            rs.push(rides * (next(RS_SIG + i) - sig[i]));
        }
        // the last step's result is the padded hash, limb by limb: the kept hash below, the fixed padding above
        for i in 0..LIMBS {
            let kept = if i < DIG_LIMBS { local[SH_DIG + i] } else { F::ZERO };
            rs.push(is_mul * (r[i] - kept - F::from(self.pad[i])));
        }
        // the second operand is the signature on the load row and on the last step, else the first operand again
        Some((rs, Step { a, sig, q, r, carry, by_sig: is_load + is_mul }))
    }

    /// A step's coefficient laws, one by one: `Σ a·b - Σ q·n - r + carry_in - 2^11·carry_out` for each coefficient
    /// of the product. What the censuses and the tamper pins read; the prover and the verifier batch them with
    /// [`Self::step_at_gamma`].
    fn coefficient_laws<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, s: &Step<F>) -> Vec<F> {
        let b: Vec<F> = (0..LIMBS).map(|j| s.a[j] + s.by_sig * (s.sig[j] - s.a[j])).collect();
        let n: Vec<F> = self.modulus.iter().map(|v| F::from(*v)).collect();
        let base = F::from(Fa4::from_u64(1 << LIMB_BITS));
        (0..COEFFS)
            .map(|c| {
                let (lo, hi) = (c.saturating_sub(LIMBS - 1), c.min(LIMBS - 1));
                let mut sum = F::ZERO;
                for i in lo..=hi {
                    sum += s.a[i] * b[c - i] - s.q[i] * n[c - i];
                }
                if c < LIMBS {
                    sum -= s.r[c];
                }
                if c > 0 {
                    sum += s.carry[c - 1];
                }
                if c < CARRIES {
                    sum -= base * s.carry[c];
                }
                sum
            })
            .collect()
    }

    /// `Σ_c γ^c · coefficient_law_c`, without forming one coefficient: a product of two limb polynomials, batched
    /// with consecutive powers of `γ`, is the product of their values at `γ`. So the whole step is
    /// `A(γ)·B(γ) - Q(γ)·N(γ) - R(γ) + (γ - 2^11)·C(γ)`, with `B = A + by_sig·(S - A)`.
    fn step_at_gamma<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, s: &Step<F>) -> Ea4
    where
        Ea4: core::ops::Mul<F, Output = Ea4>,
    {
        let at_gamma = |limbs: &[F]| limbs.iter().zip(&self.gpow).fold(Ea4::ZERO, |acc, (limb, g)| acc + *g * *limb);
        let (a, sig, q, r, c) = (at_gamma(&s.a), at_gamma(&s.sig), at_gamma(&s.q), at_gamma(&s.r), at_gamma(&s.carry));
        let b = a + (sig - a) * s.by_sig;
        ext_mul(a, b) - ext_mul(q, self.modulus_at_gamma) - r + ext_mul(self.gpow[1] - Ea4::from(Fa4::from_u64(1 << LIMB_BITS)), c)
    }

    /// Every law of the row, unbatched: the laid laws, then the step's coefficient laws.
    fn laws<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, local: &crate::air_zerocheck::Row<'_, F>, next: &dyn Fn(usize) -> F, x: &[F]) -> Vec<F> {
        let Some((mut rs, step)) = self.lay(local, next, x) else { return vec![F::ONE] };
        rs.extend(self.coefficient_laws(&step));
        rs
    }

    /// `Σ γ^k · law_k` over every law of the row, in the order [`Self::laws`] lists them.
    fn batched<F: p3_field::Field + p3_field::Algebra<Fa4>>(&self, local: &crate::air_zerocheck::Row<'_, F>, next: &dyn Fn(usize) -> F, x: &[F]) -> Ea4
    where
        Ea4: core::ops::Mul<F, Output = Ea4>,
    {
        let Some((rs, step)) = self.lay(local, next, x) else { return Ea4::ONE };
        if rs.len() != laid_law_count() || self.gpow.len() != law_count() {
            return Ea4::ONE;
        }
        let laid = rs.into_iter().zip(&self.gpow).fold(Ea4::ZERO, |acc, (r, g)| acc + *g * r);
        laid + ext_mul(self.gpow[laid_law_count()], self.step_at_gamma(&step))
    }
}

/// A product of two extension values, outside a generic context (inside one, the `Ea4 × F` bound the batching needs
/// is the only product the compiler will pick).
fn ext_mul(a: Ea4, b: Ea4) -> Ea4 {
    a * b
}

/// The columns the gate reads on the next row: the chained hash state, the kept hash, the step's first operand and
/// the signature.
fn shifted() -> Vec<usize> {
    (SH_CVIN..RS_Q).collect()
}

/// The gate's degree, MEASURED by the degree census: every law is at most a cube in the cells (a three-way
/// exclusive-or, a majority, a base-three digit) or a square times a row's weight. A next-row read is a rotated
/// column, degree one like any cell.
const NOTICE_DEGREE: usize = 3;

impl crate::air_zerocheck::AirConstraint for NoticeGate {
    fn degree(&self, _nvars: usize) -> usize {
        NOTICE_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        self.batched::<Ea4>(local, &|c| at(c, &sigma), x)
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        self.laws::<Ea4>(local, &|c| at(c, &sigma), x)
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        self.batched::<Fa4>(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        false
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some(shifted())
    }
    /// Every cell is a bit or a digit, a limb welded to them, or a number welded to the row before; no column is free.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

fn notice_bind(st: &NoticeStatement) -> Vec<Fa4> {
    let f = Fa4::from_u64;
    let mut b = vec![f(NOTICE_DOMAIN), f(st.blocks as u64), f(st.windows.len() as u64)];
    b.extend(st.context.iter().map(|v| f(*v)));
    b.extend(limbs_of_be(&st.modulus).iter().map(|v| f(*v)));
    for (at, bytes) in &st.windows {
        b.push(f(*at as u64));
        b.push(f(bytes.len() as u64));
        b.extend(bytes.iter().map(|v| f(u64::from(*v))));
    }
    b
}

/// The table for `st`: the blocks of `padded` (then blocks of zeros, hashed on), and the signature check of
/// `signature`. Laid exactly as given: the gate decides whether it is true.
fn notice_cols(st: &NoticeStatement, padded: &[u8], signature: &[u8]) -> Vec<Vec<Fa4>> {
    let laid = st.laid();
    let f = Fa4::from_u64;
    let mut table: Vec<Vec<Fa4>> = Vec::with_capacity(laid);
    let (n, s) = (limbs_of_be(&st.modulus), limbs_of_be(signature));
    // the hash chain over every laid row, and the kept hash: the state after block `blocks - 1`
    let mut cv = SHA_IV;
    let mut comps = Vec::with_capacity(laid);
    for row in 0..laid {
        let mut block = [0u8; NOTICE_BLOCK_BYTES];
        if let Some(bytes) = padded.get(row * NOTICE_BLOCK_BYTES..(row + 1) * NOTICE_BLOCK_BYTES) {
            block.copy_from_slice(bytes);
        }
        let c = compress(&cv, &block);
        comps.push((cv, c.out));
        cv = c.out;
        table.push(vec![Fa4::ZERO; NOTICE_WIDTH]);
        let row_cells = &mut table[row];
        let put_word = |cells: &mut Vec<Fa4>, base: usize, v: u32| {
            for i in 0..WORD {
                cells[base + i] = f(u64::from((v >> i) & 1));
            }
        };
        for (i, v) in c.a.iter().enumerate() {
            put_word(row_cells, SH_A + i * WORD, *v);
        }
        for (i, v) in c.e.iter().enumerate() {
            put_word(row_cells, SH_E + i * WORD, *v);
        }
        for (t, v) in c.w.iter().enumerate() {
            put_word(row_cells, SH_W + t * WORD, *v);
        }
        let lo = |v: u32| u64::from(v & 0xFFFF);
        let hi = |v: u32| u64::from(v >> 16);
        let put_small = |cells: &mut Vec<Fa4>, base: usize, bits: usize, v: u64| {
            for i in 0..bits {
                cells[base + i] = f((v >> i) & 1);
            }
        };
        for t in 16..ROUNDS {
            let s0 = c.w[t - 15].rotate_right(7) ^ c.w[t - 15].rotate_right(18) ^ (c.w[t - 15] >> 3);
            let s1 = c.w[t - 2].rotate_right(17) ^ c.w[t - 2].rotate_right(19) ^ (c.w[t - 2] >> 10);
            let c0 = (lo(c.w[t - 16]) + lo(c.w[t - 7]) + lo(s0) + lo(s1)) >> 16;
            let c1 = (hi(c.w[t - 16]) + hi(c.w[t - 7]) + hi(s0) + hi(s1) + c0) >> 16;
            put_small(row_cells, SH_WC + (t - 16) * 4, 2, c0);
            put_small(row_cells, SH_WC + (t - 16) * 4 + 2, 2, c1);
        }
        for t in 0..ROUNDS {
            let (av, bv, cvv, dv) = (c.a[t + 3], c.a[t + 2], c.a[t + 1], c.a[t]);
            let (ev, fv, gv, hv) = (c.e[t + 3], c.e[t + 2], c.e[t + 1], c.e[t]);
            let s1 = ev.rotate_right(6) ^ ev.rotate_right(11) ^ ev.rotate_right(25);
            let ch = (ev & fv) ^ (!ev & gv);
            let s0 = av.rotate_right(2) ^ av.rotate_right(13) ^ av.rotate_right(22);
            let maj = (av & bv) ^ (av & cvv) ^ (bv & cvv);
            let t1_lo = lo(hv) + lo(s1) + lo(ch) + lo(SHA_K[t]) + lo(c.w[t]);
            let t1_hi = hi(hv) + hi(s1) + hi(ch) + hi(SHA_K[t]) + hi(c.w[t]);
            let a0 = (t1_lo + lo(s0) + lo(maj)) >> 16;
            let a1 = (t1_hi + hi(s0) + hi(maj) + a0) >> 16;
            let e0 = (lo(dv) + t1_lo) >> 16;
            let e1 = (hi(dv) + t1_hi + e0) >> 16;
            let base = SH_RC + t * 12;
            put_small(row_cells, base, 3, a0);
            put_small(row_cells, base + 3, 3, a1);
            put_small(row_cells, base + 6, 3, e0);
            put_small(row_cells, base + 9, 3, e1);
        }
        let (cv_in, out) = comps[row];
        let fin = [c.a[67], c.a[66], c.a[65], c.a[64], c.e[67], c.e[66], c.e[65], c.e[64]];
        for j in 0..8 {
            put_word(row_cells, SH_OUT + j * WORD, out[j]);
            let c0 = (lo(cv_in[j]) + lo(fin[j])) >> 16;
            let c1 = (hi(cv_in[j]) + hi(fin[j]) + c0) >> 16;
            row_cells[SH_OC + j * 2] = f(c0);
            row_cells[SH_OC + j * 2 + 1] = f(c1);
            row_cells[SH_CVIN + j * 2] = f(lo(cv_in[j]));
            row_cells[SH_CVIN + j * 2 + 1] = f(hi(cv_in[j]));
        }
    }
    // the kept hash, the same on every row: the state after the last hashed block, as limbs of one number
    let kept = comps[st.blocks.min(laid) - 1].1;
    // the signature check: nothing on the first row, the load on the next, then the squarings and the last product
    let mut a = [0u64; LIMBS];
    let kept_bit = |i: usize| -> u64 { u64::from((kept[7 - i / WORD] >> (i % WORD)) & 1) };
    let kept_limbs: [u64; DIG_LIMBS] = core::array::from_fn(|m| (0..LIMB_BITS).filter(|j| m * LIMB_BITS + j < HASH_BITS).fold(0u64, |v, j| v | (kept_bit(m * LIMB_BITS + j) << j)));
    // a number as base-three digits, low digit first
    let put_digits = |cells: &mut Vec<Fa4>, base: usize, count: usize, mut v: u64| {
        for j in 0..count {
            cells[base + j] = f(v % 3);
            v /= 3;
        }
    };
    for (row, cells) in table.iter_mut().enumerate() {
        if row == LOAD_ROW {
            a[0] = 1;
        }
        // the first row's chained cells are zeros: the kept hash and the signature are laid from the load row on
        let (dig, sig_here) = if row == 0 { ([0u64; DIG_LIMBS], [0u64; LIMBS]) } else { (kept_limbs, s) };
        for (m, limb) in dig.iter().enumerate() {
            cells[SH_DIG + m] = f(*limb);
        }
        let b = if row == LOAD_ROW || row == MUL_ROW { s } else { a };
        let (q, r) = mul_divmod(&a, &b, &n);
        for i in 0..LIMBS {
            cells[RS_A + i] = f(a[i]);
            cells[RS_SIG + i] = f(sig_here[i]);
            put_digits(cells, RS_Q + i * LIMB_TRITS, LIMB_TRITS, q[i]);
            put_digits(cells, RS_R + i * LIMB_TRITS, LIMB_TRITS, r[i]);
        }
        // the carries of a·b - q·N - r, coefficient by coefficient (signed, laid with an offset)
        let mut carry: i64 = 0;
        for c in 0..CARRIES {
            let (lo, hi) = (c.saturating_sub(LIMBS - 1), c.min(LIMBS - 1));
            let mut sum: i64 = carry;
            for i in lo..=hi {
                sum += (a[i] * b[c - i]) as i64 - (q[i] * n[c - i]) as i64;
            }
            if c < LIMBS {
                sum -= r[c] as i64;
            }
            carry = sum >> LIMB_BITS;
            let laid_carry = (carry + CARRY_OFFSET as i64).clamp(0, 2 * CARRY_OFFSET as i64 - 1) as u64;
            put_digits(cells, RS_C + c * CARRY_CELLS, CARRY_TRITS, laid_carry % CARRY_OFFSET);
            cells[RS_C + c * CARRY_CELLS + CARRY_TRITS] = f(laid_carry / CARRY_OFFSET);
        }
        a = r;
    }
    (0..NOTICE_WIDTH).map(|c| table.iter().map(|row| row[c]).collect()).collect()
}

/// PROVE: the holder of a notice shows `st` to the buyer. `padded` is the hashed data with its padding (the signed
/// header lines as the signer hashed them; [`notice_padded`]) and `signature` the signer's signature. `None` when
/// the signature does not verify under the statement's modulus, when a window's bytes are not the data's at that
/// place, or when the statement is not one this class proves (never a proof of a false statement).
#[must_use]
pub fn prove_notice(st: &NoticeStatement, padded: &[u8], signature: &[u8]) -> Option<Vec<u8>> {
    if !st.well_formed() || padded.len() != st.blocks * NOTICE_BLOCK_BYTES || signature.len() != NOTICE_KEY_BYTES {
        return None;
    }
    if st.windows.iter().any(|(at, bytes)| padded.get(*at..at + bytes.len()) != Some(&bytes[..])) {
        return None;
    }
    if !notice_signature_ok(&st.modulus, padded, signature) {
        return None;
    }
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_chained_bytes(notice_cols(st, padded, signature), move |g: Ea4| NoticeGate::of(&st2, g), &notice_bind(st))
}

/// VERIFY a notice proof against the statement the buyer's wallet itself wrote down: the modulus it took from the
/// carrier's published mail key, and the windows it then reads. True means: the holder of that key signed data of
/// that many blocks whose bytes at each window's place are that window's bytes.
#[must_use]
pub fn verify_notice(bytes: &[u8], st: &NoticeStatement) -> bool {
    if bytes.is_empty() || !st.well_formed() {
        return false;
    }
    let st2 = st.clone();
    crate::committed_air::verify_air_blinded_chained_bytes(bytes, move |g: Ea4| NoticeGate::of(&st2, g), &notice_bind(st), (st.laid().trailing_zeros() as usize, NOTICE_WIDTH))
}

#[cfg(test)]
mod notice_tests;

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ D4 — THE PROOF-BOUND STORAGE BLOB (docs/DSOL-NODE-DOOR-SPEC.md §8 A4, §10 D4, §11 H1; docs/VEIL-SOVEREIGN-
//! INTERNET-SPEC-20261107.md §12, user 2026-11-13: "we need private backends now").
//!
//! THE HOLE THIS CLOSES. The chain holds a contract's storage ROOTS (`storage_pre → storage_post`), never its values. If
//! nothing carries the values a call wrote, the next caller cannot prove a call, and ONE hostile caller freezes a contract
//! forever by withholding them, or by posting a garbage blob beside an honest `storage_post`. A back end that a stranger
//! can brick is not a back end anyone can trust their users' data to.
//!
//! THE STATEMENT, proven beside every call (its own table; the contract machine's circuit is untouched):
//!
//!   there is a key `k_c` with `P(KC_DOMAIN ‖ k_c) = kc_commit` (the DEPLOY fixed it), and `W` entries, each either a WRITE
//!   `(key, value)` or a PAD, such that applying the writes in order takes `storage_pre` to `storage_post` in the
//!   contract's storage trie, and the published blob is entry by entry `ct_{j,h} = e_{j,h} + KS_{j,h}` with
//!   `KS_{j,h} = P(seed, [j, h])`, `seed = P(P(k_c, tx_hash), blob_salt)`, and `blob_digest` the fold of every `ct`.
//!
//! STRINGS (2026-11-13). A slot holding a string commits to its DIGEST, and the contract machine needs the BYTES to use it
//! again (`CONCAT`, `STR_EQ`, `RETURN`): a blob that carried only digests would let one hostile caller write a string and
//! withhold its bytes, and every later call that reads the slot could not be proven. So every entry also has
//! [`STR_SLOTS`] block slots: a string write absorbs its bytes, block by block, through the VM's own string sponge
//! (`dsol_vm::str_digest`: capacity seeded with the length, rate lanes overwritten, the same permutation), the sponge's
//! output must be the entry's `D`, and each block is encrypted under the same keystream (`KS_{j, 3+b}`). Slots past a
//! string's blocks, and every slot of a word or a PAD, are zero plaintext. The absorbed blocks are a PREFIX of the slots
//! (the schedule never lets an absorb follow an empty slot), so a reader knows where the bytes are. A stored string is
//! therefore at most `STR_SLOTS × 24 = 768` bytes (a longer one is refused when the blob is built; a contract keeps
//! longer text across several slots).
//!
//! WHY IT IS ENOUGH (A4). The trie is a Merkle commitment: ANY write-set that takes `storage_pre` to `storage_post` gives a
//! reader holding the pre-state exactly the post-state. So a blob that proves is a blob that rebuilds the contract; a
//! garbage blob with an honest `storage_post` cannot prove. A PAD is all-zero plaintext, so its ciphertext is the
//! keystream alone, indistinguishable from a write without `k_c`, and `W` is the CLASS's constant: the blob never says how
//! many slots a call wrote. The salt is fresh per PROOF (H1): two proofs of one call under one fee never share a keystream.
//!
//! ENTRY ENCODING (24 lanes, three halves): `K` the slot key, `V` the value's half, `D` a string's digest. A word is
//! `V = leaf_value_lanes(word) = [0, l0, l1, l2, l3, 0, 0, 0]`, `D = [1, 0…]` (a PRESENCE mark: the word 0 written to
//! the key 0 is a write, never a PAD); a string is `V = [1, len, 0…]`, `D = digest`, and its leaf value is `P(D, V)`
//! (`dsol_vm::leaf_value_lanes`). A reader therefore gets the VALUE back, not a digest of it, and a PAD is the only
//! all-zero entry.
//!
//! WHAT PROTECTS IT (AI RESISTANT, §2): (a) a proof every node checks; a lying prover (a garbage blob, another value for
//! one write, a missing or extra write, a reused keystream, another key) cannot make the statement true.
//! SCALE: rows `3 + Σ_write (504 + 3·blocks + 2·(32 − blocks)) + (6 + 64)·pads + 1 ≤ 3 + 600·W + 1 ≤ 2^(h+1)` for the
//! call's height class `h`; the blob is `W(h) · 1120 B` (2.2 KB at class 10, 36 KB at class 14).
//! Nothing here grows with the chain, the bonded set or the contract's age.

use crate::air_zerocheck::AirConstraint;
use crate::dsol_vm::{self, VmVal, STORAGE_DEPTH};
use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::{compress, Digest, DIGEST_LANES};
use crate::sponge_chain_air::{constants_for_seed, OUTPUT_OFF, P2_COLS, WIDTH};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::Poseidon2Air;

const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;
type P2Air = Poseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// The permutation every storage-trie hash uses ([`crate::poseidon2_compress::compress`], the production seed).
const SEED: u64 = crate::whir_rec_block::REC_DECIDER_SEED;
const L: usize = DIGEST_LANES;

/// Lanes in one entry's three halves: key, value half, string digest.
pub const ENTRY_LANES: usize = 3 * L;
/// The string block slots every entry has: a stored string is at most `STR_SLOTS × BYTES_PER_BLOCK` bytes.
pub const STR_SLOTS: usize = 32;
/// The most bytes one stored string may hold under D4.
pub const STR_STORED_MAX: usize = STR_SLOTS * dsol_vm::BYTES_PER_BLOCK;
/// Bytes of one entry on the wire: its string slots, then its three halves (each lane a canonical 31-bit field element,
/// 4 bytes little-endian).
pub const ENTRY_BYTES: usize = (STR_SLOTS + 3) * L * 4;
/// The most rows a WRITE entry occupies: the string-value row, the leaf row, 2 per trie level, 3 per string slot (an
/// absorb, a keystream, an accumulate), 6 for its three halves.
pub const WRITE_ROWS: usize = 2 + 2 * STORAGE_DEPTH + 3 * STR_SLOTS + 6;
/// Rows a PAD entry occupies: its empty string slots (a keystream, an accumulate each) and its three halves.
pub const PAD_ROWS: usize = 2 * STR_SLOTS + 6;
/// Rows before the first entry: the key commitment and the two seed rows.
pub const HEAD_ROWS: usize = 3;

/// The domain the key commitment is taken under — the DEPLOY's (`wallet` `dsol_kc_commit`), so the door matches the two.
#[must_use]
pub fn kc_domain() -> Digest {
    crate::poseidon2_compress::hash32_to_digest(blake3::hash(b"USDMD-DSOL-KC-DOMAIN-v1").as_bytes())
}

/// `P(KC_DOMAIN ‖ k_c)`: what a deploy fixes and every call's blob proof must open.
#[must_use]
pub fn kc_commit(k_c: &Digest) -> Digest {
    compress(&kc_domain(), k_c)
}

/// The blob accumulator's starting value.
#[must_use]
pub fn blob_acc_init() -> Digest {
    crate::poseidon2_compress::hash32_to_digest(blake3::hash(b"MonerousD/dsol/storage-blob/v1").as_bytes())
}

/// The fewest CPU rows one write occupies in the contract machine: each write lays its path twice (pre and post images)
/// over [`STORAGE_DEPTH`] levels. The CPU table of class `h` therefore holds at most `2^h / ROWS_PER_WRITE_MIN` writes;
/// `the_machine_spends_at_least_rows_per_write_min_rows_on_every_write` MEASURES it on a real trace.
pub const ROWS_PER_WRITE_MIN: usize = 2 * STORAGE_DEPTH;

/// `W(h)`: how many entries a call's blob has at height class `h` — every call of the class, whatever it wrote.
#[must_use]
pub fn entries_for_class(h: u8) -> usize {
    (1usize << h) / ROWS_PER_WRITE_MIN
}

/// The blob table's height class for a call of class `h`: one more, so the most writes the call can hold always fit.
#[must_use]
pub fn blob_height_log2(h: u8) -> u8 {
    h + 1
}

/// One write the call made, in execution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub key: Digest,
    pub val: VmVal,
    /// A string's bytes (empty for a word): what the blob's string slots carry.
    pub bytes: Vec<u8>,
}

/// The string slots of a write: a string's blocks first (`dsol_vm::str_block_lanes`), zero after. `None` when the
/// string's bytes are missing, do not open its digest, or need more than [`STR_SLOTS`] blocks.
#[must_use]
pub fn slots_of(w: &Write) -> Option<Vec<Digest>> {
    let mut out = vec![[0u64; L]; STR_SLOTS];
    if let VmVal::Str { digest, len } = w.val {
        if w.bytes.len() != len as usize || dsol_vm::str_digest(&w.bytes) != digest {
            return None;
        }
        let nb = dsol_vm::str_blocks(w.bytes.len());
        if nb > STR_SLOTS {
            return None;
        }
        for (b, slot) in out.iter_mut().enumerate().take(nb) {
            *slot = dsol_vm::str_block_lanes(&w.bytes, b);
        }
    }
    Some(out)
}

/// A string's bytes back from its decrypted slots: the lanes unpacked three bytes each, cut to `len`, checked against the
/// digest. `None` when they do not open it.
fn bytes_of(slots: &[Digest], digest: &Digest, len: u32) -> Option<Vec<u8>> {
    let mut b = Vec::with_capacity(slots.len() * dsol_vm::BYTES_PER_BLOCK);
    for lane in slots.iter().flatten() {
        if *lane >= 1 << (8 * dsol_vm::BYTES_PER_LANE) {
            return None;
        }
        b.extend_from_slice(&lane.to_le_bytes()[..dsol_vm::BYTES_PER_LANE]);
    }
    if b.len() < len as usize {
        return None;
    }
    b.truncate(len as usize);
    (dsol_vm::str_digest(&b) == *digest).then_some(b)
}

/// The 24 plaintext lanes of a write.
#[must_use]
pub fn entry_of(w: &Write) -> [u64; ENTRY_LANES] {
    let mut e = [0u64; ENTRY_LANES];
    e[..L].copy_from_slice(&w.key);
    match w.val {
        VmVal::Word(_) => {
            e[L..2 * L].copy_from_slice(&dsol_vm::leaf_value_lanes(&w.val));
            e[2 * L] = 1; // presence: never all zero
        }
        VmVal::Str { digest, len } => {
            e[L] = 1;
            e[L + 1] = u64::from(len);
            e[2 * L..].copy_from_slice(&digest);
        }
    }
    e
}

/// A write back from its plaintext lanes. `None` for a PAD (all zero) or lanes that are no write.
#[must_use]
pub fn write_of(e: &[u64; ENTRY_LANES]) -> Option<Write> {
    if e.iter().all(|x| *x == 0) {
        return None;
    }
    let mut key = [0u64; L];
    key.copy_from_slice(&e[..L]);
    let v = &e[L..2 * L];
    let val = match v[0] {
        0 => {
            if v[5..].iter().any(|x| *x != 0) || v[1..5].iter().any(|x| *x > 0xffff) || e[2 * L] != 1 || e[2 * L + 1..].iter().any(|x| *x != 0) {
                return None;
            }
            VmVal::Word(v[1] | v[2] << 16 | v[3] << 32 | v[4] << 48)
        }
        1 => {
            let mut digest = [0u64; L];
            digest.copy_from_slice(&e[2 * L..]);
            VmVal::Str { digest, len: u32::try_from(v[1]).ok()? }
        }
        _ => return None,
    };
    Some(Write { key, val, bytes: Vec::new() })
}

/// The write-set that takes `pre` to `post`: every slot whose value `post` holds and `pre` does not (in key order), each
/// string with its bytes from `post`'s contents. Any
/// write-set that maps one root to the other rebuilds the other exactly, so this is the blob a call carries whatever
/// order, repetition or library calls its machine wrote in. (Contract storage has no delete; a slot once present stays.)
#[must_use]
pub fn writes_between(pre: &dsol_vm::StorageTrie, post: &dsol_vm::StorageTrie) -> Vec<Write> {
    post.slots
        .iter()
        .filter(|(k, v)| pre.slots.get(*k) != Some(*v))
        .map(|(k, v)| Write {
            key: *k,
            val: *v,
            bytes: match v {
                VmVal::Str { digest, .. } => post.contents.get(digest).cloned().unwrap_or_default(),
                VmVal::Word(_) => Vec::new(),
            },
        })
        .collect()
}

/// The keystream seed of one proof: `P(P(k_c, tx_hash), blob_salt)`.
#[must_use]
pub fn stream_seed(k_c: &Digest, tx_hash: &Digest, salt: &Digest) -> Digest {
    compress(&compress(k_c, tx_hash), salt)
}

fn ks_input(j: u64, h: u64) -> Digest {
    crate::poseidon2_compress::lanes_of(&[j, h])
}

const P: u64 = 0x7f00_0001;
fn fadd(a: u64, b: u64) -> u64 {
    (a + b) % P
}
fn fsub(a: u64, b: u64) -> u64 {
    (a + P - b % P) % P
}

/// ENCRYPT a call's writes into its blob: `W` entries, the writes first in execution order, PADs after. Returns the blob
/// bytes and their digest. `None` when there are more writes than `W`.
#[must_use]
pub fn encrypt_blob(k_c: &Digest, tx_hash: &Digest, salt: &Digest, writes: &[Write], w: usize) -> Option<(Vec<u8>, Digest)> {
    if writes.len() > w {
        return None;
    }
    let seed = stream_seed(k_c, tx_hash, salt);
    let mut acc = blob_acc_init();
    let mut out = Vec::with_capacity(w * ENTRY_BYTES);
    for j in 0..w {
        let e = writes.get(j).map(entry_of).unwrap_or([0u64; ENTRY_LANES]);
        let slots = match writes.get(j) {
            Some(wr) => slots_of(wr)?,
            None => vec![[0u64; L]; STR_SLOTS],
        };
        for (b, lanes) in slots.iter().enumerate() {
            let ks = compress(&seed, &ks_input(j as u64, 3 + b as u64));
            let ct: Digest = core::array::from_fn(|i| fadd(lanes[i], ks[i]));
            acc = compress(&acc, &ct);
            for lane in ct {
                out.extend_from_slice(&(lane as u32).to_le_bytes());
            }
        }
        for h in 0..3 {
            let ks = compress(&seed, &ks_input(j as u64, h as u64));
            let ct: Digest = core::array::from_fn(|i| fadd(e[h * L + i], ks[i]));
            acc = compress(&acc, &ct);
            for lane in ct {
                out.extend_from_slice(&(lane as u32).to_le_bytes());
            }
        }
    }
    Some((out, acc))
}

/// The digest of a blob's bytes, as the door recomputes it (no key needed). `None` for bytes that are not whole entries
/// of canonical lanes.
#[must_use]
pub fn blob_digest(blob: &[u8]) -> Option<Digest> {
    if blob.len() % ENTRY_BYTES != 0 {
        return None;
    }
    let mut acc = blob_acc_init();
    for half in blob.chunks_exact(L * 4) {
        let ct: Digest = core::array::from_fn(|i| u64::from(u32::from_le_bytes(half[4 * i..4 * i + 4].try_into().unwrap_or([0xff; 4]))));
        if ct.iter().any(|x| *x >= P) {
            return None;
        }
        acc = compress(&acc, &ct);
    }
    Some(acc)
}

/// DECRYPT a blob with the contract key: its writes in order (PADs dropped), each string with its bytes. `None` when it is
/// not a blob, an entry is no write, or a string's slots do not open its digest.
#[must_use]
pub fn decrypt_blob(k_c: &Digest, tx_hash: &Digest, salt: &Digest, blob: &[u8]) -> Option<Vec<Write>> {
    blob_digest(blob)?;
    let seed = stream_seed(k_c, tx_hash, salt);
    let mut writes = Vec::new();
    for (j, entry) in blob.chunks_exact(ENTRY_BYTES).enumerate() {
        let lane_at = |at: usize| entry.get(at..at + 4).and_then(|x| x.try_into().ok()).map(|x| u64::from(u32::from_le_bytes(x)));
        let mut slots = vec![[0u64; L]; STR_SLOTS];
        for (b, slot) in slots.iter_mut().enumerate() {
            let ks = compress(&seed, &ks_input(j as u64, 3 + b as u64));
            for i in 0..L {
                slot[i] = fsub(lane_at((b * L + i) * 4)?, ks[i]);
            }
        }
        let mut e = [0u64; ENTRY_LANES];
        for h in 0..3 {
            let ks = compress(&seed, &ks_input(j as u64, h as u64));
            for i in 0..L {
                e[h * L + i] = fsub(lane_at(((STR_SLOTS + h) * L + i) * 4)?, ks[i]);
            }
        }
        if e.iter().any(|x| *x != 0) {
            let mut wr = write_of(&e)?;
            if let VmVal::Str { digest, len } = wr.val {
                wr.bytes = bytes_of(&slots, &digest, len)?;
            } else if slots.iter().flatten().any(|x| *x != 0) {
                return None;
            }
            writes.push(wr);
        }
    }
    Some(writes)
}

/// The public statement of one blob proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobStatement {
    pub storage_pre: Digest,
    pub storage_post: Digest,
    pub tx_hash: Digest,
    pub blob_salt: Digest,
    pub kc_commit: Digest,
    pub blob_digest: Digest,
    /// `W(h)`: the entries the blob has.
    pub entries: usize,
    /// The blob table's height class.
    pub height_log2: u8,
}

impl BlobStatement {
    /// The transcript bind: every public value, so a verifier reading another statement derives another transcript.
    #[must_use]
    pub fn bind(&self) -> Vec<Fa4> {
        let mut v = Vec::with_capacity(6 * L + 3);
        v.push(Fa4::from_u64(0x4434_424c)); // "D4BL"
        for d in [&self.storage_pre, &self.storage_post, &self.tx_hash, &self.blob_salt, &self.kc_commit, &self.blob_digest] {
            v.extend(d.iter().map(|x| Fa4::from_u64(*x)));
        }
        v.push(Fa4::from_u64(self.entries as u64));
        v.push(Fa4::from_u64(u64::from(self.height_log2)));
        v
    }
}

// ── the table ───────────────────────────────────────────────────────────────────────────────────────────────────

/// The row kinds, one-hot. Their order is the schedule: KC, S1, S2, then per entry (SV, LF, (PO, PN)×depth)?, the string
/// slots ((SBA KSA ABA)* (KSP ABP)*, exactly STR_SLOTS of them), KS0 AB0 KS1 AB1 KS2 AB2, then FILL to the end.
pub mod kind {
    pub const KC: usize = 0;
    pub const S1: usize = 1;
    pub const S2: usize = 2;
    pub const SV: usize = 3;
    pub const LF: usize = 4;
    pub const PO: usize = 5;
    pub const PN: usize = 6;
    pub const KS0: usize = 7;
    pub const AB0: usize = 8;
    pub const KS1: usize = 9;
    pub const AB1: usize = 10;
    pub const KS2: usize = 11;
    pub const AB2: usize = 12;
    pub const FILL: usize = 13;
    /// a string block absorbed into the string sponge
    pub const SBA: usize = 14;
    /// the keystream of an absorbed block, and its accumulate
    pub const KSA: usize = 15;
    pub const ABA: usize = 16;
    /// the keystream of an empty slot, and its accumulate
    pub const KSP: usize = 17;
    pub const ABP: usize = 18;
    pub const N: usize = 19;
}

pub const C_KIND: usize = P2_COLS;
pub const C_KC: usize = C_KIND + kind::N;
pub const C_SEED: usize = C_KC + L;
pub const C_ROOT: usize = C_SEED + L;
pub const C_BACC: usize = C_ROOT + L;
pub const C_J: usize = C_BACC + L;
pub const C_REAL: usize = C_J + 1;
pub const C_EK: usize = C_REAL + 1;
pub const C_EV: usize = C_EK + L;
pub const C_ED: usize = C_EV + L;
pub const C_NO: usize = C_ED + L;
pub const C_NN: usize = C_NO + L;
pub const C_SIB: usize = C_NN + L;
pub const C_BIT: usize = C_SIB + L;
pub const C_KACC: usize = C_BIT + 1;
pub const C_KLANE: usize = C_KACC + L;
/// One-hot of the key bit (30 … 0) the current lane is at.
pub const BITS: usize = 31;
pub const C_BITPOS: usize = C_KLANE + L;
/// `klane[0] · bitpos[0]`: the path's last level, committed so the transition laws read it at degree 1.
pub const C_END: usize = C_BITPOS + BITS;
/// The block an absorb takes in (constant over its three rows, zero elsewhere).
pub const C_BLK: usize = C_END + 1;
/// The string sponge's capacity half, and its rate output (the digest once the last block is in).
pub const C_CAP: usize = C_BLK + L;
pub const C_SDIG: usize = C_CAP + L;
/// One-hot of the string slot the entry is at.
pub const C_BS: usize = C_SDIG + L;
pub const COLS: usize = C_BS + STR_SLOTS;

const _: () = assert!(L * BITS == STORAGE_DEPTH, "the key's bits are the trie's levels");

fn kb(v: u64) -> KoalaBear {
    KoalaBear::from_u64(v)
}

/// The values one row carries besides its permutation.
#[derive(Clone)]
struct RowState {
    kind: usize,
    seed: Digest,
    root: Digest,
    bacc: Digest,
    j: u64,
    real: bool,
    e: [u64; ENTRY_LANES],
    no: Digest,
    nn: Digest,
    sib: Digest,
    bit: bool,
    kacc: Digest,
    klane: usize,
    bitpos: usize,
    blk: Digest,
    cap: Digest,
    sdig: Digest,
    bs: usize,
}

/// The direction of level `r` (0 = the leaf's) for `key`: the bit the native fold reads ([`dsol_vm::fold_path`]).
fn level_bit(key: &Digest, r: usize) -> bool {
    dsol_vm::key_bit(key, STORAGE_DEPTH - 1 - r)
}

/// Lay one row: its permutation (the input `left ‖ right`) and every carried value. Returns the permutation's output: its
/// first 8 lanes (the compression) and its last 8 (a sponge's capacity).
fn lay_row(
    cols: &mut [Vec<Fa4>],
    row: &mut usize,
    consts: &p3_poseidon2_air::RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    k_c: &Digest,
    st: &RowState,
    left: Digest,
    right: Digest,
) -> (Digest, Digest) {
    let r = *row;
    let mut state = [KoalaBear::ZERO; WIDTH];
    for i in 0..L {
        state[i] = kb(left[i]);
        state[L + i] = kb(right[i]);
    }
    let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, consts);
    for (c, v) in filled.iter().enumerate() {
        cols[c][r] = *v;
    }
    cols[C_KIND + st.kind][r] = KoalaBear::ONE;
    for i in 0..L {
        cols[C_KC + i][r] = kb(k_c[i]);
        cols[C_SEED + i][r] = kb(st.seed[i]);
        cols[C_ROOT + i][r] = kb(st.root[i]);
        cols[C_BACC + i][r] = kb(st.bacc[i]);
        cols[C_EK + i][r] = kb(st.e[i]);
        cols[C_EV + i][r] = kb(st.e[L + i]);
        cols[C_ED + i][r] = kb(st.e[2 * L + i]);
        cols[C_NO + i][r] = kb(st.no[i]);
        cols[C_NN + i][r] = kb(st.nn[i]);
        cols[C_SIB + i][r] = kb(st.sib[i]);
        cols[C_KACC + i][r] = kb(st.kacc[i]);
    }
    cols[C_J][r] = kb(st.j);
    cols[C_REAL][r] = if st.real { KoalaBear::ONE } else { KoalaBear::ZERO };
    cols[C_BIT][r] = if st.bit { KoalaBear::ONE } else { KoalaBear::ZERO };
    cols[C_KLANE + st.klane][r] = KoalaBear::ONE;
    cols[C_BITPOS + st.bitpos][r] = KoalaBear::ONE;
    for i in 0..L {
        cols[C_BLK + i][r] = kb(st.blk[i]);
        cols[C_CAP + i][r] = kb(st.cap[i]);
        cols[C_SDIG + i][r] = kb(st.sdig[i]);
    }
    cols[C_BS + st.bs][r] = KoalaBear::ONE;
    if st.klane == 0 && st.bitpos == 0 {
        cols[C_END][r] = KoalaBear::ONE;
    }
    *row += 1;
    let mut s = state;
    {
        use p3_symmetric::Permutation;
        crate::sponge_chain_air::production_perm().permute_mut(&mut s);
    }
    (core::array::from_fn(|i| u64::from(s[i].as_canonical_u32())), core::array::from_fn(|i| u64::from(s[L + i].as_canonical_u32())))
}

/// A LYING PROVER's one false step, for the tests that the statement refuses it (`Honest` is the only production value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lie {
    Honest,
    /// the first string write absorbs no block: its bytes are withheld
    WithholdBytes,
    /// the first string write absorbs another string's blocks (same block count) under its own digest
    OtherBytes,
}

/// LAY the blob table for a call: `k_c`, the statement's public values, the writes in order with the storage each starts
/// from. Returns the columns and the statement. `None` when the writes do not fit the class, a write's path is wrong, or
/// a string's bytes are missing, longer than [`STR_STORED_MAX`], or not its digest's.
#[must_use]
pub fn build_trace(
    k_c: &Digest,
    storage_pre: &dsol_vm::StorageTrie,
    tx_hash: &Digest,
    salt: &Digest,
    writes: &[Write],
    call_height_log2: u8,
) -> Option<(Vec<Vec<Fa4>>, BlobStatement)> {
    build_trace_lying(k_c, storage_pre, tx_hash, salt, writes, call_height_log2, Lie::Honest)
}

pub(crate) fn build_trace_lying(
    k_c: &Digest,
    storage_pre: &dsol_vm::StorageTrie,
    tx_hash: &Digest,
    salt: &Digest,
    writes: &[Write],
    call_height_log2: u8,
    lie: Lie,
) -> Option<(Vec<Vec<Fa4>>, BlobStatement)> {
    let w = entries_for_class(call_height_log2);
    let hb = blob_height_log2(call_height_log2);
    let rows = 1usize << hb;
    if writes.len() > w || HEAD_ROWS + writes.len() * WRITE_ROWS + (w - writes.len()) * PAD_ROWS + 1 > rows {
        return None;
    }
    let mut all_slots = Vec::with_capacity(writes.len());
    for wr in writes {
        all_slots.push(slots_of(wr)?);
    }
    let first_str = writes.iter().position(|wr| matches!(wr.val, VmVal::Str { .. }));
    if lie == Lie::OtherBytes {
        let j = first_str?;
        let other: Vec<u8> = writes[j].bytes.iter().map(|b| b ^ 0x5a).collect();
        let nb = dsol_vm::str_blocks(other.len());
        for b in 0..nb {
            all_slots[j][b] = dsol_vm::str_block_lanes(&other, b);
        }
    }
    let consts = constants_for_seed(SEED);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; rows]; COLS];
    let seed = stream_seed(k_c, tx_hash, salt);
    let mut trie = storage_pre.clone();
    let mut st = RowState {
        kind: kind::KC,
        seed: [0; L],
        root: trie.root(),
        bacc: blob_acc_init(),
        j: 0,
        real: false,
        e: [0; ENTRY_LANES],
        no: [0; L],
        nn: [0; L],
        sib: [0; L],
        bit: false,
        kacc: [0; L],
        klane: L - 1,
        bitpos: BITS - 1,
        blk: [0; L],
        cap: [0; L],
        sdig: [0; L],
        bs: 0,
    };
    let mut row = 0usize;
    let lay = |cols: &mut Vec<Vec<Fa4>>, row: &mut usize, st: &RowState, left: Digest, right: Digest| -> Digest { lay_row(cols, row, &consts, k_c, st, left, right).0 };
    let lay16 = |cols: &mut Vec<Vec<Fa4>>, row: &mut usize, st: &RowState, left: Digest, right: Digest| -> (Digest, Digest) { lay_row(cols, row, &consts, k_c, st, left, right) };

    // head: the key commitment, then the seed
    lay(&mut cols, &mut row, &st, kc_domain(), *k_c);
    st.kind = kind::S1;
    st.seed = lay(&mut cols, &mut row, &st, *k_c, *tx_hash);
    st.kind = kind::S2;
    st.seed = lay(&mut cols, &mut row, &st, st.seed, *salt);
    debug_assert_eq!(st.seed, seed);

    for j in 0..w {
        let write = writes.get(j);
        st.real = write.is_some();
        st.e = write.map(entry_of).unwrap_or([0; ENTRY_LANES]);
        st.j = j as u64;
        // the entry's string sponge opens: capacity [len, 0…], no digest yet, slot 0
        st.cap = [0; L];
        st.cap[0] = st.e[L + 1];
        st.sdig = [0; L];
        st.bs = 0;
        st.blk = [0; L];
        if let Some(wr) = write {
            let key = wr.key;
            // the old leaf and the shared siblings, from the trie as it stands before this write
            let old_leaf = trie.get(&key).map_or([0u64; L], |v| dsol_vm::slot_leaf(&key, &v));
            let sibs = trie.path(&key);
            // SV: the string value's leaf lanes (computed for a word too; a word's lanes are V itself)
            st.kind = kind::SV;
            st.kacc = [0; L];
            st.klane = L - 1;
            st.bitpos = BITS - 1;
            let ev: Digest = core::array::from_fn(|i| st.e[L + i]);
            let ed: Digest = core::array::from_fn(|i| st.e[2 * L + i]);
            let sv = lay(&mut cols, &mut row, &st, ed, ev);
            let vl = if ev[0] == 1 { sv } else { ev };
            // LF: the new leaf
            st.kind = kind::LF;
            let new_leaf = lay(&mut cols, &mut row, &st, key, vl);
            debug_assert_eq!(new_leaf, dsol_vm::slot_leaf(&key, &wr.val));
            st.no = old_leaf;
            st.nn = new_leaf;
            for r in 0..STORAGE_DEPTH {
                // `path` lists the siblings top-first; level r (0 = the leaf's) takes the r-th from the bottom, as
                // `dsol_vm`'s own fold test pairs them
                let sib = sibs[STORAGE_DEPTH - 1 - r];
                let bit = level_bit(&key, r);
                st.sib = sib;
                st.bit = bit;
                st.kind = kind::PO;
                let (l, rr) = if bit { (sib, st.no) } else { (st.no, sib) };
                let o = lay(&mut cols, &mut row, &st, l, rr);
                // the key accumulator takes this level's bit
                st.kacc[st.klane] = (2 * st.kacc[st.klane] + u64::from(bit)) % P;
                st.no = o;
                st.kind = kind::PN;
                let (l, rr) = if bit { (sib, st.nn) } else { (st.nn, sib) };
                let n = lay(&mut cols, &mut row, &st, l, rr);
                st.nn = n;
                if r + 1 == STORAGE_DEPTH {
                    if st.no != st.root {
                        return None; // the trie handed over is not the statement's
                    }
                    st.root = n;
                } else {
                    if st.klane == 0 {
                        st.bitpos -= 1;
                    }
                    st.klane = (st.klane + L - 1) % L;
                }
            }
            trie.insert_checked(&key, wr.val).ok()?;
            if trie.root() != st.root {
                return None;
            }
            st.no = [0; L];
            st.nn = [0; L];
            st.sib = [0; L];
            st.bit = false;
        }
        // the string slots: a string's blocks absorbed and encrypted, then the empty slots encrypted
        let nb = match write.map(|wr| wr.val) {
            Some(VmVal::Str { .. }) if lie == Lie::WithholdBytes && Some(j) == first_str => 0,
            Some(VmVal::Str { len, .. }) => dsol_vm::str_blocks(len as usize),
            _ => 0,
        };
        for b in 0..STR_SLOTS {
            st.bs = b;
            let ks_in = ks_input(j as u64, 3 + b as u64);
            if b < nb {
                st.blk = all_slots[j][b];
                st.kind = kind::SBA;
                let (rate, cap) = lay16(&mut cols, &mut row, &st, st.blk, st.cap);
                st.sdig = rate;
                st.cap = cap;
                st.kind = kind::KSA;
                let ks = lay(&mut cols, &mut row, &st, st.seed, ks_in);
                let ct: Digest = core::array::from_fn(|i| fadd(st.blk[i], ks[i]));
                st.kind = kind::ABA;
                st.bacc = lay(&mut cols, &mut row, &st, st.bacc, ct);
                st.blk = [0; L];
            } else {
                st.kind = kind::KSP;
                let ks = lay(&mut cols, &mut row, &st, st.seed, ks_in);
                st.kind = kind::ABP;
                st.bacc = lay(&mut cols, &mut row, &st, st.bacc, ks);
            }
        }
        st.bs = 0;
        if lie == Lie::Honest && write.and_then(|wr| match wr.val {
            VmVal::Str { digest, .. } => Some(digest),
            VmVal::Word(_) => None,
        }).is_some_and(|d| d != st.sdig)
        {
            return None; // the string's bytes are not its digest's
        }
        for h in 0..3u64 {
            st.kind = [kind::KS0, kind::KS1, kind::KS2][h as usize];
            let ks = lay(&mut cols, &mut row, &st, st.seed, ks_input(j as u64, h));
            let ct: Digest = core::array::from_fn(|i| fadd(st.e[h as usize * L + i], ks[i]));
            st.kind = [kind::AB0, kind::AB1, kind::AB2][h as usize];
            st.bacc = lay(&mut cols, &mut row, &st, st.bacc, ct);
        }
    }
    st.j = w as u64;
    st.real = false;
    st.e = [0; ENTRY_LANES];
    st.cap = [0; L];
    st.sdig = [0; L];
    st.blk = [0; L];
    st.bs = 0;
    st.kind = kind::FILL;
    while row < rows {
        lay(&mut cols, &mut row, &st, [0; L], [0; L]);
    }
    let stmt = BlobStatement {
        storage_pre: storage_pre.root(),
        storage_post: st.root,
        tx_hash: *tx_hash,
        blob_salt: *salt,
        kc_commit: kc_commit(k_c),
        blob_digest: st.bacc,
        entries: w,
        height_log2: hb,
    };
    Some((cols, stmt))
}

// ── the laws ────────────────────────────────────────────────────────────────────────────────────────────────────

pub struct BlobConstraint {
    pub gamma: Ea4,
    pub p2: crate::whole_chain::WholeChainMainConstraint,
    pub stmt: BlobStatement,
}

fn e4(v: u64) -> Ea4 {
    Ea4::from(Fa4::from_u64(v))
}

impl AirConstraint for BlobConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED 2026-11-13 by the strict prover's trace-independent degree census (MONEROUSD_PROVER_ASSERTS=1, the
        // random-line census): 5 at width 370, 11 vars, where `p2.degree()` declared 8 and every round sampled 3 points too
        // many. The census refuses any gate above its declaration, so this is checked on every strict prove.
        5
    }

    /// The columns this gate reads on the NEXT row (`n(…)` in [`Self::eval`]): the kinds, the carried lanes (key, seed,
    /// root, blob accumulator), the entry, the string sponge and slot, the slot bits, the entry counter, the REAL flag,
    /// the right half of the permutation input (`n(L + i)`), the two path chains with their sibling and bit, and the
    /// key-bit accumulators — UNIONED with what the forwarded Poseidon2 half declares (composed, never hand-listed for
    /// the half it forwards to). A-F55: the chained door binds exactly these next-row values to the commitment by its
    /// shift bind, and the prover's asserts abort a prove that reads a column outside this set.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let mut v: Vec<usize> = (C_KIND..C_KIND + kind::N).collect();
        for base in [C_KC, C_SEED, C_ROOT, C_BACC, C_EK, C_EV, C_ED, C_NO, C_NN, C_SIB, C_KACC, C_KLANE, C_BLK, C_CAP, C_SDIG] {
            v.extend(base..base + L);
        }
        v.extend(L..2 * L);
        v.extend(C_BS..C_BS + STR_SLOTS);
        v.extend(C_BITPOS..C_BITPOS + BITS);
        v.extend([C_J, C_REAL, C_BIT]);
        v.extend(self.p2.shifted_cols()?);
        v.sort_unstable();
        v.dedup();
        Some(v)
    }

    fn eval(&self, c: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = self.p2.eval(c, at, x);
        let g = self.gamma;
        let mut push = |r: Ea4| {
            acc = acc * g + r;
        };
        let n = |i: usize| at(i, &[]);
        let one = Ea4::ONE;
        // A-F55: the DATA half of the point (`x[1..]`), as `member_path_gate` reads it. The blob is proved on the BLINDED
        // chained door, which doubles the table and spends `x[0]` (the MSB) on selecting the random half; a mask over all of
        // `x` would put the last data row's transition onto a blinding row and the statement's end welds (storage_post, the
        // blob digest, the entry count) onto a row the blinding selector zeroes.
        let data = x.get(1..).unwrap_or(&[]);
        let mut is_first = Ea4::ONE;
        let mut is_last = Ea4::ONE;
        for &xk in data {
            is_first *= one - xk;
            is_last *= xk;
        }
        let tr = one - is_last;
        let k = |i: usize| c[C_KIND + i];
        let nk = |i: usize| n(C_KIND + i);
        let input = |i: usize| c[i];
        let out = |i: usize| c[OUTPUT_OFF + i];

        // 0. the kinds: each a bit, exactly one per row
        let mut sum = Ea4::ZERO;
        for i in 0..kind::N {
            push(k(i) * (one - k(i)));
            sum += k(i);
        }
        push(sum - one);
        // bits and one-hots
        push(c[C_REAL] * (one - c[C_REAL]));
        push(c[C_BIT] * (one - c[C_BIT]));
        let mut ls = Ea4::ZERO;
        for i in 0..L {
            push(c[C_KLANE + i] * (one - c[C_KLANE + i]));
            ls += c[C_KLANE + i];
        }
        push(ls - one);
        let mut bs = Ea4::ZERO;
        for b in 0..BITS {
            push(c[C_BITPOS + b] * (one - c[C_BITPOS + b]));
            bs += c[C_BITPOS + b];
        }
        push(bs - one);
        push(c[C_END] - c[C_KLANE] * c[C_BITPOS]);
        // a write's value tag: 0 a word, 1 a string
        push(c[C_REAL] * c[C_EV] * (one - c[C_EV]));
        let mut ss = Ea4::ZERO;
        for b in 0..STR_SLOTS {
            push(c[C_BS + b] * (one - c[C_BS + b]));
            ss += c[C_BS + b];
        }
        push(ss - one);
        // only a string absorbs (a word's and a PAD's tag is 0)
        push(k(kind::SBA) * (one - c[C_EV]));

        // 1. the schedule: which kind follows which
        let ab = k(kind::AB0) + k(kind::AB1) + k(kind::AB2) + k(kind::ABA) + k(kind::ABP);
        let abb = k(kind::ABA) + k(kind::ABP);
        let boundary = k(kind::S2) + k(kind::AB2);
        let last = c[C_BS + STR_SLOTS - 1];
        push(tr * k(kind::KC) * (nk(kind::S1) - one));
        push(tr * k(kind::S1) * (nk(kind::S2) - one));
        push(tr * k(kind::S2) * (nk(kind::SV) + nk(kind::KSP) - one));
        push(tr * k(kind::SV) * (nk(kind::LF) - one));
        push(tr * k(kind::LF) * (nk(kind::PO) - one));
        push(tr * k(kind::PO) * (nk(kind::PN) - one));
        push(tr * k(kind::PN) * (nk(kind::PO) - (one - c[C_END])));
        push(tr * k(kind::PN) * (nk(kind::SBA) + nk(kind::KSP) - c[C_END]));
        // the string slots: an absorb is followed by its keystream and accumulate; an empty slot never precedes an absorb
        push(tr * k(kind::SBA) * (nk(kind::KSA) - one));
        push(tr * k(kind::KSA) * (nk(kind::ABA) - one));
        push(tr * k(kind::KSP) * (nk(kind::ABP) - one));
        push(tr * k(kind::ABA) * (nk(kind::SBA) + nk(kind::KSP) - (one - last)));
        push(tr * k(kind::ABP) * (nk(kind::KSP) - (one - last)));
        push(tr * abb * (nk(kind::KS0) - last));
        push(tr * k(kind::KS0) * (nk(kind::AB0) - one));
        push(tr * k(kind::AB0) * (nk(kind::KS1) - one));
        push(tr * k(kind::KS1) * (nk(kind::AB1) - one));
        push(tr * k(kind::AB1) * (nk(kind::KS2) - one));
        push(tr * k(kind::KS2) * (nk(kind::AB2) - one));
        push(tr * k(kind::AB2) * (nk(kind::SV) + nk(kind::KSP) + nk(kind::FILL) - one));
        push(tr * k(kind::FILL) * (nk(kind::FILL) - one));

        // 2. the carried values
        for i in 0..L {
            push(tr * (n(C_KC + i) - c[C_KC + i]));
            let s1s2 = k(kind::S1) + k(kind::S2);
            push(tr * (n(C_SEED + i) - (s1s2 * out(i) + (one - s1s2) * c[C_SEED + i])));
            push(tr * (n(C_BACC + i) - (ab * out(i) + (one - ab) * c[C_BACC + i])));
            let fin = k(kind::PN) * c[C_END];
            push(tr * (n(C_ROOT + i) - (fin * out(i) + (one - fin) * c[C_ROOT + i])));
            // the entry: constant inside it; zero for a PAD
            for base in [C_EK, C_EV, C_ED] {
                push(tr * (one - boundary) * (n(base + i) - c[base + i]));
                push((one - c[C_REAL]) * c[base + i]);
            }
        }
        // the string sponge and the slot: reset at an entry's start, advanced by an absorb, rotated by an accumulate
        for i in 0..L {
            let start = if i == 0 { n(C_EV + 1) } else { Ea4::ZERO };
            let keep = one - k(kind::SBA) - boundary;
            push(tr * (n(C_CAP + i) - (k(kind::SBA) * out(L + i) + keep * c[C_CAP + i] + boundary * start)));
            push(tr * (n(C_SDIG + i) - (k(kind::SBA) * out(i) + keep * c[C_SDIG + i])));
            push((one - k(kind::SBA) - k(kind::KSA) - k(kind::ABA)) * c[C_BLK + i]);
            push(tr * (k(kind::SBA) + k(kind::KSA)) * (n(C_BLK + i) - c[C_BLK + i]));
        }
        for b in 0..STR_SLOTS {
            let first = if b == 0 { one } else { Ea4::ZERO };
            push(tr * boundary * (n(C_BS + b) - first));
            push(tr * abb * (n(C_BS + b) - c[C_BS + (b + STR_SLOTS - 1) % STR_SLOTS]));
            push(tr * (one - abb - boundary) * (n(C_BS + b) - c[C_BS + b]));
        }
        push(tr * (n(C_J) - c[C_J] - k(kind::AB2)));
        // REAL: kept inside an entry; at a boundary the next entry is real exactly when it starts with its value row
        push(tr * (n(C_REAL) - (boundary * nk(kind::SV) + (one - boundary) * c[C_REAL])));

        // 3. what each kind's permutation takes in
        let dom = kc_domain();
        let tx = self.stmt.tx_hash;
        let salt = self.stmt.blob_salt;
        for i in 0..L {
            let (li, ri) = (input(i), input(L + i));
            push(k(kind::KC) * (li - e4(dom[i])));
            push(k(kind::KC) * (ri - c[C_KC + i]));
            push(k(kind::KC) * (out(i) - e4(self.stmt.kc_commit[i])));
            push(k(kind::S1) * (li - c[C_KC + i]));
            push(k(kind::S1) * (ri - e4(tx[i])));
            push(k(kind::S2) * (li - c[C_SEED + i]));
            push(k(kind::S2) * (ri - e4(salt[i])));
            // SV hashes (D, V); LF hashes (K, value lanes) where the value lanes are V for a word, P(D, V) for a string
            push(k(kind::SV) * (li - c[C_ED + i]));
            push(k(kind::SV) * (ri - c[C_EV + i]));
            let tag = c[C_EV];
            push(tr * k(kind::SV) * (n(L + i) - (tag * out(i) + (one - tag) * c[C_EV + i])));
            // a word's D is its presence mark [1, 0…]: a write is never an all-zero entry
            let mark = if i == 0 { one } else { Ea4::ZERO };
            push(c[C_REAL] * (one - tag) * (c[C_ED + i] - mark));
            push(k(kind::LF) * (li - c[C_EK + i]));
            // the path: the node sits left or right of the sibling by the level's bit
            let b = c[C_BIT];
            for (kd, node) in [(kind::PO, C_NO), (kind::PN, C_NN)] {
                push(k(kd) * (li - ((one - b) * c[node + i] + b * c[C_SIB + i])));
                push(k(kd) * (ri - ((one - b) * c[C_SIB + i] + b * c[node + i])));
            }
            // the keystream halves: P(seed, [j, h])
            for (kd, h) in [(kind::KS0, 0u64), (kind::KS1, 1), (kind::KS2, 2)] {
                push(k(kd) * (li - c[C_SEED + i]));
                let want = match i {
                    0 => c[C_J],
                    1 => e4(h),
                    _ => Ea4::ZERO,
                };
                push(k(kd) * (ri - want));
            }
            // an absorb takes the accumulator and this half's ciphertext, the plaintext half plus the keystream before it
            for (kd, ab_kind, base) in [(kind::KS0, kind::AB0, C_EK), (kind::KS1, kind::AB1, C_EV), (kind::KS2, kind::AB2, C_ED)] {
                push(tr * k(kd) * (n(L + i) - (c[base + i] + out(i))));
                push(k(ab_kind) * (li - c[C_BACC + i]));
            }
            push(k(kind::FILL) * li);
            push(k(kind::FILL) * ri);
            // an absorb takes its block and the sponge's capacity
            push(k(kind::SBA) * (li - c[C_BLK + i]));
            push(k(kind::SBA) * (ri - c[C_CAP + i]));
            // a slot's keystream: P(seed, [j, 3 + slot])
            let slot: Ea4 = (0..STR_SLOTS).map(|b| e4(b as u64) * c[C_BS + b]).sum();
            for kd in [kind::KSA, kind::KSP] {
                push(k(kd) * (li - c[C_SEED + i]));
                let want = match i {
                    0 => c[C_J],
                    1 => e4(3) + slot,
                    _ => Ea4::ZERO,
                };
                push(k(kd) * (ri - want));
            }
            // the slot's ciphertext: the block plus its keystream (an empty slot: the keystream alone)
            push(tr * k(kind::KSA) * (n(L + i) - (c[C_BLK + i] + out(i))));
            push(tr * k(kind::KSP) * (n(L + i) - out(i)));
            push(abb * (li - c[C_BACC + i]));
            // the halves begin once the string is in: a string's sponge output is the entry's digest
            push(k(kind::KS0) * c[C_EV] * (c[C_SDIG + i] - c[C_ED + i]));
        }
        // 4. the two chains of a level and the hand-over to the next
        for i in 0..L {
            // after PO: the old chain advances, the new node, sibling and bit stay for PN
            push(tr * k(kind::PO) * (n(C_NO + i) - out(i)));
            push(tr * k(kind::PO) * (n(C_NN + i) - c[C_NN + i]));
            push(tr * k(kind::PO) * (n(C_SIB + i) - c[C_SIB + i]));
            // after PN (not the last level): the new chain advances, the old node stays
            push(tr * k(kind::PN) * (one - c[C_END]) * (n(C_NN + i) - out(i)));
            push(tr * k(kind::PN) * (one - c[C_END]) * (n(C_NO + i) - c[C_NO + i]));
            // after LF: the new chain starts at the new leaf (the old chain's start is the old leaf, a witness)
            push(tr * k(kind::LF) * (n(C_NN + i) - out(i)));
            // the last level: the old chain reached the root the write starts from, and the key is the entry's key
            push(k(kind::PN) * c[C_END] * (c[C_NO + i] - c[C_ROOT + i]));
            push(k(kind::PN) * c[C_END] * (c[C_KACC + i] - c[C_EK + i]));
        }
        push(tr * k(kind::PO) * (n(C_BIT) - c[C_BIT]));
        // 5. the key bits: the accumulator of the current lane takes the bit at PO, the lane rotates at PN
        for l in 0..L {
            push(k(kind::SV) * c[C_KACC + l]);
            let start = if l == L - 1 { one } else { Ea4::ZERO };
            push(k(kind::SV) * (c[C_KLANE + l] - start));
            push(tr * k(kind::PO) * (n(C_KACC + l) - (c[C_KACC + l] + c[C_KLANE + l] * (c[C_KACC + l] + c[C_BIT]))));
            push(tr * k(kind::PO) * (n(C_KLANE + l) - c[C_KLANE + l]));
            push(tr * k(kind::PN) * (one - c[C_END]) * (n(C_KACC + l) - c[C_KACC + l]));
            push(tr * k(kind::PN) * (one - c[C_END]) * (n(C_KLANE + l) - c[C_KLANE + (l + 1) % L]));
            push(tr * (k(kind::SV) + k(kind::LF)) * (n(C_KACC + l) - c[C_KACC + l]));
            push(tr * (k(kind::SV) + k(kind::LF)) * (n(C_KLANE + l) - c[C_KLANE + l]));
        }
        for b in 0..BITS {
            let start = if b == BITS - 1 { one } else { Ea4::ZERO };
            push(k(kind::SV) * (c[C_BITPOS + b] - start));
            push(tr * k(kind::PO) * (n(C_BITPOS + b) - c[C_BITPOS + b]));
            let above = if b + 1 < BITS { c[C_BITPOS + b + 1] } else { Ea4::ZERO };
            push(tr * k(kind::PN) * (one - c[C_END]) * (n(C_BITPOS + b) - (c[C_BITPOS + b] + c[C_KLANE] * (above - c[C_BITPOS + b]))));
            push(tr * (k(kind::SV) + k(kind::LF)) * (n(C_BITPOS + b) - c[C_BITPOS + b]));
        }

        // 6. the statement's ends
        push(is_first * (k(kind::KC) - one));
        push(is_first * c[C_J]);
        push(is_first * (c[C_BS] - one));
        for i in 0..L {
            push(is_first * c[C_CAP + i]);
            push(is_first * c[C_SDIG + i]);
        }
        let init = blob_acc_init();
        for i in 0..L {
            push(is_first * (c[C_ROOT + i] - e4(self.stmt.storage_pre[i])));
            push(is_first * (c[C_BACC + i] - e4(init[i])));
            push(is_last * (c[C_ROOT + i] - e4(self.stmt.storage_post[i])));
            push(is_last * (c[C_BACC + i] - e4(self.stmt.blob_digest[i])));
        }
        push(is_last * (k(kind::FILL) - one));
        push(is_last * (c[C_J] - e4(self.stmt.entries as u64)));
        acc
    }
}

/// The constraint for a public statement — both sides call this, so the circuit a prover satisfies is the circuit a
/// verifier rebuilds from the statement alone.
#[must_use]
pub fn make_constraint(stmt: BlobStatement) -> impl Fn(Ea4) -> BlobConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    let air = P2Air::new(constants_for_seed(SEED));
    let layout = AirLayout { preprocessed_width: 0, main_width: P2_COLS, num_public_values: 0, num_periodic_columns: 0, ..Default::default() };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |gamma: Ea4| BlobConstraint {
        gamma,
        p2: crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: COLS, preproc_w: 0, npub: 0 },
            COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        ),
        stmt: stmt.clone(),
    }
}

/// A blob proof's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobProof {
    pub bytes: Vec<u8>,
}

/// PROVE a call's blob: the writes it made from `storage_pre`, under `k_c`, for this proof's `tx_hash` and fresh `salt`.
/// Returns the proof, the statement and the blob bytes.
#[must_use]
pub fn prove_blob(
    k_c: &Digest,
    storage_pre: &dsol_vm::StorageTrie,
    tx_hash: &Digest,
    salt: &Digest,
    writes: &[Write],
    call_height_log2: u8,
) -> Option<(BlobProof, BlobStatement, Vec<u8>)> {
    let (cols, stmt) = build_trace(k_c, storage_pre, tx_hash, salt, writes, call_height_log2)?;
    let (blob, digest) = encrypt_blob(k_c, tx_hash, salt, writes, stmt.entries)?;
    if digest != stmt.blob_digest {
        return None;
    }
    // ⛔ A-F55 (2026-11-13): the BLINDED CHAINED door, never the direct light decider. MEASURED on the direct engine: its
    // solved-row liar (zero zerocheck rounds, an opened row solved to satisfy the gate) passed `verify_blob`, 19,535 B, for
    // a storage_post no write reached — that engine never opens its trace. This trace holds `k_c` and the plaintext
    // writes, so it is blinded (not the unhidden batch engine), and its gate reads the next row, so the chained door's
    // shift bind ties every next-row value it reads to the commitment.
    let bytes = crate::committed_air::prove_air_blinded_chained_bytes(cols, make_constraint(stmt.clone()), &stmt.bind())?;
    Some((BlobProof { bytes }, stmt, blob))
}

/// THE DOOR'S CHECK of a call's blob: the blob has exactly the class's entries and its digest is the statement's, and the
/// proof verifies against the statement rebuilt from public values alone. Keyless: nothing is decrypted.
#[must_use]
pub fn verify_blob(proof: &BlobProof, stmt: &BlobStatement, blob: &[u8], call_height_log2: u8) -> bool {
    if stmt.entries != entries_for_class(call_height_log2)
        || stmt.height_log2 != blob_height_log2(call_height_log2)
        || blob.len() != stmt.entries * ENTRY_BYTES
        || blob_digest(blob) != Some(stmt.blob_digest)
    {
        return false;
    }
    let shape = (usize::from(stmt.height_log2), COLS);
    // A-F55: the door the prover uses (see `prove_blob`); `shape` is the LAID table's, before blinding doubles it.
    crate::committed_air::verify_air_blinded_chained_bytes(&proof.bytes, make_constraint(stmt.clone()), &stmt.bind(), shape)
}

#[cfg(test)]
mod tests;

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Append-only **Poseidon** PQ note-commitment SPEND-membership frontier — the ZK-friendly twin of the
//! blake3 [`crate::frontier`] tree.
//!
//! WHY A SECOND TREE. The blake3 [`crate::frontier`] is the DAG/DA/note-visibility accumulator (served by
//! `/get_pq_output_tree`); blake3 is right there. But a **private** spend proves note-membership IN ZERO
//! KNOWLEDGE — it recomputes the Merkle path INSIDE the WHIR circuit without revealing which note. blake3
//! is bit-oriented (XOR/rotate/add), so one in-circuit compression costs thousands of constraints and a
//! depth-32 path blows past the ≤1.8MB / sub-1s / phone-class FAST pillar. Poseidon is pure field
//! arithmetic (x⁷ S-box + a 4×4 KoalaBear-MDS), a handful of constraints per level — the standard
//! ZK-membership hash. So the SPEND membership binds to THIS Poseidon frontier; the root is committed and
//! a spend proves against it (the wallet builds its copath with the identical `poseidon_pair`).
//!
//! ONE COMPRESSION, ONE DEFINITION. [`poseidon_pair`] does not reimplement anything: it DELEGATES to
//! [`usdm_decider::poseidon2_compress::compress`], the chain's single compression — a truncated
//! Poseidon2 permutation over `sponge_chain_air::production_perm()`, the same permutation the PoUW
//! kernel mines with. So the frontier, the wallet's copath and every in-circuit gate are byte-identical
//! by CONSTRUCTION rather than by a parity test that has to be maintained.
//!
//! ⛔⛔⛔ THIS USED TO BE A NATIVE ONE-ROUND COPY — `pre = left + 7·right`, an x⁷ S-box, then a 4×4 MDS
//! mix — reimplemented here "for byte-parity". Kill list §AG measured that function and every part of it
//! INVERTS: `x ↦ x⁷` is a bijection over KoalaBear (`gcd(7, p−1) = 1`), the MDS is invertible, and
//! `pre` is linear, so a non-membership copath could be SOLVED by division in about a millisecond and a
//! SPENT nullifier read Unspent. A second implementation of a primitive is also a second place for it to
//! be wrong; the delegation above is why there is now exactly one.
//!
//! Append is **O(DEPTH), not O(n)** (no-growth pillar): one pending hash per level (an MMR/binary-counter
//! carry) + the leaf count, never the full leaf set. Empty subtrees pad against a fixed empty ladder.

/// KoalaBear prime `p = 2^31 − 2^24 + 1`. The spend AIR + the wallet prover work in this field.
const KB_P: u64 = 2_130_706_433;


/// Depth of the spend-membership tree: 2^64 leaves. The wallet's `NOTE_TREE_DEPTH` (pq_spend.rs, pq.rs)
/// MUST equal this — a spend's membership proof and the wallet's copath are the same tree, and a mismatch
/// makes every spend unverifiable.
///
/// ⛔⛔⛔ THIS WAS 32, AND 32 GAVE THE CHAIN A DEATH DATE 97 DAYS AFTER GENESIS.
///
/// The frontier is a FIXED-HEIGHT tree: `capacity() == 2^depth`, and `append` refuses once
/// `count >= capacity()`. A refusal to append is a refusal to RECEIVE, so past that point no note can
/// enter the chain and every later payment is impossible — the ultimate fund-loss bug, on a timer.
///
/// MEASURED from the protocol's own constants (`the_note_frontier_has_no_chain_lifetime_ceiling`):
///     depth 32 -> capacity 4,294,967,296 leaves
///     BLOCK_FIXED_NOTE_COUNT 256 leaves/block x 172,800 blocks/day = 44,236,800 leaves/day
///     -> the frontier fills in 97 DAYS
/// The fill rate carries NO traffic term: the constant 256-leaf cover width is the privacy invariant, so
/// an idle chain burns capacity at exactly the same rate as a busy one. Zcash survives a depth-32 tree
/// because it appends only real notes; we append the cover shape every block, 256x faster.
///
/// At depth 64, `capacity()` saturates to `u64::MAX` — the count is a u64, so there is no reachable
/// ceiling at all. In fill-rate terms: 2^64 / 44,236,800 per day = ~1.1 x 10^9 YEARS. A chain holding
/// real funds must outlive everyone who uses it, like Bitcoin, and that is what this constant now says.
/// The other two trees were already unbounded in practice (`UNS_DEPTH` = 256, `NF_SPARSE_DEPTH` = 256);
/// this was the one fixed-capacity structure on the value path.
pub const SPEND_TREE_DEPTH: usize = 64;
/// ⛔ `BURN_CARRIER_DEPTH`, `SPEND_CARRIER_DEPTH` and `BOND_CARRIER_DEPTH` are DELETED (2026-09-30). Each was 0 — the
/// spend, burn and welded bond carriers were PATHLESS since DB-74/75/DB-313 R5 — and the census of 2026-09-30 found
/// the path they parameterised DECORATIVE (its last level's output was read by no law since §BY deleted the root
/// weld). Gate D is gone from the decider: the carrier row has ONE constant layout and its prover and verifier take
/// no depth and no root, so the DB-73/74/75 class (the wallet proving at one depth while a door verified at another,
/// runs 64/83/84/86 — every real send and redeem refused at the carrier gate) is closed by construction, not by three
/// constants that had to agree. The ACCUMULATOR keeps `SPEND_TREE_DEPTH` = 64 (that is capacity); the one carrier that
/// still walks a path is the multi-input spend below, at the accumulator's depth.
/// The FULLY-PRIVATE MULTI-INPUT spend carrier (N inputs → 2 outputs, conservation in-circuit) is proven and
/// verified at the accumulator's depth (each input ∈ `spend_frontier_root`). DB-83: the block aggregate cannot
/// state it yet, so the submit door refuses it with the reason; the constant stays named for when it can.
pub const MULTI_SPEND_CARRIER_DEPTH: usize = SPEND_TREE_DEPTH;

/// A note-commitment leaf / interior digest: canonical KoalaBear limbs (each in `[0, p)`).
///
/// ⛔⛔⛔ WAS FOUR LIMBS UNTIL 2026-09-12 (kill list §AG). Four KoalaBear limbs are 4 × 31 = 124 bits ⇒
/// 62-bit collision resistance — roughly 46,000 GPU-days to collide two subtrees and prove a spent note
/// unspent. Eight are 248 bits ⇒ 124-bit, the width `work_target_air` already uses. The name is kept so
/// the ~360 call sites that merely CARRY a digest are untouched; the width lives in ONE place, and it is
/// the compression's.
pub type Digest4 = usdm_decider::poseidon2_compress::Digest;

#[inline]
fn kb_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    if s >= KB_P {
        s - KB_P
    } else {
        s
    }
}
#[inline]
fn kb_mul(a: u64, b: u64) -> u64 {
    // ⭐ SAME VALUE, HARDWARE-WIDTH ARITHMETIC. (a·b) mod p ≡ ((a mod p)·(b mod p)) mod p for any
    // a, b — the modular-arithmetic identity — and with both factors reduced below p < 2³¹ the
    // product fits a u64 exactly (2³¹·2³¹ = 2⁶² < 2⁶⁴), so the reduction is one hardware `udiv`
    // instead of the compiler-builtin SOFTWARE u128 division the old `(a as u128 * b as u128) %
    // KB_P as u128` emitted.
    // ROOT-LAYER: this is the one multiply every Poseidon-pair limb goes through — every spine
    // fold, block root, unspent-subtree and copath in the tree reads what this line computes, so
    // the width choice is made here, never at any caller.
    // MEASURED: 2026-09-06, 10 s `sample` of the rolling-restart pin (scratchpad/s1a-sample.txt):
    // `u128_div_rem` 3,297 + `__umodti3` 937 top-of-stack samples — the single hottest leaf in the
    // whole run, ahead of the Poseidon permutation itself (519) — every one of them under this
    // function -> zero u128 division on the fold path.
    // MUST-STAY-GREEN: every Poseidon digest in the suite (spend_frontier round-trips, the
    // canonical_record_fold suite, wallet↔node root agreement) — the output value is bit-identical
    // by the identity above, so any digest change at all is a defect in this line.
    // cons: none — no new state, the same value, strictly fewer cycles.
    ((a % KB_P) * (b % KB_P)) % KB_P
}

/// The chain's compression: ONE Poseidon2 permutation over `left ‖ right`, truncated.
///
/// ⛔⛔⛔ THIS WAS A SINGLE ALGEBRAIC ROUND UNTIL 2026-09-12, and it was forgeable in about a millisecond.
/// `out = MDS·(l + 7·r)⁷`: `x ↦ x⁷` is a bijection over KoalaBear, `SPEND_MDS` is invertible, and
/// `l + 7·r` is linear in two unknowns — so a sibling could be SOLVED rather than found
/// (`sib = ((MDS⁻¹·target)^{1/7} − node)/7`), and every non-membership copath in the chain was forgeable.
/// MEASURED on this very function by `sparse_fold_forgery_pin`: a nullifier the accumulator had already
/// settled as SPENT read `Unspent`, and `verify_and_insert` then settled the double-spend. Kill list §AG.
///
/// The body delegates to `usdm_decider::poseidon2_compress::compress` so there is ONE compression in the
/// tree and this is a name for it, not a second implementation that can drift from the circuit.
#[must_use]
pub fn poseidon_pair(left: Digest4, right: Digest4) -> Digest4 {
    #[cfg(test)]
    NODE_PAIR_HASHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    usdm_decider::poseidon2_compress::compress(&left, &right)
}

/// TEST-ONLY: every node-side pair compression in this process (the simulator's speed census reads it).
#[cfg(test)]
pub static NODE_PAIR_HASHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Unpack a 32-byte on-chain value into a Poseidon leaf.
///
/// ⛔⛔⛔ THIS IS A HASH, NOT A DECODE, AND THE DIFFERENCE IS A COLLISION.
/// The old body read four little-endian u64s and reduced each mod p — total, but NOT injective: `0` and
/// `p` are distinct byte strings that named the same leaf. Callers hand this every kind of 32-byte value
/// (roots, fold accumulators, note commitments, foreign ids), and most of those are not a canonical
/// 8 × 31-bit digest encoding at all, so a decoder here would refuse perfectly good input. Compression
/// gives a total map that is collision-resistant instead.
///
/// For a value the chain itself PRODUCED and that must round-trip, use
/// [`usdm_decider::poseidon2_compress::digest_from_bytes`] / [`leaf_to_cm_bytes`], which are inverses.
#[must_use]
pub fn cm_bytes_to_leaf(cm: &[u8; 32]) -> Digest4 {
    usdm_decider::poseidon2_compress::hash32_to_digest(cm)
}

/// ⭐⭐⭐ THE ONE DEFINITION OF A NOTE'S LEAF — its position in the DA record tree and in the global
/// spend frontier. A note's front 32 bytes ARE its commitment in the canonical digest form
/// (`leaf_to_cm_bytes(cm)`, which every producer in this tree writes and [`note_cm_of`] reads back), so
/// **a note's leaf IS its commitment.**
///
/// ⛔⛔⛔ THIS USED TO BE [`cm_bytes_to_leaf`] — A HASH — AND THAT WAS KILL LIST §AO.
///
/// A note then had TWO identities: its commitment `cm`, and `hash(leaf_to_cm_bytes(cm))`. The spend
/// CROSS-BIND is `leaf_commit = Poseidon(leaf, nullifier)`, and it was computed from a DIFFERENT ONE on
/// each side — the validity carrier from the note's OPENING, the membership carrier from the RECORD LEAF:
/// ```text
/// validity   lc = Poseidon(cm,          nf)
/// membership lc = Poseidon(hash(cm_b),  nf)
/// ```
/// Both proofs honest; about different objects. So **no honest spender could satisfy both halves**, and
/// every spend class that proves membership with a `NoteMembershipCarrier` was refused — the asset
/// transfer and the bond/stake admission alike. Fail-closed, so never an inflation hole; it cost
/// LIVENESS. MEASURED on both paths before this changed.
///
/// ⭐ THE FALLBACK IS NOT A SECOND SPELLING. A front that is not a canonical digest is not a commitment
/// this chain ever made, so that note has no opening and can NEVER be spent — `note_cm_of` returns `None`
/// for it and every door refuses it. It still needs a deterministic, distinct position in the tree so the
/// record's shape is identical on every node, and the hash gives it exactly that. Every SPENDABLE note
/// takes the injective decode, which is the one spelling that has to agree with the circuits.
/// ⭐ THE LEAF COUNT AT WHICH THE MERGE COMPLETING `index`'s LEVEL-`l+1` ANCESTOR LANDS — `((index >> (l+1)) + 1) << (l+1)`,
/// the one spelling every reader uses (the witness's rewind, the member book's wants). Computed in `u128`, where shifting by
/// the full width is defined: at the top level (`l = SPEND_TREE_DEPTH - 1 = 63`) the `u64` form shifted by 64, which panics
/// in a debug build and is masked to a shift by 0 in a release build. MEASURED 2026-11-16 (lane af58): the debug test binary
/// panicked `attempt to shift right with overflow` in `MemberWitnessBook::wants_in` the first time a pin asked a note's high
/// wants (`defi_batch::pins::br15_an_order_settles_by_audit…`). At level 63 the answer is 2^64, past any leaf count.
#[must_use]
pub fn ancestor_completes_at(index: u64, l: usize) -> u128 {
    ((u128::from(index) >> (l + 1)) + 1) << (l + 1)
}

#[inline]
#[must_use]
pub fn note_leaf_of(cm: &[u8; 32]) -> Digest4 {
    cm_bytes_to_root(cm).unwrap_or_else(|| cm_bytes_to_leaf(cm))
}

/// The domain-separated empty leaf — a position never occupied by a real note. Matches the wallet's
/// `poseidon_empty_leaf()` (the all-zero digest), so the empty-tail padding is identical on both sides.
#[inline]
#[must_use]
pub fn empty_leaf() -> Digest4 {
    usdm_decider::poseidon2_compress::zero_digest()
}

/// Serialize a Poseidon leaf to its canonical 32-byte on-chain form — 8 lanes × 31 bits, LSB-first.
/// ⭐⭐⭐ THE INVERSE OF [`leaf_to_cm_bytes`], FOR A VALUE THE CHAIN ITSELF PRODUCED.
///
/// ⛔⛔⛔ A ROOT ROUND-TRIPPED THROUGH [`cm_bytes_to_leaf`] IS NOT THAT ROOT. Before kill list §AG the
/// two were a matching encode/decode pair (four little-endian u64s, each reduced mod p), so
/// `cm_bytes_to_leaf(leaf_to_cm_bytes(x)) == x` and every call site could use either. §AG made
/// `cm_bytes_to_leaf` a **HASH** — its own doc says so in capitals, because it must stay total over the
/// arbitrary 32-byte ids callers hand it (note commitments, foreign ids, nullifiers) — and the inverse
/// pair became `digest_from_bytes` / `digest_to_bytes`. Every site that was round-tripping a ROOT kept
/// compiling and started returning a hash of the root instead of the root.
///
/// MEASURED 2026-09-13: `SparseNfAcc::adopt_merkle_root` did exactly this, so a DSYNC-jumped node
/// installed `hash(the served root)` as its sparse double-spend gate. No honest copath can ever fold to
/// that value, so every spend the joiner checks reads unprovable — and its gate silently disagrees with
/// the chain it just joined. `two_nodes_instant_sync_roundtrip_serve_then_adopt` caught it as
/// "B inherited A's certified SPARSE spent-state" with two different 32-byte values.
///
/// ⛔ FAIL-CLOSED, AND THAT IS THE POINT OF RETURNING `Option`. A root the chain produced is always a
/// canonical 8×31-bit digest. A 32-byte value that is NOT one did not come from this chain — it is
/// forged, corrupt, or from before the fork — and there is no digest it "means". Reducing it into range
/// would launder it into a root nothing else can reproduce, which is the same laundering the frontier's
/// own decoder refuses slot by slot.
///
/// ⭐ USE THIS FOR ROOTS AND ACCUMULATORS; use [`cm_bytes_to_leaf`] for arbitrary ids. The two are not
/// interchangeable any more and the compiler cannot tell them apart — only the call site knows which
/// kind of 32 bytes it is holding.
#[must_use]
pub fn cm_bytes_to_root(b: &[u8; 32]) -> Option<Digest4> {
    usdm_decider::poseidon2_compress::digest_from_bytes(b)
}

/// INJECTIVE: distinct canonical digests never share a byte form.
#[must_use]
pub fn leaf_to_cm_bytes(leaf: Digest4) -> [u8; 32] {
    usdm_decider::poseidon2_compress::digest_to_bytes(&leaf)
}

/// Bytes a note's commitment occupies at the front of its payload: the canonical 32-byte digest form.
///
/// ⛔⛔⛔ ONE NOTE-COMMITMENT ENCODING (kill list §AG failure class 9, closed 2026-09-13). Every producer
/// of a note in this tree — the faucet, the order book's payout notes, the fill's three notes — writes
/// `leaf_to_cm_bytes(cm)` into `note[..NOTE_CM_BYTES]`, and the account-target index keys on exactly
/// those 32 bytes. Four READERS (the wrapped-mint credit gate, the asset-spend output reader, the
/// custodian peg-in credit, the sovereign token-create fee gate) had kept the PRE-§AG spelling — `DIGEST_LANES`
/// little-endian u64s, which coincided with this form at four lanes and became a 64-byte read of a
/// different encoding at eight. That is a second encoding of one consensus object: a note the faucet
/// sealed could not open its own mint carrier at those doors, and a 32..63-byte note PANICKED them.
pub const NOTE_CM_BYTES: usize = 32;

/// TEST FIXTURE — a 32-byte filler that IS a canonical digest encoding: `x` repeated over bytes 0..31 and byte 31
/// zero (the encoding is 8 lanes × 31 bits = 248 bits; byte 31 lies outside it and must be 0 — `digest_from_bytes`).
/// A repeating byte never forms seven consecutive set bits, so every lane stays below the KoalaBear modulus.
#[cfg(test)]
#[must_use]
pub fn canonical_filler_bytes(x: u8) -> [u8; 32] {
    let mut out = [x; 32];
    out[31] = 0;
    out
}

/// The commitment a note carries, read exactly as every producer wrote it — [`leaf_to_cm_bytes`] into
/// `note[..NOTE_CM_BYTES]` — through the injective decoder, so the digest recovered IS the digest the
/// carrier welded. `None` on a payload too short to hold a commitment, or one whose front is not a
/// canonical digest: a credit gate must never bind against an invented cm, and a non-canonical front is
/// not an alternative spelling of some commitment — it is malformed and is refused.
#[must_use]
pub fn note_cm_of(note_payload: &[u8]) -> Option<Digest4> {
    let front = note_payload.get(..NOTE_CM_BYTES)?;
    let arr: [u8; NOTE_CM_BYTES] = front.try_into().ok()?;
    cm_bytes_to_root(&arr)
}

/// Bytes a digest occupies as RAW LANES on the wire: every lane, little-endian, `8 × DIGEST_LANES`.
///
/// ⛔⛔⛔ THIS IS THE FORM FOR A VALUE THAT IS NOT A CANONICAL DIGEST. The note-membership accumulator
/// is a wrapping 512-bit SUM of leaves (`note_membership_step_new_acc`): its limbs exceed the field after
/// two folds, so the injective 31-bit-per-lane form ([`leaf_to_cm_bytes`]) would silently reduce them
/// and two accumulators would share a byte form. Raw lanes are lossless for any `[u64; DIGEST_LANES]`.
/// The membership family — the served start/prev/root/acc, the fold transition, the roots page, and
/// the tip a spend carries — travels in this ONE form so a wallet decodes the whole family with one
/// function and no slot in a packed tip can be a different width from its neighbour.
///
/// Sized by the lane count and never a literal: kill list §AG failure class 9 was exactly a literal
/// `[0u8; 32]` written eight lanes deep — `range end index 40 out of range for slice of length 32` on
/// `/get_nf_unspent_acc`, `/membership_transition`, `/get_membership_acc` and `/membership_roots`.
pub const DIGEST_LANE_BYTES: usize = 8 * usdm_decider::poseidon2_compress::DIGEST_LANES;

/// A digest → its raw-lane wire form. Total over every `[u64; DIGEST_LANES]`; see [`DIGEST_LANE_BYTES`].
#[must_use]
pub fn digest_to_lane_bytes(d: &Digest4) -> [u8; DIGEST_LANE_BYTES] {
    let mut out = [0u8; DIGEST_LANE_BYTES];
    for (lane, limb) in d.iter().enumerate() {
        out[lane * 8..lane * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Raw-lane wire bytes → the digest, or `None` unless the length is EXACTLY [`DIGEST_LANE_BYTES`].
/// A short buffer is refused, never zero-padded: a lane that silently reads as zero is the other half
/// of failure class 9 (a value that is quietly half-width).
#[must_use]
pub fn digest_from_lane_bytes(b: &[u8]) -> Option<Digest4> {
    if b.len() != DIGEST_LANE_BYTES {
        return None;
    }
    let mut out = usdm_decider::poseidon2_compress::zero_digest();
    for (lane, slot) in out.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[lane * 8..lane * 8 + 8]);
        *slot = u64::from_le_bytes(w);
    }
    Some(out)
}

/// Append-only Poseidon note-membership accumulator (MMR): one pending left-subtree hash per level + the
/// leaf count. O(DEPTH) memory + O(DEPTH) append; the fixed-DEPTH root pads the empty tail deterministically.
#[derive(Clone, Debug)]
pub struct PoseidonSpendFrontier {
    /// `pending[l]` = the completed left-subtree hash at level `l` awaiting a right sibling (`None` if none).
    pending: Vec<Option<Digest4>>,
    /// Number of leaves appended so far.
    count: u64,
}

/// Fixed-width, height-invariant wire length: 8-byte big-endian `count` + `(DEPTH+1)` fixed 32-byte slots
/// (each `Digest4` = four 8-byte big-endian limbs).
const SPEND_FRONTIER_WIRE_LEN: usize = 8 + (SPEND_TREE_DEPTH + 1) * 32;

// TRUE CONSTANT SIZE (no-growth pillar) — see the twin doc on `crate::frontier::NoteFrontier`. Serializes to the
// SAME byte-length at every count: 8-byte BE `count` + `(DEPTH+1)` fixed 32-byte slots (ZERO-padded when empty).
// Occupied slots are exactly the set bits of `count` (MMR invariant) so decode needs no discriminant/varint.
// Wire/disk form only; `append()`/`root()` and every consensus value are untouched.
impl serde::Serialize for PoseidonSpendFrontier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; SPEND_FRONTIER_WIRE_LEN];
        buf[..8].copy_from_slice(&self.count.to_be_bytes());
        for (l, slot) in self.pending.iter().enumerate().take(SPEND_TREE_DEPTH + 1) {
            if let Some(d) = slot {
                let off = 8 + l * 32;
                buf[off..off + 32].copy_from_slice(&leaf_to_cm_bytes(*d));
            }
        }
        serializer.serialize_bytes(&buf)
    }
}

impl<'de> serde::Deserialize<'de> for PoseidonSpendFrontier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SpendFrontierVisitor;
        impl<'de> serde::de::Visitor<'de> for SpendFrontierVisitor {
            type Value = PoseidonSpendFrontier;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("fixed-width PoseidonSpendFrontier bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                b: &[u8],
            ) -> Result<PoseidonSpendFrontier, E> {
                if b.len() != SPEND_FRONTIER_WIRE_LEN {
                    return Err(E::custom("bad PoseidonSpendFrontier wire length"));
                }
                let mut c = [0u8; 8];
                c.copy_from_slice(&b[..8]);
                let count = u64::from_be_bytes(c);
                let mut pending = vec![None; SPEND_TREE_DEPTH + 1];
                for (l, slot) in pending.iter_mut().enumerate() {
                    // Level 64's peak would need exactly 2^64 leaves — unrepresentable in a u64
                    // count, so that slot is always empty; unguarded, `count >> 64` is a shift
                    // overflow (see `from_peaks_hex`, the measured twin of this line).
                    if (l as u32) < u64::BITS && (count >> l) & 1 == 1 {
                        let off = 8 + l * 32;
                        let mut sb = [0u8; 32];
                        sb.copy_from_slice(&b[off..off + 32]);
                        // A slot the count says is OCCUPIED must decode: a non-canonical encoding is a
                        // malformed frontier, not a different one, and reducing it would launder it into
                        // a root nothing else can reproduce.
                        *slot = Some(
                            usdm_decider::poseidon2_compress::digest_from_bytes(&sb)
                                .ok_or_else(|| E::custom("non-canonical frontier digest"))?,
                        );
                    }
                }
                Ok(PoseidonSpendFrontier { pending, count })
            }
        }
        deserializer.deserialize_bytes(SpendFrontierVisitor)
    }
}

impl Default for PoseidonSpendFrontier {
    fn default() -> Self {
        Self {
            pending: vec![None; SPEND_TREE_DEPTH + 1],
            count: 0,
        }
    }
}

impl PoseidonSpendFrontier {
    /// A frontier of an EXPLICIT depth. Production always uses [`SPEND_TREE_DEPTH`] via [`Self::new`]; this
    /// exists so the CAPACITY BOUNDARY is reachable in a test at all. At the production depth it is 2^32
    /// appends — unreachable — which is precisely why the behaviour at that boundary went unexamined until
    /// now, and why it was able to be silently wrong. A limit nobody can test is a limit nobody has checked.
    /// Leaves this frontier can hold: `2^depth`. Beyond it there is nowhere to park a carry.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        let depth = self.pending.len().saturating_sub(1);
        if depth >= 64 {
            u64::MAX
        } else {
            1u64 << depth
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Leaves appended so far (= the next leaf's index).
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Number of pending peak SLOTS retained in RAM — one per MMR level, bounded by `SPEND_TREE_DEPTH + 1`
    /// REGARDLESS of the leaf count. The direct, concurrency-immune witness that the spend frontier is
    /// O(DEPTH) memory, not O(leaves).
    pub fn peak_slots(&self) -> usize {
        self.pending.len()
    }

    /// Append one ALIGNED subtree of `level` (a node covering `1 << level` leaves) — the same carry walk as
    /// `append`, entered at `level`. Refused (false, state untouched) when the count is not aligned to the
    /// subtree (a subtree cannot straddle a boundary) or the accumulator would exceed capacity. A record is
    /// one depth-8 subtree, so a verifier can fold a run of record ROOTS without rehashing the leaves.
    pub fn append_subtree(&mut self, level: usize, node: Digest4) -> bool {
        self.append_subtree_with(level, node, |_, _, _| {})
    }

    /// [`Self::append_subtree`], handing `on_merge(level, left, right)` the two COMPLETED windows of every merge the
    /// carry walk makes (levels `level..`), as [`Self::append_with`] does for a leaf — so a fold of record ROOTS yields
    /// the same windows a fold of their leaves does at every level at or above the record's (DB-418).
    pub fn append_subtree_with(&mut self, level: usize, node: Digest4, mut on_merge: impl FnMut(usize, Digest4, Digest4)) -> bool {
        let depth = self.pending.len().saturating_sub(1);
        // ⛔ `1u64 << level` IS NOT A SAFE WIDTH HERE. `depth` is `SPEND_TREE_DEPTH` = 64, so the guard below
        // admits `level == 64`, and a 64-bit shift by 64 is MASKED to a shift by 0 in release — `width` would
        // come back as 1, the alignment test would pass for any count, and the frontier would advance by one
        // leaf while claiming a whole top subtree. Same class as the stale root this depth bump caused in
        // `nullifier_tree` (see the note on `subtree_index` there). A width that cannot be represented is a
        // subtree this frontier cannot hold, so it is REFUSED rather than silently reinterpreted.
        let Some(width) = 1u64.checked_shl(level as u32) else {
            return false;
        };
        if level > depth || self.count % width != 0 || self.count.saturating_add(width) > self.capacity() {
            return false;
        }
        let mut cur = node;
        let mut l = level;
        while l <= depth {
            match self.pending[l].take() {
                Some(left) => {
                    on_merge(l, left, cur); // `left` and `cur` are the two COMPLETED windows at level `l`
                    cur = poseidon_pair(left, cur);
                    l += 1;
                }
                None => {
                    self.pending[l] = Some(cur);
                    break;
                }
            }
        }
        self.count += width;
        true
    }

    /// Exact state equality: same leaf count and the same pending node at every level.
    pub fn same_state(&self, other: &Self) -> bool {
        self.count == other.count && self.pending == other.pending
    }

    /// The O(DEPTH) peak spine as hex — 8-byte BE `count` ‖ `(DEPTH+1)` fixed 32-byte peak slots (zero-padded
    /// where empty; occupied slots are exactly the set bits of `count`, the MMR invariant). This is the
    /// no-growth membership anchor a wallet self-builds its note's copath against (the note-side analog of the
    /// nullifier witness): the node NEVER serves the O(n) leaf set — a spender combines its own caught block +
    /// these peaks to recompute exactly `root()`. Byte-identical to the `serde` wire form; height-invariant.
    pub fn peaks_hex(&self) -> String {
        let mut buf = vec![0u8; SPEND_FRONTIER_WIRE_LEN];
        buf[..8].copy_from_slice(&self.count.to_be_bytes());
        for (l, slot) in self.pending.iter().enumerate().take(SPEND_TREE_DEPTH + 1) {
            if let Some(d) = slot {
                let off = 8 + l * 32;
                buf[off..off + 32].copy_from_slice(&leaf_to_cm_bytes(*d));
            }
        }
        buf.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Rebuild the peak spine from `peaks_hex` (wallet side). `None` on a malformed length so a spender fails
    /// closed rather than proving against a bogus anchor. The reconstructed frontier's `root()` equals the
    /// server's spend-frontier root, so the wallet's self-built copath verifies against consensus.
    pub fn from_peaks_hex(s: &str) -> Option<Self> {
        if s.len() % 2 != 0 {
            return None;
        }
        let b: Vec<u8> = (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
            .collect::<Result<_, _>>()
            .ok()?;
        if b.len() != SPEND_FRONTIER_WIRE_LEN {
            return None;
        }
        let mut c = [0u8; 8];
        c.copy_from_slice(&b[..8]);
        let count = u64::from_be_bytes(c);
        let mut pending = vec![None; SPEND_TREE_DEPTH + 1];
        for (l, slot) in pending.iter_mut().enumerate() {
            // A peak lives at level l iff bit l of the leaf count is set. The spine carries
            // SPEND_TREE_DEPTH+1 slots, so at depth 64 the loop's last level is 64 — one past the top
            // bit of a u64 count, whose peak would require exactly 2^64 leaves, which a u64 count
            // cannot represent: that slot is always empty. Guarding the shift says so; without the
            // guard `count >> 64` is an overflow — a panic under overflow checks (every debug-profile
            // adopt/roundtrip died at this line once SPEND_TREE_DEPTH became 64) and a wrapped
            // `count >> 0` in release, which conjured a phantom level-64 peak from bit 0 whenever the
            // count was odd.
            if (l as u32) < u64::BITS && (count >> l) & 1 == 1 {
                let off = 8 + l * 32;
                let mut sb = [0u8; 32];
                sb.copy_from_slice(&b[off..off + 32]);
                // An occupied slot must decode; a non-canonical encoding is a malformed frontier, and
                // reducing it would launder it into a root nothing else can reproduce.
                *slot = Some(usdm_decider::poseidon2_compress::digest_from_bytes(&sb)?);
            }
        }
        Some(PoseidonSpendFrontier { pending, count })
    }

    /// Append one note-commitment leaf — O(DEPTH). Carries up like a binary counter.
    /// Append one note leaf. Returns `false` iff the frontier is FULL and the leaf was NOT accepted.
    ///
    /// ⛔⛔⛔ THIS USED TO DESTROY THE LEAF IN SILENCE. The carry loop was bounded by `SPEND_TREE_DEPTH` with
    /// no capacity check: once every `pending` slot is occupied, the carry runs past the top, the loop
    /// condition fails, and the function returns **without ever parking `cur`** — while `count += 1` still
    /// ran. The frontier reported accepting a note it had dropped on the floor. No panic, no `Err`, no log:
    /// a receive would look successful and the money would not exist. That is silent FUND LOSS, and it lands
    /// on the longest-lived chain first.
    ///
    /// PROVEN, not argued: `a_full_frontier_refuses_the_leaf_loudly_instead_of_destroying_it` drives a
    /// depth-4 frontier to its 16-leaf capacity and appends a 17th.
    ///
    /// This does NOT remove the capacity ceiling — that needs the append side to stop depending on a
    /// fixed-capacity structure at all ([[feedback_tree_lifetime_infinite_no_capacity_window]]). It converts
    /// silent destruction into a refusal, and an honest `count`. A refusal is a real answer; a dropped note
    /// is not.
    ///
    /// cons: none — one comparison per append, f(fixed constants), no allocation and no new state.
    pub fn append(&mut self, leaf: Digest4) -> bool {
        self.append_with(leaf, |_, _, _| {})
    }

    /// ⭐ DB-223 Q2 — [`Self::append`], reporting every MERGE its carry walk makes as `(level, left, right)`: the roots
    /// of the two level-`level` windows this very append completed and combined — the RIGHT child
    /// `[count' − 2^level, count')` (an ODD window) and its LEFT sibling just before it (EVEN), `count'` being the count
    /// after the append. Both leave the frontier the moment the walk merges them, and this is the one instant they can
    /// be captured (the path-refresh index's entries: a refreshing wallet needs the right ones, a restoring wallet that
    /// never captured its path at arrival needs the left ones too — Q2 §9 item 5, both stored). ONE walk: the plain
    /// `append` is this with a no-op, so the two can never disagree about the tree.
    pub fn append_with(&mut self, leaf: Digest4, mut on_merge: impl FnMut(usize, Digest4, Digest4)) -> bool {
        // Derive the ceiling from the ALLOCATION, so any frontier behaves identically to
        // a production one. At production depth `pending.len() - 1 == SPEND_TREE_DEPTH`, unchanged.
        let depth = self.pending.len().saturating_sub(1);
        if self.count >= self.capacity() {
            eprintln!(
                "[spend-frontier] REFUSED a note append: the accumulator is at its {} -leaf capacity. The \
                 note was NOT accepted and the count was NOT advanced — this refusal exists because the \
                 alternative was destroying the leaf in silence.",
                self.capacity()
            );
            return false;
        }
        let mut cur = leaf;
        let mut level = 0;
        while level <= depth {
            match self.pending[level].take() {
                Some(left) => {
                    on_merge(level, left, cur); // `left` and `cur` are the two COMPLETED windows at `level`
                    cur = poseidon_pair(left, cur); // we are the right sibling — combine, carry up
                    level += 1;
                }
                None => {
                    self.pending[level] = Some(cur); // park as a left sibling here and stop
                    break;
                }
            }
        }
        self.count += 1;
        true
    }

    /// The current fixed-DEPTH Poseidon root — folds the pending frontier against an empty-subtree ladder.
    /// Equals the depth-32 sparse root over the appended leaves (positions `[count, 2^32)` = empty leaf),
    /// which is exactly what a wallet's `poseidon_frontier_copath` recomputes to. Consensus-uniform.
    pub fn root(&self) -> Digest4 {
        // empty[l] = hash of an all-empty subtree at level l (empty[0] = the empty leaf).
        let mut empty = [usdm_decider::poseidon2_compress::zero_digest(); SPEND_TREE_DEPTH + 1];
        // Derive the height from the ALLOCATION, exactly as `append` does, so a frontier and its own root
        // always describe the SAME tree. Hard-coding `SPEND_TREE_DEPTH` here while `append` used the
        // allocation was a second definition of the tree's height — the defect family that produced the
        // `ordinal x 256` leaf-index failure. At production depth `pending.len() - 1 == SPEND_TREE_DEPTH`,
        // so this is byte-identical for every real frontier and changes no consensus value.
        let depth = self.pending.len().saturating_sub(1).min(SPEND_TREE_DEPTH);
        empty[0] = empty_leaf();
        for l in 1..=depth {
            empty[l] = poseidon_pair(empty[l - 1], empty[l - 1]);
        }
        // fold the completed left siblings over the empty-tail node.
        let mut node = empty[0];
        for l in 0..depth {
            node = match self.pending[l] {
                Some(left) => poseidon_pair(left, node), // completed left subtree, empty-tail as its right
                None => poseidon_pair(node, empty[l]), // empty-tail node as left, empty subtree as right
            };
        }
        node
    }

    /// The Poseidon root of a subtree of HEIGHT `level` (a `2^level`-leaf window) over the leaves appended so far,
    /// zero/empty-padded to the right. `subtree_root(SPEND_TREE_DEPTH) == root()`. This is exactly the value of a
    /// membership copath's level-`level` sibling when this frontier accumulates (IN ORDER, from that sibling's
    /// left edge) the leaves of that sibling's window — so a half-filled right sibling folds to the correct
    /// sparse subtree hash over the leaves seen so far. O(level).
    pub fn subtree_root(&self, level: usize) -> Digest4 {
        // Window EXACTLY full (2^level leaves accumulated ⇒ only bit `level` set): the single completed peak IS
        // the height-`level` root (also the level==0 single-leaf case, where the leaf lives in `pending[0]`).
        if let Some(full) = self.pending.get(level).copied().flatten() {
            return full;
        }
        // Otherwise fold the completed sub-peaks `pending[0..level]` over the empty-subtree tail (the memoized empty roots).
        let mut node = empty_subtree_root(0);
        for l in 0..level {
            node = match self.pending.get(l).copied().flatten() {
                Some(left) => poseidon_pair(left, node),
                None => poseidon_pair(node, empty_subtree_root(l)),
            };
        }
        node
    }

    /// PATH A helper — the sparse Poseidon root of the frontier's RIGHTMOST, currently-partial level-`level` window
    /// `[⌊count/2^level⌋·2^level, count)`, over ONLY the sub-level carries `pending[0..level]` (empty-padded to the
    /// right). Unlike [`subtree_root`] this NEVER returns the `pending[level]` shortcut (a *left/completed* level
    /// subtree) — it always folds the recent tail, which is exactly a note's LIVE sibling window when the note's
    /// level-`level` sibling window is the frontier's current one (`⌊count/2^level⌋ == (index>>level)^1`).
    /// ⭐⭐⭐ THE COMPLETED LEFT SIBLING AT `level` — I.E. THE MMR PEAK. THE SPENDER'S OWN WITNESS.
    ///
    /// user 2026-07-30: *"lets make the spender hold its own witness"* / *"we dont need to reconstruct the
    /// full history on demand then. How does mina handle this"*.
    ///
    /// MEASURED, and it corrected my own wrong claim: a note ONE BLOCK old (ordinal 150688, tip 150689) still
    /// needed level 14 — the completed span `[131072..147456)`. Only the siblings to a note's RIGHT are empty;
    /// every note needs the completed subtrees to its LEFT, which is all prior history. That is why "freeze at
    /// receipt" alone did not help and why the node was being asked to rebuild 16,384 blocks.
    ///
    /// But those left subtrees are EXACTLY the MMR peaks. At 150,688 blocks the decomposition is
    /// `2^17 + 2^14 + 2^11 + 2^10 + 2^7 + 2^5`, and `[131072..147456)` IS the 2^14 peak. So the whole upper
    /// copath is already in the 1,064-byte peak spine the node serves to everyone — no history, no ladder, no
    /// per-record retention. A spender fetches the peaks once at receipt and holds its own witness forever
    /// after, which is the Mina division of labour in our append-only shape.
    ///
    /// `None` = no peak occupied at this level (that side of the tree is empty, so the caller uses the empty
    /// subtree root). Fail-closed: this never invents a value.
    pub fn peak_at(&self, level: usize) -> Option<Digest4> {
        self.pending.get(level).copied().flatten()
    }

    pub fn frontier_partial_span_root(&self, level: usize) -> Digest4 {
        let mut empty = vec![usdm_decider::poseidon2_compress::zero_digest(); level + 1];
        empty[0] = empty_leaf();
        for l in 1..=level {
            empty[l] = poseidon_pair(empty[l - 1], empty[l - 1]);
        }
        let mut node = empty[0];
        for l in 0..level {
            node = match self.pending.get(l).copied().flatten() {
                Some(left) => poseidon_pair(left, node),
                None => poseidon_pair(node, empty[l]),
            };
        }
        node
    }
}

/// The wallet's SELF-BUILT membership witness for ONE owned note at leaf `index` — the note-side analog of the
/// nullifier `InsertWitness`, and the fix for "owned note not yet in the served frontier" under the O(1) no-store
/// node. It is TRUSTLESS + NO-GROWTH: the wallet never fetches the O(n) leaf set. Instead, for each depth level it
/// keeps a small accumulator of the target's sibling-window leaves as they stream by in served blocks, and
/// `authpath()` recomputes EXACTLY `PoseidonSpendFrontier::root()` — so the WHIR spend proves membership against
/// live consensus. The left (already-complete) siblings are captured once from the served O(DEPTH) peaks at catch
/// (`capture_left_from_peaks`), so the wallet never replays pre-catch history; the right siblings fill as later
/// blocks append (`observe`). O(DEPTH²) digests per owned note (phone-class: a few KB), O(DEPTH)/appended leaf.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IncrementalWitness {
    index: u64,
    leaf: Digest4,
    /// `acc[l]` accumulates, IN ORDER from the window's left edge, the leaves in the target's level-`l` sibling
    /// window `[sib_start(l), sib_start(l)+2^l)`; the sibling = `acc[l].subtree_root(l)` (empty-padded ⇒ a
    /// half-filled right sibling folds to the correct sparse subtree).
    acc: Vec<PoseidonSpendFrontier>,
    /// A completed, IMMUTABLE left-sibling subtree root, captured once from the served peaks at catch. `Some`
    /// overrides `acc[l]` (the wallet never re-derives a left sibling from history).
    captured: Vec<Option<Digest4>>,
}

/// The left edge of the target's level-`l` sibling window: `((index >> l) ^ 1) << l`.
#[inline]
fn sib_span_start(index: u64, l: usize) -> u64 {
    ((index >> l) ^ 1) << l
}

impl IncrementalWitness {
    /// Start a witness for the note at `index` with value `leaf`. Feed it the target's own block via `observe`
    /// (right siblings) and capture the left siblings from the peaks at catch.
    pub fn new(index: u64, leaf: Digest4) -> Self {
        Self {
            index,
            leaf,
            acc: (0..SPEND_TREE_DEPTH)
                .map(|_| PoseidonSpendFrontier::new())
                .collect(),
            captured: vec![None; SPEND_TREE_DEPTH],
        }
    }

    /// Observe an appended leaf at absolute index `j` (any leaf the wallet sees stream by in a served block —
    /// its own block's other notes + every later block's notes). Routes it into every sibling window it falls in.
    /// The target leaf itself (`j == index`) contributes to nothing (it is not its own sibling) and is ignored.
    pub fn observe(&mut self, j: u64, leaf: Digest4) {
        if j == self.index {
            return;
        }
        for l in 0..SPEND_TREE_DEPTH {
            let s = sib_span_start(self.index, l);
            let end = s.saturating_add(1u64 << l);
            if j >= s && j < end {
                self.acc[l].append(leaf);
            }
        }
    }

    /// Capture the already-complete LEFT siblings from the served peak spine at catch (the frontier at
    /// `count == index`, i.e. just before the target is appended). The MMR invariant: the peaks of the frontier
    /// at `count == index` are EXACTLY the left siblings of the (about-to-be-appended, rightmost) target's path —
    /// `peaks.pending[l]` is the level-`l` left sibling for every `l` where bit `l` of `index` is set. Immutable
    /// thereafter (append-only), so the wallet stores them once and never touches pre-catch history again.
    pub fn capture_left_from_peaks(&mut self, peaks_at_catch: &PoseidonSpendFrontier) {
        debug_assert_eq!(
            peaks_at_catch.count(),
            self.index,
            "peaks must be the frontier at count==index"
        );
        for l in 0..SPEND_TREE_DEPTH {
            if (self.index >> l) & 1 == 1 {
                self.captured[l] = peaks_at_catch.pending.get(l).copied().flatten();
            }
        }
    }

    /// The depth-`SPEND_TREE_DEPTH` copath `(siblings, is_target_right_child_per_level)` — the exact witness a
    /// spend feeds the membership gate. `dir[l] == true` ⇒ the target sits on the RIGHT at level `l`, sibling on
    /// the left.
    pub fn authpath(&self) -> (Vec<Digest4>, Vec<bool>) {
        let mut sibs = Vec::with_capacity(SPEND_TREE_DEPTH);
        let mut dirs = Vec::with_capacity(SPEND_TREE_DEPTH);
        for l in 0..SPEND_TREE_DEPTH {
            let sib = self.captured[l].unwrap_or_else(|| self.acc[l].subtree_root(l));
            sibs.push(sib);
            dirs.push((self.index >> l) & 1 == 1);
        }
        (sibs, dirs)
    }

    /// Recompute the frontier root from the leaf + copath — MUST equal the node's live `spend_frontier_root()` for
    /// the spend to verify. This is the wallet's self-check before it broadcasts (fail-closed if it drifts).
    pub fn root(&self) -> Digest4 {
        let (sibs, dirs) = self.authpath();
        let mut node = self.leaf;
        for l in 0..SPEND_TREE_DEPTH {
            node = if dirs[l] {
                poseidon_pair(sibs[l], node) // target on the right
            } else {
                poseidon_pair(node, sibs[l]) // target on the left
            };
        }
        node
    }

    /// FUND-SPENDABILITY-FOREVER (cardinal: no user ever loses funds; every owned note is spendable regardless of
    /// how many blocks/how much time passes). Build a witness DIRECTLY from a served/reconstructed O(DEPTH) copath —
    /// the trustless cold-restore / evicted-gap / fresh-device path. A wallet that lost its running witness (fresh
    /// seed-only restore) or fell behind the served window installs the copath a DA serve produced for its note's
    /// `index`, captures ALL siblings immutably, and then self-verifies `root()` equals the node's live
    /// `spend_frontier_root` BEFORE trusting it (a forged/stale copath fails-closed — never a wrong frontier, never a
    /// forged spend). This is what makes membership RECONSTRUCTABLE from replicated DA + verified against the O(1)
    /// root: by construction, an owned note can never become unspendable while the chain's DA is available.
    /// `dirs` MUST match `index`'s bit pattern (the copath is for THIS leaf) — a mismatched copath is rejected.
    pub fn from_copath(index: u64, leaf: Digest4, sibs: &[Digest4], dirs: &[bool]) -> Option<Self> {
        if sibs.len() != SPEND_TREE_DEPTH || dirs.len() != SPEND_TREE_DEPTH {
            return None;
        }
        for l in 0..SPEND_TREE_DEPTH {
            if dirs[l] != ((index >> l) & 1 == 1) {
                return None; // copath is not for this leaf index (bit pattern mismatch) — fail-closed
            }
        }
        let mut w = Self::new(index, leaf);
        for (l, s) in sibs.iter().enumerate().take(SPEND_TREE_DEPTH) {
            w.captured[l] = Some(*s); // every sibling captured immutably (no history replay needed)
        }
        Some(w)
    }

    /// The level-`level` sibling this witness FROZE (a completed window's captured root), if any. Read-only: the ONE
    /// source the wallet's witness book reads for DB-223 Q2 L (§12d), so a restart persists levels
    /// `RECORD_LEVEL..HIGH_LEVEL` without keeping a second copy that `forget_captures_after` would have to keep in step.
    /// Cons: none, a getter.
    #[must_use]
    pub fn captured_sibling(&self, level: usize) -> Option<Digest4> {
        self.captured.get(level).copied().flatten()
    }

    /// PATH A — freeze every RIGHT-sibling window that is now COMPLETE (`window end ≤ count`) into an IMMUTABLE
    /// `captured` sibling. Once a window holds all `2^l` of its leaves its subtree root NEVER changes again
    /// (append-only), so the wallet stores it once and need NEVER re-observe those blocks. Idempotent; the wallet
    /// calls it on each sync so its owned notes accumulate frozen siblings at exponentially-spaced completion
    /// points — after which the note stays spendable across ARBITRARY offline gaps (see [`authpath_against`]).
    /// ⭐ DB-223 Q2 — take a COMPLETED right-sibling window's root from the path-refresh stream instead of observing its
    /// `2^level` leaves: `window` is the window index at `level` (`[window·2^level, (window+1)·2^level)`). Accepted only
    /// when it IS this note's level-`level` RIGHT sibling (`window == (index >> level) ^ 1` with bit `level` of the index
    /// clear) and that sibling is not frozen yet. Returns whether it was taken. Soundness never rests on it: a wrong root
    /// folds the path to a root the anchor ring does not hold, and the spend is refused (the wallet self-checks first).
    pub fn capture_completed_window(&mut self, level: usize, window: u64, root: Digest4) -> bool {
        // The sibling window at `level` is `(index >> level) ^ 1`, on EITHER side: a right sibling completes after
        // the note (the refresh), a left one before it (a restore that never captured the peaks at arrival). The
        // wallet trusts the result only if the path refolds to a ring root it holds.
        if level >= SPEND_TREE_DEPTH || window != (self.index >> level) ^ 1 || self.captured[level].is_some() {
            return false;
        }
        self.captured[level] = Some(root);
        true
    }

    /// The note's leaf index.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The note's leaf value (what [`Self::root_against`] folds up from) — for a diagnostic that names the level a path
    /// leaves the chain's tree at.
    #[must_use]
    pub fn leaf(&self) -> Digest4 {
        self.leaf
    }

    /// ⭐ DB-223 — a fold REWIND: forget every level-≥`from_level` sibling captured from a merge that completed after leaf
    /// count `after` (the merge that yields the level-`l` sibling completes the note's level-`l+1` ancestor, at leaf count
    /// `((index >> (l+1)) + 1) << (l+1)`). Those windows may have been rewritten; captures from earlier merges stand, and
    /// the forgotten ones refill from the re-folded stream (`capture_completed_window` fills only an empty level).
    pub fn forget_captures_after(&mut self, after: u64, from_level: usize) {
        for l in from_level..SPEND_TREE_DEPTH {
            let completes = ancestor_completes_at(self.index, l);
            if completes > u128::from(after) {
                self.captured[l] = None;
            }
        }
    }

    pub fn promote_full_windows(&mut self, count: u64) {
        for l in 0..SPEND_TREE_DEPTH {
            // Only RIGHT siblings grow (bit `l` of index == 0). Left siblings are immutable from catch already.
            if (self.index >> l) & 1 == 0 && self.captured[l].is_none() {
                let s = sib_span_start(self.index, l);
                let end = s.saturating_add(1u64 << l);
                if count >= end && self.acc[l].count() == (1u64 << l) {
                    self.captured[l] = Some(self.acc[l].subtree_root(l)); // window full ⇒ freeze it forever
                }
            }
        }
    }

    /// PATH A — OFFLINE-TOLERANT SPEND (cardinal: funds spendable no matter how many blocks / how much time pass;
    /// PURE self-custody; NO DA, NO history download, NO witness-server). Reconstruct the note's depth-32 copath to
    /// the CURRENT frontier's root using ONLY (a) the wallet's captured IMMUTABLE siblings (left siblings from
    /// catch + right windows frozen by [`promote_full_windows`]) and (b) the ONE live (partially-filled) sibling
    /// window, recomputed from the node's CURRENT served peaks via `current.subtree_root(l)` — plus deterministic
    /// empty roots above the tree. The wallet needs NO running frontier advanced block-by-block and need NOT have
    /// observed the blocks since it last synced: it fetches `current` (the O(DEPTH) served peaks) at spend time. So
    /// a note stays spendable after an arbitrary offline gap, provided its (bounded, exponentially-spaced) completed
    /// sibling windows were frozen while syncing. FAIL-CLOSED: `None` if a completed sibling was never captured (the
    /// wallet must sync to catch it) — NEVER a forged/guessed copath. The caller self-verifies
    /// `root_against(current) == node_spend_root` before broadcasting.
    /// Which SOURCE supplied each level's sibling in [`authpath_against`], as one char per level:
    /// `C` = frozen capture · `A` = fully-observed accumulator · `E` = empty subtree (tree has not reached it)
    /// · `L` = live partial span read from the served peaks · `?` = fail-closed (nothing available).
    ///
    /// ⛔⛔⛔ WHICH INPUT IS WRONG — THE ONE THING THE ROOT COMPARISON CANNOT SAY.
    ///
    /// MEASURED 2026-08-01: with the note's leaf index now proven correct (the book aligns to the served peaks,
    /// 0 -> 63,251,968 leaves), the wallet's fold STILL diverges — `wallet root limb0=000000000c0249fd vs node
    /// live spend root limb0=0000000004a9a110`, 8 of 8 attempts. So the index is not the fault and exactly two
    /// inputs remain: the frozen `captured[l]` siblings and the live partial span read from the served peaks.
    /// A single root comparison cannot distinguish them; three fix attempts were spent guessing between them.
    /// This names the source at every level so the divergent one is read, not inferred.
    ///
    /// Diagnostic only — it computes no path and changes no decision.
    /// NO-WINDOW-REVIEWED: mirrors `authpath_against` exactly, over the SAME fixed 2^level Merkle sibling
    /// spans (`sib_span_start` / `frontier_partial_span_root` are the existing names for that fixed shape). The
    /// loop is SPEND_TREE_DEPTH iterations, a protocol constant; nothing is refused for age or reach.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a fixed-width tag string over SPEND_TREE_DEPTH levels, describing which
    /// branch of this wallet's own local composition ran. Never a note, commitment, amount, key or owner.
    pub fn authpath_sources(&self, current: &PoseidonSpendFrontier) -> String {
        let c = current.count();
        let mut out = String::with_capacity(SPEND_TREE_DEPTH);
        for l in 0..SPEND_TREE_DEPTH {
            let right_child = (self.index >> l) & 1 == 1;
            out.push(if right_child {
                if self.acc[l].count() == (1u64 << l) {
                    'A'
                } else if self.captured[l].is_some() {
                    'C'
                } else if self.live_left_sibling(current, l).is_some() {
                    'L'
                } else {
                    '?'
                }
            } else {
                let s = sib_span_start(self.index, l);
                let end = s.saturating_add(1u64 << l);
                if c <= s {
                    'E'
                } else if c >= end {
                    if self.acc[l].count() == (1u64 << l) {
                        'A'
                    } else if self.captured[l].is_some() {
                        'C'
                    } else {
                        '?'
                    }
                } else {
                    'L'
                }
            });
        }
        out
    }

    pub fn authpath_against(
        &self,
        current: &PoseidonSpendFrontier,
    ) -> Option<(Vec<Digest4>, Vec<bool>)> {
        let c = current.count();
        let mut sibs = Vec::with_capacity(SPEND_TREE_DEPTH);
        let mut dirs = Vec::with_capacity(SPEND_TREE_DEPTH);
        for l in 0..SPEND_TREE_DEPTH {
            let right_child = (self.index >> l) & 1 == 1; // target on the RIGHT ⇒ sibling on the LEFT
            let sib = if right_child {
                // LEFT sibling — complete before the note existed, immutable. The same ONE-source rule as the right
                // side: a window this wallet OBSERVED in full (its own block, levels < 8) IS the completed subtree by
                // construction; otherwise the captured root (the peaks at catch, or — for a seed-only restore that
                // never saw them — the stream's left window, Q2 §9 item 5). Neither ⇒ refuse, never a guess.
                if self.acc[l].count() == (1u64 << l) {
                    self.acc[l].subtree_root(l)
                } else if let Some(d) = self.captured[l] {
                    d
                } else {
                    // The left sibling has not MERGED yet: the note's level-`l` ancestor is still the frontier's live
                    // window, so the sibling is the frontier's own pending level-`l` peak (the MMR invariant) — read
                    // from the CURRENT served peaks, the source the live right branch below reads. Once the ancestor
                    // completes, the stream carries the sibling as that merge's left entry.
                    self.live_left_sibling(current, l)?
                }
            } else {
                let s = sib_span_start(self.index, l);
                let end = s.saturating_add(1u64 << l);
                if c <= s {
                    empty_subtree_root(l) // window entirely empty (tree hasn't reached it) — deterministic
                } else if c >= end {
                    // ⛔⛔⛔ A CAPTURE IS ONLY THE SUBTREE ROOT IF THE SPAN WAS ALREADY FULL WHEN TAKEN.
                    //
                    // This preferred `captured[l]` over the accumulator whenever the span is full NOW. But the
                    // capture is taken AT RECEIPT (`[freeze] 1/1 newly-owned note(s) had their depth-32 copath
                    // frozen at receipt`), and at receipt most of these spans are still PARTIAL. A partial
                    // fold is not the completed subtree root, so preferring it returned a wrong sibling for
                    // every level that completed after the note arrived, and the whole path folded to a root
                    // that can never match the chain's.
                    //
                    // MEASURED 2026-08-01 on the live pair: the wallet's self-built root was
                    // limb0=00000000309def91 against the chain's 000000006cadabe1 on ALL 8 attempts of the
                    // run — deterministic, not the tip-moved race. The node's own two fields were proven
                    // consistent on that same run (`node-fields-disagree` = 0), so the divergence is here.
                    //
                    // ONE correct source, chosen by which is DEFINITIONALLY the completed root — not a rescue
                    // order. `acc[l]` with `count == 2^l` IS the completed subtree by construction, so it is
                    // authoritative whenever it exists. A capture answers only for a span this wallet never
                    // observed in full, where the accumulator has no value to give. Neither present ⇒ refuse:
                    // fail-closed, never a folded guess.
                    if self.acc[l].count() == (1u64 << l) {
                        self.acc[l].subtree_root(l)
                    } else if let Some(d) = self.captured[l] {
                        d
                    } else {
                        return None; // completed while offline + never captured — sync to recover, never forge
                    }
                } else {
                    // window LIVE (partial) ⇒ recompute from the CURRENT served peaks. The note's level-`l` window
                    // coincides with the frontier's rightmost partial level-`l` window here (⌊c/2^l⌋·2^l == s), so
                    // `current.frontier_partial_span_root(l)` (the sub-level fold, NOT the completed-subtree shortcut) IS
                    // this sibling — no per-block observation needed.
                    current.frontier_partial_span_root(l)
                }
            };
            sibs.push(sib);
            dirs.push(right_child);
        }
        Some((sibs, dirs))
    }

    /// The level-`l` LEFT sibling read from the current peaks, when the note's level-`l` ancestor window
    /// `[s + 2^l, s + 2^(l+1))` still holds the frontier's end (`index < c < s + 2^(l+1)`): then bit `l` of `c` is set and
    /// `current`'s level-`l` peak covers exactly `[s, s + 2^l)`. Anything else is `None` — the sibling merged, and only a
    /// capture answers for it.
    fn live_left_sibling(&self, current: &PoseidonSpendFrontier, l: usize) -> Option<Digest4> {
        let c = u128::from(current.count());
        let ancestor_end = u128::from(sib_span_start(self.index, l)) + (1u128 << (l + 1));
        (c > u128::from(self.index) && c < ancestor_end).then(|| current.peak_at(l)).flatten()
    }

    /// The frontier root recomputed via [`authpath_against`] — MUST equal `current.root()` (== the node's live
    /// `spend_frontier_root`) for the offline-tolerant spend to verify. `None` (fail-closed) if a needed sibling is
    /// missing. This is the wallet's self-check before it broadcasts an offline-recovered spend.
    pub fn root_against(&self, current: &PoseidonSpendFrontier) -> Option<Digest4> {
        let (sibs, dirs) = self.authpath_against(current)?;
        let mut node = self.leaf;
        for l in 0..SPEND_TREE_DEPTH {
            node = if dirs[l] {
                poseidon_pair(sibs[l], node)
            } else {
                poseidon_pair(node, sibs[l])
            };
        }
        Some(node)
    }
}

/// The empty-subtree root at `level` (an all-empty-leaf perfect subtree) — the sparse padding a note tree folds
/// its unfilled right tail against, identical to [`PoseidonSpendFrontier::root`]'s empty ladder. Non-test helper
/// so the copath serve (below) matches the live consensus root exactly.
/// Public alias so the node can derive an upper-copath sibling for a window past the tip with no stored
/// per-block root. Same deterministic value, no state.
pub fn empty_subtree_root_pub(level: usize) -> Digest4 {
    empty_subtree_root(level)
}

/// The empty-subtree roots of every level up to [`EMPTY_ROOTS_MEMO`], computed ONCE per process: a pure function of the level,
/// asked for at every level of every witness's path on every readiness check (a wallet with a thousand reward notes recomputed
/// ~500 Poseidon pairs per note per balance poll — MEASURED 464 ms of a 500 ms summary at 230 notes).
const EMPTY_ROOTS_MEMO: usize = 64;
fn empty_roots() -> &'static [Digest4] {
    static T: std::sync::OnceLock<Vec<Digest4>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = Vec::with_capacity(EMPTY_ROOTS_MEMO + 1);
        let mut h = empty_leaf();
        t.push(h);
        for _ in 0..EMPTY_ROOTS_MEMO {
            h = poseidon_pair(h, h);
            t.push(h);
        }
        t
    })
}

pub fn empty_subtree_root(level: usize) -> Digest4 {
    match empty_roots().get(level) {
        Some(h) => *h,
        // past the memo (never asked by the tree's own depth): the same fold, computed
        None => {
            let mut h = empty_roots()[EMPTY_ROOTS_MEMO];
            for _ in EMPTY_ROOTS_MEMO..level {
                h = poseidon_pair(h, h);
            }
            h
        }
    }
}

/// The sparse Poseidon root of the perfect subtree at `level` whose leftmost leaf is `start`, over `leaves`
/// (empty-padded past `leaves.len()`). This is the value of a membership copath's level-`level` sibling; it MUST
/// fold to [`PoseidonSpendFrontier::root`] so a wallet copath verifies against live consensus.
fn sparse_subtree_root(leaves: &[Digest4], level: usize, start: usize) -> Digest4 {
    if start >= leaves.len() {
        return empty_subtree_root(level);
    }
    if level == 0 {
        return leaves[start];
    }
    let half = 1usize << (level - 1);
    poseidon_pair(
        sparse_subtree_root(leaves, level - 1, start),
        sparse_subtree_root(leaves, level - 1, start + half),
    )
}

/// THE ARCHIVAL/DA COPATH PRIMITIVE (Brick 1). The depth-`SPEND_TREE_DEPTH` membership copath `(siblings, dirs)`
/// for leaf `index`, computed directly from the full append-ordered note-commitment `leaves` (the leaf set the
/// spend frontier committed). A node/wallet that HAS the leaves (archival serve role, or reconstructed from the
/// replicated DA block stream) produces it; EVERY consumer self-verifies it recomputes the O(1)
/// `spend_frontier_root` (via [`IncrementalWitness::from_copath`] + `root()`), so the producer is NEVER trusted —
/// a lying/archival server is caught fail-closed. `None` if `index` is beyond the leaf set. This is the sole
/// source of by-construction spendability for a note whose block has left the O(1) node's served window.
pub fn frontier_copath(leaves: &[Digest4], index: usize) -> Option<(Vec<Digest4>, Vec<bool>)> {
    if index >= leaves.len() {
        return None;
    }
    let idx = index as u64;
    let mut sibs = Vec::with_capacity(SPEND_TREE_DEPTH);
    let mut dirs = Vec::with_capacity(SPEND_TREE_DEPTH);
    for l in 0..SPEND_TREE_DEPTH {
        let start = ((idx >> l) ^ 1) << l; // the left edge of the level-l sibling window
        sibs.push(sparse_subtree_root(leaves, l, start as usize));
        dirs.push((idx >> l) & 1 == 1);
    }
    Some((sibs, dirs))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {

    /// The leaf count completing an ancestor is defined at EVERY level of the tree, the top one included (the `u64` form
    /// shifted by 64 at level 63 and panicked in a debug build). Below the top it equals the old formula exactly.
    #[test]
    fn the_ancestor_completion_count_is_defined_at_every_level_including_the_top() {
        for &index in &[0u64, 1, 5, 255, 1 << 40, u64::MAX - 1, u64::MAX] {
            for l in 0..super::SPEND_TREE_DEPTH {
                let got = super::ancestor_completes_at(index, l);
                if l + 1 < 64 {
                    assert_eq!(got, (u128::from(index >> (l + 1)) + 1) << (l + 1), "level {l}, index {index}");
                } else {
                    assert_eq!(got, 1u128 << 64, "the top level completes past every u64 leaf count");
                }
                assert!(got > u128::from(index), "an ancestor completes after its own leaf (level {l}, index {index})");
            }
        }
    }

    /// The memoized empty-subtree roots are the fold itself at every level, past the memo too (a cached consensus value that
    /// differed from the computed one at any level would move every copath root that crosses it).
    #[test]
    fn the_empty_root_memo_equals_the_fold_at_every_level() {
        let mut h = empty_leaf();
        for level in 0..=(EMPTY_ROOTS_MEMO + 3) {
            assert_eq!(empty_subtree_root(level), h, "⛔ the memoized empty root differs from the fold at level {level}");
            h = poseidon_pair(h, h);
        }
    }
    /// ⭐⭐⭐ WHAT THE PEAK SPINE ACTUALLY COSTS, AT FOUR CHAIN SIZES — MEASURED, NOT ARGUED.
    ///
    /// user 2026-07-30: *"remove the O(DEPTH) peak spine because constant growth isnt ok. Did you forget what
    /// O(1) really means?"*
    ///
    /// The question deserves a number, not a definition. This appends 10 / 1,000 / 100,000 / 1,000,000 leaves
    /// and asserts the retained state NEVER exceeds `SPEND_TREE_DEPTH + 1` slots — a compile-time protocol
    /// constant, not a function of the chain. A 100,000× longer chain must not buy a single extra slot.
    ///
    /// Retained bytes are the wire form's `8 + (DEPTH+1)*32` = 1,064 B, fixed, at every size. If that number
    /// moved with the leaf count this assertion would fail and the spine WOULD be the growth vector.
    #[test]
    fn the_peak_spine_never_exceeds_its_protocol_constant_at_any_chain_size() {
        let cap = SPEND_TREE_DEPTH + 1;
        let mut f = PoseidonSpendFrontier::new();
        let mut appended = 0u64;
        let mut observed = Vec::new();
        for target in [10u64, 1_000, 100_000, 1_000_000] {
            while appended < target {
                f.append(cm_bytes_to_leaf(&{
                    let mut b = [0u8; 32];
                    b[..8].copy_from_slice(&appended.to_le_bytes());
                    b[8] = 1; // never the zero leaf
                    b
                }));
                appended += 1;
            }
            let slots = f.peak_slots();
            let wire = f.peaks_hex().len() / 2;
            observed.push((target, slots, wire));
            assert!(
                slots <= cap,
                "{target} leaves retained {slots} peak slots — the spine must never exceed {cap}, or it is a \
                 growth vector and not a protocol constant"
            );
            assert_eq!(
                wire, SPEND_FRONTIER_WIRE_LEN,
                "the served spine must be a FIXED {SPEND_FRONTIER_WIRE_LEN} bytes at every chain size"
            );
        }
        eprintln!("[spine] (leaves, slots, bytes) = {observed:?}");
        // THE ANTI-VACUITY HALF: the frontier must really be accumulating, or "flat" would be trivial.
        assert_eq!(
            f.count(),
            1_000_000,
            "the frontier must actually hold 1,000,000 leaves"
        );
        // And the retained size at 1,000,000 leaves must equal the size at 10 — flat, not merely bounded.
        assert_eq!(
            observed[0].2, observed[3].2,
            "retained bytes at 10 leaves and at 1,000,000 leaves must be IDENTICAL, not just capped"
        );
    }

    use super::*;

    /// Reference depth-32 SPARSE root — the exact algorithm the wallet's `poseidon_frontier_root` /
    /// `poseidon_frontier_copath` use. The MMR root MUST equal this for the wallet's copath to verify.
    fn empty_subtree(level: usize) -> Digest4 {
        let mut h = empty_leaf();
        for _ in 0..level {
            h = poseidon_pair(h, h);
        }
        h
    }
    fn sparse_sub(leaves: &[Digest4], level: usize, start: usize) -> Digest4 {
        if start >= leaves.len() {
            return empty_subtree(level);
        }
        if level == 0 {
            return leaves[start];
        }
        let half = 1usize << (level - 1);
        poseidon_pair(
            sparse_sub(leaves, level - 1, start),
            sparse_sub(leaves, level - 1, start + half),
        )
    }
    fn sparse_ref_root(leaves: &[Digest4]) -> Digest4 {
        sparse_sub(leaves, SPEND_TREE_DEPTH, 0)
    }

    fn tleaf(i: u64) -> Digest4 {
        usdm_decider::poseidon2_compress::lanes_of(&[i.wrapping_add(1), 0xABCD_1234, i ^ 0x55AA, 9])
    }
    fn frontier_of(leaves: &[Digest4]) -> PoseidonSpendFrontier {
        let mut f = PoseidonSpendFrontier::new();
        for l in leaves {
            f.append(*l);
        }
        f
    }

    /// THE MEMBERSHIP-WITNESS KEYSTONE, adversarially proven: a wallet's SELF-BUILT `IncrementalWitness`
    /// recomputes EXACTLY the frontier root for EVERY (index, count) across all power-of-two boundaries — via
    /// both the wallet path (capture the left siblings from the served peaks at catch, then observe every later
    /// appended leaf) AND the pure-observe path. Since the WHIR spend proves membership against
    /// `spend_frontier_root()`, this is the fix for "owned note not yet in the served frontier": the wallet no
    /// longer needs the O(n) leaf set — O(DEPTH) peaks + the streamed blocks suffice, trustlessly + no-growth.
    #[test]
    fn incremental_witness_recomputes_frontier_root_exhaustive() {
        let counts = [
            1u64, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 200,
            257,
        ];
        for &n in &counts {
            let leaves: Vec<Digest4> = (0..n).map(tleaf).collect();
            let full = frontier_of(&leaves);
            let target_root = full.root();
            assert_eq!(
                target_root,
                sparse_ref_root(&leaves),
                "frontier root must equal the sparse oracle @ n={n}"
            );
            for index in 0..n {
                // WALLET path: left siblings captured from the peaks at catch (frontier at count==index), then
                // every LATER appended leaf observed (own-block right notes + all later blocks). No history replay.
                let at_catch = frontier_of(&leaves[..index as usize]);
                let mut w = IncrementalWitness::new(index, leaves[index as usize]);
                w.capture_left_from_peaks(&at_catch);
                for j in (index + 1)..n {
                    w.observe(j, leaves[j as usize]);
                }
                assert_eq!(
                    w.root(),
                    target_root,
                    "capture+observe root mismatch @ n={n} index={index}"
                );

                // PURE-OBSERVE path (no peak capture): every leaf but the target routed through the accumulators.
                let mut w2 = IncrementalWitness::new(index, leaves[index as usize]);
                for (j, lf) in leaves.iter().enumerate() {
                    w2.observe(j as u64, *lf);
                }
                assert_eq!(
                    w2.root(),
                    target_root,
                    "observe-only root mismatch @ n={n} index={index}"
                );
            }
        }
    }

    /// SOUNDNESS: a witness carrying a leaf the frontier does NOT contain recomputes a DIFFERENT root, so a spend
    /// that tries to prove membership of a forged note fails against the live `spend_frontier_root()` (fail-closed).
    #[test]
    fn incremental_witness_rejects_a_forged_leaf() {
        let leaves: Vec<Digest4> = (0..40u64).map(tleaf).collect();
        let full = frontier_of(&leaves);
        let index = 13u64;
        let mut good = IncrementalWitness::new(index, leaves[index as usize]);
        good.capture_left_from_peaks(&frontier_of(&leaves[..index as usize]));
        for j in (index + 1)..40 {
            good.observe(j, leaves[j as usize]);
        }
        assert_eq!(
            good.root(),
            full.root(),
            "the real witness must recompute the real root"
        );
        let mut forged = good.clone();
        forged.leaf = tleaf(9999);
        assert_ne!(
            forged.root(),
            full.root(),
            "a forged leaf must NOT recompute the real frontier root"
        );
    }

    /// BRICK 1 — FUNDS-ALWAYS-SPENDABLE (cardinal): the archival/DA copath primitive `frontier_copath` produces,
    /// for ANY leaf index (including the oldest one, whose block has long left the O(1) node's served window), a
    /// copath that `IncrementalWitness::from_copath` folds to the LIVE frontier root — so the note is spendable by
    /// construction no matter how many blocks pass. TRUSTLESS: a forged sibling recomputes a DIFFERENT root (the
    /// consumer's `root() == spend_frontier_root` self-check rejects it — a lying archival server is caught), and a
    /// copath whose dirs don't match the leaf index is refused outright.
    #[test]
    fn frontier_copath_reconstructs_spendable_witness_and_rejects_forgery() {
        for &n in &[1u64, 2, 8, 33, 256, 257, 1000, 5000] {
            let leaves: Vec<Digest4> = (0..n).map(tleaf).collect();
            let root = frontier_of(&leaves).root();
            // Reconstruct the copath for EVERY index — including index 0 (the oldest, deepest-buried note).
            for &index in &[0u64, 1, n / 2, n - 1] {
                if index >= n {
                    continue; // small-n dedupe (index 1 doesn't exist when n==1)
                }
                let (sibs, dirs) =
                    frontier_copath(&leaves, index as usize).expect("copath in range");
                assert_eq!(sibs.len(), SPEND_TREE_DEPTH, "O(DEPTH) copath");
                let w =
                    IncrementalWitness::from_copath(index, leaves[index as usize], &sibs, &dirs)
                        .expect("witness installs from the served copath");
                assert_eq!(
                    w.root(),
                    root,
                    "reconstructed witness folds to the LIVE frontier root @ n={n} i={index}"
                );
                // FORGERY: flip one sibling → the self-verify root no longer matches ⇒ the spend fails-closed.
                let mut bad = sibs.clone();
                bad[0] = tleaf(0xDEAD);
                let wb =
                    IncrementalWitness::from_copath(index, leaves[index as usize], &bad, &dirs)
                        .unwrap();
                assert_ne!(
                    wb.root(),
                    root,
                    "a forged copath must NOT recompute the frontier root @ n={n} i={index}"
                );
            }
        }
        // A copath whose dirs contradict the leaf index (wrong note) is refused outright (fail-closed).
        let leaves: Vec<Digest4> = (0..100u64).map(tleaf).collect();
        let (sibs, _dirs) = frontier_copath(&leaves, 10).unwrap();
        let wrong_dirs = vec![true; SPEND_TREE_DEPTH]; // index 10 is not all-right-children
        assert!(
            IncrementalWitness::from_copath(10, leaves[10], &sibs, &wrong_dirs).is_none(),
            "a copath whose dirs mismatch the leaf index is rejected"
        );
        assert!(
            frontier_copath(&leaves, 100).is_none(),
            "an out-of-range index yields no copath"
        );
    }

    /// The O(DEPTH) peak spine round-trips byte-for-byte and reconstructs a frontier with the IDENTICAL root — the
    /// no-growth membership anchor the wallet self-builds its copath against (Brick 1).
    #[test]
    fn spend_frontier_peaks_hex_roundtrips_to_the_same_root() {
        for &n in &[0u64, 1, 5, 256, 257, 1000] {
            let leaves: Vec<Digest4> = (0..n).map(tleaf).collect();
            let f = frontier_of(&leaves);
            let re = PoseidonSpendFrontier::from_peaks_hex(&f.peaks_hex()).expect("peaks decode");
            assert_eq!(re.count(), f.count(), "count round-trips @ n={n}");
            assert_eq!(
                re.root(),
                f.root(),
                "peaks reconstruct the identical root @ n={n}"
            );
        }
        assert!(
            PoseidonSpendFrontier::from_peaks_hex("zz").is_none(),
            "malformed hex fails closed"
        );
    }

    #[test]
    fn poseidon_pair_matches_the_prover_shape() {
        // A fixed vector through the primitive (NOT a note commitment — those are the decider's two-round
        // `asset_note_cm` since 2026-09-11; this pins the pair function's determinism and canonicality).
        let leaf = poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[1000]), usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10]));
        // deterministic + canonical (< p) + not the trivial zero.
        assert_eq!(
            leaf,
            poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[1000]), usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10])),
            "poseidon_pair is deterministic"
        );
        assert!(
            leaf.iter().all(|&x| x < KB_P),
            "output limbs are canonical KoalaBear"
        );
        assert_ne!(
            leaf,
            usdm_decider::poseidon2_compress::zero_digest(),
            "a real note leaf is not the empty leaf"
        );
    }

    #[test]
    fn empty_root_is_stable_and_nonzero() {
        let f = PoseidonSpendFrontier::new();
        assert_eq!(f.count(), 0);
        let r = f.root();
        assert_eq!(
            r,
            PoseidonSpendFrontier::new().root(),
            "empty root is deterministic"
        );
        assert_eq!(
            r,
            sparse_ref_root(&[]),
            "empty MMR root == empty sparse root"
        );
    }

    #[test]
    fn mmr_root_equals_the_wallet_sparse_root_every_count() {
        // THE PARITY PROOF: for every leaf count the node's O(DEPTH) MMR root equals the wallet's sparse
        // root — so a wallet copath (poseidon_frontier_copath) recomputes exactly the node's committed root.
        let leaves: Vec<Digest4> = (0..21u64)
            .map(|i| poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[i + 1]), usdm_decider::poseidon2_compress::lanes_of(&[i + 2, i + 3, i + 4, i + 5])))
            .collect();
        let mut f = PoseidonSpendFrontier::new();
        for n in 0..leaves.len() {
            assert_eq!(
                f.root(),
                sparse_ref_root(&leaves[..n]),
                "MMR root diverged from the wallet sparse root at count {n}"
            );
            f.append(leaves[n]);
        }
        assert_eq!(f.root(), sparse_ref_root(&leaves), "final root parity");
        assert_eq!(f.count(), leaves.len() as u64);
    }

    /// THE CONSENSUS-CRITICAL CROSS-CRATE PARITY: the node's native `poseidon_pair` MUST equal
    /// `usdm_decider::poseidon_pair` (the p3-koala-bear `Fa4` hash the wallet prover + the in-circuit
    /// `SpendMembershipGate` use). A single divergent limb = a chain split, so it is proven on edge
    /// vectors (all-zero, canonical, near-p, and NON-canonical inputs that must reduce mod p identically).
    /// Rides `usdm-decider` directly — the same engine the real carrier verify uses (always on).
    #[test]
    fn native_poseidon_pair_is_byte_identical_to_the_prover_crate() {
        let vectors: [(Digest4, Digest4); 6] = [
            (usdm_decider::poseidon2_compress::lanes_of(&[0, 0, 0, 0]), usdm_decider::poseidon2_compress::lanes_of(&[0, 0, 0, 0])),
            (usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]), usdm_decider::poseidon2_compress::lanes_of(&[0, 0, 0, 0])),
            (usdm_decider::poseidon2_compress::lanes_of(&[1000, 0, 0, 0]), usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10])),
            (
                usdm_decider::poseidon2_compress::lanes_of(&[KB_P - 1, KB_P - 1, KB_P - 1, KB_P - 1]),
                usdm_decider::poseidon2_compress::lanes_of(&[KB_P - 1, KB_P - 1, KB_P - 1, KB_P - 1]),
            ),
            (usdm_decider::poseidon2_compress::lanes_of(&[123_456_789, 2, 3, 4]), usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])),
            (usdm_decider::poseidon2_compress::lanes_of(&[u64::MAX, u64::MAX, 0, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, u64::MAX, 3, 4])), // non-canonical → both reduce mod p
        ];
        for (l, r) in vectors {
            assert_eq!(
                poseidon_pair(l, r),
                usdm_decider::poseidon_pair(l, r),
                "native poseidon_pair diverged from usdm_decider::poseidon_pair on {l:?} {r:?}"
            );
        }
    }

    #[test]
    fn cm_packing_round_trips_and_frontier_matches_over_packed_leaves() {
        // A note_cm IS the Poseidon commitment serialized (`leaf_to_cm_bytes`, the injective 32-byte form).
        // Its INVERSE is `cm_bytes_to_root`: the node recovers exactly the digest the prover welded.
        //
        // ⛔⛔⛔ THIS PIN ASSERTED `cm_bytes_to_leaf(leaf_to_cm_bytes(l)) == l` AND WAS RED "BY DESIGN"
        // FROM §AG UNTIL 2026-09-13 — the §AI trap in a test: `cm_bytes_to_leaf` is a HASH (total over
        // arbitrary 32-byte ids, and it must stay one, because the fixed 256-slot block carries COVER
        // fronts that are random bytes and not canonical digests), so a digest put through it is not
        // that digest. A red pin that everyone knows is red is a pin nobody reads; the claims below are
        // the tree's actual law, and the inequality is asserted so the trap cannot be re-added quietly.
        let leaves: Vec<Digest4> = (0..9u64)
            .map(|i| poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[i + 1]), usdm_decider::poseidon2_compress::lanes_of(&[i + 2, i + 3, i + 4, i + 5])))
            .collect();
        for &l in &leaves {
            let bytes = leaf_to_cm_bytes(l);
            assert_eq!(
                cm_bytes_to_root(&bytes),
                Some(l),
                "note_cm packing must round-trip through the INJECTIVE pair (every lane, 4..7 included)"
            );
            assert_ne!(
                cm_bytes_to_leaf(&bytes),
                l,
                "the hash is NOT a decode — a digest round-tripped through `cm_bytes_to_leaf` is not that digest (§AI)"
            );
        }
        // The frontier's LEAF RULE is the total hash of the note's 32-byte front (the same rule cover
        // fronts get), and the node's MMR over those leaves equals the reference sparse root over the same
        // leaves — the two tree shapes agree on what the block holds.
        let hashed: Vec<Digest4> = leaves.iter().map(|l| cm_bytes_to_leaf(&leaf_to_cm_bytes(*l))).collect();
        let mut f = PoseidonSpendFrontier::new();
        for &h in &hashed {
            f.append(h);
        }
        assert_eq!(
            f.root(),
            sparse_ref_root(&hashed),
            "frontier over hashed note_cm fronts == reference sparse root over the same leaves"
        );
    }

    #[test]
    fn order_matters_reordered_notes_give_a_different_root() {
        let a_leaf = poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[5]), usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]));
        let b_leaf = poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[9]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]));
        let mut a = PoseidonSpendFrontier::new();
        let mut b = PoseidonSpendFrontier::new();
        a.append(a_leaf);
        a.append(b_leaf);
        b.append(b_leaf);
        b.append(a_leaf);
        assert_ne!(
            a.root(),
            b.root(),
            "leaf ORDER is bound into the root (positions committed)"
        );
    }

    /// PATH A — a note stays SPENDABLE across an ARBITRARY offline gap, reconstructed from the CURRENT served peaks
    /// + captured immutable siblings, with NO block-by-block advance and NO DA. This closes the offline-window
    /// stranding hole in pure self-custody: the wallet syncs (freezing completed windows), goes offline while the
    /// chain advances many blocks, then spends against the LIVE root using only what the node always serves.
    #[test]
    fn path_a_note_spendable_across_offline_gap_from_current_peaks_and_fails_closed() {
        let idx = 1u64; // 0b1: l=0 is a LEFT sibling (index 0, captured at catch); l≥1 are RIGHT windows
        let leaf: Digest4 = usdm_decider::poseidon2_compress::lanes_of(&[7, 7, 7, 7]);
        let mut chain = PoseidonSpendFrontier::new();
        let mut w = IncrementalWitness::new(idx, leaf);
        // leaf 0, then CATCH at count==index==1 (capture left siblings), then the target leaf 1.
        let l0: Digest4 = usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]);
        w.observe(0, l0);
        chain.append(l0);
        w.capture_left_from_peaks(&chain);
        chain.append(leaf);
        // leaves 2,3 fill the l=1 right window [2,4); the wallet observes them, then SYNCS (freezes full windows).
        for (j, v) in [(2u64, usdm_decider::poseidon2_compress::lanes_of(&[2])), (3u64, usdm_decider::poseidon2_compress::lanes_of(&[3]))] {
            w.observe(j, v);
            chain.append(v);
        }
        w.promote_full_windows(chain.count()); // freeze the completed l=1 window — immutable forever
        assert_eq!(
            w.root_against(&chain).unwrap(),
            chain.root(),
            "witness current at the sync point"
        );

        // --- WALLET GOES OFFLINE. The chain keeps advancing; the wallet observes NOTHING more. ---
        chain.append(usdm_decider::poseidon2_compress::lanes_of(&[4, 0, 0, 0]));
        chain.append(usdm_decider::poseidon2_compress::lanes_of(&[5, 0, 0, 0])); // count -> 6; the note's l=2 window [4,8) is now LIVE (partial)
        assert_ne!(
            w.root(),
            chain.root(),
            "the STALE running witness (old block-by-block authpath) no longer matches the live root — the old stranding"
        );
        // PATH A: the node serves only the O(DEPTH) peaks; the wallet reconstructs the copath to the CURRENT root.
        let served = PoseidonSpendFrontier::from_peaks_hex(&chain.peaks_hex()).unwrap();
        assert_eq!(
            w.root_against(&served).unwrap(),
            chain.root(),
            "PATH A: SPENDABLE against the CURRENT root after an offline gap — from current peaks, no gap observation, no DA"
        );

        // FAIL-CLOSED #1: a tampered/wrong anchor recomputes a different root ⇒ the wallet's self-check rejects it.
        let mut bad = served.clone();
        bad.append(usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]));
        assert_ne!(
            w.root_against(&bad).unwrap(),
            chain.root(),
            "a wrong frontier anchor is rejected (fail-closed)"
        );

        // FAIL-CLOSED #2: a witness that was OFFLINE THROUGH a window completion never captured that sibling, so it
        // cannot forge it — `authpath_against` returns None (the wallet must sync to recover; it never guesses).
        let mut w_gap = IncrementalWitness::new(idx, leaf);
        let mut chain2 = PoseidonSpendFrontier::new();
        chain2.append(l0);
        w_gap.capture_left_from_peaks(&chain2);
        chain2.append(leaf);
        chain2.append(usdm_decider::poseidon2_compress::lanes_of(&[2, 0, 0, 0])); // leaves 2,3 complete the l=1 window, but w_gap OBSERVES NEITHER
        chain2.append(usdm_decider::poseidon2_compress::lanes_of(&[3, 0, 0, 0]));
        w_gap.promote_full_windows(chain2.count());
        assert!(
            w_gap.root_against(&chain2).is_none(),
            "a note that missed its window completion is fail-closed (None) — never a forged copath"
        );
    }

    /// ⭐ DB-223 Q2 — THE PATH-REFRESH STREAM, END TO END AT THE TREE: a wallet that saw ONLY its own 256-leaf block
    /// rebuilds its full depth-64 path to the CURRENT root from (a) its own block, (b) the completed RIGHT-window roots
    /// `append_with` reports at level ≥ 8 (the stream's entries — never a leaf of another block), and (c) the current
    /// peaks. CALIBRATION: without the stream the witness cannot reach the root (fail-closed). TAMPER: one wrong window
    /// root folds to a root the chain never had. Every entry is an ODD window (a right child), about one per block.
    /// ⭐ DB-223 Q2 §9 item 5 — A SEED-ONLY RESTORE REBUILDS ITS PATH WITHOUT EVER HAVING SEEN THE PEAKS AT ARRIVAL.
    /// The note sits in block 5, so levels ≥ 8 hold LEFT siblings (blocks 0–3, block 4) that completed before it. The
    /// wallet sees only its own 256-leaf block (levels 0–7, both sides) and the stream of BOTH children of every merge
    /// (the node's recording since the agreement), plus the current peaks. CALIBRATION: with the RIGHT-only stream the
    /// path cannot reach the root (the left siblings are missing — the gap this closes). TAMPER: one wrong LEFT window
    /// root folds to a root the chain never had.
    #[test]
    fn db223_q2_a_restored_note_rebuilds_its_path_from_both_sides_of_the_stream() {
        let leaf_of = |j: u64| usdm_decider::poseidon2_compress::lanes_of(&[j + 1, 7]);
        let blocks = 12u64;
        let idx = 5 * 256 + 77;
        let mut chain = PoseidonSpendFrontier::new();
        let mut w = IncrementalWitness::new(idx, leaf_of(idx));
        let mut both: Vec<(usize, u64, Digest4)> = Vec::new();
        let mut right_only: Vec<(usize, u64, Digest4)> = Vec::new();
        for j in 0..blocks * 256 {
            if (5 * 256..6 * 256).contains(&j) {
                w.observe(j, leaf_of(j)); // its own block only — no capture of the peaks at arrival
            }
            let after = chain.count() + 1;
            assert!(
                chain.append_with(leaf_of(j), |l, left, right| {
                    if l >= 8 {
                        let rw = (after >> l) - 1;
                        both.push((l, rw - 1, left));
                        both.push((l, rw, right));
                        right_only.push((l, rw, right));
                    }
                }),
                "the chain appends"
            );
        }
        w.promote_full_windows(chain.count());
        // CALIBRATION: the right-only stream leaves the restored note's left siblings missing.
        let mut r = w.clone();
        for (l, win, root) in &right_only {
            r.capture_completed_window(*l, *win, *root);
        }
        assert_ne!(r.root_against(&chain), Some(chain.root()), "calibration: right-only cannot restore a later note");
        // TAMPER: one wrong LEFT window.
        let mut forged = w.clone();
        let mut flipped = false;
        for (l, win, root) in &both {
            let mut x = *root;
            if !flipped && win % 2 == 0 && *win == (idx >> *l) ^ 1 {
                x[0] ^= 1;
                flipped = true;
            }
            forged.capture_completed_window(*l, *win, x);
        }
        assert!(flipped, "PRECONDITION: the stream carried a left sibling of this note's path");
        assert_ne!(forged.root_against(&chain), Some(chain.root()), "⛔ a forged LEFT window reached the chain's root");
        // THE RESTORE: both sides of the stream complete the path.
        for (l, win, root) in &both {
            w.capture_completed_window(*l, *win, *root);
        }
        assert_eq!(
            w.root_against(&chain),
            Some(chain.root()),
            "⛔ DB-223 Q2: a restored note could not rebuild its path from its own block + both sides of the stream"
        );
    }

    #[test]
    fn db223_q2_a_note_refreshes_its_path_from_completed_window_roots_alone() {
        let leaf_of = |j: u64| usdm_decider::poseidon2_compress::lanes_of(&[j + 1, 7]);
        let blocks = 16u64;
        let idx = 3u64; // leaf 3 of block 0: levels 0-1 left siblings (captured at catch), every level ≥ 2 a RIGHT window
        let mut chain = PoseidonSpendFrontier::new();
        let mut w = IncrementalWitness::new(idx, leaf_of(idx));
        let mut stream: Vec<(usize, u64, Digest4)> = Vec::new();
        for j in 0..blocks * 256 {
            if j == idx {
                w.capture_left_from_peaks(&chain);
            }
            if j < 256 {
                w.observe(j, leaf_of(j)); // the wallet sees ONLY its own block's leaves
            }
            let after = chain.count() + 1;
            assert!(
                chain.append_with(leaf_of(j), |l, _left, root| {
                    if l >= 8 {
                        stream.push((l, (after >> l) - 1, root));
                    }
                }),
                "the chain appends"
            );
            if j == 255 {
                w.promote_full_windows(256); // its own block's windows (levels < 8) freeze at the block's fold
            }
        }
        assert!(stream.iter().all(|(_, win, _)| win % 2 == 1), "every stream entry is a RIGHT child (odd window)");
        assert_eq!(stream.len() as u64, blocks - 1, "about one entry per block: N − 1 after N blocks");
        // CALIBRATION: with its own block only, the note cannot reach the current root.
        assert!(w.root_against(&chain).is_none(), "calibration: without the stream the path is incomplete");
        // TAMPER: one wrong root from the stream.
        let mut forged = w.clone();
        for (k, (l, win, root)) in stream.iter().enumerate() {
            let mut r = *root;
            if k == 0 {
                r[0] ^= 1;
            }
            forged.capture_completed_window(*l, *win, r);
        }
        assert_ne!(forged.root_against(&chain), Some(chain.root()), "⛔ a forged window root reached the chain's root");
        // THE REFRESH: the stream's entries alone complete the path.
        let taken = stream.iter().filter(|(l, win, root)| w.capture_completed_window(*l, *win, *root)).count();
        assert!(taken >= 1, "the note took the windows on its path");
        let served = PoseidonSpendFrontier::from_peaks_hex(&chain.peaks_hex()).expect("the peaks decode");
        assert_eq!(
            w.root_against(&served),
            Some(chain.root()),
            "⛔ DB-223 Q2: the path rebuilt from the stream does not reach the current root"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod capacity_boundary_tests {
    use super::*;

    /// ⛔⛔⛔ A FULL FRONTIER REFUSES THE LEAF — IT DOES NOT DESTROY IT.
    ///
    /// This boundary is unreachable at the production depth (2^32 appends), so its behaviour had never been
    /// executed by anything, and it was silently wrong: the carry ran past the top slot, the leaf was never
    /// parked, and `count` was incremented anyway — the frontier claiming a note it had dropped on the floor.
    /// No panic, no `Err`, no log. A receive would have looked successful with the money gone. That is silent
    /// FUND LOSS, and it lands on the longest-lived chain first.
    ///
    /// NOTE: this does NOT remove the capacity ceiling — a fixed-capacity accumulator on the RECEIVE path is
    /// still the defect ([[feedback_tree_lifetime_infinite_no_capacity_window]]). It proves the failure is now
    /// LOUD and the state stays HONEST, which is the difference between a refusal and destroyed money.
    #[test]
    fn a_full_frontier_refuses_the_leaf_loudly_instead_of_destroying_it() {
        // Built from the struct's own private fields — this test lives in the same module, so reaching the
        // boundary needs NO new public constructor. A depth production never uses must not become a second
        // shipped shape just so a test can run.
        let mut f = PoseidonSpendFrontier {
            pending: vec![None; 5],
            count: 0,
        };
        assert_eq!(f.capacity(), 16, "a depth-4 frontier holds 2^4 leaves");

        for i in 0..16u64 {
            assert!(
                f.append(usdm_decider::poseidon2_compress::lanes_of(&[i + 1, i + 2, i + 3, i + 4])),
                "leaf {i} fits under capacity"
            );
        }
        assert_eq!(f.count(), 16, "every accepted leaf advanced the count");
        let full_root = f.root();

        // THE BOUNDARY: one more leaf than the structure can hold.
        let overflow = usdm_decider::poseidon2_compress::lanes_of(&[99, 98, 97, 96]);
        assert!(
            !f.append(overflow),
            "a FULL frontier must REFUSE the append, not swallow it"
        );

        // The refusal left NOTHING half-done. Before the fix the count WOULD have advanced here while the
        // leaf vanished — state claiming a note that exists nowhere in the tree.
        assert_eq!(
            f.count(),
            16,
            "a refused append MUST NOT advance the count — that is the silent-loss bug"
        );
        assert_eq!(
            f.root(),
            full_root,
            "a refused append changes no committed state"
        );

        // And it stays refused — retrying never invents capacity.
        assert!(!f.append(overflow), "still refused on retry");
        assert_eq!(f.count(), 16, "count still honest after repeated refusals");
    }

    /// Production shape UNCHANGED: an ordinary frontier accepts leaves exactly as before and its ceiling is
    /// still `2^SPEND_TREE_DEPTH`. The capacity check must cost an ordinary append nothing.
    #[test]
    fn an_ordinary_frontier_is_unchanged_and_still_accepts_every_leaf() {
        let mut f = PoseidonSpendFrontier::new();
        // ⛔ AT PRODUCTION DEPTH THERE IS NO REACHABLE CEILING, AND THAT IS THE POINT.
        // `count` is a u64, so a capacity of `u64::MAX` cannot be reached by appending — the chain has no
        // date on which receiving stops working. This assertion used to read `1u64 << SPEND_TREE_DEPTH`,
        // which was 2^32 and, at the constant 256-leaf-per-block cover shape, exhausted in 97 days.
        assert_eq!(
            f.capacity(),
            u64::MAX,
            "production capacity must be unreachable — a fixed ceiling here is a death date for the chain"
        );
        let before = f.root();
        for i in 0..64u64 {
            assert!(
                f.append(usdm_decider::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3])),
                "an ordinary append is accepted"
            );
        }
        assert_eq!(f.count(), 64, "all 64 leaves counted");
        assert_ne!(f.root(), before, "the root advanced");
    }
}

/// ⭐⭐⭐ §BB — THE SPEND CROSS-BIND, COMPUTED FROM THE TWO PUBLIC VALUES A SPEND ALREADY PUBLISHES.
///
/// `leaf_commit = Poseidon(note_leaf, nullifier)` is the ONE value both of a spend's carriers name — the
/// validity carrier from the note's opening and the membership carrier from the record leaf — which is
/// what makes them a statement about the SAME note rather than two unrelated facts (§AO).
///
/// ⛔⛔⛔ WHY IT IS A FUNCTION AND NOT A LOOKUP, AND WHY THAT CLOSES §BB. A block's deletion set carries
/// note COMMITMENTS; a proven spend publishes a NULLIFIER and a LEAF_COMMIT. Nothing joined the two, so a
/// peer folding `del_set` map-authoritatively could not tell a deletion a spend proved from one a producer
/// invented — measured 2026-09-14, a producer named a victim's note and every peer folded it out. This
/// recomputes the bind from the candidate commitment and the proven nullifier: if it equals the proven
/// `leaf_commit`, that commitment IS the note the spend proved, and if it does not, nothing on chain says
/// this note was spent.
///
/// A producer cannot fake it. `Poseidon` is not invertible in the direction that would matter — choosing a
/// victim's `cm` and then finding `(nf, lc)` that a carrier will ALSO prove requires forging the carrier,
/// which is the thing the aggregate verifies in circuit.
///
/// ⛔ `spend_cross_bind(cm, nullifier)` is DELETED (DB-363, 2026-09-30). It recomputed a spend's `leaf_commit` from a
/// PUBLIC commitment and the PUBLIC nullifier — the exact one-hash linkage test DB-363 closes (a relay hashing every
/// candidate leaf with the tx's nullifier joined the spend to its receive). The commitment is now `P(P(leaf, nf), r)` with
/// `r` the spender's private per-send blinding, so no node-side recomputation from public values exists by design; its only
/// caller was `Admissible::admits_deletion_of_cm`, a §BB join with zero production callers, deleted with it.
///
/// ⭐ DB-363 — the ONE blinding every node-crate TEST fixture uses for the cross-bind (the value is fixed ON PURPOSE so a
/// fixture's spend witness, membership carrier and expected commitment agree; production draws its blinding from the OS
/// CSPRNG through `usdm_decider::whir_rec_block::fresh_lc_blind()` at the wallet's send/burn assembly, never here).
pub const TEST_LC_BLIND: Digest4 = [0x363, 1, 2, 3, 4, 5, 6, 7];
// Moved here from `impl Node` (stage A of the node split, lane dcash 2026-11-11): a pure constant / function the lower modules read;
// `Node` keeps an alias so every existing caller resolves.
/// The level of the note tree at which one record's subtree is rooted (a record's 256 leaves).
pub const RECORD_SUBTREE_LEVEL: usize = 8;


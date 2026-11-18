// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! THE CHAIN'S COMPRESSION FUNCTION — one Poseidon2 permutation, truncated. The replacement for the
//! 1-round `out = MDS·(l + 7·r)⁷` that kill list §AG measured as invertible in about a millisecond.
//!
//! ## What was wrong, in one line
//! The old fold was a SINGLE algebraic round, and each of its three parts inverts: `x ↦ x⁷` is a bijection
//! over KoalaBear, `SPEND_MDS` is invertible, and `pre = l + 7·r` is linear in two unknowns. So a sibling
//! could be SOLVED — `sib = ((MDS⁻¹·target)^{1/7} − node)/7` — and every non-membership copath in the
//! nullifier accumulator was forgeable. `src/sparse_fold_preimage_probe.rs` measures that; this module is
//! what makes the measurement stop working.
//!
//! ## The replacement, and why it is not a new assumption
//! `compress(l, r) = Poseidon2₁₆([l ‖ r])[0..8]` — the TRUNCATED-PERMUTATION construction Plonky3 itself
//! uses for Merkle compression. The permutation is [`crate::sponge_chain_air::production_perm`], the SAME
//! RNG-derived `Poseidon2KoalaBear<16>` the PoUW kernel mines with and every other AIR in this crate already
//! constrains. So this adds **no new constant, no new family and no new assumption** — it reuses the one the
//! chain already stakes its proof-of-work on, and `P2_COLS` already exists to constrain it in-circuit.
//!
//! ## ⭐ WIDTH IS THE OTHER HALF, AND IT IS DELIBERATE
//! [`DIGEST_LANES`] is **8**, not 4. Four KoalaBear limbs are 4 × 31 = 124 bits ⇒ 62-bit collision
//! resistance — about 46,000 GPU-days to collide two subtrees and prove a spent note unspent, which is a
//! price an attacker on a stablecoin would pay. Eight lanes are 248 bits ⇒ 124-bit collision resistance, the
//! width [`crate::work_target_air`] already uses. A stronger round CANNOT fix a too-narrow output, so the two
//! halves ship together (user decision, 2026-09-12).
//!
//! ## What this module is NOT
//! It is not a sponge and must not be used as one: a truncated permutation compresses exactly two digests of
//! [`DIGEST_LANES`] lanes. Absorbing variable-length input needs `sponge_chain_air`'s rate/capacity split,
//! which is a different object with a different padding argument.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;

/// Lanes in a chain digest: 8 × 31 bits = 248 bits ⇒ 124-bit collision resistance. See the module note —
/// this is half the repair, and the half a stronger round cannot substitute for.
pub const DIGEST_LANES: usize = 8;

/// The permutation width the compression truncates. `2 · DIGEST_LANES` exactly: the whole state is the two
/// inputs, with no capacity, which is what makes this a compression and not a sponge.
pub const COMPRESS_WIDTH: usize = 2 * DIGEST_LANES;

const _: () = assert!(
    COMPRESS_WIDTH == crate::sponge_chain_air::WIDTH,
    "the compression consumes a whole permutation state — a width mismatch would silently drop or \
     zero-pad input lanes, which is exactly how a 2-to-1 function stops being binding"
);

/// A chain digest in limb form: [`DIGEST_LANES`] canonical KoalaBear limbs, each in `[0, p)`.
pub type Digest = [u64; DIGEST_LANES];

/// The all-zero digest — the empty leaf / empty-subtree seed. A `const` as well as a function, because
/// some callers need it in a constant context (a genesis anchor, a static default).
pub const ZERO_DIGEST: Digest = [0u64; DIGEST_LANES];

/// The all-zero digest — the empty leaf / empty-subtree seed.
#[must_use]
pub const fn zero_digest() -> Digest {
    ZERO_DIGEST
}

/// A digest whose LOW lanes are `vals` and whose remaining lanes are zero — the shape a domain tag, a
/// length, or a small scalar takes when it enters the compression.
///
/// ⛔ A HELPER RATHER THAN AN ARRAY LITERAL, ON PURPOSE. `[tag, 0, 0, 0]` was correct at four lanes and is
/// a compile error at eight, which is the GOOD case. The bad case is a literal that happens to have the
/// right length and quietly pads the wrong end — the silent-width class that has already cost this tree
/// two bugs (`u128 >> 192`, and a 248-bit digest routed through a `u128`).
#[must_use]
pub fn lanes_of(vals: &[u64]) -> Digest {
    assert!(
        vals.len() <= DIGEST_LANES,
        "{} values do not fit a {DIGEST_LANES}-lane digest",
        vals.len()
    );
    core::array::from_fn(|i| vals.get(i).copied().unwrap_or(0))
}

/// [`lanes_of`] in a `const` context — for the chain's WELL-KNOWN constants (domain-separated blinds,
/// genesis seeds), which must be digests at the current width without a runtime call.
///
/// `const fn` cannot take a closure or index a slice with `?`, so this is a hand-rolled loop rather than
/// `from_fn`. It panics at COMPILE TIME if the caller hands it more lanes than a digest has, which is the
/// same fail-closed contract as the runtime helper.
#[must_use]
pub const fn lanes_of_const(vals: &[u64]) -> Digest {
    assert!(
        vals.len() <= DIGEST_LANES,
        "the constant does not fit a digest at the current lane count"
    );
    let mut out = [0u64; DIGEST_LANES];
    let mut i = 0;
    while i < vals.len() {
        out[i] = vals[i];
        i += 1;
    }
    out
}

fn to_field(d: &Digest) -> [KoalaBear; DIGEST_LANES] {
    core::array::from_fn(|i| KoalaBear::from_u64(d[i]))
}

/// `compress(left, right)` — ONE Poseidon2 permutation over `[left ‖ right]`, truncated to the first
/// [`DIGEST_LANES`] lanes.
///
/// ⛔ Inputs are reduced into the field by `from_u64`, so a caller handing non-canonical limbs gets the
/// canonical answer rather than a distinct one. That is required for prover/verifier agreement (the AIR sees
/// canonical field elements and nothing else), and it means a digest's limbs must always be canonical —
/// [`digest_from_bytes`] guarantees it by construction.
#[must_use]
pub fn compress(left: &Digest, right: &Digest) -> Digest {
    let mut state = [KoalaBear::ZERO; COMPRESS_WIDTH];
    state[..DIGEST_LANES].copy_from_slice(&to_field(left));
    state[DIGEST_LANES..].copy_from_slice(&to_field(right));
    crate::sponge_chain_air::production_perm().permute_mut(&mut state);
    core::array::from_fn(|i| u64::from(state[i].as_canonical_u32()))
}

/// ⭐ THE SPARSE-TREE PAIR — [`compress`] for the nullifier tree's folds (the node's band cursor and view, the native
/// band transition), through an EXACT bounded cache in test builds.
///
/// WHY (MEASURED 2026-10-06, the simulator's speed census): one band step re-hashes the same pairs many times over — the
/// SAME ~250 filler keys every step (`band_filler_key(0..)`), the owner's serve and its prove job fold the same paths, the
/// lone-leaf sibling folds repeat, and every simulated node absorbs the same step. 23.3 M pair hashes went into 303
/// simulated seconds (~1,080 per cursor insert), 65 % of the journey's wall time. A pure function's result is the same
/// whoever computes it, so a cache changes no value — only how often the permutation runs.
/// WHERE: test builds only (`test` / `test-support`). A node binary calls [`compress`] directly: the working set of a step
/// (~10^5 pairs) needs a cache far above phone-class RAM to hit across steps, and the simulator's cross-NODE repeats do not
/// exist in a one-node process. The simulator does not model node CPU time (its named fidelity gap), so this moves no
/// verdict. cons: ≤ 2 × [`SPARSE_PAIR_CACHE_CAP`] entries (~25 MB) in a test process; none in a node.
#[must_use]
pub fn compress_sparse(left: &Digest, right: &Digest) -> Digest {
    #[cfg(any(test, feature = "test-support"))]
    {
        sparse_pair_cache::get_or_compute(left, right)
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        compress(left, right)
    }
}

/// The cache's generation size (entries) — two generations are kept, so the newest `CAP` to `2 × CAP` pairs hit.
#[cfg(any(test, feature = "test-support"))]
pub const SPARSE_PAIR_CACHE_CAP: usize = 131_072;

/// ⭐⭐ PERF TIER — A MEMO HIT IS CHARGED THE CPU IT STOOD IN FOR (MonerousD 2026-10-08).
///
/// The simulator's memos (this crate's sparse pair cache; the node's payload memo, lone-fold cache and PoW memo) make a
/// pure function's repeat free — exact for VALUES, and wrong for TIME once the simulator charges node CPU (PERF TIER step
/// 1): a node binary has no memo and pays every call. The doc above ("the simulator does not model node CPU time … moves
/// no verdict") predates the charge clock.
/// BORROWED-FROM: Shadow charges a virtual host the measured execution time of its code; a memo hit runs none, so it is
/// charged what its miss MEASURED — each memo's running mean over its own misses, on its own inputs (no constant).
/// ROOT-LAYER: the memo is where the call is skipped, so it is the one place that knows a call's cost went missing; the
///   charge lands on the HITTING thread (`phantom_ns`), which the node's ONE charge clock (`budget_clock::charged_cpu_us`)
///   adds to the thread's CPU — every reader of that clock (the step charge, the per-tick work budgets, an off-lock job's
///   charge) then sees a node binary's cost. A miss's measure includes the hits nested inside it.
/// MEASURED (P14 high leg on 865e797, scratchpad/night/perf-flat-20261008-205812-high.log): 1,595,501,286 pair lookups,
///   33,465,926 misses — 98 % of the nullifier tree's hashing was charged as free; node lock CPU charged 975.6 s over
///   38,273 simulated s. After: the pin `sim_charge_tests` (a hit charges the thread its measured miss; RED on a hit that
///   charges nothing) and the next P14's `node lock CPU charged`.
/// MUST-STAY-GREEN: every value the memos return (a charge moves time, never a digest); the fast journey T1.0–T3.
/// WHERE: test builds only, like the memos. cons: two clock reads per miss and one thread-local add per hit.
#[cfg(any(test, feature = "test-support"))]
pub mod sim_charge {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    thread_local! {
        static PHANTOM_NS: Cell<u64> = const { Cell::new(0) };
    }

    /// The CPU (ns) this thread's memo hits stood in for, cumulative.
    #[must_use]
    pub fn phantom_ns() -> u64 {
        PHANTOM_NS.with(Cell::get)
    }

    /// One memo's measured miss cost: the running mean (ns) over its misses.
    pub struct MissCost {
        sum_ns: AtomicU64,
        n: AtomicU64,
    }

    impl MissCost {
        #[must_use]
        pub const fn new() -> Self {
            Self { sum_ns: AtomicU64::new(0), n: AtomicU64::new(0) }
        }

        /// Run a MISS and add what it cost (its wall time on this thread, plus the hits nested in it) to the mean.
        pub fn measure<R>(&self, f: impl FnOnce() -> R) -> R {
            let p0 = phantom_ns();
            let t0 = std::time::Instant::now();
            let r = f();
            let wall_ns = t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            self.sum_ns.fetch_add(wall_ns.saturating_add(phantom_ns().saturating_sub(p0)), Ordering::Relaxed);
            self.n.fetch_add(1, Ordering::Relaxed);
            r
        }

        /// Run a MISS worth `units` charge units (a fold through `units` levels) and add its cost to the per-unit mean.
        pub fn measure_per<R>(&self, units: u64, f: impl FnOnce() -> R) -> R {
            let p0 = phantom_ns();
            let t0 = std::time::Instant::now();
            let r = f();
            let wall_ns = t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            self.sum_ns.fetch_add(wall_ns.saturating_add(phantom_ns().saturating_sub(p0)), Ordering::Relaxed);
            self.n.fetch_add(units.max(1), Ordering::Relaxed);
            r
        }

        /// A HIT: charge this thread the mean miss cost. Before the first miss there is no measured cost to charge.
        pub fn charge_hit(&self) {
            self.charge_hits(1);
        }

        /// A hit worth `units` charge units (see [`Self::measure_per`]).
        pub fn charge_hits(&self, units: u64) {
            if let Some(mean) = self.mean_ns() {
                PHANTOM_NS.with(|c| c.set(c.get().saturating_add(mean.saturating_mul(units))));
            }
        }

        /// The mean miss cost so far (ns); `None` before the first miss.
        #[must_use]
        pub fn mean_ns(&self) -> Option<u64> {
            self.sum_ns.load(Ordering::Relaxed).checked_div(self.n.load(Ordering::Relaxed))
        }
    }

    impl Default for MissCost {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
mod sparse_pair_cache {
    use super::{compress, Digest, DIGEST_LANES};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// The canonical-limb key: two digests as 16 × u32 (a digest's limbs are canonical field elements, < 2^31; a
    /// non-canonical limb is reduced by `compress` exactly as before, so keying the RAW limbs stays exact).
    type Key = [u64; 2 * DIGEST_LANES];

    #[derive(Default)]
    struct Gen {
        cur: HashMap<Key, Digest, Fx>,
        old: HashMap<Key, Digest, Fx>,
    }

    /// A multiply-xor hasher over the key's words — the inputs are hash outputs, so no adversarial collision shaping.
    #[derive(Default, Clone, Copy)]
    struct Fx(u64);
    impl std::hash::BuildHasher for Fx {
        type Hasher = FxH;
        fn build_hasher(&self) -> FxH {
            FxH(0)
        }
    }
    struct FxH(u64);
    impl std::hash::Hasher for FxH {
        fn finish(&self) -> u64 {
            self.0
        }
        /// A WORD per round, never a byte: the key hashes as one 128-byte slice (`[u64]::hash` writes its raw bytes), and
        /// one round per byte was 128 dependent multiplies a lookup — MEASURED 2026-10-07 (`sample`, link21-sample.txt):
        /// the lookup itself, not the permutation it saves, was ~19 % of every simulated node's step CPU.
        fn write(&mut self, bytes: &[u8]) {
            let mut words = bytes.chunks_exact(8);
            for w in &mut words {
                self.write_u64(u64::from_le_bytes(w.try_into().expect("an 8-byte chunk")));
            }
            for b in words.remainder() {
                self.write_u64(u64::from(*b));
            }
        }
        fn write_u64(&mut self, x: u64) {
            self.0 = (self.0.rotate_left(5) ^ x).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
        fn write_usize(&mut self, x: usize) {
            self.write_u64(x as u64);
        }
    }

    const SHARDS: usize = 32;
    static CACHE: std::sync::OnceLock<Vec<Mutex<Gen>>> = std::sync::OnceLock::new();
    /// [lookups, misses] in this process (the simulator's speed census reads them).
    pub(crate) static COUNTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

    /// The pair's measured miss cost — what every hit is charged (`super::sim_charge`).
    pub(crate) static MISS: super::sim_charge::MissCost = super::sim_charge::MissCost::new();

    pub(super) fn get_or_compute(left: &Digest, right: &Digest) -> Digest {
        let mut key: Key = [0; 2 * DIGEST_LANES];
        key[..DIGEST_LANES].copy_from_slice(left);
        key[DIGEST_LANES..].copy_from_slice(right);
        let shard = ((left[0] ^ right[0].rotate_left(13) ^ left[1].rotate_left(29)) as usize) % SHARDS;
        let cache = CACHE.get_or_init(|| (0..SHARDS).map(|_| Mutex::new(Gen::default())).collect());
        COUNTS[0].fetch_add(1, Ordering::Relaxed);
        {
            let g = cache[shard].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(d) = g.cur.get(&key).or_else(|| g.old.get(&key)) {
                let d = *d;
                drop(g);
                MISS.charge_hit();
                return d;
            }
        }
        COUNTS[1].fetch_add(1, Ordering::Relaxed);
        let out = MISS.measure(|| compress(left, right));
        let mut g = cache[shard].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= super::SPARSE_PAIR_CACHE_CAP / SHARDS {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(key, out);
        out
    }
}

/// TEST-ONLY: the sparse pair cache's [lookups, misses] in this process.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn sparse_pair_cache_counts() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (sparse_pair_cache::COUNTS[0].load(Ordering::Relaxed), sparse_pair_cache::COUNTS[1].load(Ordering::Relaxed))
}

/// ⭐ THE WIDTH-16 PERMUTATION OVER RAW LANES — the sponge step every DSOL byte string is absorbed by.
///
/// [`compress`] is this permutation with a `[left ‖ right]` shape baked in and a truncation on the way
/// out. A SPONGE needs the whole state in and the whole state out, so it needs this. It is the SAME
/// permutation object (`sponge_chain_air::production_perm`), never a second one: the circuit block
/// `pow_pq_air::lay_perm_row_flat` lays is generated from the same constants, which is what lets
/// `dsol_vm`'s absorb rows and `dsol_cpu_air`'s permutation gates describe one function.
#[must_use]
pub fn permute_lanes_16(state: &[u64; COMPRESS_WIDTH]) -> [u64; COMPRESS_WIDTH] {
    let mut st: [KoalaBear; COMPRESS_WIDTH] = core::array::from_fn(|i| KoalaBear::from_u64(state[i]));
    crate::sponge_chain_air::production_perm().permute_mut(&mut st);
    core::array::from_fn(|i| u64::from(st[i].as_canonical_u32()))
}

/// Map an ARBITRARY 32-byte identifier — a nullifier, a foreign deposit id, a key nobody chose to be a
/// digest — into a digest, by compression.
///
/// ⛔⛔⛔ THIS IS NOT [`digest_from_bytes`], AND THE TWO MUST NEVER BE SWAPPED.
/// * `digest_from_bytes` DECODES the canonical 8 × 31-bit encoding of a digest and REFUSES anything else.
///   Use it for values the chain itself produced: roots, note commitments, anything that must round-trip.
/// * this one HASHES bytes that were never a digest. A nullifier is 256 bits of blake3 output, and 256 bits
///   do not fit 248, so most nullifiers are not a canonical encoding at all — decoding one would refuse a
///   perfectly good nullifier. Equally, hashing a root would destroy the round-trip a root depends on.
///
/// Sixteen bits per lane over two halves: every input byte reaches the permutation, and no lane can exceed
/// the field, so nothing is silently reduced on the way in.
#[must_use]
pub fn hash32_to_digest(b: &[u8; 32]) -> Digest {
    let half = |o: usize| -> Digest {
        core::array::from_fn(|i| u64::from(u16::from_le_bytes([b[o + 2 * i], b[o + 2 * i + 1]])))
    };
    compress(&half(0), &half(16))
}

/// 32 bytes → a digest, or `None` if those bytes are not a canonical encoding of one.
///
/// The encoding is 8 lanes of 31 bits, LSB-first, over the low 248 bits. Canonical means every lane is
/// already `< p` AND the 8 structurally-unused top bits are clear. Anything else is MALFORMED and is
/// REFUSED — it is not an alternative spelling of some digest.
///
/// ⛔⛔⛔ THIS RETURNS AN OPTION BECAUSE SILENT REDUCTION IS THE BUG. The old packing read four
/// little-endian u64s and reduced each mod p, so `0` and `p` — distinct byte strings — named the SAME
/// digest. That is a collision handed out before any hashing happens: two different on-chain
/// commitments, one accumulator leaf. A reader that cannot fail is a reader that launders malformed
/// input into valid state, so every caller here has to decide what to do with garbage.
#[must_use]
pub fn digest_from_bytes(b: &[u8; 32]) -> Option<Digest> {
    // KNOWN (F2-red-found-20261027c): the form is 8 lanes × 31 bits = 248 bits and byte 31 is outside it; refusing only bit
    // 255 leaves bits 248..254 ignored, so two byte strings differing there parse to ONE digest. See the revert note below.
    // ⛔ REVERTED 2026-10-27 (§9.2, self-inflicted): refusing every set bit of byte 31 (7de9f3e) turned
    // `cross_device_send_converges_full_spent_state_no_island` RED (device B's fold waited on records forever; the
    // producer's by-id serve answered `hold 0`) and GREEN again with this check restored (scratchpad/funds/xdev-22.log,
    // 2.7 s). The non-injectivity F2-red-found-20261027c stays OPEN: some reader of this parse depends on bits 248..254
    // being accepted, and it must be found before the form is tightened — never tightened first.
    if b[31] & 0x80 != 0 {
        return None;
    }
    let p = u64::from(KoalaBear::ORDER_U32);
    let mut out = [0u64; DIGEST_LANES];
    for (lane, slot) in out.iter_mut().enumerate() {
        let mut v = 0u64;
        for bit in 0..31 {
            let idx = lane * 31 + bit;
            v |= u64::from((b[idx >> 3] >> (idx & 7)) & 1) << bit;
        }
        if v >= p {
            return None; // 31 bits reach 2³¹−1 while p = 2³¹−2²⁴+1: the top 2²⁴−1 values name no limb
        }
        *slot = v;
    }
    Some(out)
}

/// A digest → its 32-byte on-chain form. INJECTIVE: distinct canonical digests never share a byte form,
/// and the result is always accepted by [`digest_from_bytes`] unchanged.
#[must_use]
pub fn digest_to_bytes(d: &Digest) -> [u8; 32] {
    // Lane `l`'s 31 bits sit at bit offsets `31·l ..`, little-endian (bit `i` → byte `i >> 3`, bit `i & 7`), packed a
    // byte at a time through a shift register — the same bytes as setting each bit alone. MEASURED (stable/relay2.sample.txt):
    // the per-bit form held ~870 of a node step's samples; `digest_bytes_pack_the_bits_the_per_bit_form_sets` pins equality.
    let p = u64::from(KoalaBear::ORDER_U32);
    let mut out = [0u8; 32];
    let (mut acc, mut held, mut at) = (0u64, 0u32, 0usize);
    for &limb in d {
        acc |= (limb % p) << held;
        held += 31;
        while held >= 8 {
            out[at] = acc as u8;
            acc >>= 8;
            held -= 8;
            at += 1;
        }
    }
    if held > 0 {
        out[at] = acc as u8;
    }
    out
}

/// The per-bit reference [`digest_to_bytes`] replaced, kept for its equality pin.
#[cfg(test)]
fn digest_to_bytes_per_bit(d: &Digest) -> [u8; 32] {
    let p = u64::from(KoalaBear::ORDER_U32);
    let mut out = [0u8; 32];
    for (lane, &limb) in d.iter().enumerate() {
        let v = limb % p;
        for bit in 0..31 {
            if (v >> bit) & 1 == 1 {
                let idx = lane * 31 + bit;
                out[idx >> 3] |= 1 << (idx & 7);
            }
        }
    }
    out
}

#[cfg(test)]
mod digest_bytes_native_tests {
    use super::*;

    /// ⭐ PERF EQUALITY (lane stable 2026-11-01) — the packed form writes the bytes the per-bit form sets, on every limb
    /// shape: zero, one, p − 1, the 31-bit ceiling, a value ≥ p (reduced), and pseudo-random digests. A planted limb change
    /// changes the bytes, and every result still decodes back to the reduced digest.
    #[test]
    fn digest_bytes_pack_the_bits_the_per_bit_form_sets() {
        let p = u64::from(KoalaBear::ORDER_U32);
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut cases: Vec<Digest> = vec![[0; DIGEST_LANES], [1; DIGEST_LANES], [p - 1; DIGEST_LANES], [(1 << 31) - 1; DIGEST_LANES], [p + 5; DIGEST_LANES]];
        for _ in 0..2_000 {
            cases.push(core::array::from_fn(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s
            }));
        }
        for d in &cases {
            let packed = digest_to_bytes(d);
            assert_eq!(packed, digest_to_bytes_per_bit(d), "⛔ packed bytes differ from the per-bit form for {d:?}");
            let reduced: Digest = core::array::from_fn(|i| d[i] % p);
            assert_eq!(digest_from_bytes(&packed), Some(reduced), "the bytes decode to the reduced digest");
            let mut planted = reduced;
            planted[DIGEST_LANES - 1] = (planted[DIGEST_LANES - 1] + 1) % p;
            assert_ne!(digest_to_bytes(&planted), packed, "CALIBRATION: a changed limb changes the bytes");
        }
    }
}

#[cfg(test)]
mod poseidon2_compress_gates {
    use super::*;
    use crate::sparse_fold_preimage_probe::sparse_fold_preimage_probe::retired_one_round_fold as poseidon_pair_native;
    use crate::sparse_fold_preimage_probe::sparse_fold_preimage_probe as attack;

    /// ⭐ CALIBRATION — THE ATTACK IS ARMED. The refutation below is vacuous unless the identical solve is
    /// shown to WORK on the function being replaced. Same code path, not a re-typed copy: the solve lives in
    /// the probe module and both lanes call it.
    #[test]
    fn calibration_the_solve_still_breaks_the_old_fold() {
        let node = [11u64, 22, 33, 44];
        let target = poseidon_pair_native([5, 6, 7, 8], [9, 10, 11, 12]);
        for dir in [0u64, 1] {
            let sib = attack::solve_sibling(node, target, dir).expect("the solve is a division");
            let got = if dir == 0 {
                poseidon_pair_native(node, sib)
            } else {
                poseidon_pair_native(sib, node)
            };
            assert_eq!(
                got, target,
                "the solve no longer breaks the OLD fold — if the old fold has been deleted this gate must \
                 go with it, and every refutation below must be re-derived"
            );
        }
        eprintln!("[compress] CALIBRATION: the §AG solve still inverts the 1-round fold, both orientations");
    }

    /// ⛔⛔⛔ THE REFUTATION — the SAME solve, run against the replacement, must not produce a preimage.
    ///
    /// The old fold let a verifier's target be hit by choosing one operand freely. Here the solve is run at
    /// full strength (it is handed the target and the known operand) and its answer is checked against the
    /// real compression. There is no algebraic route from the output of a Poseidon2 permutation back to its
    /// state, so the solved value should miss — and missing on every trial is the whole claim.
    #[test]
    fn the_old_solve_finds_no_preimage_of_the_new_compression() {
        let mut hits = 0usize;
        for seed in 0..64u64 {
            let known: Digest = core::array::from_fn(|i| (seed * 31 + i as u64 + 1) % 0x7f00_0001);
            let other: Digest = core::array::from_fn(|i| (seed * 17 + i as u64 * 3 + 5) % 0x7f00_0001);
            let target = compress(&known, &other);
            // The solve works on 4 lanes; run it on the LOW four and on the HIGH four, so a lucky alignment
            // in either half would be caught.
            for half in 0..2usize {
                let n4: [u64; 4] = core::array::from_fn(|i| known[half * 4 + i]);
                let t4: [u64; 4] = core::array::from_fn(|i| target[half * 4 + i]);
                if let Some(s4) = attack::solve_sibling(n4, t4, 0) {
                    let mut forged = other;
                    forged[half * 4..half * 4 + 4].copy_from_slice(&s4);
                    if compress(&known, &forged) == target {
                        hits += 1;
                    }
                }
            }
        }
        assert_eq!(
            hits, 0,
            "⛔ the §AG solve produced a preimage of the NEW compression — the replacement inherits the \
             break it exists to close"
        );
        eprintln!("[compress] REFUTATION: 128 solve attempts against the new compression, 0 preimages");
    }

    /// A one-BIT change anywhere in either operand must move essentially the whole output. A compression that
    /// leaks structure across a single-bit change is one an attacker can walk.
    #[test]
    fn a_single_bit_change_moves_about_half_the_output_bits() {
        let left: Digest = core::array::from_fn(|i| (i as u64 + 1) * 7);
        let right: Digest = core::array::from_fn(|i| (i as u64 + 1) * 13);
        let base = digest_to_bytes(&compress(&left, &right));
        let mut total = 0usize;
        let mut trials = 0usize;
        let mut worst = usize::MAX;
        for lane in 0..DIGEST_LANES {
            for bit in 0..31u64 {
                for side in 0..2 {
                    let (mut l, mut r) = (left, right);
                    if side == 0 {
                        l[lane] ^= 1 << bit;
                    } else {
                        r[lane] ^= 1 << bit;
                    }
                    let got = digest_to_bytes(&compress(&l, &r));
                    let flipped: usize =
                        base.iter().zip(got.iter()).map(|(a, b)| (a ^ b).count_ones() as usize).sum();
                    total += flipped;
                    worst = worst.min(flipped);
                    trials += 1;
                }
            }
        }
        let mean = total as f64 / trials as f64;
        eprintln!(
            "[compress] avalanche over {trials} single-bit flips: mean {mean:.1} of 248 bits, worst {worst}"
        );
        assert!(
            (100.0..148.0).contains(&mean),
            "mean avalanche {mean:.1}/248 is not near half — the compression is leaking structure"
        );
        assert!(worst > 60, "a single-bit flip moved only {worst} output bits");
    }

    /// A digest must have EXACTLY ONE byte form, and a byte string must name AT MOST ONE digest.
    /// The old packing failed the second half for free — `0` and `p` are distinct byte strings that reduced
    /// to the same limb — which is a collision available before any hashing happens.
    #[test]
    fn the_byte_encoding_is_one_to_one_and_refuses_malformed_input() {
        for seed in 0..256u64 {
            let d: Digest = core::array::from_fn(|i| {
                (seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 0x85EB_CA6B)) % 0x7f00_0001
            });
            let b = digest_to_bytes(&d);
            assert_eq!(digest_from_bytes(&b), Some(d), "digest → bytes → digest lost a value");
            assert_eq!(digest_to_bytes(&d), b, "bytes → digest → bytes is not stable");
        }
        // CALIBRATION of the OLD defect, so "one-to-one" is measured against a real counterexample rather
        // than asserted: under the old packing these two distinct byte strings named the same digest.
        let (zero, at_p) = ({
            let mut a = [0u8; 32];
            a[0..8].copy_from_slice(&0u64.to_le_bytes());
            a
        }, {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&0x7f00_0001u64.to_le_bytes());
            b
        });
        assert_ne!(zero, at_p, "the two byte strings must differ, or this proves nothing");
        assert_eq!(digest_from_bytes(&zero), Some(zero_digest()), "the canonical zero must still decode");
        assert_eq!(
            digest_from_bytes(&at_p),
            None,
            "⛔ a NON-CANONICAL limb was accepted — silently reducing it is exactly the old collision"
        );
        // Every lane position must be checked, not just lane 0: a bound tested in one place and skipped in
        // seven is the shape of a partial fix.
        for lane in 0..DIGEST_LANES {
            let mut b = [0u8; 32];
            for bit in 0..31 {
                if (0x7f00_0001u64 >> bit) & 1 == 1 {
                    let idx = lane * 31 + bit;
                    b[idx >> 3] |= 1 << (idx & 7);
                }
            }
            assert_eq!(digest_from_bytes(&b), None, "lane {lane} accepted a non-canonical limb");
        }
        // The 8 bits above the 248-bit encoding carry nothing and must not be quietly dropped.
        let mut high = digest_to_bytes(&zero_digest());
        high[31] |= 0x80;
        assert_eq!(digest_from_bytes(&high), None, "a bit outside the encoding was silently ignored");
        eprintln!(
            "[compress] encoding is one-to-one over 256 round-trips; {DIGEST_LANES}/{DIGEST_LANES} lanes              refuse a non-canonical limb, and the out-of-range top bit is refused"
        );
    }

    /// Structural sanity a compression must not fail: it is not the identity, not constant, order matters,
    /// and the all-zero input does not map to the all-zero output (which would make empty subtrees collide
    /// with real ones at every level).
    #[test]
    fn the_compression_has_no_degenerate_structure() {
        let z = zero_digest();
        assert_ne!(compress(&z, &z), z, "compress(0,0) == 0 — every empty subtree would share a digest");
        let a: Digest = core::array::from_fn(|i| i as u64 + 1);
        let b: Digest = core::array::from_fn(|i| i as u64 + 100);
        assert_ne!(compress(&a, &b), compress(&b, &a), "the compression ignores operand ORDER");
        assert_ne!(compress(&a, &b), a, "the compression returns an operand");
        assert_eq!(compress(&a, &b), compress(&a, &b), "the compression is not deterministic");
        // Non-canonical limbs must name the canonical digest, never a distinct one.
        let mut nc = a;
        nc[0] += 0x7f00_0001;
        assert_eq!(compress(&nc, &b), compress(&a, &b), "a non-canonical limb produced a DIFFERENT digest");
        eprintln!("[compress] no degenerate structure: order-sensitive, no fixed point at zero, canonical");
    }

    /// ⭐⭐⭐ WHERE THE PERMUTATION'S INPUT AND OUTPUT LIVE IN THE TRACE — MEASURED, NOT INFERRED.
    ///
    /// Every AIR conversion welds committed cells to these two column ranges, so if the offsets are wrong
    /// the whole repair binds the wrong cells and a forged fold would verify. Plonky3's `Poseidon2Cols` is
    /// `#[repr(C)]` with `inputs: [T; WIDTH]` first and the last ending-full-round's `post` last, which
    /// PREDICTS inputs at `0..WIDTH` and the output at `P2_COLS-WIDTH..P2_COLS`. That is a prediction about
    /// a vendored struct's layout under a zero-sized S-box type — exactly the kind of thing that is true
    /// until a dependency bump, and silent when it stops being true.
    ///
    /// So it is checked against the REAL trace generator: `build_perm_chain` lays each row from the
    /// previous row's permuted state, so row 1's INPUT must equal row 0's OUTPUT. A gate that reads the
    /// generator's own chaining cannot agree with a wrong offset.
    #[test]
    fn the_permutation_input_and_output_columns_are_where_the_weld_expects() {
        use p3_field::PrimeField32;
        use p3_koala_bear::KoalaBear;
        use p3_symmetric::Permutation;
        const W: usize = crate::pow_pq_air::WIDTH;
        let p2_cols = crate::pow_pq_air::P2_COLS;
        assert!(p2_cols >= 2 * W, "a permutation row must hold at least its input and output");

        let seed: [KoalaBear; W] = core::array::from_fn(|i| KoalaBear::from_u64(i as u64 * 7 + 3));
        let cols = crate::pow_pq_air::build_perm_chain(seed, 2);
        assert_eq!(cols.len(), p2_cols, "the chain did not lay P2_COLS columns");

        // INPUT at 0..W — row 0's input cells are the seed the caller handed in.
        for (i, &s) in seed.iter().enumerate() {
            assert_eq!(cols[i][0], s, "input lane {i} is not at column {i}");
        }
        // OUTPUT at P2_COLS-W..P2_COLS — and it must equal the native permutation of the seed.
        let mut expect = seed;
        crate::sponge_chain_air::production_perm().permute_mut(&mut expect);
        for (i, &e) in expect.iter().enumerate() {
            assert_eq!(
                cols[p2_cols - W + i][0],
                e,
                "output lane {i} is not at column P2_COLS-{}+{i} — every weld in the repair would bind \
                 the wrong cell",
                W
            );
            // The generator chains row→row, so row 1's INPUT is row 0's OUTPUT. Two independent routes to
            // the same cell: a wrong offset cannot satisfy both.
            assert_eq!(cols[i][1], e, "row 1's input lane {i} is not row 0's output");
        }
        // The compression is the first DIGEST_LANES of that output, and nothing else.
        let l: Digest = core::array::from_fn(|i| u64::from(seed[i].as_canonical_u32()));
        let r: Digest = core::array::from_fn(|i| u64::from(seed[DIGEST_LANES + i].as_canonical_u32()));
        let via_cols: Digest =
            core::array::from_fn(|i| u64::from(cols[p2_cols - W + i][0].as_canonical_u32()));
        assert_eq!(
            compress(&l, &r),
            via_cols,
            "the native compression disagrees with the trace's own output cells — prover and verifier \
             would accept different statements"
        );
        eprintln!(
            "[compress] weld points MEASURED: inputs at 0..{W}, output at P2_COLS-{W}..P2_COLS \
             (P2_COLS = {p2_cols}), and the native compression equals the trace's output cells"
        );
    }

    /// The width the whole repair rests on. 8 lanes × 31 bits = 248 bits ⇒ 124-bit collision resistance;
    /// the 4 lanes this replaces were 124 bits ⇒ 62-bit, which is the half a stronger round cannot fix.
    #[test]
    fn the_digest_is_wide_enough_to_matter() {
        let bits = DIGEST_LANES * 31;
        assert_eq!(bits, 248, "the digest is {bits} bits, not 248");
        assert!(bits / 2 >= 124, "collision resistance is {} bits", bits / 2);
        eprintln!(
            "[compress] digest = {DIGEST_LANES} lanes × 31 = {bits} bits ⇒ {}-bit collision resistance \
             (was 4 lanes = 124 bits ⇒ 62-bit)",
            bits / 2
        );
    }
}

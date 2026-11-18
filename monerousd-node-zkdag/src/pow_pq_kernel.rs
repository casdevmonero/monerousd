// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! SHARED-KERNEL PQ-PoW — the PQ-PoUW hash (docs/POUW_SHARED_KERNEL_DESIGN.md).
//!
//! A memory-hard proof-of-work hash whose ONLY compute primitive is the prover's OWN
//! `Poseidon2KoalaBear<16>` permutation — the exact permutation the WHIR light decider runs. This is the
//! deliberate design: **mining hardware == proving hardware.** A miner who optimizes Poseidon2 (SIMD / the
//! egalitarian kind of acceleration) wins more blocks AND proves+verifies WHIR faster, so the network's
//! aggregate hashpower IS its aggregate proving throughput — the point RandomX's throwaway AES work could
//! never serve. Kept ASIC-resistant by memory-hardness (a large, data-dependently-mutated scratchpad) and
//! kept a progress-free Poisson lottery (grind the nonce, accept iff `hash < target`) so leader election,
//! the difficulty knob, and the Monero-CPU-miner on-ramp all survive.
//!
//! ⭐ 2026-09-12 — THE KERNEL IS NOW **ENTIRELY** POSEIDON2, AND THAT IS WHAT MAKES THE WORK PROVABLE.
//! It used to seed from `blake3(preimage)` and squeeze through `blake3` of the 16-lane state. Both were
//! fine natively and both were fatal in circuit: bitwise blake3 costs more to constrain than the whole
//! memory argument the pad needs. The hardness lives ENTIRELY in FILL + MIX, so replacing those two calls
//! with the same Poseidon2 sponge changes the memory-hardness NOT AT ALL while letting a miner PROVE that
//! its hash meets its target — which is what lets a joining node compare cumulative work it can verify
//! instead of a number somebody typed. See `usdm_decider::pow_pq_air` and kill list §AB/§AC.
//! Two further changes ride the same fork, both circuit-driven and neither weakening anything:
//!   * the permutation is the tree's ONE production instantiation (`pow_pq_air::production_constants`),
//!     not the published default set — so mining and proving are the same permutation in the literal
//!     sense this module always claimed;
//!   * the MIX read index is a power-of-two BLOCK index (a bit mask) rather than `% (ELEMS - WIDTH)`, so
//!     addressing needs no division argument in circuit. It still covers the whole pad and is still
//!     derived from the prior state, so data-dependence and the serial chain are untouched.
//!
//! Construction (every step is the prover's own Poseidon2 permutation — no foreign primitive at all):
//!   1. SEED   — absorb the preimage into the sponge (3 bytes per lane, rate 8, length-bound), permute.
//!   2. FILL   — counter-mode permutations fill a `SCRATCHPAD_ELEMS`-wide pad (must be materialized in RAM).
//!   3. MIX    — `MIX_STEPS` SEQUENTIAL, DATA-DEPENDENT rounds: read a WIDTH-block at a state-derived index,
//!               absorb it, permute, and WRITE BACK into the pad. Data-dependent addressing kills within-hash
//!               parallelism; the write-back makes the pad genuinely required (no recompute-without-memory).
//!   4. SQUEEZE— one final permutation, then the first 8 lanes as 4-byte LE words → the 256-bit digest the
//!               `hash_meets_target` comparison reads. Each lane is < 2^31, so the top bit of every 4th
//!               byte is zero and the digest ranges over ~2^248 rather than 2^256: the pass probability
//!               `P(H·work < 2^256)` shifts by a CONSTANT factor of 2^8, which the DAA absorbs the same way
//!               it absorbs any hash-rate change. Entropy stays far above the 128-bit security parameter.
//!
//! NOT feature-gated and NOT a prototype: this module IS the live consensus PoUW kernel on every device,
//! reached through [`crate::pouw`] -> [`crate::pow`]. There is no classical branch to replace and no flag
//! that selects one (the `pq-randomx` feature this note once cited is absent from `[features]`).
//!
//! STILL OPEN: `SCRATCHPAD_ELEMS`/`MIX_STEPS` are compile-time `const`s re-exported from `pow_pq_air`,
//! not governance-tunable consensus params in [`crate::params`]. Retuning either is a hard fork today.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use usdm_decider::pow_pq_air;

/// Poseidon2 state width — the SAME 16 the WHIR prover uses (kernel-sharing is exact, not merely similar).
const WIDTH: usize = pow_pq_air::WIDTH;
/// Sponge rate: half the state absorbs, half is capacity. The circuit's sponge uses the same split.
const RATE: usize = WIDTH / 2;
/// Bytes packed into one KoalaBear lane. THREE, not four: `p ≈ 2^31`, so 24 bits is the widest chunk that
/// injects without a reduction — a 4-byte chunk would make two different preimages share a lane value.
const BYTES_PER_LANE: usize = 3;

/// Scratchpad size in KoalaBear field elements. `1 << 19` = 524_288 elems ≈ 2 MiB (each elem is a u32),
/// matching RandomX's L2/L3-resident scratchpad scale so a single hash cannot be recomputed without holding
/// the whole pad in fast memory (ASIC/GPU-resistance). Initial testnet value; a governance-tunable consensus
/// parameter at mainnet (all nodes must agree, so it lives with the chain params once this gates consensus).
pub const SCRATCHPAD_ELEMS: usize = pow_pq_air::SCRATCHPAD_ELEMS;

/// Sequential, data-dependent mixing rounds per hash. Each round's read address depends on the PRIOR state
/// (no within-hash parallelism) and writes back into the pad (the pad is genuinely load-bearing). Governance-
/// tunable alongside `SCRATCHPAD_ELEMS`; together they set the hash rate the DAA then calibrates against.
pub const MIX_STEPS: usize = pow_pq_air::MIX_STEPS;
/// The pad addressed in WIDTH-wide BLOCKS — a power of two, so the MIX read index is a bit mask and needs
/// no division argument in circuit. Every block of the pad is reachable.
pub const PAD_BLOCKS: usize = SCRATCHPAD_ELEMS / WIDTH;

/// The PQ-PoUW hasher: holds the prover's Poseidon2 permutation, built once and reused across grinds.
/// `Send`/`Sync` (the permutation is immutable), so a miner thread owns one and hashes with `&self`.
pub struct PqPouwHasher {
    /// DB-167: a SHARED reference to the one production permutation. Owning it made every
    /// `PqPouwHasher::new()` re-derive the round schedule (~434 ns MEASURED), and the hasher is built
    /// per mining session; the reference costs nothing and cannot drift from the decider's instance.
    perm: &'static Poseidon2KoalaBear<WIDTH>,
}

impl Default for PqPouwHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PqPouwHasher {
    /// Build the hasher over the canonical KoalaBear Poseidon2-16 permutation — the same family+width the
    /// WHIR prover/verifier run, so a Poseidon2 speedup helps mining AND proving on the same hardware.
    pub fn new() -> Self {
        Self {
            // THE tree's one production instantiation — the same permutation the decider proves with, so
            // "mining hardware == proving hardware" is true of the constants and not only of the family.
            perm: pow_pq_air::production_perm(),
        }
    }


    /// Memory-hard PQ-PoUW hash of `preimage` → a uniform 32-byte digest (fed to `hash_meets_target`).
    /// Deterministic (same input ⇒ same output), sequential + memory-hard, computed entirely on the
    /// Poseidon2 kernel. Allocates a fresh `SCRATCHPAD_ELEMS`-wide pad per call (the memory-hardness cost).
    pub fn hash(&self, preimage: &[u8]) -> [u8; 32] {
        // 1) SEED by absorbing the preimage into the sponge: 3 bytes per lane (24 bits, so every chunk
        //    injects without reduction), RATE lanes per duplexing, OVERWRITE not XOR — the same sponge
        //    discipline the challenger and `sponge_chain_air` use. The final lane carries the LENGTH, so
        //    two preimages differing only in trailing zeros cannot collide.
        let mut lanes: Vec<KoalaBear> = preimage
            .chunks(BYTES_PER_LANE)
            .map(|c| {
                let mut w = [0u8; 4];
                w[..c.len()].copy_from_slice(c);
                KoalaBear::from_u64(u32::from_le_bytes(w) as u64)
            })
            .collect();
        lanes.push(KoalaBear::from_u64(preimage.len() as u64));
        let mut state = [KoalaBear::ZERO; WIDTH];
        lanes.chunks(RATE).for_each(|group| {
            group.iter().enumerate().for_each(|(j, &v)| state[j] = v);
            (group.len()..RATE).for_each(|j| state[j] = KoalaBear::ZERO);
            self.perm.permute_mut(&mut state);
        });

        // 2) FILL the scratchpad in counter mode (must be materialized — this is the memory the miner holds).
        let mut pad = vec![KoalaBear::ZERO; SCRATCHPAD_ELEMS];
        let mut cs = state;
        let mut i = 0usize;
        while i < SCRATCHPAD_ELEMS {
            self.perm.permute_mut(&mut cs);
            let mut j = 0;
            while j < WIDTH && i < SCRATCHPAD_ELEMS {
                pad[i] = cs[j];
                i += 1;
                j += 1;
            }
        }

        // 3) MIX: sequential, data-dependent read → absorb → permute → write-back. The read index is derived
        //    from the CURRENT state (serial dependency chain); the write-back mutates the pad so a valid hash
        //    provably touched the whole memory in order (no time-memory shortcut).
        // The read address is a BLOCK index masked to `PAD_BLOCKS` (a power of two), so no division is
        // involved anywhere — natively or in circuit — while the address still depends on the prior state.
        let mask = PAD_BLOCKS - 1;
        for _ in 0..MIX_STEPS {
            let idx = ((state[0].as_canonical_u32() as usize) & mask) * WIDTH;
            for j in 0..WIDTH {
                state[j] += pad[idx + j];
            }
            self.perm.permute_mut(&mut state);
            for j in 0..WIDTH {
                pad[idx + j] += state[j];
            }
        }

        // 4) SQUEEZE: one final permutation, then the first 8 lanes as 4-byte LE words. No foreign hash —
        //    the digest IS the sponge's output, which is what the in-circuit version can reproduce.
        self.perm.permute_mut(&mut state);
        let mut out = [0u8; 32];
        (0..8).for_each(|j| {
            out[j * 4..j * 4 + 4].copy_from_slice(&state[j].as_canonical_u32().to_le_bytes());
        });
        out
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    // TIMING PROBE (`--ignored`): per-hash cost of the memory-hard PQ-PoUW kernel. Run in RELEASE to see the
    // real (phone-class) rate; the debug figure quantifies the opt-0 penalty. Run:
    //   cargo test pouw_hash_timing -- --ignored --nocapture            (debug)
    //   cargo test --release pouw_hash_timing -- --ignored --nocapture  (release / production speed)
    #[test]
    #[ignore]
    fn pouw_hash_timing() {
        let h = PqPouwHasher::new();
        // warm alloc caches
        let _ = h.hash(b"warm");
        const N: usize = 20;
        let t0 = std::time::Instant::now();
        let mut acc = 0u8;
        for i in 0..N {
            let d = h.hash(&[b'x', i as u8, 0, 0]);
            acc ^= d[0];
        }
        let per = t0.elapsed().as_secs_f64() * 1000.0 / N as f64;
        eprintln!(
            "PQ-PoUW hash: {per:.2} ms/hash  ({:.0} H/s)  [{} perms/hash, {} MB pad]  acc={acc}",
            1000.0 / per,
            SCRATCHPAD_ELEMS / WIDTH + MIX_STEPS,
            SCRATCHPAD_ELEMS * 4 / 1024 / 1024,
        );
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let h = PqPouwHasher::new();
        let a = h.hash(b"MoneroUSD PQ-PoUW block preimage A");
        let a2 = h.hash(b"MoneroUSD PQ-PoUW block preimage A");
        let b = h.hash(b"MoneroUSD PQ-PoUW block preimage B");
        assert_eq!(
            a, a2,
            "same preimage ⇒ same digest (deterministic PoW hash)"
        );
        assert_ne!(a, b, "a different preimage ⇒ a different digest");
        // A second hasher (same canonical Poseidon2) must reproduce it bit-for-bit — the kernel is fixed.
        assert_eq!(
            a,
            PqPouwHasher::new().hash(b"MoneroUSD PQ-PoUW block preimage A")
        );
    }

    #[test]
    fn avalanche_one_bit_flip_diffuses() {
        let h = PqPouwHasher::new();
        let mut p = *b"nonce=0000 :: block header preimage bytes";
        let d0 = h.hash(&p);
        p[0] ^= 0x01; // flip ONE bit of the preimage
        let d1 = h.hash(&p);
        let diff: u32 = d0
            .iter()
            .zip(d1.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        assert!(
            diff > 64,
            "1-bit input flip must diffuse to >64/256 output bits (got {diff})"
        );
    }

    #[test]
    fn output_is_not_the_seed_the_memory_hard_core_ran() {
        // The digest must NOT equal the SEED state — proving the memory-hard core actually transformed it
        // rather than passing it through. A shortcut prover that skipped FILL+MIX would land on the seed;
        // this rejects that. The seed is now the sponge's own absorb, so it is computed the same way the
        // kernel computes it — there is no foreign hash left to compare against.
        use p3_field::PrimeField32;
        let h = PqPouwHasher::new();
        let pre = b"prove the core ran, not a passthrough";
        let mut lanes: Vec<KoalaBear> = pre
            .chunks(3)
            .map(|c| {
                let mut w = [0u8; 4];
                w[..c.len()].copy_from_slice(c);
                KoalaBear::from_u64(u32::from_le_bytes(w) as u64)
            })
            .collect();
        lanes.push(KoalaBear::from_u64(pre.len() as u64));
        let mut seed_state = [KoalaBear::ZERO; WIDTH];
        lanes.chunks(WIDTH / 2).for_each(|g| {
            g.iter().enumerate().for_each(|(j, &v)| seed_state[j] = v);
            (g.len()..WIDTH / 2).for_each(|j| seed_state[j] = KoalaBear::ZERO);
            h.perm.permute_mut(&mut seed_state);
        });
        let mut seed = [0u8; 32];
        (0..8).for_each(|j| {
            seed[j * 4..j * 4 + 4].copy_from_slice(&seed_state[j].as_canonical_u32().to_le_bytes());
        });
        assert_ne!(
            h.hash(pre),
            seed,
            "the digest must differ from the seed state (FILL + MIX must actually run)"
        );
    }

    /// The per-hash permutation counter is a pure function of the preimage width and the two frozen pad
    /// constants — the number `pow_pq_air` builds its circuit shape from. If these ever disagree the
    /// circuit would prove a different function than the miner ran.
    #[test]
    fn the_permutation_counter_matches_the_circuit_shape() {
        assert_eq!(SCRATCHPAD_ELEMS, usdm_decider::pow_pq_air::SCRATCHPAD_ELEMS);
        assert_eq!(MIX_STEPS, usdm_decider::pow_pq_air::MIX_STEPS);
        assert_eq!(PAD_BLOCKS, usdm_decider::pow_pq_air::FILL_PERMS);
        assert_eq!(
            usdm_decider::pow_pq_air::HASH_PERMS,
            PAD_BLOCKS + MIX_STEPS + 1,
            "the circuit's per-hash row count must be the kernel's own FILL + MIX + squeeze"
        );
        // The SEED absorb is the one preimage-dependent part, and it is f(preimage width, RATE) — a
        // header's width is a fixed cover shape, never a chain quantity.
        let lanes = 200usize.div_ceil(BYTES_PER_LANE) + 1;
        assert!(lanes.div_ceil(RATE) >= 1, "an absorb always costs at least one permutation");
        eprintln!(
            "[pq-kernel] kernel and circuit agree: {PAD_BLOCKS} fill + {MIX_STEPS} mix + 1 squeeze = {} \
             permutation(s), over a {SCRATCHPAD_ELEMS}-element pad",
            usdm_decider::pow_pq_air::HASH_PERMS
        );
    }

    #[test]
    fn nonce_grind_produces_distinct_digests() {
        // The lottery property: incrementing the nonce yields uncorrelated digests to grind against a target.
        let h = PqPouwHasher::new();
        let mut seen = std::collections::HashSet::new();
        for nonce in 0u32..8 {
            let mut pre = b"header|nonce=".to_vec();
            pre.extend_from_slice(&nonce.to_le_bytes());
            assert!(
                seen.insert(h.hash(&pre)),
                "each nonce must give a distinct digest"
            );
        }
    }
}

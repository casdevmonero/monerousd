// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **The PoUW base hasher — MonerousD's NOVEL Proof-of-USEFUL-Work, not classical RandomX.**
//!
//! The hash's ONLY compute primitive is the prover's OWN `Poseidon2KoalaBear<16>` permutation
//! ([`crate::pow_pq_kernel`]) — the EXACT permutation the WHIR light decider runs. This is the deliberate
//! shared-kernel design: **mining hardware == proving hardware.** A miner who optimizes Poseidon2 wins more
//! blocks AND proves+verifies WHIR faster, so the network's aggregate hashpower IS its aggregate proving
//! throughput — the useful-work property classical RandomX's throwaway AES work could never serve. It is
//! pure-Rust (no C `librandomx.a`, no JIT/W^X), so it cross-compiles to `aarch64-apple-ios` (the phone runs
//! its OWN in-process node) and leaves the desktop node monolith-free.
//!
//! The classical C RandomX fallback was **REMOVED at the source** (user 2026-07-14: "remove the classical pow
//! fallback"): MonerousD's PoW is the novel PQ-PoUW puzzle on EVERY device, never the vestigial-Monero RandomX
//! hash. There is exactly ONE hasher; the puzzle is parameterised by a PUBLIC epoch SEED — a consensus constant
//! (like a difficulty target / seedhash), NOT a key and NOT a value-bearing secret: it collects/custodies/routes
//! NOTHING, holds no funds, and every node uses the identical public seed so the PoW puzzle is uniform (the
//! consensus precondition for cross-device convergence). Per-node VALUE keys (coinbase/fee/reward) live
//! elsewhere — and since 2026-09-18 nowhere: the coinbase bind was retired (the chain is zero-emission).

use crate::hash::Hash32;
use crate::pow_pq_kernel::PqPouwHasher;

/// The PoUW hasher: the pure-Rust Poseidon2-KoalaBear kernel bound to one PUBLIC epoch `seed` (a consensus
/// puzzle parameter, not a value secret; folded into the preimage so the puzzle stays epoch-consistent). Same
/// API every call site (`crate::pow::verify_block_pow` / `PowMiner`) uses: `new(seed)`, `hash(preimage)`, `rekey`.
pub struct PouwHasher {
    inner: PqPouwHasher,
    epoch_seed: Vec<u8>,
    /// TEST BUILDS ONLY — this hasher is the BOUND PoUW double ([`bound_pow`]), fixed when it is built.
    #[cfg(test)]
    bound: bool,
}

impl PouwHasher {
    /// Build the hasher over the canonical Poseidon2-16 kernel, bound to the public epoch `seed`. `Some` always
    /// (the kernel needs no cache/dataset allocation — the memory-hard scratchpad is allocated per hash), so the
    /// `Option` matches the call-site contract without ever failing closed on init.
    pub fn new(seed: &[u8]) -> Option<Self> {
        Some(PouwHasher {
            inner: PqPouwHasher::new(),
            epoch_seed: seed.to_vec(),
            #[cfg(test)]
            bound: bound_pow::armed_on_this_thread(),
        })
    }

    /// TEST BUILDS ONLY — is this the bound PoUW double ([`bound_pow`])?
    #[cfg(test)]
    pub fn is_bound_for_test(&self) -> bool {
        self.bound
    }

    /// 32-byte PQ-PoUW digest of `epoch_seed ‖ preimage`. Deterministic — every honest node computes the
    /// identical digest for a `(seed, preimage)`, which is what the PoW target gate
    /// ([`crate::pow::hash_meets_target`]) compares against.
    pub fn hash(&self, preimage: &[u8]) -> Hash32 {
        let mut buf = Vec::with_capacity(self.epoch_seed.len() + preimage.len());
        buf.extend_from_slice(&self.epoch_seed);
        buf.extend_from_slice(preimage);
        #[cfg(test)]
        if self.bound {
            return Hash32(bound_pow::digest(&buf));
        }
        #[cfg(test)]
        if !sim_memo::bypassed() {
            return Hash32(sim_memo::get_or_compute(buf, |b| self.inner.hash(b)));
        }
        Hash32(self.inner.hash(&buf))
    }

    /// Rotate to a new public epoch seed. No-op if unchanged.
    pub fn rekey(&mut self, seed: &[u8]) {
        if seed != self.epoch_seed.as_slice() {
            self.epoch_seed = seed.to_vec();
        }
    }
}

/// ⭐ THE SIMULATOR'S POW MEMO — [`PouwHasher::hash`] through an EXACT bounded cache in test builds.
///
/// WHY (MEASURED 2026-10-07, `sample` of the fast journey, scratchpad/night/link21-sample.txt): the PQ-PoUW hash is ~33 ms
/// (32,768 FILL + MIX permutations over a 2 MiB pad), and 48 % of every simulated node's step CPU was this hash — two
/// thirds of it the PEERS re-verifying a header the producer had just hashed in the same process (`preverify_block` 4,801
/// samples vs `PowMiner::mine` 2,348 at three nodes). A pure function's digest is the same whoever computes it, so an
/// exact cache changes no value: the key is the WHOLE preimage (epoch seed ‖ header bytes), so a tampered header misses
/// and is hashed for real, and a wrong witness is refused by the same comparison as before.
/// WHERE: `cfg(test)` only. A node binary hashes each block once per process — the repeat exists only when several
/// simulated nodes share one process. The simulator does not model node CPU time (its named fidelity gap; the inbound
/// drain's 200 ms wall budget therefore starves later in the simulator than on a real node, as it already did for every
/// other unmodelled cost), so this moves no verdict.
/// cons: ≤ 2 × [`sim_memo::CAP`] entries (~3 MB) in a test process; none in a node.
#[cfg(test)]
pub mod sim_memo {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// Entries per generation; two generations are kept, so the newest `CAP` to `2 × CAP` preimages hit.
    pub const CAP: usize = 4096;

    #[derive(Default)]
    struct Gen {
        cur: HashMap<Vec<u8>, [u8; 32]>,
        old: HashMap<Vec<u8>, [u8; 32]>,
    }

    static MEMO: std::sync::OnceLock<Mutex<Gen>> = std::sync::OnceLock::new();
    /// [lookups, misses] in this process.
    pub static COUNTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

    thread_local! {
        static BYPASS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A TIMING instrument on this thread measures the real hash, never the memo (`pow_verify_cost_is_measured`).
    pub fn bypass_on_this_thread() {
        BYPASS.with(|b| b.set(true));
    }

    pub fn bypassed() -> bool {
        BYPASS.with(std::cell::Cell::get)
    }

    /// What a hit is charged: the kernel hash's measured miss cost (`usdm_decider::poseidon2_compress::sim_charge` — a node
    /// binary hashes every preimage it checks).
    static MISS: usdm_decider::poseidon2_compress::sim_charge::MissCost =
        usdm_decider::poseidon2_compress::sim_charge::MissCost::new();

    pub fn get_or_compute(key: Vec<u8>, f: impl FnOnce(&[u8]) -> [u8; 32]) -> [u8; 32] {
        let memo = MEMO.get_or_init(|| Mutex::new(Gen::default()));
        COUNTS[0].fetch_add(1, Ordering::Relaxed);
        {
            let g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(d) = g.cur.get(&key).or_else(|| g.old.get(&key)) {
                let d = *d;
                drop(g);
                MISS.charge_hit();
                return d;
            }
        }
        COUNTS[1].fetch_add(1, Ordering::Relaxed);
        let out = MISS.measure(|| f(&key)); // off the lock: another thread hashing the same preimage meanwhile computes the same digest
        let mut g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= CAP {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(key, out);
        out
    }
}

/// ⭐⭐ THE BOUND PoUW DOUBLE — the fast simulator lane's stand-in for the PQ-PoUW KERNEL, under the test-double law of the
/// testing format (memory `feedback_testing_format_20261002`; the bound certificate's and the bound band step's shape).
///
/// WHY (MEASURED link 28, the windowed simulator's critical-path meter, night/sim-20261007-225956.log): the fast journey's
/// critical path was 174.0 s, and its largest term was the producers' GRIND — 60.8 s of real ~30 ms kernel hashes, ~4 a
/// block — while the simulator charges a grind as `Physics::ms_per_hash` per try and never models the CPU (its own doc).
/// A window ends when its slowest node does, so every node waited on one node's hashing; parallel lanes cannot beat it
/// (four lanes: 46 s of grind; ten: 70.7 s — efficiency cores and contention).
///
/// WHAT IT KEEPS: the whole PoW protocol. The digest is a domain-separated blake3 of the SAME bytes the kernel hashes
/// (`epoch seed ‖ header preimage`), so every header byte is bound — a moved nonce, work, parent or root is a different
/// digest, refused by the same witness comparison and target test (`pow::verify_block_pow`, `hash_meets_target`) at
/// every door; a uniform digest meets a target with the same probability per try, so the tries a block takes — the
/// simulated grind time — and the DAA's dynamics are the kernel's.
/// WHAT IT DROPS: only the kernel's CPU (its correctness is this crate's kernel pins; the real lane `sim.sh real` and the
/// live run use the kernel).
/// WHERE IT CAN EXIST: test builds only (`cfg(test)`: a node binary has no field and no branch for it). A hasher is bound
/// or real when it is BUILT, from its building thread's arm, so a node runs one or the other as a whole: the simulator
/// arms its step thread for the fast lane before it builds any node (`NetSim::with_band_double`), and every hasher a node
/// holds — its miner, its preverify worker's — is built on that thread. A bound digest NEVER passes the real kernel and a
/// real one never passes the double (`the_bound_pow_double_binds_every_header_byte_and_never_passes_the_real_kernel`).
#[cfg(test)]
pub mod bound_pow {
    thread_local! {
        static ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Hashers built on this thread from now on are bound (`true`) or real (`false`).
    pub fn arm_on_this_thread(on: bool) {
        ARMED.with(|a| a.set(on));
    }

    pub fn armed_on_this_thread() -> bool {
        ARMED.with(std::cell::Cell::get)
    }

    /// The double's digest of the bytes the kernel would hash (`epoch seed ‖ preimage`).
    pub fn digest(buf: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-bound-pouw/v1");
        h.update(buf);
        *h.finalize().as_bytes()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::PouwHasher;

    /// ⭐ THE BOUND PoUW DOUBLE'S LAW ([`super::bound_pow`]): what the bound miner mines, the bound door admits (calibration);
    /// the REAL door refuses it; one moved header byte is refused by the bound door too (every byte is bound); and a block
    /// the real kernel mined is refused by the bound door — a node is bound or real as a whole, never both.
    #[test]
    fn the_bound_pow_double_binds_every_header_byte_and_never_passes_the_real_kernel() {
        super::bound_pow::arm_on_this_thread(true);
        let bound = crate::pow::PowMiner::new().expect("a bound hasher builds");
        super::bound_pow::arm_on_this_thread(false);
        let real = crate::pow::PowMiner::new().expect("the kernel hasher builds");
        assert!(bound.hasher().is_bound_for_test() && !real.hasher().is_bound_for_test(), "the arm decides at build");
        let mut header = crate::block::genesis_block().header;
        header.parents = vec![crate::hash::Hash32::hash(b"bound-pow parent")];
        header.timestamp = 1_000;
        header.work = 16; // ~16 tries: the double's grind runs to a real target, not a free pass
        let mut hb = header.clone();
        let pi = bound.mine(&mut hb).expect("the bound miner meets the target");
        assert!(bound.verify(&hb, &pi), "CALIBRATION: the bound door admits what the bound miner mined");
        assert!(!real.verify(&hb, &pi), "⛔ the REAL door admitted a bound-double block");
        for tamper in 0..3 {
            let mut t = hb.clone();
            match tamper {
                0 => t.nonce ^= 1,
                1 => t.work += 1,
                _ => t.timestamp += 1,
            }
            assert!(!bound.verify(&t, &pi), "⛔ the bound door admitted a header with a moved field ({tamper})");
        }
        header.work = 2; // a real grind kept short: ~2 kernel hashes
        let mut hr = header.clone();
        let rpi = real.mine(&mut hr).expect("the kernel meets the target");
        assert!(real.verify(&hr, &rpi), "CALIBRATION: the real door admits a kernel-mined block");
        assert!(!bound.verify(&hr, &rpi), "⛔ the bound door admitted a kernel-mined block (a mixed node)");
    }

    /// ⭐ THE POW MEMO IS EXACT: a memoized digest equals the kernel's own for the same preimage, a one-bit change of the
    /// header misses the memo and yields the kernel's digest of THOSE bytes, and a re-keyed epoch is a different key.
    /// A memo that returned a cached digest for a different preimage (e.g. keyed by a prefix) fails the second check.
    #[test]
    fn the_pow_memo_returns_the_kernels_digest_for_exactly_the_bytes_asked() {
        let h = PouwHasher::new(b"epoch-memo").unwrap();
        let kernel = crate::pow_pq_kernel::PqPouwHasher::new();
        let mut pre = b"memo header preimage 0000".to_vec();
        let full = |p: &[u8]| [b"epoch-memo".as_slice(), p].concat();
        let a = h.hash(&pre);
        assert_eq!(a.0, kernel.hash(&full(&pre)), "a first hash is the kernel's digest");
        let (l0, m0) = (super::sim_memo::COUNTS[0].load(std::sync::atomic::Ordering::Relaxed), super::sim_memo::COUNTS[1].load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(h.hash(&pre), a, "a repeat returns the same digest");
        let (l1, m1) = (super::sim_memo::COUNTS[0].load(std::sync::atomic::Ordering::Relaxed), super::sim_memo::COUNTS[1].load(std::sync::atomic::Ordering::Relaxed));
        assert!(l1 > l0 && m1 - m0 < l1 - l0, "the repeat was served by the memo ({l0}/{m0} → {l1}/{m1})");
        *pre.last_mut().unwrap() ^= 0x01;
        let b = h.hash(&pre);
        assert_ne!(b, a, "a one-bit header change is a different digest");
        assert_eq!(b.0, kernel.hash(&full(&pre)), "and it is the kernel's digest of the changed bytes");
        let other = PouwHasher::new(b"epoch-memX").unwrap();
        assert_eq!(other.hash(&pre).0, kernel.hash(&[b"epoch-memX".as_slice(), &pre].concat()), "the epoch seed is in the key");
    }

    #[test]
    fn pouw_hash_is_deterministic_rekeys_and_is_memory_hard() {
        let mut h = PouwHasher::new(b"epoch-000").unwrap();
        let a = h.hash(b"payload");
        assert_eq!(h.hash(b"payload"), a, "same (seed,preimage) ⇒ same digest");
        h.rekey(b"epoch-001");
        assert_ne!(
            h.hash(b"payload"),
            a,
            "a different epoch seed yields a different digest"
        );
        h.rekey(b"epoch-000");
        assert_eq!(
            h.hash(b"payload"),
            a,
            "re-keying back reproduces the digest"
        );
    }
}

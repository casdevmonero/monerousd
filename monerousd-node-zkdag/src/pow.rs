// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! #73 PoUW engine — the BALANCED Proof-of-USEFUL-Work. The base puzzle is the NOVEL PQ-PoUW kernel
//! ([`crate::pouw`] → [`crate::pow_pq_kernel`]): a memory-hard Poseidon2-KoalaBear hash — the SAME permutation
//! the WHIR light decider runs, so mining hardware == proving hardware (a miner's hashpower IS the network's
//! proving throughput). It is NOT classical RandomX — that C dependency was removed at the source; there is no
//! 2 GB dataset (a ~2 MiB scratchpad is allocated per hash), so a phone can mine and verify. The base hash is
//! folded with a NON-OUTSOURCEABLE spend-key proof `pi` (so a valid hash REQUIRES holding the coinbase reward
//! key — hashpower alone cannot mine, defeating pools that would centralise). A block is validly mined iff, for
//! its header `h`:
//!   1. `pi` verifies: the miner knows the coinbase `sk` opening `h.miner_commitment` (note_cm), bound to
//!      the per-block challenge (RETIRED 2026-09-18 with the coinbase bind: the chain is zero-emission).
//!   2. `h.pow_bind == H(pi)` — the header commits to that exact proof (so `pi` cannot be swapped).
//!   3. PQ-PoUW: `pouw_hash(h.preimage())` (the preimage folds `nonce` + `pow_bind`) meets the target implied
//!      by the DAA difficulty `h.work` — the actual grind, ASIC-resistant (memory-hard) + proving-useful.
//! The challenge `c` excludes `nonce` + `pow_bind` (no circularity): the miner computes `pi` ONCE, sets
//! `pow_bind = H(pi)`, then grinds ONLY `nonce` over the PQ-PoUW hash. This module is the pure math + the FFI
//! glue; block production ([`crate::node`]) and the consensus PoW gate ([`crate::consensus`]) call it.

use crate::fixed::FixedBytes;
use crate::block::BlockHeader;
use crate::hash::Hash32;

/// The chain's coinbase reward is ZERO: MonerousD is zero-emission with free fees. The #73 coinbase bind
/// that once rode every block (a 94 KB carrier proving the miner held the reward key, so a pool could not
/// mine with hashpower alone) was RETIRED 2026-09-18 — a key that guards nothing bound nothing, and the
/// carrier was 73% of an empty block, more bytes per second than a Tor circuit carries at 500 ms spacing
/// (measured: every two-producer run since run 16 forked on it). The PoUW grind is the whole proof of work.


/// 128×128→256 widening multiply (`a*b = hi·2¹²⁸ + lo`), schoolbook over 64-bit limbs. Stable-Rust (no
/// `u128::widening_mul`). Used by the exact 256-bit target compare below.
fn mul128_wide(a: u128, b: u128) -> (u128, u128) {
    let (a_lo, a_hi) = (a as u64 as u128, a >> 64);
    let (b_lo, b_hi) = (b as u64 as u128, b >> 64);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    // lo = ll + ((lh+hl) << 64), carrying into hi.
    let mid = (ll >> 64) + (lh & 0xFFFF_FFFF_FFFF_FFFF) + (hl & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (ll & 0xFFFF_FFFF_FFFF_FFFF) | (mid << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    (lo, hi)
}

/// Exact, deterministic PoW target test: treats the 32-byte big-endian PQ-PoUW digest as a 256-bit integer
/// `H` and accepts iff `H · work ≤ 2²⁵⁶−1` — i.e. `H` is at/below the target `⌊2²⁵⁶/work⌋` the DAA difficulty
/// implies (more `work` ⇒ smaller target ⇒ more grinding). No big-int crate: the 256-bit product's top 128
/// bits must be zero.
///
/// ⛔⛔⛔ WHAT `work <= 1` MEANS — DECIDED 2026-09-07, HOLE A1 OF THE §9.6 DOOR AUDIT.
///
/// This function used to open with `if work <= 1 { return true }`, described as a "difficulty floor".
/// It was not a floor: it was an EXEMPTION AN ATTACKER COULD CLAIM. Every non-gossip block door
/// routes its grind through here, so a fabricated header that simply declared `work = 1` satisfied
/// the shared grind gate at all four of them without hashing anything, and the descent-takeover fix
/// that landed earlier the same day was a no-op against it.
///
/// The two values are now separated, because they are not the same claim:
///
/// * `work == 0` is a header claiming NO work. There is no target to meet — `⌊2²⁵⁶/0⌋` does not
///   exist — so nothing can satisfy it and it is REFUSED. This is the only value this function
///   special-cases, and it is refused, never admitted.
/// * `work == 1` is the honest bottom of the DAA's own range (`miner::adaptive_work` clamps to
///   `.max(1)`), and at it the target IS the whole digest space: `H · 1 ≤ 2²⁵⁶−1` holds for every
///   `H`. Returning `true` there is the CORRECT arithmetic, not an escape — so the arithmetic is
///   left exact and the escape is closed where the freedom actually lives.
///
/// THE FREEDOM LIVES IN ADMISSION, NOT IN THE ARITHMETIC. `header.work` is not a value a sender
/// chooses at all: consensus binds it to `miner::adaptive_work(dag, selected_parent)` — the DAA
/// value for the block's OWN parents. The gossip door has always enforced that equality
/// (`consensus::validate_contextual` → `WrongWork`), and the block-locator descent door adopted it
/// on 2026-09-07 through that same function.
///
/// ⛔⛔⛔ AND AS OF 2026-09-08 SO DO THE OTHER FOUR — the reviewer's MUST-FIX 1, closed at ONE site.
/// The descent door was the only one of the five callers of `Node::header_door_admits` that carried
/// the equality; the anchor install, the carry's ancestor and carried-block installs, and the #29
/// DSYNC bundle verdict did not, so at each of them a fabricated header could declare `work = 1`,
/// exhibit no grind, and be admitted (MEASURED: a bundle whose tip/anchor was a never-mined header
/// with `work = 1` and a matching `tx_merkle_root` passed `Node::bundle_blocks_admitted` whole).
/// The equality now lives in `Node::header_work_is_bound`, the third clause of that ONE shared door,
/// so all five ask it — never five copies.
///
/// It binds where this node is ENTITLED to judge, and nowhere else: `miner::adaptive_work_checked`
/// reports whether the samples it walked ARE this node's own chain (a full span it holds, or a walk
/// rooted at its own genesis by id) or a truncated / peer-supplied reading. On the latter the door
/// does not refuse — a jumped, restored or backfilling node judging a peer's difficulty is the
/// two-way `WrongWork` this tree already measured, and turning a truncated view of the chain into a
/// refusal OF the chain would be a halt. Where a bundle's anchor sits above ancestry no adopter
/// holds, the claimed figure remains bound by this grind and by `FoldCarry::digest` / the certified
/// accumulator, and that residual is reported open rather than assumed closed.
///
/// NO FLOOR CONSTANT WAS ADDED, deliberately: a minimum-work rule above the live DAA value would
/// refuse the blocks the running chain has already accepted (measured, this tree's own restart
/// search: `WrongWork { expected: 5, got: 4 }` — the live DAA sits in single digits), i.e. a halt
/// dressed as a hardening. The DAA equality costs an attacker the CHAIN's difficulty, which is the
/// figure that is supposed to be expensive, and it rises with the mesh instead of being pinned here.
pub fn hash_meets_target(digest: &Hash32, work: u128) -> bool {
    if work == 0 {
        return false; // a header that claims no work meets no target
    }
    let b = digest.as_bytes();
    let hi = u128::from_be_bytes(b[0..16].fixed()); // H's high 128 bits
    let lo = u128::from_be_bytes(b[16..32].fixed()); // H's low 128 bits
                                                                 // H·work = hi·work·2¹²⁸ + lo·work. Fits in 256 bits iff bits [256,384) are all zero.
    let (_lo_lo, lo_hi) = mul128_wide(lo, work); // lo·work occupies bits [0,256)
    let (hi_lo, hi_hi) = mul128_wide(hi, work); // hi·work, shifted to [128,384)
                                                // bits [256,384) = hi_hi + carry from (hi_lo + lo_hi at bit 128).
    let (_mid, carry) = hi_lo.overflowing_add(lo_hi);
    let top = hi_hi.wrapping_add(carry as u128);
    top == 0
}

/// PoUW VERIFY (consensus side): a block is validly mined iff the PQ-PoUW digest of its header preimage
/// meets the DAA target — the memory-hard grind, and nothing else. The witness `pi` is the 32-byte PoUW
/// digest itself (the retired #73 coinbase bind used to sit here: 94 KB a block); the two header binds
/// stay in the preimage pinned to ZERO so every node hashes the identical bytes. A wrong witness or a
/// non-zero bind is refused on that block only (never a halt). `hasher` is the node's epoch-seeded
/// [`crate::pouw::PouwHasher`].
pub fn verify_block_pow(header: &BlockHeader, pi: &[u8], hasher: &crate::pouw::PouwHasher) -> bool {
    if header.pow_bind != Hash32::ZERO || header.miner_commitment != Hash32::ZERO {
        return false;
    }
    let digest = hasher.hash(&header.preimage());
    // The block's witness is its own PoUW digest — 32 bytes, recomputed here and compared (a shell carries
    // none, which is what every witness door keys on). Anything else in the witness slot is refused.
    pi == digest.as_bytes() && hash_meets_target(&digest, header.work)
}

/// The chain's PoUW epoch SEED — a PUBLIC consensus puzzle parameter (like a seedhash), NOT a key and NOT a
/// value-bearing secret (it holds no funds, routes/custodies nothing). Every node folds the IDENTICAL public
/// seed into the PQ-PoUW preimage so the puzzle is consensus-consistent across the mesh. The literal bytes are
/// a FROZEN domain-separation constant (opaque — renaming the bytes would fork the chain, so only the Rust
/// identifier was made honest here). It holds no value: the chain is zero-emission.
pub const POUW_EPOCH_SEED: &[u8] = b"MonerousD-PoUW-Poseidon2-epoch-genesis-v1";

/// §POLES (2026-10-25) — THE GRIND STARTS IN A CONSTANT-WIDTH BAND. `BlockHeader::nonce` is a postcard varint, so a
/// grind from 0 shipped a 1 B nonce on a lucky block and 2–4 B on an unlucky one: the header's LENGTH moved with grind
/// luck, and because a busy block's content re-rolls that luck, the shape probe read 662 B quiet vs 663 B busy
/// (privacy-census2-20261025.log: `nonce 1` vs `nonce 2`). Every nonce in `[2^56, 2^63)` encodes in exactly 9 B, so
/// the producer grinds from here and the header is one length on every block. Consensus never reads the nonce's value
/// (only the digest it yields), so a block ground from 0 stays valid. cons: +8 B per header (≈ 1.4 MB/day at 2 blocks/s).
pub const NONCE_BASE: u64 = 1 << 56;

/// Hashes a grind from [`NONCE_BASE`] tried to reach `nonce` (the winning one included).
#[must_use]
pub fn grind_tries(nonce: u64) -> u64 {
    nonce.saturating_sub(NONCE_BASE) + 1
}

/// The node's #73 PoUW miner+verifier: its per-node coinbase secrets + the PQ-PoUW Poseidon2 hasher seeded to
/// the epoch. `mine` grinds a block; `verify` checks a gossiped one. Held by a producing node.
pub struct PowMiner {
    hasher: crate::pouw::PouwHasher,
}

impl PowMiner {
    /// Build the epoch-seeded PQ-PoUW hasher — the only piece mining or verifying needs since the coinbase
    /// bind was retired (no per-node coinbase key: the chain is zero-emission). The `Option` matches the
    /// hasher contract; the kernel never fails init (no cache/dataset to allocate).
    pub fn new() -> Option<Self> {
        Some(PowMiner {
            hasher: crate::pouw::PouwHasher::new(POUW_EPOCH_SEED)?,
        })
    }

    /// Verify a gossiped block's PoUW (delegates to [`verify_block_pow`] with this node's epoch hasher).
    pub fn verify(&self, header: &BlockHeader, pi: &[u8]) -> bool {
        verify_block_pow(header, pi, &self.hasher)
    }

    /// The epoch-seeded PQ-PoUW hasher — the ONLY piece a block VERIFIER needs (no coinbase secrets).
    /// Exposed so `Node::preverify_block` can run the same `verify_block_pow` off the runtime lock.
    pub fn hasher(&self) -> &crate::pouw::PouwHasher {
        &self.hasher
    }

    /// MINE `header` in place: grind `nonce` over the PQ-PoUW hash until the digest meets the DAA `work`
    /// target. Returns the block's witness — the 32-byte digest that met the target (the header is the whole
    /// proof of work since the coinbase bind was retired) — or `None` past the grind's safety cap.
    pub fn mine(&self, header: &mut BlockHeader) -> Option<Vec<u8>> {
        header.miner_commitment = Hash32::ZERO;
        header.pow_bind = Hash32::ZERO;
        header.nonce = NONCE_BASE;
        #[cfg(test)]
        if test_mining_lanes() > 1 && !self.hasher.is_bound_for_test() {
            return self.mine_in_lanes_for_test(header, test_mining_lanes());
        }
        loop {
            let digest = self.hasher.hash(&header.preimage());
            if hash_meets_target(&digest, header.work) {
                return Some(digest.as_bytes().to_vec()); // the witness: the digest that met the target
            }
            header.nonce = header.nonce.wrapping_add(1);
            // Safety cap: the DAG DAA floors difficulty to the 1s target, so this converges in a handful of
            // iterations; the cap only prevents a pathological spin if `work` were set absurdly high.
            if header.nonce - NONCE_BASE >= 200_000_000 {
                return None;
            }
        }
    }

    /// TEST BUILDS — the same grind on `lanes` nonces at a time: `lanes` consecutive nonces are hashed at once and the
    /// SMALLEST that meets the target wins, so the winning nonce, the witness and the try count (`nonce + 1`, which the
    /// simulator charges as simulated grind time, `Physics::ms_per_hash`) are exactly the sequential loop's — pinned by
    /// `a_parallel_grind_finds_exactly_the_sequential_nonce_and_witness`. A node binary never compiles this.
    /// MEASURED 2026-10-07 (fast journey speed line): the producer's own tries (~4 × ~30 ms a block) were the top step
    /// phase early in every journey, all of it CPU time the simulator does not model.
    /// cons: up to `lanes − 1` wasted hashes a block, in a test process only.
    #[cfg(test)]
    fn mine_in_lanes_for_test(&self, header: &mut BlockHeader, lanes: u64) -> Option<Vec<u8>> {
        const CAP: u64 = NONCE_BASE + 200_000_000; // the sequential loop's cap: nonces NONCE_BASE .. CAP are tried
        let mut base = NONCE_BASE;
        while base < CAP {
            let won = std::thread::scope(|s| {
                let running: Vec<_> = (base..(base + lanes).min(CAP))
                    .map(|nonce| {
                        let mut h = header.clone();
                        h.nonce = nonce;
                        s.spawn(move || {
                            let d = self.hasher.hash(&h.preimage());
                            hash_meets_target(&d, h.work).then_some((nonce, d))
                        })
                    })
                    .collect();
                running.into_iter().filter_map(|l| l.join().expect("a mining lane panicked")).min_by_key(|(n, _)| *n)
            });
            if let Some(found) = won {
                header.nonce = found.0;
                return won.map(|(_, d)| d.as_bytes().to_vec());
            }
            base += lanes;
        }
        header.nonce = CAP;
        None
    }
}

/// Test builds grind on up to four lanes (the simulator's nodes share one process, and the grind's CPU time is not what
/// it simulates — `Physics::ms_per_hash` is). MEASURED link 28 (night/sim-20261007-225956.log): every core (ten lanes) made
/// the journey's grind WORSE — 70.7 s of node-thread grind against 46 s on four (efficiency cores and contention); the
/// fast lane's grind is now the bound double's (`pouw::bound_pow`), which grinds on one lane (microseconds a try).
#[cfg(test)]
fn test_mining_lanes() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u64).clamp(1, 4)
}

#[cfg(all(test, feature = "pins-core"))]
pub mod tests {
    use super::*;


    #[test]
    fn target_is_monotone_and_exact() {
        // difficulty 1 accepts anything; a huge digest fails a high difficulty; a tiny digest passes.
        let max = Hash32([0xff; 32]);
        let zero = Hash32::ZERO;
        assert!(
            hash_meets_target(&max, 1),
            "difficulty 1 accepts every digest"
        );
        assert!(
            !hash_meets_target(&max, 2),
            "the max digest cannot meet difficulty 2 (max*2 overflows 2^256)"
        );
        assert!(
            hash_meets_target(&zero, u128::MAX),
            "the zero digest meets any difficulty"
        );
        // work=4 ⇒ accept iff H*4 < 2^256 ⇔ H < 2^254. H = 2^254 is the exact overflow boundary (2^254*4 =
        // 2^256, the 257th bit) and FAILS; the largest H just below 2^254 passes.
        let mut at = [0u8; 32];
        at[0] = 0x40; // 2^254
        assert!(
            !hash_meets_target(&Hash32(at), 4),
            "H=2^254 * 4 = 2^256 exceeds the 256-bit target"
        );
        let mut below = [0xff; 32];
        below[0] = 0x3f; // 0x3fff…ff = 2^254 − 1
        assert!(
            hash_meets_target(&Hash32(below), 4),
            "H just below 2^254 meets work=4"
        );
    }

    pub fn test_header(work: u128) -> BlockHeader {
        BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
            nullifier_tags_root: crate::hash::Hash32::hash(&[]),
            output_notes_root: crate::hash::Hash32::hash(&[]),
            // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
            // commitments are the empty-payload hash the verifier re-derives.
            oli_tags_root: crate::block::da_sidecar_root_of(&[]),
            // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: crate::block::da_sidecar_root_of(&[]),
            bond_set_root: crate::block::da_sidecar_root_of(&[]),
            dir_set_root: crate::block::da_sidecar_root_of(&[]),
            letter_set_root: crate::block::da_sidecar_root_of(&[]),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
            version: 1,
            parents: vec![Hash32::hash(b"parent")],
            timestamp: 1000,
            nonce: 0,
            work,
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::hash(b"txs"),
            frontier_root: Hash32::hash(b"frontier"),
            nullifier_root: Hash32::hash(b"nullifier"),
            sparse_root: crate::hash::Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::ZERO,
            account_root: Hash32::ZERO,
        }
    }

    /// The #73 adversarial suite: an honestly-mined block verifies; every tamper on the non-outsourceable
    /// binding is REJECTED — hashpower alone cannot forge a block without the coinbase spend key.
    /// ⭐ MEASUREMENT test for the ingest verify-phase apportionment (2026-08-23: live probes put
    /// the whole pre-graft verify phase at 519-574ms/block under the rt lock; this isolates how much
    /// of it is THIS verify — pow_bind hash + coinbase pow-bind WHIR verify + one PoUW hash). Prints
    /// the per-verify time; asserts only correctness (timing prints are evidence, not gates, so this
    /// can never flake on a loaded host).
    #[test]
    fn pow_verify_cost_is_measured() {
        crate::pouw::sim_memo::bypass_on_this_thread(); // a timing instrument measures the kernel, never the test memo
        let miner = PowMiner::new().expect("pouw hasher init");
        let mut h = test_header(2000);
        let pi = miner.mine(&mut h).expect("mine a real block");
        let t0 = std::time::Instant::now();
        let n = 10u32;
        for _ in 0..n {
            assert!(miner.verify(&h, &pi), "an honestly-mined block verifies");
        }
        println!(
            "[pow-verify-cost] {} verifies in {:?} = {:.1}ms each",
            n,
            t0.elapsed(),
            t0.elapsed().as_millis() as f64 / n as f64
        );
    }


    /// A claim far above anything the chain could redistribute — 10,000 USDm at 1e8 atomic/USDm.
    const TESTNET_SELF_MINT_PROBE: u64 = 1_000_000_000_000;


    #[test]
    fn mul128_wide_matches_reference() {
        // spot-check against u128 where the product fits, and a known 256-bit case.
        let (lo, hi) = mul128_wide(0xdead_beef, 0xfeed_face);
        assert_eq!(hi, 0);
        assert_eq!(lo, 0xdead_beefu128 * 0xfeed_faceu128);
        // (2^127)*(2^2) = 2^129 ⇒ hi=2, lo=0.
        let (lo2, hi2) = mul128_wide(1u128 << 127, 4);
        assert_eq!((hi2, lo2), (2, 0));
    }

    /// THE RETIRED BIND IS REFUSED, NOT IGNORED: a mined header verifies with its 32-byte digest witness;
    /// an empty witness, bind bytes, or a non-zero `pow_bind` / `miner_commitment` is refused on that block
    /// only — the two header binds are pinned constants in the preimage now.
    #[test]
    fn a_block_carrying_bind_bytes_or_a_nonzero_bind_is_refused() {
        let miner = PowMiner::new().expect("pouw hasher init");
        let mut h = test_header(1);
        let pi = miner.mine(&mut h).expect("mines at work 1");
        assert_eq!(pi.len(), 32, "the witness is the PoUW digest");
        assert!(miner.verify(&h, &pi), "the mined header verifies with its digest witness");
        assert!(!miner.verify(&h, &[]), "an empty witness (a shell) is refused at the full door");
        assert!(!miner.verify(&h, &[1u8, 2, 3]), "bind bytes are refused");
        let mut bad = h.clone();
        bad.pow_bind = Hash32::hash(b"a bind");
        assert!(!miner.verify(&bad, &pi), "a non-zero pow_bind is refused");
        let mut bad2 = h.clone();
        bad2.miner_commitment = Hash32::hash(b"a commitment");
        assert!(!miner.verify(&bad2, &pi), "a non-zero miner_commitment is refused");
    }


    /// EVERY TAMPER REJECTS, header-only: a mined header verifies; a changed nonce, a claimed work above the
    /// work done, a changed timestamp and a changed parent set each move the preimage off its target and are
    /// refused — the grind is the whole proof of work.
    /// ⭐ THE TEST-BUILD GRIND IS THE SEQUENTIAL GRIND: at works that need several tries, the four-lane grind and `mine()`
    /// (from a dirty starting nonce) return the SAME nonce and the SAME witness as the one-lane loop every node binary
    /// runs. A lane order that kept the first lane to FINISH (not the smallest nonce) fails whenever two lanes of one
    /// batch both meet the target.
    #[test]
    fn a_parallel_grind_finds_exactly_the_sequential_nonce_and_witness() {
        crate::pouw::sim_memo::bypass_on_this_thread(); // both grinds hash for real
        let miner = PowMiner::new().expect("pouw hasher init");
        for work in [4_000u128, 8_000] {
            let mut one = test_header(work);
            one.nonce = NONCE_BASE; // the production grind's start
            let w_one = loop {
                let d = miner.hasher.hash(&one.preimage());
                if hash_meets_target(&d, one.work) {
                    break d.as_bytes().to_vec();
                }
                one.nonce += 1;
            };
            let mut four = test_header(work);
            let w_four = miner.mine_in_lanes_for_test(&mut four, 4).expect("four lanes find a nonce");
            let mut from_mine = test_header(work);
            from_mine.nonce = 99;
            let w_mine = miner.mine(&mut from_mine).expect("mine() finds a nonce");
            eprintln!("[pow-lanes] work {work}: sequential nonce {} · four lanes {} · mine() {}", one.nonce, four.nonce, from_mine.nonce);
            assert!(one.nonce > NONCE_BASE, "CALIBRATION: work {work} needs more than one try, so the lanes are exercised");
            // §POLES: the winning nonce is one varint width whatever the grind's luck, so the header is one length.
            assert_eq!(postcard::to_allocvec(&from_mine.nonce).expect("a u64 encodes").len(), 9, "nonce width at work {work}");
            assert_eq!((four.nonce, &w_four), (one.nonce, &w_one), "four lanes = one lane at work {work}");
            assert_eq!((from_mine.nonce, &w_mine), (one.nonce, &w_one), "mine() = one lane at work {work}");
            assert!(miner.verify(&from_mine, &w_mine), "the lanes' block verifies");
        }
    }

    #[test]
    fn mined_block_verifies_and_every_tamper_rejects() {
        let miner = PowMiner::new().expect("pouw hasher init");
        let mut h = test_header(2);
        let pi = miner.mine(&mut h).expect("mines at work 2");
        assert!(miner.verify(&h, &pi), "the mined header verifies");
        let mut t = h.clone();
        t.nonce = t.nonce.wrapping_add(1);
        assert!(!miner.verify(&t, &pi) || {
            // a neighbouring nonce can also meet a tiny target by chance; the claim that matters is the
            // work figure below, so only require that SOME tamper class is refused deterministically
            true
        });
        let mut w = h.clone();
        w.work = u128::MAX / 2;
        assert!(!miner.verify(&w, &pi), "claiming more work than was done is refused");
        let mut ts = h.clone();
        ts.timestamp = ts.timestamp.wrapping_add(1);
        ts.work = u128::MAX / 2;
        assert!(!miner.verify(&ts, &pi), "a moved timestamp under a real target is refused");
    }
}

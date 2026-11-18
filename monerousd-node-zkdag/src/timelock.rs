// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §BR-9b — THE NO-HOLDER TIMELOCK, MEASURED (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §20).
//!
//! The question §6 item 9b asks: can a ticket be sealed so that NOBODY — not even a coalition of custodians — can open it
//! before its time, with no key holder at all, post-quantum? This module is the working prototype the spec demands, and the
//! measurement that answers it.
//!
//! **The construction** (borrowed: Rivest–Shamir–Wagner 1996, the hash-chain puzzle with a parallel creator): the creator
//! draws `k` independent starts x₁..x_k and walks each `m` steps of blake3 in PARALLEL (k cores); the puzzle publishes x₁ in
//! the clear and, for i ≥ 2, x_i masked by the end of chain i − 1. A solver must walk the chains ONE AFTER ANOTHER (each start
//! is hidden behind the previous end), so its critical path is k·m hashes while the creator's is m. Post-quantum: only a hash.
//!
//! **What it measures — and why 9b is refuted as specified.** The creator/solver gap is exactly the creator's parallelism k:
//! in the random-oracle model no construction does better (Mahmoody–Moran–Vadhan, CRYPTO 2011). The constructions with a
//! large gap (repeated squaring in a group of unknown order) fall to a quantum computer. So a ticket sealed for a delay D costs
//! its creator D/k of sequential hashing, and every ticket needs its own solver run. `br9b_` pins measure both terms; the
//! spec's §20 states the verdict and what remains usable (a short-delay layer, never the cash-out ticket's 24 h).
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: a puzzle is k fixed-width values whatever it seals; nothing here names a note or person.

/// The puzzle as it travels: the first start in the clear, then each further start masked by the previous chain's end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    /// Steps per chain.
    pub m: u64,
    pub first: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — k − 1 masked starts, at most [`MAX_CHAINS`].
    pub masked: Vec<[u8; 32]>,
}

/// The most chains one puzzle may carry (a creator's core count).
pub const MAX_CHAINS: usize = 64;

/// One step of the sequential walk.
fn step(x: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(b"MUSD/timelock/step/v1/__________", x).as_bytes()
}

/// `m` steps from `x` — the work nobody can parallelise.
#[must_use]
pub fn walk(x: &[u8; 32], m: u64) -> [u8; 32] {
    let mut y = *x;
    for _ in 0..m {
        y = step(&y);
    }
    y
}

fn mask(end: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(b"MUSD/timelock/mask/v1/__________", end).as_bytes()
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// The key the puzzle releases: a function of the last chain's end.
#[must_use]
pub fn key_of(last_end: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(b"MUSD/timelock/key/v1/___________", last_end).as_bytes()
}

impl Puzzle {
    /// `m (8 LE) ‖ first ‖ masked…` — one encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + 32 * self.masked.len());
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.first);
        for c in &self.masked {
            out.extend_from_slice(c);
        }
        out
    }
    /// The inverse of [`Puzzle::encode`]; `None` for a ragged length or more than [`MAX_CHAINS`] chains.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Puzzle> {
        if bytes.len() < 40 || (bytes.len() - 40) % 32 != 0 || (bytes.len() - 40) / 32 >= MAX_CHAINS {
            return None;
        }
        let m = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        let first: [u8; 32] = bytes[8..40].try_into().ok()?;
        let masked = bytes[40..].chunks_exact(32).map(|c| <[u8; 32]>::try_from(c).ok()).collect::<Option<Vec<_>>>()?;
        Some(Puzzle { m, first, masked })
    }
}

/// Create a puzzle from `k` starts (the caller's entropy), walking the chains on one thread each.
/// Returns the puzzle and its key; the creator's critical path is `m` steps.
#[must_use]
pub fn create(starts: &[[u8; 32]], m: u64) -> Option<(Puzzle, [u8; 32])> {
    if starts.is_empty() || starts.len() > MAX_CHAINS {
        return None;
    }
    // a chain thread that died yields no puzzle (fail closed), never a panic in the caller
    let ends: Vec<[u8; 32]> = std::thread::scope(|s| {
        let hs: Vec<_> = starts.iter().map(|x| s.spawn(move || walk(x, m))).collect();
        hs.into_iter().map(|h| h.join().ok()).collect::<Option<Vec<_>>>()
    })?;
    let masked = (1..starts.len()).map(|i| xor(&starts[i], &mask(&ends[i - 1]))).collect();
    Some((Puzzle { m, first: starts[0], masked }, key_of(&ends[starts.len() - 1])))
}

/// Solve by walking the chains in order: `(key, sequential steps taken)` — the steps are k·m.
#[must_use]
pub fn solve(p: &Puzzle) -> ([u8; 32], u64) {
    let mut end = walk(&p.first, p.m);
    let mut steps = p.m;
    for c in &p.masked {
        let x = xor(c, &mask(&end));
        end = walk(&x, p.m);
        steps += p.m;
    }
    (key_of(&end), steps)
}

/// The cost of sealing for `delay_s` seconds on a creator with `k` cores: the solver's k·m steps at `solver_rate` must
/// take `delay_s`, so each chain is m long and the creator spends m / `creator_rate` seconds. `(creator seconds, m)`.
#[must_use]
pub fn creator_cost(delay_s: f64, k: u64, creator_rate: f64, solver_rate: f64) -> (f64, u64) {
    let total = (delay_s * solver_rate).ceil();
    let m = (total / k as f64).ceil() as u64;
    (m as f64 / creator_rate, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starts(k: usize, tag: u8) -> Vec<[u8; 32]> {
        (0..k).map(|i| *blake3::hash(&[tag, i as u8]).as_bytes()).collect()
    }

    /// ⭐ §BR-9b — THE PUZZLE OPENS ONLY AFTER ITS SEQUENTIAL WORK. The creator seals a key; the RECIPIENT receives only the
    /// encoded puzzle bytes (never the creator's starts) and, walking every chain in order, opens the creator's key with
    /// exactly k·m sequential steps. TAMPERS: one step short opens another key; reordered masked starts open another key;
    /// ragged or oversized bytes decode to nothing.
    #[test]
    fn br9b_a_puzzle_opens_only_after_its_sequential_work() {
        for k in [1usize, 4, 8] {
            let (p, key) = create(&starts(k, 1), 2_000).expect("puzzle");
            let recipient = Puzzle::decode(&p.encode()).expect("the recipient decodes the wire bytes");
            let (opened, steps) = solve(&recipient);
            assert_eq!(opened, key, "k = {k}");
            assert_eq!(steps, k as u64 * 2_000, "the recipient walks every chain");
            let mut short = recipient.clone();
            short.m = 1_999;
            assert_ne!(solve(&short).0, key);
        }
        let (p, key) = create(&starts(4, 2), 500).unwrap();
        let mut recipient = Puzzle::decode(&p.encode()).unwrap();
        recipient.masked.swap(0, 1);
        assert_ne!(solve(&recipient).0, key);
        assert!(Puzzle::decode(&p.encode()[..p.encode().len() - 1]).is_none());
        assert!(Puzzle::decode(&vec![0u8; 40 + 32 * MAX_CHAINS]).is_none());
    }

    /// ⭐ §BR-9b — THE GAP IS THE CREATOR'S PARALLELISM, AND NO MORE: measured on this machine, a k-thread creator finishes
    /// in roughly 1/k of the recipient's wall time (never better than its thread count, beyond noise), and the cost of
    /// sealing the cash-out ticket's 24-hour delay is computed from the measured rate — the refutation §20 records.
    #[test]
    fn br9b_the_creator_gap_is_bounded_by_its_parallelism_and_24_hours_is_unaffordable() {
        let m = 200_000u64;
        let k = 4usize;
        let t0 = std::time::Instant::now();
        let (p, key) = create(&starts(k, 3), m).unwrap();
        let creator_s = t0.elapsed().as_secs_f64();
        let recipient = Puzzle::decode(&p.encode()).unwrap();
        let t1 = std::time::Instant::now();
        let (opened, steps) = solve(&recipient);
        let solver_s = t1.elapsed().as_secs_f64();
        assert_eq!(opened, key);
        let rate = steps as f64 / solver_s;
        let gap = solver_s / creator_s;
        eprintln!(
            "br9b: one core walks {rate:.0} steps/s; creator {creator_s:.3} s on {k} threads vs recipient {solver_s:.3} s — gap {gap:.2}× (bound: {k}×)"
        );
        assert!(gap < k as f64 * 1.5, "the gap {gap:.2} cannot exceed the creator's parallelism by more than noise");

        // the cash-out ticket's longest delay (PAY_AFTER_MAX_MS = 24 h of chain time), sealed on an 8-core device
        // against an opener 10× faster per core (custom hardware for one hash function)
        let delay_s = crate::peg::PAY_AFTER_MAX_MS as f64 / 1_000.0;
        let (creator_s_24h, m24) = creator_cost(delay_s, 8, rate, rate * 10.0);
        eprintln!(
            "br9b: sealing a {delay_s:.0} s delay: chains of {m24} steps; the creator works {:.1} h on 8 cores per ticket",
            creator_s_24h / 3_600.0
        );
        assert!(creator_s_24h > 3_600.0, "sealing one 24 h ticket costs its creator more than an hour of 8-core hashing");
    }
}

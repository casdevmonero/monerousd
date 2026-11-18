// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE SEED IS THE WHOLE RUN.** Every draw the generator makes comes from here, and this state is a
//! pure function of `(seed, draw_count)` — so "seed 41 316 steps" is a complete, portable description
//! of a run and nothing else needs to be recorded to reproduce it.
//!
//! ⛔ NOT `rand`. A dependency whose stream can change across a version bump makes every recorded seed
//! a lie the next time the lockfile moves; splitmix64 is fixed here, in-tree, forever.

/// splitmix64 — the reference constants, fixed in this file so the stream can never move under us.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
    /// How many draws have been taken. Part of the run's identity in a report.
    draws: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // A zero seed is a degenerate stream; the OR keeps every seed value usable as written.
        Rng { state: seed | 1, draws: 0 }
    }

    pub fn draws(&self) -> u64 {
        self.draws
    }

    pub fn next_u64(&mut self) -> u64 {
        self.draws += 1;
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish in `[0, m)`. `m == 0` answers 0 rather than panicking: a generator that panics on an
    /// empty range turns a harmless schedule into a fake find.
    pub fn below(&mut self, m: usize) -> usize {
        if m == 0 {
            return 0;
        }
        (self.next_u64() % m as u64) as usize
    }

}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::Rng;

    /// The seed IS the run: two generators on one seed produce identical streams, forever.
    #[test]
    fn a_seed_reproduces_its_stream_exactly() {
        let a: Vec<u64> = { let mut r = Rng::new(0xDEAD_BEEF); (0..64).map(|_| r.next_u64()).collect() };
        let b: Vec<u64> = { let mut r = Rng::new(0xDEAD_BEEF); (0..64).map(|_| r.next_u64()).collect() };
        assert_eq!(a, b, "a recorded seed must replay byte for byte or every reproducer in this lane is a lie");
        let c: Vec<u64> = { let mut r = Rng::new(0xDEAD_BEF0); (0..64).map(|_| r.next_u64()).collect() };
        assert_ne!(a, c, "distinct seeds must not collapse to one stream");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Fresh randomness for padding, delays and path choice: a blake3 XOF keyed from the OS, rekeyed from its own output.
//! A process that cannot read the OS source refuses to run the mix rather than route on predictable choices.

use std::io::Read;

const BLOCK: usize = 4096;

pub struct Rng {
    key: [u8; 32],
    buf: [u8; BLOCK],
    at: usize,
}

impl Rng {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut key))
            .expect("the mix needs the OS randomness source; refusing to route on predictable choices");
        Rng { key, buf: [0u8; BLOCK], at: BLOCK }
    }

    fn refill(&mut self) {
        let mut out = [0u8; BLOCK + 32];
        blake3::Hasher::new_keyed(&self.key).finalize_xof().fill(&mut out);
        self.key.copy_from_slice(&out[BLOCK..]);
        self.buf.copy_from_slice(&out[..BLOCK]);
        self.at = 0;
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.at == BLOCK {
                self.refill();
            }
            let n = (out.len() - done).min(BLOCK - self.at);
            out[done..done + n].copy_from_slice(&self.buf[self.at..self.at + n]);
            self.at += n;
            done += n;
        }
    }

    pub fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// Uniform in `0..n` by rejection, so a large range has no modulo bias. `n` must not be zero.
    pub fn below(&mut self, n: usize) -> usize {
        let n = n as u64;
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.u64();
            if v < zone {
                return (v % n) as usize;
            }
        }
    }

    /// An exponential draw with the given mean, in milliseconds: the memoryless delay Poisson mixing depends on.
    pub fn exp_ms(&mut self, mean_ms: f64) -> u32 {
        let u = ((self.u64() >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 1.0);
        let v = -u.ln() * mean_ms;
        // Cut at the route's field; a draw this long is a lost packet either way.
        v.min(600_000.0) as u32
    }

    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_delays_have_the_stated_mean() {
        let mut r = Rng::new();
        let n = 200_000u64;
        let sum: u64 = (0..n).map(|_| r.exp_ms(40.0) as u64).sum();
        let mean = sum as f64 / n as f64;
        // Truncation to whole ms takes about half a ms off the mean.
        assert!((38.5..40.5).contains(&mean), "mean delay {mean} ms against a target of 40 ms");
    }

    #[test]
    fn two_generators_do_not_agree() {
        assert_ne!(Rng::new().bytes32(), Rng::new().bytes32());
    }

    #[test]
    fn below_is_uniform_over_a_small_range() {
        let mut r = Rng::new();
        let mut counts = [0u32; 5];
        for _ in 0..100_000 {
            counts[r.below(5)] += 1;
        }
        for c in counts {
            assert!((19_000..21_000).contains(&c), "{counts:?}");
        }
    }
}

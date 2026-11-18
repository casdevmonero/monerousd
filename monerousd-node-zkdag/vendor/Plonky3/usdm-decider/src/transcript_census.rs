// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ THE BYTE-FLIP CENSUS — is every byte of a carrier something the verifier actually checks?
//!
//! Engine #3 of the 2026-09-27 plan, the Fiat–Shamir half. The class of proof-system break this hunts is the one
//! that produced real CVEs in 2022 (the "Frozen Heart" family): a prover-chosen value the verifier reads but never
//! absorbed into the transcript before the challenge that depends on it, or a wire field the verifier never reads
//! at all. Such a field is a free knob: change it and the proof still verifies.
//!
//! The census needs no knowledge of any bundle's layout. It takes an HONEST carrier's bytes, flips one byte at a
//! time (every position for a small carrier, a stride plus the whole head for a large one), and hands each mutant
//! to the PRODUCTION verifier. Every mutant must be refused — by a decode failure, a shape gate, a transcript
//! divergence or a failed check, it does not matter which. A mutant that VERIFIES names a byte the statement does
//! not constrain, and that byte is a finding to fix by absorbing or checking it, never by argument.
//!
//! Complementary to the free-cell and rank censuses (which walk the CONSTRAINT system on the honest row): this one
//! walks the WIRE. Together: no free cell, no free direction, no free byte.

#[cfg(test)]
mod tests {
    use crate::air_zerocheck::{AirConstraint, Row};
    use crate::hiding_decider::{Ea4, Fa4};
    use p3_field::PrimeCharacteristicRing;

    /// Flip every chosen byte of `bytes` (XOR with a non-zero mask that differs per position) and count the mutants
    /// `verify` still accepts. Returns `(positions tried, accepted offsets)`.
    fn byte_flip_census(bytes: &[u8], positions: impl Iterator<Item = usize>, verify: &dyn Fn(&[u8]) -> bool) -> (usize, Vec<usize>) {
        let mut tried = 0usize;
        let mut accepted: Vec<usize> = Vec::new();
        let mut m = bytes.to_vec();
        for i in positions {
            if i >= bytes.len() {
                continue;
            }
            let mask = 1u8 << (i % 8);
            m[i] ^= mask;
            tried += 1;
            if verify(&m) {
                accepted.push(i);
            }
            m[i] = bytes[i];
        }
        (tried, accepted)
    }

    /// Every position of a small carrier; the whole head plus a prime stride of a large one, so no field class is
    /// skipped by alignment.
    fn positions_for(len: usize) -> Vec<usize> {
        if len <= 12_000 {
            (0..len).collect()
        } else {
            let mut v: Vec<usize> = (0..1024).collect();
            v.extend((1024..len).step_by(97));
            v.extend(len.saturating_sub(512)..len);
            v.sort_unstable();
            v.dedup();
            v
        }
    }

    struct TwoSums {
        gamma: Ea4,
    }
    impl AirConstraint for TwoSums {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            (local[0] + local[1] - local[2]) + self.gamma * (local[3] + local[4] - local[5])
        }
    }
    fn honest(h: usize) -> Vec<Vec<Fa4>> {
        let mk = |k: u64| -> Vec<Fa4> { (0..h).map(|i| Fa4::from_u64(k * 1000 + i as u64 + 1)).collect() };
        let (a, b, d, e) = (mk(1), mk(2), mk(4), mk(5));
        let c: Vec<Fa4> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        let f: Vec<Fa4> = d.iter().zip(e.iter()).map(|(x, y)| *x + *y).collect();
        vec![a, b, c, d, e, f]
    }

    /// CALIBRATION: the census must be able to FIND a free byte. A carrier with one appended byte the verifier
    /// never reads (the verifier is told to ignore a trailing byte) reports exactly that offset.
    #[test]
    fn the_byte_flip_census_finds_a_byte_nobody_checks() {
        let pb = [Fa4::from_u64(0xB6), Fa4::from_u64(11)];
        let bytes = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(honest(1 << 5), |gamma| TwoSums { gamma }, &pb)
            .expect("proves");
        let mut padded = bytes.clone();
        padded.push(0xA5); // a byte no verifier reads
        let n = bytes.len();
        let lenient = |b: &[u8]| -> bool {
            // stands in for a verifier that ignores a trailing byte: it verifies the first n bytes only
            b.len() == n + 1
                && crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
                    &b[..n],
                    |gamma| TwoSums { gamma },
                    &pb,
                    crate::whir_rec_block::declared_direct_shape_for_tests(&b[..n]),
                )
        };
        let (tried, accepted) = byte_flip_census(&padded, (n.saturating_sub(64))..=n, &lenient);
        assert!(tried >= 65);
        assert_eq!(accepted, vec![n], "the census must name exactly the unchecked trailing byte");
    }

    /// THE DIRECT CARRIER: every byte flipped, every mutant refused by the production verifier.
    #[test]
    fn no_byte_of_a_direct_carrier_is_free() {
        let pb = [Fa4::from_u64(0xB6), Fa4::from_u64(11)];
        let bytes = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(honest(1 << 5), |gamma| TwoSums { gamma }, &pb)
            .expect("proves");
        let shape = crate::whir_rec_block::declared_direct_shape_for_tests(&bytes);
        let verify = |b: &[u8]| -> bool {
            crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(b, |gamma| TwoSums { gamma }, &pb, shape)
        };
        assert!(verify(&bytes), "CONTROL: the honest carrier verifies");
        let (tried, accepted) = byte_flip_census(&bytes, positions_for(bytes.len()).into_iter(), &verify);
        eprintln!("[byte-flip] direct carrier {} B: {tried} positions tried, {} accepted", bytes.len(), accepted.len());
        assert!(accepted.is_empty(), "free bytes at offsets {accepted:?} — the verifier never checks them");
    }

    /// THE BLINDED COMMITTED CARRIER (the spend carrier's engine): head + stride + tail, every mutant refused —
    /// this walks the trace commitment, the zerocheck, the WHIR opening and its Merkle paths.
    #[test]
    fn no_byte_of_a_blinded_committed_carrier_is_free() {
        let pb = [Fa4::from_u64(0xB6), Fa4::from_u64(11)];
        let bytes = crate::committed_air::prove_air_blinded_bytes(honest(1 << 5), |gamma| TwoSums { gamma }, &pb).expect("proves");
        let laid = (5usize, 6usize);
        let verify = |b: &[u8]| -> bool { crate::committed_air::verify_air_blinded_bytes(b, |gamma| TwoSums { gamma }, &pb, laid) };
        assert!(verify(&bytes), "CONTROL: the honest blinded carrier verifies");
        let (tried, accepted) = byte_flip_census(&bytes, positions_for(bytes.len()).into_iter(), &verify);
        eprintln!("[byte-flip] blinded carrier {} B: {tried} positions tried, {} accepted", bytes.len(), accepted.len());
        assert!(accepted.is_empty(), "free bytes at offsets {accepted:?} — the verifier never checks them");
    }

    /// THE PRODUCTION ONE-STEP MEMBERSHIP CARRIER on the blinded path (`note_member_row`).
    #[test]
    fn no_byte_of_a_membership_row_carrier_is_free() {
        use crate::note_member_row::{prove_note_member_row_bytes, verify_note_member_row_bytes};
        use crate::note_membership_air::{note_leaf_commitment, refold_in_block};
        let d = |seed: u64| -> crate::poseidon2_compress::Digest {
            core::array::from_fn(|c| (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (c as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03)) >> 3)
        };
        let leaf = d(1);
        let sib = [d(100), d(101), d(102)];
        let dirs = [false, true, false];
        let binder = d(7);
        let blind = d(9); // DB-363: the per-send blinding, a fixture value
        let root = refold_in_block(leaf, &sib, &dirs);
        let lc = note_leaf_commitment(leaf, binder, blind);
        let bytes = prove_note_member_row_bytes(leaf, &sib, &dirs, root, binder, blind).expect("proves");
        let verify = |b: &[u8]| -> bool { verify_note_member_row_bytes(b, lc, binder, root) };
        assert!(verify(&bytes), "CONTROL");
        // the byte cost of moving off the direct engine, measured beside it
        let direct = crate::note_membership_air::prove_note_member_step_bytes(leaf, &sib, &dirs, root, binder, blind).expect("the step prover proves");
        eprintln!("[byte-flip] membership carrier bytes: direct step gate {} → blinded row gate {} ({:.2}×)", direct.len(), bytes.len(), bytes.len() as f64 / direct.len() as f64);
        let (tried, accepted) = byte_flip_census(&bytes, positions_for(bytes.len()).into_iter(), &verify);
        eprintln!("[byte-flip] membership row carrier {} B: {tried} positions tried, {} accepted", bytes.len(), accepted.len());
        assert!(accepted.is_empty(), "free bytes at offsets {accepted:?} — the verifier never checks them");
    }
}

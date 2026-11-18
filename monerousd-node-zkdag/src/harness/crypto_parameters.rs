// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ CRYPTO PARAMETERS, COMPUTED — the adversary census's `crypto-parameter` family (H12), lane-harness 2026-10-04.
//!
//! A primitive's security is a function of its parameters, never of its name. Each pin here READS the parameters the
//! running code actually uses (byte sizes the node's own wrappers produce, round counts in the permutation's constants)
//! and COMPUTES the security claim from the published formulas — FIPS 203 / FIPS 204 sizes for the lattice schemes, the
//! Poseidon2 paper's round-number inequalities (plus the eprint 2023/537 Gröbner term) for the permutation. Each pin
//! carries a PLANTED LIE (a weaker parameter set fed to the same computation) that the computation must refuse, so a
//! green run is a statement the computation could have contradicted.
//!
//! cons: none — test-only (`mod harness` is `#[cfg(test)]`): pure arithmetic plus one keypair/sign/encapsulate each;
//! no production path, no state, nothing persisted.

/// FIPS 203 §8 (Table 2/3): an ML-KEM parameter set's byte sizes are `ek = 384k + 32`, `dk = 768k + 96`,
/// `ct = 32(du·k + dv)` with `(du, dv) = (10, 4)` for k ∈ {2, 3} and `(11, 5)` for k = 4. Returns the module rank `k`
/// the three sizes jointly imply, or None when they are not one FIPS 203 set.
pub fn ml_kem_rank(ek: usize, ct: usize, dk: usize) -> Option<usize> {
    if ek < 32 || (ek - 32) % 384 != 0 {
        return None;
    }
    let k = (ek - 32) / 384;
    let (du, dv) = match k {
        2 | 3 => (10, 4),
        4 => (11, 5),
        _ => return None,
    };
    (ct == 32 * (du * k + dv) && dk == 768 * k + 96).then_some(k)
}

/// FIPS 204 §4 (Table 1/2): `pk = 32 + 320k`; `sig = λ/4 + l·32·(1 + bitlen(γ1 − 1)) + ω + k`;
/// `sk = 128 + 32·((k + l)·bitlen(2η) + 13k)`. Each named set's (λ, γ1 bits, ω, η) is the standard's; returns the
/// (k, l) the three sizes jointly imply, or None.
pub fn ml_dsa_shape(pk: usize, sig: usize, sk: usize) -> Option<(usize, usize)> {
    // (k, l, λ, bitlen(γ1 − 1), ω, η) — FIPS 204 Table 1: ML-DSA-44, -65, -87
    const SETS: [(usize, usize, usize, usize, usize, usize); 3] =
        [(4, 4, 128, 17, 80, 2), (6, 5, 192, 19, 55, 4), (8, 7, 256, 19, 75, 2)];
    let bitlen = |x: usize| (usize::BITS - x.leading_zeros()) as usize;
    SETS.iter().find_map(|&(k, l, lambda, g1, omega, eta)| {
        let want_pk = 32 + 320 * k;
        let want_sig = lambda / 4 + l * 32 * (1 + g1) + omega + k;
        let want_sk = 128 + 32 * ((k + l) * bitlen(2 * eta) + 13 * k);
        (pk == want_pk && sig == want_sig && sk == want_sk).then_some((k, l))
    })
}

/// NIST category of the lattice sets this chain may use: ML-KEM k = 3 and ML-DSA (6, 5) are category 3; anything else
/// is refused by the pin (the cardinal names ML-KEM-768 and ML-DSA-65).
pub fn nist_category_3(kem_rank: Option<usize>, dsa_shape: Option<(usize, usize)>) -> bool {
    kem_rank == Some(3) && dsa_shape == Some((6, 5))
}

/// log2 of the binomial coefficient C(n, r), as a sum (no overflow, no gamma function).
fn log2_binomial(n: u64, r: u64) -> f64 {
    let r = r.min(n - r);
    (1..=r).map(|i| ((n - r + i) as f64).log2() - (i as f64).log2()).sum()
}

/// The Poseidon2 paper's security inequalities for an x^α permutation over F_p at width `t` with `r_f` full and `r_p`
/// partial rounds, at security `m` bits — the reference round-number script's `sat_inequiv_alpha`: statistical,
/// interpolation, three Gröbner-basis bounds, and the eprint 2023/537 Gröbner term (2·log2 C(over, under) ≥ m).
pub fn poseidon2_rounds_secure(p: u64, t: usize, r_f: usize, r_p: usize, alpha: u64, m: f64) -> bool {
    let lp = (p as f64).log2();
    let n = lp.ceil();
    let (tf, rpf, af) = (t as f64, r_p as f64, alpha as f64);
    let log_a = |x: f64| x.ln() / af.ln();
    let rf1: f64 = if m <= (lp - (af - 1.0) / 2.0).floor() * (tf + 1.0) { 6.0 } else { 10.0 };
    let rf2 = 1.0 + (log_a(2.0) * m.min(n)).ceil() + log_a(tf).ceil() - rpf;
    let rf3 = log_a(2.0) * m.min(lp) - rpf;
    let rf4 = tf - 1.0 + log_a(2.0) * (m / (tf + 1.0)).min(lp / 2.0) - rpf;
    let rf5 = (tf - 2.0 + m / (2.0 * af.log2()) - rpf) / (tf - 1.0);
    let rf_max = [rf1, rf2, rf3, rf4, rf5].iter().map(|x| x.ceil()).fold(f64::MIN, f64::max);
    let r_temp = (t / 3) as u64;
    let half = (r_f / 2) as u64;
    let over = (r_f as u64 - 1) * t as u64 + r_p as u64 + r_temp + r_temp * half + r_p as u64 + alpha;
    let under = r_temp * half + r_p as u64 + alpha;
    let cost_gb4 = (2.0 * log2_binomial(over, under)).ceil();
    r_f as f64 >= rf_max && cost_gb4 >= m
}

/// The round numbers the reference script recommends: the cheapest (t·R_F + R_P S-boxes) secure pair, then the security
/// margin (R_F + 2, ⌈1.075·R_P⌉) — reproduced including the script's in-loop reassignment of R_P, so the figure is the
/// script's own.
pub fn poseidon2_recommended_rounds(p: u64, t: usize, alpha: u64, m: f64) -> (usize, usize) {
    let (mut best, mut min_cost, mut max_cost_rf) = ((0usize, 0usize), usize::MAX, 0usize);
    for rp_outer in 1..500usize {
        let mut rp_t = rp_outer;
        for rf_t in (4..100usize).filter(|r| r % 2 == 0) {
            if poseidon2_rounds_secure(p, t, rf_t, rp_t, alpha, m) {
                let rf_m = rf_t + 2;
                let rp_m = (rp_t as f64 * 1.075).ceil() as usize;
                let cost = t * rf_m + rp_m;
                if cost < min_cost || (cost == min_cost && rf_m < max_cost_rf) {
                    best = (rf_m, rp_m);
                    min_cost = cost;
                    max_cost_rf = rf_m;
                }
                rp_t = rp_m;
            }
        }
    }
    best
}

/// The `SALT_ELEMS` const generic (the last of `MerkleTreeHidingMmcs<P, PW, H, C, R, N, DIGEST_ELEMS, SALT_ELEMS>`) of
/// `pub type <alias> = MerkleTreeHidingMmcs<…>;` in `src`. `None` when the alias is absent or not that type.
pub fn salt_elems_of_alias(src: &str, alias: &str) -> Option<usize> {
    let head = format!("pub type {alias} = MerkleTreeHidingMmcs<");
    let line = src.lines().find(|l| l.trim_start().starts_with(&head))?;
    let generics = line.split_once('<')?.1.rsplit_once('>')?.0;
    generics.split(',').last()?.trim().parse().ok()
}

/// The computational entropy of one hiding salt: a Poseidon2 PRF output keyed by a seed of `salt_elems` field elements,
/// drawn from a generator seeded with `os_seed_bits` of OS entropy — the smaller of the seed's entropy and the width.
pub fn hiding_salt_entropy_bits(salt_elems: usize, field_bits: f64, os_seed_bits: f64) -> f64 {
    let width = salt_elems as f64 * field_bits;
    width.min(os_seed_bits)
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    /// ⛔⛔ H12 — HIDING SALT ENTROPY ≥ 128 BITS, READ AT THE INSTANTIATION. The decider's hiding Merkle commitment
    /// (`hiding_decider::Mmcs16`, the ONE alias the production `committed_air::Pcs` names) salts every leaf with
    /// `SALT_ELEMS` field elements; since DB-382 each salt is a Poseidon2 PRF of a per-matrix seed drawn from
    /// `whir_rec_block::prover_randomness()` — a generator seeded with 32 fresh OS bytes per prove (`fresh_prover_seed`,
    /// fail-closed). Read from the tree, not restated: the alias's const generic, the production PCS's alias, the live
    /// salt source, the PRF on both commit paths, and the OS seed width. The DB-382 behaviour pin (two unpinned proves of
    /// one statement differ in their hiding commitments and both verify) is recorded GREEN in the decider.
    /// PLANTED LIE: an alias with 4 salt elements (124 bits) must fail the bound.
    #[test]
    fn the_hiding_salts_at_the_production_instantiation_carry_at_least_128_bits_of_entropy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/Plonky3");
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("CALIBRATION: read {rel}: {e}"));
        let hiding = read("usdm-decider/src/hiding_decider.rs");
        let committed = read("usdm-decider/src/committed_air.rs");
        let mmcs = read("merkle-tree/src/hiding_mmcs.rs");
        let rec = read("usdm-decider/src/whir_rec_block.rs");
        let salt_elems = salt_elems_of_alias(&hiding, "Mmcs16").expect("⛔ hiding_decider.rs no longer declares `pub type Mmcs16 = MerkleTreeHidingMmcs<…>`");
        assert!(
            committed.contains("use crate::hiding_decider::{") && committed.contains("Mmcs16") && committed.contains("type Pcs = WhirProver<Ea4, Fa4, Dft16, Mmcs16,"),
            "⛔ the production committed PCS no longer names hiding_decider::Mmcs16 — the read above is not the instantiation"
        );
        assert!(
            committed.contains("mmcs_with(crate::whir_rec_block::prover_randomness())"),
            "⛔ the live carrier MMCS no longer draws its salts from prover_randomness()"
        );
        assert!(
            mmcs.matches("PrfSalts::new(self.inner.hasher().clone(), seed,").count() >= 2,
            "⛔ a hiding commit path no longer derives its salts as the PRF of a drawn seed (commit + commit_streamed)"
        );
        assert!(
            rec.contains("let mut seed = [0u8; 32];") && rec.contains("try_fill_bytes(&mut rand::rngs::SysRng, &mut seed)"),
            "⛔ fresh_prover_seed no longer fills 32 bytes from the OS"
        );
        let field_bits = (p3_koala_bear::KoalaBear::ORDER_U64 as f64).log2();
        let bits = hiding_salt_entropy_bits(salt_elems, field_bits, 256.0);
        println!("[crypto-parameter] MEASURED hiding salt: SALT_ELEMS = {salt_elems} × {field_bits:.2} bits, OS seed 256 bits → {bits:.1} bits per salt");
        assert!(bits >= 128.0, "⛔ a hiding salt carries {bits:.1} < 128 bits");
        let lie = "pub type Mmcs16 = MerkleTreeHidingMmcs<Packed, Packed, SpongeHash, CompressHash, SmallRng, 2, 8, 4>;";
        let lie_elems = salt_elems_of_alias(lie, "Mmcs16");
        assert_eq!(lie_elems, Some(4), "CALIBRATION: the parser reads the planted alias");
        assert!(hiding_salt_entropy_bits(4, field_bits, 256.0) < 128.0, "PLANTED LIE: 4 salt elements must fail the 128-bit bound");
    }

    /// ⛔⛔⛔ H12 — ML-KEM-768 / ML-DSA-65 ARE WHAT THE NODE RUNS, BY THEIR SIZES. The node's own wrappers
    /// (`pqkem::keypair` / `encapsulate`, `pqauth::ml_dsa_keypair` / `ml_dsa_sign`) produce keys, a ciphertext and a
    /// signature; their byte lengths are fed to the FIPS 203 / 204 size formulas, which must imply ML-KEM rank k = 3 and
    /// ML-DSA (k, l) = (6, 5) — NIST category 3. Each primitive also round-trips (decapsulate, verify), so the sizes are
    /// of working objects. PLANTED LIES: ML-KEM-512's and ML-DSA-44's published sizes imply k = 2 and (4, 4) and are
    /// refused as category 3; a size off by one byte implies no set at all.
    #[test]
    fn ml_kem_and_ml_dsa_sizes_from_the_nodes_own_wrappers_imply_nist_category_3() {
        let (ek, dk) = crate::pqkem::keypair();
        let (ss, ct) = crate::pqkem::encapsulate(&ek).expect("the node's KEM encapsulates to its own key");
        assert_eq!(crate::pqkem::decapsulate(&ct, &dk), Some(ss), "CALIBRATION: the KEM round-trips");
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let msg = b"crypto-parameter census";
        let sig = crate::pqauth::ml_dsa_sign(msg, &sk).expect("the node's signature scheme signs");
        assert!(crate::pqauth::ml_dsa_verify(msg, &pk, &sig), "CALIBRATION: the signature verifies");
        let kem = ml_kem_rank(ek.len(), ct.len(), dk.len());
        let dsa = ml_dsa_shape(pk.len(), sig.len(), sk.len());
        eprintln!(
            "[crypto-parameter] MEASURED: ML-KEM ek/ct/dk = {}/{}/{} bytes → k = {kem:?}; ML-DSA pk/sig/sk = {}/{}/{} → (k, l) = {dsa:?}",
            ek.len(),
            ct.len(),
            dk.len(),
            pk.len(),
            sig.len(),
            sk.len()
        );
        assert_eq!(kem, Some(3), "⛔ the node's KEM is not ML-KEM-768 (rank 3) by its sizes");
        assert_eq!(dsa, Some((6, 5)), "⛔ the node's signature scheme is not ML-DSA-65 (6, 5) by its sizes");
        assert!(nist_category_3(kem, dsa), "the pair is NIST category 3");
        // PLANTED LIES — the computation must be able to say no
        assert_eq!(ml_kem_rank(800, 768, 1632), Some(2), "CALIBRATION: ML-KEM-512's sizes imply rank 2");
        assert_eq!(ml_dsa_shape(1312, 2420, 2560), Some((4, 4)), "CALIBRATION: ML-DSA-44's sizes imply (4, 4)");
        assert!(!nist_category_3(Some(2), dsa), "PLANTED LIE: ML-KEM-512 is refused as category 3");
        assert!(!nist_category_3(kem, Some((4, 4))), "PLANTED LIE: ML-DSA-44 is refused as category 3");
        assert_eq!(ml_kem_rank(ek.len() + 1, ct.len(), dk.len()), None, "PLANTED LIE: a size off by one byte is no FIPS 203 set");
        assert_eq!(ml_dsa_shape(pk.len(), sig.len() - 1, sk.len()), None, "PLANTED LIE: a signature one byte short is no FIPS 204 set");
    }

    /// ⛔⛔⛔ H12 — POSEIDON2 OVER KOALABEAR HAS THE ROUNDS ITS SECURITY NEEDS, COMPUTED. Every permutation in the tree is
    /// `Poseidon2KoalaBear<16>` (the challenger, the PoUW kernel, every Merkle hash; width 24 is exported and checked too).
    /// The pin READS p, the S-box degree and the round counts from `p3_koala_bear`'s constants, checks x^α is a
    /// permutation (gcd(α, p − 1) = 1), and runs the Poseidon2 paper's inequalities at 128 bits: the rounds in use must be
    /// secure, must STILL be secure with the paper's margin removed (R_F − 2, ⌊R_P / 1.075⌋), and must equal the reference
    /// script's recommended pair. PLANTED LIE: (R_F, R_P) = (6, 17) is refused.
    #[test]
    fn poseidon2_koalabear_round_counts_meet_the_papers_128_bit_inequalities_with_margin() {
        let p = p3_koala_bear::KoalaBear::ORDER_U64;
        let alpha = p3_koala_bear::KOALABEAR_S_BOX_DEGREE;
        let gcd = |mut a: u64, mut b: u64| {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        };
        assert_eq!(gcd(alpha, p - 1), 1, "⛔ x^{alpha} is not a permutation of KoalaBear");
        let r_f = 2 * p3_koala_bear::KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
        for (t, r_p) in [
            (16usize, p3_koala_bear::KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16),
            (24usize, p3_koala_bear::KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_24),
        ] {
            let recommended = poseidon2_recommended_rounds(p, t, alpha, 128.0);
            let stripped = (r_f - 2, (r_p as f64 / 1.075).floor() as usize);
            eprintln!(
                "[crypto-parameter] MEASURED Poseidon2 KoalaBear t={t}: in use (R_F, R_P) = ({r_f}, {r_p}); recommended {recommended:?}; margin-stripped {stripped:?} secure = {}",
                poseidon2_rounds_secure(p, t, stripped.0, stripped.1, alpha, 128.0)
            );
            assert!(poseidon2_rounds_secure(p, t, r_f, r_p, alpha, 128.0), "⛔ Poseidon2 t={t} with ({r_f}, {r_p}) fails the 128-bit inequalities");
            assert!(
                poseidon2_rounds_secure(p, t, stripped.0, stripped.1, alpha, 128.0),
                "⛔ Poseidon2 t={t}: the security margin is not there — {stripped:?} fails the inequalities"
            );
            assert_eq!((r_f, r_p), recommended, "⛔ Poseidon2 t={t}: the rounds in use differ from the reference script's recommendation");
            assert!(!poseidon2_rounds_secure(p, t, 6, 17, alpha, 128.0), "PLANTED LIE: (6, 17) must fail the inequalities at t={t}");
        }
    }
}

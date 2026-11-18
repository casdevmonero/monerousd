// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ IS THE SPARSE TREE'S FOLD SECOND-PREIMAGE RESISTANT? A DIRECT MEASUREMENT, NOT AN OPINION.
//!
//! `spend_frontier::poseidon_pair` (mirrored natively here as
//! [`crate::nullifier_insert_air::poseidon_pair_native`]) is ONE algebraic round:
//! `out = MDS · (l + 7·r)⁷`, lane-wise. Every non-membership proof in the nullifier accumulator is a fold of
//! 256 of these, and `nf_sparse::SparseNfAcc::verify_unspent` accepts a spend the instant that fold reproduces
//! the committed root. So the double-spend guard is exactly as strong as this function's second-preimage
//! resistance, and nothing in the tree is stronger than it.
//!
//! THE QUESTION THIS ANSWERS. `x ↦ x⁷` is a BIJECTION over KoalaBear (`p − 1 = 2²⁴·127`, and `gcd(7, p−1) = 1`),
//! `MDS` is invertible (circulant `(2,3,1,1)`, eigenvalues `7, −1, 1±2i`, determinant `−35 ≠ 0`), and
//! `pre = l + 7·r` is linear. If all three hold then `out` can be walked BACKWARDS to a `pre`, and `pre` splits
//! into `(l, r)` in `p` different ways — so a sibling can be SOLVED FOR rather than found. This module does not
//! argue that; it computes the solve and reports whether the tree accepts the result.
//!
//! WHAT A POSITIVE RESULT WOULD MEAN, stated before the measurement so the result cannot be reinterpreted after
//! the fact: a spender could prove ANY nullifier unspent against ANY committed root, and
//! `SparseNfAcc::spent_verdict` would answer `Unspent` for a note already spent. That is a direct double-spend
//! of real funds, not a consensus nuisance.

#[cfg(test)]
pub(crate) mod sparse_fold_preimage_probe {
    use crate::nullifier_insert_air::{kadd, kmul, kred, SPEND_MDS};

    /// ⛔⛔⛔ THE RETIRED FOLD, REPRODUCED HERE AND NOWHERE ELSE.
    ///
    /// `spend_frontier::poseidon_pair` / `nullifier_insert_air::poseidon_pair_native` USED to be this: one
    /// algebraic round, `out = MDS·(l + 7·r)⁷`. It was replaced on 2026-09-12 (kill list §AG) because every
    /// part of it inverts. The function is kept ONLY inside this test module, so that:
    ///   * the CALIBRATION below still demonstrates a real attack on a real function rather than asserting
    ///     from memory that one used to exist, and
    ///   * the REFUTATION in `poseidon2_compress` has something to be a refutation OF.
    /// It is `#[cfg(test)]` and has no production caller — running the chain on it again would require
    /// deliberately re-exporting it, which is the point.
    pub(crate) fn retired_one_round_fold(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        let mut pre7 = [0u64; 4];
        for c in 0..4 {
            let pre = kadd(kred(left[c]), kmul(7, kred(right[c])));
            let ps = kmul(pre, pre);
            let p4 = kmul(ps, ps);
            pre7[c] = kmul(kmul(p4, ps), pre);
        }
        let mut out = [0u64; 4];
        for (rc, o) in out.iter_mut().enumerate() {
            let mut s = 0u64;
            for c in 0..4 {
                s = kadd(s, kmul(SPEND_MDS[rc][c], pre7[c]));
            }
            *o = s;
        }
        out
    }
    use retired_one_round_fold as poseidon_pair_native;

    const KB_P: u64 = 0x7f00_0001;
    /// `7⁻¹ mod (p − 1)` — the exponent that inverts `x ↦ x⁷`. `7 · 1_826_319_799 = 6·(p−1) + 1`.
    const SEVENTH_ROOT_EXP: u64 = 1_826_319_799;

    pub(crate) fn kpow(mut b: u64, mut e: u64) -> u64 {
        let (mut acc, _) = (1u64, ());
        b = kred(b);
        while e > 0 {
            if e & 1 == 1 {
                acc = kmul(acc, b);
            }
            b = kmul(b, b);
            e >>= 1;
        }
        acc
    }
    pub(crate) fn kinv(a: u64) -> u64 {
        kpow(a, KB_P - 2)
    }
    pub(crate) fn ksub(a: u64, b: u64) -> u64 {
        kadd(kred(a), KB_P - kred(b))
    }

    /// The unique `x` with `x⁷ == y`.
    pub(crate) fn seventh_root(y: u64) -> u64 {
        kpow(y, SEVENTH_ROOT_EXP)
    }

    /// `MDS⁻¹ · v` by Gauss-Jordan over KoalaBear — computed, never transcribed, so a wrong constant cannot
    /// silently make the probe report "no preimage".
    pub(crate) fn mds_solve(v: [u64; 4]) -> Option<[u64; 4]> {
        let mut a = [[0u64; 5]; 4];
        for (r, row) in a.iter_mut().enumerate() {
            for (c, cell) in row.iter_mut().take(4).enumerate() {
                *cell = kred(SPEND_MDS[r][c]);
            }
            row[4] = kred(v[r]);
        }
        for col in 0..4 {
            let piv = (col..4).find(|&r| a[r][col] != 0)?;
            a.swap(col, piv);
            let inv = kinv(a[col][col]);
            for c in col..5 {
                a[col][c] = kmul(a[col][c], inv);
            }
            for r in 0..4 {
                if r != col && a[r][col] != 0 {
                    let f = a[r][col];
                    for c in col..5 {
                        a[r][c] = ksub(a[r][c], kmul(f, a[col][c]));
                    }
                }
            }
        }
        Some([a[0][4], a[1][4], a[2][4], a[3][4]])
    }

    /// SOLVE for the sibling that makes `poseidon_pair(node, sib) == target` (or `pair(sib, node)` when
    /// `dir == 1`). This is the whole attack: not a search, a division.
    pub(crate) fn solve_sibling(node: [u64; 4], target: [u64; 4], dir: u64) -> Option<[u64; 4]> {
        let p7 = mds_solve(target)?;
        let inv7 = kinv(7);
        let mut sib = [0u64; 4];
        for c in 0..4 {
            let pre = seventh_root(p7[c]);
            sib[c] = if dir == 0 {
                // pre = node + 7·sib  ⇒  sib = (pre − node)/7
                kmul(ksub(pre, node[c]), inv7)
            } else {
                // pre = sib + 7·node  ⇒  sib = pre − 7·node
                ksub(pre, kmul(7, node[c]))
            };
        }
        Some(sib)
    }

    pub(crate) fn nf_bit(nf: &[u8; 32], level: usize) -> u8 {
        (nf[level >> 3] >> (level & 7)) & 1
    }

    pub(crate) fn fold(leaf: [u64; 4], nf: &[u8; 32], copath: &[[u64; 4]]) -> [u64; 4] {
        let mut node = leaf;
        for (level, sib) in copath.iter().enumerate() {
            node = if nf_bit(nf, level) == 0 {
                poseidon_pair_native(node, *sib)
            } else {
                poseidon_pair_native(*sib, node)
            };
        }
        node
    }

    /// ⭐ THE ALGEBRA, CHECKED ON ITS OWN BEFORE IT IS USED. If `x ↦ x⁷` were not a bijection, or `MDS` were
    /// singular, the solve below would be meaningless and its failure would prove nothing about the tree.
    #[test]
    fn the_round_is_invertible_in_both_of_its_parts() {
        for x in [1u64, 2, 7, 12345, KB_P - 1, 0x7eff_ffff] {
            assert_eq!(seventh_root(kpow(x, 7)), kred(x), "x⁷ is not a bijection at {x}");
        }
        let v = [11u64, 22, 33, 44];
        let back = mds_solve(v).expect("SPEND_MDS must be invertible");
        let mut fwd = [0u64; 4];
        for (rc, cell) in fwd.iter_mut().enumerate() {
            let mut s = 0u64;
            for c in 0..4 {
                s = kadd(s, kmul(SPEND_MDS[rc][c], back[c]));
            }
            *cell = s;
        }
        assert_eq!(fwd, v.map(kred), "MDS⁻¹ is not the inverse of MDS");
        eprintln!("[fold-probe] x⁷ is a bijection over KoalaBear and SPEND_MDS is invertible");
    }

    /// ⛔⛔⛔ THE MEASUREMENT. Can a copath be SOLVED so an arbitrary nullifier folds to an arbitrary committed
    /// root? If yes, every non-membership proof in the accumulator is forgeable and a spent note can be spent
    /// again.
    #[test]
    fn a_copath_can_be_solved_for_any_nullifier_against_any_root() {
        // A committed root nobody controls — as if read off a live chain.
        let root = poseidon_pair_native([0xdead_beef, 0x1234, 0x5678, 0x9abc], [7, 7, 7, 7]);
        // A nullifier that is ALREADY SPENT under that root, so honest non-membership is impossible.
        let nf: [u8; 32] = *blake3::hash(b"musdm.probe.already-spent-nullifier").as_bytes();

        // 255 siblings chosen with no freedom used at all, then ONE solved. The empty leaf is the fixed
        // starting value every honest non-membership proof must also start from.
        let mut copath: Vec<[u64; 4]> = (0..255u64)
            .map(|i| [kred(i + 1), kred(i + 2), kred(i + 3), kred(i + 4)])
            .collect();
        let node255 = fold([0u64; 4], &nf, &copath);
        let last = solve_sibling(node255, root, nf_bit(&nf, 255) as u64)
            .expect("the solve is a division, not a search");
        copath.push(last);

        let reproduced = fold([0u64; 4], &nf, &copath);
        assert_eq!(copath.len(), 256, "a full-depth copath, exactly what a verifier demands");
        assert_eq!(
            reproduced, root,
            "the solved copath does not reproduce the root — the fold resisted the solve"
        );
        eprintln!(
            "[fold-probe] ⛔ FORGED: a 256-sibling non-membership copath for an arbitrary nullifier against an \
             arbitrary root, built by SOLVING ONE sibling (no search, no grinding, ~1 ms)"
        );
    }

    /// The same solve, run against a SECOND unrelated root and a SECOND nullifier, so the first result cannot be
    /// a lucky constant. A break must be repeatable to be a break.
    #[test]
    fn the_solve_repeats_on_unrelated_roots_and_nullifiers() {
        for seed in 0..8u64 {
            let root = poseidon_pair_native([seed, seed + 99, seed + 1234, seed + 55555], [3, 1, 4, 1]);
            let nf: [u8; 32] = *blake3::hash(&seed.to_le_bytes()).as_bytes();
            let mut copath: Vec<[u64; 4]> =
                (0..255u64).map(|i| [kred(i ^ seed), kred(i + seed), kred(i), kred(seed)]).collect();
            let node255 = fold([0u64; 4], &nf, &copath);
            copath.push(
                solve_sibling(node255, root, nf_bit(&nf, 255) as u64).expect("solve"),
            );
            assert_eq!(fold([0u64; 4], &nf, &copath), root, "seed {seed}: the solve failed");
        }
        eprintln!("[fold-probe] ⛔ 8/8 unrelated (root, nullifier) pairs forged — the solve is general");
    }
}

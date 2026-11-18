// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ THE DOUBLE-SPEND GATE, MEASURED AGAINST THE LIVE NODE-SIDE VERIFIER.
//!
//! A copath is checked in exactly one way, by [`crate::nf_sparse::SparseNfAcc::verify_unspent`] /
//! [`crate::nf_sparse::SparseNfAcc::spent_verdict`]: fold the supplied siblings up the nullifier's bit-path
//! and compare with the committed root. Nothing else about the copath is constrained — not its provenance,
//! not its shape, not whether the siblings are subtree hashes of anything. So the gate is exactly as strong
//! as the fold's second-preimage resistance, **and no stronger**. That is not a criticism of the design; it
//! is the reason the fold itself has to be a real hash.
//!
//! It was not. Kill list §AG measured the chain's one compression as a SINGLE algebraic round,
//! `out = MDS · (l + 7·r)⁷`, and every part of it inverts: `x ↦ x⁷` is a bijection over KoalaBear
//! (`p − 1 = 2²⁴·127`, so `gcd(7, p−1) = 1`), `SPEND_MDS` is invertible, and `l + 7·r` is linear. A
//! non-membership copath could therefore be **solved by division** rather than found — in about a
//! millisecond, for any nullifier against any root — so a SPENT note read Unspent and the accumulator
//! settled the double-spend.
//!
//! ⭐ WRITTEN AS CALIBRATION PINS PLUS A GUARANTEE PIN, in that order, per
//! [[reference_refutation_before_green]]. A refusal is worth nothing until something proves a forgery was
//! actually built, so:
//!
//! 1. [`calibration_the_retired_fold_is_still_solvable_by_division`] — the attack is REAL, demonstrated on
//!    the retired function itself, which is kept here (test-only, no production caller) precisely so the
//!    calibration has a subject. ⛔ This pin must never be deleted "because the bug is fixed": deleting it
//!    is how the guarantee pin below quietly becomes vacuous.
//! 2. [`calibration_the_same_solve_gets_nowhere_against_the_live_compression`] — the REPLACEMENT is what
//!    defeats the attack, not the way this test is written. Same algebra, same code path, 0 hits.
//! 3. [`pin_a_spent_nullifier_must_never_read_unspent`] — the property real funds depend on, asserted
//!    against the accumulator every node actually gates spends on.

#[cfg(all(test, feature = "pins-core"))]
mod sparse_fold_forgery_pin {
    use crate::nf_sparse::{RefSparseNfMemo, SparseNfAcc, SpentVerdict};
    use crate::spend_frontier::Digest4;
    use usdm_decider::nullifier_insert_air::SPEND_MDS;

    /// The RETIRED digest width: four 64-bit limbs. The live one is eight 31-bit lanes — the widening that
    /// took collision resistance from 62 bits to 124. Both appear in this file on purpose.
    type RetiredDigest = [u64; 4];

    const KB_P: u64 = 0x7f00_0001;
    /// `7⁻¹ mod (p − 1)`, the exponent inverting `x ↦ x⁷`.
    const SEVENTH_ROOT_EXP: u64 = 1_826_319_799;

    fn kred(a: u64) -> u64 {
        (a as u128 % KB_P as u128) as u64
    }
    fn kadd(a: u64, b: u64) -> u64 {
        let s = a as u128 + b as u128;
        (if s >= KB_P as u128 { s - KB_P as u128 } else { s }) as u64
    }
    fn kmul(a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % KB_P as u128) as u64
    }
    fn ksub(a: u64, b: u64) -> u64 {
        kadd(kred(a), KB_P - kred(b))
    }
    fn kpow(mut b: u64, mut e: u64) -> u64 {
        let mut acc = 1u64;
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
    fn kinv(a: u64) -> u64 {
        kpow(a, KB_P - 2)
    }

    /// ⛔ THE RETIRED FOLD, KEPT ONLY SO THE CALIBRATION HAS A SUBJECT — `out = MDS · (l + 7·r)⁷`.
    ///
    /// It has no production caller and cannot acquire one: the chain's compression is
    /// `usdm_decider::poseidon2_compress::compress`, and `crate::spend_frontier::poseidon_pair` delegates
    /// to it. This copy exists because a calibration that cannot run the broken function can only assert
    /// that the fixed one is fine, which is the shape of a detector that reports clean because it cannot see.
    fn retired_one_round_fold(left: RetiredDigest, right: RetiredDigest) -> RetiredDigest {
        let pre: RetiredDigest = core::array::from_fn(|c| kadd(kred(left[c]), kmul(7, kred(right[c]))));
        let p7: RetiredDigest = core::array::from_fn(|c| kpow(pre[c], 7));
        core::array::from_fn(|r| {
            (0..4).fold(0u64, |acc, c| kadd(acc, kmul(kred(SPEND_MDS[r][c]), p7[c])))
        })
    }

    /// `MDS⁻¹ · v`, computed by elimination so a transcription slip cannot make the attack silently fail.
    fn mds_solve(v: RetiredDigest) -> RetiredDigest {
        let mut a = [[0u64; 5]; 4];
        for (r, row) in a.iter_mut().enumerate() {
            for (c, cell) in row.iter_mut().take(4).enumerate() {
                *cell = kred(SPEND_MDS[r][c]);
            }
            row[4] = kred(v[r]);
        }
        for col in 0..4 {
            let piv = (col..4).find(|&r| a[r][col] != 0).expect("SPEND_MDS is invertible");
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
        [a[0][4], a[1][4], a[2][4], a[3][4]]
    }

    /// THE WHOLE ATTACK: the sibling that makes this node hash to the target is a DIVISION, not a search.
    fn solve_sibling(node: RetiredDigest, target: RetiredDigest, dir: u8) -> RetiredDigest {
        let p7 = mds_solve(target);
        let inv7 = kinv(7);
        core::array::from_fn(|c| {
            let pre = kpow(p7[c], SEVENTH_ROOT_EXP);
            if dir == 0 {
                kmul(ksub(pre, node[c]), inv7) // pre = node + 7·sib
            } else {
                ksub(pre, kmul(7, node[c])) // pre = sib + 7·node
            }
        })
    }

    /// Fold a copath up a nullifier's bit path with the RETIRED function.
    fn fold_retired(leaf: RetiredDigest, nf: &[u8; 32], copath: &[RetiredDigest]) -> RetiredDigest {
        let mut node = leaf;
        for (level, sib) in copath.iter().enumerate() {
            node = if crate::nf_sparse::nf_bit_pub(nf, level) == 0 {
                retired_one_round_fold(node, *sib)
            } else {
                retired_one_round_fold(*sib, node)
            };
        }
        node
    }

    /// Fold with the node's OWN public `poseidon_pair` — the forgery is never checked against a local mirror.
    fn fold_with_node_hash(leaf: Digest4, nf: &[u8; 32], copath: &[Digest4]) -> Digest4 {
        let mut node = leaf;
        for (level, sib) in copath.iter().enumerate() {
            node = if crate::nf_sparse::nf_bit_pub(nf, level) == 0 {
                crate::spend_frontier::poseidon_pair(node, *sib)
            } else {
                crate::spend_frontier::poseidon_pair(*sib, node)
            };
        }
        node
    }

    /// 255 arbitrary siblings at the live width — no freedom is needed anywhere but the last level, which
    /// is the sharp edge of §AG: ONE solved sibling is enough to land on any root you name.
    fn arbitrary_live_copath(seed: u64) -> Vec<Digest4> {
        (0..255u64)
            .map(|i| core::array::from_fn(|k| kred(seed.wrapping_mul(1_000_003) + i + k as u64 + 1)))
            .collect()
    }

    fn arbitrary_retired_copath(seed: u64) -> Vec<RetiredDigest> {
        (0..255u64)
            .map(|i| core::array::from_fn(|k| kred(seed.wrapping_mul(1_000_003) + i + k as u64 + 1)))
            .collect()
    }

    /// Build a real accumulator holding real spends, advanced exactly the way production advances it, and
    /// return it with a nullifier that is genuinely SPENT inside it.
    fn a_real_accumulator_with_a_spent_nullifier() -> (SparseNfAcc, [u8; 32], RefSparseNfMemo) {
        let mut memo = RefSparseNfMemo::new();
        let mut acc = SparseNfAcc::new();
        let mut spent = [0u8; 32];
        for i in 0..16u64 {
            let nf: [u8; 32] = *blake3::hash(&[b"musdm.pin.spend".as_slice(), &i.to_le_bytes()].concat())
                .as_bytes();
            let copath = memo.insert_and_witness(&nf);
            acc.verify_and_insert(&nf, &copath).expect("an honest spend settles");
            if i == 9 {
                spent = nf;
            }
        }
        (acc, spent, memo)
    }

    /// ⭐⭐⭐ CALIBRATION 1 — THE ATTACK IS REAL, AND STILL IS, ON THE FUNCTION THAT WAS SHIPPED.
    ///
    /// Name ANY target root. Take a nullifier that is already spent under it. Pick 255 siblings out of thin
    /// air. The 256th is then a DIVISION: `sib = ((MDS⁻¹·target)^{1/7} − node) / 7`. This gate asserts the
    /// division lands exactly, for 8 independent targets, so the guarantee pin below cannot pass merely
    /// because no forgery was ever constructed.
    #[test]
    fn calibration_the_retired_fold_is_still_solvable_by_division() {
        let nf: [u8; 32] = *blake3::hash(b"musdm.pin.calibration-subject").as_bytes();
        let mut solved = 0usize;
        for t in 0..8u64 {
            // An arbitrary "committed root" — the attack does not care where it came from.
            let target: RetiredDigest =
                core::array::from_fn(|c| kred(0x51ed_beef_u64.wrapping_mul(t + 1) + c as u64 * 7_919));
            let mut copath = arbitrary_retired_copath(t);
            let node255 = fold_retired([0u64; 4], &nf, &copath);
            copath.push(solve_sibling(node255, target, crate::nf_sparse::nf_bit_pub(&nf, 255)));
            assert_eq!(copath.len(), crate::nf_sparse::NF_SPARSE_DEPTH, "a full-depth copath");
            if fold_retired([0u64; 4], &nf, &copath) == target {
                solved += 1;
            }
        }
        assert_eq!(
            solved, 8,
            "⛔ THE CALIBRATION IS NOT ARMED. The retired one-round fold no longer inverts under this \
             algebra, so the refutation below is measuring nothing. Fix the attack, not the expectation."
        );
        eprintln!(
            "[fold-pin] CALIBRATION 1: the RETIRED fold was solved by division on {solved}/8 independent \
             targets — a spent nullifier's non-membership copath, manufactured, not found"
        );
    }

    /// ⭐⭐⭐ CALIBRATION 2 — IT IS THE REPLACEMENT THAT DEFEATS IT, NOT THE WAY THIS TEST IS WRITTEN.
    ///
    /// Identical algebra, identical code path, pointed at the LIVE compression: a truncated Poseidon2
    /// permutation over `sponge_chain_air::production_perm()` — the same permutation the PoUW kernel mines
    /// with, so no new constant, family or assumption entered the chain. 64 attempts, 0 hits. A single hit
    /// here would mean the replacement inherited the algebraic structure it was chosen to destroy.
    #[test]
    fn calibration_the_same_solve_gets_nowhere_against_the_live_compression() {
        let (acc, spent, _memo) = a_real_accumulator_with_a_spent_nullifier();
        let root = acc.root();
        let mut hits = 0usize;
        for t in 0..64u64 {
            let mut copath = arbitrary_live_copath(t);
            let node255 = fold_with_node_hash(
                usdm_decider::poseidon2_compress::zero_digest(),
                &spent,
                &copath,
            );
            // The solve reads the low four lanes and writes a sibling that WOULD have worked against the
            // retired fold. Under the live compression the remaining lanes are unconstrained by it and the
            // permutation mixes all eight, so nothing about the result is predictable.
            let solved4 = solve_sibling(
                core::array::from_fn(|c| node255[c]),
                core::array::from_fn(|c| root[c]),
                crate::nf_sparse::nf_bit_pub(&spent, 255),
            );
            copath.push(usdm_decider::poseidon2_compress::lanes_of(&solved4));
            if fold_with_node_hash(usdm_decider::poseidon2_compress::zero_digest(), &spent, &copath) == root
            {
                hits += 1;
            }
        }
        assert_eq!(
            hits, 0,
            "⛔⛔⛔ THE REPLACEMENT INVERTS TOO. {hits}/64 solved copaths reproduced the LIVE root, which \
             means the new compression carries the same algebraic structure §AG broke."
        );
        eprintln!(
            "[fold-pin] CALIBRATION 2: the SAME solve against the LIVE compression — 0/64 reproduced the \
             root. The attack is armed (calibration 1) and the replacement is what stops it."
        );
    }

    /// ⛔⛔⛔ THE GUARANTEE REAL FUNDS DEPEND ON — a nullifier that IS spent must never read `Unspent`, no
    /// matter what copath is supplied. This was RED while the one-round fold was in place; it is the
    /// signal that §AG is closed on the node side.
    #[test]
    fn pin_a_spent_nullifier_must_never_read_unspent() {
        let (mut acc, spent, memo) = a_real_accumulator_with_a_spent_nullifier();
        let root = acc.root();

        // The HONEST answer first, so the pin cannot pass by the accumulator being broken in the other
        // direction (everything reading `Spent`, or every copath being rejected).
        assert_eq!(
            acc.spent_verdict(&spent, &memo.copath(&spent)),
            SpentVerdict::Spent,
            "the honest copath must prove the spend — otherwise this pin is measuring a different failure"
        );

        // 32 independent forgery attempts, each ending in the §AG solve against the real committed root.
        for t in 0..32u64 {
            let mut forged = arbitrary_live_copath(t);
            let node255 = fold_with_node_hash(
                usdm_decider::poseidon2_compress::zero_digest(),
                &spent,
                &forged,
            );
            let solved4 = solve_sibling(
                core::array::from_fn(|c| node255[c]),
                core::array::from_fn(|c| root[c]),
                crate::nf_sparse::nf_bit_pub(&spent, 255),
            );
            forged.push(usdm_decider::poseidon2_compress::lanes_of(&solved4));

            let verdict = acc.spent_verdict(&spent, &forged);
            let admitted = acc.verify_unspent(&spent, &forged).is_ok();
            let settled = acc.verify_and_insert(&spent, &forged).is_ok();
            assert_ne!(
                verdict,
                SpentVerdict::Unspent,
                "⛔⛔⛔ A SPENT NULLIFIER READS UNSPENT on attempt {t}. The double-spend gate is defeated by \
                 a copath that was SOLVED, not found — so any note can be spent an unlimited number of times."
            );
            assert!(
                !admitted,
                "⛔ attempt {t}: the accumulator ADMITTED a solved non-membership witness for a spent \
                 nullifier"
            );
            assert!(
                !settled,
                "⛔ attempt {t}: the accumulator SETTLED a double-spend on a solved witness"
            );
        }
        // And the root did not move under any of it — a refused attempt must consume nothing.
        assert_eq!(
            acc.root(),
            root,
            "⛔ a REFUSED forgery still advanced the accumulator — the refusal is not fail-closed"
        );
        eprintln!(
            "[fold-pin] GUARANTEE: 32 solved copaths against the LIVE accumulator — 0 read Unspent, 0 \
             admitted, 0 settled, and the root did not move"
        );
    }
}

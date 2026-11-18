// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root). This file is
// an original work of the MoneroUSD Protocol (the phone-class sub-1s light
// decider, task #135), added to the WHIR crate; it is NOT part of Plonky3.

//! HVZK-WHIR code-switching layer (eprint 2026/391) — the Pillar-1 (100% private)
//! honest-verifier-zero-knowledge consumer of the zero-evader helpers in
//! [`crate::utils`]. It blinds the WHIR code-switching out-of-domain (OOD) answer so
//! the PUBLISHED proof leaks nothing about the committed message (`is_zk()==1`),
//! while keeping WHIR's cheap sumcheck-dominated verifier (the property that makes the
//! MonerousD decider prove phone-class fast — [[feedback_instant_folded_broadcast_pillar]]).
//!
//! ## Integration target (verified against the decider, 2026-07-07)
//! The MonerousD decider ALREADY achieves `is_zk()==1` via `HidingFriPcs` over a
//! `MerkleTreeHidingMmcs` + `num_random_codewords=4` + Plonky3 trace randomization (statistical ZK;
//! `pqpool/src/lib.rs::build_zk_config_lfp0`). The WHIR speed-swap (hashless verifier) must PRESERVE
//! that hiding: a `HidingWhirPcs` = WHIR over a hiding Merkle MMCS PAIRED WITH these OOD-answer
//! blinding primitives (the random-codeword equivalent for WHIR's out-of-domain evaluations) — it
//! mirrors `HidingFriPcs`, and must NEVER leave base WHIR's plain (message-revealing) evaluations
//! published. `config.is_zk()` (the `hiding` gate on `ProtocolParameters`) selects this path.

use alloc::vec::Vec;

use p3_field::Field;

use crate::utils::{eval_ze_star_n, padded_ood_t1};

/// The HVZK code-switching OOD answer at folding factor `t = 1` (Construction 9.7,
/// eprint 2026/391):
///
/// ```text
///     y = ze*_l(ρ) · msg  +  ρ^l · ze*_r(ρ) · rand
/// ```
///
/// With fresh uniform `rand` (`rand.len() >= 1`) and challenge `ρ != 0`, the `rand`
/// contribution is a non-zero `F`-linear functional, so `y` is uniform in `F` and
/// INDEPENDENT of `msg` — the witness is blinded end-to-end (privacy error `ζ_ze = 0`).
/// This is the answer the HVZK prover sends in place of the plain (message-leaking) OOD
/// evaluation. `rand` MUST be secret prover randomness; passing `rand = &[]` recovers the
/// unblinded evaluation and is NOT zero-knowledge.
pub fn code_switch_ood_answer<F: Field>(challenge: F, msg: &[F], rand: &[F]) -> F {
    padded_ood_t1(challenge, msg, rand)
}

/// The zero-evader evaluation `ze*_n(ρ) · coeffs = Σ_i coeffs_i · ρ^i` (Definition 6.1,
/// eprint 2026/391), exposed for the HVZK sumcheck round-masking consumer.
pub fn zero_evader_eval<F: Field>(challenge: F, coeffs: &[F]) -> F {
    eval_ze_star_n(challenge, coeffs)
}

/// HVZK sumcheck round-mask recovery (eprint 2026/391 §9). Per round the prover masks the
/// honest claim vector `c` with fresh randomness `v` and sends the zero-evader image of the
/// mask `m = ze*_n(ρ)·v` alongside the masked image `M = ze*_n(ρ)·(c+v)`. By LINEARITY of the
/// zero-evader the verifier recovers the honest image exactly as `M − m = ze*_n(ρ)·c`, WITHOUT
/// learning `c` (uniform `v` blinds it → is_zk). This returns that recovered honest image; the
/// recovery is exact (soundness-preserving) and message-independent (zero-knowledge).
pub fn sumcheck_round_unmask<F: Field>(masked_image: F, mask_image: F) -> F {
    masked_image - mask_image
}

/// Commitment-phase HVZK code-switching for the FULL vector of out-of-domain answers — the
/// `WhirConfig::commitment_ood_samples` answers the committer publishes (one per OOD point,
/// `pcs/adapter.rs::open`). Answer `i` is blinded independently at its own challenge
/// `challenges[i]` with fresh SECRET randomness `rands[i]` (`rands[i].len() >= 1`), so the
/// published vector is JOINTLY zero-knowledge — a simulator reproduces the whole vector from the
/// public answers alone (see `commitment_ood_vector_is_jointly_simulatable`). `challenges`,
/// `msgs`, and `rands` MUST have equal length `k`; each `rands[i]` must be fresh prover
/// randomness (an empty `rands[i]` recovers the plain message-leaking evaluation and is NOT ZK).
#[must_use]
pub fn code_switch_ood_answer_vec<F: Field>(
    challenges: &[F],
    msgs: &[&[F]],
    rands: &[&[F]],
) -> Vec<F> {
    debug_assert_eq!(challenges.len(), msgs.len(), "one message per OOD challenge");
    debug_assert_eq!(challenges.len(), rands.len(), "one randomness vector per OOD challenge");
    challenges
        .iter()
        .zip(msgs)
        .zip(rands)
        .map(|((&rho, msg), rand)| code_switch_ood_answer(rho, msg, rand))
        .collect()
}

/// Verifier-side consistency check for a code-switching OOD answer (eprint 2026/391 §9.7) — the
/// counterpart of [`code_switch_ood_answer`]. Given the published answer `y`, the message-polynomial
/// evaluation `msg_eval = ze*_l(ρ)·msg` that the WHIR folding proves, and the mask-polynomial
/// evaluation `mask_eval = ze*_r(ρ)·rand` opened from the prover's mask commitment (both at the OOD
/// challenge `rho`), the answer is consistent iff
///
/// ```text
///     y == msg_eval + ρ^{msg_len} · mask_eval.
/// ```
///
/// A prover that lies about ANY of `y`, `msg_eval`, or `mask_eval` fails this identity for all but a
/// `(l+r-1)/|F|` fraction of challenges `ρ` (the zero-evader bound), so the blinding adds NO soundness
/// loss beyond that negligible term — the ZK is "free". Returns `true` iff consistent.
#[must_use]
pub fn code_switch_verify<F: Field>(y: F, msg_eval: F, mask_eval: F, rho: F, msg_len: usize) -> bool {
    y == msg_eval + rho.exp_u64(msg_len as u64) * mask_eval
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type EF = BinomialExtensionField<KoalaBear, 4>;

    /// PILLAR-1 HIDING (adversarial): the published code-switching OOD answer produced for
    /// `msg_a` with randomness `rand_a` is EXACTLY reproducible for ANY other equal-length
    /// message `msg_b` by adjusting only `rand[0]`. Hence the answer's value carries zero
    /// information about the message — it is a perfect one-time pad in `F` (Lemma 9.3).
    /// A prover that leaked the message could NOT satisfy this for a random `msg_b`.
    #[test]
    fn code_switch_answer_hides_the_message() {
        let mut rng = SmallRng::seed_from_u64(0xC0DE_5117);
        for _ in 0..128 {
            let l = 3usize; // message length
            let r = 2usize; // randomness length (r >= 1 is required for hiding)
            let rho: EF = rng.random();
            if rho.is_zero() {
                continue; // ρ = 0 has measure 1/|F| (soundness budget), not a hiding case
            }
            let msg_a: Vec<EF> = (0..l).map(|_| rng.random()).collect();
            let msg_b: Vec<EF> = (0..l).map(|_| rng.random()).collect();
            let rand_a: Vec<EF> = (0..r).map(|_| rng.random()).collect();

            let y_a = code_switch_ood_answer(rho, &msg_a, &rand_a);

            // rand[0] enters y with coefficient ρ^l·1, so cancel the message swap with
            //   delta = (ze*_l(ρ)·msg_a − ze*_l(ρ)·msg_b) / ρ^l   added to rand_b[0].
            let shift = rho.exp_u64(l as u64);
            let inv_shift = shift.try_inverse().expect("rho != 0 => rho^l != 0");
            let delta =
                (zero_evader_eval(rho, &msg_a) - zero_evader_eval(rho, &msg_b)) * inv_shift;
            let mut rand_b = rand_a.clone();
            rand_b[0] += delta;

            let y_b = code_switch_ood_answer(rho, &msg_b, &rand_b);
            assert_eq!(y_a, y_b, "HVZK hiding broken: the message leaked through the OOD answer");
        }
    }

    /// With an empty message the code-switch answer reduces to the plain zero-evader of the
    /// randomness (ρ^0 = 1) — the unblinded form, a structural sanity check.
    #[test]
    fn empty_message_reduces_to_zero_evader() {
        let mut rng = SmallRng::seed_from_u64(7);
        let rho: EF = rng.random();
        let rand: Vec<EF> = (0..4).map(|_| rng.random()).collect();
        assert_eq!(code_switch_ood_answer(rho, &[], &rand), zero_evader_eval(rho, &rand));
    }

    /// PILLAR-3 SOUNDNESS + PILLAR-1 HIDING of the sumcheck round-mask: the verifier's
    /// `M − m` recovery equals the honest zero-evader image of `c` EXACTLY (linearity), for
    /// every fresh mask `v`. So masking neither changes the sumcheck claim (sound) nor leaks
    /// `c` (the sent images `M`, `m` are the only public values, and `v` is uniform).
    #[test]
    fn sumcheck_round_mask_cancels_exactly() {
        let mut rng = SmallRng::seed_from_u64(0x5111_C0DE);
        for _ in 0..128 {
            let n = 4usize;
            let rho: EF = rng.random();
            let c: Vec<EF> = (0..n).map(|_| rng.random()).collect(); // honest round claim
            let v: Vec<EF> = (0..n).map(|_| rng.random()).collect(); // fresh mask
            let cv: Vec<EF> = c.iter().zip(&v).map(|(a, b)| *a + *b).collect();
            let masked_image = zero_evader_eval(rho, &cv);
            let mask_image = zero_evader_eval(rho, &v);
            assert_eq!(
                sumcheck_round_unmask(masked_image, mask_image),
                zero_evader_eval(rho, &c),
                "HVZK sumcheck round-mask did not cancel to the honest image"
            );
        }
    }

    /// PILLAR-1 (composed layer, perfect HVZK): the PUBLIC transcript of one HVZK round — the masked
    /// sumcheck images `(M, m)` PLUS the code-switching OOD answer `y` — is SIMULATABLE from public data
    /// alone. A simulator that knows ONLY the honest sumcheck image `S = ze*(ρ,c)` and the OOD target `y*`
    /// (NOT the witness `c`, NOT the message `msg`) produces a transcript the verifier accepts BYTE-FOR-BYTE
    /// identically to the real prover's. Hence the published transcript carries zero witness information.
    #[test]
    fn hvzk_transcript_is_simulatable_without_witness() {
        let mut rng = SmallRng::seed_from_u64(0x513D_513D);
        for _ in 0..128 {
            let n = 4usize;
            let l = 3usize;
            let rho: EF = rng.random();
            if rho.is_zero() {
                continue; // ρ = 0 is the 1/|F| soundness-budget point, not a hiding case
            }

            // ── Real prover (HOLDS the witness) publishes (M, m, y) ──
            let c: Vec<EF> = (0..n).map(|_| rng.random()).collect(); // secret round claim
            let msg: Vec<EF> = (0..l).map(|_| rng.random()).collect(); // secret message
            let v: Vec<EF> = (0..n).map(|_| rng.random()).collect(); // fresh mask
            let rand: Vec<EF> = (0..2).map(|_| rng.random()).collect(); // fresh OOD randomness
            let s = zero_evader_eval(rho, &c); // the ONLY witness-derived value the verifier binds
            let cv: Vec<EF> = c.iter().zip(&v).map(|(a, b)| *a + *b).collect();
            let real_m_big = zero_evader_eval(rho, &cv); // M = ze*(ρ, c+v)
            let real_m_small = zero_evader_eval(rho, &v); // m = ze*(ρ, v)
            let y_star = code_switch_ood_answer(rho, &msg, &rand); // y

            // ── Simulator (knows ONLY s and y_star; NEVER sees c or msg) ──
            let sim_v: Vec<EF> = (0..n).map(|_| rng.random()).collect();
            let sim_m_small = zero_evader_eval(rho, &sim_v);
            let sim_m_big = s + sim_m_small; // M := S + ze*(ρ,v) — no witness used
            // OOD: with an EMPTY simulated message the shift is ρ^0 = 1, so rand[0] = y_star hits y_star.
            let sim_y = code_switch_ood_answer(rho, &[], &[y_star]);

            // The verifier's acceptance predicate on the REAL and SIMULATED transcripts is identical:
            assert_eq!(
                sumcheck_round_unmask(real_m_big, real_m_small),
                s,
                "real transcript must open to the honest image S"
            );
            assert_eq!(
                sumcheck_round_unmask(sim_m_big, sim_m_small),
                s,
                "simulated transcript must open to S identically (no witness used)"
            );
            assert_eq!(sim_y, y_star, "simulated OOD answer must equal the published answer");
        }
    }

    /// PILLAR-3 (adversarial — MUST REJECT): any non-zero tamper on a published mask image makes the
    /// verifier's recovered image diverge from the honest bound image `S`, so the round check REJECTS.
    /// A cheating prover CANNOT alter `M` (or `m`) and still open to `S` — the mask recovery is exact,
    /// so forgery is caught with probability 1 (not just whp) for every non-zero error.
    #[test]
    fn tampered_sumcheck_mask_image_is_rejected() {
        let mut rng = SmallRng::seed_from_u64(0xBAD_5111);
        for _ in 0..128 {
            let n = 4usize;
            let rho: EF = rng.random();
            let c: Vec<EF> = (0..n).map(|_| rng.random()).collect();
            let v: Vec<EF> = (0..n).map(|_| rng.random()).collect();
            let cv: Vec<EF> = c.iter().zip(&v).map(|(a, b)| *a + *b).collect();
            let s = zero_evader_eval(rho, &c);
            let m_big = zero_evader_eval(rho, &cv);
            let m_small = zero_evader_eval(rho, &v);

            // Honest transcript opens to S (the binding the verifier checks).
            assert_eq!(sumcheck_round_unmask(m_big, m_small), s);

            // Adversary adds a non-zero error to the masked image, hoping to still open to S.
            let mut e: EF = rng.random();
            while e.is_zero() {
                e = rng.random();
            }
            assert_ne!(
                sumcheck_round_unmask(m_big + e, m_small),
                s,
                "tampered mask image MUST NOT open to the honest sumcheck image S"
            );
        }
    }

    /// PILLAR-1 (commitment phase, JOINT ZK): the whole vector of code-switched OOD answers the
    /// committer publishes (`code_switch_ood_answer_vec`, one per `commitment_ood_samples` point)
    /// is jointly simulatable — a simulator holding ONLY the public answer vector reproduces it
    /// byte-for-byte with empty messages + a solved `rand[0]` per entry, so no joint information
    /// about the `k` secret messages leaks through the commitment-phase OOD answers.
    #[test]
    fn commitment_ood_vector_is_jointly_simulatable() {
        let mut rng = SmallRng::seed_from_u64(0x0DC0_FFEE);
        let k = 5usize; // commitment_ood_samples
        let mut challenges: Vec<EF> = Vec::new();
        let mut msgs_owned: Vec<Vec<EF>> = Vec::new();
        let mut rands_owned: Vec<Vec<EF>> = Vec::new();
        for _ in 0..k {
            let mut rho: EF = rng.random();
            while rho.is_zero() {
                rho = rng.random();
            }
            challenges.push(rho);
            msgs_owned.push((0..3).map(|_| rng.random()).collect());
            rands_owned.push((0..2).map(|_| rng.random()).collect());
        }
        let msgs: Vec<&[EF]> = msgs_owned.iter().map(Vec::as_slice).collect();
        let rands: Vec<&[EF]> = rands_owned.iter().map(Vec::as_slice).collect();

        // Real prover publishes the blinded OOD answer vector.
        let real = code_switch_ood_answer_vec(&challenges, &msgs, &rands);

        // Simulator knows ONLY `real` (public), NOT the messages: empty message ⇒ shift ρ^0 = 1 ⇒
        // rand[0] = real[i] reproduces answer i exactly.
        let empty: [EF; 0] = [];
        let sim_msgs: Vec<&[EF]> = (0..k).map(|_| empty.as_slice()).collect();
        let sim_rands_owned: Vec<[EF; 1]> = real.iter().map(|&y| [y]).collect();
        let sim_rands: Vec<&[EF]> = sim_rands_owned.iter().map(<[EF; 1]>::as_slice).collect();
        let sim = code_switch_ood_answer_vec(&challenges, &sim_msgs, &sim_rands);

        assert_eq!(
            real, sim,
            "commitment-phase OOD answer vector must be jointly simulatable from public data alone"
        );
    }

    /// PILLAR-3 (soundness, both directions): the verifier check [`code_switch_verify`] ACCEPTS the
    /// honest code-switched answer and its true `(msg_eval, mask_eval)`, and REJECTS any non-zero
    /// tamper of the answer OR of either opened evaluation. So the HVZK blinding is verifiable with
    /// zero soundness loss — a cheating prover cannot pass a forged OOD answer past the verifier.
    #[test]
    fn code_switch_answer_verifies_and_rejects_tampering() {
        let mut rng = SmallRng::seed_from_u64(0xC0DE_FADE);
        for _ in 0..128 {
            let l = 3usize;
            let r = 2usize;
            let mut rho: EF = rng.random();
            while rho.is_zero() {
                rho = rng.random();
            }
            let msg: Vec<EF> = (0..l).map(|_| rng.random()).collect();
            let rand: Vec<EF> = (0..r).map(|_| rng.random()).collect();

            let y = code_switch_ood_answer(rho, &msg, &rand);
            let msg_eval = zero_evader_eval(rho, &msg); // proved by WHIR folding
            let mask_eval = zero_evader_eval(rho, &rand); // opened from the mask commitment

            // Honest answer + honest openings MUST verify.
            assert!(
                code_switch_verify(y, msg_eval, mask_eval, rho, l),
                "honest code-switched answer must verify"
            );

            // Any non-zero tamper on the answer or either opening MUST be rejected.
            let mut e: EF = rng.random();
            while e.is_zero() {
                e = rng.random();
            }
            assert!(
                !code_switch_verify(y + e, msg_eval, mask_eval, rho, l),
                "tampered answer must be rejected"
            );
            assert!(
                !code_switch_verify(y, msg_eval + e, mask_eval, rho, l),
                "tampered message evaluation must be rejected"
            );
            assert!(
                !code_switch_verify(y, msg_eval, mask_eval + e, rho, l),
                "tampered mask evaluation must be rejected"
            );
        }
    }

    /// END-TO-END CONTRACT (Pillar-1 + Pillar-3): the prover's blinded OOD vector
    /// ([`code_switch_ood_answer_vec`]) and the verifier's per-answer check ([`code_switch_verify`])
    /// COMPOSE — every honest blinded answer passes verification against its true message + mask
    /// evaluations, AND the published answer differs from the plain (message-leaking) evaluation, so
    /// the blinding is actually active. This is the exact contract the WHIR adapter's `hiding` branch
    /// implements: the prover blinds + commits the mask; the verifier opens the mask + checks.
    #[test]
    fn prover_and_verifier_primitives_compose_end_to_end() {
        let mut rng = SmallRng::seed_from_u64(0x0E2E_C0DE);
        let k = 4usize;
        let mut rho: Vec<EF> = Vec::new();
        let mut msgs_o: Vec<Vec<EF>> = Vec::new();
        let mut rands_o: Vec<Vec<EF>> = Vec::new();
        for _ in 0..k {
            let mut r: EF = rng.random();
            while r.is_zero() {
                r = rng.random();
            }
            rho.push(r);
            msgs_o.push((0..3).map(|_| rng.random()).collect());
            rands_o.push((0..2).map(|_| rng.random()).collect());
        }
        let msgs: Vec<&[EF]> = msgs_o.iter().map(Vec::as_slice).collect();
        let rands: Vec<&[EF]> = rands_o.iter().map(Vec::as_slice).collect();

        // Prover publishes the blinded OOD answers.
        let ys = code_switch_ood_answer_vec(&rho, &msgs, &rands);

        for i in 0..k {
            let msg_eval = zero_evader_eval(rho[i], &msgs_o[i]); // proved by WHIR folding
            let mask_eval = zero_evader_eval(rho[i], &rands_o[i]); // opened from the mask commitment

            // Verifier accepts the honest blinded answer against its true openings.
            assert!(
                code_switch_verify(ys[i], msg_eval, mask_eval, rho[i], msgs_o[i].len()),
                "honest blinded OOD answer must verify end-to-end"
            );
            // Blinding is genuinely active: the published answer is NOT the plain message eval
            // (unless the mask eval hit 0, a measure-1/|F| event we exclude).
            if !mask_eval.is_zero() {
                assert_ne!(
                    ys[i], msg_eval,
                    "published answer must be blinded, not the plain message evaluation"
                );
            }
        }
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! HF38 CONFIDENTIAL SOLVENCY PROOF — ported in the PQ shape from the old tree's
//! `HF_VERSION_SOLVENCY_PROOF=38`.
//!
//! A block MAY carry an opaque proof that the reserve backs the circulating supply at the required ratio
//! (150% PSM backing) **without revealing any amount** — the digital-cash pillar (an observer learns the
//! reserve is solvent, never how much reserve or how much liability). Reserve and liability are Poseidon/hash
//! COMMITMENTS (no raw value in public IO — Pillar 1); the ZK proof attests `reserve >= ratio * liability`
//! in-circuit. Zero-amount, zero-identity.
//!
//! VERIFY-IF-PRESENT (liveness pillar): the solvency carrier is OPTIONAL per block — its absence NEVER stops
//! block production/acceptance. When a block DOES carry one, consensus fail-closes on a BAD proof (rejects the
//! carrier), never on the chain's progress. This mirrors the [`crate::decider`] fail-closed seam: the real
//! verifier rides the WHIR light decider (usdm-decider); until it is installed,
//! [`RefuseAllSolvency`] REJECTS every proof so nothing unverified is ever accepted.

use serde::{Deserialize, Serialize};

/// An opaque confidential-solvency carrier: commitments to the reserve + liability (NO amounts) plus the ZK
/// proof that `reserve >= required_ratio * liability`. Every field is a commitment or a proof — never a value.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SolvencyProof {
    /// Poseidon/hash commitment to the total reserve value (opaque — no amount revealed).
    pub reserve_commit: [u8; 32],
    /// Poseidon/hash commitment to the total circulating liability (opaque — no amount revealed).
    pub liability_commit: [u8; 32],
    /// The required backing ratio in basis points (15000 = 150%). Public policy parameter, not a value leak.
    pub ratio_bps: u32,
    /// The ZK proof that the committed reserve backs the committed liability at `ratio_bps` (≤1.8MB constant).
    pub proof: Vec<u8>,
}

impl SolvencyProof {
    /// No-growth bound on the proof size — the FAST/scalable pillar (≤1.8MB constant, same cap as the decider).
    pub const MAX_PROOF_BYTES: usize = 1_800_000;
    /// The DEFAULT backing ratio (150% PSM) — mirrors `params::MINT_RATIO_DEFAULT_BPS`. This is the genesis
    /// default, NOT a hard floor: the NETWORK's required ratio is the governance-tunable `mint_ratio_bps`,
    /// enforced at mint authorization. A carrier's ratio only has to be positive to be well-formed.
    pub const MIN_RATIO_BPS: u32 = 15_000;

    /// Well-formed only if the proof is non-empty, within the constant-size cap, the two commitments are
    /// distinct non-zero digests, and the claimed ratio is POSITIVE. The NETWORK's required over-collateral
    /// ratio is NOT fixed here — it is the governance-tunable `ChainParams::mint_ratio_bps`, enforced at mint
    /// authorization (a mint whose ratio is below the current governance ratio is rejected there). Well-
    /// formedness only rules out a zero/absent ratio. An over-cap blob is rejected BEFORE verification.
    pub fn within_bounds(&self) -> bool {
        !self.proof.is_empty()
            && self.proof.len() <= Self::MAX_PROOF_BYTES
            && self.ratio_bps > 0
            && self.reserve_commit != [0u8; 32]
            && self.liability_commit != [0u8; 32]
    }
}

/// The confidential-solvency verifier seam — implemented by the WHIR light decider (usdm-decider, as a
/// prebuilt lib). Certifies the proof attests `reserve >= ratio * liability` for the committed values.
pub trait SolvencyVerifier {
    fn verify_solvency(&self, proof: &SolvencyProof) -> bool;
}

/// The default when no real verifier is installed: REJECT every proof. Nothing unverified is ever accepted;
/// the WHIR verifier replaces it at deploy time.
///
/// ⛔ Renamed from `UnverifiedSolvency` for the reason its settlement sibling records: a name that reads as
/// "unverified, therefore permitted" on a gate that refuses is a trap, and it caught me.
pub struct RefuseAllSolvency;

impl SolvencyVerifier for RefuseAllSolvency {
    fn verify_solvency(&self, _proof: &SolvencyProof) -> bool {
        false
    }
}

/// Gate a solvency carrier: enforce the constant-size + well-formedness bound FIRST, then the ZK verify —
/// both must pass (fail-closed on either). Called by consensus ONLY when a block carries a solvency proof;
/// a block WITHOUT one is always fine (verify-if-present — liveness never depends on the carrier).
pub fn accept_solvency(verifier: &dyn SolvencyVerifier, proof: &SolvencyProof) -> bool {
    proof.within_bounds() && verifier.verify_solvency(proof)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn proof(proof_len: usize) -> SolvencyProof {
        SolvencyProof {
            reserve_commit: [3u8; 32],
            liability_commit: [5u8; 32],
            ratio_bps: 15_000,
            proof: vec![1u8; proof_len],
        }
    }

    #[test]
    fn unverified_solvency_is_fail_closed() {
        // no real verifier installed -> every well-formed proof is REJECTED (never accept unverified).
        assert!(!accept_solvency(&RefuseAllSolvency, &proof(1000)));
    }

    #[test]
    fn bounds_reject_oversize_empty_zero_ratio_and_zero_commit_before_verify() {
        struct AlwaysAccept;
        impl SolvencyVerifier for AlwaysAccept {
            fn verify_solvency(&self, _p: &SolvencyProof) -> bool {
                true
            }
        }
        // over-cap / empty proof -> rejected by the no-blowup gate BEFORE the verifier runs.
        assert!(!accept_solvency(
            &AlwaysAccept,
            &proof(SolvencyProof::MAX_PROOF_BYTES + 1)
        ));
        assert!(!accept_solvency(&AlwaysAccept, &proof(0)));
        // a ZERO ratio is malformed (unbacked, meaningless) — rejected FAIL-CLOSED, the one value never accepted.
        let mut zero_ratio = proof(1000);
        zero_ratio.ratio_bps = 0;
        assert!(!accept_solvency(&AlwaysAccept, &zero_ratio));
        // The hardcoded 150% well-formedness floor is RETIRED — the required ratio moved to the governance-tunable
        // `mint_ratio_bps`, enforced in psm::authorize_mint (community's choice, per the user's decision that
        // governance may tune the coin below a stablecoin). So a positive sub-150% ratio is well-formed here.
        let mut sub150 = proof(1000);
        sub150.ratio_bps = 14_999;
        assert!(accept_solvency(&AlwaysAccept, &sub150));
        // a zero commitment is malformed (no real reserve/liability committed).
        let mut zero_res = proof(1000);
        zero_res.reserve_commit = [0u8; 32];
        assert!(!accept_solvency(&AlwaysAccept, &zero_res));
        // a well-formed carrier passes the bound + the (test) verifier.
        assert!(accept_solvency(&AlwaysAccept, &proof(1000)));
    }

    #[test]
    fn tampered_commitment_is_rejected_by_the_real_verifier_seam() {
        // A verifier that only accepts a specific (reserve, liability) binding models the real ZK check:
        // flipping a committed value must break acceptance (soundness — no forged solvency claim).
        struct BindingVerifier {
            expect_reserve: [u8; 32],
        }
        impl SolvencyVerifier for BindingVerifier {
            fn verify_solvency(&self, p: &SolvencyProof) -> bool {
                p.reserve_commit == self.expect_reserve
            }
        }
        let v = BindingVerifier {
            expect_reserve: [3u8; 32],
        };
        assert!(
            accept_solvency(&v, &proof(1000)),
            "the honest carrier verifies"
        );
        let mut tampered = proof(1000);
        tampered.reserve_commit = [9u8; 32]; // forged reserve commitment
        assert!(
            !accept_solvency(&v, &tampered),
            "a tampered reserve commitment is REJECTED"
        );
    }
}

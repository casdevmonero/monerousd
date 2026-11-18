// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! O(1) ZK consensus-verify (brick 6): the WHOLE-CHAIN block decider gate.
//!
//! A joining / validium node does NOT replay block history. It verifies ONE constant-size (≤1.8MB)
//! **block decider** proof that the chain up to `tip` is valid — the no-inflation + tamper gate and the
//! #29 DSYNC instant-sync anchor — then jumps to that tip. O(1) at ANY DAG width. (Per-tx user actions
//! — Send / bond / Swap / … — are a SEPARATE gate that already rides the HVZK-WHIR light decider, via
//! `whir_decider::pqspend_direct_verify_carrier`. This trait is the chain-level proof.)
//!
//! The concrete verifier is the pure-Rust `usdm-decider` whole-chain WHIR light decider
//! ([`crate::whir_decider::WhirDecider`]) — the ONE canonical construction every device runs, bound
//! behind the [`ConsensusVerifier`] trait. The retired pqpool STARK-era FFI is DELETED (never linked).
//! Until a verifier is installed, [`UnverifiedDecider`] is the default and REJECTS every bundle
//! (fail-closed): a node never adopts a tip it cannot verify.

use crate::block::BlockId;
use serde::{Deserialize, Serialize};

/// The constant-size decider bundle a node verifies to instant-sync (#29 DSYNC) or to gate a tip: the
/// O(1) chain accumulator + tip + blue-score, plus the recursive WHIR proof binding them together.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeciderBundle {
    pub tip: BlockId,
    pub blue_score: u64,
    pub chain_acc: [u8; 16],
    /// The whole-chain block-decider proof (≤1.8MB constant); verified by [`ConsensusVerifier::verify_bundle`].
    pub proof: Vec<u8>,
}

impl DeciderBundle {
    /// No-growth bound on the proof size — the FAST/scalable pillar (≤1.8MB constant at any width).
    pub const MAX_PROOF_BYTES: usize = 1_800_000;

    /// A bundle is well-formed only if its proof is non-empty and within the constant-size cap. An
    /// over-cap "proof" is rejected BEFORE verification so a huge blob can never even be verified
    /// (no-blowup, no DoS surface).
    pub fn within_size_bound(&self) -> bool {
        !self.proof.is_empty() && self.proof.len() <= Self::MAX_PROOF_BYTES
    }
}

/// The ZK consensus verifier seam — implemented by the pure-Rust whole-chain WHIR light decider
/// ([`crate::whir_decider::WhirDecider`]). Certifies the proof binds `(tip, blue_score, chain_acc)`
/// and that the chain is no-inflation + tamper-free.
pub trait ConsensusVerifier {
    fn verify_bundle(&self, bundle: &DeciderBundle) -> bool;
}

/// The default when no real decider verifier is installed: REJECT every bundle (fail-closed). A node
/// never adopts a tip / instant-sync bundle it cannot verify. [`crate::whir_decider::WhirDecider`] replaces it.
pub struct UnverifiedDecider;

impl ConsensusVerifier for UnverifiedDecider {
    fn verify_bundle(&self, _bundle: &DeciderBundle) -> bool {
        false
    }
}

/// Gate a decider bundle for adoption: enforce the constant-size bound FIRST, then the ZK verify —
/// both must pass (fail-closed on either). This is what a joining node calls before jumping to
/// `bundle.tip`; a validium node calls it before serving that tip onward.
pub fn accept_bundle(verifier: &dyn ConsensusVerifier, bundle: &DeciderBundle) -> bool {
    bundle.within_size_bound() && verifier.verify_bundle(bundle)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::hash::Hash32;

    fn bundle(proof_len: usize) -> DeciderBundle {
        DeciderBundle {
            tip: Hash32::hash(b"a-decider-tip"),
            blue_score: 42,
            chain_acc: [7u8; 16],
            proof: vec![1u8; proof_len],
        }
    }

    #[test]
    fn unverified_decider_is_fail_closed() {
        // no real verifier installed -> every well-formed bundle is REJECTED (never adopt unverified).
        assert!(!accept_bundle(&UnverifiedDecider, &bundle(1000)));
    }

    #[test]
    fn size_bound_rejects_oversize_and_empty_before_verify() {
        // a test verifier that would accept anything the size-gate lets through.
        struct AlwaysAccept;
        impl ConsensusVerifier for AlwaysAccept {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        // an over-cap or empty proof is rejected by the no-blowup gate BEFORE the verifier runs.
        assert!(!accept_bundle(
            &AlwaysAccept,
            &bundle(DeciderBundle::MAX_PROOF_BYTES + 1)
        ));
        assert!(!accept_bundle(&AlwaysAccept, &bundle(0)));
        // a within-bound proof passes the size gate + the (test) verifier.
        assert!(accept_bundle(&AlwaysAccept, &bundle(1000)));
    }
}

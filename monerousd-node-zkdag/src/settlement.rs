// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! HF44 PRIVATE L2 SETTLEMENT — ported in the PQ shape from the old tree's `HF_VERSION_L2_SETTLEMENT=44`.
//!
//! A block MAY carry an L2 SETTLEMENT bundle: a batch of L2 transactions proven in ONE constant-size WHIR proof
//! that transitions the committed L2 state root `prev -> new`. High effective TPS (thousands of L2 txs settle
//! under one O(1) verify) with FULL privacy — the batch is an opaque commitment, so an observer learns neither
//! which txs settled, nor amounts, nor parties (digital-cash pillar). Only the two state-root digests and the
//! proof are public, and both roots are commitments (no raw witness in public IO — Pillar 1).
//!
//! STATE-ROOT CHAINING (soundness): a settlement is accepted ONLY if its `prev_state_root` equals the node's
//! CURRENT L2 state root — so a batch cannot replay, skip, or fork the L2 state. On accept, the node advances
//! its L2 root to `new_state_root`. This is what stops a forged/duplicated settlement from moving value.
//!
//! VERIFY-IF-PRESENT (liveness pillar): the settlement carrier is OPTIONAL per block — its absence NEVER stops
//! block production/acceptance. A BAD settlement fail-closes on the carrier only, never on the chain. Mirrors
//! the [`crate::decider`] seam: the real verifier is the WHIR-native cross-sender settle (#142 conversion);
//! until it is installed, [`RefuseAllSettlement`] REJECTS every bundle so nothing unverified ever settles.

use serde::{Deserialize, Serialize};

/// An opaque L2 settlement carrier: the state-root transition `prev -> new` over an opaque batch commitment,
/// plus the ZK proof that the batch is valid (balances conserved, every L2 spend authorized) and effects the
/// transition. Every field is a commitment or a proof — never a per-tx amount/party.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SettlementBundle {
    /// The L2 state root this batch consumes (must equal the node's current L2 root — anti-replay binding).
    pub prev_state_root: [u8; 32],
    /// The L2 state root this batch produces (the node advances to this on accept).
    pub new_state_root: [u8; 32],
    /// Opaque commitment to the settled batch (no per-tx leak; binds the proof to a specific batch).
    pub batch_commit: [u8; 32],
    /// The ZK proof that `batch_commit` is a valid batch transitioning `prev_state_root -> new_state_root`
    /// (balance-conserving, no double-spend) — ≤1.8MB constant, O(1) verify at any batch size.
    pub proof: Vec<u8>,
}

impl SettlementBundle {
    /// No-growth bound on the proof size — the FAST/scalable pillar (≤1.8MB constant, same cap as the decider).
    pub const MAX_PROOF_BYTES: usize = 1_800_000;

    /// Well-formed only if the proof is non-empty + within the constant cap, the batch commitment is non-zero,
    /// and the transition is non-trivial (`new != prev`). An over-cap blob is rejected BEFORE verification
    /// (no-blowup / no DoS surface); a no-op transition carries nothing and is rejected.
    pub fn within_bounds(&self) -> bool {
        !self.proof.is_empty()
            && self.proof.len() <= Self::MAX_PROOF_BYTES
            && self.batch_commit != [0u8; 32]
            && self.new_state_root != self.prev_state_root
    }
}

/// The L2-settlement verifier seam — implemented by the WHIR-native cross-sender settle verify (#142).
/// Certifies the proof effects `prev_state_root -> new_state_root` for the committed batch, balance-conserving.
pub trait SettlementVerifier {
    fn verify_settlement(&self, bundle: &SettlementBundle) -> bool;
}

/// The default when no real verifier is installed: REJECT every bundle. Nothing unverified ever settles;
/// the WHIR-native settle verifier (#142) replaces it when the conversion lands.
///
/// ⛔ IT WAS CALLED `UnverifiedSettlement`, AND THAT NAME COST A FALSE ALARM. It reads as "unverified,
/// therefore permitted", and on 2026-09-22 I read it exactly that way and reported a fail-open default that
/// does not exist. The behaviour was always to refuse. A default that REFUSES must be named for refusing,
/// because the one thing a reader must never get wrong about a gate is which way it fails.
pub struct RefuseAllSettlement;

impl SettlementVerifier for RefuseAllSettlement {
    fn verify_settlement(&self, _bundle: &SettlementBundle) -> bool {
        false
    }
}

/// Gate an L2 settlement against the node's CURRENT L2 root: enforce (1) the constant-size + well-formedness
/// bound, (2) the anti-replay state-root binding (`prev_state_root == current_root`), and (3) the ZK verify —
/// all must pass (fail-closed on any). Returns the NEW root to advance to on success, `None` on rejection.
/// Called by consensus ONLY when a block carries a settlement; a block WITHOUT one is always fine
/// (verify-if-present — liveness never depends on the carrier).
pub fn accept_settlement(
    verifier: &dyn SettlementVerifier,
    current_root: &[u8; 32],
    bundle: &SettlementBundle,
) -> Option<[u8; 32]> {
    if bundle.within_bounds()
        && &bundle.prev_state_root == current_root
        && verifier.verify_settlement(bundle)
    {
        Some(bundle.new_state_root)
    } else {
        None
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    struct AlwaysAccept;
    impl SettlementVerifier for AlwaysAccept {
        fn verify_settlement(&self, _b: &SettlementBundle) -> bool {
            true
        }
    }

    fn bundle(prev: [u8; 32], new: [u8; 32], proof_len: usize) -> SettlementBundle {
        SettlementBundle {
            prev_state_root: prev,
            new_state_root: new,
            batch_commit: [7u8; 32],
            proof: vec![1u8; proof_len],
        }
    }

    #[test]
    fn unverified_settlement_is_fail_closed() {
        let cur = [0u8; 32];
        assert!(
            accept_settlement(&RefuseAllSettlement, &cur, &bundle(cur, [1u8; 32], 1000)).is_none()
        );
    }

    #[test]
    fn happy_path_advances_the_l2_root() {
        let cur = [0u8; 32];
        let next = [1u8; 32];
        let out = accept_settlement(&AlwaysAccept, &cur, &bundle(cur, next, 1000));
        assert_eq!(
            out,
            Some(next),
            "an honest settlement advances current -> new"
        );
    }

    #[test]
    fn wrong_prev_root_is_rejected_anti_replay() {
        // the batch consumes root X, but the node is at root Y -> REJECTED (a settlement cannot replay/fork).
        let cur = [0u8; 32];
        let stale = [9u8; 32];
        assert!(
            accept_settlement(&AlwaysAccept, &cur, &bundle(stale, [1u8; 32], 1000)).is_none(),
            "a settlement whose prev_state_root != current L2 root is REJECTED"
        );
    }

    #[test]
    fn oversize_empty_and_noop_transition_rejected_before_verify() {
        let cur = [0u8; 32];
        assert!(accept_settlement(
            &AlwaysAccept,
            &cur,
            &bundle(cur, [1u8; 32], SettlementBundle::MAX_PROOF_BYTES + 1)
        )
        .is_none());
        assert!(accept_settlement(&AlwaysAccept, &cur, &bundle(cur, [1u8; 32], 0)).is_none());
        // a no-op transition (new == prev) carries no settlement and is rejected.
        assert!(accept_settlement(&AlwaysAccept, &cur, &bundle(cur, cur, 1000)).is_none());
    }

    #[test]
    fn tampered_batch_is_rejected_by_the_real_verifier_seam() {
        // a verifier bound to a specific batch commitment models the real ZK check: swapping the batch breaks it.
        struct BindingVerifier {
            expect_batch: [u8; 32],
        }
        impl SettlementVerifier for BindingVerifier {
            fn verify_settlement(&self, b: &SettlementBundle) -> bool {
                b.batch_commit == self.expect_batch
            }
        }
        let cur = [0u8; 32];
        let v = BindingVerifier {
            expect_batch: [7u8; 32],
        };
        assert_eq!(
            accept_settlement(&v, &cur, &bundle(cur, [1u8; 32], 1000)),
            Some([1u8; 32])
        );
        let mut tampered = bundle(cur, [1u8; 32], 1000);
        tampered.batch_commit = [8u8; 32]; // forged batch
        assert!(
            accept_settlement(&v, &cur, &tampered).is_none(),
            "a tampered batch commitment is REJECTED"
        );
    }
}

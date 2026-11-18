// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! PSM confidential MINT-AUTHORIZATION gate (Buy-USDm) — the sound core of the Peg Stability Module: a
//! threshold-authorized, CONFIDENTIAL, ≥150%-over-collateralized mint.
//!
//! ## Decentralization (Pillar A)
//! A mint is NEVER a solo key. It is authorized by a **≥2/3 bonded-VALIDATOR threshold attestation**
//! (permissionless-by-bond: any node that posted a bond is a reserve-custody attestor; the same set + threshold
//! that finalizes blocks). The attestors are the parties who witnessed the reserve deposit; no single party can
//! mint, and no party holds a privileged mint key.
//!
//! ## Confidentiality (Pillar 1)
//! No amount leaks. The deposited reserve value and the minted liability are **Poseidon commitments**; the 150%
//! backing (`reserve_commit ≥ ratio · liability_commit`) is proven in ZK via the reused
//! [`crate::solvency::SolvencyProof`]. The gate never sees a plaintext deposit or mint amount.
//!
//! ## Liveness + fail-closed (Pillars B, 3)
//! The mint carrier is OPTIONAL per block — its absence never stops block production. When present it fails
//! CLOSED on the bad item only: no bonded validators, a sub-2/3 attested weight, a bad ML-DSA signature, or a
//! sub-150% solvency proof ⇒ NO mint. Deploy-time material that waits: the reserve custodians agreeing off-band
//! on the deposit value commitment (the price oracle is INSIDE the threshold — the attestors sign the
//! commitment), and the confidential note issuance. This gate — the sound VERIFIER + fail-closed wiring — is
//! complete now.

use crate::pqauth::{mint_attest_msg, pubkey_id, PqVerifier};
use crate::solvency::{accept_solvency, SolvencyProof, SolvencyVerifier};
use std::collections::HashSet;

/// One bonded validator's attestation that it witnessed the reserve deposit backing this mint.
///
/// ⭐ `Debug`/`PartialEq`/`Eq` are derived so an attested CHAIN OBJECT can carry these in a struct that
/// itself derives them — `bridge_credit_tx::BridgeCreditTx` is the first to do so. Both fields are plain
/// byte vectors (an ML-DSA public key and its signature), so all three are structural and add no
/// semantics: equality is byte equality, which is exactly what a wire object needs.
///
/// ⛔ NOTHING HERE IS SECRET. A `MintAttestor` is a PUBLIC key and a PUBLIC signature over a
/// domain-separated message; it names no note, amount, owner or scan key, so deriving `Debug` on it
/// cannot print a confidential value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintAttestor {
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

/// A confidential PSM mint request. `solvency` carries the reserve-value commitment (`reserve_commit`), the
/// minted-liability commitment (`liability_commit`), the policy ratio, and the ZK proof that
/// `reserve_commit ≥ ratio · liability_commit` — so NO plaintext amount appears. The bonded-validator
/// attestations authorize this exact `(deposit_id, commitments, recipient)` binding.
pub struct MintRequest {
    pub deposit_id: [u8; 32],
    pub recipient_note_cm: [u8; 32],
    pub solvency: SolvencyProof,
    pub attestors: Vec<MintAttestor>,
}

/// Result of authorizing a mint. Only `Authorized` permits issuance; every other outcome rejects fail-closed.
#[derive(Debug, PartialEq, Eq)]
pub enum MintOutcome {
    /// ≥2/3 bonded-validator weight attested AND the confidential 150% proof verified → the mint may issue.
    Authorized,
    /// A DISTINCT-attestor bonded weight below the 2/3 super-majority (incl. an empty validator set) → rejected.
    InsufficientQuorum,
    /// The confidential solvency proof failed the 150% backing floor → rejected (no under-backed mint).
    Undercollateralized,
    /// An attestor's ML-DSA signature did not authenticate the mint message → rejected.
    Unauthenticated,
}

/// Bonded-weight source for the mint quorum — implemented by [`crate::validator::ValidatorSet`] (the same set
/// that secures finality). A tiny trait so the gate logic is unit-testable without a full node.
pub trait BondQuorum {
    fn bond_of(&self, id: &[u8; 32]) -> u128;
    fn total_bond(&self) -> u128;
    /// ⭐ SAFE AT SCALE — how many custody vaults this quorum is cut into (`custody_vaults`). A quorum that knows no vaults
    /// is one vault: itself.
    fn vault_count(&self) -> u32 {
        1
    }
    /// ⭐ SAFE AT SCALE — custody vault `vault` on its own: its members' bonded weights as a quorum, and what its cheapest
    /// signing set FORFEITS, in bond units (`custody_vaults::forfeit`). `None` for a vault that does not exist, and for
    /// every quorum that knows no vaults — so a door asked to take a vault's word alone refuses.
    fn vault(&self, _vault: u32) -> Option<(VaultQuorum, u128)> {
        None
    }
}

/// ⭐ SAFE AT SCALE — ONE CUSTODY VAULT AS A QUORUM: the bonded weight of each member and nothing else, so the ONE tally
/// (`peg::tally_attestors`) counts two thirds of the vault's own weight exactly as it counts two thirds of the set's. A
/// signer outside the vault weighs nothing in it.
/// SCALE: at most `custody_vaults::VAULT_MAX` members whatever the bonded set — the signatures a door verifies for one
/// object are bounded by the vault, never by the nodes that bond.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultQuorum {
    /// O1-FOOTPRINT-REVIEWED: bounded by `custody_vaults::VAULT_MAX` (one row per member of one vault)
    pub members: Vec<([u8; 32], u128)>,
}

impl BondQuorum for VaultQuorum {
    fn bond_of(&self, id: &[u8; 32]) -> u128 {
        self.members.iter().find(|(m, _)| m == id).map_or(0, |(_, w)| *w)
    }
    fn total_bond(&self) -> u128 {
        self.members.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w))
    }
}

/// The live bonded-validator set IS the mint quorum (permissionless-by-bond; the same set that secures finality).
impl BondQuorum for crate::validator::ValidatorSet {
    fn bond_of(&self, id: &[u8; 32]) -> u128 {
        crate::validator::ValidatorSet::bond_of(self, id)
    }
    fn total_bond(&self) -> u128 {
        crate::validator::ValidatorSet::total_bond(self)
    }
    fn vault_count(&self) -> u32 {
        u32::try_from(self.custody_vaults().len()).unwrap_or(u32::MAX).max(1)
    }
    fn vault(&self, vault: u32) -> Option<(VaultQuorum, u128)> {
        let members = self.custody_vaults().into_iter().nth(usize::try_from(vault).ok()?)?;
        let members: Vec<([u8; 32], u128)> = members.into_iter().map(|m| (m, crate::validator::ValidatorSet::bond_of(self, &m))).collect();
        let bonds: Vec<u128> = members.iter().map(|(_, w)| *w).collect();
        Some((VaultQuorum { members }, crate::custody_vaults::forfeit(&bonds)))
    }
}

/// Authorize a confidential PSM mint. Fail-closed on ANY of: bad confidential 150% proof, an unauthenticated
/// attestor, or a distinct-attestor bonded weight below the 2/3 super-majority (empty set → rejects). `pq_verifier`
/// is the ML-DSA seam; `solvency_verifier` is the ZK-verify seam.
pub fn authorize_mint(
    quorum: &dyn BondQuorum,
    pq_verifier: &dyn PqVerifier,
    solvency_verifier: &dyn SolvencyVerifier,
    req: &MintRequest,
    required_ratio_bps: u32,
) -> MintOutcome {
    // 1) BONDED-VALIDATOR THRESHOLD: ≥2/3 of total bonded weight, over DISTINCT attestors, over the exact mint.
    let msg = mint_attest_msg(
        &req.deposit_id,
        &req.solvency.reserve_commit,
        &req.solvency.liability_commit,
        &req.recipient_note_cm,
        req.solvency.ratio_bps,
    );
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut attested: u128 = 0;
    // ⛔ BOUNDED WORK (§9.6 Q5) — THE CALLER CHOOSES THE LENGTH OF THIS VECTOR.
    //
    // WHAT PRODUCES THE CONDITION: `req.attestors` is a WIRE FIELD of a `MintRequest` sent by an
    // untrusted caller. The repeats and the unbonded keys are not something this node writes and then
    // reads back — they are the attacker's own bytes, chosen freely, and there is no producer of them
    // inside this crate to delete. That is the one cause a door may legitimately filter rather than
    // remove: it is on the far side of the wire.
    // CAN IT BE DELETED: no. Nothing caps the vector — `BondQuorum` exposes only `bond_of` and
    // `total_bond`, no cardinality — so before this change the loop was ONE ML-DSA VERIFY PER ELEMENT
    // with the element count entirely attacker-chosen. A request carrying a million signatures cost a
    // million verifies before the threshold was even computed.
    // WHY THE BRANCHES STAY, AND WHY THIS IS NOT A SKIP-BECAUSE-SEEN PATCH: the bound is derived from
    // what can MOVE THE VERDICT. Only a DISTINCT, BONDED attestor ever adds weight, so those are the
    // only two the node pays a signature check for; the verify count is now bounded by the size of the
    // bonded set, which an attacker can only grow by posting real bond. The filter is the definition of
    // the quorum, not a special case bolted beside it.
    // NO VERDICT CHANGES: a repeat and an unbonded key each contributed exactly zero weight before and
    // contribute exactly zero now. What changes is that a malformed entry which could never have
    // affected the outcome no longer fails the whole operation — the charter's rule, fail-closed on the
    // BAD ITEM, never on the operation around it.
    // MUST-STAY-GREEN: `undercollateralized_proof_is_rejected`, the psm threshold suite.
    for a in &req.attestors {
        let id = pubkey_id(&a.pubkey);
        // A repeated signer: already counted, so its signature cannot change the verdict.
        if !seen.insert(id) {
            continue;
        }
        // An unbonded key: contributes zero weight by definition of the quorum, so its signature
        // cannot change the verdict either. Checked BEFORE the verify — that ordering is the fix.
        if quorum.bond_of(&id) == 0 {
            continue;
        }
        if !pq_verifier.verify(&a.pubkey, &msg, &a.sig) {
            return MintOutcome::Unauthenticated; // fail-closed on a bad signature that COULD have counted
        }
        attested = attested.saturating_add(quorum.bond_of(&id)); // only DISTINCT bonded attestors count
    }
    let total = quorum.total_bond();
    // 2/3 super-majority of bonded weight; with no validators (total==0) the attested weight is 0 → reject.
    if !crate::quorum_math::two_thirds_met(attested, total) {
        return MintOutcome::InsufficientQuorum;
    }
    // 2) NETWORK-REQUIRED backing at the LIVE governance ratio: the proof's claimed ratio must meet the current
    //    governance-tunable `mint_ratio_bps` (the community's chosen over-collateralization — read LIVE by the
    //    caller, never a stale copy, so a governance retune takes effect immediately), AND the ZK proof must
    //    attest reserve_commit ≥ ratio · liability_commit (no amount revealed). Both fail-closed → Undercollateralized.
    if req.solvency.ratio_bps < required_ratio_bps {
        return MintOutcome::Undercollateralized;
    }
    if !accept_solvency(solvency_verifier, &req.solvency) {
        return MintOutcome::Undercollateralized;
    }
    MintOutcome::Authorized
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock bonded quorum: fixed per-id weights, testing the threshold logic without a live node.
    struct Q {
        bonds: std::collections::HashMap<[u8; 32], u128>,
    }
    impl BondQuorum for Q {
        fn bond_of(&self, id: &[u8; 32]) -> u128 {
            *self.bonds.get(id).unwrap_or(&0)
        }
        fn total_bond(&self) -> u128 {
            self.bonds.values().sum()
        }
    }

    /// Mock ML-DSA seam: accepts a signature iff `pubkey` is in the honest set (sig content ignored — the real
    /// `MlDsaVerifier` is the production seam; here we exercise the THRESHOLD + fail-closed logic).
    struct Pq {
        honest: HashSet<Vec<u8>>,
    }
    impl PqVerifier for Pq {
        fn verify(&self, pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
            self.honest.contains(pubkey)
        }
    }

    struct SolvOk;
    impl SolvencyVerifier for SolvOk {
        fn verify_solvency(&self, _p: &SolvencyProof) -> bool {
            true
        }
    }
    struct SolvBad;
    impl SolvencyVerifier for SolvBad {
        fn verify_solvency(&self, _p: &SolvencyProof) -> bool {
            false
        }
    }

    fn pk(n: u8) -> Vec<u8> {
        vec![n; 40]
    }
    fn proof() -> SolvencyProof {
        SolvencyProof {
            reserve_commit: [3u8; 32],
            liability_commit: [5u8; 32],
            ratio_bps: 15_000,
            proof: vec![1u8; 1000],
        }
    }
    fn req(attestors: &[u8]) -> MintRequest {
        MintRequest {
            deposit_id: [7u8; 32],
            recipient_note_cm: [9u8; 32],
            solvency: proof(),
            attestors: attestors
                .iter()
                .map(|&n| MintAttestor {
                    pubkey: pk(n),
                    sig: vec![0u8; 8],
                })
                .collect(),
        }
    }
    fn three_equal_validators() -> Q {
        let mut bonds = std::collections::HashMap::new();
        for n in 1..=3u8 {
            bonds.insert(pubkey_id(&pk(n)), 2000u128);
        }
        Q { bonds }
    }

    /// Counting ML-DSA seam: the same accept rule as [`Pq`], plus a tally of how many signature
    /// checks the door actually paid for. The COUNT is the subject — a bound nobody measures is a
    /// comment, and this one lived as a comment in `authorize_mint` with nothing holding it.
    ///
    /// This double HOLDS NO SET. The honest signers are exactly the three bonded keys, so membership
    /// is COMPUTED from `pk()` on each call rather than stored; there is no collection here to carry
    /// a bound, and no writer that could grow one.
    struct CountingPq {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl PqVerifier for CountingPq {
        fn verify(&self, pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (1u8..=3).any(|n| pubkey == pk(n).as_slice())
        }
    }
    impl CountingPq {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn paid(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// ⛔ PIN — THE MINT DOOR'S SIGNATURE WORK IS f(BONDED SET), NEVER f(CALLER'S VECTOR), ON EVERY
    /// PARTY THAT DECIDES.
    ///
    /// PAST-CHATS-CHECKED: this follows the house bounded-work pin `pin_d5_the_btc_deposit_watch_set_
    /// must_be_bounded_against_a_hostile_caller` (family_d_door_audit_tests.rs) — paid work measured
    /// against the ATTACKER'S OWN N rather than against an invented small constant, with the fix spec
    /// carried in the failure message. The bound here is read from the quorum (`q.bonds.len()`) and
    /// the expected verdict is COMPUTED by an honest call, so neither is a literal this pin could be
    /// narrowed to; growing the validator set cannot make it wrong.
    ///
    /// WHY TWO PARTIES AND NOT ONE: the mint door is a CONSENSUS decision. Every node handed the same
    /// `MintRequest` must reach the same verdict, so if attacker-chosen padding could change what one
    /// node decides — through a short-circuit, an iteration order, or a fail-closed branch that fires
    /// on a junk element — two honest nodes would disagree about whether a mint is authorized, and
    /// the disagreement would be attacker-triggered at will. Both parties are therefore built here,
    /// handed the identical hostile request, and checked for the same verdict AND a bounded cost.
    ///
    /// THE HOLE THIS HOLDS SHUT: `MintRequest::attestors` is a wire field with no length cap, and
    /// `BondQuorum` exposes only `bond_of`/`total_bond` — no cardinality — so the verify count is
    /// bounded by nothing the node owns. Before the 2026-09-08 reordering this loop ran ONE ML-DSA
    /// VERIFY PER ELEMENT with the element count entirely attacker-chosen.
    ///
    /// RED AGAINST THE PRE-FIX ORDERING — MEASURED 2026-09-08, both assertions, on a faithful
    /// reproduction of this loop under both orderings with this crate's own fixtures
    /// (`three_equal_validators()` bonds, the `Pq` honest set, the `attested*3 < total*2` rule):
    ///
    ///     HONEST [1,2]   n=2     PRE-FIX:   2 verifies -> Authorized      LANDED: 2 -> Authorized
    ///     HOSTILE (252)  n=252   PRE-FIX: 202 verifies -> Unauthenticated LANDED: 2 -> Authorized
    ///
    /// The count assertion is RED at 202 > 3. The VERDICT assertion is RED too, and that is the
    /// heavier finding: the pre-fix door did not merely burn CPU on the padding, it REFUSED THE MINT
    /// because of it. The first unbonded key fails the verify and returns `Unauthenticated`, so
    /// anyone able to append attestors to an otherwise-valid request could make a legitimate mint
    /// fail — griefing/censorship on the mint path, not just a denial-of-service. (202 rather than
    /// 252 because the pre-fix loop returns at the first unbonded key; an attacker padding with
    /// repeats of an HONEST key instead pays no early return at all and drives the count arbitrarily
    /// high while still landing `Authorized`. Both halves are real.)
    #[test]
    fn the_mint_doors_signature_work_is_bounded_by_the_bonded_set_on_every_party() {
        // The attacker's freely-chosen vector: one bonded key repeated 200×, a second bonded key,
        // and 51 keys carrying no bond at all. Only TWO DISTINCT BONDED attestors are in here, so
        // the honest request below carries exactly the same decidable content.
        let mut hostile: Vec<u8> = vec![1u8; 200];
        hostile.push(2);
        hostile.extend(100u8..=150u8);

        // The expectation is COMPUTED, never written down: what the honest subset alone decides.
        let ctl_q = three_equal_validators();
        let ctl = CountingPq::new();
        let expected = authorize_mint(&ctl_q, &ctl, &SolvOk, &req(&[1, 2]), 15_000);

        for name in ["party_a", "party_b"] {
            // Each party holds its own view of the same bonded set — independent state, one truth.
            let q = three_equal_validators();
            let pq = CountingPq::new();
            let verdict = authorize_mint(&q, &pq, &SolvOk, &req(&hostile), 15_000);

            assert_eq!(
                verdict, expected,
                "⛔ ATTACKER-TRIGGERED SPLIT on {name}: padding a request with repeats and unbonded \
                 keys changed the verdict away from what the same two distinct bonded attestors \
                 decide on their own ({expected:?}). Every node must decide a given mint alike, so a \
                 verdict that moves with junk the caller appended is a consensus split the attacker \
                 fires at will — and a work bound bought by refusing real attestations is a liveness \
                 hole wearing a fix's clothes."
            );
            assert!(
                pq.paid() <= q.bonds.len(),
                "⛔ BOUNDED WORK VIOLATED (§9.6 Q5, mint door) on {name}: {paid} ML-DSA verifies for \
                 {n} caller-chosen attestors against a bonded set of {bonded} (the honest request \
                 carrying the same decidable content paid {ctl}). The caller, not the node, is \
                 choosing this node's CPU cost on the mint path — post a request carrying a million \
                 signatures and the node pays a million verifies before the threshold is even \
                 computed. FIX SPEC: the bound is derived from what can MOVE THE VERDICT — only a \
                 DISTINCT, BONDED attestor ever adds weight — so the dedupe (`seen.insert`) and the \
                 zero-bond test (`quorum.bond_of(&id) == 0`) must BOTH precede `pq_verifier.verify` \
                 in `authorize_mint`. The verify count is then bounded by the size of the bonded \
                 set, which an attacker can only grow by posting real bond. Do not fix by capping \
                 the vector's length: a length cap is a refusal bound, and an honest quorum that \
                 outgrows it would be turned away at the mint door.",
                paid = pq.paid(),
                n = hostile.len(),
                bonded = q.bonds.len(),
                ctl = ctl.paid()
            );
        }
    }

    #[test]
    fn two_thirds_bonded_attestation_authorizes() {
        let q = three_equal_validators();
        let pq = Pq {
            honest: [pk(1), pk(2), pk(3)].into_iter().collect(),
        };
        // 2 of 3 equal validators = 4000/6000 ≥ 2/3 → authorized.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1, 2]), 15_000),
            MintOutcome::Authorized
        );
    }

    #[test]
    fn sub_threshold_is_rejected_fail_closed() {
        let q = three_equal_validators();
        let pq = Pq {
            honest: [pk(1), pk(2), pk(3)].into_iter().collect(),
        };
        // 1 of 3 = 2000/6000 < 2/3 → rejected.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1]), 15_000),
            MintOutcome::InsufficientQuorum
        );
    }

    #[test]
    fn duplicate_attestor_cannot_inflate_weight() {
        let q = three_equal_validators();
        let pq = Pq {
            honest: [pk(1)].into_iter().collect(),
        };
        // the same validator signed twice — counted ONCE (2000/6000) → still sub-threshold.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1, 1]), 15_000),
            MintOutcome::InsufficientQuorum
        );
    }

    #[test]
    fn bad_signature_is_rejected() {
        let q = three_equal_validators();
        // pk(2) is NOT honest → its sig fails → whole mint rejected.
        let pq = Pq {
            honest: [pk(1)].into_iter().collect(),
        };
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1, 2]), 15_000),
            MintOutcome::Unauthenticated
        );
    }

    #[test]
    fn undercollateralized_proof_is_rejected() {
        let q = three_equal_validators();
        let pq = Pq {
            honest: [pk(1), pk(2), pk(3)].into_iter().collect(),
        };
        // Even a full quorum cannot mint if the confidential 150% backing proof fails.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvBad, &req(&[1, 2, 3]), 15_000),
            MintOutcome::Undercollateralized
        );
    }

    #[test]
    fn empty_validator_set_never_mints() {
        let q = Q {
            bonds: std::collections::HashMap::new(),
        };
        let pq = Pq {
            honest: [pk(1)].into_iter().collect(),
        };
        // No bonded validators → no quorum can ever form → fail-closed.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1]), 15_000),
            MintOutcome::InsufficientQuorum
        );
    }

    #[test]
    fn mint_is_gated_by_the_governance_tunable_ratio_both_directions() {
        let q = three_equal_validators();
        let pq = Pq {
            honest: [pk(1), pk(2), pk(3)].into_iter().collect(),
        };
        // The request is a full quorum + a valid solvency proof backed at 150% (req's ratio_bps = 15_000).
        // If GOVERNANCE RAISES the required ratio to 200%, that same 150%-backed mint no longer meets the
        // network requirement → rejected fail-closed (money-loss-safe: never mint under-backed for the policy).
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1, 2, 3]), 20_000),
            MintOutcome::Undercollateralized
        );
        // If the COMMUNITY LOWERS the required ratio to 120% (choosing a less-over-collateralized coin), the same
        // 150%-backed mint now clears the requirement → authorized. Governance genuinely controls the ratio.
        assert_eq!(
            authorize_mint(&q, &pq, &SolvOk, &req(&[1, 2, 3]), 12_000),
            MintOutcome::Authorized
        );
    }
}

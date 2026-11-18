// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! BOND-WEIGHTED MULTISIG TALLY — MonerousD's post-quantum threshold-authorization overlay for the reserve bridge.
//!
//! WHAT IT IS (owner, 2026-09-20: "our pq frost is actually 'bond-weighted multisig tally' and signing is
//! automated by nodes"): every bonded custodian node signs the SAME statement INDEPENDENTLY and AUTOMATICALLY
//! with its own ML-DSA-65 key, and a verifier tallies the DISTINCT bonded weight behind the valid signatures to
//! ≥2/3 of the total. There is no key generation ceremony, no share, no nonce round, no interactive session and
//! no coordinator — nothing a node must do by hand, and a custodian that is offline simply contributes no
//! weight until it is back. The name "PQ-FROST" this module carried until 2026-09-21 was wrong: FROST is an
//! interactive share-based signing session with a manual local signing round, and this scheme has no such
//! round. The wire domain tags still spell `PQFROST` — they are consensus bytes and must not change; the
//! words are historical.
//!
//! THE GOAL: the first fully post-quantum bridge. A home chain's own asset signature is unavoidably classical —
//! that is the one thing we do not control. Everything MonerousD DOES control is post-quantum: this module makes
//! every RESERVE MOVEMENT (a peg-out that releases home-chain funds) ride UNDER a post-quantum threshold
//! CERTIFICATE — ≥2/3 of the LIVE bonded validators' distinct ML-DSA-65 signatures over the EXACT movement
//! statement — before any foreign-chain signature is ever produced. So the AUTHORITY that unlocks the reserve is
//! post-quantum: an adversary (even a quantum one) cannot AUTHORIZE a movement without forging the PQ signature.
//! The bridge is a PQ-secure OVERLAY; the funds are PQ-secured to the maximum the home chain allows, and the
//! foreign signature is a marked bridge-endpoint that only ever exists downstream of a valid PQ certificate. The
//! Bitcoin leg mirrors the same shape on its own terms (`crate::btc_tx`, `crate::btc_payout`): a k-of-n
//! `OP_CHECKSIGADD` leaf with slots ∝ bond, each custodian's own independent BIP-340 signature, no aggregate key.
//!
//! The certificate is a set of REAL post-quantum signatures tallied by DISTINCT bonded weight (the sound
//! `crate::peg` threshold shape), NEVER a Shor-breakable discrete-log aggregate. It composes with the existing
//! WHIR private-threshold machinery (the O(1), which-signer-hiding form of the same certificate) — that
//! ZK-aggregate is the privacy hardening; the authorization security is right here.

use std::collections::HashSet;

use crate::pqauth::{pubkey_id, PqVerifier};
use crate::psm::{BondQuorum, MintAttestor};

/// A post-quantum threshold-authorization certificate: a set of REAL post-quantum signatures over one statement,
/// whose DISTINCT bonded weight the verifier tallies to ≥2/3. Post-quantum only — no discrete-log aggregate.
#[derive(Clone, Default)]
pub struct PqThresholdCert {
    pub attestors: Vec<MintAttestor>,
}

/// The domain-separated RESERVE-MOVEMENT statement the quorum threshold-signs. Binds the asset + the exact foreign
/// destination + the value COMMITMENT (never a cleartext amount) + the burned USDm nullifier + the movement epoch,
/// so a PQ certificate authorizes EXACTLY ONE foreign movement — it can never be replayed to a different
/// destination, amount, asset, or epoch, and it is tied to the single-use burn that funds the withdrawal.
pub fn reserve_move_statement(
    asset: &str,
    dest: &[u8],
    amount_commit: &crate::spend_frontier::Digest4,
    usdm_nullifier: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + asset.len() + dest.len() + 32 + 32 + 8);
    m.extend_from_slice(b"USDMD-PQFROST-RESERVE-MOVE-v1");
    m.extend_from_slice(&(asset.len() as u32).to_le_bytes());
    m.extend_from_slice(asset.as_bytes());
    m.extend_from_slice(&(dest.len() as u32).to_le_bytes());
    m.extend_from_slice(dest);
    for x in amount_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(usdm_nullifier);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// Verify a bond-weighted multisig tally certificate over `statement`: EVERY attestor's post-quantum signature must verify
/// over the exact statement, AND the DISTINCT bonded weight of the signers must be ≥2/3 of the total. Fail-closed on
/// any bad signature, any sub-threshold weight, or a zero total. A duplicated signer counts ONCE (no weight
/// inflation); an outsider (unbonded) contributes ZERO weight; a certificate signed over any other statement is
/// rejected. This is the SOLE gate that authorizes a reserve movement — the post-quantum overlay's authority check.
#[must_use]
pub fn verify_threshold(
    statement: &[u8],
    cert: &PqThresholdCert,
    quorum: &dyn BondQuorum,
    verifier: &dyn PqVerifier,
) -> bool {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut attested: u128 = 0;
    for a in &cert.attestors {
        // any bad post-quantum signature fails the whole authorization closed
        if !verifier.verify(&a.pubkey, statement, &a.sig) {
            return false;
        }
        let id = pubkey_id(&a.pubkey);
        if seen.insert(id) {
            attested = attested.saturating_add(quorum.bond_of(&id)); // distinct bonded weight only
        }
    }
    let total = quorum.total_bond();
    crate::quorum_math::two_thirds_met(attested, total)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::bridge::Custodian;
    use crate::pqauth::MlDsaVerifier;
    use crate::validator::ValidatorSet;

    fn quorum(n: u8) -> (Vec<Custodian>, ValidatorSet) {
        let custodians: Vec<Custodian> =
            (0..n).map(|i| Custodian::generate(&[50 + i; 32])).collect();
        let mut vs = ValidatorSet::new();
        for c in &custodians {
            vs.admit(c.id(), 5000, 0).unwrap();
        }
        (custodians, vs)
    }

    // The tally's authority: a real ≥2/3 post-quantum threshold authorizes a reserve movement, and EVERY forgery
    // is rejected — the adversarial tamper test the SOUND pillar mandates for a new mechanism.
    #[test]
    fn pq_threshold_authorizes_a_reserve_move_and_rejects_every_forgery() {
        let (custodians, vs) = quorum(3);
        let v = MlDsaVerifier;
        let stmt = reserve_move_statement("BTC", b"tb1pdestination", &usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), &[7u8; 32], 42);

        // 2-of-3 REAL post-quantum signatures ⇒ ≥2/3 bonded weight ⇒ the reserve move is AUTHORIZED.
        let cert = PqThresholdCert {
            attestors: vec![custodians[0].attest(&stmt), custodians[1].attest(&stmt)],
        };
        assert!(
            verify_threshold(&stmt, &cert, &vs, &v),
            "2-of-3 post-quantum threshold authorizes the move"
        );

        // sub-threshold (1-of-3) ⇒ rejected fail-closed.
        let sub = PqThresholdCert {
            attestors: vec![custodians[0].attest(&stmt)],
        };
        assert!(
            !verify_threshold(&stmt, &sub, &vs, &v),
            "1-of-3 sub-threshold rejected"
        );

        // a forged non-bonded OUTSIDER (real sig, ZERO bonded weight) + 1 real ⇒ still < 2/3 ⇒ rejected.
        let outsider = Custodian::generate(&[0x99u8; 32]);
        let forged = PqThresholdCert {
            attestors: vec![custodians[0].attest(&stmt), outsider.attest(&stmt)],
        };
        assert!(
            !verify_threshold(&stmt, &forged, &vs, &v),
            "outsider carries 0 bonded weight → rejected"
        );

        // a certificate over a DIFFERENT statement (attacker's destination) does not verify over `stmt` ⇒ rejected
        // (a threshold signed for one movement can never be replayed to move funds to another address/amount).
        let attacker =
            reserve_move_statement("BTC", b"tb1pATTACKERaddr", &usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), &[7u8; 32], 42);
        let wrong = PqThresholdCert {
            attestors: vec![
                custodians[0].attest(&attacker),
                custodians[1].attest(&attacker),
            ],
        };
        assert!(
            !verify_threshold(&stmt, &wrong, &vs, &v),
            "a cert over a different statement is rejected (no replay to another dest)"
        );

        // a DUPLICATED signer counts once ⇒ two signatures from ONE validator is not 2/3 ⇒ rejected (no inflation).
        let dup = PqThresholdCert {
            attestors: vec![custodians[0].attest(&stmt), custodians[0].attest(&stmt)],
        };
        assert!(
            !verify_threshold(&stmt, &dup, &vs, &v),
            "a duplicated signer counts once → no weight inflation"
        );

        // an EMPTY certificate against an empty (zero-total) quorum ⇒ never authorizes.
        let empty_vs = ValidatorSet::new();
        assert!(
            !verify_threshold(&stmt, &PqThresholdCert::default(), &empty_vs, &v),
            "empty cert / zero total → never authorizes"
        );
    }
}

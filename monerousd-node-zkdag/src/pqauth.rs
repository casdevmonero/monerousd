// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Post-quantum signature verification seam + the fail-closed default.
//!
//! Two consensus surfaces authenticate a party by a PQ signature: validator finality votes and site
//! publishes. The signature primitive is ML-DSA (post-quantum), via the pqcrypto
//! path-dep; [`PqVerifier`] is the stable seam it implements — `verify(pubkey, msg, sig) -> bool`,
//! exactly ML-DSA's shape, with `pubkey`/`sig` opaque PQ-sized bytes so the base layer stays PQ.
//!
//! Until a real verifier is pinned, [`UnpinnedVerifier`] is the default and rejects EVERY signature
//! (fail-closed): a node authenticates nothing — no vote counts, no publish adopts — rather than
//! trusting an unauthenticated record. This mirrors the pinned-quorum fail-closed model used across
//! the protocol (the verifier code + fail-closed wiring exist now; only the key material waits).
//!
//! Every signed message is DOMAIN-SEPARATED (a distinct tag per purpose) so a signature for one
//! surface can never be replayed on another.

use crate::block::BlockId;
use crate::hash::Hash32;
use crate::site::SitePublish;

/// The PQ signature verifier a real ML-DSA implementation provides.
pub trait PqVerifier {
    /// Verify `sig` is a valid signature by `pubkey` over `msg`. Opaque PQ bytes; base layer stays PQ.
    fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// The default when no PQ verifier has been pinned: reject every signature (fail-closed). Nothing
/// authenticates until a real ML-DSA verifier is installed — the safe state, never trust-by-default.
pub struct UnpinnedVerifier;

impl PqVerifier for UnpinnedVerifier {
    fn verify(&self, _pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// The real post-quantum signature verifier: **ML-DSA-65** (FIPS 204, NIST security level 3) — the
/// production drop-in for [`UnpinnedVerifier`] that a node pins via `set_site_verifier` /
/// `set_finality_verifier`. `pubkey`/`sig` are the ML-DSA-65 encoded bytes; malformed inputs are
/// rejected (never a panic), and a wrong key / tampered message / tampered signature all fail.
pub struct MlDsaVerifier;

impl PqVerifier for MlDsaVerifier {
    fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use pqcrypto_mldsa::mldsa65;
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        let pk = match mldsa65::PublicKey::from_bytes(pubkey) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s = match mldsa65::DetachedSignature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        mldsa65::verify_detached_signature(&s, msg, &pk).is_ok()
    }
}

/// A fresh ML-DSA-65 keypair as bytes: `(public verification key, secret signing key)`. The signing
/// side of [`MlDsaVerifier`] — a validator signs its finality vote; a site owner signs a publish.
pub fn ml_dsa_keypair() -> (Vec<u8>, Vec<u8>) {
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
    let (pk, sk) = mldsa65::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Produce a detached ML-DSA-65 signature over `msg` with `secret`. `None` if the key is malformed.
pub fn ml_dsa_sign(msg: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};
    let sk = mldsa65::SecretKey::from_bytes(secret).ok()?;
    Some(mldsa65::detached_sign(msg, &sk).as_bytes().to_vec())
}

/// Verify a detached ML-DSA-65 signature `sig` by `pubkey` over `msg`. The standalone counterpart to
/// [`ml_dsa_sign`] (the [`MlDsaVerifier`] trait object is for the pluggable finality/site verifiers); callers
/// that just need a one-shot PQ check (e.g. the peer directory's self-attested records) use this. Malformed
/// key/signature bytes verify as `false` — reject fail-closed, never trust-by-default.
pub fn ml_dsa_verify(msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
    MlDsaVerifier.verify(pubkey, msg, sig)
}

/// The id a public key maps to (a validator id / a site owner id): `H(pubkey)`.
pub fn pubkey_id(pubkey: &[u8]) -> [u8; 32] {
    *Hash32::hash(pubkey).as_bytes()
}

/// ⭐⭐⭐ A-F47 — THE START OF EVERY NODE-KEY STATEMENT: its domain, then the network this process runs on
/// ([`crate::params::process_network_id`], `blake3` of the genesis prefix, which on mainnet also commits to the launch anchor).
///
/// WHAT WAS WRONG (2026-11-12, found reading `vote_guard.rs` while preparing the testnet origin's regenesis): a finality vote
/// signed `domain ‖ block ‖ height` and nothing else, and the vote key is derived from the wallet seed with no network in its
/// path (`pq::derive_validator_identity`) or kept per PORT (`validator-<port>.key`). One key that votes on the testnet and
/// later on mainnet signs two blocks at one height on two chains, and that pair verified as a `Class::Equivocation` on the
/// chain where the bond is: the honest operator's bond burned and its id barred forever, by its own honest votes. Price
/// marks, wrapped-asset ratios and revalue marks carried only integers, so a statement signed on one chain was a statement
/// on the other.
///
/// BORROWED: Ethereum's signing domain (`compute_domain` = fork version ‖ genesis_validators_root, mixed into every signing
/// root): a signature names its chain, so one key on two chains never signs one statement twice. Keys stay as they are
/// (a seed restores the same validator on any machine); the STATEMENT carries the chain.
///
/// WHO MAY CALL IT: a builder whose statement is built only inside a node process — the daemon (`main.rs`) and the
/// in-process node (`serve::run_in_process`) each fix the network once at genesis (`params::set_process_network_id`) before any
/// key signs. A statement the WALLET builds (a SAT bond, an unbond, a governance vote, a directory or clue registration, a site
/// publish, an asset's supply, a yield claim) does not call it: the wallet switches networks at runtime and fixes no process
/// network, and each of those names its chain by its content (a nullifier, a chain-derived bond instance and nonce, a note
/// commitment) — `node_statement_census` names every one with its reason.
///
/// SCALE: 32 bytes per statement, a constant; no term in nodes, items or height.
/// AI RESISTANCE: (a) — every verifying node rebuilds the statement under its own network id, so a signature from another
/// chain is a false statement the ML-DSA check refuses.
#[must_use]
pub fn node_statement(domain: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 32 + 128);
    m.extend_from_slice(domain);
    m.extend_from_slice(crate::params::process_network_id().as_bytes());
    m
}

/// The domain-separated message a validator's finality-vote signature must cover, on THIS network ([`node_statement`],
/// A-F47: without the network a vote signed on the testnet was a vote on mainnet, and a pair of them an equivocation).
pub fn finality_vote_msg(block: &BlockId, height: u64) -> Vec<u8> {
    let mut m = node_statement(b"musdm.finality.vote.v1");
    m.extend_from_slice(block.as_bytes());
    m.extend_from_slice(&height.to_le_bytes());
    m
}

/// The domain-separated message a site owner's publish signature must cover.
pub fn site_publish_msg(publish: &SitePublish) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 8 + 32);
    m.extend_from_slice(b"musdm.site.publish.v1");
    m.extend_from_slice(publish.site_id.as_bytes());
    m.extend_from_slice(&publish.version.to_le_bytes());
    m.extend_from_slice(publish.manifest_root.as_bytes());
    m
}

/// The domain-separated message a governance vote signature must cover — binds the EXACT proposal id +
/// chamber (1 = miners, 2 = validators), so a vote can't be replayed onto another proposal or chamber.
/// The wallet builds the IDENTICAL bytes to sign; the node verifies the ML-DSA signature and credits the
/// voter's on-chain chamber weight (a validator's bond), so no one can cast another party's vote.
pub fn governance_vote_msg(proposal_id: &[u8; 32], chamber: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 1);
    m.extend_from_slice(b"musdm.gov.vote.v1");
    m.extend_from_slice(proposal_id);
    m.push(chamber);
    m
}

/// The domain-separated message a `@username` registration signature must cover — binds the EXACT name + the
/// address it maps to (with a 0-byte separator so the pair can't be re-split ambiguously), so a signature can't
/// be replayed to point a name at a different address. The wallet builds the IDENTICAL bytes to sign; the node
/// verifies the ML-DSA signature and sets the owner id = H(pubkey).
pub fn name_register_msg(name: &str, address: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + name.len() + 1 + address.len());
    m.extend_from_slice(b"musdm.name.register.v1");
    m.extend_from_slice(name.as_bytes());
    m.push(0u8);
    m.extend_from_slice(address.as_bytes());
    m
}

/// The domain-separated message a CLUE-KEY publish signature must cover — binds the EXACT clue-key blob so a
/// signature can't be replayed to register a different clue key. The wallet builds the IDENTICAL bytes to sign;
/// the node verifies the ML-DSA signature and keys the clue key by `H(pubkey)` = the address spend tag `b`, so
/// only the address owner can set/update their OWN clue key (used by the oblivious cold-restore path).
pub fn clue_register_msg(clue_pk: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(23 + clue_pk.len());
    m.extend_from_slice(b"musdm.clue.register.v1");
    m.push(0u8);
    m.extend_from_slice(clue_pk);
    m
}

/// The domain-bound message every PSM mint attestor signs — binds the deposit id + BOTH confidential value
/// commitments (reserve + minted liability) + the recipient note + the policy ratio, so a signature can't be
/// replayed to a different mint amount, recipient, or backing. A ≥2/3 bonded-validator threshold over this exact
/// message authorizes the confidential mint (Buy-USDm).
pub fn mint_attest_msg(
    deposit_id: &[u8; 32],
    reserve_commit: &[u8; 32],
    liability_commit: &[u8; 32],
    recipient_cm: &[u8; 32],
    ratio_bps: u32,
) -> Vec<u8> {
    let mut m = node_statement(b"musdm.psm.mint.v1");
    m.extend_from_slice(deposit_id);
    m.extend_from_slice(reserve_commit);
    m.extend_from_slice(liability_commit);
    m.extend_from_slice(recipient_cm);
    m.extend_from_slice(&ratio_bps.to_le_bytes());
    m
}

/// The domain-separated message a validator's UNBOND (withdraw) signature must cover — binds the validator id so
/// ONLY the key-holder can remove their OWN bond weight from the set (no one can unbond another validator).
/// The message a validator signs to BOND ITS MEMBERSHIP — `H(pubkey)` under its own domain tag, so a
/// membership signature can never be replayed as an unbond, a finality vote or a peg attestation —
/// AND the digest of the seat's header (its foreign custody points + its ML-KEM encapsulation key).
///
/// ⛔ THE HEADER MUST BE UNDER THE SIGNATURE. The first spelling (2026-09-17, hours old) signed the id
/// alone, so any relay could re-frame a valid seat with SUBSTITUTED reserve key shares and a substituted
/// encapsulation key: the apply door would re-verify the signature over the untouched id, seat the
/// member, and register the attacker's points into the reserve aggregate and the attacker's ek as the
/// address sealed peg deltas go to. Binding `header_digest` here means the bytes that reach the custody
/// registry are exactly the bytes the key-holder signed.
pub fn validator_membership_msg(id: &[u8; 32], header_digest: &[u8; 32]) -> Vec<u8> {
    let mut m = node_statement(b"musdm.validator.membership.v2");
    m.extend_from_slice(id);
    m.extend_from_slice(header_digest);
    m
}

/// ⛔⛔⛔ DB-258 — THE UNBOND STATEMENT SIGNS EVERYTHING THAT DECIDES WHAT THE UNBOND DOES: the validator, WHICH
/// bonding it ends (`instance`, chain-derived: `Node::bond_instance_of`), and where the returned note is FILED (the
/// owner's account bucket and a digest of its encapsulation key). v1 signed the id alone, so every past unbond of V (all
/// public) replayed against V's next bond, and a relayer could refile the returned note under another bucket.
/// ONE definition: the node's own unbond, an external key-holder and every verifying door build these bytes here.
/// ⛔ DB-258d (v3): the request's NONCE is signed too, so each unbond request is its own one-shot right
/// (`unbond_tx::unbond_right_nf`). v2 signed no per-request value, so V's old unbond of a seat replayed against V's later
/// seating (a seat's instance carries no per-seating value).
/// ⭐ DB-273 §19.3 L2 (v4): the returned note's owner is its OLI clue, signed as `oli::owner_clue_digest(clue)` (the
/// canonical length-prefixed digest) in place of the static (bucket, H(ek)) pair — so no unbond names a wallet's one
/// account, and a relay that replaces the clue voids the signature.
pub fn validator_unbond_msg(
    id: &[u8; 32],
    instance: &[u8; 32],
    owner_clue_digest: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(25 + 32 * 4);
    m.extend_from_slice(b"musdm.validator.unbond.v4");
    m.extend_from_slice(id);
    m.extend_from_slice(instance);
    m.extend_from_slice(owner_clue_digest);
    m.extend_from_slice(nonce);
    m
}

/// ⭐ DB-313 R2 (b) — THE BOND STATEMENT a validator's own key signs: the vote identity `vid` takes weight `weight`,
/// backed by the note locked at `locked_cm`, whose consumed input is `nullifier`. Naming the note and the nullifier
/// makes the signature single-use (a replay names a spent nullifier) and ties the weight to ONE proven carrier, so a
/// relayer cannot re-point it and no one but the vid's key holder can bond onto that vid (R2's squat).
pub fn validator_bond_msg(vid: &[u8; 32], weight: u64, locked_cm: &[u8; 32], nullifier: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(23 + 32 + 8 + 64);
    m.extend_from_slice(b"musdm.validator.bond.v1");
    m.extend_from_slice(vid);
    m.extend_from_slice(&weight.to_le_bytes());
    m.extend_from_slice(locked_cm);
    m.extend_from_slice(nullifier);
    m
}

/// The exact `bond_notes` length of a signed bond statement: `vid(32) ‖ W(8 LE) ‖ ML-DSA-65 pk ‖ detached sig`.
/// ONE encoding: any other length is not a statement.
#[must_use]
pub fn bond_statement_len() -> usize {
    32 + 8 + pqcrypto_mldsa::mldsa65::public_key_bytes() + pqcrypto_mldsa::mldsa65::signature_bytes()
}

/// Encode a signed statement (the wallet's node signs it at `/sign_bond`).
#[must_use]
pub fn bond_statement_encode(vid: &[u8; 32], weight: u64, pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + pk.len() + sig.len());
    out.extend_from_slice(vid);
    out.extend_from_slice(&weight.to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(sig);
    out
}

/// ⭐⭐⭐ DB-313 R2 (b) — READ AND VERIFY a carried bond statement against the transaction's OWN locked note and
/// nullifier. `Some((vid, weight))` only if the length is exact, `vid == H(pk)`, `weight > 0`, and the ML-DSA-65
/// signature over [`validator_bond_msg`] verifies under `pk`. The submit door, the template and the graft apply all
/// read THIS — one reader, so no door can admit what another refuses.
#[must_use]
pub fn bond_statement_verified(
    bond_notes: &[u8],
    locked_cm: &[u8; 32],
    nullifier: &[u8; 32],
) -> Option<([u8; 32], u64)> {
    if bond_notes.len() != bond_statement_len() {
        return None;
    }
    let pk_len = pqcrypto_mldsa::mldsa65::public_key_bytes();
    let vid: [u8; 32] = bond_notes[..32].try_into().ok()?;
    let weight = u64::from_le_bytes(bond_notes[32..40].try_into().ok()?);
    let pk = &bond_notes[40..40 + pk_len];
    let sig = &bond_notes[40 + pk_len..];
    if weight == 0 || pubkey_id(pk) != vid {
        return None;
    }
    ml_dsa_verify(&validator_bond_msg(&vid, weight, locked_cm, nullifier), pk, sig).then_some((vid, weight))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    // A deterministic in-test stand-in for ML-DSA: "sig" = H(pubkey || msg). A TEST DOUBLE only —
    // it exercises the verify CONTRACT (accept the right sig; reject a tampered msg/sig/key), NOT a
    // real signature scheme. The production verifier is ML-DSA from the PQ dep.
    struct TestVerifier;
    fn test_sign(pubkey: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(pubkey);
        b.extend_from_slice(msg);
        Hash32::hash(&b).as_bytes().to_vec()
    }
    impl PqVerifier for TestVerifier {
        fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            test_sign(pubkey, msg) == sig
        }
    }

    #[test]
    fn unpinned_verifier_is_fail_closed() {
        // even a well-formed-looking sig is rejected while no real verifier is pinned.
        assert!(!UnpinnedVerifier.verify(b"pk", b"msg", b"sig"));
    }

    #[test]
    fn verify_contract_accepts_valid_rejects_tamper() {
        let v = TestVerifier;
        let pk = b"validator-pubkey";
        let msg = finality_vote_msg(&Hash32::hash(b"blk"), 7);
        let sig = test_sign(pk, &msg);
        assert!(v.verify(pk, &msg, &sig), "valid signature accepted");
        // tampered message (a different height) — reject.
        let msg2 = finality_vote_msg(&Hash32::hash(b"blk"), 8);
        assert!(!v.verify(pk, &msg2, &sig), "message tamper rejected");
        // tampered signature — reject.
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(!v.verify(pk, &msg, &bad), "signature tamper rejected");
        // wrong key — reject.
        assert!(!v.verify(b"other-pubkey", &msg, &sig), "wrong key rejected");
    }

    #[test]
    fn domains_are_separated_so_signatures_do_not_cross_replay() {
        let block = Hash32::hash(b"b");
        let vote = finality_vote_msg(&block, 1);
        let publish = site_publish_msg(&SitePublish::new([1u8; 32], "s", 1, Hash32::hash(b"r")));
        assert_ne!(vote, publish);
        assert!(vote.starts_with(b"musdm.finality.vote.v1"));
        assert!(publish.starts_with(b"musdm.site.publish.v1"));
    }

    #[test]
    fn ml_dsa_verifier_accepts_real_signature_and_rejects_tamper() {
        use pqcrypto_mldsa::mldsa65::{detached_sign, keypair};
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

        let (pk, sk) = keypair();
        let v = MlDsaVerifier;
        let msg = finality_vote_msg(&Hash32::hash(b"a-finalized-block"), 42);
        let sig = detached_sign(&msg, &sk);

        // a genuine ML-DSA-65 signature over the exact message verifies.
        assert!(
            v.verify(pk.as_bytes(), &msg, sig.as_bytes()),
            "valid ML-DSA sig accepts"
        );
        // a tampered message (different height) is rejected.
        let msg2 = finality_vote_msg(&Hash32::hash(b"a-finalized-block"), 43);
        assert!(
            !v.verify(pk.as_bytes(), &msg2, sig.as_bytes()),
            "message tamper rejected"
        );
        // a tampered signature is rejected.
        let mut bad = sig.as_bytes().to_vec();
        bad[0] ^= 0xff;
        assert!(
            !v.verify(pk.as_bytes(), &msg, &bad),
            "signature tamper rejected"
        );
        // a different key is rejected.
        let (pk2, _sk2) = keypair();
        assert!(
            !v.verify(pk2.as_bytes(), &msg, sig.as_bytes()),
            "wrong key rejected"
        );
        // malformed key / signature bytes are rejected (no panic).
        assert!(!v.verify(b"too-short", &msg, sig.as_bytes()));
        assert!(!v.verify(pk.as_bytes(), &msg, b"too-short"));
    }

    #[test]
    fn ml_dsa_keypair_and_sign_round_trip_through_the_verifier() {
        // the signing helpers (validator/site side) produce signatures the verifier accepts.
        let (pk, sk) = ml_dsa_keypair();
        let msg = site_publish_msg(&SitePublish::new(
            [2u8; 32],
            "explorer",
            3,
            Hash32::hash(b"root"),
        ));
        let sig = ml_dsa_sign(&msg, &sk).expect("sign");
        let v = MlDsaVerifier;
        assert!(
            v.verify(&pk, &msg, &sig),
            "a freshly signed message verifies"
        );
        assert!(
            !v.verify(&pk, b"a different message", &sig),
            "tamper rejected"
        );
        assert!(
            ml_dsa_sign(&msg, b"malformed-secret").is_none(),
            "bad secret -> None"
        );
    }
    /// ⭐⭐⭐ A-F47 CENSUS — EVERY NODE-KEY STATEMENT NAMES ITS NETWORK, AND EVERY STATEMENT DOMAIN IN THE SOURCE IS NAMED HERE.
    /// (1) Behaviour: the same vote, mark, ratio, mint, seat and theft certificate built under the testnet and under mainnet
    /// are different bytes, each starting with its domain and that network's id — a signature over one is no signature over
    /// the other, so an honest key's testnet vote can never be half of a mainnet equivocation. (2) Source: every `musdm.`
    /// domain literal outside tests is either a NODE domain, which must be the argument of `node_statement`, or a named
    /// exception with its reason; a new domain in neither list fails here the day it is written.
    #[test]
    fn af47_every_node_key_statement_names_its_network_and_every_domain_is_listed() {
        use crate::params::{network_genesis_prefix, process_network_id, set_thread_network_for_test};
        const NODE: &[&str] = &[
            "musdm.finality.vote.v1",
            "musdm.psm.mint.v1",
            "musdm.validator.membership.v2",
            "musdm.peg.in.conf.v4",
            "musdm.wrap.mint.conf.v3",
            "musdm.peg.out.conf.v7",
            "musdm.peg.revalue.v2",
            "musdm.peg.bridge-credit.v2",
            "musdm.peg.wrapped-register.v1",
            "musdm.peg.price-mark.v1",
            "musdm.peg.vault-merge.release.v1",
            "musdm.peg.vault-merge.accept.v1",
            "musdm.peg.vault-rebalance.carve.v1",
            "musdm.peg.vault-rebalance.take.v1",
            "musdm.peg.vault-rebalance.cancel.v1",
            "musdm.peg.vault-rebalance.consent.v1",
            "musdm.peg.vault-key.take.v2",
            "musdm.peg.vault-key.retire.v1",
            "musdm.peg.reserve-cost.v1",
            "musdm.peg.theft-repay.v1",
            "musdm.peg.pot-fill.v1",
            "musdm.peg.unit-close.v1",
            "musdm.peg.pool.release-batch.v1",
            "musdm.peg.decoy-batch.v1",
            "musdm.peg.decoy-return.v1",
            "musdm.custody.share.v1",
            "musdm.validator.instance.v2",
        ];
        // Not bound to the process network, each for its reason. A WALLET builds it (the wallet switches networks at run time
        // and fixes no process network), and its content already names its chain; or it is a hash, never a signature.
        const OTHER: &[(&str, &str)] = &[
            ("musdm.site.publish.v1", "wallet key; a site's owner publishes its own manifest root"),
            ("musdm.gov.vote.v1", "wallet key; the proposal id is a chain object of this network"),
            ("musdm.name.register.v1", "wallet key; a name maps to an address whose network the address names"),
            ("musdm.clue.register.v1", "wallet key; the clue key is the wallet's own"),
            ("musdm.dir.register.v1", "wallet key; a directory entry is paid with a note of this network"),
            ("musdm.validator.unbond.v4", "the validator's own key, also from the wallet seed; names the bond instance, which every node derives under its own network id (musdm.validator.instance.v2 is a NODE domain), and a one-shot nonce"),
            ("musdm.validator.bond.v1", "the validator's own key, also from the wallet seed; names the locked note and its nullifier on this chain"),
            ("musdm.validator.seat.v1", "a hash: the seat-right nullifier, never signed"),
            ("musdm.validator.unbond-right.v2", "a hash: the unbond-right nullifier, never signed"),
            ("musdm.spend.statement.v1", "the spend proof's statement domain, built by the wallet prover; a spend is bound to its chain by its stamp (mempool::stamp)"),
            ("musdm.spend.lock.v1", "the spend lock domain, built by the wallet prover; bound to its chain by its stamp"),
        ];
        // (1) behaviour, under two networks
        let under = |net: &str| -> Vec<Vec<u8>> {
            set_thread_network_for_test(&network_genesis_prefix(net));
            let id = *process_network_id().as_bytes();
            let v = vec![
                finality_vote_msg(&crate::hash::Hash32([7u8; 32]), 5),
                mint_attest_msg(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 15_000),
                validator_membership_msg(&[5u8; 32], &[6u8; 32]),
                crate::peg::PegLedger::price_mark_msg(9, 0, 74_282_306_163),
                crate::theft_tx::theft_msg(b"statement", &[[8u8; 32]], 100_000_000),
            ];
            for (m, d) in v.iter().zip(["musdm.finality.vote.v1", "musdm.psm.mint.v1", "musdm.validator.membership.v2", "musdm.peg.price-mark.v1", "USDMD-PQFROST-THEFT-v3"]) {
                assert!(m.starts_with(d.as_bytes()) && m[d.len()..].starts_with(&id), "{d} starts with its domain and the network id");
            }
            v
        };
        let (test, main) = (under("testnet"), under("mainnet"));
        for (t, m) in test.iter().zip(&main) {
            assert_ne!(t, m, "a node-key statement on the testnet is not the same statement on mainnet");
        }
        // (2) source census
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let src = if base.join("src/pqauth.rs").exists() { base.join("src") } else { base.join("../src") };
        let mut files = vec![src.clone()];
        // Every builder handed straight to a signing call (`ml_dsa_sign(&builder(` / `.attest(&builder(`) is named: the domain
        // census above sees only `musdm.` literals, and a node-key statement under another prefix (`MUSD/…`, `USDMD-…`) is
        // caught here. A call that signs a variable is not seen by this scan; its builder is one of these by construction.
        const BOUND_BUILDERS: &[&str] = &[
            "finality_vote_msg", "mint_attest_msg", "validator_membership_msg", "price_mark_msg", "wrapped_register_msg",
            "theft_msg", "deal_msg", "signal_msg", "statement",
        ];
        const OTHER_BUILDERS: &[(&str, &str)] = &[
            ("validator_unbond_msg", "see musdm.validator.unbond.v4"),
            ("validator_bond_msg", "see musdm.validator.bond.v1"),
            ("clue_register_msg", "see musdm.clue.register.v1"),
            ("governance_vote_msg", "see musdm.gov.vote.v1"),
            ("name_register_msg", "see musdm.name.register.v1"),
            ("site_publish_msg", "see musdm.site.publish.v1"),
            ("lock_msg", "names the genesis itself (spend_lock::lock_msg)"),
            ("record_msg", "the entry-mix coordinator's record of its own round id; moves no value"),
            ("peer_record_msg", "a transport record of an onion; names no chain and moves no value — carried to another network it points at a node that answers FOREIGN NETWORK"),
            ("attestation_msg", "a builder's signature over a release, the same binary on every network; verify-release checks it offline, with no node"),
        ];
        let mut unknown_builders = Vec::new();
        let mut seen_node = std::collections::BTreeSet::new();
        let mut unknown = Vec::new();
        while let Some(dir) = files.pop() {
            for e in std::fs::read_dir(&dir).expect("the node source is readable") {
                let p = e.expect("an entry").path();
                if p.is_dir() {
                    files.push(p);
                    continue;
                }
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name.ends_with("_pins.rs") || name.ends_with("_pin.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).expect("a source file");
                // a whole test file (`#![cfg(test)]`-style inner attribute near its top, or the shared test support) is not live code
                if name == "pins.rs" || name == "test_support.rs" || text.lines().take(60).any(|l| l.trim_start().starts_with("#![cfg(") && l.contains("test")) {
                    continue;
                }
                // the live code is the file without its test modules: a `#[cfg(...test...)]` line whose next line opens a `mod … {`
                // is skipped through that module's closing `}` at column 0 (rustfmt layout); live code after it is still read
                let lines: Vec<&str> = text.split_inclusive('\n').collect();
                let mut kept = String::with_capacity(text.len());
                let mut k = 0;
                while k < lines.len() {
                    let l = lines[k];
                    let next = lines.get(k + 1).map(|n| n.trim_start()).unwrap_or("");
                    if l.trim_start().starts_with("#[cfg(") && l.contains("test") && (next.starts_with("mod ") || next.starts_with("pub mod ")) {
                        if next.trim_end().ends_with('{') {
                            k += 2;
                            while k < lines.len() && lines[k].trim_end() != "}" {
                                k += 1;
                            }
                        } else {
                            k += 1;
                        }
                        k += 1;
                        continue;
                    }
                    kept.push_str(l);
                    k += 1;
                }
                let live = kept.as_str();
                for call in ["ml_dsa_sign(&", ".attest(&"] {
                    let mut at = 0;
                    while let Some(i) = live[at..].find(call) {
                        let start = at + i + call.len();
                        let rest = &live[start..];
                        let path_len = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':')).unwrap_or(0);
                        if rest[path_len..].starts_with('(') && path_len > 0 {
                            let name = rest[..path_len].rsplit("::").next().unwrap_or("");
                            if !BOUND_BUILDERS.contains(&name) && !OTHER_BUILDERS.iter().any(|(o, _)| *o == name) {
                                unknown_builders.push(format!("{}: {name}", p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                            }
                        }
                        at = start;
                    }
                }
                let mut at = 0;
                while let Some(i) = live[at..].find("b\"musdm.") {
                    let start = at + i + 2;
                    let end = start + live[start..].find('"').expect("a closed literal");
                    let d = &live[start..end];
                    if NODE.contains(&d) {
                        assert!(live[..at + i].ends_with("node_statement("), "{name}: the node-key domain {d} is not built through node_statement");
                        seen_node.insert(d.to_string());
                    } else if !OTHER.iter().any(|(o, _)| *o == d) {
                        unknown.push(format!("{name}: {d}"));
                    }
                    at = end;
                }
            }
        }
        assert!(unknown_builders.is_empty(), "statement builders signed in the source and named in neither list (bind a node-key one with node_statement and list it in BOUND_BUILDERS, or list it in OTHER_BUILDERS with its reason): {unknown_builders:?}");
        assert!(unknown.is_empty(), "statement domains named in neither list (route a node-key one through node_statement and list it in NODE, or list it in OTHER with its reason): {unknown:?}");
        let missing: Vec<_> = NODE.iter().filter(|d| !seen_node.contains(**d)).collect();
        assert!(missing.is_empty(), "NODE domains no longer in the source (remove them from the census): {missing:?}");
    }

    /// ⛔ A-F47 REFUSAL — ONE HONEST KEY'S VOTE ON ANOTHER NETWORK IS NEVER HALF OF AN EQUIVOCATION HERE. The key votes block A
    /// at height 5 on mainnet and block B at height 5 on the testnet (one seed, one validator, two chains: what every wallet
    /// that tried the testnet before launch will do). Before A-F47 the vote statement named no chain, so the pair verified as a
    /// `Class::Equivocation` and burned the bond; now the mainnet vote is no testnet statement and the pair proves nothing. The
    /// same two blocks signed on ONE network still prove the equivocation, so slashing a real double vote is untouched.
    #[test]
    fn af47_a_vote_signed_on_another_network_is_never_half_of_an_equivocation() {
        use crate::params::{network_genesis_prefix, set_thread_network_for_test};
        use crate::validator::VoteCert;
        let (pk, sk) = ml_dsa_keypair();
        let (a, b) = (crate::hash::Hash32([0x0a; 32]), crate::hash::Hash32([0x0b; 32]));
        let vote = |block: crate::hash::Hash32| VoteCert {
            pubkey: pk.clone(),
            block,
            height: 5,
            sig: ml_dsa_sign(&finality_vote_msg(&block, 5), &sk).expect("the vote key signs"),
        };
        set_thread_network_for_test(&network_genesis_prefix("mainnet"));
        let on_mainnet = vote(a);
        set_thread_network_for_test(&network_genesis_prefix("testnet"));
        let on_testnet = vote(b);
        let cross = crate::equivocation_tx::encode(&on_mainnet, &on_testnet).expect("two blocks at one height under one key");
        assert_eq!(
            crate::equivocation_tx::proves_equivocation(&cross, &MlDsaVerifier),
            None,
            "⛔ A-F47: a vote signed on mainnet and one signed on the testnet slashed the honest key on the testnet"
        );
        let here = crate::equivocation_tx::encode(&vote(a), &on_testnet).expect("two blocks at one height under one key");
        assert_eq!(
            crate::equivocation_tx::proves_equivocation(&here, &MlDsaVerifier),
            Some(pubkey_id(&pk)),
            "a real double vote on this network still proves the equivocation"
        );
    }
}

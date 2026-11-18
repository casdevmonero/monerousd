// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-9a step (c) — THE EPOCH RELEASE AND THE EPOCH TICKET (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §19.1, §19.3).
//!
//! **The ticket** (`seal_ticket`): a cash-out piece's ticket key K is encapsulated to the FINAL key of the epoch its
//! `pay_after` falls in — ONE ciphertext of `epoch_key::CT_BYTES`, whatever the custody size — and the ticket is sealed under
//! K exactly as §BR-5 seals it. The ticketed commitment the quorum signs binds the ciphertext's hash in the slot the per-
//! ticket share commitments held (`cashout_ticket::ticketed_commit(inner, ticket, &[H(ct)])`), so a relay that swaps the
//! ciphertext voids the payout and the signed statement needs no new field. K is known to the wallet that drew it, so the
//! §BR-5 B5-d escrow stays reclaimable by its owner whatever custody does.
//!
//! **The release** (`ReleaseBundle`, sealed per custodian like §BR-5's release — NEVER public, §19.1 item 1): at the epoch
//! each custodian sends every other custodian its captured shares of that epoch, one per dealer. A custodian holding ≥ t
//! verified shares of every dealer (`open_epoch`) rebuilds each dealer's seed, re-derives its public part and compares it
//! with the hash the ledger recorded — exact per-dealer accountability — sums the dealers' secrets and accepts the epoch secret
//! only if it passes `epoch_key::release_check`. A dealer whose shares rebuild another public part is NAMED by a
//! `FraudProof` any node can check from the ledger alone (`fraud_proof_holds`).
//!
//! **A faulty dealer stops no money.** Its epoch's tickets are not opened by custody; their pieces stay in the B5-d escrow,
//! which the owner reclaims with K. The dealer's bond answers for it (the proof's slashing object rides a later step).
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: a bundle is sealed to one custodian's ML-KEM key; a fraud proof reveals only the seed of the
//! dealer it convicts (whose contribution is void anyway); a ticket is one constant-width ciphertext plus §BR-5's ticket.

use crate::epoch_deal_tx::{share_commit, DealRecord, EpochRound, SHARE_BYTES};

/// One custodian's release of an epoch: its share of each dealer's seed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseBundle {
    pub from: [u8; 32],
    pub epoch: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per dealer, at most `PEG_ATTEST_SEALED_MAX`.
    pub shares: Vec<([u8; 32], Vec<u8>)>,
}

/// Evidence that `dealer`'s shares for `epoch` rebuild a public part other than the one it published: t shares, each
/// under the commitment the dealer signed to its recipient.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FraudProof {
    pub dealer: [u8; 32],
    pub epoch: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — exactly t (recipient, share) pairs, t ≤ PEG_ATTEST_SEALED_MAX.
    pub shares: Vec<([u8; 32], Vec<u8>)>,
}

/// What a custodian's release gathering yields for an epoch.
#[derive(Debug)]
pub enum EpochOpen {
    /// The epoch secret, every dealer rebuilt exactly and the release check passed.
    Key(crate::epoch_key::EpochSecretKey),
    /// Fewer than t verified shares of some dealer so far — wait for more bundles.
    Short,
    /// One or more dealers convicted; the epoch's key is not recoverable (its tickets stay in their owners' escrow).
    Faulty(Vec<FraudProof>),
}

fn to_share(raw: &[u8]) -> Option<crate::shamir::Share> {
    (raw.len() == SHARE_BYTES).then(|| crate::shamir::Share { x: raw[0], y: raw[1..].to_vec() })
}

/// The shares that verify: from a roster member, of a recorded dealer, under the commitment the dealer signed to that member.
fn verified(round: &EpochRound, epoch: u64, dealer: &[u8; 32], rec: &DealRecord, from: &[u8; 32], raw: &[u8]) -> bool {
    let Ok(pos) = round.roster.binary_search(from) else { return false };
    let Ok(plain) = <[u8; SHARE_BYTES]>::try_from(raw) else { return false };
    rec.commits.get(pos) == Some(&share_commit(dealer, epoch, from, &plain))
}

/// Rebuild one dealer's secret from ≥ t verified shares: `Ok(secret)` when its seed re-derives the recorded public part,
/// `Err(proof)` when it re-derives another.
fn rebuild(
    epoch: u64,
    dealer: &[u8; 32],
    rec: &DealRecord,
    shares: &[([u8; 32], Vec<u8>)],
) -> Option<Result<crate::epoch_key::DealerSecret, FraudProof>> {
    let parsed: Vec<crate::shamir::Share> = shares.iter().map(|(_, s)| to_share(s)).collect::<Option<_>>()?;
    let seed: [u8; 32] = crate::shamir::combine(&parsed)?.try_into().ok()?;
    let (secret, part) = crate::epoch_key::deal(&crate::epoch_deal_tx::matrix_seed(epoch), &seed);
    if *blake3::hash(&crate::epoch_key::pack_b(&part)).as_bytes() == rec.b_hash {
        Some(Ok(secret))
    } else {
        Some(Err(FraudProof { dealer: *dealer, epoch, shares: shares.to_vec() }))
    }
}

/// ⭐ OPEN AN EPOCH from the release bundles a custodian has gathered (its own included), against the ledger's round and
/// final public key.
#[must_use]
pub fn open_epoch(
    epoch: u64,
    round: &EpochRound,
    pk: &crate::epoch_key::EpochPublicKey,
    bundles: &[ReleaseBundle],
) -> EpochOpen {
    let t = crate::shamir::two_thirds_threshold(round.roster.len());
    let mut secrets = Vec::with_capacity(round.dealers.len());
    let mut faults = Vec::new();
    for (dealer, rec) in &round.dealers {
        let mut good: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(t);
        for b in bundles.iter().filter(|b| b.epoch == epoch) {
            if good.len() == t || good.iter().any(|(f, _)| *f == b.from) {
                continue;
            }
            if let Some((_, raw)) = b.shares.iter().find(|(d, _)| d == dealer) {
                if verified(round, epoch, dealer, rec, &b.from, raw) {
                    good.push((b.from, raw.clone()));
                }
            }
        }
        if good.len() < t {
            return EpochOpen::Short;
        }
        match rebuild(epoch, dealer, rec, &good) {
            Some(Ok(s)) => secrets.push(s),
            Some(Err(p)) => faults.push(p),
            None => return EpochOpen::Short,
        }
    }
    if !faults.is_empty() {
        return EpochOpen::Faulty(faults);
    }
    let sk = crate::epoch_key::secret_from(&secrets);
    if crate::epoch_key::release_check(pk, &sk) {
        EpochOpen::Key(sk)
    } else {
        EpochOpen::Faulty(Vec::new())
    }
}

/// ⭐ CHECK A FRAUD PROOF from the ledger alone: t shares, each from a roster member under the dealer's signed commitment,
/// whose seed re-derives a public part other than the one the dealer published.
#[must_use]
pub fn fraud_proof_holds(round: &EpochRound, p: &FraudProof) -> bool {
    let Some(rec) = round.dealers.get(&p.dealer) else { return false };
    let t = crate::shamir::two_thirds_threshold(round.roster.len());
    let mut froms: Vec<[u8; 32]> = p.shares.iter().map(|(f, _)| *f).collect();
    froms.sort_unstable();
    froms.dedup();
    if p.shares.len() != t || froms.len() != t {
        return false;
    }
    if !p.shares.iter().all(|(f, raw)| verified(round, p.epoch, &p.dealer, rec, f, raw)) {
        return false;
    }
    matches!(rebuild(p.epoch, &p.dealer, rec, &p.shares), Some(Err(_)))
}

/// ⭐ SEAL A CASH-OUT TICKET TO ITS EPOCH: `(K, ciphertext, ticket, ticketed commitment)` for a piece paying `address` after
/// `pay_after`, under the epoch's final key `pk` and the wallet's fresh `m`.
#[allow(clippy::type_complexity)]
#[must_use]
pub fn seal_ticket(
    pk: &crate::epoch_key::EpochPublicKey,
    m: &[u8; 32],
    address: &[u8],
    pay_after: u64,
    blind: &crate::spend_frontier::Digest4,
) -> Option<([u8; 32], Vec<u8>, Vec<u8>, [u8; 32])> {
    let (key, ct) = crate::epoch_key::encapsulate(pk, m);
    let ticket = crate::cashout_ticket::seal(&key, address, pay_after, blind)?.to_vec();
    let inner = crate::peg::redeem_commit(address, pay_after, blind);
    let tc = crate::cashout_ticket::ticketed_commit(&inner, &ticket, &[*blake3::hash(&ct).as_bytes()]);
    Some((key, ct, ticket, tc))
}

/// ⭐ OPEN A CASH-OUT TICKET with its epoch's released secret: the destination, `pay_after` and blind — only if the
/// ciphertext decapsulates under the epoch key and the ticket opens the signed ticketed commitment.
#[must_use]
pub fn open_ticket(
    pk: &crate::epoch_key::EpochPublicKey,
    sk: &crate::epoch_key::EpochSecretKey,
    ct: &[u8],
    ticket: &[u8],
    ticketed: &[u8; 32],
) -> Option<([u8; 32], Vec<u8>, u64, crate::spend_frontier::Digest4)> {
    let key = crate::epoch_key::decapsulate(pk, sk, ct)?;
    let (address, pay_after, blind) = crate::cashout_ticket::open_ticketed(&key, ticket, &[*blake3::hash(ct).as_bytes()], ticketed)?;
    Some((key, address, pay_after, blind))
}

/// The bundle wire: `postcard(bundle)` sealed under one custodian's ML-KEM-768 key (`ct ‖ tag ‖ masked body`).
#[must_use]
pub fn seal_bundle(ek: &[u8], b: &ReleaseBundle) -> Option<Vec<u8>> {
    let body = postcard::to_stdvec(b).ok()?;
    let (ss, ct) = crate::pqkem::encapsulate(ek)?;
    let mut ks = vec![0u8; body.len()];
    blake3::Hasher::new_derive_key("MUSD/epoch-release/stream/v1").update(&ss).update(&ct).finalize_xof().fill(&mut ks);
    let masked: Vec<u8> = body.iter().zip(&ks).map(|(a, k)| a ^ k).collect();
    let tag = blake3::Hasher::new_derive_key("MUSD/epoch-release/tag/v1").update(&ss).update(&masked).finalize();
    let mut out = ct;
    out.extend_from_slice(&tag.as_bytes()[..16]);
    out.extend_from_slice(&masked);
    Some(out)
}

/// Open a bundle sealed to this custodian. `None` when it is not ours, tampered or malformed.
#[must_use]
pub fn open_bundle(dk: &[u8], sealed: &[u8]) -> Option<ReleaseBundle> {
    let ct_len = crate::pqkem::ciphertext_len();
    if sealed.len() < ct_len + 16 {
        return None;
    }
    let (ct, rest) = sealed.split_at(ct_len);
    let (tag, masked) = rest.split_at(16);
    let ss = crate::pqkem::decapsulate(ct, dk)?;
    let want = blake3::Hasher::new_derive_key("MUSD/epoch-release/tag/v1").update(&ss).update(masked).finalize();
    if &want.as_bytes()[..16] != tag {
        return None;
    }
    let mut ks = vec![0u8; masked.len()];
    blake3::Hasher::new_derive_key("MUSD/epoch-release/stream/v1").update(&ss).update(ct).finalize_xof().fill(&mut ks);
    let body: Vec<u8> = masked.iter().zip(&ks).map(|(a, k)| a ^ k).collect();
    crate::chain_object::decode_exact::<ReleaseBundle>(&body)
}

/// TEST — a deterministic one-dealer epoch key pair, for fixtures that seal a ticket without exercising the release.
#[cfg(test)]
#[must_use]
pub fn test_epoch_keypair() -> (crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey) {
    let seed = crate::epoch_deal_tx::matrix_seed(0);
    let (sec, part) = crate::epoch_key::deal(&seed, &[0x7e; 32]);
    (crate::epoch_key::combine_public(&seed, &[part]), crate::epoch_key::secret_from(&[sec]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_deal_tx::{build, open_share, EpochKeyDealTx, EpochKeyLedger, DEAL_LEAD_EPOCHS};

    struct Member {
        id: [u8; 32],
        pk: Vec<u8>,
        sk: Vec<u8>,
        ek: Vec<u8>,
        dk: Vec<u8>,
    }

    fn custody(n: usize) -> Vec<Member> {
        let mut v: Vec<Member> = (0..n)
            .map(|_| {
                let (pk, sk) = crate::pqauth::ml_dsa_keypair();
                let (ek, dk) = crate::validator::custody_kem_from_vote_sk(&sk);
                Member { id: crate::pqauth::pubkey_id(&pk), pk, sk, ek, dk }
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    fn entropy(tag: u8, i: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new().update(&[tag, i as u8]).finalize_xof().fill(&mut out);
        out
    }

    /// One epoch dealt by every member (dealer `bad`, if any, shares a seed other than the one its public part comes from),
    /// folded into a ledger; every member's captured shares; the final key.
    #[allow(clippy::type_complexity)]
    fn dealt_epoch(c: &[Member], bad: Option<usize>) -> (u64, EpochRound, crate::epoch_key::EpochPublicKey, Vec<ReleaseBundle>) {
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.id).collect();
        let roster: Vec<([u8; 32], Vec<u8>)> = c.iter().map(|m| (m.id, m.ek.clone())).collect();
        let t = crate::shamir::two_thirds_threshold(c.len());
        let mut l = EpochKeyLedger::default();
        l.tick(10, &ids);
        let e = 10 + DEAL_LEAD_EPOCHS;
        let mut deals = Vec::new();
        for (i, m) in c.iter().enumerate() {
            let seed: [u8; 32] = entropy(1, i, 32).try_into().unwrap();
            let mut d = build(&m.pk, &m.sk, e, &roster, &seed, &entropy(2, i, (t - 1) * 32)).unwrap();
            if bad == Some(i) {
                // the dealer re-deals the shares of ANOTHER seed under its real public part, re-signing the whole deal
                let other: [u8; 32] = entropy(9, i, 32).try_into().unwrap();
                let shadow = build(&m.pk, &m.sk, e, &roster, &other, &entropy(2, i, (t - 1) * 32)).unwrap();
                d.shares = shadow.shares;
                d.sig = crate::pqauth::ml_dsa_sign(&crate::epoch_deal_tx::deal_msg(&d.vid, e, &d.b, &d.shares), &m.sk).unwrap();
            }
            assert!(d.authorised());
            assert_eq!(l.refusal(&d), None);
            l.observe_deal(&d);
            deals.push(d);
        }
        l.tick(11, &ids);
        let pk = l.public_key(e).expect("final");
        let round = l.epochs.get(&e).cloned().unwrap();
        let bundles = c
            .iter()
            .map(|m| ReleaseBundle {
                from: m.id,
                epoch: e,
                shares: deals
                    .iter()
                    .map(|d: &EpochKeyDealTx| {
                        let s = d.shares.iter().find(|s| s.to == m.id).unwrap();
                        (d.vid, open_share(&m.dk, &s.sealed).unwrap().to_vec())
                    })
                    .collect(),
            })
            .collect();
        (e, round, pk, bundles)
    }

    /// ⭐ §BR-9a step (c) — A CASH-OUT TICKET SEALED TO ITS EPOCH IS OPENED BY CUSTODY FROM t RELEASES, AND NOT FROM t − 1.
    /// Six custodians deal; the WALLET seals a ticket to the epoch's final key; every custodian sends each other custodian its
    /// release bundle SEALED to that custodian's ML-KEM key; the RECIPIENT custodian opens the bundles sealed to it, rebuilds
    /// every dealer exactly, passes the release check and opens the ticket to the attested destination. TAMPERS: t − 1
    /// bundles open nothing (Short); a bundle opened under another custodian's key is refused; a ticket whose ciphertext was
    /// swapped for another epoch-key ciphertext opens nothing.
    #[test]
    fn br9a_c_a_ticket_sealed_to_its_epoch_is_opened_by_custody_from_t_releases_and_not_from_t_minus_one() {
        let c = custody(6);
        let t = crate::shamir::two_thirds_threshold(6);
        let (e, round, pk, bundles) = dealt_epoch(&c, None);
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0x9c, 1, 2, 3]);
        let addr = b"bc1qepochticketdestination0000000000000000".to_vec();
        let (key, ct, ticket, tc) = seal_ticket(&pk, &entropy(3, 0, 32).try_into().unwrap(), &addr, 4_000, &blind).unwrap();
        assert_eq!(ct.len(), crate::epoch_key::CT_BYTES, "one ciphertext, whatever the custody size");

        // the recipient custodian (member 0) receives every other member's bundle sealed to it
        let me = &c[0];
        let wire: Vec<Vec<u8>> = bundles.iter().map(|b| seal_bundle(&me.ek, b).unwrap()).collect();
        assert!(open_bundle(&c[1].dk, &wire[2]).is_none(), "a bundle sealed to member 0 opens under no other key");
        let received: Vec<ReleaseBundle> = wire.iter().map(|w| open_bundle(&me.dk, w).expect("ours")).collect();

        assert!(matches!(open_epoch(e, &round, &pk, &received[..t - 1]), EpochOpen::Short), "t − 1 releases open nothing");
        let EpochOpen::Key(sk) = open_epoch(e, &round, &pk, &received[..t]) else { panic!("t releases open the epoch") };
        assert_eq!(open_ticket(&pk, &sk, &ct, &ticket, &tc), Some((key, addr.clone(), 4_000, blind)));

        let (_, other_ct, _, _) = seal_ticket(&pk, &entropy(3, 1, 32).try_into().unwrap(), &addr, 4_000, &blind).unwrap();
        assert!(open_ticket(&pk, &sk, &other_ct, &ticket, &tc).is_none(), "a swapped ciphertext opens nothing");
    }

    /// ⭐ §BR-9a step (c) TAMPER — A DEALER WHO SHARES ANOTHER SEED IS NAMED, AND THE PROOF CONVICTS ONLY HIM. Dealer 3 signs a
    /// deal whose shares are of a seed other than the one its public part comes from. Custody's opening yields a fraud proof
    /// naming dealer 3 (and only 3), which any node checks from the ledger alone; the same proof re-pointed at an honest
    /// dealer, or with one share altered, does not hold. CONTROL: with no bad dealer the epoch opens.
    #[test]
    fn br9a_c_a_dealer_who_shares_another_seed_is_named_by_a_proof_any_node_checks() {
        let c = custody(5);
        let (e, round, pk, bundles) = dealt_epoch(&c, Some(3));
        let EpochOpen::Faulty(proofs) = open_epoch(e, &round, &pk, &bundles) else { panic!("the bad dealer must be caught") };
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].dealer, c[3].id, "the proof names the dealer who cheated");
        assert!(fraud_proof_holds(&round, &proofs[0]), "any node checks it from the ledger alone");
        let mut framed = proofs[0].clone();
        framed.dealer = c[1].id;
        assert!(!fraud_proof_holds(&round, &framed), "re-pointed at an honest dealer it convicts no one");
        let mut altered = proofs[0].clone();
        altered.shares[0].1[5] ^= 1;
        assert!(!fraud_proof_holds(&round, &altered), "an altered share breaks the dealer's commitment");
        let (e2, round2, pk2, bundles2) = dealt_epoch(&c, None);
        assert!(matches!(open_epoch(e2, &round2, &pk2, &bundles2), EpochOpen::Key(_)), "CONTROL: an honest epoch opens");
    }
}

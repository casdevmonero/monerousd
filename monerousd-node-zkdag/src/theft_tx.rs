// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ DB-274 P4b (§8.15) — `Class::ReserveTheft`: A THEFT SLASH IS A CHAIN OBJECT, BECAUSE IT BURNS A BOND.
//!
//! ## What this replaces, and the three holes it closes
//! `POST /slash_reserve_theft` called `Node::slash_reserve_theft`, which ran `validators.slash(id)` on the ONE node that
//! received the request:
//! 1. **A socket moved consensus state.** No block carried the slash, so every peer kept the offender's weight, and
//!    from then on every ≥2/3 denominator (credits, price marks, the custody tally, finality) differed between that
//!    node and the mesh. MEASURED by `db274_p4b_the_reserve_theft_slash_travels_the_mesh_and_never_mutates_at_the_socket`
//!    (A 0/10,000 vs B 5,000/15,000, thief bond / total bond).
//! 2. **The offenders were unbound.** The certificate signed `"…THEFT-v1" ‖ statement`, and the offender list was a
//!    separate, unsigned argument. So one genuine certificate slashed ANY validator a caller named. MEASURED by
//!    `db274_p4b_a_genuine_theft_cert_never_slashes_a_validator_it_does_not_name` (A 0 vs B 5,000).
//! 3. **An unbonding thief escaped.** Only `validators.slash(id)` ran, so a custodian that unbonded right after a
//!    theft kept its returning note. Equivocation's slash already reached `unbonding` (DB-274 P2 F2).
//!
//! ## The borrowed shape
//! DB-266's `Class::Equivocation`, itself Ethereum's slashing operations. The evidence is a framed object. The route
//! PUBLISHES it and never mutates. It rides `Block::bond_set`, and every node applies it inside `apply_bond_set` at the
//! block's FOLD step, through ONE slash function shared with equivocation (`Node::apply_slash`), which reaches a
//! validator that is bonded OR unbonding.
//!
//! ## The certificate is weighed in the step's PRE-state (lane-wallet's review, C3)
//! `apply_bond_set` walks its entries and mutates the set as it goes. A seat earlier in the same bond set would change
//! a later theft's denominator. So `apply_bond_set` takes ONE copy of the set before its loop, only when the step
//! carries a theft object, and every theft object in the step is weighed against that copy. That is the same
//! canonical pre-state P4a's credits are judged in.
//!
//! ## Bounds, constant and structural (C1, C2)
//! The shared tally (`bond_tally::verify_threshold`) ML-DSA-verifies EVERY attestor before weighing, so decode refuses
//! what would make it walk without limit:
//! - duplicate attestor keys;
//! - more attestors than `RESERVE_THEFT_MAX_ATTESTORS`;
//! - a key or signature of the wrong width;
//! - more offenders than `RESERVE_THEFT_MAX_OFFENDERS`, or an offender list that is not strictly ascending (so one
//!   theft has one encoding and one content id).
//! Whether an offender holds weight is chain state, so decode never asks it. The fold slashes whoever is bonded or
//! unbonding.
//!
//! ## Named residuals
//! - **The evidence window (C4).** A thief whose unbonding window closed, and whose note returned, BEFORE the evidence
//!   folds is out of reach. That is the same bound equivocation has.
//! - **No network id** in any attested message of this family (peg, tally, equivocation). A cross-network certificate
//!   replay needs a reused validator key. The residual is class-wide, not this object's.
//! - **The depositor make-whole is unbuilt.** The burned weight is returned as a figure and credited nowhere. When it
//!   is built, it is a value-creation site and enters that census.
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;

/// FIPS 204, ML-DSA-65: the public key and signature widths. An attestor of any other width is refused at decode, so
/// the wire bound below is exact.
pub const ML_DSA_65_PK_BYTES: usize = 1_952;
pub const ML_DSA_65_SIG_BYTES: usize = 3_309;

/// Offenders per object. They are validators, so the list is bounded like the attestor list of every other
/// quorum-attested object: `MAX_CREDIT_ATTESTORS` = `DAG_WIDTH_CEILING` (lane-wallet's C2: a CONSTANT, because a
/// structure-only door cannot read the set).
pub const RESERVE_THEFT_MAX_OFFENDERS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;
/// Attestors per object, the same derivation (C1). Each one costs a verifier ML-DSA-65 verify, and the tally verifies
/// every one before it weighs.
pub const RESERVE_THEFT_MAX_ATTESTORS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;

/// The widest `bond_tally::reserve_move_statement`: its 29-byte domain, two length-prefixed strings (the asset and
/// the foreign destination, each at most a foreign address, `PEG_ATTEST_ADDRESS_MAX`), the 32-byte amount
/// commitment, the 32-byte burned nullifier and the 8-byte epoch.
pub const RESERVE_THEFT_STATEMENT_MAX: usize =
    29 + 4 + crate::peg_attest::PEG_ATTEST_ADDRESS_MAX + 4 + crate::peg_attest::PEG_ATTEST_ADDRESS_MAX + 32 + 32 + 8;

/// The widest honest object, derived from the bounds above: the frame (4-byte magic + class byte), then postcard's
/// length varints (≤ 5 bytes each; ≤ 3 for a per-item length below 2^21), the statement, the offender ids and the
/// attestors' keys and signatures. Anything wider is refused before it is parsed.
pub const RESERVE_THEFT_WIRE_MAX: usize = 4
    + 1
    + 5
    + RESERVE_THEFT_STATEMENT_MAX
    + 5
    + RESERVE_THEFT_MAX_OFFENDERS * 32
    + 10 // the loss: postcard's u64 varint, at most 10 bytes
    + 5
    + RESERVE_THEFT_MAX_ATTESTORS * (3 + ML_DSA_65_PK_BYTES + 3 + ML_DSA_65_SIG_BYTES);

/// The payload: `(statement, offenders ascending, the stolen amount in sats, attestors as (pubkey, signature))`.
pub type ReserveTheftPayload = (Vec<u8>, Vec<[u8; 32]>, u64, Vec<(Vec<u8>, Vec<u8>)>);

/// ⭐ §BR-3 17.5 — the most a theft can claim: every bitcoin there will ever be (21M × 10⁸ sats). A loss is public (it is a
/// Bitcoin transaction anyone can see), so stating it inside the signed message reveals nothing.
pub const RESERVE_THEFT_LOSS_MAX_SATS: u64 = 2_100_000_000_000_000;

/// THE message a theft certificate signs (v3): the domain, the length-prefixed statement, the offender count and the
/// offender ids in ascending order, then the stolen amount in sats (§BR-3 17.5). The offenders AND the loss are INSIDE the
/// signature, so a certificate slashes exactly the validators it names and books exactly the loss custody attested.
#[must_use]
pub fn theft_msg(statement: &[u8], offenders: &[[u8; 32]], loss_sats: u64) -> Vec<u8> {
    let mut m = crate::pqauth::node_statement(b"USDMD-PQFROST-THEFT-v3");
    m.extend_from_slice(&(statement.len() as u32).to_le_bytes());
    m.extend_from_slice(statement);
    m.extend_from_slice(&(offenders.len() as u32).to_le_bytes());
    for id in offenders {
        m.extend_from_slice(id);
    }
    m.extend_from_slice(&loss_sats.to_le_bytes());
    m
}

/// §BR-3 17.5 — the one-time key a theft's LOSS is booked under (`PegLedger::book_theft`): one statement books once, so a
/// second certificate for the same theft (naming another offender) slashes its offender but never books the loss twice.
#[must_use]
pub fn theft_loss_key(statement: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/theft-loss-key/v1");
    h.update(statement);
    *h.finalize().as_bytes()
}

/// The offenders in their one canonical order: ascending, each once.
#[must_use]
pub fn canonical_offenders(offenders: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut v = offenders.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// Frame the evidence as a `Class::ReserveTheft` object, the one publication path. `None` when the evidence is not
/// canonical (offenders not strictly ascending), is empty, or exceeds a bound: the same checks `decode` runs.
#[must_use]
pub fn wire(
    statement: &[u8],
    offenders: &[[u8; 32]],
    loss_sats: u64,
    cert: &crate::bond_tally::PqThresholdCert,
) -> Option<Vec<u8>> {
    let attestors: Vec<(Vec<u8>, Vec<u8>)> =
        cert.attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect();
    let payload: ReserveTheftPayload = (statement.to_vec(), offenders.to_vec(), loss_sats, attestors);
    let bytes = postcard::to_allocvec(&payload).ok()?;
    decode(&bytes)?; // the publisher builds nothing the door would refuse
    Some(crate::chain_object::frame(Class::ReserveTheft, &bytes))
}

/// Strict decode: one encoding (`decode_exact`), every bound above, strictly ascending offenders, distinct attestor
/// keys, and exact ML-DSA-65 widths. Structure only: no signature is verified and no chain state is read here.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<(Vec<u8>, Vec<[u8; 32]>, u64, crate::bond_tally::PqThresholdCert)> {
    if payload.len() > RESERVE_THEFT_WIRE_MAX {
        return None; // wider than any honest evidence: refused before it is parsed
    }
    let (statement, offenders, loss_sats, attestors) = decode_exact::<ReserveTheftPayload>(payload)?;
    if loss_sats == 0 || loss_sats > RESERVE_THEFT_LOSS_MAX_SATS {
        return None; // a theft of nothing, or of more bitcoin than exists
    }
    if statement.is_empty() || statement.len() > RESERVE_THEFT_STATEMENT_MAX {
        return None;
    }
    if offenders.is_empty() || offenders.len() > RESERVE_THEFT_MAX_OFFENDERS {
        return None;
    }
    if offenders.windows(2).any(|w| w[0] >= w[1]) {
        return None; // not ascending, or an id twice: not the one encoding
    }
    if attestors.is_empty() || attestors.len() > RESERVE_THEFT_MAX_ATTESTORS {
        return None;
    }
    let mut keys: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for (pk, sig) in &attestors {
        if pk.len() != ML_DSA_65_PK_BYTES || sig.len() != ML_DSA_65_SIG_BYTES || !keys.insert(pk.as_slice()) {
            return None; // a width no ML-DSA-65 key or signature has, or one signer twice
        }
    }
    let cert = crate::bond_tally::PqThresholdCert {
        attestors: attestors
            .into_iter()
            .map(|(pubkey, sig)| crate::psm::MintAttestor { pubkey, sig })
            .collect(),
    };
    Some((statement, offenders, loss_sats, cert))
}

/// What applying an evidence object did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TheftApply {
    /// Not a theft object: left entirely alone.
    NotTheft,
    /// The named offenders that held weight here were slashed. Carries the total burned, bond plus unbonding.
    Slashed(u128),
    /// Refused before anything moved, with the reason a node can act on.
    Refused(&'static str),
}


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn enc(p: &ReserveTheftPayload) -> Vec<u8> {
        postcard::to_allocvec(p).expect("a payload encodes")
    }

    /// ⛔ DB-274 P4b (§8.15, lane-wallet's C1/C2) — decode admits ONLY the one canonical, bounded shape, before any
    /// signature is verified and without reading any chain state. Each refusal below is a shape that would either give
    /// one theft two encodings (two content ids, two carriages), or make the tally verify without limit.
    /// CALIBRATION: the canonical object decodes, so every refusal is the decoder's own.
    #[test]
    fn a_theft_object_decodes_only_in_its_one_canonical_bounded_shape() {
        let (pk1, sk1) = crate::pqauth::ml_dsa_keypair();
        let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        let stmt = b"a reserve move no certificate authorized".to_vec();
        let (lo, hi) = ([1u8; 32], [2u8; 32]);
        let msg = theft_msg(&stmt, &[lo, hi], 100_000_000);
        let sign = |pk: &[u8], sk: &[u8]| (pk.to_vec(), crate::pqauth::ml_dsa_sign(&msg, sk).expect("signs"));
        let good: ReserveTheftPayload = (stmt.clone(), vec![lo, hi], 100_000_000, vec![sign(&pk1, &sk1), sign(&pk2, &sk2)]);
        assert!(decode(&enc(&good)).is_some(), "CALIBRATION: the canonical object decodes");
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut p = good.clone();
        p.1 = vec![hi, lo];
        cases.push(("offenders out of order", enc(&p)));
        let mut p = good.clone();
        p.1 = vec![lo, lo];
        cases.push(("one offender twice", enc(&p)));
        let mut p = good.clone();
        p.1 = Vec::new();
        cases.push(("no offender", enc(&p)));
        let mut p = good.clone();
        p.1 = (0..=RESERVE_THEFT_MAX_OFFENDERS as u32)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                id
            })
            .collect();
        cases.push(("more offenders than the constant cap", enc(&p)));
        let mut p = good.clone();
        p.3 = vec![good.3[0].clone(), good.3[0].clone()];
        cases.push(("one signer twice", enc(&p)));
        let mut p = good.clone();
        p.3[0].0.push(0);
        cases.push(("a key of the wrong width", enc(&p)));
        let mut p = good.clone();
        p.3[0].1.pop();
        cases.push(("a signature of the wrong width", enc(&p)));
        let mut p = good.clone();
        p.3 = Vec::new();
        cases.push(("no attestor", enc(&p)));
        let mut p = good.clone();
        p.0 = Vec::new();
        cases.push(("an empty statement", enc(&p)));
        let mut p = good.clone();
        p.0 = vec![7u8; RESERVE_THEFT_STATEMENT_MAX + 1];
        cases.push(("a statement wider than the widest reserve move", enc(&p)));
        let mut p = good.clone();
        p.2 = 0;
        cases.push(("a loss of nothing", enc(&p)));
        let mut p = good.clone();
        p.2 = RESERVE_THEFT_LOSS_MAX_SATS + 1;
        cases.push(("a loss of more bitcoin than exists", enc(&p)));
        let mut trailing = enc(&good);
        trailing.push(0);
        cases.push(("a trailing byte (a second encoding)", trailing));
        for (what, bytes) in cases {
            assert!(decode(&bytes).is_none(), "⛔ DB-274 P4b: a theft object with {what} decoded");
        }
    }

    /// The v2 message binds the offenders: another offender list is another message, so the SAME signatures never
    /// cover it.
    #[test]
    fn the_v2_message_binds_the_offender_list() {
        let s = b"one theft".as_slice();
        assert_ne!(theft_msg(s, &[[1u8; 32]], 5), theft_msg(s, &[[2u8; 32]], 5), "a swapped offender is another message");
        assert_ne!(
            theft_msg(s, &[[1u8; 32]], 5),
            theft_msg(s, &[[1u8; 32], [2u8; 32]], 5),
            "an added offender is another message"
        );
        assert_ne!(theft_msg(s, &[[1u8; 32]], 5), theft_msg(s, &[[1u8; 32]], 6), "§BR-3 17.5: another loss is another message");
        assert_eq!(
            canonical_offenders(&[[2u8; 32], [1u8; 32], [2u8; 32]]),
            vec![[1u8; 32], [2u8; 32]],
            "the one canonical order: ascending, each once"
        );
    }
}

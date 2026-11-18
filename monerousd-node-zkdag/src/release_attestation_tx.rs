// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-10 — A BUILDER'S RELEASE ATTESTATION (`Class::ReleaseAttestation`): reproducible builds, attested on chain.
//!
//! Each independent builder reproduces a release and signs `(release hash, version, plain-language notes, emergency)` with
//! its ML-DSA key. The chain keeps each builder's LATEST attestation (bounded by the builder set compiled into this release,
//! `canonical_builders.txt`), and the wallet offers an update only when ≥ 3 builders attest the same hash (spec §8). The
//! attestation is informational: it moves no value and changes no rule; nodes still choose what they run (the Bitcoin model).
//! Borrowed shape: Bitcoin Core's Guix builders and their signed attestations, with the signer set in the release itself.
//!
//! §9.6: (1) PoW — the carrying block's; (2) the signature — ML-DSA-65 by a key whose id is in the compiled builder set; (3)
//! value — none; (4) replay — one id per (builder, release hash) on the lane, and the registry keeps one entry per builder;
//! (5) bounded work — one signature, bounded strings; (6) parity with `Class::DeploymentSignal` (the other signed
//! informational message): the key is checked against a set, the object moves nothing else.

use serde::{Deserialize, Serialize};

/// The longest version string and release notes an attestation carries.
pub const VERSION_MAX: usize = 32;
pub const NOTES_MAX: usize = 600;
/// The builders that must agree before a wallet offers an update.
pub const BUILDERS_TO_OFFER: usize = 3;

/// The builder key ids this release counts.
#[must_use]
pub fn builders() -> Vec<[u8; 32]> {
    include_str!("canonical_builders.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(id_of_hex)
        .collect()
}

/// A 64-hex-digit key id, or `None`.
fn id_of_hex(l: &str) -> Option<[u8; 32]> {
    let b = l.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

#[cfg(test)]
static TEST_BUILDERS: std::sync::Mutex<Option<Vec<[u8; 32]>>> = std::sync::Mutex::new(None);
/// Test builds only: stand in a builder set (process-wide: only attestation objects read it, and no other test lays one).
#[cfg(test)]
pub fn set_builders_for_test(b: Option<Vec<[u8; 32]>>) {
    *TEST_BUILDERS.lock().unwrap_or_else(|e| e.into_inner()) = b;
}
fn builder_set() -> Vec<[u8; 32]> {
    #[cfg(test)]
    if let Some(b) = TEST_BUILDERS.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return b;
    }
    builders()
}

/// The attestation, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAttestationTx {
    pub release_hash: [u8; 32],
    pub version: String,
    pub notes: String,
    pub emergency: bool,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 public key (decode refuses any other width).
    pub builder_pk: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 signature (decode refuses any other width).
    pub sig: Vec<u8>,
}

/// What a builder signs.
#[must_use]
pub fn attestation_msg(release_hash: &[u8; 32], version: &str, notes: &str, emergency: bool) -> Vec<u8> {
    let mut m = b"MUSD/release-attestation/v1".to_vec();
    m.extend_from_slice(release_hash);
    m.extend_from_slice(&(version.len() as u32).to_le_bytes());
    m.extend_from_slice(version.as_bytes());
    m.extend_from_slice(&(notes.len() as u32).to_le_bytes());
    m.extend_from_slice(notes.as_bytes());
    m.push(u8::from(emergency));
    m
}

/// One id per (builder, release).
#[must_use]
pub fn attestation_nf(builder: &[u8; 32], release_hash: &[u8; 32]) -> [u8; 32] {
    let mut pre = b"MONEROUSD-RELEASE-ATTESTATION-NF-v1".to_vec();
    pre.extend_from_slice(builder);
    pre.extend_from_slice(release_hash);
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl ReleaseAttestationTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::ReleaseAttestation, &self.encode())
    }
    /// One canonical encoding, bounded strings, exact key widths.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<ReleaseAttestationTx> {
        let t: ReleaseAttestationTx = crate::chain_object::decode_exact(bytes)?;
        (!t.version.is_empty()
            && t.version.len() <= VERSION_MAX
            && t.notes.len() <= NOTES_MAX
            && t.builder_pk.len() == crate::theft_tx::ML_DSA_65_PK_BYTES
            && t.sig.len() == crate::theft_tx::ML_DSA_65_SIG_BYTES)
            .then_some(t)
    }
    /// The builder's key id.
    #[must_use]
    pub fn builder(&self) -> [u8; 32] {
        crate::pqauth::pubkey_id(&self.builder_pk)
    }
    /// The whole rule: a builder of this release's set signed exactly this attestation.
    #[must_use]
    pub fn authorised(&self) -> bool {
        builder_set().contains(&self.builder())
            && crate::pqauth::ml_dsa_verify(
                &attestation_msg(&self.release_hash, &self.version, &self.notes, self.emergency),
                &self.builder_pk,
                &self.sig,
            )
    }
}

/// What applying an attestation at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationApply {
    NotAttestation,
    Applied,
    Refused(&'static str),
}


/// The releases ≥ [`BUILDERS_TO_OFFER`] builders attest, from a registry of each builder's latest attestation:
/// `(hash, version, notes, emergency, builders)`, most-attested first.
#[must_use]
pub fn offered_releases(registry: &std::collections::BTreeMap<[u8; 32], ReleaseAttestationTx>) -> Vec<([u8; 32], String, String, bool, usize)> {
    let mut by: std::collections::BTreeMap<[u8; 32], (String, String, bool, usize)> = std::collections::BTreeMap::new();
    for t in registry.values() {
        let e = by.entry(t.release_hash).or_insert((t.version.clone(), t.notes.clone(), t.emergency, 0));
        e.3 += 1;
    }
    let mut v: Vec<_> = by.into_iter().filter(|(_, (_, _, _, n))| *n >= BUILDERS_TO_OFFER).map(|(h, (ver, n, e, c))| (h, ver, n, e, c)).collect();
    v.sort_by(|a, b| b.4.cmp(&a.4));
    v
}

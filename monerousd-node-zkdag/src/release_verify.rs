// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ RELEASE VERIFICATION BEFORE THE FIRST RUN (readiness T6 items 5–6; docs/INSTALL.md §1).
//!
//! A release ships `SHA256SUMS` (the artifacts' SHA-256 digests, `shasum -a 256` format) and a directory of
//! [`crate::release_attestation_tx::ReleaseAttestationTx`] files: each is ONE builder's ML-DSA-65 signature over the release
//! hash — `blake3(SHA256SUMS bytes)` — so an attestation covers EXACTLY the artifact hashes the user checks, byte for byte.
//! `usdmd-node verify-release --sums SHA256SUMS --attestations DIR` recomputes every listed digest from the files beside
//! `SHA256SUMS`, decodes every attestation, and accepts only when every digest matches and at least
//! [`BUILDERS_REQUIRED`] DISTINCT builders from the compiled-in builder set (`release_attestation_tx::builders`) have signed
//! this exact release hash. The same objects, carried on the chain, are what §BR-10's attested-release root reads
//! (`NodeRuntime::attested_release_root`) — one attestation shape, one signer set, offline and on-chain.
//!
//! ROOT-LAYER: the user's trust in a downloaded binary is produced HERE, before the binary runs — a check inside the running
//! node would be the binary vouching for itself. The attestation shape and the builder set are the chain's own
//! (`release_attestation_tx`), so this verifier adds no second signer set and no second encoding.
//! MEASURED: before this module, docs/INSTALL.md §1 named `usdmd-node verify-release` and `grep verify-release main.rs` found
//! 0 hits — the documented verification did not exist and a user had `shasum -c` alone (no signer). The pin below runs the
//! verifier over a built release directory and six tampers, each refused on its own named arm.
//! MUST-STAY-GREEN: `release_attestation_tx` pins (the chain's attestation door), `NodeRuntime::attested_release_root`;
//! nothing on the chain reads this module. This module WRITES nothing: it reads the release files the user downloaded.
//!
//! Borrowed: Debian's `SHA256SUMS` + detached signatures over the sums file (the hashes are what the signature covers, so the
//! user verifies one signature set for every artifact); Bitcoin Core's "two or more Guix builders attest one hash" release
//! rule, with ML-DSA-65 in place of PGP.
//!
//! Fail closed: a digest that does not match, a file that is missing, an attestation that does not verify, one by an unknown
//! builder, one over another release hash, or fewer than two distinct builders each refuse the whole release — nothing is
//! "partially verified".

use std::path::{Path, PathBuf};

/// Two independent builders must attest one build hash (docs/PUBLIC-TESTNET-LAUNCH.md §2 item 6).
pub const BUILDERS_REQUIRED: usize = 2;

/// Why a release was refused — every arm names the file or builder, never a secret.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    SumsUnreadable(String),
    SumsMalformed { line: usize },
    ArtifactMissing(String),
    DigestMismatch(String),
    AttestationsUnreadable(String),
    AttestationUnreadable(String),
    AttestationMalformed(String),
    AttestationNotAuthorised(String),
    AttestationForAnotherRelease(String),
    TooFewBuilders { distinct: usize, required: usize },
}

impl std::fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SumsUnreadable(w) => write!(f, "SHA256SUMS could not be read: {w}"),
            Self::SumsMalformed { line } => write!(f, "SHA256SUMS line {line} is not `<64 hex>  <file>`"),
            Self::ArtifactMissing(n) => write!(f, "artifact {n} named in SHA256SUMS is missing or unreadable"),
            Self::DigestMismatch(n) => write!(f, "artifact {n} does not hash to its SHA256SUMS line — REFUSED, do not run it"),
            Self::AttestationsUnreadable(w) => write!(f, "the attestations directory could not be read: {w}"),
            Self::AttestationUnreadable(n) => write!(f, "attestation {n} could not be read"),
            Self::AttestationMalformed(n) => write!(f, "attestation {n} is not a release attestation (hex or raw postcard)"),
            Self::AttestationNotAuthorised(n) => write!(f, "attestation {n} is not a valid signature by a compiled-in release builder"),
            Self::AttestationForAnotherRelease(n) => write!(f, "attestation {n} signs another release hash, not this SHA256SUMS"),
            Self::TooFewBuilders { distinct, required } => write!(f, "{distinct} distinct builder(s) attest this release; {required} are required"),
        }
    }
}

/// The release hash every attestation signs: blake3 over the exact bytes of `SHA256SUMS`.
#[must_use]
pub fn release_hash_of(sums_bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("MUSD/release-hash/sha256sums/v1").update(sums_bytes).finalize().as_bytes()
}

/// `(digest, file name)` per non-empty line of a `SHA256SUMS` file (`<64 hex>  <name>` or `<64 hex> *<name>`).
pub fn parse_sums(text: &str) -> Result<Vec<([u8; 32], String)>, ReleaseRefusal> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hex, name) = match line.split_once(' ') {
            Some(parts) => parts,
            None => return Err(ReleaseRefusal::SumsMalformed { line: i + 1 }),
        };
        let name = name.trim_start().trim_start_matches('*').trim();
        if hex.len() != 64 || name.is_empty() {
            return Err(ReleaseRefusal::SumsMalformed { line: i + 1 });
        }
        let mut d = [0u8; 32];
        for (k, b) in d.iter_mut().enumerate() {
            *b = match u8::from_str_radix(&hex[2 * k..2 * k + 2], 16) {
                Ok(v) => v,
                Err(_) => return Err(ReleaseRefusal::SumsMalformed { line: i + 1 }),
            };
        }
        out.push((d, name.to_string()));
    }
    Ok(out)
}

fn sha256_file(path: &Path) -> Option<[u8; 32]> {
    use bitcoin_hashes::{sha256, Hash, HashEngine};
    let mut f = std::fs::File::open(path).ok()?;
    let mut e = sha256::Hash::engine();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        e.input(&buf[..n]);
    }
    Some(sha256::Hash::from_engine(e).to_byte_array())
}

/// Decode one attestation file: hex text or raw postcard bytes of a [`crate::release_attestation_tx::ReleaseAttestationTx`].
fn decode_attestation(bytes: &[u8]) -> Option<crate::release_attestation_tx::ReleaseAttestationTx> {
    let as_hex = std::str::from_utf8(bytes).ok().and_then(|t| crate::rpc_http::hex_decode(t.trim()));
    let raw: &[u8] = match &as_hex {
        Some(h) => h,
        None => bytes,
    };
    crate::release_attestation_tx::ReleaseAttestationTx::decode(raw)
}

/// ⭐ VERIFY A RELEASE: every artifact's digest and at least [`BUILDERS_REQUIRED`] distinct authorised builders over this
/// exact `SHA256SUMS`. `Ok(builders)` names the attesting builder ids; any `Err` means: do not run it.
pub fn verify_release(sums_path: &Path, attestations_dir: &Path) -> Result<Vec<[u8; 32]>, ReleaseRefusal> {
    let sums_bytes = match std::fs::read(sums_path) {
        Ok(b) => b,
        Err(e) => return Err(ReleaseRefusal::SumsUnreadable(e.to_string())),
    };
    let sums_text = String::from_utf8_lossy(&sums_bytes);
    let entries = parse_sums(&sums_text)?;
    // the artifacts live beside SHA256SUMS; a sums file with no parent (a bare name) names the working directory
    let base: PathBuf = match sums_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    for (want, name) in &entries {
        let got = match sha256_file(&base.join(name)) {
            Some(d) => d,
            None => return Err(ReleaseRefusal::ArtifactMissing(name.clone())),
        };
        if got != *want {
            return Err(ReleaseRefusal::DigestMismatch(name.clone()));
        }
    }
    let release_hash = release_hash_of(&sums_bytes);
    let dir = match std::fs::read_dir(attestations_dir) {
        Ok(d) => d,
        Err(e) => return Err(ReleaseRefusal::AttestationsUnreadable(e.to_string())),
    };
    let mut files: Vec<PathBuf> = dir.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_file()).collect();
    files.sort();
    let mut builders: Vec<[u8; 32]> = Vec::new();
    for p in files {
        let name = match p.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => return Err(ReleaseRefusal::AttestationUnreadable(p.display().to_string())),
        };
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(_) => return Err(ReleaseRefusal::AttestationUnreadable(name)),
        };
        let t = match decode_attestation(&bytes) {
            Some(t) => t,
            None => return Err(ReleaseRefusal::AttestationMalformed(name)),
        };
        if !t.authorised() {
            return Err(ReleaseRefusal::AttestationNotAuthorised(name));
        }
        if t.release_hash != release_hash {
            return Err(ReleaseRefusal::AttestationForAnotherRelease(name));
        }
        let b = t.builder();
        if !builders.contains(&b) {
            builders.push(b);
        }
    }
    if builders.len() < BUILDERS_REQUIRED {
        return Err(ReleaseRefusal::TooFewBuilders { distinct: builders.len(), required: BUILDERS_REQUIRED });
    }
    Ok(builders)
}

#[cfg(test)]
mod tests {
    // LOCAL-STORAGE-REQUIRED: a TEST FIXTURE only — a throw-away release directory (three files of a few hundred bytes) the
    // verifier is pointed at, removed at the end; the node writes nothing and no node state is involved.
    // bound: 0 B on any node; the fixture's three files, deleted by the test.
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("usdmd-release-verify-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("att")).expect("tmp");
        d
    }
    fn attest(release_hash: &[u8; 32], pk: &[u8], sk: &[u8]) -> Vec<u8> {
        let (version, notes, emergency) = ("0.1.0", "testnet", false);
        let sig = crate::pqauth::ml_dsa_sign(&crate::release_attestation_tx::attestation_msg(release_hash, version, notes, emergency), sk).expect("signs");
        crate::release_attestation_tx::ReleaseAttestationTx { release_hash: *release_hash, version: version.into(), notes: notes.into(), emergency, builder_pk: pk.to_vec(), sig }.encode()
    }
    fn put(d: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(d.join(name), bytes).expect("the fixture file writes");
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// ⭐ T6 — A RELEASE IS ACCEPTED ONLY WHEN EVERY ARTIFACT HASHES TO ITS LINE AND TWO DISTINCT BUILDERS SIGNED THIS EXACT
    /// SUMS FILE. TAMPERS, each refused on its own: one byte changed in an artifact (its digest no longer matches); one
    /// builder only; the same builder twice; an attestation over another release hash; an attestation by a key outside the
    /// builder set; a malformed sums line. CALIBRATION: the honest release passes and names both builders.
    #[test]
    fn a_release_is_accepted_only_with_matching_digests_and_two_distinct_authorised_builders() {
        let d = tmp("ok");
        put(&d, "usdmd-node", b"the node binary bytes");
        put(&d, "wallet.dmg", b"the wallet bytes");
        let line = |name: &str| -> String {
            let dg = sha256_file(&d.join(name)).expect("hash");
            format!("{}  {name}\n", dg.iter().map(|b| format!("{b:02x}")).collect::<String>())
        };
        let sums = format!("{}{}", line("usdmd-node"), line("wallet.dmg"));
        put(&d, "SHA256SUMS", sums.as_bytes());
        let rh = release_hash_of(sums.as_bytes());
        let (pk1, sk1) = crate::pqauth::ml_dsa_keypair();
        let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        let (pk3, sk3) = crate::pqauth::ml_dsa_keypair();
        crate::release_attestation_tx::set_builders_for_test(Some(vec![crate::pqauth::pubkey_id(&pk1), crate::pqauth::pubkey_id(&pk2)]));
        put(&d, "att/b1.att", &attest(&rh, &pk1, &sk1));
        put(&d, "att/b2.att", hex(&attest(&rh, &pk2, &sk2)).as_bytes());
        let ok = verify_release(&d.join("SHA256SUMS"), &d.join("att")).expect("CALIBRATION: the honest release verifies");
        assert_eq!(ok.len(), 2, "both builders are named");
        // ⛔ one byte of an artifact changed
        put(&d, "wallet.dmg", b"the wallet byteS");
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::DigestMismatch("wallet.dmg".into())));
        put(&d, "wallet.dmg", b"the wallet bytes");
        // ⛔ one builder only, and the same builder twice
        std::fs::remove_file(d.join("att/b2.att")).expect("rm");
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::TooFewBuilders { distinct: 1, required: 2 }));
        put(&d, "att/b1-again.att", &attest(&rh, &pk1, &sk1));
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::TooFewBuilders { distinct: 1, required: 2 }));
        std::fs::remove_file(d.join("att/b1-again.att")).expect("rm");
        // ⛔ an attestation over another release hash
        put(&d, "att/b2.att", &attest(&[7u8; 32], &pk2, &sk2));
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::AttestationForAnotherRelease("b2.att".into())));
        // ⛔ a builder outside the compiled-in set
        put(&d, "att/b2.att", &attest(&rh, &pk3, &sk3));
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::AttestationNotAuthorised("b2.att".into())));
        // ⛔ a malformed sums line
        put(&d, "att/b2.att", &attest(&rh, &pk2, &sk2));
        put(&d, "SHA256SUMS", format!("{sums}deadbeef  usdmd-node\n").as_bytes());
        assert_eq!(verify_release(&d.join("SHA256SUMS"), &d.join("att")), Err(ReleaseRefusal::SumsMalformed { line: 3 }));
        crate::release_attestation_tx::set_builders_for_test(None);
        let _ = std::fs::remove_dir_all(&d);
    }
}

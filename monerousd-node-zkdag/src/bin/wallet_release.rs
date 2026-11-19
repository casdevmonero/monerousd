// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE WALLET RELEASE SIGNER (lane speed5, 2026-11-18; user: "lets build the one click ota update for the wallet now and then
//! prove that it works and then release it on all platforms").
//!
//!   wallet_release keygen <dir>                      a fresh ML-DSA-65 release key: <dir>/release.pk (public) and
//!                                                    <dir>/release.sk (owner-only, 0600). Prints only the public key's id.
//!   wallet_release sign <manifest.json> <release.sk> writes <manifest.json>.sig: ML-DSA-65 over
//!                                                    `MANIFEST_DOMAIN ‖ the manifest's exact bytes`
//!   wallet_release verify <manifest.json> <release.pk>
//!
//! The wallet compiles the public key in and refuses any manifest whose signature does not verify under it, and any file
//! whose size and blake3 differ from what the signed manifest names (monerousd-wallet-v2 `updater.rs`).
//! AI RESISTANT: (c) today — one key on one machine signs a release, named plainly; before real funds it becomes a
//! threshold of keys on separate machines (charter §2: a person, key or machine that could ship code is a threshold).
//! A secret key is never printed, logged or sent anywhere.
//! LOCAL-STORAGE-REQUIRED: a release tool run by the developer, never by a node: the signing key must live somewhere the
//! wallet's verifier cannot reach (it is the point of a signature), and the signature is a file published beside the manifest.
//! bound: one 4,032-byte secret key, one 1,952-byte public key and one 3,309-byte signature per release — never per item.
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

/// The domain every wallet release signature covers (the wallet's `updater::MANIFEST_DOMAIN` is the same bytes).
const MANIFEST_DOMAIN: &[u8] = b"MUSD-wallet-release-v1\0";

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") => {
            let dir = std::path::Path::new(a.get(2).expect("keygen <dir>"));
            std::fs::create_dir_all(dir).expect("the key folder");
            let (pk, sk) = usdmd_node::pqauth::ml_dsa_keypair();
            let skp = dir.join("release.sk");
            if skp.exists() {
                eprintln!("{} exists — refusing to replace a release key", skp.display());
                std::process::exit(1);
            }
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&skp).expect("release.sk");
            f.write_all(&sk).expect("write release.sk");
            std::fs::write(dir.join("release.pk"), &pk).expect("release.pk");
            println!("release key id {}", hex(&usdmd_node::pqauth::pubkey_id(&pk)));
        }
        Some("sign") => {
            let (m, k) = (a.get(2).expect("sign <manifest> <sk>"), a.get(3).expect("sign <manifest> <sk>"));
            let body = std::fs::read(m).expect("the manifest");
            let sk = std::fs::read(k).expect("the release key");
            let mut msg = MANIFEST_DOMAIN.to_vec();
            msg.extend_from_slice(&body);
            let sig = usdmd_node::pqauth::ml_dsa_sign(&msg, &sk).expect("a well-formed release key");
            std::fs::write(format!("{m}.sig"), &sig).expect("write the signature");
            println!("signed {} ({} B manifest, {} B signature)", m, body.len(), sig.len());
        }
        Some("manifest") => {
            // wallet_release manifest <out dir> <version> <notes> <release.sk> <platform>=<file> …
            // writes <out dir>/wallet-manifest.json (each file's name, exact size and blake3) and its .sig, in one step
            let out = std::path::Path::new(a.get(2).expect("manifest <out> <version> <notes> <sk> <platform>=<file>…"));
            let (version, notes, sk) = (a.get(3).expect("version"), a.get(4).expect("notes"), a.get(5).expect("release.sk"));
            let mut assets = serde_json::Map::new();
            for spec in &a[6..] {
                let (platform, file) = spec.split_once('=').expect("<platform>=<file>");
                let bytes = std::fs::read(file).expect("a release file");
                let name = std::path::Path::new(file).file_name().and_then(|n| n.to_str()).expect("a file name").to_string();
                assets.insert(
                    platform.to_string(),
                    serde_json::json!({ "name": name, "size": bytes.len(), "blake3": blake3::hash(&bytes).to_hex().to_string() }),
                );
            }
            let m = serde_json::json!({ "product": "monerousd-wallet", "version": version, "notes": notes, "assets": assets });
            let path = out.join("wallet-manifest.json");
            std::fs::write(&path, serde_json::to_vec_pretty(&m).expect("json")).expect("write the manifest");
            let body = std::fs::read(&path).expect("the manifest");
            let mut msg = MANIFEST_DOMAIN.to_vec();
            msg.extend_from_slice(&body);
            let sig = usdmd_node::pqauth::ml_dsa_sign(&msg, &std::fs::read(sk).expect("the release key")).expect("a release key");
            std::fs::write(format!("{}.sig", path.display()), &sig).expect("write the signature");
            println!("wrote {} ({} platform(s), version {version}) and its signature", path.display(), m["assets"].as_object().map_or(0, |o| o.len()));
        }
        Some("verify") => {
            let (m, p) = (a.get(2).expect("verify <manifest> <pk>"), a.get(3).expect("verify <manifest> <pk>"));
            let body = std::fs::read(m).expect("the manifest");
            let sig = std::fs::read(format!("{m}.sig")).expect("the signature");
            let pk = std::fs::read(p).expect("the public key");
            let mut msg = MANIFEST_DOMAIN.to_vec();
            msg.extend_from_slice(&body);
            let ok = usdmd_node::pqauth::ml_dsa_verify(&msg, &pk, &sig);
            println!("{}", if ok { "VALID" } else { "INVALID" });
            std::process::exit(i32::from(!ok));
        }
        _ => {
            eprintln!("usage: wallet_release keygen <dir> | sign <manifest.json> <release.sk> | verify <manifest.json> <release.pk>");
            std::process::exit(2);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

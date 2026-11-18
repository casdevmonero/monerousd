// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — exercise the wallet's REAL clue-key PUBLISH + RESOLVE against the live loopback node
// (the oblivious cold-restore directory, brick 4). stdin line1 = wallet mnemonic. It serializes the wallet's
// PUBLIC OMR clue key, SIGNS `clue_register_msg(clue_pk)` with the ML-DSA-65 spend key, POSTs /register_clue_key,
// then RESOLVES the clue key back by the address owner id `b = H(spend_pk)` and asserts it round-trips
// byte-for-byte AND reconstructs the exact CluePublicKey. Finally an adversarial tampered-signature registration
// must be REJECTED (fail-closed) — only the address key-holder can publish their own clue key.
use monerousd_wallet_v2_lib::{omr, pq};
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

/// The IDENTICAL bytes the node's `pqauth::clue_register_msg(clue_pk)` builds — domain ‖ 0 ‖ clue_pk.
fn clue_msg(clue_pk: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(22 + 1 + clue_pk.len());
    m.extend_from_slice(b"musdm.clue.register.v1");
    m.push(0u8);
    m.extend_from_slice(clue_pk);
    m
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore wallet");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();

    let clue_pk = keys.clue_pk.to_bytes();
    let sig = pq::sign_spend(&keys, &clue_msg(&clue_pk)).expect("sign clue register");

    // 1) PUBLISH the clue key (ML-DSA authenticated).
    let reg: serde_json::Value = ag
        .post(&format!("{NODE}/register_clue_key"))
        .send_json(serde_json::json!({
            "pubkey": hex::encode(&keys.spend_pk),
            "clue_pk": hex::encode(&clue_pk),
            "sig": hex::encode(&sig),
        }))
        .unwrap().into_json().unwrap();

    // 2) RESOLVE it back by the address owner id b = H(spend_pk).
    let res: serde_json::Value = ag
        .post(&format!("{NODE}/resolve_clue_key"))
        .send_json(serde_json::json!({ "b_hex": hex::encode(keys.b) }))
        .unwrap().into_json().unwrap();
    let resolved_hex = res["clue_pk"].as_str().unwrap_or("");
    let resolved = hex::decode(resolved_hex).unwrap_or_default();

    let bytes_match = resolved == clue_pk;
    let reconstructs = omr::CluePublicKey::from_bytes(&resolved).map(|pk| pk == keys.clue_pk).unwrap_or(false);

    // 3) ADVERSARIAL — a TAMPERED signature must be rejected (fail-closed).
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0x01;
    let evil: serde_json::Value = ag
        .post(&format!("{NODE}/register_clue_key"))
        .send_json(serde_json::json!({
            "pubkey": hex::encode(&keys.spend_pk),
            "clue_pk": hex::encode(&clue_pk),
            "sig": hex::encode(&bad_sig),
        }))
        .unwrap().into_json().unwrap();

    println!("clue_pk_bytes={} register_resp={reg} resolved_len={}", clue_pk.len(), resolved.len());
    println!("bytes_roundtrip={bytes_match} reconstructs_exact_key={reconstructs} tampered_sig_registered={}", evil["registered"]);
    assert!(reg["registered"].as_bool().unwrap_or(false), "honest registration must succeed");
    assert!(bytes_match, "resolved clue key must byte-match the published one");
    assert!(reconstructs, "resolved blob must reconstruct the EXACT CluePublicKey");
    assert_eq!(evil["registered"].as_bool(), Some(false), "a tampered signature must be REJECTED (fail-closed)");
    println!("OK — clue directory: publish + resolve round-trips, ML-DSA-authenticated, tamper-rejected.");
}

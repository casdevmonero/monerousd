// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — run the wallet's REAL @username (USDm Pay) register + resolve pipeline against the live
// loopback node, to prove it end to end. stdin: line1 = mnemonic, line2 = username (default "alice"). It (1) SIGNS
// `name_register_msg(name, own_address)` with the ML-DSA-65 spend key, (2) POSTs /register_username, (3) resolves
// @name and confirms it maps to the wallet's OWN address, (4) ADVERSARIAL: a tampered signature MUST be rejected
// (UNAUTHENTICATED). Prints all four so the sound authenticated registry is verified live.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

/// The IDENTICAL bytes the node's `pqauth::name_register_msg` builds — domain ‖ name ‖ 0 ‖ address.
fn name_register_msg(name: &str, address: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(22 + name.len() + 1 + address.len());
    m.extend_from_slice(b"musdm.name.register.v1");
    m.extend_from_slice(name.as_bytes());
    m.push(0u8);
    m.extend_from_slice(address.as_bytes());
    m
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let mut ls = s.lines();
    let seed = ls.next().expect("line1 mnemonic").trim();
    let name = ls.next().unwrap_or("alice").trim().to_string();
    let keys = pq::restore(seed).expect("restore wallet");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();

    // 1. SIGN + register the handle.
    let msg = name_register_msg(&name, &keys.address);
    let sig = pq::sign_spend(&keys, &msg).expect("sign register");
    let reg: serde_json::Value = ag
        .post(&format!("{NODE}/register_username"))
        .send_json(serde_json::json!({
            "name": name, "address": keys.address,
            "pubkey": hex::encode(&keys.spend_pk), "sig": hex::encode(&sig),
        }))
        .unwrap().into_json().unwrap();

    // 2. Resolve @name → confirm it maps to the wallet's OWN address.
    let res: serde_json::Value = ag
        .post(&format!("{NODE}/resolve_username"))
        .send_json(serde_json::json!({ "name": name }))
        .unwrap().into_json().unwrap();
    let resolved_matches = res["address"].as_str() == Some(keys.address.as_str());

    // 3. ADVERSARIAL: a tampered signature (on a fresh name) MUST be rejected UNAUTHENTICATED (no unsigned claim).
    let mut bad = sig.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let tampered: serde_json::Value = ag
        .post(&format!("{NODE}/register_username"))
        .send_json(serde_json::json!({
            "name": format!("{name}-forged"), "address": keys.address,
            "pubkey": hex::encode(&keys.spend_pk), "sig": hex::encode(&bad),
        }))
        .unwrap().into_json().unwrap();

    println!(
        "register={reg} resolve={res} resolved_matches_own_address={resolved_matches} tampered_register={tampered}"
    );
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — run the wallet's REAL validator UNBOND pipeline against the live loopback node. stdin: line1
// = validator mnemonic (must ALREADY be bonded, e.g. via bond_check). It SIGNS `validator_unbond_msg(b)` (b =
// H(spend_pk)) with the ML-DSA-65 spend key and POSTs /unbond_validator; the node verifies + removes the weight.
// Prints the validator set BEFORE and AFTER so the weight decrement is verified live (1/N → 0/0).
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

/// The IDENTICAL bytes the node's `pqauth::validator_unbond_msg(id)` builds — domain ‖ id(32).
fn unbond_msg(id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(25 + 32);
    m.extend_from_slice(b"musdm.validator.unbond.v1");
    m.extend_from_slice(id);
    m
}

fn vset(ag: &ureq::Agent) -> (u64, u64) {
    ag.post(&format!("{NODE}/get_validator_bond_tree"))
        .send_json(serde_json::json!({}))
        .ok()
        .and_then(|r| r.into_json::<serde_json::Value>().ok())
        .map(|j| (
            j["validators"].as_u64().unwrap_or(0),
            j["total_bond"].as_u64().unwrap_or(0),
        ))
        .unwrap_or((0, 0))
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore validator");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();

    let before = vset(&ag);
    let sig = pq::sign_spend(&keys, &unbond_msg(&keys.b)).expect("sign unbond");
    let resp: serde_json::Value = ag
        .post(&format!("{NODE}/unbond_validator"))
        .send_json(serde_json::json!({ "pubkey": hex::encode(&keys.spend_pk), "sig": hex::encode(&sig) }))
        .unwrap().into_json().unwrap();
    let after = vset(&ag);
    println!("validators_before={before:?} unbond_resp={resp} validators_after={after:?}");
}

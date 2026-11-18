// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — run the wallet's REAL bicameral-GOVERNANCE vote pipeline against the live loopback node, to
// prove it end to end. stdin: line1 = validator mnemonic (must ALREADY be a bonded validator, e.g. via bond_check,
// so its validator-chamber weight > 0). It (1) PROPOSES a runtime-tunable param change (permissionless), (2) SIGNS
// a validator-chamber vote with its ML-DSA-65 spend key over the domain-bound message, (3) SUBMITS voter_pubkey +
// signature — the node verifies the signature, sets voter id = H(pubkey), and credits the voter's ON-CHAIN bonded
// weight (no client-supplied number). Prints the governance snapshot before/after so the validator tally moves.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

/// The IDENTICAL bytes the node's `pqauth::governance_vote_msg` builds — domain ‖ proposal_id(32) ‖ chamber(1).
fn governance_vote_msg(proposal_id: &[u8; 32], chamber: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(17 + 32 + 1);
    m.extend_from_slice(b"musdm.gov.vote.v1");
    m.extend_from_slice(proposal_id);
    m.push(chamber);
    m
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore validator");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(25)).build();

    // 1. PROPOSE a runtime-tunable change (permissionless — the anti-capture gate is at enact). value = string.
    let prop: serde_json::Value = ag
        .post(&format!("{NODE}/propose_param_change"))
        .send_json(serde_json::json!({ "kind": "dag_width", "value": "64" }))
        .unwrap().into_json().unwrap();
    let pid_hex = prop["proposal_id"].as_str().expect("proposal_id").to_string();
    let pid_bytes = hex::decode(&pid_hex).unwrap();
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&pid_bytes);

    let gov_before: serde_json::Value =
        ag.get(&format!("{NODE}/get_governance")).call().unwrap().into_json().unwrap();

    // 2. SIGN the validator-chamber (2) vote with the ML-DSA spend key + submit pubkey + detached signature.
    let msg = governance_vote_msg(&pid, 2);
    let sig = pq::sign_spend(&keys, &msg).expect("sign governance vote");
    let vote: serde_json::Value = ag
        .post(&format!("{NODE}/submit_governance_vote"))
        .send_json(serde_json::json!({
            "proposal_id": pid_hex,
            "voter_pubkey": hex::encode(&keys.spend_pk),
            "sig": hex::encode(&sig),
        }))
        .unwrap().into_json().unwrap();

    // 3. ADVERSARIAL: a TAMPERED signature (flip a byte) MUST be rejected by the node's ML-DSA verify.
    let mut bad = sig.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let tampered: serde_json::Value = ag
        .post(&format!("{NODE}/submit_governance_vote"))
        .send_json(serde_json::json!({
            "proposal_id": pid_hex,
            "voter_pubkey": hex::encode(&keys.spend_pk),
            "sig": hex::encode(&bad),
        }))
        .unwrap().into_json().unwrap();

    let gov_after: serde_json::Value =
        ag.get(&format!("{NODE}/get_governance")).call().unwrap().into_json().unwrap();
    println!(
        "proposal_id={} vote={} tampered_sig={} gov_before={} gov_after={}",
        &pid_hex[..16], vote, tampered, gov_before, gov_after
    );
}

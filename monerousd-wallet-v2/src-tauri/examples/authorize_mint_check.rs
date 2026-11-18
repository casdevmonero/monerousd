// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// LIVE proof of the PSM confidential MINT-AUTHORIZATION gate (Buy-USDm) against the loopback node. stdin line1
// = a mnemonic that is ALREADY BONDED (run bond_check first, so this wallet is a bonded validator = the mint
// quorum). It signs `mint_attest_msg(...)` with the ML-DSA-65 spend key and POSTs /authorize_mint three ways to
// show the gate DISCRIMINATES LIVE: (A) bonded attestor → threshold met → UNDERCOLLATERALIZED (the confidential
// 150% ZK solvency seam is UnpinnedSolvency = fail-closed until the pqpool proof is installed); (B) a fresh,
// NON-bonded attestor → INSUFFICIENT_QUORUM; (C) a bonded attestor with a TAMPERED signature → UNAUTHENTICATED.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

/// The IDENTICAL bytes the node's `pqauth::mint_attest_msg(...)` builds.
fn mint_msg(deposit_id: &[u8; 32], reserve: &[u8; 32], liability: &[u8; 32], recipient: &[u8; 32], ratio: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(17 + 32 * 4 + 4);
    m.extend_from_slice(b"musdm.psm.mint.v1");
    m.extend_from_slice(deposit_id);
    m.extend_from_slice(reserve);
    m.extend_from_slice(liability);
    m.extend_from_slice(recipient);
    m.extend_from_slice(&ratio.to_le_bytes());
    m
}

/// One attestor record for `attestors_hex`: `pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig`.
fn attestor_record(pubkey: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&(pubkey.len() as u16).to_le_bytes());
    r.extend_from_slice(pubkey);
    r.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    r.extend_from_slice(sig);
    r
}

fn authorize(ag: &ureq::Agent, reserve: &[u8; 32], liability: &[u8; 32], recipient: &[u8; 32], ratio: u32, attestors_hex: &str) -> String {
    let deposit_id = [7u8; 32];
    let resp: serde_json::Value = ag
        .post(&format!("{NODE}/authorize_mint"))
        .send_json(serde_json::json!({
            "deposit_id": hex::encode(deposit_id),
            "recipient_cm": hex::encode(recipient),
            "reserve_commit": hex::encode(reserve),
            "liability_commit": hex::encode(liability),
            "ratio_bps": ratio,
            "solvency_proof": hex::encode(vec![1u8; 1000]), // well-formed; UnpinnedSolvency rejects → fail-closed
            "attestors_hex": attestors_hex,
        }))
        .unwrap().into_json().unwrap();
    resp["outcome"].as_str().unwrap_or("?").to_string()
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore bonded validator");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();

    // Two distinct non-zero commitments + the 150% ratio (well-formed solvency shape).
    let reserve = [3u8; 32];
    let liability = [5u8; 32];
    let recipient = keys.b; // mint to this wallet's address tag
    let ratio = 15_000u32;
    let msg = mint_msg(&[7u8; 32], &reserve, &liability, &recipient, ratio);

    // (A) BONDED attestor (this wallet, bonded via bond_check) → threshold met → solvency fail-closed.
    let sig = pq::sign_spend(&keys, &msg).expect("sign mint attest");
    let rec_bonded = hex::encode(attestor_record(&keys.spend_pk, &sig));
    let a = authorize(&ag, &reserve, &liability, &recipient, ratio, &rec_bonded);

    // (B) FRESH, NON-bonded attestor (valid sig, zero bonded weight) → sub-threshold.
    let fresh = pq::derive_keys(&*blake3::hash(b"MUSD/psm/fresh-attestor").as_bytes());
    let fsig = pq::sign_spend(&fresh, &msg).expect("sign fresh");
    let rec_fresh = hex::encode(attestor_record(&fresh.spend_pk, &fsig));
    let b = authorize(&ag, &reserve, &liability, &recipient, ratio, &rec_fresh);

    // (C) BONDED attestor but a TAMPERED signature → unauthenticated.
    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    let rec_bad = hex::encode(attestor_record(&keys.spend_pk, &bad));
    let c = authorize(&ag, &reserve, &liability, &recipient, ratio, &rec_bad);

    println!("A bonded_attestor_threshold_met = {a}");
    println!("B non_bonded_attestor          = {b}");
    println!("C tampered_signature           = {c}");
    assert_eq!(a, "UNDERCOLLATERALIZED", "bonded 2/3 threshold met → fails CLOSED on the confidential 150% ZK seam");
    assert_eq!(b, "INSUFFICIENT_QUORUM", "a non-bonded attestor carries zero bonded weight → sub-threshold");
    assert_eq!(c, "UNAUTHENTICATED", "a tampered ML-DSA signature is rejected");
    println!("OK — PSM mint gate LIVE: discriminates threshold / auth / solvency-fail-closed on the real node.");
}

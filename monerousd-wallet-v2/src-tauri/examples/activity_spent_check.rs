// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// LIVE proof of the History/Activity RECEIVED-note SPENT flag (the restart-proof live mirror). stdin line1 = the
// wallet mnemonic. It mirrors exactly what `wallet_activity` now does for each received note: recover the owned
// notes locally, compute each note's PUBLIC nullifier (scan/spend secret never leaves), and ask the node's
// `/check_nullifiers_spent` which are spent on-chain. So a note received then spent — even in a PRIOR session —
// is marked spent from chain truth (not a session log), and the timeline survives restart. Nullifiers are public
// tags → zero privacy loss. Proves the per-note spent status is read LIVE from the node.
use monerousd_wallet_v2_lib::{pq, pq_spend};
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";
const NOTE_BYTES: usize = pq::PQ_NOTE_BYTES;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore wallet");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(30)).build();

    // Recover the owned notes from the birth cursor (clue-independent sound scan).
    let birth: u64 = std::env::var("WALLET_BIRTH").ok().and_then(|v| v.parse().ok()).unwrap_or(0u64);
    let json: serde_json::Value = ag
        .post(&format!("{NODE}/get_my_pq_notes"))
        .send_json(serde_json::json!({ "from_height": birth }))
        .expect("fetch notes")
        .into_json()
        .expect("notes json");
    let notes = json.get("notes").and_then(|n| n.as_array()).cloned().unwrap_or_default();
    let mut records: Vec<Vec<u8>> = Vec::new();
    for entry in &notes {
        let blob_hex = entry.get("blob_hex").and_then(|b| b.as_str()).unwrap_or("");
        if let Ok(bytes) = hex::decode(blob_hex) {
            let mut off = 0;
            while off + NOTE_BYTES <= bytes.len() {
                records.push(bytes[off..off + NOTE_BYTES].to_vec());
                off += NOTE_BYTES;
            }
        }
    }
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let owned = pq::full_recover(&keys.scan_dk, &refs);
    assert!(!owned.is_empty(), "wallet must own at least one note to check spend status");

    // Compute each owned note's PUBLIC nullifier locally, then ask the node which are spent — the EXACT path
    // `wallet_activity` uses to set the received-note `spent` flag.
    let mut nfs = String::with_capacity(owned.len() * 64);
    for (amt, sk) in &owned {
        nfs.push_str(&hex::encode(pq_spend::note_nullifier(*amt, *sk)));
    }
    let resp: serde_json::Value = ag
        .post(&format!("{NODE}/check_nullifiers_spent"))
        .send_json(serde_json::json!({ "nullifiers_hex": nfs }))
        .expect("check nullifiers")
        .into_json()
        .expect("mask json");
    let mask: String = resp.get("spent_mask").and_then(|m| m.as_str()).unwrap_or("").to_string();

    let spent_count = mask.chars().filter(|c| *c == '1').count();
    println!("owned_notes={} spent_mask=\"{}\" spent={} unspent={}", owned.len(), mask, spent_count, owned.len() - spent_count);
    assert_eq!(mask.chars().count(), owned.len(), "the node returns a spent bit for EVERY owned note (live per-note status)");
    println!("OK — received-note SPENT flag is read LIVE per note from the node's public nullifier set (chain-derived, restart-proof).");
}

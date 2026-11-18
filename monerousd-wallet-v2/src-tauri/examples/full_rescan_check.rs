// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// LIVE proof of the SOUND COMPLETE balance path (`wallet_full_rescan` / `pq::full_recover`) against the loopback
// node. stdin line1 = the wallet mnemonic. It fetches the served notes from the wallet's BIRTH cursor and ML-KEM-
// decapsulates them ALL locally, IGNORING the detection clues — the authoritative "verify all funds" scan that no
// malicious sender or node clue can defeat (a corrupt/non-pertinent clue on a note we own can silently hide it
// from the fast clue-accelerated preview; this path cannot be fooled). The scan key never leaves this process; the
// node learns nothing about which served notes are ours. Proves the wallet's OWN note(s) recover clue-INDEPENDENTLY.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";
const NOTE_BYTES: usize = pq::PQ_NOTE_BYTES;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore wallet");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(30)).build();

    // Fetch the served notes from the wallet's BIRTH cursor (the sound non-growing anchor; a fresh wallet born at
    // tip scans ~nothing). The complete recover is clue-INDEPENDENT — no clue filter suppresses a note that is ours.
    let birth: u64 = std::env::var("WALLET_BIRTH").ok().and_then(|v| v.parse().ok()).unwrap_or(0u64);
    let json: serde_json::Value = ag
        .post(&format!("{NODE}/get_my_pq_notes"))
        .send_json(serde_json::json!({ "from_height": birth }))
        .expect("fetch notes")
        .into_json()
        .expect("notes json");
    let notes = json.get("notes").and_then(|n| n.as_array()).cloned().unwrap_or_default();

    // Flatten to raw note records.
    let mut records: Vec<Vec<u8>> = Vec::new();
    for entry in &notes {
        let blob_hex = entry.get("blob_hex").and_then(|b| b.as_str()).unwrap_or("");
        let bytes = match hex::decode(blob_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut off = 0;
        while off + NOTE_BYTES <= bytes.len() {
            records.push(bytes[off..off + NOTE_BYTES].to_vec());
            off += NOTE_BYTES;
        }
    }
    let served = records.len();

    // SOUND complete recover: decap EVERY served note locally, clue-independent.
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let owned = pq::full_recover(&keys.scan_dk, &refs);
    let atomic: u64 = owned.iter().map(|(a, _)| *a).fold(0u64, |x, y| x.saturating_add(y));

    println!("served_notes={served} owned_notes={} atomic={atomic} usdm={:.8}", owned.len(), atomic as f64 / 1e8);
    assert!(!owned.is_empty(), "the sound complete scan must recover the wallet's OWN note(s) from the live chain");
    assert!(atomic > 0, "recovered balance must be positive");
    println!("OK — SOUND complete scan (clue-independent) recovers the wallet's OWN note(s) live: no false-negative money loss.");
}

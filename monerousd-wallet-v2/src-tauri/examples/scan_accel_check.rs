// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// LIVE proof that the wallet's CLUE-ACCELERATED balance scan (the wired `wallet_balance` fast path) recovers
// the EXACT same owned set as a full decap, over the real chain's served notes — while ML-KEM-decapping only
// the clue-pertinent (or unclued) notes. stdin line1 = wallet mnemonic. It fetches every served note, then:
//   (A) FULL baseline: decap every note → owned amounts A.
//   (B) CLUE-ACCEL: batch-resolve clues by cm (/get_note_clues), keep a note iff it has NO clue OR its clue is
//       pertinent to us, decap only those → owned amounts B.
// Asserts A == B (no false negatives — correctness preserved incl. the unclued cover-note fallback) and reports
// the decap count (B's survivors) vs the served total. Same primitives the shipped scanner uses.
use monerousd_wallet_v2_lib::{omr, pq};
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore wallet");
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(25)).build();

    // Fetch every served note record (birth cursor env-driven — not a from-genesis literal).
    let birth = std::env::var("WALLET_BIRTH").ok().and_then(|v| v.parse().ok()).unwrap_or(0u64);
    let my: serde_json::Value = ag
        .post(&format!("{NODE}/get_my_pq_notes"))
        .send_json(serde_json::json!({ "from_height": birth }))
        .unwrap().into_json().unwrap();
    let mut records: Vec<Vec<u8>> = Vec::new();
    for e in my["notes"].as_array().cloned().unwrap_or_default() {
        let bytes = match hex::decode(e["blob_hex"].as_str().unwrap_or("")) { Ok(b) => b, _ => continue };
        let mut off = 0;
        while off + pq::PQ_NOTE_BYTES <= bytes.len() {
            records.push(bytes[off..off + pq::PQ_NOTE_BYTES].to_vec());
            off += pq::PQ_NOTE_BYTES;
        }
    }
    let served = records.len();

    // (A) FULL baseline — decap every served note.
    let mut full: Vec<u64> = records.iter()
        .filter_map(|n| pq::scan_note_full(n, &keys.scan_dk).map(|(a, _)| a))
        .collect();
    full.sort_unstable();

    // (B) CLUE-ACCEL — batch-resolve clues by cm, keep pertinent-or-unclued, decap only those.
    let mut cms_hex = String::new();
    for n in &records { cms_hex.push_str(&hex::encode(&n[0..32])); }
    let cl: serde_json::Value = ag
        .post(&format!("{NODE}/get_note_clues"))
        .send_json(serde_json::json!({ "cms_hex": cms_hex }))
        .unwrap().into_json().unwrap();
    let clues: Vec<Option<omr::Clue>> = cl["clues"].as_array().cloned().unwrap_or_default()
        .iter().map(|v| v.as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| omr::Clue::from_bytes(&b)))
        .collect();
    let mut decaps = 0usize;
    let mut accel: Vec<u64> = Vec::new();
    for (i, n) in records.iter().enumerate() {
        let keep = match clues.get(i).and_then(|c| c.as_ref()) {
            Some(clue) => omr::is_pertinent(&keys.clue_sk, clue),
            None => true, // unclued (cover) → full decap fallback
        };
        if keep {
            decaps += 1;
            if let Some((a, _)) = pq::scan_note_full(n, &keys.scan_dk) { accel.push(a); }
        }
    }
    accel.sort_unstable();

    let clued = clues.iter().filter(|c| c.is_some()).count();
    println!("served_notes={served} clued={clued} full_decaps={served} accel_decaps={decaps}");
    println!("owned_full={full:?}");
    println!("owned_accel={accel:?}");
    assert_eq!(full, accel, "clue-accelerated scan MUST recover the SAME owned set as a full decap (no false negatives)");
    assert!(decaps <= served, "accel decaps never exceed served");
    println!("OK — clue-accelerated wallet_balance recovers the exact owned set; decaps = O(owned + unclued).");
}

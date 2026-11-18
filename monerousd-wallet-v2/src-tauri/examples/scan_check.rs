// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — restore a wallet from a mnemonic (stdin line 1) and LOCALLY scan a hex blob of served
// note payloads (stdin line 2), printing the recovered atomic balance + note count. It exercises the wallet's
// OWN local-decap scan (`pq::scan_note_full`; the scan key never leaves the process), so it proves whether a
// wallet can see a given note set. No secrets are baked in; the seed is supplied device-locally at run time.
// ⛔ `Digest4` IS THE TYPE, NEVER A LITERAL. This example spelled the digest `[u64; 4]` while the
// tree widened it to 8 lanes (§AG), so it stopped compiling and took `cargo test` down with it — every
// wallet pin became unrunnable by the default command. The alias is the node's own
// (`usdm_decider::poseidon2_compress::Digest`), so this file can never again disagree with the chain
// about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;
use monerousd_wallet_v2_lib::{pq, pq_spend};
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    let mut lines = s.lines();
    let phrase = lines.next().expect("line 1 = mnemonic").trim();
    let blobs_hex = lines.next().unwrap_or("").trim();
    let keys = pq::restore(phrase).expect("restore from mnemonic");
    let bytes = hex::decode(blobs_hex).expect("hex blob");
    // Recover every owned note (amount, sk) via local decap — the scan key never leaves this process.
    let mut owned: Vec<(u64, Digest4)> = Vec::new();
    let mut off = 0;
    while off + pq::PQ_NOTE_BYTES <= bytes.len() {
        if let Some(a_sk) = pq::scan_note_full(&bytes[off..off + pq::PQ_NOTE_BYTES], &keys.scan_dk) {
            owned.push(a_sk);
        }
        off += pq::PQ_NOTE_BYTES;
    }
    // Exclude already-spent notes: compute each note's PUBLIC nullifier + ask the node which are spent.
    let mut nfs = String::new();
    for (amt, sk) in &owned {
        nfs.push_str(&hex::encode(pq_spend::note_nullifier(*amt, *sk)));
    }
    let mask: Vec<char> = if owned.is_empty() {
        Vec::new()
    } else {
        let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).build();
        ag.post(&format!("{NODE}/check_nullifiers_spent"))
            .send_json(serde_json::json!({ "nullifiers_hex": nfs }))
            .ok()
            .and_then(|r| r.into_json::<serde_json::Value>().ok())
            .and_then(|j| j.get("spent_mask").and_then(|m| m.as_str()).map(|s| s.chars().collect()))
            .unwrap_or_default()
    };
    let unspent: Vec<u64> = owned
        .iter()
        .enumerate()
        .filter(|(i, _)| mask.get(*i).copied() != Some('1'))
        .map(|(_, (amt, _))| *amt)
        .collect();
    let atomic: u64 = unspent.iter().fold(0u64, |a, x| a.saturating_add(*x));
    println!(
        "owned_scanned={} unspent_notes={} atomic={atomic} usdm={:.8}",
        owned.len(),
        unspent.len(),
        atomic as f64 / 1e8
    );
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Measured proof of the OBLIVIOUS cold-restore keystone (brick 1): the wallet-side detection cost.
//
// It builds a simulated chain of N notes — a handful sealed to ME, the rest to strangers — then MEASURES the
// recipient-side detection pass (`is_pertinent` over every clue, the CHEAP test). The candidates it yields are
// the ONLY notes that then need the expensive ML-KEM decap, so the reduction it prints (naive N decaps → OMR C
// decaps) is the real O(chain)→O(owned) cold-restore win, and the detection wall-clock proves the sub-1s FAST
// pillar. Detection uses ONLY a wallet-local secret — the node/observer learns nothing (zero-leak).
use monerousd_wallet_v2_lib::omr;
use std::time::Instant;

fn main() {
    // Two reproducible test wallets (entropy DERIVED from a label — a fixed vector, not a minted key).
    let me_ent = *blake3::hash(b"MUSD/omr/bench/me").as_bytes();
    let other_ent = *blake3::hash(b"MUSD/omr/bench/other").as_bytes();
    let (pk_me, sk_me) = omr::derive_clue_key(&me_ent);
    let (pk_other, _) = omr::derive_clue_key(&other_ent);

    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let owned: Vec<usize> = vec![7, n / 3, (2 * n) / 3, n - 4]; // my notes, scattered through the chain

    // Sender side (setup): seal a clue onto every note. In production one sender does this once per note.
    let t_build = Instant::now();
    let clues: Vec<omr::Clue> = (0..n)
        .map(|i| {
            let nonce = *blake3::hash(&(i as u64).to_le_bytes()).as_bytes();
            let pk = if owned.contains(&i) { &pk_me } else { &pk_other };
            omr::make_clue(pk, &nonce)
        })
        .collect();
    let build_ms = t_build.elapsed().as_millis();

    // RECIPIENT side (the cold-restore hot path): test every clue with MY wallet-local secret.
    let t_detect = Instant::now();
    let candidates: Vec<usize> = (0..n).filter(|&i| omr::is_pertinent(&sk_me, &clues[i])).collect();
    let detect_us = t_detect.elapsed().as_micros();
    let detect_ms = detect_us as f64 / 1000.0;

    let per_note_us = detect_us as f64 / n as f64;
    let reduction = n as f64 / candidates.len().max(1) as f64;
    let correct = candidates == owned;

    println!("── OMR cold-restore detection bench ──────────────────────────────");
    println!("packed clue on-chain     : {} bytes/note", omr::Clue::BYTES);
    println!("chain notes (N)          : {n}");
    println!("owned notes (O)          : {}", owned.len());
    println!("sender clue-seal (setup) : {build_ms} ms  ({:.2} ms/note)", build_ms as f64 / n as f64);
    println!("── recipient detection (the cold-restore cost) ──────────────────");
    println!("detect ALL {n} clues      : {detect_ms:.1} ms  ({per_note_us:.1} µs/note)");
    println!("candidates found (C)     : {}  {}", candidates.len(),
        if correct { "== owned ✓ (no false pos/neg)" } else { "✗ MISMATCH" });
    println!("EXPENSIVE ML-KEM decaps  : naive {n}  →  OMR {}   ({reduction:.0}× fewer)", candidates.len());
    // Extrapolate the detection pass to a large chain to show it stays sub-1s by the per-note cost.
    let notes_for_1s = (1_000_000.0 / per_note_us) as u64;
    println!("detection throughput     : ~{notes_for_1s} notes / second (sub-1s FAST pillar)");
    assert!(correct, "detection must yield EXACTLY the owned set");
}

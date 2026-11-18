// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ CROSS-SENDER WHIR-SHAPED RECURSIVE-VERIFY SETTLE — the live-mesh producer step (task #144).
//!
//! This is the exact operation a MonerousD producer node runs on the live greenfield mesh to settle a block:
//! N INDEPENDENT senders each produce their OWN inner WHIR/sumcheck spend proof; the producer — holding ONLY
//! the public proofs (NO witness/sk, Pillar-1 privacy) — RECURSIVELY VERIFIES all N IN-CIRCUIT (WHIR-verifies-
//! WHIR, FRI-free) and folds them, via the light decider, into ONE O(1) outer proof. Every other node verifies
//! that ONE constant-size proof instead of re-verifying each tx — so settled TPS = N × BPS × DAG-width, and it
//! scales with node/producer count without bound.
//!
//! Run: `xsender_recursive_settle [N1 N2 …]`  (default sweep 32 64 128 256 512 1024). It prints, per N: the
//! outer carrier bytes (must stay ~CONSTANT ∀N), the ONE O(1) verify time, and the verify-cost-per-settled-tx
//! (must SHRINK ∝ 1/N — the VISA-class lever), then adversarially forges one sender's inner proof and confirms
//! the recursive verify REJECTS it fail-closed.

use usdm_decider::whir_rec_block::xsender_recursive_settle_run;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sweep: Vec<usize> = if args.is_empty() {
        vec![32, 64, 128, 256, 512, 1024]
    } else {
        args.iter().filter_map(|a| a.parse::<usize>().ok()).map(|n| n.max(32)).collect()
    };

    println!("=== CROSS-SENDER WHIR-SHAPED RECURSIVE-VERIFY SETTLE (task #144) — live-mesh producer step ===");
    println!(
        "{:>7} | {:>12} | {:>12} | {:>18}",
        "N", "outer bytes", "verify µs", "µs / settled tx"
    );
    println!("{}", "-".repeat(58));

    let mut first: Option<(usize, usize)> = None; // (N0, carrier0)
    let mut last: Option<(usize, usize, u128)> = None; // (N, carrier, verify_us)
    for &n in &sweep {
        let (carrier, verify_us, ok) = xsender_recursive_settle_run(n, None);
        assert!(ok, "the O(1) outer proof MUST verify all {n} INDEPENDENT inner proofs (live-mesh settle)");
        let per_tx = verify_us as f64 / n as f64;
        println!("{:>7} | {:>12} | {:>12} | {:>15.3} µs", n, carrier, verify_us, per_tx);
        if first.is_none() {
            first = Some((n, carrier));
        }
        last = Some((n, carrier, verify_us));
    }
    println!("{}", "-".repeat(58));

    // O(1) verdict: the outer carrier must stay ~constant as the independent-sender count grows.
    let (n0, s0) = first.unwrap();
    let (n1, s1, v1) = last.unwrap();
    let flat = s1 <= s0 + s0 / 2; // within 1.5× over the whole sweep ⇒ constant (only the ~log-N fold rounds move)
    println!(
        "O(1) CARRIER: N {}→{} ⇒ outer proof {}→{} B ({}) — {} independent senders settle under ONE {}-byte proof.",
        n0, n1, s0, s1, if flat { "CONSTANT ✅" } else { "GREW ❌" }, n1, s1
    );
    println!(
        "O(1) VERIFY: ONE proof, ~{} µs, settles {} txs ⇒ {:.3} µs per settled tx (shrinks ∝ 1/N — the VISA lever).",
        v1, n1, v1 as f64 / n1 as f64
    );
    assert!(flat, "recursive-verify SETTLE carrier MUST stay ~constant across the sender sweep (O(1) pillar)");

    // Adversarial: forge ONE sender's inner proof (a bad round poly) → the recursive verify REJECTS fail-closed.
    let (_fc, _fu, forged_ok) = xsender_recursive_settle_run(n1, Some(0));
    assert!(!forged_ok, "a FORGED inner proof MUST be rejected by the recursive verifier (fail-closed)");
    println!("FORGED sender inner proof at N={n1}: recursive verify REJECTED ✅ (fail-closed, honest senders unaffected).");

    println!("=== DONE — WHIR-verifies-WHIR N-independent recursive settle: O(1) downstream, FRI-free, no witness/sk. ===");
}

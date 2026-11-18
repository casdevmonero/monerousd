// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **WHAT A BLOCK COSTS ON THE WIRE, FIELD BY FIELD — the follower's budget, measured.**
//!
//! MEASURED 2026-09-26: a block serves at ~29 KB (`[block-lane] serving one block by id (29254 byte(s))`)
//! and the chain produces 2 blocks/s mesh-wide = ~57 KB/s of blocks. The hypothesis this module was written
//! to test — that ~57 KB/s saturates a Tor circuit (DB-68b's older ~56 KB/s figure) — was REFUTED by the
//! DB-230 per-page timing on gate K: one lane moved a 1,133,098 B DSYNC bundle in 3,458 ms (319 KB/s), while
//! single 29 KB block pulls took 1.7–2.7 s (10–16 KB/s). The follower is LATENCY-bound (one block per Tor
//! round trip) and APPLY-bound (~190 ms per block of Merkle-view advance, DB-232), not bandwidth-bound.
//!
//! The owner's standing rule for per-block bytes is [[feedback_block_time_stays_shrink_proof_bytes]]: keep
//! the 500 ms block and shrink per-block bytes. This module is the instrument that says WHICH bytes: it
//! serialises one produced block with the node's own wire codec and prints the size of every field. It
//! asserts only what must hold for the breakdown to be honest — the fields sum to the whole — so it is a
//! measurement, never a threshold tuned to pass.
//!
//! cons: none — one produced block on an in-memory testnet party, f(fixed constants); test-only.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;

    fn wire_len<T: serde::Serialize>(v: &T) -> usize {
        postcard::to_allocvec(v).map(|b| b.len()).unwrap_or(0)
    }

    /// R4 — the same census on a node that lays its block ledger REAL (the shape every production block carries; a default
    /// test node lays the bound double, so the census above weighs ~120 KB where a real block weighs ~1.5 MB — MEASURED
    /// 2026-11-02 on four T5 runs, 1,512,985–1,520,265 B from the 34th block on).
    #[test]
    fn r4_a_real_ledger_block_prints_its_wire_bytes_field_by_field_and_the_fields_sum_to_the_whole() {
        let mut node = crate::node::tests::testnet_party_folding_at_tip();
        node.arm_real_ledger_for_test();
        census(&mut node, "real ledger", true);
    }

    #[test]
    fn a_produced_block_prints_its_wire_bytes_field_by_field_and_the_fields_sum_to_the_whole() {
        let mut node = crate::node::tests::testnet_party_folding_at_tip();
        census(&mut node, "default test node", false);
    }

    fn census(node: &mut crate::node::Node, label: &str, ledger: bool) {
        // A few blocks so the nullifier proof and the transitions carry their steady-state shape — and, on a node that lays
        // its ledger, past the block where the anchor ring completes and every block carries the member ledger (the
        // 34th on the T5 runs). The bound is the ring's own depth twice over, a fixed constant.
        let mut blk = None;
        for i in 0..(2 * crate::params::RECORD_FOLD_DEPTH_DEFAULT + 3) {
            blk = node.produce(5_000 + i * 500, Hash32::hash(b"fr"), Hash32::hash(b"mc"));
            if i >= 2 && (!ledger || blk.as_ref().is_some_and(|b| b.member_transition.is_some())) {
                break;
            }
        }
        let b = blk.expect("the party produces");
        assert!(!ledger || b.member_transition.is_some(), "⛔ {label}: no produced block carried the member ledger");
        let total = wire_len(&b);
        let fields: Vec<(&str, usize)> = vec![
            ("header", wire_len(&b.header)),
            ("tx_ids", wire_len(&b.tx_ids)),
            ("pow_proof", wire_len(&b.pow_proof)),
            ("note_transition", wire_len(&b.note_transition)),
            ("cover_transition", wire_len(&b.cover_transition)),
            // §RF-3 §12 (2026-10-24) added the member ledger beside the note ledger; the census must name every
            // wire field or its sum is a claim the block refutes. MEASURED 2026-10-26 (lane-verify-ypir.log):
            // `the per-field wire sizes must sum to the block's own wire size — a field is missing from the census`.
            ("member_transition", wire_len(&b.member_transition)),
            ("nullifier_proof", wire_len(&b.nullifier_proof)),
            ("note_commitments", wire_len(&b.note_commitments)),
            ("oli_tags", wire_len(&b.oli_tags)),
            ("account_targets", wire_len(&b.account_targets)),
            ("bond_set", wire_len(&b.bond_set)),
            // Back on the wire with DB-224's carriage (it was `serde(skip)` after DB-191); the sum below caught it.
            // `output_notes` stays `serde(skip)` — not wire bytes, so not listed.
            ("credit_set", wire_len(&b.credit_set)),
            ("dir_set", wire_len(&b.dir_set)),
            ("letter_set", wire_len(&b.letter_set)),
            // §DIRECT CASH (2026-11) put the padded tags' evidence on the wire; the sum below named the gap
            // (MEASURED 2026-11-10: fields 1,031,215 B against a block of 1,040,435 B).
            ("tag_evidence", wire_len(&b.tag_evidence)),
        ];
        let summed: usize = fields.iter().map(|(_, n)| *n).sum();
        let mut sorted = fields.clone();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("[block-wire] {label}: one produced block = {total} byte(s) on the wire; by field (largest first):");
        for (name, n) in &sorted {
            eprintln!(
                "[block-wire]   {name:<18} {n:>7} B  ({:>5.1}%)",
                100.0 * *n as f64 / total.max(1) as f64
            );
        }
        eprintln!(
            "[block-wire] at 2 blocks/s that is {:.1} KB/s of block bytes (one Tor lane measured 319 KB/s on \
             a bundle, gate K — the follower is latency- and apply-bound, not bandwidth-bound)",
            2.0 * total as f64 / 1024.0
        );
        // The breakdown must account for the whole, or it is naming the wrong bytes. A struct field this
        // list does not name would show up as a gap here instead of hiding.
        assert_eq!(
            summed, total,
            "the per-field wire sizes must sum to the block's own wire size — a field is missing from the census"
        );
        if ledger {
            // The block's ONE joined ledger proof (R4 lever 4 C2), a constant of its shape — what an armed simulation's doubles must weigh.
            let nt = b.note_transition.as_ref().expect("a ledger block carries its note transition");
            let mt = b.member_transition.as_ref().expect("checked above");
            eprintln!(
                "[block-wire] {label}: note ledger agg {} B · tag ledger agg {} B · member ledger agg {} B · tuples {} B",
                nt.agg.len(),
                nt.tag_agg.len(),
                mt.agg.len(),
                nt.tuples.len()
            );
            // R4 parity: an armed simulation's doubles weigh exactly these (`note_transition::bound_weight`) — a proof that
            // changes size turns THIS red, never the simulator's relay cost silently.
            use crate::note_transition::bound_weight as w;
            assert_eq!(
                (nt.agg.len(), nt.tag_agg.len(), mt.agg.len()),
                (w::LEDGER_JOINED, 0, 0),
                "⛔ a real ledger proof's length moved (or the joined note+tag+member form did not lay): set bound_weight to the real prover's length"
            );
        }
    }

    /// R4 — SIM/REAL BYTE PARITY ACROSS TWO NODES: a default test node (the bound ledger double) produces steady-state
    /// blocks whose three ledger seals weigh exactly the real joined proof, and a SECOND node ingests every one of them through its
    /// own armed door (which takes the seal back out only from the real weight) and stands on the producer's tip.
    /// TWO-PARTY-REVIEWED: the producer and the ingesting peer are two independent `Node`s; the peer holds only the bytes.
    #[test]
    fn r4_a_simulated_ledger_block_weighs_what_a_real_one_weighs_and_a_peer_admits_it() {
        let mut producer = crate::node::tests::testnet_party_folding_at_tip();
        let mut peer = crate::node::tests::testnet_party_folding_at_tip();
        let mut last = None;
        for i in 0..(2 * crate::params::RECORD_FOLD_DEPTH_DEFAULT + 3) {
            let ts = 5_000 + i * 500;
            let Some(b) = producer.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")) else { continue };
            let _ = peer.ingest_block(b.clone(), ts + 1);
            let ledger = b.member_transition.is_some();
            last = Some(b);
            if i >= 2 && ledger {
                break;
            }
        }
        let b = last.expect("the producer produces");
        let nt = b.note_transition.as_ref().expect("a ledger block carries its note transition");
        let mt = b.member_transition.as_ref().expect("⛔ no simulated block carried the member ledger");
        use crate::note_transition::bound_weight as w;
        eprintln!("[block-wire] simulated ledger block = {} byte(s) on the wire", wire_len(&b));
        assert_eq!(
            nt.agg.len() + nt.tag_agg.len() + mt.agg.len(),
            w::LEDGER_JOINED,
            "⛔ a simulated block's ledger proofs do not weigh the real joined one"
        );
        assert_eq!(peer.selected_tip(), producer.selected_tip(), "⛔ the peer did not admit the producer's weighted ledger blocks");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A NODE'S RECORD SPACE IS THE CONSENSUS RECORD SPACE — BLOCKS THE NETWORK NEVER SAW DO NOT LIVE IN IT.**
//!
//! Gates 32–37 (2026-09-02/03), measured on the kept scratch of gate 37: the restarted node's last three
//! blocks before its clean shutdown were recorded locally (ordinals 190–192) and NEVER reached its peer;
//! the peer kept producing while it was down. After the restart the node adopted the peer's certified spine
//! four times (`served_seq now 220 → 583`) but KEPT its three orphaned records, so its record space was the
//! peer's plus three extras interleaved — two different record SETS, which no ordering rule can reconcile:
//! every ROOTS RUN the peer served was refused ("does NOT fold from the certified accumulator to the certified
//! target") because the fold origin was the node's OWN record accumulator, built over its orphans, and the
//! heal never closed. The in-process resume and exchange pins are green because they never model a block that
//! one side holds and the other never received. This pin does.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::decider::{ConsensusVerifier, DeciderBundle};
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::relay::RelayOutcome;
    use crate::sync::{AdoptOutcome, FrontierSnapshot};

    struct AcceptAll;
    impl ConsensusVerifier for AcceptAll {
        fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
            true
        }
    }

    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 0; // this file's subject is not the fold delay: fold at the tip, canonical order
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        Node::with_params(g, p).expect("a testnet node builds")
    }

    fn genesis_ts(n: &Node) -> u64 {
        n.dag().get(&n.selected_tip().expect("tip")).expect("header").header.timestamp
    }

    /// Every row of the certified span page must map to the same ordinal on A (the ordinal is the coordinate
    /// a wallet is handed). The page is the node's own bounded lane (at most `DA_LADDER_SPAN` rows).
    fn diverged(a: &Node, b: &Node, rows: &[(u64, u64, Vec<u8>, Vec<u8>)]) -> Vec<(u64, Option<u64>, Option<u64>)> {
        let mut out = Vec::new();
        for (ord, rid, _, _) in rows {
            let (oa, ob) = (a.da_record_ordinal(*rid), b.da_record_ordinal(*rid));
            if oa != Some(*ord) || ob != Some(*ord) {
                out.push((*ord, oa, ob));
            }
        }
        out
    }

    /// ⛔ DB-261 — THIS FILE WAS CITED FOUR TIMES AS THE RECONCILE'S PIN AND HELD NO #[test] (since 2026-09-22): the
    /// body was gone, the helpers stayed, and every "Pinned by `orphaned_prerestart_records_tests`" in node.rs pointed
    /// at nothing. Restored on the file's own scenario, through the production doors (the adopt, the page rows, the
    /// roots-run door and its reconcile). MEASURED 08:17 while restoring it: the stranded tail no longer survives to
    /// the closure at all — the adopt evicts every local claim from `reconcile_origin_ordinal()` up (`[dsync] N local
    /// ordinal claim(s) … left the index`), so the gate-37 wall is closed AT THE ADOPT and the closure's reconcile is
    /// the second line. The pin asserts the whole guarantee end to end: no stranded record keeps an ordinal the chain
    /// gives another record, B's record space EQUALS A's once the page rows and a span closed across TWO runs
    /// (DB-262) land, and a forged run leaves the span open.
    #[test]
    fn a_stranded_tail_leaves_the_record_space_when_the_certified_span_closes_and_a_forged_run_evicts_nothing() {
        let produce = |n: &mut Node, ts: u64, tag: &str| {
            n.produce(ts, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner")).expect("a block produces")
        };
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let t0 = genesis_ts(&node_a);
        for k in 0..10u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_a, ts, &format!("c{k}"));
            assert!(matches!(node_b.ingest_block(c, ts + 1_000), RelayOutcome::Added(_)), "setup: B grafts");
        }
        // B's last blocks before its shutdown: folded on B, never seen by A.
        let mut stranded: Vec<(u64, u64)> = Vec::new();
        for k in 0..3u64 {
            let b = produce(&mut node_b, t0 + 60_000 * (11 + k) + 20_000, &format!("s{k}"));
            let seq = Node::da_record_id_for_block(&b.id(), 0);
            stranded.push((seq, node_b.da_record_ordinal(seq).expect("setup: B folded its own block")));
        }
        for (seq, ord) in &stranded {
            assert_ne!(node_a.da_addr_at_ordinal(*ord), Some(*seq), "calibration: A never saw B's record at {ord}");
        }
        // A carries on while B is down.
        for k in 0..20u64 {
            produce(&mut node_a, t0 + 60_000 * (11 + k), &format!("a{k}"));
        }
        for (seq, ord) in &stranded {
            assert!(
                node_a.da_addr_at_ordinal(*ord).is_some(),
                "calibration: the chain gives ordinal {ord} (B's stranded {seq}) to ANOTHER record"
            );
        }
        let bundle = node_a
            .build_sync_bundle(
                vec![1u8; 4096],
                FrontierSnapshot {
                    root: *node_a.note_frontier_root().as_bytes(),
                    height: node_a.note_frontier_count(),
                    peaks_hex: node_a.spend_frontier_peaks_hex(),
                },
            )
            .expect("A serves a bundle");
        assert!(matches!(node_b.instant_sync(bundle), AdoptOutcome::Adopted(_)), "B adopts A's certified state");
        for (seq, ord) in &stranded {
            assert_ne!(
                node_b.da_record_ordinal(*seq),
                Some(*ord),
                "⛔ the stranded record still claims ordinal {ord} after the certified adopt — the gate-37 restart wall"
            );
        }
        // The peer's page re-supplies the coordinates (uncertified, judged by the span below).
        node_b.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
        let (from, count) = node_b.roots_run_ask_range().expect("B's headers-first span is open after the jump");
        let end = from + count as u64;
        let roots: Vec<_> = (from..end)
            .map(|o| node_a.block_root_at_ordinal(o).expect("A derives its own root"))
            .collect();
        assert!(roots.len() >= 6, "calibration: a span worth splitting ({} roots)", roots.len());

        // FORGED — the next-to-last root altered: refused whole, the span stays open.
        let mut forged = roots.clone();
        let at = roots.len() - 2;
        forged[at][0] ^= 1;
        assert!(!node_b.accept_fetched_root_run(from, &forged), "a forged run does not close the span");
        assert!(!node_b.roots_run_closed(), "the door stays open");

        // GENUINE — across two runs.
        let (from, _) = node_b.roots_run_ask_range().expect("the ask restarts at the origin");
        let split = roots.len() / 3;
        assert!(node_b.accept_fetched_root_run(from, &roots[..split]), "the first run folds onto the cursor");
        assert!(!node_b.roots_run_closed(), "calibration: still open after the first run");
        assert!(node_b.accept_fetched_root_run(from + split as u64, &roots[split..]), "the second run closes the span");
        assert!(node_b.roots_run_closed(), "the span closed on the certified spine");
        for (i, r) in roots.iter().enumerate() {
            assert_eq!(node_b.ladder_root_at_ordinal(from + i as u64), Some(*r), "the verified ladder holds every root");
        }
        for ord in from..end {
            assert_eq!(
                node_b.da_addr_at_ordinal(ord),
                node_a.da_addr_at_ordinal(ord),
                "⛔ B's record space differs from the chain's at ordinal {ord} after the certified span closed"
            );
        }
        for (seq, ord) in &stranded {
            assert_ne!(node_b.da_record_ordinal(*seq), Some(*ord), "no stranded record re-entered at {ord}");
        }
    }

}

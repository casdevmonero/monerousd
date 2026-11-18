// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A RECORD'S ORDINAL IS AN INDEX INTO CONSENSUS ORDER — AND IT MUST STAY ONE ACROSS A RESTART.**
//!
//! `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal` (node.rs) proves two LIVE
//! producers agree on every ordinal. Gates 32–37 (2026-09-02/03) measured the one case it does not cover:
//! a node that RESUMES from its checkpoint claims its next ordinals from a counter
//! (`served_seq = max(served_seq, snapshot.served_seq)`, then `max(served_seq, da_ord_top + 1)`), so the
//! records it files after the restart carry ITS counter's numbers while its peer files the same blocks at
//! consensus positions — on the live scratch pair ordinal 190 named seq 831274 on the restarted node and
//! seq 286880 on its peer. Every order-sensitive structure above the ordinal (the frontier spine, ladder
//! spans, ROOTS RUN folds, the heal's catch-up) then disagrees between the two nodes and a restarted node
//! can never re-close. This pin is that journey in-process.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::hash::Hash32;
    use crate::node::tests::{genesis_block, grind_tx};
    use crate::node::Node;

    fn mine_one(node: &mut Node, tag: &str, i: u32, ts: u64) -> Option<crate::block::Block> {
        let need = node.mempool().required_stamp_bits();
        let tx = grind_tx(
            format!("mine-{tag}-{i}").as_bytes(),
            1000,
            vec![Hash32::hash(format!("mine-nf-{tag}-{i}").as_bytes())],
            need,
        );
        let _ = node.ingest_tx_unverified(tx);
        node.produce(ts, Hash32::hash(b"f"), Hash32::hash(b"r"))
    }

    /// Every ordinal both nodes hold must name the SAME block (same copath root at that address).
    fn diverged_ordinals(a: &Node, b: &Node) -> Vec<(u64, u64, Option<u64>, Option<u64>)> {
        let mut out = Vec::new();
        for ord in 0..a.served_seq().min(b.served_seq()) {
            let Some(pos) = a.da_addr_at_ordinal(ord) else { continue };
            let ra = a.da_note_copath_in_block(pos, 0).map(|(_, _, root)| root);
            let rb = b.da_note_copath_in_block(pos, 0).map(|(_, _, root)| root);
            if ra != rb {
                out.push((ord, pos, a.da_record_ordinal(pos), b.da_record_ordinal(pos)));
            }
        }
        out
    }

    /// ⭐ A RESTORED NODE MUST DERIVE THE SAME PER-ORDINAL ROOT FOR AN IDLE RECORD AS IT DID BEFORE THE
    /// RESTART. Gate 38 (2026-09-03): the restarted node's roots for 139 of 153 records differed from the
    /// peer's verified ladder — the idle-record ratio — right after a snapshot restore.
    #[test]
    fn a_restored_node_derives_the_same_idle_record_roots_as_before_the_restart() {
        let mut a = Node::new(genesis_block()).unwrap();
        let mut blocks = Vec::new();
        for i in 0..4u32 {
            if let Some(blk) = a.produce(5_000 + i as u64, Hash32::hash(format!("idle-{i}").as_bytes()), Hash32::hash(b"r")) { blocks.push(blk); }
        }
        let before: Vec<_> = (0..a.served_seq()).map(|o| a.block_root_at_ordinal(o)).collect();
        assert!(before.iter().all(|r| r.is_some()), "every ordinal derives a root before the restart: {before:?}");
        let snap = a.export_snapshot().expect("export");
        let mut a2 = Node::new(genesis_block()).unwrap();
        assert!(a2.restore_snapshot(snap), "the fresh node accepts the checkpoint");
        let after: Vec<_> = (0..a2.served_seq()).map(|o| a2.block_root_at_ordinal(o)).collect();
        assert_eq!(a.served_seq(), a2.served_seq(), "same record count after the restore");
        let diff: Vec<u64> = (0..before.len()).filter(|i| before[*i] != after[*i]).map(|i| i as u64).collect();
        assert!(
            diff.is_empty(),
            "the restored node derives DIFFERENT roots at ordinals {diff:?} (of {}) — an idle record's bytes are \
             not restored/regenerated the way they were written, so every restart makes the node disagree with \
             its peers on every idle record. before={:?} after={:?}",
            before.len(), before, after
        );
    }

}

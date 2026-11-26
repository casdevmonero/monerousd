// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **EVERY NODE THAT HOLDS THE SAME DAG FOLDS THE SAME RECORDS AT THE SAME ORDINALS — THE NOTE SPINE IS A
//! PURE FUNCTION OF THE DAG, NEVER OF THE ORDER A NODE HAPPENED TO RECEIVE BLOCKS IN.**
//!
//! v31 folds a block's record into the note spine only once the block is `record_fold_depth`
//! selected-chain steps below the selected tip, walking the selected chain oldest first and folding
//! each chain block's merge set in the DAG's canonical (blue_work, id) order (`Node::fold_canonical_records`).
//! Ingest writes bytes; the fold assigns the ordinal, the leaves, the accumulator step, the anchor.
//!
//! ROOT-LAYER: the ordinal is PRODUCED by `fold_record_into_spine`, called only from the canonical pass
//! (and once for genesis at construction); no ingest path claims an ordinal any more. The pass reads the
//! DAG — selected parents, headers' parents, blue work — the one thing every node agrees on.
//! MEASURED: gate 41 (2026-09-03, scratch jUhX9D), BEFORE — with arrival-order folding, 597 of 598
//! records both nodes wrote sat at DIFFERENT ordinals (from ordinal 74, the first concurrent block);
//! every restart wall since gate 32 was that. AFTER — these pins (run 2026-09-03): two producers that
//! ingest each other's blocks in OPPOSITE orders, a block that lands late on one side, a node resumed
//! from its checkpoint, and a pair whose separate chains merge (a reorg below the fold depth) all end
//! with identical ordinals for every folded record, identical spine roots and identical accumulator
//! series (0 disagreements). The live claim is gate 42's step 3: roots EQUAL, both READY, gap 0.
//! MUST-STAY-GREEN: canonical_ordinal_after_resume_tests, orphaned_prerestart_records_tests,
//! da_seed_regen_tests, idle_record_regeneration_tests, the persist door pins (v31 carries the cursor),
//! every copath/witness test — a folded record's coordinates are unchanged, only WHEN it folds moved.
//!
//! Two parties in every test — `node_a` and `node_b` both PRODUCE and both INGEST — and every assertion
//! is that they hold the SAME thing.
//!
//! cons: none — the pass visits each block exactly once, when it folds; the work per block is a function
//! of the DAG width and the fold depth (fixed constants), never of the chain length. The cursor is one
//! block id; nothing new is stored. The wait before a record is spendable is `record_fold_depth` blocks
//! (4 × ~500 ms); the fixtures here are a dozen in-memory blocks per node.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::block::Block;
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::relay::RelayOutcome;
    use crate::node::tests::page_above_anchor;

    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 4; // the pins exercise the mechanism at a small depth; the gate runs the constant
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        // §FAST (lane c batch 4): every node a pin in this module builds is built on the pin's own thread, so all of them
        // grind the BOUND PoUW double (`pouw::bound_pow`: every header byte bound, only the kernel CPU dropped; its law
        // has its own pin). Armed at the fixture, once, so no pin in the module runs a mixed mesh.
        crate::pouw::bound_pow::arm_on_this_thread(true);
        let mut n = Node::with_params(g, p).expect("a testnet node builds");
        // ⭐ TEST SPEED (lane-recursion review 2026-09-29 05:52: determinism at the CALL SITE, never inside the secret
        // derivation): each fixture node gets a REPRODUCIBLE, DISTINCT miner seed (the producer's nullifier-decoy
        // secret), so a test chain's certified statement repeats across runs and its whole-chain certificate step comes
        // from the cross-run cache instead of a ~5 min prove. MEASURED before: the jumper pin re-proved on every run
        // (963 s, then 664 s) because the OS-drawn seed moved the nullifier root. Production `Node::new` still draws a
        // fresh seed (`reward::tests` pins two default seeds differ).
        n.set_miner_seed_for_test(fixture_miner_seed());
        // DB-396: these fixtures fold more than SPINE_RING_LEN reward-carrying blocks; a node with no band prover — which
        // no mesh runs — waits at the band's lag cap and leaves the later ordinals unassigned. Keep the band moving the
        // way a production node's prove worker does.
        n.autoprove_band_for_test();
        n
    }

    /// Node `i` of the current test (libtest runs each test on its own thread, so the counter restarts per test and a
    /// test's nodes get the same seeds on every run, in construction order).
    fn fixture_miner_seed() -> [u8; 32] {
        thread_local! { static NEXT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
        let i = NEXT.with(|c| {
            let v = c.get();
            c.set(v + 1);
            v
        });
        *blake3::Hasher::new_derive_key("MUSD/fixture-miner-seed/v1").update(&i.to_le_bytes()).finalize().as_bytes()
    }

    fn genesis_ts(n: &Node) -> u64 {
        n.dag().get(&n.selected_tip().expect("tip")).expect("header").header.timestamp
    }

    fn produce(n: &mut Node, ts: u64, tag: &str) -> Block {
        // the served bundle (`bundle_of`) may have grown this node's chain at the chain's own spacing, past the pin's clock: a
        // block is never stamped at or below its producer's tip, so the pin's next step stays a valid block whatever the serve needed
        let ts = ts.max(genesis_ts(n).saturating_add(1));
        n.produce(ts, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner"))
            .expect("a block produces")
    }

    fn ingest(n: &mut Node, b: &Block, ts: u64, who: &str) {
        let out = n.ingest_block(b.clone(), ts);
        assert!(matches!(out, RelayOutcome::Added(_)), "setup: {who} grafts the block: {out:?}");
    }

    /// The block lane's work, in process (DB-100b, 2026-09-19): a certified bundle carries the served
    /// tip's own past above the fold root — never the other branch a producer still holds unmerged — so a
    /// merge block that names that branch PARKS on a jumper that never received it, and the by-id / batch
    /// lanes supply the ancestry (the runtime's Buffered arm). Here the producer's blocks are handed over
    /// oldest first; the parked block cascades in behind its parents.
    fn ingest_with_lanes(n: &mut Node, b: &Block, ts: u64, who: &str, supply: &[Block]) {
        if matches!(n.ingest_block(b.clone(), ts), RelayOutcome::Added(_)) {
            serve_wants_from(n, supply, ts);
            return;
        }
        for s in supply {
            if n.dag().get(&s.id()).is_none() {
                let _ = n.ingest_block(s.clone(), ts);
            }
        }
        if n.dag().get(&b.id()).is_none() {
            assert!(
                matches!(n.ingest_block(b.clone(), ts), RelayOutcome::Added(_)),
                "setup: {who} grafts the block once the lanes supplied the branch it merges"
            );
        }
        serve_wants_from(n, supply, ts);
    }

    /// The by-id block lane's work, in process: a body the canonical fold WAITS for (`[fold-wait] … named to
    /// the by-id block lane` — a member held only as a shell, e.g. the orphan that cascaded in behind its
    /// parents) is handed over from the producer's blocks; a Duplicate keeps the body (`fill_shell_body…`).
    /// CHAIN-PUBLISH-REVIEWED: a TEST harness's stand-in for the runtime tick — the fold pass it runs is the
    /// same canonical fold every node runs over the blocks it holds; nothing here is state another node must
    /// agree on beyond what the DAG already carries.
    fn serve_wants_from(n: &mut Node, supply: &[Block], ts: u64) {
        for _ in 0..4 {
            let _ = n.fold_canonical_records(); // the pass that names what the fold waits for
            let wants = n.wanted_block_ids();
            if wants.is_empty() && n.relay_buffered_len() == 0 {
                break;
            }
            // the batch page's shape: the producer's bodies above what this node holds, oldest first — a
            // wanted id's whole missing ancestry lands in order and the parked children cascade behind it
            for b in supply {
                if n.dag().get(&b.id()).is_none() || n.holds_only_a_shell(&b.id()) {
                    let _ = n.ingest_block(b.clone(), ts);
                }
            }
        }
    }

    /// The whole fold-visible state of a node: (block id → ordinal) for every block named, the spine
    /// root, the dense counter, and the accumulator series over the folded ordinals.
    fn fold_state(n: &Node, blocks: &[Block]) -> (Vec<(Hash32, Option<u64>)>, crate::spend_frontier::Digest4, u64, Vec<Option<crate::spend_frontier::Digest4>>) {
        let ords: Vec<(Hash32, Option<u64>)> = blocks
            .iter()
            .map(|b| (b.id(), n.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0))))
            .collect();
        let served = n.served_seq();
        let accs: Vec<Option<crate::spend_frontier::Digest4>> = (0..served).map(|k| n.da_membership_acc_at_ordinal(k)).collect();
        (ords, n.spend_frontier_root(), served, accs)
    }

    fn assert_same_fold(node_a: &Node, node_b: &Node, blocks: &[Block], what: &str) {
        let (oa, ra, sa, aa) = fold_state(node_a, blocks);
        let (ob, rb, sb, ab) = fold_state(node_b, blocks);
        let disagree: Vec<_> = oa
            .iter()
            .zip(ob.iter())
            .filter(|(x, y)| x.1 != y.1)
            .map(|(x, y)| (x.0, x.1, y.1))
            .collect();
        assert!(disagree.is_empty(), "{what}: ordinals differ for {} block(s): {disagree:?}", disagree.len());
        assert_eq!(sa, sb, "{what}: the dense fold counter differs");
        assert_eq!(ra, rb, "{what}: the spine roots differ");
        // ⛔ G2a — the anchor spine folded into the WHIR decider: one leaf per folded record (genesis, ordinal 0, none), and
        // a rewind takes back every leaf it un-folds. MEASURED on the fast journey: n0 1868 vs n1 1872 leaves, spine SAME.
        for (n, side) in [(node_a, "A"), (node_b, "B")] {
            assert_eq!(
                n.root_history_count(),
                n.served_seq().saturating_sub(1),
                "{what}: ⛔ G2a node {side}'s root_history holds {} anchors over {} folded records",
                n.root_history_count(),
                n.served_seq().saturating_sub(1)
            );
        }
        assert_eq!(node_a.root_history_root(), node_b.root_history_root(), "{what}: ⛔ G2a the anchor spines differ");
        // The accumulator step at every ordinal BOTH sides hold (a resumed node re-derives the persisted
        // prefix's series from its peer's roots run — that lane is not this pin's subject).
        let compared: Vec<(u64, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> = aa
            .iter()
            .zip(ab.iter())
            .enumerate()
            .filter_map(|(k, (x, y))| match (x, y) {
                (Some(x), Some(y)) => Some((k as u64, *x, *y)),
                _ => None,
            })
            .collect();
        let acc_disagree: Vec<_> = compared.iter().filter(|(_, x, y)| x != y).collect();
        assert!(acc_disagree.is_empty(), "{what}: the accumulator series differ at {acc_disagree:?}");
        assert!(!compared.is_empty(), "{what}: setup — no accumulator step was comparable");
        let folded = oa.iter().filter(|(_, o)| o.is_some()).count();
        assert!(folded > 0, "{what}: setup — nothing folded, the pin proved nothing");
    }

    /// Both produce a sibling on genesis, then ingest each other's sibling — A holds [a1, b1], B holds
    /// [b1, a1]. Six common blocks later the siblings are below the fold depth on both.
    #[test]
    fn two_producers_that_ingest_each_others_blocks_in_opposite_orders_fold_identical_ordinals() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let a1 = produce(&mut node_a, t0 + 60_000, "a1");
        let b1 = produce(&mut node_b, t0 + 60_000, "b1");
        ingest(&mut node_a, &b1, t0 + 61_000, "A");
        ingest(&mut node_b, &a1, t0 + 61_000, "B");
        let mut blocks = vec![a1, b1];
        for k in 0..6u64 {
            let ts = t0 + 120_000 + k * 60_000;
            let c = produce(&mut node_a, ts, &format!("c{k}"));
            ingest(&mut node_b, &c, ts + 1_000, "B");
            blocks.push(c);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "opposite arrival orders");
        assert!(
            node_a.da_record_ordinal(Node::da_record_id_for_block(&blocks[0].id(), 0)).is_some()
                && node_a.da_record_ordinal(Node::da_record_id_for_block(&blocks[1].id(), 0)).is_some(),
            "both siblings are below the fold depth and folded"
        );
    }

    /// A's two chained blocks reach B only after B has produced two of its own — B folds nothing of A's
    /// until the merge, and then both fold the merged past identically.
    #[test]
    fn a_block_that_lands_late_on_one_node_still_folds_at_the_same_ordinal_everywhere() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let a1 = produce(&mut node_a, t0 + 60_000, "a1");
        let a2 = produce(&mut node_a, t0 + 120_000, "a2");
        let b1 = produce(&mut node_b, t0 + 60_000, "b1");
        let b2 = produce(&mut node_b, t0 + 120_000, "b2");
        ingest(&mut node_b, &a1, t0 + 180_000, "B");
        ingest(&mut node_b, &a2, t0 + 181_000, "B");
        ingest(&mut node_a, &b1, t0 + 180_000, "A");
        ingest(&mut node_a, &b2, t0 + 181_000, "A");
        let mut blocks = vec![a1, a2, b1, b2];
        for k in 0..7u64 {
            let ts = t0 + 240_000 + k * 60_000;
            let c = produce(&mut node_b, ts, &format!("m{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            blocks.push(c);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "late arrival");
    }

    /// A resumed node — its checkpoint anchored at the fold root — re-derives the same fold as the node
    /// that never stopped, once the blocks above its anchor come back.
    #[test]
    fn a_node_resumed_from_its_checkpoint_folds_the_next_blocks_at_the_same_ordinals_as_its_peer() {
        let mut node_b = testnet_node();
        let mut node_a = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut blocks: Vec<Block> = Vec::new();
        for k in 0..8u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("p{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            blocks.push(c);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "before the checkpoint");
        // the snapshot AND its fold record, through the ONE resume a boot runs (a snapshot-only restore is a path no node
        // takes: MEASURED link 31, it holds no nullifier view and its fold waited at the DB-353 §13.6 respend verdict
        // forever — this pin's red in every recorded run since 2026-10-04)
        let (snap, fold) = node_a.checkpoint_for_test().expect("checkpoint");
        assert!(
            !snap.fold_carry.unfolded.is_empty(),
            "setup: the checkpoint carries the blocks above the fold root ({} carried)",
            snap.fold_carry.unfolded.len()
        );
        let mut resumed = testnet_node();
        assert!(resumed.resume_from_checkpoint_for_test(snap, fold), "the checkpoint resumes");
        if let Err(why) = resumed.warm_view_from_for_test(&node_b) {
            panic!("PRECONDITION: the resumed node warms its view from its peer — {why}");
        }
        // NOTHING is re-ingested by hand: the checkpoint's carried blocks put the DAG back at the tip
        assert_eq!(
            resumed.selected_tip(),
            node_a.selected_tip(),
            "the resumed node's DAG reaches the tip from the checkpoint alone"
        );
        for k in 8..14u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("p{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            ingest(&mut resumed, &c, ts + 1_000, "resumed A");
            blocks.push(c);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "the never-stopped party");
        assert_same_fold(&resumed, &node_b, &blocks, "the resumed party");
    }

    /// ⛔⛔⛔ DB-424 — A CHECKPOINT SAVED MID-BATCH RESUMES THE BATCH; IT NEVER RENUMBERS ITS CHAIN BLOCK.
    ///
    /// MEASURED (sweep simpar-20261008-012522, seed 0x6 T3, node 0): the fold placed chain block aa3437ae's batch
    /// {61206401 → 1384, b066bac6 → 1385, aa3437ae → 1386}; the two members folded, the chain block waited (the DB-396 band
    /// wait), and the validator-provision restart checkpointed THEN — cursor 1383, spine 1385. The resumed node placed
    /// aa3437ae at 1384 with no members, and every pass after that was refused at the leaf law ("ordinal 1384 would append
    /// at leaf 354560 but its ordinal places it at 354048") for the remaining 860 simulated seconds: the bond never seated
    /// on node 0 ([0, 4e6, 4e6]). Two drops across the restart (fixed together, at their producers): the checkpoint's carry named the two
    /// folded members as FLOOR ancestors (prefix the mergeset walk stops at), and the restore never rebuilt the
    /// `da_leafstart_mem` marker that lets a mid-batch retry count a member as verified in its slot.
    ///
    /// The pin: two producers, sibling blocks, a real-note chain block merging both whose record the restarting node does
    /// not hold yet, so its fold stops mid-batch exactly as the band wait stopped node 0's. The never-stopped peer B decides
    /// the ordinals; the resumed node must fold the chain block — and everything after — at B's ordinals and B's spine root.
    #[test]
    fn a_node_checkpointed_mid_batch_resumes_the_batch_at_its_peers_ordinals() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut blocks: Vec<Block> = Vec::new();
        for k in 0..3u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("mb{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            blocks.push(c);
        }
        // two siblings: whichever is not the merging block's selected parent is a MEMBER of its batch
        let ts = t0 + 60_000 * 4;
        let a1 = produce(&mut node_a, ts, "mb-a1");
        let b1 = produce(&mut node_b, ts + 7, "mb-b1");
        ingest(&mut node_a, &b1, ts + 1_000, "A");
        ingest(&mut node_b, &a1, ts + 1_000, "B");
        blocks.push(a1.clone());
        blocks.push(b1.clone());
        // the merging chain block carries a real note, so its record is wanted by id and never regenerated from its header
        let mut note = Hash32::hash(b"db424-mid-batch-cm").as_bytes().to_vec();
        let mut ctr = 0u64;
        while note.len() < crate::cover::PQ_NOTE_BYTES {
            note.extend_from_slice(Hash32::hash(&[&b"db424-ct"[..], &ctr.to_le_bytes()].concat()).as_bytes());
            ctr += 1;
        }
        note.truncate(crate::cover::PQ_NOTE_BYTES);
        let (c, _) = node_a.carry_notes_in_a_block_for_test(ts + 60_000, &note);
        ingest(&mut node_b, &c, ts + 61_000, "B");
        blocks.push(c.clone());
        let member = match node_a.dag().get(&c.id()).and_then(|n| n.selected_parent) {
            Some(sp) if sp == a1.id() => b1.id(),
            Some(sp) if sp == b1.id() => a1.id(),
            other => panic!("setup: the chain block's selected parent is one of the siblings, got {other:?}"),
        };
        // A does not hold the chain block's record when its batch comes up (the band wait's shape: the members fold, the
        // chain block's own step does not)
        assert!(node_a.withhold_block_record_for_test(&c.id()), "setup: A held the chain block's record");
        for k in 0..5u64 {
            let ts = t0 + 60_000 * (6 + k);
            let d = produce(&mut node_b, ts, &format!("mb-d{k}"));
            ingest(&mut node_a, &d, ts + 1_000, "A");
            blocks.push(d);
        }
        let _ = node_a.fold_canonical_records();
        // ⛔ FOLD OVERHAUL (docs/FOLD-OVERHAUL-DEEP-AUDIT-20261126.md, F-7): this test used to assert that A folded the batch's
        // member and stopped before its chain block — a half-applied step held between passes, the shape that wedged the live
        // testnet. A step is atomic now: with the chain block's record missing, A folds NOTHING of the batch.
        assert!(!node_a.block_record_folded_for_test(&member), "ATOMIC STEP: A folded a member of a step it could not finish");
        assert!(!node_a.block_record_folded_for_test(&c.id()), "PRECONDITION: A's step waits on the chain block's record");
        assert!(node_b.block_record_folded_for_test(&c.id()), "CONTROL: B folded the whole batch");
        // the checkpoint is taken NOW, while the step waits — the snapshot AND its fold record, through the ONE resume a boot runs
        let (snap, fold) = node_a.checkpoint_for_test().expect("A exports its checkpoint");
        let mut resumed = testnet_node();
        assert!(resumed.resume_from_checkpoint_for_test(snap, fold), "the mid-batch checkpoint resumes");
        // a restarted node's runtime warms its nullifier view before its fold can decide a respend (DB-353 §13.6) — the
        // same door, in process
        if let Err(why) = resumed.warm_view_from_for_test(&node_b) {
            panic!("PRECONDITION: the resumed node warms its view from its peer — {why}");
        }
        // the chain block's record arrives by the production fetch path, on both A and its resumed twin
        for n in [&mut node_a, &mut resumed] {
            let _ = n.fold_canonical_records();
            let _ = n.deliver_wanted_records_for_test(&node_b);
            let _ = n.fold_canonical_records();
        }
        for k in 0..5u64 {
            let ts = t0 + 60_000 * (11 + k);
            let d = produce(&mut node_b, ts, &format!("mb-e{k}"));
            ingest(&mut node_a, &d, ts + 1_000, "A");
            ingest(&mut resumed, &d, ts + 1_000, "resumed A");
            blocks.push(d);
        }
        let ord = |n: &Node| n.da_record_ordinal(Node::da_record_id_for_block(&c.id(), 0));
        assert!(ord(&node_b).is_some(), "CONTROL: the peer numbered the chain block");
        assert_eq!(ord(&node_a), ord(&node_b), "CONTROL: the never-stopped twin numbers the chain block as its peer does");
        assert_eq!(
            ord(&resumed),
            ord(&node_b),
            "⛔ DB-424: the node resumed from a mid-batch checkpoint numbered the batch's chain block differently from its peer \
             (or never folded it) — its spine can never again reach a root its peers hold"
        );
        assert_same_fold(&node_a, &node_b, &blocks, "the never-stopped party");
        assert_same_fold(&resumed, &node_b, &blocks, "the party resumed mid-batch");
    }

    /// ⛔⛔ FOLD OVERHAUL — A FOLD STEP IS ATOMIC (docs/FOLD-OVERHAUL-DEEP-AUDIT-20261126.md; BORROWED: Bitcoin Core's
    /// ConnectBlock, Kaspa's chain-block acceptance). One chain block's batch applies whole or not at all: while the chain
    /// block's record is missing, no member of its batch folds, the spine stays exactly the cursor's prefix, and once the
    /// record arrives the whole step applies at the ordinals its peer gave it.
    /// RED-FIRST (on main before the overhaul): the member folded and the spine stood one record past the cursor — the half
    /// step that wedged the live testnet on 2026-11-25 (`[fold-order] ⛔ ordinal 4554 would append at leaf 1166080 …`).
    #[test]
    fn a_fold_step_is_atomic_no_member_folds_before_its_whole_batch_can() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut blocks: Vec<Block> = Vec::new();
        for k in 0..3u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("at{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            blocks.push(c);
        }
        // two siblings: whichever is not the merging block's selected parent is a MEMBER of its batch
        let ts = t0 + 60_000 * 4;
        let a1 = produce(&mut node_a, ts, "at-a1");
        let b1 = produce(&mut node_b, ts + 7, "at-b1");
        ingest(&mut node_a, &b1, ts + 1_000, "A");
        ingest(&mut node_b, &a1, ts + 1_000, "B");
        blocks.push(a1.clone());
        blocks.push(b1.clone());
        // the merging chain block carries a real note, so its record is wanted by id and never regenerated from its header
        let mut note = Hash32::hash(b"fold-atomic-cm").as_bytes().to_vec();
        let mut ctr = 0u64;
        while note.len() < crate::cover::PQ_NOTE_BYTES {
            note.extend_from_slice(Hash32::hash(&[&b"fold-atomic-ct"[..], &ctr.to_le_bytes()].concat()).as_bytes());
            ctr += 1;
        }
        note.truncate(crate::cover::PQ_NOTE_BYTES);
        let (c, _) = node_a.carry_notes_in_a_block_for_test(ts + 60_000, &note);
        ingest(&mut node_b, &c, ts + 61_000, "B");
        blocks.push(c.clone());
        let member = match node_a.dag().get(&c.id()).and_then(|n| n.selected_parent) {
            Some(sp) if sp == a1.id() => b1.id(),
            Some(sp) if sp == b1.id() => a1.id(),
            other => panic!("setup: the chain block's selected parent is one of the siblings, got {other:?}"),
        };
        assert!(node_a.withhold_block_record_for_test(&c.id()), "setup: A held the chain block's record");
        for k in 0..5u64 {
            let ts = t0 + 60_000 * (6 + k);
            let d = produce(&mut node_b, ts, &format!("at-d{k}"));
            ingest(&mut node_a, &d, ts + 1_000, "A");
            blocks.push(d);
        }
        let _ = node_a.fold_canonical_records();
        assert!(node_b.block_record_folded_for_test(&c.id()), "CONTROL: B, holding every record, folded the whole batch");
        assert!(
            !node_a.block_record_folded_for_test(&member),
            "⛔ ATOMIC STEP: A folded the batch's member while the batch's chain block could not fold — a half-applied step"
        );
        assert!(!node_a.block_record_folded_for_test(&c.id()), "PRECONDITION: A's step waits on the chain block's record");
        let cursor_ord = node_a.fold_cursor_row_for_test().unwrap_or(0);
        assert_eq!(
            node_a.note_frontier_count(),
            cursor_ord * crate::cover::BLOCK_FIXED_NOTE_COUNT as u64,
            "⛔ ATOMIC STEP: A's spine holds leaves past its fold cursor's prefix between passes"
        );
        // the record arrives by the production fetch path: the whole step applies, at the peer's ordinals
        for _ in 0..3 {
            let _ = node_a.deliver_wanted_records_for_test(&node_b);
            let _ = node_a.fold_canonical_records();
        }
        assert!(node_a.block_record_folded_for_test(&c.id()), "the step applied once its chain block's record arrived");
        let ord = |n: &Node, id: &crate::block::BlockId| n.da_record_ordinal(Node::da_record_id_for_block(id, 0));
        assert_eq!(ord(&node_a, &member), ord(&node_b, &member), "the member takes the ordinal its peer gave it");
        assert_eq!(ord(&node_a, &c.id()), ord(&node_b, &c.id()), "the chain block takes the ordinal its peer gave it");
        assert_same_fold(&node_a, &node_b, &blocks, "the party whose step waited whole");
    }

    /// ⛔ G11c — A NODE STOPPED MID-BATCH NEVER SERVES A BUNDLE NO ADOPTER CAN TAKE (§9.6 (6): serve/adopt parity).
    ///
    /// MEASURED (real leg 4, main 2279431, scratchpad/night/sim-20261023-092259.log): server n0 stood mid-batch — fold
    /// anchor at record 570, spine 571 (a member folded, its chain block's step waiting) — and served the LIVE spine under
    /// the anchor's position; the joiner n2's rescue adopt was refused `FrontierUnbound` (DB-376: the spine must hold
    /// exactly anchor_ordinal × 256 leaves) and n2's fold stayed wedged at 259 for the rest of the leg (bond never seated).
    /// The pin: DB-424's mid-batch shape on the server; every bundle it serves must bind its spine at its anchor and adopt
    /// on a fresh node — mid-batch AND once the batch completes (the CONTROL: serving resumes at the batch boundary).
    #[test]
    fn a_node_stopped_mid_batch_serves_only_bundles_an_adopter_can_take() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..3u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("g11c{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
        }
        let ts = t0 + 60_000 * 4;
        let a1 = produce(&mut node_a, ts, "g11c-a1");
        let b1 = produce(&mut node_b, ts + 7, "g11c-b1");
        ingest(&mut node_a, &b1, ts + 1_000, "A");
        ingest(&mut node_b, &a1, ts + 1_000, "B");
        let mut note = Hash32::hash(b"g11c-mid-batch-cm").as_bytes().to_vec();
        let mut ctr = 0u64;
        while note.len() < crate::cover::PQ_NOTE_BYTES {
            note.extend_from_slice(Hash32::hash(&[&b"g11c-ct"[..], &ctr.to_le_bytes()].concat()).as_bytes());
            ctr += 1;
        }
        note.truncate(crate::cover::PQ_NOTE_BYTES);
        let (c, _) = node_a.carry_notes_in_a_block_for_test(ts + 60_000, &note);
        ingest(&mut node_b, &c, ts + 61_000, "B");
        assert!(node_a.withhold_block_record_for_test(&c.id()), "setup: A held the chain block's record");
        for k in 0..5u64 {
            let ts = t0 + 60_000 * (6 + k);
            let d = produce(&mut node_b, ts, &format!("g11c-d{k}"));
            ingest(&mut node_a, &d, ts + 1_000, "A");
        }
        let _ = node_a.fold_canonical_records();
        assert!(!node_a.block_record_folded_for_test(&c.id()), "PRECONDITION: A's fold stopped mid-batch, before the chain block");
        let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        let (anchor, _) = node_a.fold_anchor().expect("A has a fold anchor");
        let anchor_pos = node_a.certified_fold_base_position(&anchor).expect("A's anchor holds its row");
        // ⛔ FOLD OVERHAUL (docs/FOLD-OVERHAUL-DEEP-AUDIT-20261126.md): this precondition used to read "A's spine stands ABOVE
        // its fold anchor mid-batch" — the half step that made every served bundle unbindable (G11c's measured cause). A step
        // is atomic now: while the step waits, the spine is EXACTLY the anchor's prefix, so what A serves binds by construction.
        assert_eq!(
            node_a.note_frontier_count(),
            anchor_pos * width,
            "⛔ ATOMIC STEP: while its step waits, A's spine is not its fold anchor's prefix (anchor position {anchor_pos})"
        );
        // ⛔ A FIXTURE NEVER FALLS BEHIND THE DOOR: what A serves is what a real node serves (census S-DRAFT-ADOPT)
        let serve = |n: &mut Node| n.serve_join_bundle().and_then(|w| crate::sync::SyncBundle::from_wire(&w));
        let adopts = |bundle: crate::sync::SyncBundle, what: &str| {
            assert!(
                crate::sync::frontier_spine_binds(&bundle.frontier, bundle.anchor_ordinal),
                "⛔ G11c: {what}: the served spine holds {} leaves under anchor position {} — every adopter refuses it \
                 (DB-376 FrontierUnbound)",
                bundle.frontier.height,
                bundle.anchor_ordinal
            );
            let mut node_c = testnet_node();
            node_c.set_decider_verifier(Box::new(AcceptAll));
            let out = node_c.instant_sync(bundle);
            assert!(matches!(out, AdoptOutcome::Adopted(_)), "⛔ G11c: {what}: a fresh node refused the served bundle: {out:?}");
        };
        if let Some(bundle) = serve(&mut node_a) {
            adopts(bundle, "mid-batch");
        }
        // CONTROL: the chain block's record arrives by the production fetch path; the batch completes and A serves again
        let _ = node_a.deliver_wanted_records_for_test(&node_b);
        let _ = node_a.fold_canonical_records();
        assert!(node_a.block_record_folded_for_test(&c.id()), "CONTROL: A's fold completed the batch");
        // a served bundle needs its 32 vouching blocks above the anchor: A's chain grows until one is servable, as a real node's does
        let bundle = bundle_of(&mut node_a);
        adopts(bundle, "at the batch boundary");
    }

    /// A node that JUMPS by a bundle receives the producer's unfolded blocks and their folded parents with
    /// it, so its DAG reaches the certified tip and it folds them — and everything after — at the
    /// producer's ordinals. Built on two producers exchanging blocks, so the carried blocks name parents
    /// below the fold root (the case a single anchor cannot express).
    /// DIAGNOSTIC (ignored): what position does a JUMPED node stand on? Under the derived rule the base
    /// must equal the producer's position for the anchor, or every carried block folds one place off.
    #[test]
    #[ignore]
    fn diag_jump_base_position() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::{AdoptOutcome, FrontierSnapshot};
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut peer_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..8u64 {
            let ts = t0 + 60_000 * (k + 1);
            let a = produce(&mut node_a, ts, &format!("ja{k}"));
            let b = produce(&mut peer_b, ts + 7, &format!("jb{k}"));
            ingest(&mut node_a, &b, ts + 1_000, "A");
            ingest(&mut peer_b, &a, ts + 1_000, "B");
        }
        let bundle = bundle_of(&mut node_a); // the served bundle (census S-DRAFT-ADOPT)
        let anchor = Some(bundle.anchor_block.id());
        let certified = bundle.frontier.height / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        let a_anchor_ord = anchor.and_then(|id| node_a.da_record_ordinal(Node::da_record_id_for_block(&id, 0)));
        eprintln!(
            "[diag] producer A: served_seq={} spine_records={} anchor={:?} anchor_ordinal={:?} | bundle frontier records={}",
            node_a.served_seq(),
            node_a.spend_frontier_count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64,
            anchor.map(|i| i.to_hex()[..8].to_string()),
            a_anchor_ord,
            certified
        );
        let mut node_c = testnet_node();
        node_c.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(node_c.instant_sync(bundle), AdoptOutcome::Adopted(_)), "C adopts A's bundle");
        page_above_anchor(&mut node_c, &node_a);
        let c_anchor_ord = anchor.and_then(|id| node_c.da_record_ordinal(Node::da_record_id_for_block(&id, 0)));
        eprintln!(
            "[diag] jumped C: served_seq={} spine_records={} anchor_ordinal={:?} — base would be {}",
            node_c.served_seq(),
            node_c.spend_frontier_count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64,
            c_anchor_ord,
            node_c.served_seq().saturating_sub(1)
        );
        eprintln!(
            "[diag] the peer A's base for its next fold = {:?}; C must match it",
            a_anchor_ord
        );
    }

    fn a_node_that_jumps_by_a_bundle_folds_the_carried_blocks_at_the_producers_ordinals() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::{AdoptOutcome, FrontierSnapshot};
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut blocks: Vec<Block> = Vec::new();
        for k in 0..8u64 {
            let ts = t0 + 60_000 * (k + 1);
            let a = produce(&mut node_a, ts, &format!("ja{k}"));
            let b = produce(&mut node_b, ts + 7, &format!("jb{k}"));
            ingest(&mut node_a, &b, ts + 1_000, "A");
            ingest(&mut node_b, &a, ts + 1_000, "B");
            blocks.push(a);
            blocks.push(b);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "setup: the producers agree");
        let bundle = bundle_of(&mut node_a); // the served bundle (census S-DRAFT-ADOPT)
        assert!(
            !bundle.fold_carry.unfolded.is_empty() && !bundle.fold_carry.ancestors.is_empty(),
            "setup: the bundle carries unfolded blocks ({}) and the folded parents they name ({})",
            bundle.fold_carry.unfolded.len(),
            bundle.fold_carry.ancestors.len()
        );
        let mut node_c = testnet_node();
        node_c.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(node_c.instant_sync(bundle), AdoptOutcome::Adopted(_)), "C adopts A's bundle");
        page_above_anchor(&mut node_c, &node_a);
        assert_eq!(node_c.selected_tip(), node_a.selected_tip(), "C's DAG reaches A's certified tip");
        let mut later: Vec<Block> = Vec::new();
        for k in 8..16u64 {
            let ts = t0 + 60_000 * (k + 1);
            let a = produce(&mut node_a, ts, &format!("ja{k}"));
            ingest(&mut node_b, &a, ts + 1_000, "B");
            ingest(&mut node_c, &a, ts + 1_000, "C");
            later.push(a);
        }
        let carried_and_later: Vec<Block> = blocks[8..].iter().chain(later.iter()).cloned().collect();
        assert_same_fold(&node_a, &node_c, &carried_and_later, "the jumped node folds the carried blocks and the next ones like the producer");
        assert_same_fold(&node_a, &node_b, &carried_and_later, "the producers still agree");
    }

    /// ⛔⛔⛔ DB-358 RESIDUAL 3 — A NODE THAT JOINS BY A BUNDLE MUST NOT CREDIT A RE-SPEND CARRIED IN ITS WINDOW.
    /// A funds a note, spends it, and that spend FOLDS (its nullifier is in the certified state below the fold root). A
    /// then lays a RE-SPEND of the same note (past its own door — the rogue shape) and serves a bundle while that block
    /// is still UNFOLDED, so it rides the bundle's carried window. C adopts the bundle and keeps following. The
    /// re-spend's first contact is below C's anchor (the first-contact memo, an arrival-time fact, never saw it), so only
    /// a decision over the canonical fold-point set refuses it on C. Asserted on BOTH: neither holds the re-spend's
    /// output, AND C keeps folding the blocks after it like the producer (a node that waits forever has not answered).
    /// CALIBRATION: the bundle's carried window holds the re-spend block; A credited the first spend.
    #[test]
    fn db358_r3_a_bundle_joiner_does_not_credit_a_re_spend_carried_in_its_window_and_keeps_folding() {
        jump_with_a_carried_spend(true);
    }

    /// The CONTROL of the residual-3 pin: the SAME jump, but the carried block holds an HONEST spend of a different funded
    /// note. Both nodes must credit it and fold alike — so a divergence the re-spend case shows is the re-spend's, not
    /// the jump's or the carried spend's.
    #[test]
    fn db358_r3_control_a_bundle_joiner_folds_an_honest_spend_carried_in_its_window_like_the_producer() {
        jump_with_a_carried_spend(false);
    }

    /// The body of both residual-3 pins: `respend` = the carried block re-spends the note spent (and folded) before the
    /// bundle; otherwise it spends a different funded note.
    fn jump_with_a_carried_spend(respend: bool) {
        // ⛔ THE PRE-SWITCH MODE, NAMED (2026-11-26): these spends prove their input with a MEMBER LEG, which the constant chain refuses
        // ("a member leg under the constant chain", `member_carrier_verdict`: the absence wrapper is the membership), so under
        // `params::CANON_LIVE` they never fold ("CALIBRATION: A folded the first spend" failed). DB-358's first-spender rule is
        // pinned here in the pre-switch mode it was written for, on this thread with the switch off; under the switch the same
        // rule is the respend verdict over the canonical chain.
        crate::params::set_canon_live_for_test(Some(false));
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::{AdoptOutcome, FrontierSnapshot};
        use usdm_decider::poseidon2_compress::lanes_of;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let mut node_a = testnet_node();
        // Blocks to lay so a record FOLDS: this chain's own fold depth, plus the block itself — derived, never a guess;
        // and the blocks the joiner follows afterwards: two such spans, so every carried block folds behind it.
        let past_fold = node_a.params().record_fold_depth + 1;
        let follow = past_fold * 2;
        let t0 = genesis_ts(&node_a);
        let mut ts = t0;
        let mut step = |n: &mut Node, tag: &str| -> Block {
            ts += 60_000;
            produce(n, ts, tag)
        };
        let witness = |k: u64| usdm_decider::whir_rec_block::SpendValidityWitness {
            value_in: 1_000 + 100000, // §BR-14: the input funds the protocol fee
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x358, 0x3, 1, 1])),
            value_out: 1_000,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            lc_blind: lanes_of(&[0x358, k, 2, 2]),
            out0_value: 600,
            out0_opening: lanes_of(&[0x358, k, 3, 3]),
            out1_value: 400,
            out1_opening: lanes_of(&[0x358, k, 4, 4]),
        };
        let w1 = witness(1);
        // The re-spend reuses the first spend's INPUT (same key and value); the control spends a different funded note.
        let w2 = if respend {
            witness(2)
        } else {
            usdm_decider::whir_rec_block::SpendValidityWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x358, 0x4, 1, 1])), ..witness(2) }
        };
        // FUND the input(s) (one block, folded).
        let to_fund: Vec<&usdm_decider::whir_rec_block::SpendValidityWitness> = if respend { vec![&w1] } else { vec![&w1, &w2] };
        let _ = crate::node::tests::fund_inputs_for_test(&mut node_a, &mut [], &to_fund, t0 + 30_000);
        for k in 0..past_fold {
            step(&mut node_a, &format!("r3-fund-fold{k}"));
        }
        let spend_of = |n: &Node, w: &usdm_decider::whir_rec_block::SpendValidityWitness, label: &str| {
            let (blob, cms, nf, lc, _d) = crate::note_transition::prove_wallet_spend(w).expect("an honest validity proof");
            let mut notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
            for c in cms {
                let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
                note[..32].copy_from_slice(&b32(c));
                notes.extend_from_slice(&note);
            }
            let tags = crate::note_transition::test_spend_tag_list(nf, w, label);
            let mut tx = crate::node::tests::grind_tx(&blob, blob.len() as u32, tags, n.mempool().required_stamp_bits());
            tx.output_notes = notes;
            tx.note_clues = crate::note_transition::fixture_note_clues(&cms);
            tx.membership_leaf_commit = b32(lc);
            let input = crate::node::tests::note_of_witness_for_test(w).1;
            crate::node::tests::attach_member_leg_for_test(n, &mut tx, &input, w, nf, &cms);
            (tx, b32(cms[0]), b32(nf))
        };
        // SPEND #1, folded on A.
        let (tx1, out1, nf1) = spend_of(&node_a, &w1, "r3-first");
        node_a.ingest_tx_unverified(tx1).expect("A pools the first spend");
        step(&mut node_a, "r3-s1");
        for k in 0..past_fold {
            step(&mut node_a, &format!("r3-s1-fold{k}"));
        }
        assert!(node_a.holds_record_with_cm(&out1), "CALIBRATION: A folded the first spend and holds its output");
        // THE RE-SPEND of the same note, laid past A's own door, and still UNFOLDED when the bundle is served.
        let (tx2, out2, nf2) = spend_of(&node_a, &w2, "r3-again");
        assert_eq!(nf1 == nf2, respend, "CALIBRATION: the re-spend reveals the first spend's nullifier; the control a fresh one");
        node_a.ingest_tx_unverified(tx2).expect("the rogue producer pools the re-spend past its door");
        let s2 = step(&mut node_a, "r3-s2");
        assert!(
            s2.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == out2),
            "CALIBRATION: the re-spend block carries the re-spend's output"
        );
        // ⛔ the bundle a real node serves (census S-DRAFT-ADOPT), never a draft beside the serve path
        let bundle = bundle_of(&mut node_a);
        // G11b: the bundle is CONSTANT — it serves the fold anchor and carries no unfolded window, so the re-spend block
        // above the anchor reaches the joiner on the follow page (`page_above_anchor`), through the ordinary ingest door.
        assert!(
            bundle.fold_carry.unfolded.is_empty() && node_a.dag().get(&s2.id()).map_or(false, |h| {
                h.blue_score > node_a.dag().get(&bundle.tip_block.id()).map_or(u64::MAX, |t| t.blue_score)
            }),
            "CALIBRATION: the re-spend block sits ABOVE the constant bundle's served anchor (it rides the follow page)"
        );
        {
            let carried = &s2;
            eprintln!(
                "[db358-r3] the carried spend block: note_transition {} member_transition {} output_notes {} B oli_tags {} B",
                carried.note_transition.is_some(),
                carried.member_transition.is_some(),
                carried.output_notes.len(),
                carried.oli_tags.len()
            );
            let root = carried.header.output_notes_root;
            let nt_ok = carried
                .note_transition
                .as_ref()
                .and_then(|t| crate::note_transition::verify(t, &root, &carried.oli_tags))
                .is_some();
            let with_members = carried
                .note_transition
                .as_ref()
                .and_then(|t| {
                    crate::member_transition::spends_proven_with_members(t, carried.member_transition.as_ref(), &root, &carried.oli_tags)
                })
                .is_some();
            eprintln!("[db358-r3] the carried block's note transition verifies {nt_ok}; with its member proofs {with_members}");
        }
        let mut node_c = testnet_node();
        node_c.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(node_c.instant_sync(bundle), AdoptOutcome::Adopted(_)), "C adopts A's bundle");
        page_above_anchor(&mut node_c, &node_a);
        assert!(
            node_c.dag().get(&s2.id()).is_some(),
            "CALIBRATION: the re-spend block reached the joiner on the follow page"
        );
        // ⭐ THE WARM (2026-10-04, the fixture made faithful, part 2): a node that jumped holds the certified spent-set ROOT
        // and no view, so its fold cannot decide a carried spend against the set ("[respend] ⏸ DB-353 §13.6 … its tag's
        // shard is not held") — on a mesh it warms its view from a peer's key-ordered stream (DB-290, the pivot flow a
        // worker runs; the db290 pin's shape) before it can judge anything. MEASURED 2026-10-04 before this: with the band
        // relay alone C still waited at the carried spend in the control, and in the re-spend arm C's credit-at-adopt was
        // never judged. Here C pages A's stream exactly as the wire lane does and installs the healed view — through the
        // ONE shared helper every jumper fixture warms with (`Node::warm_view_from_for_test`, 2026-10-04), run by
        // `page_above_anchor` right after the adopt as the runtime's pivot worker does (db265, 2026-10-23).
        assert!(node_c.nf_view_held(), "CALIBRATION: the joiner's view warmed from the producer's honest stream after the adopt");
        let mut later: Vec<Block> = Vec::new();
        // ⭐ THE BAND RELAY (2026-10-03, the fixture made faithful): on a mesh, a step's proven band transition reaches the
        // joiner through the relay (`BandStep`, `Node::band_offer`) — the hub pin's band worker does exactly this, and
        // there the joiner keeps folding (d3036df). This fixture proved none, so C's fold waited at the carried spend
        // ("[respend] ⏸ DB-353 §13.6") by construction. A proves each awaiting step with its own view and offers the
        // SAME objects to C, as the relay would; the receipts are logged so a refusal names itself.
        let mut relayed = (0usize, std::collections::BTreeMap::<String, usize>::new());
        for k in 0..follow {
            let blk = step(&mut node_a, &format!("r3-after{k}"));
            let arrive = blk.header.timestamp + 1_000;
            ingest(&mut node_c, &blk, arrive, "C");
            for t in node_a.band_catch_up_for_test() {
                relayed.0 += 1;
                *relayed.1.entry(format!("{:?}", node_c.band_offer(t, false))).or_default() += 1;
            }
            later.push(blk);
        }
        eprintln!("[db358-r3] band steps A proved and relayed to C: {}; C's receipts: {:?}", relayed.0, relayed.1);
        // THE RECORD LANE (MEASURED 2026-10-05 20:40, pins-band.log): the bundle carries the spend block in its unfolded
        // window as a SHELL — `output_notes 0 B` — so C cannot lay that block's record and its fold re-placed ordinal 10 on
        // every pass while A reached 19 ("ordinals differ for 6 block(s)"). In production the joiner names the record on the
        // by-id lane and the peer serves the block body (`[da-fetch] … ADMITTED`); `serve_wants_from` is that lane in fixture
        // form: C's wants are answered from A's full blocks. Without it the pin judged the fixture, not the chain.
        let supply: Vec<Block> = std::iter::once(s2.clone()).chain(later.iter().cloned()).collect();
        let arrive = later.last().map(|b| b.header.timestamp + 2_000).unwrap_or(t0);
        serve_wants_from(&mut node_c, &supply, arrive);
        // The by-RECORD-ID lane (MEASURED 2026-10-05 21:01, pins-r3.log): the carried block is held with its proofs, so the
        // block lane has nothing to re-serve, and the fold names the RECORD it lacks (`want_held_block_record`) — in
        // production the peer answers from its ledger (`accept_fetched_record`); the helper is that door.
        for pass in 0..8 {
            let _ = node_c.fold_canonical_records();
            let wanted = node_c.wanted_record_ids();
            let landed = node_c.deliver_wanted_records_for_test(&node_a);
            eprintln!(
                "[db358-r3] record lane pass {pass}: C wants {} record id(s) {:?}; A serves {} of them; landed {landed}",
                wanted.len(),
                wanted.iter().map(|r| r % 100_000).collect::<Vec<_>>(),
                wanted.iter().filter(|r| node_a.ledger_record_for_rid(**r).is_some()).count()
            );
            if landed == 0 && !node_c.has_wanted_record_ids() {
                break;
            }
        }
        let _ = (node_a.fold_canonical_records(), node_c.fold_canonical_records());
        eprintln!(
            "[db358-r3] re-spend output held: A {} C {}",
            node_a.holds_record_with_cm(&out2),
            node_c.holds_record_with_cm(&out2)
        );
        if respend {
            assert!(!node_a.holds_record_with_cm(&out2), "⛔⛔⛔ DB-358: the PRODUCER credited a re-spend of a folded note");
            assert!(
                !node_c.holds_record_with_cm(&out2),
                "⛔⛔⛔ DB-358 RESIDUAL 3: a node that joined by a bundle credited a RE-SPEND carried in its window — the \
                 same note paid twice on the joiner"
            );
        } else {
            assert!(
                node_a.holds_record_with_cm(&out2) && node_c.holds_record_with_cm(&out2),
                "CONTROL: an honest spend carried in the window is credited on the producer AND the joiner"
            );
        }
        assert_same_fold(&node_a, &node_c, &later, "the joiner keeps folding after the carried spend like the producer");
    }

    /// Two nodes grow SEPARATE chains (each folds its own first blocks), then exchange everything: one
    /// selected chain wins, the other node rewinds what it folded below the fold root and re-folds in the
    /// canonical order — and after merge blocks both hold the same fold of the whole past.
    #[test]
    fn a_pair_whose_separate_chains_merge_rewinds_the_loser_and_folds_the_same_spine_on_both() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut a_chain: Vec<Block> = Vec::new();
        let mut b_chain: Vec<Block> = Vec::new();
        for k in 0..7u64 {
            let ts = t0 + 60_000 * (k + 1);
            a_chain.push(produce(&mut node_a, ts, &format!("a{k}")));
            b_chain.push(produce(&mut node_b, ts + 7, &format!("b{k}")));
        }
        assert!(node_a.served_seq() > 1 && node_b.served_seq() > 1, "setup: each folded its own prefix");
        for (k, b) in b_chain.iter().enumerate() {
            ingest(&mut node_a, b, t0 + 600_000 + k as u64 * 1_000, "A");
        }
        for (k, a) in a_chain.iter().enumerate() {
            ingest(&mut node_b, a, t0 + 600_000 + k as u64 * 1_000, "B");
        }
        let mut blocks: Vec<Block> = a_chain.iter().chain(b_chain.iter()).cloned().collect();
        assert_same_fold(&node_a, &node_b, &blocks, "after the exchange (one chain won)");
        for k in 0..7u64 {
            let ts = t0 + 700_000 + k * 60_000;
            let m = produce(&mut node_a, ts, &format!("merge{k}"));
            ingest(&mut node_b, &m, ts + 1_000, "B");
            blocks.push(m);
        }
        assert_same_fold(&node_a, &node_b, &blocks, "after the merge blocks folded both pasts");
        let unfolded = blocks
            .iter()
            .filter(|b| node_a.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0)).is_none())
            .count();
        assert!(unfolded <= 5, "only the blocks above the fold depth stay unfolded: {unfolded}");
    }
    /// DB-100b (run 102f, 2026-09-19): THE CARRY IS THE TIP'S OWN PAST ABOVE THE FOLD ROOT — never every
    /// unfolded block the node holds. Two separate 7-block chains are exchanged: the loser's blocks are
    /// side blocks no chain block has merged yet, and before this fix every one of them rode the checkpoint
    /// and the served bundle whole (node 1's bundle grew to 10 MB with the fork on the real nodes, on the
    /// same Tor lane the 32-body pages needed). Once a merge block names them, they are in the tip's past
    /// and ride until they fold — the bound is the tip's past, not "own blocks only".
    #[test]
    fn a_bundles_carry_holds_the_tips_own_past_above_the_fold_root_never_the_other_branch() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut a_chain: Vec<Block> = Vec::new();
        let mut b_chain: Vec<Block> = Vec::new();
        for k in 0..7u64 {
            let ts = t0 + 60_000 * (k + 1);
            a_chain.push(produce(&mut node_a, ts, &format!("a{k}")));
            b_chain.push(produce(&mut node_b, ts + 7, &format!("b{k}")));
        }
        for (k, b) in b_chain.iter().enumerate() {
            ingest(&mut node_a, b, t0 + 600_000 + k as u64 * 1_000, "A");
        }
        let tip = node_a.dag().selected_tip().expect("node_a stands on a tip");
        let a_won = a_chain.iter().any(|b| b.id() == tip);
        let (winner, loser) = if a_won { (&a_chain, &b_chain) } else { (&b_chain, &a_chain) };
        assert!(winner.iter().any(|b| b.id() == tip), "setup: the tip is the head of one exchanged chain");
        for b in loser {
            assert!(node_a.dag().get(&b.id()).is_some(), "setup: node_a HOLDS every block of the losing chain");
        }
        let carry = node_a.unfolded_carry();
        let carried: Vec<_> = carry.unfolded.iter().map(|(b, _, _)| b.id()).collect();
        // DB-117b (2026-09-20): a losing-branch block RIDES — as a header SHELL, never whole. DB-117 needs it
        // in the receiver's DAG (an accepted block the accumulator summed must be `Duplicate` on
        // re-delivery, not summed twice), and DB-100b's bound is about what it CARRIES: no body, no proofs.
        // A shell is header + tx ids; the 10 MB fork bundle of run 102f was the other branch's proofs.
        for b in loser {
            let Some((shell, _, _)) = carry.unfolded.iter().find(|(c, _, _)| c.id() == b.id()) else {
                panic!(
                    "a losing-branch block {:?} is missing from the carry — an accepted block the accumulator \
                     summed must reach the receiver's DAG so its re-delivery is Duplicate (DB-117)",
                    b.id()
                );
            };
            assert!(
                shell.pow_proof.is_empty()
                    && shell.output_notes.is_empty()
                    && shell.nullifier_proof.fold.is_empty()
                    && shell.note_transition.is_none(),
                "a losing-branch block {:?} rode the carry WHOLE although no chain block of the tip merged it — \
                 the bundle grows with the fork (run 102f: 1.6 → 10 MB) on the lane that must close it",
                b.id()
            );
        }
        let above_root: Vec<_> = winner
            .iter()
            .filter(|b| node_a.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0)).is_none())
            .map(|b| b.id())
            .collect();
        assert!(!above_root.is_empty(), "setup: the winner has unfolded blocks above the fold root");
        for id in &above_root {
            assert!(carried.contains(id), "a winner block above the fold root {id:?} is missing from the carry");
        }
        // A merge block names both branches: the loser's blocks are now in the tip's past and ride.
        let m = produce(&mut node_a, t0 + 700_000, "merge0");
        assert!(node_a.dag().get(&m.id()).is_some(), "setup: the merge block grafted");
        let carry2 = node_a.unfolded_carry();
        let carried2: Vec<_> = carry2.unfolded.iter().map(|(b, _, _)| b.id()).collect();
        assert!(
            loser.iter().any(|b| carried2.contains(&b.id())),
            "once a chain block merges the other branch its blocks are in the tip's past and must ride until \
             they fold — the bound is the tip's past, not this node's own blocks"
        );
        assert!(carried2.contains(&m.id()), "the merge block itself rides");
        // and the carry stays inside the body-ring bound whatever the DAG holds
        assert!(carry2.unfolded.len() <= crate::node::LIVE_LANE_DEPTH, "the carry is bounded by LIVE_LANE_DEPTH");
    }
    /// The LIVE runtime never calls `produce`/`ingest_block`: it mines off-lock and grafts through
    /// `graft_mined_own`, and ingests gossip through `ingest_block_preverified` — where a buffered
    /// descendant cascades in behind the block handed in. Gate 43 (2026-09-03, scratch PPeqTs): five
    /// DSYNC jumps, `[fold-carry]` 0 on both nodes, the jumper buffered 390 children and added 0 — the
    /// buffer behind `unfolded_carry` was only ever filled by the wrappers the runtime does not use.
    /// This pins the runtime's ingest path: handed-in AND cascaded blocks are carried until they fold.
    #[test]
    fn a_node_that_ingests_through_the_runtime_path_carries_every_admitted_block_including_the_cascade() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a) + 60_000;
        let mut blocks = Vec::new();
        for i in 0..6u64 {
            let b = node_a
                .produce(t0 + i * 60_000, Hash32::hash(format!("rt-{i}").as_bytes()), Hash32::hash(b"m"))
                .expect("node_a produces");
            blocks.push(b);
        }
        // node_b receives the LAST block first (it buffers), then the rest in order: the fifth's graft
        // cascades the sixth in behind it.
        let last = blocks.len() - 1;
        assert!(
            !matches!(
                node_b.ingest_block_preverified(blocks[last].clone(), t0 + 900_000),
                RelayOutcome::Added(_)
            ),
            "setup: the orphan buffers"
        );
        for (i, b) in blocks[..last].iter().enumerate() {
            assert!(
                matches!(
                    node_b.ingest_block_preverified(b.clone(), t0 + 900_100 + i as u64),
                    RelayOutcome::Added(_)
                ),
                "setup: block {i} grafts on the runtime path"
            );
        }
        assert!(node_b.dag().get(&blocks[last].id()).is_some(), "setup: the buffered last block cascaded in");
        // Fold depth 4: the tip minus four selected-parent steps is the fold root, so the first two
        // records folded and the four newest blocks are what a checkpoint or a bundle must carry.
        let depth = node_a.dag().record_fold_depth() as usize;
        let mut want: Vec<_> = blocks[blocks.len() - depth..].iter().map(|b| b.id()).collect();
        want.sort();
        for (who, n) in [("producer", &node_a), ("runtime ingester", &node_b)] {
            let carry = n.unfolded_carry();
            let mut ids: Vec<_> = carry.unfolded.iter().map(|(b, _, _)| b.id()).collect();
            ids.sort();
            assert_eq!(ids, want, "{who}: every admitted block above the fold root rides the carry (cascade included)");
        }
        assert_same_fold(&node_a, &node_b, &blocks, "runtime-path ingest");
    }

    /// A's certified bundle at this moment (its fold root as the anchor, the unfolded blocks as the carry).
    /// ⛔ A FIXTURE NEVER FALLS BEHIND THE DOOR (user 2026-11-26: "make sure the fixtures can never fall behind our code again and
    /// update automatically"). The bundle a pin hands a joiner is the one a real node SERVES: the node's own frozen bundle
    /// through `serve_join_bundle`, which runs the joiner's own join door before it serves (`production_bundle_for_test`). So
    /// whatever the door requires next, the fixture already carries it, because it IS the production bundle. Before, this built
    /// a DRAFT beside the serve path (`build_sync_bundle`, an empty join proof), and from 11/10 on the door refused it
    /// `AnchorArray`: 13 pins of this module stood red, and the joins, restarts and reorgs they cover went untested.
    /// Census S-DRAFT-ADOPT (scratchpad/secure.py, every landing) refuses a test that hands a draft to a joiner's adopt.
    /// The server may grow its chain until a bundle is servable (a freeze every 16 fold steps, 32 vouching blocks above it);
    /// `page_above_anchor` then brings those blocks to the joiner the way the runtime's follow lane does.
    fn bundle_of(node: &mut Node) -> crate::sync::SyncBundle {
        let ts = genesis_ts(node);
        node.production_bundle_for_test(ts, "fixture-served")
    }

    /// DB-223 / DB-274 P3 — NON-PROVING premise of the jumper pin below (seconds, debug profile): on a serving node the
    /// ring is complete and its newest entry is the ordinal of the bundle's fold root (`certified_fold_base_position`),
    /// which is what the draft requires before it ships the ring.
    #[test]
    fn db223_ring_a_servers_complete_ring_ends_at_its_fold_root_ordinal() {
        let mut node_a = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..12u64 {
            produce(&mut node_a, t0 + 60_000 * (k + 1), &format!("ringp{k}"));
        }
        let root = node_a.fold_anchor_block().expect("a fold root");
        let anchor_ordinal = node_a.certified_fold_base_position(&root);
        let ring = node_a.anchor_ring();
        eprintln!(
            "[db223-ring] fold root ordinal {anchor_ordinal:?}, ring {} entries {:?}..{:?}, complete {}",
            ring.len(),
            ring.first().map(|(o, _)| *o),
            ring.last().map(|(o, _)| *o),
            node_a.anchor_ring_is_complete()
        );
        assert!(node_a.anchor_ring_is_complete(), "the serving node's ring is complete");
        assert_eq!(ring.last().map(|(o, _)| *o), anchor_ordinal, "the ring's newest entry is the fold root's ordinal");
    }

    /// NON-PROVING DIAGNOSTIC (debug, seconds) for the jumper pin below: a fresh node's HEADER DOOR on a DRAFTED bundle
    /// (everything but the certificate step). The jumper pin measured `Unverified` for a ring-only tamper — the header
    /// door and the decider verify run BEFORE the certificate and read no ring — so this names what that door refuses.
    #[test]
    fn db223_ring_diag_a_fresh_node_admits_the_header_door_of_an_honest_drafted_bundle() {
        let mut node_a = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..12u64 {
            produce(&mut node_a, t0 + 60_000 * (k + 1), &format!("ringd{k}"));
        }
        let frontier = crate::sync::FrontierSnapshot {
            root: *node_a.note_frontier_root().as_bytes(),
            height: node_a.note_frontier_count(),
            peaks_hex: node_a.spend_frontier_peaks_hex(),
        };
        let draft = node_a.draft_sync_bundle(frontier).expect("a draft");
        let victim = testnet_node();
        let why = victim.bundle_blocks_refusal(&draft);
        eprintln!("[db223-ring-diag] fresh node's header door on an honest draft: {why:?}");
        assert!(why.is_none(), "⛔ a fresh node's header door refuses an HONEST bundle: {why:?}");
    }

    /// ⛔ DB-223 / DB-274 P3 — A JUMPER RECEIVES THE CANONICAL ANCHOR RING, CERTIFIED ENTRY BY ENTRY. The server ships
    /// the complete ring at its fold root and the jumper installs exactly it; a copy with ONE OLDER root forged is
    /// refused by the certificate gate, because the ring's digest rides the certified frontier input. The adopter's own
    /// install check covers only the newest entry, so without the binding this forgery would pass — and a jumper would
    /// then judge spends against a root the chain never had.
    /// TWO-PARTY-REVIEWED: A serves; C (honest jumper) and V (victim of the forged copy) adopt; the claim is what they hold.
    #[test]
    fn db223_ring_a_jumper_installs_the_servers_certified_ring_and_refuses_one_forged_older_root() {
        // The test bundle's DECIDER proof is a placeholder (the WHIR decider verify is pinned on its own), so every
        // adopter here accepts the decider leg — exactly as the other adopt pins in this file do — and the verdict under
        // test is the CERTIFICATE's. MEASURED 2026-09-29: without it the forged bundle stopped at the decider gate
        // (`Unverified`) and the certificate check this pin names was never reached.
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..12u64 {
            produce(&mut node_a, t0 + 60_000 * (k + 1), &format!("ring{k}"));
        }
        let bundle = bundle_of(&mut node_a);
        assert!(bundle.anchor_ring.len() >= 2, "CALIBRATION: the server holds and ships a complete multi-entry ring");
        assert_eq!(
            bundle.anchor_ring.last().map(|(o, _)| *o),
            Some(bundle.anchor_ordinal),
            "the shipped ring ends at the bundle's fold root"
        );
        // TAMPER: one OLDER root changed; the newest (the only entry the install check reads) is untouched.
        let mut forged = bundle.clone();
        forged.anchor_ring[0].1[0] ^= 1;
        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let verdict = victim.instant_sync(forged);
        assert!(
            matches!(verdict, crate::sync::AdoptOutcome::CertificateUnproven),
            "⛔ DB-223: a bundle whose anchor ring carries a forged older root was not refused by the certificate: {verdict:?}"
        );
        assert!(victim.anchor_ring().is_empty(), "the victim installed nothing from the forged bundle");
        let mut node_c = testnet_node();
        node_c.set_decider_verifier(Box::new(AcceptAll));
        let adopted = node_c.instant_sync(bundle.clone());
        assert!(matches!(adopted, crate::sync::AdoptOutcome::Adopted(_)), "C adopts A's honest bundle: {adopted:?}");
        // The jumper may fold carried blocks right after the adopt, so its ring can EXTEND past the bundle's: the
        // bundle's ring must be a prefix of it, entry for entry, and the whole must still be canonical.
        let held = node_c.anchor_ring();
        assert!(
            held.len() >= bundle.anchor_ring.len() && held[..bundle.anchor_ring.len()] == bundle.anchor_ring[..],
            "⛔ DB-223: the jumper does not hold the server's ring (held {} entries {:?}..{:?}, shipped {} entries {:?}..{:?})",
            held.len(),
            held.first().map(|(o, _)| *o),
            held.last().map(|(o, _)| *o),
            bundle.anchor_ring.len(),
            bundle.anchor_ring.first().map(|(o, _)| *o),
            bundle.anchor_ring.last().map(|(o, _)| *o)
        );
        assert!(node_c.anchor_ring_is_complete(), "the jumper's ring is the canonical ring at its fold position");
    }

    /// Two full nodes on a common chain, then a heavier branch that forks BELOW their fold root. Gate 44
    /// (2026-09-03, scratch N9yLYo): the rewind picked the deepest folded block on the new chain, so the
    /// spine left from ordinal 0 (207 records) on one node and from its floor (383) on the other. The
    /// fork point is the highest common chain block: everything below it keeps its ordinal.
    #[test]
    fn a_chain_move_below_the_fold_root_rewinds_to_the_fork_point_on_both_full_nodes_never_to_genesis() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut common: Vec<Block> = Vec::new();
        for k in 0..10u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("c{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            common.push(c);
        }
        assert_same_fold(&node_a, &node_b, &common, "setup: the common chain");
        let c2 = Node::da_record_id_for_block(&common[2].id(), 0);
        let c2_ord = node_a.da_record_ordinal(c2).expect("setup: c2 folded on A (depth 4 below the tip)");
        assert!(node_a.da_record_ordinal(Node::da_record_id_for_block(&common[5].id(), 0)).is_some(), "setup: A's fold root");
        // a third party holds only the first four blocks and builds a heavier branch from there
        let mut node_c = testnet_node();
        for c in &common[..4] {
            ingest(&mut node_c, c, t0 + 700_000, "C");
        }
        let mut branch: Vec<Block> = Vec::new();
        for k in 0..12u64 {
            branch.push(produce(&mut node_c, t0 + 60_000 * (11 + k), &format!("x{k}")));
        }
        for x in &branch {
            ingest(&mut node_a, x, t0 + 3_000_000, "A");
            ingest(&mut node_b, x, t0 + 3_000_000, "B");
        }
        assert_eq!(node_a.selected_tip(), Some(branch[11].id()), "setup: the branch is the selected chain");
        assert!(node_a.fold_reorgs_for_test() >= 1, "A's selected chain moved below its fold root");
        assert_eq!(
            node_a.da_record_ordinal(c2),
            Some(c2_ord),
            "a record below the fork point keeps its ordinal — the rewind stops at the fork point, not genesis"
        );
        assert!(!node_a.spine_stale_for_test() && !node_b.spine_stale_for_test(), "full nodes hold the DAG: never stale");
        let all: Vec<Block> = common.iter().chain(branch.iter()).cloned().collect();
        assert_same_fold(&node_a, &node_b, &all, "both full nodes re-fold from the fork point identically");
        assert_same_fold(&node_a, &node_c, &all, "and like the party that built the branch");
    }

    /// A node that folded its OWN blocks while the peer folded others holds ordinal claims the certified
    /// spine does not contain. Gate 44: the restarted node kept its claims at 165..168 against the peer's
    /// 165..192, treated those blocks as folded, skipped them in every later merge set and diverged for
    /// good. A certified adopt drops every local claim from the reconcile origin up.
    #[test]
    fn a_node_with_stale_local_claims_that_jumps_drops_them_and_folds_the_merged_blocks_like_the_producer() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let mut node_c = testnet_node();
        node_c.set_decider_verifier(Box::new(AcceptAll));
        let t0 = genesis_ts(&node_a);
        let mut common: Vec<Block> = Vec::new();
        for k in 0..4u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("c{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            ingest(&mut node_c, &c, ts + 1_000, "C");
            common.push(c);
        }
        // C goes its own way: six private blocks, the first two of which it folds at its own ordinals
        let mut private: Vec<Block> = Vec::new();
        for k in 0..6u64 {
            private.push(produce(&mut node_c, t0 + 300_000 + 60_000 * k, &format!("p{k}")));
        }
        let p0 = Node::da_record_id_for_block(&private[0].id(), 0);
        assert!(node_c.da_record_ordinal(p0).is_some(), "setup: C folded its first private block");
        // A and B run twelve more rounds without C
        for k in 4..16u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_b, ts, &format!("c{k}"));
            ingest(&mut node_a, &c, ts + 1_000, "A");
            common.push(c);
        }
        assert!(matches!(node_c.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "C jumps by A's bundle");
        page_above_anchor(&mut node_c, &node_a);
        // the served bundle may have grown A's chain past what B holds: B follows it by the same follow lane, as a real peer does
        page_above_anchor(&mut node_b, &node_a);
        assert!(
            node_c.da_record_ordinal(p0).is_none(),
            "C's own claim for a record the certified spine does not contain is gone"
        );
        // the peer's pages re-supply the certified prefix's coordinates (in-process: handed over directly)
        node_c.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
        // A merges C's private blocks and keeps producing; C follows, its pages arriving as A folds
        for p in &private {
            ingest(&mut node_a, p, t0 + 1_500_000, "A");
            ingest(&mut node_b, p, t0 + 1_500_000, "B");
        }
        let mut later: Vec<Block> = Vec::new();
        let mut refused_late_merge = false;
        for k in 0..8u64 {
            let y = produce(&mut node_a, t0 + 2_000_000 + 60_000 * k, &format!("y{k}"));
            ingest(&mut node_b, &y, t0 + 2_900_000, "B");
            // ⛔ DB-282 (re-posed 2026-09-27): A's first `y` merges C's PRE-ANCHOR private blocks — a late merge C cannot
            // place (its bounded past stops at the anchor, so before DB-282 it grafted `y` and scored it differently
            // from A; this test compared ordinals only and never saw that). C now refuses the merge as history, marks
            // its spine, and follows A through the certified re-anchor below (the runtime's stale-spine bundle ask).
            match node_c.ingest_block(y.clone(), t0 + 2_900_000) {
                RelayOutcome::Added(_) | RelayOutcome::Duplicate(_) => {}
                RelayOutcome::DagRejected(crate::dag::DagError::MergesPreAnchorHistory(_))
                | RelayOutcome::Buffered { .. } => refused_late_merge = true,
                other => panic!("C refuses the late merge as history, never as invalid: {other:?}"),
            }
            node_c.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
            later.push(y);
        }
        if refused_late_merge {
            assert!(
                node_c.spine_stale_for_test(),
                "⛔ DB-282: the refused late merge must mark C for a certified re-anchor"
            );
            assert!(
                matches!(node_c.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)),
                "C re-anchors on A's certified state"
            );
            page_above_anchor(&mut node_c, &node_a);
            node_c.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
        }
        // After the re-anchor the merged blocks sit in C's CERTIFIED prefix (no locally folded accumulator step), so C
        // follows A block by block again: these it folds itself, which gives the accumulator series a comparable span.
        for k in 0..8u64 {
            let z = produce(&mut node_a, t0 + 3_500_000 + 60_000 * k, &format!("z{k}"));
            ingest(&mut node_b, &z, t0 + 3_990_000, "B");
            ingest(&mut node_c, &z, t0 + 3_990_000, "C (following A after the re-anchor)");
            node_c.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
            later.push(z);
        }
        // Whatever C holds of A's later blocks, it scores exactly as A does (the property the ordinals alone never
        // checked).
        for y in &later {
            if let (Some(x), Some(z)) = (node_a.dag().get(&y.id()), node_c.dag().get(&y.id())) {
                assert_eq!(
                    (x.blue_score, x.blue_work),
                    (z.blue_score, z.blue_work),
                    "⛔ DB-282: C scores A's block {} differently from A",
                    &y.id().to_hex()[..8]
                );
            }
        }
        eprintln!("A rows: {:?}", node_a.ordinal_rows_for_test());
        eprintln!("C rows: {:?}", node_c.ordinal_rows_for_test());
        eprintln!("p records: {:?}", private.iter().map(|b| Node::da_record_id_for_block(&b.id(), 0)).collect::<Vec<_>>());
        eprintln!("y records: {:?}", later.iter().map(|b| Node::da_record_id_for_block(&b.id(), 0)).collect::<Vec<_>>());
        assert!(!node_c.spine_stale_for_test(), "C never conflicts with the producer's rows");
        assert!(node_a.da_record_ordinal(p0).is_some(), "setup: the producer folded C's first private block");
        let merged: Vec<Block> = private.iter().chain(later.iter()).cloned().collect();
        // The mesh lanes a jumper runs on a mesh (record lane, warm lane, band relay) — `Node::settle_mesh_lanes_for_test`.
        node_a.settle_mesh_lanes_for_test(&mut [&mut node_b, &mut node_c], merged.len() + 2);
        assert_same_fold(&node_a, &node_c, &merged, "the jumper folds its own merged blocks at the producer's ordinals");
        assert_same_fold(&node_a, &node_b, &merged, "the full nodes agree");
    }

    /// Ordinal 0 is genesis on every persisted node — the same block, record and row everywhere — and a
    /// peer's pages start at 1. Gate 45 (2026-09-03, scratch H90thk): a node that evicted its own row 0
    /// at its adopt carried a 1-row gap forever, served every roots run with a hole at 0, and its
    /// restarted peer refused those runs whole, starving regeneration and verification on that side.
    #[test]
    fn a_persisted_node_keeps_its_genesis_row_through_a_certified_adopt() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let dir = std::env::temp_dir().join(format!("musd-genesis-row-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = node_b.enable_persist(dir.join("state.snap")); // fresh start: files the genesis record
        let genesis = node_b.dag().genesis().expect("genesis");
        let rid0 = Node::da_record_id_for_block(&genesis, 0);
        assert_eq!(node_b.da_record_ordinal(rid0), Some(0), "setup: genesis sits at ordinal 0 on the persisted node");
        let t0 = genesis_ts(&node_a);
        for k in 0..12u64 {
            produce(&mut node_a, t0 + 60_000 * (k + 1), &format!("g{k}"));
        }
        node_b.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B adopts A's bundle");
        page_above_anchor(&mut node_b, &node_a);
        assert_eq!(
            node_b.da_record_ordinal(rid0),
            Some(0),
            "the genesis row survives the adopt — it is the one row no page will ever re-supply"
        );
        assert!(node_b.da_record_notes(rid0).is_some(), "and the genesis record's bytes are still served");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔⛔⛔ DB-270 R3 (lane-dsol-zkvm's review §1, "the same conflation, on EVERY node") — a fold-reorg re-buffers
    /// evicted window blocks into the unfolded set (`rewind_fold_to_common` → `rebuffer_unfolded_blocks`) without
    /// taking them out of the window, and the span chains the two sets without dedup. A node that NEVER jumped then
    /// holds a span its own accumulator does not count, and refuses its own carriers until the blocks re-fold.
    #[test]
    fn db270_after_a_fold_reorg_the_span_holds_what_the_accumulator_counts() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let t0 = genesis_ts(&node_a);
        for k in 0..10u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_a, ts, &format!("c{k}"));
            ingest(&mut node_b, &c, ts + 1_000, "B");
        }
        for k in 0..40u64 {
            produce(&mut node_a, t0 + 60_000 * (11 + k), &format!("a{k}"));
        }
        let mut b_only: Vec<Block> = Vec::new();
        for k in 0..60u64 {
            b_only.push(produce(&mut node_b, t0 + 60_000 * (11 + k) + 20_000, &format!("b{k}")));
        }
        for b in &b_only {
            ingest(&mut node_a, b, t0 + 9_000_000, "A");
        }
        assert!(node_a.fold_reorgs_for_test() >= 1, "CONTROL: A rewound its fold to the fork point");
        let (held, counted) =
            (node_a.nf_fold_inputs_len() as u64, node_a.nf_fold_seq().saturating_sub(node_a.nf_fold_base().1));
        assert_eq!(
            held, counted,
            "⛔⛔⛔ DB-270 R3: after a fold-reorg A's span holds {held} block(s) while its accumulator counts {counted} \
             above the base — re-buffered window blocks are counted twice"
        );
        let nf = *crate::hash::Hash32::hash(b"db270-r3-never-spent").as_bytes();
        assert!(
            node_a.self_build_spend_carrier(&[nf]).is_some(),
            "⛔⛔⛔ DB-270 R3: after a fold-reorg the node cannot build its own spend's carrier"
        );
    }

    /// ⛔⛔ §POLES (lane a, 2026-10-25) — A FOLD ROOT THAT DROPS BELOW THE FOLD TIP LEAVES NO TRACE OF WHAT IT UN-FOLDED.
    /// The 4-node launch census (census4-rw1.log): the selected chain re-formed with denser merge sets, so the block
    /// `record_fold_depth` chain steps below the tip became the fold tip's own parent — `[fold-reorg] 1 record(s) from
    /// ordinal 75 … fork point 779660fa` with nothing to re-fold. The three nodes that had folded ordinal 75 kept its
    /// anchor witness, its window entry, its sidecar cursor and its membership tip, and held one journal entry fewer
    /// than the node that never folded it: 12 DIFFERS. Reduced here: two observers of one producer, A folding at depth
    /// 4 until its root drops one block (depth 5 — the same `rewind_fold_to_common` path, no re-fold above it), B at
    /// depth 5 all along. Past `SPINE_RING_LEN` records so the journals are full. Every replicated field must agree.
    /// TWO-PARTY-REVIEWED: A and B are independent `Node`s grafting the same producer's blocks; the assertion compares
    /// what each HOLDS, field by field.
    #[test]
    fn a_fold_root_that_drops_below_the_fold_tip_leaves_the_node_where_a_never_folded_peer_stands() {
        // ⛔ A FIXTURE NEVER FALLS BEHIND THE CODE (2026-11-26): the fold depth is DERIVED from the chain's own step since A-F60/A-F96
        // (`dag::fold_depth_for(param, step) = clamp(ceil(FOLD_SETTLE_MS / step), FOLD_DEPTH_MIN, param)`), and a parameter above
        // FOLD_DEPTH_MIN (2) at this pin's 60 s step folds at 2 whatever it is: depth 4 and depth 5 folded alike, so the calibration
        // "A holds one record more than B" could not hold. Parameters at or below FOLD_DEPTH_MIN are used as given, so the pin
        // states its two depths there: A at 1, B at 2.
        let depth_of = |n: &mut Node, d: u64| {
            let mut p = n.params().clone();
            p.record_fold_depth = d;
            n.set_params(p);
        };
        let mut prod = testnet_node();
        let mut a = testnet_node();
        let mut b = testnet_node();
        depth_of(&mut a, 1);
        depth_of(&mut b, 2);
        let t0 = genesis_ts(&prod);
        let n = Node::SPINE_RING_LEN as u64 + 12;
        for k in 0..n {
            let ts = t0 + 60_000 * (k + 1);
            let blk = produce(&mut prod, ts, &format!("drop{k}"));
            ingest(&mut a, &blk, ts + 1_000, "A");
            ingest(&mut b, &blk, ts + 1_000, "B");
        }
        assert_eq!(a.served_seq(), b.served_seq() + 1, "CALIBRATION: A (depth 1) holds one record more than B (depth 2)");
        let reorgs = a.fold_reorgs_for_test();
        depth_of(&mut a, 2);
        let _ = a.fold_canonical_records();
        assert!(a.fold_reorgs_for_test() > reorgs, "CALIBRATION: A's fold root dropped below its fold tip (a fold reorg)");
        assert_eq!(a.served_seq(), b.served_seq(), "CALIBRATION: A and B now hold the same records");
        let local: Vec<&str> = crate::node::restart_census_stand_ins::NODE_LOCAL.iter().map(|(f, _)| *f).collect();
        let unordered: Vec<&str> = crate::node::restart_census_stand_ins::UNORDERED.iter().map(|(f, _)| *f).collect();
        let by_statement: Vec<&str> =
            crate::node::restart_census_stand_ins::BY_STATEMENT.iter().map(|(f, _)| *f).collect();
        let census = |x: &Node| {
            let mut v = x.restart_census_digest();
            for (f, d) in x.restart_census_stand_ins() {
                if let Some(slot) = v.iter_mut().find(|(g, _)| *g == f) {
                    slot.1 = Some(d);
                }
            }
            v
        };
        let set = |x: &Node, f: &str| {
            crate::node::restart_census_fields::multiset_digest(&|out| x.census_field_render(f, out))
        };
        let stmt = |x: &Node, f: &str| {
            crate::node::restart_census_fields::multiset_digest(&|out| x.census_field_render_statement(f, out))
        };
        let (ca, cb) = (census(&a), census(&b));
        let differs: Vec<&str> = ca
            .iter()
            .zip(cb.iter())
            .filter(|(x, y)| {
                !local.contains(&x.0)
                    && x.1.map(|d| d.0) != y.1.map(|d| d.0)
                    && !(unordered.contains(&x.0) && set(&a, x.0) == set(&b, x.0))
                    && !(by_statement.contains(&x.0) && stmt(&a, x.0) == stmt(&b, x.0))
            })
            .map(|(x, _)| x.0)
            .collect();
        assert!(
            differs.is_empty(),
            "⛔ after its fold root dropped one block, A is not where a node that never folded that record stands: {} \
             field(s) differ: {differs:?}",
            differs.len()
        );
    }

    /// ⛔ §CERT (lane a 2026-10-26) — A FOLD ROOT THAT DROPS NEVER STRANDS THE SERVED CERTIFICATE. The served position is
    /// the fold root (`served_tip`), so a fold reorg serves a LIGHTER position than the certificate last certified. The
    /// step's work delta was `blue_work − certified_blue_work`, saturating to 0 there, and the install still moved the
    /// cursor down: the certificate's work and the cursor parted for good and every later bundle declared a work its
    /// certificate did not attest. MEASURED (certify 2026-10-25, sim-20261025-171545.log): the joiner's 23 re-anchor
    /// adopts from ordinal 414 on all answered `CertificateUnproven`; it never folded past 495 and T3's bond never
    /// reached it. The claim is what a fresh adopter does with the bundles the reorged node serves.
    /// TWO-PARTY-REVIEWED: A serves; V adopts; the verdict is V's.
    #[test]
    fn a_bundle_served_after_the_fold_root_dropped_still_carries_a_certificate_an_adopter_accepts() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        // ⛔ A FIXTURE NEVER FALLS BEHIND THE DOOR: what A serves is what a real node serves (`serve_join_bundle`, the frozen
        // bundles checked by the joiner's own door), never a draft beside it (census S-DRAFT-ADOPT)
        let serve = |node: &mut Node| node.serve_join_bundle().and_then(|w| crate::sync::SyncBundle::from_wire(&w));
        let adopt = |b: crate::sync::SyncBundle| {
            let mut v = testnet_node();
            v.set_decider_verifier(Box::new(AcceptAll));
            v.instant_sync(b)
        };
        // the fold depth is derived from the chain's step (`dag::fold_depth_for`): above FOLD_DEPTH_MIN a 60 s step folds at 2
        // whatever the parameter, so the pin's drop is stated where parameters are used as given: depth 1, then 2
        let depth_of = |n: &mut Node, d: u64| {
            let mut p = n.params().clone();
            p.record_fold_depth = d;
            n.set_params(p);
        };
        let mut prod = testnet_node();
        let mut a = testnet_node();
        depth_of(&mut a, 1);
        let t0 = genesis_ts(&prod);
        let n = Node::SPINE_RING_LEN as u64 + 12;
        for k in 0..n {
            let ts = t0 + 60_000 * (k + 1);
            let blk = produce(&mut prod, ts, &format!("cert{k}"));
            ingest(&mut a, &blk, ts + 1_000, "A");
        }
        let first = serve(&mut a).expect("CALIBRATION: A serves a bundle at its depth-1 fold root");
        assert!(matches!(adopt(first), AdoptOutcome::Adopted(_)), "CALIBRATION: a fresh node adopts A's first bundle");
        let reorgs = a.fold_reorgs_for_test();
        depth_of(&mut a, 2);
        let _ = a.fold_canonical_records();
        assert!(a.fold_reorgs_for_test() > reorgs, "CALIBRATION: A's fold root dropped below its fold tip (a fold reorg)");
        // at the lighter position: a serve may be declined, but a bundle served must be one an adopter accepts
        if let Some(mid) = serve(&mut a) {
            let v = adopt(mid);
            assert!(
                !matches!(v, AdoptOutcome::CertificateUnproven),
                "⛔ A served a bundle at its dropped fold root whose certificate does not certify it: {v:?}"
            );
        }
        for k in n..n + 4 {
            let ts = t0 + 60_000 * (k + 1);
            let blk = produce(&mut prod, ts, &format!("cert{k}"));
            ingest(&mut a, &blk, ts + 1_000, "A");
        }
        let later = serve(&mut a).expect("A serves once its fold root is past the position it last certified");
        let v = adopt(later);
        assert!(
            matches!(v, AdoptOutcome::Adopted(_)),
            "⛔ after a fold reorg A's later bundle is refused by a fresh adopter: {v:?}"
        );
    }

    #[test]
    fn a_node_holding_the_peers_orphans_adopts_the_peers_certified_state_despite_its_own_heavier_tip() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let t0 = genesis_ts(&node_a);
        let mut common: Vec<Block> = Vec::new();
        for k in 0..10u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_a, ts, &format!("c{k}"));
            ingest(&mut node_b, &c, ts + 1_000, "B");
            common.push(c);
        }
        // A mines 40 blocks B never sees (B was down); B, back up, mines 60 alone on its old tip
        let mut a_only: Vec<Block> = Vec::new();
        for k in 0..40u64 {
            a_only.push(produce(&mut node_a, t0 + 60_000 * (11 + k), &format!("a{k}")));
        }
        let mut b_only: Vec<Block> = Vec::new();
        for k in 0..60u64 {
            b_only.push(produce(&mut node_b, t0 + 60_000 * (11 + k) + 20_000, &format!("b{k}")));
        }
        let b_work = node_b.dag().get(&node_b.selected_tip().unwrap()).map(|n| n.blue_work).unwrap();
        // A's newest block reaches B by gossip: its parent is one of the 40 B never saw — an orphan
        assert!(
            !matches!(node_b.ingest_block(a_only[39].clone(), t0 + 9_000_000), RelayOutcome::Added(_)),
            "setup: the peer's newest block buffers on B (parent unknown)"
        );
        let bundle = bundle_of(&mut node_a);
        assert!(bundle.blue_work < b_work, "setup: B's own tip outweighs A's certified tip in B's partial view");
        assert!(
            matches!(node_b.instant_sync(bundle), AdoptOutcome::Adopted(_)),
            "B adopts: it holds the peer's orphans, so its own weight is a partial count"
        );
        page_above_anchor(&mut node_b, &node_a);
        // B still holds its own heavier branch, so its selected chain stays there and moves below the
        // certified prefix it just adopted: it goes stale rather than re-fold shells. A merges B's branch
        // (a real rewind to the fork point on the full node) and serves the certified state B then takes.
        assert!(node_b.spine_stale_for_test(), "B's own branch is heavier: its chain leaves the adopted prefix, so it stops folding");
        for b in &b_only {
            ingest(&mut node_a, b, t0 + 9_000_000, "A");
        }
        assert!(node_a.fold_reorgs_for_test() >= 1, "A rewinds to the fork point to take B's heavier branch");
        assert!(
            matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)),
            "B takes A's certified state on the merged chain"
        );
        page_above_anchor(&mut node_b, &node_a);
        assert!(!node_b.spine_stale_for_test(), "re-anchored on the merged chain");
        node_b.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
        let mut later: Vec<Block> = Vec::new();
        for k in 0..40u64 {
            let y = produce(&mut node_a, t0 + 10_000_000 + 60_000 * k, &format!("y{k}"));
            // DB-100b: the certified bundle carried the merged chain's past only; the 40 blocks A mined while
            // B was down reach B by the block lanes when a merge block names them (in-process: handed over).
            ingest_with_lanes(&mut node_b, &y, t0 + 20_000_000, "B", &a_only);
            node_b.adopt_rows_for_test(&node_a.ordinal_rows_for_test());
            later.push(y);
        }
        let mut merged: Vec<Block> = b_only.iter().chain(later.iter()).cloned().collect();
        // The mesh lanes a jumper runs on a mesh (record lane, shell-body lane, re-anchor, warm lane, band relay) —
        // `Node::settle_mesh_lanes_for_test`. A body A folded and dropped reaches B only as the certified bundle that
        // covers it (DB-4 / DB-274 P5, measured lane a 2026-10-26: B's fold waited at 106 for it, A at 147).
        node_a.settle_mesh_lanes_for_test(&mut [&mut node_b], merged.len() + 2);
        // …and from there B folds the next blocks ITSELF, at the producer's ordinals with the producer's accumulator
        // steps (a jump holds no step below its anchor: these are the steps both sides fold).
        for k in 0..8u64 {
            let ts = t0 + 30_000_000 + 60_000 * k;
            let z = produce(&mut node_a, ts, &format!("z{k}"));
            ingest_with_lanes(&mut node_b, &z, ts + 1_000, "B", &merged);
            merged.push(z);
        }
        node_a.settle_mesh_lanes_for_test(&mut [&mut node_b], merged.len() + 2);
        assert_same_fold(&node_a, &node_b, &merged, "the re-anchored node folds the merged branch like the producer");
    }

    /// Pages are uncertified: a diverged peer pages its own claims. They fill slots this node has no
    /// claim for and never displace one it has, and a hint that disagrees with this node's canonical
    /// order is dropped — never a reason to go stale. Gate 45: the healthy node paged from its restarted
    /// peer, took the peer's divergent rows below its own counter and corrupted its own index.
    #[test]
    fn a_diverged_peers_page_rows_never_displace_a_healthy_nodes_claims_or_stall_its_fold() {
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let mut node_c = testnet_node();
        let t0 = genesis_ts(&node_a);
        let mut common: Vec<Block> = Vec::new();
        for k in 0..8u64 {
            let ts = t0 + 60_000 * (k + 1);
            let c = produce(&mut node_a, ts, &format!("c{k}"));
            ingest(&mut node_b, &c, ts + 1_000, "B");
            ingest(&mut node_c, &c, ts + 1_000, "C");
            common.push(c);
        }
        // C diverges: twelve blocks of its own, folded at its own ordinals
        for k in 0..12u64 {
            produce(&mut node_c, t0 + 60_000 * (9 + k) + 30_000, &format!("x{k}"));
        }
        // A and B carry on together
        let mut later: Vec<Block> = Vec::new();
        for k in 0..12u64 {
            let y = produce(&mut node_a, t0 + 60_000 * (9 + k), &format!("y{k}"));
            ingest(&mut node_b, &y, t0 + 5_000_000, "B");
            later.push(y);
        }
        let rows_before = node_a.ordinal_rows_for_test();
        let count_before = node_a.note_frontier_count();
        // C's pages reach A (a diverged peer answering A's asks)
        node_a.adopt_rows_for_test(&node_c.ordinal_rows_for_test());
        assert_eq!(node_a.ordinal_rows_for_test(), rows_before, "A's claims are untouched by a diverged peer's rows");
        assert!(!node_a.spine_stale_for_test(), "a page never makes a healthy node stale");
        assert_eq!(node_a.note_frontier_count(), count_before, "A's spine is untouched");
        // A keeps folding with B exactly as before
        for k in 12..20u64 {
            let y = produce(&mut node_a, t0 + 60_000 * (9 + k), &format!("y{k}"));
            ingest(&mut node_b, &y, t0 + 5_000_000, "B");
            later.push(y);
        }
        let all: Vec<Block> = common.iter().chain(later.iter()).cloned().collect();
        assert_same_fold(&node_a, &node_b, &all, "the healthy pair agrees after the diverged peer's pages");
        assert!(!node_a.spine_stale_for_test());
    }

    /// Replay of the restart schedule the fuzz search flags: three parties, each round every party
    /// produces, one owed block is delivered, one party restarts through its checkpoint; then everything
    /// owed is delivered. Prints the first round at which a delivery is REFUSED (the block set splits)
    /// with each party's difficulty samples for that block's selected parent.
    #[test]
    #[ignore]
    fn diag_restart_rounds_first_refusal() {
        let parties = 3usize;
        let mut nodes: Vec<Node> = (0..parties).map(|_| testnet_node()).collect();
        let t0 = genesis_ts(&nodes[0]);
        let spacing = nodes[0].params().target_spacing_ms;
        let mut now = t0 + 60_000;
        let mut owed: Vec<(usize, Block)> = Vec::new();
        let mut rng: u64 = 0xD1B5_4A32_D192_ED03 | 1;
        let mut rand = |m: usize| -> usize { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; if m == 0 { 0 } else { (rng >> 3) as usize % m } };
        let samples = |n: &Node, tip: &crate::block::BlockId| -> Vec<crate::dag::DaaSample> {
            let dag = n.dag();
            let want = dag.params().daa_sample_len as usize;
            let mut out = Vec::new();
            let mut cur = Some(*tip);
            while let Some(c) = cur {
                if out.len() >= want { break; }
                match dag.get(&c) {
                    Some(b) => {
                        out.push((b.header.timestamp, b.header.work, b.blue_score));
                        cur = b.selected_parent;
                        if cur.is_none() {
                            if let Some(w) = dag.window_below(&c) {
                                for s in w.iter() { if out.len() >= want { break; } out.push(*s); }
                            }
                        }
                    }
                    None => { out.push((0, 0, 0)); break; }
                }
            }
            out
        };
        for round in 0..10 {
            for i in 0..parties {
                now += spacing;
                if let Some(b) = nodes[i].produce(now, Hash32::hash(format!("r{round}-{i}").as_bytes()), Hash32::hash(b"m")) {
                    for j in 0..parties { if j != i { owed.push((j, b.clone())); } }
                }
            }
            let k = rand(8);
            if !owed.is_empty() {
                let k = k % owed.len();
                let (to, blk) = owed.remove(k);
                now += 1;
                if !matches!(nodes[to].ingest_block(blk.clone(), now), RelayOutcome::Added(_)) { owed.push((to, blk)); }
            }
            let r = round % parties;
            if let Some(snap) = nodes[r].export_snapshot() {
                let mut fresh = testnet_node();
                assert!(fresh.restore_snapshot(snap), "restore");
                let g = fresh.dag().genesis();
                let gv = g.and_then(|g| fresh.dag().get(&g).map(|n| (n.header.timestamp, n.header.work, n.selected_parent.is_some(), fresh.dag().window_below(&g).map(|w| w.len()))));
                let anchor = fresh.fold_anchor();
                eprintln!("RESTART round {round} party {r}: genesis present {:?} view {:?}; anchor {:?}; tips {}", g.map(|x| x.to_hex()[..8].to_string()), gv, anchor.map(|(a, s)| (a.to_hex()[..8].to_string(), s)), fresh.dag().tips().len());
                nodes[r] = fresh;
            }
            if round < 9 {
                continue; // mirror the schedule search: everything owed is delivered only at the end
            }
            // drain
            let mut passes = 0;
            while !owed.is_empty() && passes < 2_000 {
                let (to, blk) = owed.remove(0);
                now += 1;
                let out = nodes[to].ingest_block(blk.clone(), now);
                if !matches!(out, RelayOutcome::Added(_) | RelayOutcome::Duplicate(_)) {
                    if let RelayOutcome::Invalid(_) = out {
                        let sp = blk.header.parents.iter().max_by_key(|p| nodes[to].dag().get(p).map(|n| (n.blue_work, **p))).copied().unwrap();
                        eprintln!("ROUND {round} (restarted party {r}): party {to} REFUSED block {} => {:?}", &blk.id().to_hex()[..8], out);
                        for (i, n) in nodes.iter().enumerate() {
                            let d = n.dag();
                            let v = d.get(&sp).map(|x| (x.header.timestamp, x.header.work, x.blue_score, x.selected_parent.map(|p| p.to_hex()[..8].to_string()), d.window_below(&sp).map(|w| w.len())));
                            let anc = n.fold_anchor().map(|(a, s)| (a.to_hex()[..8].to_string(), s, d.window_below(&a).map(|w| w.len())));
                            eprintln!("  party {i}: sp {} view {:?} | anchor {:?} | samples(sp)={:?}", &sp.to_hex()[..8], v, anc, samples(n, &sp));
                        }
                        return;
                    }
                    owed.push((to, blk));
                }
                passes += 1;
            }
        }
        let tips: Vec<Option<crate::block::BlockId>> = nodes.iter().map(|n| n.selected_tip()).collect();
        eprintln!("no refusal; owed left {}; tips {:?}", owed.len(), tips.iter().map(|t| t.map(|x| x.to_hex()[..8].to_string())).collect::<Vec<_>>());
        if tips.iter().any(|t| *t != tips[0]) {
            for (i, n) in nodes.iter().enumerate() {
                let d = n.dag();
                let view = |t: &crate::block::BlockId| d.get(t).map(|x| (x.blue_work, x.blue_score, x.selected_parent.map(|p| p.to_hex()[..8].to_string()))).map(|v| format!("{v:?}")).unwrap_or("ABSENT".into());
                eprintln!("  party {i}: {}", tips.iter().map(|t| format!("{}={}", &t.unwrap().to_hex()[..8], view(&t.unwrap()))).collect::<Vec<_>>().join(" | "));
                eprintln!("    tips set {:?} holds {} blocks", d.tips().iter().map(|x| x.to_hex()[..8].to_string()).collect::<Vec<_>>(), d.len());
            }
        }
    }


    /// ⛔⛔⛔ DB-161 — A NODE WHOSE FOLD IS BEHIND STILL SERVES A CERTIFIED BUNDLE.
    ///
    /// THE HALT THIS PINS, measured on the live pair 2026-09-22: 27780 sat 79,435 blocks behind and fired
    /// `sync_ask()` 6,085 times; 28901, its ONLY peer, answered 6,855 times with *"not serving a bundle: N
    /// unfolded block(s) — this node's fold is behind; a caught-up peer serves"*. There was no caught-up
    /// peer. `Adopted` = 0, both heights frozen, and the gap grew all night.
    ///
    /// DB-139's remedy for a bundle that grew with the fold lag was to REFUSE past `LIVE_LANE_DEPTH`. A
    /// refusal is not a fix for a growth axis: it turns a SIZE bug into a LIVENESS bug, and this one failed
    /// closed on CHAIN PROGRESS, which the no-halts cardinal forbids. The serve now falls back to the
    /// node's own FOLD ROOT — the highest position it has folded through and can therefore cover
    /// completely — with the lag term of the carry dropped.
    ///
    /// Drives a REAL fold-behind node: `LIVE_LANE_DEPTH + 1` blocks ingested and never folded.
    #[test]
    fn a_fold_behind_node_still_serves_a_certified_bundle_anchored_at_its_fold_root() {
        let mut producer = testnet_node();
        let mut lagging = testnet_node();
        let t0 = genesis_ts(&producer) + 60_000;

        // A few REAL blocks, ingested so the laggard has a genuine DAG and a fold root…
        let mut seed = Vec::new();
        for i in 0..4u64 {
            let b = produce(&mut producer, t0 + i * 1_000, "db161");
            lagging.ingest_block(b.clone(), t0 + i * 1_000 + 500);
            seed.push(b);
        }
        let _ = lagging.fold_canonical_records();
        // …then the fold lag itself. The gate refused on `unfolded_blocks.len()`, so that counter IS the
        // condition under test; mining past 512 takes ~45 minutes (measured: 300 blocks in 25 min), which
        // is not a unit pin. These are real blocks the laggard already holds, pushed to drive the count.
        while lagging.unfolded_blocks_len_for_test() <= crate::node::LIVE_LANE_DEPTH {
            for b in &seed {
                lagging.push_unfolded_for_test(b.clone());
            }
        }
        assert!(
            lagging.unfolded_blocks_len_for_test() > crate::node::LIVE_LANE_DEPTH,
            "PRECONDITION: the laggard's fold must be behind by more than the carry's reach, or this pin \
             is not exercising the gate at all — it holds {} unfolded",
            lagging.unfolded_blocks_len_for_test()
        );

        // ⛔ THE REGRESSION: this used to be `None`, and a mesh where every node's fold is behind then had
        // nobody able to serve the one lane that could repair it.
        let frontier = lagging.frontier_snapshot_for_test();
        let bundle = lagging
            .build_sync_bundle(Vec::new(), frontier)
            .expect(
                "⛔ A FOLD-BEHIND NODE REFUSED TO SERVE A BUNDLE. On a mesh where no peer is caught up \
                 that refusal is a permanent chain halt — measured live on 2026-09-22, 6,855 refusals \
                 against 6,085 asks with zero adopts.",
            );

        // It serves the position it can FULLY COVER: its own fold root, with no lag term in the carry.
        let root = lagging.fold_anchor_block().expect("a folded node has a fold root");
        assert_eq!(
            bundle.tip_block.id(),
            root,
            "past the carry's reach the served position must be this node's FOLD ROOT — the highest one it \
             has folded through — never a tip it cannot cover"
        );
        assert!(
            bundle.fold_carry.unfolded.is_empty(),
            "⛔ the carry still holds {} unfolded block(s) — that is the O(fold lag) term DB-139 measured \
             at 26 MB, and serving the fold root means there is nothing above it to carry",
            bundle.fold_carry.unfolded.len()
        );

        // NON-VACUITY: a CAUGHT-UP node still serves its real tip, so the fallback is a fallback and not
        // the new normal.
        let ftip = producer.frontier_snapshot_for_test();
        let caught_up = producer
            .build_sync_bundle(Vec::new(), ftip)
            .expect("a caught-up node serves");
        // G11b (2026-10-22): a caught-up node serves its certified FOLD ROOT too — the one served position at
        // every lag (Kaspa's pruning point); the blocks above it ride the follow-page lane, never the bundle.
        assert_eq!(
            caught_up.tip_block.id(),
            producer.served_tip().expect("a served position"),
            "a node whose fold is current serves the one position `served_tip` names"
        );
        assert!(caught_up.fold_carry.unfolded.is_empty(), "the bundle never carries the unfolded backlog (G11b)");
        eprintln!(
            "[db161] laggard held {} unfolded and served its fold root; the caught-up node served its tip",
            lagging.unfolded_blocks_len_for_test()
        );
    }

    /// G11b (2026-10-22, lane b; readiness T1 the join + T3 launch leg 1 + NO-GROWTH): THE SYNC BUNDLE IS CONSTANT.
    /// `fold_carry.unfolded` carried the WHOLE BODY of every unfolded block up to LIVE_LANE_DEPTH (512), so the served
    /// bundle's bound was 512 × block wire — 16 MB at a 32 KB block, 68 MB at the 132 KB block the carried finality
    /// votes made (scratchpad/verify/launch-leg1-20261022-2057.log: 2,739 refusals of 17–57 MB bundles past the 16 MiB
    /// frame from t≈150 s, every joiner stranded on a stale bundle, DB-428 UNPLACED). BORROWED, cited: Kaspa's pruning
    /// point (the certified state is served AT the fold root) + Bitcoin headers-first / getblocks (the blocks above it
    /// ride the kind-9 follow-page lane this node already has — DB-446 `follow_page_after_locator`, `CBlockLocator`).
    /// Two scales tell a constant from a slope: the same node serves once nearly folded and once 300 blocks behind.
    /// RED on main 26d14e5: the carry held 300 bodies and the wire grew with the lag.
    #[test]
    fn a_node_behind_its_fold_by_less_than_the_lane_depth_serves_the_same_constant_bundle_at_its_fold_root() {
        let mut producer = testnet_node();
        let mut lagging = testnet_node();
        let t0 = genesis_ts(&producer) + 60_000;
        let mut seed = Vec::new();
        for i in 0..4u64 {
            let b = produce(&mut producer, t0 + i * 1_000, "g11b");
            lagging.ingest_block(b.clone(), t0 + i * 1_000 + 500);
            seed.push(b);
        }
        let _ = lagging.fold_canonical_records();
        let root = lagging.fold_anchor_block().expect("a folded node has a fold root");
        let base = lagging.unfolded_blocks_len_for_test();
        let fb = lagging.frontier_snapshot_for_test();
        let small = lagging.build_sync_bundle(Vec::new(), fb).expect("a folded node serves");
        let small_wire = small.to_wire().len();
        while lagging.unfolded_blocks_len_for_test() < 300 {
            for b in &seed {
                lagging.push_unfolded_for_test(b.clone());
            }
        }
        let lag = lagging.unfolded_blocks_len_for_test();
        assert!(
            lag <= crate::node::LIVE_LANE_DEPTH,
            "PRECONDITION: the lag {lag} must sit INSIDE the lane depth — past it the DB-161 arm served the fold root already"
        );
        let frontier = lagging.frontier_snapshot_for_test();
        let bundle = lagging.build_sync_bundle(Vec::new(), frontier).expect("a fold-behind node serves (DB-161)");
        let wire = bundle.to_wire().len();
        let per_block = wire.saturating_sub(small_wire) / lag.saturating_sub(base).max(1);
        eprintln!(
            "[g11b] lag {base} → {lag} unfolded: bundle wire {small_wire} → {wire} B, carried unfolded {} ({per_block} B/block; \
             × LIVE_LANE_DEPTH {} = {} B against the 16 MiB frame)",
            bundle.fold_carry.unfolded.len(),
            crate::node::LIVE_LANE_DEPTH,
            per_block * crate::node::LIVE_LANE_DEPTH
        );
        assert!(
            bundle.fold_carry.unfolded.is_empty(),
            "⛔ G11b: the carry holds {} unfolded BODIES — the bundle grows with the fold lag (wire {small_wire} → {wire} B over \
             {base} → {lag} blocks, {per_block} B/block); at LIVE_LANE_DEPTH that is {} B, the 17–57 MB bundles the frame refused",
            bundle.fold_carry.unfolded.len(),
            per_block * crate::node::LIVE_LANE_DEPTH
        );
        assert_eq!(bundle.tip_block.id(), root, "the served position is the certified fold root, always");
        assert_eq!(small.tip_block.id(), root, "the served position is the certified fold root at every lag");
        assert!(wire <= 1_800_000, "⛔ the bundle wire {wire} B is past the ≤ 1.8 MB cardinal");
        // MEASURED (g11b-green2-20261022-2232.log): 13,210 → 13,207 B over 4 → 300 blocks — a constant (the 3 B are a
        // count's varint width); on main 26d14e5 the same two scales read 158,066 → 9,381,132 B (31,159 B/block).
        assert!(
            wire.abs_diff(small_wire) <= 64,
            "⛔ the bundle wire changed {small_wire} → {wire} B with the fold lag {base} → {lag}: a slope, not a constant"
        );
    }


    /// ⭐⭐⭐ DB-154 — THE COPATH LANE NOW HAS SOMETHING IN CONSENSUS TO ANCHOR TO.
    ///
    /// THE GAP THIS CLOSES: `header.nullifier_root` is the A_tip FOLD — order-free and perfect for
    /// answering *"is the spent set the same"*, and useless for a copath, because a wallet cannot fold a
    /// copath against a fold. So a wallet checking a served non-membership copath was trusting the ONE
    /// node that served it: the local-state-decides-truth class wearing a proof.
    ///
    /// The block now also commits `header.sparse_root`, the MERKLE root of the spent set. This holds the
    /// two things that make it consensus rather than a node's opinion:
    ///   1. TWO nodes that accepted the same blocks commit the SAME root — so it is the chain's value,
    ///      not the producer's;
    ///   2. a copath served by one node folds to the root the OTHER committed — which is the wallet's
    ///      whole use for it.
    #[test]
    fn two_nodes_that_accepted_the_same_blocks_commit_one_sparse_root_and_a_copath_folds_to_it() {
        // ⛔ THE PRE-SWITCH MODE, NAMED (2026-11-26): this pin settles a spend as a band step with a held nullifier VIEW. Under the
        // constant chain (`params::CANON_LIVE`, ON in every build) no node holds the spent set (A-F114 U1), so that mode is not what
        // production runs; its code is still in the tree, and this pin keeps it correct on its own thread with the switch off.
        crate::params::set_canon_live_for_test(Some(false));
        let mut a = testnet_node();
        let mut b = testnet_node();
        let t0 = genesis_ts(&a) + 60_000;

        // Both nodes accept the same blocks, each folding as it goes.
        let mut last = None;
        let mut root_before_last = [0u8; 32];
        for i in 0..5u64 {
            // The header commits the PRE-block root, so the value to hold it to is the producer's tree
            // as it stood BEFORE this block — the same pre->post shape `nullifier_root` already uses.
            root_before_last = a.sparse_tree_root_or_zero();
            let blk = produce(&mut a, t0 + i * 1_000, "db154");
            b.ingest_block(blk.clone(), t0 + i * 1_000 + 400);
            // EVERY block's commitment is held to its own pre-state, not just the last: a chain that is
            // right only at the end is a chain that drifted and came back.
            assert_eq!(
                blk.header.sparse_root.0, root_before_last,
                "block {i} committed a root its producer's tree never held"
            );
            last = Some(blk);
        }
        let _ = a.fold_canonical_records();
        let _ = b.fold_canonical_records();
        let last = last.expect("setup: blocks were produced");
        // ⭐ P1 (2026-10-04, the pin made faithful): the spent set moves only when a REAL admitted spend's band step is
        // PROVEN (`band_drain`), never by a block's cover tags, so five spendless blocks leave both trees at the empty
        // root and "pre ≠ post" below would be vacuous. A settles one spend as a band step with its own view (one real
        // proof) and B, which noted the same step, takes the SAME relayed transition — the one way a spent tag reaches
        // a peer's set on the mesh. The header of `last` committed the band root as it stood at produce (the PRE root).
        let _ = (a.band_catch_up_for_test(), b.band_catch_up_for_test());
        let settled = *crate::hash::Hash32::hash(b"db154-settled-spend").as_bytes();
        let step = a.band_plant_for_test(1 << 40, &[settled]).expect("A settles one spend as a band step");
        b.band_note_step_for_test(1 << 40, &[settled]);
        assert_eq!(
            b.band_offer(step, false),
            crate::nf_sparse::BandReceipt::Verified,
            "CALIBRATION: B verifies the relayed band step against the set it derives"
        );

        // ⭐ DO THE TWO SPARSE ROOTS AGREE? `sparse_acc` is the O(1) accumulator every verify path
        // compares against; `sparse_work` is the tree DB-154 commits. If they diverge, the committed root
        // and the verified root are two different values — the second-spelling class — so this is measured
        // before anything is wired to either.
        assert_eq!(
            a.sparse_merkle_root(),
            a.sparse_tree_root_or_zero(),
            "⛔ THE ACCUMULATOR AND THE TREE HOLD DIFFERENT ROOTS. Every verify path compares a carrier's \
             pre against `sparse_acc`, and DB-154 commits the TREE's root — if these ever diverge the \
             chain commits one value and verifies another, which is the second-spelling class at the \
             centre of the nullifier lane."
        );

        // ⛔ THE PRODUCER COMMITTED A REAL ROOT, not the zero a treeless node signs.
        assert_ne!(
            last.header.sparse_root,
            crate::hash::Hash32::ZERO,
            "⛔ the producer committed NO sparse root — the copath lane is still anchored to nothing, \
             which is the whole of DB-154"
        );

        // 1. ONE VALUE, TWO NODES. If these differ the field is the producer's opinion, not the chain's.
        let (ra, rb) = (a.sparse_tree_root_or_zero(), b.sparse_tree_root_or_zero());
        assert_eq!(
            ra, rb,
            "⛔ TWO NODES THAT ACCEPTED THE SAME BLOCKS HOLD DIFFERENT SPARSE ROOTS. Committing that \
             value would put each node's own state into the header — the local-state-decides-truth class \
             this field exists to leave behind."
        );
        assert_eq!(
            last.header.sparse_root.0, root_before_last,
            "⛔ the committed root is not the one the producer's tree held BEFORE this block — a \
             commitment that describes no reachable state anchors nothing"
        );
        assert_ne!(
            last.header.sparse_root.0, ra,
            "and it is the PRE root, not the post: a block whose spends moved the set must commit the \
             state its own spends prove non-membership against, exactly as `nullifier_root` does"
        );

        // 2. THE WALLET'S USE: a copath served by A folds to the root B committed. Drives an unspent
        //    nullifier, which is what a spender actually proves.
        let nf = {
            let mut n = [0u8; 32];
            n[0] = 0xDB;
            n[1] = 0x9A;
            n[31] = 0x54;
            n
        };
        let copath = a.da_sparse_copath(&nf);
        assert!(!copath.is_empty(), "setup: A served a copath at all");
        let verdict = b.sparse_spent_verdict(&nf);
        assert!(
            !matches!(verdict, crate::nf_sparse::SpentVerdict::Spent),
            "setup: an untouched nullifier must not read as spent — {verdict:?}"
        );
        eprintln!(
            "[db154] both nodes committed sparse_root {:02x}{:02x}… and A's copath is {} level(s) deep",
            ra[0], ra[1],
            copath.len()
        );
    }


    /// ⛔⛔⛔ DB-162 — A HEALTHY NODE REPORTS ZERO NOTE-PAYLOAD DEBT, SO A WALLET CAN CERTIFY A BALANCE.
    ///
    /// THE FAILURE THIS PINS, gate STEP 2 2026-09-22: a fresh two-node chain reported `debt=406`
    /// (`records_held 374 of 506`). The wallet relayed the node's own claim and downgraded a balance it
    /// had ALREADY scanned correctly — `1 owned note(s), 2500000000 atomic spendable` — to `0 owned, 0
    /// atomic spendable`. The gate failed with *"balance never reached 25.0 spendable"*. The money was on
    /// chain, found, and hidden by arithmetic.
    ///
    /// The cause was units: `note_body_target` is a CHAIN POSITION (`state.blue_score`) and
    /// `blocks_note_applied` was a COUNTER of blocks that applied note bytes (deleted 2026-10-22). Most blocks are cover-only
    /// and apply none, so their difference is roughly the count of cover-only blocks and never reaches
    /// zero. The debt now reads `payload_gap` — the set of blocks held WITHOUT their data, which is empty
    /// on a healthy mesh.
    #[test]
    fn a_healthy_node_reports_no_note_payload_debt_however_many_cover_only_blocks_it_made() {
        let mut n = testnet_node();
        let t0 = genesis_ts(&n) + 60_000;
        // Cover-only blocks: no real payment, exactly the shape that inflated the old difference.
        for i in 0..12u64 {
            let _ = produce(&mut n, t0 + i * 1_000, "db162");
        }
        let _ = n.fold_canonical_records();
        assert!(
            n.dag().get(&n.selected_tip().expect("a tip")).is_some(),
            "setup: the node produced a chain"
        );
        assert_eq!(
            n.note_payload_debt(),
            0,
            "⛔ A NODE THAT PRODUCED EVERY ONE OF ITS OWN BLOCKS REPORTS A NOTE-PAYLOAD DEBT. Every wallet \
             attached to it refuses to certify a balance and shows 0 spendable while its owner holds \
             money — measured as exactly that on the gate, debt=406 against a 25.0 faucet."
        );
    }




    /// ⛔ DB-265 — A JOINER AND ITS ORIGIN MUST COMPUTE THE SAME GHOSTDAG DATA FOR EVERY BLOCK BOTH HOLD, AND FOLD THE
    /// SAME ORDINALS, WHEN BOTH PRODUCE AFTER THE JOIN WITH DELIVERY LAG. MEASURED gate Q (/tmp/musd-ecocheck-YL3Vfe): two
    /// honest nodes on one binary folded DIFFERENT records at ordinal 113 and kept them while sharing a selected tip —
    /// impossible if both derive one selected parent per block from one DAG. The joiner computes GHOSTDAG above an anchor
    /// shell (its past is a certified weight, not blocks), the one place the two views can differ. Two-round delivery lag
    /// both ways makes every round's pair siblings (DAG width 2), the shape of a live pair.
    #[test]
    fn db265_a_joiner_and_its_origin_agree_on_every_blocks_ghostdag_data_and_fold_after_concurrent_production() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        // the origin re-anchors by the joiner's bundle when a fold reorg deeper than the rewind ring stales its spine
        node_a.set_decider_verifier(Box::new(AcceptAll));
        let t0 = genesis_ts(&node_a);
        for k in 0..12u64 {
            produce(&mut node_a, t0 + 60_000 * (k + 1), &format!("o{k}"));
        }
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B joins by A's bundle");
        page_above_anchor(&mut node_b, &node_a);
        const LAG: usize = 2;
        let mut to_a: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        let mut to_b: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        let mut produced: Vec<Block> = Vec::new();
        for r in 0..40usize {
            let ts = t0 + 60_000 * (13 + r as u64);
            let a = produce(&mut node_a, ts, &format!("a{r}"));
            let b = produce(&mut node_b, ts + 11, &format!("b{r}"));
            to_b.push_back((r + LAG, a.clone()));
            to_a.push_back((r + LAG, b.clone()));
            produced.push(a);
            produced.push(b);
            while to_a.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_a.pop_front().unwrap();
                ingest(&mut node_a, &blk, ts + 500, "A");
            }
            while to_b.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_b.pop_front().unwrap();
                ingest(&mut node_b, &blk, ts + 500, "B");
            }
        }
        let t_end = t0 + 60_000 * 60;
        for (_, blk) in to_a.drain(..) {
            ingest(&mut node_a, &blk, t_end, "A");
        }
        for (_, blk) in to_b.drain(..) {
            ingest(&mut node_b, &blk, t_end, "B");
        }
        // DETERMINISM: block ids vary run to run (the grind), so the (blue_work, id) tie-break chose the joiner's chain in
        // some runs and the joiner never had to rewind — a GREEN by luck (MEASURED: solo GREEN, in-suite RED, same code).
        // Two more ORIGIN blocks on top. MEASURED 2026-10-23: they extend whichever tip wins the tie, so in ~half the runs
        // the joiner's chain still wins and the ORIGIN rewinds 69 records — deeper than the rewind ring, so its spine goes
        // stale and the settle below re-anchors it by the joiner's bundle (the runtime's stale-spine lane).
        for k in 0..2u64 {
            let x = produce(&mut node_a, t_end + 60_000 * (k + 1), &format!("win{k}"));
            ingest(&mut node_b, &x, t_end + 60_000 * (k + 1) + 500, "B");
            produced.push(x);
        }
        let mut differ: Vec<String> = Vec::new();
        for blk in &produced {
            let id = blk.id();
            let (Some(x), Some(y)) = (node_a.dag().get(&id), node_b.dag().get(&id)) else {
                panic!("setup: both nodes hold every block produced after the join ({})", &id.to_hex()[..8]);
            };
            if (x.blue_score, x.blue_work, x.selected_parent) != (y.blue_score, y.blue_work, y.selected_parent) {
                differ.push(format!(
                    "{}: A bs{} bw{} sp{:?} / B bs{} bw{} sp{:?}",
                    &id.to_hex()[..8],
                    x.blue_score,
                    x.blue_work,
                    x.selected_parent.map(|p| p.to_hex()[..8].to_string()),
                    y.blue_score,
                    y.blue_work,
                    y.selected_parent.map(|p| p.to_hex()[..8].to_string())
                ));
            }
        }
        assert!(
            differ.is_empty(),
            "⛔ DB-265: {} block(s) carry DIFFERENT GHOSTDAG data on the origin and the joiner — one tip can then \
             name two selected chains, and the fold (a function of the selected chain) diverges: {:?}",
            differ.len(),
            &differ[..differ.len().min(8)]
        );
        assert_eq!(node_a.selected_tip(), node_b.selected_tip(), "one tip once both hold every block");
        // Name each folded record by who produced it and when, on both sides, before the fold comparison: the first
        // measured failure was pairs of records at SWAPPED ordinals (13<->16, 14<->18, …) with identical GHOSTDAG data.
        let tag_of: std::collections::HashMap<crate::block::BlockId, String> = produced
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let tag = if i >= 80 { format!("win{}", i - 80) } else { format!("{}{}", if i % 2 == 0 { "a" } else { "b" }, i / 2) };
                (b.id(), tag)
            })
            .collect();
        let chain_of = |n: &Node| -> std::collections::HashSet<crate::block::BlockId> {
            let mut out = std::collections::HashSet::new();
            let mut cur = n.selected_tip();
            while let Some(c) = cur {
                out.insert(c);
                cur = n.dag().get(&c).and_then(|x| x.selected_parent);
            }
            out
        };
        let (chain_a, chain_b) = (chain_of(&node_a), chain_of(&node_b));
        let seq_of = |n: &Node, chain: &std::collections::HashSet<crate::block::BlockId>| -> Vec<String> {
            let mut v: Vec<(u64, String)> = produced
                .iter()
                .filter_map(|b| {
                    let o = n.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0))?;
                    Some((o, format!("{o}:{}{}", tag_of[&b.id()], if chain.contains(&b.id()) { "*" } else { "" })))
                })
                .collect();
            v.sort();
            v.into_iter().map(|(_, s)| s).take(24).collect()
        };
        eprintln!(
            "[db265] fold order (ordinal:producer+round, * = on the shared selected chain)\n  origin: {}\n  joiner: {}",
            seq_of(&node_a, &chain_a).join(" "),
            seq_of(&node_b, &chain_b).join(" ")
        );
        // The mesh lanes a jumper runs on a mesh (record lane, warm lane, band relay) — `Node::settle_mesh_lanes_for_test`.
        node_a.settle_mesh_lanes_for_test(&mut [&mut node_b], produced.len() + 2);
        // Both fold ON after the settle — a re-anchored origin included (its per-ordinal accumulators below the anchor
        // come from the roots-run lane, not this pin's subject): 8 sequential rounds fold past the depth, so the
        // accumulator series is compared at ordinals BOTH nodes folded themselves after any re-anchor.
        let t_post = t_end + 60_000 * 3;
        for k in 0..8u64 {
            let ts = t_post + 60_000 * k;
            let x = produce(&mut node_a, ts, &format!("post-a{k}"));
            ingest(&mut node_b, &x, ts + 200, "B");
            let y = produce(&mut node_b, ts + 400, &format!("post-b{k}"));
            ingest(&mut node_a, &y, ts + 600, "A");
            produced.push(x);
            produced.push(y);
        }
        node_a.settle_mesh_lanes_for_test(&mut [&mut node_b], produced.len() + 2);
        assert_same_fold(&node_a, &node_b, &produced, "the joiner folds like its origin after concurrent production");
    }


    /// ⛔ DB-267 — A RESTARTED NODE MUST COMPUTE THE SAME GHOSTDAG DATA AS ITS NEVER-RESTARTED PEER FOR EVERY BLOCK BOTH
    /// HOLD. MEASURED gate Q2 (/tmp/musd-ecocheck-t0Jfdc): after node1's restart (snapshot + 57 carried blocks + 506 window
    /// blocks) the pair held the SAME recent DAG with IDENTICAL parent sets, yet node1 scored all 86 common blocks exactly
    /// 32 lower than node2 (3ebddb23: 1433 vs 1465, c0c133c8: 1444 vs 1476) — the checker saw a fork at every score and
    /// the pair never read as converged. Production fold depth, the production restart path (block window +
    /// `enable_persist` → `restore_from_disk`), width-2 concurrent production before the restart and after it, and the
    /// peer producing alone while the node is down — the gate's step-3 shape.
    #[test]
    fn db267_a_restarted_node_scores_every_block_exactly_as_its_never_restarted_peer() {
        fn production_depth_node() -> Node {
            let mut p = ChainParams::default();
            p.genesis_parity_commit = network_genesis_prefix("testnet");
            p.net_prefix_len = p.genesis_parity_commit.len();
            let mut g = crate::node::tests::genesis_block();
            g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
            crate::pouw::bound_pow::arm_on_this_thread(true); // §FAST: the bound PoUW double, as `testnet_node`
            Node::with_params(g, p).expect("a testnet node builds")
        }
        fn exchange(
            node_a: &mut Node,
            node_b: &mut Node,
            rounds: usize,
            t: &mut u64,
            tag: &str,
            produced: &mut Vec<Block>,
        ) {
            let mut to_a: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
            let mut to_b: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
            for r in 0..rounds {
                *t += 60_000;
                let a = produce(node_a, *t, &format!("{tag}a{r}"));
                let b = produce(node_b, *t + 11, &format!("{tag}b{r}"));
                to_b.push_back((r + 1, a.clone()));
                to_a.push_back((r + 1, b.clone()));
                produced.push(a);
                produced.push(b);
                while to_a.front().map_or(false, |(due, _)| *due <= r) {
                    let (_, blk) = to_a.pop_front().unwrap();
                    ingest(node_a, &blk, *t + 500, "A");
                }
                while to_b.front().map_or(false, |(due, _)| *due <= r) {
                    let (_, blk) = to_b.pop_front().unwrap();
                    ingest(node_b, &blk, *t + 500, "B");
                }
            }
            *t += 60_000;
            for (_, blk) in to_a.drain(..) {
                ingest(node_a, &blk, *t, "A");
            }
            for (_, blk) in to_b.drain(..) {
                ingest(node_b, &blk, *t, "B");
            }
        }
        let dir = std::env::temp_dir().join(format!(
            "musd-db267-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (snap, win) = (dir.join("state.snap"), dir.join("window"));
        let mut node_a = production_depth_node();
        node_a.enable_block_window(win.clone());
        assert!(!node_a.enable_persist(snap.clone()).expect("persist enables"), "setup: a fresh node resumes nothing");
        let mut node_b = production_depth_node();
        let mut t = genesis_ts(&node_a);
        let mut produced: Vec<Block> = Vec::new();
        exchange(&mut node_a, &mut node_b, 80, &mut t, "pre", &mut produced);
        assert_eq!(node_a.selected_tip(), node_b.selected_tip(), "setup: one DAG before the restart");
        let tip_score_before = node_a.dag().get(&node_a.selected_tip().unwrap()).map(|n| n.blue_score);
        node_a.persist_blocking();
        drop(node_a);
        // B carries on alone while A is down.
        for r in 0..40usize {
            t += 60_000;
            produced.push(produce(&mut node_b, t, &format!("down{r}")));
        }
        let mut node_a = production_depth_node();
        node_a.enable_block_window(win.clone());
        assert!(node_a.enable_persist(snap.clone()).expect("persist enables"), "A resumes its checkpoint");
        // the blocks B produced while A was down, in order (their parents are the pre-restart DAG and each other)
        let down: Vec<Block> = produced[produced.len() - 40..].to_vec();
        for blk in &down {
            if node_a.dag().get(&blk.id()).is_none() {
                ingest(&mut node_a, blk, t + 1_000, "A (restarted)");
            }
        }
        let after_down_score = node_a.dag().get(&node_a.selected_tip().unwrap()).map(|n| n.blue_score);
        exchange(&mut node_a, &mut node_b, 30, &mut t, "post", &mut produced);
        let mut differ: Vec<String> = Vec::new();
        let mut compared = 0usize;
        for blk in &produced {
            let id = blk.id();
            let (Some(x), Some(y)) = (node_a.dag().get(&id), node_b.dag().get(&id)) else { continue };
            compared += 1;
            if (x.blue_score, x.blue_work, x.selected_parent) != (y.blue_score, y.blue_work, y.selected_parent) {
                differ.push(format!(
                    "{}: restarted bs{} / peer bs{}{}",
                    &id.to_hex()[..8],
                    x.blue_score,
                    y.blue_score,
                    if x.selected_parent != y.selected_parent { " (selected parent differs)" } else { "" }
                ));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(compared >= 100, "calibration: {compared} blocks compared (tip before restart {tip_score_before:?}, after the down blocks {after_down_score:?})");
        assert!(
            differ.is_empty(),
            "⛔ DB-267: the restarted node's GHOSTDAG data differs from its peer's for {} of {compared} common block(s) \
             (tip before restart {tip_score_before:?}, after the down blocks {after_down_score:?}) — the pair can never read \
             as converged: {:?}",
            differ.len(),
            &differ[..differ.len().min(10)]
        );
        assert_eq!(node_a.selected_tip(), node_b.selected_tip(), "one tip once both hold every block");
    }


    /// ⛔ DB-267 (the gate's exact shape) — A JOINER THAT CRAWLED AND PRODUCED BEFORE IT JUMPED MUST STILL SCORE EVERY
    /// BLOCK AS ITS ORIGIN DOES. MEASURED gate Q2 (n2.log): n2 crawled 49 -> 208 by pages, produced its own blocks while
    /// behind ("the deferral is NOT catching up … Extending the chain anyway"), then adopted at 496 and printed
    /// "re-folded 32 held block(s) outside the adopted tip's past" / "DB-249: re-applied 32 held block(s) … this node's
    /// next block merges them" — and from then on scored every block exactly +32 (= ghostdag_k) against the origin.
    #[test]
    fn db267_a_joiner_that_crawled_and_produced_before_it_jumped_scores_every_block_as_its_origin_does() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let mut t = genesis_ts(&node_a);
        let mut produced: Vec<Block> = Vec::new();
        // B crawls A's first 40 blocks.
        for k in 0..40u64 {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("crawl{k}"));
            ingest(&mut node_b, &a, t + 500, "B (crawl)");
            produced.push(a);
        }
        // B, behind, extends its own tip anyway; A receives those blocks (they are gossiped) and keeps producing.
        for k in 0..10u64 {
            t += 60_000;
            let b = produce(&mut node_b, t + 7, &format!("own{k}"));
            ingest(&mut node_a, &b, t + 600, "A");
            produced.push(b);
        }
        for k in 0..60u64 {
            t += 60_000;
            produced.push(produce(&mut node_a, t, &format!("ahead{k}")));
        }
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B jumps by A's bundle");
        page_above_anchor(&mut node_b, &node_a);
        // Width-2 production after the jump, one-round lag both ways.
        let mut to_a: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        let mut to_b: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        for r in 0..30usize {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("pa{r}"));
            let b = produce(&mut node_b, t + 11, &format!("pb{r}"));
            to_b.push_back((r + 1, a.clone()));
            to_a.push_back((r + 1, b.clone()));
            produced.push(a);
            produced.push(b);
            while to_a.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_a.pop_front().unwrap();
                ingest(&mut node_a, &blk, t + 500, "A");
            }
            while to_b.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_b.pop_front().unwrap();
                ingest(&mut node_b, &blk, t + 500, "B");
            }
        }
        t += 60_000;
        for (_, blk) in to_a.drain(..) {
            ingest(&mut node_a, &blk, t, "A");
        }
        for (_, blk) in to_b.drain(..) {
            ingest(&mut node_b, &blk, t, "B");
        }
        let mut differ: Vec<String> = Vec::new();
        let mut compared = 0usize;
        for blk in produced.iter().rev().take(60) {
            let id = blk.id();
            let (Some(x), Some(y)) = (node_a.dag().get(&id), node_b.dag().get(&id)) else {
                panic!("setup: both nodes hold every block produced after the jump ({})", &id.to_hex()[..8]);
            };
            compared += 1;
            if (x.blue_score, x.blue_work, x.selected_parent) != (y.blue_score, y.blue_work, y.selected_parent) {
                differ.push(format!("{}: origin bs{} / joiner bs{}", &id.to_hex()[..8], x.blue_score, y.blue_score));
            }
        }
        assert_eq!(compared, 60, "calibration: every post-jump block compared");
        assert!(
            differ.is_empty(),
            "⛔ DB-267: the joiner that crawled before it jumped scores {} of {compared} post-jump block(s) differently \
             from its origin: {:?}",
            differ.len(),
            &differ[..differ.len().min(10)]
        );
        assert_eq!(node_a.selected_tip(), node_b.selected_tip(), "one tip once both hold every block");
    }


    /// ⛔ DB-267 (the gate's LATE-MERGE shape) — the origin receives the joiner's side blocks only AFTER the bundle point,
    /// so a post-bundle origin block names an old joiner block as a DIRECT parent. On the joiner that old block's whole
    /// crawl ancestry lies outside `bounded_past(sp)` (the walk stops at the certified anchor), so the mergeset BFS walks
    /// down the crawl and the k-cluster colouring passes up to k of them blue — on the origin they are inside past(sp).
    /// MEASURED gate Q2: n2 (the joiner) scored every later block exactly +32 = ghostdag_k.
    #[test]
    fn db267_a_late_merge_of_a_joiners_side_blocks_scores_identically_on_the_joiner_and_the_origin() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let mut t = genesis_ts(&node_a);
        for k in 0..40u64 {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("crawl{k}"));
            ingest(&mut node_b, &a, t + 500, "B (crawl)");
        }
        // B, behind, extends its own tip; A does NOT see these yet.
        let mut side: Vec<Block> = Vec::new();
        for k in 0..10u64 {
            t += 60_000;
            side.push(produce(&mut node_b, t + 7, &format!("side{k}")));
        }
        for k in 0..60u64 {
            t += 60_000;
            produce(&mut node_a, t, &format!("ahead{k}"));
        }
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B jumps by A's bundle");
        page_above_anchor(&mut node_b, &node_a);
        // Only now does A receive B's side blocks; A's next block merges them LATE (a direct parent is B's side tip).
        for blk in &side {
            ingest(&mut node_a, blk, t + 800, "A (late side blocks)");
        }
        t += 60_000;
        let late = produce(&mut node_a, t, "late-merge");
        assert!(
            late.header.parents.contains(&side.last().unwrap().id()),
            "calibration: A's post-bundle block names B's side tip as a direct parent"
        );
        // The joiner cannot place the late merge's mergeset (it reaches its pre-anchor crawl). It must NEVER score it
        // differently from the origin: it either scores it identically or BUFFERS it until a certified re-anchor carries
        // it with the origin's blue data.
        let outcome = node_b.ingest_block(late.clone(), t + 500);
        // DB-282: the late merge names a block the joiner holds only as PRE-ANCHOR history, so the DAG refuses it as a
        // merge of history (never `Invalid`) and the joiner's spine is marked for the certified re-anchor below.
        let buffered = matches!(
            outcome,
            RelayOutcome::Buffered { .. }
                | RelayOutcome::DagRejected(crate::dag::DagError::MergesPreAnchorHistory(_))
        );
        assert!(
            buffered || matches!(outcome, RelayOutcome::Added(_)),
            "the joiner either buffers, refuses as a merge of pre-anchor history, or adds the late merge — never \
             refuses it as invalid: {outcome:?}"
        );
        if matches!(outcome, RelayOutcome::DagRejected(_)) {
            assert!(
                node_b.spine_stale_for_test(),
                "⛔ DB-282: a refused late merge must mark the joiner for a certified re-anchor — else it waits out the \
                 ~90 s stall detector before it can follow the chain again"
            );
        }
        let mut produced: Vec<Block> = vec![late.clone()];
        for r in 0..6usize {
            t += 60_000;
            produced.push(produce(&mut node_a, t, &format!("after{r}")));
        }
        if buffered {
            // The certified re-anchor (the stall path's jump, driven here directly): A is heavier by the late merge and
            // everything after it, so B adopts and holds `late` with A's carried blue data.
            assert!(
                matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)),
                "the joiner re-anchors on the origin's certified state"
            );
            page_above_anchor(&mut node_b, &node_a);
        } else {
            for blk in &produced[1..] {
                ingest(&mut node_b, blk, t + 500, "B");
            }
        }
        for r in 0..6usize {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("later{r}"));
            ingest(&mut node_b, &a, t + 500, "B (after the re-anchor)");
            produced.push(a);
        }
        let mut differ: Vec<String> = Vec::new();
        let mut compared = 0usize;
        for blk in &produced {
            let id = blk.id();
            let (Some(x), Some(y)) = (node_a.dag().get(&id), node_b.dag().get(&id)) else {
                continue; // below the re-anchored joiner's horizon: held as certified state, not as a block
            };
            compared += 1;
            // Blue score and blue work are the consensus data; a carried block's selected-parent LINK may be absent on
            // the joiner (its parent is below the new anchor), which is structure, not a score.
            if (x.blue_score, x.blue_work) != (y.blue_score, y.blue_work) {
                differ.push(format!("{}: origin bs{} / joiner bs{}", &id.to_hex()[..8], x.blue_score, y.blue_score));
            }
        }
        assert!(compared >= 6, "calibration: {compared} blocks compared (the post-re-anchor blocks at least)");
        assert!(
            differ.is_empty(),
            "⛔ DB-267: after a LATE merge of the joiner's side blocks, {} of {} block(s) score differently on the joiner — \
             the gate-Q2 +32: {:?}",
            differ.len(),
            produced.len(),
            &differ[..differ.len().min(8)]
        );
    }


    /// A jumper as gate Q6 measured it (2026-09-27): B crawls A's first 40 blocks and produces NOTHING, A runs 60
    /// ahead, B jumps by A's bundle. Returns the two nodes, the clock, and A's 60 "ahead" blocks — the first ones sit
    /// below the bundle's anchor, inside the certified past B adopted.
    fn db282_jumper_after_a_crawl() -> (crate::node::Node, crate::node::Node, u64, Vec<Block>) {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let mut t = genesis_ts(&node_a);
        for k in 0..40u64 {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("crawl{k}"));
            ingest(&mut node_b, &a, t + 500, "B (crawl)");
        }
        let mut ahead: Vec<Block> = Vec::new();
        for k in 0..60u64 {
            t += 60_000;
            ahead.push(produce(&mut node_a, t, &format!("ahead{k}")));
        }
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B jumps by A's bundle");
        (node_a, node_b, t, ahead)
    }

    /// ⛔⛔⛔ DB-282 — A JUMPER NEVER RE-APPLIES A BLOCK ITS CERTIFIED STATE ALREADY COUNTS.
    ///
    /// MEASURED gate Q6 (/tmp/musd-ecocheck-CwYXAx, n2.log): right after "adopted certified state to height 329" the
    /// runtime drained an inventory computed BEFORE the jump ("getdata: 32 body(ies) named … (41 still queued)", pages
    /// of 25, 26 and 18 bodies) — ~70 of the origin's OLD blocks, every one inside the certified past. Their parents
    /// sat in the jumper's crawl island, so each one grafted, and a graft applies the block in one act: A_tip folds
    /// its leaf AGAIN (the certified A_tip already counts it — the DB-250 class through a new door), its record is
    /// written, its chain objects, bonds, directory and letters are applied. Any peer that serves an old block by id
    /// reaches the same door. Kaspa refuses a block that is not in the future of its pruning point
    /// (`check_pruning_violation`); a jumper's certified anchor is that point for it.
    #[test]
    fn db282_a_jumper_never_re_applies_a_block_its_certified_state_already_counts() {
        let (node_a, mut node_b, t, ahead) = db282_jumper_after_a_crawl();
        let certified_atip = node_a.nf_unspent_acc();
        assert_eq!(node_b.nf_unspent_acc(), certified_atip, "calibration: the jumper stands on the certified A_tip");
        assert!(
            node_b.dag().get(&ahead[0].header.parents[0]).is_some(),
            "calibration: the jumper's crawl island holds the parent of the origin's first old block, so it can graft"
        );
        assert!(
            node_b.dag().get(&ahead[0].id()).is_none(),
            "calibration: the old block itself is not held — it lies between the island and the anchor"
        );
        let tips_before = node_b.dag().tips();
        let outcomes: Vec<String> = ahead[0..10]
            .iter()
            .map(|b| format!("{:?}", node_b.ingest_block(b.clone(), t + 700)))
            .collect();
        let entered: Vec<String> = ahead[0..10]
            .iter()
            .filter(|b| node_b.dag().get(&b.id()).is_some())
            .map(|b| b.id().to_hex()[..8].to_string())
            .collect();
        assert_eq!(
            node_b.nf_unspent_acc(),
            certified_atip,
            "⛔ DB-282: the jumper RE-FOLDED blocks its certified A_tip already counts — its absence accumulator left \
             the chain's (outcomes {outcomes:?})"
        );
        assert!(
            entered.is_empty(),
            "⛔ DB-282: {} block(s) inside the certified past entered the jumper's DAG (applied in the graft's single \
             act): {entered:?}",
            entered.len()
        );
        assert_eq!(node_b.dag().tips(), tips_before, "⛔ DB-282: an old block became a tip below the anchor");
    }

    /// ⛔ DB-282 — …AND ITS NEXT BLOCKS SCORE EXACTLY AS ITS ORIGIN SCORES THEM. MEASURED gate Q6: 84 blocks both nodes
    /// held, identical parent sets, identical selected flags — and the jumper scored every one exactly +32 (=
    /// ghostdag_k). Its next block named a regrown island tip: the mergeset BFS walked the island (outside
    /// `bounded_past(sp)`, which stops at the anchor) and the k-cluster colouring passed 32 of them blue. On the origin
    /// the island is inside past(sp). This is the jumper's OWN production reaching DB-267 — no side blocks needed.
    #[test]
    fn db282_a_jumper_offered_its_certified_past_scores_its_next_blocks_as_its_origin_does() {
        let (mut node_a, mut node_b, mut t, ahead) = db282_jumper_after_a_crawl();
        page_above_anchor(&mut node_b, &node_a);
        for b in &ahead[0..10] {
            let _ = node_b.ingest_block(b.clone(), t + 700);
        }
        let mut produced: Vec<Block> = Vec::new();
        let mut to_a: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        let mut to_b: std::collections::VecDeque<(usize, Block)> = std::collections::VecDeque::new();
        for r in 0..12usize {
            t += 60_000;
            let b = produce(&mut node_b, t + 11, &format!("pb{r}"));
            let a = produce(&mut node_a, t, &format!("pa{r}"));
            to_a.push_back((r + 1, b.clone()));
            to_b.push_back((r + 1, a.clone()));
            produced.push(b);
            produced.push(a);
            while to_a.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_a.pop_front().unwrap();
                ingest(&mut node_a, &blk, t + 500, "A");
            }
            while to_b.front().map_or(false, |(due, _)| *due <= r) {
                let (_, blk) = to_b.pop_front().unwrap();
                ingest(&mut node_b, &blk, t + 500, "B");
            }
        }
        t += 60_000;
        for (_, blk) in to_a.drain(..) {
            ingest(&mut node_a, &blk, t, "A");
        }
        for (_, blk) in to_b.drain(..) {
            ingest(&mut node_b, &blk, t, "B");
        }
        // Review (1), lane-db224-carriage: the jumper's OWN templates name no block it holds only as history — its tip
        // set holds settled structure alone, so its next block cannot merge the island. (B's blocks are the even
        // entries: each round pushes B's block first.)
        for blk in produced.iter().step_by(2) {
            for p in &blk.header.parents {
                assert!(
                    node_b.dag().get(p).map_or(false, |n| n.settled),
                    "⛔ DB-282: the jumper's own block {} names parent {} that it holds only as pre-anchor history",
                    &blk.id().to_hex()[..8],
                    &p.to_hex()[..8]
                );
            }
        }
        let mut differ: Vec<String> = Vec::new();
        for blk in &produced {
            let id = blk.id();
            let (Some(x), Some(y)) = (node_a.dag().get(&id), node_b.dag().get(&id)) else {
                panic!("setup: both nodes hold every block produced after the jump ({})", &id.to_hex()[..8]);
            };
            if (x.blue_score, x.blue_work, x.selected_parent) != (y.blue_score, y.blue_work, y.selected_parent) {
                differ.push(format!("{}: origin bs{} / jumper bs{}", &id.to_hex()[..8], x.blue_score, y.blue_score));
            }
        }
        assert!(
            differ.is_empty(),
            "⛔ DB-282: after being offered its certified past, the jumper scores {} of {} post-jump block(s) differently \
             from its origin (gate Q6: +32 on 84/84): {:?}",
            differ.len(),
            produced.len(),
            &differ[..differ.len().min(10)]
        );
        assert_eq!(node_a.selected_tip(), node_b.selected_tip(), "one tip once both hold every block");
    }


    /// ⛔ DB-282 (review 3, lane-db224-carriage) — A JUMPED NODE THAT RESTARTS STILL ADMITS ITS PEER'S NEXT BLOCKS, AND
    /// ITS PEER ADMITS ITS OWN. The settled flag is not persisted: the restore re-derives it (the checkpoint's anchor
    /// through `add_anchor`, the carry through `add_carried_block`, the window span as history). A restore that left the
    /// carry unsettled would make the restarted jumper refuse every block its peer builds — a halt, which this refuses.
    #[test]
    fn db282_a_jumped_node_that_restarts_admits_its_peers_next_blocks() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        // The node's own persist door lays out its datadir; the pin only names a fresh path.
        let dir = std::env::temp_dir().join(format!(
            "musd-db282-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let (snap, win) = (dir.join("state.snap"), dir.join("window"));
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.enable_block_window(win.clone());
        assert!(!node_b.enable_persist(snap.clone()).expect("persist enables"), "setup: a fresh node resumes nothing");
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let mut t = genesis_ts(&node_a);
        for k in 0..40u64 {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("crawl{k}"));
            ingest(&mut node_b, &a, t + 500, "B (crawl)");
        }
        for k in 0..60u64 {
            t += 60_000;
            produce(&mut node_a, t, &format!("ahead{k}"));
        }
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B jumps by A's bundle");
        page_above_anchor(&mut node_b, &node_a);
        for r in 0..8usize {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("pre{r}a"));
            let b = produce(&mut node_b, t + 11, &format!("pre{r}b"));
            ingest(&mut node_b, &a, t + 500, "B (jumped)");
            ingest(&mut node_a, &b, t + 500, "A");
        }
        node_b.persist_blocking();
        drop(node_b);
        let mut node_b = testnet_node();
        node_b.enable_block_window(win.clone());
        node_b.set_decider_verifier(Box::new(AcceptAll));
        assert!(node_b.enable_persist(snap.clone()).expect("persist enables"), "the jumper resumes its checkpoint");
        let mut produced: Vec<Block> = Vec::new();
        for r in 0..6usize {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("post{r}a"));
            let got = node_b.ingest_block(a.clone(), t + 500);
            assert!(
                matches!(got, RelayOutcome::Added(_) | RelayOutcome::Duplicate(_)),
                "⛔ DB-282: the RESTARTED jumper refused its peer's block {} (round {r}): {got:?} — a restore that leaves \
                 its carry unsettled halts the node",
                &a.id().to_hex()[..8]
            );
            produced.push(a);
        }
        t += 60_000;
        let b = produce(&mut node_b, t + 11, "after-restart");
        ingest(&mut node_a, &b, t + 500, "A (the restarted jumper's block)");
        produced.push(b);
        for blk in &produced {
            let id = blk.id();
            let (x, y) = (node_a.dag().get(&id).expect("A holds it"), node_b.dag().get(&id).expect("B holds it"));
            assert_eq!(
                (x.blue_score, x.blue_work),
                (y.blue_score, y.blue_work),
                "⛔ DB-282: after its restart the jumper scores {} differently from its peer",
                &id.to_hex()[..8]
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// ⛔ DB-269 — AN HONEST ADOPT MUST NOT COUNT A HELD BLOCK THE CERTIFIED STATE ALREADY COUNTS. `instant_sync`'s D-36
    /// arm re-folds every held UNFOLDED block that is not within `RECORD_FOLD_DEPTH_DEFAULT` parent levels of the served
    /// tips into the nullifier accumulator (and DB-249 re-applies its chain objects). A joiner that CRAWLED before it
    /// jumped holds an unfolded tail deep inside the certified past; A_tip is ADDITIVE with no dedup (the DB-250 class),
    /// so those blocks count twice and the joiner's A_tip leaves the chain's. MEASURED gate Q2 n2.log: "re-folded 32
    /// held block(s) outside the adopted tip's past into the inherited nullifier state" after a crawl to 208 and a jump
    /// to 496.
    #[test]
    fn db269_a_joiner_that_crawled_counts_no_held_block_twice_in_its_nullifier_accumulator() {
        use crate::decider::{ConsensusVerifier, DeciderBundle};
        use crate::sync::AdoptOutcome;
        struct AcceptAll;
        impl ConsensusVerifier for AcceptAll {
            fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
                true
            }
        }
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        node_b.set_decider_verifier(Box::new(AcceptAll));
        let mut t = genesis_ts(&node_a);
        for k in 0..40u64 {
            t += 60_000;
            let a = produce(&mut node_a, t, &format!("crawl{k}"));
            ingest(&mut node_b, &a, t + 500, "B (crawl)");
        }
        for k in 0..60u64 {
            t += 60_000;
            produce(&mut node_a, t, &format!("ahead{k}"));
        }
        let certified = node_a.nf_unspent_acc();
        assert_ne!(node_b.nf_unspent_acc(), certified, "calibration: the joiner's accumulator differs before the adopt");
        assert!(
            node_b.unfolded_blocks_len() > 0,
            "calibration: the joiner holds an unfolded crawl tail at the adopt (the blocks D-36 would re-fold)"
        );
        assert!(matches!(node_b.instant_sync(bundle_of(&mut node_a)), AdoptOutcome::Adopted(_)), "B jumps by A's bundle");
        assert_eq!(
            node_b.nf_unspent_acc(),
            certified,
            "⛔ DB-269: after an honest adopt the joiner's A_tip is not the origin's — a held block INSIDE the certified past \
             (its crawl's unfolded tail) was re-folded, counted twice"
        );
    }

}

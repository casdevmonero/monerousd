// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_call_tx::ring_tests` — the tests of `dsol_call_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_call_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_call_tx::ring_tests::…`), and `use super::*` reaches `dsol_call_tx`'s items through the node's re-export.

// the imports of `dsol_call_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::contract_state::update_root;
#[allow(unused_imports)]
use crate::contract_state::PathWire;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ContractManifest;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::DSOL_CODE_BYTES_MAX;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES;
#[allow(unused_imports)]
use crate::spend_frontier::Digest4;
#[allow(unused_imports)]
use usdm_decider::dsol_cpu_air::DsolCallProof;
#[allow(unused_imports)]
use usdm_decider::dsol_cpu_air::DsolStatement;
#[allow(unused_imports)]
use usdm_decider::dsol_cpu_air::ProvenCall;
#[allow(unused_imports)]
use usdm_decider::dsol_vm::Effect;

use super::fixtures::*;
use crate::contract_state::{empty_root, ContractStateTree};

#[test]
fn f13_a_follower_rebuilds_the_contract_state_root_from_the_rings_transitions_on_both_nodes() {
    let fee = 50_000_000u64;
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = crate::dsol_deploy_tx::fixtures::deployer();
    let ts = crate::dsol_deploy_tx::fixtures::fund_fee_note(&mut a, &mut [&mut b], 43, 5_000);
    let mut tree = ContractStateTree::new();
    let d = crate::dsol_deploy_tx::fixtures::deploy(&a, &who, &tree, &program(), fee, 43);
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published));
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"f13-ring-deploy"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    tree.insert(d.cid(), d.leaf());
    let ts = fund_fee_note(&mut a, &mut [&mut b], 43, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let t = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 43, next, None);
    assert!(matches!(a.publish_dsol_call(&t), crate::node::AssetSpendOutcome::Published), "the call publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"f13-ring-call"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let _ = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    for (name, n) in [("A", &a), ("B", &b)] {
        let (root, rows, oldest) = n.contract_leaf_updates_from(0);
        assert_eq!(root, n.peg().contract_state_root());
        assert_eq!(rows.len(), 2, "⛔ {name}: the ring holds the deploy and the call, nothing else: {rows:?}");
        assert_eq!(oldest, Some(rows[0].blue));
        assert_eq!(rows[0].pre, empty_root(), "⛔ {name}: the deploy moved the EMPTY root");
        assert_eq!((rows[0].cid, rows[0].leaf), (d.cid(), d.leaf()));
        assert_eq!(rows[1].pre, rows[0].post, "⛔ {name}: the call's pre root is the deploy's post root — one chain");
        assert_eq!(rows[1].leaf, t.manifest.leaf(t.root.stmt.storage_post), "⛔ {name}: the call's leaf is the post-storage leaf");
        assert_eq!(rows[1].post, root, "⛔ {name}: the last transition ends on the node's root");
        let mut follower = ContractStateTree::new();
        assert_eq!(follower.follow(&rows), 2, "⛔ {name}: a follower from the empty tree applies both");
        assert_eq!(follower.root(), root, "⛔ {name}: the follower holds the node's root");
        let mut stranger = ContractStateTree::new();
        stranger.insert([0x5a; 32], crate::spend_frontier::cm_bytes_to_leaf(&[0x33; 32]));
        assert_eq!(stranger.follow(&rows), 0, "⛔ {name}: a replica on another root applies nothing");
        let (_, later, _) = n.contract_leaf_updates_from(rows[1].blue + 1);
        assert!(later.is_empty(), "paging by height returns nothing past the newest entry");
    }
    assert_eq!(a.contract_leaf_updates_from(0).1.iter().map(|u| (u.pre, u.cid, u.leaf, u.post)).collect::<Vec<_>>(),
        b.contract_leaf_updates_from(0).1.iter().map(|u| (u.pre, u.cid, u.leaf, u.post)).collect::<Vec<_>>(),
        "⛔ the two nodes filed different transitions");
}

/// ⭐ §BR-12 A3 VALIDITY WINDOW (FOUND by the F13 layer-2 journey): a call PROVEN in epoch `e` applies when its block lands in
/// epoch `e + 1` — on both nodes, from the block alone — and the fold door still takes it at `e + 2`, while one three epochs
/// stale, or proven for a future epoch, is refused. RED before: the exact-epoch rule refused the honest call carried later.
#[test]
fn f13_a_call_proven_in_the_previous_epoch_applies_and_three_epochs_stale_or_future_is_refused_on_both_nodes() {
    let fee = 25_000_000u64;
    // both nodes keep their band moving as a production prove worker does (DB-396): the pin lays a whole epoch of blocks
    let mk = || crate::node::tests::testnet_party_folding_at_tip().with_band_prover_for_test();
    let (mut a, mut b) = (mk(), mk());
    let who = crate::dsol_deploy_tx::fixtures::deployer();
    let ts = crate::dsol_deploy_tx::fixtures::fund_fee_note(&mut a, &mut [&mut b], 44, 5_000);
    let mut tree = ContractStateTree::new();
    let d = crate::dsol_deploy_tx::fixtures::deploy(&a, &who, &tree, &program(), fee, 44);
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published));
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"f13-epoch-deploy"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    tree.insert(d.cid(), d.leaf());
    let mut ts = fund_fee_note(&mut a, &mut [&mut b], 44, ts);
    let e = crate::oli::EPOCH_BLOCKS;
    // the chain must stand in epoch 1 or later for "the epoch before" to exist: lay empty blocks past the first boundary
    let mut laid = 0u64;
    while a.selected_tip_blue_score().expect("a tip") < e + 1 {
        ts += 500;
        let blk = a.produce(ts, crate::hash::Hash32::hash(&laid.to_le_bytes()), crate::hash::Hash32::hash(b"mc")).expect("A lays an empty block");
        assert!(matches!(b.ingest_block(blk, ts), crate::relay::RelayOutcome::Added(_)), "B grafts the empty block");
        laid += 1;
        assert!(laid < 4 * e, "PRECONDITION: the blue score does not climb past the epoch boundary");
    }
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let carrying = crate::dsol::dsol_block_number(next);
    assert!(carrying >= e, "PRECONDITION: the carrying block stands in epoch 1 or later ({next})");
    // proven for the epoch BEFORE the one the block will carry it in (the window), and for the one AFTER (future)
    let proven_previous = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 44, next - e, None);
    let proven_future = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 44, next + e, None);
    assert_eq!(proven_previous.root.stmt.block_number + e, carrying, "CALIBRATION: the previous call names the epoch before the carrying one");
    for n in [&a, &b] {
        assert_eq!(n.dsol_call_refusal(&proven_previous, crate::respend::MemberDoor::Fold, Some(next)), None, "⛔ the previous epoch's call is refused");
        assert!(n.dsol_call_refusal(&proven_future, crate::respend::MemberDoor::Fold, Some(next)).is_some(), "⛔ a future-epoch call passed the fold door");
        // the same call, carried two epochs after it was proven: still inside the window; three epochs after: stale
        assert_eq!(n.dsol_call_refusal(&proven_previous, crate::respend::MemberDoor::Fold, Some(next + e)), None, "⛔ a call two epochs old is refused (the window is three)");
        assert!(n.dsol_call_refusal(&proven_previous, crate::respend::MemberDoor::Fold, Some(next + 2 * e)).is_some(), "⛔ a three-epochs-stale call passed the fold door");
    }
    // the block carries the previous epoch's call and both nodes apply it
    assert!(matches!(a.publish_dsol_call(&proven_previous), crate::node::AssetSpendOutcome::Published), "the call publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"f13-epoch-call"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let _ = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    let mut expect = tree.clone();
    expect.insert(d.cid(), proven_previous.manifest.leaf(proven_previous.root.stmt.storage_post));
    assert_eq!(a.peg().contract_state_root(), expect.root(), "⛔ A did not apply the previous epoch's call");
    assert_eq!(b.peg().contract_state_root(), expect.root(), "⛔ the PEER did not apply the previous epoch's call");
}

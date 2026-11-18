// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_fee_update_tx::tests` — the tests of `dsol_fee_update_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_fee_update_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_fee_update_tx::tests::…`), and `use super::*` reaches `dsol_fee_update_tx`'s items through the node's re-export.

// the imports of `dsol_fee_update_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::contract_state::update_root;
#[allow(unused_imports)]
use crate::contract_state::PathWire;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ContractManifest;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::DSOL_PUBLISHER_FEE_MAX_ATOMIC;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES;
#[allow(unused_imports)]
use crate::spend_frontier::Digest4;

use super::fixtures::*;
use super::*;
use crate::chain_object::{admissible, Class};
use crate::dsol_call_tx::fixtures as callf;
use crate::dsol_deploy_tx::fixtures as dep;

fn admit(t: &DsolFeeUpdateTx) -> bool {
    admissible(&t.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false)
}

/// ⭐ RED→GREEN PIN (§BR-12 L3) — A FEE CUT APPLIES ON TWO NODES; A CALL ON THE OLD MANIFEST IS REFUSED, ONE ON THE NEW PAYS
/// LESS. RED before: no update class existed, so a deployed fee was forever. The deployer cuts 25 → 10 USDm; A lays it, B
/// grafts the block and folds; both roots equal the tree with the leaf under the new manifest; a call built on the old
/// manifest fails both fold doors (its leaf moved — a caller can never be charged the old, higher fee), and a call built on
/// the new manifest paying 10 USDm applies on both. The same cut again is refused (the leaf already moved).
#[test]
fn dsol_a_fee_cut_applies_on_two_nodes_and_calls_pay_the_new_lower_fee() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = dep::deployer();
    let ts = dep::fund_fee_note(&mut a, &mut [&mut b], 51, 5_000);
    let mut tree = crate::contract_state::ContractStateTree::new();
    let d = dep::deploy(&a, &who, &tree, &callf::program(), 2_500_000_000, 51);
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published));
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-cut-deploy"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    tree.insert(d.cid(), d.leaf());
    assert_eq!(a.peg().contract_state_root(), tree.root(), "PRECONDITION: the deploy applied");
    let storage0 = crate::dsol_deploy_tx::empty_storage_root();
    let cut_tx = cut(&d, &who, &tree, storage0, 1_000_000_000);
    assert!(admit(&cut_tx), "the deployer's cut is admissible");
    assert!(matches!(a.publish_dsol_fee_update(&cut_tx), crate::node::AssetSpendOutcome::Published), "the cut publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-cut"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    let mut expect = tree.clone();
    expect.insert(d.cid(), cut_tx.new_manifest().leaf(storage0));
    assert_eq!(a.peg().contract_state_root(), expect.root(), "⛔ A's root is not the leaf under the new manifest");
    assert_eq!(b.peg().contract_state_root(), expect.root(), "⛔ the PEER's root differs after the cut");
    // the same cut again: the leaf already moved
    for (w, n) in [("A", &mut a), ("B", &mut b)] {
        let out = n.publish_dsol_fee_update(&cut_tx);
        assert!(matches!(out, crate::node::AssetSpendOutcome::Refused(_) | crate::node::AssetSpendOutcome::NotPublished), "⛔ {w} admitted a replayed cut: {out:?}");
    }
    // calls: the old manifest is stale on both; the new one pays 10 USDm
    let ts = callf::fund_fee_note(&mut a, &mut [&mut b], 51, ts);
    let _ = callf::fund_fee_note(&mut a, &mut [&mut b], 52, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let stale = callf::call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 51, next, None);
    assert_eq!(stale.manifest.fee(), 2_500_000_000, "CALIBRATION: built on the OLD manifest");
    assert!(a.dsol_call_refusal(&stale, crate::respend::MemberDoor::Fold, Some(next)).is_some() && b.dsol_call_refusal(&stale, crate::respend::MemberDoor::Fold, Some(next)).is_some(), "⛔ a call on the old (higher) manifest was accepted after the cut");
    let mut d_new = d.clone();
    d_new.publisher_fee_le = cut_tx.new_fee_le; // the deploy as the chain now reads it (the same code, spk, deployer)
    assert_eq!(d_new.manifest(), cut_tx.new_manifest(), "CALIBRATION: the fixture's new manifest is the chain's");
    let fresh = callf::call(&a, &d_new, &expect, usdm_decider::dsol_vm::StorageTrie::default(), 52, next, None);
    assert_eq!(fresh.manifest.fee(), 1_000_000_000);
    assert_eq!(a.dsol_call_refusal(&fresh, crate::respend::MemberDoor::Fold, Some(next)), None, "⛔ a call on the new manifest is refused on A");
    assert_eq!(b.dsol_call_refusal(&fresh, crate::respend::MemberDoor::Fold, Some(next)), None, "⛔ a call on the new manifest is refused on B");
}

/// ⭐ TAMPER PIN (§BR-12 L3) — a RAISE, an EQUAL fee, a signature by a key that is not the deployer, a body changed after
/// signing, and a path on a tree the chain does not hold: each refused (the stateless ones at the pool door too).
#[test]
fn dsol_a_fee_raise_an_equal_fee_a_non_deployer_or_a_changed_body_is_refused_on_both_nodes() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = dep::deployer();
    let ts = dep::fund_fee_note(&mut a, &mut [&mut b], 53, 5_000);
    let mut tree = crate::contract_state::ContractStateTree::new();
    let d = dep::deploy(&a, &who, &tree, &callf::program(), 2_500_000_000, 53);
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published));
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-tamper-deploy"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let _ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    tree.insert(d.cid(), d.leaf());
    let storage0 = crate::dsol_deploy_tx::empty_storage_root();
    let honest = cut(&d, &who, &tree, storage0, 1_000_000_000);
    let fold_door = |n: &crate::node::Node, x: &DsolFeeUpdateTx| n.dsol_fee_update_refusal(x);
    assert!(admit(&honest));
    assert_eq!((fold_door(&a, &honest), fold_door(&b, &honest)), (None, None), "CALIBRATION: the honest cut passes both fold doors");
    let raise = cut(&d, &who, &tree, storage0, 3_000_000_000);
    let equal = cut(&d, &who, &tree, storage0, 2_500_000_000);
    let stranger = {
        let other = dep::deployer();
        let mut s = honest.clone();
        s.deployer_pk = other.pk.clone();
        s.sig = crate::pqauth::ml_dsa_sign(&s.signing_body(), &other.sk).expect("signed by a stranger");
        s
    };
    let changed = {
        let mut c = honest.clone();
        c.new_fee_le = 500_000_000u64.to_le_bytes(); // changed after signing
        c
    };
    for (what, x) in [("raising the fee", &raise), ("keeping the fee equal", &equal), ("signed by a key that is not the deployer", &stranger), ("changed after signing", &changed)] {
        assert!(!admit(x), "⛔ the pool door admitted an update {what}");
        assert!(fold_door(&a, x).is_some() && fold_door(&b, x).is_some(), "⛔ a fold door accepted an update {what}");
        assert!(matches!(a.publish_dsol_fee_update(x), crate::node::AssetSpendOutcome::Refused(_)), "⛔ the publisher took an update {what}");
    }
    let stale = {
        let mut planted = tree.clone();
        planted.insert([0x79u8; 32], crate::contract_state::contract_leaf(&[2u8; 32], usdm_decider::poseidon2_compress::zero_digest(), storage0));
        cut(&d, &who, &planted, storage0, 1_000_000_000)
    };
    assert!(admit(&stale), "CALIBRATION: a stale path is not a blob defect");
    assert!(fold_door(&a, &stale).is_some() && fold_door(&b, &stale).is_some(), "⛔ a fold door moved a leaf from a path that does not open its root");
    assert!(!admissible(&crate::chain_object::frame(Class::DsolFeeUpdate, b"not an update"), 10, 0, false), "garbage is never admitted");
}

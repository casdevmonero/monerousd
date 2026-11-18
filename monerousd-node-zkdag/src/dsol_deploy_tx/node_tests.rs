// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_deploy_tx::tests` — the tests of `dsol_deploy_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_deploy_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_deploy_tx::tests::…`), and `use super::*` reaches `dsol_deploy_tx`'s items through the node's re-export.

// the imports of `dsol_deploy_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::asset_tx::CreationFee;
#[allow(unused_imports)]
use crate::contract_state::contract_leaf;
#[allow(unused_imports)]
use crate::contract_state::insert_root;
#[allow(unused_imports)]
use crate::contract_state::PathWire;
#[allow(unused_imports)]
use crate::spend_frontier::Digest4;

use super::fixtures::*;
use super::*;
use crate::chain_object::{admissible, Class};

fn admit(d: &DsolDeployTx) -> bool {
    admissible(&d.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false)
}

/// ⭐ RED→GREEN PIN (§BR-12 L1) — A DEPLOY APPLIES ON TWO NODES TO ONE CONTRACT-STATE ROOT AND PAYS ITS PRICE INTO THE
/// POOLS, FROM THE BLOCK ALONE. RED before: no `Class::DsolDeploy` existed (the byte was reserved), so nothing could carry
/// a contract onto the chain. A deploys; B grafts the block over the wire shape and folds; both read the same root (the
/// prover's full tree's root for that one leaf), the same pools (+ price + F), both hold the change; a second deploy
/// paying with the SAME fee note is refused on both (the spent set), and a deploy of the same cid cannot exist (the cid
/// is the note's image). TWO-PARTY-REVIEWED: asserted on the PEER from the block it grafted.
#[test]
fn dsol_a_deploy_applies_on_two_nodes_to_one_contract_state_root_and_pays_its_price() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = deployer();
    let ts = fund_fee_note(&mut a, &mut [&mut b], 21, 5_000);
    let tree = crate::contract_state::ContractStateTree::new();
    assert_eq!(a.peg().contract_state_root(), crate::contract_state::empty_root(), "CALIBRATION: a fresh chain holds the empty root");
    let code = crate::dsol::compile(crate::dsol::DsolKind::Generic, "FIX", "fixture").bytecode;
    let d = deploy(&a, &who, &tree, &code, 25_000_000, 21);
    assert!(admit(&d), "the honest paid, signed deploy is admissible");
    let (pa0, pb0) = (a.peg().fee_pools(), b.peg().fee_pools());
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published), "the deploy publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-deploy-fr"), crate::hash::Hash32::hash(b"dsol-deploy-mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)), "B grafts the deploy block");
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    let mut expect = tree.clone();
    expect.insert(d.cid(), d.leaf());
    assert_eq!(a.peg().contract_state_root(), expect.root(), "⛔ A's root is not the tree with this one contract");
    assert_eq!(b.peg().contract_state_root(), expect.root(), "⛔ the PEER's root differs — the deploy did not travel as a function of the chain");
    let (pa, pb) = (a.peg().fee_pools(), b.peg().fee_pools());
    assert_eq!(pa, pb, "⛔ the producer and the peer credited different pools for one deploy");
    let paid = u128::from(d.deploy_price() + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
    assert_eq!(pa.total() - pa0.total(), paid, "⛔ the pools must take exactly the price + the network fee (the deploy's burn)");
    assert_eq!(pb0, pa0);
    let change_cm = <[u8; 32]>::try_from(&d.fee.change_note[..32]).expect("cm");
    assert!(a.holds_record_with_cm(&change_cm) && b.holds_record_with_cm(&change_cm), "⛔ the burn's change is held on both nodes");
    // the same fee note again: a second deploy (a different code) built on the NEW tree — refused by the spent set
    let mut tree2 = tree.clone();
    tree2.insert(d.cid(), d.leaf());
    let again = deploy(&a, &who, &tree2, b"another program", 0, 21);
    assert_eq!(again.cid(), d.cid(), "CALIBRATION: the same fee note derives the same cid");
    assert!(again.self_authorised(), "CALIBRATION: its burn and signature are valid for itself — only the spent set can refuse it");
    for (w, n) in [("A", &mut a), ("B", &mut b)] {
        let out = n.publish_dsol_deploy(&again);
        assert!(
            matches!(out, crate::node::AssetSpendOutcome::Refused(_) | crate::node::AssetSpendOutcome::NotPublished),
            "⛔ {w} admitted a deploy paid with an already-spent note: {out:?}"
        );
    }
    let _ = ts;
}

/// ⭐ TAMPER PIN (§BR-12 L1) — each refused at the pool door AND at both nodes' fold door, the honest deploy admitted:
/// a burn one unit short; a burn lifted from another deploy; a forged deployer signature (another key); a body changed
/// after signing (the fee raised); a STALE path (built on a tree that does not hold what the chain holds); code over the
/// byte cap and a height class over the verifier's ceiling (refused at decode).
#[test]
fn dsol_a_deploy_with_a_short_fee_a_forged_signature_a_stale_path_or_a_bad_bound_is_refused_on_both_nodes() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = deployer();
    fund_fee_note(&mut a, &mut [&mut b], 22, 5_000);
    fund_fee_note(&mut a, &mut [&mut b], 23, 9_000);
    let tree = crate::contract_state::ContractStateTree::new();
    let code = crate::dsol::compile(crate::dsol::DsolKind::Generic, "FIX", "fixture").bytecode;
    let honest = deploy(&a, &who, &tree, &code, 1_000_000, 22);
    // the fold door's READ-ONLY verdict (what `apply_chain_dsol_deploy` judges before it writes)
    let fold_door = |n: &crate::node::Node, x: &DsolDeployTx| n.dsol_deploy_refusal(x, crate::respend::MemberDoor::Fold);
    assert!(admit(&honest), "CALIBRATION: the honest deploy is admissible");
    assert_eq!((fold_door(&a, &honest), fold_door(&b, &honest)), (None, None), "CALIBRATION: the honest deploy passes both fold doors");
    let mut short = honest.clone();
    {
        let mut w = fee_witness(&honest.cid(), 22);
        w.out0_value -= 1;
        w.out1_value += 1;
        let (carrier, cms, _nf, _lc) =
            usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, w.out0_value).expect("the short burn proves");
        short.fee.carrier = carrier;
        short.fee.change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
        short.sig = crate::pqauth::ml_dsa_sign(&short.signing_body(), &who.sk).expect("re-signed");
    }
    let lifted = {
        // another deploy (its own fee note, its own cid) wearing the HONEST deploy's burn carrier: the carrier opens to the
        // honest cid's burn commitment, not this deploy's (the cid is a function of the fee note the carrier spends)
        let mut l = deploy(&a, &who, &tree, b"other program", 0, 23);
        l.fee.carrier = honest.fee.carrier.clone();
        l.sig = crate::pqauth::ml_dsa_sign(&l.signing_body(), &who.sk).expect("re-signed");
        l
    };
    let forged = {
        let other = deployer();
        let mut f = honest.clone();
        f.sig = crate::pqauth::ml_dsa_sign(&f.signing_body(), &other.sk).expect("signed by another key");
        f
    };
    let raised = {
        let mut r = honest.clone();
        r.publisher_fee_le = (r.publisher_fee() + 1).to_le_bytes(); // the body changed after signing
        r
    };
    let stale = {
        let mut planted = tree.clone();
        planted.insert([0x77u8; 32], crate::contract_state::contract_leaf(&[1u8; 32], usdm_decider::poseidon2_compress::zero_digest(), empty_storage_root()));
        let mut s = honest.clone();
        s.state_path = planted.path(&honest.cid()); // a path on a tree the chain does not hold
        s.sig = crate::pqauth::ml_dsa_sign(&s.signing_body(), &who.sk).expect("re-signed");
        s
    };
    for (what, x) in [("one unit short", &short), ("lifted from another deploy", &lifted), ("signed by another key", &forged), ("changed after signing", &raised)] {
        assert!(!admit(x), "⛔ the pool door admitted a deploy {what}");
        assert!(fold_door(&a, x).is_some() && fold_door(&b, x).is_some(), "⛔ a node's fold door accepted a deploy {what}");
        assert!(matches!(a.publish_dsol_deploy(x), crate::node::AssetSpendOutcome::Refused(_)), "⛔ the publisher took a deploy {what}");
    }
    // the stale path passes the stateless door (nothing in the blob is wrong) and is refused at the FOLD, on both
    assert!(admit(&stale), "CALIBRATION: a stale path is not a blob defect — the pool door cannot see the root");
    assert!(fold_door(&a, &stale).is_some() && fold_door(&b, &stale).is_some(), "⛔ a fold door inserted from a path that does not open its root");
    // decode bounds
    let mut big = honest.clone();
    big.code = vec![0u8; DSOL_CODE_BYTES_MAX + 1];
    assert!(DsolDeployTx::decode(&big.encode()).is_none(), "code over the byte cap is refused at decode");
    let mut tall = honest.clone();
    tall.height_class = usdm_decider::dsol_cpu_air::MAX_HEIGHT_LOG2 + 1;
    assert!(DsolDeployTx::decode(&tall.encode()).is_none(), "a height class over the verifier's ceiling is refused at decode");
    assert!(!admissible(&crate::chain_object::frame(Class::DsolDeploy, b"not a deploy"), 10, 0, false), "garbage is never admitted");
}

/// ⭐ FOOTPRINT PIN (§BR-12 L1) — THE NODE HOLDS ONE ROOT, HOWEVER MANY CONTRACTS ARE DEPLOYED. Three deploys in three
/// blocks; after each the node's ledger word is the prover-side tree's root and nothing else about the ledger grew: its
/// serialised size is constant across the deploys (one 32-byte word changes value, no map takes a row). The code rides
/// the block, never the node.
#[test]
fn dsol_the_node_holds_one_root_after_many_deploys() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = deployer();
    let mut ts = 5_000u64;
    let mut tree = crate::contract_state::ContractStateTree::new();
    let mut sizes = Vec::new();
    for (i, tag) in [31u64, 32, 33].into_iter().enumerate() {
        ts = fund_fee_note(&mut a, &mut [&mut b], tag, ts);
        let code = format!("program {i}").into_bytes();
        let d = deploy(&a, &who, &tree, &code, 0, tag);
        assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published), "deploy {i} publishes");
        let blk = a.produce(ts + 500, crate::hash::Hash32::hash(format!("dsol-many-{i}").as_bytes()), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
        assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
        ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
        tree.insert(d.cid(), d.leaf());
        assert_eq!(a.peg().contract_state_root(), tree.root(), "⛔ deploy {i}: A's root is not the tree's");
        assert_eq!(b.peg().contract_state_root(), tree.root(), "⛔ deploy {i}: B's root is not the tree's");
        // the ledger's public words are zeroed first: each deploy pays its price into the pools and a postcard varint widens with
        // the value (MEASURED 466 → 469 → 473 B with them in) — the question here is whether anything ELSE grew
        // … and the root itself is eight KoalaBear limbs whose varint widths follow their values (MEASURED 444 → 443 → 445
        // B with only the fee words zeroed), so it is zeroed too: what is left must be constant, or a row is hiding
        let mut w = a.peg().br_census();
        w.words = [0u64; 25];
        w.contract_state_root = usdm_decider::poseidon2_compress::zero_digest();
        sizes.push(postcard::to_allocvec(&w).map(|v| v.len()).unwrap_or(0));
    }
    assert!(sizes.iter().all(|s| *s == sizes[0]), "⛔ the ledger's carried words grew with the deploys: {sizes:?} — a per-contract row is hiding somewhere");
    assert_eq!(tree.len(), 3);
}

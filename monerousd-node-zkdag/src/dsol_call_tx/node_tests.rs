// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_call_tx::tests` — the tests of `dsol_call_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_call_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_call_tx::tests::…`), and `use super::*` reaches `dsol_call_tx`'s items through the node's re-export.

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
use super::*;
use crate::chain_object::{admissible, Class};
use crate::dsol_deploy_tx::fixtures as dep;

fn admit(t: &DsolCallTx) -> bool {
    admissible(&t.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false)
}

/// A deployed fixture contract on two nodes: (a, b, the deploy, the prover's tree, the next timestamp).
fn deployed(fee: u64, tag: u64) -> (crate::node::Node, crate::node::Node, crate::dsol_deploy_tx::DsolDeployTx, crate::contract_state::ContractStateTree, u64) {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = dep::deployer();
    let ts = dep::fund_fee_note(&mut a, &mut [&mut b], tag, 5_000);
    let mut tree = crate::contract_state::ContractStateTree::new();
    let d = dep::deploy(&a, &who, &tree, &program(), fee, tag);
    assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published), "the deploy publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-call-deploy-fr"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    tree.insert(d.cid(), d.leaf());
    assert_eq!(a.peg().contract_state_root(), tree.root(), "PRECONDITION: the deploy applied");
    (a, b, d, tree, ts)
}

/// ⭐ RED→GREEN PIN (§BR-12 L2) — A PROVEN CALL APPLIES ON TWO NODES: ONE ROOT MOVES, THE PUBLISHER IS PAID. RED before:
/// no `Class::DsolCall` existed, so no contract could be called on chain. The caller's node lays it; the peer grafts the
/// block over the wire shape and folds; both nodes' roots equal the prover's tree with the leaf moved to `storage_post`,
/// both record the publisher's fee note (its commitment a public function of the deploy's words and this call) and the
/// caller's change, the pools took exactly the network fee F, and the call's `Nullifier` effect tag is spent on both.
/// TWO-PARTY-REVIEWED: asserted on the PEER from the block it grafted.
#[test]
fn dsol_a_proven_call_moves_one_contract_state_root_on_two_nodes_and_pays_the_publisher() {
    let fee = 25_000_000u64;
    let (mut a, mut b, d, tree, ts) = deployed(fee, 41);
    let ts = fund_fee_note(&mut a, &mut [&mut b], 41, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let t = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 41, next, None);
    assert_eq!(t.self_authorised(), None, "CALIBRATION: the honest call is self-authorised");
    assert!(admit(&t), "the honest call is admissible");
    let (pa0, pb0) = (a.peg().fee_pools(), b.peg().fee_pools());
    assert!(matches!(a.publish_dsol_call(&t), crate::node::AssetSpendOutcome::Published), "the call publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-call-fr"), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
    assert_eq!(a.dag().get(&blk.id()).map(|n| n.blue_score), Some(next), "CALIBRATION: the call was built for the block that carries it (A3)");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)), "B grafts the call block");
    let _ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    let mut expect = tree.clone();
    expect.insert(d.cid(), d.manifest().leaf(t.root.stmt.storage_post));
    assert_ne!(t.root.stmt.storage_post, t.root.stmt.storage_pre, "CALIBRATION: the program wrote a slot");
    assert_eq!(a.peg().contract_state_root(), expect.root(), "⛔ A's root did not move to the call's post-state");
    assert_eq!(b.peg().contract_state_root(), expect.root(), "⛔ the PEER's root differs — the call did not travel as a function of the chain");
    let (pa, pb) = (a.peg().fee_pools(), b.peg().fee_pools());
    assert_eq!(pa, pb, "⛔ the producer and the peer credited different pools for one call");
    assert_eq!(pa.total() - pa0.total(), u128::from(usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC), "⛔ the pools take exactly the network fee F; the publisher fee goes to the publisher");
    assert_eq!(pb0, pa0);
    let pub_cm = <[u8; 32]>::try_from(&t.fee.publisher_note[..32]).expect("cm");
    let chg_cm = <[u8; 32]>::try_from(&t.fee.change_note[..32]).expect("cm");
    assert!(a.holds_record_with_cm(&pub_cm) && b.holds_record_with_cm(&pub_cm), "⛔ the publisher's fee note is not held on both nodes");
    assert!(a.holds_record_with_cm(&chg_cm) && b.holds_record_with_cm(&chg_cm), "⛔ the caller's change is not held on both nodes");
    // the publisher derives its note from the chain alone: the deploy's words and this call's public seed
    assert_eq!(
        publisher_fee_cm(&d.manifest(), &d.cid(), &t.tx_hash()).map(crate::spend_frontier::leaf_to_cm_bytes),
        Some(pub_cm),
        "the publisher's wallet recomputes the fee note's commitment from public bytes"
    );
    let own = t.own_nullifiers();
    assert_eq!(own.len(), 2, "CALIBRATION: the fee nullifier and one Nullifier effect");
    for nf in &own {
        assert_eq!(a.sparse_spent_verdict(nf), crate::nf_sparse::SpentVerdict::Spent, "⛔ a call tag is not spent on A");
        assert_eq!(b.sparse_spent_verdict(nf), crate::nf_sparse::SpentVerdict::Spent, "⛔ a call tag is not spent on B");
    }
    // the same call again: refused by the spent set on both (the fee note and the effect tag are retired)
    for (w, n) in [("A", &mut a), ("B", &mut b)] {
        assert!(
            matches!(n.publish_dsol_call(&t), crate::node::AssetSpendOutcome::Refused(_) | crate::node::AssetSpendOutcome::NotPublished),
            "⛔ {w} admitted a replayed call"
        );
    }
}

/// ⭐ TAMPER PIN (§BR-12 L2) — each refused at the pool door (stateless) or at both fold doors, the honest call admitted:
/// a fee BELOW the deployed amount (the carrier is honest for the smaller amount, the manifest says more); a manifest that
/// understates the fee (the leaf no longer opens the root); a forged caller signature; a statement whose `tx_hash` is
/// another fee note's; a `block_number` one epoch late; a wrong `storage_pre`; a flipped proof byte; a call whose code is
/// not the deployed one.
#[test]
fn dsol_a_call_paying_less_a_forged_caller_a_wrong_epoch_a_wrong_pre_state_or_a_bad_proof_is_refused_on_both_nodes() {
    let fee = 25_000_000u64;
    let (mut a, mut b, d, tree, ts) = deployed(fee, 42);
    let ts = fund_fee_note(&mut a, &mut [&mut b], 42, ts);
    let _ts = fund_fee_note(&mut a, &mut [&mut b], 43, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let honest = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 42, next, None);
    let fold_door = |n: &crate::node::Node, x: &DsolCallTx| n.dsol_call_refusal(x, crate::respend::MemberDoor::Fold, Some(next));
    assert!(admit(&honest), "CALIBRATION: the honest call is admissible");
    assert_eq!((fold_door(&a, &honest), fold_door(&b, &honest)), (None, None), "CALIBRATION: the honest call passes both fold doors");
    // a fee below the manifest: the carrier proves fee − 1 into the publisher's opening; the object still states the manifest
    let under = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 42, next, Some(fee - 1));
    assert!(!under.fee_carrier_verifies(), "⛔ a fee one unit under the deployed amount verified against the manifest");
    // a manifest that understates the fee to match: the leaf is not the chain's
    let mut lying = under.clone();
    lying.manifest = lying.manifest.with_fee(fee - 1);
    {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        lying.pk_c = pk; // re-sign (the statement's caller no longer matches: that too is a refusal, and the real one is the leaf)
        lying.sig = crate::pqauth::ml_dsa_sign(&lying.signing_body(), &sk).expect("signed");
    }
    assert!(lying.fee_carrier_verifies(), "CALIBRATION: against its OWN lying manifest the under-paying carrier verifies");
    assert!(lying.root_after(a.peg().contract_state_root()).is_none(), "⛔ a leaf built from a lying manifest opened the root");
    let forged = {
        let mut f = honest.clone();
        let (_pk, sk) = crate::pqauth::ml_dsa_keypair();
        f.sig = crate::pqauth::ml_dsa_sign(&f.signing_body(), &sk).expect("signed by another key");
        f
    };
    let wrong_tx = {
        let mut w = honest.clone();
        w.fee = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 43, next, None).fee; // another note's spend
        w
    };
    // built for the NEXT epoch (a future floor) — refused; the PREVIOUS epoch is the validity window's and is pinned below
    let late = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 42, next + crate::oli::EPOCH_BLOCKS, None);
    assert_ne!(late.root.stmt.block_number, crate::dsol::dsol_block_number(next), "CALIBRATION: the late call names another epoch floor");
    let wrong_pre = {
        let mut st = usdm_decider::dsol_vm::StorageTrie::default();
        st.insert_checked(&usdm_decider::poseidon2_compress::lanes_of(&[1, 2]), usdm_decider::dsol_vm::VmVal::Word(9)).expect("a slot");
        call(&a, &d, &tree, st, 42, next, None)
    };
    let bad_proof = {
        let mut p = honest.clone();
        let n = p.root.proof.bytes.len() / 2;
        p.root.proof.bytes[n] ^= 1;
        p
    };
    let other_code = {
        let mut o = honest.clone();
        o.code[0].push(0u8);
        o
    };
    for (what, x, stateless) in [
        ("paying one unit under the deployed fee", &under, true),
        ("signed by another key", &forged, true),
        ("stating another fee note's tx hash", &wrong_tx, true),
        ("built for the next epoch", &late, false),
        ("naming a storage root the chain does not hold", &wrong_pre, false),
        ("carrying a flipped proof byte", &bad_proof, true),
        ("carrying code that is not the deployed one", &other_code, true),
    ] {
        if stateless {
            assert!(!admit(x), "⛔ the pool door admitted a call {what}");
        } else {
            assert!(admit(x), "CALIBRATION: a call {what} is not a blob defect");
        }
        assert!(fold_door(&a, x).is_some() && fold_door(&b, x).is_some(), "⛔ a node's fold door accepted a call {what}");
    }
    assert!(fold_door(&a, &lying).is_some() && fold_door(&b, &lying).is_some(), "⛔ a fold door accepted a call whose manifest understates the fee");
    assert!(!admissible(&crate::chain_object::frame(Class::DsolCall, b"not a call"), 10, 0, false), "garbage is never admitted");
}

/// ⭐ PRIVACY-SHAPE PIN (§BR-12 L3, bridge spec §10 acceptance "a fee-paying transaction byte-shape-identical to one
/// without") — two contracts of ONE code, one free and one charging 25 USDm per call, deployed on one pair; a call of each:
/// the two call objects have the SAME byte length (the fee rides as 8 fixed bytes in the manifest; the fee note is one
/// ordinary output either way), and so do the two deploys. CALIBRATION: the two calls differ in content (cid, fee, note).
#[test]
fn dsol_a_calls_byte_shape_does_not_follow_its_publisher_fee() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let who = dep::deployer();
    let mut ts = 5_000u64;
    let mut tree = crate::contract_state::ContractStateTree::new();
    // both deploys' fee notes first (a fee leg needs its note's folded record)
    ts = dep::fund_fee_note(&mut a, &mut [&mut b], 46, ts);
    ts = dep::fund_fee_note(&mut a, &mut [&mut b], 47, ts);
    // the two deploy objects, both built on the EMPTY tree (a compact path's length follows the tree's population, not the
    // fee — the second deploy to land carries one more sibling), differ only in the fee: equal byte lengths
    let probe_free = dep::deploy(&a, &who, &tree, &program(), 0, 46);
    let probe_paid = dep::deploy(&a, &who, &tree, &program(), 2_500_000_000, 47);
    assert_ne!(probe_free.wire(), probe_paid.wire(), "CALIBRATION: two different deploys");
    assert_eq!(probe_free.wire().len(), probe_paid.wire().len(), "⛔ a deploy's byte length follows its publisher fee");
    let mut deploys = Vec::new();
    for (fee, tag) in [(0u64, 46u64), (2_500_000_000, 47)] {
        let d = dep::deploy(&a, &who, &tree, &program(), fee, tag);
        assert!(matches!(a.publish_dsol_deploy(&d), crate::node::AssetSpendOutcome::Published), "deploy at fee {fee} publishes");
        let blk = a.produce(ts + 500, crate::hash::Hash32::hash(format!("dsol-shape-{tag}").as_bytes()), crate::hash::Hash32::hash(b"mc")).expect("A lays it");
        assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
        ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
        tree.insert(d.cid(), d.leaf());
        deploys.push(d);
    }
    ts = fund_fee_note(&mut a, &mut [&mut b], 46, ts);
    let _ = fund_fee_note(&mut a, &mut [&mut b], 47, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let free = call(&a, &deploys[0], &tree, usdm_decider::dsol_vm::StorageTrie::default(), 46, next, None);
    let paid = call(&a, &deploys[1], &tree, usdm_decider::dsol_vm::StorageTrie::default(), 47, next, None);
    assert_eq!(free.self_authorised(), None);
    assert_eq!(paid.self_authorised(), None);
    assert_ne!(free.wire(), paid.wire(), "CALIBRATION: two different calls");
    // THE FEE-SHAPE CLAIM, over everything the fee can reach. A call's whole wire is NOT a fixed width: its statement, its
    // effects and its proof carry random digests whose postcard varints take 1–5 bytes a lane (MEASURED 2026-11-01:
    // 424,995 vs 424,994, then 325,286 vs 325,284 bytes for two honest calls of the same fee class), a width that follows
    // hashes, never the fee. So the two calls are compared with the SAME proven segment (the free call wearing the paid
    // call's root): what is left to differ is the manifest, the fee words, the notes, the clue and the path — and none of
    // those may follow the fee's magnitude. The manifest alone is also pinned fixed-width.
    let mut free_in_paid_shape = free.clone();
    free_in_paid_shape.root = paid.root.clone();
    assert_eq!(
        free_in_paid_shape.wire().len(),
        paid.wire().len(),
        "⛔ a call's byte length follows its publisher fee (free {} vs 25 USDm {})",
        free_in_paid_shape.wire().len(),
        paid.wire().len()
    );
    assert_eq!(
        postcard::to_allocvec(&free.manifest).expect("encodes").len(),
        postcard::to_allocvec(&paid.manifest).expect("encodes").len(),
        "⛔ the manifest's width follows its fee"
    );
}

/// ⭐ PIN (§BR-12 L2, spec §3) — TWO CALLS ON ONE CONTRACT IN ONE BLOCK: the first applies, the second is refused on the
/// item identically on both nodes (its path opens the pre-state the first call moved), and the block stands. Ethereum's
/// nonce-conflict shape: the loser re-proves on the new state.
#[test]
fn dsol_two_calls_on_one_contract_in_one_block_apply_the_first_and_refuse_the_second_on_both_nodes() {
    let (mut a, mut b, d, tree, ts) = deployed(0, 44);
    let ts = fund_fee_note(&mut a, &mut [&mut b], 44, ts);
    let ts = fund_fee_note(&mut a, &mut [&mut b], 45, ts);
    let next = a.selected_tip_blue_score().expect("a tip") + 1;
    let first = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 44, next, None);
    let second = call(&a, &d, &tree, usdm_decider::dsol_vm::StorageTrie::default(), 45, next, None);
    assert_ne!(first.own_nullifiers()[0], second.own_nullifiers()[0], "CALIBRATION: two fee notes");
    assert!(matches!(a.publish_dsol_call(&first), crate::node::AssetSpendOutcome::Published));
    assert!(matches!(a.publish_dsol_call(&second), crate::node::AssetSpendOutcome::Published), "both are admissible at the pool: the conflict is the fold's");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"dsol-two-calls"), crate::hash::Hash32::hash(b"mc")).expect("A lays both");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)));
    let _ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    // exactly one applied: the root is the tree with ONE moved leaf (both calls write the same post-state, so the root is
    // the same whichever won — the spent set tells which)
    let mut expect = tree.clone();
    expect.insert(d.cid(), d.manifest().leaf(first.root.stmt.storage_post));
    assert_eq!(a.peg().contract_state_root(), expect.root(), "⛔ A's root is not ONE call's post-state");
    assert_eq!(b.peg().contract_state_root(), expect.root(), "⛔ B's root is not ONE call's post-state");
    let spent = |n: &crate::node::Node, t: &DsolCallTx| n.sparse_spent_verdict(&t.own_nullifiers()[0]) == crate::nf_sparse::SpentVerdict::Spent;
    assert_eq!((spent(&a, &first), spent(&a, &second)), (spent(&b, &first), spent(&b, &second)), "⛔ the two nodes disagree about which call won");
    assert!(spent(&a, &first) != spent(&a, &second), "⛔ both calls applied (or neither): {} {}", spent(&a, &first), spent(&a, &second));
}

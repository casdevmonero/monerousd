// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_deploy_tx::fixtures` — the tests of `dsol_deploy_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_deploy_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_deploy_tx::fixtures::…`), and `use super::*` reaches `dsol_deploy_tx`'s items through the node's re-export.

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

use super::*;
use usdm_decider::poseidon2_compress::lanes_of;
use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};

/// A deployer: an ML-DSA-65 keypair and the publisher's ML-KEM-768 keys.
pub(crate) struct Deployer {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub view_ek: Vec<u8>,
    /// The publisher's note owner (its `spk` is the manifest's `publisher_spk`; its `(ask, nk)` spends the fee notes).
    pub owner: usdm_decider::whir_rec_block::NoteOwner,
}

pub(crate) fn deployer() -> Deployer {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (view_ek, _) = crate::pqkem::keypair();
    let owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[0xd5_11, 7, 7, 7]));
    Deployer { pk, sk, view_ek, owner }
}

/// The fee note's witness for a deploy whose cid is `cid` — the deployer's one USDm note of price + F + change.
pub(crate) fn fee_witness(cid: &[u8; 32], tag: u64) -> SpendValidityWitness {
    let price = dsol_deploy_fee_atomic();
    let value_in = price + PROTOCOL_FEE_ATOMIC + 70_000_000;
    SpendValidityWitness {
        value_in,
        owner: NoteOwner::from_test_key(lanes_of(&[0xd5_01, tag, 1, 2])),
        value_out: value_in - PROTOCOL_FEE_ATOMIC,
        fee: PROTOCOL_FEE_ATOMIC,
        lc_blind: lanes_of(&[0xd5_01, tag, 3, 3]),
        out0_value: price,
        out0_opening: deploy_burn_opening(cid),
        out1_value: value_in - PROTOCOL_FEE_ATOMIC - price,
        out1_opening: lanes_of(&[0xd5_01, tag, 4, 4]),
    }
}

/// The fee note's nullifier for `tag` — what the cid derives from. The witness's `out0_opening` depends on the cid, and
/// the nullifier depends only on the input (value, owner), so the two are consistent by construction.
pub(crate) fn fee_nullifier(tag: u64) -> [u8; 32] {
    let w = fee_witness(&[0u8; 32], tag);
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("a well-formed witness states its leaf");
    crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::note_nullifier(&w.owner.nk, &leaf))
}

/// Fund the deploy's fee note on `a` and every peer (one block, folded), as a wallet's note would be.
pub(crate) fn fund_fee_note(a: &mut crate::node::Node, peers: &mut [&mut crate::node::Node], tag: u64, ts: u64) -> u64 {
    let cid = dsol_cid(&fee_nullifier(tag));
    let w = fee_witness(&cid, tag);
    let (note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    for p in peers.iter_mut() {
        assert!(
            matches!(p.ingest_block(funding.clone(), ts + 1), crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: a peer grafts the deploy fee's funding block"
        );
    }
    let ts = crate::node::tests::produce_past_the_fold(a, peers, ts + 20, 20);
    assert!(a.holds_record_with_cm(&cm), "PRECONDITION: the deployer's node holds the fee note's folded record");
    ts
}

/// The fee leg: the burn carrier, the fee note's one-step member leg built from `a`'s own stream, the change and its clue.
pub(crate) fn fee_leg(a: &crate::node::Node, cid: &[u8; 32], tag: u64) -> CreationFee {
    let price = dsol_deploy_fee_atomic();
    let w = fee_witness(cid, tag);
    let (_note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, price).expect("the fee burn proves");
    assert_eq!(cms[0], deploy_burn_cm(cid, price), "CALIBRATION: the burn destroys exactly this deploy's price");
    assert_eq!(crate::spend_frontier::leaf_to_cm_bytes(nf), fee_nullifier(tag), "CALIBRATION: the carrier's nullifier is the one the cid derives from");
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("a well-formed witness states its leaf");
    let (membership_carrier, membership_tip) =
        crate::node::tests::one_step_membership_for_test(a, &cm, leaf, nf, w.lc_blind).expect("the fee note's member step builds");
    let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    let mut change_clue = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/dsol-deploy-change-clue/v1");
    h.update(&tag.to_le_bytes());
    h.update(cid);
    h.finalize_xof().fill(&mut change_clue);
    CreationFee {
        nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
        leaf_commit: crate::spend_frontier::leaf_to_cm_bytes(lc),
        carrier,
        membership_carrier,
        membership_tip,
        change_note,
        change_clue,
    }
}

/// A signed, paid deploy of `code` whose state path is built on `tree` (the prover's replica of the chain's tree).
/// The fixture contract's storage key `k_c` (D4): its commitment is what [`deploy`] records, and every fixture call's blob is
/// encrypted under it.
pub(crate) fn fixture_kc() -> usdm_decider::poseidon2_compress::Digest {
    usdm_decider::poseidon2_compress::hash32_to_digest(blake3::hash(b"fixture k_c").as_bytes())
}

pub(crate) fn deploy(
    a: &crate::node::Node,
    who: &Deployer,
    tree: &crate::contract_state::ContractStateTree,
    code: &[u8],
    publisher_fee_atomic: u64,
    tag: u64,
) -> DsolDeployTx {
    let cid = dsol_cid(&fee_nullifier(tag));
    let fee = fee_leg(a, &cid, tag);
    assert_eq!(dsol_cid(&fee.nullifier), cid, "CALIBRATION: the cid is the fee nullifier's image");
    let mut d = DsolDeployTx {
        code: code.to_vec(),
        height_class: 14,
        name: "fixture contract".into(),
        publisher_fee_le: publisher_fee_atomic.to_le_bytes(),
        publisher_spk: crate::spend_frontier::leaf_to_cm_bytes(who.owner.spk()),
        view_ek: who.view_ek.clone(),
        kc_commit: usdm_decider::poseidon2_compress::digest_to_bytes(&usdm_decider::dsol_blob_air::kc_commit(&fixture_kc())),
        deployer_pk: who.pk.clone(),
        sig: Vec::new(),
        state_path: tree.path(&cid),
        fee,
    };
    d.sig = crate::pqauth::ml_dsa_sign(&d.signing_body(), &who.sk).expect("the deployer signs");
    d
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_call_tx::fixtures` — the tests of `dsol_call_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_call_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_call_tx::fixtures::…`), and `use super::*` reaches `dsol_call_tx`'s items through the node's re-export.

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

use super::*;
use usdm_decider::dsol_vm::{op, StorageTrie, VmCtx};
use usdm_decider::poseidon2_compress::lanes_of;
use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};

/// A program that writes one storage slot, emits one nullifier from THIS call's tx hash (so two calls of one contract emit
/// two tags — one secret twice is one tag, rightly a double spend) and returns: `main: PUSH_BYTES "key"; PUSH_U64 7; SSTORE;
/// TX_HASH; NULLIFIER; RETURN`.
pub(crate) fn program() -> Vec<u8> {
    let hdr = 5 + 8;
    let mut out = vec![usdm_decider::dsol_vm::DSOL_VERSION];
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&usdm_decider::dsol_vm::entry_hash(b"main").to_le_bytes());
    out.extend_from_slice(&(hdr as u32).to_le_bytes());
    out.push(op::PUSH_BYTES);
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(b"key");
    out.push(op::PUSH_U64);
    out.extend_from_slice(&7u64.to_le_bytes());
    out.push(op::SSTORE);
    out.push(op::TX_HASH);
    out.push(op::NULLIFIER);
    out.push(op::RETURN);
    out
}

pub(crate) const HEIGHT_CLASS: u8 = 14;

/// The caller's fee-note witness for a call of `cid` paying `fee` to the publisher's opening. The INPUT is one fixed
/// note (10 USDm + F), whatever the fee, so its nullifier — and the `tx_hash` built on it — is the same for every fee a
/// pin tries.
pub(crate) fn fee_witness(publisher_opening: Digest4, fee: u64, tag: u64) -> SpendValidityWitness {
    let value_in = 10_000_000_000 + PROTOCOL_FEE_ATOMIC;
    assert!(fee <= 10_000_000_000, "the fixture's note covers fees up to 100 USDm");
    SpendValidityWitness {
        value_in,
        owner: NoteOwner::from_test_key(lanes_of(&[0xca_11, tag, 1, 2])),
        value_out: value_in - PROTOCOL_FEE_ATOMIC,
        fee: PROTOCOL_FEE_ATOMIC,
        lc_blind: lanes_of(&[0xca_11, tag, 3, 3]),
        out0_value: fee,
        out0_opening: publisher_opening,
        out1_value: value_in - PROTOCOL_FEE_ATOMIC - fee,
        out1_opening: lanes_of(&[0xca_11, tag, 4, 4]),
    }
}

/// The fee note's nullifier for `tag` (independent of the opening the outputs use).
pub(crate) fn fee_nullifier(tag: u64) -> [u8; 32] {
    let w = fee_witness(usdm_decider::poseidon2_compress::zero_digest(), 0, tag);
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("a well-formed witness states its leaf");
    crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::note_nullifier(&w.owner.nk, &leaf))
}

/// Fund the caller's fee note on `a` and every peer (one block, folded).
pub(crate) fn fund_fee_note(a: &mut crate::node::Node, peers: &mut [&mut crate::node::Node], tag: u64, ts: u64) -> u64 {
    let w = fee_witness(usdm_decider::poseidon2_compress::zero_digest(), 0, tag);
    let (note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    for p in peers.iter_mut() {
        assert!(
            matches!(p.ingest_block(funding.clone(), ts + 1), crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: a peer grafts the call fee's funding block"
        );
    }
    let ts = crate::node::tests::produce_past_the_fold(a, peers, ts + 20, 20);
    assert!(a.holds_record_with_cm(&cm), "PRECONDITION: the caller's node holds the fee note's folded record");
    ts
}

/// A proven, signed, paid call of the deployed contract `d` whose state is `storage` (empty right after the deploy),
/// built on `tree` (the prover's replica), to be carried in the block of blue score `carrying_blue`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn call(
    a: &crate::node::Node,
    d: &crate::dsol_deploy_tx::DsolDeployTx,
    tree: &crate::contract_state::ContractStateTree,
    storage: StorageTrie,
    tag: u64,
    carrying_blue: u64,
    fee_override: Option<u64>,
) -> DsolCallTx {
    let cid = d.cid();
    let manifest = d.manifest();
    let fee_nf = fee_nullifier(tag);
    let tx_hash = usdm_decider::dsol_vm::dsol_tx_hash(&fee_nf);
    let (pk_c, sk_c) = crate::pqauth::ml_dsa_keypair();
    let ctx = VmCtx {
        contract_id: cid,
        block_number: crate::dsol::dsol_block_number(carrying_blue),
        tx_hash,
        caller_wallet: usdm_decider::dsol_vm::dsol_caller_wallet(&pk_c).expect("an ML-DSA-65 key"),
        caller_subaddress: usdm_decider::dsol_vm::dsol_caller_subaddress(&pk_c).expect("an ML-DSA-65 key"),
    };
    let storage_pre = storage.root();
    let (proof, stmt, run) = usdm_decider::dsol_cpu_air::prove_dsol_call_run(
        &d.code,
        "main",
        b"",
        ctx,
        storage,
        1 << HEIGHT_CLASS,
        &mut usdm_decider::dsol_vm::NoHost,
        Some(HEIGHT_CLASS),
    )
    .expect("the fixture call proves");
    // the fee: the deployed amount (or an override, for a tamper) into the publisher's opening for THIS call
    let fee = fee_override.unwrap_or(manifest.fee());
    let opening = publisher_fee_opening(&manifest.publisher_spk, &cid, &tx_hash).expect("a canonical publisher spk");
    let w = fee_witness(opening, fee, tag);
    let (_note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, fee).expect("the fee spend proves");
    assert_eq!(crate::spend_frontier::leaf_to_cm_bytes(nf), fee_nf, "CALIBRATION: the carrier's nullifier is the one tx_hash derives from");
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("leaf");
    let (membership_carrier, membership_tip) =
        crate::node::tests::one_step_membership_for_test(a, &cm, leaf, nf, w.lc_blind).expect("the fee note's member step builds");
    let mut publisher_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    publisher_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[0]));
    let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    let mut t = DsolCallTx {
        cid,
        manifest,
        storage_pre: crate::spend_frontier::leaf_to_cm_bytes(storage_pre),
        state_path: tree.path(&cid),
        pk_c,
        sig: Vec::new(),
        root: ProvenSegment { stmt, proof, effects: run.effects.clone() },
        libraries: Vec::new(),
        code: vec![d.code.clone()],
        fee: CallFee {
            nullifier: fee_nf,
            leaf_commit: crate::spend_frontier::leaf_to_cm_bytes(lc),
            carrier,
            membership_carrier,
            membership_tip,
            publisher_note,
            change_note,
            change_clue: vec![0x5du8; crate::peg_in_tx::OWNER_CLUE_MAX],
        },
        storage: {
            // D4: the contract's whole post-state, encrypted under the fixture key with a salt fresh to this proof, and
            // proven from the empty trie
            let salt = *blake3::hash(&[tag.to_le_bytes(), carrying_blue.to_le_bytes()].concat()).as_bytes();
            let writes = usdm_decider::dsol_blob_air::writes_between(&StorageTrie::default(), &run.storage);
            let (bp, _, blob) = usdm_decider::dsol_blob_air::prove_blob(
                &crate::dsol_deploy_tx::fixtures::fixture_kc(),
                &StorageTrie::default(),
                &usdm_decider::dsol_vm::str_digest(&tx_hash),
                &usdm_decider::poseidon2_compress::hash32_to_digest(&salt),
                &writes,
                HEIGHT_CLASS,
            )
            .expect("an honest blob proves");
            crate::dsol_call_tx::StorageBlob { salt, blob, proof: bp.bytes }
        },
    };
    t.sig = crate::pqauth::ml_dsa_sign(&t.signing_body(), &sk_c).expect("the caller signs");
    t
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `wrapped_asset_tx::tests` — the tests of `wrapped_asset_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `wrapped_asset_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`wrapped_asset_tx::tests::…`), and `use super::*` reaches `wrapped_asset_tx`'s items through the node's re-export.

// the imports of `wrapped_asset_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::chain_object::decode_exact;
#[allow(unused_imports)]
use crate::chain_object::frame;
#[allow(unused_imports)]
use crate::chain_object::unframe;
#[allow(unused_imports)]
use crate::chain_object::Class;
#[allow(unused_imports)]
use crate::psm::MintAttestor;
#[allow(unused_imports)]
use serde::Deserialize;
#[allow(unused_imports)]
use serde::Serialize;

use super::*;
use crate::bridge::Custodian;

fn header() -> WrappedAssetRegisterHeader {
    WrappedAssetRegisterHeader {
        epoch_id: 3,
        asset_id: 77,
        prev_ratio_bps: 0,
        ratio_bps: 15_000,
    }
}

fn one_attestor(h: &WrappedAssetRegisterHeader) -> Vec<MintAttestor> {
    let msg = crate::peg::PegLedger::wrapped_register_msg(
        h.epoch_id,
        h.asset_id,
        h.prev_ratio_bps,
        h.ratio_bps,
    );
    vec![Custodian::generate(&[41u8; 32]).attest(&msg)]
}

/// The wire is ONE encoding, and a tolerated tail is refused — the shared `decode_exact` contract.
/// Without it, `encode(x) || junk` would decode to the SAME object under a DIFFERENT content id.
#[test]
fn the_wire_round_trips_under_its_own_class_and_refuses_a_trailing_tail() {
    let h = header();
    let att = one_attestor(&h);
    let blob = wire(&h, &att);
    let (class, payload) = unframe(&blob).expect("it frames");
    assert_eq!(class, Class::WrappedAssetRegister, "it frames under its own class");
    let (got, got_att) = decode(payload).expect("it decodes");
    assert_eq!(got, h, "the header survives the round trip");
    assert_eq!(got_att.len(), 1, "the attestation survives the round trip");

    let mut tailed = payload.to_vec();
    tailed.push(0u8);
    assert!(
        decode(&tailed).is_none(),
        "a tolerated tail would let one object wear two content ids"
    );
}

/// The decode is where this class's bounds live: no attestors, or a sub-1:1 target, never becomes an
/// object at all — so neither can reach a signature verify or the door.
#[test]
fn the_decode_refuses_an_unattested_or_sub_one_to_one_registration() {
    let h = header();
    let att = one_attestor(&h);
    let no_att = encode(&h, &[]);
    assert!(decode(&no_att).is_none(), "an unattested registration is not an object");

    let sub = WrappedAssetRegisterHeader { ratio_bps: 9_999, ..h };
    let sub_bytes = encode(&sub, &att);
    assert!(
        decode(&sub_bytes).is_none(),
        "a sub-1:1 ratio must be REFUSED at the wire, never silently clamped to a value nobody signed"
    );
}

/// ⛔⛔⛔ THE PIN THAT PROVES THE FIX: A SECOND NODE DERIVES THE RATIO FROM THE OBJECT, AND A FORGED
/// ATTESTATION MOVES NOTHING ON IT.
///
/// TWO PARTIES, because that is the only place the defect existed. Before this class, node A took a
/// ratio from its own socket and node B never learned it, so the two minted against different numbers
/// and neither could tell. This asserts what the PEER HOLDS — the rule this tree learned when a DEX
/// fill's burn stayed local and the maker's lot was paid a second time: a test that asserts on what a
/// call RETURNS proves nothing.
///
/// RED WITHOUT THE FIX: there is no object to deliver at all — the ratio could only be set by calling
/// the ledger directly on each node in turn.
#[test]
fn a_second_node_derives_the_ratio_from_the_block_object_and_refuses_a_forged_one() {
    use crate::node::tests::genesis_block;
    use crate::node::Node;
    const ASSET: u32 = 77;

    // A bonded quorum on BOTH nodes — the same charter, admitted independently by each party, exactly
    // as a real mesh admits bond transactions. Without it `threshold_ok` is fail-closed (`total > 0`),
    // which is itself the right posture: no quorum, no ratio.
    let custodians: Vec<Custodian> = (0..3u8).map(|i| Custodian::generate(&[60 + i; 32])).collect();
    let mut a = Node::new(genesis_block()).unwrap();
    let mut b = Node::new(genesis_block()).unwrap();
    for n in [&mut a, &mut b] {
        for c in &custodians {
            n.admit_validator(c.id(), 5_000, 0).unwrap();
        }
    }
    assert_eq!(
        b.peg().wrapped_asset_ratio_bps(ASSET),
        None,
        "precondition: the peer has never heard of this asset"
    );

    // A publishes the registration: >=2/3 of the bonded set attest the EXACT transition 0 -> 15000.
    let h = WrappedAssetRegisterHeader {
        epoch_id: 1,
        asset_id: ASSET,
        prev_ratio_bps: 0,
        ratio_bps: 15_000,
    };
    let msg = crate::peg::PegLedger::wrapped_register_msg(
        h.epoch_id,
        h.asset_id,
        h.prev_ratio_bps,
        h.ratio_bps,
    );
    let attestors: Vec<MintAttestor> = custodians.iter().map(|c| c.attest(&msg)).collect();
    let blob = wire(&h, &attestors);

    // THE PUBLISHER PATH IS LIVE: the tx the RPC now builds is one this node's own admission gate
    // ACCEPTS. Without this the route could publish an object every node refuses, which would read as
    // "the ratio silently stopped working" rather than as a refusal.
    let bits = a.required_stamp_bits();
    let admit = a.ingest_tx(as_pq_tx(&h, &attestors, bits));
    eprintln!("[wat] ingest_tx verdict for the published registration: {admit:?}");
    assert!(
        admit.is_ok(),
        "the published registration tx must be admissible, or the route publishes into a void: {admit:?}"
    );

    // THE PEER applies the object through the REAL block-apply seam — no RPC, no local command.
    assert_eq!(
        crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(&mut b, &blob, &crate::pqauth::MlDsaVerifier),
        RegisterApply::Registered,
        "the peer must adopt a >=2/3-attested registration carried by a block"
    );
    assert_eq!(
        b.peg().wrapped_asset_ratio_bps(ASSET),
        Some(15_000),
        "⛔ THE WHOLE POINT: a node that only ever saw the OBJECT derives the ratio the chain set"
    );

    // A FORGED registration — the same asset, a ratio the attestors never signed. The signatures are
    // real but they authorise a DIFFERENT transition, so the tally fails and nothing moves.
    let forged = WrappedAssetRegisterHeader { ratio_bps: 10_000, prev_ratio_bps: 15_000, ..h };
    let forged_blob = wire(&forged, &attestors);
    let outcome = crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(&mut b, &forged_blob, &crate::pqauth::MlDsaVerifier);
    // NON-VACUITY: the reason is named, not just the refusal. `prev_ratio_bps` here MATCHES what the
    // peer holds, so the commitment chain passes and the only thing left to refuse it is the bonded
    // tally — this asserts the tally actually ran rather than the object failing for some other reason.
    assert_eq!(
        outcome,
        RegisterApply::Refused(crate::peg::PegOutcome::InsufficientThreshold),
        "⛔ a ratio nobody attested must be refused BY THE TALLY"
    );
    assert_eq!(
        b.peg().wrapped_asset_ratio_bps(ASSET),
        Some(15_000),
        "⛔ a refused registration must leave the peer's ratio exactly as it was"
    );

    // AND A REPLAY of the original object, now that the peer has moved past it: its attested `prev` is
    // 0, the peer holds 15000, so the commitment chain refuses it with no stored replay key at all.
    let replayed = crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(&mut b, &blob, &crate::pqauth::MlDsaVerifier);
    assert!(
        matches!(replayed, RegisterApply::Refused(crate::peg::PegOutcome::Replay)),
        "⛔ a replayed registration must be refused by the commitment chain, got {replayed:?}"
    );
}

/// A blob of another class is not this object — the class is READ, never guessed.
#[test]
fn a_blob_of_another_class_is_not_a_registration() {
    let other = frame(Class::OrderPost, b"not-a-registration");
    assert!(
        unframe(&other).map(|(c, _)| c) != Some(Class::WrappedAssetRegister),
        "the class byte decides, and it says OrderPost"
    );
}

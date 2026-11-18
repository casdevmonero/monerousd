// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::dir_entry_tx` that reads or moves the node: its apply at the fold and the two test
//! helpers that drive a node, placed here (lane goods, 2026-11-11) in the shape of the node split's stage A so the object module
//! itself never reaches up into the node and can live in a crate of its own. The module's own doc (`dir_entry_tx.rs`) holds the
//! finding, the price, the §9.6 answers and the cons; nothing here changes them.

#![allow(unused_imports)]
use crate::asset_tx::CreationFee;
use crate::dir_entry_tx::*;
use crate::directory::DirEntry;

/// ⭐ THE FOLD DOOR: every node, in canonical order, from the block's bytes alone. The entry's signature and binding, the
/// burn carrier, the fee note's membership (`MemberDoor::Fold`), then the directory's own rule (first come, owner
/// continuity) applied in the block's journaled step, so a rewind un-folds it with its block.
///
/// ⛔ A CARRIED, VALID, PAID ENTRY ALWAYS BURNS ITS FEE, WHETHER OR NOT THE DIRECTORY WRITES IT. The first build refused
/// an entry the directory's rule did not write (a name another claim took first) and relied on "an object refused at
/// its fold spends nothing". MEASURED three times on three real nodes, 2026-11-10 22:24 to 2026-11-11 01:05: two
/// wallets claimed one name within the fold lag, the loser's entry was refused here, and a cold restore of the loser's
/// seed read 0: its whole fee note (300000000 atomic) was certified spent and its change was gone, though the same case
/// passes in-process (`db274_two_nodes_that_apply_two_registrations_of_one_name…`). That is hole A-F22 in the fold's
/// refused-object path, not this class's to fix; this class no longer TAKES that path for anything an honest wallet
/// can do. What an honest wallet can lose is now exactly the fee it was shown: the price is burned and the change
/// returns in both fold orders, so a re-ordering of the step changes who owns the name and never what anyone holds.
/// The pool door still refuses, before anything is carried, an entry that would not be written (`Node::publish_dir_entry`),
/// so the fee is spent on an unwritten entry only in a true race. BORROWED: a transaction that is mined pays its fee
/// whether or not its call succeeds (Ethereum gas; an ENS registration that loses a race).
/// cons: the loser of a name race pays its claim's fee (0.08 USDm for a name) and gets no name; the wallet says so
/// before the claim. A refusal that remains (below) is on the item only.
pub fn apply_chain_dir_entry(node: &mut crate::node::Node, blob: &[u8]) -> DirEntryApply {
    let Some((crate::chain_object::Class::DirEntry, payload)) = crate::chain_object::unframe(blob) else {
        return DirEntryApply::NotDirEntry;
    };
    let Some(t) = DirEntryTx::decode(payload) else {
        return DirEntryApply::Refused("the payload is not a paid directory entry");
    };
    if let Some(why) = node.dir_entry_refusal(&t, crate::respend::MemberDoor::Fold) {
        return DirEntryApply::Refused(why);
    }
    let written = node.apply_dir_entry_at_fold(&t.entry);
    if written && !t.art.is_empty() {
        // the picture the entry names, kept by its digest (the decode held: these bytes hash to `entry.pic`)
        let _ = node.keep_dir_pic(&t.art);
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.fee.change_note);
    if written {
        DirEntryApply::Applied
    } else {
        DirEntryApply::Paid
    }
}

/// TEST — lay the USDm note that `entry`'s fee witness (`tag`) spends on `a`, graft it on every peer, and fold it past the
/// fold depth on every party. Returns the timestamp to continue from.
#[cfg(test)]
pub(crate) fn fund_dir_fee_note_for_test(
    a: &mut crate::node::Node,
    peers: &mut [&mut crate::node::Node],
    entry: &DirEntry,
    tag: u64,
    ts: u64,
) -> u64 {
    let w = dir_fee_witness_for_test(entry, tag);
    let (funded, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &funded);
    for p in peers.iter_mut() {
        assert!(
            matches!(p.ingest_block(funding.clone(), ts + 1), crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: a peer grafts the directory fee's funding block"
        );
    }
    let ts = crate::node::tests::produce_past_the_fold(a, peers, ts + 20, 20);
    assert!(a.holds_record_with_cm(&cm), "PRECONDITION: the payer's node holds the folded record of the fee's funding");
    ts
}

/// TEST — `entry` as the paid object its owner's wallet builds: the real bond-validity carrier (out0 = exactly the entry's
/// price into [`dir_burn_cm`], out1 = change, the network fee welded), the one-step membership from `a`'s record, the
/// change output and a change clue. The funding `tag` names must be laid and folded on `a` first.
#[cfg(test)]
pub(crate) fn paid_dir_entry_for_test(a: &crate::node::Node, entry: DirEntry, tag: u64) -> DirEntryTx {
    let wire = entry.to_wire();
    let price = dir_entry_fee_atomic(wire.len());
    let w = dir_fee_witness_for_test(&entry, tag);
    let (_funded, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, price).expect("the fee burn proves");
    assert_eq!(cms[0], dir_burn_cm(&dir_entry_id(&wire), price), "CALIBRATION: the burn destroys exactly this entry's price");
    let spent = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("a well-formed witness");
    let (membership_carrier, membership_tip) =
        crate::node::tests::one_step_membership_for_test(a, &cm, spent, nf, w.lc_blind).expect("the member step builds");
    let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    let mut change_clue = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/dir-entry-change-clue/v1");
    h.update(&tag.to_le_bytes());
    h.finalize_xof().fill(&mut change_clue);
    DirEntryTx {
        entry,
        fee: CreationFee {
            nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
            leaf_commit: crate::spend_frontier::leaf_to_cm_bytes(lc),
            carrier,
            membership_carrier,
            membership_tip,
            change_note,
            change_clue,
        },
        art: Vec::new(),
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::fam_c_door_audit_20260907_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! ⛔⛔⛔ FAMILY C DOOR AUDIT (charter §9.6, 2026-09-07) — NOTE / RECORD / SERVED-PAGE INGRESS.
//!
//! These pins are the ADVERSARIAL half of the six-question audit of the record/sidecar ingress
//! doors. They are the sibling hunt of the block-locator PoW omission: a second admission path
//! that carried the parse and the apply across but not the ACCEPTANCE VERDICT.
//!
//! The door under test is the receive/deletion SIDECAR fold. Two ingress paths reach it —
//! `apply_backfilled_notes` (the kind-0/1 ledger page) and `adopt_sidecar_row` (the kind-5
//! sidecar page) — and both end at the SAME shared sink:
//!     adopt_ledger_sidecars_recv / adopt_ledger_sidecars_del  →  fold_record_sidecars_if_ready
//!
//! `fold_record_sidecars_if_ready` derives the copath from THIS NODE'S OWN MAP
//! (`uns_copath_from_map`), so `UnspentNoteAcc::receive`'s documented fail-closed property —
//! "a forged copath cannot conjure one into existence" — cannot fire: a locally-derived copath
//! reproduces the live root BY CONSTRUCTION for every commitment not already present. The only
//! thing standing between a served 32-byte value and membership of the unspent set is therefore
//! the caller's admission verdict, and neither caller enforces one on the sidecar bytes.
//!
//! Question 6 (PARITY) names the door these parallel: `accept_fetched_record`, which binds a
//! served record's folded root to a root this chain committed (the filed per-ordinal root, the
//! `note_membership_step_new_acc` relation, or `span_closes_to_target`). NONE of those three
//! checks is carried onto the sidecar bytes on either path.
//!
//! A RED here is the fix spec, not a bug report. It stays red until the shared sink refuses.
use super::tests::genesis_block;
use super::*;

/// A victim node that has recorded one real credit note and is READY to serve — the ordinary
/// steady state, not a recovery corner.
fn victim_with_one_real_note(tag: &[u8]) -> (Node, [u8; 32]) {
    let mut n = Node::new_folding_at_tip_for_test(genesis_block()).expect("victim node");
    let honest_cm = *blake3::hash(&[b"famc-honest-note".as_slice(), tag].concat()).as_bytes();
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&honest_cm);
    n.pending_credit_notes.push(note);
    let _ = n
        .produce(
            5_000,
            Hash32::hash(&[b"famc-fr".as_slice(), tag].concat()),
            Hash32::hash(b"famc-mc"),
        )
        .expect("the block that folds the credit note");
    assert!(n.serve_ready(), "precondition: the victim is READY to serve");
    (n, honest_cm)
}

/// ⛔⛔⛔ THE RIDS A REAL ATTACKER WOULD CHOOSE — NEVER A MAGIC CONSTANT.
///
/// Every pin below used to name the attacker's record `0xDEAD_BEEF_0000_000N`: a large, obviously
/// foreign address that lands in NO map this node keeps. A door keyed on a coordinate resolver is
/// only tested by coordinates that reach the resolver's other branches — and that constant reached
/// none of them, which is how five green pins stood beside an open door (MEASURED 2026-09-08: with
/// `rid = 0xDEAD_BEEF_0000_0003` the victim's note survived; with `rid = <a live ordinal>` it did
/// not). `rid` is peer-chosen wire data, so the attacker picks whatever is cheapest.
///
/// These are the four shapes that cost an attacker nothing to compute:
///   * ADJACENT ORDINAL — a live ordinal this node holds a chain-bound record at. Ordinals are
///     small and dense; naming one is guessing an integer under 100.
///   * ORDINAL TOP / TOP+1 — the position the next honest record will occupy.
///   * THE HONEST RESOLVER'S OWN ANSWER — the address `da_record_id_for_block` derives for a block
///     every peer has seen. Public chain structure: the attacker computes it exactly.
///   * NEAR-MISS SUB-SLOT — a sibling sub-address of that same real block (`sub = 1`), one the
///     record writer itself can produce and which differs from the real one by a small offset.
/// Each pin runs against ALL of them, so no single coordinate can pass on the others' behalf.
fn peer_plausible_rids(n: &Node) -> Vec<(&'static str, u64)> {
    let mut out: Vec<(&'static str, u64)> = Vec::new();
    // A live ordinal whose record this node holds and has marked CHAIN-BOUND — the shape that
    // borrowed an honest record's authority through the deleted `record_row_key`.
    let mut ords: Vec<(u64, u64)> = n.da_ord_rev_mem.iter().map(|(o, a)| (*o, *a)).collect();
    ords.sort_unstable();
    for (o, a) in &ords {
        if n.record_bytes_are_chain_bound(RecAddr::local(*a)) {
            out.push(("adjacent live chain-bound ordinal", *o));
            break;
        }
    }
    out.push(("ordinal top", n.da_record_ordinal_top()));
    out.push(("ordinal top + 1", n.da_record_ordinal_top().saturating_add(1)));
    // The honest resolver's OWN answer for a block this chain really holds, and its near-miss
    // sibling sub-slot. Both are pure derivations of a public block id.
    if let Some(tip) = n.relay.dag().tips().first().copied() {
        out.push((
            "the honest resolver's own answer for a real block",
            Node::da_record_id_for_block(&tip, 0),
        ));
        out.push((
            "near-miss sibling sub-slot of that same real block",
            Node::da_record_id_for_block(&tip, 1),
        ));
    }
    assert!(
        out.len() >= 4,
        "the fixture must offer at least four peer-plausible coordinates, not one constant"
    );
    out
}

fn forged_entry(rid: u64) -> crate::protocol::LedgerRecord {
    crate::protocol::LedgerRecord::assemble(
        rid,
        (
            vec![7u8; crate::cover::PQ_NOTE_BYTES], // garbage body: reaches NO committed root
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        Some(crate::cover::TEST_COVER_KEY), // a forged entry wears a key like any page entry; its bytes still reach no root
    )
}

/// ⛔ HOLE C-H4 (CANDIDATE) — DOES THE REFUSED RECORD BECOME ITS OWN AUTHORITY?
///
/// `apply_backfilled_notes` writes a refused entry's bytes via `record_note_payload_at`, and
/// `da_block_root_at_ordinal_derive` (node.rs:7407) DERIVES the "committed" root for an ordinal
/// from `da_record_notes(ordinal)` — the bytes this node holds. If the write above lands under a
/// coordinate the derive can reach, the SECOND offer of the same forged record finds
/// `want_root == got` and the verified-fetch door ACCEPTS what it refused a moment earlier:
/// circular authority, the same shape as the measured fetch-and-discard raw-map read.
/// This pin measures whether the round-trip guard in the derive actually blocks that.
#[test]
fn fam_c_h4_a_refused_record_must_not_become_its_own_root_authority() {
    for (shape, attacker_rid) in peer_plausible_rids(&victim_with_one_real_note(b"h4").0) {
        let (mut victim, _honest) = victim_with_one_real_note(b"h4");
        let body = vec![7u8; crate::cover::PQ_NOTE_BYTES];
        if victim.accept_fetched_record(attacker_rid, &body, Some(crate::cover::TEST_COVER_KEY)) {
            continue; // this coordinate is genuinely admissible — not an attack, nothing to pin
        }
        // The pump applies the page regardless (hole C-H1), writing these bytes into the row.
        victim.apply_backfilled_notes(&[forged_entry(attacker_rid)]);
        assert!(
            !victim.accept_fetched_record(attacker_rid, &body, Some(crate::cover::TEST_COVER_KEY)),
            "⛔ CIRCULAR AUTHORITY at rid shape '{shape}' (rid={attacker_rid}): the \
             verified-fetch door ACCEPTED on the second offer a record it refused on the first, \
             because apply_backfilled_notes had meanwhile stored the attacker's own bytes and \
             the root is DERIVED from them."
        );
    }
}


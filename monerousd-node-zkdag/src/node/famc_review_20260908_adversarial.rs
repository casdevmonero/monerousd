// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::famc_review_20260908_adversarial` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! ⛔⛔⛔ ADVERSARIAL REVIEW OF THE FAMILY C FIX (2026-09-08) — FRESH ATTACKS, NOT THE PINNED ONES.
//!
//! The lane's four pins all name the attacker record by a LARGE, obviously-foreign address
//! (`0xDEAD_BEEF_0000_000N`). The fix keys its whole verdict on `Node::record_row_key`, a
//! coordinate resolver whose branch 2 reads `da_ord_rev_mem` — the ORDINAL→address map. Ordinals
//! are small dense integers and record addresses are 56-bit block-id folds times
//! `DA_RECORDS_PER_HEIGHT`, so the two key spaces are disjoint in practice and no pinned rid ever
//! lands in the ordinal one. `rid` is peer-chosen wire data (`decode_sidecar_page` →
//! `on_sidecar_page` → `adopt_sidecar_row`, node_runtime.rs:3854), so an attacker simply names a
//! SMALL rid. These two tests are the variants the lane did not construct.
//!
//! ROOT-LAYER: these are REVIEW PINS, not a fix — they are written at the door the fix installed
//! (`fold_record_sidecars_inner` / `ordinal_authority_is_provisional`), which is where the
//! authority verdict is PRODUCED, so a repair has to move the resolver itself rather than any of
//! its readers.
//! MEASURED 2026-09-08 (static, the tree these were written against): ONE `rid` was resolved by
//! FOUR different key preferences — `record_row_key` preferred `da_mem[rid]` then
//! `da_ord_rev_mem[rid]`; `da_recv_wire` and `da_del_wire` each preferred their own sidecar map;
//! `adopt_ledger_sidecars_recv/_del` filed the served bytes under the RAW rid with no resolution
//! at all; `sidecar_addr` had a fifth probe order.
//!
//! ⭐⭐⭐ CLOSED 2026-09-08, AT THE RESOLVER, NOT AT ANY READER. `record_row_key` is DELETED (see
//! the note at its old site); the two coordinate spaces are now separate TYPES ([`rec_coord`]);
//! the admission path takes a peer's `rid` as an address and never tries it as an ordinal; the
//! one crossing is `Node::record_addr_at_ordinal`; and `ordinal_authority_is_provisional` takes
//! a `RecOrd`, so `da_mem.contains_key(&ordinal)` no longer compiles — MEASURED as a NEGATIVE
//! COMPILE, not asserted: re-inserting that one line yields
//! `node.rs:7168: error[E0308]: mismatched types: expected &u64, found &RecOrd`.
//! The four family C pins these audit now run against a table of PEER-PLAUSIBLE rids
//! (`peer_plausible_rids`) — adjacent live ordinal, ordinal top, top+1, the honest resolver's own
//! answer for a real block, and that block's near-miss sibling sub-slot — instead of one magic
//! constant, so no single coordinate can pass on the others' behalf again.
//!
//! ⚠️ EXECUTION STATUS, STATED RATHER THAN IMPLIED (2026-09-08): this module COMPILES clean under
//! `cargo check --lib --tests`, and the key-space claim above is a real negative-compile
//! measurement. The pins themselves were NOT executed in the session that wrote this fix: a
//! concurrent lane left `peg.rs::{is_liquidated, liquidate_confidential,
//! liquidation_threshold_bps, reserve_hwm_commit, verify_revaluation, wrapped_asset_hwm_commit}`
//! built-and-unwired, and `finish-before-testing-guard` correctly refuses every `cargo test` in
//! the tree while that stands. Wiring or deleting another lane's work to unblock a test run is
//! exactly the shape that guard exists to stop, so it was not done. FIRST ACTION FOR WHOEVER
//! PICKS THIS UP: `cargo test --lib famc_` once that lane lands, and replace this paragraph with
//! the run's numbers.
//! MUST-STAY-GREEN: the 4 family C pins and their control, and every honest fold that reaches
//! `fold_record_sidecars_if_ready` — these tests add no production code and change no behaviour.
use super::tests::genesis_block;
use super::*;

fn victim_with_one_real_note(tag: &[u8]) -> (Node, [u8; 32]) {
    let mut n = Node::new_folding_at_tip_for_test(genesis_block()).expect("victim node");
    let honest_cm = *blake3::hash(&[b"famc-rev-note".as_slice(), tag].concat()).as_bytes();
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&honest_cm);
    n.pending_credit_notes.push(note);
    let _ = n
        .produce(
            5_000,
            Hash32::hash(&[b"famc-rev-fr".as_slice(), tag].concat()),
            Hash32::hash(b"famc-rev-mc"),
        )
        .expect("the block that folds the credit note");
    assert!(n.serve_ready(), "precondition: the victim is READY");
    (n, honest_cm)
}

/// An ordinal whose record this node holds and has marked CHAIN-BOUND, and which is NOT itself a
/// key of `da_mem` — i.e. exactly what `record_row_key`'s ordinal branch resolves.
fn a_chain_bound_ordinal(n: &Node) -> u64 {
    let cands: Vec<(u64, u64)> = n
        .da_ord_rev_mem
        .iter()
        .map(|(o, a)| (*o, *a))
        .collect();
    for (o, a) in cands {
        if !n.da_mem.contains_key(&o) && n.record_bytes_are_chain_bound(RecAddr::local(a)) {
            return o;
        }
    }
    panic!("the victim holds no chain-bound record at any ordinal — fixture is wrong");
}

/// ⛔ FRESH VARIANT OF C-H4 — THE SAME KEY-SPACE CONFUSION, RUN THE OTHER WAY.
///
/// `ordinal_authority_is_provisional(ord)` asks `da_mem.contains_key(&ord)` before anything else.
/// `da_mem` is keyed by record ADDRESS, and `apply_backfilled_notes` writes a refused page
/// entry's bytes at the peer-chosen `rid` verbatim (`record_note_payload_at` →
/// `record_note_payload_inner` with `exact_addr`). So one refused page entry named
/// `rid = <a live ordinal>` plants a PROVISIONAL row in the ordinal key space and suppresses that
/// ordinal's honest authority — the derived root AND the committed membership accumulator — for
/// every later record admission.
#[test]
fn famc_rev_a_refused_page_entry_named_by_an_ordinal_poisons_that_ordinals_authority() {
    let (mut victim, _honest) = victim_with_one_real_note(b"rev2");
    let bound_ord = a_chain_bound_ordinal(&victim);
    assert!(
        !victim.ordinal_authority_is_provisional(RecOrd::new(bound_ord)),
        "precondition: the honest ordinal's authority is not provisional"
    );
    let entry = crate::protocol::LedgerRecord::assemble(
        bound_ord,
        (
            vec![7u8; crate::cover::PQ_NOTE_BYTES],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        Some(crate::cover::TEST_COVER_KEY),
    );
    victim.apply_backfilled_notes(&[entry]);
    assert!(
        !victim.ordinal_authority_is_provisional(RecOrd::new(bound_ord)),
        "⛔ AUTHORITY POISONING: one REFUSED page entry named `rid = {bound_ord}` (a live \
         ordinal) planted a provisional row in `da_mem` under the ordinal key space, so this \
         node now refuses its own committed authority at that ordinal."
    );
}


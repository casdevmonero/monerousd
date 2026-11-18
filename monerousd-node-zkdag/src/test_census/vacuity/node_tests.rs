// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `test_census::vacuity::tests` — the vacuity census's own pin, which drives the harness, kept in the node crate by the node split
//! (stage B, lane dcash 2026-11-11): the recorder itself compiles in the ledger crate (`usdm_ledger::test_census::vacuity`), whose
//! gates call it; the node re-exports it, so the counters are one set and the test path is unchanged.

use super::*;

/// ⭐⭐⭐ EVERY REGISTERED GATE MUST HAVE DECIDED SOMETHING, ON A REAL INPUT, AT LEAST ONCE.
///
/// This runs a workload that moves real money — a spend with a real carrier, carried notes, a carried
/// deletion, a framed chain object — and then asks each gate whether it was ever handed an input it
/// could have REFUSED. A gate reported here is not covered, however green the rest of the suite is.
///
/// ⛔ THE FAILURE MESSAGE NAMES THE GATE AND ITS VACUOUS ARM, because "coverage is low" is not
/// actionable and "`nullifier_witnesses_gate` only ever saw nullifier-free transactions" is.
#[test]
fn every_consensus_gate_with_a_vacuous_arm_has_decided_at_least_one_real_input() {
    // A workload with a real spend: `Sim` now plants notes at witness-derived commitments and
    // `spend_tx_for_test` proves a real carrier, so this walks the doors rather than past them.
    use crate::consensus_scenarios::Sim;
    use crate::harness::fuzz::op::Op;
    // ⭐ FOLDING AT TIP (2026-10-04): since DB-223 Q7 a spend carries its input's member leg, built from the spender's
    // OWN folded stream — at the production depth (32) a two-block schedule folds nothing, `spend_tx_for_test` returns
    // `MemberCarrierRequired` ("[spend-miss] … built no carrier") and no spend ever reaches the nullifier gates: four of
    // six registered gates read "NEVER DECIDED A REAL INPUT" for that reason, not for lack of coverage.
    let mut sim = Sim::new_folding_at_tip(2, 0x5eed_0000_0000_0001);
    // ⭐ A FRAMED CHAIN OBJECT, or `wrapper_binds_object` never sees a carriage to bind. The census
    // reported it `0 · 0` on the first run — not "ran and passed", but NEVER HANDED ANYTHING — which
    // is precisely the state this module exists to make impossible to miss.
    {
        let note: Vec<u8> = (0..crate::cover::PQ_NOTE_BYTES)
            .map(|i| ((i as u32 * 5 + 29) % 251) as u8)
            .collect();
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[..32]);
        let credit = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: cm,
            asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            amount: 1_000,
            note,
            owner_clue: Vec::new(),
            attestors: Vec::new(),
    };
        let bits = sim.parties[0].mempool().required_stamp_bits();
        let _ = sim.parties[0].ingest_tx(credit.as_pq_tx(bits));
    }
    for op in [
        Op::Receive(0),
        Op::Receive(0),
        Op::Produce(0, 2),
        Op::Spend(0),
        Op::Drain,
        Op::Produce(1, 2),
        Op::Drain,
    ] {
        let _ = sim.step_checked(op.to_act(2));
    }

    eprintln!("[vacuity] gate decisions (real · vacuous):");
    for g in GATES {
        let (real, vac) = counts(g.name);
        eprintln!(
            "[vacuity]   {:<42} {:>6} · {:>6}   {}",
            g.name,
            real,
            vac,
            if real == 0 { "⛔ NEVER DECIDED A REAL INPUT" } else { "ok" }
        );
    }
    let blind = never_really_ran();
    eprintln!(
        "[vacuity] {} of {} registered gates never decided a real input: {blind:?}",
        blind.len(),
        GATES.len()
    );

    // ⛔ THE ASSERTION IS THE WHOLE POINT. A gate that never runs cannot report what it would have
    // said, and every verdict downstream of it is vacuous — which is exactly how §CC, §CD, §CE and the
    // `AlreadyPresent` fund-stranding defect all hid behind one fixture that set `nullifiers: vec![]`.
    assert!(
        blind.is_empty(),
        "⛔⛔⛔ {} REGISTERED GATE(S) NEVER DECIDED A REAL INPUT IN THIS PROCESS: {blind:?}\n\
         Each is listed in `GATES` with the input shape that makes it return without deciding. A gate \
         in this state is NOT covered: the suite can be entirely green while it has never once been \
         handed something it could refuse. Fix the WORKLOAD (give it an input that reaches the gate), \
         never the registration.",
        blind.len()
    );
}

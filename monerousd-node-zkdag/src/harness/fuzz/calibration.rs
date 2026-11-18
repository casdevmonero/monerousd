// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE HARNESS TURNED ON ITSELF.**
//!
//! Phase-3 calibration produced a finding on lane F's first real campaign
//! (`seed 0x9e3779b97f4a7c17`, shrunk 1-minimal to three ops):
//!
//! ```text
//!   I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN
//!   produce 0 0 · drop 1 · produce 1 0
//! ```
//!
//! Before that is reported as a chain defect it has to be decided against the OTHER hypothesis: that
//! the fuzzer's own convergence bookkeeping is wrong and the two parties were never fed the same
//! blocks in the first place. I-3's predicate is *"two nodes fed the same accepted blocks reach
//! byte-identical roots"* — if the schedule created a partition and never repaired it, the predicate's
//! ANTECEDENT is false and a divergence is not a violation of anything.
//!
//! ⛔ THIS DISTINCTION IS THE WHOLE VALUE OF THE INSTRUMENT. A harness that reports its own
//! bookkeeping as a consensus break is worse than no harness: the design's own oracle header says
//! asserting I-3 outside quiescence "would be a false-alarm generator, and a harness that cries wolf
//! is one that cannot be trusted". So the question is settled by MEASUREMENT — two runs differing in
//! one op — and not by reading either side's comments.
//!
//! The mechanism under suspicion is `engine.rs`:
//!
//! ```text
//!   Op::Drop(_)                     => drop_unrepaired = true,
//!   Op::Produce(..) | Op::Receive(_)
//!   | Op::Spend(_)  | Op::Invalid(_) => drop_unrepaired = false,
//! ```
//!
//! The clearing rule is justified in-tree as *"any production gives the repair path something to ask
//! about"*. That is true for the parties that RECEIVE the new block — `Sim::deliver_to` walks the
//! missing lineage down and pulls it out of the schedule's record, which is a real repair. It is NOT
//! true for the party that LOST the delivery, because `Sim::drop_one(i)` removes an entry owed to `i`
//! and a `Produce(i, _)` enqueues deliveries to everyone EXCEPT `i`. Nothing is ever handed to `i`,
//! so `i` never gets the chance to parent-ask, and the partition is permanent.
//!
//! The rule is therefore PARTY-BLIND where the defect is party-specific. This module measures that.
//!
//! ── ⭐ CLOSED 2026-09-08 (defect register D-21/D-22) ──────────────────────────────────────────────
//!
//! `engine.rs` now keeps the bookkeeping PER PARTY and decides repair from what the party HOLDS rather
//! than from which op ran: a `Drop(i)` is cleared only when party `i`'s own `dag_len` grows by a block
//! it did not itself produce, which is exactly "a delivery reached `i`". Two further holes fell out of
//! the same rewrite — a `Produce` that returned early (orphans buffered) cleared the old flag while
//! enqueuing nothing at all, and a party's own block used to look like an arrival to it.
//!
//! MEASURED, this sequence, before and after:
//!
//! ```text
//!   [H-1] produce/drop/produce -> I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN   (before)
//!   [H-1] produce/drop/produce -> None                                       (after)
//! ```
//!
//! The pins below were written to assert the FALSE ALARM and to invert the day the engine was fixed.
//! They inverted, and they are rewritten here to hold the fixed behaviour — with the finding kept in
//! this header rather than deleted, because a finding that vanishes with its fix teaches nobody. The
//! second pin now guards the thing that matters more than the green: that I-3 was REPAIRED, not
//! switched off. It proves the gate RE-ARMS — a drop that is genuinely healed by a later delivery is
//! asserted again in full.

use crate::harness::fuzz::engine::run_sequence;
use crate::harness::fuzz::op::Op;

/// The 1-minimal sequence the shrinker emitted, verbatim.
pub fn the_emitted_reproducer() -> Vec<Op> {
    vec![Op::Produce(0, 0), Op::Drop(1), Op::Produce(1, 0)]
}

/// The same schedule with the `Drop` removed — the control. Everything else is identical, so any
/// difference between the two runs is attributable to the dropped delivery and to nothing else.
pub fn the_control_without_the_drop() -> Vec<Op> {
    vec![Op::Produce(0, 0), Op::Produce(1, 0)]
}

/// The REPAIRED schedule: the same drop, but the next block is produced by party **0**, so it is
/// enqueued TO party 1 and the `Drain` hands it over. `Sim::deliver_to` then finds the parent missing,
/// walks the lineage out of the schedule's record and gives party 1 the block it lost. This is the
/// case the gate must NOT suppress — convergence is assertable again, and I-3 is asked in full.
pub fn the_schedule_whose_drop_is_repaired() -> Vec<Op> {
    vec![Op::Produce(0, 0), Op::Drop(1), Op::Produce(0, 0), Op::Drain]
}

/// The seed the campaign reported. The seed IS the reproducer; nothing here re-rolls it.
pub const SEED: u64 = 0x9e37_79b9_7f4a_7c17;

#[cfg(test)]
mod pins {
    use super::*;

    /// ⭐ H-1, NOW THE REGRESSION — THE PARTY THAT LOST THE DELIVERY IS NOT ASSERTED AGAINST.
    ///
    /// Two runs, one variable, exactly as when this measured the false alarm. The reproducer must now
    /// report NOTHING, and it must report nothing FOR THE RIGHT REASON: `convergence_unassertable`
    /// stays true, because party 1 was never handed anything and the partition is real. A run that
    /// reported no finding with the flag CLEAR would mean the engine had decided the mesh converged,
    /// which on this schedule it cannot — that would be a silent weakening, so the flag is asserted
    /// alongside the absence.
    ///
    /// The control must be silent with a CLEAR flag: no drop, nothing to suppress, I-3 asked in full
    /// and satisfied. Together the two runs say the suppression is caused by the dropped delivery and
    /// by nothing else — the same one-variable design that decided the original finding.
    ///
    /// ══ COST OF THE D-21 FIX, WRITTEN DOWN RATHER THAN IMPLIED ═══════════════════════════════════
    /// This fix SUPPRESSES I-3 on strictly MORE schedules than the rule it replaces: every run in
    /// which a dropped party is never delivered to again is now unassertable, where before any
    /// party's production re-opened the gate. That is a real soundness cost and it is bounded three
    /// ways, each f(fixed constants) rather than f(history):
    ///   1. PER PARTY — at most `MAX_PARTIES` = 4 flags exist, so one party's partition can never
    ///      silence the assertion for another; the old single bool silenced all of them together.
    ///   2. RE-ARMS ON ONE BLOCK — the flag clears on the FIRST delivery to that party. One block is
    ///      the whole condition: nothing counts attempts, and nothing ages out. `h1b` is that bound,
    ///      executed rather than argued.
    ///   3. COUNTED, NOT HIDDEN — `Outcome::convergence_unassertable` is reported per run and the
    ///      campaign report cites the rate, so over-suppression surfaces as a NUMBER rather than as a
    ///      green tick (that field's own doc states this is why it exists).
    /// Against that cost: the old rule asserted I-3 on partitions it had itself created, which is not
    /// a stricter check but a WRONG one. MEASURED — D-22 recorded the live campaign RED
    /// (`cargo test --lib harness::` → `33 passed; 1 failed`) on exactly this artefact, and this
    /// sequence went `I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN` → `None` across the fix. A false
    /// alarm on the most severe invariant in the catalogue costs the whole instrument its credibility.
    #[test]
    fn h1_the_lost_delivery_suppresses_i3_and_only_the_lost_delivery_does() {
        let with_drop = run_sequence(2, SEED, &the_emitted_reproducer());
        let without_drop = run_sequence(2, SEED, &the_control_without_the_drop());

        let with_flag = with_drop.convergence_unassertable;
        let without_flag = without_drop.convergence_unassertable;
        let with_inv = with_drop.finding.map(|f| f.invariant);
        let without_inv = without_drop.finding.map(|f| f.invariant);

        println!(
            "[H-1] produce/drop/produce -> {with_inv:?} (unassertable={with_flag})   |   \
             produce/produce (control) -> {without_inv:?} (unassertable={without_flag})"
        );

        assert_eq!(
            with_inv, None,
            "⛔ THE FALSE ALARM IS BACK. `engine.rs` is reporting a consensus break on a partition its \
             own schedule created and never repaired: `Sim::drop_one(1)` destroys the delivery owed to \
             party 1, and `produce_one(1)` enqueues to everyone EXCEPT party 1, so nothing is ever \
             handed to it. I-3's antecedent — two nodes fed the SAME accepted blocks — is false here, \
             so this is not a violation of anything. Check that the per-party drop bookkeeping still \
             re-baselines a producer against its OWN block."
        );
        assert!(
            with_flag,
            "⛔ SILENTLY WEAKENED: the reproducer reported no finding AND declared convergence \
             assertable, which would mean the engine believes these two parties converged. Party 1 \
             holds strictly less and can never catch up on this schedule. An absent finding is only \
             correct here because the run is UNASSERTABLE; if the flag is clear, the check was \
             skipped for the wrong reason and every campaign built on it is reporting false green."
        );
        assert_eq!(
            without_inv, None,
            "the control diverges with no Drop at all, so the divergence is NOT the partition's doing \
             and lane F is reporting a REAL consensus finding. Escalate it as an order-dependence in \
             the record fold; do not close it as a harness defect."
        );
        assert!(
            !without_flag,
            "the control contains no Drop, so nothing may suppress I-3 on it. A set flag here means \
             the gate now fires on schedules that never lost a delivery — the suppression has leaked \
             beyond its cause and the instrument is blind, not merely quiet."
        );
    }

    /// ⭐⭐⭐ H-1c — THE ONE MEASUREMENT THAT DECIDES WHAT THE CAMPAIGN'S REMAINING RED ACTUALLY IS.
    ///
    /// With D-21 fixed, lane F still fails, but on a DIFFERENT schedule: `produce 0 0 · drop 1 ·
    /// produce 0 0`, reporting `nullifier_count 513 vs 257`. Party **0** produces the second block, so
    /// party 1 IS delivered to and the convergence gate correctly re-arms — this is not the old
    /// artefact. Two readings are possible and they have opposite severities:
    ///
    ///   (a) `Sim::deliver_to`'s lineage walk never actually recovers the destroyed block, so party B
    ///       is still missing a BLOCK. A harness-side repair defect.
    ///   (b) Party B HOLDS both blocks and folded only one record. A real consensus defect — state is
    ///       not a function of the chain, which is precisely what I-3 exists to catch.
    ///
    /// Guessing between them is exactly the move that has cost this project the most, so this pin
    /// asks the two DAGs directly. Both endpoints are independent `Node`s inside the mesh — party A
    /// produced every block and party B is the one whose delivery was destroyed — and the assertion
    /// is that B OBSERVES what A produced. Block possession is the DELIVERY layer; the nullifier
    /// count the campaign reports is the FOLD layer. Comparing the two layers across the two parties
    /// separates the candidates with one fact and no interpretation.
    ///
    /// cons: none — four acts on a 2-party mesh, no store, no growth term.
    #[test]
    fn h1c_does_the_party_that_lost_a_delivery_get_the_block_back_or_only_lose_the_fold() {
        use crate::consensus_scenarios::{Act, Sim};

        let mut sim = Sim::new(2, SEED);
        // `Op::Produce(0, 0)` lowers to `Act::Produce(0, 1)` — one block. The same schedule as the
        // campaign's shrunk reproducer, driven directly so both parties' DAGs can be read afterwards.
        let _ = sim.step_checked(Act::Produce(0, 1));
        let _ = sim.step_checked(Act::Drop(1));
        let _ = sim.step_checked(Act::Produce(0, 1));
        sim.drain();

        // The two endpoints, named: A produced both blocks, B is the party whose delivery was
        // destroyed. Neither plays both roles — B's state is only ever moved by what reaches it.
        let party_a = &sim.parties[0];
        let party_b = &sim.parties[1];
        let blocks_a = party_a.dag().len();
        let blocks_b = party_b.dag().len();
        println!("[H-1c] after drain: party_a holds {blocks_a} block(s), party_b holds {blocks_b}");

        // ⛔ THE CONTROL, RUN BEFORE ANY CLAIM ABOUT THE DROP. The same two productions with NO drop
        // at all: if the nullifier gap appears here too, it is not caused by the parent-ask recovery
        // and any statement blaming that path is wrong. One variable, exactly as H-1 does it.
        let mut ctl = Sim::new(2, SEED);
        let _ = ctl.step_checked(Act::Produce(0, 1));
        let _ = ctl.step_checked(Act::Produce(0, 1));
        ctl.drain();
        let ca = crate::harness::fuzz::oracle::sample(&ctl.parties[0]);
        let cb = crate::harness::fuzz::oracle::sample(&ctl.parties[1]);
        println!(
            "[H-1c CONTROL no-drop] party_a: dag={} rec_top={} uns_leaves={} nf_count={}  |  \
             party_b: dag={} rec_top={} uns_leaves={} nf_count={}",
            ca.dag_len, ca.record_ordinal_top, ca.uns_leaf_count, ca.nf_count,
            cb.dag_len, cb.record_ordinal_top, cb.uns_leaf_count, cb.nf_count
        );

        // WHICH LAYER DIVERGED — printed so the next reader does not have to re-derive it. `dag_len`
        // is possession, `record_ordinal_top` is the DA record layer, `uns_leaf_count`/`nf_count` are
        // the fold. Whichever of the three first disagrees names the seam.
        let sa = crate::harness::fuzz::oracle::sample(party_a);
        let sb = crate::harness::fuzz::oracle::sample(party_b);
        println!(
            "[H-1c] party_a: dag={} rec_top={} uns_leaves={} nf_count={} spend_frontier={}",
            sa.dag_len, sa.record_ordinal_top, sa.uns_leaf_count, sa.nf_count, sa.spend_frontier_count
        );
        println!(
            "[H-1c] party_b: dag={} rec_top={} uns_leaves={} nf_count={} spend_frontier={}",
            sb.dag_len, sb.record_ordinal_top, sb.uns_leaf_count, sb.nf_count, sb.spend_frontier_count
        );

        assert_eq!(
            blocks_a, blocks_b,
            "⛔ READING (a) CONFIRMED — THE LOST BLOCK IS NEVER RECOVERED. After a full `drain` (8 \
             rounds of up to 8,000 deliveries plus a `repair_round`) party_b still holds {blocks_b} \
             block(s) against party_a's {blocks_a}. The destroyed block is still in `Sim::blocks`, so \
             `deliver_to`'s lineage walk had it available and did not hand it over: the walk asks for \
             the missing PARENT of the block being delivered and inserts the lineage ahead of it, so \
             the failure is in that recovery and not in the chain. The nullifier gap the campaign \
             reports is then a DELIVERY defect in the simulator, I-3's antecedent is still false on \
             this schedule, and the convergence gate is re-arming too early — its repair signal must \
             become 'the party holds the block it lost' rather than 'the party received something'. \
             FIX THERE, not in the fold."
        );
        // ⭐⭐ D-35, MEASURED AND THEN CLOSED 2026-09-08. This pin decided the diagnosis and now holds
        // the fix.
        //
        // BEFORE:  party_a nf=513, party_b nf=257  (identical DAGs, identical records, identical
        //          unspent leaves — short by exactly 256, one block's cover)
        // AFTER:   party_a nf=513, party_b nf=513
        // CONTROL (no drop, both runs): 513 vs 513 — so the gap required the recovery and nothing else.
        //
        // The cause was that `fold_block_nf_in_order` sat behind `if matches!(outcome,
        // RelayOutcome::Added(_))` and ran with the NAMED block's pre/post/tags, so a block arriving
        // behind it in a cascade — a parent-ask recovery, a released buffered descendant — was
        // recorded but its spend transition was never folded. The A_tip fold already ran per grafted
        // block, which is why the consensus roots matched and this stayed invisible.
        //
        // ⛔ NOT A NEW PER-ITEM LOOP (R-C1 is about a per-item write loop measured at 43-44 ms/block
        // against a 500 ms block time, which converges only on a dead chain). NOTHING per-item was
        // added here and the per-block cost is UNCHANGED: one fold per block, exactly what a directly
        // delivered block has always paid. What changed is the FIRING CONDITION — once per grafted
        // block instead of once per receive — so the arithmetic over any interval is
        // (blocks admitted) x (one fold), which is precisely what the same node would have paid had
        // those blocks arrived in order. A cascade of K blocks previously paid 1 fold and owed K-1;
        // it now pays K and owes none. The produce-side drain beside it states the identical
        // arithmetic for the record apply it was added for.
        assert_eq!(
            sa.nf_count, sb.nf_count,
            "⛔ D-35 HAS REGRESSED: the party that lost a delivery and recovered it by parent ask holds              the same blocks ({blocks_a} vs {blocks_b}), the same records and the same unspent leaves,              but a DIFFERENT nullifier count ({} vs {}) — short by {}, a whole number of 256-wide block              covers. A block is being recorded without its spend transition being folded. Wallets fold              the SERVED nullifier stream to its end to name a spend endpoint, so a node in this state              serves a short stream and every spender resolving against it is refused. Check that BOTH              fold sites still fire per GRAFTED block rather than per `RelayOutcome::Added`: the loop in              `ingest_block` and the cascade drain in `graft_mined_own`.",
            sa.nf_count,
            sb.nf_count,
            sa.nf_count.abs_diff(sb.nf_count)
        );
    }

    /// ⭐⭐⭐ H-5 (CALIBRATION ROWS D-5 / D-7) — AN ATTACKER MUST NOT CHOOSE WHAT THIS NODE HOLDS.
    ///
    /// Until this landed the harness had NO growth oracle of any kind (`grep -rni census src/harness`
    /// → 0 substantive hits), so a whole class was invisible by construction: a node can be perfectly
    /// correct about consensus — every root, every count, every verdict right — and still fill up on
    /// input a caller chose. Both missed rows are that shape:
    ///   * D-5: `btc_watch::confirmed_pending_cached` turned ANY string a caller posted into a
    ///     permanent sweep entry, one Tor round-trip per entry per cycle, forever.
    ///   * D-7: the unauthenticated `NoteClue` arm wrote `pending_tags` under a bound proven for a
    ///     DIFFERENT writer — the per-writer census this row exists to force.
    ///
    /// The machinery is now in the oracle: `Sample::store_entries_total` reads the node's OWN
    /// `da_entry_census_named`, and `I-NG HOSTILE-ACTION-GREW-A-STORE` fires when a HOSTILE op
    /// increases it, naming the store from the live census at finding time.
    ///
    /// This pin asserts the property directly rather than waiting for a campaign to wander into it,
    /// and it checks NON-VACUITY first: a census of zero would make "nothing grew" a statement about
    /// nothing at all.
    ///
    /// cons: none — a handful of acts on a 2-party mesh, no store, no growth term.
    #[test]
    fn h5_a_hostile_action_does_not_grow_what_the_victim_holds() {
        use crate::consensus_scenarios::{Act, Sim};

        let mut sim = Sim::new(2, SEED);
        // Real work first, so the node genuinely HOLDS things — a census of zero proves nothing.
        let _ = sim.step_checked(Act::Receive(0));
        sim.drain();
        let _ = sim.step_checked(Act::Produce(0, 1));
        sim.drain();

        let before = crate::harness::fuzz::oracle::sample(&sim.parties[1]);
        assert!(
            before.store_entries_total > 0,
            "⛔ THE CENSUS IS EMPTY: this node holds nothing, so 'a hostile op grew nothing' would be a \
             claim about an empty set. Advance the schedule until the node actually holds entries \
             rather than weakening this check."
        );
        println!("[H-5] victim holds {} store entries before the hostile ops", before.store_entries_total);

        // Every hostile op in the alphabet, aimed at the victim, one after another.
        for act in [Act::ForgeRows(1), Act::Tamper(1, 0), Act::Replay(1, 0), Act::Invalid(1)] {
            let label = format!("{act:?}");
            let mid = crate::harness::fuzz::oracle::sample(&sim.parties[1]);
            let census_before: Vec<(&'static str, usize)> = sim.parties[1]
                .da_entry_census_named()
                .into_iter()
                .map(|(n, e, _)| (n, e))
                .collect();
            let _ = sim.step_checked(act);
            let after = crate::harness::fuzz::oracle::sample(&sim.parties[1]);
            // Name the exact store that moved, so the finding points at a WRITER rather than a total.
            let grew: Vec<String> = sim.parties[1]
                .da_entry_census_named()
                .into_iter()
                .filter_map(|(n, e, _)| {
                    let was = census_before.iter().find(|(m, _)| *m == n).map(|(_, c)| *c).unwrap_or(0);
                    (e > was).then(|| format!("{n}: {was} -> {e} (+{})", e - was))
                })
                .collect();
            if !grew.is_empty() {
                println!("[H-5] {label} GREW: {}", grew.join(", "));
            }
            println!(
                "[H-5] {label}: {} -> {} entries",
                mid.store_entries_total, after.store_entries_total
            );
            // Same discriminator the oracle uses: growth is only a finding when NO chain work backs
            // it. A hostile op that made this party accept a block grew its stores honestly.
            assert!(
                after.store_entries_total <= mid.store_entries_total || after.dag_len > mid.dag_len,
                "⛔ I-NG / rows D-5+D-7: the HOSTILE op {label} grew what this node HOLDS ({} -> {}). \
                 An attacker must never be able to choose this node's footprint: growth on an \
                 adversarial action is invisible to every root and count the rest of the catalogue \
                 reads, and it is paid forever. Live census: [{}]. Fix at the WRITER — the set a node \
                 sweeps or stages must be one it PRODUCED, never one a caller named.",
                mid.store_entries_total,
                after.store_entries_total,
                sim.parties[1]
                    .da_entry_census_named()
                    .into_iter()
                    .filter(|(_, e, _)| *e > 0)
                    .map(|(n, e, _)| format!("{n}={e}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    /// ⭐⭐⭐ H-6 (CALIBRATION ROW E-4) — ONE NOTE, ONE RECORD. THE CARRIAGE-COUNT ORACLE, ARMED.
    ///
    /// Row E-4 is the 2026-09-03 DEX double-payout, and the design is explicit that it is a DISTINCT
    /// invariant from conservation: both carried copies were individually legitimate, every amount
    /// balanced, and the maker's lot still paid out twice. A sum cannot see a duplicate — only a count
    /// can. Nothing in the harness counted carriages before this (`grep -rni carriage src/harness` → 0).
    ///
    /// This pin does two things, and the SECOND is the one that matters:
    ///   1. asserts the property on a real schedule — no real note is carried by two records;
    ///   2. proves the detector CAN FIRE, by asking the same primitive about a commitment that is
    ///      genuinely carried and confirming it counts it. A carriage oracle that answers 0 for
    ///      everything would pass part 1 forever while detecting nothing, which is precisely the
    ///      failure mode that let three other rows sit "green" and blind.
    ///
    /// cons: none — one receive plus a drain on a 2-party mesh; the counts are read, never stored.
    #[test]
    fn h6_no_real_note_is_carried_by_two_records_and_the_counter_can_see_carriages() {
        use crate::consensus_scenarios::{Act, Sim};

        let mut sim = Sim::new(2, SEED);
        let _ = sim.step_checked(Act::Receive(0));
        sim.drain();
        let _ = sim.step_checked(Act::Receive(1));
        sim.drain();

        // NON-VACUITY: the counter must actually SEE the notes this schedule created. If every count
        // is 0 the oracle is blind and "nothing was carried twice" is a claim about nothing.
        let (unspent_avail, _) = sim.hostile_payload_available_for_test();
        assert!(
            unspent_avail > 0,
            "no real note exists in this schedule, so the carriage counter has nothing to count"
        );
        let mut seen_carried = 0usize;
        for party in sim.parties.iter() {
            for cm in sim.real_note_cms_for_test() {
                let n = party.da_carriage_count(&cm);
                if n > 0 {
                    seen_carried += 1;
                }
            }
        }
        println!("[H-6] carriage counter observed {seen_carried} (party, note) carriages");
        assert!(
            seen_carried > 0,
            "⛔ THE CARRIAGE COUNTER IS BLIND: it counted ZERO carriages across every party and every \
             real note, while this schedule demonstrably received notes. A counter that answers 0 for \
             everything passes the no-double-carriage assertion forever and detects nothing — the exact \
             shape of a green row that tests nothing. Check `da_carriage_count`'s match against the \
             note bytes a record actually stores."
        );

        // THE PROPERTY.
        assert!(
            sim.carriage_verdict().is_ok(),
            "{}",
            sim.carriage_verdict().unwrap_err()
        );
    }

    /// ⭐⭐⭐ H-7 (CALIBRATION ROW E-7) — A NODE FED ONLY THE BLOCKS MUST DERIVE WHAT THE LIVE MESH HOLDS.
    ///
    /// Row E-7 is the 2026-09-03 double payout and its cause was one line: *"the burn was LOCAL and
    /// never travelled."* Every live party self-verified correctly and the money still went out twice.
    /// Comparing live parties cannot find that — they can all be wrong together, and there they were
    /// all individually right. Nothing in the harness did a cold replay
    /// (`grep -rni "cold.peer" src/harness` → 0).
    ///
    /// `Sim::cold_peer_verdict` builds a party that cannot be in on it: a fresh node, its own empty
    /// datadir, no mempool, no staging, no adopted bundle, handed nothing but the blocks. What it
    /// derives is what the chain SAYS. A live party that disagrees is holding value no block carries.
    ///
    /// NON-VACUITY: the cold peer must actually have built something. A node that ingested nothing
    /// would sit on the genesis root and "everyone agrees with it" would be a statement about an empty
    /// chain — the failure mode that let three other rows sit green and blind.
    ///
    /// cons: one extra node fed this case's blocks once; dropped at the end of the test.
    #[test]
    fn h7_a_cold_node_fed_only_blocks_derives_what_the_live_mesh_holds() {
        use crate::consensus_scenarios::{Act, Sim};

        let mut sim = Sim::new(2, SEED);
        let _ = sim.step_checked(Act::Receive(0));
        sim.drain();
        let _ = sim.step_checked(Act::Produce(0, 1));
        sim.drain();
        let _ = sim.step_checked(Act::Receive(1));
        sim.drain();

        let blocks = sim.produced_block_count_for_test();
        println!("[H-7] chain carries {blocks} block(s); replaying them into a cold node");
        assert!(
            blocks > 1,
            "⛔ NOTHING TO REPLAY: the schedule produced {blocks} block(s), so a cold node would sit on \
             genesis and 'the mesh agrees with it' would be a claim about an empty chain. Advance the \
             schedule rather than weakening this check."
        );

        match sim.cold_peer_verdict() {
            Ok(()) => println!("[H-7] cold peer derives the same unspent root as every live party"),
            Err(why) => panic!(
                "⛔ E-7 / TRUSTLESS: {why}\n\nSelf-verification is not consensus. A live party whose \
                 state a chain-only replay cannot reproduce is holding something that never travelled — \
                 the exact shape that paid a maker's lot out twice while every node was individually \
                 correct. Find the writer that mutated state OUTSIDE a block."
            ),
        }
    }

    /// ⭐⭐⭐ H-8 (CALIBRATION ROWS C-H4 / E-5) — A REFUSAL MUST NOT BE PURCHASABLE BY ASKING TWICE.
    ///
    /// CIRCULAR AUTHORITY: a node refuses an item, stores something DERIVED FROM that item anyway,
    /// and then accepts the same item on its second offer because the authority it now judges against
    /// came from the item itself. This is not hypothetical — D-32 was exactly it, LIVE, at the
    /// verified-fetch door, and it was FUNDS-LOSS. It is invisible to every single-offer test by
    /// construction: the first offer is refused, which looks correct, and nothing ever asks again.
    /// The harness had no re-offer capability at all (`Op::Replay` replays a BUNDLE, not a record
    /// offer), which is precisely why both rows sat missed.
    ///
    /// NON-VACUITY: the offer must actually reach a door with rows to judge. A party holding no
    /// ordinal rows would be asked nothing twice, and "the answers matched" would be a statement about
    /// an empty offer.
    ///
    /// cons: none — a short schedule on a 2-party mesh; the offers go through the same production door
    /// a real page uses and nothing is retained.
    #[test]
    fn h8_a_door_that_refused_an_offer_still_refuses_the_identical_second_offer() {
        use crate::consensus_scenarios::{Act, Sim};

        let mut sim = Sim::new(2, SEED);
        let _ = sim.step_checked(Act::Receive(0));
        sim.drain();
        let _ = sim.step_checked(Act::Produce(0, 1));
        sim.drain();

        let rows_held: usize = sim.parties[1].ordinal_rows_for_test().len();
        println!("[H-8] victim holds {rows_held} ordinal row(s) to judge a forged re-offer against");
        assert!(
            rows_held > 0,
            "⛔ NOTHING TO OFFER: the victim holds no ordinal rows, so the door is handed an EMPTY \
             offer and 'both answers matched' would be a claim about nothing. Advance the schedule \
             rather than weakening this check."
        );

        match sim.provenance_verdict() {
            Ok(()) => println!("[H-8] identical re-offer got the identical verdict on every party"),
            Err(why) => panic!(
                "⛔ C-H4 / E-5 — CIRCULAR AUTHORITY: {why}\n\nThe door's answer changed while the \
                 offer did not, so the thing that changed is what the door judges AGAINST. Find the \
                 writer that stored something derived from bytes the door was in the middle of \
                 REFUSING — that store is the authority the attacker is now borrowing."
            ),
        }
    }

    /// ⭐⭐⭐ H-3 (D-37) — WHAT A REPRODUCER ACTUALLY GUARANTEES, EXECUTED RATHER THAN CLAIMED.
    ///
    /// `run_sequence` used to claim outright determinism in `(parties, seed, ops)`. On 2026-09-08 the
    /// campaign refuted it in its own words — *"the finding did NOT reproduce on replay from its own
    /// seed"* — and this pin was written to find out which side was wrong.
    ///
    /// MEASURED, and it is the HARNESS's claim that was wrong, not the node:
    /// * five identical replays gave signatures `[A, B, A, A, A]` — divergence is PROBABILISTIC, so a
    ///   single comparison is a coin-flip detector (consecutive runs of this pin gave false, false,
    ///   then true on identical input). That is why it replays `REPS` times.
    /// * bisecting to the first diverging step landed on a produce, and the tip diff read
    ///   `ts=1000 txs=256 nfroot=SAME txroot=DIFFERENT`, with the SORTED tx-id digests also different.
    ///   Different TRANSACTIONS, not the same set reordered — which REFUTES the consensus reading (a
    ///   stable id set committing to two different merkle roots, the failure the mempool sort's own
    ///   comment warns of).
    /// * `cover::cover_note` mints a FRESH ML-KEM keypair per cover note ("throwaway recipient —
    ///   discarded, so nobody can ever spend this note"). Cover an observer can predict is not cover,
    ///   so this randomness is the PRIVACY PILLAR doing its job. Seeding it for the fuzzer's
    ///   convenience would be a straight pillar trade and is never the answer.
    /// * across those same replays every consensus-meaningful field — `uns_root`, `uns_leaf_fold`,
    ///   `uns_leaf_count`, `nf_count`, `nf_acc`, `record_ordinal_top`, `dag_len`, `tip_blue_work`,
    ///   `spine_len` — was IDENTICAL. Only `tip` moved.
    ///
    /// So the guarantee a reproducer offers is the one asserted here: **the state the catalogue judges
    /// is a function of `(parties, seed, ops)`; block identity is not.** Every invariant is stated over
    /// that state and never over a block id, so a finding re-decides identically on replay even though
    /// the blocks carrying it are freshly covered each time. If THIS ever fails, the nondeterminism has
    /// reached something consensus depends on and no reproducer in the lane can be trusted.
    ///
    /// cons: none — `REPS` short replays, no store, nothing retained.
    #[test]
    fn h3_the_state_the_catalogue_judges_replays_identically_from_seed_and_ops() {
        use crate::consensus_scenarios::Sim;
        use crate::harness::fuzz::engine::fuzz_one;

        let (ops, _first) = fuzz_one(2, SEED, 48);

        // One replay's consensus-meaningful state for both parties, block identity deliberately
        // EXCLUDED — see the doc above for why `tip` is legitimately not reproducible.
        let replay = || -> Vec<String> {
            let mut sim = Sim::new(2, SEED);
            for op in &ops {
                let _ = sim.step_checked(op.to_act(2));
            }
            sim.parties
                .iter()
                .map(|n| {
                    let s = crate::harness::fuzz::oracle::sample(n);
                    format!(
                        "uns_root={:?} uns_fold={:#x} uns_leaves={} nf_count={} nf_acc={:?} nf_root={:?} membership_tip={:?} spend_frontier={} missing_parents={} parent_blue_work={:?} rec_top={} dag_len={} blue_work={:?} spine_len={} inversions={}",
                        s.uns_root, s.uns_leaf_fold, s.uns_leaf_count, s.nf_count, s.nf_acc,
                        s.nf_root, s.membership_tip, s.spend_frontier_count, s.tip_missing_parents,
                        s.parent_blue_work,
                        s.record_ordinal_top, s.dag_len, s.tip_blue_work, s.spine_len,
                        s.spine_ordinal_inversions
                    )
                })
                .collect()
        };

        // Divergence is probabilistic, so sample repeatedly rather than once.
        const REPS: usize = 5;
        let first = replay();
        for rep in 1..REPS {
            let again = replay();
            for (party, (a, b)) in first.iter().zip(again.iter()).enumerate() {
                assert_eq!(
                    a, b,
                    "⛔ D-37 HAS ESCALATED: replay {rep} of the SAME (parties, seed, ops) produced                      different CONSENSUS state on party {party}. Block identity is allowed to move —                      cover notes are freshly keyed by design — but the state the catalogue judges must                      be a function of the inputs, or no reproducer in this lane means anything and no                      detection number may be cited. Diff the fields in the two strings: the first one                      that differs names the subsystem that has become order- or entropy-dependent."
                );
            }
        }
        println!("[H-3] {REPS} replays: consensus state IDENTICAL on both parties (block ids differ by design)");

        // ⛔ THE SECOND HALF, AND THE ONE THE CAMPAIGN ACTUALLY TRIPS ON. The state above is replayed
        // through `Sim` directly, with no oracle. `run_sequence` additionally asks the catalogue after
        // every step and BREAKS at the first finding — so a verdict that is not a function of the state
        // makes `steps_run` (and therefore the whole outcome) vary even though the chain does not. The
        // campaign's own report is exactly this: `fuzz_one` and its replay call `run_sequence` with
        // IDENTICAL arguments, and one finds a violation while the other does not.
        let verdicts: Vec<String> = (0..REPS)
            .map(|_| {
                let o = run_sequence(2, SEED, &ops);
                format!(
                    "{}@{}",
                    o.finding.as_ref().map(|f| f.invariant).unwrap_or("none"),
                    o.steps_run
                )
            })
            .collect();
        println!("[H-3] {REPS} oracle verdicts: {verdicts:?}");
        assert!(
            verdicts.iter().all(|v| *v == verdicts[0]),
            "⛔ D-37 LOCALISED TO THE ORACLE: the same (parties, seed, ops) produced DIFFERENT verdicts              {verdicts:?} while the consensus state replayed IDENTICALLY (asserted above, every Sample              field). So the catalogue's verdict is not a function of the state it judges — it depends on              something entropy- or order-bearing inside `Oracle` itself. That is why the campaign reports              'the finding did NOT reproduce on replay from its own seed' while the chain is perfectly              reproducible, and why no lane-F detection number may be cited until it is closed. Look for a              HashSet/HashMap the oracle iterates, or state it carries across steps that is not derived              from the samples."
        );
    }

    /// ⭐⭐ H-1b — THE GATE RE-ARMS. THIS IS THE PIN THAT SEPARATES A FIX FROM SWITCHING I-3 OFF.
    ///
    /// Suppressing an invariant is trivially "green", and that is exactly the danger in a fix shaped
    /// like this one: an engine that simply never asserted convergence would pass H-1 forever while
    /// testing nothing. So this pin drives the SAME drop and then genuinely repairs it — party **0**
    /// produces the next block, so it is enqueued TO party 1, and the `Drain` hands it over;
    /// `deliver_to` finds the parent missing and walks the lost lineage out of the schedule's record.
    ///
    /// After that repair the run must be fully asserted again (`convergence_unassertable == false`)
    /// and must hold I-3 (no finding). This is bound 2 of the cost written on `h1` above, executed
    /// rather than asserted in prose: the suppression lasts exactly until one block reaches the party
    /// that lost one. If the flag were still set here, the engine would have learned to suppress on
    /// any drop for the rest of the run — the blind half of D-21, arrived at from the other side.
    ///
    /// cons: none — four ops on a 2-party mesh, no store, no growth term; the run is the assertion.
    #[test]
    fn h1b_a_drop_that_is_actually_repaired_is_asserted_again_in_full() {
        let out = run_sequence(2, SEED, &the_schedule_whose_drop_is_repaired());
        let inv = out.finding.as_ref().map(|f| f.invariant);
        println!(
            "[H-1b] produce/drop/produce(0)/drain -> {inv:?} (unassertable={})",
            out.convergence_unassertable
        );
        // The discriminator the original H-1b established: an UNREPAIRED partition shows one side
        // simply holding LESS, where a genuine order-dependence shows two equal-sized sides
        // disagreeing on their FOLD. Printed so a failure here is diagnosable without a re-run.
        if let Some(f) = out.finding.as_ref() {
            println!("[H-1b] detail = {}", f.detail);
        }

        assert!(
            !out.convergence_unassertable,
            "⛔ THE GATE NEVER RE-ARMS: party 1's lost delivery WAS handed over — party 0's later \
             block was enqueued to it and the Drain delivered it, which is the parent-ask path the \
             drop doc names — yet convergence is still declared unassertable. An engine that \
             suppresses I-3 for the rest of a run after any Drop passes H-1 while testing nothing at \
             all. The repair signal must be that the party's OWN dag grew by a block it did not \
             produce."
        );

        // ⭐ AND IT NOW CONVERGES. When this pin was written the repaired schedule still reported
        // `I-3 ... nullifier_count 513 vs 257` — a COUNT GAP, one side holding less, which `h1c`
        // then decided was a real chain defect rather than a bookkeeping artefact (D-35: a block
        // recovered by the parent ask was recorded without its spend transition being folded). With
        // that closed, the delivery brings party 1 genuinely level and I-3 is satisfied.
        //
        // So this pin now asserts BOTH halves of a real repair: the gate re-arms, AND the parties
        // actually agree once it does. Asserting only the first would let a future regression hide —
        // an engine that re-armed the gate over a still-divergent mesh would pass on the flag alone.
        assert_eq!(
            inv, None,
            "the repaired schedule reports a finding again. Both parties have been fed the same \
             accepted blocks here, so I-3's antecedent HOLDS and this is a real consensus finding, \
             not a harness artefact. If the detail is a nullifier COUNT GAP, D-35 has regressed — a \
             block is being recorded without its spend transition folding (see `h1c`). If it is an \
             equal-sized FOLD disagreement, it is a new order-dependence in the record fold. Either \
             way: escalate, do not fold it into D-21."
        );
    }
}

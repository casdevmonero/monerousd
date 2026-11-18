// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::db353_p1_node_pins` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::genesis_block;
use super::{AssetSpendOutcome, Node};
use crate::hash::Hash32;
use crate::nf_sparse::BandReceipt;

/// ⭐ DB-353 §11.12 — THE WORKER'S UNDER-LOCK HALF SERVES THE FIRST STEP ITS OWNER HOLDS. A producer folding at the tip
/// lays one block; its fold notes the block's step with the admitted lane; the node, the sole known prover, owns it,
/// so `band_next_owned_step` must hand back a served job for exactly that step (the proof itself runs off the lock and
/// is pinned by the runtime's worker pin). On failure it says WHICH condition refused, so the break is named.
#[test]
fn db353_the_owner_serves_the_first_step_it_owns() {
    // DB-223 Q7: the spend's note is FUNDED on chain — the testnet identity admits the funding credit (DB-354).
    let mut n = crate::node::tests::testnet_party_folding_at_tip();
    n.set_public_id("band-owner-unit".to_string());
    // ⛔ DB-367: a step awaits a carrier only when its block's lane holds JUSTIFIED tags — an idle block's fill admits
    // nothing — so the laid block carries one honest spend, whose stated tags are the step's admitted set.
    let spend = super::tests::honest_spend_tx_for_test(&mut n, &mut [], 0x0e1);
    n.ingest_tx_unverified(spend).expect("the node pools a spend");
    n.produce(5_000, Hash32::hash(b"owner-fr"), Hash32::hash(b"owner-mc")).expect("the node lays a block");
    let _ = n.fold_canonical_records();
    let steps = n.band_door.awaiting_steps();
    let summary: Vec<(u64, Option<usize>)> = steps.iter().map(|(o, _, a)| (*o, a.as_ref().map(Vec::len))).collect();
    let pointer = n.band_pointer();
    let view = n.sparse_work.as_ref().map(|v| v.shard_policy());
    eprintln!("[owner-unit] pointer {pointer:?} awaiting {summary:?} view policy {view:?}");
    assert!(pointer.is_some(), "CALIBRATION: the laid block's fold step awaits its carrier");
    assert!(steps.first().is_some_and(|(_, _, a)| a.is_some()), "⛔ the producer noted its OWN block's step UNKNOWN");
    let provers = n.band_provers();
    assert_eq!(provers, vec!["band-owner-unit".to_string()], "CALIBRATION: the node is its only known prover");
    let job = n.band_next_owned_step(&provers, 0);
    assert_eq!(
        job.map(|j| j.ordinal),
        pointer,
        "⛔ the owner served nothing for the step it owns — the worker would never prove"
    );
}

/// ⛔⛔ DB-353 §11.13 — AN OPEN STEP ITS OWNER NEVER PROVED IS PROVEN BY A HOLDER THAT ABSORBED IT (found 2026-10-02 on
/// the hub: both parties' bands sat at the first real step forever, then went stale and every pool refused every spend).
/// The worker ABSORBS a step it does not own into its cursor (so it can prove later steps on top of it), and from then on
/// skipped it — so when the owner never proved it and it turned OPEN (`band_open_after` steps behind the latest: the
/// §11.13 rule that ANY holder proves it), no holder that had absorbed it ever did. One absent owner stalled every band.
/// Here: a holder and an absent owner ("ghost") of step 0; step 0 is absorbed while closed, then — once open — the
/// worker must serve step 0 itself, never step past it.
#[test]
fn db353_an_open_step_its_owner_never_proved_is_proven_by_a_holder_that_absorbed_it() {
    let mut n = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    n.set_public_id("band-holder".to_string());
    let m = crate::nf_sparse::band_owner_count(n.params().target_spacing_ms, 2);
    let ghost = (0u32..)
        .map(|i| format!("ghost-owner-{i}"))
        .find(|g| {
            let provers = vec!["band-holder".to_string(), g.clone()];
            crate::nf_sparse::band_step_owner(0, &provers, m).as_deref() == Some(g.as_str())
        })
        .expect("some ghost name owns step 0");
    let provers = vec!["band-holder".to_string(), ghost];
    let open_after = crate::nf_sparse::band_open_after(m) as u64;
    let tag = |o: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x0be7, o, 3, 5]));
    n.band_note_step_for_test(0, &[tag(0)]);
    assert!(
        n.band_next_owned_step(&provers, 0).is_none(),
        "CALIBRATION: step 0 is the ghost's and its lease has not expired — the holder absorbs it and proves nothing"
    );
    for o in 1..=open_after {
        n.band_note_step_for_test(o, &[tag(o)]);
    }
    assert_eq!(n.band_pointer(), Some(0), "CALIBRATION: the band still waits at step 0");
    // the ghost's lease on the pointer step has expired (the band did not move for the runtime's lease)
    let job = n.band_next_owned_step(&provers, 1).expect("the holder serves a step");
    assert_eq!(
        job.ordinal, 0,
        "⛔⛔ DB-353 §11.13: step 0 is OPEN (its owner never proved it) and the holder stepped past it — the band waits at \
         step 0 forever and goes stale"
    );
}

/// ⛔⛔ THE OWNERS SPLIT THE BAND UNDER BACKPRESSURE. MEASURED 2026-10-06 (`sim-20261006-033642`, 2 nodes): with the fold
/// waiting at the 64-step cap, the old open rule (`band_open_after(m)` later steps noted) read EVERY step from the pointer
/// on as open, so both holders served the pointer step — node 0 276 jobs all verified, node 1 278 jobs with 275 refused
/// "already applied" — and the band ran at one node's pace. Here two holders of one door with 40 noted steps and a
/// moving band (lease NOT expired) must each serve a step THEY OWN, and two different ones. RED on the pre-fix rule by
/// construction: both served step 0. And once the lease expires, the pointer step is any holder's (liveness, unchanged).
/// TWO-PARTY-REVIEWED: two independent Nodes, each choosing from its own door and its own id.
#[test]
fn db353_two_owners_split_a_full_band_and_never_both_prove_the_pointer_step() {
    let ids = ["band-owner-a".to_string(), "band-owner-b".to_string()];
    let provers = ids.to_vec();
    let tag = |o: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x5b17, o, 3, 5]));
    let mut nodes: Vec<Node> = ids
        .iter()
        .map(|id| {
            let mut n = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
            n.set_public_id(id.clone());
            for o in 0..40u64 {
                n.band_note_step_for_test(o, &[tag(o)]);
            }
            n
        })
        .collect();
    let m = crate::nf_sparse::band_owner_count(nodes[0].params().target_spacing_ms, provers.len());
    assert!(m >= 2, "CALIBRATION: two provers make two owners (m = {m})");
    assert!(40 > crate::nf_sparse::band_open_after(m), "CALIBRATION: the door holds far more than 2m steps (backpressure)");
    let jobs: Vec<u64> = nodes
        .iter_mut()
        .map(|n| n.band_next_owned_step(&provers, 0).expect("every owner serves a step it owns").ordinal)
        .collect();
    for (i, o) in jobs.iter().enumerate() {
        assert_eq!(
            crate::nf_sparse::band_step_owner(*o, &provers, m).as_deref(),
            Some(ids[i].as_str()),
            "⛔ holder {i} served step {o}, which it does not own, while the band is moving"
        );
    }
    assert_ne!(jobs[0], jobs[1], "⛔⛔ both holders proved the SAME step {} — the band runs at one node's pace", jobs[0]);
    // A STEP PROVEN AHEAD AND HELD IS NEVER SERVED AGAIN. MEASURED (`sim-20261006-035001`): the selector asked only "not
    // verified", re-served the held step, and its own door refused the copy 477 times ("a solicited copy … already held").
    let ahead = usize::from(jobs[0] == 0); // the holder whose first step is NOT the pointer: its proof can only be held
    nodes[ahead].arm_band_double_for_test();
    let job = nodes[ahead].band_next_owned_step(&provers, 0).expect("the owner serves its step again from a fresh call");
    let first = job.ordinal;
    let t = job.prove().expect("the bound double proves the served step");
    let receipt = nodes[ahead].band_offer(t, true);
    assert!(matches!(receipt, BandReceipt::Held), "CALIBRATION: a step proven ahead of its predecessor is HELD: {receipt:?}");
    // the cursor is rebuilt from the pointer (what any refusal, an applied absorb or a shed does) — the walk that re-served
    nodes[ahead].band_cursor_reset();
    let next = nodes[ahead].band_next_owned_step(&provers, 0).map(|j| j.ordinal);
    assert_ne!(next, Some(first), "⛔⛔ the holder re-served step {first}, which its door already holds — it would prove it again");
    // liveness: the pointer's owner is silent past its lease — the other holder takes the pointer step
    let pointer_owner = crate::nf_sparse::band_step_owner(0, &provers, m).expect("step 0 has an owner");
    let other = usize::from(ids[0] == pointer_owner);
    let mut fresh = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    fresh.set_public_id(ids[other].clone());
    for o in 0..40u64 {
        fresh.band_note_step_for_test(o, &[tag(o)]);
    }
    let _ = fresh.band_next_owned_step(&provers, 0); // absorbs the pointer step (not its own) and serves its own
    let job = fresh.band_next_owned_step(&provers, 1).expect("the holder serves the expired pointer step");
    assert_eq!(job.ordinal, 0, "⛔ the pointer's owner is silent past its lease and no other holder took step 0");
}

/// ⛔⛔ DB-404 — AN ABSENT OWNER COSTS ONE LEASE, THEN ITS STEPS ARE THE LIVE PROVERS' — AND P7'S TURN NEVER MOVES.
/// MEASURED sim-20261006-234445: a joiner ~600 steps behind owned one band step in three on every peer, each such step
/// waited a whole pointer lease, and the band fell to its 64-step cap (sim-20261007-002601 T3: lag 63/64 on both nodes).
/// MEASURED sim-20261007-002009 (the first DB-404, reverted as DEBT): benching inside `band_provers()` also removed the
/// benched peer from P7's turn set on the benching node only, so both nodes held the same turns.
/// Here a holder and a ghost — a KNOWN peer (adopted from a signed record, as the wire adopts one) that never proves —
/// share 40 noted steps; the holder runs the worker's own loop over `band_provers()` (serve what it owns; take the pointer
/// step only once its lease expired) with the bound band double until every step applied. (a) The band waits exactly ONE
/// lease. (b) The prover set P7's turn reads still names the ghost, so for every pointer exactly one of the two holds the
/// turn — the holder judging over its `band_provers()`, the ghost over its own view of the same two ids.
/// CALIBRATION: the ghost owns many of the 40 steps, so a rule with no bench waits one lease per ghost-owned step.
#[test]
fn db404_an_absent_owner_costs_one_lease_and_never_moves_p7s_turn() {
    let mut n = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    n.arm_band_double_for_test();
    let (gpk, gsk) = crate::pqauth::ml_dsa_keypair();
    let rec = crate::peer_directory::signed_record_for_test(
        &gpk,
        &gsk,
        "h34wf6htca3sje4d6m52ujulyll4kujdbh2fjrxc7hpd4tobfzxtxaad.onion",
        35000,
        1,
    );
    let ghost = rec.record.peer_id.clone();
    assert_eq!(n.adopt_peer(&rec), crate::peer_directory::PeerOutcome::Adopted, "CALIBRATION: the ghost is a known peer");
    let m = crate::nf_sparse::band_owner_count(n.params().target_spacing_ms, 2);
    let holder = (0u32..)
        .map(|i| format!("band-holder-{i}"))
        .find(|h| {
            let mut provers = vec![h.clone(), ghost.clone()];
            provers.sort();
            crate::nf_sparse::band_step_owner(0, &provers, m).as_deref() == Some(ghost.as_str())
        })
        .expect("some holder name leaves step 0 to the ghost");
    n.set_public_id(holder.clone());
    let provers = n.band_provers();
    assert_eq!(provers.len(), 2, "CALIBRATION: the holder sees itself and the ghost: {provers:?}");
    let steps = 40u64;
    let ghost_owned = (0..steps).filter(|o| crate::nf_sparse::band_step_owner(*o, &provers, m).as_deref() == Some(ghost.as_str())).count();
    assert!(ghost_owned >= 8, "CALIBRATION: the ghost owns {ghost_owned} of {steps} steps — each a lease without a bench");
    let tag = |o: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x0404, o, 3, 5]));
    for o in 0..steps {
        n.band_note_step_for_test(o, &[tag(o)]);
    }
    let start = n.band_steps_applied();
    let (mut leases, mut rounds) = (0usize, 0usize);
    while n.band_pointer().is_some() {
        rounds += 1;
        assert!(rounds <= 8 * steps as usize, "⛔ the band did not finish {steps} steps in {rounds} worker rounds");
        let now = n.band_provers(); // the runtime re-reads the prover set every worker round
        let job = match n.band_next_owned_step(&now, 0) {
            Some(j) => j,
            None => {
                // nothing this holder owns is left to prove: the band waits out the pointer's lease, then takes it
                leases += 1;
                n.band_next_owned_step(&now, 1).expect("an expired pointer step is any holder's")
            }
        };
        let t = job.prove().expect("the bound double proves a served step");
        let _ = n.band_offer(t, true);
    }
    eprintln!(
        "[db404] {steps} steps applied ({}) in {rounds} worker rounds; leases waited {leases}; the ghost owned {ghost_owned}",
        n.band_steps_applied() - start
    );
    assert_eq!(
        leases, 1,
        "⛔⛔ DB-404: the band waited {leases} pointer leases for an owner that never proves ({ghost_owned} steps were \
         its) — one lease per absent owner's step is what dropped the live band to its cap"
    );
    // (b) P7's turn: the set it reads is unchanged by the bench, so the two nodes split every turn exactly once
    let after = n.band_provers();
    assert_eq!(after, provers, "⛔ the bench reached the prover set P7's turn reads — two nodes would hold the same turns");
    let mut ghost_view = vec![holder.clone(), ghost.clone()];
    ghost_view.sort();
    for p in 0..2 * steps {
        let holders = [
            crate::node_runtime::NodeRuntime::<crate::transport::MultiTransport>::p7_turn_is_mine(Some(p), &after, Some(holder.as_str())),
            crate::node_runtime::NodeRuntime::<crate::transport::MultiTransport>::p7_turn_is_mine(Some(p), &ghost_view, Some(ghost.as_str())),
        ];
        assert_eq!(holders.iter().filter(|h| **h).count(), 1, "⛔ P7 turn at pointer {p}: holder/ghost hold {holders:?}");
    }
}

/// ⭐⭐ DB-454 — ONE TAKER PER OPEN POINTER STEP, ROTATING PER LAPSE. MEASURED (link 85): the old open rule
/// (`pointer_lease_expired && ordinal == pointer`) was true on EVERY holder at once, so a 3-node mesh proved each
/// lapsed step three times (the real-proof relay pin sat at 161 jobs for 89 steps, 80 own "already applied" refusals,
/// and the band never closed its lag). The backup taker is a deterministic function of the public ids every holder
/// shares — `band_backup_is_me` over `band_step_owners` with the step's own owner removed, indexed by the lapse count —
/// so on each lapse exactly ONE holder takes the open step, and the step's absent owner is never its own backup.
/// A further lapse rotates to the next rank, so a backup that is itself absent hands the step on (liveness).
/// RED on the pre-fix rule by construction: before this fix the open step had no single taker at all.
/// TWO-PARTY-REVIEWED: the taker is a PURE function of the public ids every holder shares, with NO per-node state — so
/// two nodes given the same (ordinal, prover set, lapse) necessarily pick the same taker, which is the whole property.
/// The cross-node boundary itself (three independent Nodes relaying one owner's proof to the two non-owners) is measured
/// by `sim_band_relay_real_proofs_let_non_owners_take_the_owners_steps` and its charged sibling; this pins the shared
/// selector those two agree on, directly and in milliseconds.
#[test]
fn db454_a_lapsed_open_step_has_exactly_one_backup_taker_rotating_per_lapse() {
    let provers: Vec<String> = (0..5).map(|i| format!("band-prover-{i}")).collect();
    let ordinal = 7u64;
    let m = crate::nf_sparse::band_owner_count(500, provers.len());
    let owner = crate::nf_sparse::band_step_owner(ordinal, &provers, m);
    assert!(owner.is_some(), "CALIBRATION: the step has an owner over {} provers", provers.len());
    // lapses == 0 — still within the owner's lease: NO holder is a backup taker.
    for p in &provers {
        assert!(
            !Node::band_backup_is_me(ordinal, &owner, &provers, Some(p.as_str()), 0),
            "⛔ holder {p} took the open step while the owner's lease still ran (lapses == 0)"
        );
    }
    // each lapse: EXACTLY ONE holder is the backup; it is never the step's own owner; and consecutive lapses rotate.
    let mut takers: Vec<String> = Vec::new();
    for lapse in 1..=provers.len() as u64 {
        let who: Vec<&String> = provers
            .iter()
            .filter(|p| Node::band_backup_is_me(ordinal, &owner, &provers, Some(p.as_str()), lapse))
            .collect();
        assert_eq!(
            who.len(),
            1,
            "⛔⛔ lapse {lapse}: {} holders took the SAME open step {ordinal} — the stampede the real lane measured ({who:?})",
            who.len()
        );
        assert_ne!(Some(who[0].clone()), owner, "⛔ lapse {lapse}: the step's own (absent) owner was picked as its own backup");
        takers.push(who[0].clone());
    }
    // the first `provers.len() − 1` lapses rotate through every non-owner (then the cycle repeats).
    let non_owners = provers.len() - 1;
    let distinct: std::collections::BTreeSet<&String> = takers.iter().take(non_owners).collect();
    assert_eq!(
        distinct.len(),
        non_owners,
        "⛔ the backup did not rotate through every one of the {non_owners} non-owners across lapses — takers {takers:?}"
    );
}

/// ⭐⭐ SPEED R4 (2026-11-10) — A BENCH MOVES ONLY THE BENCHED PROVER'S OWN STEPS, TO THE NEXT PROVER IN THAT STEP'S ORDER,
/// AND THE BENCHED PROVER IS STILL ASKED, LAST. `Node::band_order` over five provers and 256 steps: with one prover
/// benched, every step it does not own keeps the owner the full set gives it, every step it owns goes to the second
/// prover of that step's own order, and it stands last in every order. With nobody benched the order is the owner then
/// exactly the provers `band_backup_is_me` names lapse by lapse (DB-454's one taker per lapse, unchanged).
/// CALIBRATION (the hazard is armed): the rule this replaces — the owner over the provers NOT benched — moves steps the
/// benched prover never owned, which is what made two nodes with different benches disagree about every owner.
/// TWO-PARTY-REVIEWED: the order is a PURE function of the public ids and the caller's own bench set, with no other
/// per-node state; the two-node boundary is the pin below.
#[test]
fn speed_r4_a_bench_moves_only_the_benched_provers_steps_and_asks_it_last() {
    let provers: Vec<String> = (0..5).map(|i| format!("band-prover-{i}")).collect();
    let m = crate::nf_sparse::band_owner_count(500, provers.len());
    let sat = provers[2].clone();
    let live: Vec<String> = provers.iter().filter(|p| **p != sat).cloned().collect();
    let m_live = crate::nf_sparse::band_owner_count(500, live.len());
    let nobody = |_: &str| false;
    let one = |p: &str| p == sat;
    let (mut moved, mut kept, mut replaced_rule_moved_others) = (0usize, 0usize, 0usize);
    for o in 0..256u64 {
        let full = Node::band_order(o, &provers, m, &nobody);
        let with = Node::band_order(o, &provers, m, &one);
        let as_set = |v: &[String]| v.iter().cloned().collect::<std::collections::BTreeSet<String>>();
        assert_eq!(as_set(&full).len(), provers.len(), "step {o}: the order names every prover exactly once");
        assert_eq!(as_set(&with), as_set(&full), "step {o}: a bench drops nobody from the order");
        let owner = crate::nf_sparse::band_step_owner(o, &provers, m).expect("the step has an owner");
        assert_eq!(full[0], owner, "step {o}: the order starts at the owner every node computes");
        for lapse in 1..provers.len() as u64 {
            let who = &full[lapse as usize];
            assert!(
                Node::band_backup_is_me(o, &Some(owner.clone()), &provers, Some(who.as_str()), lapse),
                "⛔ step {o} lapse {lapse}: the order hands the step to {who}, not to the prover DB-454 names"
            );
        }
        assert_eq!(with.last(), Some(&sat), "⛔ step {o}: the benched prover is not asked last (left out, or still ahead)");
        if owner == sat {
            moved += 1;
            assert_eq!(with[0], full[1], "⛔ step {o}: the benched owner's step did not go to the next prover of ITS order");
        } else {
            kept += 1;
            assert_eq!(with[0], owner, "⛔⛔ step {o} is not the benched prover's and changed hands — two nodes that bench differently disagree on it");
            if crate::nf_sparse::band_step_owner(o, &live, m_live) != Some(owner) {
                replaced_rule_moved_others += 1;
            }
        }
    }
    assert!(moved >= 16 && kept >= 16, "CALIBRATION: the benched prover owns {moved} of 256 steps, the others {kept}");
    assert!(
        replaced_rule_moved_others >= 16,
        "CALIBRATION: the replaced rule (the owner over the provers not benched) moved only {replaced_rule_moved_others} steps of OTHER owners"
    );
}

/// The worker's loop on two nodes that hold the same 40 noted steps, for the pin below. `x` has lapsed `y`'s lease on the
/// pointer step and benched it; from there, round by round, BOTH nodes are served a step under their own view before
/// either proof lands (two proofs in flight at once, which is what a race is), both prove, and the proofs are delivered —
/// `first` delivers before the other every round — each to its own door and, when its door takes it, relayed to the
/// peer's. A node whose own proof finds another proof of that step already taken has lost a race: with `corrects` it
/// tells its ownership so, exactly as the runtime does (`NodeRuntime::tick_relay` → `Node::band_own_proof_lost`).
/// `slow` names a prover whose proofs take TWO rounds: the proof it starts in one round lands in the next, and it is
/// served nothing while one is in flight. That is the prover a lease lapses on, and it is what keeps the two views
/// colliding — at equal speed each prover's own steps land before the other is ever served them (first run of this pin,
/// 2026-11-10: 1 discarded proof with or without the correction, so equal speed arms nothing past the first race).
/// Returns (step proofs made and delivered, proofs discarded as lost races, leases waited after the first).
#[cfg(test)]
fn race_two_provers(nodes: &mut [Node; 2], provers: &[String], first: usize, slow: Option<usize>, corrects: bool) -> (usize, usize, usize) {
    let (mut made, mut discarded, mut leases) = (0usize, 0usize, 0usize);
    // the slow prover's proof, started one round ago and landing in this one
    let mut late: Option<(u64, crate::nf_sparse::BandTransition)> = None;
    for round in 0..400 {
        if nodes.iter().all(|n| n.band_pointer().is_none()) {
            return (made, discarded, leases);
        }
        let landing = late.take();
        let busy = |i: usize| slow == Some(i) && landing.is_some();
        let mut jobs: Vec<Option<super::BandProveJob>> =
            (0..2).map(|i| if busy(i) { None } else { nodes[i].band_next_owned_step(provers, 0) }).collect();
        if jobs.iter().all(Option::is_none) && landing.is_none() {
            // nobody holds the pointer step under either view: its lease runs out, and the lapse hands it on
            leases += 1;
            jobs = nodes.iter_mut().map(|n| n.band_next_owned_step(provers, 1)).collect();
            assert!(jobs.iter().any(Option::is_some), "⛔ round {round}: the pointer's lease lapsed and no prover took the step");
        }
        let mut proofs: Vec<Option<(u64, crate::nf_sparse::BandTransition)>> =
            jobs.into_iter().map(|j| j.map(|j| (j.ordinal, j.prove().expect("the bound double proves a served step")))).collect();
        if let Some(s) = slow {
            // what the slow prover started now is still in flight; what it started last round lands
            late = proofs[s].take();
            proofs[s] = landing;
        }
        for i in [first, 1 - first] {
            let Some((ordinal, t)) = proofs[i].clone() else { continue };
            made += 1;
            let own = nodes[i].band_offer_own(t.clone());
            if own.lost_to_another_proof() {
                discarded += 1;
                if corrects {
                    nodes[i].band_own_proof_lost(ordinal, provers, true); // this pin's lost race is a slow owner's
                }
                nodes[i].band_cursor_reset();
            } else if matches!(own, BandReceipt::Verified | BandReceipt::Held) {
                let _ = nodes[1 - i].band_offer(t, true);
            } else {
                nodes[i].band_cursor_reset();
            }
        }
    }
    panic!("⛔ the band did not finish in 400 rounds: pointers {:?}", nodes.iter().map(Node::band_pointer).collect::<Vec<_>>());
}

/// ⭐⭐ SPEED R4 (2026-11-10) — TWO PROVERS HOLD ONE STEP FOR ONE RACE, THEN THEY AGREE.
/// MEASURED on two real nodes (the landed binary): node 0 benched node 1 after one lapsed lease, node 1 could not know,
/// and both proved node 1's steps until the bench ran out — 4 of node 0's 14 step proofs in 8 minutes were refused
/// "already applied", 273 in one night. Here the same two views: `x` benches `y` on a lapse of the pointer's lease, and
/// both keep proving, two proofs in flight every round.
/// CALIBRATION (the hazard is armed): with no correction and `y` slower than `x` — the prover a lease lapses on — every
/// one of `y`'s steps is proven twice, for as long as the bench lasts; and at equal speed the views never meet (`x`
/// holds `y` benched to the end, `y` never learns).
/// With the correction the two views meet after ONE discarded proof, whichever proof lands first:
/// - `y`'s lands first → `x` lost the race → `x` trusts `y` again, and from then on each proves its own steps;
/// - `x`'s lands first, or `y` is the slow one → `y` lost a step it owns → `y` benches itself, and `x` (which holds
///   `y` benched) proves them all.
/// In each, every step is applied on both nodes and no lease is waited after the first.
/// TWO-PARTY-REVIEWED: two independent Nodes, each choosing from its own door, its own id and its own bench set; every
/// proof one makes is offered to the other's door as a relayed copy and judged there.
#[test]
fn speed_r4_two_provers_hold_one_step_for_one_race_and_then_agree() {
    let ids = ["band-race-a".to_string(), "band-race-b".to_string()];
    let provers = ids.to_vec();
    let steps = 40u64;
    let tag = |o: u64| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x4a11, o, 3, 5]));
    let m = crate::nf_sparse::band_owner_count(crate::params::ChainParams::default().target_spacing_ms, provers.len());
    assert!(m >= 2, "CALIBRATION: two provers make two owners (m = {m})");
    // `y` owns the pointer step; `x` is the other
    let pointer_owner = crate::nf_sparse::band_step_owner(0, &provers, m).expect("step 0 has an owner");
    let y = usize::from(ids[1] == pointer_owner);
    let x = 1 - y;
    let ys_steps = (0..steps).filter(|o| crate::nf_sparse::band_step_owner(*o, &provers, m).as_deref() == Some(ids[y].as_str())).count();
    assert!(ys_steps >= 8, "CALIBRATION: `y` owns {ys_steps} of {steps} steps");
    let fresh_pair = || -> [Node; 2] {
        let mut pair = ids.clone().map(|id| {
            let mut n = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
            n.arm_band_double_for_test();
            n.set_public_id(id);
            for o in 0..steps {
                n.band_note_step_for_test(o, &[tag(o)]);
            }
            n
        });
        // `y` is late with the pointer step: its lease lapses at `x`, which takes the step and benches `y`
        let _ = pair[x].band_next_owned_step(&provers, 0);
        let taken = pair[x].band_next_owned_step(&provers, 1).expect("the lapse hands `y`'s pointer step to `x`");
        assert_eq!(taken.ordinal, 0, "CALIBRATION: `x` took the pointer step");
        assert!(pair[x].band_benched_here(&ids[y]), "CALIBRATION: `x` benched `y`");
        assert!(!pair[y].band_benched_here(&ids[y]), "CALIBRATION: `y` does not know");
        pair[x].band_cursor_reset();
        pair
    };
    // CALIBRATION — no correction, `y` slow: `y`'s steps are proven by both for as long as the bench lasts
    let mut blind = fresh_pair();
    let (made, discarded, _) = race_two_provers(&mut blind, &provers, x, Some(y), false);
    eprintln!("[speed-r4] no correction, the benched prover slow: {made} step proofs delivered for {steps} steps, {discarded} discarded");
    assert!(
        discarded >= ys_steps / 2,
        "CALIBRATION: with no correction only {discarded} proofs were discarded — the two views do not collide here"
    );
    // CALIBRATION — no correction, equal speed: one race, and the two views are as far apart after it as before
    let mut blind = fresh_pair();
    let _ = race_two_provers(&mut blind, &provers, y, None, false);
    assert!(
        blind[x].band_benched_here(&ids[y]) && !blind[y].band_benched_here(&ids[y]),
        "CALIBRATION: with no correction the views met on their own — the correction below would prove nothing"
    );
    for (first, slow, who) in [
        (y, None, "the benched prover's proof lands first"),
        (x, None, "the benching prover's proof lands first"),
        (x, Some(y), "the benched prover is slow, its proofs land a round late"),
    ] {
        let mut pair = fresh_pair();
        let (made, discarded, leases) = race_two_provers(&mut pair, &provers, first, slow, true);
        eprintln!("[speed-r4] {who}: {made} step proofs for {steps} steps, {discarded} discarded, {leases} lease(s) waited");
        assert!(pair.iter().all(|n| n.band_pointer().is_none()), "⛔ {who}: a node's band did not finish");
        assert_eq!(pair[0].band_root(), pair[1].band_root(), "⛔ {who}: the two nodes' bands differ after the same steps");
        assert!(discarded <= 1, "⛔⛔ {who}: {discarded} step proofs were made and thrown away — the two views did not meet after one race");
        assert_eq!(leases, 0, "⛔ {who}: the band waited {leases} lease(s) after the views met");
        assert_eq!(made, steps as usize + discarded, "⛔ {who}: {made} proofs for {steps} steps and {discarded} discarded");
        if first == y && slow.is_none() {
            assert!(!pair[x].band_benched_here(&ids[y]), "⛔ `y` delivered first and `x` still holds it benched");
            assert!(!pair[y].band_benched_here(&ids[y]), "⛔ `y` won its step and benched itself");
        } else {
            assert!(pair[y].band_benched_here(&ids[y]), "⛔ `y` lost a step it owns and still proves its steps");
            assert!(pair[x].band_benched_here(&ids[y]), "⛔ `x` won the race and gave `y`'s steps back to it");
        }
    }
}

/// ⭐⭐⭐ THE FOLD-POINT SET IS POINTER-FREE — the property that lets DB-358's first-contact memo read it at graft (C1).
/// TWO PARTIES at DIFFERENT pointers over ONE fold: `applied` has drained the step into its view, `waiting` still
/// holds it as a pending admitted set. Both must answer every tag the same. CALIBRATION (the hazard is armed): the
/// VIEW ALONE answers differently on the two — that difference is what split the memo before P2'.
#[test]
fn db353_p1_the_fold_point_set_is_pointer_free() {
    let mut applied = Node::new(genesis_block()).unwrap();
    let mut waiting = Node::new(genesis_block()).unwrap();
    let tags: Vec<[u8; 32]> = (0..4u8).map(|i| [0xD0 ^ i; 32]).collect();
    let stranger = [0x5Au8; 32];
    waiting.band_note_step_for_test(0, &tags);
    let step = applied.band_plant_for_test(0, &tags).expect("the step verifies on the node that proves it");
    assert!(applied.band_pointer().is_none() && waiting.band_pointer() == Some(0), "CALIBRATION: the two pointers differ");
    // CALIBRATION: the view alone is pointer-dependent — the applied node's view holds the tags, the waiting one's not.
    let in_view = |n: &Node, t: &[u8; 32]| n.sparse_work.as_ref().and_then(|v| v.holds_spent_leaf(t)) == Some(true);
    assert!(tags.iter().all(|t| in_view(&applied, t)), "CALIBRATION: the drained view holds every admitted tag");
    assert!(tags.iter().all(|t| !in_view(&waiting, t)), "CALIBRATION: the waiting view holds none of them");
    // THE PROPERTY: the fold-point set answers the same on both nodes, for the step's tags and for a stranger.
    for t in &tags {
        assert!(applied.fold_point_spent_set().holds(t), "the applied node's fold-point set holds an admitted tag");
        assert!(
            waiting.fold_point_spent_set().holds(t),
            "⛔ the WAITING peer's fold-point set does not hold a tag its pending step admits — the memo would read \
             it fresh at graft on this node and old on the other"
        );
    }
    assert!(!applied.fold_point_spent_set().holds(&stranger), "a tag no step admitted is not held (applied)");
    assert!(!waiting.fold_point_spent_set().holds(&stranger), "a tag no step admitted is not held (waiting peer)");
    // And the drain does not move the peer's answer: it takes the same relayed object and lands where `applied` is.
    assert_eq!(waiting.band_offer(step, false), BandReceipt::Verified);
    assert!(tags.iter().all(|t| waiting.fold_point_spent_set().holds(t)), "the drain kept every answer the same");
    assert!(!waiting.fold_point_spent_set().holds(&stranger), "…and invented none");
    assert_eq!(waiting.band_root(), applied.band_root(), "the peer's band is the prover's after the relayed step");
}

/// §POLES T1 PRIVACY: `bond_set` and `dir_set` have constant byte shape regardless of carried entry count.
/// RED-first: the pin asserts the shape mismatch first (refutation), then asserts equality (census).
#[test]
fn poles_bond_set_dir_set_and_credit_set_have_constant_byte_shape() {
    let mut a = Node::new(genesis_block()).unwrap();
    // IDLE BLOCK: no pending bonds, no pending directory registrations.
    let idle = a.produce(1_000, Hash32::hash(b"idle-fr"), Hash32::hash(b"idle-mc")).expect("idle block");
    let idle_bond_len = idle.bond_set.len();
    let idle_dir_len = idle.dir_set.len();
    let idle_credit_len = idle.credit_set.len();
    assert_eq!(idle_bond_len, crate::block::SIDECAR_PADDED_BYTES,
        "REFUTATION: an idle block's bond_set must be the constant padded size, got {idle_bond_len}");
    assert_eq!(idle_dir_len, crate::block::SIDECAR_PADDED_BYTES,
        "REFUTATION: an idle block's dir_set must be the constant padded size, got {idle_dir_len}");
    assert_eq!(idle_credit_len, crate::block::CREDIT_SET_SEALED_BYTES,
        "REFUTATION: an idle block's credit_set must be the constant sealed width (§22), got {idle_credit_len}");
    // The parser reads zero real entries from the padded idle bond_set.
    let (entries, malformed) = Node::bond_set_entries(&idle.bond_set);
    assert!(entries.into_iter().flatten().count() == 0, "CALIBRATION: idle bond_set has no real entries");
    assert!(malformed, "CALIBRATION: the sentinel triggers the malformed tail flag");
    // The idle block still carries a mining reward in its credit_set (every produced block does).
    assert!(crate::block::credit_set_has_entries(&idle.credit_set, crate::block::credit_seal_key(&idle.header, idle.cover_key.as_ref()).as_ref()),
        "CALIBRATION: idle credit_set carries the mining reward");

    // BUSY BLOCK: publish a validator bond so bond_set carries a real entry.
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let header = crate::membership_bond_tx::MembershipBondHeader {
        secp33: vec![2u8; 33],
        ed32: [9u8; 32],
        kem_ek: ek,
        nonce: crate::membership_bond_tx::fresh_seat_nonce(),
    };
    let sig = crate::pqauth::ml_dsa_sign(
        &crate::pqauth::validator_membership_msg(&vid, &header.digest()),
        &sk,
    ).expect("signs");
    assert_eq!(
        a.publish_membership_bond(&pk, &sig, header),
        AssetSpendOutcome::Published,
        "CALIBRATION: the bond publishes"
    );
    let busy = a.produce(2_000, Hash32::hash(b"busy-fr"), Hash32::hash(b"busy-mc")).expect("busy block");
    let busy_bond_len = busy.bond_set.len();
    let busy_dir_len = busy.dir_set.len();
    let busy_credit_len = busy.credit_set.len();
    // THE PROPERTY: busy and idle blocks have identical byte lengths.
    assert_eq!(busy_bond_len, idle_bond_len,
        "§POLES: bond_set shape leaks entry count — busy {busy_bond_len} != idle {idle_bond_len}");
    assert_eq!(busy_dir_len, idle_dir_len,
        "§POLES: dir_set shape leaks entry count — busy {busy_dir_len} != idle {idle_dir_len}");
    assert_eq!(busy_credit_len, idle_credit_len,
        "§POLES: credit_set shape leaks entry count — busy {busy_credit_len} != idle {idle_credit_len}");
    // The parser reads the real entry from the busy bond_set.
    let (entries, _) = Node::bond_set_entries(&busy.bond_set);
    assert!(entries.into_iter().flatten().count() > 0, "CALIBRATION: busy bond_set has real entries");
    // The busy block carries a reward in its credit_set.
    assert!(crate::block::credit_set_has_entries(&busy.credit_set, crate::block::credit_seal_key(&busy.header, busy.cover_key.as_ref()).as_ref()),
        "CALIBRATION: busy credit_set carries the mining reward");
    // §POLES: the root binds the REAL content, not the cover padding.
    assert_eq!(
        busy.header.bond_set_root,
        crate::block::da_sidecar_root_of(
            &busy.bond_set[..crate::block::sidecar_real_len(&busy.bond_set)]
        ),
        "the busy block's root binds its real bond_set content"
    );
    assert_eq!(
        idle.header.bond_set_root,
        crate::block::da_sidecar_root_of(
            &idle.bond_set[..crate::block::sidecar_real_len(&idle.bond_set)]
        ),
        "the idle block's root binds its real bond_set content"
    );
    // §22: the credit root binds the SEALED bytes whole — a keyless door binds the body, a holder reads the frames.
    assert_eq!(busy.header.credit_set_root, crate::block::credit_set_root_of(&busy.credit_set), "the busy block's root binds its sealed credit_set");
    assert_eq!(idle.header.credit_set_root, crate::block::credit_set_root_of(&idle.credit_set), "the idle block's root binds its sealed credit_set");
    for (who, b) in [("busy", &busy), ("idle", &idle)] {
        assert!(crate::block::credit_set_open(&b.credit_set, None).is_none(), "§22 ({who}): a keyless observer opens nothing");
        assert!(crate::block::sidecar_real_len(&b.credit_set) == 0 || crate::block::credit_set_iter_plain(&b.credit_set).is_none(),
            "§22 ({who}): the keyless frame walk reads no entry off the sealed bytes");
        let key = crate::block::credit_seal_key(&b.header, b.cover_key.as_ref()).expect("a produced block carries its key");
        assert!(crate::block::credit_set_has_entries(&b.credit_set, Some(&key)), "§22 ({who}): the holder reads the reward");
    }
}

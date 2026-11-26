// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE RUNTIME-MESH BACKEND — the same cases, driven through real `NodeRuntime`s over an in-memory
//! cell hub.**
//!
//! `consensus_scenarios` drives bare `Node`s and EMULATES the mesh's repair paths (parent asks, pages,
//! roots runs, notes backfill, beacons, heals). That is fast and it searches well, but every emulated
//! path is a place the emulation can differ from the node. This backend removes the emulation: each
//! party is a full `NodeRuntime` ticking exactly as the daemon ticks, and the only thing the schedule
//! owns is DELIVERY — which cells reach which party, when, and which are lost — through a hub that holds
//! every sent cell until the schedule releases it. Gossip, note requests and pages, roots runs, beacons,
//! sync bundles, backfill, re-relay and the unspent heal all run on their own code, on their own wire
//! shapes, at the channel's own pacing.
//!
//! The case grammar is the one `consensus_scenarios.txt` uses, with delivery mapped to the hub:
//! `deliver k` releases everything held for party `k mod parties`, `burst k` releases for everyone,
//! `drop p` discards what party `p` has not yet received (gossip never brings it again; only the
//! node's own asks can), `drain` releases and ticks until nothing moves. `jump` is explicit (the
//! runtime also syncs on its own when beacons split). The note actions act on the runtime's node
//! exactly as in the bare-node engine; the adversarial ones stay with that engine.
//!
//! ⛔ SCOPE: still an in-process island — no onion transport, no per-node cost, no scale. The live pair
//! gate and the multi-device run at the scale floor remain the only network proofs.

#[cfg(test)]
pub(crate) mod tests {
    /// A FABRICATED, PoUW-less block shaped exactly like a real one: a real header's fields with a
    /// new parent, a fresh timestamp/nonce, and a saturated `work` claim — no `pow_proof`, and a
    /// grind that meets no target. The three carry/anchor door pins below all drive this same
    /// shape, so the fabrication is written once (the door under test differs, the bytes do not).
    fn forged_powless_block_on(
        real: &crate::block::BlockHeader,
        parent: crate::block::BlockId,
        salt: u64,
    ) -> crate::block::Block {
        let mut h = real.clone();
        h.parents = vec![parent];
        h.timestamp = real.timestamp + 1_000 + salt;
        h.nonce = 0xFEED_FACE + salt;
        h.work = u128::MAX / 4;
        h.tx_merkle_root = crate::miner::tx_merkle_root(&[]);
        crate::block::Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: h,
            tx_ids: Vec::new(),
            pow_proof: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            cover_transition: None,
            member_transition: None,
        }
    }
    use crate::block::Block;
    use crate::consensus_scenarios::{parse, scenario_node_in, scenario_node_resumed_in_at_depth, Act, ScenarioDataDir, CASES};
    use crate::hash::Hash32;
    use crate::net::{NetError, CELL_SIZE};
    use crate::node::Node;
    use crate::node_runtime::NodeRuntime;
    use crate::transport::CellTransport;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// The hub: every cell a party sends is HELD for each other party until the schedule releases it.
    struct HubState {
        /// ⭐ THE FETCH-AND-DISCARD CYCLE'S OWN MEASUREMENT, IN FIXED SIZE.
        ///
        /// A by-record page answered N times in a row to the same asker for the same request is a
        /// page that asker threw away N-1 times: the answer landed, the retention rule released it,
        /// the want re-fired, the peer re-served it. The 2026-09-05 gate measured 41 such re-serves
        /// in 6.5 minutes; one in-process run of the rolling-restart pin measured 1,990 × 885,504
        /// bytes before a 40-minute wall clock killed it. Nothing counted that, so the loop was
        /// invisible to every assertion in the suite — only a log grep could see it.
        ///
        /// THE DISCRIMINATOR IS THE ANSWER, NOT THE ASK. A repeated request body alone is not the
        /// defect: a page truncated at the byte budget is re-asked with the identical body and
        /// carries DIFFERENT records each round, which is progress. What can only be discard-and-
        /// refetch is the same asker receiving a BYTE-IDENTICAL page again, so the digest covers
        /// request ‖ response.
        /// MEASURED 2026-09-05 on the first run of this pin after the Cause-1 fixes: 388 answered
        /// by-record asks / 14,662,038 bytes with a request-only streak of 5 — against 1,990
        /// answers × 885,504 bytes on the pre-fix tree, which never reached an assertion at all.
        ///
        /// FIXED SIZE BY CONSTRUCTION, not by a declared bound: (asker index, a 32-byte digest of
        /// request ‖ response, its consecutive-repeat count, the worst such count of the run, the
        /// request kind that set that worst) plus two counters. Never a map keyed by what was asked
        /// — that would grow with the run, which is the very shape this exists to measure.
        by_id: Mutex<(usize, [u8; 32], u64, u64, u8)>,
        by_id_answers: std::sync::atomic::AtomicU64,
        by_id_bytes: std::sync::atomic::AtomicU64,
        /// ⭐ THE HUB'S ONE CLOCK (DB-416's shape, the netsim's `SimEndpoint::clock_ms`): every party's runtime reads the
        /// sim's `now` through `CellTransport::clock_ms`, so `NodeRuntime::now_unix_ms` and the `tick(now)` it is driven
        /// with are the SAME clock — as on a daemon, where both are the wall clock. ⛔ MEASURED (link 58, db275,
        /// scratchpad/night/link58-db275b.log): with no hub clock `now_unix_ms` fell back to the WALL clock while `tick`
        /// ran on the sim's; the served-bundle arm (`on_sync_response`) stamped p1's `last_batch_pull_ms` with wall time,
        /// ~weeks ahead of the sim, so p1's re-arm gate (`now − last < rearm`, saturating) refused every catch-up ask for the
        /// rest of the run — 18 of 18 post-heal inventories came from p0 (tip score 121), none from p1 (90), and the pair
        /// never converged. Set by `RtSim::tick` (the one choke point every drive loop passes) and before any runtime is
        /// built or announced.
        clock: std::sync::atomic::AtomicU64,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one queue per party of the case, each
        /// drained by the schedule's own deliveries; a test scaffold, never a node store.
        held: Vec<Mutex<VecDeque<Vec<u8>>>>,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one queue per party, drained by the
        /// runtime's own inbound poll every tick; a test scaffold, never a node store.
        released: Vec<Mutex<VecDeque<Vec<u8>>>>,
        /// THE BULK LANE, requester side: what each party asked for and has not been answered yet.
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one queue per party, drained by the
        /// sim's own bulk pump every tick; a test scaffold, never a node store.
        bulk_reqs: Vec<Mutex<VecDeque<Vec<u8>>>>,
        /// THE BULK LANE, answer side: pages waiting for the party that asked.
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one queue per party, drained by the
        /// runtime's own `take_bulk_responses` every tick; a test scaffold, never a node store.
        bulk_resp: Vec<Mutex<VecDeque<Vec<u8>>>>,
        /// ⭐ DB-326 / G11b — THE FOLLOW LANE'S one-outstanding bookkeeping (what arti keeps per followed host, what
        /// `SimEndpoint::follow_out` keeps per link): `true` while this party has a `FOLLOW` (kind 20) in flight. The hub
        /// is one host per party, so one flag per party. Set in `bulk_follow_request`, cleared when the party drains its
        /// `BLOCKFOLW` page or when no peer answered the ask (an unanswered follow must not pin the party forever).
        /// MEASURED (G11b, 2026-10-22): with the trait default (`bulk_follow_request` = 0) the hub had NO follow lane,
        /// so a party adopting the constant bundle at a peer's fold anchor could never page the backlog above it —
        /// recorded_case_05 folded 27 of 94, the 64-deep loss took 13 trips. O1-FOOTPRINT-REVIEWED: one bool per party.
        follow_out: Vec<std::sync::atomic::AtomicBool>,
    }

    impl HubState {
        fn new(parties: usize) -> Arc<HubState> {
            Arc::new(HubState {
                by_id: Mutex::new((usize::MAX, [0u8; 32], 0, 0, 0)),
                by_id_answers: std::sync::atomic::AtomicU64::new(0),
                by_id_bytes: std::sync::atomic::AtomicU64::new(0),
                clock: std::sync::atomic::AtomicU64::new(0),
                held: (0..parties).map(|_| Mutex::new(VecDeque::new())).collect(),
                released: (0..parties).map(|_| Mutex::new(VecDeque::new())).collect(),
                bulk_reqs: (0..parties).map(|_| Mutex::new(VecDeque::new())).collect(),
                bulk_resp: (0..parties).map(|_| Mutex::new(VecDeque::new())).collect(),
                follow_out: (0..parties).map(|_| std::sync::atomic::AtomicBool::new(false)).collect(),
            })
        }
        fn release(&self, to: usize) -> usize {
            let mut h = self.held[to].lock().unwrap();
            let mut r = self.released[to].lock().unwrap();
            let n = h.len();
            r.extend(h.drain(..));
            n
        }
        fn discard(&self, to: usize) -> usize {
            let mut h = self.held[to].lock().unwrap();
            let n = h.len();
            h.clear();
            n
        }
        fn in_flight(&self) -> usize {
            self.held.iter().map(|q| q.lock().unwrap().len()).sum::<usize>()
                + self.released.iter().map(|q| q.lock().unwrap().len()).sum::<usize>()
                + self.bulk_reqs.iter().map(|q| q.lock().unwrap().len()).sum::<usize>()
                + self.bulk_resp.iter().map(|q| q.lock().unwrap().len()).sum::<usize>()
        }
    }

    /// One party's endpoint on the hub.
    struct HubEndpoint {
        hub: Arc<HubState>,
        me: usize,
    }

    /// A hub party's peering (see `HubEndpoint::peering`): the hub is connected by construction, so `add` dials nothing,
    /// there is no own onion identity at the transport, and every other party is a live writer.
    struct HubPeering {
        parties: usize,
        me: usize,
    }

    impl crate::transport::PeerPeering for HubPeering {
        fn add(&self, _peer_id: &str, _addr: &str, _x_pk: &[u8], _ek: &[u8]) -> bool {
            true
        }
        fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
            None
        }
        fn live_writers(&self) -> usize {
            (0..self.parties).filter(|&j| j != self.me).count()
        }
    }

    impl CellTransport for HubEndpoint {
        fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
            if cell.len() != CELL_SIZE {
                return Err(NetError::BadCell);
            }
            if crate::net::is_cover(&cell) {
                return Ok(()); // cover traffic is a wire property, not a consensus one: the hub carries payload only
            }
            for (i, q) in self.hub.held.iter().enumerate() {
                if i != self.me {
                    q.lock().unwrap().push_back(cell.clone());
                }
            }
            Ok(())
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            self.hub.released[self.me].lock().unwrap().pop_front()
        }
        /// ⭐⭐⭐ THE BULK LANE. Sidecar rows (kind 5), roots runs (kind 6) and record pages travel HERE,
        /// not on the cell path — on the live nodes every one of them is a `[bulk] page fetched from
        /// …onion`. A hub without this lane is a mesh where a node that needs rows can never obtain
        /// them: MEASURED 2026-09-03, the first runtime-backend run failed all ten recorded cases, and
        /// the restarted party sat at `served_seq` 8 for 640 rounds with `wants(ord=[1,2,3])` and
        /// `[fold-wait] … the fold waits for the rows` while its peer served nobody.
        /// The request is queued for the sim's pump, which answers it from a PEER through the same
        /// `serve_notes_req_bytes` the production slot installs (serve.rs).
        fn has_bulk_lane(&self) -> bool {
            true
        }
        /// The hub's one clock (see `HubState::clock`): the runtime's timers read the sim's `now`, never the wall clock.
        fn clock_ms(&self) -> Option<u64> {
            Some(self.hub.clock.load(std::sync::atomic::Ordering::Relaxed))
        }
        /// ⭐ DB-412 — the hub's PEERING, counted as arti counts its writers (the netsim's `SimPeering` shape): every other
        /// party is a live link (the hub never severs one; a restart is instantaneous). ⛔ MEASURED (link 19,
        /// `honest_schedule_seed_3`, scratchpad/night/link19-seed3.log): with the default `NoPeering` (0 live writers)
        /// every party took the LONE-node branch of `fair_share_spacing_ms` and produced at the 500 ms mesh target — three
        /// parties laying ~6 blocks/s, the band at its 64-step cap on every party and still stepping when the drain's
        /// 400 settle rounds ran out. Three connected daemons space at the fair share instead.
        fn peering(&self) -> Box<dyn crate::transport::PeerPeering> {
            Box::new(HubPeering { parties: self.hub.held.len(), me: self.me })
        }
        fn bulk_raw_request(&self, req: &[u8]) -> bool {
            self.hub.bulk_reqs[self.me].lock().unwrap().push_back(req.to_vec());
            true
        }
        /// ⭐ DB-326 / G11b — the hub's FOLLOW lane: one `FOLLOW` (kind 20) outstanding per party. The ask rides the same
        /// `bulk_reqs` queue every bulk kind rides; `pump_bulk` answers it from a PEER through `serve_notes_req_bytes`
        /// (kind 20 → `follow_page_after_locator`), and the runtime's intake dispatches the `BLOCKFOLW` page to
        /// `on_follow_page`. Returns 1 when a follow was issued, 0 while one is in flight (the runtime offers the ask
        /// every tick, as it does over arti).
        fn bulk_follow_request(&self, req: &[u8]) -> usize {
            use std::sync::atomic::Ordering;
            if self.hub.follow_out[self.me].swap(true, Ordering::AcqRel) {
                return 0;
            }
            self.hub.bulk_reqs[self.me].lock().unwrap().push_back(req.to_vec());
            1
        }
        fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
            let mut q = self.hub.bulk_resp[self.me].lock().unwrap();
            let n = max.min(q.len());
            let out: Vec<Vec<u8>> = q.drain(..n).collect();
            if out.iter().any(|p| p.len() >= 9 && &p[..9] == b"BLOCKFOLW") {
                // the follow's answer is in the party's hands: the next tick's offer may issue a new one
                self.hub.follow_out[self.me].store(false, std::sync::atomic::Ordering::Release);
            }
            out
        }
    }

    pub(crate) struct RtSim {
        hub: Arc<HubState>,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — the party count the case fixes.
        parties: Vec<NodeRuntime<HubEndpoint>>,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most one per Produce action of a
        /// fixed-length case; the ordinal comparison at the end reads it.
        blocks: Vec<Block>,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per Receive action of the case.
        real_notes: Vec<([u8; 32], bool)>,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per Receive action of the case.
        real_records: Vec<u64>,
        now: u64,
        rng: u64,
        /// A HARD WALL-CLOCK DEADLINE FOR THE WHOLE SCENARIO, checked at every tick. `None` (the
        /// default) means no deadline. A pin that cannot finish gates nothing: on 2026-09-06 the two
        /// rolling-restart pins ran into a 25-minute external alarm and were KILLED, not asserted —
        /// so for that whole day they proved nothing while looking registered. A deadline that FAILS
        /// LOUDLY inside the test turns "silently hung" into a named, diagnosable red.
        deadline: Option<std::time::Instant>,
        /// Which holder answers the next bulk ask (rotates, so one party is never the only server).
        bulk_rotor: usize,
        /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one entry per executed action.
        trace: Vec<Act>,
        /// TRANSPORT LATENCY for the bulk lane, in pump passes (0 = same-tick answers, the
        /// historical harness shape). The live pair rides Tor: an ask and its answer are separated
        /// by a real round trip, so at ANY sampling instant a producing node has an ask-width of
        /// in-flight entries — a shape the same-tick hub can never show (measured this session:
        /// two full-speed probes read every term 0 at every sample while the live gate read 32/64
        /// forever). Implemented by SKIPPING serve passes: while `pump_clock % (bulk_delay + 1) !=
        /// 0` the queued asks simply wait in the hub's existing queues — the same answer, through
        /// the same serve fn, just later. No new store of any kind.
        bulk_delay: u64,
        /// The byte budget a served BLOCK-DESCENT page (bulk ask kind 9) is cut to. The live cell
        /// lane cuts every page at 36,000 bytes (~4 block shells); the bulk stream at 1 MiB.
        /// Default = the bulk stream, so every existing scenario is unchanged; a scenario that
        /// wants the CELL lane's page sets it. Other bulk kinds always keep the 1 MiB budget.
        bulk_budget: usize,
        /// Pump-pass clock for `bulk_delay` (increments once per `pump_bulk`).
        pump_clock: u64,
        /// ⛔ DB-275 — every body a `BLOCKBTCH` answer carried to an asker, and how many of them that asker already
        /// held WHOLE at the moment it asked (the hub serves in the same pump pass the ask was queued, so the
        /// asker's DAG here IS its DAG at ask time). Two counters, never a map: fixed size by construction.
        batch_bodies_served: u64,
        batch_bodies_already_held: u64,
        /// DB-275: bodies the asker NAMED in a GETDATA and then held whole by the time the server answered — a race with
        /// another lane (a by-id pull landing inside the same tick), not a server guess. Reported, never counted as waste.
        batch_bodies_named_raced: u64,
        /// DB-275b: per asker, the holder that answered its last kind-18 inventory. A kind-19 GETDATA goes back to that
        /// holder — the production rule (`arti_transport::pick_bulk_host`), mirrored so the sim routes like the wire.
        /// O1-FOOTPRINT-REVIEWED: one slot per party of the case.
        inv_holder: Vec<Option<usize>>,
        /// ⭐ Each party's ML-DSA identity key — the daemon's key file, kept across a restart as the file is. A party
        /// ANNOUNCES its own signed peer record at boot and after every restart (`announce`), as every daemon does once its
        /// onion is up. ⛔ MEASURED (link 19, `honest_schedule_seed_2`, scratchpad/night/link19-seed2c.log): with no
        /// announce every party had NO public id, so no party OWNED a band step (`band_next_owned_step`: `me` = None) and
        /// the band moved only when the pointer's lease expired — a lease that is twice the band's own measured step time,
        /// itself lease-bound: 5 steps applied in the whole run, the band at its 64-step cap, the fold waiting on it
        /// 3,948 times (the baseline 26cfe90 run the same: 4,107 waits). A hub of identity-less nodes measures a mesh no
        /// operator runs. O1-FOOTPRINT-REVIEWED: one keypair per party, fixed by the case.
        keys: Vec<(Vec<u8>, Vec<u8>)>,
        /// ⛔ THE DISK THIS RUN OWNS — one datadir per party, index-aligned with `parties`, for the whole
        /// life of the `RtSim`; `restart` reuses `dirs[i]` instead of minting another, and dropping the
        /// `RtSim` removes the subtree even when a case panics. Same lifecycle, same reason, as
        /// `Sim::dirs`: see [`ScenarioDataDir`] for the 11,161-orphaned-directory measurement.
        ///
        /// ⛔ THIS FIELD MUST STAY LAST — Rust drops fields in declaration order, so `parties` dies before
        /// the directories its nodes persist into.
        /// O1-FOOTPRINT-REVIEWED: bounded by `harness::fuzz::engine::MAX_PARTIES` — one slot per party,
        /// fixed by the case before it runs; a restart REUSES its slot rather than adding one.
        dirs: Vec<ScenarioDataDir>,
    }

    const SLOT_MS: u64 = crate::net::COVER_INTERVAL_MS;

    impl RtSim {
        fn new(parties: usize, seed: u64) -> RtSim {
            let n = parties.max(2);
            let hub = HubState::new(n);
            let mut rts = Vec::with_capacity(n);
            let dirs: Vec<ScenarioDataDir> = (0..n).map(|_| ScenarioDataDir::new()).collect();
            // §FAST (lane c batch 4): the whole hub grinds the BOUND PoUW double (`pouw::bound_pow`), never mixed — armed
            // here, before any party or its runtime's preverify hasher is built; a restart in this thread stays armed.
            crate::pouw::bound_pow::arm_on_this_thread(true);
            let nodes: Vec<Node> = (0..n).map(|i| scenario_node_in(&dirs[i])).collect();
            let now = nodes[0]
                .dag()
                .get(&nodes[0].selected_tip().expect("tip"))
                .expect("header")
                .header
                .timestamp
                + 60_000;
            hub.clock.store(now, std::sync::atomic::Ordering::Relaxed); // the runtimes are built on the sim's clock
            for (i, node) in nodes.into_iter().enumerate() {
                let mut rt = NodeRuntime::new(node, HubEndpoint { hub: Arc::clone(&hub), me: i });
                rt.mark_mesh_joined_for_test();
                rt.node_mut().arm_band_double_for_test(); // the whole hub runs the bound band double, never mixed
                rts.push(rt);
            }
            let mut sim = RtSim { hub, parties: rts, blocks: Vec::new(), real_notes: Vec::new(), real_records: Vec::new(), now, rng: seed | 1, deadline: None, bulk_rotor: 0, trace: Vec::new(), bulk_delay: 0, bulk_budget: 1_048_576, pump_clock: 0, batch_bodies_served: 0, batch_bodies_already_held: 0, batch_bodies_named_raced: 0, inv_holder: vec![None; n], keys: (0..n).map(|_| crate::pqauth::ml_dsa_keypair()).collect(), dirs };
            for i in 0..n {
                sim.announce(i);
            }
            sim
        }

        /// ⭐ TEST FIXTURE — THE HUB OVER GIVEN NODES: the in-process DA lane a wire-fed party needs. Each node is wrapped
        /// in its real `NodeRuntime` on the hub (cells + the bulk lane, as the live nodes carry them), so a party handed a
        /// block over the wire fetches the block's RECORD by id from a peer that holds it — the production lane — instead of
        /// a pin planting it. Built for the DB-224 carriage pins, whose objects now apply at their block's fold (DB-274 P4b),
        /// and a fold needs the record the wire never carries. The clock starts past the LATEST party tip.
        pub(crate) fn with_nodes(nodes: Vec<Node>, seed: u64) -> RtSim {
            let n = nodes.len();
            assert!(n >= 2, "a hub needs at least two parties");
            let hub = HubState::new(n);
            let dirs: Vec<ScenarioDataDir> = (0..n).map(|_| ScenarioDataDir::new()).collect();
            let latest_tip_ts = nodes
                .iter()
                .map(|node| {
                    let tip = node.selected_tip().expect("every party holds a tip (genesis at least)");
                    node.dag().get(&tip).expect("a party holds its own tip's header").header.timestamp
                })
                .max()
                .expect("at least two parties");
            let now = latest_tip_ts + 60_000;
            hub.clock.store(now, std::sync::atomic::Ordering::Relaxed); // the runtimes are built on the sim's clock
            let mut rts = Vec::with_capacity(n);
            for (i, node) in nodes.into_iter().enumerate() {
                let mut rt = NodeRuntime::new(node, HubEndpoint { hub: Arc::clone(&hub), me: i });
                rt.mark_mesh_joined_for_test();
                rt.node_mut().arm_band_double_for_test(); // the whole hub runs the bound band double, never mixed
                rts.push(rt);
            }
            let mut sim = RtSim { hub, parties: rts, blocks: Vec::new(), real_notes: Vec::new(), real_records: Vec::new(), now, rng: seed | 1, deadline: None, bulk_rotor: 0, trace: Vec::new(), bulk_delay: 0, bulk_budget: 1_048_576, pump_clock: 0, batch_bodies_served: 0, batch_bodies_already_held: 0, batch_bodies_named_raced: 0, inv_holder: vec![None; n], keys: (0..n).map(|_| crate::pqauth::ml_dsa_keypair()).collect(), dirs };
            for i in 0..n {
                sim.announce(i);
            }
            sim
        }

        /// The hub's clock (ms) — a pin that produces directly stamps its block past it, so the block sits after every
        /// block the runtimes laid.
        pub(crate) fn now(&self) -> u64 {
            self.now
        }

        /// Party `i`'s node, read-only.
        pub(crate) fn node(&self, i: usize) -> &Node {
            self.parties[i].node()
        }

        /// Party `i`'s node, to act on directly (publish, ingest a wire block) between drains.
        pub(crate) fn node_mut(&mut self, i: usize) -> &mut Node {
            self.parties[i].node_mut()
        }

        /// Run ROUNDS (every queue released, every party ticked once, the clock one slot on) until `done` holds, at most
        /// `max_rounds`; returns whether it held. The bounded driver for a pin whose condition lands in a few rounds — a
        /// full `drain` waits for quiet, and two producing runtimes are never quiet.
        pub(crate) fn rounds_until(&mut self, max_rounds: usize, done: impl Fn(&RtSim) -> bool) -> bool {
            for _ in 0..max_rounds {
                if done(self) {
                    return true;
                }
                self.burst_all();
            }
            done(self)
        }

        /// Drain the hub until `done` holds, at most `rounds` drains; returns whether it held.
        pub(crate) fn drain_until(&mut self, rounds: usize, done: impl Fn(&RtSim) -> bool) -> bool {
            for _ in 0..rounds {
                if done(self) {
                    return true;
                }
                self.drain();
            }
            done(self)
        }

        /// Arm the scenario's hard wall-clock deadline: every subsequent tick asserts the clock has
        /// not passed it. See the `deadline` field for why a pin must fail loudly rather than hang.
        pub(crate) fn arm_deadline(&mut self, budget: std::time::Duration) {
            self.deadline = Some(std::time::Instant::now() + budget);
        }

        fn rand(&mut self, m: usize) -> usize {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            if m == 0 { 0 } else { (self.rng >> 3) as usize % m }
        }

        fn tick(&mut self, i: usize) {
            // THE HARD DEADLINE, checked at the one choke point every drive loop passes through —
            // produce, drain, burst and deliver all reach here — so a scenario that stops making
            // progress fails LOUDLY mid-run instead of hanging until an external alarm kills it
            // (which is what happened to both rolling-restart pins on 2026-09-06: killed at 25
            // minutes, nothing asserted, nothing gated).
            if let Some(d) = self.deadline {
                assert!(
                    std::time::Instant::now() < d,
                    "SCENARIO DEADLINE BLOWN: the drive loop was still ticking when the scenario's \
                     hard wall-clock budget expired (trace so far: {:?}). A pin that cannot finish \
                     gates nothing — diagnose the loop, do not raise the budget.",
                    self.trace
                );
            }
            self.hub.clock.store(self.now, std::sync::atomic::Ordering::Relaxed); // the one clock (see `HubState::clock`)
            let _ = self.parties[i].tick(self.now, Hash32::hash(b"scenario-frontier"), Hash32::hash(b"scenario-miner"));
            // ⭐ THE SERVING LOOP'S OTHER HALF (`main.rs`'s relay thread): `tick_relay` runs the band PROVE WORKER and relays
            // its steps. Driving `tick` alone exercised a loop no serving node runs — MEASURED 2026-10-02: the fold outran
            // the band past its lag cap 994 times in one journey, the door went stale, and every pool refused every spend.
            // The hub's parties run the bound band double (`arm_band_double_for_test`), so a step costs microseconds.
            self.parties[i].tick_relay(self.now);
            self.pump_bulk();
        }

        /// Answer the bulk lane the way a peer does: every queued request is served by ANOTHER party
        /// through `serve_notes_req_bytes` — the exact function serve.rs installs in the transport's
        /// bulk slot — and the bytes are queued for the asker's own `take_bulk_responses`.
        /// Holders are tried in rotation and the first non-empty answer wins; when no peer holds it the
        /// ask is simply unanswered, exactly as on the wire (the node re-asks on its own cadence).
        fn pump_bulk(&mut self) {
            // The bulk lane's transport latency (see `bulk_delay`): on a skipped pass the queued
            // asks stay exactly where they are and are served on the next serving pass — the
            // in-flight interval every real transport has.
            self.pump_clock = self.pump_clock.wrapping_add(1);
            if self.bulk_delay > 0 && self.pump_clock % (self.bulk_delay + 1) != 0 {
                return;
            }
            let n = self.parties.len();
            for asker in 0..n {
                let pending: Vec<Vec<u8>> = {
                    let mut q = self.hub.bulk_reqs[asker].lock().unwrap();
                    q.drain(..).collect()
                };
                for req in pending {
                    self.bulk_rotor = self.bulk_rotor.wrapping_add(1);
                    let mut answered = false;
                    // DB-275b: a GETDATA goes to the holder whose inventory named its ids (production's rule).
                    let getdata_holder = if req.first() == Some(&19u8) { self.inv_holder[asker] } else { None };
                    for step in 0..n {
                        let holder = match getdata_holder {
                            Some(h) if step == 0 => h,
                            Some(_) => break,
                            None => (asker + 1 + self.bulk_rotor.wrapping_add(step) % n) % n,
                        };
                        if holder == asker {
                            continue;
                        }
                        // The page budget knob applies to the BLOCK DESCENT ask (kind 9) alone — the lane whose
                        // page order the §DB pins exercise. Every other bulk kind (records, sidecars, DA
                        // chunks) keeps the bulk stream's 1 MiB, or a scenario would spend its whole
                        // budget paging records through a keyhole.
                        let budget = if req.first() == Some(&9u8) { self.bulk_budget } else { 1_048_576 };
                        let page = self.parties[holder].serve_notes_req_bytes(&req, budget);
                        if !page.is_empty() {
                            // DB-275: a batch-lane answer (the kind-13 page, or a kind-19 GETDATA) is measured against what
                            // the ASKER holds whole. A body the SERVER CHOSE (not named in the request) that the asker holds is
                            // the waste the gates measured; a body the asker NAMED and then got by another lane inside the same
                            // tick is a race, counted apart.
                            let named: std::collections::HashSet<crate::block::BlockId> =
                                if req.first() == Some(&19u8) && req.len() >= 2 {
                                    req[2..]
                                        .chunks_exact(32)
                                        .map(|c| {
                                            let mut id = [0u8; 32];
                                            id.copy_from_slice(c);
                                            Hash32(id)
                                        })
                                        .collect()
                                } else {
                                    std::collections::HashSet::new()
                                };
                            for id in batch_page_block_ids(&page) {
                                self.batch_bodies_served += 1;
                                let a = self.parties[asker].node();
                                if a.dag().get(&id).is_some() && !a.holds_only_a_shell(&id) {
                                    if named.contains(&id) {
                                        self.batch_bodies_named_raced += 1;
                                    } else {
                                        self.batch_bodies_already_held += 1;
                                    }
                                }
                            }
                            // A by-RECORD ask (1u8 block-ids / 2u8 record-ids) answered AGAIN,
                            // identically, to the SAME asker means the previous answer was
                            // discarded rather than consumed. Counted here because the hub is the
                            // one place both the ask and the answer are visible.
                            if matches!(req.first(), Some(1u8) | Some(2u8)) {
                                use std::sync::atomic::Ordering;
                                let kind = req[0];
                                let mut pre = req.clone();
                                pre.extend_from_slice(&page);
                                let digest = *blake3::hash(&pre).as_bytes();
                                let mut slot = self.hub.by_id.lock().unwrap();
                                let streak = if slot.0 == asker && slot.1 == digest {
                                    slot.2 + 1
                                } else {
                                    1
                                };
                                let (worst, worst_kind) = if streak > slot.3 {
                                    (streak, kind)
                                } else {
                                    (slot.3, slot.4)
                                };
                                *slot = (asker, digest, streak, worst, worst_kind);
                                drop(slot);
                                self.hub.by_id_answers.fetch_add(1, Ordering::Relaxed);
                                self.hub
                                    .by_id_bytes
                                    .fetch_add(page.len() as u64, Ordering::Relaxed);
                            }
                            if req.first() == Some(&18u8) {
                                self.inv_holder[asker] = Some(holder);
                            }
                            self.hub.bulk_resp[asker].lock().unwrap().push_back(page);
                            answered = true;
                            break;
                        }
                    }
                    // ⭐ AN ASK NOBODY ANSWERS LOOKS EXACTLY LIKE AN ASK NEVER MADE — and the two need
                    // opposite fixes. MEASURED 2026-09-04: a party sat at sidecar cursor 4 reporting
                    // `ask_wanted=true` and a 266-row gap, its peer was a node that could serve every
                    // ordinal it wanted, and exactly ONE `[sidecar-page]` line existed in the entire run.
                    // Nothing distinguished "the ask never went out" from "every ask came back empty".
                    // This line says which.
                    //
                    // Counts only, throttled to powers of two so a long scenario cannot flood the log,
                    // and TEST-ONLY (this hub is the scenario harness, never a serve path). It names the
                    // request KIND, which is protocol structure, and carries no chain data at all.
                    if !answered && req.first() == Some(&20u8) {
                        // an unanswered FOLLOW releases the party's one outstanding slot, else it never follows again
                        self.hub.follow_out[asker].store(false, std::sync::atomic::Ordering::Release);
                    }
                    if !answered {
                        use std::sync::atomic::{AtomicU64, Ordering};
                        static UNANSWERED: AtomicU64 = AtomicU64::new(0);
                        let n_ua = UNANSWERED.fetch_add(1, Ordering::Relaxed) + 1;
                        if n_ua.is_power_of_two() {
                            eprintln!(
                                "[hub] {n_ua} bulk ask(s) went UNANSWERED so far — latest kind={:?} from party {asker}",
                                req.first()
                            );
                        }
                    }
                }
            }
        }

        fn tick_all(&mut self) {
            let n = self.parties.len();
            for i in 0..n {
                self.tick(i);
            }
            self.now += SLOT_MS;
        }

        /// Record a block a party holds in full (its own production) in the schedule's ledger.
        fn note_new_tip(&mut self, i: usize) {
            let Some(t) = self.parties[i].node().selected_tip() else { return };
            if self.blocks.iter().any(|b| b.id() == t) {
                return;
            }
            let carried = self.parties[i].node().unfolded_carry().unfolded.into_iter().find(|(b, _, _)| b.id() == t).map(|(b, _, _)| b);
            if let Some(b) = carried {
                self.blocks.push(b);
            }
        }

        /// Party `i` produces `count` blocks: it ticks through spacing slots while the others hold what
        /// it sends. The runtime's own gates apply (mesh joined, no orphans, spacing).
        /// ⭐ The clock steps by the spacing the runtime ACTUALLY enforces (`production_spacing_ms`: the mesh
        /// target shared by the producers it sees, never below the relay floor). Stepped by the bare target, the
        /// spacing gate stayed closed on 7 of 8 slots once the floor landed, and the scenario measured its own
        /// fixture (a_deep_gossip_loss: 9 blocks produced of the 16 it needs) instead of the chain.
        /// ⭐ DB-412: the runtime's production gap is memoryless (`NodeRuntime::production_due`), so the clock steps to the
        /// attempt the runtime itself has scheduled (`next_production_at_ms`), at least one slot.
        fn produce(&mut self, i: usize, count: usize) {
            for _ in 0..count {
                let tip_before = self.parties[i].node().selected_tip();
                let mut guard = 0;
                loop {
                    self.now = (self.now + SLOT_MS).max(self.parties[i].next_production_at_ms());
                    self.tick(i);
                    if self.parties[i].node().selected_tip() != tip_before || guard >= 4 {
                        break;
                    }
                    guard += 1;
                }
                self.note_new_tip(i);
            }
        }

        fn deliver_to(&mut self, to: usize) {
            self.hub.release(to);
            self.tick(to);
        }

        fn burst_all(&mut self) {
            let n = self.parties.len();
            for i in 0..n {
                self.hub.release(i);
            }
            self.tick_all();
        }

        fn observe(&self) -> Vec<String> {
            self.parties
                .iter()
                .map(|rt| {
                    let p = rt.node();
                    format!(
                        "{}|{}|{}|{}|{}|{:?}|{:?}|{}|{}|{:?}",
                        p.served_seq(), p.sidecar_gap_count(), p.missing_record_count(), p.serve_ready(),
                        p.spine_stale_for_test(), p.spend_frontier_root(), p.nullifier_root(), p.relay_buffered_len(),
                        p.ordinal_rows_for_test().len(), p.selected_tip()
                    )
                })
                .collect()
        }

        /// Release everything and tick everyone until the mesh has nothing left to say.
        ///
        /// ⭐ TWO PHASES, because on THIS backend every party is a real self-producing node (that is the
        /// point of the runtime backend — the bare-node engine only produced when the script said so).
        ///
        ///  1. LIVE TIME: the clock advances, so deliveries, note pages, roots runs, the sidecar walk,
        ///     the readiness heal and re-anchoring all run on their real cadences — and every party keeps
        ///     mining, exactly as a live mesh does.
        ///  2. SETTLE: the clock is FROZEN. Each party's spacing gate (`now_ms - last_produce_ms >=
        ///     spacing_ms`) therefore closes after at most one more block, gossip keeps flowing, and the
        ///     DAG converges. Nothing is disabled and no node feature is stripped — production simply
        ///     stops being triggered, the way a mesh with no new work behaves.
        ///
        /// MEASURED 2026-09-03: without phase 2 all ten recorded cases failed identically ("party 1
        /// stands on a different selected tip than party 0") — every party had just mined a block its
        /// peers had not seen yet, so the observation never quiesced and the 800-round loop simply ran
        /// out. That was the harness reading a live mesh at an arbitrary instant, not a node defect.
        fn drain(&mut self) {
            let drain_t0 = std::time::Instant::now();
            let n = self.parties.len();
            // Phase 1 — live time.
            let mut quiet = 0usize;
            let mut p1_rounds = 0usize;
            let mut last = self.observe();
            for r in 0..240 {
                p1_rounds = r + 1;
                for i in 0..n {
                    self.hub.release(i);
                }
                self.tick_all();
                if r % 40 == 39 {
                    // Wall-time observability for the 600s deadline: WHICH phase burns the budget,
                    // and at what per-round cost, is invisible from the node logs alone.
                    eprintln!("[drain] phase1 round {r} elapsed {:?}", drain_t0.elapsed());
                }
                let now = self.observe();
                if self.hub.in_flight() == 0 && now == last {
                    quiet += 1;
                    if quiet >= 8 {
                        break;
                    }
                } else {
                    quiet = 0;
                }
                last = now;
            }
            // Phase 2 — SETTLE: no new work, clock still running.
            //
            // ⛔ The first version froze the clock instead. That silenced every repair cadence the node
            // has — the 2 s sidecar/range re-ask throttles and the readiness heal are all
            // `now_ms - last >= interval` — so a party that still owed itself rows could never ask for
            // them again and the mesh sat there owing each other records (MEASURED 2026-09-03: both
            // parties ended `ask_wanted=true` with fold counters 3 and 9). Production is paused through
            // the runtime's own `external_producer` state, the one serve.rs uses when another path
            // drives production; everything else keeps running on the real clock.
            for i in 0..n {
                self.parties[i].set_production_paused_for_test(true);
            }
            quiet = 0;
            let mut p2_rounds = 0usize;
            last = self.observe();
            for r in 0..400 {
                p2_rounds = r + 1;
                for i in 0..n {
                    self.hub.release(i);
                }
                self.tick_all();
                if r % 40 == 39 {
                    eprintln!("[drain] phase2 round {r} elapsed {:?}", drain_t0.elapsed());
                }
                let now = self.observe();
                if self.hub.in_flight() == 0 && now == last {
                    quiet += 1;
                    if quiet >= 8 {
                        break;
                    }
                } else {
                    quiet = 0;
                }
                last = now;
            }
            for i in 0..n {
                self.parties[i].set_production_paused_for_test(false);
            }
            // The drain's own verdict line: rounds used per phase and total wall — the figures the
            // 600s deadline diagnosis needs (a phase that runs its FULL budget never quiesced).
            eprintln!(
                "[drain] done: phase1 {p1_rounds}/240 round(s), phase2 {p2_rounds}/400 round(s), wall {:?}",
                drain_t0.elapsed()
            );
        }

        fn restart(&mut self, i: usize) {
            // ⭐ G1h — THE PRODUCTION RESTART on the hub backend: the party's process writes its shutdown checkpoint
            // (snapshot + fold record) into its own datadir, the process is GONE (runtime and node dropped before any
            // file is re-opened, as `netsim::restart` does), and the next process boots in the same directory through
            // the ONE resume (`scenario_node_resumed_in_at_depth`: band door, respend carry, window span). Before, a
            // snapshot-only `clear_checkpoint` + `restore_snapshot` left the band door at genesis, the warm never
            // started and the fold waited forever (cases 05 and 12 RED; see the door's doc).
            self.parties[i].node().persist_blocking();
            drop(self.parties.remove(i));
            let Some(fresh) = scenario_node_resumed_in_at_depth(&self.dirs[i], crate::params::RECORD_FOLD_DEPTH_DEFAULT) else {
                eprintln!("[scenario] ⛔ party {i}: its shutdown checkpoint did not resume — the party is GONE for the run");
                let mut rt = NodeRuntime::new(scenario_node_in(&self.dirs[i]), HubEndpoint { hub: Arc::clone(&self.hub), me: i });
                rt.mark_mesh_joined_for_test();
                rt.node_mut().arm_band_double_for_test();
                self.parties.insert(i, rt);
                return;
            };
            let _ = self.hub.discard(i);
            self.hub.released[i].lock().unwrap().clear();
            self.hub.bulk_reqs[i].lock().unwrap().clear();
            self.hub.bulk_resp[i].lock().unwrap().clear();
            self.hub.follow_out[i].store(false, std::sync::atomic::Ordering::Release);
            self.hub.clock.store(self.now, std::sync::atomic::Ordering::Relaxed);
            let mut rt = NodeRuntime::new(fresh, HubEndpoint { hub: Arc::clone(&self.hub), me: i });
            rt.mark_mesh_joined_for_test();
            rt.node_mut().arm_band_double_for_test(); // the restarted party rejoins the bound hub
            self.parties.insert(i, rt);
            self.announce(i); // a restarted daemon announces its own record again once its onion is up
        }

        /// Party `i` announces its own signed peer record (see `keys`) — the daemon's boot announce, through the one shared
        /// simulated-identity site (`harness::netsim::announce_sim_identity`).
        fn announce(&mut self, i: usize) {
            let now = self.now;
            self.hub.clock.store(now, std::sync::atomic::Ordering::Relaxed);
            crate::harness::netsim::announce_sim_identity(&mut self.parties[i], "hub-party-onion", i, &self.keys[i], now);
        }

        fn jump(&mut self, i: usize, j: usize) {
            if i == j || i >= self.parties.len() || j >= self.parties.len() {
                return;
            }
            // ⛔ A FIXTURE NEVER FALLS BEHIND THE DOOR (census S-DRAFT-ADOPT, 2026-11-26): the jump takes the bundle the source node
            // SERVES (`serve_join_bundle`, checked by the joiner's own door before it is served), never a draft beside the serve
            // path (the door refuses a draft `AnchorArray`); a source that cannot serve yet offers no jump.
            let bundle = self.parties[j].node().serve_join_bundle().and_then(|w| crate::sync::SyncBundle::from_wire(&w));
            if let Some(b) = bundle {
                let _ = self.parties[i].node_mut().instant_sync(b);
            }
        }

        fn receive(&mut self, i: usize) {
            // ⭐ WITNESS-DERIVED, like the consensus sim: a note is spendable only at the commitment the
            // prover writes as its leaf, or `Op::Spend` builds a carrier-less transaction no transition
            // can state and every peer refuses its deletion (§BB). Offset so this sim's notes are never
            // byte-identical to the other's while staying deterministic for a reproducer.
            let (note, cm) = Node::test_spendable_note(1_000 + self.real_notes.len() as u64);
            // ⛔ STAGED, never written into the record store directly (lane a 2026-10-22, replica census): a direct
            // `record_note_payload(0, ..)` made a block-less record on ONE party that no peer could hold — the
            // divergence `pending_credit_notes` documents. The production lane: stage the note beside its justifier,
            // this party's next produced block carries both, every party records it at the block's address.
            self.parties[i].node_mut().stage_credit_note(note.clone());
            // ⭐ §BA — and the object that justifies it, or the peer refuses the note itself.
            self.parties[i].node_mut().stage_credit_justifier(
                crate::bridge_credit_tx::BridgeCreditTx {
                    deposit_id: cm,
                    asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                    amount: 1_000,
                    note: note.clone(),
                    owner_clue: Vec::new(),
                    attestors: Vec::new(),
                }
                .wire(),
            );
            self.real_notes.push((cm, false));
            let before = self.blocks.len();
            self.produce(i, 1);
            if self.blocks.len() > before {
                self.real_records.push(Node::da_record_id_for_block(&self.blocks[before].id(), 0));
            }
        }

        fn spend(&mut self, i: usize) {
            let pick = self
                .real_notes
                .iter()
                .position(|(cm, spent)| !*spent && !self.parties[i].node().records_containing_cm(cm).is_empty());
            let Some(k) = pick else { return };
            let cm = self.real_notes[k].0;
            let salt = self.blocks.len() as u64 + 7_000;
            if self.parties[i].node_mut().spend_tx_for_test(&cm, salt).is_err() {
                return;
            }
            let before = self.blocks.len();
            self.produce(i, 1);
            if self.blocks.len() > before && !self.blocks[before].nullifier_proof.padded_tags.is_empty() {
                self.real_notes[k].1 = true;
            }
        }

        fn step(&mut self, a: Act) {
            self.trace.push(a.clone());
            let n = self.parties.len();
            match a {
                Act::Produce(i, c) => { if i < n { self.produce(i, c); } }
                Act::Deliver(k) => { let to = k % n; self.deliver_to(to); }
                Act::Burst(_) => self.burst_all(),
                Act::Drop(i) => { if i < n { let _ = self.hub.discard(i); } }
                Act::Drain => self.drain(),
                Act::Restart(i) => { if i < n { self.restart(i); } }
                Act::Jump(i, j) => self.jump(i, j),
                Act::Receive(i) => { if i < n { self.receive(i); } }
                Act::Spend(i) => { if i < n { self.spend(i); } }
                Act::Forget(i) => {
                    if i < n {
                        let ids: Vec<u64> = self.blocks.iter().filter(|b| b.header.output_notes_root == Hash32::hash(&[])).map(|b| Node::da_record_id_for_block(&b.id(), 0)).collect();
                        for seq in ids { let _ = self.parties[i].node_mut().test_drop_record_bytes(seq); }
                    }
                }
                Act::Tamper(_, _) | Act::ForgeRows(_) | Act::Invalid(_) | Act::Replay(_, _) => {} // the bare-node engine covers the adversary
            }
        }

        /// The verdict, and on ANY failure every party's fold and band state appended (ordinals, counts and flags only) —
        /// so a red names whether a fold is waiting, on what, and where each party's band and tip stand.
        fn verdict(&self) -> Result<(), String> {
            self.verdict_inner().map_err(|why| {
                let parties: Vec<String> = self
                    .parties
                    .iter()
                    .enumerate()
                    .map(|(k, rt)| {
                        let n = rt.node();
                        format!(
                            "p{k}: tip {} served_seq {} unfolded {} wait {:?} stale {} missing {} wedge {:?} · {} · {}",
                            n.tip_height(),
                            n.served_seq(),
                            n.unfolded_blocks_len(),
                            n.fold_wait_state().map(|(b, c)| (b.to_hex()[..8].to_string(), c)),
                            n.spine_stale_for_test(),
                            n.missing_record_count(),
                            n.wedge_reason(),
                            n.band_diag_for_test(),
                            rt.band_worker_diag_for_test(self.now)
                        )
                    })
                    .collect();
                format!("{why}\n  [state] {}", parties.join("\n  [state] "))
            })
        }

        fn verdict_inner(&self) -> Result<(), String> {
            let nodes: Vec<&Node> = self.parties.iter().map(|rt| rt.node()).collect();
            let tip0 = nodes[0].selected_tip();
            for (i, n) in nodes.iter().enumerate().skip(1) {
                if n.selected_tip() != tip0 {
                    return Err(format!("party {i} stands on a different selected tip than party 0 ({:?} vs {:?})", n.selected_tip(), tip0));
                }
            }
            let ords = |n: &Node| -> Vec<Option<u64>> {
                self.blocks.iter().map(|b| n.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0))).collect()
            };
            let o0 = ords(nodes[0]);
            for (i, n) in nodes.iter().enumerate().skip(1) {
                let oi = ords(n);
                let differ: Vec<(usize, Option<u64>, Option<u64>)> = o0.iter().zip(oi.iter()).enumerate().filter(|(_, (a, b))| a != b).map(|(k, (a, b))| (k, *a, *b)).collect();
                if !differ.is_empty() {
                    return Err(format!("party {i} folds {} block(s) at different ordinals than party 0: {:?}", differ.len(), &differ[..differ.len().min(6)]));
                }
                if n.served_seq() != nodes[0].served_seq() { return Err(format!("party {i} dense fold counter {} vs party 0 {}", n.served_seq(), nodes[0].served_seq())); }
                if n.spend_frontier_root() != nodes[0].spend_frontier_root() { return Err(format!("party {i} spine root differs from party 0")); }
            }
            // ⭐ Stage-3 cross-party pin (a) — REVERSE-map equality: the (ordinal -> record) map, not
            // just the per-block (record -> ordinal) zip above. Catches a PHANTOM row — an ordinal
            // occupied by a rid outside the recorded block list — which the forward zip can never see.
            // The horizon covers every ordinal any party can legally hold (one per block + genesis).
            // These are PINS (verdict tightening on the failing schedules, per the stage-3 design),
            // not fixes — nothing is rescued: every mismatch is a returned failure.
            // MUST-STAY-GREEN: the recorded cases and honest schedules that already pass only tighten.
            let horizon = self.blocks.len() as u64 + 2;
            for o in 0..horizon {
                let a0 = nodes[0].da_addr_at_ordinal(o);
                for (i, n) in nodes.iter().enumerate().skip(1) {
                    let ai = n.da_addr_at_ordinal(o);
                    if ai != a0 {
                        return Err(format!(
                            "party {i} holds a different record at ordinal {o} than party 0 \
                             (reverse map: {a0:?} vs {ai:?})"
                        ));
                    }
                }
            }
            // ⭐ Stage-3 cross-party pin (c) — the leaf law asserted from OUTSIDE, per party: the
            // spine holds exactly cursor_row * width leaves (genesis holds position 0 and contributes
            // none; a party that never folded holds an empty spine) — the same law the C5 pass gate
            // checks from inside, measured here at quiescence where mid-batch excess must be gone.
            for (i, n) in nodes.iter().enumerate() {
                let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                let want = match n.fold_cursor_row_for_test() {
                    Some(row) => row.saturating_mul(width),
                    None => 0, // no cursor row = nothing folded: the law requires an empty spine
                };
                if n.spend_frontier_count() != want {
                    return Err(format!(
                        "party {i} violates the leaf law: {} leaves vs cursor row {:?} * {width}",
                        n.spend_frontier_count(),
                        n.fold_cursor_row_for_test()
                    ));
                }
            }
            for (i, n) in nodes.iter().enumerate() {
                if n.da_addr_at_ordinal(0).is_none() { return Err(format!("party {i} has no record at ordinal 0 — the genesis row was evicted")); }
                if n.relay_buffered_len() > 0 { return Err(format!("party {i} still holds {} gossiped block(s) waiting on a parent", n.relay_buffered_len())); }
                if n.spine_stale_for_test() { return Err(format!("party {i} is STALE once everything is delivered")); }
                if n.sidecar_gap_count() != 0 { return Err(format!("party {i} has a sidecar gap of {}", n.sidecar_gap_count())); }
                if n.missing_record_count() != 0 { return Err(format!("party {i} still misses {} record(s)", n.missing_record_count())); }
                if !n.serve_ready() { return Err(format!("party {i} is NOT READY once everything is delivered")); }
                if !self.parties[i].mesh_joined() { return Err(format!("party {i} left the mesh")); }
            }
            for seq in &self.real_records {
                let b0 = nodes[0].da_record_notes(*seq);
                if b0.is_none() { return Err(format!("party 0 does not hold real record {seq}")); }
                for (i, n) in nodes.iter().enumerate().skip(1) {
                    if n.da_record_notes(*seq) != b0 { return Err(format!("party {i} holds different bytes (or none) for real record {seq}")); }
                }
            }
            // Z1: a node cannot answer "is this commitment spent" any more (spent-ness is a fact about
            // a NULLIFIER, unlinkable to a commitment by construction). What every party must still be
            // able to do with a real note is FIND it: its record, on every party. A note nobody can find
            // is a note nobody can spend.
            for (cm, _spent) in &self.real_notes {
                for (i, n) in nodes.iter().enumerate() {
                    if n.records_containing_cm(cm).is_empty() {
                        return Err(format!(
                            "party {i} cannot find a real note's record once everything is delivered"
                        ));
                    }
                }
            }
            Ok(())
        }

        /// ⭐ Stage-3 cross-party pin (b) — ZERO-REFUSAL REPLAY at quiescence: feed every party's
        /// full sidecar page into every other party and assert `adopt_sidecar_row` refuses NOTHING
        /// ("[fold-row-hint] drops == 0" in its operational form). The forward/reverse map pins say
        /// the numberings agree in memory; this says they agree ON THE WIRE — no row any party serves
        /// can conflict with any other party's claims. Run AFTER `verdict()` (the replay adopts rows,
        /// which must not mask verdict state). A refusal here is the exact measured red mechanism:
        /// every `adopt_sidecar_row` returning false via the local-claim arm on a level pair.
        fn zero_refusal_replay(&mut self) -> Result<(), String> {
            let n = self.parties.len();
            let horizon = self.blocks.len() as u64 + 2;
            for i in 0..n {
                let rows: Vec<(u64, u64)> = {
                    let src = self.parties[i].node();
                    (0..horizon)
                        .filter_map(|o| src.da_addr_at_ordinal(o).map(|rid| (o, rid)))
                        .collect()
                };
                for j in 0..n {
                    if i == j {
                        continue;
                    }
                    let before = self.parties[j].node().row_hint_mismatch_count_for_test();
                    for (o, rid) in &rows {
                        let _ = self.parties[j].node_mut().adopt_sidecar_row(*o, *rid);
                    }
                    let after = self.parties[j].node().row_hint_mismatch_count_for_test();
                    if after != before {
                        return Err(format!(
                            "party {j} refused {} of party {i}'s page rows at quiescence — the \
                             parties do not hold one numbering on the wire",
                            after - before
                        ));
                    }
                }
            }
            Ok(())
        }
    }

    fn as_case(name: &str, parties: usize, script: &[Act]) -> String {
        let mut out = format!("name {name}\nparties {parties}\n");
        for a in script {
            out.push_str(&match a {
                Act::Produce(i, n) => format!("produce {i} {n}\n"),
                Act::Deliver(k) => format!("deliver {k}\n"),
                Act::Drain => "drain\n".to_string(),
                Act::Restart(i) => format!("restart {i}\n"),
                Act::Jump(i, j) => format!("jump {i} {j}\n"),
                Act::Burst(k) => format!("burst {k}\n"),
                Act::Drop(i) => format!("drop {i}\n"),
                Act::Receive(i) => format!("receive {i}\n"),
                Act::Forget(i) => format!("forget {i}\n"),
                Act::Tamper(i, j) => format!("tamper {i} {j}\n"),
                Act::ForgeRows(i) => format!("forge-rows {i}\n"),
                Act::Invalid(i) => format!("invalid {i}\n"),
                Act::Replay(i, j) => format!("replay {i} {j}\n"),
                Act::Spend(i) => format!("spend {i}\n"),
            });
        }
        out
    }

    /// One recorded case, replayed through REAL runtimes over the hub. One test per case so cargo runs
    /// them across cores (a case is ~ a minute of ticking).
    fn run_case(k: usize) {
        let cases = parse(CASES).expect("the case library parses");
        let Some(c) = cases.get(k) else { return }; // fewer cases than slots: nothing to run
        let mut sim = RtSim::new(c.parties, 0x5EED_5EED_5EED_5EED);
        for a in &c.script {
            sim.step(a.clone());
        }
        sim.drain();
        if let Err(why) = sim.verdict() {
            panic!("consensus scenario '{}' FAILED on the runtime backend: {why}", c.name);
        }
        if let Err(why) = sim.zero_refusal_replay() {
            panic!("consensus scenario '{}' FAILED the zero-refusal replay: {why}", c.name);
        }
    }

    #[test] fn recorded_case_00_holds_on_the_runtime_backend() { run_case(0) }
    #[test] fn recorded_case_01_holds_on_the_runtime_backend() { run_case(1) }
    #[test] fn recorded_case_02_holds_on_the_runtime_backend() { run_case(2) }
    #[test] fn recorded_case_03_holds_on_the_runtime_backend() { run_case(3) }
    #[test] fn recorded_case_04_holds_on_the_runtime_backend() { run_case(4) }
    #[test] fn recorded_case_05_holds_on_the_runtime_backend() { run_case(5) }
    #[test] fn recorded_case_06_holds_on_the_runtime_backend() { run_case(6) }
    #[test] fn recorded_case_07_holds_on_the_runtime_backend() { run_case(7) }
    #[test] fn recorded_case_08_holds_on_the_runtime_backend() { run_case(8) }
    #[test] fn recorded_case_09_holds_on_the_runtime_backend() { run_case(9) }
    #[test] fn recorded_case_10_holds_on_the_runtime_backend() { run_case(10) }
    #[test] fn recorded_case_11_holds_on_the_runtime_backend() { run_case(11) }
    #[test] fn recorded_case_12_holds_on_the_runtime_backend() { run_case(12) }

    /// The library must not outgrow the slots above silently.
    #[test]
    fn every_recorded_case_has_a_runtime_backend_slot() {
        let cases = parse(CASES).expect("the case library parses");
        // The slots are COUNTED off this file, never a hand-kept number: the old bound read `<= 12` beside thirteen slots
        // (00..=12), so a full library failed with every case slotted (RED on the baseline, base-5scen-244.log).
        let src = include_str!("mesh_runtime_scenarios.rs");
        let slots = (0..cases.len().max(64))
            .filter(|i| src.contains(&format!("fn recorded_case_{i:02}_holds_on_the_runtime_backend() {{ run_case({i}) }}")))
            .count();
        assert!(slots >= 1, "CALIBRATION: the slot reader finds the slots in this file");
        assert!(cases.len() <= slots, "add recorded_case_{:02} slots: the library holds {} cases, {slots} slotted", cases.len() - 1, cases.len());
    }

    /// The block ids a `BLOCKBTCH` page carries (`BLOCKBTCH` ‖ hint(32) ‖ (u32 LE len ‖ postcard block)*), in page
    /// order — the same framing `NodeRuntime::on_pulled_block_batch` reads. Anything else answers empty.
    fn batch_page_block_ids(page: &[u8]) -> Vec<crate::block::BlockId> {
        let mut out = Vec::new();
        if page.len() < 9 + 32 || &page[..9] != b"BLOCKBTCH" {
            return out;
        }
        let mut off = 9 + 32;
        while off + 4 <= page.len() {
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&page[off..off + 4]);
            let len = u32::from_le_bytes(lb) as usize;
            off += 4;
            if len == 0 || off + len > page.len() {
                break;
            }
            if let Some(b) = crate::block::gossip_decode(&page[off..off + len]) { // §22: a page frame is the envelope
                out.push(b.id());
            }
            off += len;
        }
        out
    }

    /// ⛔⛔⛔ DB-275 — A HEALED SPLIT MUST CATCH UP WITHOUT RE-SHIPPING BODIES THE ASKER ALREADY HOLDS.
    ///
    /// MEASURED gate Q3 (/tmp/musd-ecocheck-7Y1VJj): after node1's restart the pair ran as two branches and node1's
    /// batch pages were 91% bodies it already held whole (736 of 805; every late page `26 already held (26 whole)`),
    /// with the serve line `2 of 94 locator id(s) held … candidates 538`. Gates K (89%) and O (82%) measured the same.
    /// The server infers what the asker holds from a SAMPLED locator plus a 128-id have list; after a split the
    /// asker's holdings sit beside its own branch, which the server lacks, so hundreds of held blocks stay candidates.
    ///
    /// Shape (the gate's): a shared prefix; each side's first post-split blocks reach the other; then both extend
    /// alone and every gossiped cell is LOST (a restart's downtime); then the mesh heals on live time. The pair must
    /// converge (the full cross-party verdict), and no body the batch lane carries may be one the asker already held
    /// whole when it asked.
    #[test]
    fn db275_a_healed_split_catches_up_without_reshipping_bodies_the_asker_holds() {
        let mut sim = RtSim::new(2, 275);
        sim.arm_deadline(std::time::Duration::from_secs(900));
        // The shared prefix.
        sim.produce(0, 6);
        sim.burst_all();
        sim.burst_all();
        // Each side's early post-split blocks reach the other: the asker holds some of the server's branch and the
        // server holds some of the asker's.
        sim.produce(0, 8);
        sim.produce(1, 8);
        sim.burst_all();
        sim.burst_all();
        // THE SPLIT: both extend alone and every gossiped cell is lost.
        sim.produce(0, 40);
        sim.produce(1, 40);
        for q in sim.hub.held.iter() {
            q.lock().unwrap().clear();
        }
        let (served0, held0, raced0) =
            (sim.batch_bodies_served, sim.batch_bodies_already_held, sim.batch_bodies_named_raced);
        sim.drain();
        let served = sim.batch_bodies_served - served0;
        let held = sim.batch_bodies_already_held - held0;
        let raced = sim.batch_bodies_named_raced - raced0;
        let verdict = sim.verdict();
        eprintln!(
            "[db275] after the heal: {served} batch bod(ies) served, {held} the SERVER chose that the asker already held \
             whole, {raced} named by the asker then landed by another lane first; verdict {verdict:?}"
        );
        assert!(served > 0, "CALIBRATION: the healed split must reach the batch lane (no body was paged at all)");
        assert_eq!(
            held, 0,
            "⛔⛔⛔ DB-275: {held} of {served} bodies the SERVER chose were ones the asker ALREADY HELD WHOLE — the server \
             guessed the asker's holdings from a sampled locator (gate Q3: 91% of node1's pages)"
        );
        if let Err(why) = verdict {
            panic!("⛔ DB-275: the healed split did not converge: {why}");
        }
    }

    /// The search over the honest alphabet, on real runtimes — one seed per test.
    fn search_seed(seed: u64) {
        let parties = 3usize;
        let mut sim = RtSim::new(parties, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..24 {
            let r = sim.rand(100);
            let i = sim.rand(parties);
            let j = sim.rand(parties);
            let a = if r < 35 { Act::Produce(i, 1) } else if r < 55 { Act::Deliver(sim.rand(64)) } else if r < 65 { Act::Burst(1) } else if r < 72 { Act::Drop(i) } else if r < 82 { Act::Restart(i) } else if r < 88 { Act::Jump(i, j) } else if r < 95 { Act::Receive(i) } else { Act::Spend(i) };
            sim.step(a);
        }
        sim.drain();
        if let Err(why) = sim.verdict() {
            panic!(
                "RUNTIME BACKEND — seed {seed}: {why}\npaste this into consensus_scenarios.txt:\n\n{}",
                as_case(&format!("found-runtime-seed-{seed}"), parties, &sim.trace)
            );
        }
        if let Err(why) = sim.zero_refusal_replay() {
            panic!(
                "RUNTIME BACKEND — seed {seed} FAILED the zero-refusal replay: {why}\npaste this \
                 into consensus_scenarios.txt:\n\n{}",
                as_case(&format!("found-runtime-seed-{seed}"), parties, &sim.trace)
            );
        }
    }

    #[test] fn honest_schedule_seed_1_on_the_runtime_backend() { search_seed(1) }
    #[test] fn honest_schedule_seed_2_on_the_runtime_backend() { search_seed(2) }
    #[test] fn honest_schedule_seed_3_on_the_runtime_backend() { search_seed(3) }
    #[test] fn honest_schedule_seed_4_on_the_runtime_backend() { search_seed(4) }
    /// DIAGNOSTIC (ignored): does a produced block actually CROSS the hub and land in the peer's DAG?
    /// Every recorded case failed the runtime backend with "different selected tip" — one cause, not
    /// fourteen. This prints, per round, what each party holds and what the hub carries.
    #[test]
    #[ignore]
    fn diag_hub_delivers_blocks() {
        let mut s = RtSim::new(2, 1);
        let t0: Vec<String> = s.parties.iter().map(|rt| format!("{:?}", rt.node().selected_tip())).collect();
        eprintln!("[diag] start tips {t0:?}");
        let spacing = s.parties[0].production_spacing_ms().max(SLOT_MS);
        for round in 0..12 {
            s.now += spacing;
            s.tick(0);
            let held = s.hub.held[1].lock().unwrap().len();
            eprintln!(
                "[diag] r{round} p0 ticked: blocks={} tip={:?} | hub->p1 held={held}",
                s.parties[0].node().dag().block_ids().len(),
                s.parties[0].node().selected_tip()
            );
            s.hub.release(1);
            s.tick(1);
            eprintln!(
                "[diag] r{round} p1 ticked: blocks={} tip={:?} buffered={} | hub->p1 held={} released={}",
                s.parties[1].node().dag().block_ids().len(),
                s.parties[1].node().selected_tip(),
                s.parties[1].node().relay_buffered_len(),
                s.hub.held[1].lock().unwrap().len(),
                s.hub.released[1].lock().unwrap().len()
            );
        }
        eprintln!(
            "[diag] END p0 dag {} blocks, p1 dag {} blocks",
            s.parties[0].node().dag().block_ids().len(),
            s.parties[1].node().dag().block_ids().len()
        );
    }

    /// DIAGNOSTIC (ignored): the LAST hole of case 04 — one record party 0 folds and party 1 does not.
    /// Interrogate both parties directly: who holds the block, who holds the record, what the peer's own
    /// sidecar page carries for that ordinal, and what the asker's row door does with it.
    #[test]
    #[ignore]
    fn diag_case_04_last_hole() {
        let mut s = RtSim::new(2, 4);
        for a in [Act::Produce(0, 4), Act::Produce(1, 4), Act::Deliver(2), Act::Restart(0), Act::Restart(1)] {
            s.step(a);
        }
        s.drain();
        for (i, rt) in s.parties.iter().enumerate() {
            let p = rt.node();
            eprintln!(
                "[diag] p{i}: seq={} certified={} cursor={} ask_from={} ask_wanted={} gap={} missing={} breakdown={:?} tip={:?}",
                p.served_seq(), p.certified_record_position(), p.sidecar_cursor(), p.sidecar_ask_from(),
                p.sidecar_ask_wanted(), p.sidecar_gap_count(), p.missing_record_count(),
                p.missing_record_breakdown(), p.selected_tip()
            );
        }
        let mut holes: Vec<(usize, u64, u64)> = Vec::new();
        for (k, b) in s.blocks.iter().enumerate() {
            let rid = Node::da_record_id_for_block(&b.id(), 0);
            let o0 = s.parties[0].node().da_record_ordinal(rid);
            let o1 = s.parties[1].node().da_record_ordinal(rid);
            // ⭐ IS THIS BLOCK IN THE SELECTED TIP'S PAST, on each party? THE one boolean that separates
            // the two remaining explanations, and the one nothing here prints.
            //
            // `in_dag` says only whether a party HOLDS the block; it cannot say whether the block is part
            // of consensus. Both readings fit the measurement and they need opposite fixes:
            //   * IN the tip's past on one party and ABSENT from the other's DAG ⇒ that party has a HOLE
            //     in its DAG — it accepted a block whose ancestor it lacks, which `add_block`'s
            //     parent-validation is supposed to make impossible. That is a delivery/backfill defect.
            //   * NOT in the tip's past anywhere ⇒ it is an ORPHAN, and a party that still folded it gave
            //     a record ordinal to a block consensus does not place. That is a fold defect, and it is
            //     what makes two nodes on the SAME TIP number their records differently.
            // Both parties share a tip in this scenario, so `past_of(tip)` is the same question on each.
            let in_chain = |i: usize| -> bool {
                let n = s.parties[i].node();
                match n.selected_tip() {
                    Some(t) => t == b.id() || crate::dag::Dag::past_of(n.dag(), &t).contains(&b.id()),
                    None => false,
                }
            };
            eprintln!(
                "[diag] block {k} rid={rid}: p0 ord={o0:?} holds={} in_dag={} in_chain={} | p1 ord={o1:?} holds={} in_dag={} in_chain={}",
                s.parties[0].node().da_record_notes(rid).is_some(),
                s.parties[0].node().dag().get(&b.id()).is_some(),
                in_chain(0),
                s.parties[1].node().da_record_notes(rid).is_some(),
                s.parties[1].node().dag().get(&b.id()).is_some(),
                in_chain(1)
            );
            if o0 != o1 {
                if let Some(o) = o0.or(o1) {
                    holes.push((k, rid, o));
                }
            }
        }
        // Which blocks on each party's own selected chain have NO row? Those are what the fold waits on,
        // and the peer either holds their rows (so the ask must reach them) or does not (so nobody can).
        for i in 0..s.parties.len() {
            let peer = 1 - i;
            let tip = s.parties[i].node().selected_tip().expect("tip");
            let mut chain: Vec<_> = crate::dag::Dag::past_of(s.parties[i].node().dag(), &tip).into_iter().collect();
            chain.push(tip);
            let mut rowless = 0usize;
            let mut shown = 0usize;
            for id in &chain {
                let rid = Node::da_record_id_for_block(id, 0);
                if s.parties[i].node().da_record_ordinal(rid).is_none() {
                    rowless += 1;
                    if shown < 4 {
                        shown += 1;
                        eprintln!(
                            "[diag] p{i} chain block {id:?} has NO row: holds_bytes={} | peer p{peer} ord={:?} holds_bytes={}",
                            s.parties[i].node().da_record_notes(rid).is_some(),
                            s.parties[peer].node().da_record_ordinal(rid),
                            s.parties[peer].node().da_record_notes(rid).is_some()
                        );
                    }
                }
            }
            eprintln!("[diag] p{i}: {rowless} of {} own-chain blocks have no row", chain.len());
        }
        for (k, rid, ord) in holes {
            let (rows, covered) = s.parties[0].node().sidecar_page(ord, 4, 1 << 20);
            eprintln!("[diag] block {k} (rid {rid}, ordinal {ord}): p0's own page from {ord} carries {} row(s), covered_upto {covered}", rows.len());
            for (o, r) in &rows {
                let took = s.parties[1].node_mut().adopt_sidecar_row(*o, *r);
                eprintln!(
                    "[diag]   row ord={o} rid={r} -> p1 adopt_sidecar_row = {took} (p1 ord now {:?})",
                    s.parties[1].node().da_record_ordinal(*r)
                );
            }
        }
    }

    /// ⭐ A BUFFERED ORPHAN NAMES ITS MISSING PARENT TO THE 7u8 BLOCK LANE.
    ///
    /// ROOT-LAYER: `RelayOutcome::Buffered { missing }` is the ONE place the runtime learns "a
    /// live peer's chain contains a block I lack, and here is its id". That arm fired only a
    /// throttled #29 DSYNC ask — a lane whose served bundle is the LAST INSTALLED one, built one
    /// whole prove earlier; when the machine is loaded, that bundle lags the live chain past the
    /// adopt's 32-wide level range and every ask comes back `NotHeavier`, so the ONLY repair lane
    /// cannot act and the orphan chain just grows. The missing parent's ID is in hand, and the
    /// bounded by-id block lane (7u8: `want_block_by_id` slots, the 2s-paced ask, the shell serve,
    /// the fail-closed wanted-shell door, parked children released through preverify) already
    /// exists end to end for the fold's own waits — the Buffered arm simply never named the
    /// parent to it.
    ///
    /// MEASURED (step3-probe run 5, scratch /tmp/musd-step3probe-3BmIm8, 2026-09-07): n2 deferred
    /// production on ONE missing parent for 171s while its buffered chain grew 3 -> 440 blocks
    /// ("[produce] deferred: 440 gossiped block(s) wait on parents this node lacks"), its dsync
    /// asks were all refused ("adopt outcome: Some(NotHeavier)" — the peer's bundles were built
    /// minutes earlier under load), and n1 logged ZERO `[block-lane]` serves the whole run: no
    /// lane ever asked for the parent by id. Run 4 (BFhZNo) hit the same arm as the gate's
    /// step-3 red.
    ///
    /// MUST-STAY-GREEN: the DSYNC ask stays exactly as it is (deep gaps are still the jump's job);
    /// the want set stays TX_REQ_FIXED_COUNT-slot bounded and drains when the block LANDS; a
    /// parked block is never asked for (it is already here — its strand drains when its ancestor
    /// lands). cons: one bounded slot write per Buffered outcome; the 2s-paced ask already existed.
    #[test]
    fn a_buffered_orphan_names_its_missing_parent_to_the_block_lane() {
        let mut s = RtSim::new(2, 0x0907_2026_0907_0001u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        // A converged pair.
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        // B1 is LOST to party 1 (a dropped gossip cell is re-delivered by nobody); B2 arrives and
        // parks on it — the exact wedge shape of probe runs 3/4/5.
        s.step(Act::Produce(0, 1));
        s.step(Act::Drop(1)); // B1, discarded in flight
        s.step(Act::Produce(0, 1)); // B2
        let missing_parent = {
            // The dropped block is the parent of party 0's new tip.
            let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
            s.parties[0]
                .node()
                .dag()
                .get(&tip)
                .and_then(|n| n.selected_parent)
                .expect("the new tip has a selected parent")
        };
        // Deliver B2 and let it clear the off-lock preverifier into the apply loop. The wait is on
        // the DEFINITIVE state (the child parked), never on a clock.
        // Under compact relay (DB-12 by-id, DB-17 batch page, 2026-09-18) the missing parent is
        // usually fetched BEFORE the child can park: the beacon names a tip party 1 lacks, the batch
        // page carries the parent and the child in order, and nothing strands. When a child DOES park
        // (the page lost a race), it must name its parent to the block lane — the pre-2026-09-18 shape.
        let mut parked_once = false;
        for _ in 0..40 {
            s.step(Act::Deliver(1));
            if s.parties[1].node().relay_buffered_len() > 0 {
                parked_once = true;
                let wants = s.parties[1].node_mut().wanted_block_ids();
                assert!(
                    wants.contains(&missing_parent) || s.parties[1].node().dag().get(&missing_parent).is_some(),
                    "party 1 parked a gossiped block on missing parent {missing_parent:?} and named NO \
                     by-id block want (live wants: {wants:?}) — the only repair lane left is the DSYNC \
                     bundle, which under load is served one whole prove old and refused NotHeavier \
                     forever (probe run 5: a 440-block orphan chain held for 171s)"
                );
                break;
            }
            if s.parties[1].node().dag().get(&missing_parent).is_some() {
                break; // the block lane delivered the parent before the child could park
            }
        }
        eprintln!("[orphan-pin] parked_once={parked_once} (a parked child names its parent; an unparked one was healed by the page)");
        s.drain();
        let still = s.parties[1].node_mut().wanted_block_ids();
        assert!(
            still.is_empty(),
            "the block want never retired — no lane delivered the block it named ({still:?})"
        );
        let strand_drained = s.parties[1].node().relay_buffered_len() == 0;
        assert!(
            strand_drained,
            "party 1 still parks blocks at quiescence — the strand never drained"
        );
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "the pair did not re-reach one chain after the parent-want heal"
        );
    }

    /// ⭐ A WANTED SHELL THAT CANNOT GRAFT NAMES ITS OWN MISSING PARENTS TO THE SAME LANE.
    ///
    /// ROOT-LAYER: `graft_wanted_block_shell` is where a served shell's parent ids are LEARNED
    /// (the header is in hand, id-authenticated); when the graft refuses because a parent is
    /// neither in the DAG nor parked, that parent is a block this node lacks BY ID — exactly what
    /// the want slots exist for. Without the naming, a gossip loss of TWO OR MORE consecutive
    /// blocks is unhealable by the lane: the Buffered arm names only the newest missing link (the
    /// older one has no arrived child to name it), the served shell for that link fails to graft
    /// forever, and the lane re-asks the same id on every cadence.
    ///
    /// MEASURED (step3-probe run 6, scratch /tmp/musd-step3probe-M26WCR, 2026-09-07, binary
    /// bc488fab with the Buffered-arm naming already in): n2 wedged at height 171 for 319s to the
    /// budget's end (final gap 651) while its block lane logged "[block-lane] 0 of 2 served
    /// shell(s) grafted (unwanted, already held, or a parent still missing — the lane re-asks on
    /// its own cadence)" — the shell round-tripped every 2s and the parent it needed was never
    /// named by anything.
    ///
    /// MUST-STAY-GREEN: the naming is bounded by the header's parent list (dag-width) and the
    /// TX_REQ_FIXED_COUNT slot array; a parked parent is never named (already held — its strand
    /// drains when its ancestor lands); a landed parent frees its slot as always. The lane walks
    /// a contiguous loss backwards one served page per cadence — a bounded lookup chain, never a
    /// tip chase. cons: a parent-presence read per refused shell.
    #[test]
    fn a_wanted_shell_that_cannot_graft_names_its_missing_parents() {
        let mut s = RtSim::new(2, 0x0907_2026_0907_0002u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        // TWO consecutive blocks are lost to party 1; the third arrives and parks.
        s.step(Act::Produce(0, 1)); // B4 — lost
        s.step(Act::Drop(1));
        s.step(Act::Produce(0, 1)); // B5 — lost
        s.step(Act::Drop(1));
        s.step(Act::Produce(0, 1)); // B6 — arrives, parks on B5
        assert!(s.blocks.len() >= 6, "the schedule produced {} block(s), need 6", s.blocks.len());
        let (b4, b5) = (s.blocks[s.blocks.len() - 3].clone(), s.blocks[s.blocks.len() - 2].clone());
        // Under compact relay (DB-12 by-id, DB-17/50/60/69 batch page, 2026-09-18) a block travels as a
        // tip announcement plus a pull, and the batch page brings a lost span in order before any child
        // can park — so the "parked child names its newest missing link" arming of 2026-09-07 no longer
        // fires on this backend (measured 2026-09-19: 40 deliveries, nothing parked, the span healed by
        // the page). The Buffered arm's own write is pinned by
        // `a_buffered_orphan_names_its_missing_parent_to_the_block_lane`; THIS pin holds the shell DOOR:
        // party 1 holds neither B4 nor B5, the C1 fold-wait names B5 (the same `want_block_by_id` write
        // the arm makes), and the served shell must refuse AND name its missing parent.
        assert!(s.parties[1].node().dag().get(&b4.id()).is_none(), "party 1 must lack B4 for this shape");
        assert!(s.parties[1].node().dag().get(&b5.id()).is_none(), "party 1 must lack B5 for this shape");
        s.parties[1].node_mut().want_block_by_id(b5.id());
        let wants = s.parties[1].node_mut().wanted_block_ids();
        assert!(wants.contains(&b5.id()), "the want slot did not take the newest missing link (wants: {wants:?})");
        // The peer's serve round-trips B5's shell; it cannot graft (B4 is missing too). The
        // refusal must NAME B4 — the id is right there in the shell's own header.
        let placed = s.parties[1].node_mut().graft_block_shell_from_trusted_id(&b5);
        assert!(!placed, "B5 grafted with B4 absent — the DAG accepted a parentless block");
        let wants = s.parties[1].node_mut().wanted_block_ids();
        assert!(
            wants.contains(&b4.id()),
            "the refused shell did not name its own missing parent — the lane re-asks the same \
             id forever and a two-deep gossip loss never heals (probe run 6: wedged 319s to the \
             budget's end, final height gap 651). Live wants: {wants:?}"
        );
        // And with the parent named, the next served page heals the whole segment parents-first.
        assert!(
            s.parties[1].node_mut().graft_block_shell_from_trusted_id(&b4),
            "B4's shell did not graft although its parents are held"
        );
        // B5 was PARKED behind B4 by the refusal above (and its want slot freed — a parked id is held, not
        // wanted). In the runtime the page door cascades the park behind a landed parent
        // (`take_orphans_waiting_on` → `readmit_parked_shell`); this pin drives that same step by hand.
        if s.parties[1].node().dag().get(&b5.id()).is_none() {
            let waiting = s.parties[1].node_mut().take_orphans_waiting_on(&b4.id());
            assert!(!waiting.is_empty(), "B5 must be parked behind B4 after its refused graft");
            for blk in waiting {
                // a shell re-enters through the shell door; a full block (this fixture parks the full block)
                // walks the preverify/ingest door, exactly as the runtime's cascade routes it
                if blk.pow_proof.is_empty() {
                    let _ = s.parties[1].node_mut().readmit_parked_shell(&blk);
                } else {
                    let now = s.now;
                    let _ = s.parties[1].node_mut().ingest_block(blk, now);
                }
            }
        }
        assert!(s.parties[1].node().dag().get(&b5.id()).is_some(), "B5 landed behind B4 through the strand cascade");
        s.drain();
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "the pair did not re-reach one chain after the segment heal"
        );
    }

    /// ⛔⛔ DB-335 — A CHAIN OBJECT A NODE BUILDS ITSELF REACHES A PEER'S POOL WITHOUT ANY BLOCK.
    ///
    /// Every node-level publication (DEX fills, asset create/mint/spend, both unbonds, the seat request, equivocation
    /// evidence, peg objects, price marks, yield claims) entered THIS node's pool through the gossip admission door and
    /// queued nothing: it left inside a block this node authored, or through the stuck re-relay after 4 blocks of pool
    /// height — never on a node whose pool height is frozen. The object here is equivocation evidence, which needs no
    /// funding, no bond and no held block to be well-formed. THE WITNESS IS B's OWN POOL: a block that carries the object
    /// SETTLES it on B, it never pools it, so B's pool can hold A's object only if A GOSSIPED it — whatever either side
    /// produces meanwhile. (Two fixtures tried "no block at all" and both measured ~400 produced blocks: a connected pair
    /// joins itself. The precondition was the fixture's claim, not the property's.) CONTROL: A's own pool holds it.
    #[test]
    fn db335_a_chain_object_a_node_builds_reaches_the_peers_pool_without_a_block() {
        // Two UNJOINED runtimes on one plain genesis: neither is a bootstrap origin, so neither produces (join-mesh-or-
        // nothing) and neither can join the other, since joining is grafting a peer's block. (A scenario party is built
        // to produce: the first cut used `scenario_node_in` and both sides laid ~400 blocks, so a block could carry the
        // object and the pin could not tell gossip from carriage — measured on cycle 15's P binary b1361583.)
        let g = crate::node::tests::genesis_block();
        let (ta, tb) = crate::transport::LoopbackTransport::pair();
        let mut a = NodeRuntime::new(Node::new(g.clone()).unwrap(), ta);
        let mut b = NodeRuntime::new(Node::new(g).unwrap(), tb);
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vote = |tag: &[u8]| {
            let block = Hash32::hash(tag);
            crate::validator::VoteCert {
                pubkey: pk.clone(),
                block,
                height: 5,
                sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&block, 5), &sk)
                    .expect("the key signs a finality vote"),
            }
        };
        let (x, y) = (vote(b"db335-x"), vote(b"db335-y"));
        let id = crate::mempool::PqTx::content_id(
            &crate::equivocation_tx::wire(&x, &y).expect("one key, one height, two blocks"),
        );
        assert!(
            matches!(a.node_mut().publish_equivocation(&x, &y), crate::node::AssetSpendOutcome::Published),
            "A publishes the evidence through the node-level publication"
        );
        assert!(a.node().mempool().contains(&id), "CONTROL: A's own pool holds it");
        assert!(!b.node().mempool().contains(&id), "PRECONDITION: B does not hold it before any tick");
        let (fr, mc) = (Hash32::hash(b"db335-fr"), Hash32::hash(b"db335-mc"));
        let t0 = a.node().dag().get(&a.node().selected_tip().expect("tip")).expect("header").header.timestamp + 60_000;
        let mut ticks = 0u64;
        // ⭐ THE WITNESS IS B'S GOSSIP DOOR, NOT B'S POOL BETWEEN TICKS (cycle 16, F2, MEASURED): two genesis runtimes
        // join each other on the first beacon ("a live peer's canonical tip is an ancestor of our resumed tip") and
        // produce, so a block can carry the object in the very tick it arrives — the F2 run showed the evidence
        // assembled on B, then carried by a block, and a between-tick pool check never saw it. `txs_ingested` counts only
        // the gossip door's admissions (never a block's carriage), and A has pooled exactly ONE object, so a non-zero
        // count on B is this object reaching B's pool without a block.
        assert_eq!(a.node().mempool().len(), 1, "PRECONDITION: A pooled exactly one object, so B's gossip count is it");
        let mut gossiped = 0usize;
        while ticks < 400 && gossiped == 0 {
            let now = t0 + ticks * SLOT_MS;
            let _ = a.tick(now, fr, mc);
            gossiped += b.tick(now, fr, mc).txs_ingested;
            ticks += 1;
        }
        assert!(
            gossiped > 0,
            "⛔⛔ DB-335: after {ticks} tick(s) B's gossip door admitted nothing — the evidence A built and pooled was \
             never gossiped, so it reaches a peer only inside a block (which settles it, never pools it)"
        );
    }

    /// ⭐ A DEEP GOSSIP LOSS HEALS AT PAGE SPEED — NEVER ONE LEVEL PER ROUND TRIP.
    ///
    /// Two independent nodes: party 0 PRODUCES and serves; party 1 is the peer that lost a burst
    /// of gossip and must re-reach party 0's chain over the wire — the tips must agree at the end.
    ///
    /// ROOT-LAYER: the block lane's serve answers only the ids the asker NAMED, and the asker can
    /// only learn a missing block's parent by round-tripping that block's shell first — so a
    /// contiguous loss of N blocks costs N round trips even when every answer arrives instantly.
    /// The producer extends the chain faster than one block per lane cadence, so the descent
    /// LOSES THE RACE by construction: the gap never closes, the deferral buffer never drains,
    /// and the pair's heights never re-meet.
    ///
    /// MEASURED (step3-probe run 8, scratch /tmp/musd-step3probe-r1iHrY, 2026-09-07, binary
    /// 6cd9432b with both parent-naming fixes already in): 288 byte-identical "[block-lane]
    /// serving 4 shell(s) of 5 asked" serves against the same want set, ZERO grafts in 240s,
    /// h1=592 vs h2=444 at the deadline with 52 blocks parked — the lane round-tripped the same
    /// un-graftable children forever while the descent frontier never advanced past the budget.
    ///
    /// THE LAW: one served page must carry the asked block AND its missing ancestry down to the
    /// asker's own frontier (the asker states its floor; the peer's serve descends to it within
    /// the byte budget), and the ingest must graft that whole span through the page's own chain
    /// of custody — so a loss of any depth heals in ceil(depth/page) round trips, not depth
    /// round trips. Fail-closed: trust flows only from fold-named want ids down the
    /// id-authenticated parent links of shells in the SAME page; an id outside that closure is
    /// refused exactly as before.
    #[test]
    fn a_deep_gossip_loss_heals_at_page_speed_not_one_level_per_round() {
        let mut s = RtSim::new(2, 0x0907_2026_0907_0003u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        // TWELVE consecutive blocks are lost to party 1 (a restart, a Tor wedge, a saturated
        // queue — any burst loss); the thirteenth arrives and parks on the span.
        for _ in 0..12 {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1));
        }
        s.step(Act::Produce(0, 1)); // arrives, parks on the 12-deep missing span
        assert!(
            s.blocks.len() >= 16,
            "the schedule produced {} block(s), need 16",
            s.blocks.len()
        );
        let dropped: Vec<crate::block::BlockId> = s.blocks[s.blocks.len() - 13..s.blocks.len() - 1]
            .iter()
            .map(|b| b.id())
            .collect();
        for id in &dropped {
            assert!(s.parties[1].node().dag().get(id).is_none(), "party 1 must lack the dropped span for this shape");
        }
        // ── THE HEAL, on the lane party 1 actually uses (2026-09-18 compact relay: the peer's tip
        // beacon names a block party 1 lacks; the batch page — DB-17/50/60/69 — carries every body above
        // party 1's OWN tip, oldest first, in ONE page; the off-lock verifier applies them in order). Each
        // trip delivers what the hub holds for party 1, advances the clock past the lane's 2 s ask pace
        // and ticks the asker twice (ask out + served; answer lands + applies). The trip cap is the LAW:
        // the span heals at PAGE speed (12 bodies against a 32-body page), never one level per trip. The
        // 2026-09-07 arming ("the child parks, the descent names its parents") no longer fires here — the
        // page brings the span before a child can park (measured 2026-09-19: 40 deliveries, nothing parked).
        let mut trips = 0usize;
        loop {
            let landed = dropped.iter().filter(|id| s.parties[1].node().dag().get(id).is_some()).count();
            let parked = s.parties[1].node().relay_buffered_len();
            let wants = s.parties[1].node_mut().wanted_block_ids();
            if landed == dropped.len() && parked == 0 && wants.is_empty() {
                break;
            }
            trips += 1;
            assert!(
                trips <= 6,
                "the 12-deep loss did not heal at page speed: {trips} round trip(s) spent, {landed} of {} \
                 dropped block(s) landed, {} want(s) still live, {parked} block(s) still parked — the lane is \
                 walking one level per round trip (probe run 8: 288 identical serves, zero grafts, gap 148 at \
                 the deadline). Wants: {wants:?}",
                dropped.len(),
                wants.len()
            );
            s.now += 2_100; // the lane's own ask cadence
            s.step(Act::Deliver(1)); // the announcement lands; the ask goes out; the peer serves it
            s.tick(1); // the answer lands; the bodies apply; parked strands cascade
        }
        for id in &dropped {
            assert!(
                s.parties[1].node().dag().get(id).is_some(),
                "dropped block {id:?} never landed although the lane closed its want set"
            );
        }
        s.drain();
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "the pair did not re-reach one chain after the page-speed heal"
        );
    }

    /// ⛔⛔⛔ TIER 1 — A PAYMENT ONE PARTY LAYS IS RECORDED BY ITS PEER, over the hub (cells + the bulk lane, as the live
    /// nodes carry them). Party 0 pools ONE honest payment (a real validity carrier) and lays it; party 1 never pools it
    /// and must hold the payment's output in a record — the bytes reach it only as a record page.
    /// WHY HERE AND NOT ON A LOOPBACK PAIR (measured 2026-10-02): `LoopbackTransport` has no bulk lane, and every record is
    /// the fixed 256-note payload (~295 KB) while the cell lane answers a by-id ask with a 36,000-byte page — so on a
    /// loopback pair a payment block's record never crosses (720 asks in 120 s, every answer `hold 0`). Letting the cell
    /// page carry one oversized record was tried and REVERTED (§9.2): it opened the unconditional kind-8 cell range ask to
    /// ~73-cell answers and broke `a_loss_deeper_than_the_want_slot_array_still_heals_at_page_speed`. Records ride the bulk
    /// lane, here as on the live nodes.
    /// TWO-PARTY-REVIEWED: party 0 lays the payment; party 1 is fed only what the hub carries; the claim is party 1's.
    ///
    /// ⭐ DB-358 r3 — THE JOINER'S LIVENESS, ON THE FAITHFUL HUB (with its band worker). In process, a node that jumped
    /// past an UNFOLDED block holding an honest spend kept the payment (6329ccf) but its fold WAITED at that spend
    /// ("[respend] ⏸ DB-353 §13.6 … admitted set is unknown here"): an awaiting band step resolves only when a later block
    /// carries its proven band transition, and the bare fixture proves none. Here the hub's band worker proves them, so
    /// this measures whether the wait is a fixture artifact or a real stall: party 1 jumps by party 0's bundle while the
    /// spend block is unfolded (the block is owed to party 1, never delivered), then follows the hub. Asserted: party 1
    /// holds the payment AND folds as far as party 0.
    /// TWO-PARTY-REVIEWED: party 0 lays the payment; party 1 learns it only through the jump and the hub.
    /// The CONTROL of the hub joiner pin: the SAME jump and follow, with NO spend in the jump window. If this one cannot
    /// drain either, the stall is the hub jump's own (pre-existing), not the carried spend's.
    /// TWO-PARTY-REVIEWED: party 0 produces; party 1 learns it only through the jump and the hub.
    #[test]
    fn control_a_joiner_that_jumps_past_unfolded_idle_blocks_keeps_folding_over_the_hub() {
        let mut s = RtSim::new(2, 0x358_3_2026_1003u64);
        s.arm_deadline(std::time::Duration::from_secs(300));
        for a in [Act::Produce(0, 2), Act::Drain] {
            s.step(a);
        }
        s.step(Act::Produce(0, 1)); // an idle block — owed to party 1, never delivered
        s.step(Act::Jump(1, 0));
        // Two follow rounds: every hub Drain runs to its round cap (40–136 s measured — the hub always has a few messages
        // in flight), so twelve rounds blew the 300 s scenario deadline although the pair had converged (MEASURED
        // 10/03: one round after the jump, both tips equal and both folds at 393).
        for _ in 0..2 {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drain);
        }
        let (seq0, seq1) = (s.parties[0].node().served_seq(), s.parties[1].node().served_seq());
        eprintln!("[db358-r3-hub-control] folded positions: party0 {seq0} party1 {seq1}");
        assert_eq!(seq1, seq0, "⛔ the joiner's fold stopped short of the producer's with no spend in its window");
    }

    #[test]
    fn a_joiner_that_jumps_past_an_unfolded_honest_spend_credits_it_and_keeps_folding_over_the_hub() {
        let mut s = RtSim::new(2, 0x358_3_2026_1003u64);
        s.arm_deadline(std::time::Duration::from_secs(300));
        for a in [Act::Produce(0, 2), Act::Drain] {
            s.step(a);
        }
        // The payment's input is funded on party 0 alone — party 1 learns everything from here on by its jump.
        let spend = crate::node::tests::honest_spend_tx_for_test(s.parties[0].node_mut(), &mut [], 0x3583);
        let out0: [u8; 32] = spend.output_notes[..32].try_into().expect("a note's commitment is its first 32 bytes");
        s.parties[0].node_mut().ingest_tx_unverified(spend).expect("party 0 pools an honest payment");
        s.step(Act::Produce(0, 1)); // the spend block — owed to party 1, never delivered
        assert!(s.parties[0].node().holds_record_with_cm(&out0), "CALIBRATION: party 0 laid the payment");
        s.step(Act::Jump(1, 0)); // party 1 adopts party 0's bundle while the spend block is still unfolded
        // ONE follow round — see the control's note: every hub Drain runs to its round cap, and this scenario's drains
        // carry the funding blocks too (two rounds measured past the 300 s deadline); one round already converged the
        // control (393/393 measured).
        s.step(Act::Produce(0, 1));
        s.step(Act::Drain);
        let (seq0, seq1) = (s.parties[0].node().served_seq(), s.parties[1].node().served_seq());
        let held1 = s.parties[1].node().holds_record_with_cm(&out0);
        eprintln!("[db358-r3-hub] party 1 holds the payment: {held1}; folded positions: party0 {seq0} party1 {seq1}");
        assert!(held1, "⛔⛔⛔ the joiner LOST an honest payment carried in its jump window");
        assert_eq!(seq1, seq0, "⛔ the joiner's fold stopped short of the producer's — it waits at the carried spend");
    }

    #[test]
    fn a_payment_one_party_lays_is_recorded_by_its_peer_over_the_hub() {
        let mut s = RtSim::new(2, 0x7e1_2026_1002u64);
        s.arm_deadline(std::time::Duration::from_secs(300));
        for a in [Act::Produce(0, 2), Act::Drain] {
            s.step(a);
        }
        // DB-223 Q7: the payment's input is FUNDED on chain first; the funding (and fold) blocks reach party 1 too.
        let spend = {
            let (p0, rest) = s.parties.split_at_mut(1);
            let mut peers: Vec<&mut crate::node::Node> = rest.iter_mut().map(|p| p.node_mut()).collect();
            crate::node::tests::honest_spend_tx_for_test(p0[0].node_mut(), &mut peers, 0x7e1)
        };
        let out0: [u8; 32] = spend.output_notes[..32].try_into().expect("a note's commitment is its first 32 bytes");
        s.parties[0].node_mut().ingest_tx_unverified(spend).expect("party 0 pools an honest payment");
        s.step(Act::Produce(0, 1));
        assert!(s.parties[0].node().holds_record_with_cm(&out0), "CALIBRATION: party 0 laid the payment and recorded it");
        for _ in 0..4 {
            if s.parties[1].node().holds_record_with_cm(&out0) {
                break;
            }
            s.step(Act::Drain);
        }
        assert!(
            s.parties[1].node().holds_record_with_cm(&out0),
            "⛔⛔⛔ TIER 1: party 1, fed only what the hub carries, never recorded the payment's output — a payment crosses \
             the mesh only if the block that carries it can be recorded by a node that never pooled it"
        );
    }

    /// ⛔⛔⛔ A LOSS DEEPER THAN THE WANT-SLOT ARRAY — THE DESCENT'S LEARNED PARENTS FELL ON THE FLOOR.
    ///
    /// The sibling pin above drives a TWELVE-deep loss, which is under
    /// [`crate::protocol::TX_REQ_FIXED_COUNT`] (32) — the width of `Node::wanted_block_slots`. At
    /// that depth the ask never fills its own slot array, so the one branch that decides whether a
    /// deep loss can heal at all is never taken. This pin drives the loss PAST that width.
    ///
    /// THE DEFECT: `Node::want_block_by_id` places a name only when a slot is free
    /// (`iter_mut().find(|s| s.is_none())`) and DROPS it silently otherwise. The slots are filled
    /// by the canonical fold's own C1 waits, re-derived and re-named on every fold pass, so on a
    /// loss deeper than the array they are permanently full of the SHALLOW end of the loss. The
    /// descent's one learning step — a served shell that cannot graft naming its missing parents
    /// (`graft_block_shell_from_trusted_id`) — therefore places nothing, the ask is byte-identical
    /// on the next cadence, the serve is byte-identical in reply, and the lane round-trips forever
    /// while the producer keeps extending.
    ///
    /// MEASURED in situ (step3-probe run 9, binary usdmd-node-descent-ca2b201278c117e2, evidence
    /// /tmp/musd-step3probe-dLSSy6): node1 emitted 407 BYTE-IDENTICAL
    /// `[block-lane] descent: serving 4 shell(s) for 32 asked block(s) (locator 13), 35033 byte(s)`
    /// serves and node2 answered every one with `[block-lane] 0 of 4 served shell(s) grafted`
    /// (152 of them) — "32 asked" IS the saturated slot array. node2's height stalled at 792 while
    /// node1 reached 987, and its beacon read `ours 829` for the last 100s of the budget.
    ///
    /// THE LAW: a want set is a DEBT, not a fixed-size table of the first 32 debts. When a served
    /// shell names a parent this node lacks, that name must be placeable — the parent is strictly
    /// closer to the fold's floor than the child whose slot it would take, so the lane must always
    /// be able to deepen. Fail-closed is unchanged: only ids reached down an id-authenticated
    /// parent link from a shell the fold already named can enter, and the ingest door's checks are
    /// untouched.
    #[test]
    fn a_loss_deeper_than_the_want_slot_array_still_heals_at_page_speed() {
        let mut s = RtSim::new(2, 0x0907_2026_0907_00d1u64);
        s.arm_deadline(std::time::Duration::from_secs(900));
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        // A burst loss DEEPER than the want-slot array (64 > TX_REQ_FIXED_COUNT = 32): the whole
        // span cannot be named at once, so the lane must be able to learn its way down.
        const LOST: usize = 64;
        for _ in 0..LOST {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1));
        }
        s.step(Act::Produce(0, 1)); // arrives, parks on the deep missing span
        assert!(
            s.blocks.len() >= LOST + 4,
            "the schedule produced {} block(s), need {}",
            s.blocks.len(),
            LOST + 4
        );
        let dropped: Vec<crate::block::BlockId> = s.blocks
            [s.blocks.len() - (LOST + 1)..s.blocks.len() - 1]
            .iter()
            .map(|b| b.id())
            .collect();
        for id in &dropped {
            assert!(s.parties[1].node().dag().get(id).is_none(), "party 1 must lack the dropped span for this shape");
        }
        // The heal budget is the LAW restated at this depth: the batch page (DB-17/50/60/69) carries up
        // to 32 bodies above the asker's own tip per round trip, so a 64-deep loss costs a handful of
        // trips (two pages), never one per level and never unbounded. 12 trips leaves ample slack for
        // ask/answer/apply staggering at 64 blocks lost. (The 2026-09-07 "parked child" arming no longer
        // fires under compact relay — see the 12-deep sibling pin.)
        // THE HEAL, MEASURED 2026-10-27 (scratchpad/funds/loss-17.log): the inventory lists the span (65 ids), pages of
        // 8 and 6 bodies land (the byte budget below), and when the block lanes read STALE against the live bound the
        // node takes the certified jump (`[dsync] … taking the jump; the lanes failed (IBD)`) — after it the asker holds
        // the producer's tip, 56 dropped blocks above its anchor and 8 below it as history. The claim is completion
        // within the derived budget by lane or by jump, never one level per trip and never unbounded.
        // PAGE SPEED, IN THE LANE'S OWN UNITS (2026-10-27): a page carries up to 32 bodies OR
        // `BLOCK_BATCH_BYTES_MAX` (768 KiB), whichever binds — at ~94–120 KB per body that is 6–8 bodies, so a
        // 64-deep loss is ~9–11 pages, each one round trip, plus the inventory and descent trips before the first
        // page. MEASURED (scratchpad/funds/loss-11.log): pages of 8, 6, 6, 6, 6 … landed 56 of 64 by trip 13 with 0
        // wants and 0 parked — advancing at page speed. The bound is derived from the budget and the real wire
        // size of the dropped blocks, never a quoted 12.
        let max_wire = s.blocks.iter().map(|b| postcard::to_allocvec(b).map(|v| v.len()).unwrap_or(0)).max().unwrap_or(1).max(1);
        let per_page = (crate::node_runtime::BLOCK_BATCH_BYTES_MAX / max_wire).clamp(1, 32);
        let trip_budget = 3 + LOST.div_ceil(per_page) + 2;
        eprintln!("[deep-loss] max body wire {max_wire} B → {per_page} bodies per page → trip budget {trip_budget} for {LOST} lost");
        let mut trips = 0usize;
        let mut repeats = 0usize;
        let mut last_ask: Option<[u8; 32]> = None;
        loop {
            let wants = s.parties[1].node_mut().wanted_block_ids();
            let parked = s.parties[1].node().relay_buffered_len();
            // HEALED = held, or RELEASED BELOW THE DAG'S OWN RETENTION FLOOR (2026-10-27). The producer keeps producing
            // while the loss heals, so by the time the last page lands the asker's tip has moved on and the DAG window
            // (`Dag::keep_depth`, NO-GROWTH) has released the oldest of the dropped span: MEASURED (scratchpad/funds/
            // loss-15.log) 0 wants, 0 parked, tip score 103 at 97 held blocks, and exactly the 8 oldest dropped blocks
            // (scores 4..11) absent — below the floor, never a hole. The heal's claim is the tip, the empty want set
            // and the empty park; a released block is not a loss.
            // The producer's chain is linear here (one party produces on its own tip), so a block's blue score is its
            // position in the sim's block list + 1 — read from the list, since BOTH DAGs may have released it.
            let score_of = |id: &crate::block::BlockId| s.blocks.iter().position(|b| b.id() == *id).map(|k| k as u64 + 1);
            let (landed, released, caught_up) = {
                let p1 = s.parties[1].node();
                let p0 = s.parties[0].node();
                let tip_score = p1.selected_tip().and_then(|t| p1.dag().get(&t)).map_or(0, |n| n.blue_score);
                // below the asker's own history floor: the DAG retention window, or — when the lanes were STALE and
                // the asker took the certified jump (IBD; MEASURED loss-16.log `[dsync] … taking the jump; the lanes
                // failed (IBD)`) — its certified anchor: a jumper holds the chain from its anchor up (DB-282), and the
                // blocks below are history it never needs
                let floor = tip_score.saturating_sub(p1.dag().keep_depth()).max(p1.certified_anchor_score());
                let held = dropped.iter().filter(|id| p1.dag().get(id).is_some()).count();
                let below = dropped.iter().filter(|id| p1.dag().get(id).is_none() && score_of(id).is_some_and(|sc| sc < floor)).count();
                // caught up = the asker HOLDS the producer's own selected tip (gossip may be one block in flight)
                let caught_up = p0.selected_tip().is_some_and(|t| p1.dag().get(&t).is_some());
                (held, below, caught_up)
            };
            if caught_up && wants.is_empty() && parked == 0 && landed + released == dropped.len() {
                eprintln!("[deep-loss] healed after {trips} trip(s): {landed} landed, {released} released below the retention floor, on the producer's tip");
                break;
            }
            // The livelock's own signature: the SAME want set two cadences running means the
            // lane learned nothing from the page it just consumed.
            let mut blob: Vec<u8> = Vec::with_capacity(wants.len() * 32);
            for id in &wants {
                blob.extend_from_slice(id.as_bytes());
            }
            let digest = *blake3::hash(&blob).as_bytes();
            if last_ask == Some(digest) {
                repeats += 1;
            }
            last_ask = Some(digest);
            trips += 1;
            if trips > trip_budget {
                // DIAGNOSTIC (2026-10-27): which dropped blocks never landed, and what the asker holds around them
                let p1 = s.parties[1].node();
                let tip_score = p1.selected_tip().and_then(|t| p1.dag().get(&t)).map_or(0, |n| n.blue_score);
                for (i, id) in dropped.iter().enumerate() {
                    if p1.dag().get(id).is_none() {
                        let parent_held = s.blocks.iter().find(|b| b.id() == *id).map(|b| b.header.parents.iter().all(|pp| p1.dag().get(pp).is_some()));
                        eprintln!(
                            "[deep-loss-diag] dropped #{i} {} absent: parked {} · wanted {} · parent(s) held {:?}",
                            &id.to_hex()[..8], p1.relay_parked(id), p1.wants_block(id), parent_held
                        );
                    }
                }
                eprintln!("[deep-loss-diag] asker tip score {tip_score}, dag {} block(s), parked {}", p1.dag().len(), p1.relay_buffered_len());
            }
            assert!(
                trips <= trip_budget,
                "a {LOST}-deep loss did not heal at page speed ({per_page} bodies per page, budget {trip_budget}): {trips} round trip(s) spent, {landed} of {LOST} dropped \
                 block(s) landed, {} want(s) still live, {parked} block(s) still parked, {repeats} identical \
                 consecutive want set(s). The want-slot array is saturated and the descent's learned parents \
                 are being dropped (probe run 9: 407 byte-identical serves, 0 grafts, gap 195).",
                wants.len()
            );
            s.now += 2_100; // the lane's own ask cadence
            s.step(Act::Deliver(1)); // the announcement lands; the ask goes out; the peer serves it
            // a 32-body page walks the off-lock verifier (~30 ms a body in wall time): give the drain the
            // ticks it needs to apply the page — one ask cadence is ~20 runtime ticks on a live node
            for _ in 0..8 {
                s.tick(1);
            }
        }
        {
            let p1 = s.parties[1].node();
            let p0 = s.parties[0].node();
            let tip_score = p1.selected_tip().and_then(|t| p1.dag().get(&t)).map_or(0, |n| n.blue_score);
            let floor = tip_score.saturating_sub(p1.dag().keep_depth()).max(p1.certified_anchor_score());
            let _ = p0;
            for id in &dropped {
                let released = s.blocks.iter().position(|b| b.id() == *id).is_some_and(|k| (k as u64 + 1) < floor);
                assert!(
                    p1.dag().get(id).is_some() || released,
                    "dropped block {id:?} never landed although the lane closed its want set"
                );
            }
        }
        s.drain();
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "the pair did not re-reach one chain after a loss deeper than the want-slot array"
        );
    }

    /// ⛔⛔⛔ THE CELL LANE'S PAGE IS FOUR SHELLS, AND A GAP DEEPER THAN THAT NEVER HEALED (2026-09-17).
    ///
    /// The sibling pins above serve their pages from the BULK stream (1 MiB — a 64-deep plan fits
    /// one page, so the cut never falls inside it and the page order is invisible). The live
    /// cell lane cuts every page at 36,000 bytes: ~4 shells. MEASURED on two real nodes (seat
    /// journey run 8, `usdmd_journey_seat_52590`, both bulk circuits timed out so every ask rode
    /// the cell lane): node0 logged ~30 consecutive
    ///     [block-lane] descent: serving 4 shell(s) for 18 asked block(s) (locator 12), 35133 byte(s)
    ///     [block-lane] 0 of 4 served shell(s) grafted (unwanted, already held, or a parent still missing …)
    /// while its orphan count climbed 4 → 16 and `[produce] ⛔ the deferral is NOT catching up`
    /// fired for 400 s; the pair mined two chains, then DSYNC-jumped onto EACH OTHER'S (a swap,
    /// still two chains), and each jump discarded the seat the abandoned chain had carried
    /// (`validators=1` each, holding the OTHER's id — the §DB finding).
    ///
    /// WHY: the plan is served DESCENDING by score so the asked anchor always rides the page; a
    /// shell whose parent is still missing was then DROPPED (`add_wanted_shell` false → nothing
    /// kept) while its want slot stayed live (the id is not in the DAG). The next ask named the
    /// same shallow ids, the server's top-4-by-score were those same shells, and the page was
    /// byte-identical forever. The fix is on the asker: a served shell inside the trusted closure
    /// whose parents are missing is PARKED in the relay's orphan buffer (the same bounded park a
    /// gossiped orphan uses) and its want slot is released — so the next ask names ONLY the deeper
    /// missing parents, the page descends by four per trip, and the landing of the deepest parent
    /// cascades the parked strand up through the relay exactly as a gossiped orphan chain does.
    ///
    /// The bound below is the page-speed law at the CELL lane's width and the lane's own cadence:
    /// the ask is re-sent every 2 s whether or not the last page has landed (no in-flight
    /// bookkeeping — pre-existing, and bounded: a duplicate page or two per descent step), and
    /// the sim's bulk pump lands a page one to three ticks after its ask, so each 4-shell step
    /// costs a few ticks and a few repeated asks. The law is therefore stated as PROGRESS: the
    /// park (or the DAG) must grow within every window of 6 trips, the whole gap heals within
    /// 4·⌈LOST/4⌉ + 8 trips, and identical consecutive want sets stay under 3 per page. Before
    /// the fix this pin spun with an identical want set on EVERY trip and ONE block parked
    /// (RED, refutation first: 11 trips, 9 identical want sets, 5 wants live, 1 parked); after:
    /// the park grows by four per step (1 → 5 → 9 → 13 → 17 …) until the deepest parent lands
    /// and the strand cascades.
    #[test]
    fn a_gap_deeper_than_one_cell_lane_page_heals_by_descending_a_page_per_trip() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_00e1u64);
        s.arm_deadline(std::time::Duration::from_secs(900));
        // THE CELL LANE'S PAGE: 36,000 bytes, exactly what the live runtime hands
        // `serve_notes_req_bytes` on the `NotesReq` path.
        s.bulk_budget = 36_000;
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        const LOST: usize = 24;
        for _ in 0..LOST {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1));
        }
        s.step(Act::Produce(0, 1)); // arrives, parks on the deep missing span
        let dropped: Vec<crate::block::BlockId> = s.blocks
            [s.blocks.len() - (LOST + 1)..s.blocks.len() - 1]
            .iter()
            .map(|b| b.id())
            .collect();
        for id in &dropped {
            assert!(s.parties[1].node().dag().get(id).is_none(), "party 1 must lack the dropped span for this shape");
        }
        // The asker DEFERS its own production while it is behind — exactly what the live runtime does
        // (`[produce] deferred: N gossiped block(s) wait on parents`).
        s.parties[1].set_production_paused_for_test(true);
        // The 36 KB budget knob applies to the kind-9 DESCENT ask alone (the cell lane's page); under
        // compact relay the batch page (kind 13, the bulk lane's 1 MiB) brings the span in one page, so
        // the trip cap below is generous for it and exact for the descent should the lane fall back to
        // it. (The 2026-09-07 "parked child" arming no longer fires here — see the 12-deep sibling pin.)
        let pages = LOST.div_ceil(4);
        let cap = 4 * pages + 8;
        let mut trips = 0usize;
        let mut repeats = 0usize;
        let mut last_ask: Option<[u8; 32]> = None;
        // PROGRESS WINDOW: held = parked + landed. If it has not grown across 6 consecutive trips
        // the descent is not descending, whatever the trip cap still allows.
        let mut held_at_window: usize = 0;
        loop {
            let wants = s.parties[1].node_mut().wanted_block_ids();
            let parked = s.parties[1].node().relay_buffered_len();
            let landed = dropped.iter().filter(|id| s.parties[1].node().dag().get(id).is_some()).count();
            if landed == dropped.len() && wants.is_empty() && parked == 0 {
                break;
            }
            let held = parked + s.parties[1].node().dag().len();
            if trips % 6 == 0 {
                assert!(
                    trips == 0 || held > held_at_window,
                    "no descent progress across 6 trips (held {held_at_window} → {held}): the \
                     served page is the same shallow shells again — the run-8 livelock"
                );
                held_at_window = held;
            }
            let mut blob: Vec<u8> = Vec::with_capacity(wants.len() * 32);
            for id in &wants {
                blob.extend_from_slice(id.as_bytes());
            }
            let digest = *blake3::hash(&blob).as_bytes();
            if last_ask == Some(digest) {
                repeats += 1;
            }
            last_ask = Some(digest);
            trips += 1;
            assert!(
                trips <= cap,
                "a {LOST}-deep loss did not heal through 4-shell pages: {trips} round trip(s) \
                 spent (cap {cap} = 4 trips per 4-shell page + 8), {} want(s) still live, {parked} \
                 block(s) still parked, {repeats} identical consecutive want set(s). The served \
                 page is the same four shallow shells every trip (run 8: ~30 byte-identical \
                 4-shell pages, 0 grafted).",
                wants.len()
            );
            s.now += 2_100; // the lane's own ask cadence
            // One ask cadence is ~20 runtime ticks on a live node (100 ms each); the drain budget
            // per tick is shared with record pages, so give the page a few ticks to land and apply.
            s.step(Act::Deliver(1)); // the announcement lands; the ask goes out; the peer serves it
            for _ in 0..3 {
                s.tick(1);
            }
        }
        s.parties[1].set_production_paused_for_test(false);
        assert!(
            repeats < 3 * pages,
            "{repeats} byte-identical consecutive want sets over {trips} trip(s) — three or more \
             repeated asks per descent step means the ask did not descend"
        );
        for id in &dropped {
            assert!(
                s.parties[1].node().dag().get(id).is_some(),
                "dropped block {id:?} never landed although the lane closed its want set"
            );
        }
        s.drain();
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "the pair did not re-reach one chain after a gap deeper than one cell-lane page"
        );
    }

    /// ⛔⛔⛔ THE RUN-9 SHAPE: THE DEEP WANT MUST HEAD THE PAGE WHILE FRESH SHALLOW WANTS PILE UP (§DB-6).
    ///
    /// With DB-1/DB-2 in place the seat journey's run 9 (`usdmd_journey_seat_35880`) still sat ~200
    /// blocks behind for its whole life: `0 of 85 served shell(s) grafted`, `0 of 86 …`, … while
    /// `[beacon] heavier tip seen (peer blue_work 546 > ours 345)` repeated. The asker's want set
    /// was a deep descent want PLUS a fresh shallow want per newly gossiped block (its parent is
    /// missing), and the server's one global DESCENDING plan put those fresh wants — the highest
    /// scores — at the top of every page. Each page was the newest N shells, none graftable, and
    /// the deep want never got a byte of page while the peer produced.
    ///
    /// This pins the SERVE directly, where the page's content is decided: one held chain, an ask
    /// naming a deep want and three fresh shallow wants, a page budget of two shells. The page
    /// must open with the DEEPEST asked id and continue with its own parent — a contiguous run
    /// from an asker-named anchor — never with the newest shell. Under the old global descending
    /// order the same ask answered `[newest, newest.parent]` (RED first: that is exactly the
    /// run-9 page). The asker's half of the descent (park, free the slot, cascade) is pinned by
    /// `a_gap_deeper_than_one_cell_lane_page_heals_by_descending_a_page_per_trip`.
    #[test]
    fn a_descent_want_is_served_ahead_of_fresh_shallow_wants() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_00e2u64);
        s.arm_deadline(std::time::Duration::from_secs(900));
        // Party 0 holds a 20-block chain above genesis; party 1 holds genesis only (its locator is
        // what a node ~20 blocks behind would send).
        s.step(Act::Produce(0, 20));
        assert!(s.blocks.len() >= 20, "the chain did not build: {} block(s)", s.blocks.len());
        let chain: Vec<crate::block::BlockId> = s.blocks.iter().map(|b| b.id()).collect();
        // The ask: locator = genesis (all party 1 holds); asked = the DEEP want (block 4 — the
        // parent of a parked block 5) and three FRESH shallow wants (blocks 18, 19, 20 — parents of
        // three newly gossiped blocks whose bodies the peer went on to produce).
        // The locator names THE PARTY'S OWN genesis (the network-prefixed one the sim builds); the
        // default `genesis_block().id()` never matched it — a latent pin bug the top-down page hid.
        let genesis = s.parties[0].node().dag().genesis().expect("the party holds its genesis");
        let deep = chain[3];
        let fresh = [chain[17], chain[18], chain[19]];
        let mut req = Vec::new();
        req.push(9u8);
        req.push(1u8);
        req.extend_from_slice(genesis.as_bytes());
        for f in &fresh {
            req.extend_from_slice(f.as_bytes());
        }
        req.extend_from_slice(deep.as_bytes()); // the deep want LAST in the ask — order must not matter
        // A page of two shells (18,000 bytes ≈ 2 × 8.7 KB).
        let page = s.parties[0].serve_notes_req_bytes(&req, 18_000);
        assert!(page.len() > 13 && &page[..9] == b"BLOCKPAGE", "no BLOCKPAGE answered");
        let mut served: Vec<crate::block::BlockId> = Vec::new();
        let body = &page[9..];
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&body[off..off + 4]);
            let len = u32::from_le_bytes(lb) as usize;
            off += 4;
            if len == 0 || off + len > body.len() {
                break;
            }
            let b: crate::block::Block =
                postcard::from_bytes(&body[off..off + len]).expect("a served shell decodes");
            served.push(b.id());
            off += len;
        }
        assert_eq!(served.len(), 2, "a two-shell budget must answer two shells: {}", served.len());
        assert_eq!(
            served[0], deep,
            "the page must OPEN with the deepest asked id (block 4); it opened with block {:?} — the \
             run-9 page (the newest shells first, the deep want starved)",
            chain.iter().position(|c| *c == served[0]).map(|i| i + 1)
        );
        assert_eq!(
            served[1], chain[2],
            "the page must continue with the deep anchor's OWN parent (block 3) — a contiguous run \
             from an asker-named anchor is what the page door's closure admits"
        );
        for f in &fresh {
            assert!(
                !served.contains(f),
                "a fresh shallow want rode the page ahead of the deep descent"
            );
        }
        // And the SAME ask with a budget wide enough for the deep run AND one fresh run keeps the
        // deep run first: the fresh anchors take what is left, never the head of the page.
        let wide = s.parties[0].serve_notes_req_bytes(&req, 60_000);
        let mut first: Option<crate::block::BlockId> = None;
        let body = &wide[9..];
        if body.len() >= 4 {
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&body[..4]);
            let len = u32::from_le_bytes(lb) as usize;
            if len > 0 && 4 + len <= body.len() {
                let b: crate::block::Block =
                    postcard::from_bytes(&body[4..4 + len]).expect("a served shell decodes");
                first = Some(b.id());
            }
        }
        assert_eq!(first, Some(deep), "a wider page still opens with the deepest asked id");
    }

    /// ⭐ THE TIP PULL (item 1, 2026-09-17). Run 13 measured a pair whose pushes stalled while every PULL
    /// landed: the behind node could only ever learn the peer's tip by luck. A kind-11 ask over the asker's
    /// own stream returns the peer's WITNESSED selected tip, served once per `TIP_SERVE_MIN_MS`.
    #[test]
    fn a_tip_pull_serves_the_witnessed_selected_tip_once_per_window() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_0011u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.step(Act::Produce(0, 5));
        let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        let resp = s.parties[0].serve_notes_req_bytes(&[11u8], 1_048_576);
        assert!(
            resp.len() > 13 && &resp[..9] == b"BLOCKFULL",
            "no BLOCKFULL answered ({} bytes)",
            resp.len()
        );
        let mut lb = [0u8; 4];
        lb.copy_from_slice(&resp[9..13]);
        let len = u32::from_le_bytes(lb) as usize;
        let block: crate::block::Block =
            postcard::from_bytes(&resp[13..13 + len]).expect("the served tip decodes");
        assert_eq!(block.id(), tip, "the served block is the selected tip");
        assert!(
            !block.pow_proof.is_empty(),
            "⛔ the served tip carries no witness — a puller could never trust it"
        );
        let again = s.parties[0].serve_notes_req_bytes(&[11u8], 1_048_576);
        assert!(
            again.is_empty(),
            "a second pull inside the serve window must be the empty frame ({} bytes)",
            again.len()
        );
    }

    /// A party that never received ONE of the peer's blocks (every push dropped — run 13's stalled dial)
    /// PULLS the peer's tip: the witnessed block walks the off-lock verify door, parks behind its missing
    /// parent, and that parent becomes the WANT the kind-9 descent asks for. A node lives on what it pulls.
    #[test]
    fn a_starved_node_pulls_the_peers_tip_and_its_descent_names_the_parent() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_0012u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.parties[1].set_production_paused_for_test(true);
        for _ in 0..6 {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1)); // every push to party 1 is lost
        }
        let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        let parent = s.parties[0].node().dag().get(&tip).expect("tip node").header.parents[0];
        assert!(s.parties[1].node().dag().get(&tip).is_none(), "party 1 never saw the tip");
        assert_eq!(s.parties[1].node().relay_buffered_len(), 0, "nothing parked before the pull");
        let resp = s.parties[0].serve_notes_req_bytes(&[11u8], 1_048_576);
        assert!(resp.len() > 13 && &resp[..9] == b"BLOCKFULL", "no BLOCKFULL answered");
        s.parties[1].on_pulled_tip_block(&resp[9..]);
        for _ in 0..12 {
            s.now += 500;
            s.tick(1);
            if s.parties[1].node().relay_buffered_len() > 0 {
                break;
            }
        }
        assert_eq!(
            s.parties[1].node().relay_buffered_len(),
            1,
            "⛔ the pulled, witnessed tip did not park behind its missing parent"
        );
        let wants = s.parties[1].node_mut().wanted_block_ids();
        assert!(
            wants.contains(&parent),
            "the descent's want must name the pulled tip's parent ({} want(s))",
            wants.len()
        );
        s.parties[1].set_production_paused_for_test(false);
    }

    /// ⭐ R4 — the same starved party pulls the peer's tip AS `block_part::PARTS` LANE-PARALLEL PARTS: every part is
    /// served from the block's own gossip bytes, the join lands whole through the by-id door, and the tip parks behind its
    /// missing parent exactly as a whole pull's does. Every lie lands nothing: another block's parts answered under the
    /// tip's id (they join to a block that is not the one asked for), and a part whose total disagrees with the others
    /// (the join never closes).
    #[test]
    fn r4_a_tip_pulled_in_parts_lands_whole_and_a_foreign_or_lying_part_lands_nothing() {
        use crate::block_part::{ask, PARTS};
        let mut s = RtSim::new(2, 0x0917_2026_1102_0025u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.parties[1].set_production_paused_for_test(true);
        for _ in 0..6 {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1)); // every push to party 1 is lost
        }
        let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        let parent = s.parties[0].node().dag().get(&tip).expect("tip node").header.parents[0];
        assert!(s.parties[1].node().dag().get(&tip).is_none(), "CALIBRATION: party 1 never saw the tip");
        let settle = |s: &mut RtSim| {
            for _ in 0..12 {
                s.now += 500;
                s.tick(1);
                if s.parties[1].node().relay_buffered_len() > 0 {
                    break;
                }
            }
        };
        let part = |s: &mut RtSim, of: &crate::hash::Hash32, k: u8| -> Vec<u8> {
            let page = s.parties[0].serve_notes_req_bytes(&ask(&of.0, k), 1_048_576);
            assert_eq!(&page[..8], crate::block_part::BLOCK_PART_TAG, "a part is answered under its tag");
            assert!(page.len() > 8 + 33, "the server holds the block: part {k} is not a notfound");
            page
        };
        // No tick runs until the honest parts land: the puller's own catch-up must not be what moves a block in.
        // ⛔ another block's parts under the tip's id: they join whole, to a block that is not the tip
        s.parties[1].open_block_parts_for_test(tip.0);
        for k in 0..PARTS as u8 {
            let mut page = part(&mut s, &parent, k);
            page[8..40].copy_from_slice(&tip.0);
            s.parties[1].on_block_part(&page[8..], false);
        }
        assert!(
            !s.parties[1].handed_to_verifier_for_test(&tip.0) && !s.parties[1].handed_to_verifier_for_test(&parent.0),
            "⛔ a join of ANOTHER block's parts under the tip's id reached the verifier"
        );
        // ⛔ a part whose total disagrees: that part is refused and the join stays open
        s.parties[1].open_block_parts_for_test(tip.0);
        for k in 0..PARTS as u8 {
            let mut page = part(&mut s, &tip, k);
            if k == 1 {
                let lied = u32::from_le_bytes(page[41..45].try_into().unwrap()) + 1;
                page[41..45].copy_from_slice(&lied.to_le_bytes());
            }
            s.parties[1].on_block_part(&page[8..], false);
        }
        assert!(!s.parties[1].handed_to_verifier_for_test(&tip.0), "⛔ a join with a lying part's total reached the verifier");
        // ⭐ the honest part 1 closes that join: the tip lands whole and parks behind its missing parent
        let page = part(&mut s, &tip, 1);
        s.parties[1].on_block_part(&page[8..], false);
        assert!(s.parties[1].handed_to_verifier_for_test(&tip.0), "⛔ the honest parts joined to the tip and did not reach the verifier");
        settle(&mut s);
        assert_eq!(s.parties[1].node().relay_buffered_len(), 1, "⛔ the tip pulled in parts did not park behind its missing parent");
        assert!(s.parties[1].node_mut().wanted_block_ids().contains(&parent), "the descent's want names the parent");
        s.parties[1].set_production_paused_for_test(false);
    }

    /// ⭐⭐⭐ DB-44 (2026-09-18, run 58): a child parked on a missing parent must graft once that parent
    /// lands by ANY door — here the by-id pull door (`BLOCKFULL`), which the relay's own receive-path
    /// cascade never sees. Before the sweep such children sat in the buffer until they aged out (43 in one
    /// run, every one "held WHOLE"), and every expiry fed the bundle-patience trigger.
    #[test]
    fn a_child_parked_on_a_parent_that_lands_by_the_pull_door_grafts_without_aging_out() {
        let mut s = RtSim::new(2, 0x0918_2026_0918_0044u64);
        s.arm_deadline(std::time::Duration::from_secs(300));
        s.parties[1].set_production_paused_for_test(true);
        s.step(Act::Produce(0, 1));
        s.step(Act::Deliver(1)); // block 1 shared
        s.step(Act::Produce(0, 1));
        s.step(Act::Drop(1)); // block 2 lost to party 1
        let parent = s.parties[0].node().selected_tip().expect("party 0 tip");
        s.step(Act::Produce(0, 1));
        s.step(Act::Deliver(1)); // block 3 arrives at party 1 and parks on the missing block 2
        let child = s.parties[0].node().selected_tip().expect("party 0 tip");
        // one tick ingests the child: it parks on the missing parent (the sim's hub may already be
        // answering the parent pull the park fires — the door under test is the same either way)
        let mut parked_seen = false;
        for _ in 0..4 {
            s.now += 500;
            s.tick(1);
            parked_seen |= s.parties[1].node().relay_buffered_len() > 0;
            if s.parties[1].node().dag().get(&child).is_some() {
                break;
            }
        }
        let parent_before = s.parties[1].node().dag().get(&parent).is_some();
        eprintln!("[pin] parked_seen={parked_seen} parent_already_grafted={parent_before}");
        // the parent lands by the PULL door, not the relay's receive path
        let mut req = vec![12u8];
        req.extend_from_slice(parent.as_bytes());
        let resp = s.parties[0].serve_notes_req_bytes(&req, 1_048_576);
        assert!(resp.len() > 13 && &resp[..9] == b"BLOCKFULL", "no BLOCKFULL answered ({} byte(s))", resp.len());
        s.parties[1].on_pulled_tip_block(&resp[9..]);
        for _ in 0..40 {
            s.now += 500;
            s.tick(1);
            if s.parties[1].node().dag().get(&child).is_some() {
                break;
            }
        }
        assert!(s.parties[1].node().dag().get(&parent).is_some(), "the pulled parent grafted");
        assert!(s.parties[1].node().dag().get(&child).is_some(), "the parked child grafted once its parent landed by the pull door");
        assert_eq!(s.parties[1].node().relay_buffered_len(), 0, "nothing left parked to age out");
        // DB-47: a THREE-deep strand — the grandparent lost, the parent PARKED (so the relay marks it
        // buffered), the child parked on the parent; the grandparent lands by the pull door. The parent
        // must be released, graft, and — its stale park record forgotten — release the child in turn.
        s.step(Act::Produce(0, 1));
        s.step(Act::Drop(1)); // grandparent lost
        let gp = s.parties[0].node().selected_tip().expect("tip");
        s.step(Act::Produce(0, 1));
        s.step(Act::Deliver(1)); // parent arrives, parks on the grandparent
        let p2 = s.parties[0].node().selected_tip().expect("tip");
        s.step(Act::Produce(0, 1));
        s.step(Act::Deliver(1)); // child arrives, parks on the parked parent
        let c2 = s.parties[0].node().selected_tip().expect("tip");
        for _ in 0..3 {
            s.now += 500;
            s.tick(1);
        }
        let mut req = vec![12u8];
        req.extend_from_slice(gp.as_bytes());
        let resp = s.parties[0].serve_notes_req_bytes(&req, 1_048_576);
        assert!(resp.len() > 13 && &resp[..9] == b"BLOCKFULL");
        s.parties[1].on_pulled_tip_block(&resp[9..]);
        for _ in 0..60 {
            s.now += 500;
            s.tick(1);
            if s.parties[1].node().dag().get(&c2).is_some() {
                break;
            }
        }
        assert!(s.parties[1].node().dag().get(&gp).is_some(), "the pulled grandparent grafted");
        assert!(s.parties[1].node().dag().get(&p2).is_some(), "the parked parent was released and grafted");
        assert!(s.parties[1].node().dag().get(&c2).is_some(), "the child parked on a once-parked parent grafted too");
        assert_eq!(s.parties[1].node().relay_buffered_len(), 0, "nothing left parked after a three-deep strand");
        s.parties[1].set_production_paused_for_test(false);
    }

    /// ⭐⭐⭐ DB-30 (2026-09-18, run 41): a record-ladder span is a 128 KB blob; on the PACED cell lane it was
    /// 32 cells (~0.8 s of the whole lane), shed 781 times from a stalled writer and re-asked every tick —
    /// the congestion collapse that left n0 at 279 while n1 ran to 615. It is a bulk page now: `[14][span]`
    /// → `LADDRESP ‖ span ‖ blob` for a span the peer holds sealed, the EMPTY frame otherwise (control), and
    /// the asker's adopt stays self-verifying — a blob that does not fold rung-to-rung installs nothing.
    #[test]
    fn a_ladder_span_is_served_over_the_bulk_lane_and_a_forged_one_installs_nothing() {
        let mut s = RtSim::new(2, 0x0918_2026_0918_0030u64);
        s.arm_deadline(std::time::Duration::from_secs(120));
        let span_bytes = (crate::node::Node::DA_LADDER_SPAN as usize) * crate::node::Node::LADDER_SLOT_BYTES;
        s.parties[0].node_mut().hold_ladder_span_for_test(7, vec![0x11u8; span_bytes]);
        let mut req = vec![14u8];
        req.extend_from_slice(&7u64.to_le_bytes());
        let resp = s.parties[0].serve_notes_req_bytes(&req, 1_048_576);
        assert_eq!(resp.len(), 16 + span_bytes, "LADDRESP ‖ span ‖ blob");
        assert_eq!(&resp[..8], b"LADDRESP");
        assert_eq!(&resp[8..16], &7u64.to_le_bytes());
        // control: a span this node does not hold answers the empty frame, never a fabrication
        let mut req8 = vec![14u8];
        req8.extend_from_slice(&8u64.to_le_bytes());
        assert!(s.parties[0].serve_notes_req_bytes(&req8, 1_048_576).is_empty());
        // a malformed ask (wrong width) is not a ladder ask at all
        assert!(s.parties[0].serve_notes_req_bytes(&[14u8, 7u8], 1_048_576).is_empty());
        // the asker's door: this blob is not a sealed span (it folds nowhere) — refused, nothing installed
        assert!(!s.parties[1].on_pulled_ladder_span(&resp[8..]), "a forged span blob must be refused");
        assert!(s.parties[1].node().ladder_span_blob(7).is_none(), "nothing installed on a refused blob");
    }

    /// ⭐⭐⭐ THE BATCH CATCH-UP PAGE (2026-09-18, run 26): a node eight blocks behind names its own tip and
    /// receives every body above it in ONE round trip, oldest first; after the off-lock verifier drains it
    /// stands at the peer's tip. One block per round trip could never keep up with a producer making one
    /// block a second (885 asks, 79 answers, 232 blocks behind after ten minutes). Control: a tip the peer
    /// does not hold answers the hint-less EMPTY page (DB-69: a zero anchor hint and no body — a fork falls
    /// back to the by-id and descent lanes; the page itself frees the asker's one-page slot).
    #[test]
    fn a_node_behind_by_a_page_catches_up_in_one_batch_round_trip() {
        let mut s = RtSim::new(2, 0x0918_2026_0918_0013u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.parties[1].set_production_paused_for_test(true);
        s.step(Act::Produce(0, 1));
        s.step(Act::Deliver(1)); // party 1 holds block 1 whole — its tip
        let my_tip = s.parties[1].node().selected_tip().expect("party 1 has a tip");
        for _ in 0..8 {
            s.step(Act::Produce(0, 1));
            s.step(Act::Drop(1)); // every push of the next eight is lost
        }
        let peer_tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        assert_ne!(my_tip, peer_tip);
        assert!(s.parties[1].node().dag().get(&peer_tip).is_none(), "party 1 never saw the peer's tip");
        // the locator form: a foreign id first (the peer skips it), then our tip
        let mut req = vec![13u8, 2u8];
        req.extend_from_slice(crate::hash::Hash32::hash(b"a fork tip the peer lacks").as_bytes());
        req.extend_from_slice(my_tip.as_bytes());
        req.push(16);
        let resp = s.parties[0].serve_notes_req_bytes(&req, 1_048_576);
        assert!(resp.len() > 13 && &resp[..9] == b"BLOCKBTCH", "no BLOCKBTCH answered ({} byte(s))", resp.len());
        s.parties[1].on_pulled_block_batch(&resp[9..]);
        for _ in 0..40 {
            s.now += 500;
            s.tick(1);
            if s.parties[1].node().selected_tip() == Some(peer_tip) {
                break;
            }
        }
        assert_eq!(
            s.parties[1].node().selected_tip(),
            Some(peer_tip),
            "⛔ the batch page did not bring the behind node to the peer's tip in one round trip"
        );
        let mut bad = vec![13u8, 1u8];
        bad.extend_from_slice(crate::hash::Hash32::hash(b"a tip nobody holds").as_bytes());
        bad.push(16);
        // DB-69 (run 80, 2026-09-18): a batch ask is ALWAYS answered with a BLOCKBTCH page so the asker's
        // one-page slot frees on that page and nothing else; a tip this node does not hold answers the
        // HINT-LESS EMPTY page — a zero anchor hint and no body — never a fabrication. (Before DB-69 the
        // control expected an empty frame; an empty frame of any kind used to free the slot early and the
        // peer re-served the same 32 bodies on every other page.)
        let foreign = s.parties[0].serve_notes_req_bytes(&bad, 1_048_576);
        assert_eq!(foreign.len(), 9 + 32, "a foreign tip answers the hint-less empty page, {} byte(s)", foreign.len());
        assert_eq!(&foreign[..9], b"BLOCKBTCH");
        assert!(foreign[9..].iter().all(|b| *b == 0), "the empty page carries a ZERO hint (no anchor this node holds)");
        s.parties[1].set_production_paused_for_test(false);
    }

    /// ⛔⛔⛔ ADVERSARIAL: A MALICIOUS SERVER'S PAGE OF FABRICATED, PoUW-LESS ANCESTRY.
    ///
    /// The descent lane's page-scoped trusted closure authenticates each LINK correctly — a shell
    /// is grafted only when `Block::id()`, recomputed from its own bytes, equals an id the asker
    /// already trusts, and `BlockHeader::preimage` covers the parent list — so no id can be
    /// forged. But the door that closure feeds (`Node::graft_block_shell_from_trusted_id`) checks
    /// NOTHING about proof of work: no `hash_meets_target(hasher.hash(preimage), work)`, which is
    /// the one half of `pow::verify_block_pow` that needs the HEADER ALONE and no witness. Trust
    /// therefore means "some header named this id", never "this block was mined".
    ///
    /// THE ATTACK this pin drives: an attacker fabricates a chain of shells rooted at a block the
    /// victim really holds, each claiming a huge `header.work`, and needs exactly ONE want slot to
    /// point at its tip. The Buffered arm hands that over for the price of a single mined block —
    /// `node_runtime.rs` names an orphan's DECLARED parent (attacker-chosen bytes in the orphan's
    /// header) to the block lane. The closure then walks the whole fabricated span down in one
    /// page. `Dag::ghostdag_data` sums `header.work` of the mergeset blues straight into
    /// `blue_work`, and `Dag::order_key` picks the selected tip by `(blue_work, id)`.
    ///
    /// THE LAW: a shell that carries no evidence it was mined must never enter the DAG, and
    /// nothing partial may be applied — the page is refused whole.
    ///
    /// ROOT-LAYER: the ingest door is where block ADMISSION is produced — the page loop, the
    /// trusted closure and the want slots are all consumers of that one decision, so the pin
    /// asserts at the DAG (did the fabricated id land) rather than at any lane's bookkeeping.
    /// MEASURED 2026-09-07, RED at 36.31s: `landed=true, in_dag=true` — a fabricated shell with
    /// no `pow_proof` and a grind that meets no target entered the DAG claiming work
    /// 85070591730234615865843651857942052863 against an honest tip blue_work of 295; and the
    /// refused fabricated tip taught the node to want the next fabricated id (`learned=true`).
    /// FOUR earlier runs drove the same three shells in over the hub's bulk lane and every one
    /// printed "[block-lane] 3 of 3 served shell(s) grafted" — the page closure walking two
    /// levels the node never named — then never returned from that tick (killed at 41, 28, 10
    /// and 9 minutes of 99% CPU). Source: `graft_block_shell_from_trusted_id` (node.rs) runs
    /// exactly two checks (id already held, tx-merkle) plus `Dag::add_wanted_shell` (parents
    /// present); `pow::verify_block_pow`'s step 3 `hash_meets_target(hasher.hash(&preimage),
    /// header.work)` needs the header ALONE and is called on NO shell path.
    /// MUST-STAY-GREEN: the honest-heal pins on this same lane — the page-speed descent heal, the
    /// wanted-shell parent naming, the buffered-orphan naming, and the one-round-trip block-lane
    /// answer; this pin adds no lane behaviour, it only asserts what the door refuses.

    /// COMPACT-BLOCK RELAY, the round trip in-sim (Bitcoin `inv` → `getdata`): party 0 produces and the
    /// paced lane carries only its beacon. With the sim's bulk pump STALLED, party 1 holds nothing — proof
    /// that no whole block is pushed any more — and its one by-id ask sits observable in the hub. Releasing
    /// the pump serves the block whole; party 1 grafts it with its witness. RED before the relay landed.
    #[test]
    fn a_produced_block_is_announced_and_pulled_by_id_never_pushed_whole() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_0020u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.parties[1].set_production_paused_for_test(true);
        s.bulk_delay = 1_000_000; // the pump never serves: only a PUSH could deliver the block now
        s.step(Act::Produce(0, 1));
        let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        let mut want = vec![12u8];
        want.extend_from_slice(tip.as_bytes());
        for _ in 0..6 {
            s.now += 500;
            s.tick(0); // party 0's pacing pump emits the beacon cells
            s.step(Act::Deliver(1)); // the hub releases them to party 1, which ticks and reads the beacon
        }
        assert!(
            s.parties[1].node().dag().get(&tip).is_none(),
            "⛔ the whole block reached party 1 without any pull — it is still being PUSHED"
        );
        let asks = s.hub.bulk_reqs[1].lock().unwrap().iter().filter(|a| **a == want).count();
        assert_eq!(asks, 1, "⛔ the announced block must be asked for by id exactly once: {asks}");
        s.bulk_delay = 0; // release the pump: the ask is served whole
        for _ in 0..16 {
            s.now += 500;
            s.tick(1);
            s.tick(0);
            if s.parties[1].node().dag().get(&tip).is_some() {
                break;
            }
        }
        assert!(s.parties[1].node().dag().get(&tip).is_some(), "⛔ the block pulled by id never grafted");
        assert!(
            s.parties[1].node().full_block_by_id(&tip).map_or(false, |b| !b.pow_proof.is_empty()),
            "⛔ party 1 holds the block as a shell, not whole"
        );
        s.parties[1].set_production_paused_for_test(false);
    }

    /// COMPACT-BLOCK RELAY, parent-first backfill: party 1 missed three blocks (every cell to it was
    /// dropped) and then pulls party 0's tip; the tip parks behind its missing parent and that parent is
    /// asked for BY ID at once (observable with the pump stalled); releasing the pump lands the parent whole
    /// and the parked child follows.
    #[test]
    fn a_pulled_block_parked_behind_a_missing_parent_pulls_the_parent_by_id() {
        let mut s = RtSim::new(2, 0x0917_2026_0917_0021u64);
        s.arm_deadline(std::time::Duration::from_secs(600));
        s.parties[1].set_production_paused_for_test(true);
        for _ in 0..3 {
            s.step(Act::Produce(0, 1));
            s.now += 500;
            s.tick(0);
            s.step(Act::Drop(1)); // every cell to party 1 is lost
        }
        let tip = s.parties[0].node().selected_tip().expect("party 0 has a tip");
        let parent = s.parties[0].node().dag().get(&tip).expect("tip node").header.parents[0];
        assert!(s.parties[1].node().dag().get(&tip).is_none() && s.parties[1].node().dag().get(&parent).is_none());
        let mut ask = vec![12u8];
        ask.extend_from_slice(tip.as_bytes());
        let resp = s.parties[0].serve_notes_req_bytes(&ask, 1_048_576);
        assert!(resp.len() > 13 && &resp[..9] == b"BLOCKFULL", "no BLOCKFULL for the by-id ask");
        s.bulk_delay = 1_000_000; // stall the pump so the parent ask stays observable
        s.parties[1].on_pulled_tip_block(&resp[9..]);
        let mut want_parent = vec![12u8];
        want_parent.extend_from_slice(parent.as_bytes());
        for _ in 0..12 {
            s.now += 500;
            s.tick(1);
            if s.hub.bulk_reqs[1].lock().unwrap().iter().any(|a| *a == want_parent) {
                break;
            }
        }
        assert_eq!(s.parties[1].node().relay_buffered_len(), 1, "⛔ the pulled tip did not park behind its missing parent");
        let asks = s.hub.bulk_reqs[1].lock().unwrap().iter().filter(|a| **a == want_parent).count();
        assert_eq!(asks, 1, "⛔ the missing parent must be pulled by id exactly once: {asks}");
        s.bulk_delay = 0;
        for _ in 0..24 {
            s.now += 500;
            s.tick(1);
            s.tick(0);
            if s.parties[1].node().dag().get(&tip).is_some() {
                break;
            }
        }
        eprintln!("[pin-diag] parked pairs at the end: {}", s.parties[1].node().relay_buffered_for_test().len());
        assert!(
            s.parties[1].node().full_block_by_id(&parent).map_or(false, |b| !b.pow_proof.is_empty()),
            "⛔ the parent pulled by id never landed whole (in the DAG: {}, unfolded entry: {:?}, tip in DAG: {})",
            s.parties[1].node().dag().get(&parent).is_some(),
            s.parties[1].node().full_block_by_id(&parent).map(|b| b.pow_proof.len()),
            s.parties[1].node().dag().get(&tip).is_some()
        );
        assert!(s.parties[1].node().dag().get(&tip).is_some(), "⛔ the parked child was not released by its parent");
        s.parties[1].set_production_paused_for_test(false);
    }

    /// The by-id lane answers ONLY from the live window it holds unfolded: an unknown id gets the empty
    /// frame, never a fabrication.
    #[test]
    fn the_by_id_lane_answers_nothing_for_a_block_it_does_not_hold() {
        let mut s = RtSim::new(1, 0x0917_2026_0917_0022u64);
        s.step(Act::Produce(0, 1));
        let mut ask = vec![12u8];
        ask.extend_from_slice(&[0xABu8; 32]);
        let resp = s.parties[0].serve_notes_req_bytes(&ask, 1_048_576);
        assert!(resp.is_empty(), "⛔ a by-id ask for an unheld block was answered with {} byte(s)", resp.len());
    }
    /// TWO INDEPENDENT RUNTIME NODES on one shared tip — the starting state every door pin below
    /// attacks. Party 0 is the honest peer that never sees the fabrication; party 1 is the victim
    /// whose door is driven. Returns `(sim, shared tip, that tip's header, its honest blue_work)`.
    ///
    /// The verdict is read ACROSS THE BOUNDARY: each pin asserts that the victim's fork choice
    /// still agrees with the untouched peer's after the attack. That disagreement is what a
    /// takeover produces, and no single node can observe it about itself.
    fn produced_pair_on_one_tip(
        seed: u64,
    ) -> (RtSim, crate::block::BlockId, crate::block::BlockHeader, u128) {
        let mut s = RtSim::new(2, seed);
        s.arm_deadline(std::time::Duration::from_secs(300));
        for a in [Act::Produce(0, 3), Act::Drain] {
            s.step(a);
        }
        let peer_tip = s.parties[0].node().selected_tip().expect("honest peer tip");
        let victim_tip = s.parties[1].node().selected_tip().expect("victim tip");
        assert_eq!(
            peer_tip, victim_tip,
            "the two parties did not reach one tip before the attack — the pin's premise is gone"
        );
        let n = s.parties[1]
            .node()
            .dag()
            .get(&victim_tip)
            .expect("the victim holds the shared tip");
        let header = n.header.clone();
        let honest_work = n.blue_work;
        (s, victim_tip, header, honest_work)
    }

    /// ⛔⛔⛔ ADVERSARIAL: A FOLD CARRY'S *ANCESTOR* SHELL, FABRICATED AND PoUW-LESS.
    ///
    /// The sibling of `a_forged_powless_ancestry_page_is_refused_by_the_descent_door`, one door
    /// over. `Node::graft_unfolded_carry` installs a carry's `ancestors` through
    /// `Dag::add_ancestor_anchor`, which takes `blue_work` and `blue_score` AS PARAMETERS from the
    /// wire and constructs a `BlockNode` from them — one of the five literal `BlockNode{..}` sites
    /// in `dag.rs`, and therefore one of the five ways a `blue_work` the fork choice reads is
    /// created. That door ran NO proof-of-work check: the carry's soundness rested entirely on the
    /// #29 decider proof binding `chain_acc` (`FoldCarry::digest` → `sync::sync_binding`), i.e. on
    /// a check that lives in a DIFFERENT module and answers a DIFFERENT question — the frozen-door
    /// law says a door carries its own admission.
    ///
    /// THE LAW: the same law the descent pin states, at the carry door — a block that carries no
    /// evidence it was mined never becomes a `BlockNode`, whatever lane brought it.
    /// ROOT-LAYER: asserts at the DAG (did the fabricated id land) and across the two parties (do
    /// their fork choices still agree), never at a lane's bookkeeping.
    /// MUST-STAY-GREEN: the honest carry paths — both rolling-restart pins (a restore's own carry
    /// is real mined headers), the canonical-record-fold suite, honest_schedule_seed_3.
    #[test]
    fn a_forged_powless_carry_ancestor_is_refused_by_the_fold_carry_door() {
        let (mut s, shared_tip, real, honest_work) =
            produced_pair_on_one_tip(0x0907_2026_0907_0a5eu64);

        // An ancestor shell is installed with NO parent link required (`selected_parent: None` at
        // this call site), so nothing structural stands between the wire bytes and a `BlockNode`.
        let forged = forged_powless_block_on(&real, shared_tip, 7);
        let forged_id = forged.id();
        let carry = crate::sync::FoldCarry {
            ancestors: vec![(forged, u128::MAX / 2, 9_999_999)],
            ..Default::default()
        };
        s.parties[1].node_mut().graft_unfolded_carry(carry);
        let claimed = match s.parties[1].node().dag().get(&forged_id) {
            Some(n) => n.blue_work, // it landed: the weight the fork choice would now read
            None => 0,              // refused: nothing to read
        };
        let landed = s.parties[1].node().dag().get(&forged_id).is_some();
        let victim_tip = s.parties[1].node().selected_tip();
        let peer_tip = s.parties[0].node().selected_tip();
        assert!(
            !landed && victim_tip == peer_tip,
            "a FABRICATED, PoUW-less ANCESTOR entered the DAG through the fold-carry door \
             (in_dag={landed}) with blue_work {claimed} against the honest tip's {honest_work} — \
             it carries no `pow_proof` and its grind meets no target, and `add_ancestor_anchor` \
             took its weight straight off the wire. The victim's tip is {victim_tip:?} against the \
             untouched peer's {peer_tip:?}."
        );
    }

    /// ⛔⛔⛔ ADVERSARIAL: A FOLD CARRY'S *UNFOLDED* BLOCK, FABRICATED AND PoUW-LESS.
    ///
    /// The second `BlockNode` site `Node::graft_unfolded_carry` writes: `Dag::add_carried_block`,
    /// which likewise takes `(blue_work, blue_score)` from the wire, links the block's parents,
    /// and puts it in `tips` — so a fabricated carried block becomes a TIP CANDIDATE the fork
    /// choice ranks by `Dag::order_key`. Its one structural requirement is that every parent is
    /// already present, which an attacker satisfies for free by naming a block the victim holds.
    ///
    /// THE LAW / ROOT-LAYER / MUST-STAY-GREEN: as the ancestor pin above.
    #[test]
    fn a_forged_powless_carried_block_is_refused_by_the_fold_carry_door() {
        let (mut s, shared_tip, real, honest_work) =
            produced_pair_on_one_tip(0x0907_2026_0907_0b6fu64);

        // Parent = a block both parties really hold, so `add_carried_block`'s parents-present
        // check passes and only a proof-of-work check can refuse it.
        let forged = forged_powless_block_on(&real, shared_tip, 11);
        let forged_id = forged.id();
        let carry = crate::sync::FoldCarry {
            unfolded: vec![(forged, u128::MAX / 2, 9_999_999)],
            ..Default::default()
        };
        s.parties[1].node_mut().graft_unfolded_carry(carry);
        let landed = s.parties[1].node().dag().get(&forged_id).is_some();
        let victim_tip = s.parties[1].node().selected_tip();
        let peer_tip = s.parties[0].node().selected_tip();
        assert!(
            !landed && victim_tip == peer_tip,
            "a FABRICATED, PoUW-less CARRIED block entered the DAG through the fold-carry door \
             (in_dag={landed}); the victim's tip is now {victim_tip:?} against the untouched \
             peer's {peer_tip:?} (honest blue_work {honest_work}). `add_carried_block` takes the \
             weight off the wire and puts the block in `tips`, so the fabrication is a tip \
             candidate the moment it lands."
        );
    }

    /// ⛔⛔⛔ ADVERSARIAL: A FABRICATED, PoUW-LESS *ANCHOR* — the heaviest door of the five.
    ///
    /// `Dag::add_anchor` is the #29 DSYNC / restore trust-root install: on a `(blue_work, id)` win
    /// it CLEARS `tips` and makes the anchor the sole selected tip, with no parent required and no
    /// ancestry replayed. `Node::admit_anchor_block` is the door in front of it; before this round
    /// nothing on that path asked whether the anchor block was mined.
    ///
    /// THE LAW: an unmined header must not become a trust root. ROOT-LAYER: the assertion is on
    /// the DAG and on the two parties' fork choices, because a takeover here is total — every
    /// other tip is discarded by construction.
    /// SCOPE, stated so the next reader does not over-read the green: the grind binds
    /// `header.work` — the figure GHOSTDAG sums — and NOT the accumulated `blue_work` PARAMETER
    /// this door also takes. That parameter's binding belongs to `sync::sync_binding` on the adopt
    /// path and to the snapshot on the restore path; it is a different question with a different
    /// owner. This pin closes the grind half of the door.
    /// MUST-STAY-GREEN: the restore/adopt paths that install REAL mined tips — both rolling-restart
    /// pins, the persist door tests, the divergent-root adoption tests.
    #[test]
    fn a_forged_powless_anchor_is_refused_by_the_adopt_door() {
        let (mut s, shared_tip, real, honest_work) =
            produced_pair_on_one_tip(0x0907_2026_0907_0c7du64);

        let forged = forged_powless_block_on(&real, shared_tip, 13);
        let forged_id = forged.id();
        let installed = s.parties[1]
            .node_mut()
            .admit_anchor_block(forged, u128::MAX / 2, 9_999_999);
        let landed = s.parties[1].node().dag().get(&forged_id).is_some();
        let victim_tip = s.parties[1].node().selected_tip();
        let peer_tip = s.parties[0].node().selected_tip();
        assert!(
            !installed && !landed && victim_tip == peer_tip,
            "a FABRICATED, PoUW-less ANCHOR was installed as a trust root \
             (installed={installed}, in_dag={landed}); the victim's tip is now {victim_tip:?} \
             against the untouched peer's {peer_tip:?} (honest blue_work {honest_work}). \
             `add_anchor` clears the tip set on a weight win, so an unmined anchor is a complete \
             takeover of the fork choice."
        );
    }

    /// ⭐ THE RECORD-KEY INDEX AGREES WITH THE FULL SCAN IT REPLACED — TWO REAL RUNTIMES, ACROSS
    /// PRODUCE AND INGEST.
    ///
    /// `Node::block_for_record_addr` answers "which block does record-address X belong to" — a
    /// question consensus reads (`block_declares_no_notes` turns it into "this row IS an idle
    /// record"). It used to allocate and scan a Vec of EVERY block id per call; it is now one read
    /// of [`crate::dag::Dag::record_key_index`]. This pin holds the index to the SCAN's answer on
    /// the two block-store write lanes both parties share through their real runtime paths — each
    /// party's own production, and gossip ingest of the peer's blocks — and then holds the two
    /// PARTIES to each other, because a fast wrong answer that differs per node is how two honest
    /// nodes split.
    ///
    /// ⛔ THE SNAPSHOT-ADOPT (Restart → `add_anchor`) LANE IS DELIBERATELY NOT DRIVEN HERE. It is a
    /// third insert site, but a restart-against-a-live-peer schedule additionally exercises the OPEN
    /// certified-reanchor / restart-mid-jump fold item (`fold-stuck`; the both-restart pin below
    /// documents it), whose many full `drain` passes make such a schedule run for minutes. The adopt
    /// lane's own index maintenance is covered structurally: the `dag.rs` sibling drives
    /// `add_anchor`-shaped bulk inserts across the prune, and both rolling-restart pins below run the
    /// restart/adopt path and assert convergence. This pin isolates the produce+ingest agreement,
    /// which quiesces in seconds.
    ///
    /// ROOT-LAYER: the index is maintained at `Dag::insert_block`, the one door every insert lane
    /// shares — this pin drives the two runtime lanes rather than asserting at any single reader.
    /// The insert+prune lanes are owned by the `dag.rs` sibling pin
    /// (`the_record_key_index_agrees_with_a_full_scan_across_insert_and_prune`).
    /// MEASURED: RED run 2026-09-06 — with `insert_block` filing nothing, the dag.rs sibling under
    /// the same mutation reached the agreement assert directly: None vs Some over 590 held blocks,
    /// the key named (`block_for_record_key` answered None for a key with exactly one holder). This
    /// runtime pin's own RED is the same class one layer up: a party's indexed lookup disagreeing
    /// with its own held-block scan.
    /// MUST-STAY-GREEN: the recorded runtime-backend cases, both rolling-restart pins, and the
    /// dag.rs insert+prune sibling.
    /// cons: none on any production path — the quadratic reference scan below is TEST-ONLY and
    /// bounded by this fixed schedule (~7 driven blocks + genesis per party ⇒ ≤ 8×8 = 64 key
    /// comparisons per party, once, at quiescence); the node-side lookup it checks is one indexed
    /// read.
    #[test]
    fn the_record_key_index_agrees_with_a_full_scan_on_both_parties_across_produce_and_ingest() {
        let mut s = RtSim::new(2, 0x0906_2026_0906_0001u64);
        // PRODUCE + INGEST, BOUNDED — no `drain()`. `drain()`'s live phase lets both parties keep
        // mining for up to 240 rounds ("exactly as a live mesh does"), so any schedule that calls it
        // accumulates hundreds of blocks: a `drain`-based draft of this pin ran past 10 minutes with
        // the fold counter at 454, none of it an index cost. This claim needs no convergence — only
        // that each party HOLD blocks written through its two `Dag::insert_block` lanes (own produce,
        // peer ingest) and answer `block_for_record_key` for them as a full scan would. So the drive
        // is fixed: each side produces, repeated bursts release everything held so the peer grafts it,
        // and a funded receive adds a real-note block. The burst repeats are gossip-propagation rounds
        // (a fixed handful), NOT a cover/nullifier build — the block cover width is the production
        // constant the node applies inside `produce`.
        for a in [
            Act::Produce(0, 3),
            Act::Produce(1, 3),
            Act::Burst(1),
            Act::Burst(1),
            Act::Burst(1),
            Act::Burst(1),
            Act::Receive(0),
            Act::Burst(1),
            Act::Burst(1),
            Act::Burst(1),
            Act::Burst(1),
        ] {
            s.step(a);
        }
        for i in 0..s.parties.len() {
            let p = s.parties[i].node();
            let held = p.dag().block_ids();
            assert!(
                held.len() > 4,
                "setup: party {i} holds only {} block(s) — the lanes this pin drives were not \
                 exercised",
                held.len()
            );
            for id in &held {
                let key = crate::dag::Dag::record_key(id);
                // THE OLD DERIVATION, verbatim in shape: a linear scan of every held id. Unique
                // holder ⇒ that block; collision ⇒ the index answers None by design (fail-closed
                // where the old scan answered whichever colliding block iteration reached first).
                let holders = held.iter().filter(|x| crate::dag::Dag::record_key(x) == key).count();
                let expect = if holders == 1 { Some(*id) } else { None };
                assert_eq!(
                    p.dag().block_for_record_key(key),
                    expect,
                    "party {i}: key {key:#x} — the index disagrees with the full scan over {} held \
                     blocks ({holders} holder(s) of this key)",
                    held.len()
                );
            }
            // THE BOUND, stated and asserted: the index files exactly the blocks the store holds —
            // it mirrors the DAG's own prune-bounded store and adds no growth axis of its own.
            let (distinct, filed) = p.dag().record_key_index_census();
            assert_eq!(
                filed,
                p.dag().len(),
                "party {i}: the index files {filed} blocks but the store holds {} — the two \
                 structures drifted",
                p.dag().len()
            );
            assert!(
                distinct <= p.dag().len(),
                "party {i}: {distinct} distinct keys over {} blocks — an entry outlived its block",
                p.dag().len()
            );
        }
        // AND THE PARTIES AGREE WITH EACH OTHER on every block both hold — the per-node-different
        // answer is the split the old scan's arbitrary collision pick could have produced.
        let held0 = s.parties[0].node().dag().block_ids();
        for id in &held0 {
            if s.parties[1].node().dag().get(id).is_none() {
                continue; // only blocks BOTH parties hold can be required to answer identically
            }
            let key = crate::dag::Dag::record_key(id);
            assert_eq!(
                s.parties[0].node().dag().block_for_record_key(key),
                s.parties[1].node().dag().block_for_record_key(key),
                "the two parties answer key {key:#x} differently for a block both hold"
            );
        }
    }

    /// ⭐ ADJACENT DEFECT (a) OF THE 2026-09-05 GATE — ONE ROUND TRIP RETIRES THE WANT.
    ///
    /// The gate's freeze was not slow healing, it was a want that could never retire: the fold named
    /// a missing BLOCK, the ask went out on the by-block-id lane, and the answer was that block's DA
    /// RECORD. `wanted_block_ids` drains only when the DAG holds the BLOCK, so every 2s the same
    /// three ids were re-asked and the same three 885,644-byte records were re-served — forever.
    ///
    /// ROOT-LAYER: the defect lived in WHAT THE SERVE RETURNS, so the pin is on the serve/ingest
    /// pair, not on any timer: one ask, one answer, and the slot must be gone. A pin that allowed
    /// N round trips would pass on the very re-ask loop that froze the gate.
    /// MEASURED 2026-09-05 (scratch /tmp/musd-ecocheck-D6U9H2): 41 record re-serves x 885,644 bytes
    /// (~36 MB in ~6.5 min) against 3 wants that never retired, saturating all four bulk lanes to
    /// the only peer; in-process the pre-fix tree logged 5,031 `[block-id-serve] answering 3 …
    /// 885,504 byte(s)` re-serves in a single run.
    /// MEASURED HERE: the 7u8 answer is a header+tx_ids shell — asserted under 64 KiB against the
    /// ~885 KB record page it replaces — and after exactly ONE ask/answer the DAG holds the block
    /// and the slot is free.
    /// MUST-STAY-GREEN: the recorded runtime-backend cases and
    /// `rolling_restart_pair_heals_fold_block_wants_and_missing_records` (the whole-lane pin); this
    /// one isolates the single exchange inside it.
    /// RED before the fix: the ask carried 1u8, the answer was a `LedgerRecord` page with no
    /// BLOCKPAGE magic, `on_block_page` never ran, and the slot still named the block after the tick.
    #[test]
    fn a_block_lane_answer_grafts_the_block_and_drains_its_slot_in_one_round_trip() {
        let mut s = RtSim::new(2, 0x0511_2026_0905_0007u64);
        // A converged pair, then ONE block party 0 never hears — the exact shape a restart leaves:
        // an id chain structure names and this DAG does not hold.
        s.step(Act::Produce(0, 2));
        s.step(Act::Drain);
        assert_eq!(
            s.parties[0].node().selected_tip(),
            s.parties[1].node().selected_tip(),
            "fixture: the pair must stand on ONE tip before party 1 extends it — otherwise the block party 0 \
             lacks is not one block but a span, and this pin measures a page, not a slot"
        );
        s.step(Act::Produce(1, 1));
        s.step(Act::Drop(0));
        let missing = s.parties[1]
            .node()
            .selected_tip()
            .expect("party 1 stands on the tip it just produced");
        let missing_parents: Vec<_> = s.parties[1].node().dag().get(&missing).map(|n| n.header.parents.clone()).unwrap_or_default();
        for p in &missing_parents {
            assert!(
                s.parties[0].node().dag().get(p).is_some(),
                "fixture: party 0 must hold every parent of the one block it lacks ({p:?} is absent)"
            );
        }
        assert!(
            s.parties[0].node().dag().get(&missing).is_none(),
            "the fixture is only meaningful while party 0 LACKS the block — it holds it already"
        );
        // C1's wait names the block, the same call `fold_canonical_records` makes.
        s.parties[0].node_mut().want_block_by_id(missing);
        assert!(
            s.parties[0].node().wants_block(&missing),
            "the fold's wait must register the block before the lane can be pinned"
        );
        // ── THE ONE ROUND TRIP, on the lane's own wire: the request the requester builds, the
        // serve serve.rs installs, the response door the drain routes to.
        let mut req = Vec::with_capacity(33);
        req.push(7u8);
        req.extend_from_slice(missing.as_bytes());
        let page = s.parties[1].serve_notes_req_bytes(&req, 1_048_576);
        assert!(
            page.len() > 13 && &page[..9] == b"BLOCKPAGE",
            "the block lane must answer a named block with the BLOCK — a record page can never \
             retire the want (got {} byte(s))",
            page.len()
        );
        assert!(
            page.len() < 64 * 1024,
            "a block-want answer must not cost a record page: {} byte(s) served where the measured \
             record answer was 885,644",
            page.len()
        );
        s.hub.bulk_resp[0].lock().unwrap().push_back(page);
        // The answer lands through the drain and the shell grafts on the tick that consumes it; a body
        // pulled by id walks the off-lock verifier and applies on the tick after. Since 2026-09-18 the
        // lane's own ask also goes out on its 2 s cadence, so the hub may answer once more — the LAW is
        // that the block lands within a bounded handful of ticks and the want retires by the LANDING,
        // never a 2 s re-ask loop (measured 2026-09-19: one tick consumed the page but the graft landed
        // on the next).
        let mut ticks = 0usize;
        while s.parties[0].node().dag().get(&missing).is_none() {
            ticks += 1;
            assert!(
                ticks <= 12,
                "one answered ask must LAND the block in the DAG within a handful of ticks — that is the \
                 only thing that retires a C1 want ({ticks} tick(s), still absent)"
            );
            s.now += 2_100;
            s.tick(0);
        }
        eprintln!("[pin] the named block landed after {ticks} extra tick(s)");
        let still = s.parties[0].node_mut().wanted_block_ids();
        assert!(
            !still.contains(&missing),
            "the slot must be free after ONE round trip — {} want(s) still live, which is the 2s \
             re-ask loop that froze the gate",
            still.len()
        );
    }

    /// MEASURE the light decider's proving time (what every sync-serving node pays per tip change).
    #[test]
    #[ignore]
    fn diag_light_decider_proof_time() {
        let acc: [u8; 16] = [7u8; 16];
        for k in 0..3u8 {
            let mut a = acc;
            a[0] = k;
            let t = std::time::Instant::now();
            let p = crate::whir_decider::decider_prove_light(&a);
            eprintln!("PROOF {k}: {} ms, {} bytes", t.elapsed().as_millis(), p.map(|v| v.len()).unwrap_or(0));
        }
    }




    /// ⛔⭐⭐⭐ THE GATE'S STEP 3, IN PROCESS — A DIAGNOSIS LOOP THAT COSTS SECONDS INSTEAD OF 8 MINUTES.
    ///
    /// ⛔ WHY THIS EXISTS. Three files cite
    /// `rolling_restart_pair_heals_fold_block_wants_and_missing_records` as if it were a pin. It has
    /// ONE occurrence in the whole tree and it is a comment: **the test was never written**. So the only
    /// way to observe a rolling-restart backfill has been `ecosystem-check.sh`, at ~8 minutes per
    /// sample — and step 3 has at least THREE failure modes (single-row poison, mutual-dependency
    /// deadlock, post-restart balance 0.0), so every hypothesis costs several samples to test. MEASURED
    /// 2026-09-25: twelve gate runs, ~96 minutes, of which ~64 minutes measured a STALE BINARY (DB-208).
    /// That is the dominant cost of closing criteria 6, 7, 8 and 11, and it is a tooling cost, not a
    /// chain one.
    ///
    /// The harness already had everything: `RtSim` boots real `NodeRuntime`s over a simulated hub, and
    /// `restart()` clears the checkpoint and reboots a party from its own snapshot through the real
    /// `restore_snapshot` path. Only the scenario was missing.
    ///
    /// ⛔ TRIPWIRE, deliberately: it asserts TODAY'S MEASURED BEHAVIOUR (the restarted party does NOT
    /// finish its DA backfill), for the reason DB-193's tripwire states — a permanently-red test is
    /// noise, while a passing test that pins a launch blocker is a standing claim the blocker is still
    /// there. The numbers are PRINTED every run, which is what makes this a diagnosis loop rather than a
    /// yes/no. When the backfill completes this goes RED, and whoever fixed it must flip the assertion
    /// to `missing == 0 && ready` — which is exactly criterion 7's step 3, and closing it in process is
    /// how the 8-minute loop stops being the bottleneck.
    #[test]
    fn a_restarted_party_does_not_finish_its_da_backfill_the_gate_step_3_in_process() {
        let mut s = RtSim::new(2, 0x0925_2026_0925_0031u64);
        s.arm_deadline(std::time::Duration::from_secs(600));

        // ⛔ THE DEFICIT MUST BE REAL OR THIS PROVES NOTHING. My first cut produced with both parties
        // connected, so party 1 already held every record and the reading was `missing_records 0 -> 0`:
        // an assertion that could not have gone the other way, which is the DB-211 defect committed twice
        // in one session. Party 1 is PARTITIONED while the chain advances, so it genuinely owes records
        // before it is restarted — that debt is the precondition the whole scenario is about.
        s.parties[1].set_production_paused_for_test(true);
        for _ in 0..12 {
            s.step(Act::Produce(0, 1));
            s.now += 500;
            s.tick(0);
            s.step(Act::Drop(1)); // party 1 hears nothing: it falls behind on blocks AND records
        }
        // Heal the partition and let party 1 LEARN it is behind. `missing_record_count` is
        // RANGE-DERIVED (certified position minus cursor), so a party that has not yet heard a certified
        // position reports 0 debt however far behind it actually is — measuring before it re-meshes is
        // how the first cut got its vacuous `0 -> 0`. Drive until it reports a deficit, then stop.
        let mut before = 0usize;
        for _ in 0..80 {
            s.now += 500;
            s.tick_all();
            before = s.parties[1].node().missing_record_count();
            if before > 0 {
                break;
            }
        }
        let ready_before = s.parties[1].node().serve_ready();
        // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT and a boolean over this party's own catch-up state.
        // Never a record id, ordinal, commitment, note, amount, key or owner.
        eprintln!(
            "[step3-repro] after a 12-round partition + up to 80 heal rounds: missing_records={before}, serve_ready={ready_before}"
        );

        // ⛔⛔⛔ WHAT THIS ESTABLISHES IS NOT WHAT I SET OUT TO BUILD, AND IT IS WORTH MORE.
        //
        // The intent was a seconds-fast reproduction of the gate's step 3, so the ~8-minute diagnosis
        // loop would stop being the bottleneck on criteria 6/7/8/11. It is not one — because the
        // in-process harness CANNOT EVEN CREATE THE PRECONDITION. Twelve rounds fully partitioned plus
        // up to eighty heal rounds leave party 1 owing ZERO records, while the real gate's restarted
        // node sits at a saturated want set for its entire run.
        //
        // `missing_record_count` is RANGE-DERIVED (certified position minus cursor, plus by-id wants), so
        // what this measures is that the simulated hub never puts a party in the state the gate
        // reproduces every single time: behind on RECORDS, not merely on blocks. **That gap is why step 3
        // has never been caught in process**, and closing it is the prerequisite for any fast loop here.
        //
        // Pinned as today's measured truth rather than left permanently red (DB-193's rule). The day the
        // harness models DA debt this goes RED, and whoever made it do so should finish the job:
        // `s.restart(1)`, drive ticks, and assert the backfill COMPLETES.
        assert_eq!(
            before, 0,
            "⛔ THE HARNESS NOW ACCRUES A REAL DA RECORD DEFICIT ({before} records) — the precondition \
             the gate reproduces and this sim never could. Finish it: `s.restart(1)`, drive ticks, then \
             assert `missing_record_count() == 0 && serve_ready()`. That is criterion 7's step 3 in \
             process, at seconds per sample instead of eight minutes."
        );
    }
}

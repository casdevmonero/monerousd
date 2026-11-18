// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ DB-350 — THE RECORD ASK NEVER NAMES A COMMITMENT.
//!
//! A wallet that could not prove its note's membership used to post `/want_note_record {cm_hex}` to its node,
//! and the node put `[3] ‖ cm` on the wire to a peer: "this node's wallet owns commitment X". Nothing else on
//! the network names an input's commitment — a spend publishes a nullifier and the RECORD that holds its input
//! (`PqTx::membership_tip`, filed open), never the note — so that ask was the one surface that joined a node,
//! and its onion, to one specific note, and through the note's block to the payment that created it.
//!
//! It was also redundant. A record fetched by commitment is admitted only if this node already PLACES it
//! (`accept_fetched_record` refuses an unplaced record — DB-227), and a placed record with no bytes is already
//! wanted BY ITS PUBLIC ADDRESS: the wallet's own `/note_copath` read at `(record, slot)` reaches
//! `da_record_reals`, whose miss arm raises the by-id want (kind 2). DB-350 deletes the lane at source.
//!
//! TWO PARTIES in every pin. `peer` produced the records and answers what it receives; the wallet's node is a
//! real `NodeRuntime` whose transport hands every outbound byte string to the peer — bulk asks as sent, and
//! cells reassembled by the node's own `Reassembler` and decoded by `WireMsg::from_wire`, so an ask that falls
//! back to the paced cell lane is read exactly as the peer would read it. Every assertion is about what the
//! PEER RECEIVED, never about what a call returned.
//!
//! What the pins prove, and what they do not:
//! * no byte string the wallet's node sends carries the owned commitment or its leaf encodings — on the bulk lane
//!   and on the cell lane, in both states a node can miss a record in: grafted without its payload (the wire
//!   shape since DB-165), and placed by a sidecar row alone (a jumped span);
//! * the asks are the same whichever note of a record the wallet owns (X and Y share record R);
//! * across records (X in R, Z in R') the asks differ ONLY in the 8-byte record address when nothing owed either
//!   record before the wallet asked. That residual is the spend-time record linkage filed open in the privacy
//!   census as `Ask::record_by_id`, beside `PqTx::membership_tip`, which names the same record to every node
//!   when the spend is published; DB-223's record-free membership leg closes both;
//! * a stale peer's kind-3 bytes are answered with nothing, and the route that raised them is gone.
//!
//! cons: none — a fixed two-block, two-party fixture; nothing here scales with the chain.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::block::Block;
    use crate::hash::Hash32;
    use crate::net::{NetError, Reassembler};
    use crate::node::Node;
    use crate::node_runtime::NodeRuntime;
    use crate::protocol::WireMsg;
    use crate::relay::RelayOutcome;
    use crate::transport::CellTransport;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const NOTE: usize = crate::cover::PQ_NOTE_BYTES;
    /// The bulk lane's page budget: the transport's ~1 MiB, inside the 1.8 MB pillar.
    const PAGE_BUDGET: usize = 1 << 20;
    /// Ticks the wallet's node runs after the miss, each 3.5 s apart — past the 3 s pace of every paced ask, so an
    /// ask that would go out does go out. A fixed fixture constant, never a term in history.
    const TICKS: u64 = 24;
    const TICK_MS: u64 = 3_500;

    /// A note shaped like a sealed one: its commitment in front, high-entropy bytes behind it, so "the commitment
    /// is not on the wire" is tested against bytes that cannot match by chance.
    fn sealed(tag: &[u8]) -> Vec<u8> {
        let mut n = Hash32::hash(tag).as_bytes().to_vec();
        let mut ctr = 0u64;
        while n.len() < NOTE {
            let mut pre = tag.to_vec();
            pre.extend_from_slice(&ctr.to_le_bytes());
            n.extend_from_slice(Hash32::hash(&pre).as_bytes());
            ctr += 1;
        }
        n.truncate(NOTE);
        n
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// One owned note: its commitment, the canonical record address that holds it, and its served slot.
    #[derive(Clone, Copy, Debug)]
    struct Owned {
        cm: [u8; 32],
        rid: u64,
        slot: u8,
    }

    /// The peer's own transport. The pins read what the peer RECEIVES, so it sends nothing anywhere.
    struct Deaf;
    impl CellTransport for Deaf {
        fn send_cell(&self, _cell: Vec<u8>) -> Result<(), NetError> {
            Ok(())
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            None
        }
    }

    type Peer = Arc<Mutex<NodeRuntime<Deaf>>>;

    /// The peer produced two records: R holds X and Y, R' holds Z.
    struct Fixture {
        peer: Peer,
        blocks: Vec<Block>,
        /// `(the peer's ordinal, record address)` for R and R' — what a sidecar page hands a jumped node.
        rows: Vec<(u64, u64)>,
        x: Owned,
        y: Owned,
        z: Owned,
    }

    fn fixture() -> Fixture {
        let mut a = crate::node::tests::testnet_party_folding_at_tip();
        let (nx, ny, nz) = (sealed(b"db350-note-x"), sealed(b"db350-note-y"), sealed(b"db350-note-z"));
        let (b1, r) = a.carry_notes_in_a_block_for_test(5_000, &[nx.clone(), ny.clone()].concat());
        let (b2, r2) = a.carry_notes_in_a_block_for_test(6_000, &nz);
        assert_ne!(r, r2, "PRECONDITION: two blocks, two records");
        let owned = |a: &Node, note: &[u8], rid: u64| -> Owned {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&note[..32]);
            let slot = a
                .da_record_notes(rid)
                .expect("PRECONDITION: the peer holds its own record")
                .chunks(NOTE)
                .position(|c| c[..32] == cm)
                .expect("PRECONDITION: the note sits in its record");
            Owned { cm, rid, slot: slot as u8 }
        };
        let (x, y, z) = (owned(&a, &nx, r), owned(&a, &ny, r), owned(&a, &nz, r2));
        let rows = [r, r2]
            .iter()
            .map(|rid| (a.da_record_ordinal(*rid).expect("PRECONDITION: the peer placed its record"), *rid))
            .collect();
        Fixture { peer: Arc::new(Mutex::new(NodeRuntime::new(a, Deaf))), blocks: vec![b1, b2], rows, x, y, z }
    }

    /// What the peer RECEIVED from the wallet's node, in order: every ask (`"ask"` — a bulk request as sent, or a
    /// `NotesReq` reassembled from cells), every other reassembled message (`"msg"`, its wire bytes) and every raw
    /// cell (`"cell"`).
    #[derive(Clone, Default)]
    struct Received(Arc<Mutex<Vec<(&'static str, Vec<u8>)>>>);
    impl Received {
        fn push(&self, what: &'static str, bytes: &[u8]) {
            self.0.lock().unwrap().push((what, bytes.to_vec()));
        }
        fn all(&self) -> Vec<(&'static str, Vec<u8>)> {
            self.0.lock().unwrap().clone()
        }
        fn asks(&self) -> Vec<Vec<u8>> {
            self.all().into_iter().filter(|(w, _)| *w == "ask").map(|(_, b)| b).collect()
        }
    }

    /// Which lane the wallet's node has to its peer: the bulk lane (a production onion link), or the paced cell
    /// lane alone (a link with no bulk lane — every ask falls back to a `NotesReq` message in cells).
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Lane {
        Bulk,
        CellOnly,
    }

    /// The wallet's node's link, whose far end is the peer. On the bulk lane the peer answers the RECORD asks
    /// (kinds 0-3) exactly as its serve dispatcher answers them; every other ask is recorded as received and left
    /// unanswered — bundles, blocks and follows are not this surface.
    struct LinkToPeer {
        lane: Lane,
        received: Received,
        peer: Peer,
        answers: Mutex<VecDeque<Vec<u8>>>,
        cells: Mutex<Reassembler>,
    }
    impl CellTransport for LinkToPeer {
        fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
            self.received.push("cell", &cell);
            if let Ok(Some(wire)) = self.cells.lock().unwrap().accept(&cell) {
                match WireMsg::from_wire(&wire) {
                    Some(WireMsg::NotesReq(req)) => self.received.push("ask", &req),
                    _ => self.received.push("msg", &wire),
                }
            }
            Ok(())
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            None
        }
        fn has_bulk_lane(&self) -> bool {
            self.lane == Lane::Bulk
        }
        fn bulk_raw_request(&self, req: &[u8]) -> bool {
            if self.lane != Lane::Bulk {
                return false; // no bulk lane: nothing was sent, and the caller falls back to cells
            }
            self.received.push("ask", req);
            if req.len() != 12 && matches!(req.first(), Some(0..=3)) {
                let page = self.peer.lock().unwrap().serve_notes_req_bytes(req, PAGE_BUDGET);
                if !page.is_empty() {
                    self.answers.lock().unwrap().push_back(page);
                }
            }
            true
        }
        fn bulk_follow_request(&self, req: &[u8]) -> usize {
            if self.lane != Lane::Bulk {
                return 0;
            }
            self.received.push("ask", req);
            1
        }
        fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
            self.answers.lock().unwrap().drain(..).collect()
        }
        fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
            let mut q = self.answers.lock().unwrap();
            let n = max.min(q.len());
            q.drain(..n).collect()
        }
    }

    /// The wallet's node, the SAME node in every world: its private secrets are pinned equal (the miner seed its
    /// DA-sampling secret derives from — `da_sampling_secret`), so the chunks it privately samples of a record it lacks
    /// are the same in every world, and the ONE thing that differs between worlds is which note the wallet owns.
    /// MEASURED why: with two independent seeds the grafted worlds differed only in their kind-10 DA-sample indices —
    /// the node's own coin flips, no wallet input.
    fn the_wallets_node() -> Node {
        let mut n = crate::node::tests::testnet_party_folding_at_tip();
        n.set_miner_seed_for_test([0x35; 32]);
        n
    }

    /// The wallet's node GRAFTED the peer's blocks as a peer receives them — through the block's own codec, so
    /// no payload rides (DB-165) — so it holds each block and owes its record before any wallet asks.
    fn grafted_without_payload(fx: &Fixture) -> Node {
        let mut n = the_wallets_node();
        for b in &fx.blocks {
            let wire: Block = postcard::from_bytes(&postcard::to_allocvec(b).expect("a block encodes"))
                .expect("a block decodes from its own encoding");
            assert!(
                matches!(n.ingest_block(wire, 7_000), RelayOutcome::Added(_)),
                "PRECONDITION: the wallet's node grafts the peer's block"
            );
        }
        n
    }

    /// The wallet's node PLACED the peer's records from sidecar rows alone, as a node that jumped the span does:
    /// it knows where each record sits and holds no block, so nothing asked for either record before the wallet.
    fn placed_by_sidecar(fx: &Fixture) -> Node {
        let mut n = the_wallets_node();
        for (ord, rid) in &fx.rows {
            assert!(n.adopt_sidecar_row(*ord, *rid), "PRECONDITION: the sidecar row files");
        }
        n
    }

    struct Run {
        received: Received,
        rt: Arc<Mutex<NodeRuntime<LinkToPeer>>>,
        /// Did the wallet's node hold a record carrying the note before the wallet asked? `false` is the exact
        /// trigger of the retired by-commitment want (`want_record_by_cm` returned early on a held one).
        held_before: bool,
        /// What `/want_note_record` answered — the retired route, posted exactly as a pre-DB-350 wallet posts it.
        retired_route: u16,
    }

    /// The wallet's membership-miss path, request for request as the wallet's send makes it (`resolve_position_
    /// by_cm`, then `build_note_membership_carrier`), plus the retired `/want_note_record` a wallet built before
    /// DB-350 posts next. Then the wallet's node runs its ticks and its link delivers what it asked for.
    fn wallet_misses(node: Node, fx: &Fixture, o: Owned, lane: Lane) -> Run {
        let received = Received::default();
        let link = LinkToPeer {
            lane,
            received: received.clone(),
            peer: fx.peer.clone(),
            answers: Mutex::new(VecDeque::new()),
            cells: Mutex::new(Reassembler::new()),
        };
        let rt = Arc::new(Mutex::new(NodeRuntime::new(node, link)));
        let held_before = rt.lock().unwrap().node().da_record_held(o.rid);
        let cms = hex(&o.cm);
        let _ = crate::rpc_http::route(&rt, "POST", "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{cms}"}}"#));
        let mut pos = o.rid.to_le_bytes().to_vec();
        pos.push(o.slot);
        let _ = crate::rpc_http::route(
            &rt,
            "POST",
            "/note_copath",
            &format!(
                r#"{{"positions_hex":"{}","cms_hex":"{cms}","addrs_hex":"{}"}}"#,
                hex(&pos),
                hex(&o.rid.to_le_bytes())
            ),
        );
        let (retired_route, _) =
            crate::rpc_http::route(&rt, "POST", "/want_note_record", &format!(r#"{{"cm_hex":"{cms}"}}"#));
        for k in 0..TICKS {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * TICK_MS);
        }
        Run { received, rt, held_before, retired_route }
    }

    /// Every spelling of a commitment the node's codecs use: the raw 32 bytes, and its leaf in the canonical 32-byte
    /// form and the 8-lane wire form.
    fn spellings(cm: &[u8; 32]) -> Vec<Vec<u8>> {
        let leaf = crate::spend_frontier::note_leaf_of(cm);
        vec![
            cm.to_vec(),
            crate::spend_frontier::leaf_to_cm_bytes(leaf).to_vec(),
            crate::spend_frontier::digest_to_lane_bytes(&leaf).to_vec(),
        ]
    }

    fn carries(hay: &[u8], needle: &[u8]) -> bool {
        needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Which received byte strings carry the commitment in any spelling: every ask, every reassembled message,
    /// every raw cell, and the raw cells joined.
    fn leaks(r: &Received, cm: &[u8; 32]) -> Vec<String> {
        let mut joined_cells = Vec::new();
        let mut out = Vec::new();
        for (i, (what, bytes)) in r.all().iter().enumerate() {
            if *what == "cell" {
                joined_cells.extend_from_slice(bytes);
            }
            if spellings(cm).iter().any(|s| carries(bytes, s)) {
                out.push(format!("{what} #{i} (first byte {:?}, {} B)", bytes.first(), bytes.len()));
            }
        }
        if spellings(cm).iter().any(|s| carries(&joined_cells, s)) {
            out.push("the joined cell stream".to_string());
        }
        out
    }

    fn replace_all(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(hay.len());
        let mut i = 0;
        while i < hay.len() {
            if hay.len() - i >= from.len() && &hay[i..i + from.len()] == from {
                out.extend_from_slice(to);
                i += from.len();
            } else {
                out.push(hay[i]);
                i += 1;
            }
        }
        out
    }

    /// The by-id asks (kind 2) the peer received, each as the record addresses it names.
    fn by_id_names(asks: &[Vec<u8>]) -> Vec<Vec<u64>> {
        asks.iter()
            .filter(|a| a.len() != 12 && a.first() == Some(&2u8))
            .map(|a| a[1..].chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
            .collect()
    }

    type Placement = (&'static str, fn(&Fixture) -> Node);
    const PLACEMENTS: [Placement; 2] =
        [("grafted without its payload", grafted_without_payload), ("placed by a sidecar row", placed_by_sidecar)];

    /// ⛔⛔⛔ THE PEER MUST NOT LEARN WHICH COMMITMENT THE WALLET OWNS. The wallet's node misses a record holding the
    /// wallet's note, the wallet takes its whole miss path, and the node runs; nothing the peer received — on the
    /// bulk lane or the cell lane — may carry the commitment in any spelling. RED before DB-350: `[3] ‖ cm`.
    #[test]
    fn db350_a_wallets_membership_miss_never_puts_its_commitment_on_the_wire() {
        let fx = fixture();
        // CALIBRATION — the detector is armed: the retired ask, `[3] ‖ cm`, is exactly what it must catch.
        let probe = Received::default();
        let mut retired = vec![3u8];
        retired.extend_from_slice(&fx.x.cm);
        probe.push("ask", &retired);
        assert!(!leaks(&probe, &fx.x.cm).is_empty(), "CALIBRATION: the retired by-commitment ask must be caught");
        for (placement, build) in PLACEMENTS {
            for lane in [Lane::Bulk, Lane::CellOnly] {
                for o in [fx.x, fx.y, fx.z] {
                    let run = wallet_misses(build(&fx), &fx, o, lane);
                    assert!(
                        !run.held_before,
                        "PRECONDITION ({placement}, {lane:?}): the wallet's node held no record carrying the note \
                         when the wallet asked — the exact state that raised the by-commitment ask"
                    );
                    assert!(
                        !run.received.asks().is_empty(),
                        "CALIBRATION ({placement}, {lane:?}): the wallet's node asked its peer for records on this \
                         lane — a node that asks nothing would pass vacuously"
                    );
                    let found = leaks(&run.received, &o.cm);
                    assert!(
                        found.is_empty(),
                        "⛔⛔⛔ ({placement}, {lane:?}) THE PEER LEARNED WHICH COMMITMENT THE WALLET OWNS: the owned \
                         commitment rode {} — every received byte string must name public chain coordinates only",
                        found.join("; ")
                    );
                }
            }
        }
    }

    /// ⭐ THE ASK NAMES A RECORD, NEVER WHICH OF ITS NOTES. X and Y share record R, so the peer must receive the
    /// same asks whichever the wallet owns. Across records the only difference allowed is the record address — the
    /// residual pinned to its exact width — and when the node already owed both records (a graft without payload),
    /// not even that. RED before DB-350: `[3] ‖ X` against `[3] ‖ Y`.
    #[test]
    fn db350_the_ask_names_the_record_never_which_of_its_notes_the_wallet_owns() {
        let fx = fixture();
        let asks = |build: fn(&Fixture) -> Node, o: Owned| -> Vec<Vec<u8>> {
            // §20.2: a produced block's padded tag lane follows its producer-drawn cover key, so two independent builds
            // differ by their keys alone (the node's own block id in the locator ask); seeding each build's keys identically
            // makes the asks comparable — the difference the assertions read is then which note the wallet owns, nothing else.
            crate::cover::seed_cover_keys_for_test(Some(0x350));
            let out = wallet_misses(build(&fx), &fx, o, Lane::Bulk).received.asks();
            crate::cover::seed_cover_keys_for_test(None);
            out
        };

        // Placed by a sidecar row alone: nothing asked for either record before the wallet did.
        let (x, y, z) = (asks(placed_by_sidecar, fx.x), asks(placed_by_sidecar, fx.y), asks(placed_by_sidecar, fx.z));
        assert_eq!(
            x, y,
            "⛔ X and Y share one record, yet the peer received different asks — something other than the record \
             names the note the wallet owns"
        );
        assert!(
            by_id_names(&x).iter().any(|ids| ids.contains(&fx.x.rid)),
            "CALIBRATION: the missed record is asked for by its public address (kind 2) — so the comparison below \
             reads a real difference: {:?}",
            by_id_names(&x)
        );
        assert_ne!(x, z, "CALIBRATION: two records, two addresses on the wire");
        let masked = |asks: &[Vec<u8>], rid: u64| -> Vec<Vec<u8>> {
            asks.iter().map(|a| replace_all(a, &rid.to_le_bytes(), &[0xEE; 8])).collect()
        };
        assert_eq!(
            masked(&x, fx.x.rid),
            masked(&z, fx.z.rid),
            "⛔ X and Z differ in more than the 8-byte record address — the wire carries something of the note"
        );

        // Grafted without its payload: the node owed both records before the wallet asked, so the wallet's miss
        // adds nothing a peer can see.
        let (gx, gy, gz) =
            (asks(grafted_without_payload, fx.x), asks(grafted_without_payload, fx.y), asks(grafted_without_payload, fx.z));
        assert_eq!(gx, gy, "⛔ (grafted) X and Y share one record, yet the asks differ");
        assert_eq!(
            gx, gz,
            "⛔ (grafted) the node already owed BOTH records, yet which one the wallet missed is visible on the wire: \
             {:?} against {:?}",
            by_id_names(&gx),
            by_id_names(&gz)
        );
    }

    /// ⭐ ONE CANONICAL SET ON THE WIRE. The by-id ask encoded the held-block/fold wants and THEN the resolver-miss wants
    /// as two ascending runs, never deduped, so an id past the first run's end told the peer a READ had missed it — a
    /// wallet's membership read among them — and a record in both sets rode the ask twice. Here the node owes a
    /// held-block record whose address is LARGER than the record the wallet then misses, so the two-run encoding is
    /// out of order. Every by-id ask must be one set — each id once — whose order carries no role.
    /// RED before DB-350: `[2] ‖ owed ‖ missed`.
    /// ⛔ This pin used to read "one ASCENDING set". Since H5 (6c98bf3, 2026-10-05) `padded_record_ask` emits the set in
    /// a KEYED order — a PRF of the node's per-boot secret and a per-ask nonce — so ascending became a coin flip per ask
    /// (MEASURED red on one flip, night/db432-green-20261008.log). The property DB-350 needs is unchanged and
    /// is now asserted deterministically: no id twice, and the same two roles land in BOTH orders across asks, so
    /// position cannot say which id a read missed.
    #[test]
    fn db350_every_by_id_ask_is_one_ascending_set() {
        let fx = fixture();
        let mut node = placed_by_sidecar(&fx);
        let owed = fx.x.rid.max(fx.z.rid) + 1;
        // The fold's own door (a held block whose record this node still owes) — the FIRST run of the old encoding.
        node.want_held_block_record(owed);
        let run = wallet_misses(node, &fx, fx.x, Lane::Bulk);
        let asks = by_id_names(&run.received.asks());
        assert!(
            asks.iter().any(|ids| ids.contains(&owed) && ids.contains(&fx.x.rid)),
            "CALIBRATION: one ask names both the owed record and the missed one, so its order is a real readout: {asks:?}"
        );
        for ids in &asks {
            let mut set = ids.clone();
            set.sort_unstable();
            set.dedup();
            assert_eq!(set.len(), ids.len(), "⛔ a by-id ask names an id twice — two runs, never deduped: {ids:?}");
        }
        // The order is keyed, never a role: the owed-first (old first run) and missed-first orders both occur.
        let node = run.rt.lock().unwrap();
        let (mut owed_first, mut missed_first) = (false, false);
        for _ in 0..64 {
            let ask = node.node().padded_record_ask(&[owed, fx.x.rid]);
            let (o, m) = (ask.iter().position(|a| *a == owed), ask.iter().position(|a| *a == fx.x.rid));
            match (o, m) {
                (Some(o), Some(m)) if o < m => owed_first = true,
                (Some(_), Some(_)) => missed_first = true,
                _ => panic!("⛔ a padded ask dropped a real want: {ask:?}"),
            }
        }
        assert!(
            owed_first && missed_first,
            "⛔ across 64 asks the owed and missed records always sit in one order — position says which a read missed"
        );
    }

    /// MUST-STAY-GREEN: deleting the by-commitment lane loses no recovery. The record the wallet missed arrives by
    /// its public address, the wallet's node verifies it against the block it grafted, and the membership read the
    /// wallet retries now serves the note's in-block copath.
    #[test]
    fn db350_the_missed_record_still_arrives_by_its_public_address() {
        let fx = fixture();
        let run = wallet_misses(grafted_without_payload(&fx), &fx, fx.x, Lane::Bulk);
        assert!(!run.held_before, "PRECONDITION: the wallet's node lacked the record when the wallet asked");
        // What the PEER received named the record only by a public coordinate — its record address (kind 2) or its
        // block id (kind 1) — and never the note.
        let block_id = *fx.blocks[0].id().as_bytes();
        let asks = run.received.asks();
        assert!(
            asks.iter().any(|a| {
                (a.first() == Some(&2u8) && a[1..].chunks_exact(8).any(|c| c == &fx.x.rid.to_le_bytes()[..]))
                    || (a.first() == Some(&1u8) && a[1..].chunks_exact(32).any(|c| c == &block_id[..]))
            }),
            "⛔ the peer was never asked for the missed record by a public coordinate — by-id asks received: {:?}",
            by_id_names(&asks)
        );
        assert!(leaks(&run.received, &fx.x.cm).is_empty(), "⛔ the peer's view of this recovery carries the commitment");
        assert!(
            run.rt.lock().unwrap().node().da_record_held(fx.x.rid),
            "⛔ the record the wallet missed never arrived — by-id asks the peer received: {:?}",
            by_id_names(&asks)
        );
        let mut pos = fx.x.rid.to_le_bytes().to_vec();
        pos.push(fx.x.slot);
        let (_, copath) =
            crate::rpc_http::route(&run.rt, "POST", "/note_copath", &format!(r#"{{"positions_hex":"{}"}}"#, hex(&pos)));
        assert!(
            copath.contains("\"served\":true"),
            "⛔ the retried membership read still cannot serve the note's in-block copath: {copath}"
        );
    }

    /// ⛔ A STALE PEER'S BY-COMMITMENT ASK IS ANSWERED WITH NOTHING, AND THE ROUTE THAT RAISED IT IS GONE. The tag
    /// stays reserved: its bytes are never parsed as another kind, and no record is scanned for the named note.
    /// RED before DB-350: the peer served the record containing the named commitment, and the route answered 200.
    #[test]
    fn db350_a_stale_by_commitment_ask_is_answered_with_nothing_and_its_route_is_gone() {
        let fx = fixture();
        let mut by_id = vec![2u8];
        by_id.extend_from_slice(&fx.x.rid.to_le_bytes());
        assert!(
            !fx.peer.lock().unwrap().serve_notes_req_bytes(&by_id, PAGE_BUDGET).is_empty(),
            "CALIBRATION: the peer serves the same record by its public address, so an answering by-commitment arm \
             would have something to return"
        );
        let mut by_cm = vec![3u8];
        by_cm.extend_from_slice(&fx.x.cm);
        let seen_before = crate::node_runtime::by_commitment_asks_received();
        let answer = fx.peer.lock().unwrap().serve_notes_req_bytes(&by_cm, PAGE_BUDGET);
        assert!(
            answer.is_empty(),
            "⛔ a peer's by-commitment ask was answered with {} byte(s) — the retired tag must answer nothing",
            answer.len()
        );
        assert!(
            crate::node_runtime::by_commitment_asks_received() > seen_before,
            "CALIBRATION: the retired arm SAW the ask — the second party counts every by-commitment ask it receives \
             (`[cm-ask-in]`, every arrival printed), so one arrival cannot hide from the real-process observation"
        );
        let run = wallet_misses(placed_by_sidecar(&fx), &fx, fx.x, Lane::Bulk);
        assert_eq!(run.retired_route, 404, "⛔ /want_note_record still answers: the by-commitment door is open");
    }

    /// DB-433's link: the peer answers every record ask (kinds 0-3) through its serve dispatcher, but the answer stays ON
    /// THE WIRE until the pin releases it (`land`) or loses it (`lose`) — a round trip the asker's ticks run inside.
    struct SlowLink {
        received: Received,
        peer: Peer,
        wire: SlowWire,
    }
    /// The pin's handle on that link's wire: answers in flight, and answers landed for the asker to take.
    #[derive(Clone, Default)]
    struct SlowWire {
        on_wire: Arc<Mutex<Vec<Vec<u8>>>>,
        answers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }
    impl SlowWire {
        fn land(&self) {
            let mut w = self.on_wire.lock().unwrap();
            self.answers.lock().unwrap().extend(w.drain(..));
        }
        fn lose(&self) {
            self.on_wire.lock().unwrap().clear();
        }
        /// An answer the pin builds itself lands for the asker to take.
        fn deliver(&self, page: Vec<u8>) {
            self.answers.lock().unwrap().push_back(page);
        }
    }
    impl CellTransport for SlowLink {
        fn send_cell(&self, _cell: Vec<u8>) -> Result<(), NetError> {
            Ok(())
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            None
        }
        fn has_bulk_lane(&self) -> bool {
            true
        }
        fn bulk_raw_request(&self, req: &[u8]) -> bool {
            self.received.push("ask", req);
            if req.len() != 12 && matches!(req.first(), Some(0..=3)) {
                let page = self.peer.lock().unwrap().serve_notes_req_bytes(req, PAGE_BUDGET);
                if !page.is_empty() {
                    self.wire.on_wire.lock().unwrap().push(page);
                }
            }
            true
        }
        fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
            self.wire.answers.lock().unwrap().drain(..).collect()
        }
        fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
            let mut q = self.wire.answers.lock().unwrap();
            let n = max.min(q.len());
            q.drain(..n).collect()
        }
    }

    /// The wallet's node owes record X (it grafted X's block without its payload, and the fold wants the record by its
    /// address), over a link whose answers stay in flight until the pin lands or loses them.
    fn owes_x_over_a_slow_link(fx: &Fixture) -> (Arc<Mutex<NodeRuntime<SlowLink>>>, Received, SlowWire) {
        let mut node = grafted_without_payload(fx);
        node.want_held_block_record(fx.x.rid);
        let received = Received::default();
        let wire = SlowWire::default();
        let link = SlowLink { received: received.clone(), peer: fx.peer.clone(), wire: wire.clone() };
        (Arc::new(Mutex::new(NodeRuntime::new(node, link))), received, wire)
    }

    /// The by-record-id asks (kind 2) the PEER received.
    fn kind2_asks(received: &Received) -> Vec<Vec<u8>> {
        received.asks().into_iter().filter(|a| a.first() == Some(&2u8)).collect()
    }

    /// The by-record-id asks (kind 2) the PEER received that name `rid`.
    fn kind2_asks_naming(received: &Received, rid: u64) -> usize {
        by_id_names(&kind2_asks(received)).iter().filter(|ids| ids.contains(&rid)).count()
    }

    /// The tag a by-record-id answer echoes: its header's second word.
    fn echoed_tag(answer: &[u8]) -> u64 {
        u64::from_le_bytes(answer[8..16].try_into().unwrap())
    }

    /// ⭐⭐ DB-433 — EVERY BY-RECORD-ID ASK IS ANSWERED, AND THE ANSWER NAMES ITS ASK (Bitcoin `getdata` → `block` |
    /// `notfound`). A peer holding none of the named records answered NOTHING, so an asker keeping one ask outstanding
    /// could not tell "nobody here has it" from "the answer is on its way" and waited out the 45 s backstop — the shape
    /// that made DB-432's T1.6 flaky. RED before DB-433: the lacking ask's answer is empty, and the held ask's answer
    /// carries no tag (its header was four zero words).
    #[test]
    fn db433_every_by_record_id_ask_is_answered_with_its_tag() {
        let fx = fixture();
        let ask = |ids: &[u64]| -> Vec<u8> {
            let mut req = vec![2u8];
            for r in ids {
                req.extend_from_slice(&r.to_le_bytes());
            }
            req
        };
        let held = ask(&[fx.x.rid]);
        let lacking = ask(&[u64::MAX - 7, u64::MAX - 9]);
        assert!(
            fx.peer.lock().unwrap().node().da_record_notes(u64::MAX - 7).is_none(),
            "PRECONDITION: the peer holds no record at the lacking addresses"
        );
        let got = fx.peer.lock().unwrap().serve_notes_req_bytes(&held, PAGE_BUDGET);
        assert!(got.len() > 32, "CALIBRATION: the peer serves record X by its address ({} byte(s))", got.len());
        assert_eq!(
            echoed_tag(&got),
            crate::node_runtime::record_ask_tag(&held),
            "⛔ the answer to a by-record-id ask does not name the ask it answers"
        );
        let none = fx.peer.lock().unwrap().serve_notes_req_bytes(&lacking, PAGE_BUDGET);
        assert_eq!(
            none.len(),
            32,
            "⛔ a peer holding none of the named records answered {} byte(s) — it must answer the header alone (notfound)",
            none.len()
        );
        assert_eq!(echoed_tag(&none), crate::node_runtime::record_ask_tag(&lacking), "⛔ the notfound names no ask");
        assert_eq!(none[16..24], [0u8; 8], "⛔ the notfound must read as a by-id page (covered_upto 0)");
    }

    /// ⭐⭐⭐ DB-433 — A RECORD WANT RIDES ONE OUTSTANDING ASK (Bitcoin Core `mapBlocksInFlight`). The by-record-id ask was
    /// re-sent every relay tick while its first copy was still in flight, and each copy's answer came back whole and
    /// already held — MEASURED in the P14 low leg: 789 of 1,048 by-id answers `0/3 … already-held=3`, ~935 KB each. The
    /// transport's duplicate rule could not refuse the copies: each carries fresh decoys. Here the peer's answer stays in
    /// flight for twelve relay ticks (3 s, inside the backstop), then lands: the peer must have received ONE ask naming
    /// X, the asker must then HOLD X, and no later ask may name it. RED before DB-433: twelve asks.
    #[test]
    fn db433_a_record_want_rides_one_outstanding_ask() {
        let fx = fixture();
        let (rt, received, wire) = owes_x_over_a_slow_link(&fx);
        assert!(!rt.lock().unwrap().node().da_record_held(fx.x.rid), "PRECONDITION: the asker lacks record X");
        for k in 0..12u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        let in_flight = kind2_asks_naming(&received, fx.x.rid);
        assert!(in_flight >= 1, "CALIBRATION: the owed record is asked for by its address");
        assert_eq!(
            in_flight, 1,
            "⛔ the peer received {in_flight} by-record-id asks naming X while the first one's answer was still in flight"
        );
        wire.land();
        for k in 12..24u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the answer landed and the asker still lacks X");
        assert_eq!(kind2_asks_naming(&received, fx.x.rid), 1, "⛔ the asker holds X and still asked for it again");
    }

    /// ⭐⭐ DB-433 — A NOTFOUND ENDS THE ASK AT ONCE. The first ask's answer is a `notfound` (the host it reached holds
    /// none of the ids): the very next drain asks again — never the 45 s backstop DB-432 waited — and that second ask
    /// is then the one outstanding ask. RED before DB-433: three asks in three ticks (no outstanding rule); under
    /// DB-432's rule, one (the notfound was invisible to it).
    #[test]
    fn db433_a_notfound_ends_the_ask_at_once() {
        let fx = fixture();
        let (rt, received, wire) = owes_x_over_a_slow_link(&fx);
        let _ = rt.lock().unwrap().tick_relay(20_000);
        let first = kind2_asks(&received);
        assert_eq!(kind2_asks_naming(&received, fx.x.rid), 1, "CALIBRATION: the first ask names X");
        wire.lose();
        let mut notfound = vec![0u8; 32];
        notfound[8..16].copy_from_slice(&crate::node_runtime::record_ask_tag(&first[0]).to_le_bytes());
        wire.deliver(notfound);
        let _ = rt.lock().unwrap().tick_relay(20_250);
        let _ = rt.lock().unwrap().tick_relay(20_500);
        assert_eq!(
            kind2_asks_naming(&received, fx.x.rid),
            2,
            "⛔ after a notfound the asker must ask again at once, and then keep that ONE ask outstanding"
        );
        wire.land();
        for k in 3..12u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the second ask's answer never admitted X");
    }

    /// MUST-STAY-GREEN (DB-433's liveness arm): an answer LOST on the wire is not waited for forever — once the backstop
    /// (`BATCH_PAGE_OUTSTANDING_MS`, DB-65c's one-outstanding bound) has passed, the want is asked again and its answer
    /// is admitted.
    #[test]
    fn db433_a_lost_record_answer_is_asked_again_after_the_backstop() {
        let fx = fixture();
        let (rt, received, wire) = owes_x_over_a_slow_link(&fx);
        let _ = rt.lock().unwrap().tick_relay(20_000);
        assert_eq!(kind2_asks_naming(&received, fx.x.rid), 1, "CALIBRATION: the first ask names X");
        wire.lose();
        let after = 20_000 + crate::node_runtime::BATCH_PAGE_OUTSTANDING_MS;
        for k in 0..4u64 {
            let _ = rt.lock().unwrap().tick_relay(after + k * 250);
        }
        assert!(
            kind2_asks_naming(&received, fx.x.rid) >= 2,
            "⛔ the first answer was lost and X was never asked for again past the backstop"
        );
        wire.land();
        for k in 4..12u64 {
            let _ = rt.lock().unwrap().tick_relay(after + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the re-asked record never arrived");
    }

    /// The wallet's node grafted the peer's blocks WITHOUT their payload and nothing asked for a record by its address: the
    /// only lane that can fetch the records is the by-BLOCK-id backfill (kind 1, `blocks_missing_ledger_records`), over a
    /// link whose answers stay in flight until the pin lands or loses them.
    fn owes_blocks_over_a_slow_link(fx: &Fixture) -> (Arc<Mutex<NodeRuntime<SlowLink>>>, Received, SlowWire) {
        let node = grafted_without_payload(fx);
        let received = Received::default();
        let wire = SlowWire::default();
        let link = SlowLink { received: received.clone(), peer: fx.peer.clone(), wire: wire.clone() };
        (Arc::new(Mutex::new(NodeRuntime::new(node, link))), received, wire)
    }

    /// The by-block-id asks (kind 1) the PEER received.
    fn kind1_asks(received: &Received) -> Vec<Vec<u8>> {
        received.asks().into_iter().filter(|a| a.len() != 12 && a.first() == Some(&1u8)).collect()
    }

    /// The by-block-id asks (kind 1) the PEER received that name the block `id`.
    fn kind1_asks_naming(received: &Received, id: &Hash32) -> usize {
        kind1_asks(received).iter().filter(|a| a[1..].chunks_exact(32).any(|c| c == id.as_bytes())).count()
    }

    /// ⭐⭐ DB-434 — EVERY BY-BLOCK-ID ASK IS ANSWERED, AND THE ANSWER NAMES ITS ASK (DB-433's shape for kind 1). A peer
    /// holding none of the named blocks' records answered NOTHING, so the asker could not tell "nobody here has it" from
    /// "the answer is on its way". RED before DB-434: the lacking ask's answer is empty, and the held ask's answer carries
    /// no tag (its header was four zero words).
    #[test]
    fn db434_every_by_block_id_ask_is_answered_with_its_tag() {
        let fx = fixture();
        let ask = |ids: &[[u8; 32]]| -> Vec<u8> {
            let mut req = vec![1u8];
            for id in ids {
                req.extend_from_slice(id);
            }
            req
        };
        let held = ask(&[*fx.blocks[0].id().as_bytes()]);
        let lacking = ask(&[[0xA7u8; 32], [0xB9u8; 32]]);
        let got = fx.peer.lock().unwrap().serve_notes_req_bytes(&held, PAGE_BUDGET);
        assert!(got.len() > 32, "CALIBRATION: the peer serves block X's record by the block's id ({} byte(s))", got.len());
        assert_eq!(
            echoed_tag(&got),
            crate::node_runtime::record_ask_tag(&held),
            "⛔ the answer to a by-block-id ask does not name the ask it answers"
        );
        let none = fx.peer.lock().unwrap().serve_notes_req_bytes(&lacking, PAGE_BUDGET);
        assert_eq!(
            none.len(),
            32,
            "⛔ a peer holding none of the named blocks' records answered {} byte(s) — it must answer the header alone (notfound)",
            none.len()
        );
        assert_eq!(echoed_tag(&none), crate::node_runtime::record_ask_tag(&lacking), "⛔ the notfound names no ask");
        assert_eq!(none[16..24], [0u8; 8], "⛔ the notfound must read as a by-id page (covered_upto 0)");
    }

    /// ⭐⭐⭐ DB-434 — A BLOCK'S RECORD RIDES ONE OUTSTANDING BY-BLOCK-ID ASK (Bitcoin Core `mapBlocksInFlight`). The kind-1
    /// backfill re-sent the same block ids every relay tick while the first copy's answer was still in flight — MEASURED
    /// (link 41, five P14 low legs on DB-433): 571–1,071 by-id answers per 1 k leg arrived `0/3 … already-held=3`, every one
    /// a kind-1 answer. Here the peer's answer stays in flight for twelve relay ticks (3 s, inside the backstop), then lands:
    /// the peer must have received ONE ask naming X's block, the asker must then HOLD record X, and no later ask may name
    /// the block. RED before DB-434: twelve asks.
    #[test]
    fn db434_a_block_record_rides_one_outstanding_ask() {
        let fx = fixture();
        let (rt, received, wire) = owes_blocks_over_a_slow_link(&fx);
        let bx = fx.blocks[0].id();
        assert!(!rt.lock().unwrap().node().da_record_held(fx.x.rid), "PRECONDITION: the asker lacks record X");
        for k in 0..12u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        let in_flight = kind1_asks_naming(&received, &bx);
        assert!(in_flight >= 1, "CALIBRATION: the block whose record is missing is asked for by its id");
        assert_eq!(
            in_flight, 1,
            "⛔ the peer received {in_flight} by-block-id asks naming X's block while the first one's answer was still in flight"
        );
        wire.land();
        for k in 12..24u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the answer landed and the asker still lacks record X");
        assert_eq!(kind1_asks_naming(&received, &bx), 1, "⛔ the asker holds X's record and still asked for its block again");
    }

    /// ⭐⭐ DB-434 — A NOTFOUND ENDS THE BY-BLOCK-ID ASK AT ONCE: the first ask's answer is a `notfound`, so the very next
    /// tick asks again — never the 45 s backstop — and that second ask is then the one outstanding ask. RED before DB-434:
    /// three asks in three ticks (no outstanding rule).
    #[test]
    fn db434_a_notfound_ends_the_block_ask_at_once() {
        let fx = fixture();
        let (rt, received, wire) = owes_blocks_over_a_slow_link(&fx);
        let bx = fx.blocks[0].id();
        let _ = rt.lock().unwrap().tick_relay(20_000);
        let first = kind1_asks(&received);
        assert_eq!(kind1_asks_naming(&received, &bx), 1, "CALIBRATION: the first ask names X's block");
        wire.lose();
        let mut notfound = vec![0u8; 32];
        notfound[8..16].copy_from_slice(&crate::node_runtime::record_ask_tag(&first[0]).to_le_bytes());
        wire.deliver(notfound);
        let _ = rt.lock().unwrap().tick_relay(20_250);
        let _ = rt.lock().unwrap().tick_relay(20_500);
        assert_eq!(
            kind1_asks_naming(&received, &bx),
            2,
            "⛔ after a notfound the asker must ask again at once, and then keep that ONE ask outstanding"
        );
        wire.land();
        for k in 3..12u64 {
            let _ = rt.lock().unwrap().tick_relay(20_000 + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the second ask's answer never admitted record X");
    }

    /// MUST-STAY-GREEN (DB-434's liveness arm): a by-block-id answer LOST on the wire is not waited for forever — past the
    /// backstop (`BATCH_PAGE_OUTSTANDING_MS`) the block is asked for again and its record is admitted.
    #[test]
    fn db434_a_lost_block_answer_is_asked_again_after_the_backstop() {
        let fx = fixture();
        let (rt, received, wire) = owes_blocks_over_a_slow_link(&fx);
        let bx = fx.blocks[0].id();
        let _ = rt.lock().unwrap().tick_relay(20_000);
        assert_eq!(kind1_asks_naming(&received, &bx), 1, "CALIBRATION: the first ask names X's block");
        wire.lose();
        let after = 20_000 + crate::node_runtime::BATCH_PAGE_OUTSTANDING_MS;
        for k in 0..4u64 {
            let _ = rt.lock().unwrap().tick_relay(after + k * 250);
        }
        assert!(
            kind1_asks_naming(&received, &bx) >= 2,
            "⛔ the first answer was lost and X's block was never asked for again past the backstop"
        );
        wire.land();
        for k in 4..12u64 {
            let _ = rt.lock().unwrap().tick_relay(after + k * 250);
        }
        assert!(rt.lock().unwrap().node().da_record_held(fx.x.rid), "⛔ the re-asked record never arrived");
    }
}

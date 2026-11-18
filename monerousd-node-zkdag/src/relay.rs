// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Block relay + orphan buffer (the graft half of gossip), consensus-strict.
//!
//! Gossip delivers blocks out of order: a node can hear a child before its parent. The relay
//! guarantees EVERY consensus-valid block eventually grafts once its ancestors arrive — it never
//! drops a valid block for arriving early. On [`BlockRelay::receive`] it first applies the
//! self-contained [`crate::consensus::validate_structural`] checks; then it tries to graft, and at
//! EVERY DAG insertion (the first attempt AND every orphan-drain retry) it applies
//! [`crate::consensus::validate_contextual`] (parent membership, median-time-past, DAA work). So a
//! block that is merely early buffers, a consensus-INVALID block is rejected, and a late-arriving
//! valid block still grafts — the correctness the monerod gossip path lacked.
//!
//! The buffer is bounded ([`ORPHAN_CAP`]) so a flood of unattachable orphans cannot grow memory;
//! dropped orphans are re-gossiped by peers later. The transport binding (libp2p_ffi onion mesh)
//! feeds `receive` on inbound gossip and pushes locally-produced blocks — that wiring is the next
//! increment; this brick is the transport-independent, consensus-strict graft logic it drives.

use std::collections::{HashMap, HashSet};

use crate::block::{Block, BlockId};
use crate::consensus::{validate_contextual, validate_structural, ConsensusError};
use crate::dag::{Dag, DagError};

/// Bound on buffered (not-yet-attachable) orphan blocks — the no-growth cap on relay memory.
pub const ORPHAN_CAP: usize = 32;
/// DB-9 (2026-09-17): how many EVICTED orphans' `(child, missing parent)` pairs the relay remembers, so
/// the child is re-wanted through the shell lane the moment its parent lands. O1: a fixed ring of 64 B
/// entries; the bodies are gone (the notes are DA — the notes lane re-serves them on demand).
pub const EVICTED_ORPHAN_RING: usize = 512;
/// ⭐ THE DESCENT PARK'S OWN BOUND (2026-09-17, §DB): how many block-lane page shells may wait in the
/// orphan buffer for a deeper parent. A page is ~4 shells and a gap the lane should close is a few
/// pages; 128 shells (~1.1 MB) is the whole of what the lane may hold — a deeper gap is the DSYNC
/// jump's business, never RAM. One small size, whatever the peer does.
pub const PAGE_SHELL_PARK_MAX: usize = 512;

/// What happened to a received block.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Grafted into the DAG (id returned). May have cascaded buffered descendants in as well.
    Added(BlockId),
    /// Held: a parent is not yet known. Retried automatically when `missing` arrives.
    Buffered { block: BlockId, missing: BlockId },
    /// Already buffered and waiting; ignored.
    AlreadyBuffered(BlockId),
    /// Already in the DAG; ignored (gossip re-delivery is harmless).
    Duplicate(BlockId),
    /// Failed consensus validation (structural or contextual) — rejected.
    Invalid(ConsensusError),
    /// Passed validation but the DAG rejected it (e.g. a second genesis).
    DagRejected(DagError),
}

/// Wraps a [`Dag`] with an orphan buffer so out-of-order gossip converges, consensus-strict.
pub struct BlockRelay {
    dag: Dag,
    /// missing-parent id -> blocks waiting for it.
    waiting: HashMap<BlockId, Vec<Block>>,
    /// ids currently buffered (avoids double-buffering + bounds the buffer).
    buffered: HashSet<BlockId>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PAGE_SHELL_PARK_MAX — the block lane refuses to park past it;
    /// entries leave with their strand in `take_waiting_on`.
    parked_page: std::collections::HashSet<BlockId>,
    /// When each buffered orphan was parked (run 37, 2026-09-18: 24 orphans whose parents had left the
    /// peer's body window sat in the buffer all run and every new orphan evicted a live one). An orphan
    /// older than `expire_orphans`' age leaves; the certified bundle covers what it waited for.
    /// O1-FOOTPRINT-REVIEWED: bounded by ORPHAN_CAP (one entry per buffered orphan)
    parked_at_ms: HashMap<BlockId, u64>,
    /// The last `now_ts` a receive saw — the clock `buffer()` stamps orphans with.
    now_ms: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by ORPHAN_CAP — insertion order of the buffered orphans, so the cap
    /// evicts the OLDEST (a fresh gossiped tip must never be refused for a stale orphan).
    order: std::collections::VecDeque<BlockId>,
    /// O1-FOOTPRINT-REVIEWED: bounded by EVICTED_ORPHAN_RING — `(child, missing parent)` of evicted
    /// orphans; drained into shell-lane wants when the parent lands (DB-9).
    evicted: std::collections::VecDeque<(BlockId, BlockId)>,
    /// Every block grafted by the CURRENT `receive`, with the payload it carried: `(id, output_notes,
    /// account_targets)`. Cleared at the start of each `receive` and drained by the caller right after, so it
    /// holds one receive's worth and never accumulates.
    ///
    /// This exists because `RelayOutcome::Added` names only the block that was handed in, while `drain_from`
    /// may graft a whole cascade of buffered descendants behind it. A caller acting on the outcome alone
    /// never learned those blocks entered the DAG. The last three fields — the header-committed nullifier
    /// pre-root, the carried tag set and the carried height-1 fold — ride here for the same reason the notes
    /// do: a `BlockNode` keeps only header+tx_ids, so a CASCADED block's spend transition would otherwise be
    /// unfoldable by the very node that just accepted it.
    /// block's spends must be foldable by the very node that just accepted it, exactly like its notes.
    /// The eighth element is the block's carried validator-bond set ([`Block::bond_set`]) — a CASCADED
    /// block's bonds must be admitted by the very node that just accepted it, exactly like its spends.
    /// ⭐⭐⭐ THE TWELFTH ELEMENT — THE BLOCK'S NOTE TRANSITION (§BA/§BB), and it rides here for the
    /// EXACT reason stated above: a `BlockNode` keeps only header+tx_ids, so a CASCADED block's
    /// note-transition proof would otherwise be unreachable by the very node that just accepted it —
    /// and without it that node judges the block's notes by resolved bodies alone, which is the §BA
    /// hole. ⛔ Drained per receive like every other payload here; nothing is retained per block.
    grafted: Vec<(
        BlockId,
        Vec<u8>,
        Vec<u8>,
        crate::hash::Hash32,
        Vec<[u8; 32]>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        crate::hash::Hash32,
        Option<crate::note_transition::NoteTransition>,
        // ⭐ §BA — the block's CREDIT SET, APPENDED LAST (never inserted: a positional insert shifts every
        // index in both pushes and both destructures, which is exactly how the last widening broke). It
        // rides the carry for the same reason the notes and the transition do — the DAG keeps header and
        // ids only, so a cascaded block's sidecar is otherwise unreachable by the node that accepted it.
        Vec<u8>,
        // The CONSTANT-WIDTH transition (DB-83), APPENDED LAST for the same reason — same carry, same
        // unreachability if it did not ride, and its tags are what let a multi-input spend settle.
        Option<crate::note_transition::CoverTransition>,
        // DB-351: the block's filed locator tags, APPENDED LAST — the note transition's D is recomputed from them.
        Vec<u8>,
        // DB-223 Q7: the block's member transition, APPENDED LAST — a stated spend counts only with its input proven.
        Option<crate::member_transition::MemberTransition>,
            // §20.2 — the carried body's COVER KEY, appended last (in process with the body; never on the wire)
        Option<crate::cover::CoverKey>,
        // §22b — the body's WIDE OBJECTS (BIP152: the bytes the sealed set names by hash), appended last
        Vec<Vec<u8>>,
    )>,
    /// TRUE when some parked block's "missing" parent turned out to be ALREADY IN THE DAG, so
    /// `waiting` holds at least one child whose parent is present and no future graft will ever
    /// drain it. Two strand shapes set it, and both stranded FOREVER before this existed:
    ///
    /// 1. `receive` of a block already in the DAG returned `Duplicate` WITHOUT draining
    ///    `waiting[id]` — but a parent that entered the DAG out-of-band (a DSYNC anchor, a
    ///    fold-carry graft) never fires `drain_from`, so its parked children's ONLY release was a
    ///    re-delivery of that parent, and the re-delivery dropped them on the floor.
    /// 2. `drain_from` popped a waiter that was already in the DAG (an anchored block whose own
    ///    children were parked on it) and `continue`d without walking THROUGH it, so the
    ///    grandchildren stayed parked on a present parent — transitivity broken at exactly one hop.
    ///
    /// ⛔ A BOOL, NEVER A QUEUE, and the strands are NOT grafted inline here on purpose: a cascade
    /// of parked blocks applied inside `receive` under the runtime lock is un-budgeted (measured
    /// class: 288 parked × ~50 ms apply ≈ 15 s lock hold). The blocks stay where they already are —
    /// the ORPHAN_CAP-bounded `waiting` map — and the caller (the runtime tick) reads this flag,
    /// walks `missing_parents()` for present parents, and re-injects their waiters through the SAME
    /// preverify/FIFO lane as fresh gossip: every admission gate re-runs (nothing is trusted for
    /// having been parked) and the 200 ms apply budget holds. Nothing new is retained on any axis.
    strand_hint: bool,
    /// ⭐ ITEM-6 CASCADE BUDGET — how many parked descendants THIS receive may still cascade into the
    /// DAG (set per call by `receive_bounded`, `usize::MAX` = unbounded). A descendant past the bound
    /// stays in `waiting` with `strand_hint` set — see `receive_bounded`. A plain counter, never a
    /// store: it retains nothing.
    cascade_bound: usize,
    /// O1-FOOTPRINT-REVIEWED: bounded by DAG width (ORPHAN_CAP = 32 ≤ DAG_WIDTH_CEILING) — the WHOLE blocks the
    /// cascade of ONE receive released from the orphan buffer, handed to the node at once so their bodies
    /// reach the unfolded window (the by-id lane and the bundle's carry serve them whole). MEASURED
    /// 2026-09-18: a cascade-released child had no body anywhere — a header shell stood in for it.
    cascaded_bodies: Vec<Block>,
    /// ⛔ DB-282 — TRUE once since the last take: a block (named or cascaded) merged pre-anchor history into settled
    /// structure (`DagError::MergesPreAnchorHistory`). A bool, never a queue: the node reads it after each receive and
    /// marks its spine for a certified re-anchor. Retains nothing.
    history_merge_refused: bool,
    /// ⭐ DB-317 — the (refused history root, settled parent) pairs that already asked for a re-anchor. A live merge fires
    /// ONCE per pair: a re-serve of the same mined merge at an unchanged anchor is a silent drop (review by
    /// lane-db224-carriage — otherwise every descent round trip re-adopts for one mined block). After an anchor change
    /// the settled parent is history, so the merge cannot fire anyway; a NEW merge names a new settled parent and does.
    /// O1-FOOTPRINT-REVIEWED: bounded by ORPHAN_CAP pairs (64 B each), oldest dropped first.
    history_fired: std::collections::VecDeque<(BlockId, BlockId)>,
}

impl BlockRelay {
    /// Start a relay seeded with the genesis block.
    pub fn new(genesis: Block) -> Result<Self, DagError> {
        let mut dag = Dag::new();
        dag.add_block(genesis)?;
        Ok(BlockRelay {
            dag,
            waiting: HashMap::new(),
            parked_at_ms: HashMap::new(),
            now_ms: 0,
            buffered: HashSet::new(),
            parked_page: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
            evicted: std::collections::VecDeque::new(),
            grafted: Vec::new(),
            strand_hint: false,
            cascade_bound: usize::MAX,
            cascaded_bodies: Vec::new(),
            history_merge_refused: false,
            history_fired: std::collections::VecDeque::new(),
        })
    }

    /// Start a relay on an existing DAG.
    pub fn from_dag(dag: Dag) -> Self {
        BlockRelay {
            dag,
            waiting: HashMap::new(),
            parked_at_ms: HashMap::new(),
            now_ms: 0,
            buffered: HashSet::new(),
            parked_page: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
            evicted: std::collections::VecDeque::new(),
            grafted: Vec::new(),
            strand_hint: false,
            cascade_bound: usize::MAX,
            cascaded_bodies: Vec::new(),
            history_merge_refused: false,
            history_fired: std::collections::VecDeque::new(),
        }
    }

    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    pub fn dag_mut(&mut self) -> &mut Dag {
        &mut self.dag
    }

    /// Bytes held by the parked (parent-waiting) blocks and the cascade buffer — for `/ram_census`.
    #[must_use]
    pub fn buffered_census_bytes(&self) -> usize {
        self.waiting.values().flat_map(|v| v.iter()).map(|b| b.census_bytes()).sum::<usize>()
            + self.cascaded_bodies.iter().map(|b| b.census_bytes()).sum::<usize>()
    }

    pub fn buffered_len(&self) -> usize {
        // The blocks actually waiting on a parent — never the dedupe set alone, which can keep an id
        // whose block was placed by another path (a carry, an anchor) and never drained (the schedule
        // search: a phantom orphan that would have deferred production forever).
        self.waiting.values().map(|v| v.len()).sum()
    }

    /// TRUE when this id ARRIVED and is parked awaiting its own parent. Such a block needs no
    /// by-id fetch — it is already here, and its strand drains when its ancestor lands — so the
    /// Buffered arm's parent-want wiring consults this before spending a want slot.
    pub fn is_parked(&self, id: &BlockId) -> bool {
        self.buffered.contains(id)
    }

    /// Park a shell the block lane has AUTHENTICATED (a page-closure member that passed the header
    /// door and the DAA equality) on the parent it still lacks — the same ORPHAN_CAP-bounded buffer
    /// a gossiped orphan enters after an `UnknownParent` verdict, released by the same `drain_from`
    /// cascade when that parent lands. The lane's page is ~4 shells, so a gap deeper than a page
    /// can only heal if the shells it has already fetched are KEPT while the ask descends
    /// (2026-09-17: dropping them re-fetched the same four forever).
    /// Drop every buffered orphan parked longer than `max_age_ms` (run 37: dead parkings held 24 of the
    /// 32 slots all run). Returns how many left. The bundle lane covers what they waited for.
    pub fn expire_orphans(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        self.expire_orphans_named(now_ms, max_age_ms).len()
    }

    /// The same expiry, naming each evicted orphan with the parent it waited for — so the node can say
    /// whether that parent is absent, a held shell, or held whole (DB-41 diagnosis, 2026-09-18).
    /// O1-FOOTPRINT-REVIEWED: returns only what this call evicts from the bounded orphan buffer.
    ///
    /// ⭐ A CHAIN THAT IS STILL ARRIVING NEVER EXPIRES (2026-11-09). An orphan whose missing parent is itself parked waits
    /// on that parent's chain, so a chain's age is the time since ANY of its members arrived — BORROWED: Bitcoin Core keeps
    /// a block downloaded ahead of its parents until they connect, and only a download that stops making progress is a
    /// stall. MEASURED (eclipse.py, 900 s eclipse, four real nodes): the rejoining node's 40-block side chain was listed in
    /// the right order, but each 1.2 MB body took ~10 s over Tor, so every member parked a minute before its parent
    /// landed and was dropped (66 drops on one honest node); the merge never placed and the network split for good (fold
    /// 134 against 117). A chain that brings nothing new for `max_age_ms` still expires whole, as before, and the bundle
    /// lane takes it. cons: none — the same ORPHAN_CAP bound; one pass over the parked set per call.
    pub fn expire_orphans_named(&mut self, now_ms: u64, max_age_ms: u64) -> Vec<(BlockId, BlockId)> {
        self.now_ms = self.now_ms.max(now_ms);
        // each parked orphan's own missing parent, then the newest arrival along every chain through it
        let missing_of: HashMap<BlockId, BlockId> =
            self.waiting.iter().flat_map(|(m, bs)| bs.iter().map(move |b| (b.id(), *m))).collect();
        let root_of = |mut id: BlockId| -> BlockId {
            for _ in 0..=self.buffered.len() {
                match missing_of.get(&id) {
                    Some(m) if self.buffered.contains(m) => id = *m,
                    Some(m) => return *m,
                    None => return id,
                }
            }
            id
        };
        let mut newest_by_root: HashMap<BlockId, u64> = HashMap::new();
        for (id, at) in &self.parked_at_ms {
            let e = newest_by_root.entry(root_of(*id)).or_insert(0);
            *e = (*e).max(*at);
        }
        let stale: Vec<BlockId> = self
            .parked_at_ms
            .keys()
            .filter(|id| now_ms.saturating_sub(newest_by_root.get(&root_of(**id)).copied().unwrap_or(0)) > max_age_ms)
            .copied()
            .collect();
        let mut named = Vec::with_capacity(stale.len());
        for old in &stale {
            if !self.buffered.contains(old) {
                // A stamp without a park record: the child was released by another door and its
                // stamp outlived it. That is bookkeeping to drop, not an orphan that expired — an
                // expiry here would arm the fork-choice bundle trigger on a node that is not behind.
                self.forget_park(old);
                continue;
            }
            let mut parent: Option<BlockId> = None;
            for (missing, blocks) in self.waiting.iter_mut() {
                if let Some(pos) = blocks.iter().position(|b| b.id() == *old) {
                    blocks.remove(pos);
                    parent = Some(*missing);
                    break;
                }
            }
            self.forget_park(old);
            named.push((*old, parent.unwrap_or(*old)));
        }
        self.waiting.retain(|_, v| !v.is_empty());
        named
    }

    pub fn park_shell(&mut self, missing: BlockId, block: Block) {
        let bid = block.id();
        let before = self.buffered.len();
        self.buffer(missing, block);
        if self.buffered.len() > before {
            self.parked_page.insert(bid);
        }
    }

    /// How many PAGE shells are parked right now — the block lane's own strand, counted apart from
    /// gossip orphans (DB-8, 2026-09-17: the park bound used to read the WHOLE orphan buffer, so a few
    /// hundred gossiped blocks buffered behind a gap refused every descent shell and the lane halted).
    pub fn parked_page_len(&self) -> usize {
        self.parked_page.len()
    }

    /// Every buffered block with the parent it waits on (diagnostics).
    pub fn buffered_pairs(&self) -> Vec<(BlockId, BlockId)> {
        self.waiting
            .iter()
            .flat_map(|(missing, blocks)| blocks.iter().map(move |b| (b.id(), *missing)))
            .collect()
    }

    /// EVERY block the last [`Self::receive`] grafted, with the payload each carried: the block that was
    /// handed in, plus every buffered descendant that cascaded in behind it. `RelayOutcome::Added` names only
    /// the first, so this is the only complete account of what entered the DAG.
    ///
    /// Transient — cleared at the start of each `receive` and drained by the caller immediately after, so it
    /// holds one receive's worth of blocks and never accumulates.
    pub fn take_grafted(
        &mut self,
    ) -> Vec<(
        BlockId,
        Vec<u8>,
        Vec<u8>,
        crate::hash::Hash32,
        Vec<[u8; 32]>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        crate::hash::Hash32,
        Option<crate::note_transition::NoteTransition>,
        // ⭐ §BA — the block's CREDIT SET, APPENDED LAST (never inserted: a positional insert shifts every
        // index in both pushes and both destructures, which is exactly how the last widening broke). It
        // rides the carry for the same reason the notes and the transition do — the DAG keeps header and
        // ids only, so a cascaded block's sidecar is otherwise unreachable by the node that accepted it.
        Vec<u8>,
        // The CONSTANT-WIDTH transition (DB-83), APPENDED LAST for the same reason — same carry, same
        // unreachability if it did not ride, and its tags are what let a multi-input spend settle.
        Option<crate::note_transition::CoverTransition>,
        // DB-351: the block's filed locator tags, APPENDED LAST — the note transition's D is recomputed from them.
        Vec<u8>,
        // DB-223 Q7: the block's member transition, APPENDED LAST.
        Option<crate::member_transition::MemberTransition>,
            // §20.2 — the carried body's COVER KEY, appended last (in process with the body; never on the wire)
        Option<crate::cover::CoverKey>,
        // §22b — the body's WIDE OBJECTS (BIP152: the bytes the sealed set names by hash), appended last
        Vec<Vec<u8>>,
    )> {
        std::mem::take(&mut self.grafted)
    }

    /// Receive a gossiped (or locally-produced) block. Applies structural validation, then grafts
    /// (with contextual validation) or buffers it; grafting cascades to attachable descendants.
    pub fn receive(&mut self, block: Block, now_ts: u64) -> RelayOutcome {
        self.receive_bounded(block, now_ts, usize::MAX)
    }

    /// ⭐ ITEM-6 CASCADE BUDGET — `receive` with a BOUND on how many parked descendants one call may
    /// cascade into the DAG. Every block a receive grafts costs the caller one ~50-65 ms record apply
    /// under the rt lock, and the 200 ms apply budget used to be checked only BETWEEN ingest calls —
    /// one call cascading hundreds of parked blocks was the measured `[tick-slow] drain held the rt
    /// lock 8368ms` (232 occurrences in one boot). The caller sizes `max_cascade` from its remaining
    /// budget; a descendant past the bound simply STAYS in the ORPHAN_CAP-bounded `waiting` map (the
    /// store that already held it) with `strand_hint` set, and `take_stranded_blocks` releases it
    /// into the budgeted preverify/FIFO ingest lane next tick — full gates re-run, nothing dropped,
    /// nothing refused, no second store and no second encoding. `usize::MAX` = the old unbounded
    /// inline cascade (tests and non-runtime callers).
    pub fn receive_bounded(
        &mut self,
        block: Block,
        now_ts: u64,
        max_cascade: usize,
    ) -> RelayOutcome {
        self.grafted.clear();
        self.cascade_bound = max_cascade;
        let id = block.id();
        if self.dag.contains(&id) {
            // TRANSITIVITY: a duplicate delivery may be the ONLY event that ever names a parent whose
            // children are parked — a parent that entered the DAG out-of-band (a DSYNC anchor, a
            // fold-carry graft) never fires `drain_from`, so returning here WITHOUT flagging the
            // strand left `waiting[id]` parked forever behind a present parent. Flag it; the caller
            // releases the waiters through the budgeted preverify/FIFO ingest lane (full gates
            // re-run), never as an inline cascade under the runtime lock. See `strand_hint`.
            if self.waiting.contains_key(&id) {
                self.strand_hint = true;
            }
            return RelayOutcome::Duplicate(id);
        }
        if self.buffered.contains(&id) {
            if self.waiting.values().any(|v| v.iter().any(|b| b.id() == id)) {
                return RelayOutcome::AlreadyBuffered(id);
            }
            self.buffered.remove(&id); // a stale dedupe entry: the block is not waiting anywhere
        }
        if let Err(e) = validate_structural(&block, now_ts, self.dag.params()) {
            return RelayOutcome::Invalid(e);
        }
        self.now_ms = self.now_ms.max(now_ts);
        self.attempt(block)
    }

    /// Try to graft one block: contextual-validate, then add (cascading), buffer (early), or reject.
    fn attempt(&mut self, block: Block) -> RelayOutcome {
        let id = block.id();
        match validate_contextual(&self.dag, &block.header) {
            Ok(()) => {
                let carried = (
                    block.output_notes.clone(),
                    block.account_targets.clone(),
                    block.header.nullifier_root,
                    block.nullifier_proof.padded_tags.clone(),
                    block.nullifier_proof.fold.clone(),
                    block.bond_set.clone(),
                    // The ninth/tenth elements: the carried directory + letter sets — a CASCADED block's
                    // @username sign-ups and letter anchors must fold on the very node that just accepted it,
                    // exactly like its spends and bonds (the multi-path divergence lesson).
                    block.dir_set.clone(),
                    block.letter_set.clone(),
                    // ⛔ THE ELEVENTH ELEMENT — THE COMMITTED POST-ROOT, so a CASCADED block can run the
                    // same nullifier fold the named block runs. Without it the fold's soundness gate
                    // (`adopt_sparse_via_block_fold` compares its re-derivation against this committed
                    // value) had nothing to compare to off the `Added` path, so the fold was keyed to the
                    // one block `RelayOutcome::Added` names and every block that entered behind it in a
                    // cascade skipped `nf_blocks`/`nf_leaves`, the DA-servable nullifier stream
                    // (`da_nf_store`) and the cover-conf accumulator. Carried here, from the block itself,
                    // for exactly the reason the notes/targets above are: a block is applied because it
                    // ENTERED THE DAG, never because of which enum variant described its arrival.
                    block.nullifier_proof.post_root,
                    // ⭐ THE TWELFTH — the block's NOTE TRANSITION (§BA/§BB). Appended, never inserted:
                    // every element here is read positionally, so a new field goes on the END.
                    block.note_transition.clone(),
                    block.credit_set.clone(),
                    // ⭐ THE FOURTEENTH (DB-83) — the CONSTANT-WIDTH transition. Appended, never inserted.
                    block.cover_transition.clone(),
                    // ⭐ THE FIFTEENTH (DB-351) — the block's filed locator tags (`cm ‖ k`). The note transition's
                    // tuples bind each spend's filing digest D, and a peer recomputes D from THESE bytes, so the
                    // transition cannot be verified without them. Appended, never inserted.
                    block.oli_tags.clone(),
                    // ⭐ THE SIXTEENTH (DB-223 Q7) — the block's MEMBER transition: a stated spend's outputs are
                    // justified only when it proves the spend's input exists. Appended, never inserted.
                    block.member_transition.clone(),
                    block.cover_key, // §20.2
                    block.wide_objects.clone(), // §22b, last
                );
                match self.dag.add_block(block) {
                    Ok(added) => {
                        self.grafted.push((
                            added, carried.0, carried.1, carried.2, carried.3, carried.4,
                            carried.5, carried.6, carried.7, carried.8, carried.9, carried.10,
                            carried.11, carried.12, carried.13, carried.14, carried.15,
                        ));
                        self.drain_from(added);
                        RelayOutcome::Added(added)
                    }
                    Err(DagError::Duplicate(_)) => RelayOutcome::Duplicate(id),
                    Err(DagError::BelowSettledBase(r)) => {
                        // DB-282: the block is history on this node, so every orphan parked on it can never connect —
                        // drop them now rather than pulling their ancestry by id until they expire. ⭐ DB-317: the whole
                        // strand, and a strand the peer's live chain merges re-anchors this node, as a late merge does.
                        if self.drop_strand_on_history(&r) {
                            self.history_merge_refused = true;
                        }
                        RelayOutcome::DagRejected(DagError::BelowSettledBase(r))
                    }
                    Err(DagError::MergesPreAnchorHistory(r)) => {
                        // DB-282: a late merge this node cannot place — its waiters are dropped with it, and the node is
                        // told to re-anchor (`take_history_merge_refused`).
                        let _ = self.take_waiting_on(&r);
                        self.history_merge_refused = true;
                        RelayOutcome::DagRejected(DagError::MergesPreAnchorHistory(r))
                    }
                    Err(DagError::ViolatesMergeDepth(r)) => {
                        // DB-361: invalid on every node — nothing waiting on it can ever connect, so its waiters go
                        // with it. No re-anchor: this is a verdict every node shares, not this node's missing history.
                        let _ = self.take_waiting_on(&r);
                        RelayOutcome::DagRejected(DagError::ViolatesMergeDepth(r))
                    }
                    Err(e) => RelayOutcome::DagRejected(e),
                }
            }
            Err(ConsensusError::UnknownParent(p)) => {
                self.buffer(p, block);
                RelayOutcome::Buffered {
                    block: id,
                    missing: p,
                }
            }
            Err(other) => RelayOutcome::Invalid(other),
        }
    }

    /// After `just_added` lands, retry every block that was waiting on it, cascading. Each retry is
    /// re-validated: a now-attachable block that is consensus-invalid is dropped (not grafted).
    ///
    /// ⭐ ITEM-6 CASCADE PAGE — the walk releases at most `cascade_bound` descendants per receive (the
    /// caller sizes it from its remaining 200 ms rt-lock apply budget). A descendant past the page
    /// stays exactly where it already was — parked in `waiting`, now keyed on a PRESENT parent — and
    /// `strand_hint` fires, so `take_stranded_blocks` re-injects it through the preverify/FIFO ingest
    /// lane on the next tick and the walk resumes there, tick after tick, until the park map holds no
    /// releasable block. The page decides WHICH lock hold the ~50-65 ms per-block apply lands in.
    /// The whole blocks the last receive's cascade released (see `cascaded_bodies`); drained by the node.
    pub fn take_cascaded_bodies(&mut self) -> Vec<Block> {
        std::mem::take(&mut self.cascaded_bodies)
    }
    fn drain_from(&mut self, just_added: BlockId) {
        let mut ready = vec![just_added];
        while let Some(parent) = ready.pop() {
            let mut waiters = match self.waiting.remove(&parent) {
                Some(w) => w,
                None => continue,
            };
            if self.cascade_bound == 0 {
                // Page exhausted before this parent's waiters: re-park them untouched. Their parent
                // is in the DAG, so only the strand lane can release them — flag it.
                if !waiters.is_empty() {
                    match self.waiting.get_mut(&parent) {
                        Some(v) => v.append(&mut waiters),
                        None => {
                            self.waiting.insert(parent, waiters);
                        }
                    }
                    self.strand_hint = true;
                }
                continue; // keep walking `ready`: each entry only re-parks, no graft work
            }
            let mut deferred: Vec<Block> = Vec::new();
            for b in waiters {
                if self.cascade_bound == 0 {
                    deferred.push(b);
                    continue;
                }
                let bid = b.id();
                // A shell that came off a served page keeps that mark across a re-park: the readmit
                // door (`readmit_parked_shell`) finds page shells by it. DB-49 forgets the stamp and
                // the age order here so a released child never expires as an orphan; the page mark
                // travels with the block into `park_shell` below.
                let was_page = self.parked_page.contains(&bid);
                self.forget_park(&bid);
                if self.dag.contains(&bid) {
                    // WHAT PRODUCES a parked waiter that is already in the DAG: the out-of-band
                    // insert paths — `Dag::add_anchor` (a #29 DSYNC adopt) and `add_carried_block`
                    // (the v31 fold carry) — place blocks directly, bypassing `receive`, so a block
                    // that parked here earlier can be present by the time its parent grafts. The
                    // skip itself MUST STAY (the block is in the DAG; re-adding is a Duplicate by
                    // construction and its payload was already applied by the path that placed it).
                    // WHAT WAS WRONG is what the bare `continue` dropped: no graft of `bid` will
                    // EVER fire `drain_from` for the blocks parked ON `bid` (only `attempt` fires
                    // it, and `bid` can never be attempted again), so `waiting[bid]` stranded
                    // forever behind a PRESENT parent — transitivity broken at exactly one hop.
                    // Flag the strand; the caller releases `waiting[bid]` through the budgeted
                    // preverify/FIFO ingest lane (full gates re-run), never as an inline cascade
                    // here. See `strand_hint`.
                    if self.waiting.contains_key(&bid) {
                        self.strand_hint = true;
                    }
                    continue;
                }
                match validate_contextual(&self.dag, &b.header) {
                    Ok(()) => {
                        let carried = (
                            b.output_notes.clone(),
                            b.account_targets.clone(),
                            b.header.nullifier_root,
                            b.nullifier_proof.padded_tags.clone(),
                            b.nullifier_proof.fold.clone(),
                            b.bond_set.clone(),
                            // Ninth/tenth: directory + letter sets — see the sibling comment in `attempt`.
                            b.dir_set.clone(),
                            b.letter_set.clone(),
                            // Eleventh: the committed post-root, so this RELEASED descendant folds its
                            // nullifier transition too. This is the exact site the comment below describes
                            // for the DA record — the same reverse-order arrival that left blocks in the DAG
                            // with no record left them with no nullifier fold either, and only the record
                            // half was fixed.
                            b.nullifier_proof.post_root,
                            // ⭐ THE TWELFTH — see the named-block capture above.
                            b.note_transition.clone(),
                            // ⭐ THE THIRTEENTH (§BA) — the carried credit set. A released descendant's
                            // non-spend notes are judged by exactly this, and a descendant whose sidecar
                            // did not ride has every such note refused rather than admitted.
                            b.credit_set.clone(),
                            // ⭐ THE FOURTEENTH (DB-83) — see the named-block capture above.
                            b.cover_transition.clone(),
                            // ⭐ THE FIFTEENTH (DB-351) — see the named-block capture above.
                            b.oli_tags.clone(),
                            // ⭐ THE SIXTEENTH (DB-223 Q7) — see the named-block capture above.
                            b.member_transition.clone(),
                            b.cover_key, // §20.2
                            b.wide_objects.clone(), // §22b, last
                );
                        let body = b.clone();
                        let added = match self.dag.add_block(b) {
                            Ok(added) => Some(added),
                            Err(DagError::BelowSettledBase(r)) => {
                                // DB-282: a released descendant that is history here strands its own waiters for
                                // good — drop them with it (see `attempt`), and re-anchor on a live merge (DB-317).
                                if self.drop_strand_on_history(&r) {
                                    self.history_merge_refused = true;
                                }
                                None
                            }
                            Err(DagError::MergesPreAnchorHistory(r)) => {
                                // DB-282: a released late merge — dropped with its waiters, and the node re-anchors.
                                let _ = self.take_waiting_on(&r);
                                self.history_merge_refused = true;
                                None
                            }
                            Err(DagError::ViolatesMergeDepth(r)) => {
                                // DB-361: invalid everywhere — its waiters can never connect.
                                let _ = self.take_waiting_on(&r);
                                None
                            }
                            Err(_) => None,
                        };
                        if let Some(added) = added {
                            if self.cascaded_bodies.len() < ORPHAN_CAP {
                                self.cascaded_bodies.push(body);
                            }
                            // REPORT THE CASCADE. A buffered descendant grafts here, inside the drain, and
                            // `RelayOutcome::Added` names only the block that triggered it. A caller that
                            // acted on the outcome alone therefore never learned about these blocks at all —
                            // measured: after a reverse-order ingest, two of three blocks were IN THE DAG with
                            // NO DA record, so the payments they carried were unrecorded and unspendable on
                            // that node. Out-of-order arrival is the normal case on a real mesh.
                            self.grafted.push((
                                added, carried.0, carried.1, carried.2, carried.3, carried.4,
                                carried.5, carried.6, carried.7, carried.8, carried.9, carried.10,
                                carried.11, carried.12, carried.13, carried.14, carried.15,
                            ));
                            ready.push(added);
                            // One page slot consumed per RELEASED descendant (the caller pays one
                            // ~50-65 ms record apply per entry in `grafted`).
                            self.cascade_bound = self.cascade_bound.saturating_sub(1);
                        }
                    }
                    Err(ConsensusError::UnknownParent(p2)) => {
                        if was_page {
                            self.park_shell(p2, b);
                        } else {
                            self.buffer(p2, b);
                        }
                    }
                    Err(_) => { /* consensus-invalid now that parents are known -> drop */ }
                }
            }
            if !deferred.is_empty() {
                // Waiters past the page: re-park on the same (present) parent — the dedupe entries in
                // `buffered` were never touched for these — and flag the strand lane to resume.
                match self.waiting.get_mut(&parent) {
                    Some(v) => v.append(&mut deferred),
                    None => {
                        self.waiting.insert(parent, deferred);
                    }
                }
                self.strand_hint = true;
            }
        }
    }

    /// Parents this node is waiting on and has never seen. A caller drains this to ASK for them.
    ///
    /// ⛔⛔⛔ "RE-GOSSIPED BY PEERS LATER" IS AN ASSUMPTION NOTHING GUARANTEES — AND IT IS THE WINDOW.
    ///
    /// user 2026-08-01: "if 1 send works then millions of sends should work automatically by construction...
    /// That smells like a banned moving window bug."
    ///
    /// A block is gossiped ONCE. When its parent is lost, this buffer holds the child and WAITS for a
    /// re-gossip that never comes, so delivery depends on whether the parent happened to survive the wire —
    /// exactly the capacity-dependent shape that makes one send settle and the next not.
    ///
    /// MEASURED 2026-07-31/08-01: ~6 KB multi-cell payment blocks arrive 1-of-3 by block-id correlation while
    /// 1,153-byte single-cell cover blocks always pass; stranded reassembly partials ran 62 -> 34 -> 11 as I
    /// changed WHICH cell the saturated queue drops. Improving the victim is still a window. The fix is that
    /// a node must never depend on a block arriving: it must be able to ASK for any parent it lacks.
    ///
    /// This exposes the wanted set so the runtime can request it. Waiting is replaced by asking.
    ///
    /// O1-FOOTPRINT-REVIEWED: returns ids from the EXISTING `waiting` map, already bounded by ORPHAN_CAP — a
    /// fixed protocol constant. Stores nothing new and adds no term in height, blocks or notes.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: block ids are public DAG identifiers every peer gossips in clear;
    /// never a note, amount, key or owner.
    pub fn missing_parents(&self) -> Vec<BlockId> {
        let mut v: Vec<BlockId> = self.waiting.keys().filter(|id| !self.buffered.contains(*id)).copied().collect();
        v.sort_unstable(); // one order, never the map's (`sorted_ids`)
        v
    }

    /// Remove and return every block parked WAITING ON `parent`. A #29 DSYNC adopt installs the
    /// certified tip as a DAG anchor OUT-OF-BAND (`add_anchor`, bypassing `receive`), so
    /// `drain_from` never fires for it and children parked on that tip would strand forever.
    /// The caller re-injects these through the SAME full ingest path as fresh gossip (every gate
    /// re-runs — nothing is trusted for having been parked); the first graft cascades the rest
    /// via the normal `drain_from`.
    ///
    /// ROOT-LAYER: the strand is PRODUCED here — `waiting` is this relay's own park map and no
    /// other layer can know which children were parked on the anchored id; draining anywhere
    /// else would read a copy of state only this map holds.
    /// MEASURED: live pair 2026-08-23, 240s sample — cross-merge 6 of 82 / 9 of 97 peer blocks
    /// (6-9%), origin log rooted every `Buffered {{ missing: … }}` chain at the DSYNC-adopted
    /// tip id (67a728aa…), 46 Buffered vs 0 Added in the era tail. The re-injection targets
    /// exactly that root.
    /// MUST-STAY-GREEN: `receive`'s outcomes and cascade order are untouched; re-injected blocks
    /// pass the full admission gates again (a forged parked block is still refused); the
    /// convergence + xdev suites and `a_forged_pow_block_is_refused…` stay green.
    /// ⛔⛔ DB-297 — AFTER AN ADOPT, DROP EVERY ORPHAN PARKED AGAINST THE DAG THE ADOPT REPLACED.
    ///
    /// A parked block is LIVE when its ancestry reaches a block this DAG holds, THROUGH THE PARK MAP:
    /// - a child waiting on a held block (the adopted tip, a carried block);
    /// - transitively, the parked children waiting on it, which the cascade drains behind it.
    ///
    /// Every other parked block waits on a parent nothing held can reach. After an adopt it is either pre-anchor
    /// history the settled-base rule (DB-282) can never admit, or a live block the next inventory re-lists (its
    /// candidates are every retained block not in the asker's past). It leaves through `forget_park`, the release the
    /// minute's expiry and the cap eviction already use. The DB-9 evicted ring goes with it: its pairs name parents of
    /// the replaced DAG.
    ///
    /// The runtime calls this BEFORE the tip re-inject (`take_waiting_on(tip)`). That call takes a live strand's head
    /// out of the park map, after which its children could no longer be told apart from junk.
    ///
    /// ROOT-LAYER: `waiting` is this relay's own park map; only it knows which parked strands reach a held block.
    /// MEASURED gate Q8 (n2, docs/DB-297-…), before:
    /// - every orphan except the adopted tip's children survived the adopt;
    /// - a ~115-block pre-anchor chain cycled park → expire → re-park at least 3 times, ~3.3 MB of by-id pulls each;
    /// - the buffer sat at its 32 cap all run ("deferral is NOT catching up: 32 orphan(s)" ×825).
    /// After: the pins `db297_*`.
    /// MUST-STAY-GREEN: the tip re-inject (it still finds the tip's children, which are live), the cascade,
    /// `expire_orphans_named`, and the DB-9 eviction pin.
    /// O1-FOOTPRINT-REVIEWED: one pass over the ORPHAN_CAP-bounded park map; retains nothing.
    pub fn drop_orphans_the_dag_cannot_attach(&mut self) -> usize {
        let mut live: HashSet<BlockId> = HashSet::new();
        let mut frontier: Vec<BlockId> = Self::sorted_ids(self.waiting.keys().filter(|p| self.dag.get(p).is_some()));
        if !frontier.is_empty() {
            // Children of a held block wait on nothing: the strand drain re-injects them through the full gates.
            self.strand_hint = true;
        }
        while let Some(p) = frontier.pop() {
            if let Some(kids) = self.waiting.get(&p) {
                for k in kids {
                    let id = k.id();
                    if live.insert(id) {
                        frontier.push(id);
                    }
                }
            }
        }
        let dead: Vec<BlockId> = self.buffered.iter().filter(|id| !live.contains(*id)).copied().collect();
        for blocks in self.waiting.values_mut() {
            blocks.retain(|b| live.contains(&b.id()));
        }
        self.waiting.retain(|_, v| !v.is_empty());
        for id in &dead {
            self.forget_park(id);
        }
        self.evicted.clear();
        dead.len()
    }

    /// Every parent parked children wait for — the waiting-map keys WITHOUT the "not itself parked"
    /// filter of `missing_parents` (DB-47, run 60: a parent that was parked and then landed by a non-relay
    /// door stayed in `buffered`, so `missing_parents` hid its key and its children aged out "held WHOLE").
    pub fn waiting_parents_all(&self) -> Vec<BlockId> {
        Self::sorted_ids(self.waiting.keys())
    }
    /// Every block parked in the orphan buffer (held, not yet placed) — bounded by ORPHAN_CAP.
    pub fn parked_ids(&self) -> Vec<BlockId> {
        Self::sorted_ids(self.buffered.iter())
    }

    /// ONE ORDER, NOT THE MAP'S (lane b 2026-10-24, T3): a caller asks, re-wants or re-injects in the order these
    /// lists come back, and a HashMap/HashSet's order is per instance (RandomState) — one seed would then ask in two
    /// orders (the class `Reassembler::stuck_requests` showed on the wire, replay-r39.log). Bounded by ORPHAN_CAP.
    fn sorted_ids<'a>(ids: impl Iterator<Item = &'a BlockId>) -> Vec<BlockId> {
        let mut v: Vec<BlockId> = ids.copied().collect();
        v.sort_unstable();
        v
    }

    /// Forget a stale park record for `id` (it landed by another door): the sweep calls this for a parent
    /// the DAG holds whole. Returns whether anything was forgotten.
    /// Forget EVERY park record of `id`: the body set, the page set, the park stamp and the age
    /// order. Every release path — the relay's own cascade, a sweep take, an eviction, an expiry —
    /// goes through here. MEASURED run 62 (2026-09-18): a stamp that outlived its park record read
    /// as an ORPHAN EXPIRY a minute later — 41 "expired" orphans on node 1 that were held whole,
    /// each one arming the bundle trigger and root-splitting a node that was not behind.
    fn forget_park(&mut self, id: &BlockId) {
        self.buffered.remove(id);
        self.parked_page.remove(id);
        self.parked_at_ms.remove(id);
        self.order.retain(|o| o != id);
    }

    pub fn unbuffer(&mut self, id: &BlockId) -> bool {
        let was = self.buffered.contains(id);
        self.forget_park(id);
        for (_, blocks) in self.waiting.iter_mut() {
            blocks.retain(|b| b.id() != *id);
        }
        self.waiting.retain(|_, v| !v.is_empty());
        was
    }

    pub fn take_waiting_on(&mut self, parent: &BlockId) -> Vec<Block> {
        let out = self.waiting.remove(parent).unwrap_or_default();
        for b in &out {
            self.forget_park(&b.id());
        }
        out
    }

    /// ⭐ DB-317 — `refused` was refused as pre-anchor history (`BelowSettledBase`), so every block parked on it,
    /// TRANSITIVELY, can never connect here: the whole strand is dropped now (only the direct waiters were, and the rest
    /// expired a minute later — gate Q11: 43 expiries, all rooted at one refused block). Returns whether any dropped block
    /// names a SETTLED parent: a block of this node's own chain merging the refused strand, i.e. the peer's LIVE chain
    /// builds on it, which only a certified re-anchor places (DB-282's promise, kept today only by the mixed-parent arm).
    /// A stale strand cannot name a settled parent — settled means built at or after the anchor — so it re-anchors
    /// nothing. Bounded: each parked block (≤ ORPHAN_CAP) is taken once, with ≤ dag_width parent lookups.
    fn drop_strand_on_history(&mut self, refused: &BlockId) -> bool {
        let mut live_merge = false;
        let mut stack = vec![*refused];
        while let Some(parent) = stack.pop() {
            for b in self.take_waiting_on(&parent) {
                let settled_parent =
                    b.header.parents.iter().find(|p| self.dag.get(p).map_or(false, |n| n.settled)).copied();
                if let Some(t) = settled_parent {
                    // Once per (refused root, settled parent): see `history_fired`.
                    if !self.history_fired.contains(&(*refused, t)) {
                        self.history_fired.push_back((*refused, t));
                        while self.history_fired.len() > ORPHAN_CAP {
                            self.history_fired.pop_front();
                        }
                        live_merge = true;
                    }
                }
                stack.push(b.id());
            }
        }
        live_merge
    }

    /// TRUE once since the last take: a parked block's "missing" parent turned out to be ALREADY in
    /// the DAG (see the two strand arms in `receive` and `drain_from`), so `waiting` holds at least
    /// one child whose parent is present and that nothing else will ever release. The caller walks
    /// `missing_parents()` for parents the DAG holds and re-injects their waiters via
    /// `take_waiting_on` through the ordinary budgeted ingest lane. A bool, never a queue: the
    /// blocks stay in the ORPHAN_CAP-bounded `waiting` map until released, so this retains nothing.
    /// ⛔ DB-282 — did a receive since the last take refuse a late merge of pre-anchor history? See
    /// `history_merge_refused`; the node answers with a certified re-anchor.
    pub fn take_history_merge_refused(&mut self) -> bool {
        std::mem::take(&mut self.history_merge_refused)
    }

    pub fn take_strand_hint(&mut self) -> bool {
        std::mem::take(&mut self.strand_hint)
    }

    fn buffer(&mut self, missing: BlockId, block: Block) {
        let bid = block.id();
        if self.buffered.contains(&bid) {
            return;
        }
        self.parked_at_ms.insert(bid, self.now_ms); // O1-FOOTPRINT-REVIEWED: bounded by ORPHAN_CAP
        // DB-9 (2026-09-17): the buffer held up to 100,000 FULL blocks (~134 MB measured in run 6 — a
        // phone-class node cannot). At ORPHAN_CAP the OLDEST orphan's body is dropped and its
        // `(child, parent)` kept in a small ring: when the parent lands the child is re-WANTED through the
        // shell lane (structure) and its notes come from the DA lane — nothing is lost, nothing grows.
        while self.buffered.len() >= ORPHAN_CAP {
            let Some(old) = self.order.pop_front() else { break };
            let mut parent_of_old: Option<BlockId> = None;
            for (parent, blocks) in self.waiting.iter_mut() {
                if let Some(pos) = blocks.iter().position(|b| b.id() == old) {
                    blocks.remove(pos);
                    parent_of_old = Some(*parent);
                    break;
                }
            }
            self.waiting.retain(|_, v| !v.is_empty());
            self.buffered.remove(&old);
            self.parked_page.remove(&old);
            self.parked_at_ms.remove(&old);
            if let Some(p) = parent_of_old {
                self.evicted.push_back((old, p));
                while self.evicted.len() > EVICTED_ORPHAN_RING {
                    self.evicted.pop_front();
                }
            }
        }
        if self.buffered.insert(bid) {
            self.waiting.entry(missing).or_default().push(block);
            self.order.push_back(bid);
        }
        // ⭐ DB-135 (2026-09-21): A STRAND THAT IS STILL ARRIVING IS NOT STALE. The children parked on
        // `bid` waited for exactly this block; its arrival — even as an orphan of its own parent — is their
        // progress, so their park clocks restart here. MEASURED on the live pair (19:13, both nodes): by-id
        // descents of 25–37 blocks over Tor landed one parent per round trip and every orphan kept its
        // ORIGINAL stamp, so the top of each strand expired at the minute mark before the bottom landed
        // ("orphan X expired … the parent it waited for, Y, is ABSENT", with Y parked a line later) and the
        // same strand was pulled again from the top, without end. Bitcoin's shape: an orphan's timer
        // measures a request that went unanswered, never a descent that is still landing.
        // ROOT-LAYER: the park stamp is written in exactly two places — the insert above and this restart.
        // MUST-STAY-GREEN: `a_child_released_by_the_sweep_is_never_reported_as_an_expired_orphan` (a stamp
        // without a park record is still dropped, not expired) and the ORPHAN_CAP eviction pin.
        // cons: none — one map lookup and one stamp write per child parked on this block.
        if let Some(children) = self.waiting.get(&bid) {
            let kids: Vec<BlockId> = children.iter().map(|b| b.id()).collect();
            for kid in kids {
                if let Some(at) = self.parked_at_ms.get_mut(&kid) {
                    *at = self.now_ms;
                }
            }
        }
    }

    /// DB-9: the evicted orphans that were waiting on `parent` — their ids, to be re-wanted now that the
    /// parent landed. Drains those entries.
    pub fn take_evicted_children_of(&mut self, parent: &BlockId) -> Vec<BlockId> {
        let mut out = Vec::new();
        self.evicted.retain(|(child, p)| {
            if p == parent {
                out.push(*child);
                false
            } else {
                true
            }
        });
        out
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader, BlockId};

    /// A constant-width note carrier (DB-165): every block ships exactly `BLOCK_NOTE_COMMITMENTS_BYTES` of commitments,
    /// quiet or busy, and the header binds them. These fixtures predated the rule and shipped an EMPTY carrier, so the
    /// structural gate refused them as `NoteCarrierWidth` before any assertion ran (three tests red since the rule
    /// landed). Cover slots here are distinct per-index digests — the gate checks the width and the binding only.
    fn carrier() -> Vec<u8> {
        (0..crate::cover::BLOCK_FIXED_NOTE_COUNT as u64)
            .flat_map(|i| crate::hash::Hash32::hash(&i.to_le_bytes()).0)
            .collect()
    }

    /// DB-9: the 33rd orphan evicts the OLDEST (its body gone, its id kept), the buffer never exceeds
    /// ORPHAN_CAP, and the evicted child is handed back for a re-want when its parent lands.
    #[test]
    fn the_orphan_buffer_evicts_the_oldest_at_its_phone_size_cap_and_remembers_it_for_a_re_want() {
        let mut r = BlockRelay::new(crate::block::genesis_block()).expect("relay");
        let mut kids: Vec<(BlockId, BlockId)> = Vec::new();
        for i in 0..(ORPHAN_CAP + 1) {
            let parent = crate::hash::Hash32::hash(&[b"missing-parent".as_slice(), &[i as u8]].concat());
            let mut b = crate::block::genesis_block();
            b.header.timestamp = 100 + i as u64;
            b.header.parents = vec![parent];
            kids.push((b.id(), parent));
            r.park_shell(parent, b);
            assert!(r.buffered_len() <= ORPHAN_CAP, "⛔ the orphan buffer grew past ORPHAN_CAP");
        }
        let (first_child, first_parent) = kids[0];
        assert!(!r.is_parked(&first_child), "the oldest orphan's body was evicted");
        assert!(r.is_parked(&kids[ORPHAN_CAP].0), "the newest orphan is held");
        let re = r.take_evicted_children_of(&first_parent);
        assert_eq!(re, vec![first_child], "the evicted child is handed back for a re-want when its parent lands");
        assert!(r.take_evicted_children_of(&first_parent).is_empty(), "…once");
    }

    /// ⛔ DB-297 — the drop after an adopt keeps every strand that reaches a held block, releases the rest, and clears
    /// the DB-9 evicted ring (its pairs name parents of the replaced DAG).
    /// TWO-PARTY-REVIEWED: the park map is ONE node's local bookkeeping, so this pins the data structure alone. The
    /// two-party half, where an origin produces and serves and a SECOND node adopts its bundle, drops the orphans and
    /// is re-served nothing pre-anchor, is `node_runtime::sidecar_ask_tests::db297_an_adopt_drops_orphans_parked_
    /// against_the_replaced_dag`.
    #[test]
    fn db297_the_drop_keeps_every_strand_that_reaches_a_held_block_and_clears_the_evicted_ring() {
        let g = crate::block::genesis_block();
        let mk = |parent: BlockId, tag: u64| {
            let mut b = crate::block::genesis_block();
            b.header.timestamp = 5_000 + tag;
            b.header.parents = vec![parent];
            b
        };
        let build = || -> (BlockRelay, BlockId, Block, Block, Block, Block) {
            let mut r = BlockRelay::new(g.clone()).expect("relay");
            let victim_parent = crate::hash::Hash32::hash(b"db297-victim-parent");
            r.park_shell(victim_parent, mk(victim_parent, 0)); // parked FIRST, so the cap evicts it below
            let x = mk(g.id(), 1); // live: it waits on the held genesis
            let y = mk(x.id(), 2); // live: it waits on X, which the cascade drains
            let absent = crate::hash::Hash32::hash(b"db297-absent");
            let j1 = mk(absent, 3); // junk: its parent is held by nothing
            let j2 = mk(j1.id(), 4); // junk: it waits on junk
            r.park_shell(g.id(), x.clone());
            r.park_shell(x.id(), y.clone());
            r.park_shell(absent, j1.clone());
            r.park_shell(j1.id(), j2.clone());
            for k in 0..(ORPHAN_CAP as u64 - 4) {
                let p = crate::hash::Hash32::hash(&[b"db297-single".as_slice(), &k.to_le_bytes()].concat());
                r.park_shell(p, mk(p, 100 + k));
            }
            (r, victim_parent, x, y, j1, j2)
        };
        // CALIBRATION: the buffer is at its cap, and the ring remembers the evicted victim.
        let (mut r, vp, ..) = build();
        assert_eq!(r.buffered_len(), ORPHAN_CAP, "calibration: the buffer is at its cap");
        assert_eq!(r.take_evicted_children_of(&vp).len(), 1, "calibration: the ring holds the evicted victim");
        let (mut r, vp, x, y, j1, j2) = build();
        let dropped = r.drop_orphans_the_dag_cannot_attach();
        assert!(r.is_parked(&x.id()) && r.is_parked(&y.id()), "⛔ DB-297: a strand reaching a held block was dropped");
        assert!(!r.is_parked(&j1.id()) && !r.is_parked(&j2.id()), "⛔ DB-297: a strand reaching nothing held survived");
        assert_eq!(r.buffered_len(), 2, "only the live strand stays");
        assert_eq!(dropped, ORPHAN_CAP - 2, "every other parked block is released");
        assert!(r.take_evicted_children_of(&vp).is_empty(), "⛔ DB-297: the evicted ring survived the adopt");
        assert!(
            r.missing_parents().iter().all(|p| *p == g.id() || *p == x.id()),
            "⛔ DB-297: a descent want still names junk"
        );
    }
    /// MEASURED run 62 (2026-09-18, two real nodes over Tor): node 1 logged 41 orphans "expired after
    /// a minute — held WHOLE" while the sweep had released 42 parked children. The released child's
    /// park STAMP outlived its park record, so a minute later it expired as an orphan naming ITSELF
    /// as its parent — and every false expiry armed the fork-choice bundle trigger. A released child
    /// is not an orphan; only a child still parked can expire (the second arm proves the detector
    /// still fires for a genuinely stranded child).
    #[test]
    fn a_child_released_by_the_sweep_is_never_reported_as_an_expired_orphan() {
        let mut r = BlockRelay::new(crate::block::genesis_block()).expect("relay");
        assert!(r.expire_orphans_named(1_000, 60_000).is_empty(), "nothing parked yet");
        let parent = crate::hash::Hash32::hash(b"missing-parent-released");
        let mut b = crate::block::genesis_block();
        b.header.timestamp = 100;
        b.header.parents = vec![parent];
        let child = b.id();
        r.park_shell(parent, b);
        assert!(r.is_parked(&child), "parked on the missing parent");
        let taken = r.take_waiting_on(&parent);
        assert_eq!(taken.len(), 1, "the sweep took the parked child");
        assert!(!r.is_parked(&child), "a taken child is no longer parked");
        let stranded_parent = crate::hash::Hash32::hash(b"missing-parent-stranded");
        let mut c = crate::block::genesis_block();
        c.header.timestamp = 101;
        c.header.parents = vec![stranded_parent];
        let stranded = c.id();
        r.park_shell(stranded_parent, c);
        let expired = r.expire_orphans_named(70_000, 60_000);
        assert_eq!(
            expired,
            vec![(stranded, stranded_parent)],
            "⛔ only the child STILL parked expires; the child the sweep released must not be reported \
             (run 62: a released child expired a minute later naming itself as its parent)"
        );
        assert!(!r.is_parked(&stranded), "the expired orphan is forgotten");
    }
    /// DB-135 (2026-09-21, live pair 19:13): a by-id descent lands one parent per Tor round trip and each
    /// parent is itself an orphan of the next; with fixed park stamps the strand's top expired at the
    /// minute mark before its bottom landed, and the same strand was pulled again from the top, without
    /// end. A parked child's clock restarts when the block it waited for arrives — even as another orphan.
    /// TWO-PARTY-REVIEWED: the park clock is one node's bookkeeping of its own orphans; the second party
    /// (the peer that serves each parent one round trip at a time) is the real-node restart journey
    /// `a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin`.
    #[test]
    fn a_parked_child_restarts_its_wait_when_its_missing_parent_arrives_as_an_orphan_of_its_own() {
        let mut r = BlockRelay::new(crate::block::genesis_block()).expect("relay");
        let grand = crate::hash::Hash32::hash(b"missing-grandparent-of-the-strand");
        let mut p = crate::block::genesis_block();
        p.header.timestamp = 100;
        p.header.parents = vec![grand];
        let parent_id = p.id();
        let mut c = crate::block::genesis_block();
        c.header.timestamp = 101;
        c.header.parents = vec![parent_id];
        let child_id = c.id();
        // t = 0: the child parks on its missing parent
        assert!(r.expire_orphans_named(0, 60_000).is_empty(), "nothing parked yet");
        r.park_shell(parent_id, c);
        // t = 50 s: the parent lands — as an orphan of ITS missing parent
        assert!(r.expire_orphans_named(50_000, 60_000).is_empty(), "nothing is a minute old yet");
        r.park_shell(grand, p);
        // t = 70 s: the child has been parked 70 s, but its wait was answered at 50 s — it must NOT expire
        assert!(
            r.expire_orphans_named(70_000, 60_000).is_empty(),
            "⛔ a strand whose descent is still landing expired at the minute mark (the live-pair livelock)"
        );
        assert!(r.is_parked(&child_id) && r.is_parked(&parent_id), "both still parked");
        // t = 115 s: the grandparent never came — now BOTH expire, each naming what it waited for
        let expired: std::collections::HashSet<(BlockId, BlockId)> =
            r.expire_orphans_named(115_000, 60_000).into_iter().collect();
        let want: std::collections::HashSet<(BlockId, BlockId)> =
            [(child_id, parent_id), (parent_id, grand)].into_iter().collect();
        assert_eq!(expired, want, "a strand whose descent stopped still expires, naming its waits");
    }

    /// The other direction (the inventory's own, parents first — eclipse.py 2026-11-09): a parent parks on its missing
    /// parent, then its child keeps arriving. CALIBRATION: by its own age the parent is 70 s old at t = 70 s, past the
    /// minute — the per-block rule dropped it while its chain was still landing.
    #[test]
    fn a_parked_parent_whose_children_keep_arriving_is_never_dropped_and_a_stalled_chain_still_expires() {
        let mut r = BlockRelay::new(crate::block::genesis_block()).expect("relay");
        let grand = crate::hash::Hash32::hash(b"missing-root-of-the-side-chain");
        let mut p = crate::block::genesis_block();
        p.header.timestamp = 200;
        p.header.parents = vec![grand];
        let parent_id = p.id();
        let mut c = crate::block::genesis_block();
        c.header.timestamp = 201;
        c.header.parents = vec![parent_id];
        let child_id = c.id();
        assert!(r.expire_orphans_named(0, 60_000).is_empty(), "nothing parked yet");
        r.park_shell(grand, p); // t = 0: the parent parks on the missing root
        assert!(r.expire_orphans_named(50_000, 60_000).is_empty(), "nothing is a minute old yet");
        r.park_shell(parent_id, c); // t = 50 s: its child arrives behind it
        assert!(
            r.expire_orphans_named(70_000, 60_000).is_empty(),
            "⛔ a parent whose chain is still arriving was dropped at its own minute mark (the eclipse split)"
        );
        assert!(r.is_parked(&parent_id) && r.is_parked(&child_id), "the whole chain still parked");
        let expired: std::collections::HashSet<(BlockId, BlockId)> =
            r.expire_orphans_named(115_000, 60_000).into_iter().collect();
        let want: std::collections::HashSet<(BlockId, BlockId)> =
            [(child_id, parent_id), (parent_id, grand)].into_iter().collect();
        assert_eq!(expired, want, "a chain that brought nothing new for a minute expires whole");
    }
    use crate::hash::Hash32;

    // A consensus-valid block on `parents`: work = the DAA expectation over the selected parent.
    fn valid(dag: &Dag, parents: Vec<BlockId>, ts: u64, nonce: u64) -> Block {
        let work = if parents.is_empty() {
            crate::miner::BOOTSTRAP_WORK
        } else {
            let sp = *parents
                .iter()
                .max_by(|a, b| dag.order_key(a).cmp(&dag.order_key(b)))
                .unwrap();
            crate::miner::adaptive_work(dag, Some(sp))
        };
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: carrier(),
            header: BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&carrier()),
                nullifier_tags_root: crate::hash::Hash32::hash(&[]),
                output_notes_root: crate::hash::Hash32::hash(&[]),
                // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
                // commitments are the empty-payload hash the verifier re-derives.
                oli_tags_root: crate::block::da_sidecar_root_of(&[]),
                // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
                credit_set_root: crate::block::da_sidecar_root_of(&[]),
                transitions_root: crate::block::empty_transitions_root(),
                cover_seed_commit: crate::hash::Hash32::ZERO,
                member_ring_commit: crate::hash::Hash32::ZERO,
                account_targets_root: crate::block::da_sidecar_root_of(&[]),
                bond_set_root: crate::block::da_sidecar_root_of(&[]),
                dir_set_root: crate::block::da_sidecar_root_of(&[]),
                letter_set_root: crate::block::da_sidecar_root_of(&[]),
                tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
                level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
                version: 1,
                parents,
                timestamp: ts,
                nonce,
                work,
                pow_bind: Hash32::ZERO,
                tx_merkle_root: Hash32::ZERO,
                frontier_root: Hash32::ZERO,
                nullifier_root: Hash32::ZERO,
                sparse_root: Hash32::ZERO,
                chain_acc: [0u8; 16],
                miner_commitment: Hash32::ZERO,
                account_root: Hash32::ZERO,
            },
            tx_ids: vec![],
            pow_proof: Vec::new(),
            note_transition: None,
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        }
    }

    const NOW: u64 = 100_000_000;

    #[test]
    fn reverse_order_gossip_all_grafts() {
        // Build a valid chain against a reference DAG, then feed the blocks to a fresh relay in
        // REVERSE. All but genesis buffer; feeding genesis cascades them all in (each re-validated).
        let mut refdag = Dag::new();
        let g = valid(&refdag, vec![], 0, 0);
        let gid = g.id();
        refdag.add_block(g.clone()).unwrap();
        let mut chain = vec![g];
        let mut prev = gid;
        for i in 1..=8u64 {
            let b = valid(&refdag, vec![prev], i * 1000, i);
            prev = b.id();
            refdag.add_block(b.clone()).unwrap();
            chain.push(b);
        }
        let mut relay = BlockRelay::from_dag(Dag::new());
        for b in chain.iter().rev() {
            relay.receive(b.clone(), NOW);
        }
        assert_eq!(relay.dag().len(), chain.len());
        assert_eq!(relay.buffered_len(), 0);
        assert_eq!(relay.dag().selected_tip(), Some(prev));
    }

    #[test]
    fn width2_merge_waits_for_both_parents() {
        let mut refdag = Dag::new();
        let g = valid(&refdag, vec![], 0, 0);
        let gid = g.id();
        refdag.add_block(g.clone()).unwrap();
        let a = valid(&refdag, vec![gid], 1000, 1);
        refdag.add_block(a.clone()).unwrap();
        let b = valid(&refdag, vec![gid], 1000, 2);
        refdag.add_block(b.clone()).unwrap();
        let c = valid(&refdag, vec![a.id(), b.id()], 2000, 3); // merges a + b

        let mut relay = BlockRelay::new(g.clone()).unwrap();
        // Deliver the merge FIRST: missing a (or b).
        match relay.receive(c.clone(), NOW) {
            RelayOutcome::Buffered { missing, .. } => {
                assert!(missing == a.id() || missing == b.id())
            }
            o => panic!("expected buffered, got {o:?}"),
        }
        assert!(!relay.dag().contains(&c.id()));
        assert_eq!(relay.receive(a.clone(), NOW), RelayOutcome::Added(a.id()));
        assert!(!relay.dag().contains(&c.id()), "c still waits for b");
        assert_eq!(relay.receive(b.clone(), NOW), RelayOutcome::Added(b.id()));
        assert!(
            relay.dag().contains(&c.id()),
            "c grafts once both parents present"
        );
        assert_eq!(relay.dag().len(), 4);
        assert_eq!(relay.buffered_len(), 0);
    }

    #[test]
    fn rejects_invalid_and_ignores_dup_and_buffered() {
        let refdag = Dag::new();
        let g = valid(&refdag, vec![], 0, 0);
        let mut relay = BlockRelay::new(g.clone()).unwrap();
        let gid = relay.dag().genesis().unwrap();
        let a = valid(relay.dag(), vec![gid], 1000, 1);
        assert_eq!(relay.receive(a.clone(), NOW), RelayOutcome::Added(a.id()));
        assert_eq!(
            relay.receive(a.clone(), NOW),
            RelayOutcome::Duplicate(a.id())
        );

        // A block with the wrong declared work is rejected (consensus-strict).
        let mut badwork = valid(relay.dag(), vec![gid], 3000, 8);
        badwork.header.work += 1;
        assert!(matches!(
            relay.receive(badwork, NOW),
            RelayOutcome::Invalid(ConsensusError::WrongWork { .. })
        ));

        // An orphan buffers, and a second delivery is reported AlreadyBuffered.
        let orphan = Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: carrier(),
            header: BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&carrier()),
                nullifier_tags_root: crate::hash::Hash32::hash(&[]),
                output_notes_root: crate::hash::Hash32::hash(&[]),
                // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
                // commitments are the empty-payload hash the verifier re-derives.
                oli_tags_root: crate::block::da_sidecar_root_of(&[]),
                // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
                credit_set_root: crate::block::da_sidecar_root_of(&[]),
                transitions_root: crate::block::empty_transitions_root(),
                cover_seed_commit: crate::hash::Hash32::ZERO,
                member_ring_commit: crate::hash::Hash32::ZERO,
                account_targets_root: crate::block::da_sidecar_root_of(&[]),
                bond_set_root: crate::block::da_sidecar_root_of(&[]),
                dir_set_root: crate::block::da_sidecar_root_of(&[]),
                letter_set_root: crate::block::da_sidecar_root_of(&[]),
                tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
                level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
                version: 1,
                parents: vec![Hash32::hash(b"unknown-parent")],
                timestamp: 2000,
                nonce: 7,
                work: 1000,
                pow_bind: Hash32::ZERO,
                tx_merkle_root: Hash32::ZERO,
                frontier_root: Hash32::ZERO,
                nullifier_root: Hash32::ZERO,
                sparse_root: Hash32::ZERO,
                chain_acc: [0u8; 16],
                miner_commitment: Hash32::ZERO,
                account_root: Hash32::ZERO,
            },
            tx_ids: vec![],
            pow_proof: Vec::new(),
            note_transition: None,
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        };
        match relay.receive(orphan.clone(), NOW) {
            RelayOutcome::Buffered { .. } => {}
            o => panic!("expected buffered, got {o:?}"),
        }
        assert_eq!(
            relay.receive(orphan.clone(), NOW),
            RelayOutcome::AlreadyBuffered(orphan.id())
        );
    }
}

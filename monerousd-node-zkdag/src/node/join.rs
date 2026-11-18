// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — a node's side of joining by real work (`crate::join_proof`, `docs/JOIN-BY-WORK-SPEC-20261106.md`): what it keeps as
//! the fold moves, what it stamps in its own headers, what it serves, and what a joiner checks and takes.
//! Neither a level root nor a commit is ever a reason to refuse a block, so none of this can halt production or split the chain.

use super::*;
use crate::join_proof::{self as jp, FoldStep, JoinClaim, JoinProof, JoinRefusal, JoinVerdict};

/// How deep a level array is rebuilt when it is not held. A folded block's array is always held, so only unfolded blocks recurse.
const LEVEL_WALK_DEPTH: usize = 256;
/// A bundle is frozen once per this many fold ordinals. The kept bundles must reach back past what a served one needs: a
/// bundle passes the join door only with `join_proof::VOUCHERS` (32) vouching headers above its anchor, the anchor sits at the
/// fold (about 8 blocks under the tip), and the headers that stamp an ordinal below it or another fork's commits do not vouch,
/// so a bundle is servable only from about 45 steps after it froze. At 8 × `FROZEN_KEPT` (56 steps) about two bundles were
/// ever in that range, and a fork's headers often left none (MEASURED 2026-11-08, real nodes: "nothing to serve: 7 bundle(s)
/// frozen", a node 60 blocks behind that could not rejoin). At 16 the kept reach is 112 steps, about 65 of them servable.
/// Cons: a joiner adopts a bundle up to 112 steps under the tip and pulls those blocks after it (at most 16 more than
/// before on average); the 7 files on disk are unchanged.
const FREEZE_EVERY: u64 = 16;

/// Why the last freeze attempt did not freeze, said once per change of reason ("" once one freezes), so a node that serves no
/// bundle says where it stopped. DIGITAL-CASH-PRIVACY-REVIEWED: fixed phrases about public chain structure.
fn freeze_skipped(why: &'static str) {
    static LAST: std::sync::Mutex<&str> = std::sync::Mutex::new("");
    let Ok(mut last) = LAST.lock() else { return };
    if *last != why {
        if why.is_empty() {
            eprintln!("[join-freeze] froze a bundle");
        } else {
            eprintln!("[join-freeze] not frozen: {why}");
        }
        *last = why;
    }
}
/// Bundles kept: the newest with enough vouchers above it is served. The whole-block window stays above the oldest.
const FROZEN_KEPT: usize = 7;
const LEVEL_ARRAYS_KEPT: usize = 512;
/// Fold passes with work held and nothing folded before a node counts as stopped: about 30 s at the two passes a second measured on real nodes.
const FOLD_STUCK_PASSES: u64 = 64;
/// A fold step folded without its body: this node cannot vouch from there on, and is not refused for it.
const UNKNOWN_ADMITTED: [u8; 32] = [0xff; 32];

/// ⭐ SPEED (lane speed4, 2026-11-12) — MEMOS of what a block's level array is built from, by block id. MEASURED (40 s
/// stack sample of a real producer, `prof-g2`): `level_array_of_parents` re-ran the PoUW header hash of every mergeset
/// blue on every template stamp and rebuilt every unfolded block's array from scratch (its `made` map lives one call):
/// about 6 % of the producer's working CPU. Both values are pure functions — a header's digest of the header, and a
/// block's array of the block's own PAST, which never changes once the block exists — so a memo returns exactly what a
/// recomputation would. Only `Some` arrays are kept: a `None` (the walk's depth bound, a block not held) can become
/// `Some` later and is always recomputed. Bounded: each memo is cleared when it reaches [`MEMO_KEPT`] entries.
/// Per PROCESS, so per node in production (one node per process). In a multi-node test process a node may be handed an
/// array it could not yet build itself — always the true array of that block, never a different one.
/// CHAIN-OBJECT: none — a cache of local derivations; no state, no wire, no consensus value changes.
/// Scale: constant (at most `MEMO_KEPT` entries each; an array is a few levels of 32 bytes).
const MEMO_KEPT: usize = 4096;
type Memo<V> = std::sync::Mutex<std::collections::HashMap<[u8; 32], V>>;
fn digest_memo() -> &'static Memo<Hash32> {
    static M: std::sync::OnceLock<Memo<Hash32>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}
fn array_memo() -> &'static Memo<Vec<[u8; 32]>> {
    static M: std::sync::OnceLock<Memo<Vec<[u8; 32]>>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}
fn memo_get<V: Clone>(m: &Memo<V>, k: &[u8; 32]) -> Option<V> {
    m.lock().ok()?.get(k).cloned()
}
fn memo_put<V>(m: &Memo<V>, k: [u8; 32], v: V) {
    if let Ok(mut g) = m.lock() {
        if g.len() >= MEMO_KEPT {
            g.clear();
        }
        g.insert(k, v);
    }
}

impl Node {
    fn header_digest(&self, h: &crate::block::BlockHeader) -> Option<Hash32> {
        self.pow_miner.as_ref().map(|m| m.hasher().hash(&h.preimage()))
    }

    /// [`Self::header_digest`] of the header of the held block `id`, memoised by id (the header is bound into the id).
    fn header_digest_of(&self, id: &BlockId, h: &crate::block::BlockHeader) -> Option<Hash32> {
        self.pow_miner.as_ref()?; // exactly `header_digest`'s answer for a node with no miner
        if let Some(d) = memo_get(digest_memo(), id.as_bytes()) {
            return Some(d);
        }
        let d = self.header_digest(h)?;
        memo_put(digest_memo(), *id.as_bytes(), d);
        Some(d)
    }

    /// The array a block with these parents must commit to. A blue block counts only if its own root is right, by the same rule on every
    /// node, so a miner with a wrong root costs nobody anything and truncates no walk.
    fn level_array_of_parents(&self, parents: &[BlockId], made: &mut std::collections::HashMap<[u8; 32], Option<Vec<[u8; 32]>>>, depth: usize) -> Option<Vec<[u8; 32]>> {
        let gd = self.relay.dag().ghostdag_data(parents);
        let base = self.level_array_of(&gd.selected_parent, made, depth + 1)?;
        let mut members = Vec::with_capacity(gd.mergeset_blues.len());
        for m in &gd.mergeset_blues {
            let header = self.relay.dag().get(m)?.header.clone();
            let counted = self.level_array_of(m, made, depth + 1).is_some_and(|a| jp::level_root(&a) == header.level_root);
            if counted {
                members.push((*m.as_bytes(), jp::level_of(&self.header_digest_of(m, &header)?)));
            }
        }
        Some(jp::next_levels(&base, members))
    }

    fn level_array_of(&self, id: &BlockId, made: &mut std::collections::HashMap<[u8; 32], Option<Vec<[u8; 32]>>>, depth: usize) -> Option<Vec<[u8; 32]>> {
        if let Some(a) = self.join.arrays.get(id.as_bytes()) {
            return Some(a.clone());
        }
        if let Some(a) = made.get(id.as_bytes()) {
            return a.clone();
        }
        if let Some(a) = memo_get(array_memo(), id.as_bytes()) {
            return Some(a);
        }
        if self.relay.dag().genesis() == Some(*id) {
            return Some(Vec::new());
        }
        if depth > LEVEL_WALK_DEPTH {
            return None;
        }
        let parents = self.relay.dag().get(id)?.header.parents.clone();
        let out = self.level_array_of_parents(&parents, made, depth);
        made.insert(*id.as_bytes(), out.clone());
        if let Some(a) = &out {
            memo_put(array_memo(), *id.as_bytes(), a.clone());
        }
        out
    }

    /// What a block this node mines commits to. Called wherever the parents are fixed, before the grind.
    pub(crate) fn stamp_join_fields(&self, header: &mut crate::block::BlockHeader) {
        let mut made = std::collections::HashMap::new();
        header.level_root = match self.level_array_of_parents(&header.parents, &mut made, 0) {
            Some(a) => jp::level_root(&a),
            None => Hash32::ZERO, // peers stop counting this block in their level arrays; it is refused by nobody
        };
        if let Some((o, (_, c))) = self.join.fold.iter().next_back() {
            header.fold_ordinal = *o;
            header.fold_commit = Hash32(*c);
        }
        if let Some((o, (_, c))) = self.join.band.iter().next_back() {
            header.band_ordinal = *o;
            header.band_commit = Hash32(*c);
        }
    }

    /// A fold step: its level array goes in the store, and it waits for its batch's end to join the commit chain.
    pub(crate) fn join_note_fold_step(&mut self, b: &BlockId, ordinal: u64, admitted: Option<&[[u8; 32]]>) {
        let hash = match admitted {
            Some(tags) => jp::admitted_hash(tags),
            None => UNKNOWN_ADMITTED,
        };
        self.join_step_buf.push((ordinal, *b.as_bytes(), hash));
        let mut made = std::collections::HashMap::new();
        let Some(array) = self.level_array_of(b, &mut made, 0) else { return };
        let Some(header) = self.relay.dag().get(b).map(|n| n.header.clone()) else { return };
        let Some(digest) = self.header_digest(&header) else { return };
        self.join.note_array(*b.as_bytes(), array.clone(), LEVEL_ARRAYS_KEPT);
        if jp::level_root(&array) == header.level_root {
            self.join.levels.note(&header, jp::level_of(&digest), array);
        }
    }

    /// The value a joiner recomputes from a bundle, read from this node's own state at a batch's end.
    fn own_state_digest(&self) -> [u8; 32] {
        let frontier = self.frontier_snapshot_for_join();
        let anchor_ordinal = self.fold_chain_tip.and_then(|c| self.certified_fold_base_position(&c));
        let (ring, members) = self.join_rings(anchor_ordinal);
        crate::sync::state_digest(&frontier, &self.state_snapshot(), &ring, &members)
    }

    pub(crate) fn frontier_snapshot_for_join(&self) -> FrontierSnapshot {
        FrontierSnapshot {
            root: *self.note_frontier_root().as_bytes(),
            height: self.note_frontier_count(),
            peaks_hex: self.spend_frontier_peaks_hex(),
        }
    }

    /// The anchor ring and member ring history at a fold position, only when this node holds all of them. One definition, read by the
    /// bundle and by the commit, so the two cannot differ.
    pub(crate) fn join_rings(&self, anchor_ordinal: Option<u64>) -> (Vec<(u64, crate::spend_frontier::Digest4)>, Vec<(u64, Hash32)>) {
        let ring = if self.anchor_ring_is_complete() && self.spine_recent_roots.back().map(|(o, _)| *o) == anchor_ordinal {
            self.anchor_ring()
        } else {
            Vec::new()
        };
        let members = if ring.is_empty() || self.member_ring_commits.back().map(|(o, _)| *o) != anchor_ordinal {
            Vec::new()
        } else {
            self.member_ring_commits()
        };
        (ring, members)
    }

    /// A batch ended: its steps join the commit chain, the last carrying the state a joiner can stand on.
    pub(crate) fn join_batch_end(&mut self) {
        let steps = std::mem::take(&mut self.join_step_buf);
        let Some(last) = steps.last().map(|(o, _, _)| *o) else { return };
        let state = self.own_state_digest();
        for (o, block, admitted) in steps {
            let s = if o == last { state } else { [0u8; 32] };
            self.join.fold_insert(o, FoldStep { block, admitted, state: s });
            if std::env::var("EXP_JOIN_TRACE").is_ok() {
                let x = |b: &[u8; 32]| b[..4].iter().map(|v| format!("{v:02x}")).collect::<String>();
                let c = self.join.fold.get(&o).map_or([0u8; 32], |(_, c)| *c);
                // DIGITAL-CASH-PRIVACY-REVIEWED: prefixes of hashes over public chain state; a temporary trace.
                eprintln!("[join-step] o={o} block={} admitted={} state={} commit={}", x(&block), x(&admitted), x(&s), x(&c));
                if o == last {
                    let frontier = self.frontier_snapshot_for_join();
                    let (ring, members) = self.join_rings(Some(o));
                    let parts: Vec<String> = crate::sync::state_digest_parts(&frontier, &self.state_snapshot(), &ring, &members).iter().map(|p| x(p)).collect();
                    // DIGITAL-CASH-PRIVACY-REVIEWED: prefixes of hashes over public chain state; a temporary trace.
                    eprintln!("[join-parts] o={o} {}", parts.join(" "));
                }
            }
        }
        self.join_sync_band();
    }

    pub(crate) fn join_sync_band(&mut self) {
        let empty = self.band_door.evidence_root_at(0).map(|r| jp::root_hash(&r));
        // The tail is enough: the door moves a few steps between calls, and a rewind stays inside the fold's own reach.
        let held = self.band_door.ring_steps().count();
        let ring: Vec<(u64, [u8; 32])> = self.band_door.ring_steps().skip(held.saturating_sub(256)).map(|(o, r)| (o, jp::root_hash(&r))).collect();
        self.join.band_sync(empty, ring);
        if std::env::var("EXP_JOIN_TRACE").is_ok() {
            if let Some((o, (r, c))) = self.join.band.iter().next_back() {
                let x = |b: &[u8; 32]| b[..4].iter().map(|v| format!("{v:02x}")).collect::<String>();
                // DIGITAL-CASH-PRIVACY-REVIEWED: prefixes of hashes over public chain state; a temporary trace.
                eprintln!("[join-band] o={o} root={} commit={}", x(r), x(c));
            }
        }
    }

    /// Freeze a bundle now and then. Nothing here proves anything, so a bundle exists as soon as the fold has moved.
    pub(crate) fn maybe_freeze_join_bundle(&mut self) {
        let frontier = self.frontier_snapshot_for_join();
        if self.serve_waits_mid_batch(&frontier) {
            return freeze_skipped("the fold stands mid-batch");
        }
        if self.band_door.is_stale() {
            return freeze_skipped("the band door is stale");
        }
        let Some(anchor) = self.fold_chain_tip else { return };
        let Some(position) = self.certified_fold_base_position(&anchor) else { return };
        if position < self.join_last_freeze.saturating_add(FREEZE_EVERY) {
            return;
        }
        // Due from here on: if nothing below freezes, the state moved after its step, the anchor has no level array, or no draft.
        freeze_skipped("due, and the state moved after its fold step, the anchor has no level array, or the draft failed");
        if self.join.fold.get(&position).map(|(s, _)| s.state) != Some(self.own_state_digest()) {
            return; // the state moved after the step was committed: the next batch's end freezes instead
        }
        let Some(array) = self.join.arrays.get(anchor.as_bytes()).cloned() else { return };
        let Some(mut bundle) = self.draft_sync_bundle(frontier) else { return };
        let genesis = self.relay.dag().genesis().map_or(jp::NO_BLOCK, |g| *g.as_bytes());
        let (level, links) = self.join.levels.best_walk(&array, &genesis);
        let history = self.band_door.join_history(crate::nf_evidence::EVIDENCE_WINDOW_STEPS).into_iter().map(|(ordinal, root, admitted)| jp::HistoryStep { ordinal, root, admitted }).collect();
        bundle.join = JoinProof { level, anchor_array: array, links, history, ..JoinProof::default() };
        self.join_last_freeze = position;
        freeze_skipped("");
        self.join_frozen.push_back(bundle);
        if self.join_frozen.len() > FROZEN_KEPT {
            self.join_frozen.pop_front();
        }
        self.save_frozen_join_bundles();
    }

    /// Where the kept bundles live on disk: beside the snapshot, one file per bundle, never more than `FROZEN_KEPT`.
    fn frozen_dir(&self) -> Option<std::path::PathBuf> {
        self.persist_path().and_then(|p| p.parent()).map(|d| d.join("join-frozen"))
    }

    /// The kept bundles survive a restart. A bundle can be served only once `VOUCHERS` blocks stand above its anchor, so a node that
    /// lost them at a restart served nothing for the minutes those blocks take, and no node could join it or heal a deep fork with it
    /// (MEASURED 2026-11-07, the partition-heal check: both nodes restarted, then FewVouchers for every bundle for 5 minutes). Disk: at
    /// most `FROZEN_KEPT` files of one bundle each, the oldest deleted as a new one lands; written once per `FREEZE_EVERY` fold steps.
    fn save_frozen_join_bundles(&self) {
        let Some(dir) = self.frozen_dir() else { return };
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let kept: std::collections::HashSet<String> = self.join_frozen.iter().map(|b| format!("{}.bin", b.anchor_ordinal)).collect();
        if let Some(newest) = self.join_frozen.back() {
            let path = dir.join(format!("{}.bin", newest.anchor_ordinal));
            let tmp = dir.join(format!("{}.tmp", newest.anchor_ordinal));
            if std::fs::write(&tmp, newest.to_wire()).is_ok() && std::fs::rename(&tmp, &path).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if !kept.contains(&e.file_name().to_string_lossy().to_string()) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    /// At restart: the bundles kept before it, oldest first. Each is still served only after it passes the very door a joiner runs
    /// (`serve_join_bundle`), so a bundle from a fork this node has since left, or a damaged file, is never served.
    pub(super) fn load_frozen_join_bundles(&mut self) {
        let Some(dir) = self.frozen_dir() else { return };
        let Ok(entries) = std::fs::read_dir(&dir) else { return };
        let mut loaded: Vec<SyncBundle> = entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|bytes| SyncBundle::from_wire(&bytes))
            .collect();
        loaded.sort_by_key(|b| b.anchor_ordinal);
        let skip = loaded.len().saturating_sub(FROZEN_KEPT);
        self.join_frozen = loaded.into_iter().skip(skip).collect();
        // DIGITAL-CASH-PRIVACY-REVIEWED: a count of public bundles.
        eprintln!("[join-freeze] {} bundle(s) kept from before the restart", self.join_frozen.len());
    }

    /// What a bundle claims, recomputed from its own fields.
    fn join_claim<'a>(&self, bundle: &'a SyncBundle) -> JoinClaim<'a> {
        let band_root = crate::nf_sparse::RefSparseNf::from_band(&bundle.nullifier.band).root();
        JoinClaim {
            anchor: &bundle.anchor_block.header,
            anchor_ordinal: bundle.anchor_ordinal,
            state: crate::sync::state_digest(&bundle.frontier, &bundle.nullifier, &bundle.anchor_ring, &bundle.member_ring_commits),
            declared_work: bundle.blue_work,
            band_root: jp::root_hash(&band_root),
            band_next_ordinal: bundle.nullifier.band_next_ordinal,
            awaiting: bundle.nullifier.band_awaiting.iter().map(|(o, b, a)| (*o, *b, a.as_ref().map(|t| jp::admitted_hash(t)))).collect(),
            genesis: self.relay.dag().genesis().map_or(jp::NO_BLOCK, |g| *g.as_bytes()),
        }
    }

    /// The door. Every bundle passes here before anything it carries is installed.
    pub(crate) fn join_verdict(&self, bundle: &SyncBundle) -> Result<JoinVerdict, JoinRefusal> {
        let Some(m) = self.pow_miner.as_ref() else { return Err(JoinRefusal::NotMined) };
        let hasher = m.hasher();
        jp::verify_join(&bundle.join, &self.join_claim(bundle), &|h| hasher.hash(&h.preimage()))
    }

    /// Fill in what moved since a bundle froze: the headers above its anchor and the commit steps they name.
    fn finish_join_bundle(&self, frozen: &SyncBundle) -> Option<SyncBundle> {
        let anchor = frozen.anchor_block.id();
        let dag = self.relay.dag();
        dag.get(&anchor)?;
        let mut seen: std::collections::HashSet<BlockId> = std::collections::HashSet::new();
        let mut walk = vec![anchor];
        let mut above: Vec<&crate::dag::BlockNode> = Vec::new();
        while let Some(id) = walk.pop() {
            let Some(n) = dag.get(&id) else { continue };
            for child in &n.children {
                if seen.insert(*child) {
                    walk.push(*child);
                    if let Some(c) = dag.get(child) {
                        above.push(c);
                    }
                }
            }
        }
        // Every voucher is a block above the anchor, so a bundle with fewer than `VOUCHERS` of them is refused by the join door
        // whatever else it carries. Asked here, before the fold and band steps are copied and the door re-runs: a serve tried each
        // kept bundle newest first, and the young ones all failed this way, so one answer held the runtime for 13,179 ms and
        // arrived after the asker's 12 s header guard (MEASURED 2026-11-07, heal.py: "a kind-4 ask held the rt lock 13179ms", the
        // joiner's "response header never arrived"). cons: none — the refusal is the door's own, reached earlier.
        if above.len() < jp::VOUCHERS {
            return None;
        }
        // The suffix holds at most `MAX_SUFFIX` headers, so it is filled with the ones that VOUCH for this node's chain first — a
        // header whose fold and band commits are this node's own at the ordinals it names, the very match the join door counts
        // (`join_proof::verify_join`) — then the rest nearest the anchor. Taken by blue score over every descendant, a fork's
        // headers crowded the vouchers out (MEASURED 2026-11-08, real nodes: 24 vouchers of 96 headers, 44 from the other fork,
        // so no bundle was ever served and a node stopped below a deep reorg never re-anchored). The door is unchanged: it still
        // counts every voucher itself. Oldest first in the result: a parent's blue score is below its child's.
        let anchor_ordinal = frozen.anchor_ordinal;
        let vouches = |n: &crate::dag::BlockNode| {
            let h = &n.header;
            h.fold_ordinal >= anchor_ordinal
                && self.join.fold.get(&h.fold_ordinal).is_some_and(|(_, c)| c == h.fold_commit.as_bytes())
                && self.join.band.get(&h.band_ordinal).is_some_and(|(_, c)| c == h.band_commit.as_bytes())
        };
        // ⭐ A-F56: the cut keeps every header's path back to the anchor (`jp::path_closed_suffix`): cutting the vouchers' parents
        // away made this node's own door refuse every bundle it froze after a fold reorg (`Suffix`), so a stopped fold asked
        // for a bundle and none was ever served. Listed parents first, as the door reads them.
        let candidates: Vec<jp::SuffixCandidate<'_>> = above
            .iter()
            .map(|n| jp::SuffixCandidate { id: *n.header.id().as_bytes(), parents: &n.header.parents, blue_score: n.blue_score, vouches: vouches(n) })
            .collect();
        let chosen = jp::path_closed_suffix(anchor.as_bytes(), &candidates, jp::MAX_SUFFIX);
        let by_id: std::collections::HashMap<[u8; 32], &crate::dag::BlockNode> = above.iter().map(|n| (*n.header.id().as_bytes(), *n)).collect();
        let suffix: Vec<crate::block::BlockHeader> = chosen.iter().filter_map(|id| by_id.get(id)).map(|n| n.header.clone()).collect();
        let mut bundle = frozen.clone();
        let oldest_named = bundle.nullifier.band_awaiting.iter().map(|(o, _, _)| *o).chain(bundle.join.history.iter().map(|h| h.ordinal)).min();
        let first_step = oldest_named.map_or(bundle.anchor_ordinal, |o| o.min(bundle.anchor_ordinal));
        bundle.join.fold_start = first_step;
        bundle.join.fold_prev = self.join.fold.get(&first_step.saturating_sub(1)).map_or([0u8; 32], |(_, c)| *c);
        bundle.join.fold_steps = self.join.fold.range(first_step..).take(jp::MAX_STEPS).map(|(_, (s, _))| *s).collect();
        let band_root = jp::root_hash(&crate::nf_sparse::RefSparseNf::from_band(&bundle.nullifier.band).root());
        let band_reach = bundle.join.history.iter().map(|h| h.ordinal).min().map_or(bundle.nullifier.band_next_ordinal.saturating_sub(1), |o| o);
        let band_from = self.join.band.range(..=band_reach).next_back().map(|(o, _)| *o)?;
        bundle.join.band_prev = self.join.band.range(..band_from).next_back().map_or([0u8; 32], |(_, (_, c))| *c);
        bundle.join.band_steps = self.join.band.range(band_from..).take(jp::MAX_STEPS).map(|(o, (r, _))| (*o, *r)).collect();
        bundle.join.suffix = suffix;
        self.carry_anchor_anticone(&mut bundle);
        Some(bundle)
    }

    /// ⭐⭐ A-F94 (lane speed5, 2026-11-17; docs/JOIN-WIDE-DAG-SPEC-20261117.md) — THE SERVED BUNDLE CARRIES ITS ANCHOR'S
    /// MERGE-WINDOW ANTICONE, gathered at SERVE time. A frozen bundle's anchor (the fold root when it froze, served up to ~112
    /// steps later) sits INSIDE the DAG's merge horizon, so on a wide DAG honest new blocks keep merging side blocks born
    /// around it; the joiner held those only as pre-anchor history (or not at all) and DB-282 refused every block that merged
    /// them (MEASURED, launch simulator: joiners stalled together at one tip, `BelowSettledBase` / `MergesPreAnchorHistory` on
    /// parents at blue 173 against a settled top of 168-177; 8-11 re-adopts each, never converging). The anticone here is every
    /// block this node holds that is neither in past(anchor) nor its future, within `ghostdag_k` blue levels under the anchor or
    /// above it, heaviest first, at most `2 × dag_width`, each WHOLE (a body from the live window) with its blue data — the
    /// adopter places them as carried, settled structure (`place_unfolded_carry`, the door every carried body used before
    /// G11b: grind-checked, notes judged with each block's own evidence). Gathered when SERVED, so a side block born after the
    /// freeze rides too. BORROWED: Kaspa's IBD, which sends the pruning point's anticone with its GHOSTDAG data.
    /// The binding is recomputed from the bundle's own fields (`sync_binding`), as every adopter recomputes it.
    /// TRUST, named: the carried blocks' blue data is the server's, exactly as `fold_carry.ancestors`' is today (the join door's
    /// work commitment, `state_digest`, covers the state, not the carry); each header's PoW is checked on adopt.
    /// SCALE: one past walk and one future walk of the anchor (bounded by the DAG's keep window) per serve; at most 2 × dag_width
    /// bodies (~409 KB each, MEASURED median frame) — a wide anchor adds up to that, a narrow one nothing.
    fn carry_anchor_anticone(&self, bundle: &mut SyncBundle) {
        let at = bundle.anchor_block.id();
        let dag = self.relay.dag();
        let Some(at_score) = dag.get(&at).map(|n| n.blue_score) else { return };
        let floor = at_score.saturating_sub(self.params().ghostdag_k);
        let past: std::collections::HashSet<BlockId> = dag.past_of(&at).into_iter().collect();
        let future: std::collections::HashSet<BlockId> = dag.descendants_of(&at).into_iter().collect();
        let mut side: Vec<(u128, BlockId, u64)> = dag
            .block_ids()
            .into_iter()
            .filter(|id| *id != at && !past.contains(id) && !future.contains(id))
            .filter_map(|id| dag.get(&id).filter(|n| n.blue_score >= floor).map(|n| (n.blue_work, id, n.blue_score)))
            .collect();
        side.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.as_bytes().cmp(y.1.as_bytes())));
        side.dedup_by(|x, y| x.1 == y.1);
        side.truncate(self.params().dag_width.max(1) * 2);
        let ids: Vec<BlockId> = side.iter().map(|(_, id, _)| *id).collect();
        let bodies = self.whole_blocks_by_ids(&ids, crate::arti_transport::BULK_FRAME_MAX / 2);
        let have: std::collections::HashSet<[u8; 32]> = bundle.fold_carry.unfolded.iter().map(|(b, _, _)| *b.id().as_bytes()).collect();
        let mut added = 0usize;
        for b in bodies {
            if have.contains(b.id().as_bytes()) {
                continue;
            }
            if let Some((work, _, score)) = side.iter().find(|(_, id, _)| *id == b.id()) {
                // ⛔⛔ J12 (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J12) — A CARRIED BODY TRAVELS WITH
                // ITS SIDECAR. `unfolded` crosses the wire by serde, which skips a body's cover key, wide objects and spend
                // transactions (§22b/§22c); `carry_for` ships them in `FoldCarry::sidecars` beside every carried body and this
                // carry did not. MEASURED (netsim launch, main 4e899429, scratchpad r5_join.log:27470-27496): joiner n4 held
                // such a body whole, its fold printed "held body true · wide bytes missing true" until the chain outgrew the
                // reach, it went stale, and its fold stood at 160 against node 0's 212 at the end. The same entry shape and the
                // same filter as `carry_for` (node.rs, "§22b: the in-process sidecar of every carried body"); placement
                // re-attaches it and drops every wide byte the sealed set does not name, so a forged entry changes nothing.
                // SCALE: one entry per carried anticone body (≤ 2 × dag_width); nothing grows with nodes or height.
                // cons: the bundle grows by those bodies' wide objects and spends, which a body that folds needs anyway.
                if b.cover_key.is_some() || !b.wide_objects.is_empty() || !b.tx_bodies.is_empty() {
                    bundle.fold_carry.sidecars.push((*b.id().as_bytes(), b.cover_key, b.wide_objects.clone(), b.tx_bodies.clone()));
                }
                bundle.fold_carry.unfolded.push((b, *work, *score));
                added += 1;
            }
        }
        if added == 0 {
            return;
        }
        let digest = bundle.fold_carry.digest();
        bundle.decider.chain_acc = crate::sync::sync_binding(
            &bundle.decider.tip,
            bundle.decider.blue_score,
            &bundle.frontier,
            &bundle.nullifier,
            &bundle.genesis_commit,
            &at,
            bundle.anchor_blue_score,
            &digest,
            bundle.blue_work,
            bundle.anchor_blue_work,
            bundle.anchor_ordinal,
        );
        // DIGITAL-CASH-PRIVACY-REVIEWED: a count of public blocks and a public position.
        eprintln!("[join-serve] A-F94: carried {added} block(s) of the anchor's anticone (anchor ordinal {})", bundle.anchor_ordinal);
    }

    /// The newest frozen bundle that passes the very door a joiner runs. `None`: nothing to serve yet, and a young chain is walked by lanes.
    pub(crate) fn serve_join_bundle(&self) -> Option<Vec<u8>> {
        let mut last_refusal = None;
        for frozen in self.join_frozen.iter().rev() {
            let Some(bundle) = self.finish_join_bundle(frozen) else { continue };
            match self.join_verdict(&bundle) {
                Ok(v) => {
                    let wire = bundle.to_wire();
                    // DIGITAL-CASH-PRIVACY-REVIEWED: public chain position, a count, an estimate of public work and a byte length.
                    eprintln!("[join-serve] anchor ordinal {} vouchers {} estimate {} declared {} level {} links {} bytes {}", bundle.anchor_ordinal, v.vouchers, v.estimate, bundle.blue_work, bundle.join.level, bundle.join.links.len(), wire.len());
                    return Some(wire);
                }
                Err(r) => {
                    if std::env::var("EXP_JOIN_TRACE").is_ok() {
                        let ords: Vec<(u64, u64)> = bundle.join.suffix.iter().rev().map(|h| (h.fold_ordinal, h.band_ordinal)).collect();
                        // DIGITAL-CASH-PRIVACY-REVIEWED: public positions; a temporary trace.
                        eprintln!("[join-try] anchor {} fold_start {} steps {} band {:?} suffix {} {:?} refused {:?}", bundle.anchor_ordinal, bundle.join.fold_start, bundle.join.fold_steps.len(), bundle.join.band_steps.first().map(|(o, _)| *o), ords.len(), &ords[..ords.len().min(12)], r);
                    }
                    last_refusal = Some(r);
                }
            }
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a count and a refusal name.
        eprintln!("[join-serve] nothing to serve: {} bundle(s) frozen, the newest refusal {:?}", self.join_frozen.len(), last_refusal);
        None
    }

    /// This node's fold has stopped, and a verified bundle stands past it. Whatever stopped the fold, the bundle restarts it, and a bundle only ever
    /// moves a fold forward, so a hostile peer gains nothing it could not gain with any other verified bundle. MEASURED 2026-11-06: a joined node at the
    /// tip with its fold 90 steps behind refused 11 served bundles as "inside the catch-up depth". The block lanes can never close that gap: the blocks
    /// are already here. cons: one bundle, about 1 MB, per restart of a stopped fold.
    pub(crate) fn fold_stuck_behind(&self, anchor_ordinal: u64) -> bool {
        // Both counters: each names a different way a pass ends with nothing folded, and a wait on one block counts only in the second.
        let waited_on_one_block = self.fold_wait_on.is_some_and(|(_, passes)| passes >= FOLD_STUCK_PASSES);
        // ⛔⛔ J14 (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J14) — A FOLD WAITING ON THE BAND'S PROOF LANE IS NOT
        // STUCK. When a viewless node's fold waits on a block whose evidence names a band step its band has noted but not yet applied
        // (the step's admitted set is known; only its band proof is owed), the band moves when that proof lands — a lane with its own
        // bound (P7's escape, A-F98). Taking a bundle then is no repair: every adopt drops the nullifier view and the warm job building
        // it. MEASURED (testnet gate, main 7344a2c8, netsim replica census): the joiner re-adopted 6 times, each "the fold stopped
        // behind a verified bundle", while its band awaited steps 82..86 with every admitted set known (0 unknown) and its warm had taken
        // 32,768 tags — each adopt dropped the warm, so it never held a view and never stopped needing the band; it stayed 33-58
        // blocks behind and failed "the joiner reaches one chain and a current view" in 600 s.
        // The wait stays bounded: an awaiting step whose set is UNKNOWN still counts as stuck, and the P7 escape ends a band that
        // waits too long on a proof; a stale spine (`spine_stale`) re-anchors as before.
        // AI RESISTANT: (b) code — a peer can only delay a proof, which P7 bounds; nothing here admits or refuses a block.
        // SCALE: one read of the awaiting window (≤ the lag cap) per bundle weighed; nothing grows.
        // cons: a fold that waits on the band alone takes the bundle only once P7 has ended that wait, not after 64 passes.
        let awaiting = self.band_door.awaiting_steps();
        let band_owes_only_proofs = !awaiting.is_empty() && awaiting.iter().all(|(_, _, admitted)| admitted.is_some());
        // ⛔⛔ J15 (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J15) — "STUCK" IS THE CHAIN OUTGROWING THE FOLD, NOT A
        // COUNT OF PASSES. A no-progress pass is counted whenever the fold has nothing new at its root — the ordinary depth wait and side
        // blocks not yet merged included ("[fold-depth] … not stuck" is printed and the counter still rises) — and passes come at the
        // node's own loop rate, so 64 of them are seconds. MEASURED (testnet gate, main b80c0511, replica census): the joiner took 6 bundles
        // on "the fold stopped behind a verified bundle" with NO fold wait logged before any of them; the passing launch simulator prints
        // the same "stranded" lines on its seeds (318). Each adopt dropped the joiner's view and warm and landed it 40-60 levels behind.
        // Now the streak also needs the selected chain to have grown `UNFOLDED_BODY_REACH_LEVELS` (32) levels since it began — A-F63's
        // own measure for a wait that outgrew its reach.
        // AI RESISTANT: (b) code; a peer gains nothing — it can only delay a node's adopt, and a fold that truly stopped still crosses 32 levels.
        // SCALE: two u64 reads; nothing grows.
        // cons: a fold that truly stopped takes a bundle after the chain grows 32 levels, not after 64 passes.
        let tip_len = self.relay.dag().selected_tip().and_then(|t| self.relay.dag().get(&t)).map_or(0, |n| n.selected_chain_len);
        let outgrown = tip_len.saturating_sub(self.fold_progress_since_len) >= crate::node::UNFOLDED_BODY_REACH_LEVELS;
        ((self.fold_no_progress_passes >= FOLD_STUCK_PASSES && outgrown) || waited_on_one_block)
            && !band_owes_only_proofs
            && anchor_ordinal > self.served_seq()
    }

    /// Give the band door the steps before its position, once it stands where the bundle says.
    pub(crate) fn join_install_history(&mut self) {
        let steps: Vec<(u64, crate::spend_frontier::Digest4, Vec<[u8; 32]>)> = self.join.history.iter().map(|h| (h.ordinal, h.root, h.admitted.clone())).collect();
        self.band_door.install_history(&steps);
    }

    /// A joiner took a bundle: it can now commit and serve from where the bundle stands.
    pub(crate) fn join_take_adopted(&mut self, bundle: &SyncBundle) {
        let p = &bundle.join;
        self.join.seed_fold(p.fold_start, p.fold_prev, &p.fold_steps, bundle.anchor_ordinal);
        let at_band = p.band_steps.iter().rposition(|(o, _)| *o < bundle.nullifier.band_next_ordinal).map_or(0, |i| i + 1);
        self.join.seed_band(p.band_prev, &p.band_steps[..at_band]);
        self.join.history = p.history.clone();
        self.join.note_array(*bundle.anchor_block.id().as_bytes(), p.anchor_array.clone(), LEVEL_ARRAYS_KEPT);
        self.join.levels.inherit(p);
        self.join_last_freeze = bundle.anchor_ordinal;
    }
}

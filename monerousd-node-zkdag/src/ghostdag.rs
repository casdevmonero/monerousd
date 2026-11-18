// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! GHOSTDAG ordering (brick 2): the mergeset, the k-cluster blue/red coloring, and the true
//! blue-score / blue-work recurrence — the PHANTOM/GHOSTDAG consensus ordering over the DAG.
//! (Parameter rationale + the no-growth argument live in the README.)
//!
//! For a new block `B` with selected parent `sp`:
//!   * `mergeset(B) = past(B) \ past(sp)` — the blocks `B` merges that `sp` had not seen. It
//!     INCLUDES `sp` (since `sp ∉ past(sp)`), which is always colored blue.
//!   * a mergeset block `K` is **blue** iff adding it keeps the blue set a *k-cluster*: the number
//!     of blues in `K`'s anticone is `≤ k`, and adding `K` pushes no existing blue's blue-anticone
//!     over `k`. Otherwise `K` is **red**.
//!   * `blue_score(B) = blue_score(sp) + |mergeset_blues(B)|`;
//!     `blue_work(B) = blue_work(sp) + Σ work(b)` over `b ∈ mergeset_blues(B)`.
//!
//! No-growth: the mergeset is the anticone `B` merges — bounded by that anticone, not by chain
//! height. The `past(sp)` boundary scan is capped (the `merge_depth_cap` param), so per-block
//! GHOSTDAG work is O(1) in chain height. `k` and the cap are governance-tunable ([`crate::params`]).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::block::BlockId;
use crate::dag::Dag;

/// The GHOSTDAG data computed for a block from its parents. `k` (the k-cluster bound) and the
/// merge-depth scan cap come from the DAG's governance-tunable [`crate::params::ChainParams`].
#[derive(Clone, Debug)]
pub struct GhostdagData {
    /// The selected parent = the parent maximizing `(blue_work, id)`.
    pub selected_parent: BlockId,
    /// Mergeset blocks colored blue (includes `selected_parent`, topologically ordered).
    pub mergeset_blues: Vec<BlockId>,
    /// Mergeset blocks colored red (in the k-cluster sense).
    pub mergeset_reds: Vec<BlockId>,
    /// `blue_score(sp) + |mergeset_blues|`.
    pub blue_score: u64,
    /// `blue_work(sp) + Σ work(mergeset_blues)`.
    pub blue_work: u128,
}

impl Dag {
    /// Compute GHOSTDAG data for a NON-genesis block whose `parents` are all already in the DAG.
    pub fn ghostdag_data(&self, parents: &[BlockId]) -> GhostdagData {
        let Some(sp) = parents.iter().max_by(|a, b| self.order_key(a).cmp(&self.order_key(b))).copied() else {
            // a parentless block is refused by the structural gate (`ConsensusError::NoParents`) before it reaches
            // here; the datum of one names no parent and carries no score or work, so nothing can mistake it for a
            // chain position (fail closed on the block, never on the process)
            return GhostdagData {
                selected_parent: BlockId::default(),
                mergeset_blues: Vec::new(),
                mergeset_reds: Vec::new(),
                blue_score: 0,
                blue_work: 0,
            };
        };

        // The mergeset, topologically ordered (ancestors first). Includes sp.
        let mergeset = self.mergeset(parents, &sp);

        // Ancestor-within-mergeset sets (DP over the topo order): anc[i] = mergeset members that
        // are ancestors of mergeset[i]. Bounded by the mergeset size (no-growth).
        let idx: HashMap<BlockId, usize> = mergeset
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();
        let mut anc: Vec<HashSet<BlockId>> = vec![HashSet::new(); mergeset.len()];
        for (i, m) in mergeset.iter().enumerate() {
            let mut ai: HashSet<BlockId> = HashSet::new();
            if let Some(node) = self.get(m) {
                for p in &node.header.parents {
                    if let Some(&pi) = idx.get(p) {
                        ai.insert(*p);
                        for a in &anc[pi] {
                            ai.insert(*a);
                        }
                    }
                }
            }
            anc[i] = ai;
        }

        // x ∈ anticone(y): neither is an ancestor of the other (within the mergeset).
        let in_anticone = |x_idx: usize, y_idx: usize| -> bool {
            !anc[y_idx].contains(&mergeset[x_idx]) && !anc[x_idx].contains(&mergeset[y_idx])
        };

        // k-cluster coloring. sp seeds the blue set FIRST (so every other mergeset block counts it
        // in its anticone); each remaining mergeset block is then tested in topological order.
        // `k_bound` is the active governance-tunable k-cluster bound (see crate::params).
        let k_bound = self.params().ghostdag_k;
        let mut blues: Vec<BlockId> = vec![sp];
        let mut reds: Vec<BlockId> = Vec::new();
        let mut blue_anticone_size: HashMap<BlockId, u64> = HashMap::new();
        blue_anticone_size.insert(sp, 0);

        for (ki, k) in mergeset.iter().enumerate() {
            if *k == sp {
                continue;
            }
            let mut ok = true;
            let mut k_anticone = 0u64;
            let mut to_bump: Vec<BlockId> = Vec::new();
            for b in &blues {
                let bi = idx[b];
                if in_anticone(bi, ki) {
                    k_anticone += 1;
                    if k_anticone > k_bound {
                        ok = false;
                        break;
                    }
                    if blue_anticone_size[b] + 1 > k_bound {
                        ok = false;
                        break;
                    }
                    to_bump.push(*b);
                }
            }
            if ok {
                blues.push(*k);
                blue_anticone_size.insert(*k, k_anticone);
                for b in to_bump {
                    if let Some(n) = blue_anticone_size.get_mut(&b) {
                        *n += 1;
                    }
                }
            } else {
                reds.push(*k);
            }
        }

        // sp is a parent the caller found in the DAG; the (unreachable) miss scores from zero rather than aborting
        let (sp_score, sp_work) = self.get(&sp).map_or((0, 0), |n| (n.blue_score, n.blue_work));
        let blue_score = sp_score + blues.len() as u64;
        let mut blue_work = sp_work;
        for b in &blues {
            blue_work = blue_work.saturating_add(self.get(b).map(|n| n.header.work).unwrap_or(0));
        }

        GhostdagData {
            selected_parent: sp,
            mergeset_blues: blues,
            mergeset_reds: reds,
            blue_score,
            blue_work,
        }
    }

    /// `mergeset(B) = past(B) \ past(sp)`, topologically ordered, INCLUDING `sp`. BFS from the
    /// parents, stopping at the `past(sp)` boundary — bounded by the merged anticone, not height.
    /// The mergeset size, computed with the walk STOPPING once it passes `bound`.
    ///
    /// Returns `Err(actual_seen)` when the block merges more than the shape bound allows. The early stop is
    /// the whole point: measuring the size by building the full mergeset first would pay the very unbounded
    /// cost this is meant to prevent, so validation work stays `O(bound)` = `O(protocol shape)` even when a
    /// peer floods it.
    pub fn mergeset_size_within(
        &self,
        parents: &[BlockId],
        sp: &BlockId,
        bound: usize,
    ) -> Result<usize, usize> {
        let past_sp = self.bounded_past(sp);
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = parents.iter().copied().collect();
        let mut n = 0usize;
        while let Some(x) = queue.pop_front() {
            if past_sp.contains(&x) || !visited.insert(x) {
                continue;
            }
            n += 1;
            if n > bound {
                return Err(n);
            }
            if let Some(node) = self.get(&x) {
                for p in &node.header.parents {
                    queue.push_back(*p);
                }
            }
        }
        Ok(n)
    }

    fn mergeset(&self, parents: &[BlockId], sp: &BlockId) -> Vec<BlockId> {
        let past_sp = self.bounded_past(sp);
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = parents.iter().copied().collect();
        let mut ms: Vec<BlockId> = Vec::new();
        while let Some(x) = queue.pop_front() {
            if past_sp.contains(&x) {
                continue; // x ∈ past(sp): sp already saw it, not merged by B
            }
            if !visited.insert(x) {
                continue;
            }
            ms.push(x); // includes sp (sp ∉ past(sp))
            if let Some(n) = self.get(&x) {
                for p in &n.header.parents {
                    queue.push_back(*p);
                }
            }
        }
        // ⛔⛔⛔ CANONICAL ORDER, NOT ARRIVAL ORDER. This sorted by `topo_order` — the LOCAL INSERTION
        // counter. Two nodes handed the same blocks in different orders therefore built different mergeset
        // orderings, and the k-cluster colouring below walks exactly this order: different order can mean
        // different blues/reds, hence a different `blue_score`/`blue_work`, hence two honest nodes disagreeing
        // about the canonical chain. That is a same-chain split manufactured purely by the order packets
        // happened to arrive in — with no attacker and no fork in sight.
        //
        // The order must be a function of the DAG, never of this node's history with it. Emit a topological
        // order (ancestors first, which the colouring requires) breaking every tie on `(blue_work, id)` —
        // both values every node derives identically from the blocks themselves.
        ms = self.canonical_topological_order(ms);
        ms
    }

    /// Deterministic topological order over a mergeset: ancestors first, ties broken by `(blue_work, id)`.
    ///
    /// Kahn's algorithm over the edges INTERNAL to the mergeset, always emitting the smallest ready block by
    /// `(blue_work, id)`. Both keys are pure functions of the DAG, so every node produces the identical
    /// sequence for the identical block set — which is the property the colouring, and therefore consensus,
    /// depends on. Cost is a function of the mergeset (itself bounded by the protocol shape bound), never of
    /// chain height.
    fn canonical_topological_order(&self, ms: Vec<BlockId>) -> Vec<BlockId> {
        let member: HashSet<BlockId> = ms.iter().copied().collect();
        // in_ms_parents[x] = x's parents that are themselves in the mergeset (the only ordering constraints).
        let mut pending: HashMap<BlockId, usize> = HashMap::new();
        let mut children_in_ms: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for m in &ms {
            let parents: Vec<BlockId> = self
                .get(m)
                .map(|n| {
                    n.header
                        .parents
                        .iter()
                        .copied()
                        .filter(|p| member.contains(p))
                        .collect()
                })
                .unwrap_or_default();
            pending.insert(*m, parents.len());
            for p in parents {
                children_in_ms.entry(p).or_default().push(*m);
            }
        }
        let key = |id: &BlockId| (self.get(id).map(|n| n.blue_work).unwrap_or(0), *id);
        let mut ready: Vec<BlockId> = ms.iter().copied().filter(|m| pending[m] == 0).collect();
        ready.sort_by_key(key);
        let mut out: Vec<BlockId> = Vec::with_capacity(ms.len());
        while !ready.is_empty() {
            let next = ready.remove(0);
            out.push(next);
            if let Some(kids) = children_in_ms.get(&next) {
                for k in kids.clone() {
                    if let Some(c) = pending.get_mut(&k) {
                        *c -= 1;
                        if *c == 0 {
                            ready.push(k);
                        }
                    }
                }
                ready.sort_by_key(key);
            }
        }
        // A cycle is impossible in a DAG; if anything were left it would silently vanish from the mergeset,
        // so append it deterministically rather than dropping blocks (a dropped block is a dropped note).
        if out.len() != ms.len() {
            let emitted: HashSet<BlockId> = out.iter().copied().collect();
            let mut rest: Vec<BlockId> = ms.into_iter().filter(|m| !emitted.contains(m)).collect();
            rest.sort_by_key(|id| key(id));
            out.extend(rest);
        }
        out
    }

    /// The strict ancestors of `sp` (NOT including `sp`), BFS bounded by [`MERGE_DEPTH_CAP`].
    /// ⛔ A-F97 (lane speed5, 2026-11-17) — IS THIS NODE'S GHOSTDAG OF A BLOCK ON `parents` EXACTLY A FULL NODE'S? True iff every
    /// block the two walks of [`Self::ghostdag_data`] reach is HELD: `bounded_past(sp)` up to its cap, and the mergeset BFS. An
    /// absent id is inserted by those walks but never expanded, so the past(sp) this node sees is smaller and the mergeset may
    /// hold a block a full node counts inside past(sp). With every block held, both walks visit exactly the blocks, in exactly
    /// the order, a node holding the whole DAG visits (same headers, same parent order, same cap), and the colouring reads only
    /// those blocks, so the figures are the full node's. Used by `Dag::add_carried_block` to check a server's stated figures.
    /// SCALE: ≤ merge_depth_cap + mergeset lookups, the same walk `ghostdag_data` already makes; constant in height and nodes.
    pub(crate) fn ghostdag_view_is_exact(&self, parents: &[BlockId], sp: &BlockId) -> bool {
        let cap = self.params().merge_depth_cap;
        let Some(spn) = self.get(sp) else { return false };
        let mut past: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = spn.header.parents.clone().into();
        while let Some(x) = queue.pop_front() {
            if past.len() >= cap {
                break;
            }
            if !past.insert(x) {
                continue;
            }
            match self.get(&x) {
                Some(n) => queue.extend(n.header.parents.iter().copied()),
                None => return false,
            }
        }
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = parents.iter().copied().collect();
        while let Some(x) = queue.pop_front() {
            if past.contains(&x) || !visited.insert(x) {
                continue;
            }
            match self.get(&x) {
                Some(n) => queue.extend(n.header.parents.iter().copied()),
                None => return false,
            }
        }
        true
    }

    fn bounded_past(&self, sp: &BlockId) -> HashSet<BlockId> {
        let cap = self.params().merge_depth_cap;
        let mut past: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = self
            .get(sp)
            .map(|n| n.header.parents.clone())
            .unwrap_or_default()
            .into();
        while let Some(x) = queue.pop_front() {
            if past.len() >= cap {
                break;
            }
            if !past.insert(x) {
                continue;
            }
            if let Some(n) = self.get(&x) {
                for p in &n.header.parents {
                    queue.push_back(*p);
                }
            }
        }
        past
    }
}

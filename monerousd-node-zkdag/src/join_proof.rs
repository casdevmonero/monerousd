// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — JOINING BY REAL WORK (`docs/JOIN-BY-WORK-SPEC-20261106.md`).
//!
//! What a node with no chain checks before it stands on a served state: a chain of headers whose own digests show the hashing, and recent
//! headers that commit to that state. Nothing here is proved by the server, so serving costs no proving.
//!
//! BORROWED: Kaspa's pruning proof and header state commitment, NiPoPoW's superblock levels, Bitcoin's most-work rule.
//!
//! ROOT-LAYER: a joiner's whole trust in a state is decided here, at the one door every bundle passes, from header bytes it hashes itself.
//! MEASURED: the whole-chain certificate this replaces verified an invented chain claiming 2^120 work in 680.8 s (real prover and verifier,
//! no chain held), and a new node stood at height 0 for 30 minutes against a tip of 471.
//! MUST-STAY-GREEN: this module's tamper tests; `scratchpad/net/join.py` on real nodes.
//!
//! §9.6 door: (1) proof of work: every level and suffix header's digest is recomputed against its own target, and a level is read from
//! that digest; (2) own proof: links by Merkle path and by `parents`, commits by hash chain; (3) value: it decides whether a state is
//! installed, and a false state needs [`VOUCHERS`] blocks of real work on the forger's own fork; (4) replay: the adopt door's `NotHeavier`;
//! (5) work bound: [`M`], [`MAX_SUFFIX`], [`MAX_STEPS`] checked before any hash; (6) parity with the gossip door: its grind and target; its
//! contextual checks cannot run here, because a joiner holds no ancestry, which is why this exists.

use crate::block::BlockHeader;
use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// How many level slots a header's root covers. A digest has 256 bits, and more than 127 leading zero bits is out of reach of `u128` work.
pub const LEVELS: usize = 128;
const LEVEL_PATH_DEPTH: usize = 7;
/// Newest headers kept, and links walked, per level. The estimate's relative error is about 1 / sqrt(M).
pub const M: usize = 64;
/// Most headers a proof may carry above its anchor. The whole-block window is 64.
pub const MAX_SUFFIX: usize = 96;
/// Blocks that must commit to the served state.
pub const VOUCHERS: usize = 32;
/// Most fold or band steps a proof may carry to reach its vouchers.
pub const MAX_STEPS: usize = 512;
/// A declared weight may exceed the measured estimate by this factor, which absorbs the estimate's noise and parallel blocks a level walk misses.
pub const WEIGHT_CAP_FACTOR: u128 = 2;
/// A suffix header's declared work may be below the level chain's median by this factor: difficulty can fall when miners leave, and a
/// forger must not hide in a suffix of easy blocks.
pub const SUFFIX_WORK_SLACK: u128 = 4;
/// A walk that stops short of the chain's start must show at least this many links: a single lucky digest proves little, and a sample this small says
/// nothing about the chain's difficulty. A walk that reaches the start may be shorter: a young chain has nothing more to show.
pub const MIN_LINKS: usize = 8;
/// The empty slot of a level array: no block of that level yet.
pub const NO_BLOCK: [u8; 32] = [0u8; 32];

/// A digest's level: its leading zero bits, read the way `hash_meets_target` reads a digest. Absolute, never relative to declared work.
#[must_use]
pub fn level_of(digest: &Hash32) -> usize {
    let mut zeros = 0usize;
    for byte in digest.as_bytes() {
        zeros += byte.leading_zeros() as usize;
        if *byte != 0 {
            break;
        }
    }
    zeros.min(LEVELS - 1)
}

/// The level array after a block: its selected parent's array, updated with each blue mergeset block in canonical order. Trimmed of
/// empty slots at the top, so a young chain holds little.
#[must_use]
pub fn next_levels(parent: &[[u8; 32]], mergeset: impl IntoIterator<Item = ([u8; 32], usize)>) -> Vec<[u8; 32]> {
    let mut out = parent.to_vec();
    for (id, level) in mergeset {
        if out.len() <= level {
            out.resize(level + 1, NO_BLOCK);
        }
        for slot in &mut out[..=level] {
            *slot = id;
        }
    }
    out
}

fn slot_at(array: &[[u8; 32]], level: usize) -> [u8; 32] {
    match array.get(level) {
        Some(id) => *id,
        None => NO_BLOCK,
    }
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/level-tree/v1");
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

fn zero_at(depth: usize) -> [u8; 32] {
    let mut z = NO_BLOCK;
    for _ in 0..depth {
        z = node_hash(&z, &z);
    }
    z
}

/// The nodes of the fixed-depth tree, row by row, leaves first, with absent right siblings read as the empty subtree of that depth.
fn tree_rows(array: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut row = array.to_vec();
    let mut rows = Vec::with_capacity(LEVEL_PATH_DEPTH + 1);
    for depth in 0..LEVEL_PATH_DEPTH {
        let empty = zero_at(depth);
        if row.is_empty() {
            row.push(empty);
        }
        if row.len() % 2 == 1 {
            row.push(empty);
        }
        let parents = row.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
        rows.push(row);
        row = parents;
    }
    rows.push(row);
    rows
}

/// The header's `level_root`: a Merkle root over [`LEVELS`] slots. The empty array has a root too, the same on every node.
#[must_use]
pub fn level_root(array: &[[u8; 32]]) -> Hash32 {
    let rows = tree_rows(array);
    Hash32(rows[LEVEL_PATH_DEPTH][0])
}

fn level_path(array: &[[u8; 32]], level: usize) -> [[u8; 32]; LEVEL_PATH_DEPTH] {
    let rows = tree_rows(array);
    let mut path = [NO_BLOCK; LEVEL_PATH_DEPTH];
    let mut i = level;
    for (depth, slot) in path.iter_mut().enumerate() {
        *slot = match rows[depth].get(i ^ 1) {
            Some(sibling) => *sibling,
            None => zero_at(depth),
        };
        i >>= 1;
    }
    path
}

fn path_reaches(root: &Hash32, level: usize, value: &[u8; 32], path: &[[u8; 32]; LEVEL_PATH_DEPTH]) -> bool {
    if level >= LEVELS {
        return false;
    }
    let mut h = *value;
    let mut i = level;
    for sibling in path {
        h = if i & 1 == 0 { node_hash(&h, sibling) } else { node_hash(sibling, &h) };
        i >>= 1;
    }
    h == *root.as_bytes()
}

/// `fold_commit(o) = H(fold_commit(o-1), o, block, admitted, state)`. `state` is zero inside a batch: only a batch's end is a state anyone can stand on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldStep {
    pub block: [u8; 32],
    pub admitted: [u8; 32],
    pub state: [u8; 32],
}

#[must_use]
pub fn fold_commit_next(prev: &[u8; 32], ordinal: u64, s: &FoldStep) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/fold-commit/v1");
    h.update(prev);
    h.update(&ordinal.to_le_bytes());
    h.update(&s.block);
    h.update(&s.admitted);
    h.update(&s.state);
    *h.finalize().as_bytes()
}

#[must_use]
pub fn band_commit_next(prev: &[u8; 32], ordinal: u64, root: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/band-commit/v1");
    h.update(prev);
    h.update(&ordinal.to_le_bytes());
    h.update(root);
    *h.finalize().as_bytes()
}

/// A fold step's admitted tags as one value, in any order: the fold and the band's journal list them differently.
#[must_use]
pub fn admitted_hash(admitted: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/fold-admitted/v1");
    let mut sorted = admitted.to_vec();
    sorted.sort_unstable();
    for t in &sorted {
        h.update(t);
    }
    *h.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelLink {
    pub header: BlockHeader,
    pub next: [u8; 32],
    pub path: [[u8; 32]; LEVEL_PATH_DEPTH],
}

/// One band step before where a bundle's band stands. A block's spend evidence may name a step up to the evidence window back, so a joiner needs
/// these to reach the verdict every other node reaches on the blocks above its anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryStep {
    pub ordinal: u64,
    pub root: crate::spend_frontier::Digest4,
    pub admitted: Vec<[u8; 32]>,
}

/// A band root as the band chain names it.
#[must_use]
pub fn root_hash(d: &crate::spend_frontier::Digest4) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/band-root/v1");
    for lane in d.iter() {
        h.update(&lane.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// What a bundle carries to show its anchor sits on real work and its state is vouched for.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinProof {
    pub level: u8,
    /// The anchor's whole level array, so a joiner can check the blocks above it.
    pub anchor_array: Vec<[u8; 32]>,
    pub links: Vec<LevelLink>,
    /// Headers built on the anchor, oldest first, each naming the anchor or an earlier one as a parent. All of them, not only the selected chain:
    /// any block above the anchor took real work, and with two producers crossing the selected chain is about 60 % of them.
    pub suffix: Vec<BlockHeader>,
    pub fold_start: u64,
    pub fold_prev: [u8; 32],
    pub fold_steps: Vec<FoldStep>,
    pub band_prev: [u8; 32],
    /// Band steps that moved the root, in order, from at or before the oldest history step.
    pub band_steps: Vec<(u64, [u8; 32])>,
    pub history: Vec<HistoryStep>,
}

/// The state a bundle would install, as far as the proof is concerned.
pub struct JoinClaim<'a> {
    pub anchor: &'a BlockHeader,
    pub anchor_ordinal: u64,
    pub state: [u8; 32],
    pub declared_work: u128,
    pub band_root: [u8; 32],
    pub band_next_ordinal: u64,
    /// Fold steps the band has not applied: `(ordinal, block, admitted)`.
    pub awaiting: Vec<(u64, [u8; 32], Option<[u8; 32]>)>,
    pub genesis: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinVerdict {
    pub estimate: u128,
    pub vouchers: usize,
    pub fold_commit: [u8; 32],
    pub band_commit: [u8; 32],
    pub band_ordinal: u64,
}

/// Every way a proof fails, named for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinRefusal {
    TooLarge,
    AnchorArray,
    Link,
    LevelTooLow,
    NotMined,
    ShortWalk,
    WeightAboveEstimate,
    Suffix,
    SuffixEasy,
    State,
    Band,
    Awaiting,
    History,
    FewVouchers,
}

/// The check every joiner runs, and every server runs on itself before serving. `digest` is the chain's PoUW hash of a header.
/// The work of the heaviest single path from the anchor up through a suffix: Bitcoin's chainwork, summed along parent links, so a block
/// beside the path (one GHOSTDAG would colour red) adds nothing. Headers are taken in the order the suffix lists them, parents first, as
/// `verify_join` requires; a header whose parents are all outside the anchor and the suffix adds nothing. The anchor's own `blue_work`
/// plus this is the least work the serving chain can hold, which is what a node on a deep fork compares with its own tip.
/// One block of the anchor's future, as the server choosing a suffix sees it.
#[derive(Clone, Copy, Debug)]
pub struct SuffixCandidate<'a> {
    pub id: [u8; 32],
    pub parents: &'a [crate::block::BlockId],
    pub blue_score: u64,
    /// Its fold and band commits are the server's own at the ordinals it names (what [`verify_join`] counts as a voucher).
    pub vouches: bool,
}

/// ⭐ A-F56 (lane goodshalt, 2026-11-13) — WHICH OF THE ANCHOR'S DESCENDANTS A SERVED BUNDLE CARRIES: at most `max` of them, every one
/// with a parent path back to the anchor inside the set, listed parents first, vouchers nearest the anchor taken first. The result
/// passes [`verify_join`]'s suffix rule ("a parent among the anchor and the headers listed before it") BY CONSTRUCTION.
///
/// WHY (MEASURED 2026-11-13, lane goodshalt's three real nodes, main b200022e + A-F54): the server sorted the descendants vouchers
/// first and cut the list at `MAX_SUFFIX`. After a fold reorg the blocks between the anchor and the vouchers carry commits that no
/// longer match the server's own, so the cut removed them and the vouchers above lost every path to the anchor: its own door
/// refused the bundle with `Suffix` ("nothing to serve: 7 bundle(s) frozen, the newest refusal Some(Suffix)", 40 of 46 serves on
/// the node ahead). Two nodes whose folds had stopped asked for a bundle 93 and 105 times, got none, and never restarted: the
/// repair that ends a stopped fold could not run.
/// BORROWED: Bitcoin's `headers` message (a contiguous chain from a known block, never a selection of loose headers) and
/// Kahn's topological order for the listing.
/// SCALE: `max` (96) headers, each path walk at most the anchor's depth below the tip inside the candidates; no term in the bonded
/// set or in height beyond the walk the server already makes. AI RESISTANT: (b) the server's own choice; the joiner's door
/// (`verify_join`) is unchanged and still checks every rule, so a lying server gains nothing it could not before.
/// cons: a path block that does not vouch takes a slot a voucher could have had (vouchers nearest the anchor go first, so their
/// paths are the shortest); 0 bytes beyond the existing 96-header bound.
pub fn path_closed_suffix(anchor: &[u8; 32], candidates: &[SuffixCandidate<'_>], max: usize) -> Vec<[u8; 32]> {
    use std::collections::{HashMap, HashSet};
    let by_id: HashMap<[u8; 32], &SuffixCandidate<'_>> = candidates.iter().map(|c| (c.id, c)).collect();
    let mut order: Vec<&SuffixCandidate<'_>> = candidates.iter().collect();
    order.sort_by_key(|c| (!c.vouches, c.blue_score, c.id));
    let mut kept: HashSet<[u8; 32]> = HashSet::new();
    for c in order {
        if kept.len() >= max {
            break;
        }
        if kept.contains(&c.id) {
            continue;
        }
        // the path from `c` down to the anchor or to a block already kept, through parents in the anchor's future
        let mut path = vec![c.id];
        let mut cur = c;
        let reached = loop {
            let ps: Vec<[u8; 32]> = cur.parents.iter().map(|p| *p.as_bytes()).collect();
            if ps.iter().any(|p| p == anchor || kept.contains(p)) {
                break true;
            }
            // a vouching parent first (it counts at the door), then the one nearest the anchor
            let Some(next) = ps.iter().filter_map(|p| by_id.get(p)).min_by_key(|x| (!x.vouches, x.blue_score, x.id)) else {
                break false; // no parent in the anchor's future: not a descendant the door can place
            };
            path.push(next.id);
            cur = next;
        };
        if reached && kept.len() + path.len() <= max {
            kept.extend(path);
        }
    }
    // parents first: Kahn's order over the kept set, ties by blue score then id
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(kept.len());
    let mut placed: HashSet<[u8; 32]> = HashSet::new();
    let mut left: Vec<&SuffixCandidate<'_>> = kept.iter().filter_map(|id| by_id.get(id).copied()).collect();
    left.sort_by_key(|c| (c.blue_score, c.id));
    while !left.is_empty() {
        let Some(i) = left.iter().position(|c| c.parents.iter().all(|p| !kept.contains(p.as_bytes()) || placed.contains(p.as_bytes()))) else {
            break; // a cycle cannot occur in a DAG; nothing unplaceable is listed
        };
        let c = left.remove(i);
        placed.insert(c.id);
        out.push(c.id);
    }
    out
}

pub fn suffix_chain_work(anchor: &[u8; 32], suffix: &[BlockHeader]) -> u128 {
    let mut path: std::collections::HashMap<[u8; 32], u128> = std::collections::HashMap::with_capacity(suffix.len() + 1);
    path.insert(*anchor, 0);
    let mut best = 0u128;
    for h in suffix {
        let below = h.parents.iter().filter_map(|p| path.get(p.as_bytes()).copied()).max();
        if let Some(below) = below {
            let w = below.saturating_add(h.work);
            best = best.max(w);
            path.insert(*h.id().as_bytes(), w);
        }
    }
    best
}

pub fn verify_join(proof: &JoinProof, claim: &JoinClaim<'_>, digest: &dyn Fn(&BlockHeader) -> Hash32) -> Result<JoinVerdict, JoinRefusal> {
    use JoinRefusal as R;
    if proof.links.len() > M
        || proof.suffix.len() > MAX_SUFFIX
        || proof.fold_steps.len() > MAX_STEPS
        || proof.band_steps.len() > MAX_STEPS
        || proof.anchor_array.len() > LEVELS
    {
        return Err(R::TooLarge);
    }
    if level_root(&proof.anchor_array) != claim.anchor.level_root {
        return Err(R::AnchorArray);
    }
    // ── the level chain ──
    let level = proof.level as usize;
    if level >= LEVELS {
        return Err(R::LevelTooLow);
    }
    let mut want = slot_at(&proof.anchor_array, level);
    let mut counted = 0u128;
    let mut works: Vec<u128> = Vec::with_capacity(proof.links.len());
    for link in &proof.links {
        let id = *link.header.id().as_bytes();
        if id != want {
            return Err(R::Link);
        }
        if id != claim.genesis {
            let d = digest(&link.header);
            if !crate::pow::hash_meets_target(&d, link.header.work) {
                return Err(R::NotMined);
            }
            if level_of(&d) < level {
                return Err(R::LevelTooLow);
            }
            counted += 1;
            works.push(link.header.work);
        }
        if !path_reaches(&link.header.level_root, level, &link.next, &link.path) {
            return Err(R::Link);
        }
        want = link.next;
    }
    if works.len() < MIN_LINKS && want != NO_BLOCK && want != claim.genesis {
        return Err(R::ShortWalk);
    }
    let estimate = match counted.checked_shl(level as u32) {
        Some(e) => e,
        None => return Err(R::LevelTooLow),
    };
    if claim.declared_work > estimate.saturating_mul(WEIGHT_CAP_FACTOR) {
        return Err(R::WeightAboveEstimate);
    }
    works.sort_unstable();
    let median_work = match works.get(works.len() / 2) {
        Some(w) => *w,
        None => 0, // a chain with no level blocks yet: nothing to compare a suffix with
    };
    // ── the suffix ──
    let mut above: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::with_capacity(proof.suffix.len() + 1);
    above.insert(*claim.anchor.id().as_bytes());
    for h in &proof.suffix {
        if !h.parents.iter().any(|p| above.contains(p.as_bytes())) {
            return Err(R::Suffix);
        }
        if !crate::pow::hash_meets_target(&digest(h), h.work) {
            return Err(R::NotMined);
        }
        // A young chain's first blocks carry the bootstrap difficulty, well above what its DAA settles on: too small a sample to judge by.
        if works.len() >= MIN_LINKS && h.work.saturating_mul(SUFFIX_WORK_SLACK) < median_work {
            return Err(R::SuffixEasy);
        }
        above.insert(*h.id().as_bytes());
    }
    // ── the state, on the fold chain ──
    let idx = |o: u64| o.checked_sub(proof.fold_start).map(|d| d as usize).filter(|d| *d < proof.fold_steps.len());
    let at = idx(claim.anchor_ordinal).ok_or(R::State)?;
    let anchor_step = &proof.fold_steps[at];
    if anchor_step.state != claim.state || anchor_step.block != *claim.anchor.id().as_bytes() {
        return Err(R::State);
    }
    let mut fold_chain: Vec<[u8; 32]> = Vec::with_capacity(proof.fold_steps.len());
    let mut c = proof.fold_prev;
    for (i, s) in proof.fold_steps.iter().enumerate() {
        c = fold_commit_next(&c, proof.fold_start + i as u64, s);
        fold_chain.push(c);
    }
    // ── the band, on the band chain ──
    let at_band = proof.band_steps.iter().rposition(|(o, _)| *o < claim.band_next_ordinal).ok_or(R::Band)?;
    let (band_ordinal, band_root) = proof.band_steps[at_band];
    if band_root != claim.band_root {
        return Err(R::Band);
    }
    let mut band_chain: Vec<(u64, [u8; 32])> = Vec::with_capacity(proof.band_steps.len());
    let mut b = proof.band_prev;
    let mut last = None;
    for (o, root) in &proof.band_steps {
        if last.is_some_and(|l| *o <= l) {
            return Err(R::Band);
        }
        last = Some(*o);
        b = band_commit_next(&b, *o, root);
        band_chain.push((*o, b));
    }
    // ── what the band has yet to apply is on the fold chain too ──
    for (o, block, admitted) in &claim.awaiting {
        let step = idx(*o).map(|i| &proof.fold_steps[i]).ok_or(R::Awaiting)?;
        if step.block != *block || admitted.is_some_and(|a| a != step.admitted) {
            return Err(R::Awaiting);
        }
    }
    // ── the steps before the band's position are on both chains ──
    if proof.history.len() > MAX_STEPS {
        return Err(R::TooLarge);
    }
    for h in &proof.history {
        let step = idx(h.ordinal).map(|i| &proof.fold_steps[i]).ok_or(R::History)?;
        if step.admitted != admitted_hash(&h.admitted) {
            return Err(R::History);
        }
        let moved = proof.band_steps.iter().rposition(|(o, _)| *o <= h.ordinal).ok_or(R::History)?;
        if proof.band_steps[moved].1 != root_hash(&h.root) {
            return Err(R::History);
        }
    }
    // ── the vouchers ──
    let mut vouchers = 0usize;
    let (mut fold_only, mut band_only, mut below) = (0usize, 0usize, 0usize);
    for h in &proof.suffix {
        let fold_ok = h.fold_ordinal >= claim.anchor_ordinal && idx(h.fold_ordinal).is_some_and(|i| fold_chain[i] == *h.fold_commit.as_bytes());
        let band_ok = band_chain.iter().any(|(o, c)| *o == h.band_ordinal && c == h.band_commit.as_bytes());
        below += usize::from(h.fold_ordinal < claim.anchor_ordinal);
        fold_only += usize::from(fold_ok && !band_ok);
        band_only += usize::from(band_ok && !fold_ok);
        if fold_ok && band_ok {
            vouchers += 1;
        }
    }
    if vouchers < VOUCHERS {
        // Public header positions and counts only: which of the two commitments the suffix failed to match.
        eprintln!(
            "[join-check] {vouchers} voucher(s) of {} suffix header(s): {fold_only} match the fold chain only, {band_only} the band chain \
             only, {below} name a fold step below the anchor; {} band step(s) in the proof",
            proof.suffix.len(),
            proof.band_steps.len()
        );
        return Err(R::FewVouchers);
    }
    Ok(JoinVerdict {
        estimate,
        vouchers,
        fold_commit: fold_chain[at],
        band_commit: band_chain[at_band].1,
        band_ordinal,
    })
}

/// One retained header. A node that folded the block holds its whole array; a node that inherited it holds only the link it was given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LevelEntry {
    header: BlockHeader,
    array: Vec<[u8; 32]>,
    inherited: Option<(usize, LevelLink)>,
}

/// The newest [`M`] headers of each level: a bounded store that survives the block window, and all a node needs to prove work from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelStore {
    by_level: Vec<std::collections::VecDeque<[u8; 32]>>,
    entries: std::collections::HashMap<[u8; 32], LevelEntry>,
}

impl LevelStore {
    fn remember(&mut self, level: usize, id: [u8; 32]) {
        if self.by_level.len() <= level {
            self.by_level.resize_with(level + 1, Default::default);
        }
        let q = &mut self.by_level[level];
        if q.contains(&id) {
            return;
        }
        q.push_back(id);
        if q.len() > M {
            if let Some(gone) = q.pop_front() {
                if !self.by_level.iter().any(|q| q.contains(&gone)) {
                    self.entries.remove(&gone);
                }
            }
        }
    }

    /// Note a folded block. A re-fold of a held block is harmless: an id appears once per level.
    pub fn note(&mut self, header: &BlockHeader, level: usize, array: Vec<[u8; 32]>) {
        let id = *header.id().as_bytes();
        self.entries.insert(id, LevelEntry { header: header.clone(), array, inherited: None });
        for l in 0..=level.min(LEVELS - 1) {
            self.remember(l, id);
        }
    }

    /// Keep what a joiner was shown, so it can show the next joiner.
    pub fn inherit(&mut self, proof: &JoinProof) {
        let level = proof.level as usize;
        for link in proof.links.iter().rev() {
            let id = *link.header.id().as_bytes();
            self.entries.entry(id).or_insert(LevelEntry { header: link.header.clone(), array: Vec::new(), inherited: Some((level, link.clone())) });
            self.remember(level, id);
        }
    }

    fn link_from(&self, id: &[u8; 32], level: usize) -> Option<LevelLink> {
        let e = self.entries.get(id)?;
        if let Some((inherited_level, link)) = &e.inherited {
            return (*inherited_level == level).then(|| link.clone());
        }
        Some(LevelLink { header: e.header.clone(), next: slot_at(&e.array, level), path: level_path(&e.array, level) })
    }

    /// Walk one level from an array, up to [`M`] links. Stops where the store's reach ends.
    fn walk(&self, array: &[[u8; 32]], level: usize, genesis: &[u8; 32]) -> Vec<LevelLink> {
        let mut out = Vec::new();
        let mut want = slot_at(array, level);
        while out.len() < M && want != NO_BLOCK {
            let Some(link) = self.link_from(&want, level) else { break };
            let id = *link.header.id().as_bytes();
            let next = link.next;
            out.push(link);
            if id == *genesis {
                break;
            }
            want = next;
        }
        out
    }

    /// The level whose walk shows the most work, with its links.
    #[must_use]
    pub fn best_walk(&self, array: &[[u8; 32]], genesis: &[u8; 32]) -> (u8, Vec<LevelLink>) {
        let mut best = (0u8, Vec::new(), 0u128);
        for level in 0..array.len().min(LEVELS) {
            let links = self.walk(array, level, genesis);
            let counted = links.iter().filter(|l| *l.header.id().as_bytes() != *genesis).count() as u128;
            let reached_start = links.last().is_none_or(|l| l.next == NO_BLOCK || *l.header.id().as_bytes() == *genesis);
            if links.len() < MIN_LINKS && !reached_start {
                continue;
            }
            let Some(est) = counted.checked_shl(level as u32) else { continue };
            if est >= best.2 {
                best = (level as u8, links, est);
            }
        }
        (best.0, best.1)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// All a node keeps for joining. Bounded: [`LevelStore`], a fixed count of arrays, a fixed count of commit steps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinState {
    pub levels: LevelStore,
    pub arrays: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>>,
    array_order: std::collections::VecDeque<[u8; 32]>,
    pub fold: std::collections::BTreeMap<u64, (FoldStep, [u8; 32])>,
    pub band: std::collections::BTreeMap<u64, ([u8; 32], [u8; 32])>,
    /// The history this node joined with, kept so a restart soon after joining can still judge the blocks above its anchor.
    pub history: Vec<HistoryStep>,
}

/// Commit steps kept. A joiner needs the band's lag plus the suffix, well inside this.
const COMMIT_STEPS_KEPT: usize = 1024;

impl JoinState {
    pub fn note_array(&mut self, id: [u8; 32], array: Vec<[u8; 32]>, keep: usize) {
        if self.arrays.insert(id, array).is_none() {
            self.array_order.push_back(id);
        }
        while self.array_order.len() > keep {
            if let Some(gone) = self.array_order.pop_front() {
                self.arrays.remove(&gone);
            }
        }
    }

    /// A step at `o`, replacing anything at or above it: a re-fold rewrites the chain from there.
    pub fn fold_insert(&mut self, o: u64, step: FoldStep) {
        self.fold.split_off(&o);
        let prev = match self.fold.range(..o).next_back() {
            Some((_, (_, c))) => *c,
            None => NO_BLOCK,
        };
        self.fold.insert(o, (step, fold_commit_next(&prev, o, &step)));
        while self.fold.len() > COMMIT_STEPS_KEPT {
            self.fold.pop_first();
        }
    }

    /// Bring the band chain to what the door holds. The chain names only the steps that moved the root, so idle steps, which nodes may apply in
    /// different drains, cannot make two nodes differ. A rewind shows as a different root, and the chain is rewritten from there.
    pub fn band_sync(&mut self, empty_root: Option<[u8; 32]>, ring: Vec<(u64, [u8; 32])>) {
        if self.band.is_empty() {
            if let Some(root) = empty_root {
                self.band.insert(0, (root, band_commit_next(&NO_BLOCK, 0, &root)));
            }
        }
        let mut newest = None;
        let first_held = self.band.keys().next().copied();
        for (o, root) in &ring {
            if first_held.is_some_and(|f| *o < f) {
                continue; // before this chain begins: a joiner's chain starts where its bundle's did
            }
            newest = Some(*o);
            let before = self.band.range(..*o).next_back().map(|(_, (r, c))| (*r, *c));
            let moved = before.map(|(r, _)| r) != Some(*root);
            match (moved, self.band.get(o).map(|(r, _)| r == root)) {
                (true, Some(true)) | (false, None) => {}
                (false, Some(_)) => {
                    self.band.split_off(o);
                }
                (true, _) => {
                    self.band.split_off(o);
                    let prev = match before {
                        Some((_, c)) => c,
                        None => NO_BLOCK,
                    };
                    self.band.insert(*o, (*root, band_commit_next(&prev, *o, root)));
                }
            }
        }
        if let Some(n) = newest {
            self.band.split_off(&n.saturating_add(1));
        }
        while self.band.len() > COMMIT_STEPS_KEPT {
            self.band.pop_first();
        }
    }

    /// What a joiner was shown, up to where it stands. It folds the rest itself.
    pub fn seed_fold(&mut self, start: u64, prev: [u8; 32], steps: &[FoldStep], through: u64) {
        self.fold.clear();
        let mut c = prev;
        for (i, s) in steps.iter().enumerate() {
            let o = start + i as u64;
            if o > through {
                break;
            }
            c = fold_commit_next(&c, o, s);
            self.fold.insert(o, (*s, c));
        }
    }

    pub fn seed_band(&mut self, prev: [u8; 32], steps: &[(u64, [u8; 32])]) {
        self.band.clear();
        let mut c = prev;
        for (o, root) in steps {
            c = band_commit_next(&c, *o, root);
            self.band.insert(*o, (*root, c));
        }
    }
}

#[cfg(test)]
mod path_closed_suffix_tests {
    use super::*;
    use crate::hash::Hash32;

    fn id(tag: u8, i: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1..5].copy_from_slice(&i.to_be_bytes());
        b
    }

    /// The door's own suffix rule, as `verify_join` applies it: every header has a parent among the anchor and the ones before it.
    fn passes_the_suffix_rule(anchor: &[u8; 32], listed: &[[u8; 32]], parents: &std::collections::HashMap<[u8; 32], Vec<Hash32>>) -> bool {
        let mut above: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::from([*anchor]);
        for h in listed {
            if !parents[h].iter().any(|p| above.contains(p.as_bytes())) {
                return false;
            }
            above.insert(*h);
        }
        true
    }

    /// ⭐ A-F56 PIN (RED-first by its calibration): after a reorg the anchor's future holds a run of blocks that no longer vouch
    /// between the anchor and the vouchers, and many short side blocks beside it. Cutting vouchers-first leaves the vouchers with
    /// no path to the anchor (the door's `Suffix` refusal, measured on real nodes); the path-closed choice keeps every voucher and
    /// passes the rule.
    #[test]
    fn a_served_suffix_keeps_every_header_s_path_to_the_anchor() {
        let anchor = id(0xA0, 0);
        let mut parents: std::collections::HashMap<[u8; 32], Vec<Hash32>> = std::collections::HashMap::new();
        let mut score: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
        let mut vouch: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        // ten blocks the reorg left without a matching commit: anchor → c1 → … → c10
        let mut below = anchor;
        for i in 1..=10u32 {
            let c = id(0xC0, i);
            parents.insert(c, vec![Hash32(below)]);
            score.insert(c, 10 + u64::from(i));
            below = c;
        }
        // forty vouchers on top of them
        for i in 1..=40u32 {
            let v = id(0xB0, i);
            parents.insert(v, vec![Hash32(below)]);
            score.insert(v, 20 + u64::from(i));
            vouch.insert(v);
            below = v;
        }
        // a hundred short side blocks straight off the anchor, nearer to it than the reorged run
        for i in 1..=100u32 {
            let s = id(0x50, i);
            parents.insert(s, vec![Hash32(anchor)]);
            score.insert(s, 1 + u64::from(i % 9));
        }
        let ids: Vec<[u8; 32]> = parents.keys().copied().collect();
        let cands: Vec<SuffixCandidate<'_>> =
            ids.iter().map(|i| SuffixCandidate { id: *i, parents: &parents[i], blue_score: score[i], vouches: vouch.contains(i) }).collect();

        // CALIBRATION: the old choice (vouchers first, nearest the anchor, cut at the bound, then by blue score) breaks the rule here
        let mut old: Vec<&SuffixCandidate<'_>> = cands.iter().collect();
        old.sort_by_key(|c| (!c.vouches, c.blue_score, c.id));
        old.truncate(MAX_SUFFIX);
        old.sort_by_key(|c| (c.blue_score, c.id));
        let old_ids: Vec<[u8; 32]> = old.iter().map(|c| c.id).collect();
        assert!(!passes_the_suffix_rule(&anchor, &old_ids, &parents), "CALIBRATION: the fixture must reproduce the Suffix refusal, else the pin proves nothing");

        let chosen = path_closed_suffix(&anchor, &cands, MAX_SUFFIX);
        assert!(chosen.len() <= MAX_SUFFIX, "⛔ the suffix passed its bound");
        assert!(passes_the_suffix_rule(&anchor, &chosen, &parents), "⛔ A-F56: a served suffix leaves a header with no path to the anchor (the door refuses it: Suffix)");
        let vouchers = chosen.iter().filter(|c| vouch.contains(*c)).count();
        assert_eq!(vouchers, 40, "⛔ A-F56: the path-closed suffix dropped vouchers it had room for");
        assert!(vouchers >= VOUCHERS, "the bundle carries enough vouchers for the door");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(h: &BlockHeader) -> Hash32 {
        Hash32(*blake3::hash(&h.preimage()).as_bytes())
    }

    fn mined(parents: Vec<crate::block::BlockId>, array: &[[u8; 32]], folds: (u64, [u8; 32], u64, [u8; 32]), work: u128, seed: u64) -> BlockHeader {
        let mut h = crate::pow::tests::test_header(work);
        h.parents = parents;
        h.level_root = level_root(array);
        h.fold_ordinal = folds.0;
        h.fold_commit = Hash32(folds.1);
        h.band_ordinal = folds.2;
        h.band_commit = Hash32(folds.3);
        h.timestamp = seed;
        for nonce in 0u64.. {
            h.nonce = nonce;
            if crate::pow::hash_meets_target(&digest_of(&h), work) {
                return h;
            }
        }
        unreachable!()
    }

    struct Chain {
        proof: JoinProof,
        anchor: BlockHeader,
        state: [u8; 32],
        band_root: [u8; 32],
        ordinal: u64,
        work: u128,
    }

    /// A small real chain, an anchor, then a suffix whose every block commits to the state.
    fn chain(suffix_len: usize, wrong_state_commit: bool, chain_work: u128, suffix_work: u128) -> Chain {
        let mut store = LevelStore::default();
        let mut array: Vec<[u8; 32]> = Vec::new();
        let mut parent = crate::block::BlockId::default();
        let mut declared = 0u128;
        // At least 80 blocks, and as many more as the best level walk needs to show MIN_LINKS links: a walk shorter than that
        // reaches the start and the door rightly treats the chain as young (no difficulty sample), so a fixture that stops
        // short asks the suffix rules nothing. MEASURED 2026-11-11 (lane audit, main 7217023e): after the header changes of
        // 11-07 to 11-11, 80 blocks no longer gave the walk MIN_LINKS links and `a_low_difficulty_suffix_cannot_vouch` read Ok.
        let mut i = 0u64;
        while i < 80 || store.best_walk(&array, &NO_BLOCK).1.len() < MIN_LINKS {
            assert!(i < 20_000, "CALIBRATION: the fixture chain never gave its level walk MIN_LINKS links");
            let h = mined(vec![parent], &array, (0, NO_BLOCK, 0, NO_BLOCK), chain_work, i);
            let level = level_of(&digest_of(&h));
            declared += h.work;
            let id = *h.id().as_bytes();
            store.note(&h, level, array.clone());
            array = next_levels(&array, [(id, level)]);
            parent = h.id();
            i += 1;
        }
        let state = [7u8; 32];
        let band_root = [9u8; 32];
        let anchor = mined(vec![parent], &array, (0, NO_BLOCK, 0, NO_BLOCK), chain_work, 1000);
        let ordinal = 100u64;
        let step = FoldStep { block: *anchor.id().as_bytes(), admitted: admitted_hash(&[]), state };
        let fold_prev = [1u8; 32];
        let c = fold_commit_next(&fold_prev, ordinal, &step);
        let band_prev = [2u8; 32];
        let b = band_commit_next(&band_prev, 99, &band_root);
        let (level, links) = store.best_walk(&array, &NO_BLOCK);
        let mut up = Vec::new();
        let mut p = anchor.id();
        for i in 0..suffix_len {
            let commit = if wrong_state_commit { [0xee; 32] } else { c };
            let h = mined(vec![p], &[], (ordinal, commit, 99, b), suffix_work, 2000 + i as u64);
            p = h.id();
            up.push(h);
        }
        Chain {
            proof: JoinProof {
                level,
                anchor_array: array,
                links,
                suffix: up,
                fold_start: ordinal,
                fold_prev,
                fold_steps: vec![step],
                band_prev,
                band_steps: vec![(99, band_root)],
                history: Vec::new(),
            },
            anchor,
            state,
            band_root,
            ordinal,
            work: declared,
        }
    }

    fn check(c: &Chain, declared: u128, state: [u8; 32]) -> Result<JoinVerdict, JoinRefusal> {
        verify_join(
            &c.proof,
            &JoinClaim {
                anchor: &c.anchor,
                anchor_ordinal: c.ordinal,
                state,
                declared_work: declared,
                band_root: c.band_root,
                band_next_ordinal: 100,
                awaiting: Vec::new(),
                genesis: NO_BLOCK,
            },
            &digest_of,
        )
    }

    #[test]
    fn an_honest_chain_is_adopted_and_its_estimate_tracks_its_real_work() {
        let c = chain(40, false, 4, 4);
        let v = check(&c, c.work, c.state).expect("an honest proof");
        assert!(v.vouchers >= VOUCHERS);
        assert!(v.estimate * WEIGHT_CAP_FACTOR >= c.work, "estimate {} of real {}", v.estimate, c.work);
    }

    #[test]
    fn claimed_work_above_what_the_digests_show_is_refused() {
        let c = chain(40, false, 4, 4);
        assert_eq!(check(&c, 1u128 << 120, c.state), Err(JoinRefusal::WeightAboveEstimate));
    }

    #[test]
    fn a_state_the_headers_do_not_commit_to_is_refused() {
        let c = chain(40, false, 4, 4);
        assert_eq!(check(&c, c.work, [8u8; 32]), Err(JoinRefusal::State));
        let mut forged = chain(40, false, 4, 4);
        forged.proof.fold_steps[0].state = [8u8; 32];
        assert_eq!(check(&forged, forged.work, [8u8; 32]), Err(JoinRefusal::FewVouchers), "the honest commits do not match a forged step");
    }

    #[test]
    fn too_few_blocks_vouching_is_refused() {
        let c = chain(VOUCHERS - 1, false, 4, 4);
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::FewVouchers));
        let c = chain(40, true, 4, 4);
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::FewVouchers));
    }

    #[test]
    fn a_broken_or_low_level_chain_is_refused() {
        let mut c = chain(40, false, 4, 4);
        c.proof.links.remove(1);
        assert_eq!(check(&c, 0, c.state), Err(JoinRefusal::Link));
        let mut c = chain(40, false, 4, 4);
        c.proof.links[0].next = [3u8; 32];
        assert_eq!(check(&c, 0, c.state), Err(JoinRefusal::Link));
        let mut c = chain(40, false, 4, 4);
        c.proof.level = c.proof.level.saturating_add(40);
        assert!(check(&c, 0, c.state).is_err());
        let mut c = chain(40, false, 4, 4);
        c.proof.anchor_array[0][0] ^= 1;
        assert_eq!(check(&c, 0, c.state), Err(JoinRefusal::AnchorArray));
    }

    #[test]
    fn suffix_chain_work_counts_one_path_never_a_side_block() {
        let anchor = mined(vec![crate::block::BlockId::default()], &[], (0, NO_BLOCK, 0, NO_BLOCK), 4, 1);
        let a = *anchor.id().as_bytes();
        let one = mined(vec![anchor.id()], &[], (0, NO_BLOCK, 0, NO_BLOCK), 4, 2);
        let side = mined(vec![anchor.id()], &[], (0, NO_BLOCK, 0, NO_BLOCK), 4, 3); // a sibling of `one`: off the heaviest path
        let two = mined(vec![one.id()], &[], (0, NO_BLOCK, 0, NO_BLOCK), 4, 4);
        let stray = mined(vec![crate::block::BlockId::default()], &[], (0, NO_BLOCK, 0, NO_BLOCK), 1000, 5); // not above the anchor
        assert_eq!(suffix_chain_work(&a, &[one.clone(), side.clone(), two.clone()]), one.work + two.work);
        assert_eq!(suffix_chain_work(&a, &[one.clone(), side, two.clone(), stray]), one.work + two.work);
        assert_eq!(suffix_chain_work(&a, &[]), 0);
    }

    #[test]
    fn a_suffix_that_is_not_mined_or_does_not_connect_is_refused() {
        let mut c = chain(40, false, 4, 4);
        let last = c.proof.suffix.len() - 1;
        c.proof.suffix[last].parents = vec![crate::block::BlockId::default()];
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::Suffix));
        let mut c = chain(40, false, 4, 4);
        c.proof.suffix[0].work = 0;
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::NotMined));
    }

    #[test]
    fn a_low_difficulty_suffix_cannot_vouch() {
        let c = chain(40, false, 64, 4);
        assert!(c.proof.links.len() >= MIN_LINKS, "CALIBRATION: the walk shows {} links, fewer than the door judges a suffix by", c.proof.links.len());
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::SuffixEasy));
    }

    #[test]
    fn a_wrong_band_is_refused() {
        let mut c = chain(40, false, 4, 4);
        c.band_root = [4u8; 32];
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::Band));
    }

    #[test]
    fn history_the_chains_do_not_name_is_refused() {
        let mut c = chain(40, false, 4, 4);
        c.proof.history = vec![HistoryStep { ordinal: 100, root: [1u64; 8], admitted: vec![[5u8; 32]] }];
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::History), "an admitted set the fold chain does not name");
        c.proof.history[0].admitted = Vec::new();
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::History), "a root the band chain does not name");
        c.proof.history[0].ordinal = 7;
        assert_eq!(check(&c, c.work, c.state), Err(JoinRefusal::History), "a step before what the proof reaches");
    }

    #[test]
    fn a_joiner_can_show_the_next_joiner_what_it_was_shown() {
        let c = chain(40, false, 4, 4);
        let mut s = LevelStore::default();
        s.inherit(&c.proof);
        let (level, links) = s.best_walk(&c.proof.anchor_array, &NO_BLOCK);
        assert_eq!((level, links), (c.proof.level, c.proof.links.clone()));
    }

    #[test]
    fn the_level_store_stays_bounded() {
        let mut s = LevelStore::default();
        for i in 0..5000u64 {
            let mut h = crate::pow::tests::test_header(4);
            h.timestamp = i;
            let level = (i.trailing_zeros() as usize).min(LEVELS - 1);
            s.note(&h, level, Vec::new());
        }
        assert!(s.len() <= M * 13, "held {}", s.len());
    }
}

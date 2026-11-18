// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-223 Q2 CATCH-UP — THE WINDOW INDEX: every completed spine window at level ≥ 8, both children, addressed
//! by POSITION, sharded by block range and served by the OLI PIR machinery (`docs/DB-223-Q2-PATH-REFRESH-INDEX-SPEC.md`
//! §3 and §9, accepted; the user's 9/28 decision: the index grows, split mesh-wide).
//!
//! A wallet that captured its note at arrival refreshes from the STREAM (`Node::path_refresh_stream`). A wallet that did
//! not — restarted, restored from its seed, or offline past the stream's reach — fetches the ≤ 56 completed windows its
//! path needs from here (the low half as whole shard tables, the high half by the level-major tables' constant asks),
//! and then follows the stream. Nothing here is believed: a fetched
//! window is used only when the path refolds to a ring root the wallet holds.
//!
//! **Content.** `root(l, w)`, the subtree root over leaves `[w·2^l, (w+1)·2^l)`, for every level `l ≥ 8` and every
//! window that has completed. It is consensus-derived: every node's fold computes the same value (the frontier's
//! `append_with` hands out both children of each merge), so an entry is never claimed.
//!
//! **Addressing.** By position, never by key: window `(l, w)` completes at block index
//! `b = (w + 1)·2^(l−8) − 1` (block index = fold ordinal − 1; genesis contributes no leaves). A wallet therefore knows
//! the exact cell it wants, and PIR hides which.
//!
//! **Two halves, split where a name would leak (§12, §12d).**
//! - A LOW level (`l < HIGH_LEVEL`) is one whose window spans at most half a shard. It completes inside the note's OWN
//!   shard, so it lives in shard `b / SHARD_BLOCKS` at a fixed cell. A shard table is 256 KB — half one PIR hint — so it
//!   is served WHOLE (DB-413, the §12d rule below): a catch-up fetches every held shard outright and reads its cells
//!   locally, naming nothing and asking nothing per note.
//! - A HIGH level (`l ≥ HIGH_LEVEL`) names another shard wherever it completes. The name set of such levels was the
//!   note's own prefix structure (§12, measured by `q2_a_catch_up_names_no_block_shard_but_the_notes_own`). So each
//!   high level is its own LEVEL-MAJOR table `T_l`, indexed by window number and asked once per catch-up whatever the
//!   note — a constant name. It is served WHOLE while it is small (no more bytes than a PIR hint) and by PIR above
//!   that, on the OLI layout unchanged.

use crate::fixed::FixedBytes;
use crate::spend_frontier::{Digest4, DIGEST_LANE_BYTES, SPEND_TREE_DEPTH};
use std::collections::{BTreeMap, BTreeSet};

/// The level of one record (`cover::BLOCK_FIXED_NOTE_COUNT` = 256 = 2^8 leaves).
pub const RECORD_LEVEL: usize = 8;
/// Bytes of one window root in a table cell (the lane encoding the stream serves).
pub const ROOT_BYTES: usize = DIGEST_LANE_BYTES;
/// Roots per PIR column: an OLI column is `S_ROWS` bytes.
pub const ROOTS_PER_COL: usize = crate::oli::S_ROWS / ROOT_BYTES;
/// Columns per shard table: an OLI shard's, so one answer costs exactly what an OLI answer costs.
pub const SHARD_COLS: usize = crate::oli::SHARD_BUCKETS as usize;
/// Levels an index holds: `RECORD_LEVEL ..= SPEND_TREE_DEPTH − 1` (the root has no sibling).
pub const INDEX_LEVELS: usize = SPEND_TREE_DEPTH - RECORD_LEVEL;

/// The cells one shard of `r` blocks needs (`r` a power of two). It holds only the LOW levels: every level `j = l − 8`
/// whose window spans at most HALF the shard (`2^j ≤ r/2`) completes `r / 2^j` windows inside it, `2r − 2` cells in total.
/// A level whose window spans the whole shard or more is not in any shard: it is level-major ([`HIGH_LEVEL`]), because
/// the shard it completes in is another shard than the note's (§12).
#[must_use]
pub const fn shard_cells_for(r: u64) -> usize {
    2 * r as usize - 2
}

/// Blocks per index shard (R), DERIVED, not tuned: the largest power of two whose shard fits ONE OLI-shaped table
/// (`SHARD_COLS × ROOTS_PER_COL` = 4,096 roots). With the high levels level-major (§12d), R = 2,048 needs 4,094 cells and
/// 4,096 would need 8,190. (Before §12d every level shared the shard, which held R to 1,024.)
pub const SHARD_BLOCKS: u64 = 2048;
const _: () = assert!(
    shard_cells_for(SHARD_BLOCKS) <= SHARD_COLS * ROOTS_PER_COL
        && shard_cells_for(SHARD_BLOCKS * 2) > SHARD_COLS * ROOTS_PER_COL,
    "SHARD_BLOCKS must be the largest power of two whose shard fits one table"
);
/// Cells per shard.
pub const SHARD_CELLS: usize = shard_cells_for(SHARD_BLOCKS);
const SHARD_LOG: usize = SHARD_BLOCKS.trailing_zeros() as usize;
/// ⭐ §12d — the first LEVEL-MAJOR level: the lowest level whose window spans a whole shard (`2^(l−8) = SHARD_BLOCKS`).
/// Its sibling completes in another shard than the note's, so it must never be asked by shard name. Levels
/// `RECORD_LEVEL .. HIGH_LEVEL` stay in block shards; a wallet persists them (with levels 0–7) once its note's shard
/// completes, so a restart asks nothing for them (§12b L).
pub const HIGH_LEVEL: usize = RECORD_LEVEL + SHARD_LOG;

/// ⭐ §12d — a level-major table is served WHOLE while it holds at most this many roots: exactly one PIR hint's bytes
/// (`S_ROWS × N_LWE × 4` = 512 KB). A table that small costs a wallet no more to fetch outright than PIR's hint, and
/// fetching it names nothing, since every catching-up wallet fetches every whole-mode table. DERIVED from the PIR
/// constants, not tuned.
pub const WHOLE_MAX_ROOTS: usize = crate::oli::S_ROWS * crate::oli::N_LWE * 4 / ROOT_BYTES;

/// How a level-major table is served, a public function of its LENGTH alone, so every wallet asks it the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighMode {
    /// Fetched outright (every wallet fetches every one).
    Whole,
    /// Asked by SimplePIR on the OLI layout: 128-byte columns, two roots each.
    Pir,
}

/// The serve mode of a level-major table of `len` roots.
#[must_use]
pub fn high_mode(len: usize) -> HighMode {
    if len <= WHOLE_MAX_ROOTS {
        HighMode::Whole
    } else {
        HighMode::Pir
    }
}

/// Columns of a level-major table of `len` roots in the OLI layout (`ROOTS_PER_COL` roots per `S_ROWS`-byte column).
#[must_use]
pub fn high_cols(len: usize) -> usize {
    len.div_ceil(ROOTS_PER_COL)
}

/// The block index at which window `(level, window)` completes, if it is an index window (level in range, no overflow).
#[must_use]
pub fn completing_block(level: usize, window: u64) -> Option<u64> {
    if !(RECORD_LEVEL..SPEND_TREE_DEPTH).contains(&level) {
        return None;
    }
    let end = (u128::from(window) + 1).checked_mul(1u128 << (level - RECORD_LEVEL))?;
    u64::try_from(end - 1).ok()
}

/// `(shard, cell)` of LOW-level window `(level, window)`: the ONE address a node writes and a wallet asks for. `None`
/// for a high level (`≥ HIGH_LEVEL`) — it has no shard, only its level-major table — and for anything out of range.
#[must_use]
pub fn locate(level: usize, window: u64) -> Option<(u64, usize)> {
    if !(RECORD_LEVEL..HIGH_LEVEL).contains(&level) {
        return None;
    }
    let shard = completing_block(level, window)? / SHARD_BLOCKS;
    let j = level - RECORD_LEVEL;
    // The `SHARD_BLOCKS / 2^j` windows of this level that complete in the shard follow every lower level's.
    let base = (2 * SHARD_BLOCKS as usize) - ((2 * SHARD_BLOCKS as usize) >> j);
    let off = usize::try_from(window.checked_sub(shard.checked_mul(SHARD_BLOCKS >> j)?)?).ok()?;
    if off >= (SHARD_BLOCKS >> j) as usize {
        return None;
    }
    let cell = base + off;
    (cell < SHARD_CELLS).then_some((shard, cell))
}

/// ⭐ DB-418 — THE ONE WINDOW NUMBERING OF A MERGE. A fold — of leaves (`append_with`) or of record roots
/// (`append_subtree_with`) — that merges two completed windows at `level` hands out `left` and `right`; with `count_after`
/// the frontier's leaf count once the append that made the merge is done, `right` is window `(count_after >> level) − 1`
/// and `left` the one before it. Every writer of the index numbers its windows here: the live fold, the resume replay and
/// the roots-run rebuild after an adopt. `None` below the record level (those levels live in the note's own record) and
/// at a level no u64 count shifts by.
#[must_use]
pub fn merged_windows(level: usize, count_after: u64, left: Digest4, right: Digest4) -> Option<[(u8, u64, Digest4); 2]> {
    if level < RECORD_LEVEL {
        return None;
    }
    let right_window = count_after.checked_shr(u32::try_from(level).ok()?)?.checked_sub(1)?;
    let level = u8::try_from(level).ok()?;
    Some([(level, right_window.checked_sub(1)?, left), (level, right_window, right)])
}

/// Every LOW-level index window that completes inside shard `shard`, level by level.
#[must_use]
pub fn windows_in_shard(shard: u64) -> Vec<(usize, u64)> {
    let lo = u128::from(shard) * u128::from(SHARD_BLOCKS);
    let hi = lo + u128::from(SHARD_BLOCKS);
    let mut out = Vec::with_capacity(SHARD_CELLS);
    for level in RECORD_LEVEL..HIGH_LEVEL {
        let span = 1u128 << (level - RECORD_LEVEL);
        // lo ≤ (w+1)·span − 1 < hi  ⇔  ⌈(lo+1)/span⌉ ≤ w+1 ≤ ⌊hi/span⌋
        for wp1 in (lo + 1).div_ceil(span)..=(hi / span) {
            if let Ok(w) = u64::try_from(wp1 - 1) {
                out.push((level, w));
            }
        }
    }
    out
}

/// The windows a note at leaf `index` needs from the index when the tree holds `count` leaves: at every level ≥ 8, its
/// sibling window — left or right — once that window is COMPLETE (its last leaf is below `count`). Levels below 8 come
/// from the note's own record. At most `INDEX_LEVELS` (56).
#[must_use]
pub fn sibling_windows(index: u64, count: u64) -> Vec<(usize, u64)> {
    (RECORD_LEVEL..SPEND_TREE_DEPTH)
        .filter_map(|l| {
            let w = (index >> l) ^ 1;
            ((u128::from(w) + 1) << l <= u128::from(count)).then_some((l, w))
        })
        .collect()
}

/// The index this node holds: one fixed-size table of cells per held shard (the LOW levels) and one append-only
/// level-major table per HIGH level.
/// O1-FOOTPRINT-REVIEWED: one `SHARD_CELLS` table per HELD shard (256 KB of roots per 2,048 blocks), plus the level-major
/// tables: ≈ 2·N/2^11 roots × 64 B in total — 39 MB at 10 years of the 2 blocks/s target, 3.9 MB at 1 (§12d). The
/// growth is the user's 9/28 decision (the index grows, split mesh-wide by the holder policy; whole-table replication
/// until that policy lands, lane-recursion's condition (a)), never a per-note or per-request term.
#[derive(Clone, Default)]
pub struct WindowIndex {
    shards: BTreeMap<u64, Vec<Option<Digest4>>>,
    /// ⭐ §12d — `T_l` for every `l ≥ HIGH_LEVEL`: window `w` at index `w`. A window this node never folded (a jumper's
    /// pre-anchor history) is `None`, and a table with a hole is not served (another holder answers).
    high: BTreeMap<usize, Vec<Option<Digest4>>>,
    /// T1.7 — the resume files ([`WinFile`]) changed since the last checkpoint wrote them. Shared (an `Arc`) so a
    /// checkpoint thread whose write failed hands its files back without the node's lock.
    dirty: std::sync::Arc<std::sync::Mutex<BTreeSet<WinFile>>>,
}

/// ⭐ T1.7 — ONE RESUME FILE of the window index beside the snapshot: a low shard, or a chunk of `HIGH_CHUNK` windows of
/// one level-major table. A closed shard never changes again, so a checkpoint rewrites only the files a fold (or a rewind)
/// touched since the last one — O(1) files per checkpoint, never the whole index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WinFile {
    Shard(u64),
    High(usize, u64),
}

/// Windows per level-major resume file: one shard table's worth of roots.
pub const HIGH_CHUNK: u64 = (SHARD_COLS * ROOTS_PER_COL) as u64;

/// Bytes of one resume-file entry: `level (1) ‖ window (8, LE) ‖ root (ROOT_BYTES)`.
const WIN_ENTRY_BYTES: usize = 1 + 8 + ROOT_BYTES;

impl WinFile {
    /// The file that holds window `(level, window)`.
    #[must_use]
    pub fn of(level: usize, window: u64) -> Option<Self> {
        if (HIGH_LEVEL..SPEND_TREE_DEPTH).contains(&level) {
            completing_block(level, window)?;
            return Some(Self::High(level, window / HIGH_CHUNK));
        }
        locate(level, window).map(|(s, _)| Self::Shard(s))
    }

    /// The file's name inside the index directory.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Shard(s) => format!("s{s}.win"),
            Self::High(l, c) => format!("h{l}-{c}.win"),
        }
    }

    /// The inverse of [`Self::name`] (anything else is not an index file).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".win")?;
        if let Some(s) = stem.strip_prefix('s') {
            return s.parse().ok().map(Self::Shard);
        }
        let (l, c) = stem.strip_prefix('h')?.split_once('-')?;
        let l: usize = l.parse().ok()?;
        (HIGH_LEVEL..SPEND_TREE_DEPTH).contains(&l).then_some(())?;
        Some(Self::High(l, c.parse().ok()?))
    }
}

/// What every census and diagnostic reads of a window index: its WINDOWS (`shards`, `high`), which are chain state. Its
/// changed-file set (`dirty`) is this process's checkpoint bookkeeping — two nodes holding the same windows differ there
/// only in when each last wrote its resume files — so it is not shown. MEASURED link 25 (night/sim-20261007-202710.log):
/// the replica census read `window_index DIFFERS` between two nodes whose windows were byte-identical, at `dirty`
/// {Shard(0)} vs {}.
impl std::fmt::Debug for WindowIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowIndex").field("shards", &self.shards).field("high", &self.high).finish_non_exhaustive()
    }
}

impl WindowIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Write the root of a window that just completed. A re-fold after a rewind writes the same cell with the re-folded
    /// value. `false` when `(level, window)` is not an index window.
    pub fn record(&mut self, level: usize, window: u64, root: Digest4) -> bool {
        if (HIGH_LEVEL..SPEND_TREE_DEPTH).contains(&level) {
            // A window number is bounded by the chain (it completes at block (w+1)·2^(l−8) − 1), so the table never
            // outgrows the chain it indexes; a number no u64 block index can reach is refused.
            let (Some(_), Ok(w)) = (completing_block(level, window), usize::try_from(window)) else {
                return false;
            };
            let t = self.high.entry(level).or_default();
            if t.len() <= w {
                t.resize(w + 1, None);
            }
            t[w] = Some(root);
            self.mark(WinFile::High(level, window / HIGH_CHUNK));
            return true;
        }
        let Some((shard, cell)) = locate(level, window) else {
            return false;
        };
        self.shards.entry(shard).or_insert_with(|| vec![None; SHARD_CELLS])[cell] = Some(root);
        self.mark(WinFile::Shard(shard));
        true
    }

    pub fn mark(&self, f: WinFile) {
        if let Ok(mut d) = self.dirty.lock() {
            d.insert(f);
        }
    }

    /// Every held window, `(level, window, root)`: the low shards cell by cell, then the level-major tables.
    #[must_use]
    pub fn entries(&self) -> Vec<(usize, u64, Digest4)> {
        let mut out = Vec::new();
        for (shard, cells) in &self.shards {
            for (level, window) in windows_in_shard(*shard) {
                if let Some((_, cell)) = locate(level, window) {
                    if let Some(Some(r)) = cells.get(cell) {
                        out.push((level, window, *r));
                    }
                }
            }
        }
        for (level, t) in &self.high {
            for (w, r) in t.iter().enumerate() {
                if let Some(r) = r {
                    out.push((*level, w as u64, *r));
                }
            }
        }
        out
    }

    /// Write every window `other` holds into this index (the later value wins, as a re-fold does).
    pub fn merge(&mut self, other: &WindowIndex) {
        for (level, window, root) in other.entries() {
            self.record(level, window, root);
        }
    }

    /// Forget everything (an adopt replaced the spine this index described); its resume files are removed at the next
    /// checkpoint.
    pub fn clear(&mut self) {
        let keys: Vec<WinFile> = self.files();
        for f in keys {
            self.mark(f);
        }
        self.shards.clear();
        self.high.clear();
    }

    /// ⭐ DB-418 — KEEP, IN PLACE, ONLY THE WINDOWS `frontier` BINDS ([`Self::bound_to`]): a held pair whose parent is a
    /// peak of `frontier`, or a kept window, stays; anything else (a window of a replaced spine, a stale or tampered resume
    /// file) is dropped. Every resume file whose bytes that changes is marked for the next checkpoint (rewritten, or
    /// removed when nothing in it stays), and the changed-file set stays THIS index's, so a checkpoint in flight still hands
    /// its files back here. The one binding step of both a resume and a certified adopt. Returns (held, kept).
    pub fn retain_bound_to(&mut self, frontier: &crate::spend_frontier::PoseidonSpendFrontier) -> (usize, usize) {
        let kept = self.bound_to(frontier);
        for f in self.files() {
            if self.encode_file(f) != kept.encode_file(f) {
                self.mark(f);
            }
        }
        let held = self.len();
        self.shards = kept.shards;
        self.high = kept.high;
        (held, self.len())
    }

    /// Forget the changed-file set: the index was just read from its files, so nothing in it differs from them yet.
    pub fn forget_changes(&self) {
        if let Ok(mut d) = self.dirty.lock() {
            d.clear();
        }
    }

    /// The resume files the held windows live in.
    #[must_use]
    pub fn files(&self) -> Vec<WinFile> {
        let mut out: BTreeSet<WinFile> = self.shards.keys().map(|s| WinFile::Shard(*s)).collect();
        for (level, t) in &self.high {
            for (w, r) in t.iter().enumerate() {
                if r.is_some() {
                    out.insert(WinFile::High(*level, w as u64 / HIGH_CHUNK));
                }
            }
        }
        out.into_iter().collect()
    }

    /// The bytes of resume file `f` (`None` when it holds nothing: the file is removed). Entries in window order.
    #[must_use]
    pub fn encode_file(&self, f: WinFile) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut put = |level: usize, window: u64, r: &Digest4| {
            out.push(level as u8);
            out.extend_from_slice(&window.to_le_bytes());
            out.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(r));
        };
        match f {
            WinFile::Shard(s) => {
                let cells = self.shards.get(&s)?;
                for (level, window) in windows_in_shard(s) {
                    if let Some((_, cell)) = locate(level, window) {
                        if let Some(Some(r)) = cells.get(cell) {
                            put(level, window, r);
                        }
                    }
                }
            }
            WinFile::High(level, chunk) => {
                let t = self.high.get(&level)?;
                let lo = usize::try_from(chunk.checked_mul(HIGH_CHUNK)?).ok()?;
                let hi = lo.saturating_add(HIGH_CHUNK as usize).min(t.len());
                for w in lo..hi {
                    if let Some(r) = &t[w] {
                        put(level, w as u64, r);
                    }
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// Decode resume file `f`'s bytes into this index. Refused whole (nothing recorded, `false`) when the length is not a
    /// whole number of entries or any entry is not an index window that belongs to `f`.
    pub fn decode_file_into(&mut self, f: WinFile, bytes: &[u8]) -> bool {
        if bytes.len() % WIN_ENTRY_BYTES != 0 {
            return false;
        }
        let mut rows = Vec::with_capacity(bytes.len() / WIN_ENTRY_BYTES);
        for e in bytes.chunks(WIN_ENTRY_BYTES) {
            let level = usize::from(e[0]);
            let window = u64::from_le_bytes(e[1..9].fixed());
            let Some(root) = crate::spend_frontier::digest_from_lane_bytes(&e[9..]) else { return false };
            if WinFile::of(level, window) != Some(f) {
                return false;
            }
            rows.push((level, window, root));
        }
        for (level, window, root) in rows {
            self.record(level, window, root);
        }
        true
    }

    /// The resume files changed since the last call, with their bytes (`None` = remove the file). Hands the set over: a
    /// writer that fails gives the names back with [`Self::return_files`].
    #[must_use]
    pub fn take_dirty_files(&self) -> Vec<(WinFile, Option<Vec<u8>>)> {
        let keys: Vec<WinFile> = match self.dirty.lock() {
            Ok(mut d) => std::mem::take(&mut *d).into_iter().collect(),
            Err(_) => Vec::new(),
        };
        keys.into_iter().map(|f| (f, self.encode_file(f))).collect()
    }

    /// Give back files a checkpoint did not write; the next checkpoint writes them (with the then-current bytes).
    pub fn return_files(dirty: &std::sync::Arc<std::sync::Mutex<BTreeSet<WinFile>>>, files: impl IntoIterator<Item = WinFile>) {
        if let Ok(mut d) = dirty.lock() {
            d.extend(files);
        }
    }

    /// The shared changed-file set (for [`Self::return_files`] from a checkpoint thread).
    #[must_use]
    pub fn dirty_handle(&self) -> std::sync::Arc<std::sync::Mutex<BTreeSet<WinFile>>> {
        std::sync::Arc::clone(&self.dirty)
    }

    /// ⭐ T1.7 — THE WINDOWS OF THIS INDEX THAT ARE BOUND TO `frontier`'s root, and nothing else. A held pair
    /// `(l, 2v), (l, 2v+1)` is bound when its parent `H(left, right)` is the frontier's level-`l+1` PEAK at window `v`
    /// (an MMR peak is a completed left subtree that has not merged yet, so it is the top of every held chain below it), or
    /// is itself a bound held window. Walking from the top level down binds every kept root to the spine root by hashes —
    /// the same authority the fold had — so a resume file that is stale, from another fork, or tampered keeps nothing that
    /// is not the chain's. A lone window (its sibling not held) is not bound. O(held) Poseidon compressions.
    #[must_use]
    pub fn bound_to(&self, frontier: &crate::spend_frontier::PoseidonSpendFrontier) -> WindowIndex {
        let held: BTreeMap<(usize, u64), Digest4> = self.entries().into_iter().map(|(l, w, r)| ((l, w), r)).collect();
        let count = frontier.count();
        let mut kept = WindowIndex::new();
        for level in (RECORD_LEVEL..SPEND_TREE_DEPTH).rev() {
            let at: Vec<(u64, Digest4)> = held.range((level, 0)..=(level, u64::MAX)).map(|((_, w), r)| (*w, *r)).collect();
            for (w, left) in at {
                if w % 2 == 1 {
                    continue;
                }
                let Some(right) = held.get(&(level, w + 1)).copied() else { continue };
                let parent = crate::spend_frontier::poseidon_pair(left, right);
                let up = level + 1;
                let v = w / 2;
                let is_peak = up < 64
                    && (count >> up) & 1 == 1
                    && (count >> up) - 1 == v
                    && frontier.peak_at(up) == Some(parent);
                let under_bound = up < SPEND_TREE_DEPTH && kept.get(up, v) == Some(parent);
                if is_peak || under_bound {
                    kept.record(level, w, left);
                    kept.record(level, w + 1, right);
                }
            }
        }
        // the binding pass wrote nothing that needs saving; the caller decides which files are stale
        if let Ok(mut d) = kept.dirty.lock() {
            d.clear();
        }
        kept
    }

    /// The held root of `(level, window)`, if this node holds it.
    #[must_use]
    pub fn get(&self, level: usize, window: u64) -> Option<Digest4> {
        if (HIGH_LEVEL..SPEND_TREE_DEPTH).contains(&level) {
            return *self.high.get(&level)?.get(usize::try_from(window).ok()?)?;
        }
        let (shard, cell) = locate(level, window)?;
        *self.shards.get(&shard)?.get(cell)?
    }

    /// A fold REWIND to the fold that placed block `from_block`: forget every window that completed at or after it (the
    /// re-fold writes them again), so a rewound history is never served.
    pub fn forget_from_block(&mut self, from_block: u64) {
        let before = self.files();
        // The level-major tables: window w completes at (w+1)·span − 1, so the first window to forget is the first
        // with (w+1)·span − 1 ≥ from_block, i.e. w ≥ ⌈(from_block+1)/span⌉ − 1. Everything from there is truncated.
        for (level, t) in &mut self.high {
            let span = 1u128 << (level - RECORD_LEVEL);
            let keep = (u128::from(from_block) + 1).div_ceil(span) - 1;
            if let Ok(keep) = usize::try_from(keep) {
                t.truncate(keep);
            }
        }
        self.high.retain(|_, t| !t.is_empty());
        let first = from_block / SHARD_BLOCKS;
        self.shards.retain(|s, _| *s <= first);
        let Some(t) = self.shards.get_mut(&first) else {
            return;
        };
        for (level, window) in windows_in_shard(first) {
            if let (Some(b), Some((_, cell))) = (completing_block(level, window), locate(level, window)) {
                if b >= from_block {
                    t[cell] = None;
                }
            }
        }
        // every file the rewind could have touched is rewritten (or removed) by the next checkpoint
        for f in before {
            let touched = match f {
                WinFile::Shard(s) => s >= first,
                WinFile::High(level, chunk) => {
                    let span = 1u128 << (level - RECORD_LEVEL);
                    let keep = ((u128::from(from_block) + 1).div_ceil(span) - 1) / u128::from(HIGH_CHUNK);
                    u128::from(chunk) >= keep
                }
            };
            if touched {
                self.mark(f);
            }
        }
    }

    /// ⭐ §12d — the level-major table `T_level` in the OLI layout (roots in window order, two per 128-byte column, the
    /// last column zero-padded), or `None` when the level is not a high level, holds nothing, or has a HOLE: a window this
    /// node never folded is served by no one from here, so a wallet asks another holder rather than decoding zeros.
    #[must_use]
    pub fn high_table(&self, level: usize) -> Option<Vec<u8>> {
        self.high_table_at(level, self.high_len(level))
    }

    /// ⛔ DB-405 — `T_level` AS OF `len` roots, a VERSION (the high twin of [`Self::table`]'s): the first `len` windows only,
    /// so a hint taken over `len` roots and an answer asked after more windows completed read the same bytes. `None` past
    /// what is held, on a hole in the prefix, or for an empty prefix.
    #[must_use]
    pub fn high_table_at(&self, level: usize, len: usize) -> Option<Vec<u8>> {
        let t = self.high.get(&level)?.get(..len)?;
        if t.is_empty() || t.iter().any(Option::is_none) {
            return None;
        }
        let mut out = vec![0u8; high_cols(t.len()) * crate::oli::S_ROWS];
        for (w, root) in t.iter().enumerate() {
            if let Some(r) = root {
                out[w * ROOT_BYTES..(w + 1) * ROOT_BYTES].copy_from_slice(&crate::spend_frontier::digest_to_lane_bytes(r));
            }
        }
        Some(out)
    }

    /// The number of windows `T_level` indexes (holes included), 0 for a level not held.
    #[must_use]
    pub fn high_len(&self, level: usize) -> usize {
        self.high.get(&level).map_or(0, Vec::len)
    }

    /// Shard `shard`'s PIR table: `SHARD_COLS` columns of `oli::S_ROWS` bytes, column-major (`table[c·S_ROWS + r]`, the
    /// layout `oli::answer_columns` reads), two roots per column in cell order, an empty cell all zero.
    /// ⛔ T1.7 — FAIL CLOSED ON A HOLE. `folded_blocks` is the records this node has folded; a window whose pair has
    /// completed below it (`completing_block(l, w|1) < folded_blocks`) is one the index must hold. A shard missing any such
    /// cell is NOT served (`None`): its zero bytes would decode as a root, and a wallet captured those zeros and stayed
    /// "confirming" for ever (MEASURED, sim fast lane T1.7: every refresh "11 own-shard roots captured", none refolding).
    /// ⛔⛔ DB-405 — THE TABLE AS OF `folded_blocks`, a VERSION: only the cells whose window's PAIR merged below it (DB-411:
    /// the fold writes both children of a merge at once), so the same version reads the same bytes at any later time (a
    /// later fold only fills cells whose pair merges at or past it). A PIR answer decodes
    /// only against the hint of the SAME table, and a wallet's hint ask and its answer asks are apart in time while the
    /// node folds on: the hint names the version it covered and the answer is computed over that version.
    /// ROOT-LAYER: the table is PRODUCED here, from the index; both doors and every caller read it through this one
    ///   function, so the version is a property of the table, not of either route.
    /// MEASURED: before — sim-20261006-235327 T1.7, 14 sends "the refreshed path does not refold" after node 0's restart
    ///   (the fold replaying between the wallet's two asks); after — `db405_a_fold_between_the_hint_and_the_answer_never…`
    ///   and the wallet's `db405_the_low_catch_up_over_a_node_folding…`.
    /// MUST-STAY-GREEN: `db223_q2_the_window_index_pir_routes…`, the wallet's low catch-up pins, the T1.7 fail-closed rule
    ///   (a hole below the version still serves nothing).
    #[must_use]
    pub fn table(&self, shard: u64, folded_blocks: u64) -> Option<Vec<u8>> {
        if !self.shard_whole(shard, folded_blocks) {
            return None;
        }
        let cells = self.shards.get(&shard)?;
        let mut t = vec![0u8; SHARD_COLS * crate::oli::S_ROWS];
        for (level, window) in windows_in_shard(shard) {
            // ⛔⛔ DB-411: a cell is in version `folded_blocks` once its PAIR merged below it — the fold records both children
            // of a merge at once (node.rs `append_with`), so a LEFT window is written at its right sibling's completing
            // block, not its own. Keyed on the window's own completion, every version held some pending left peak whose
            // cell a later fold filled: the table "as of" a version changed under every hint taken at it (MEASURED
            // sim-20261007-061937: 803 `HINT_STALE` refusals in a row, a POS charge expired). The same pair rule as
            // `shard_whole`; an unmerged left window is the frontier's peak, which the wallet reads from the peaks.
            if !completing_block(level, window | 1).is_some_and(|b| b < folded_blocks) {
                continue; // its pair merges at or past the version: not in this version's table
            }
            let Some((_, cell)) = locate(level, window) else { continue };
            if let Some(Some(r)) = cells.get(cell) {
                // Column cell / 2 at offset (cell % 2)·64 — contiguous in column-major order.
                let at = cell * ROOT_BYTES;
                t[at..at + ROOT_BYTES].copy_from_slice(&crate::spend_frontier::digest_to_lane_bytes(r));
            }
        }
        Some(t)
    }

    /// Shard `shard` is held with every cell whose pair completed below `folded_blocks`.
    fn shard_whole(&self, shard: u64, folded_blocks: u64) -> bool {
        let Some(cells) = self.shards.get(&shard) else { return false };
        windows_in_shard(shard).into_iter().all(|(level, window)| {
            let pair_done = completing_block(level, window | 1).is_some_and(|b| b < folded_blocks);
            !pair_done || locate(level, window).is_some_and(|(_, cell)| cells[cell].is_some())
        })
    }

    /// The shards held.
    pub fn held_shards(&self) -> impl Iterator<Item = u64> + '_ {
        self.shards.keys().copied()
    }

    /// The shards [`Self::table`] serves at `folded_blocks` (held, and no hole below the fold) — the name set a wallet asks.
    #[must_use]
    pub fn servable_shards(&self, folded_blocks: u64) -> Vec<u64> {
        self.shards.keys().copied().filter(|s| self.shard_whole(*s, folded_blocks)).collect()
    }

    /// Roots held (the census's count), both halves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.values().chain(self.high.values()).map(|t| t.iter().filter(|c| c.is_some()).count()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The public LWE matrix seed of the window-index PIR: ONE per chain (keyed by the genesis-derived OLI chain key), so a
/// closed shard's hint never changes and a wallet may reuse it.
#[must_use]
pub fn pir_seed(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/window-index/pir-seed/v1");
    h.update(chain_key);
    *h.finalize().as_bytes()
}

/// The root at cell `cell` of a table column (`S_ROWS` bytes): the wallet's read of a whole shard table (DB-413) or of
/// a recovered level-major PIR column, the inverse of [`WindowIndex::table`]'s layout. The same for a level-major table,
/// with the window number as the cell.
#[must_use]
pub fn root_in_column(column: &[u8], cell: usize) -> Option<Digest4> {
    let at = (cell % ROOTS_PER_COL) * ROOT_BYTES;
    let bytes = column.get(at..at + ROOT_BYTES)?;
    // T1.7: an all-zero cell is a cell the table does not hold, never a root — a wallet must not capture it.
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    crate::spend_frontier::digest_from_lane_bytes(bytes)
}

/// ⭐ §12d — the INCREMENTAL PIR hint of a level-major table: the hint words over its first `cols` columns, and a blake3
/// digest of those columns' bytes, so the next extension can check that nothing it covered has changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighHint {
    pub cols: usize,
    pub digest: [u8; 32],
    pub words: Vec<u32>,
}

/// Extend `prev` to cover all of `table` (column-major, `S_ROWS`-byte columns). Only the APPENDED columns are added
/// when `prev`'s columns are unchanged (their digest still matches), at one column's work each (`S_ROWS × N_LWE`).
/// Anything else is rebuilt from scratch: a rewind rewrote a covered column, the table shrank, or there was no
/// previous hint. Either way the result equals the hint of the whole table (pinned against a from-scratch build).
/// Lane-recursion's condition (b): a hint never goes stale silently.
#[must_use]
pub fn extend_high_hint(prev: Option<&HighHint>, table: &[u8], seed: &[u8; 32]) -> HighHint {
    let s_rows = crate::oli::S_ROWS;
    let cols = table.len() / s_rows;
    let digest_of = |c: usize| *blake3::hash(&table[..c * s_rows]).as_bytes();
    let words = match prev.filter(|p| p.cols <= cols && digest_of(p.cols) == p.digest) {
        Some(p) => {
            let mut w = p.words.clone();
            for (a, b) in w.iter_mut().zip(crate::oli::hint_words_for_columns(table, p.cols, cols, seed)) {
                *a = a.wrapping_add(b);
            }
            w
        }
        None => crate::oli::hint_words_for_columns(table, 0, cols, seed),
    };
    HighHint { cols, digest: digest_of(cols), words }
}

/// ⛔ DB-405 — the digest a hint door names for the table it covered and an answer door checks before it answers: blake3
/// of the table's bytes. One spelling for the shard and the level-major doors (and the incremental high hint's digest,
/// which is the same blake3 over the covered columns). A mismatch means a rewind rewrote a covered cell: `HINT_STALE`.
#[must_use]
pub fn table_digest(table: &[u8]) -> [u8; 32] {
    *blake3::hash(table).as_bytes()
}

/// The hint bytes a wallet decodes with: little-endian words, `S_ROWS × N_LWE` of them (`oli::recover_bucket`'s shape).
#[must_use]
pub fn high_hint_bytes(h: &HighHint) -> Vec<u8> {
    let mut out = Vec::with_capacity(h.words.len() * 4);
    for w in &h.words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// ⭐ §12d — THE LEVEL-MAJOR SERVE DOOR'S ANSWER. §9.6:
/// 1. PoW — n/a, no block enters.
/// 2. Proof — n/a: the roots are consensus-derived, and the wallet trusts only a path that refolds to a ring root it
///    holds.
/// 3. Conservation — n/a, reads only.
/// 4. Replay — n/a, reads only.
/// 5. Bounded work — one pass over at most the table's first `c` columns per query. `c` is taken from the query's length
///    and refused past the table, so a query built on a smaller (older) table stays answerable while the table grows.
///    At most `oli::WAVE_QUERIES` queries, all of one length. Anything else is refused before any work.
/// 6. Parity with the shard door ([`answer`]) and the OLI door — the same `answer_columns`, the same `S_ROWS` layout and
///    the same query bound.
#[must_use]
pub fn high_answer(table: &[u8], queries: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let s_rows = crate::oli::S_ROWS;
    let first = queries.first()?;
    if queries.len() > crate::oli::WAVE_QUERIES
        || first.is_empty()
        || first.len() % 4 != 0
        || queries.iter().any(|q| q.len() != first.len())
    {
        return None;
    }
    let c = first.len() / 4;
    if table.len() % s_rows != 0 || c > table.len() / s_rows {
        return None;
    }
    let parsed: Vec<Vec<u32>> = queries
        .iter()
        .map(|q| q.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect())
        .collect();
    let answers = crate::oli::answer_columns(&table[..c * s_rows], c, &parsed)?;
    Some(answers.into_iter().map(|a| a.iter().flat_map(|w| w.to_le_bytes()).collect()).collect())
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::spend_frontier::PoseidonSpendFrontier;

    /// ⭐ The address is a BIJECTION into one table: every window that completes in a shard gets a distinct cell of
    /// that shard below `SHARD_CELLS`, and the lower levels alone fill `2R − 1` of them.
    #[test]
    fn db223_every_window_of_a_shard_has_one_distinct_cell_inside_one_pir_table() {
        for shard in [0u64, 1, 7] {
            let mut seen = std::collections::BTreeSet::new();
            for (level, w) in windows_in_shard(shard) {
                let (s, cell) = locate(level, w).expect("an index window has an address");
                assert_eq!(s, shard, "a window lands in the shard of its completing block");
                assert!(cell < SHARD_CELLS, "inside the table");
                assert!(seen.insert(cell), "⛔ two windows share cell {cell} in shard {shard}");
            }
            assert_eq!(seen.len(), SHARD_CELLS, "every LOW level of the shard is present, and nothing else");
        }
        assert!(SHARD_CELLS <= SHARD_COLS * ROOTS_PER_COL, "the shard fits one OLI-shaped table");
        assert_eq!(locate(RECORD_LEVEL - 1, 0), None, "below the record level is not an index window");
        assert_eq!(locate(SPEND_TREE_DEPTH, 0), None, "the root level has no sibling");
        assert_eq!(locate(HIGH_LEVEL, 0), None, "⛔ §12d: a HIGH level has no shard — it is level-major");
        assert_eq!(1u64 << (HIGH_LEVEL - RECORD_LEVEL), SHARD_BLOCKS, "HIGH_LEVEL is the first level spanning a shard");
    }

    fn build(blocks: u64, salt: u64, index: &mut WindowIndex) -> (PoseidonSpendFrontier, Vec<(usize, u64)>) {
        let leaf_of = |j: u64| usdm_decider::poseidon2_compress::lanes_of(&[j + salt, 11]);
        let mut chain = PoseidonSpendFrontier::new();
        let mut written = Vec::new();
        for j in 0..blocks * 256 {
            let after = chain.count() + 1;
            assert!(
                chain.append_with(leaf_of(j), |l, left, right| {
                    if l >= RECORD_LEVEL {
                        let rw = (after >> l) - 1;
                        assert!(index.record(l, rw - 1, left) && index.record(l, rw, right), "index windows");
                        written.push((l, rw - 1));
                        written.push((l, rw));
                    }
                }),
                "the chain appends"
            );
        }
        (chain, written)
    }

    /// ⛔⛔ DB-411 — A TABLE VERSION IS ONE SET OF BYTES FOR EVER. `table(shard, V)` is what a wallet's hint covers and what the
    /// answer to it is computed over (DB-405), so every later fold must leave `table(shard, V)` byte-identical — or every
    /// answer to a hint at `V` is refused `HINT_STALE`. The fold records a LEFT window when its pair MERGES (both children
    /// at once, node.rs `append_with`), i.e. at its right sibling's completing block, not its own.
    /// MEASURED sim-20261007-061937 (ecosystem journey, T3 POS tap): the payer's low catch-up was refused `HINT_STALE`
    /// 803 times in a row; its membership path never completed ("a window it needs is missing") and the signed charge
    /// expired after 125.7 s. Here: every version of shard 0 is snapshotted as the chain grows one record at a time, and
    /// each one the node served a table at is re-read after 70 more records (every pair pending at any snapshot merges by
    /// then). RED before the fix: versions 1..=60 all moved.
    /// CALIBRATION: the snapshots are not all one table (the version moves).
    #[test]
    fn db411_a_table_version_reads_the_same_bytes_after_every_later_fold() {
        let leaf_of = |j: u64| usdm_decider::poseidon2_compress::lanes_of(&[j, 0x411]);
        let mut index = WindowIndex::new();
        let mut chain = PoseidonSpendFrontier::new();
        let mut snaps: Vec<(u64, Option<Vec<u8>>)> = Vec::new();
        let total = 130u64;
        for j in 0..total * 256 {
            let after = chain.count() + 1;
            assert!(
                chain.append_with(leaf_of(j), |l, left, right| {
                    if l >= RECORD_LEVEL {
                        let rw = (after >> l) - 1;
                        assert!(index.record(l, rw - 1, left) && index.record(l, rw, right), "index windows");
                    }
                }),
                "the chain appends"
            );
            if chain.count() % 256 == 0 && chain.count() >> RECORD_LEVEL <= 60 {
                let v = chain.count() >> RECORD_LEVEL;
                snaps.push((v, index.table(0, v)));
            }
        }
        assert!(snaps.iter().filter(|(_, t)| t.is_some()).count() >= 50, "CALIBRATION: the shard is served at most versions");
        assert!(snaps.windows(2).any(|w| w[0].1 != w[1].1), "CALIBRATION: the version moves the table");
        // A version the node served no table at (`None` → `SHARD_NOT_HELD`, no hint handed out) cannot go stale; every
        // version it DID serve a hint over must read the same bytes now.
        let moved: Vec<u64> =
            snaps.iter().filter(|(v, t)| t.is_some() && index.table(0, *v) != *t).map(|(v, _)| *v).collect();
        assert!(
            moved.is_empty(),
            "⛔⛔ DB-411: versions {moved:?} of shard 0 read different bytes after later folds — a hint taken at any of them is \
             answered HINT_STALE for ever, and the wallet's membership path never completes"
        );
    }

    /// ⭐ The index holds every window a note's path needs: a note whose wallet kept NOTHING but its own record's 256
    /// leaves rebuilds its depth-64 path to the current root from the index plus the current peaks.
    /// CALIBRATION: an empty index leaves the path incomplete. TAMPER: one wrong indexed root folds elsewhere.
    #[test]
    fn db223_a_note_restored_from_its_record_alone_rebuilds_its_path_from_the_window_index() {
        let salt = 3u64;
        let leaf_of = |j: u64| usdm_decider::poseidon2_compress::lanes_of(&[j + salt, 11]);
        let mut index = WindowIndex::new();
        let (chain, _) = build(37, salt, &mut index);
        let idx = 6 * 256 + 91;
        let witness = |source: &WindowIndex| {
            let mut w = crate::spend_frontier::IncrementalWitness::new(idx, leaf_of(idx));
            for j in (idx / 256) * 256..(idx / 256 + 1) * 256 {
                w.observe(j, leaf_of(j));
            }
            for (l, win) in sibling_windows(idx, chain.count()) {
                if let Some(r) = source.get(l, win) {
                    w.capture_completed_window(l, win, r);
                }
            }
            w
        };
        assert_ne!(
            witness(&WindowIndex::new()).root_against(&chain),
            Some(chain.root()),
            "CALIBRATION: with no index the restored path is incomplete"
        );
        let (l0, w0) = sibling_windows(idx, chain.count())[0];
        let mut forged = index.clone();
        let mut bad = forged.get(l0, w0).expect("the nearest sibling is indexed");
        bad[0] ^= 1;
        forged.record(l0, w0, bad);
        assert_ne!(witness(&forged).root_against(&chain), Some(chain.root()), "⛔ a forged indexed root reached the root");
        assert_eq!(
            witness(&index).root_against(&chain),
            Some(chain.root()),
            "⛔ DB-223 Q2: the window index did not hold every window a restored note's path needs"
        );
        // The PIR table round-trips the root through its layout.
        let (s, cell) = locate(l0, w0).expect("addressed");
        let t = index.table(s, chain.count() >> RECORD_LEVEL).expect("held");
        let col = cell / ROOTS_PER_COL;
        let column = &t[col * crate::oli::S_ROWS..(col + 1) * crate::oli::S_ROWS];
        assert_eq!(root_in_column(column, cell), index.get(l0, w0), "the table cell decodes to the indexed root");
    }

    /// ⛔⛔⛔ DB-223 Q2 §12 — A CATCH-UP NAMES NO BLOCK SHARD BUT THE NOTE'S OWN. RED FIRST (§12; lane-review §12b).
    ///
    /// The wire names a shard in clear; PIR hides only the cell. Before H, a sibling at level `l ≥ 18` completed in a
    /// shard fixed by the note's high bits. So the named set was the nested prefix structure of the note's block, and
    /// uniform dummies could not hide it: level 18 alone named the ADJACENT shard.
    /// After H, every level whose window spans a shard or more is asked from a level-major table, a constant name per
    /// level. A block shard is asked only for the note's OWN shard, which rides §11's age-matched cover set.
    /// Pure: address arithmetic over 2,000 random notes in chains of up to ~5 M blocks, no PIR.
    #[test]
    fn q2_a_catch_up_names_no_block_shard_but_the_notes_own() {
        let mut rng = 0x5eed_2230_u64;
        let mut leaks = 0usize;
        let mut example = None;
        for _ in 0..2000 {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let count_blocks = 2 + (rng >> 20) % 5_000_000;
            let count = count_blocks * 256;
            let index = (rng >> 7) % count;
            let own = (index / 256) / SHARD_BLOCKS;
            let named: std::collections::BTreeSet<u64> = sibling_windows(index, count)
                .into_iter()
                .filter_map(|(l, w)| locate(l, w).map(|(s, _)| s))
                .collect();
            if named.iter().any(|s| *s != own) {
                leaks += 1;
                example.get_or_insert((index / 256, own, named));
            }
        }
        eprintln!("[q2-§12] catch-ups naming a shard beyond the note's own: {leaks} of 2000; first: {example:?}");
        assert_eq!(
            leaks, 0,
            "⛔ DB-223 Q2 §12: a catch-up names block shards beyond the note's own (block, own shard, named): \
             {example:?} — the note's position rides the wire in clear"
        );
    }

    /// ⭐ A rewind forgets exactly the windows that completed at or after the rewound block, and no earlier one.
    #[test]
    fn db223_a_rewind_forgets_the_windows_completed_from_the_rewound_block_on() {
        let mut index = WindowIndex::new();
        let (_, written) = build(24, 5, &mut index);
        let from = 13u64;
        index.forget_from_block(from);
        for (l, w) in written {
            let b = completing_block(l, w).expect("index window");
            assert_eq!(index.get(l, w).is_some(), b < from, "window ({l}, {w}) completing at block {b}");
        }
    }

    fn synthetic_root(level: usize, w: u64) -> Digest4 {
        usdm_decider::poseidon2_compress::lanes_of(&[level as u64, w, 0x12d])
    }

    /// ⭐ §12d — A LEVEL-MAJOR TABLE, END TO END THROUGH THE REAL PIR, AND ITS HINT KEPT INCREMENTALLY.
    ///
    /// - A table past `WHOLE_MAX_ROOTS` is PIR-mode.
    /// - A wave recovers a root through the table's hint and `root_in_column` (the window number is the cell).
    /// - The incrementally extended hint EQUALS a from-scratch hint after the table grows (condition (b)).
    /// - A query built on the OLDER, smaller table is still answered correctly after growth (the server takes `c` from
    ///   the query's length).
    /// - The door refuses a query longer than the table and a wave of mixed lengths.
    #[test]
    fn q2_a_level_major_table_round_trips_through_pir_and_its_hint_grows_incrementally() {
        let level = HIGH_LEVEL;
        let mut index = WindowIndex::new();
        let n0 = WHOLE_MAX_ROOTS as u64 + 900;
        for w in 0..n0 {
            assert!(index.record(level, w, synthetic_root(level, w)), "a high window is recorded");
        }
        assert_eq!(high_mode(index.high_len(level)), HighMode::Pir, "PRECONDITION: past WHOLE_MAX_ROOTS the table is PIR");
        let seed = pir_seed(&[5u8; 32]);
        let table0 = index.high_table(level).expect("a table with no hole is served");
        let h0 = extend_high_hint(None, &table0, &seed);
        assert_eq!(h0.cols, high_cols(n0 as usize));
        // A query on the table as it stood, for window w0.
        let w0 = 4_321u64;
        let a0 = crate::oli::expand_a(&seed, h0.cols);
        let (q0, sk0) = crate::oli::build_query_with_a(&a0, w0 as usize / ROOTS_PER_COL, &[8u8; 32]).expect("query");
        let decode = |answers: &[Vec<u8>], hint: &HighHint, sk: &[u8], w: u64| {
            let col = crate::oli::recover_bucket(&answers[0], &high_hint_bytes(hint), sk, 0).expect("decodes");
            root_in_column(&col, w as usize)
        };
        let ans0 = high_answer(&table0, &[q0.clone()]).expect("answered");
        assert_eq!(decode(&ans0, &h0, &sk0, w0), Some(synthetic_root(level, w0)), "⛔ PIR did not recover the root");
        // The table grows; the node extends its hint incrementally.
        for w in n0..n0 + 1_000 {
            index.record(level, w, synthetic_root(level, w));
        }
        let table1 = index.high_table(level).expect("served");
        let inc = extend_high_hint(Some(&h0), &table1, &seed);
        let scratch = extend_high_hint(None, &table1, &seed);
        assert_eq!(inc, scratch, "⛔ the incrementally extended hint differs from a from-scratch hint");
        // The OLD query (built for h0.cols columns) is still answered correctly by the grown table with the old hint.
        let ans_old = high_answer(&table1, &[q0.clone()]).expect("an older, shorter query stays answerable");
        assert_eq!(decode(&ans_old, &h0, &sk0, w0), Some(synthetic_root(level, w0)), "⛔ growth broke an older query");
        // Bounded work: a query longer than the table, and a wave of mixed lengths, are refused before any work.
        let too_long = vec![0u8; (inc.cols + 1) * 4];
        assert!(high_answer(&table1, &[too_long]).is_none(), "⛔ a query past the table was answered");
        assert!(high_answer(&table1, &[q0.clone(), vec![0u8; 8]]).is_none(), "⛔ a mixed-length wave was answered");
        let mut over = vec![q0.clone(); crate::oli::WAVE_QUERIES];
        over.push(q0);
        assert!(high_answer(&table1, &over).is_none(), "⛔ a wave past WAVE_QUERIES was answered");
    }

    /// ⭐ §12d — A REWIND TRUNCATES A LEVEL-MAJOR TABLE AT THE FIRST WINDOW COMPLETED AT OR AFTER THE REWOUND BLOCK, and the
    /// next hint extension sees the rewrite (its digest no longer matches) and rebuilds. A small table is WHOLE-mode, and a
    /// table with a HOLE (a jumper's pre-anchor history) is not served.
    #[test]
    fn q2_a_rewind_truncates_a_level_major_table_and_a_holed_table_is_not_served() {
        let level = HIGH_LEVEL + 2; // windows span 2^(l−8) blocks
        let span = 1u64 << (level - RECORD_LEVEL);
        let mut index = WindowIndex::new();
        for w in 0..40u64 {
            index.record(level, w, synthetic_root(level, w));
        }
        assert_eq!(high_mode(index.high_len(level)), HighMode::Whole, "a 40-root table is served whole");
        let seed = pir_seed(&[6u8; 32]);
        let before = extend_high_hint(None, &index.high_table(level).expect("served"), &seed);
        // Rewind to the fold that placed block 10·span + 3: windows 0..=9 completed before it; window 10 completes at
        // 11·span − 1 ≥ 10·span + 3, so it and every later one are forgotten.
        index.forget_from_block(10 * span + 3);
        assert_eq!(index.high_len(level), 10, "⛔ the rewind kept a window that completed at or after the rewound block");
        for w in 0..10u64 {
            assert_eq!(index.get(level, w), Some(synthetic_root(level, w)), "an earlier window is kept");
        }
        // Re-fold with DIFFERENT roots: the hint extension must notice and rebuild.
        for w in 10..40u64 {
            index.record(level, w, synthetic_root(level + 1, w));
        }
        let table = index.high_table(level).expect("served");
        assert_eq!(
            extend_high_hint(Some(&before), &table, &seed),
            extend_high_hint(None, &table, &seed),
            "⛔ a hint covering rewritten columns was extended instead of rebuilt"
        );
        // A hole: a node that folded only windows 20.. (a jumper) serves nothing for this level.
        let mut jumper = WindowIndex::new();
        for w in 20..40u64 {
            jumper.record(level, w, synthetic_root(level, w));
        }
        assert!(jumper.high_table(level).is_none(), "⛔ a table with a hole was served (a wallet would decode zeros)");
        assert_eq!(jumper.get(level, 25), Some(synthetic_root(level, 25)), "the windows it folded are still held");
    }

    /// ⭐ §12d MEASURING PIN — THE COST OF ONE CATCH-UP AT 1 AND AT 10 YEARS of the 2 blocks/s target, from the served
    /// shapes.
    /// - Wire bytes are computed from each table's mode and asserted inside the §12d figures (≈ 2.1 MB and ≈ 4.8 MB).
    /// - The holder's answer time (one pass per PIR table) is PRINTED, not asserted — it varies by machine — and the
    ///   runner records the peak.
    /// Synthetic roots at the true table lengths `N / 2^(l−8)`.
    #[test]
    fn q2_catch_up_pir_cost_at_1_and_10_years() {
        for (years, cap_mb) in [(1u64, 2.3f64), (10, 5.0)] {
            let n_blocks = years * 365 * 24 * 3600 * 2;
            let mut index = WindowIndex::new();
            for level in HIGH_LEVEL..SPEND_TREE_DEPTH {
                let len = n_blocks >> (level - RECORD_LEVEL);
                for w in 0..len {
                    index.record(level, w, synthetic_root(level, w));
                }
            }
            let hint_bytes = crate::oli::S_ROWS * crate::oli::N_LWE * 4;
            let (mut wire, mut pir_levels, mut holder_ms) = (0usize, 0usize, 0u128);
            for level in HIGH_LEVEL..SPEND_TREE_DEPTH {
                let len = index.high_len(level);
                if len == 0 {
                    continue;
                }
                match high_mode(len) {
                    HighMode::Whole => wire += len * ROOT_BYTES,
                    HighMode::Pir => {
                        let cols = high_cols(len);
                        wire += hint_bytes + cols * 4 + crate::oli::S_ROWS * 4;
                        pir_levels += 1;
                        let table = index.high_table(level).expect("served");
                        let q: Vec<u8> = (0..cols as u32).flat_map(|c| c.wrapping_mul(2_654_435_761).to_le_bytes()).collect();
                        let t = std::time::Instant::now();
                        let a = high_answer(&table, &[q]).expect("answered");
                        holder_ms += t.elapsed().as_millis();
                        assert_eq!(a[0].len(), crate::oli::S_ROWS * 4, "one S_ROWS-word answer");
                    }
                }
            }
            let mb = wire as f64 / 1e6;
            eprintln!(
                "[q2-§12d-cost] {years} year(s): N = {n_blocks} blocks, {pir_levels} PIR table(s), catch-up wire {mb:.2} MB \
                 (hints reusable across one restore's notes), holder answer time {holder_ms} ms for all PIR tables"
            );
            assert!(mb <= cap_mb, "⛔ §12d: one catch-up at {years} year(s) costs {mb:.2} MB, above the stated {cap_mb} MB");
        }
    }
}

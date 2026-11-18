// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE BLOCK WINDOW — every whole block above the DAG's horizon, kept on disk in the node's
//! `pruning-window-{port}` directory. Kaspa's pruning-point block store and Bitcoin Core's `blk*.dat`
//! files, in MonerousD's shape.
//!
//! WHY (owner, 2026-09-21): "the dags are not supposed to be disjointed … All present and future nodes
//! should be on the same dag … use kaspa and bitcoins proven formula" and "yes you have my permission for
//! the on disc window".
//!
//! ROOT-LAYER: this store is where "which blocks does this node still hold whole" is PRODUCED. Until
//! 2026-09-21 that answer lived in a RAM ring of 512 folded blocks plus the ~34-block unfolded set, so a
//! restart emptied it and every serve door (by id, by locator page, the bundle's anchor witness) read an
//! empty answer. The doors read this store now; nothing else decides what is servable.
//! MEASURED: before — the live testnet pair, 2026-09-21 19:13, after both nodes restarted: DAGs of 38 and
//! 34 blocks, ZERO blocks shared above genesis, both bundles refused ("anchor block: no witness carried"),
//! heights 1923 / 1948 flat for eight minutes (a halt). After — the real-node restart journey
//! `a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin` asserts both nodes'
//! recent DAG rows are ONE set after every restart; its numbers are recorded in
//! docs/FUNDS-LOSS-KILL-LIST.md § DB-135b when it runs green.
//! MUST-STAY-GREEN: `a_folded_block_stays_servable_by_id_and_by_batch…` (the ring's pin, now the
//! window's), every carry/restore pin in `canonical_record_fold_tests`, and the RAM census (the window's
//! index is 48 bytes per retained block; bodies are on disk).
//!
//! THE BORROWED SHAPE. Kaspa keeps every block above its pruning point on every node, and the pruning
//! point is a function of the DAG (the selected-chain block at a fixed depth), so all synced nodes hold
//! the same set and a restarted node reopens the same store. Here the horizon is the one
//! [`crate::dag::Dag::horizon_blue_score`] derives from the live params (`merge_depth_cap * 2 +
//! daa_sample_len + margin` blue score below the tip): a block enters the window when it leaves the
//! unfolded set with its body in hand, and leaves the window when the horizon passes it. On restart the
//! window's headers re-enter the DAG below the checkpoint's anchor, so the resumed node holds exactly the
//! span its peers hold and every catch-up lane (by id, by locator page, shell) serves from the same disk
//! store it served from before the restart.
//!
//! BOUND, stated plainly (no growth on any axis): at most `DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK +
//! 2*merge_depth_cap + daa_sample_len` blocks — the very span the in-memory DAG keeps — each one whole
//! block (~21 KB at today's shape). At the default `merge_depth_cap` of 3,600 that is about 7,800 blocks
//! ≈ 160 MB on disk, and ~48 bytes per block of index in RAM (id → blue score, and a score-ordered set),
//! whatever the chain height. Nothing here is f(height): the horizon advances with the tip and the files
//! below it are deleted. This is NOT a reach bound on any proof or state question — the checkpoint answers
//! those at any age; this store only carries the blocks a peer needs to catch up, exactly what Bitcoin's
//! block files are.
//!
//! A corrupt or missing file costs a peer one page from another node, never a coin. A file that fails to
//! decode is treated as absent (the id is dropped from the served set), never as chain truth. A file whose
//! size cannot be read counts as zero bytes in the census only — the census is a diagnostic, never a gate.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: the bytes stored are the blocks the chain already carries and every
//! peer already serves — public chain structure, no wallet key, note, amount or owner beyond what a block
//! itself publishes. The directory is per node and never leaves the machine.

use std::collections::{BTreeSet, HashMap};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::block::{Block, BlockId};

/// The window directory's name prefix under the node's state directory: `pruning-window-{port}`.
pub const WINDOW_DIR_PREFIX: &str = "pruning-window-";
/// How many blue scores below the tip a block keeps its proofs — defined in [`crate::dag::WHOLE_KEEP`], beside the merge depth it sets.
pub const WHOLE_KEEP: u64 = crate::dag::WHOLE_KEEP;

/// ⛔ DB-270 — the generation a block carries when no fold under ANY generation stamped it (a carried block of the
/// adopted past, a re-buffered shell). It never equals a live `base_gen`, so such a block is never in the fold span.
pub const GEN_NONMEMBER: u64 = u64::MAX;
/// DB-270 step 1's generation file, RETIRED by step 2: the generation rides the checkpoint's fold record
/// (`persist::FoldRecord`), written at the same instant as the A_tip it describes. A file of its own was written at a
/// different instant and could not say which state it belonged to. `apply_checkpoint` deletes a leftover one.
const BASE_GEN_FILE: &str = "nf-base-gen";

/// One stored block with the blue data the DAG assigned it, so a restart can re-install it as an
/// ancestor with the same fork-choice weight it had (the DAG never recomputes GHOSTDAG for a block whose
/// parents left the span).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowEntry {
    pub block: Block,
    pub blue_work: u128,
    pub blue_score: u64,
    pub selected_parent: Option<[u8; 32]>,
    /// §22/§22b — what travels BESIDE the body (never in its postcard form): its cover key and the wide objects its sealed
    /// credit set names by hash. Kept with the body so the window serves a lagging peer the WHOLE body (a page frame is
    /// the gossip envelope), and a body read back opens and resolves exactly as it did when it folded. Re-installed on the
    /// block at every read ([`decode_entry`]).
    pub side_cover_key: Option<[u8; 32]>,
    pub side_wide: Vec<Vec<u8>>,
    /// §22c — the block's real notes and its stated spends' transactions, beside the body for as long as it is whole: a
    /// peer served this block judges every stated spend itself (`spend_evidence`) and needs both to do it. They leave
    /// with the block's proofs ([`BlockWindow::strip_below`]): a proofless block is served to nobody as a body to judge.
    pub side_notes: Vec<u8>,
    pub side_txs: Vec<Vec<u8>>,
    /// lane agg — the block's openings tables (`Block::agg_tables`), beside its bodies and leaving with them.
    pub side_tables: Vec<Vec<u8>>,
}

/// The pre-lane-agg entry shape (§22c's notes and transactions, no openings tables).
#[derive(serde::Deserialize)]
struct WindowEntryV3 {
    block: Block,
    blue_work: u128,
    blue_score: u64,
    selected_parent: Option<[u8; 32]>,
    side_cover_key: Option<[u8; 32]>,
    side_wide: Vec<Vec<u8>>,
    side_notes: Vec<u8>,
    side_txs: Vec<Vec<u8>>,
}

/// The pre-§22c entry shape (the key and the wide objects, no notes or transactions).
#[derive(serde::Deserialize)]
struct WindowEntryV2 {
    block: Block,
    blue_work: u128,
    blue_score: u64,
    selected_parent: Option<[u8; 32]>,
    side_cover_key: Option<[u8; 32]>,
    side_wide: Vec<Vec<u8>>,
}

/// The pre-§22b entry shape (no side fields) — read so a window written before this field still serves its bodies.
#[derive(serde::Deserialize)]
struct WindowEntryV1 {
    block: Block,
    blue_work: u128,
    blue_score: u64,
    selected_parent: Option<[u8; 32]>,
}

/// THE ONE DECODE of a stored entry: the current shape, else the pre-§22b one; the side fields go back onto the block.
fn decode_entry(bytes: &[u8]) -> Option<WindowEntry> {
    let mut e = match crate::chain_object::decode_exact::<WindowEntry>(bytes) {
        Some(e) => e,
        None => match crate::chain_object::decode_exact::<WindowEntryV3>(bytes).map(|v| WindowEntry {
            block: v.block,
            blue_work: v.blue_work,
            blue_score: v.blue_score,
            selected_parent: v.selected_parent,
            side_cover_key: v.side_cover_key,
            side_wide: v.side_wide,
            side_notes: v.side_notes,
            side_txs: v.side_txs,
            side_tables: Vec::new(),
        }) {
            Some(e) => e,
            None => match crate::chain_object::decode_exact::<WindowEntryV2>(bytes) {
            Some(v) => WindowEntry {
                block: v.block,
                blue_work: v.blue_work,
                blue_score: v.blue_score,
                selected_parent: v.selected_parent,
                side_cover_key: v.side_cover_key,
                side_wide: v.side_wide,
                side_notes: Vec::new(),
                side_txs: Vec::new(),
                side_tables: Vec::new(),
            },
            None => {
                let v = crate::chain_object::decode_exact::<WindowEntryV1>(bytes)?;
                WindowEntry {
                    block: v.block,
                    blue_work: v.blue_work,
                    blue_score: v.blue_score,
                    selected_parent: v.selected_parent,
                    side_cover_key: None,
                    side_wide: Vec::new(),
                    side_notes: Vec::new(),
                    side_txs: Vec::new(),
                    side_tables: Vec::new(),
                }
            }
        },
        },
    };
    e.block.cover_key = e.side_cover_key;
    e.block.wide_objects = e.side_wide.clone();
    e.block.tx_bodies = e.side_txs.clone();
    e.block.agg_tables = e.side_tables.clone();
    // the body only when it is the body the header commits (a file edited on disk serves nothing it cannot bind)
    if !e.side_notes.is_empty() && crate::block::da_notes_root_of(&e.side_notes) == e.block.header.output_notes_root {
        e.block.output_notes = e.side_notes.clone();
    }
    Some(e)
}

/// The on-disk window (or an in-memory one for a node with no state directory — a test party or a node
/// that has not enabled persistence). Every field below holds one entry per block inside the DAG's
/// retained span and nothing else: `prune_below` drops every entry under the horizon the DAG itself
/// prunes at, so the bound is the DAG's own.
pub struct BlockWindow {
    dir: Option<PathBuf>,
    /// The in-memory store, used ONLY when `dir` is `None`.
    /// O1-FOOTPRINT-REVIEWED: bounded by DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK + 2*merge_depth_cap + daa_sample_len (the Dag's retained span; `prune_below` enforces it)
    mem: HashMap<BlockId, WindowEntry>,
    /// id → blue score: the index every read goes through.
    /// O1-FOOTPRINT-REVIEWED: bounded by DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK + 2*merge_depth_cap + daa_sample_len (one entry per retained block)
    by_id: HashMap<BlockId, u64>,
    /// (blue score, id) ascending — the restore order (parents before children) and the prune cursor.
    /// O1-FOOTPRINT-REVIEWED: bounded by DAG_PRUNE_KEEP_MARGIN + DAG_PRUNE_SLACK + 2*merge_depth_cap + daa_sample_len (mirrors `by_id` exactly)
    by_score: BTreeSet<(u64, BlockId)>,
    /// The blocks not yet checked for stripping, lowest score first. Bounded by the window: a block leaves it when stripped or gone.
    whole: BTreeSet<(u64, BlockId)>,
    /// ⛔ DB-270 — the fold-base GENERATION each held block was folded into A_tip under (`Node::fold_block_into_atip`
    /// stamps it). A block is in the nullifier fold span only while its generation equals `base_gen`; a base-replacing
    /// adopt bumps `base_gen`, so every block held before it stops being a member at once. Carried in the FILE NAME
    /// (generation 0 keeps the legacy name), so `open` still indexes without decoding a body.
    /// O1-FOOTPRINT-REVIEWED: mirrors `by_id` exactly (one entry per retained block).
    gens: HashMap<BlockId, u64>,
    /// Held blocks per generation — the span's window count in O(1).
    /// O1-FOOTPRINT-REVIEWED: one entry per distinct generation among held blocks (≤ the window; 1 in steady state).
    gen_counts: HashMap<u64, usize>,
    /// ⛔ DB-270 — the CURRENT fold-base generation. Step 2: persisted in the checkpoint's fold record, so a restart reads
    /// the membership of the instant its snapshot captured.
    base_gen: u64,
    /// ⛔ DB-270 step 2 — the write EPOCH of each held block's file (carried in its name). The epoch advances at every
    /// checkpoint capture (`seal_epoch`), so a restore tells the files its checkpoint counted from those written after.
    /// O1-FOOTPRINT-REVIEWED: mirrors `by_id` exactly (one entry per retained block).
    epochs: HashMap<BlockId, u64>,
    /// DB-270 step 2 — other names of an indexed block found at `open` (a re-stamp links a new name and unlinks the old
    /// one only once a checkpoint is durable). Resolved, and emptied, by `apply_checkpoint`.
    /// O1-FOOTPRINT-REVIEWED: at most one extra name per retained block, emptied by the restore that reads them.
    shadows: Vec<(BlockId, u64, u64, u64)>,
    /// DB-270 step 2 — the epoch new files are written in.
    epoch: Cell<u64>,
    /// DB-270 step 2 — every block below this blue score has left the window (a member was absorbed into the base). The
    /// checkpoint records it; a restore deletes any file still below it and never absorbs it again.
    boundary: u64,
    /// ⛔ DB-270 step 2 — files the prune (or a re-stamp) removed from the index that stay on disk until the NEXT checkpoint
    /// is durable: until then the checkpoint on disk may still count them.
    /// O1-FOOTPRINT-REVIEWED: bounded by the blocks pruned or re-stamped between two checkpoints — at most the window.
    pending_unlink: RefCell<Vec<PathBuf>>,
    /// DB-270 step 2 — unlinks handed to a checkpoint save that did not land; the next capture takes them again.
    /// O1-FOOTPRINT-REVIEWED: holds only what one `pending_unlink` held (same bound).
    unflushed: Arc<Mutex<Vec<PathBuf>>>,
    /// Bytes on disk (or in `mem`), maintained on every keep and prune for the RAM/disk census.
    bytes: u64,
}

impl BlockWindow {
    /// A window with no directory: blocks stay in RAM, pruned by the same horizon rule.
    pub fn in_memory() -> Self {
        BlockWindow {
            dir: None,
            mem: HashMap::new(),
            by_id: HashMap::new(),
            by_score: BTreeSet::new(),
            whole: BTreeSet::new(),
            gens: HashMap::new(),
            gen_counts: HashMap::new(),
            base_gen: 0,
            epochs: HashMap::new(),
            shadows: Vec::new(),
            epoch: Cell::new(0),
            boundary: 0,
            pending_unlink: RefCell::new(Vec::new()),
            unflushed: Arc::new(Mutex::new(Vec::new())),
            bytes: 0,
        }
    }

    /// Open (creating if absent) the window directory and index every stored block by its file name —
    /// `{blue_score:020}-{id hex}.blk` — without decoding a single body. A file whose name does not parse
    /// is ignored (it is not one of ours).
    pub fn open(dir: PathBuf) -> Self {
        let mut w = BlockWindow {
            dir: Some(dir.clone()),
            mem: HashMap::new(),
            by_id: HashMap::new(),
            by_score: BTreeSet::new(),
            whole: BTreeSet::new(),
            gens: HashMap::new(),
            gen_counts: HashMap::new(),
            base_gen: 0,
            epochs: HashMap::new(),
            shadows: Vec::new(),
            epoch: Cell::new(0),
            boundary: 0,
            pending_unlink: RefCell::new(Vec::new()),
            unflushed: Arc::new(Mutex::new(Vec::new())),
            bytes: 0,
        };
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!(
                "[block-window] cannot create {} — the window stays in RAM for this run",
                dir.display()
            );
            w.dir = None;
            return w;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return w;
        };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((score, id, gen, epoch)) = Self::parse_name(name) else { continue };
            let len = match entry.metadata() {
                Ok(m) => m.len(),
                Err(_) => 0, // census only — see the module doc
            };
            w.bytes = w.bytes.saturating_add(len);
            // DB-270 step 2: one block can have two names on disk (a re-stamp links a new name and unlinks the old one only
            // once a checkpoint is durable). The newest is indexed; the others wait for `apply_checkpoint`, which knows
            // which instant the restored state counted.
            if let Some(prev_epoch) = w.epochs.get(&id).copied() {
                if epoch <= prev_epoch {
                    w.shadows.push((id, score, gen, epoch));
                    continue;
                }
                let prev_gen = w.gens.get(&id).copied().unwrap_or(0);
                let prev_score = w.by_id.get(&id).copied().unwrap_or(score);
                w.shadows.push((id, prev_score, prev_gen, prev_epoch));
                w.by_score.remove(&(prev_score, id));
                Self::count_sub(&mut w.gen_counts, prev_gen);
            }
            w.by_id.insert(id, score);
            w.by_score.insert((score, id));
            w.whole.insert((score, id));
            w.gens.insert(id, gen);
            w.epochs.insert(id, epoch);
            Self::count_add(&mut w.gen_counts, gen);
        }
        // DB-270 step 2: the base generation, the boundary and the epoch come from the checkpoint's fold record
        // (`apply_checkpoint`); until one is applied, new files are named above every name already on disk.
        let top = w.epochs.values().copied().chain(w.shadows.iter().map(|s| s.3)).max().unwrap_or(0);
        w.epoch.set(top.saturating_add(1));
        eprintln!(
            "[block-window] opened {} — {} block(s), {} KB on disk",
            dir.display(),
            w.by_id.len(),
            w.bytes / 1024
        );
        w
    }

    /// `{blue_score:020}-{id hex}.blk` for generation 0 written in epoch 0 (the legacy name, so every existing window
    /// reads unchanged), and `…-g{gen}-e{epoch}.blk` otherwise (DB-270: the fold-base generation; step 2: the write epoch).
    fn file_name(blue_score: u64, id: &BlockId, gen: u64, epoch: u64) -> String {
        if gen == 0 && epoch == 0 {
            format!("{blue_score:020}-{}.blk", id.to_hex())
        } else {
            format!("{blue_score:020}-{}-g{gen}-e{epoch}.blk", id.to_hex())
        }
    }

    /// The name `id` is indexed under.
    fn name_of(&self, score: u64, id: &BlockId) -> String {
        Self::file_name(score, id, self.gens.get(id).copied().unwrap_or(0), self.epochs.get(id).copied().unwrap_or(0))
    }

    /// `(score, id, gen, epoch)` from a window file name: the legacy name, step 1's `-g{gen}`, or `-g{gen}-e{epoch}`.
    fn parse_name(name: &str) -> Option<(u64, BlockId, u64, u64)> {
        let stem = name.strip_suffix(".blk")?;
        let (score, rest) = stem.split_once('-')?;
        let score: u64 = score.parse().ok()?;
        let (hex, gen, epoch) = match rest.split_once("-g") {
            Some((hex, tail)) => match tail.split_once("-e") {
                Some((g, e)) => (hex, g.parse::<u64>().ok()?, e.parse::<u64>().ok()?),
                None => (hex, tail.parse::<u64>().ok()?, 0),
            },
            None => (rest, 0, 0),
        };
        if hex.len() != 64 {
            return None;
        }
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        Some((score, crate::hash::Hash32(raw), gen, epoch))
    }

    fn count_add(counts: &mut HashMap<u64, usize>, gen: u64) {
        *counts.entry(gen).or_insert(0) += 1;
    }

    fn count_sub(counts: &mut HashMap<u64, usize>, gen: u64) {
        if let Some(c) = counts.get_mut(&gen) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&gen);
            }
        }
    }

    /// DB-270: the fold-base generation a held block was stamped under; `None` when the window does not hold it.
    pub fn gen_of(&self, id: &BlockId) -> Option<u64> {
        self.by_id.contains_key(id).then(|| self.gens.get(id).copied().unwrap_or(0))
    }

    /// DB-270: how many held blocks carry generation `gen` — the window's share of the fold span, in O(1).
    pub fn count_gen(&self, gen: u64) -> usize {
        self.gen_counts.get(&gen).copied().unwrap_or(0)
    }

    /// DB-270: the current fold-base generation.
    pub fn base_gen(&self) -> u64 {
        self.base_gen
    }

    /// ⛔ DB-270 — START A NEW FOLD-BASE GENERATION (the base-replacing adopt). Every block held now stops being a member
    /// of the fold span at once — O(1), no file touched. Step 2: RAM only; the next checkpoint's fold record persists it,
    /// at the same instant as the A_tip it belongs to (a crash before then resumes the pre-adopt state whole).
    pub fn bump_base_gen(&mut self) -> u64 {
        self.base_gen = self.base_gen.saturating_add(1).min(GEN_NONMEMBER - 1);
        self.base_gen
    }

    /// ⛔ DB-270 step 2 — SEAL THE CURRENT WRITE EPOCH AT A CHECKPOINT CAPTURE. Returns the epoch the capture belongs to
    /// (every file written so far carries it or an earlier one) and the files that capture makes safe to unlink once its
    /// snapshot is on disk (pruned or re-stamped before it, plus any a failed save handed back). New files are written
    /// in the next epoch from here on.
    pub fn seal_epoch(&self) -> (u64, Vec<PathBuf>) {
        let e = self.epoch.get();
        self.epoch.set(e.saturating_add(1));
        let mut unlink: Vec<PathBuf> = std::mem::take(&mut *self.pending_unlink.borrow_mut());
        if let Ok(mut back) = self.unflushed.lock() {
            unlink.append(&mut back);
        }
        (e, unlink)
    }

    /// DB-270 step 2 — where a checkpoint save that did not land hands its unlinks back (the next capture takes them).
    pub fn unflushed_handle(&self) -> Arc<Mutex<Vec<PathBuf>>> {
        Arc::clone(&self.unflushed)
    }

    /// DB-270 step 2 — unlink the files a DURABLE checkpoint no longer counts. A file already gone is not an error.
    pub fn flush_unlinks(paths: &[PathBuf]) {
        for p in paths {
            let _ = std::fs::remove_file(p);
        }
    }

    /// DB-270 step 2 — every block below this blue score has left the window (recorded by the checkpoint).
    pub fn boundary(&self) -> u64 {
        self.boundary
    }

    /// DB-270 step 2 (tests) — the write epoch a held block's file carries.
    #[cfg(test)]
    pub fn epoch_of(&self, id: &BlockId) -> Option<u64> {
        self.by_id.contains_key(id).then(|| self.epochs.get(id).copied().unwrap_or(0))
    }

    /// ⛔⛔⛔ DB-270 step 2 — RECONCILE THE WINDOW WITH THE CHECKPOINT A RESTORE RESUMES (its fold record's epoch, base
    /// generation and boundary), before anything reads the window:
    ///   * a name written AFTER the checkpoint (epoch > `epoch`) is dropped — the block falls back to its newest older
    ///     name if it has one, otherwise it is not held: the checkpoint never counted it, and it re-arrives through the
    ///     ordinary graft door (a block held here would be refused as a duplicate and never folded — R5);
    ///   * every other duplicate name is an older copy of a held block and is deleted;
    ///   * a block below `boundary` was absorbed into the recorded base: deleted, never absorbed again (R7).
    /// Then the generation and boundary are the recorded ones and new files are written from `epoch + 1`.
    /// Returns how many blocks the window stopped holding.
    pub fn apply_checkpoint(&mut self, epoch: u64, base_gen: u64, boundary: u64) -> usize {
        let mut dropped = 0usize;
        if let Some(dir) = self.dir.clone() {
            let newer: Vec<BlockId> = self.epochs.iter().filter(|(_, e)| **e > epoch).map(|(id, _)| *id).collect();
            for id in newer {
                let score = self.by_id.get(&id).copied().unwrap_or(0);
                let _ = std::fs::remove_file(dir.join(self.name_of(score, &id)));
                self.forget(&id);
                let best = self
                    .shadows
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.0 == id && s.3 <= epoch)
                    .max_by_key(|(_, s)| s.3)
                    .map(|(i, _)| i);
                match best {
                    Some(i) => {
                        let (_, sc, g, e) = self.shadows.remove(i);
                        self.by_id.insert(id, sc);
                        self.by_score.insert((sc, id));
                        self.whole.insert((sc, id));
                        self.gens.insert(id, g);
                        self.epochs.insert(id, e);
                        Self::count_add(&mut self.gen_counts, g);
                    }
                    None => dropped += 1,
                }
            }
            for (id, sc, g, e) in std::mem::take(&mut self.shadows) {
                let _ = std::fs::remove_file(dir.join(Self::file_name(sc, &id, g, e)));
            }
            let below: Vec<(u64, BlockId)> =
                self.by_score.range(..(boundary, crate::hash::Hash32([0u8; 32]))).copied().collect();
            for (sc, id) in below {
                let _ = std::fs::remove_file(dir.join(self.name_of(sc, &id)));
                self.forget(&id);
                dropped += 1;
            }
            let _ = std::fs::remove_file(dir.join(BASE_GEN_FILE));
            self.bytes = std::fs::read_dir(&dir)
                .map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum::<u64>())
                .unwrap_or(self.bytes);
        }
        self.base_gen = base_gen;
        self.boundary = boundary;
        self.epoch.set(epoch.saturating_add(1));
        dropped
    }

    /// Drop `id` from every index (its file is the caller's business).
    fn forget(&mut self, id: &BlockId) {
        if let Some(score) = self.by_id.remove(id) {
            self.by_score.remove(&(score, *id));
        }
        let gen = self.gens.remove(id).unwrap_or(0);
        self.epochs.remove(id);
        Self::count_sub(&mut self.gen_counts, gen);
    }

    /// ⛔ DB-270 — RE-STAMP a held block under `gen` (a block this node folds into A_tip again, e.g. the DB-269 re-fold
    /// after an adopt). Returns whether the window holds `id`, so the caller knows the stamp landed here. A rename that
    /// fails keeps the OLD stamp and says so: the block then reads as outside the span, which refuses a carrier (fail
    /// closed), never admits one.
    pub fn restamp(&mut self, id: &BlockId, gen: u64) -> bool {
        let Some(score) = self.by_id.get(id).copied() else {
            return false;
        };
        let old = self.gens.get(id).copied().unwrap_or(0);
        if old == gen {
            return true;
        }
        let (old_epoch, cur) = (self.epochs.get(id).copied().unwrap_or(0), self.epoch.get());
        if let Some(dir) = self.dir.as_ref() {
            let from = dir.join(Self::file_name(score, id, old, old_epoch));
            let to = dir.join(Self::file_name(score, id, gen, cur));
            // DB-270 step 2: a name written before the last checkpoint belongs to that checkpoint's instant, so it is not
            // renamed away — the new stamp is a hard link and the old name is unlinked once the NEXT checkpoint is durable
            // (a restore from the older one then still finds the old stamp). A name written since then belongs to no
            // durable instant and is renamed in place.
            let res = if old_epoch == cur {
                std::fs::rename(&from, &to)
            } else {
                std::fs::hard_link(&from, &to).map(|()| self.pending_unlink.borrow_mut().push(from.clone()))
            };
            if let Err(e) = res {
                eprintln!(
                    "[block-window] ⛔ cannot re-stamp block {} ({e}) — it keeps generation {old} and reads as outside \
                     the fold span",
                    &id.to_hex()[..8]
                );
                return true;
            }
        }
        self.gens.insert(*id, gen);
        self.epochs.insert(*id, cur);
        Self::count_sub(&mut self.gen_counts, old);
        Self::count_add(&mut self.gen_counts, gen);
        true
    }

    pub fn contains(&self, id: &BlockId) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Bytes the stored blocks occupy — on disk when a directory is named, in RAM for an in-memory window.
    pub fn stored_bytes(&self) -> usize {
        self.bytes as usize
    }

    /// Bytes this window costs in RAM: the two indexes (id → score, and the score-ordered set) plus the
    /// in-memory bodies only when no directory is named. The RAM census reads THIS, never the disk figure.
    pub fn ram_bytes(&self) -> usize {
        const INDEX_ENTRY_BYTES: usize = (32 + 8) + (8 + 32) + (32 + 8) + (32 + 8); // by_id + by_score + gens + epochs (DB-270)
        let index = self.by_id.len() * INDEX_ENTRY_BYTES;
        if self.dir.is_some() { index } else { index + self.bytes as usize }
    }

    /// The lowest blue score held, if any — the floor the locator page lane reasons from.
    pub fn floor_blue_score(&self) -> Option<u64> {
        self.by_score.iter().next().map(|(s, _)| *s)
    }

    /// Every stored block in ascending blue score — the restore order (a parent's score is below its
    /// child's). Bounded by the window span.
    pub fn ascending(&self) -> Vec<(u64, BlockId)> {
        self.by_score.iter().copied().collect()
    }

    /// Keep one whole block with its blue data. Idempotent: a block already held is not rewritten.
    /// Returns whether it was newly stored.
    /// CHAIN-PUBLISH-REVIEWED: stores a block the chain already carries; decides nothing for the chain.
    pub fn keep(
        &mut self,
        block: &Block,
        blue_work: u128,
        blue_score: u64,
        selected_parent: Option<BlockId>,
        // DB-270: the fold-base generation the block was folded into A_tip under (`GEN_NONMEMBER` if none).
        gen: u64,
    ) -> bool {
        let id = block.id();
        if self.by_id.contains_key(&id) {
            return false;
        }
        let entry = WindowEntry {
            block: block.clone(),
            blue_work,
            blue_score,
            selected_parent: selected_parent.map(|p| *p.as_bytes()),
            side_cover_key: block.cover_key,
            side_wide: block.wide_objects.clone(),
            side_notes: block.output_notes.clone(),
            side_txs: block.tx_bodies.clone(),
            side_tables: block.agg_tables.clone(),
        };
        let Ok(bytes) = postcard::to_allocvec(&entry) else {
            return false;
        };
        match self.dir.as_ref() {
            Some(dir) => {
                // The owner-approved on-disk write (user 2026-09-21: "yes you have my permission for the on
                // disc window"), recorded as `block_window.rs:pruning-window` in the storage decision channel.
                // Written under a temp name and renamed into place, so a crash mid-write leaves no half file
                // under a real name. cons: none — one file per block held, at most the horizon span of them
                // (~7,800 × 21 KB ≈ 160 MB at the default params), deleted as the horizon passes.
                let epoch = self.epoch.get();
                let final_path = dir.join(Self::file_name(blue_score, &id, gen, epoch));
                let tmp_path = dir.join(format!("{}.tmp", Self::file_name(blue_score, &id, gen, epoch)));
                // DB-270 step 2: a block pruned and kept again inside one epoch has the same name — its pending unlink
                // would delete the file written now.
                self.pending_unlink.borrow_mut().retain(|p| p != &final_path);
                if std::fs::write(&tmp_path, &bytes).is_err() {
                    return false;
                }
                if std::fs::rename(&tmp_path, &final_path).is_err() {
                    let _ = std::fs::remove_file(&tmp_path);
                    return false;
                }
            }
            None => {
                self.mem.insert(id, entry);
            }
        }
        self.by_id.insert(id, blue_score);
        self.by_score.insert((blue_score, id));
        self.whole.insert((blue_score, id));
        self.gens.insert(id, gen);
        self.epochs.insert(id, self.epoch.get());
        Self::count_add(&mut self.gen_counts, gen);
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        // goods spec §3.3: every block this node keeps passes here once, so this is where its own wallet's claim
        // watch reads the rows (a no-op unless the wallet is waiting for a download's key)
        crate::claim_watch::note_block(block);
        // Veil: a payment this node was told of for hosting a site is looked for among the block's note commitments
        // (a no-op unless one is being watched for)
        crate::veil::note_block_commitments(&block.note_commitments);
        true
    }

    /// The stored entry for `id`, read from disk (or RAM). A file that fails to read or decode is
    /// reported absent — never served.
    /// ⛔ WHY a block the index CLAIMS cannot be read back — for the callers that only see `None`.
    ///
    /// "cannot read it back" has two very different meanings with opposite fixes: the file is not there
    /// (a write that never landed, or something deleted it) versus the bytes do not decode (truncated, or
    /// a version skew). Both `prune_below` and `Node::nf_fold_inputs_page` refuse on this condition, and
    /// neither could say which — that ambiguity cost three sightings of one intermittent failure.
    #[must_use]
    pub fn read_failure_reason(&self, id: &BlockId) -> String {
        let Some(score) = self.by_id.get(id).copied() else {
            return "the index does not claim this block at all".to_string();
        };
        match self.dir.as_ref() {
            Some(dir) => {
                let path = dir.join(self.name_of(score, id));
                match std::fs::read(&path) {
                    Err(e) => format!("blue_score {score}, file {} unreadable: {e}", path.display()),
                    Ok(b) => match decode_entry(&b) {
                        Some(_) => format!("blue_score {score}: it reads back fine NOW (a transient miss)"),
                        None => format!("blue_score {score}: {} byte(s) do not decode exactly (ONE encoding per entry)", b.len()),
                    },
                }
            }
            None => match self.mem.get(id) {
                Some(_) => format!("blue_score {score}: present in memory (a transient miss)"),
                None => format!("blue_score {score}: the index claims it but memory does not hold it"),
            },
        }
    }

    pub fn entry(&self, id: &BlockId) -> Option<WindowEntry> {
        let score = *self.by_id.get(id)?;
        match self.dir.as_ref() {
            Some(dir) => {
                let bytes = std::fs::read(dir.join(self.name_of(score, id))).ok()?;
                decode_entry(&bytes)
            }
            None => self.mem.get(id).cloned(),
        }
    }

    /// The block for `id`, if the window holds it: whole near the tip, its proofs gone below [`WHOLE_KEEP`]. Every chain
    /// fact a fold or restart reads (header, tags, notes, sets) is in both forms.
    pub fn get(&self, id: &BlockId) -> Option<Block> {
        self.entry(id).map(|e| e.block)
    }

    /// The block for `id` only while it still carries its proofs: what a peer can verify, so every serve door reads this.
    /// A peer further behind than [`WHOLE_KEEP`] adopts a bundle instead, which is the O(1) sync the chain promises.
    pub fn get_whole(&self, id: &BlockId) -> Option<Block> {
        self.get(id).filter(|b| !b.pow_proof.is_empty())
    }

    /// Drop the proofs of every block below `score`, each file rewritten once under its own name (temp and rename, as
    /// [`Self::keep`] writes). A proof is most of a block and nothing a node needs again once it folded the block and
    /// no peer can be served it. Returns how many were stripped.
    /// O1-INFINITY-REVIEWED: one rewrite per block ever kept, and the set it walks is bounded by the window.
    /// LOCAL-STORAGE-REQUIRED: this makes an existing file smaller and adds none; the window it shrinks is what a restart resumes from, and no proof or wire field holds those blocks' bodies.
    /// bound: never more than the window's own block files, each about 55 KB after this, and the window is a fixed depth in blocks.
    pub fn strip_below(&mut self, score: u64) -> usize {
        let due: Vec<(u64, BlockId)> = self.whole.iter().take_while(|(s, _)| *s < score).copied().collect();
        let mut stripped = 0;
        for at in due {
            self.whole.remove(&at);
            let id = at.1;
            let Some(s) = self.by_id.get(&id).copied() else {
                continue;
            };
            let Some(mut entry) = self.entry(&id) else { continue };
            if entry.block.pow_proof.is_empty() {
                continue;
            }
            entry.block.strip_proofs();
            // §22c: the spends' transactions and the body beside them leave with the proofs
            entry.side_txs = Vec::new();
            entry.side_tables = Vec::new();
            entry.side_notes = Vec::new();
            let Ok(bytes) = postcard::to_allocvec(&entry) else { continue };
            match self.dir.as_ref() {
                Some(dir) => {
                    let path = dir.join(self.name_of(s, &id));
                    let tmp = path.with_extension("strip.tmp");
                    let old = std::fs::metadata(&path).map_or(0, |m| m.len());
                    if std::fs::write(&tmp, &bytes).is_err() || std::fs::rename(&tmp, &path).is_err() {
                        let _ = std::fs::remove_file(&tmp);
                        continue;
                    }
                    self.bytes = self.bytes.saturating_sub(old).saturating_add(bytes.len() as u64);
                }
                None => {
                    self.mem.insert(id, entry);
                }
            }
            stripped += 1;
        }
        stripped
    }

    /// Remove `id` and HAND ITS BODY BACK with its fold-base generation. The window holds only FOLDED blocks, so a
    /// block whose record a fold reorg evicted leaves it here and re-enters the unfolded set — where a node that never
    /// folded it holds it. The file is deleted at once, never deferred: the re-fold may write the same name back before
    /// a deferred unlink runs. A body that cannot be read back (or a file that cannot be deleted) stays held — `None` —
    /// like `prune_below`'s refusal to forget a body it did not hand back.
    /// ROOT-LAYER: the window is WRITTEN by the fold (`keep` at the fold step); the rewind is the one inverse of that
    /// write, so the eviction un-writes it here rather than any census or reader learning to skip evicted entries.
    /// MEASURED: before — fold-root-drop pin (scratchpad/night/droppin-red1.out) block_window + nf_unfolded_gen DIFFER
    /// between a node that folded-then-evicted and one that never folded; after — the droppin run of this commit.
    /// MUST-STAY-GREEN: prune_below's hand-back, restamp, the window census pins, the canonical_record_fold_tests.
    /// O1-INFINITY-REVIEWED: removes ONE entry of the existing horizon-bounded window (keep_depth blocks, a constant);
    /// the one read is of the body being moved to the unfolded set, never a reconstruction of authority or a new store.
    pub fn take(&mut self, id: &BlockId) -> Option<(Block, u64)> {
        let score = *self.by_id.get(id)?;
        let gen = *self.gens.get(id)?;
        let e = match self.dir.as_ref() {
            Some(dir) => {
                let path = dir.join(self.name_of(score, id));
                let bytes = std::fs::read(&path).ok()?;
                let e = decode_entry(&bytes)?;
                std::fs::remove_file(&path).ok()?;
                self.bytes = self.bytes.saturating_sub(bytes.len() as u64);
                e
            }
            None => {
                let e = self.mem.remove(id)?;
                if let Ok(v) = postcard::to_allocvec(&e) {
                    self.bytes = self.bytes.saturating_sub(v.len() as u64);
                }
                e
            }
        };
        self.forget(id);
        Some((e.block, gen))
    }

    /// Delete every block whose blue score is below `horizon` and HAND THEM BACK, ascending. Cost is the
    /// number removed (a range walk over the ordered set), never the window size — one block per block in
    /// steady state.
    ///
    /// ⭐ RETURNING THE BODIES IS WHAT LETS THE NULLIFIER FOLD BASE FOLLOW THE SAME HORIZON THE WINDOW
    /// CUTS AT. A block leaving the window is the exact moment its nullifier transition stops being
    /// servable, so it is also the moment it must be absorbed into the base a spender roots its absence
    /// carrier at (`Node::advance_nf_fold_base`). Reading them here costs nothing extra: the entry is
    /// already loaded on the deletion path, and handing it back replaces a second read the caller would
    /// otherwise have to do BEFORE calling this — which would be a read of a file this call then deletes.
    ///
    /// DB-270: each body comes back WITH its fold-base generation, because only a MEMBER of the fold span may be absorbed
    /// into the base (a block of an adopted past is already counted by the certified base it adopted).
    pub fn prune_below(&mut self, horizon: u64) -> Vec<(Block, u64)> {
        let gone: Vec<(u64, BlockId)> =
            self.by_score.range(..(horizon, crate::hash::Hash32([0u8; 32]))).copied().collect();
        let mut out: Vec<(Block, u64)> = Vec::with_capacity(gone.len());
        for (score, id) in &gone {
            self.by_score.remove(&(*score, *id));
            self.by_id.remove(id);
            let gen = self.gens.remove(id).unwrap_or(0);
            let epoch = self.epochs.remove(id).unwrap_or(0);
            Self::count_sub(&mut self.gen_counts, gen);
            match self.dir.as_ref() {
                Some(dir) => {
                    let path = dir.join(Self::file_name(*score, id, gen, epoch));
                    let len = match std::fs::metadata(&path) {
                        Ok(m) => m.len(),
                        Err(_) => 0, // census only — see the module doc
                    };
                    // ⛔⛔⛔ A BLOCK MAY NOT BE FORGOTTEN UNLESS ITS BODY WAS HANDED BACK.
                    //
                    // ROOT-LAYER: the caller folds every returned body into `nf_fold_base`, and the base
                    // plus the surviving window must reproduce A_tip — that identity is what lets ANY
                    // spender build a carrier that reaches the tip. This arm used to `remove_file`
                    // unconditionally while only pushing the body on a successful read+decode. A failed
                    // read therefore removed the block from the index AND DELETED ITS ONLY COPY, so the
                    // base could never absorb it and A_tip counted a block nothing could account for.
                    // Permanent and irrecoverable — the file is gone.
                    //
                    // MEASURED 2026-09-24, the third sighting of an intermittent failure I could not
                    // isolate twice: `[node-carrier] … ARITHMETIC: A_tip has taken nf_fold_seq=90 step(s),
                    // the base absorbed base_seq=61, so the span should be 29 block(s) and it is 19 —
                    // SHORT: blocks A_tip counted are missing from the span.` TEN blocks in neither.
                    //
                    // ⛔ THE COST IS EVERY SPENDER. A wallet folds the served span and compares to the
                    // served A_tip; once a block is lost from both, that comparison can NEVER close, so
                    // the carrier never becomes Ready and the send fails with nothing to point at — at
                    // every height, forever, on that node.
                    //
                    // So: hand it back or KEEP it. An unreadable file is left indexed and undeleted for
                    // the next pass — transient pressure heals, and a genuinely corrupt file stops the
                    // window shrinking and says so, which is a loud operational condition rather than a
                    // silently broken spend path. Liveness is unaffected: the chain keeps advancing.
                    // ⛔ NAME THE ACTUAL CAUSE. "cannot read back" has two very different meanings — the
                    // file is not there (a write that never landed, or something deleted it) versus the
                    // bytes do not decode (a truncated or version-skewed entry) — and they need opposite
                    // fixes. Saying only "cannot" is what made this take three sightings to isolate.
                    let why: String;
                    let body = match std::fs::read(&path) {
                        Err(e) => {
                            why = format!("the file is unreadable: {e}");
                            None
                        }
                        Ok(bytes) => match decode_entry(&bytes) {
                            Some(e) => {
                                why = String::new();
                                Some(e)
                            }
                            None => {
                                why = format!("{} byte(s) present but they do not decode exactly (ONE encoding per entry)", bytes.len());
                                None
                            }
                        },
                    };
                    match body {
                        Some(e) => {
                            out.push((e.block, gen));
                            // ⛔ DB-270 step 2: NOT unlinked yet — the checkpoint on disk may still count this block as a
                            // span member. It goes once the next checkpoint (which records the absorbing base) is durable.
                            self.pending_unlink.borrow_mut().push(path.clone());
                            self.bytes = self.bytes.saturating_sub(len);
                        }
                        None => {
                            // Put it back: it was never absorbed, so it must stay the window's problem.
                            self.by_score.insert((*score, *id));
                            self.whole.insert((*score, *id));
                            self.by_id.insert(*id, *score);
                            self.gens.insert(*id, gen);
                            self.epochs.insert(*id, epoch);
                            Self::count_add(&mut self.gen_counts, gen);
                            eprintln!(
                                "[block-window] ⛔ cannot read back block {} at blue_score {score} ({why}) \
                                 — NOT pruned and NOT deleted. Its body has never been folded into the \
                                 nullifier fold base, so deleting it would leave A_tip counting a block \
                                 neither the base nor the span can account for, and no spender could ever \
                                 build a carrier that reaches the tip on this node.",
                                &id.to_hex()[..8]
                            );
                        }
                    }
                }
                None => {
                    if let Some(e) = self.mem.remove(id) {
                        let len = match postcard::to_allocvec(&e) {
                            Ok(v) => v.len() as u64,
                            Err(_) => 0, // census only — see the module doc
                        };
                        self.bytes = self.bytes.saturating_sub(len);
                        out.push((e.block, gen));
                    }
                }
            }
        }
        // DB-270 step 2: the boundary a checkpoint records — below it every block has left the window. A block that could
        // not be read back stays held (above), so the boundary never passes it: a restore must not delete an unabsorbed
        // block as if the base counted it.
        let held_floor = self.by_score.iter().next().map(|(s, _)| *s).unwrap_or(horizon);
        self.boundary = self.boundary.max(horizon.min(held_floor));
        out
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn block_with_ts(ts: u64) -> Block {
        let mut b = crate::block::genesis_block();
        b.header.timestamp = ts;
        b.pow_proof = vec![7u8; 32];
        b
    }

    /// The window keeps whole blocks with their blue data, answers by id, and drops everything below the
    /// horizon — the same behaviour on disk and in RAM. TWO-PARTY-REVIEWED: a store's own bookkeeping; the
    /// cross-node side (a restarted node serving a peer from this store) is the real-node restart journey
    /// `a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin`.
    #[test]
    fn the_window_keeps_serves_and_prunes_the_same_on_disk_and_in_ram() {
        let dir = std::env::temp_dir().join(format!("usdmd-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for mut w in [BlockWindow::in_memory(), BlockWindow::open(dir.clone())] {
            let a = block_with_ts(100);
            let b = block_with_ts(200);
            assert!(w.keep(&a, 10, 5, None, 0), "first keep stores");
            assert!(!w.keep(&a, 10, 5, None, 0), "a second keep of the same block is a no-op");
            assert!(w.keep(&b, 20, 9, Some(a.id()), 0));
            assert_eq!(w.len(), 2);
            assert_eq!(w.floor_blue_score(), Some(5));
            let e = w.entry(&b.id()).expect("b is held");
            assert_eq!(
                (e.blue_work, e.blue_score, e.selected_parent),
                (20, 9, Some(*a.id().as_bytes()))
            );
            assert_eq!(w.get(&a.id()).map(|x| x.id()), Some(a.id()));
            assert_eq!(w.ascending(), vec![(5, a.id()), (9, b.id())]);
            let left = w.prune_below(9);
            assert_eq!(left.len(), 1, "only the block below the horizon leaves");
            assert_eq!(
                left[0].0.id(),
                a.id(),
                "the pruned BODY is handed back — the nullifier fold base is advanced from it, so a \
                 count alone would silently drop the transition of every block that leaves the window"
            );
            assert!(!w.contains(&a.id()) && w.contains(&b.id()));
            assert!(w.get(&a.id()).is_none(), "a pruned block is gone, not served");
            // DECLARED FIXTURE AMENDMENT (DB-270 step 2): the pruned file is unlinked once a checkpoint is durable.
            let (_, unlink) = w.seal_epoch();
            BlockWindow::flush_unlinks(&unlink);
        }
        // A reopen indexes what the first incarnation left on disk — the restart shape.
        let reopened = BlockWindow::open(dir.clone());
        assert_eq!(reopened.len(), 1, "the surviving block is indexed from its file name alone");
        assert!(reopened.get(&block_with_ts(200).id()).is_some(), "…and its body reads back");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔ DB-270 — THE FOLD-BASE GENERATION SURVIVES A REOPEN, A RE-STAMP AND A PRUNE, on disk and in RAM alike: a block
    /// stamped under generation g reads back under g after a reopen (its file name carries it), a re-stamp moves it
    /// (and its count), a bumped base generation is read back by the next incarnation, and a pruned body comes back
    /// with the generation the caller must judge membership by. TWO-PARTY-REVIEWED: a store's own bookkeeping across
    /// two incarnations; the cross-node side is `db270_*` (a jumper against its origin).
    #[test]
    fn a_blocks_fold_base_generation_survives_reopen_restamp_and_prune() {
        let dir = std::env::temp_dir().join(format!("usdmd-window-gen-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (a, b) = (block_with_ts(300), block_with_ts(400));
        {
            let mut w = BlockWindow::open(dir.clone());
            assert!(w.keep(&a, 10, 5, None, 0) && w.keep(&b, 20, 9, Some(a.id()), GEN_NONMEMBER));
            assert_eq!((w.count_gen(0), w.count_gen(GEN_NONMEMBER)), (1, 1), "one member, one non-member");
            assert_eq!(w.bump_base_gen(), 1, "a new generation starts");
            assert!(w.restamp(&b.id(), 1), "b is held, so the re-stamp lands here");
            assert_eq!((w.count_gen(1), w.count_gen(GEN_NONMEMBER)), (1, 0), "the re-stamp moved b's count");
        }
        let mut w = BlockWindow::open(dir.clone());
        // DECLARED FIXTURE AMENDMENT (DB-270 step 2): the generation comes back through the checkpoint's fold record.
        w.apply_checkpoint(u64::MAX - 1, 1, 0);
        assert_eq!(w.base_gen(), 1, "the reopened window reads the bumped generation");
        assert_eq!((w.gen_of(&a.id()), w.gen_of(&b.id())), (Some(0), Some(1)), "each file name carried its stamp");
        assert!(w.get(&b.id()).is_some(), "a re-stamped block still reads back");
        let left = w.prune_below(9);
        assert_eq!(left.len(), 1);
        assert_eq!((left[0].0.id(), left[0].1), (a.id(), 0), "the pruned body comes back with its generation");
        assert!(!w.restamp(&a.id(), 1), "a pruned block is not held, so a re-stamp does not land here");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔ DB-270 step 2 — A CHECKPOINT KEEPS EXACTLY THE FILES ITS INSTANT COUNTED: a file written after the capture is
    /// dropped at the restore, a re-stamp after the capture falls back to the stamp the capture saw, and a prune after the
    /// capture leaves the file on disk (the restored base never absorbed it) until the next checkpoint is durable.
    /// TWO-PARTY-REVIEWED: a store's own bookkeeping across two incarnations; the cross-node side is the DB-270 R4–R7 pins.
    #[test]
    fn a_checkpoint_keeps_exactly_the_files_its_instant_counted() {
        let dir = std::env::temp_dir().join(format!("usdmd-window-epoch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (a, b, c) = (block_with_ts(500), block_with_ts(600), block_with_ts(700));
        let e;
        {
            let mut w = BlockWindow::open(dir.clone());
            assert!(w.keep(&a, 10, 5, None, 0) && w.keep(&b, 20, 9, Some(a.id()), GEN_NONMEMBER));
            let (sealed, unlink) = w.seal_epoch(); // THE capture
            assert!(unlink.is_empty(), "nothing was pruned before the capture");
            e = sealed;
            assert!(w.keep(&c, 30, 12, Some(b.id()), 0), "c is written after the capture");
            assert!(w.restamp(&b.id(), 0), "b is re-stamped after the capture");
            let left = w.prune_below(9);
            assert_eq!(left.len(), 1, "a is pruned after the capture");
            // THE CRASH: no second capture, so nothing pending is unlinked.
        }
        let mut w = BlockWindow::open(dir.clone());
        assert_eq!(w.apply_checkpoint(e, 0, 0), 1, "exactly c (written after the capture) stops being held");
        assert!(!w.contains(&c.id()), "a block written after the checkpoint is not held — it re-arrives by the graft door");
        assert_eq!(w.gen_of(&b.id()), Some(GEN_NONMEMBER), "b falls back to the stamp the checkpoint saw");
        assert_eq!(w.gen_of(&a.id()), Some(0), "a, pruned after the checkpoint, is still held for the base that never absorbed it");
        let names = std::fs::read_dir(&dir).map(|rd| rd.flatten().count()).unwrap_or(0);
        assert_eq!(names, 2, "one file per held block — the newer names are gone");
        // A second restore from a checkpoint that DID record the prune deletes a without absorbing it.
        let mut w2 = BlockWindow::open(dir.clone());
        assert_eq!(w2.apply_checkpoint(e, 0, 9), 1, "a, below the recorded boundary, is deleted");
        assert!(!w2.contains(&a.id()) && w2.contains(&b.id()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

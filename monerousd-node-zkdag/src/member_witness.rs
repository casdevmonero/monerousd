// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ DB-223 — THE WALLET'S MEMBER WITNESS BOOK: a depth-64 path per owned note, kept current from PUBLIC data only,
//! and the member-path carrier a spend attaches (`PqTx::member_carrier`).
//!
//! It lives in the node library so the wallet and the node's own pins run ONE spelling of the capture, the refresh and
//! the carrier build (the wallet feeds it over HTTP; a pin feeds it from an in-process node).
//!
//! What it reads, and why none of it names a note (DB-223 Q2 §9):
//!   * the node's PATH-REFRESH STREAM (`Node::path_refresh_stream` / `POST /path_refresh_stream`): the completed
//!     subtree windows since a cursor, the newest anchor-ring root and the current frontier peaks — byte-identical for
//!     every wallet, addressed by tree position, never by note;
//!   * the note's OWN record (its 256 leaves), which the wallet already reads to learn it owns the note.
//!
//! The witness is CAPTURED AT ARRIVAL (AGENTS.md §6: a witness can only be captured at the instant of arrival), and
//! NOTHING in it depends on when the wallet polls:
//!   * the record's fold ordinal is found by its level-8 ROOT, which the stream carries as a merge child (both children
//!     of every merge ride it, §9 item 5) — or, for the newest record at an odd ordinal, as the frontier's own level-8
//!     peak;
//!   * levels 0–7 come from the record's own 256 leaves;
//!   * a level ≥ 8 sibling, left or right, comes from the stream entry of the merge that completes the note's ancestor,
//!     every one of which is at or after the record's own fold; a sibling whose merge has not happened yet is read from
//!     the newest peaks (`IncrementalWitness::authpath_against`).
//! The book keeps the stream's entries for the stream's own reach (`Node::anchor_ring_len_of`), so a note detected
//! after its record folded — a lagging scan — replays them locally, with no different ask on the wire. Beyond that
//! reach is the restore path (the catch-up waves); until they exist the spend keeps the legacy membership door.
//!
//! TRUST: nothing from the node is believed — a carrier is built only when the refreshed path refolds to the newest
//! RING root the stream named, and the node's pool gate re-checks that root against its OWN ring.

use crate::spend_frontier::{Digest4, IncrementalWitness, PoseidonSpendFrontier, SPEND_TREE_DEPTH};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Leaves per record (`cover::BLOCK_FIXED_NOTE_COUNT`).
const RECORD_LEAVES: u64 = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;

/// The level at which a record is one subtree (`2^8 = RECORD_LEAVES`).
const RECORD_LEVEL: usize = crate::spend_frontier::RECORD_SUBTREE_LEVEL;

/// ⭐ DB-223 Q2 §12d L — the levels above the record a wallet KEEPS once they are fixed forever: `RECORD_LEVEL ..
/// HIGH_LEVEL`, every level whose window completes inside the note's own index shard. From the window index's own
/// constants, never a literal.
pub const FIXED_LEVELS: usize = crate::window_index::HIGH_LEVEL - crate::window_index::RECORD_LEVEL;
const _: () = assert!(RECORD_LEVEL == crate::window_index::RECORD_LEVEL, "the book and the index agree on the record level");

/// A-F25 — the one refusal of an object's leg that is a WAIT and nothing else: the note's record folded after the
/// node's newest final step. A caller shows it as "final in a moment" and asks again; every other refusal is a fault.
pub const NOT_FINAL_YET: &str = "the note is not final yet — its object waits for the chain to make the note's own step final";

/// The stream's reach in fold steps — the same definition the node's stream window reads.
fn stream_reach() -> u64 {
    crate::params::anchor_ring_len_of(&crate::params::ChainParams::default()) as u64
}

/// ⭐ DB-223 — parse a `POST /path_refresh_stream` answer (the JSON `rpc_http` serves) back into the stream the book
/// applies. The ONE wire spelling, beside the book, so the wallet cannot drift from the serve. `None` for anything that
/// is not exactly that answer (a missing field, a non-hex root, a root that is not a digest).
#[must_use]
pub fn stream_from_json(v: &serde_json::Value) -> Option<crate::node::PathRefreshStream> {
    let root = |s: &str| -> Option<Digest4> {
        let bytes = crate::rpc_http::hex_decode(s)?;
        crate::spend_frontier::digest_from_lane_bytes(&bytes)
    };
    let mut entries = Vec::new();
    for e in v.get("entries")?.as_array()? {
        let level = u8::try_from(e.get("level")?.as_u64()?).ok()?;
        entries.push((e.get("ordinal")?.as_u64()?, level, e.get("window")?.as_u64()?, root(e.get("root_hex")?.as_str()?)?));
    }
    let newest_ordinal = v.get("newest_ordinal")?.as_u64()?;
    let newest_hex = v.get("newest_root_hex")?.as_str()?;
    let newest = if newest_hex.is_empty() { None } else { Some((newest_ordinal, root(newest_hex)?)) };
    let since_hex = v.get("since_root_hex")?.as_str()?;
    let since_root = if since_hex.is_empty() { None } else { Some(root(since_hex)?) };
    // A-F25: the newest FINAL ring entry and the peaks at that step. Absent, or an empty root, is "this node names none"
    // (an object then waits); a root that is present and is not a digest refuses the whole answer, as every root does.
    let final_hex = v.get("final_root_hex").and_then(|h| h.as_str()).unwrap_or("");
    let final_anchor = if final_hex.is_empty() { None } else { Some((v.get("final_ordinal")?.as_u64()?, root(final_hex)?)) };
    Some(crate::node::PathRefreshStream {
        entries,
        newest,
        peaks_hex: v.get("peaks_hex")?.as_str()?.to_string(),
        catch_up: v.get("catch_up")?.as_bool()?,
        since: v.get("since")?.as_u64()?,
        since_root,
        final_anchor,
        final_peaks_hex: v.get("final_peaks_hex").and_then(|h| h.as_str()).unwrap_or("").to_string(),
    })
}

/// ⭐ DB-223 Q2 §11 R-b3 — a note's place INSIDE its record: its slot and its 8 intra-record siblings (levels 0–7). Fixed
/// forever at the record's fold: the record's leaves and their order are the record's own, so a fold rewind that moves
/// the record to another ordinal moves none of these. It is therefore all a note needs to be re-captured — after a
/// rewind or a restart — with no record fetch: the record's level-8 root refolds from the leaf and this path, and names
/// the record's ordinal in the stream. 1 + 8 × 64 = 513 B, where the whole record is 256 × 64 = 16 KB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecordPath {
    /// The note's slot in its record (`0..RECORD_LEAVES`).
    pub slot: u8,
    /// The level-`l` sibling of the note's level-`l` ancestor, `l = 0..8`.
    pub siblings: [Digest4; RECORD_LEVEL],
}

impl RecordPath {
    /// The path of `cm` inside the record whose 256 leaves are `leaves` (the record's own order,
    /// `Node::block_leaves_from_notes`). `None` when `leaves` is not a whole record or `cm` is not one of its leaves.
    #[must_use]
    pub fn of_record(cm: &[u8; 32], leaves: &[Digest4]) -> Option<Self> {
        if leaves.len() as u64 != RECORD_LEAVES {
            return None;
        }
        let leaf = crate::spend_frontier::note_leaf_of(cm);
        let slot = leaves.iter().position(|l| *l == leaf)?;
        let mut level: Vec<Digest4> = leaves.to_vec();
        let mut idx = slot;
        let mut siblings = [Digest4::default(); RECORD_LEVEL];
        for s in siblings.iter_mut() {
            *s = level[idx ^ 1];
            level = level.chunks_exact(2).map(|p| crate::spend_frontier::poseidon_pair(p[0], p[1])).collect();
            idx >>= 1;
        }
        Some(Self { slot: u8::try_from(slot).ok()?, siblings })
    }

    /// The ONE byte spelling of a path (the wallet's store writes and reads exactly this): `slot(1) ‖ 8 × digest lanes`.
    pub const BYTES: usize = 1 + RECORD_LEVEL * crate::spend_frontier::DIGEST_LANE_BYTES;

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.push(self.slot);
        for s in &self.siblings {
            out.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(s));
        }
        out
    }

    /// `None` unless `b` is EXACTLY [`Self::BYTES`] long — a short buffer is refused, never padded.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::BYTES {
            return None;
        }
        let mut siblings = [Digest4::default(); RECORD_LEVEL];
        for (s, chunk) in siblings.iter_mut().zip(b[1..].chunks_exact(crate::spend_frontier::DIGEST_LANE_BYTES)) {
            *s = crate::spend_frontier::digest_from_lane_bytes(chunk)?;
        }
        Some(Self { slot: b[0], siblings })
    }

    /// The record's level-8 root, refolded from the note's leaf and this path.
    #[must_use]
    pub fn record_root(&self, leaf: Digest4) -> Digest4 {
        let mut acc = leaf;
        for (l, s) in self.siblings.iter().enumerate() {
            acc = if (self.slot >> l) & 1 == 0 {
                crate::spend_frontier::poseidon_pair(acc, *s)
            } else {
                crate::spend_frontier::poseidon_pair(*s, acc)
            };
        }
        acc
    }
}

/// ⭐ DB-223 — the member witness book (see the module doc). Serializable: it is the wallet's own knowledge (its notes'
/// paths), kept beside its seed, never sent anywhere.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MemberWitnessBook {
    /// One incremental witness per owned note, keyed by its commitment, with its [`RecordPath`] — kept so a fold REWIND
    /// can re-capture the note from its own record (R-b3: the path is the record's whole contribution, 513 B, not its
    /// 256 leaves), the one input the stream cannot resend.
    notes: BTreeMap<[u8; 32], (IncrementalWitness, RecordPath)>,
    /// The stream entries `(fold ordinal, level, window, root)` of the last [`stream_reach`] fold steps, oldest first.
    recent: VecDeque<(u64, u8, u64, Digest4)>,
    /// The newest anchor-ring entry the stream named: the root a carrier must refold to.
    newest: Option<(u64, Digest4)>,
    /// The frontier peaks at that same fold step.
    peaks_hex: String,
    /// ⭐ A-F25 — the newest FINAL anchor-ring entry the stream named (a fold step no rewind can re-order,
    /// `Node::final_anchor`): the root an OBJECT's leg refolds to ([`AnchorRule::Final`]). `None` until a node names one.
    #[serde(default)]
    final_anchor: Option<(u64, Digest4)>,
    /// The frontier peaks at that final step.
    #[serde(default)]
    final_peaks_hex: String,
    /// The stream cursor: every entry at or below it has been applied.
    cursor: u64,
    /// Owned notes seen in an APPLIED block whose record has not folded yet: `(cm, its RecordPath, a persisted ordinal
    /// hint)`. A wallet learns it owns a note when the block is applied, about one fold depth before the record takes its
    /// position, so the capture waits here until the stream reaches that fold (bounded by the wallet's own pending
    /// receipts). The hint is `Some` only for a note restored from the wallet's store ([`Self::path_restored`]).
    pending: Vec<([u8; 32], RecordPath, Option<u64>)>,
    /// ⭐ DB-223 Q2 §12d L — a restarted wallet's KEPT levels `RECORD_LEVEL..HIGH_LEVEL` for a note not captured yet
    /// ([`Self::fixed_levels_restored`]); applied at the note's capture, before any stream entry. Bounded by the owned
    /// set ([`Self::retain_notes`]), never by history.
    #[serde(default)]
    restored_fixed: BTreeMap<[u8; 32], [Digest4; FIXED_LEVELS]>,
    /// ⭐ THE BOOK'S WANT SET — owned notes the wallet registered ([`Self::want_all`]) that the book does not hold yet: the
    /// notes whose record the wallet asks by address when the stream cannot deliver it. WRITTEN where a note joins the
    /// wallet's owned set and cleared at its capture, so a scan pass reads the want set (the delta), never the owned set —
    /// the "write it down, then look it up" shape. Bounded by the owned set ([`Self::retain_notes`]), never by history.
    #[serde(default)]
    wanted: BTreeSet<[u8; 32]>,
}

/// What one stream window NAMES ([`MemberWitnessBook::stream_names`]), built once per capture pass.
struct StreamNames {
    by_root: std::collections::HashMap<Digest4, u64>,
    newest_peak: Option<(u64, Digest4)>,
    newest: Option<u64>,
}

#[cfg(test)]
thread_local! {
    /// Record-root refolds a capture decision paid (the restore-cost pin's count; test builds only).
    static RECORD_ROOT_REFOLDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl StreamNames {
    /// The fold ordinal at which the note's record took its position: the record is the level-8 window `ordinal − 1`, so
    /// its ROOT names it — as a merge child in the kept stream entries, or, while it is the newest record at an odd
    /// ordinal and has no right sibling yet, as the newest frontier's own level-8 peak. A record's leaves carry its cover
    /// fill, derived from the record's own id, so two records never share a root. Else a restored ordinal (the wallet's
    /// fetch-confirmed position, just re-confirmed by fetching that record and finding the note in it) is accepted for ANY
    /// record already folded (1 ..= newest).
    fn place(&self, cm: &[u8; 32], path: &RecordPath, hint: Option<u64>) -> Option<u64> {
        #[cfg(test)]
        RECORD_ROOT_REFOLDS.with(|c| c.set(c.get() + 1));
        let root = path.record_root(crate::spend_frontier::note_leaf_of(cm));
        self.by_root
            .get(&root)
            .and_then(|window| window.checked_add(1))
            .or_else(|| self.newest_peak.filter(|(_, peak)| *peak == root).map(|(ordinal, _)| ordinal))
            .or_else(|| hint.filter(|o| self.newest.is_some_and(|n| *o >= 1 && *o <= n)))
    }
}

/// ⭐ DB-223 Q2 §12d L — apply kept fixed levels to a witness, each ONLY through `capture_completed_window`: a root is
/// taken only at the note's own sibling window at that level and only into an empty level. Nothing is believed — a
/// wrong root folds the path to a root the ring does not hold, and `carrier_for` refuses it.
fn apply_fixed_levels(w: &mut IncrementalWitness, levels: &[Digest4; FIXED_LEVELS]) {
    let index = w.index();
    for (i, root) in levels.iter().enumerate() {
        let level = RECORD_LEVEL + i;
        let _ = w.capture_completed_window(level, (index >> level) ^ 1, *root);
    }
}

impl MemberWitnessBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cursor to ask the next stream answer from.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Whether the book holds a witness for `cm`.
    #[must_use]
    pub fn holds(&self, cm: &[u8; 32]) -> bool {
        self.notes.contains_key(cm)
    }

    /// Apply one stream answer: every completed window goes to every witness (each takes only its own path's
    /// siblings), the newest ring root and its peaks are remembered. When the node says the cursor predates its window,
    /// the answer is STILL applied — a book that refused it would stand at that cursor forever — and a book holding
    /// witnesses answers `Err`: a window completed in the gap may be one of their paths' siblings, so those paths fail
    /// closed at `carrier_for` until the catch-up waves repair them. Never a silently holed refresh.
    pub fn apply_stream(&mut self, s: &crate::node::PathRefreshStream) -> Result<(), &'static str> {
        // ⭐ A FOLD REWIND: the node's ring root at this book's cursor is not the one the book applied, so windows the
        // book captured after the fork may have been rewritten. The node's rewind reaches at most its journal
        // (`SPINE_RING_LEN` steps ≤ the stream's reach), so everything at or below `cursor − reach` stands.
        if let (Some(theirs), Some((ordinal, ours))) = (s.since_root, self.newest) {
            if s.since == self.cursor && ordinal == self.cursor && theirs != ours {
                self.rewind_to(self.cursor.saturating_sub(stream_reach()));
                return Err("the node's fold history differs from the one this book applied — re-capturing from the fork");
            }
        }
        // ⭐ THE SAME REWIND, SEEN FROM BELOW: the node's ring newest stands BELOW this book's cursor. A ring only moves
        // back by a rewind (or the mesh walk answered from a node that is behind — re-capturing then costs one poll and
        // nothing else), and after a rewind below the cursor the ring no longer HOLDS the cursor's step, so `since_root`
        // is `None` and the check above cannot fire. MEASURED (launch leg 1 at 10 nodes, seed 0x713100f320261022,
        // scratchpad/verify/launch-leg1-g11b-20261022-2245.log:12449 → :24046): node 0 rewound "16 record(s) from
        // ordinal 69" below the wallet's cursor; the book kept the rewound order's windows, anchored its carrier at a root
        // the fold never produced, and the node refused the send ("… never produced within its ring"). Pinned by
        // `a_ring_newest_below_the_books_cursor_is_a_rewind_and_the_book_recaptures_from_the_fork`. BORROWED SHAPE: Zcash's
        // wallet drops a note's witness history above a reorg and re-anchors in the current chain.
        if s.since == self.cursor && s.newest.is_some_and(|(o, _)| o < self.cursor) {
            self.rewind_to(self.cursor.saturating_sub(stream_reach()));
            return Err("the node's ring stands below this book's cursor — its fold rewound; re-capturing from the fork");
        }
        let holed = s.catch_up && !self.notes.is_empty();
        let before = self.cursor;
        for &(ordinal, level, window, root) in &s.entries {
            if ordinal <= before {
                continue; // already applied (the serve answers `> since`; this keeps a repeated answer idempotent)
            }
            for (w, _) in self.notes.values_mut() {
                let _ = w.capture_completed_window(usize::from(level), window, root);
            }
            self.recent.push_back((ordinal, level, window, root));
            self.cursor = self.cursor.max(ordinal);
        }
        if let Some((ordinal, root)) = s.newest {
            self.newest = Some((ordinal, root));
            self.peaks_hex = s.peaks_hex.clone();
            self.cursor = self.cursor.max(ordinal);
        }
        // A-F25: the node's newest final step, with its peaks. A final step only moves forward; an answer that names none
        // (a node that has just started, or one that predates the field) leaves the one this book holds standing.
        if let Some((ordinal, root)) = s.final_anchor {
            if self.final_anchor.is_none_or(|(held, _)| ordinal >= held) {
                self.final_anchor = Some((ordinal, root));
                self.final_peaks_hex = s.final_peaks_hex.clone();
            }
        }
        let floor = self.cursor.saturating_sub(stream_reach());
        while self.recent.front().is_some_and(|(o, ..)| *o <= floor) {
            self.recent.pop_front();
        }
        self.capture_pending();
        if holed {
            return Err("the stream no longer reached this book's cursor — held paths wait for the one-shot catch-up");
        }
        Ok(())
    }

    /// Step the book back to fold step `floor`: stream state above it is dropped (the next ask re-reads it), a note whose
    /// record folded above it waits to be captured afresh (the record may re-fold elsewhere), and every other note
    /// forgets the captures of merges that completed after `floor`.
    fn rewind_to(&mut self, floor: u64) {
        self.recent.retain(|(o, ..)| *o <= floor);
        self.cursor = floor;
        self.newest = None;
        self.peaks_hex.clear();
        if self.final_anchor.is_some_and(|(o, _)| o > floor) {
            // a "final" step above a rewind's floor was not final on the node that now answers: forget it, fail closed
            self.final_anchor = None;
            self.final_peaks_hex.clear();
        }
        let after = floor.saturating_mul(RECORD_LEAVES);
        for (cm, (mut w, path)) in std::mem::take(&mut self.notes) {
            if w.index() >= after {
                self.pending.push((cm, path, None));
                self.wanted.insert(cm); // its capture is undone: the book wants it again
            } else {
                w.forget_captures_after(after, RECORD_LEVEL);
                self.notes.insert(cm, (w, path));
            }
        }
    }

    /// Keep paths (and waiting captures) only for the notes `keep` says this wallet still owns: a spent note's path goes
    /// with it, so the book is bounded by the owned set, never by history.
    pub fn retain_notes(&mut self, keep: impl Fn(&[u8; 32]) -> bool) {
        self.notes.retain(|cm, _| keep(cm));
        self.pending.retain(|(cm, ..)| keep(cm));
        self.restored_fixed.retain(|cm, _| keep(cm));
        self.wanted.retain(|cm| keep(cm));
    }

    /// Register owned notes the book must come to hold ([`Self::wanted_notes`]); a note it already holds is not registered.
    /// The wallet calls this where a note JOINS its owned set (the merge of a pass's hits; the store restore, the rescan
    /// rebuild and its carry-forward), so the cost is the size of the set that changed.
    pub fn want_all(&mut self, cms: impl IntoIterator<Item = [u8; 32]>) {
        for cm in cms {
            if !self.notes.contains_key(&cm) {
                self.wanted.insert(cm);
            }
        }
    }

    /// The registered notes the book does not hold yet (pending ones included: a pending note may need its record's
    /// ordinal), in commitment order.
    #[must_use]
    pub fn wanted_notes(&self) -> Vec<[u8; 32]> {
        self.wanted.iter().copied().collect()
    }

    /// ⭐⭐ DB-223 Q2 §12d L — the note's siblings at levels `RECORD_LEVEL..HIGH_LEVEL` once they are FIXED FOREVER: every
    /// one captured, AND the merge completing the note's level-`HIGH_LEVEL` ancestor (leaf `((index >> HIGH_LEVEL) + 1) <<
    /// HIGH_LEVEL`) at a fold ordinal no rewind can reach any more (`≤ cursor − stream reach`, the rule
    /// [`Self::path_restored`]'s ordinal hint obeys). What a wallet keeps beside the note's [`RecordPath`] so a restart asks
    /// nothing for these levels. `None` before that: `capture_completed_window` only FILLS an empty level, so a kept root
    /// that a later rewind moved would block the stream's correct capture — a level is kept only once nothing can move it.
    #[must_use]
    pub fn fixed_levels(&self, cm: &[u8; 32]) -> Option<[Digest4; FIXED_LEVELS]> {
        let (w, _) = self.notes.get(cm)?;
        let floor = self.cursor.checked_sub(stream_reach())?;
        let completes_leaf = (u128::from(w.index() >> crate::window_index::HIGH_LEVEL) + 1) << crate::window_index::HIGH_LEVEL;
        if completes_leaf / u128::from(RECORD_LEAVES) > u128::from(floor) {
            return None;
        }
        let mut out = [Digest4::default(); FIXED_LEVELS];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = w.captured_sibling(RECORD_LEVEL + i)?;
        }
        Some(out)
    }

    /// ⭐ DB-223 Q2 §12d L — the RESTART door for [`Self::fixed_levels`]: `levels` a wallet kept for `cm` are applied when
    /// the note is captured (at once if the book already holds it), each only through `capture_completed_window` (see
    /// `apply_fixed_levels`). A restarted wallet then needs no stream entry and no index ask for these levels.
    pub fn fixed_levels_restored(&mut self, cm: [u8; 32], levels: [Digest4; FIXED_LEVELS]) {
        match self.notes.get_mut(&cm) {
            Some((w, _)) => apply_fixed_levels(w, &levels),
            None => {
                self.restored_fixed.insert(cm, levels);
            }
        }
    }

    /// ⭐ DB-223 Q2 §12d H — what ONE held note still needs from a catch-up: its sibling `(level, window)` at every HIGH
    /// level (`≥ window_index::HIGH_LEVEL`) whose ancestor merge has COMPLETED by the newest peaks (leaf
    /// `((index >> (l+1)) + 1) << (l+1)`, the formula `forget_captures_after` uses) and that the witness has not
    /// captured. Before that merge the peaks still supply the sibling, so nothing is wanted; after it, only the merge's
    /// stream entry or the level-major table has it. The low levels are the note's own shard's (L keeps them across a
    /// restart). O(levels) per note; empty with no peaks yet.
    #[must_use]
    pub fn high_wants(&self, cm: &[u8; 32]) -> Vec<(usize, u64)> {
        self.wants_in(cm, crate::window_index::HIGH_LEVEL..SPEND_TREE_DEPTH)
    }

    /// ⭐ THE LOW-LEVEL TWIN of [`Self::high_wants`]: the note's own-shard siblings (`RECORD_LEVEL .. HIGH_LEVEL`) whose
    /// ancestor merge has completed and that the witness has not captured. A note found AFTER those windows left the
    /// stream's reach — every note an OLI lookup or a seed restore finds, since a note enters the locator index only once
    /// its epoch closes — can take them from nowhere else: the node's shard tables (`/window_index_table`, served whole — DB-413), which the
    /// wallet's `LowCatchUp` asks. MEASURED 2026-10-06 (simulator `sim-20261006-030645`, T1.2): W2's note was located by
    /// OLI, decapped and owned, and read "confirming" for 320 s — `high_wants` asked nothing, so its levels 8..18 never
    /// arrived and the path never refolded (`path_ready` false). O(levels) per note; empty with no peaks yet.
    #[must_use]
    pub fn low_wants(&self, cm: &[u8; 32]) -> Vec<(usize, u64)> {
        self.wants_in(cm, RECORD_LEVEL..crate::window_index::HIGH_LEVEL)
    }

    /// WHY `cm` is not [`Self::path_ready`] — the failure reason a wallet prints instead of a bare "confirming" (user
    /// 2026-10-06: "accurate reasons for any failure"). Pending ⇒ [`Self::explain_pending`]; held ⇒ the completed sibling
    /// levels the witness still lacks (all levels, so a gap the catch-ups do not ask is visible), and whether the path
    /// refolds to the newest ring root. Reads only. DIGITAL-CASH-PRIVACY-REVIEWED: levels and ordinals of this wallet's own
    /// book, printed to its own stderr; no commitment, key, amount or owner.
    #[must_use]
    pub fn explain_unready(&self, cm: &[u8; 32]) -> String {
        if self.is_pending(cm) {
            return format!("pending capture: {}", self.explain_pending(cm));
        }
        let Some((w, _)) = self.notes.get(cm) else {
            return "not in the book (never offered: no arrival and no ordinal fetch)".to_string();
        };
        let missing: Vec<usize> = self.wants_in(cm, 0..SPEND_TREE_DEPTH).into_iter().map(|(l, _)| l).collect();
        let current = PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex);
        let ready = self.path_ready(cm);
        // WHICH LEVEL LEAVES THE CHAIN'S TREE — the one thing "refolds false" cannot say.
        // ROOT-LAYER: the book is where the path is COMPOSED (capture, catch-up, peaks), so it is the one place that can
        //   say which source fed each level; the carrier only sees the folded result. Diagnostic only — no decision reads it.
        // MEASURED: sim-20261006-235327 T1.7 — after node 0's restart W1's note read "missing [] · refolds false" on 14
        //   sends over 832 simulated s: a WRONG value (never a missing one) at an unnamed level, and a captured level is
        //   filled only once, so the path never healed. This line names the level on the next run.
        // MUST-STAY-GREEN: every member_witness / db223 pin (the reason string is read by no decision).
        // Unready only: each level's source (`authpath_sources`), the path's own level-8 node (the record root), every
        // sibling at or above the record level as `level:window:limb0` (a cross-node forensic compares them with any
        // node's window index), and the folded root against the ring root. Window numbers name tree positions of this
        // wallet's own note — the class of the leaf index above — on its own stderr.
        let mut trace = String::new();
        if let (false, Some(c)) = (ready, current.as_ref()) {
            match w.authpath_against(c) {
                None => trace.push_str(" · no path: a level has no source"),
                Some((sibs, dirs)) => {
                    let mut node = w.leaf();
                    let mut own8 = node;
                    let mut above = Vec::new();
                    for l in 0..SPEND_TREE_DEPTH {
                        if l == RECORD_LEVEL {
                            own8 = node;
                        }
                        if l >= RECORD_LEVEL && (w.index() >> l) > 0 {
                            above.push(format!("{l}:{}:{:x}", (w.index() >> l) ^ 1, sibs[l][0]));
                        }
                        node = if dirs[l] {
                            crate::spend_frontier::poseidon_pair(sibs[l], node)
                        } else {
                            crate::spend_frontier::poseidon_pair(node, sibs[l])
                        };
                    }
                    trace = format!(
                        " · sources {} · own level-8 node {}:{:x} · siblings ≥ 8 [{}] · folds to {:x} vs ring {:?}",
                        w.authpath_sources(c),
                        w.index() >> RECORD_LEVEL,
                        own8[0],
                        above.join(" "),
                        node[0],
                        self.newest.map(|(o, r)| format!("{o}:{:x}", r[0]))
                    );
                }
            }
        }
        format!(
            "held at leaf {} (record ordinal {}); completed sibling levels still missing {:?}; newest ring ordinal {:?}; \
             peaks decode {}; refolds to the newest root {}{}",
            w.index(),
            w.index() / RECORD_LEAVES + 1,
            missing,
            self.newest.map(|(o, _)| o),
            current.is_some(),
            ready,
            trace
        )
    }

    fn wants_in(&self, cm: &[u8; 32], levels: std::ops::Range<usize>) -> Vec<(usize, u64)> {
        let (Some((w, _)), Some(current)) = (self.notes.get(cm), PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex))
        else {
            return Vec::new();
        };
        let count = u128::from(current.count());
        let index = w.index();
        levels
            .filter(|l| crate::spend_frontier::ancestor_completes_at(index, *l) <= count && w.captured_sibling(*l).is_none())
            .map(|l| (l, (index >> l) ^ 1))
            .collect()
    }

    /// The commitments of the notes this book holds a witness for (a catch-up asks once per held note).
    #[must_use]
    pub fn held_notes(&self) -> Vec<[u8; 32]> {
        self.notes.keys().copied().collect()
    }

    /// ⭐ DB-223 Q2 §12d H — one root a catch-up recovered: every held witness takes it only at its OWN sibling window at
    /// that level and only into an empty level (`capture_completed_window`). Never authority: a wrong root folds the path
    /// to a root the ring does not hold, and `carrier_for` refuses it.
    pub fn capture_caught_up(&mut self, level: usize, window: u64, root: Digest4) {
        for (w, _) in self.notes.values_mut() {
            let _ = w.capture_completed_window(level, window, root);
        }
    }

    /// ⭐ DB-223 Q2 §12d L — every note's levels to keep: each held note's [`Self::fixed_levels`] once fixed, and every
    /// restored set still waiting for its note's capture, so a second restart keeps the identical set. O(owned notes).
    #[must_use]
    pub fn held_fixed_levels(&self) -> Vec<([u8; 32], [Digest4; FIXED_LEVELS])> {
        let mut out: Vec<([u8; 32], [Digest4; FIXED_LEVELS])> =
            self.notes.keys().filter_map(|cm| self.fixed_levels(cm).map(|l| (*cm, l))).collect();
        out.extend(self.restored_fixed.iter().map(|(cm, l)| (*cm, *l)));
        out
    }

    /// Whether the book's path for `cm` refolds to the newest ring root the stream named — the check `carrier_for`
    /// runs before it proves, without the proof.
    #[must_use]
    pub fn path_ready(&self, cm: &[u8; 32]) -> bool {
        let (Some((w, _)), Some((_, root))) = (self.notes.get(cm), self.newest) else {
            return false;
        };
        PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex).is_some_and(|c| w.root_against(&c) == Some(root))
    }

    /// [`Self::path_ready`] for many notes at once: the frontier is parsed ONCE for the whole set (a per-note call re-parsed
    /// every peak from hex for every note — the balance summary asks for every owned note on every poll, and a mining
    /// wallet owns one note per reward). Same verdict per note as `path_ready`, in `cms` order.
    #[must_use]
    pub fn paths_ready(&self, cms: &[[u8; 32]]) -> Vec<bool> {
        let (Some((_, root)), Some(frontier)) = (self.newest, PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex)) else {
            return vec![false; cms.len()];
        };
        cms.iter()
            .map(|cm| self.notes.get(cm).is_some_and(|(w, _)| w.root_against(&frontier) == Some(root)))
            .collect()
    }

    /// A note this wallet owns appeared in an APPLIED block whose record is `leaves` (its 256 leaves,
    /// `Node::block_leaves_from_notes` over the block's own real notes — the ones `/applied_notes_from` serves for every
    /// block, so no record is named). The capture happens once the stream names the record's fold
    /// ([`Self::ordinal_of_record`]), at this call or at a later `apply_stream`.
    /// A note that is not a leaf of `leaves` cannot be captured from them, so it is not kept waiting.
    pub fn note_arrived(&mut self, cm: [u8; 32], leaves: Vec<Digest4>) {
        let Some(path) = RecordPath::of_record(&cm, &leaves) else {
            return;
        };
        self.wait_for_fold(cm, path, None);
    }

    /// ⭐ R-b3 — the wallet's RESTART door: a note it kept as `(cm, path, ordinal)` ([`Self::held_paths`]) is handed back
    /// with no record fetch, and captured exactly as at arrival — at the ordinal the stream NAMES by the record's root.
    /// The kept `ordinal` is used only when the stream cannot name the record AND it lies beyond the reach of any fold
    /// rewind (`cursor − stream reach`, the node's journal bound), where no rewind can have moved it since. It is never
    /// believed: a wrong one folds to a root the ring does not hold and `carrier_for` refuses it (fail closed); the OLI
    /// entry, which names the record's CURRENT ordinal (DB-223 Q2 §11 (a)), re-locates the note.
    /// O1-INFINITY-REVIEWED: this is the WALLET's own witness book (it lives in the node library only so the wallet and
    /// the pins run one spelling; no node calls it); it holds O(this wallet's owned notes), bounded by `retain_notes`,
    /// with no term in chain height; and nothing here is authority — the path must refold to the node's OWN ring root.
    pub fn path_restored(&mut self, cm: [u8; 32], path: RecordPath, ordinal: u64) {
        self.wait_for_fold(cm, path, Some(ordinal));
    }

    /// ⭐ DB-414 — ONE pending entry per note, and a re-offer UPDATES it: a different path (the note re-arrived in another
    /// record — its transaction re-carried by another block) replaces the old one, and the same path takes a real fold
    /// ordinal (≥ 1) over none or the "not folded yet" 0 a previous process saved. MEASURED (sim-20261007-115444, fast
    /// seed 0x1, T3): a hint-0 note whose record had left the stream's reach was offered `(path, ordinal)` by the wallet's
    /// fetch by address every pass, and every offer was dropped because the note was already pending — "pending capture"
    /// for 850 simulated s. Nothing offered is believed: `capture_at` places the path, and it counts only if it refolds to
    /// the ring root the node's own ring names (`carrier_for`). A held note is never replaced.
    /// cons: none — the same one entry per pending note; an offer now costs one scan of the pending list (O(owned notes)).
    fn wait_for_fold(&mut self, cm: [u8; 32], path: RecordPath, hint: Option<u64>) {
        if !self.notes.contains_key(&cm) {
            let real = hint.filter(|o| *o >= 1);
            match self.pending.iter_mut().find(|(c, ..)| *c == cm) {
                Some(entry) if entry.1 != path => *entry = (cm, path, hint),
                Some(entry) => {
                    if real.is_some() {
                        entry.2 = real;
                    }
                }
                None => self.pending.push((cm, path, hint)),
            }
            self.capture_one(cm);
        }
    }

    /// ⭐ AN OFFER TRIES ITS OWN NOTE — the parked set is retried when the EVIDENCE it waits on arrives
    /// ([`Self::apply_stream`]), never on every offer. A note's capture depends only on the stream (the record-level roots,
    /// the newest frontier) and its own path and hint, so offering note A cannot make note B capturable; retrying the whole
    /// pending list on each offer was pure repetition. The shape is Bitcoin Core's orphan pool: an orphan is retried when
    /// its missing parent arrives, not each time another orphan is added.
    /// MEASURED (P14 low leg on 502520a, the merchant wallet W2's store, usdmw_sim_w2_*/wallet-stderr.log): a process
    /// restoring 2,342 owned notes spent 11,586 ms in `wallet_restore` (744 notes: 1,332 ms — 3.1× the notes, 8.7× the
    /// time). Every `path_restored` re-attempted every pending note — Σk ≈ 2.7 M record-root refolds of ~9 Poseidon2
    /// permutations each — and that poll's 742 simulated s is why T3's merchant never read the tap spendable.
    /// MUST-STAY-GREEN: db414 (a re-offer with newer evidence is captured), every member_witness pin, the wallet's restart
    /// pins (R-b3 paths, §12d L fixed levels).
    /// cons: none — the same captures happen at the same evidence; an offer costs one refold and one index pass of the
    /// stream window instead of a refold of every pending note.
    fn capture_one(&mut self, cm: [u8; 32]) {
        let Some(at) = self.pending.iter().position(|(c, ..)| *c == cm) else {
            return;
        };
        let (_, path, hint) = self.pending[at];
        let names = self.stream_names();
        if let Some(ordinal) = names.place(&cm, &path, hint) {
            if self.capture_at(cm, ordinal, path).is_ok() {
                self.pending.remove(at);
            }
        }
    }

    /// What the stream NAMES, indexed once per pass: each record-level root's window (the OLDEST entry wins, as the
    /// deque scan it replaces found it first), the newest frontier's own level-8 peak while it is a lone newest record,
    /// and the newest fold ordinal for a restored hint.
    fn stream_names(&self) -> StreamNames {
        let mut by_root: std::collections::HashMap<Digest4, u64> = std::collections::HashMap::new();
        for (_, level, window, root) in &self.recent {
            if usize::from(*level) == RECORD_LEVEL {
                by_root.entry(*root).or_insert(*window);
            }
        }
        let newest = self.newest.map(|(o, _)| o);
        let newest_peak = newest.and_then(|ordinal| {
            let current = PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex)?;
            (current.count() == ordinal.checked_mul(RECORD_LEAVES)?)
                .then(|| current.peak_at(RECORD_LEVEL))
                .flatten()
                .map(|peak| (ordinal, peak))
        });
        StreamNames { by_root, newest_peak, newest }
    }

    /// ⭐ R-b3 — every held note's `(cm, path, ordinal)`: its captured ordinal, or for a note still waiting the hint it
    /// was handed back with. What the wallet keeps so a restart re-captures with no record fetch. O(owned notes),
    /// because [`Self::retain_notes`] bounds the book by the owned set.
    #[must_use]
    pub fn held_paths(&self) -> Vec<([u8; 32], RecordPath, Option<u64>)> {
        let mut out: Vec<([u8; 32], RecordPath, Option<u64>)> =
            self.notes.iter().map(|(cm, (w, p))| (*cm, *p, Some(w.index() / RECORD_LEAVES + 1))).collect();
        out.extend(self.pending.iter().copied());
        out
    }

    /// Whether `cm` still waits for its record's fold (never captured yet).
    #[must_use]
    pub fn is_pending(&self, cm: &[u8; 32]) -> bool {
        self.pending.iter().any(|(c, ..)| c == cm)
    }

    /// Capture every pending note whose record's fold the stream has now named — or, for a restored note, whose
    /// persisted ordinal lies beyond any rewind's reach ([`Self::path_restored`]).
    fn capture_pending(&mut self) {
        // A restored ordinal (the wallet's fetch-confirmed position, just re-confirmed by fetching that record and finding
        // the note in it) is accepted for ANY record already folded (1 ..= newest). MEASURED 2026-10-05 22:15
        // (w1-custody4.err): after a NODE restart the stream's recent entries start above the note's record, so
        // `ordinal_of_record` found nothing and the old floor (`cursor − stream_reach`) dropped the hint too — the note sat
        // pending for ever and read "confirming". The hint places the path; `capture_at` and the refold against the
        // served frontier still decide whether it is READY, so a wrong hint yields an unready path, never a wrong one.
        if self.pending.is_empty() {
            return;
        }
        // ONE index of what the stream names per pass (`stream_names`), never a deque scan and a frontier parse per note.
        let names = self.stream_names();
        let pending = std::mem::take(&mut self.pending);
        for (cm, path, hint) in pending {
            let found = names.place(&cm, &path, hint);
            match found {
                Some(ordinal) if self.capture_at(cm, ordinal, path).is_ok() => {}
                _ => self.pending.push((cm, path, hint)),
            }
        }
    }

    /// WHY a note is still pending — the failure reason the simulator prints (user 2026-10-06: "accurate reasons for any
    /// failure"): the record root its path expects, how many record-level windows the stream gave and their range, whether
    /// that root appears at ANY level, and the stream's newest ordinal. Reads only; changes nothing.
    #[must_use]
    pub fn explain_pending(&self, cm: &[u8; 32]) -> String {
        let Some((_, path, hint)) = self.pending.iter().find(|(c, ..)| c == cm) else {
            return "not pending".to_string();
        };
        let root = path.record_root(crate::spend_frontier::note_leaf_of(cm));
        let at_level: Vec<u64> =
            self.recent.iter().filter(|(_, level, _, _)| usize::from(*level) == RECORD_LEVEL).map(|(_, _, w, _)| *w).collect();
        let any_level = self.recent.iter().find(|(_, _, _, r)| *r == root).map(|(o, l, w, _)| (*o, *l, *w));
        format!(
            "expects record root {:?}; the stream gave {} record-level window(s) (windows {:?}..{:?}) and {} entries in all;              that root appears at {:?}; newest ordinal {:?}; restored hint {:?}",
            &format!("{root:?}").chars().take(24).collect::<String>(),
            at_level.len(),
            at_level.iter().min(),
            at_level.iter().max(),
            self.recent.len(),
            any_level,
            self.newest.map(|(o, _)| o),
            hint
        )
    }


    /// CAPTURE AT ARRIVAL: the note `cm` this wallet owns sits in the record that folded at `ordinal`, whose 256 leaves
    /// are `leaves` (in the record's own order, `Node::block_leaves_from_notes`). Builds its witness from the record's
    /// own leaves (levels 0–7) and every kept stream entry (levels ≥ 8, both sides — each merge that completes one of
    /// the note's ancestors is at or after `ordinal`); a sibling not merged yet is read from the newest peaks at spend.
    pub fn on_arrival(&mut self, cm: [u8; 32], ordinal: u64, leaves: &[Digest4]) -> Result<(), &'static str> {
        if leaves.len() as u64 != RECORD_LEAVES {
            return Err("a record at ordinal ≥ 1 with exactly 256 leaves is required");
        }
        let path = RecordPath::of_record(&cm, leaves).ok_or("the note is not a leaf of this record")?;
        self.capture_at(cm, ordinal, path)
    }

    /// The one capture: levels 0–7 from the note's [`RecordPath`] (each taken as the completed window it is — left or
    /// right), levels ≥ 8 from every kept stream entry.
    fn capture_at(&mut self, cm: [u8; 32], ordinal: u64, path: RecordPath) -> Result<(), &'static str> {
        if ordinal == 0 || u64::from(path.slot) >= RECORD_LEAVES {
            return Err("a record at ordinal ≥ 1 and a slot inside it are required");
        }
        let leaf = crate::spend_frontier::note_leaf_of(&cm);
        // Genesis contributes no leaves, so the record at ordinal k occupies [(k−1)·256, k·256).
        let index = (ordinal - 1) * RECORD_LEAVES + u64::from(path.slot);
        let mut w = IncrementalWitness::new(index, leaf);
        for (l, s) in path.siblings.iter().enumerate() {
            if !w.capture_completed_window(l, (index >> l) ^ 1, *s) {
                return Err("an intra-record sibling was refused by the witness");
            }
        }
        // DB-223 Q2 §12d L: a restarted wallet's kept fixed levels, before any stream entry.
        if let Some(levels) = self.restored_fixed.remove(&cm) {
            apply_fixed_levels(&mut w, &levels);
        }
        for &(_, level, window, root) in &self.recent {
            let _ = w.capture_completed_window(usize::from(level), window, root);
        }
        self.notes.insert(cm, (w, path));
        self.wanted.remove(&cm);
        Ok(())
    }

    /// ⭐ THE SPEND'S OWN READINESS CHECK, WITHOUT THE PROOF (lane funds-brb33, 2026-11-01): everything [`Self::carrier_for`]
    /// decides BEFORE it proves — the note is held, a ring root was named, the newest peaks decode, the refreshed path is
    /// complete and refolds to that root — returned as the path it would prove, or the same refusal `carrier_for` would give.
    /// `carrier_for` IS this check followed by the proof, so a reader of `leg_ready` can never disagree with the spend.
    /// MEASURED why a separate cached verdict was refused (brb32, k1-wallet-pins.log, k3-pins.log): gating `spendable_now` on
    /// the book's `path_ready` read a verdict the UI process never refreshed ("Your stake" 0.00 for 1,183 s) while the spend
    /// path, which polls the stream first, succeeded in ~60 s. The dry run is the spend path's own check after its own refresh.
    fn leg_check(
        &self,
        cm: &[u8; 32],
        current: &Result<PoseidonSpendFrontier, &'static str>,
    ) -> Result<(Vec<Digest4>, Vec<bool>, Digest4), &'static str> {
        // the builder's own order of refusal: held → a ring root named → the peaks decode → the path refolds
        let (w, _) = self.notes.get(cm).ok_or("this book holds no witness for the note")?;
        let (_, root) = self.newest.ok_or("no ring root seen yet")?;
        let current = current.as_ref().map_err(|e| *e)?;
        let (sibs, dirs) = w.authpath_against(current).ok_or("the path is incomplete (a window it needs is missing)")?;
        if sibs.len() != SPEND_TREE_DEPTH || w.root_against(current) != Some(root) {
            return Err("the refreshed path does not refold to the ring root the stream named");
        }
        Ok((sibs, dirs, root))
    }

    /// ⭐⭐ A-F25 — AN OBJECT'S READINESS CHECK: [`Self::leg_check`] against the newest FINAL ring root instead of the
    /// newest one. The path is read against the frontier AS IT STOOD AT THE FINAL STEP (its peaks ride the stream beside
    /// the root): every level of [`IncrementalWitness::authpath_against`] is decided by that frontier's own leaf count,
    /// so a window that completed after the final step is read as it was then (empty, or the frontier's live peak) and
    /// nothing a later fold wrote enters the path. Built only if the path refolds to the final root the stream named, so
    /// a node that names a wrong "final" root gets no leg out of this book, and the fold door re-checks the root against
    /// its own ring. Returns the path and the `(fold step, root)` it is anchored at.
    /// [`NOT_FINAL_YET`] when the note's record folded after the final step: the object waits for the note's own
    /// finality and never falls back to the newest root (see [`Self::object_carrier_for`] for why).
    fn final_leg_check(&self, cm: &[u8; 32]) -> Result<(Vec<Digest4>, Vec<bool>, (u64, Digest4)), &'static str> {
        let (w, _) = self.notes.get(cm).ok_or("this book holds no witness for the note")?;
        let (step, root) = self.final_anchor.ok_or("the node has named no final fold step yet")?;
        let at_final = PoseidonSpendFrontier::from_peaks_hex(&self.final_peaks_hex).ok_or("the peaks at the final step do not decode")?;
        if w.index() >= at_final.count() {
            return Err(NOT_FINAL_YET);
        }
        let (sibs, dirs) = w.authpath_against(&at_final).ok_or("the path is incomplete (a window it needs is missing)")?;
        if sibs.len() != SPEND_TREE_DEPTH || w.root_against(&at_final) != Some(root) {
            return Err("the path does not refold to the final ring root the stream named");
        }
        Ok((sibs, dirs, (step, root)))
    }

    /// The newest FINAL anchor-ring entry the stream named: `(fold step, root)`, the root [`Self::object_carrier_for`]
    /// refolds a path to. Public chain data.
    #[must_use]
    pub fn final_anchor(&self) -> Option<(u64, Digest4)> {
        self.final_anchor
    }

    /// Whether an OBJECT spending `cm` could build its member leg NOW ([`Self::object_carrier_for`] minus the proof), or
    /// the exact refusal that call would return ([`NOT_FINAL_YET`] while the note waits for its own finality).
    pub fn object_leg_ready(&self, cm: &[u8; 32]) -> Result<(), &'static str> {
        self.final_leg_check(cm).map(|_| ())
    }

    /// ⭐⭐ A-F25 — THE MEMBER LEG OF AN OBJECT (an order's bind, a fill's half, a burn, a deposit, a receipt, the fee note
    /// of a creation or a directory entry): the note's path to the newest FINAL ring root, cross-bound to the object
    /// (`binder` its nullifier, `blind` its leaf blinding, two ZERO outputs). Returns the carrier, its tuple and the
    /// `(fold step, root)` it is anchored at.
    ///
    /// WHAT WAS WRONG (measured on three real nodes, 2026-11-11, finding A-F25): an object's leg was anchored at the
    /// NEWEST ring root, as a send's is. The newest fold step can still be re-ordered. A fill admitted with a leg at
    /// node 1's newest step (ring ordinal 348) was refused six steps later by every node's fold ("anchor at ring ordinal
    /// None", the ring spanning 1..354): the step had been re-ordered and no ring held that root any more. The order was
    /// gone from the book, the maker kept the unit unpaid and the taker's wallet showed its money spent. The same class
    /// refused directory entries (five runs) and a creation's fee note (A-F23).
    ///
    /// THE RULE: an object's leg names the newest root the chain has made FINAL, so the tip's re-ordering cannot
    /// refuse it. The node says which step that is (`Node::final_anchor`: the chain's vote finality, under which the
    /// root cannot change at all; or, when no vote stands, the depth the fold rewinds in place, which only a reorg
    /// deeper than 64 steps re-orders); this book never guesses it.
    ///
    /// WHY A YOUNGER NOTE WAITS INSTEAD OF USING THE NEWEST ROOT: the tuple's anchor is public. "Final when the note is
    /// old, newest when it is fresh" would publish one bit with every object: this note folded after the last final
    /// step. That cuts the note's candidates from every note ever made to the 256 leaves of each of the few steps
    /// since, and ties one person's quick consecutive actions together. One rule for the whole class publishes
    /// nothing: every object built at one moment names the same root, whatever its note's age (DIGITAL CASH).
    /// A SEND names the same final root since A-F36, through [`Self::final_carrier_for`] with its own two outputs.
    ///
    /// BORROWED: Zcash wallets' anchor depth (a spend names a root some blocks back, every wallet the same depth, and
    /// a note younger than the depth is not spendable yet).
    /// cons: an object spending a note younger than finality waits that note's own finality (10 s to 2 min measured on
    /// the three-node rig with votes; `SPINE_RING_LEN` fold steps with none). 0 bytes on the chain or the wire.
    pub fn object_carrier_for(
        &self,
        cm: &[u8; 32],
        binder: Digest4,
        blind: Digest4,
        out0_cm: &[u8; 32],
        out1_cm: &[u8; 32],
    ) -> Result<(Vec<u8>, usdm_decider::member_path_gate::MemberTuple, (u64, Digest4)), &'static str> {
        // an object names no outputs: its leg binds the zero pair (the object's own door states what it creates)
        self.final_carrier_for(cm, binder, blind, &[0u8; 32], &[0u8; 32])
    }

    /// ⭐ A-F52 (lane speed4, 2026-11-13) — THE ONE FINAL-ROOT LEG BUILDER, for an object (the zero output pair,
    /// [`Self::object_carrier_for`]) and for a SEND (its two real outputs). A-F36 moved a send's leg to the final root by
    /// calling the OBJECT builder, whose tuple binds the zero output pair; a send's tuple must bind ITS outputs
    /// (`member_transition::cross_binds`: binder, leaf AND outputs), so every payment was refused at the door ("a
    /// member-path carrier speaks for another spend"). MEASURED on two real nodes at main 7d5e12b2: 697 such refusals
    /// on node 0 in a 24-payer burst, no payment applied. One builder, the outputs a parameter, so the two classes
    /// cannot drift apart again. The anchor rule and its privacy argument are [`Self::object_carrier_for`]'s.
    /// cons: none (the same proof; only which outputs it binds is now the caller's).
    pub fn final_carrier_for(
        &self,
        cm: &[u8; 32],
        binder: Digest4,
        blind: Digest4,
        out0_cm: &[u8; 32],
        out1_cm: &[u8; 32],
    ) -> Result<(Vec<u8>, usdm_decider::member_path_gate::MemberTuple, (u64, Digest4)), &'static str> {
        let (sibs, dirs, anchor) = self.final_leg_check(cm)?;
        let outs = crate::member_transition::outs_digest(out0_cm, out1_cm).ok_or("the outputs are not canonical")?;
        let leaf = crate::spend_frontier::note_leaf_of(cm);
        let (carrier, tuple) =
            usdm_decider::member_path_gate::prove_member_path_carrier(leaf, &sibs, &dirs, binder, blind, outs)
                .ok_or("the member-path carrier did not prove")?;
        if tuple.anchor != anchor.1 {
            return Err("the carrier's anchor is not the final ring root");
        }
        Ok((carrier, tuple, anchor))
    }

    /// The newest peaks as a frontier — the one parse every readiness check and carrier shares. `Err` when none decode (no
    /// stream applied yet, or a malformed answer): every note then reads "not ready" with that reason, never a guess.
    fn current_frontier(&self) -> Result<PoseidonSpendFrontier, &'static str> {
        PoseidonSpendFrontier::from_peaks_hex(&self.peaks_hex).ok_or("the newest peaks do not decode")
    }

    /// SPEED / CASH (2026-11-10) — the newest anchor-ring entry the stream named: `(fold step, root)`, the root
    /// [`Self::carrier_for`] refolds a path to. A wallet keeps the pair beside a send it built, so it can later read
    /// whether its node's ring still holds that root at that step (a send whose anchor left the ring cannot be carried).
    /// Public chain data: the same root the send's member tuple publishes.
    #[must_use]
    pub fn newest_anchor(&self) -> Option<(u64, Digest4)> {
        self.newest
    }

    /// Whether a spend of `cm` could build its member leg NOW — [`Self::carrier_for`] minus the proof (`Ok`), or the exact
    /// refusal that call would return. The caller refreshes the book from the stream first, as the spend does.
    pub fn leg_ready(&self, cm: &[u8; 32]) -> Result<(), &'static str> {
        self.leg_check(cm, &self.current_frontier()).map(|_| ())
    }

    /// [`Self::leg_ready`] for many notes at once, in `cms` order, with the frontier parsed ONCE (the balance summary asks
    /// for every owned note on every poll; a mining wallet owns one note per reward).
    #[must_use]
    pub fn legs_ready(&self, cms: &[[u8; 32]]) -> Vec<Result<(), &'static str>> {
        let current = self.current_frontier();
        cms.iter().map(|cm| self.leg_check(cm, &current).map(|_| ())).collect()
    }

    /// The member-path carrier for spending `cm` under nullifier `binder` into the outputs `out0_cm`, `out1_cm`: the
    /// refreshed depth-64 path to the NEWEST ring root the stream named. `Err` (never a guessed path) when the book
    /// does not hold the note, has not seen a ring root, or the path does not refold to it — exactly [`Self::leg_check`]'s
    /// verdict, then the proof.
    pub fn carrier_for(
        &self,
        cm: &[u8; 32],
        binder: Digest4,
        // DB-363: the spend's per-send blinding — the SAME value its validity carrier was proven with, so the member
        // tuple's `leaf_commit` is the spend's own (`cross_binds`). The spender draws it; this book never stores it.
        blind: Digest4,
        out0_cm: &[u8; 32],
        out1_cm: &[u8; 32],
    ) -> Result<(Vec<u8>, usdm_decider::member_path_gate::MemberTuple), &'static str> {
        let (sibs, dirs, root) = self.leg_check(cm, &self.current_frontier())?;
        let outs = crate::member_transition::outs_digest(out0_cm, out1_cm).ok_or("the outputs are not canonical")?;
        let leaf = crate::spend_frontier::note_leaf_of(cm);
        let (carrier, tuple) =
            usdm_decider::member_path_gate::prove_member_path_carrier(leaf, &sibs, &dirs, binder, blind, outs)
                .ok_or("the member-path carrier did not prove")?;
        if tuple.anchor != root {
            return Err("the carrier's anchor is not the ring root");
        }
        Ok((carrier, tuple))
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ DB-223 Q2 §11 R-b3 — a note's 513-byte [`RecordPath`] is its whole record's contribution to its witness. RED
    /// before R-b3 (the book held the 256 leaves and no path type existed). The path refolds to the SAME level-8 root the
    /// frontier computes over the record's leaves at every slot tested (both parities, both ends), so a book holding
    /// only the path names the record's fold exactly as one holding the leaves; its bytes round-trip, and a short buffer,
    /// a non-member and a tampered sibling are each refused or detected.
    #[test]
    fn db223_rb3_a_notes_record_path_refolds_to_its_records_root_and_round_trips() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let leaves: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, 0xB3, 7])).collect();
        for slot in [0usize, 1, 126, 127, 200, 255] {
            // A note's leaf is `note_leaf_of(cm)`; plant a cm whose leaf this record holds at `slot`.
            let cm = [slot as u8 ^ 0x5C; 32];
            let mut rec = leaves.clone();
            rec[slot] = crate::spend_frontier::note_leaf_of(&cm);
            let mut g = PoseidonSpendFrontier::new();
            assert!(rec.iter().all(|l| g.append(*l)), "the planted record appends");
            let path = RecordPath::of_record(&cm, &rec).expect("the note is a leaf of its record");
            assert_eq!(usize::from(path.slot), slot);
            assert_eq!(
                path.record_root(crate::spend_frontier::note_leaf_of(&cm)),
                g.subtree_root(RECORD_LEVEL),
                "slot {slot}: the path refolds to the frontier's own level-8 root"
            );
            let bytes = path.to_bytes();
            assert_eq!(bytes.len(), RecordPath::BYTES, "one fixed width: 1 + 8 digests");
            assert_eq!(RecordPath::from_bytes(&bytes), Some(path), "the bytes round-trip");
            assert_eq!(RecordPath::from_bytes(&bytes[..bytes.len() - 1]), None, "a short buffer is refused, never padded");
            // TAMPER: one sibling changed ⇒ another root (the book would name no fold, or a wrong one that the ring refuses).
            let mut bad = path;
            bad.siblings[3][0] ^= 1;
            assert_ne!(bad.record_root(crate::spend_frontier::note_leaf_of(&cm)), g.subtree_root(RECORD_LEVEL));
        }
        assert_eq!(RecordPath::of_record(&[0xEE; 32], &leaves), None, "a note that is not a leaf of the record has no path");
        assert_eq!(RecordPath::of_record(&[0x5C; 32], &leaves[..255]), None, "a partial record has no path");
    }

    /// ⭐⭐ DB-414 — A PENDING NOTE RE-OFFERED WITH NEWER EVIDENCE TAKES IT. MEASURED (sim-20261007-115444, fast seed 0x1,
    /// T3 POS): the payer's process saved two notes it had seen arrive but not yet fold (ordinal 0 = "not folded yet");
    /// the next process handed them back with hint 0, by when their records had folded and left the stream's reach, so
    /// the stream could not name them. The wallet then fetched each record BY ADDRESS and offered `(path, its fold
    /// ordinal)` — and `wait_for_fold` dropped the offer because the note was already pending. "pending capture … restored
    /// hint Some(0)" for 850 simulated s, the tap's signed charge expired, T3 red.
    /// Two offers, both RED before: (a) the same path with the record's real ordinal after a hint-0 hand-back; (b) a note
    /// pending on record A that re-arrives in record B (its transaction re-carried by another block), whose fold the
    /// stream names. CALIBRATION: before each offer the note is pending, so the offer is what places it. A re-offer never
    /// replaces a held note, and the book keeps ONE pending entry per note whatever is offered (no growth per offer).
    /// O1-INFINITY-REVIEWED: the WALLET's own witness book, O(its owned notes) with one fixed-size entry each; no node
    /// state, no history term — and nothing here is authority (a path counts only if it refolds to the node's ring root).
    /// TWO-PARTY-REVIEWED: the two parties are the saving process and the handing-back process of one wallet (the kept
    /// `(path, 0)` crosses between them); the stream is synthetic here. The cross-node proof is the simulator's T3 POS
    /// step: the payer's node serves the stream and the record, and the merchant reads the payment through the OTHER node.
    #[test]
    fn db414_a_pending_note_re_offered_with_newer_evidence_is_captured() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let cm = [0x41u8; 32];
        let record = |tag: u64, slot: usize| {
            let mut l: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, tag, 0x14])).collect();
            l[slot] = crate::spend_frontier::note_leaf_of(&cm);
            RecordPath::of_record(&cm, &l).expect("the note is a leaf of its record")
        };
        let stream = |entries: Vec<(u64, u8, u64, Digest4)>, newest: u64| crate::node::PathRefreshStream {
            entries,
            newest: Some((newest, lanes(&[newest, 0xAB]))),
            peaks_hex: String::new(),
            catch_up: false,
            since: 0,
            since_root: None,
            final_anchor: None,
            final_peaks_hex: String::new(),
        };
        // (a) hint 0; the record folded at ordinal 7 and the stream (newest 900) no longer names it.
        let path = record(0xA, 9);
        let mut b = MemberWitnessBook::new();
        b.path_restored(cm, path, 0);
        b.apply_stream(&stream(Vec::new(), 900)).expect("the stream reaches the book");
        assert!(b.is_pending(&cm), "CALIBRATION: a hint-0 hand-back past the record's reach cannot place the note");
        b.path_restored(cm, path, 7); // the wallet's fetch by address names the record's fold ordinal
        assert!(b.holds(&cm), "⛔ (a) the re-offer carrying the record's fold ordinal was dropped — the note waits forever");
        assert_eq!(b.held_paths(), vec![(cm, path, Some(7))], "captured at the offered ordinal");
        b.path_restored(cm, record(0xB, 3), 8);
        assert_eq!(b.held_paths(), vec![(cm, path, Some(7))], "a re-offer never replaces a HELD note");

        // (b) pending on record A (which never folds); the note re-arrives in record B, which folds at ordinal 12.
        let (a_path, b_path) = (record(0xC, 2), record(0xD, 200));
        let mut c = MemberWitnessBook::new();
        c.wait_for_fold(cm, a_path, None);
        let b_root = b_path.record_root(crate::spend_frontier::note_leaf_of(&cm));
        c.apply_stream(&stream(vec![(12, RECORD_LEVEL as u8, 11, b_root)], 12)).expect("the stream reaches the book");
        assert!(c.is_pending(&cm), "CALIBRATION: record A's root is not the one the stream names");
        for _ in 0..3 {
            c.wait_for_fold(cm, a_path, None); // a repeat of the old offer changes nothing and adds nothing
        }
        assert_eq!(c.held_paths().len(), 1, "one pending entry per note, whatever is offered");
        c.wait_for_fold(cm, b_path, None);
        assert!(c.holds(&cm), "⛔ (b) the note's re-arrival in the record that folded was dropped");
        assert_eq!(c.held_paths(), vec![(cm, b_path, Some(12))], "captured where record B folded");
    }

    /// ⭐ A FOLD REWIND BELOW THE BOOK'S CURSOR IS DETECTED BY THE RING MOVING BACK — not only by another root at the
    /// cursor's step. MEASURED RED (launch leg 1 at 10 nodes, seed 0x713100f320261022, scratchpad/verify/
    /// launch-leg1-g11b-20261022-2245.log:12449 → :24046): node 0 rewound "16 record(s) from ordinal 69" while the
    /// wallet's book stood at a higher cursor; at the next poll the node's ring no longer HELD the cursor's step, so
    /// `since_root` was `None`, the differing-root check never fired, the book kept the rewound order's windows and its
    /// carrier anchored at a root the node's fold never produced — "[admit] ⛔ REFUSE: a member-path carrier anchored at a
    /// root this node's own fold never produced within its ring", the wallet's send REJECTED, T1.2 FAIL. The node's ring
    /// newest only moves back by a rewind (or the mesh walk answered from a node that is behind, where re-capturing costs a
    /// poll and nothing else), so a newest below the cursor is the rewind signal. BORROWED SHAPE: Zcash's wallet drops a
    /// note's witness history above a reorg and re-anchors in the current chain (`-anchorconfirmations` only makes it rare;
    /// the rebuild is what makes it correct). CONTROL: a stream that merely advances applies and is `Ok`.
    /// TWO-PARTY-REVIEWED: the two parties are the NODE whose fold rewound (its anchor ring, the stream it serves — the
    /// node's own `PathRefreshStream` type, in the rewound shape measured from node 0's log) and the WALLET process holding
    /// the book; this pin fixes the node side's answer and judges the book. The cross-process proof is launch leg 1 at 10
    /// nodes (the real wallet-harness process against node 0's live rewind), re-run with this fix.
    #[test]
    fn a_ring_newest_below_the_books_cursor_is_a_rewind_and_the_book_recaptures_from_the_fork() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let stream = |entries: Vec<(u64, u8, u64, Digest4)>, newest: u64, since: u64, since_root: Option<Digest4>| {
            crate::node::PathRefreshStream {
                entries,
                newest: Some((newest, lanes(&[newest, 0xAB]))),
                peaks_hex: String::new(),
                catch_up: false,
                since,
                since_root,
                final_anchor: None,
                final_peaks_hex: String::new(),
            }
        };
        let order1 = |o: u64| (o, RECORD_LEVEL as u8, o - 1, lanes(&[o, 0x01]));
        let mut b = MemberWitnessBook::new();
        b.apply_stream(&stream((60..=84).map(order1).collect(), 84, 0, None)).expect("the first order applies");
        assert_eq!(b.cursor(), 84, "CALIBRATION: the book stands at the newest step it applied");
        assert_eq!(b.recent.len(), 25, "CALIBRATION: every window of the first order is held");
        // CONTROL: the ring advanced on the same history (the root at the cursor's step is the one the book applied).
        let same = lanes(&[84u64, 0xAB]);
        b.apply_stream(&stream(vec![order1(85)], 85, 84, Some(same))).expect("an advancing stream applies");
        assert_eq!(b.cursor(), 85);
        // The node rewound from ordinal 69 and had refolded to 75 by this poll: its ring newest is 75 and it no longer
        // holds step 85, so `since_root` is None.
        let rewound = stream(Vec::new(), 75, 85, None);
        let verdict = b.apply_stream(&rewound);
        assert!(
            verdict.is_err(),
            "⛔ the book did not notice the node's ring moving back below its cursor — it keeps the rewound order's windows and \
             anchors a carrier at a root the node's fold never produced"
        );
        assert!(b.cursor() <= 68, "⛔ the book re-captures from at or below the fork (cursor {}, fork 68)", b.cursor());
        assert!(
            b.recent.iter().all(|(o, ..)| *o <= 68),
            "⛔ a window of the rewound order is still held above the fork: {:?}",
            b.recent.iter().map(|(o, ..)| *o).filter(|o| *o > 68).collect::<Vec<_>>()
        );
        assert_eq!(b.newest, None, "no ring root is named until the stream from the fork is applied");
        // The next poll, asked from the rewound cursor, re-applies the new order and the book stands at the node's newest.
        let order2 = |o: u64| (o, RECORD_LEVEL as u8, o - 1, lanes(&[o, 0x02]));
        let since = b.cursor();
        b.apply_stream(&stream((since + 1..=75).map(order2).collect(), 75, since, None)).expect("the new order applies");
        assert_eq!(b.cursor(), 75);
        assert!(b.recent.iter().filter(|(o, ..)| *o > 68).all(|(o, _, _, r)| *r == lanes(&[*o, 0x02])), "the new order's roots");
    }

    /// ⭐ A WALLET'S RESTART COSTS ONE RECORD-ROOT REFOLD PER NOTE, NOT ONE PER NOTE PER NOTE. A process hands its N kept
    /// paths back (`path_restored`, the R-b3 restart door) into an empty book, then the first stream answer names every
    /// record. MEASURED before (P14 low leg on 502520a, the merchant wallet's process): 2,342 notes handed back in
    /// 11,586 ms (744 in 1,332 ms) because every hand-back re-attempted the whole pending list — Σk refolds. TWO SCALES:
    /// the count at N = 64 and N = 512 must both stay within 2·N (one refold at the hand-back, one when the stream names
    /// the record); the quadratic shape gives N(N+1)/2 + N (2,144 and 131,840). CALIBRATION: every note is captured where
    /// the stream named its record, so the count is not low for having decided less.
    /// O1-INFINITY-REVIEWED: the WALLET's own in-memory witness book (O(its owned notes), nothing persisted, no node
    /// state, no height term); the count under test is a test-only thread-local. cons: none — a test.
    /// TWO-PARTY-REVIEWED: the two parties are the wallet process that kept the paths and the process that hands them
    /// back; the stream is synthetic here. The cross-node proof is the simulator's T3 POS step, where the merchant's
    /// per-poll process restores every reward it holds and reads the payer's payment through the OTHER node.
    #[test]
    fn a_restore_of_n_kept_paths_refolds_each_note_a_constant_number_of_times_at_two_scales() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let run = |n: u64| -> u64 {
            let notes: Vec<([u8; 32], RecordPath)> = (0..n)
                .map(|k| {
                    let mut cm = [0x52u8; 32];
                    cm[..8].copy_from_slice(&k.to_le_bytes());
                    let mut l: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, k, 0x52])).collect();
                    l[(k % RECORD_LEAVES) as usize] = crate::spend_frontier::note_leaf_of(&cm);
                    (cm, RecordPath::of_record(&cm, &l).expect("the note is a leaf of its record"))
                })
                .collect();
            let mut b = MemberWitnessBook::new();
            RECORD_ROOT_REFOLDS.with(|c| c.set(0));
            for (cm, path) in &notes {
                b.path_restored(*cm, *path, 0); // "not folded yet": nothing places it until the stream names its record
            }
            let entries: Vec<(u64, u8, u64, Digest4)> = notes
                .iter()
                .enumerate()
                .map(|(k, (cm, path))| {
                    let k = k as u64;
                    (k + 1, RECORD_LEVEL as u8, k, path.record_root(crate::spend_frontier::note_leaf_of(cm)))
                })
                .collect();
            b.apply_stream(&crate::node::PathRefreshStream {
                entries,
                newest: Some((n, lanes(&[n, 0xAB]))),
                peaks_hex: String::new(),
                catch_up: false,
                since: 0,
                since_root: None,
                final_anchor: None,
                final_peaks_hex: String::new(),
            })
            .expect("the stream reaches the book");
            for (k, (cm, path)) in notes.iter().enumerate() {
                assert_eq!(
                    b.held_paths().iter().find(|(c, ..)| c == cm).copied(),
                    Some((*cm, *path, Some(k as u64 + 1))),
                    "CALIBRATION: note {k} of {n} is captured at the ordinal the stream named for its record"
                );
            }
            RECORD_ROOT_REFOLDS.with(std::cell::Cell::get)
        };
        let (small, large) = (run(64), run(512));
        eprintln!("[restore-cost] record-root refolds: {small} for 64 kept paths, {large} for 512");
        assert!(
            small <= 2 * 64 && large <= 2 * 512,
            "⛔ handing back N kept paths cost {small} refolds at N = 64 and {large} at N = 512 — a slope in N per note \
             (every hand-back retried the whole pending list), so a miner's wallet restart grows quadratically with \
             the rewards it holds"
        );
    }

    /// ⭐ DB-223 Q2 §12d L — A RESTART AFTER THE NOTE'S SHARD COMPLETES ASKS NOTHING FOR LEVELS `RECORD_LEVEL..HIGH_LEVEL`.
    /// The arrival book captures the note and the stream completes its level-8..18 siblings; once the merge completing
    /// the level-`HIGH_LEVEL` ancestor is beyond any fold rewind, the book hands those levels out to keep. A restarted
    /// book whose stream starts AFTER every one of those windows (the gap an offline wallet meets: the stream cannot
    /// resend them) holds all of them from the kept set alone — no stream entry, no index ask.
    /// CALIBRATION (the RED before L): one fold step inside a rewind's reach, nothing is handed out; and the same restart
    /// WITHOUT the kept set holds the note but none of levels 8..18. A double restart re-keeps the identical set, and a set
    /// restored for a note not captured yet is re-kept too.
    /// TWO-PARTY-REVIEWED: the two parties are the arrival process and the restarted process of one wallet (what crosses
    /// is the kept set). The stream is synthetic here, so no root is refolded: whether a kept root is RIGHT is decided by
    /// the refold at `carrier_for` against the node's own ring, pinned by the R-b3 restart pin (a tampered kept sibling
    /// never refolds).
    /// O1-INFINITY-REVIEWED: the WALLET's own book, O(its owned notes) with FIXED_LEVELS digests each; no node state.
    #[test]
    fn db223_q2_l_a_restart_after_the_shard_completes_keeps_levels_8_to_18_and_asks_nothing_for_them() {
        use crate::window_index::HIGH_LEVEL;
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let cm = [0x6Du8; 32];
        let slot = 5usize;
        let mut leaves: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, 0x12, 9])).collect();
        leaves[slot] = crate::spend_frontier::note_leaf_of(&cm);
        let ordinal = 1u64;
        let index = (ordinal - 1) * RECORD_LEAVES + slot as u64;
        let root_at = |l: usize| lanes(&[l as u64, 0xF1, 0xED]);
        // One stream entry per level: the merge that completes the note's level-(l+1) ancestor names its level-l sibling.
        let sibling_entries: Vec<(u64, u8, u64, Digest4)> = (RECORD_LEVEL..HIGH_LEVEL)
            .map(|l| {
                let completes_leaf = ((index >> (l + 1)) + 1) << (l + 1);
                (completes_leaf / RECORD_LEAVES, l as u8, (index >> l) ^ 1, root_at(l))
            })
            .collect();
        let stream = |entries: Vec<(u64, u8, u64, Digest4)>, newest_ordinal: u64| crate::node::PathRefreshStream {
            entries,
            newest: Some((newest_ordinal, lanes(&[newest_ordinal, 0xAB]))),
            peaks_hex: String::new(),
            catch_up: false,
            since: 0,
            since_root: None,
            final_anchor: None,
            final_peaks_hex: String::new(),
        };
        let completes_ord = (((index >> HIGH_LEVEL) + 1) << HIGH_LEVEL) / RECORD_LEAVES;
        let fixed_at = completes_ord + stream_reach();

        let mut a = MemberWitnessBook::new();
        a.on_arrival(cm, ordinal, &leaves).expect("the note is captured at arrival");
        a.apply_stream(&stream(sibling_entries, fixed_at - 1)).expect("the stream reaches the arrival book");
        assert_eq!(a.fixed_levels(&cm), None, "CALIBRATION: inside a rewind's reach, no level is handed out to keep");
        a.apply_stream(&stream(Vec::new(), fixed_at)).expect("the stream reaches the arrival book");
        let kept = a.fixed_levels(&cm).expect("beyond any rewind, levels 8..HIGH_LEVEL are fixed");
        assert_eq!(
            kept.to_vec(),
            (RECORD_LEVEL..HIGH_LEVEL).map(root_at).collect::<Vec<_>>(),
            "the kept levels are exactly the captured siblings"
        );
        assert_eq!(a.held_fixed_levels(), vec![(cm, kept)], "one owned note, one kept set");
        let (kcm, kpath, kord) = a.held_paths()[0];
        let kord = kord.expect("a captured note keeps its ordinal");
        drop(a);

        // The restarted process's stream starts AFTER every level-8..18 window: it carries none of them.
        let later = stream(Vec::new(), fixed_at + 10);
        let restart = |kept_set: &[([u8; 32], [Digest4; FIXED_LEVELS])]| {
            let mut b = MemberWitnessBook::new();
            b.path_restored(kcm, kpath, kord);
            for (c, l) in kept_set {
                b.fixed_levels_restored(*c, *l);
            }
            let _ = b.apply_stream(&later);
            b
        };
        let bare = restart(&[]);
        assert!(bare.holds(&cm), "PRECONDITION: the kept ordinal (beyond any rewind) places the note");
        assert_eq!(bare.fixed_levels(&cm), None, "CALIBRATION (RED before L): the gap leaves levels 8..18 empty");
        let b = restart(&[(cm, kept)]);
        assert_eq!(b.fixed_levels(&cm), Some(kept), "⛔ L: the restarted book lost a kept level — it would ask the index");
        let c = restart(&b.held_fixed_levels());
        assert_eq!(c.held_fixed_levels(), b.held_fixed_levels(), "⛔ a double restart did not re-keep the identical set");
        // A restart before the first stream answer: the note waits for capture, and its kept set is re-kept meanwhile.
        let mut d = MemberWitnessBook::new();
        d.path_restored(kcm, kpath, kord);
        d.fixed_levels_restored(kcm, kept);
        assert_eq!(d.held_fixed_levels(), vec![(cm, kept)], "⛔ a waiting note's kept levels were dropped");
        // Bounded by the owned set: a note the wallet no longer owns takes its kept set with it.
        d.retain_notes(|_| false);
        assert!(d.held_fixed_levels().is_empty(), "a spent note's kept levels leave with it");
    }

    /// ⭐ DB-223 Q2 §12d H — WHAT A CATCH-UP MUST FETCH, AND THAT ITS ROOT LANDS ONLY WHERE IT BELONGS. A note at leaf 5;
    /// the newest peaks say `2^22` leaves exist. Its high-level ancestors at levels 19, 20 and 21 have merged (their merges
    /// complete at leaves `2^20`, `2^21`, `2^22`), and nothing captured their siblings (the stream's entries are gone — the
    /// gap), so exactly those three `(level, window)` are wanted. A root at ANOTHER window of level 19 is not taken; the
    /// right one clears level 19's want.
    /// CALIBRATION: with `2^19` leaves no high ancestor has merged yet (the peaks still supply the siblings) — no want.
    /// TWO-PARTY-REVIEWED: the book's own bookkeeping over a synthetic peaks answer; the client that fetches the roots is
    /// pinned against the node's own doors in the wallet crate (`window_catch_up`), and the refold decides at the carrier.
    #[test]
    fn db223_q2_h_a_catch_up_wants_exactly_the_merged_high_siblings_and_takes_a_root_only_at_its_window() {
        use crate::window_index::HIGH_LEVEL;
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let cm = [0x7Au8; 32];
        let slot = 5usize;
        let mut leaves: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, 0x2B, 1])).collect();
        leaves[slot] = crate::spend_frontier::note_leaf_of(&cm);
        // The peaks answer of a frontier with `count` leaves: the ONE encoder's bytes with the count overwritten and one
        // peak slot filled at each set bit (their values never matter to what is wanted).
        let peaks_of = |count: u64| {
            let mut b = crate::rpc_http::hex_decode(&PoseidonSpendFrontier::new().peaks_hex()).expect("the encoder speaks hex");
            b[..8].copy_from_slice(&count.to_be_bytes());
            for l in 0..64usize {
                if count >> l & 1 == 1 {
                    b[8 + l * 32..8 + l * 32 + 32].copy_from_slice(&[0x5Au8; 32]);
                }
            }
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        };
        let stream_at = |count: u64| crate::node::PathRefreshStream {
            entries: Vec::new(),
            newest: Some((count / RECORD_LEAVES, lanes(&[count, 0xAB]))),
            peaks_hex: peaks_of(count),
            catch_up: true,
            since: 0,
            since_root: None,
            final_anchor: None,
            final_peaks_hex: String::new(),
        };
        let mut book = MemberWitnessBook::new();
        book.on_arrival(cm, 1, &leaves).expect("captured at arrival");
        let _ = book.apply_stream(&stream_at(1 << 19));
        assert!(book.high_wants(&cm).is_empty(), "CALIBRATION: before any high ancestor merges, nothing is wanted");
        let _ = book.apply_stream(&stream_at(1 << 22));
        let wants = book.high_wants(&cm);
        assert_eq!(
            wants,
            vec![(HIGH_LEVEL, 1), (HIGH_LEVEL + 1, 1), (HIGH_LEVEL + 2, 1)],
            "⛔ the catch-up wants are not exactly the merged, uncaptured high siblings"
        );
        assert_eq!(book.held_notes(), vec![cm], "one held note");
        book.capture_caught_up(HIGH_LEVEL, 2, lanes(&[99]));
        assert_eq!(book.high_wants(&cm).len(), 3, "⛔ a root at another window of the level was taken");
        book.capture_caught_up(HIGH_LEVEL, 1, lanes(&[19]));
        assert_eq!(book.high_wants(&cm), vec![(HIGH_LEVEL + 1, 1), (HIGH_LEVEL + 2, 1)], "the right root clears level 19");
    }
    /// ⭐ RED→GREEN PIN (lane funds-brb33, 2026-11-01) — `leg_ready` IS `carrier_for` WITHOUT THE PROOF: at every state of
    /// one note's life (not held → held but no ring root named → the ring root named → a stream that names a DIFFERENT root)
    /// the dry run returns exactly the verdict the carrier builder returns, by reason; and on the ready note the carrier it
    /// proves anchors at the root the dry run accepted. RED before: no such reader existed — the wallet's readers read either
    /// `spendable_now` (true before the leg could be proved: F9's Unstake and A5's consecutive sends failed after the press)
    /// or the book's cached `path_ready` (brb32: never refreshed in the UI process). The record is a REAL frontier of 256
    /// appended leaves, so the ring root the stream names is the chain's own, never a planted digest.
    /// CALIBRATION: the unready arms are refused by name, so the pin cannot pass on a book that says "ready" to everything.
    /// TWO-PARTY-REVIEWED: one wallet's book against its node's stream; the cross-node proof is F9 (the peer reads the stake)
    /// and A5 (both nodes hold the same stakers' pool after the consecutive sends).
    #[test]
    fn leg_ready_is_the_carrier_builders_own_verdict_without_the_proof() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let cm = [0x33u8; 32];
        let slot = 77usize;
        let mut leaves: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, 0x33, 0xB3])).collect();
        leaves[slot] = crate::spend_frontier::note_leaf_of(&cm);
        let mut g = PoseidonSpendFrontier::new();
        assert!(leaves.iter().all(|l| g.append(*l)), "the record appends to a real frontier");
        let stream = |root: Digest4| crate::node::PathRefreshStream {
            entries: Vec::new(),
            newest: Some((1, root)),
            peaks_hex: g.peaks_hex(),
            catch_up: false,
            since: 0,
            since_root: None,
            final_anchor: None,
            final_peaks_hex: String::new(),
        };
        let binder = lanes(&[0xB1, 2, 3, 4]);
        let blind = crate::spend_frontier::TEST_LC_BLIND;
        let (o0, o1) = ([0u8; 32], [0u8; 32]);
        let mut book = MemberWitnessBook::new();
        // 1. not held
        assert_eq!(book.leg_ready(&cm), Err("this book holds no witness for the note"), "CALIBRATION: an unknown note is not ready");
        assert_eq!(book.carrier_for(&cm, binder, blind, &o0, &o1).err(), book.leg_ready(&cm).err(), "⛔ (1) the dry run disagrees with the builder");
        // 2. held, but the stream has named no ring root (an empty stream answer decodes the peaks of an empty frontier)
        book.on_arrival(cm, 1, &leaves).expect("captured at arrival");
        let mut no_root = stream(g.root());
        no_root.newest = None;
        no_root.peaks_hex = PoseidonSpendFrontier::new().peaks_hex();
        let _ = book.apply_stream(&no_root);
        assert_eq!(book.leg_ready(&cm), Err("no ring root seen yet"), "CALIBRATION: held is not ready");
        assert_eq!(book.carrier_for(&cm, binder, blind, &o0, &o1).err(), book.leg_ready(&cm).err(), "⛔ (2) the dry run disagrees with the builder");
        // 3. the stream names the record's own ring root: READY, and the carrier anchors there
        book.apply_stream(&stream(g.root())).expect("the stream reaches the book");
        assert_eq!(book.leg_ready(&cm), Ok(()), "⛔ (3) the folded, root-named note is not ready");
        assert_eq!(book.legs_ready(&[cm, [0xEEu8; 32]]), vec![Ok(()), Err("this book holds no witness for the note")], "the batch form agrees per note");
        let (_, tuple) = book.carrier_for(&cm, binder, blind, &o0, &o1).expect("⛔ (3) the builder refuses a note the dry run called ready");
        assert_eq!(tuple.anchor, g.root(), "the carrier anchors at the root the dry run accepted");
        // 4. TAMPER: a stream naming another root (a fold the book did not follow) — refused by both, by the same reason
        book.apply_stream(&stream(lanes(&[0xDE, 0xAD]))).expect("the stream reaches the book");
        assert_eq!(book.leg_ready(&cm), Err("the refreshed path does not refold to the ring root the stream named"));
        assert_eq!(book.carrier_for(&cm, binder, blind, &o0, &o1).err(), book.leg_ready(&cm).err(), "⛔ (4) the dry run disagrees with the builder");
    }

    /// ⛔ A-F53 (lane veil, 2026-11-13, three real nodes): a RECEIVED note stays unspendable when its record is re-folded —
    /// "pending capture: expects record root …; that root appears at None" for 600 s while the nodes logged fold reorgs of
    /// 5–10 records. The book's side of that claim, in the measured shapes: (a) a note PENDING (arrived, its record not
    /// folded yet) when the node's fold rewinds below the book's cursor, whose record then folds at another ordinal in the
    /// new order; (b) a note already CAPTURED at ordinal 70 when the rewind moves its record to ordinal 73. A record's
    /// level-8 root is a function of its own leaves (`RecordPath`), so in both the note must be captured exactly where the
    /// NEW order folds the record, and nowhere else. CALIBRATION: before the new order names the record, the note is pending
    /// (so the new stream is what places it); CONTROL: a stream naming only OTHER records leaves it pending.
    /// MEASURED GREEN (lane names, 22:13): the book was never the fault. The real cause is A-F58 — the record's block was
    /// never merged again, so no node re-folded it (dag::af58_…_is_merged_and_never_stranded).
    /// TWO-PARTY-REVIEWED: the node whose fold rewound (its stream, in the rewound shape measured from the rig logs) and the
    /// wallet process holding the book; the cross-node proof is the real-node attack row for A-F53.
    /// O1-INFINITY-REVIEWED: the WALLET's own in-memory book, O(its owned notes); no node state, no history term.
    #[test]
    fn af53_a_note_whose_record_is_refolded_is_captured_where_the_new_order_folds_it() {
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let stream = |entries: Vec<(u64, u8, u64, Digest4)>, newest: u64, since: u64, since_root: Option<Digest4>| {
            crate::node::PathRefreshStream {
                entries,
                newest: Some((newest, lanes(&[newest, 0xAB]))),
                peaks_hex: String::new(),
                catch_up: false,
                since,
                since_root,
                final_anchor: None,
                final_peaks_hex: String::new(),
            }
        };
        let cm = [0x53u8; 32];
        let mut leaves: Vec<Digest4> = (0..RECORD_LEAVES).map(|i| lanes(&[i, 0xF5, 3])).collect();
        leaves[17] = crate::spend_frontier::note_leaf_of(&cm);
        let path = RecordPath::of_record(&cm, &leaves).expect("the note is a leaf of its record");
        let root = path.record_root(crate::spend_frontier::note_leaf_of(&cm));
        let order1 = |o: u64| (o, RECORD_LEVEL as u8, o - 1, lanes(&[o, 0x01]));
        let order2 = |o: u64| (o, RECORD_LEVEL as u8, o - 1, lanes(&[o, 0x02]));
        // ── (a) pending across the rewind
        let mut a = MemberWitnessBook::new();
        a.apply_stream(&stream((60..=84).map(order1).collect(), 84, 0, None)).expect("the first order applies");
        a.note_arrived(cm, leaves.clone());
        assert!(a.is_pending(&cm), "CALIBRATION: the note's record has not folded in the first order");
        let _ = a.apply_stream(&stream(Vec::new(), 75, 84, None));
        assert!(a.cursor() <= 68, "CALIBRATION: the book noticed the rewind (cursor {})", a.cursor());
        let since = a.cursor();
        a.apply_stream(&stream((since + 1..=75).map(order2).collect(), 75, since, None)).expect("the new order applies");
        assert!(a.is_pending(&cm), "CONTROL: a stream that names other records leaves the note pending");
        a.apply_stream(&stream(vec![(76, RECORD_LEVEL as u8, 75, root)], 76, 75, None)).expect("the fold of the record applies");
        assert!(
            a.holds(&cm),
            "⛔ A-F53 (a): the note pending across a fold rewind was never captured where the new order folded its record: {}",
            a.explain_unready(&cm)
        );
        assert_eq!(a.held_paths(), vec![(cm, path, Some(76))], "captured at the NEW order's ordinal");
        // ── (b) captured, then its record moves
        let mut b = MemberWitnessBook::new();
        let mut first: Vec<(u64, u8, u64, Digest4)> = (60..=84).map(order1).collect();
        first[10] = (70, RECORD_LEVEL as u8, 69, root);
        b.note_arrived(cm, leaves.clone());
        b.apply_stream(&stream(first, 84, 0, None)).expect("the first order applies");
        assert_eq!(b.held_paths(), vec![(cm, path, Some(70))], "CALIBRATION: captured at 70 in the first order");
        let _ = b.apply_stream(&stream(Vec::new(), 75, 84, None));
        assert!(b.is_pending(&cm), "CALIBRATION: the rewind below 70 undoes the capture");
        let since = b.cursor();
        let mut second: Vec<(u64, u8, u64, Digest4)> = (since + 1..=75).map(order2).collect();
        let at73 = second.iter().position(|e| e.0 == 73).expect("73 is in the new order");
        second[at73] = (73, RECORD_LEVEL as u8, 72, root);
        b.apply_stream(&stream(second, 75, since, None)).expect("the new order applies");
        assert!(
            b.holds(&cm),
            "⛔ A-F53 (b): the captured note whose record re-folded at 73 was never re-captured: {}",
            b.explain_unready(&cm)
        );
        assert_eq!(b.held_paths(), vec![(cm, path, Some(73))], "re-captured where the new order put its record");
    }
}

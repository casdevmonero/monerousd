// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE CANONICAL TAG CHAIN — the one value a constant node holds of every spend in history (A-F114 phase 2,
//! lane speed5, 2026-11-22; docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md, "FOUND 2026-11-22").
//!
//! User 2026-11-22: *"the memory shouldnt be growing with time"*. A node can drop the spent set only if a spender proves
//! its nullifier absent from every block since its note was made, against a value the node holds. That value must not be
//! a SUM (a forger hits a sum with fake blocks by Wagner's k-tree), so it is a HASH CHAIN in canonical record order
//! (BORROWED: Bitcoin's prev-hash): each record's tags, padded with domain fillers to whole chunks of
//! [`usdm_agg::absence_ssa::CHUNK_TAGS`], step `C' = sponge(C ‖ chunk)`, exactly the step the absence carrier's leaf
//! constrains in circuit. A carrier ending at the node's `C` cannot have been forged backwards (a Poseidon2 preimage).
//!
//! AI RESISTANT: (a) — the carrier is a proof every node checks against this value; the value is a hash chain.
//! SCALE: one digest; a record costs `ceil(tags / 32)` chain steps (~8 for a 256-tag block), nothing per height.
//! O1-FOOTPRINT-REVIEWED: no state here; the node holds one digest and a ring of CANON_RECENT_RECORDS digests.
use usdm_agg::absence_ssa::{chain_step, filler_tag, out_aux, Chunk, Lanes, Record, CHUNK_TAGS};
use usdm_decider::hiding_decider::Fa4;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::spend_frontier::Digest4;

/// ⭐ THE SWITCH (A-F114): defined once in `params` (the ledger reads it too), re-exported here for the node's readers.
pub use crate::params::{canon_live, CANON_LIVE};

/// Records a node keeps the end and the tags of, newest last, so a carrier ending a few records back still finds its end and
/// the node checks the records after it itself. A constant: a bound on how stale a spender's carrier may be (the wallet
/// extends it; at ~5 s a record, about 85 minutes), never a term in height.
/// SCALE: ~1,024 × 256 tags ≈ 262 k map entries (~13 MB), and the tags and output leaves in the ring (~16 MB), whatever
/// the height.
pub const CANON_RECENT_RECORDS: usize = 1024;

/// ⭐ A-F114 UPGRADE (U2) — records a node holds BELOW the judged window, so it can still serve a joiner whose bundle stands
/// under the tip: a served bundle is up to ~112 fold steps old (`node::join` FREEZE_EVERY 16 × FROZEN_KEPT 7) and a block
/// lays at least one record. Never judged: a spend's end and a tag's presence are read only inside the newest
/// [`CANON_RECENT_RECORDS`] by index ([`CanonRecent::judge_floor`]), so a node that holds the margin and a joiner that does
/// not reach one verdict. SCALE: a constant (+512 records, ~8 MB tags and leaves). cons: that RAM on every node.
pub const CANON_SERVE_MARGIN: usize = 512;

/// ⭐ A-F114 U2 — the records a joiner pulls per answer (the HTTP route's page, ~1 MB at full records).
pub const CANON_PAGE_RECORDS: usize = 64;

/// ⭐ THE RECENT WINDOW (A-F114 2c): the last [`CANON_RECENT_RECORDS`] records' ends and tags, and for every tag in them the
/// newest ordinal that carried it. A spend whose carrier ends at record `T` is spent after `T` iff its nullifier is a tag
/// of a record after `T`: one map lookup.
/// O1-FOOTPRINT-REVIEWED: at most CANON_RECENT_RECORDS records and their tags; the oldest record is evicted on every push.
/// One record the window holds: its chain index, its end value, its tags, its output leaves, and its block's blue score
/// (the coordinate a wallet's scan counts, so its follower absorbs only records its scan has read).
pub type RecentRecord = (u64, Digest4, std::sync::Arc<Vec<[u8; 32]>>, std::sync::Arc<Vec<Digest4>>, u64);

#[derive(Default)]
pub struct CanonRecent {
    ring: std::collections::VecDeque<RecentRecord>,
    newest: std::collections::HashMap<[u8; 32], u64>,
    /// ⛔ U-LOCK-9 (2026-11-27) — how many ring records carry each output-leaf list, keyed by [`leaves_digest`], so
    /// [`Self::holds_leaves`] is one lookup instead of a compare against every record (the fold's provisional-row sweep asked it
    /// once per held row per fold step). Kept by the ring's only writers: `push` (its push and pop) and `truncate_from`.
    /// O1-FOOTPRINT-REVIEWED: one 32 B key and a count per ring record, bounded as the ring is.
    leaf_sets: std::collections::HashMap<[u8; 32], u32>,
}

/// ⛔ U-LOCK-9 — one digest of a record's output leaves (blake3 over their canonical bytes), the key [`CanonRecent::holds_leaves`]
/// reads. Two lists with one digest are one list (blake3's collision resistance), so the answer is the list compare's answer.
#[must_use]
pub fn leaves_digest(leaves: &[Digest4]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("monerousd canon window leaves v1");
    for l in leaves {
        h.update(&digest_bytes(l));
    }
    *h.finalize().as_bytes()
}

impl CanonRecent {
    /// Record `ordinal` folded with these tags and output leaves, the chain at its end `c`.
    pub fn push(&mut self, ordinal: u64, c: Digest4, tags: std::sync::Arc<Vec<[u8; 32]>>, leaves: std::sync::Arc<Vec<Digest4>>, score: u64) {
        for t in tags.iter() {
            self.newest.insert(*t, ordinal);
        }
        *self.leaf_sets.entry(leaves_digest(&leaves)).or_insert(0) += 1;
        self.ring.push_back((ordinal, c, tags, leaves, score));
        while self.ring.len() > CANON_RECENT_RECORDS + CANON_SERVE_MARGIN {
            if let Some((o, _, old, old_leaves, _)) = self.ring.pop_front() {
                self.forget_leaves(&old_leaves);
                for t in old.iter() {
                    if self.newest.get(t) == Some(&o) {
                        self.newest.remove(t);
                    }
                }
            }
        }
    }

    /// The record index after the newest held (0 with none).
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.ring.back().map_or(0, |(o, _, _, _, _)| o.saturating_add(1))
    }

    /// ⭐ A-F114 U2 — the oldest record index a verdict reads: the newest [`CANON_RECENT_RECORDS`] by INDEX, whatever this
    /// node holds below them (the serve margin), so every node judges one window.
    #[must_use]
    pub fn judge_floor(&self) -> u64 {
        self.next_index().saturating_sub(CANON_RECENT_RECORDS as u64)
    }

    /// The record whose end is `c`, if the judged window holds it.
    #[must_use]
    pub fn ordinal_of_end(&self, c: &Digest4) -> Option<u64> {
        let floor = self.judge_floor();
        self.ring.iter().rev().take_while(|(o, _, _, _, _)| *o >= floor).find(|(_, e, _, _, _)| e == c).map(|(o, _, _, _, _)| *o)
    }

    /// ⭐ A-F118 — does a record this window holds (judged or serve margin) carry exactly these output leaves, in order?
    #[must_use]
    pub fn holds_leaves(&self, leaves: &[Digest4]) -> bool {
        self.leaf_sets.contains_key(&leaves_digest(leaves))
    }

    /// As [`Self::holds_leaves`], for a caller that already holds the list's [`leaves_digest`].
    #[must_use]
    pub fn holds_leaves_digest(&self, d: &[u8; 32]) -> bool {
        self.leaf_sets.contains_key(d)
    }

    fn forget_leaves(&mut self, leaves: &[Digest4]) {
        let d = leaves_digest(leaves);
        if let Some(n) = self.leaf_sets.get_mut(&d) {
            *n -= 1;
            if *n == 0 {
                self.leaf_sets.remove(&d);
            }
        }
    }

    /// Was `tag` carried by any record of the judged window?
    #[must_use]
    pub fn holds(&self, tag: &[u8; 32]) -> bool {
        let floor = self.judge_floor();
        self.newest.get(tag).is_some_and(|o| *o >= floor)
    }

    /// ⭐ A-F114 U2 — THE JUDGED WINDOW AS ONE VALUE: every judged record's `(index, end, score)`, oldest first. Committed in
    /// the state a joiner stands on (`sync::NullifierSnapshot::canon`), so the 32 mined vouchers vouch it; the tags and
    /// leaves are bound by the chain itself (each record's end is `record_step` of the one before).
    #[must_use]
    pub fn window_digest(&self) -> [u8; 32] {
        let floor = self.judge_floor();
        window_digest_of(self.ring.iter().filter(|(o, _, _, _, _)| *o >= floor).map(|(o, c, _, _, sc)| (*o, *c, *sc)))
    }

    /// Was `tag` carried by a record after `after`, within the window?
    #[must_use]
    pub fn spent_after(&self, tag: &[u8; 32], after: u64) -> bool {
        self.newest.get(tag).is_some_and(|o| *o > after)
    }

    /// The records held, oldest first, with their tags (what the sidecar keeps).
    #[must_use]
    pub fn entries(&self) -> Vec<crate::persist::CanonEntry> {
        self.ring.iter().map(|(o, c, t, l, sc)| (*o, *c, t.as_ref().clone(), l.as_ref().clone(), *sc)).collect()
    }

    /// Up to `count` records from chain index `from` (oldest first): what the wallet follower reads.
    #[must_use]
    pub fn range(&self, from: u64, count: usize) -> Vec<RecentRecord> {
        self.ring.iter().filter(|(o, _, _, _, _)| *o >= from).take(count).cloned().collect()
    }

    /// ⭐ A-F114 U3 — drop every record at or above index `from` (a fold rewind): the ring and the tag map both, and a
    /// tag a dropped record carried is re-filed at its newest remaining record if one carries it too.
    pub fn truncate_from(&mut self, from: u64) {
        let mut dropped: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        while self.ring.back().is_some_and(|(o, _, _, _, _)| *o >= from) {
            if let Some((o, _, tags, leaves, _)) = self.ring.pop_back() {
                self.forget_leaves(&leaves);
                for t in tags.iter() {
                    if self.newest.get(t) == Some(&o) {
                        self.newest.remove(t);
                        dropped.insert(*t);
                    }
                }
            }
        }
        if dropped.is_empty() {
            return;
        }
        for (o, _, tags, _, _) in &self.ring {
            for t in tags.iter() {
                if dropped.contains(t) {
                    self.newest.insert(*t, *o);
                }
            }
        }
    }

    /// The oldest record index the window holds.
    #[must_use]
    pub fn oldest(&self) -> Option<u64> {
        self.ring.front().map(|(o, _, _, _, _)| *o)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

/// A tag's lanes as the carrier's circuit reads them: `nf_to_limbs` (Poseidon2 lanes, each < p) as field elements.
#[must_use]
pub fn tag_lanes(tag: &[u8; 32]) -> Lanes {
    let d = usdm_decider::nf_sparse_air::nf_to_limbs(tag);
    core::array::from_fn(|i| Fa4::from_u32(d[i] as u32))
}

#[must_use]
pub fn to_lanes(d: &Digest4) -> Lanes {
    core::array::from_fn(|i| Fa4::from_u32(d[i] as u32))
}

#[must_use]
pub fn of_lanes(l: &Lanes) -> Digest4 {
    core::array::from_fn(|i| u64::from(l[i].as_canonical_u32()))
}

/// A chain value as 32 bytes (eight lanes, each a little-endian u32): the wire form of a record end.
#[must_use]
pub fn digest_bytes(d: &Digest4) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&(d[i] as u32).to_le_bytes());
    }
    out
}

/// The inverse of [`digest_bytes`]; `None` for a lane at or above the field's modulus (one value, one encoding).
#[must_use]
pub fn digest_of_bytes(b: &[u8; 32]) -> Option<Digest4> {
    let mut d = [0u64; 8];
    for i in 0..8 {
        let v = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().ok()?);
        if Fa4::from_u32(v).as_canonical_u32() != v {
            return None;
        }
        d[i] = u64::from(v);
    }
    Some(d)
}

/// The chain before any record: a domain image, never zero.
#[must_use]
pub fn genesis() -> Digest4 {
    // "CANONCH2"
    let dom: Lanes = core::array::from_fn(|i| Fa4::from_u32([0x4341_4E4F, 0x4E43_4832, 0, 0, 0, 0, 0, 1][i]));
    of_lanes(&usdm_agg::absence_ssa::nfs_digest(&[(dom, [Fa4::ZERO; 8])]))
}

/// The END lane of record `index` (the chain's OWN record count, 0 first — never a node's arrival ordinal nor a record
/// address, which are other coordinate spaces): the carrier's one definition.
pub use usdm_agg::absence_ssa::end_aux;

/// ⭐ A-F114 — THE ONE RECORD SHAPE (2026-11-22). Every record of the canonical chain lays exactly [`RECORD_TAG_CHUNKS`] tag
/// chunks and [`RECORD_OUT_CHUNKS`] output chunks, because a carrier's leaf proves records of ONE `(t, o)` and its merge
/// joins only proofs of one shape (`absence_u::prove_span`, `prove_merge`). Found reading the fold: a record padded only to
/// whole chunks took the block's admitted tag count (the lane minus its losers, so 1 to 8 chunks, and none at a block's
/// later sub-records), and the first record of another shape would have stopped every carrier on the chain. A record is
/// one lane's width of tags ([`crate::cover::BLOCK_FIXED_NULLIFIER_COUNT`]) and one DA record's leaves
/// ([`crate::cover::BLOCK_FIXED_NOTE_COUNT`]); a block with more tags than one record holds is laid as more records
/// ([`record_units`]). cons: an idle record steps 16 chunks where it stepped 2 (~14 more chain steps, ~460 permutations,
/// well under a millisecond); a block with more than 256 admitted tags adds a record per 256 (the window's 1,024 records
/// then span fewer blocks, by the same count).
pub const RECORD_TAGS: usize = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
pub const RECORD_LEAVES: usize = crate::cover::BLOCK_FIXED_NOTE_COUNT;
pub const RECORD_TAG_CHUNKS: usize = RECORD_TAGS / CHUNK_TAGS;
pub const RECORD_OUT_CHUNKS: usize = RECORD_LEAVES / CHUNK_TAGS;
const _: () = assert!(RECORD_TAGS % CHUNK_TAGS == 0 && RECORD_LEAVES % CHUNK_TAGS == 0, "a record is whole chunks");

/// ⭐ A-F114 — THE ONE SHAPE THE SPEND DOOR ADMITS: a wallet's list ([`crate::canon_carrier_core::WALLET_SLOTS`]) over the
/// one record shape, [`crate::canon_carrier_core::SPAN`] records a leaf. A wrapper of any other shape is refused before its
/// family is built (`absence_u::verify_spend`).
pub const SPEND_SHAPE: usdm_agg::absence_u::Shape =
    (crate::canon_carrier_core::WALLET_SLOTS, RECORD_TAG_CHUNKS, RECORD_OUT_CHUNKS, crate::canon_carrier_core::SPAN);
// the door and the payment tree admit ONE shape: the node's derivation and the prover crate's constant must agree
const _: () = {
    let (a, b) = (SPEND_SHAPE, usdm_agg::absence_u::ADMITTED_SPEND_SHAPE);
    assert!(a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3, "SPEND_SHAPE must equal absence_u::ADMITTED_SPEND_SHAPE");
};

/// ⭐ A-F114 — A BLOCK'S RECORDS OF THE CHAIN: its admitted tags and one DA record's leaves laid [`RECORD_TAGS`] and
/// [`RECORD_LEAVES`] at a time, so every record has the one shape. At least one record (an idle record still steps the
/// chain); as many as the longer of the two needs. The fold steps each in order and the window holds each.
#[must_use]
pub fn record_units(tags: &[[u8; 32]], leaves: &[Digest4]) -> Vec<(Vec<[u8; 32]>, Vec<Digest4>)> {
    let n = tags.len().div_ceil(RECORD_TAGS).max(leaves.len().div_ceil(RECORD_LEAVES)).max(1);
    (0..n)
        .map(|u| {
            let t = tags.iter().skip(u * RECORD_TAGS).take(RECORD_TAGS).copied().collect();
            let l = leaves.iter().skip(u * RECORD_LEAVES).take(RECORD_LEAVES).copied().collect();
            (t, l)
        })
        .collect()
}

fn whole_chunks(mut lanes: Vec<Lanes>, filler_from: u64, chunks: usize) -> Vec<Vec<Lanes>> {
    // the one shape; a caller that passed more than a record holds gets whole chunks of it (another shape, which every
    // carrier refuses), never a truncation that would drop a tag from the chain
    let target = (chunks * CHUNK_TAGS).max(lanes.len().div_ceil(CHUNK_TAGS) * CHUNK_TAGS);
    let mut i = filler_from;
    while lanes.len() < target {
        lanes.push(filler_tag(i));
        i += 1;
    }
    lanes.chunks(CHUNK_TAGS).map(<[Lanes]>::to_vec).collect()
}

/// Record `index` as the chain absorbs it: its tags in order (domain fillers to whole chunks, aux zero), then its output
/// leaves (`Node::da_block_leaves`, fillers from a disjoint range, aux `out_aux`, the last one [`end_aux`]). At least one
/// chunk of each, so an idle record still steps the chain.
#[must_use]
pub fn record(tags: &[[u8; 32]], leaves: &[Digest4], index: u64) -> Record {
    let tags: Vec<Chunk> =
        whole_chunks(tags.iter().map(tag_lanes).collect(), 0, RECORD_TAG_CHUNKS).into_iter().map(|c| (c, [Fa4::ZERO; 8])).collect();
    let oc = whole_chunks(leaves.iter().map(to_lanes).collect(), 1 << 40, RECORD_OUT_CHUNKS);
    let n = oc.len();
    let outs: Vec<Chunk> = oc.into_iter().enumerate().map(|(k, c)| (c, if k + 1 == n { end_aux(index) } else { out_aux() })).collect();
    Record { tags, outs }
}

/// The one spelling of [`CanonRecent::window_digest`].
#[must_use]
pub fn window_digest_of(entries: impl Iterator<Item = (u64, Digest4, u64)>) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/canon-window/v1");
    for (o, c, sc) in entries {
        h.update(&o.to_le_bytes());
        h.update(&digest_bytes(&c));
        h.update(&sc.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// ⭐ A-F114 U2 — the canonical chain a joiner stands on, committed in its vouched state (`sync::NullifierSnapshot::canon`):
/// the next record index, the end after the newest record, the judged window's digest, and the chain's three record-index
/// counters (decoy batch, bounty, theft), which every node steps with the records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonState {
    pub index: u64,
    pub c: [u8; 32],
    pub window: [u8; 32],
    pub seqs: (u64, u64, u64),
}

/// One record of a [`CanonPage`]: its index, its end, its tags, its output leaves (eight lanes each, `digest_bytes`), its
/// block's blue score.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonPageRecord {
    pub i: u64,
    pub end: [u8; 32],
    pub tags: Vec<[u8; 32]>,
    pub leaves: Vec<[u8; 32]>,
    pub score: u64,
}

/// ⭐ A-F114 U2 — a run of consecutive records and the end BEFORE its first (genesis before record 0): what a joiner checks
/// link by link. Wire: `CANON_PAGE_TAG ‖ postcard(CanonPage)`; the tag alone is the `notfound`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonPage {
    pub prev: [u8; 32],
    pub records: Vec<CanonPageRecord>,
}

/// The answer's tag on the bulk lane (kind [`BULK_REQ_KIND_CANON_PAGE`]).
pub const CANON_PAGE_TAG: &[u8; 8] = b"CANONPGE";
/// ⭐ A-F114 U2 — THE CANONICAL RECORD PULL: `[33][from u64 LE][count u16 LE]` (11 bytes; no marker kind may be 12).
pub const BULK_REQ_KIND_CANON_PAGE: u8 = 33;

#[must_use]
pub fn canon_page_ask(from: u64, count: u16) -> Vec<u8> {
    let mut r = Vec::with_capacity(11);
    r.push(BULK_REQ_KIND_CANON_PAGE);
    r.extend_from_slice(&from.to_le_bytes());
    r.extend_from_slice(&count.to_le_bytes());
    r
}

/// `(from, count)` of a kind-33 ask, by its exact shape.
#[must_use]
pub fn parse_canon_page_ask(req: &[u8]) -> Option<(u64, u16)> {
    if req.len() != 11 || req[0] != BULK_REQ_KIND_CANON_PAGE {
        return None;
    }
    Some((u64::from_le_bytes(req[1..9].try_into().ok()?), u16::from_le_bytes(req[9..11].try_into().ok()?)))
}

/// A page decoded and checked link by link: each record of the chain's one shape (at most [`RECORD_TAGS`] tags and
/// [`RECORD_LEAVES`] leaves, every lane canonical), consecutive, and `record_step(prev, record) == end` for each. Returns
/// the records with their decoded ends, or `None` for any defect. A forged record that passes needs a Poseidon2 collision.
#[must_use]
pub fn check_canon_page(page: &CanonPage) -> Option<(Digest4, Vec<RecentRecord>)> {
    if page.records.is_empty() || page.records.len() > CANON_PAGE_RECORDS {
        return None;
    }
    let prev = digest_of_bytes(&page.prev)?;
    let mut p = prev;
    let mut out = Vec::with_capacity(page.records.len());
    for (k, r) in page.records.iter().enumerate() {
        if k > 0 && r.i != page.records[k - 1].i.checked_add(1)? {
            return None;
        }
        if r.tags.len() > RECORD_TAGS || r.leaves.len() > RECORD_LEAVES {
            return None;
        }
        let leaves: Vec<Digest4> = r.leaves.iter().map(digest_of_bytes).collect::<Option<_>>()?;
        let end = digest_of_bytes(&r.end)?;
        if record_step(&p, &r.tags, &leaves, r.i) != end {
            return None;
        }
        p = end;
        out.push((r.i, end, std::sync::Arc::new(r.tags.clone()), std::sync::Arc::new(leaves), r.score));
    }
    Some((prev, out))
}

/// ⭐ A-F114 U2 — A JOINER'S PULL OF THE JUDGED WINDOW, checked backward from the vouched end. It holds the records it has,
/// newest end known (`want_top`, the vouched `c` at first), and asks for the run just below them; a page must END at the
/// record below its lowest with exactly that end, and its own `prev` becomes the next end wanted. When the window is whole
/// its `(index, end, score)` digest must be the vouched one, or the pull starts over (scores are bound only by the digest).
/// SCALE: at most [`CANON_RECENT_RECORDS`] records held while pulling, the window itself. AI RESISTANT: (a) — the vouched
/// state (32 mined headers) and a hash chain; a lying server gains a refused page.
#[derive(Clone, Debug)]
pub struct CanonFill {
    pub state: CanonState,
    /// Records held so far, oldest first, contiguous up to `state.index - 1`.
    got: std::collections::VecDeque<RecentRecord>,
    /// The end of the record just below the lowest held (the vouched `c` before any page).
    want_top: Digest4,
}

/// What one page did to a fill.
#[derive(Debug, PartialEq, Eq)]
pub enum FillStep {
    /// Taken; more to pull.
    Progress,
    /// The window is whole and its digest is the vouched one: install these, oldest first.
    Done,
    /// The page does not fit (not the run asked, or a broken link): dropped, the fill unchanged.
    Refused,
    /// The whole window's digest is not the vouched one: the fill starts over.
    Restart,
}

impl CanonFill {
    /// `None` when `state.c` is not a canonical value.
    #[must_use]
    pub fn new(state: CanonState) -> Option<Self> {
        Some(Self { want_top: digest_of_bytes(&state.c)?, state, got: std::collections::VecDeque::new() })
    }

    fn need_from(&self) -> u64 {
        self.state.index.saturating_sub(CANON_RECENT_RECORDS as u64)
    }

    fn low(&self) -> u64 {
        self.got.front().map_or(self.state.index, |r| r.0)
    }

    /// Is the window whole already (a chain with no records, or every record held)?
    #[must_use]
    pub fn whole(&self) -> bool {
        self.low() <= self.need_from()
    }

    /// The run to ask for next: `(from, count)`.
    #[must_use]
    pub fn ask(&self) -> Option<(u64, u16)> {
        let (low, need) = (self.low(), self.need_from());
        if low <= need {
            return None;
        }
        let from = low.saturating_sub(CANON_PAGE_RECORDS as u64).max(need);
        Some((from, u16::try_from(low - from).ok()?))
    }

    /// Take one checked page.
    pub fn take(&mut self, page: &CanonPage) -> FillStep {
        let Some((prev, recs)) = check_canon_page(page) else { return FillStep::Refused };
        let Some((from, count)) = self.ask() else { return FillStep::Refused };
        let fits = recs.first().map(|r| r.0) == Some(from)
            && recs.len() == usize::from(count)
            && recs.last().is_some_and(|r| r.0.saturating_add(1) == self.low() && r.1 == self.want_top);
        if !fits {
            return FillStep::Refused;
        }
        for r in recs.into_iter().rev() {
            self.got.push_front(r);
        }
        self.want_top = prev;
        if !self.whole() {
            return FillStep::Progress;
        }
        if window_digest_of(self.got.iter().map(|(o, c, _, _, sc)| (*o, *c, *sc))) == self.state.window {
            FillStep::Done
        } else {
            self.got.clear();
            self.want_top = digest_of_bytes(&self.state.c).unwrap_or(self.want_top);
            FillStep::Restart
        }
    }

    /// The records, oldest first (after `Done`).
    #[must_use]
    pub fn into_records(self) -> Vec<RecentRecord> {
        self.got.into_iter().collect()
    }
}

/// Step the chain over record `index`.
#[must_use]
pub fn record_step(c: &Digest4, tags: &[[u8; 32]], leaves: &[Digest4], index: u64) -> Digest4 {
    let mut l = to_lanes(c);
    let r = record(tags, leaves, index);
    for (t, aux) in r.tags.iter().chain(&r.outs) {
        l = chain_step(&l, t, aux).expect("record yields whole chunks");
    }
    of_lanes(&l)
}

impl crate::node::Node {
    /// ⭐ A-F114 2c — THE ONE DOOR every "is this nullifier unspent" reader asks (the audit's shared site): `None` when the
    /// spend wrapper `w.proof` shows the note behind `leaf_commit` (the spend's own member tuple) made in a record of this chain
    /// and `nf` a tag of no record from its making to `w.end`, `w.end` is a record end this node's window holds, and `nf` is a
    /// tag of no record after it; otherwise the reason it refuses. It names no record, no position, no list.
    /// §9.6: (1) PoW — the tx's own; (2) the wrapper by `usdm_agg::absence_u::verify_spend` (the universal family: every
    /// node below verified in circuit, one claim, one proof size at any depth);
    /// (3) value — none created here; (4) replay — the window's tags refuse a spend after `end`, the carrier every one before;
    /// (5) work — one SSA verify and one map lookup; (6) parity — the set's `holds` answers the same question for the same
    /// nullifier; (7) scale — a constant per nullifier, nothing per height; (8) (a) a proof every node checks, and a lying
    /// prover is refused by the carrier's and the wrapper's own pins (a1-a8, w1).
    pub(crate) fn canon_absence_refusal(&self, nf: &[u8; 32], leaf_commit: &Digest4, w: &crate::nf_sparse::CanonAbsence) -> Option<&'static str> {
        let Some(t) = self.canon_recent.ordinal_of_end(&w.end) else {
            return Some("the carrier's chain end is not a record end this node's window holds: extend it to a recent record");
        };
        if self.canon_recent.spent_after(nf, t) {
            return Some("the nullifier is a tag of a record after the carrier's end: already spent");
        }
        // the binder is the nullifier as the member tuple states it (`member_transition::cross_binds`: cm_bytes_to_root)
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(nf) else {
            return Some("the nullifier is not a canonical digest, so it binds no member tuple");
        };
        if !usdm_agg::absence_u::verify_spend(&w.proof, SPEND_SHAPE, &tag_lanes(nf), &to_lanes(&binder), &to_lanes(leaf_commit), &to_lanes(&w.end)) {
            return Some("the spend's absence proof does not show its note made in this chain and its nullifier unspent to its end");
        }
        None
    }
}

impl crate::node::Node {
    /// ⭐ A-F114 2c — ONE TAG AT THE FOLD under the constant chain (`CANON_LIVE`): `Some(true)` = spent (its item loses),
    /// `Some(false)` = unspent. Called right before the record takes its position, so the window holds exactly the records
    /// before it in canonical order, the same on every node.
    /// * a stated spend's nullifier (`lc` = its own tuple's leaf commitment): its wrapper decides (`canon_absence_refusal`);
    /// * a class object's burned note (`object_tag`): FAIL-CLOSED until objects carry wrappers (audit, phase 4 list);
    /// * every other tag (`tag1`, cover): refused only when a record of the window carries it — `tag1`'s uniqueness beyond
    ///   the window is its owner's devices' own check (the audit's (iv): only the `slot_key` holder can claim).
    pub(crate) fn canon_tag_spent(
        &self,
        t: &[u8; 32],
        lc: Option<&Digest4>,
        unknown: bool,
        ev: Option<&crate::nf_evidence::CanonTagEvidence>,
    ) -> Option<bool> {
        if let Some(lc) = lc {
            let Some(e) = ev else { return Some(true) };
            let w = crate::nf_sparse::CanonAbsence { proof: e.wrapper.clone(), end: e.end };
            return Some(self.canon_absence_refusal(t, lc, &w).is_some());
        }
        if unknown {
            return Some(true); // an object tag `chain_object::object_tag_roles` has not read: fail closed
        }
        Some(self.canon_recent.holds(t))
    }

    /// ⭐ A-F114 — THE POOL DOOR'S READING OF A FRAMED OBJECT under the constant chain, the fold's rule exactly: each
    /// `Leg` by its wrapper (the i-th wrapper the tx carries for the i-th leg, in `object_tag_roles` order), each `OneTime`
    /// and every other lane tag (cover) by the window, and an `Unknown` tag refused. A courtesy; the fold decides.
    pub(crate) fn canon_object_absent(&self, tx: &crate::mempool::PqTx) -> bool {
        let Some(roles) = crate::chain_object::object_tag_roles(&tx.blob) else { return false };
        let ws = tx.nullifier_absence.first().map(crate::nf_sparse::canon_wrappers).unwrap_or_default();
        let legs: Vec<(&[u8; 32], &Digest4)> = roles
            .iter()
            .filter_map(|(t, r)| if let crate::chain_object::TagRole::Leg(lc) = r { Some((t, lc)) } else { None })
            .collect();
        if legs.len() != ws.len() || roles.iter().any(|(_, r)| *r == crate::chain_object::TagRole::Unknown) {
            return false;
        }
        // ⭐ A-F114 — A-F26's CLASS UNDER THE CONSTANT CHAIN: every slot of one DeFi batch names ONE chain end, or the ends
        // would partition its real slots (a wallet's end) from its covers (the builder's), as anchors once did (FOUND
        // 2026-11-22 reading the DefiSlots door for the covers pin)
        if crate::chain_object::unframe(&tx.blob).is_some_and(|(c, _)| c == crate::chain_object::Class::DefiSlots)
            && ws.windows(2).any(|p| p[0].end != p[1].end)
        {
            return false;
        }
        if legs.iter().zip(&ws).any(|((t, lc), w)| self.canon_absence_refusal(t, lc, w).is_some()) {
            return false;
        }
        tx.nullifiers.iter().filter(|n| !legs.iter().any(|(t, _)| **t == n.0)).all(|n| !self.canon_recent.holds(&n.0))
    }
}

/// ⭐ A-F114 (B′) — THE ONE READER OF A SEND'S REAL INPUT under the constant chain: its spend tuple's nullifier (the
/// lane's first tag) and the leaf commitment its spend carrier proves (`Node::spend_tuple_of`: `nullifiers[0]`,
/// `membership_leaf_commit`). The wrapper is checked against exactly this pair, so it vouches for the note the spend carrier
/// opened and for no other (the cross-bind the member tuple used to make, `member_transition::cross_binds`). Every switch
/// reader (the pool gate, the member verdict, the producer's evidence, the tree statement) reads it here.
#[must_use]
pub(crate) fn canon_spend_input(tx: &crate::mempool::PqTx) -> Option<([u8; 32], Digest4)> {
    let t = crate::node::Node::spend_tuple_of(tx)?;
    Some((t.nullifier, crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit)?))
}

/// ⭐ A-F114 — A DEFI SLOT'S STATE under the constant chain, as custody's intake reads it (`defi_lane::NodeHost::slot_live`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonSlot {
    /// the window carries its nullifier: it can never be carried
    Spent,
    /// its held wrapper is refused by the canonical door at an end this node holds: it can never be carried as held
    Refused,
    /// no wrapper held yet, or one whose end the window no longer holds: its holder sends a fresh one (never dropped for it)
    Pending,
    /// carried
    Live,
}

impl crate::node::Node {
    /// ⭐ A-F114 — the state of a slot spending `nf` (bytes) under the cross-bind `lc`, from the window and the wrapper its
    /// holder relayed (`canon_held_wrappers`, one `CanonAbsence` a slot). The same door every spend meets
    /// (`canon_absence_refusal`); nothing here is a second rule.
    pub(crate) fn canon_slot_state(&self, nf: &[u8; 32], lc: &Digest4) -> CanonSlot {
        if self.canon_recent.holds(nf) {
            return CanonSlot::Spent;
        }
        let Some((_, held)) = self.canon_held_wrappers.iter().find(|(k, _)| k == nf) else { return CanonSlot::Pending };
        let ws: Vec<crate::nf_sparse::CanonAbsence> = postcard::from_bytes(held).unwrap_or_default();
        let Some(w) = ws.first() else { return CanonSlot::Pending };
        if self.canon_recent.ordinal_of_end(&w.end).is_none() {
            return CanonSlot::Pending;
        }
        if self.canon_absence_refusal(nf, lc, w).is_some() {
            CanonSlot::Refused
        } else {
            CanonSlot::Live
        }
    }
}

/// How many held claims' wrappers a node keeps (`Node::canon_held_wrappers`): a protocol constant, the oldest leaving first.
pub(crate) const CANON_HELD_MAX: usize = 64;

std::thread_local! {
    /// The spender's wrappers for the ONE rpc call in progress on this thread (`scope_spender_wrappers`).
    static SPENDER_WRAPPERS: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// ⭐ A-F114 — THE SPENDER'S WRAPPERS FOR AN OBJECT IT SUBMITS. Every object route builds its pooled tx in one place
/// (`Node::spending_object_tx`), which under the old chain asked this node's spent view for the absence evidence. The
/// constant chain holds no such view: only the spender can prove its note unspent. So `rpc_http::route` reads a body's
/// `canon_absence_hex` (`postcard(Vec<CanonAbsence>)`, one per `Leg` of the object, in its order) into this scope for the
/// length of that one call, and the builder carries it. Dropped with the guard, so nothing outlives the call; a call
/// handed to another thread sees none and its object is refused at the pool, never at the fold (where a refused object
/// would burn the note it spends). O1-FOOTPRINT-REVIEWED: one call's bytes, released with the call.
#[must_use]
pub(crate) fn scope_spender_wrappers(bytes: Option<Vec<u8>>) -> SpenderWrappersScope {
    SPENDER_WRAPPERS.with(|c| *c.borrow_mut() = bytes);
    SpenderWrappersScope
}

/// The scoped wrappers of the call in progress, if it named any.
#[must_use]
pub(crate) fn spender_wrappers() -> Option<Vec<u8>> {
    SPENDER_WRAPPERS.with(|c| c.borrow().clone())
}

/// Clears the call's wrappers when the call ends.
pub(crate) struct SpenderWrappersScope;

impl Drop for SpenderWrappersScope {
    fn drop(&mut self) {
        SPENDER_WRAPPERS.with(|c| *c.borrow_mut() = None);
    }
}

impl crate::node::Node {
    /// ⭐ A-F114 2c — THE PRODUCER'S EVIDENCE under the constant chain: each selected tx's spend wrapper (its witness's
    /// `canon[i]`, paired with its i-th member tuple) laid at the lane position of that tuple's nullifier (the tag whose
    /// `cm_bytes_to_root` is the tuple's binder); every other position `None` (cover, `tag1`: the fold judges those by its
    /// window). A tx whose wrapper count is not its tuple count lays nothing, and its spend loses at the fold.
    pub(crate) fn canon_tag_evidence_for(&self, padded: &[[u8; 32]], txs: &[crate::mempool::PqTx]) -> Vec<u8> {
        let mut list: Vec<Option<crate::nf_evidence::CanonTagEvidence>> = vec![None; padded.len()];
        for tx in txs {
            // a framed object: its i-th wrapper at the lane position of its i-th `Leg` (`chain_object::object_tag_roles`)
            if let Some(roles) = crate::chain_object::unframe(&tx.blob).and_then(|_| crate::chain_object::object_tag_roles(&tx.blob)) {
                let ws = tx.nullifier_absence.first().map(crate::nf_sparse::canon_wrappers).unwrap_or_default();
                let legs: Vec<[u8; 32]> =
                    roles.iter().filter(|(_, r)| matches!(r, crate::chain_object::TagRole::Leg(_))).map(|(t, _)| *t).collect();
                if legs.len() == ws.len() {
                    for (t, w) in legs.iter().zip(&ws) {
                        if let Some(i) = padded.iter().position(|p| p == t) {
                            list[i] = Some(crate::nf_evidence::CanonTagEvidence { end: w.end, wrapper: w.proof.clone() });
                        }
                    }
                }
                continue;
            }
            // ⭐ A-F114 (B′): the spend's OWN input (its spend tuple), never a member tuple (the switch's form carries none)
            let Some((nf, _)) = canon_spend_input(tx) else { continue };
            let ws = tx.nullifier_absence.first().map(crate::nf_sparse::canon_wrappers).unwrap_or_default();
            let [w] = ws.as_slice() else {
                continue; // one input, one wrapper: anything else states nothing
            };
            if let Some(i) = padded.iter().position(|t| *t == nf) {
                list[i] = Some(crate::nf_evidence::CanonTagEvidence { end: w.end, wrapper: w.proof.clone() });
            }
        }
        postcard::to_allocvec(&list).unwrap_or_default()
    }
}

// TWO-PARTY-REVIEWED: a pure function of the records in order; the cross-party claim (two nodes folding the same records
// in different arrival orders reach the same C) is pinned where the node folds records (node/pins.rs, A-F114).
#[cfg(test)]
mod tests {
    use super::*;

    fn tag(i: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = i;
        t[31] = 0xA5;
        t
    }

    /// ⭐ A-F139 — A WRITE IN FLIGHT NEVER UNDOES A REWIND. RED before A-F139: the saver's `store(top)` after its write raised
    /// the cursor a rewind had just lowered, so the abandoned branch's slots were never rewritten.
    #[test]
    fn af139_a_write_captured_before_a_rewind_never_raises_the_cursor_past_it() {
        let saved = CanonSaved::default();
        saved.set(100);
        let (from, epoch) = saved.get();
        assert_eq!(from, 100, "CALIBRATION: the cursor stands at 100");
        saved.lower(90); // a fold rewind lands while the write captured at `epoch` runs
        saved.landed(epoch, 120);
        assert_eq!(saved.get().0, 90, "⛔ A-F139: the write's landing undid the rewind (slots 90.. never rewritten)");
        let (_, now) = saved.get();
        saved.landed(now, 120);
        assert_eq!(saved.get().0, 120, "⛔ a write with no change below it since its capture did not advance the cursor");
    }

    /// The chain moves with every record, depends on order and content, and an idle record still steps it.
    #[test]
    fn the_chain_is_order_and_content_bound_and_idle_records_step_it() {
        let g = genesis();
        assert_ne!(g, [0u64; 8], "genesis is a domain image, never zero");
        let a = record_step(&g, &[tag(1), tag(2)], &[], 0);
        let b = record_step(&g, &[tag(2), tag(1)], &[], 0);
        assert_ne!(a, b, "tag order is part of the chain");
        assert_ne!(a, record_step(&g, &[tag(1), tag(3)], &[], 0), "tag content is part of the chain");
        assert_ne!(record_step(&g, &[], &[], 0), g, "an idle record steps the chain");
        let ab = record_step(&record_step(&g, &[tag(1)], &[], 0), &[tag(2)], &[], 1);
        let ba = record_step(&record_step(&g, &[tag(2)], &[], 0), &[tag(1)], &[], 1);
        assert_ne!(ab, ba, "record order is part of the chain");
        assert_eq!(record(&vec![tag(9); 33], &[], 0).tags.len(), 2, "33 tags fill two chunks");
        assert_ne!(record_step(&g, &[tag(1)], &[[3u64; 8]], 0), record_step(&g, &[tag(1)], &[], 0), "the outputs are part of the chain");
        assert_ne!(record_step(&g, &[tag(1)], &[], 0), record_step(&g, &[tag(1)], &[], 1), "the record index is part of the chain");
    }

    /// The window answers "spent after T" by lookup, forgets only what left the window, and never exceeds its bound.
    #[test]
    fn the_recent_window_answers_spent_after_and_stays_bounded() {
        let mut w = CanonRecent::default();
        let mut c = genesis();
        for o in 1..=(CANON_RECENT_RECORDS as u64 + 10) {
            let tags = std::sync::Arc::new(vec![tag((o % 200) as u8), { let mut t = tag(0); t[1] = (o >> 8) as u8; t[2] = o as u8; t }]);
            c = record_step(&c, &tags, &[], o);
            w.push(o, c, tags, std::sync::Arc::new(Vec::new()), o);
        }
        assert_eq!(w.len(), CANON_RECENT_RECORDS, "the window never exceeds its bound");
        let last = CANON_RECENT_RECORDS as u64 + 10;
        let mut t_last = tag(0);
        t_last[1] = (last >> 8) as u8;
        t_last[2] = last as u8;
        assert!(w.spent_after(&t_last, last - 1), "a tag of the newest record is spent after the record before it");
        assert!(!w.spent_after(&t_last, last), "and not after the newest record itself");
        assert_eq!(w.ordinal_of_end(&c), Some(last), "the newest end is found");
        assert_eq!(w.ordinal_of_end(&genesis()), None, "an end outside the window is not");
        let mut t_old = tag(0);
        t_old[1] = 0;
        t_old[2] = 3;
        assert!(!w.spent_after(&t_old, 0), "a tag only an evicted record carried is forgotten");
    }

    /// ⭐ THE NODE'S VALUE IS THE CARRIER'S: a leaf proven over a record's chunks ends at exactly `record_step`'s value, and
    /// the door accepts it there (the node and the circuit compute one chain).
    #[test]
    fn a_carrier_over_a_record_ends_at_the_nodes_chain_value() {
        let g = genesis();
        let tags: Vec<[u8; 32]> = (1..=40u8).map(tag).collect();
        let nf = (tag_lanes(&tag(200)), 0u32);
        let leaves: Vec<Digest4> = (1..=5u64).map(|i| [i, 2, 3, 4, 5, 6, 7, 8]).collect();
        let c1 = record_step(&g, &tags, &leaves, 0);
        let r = record(&tags, &leaves, 0);
        let e = [(nf.0, to_lanes(&leaves[2]))];
        let p = usdm_agg::absence_u::prove_leaf(&e, to_lanes(&g), &[false], &r).expect("an absent nullifier proves");
        let d = usdm_agg::absence_u::list_digest(&e);
        assert!(usdm_agg::absence_u::verify(&p, (1, RECORD_TAG_CHUNKS, RECORD_OUT_CHUNKS, 1), &d, &to_lanes(&g), &[false], &to_lanes(&c1), &[true]), "made in this record: the bit is set");
        let spent = [(tag_lanes(&tag(7)), to_lanes(&leaves[2]))];
        assert!(usdm_agg::absence_u::prove_leaf(&spent, to_lanes(&g), &[false], &r).is_none(), "made and spent here: no carrier");
    }
}

impl crate::node::Node {
    /// ⭐ A-F114 U2 — the canonical chain this node stands on, as the state a joiner is vouched (`sync::NullifierSnapshot`).
    /// Zero on today's chain (the switch off), so every node commits the same value there.
    #[must_use]
    pub(crate) fn canon_state(&self) -> CanonState {
        if !canon_live() {
            return CanonState::default();
        }
        CanonState {
            index: self.canon_index,
            c: digest_bytes(&self.canon_c),
            window: self.canon_recent.window_digest(),
            seqs: (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq),
        }
    }

    /// ⭐ A-F114 U2 — install an adopted bundle's canonical chain: its index, end and counters at once, its window by the pull
    /// ([`CanonFill`]). A chain with no records installs whole (its window is empty; the digest must still be the empty one).
    pub(crate) fn adopt_certified_canon(&mut self, state: CanonState) {
        if !canon_live() {
            return;
        }
        let Some(fill) = CanonFill::new(state) else {
            eprintln!("[canon] ⛔ A-F114 U2: an adopted bundle names a non-canonical chain end — nothing installed");
            return;
        };
        self.canon_index = state.index;
        self.canon_c = digest_of_bytes(&state.c).unwrap_or(self.canon_c);
        (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq) = state.seqs;
        self.canon_recent = CanonRecent::default();
        self.canon_saved_top.lower(0); // A-F139: the window is replaced whole — every slot is rewritten once it lands
        self.canon_missing = 0;
        self.canon_rewind.clear(); // the adopted state has no local fold history to rewind into
        if fill.whole() && window_digest_of(std::iter::empty()) == state.window {
            self.canon_fill = None;
        } else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: the chain's own record index only.
            eprintln!("[canon] A-F114 U2: adopted the canonical chain at record {} — pulling its window before the fold moves", state.index);
            self.canon_fill = Some(fill);
        }
    }

    /// The pull's next ask (`[33][from][count]`), while a window is being pulled.
    #[must_use]
    pub(crate) fn canon_fill_ask(&self) -> Option<Vec<u8>> {
        let (from, count) = self.canon_fill.as_ref()?.ask()?;
        Some(canon_page_ask(from, count))
    }

    /// ⭐ A-F114 U2 — serve a kind-33 ask from the records this node holds (the judged window and the serve margin):
    /// `CANON_PAGE_TAG ‖ postcard(CanonPage)`, or the tag alone when it does not hold the whole run. Public chain data, the
    /// same for every asker (the tags every block carries and the ends every node derives).
    #[must_use]
    pub(crate) fn canon_page_serve(&self, req: &[u8]) -> Vec<u8> {
        let mut out = CANON_PAGE_TAG.to_vec();
        let Some((from, count)) = parse_canon_page_ask(req) else { return out };
        let count = usize::from(count).min(CANON_PAGE_RECORDS);
        if self.canon_fill.is_some() || count == 0 {
            return out; // a node still pulling its own window serves none of it
        }
        let recs = self.canon_recent.range(from, count);
        if recs.len() != count || recs.first().map(|r| r.0) != Some(from) {
            return out;
        }
        let prev = if from == 0 {
            Some(genesis())
        } else {
            self.canon_recent.range(from - 1, 1).first().filter(|r| r.0 == from - 1).map(|r| r.1)
        };
        let Some(prev) = prev else { return out };
        let page = CanonPage {
            prev: digest_bytes(&prev),
            records: recs
                .iter()
                .map(|(i, c, t, l, sc)| CanonPageRecord { i: *i, end: digest_bytes(c), tags: t.as_ref().clone(), leaves: l.iter().map(digest_bytes).collect(), score: *sc })
                .collect(),
        };
        if let Ok(b) = postcard::to_allocvec(&page) {
            out.extend_from_slice(&b);
        }
        out
    }

    /// ⭐ A-F114 U2 — take a `CANONPGE` answer (after the tag). `true` when it moved the pull.
    /// §9.6 DOOR (a new ingress path: records of the canonical window from a peer):
    /// (1) proof of work — none here: the state the pull ends at was vouched by `VOUCHERS` mined headers at the join door
    ///     (`join_proof::verify_join`, the state digest binds `NullifierSnapshot::canon`) before this door opens;
    /// (2) its own proof — each record's end is `record_step` of the end before it and the run ends at the end already held
    ///     (`check_canon_page`, `CanonFill::take`): a forged record needs a Poseidon2 collision; scores are bound by the
    ///     window digest at the end;
    /// (3) value — none created or moved: the records are read by the judge, never credited from;
    /// (4) replay — an unasked run, a run already held or one that does not end where the pull stands is `Refused`;
    /// (5) work bound — one page ≤ `CANON_PAGE_RECORDS` records of the one record shape, checked before any hash; a pull holds
    ///     at most `CANON_RECENT_RECORDS` records;
    /// (6) parity — the HTTP `/canon/records` route a wallet reads serves the same records, and the wallet checks the same links;
    /// (7) scale — one window per join, constant in the bonded set, the users and the height;
    /// (8) AI RESISTANT (a): a hash chain into a vouched end; a lying server gains a refused page, a persuasive one nothing.
    pub(crate) fn canon_page_take(&mut self, body: &[u8]) -> bool {
        let Some(fill) = self.canon_fill.as_mut() else { return false };
        let Some(page) = crate::chain_object::decode_exact::<CanonPage>(body) else { return false };
        match fill.take(&page) {
            FillStep::Progress => true,
            FillStep::Refused => false,
            FillStep::Restart => {
                eprintln!("[canon] ⛔ A-F114 U2: a pulled window does not reach the vouched digest — the pull starts over");
                true
            }
            FillStep::Done => {
                let Some(fill) = self.canon_fill.take() else { return false };
                self.canon_recent = CanonRecent::default();
                self.canon_saved_top.lower(0); // A-F139: the pulled window replaces every slot
                for (i, c, t, l, sc) in fill.into_records() {
                    self.canon_recent.push(i, c, t, l, sc);
                }
                // DIGITAL-CASH-PRIVACY-REVIEWED: a count and the chain's own record index.
                eprintln!("[canon] A-F114 U2: the window is whole ({} records to record {}) — the fold moves", self.canon_recent.len(), self.canon_index);
                true
            }
        }
    }
}

/// ⭐ A-F114 U3 — the canonical chain's state at one point: `(index, end, (decoy, bounty, theft) counters)`.
pub type CanonSnap = (u64, Digest4, (u64, u64, u64));

/// ⭐ A-F139 (lane selfheal, 2026-11-25) — THE RING FILE'S WRITE CURSOR, `(top, epoch)`: the record index through which the
/// file on disk holds THIS node's chain, and an epoch every change below `top` bumps.
/// MEASURED why (live origin and wallet node, 06:37/06:38): both ring files held 1,536 slots in place (25..1560 under head
/// 1561; 26..1561 under head 1562) and neither LINKED, so each node pulled its window from the other, and a node pulling
/// serves none (`canon_page_serve`): the fold sat at record 1562 for good and finality with it. The cursor was one
/// `AtomicU64` the saver thread STORED after its write, while a fold rewind on the node thread lowered it (`fetch_min`):
/// a rewind landing during a write was undone by the store, so the slots of the abandoned branch were never rewritten.
/// Now a write advances the cursor only when no change below it happened since its capture (the epoch it captured is
/// still the cell's); a rewind, an adopted window and a resume each lower it and bump the epoch, under one lock.
/// O1-FOOTPRINT-REVIEWED: two u64 behind one mutex, at any height.
#[derive(Default)]
pub struct CanonSaved(std::sync::Mutex<(u64, u64)>);

impl CanonSaved {
    fn cell(&self) -> std::sync::MutexGuard<'_, (u64, u64)> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// `(top, epoch)` now.
    #[must_use]
    pub fn get(&self) -> (u64, u64) {
        *self.cell()
    }
    /// The slots from `index` up no longer hold this node's chain: the next write rewrites them.
    pub fn lower(&self, index: u64) {
        let mut g = self.cell();
        g.0 = g.0.min(index);
        g.1 = g.1.wrapping_add(1);
    }
    /// The file holds this node's chain through `top` (a resume that read it back whole).
    pub fn set(&self, top: u64) {
        let mut g = self.cell();
        *g = (top, g.1.wrapping_add(1));
    }
    /// A write captured at `epoch` landed: the file holds the chain through `top` — unless something below changed since.
    pub fn landed(&self, epoch: u64, top: u64) {
        let mut g = self.cell();
        if g.1 == epoch {
            g.0 = top;
        }
    }
}

/// What a checkpoint writes of the canonical chain: the head, the slots, the cursor, the epoch it was captured at and the
/// top the write makes current.
pub type CanonRingCapture = (crate::persist::CanonHead, Vec<(u64, Vec<u8>)>, std::sync::Arc<CanonSaved>, u64, u64);

impl crate::node::Node {
    pub(crate) fn canon_snapshot(&self) -> CanonSnap {
        (self.canon_index, self.canon_c, (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq))
    }

    /// Put the chain back to `snap`: its index, end and counters, and drop every window record at or above its index.
    pub(crate) fn canon_restore(&mut self, snap: CanonSnap) {
        let (index, c, seqs) = snap;
        self.canon_recent.truncate_from(index);
        self.canon_saved_top.lower(index); // the slots from here are rewritten (A-F139: a write in flight never undoes this)
        self.canon_index = index;
        self.canon_c = c;
        (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq) = seqs;
    }

    /// A fold step folded: keep the state before it, bounded by the rewind reach.
    pub(crate) fn canon_note_step(&mut self, fold_ordinal: u64, before: CanonSnap) {
        self.canon_rewind.retain(|(o, _)| *o < fold_ordinal);
        self.canon_rewind.push_back((fold_ordinal, before));
        while self.canon_rewind.len() > Self::REWIND_RETAIN {
            self.canon_rewind.pop_front();
        }
    }

    /// ⭐ A-F114 U3 — a fold rewind from `first_evict`: the chain returns to its state before that step. A rewind below what the
    /// ring reaches cannot be restored here: the spine is marked stale and the certified re-anchor settles it (the frontier's
    /// own rule, `rewind_fold_to_common`), never a chain left past the fork.
    pub(crate) fn canon_rewind_from(&mut self, first_evict: u64) {
        let Some(pos) = self.canon_rewind.iter().position(|(o, _)| *o >= first_evict) else { return };
        let (o, snap) = self.canon_rewind[pos];
        if o != first_evict && pos == 0 && canon_live() && self.canon_rewind.len() >= Self::REWIND_RETAIN {
            self.mark_spine_stale("the canonical chain's state before the fork point is past its rewind ring — the certified re-anchor settles it");
            return;
        }
        self.canon_rewind.truncate(pos);
        self.canon_restore(snap);
    }
}

impl crate::node::Node {
    /// ⭐ A-F114 U5 — what a checkpoint writes of the canonical chain, captured under the lock: the head, the slots of every
    /// record new or rewound since the last write that succeeded, the saved-top cell and the top this write makes current.
    /// `None` before the network upgrade (nothing is written on today's chain).
    pub(crate) fn capture_canon_ring(&self) -> Option<CanonRingCapture> {
        if !canon_live() {
            return None;
        }
        let fill = self.canon_fill.as_ref().map(|f| f.state);
        let (from, epoch) = self.canon_saved_top.get();
        let slots: Vec<(u64, Vec<u8>)> = if fill.is_some() {
            Vec::new()
        } else {
            self.canon_recent
                .range(from, usize::MAX)
                .iter()
                .filter_map(|(i, c, t, l, sc)| crate::persist::canon_slot(&(*i, *c, t.as_ref().clone(), l.as_ref().clone(), *sc)).map(|b| (*i, b)))
                .collect()
        };
        let head = (
            self.canon_index,
            self.canon_c,
            self.canon_missing,
            (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq),
            fill,
            self.canon_rewind.iter().copied().collect(),
            self.da_ord_top_for_canon(),
            self.canon_recent.window_digest(),
        );
        Some((head, slots, std::sync::Arc::clone(&self.canon_saved_top), epoch, if fill.is_some() { 0 } else { self.canon_index }))
    }

    /// ⭐ A-F114 U5 — resume the canonical chain from its ring file. The run read back must link record to record and end at
    /// the head's end, and reach the judged window (or the chain's start); otherwise the window is pulled from a peer
    /// against this node's own head (each record checked link by link back from it). The head was captured at a fold top: a
    /// head AHEAD of the resumed checkpoint is rolled back by its rewind ring; one BEHIND it cannot be brought forward here,
    /// so the spine is marked stale and the certified re-anchor settles it.
    /// What it trusts: this node's own resume point, exactly as the checkpoint beside it is trusted (the same kind of file,
    /// written in the same capture). The records are re-linked here, never taken on the file's word, and nothing read here
    /// is served to another node as authority: a joiner pulls a window and checks each record against a VOUCHED end.
    /// O1-INFINITY-REVIEWED: the read is one file of exactly CANON_RING_SLOTS fixed-width slots (~25 MB) and a head of a few KB; its size, its read time and the RAM it fills are f(CANON_RING_SLOTS, CANON_SLOT_BYTES), constants, at height 0 or 10^9 — never the chain's length, the spends or the notes.
    pub(crate) fn restore_canon_ring(&mut self, snapshot: &std::path::PathBuf) -> bool {
        let Some((head, run)) = crate::persist::load_canon_ring(snapshot) else { return false };
        let (index, c, missing, seqs, fill, rewind, fold_top, window) = head;
        self.canon_missing = missing;
        // ⭐ A-F139 — THE RING'S OWN LINKED PART, BEFORE ANY PEER IS ASKED. The run links record to record up to its first
        // break (`linked_len`); a state the head's rewind ring names (the chain before a recent fold step) that this linked
        // part reaches and ends at is a state this node held, so it resumes there and RE-FOLDS the steps after it from its
        // own blocks (`canon_resume_rewind`, taken by the fold's next pass), never waiting on a window pull a peer that is
        // pulling too can never serve (MEASURED live 06:38: both nodes pulling, the fold at 1562 for good). A head written
        // while a pull ran (fill) after such a resume carries that same rewind ring, so it recovers the same way; a pull
        // after a genuine adopt carries none (`adopt_certified_canon` clears it) and pulls as before.
        // S-WAIT: the pull stays only for a node with nothing of its own to stand on — a fresh joiner, whose peers hold it.
        let linked_len = run.iter().zip(run.iter().skip(1)).take_while(|(a, b)| record_step(&a.1, &b.2, &b.3, b.0) == b.1).count()
            + usize::from(!run.is_empty());
        let whole = linked_len == run.len() && run.last().map_or(index == 0, |e| e.0 + 1 == index && e.1 == c);
        // ⭐ A-F139 — and the run's linked SUFFIX that ends at the head's own end: the records after a stale stretch (a write a
        // rewind undid leaves the abandoned branch's slots in the middle; every slot written after it is this node's chain and
        // links to the head). MEASURED live 07:07 (origin, ring 25..1560 under head 1561): no rewind state was reached, so the
        // break is older than the rewind ring — the suffix is what the file still holds of the chain.
        let suffix_len = if run.last().is_some_and(|e| e.0 + 1 == index && e.1 == c) {
            1 + run.iter().rev().zip(run.iter().rev().skip(1)).take_while(|(b, a)| record_step(&a.1, &b.2, &b.3, b.0) == b.1).count()
        } else {
            0
        };
        let reach_of = |n: usize, at: u64| (n as u64) >= at.min(CANON_RECENT_RECORDS as u64);
        // ⭐ A-F139b — THE LINKED SUFFIX FIRST, FOR EVERY HEAD (a pull's included): records that step one into the next and end at
        // the head's own end ARE the chain's records (a forged one needs a Poseidon2 collision — the same test a pulled page passes,
        // `CanonFill::take`), and their scores are bound by the window digest the head vouches (a pull's vouched state's, else this
        // node's own at capture). MEASURED why (origin 07:23, binary a2136436): the head written while the first fix's pull ran had
        // an empty rewind ring, so the resume took it for a joiner's and pulled again — from a peer that was pulling too.
        let vouched = fill.map_or(window, |s| s.window);
        let from_suffix = (suffix_len > 0 && reach_of(suffix_len, index))
            .then(|| {
                let mut w = CanonRecent::default();
                for (i, e, t, l, sc) in run.iter().skip(run.len() - suffix_len) {
                    w.push(*i, *e, std::sync::Arc::new(t.clone()), std::sync::Arc::new(l.clone()), *sc);
                }
                w
            })
            .filter(|w| w.window_digest() == vouched);
        if !whole || fill.is_some() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: counts, the chain's own record indexes and one boolean only.
            eprintln!(
                "[resume] A-F139: ring {} record(s) {:?}..{:?} under head {index}: {linked_len} link from its start, {suffix_len} back \
                 from the head's end (from record {:?}); the judged window needs {}; suffix window digest {}; rewind ring {} state(s); \
                 pull under way {}",
                run.len(),
                run.first().map(|e| e.0),
                run.last().map(|e| e.0),
                run.len().checked_sub(suffix_len).and_then(|k| run.get(k)).map(|e| e.0),
                index.min(CANON_RECENT_RECORDS as u64),
                if from_suffix.is_some() { "matches the head's" } else { "absent or not the head's" },
                rewind.len(),
                fill.is_some()
            );
        }
        if from_suffix.is_none() {
            if let Some(state) = fill.filter(|_| rewind.is_empty()) {
                self.adopt_certified_canon(state);
                eprintln!("[resume] canonical chain: a window pull to record {} resumes", state.index);
                return true;
            }
        }
        // the newest rewind state the linked part ends at: `(records kept, position in the rewind ring)`
        let recover = if from_suffix.is_some() {
            None
        } else {
            rewind.iter().enumerate().rev().find_map(|(pos, (_, (at, end, _)))| {
                if *at == 0 {
                    return (*end == genesis()).then_some((0usize, pos));
                }
                let first = run.first()?.0;
                let p = usize::try_from((*at - 1).checked_sub(first)?).ok()?;
                (p < linked_len && run[p].1 == *end && reach_of(p + 1, *at)).then_some((p + 1, pos))
            })
        };
        self.canon_index = index;
        self.canon_c = c;
        (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq) = seqs;
        self.canon_recent = CanonRecent::default();
        self.canon_rewind = rewind.iter().copied().collect();
        let mut fold_top = fold_top;
        if let Some(w) = from_suffix {
            self.canon_recent = w;
            if whole {
                self.canon_saved_top.set(index);
                // DIGITAL-CASH-PRIVACY-REVIEWED: counts and the chain's own record index only.
                eprintln!("[resume] canonical chain at record {index} ({} records from the ring file)", self.canon_recent.len());
            } else {
                self.canon_saved_top.set(0); // every slot is rewritten at the next checkpoint (the stale stretch with them)
                // DIGITAL-CASH-PRIVACY-REVIEWED: counts and the chain's own record index only.
                eprintln!("[resume] A-F139: canonical chain at record {index} from the ring file's linked suffix ({} records) — no peer asked", self.canon_recent.len());
            }
        } else if let Some((keep, pos)) = recover {
            let (o, (at, end, rseqs)) = rewind[pos];
            for (i, e, t, l, sc) in run.into_iter().take(keep) {
                self.canon_recent.push(i, e, std::sync::Arc::new(t), std::sync::Arc::new(l), sc);
            }
            self.canon_index = at;
            self.canon_c = end;
            (self.canon_decoy_seq, self.canon_bounty_seq, self.canon_theft_seq) = rseqs;
            self.canon_rewind.truncate(pos);
            self.canon_saved_top.set(at); // the slots from `at` up are rewritten as the re-fold steps them
            fold_top = o.saturating_sub(1); // the state before fold step `o` is the chain at fold `o − 1`
            // DIGITAL-CASH-PRIVACY-REVIEWED: counts and the chain's own record and fold indexes only.
            eprintln!(
                "[resume] A-F139: {linked_len} of the ring file's records link (head {index}); kept {keep}, resumed at record \
                 {at}, the state before fold step {o} — the steps after it re-fold from this node's own blocks, no peer asked"
            );
        } else if let Some(state) = fill {
            self.canon_rewind.clear();
            self.adopt_certified_canon(state);
            eprintln!("[resume] canonical chain: a window pull to record {} resumes (the ring file reaches no rewind state)", state.index);
            return true;
        } else {
            let state = CanonState { index, c: digest_bytes(&c), window, seqs };
            let rw = std::mem::take(&mut self.canon_rewind);
            self.adopt_certified_canon(state);
            self.canon_rewind = rw;
            eprintln!("[resume] ⛔ canonical chain: the ring file does not hold a linked window to record {index} — pulled from a peer");
        }
        let top = self.da_ord_top_for_canon();
        if fold_top > top {
            self.canon_rewind_from(top.saturating_add(1));
            eprintln!("[resume] canonical chain captured at fold {fold_top}, the checkpoint at {top}: rolled back");
        } else if fold_top < top && self.canon_fill.is_none() {
            // ⭐ A-F139 — the chain this node holds stands at fold `fold_top`, the checkpoint further on: the fold re-folds
            // the steps after it from this node's own blocks (the fold's own rewind rule, `rewind_fold_to_common`, which
            // fails closed to the certified re-anchor when it cannot derive the prefix), never a peer asked first.
            self.canon_resume_rewind = Some(fold_top.saturating_add(1));
            eprintln!("[resume] canonical chain at fold {fold_top}, the checkpoint at {top}: the fold re-folds from step {}", fold_top + 1);
        } else if fold_top < top {
            self.mark_spine_stale("the canonical chain on disk is older than the checkpoint — the certified re-anchor settles it");
        }
        true
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ R4 — A PULLED BLOCK TRAVELS IN `PARTS` PIECES, ONE PER BULK LANE, AND IS JUDGED WHOLE.
//!
//! MEASURED 2026-11-02 (T5, four real two-node runs): from the 34th block on every block is ~1.4–1.5 MB on the wire, one
//! by-id pull moved it over ONE onion circuit at 79–178 KB/s (8–25 s per block), and a producer spaces itself to the relay
//! floor, so the real pair ran at ~41 s per block per node. The transport already holds `BULK_LANES_PER_HOST` isolated
//! circuits per host (`acquire_bulk_lane` takes any free one), so the same block asked as `PARTS` byte ranges crosses
//! them in parallel. Borrowed shape: BitTorrent's piece fetch from one peer over several connections, and this tree's own
//! release chunks (`release.rs`, kind 23) — `[kind][content id][index]` out, `TAG ‖ id ‖ index ‖ …` back.
//!
//! The ask is `[25][block id 32][part u8]` (34 bytes); the answer is `BLOCKPRT ‖ id ‖ part ‖ total u32 ‖ bytes`, the
//! `part`-th of `PARTS` equal ranges of the block's gossip encoding (`block::gossip_encode`, the bytes a by-id pull
//! carries); `BLOCKPRT ‖ id ‖ part` alone is the `notfound`. A part carries no verdict of its own: the puller joins the
//! `PARTS` ranges, decodes the block and requires its id to be the one it asked for, then hands it to the SAME door a
//! whole by-id pull enters (`NodeRuntime::on_pulled_tip_block`: PoW, the off-lock verifier, ingest).
//!
//! §9.6 — the new ingress path: (1) PoW is verified by the door the joined block enters (`on_pulled_tip_block` refuses an
//! empty witness and hands the block to the off-lock PoW/ingest verifier), exactly as a whole by-id pull; (2) the block's
//! own proofs are verified there too — a part is never applied; (3) value: a part cannot create value, it is bytes until
//! the joined block passes every gate the by-id door runs; (4) replay: a block already held is a no-op at that door, the
//! assembly ring keys each id once; (5) work bound: an answer is at most `BULK_FRAME_MAX`, a part's range is fixed by the
//! total it names (checked equal across parts), the assembly ring holds at most `ASSEMBLY_RING` ids; (6) parity with the
//! kind-12 by-id door it parallels: same serve source (`full_block_by_id` → `gossip_encode`), same ingest door, and one
//! more check — the joined block's id must equal the asked id (a whole by-id answer is judged by whatever it is).
//! DIGITAL-CASH-PRIVACY-REVIEWED: an ask names a block id the asker heard announced and a part index — public chain data,
//! the same as a kind-12 ask — and no account, note, amount or holder.

/// The bulk-lane ask kind: `[25][id 32][part u8]`.
pub const BULK_REQ_KIND_BLOCK_PART: u8 = 25;
/// The answer tag.
pub const BLOCK_PART_TAG: &[u8; 8] = b"BLOCKPRT";
/// ⭐ C1 (SPEED, 2026-11-12) — the COMPACT part ask, `[29][id 32][part u8]`: the same block, the same parts, cut from
/// [`crate::block::gossip_encode_compact`] (each carried spend transaction named by its id, BIP152's compact block) instead
/// of [`crate::block::gossip_encode`]. The puller fills the named transactions from its own pool and, on a miss, asks the
/// full form (kind 25) — so a compact join and a full join of one id never share parts ([`Assemblies::open_as`]).
/// §9.6: the joined bytes enter the SAME door a kind-25 join enters, after `gossip_decode_compact` has rebuilt the carried
/// list and found it to be the one the block id commits; every check of that door runs on those bytes (1–6 as kind 25's).
/// DIGITAL-CASH-PRIVACY-REVIEWED: an ask names an announced block id and a part index — public chain data, as kind 25.
pub const BULK_REQ_KIND_BLOCK_PART_COMPACT: u8 = 29;
/// The compact answer's tag.
pub const BLOCK_PART_COMPACT_TAG: &[u8; 8] = b"BLOCKPRC";
/// Parts per block: one per bulk lane the transport holds per host.
pub const PARTS: usize = crate::arti_transport::BULK_LANES_PER_HOST;
/// The assembly ring's depth: the by-id slot's in-flight cap over `PARTS` (whole blocks in flight at once), doubled for
/// the ones whose last part is still on the wire. A constant of the transport, never of the chain.
pub const ASSEMBLY_RING: usize = 4;

/// The kind-25 ask for part `part` of block `id`.
#[must_use]
pub fn ask(id: &[u8; 32], part: u8) -> Vec<u8> {
    ask_as(id, part, false)
}

/// The part ask in either form: kind 25 (full) or kind 29 (`compact`).
#[must_use]
pub fn ask_as(id: &[u8; 32], part: u8, compact: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(34);
    v.push(if compact { BULK_REQ_KIND_BLOCK_PART_COMPACT } else { BULK_REQ_KIND_BLOCK_PART });
    v.extend_from_slice(id);
    v.push(part);
    v
}

/// Is `req` a kind-25 ask? `Some((id, part))`, the part in range.
#[must_use]
pub fn parse_ask(req: &[u8]) -> Option<([u8; 32], u8)> {
    parse_ask_any(req).and_then(|(id, part, compact)| (!compact).then_some((id, part)))
}

/// Is `req` a part ask of either form? `Some((id, part, compact))`, the part in range.
#[must_use]
pub fn parse_ask_any(req: &[u8]) -> Option<([u8; 32], u8, bool)> {
    if req.len() != 34 || usize::from(req[33]) >= PARTS {
        return None;
    }
    let compact = match req[0] {
        BULK_REQ_KIND_BLOCK_PART => false,
        BULK_REQ_KIND_BLOCK_PART_COMPACT => true,
        _ => return None,
    };
    Some((<[u8; 32]>::try_from(&req[1..33]).ok()?, req[33], compact))
}

/// The byte range of part `part` of a `total`-byte block: `PARTS` equal ranges, the last one short.
#[must_use]
pub fn range(total: usize, part: u8) -> core::ops::Range<usize> {
    let step = total.div_ceil(PARTS);
    let lo = (usize::from(part) * step).min(total);
    lo..(lo + step).min(total)
}

/// The answer page for part `part` of `id`, given the block's gossip bytes (`None` = the `notfound`).
#[must_use]
pub fn encode_answer(id: &[u8; 32], part: u8, bytes: Option<&[u8]>) -> Vec<u8> {
    encode_answer_as(id, part, bytes, false)
}

/// [`encode_answer`] in either form; the tag names the form (`BLOCKPRT` full, `BLOCKPRC` compact).
#[must_use]
pub fn encode_answer_as(id: &[u8; 32], part: u8, bytes: Option<&[u8]>, compact: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 33 + bytes.map_or(0, |b| 4 + range(b.len(), part).len()));
    v.extend_from_slice(if compact { BLOCK_PART_COMPACT_TAG } else { BLOCK_PART_TAG });
    v.extend_from_slice(id);
    v.push(part);
    if let Some(b) = bytes {
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend_from_slice(&b[range(b.len(), part)]);
    }
    v
}

/// One decoded answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartAnswer {
    pub id: [u8; 32],
    pub part: u8,
    pub total: usize,
    pub bytes: Vec<u8>,
    /// The form the answer's tag named (C1): a part lands only in a join of its own form.
    pub compact: bool,
}

/// Decode an answer page (after its tag). `Ok(None)` = the `notfound`; `Err` = malformed: a part out of range, a total
/// past the bulk frame, or a slice that is not exactly the range the total names.
pub fn decode_answer(body: &[u8]) -> Result<Option<PartAnswer>, ()> {
    if body.len() < 33 {
        return Err(());
    }
    let id = <[u8; 32]>::try_from(&body[..32]).map_err(|_| ())?;
    let part = body[32];
    if usize::from(part) >= PARTS {
        return Err(());
    }
    if body.len() == 33 {
        return Ok(None);
    }
    let rest = &body[33..];
    if rest.len() < 4 {
        return Err(());
    }
    let total = u32::from_le_bytes(rest[..4].try_into().map_err(|_| ())?) as usize;
    if total == 0 || total > crate::arti_transport::BULK_FRAME_MAX || rest.len() - 4 != range(total, part).len() {
        return Err(());
    }
    Ok(Some(PartAnswer { id, part, total, bytes: rest[4..].to_vec(), compact: false }))
}

/// One block being joined from its parts.
#[derive(Clone, Debug)]
struct Assembly {
    id: [u8; 32],
    total: usize,
    parts: Vec<Option<Vec<u8>>>,
    /// when its parts were last asked for (the puller's clock): a join is LIVE for `stale_ms` after that
    asked_ms: u64,
    /// C1: the form its parts are cut from (`gossip_encode_compact` when true): one form per join, never mixed.
    compact: bool,
}

/// How many joins may be LIVE at once: the by-id lane's own width (`BULK_BY_ID_INFLIGHT` part asks in flight, `PARTS`
/// per block). One more would be a join whose asks the lane refuses.
pub const LIVE_JOINS: usize = crate::arti_transport::BULK_BY_ID_INFLIGHT / PARTS;
const _: () = assert!(LIVE_JOINS >= 1 && LIVE_JOINS <= ASSEMBLY_RING);

/// The puller's joins in flight: at most `ASSEMBLY_RING` blocks held, at most `LIVE_JOINS` of them live. Process-local
/// scratch for bytes in transit, never node state: nothing here is read by a door, persisted or served.
///
/// ⛔⭐ A JOIN STILL RECEIVING IS NEVER DROPPED FOR A NEWER PULL (2026-11-10). The ring used to drop its OLDEST join
/// whenever a fifth was opened, and a join was opened before its asks were sent — so a pull the lane then REFUSED
/// (its 8 asks in flight are 2 blocks) still pushed a live join out. MEASURED on two real nodes: a joiner 18 blocks
/// behind fetched 510 block parts (131 MB) and joined 10 blocks from them; every other part landed on a join that was
/// gone, the block was asked for again 30 s later, and the lanes carried 16 to 22 copies of each block while the node
/// fell 40 further behind. The landed binary shows the same loss at a lower rate (24 pulls, 6 blocks joined; 2.5 to
/// 4.2 MB fetched per 1.2 MB block in every earlier run).
/// Now a new join opens only while fewer than `LIVE_JOINS` are live — live = asked within `stale_ms`, the by-id
/// re-ask interval, after which its id may be asked again anyway — and the join that gives way when the ring is full
/// is the one asked longest ago, which is then stale. A pull that finds no room is refused BEFORE anything is sent,
/// and its caller's own lane rule takes the block (the GETDATA page, or the next round), as for any refused ask.
/// BORROWED: Bitcoin Core's `mapBlocksInFlight` with `MAX_BLOCKS_IN_TRANSIT_PER_PEER` — a block is requested only
/// while a download slot is free, and a slot is freed by arrival or by its timeout, never by the next request.
/// cons: none — the same four slots; a pull that would have evicted a live join waits for one of two to finish.
#[derive(Clone, Debug, Default)]
pub struct Assemblies {
    ring: Vec<Assembly>,
}

impl Assemblies {
    /// Note that `id` is being pulled at `now_ms`, so its parts have a join to land in. `false` = no room: `LIVE_JOINS`
    /// joins were asked within `stale_ms` and are still receiving; nothing is opened and nothing is dropped. An id
    /// already being joined keeps the parts it has and is live again (its missing parts are what the re-ask names).
    #[must_use]
    pub fn open(&mut self, id: [u8; 32], now_ms: u64, stale_ms: u64) -> bool {
        self.open_as(id, now_ms, stale_ms, false)
    }

    /// [`Self::open`] in a form (C1). An id already being joined in the OTHER form starts over in this one (its parts are
    /// cut from other bytes, so none of them can land here); in the same form it keeps its parts, as `open` does.
    #[must_use]
    pub fn open_as(&mut self, id: [u8; 32], now_ms: u64, stale_ms: u64, compact: bool) -> bool {
        if let Some(a) = self.ring.iter_mut().find(|a| a.id == id) {
            if a.compact != compact {
                *a = Assembly { id, total: 0, parts: vec![None; PARTS], asked_ms: now_ms, compact };
            }
            a.asked_ms = now_ms;
            return true;
        }
        let live = self.ring.iter().filter(|a| now_ms.saturating_sub(a.asked_ms) < stale_ms).count();
        if live >= LIVE_JOINS {
            return false;
        }
        if self.ring.len() >= ASSEMBLY_RING {
            // fewer than LIVE_JOINS of ASSEMBLY_RING are live, so the one asked longest ago is stale
            let oldest = self.ring.iter().enumerate().min_by_key(|(_, a)| a.asked_ms).map_or(0, |(i, _)| i);
            self.ring.remove(oldest);
        }
        self.ring.push(Assembly { id, total: 0, parts: vec![None; PARTS], asked_ms: now_ms, compact });
        true
    }

    /// The asks for `id` never left (the lane refused every one): a join nothing is coming for holds no slot. A join
    /// that already holds a part stays — its earlier asks did leave.
    pub fn close_unasked(&mut self, id: &[u8; 32]) {
        self.ring.retain(|a| a.id != *id || a.parts.iter().any(Option::is_some));
    }

    /// How many joins are LIVE at `now_ms`: asked within `stale_ms` (the by-id re-ask interval) — blocks this node was told
    /// exist and is receiving now. At `LIVE_JOINS` every download slot is busy. Read by this node's own production timer
    /// (`NodeRuntime::behind_peers`, A-F60); no door reads it.
    #[must_use]
    pub fn live(&self, now_ms: u64, stale_ms: u64) -> usize {
        self.ring.iter().filter(|a| now_ms.saturating_sub(a.asked_ms) < stale_ms).count()
    }

    /// Is `id` being joined?
    #[must_use]
    pub fn is_open(&self, id: &[u8; 32]) -> bool {
        self.ring.iter().any(|a| a.id == *id)
    }

    /// The form `id` is being joined in (`None` when it is not being joined).
    #[must_use]
    pub fn form(&self, id: &[u8; 32]) -> Option<bool> {
        self.ring.iter().find(|a| a.id == *id).map(|a| a.compact)
    }

    /// Land one answer. `Some(bytes)` = every part arrived and they join to `total` bytes (the join is closed);
    /// `None` = still waiting, or the answer was refused: a part for a block not being joined, a total that disagrees
    /// with the parts already landed, or a part already held (one copy of each range — the first).
    pub fn land(&mut self, a: PartAnswer) -> Option<Vec<u8>> {
        let at = self.ring.iter().position(|x| x.id == a.id)?;
        let join = &mut self.ring[at];
        if join.compact != a.compact || (join.total != 0 && join.total != a.total) {
            return None;
        }
        join.total = a.total;
        let slot = &mut join.parts[usize::from(a.part)];
        if slot.is_some() {
            return None;
        }
        *slot = Some(a.bytes);
        if join.parts.iter().any(Option::is_none) {
            return None;
        }
        let join = self.ring.remove(at);
        let bytes: Vec<u8> = join.parts.into_iter().flatten().flatten().collect();
        (bytes.len() == join.total).then_some(bytes)
    }

    /// The parts of `id` not yet landed (the re-ask names only these).
    #[must_use]
    pub fn missing(&self, id: &[u8; 32]) -> Vec<u8> {
        self.ring
            .iter()
            .find(|a| a.id == *id)
            .map_or_else(|| (0..PARTS as u8).collect(), |a| (0..PARTS as u8).filter(|&k| a.parts[usize::from(k)].is_none()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranges tile the block exactly, an answer round-trips, and every malformed answer is refused: a part out of
    /// range, a total past the frame, a slice longer or shorter than its range.
    #[test]
    fn r4_block_parts_tile_the_block_and_a_malformed_answer_is_refused() {
        for total in [1usize, 3, 4, 5, 1_000, 1_379_520] {
            let joined: Vec<usize> = (0..PARTS as u8).flat_map(|k| range(total, k)).collect();
            assert_eq!(joined, (0..total).collect::<Vec<_>>(), "the parts tile a {total}-byte block exactly once");
        }
        let id = [7u8; 32];
        let bytes: Vec<u8> = (0..10_001u32).map(|i| i as u8).collect();
        for k in 0..PARTS as u8 {
            let page = encode_answer(&id, k, Some(&bytes));
            assert_eq!(&page[..8], BLOCK_PART_TAG);
            let a = decode_answer(&page[8..]).expect("well formed").expect("an answer");
            assert_eq!((a.id, a.part, a.total), (id, k, bytes.len()));
            assert_eq!(a.bytes, bytes[range(bytes.len(), k)].to_vec());
        }
        assert_eq!(decode_answer(&encode_answer(&id, 1, None)[8..]), Ok(None), "the notfound");
        assert_eq!(parse_ask(&ask(&id, 3)), Some((id, 3)));
        assert_eq!(parse_ask(&ask(&id, PARTS as u8)), None, "an ask for a part out of range");
        let mut long = encode_answer(&id, 0, Some(&bytes));
        long.push(0);
        assert!(decode_answer(&long[8..]).is_err(), "a slice longer than its range");
        let mut short = encode_answer(&id, 0, Some(&bytes));
        short.pop();
        assert!(decode_answer(&short[8..]).is_err(), "a slice shorter than its range");
        let mut bad_part = encode_answer(&id, 0, Some(&bytes));
        bad_part[8 + 32] = PARTS as u8;
        assert!(decode_answer(&bad_part[8..]).is_err(), "a part out of range");
        let mut huge = encode_answer(&id, 0, None);
        huge.extend_from_slice(&((crate::arti_transport::BULK_FRAME_MAX + 1) as u32).to_le_bytes());
        assert!(decode_answer(&huge[8..]).is_err(), "a total past the bulk frame");
    }

    /// The join: parts land in any order and join to the block; a part for a block not being joined, a second copy of a
    /// part, and a part whose total disagrees are refused; the ring holds at most `ASSEMBLY_RING` blocks.
    #[test]
    fn r4_block_parts_join_in_any_order_and_a_stray_or_disagreeing_part_is_refused() {
        let id = [9u8; 32];
        let bytes: Vec<u8> = (0..4_097u32).map(|i| (i * 7) as u8).collect();
        let answer = |k: u8| decode_answer(&encode_answer(&id, k, Some(&bytes))[8..]).unwrap().unwrap();
        let mut joins = Assemblies::default();
        assert_eq!(joins.land(answer(0)), None, "a part for a block not being joined is refused");
        assert!(joins.open(id, 1_000, STALE));
        assert_eq!(joins.missing(&id), (0..PARTS as u8).collect::<Vec<_>>());
        let order: Vec<u8> = (0..PARTS as u8).rev().collect();
        for (n, &k) in order.iter().enumerate() {
            let got = joins.land(answer(k));
            if n + 1 < PARTS {
                assert_eq!(got, None, "waiting for the other parts");
                assert_eq!(joins.land(answer(k)), None, "a second copy of a part is refused");
            } else {
                assert_eq!(got, Some(bytes.clone()), "every part landed: the block joins whole");
            }
        }
        assert!(!joins.is_open(&id), "a joined block leaves the ring");
        assert!(joins.open(id, 2_000, STALE));
        let mut liar = answer(1);
        liar.total += 1;
        let _ = joins.land(answer(0));
        assert_eq!(joins.land(liar), None, "a part whose total disagrees with the landed parts is refused");
        // one new pull per stale interval, far more of them than slots: the ring stays a constant size
        for i in 0..(ASSEMBLY_RING as u8 + 3) {
            assert!(joins.open([i; 32], 2_000 + STALE * (u64::from(i) + 1), STALE), "a pull whose predecessors are all stale has room");
        }
        assert_eq!(joins.ring.len(), ASSEMBLY_RING, "the ring holds a constant number of joins");
    }

    const STALE: u64 = 30_000;

    /// ⭐ A JOIN STILL RECEIVING IS NEVER DROPPED FOR A NEWER PULL — the loss two real nodes measured (2026-11-10: 510
    /// parts fetched, 10 blocks joined). `LIVE_JOINS` blocks are being pulled and each holds some of its parts:
    /// (1) every further pull inside the stale interval is refused, opens nothing and drops nothing — CALIBRATION: the
    ///     replaced rule (open always, drop the oldest when the ring is full) loses the first block after
    ///     `ASSEMBLY_RING − LIVE_JOINS + 1` such pulls, shown here on the same sequence;
    /// (2) both blocks then join whole from their remaining parts;
    /// (3) a pull the lane refused outright (no part ever landed) is closed and holds no slot;
    /// (4) a join asked longer ago than the stale interval no longer holds a new pull back, keeps the parts it has, and
    ///     still joins when its last part lands late — and an id asked again is live again with its parts kept.
    #[test]
    fn speed_a_join_still_receiving_is_never_dropped_for_a_newer_pull() {
        let block = |seed: u8| -> ([u8; 32], Vec<u8>) { ([seed; 32], (0..5_003u32).map(|i| (i as u8).wrapping_mul(seed)).collect()) };
        let part = |b: &([u8; 32], Vec<u8>), k: u8| decode_answer(&encode_answer(&b.0, k, Some(&b.1))[8..]).unwrap().unwrap();
        let live: Vec<([u8; 32], Vec<u8>)> = (1..=LIVE_JOINS as u8).map(block).collect();
        // CALIBRATION — the replaced rule on this sequence
        let mut replaced: Vec<[u8; 32]> = live.iter().map(|b| b.0).collect();
        let newer = ASSEMBLY_RING - LIVE_JOINS + 1;
        for i in 0..newer as u8 {
            if replaced.len() >= ASSEMBLY_RING {
                replaced.remove(0);
            }
            replaced.push([0xA0 + i; 32]);
        }
        assert!(!replaced.contains(&live[0].0), "CALIBRATION: under the replaced rule {newer} newer pull(s) dropped the first live join");
        // (1)
        let mut joins = Assemblies::default();
        for b in &live {
            assert!(joins.open(b.0, 10_000, STALE));
            assert_eq!(joins.land(part(b, 0)), None, "one part of {PARTS} landed");
        }
        for i in 0..(2 * ASSEMBLY_RING) as u8 {
            assert!(!joins.open([0xA0 + i; 32], 10_000 + u64::from(i), STALE), "⛔⛔ a pull opened while {LIVE_JOINS} joins are still receiving");
        }
        assert_eq!(joins.ring.len(), LIVE_JOINS, "⛔ a refused pull left a join behind");
        // (2)
        for b in &live {
            for k in 1..PARTS as u8 {
                let got = joins.land(part(b, k));
                assert_eq!(got.is_some(), usize::from(k) + 1 == PARTS, "⛔⛔ a part of a block still being joined was refused");
                if let Some(bytes) = got {
                    assert_eq!(bytes, b.1, "the joined bytes are the block's");
                }
            }
        }
        // (3)
        let refused = [0xB1u8; 32];
        assert!(joins.open(refused, 20_000, STALE), "room again once the live joins finished");
        joins.close_unasked(&refused);
        assert!(!joins.is_open(&refused), "⛔ a pull whose asks never left still holds a slot");
        // (4)
        let slow = block(0x51);
        assert!(joins.open(slow.0, 30_000, STALE));
        let _ = joins.land(part(&slow, 2));
        joins.close_unasked(&slow.0);
        assert!(joins.is_open(&slow.0), "⛔ a join that holds a part was closed as never asked");
        for i in 0..(LIVE_JOINS as u8 - 1) {
            assert!(joins.open([0xC0 + i; 32], 30_000, STALE));
        }
        assert!(!joins.open([0xCF; 32], 30_000 + STALE - 1, STALE), "CALIBRATION: inside the stale interval the slow join still holds its place");
        assert!(joins.open([0xCF; 32], 30_000 + STALE, STALE), "⛔ a join asked a whole stale interval ago still held a new pull back");
        assert!(joins.is_open(&slow.0), "⛔ a stale join was dropped while the ring had room");
        assert!(joins.open(slow.0, 30_000 + STALE + 5, STALE), "asked again: the same join");
        assert_eq!(joins.missing(&slow.0), (0..PARTS as u8).filter(|k| *k != 2).collect::<Vec<_>>(), "⛔ a re-asked join lost the part it held");
        let mut whole = None;
        for k in (0..PARTS as u8).filter(|k| *k != 2) {
            whole = joins.land(part(&slow, k));
        }
        assert_eq!(whole, Some(slow.1.clone()), "⛔ a join re-asked after its stale interval did not join from its late parts");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ DB-358 — WHICH OF TWO SPENDS OF ONE NULLIFIER COUNTS. First in canonical order, decided at the record fold
//! (docs/DB-358-THE-BLOCK-PATH-CREDITS-A-RESPENT-NULLIFIER.md §5b-§5c).
//!
//! MEASURED (RED, `a_peer_refuses_a_second_spend_of_one_nullifier_carried_in_a_later_block`): the block path credited
//! a second spend of an already-spent nullifier. A sparse insert of a key the view already holds is a no-op, so the
//! lane cannot tell a replay from a fresh spend, and only the POOL door refused, which a producer never passes.
//!
//! BORROWED SHAPE (Kaspa, Bitcoin): transactions are accepted in the canonical order, and one whose input an earlier
//! accepted transaction consumed is simply not accepted. No block is rejected for it. The verdict is a function of the
//! canonical order and the block's own carried lane, so every node reaches the same one.
//!
//! This module is the RULE, pure and table-tested. The node supplies ONE thing: what its canonical fold-point set
//! `S_b` says about a tag at block `b`'s fold — held, not held, or undecidable here (DB-353 §13.6). It decides nothing
//! else. Work is per decided block and bounded by that block's own items; nothing here reads history.
//!
//! ⭐ DB-353 §13.6 (2026-09-30): the decision reads `S_b` = the held view (every applied band step) ∪ the admitted set of
//! every step noted before `b`. Every earlier block in fold order is noted by the time `b` folds, so `S_b` is the same
//! on every node holding the same bodies. It replaced the graft-time FIRST-CONTACT MEMO and the CLAIMS map — both
//! ARRIVAL facts, which is why a DSYNC joiner's carried window (DB-358 r3) and a reorg past the fold lag (r4) could be
//! decided differently on two nodes.

use std::collections::HashSet;

/// A nullifier-lane tag.
pub type Tag = [u8; 32];
/// An output note commitment (the record's key for a note).
pub type Cm = [u8; 32];

/// ⛔ DB-358 (1): which door asks a spend's named-record membership question.
/// ([`crate::node::Node::verify_membership_carrier_one_step`]). Every caller must name one, so the compiler holds the
/// census.
/// * `Admit`: a pool or service door deciding what THIS node takes in. It also requires the named record to be FOLDED
///   here. A staged record can still lose outputs at the fold, so a spend of one is refused until the fold settles it.
///   The refusal is a wait, never a verdict.
/// * `Fold`: a class object applying at its block's canonical FOLD (a USDm bond, an asset transfer, a yield claim). The
///   named record must be folded BEFORE this block, i.e. earlier in the canonical order every node folds in. So the
///   verdict is the order's, identical on every node, and never "does this node happen to hold the record". The old
///   `Graft` door asked only the latter, and a record whose block folds after the object's was accepted by a node that
///   had grafted it and refused by one that had not: two validator sets from one chain (MEASURED,
///   `a_fold_door_membership_verdict_is_the_same_on_a_node_holding_an_unfolded_record_and_one_without_it`). A refusal
///   here is final for the object; the block still folds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberDoor {
    Admit,
    Fold,
}

/// One nullifier-revealing item of a block: every tag it retires and every output note it credits. A multi-input
/// spend retires several tags. One spent by any earlier item consumes the whole item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub tags: Vec<Tag>,
    pub outputs: Vec<Cm>,
    /// ⛔ A-F22 (2026-11-11) — WHICH ITEM, never which tag: a class object's carriage hash (`Hash32::hash` of its framed bytes),
    /// `None` for a stated spend. The object fold names the objects that LOST by this key. Naming them by tag was the hole: the
    /// contested tag belongs to the winner too, so the winning object was skipped as a "loser", applied nothing, and its
    /// occurrence of the tag stayed admitted — the note was spent and nothing came back (MEASURED by lane goods on three real
    /// nodes, main ff11315e: a cold restore of the paying wallet read atomic 0).
    pub key: Option<[u8; 32]>,
}

/// ⛔ DB-358 increment 2: the fold-time respend state a CHECKPOINT keeps — since DB-353 §13.6 only what a REWIND needs.
///
/// The journal puts a revoked note back at its row position when a rewind hands its block back to the fold, and the
/// reach is the ordinal ring the journal is released against. The first-contact memos and the claims that used to ride
/// here are GONE: they were ARRIVAL facts, and the decision now reads the canonical fold-point set, which a resumed
/// node rebuilds from its own view and band door.
///
/// It rides the checkpoint's fold-record trailer (`persist::FoldRecord`), written at the same instant as the
/// accumulator it describes, and never a DSYNC bundle. Every list is in a canonical order, so one state has one
/// encoding. Bound: journal entries for real conflicts only (empty on an honest chain), and the reach ring
/// (`SPINE_RING_LEN`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RespendCarry {
    /// `(block, its record address, its revoked (row position, note bytes))`, ascending by block.
    pub journal: Vec<([u8; 32], u64, Vec<(u64, Vec<u8>)>)>,
    /// `(ordinal, block)` of each fold step a rewind can still reach, oldest first.
    pub reach: Vec<(u64, [u8; 32])>,
}

/// The v2 carry's leading word. A v1 carry opens with its memo COUNT, and `u32::MAX` memos can never fit the bytes
/// behind them (the decoder's remaining-length check refuses it), so the marker cannot be mistaken for a v1 carry.
const CARRY_V2: u32 = u32::MAX;

impl RespendCarry {
    /// True when there is nothing to carry. The checkpoint then writes the fold record's pre-increment-2 bytes exactly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.journal.is_empty() && self.reach.is_empty()
    }

    /// Fixed-width little-endian, the fold record's own style. The encoding is total (no serializer that can fail), and
    /// every list is length-prefixed. v2 (DB-353 §13.6):
    /// `[u32 CARRY_V2]`, `journal: n × [block32][u64 addr][u32 k][k × ([u64 pos][u32 len][len bytes])]`,
    /// `reach: n × [u64 ordinal][block32]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&CARRY_V2.to_le_bytes());
        v.extend_from_slice(&(self.journal.len() as u32).to_le_bytes());
        for (id, addr, revoked) in &self.journal {
            v.extend_from_slice(id);
            v.extend_from_slice(&addr.to_le_bytes());
            v.extend_from_slice(&(revoked.len() as u32).to_le_bytes());
            for (pos, note) in revoked {
                v.extend_from_slice(&pos.to_le_bytes());
                v.extend_from_slice(&(note.len() as u32).to_le_bytes());
                v.extend_from_slice(note);
            }
        }
        v.extend_from_slice(&(self.reach.len() as u32).to_le_bytes());
        for (o, id) in &self.reach {
            v.extend_from_slice(&o.to_le_bytes());
            v.extend_from_slice(id);
        }
        v
    }

    /// The exact inverse of [`Self::encode`]. `None` on any short read or trailing byte, so a corrupt segment is
    /// refused whole, never half-read. Every count is checked against the bytes that remain before anything is
    /// allocated, so a forged count cannot make it allocate.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        struct R<'a>(&'a [u8]);
        impl<'a> R<'a> {
            fn take(&mut self, n: usize) -> Option<&'a [u8]> {
                if self.0.len() < n {
                    return None;
                }
                let (h, t) = self.0.split_at(n);
                self.0 = t;
                Some(h)
            }
            fn u32(&mut self) -> Option<usize> {
                Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
            }
            fn u64(&mut self) -> Option<u64> {
                Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
            }
            fn b32(&mut self) -> Option<[u8; 32]> {
                self.take(32)?.try_into().ok()
            }
            /// A count of items at least `min` bytes each, refused if the rest could not hold them.
            fn count(&mut self, min: usize) -> Option<usize> {
                let n = self.u32()?;
                (n.checked_mul(min)? <= self.0.len()).then_some(n)
            }
            fn tags(&mut self) -> Option<Vec<Tag>> {
                let n = self.count(32)?;
                (0..n).map(|_| self.b32()).collect()
            }
        }
        let mut r = R(b);
        let revoked_list = |r: &mut R<'_>| -> Option<Vec<(u64, Vec<u8>)>> {
            let k = r.count(12)?;
            (0..k)
                .map(|_| {
                    let pos = r.u64()?;
                    let len = r.u32()?;
                    Some((pos, r.take(len)?.to_vec()))
                })
                .collect()
        };
        let mut peek = R(b);
        if peek.u32()? == CARRY_V2 as usize {
            r.u32()?;
            let n = r.count(32 + 8 + 4)?;
            let journal = (0..n)
                .map(|_| Some((r.b32()?, r.u64()?, revoked_list(&mut r)?)))
                .collect::<Option<Vec<_>>>()?;
            let n = r.count(8 + 32)?;
            let reach = (0..n).map(|_| Some((r.u64()?, r.b32()?))).collect::<Option<Vec<_>>>()?;
            return r.0.is_empty().then_some(RespendCarry { journal, reach });
        }
        // A v1 carry (a checkpoint written before DB-353 §13.6): read it WHOLE, so damage is still refused, and DISCARD
        // its arrival facts — the memos, the claims, each journal entry's claimed tags and the reach's lane keys. The
        // decision no longer reads them; the journal and the reach it keeps are exactly what a rewind needs.
        let n = r.count(32 + 8)?;
        for _ in 0..n {
            r.b32()?;
            r.tags()?;
            r.tags()?;
        }
        let n = r.count(64)?;
        for _ in 0..n {
            r.b32()?;
            r.b32()?;
        }
        let n = r.count(32 + 8 + 8)?;
        let journal = (0..n)
            .map(|_| {
                let id = r.b32()?;
                let addr = r.u64()?;
                r.tags()?;
                Some((id, addr, revoked_list(&mut r)?))
            })
            .collect::<Option<Vec<_>>>()?;
        let n = r.count(8 + 64)?;
        let reach = (0..n)
            .map(|_| {
                let o = r.u64()?;
                let id = r.b32()?;
                r.b32()?;
                Some((o, id))
            })
            .collect::<Option<Vec<_>>>()?;
        r.0.is_empty().then_some(RespendCarry { journal, reach })
    }
}

/// A block's verdict at its fold (DB-353 §13.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldVerdict {
    /// Every item decided. `revoke`: the outputs of every LOSING item — they leave the block's staged row before the
    /// fold assigns it a position, so they never reach the spine. `losers`: those items' tags — they leave the step's
    /// ADMITTED set, so a loser's input is never burned (DB-358 r5). Both empty on an honest chain.
    /// `lost_keys`: the `key` of every LOSING item that has one (a class object), once per losing occurrence, in item order.
    Decided { revoke: Vec<Cm>, losers: Vec<Tag>, lost_keys: Vec<[u8; 32]> },
    /// An item is UNDECIDABLE here: nothing says it lost, and one of its tags is one this node's fold-point set cannot
    /// answer (a step noted before the block is UNKNOWN — its body was not held at its fold — the door is stale past a
    /// gap, or the held view does not cover the tag's shard). The canonical fold pass stops BEFORE the block and
    /// resumes when the set becomes answerable. Never an exclusion, never an admission on a guess.
    Wait,
}

/// ⭐ DB-353 §13.6 — decide block `b`'s items at its fold over the canonical fold-point set `S_b`, in the block's own
/// item order. `in_fold_point_set(t)`: `Some(true)` = `S_b` holds t (spent by an earlier block in canonical order),
/// `Some(false)` = it provably does not, `None` = undecidable on this node.
///
/// An item LOSES iff one of its tags is in `S_b`, or was spent by an EARLIER item of this block (one block, one spend
/// of a tag, first in the block's order); a single consumed tag consumes the whole item. It WAITS iff nothing decides
/// it lost and one of its tags is undecidable. Otherwise it WINS, and its tags join the block's spent-here set.
///
/// The verdict is a function of `S_b` and the block's own items, so every node holding the same bodies reaches it,
/// whatever order it grafted them in. An honest block (no contest) revokes nothing and records nothing.
#[must_use]
pub fn decide_at_fold(items: &[Item], in_fold_point_set: impl Fn(&Tag) -> Option<bool>) -> FoldVerdict {
    let mut spent_here: HashSet<Tag> = HashSet::new();
    let mut revoke: Vec<Cm> = Vec::new();
    let mut losers: Vec<Tag> = Vec::new();
    let mut lost_keys: Vec<[u8; 32]> = Vec::new();
    for item in items {
        let mut undecidable = false;
        let lost = item.tags.iter().any(|t| {
            if spent_here.contains(t) {
                return true;
            }
            match in_fold_point_set(t) {
                Some(held) => held,
                None => {
                    undecidable = true;
                    false
                }
            }
        });
        if lost {
            revoke.extend(item.outputs.iter().copied());
            losers.extend(item.tags.iter().copied());
            lost_keys.extend(item.key);
            continue;
        }
        if undecidable {
            return FoldVerdict::Wait;
        }
        spent_here.extend(item.tags.iter().copied());
    }
    FoldVerdict::Decided { revoke, losers, lost_keys }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn tag(b: u8) -> Tag {
        [b; 32]
    }
    fn cm(b: u8) -> Cm {
        let mut c = [b; 32];
        c[0] = 0xC0;
        c
    }
    fn item(tags: &[u8], outs: &[u8]) -> Item {
        Item { tags: tags.iter().map(|b| tag(*b)).collect(), outputs: outs.iter().map(|b| cm(*b)).collect(), key: None }
    }

    /// `S_b` as a table: the tags held, and the tags undecidable here; every other tag provably not held.
    fn s_b(held: &[u8], unknown: &[u8]) -> impl Fn(&Tag) -> Option<bool> {
        let (h, u): (Vec<Tag>, Vec<Tag>) = (held.iter().map(|b| tag(*b)).collect(), unknown.iter().map(|b| tag(*b)).collect());
        move |t: &Tag| if h.contains(t) { Some(true) } else if u.contains(t) { None } else { Some(false) }
    }

    /// ⛔ A-F22 — THE LOSER IS AN ITEM, NOT A TAG. Two objects of one block spend one tag: the first in the block's order wins and
    /// ONLY the second is named lost, by its key; the winner's key is never in `lost_keys`, though its tag is in `losers`. A
    /// re-carried object (the same key twice) loses its later occurrence only. An object whose tag `S_b` already holds loses.
    /// CALIBRATION: the old reading (an object whose tag is among the losers' tags) names the WINNER lost here, which is the
    /// measured hole; the first assertion is the one that reading fails.
    #[test]
    fn a_contested_tag_names_only_the_losing_object_never_the_winner() {
        let obj = |tags: &[u8], key: u8| Item { tags: tags.iter().map(|b| tag(*b)).collect(), outputs: vec![cm(key)], key: Some([key; 32]) };
        let (a, b) = (obj(&[7], 0xA1), obj(&[7], 0xB2));
        let FoldVerdict::Decided { losers, lost_keys, revoke } = decide_at_fold(&[a.clone(), b.clone()], s_b(&[], &[])) else {
            panic!("an answerable block waited");
        };
        assert_eq!(lost_keys, vec![[0xB2; 32]], "⛔ A-F22: the winning object was named lost (or the loser was not)");
        assert_eq!(losers, vec![tag(7)], "the loser's one occurrence of the tag leaves the admitted set");
        assert_eq!(revoke, vec![cm(0xB2)], "only the loser's outputs are revoked");
        // the old reading, for the record: by tag, the winner is "a loser" too — the hole this test holds closed
        assert!(a.tags.iter().any(|t| losers.contains(t)), "CALIBRATION: by tag the winner looks lost");
        // a re-carried object: its first occurrence wins, its second loses
        let FoldVerdict::Decided { lost_keys, .. } = decide_at_fold(&[a.clone(), a.clone()], s_b(&[], &[])) else { panic!() };
        assert_eq!(lost_keys, vec![[0xA1; 32]], "a re-carried object loses exactly one occurrence");
        // a tag an earlier block spent: every object naming it loses
        let FoldVerdict::Decided { lost_keys, .. } = decide_at_fold(&[a, b], s_b(&[7], &[])) else { panic!() };
        assert_eq!(lost_keys, vec![[0xA1; 32], [0xB2; 32]], "⛔ an object re-spending an S_b tag was credited");
    }

    /// ⭐ DB-353 §13.6 — THE TABLE, ROW BY ROW, over the canonical fold-point set `S_b`.
    #[test]
    fn db353_13_6_the_fold_rule_decides_every_row_of_the_table() {
        let decided = |revoke: Vec<Cm>, losers: Vec<Tag>| FoldVerdict::Decided { revoke, losers, lost_keys: Vec::new() };
        // (1) an earlier block in canonical order spent the tag (S_b holds it) ⇒ LOSES: outputs revoked, tags leave the
        // admitted set.
        let v = decide_at_fold(&[item(&[1], &[10, 11])], s_b(&[1], &[]));
        assert_eq!(v, decided(vec![cm(10), cm(11)], vec![tag(1)]), "⛔ a re-spend of an S_b tag was credited");
        // (2) no earlier spender ⇒ WINS, and an honest block revokes nothing and records nothing.
        assert_eq!(decide_at_fold(&[item(&[2], &[12])], s_b(&[], &[])), decided(Vec::new(), Vec::new()));
        // (3) two items of ONE block spending one tag: the first in the block's order wins.
        let v = decide_at_fold(&[item(&[3], &[13]), item(&[3], &[14])], s_b(&[], &[]));
        assert_eq!(v, decided(vec![cm(14)], vec![tag(3)]), "⛔ one block credited two spends of one tag");
        // (4) a multi-input item: ONE consumed tag consumes the whole item, and all its outputs are revoked.
        let v = decide_at_fold(&[item(&[4, 5], &[15, 16])], s_b(&[5], &[]));
        assert_eq!(v, decided(vec![cm(15), cm(16)], vec![tag(4), tag(5)]), "⛔ a spend with one consumed input was credited");
        // (5) UNDECIDABLE and nothing says it lost ⇒ the WHOLE block WAITS (never excluded, never admitted on a guess).
        assert_eq!(decide_at_fold(&[item(&[6], &[17])], s_b(&[], &[6])), FoldVerdict::Wait, "⛔ an undecidable tag was guessed");
        // (6) …but a tag that DOES decide it lost wins over an undecidable sibling tag: a loss needs no more evidence.
        let v = decide_at_fold(&[item(&[7, 8], &[18])], s_b(&[8], &[7]));
        assert_eq!(v, decided(vec![cm(18)], vec![tag(7), tag(8)]), "a known loss must not wait on an unknown sibling");
        // (7) a later item waits even after an earlier one won: the block is decided whole or not at all.
        assert_eq!(decide_at_fold(&[item(&[9], &[19]), item(&[10], &[20])], s_b(&[], &[10])), FoldVerdict::Wait);
    }

    /// ⭐ DB-353 §13.6 — TWO NODES, OPPOSITE GRAFT ORDERS, ONE VERDICT, WITH NO ARRIVAL FACT AT ALL. X and Y are sibling
    /// blocks spending one tag, and X precedes Y in canonical order. Whatever order a node grafted them in, at X's fold
    /// `S_X` does not hold the tag and at Y's fold `S_Y` does (X's admitted step was noted first), because `S_b` is a
    /// function of the canonical order alone. The fold replays X then Y on every node: X is credited, Y is revoked, and
    /// Y's tag leaves Y's admitted set (its input is not burned twice). CALIBRATION: the replay is the rule itself, run
    /// twice from the two nodes' (identical) canonical sets.
    #[test]
    fn db353_13_6_opposite_graft_orders_reach_one_verdict_at_the_fold() {
        let t = tag(0x44);
        let (x, y) = (item(&[0x44], &[0x51]), item(&[0x44], &[0x52]));
        let fold_in_canonical_order = || {
            // S grows by each decided block's admitted tags (its lane minus its losers), exactly as the band notes it.
            let mut s: HashSet<Tag> = HashSet::new();
            let mut out = Vec::new();
            for blk in [&x, &y] {
                let v = decide_at_fold(std::slice::from_ref(blk), |q| Some(s.contains(q)));
                if let FoldVerdict::Decided { losers, .. } = &v {
                    s.extend(blk.tags.iter().filter(|q| !losers.contains(q)).copied());
                }
                out.push(v);
            }
            out
        };
        let on_p = fold_in_canonical_order(); // P grafted X then Y
        let on_q = fold_in_canonical_order(); // Q grafted Y then X — the fold reads neither order
        assert_eq!(
            on_p,
            vec![
                FoldVerdict::Decided { revoke: Vec::new(), losers: Vec::new(), lost_keys: Vec::new() },
                FoldVerdict::Decided { revoke: vec![cm(0x52)], losers: vec![t], lost_keys: Vec::new() }
            ],
            "the first spender in canonical order is credited and the second revoked"
        );
        assert_eq!(on_p, on_q, "⛔ two nodes that grafted the siblings in opposite orders decided differently");
    }

    /// ⛔ DB-358 increment 2 — THE CHECKPOINT ENCODING IS EXACT AND REFUSES DAMAGE WHOLE. A carry with every list
    /// non-empty round-trips byte-exact. A truncated segment, a trailing byte, and a forged count are each refused
    /// (`None`), and the forged count is refused before anything is allocated.
    #[test]
    fn db358_the_respend_carry_round_trips_exactly_and_refuses_every_damaged_segment() {
        let carry = RespendCarry {
            journal: vec![([0x61; 32], 77, vec![(0, vec![9u8; 33]), (5, Vec::new())])],
            reach: vec![(3, [0x60; 32]), (4, [0x61; 32])],
        };
        let bytes = carry.encode();
        assert_eq!(RespendCarry::decode(&bytes), Some(carry.clone()), "the carry must parse back exactly");
        assert_eq!(RespendCarry::decode(&RespendCarry::default().encode()), Some(RespendCarry::default()));

        for cut in [1usize, 4, 33, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(RespendCarry::decode(&bytes[..bytes.len() - cut]), None, "a segment cut by {cut} B is refused");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(RespendCarry::decode(&trailing), None, "a trailing byte is refused");
        // A forged journal count of u32::MAX behind the v2 marker: refused by the remaining-length check, never allocated.
        let mut forged = CARRY_V2.to_le_bytes().to_vec();
        forged.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(RespendCarry::decode(&forged), None, "a count the bytes cannot hold is refused");
    }

    /// ⭐ DB-353 §13.6 — A v1 CHECKPOINT (written before the memos and claims retired) is read WHOLE and its arrival facts
    /// DISCARDED: the journal and the reach a rewind needs survive, byte-exact, and damage is still refused whole.
    #[test]
    fn db353_13_6_a_v1_carry_is_read_whole_and_its_arrival_facts_discarded() {
        // The v1 layout, spelled by hand: memos, claims, journal (with claimed tags), reach (with lane keys).
        let mut v1 = Vec::new();
        let u32le = |v: &mut Vec<u8>, n: u32| v.extend_from_slice(&n.to_le_bytes());
        u32le(&mut v1, 1); // one memo
        v1.extend_from_slice(&tag(0x01));
        u32le(&mut v1, 1);
        v1.extend_from_slice(&tag(0x02)); // old
        u32le(&mut v1, 0); // pending
        u32le(&mut v1, 1); // one claim
        v1.extend_from_slice(&tag(0x04));
        v1.extend_from_slice(&[0x61; 32]);
        u32le(&mut v1, 1); // one journal entry
        v1.extend_from_slice(&[0x61; 32]);
        v1.extend_from_slice(&77u64.to_le_bytes());
        u32le(&mut v1, 1);
        v1.extend_from_slice(&tag(0x04)); // claimed
        u32le(&mut v1, 1);
        v1.extend_from_slice(&0u64.to_le_bytes());
        u32le(&mut v1, 3);
        v1.extend_from_slice(&[9u8; 3]);
        u32le(&mut v1, 1); // one reach entry
        v1.extend_from_slice(&3u64.to_le_bytes());
        v1.extend_from_slice(&[0x60; 32]);
        v1.extend_from_slice(&tag(0x01)); // lane key
        let got = RespendCarry::decode(&v1).expect("a v1 carry is read");
        assert_eq!(
            got,
            RespendCarry { journal: vec![([0x61; 32], 77, vec![(0, vec![9u8; 3])])], reach: vec![(3, [0x60; 32])] },
            "the journal and the reach survive; the memo, the claim, the claimed tags and the lane key are discarded"
        );
        assert_eq!(RespendCarry::decode(&v1[..v1.len() - 1]), None, "a damaged v1 carry is still refused whole");
    }
}

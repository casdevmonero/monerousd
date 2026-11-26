// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A-F114 — THE ONE ABSENCE CARRIER (moved here from the wallet's `canon_carrier.rs`, byte for byte, so the wallet and a
//! node's own custody, its DefiSlots cover carrier, run ONE implementation, docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md). A
//! fixed list of [`WALLET_SLOTS`] entries `(nullifier lanes, leaf)` follows the canonical tag chain's records, one leaf and
//! one merge a record (`usdm_agg::absence_u`); an entry joins before the record that makes it, leaves at the record that
//! spends it, and a spend proves the wrapper the node's door checks (`Node::canon_absence_refusal`).
//! AI RESISTANT: (a), every value a door accepts from it is a proof the door checks.
//! SAFE AT SCALE: one carrier of the family's one size per list; no term in the bonded set or the height.

use serde::{Deserialize, Serialize};
use usdm_agg::absence_ssa::{Entry, Lanes, Record};
use usdm_agg::absence_u::{empty_entry, prove_merge, prove_reshape, prove_span, prove_spend, step, UProof};

/// Slots of one list (the family shape's entry count). ⭐ A-F114: ONE note a list, so a list costs what its one note does.
/// MEASURED (`absence_ssa::tests::s2`, `absence_u::tests::u5`): a leaf takes ≈ 2^11 rows × slots × records, and a list proves
/// one leaf and one merge (~6.3 s on this Mac) per absorb whatever its slots hold. Sixteen slots over one record cost ~6.3 s
/// a record even for a wallet holding one note, which cannot keep pace with a record every ~3.5 s. One slot over a
/// [`SPAN`]-record leaf costs ~6.3 s per sixteen records, ~0.39 s a record per note held.
pub const WALLET_SLOTS: usize = 1;

/// Records one leaf spans: `WALLET_SLOTS × SPAN = 16` fills the family's 2^15 rows. Stated cost: a note just made is
/// spendable once the span holding its making record closes, at most SPAN records later (~1 minute at ~3.5 s a record).
pub const SPAN: usize = 16;

/// The wallet's carrier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonCarrier {
    /// The fixed-length list: each slot a note's (nullifier lanes, leaf) or an empty entry.
    pub slots: Vec<Entry>,
    /// Notes received but not yet made in a followed record: they take an empty slot before that record.
    pub pending: Vec<Entry>,
    /// The ONE running carrier over every record followed since `start` (none before the first record).
    pub carrier: Option<Vec<u8>>,
    /// The chain value the next record starts from, and the created bits there.
    pub end: Lanes,
    pub f_end: Vec<bool>,
    /// The next record index this carrier has NOT yet proven: the first record of the span being gathered.
    pub next_index: u64,
    /// Records a leaf spans for this carrier ([`SPAN`] by default; a test may run one).
    #[serde(default = "default_span")]
    pub span: usize,
    /// The records of the span being gathered (from `next_index`). Not saved: after a reload the follower reads them
    /// again from `next_index`, which the node's window still holds.
    #[serde(skip)]
    pub buffer: Vec<Record>,
    /// ⛔ A-F121 (ported to main 2026-11-26 from the Solstice lane's b6344ffc; finding A-F141 is the same class, measured by the
    /// testnet gate) — THE CARRIER AS IT STOOD BEFORE EACH OF ITS LAST SPAN PROOFS, newest last, so a canonical-chain REORG across
    /// those closes is UNDONE instead of freezing the note. MEASURED (testnet gate 20261126-002408 and -005844, restart): after a
    /// restart the node's fold re-folded 7 and 12 records, its canonical ring rewound (`Node::canon_rewind_from`), and the payer's
    /// carrier kept the old ends: every send was refused MEMBERSHIP_PROOF_MISSING (the wrapper's end is no end the node's window
    /// holds, `MemberGate::AnchorNotHeld`), 82 and 56 times, until the check's bound. The node rewinds at most `REWIND_RETAIN`
    /// (2 × `SPINE_RING_LEN` = 128) records, which crosses at most `REWIND_SPANS − 1` span closes of [`SPAN`] records, so
    /// [`REWIND_SPANS`] saved states cover every rewind it makes; deeper is the node's own stale-spine re-anchor.
    /// SCALE: a constant number of saved states (each one carrier proof and the slot list), independent of height and of the
    /// bonded set. cons: the wallet's saved carrier file holds up to `REWIND_SPANS` more proofs.
    #[serde(default)]
    pub prev: std::collections::VecDeque<CarrierState>,
}

/// ⛔ A-F121 — how many span proofs a carrier can undo: every span close the node's deepest rewind (`REWIND_RETAIN` = 2 ×
/// `SPINE_RING_LEN` records) can cross, plus the one it may start inside.
pub const REWIND_SPANS: usize = (2 * crate::params::SPINE_RING_LEN).div_ceil(SPAN) + 1;

/// ⛔ A-F121 — a carrier's proven state (everything but the open buffer and the saved states themselves).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarrierState {
    pub slots: Vec<Entry>,
    pub pending: Vec<Entry>,
    pub carrier: Option<Vec<u8>>,
    pub end: Lanes,
    pub f_end: Vec<bool>,
    pub next_index: u64,
}

fn default_span() -> usize {
    SPAN
}

impl CanonCarrier {
    /// A carrier that starts at the chain value `start` (the end of record `next_index - 1`, or the chain's genesis).
    #[must_use]
    pub fn starting_at(start: Lanes, next_index: u64) -> Self {
        let slots = (0..WALLET_SLOTS as u64).map(empty_entry).collect();
        Self {
            slots,
            pending: Vec::new(),
            carrier: None,
            end: start,
            f_end: vec![false; WALLET_SLOTS],
            next_index,
            span: SPAN,
            buffer: Vec::new(),
            prev: std::collections::VecDeque::new(),
        }
    }

    /// ⛔ A-F121 — the chain end this carrier stands at after the records of its open span: its proven `end` stepped through
    /// `buffer`. The follower compares it with the node's end of the record just behind the carrier, so a reorg under it is seen
    /// before anything more is absorbed. `None` only for a malformed buffered record.
    #[must_use]
    pub fn open_end(&self) -> Option<Lanes> {
        let mut e = self.end;
        for r in &self.buffer {
            e = step(&e, r)?;
        }
        Some(e)
    }

    /// ⛔ A-F121 — keep this carrier's proven state before a span proof (see [`Self::prev`]); the oldest leaves past
    /// [`REWIND_SPANS`].
    fn save_prev(&mut self) {
        self.prev.push_back(CarrierState {
            slots: self.slots.clone(),
            pending: self.pending.clone(),
            carrier: self.carrier.clone(),
            end: self.end,
            f_end: self.f_end.clone(),
            next_index: self.next_index,
        });
        while self.prev.len() > REWIND_SPANS {
            self.prev.pop_front();
        }
    }

    /// ⛔ A-F121 — UNDO the last span proof: the chain reorganized across that close (the node's end of record `next_index − 1`
    /// is no longer this carrier's `end`). The follower calls it until the ends agree. Returns `false` when no saved state is
    /// left (nothing proven yet, or a reorg deeper than the node ever makes): the follower then reports it, never follows a dead
    /// branch.
    /// ⛔ AN UNDO NEVER FORGETS A NOTE (lane livewedge, 2026-11-26). The chain's records are what an undo rolls back; the set
    /// of notes this wallet REGISTERED is the wallet's own knowledge, not the chain's, and a saved state is older than it. So
    /// every note held before the undo (a slot or pending) that the restored slots do not hold goes back to pending: it
    /// rejoins a slot when the new branch carries its making record, exactly like a note registered now. MEASURED why
    /// (testnet gate 20261126-030735, payer wallet log): the send registered its note, the follow undid seven span closes
    /// back to a state saved before that registration, the note stood nowhere, and the send was refused at once "this note
    /// is in no carrier list (it was never registered)". One source of truth: registration lives in the carrier's lists,
    /// and no rewind of the chain view deletes it.
    /// SCALE: one pass over `WALLET_SLOTS` + pending entries, a constant.
    pub fn rewind_prev(&mut self) -> bool {
        let Some(p) = self.prev.pop_back() else { return false };
        let held: Vec<Entry> = (0..self.slots.len())
            .filter(|&j| self.slots[j] != empty_entry(j as u64))
            .map(|j| self.slots[j])
            .chain(self.pending.iter().copied())
            .collect();
        self.slots = p.slots;
        self.pending = p.pending;
        for e in held {
            if !self.slots.contains(&e) && !self.pending.contains(&e) {
                self.pending.push(e);
            }
        }
        self.carrier = p.carrier;
        self.end = p.end;
        self.f_end = p.f_end;
        self.next_index = p.next_index;
        self.buffer.clear();
        true
    }

    /// The next record this carrier expects to be handed: the first after the span being gathered.
    #[must_use]
    pub fn expects(&self) -> u64 {
        self.next_index + self.buffer.len() as u64
    }

    /// The same carrier with a leaf spanning `span` records (a test runs one).
    #[must_use]
    pub fn with_span(mut self, span: usize) -> Self {
        self.span = span.max(1);
        self
    }

    fn reshape(&mut self, new: Vec<Entry>, replaced: Vec<bool>) -> Result<(), String> {
        if let Some(c) = &self.carrier {
            let r = prove_reshape(c, &self.slots, &new, &replaced).ok_or("the reshape did not prove")?;
            self.carrier = Some(r);
        } // nothing proven yet: the list simply starts as `new`
        for (f, r) in self.f_end.iter_mut().zip(&replaced) {
            if *r {
                *f = false;
            }
        }
        self.slots = new;
        Ok(())
    }

    /// Follow record `index` (its tags and outputs as the chain absorbs them). Records must arrive in order; the carrier
    /// proves them a span at a time (`span` records a leaf).
    pub fn absorb(&mut self, index: u64, rec: &Record) -> Result<(), String> {
        let want = self.next_index + self.buffer.len() as u64;
        if index != want {
            return Err(format!("record {index} out of order: this carrier expects {want}"));
        }
        self.buffer.push(rec.clone());
        if self.buffer.len() < self.span.max(1) {
            return Ok(());
        }
        let recs = std::mem::take(&mut self.buffer);
        self.absorb_span(&recs)
    }

    fn absorb_span(&mut self, recs: &[Record]) -> Result<(), String> {
        self.save_prev(); // ⛔ A-F121: a reorg across this close is undone from here
        let k = self.slots.len();
        let tag_in = |nf: &Lanes| recs.iter().any(|r| r.tags.iter().any(|(items, _)| items.contains(nf)));
        let out_in = |leaf: &Lanes| recs.iter().any(|r| r.outs.iter().any(|(items, _)| items.contains(leaf)));
        let mut new = self.slots.clone();
        let mut replaced = vec![false; k];
        // a created note whose nullifier the span carries was spent in it: its slot leaves first
        for j in 0..k {
            if self.f_end[j] && tag_in(&self.slots[j].0) {
                new[j] = empty_entry(j as u64);
                replaced[j] = true;
            }
        }
        // a pending note the span makes takes an empty slot first; one made AND spent inside the span never needs a
        // wrapper, and a span leaf cannot hold it, so it leaves the pending list without joining
        let made: Vec<Entry> = self.pending.iter().copied().filter(|(_, leaf)| out_in(leaf)).collect();
        let joining: Vec<Entry> = made.iter().copied().filter(|(nf, _)| !tag_in(nf)).collect();
        for e in &joining {
            let slot = (0..k).find(|&j| new[j] == empty_entry(j as u64)).ok_or("every slot is held: a second list is needed")?;
            new[slot] = *e;
            replaced[slot] = true;
        }
        self.pending.retain(|e| !made.contains(e));
        if replaced.iter().any(|r| *r) {
            self.reshape(new, replaced)?;
        }
        let mut end = self.end;
        for r in recs {
            end = step(&end, r).ok_or("a malformed record")?;
        }
        // a list of empty slots claims nothing, so it proves nothing: its chain value steps and any carrier it had is dropped
        if (0..k).all(|j| self.slots[j] == empty_entry(j as u64)) {
            self.carrier = None;
            self.f_end = vec![false; k];
            self.end = end;
            self.next_index += recs.len() as u64;
            return Ok(());
        }
        let leaf = prove_span(&self.slots, self.end, &self.f_end, recs).ok_or("the span's leaf did not prove")?;
        let ap: UProof = postcard::from_bytes(&leaf).map_err(|e| e.to_string())?;
        self.carrier = Some(match &self.carrier {
            Some(c) => prove_merge(c, &leaf).ok_or("the span did not merge into the carrier")?,
            None => leaf,
        });
        self.f_end = ap.f_end;
        self.end = end;
        self.next_index += recs.len() as u64;
        Ok(())
    }

    /// The spend of the note in slot `j`: the wrapper over the carrier and the chain end it was built to.
    pub fn spend(&self, j: usize, binder: Lanes, blind: Lanes) -> Result<(Vec<u8>, Lanes), String> {
        if !self.f_end.get(j).copied().unwrap_or(false) {
            return Err("this note is not made in the carrier's span yet".into());
        }
        let c = self.carrier.as_ref().ok_or("nothing proven yet")?;
        let w = prove_spend(&self.slots, j, c, binder, blind).ok_or("the spend wrapper did not prove")?;
        Ok((w, self.end))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// `n` records from index `from` on one branch (`salt` names it): each carries one tag of that branch, so two branches
    /// step the chain to different ends from the same index.
    fn branch(from: u64, n: u64, salt: u64) -> Vec<(u64, Record)> {
        (from..from + n)
            .map(|i| {
                let tag = *blake3::hash(&[salt.to_le_bytes(), i.to_le_bytes()].concat()).as_bytes();
                (i, crate::canon_chain::record(&[tag], &[], i))
            })
            .collect()
    }

    fn follow(c: &mut CanonCarrier, recs: &[(u64, Record)]) {
        for (i, r) in recs {
            c.absorb(*i, r).expect("an in-order record absorbs");
        }
    }

    /// ⛔ A-F121 / A-F141 (ported to main 2026-11-26) — A REORG ACROSS SPAN CLOSES IS UNDONE AND THE CARRIER FOLLOWS THE NEW BRANCH.
    /// A carrier proves three spans of branch A; the chain then re-orders everything after the first span (branch B). Two
    /// `rewind_prev` calls return it EXACTLY to its state at the first close, it then follows branch B, and its end is the end a
    /// carrier that only ever saw branch B reaches. The saved states stay bounded by `REWIND_SPANS`, and `open_end` is the end of
    /// the open span. RED before the port: `CanonCarrier` held no saved state, and the follower kept branch A's ends for good
    /// (the testnet gate's restart: MEMBERSHIP_PROOF_MISSING on every send). An empty-slot carrier steps its end without proving
    /// (`absorb_span`'s empty-list arm), so this pin proves the rewind rule in seconds.
    #[test]
    fn af121_a_reorg_across_span_closes_is_undone_and_the_carrier_follows_the_new_branch() {
        let start = crate::canon_chain::to_lanes(&crate::canon_chain::genesis());
        let span = SPAN as u64;
        let mut c = CanonCarrier::starting_at(start, 0);
        follow(&mut c, &branch(0, span, 1));
        let at_first_close = (c.end, c.next_index);
        follow(&mut c, &branch(span, 2 * span, 1));
        assert_eq!(c.next_index, 3 * span, "CALIBRATION: three spans proven");
        assert_eq!(c.prev.len(), 3, "⛔ a saved state is kept before each span proof");
        assert!(c.rewind_prev() && c.rewind_prev(), "⛔ the carrier cannot undo its last two span proofs");
        assert_eq!((c.end, c.next_index), at_first_close, "⛔ the rewind did not restore the state at the first close");
        follow(&mut c, &branch(span, 2 * span, 2));
        let mut only_b = CanonCarrier::starting_at(start, 0);
        follow(&mut only_b, &branch(0, span, 1));
        follow(&mut only_b, &branch(span, 2 * span, 2));
        assert_eq!((c.end, c.next_index), (only_b.end, only_b.next_index), "⛔ after the rewind the carrier does not stand where the new branch leads");
        // the saved states never grow past the deepest rewind the node makes
        follow(&mut c, &branch(3 * span, span * (REWIND_SPANS as u64 + 2), 3));
        assert_eq!(c.prev.len(), REWIND_SPANS, "⛔ the saved states grew past REWIND_SPANS");
        // the open span's end steps through its buffered records
        let open = branch(c.next_index, 3, 4);
        let mut expect = c.end;
        for (_, r) in &open {
            expect = step(&expect, r).expect("a record steps");
        }
        follow(&mut c, &open);
        assert_eq!(c.open_end(), Some(expect), "⛔ open_end is not the end after the open span's records");
    }

    /// ⛔ AN UNDO NEVER FORGETS A NOTE (lane livewedge, 2026-11-26). A note registered AFTER the carrier's last saved states
    /// (pending: its making record has not come yet) must still stand pending after the carrier undoes every one of those
    /// closes, so the send that registered it waits for its span instead of being refused "in no carrier list". RED before the
    /// fix: `rewind_prev` restored the saved pending list, which predates the registration (testnet gate 20261126-030735).
    /// TWO-PARTY-REVIEWED: one wallet's local bookkeeping rule (what an undo keeps of its own registrations); the two-party side,
    /// a node's reorg seen by a real wallet on another process, is the gate's `pay` / `change` checks on two real nodes.
    #[test]
    fn an_undo_across_span_closes_keeps_every_note_registered_after_the_saved_state() {
        let start = crate::canon_chain::to_lanes(&crate::canon_chain::genesis());
        let span = SPAN as u64;
        let mut c = CanonCarrier::starting_at(start, 0);
        follow(&mut c, &branch(0, 2 * span, 1));
        let note: Entry = (c.end, start);
        assert!((0..c.slots.len()).all(|j| empty_entry(j as u64) != note), "CALIBRATION: the note is no empty slot's entry");
        c.pending.push(note); // `register`, after both saved states
        follow(&mut c, &branch(2 * span, span, 1));
        assert!(c.pending.contains(&note), "CALIBRATION: no record makes the note, so it waits");
        assert!(c.rewind_prev() && c.rewind_prev() && c.rewind_prev(), "CALIBRATION: three closes undo");
        assert_eq!(c.next_index, 0, "CALIBRATION: the carrier stands at its start");
        assert!(c.pending.contains(&note), "⛔ the undo forgot a registered note: its send is refused as never registered");
        assert_eq!(c.pending.iter().filter(|e| **e == note).count(), 1, "⛔ the undo registered the note twice");
    }
}

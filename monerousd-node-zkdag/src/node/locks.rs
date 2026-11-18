// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ PAYMENT LOCKS, THE NODE'S HALF (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11, stage 1; `crate::spend_lock`):
//! which pool payments a validator may lock, the door a received lock enters, and how much stake has locked a payment.
//!
//! ⛔ STAGE 1 CHANGES NO CONSENSUS RULE. Nothing in the fold, the block doors or the pool's admission reads the lock
//! book. It is this node's count of signatures it verified, shown to its own wallet as "how much stake has locked this
//! payment" — never as "final" (§11.5: that word needs stages 3 and 4).

use super::*;
use crate::spend_lock::{LockCandidate, SpendLock, MAX_TAGS};

/// Verified locks this node cannot count yet: the payment has not reached its pool (a 5 KB lock outruns a 414 KB
/// payment), or its own fold has not reached the payment's anchor (the signer folded that step first).
/// A fixed ring. When it is full, the validator holding the most entries gives up its oldest, so one bonded key's
/// flood displaces only that key's own locks.
pub(crate) const LOCK_EARLY_MAX: usize = 256;
/// What the lock door and the book's tick did, by kind, since this process started ([`Node::lock_door_tally`]).
pub(crate) const LOCK_DOOR_KINDS: usize = 11;
/// The tally's rows, in the order the pool page prints them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoorTally {
    Counted = 0,
    Early = 1,
    Duplicate = 2,
    RefusedShape = 3,
    RefusedExpired = 4,
    RefusedNoStake = 5,
    RefusedLifetime = 6,
    RefusedSignature = 7,
    CountedFromEarly = 8,
    DroppedLifetime = 9,
    GaveWay = 10,
}
/// Statements the book counts at once. The book holds locks only for payments in this node's own pool and is cut back
/// to them on every tick; this is the hard ceiling beside that rule.
pub(crate) const LOCK_BOOK_MAX: usize = 4096;
/// The widest ML-DSA-65 key and signature a lock may carry (FIPS 204: 1,952 and 3,309 bytes).
const LOCK_PUBKEY_MAX: usize = 1952;
const LOCK_SIG_MAX: usize = 3309;

/// What the lock door did with one lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockOutcome {
    /// Fresh, verified, and its payment is in this node's pool: counted.
    Counted,
    /// Fresh and verified, and not countable yet: its payment is not in this node's pool, or this node's fold has not
    /// reached the payment's anchor. Kept in the early ring and counted by the book's tick once both are here.
    Early,
    /// This validator's lock on this statement is already held.
    Duplicate,
    /// Refused (malformed, expired, a signature that does not verify, a key with no stake, an expiry that is not the
    /// held payment's).
    Refused,
}

impl LockOutcome {
    /// Does this node pass the lock on? Only a fresh, verified one — never a duplicate, never a refusal.
    #[must_use]
    pub fn relays(self) -> bool {
        matches!(self, LockOutcome::Counted | LockOutcome::Early)
    }
}

impl Node {
    /// The statement and locked tags of a pool payment, or `None` for an object that is not a note spend (stage 1 locks
    /// payments only).
    /// ONE SPELLING with the block: a stated spend has TWO real tags, its nullifier and its claim tag (DB-329 §7e; the
    /// rest of its constant-width tag set is cover), and a block publishes exactly `(nullifier, tag1, out0, out1)` for it
    /// (`member_transition::stated_spend_rows`, the list `respend_items` reads at the fold). The statement is those four
    /// values, so the lock a validator signs over a pool payment and the spend a block later carries are compared
    /// like for like, with no knowledge of which other cells are cover.
    pub(crate) fn lock_statement_of(tx: &PqTx) -> Option<([u8; 32], Vec<[u8; 32]>)> {
        let st = Self::spend_tuple_of(tx)?;
        Some(Self::lock_statement_of_tuple(&st))
    }

    /// [`Self::lock_statement_of`] from the four values themselves (what a block's stated-spend row carries).
    pub(crate) fn lock_statement_of_tuple(st: &crate::note_transition::SpendTuple) -> ([u8; 32], Vec<[u8; 32]>) {
        let tags = vec![st.nullifier, st.tag1];
        debug_assert!(tags.len() <= MAX_TAGS);
        (crate::spend_lock::statement_of(&tags, &st.out0_cm, &st.out1_cm), tags)
    }

    /// This node's newest fold step (the ordinal its anchor ring ends at); `0` before its first fold.
    pub(crate) fn lock_fold_step(&self) -> u64 {
        self.spine_recent_roots.back().map_or(0, |(o, _)| *o)
    }

    /// The fold step at which `tx`'s member anchor leaves the ring: its anchor's own step plus the ring's length.
    /// `None` when this node's ring does not hold the anchor (the payment cannot be judged here now).
    pub(crate) fn lock_expiry_of(&self, tx: &PqTx) -> Option<u64> {
        let t = crate::member_transition::read_tuple(&tx.member_tuple)?;
        let step = self.spine_recent_roots.iter().find(|(_, r)| *r == t.anchor).map(|(o, _)| *o)?;
        Some(step.saturating_add(self.anchor_ring_len() as u64))
    }

    /// Does `voter` weigh on finality at the height this node can judge now? (An unbonded key signs nothing.)
    pub(crate) fn lock_signer_has_weight(&self, voter: &[u8; 32]) -> bool {
        self.validators.finality_weight_of_at(voter, self.fold_cursor_blue()) > 0
    }

    /// Does a block this node holds above its fold already SPEND `tag`? The pool's own reader of that fact
    /// (`spent_by_an_unfolded_block`, DB-353/DB-367): a tag counts only when the block JUSTIFIES it, so a producer that
    /// merely names a victim's pending tag in its fill stops no validator from locking the victim's payment, and only a
    /// block on the chain this node follows counts.
    pub(crate) fn tag_in_held_blocks(&self, tag: &[u8; 32]) -> bool {
        self.spent_by_an_unfolded_block(tag)
    }

    /// ⭐ THE PAYMENTS THIS VALIDATOR MAY LOCK NOW (§11.2 "Lock", rules 1–3; rule 4, the write-ahead, is the caller's).
    /// A payment qualifies when: it is in this node's own pool (so it passed this node's own pool door: its proofs, its
    /// anchor in this node's ring, its fee and stamp); it is a note spend; its anchor has at least HALF the ring left
    /// (so a locked payment has that long to enter a final block); and none of its tags appears in a block this node
    /// holds above its fold (a tag a held block already spends is not this validator's to promise).
    /// `skip(candidate)` is the caller's own table: a payment it already locked, or one whose tag it locked to
    /// another statement. It sees the whole candidate, lifetime included, and a skipped payment never takes one of
    /// the `cap` places. At most `cap` candidates: the tick's work bound; the next tick takes the next ones.
    /// DERIVED: "half the ring" is the one margin — a lock signed with less could outlive its own payment.
    /// cons: one ring lookup per pool payment per call (at most one ring of 40-byte entries compared), before `skip`.
    pub fn lockable_payments(&self, skip: &dyn Fn(&LockCandidate) -> bool, cap: usize) -> Vec<LockCandidate> {
        let now = self.lock_fold_step();
        let half_ring = (self.anchor_ring_len() as u64) / 2;
        let mut out = Vec::new();
        for tx in self.mempool().iter() {
            if out.len() >= cap {
                break;
            }
            let Some((statement, tags)) = Self::lock_statement_of(tx) else { continue };
            let Some(expiry) = self.lock_expiry_of(tx) else { continue };
            let cand = LockCandidate { statement, tags, expiry };
            if skip(&cand) {
                continue;
            }
            if expiry.saturating_sub(now) < half_ring {
                continue;
            }
            if cand.tags.iter().any(|t| self.tag_in_held_blocks(t)) {
                continue;
            }
            out.push(cand);
        }
        out
    }

    /// Does this node hold `voter`'s lock on `statement`, counted or waiting?
    pub(crate) fn holds_lock_from(&self, statement: &[u8; 32], voter: &[u8; 32]) -> bool {
        self.lock_book.get(statement).is_some_and(|m| m.contains_key(voter))
            || self.lock_early.iter().any(|(v, l)| v == voter && l.statement == *statement)
    }

    /// ⭐ THE LOCKS VALIDATOR `me` SHOULD SIGN NOW ([`Self::lockable_payments`] under its own table `guard`):
    /// a payment its table admits and it has not signed; and a payment it DID sign whose lock this node no longer
    /// holds. The second case is a restart: the node's book is memory and starts empty, while the table and the pool
    /// payment are still here, so without it a restarted validator's lock on every payment in flight is gone for good
    /// (nobody re-sends a lock). It is signed again only under the expiry the table recorded, so the validator states
    /// one lifetime per statement; a peer that still holds the first copy reads the second as a duplicate.
    /// Never listed: a payment any of whose tags the table binds to another statement (the double spend's other side).
    /// cons: after a restart, one signature and one two-cell message per payment still in the pool, once.
    pub fn lock_work_for(&self, me: &[u8; 32], guard: &crate::spend_lock::LockGuard, cap: usize) -> Vec<LockCandidate> {
        self.lockable_payments(
            &|c| {
                if !guard.admits(&c.tags, &c.statement) {
                    return true; // a tag of it is this key's promise to another statement
                }
                if !guard.holds(&c.tags, &c.statement) {
                    return false; // new to this key
                }
                // signed before: again only when this node lost the lock, and only under the lifetime first stated
                self.holds_lock_from(&c.statement, me) || guard.held_expiry(&c.tags, &c.statement) != Some(c.expiry)
            },
            cap,
        )
    }

    /// The pool payment whose statement is `statement`, if this node holds one.
    /// cons: one pass over the pool (a digest of at most 320 B per payment); the pool is bounded by its own cap.
    fn pool_payment_by_statement(&self, statement: &[u8; 32]) -> Option<&PqTx> {
        self.mempool().iter().find(|tx| Self::lock_statement_of(tx).is_some_and(|(s, _)| s == *statement))
    }

    /// ⭐ THE LOCK DOOR — every lock this node counts enters here (its own, from `lock_tick`; a peer's, from gossip).
    /// §9.6: (1) PoW: none, a lock is a signature by a bonded key and the bond is its cost. (2) Its own proof: the
    /// ML-DSA-65 signature under this node's pinned verifier over `lock_msg(network, statement, expiry)`, by a key
    /// that weighs on finality at the height this node judges. (3) Value: a lock creates and moves none, and no fold,
    /// block door or pool rule reads the book (stage 1), so the worst a wrong lock can do is a wrong count on this
    /// node's own wallet page — and a count needs a bonded key's real signature. (4) Replay: refused by the SET, keyed
    /// (statement, validator); a lock from another network fails its signature (the network is in the message); a
    /// lock whose expiry has passed is refused. (5) Work: the length, expiry and duplicate refusals cost nothing and
    /// run first; then ONE signature verify; the book holds at most `LOCK_BOOK_MAX` statements of this node's own
    /// pool, the early ring `LOCK_EARLY_MAX` locks, and a full ring evicts from the validator that holds the most of it
    /// (`lock_early_keep`). (6) Parity with the door it parallels, the vote gossip door
    /// (`ingest_finality_vote_gossip`): the same verifier, the same weight rule, the same duplicate rule. That door
    /// also binds a vote to a block this node holds; a lock binds to a pool payment instead: a lock is COUNTED only
    /// when this node holds the payment and the lock's expiry is exactly that payment's.
    /// ⛔ A LOCK THIS NODE CANNOT JUDGE YET WAITS, IT IS NOT REFUSED. A lock's expiry is its payment's anchor step
    /// plus one ring, on the SIGNER's fold. A receiver whose fold is one step behind the signer reads that expiry as
    /// "more than one ring ahead"; the door refused it on that reading, the signer never re-sends, and the payee's
    /// node stayed at one validator's stake (two real nodes, 2026-11-10 05:20 and 05:33: 50 % of stake at 7.7 s,
    /// never two-thirds). No upper bound is read here: a lock counts only by equality with a held payment's own
    /// lifetime, so a lock that states an absurd one waits in its signer's share of the early ring and counts for
    /// nothing.
    /// CACHE-ONLY: this node's own count of signatures it verified; nothing consensus-visible is decided from it.
    pub fn ingest_spend_lock(&mut self, lock: SpendLock) -> LockOutcome {
        if lock.pubkey.is_empty() || lock.pubkey.len() > LOCK_PUBKEY_MAX || lock.sig.is_empty() || lock.sig.len() > LOCK_SIG_MAX {
            return self.lock_door_note(DoorTally::RefusedShape, LockOutcome::Refused);
        }
        if lock.expiry <= self.lock_fold_step() {
            return self.lock_door_note(DoorTally::RefusedExpired, LockOutcome::Refused);
        }
        let voter = crate::pqauth::pubkey_id(&lock.pubkey);
        if self.lock_book.get(&lock.statement).is_some_and(|m| m.contains_key(&voter))
            || self.lock_early.iter().any(|(v, l)| *v == voter && l.statement == lock.statement)
        {
            return self.lock_door_note(DoorTally::Duplicate, LockOutcome::Duplicate);
        }
        if !self.lock_signer_has_weight(&voter) {
            return self.lock_door_note(DoorTally::RefusedNoStake, LockOutcome::Refused);
        }
        let held = self.pool_payment_by_statement(&lock.statement).map(|tx| self.lock_expiry_of(tx));
        if let Some(Some(exp)) = held {
            if exp != lock.expiry {
                // a lock that states another lifetime than the payment it names
                return self.lock_door_note(DoorTally::RefusedLifetime, LockOutcome::Refused);
            }
        }
        let genesis = self.params().genesis_parity_commit.clone();
        if !self.finality_verifier.verify(&lock.pubkey, &crate::spend_lock::lock_msg(&genesis, &lock.statement, lock.expiry), &lock.sig) {
            return self.lock_door_note(DoorTally::RefusedSignature, LockOutcome::Refused);
        }
        match held {
            Some(Some(_)) if self.lock_book.len() < LOCK_BOOK_MAX || self.lock_book.contains_key(&lock.statement) => {
                self.lock_book.entry(lock.statement).or_default().insert(voter, lock);
                self.lock_door_note(DoorTally::Counted, LockOutcome::Counted)
            }
            _ => {
                // the payment is not here yet, or its anchor is not in this node's ring yet: keep the verified lock
                self.lock_early_keep(voter, lock);
                self.lock_door_note(DoorTally::Early, LockOutcome::Early)
            }
        }
    }

    /// One more of `kind` on the door's tally; hands `out` back so a door arm reads as one line.
    fn lock_door_note(&mut self, kind: DoorTally, out: LockOutcome) -> LockOutcome {
        let row = &mut self.lock_door_tally[kind as usize];
        *row = row.saturating_add(1);
        out
    }

    /// What the lock door and the book's tick did, by kind, since this process started (the order of [`DoorTally`]).
    /// CACHE-ONLY: a readout of this process's own door for its operator; no rule reads it.
    #[must_use]
    pub fn lock_door_tally(&self) -> [u64; LOCK_DOOR_KINDS] {
        self.lock_door_tally
    }

    /// Keep a verified lock in the early ring. A full ring evicts the OLDEST lock of the validator holding the MOST
    /// entries: a bonded key that floods the ring (made-up statements, absurd lifetimes) displaces only its own locks,
    /// and every other validator's early locks stay until their payments arrive.
    /// cons: one pass over at most `LOCK_EARLY_MAX` + 1 entries of 32-byte ids per eviction; no hashing.
    fn lock_early_keep(&mut self, voter: [u8; 32], lock: SpendLock) {
        self.lock_early.push_back((voter, lock));
        while self.lock_early.len() > LOCK_EARLY_MAX {
            // O1-FOOTPRINT-REVIEWED: one entry per validator present in the ring, built and dropped inside this call.
            let mut held: std::collections::BTreeMap<[u8; 32], usize> = std::collections::BTreeMap::new();
            for (v, _) in &self.lock_early {
                *held.entry(*v).or_default() += 1;
            }
            let Some(most) = held.into_iter().max_by_key(|(_, n)| *n).map(|(v, _)| v) else { break };
            let Some(at) = self.lock_early.iter().position(|(v, _)| *v == most) else { break };
            self.lock_early.remove(at);
            self.lock_door_tally[DoorTally::GaveWay as usize] = self.lock_door_tally[DoorTally::GaveWay as usize].saturating_add(1);
        }
    }

    /// The book's housekeeping, once per runtime tick: early locks whose payment has arrived are counted (their expiry
    /// checked against the payment now that it is held), and the book is cut back to the payments this node's pool
    /// holds and to locks that have not expired.
    pub(crate) fn lock_book_tick(&mut self) {
        if self.lock_book.is_empty() && self.lock_early.is_empty() {
            return;
        }
        let now = self.lock_fold_step();
        // O1-FOOTPRINT-REVIEWED: one entry per pool payment, built and dropped inside this call.
        let pool: std::collections::BTreeMap<[u8; 32], Option<u64>> = self
            .mempool()
            .iter()
            .filter_map(|tx| Self::lock_statement_of(tx).map(|(s, _)| (s, self.lock_expiry_of(tx))))
            .collect();
        self.lock_book.retain(|st, m| {
            m.retain(|_, l| l.expiry > now);
            !m.is_empty() && pool.contains_key(st)
        });
        let early = std::mem::take(&mut self.lock_early);
        for (voter, l) in early {
            if l.expiry <= now {
                continue;
            }
            match pool.get(&l.statement) {
                Some(Some(exp)) if *exp == l.expiry => {
                    if self.lock_book.len() < LOCK_BOOK_MAX || self.lock_book.contains_key(&l.statement) {
                        self.lock_book.entry(l.statement).or_default().insert(voter, l);
                        let _ = self.lock_door_note(DoorTally::CountedFromEarly, LockOutcome::Counted);
                    } else {
                        self.lock_early.push_back((voter, l)); // the book is at its ceiling: the verified lock keeps waiting
                    }
                }
                Some(Some(_)) => {
                    // the payment is here and the lock states another lifetime: dropped, counted for nothing
                    let _ = self.lock_door_note(DoorTally::DroppedLifetime, LockOutcome::Refused);
                }
                _ => self.lock_early.push_back((voter, l)), // still waiting: the order and each validator's share are kept
            }
        }
    }

    /// How much finality stake has locked `statement`, in basis points of the stake this node judges now (0..=10,000).
    /// CACHE-ONLY: a readout for this node's own wallet page; no rule reads it.
    #[must_use]
    pub fn lock_weight_bp(&self, statement: &[u8; 32]) -> u32 {
        let h = self.fold_cursor_blue();
        let total = self.validators.total_finality_weight_at(h);
        if total == 0 {
            return 0;
        }
        let locked = self
            .lock_book
            .get(statement)
            .map_or(0u128, |m| m.keys().fold(0u128, |a, v| a.saturating_add(self.validators.finality_weight_of_at(v, h))));
        (locked.min(total).saturating_mul(10_000) / total) as u32
    }

    /// [`Self::lock_weight_bp`] for a pool payment (`0` for an object that is not a note spend).
    #[must_use]
    pub fn lock_weight_bp_of_tx(&self, tx: &PqTx) -> u32 {
        Self::lock_statement_of(tx).map_or(0, |(s, _)| self.lock_weight_bp(&s))
    }

    /// The locks this node holds for `statement` (stage 4 carries them as evidence; the pins read them).
    pub(crate) fn locks_held_for(&self, statement: &[u8; 32]) -> Vec<SpendLock> {
        self.lock_book.get(statement).map(|m| m.values().cloned().collect()).unwrap_or_default()
    }
}

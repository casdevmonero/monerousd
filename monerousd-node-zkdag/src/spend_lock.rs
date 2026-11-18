// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ PAYMENT LOCKS (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §10–§11, stage 1) — a bonded validator signs the PAYMENT.
//!
//! WHY: a payment becomes final today only as part of a block (push → block proof → block relay → settle wait → votes).
//! A payment between two parties needs no place in an order: it needs only that no OTHER spend of the same notes can
//! win. Each bonded validator that holds a pool payment and has passed it through its own pool door signs a LOCK:
//! "these tags are spent by this statement and no other". Locks from two-thirds of stake are a certificate.
//!
//! BORROWED: FastPay (Baudet, Danezis, Sonnino 2020) and Sui's owned-object path — consistent broadcast by the
//! validator set, one signature per object per validator, quorum intersection instead of ordering. The write-ahead
//! record is this tree's own vote guard (`vote_guard`, DB-370): what a key signed reaches the disk before the signature.
//!
//! ⛔ WHAT STAGE 1 IS AND IS NOT. This file makes locks exist, travel and be counted. It changes NO consensus rule: the
//! fold does not read a lock, so a certificate is NOT yet binding against a second spend that a prepared block carries
//! (§11.1). Nothing built on this stage may call a locked payment "final"; it may say how much stake has locked it.
//! Stages 3 and 4 (the fold follows finality; evidence voids the second spend) are what make the word true.
//!
//! THE STATEMENT is what a block publishes for a spend and a validator can recompute from the payment's own bytes: its
//! tags and its two output commitments (`note_transition::SpendTuple`). Two encodings of one spend (the same tags, the
//! same outputs) are one statement, so re-proving a payment is never a conflict.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: a lock names a statement digest and a validator. Every node that relays pool
//! payments already holds the payment the digest is taken from; the lock adds "this validator saw it", which the
//! payment's own gossip path already shows to the same nodes. Nothing here is written to a block in the honest case,
//! and no log line in this file prints a tag, a digest, a key or an amount.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Domain of the statement digest.
pub const STATEMENT_DOMAIN: &[u8] = b"musdm.spend.statement.v1";
/// Domain of the signed lock message.
pub const LOCK_DOMAIN: &[u8] = b"musdm.spend.lock.v1";
/// Most tags one statement carries: the constant-width spend's eight (`cover`), never a function of the pool.
pub const MAX_TAGS: usize = 8;
/// Locks one validator signs per tick: a fixed work bound for the tick, never a bound on what it will sign in the end
/// (the next tick takes the next ones).
pub const LOCKS_PER_TICK: usize = 16;
/// The write-ahead table's hard size: a full table signs no further lock until rows lapse (the payment is then simply
/// not locked by this validator and settles through its block as every payment does today — fail closed on the item).
pub const LOCK_TABLE_MAX_ROWS: usize = 65_536;
/// One row of the write-ahead record: `tag ‖ statement ‖ expiry (u64 LE)`.
const ROW_BYTES: usize = 32 + 32 + 8;
const MAGIC: &[u8; 8] = b"MUSDLCK1";

/// The digest of one spend's statement: its tags in the payment's own order, then its two output commitments.
#[must_use]
pub fn statement_of(tags: &[[u8; 32]], out0_cm: &[u8; 32], out1_cm: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(STATEMENT_DOMAIN);
    h.update(&[tags.len().min(usize::from(u8::MAX)) as u8]);
    for t in tags {
        h.update(t);
    }
    h.update(out0_cm);
    h.update(out1_cm);
    *h.finalize().as_bytes()
}

/// The message a lock's signature covers: domain, the network (its genesis commitment, so a lock never replays on
/// another network), the statement, and the fold step at which the payment's anchor leaves the ring.
#[must_use]
pub fn lock_msg(genesis: &[u8], statement: &[u8; 32], expiry: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(LOCK_DOMAIN.len() + 2 + genesis.len() + 32 + 8);
    m.extend_from_slice(LOCK_DOMAIN);
    m.extend_from_slice(&(genesis.len().min(usize::from(u16::MAX)) as u16).to_le_bytes());
    m.extend_from_slice(genesis);
    m.extend_from_slice(statement);
    m.extend_from_slice(&expiry.to_le_bytes());
    m
}

/// One validator's lock on one statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendLock {
    /// The validator's ML-DSA-65 public key (its id is `pqauth::pubkey_id` of this).
    pub pubkey: Vec<u8>,
    pub statement: [u8; 32],
    /// The fold step at which the locked payment's anchor leaves the ring: the lock means nothing after it.
    pub expiry: u64,
    pub sig: Vec<u8>,
}

impl SpendLock {
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// `None` for bytes that are not exactly one lock.
    #[must_use]
    pub fn from_wire(b: &[u8]) -> Option<SpendLock> {
        let (l, rest): (SpendLock, &[u8]) = postcard::take_from_bytes(b).ok()?;
        rest.is_empty().then_some(l)
    }
}

/// Most locks one certificate carries: one per validator, and never more than this many are read. A fixed work bound
/// for the certificate's door; a set larger than this needs lock batches (spec §11.4, "Bytes"), which are not built.
pub const CERT_LOCKS_MAX: usize = 256;

/// ⭐ A CERTIFICATE (spec §11.7): the locks of validators holding at least TWO THIRDS of the finality stake on ONE
/// statement. It is the only thing that voids a second spend, because it is the only set of locks that cannot coexist
/// with a block made final without an honest locker: with `3f+1` validators it has at least `f+1` honest signers, and
/// no `2f+1` validators can finalize a conflicting block without one of them. (Locks from just over one third are NOT
/// enough: §11.7 shows how a dishonest third could then split honest nodes' state.)
/// The certificate states the spend itself (its two real tags and its two outputs), so anyone can recompute the
/// statement the locks sign; nothing in it is new to a reader of the block that later carries the spend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockCertificate {
    /// The certified spend's real tags (its nullifier and its claim tag), in the statement's order.
    /// O1-FOOTPRINT-REVIEWED: at most `MAX_TAGS` entries.
    pub tags: Vec<[u8; 32]>,
    pub out0_cm: [u8; 32],
    pub out1_cm: [u8; 32],
    /// The fold step at which the certified payment's anchor leaves the ring; every lock states the same one.
    pub expiry: u64,
    /// O1-FOOTPRINT-REVIEWED: at most `CERT_LOCKS_MAX` entries, one per validator.
    pub locks: Vec<SpendLock>,
}

/// Why a certificate is refused (said by its door; never a tag, a digest or a key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertRefusal {
    /// No tags, more tags than a spend has, no locks, or more locks than a certificate carries.
    Shape,
    /// The fold has reached the step at which the certified payment's anchor left the ring.
    Expired,
    /// A lock that names another statement or another expiry than the certificate's.
    ForeignLock,
    /// A lock whose signature does not verify (for this network, this statement, this expiry).
    BadSignature,
    /// One validator signed twice in it.
    DuplicateSigner,
    /// The signers hold less than two thirds of the stake.
    BelowTwoThirds,
}

impl LockCertificate {
    /// The statement the certificate's locks must all sign.
    #[must_use]
    pub fn statement(&self) -> [u8; 32] {
        statement_of(&self.tags, &self.out0_cm, &self.out1_cm)
    }

    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// `None` for bytes that are not exactly one certificate.
    #[must_use]
    pub fn from_wire(b: &[u8]) -> Option<LockCertificate> {
        let (c, rest): (LockCertificate, &[u8]) = postcard::take_from_bytes(b).ok()?;
        rest.is_empty().then_some(c)
    }

    /// ⭐ THE ONE VERIFICATION every reader of a certificate runs (the pool door, the voter, the fold): shape; not
    /// expired at `fold_step`; every lock is for THIS statement and THIS expiry; every signature verifies for this
    /// network; no validator counted twice; and the signers' stake (`weight_of`, a signer with none adds nothing) is at
    /// least two thirds of `total`. `Ok(statement)` or the refusal.
    /// §9.6 for the object: (1) PoW — the carrying block's, at its own door. (2) Its own proof — every lock's ML-DSA-65
    /// signature, checked here from the object's bytes. (3) Value — a certificate creates and moves none; at the fold it
    /// can only make a spend of one of its tags with ANOTHER statement lose, the verdict the fold already gives a spend
    /// of a spent tag. (4) Replay — the statement, the network and the expiry are in every signed message; an expired
    /// certificate is refused here. (5) Work — at most `CERT_LOCKS_MAX` signature checks, after the free refusals.
    /// (6) Parity with the lock door (`Node::ingest_spend_lock`): the same message, the same verifier, the same expiry
    /// rule, one signer once; the lock door's "the payment is in my pool" has no counterpart because the certificate
    /// states the spend itself.
    pub fn verify(
        &self,
        genesis: &[u8],
        fold_step: u64,
        verifier: &dyn crate::pqauth::PqVerifier,
        weight_of: &dyn Fn(&[u8; 32]) -> u128,
        total: u128,
    ) -> Result<[u8; 32], CertRefusal> {
        if self.tags.is_empty() || self.tags.len() > MAX_TAGS || self.locks.is_empty() || self.locks.len() > CERT_LOCKS_MAX {
            return Err(CertRefusal::Shape);
        }
        if self.expiry <= fold_step {
            return Err(CertRefusal::Expired);
        }
        let statement = self.statement();
        let msg = lock_msg(genesis, &statement, self.expiry);
        let mut signers: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        let mut have: u128 = 0;
        for l in &self.locks {
            if l.statement != statement || l.expiry != self.expiry {
                return Err(CertRefusal::ForeignLock);
            }
            let voter = crate::pqauth::pubkey_id(&l.pubkey);
            if !signers.insert(voter) {
                return Err(CertRefusal::DuplicateSigner);
            }
            if !verifier.verify(&l.pubkey, &msg, &l.sig) {
                return Err(CertRefusal::BadSignature);
            }
            have = have.saturating_add(weight_of(&voter));
        }
        if total == 0 || !crate::quorum_math::two_thirds_met(have, total) {
            return Err(CertRefusal::BelowTwoThirds);
        }
        Ok(statement)
    }
}

/// A pool payment this validator may lock now (`Node::lockable_payments`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockCandidate {
    pub statement: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: at most `MAX_TAGS` entries, a protocol constant.
    pub tags: Vec<[u8; 32]>,
    pub expiry: u64,
}

/// ⛔ THE VALIDATOR'S WRITE-AHEAD LOCK TABLE — which statement each tag is locked to, on disk BEFORE a signature for it
/// exists. A validator that signs two statements for one tag hands every node slashing evidence and breaks the one
/// property a certificate rests on, so the table is never held in memory alone ("process-local state is not state"):
/// a restarted validator reads it back and refuses the second statement exactly as it would have before the restart.
///
/// BORROWED: `vote_guard::VoteGuard` (DB-370), itself the slashing-protection record of Ethereum validator clients.
/// A record that exists and cannot be read whole LOCKS the guard: the validator signs no lock rather than guess.
///
/// LOCAL-STORAGE-REQUIRED: this is what THIS key has signed and the chain has not yet seen. No proof, DA record or wire
///   field can hold it: a lock is off-chain by design and only its signer knows it exists, and held in RAM alone a
///   restart would let the key sign a second statement for a locked tag — slashing evidence against an honest
///   operator, and the end of the certificate's guarantee. The same class as the vote guard's record.
/// bound: at most `LOCK_TABLE_MAX_ROWS` live rows of 72 B. Rows are dropped when their lock's anchor leaves the ring,
///   and the record is rewritten whenever dropped rows outnumber live ones, so it never exceeds
///   2 × 65,536 × 72 B + 8 B = 9,437,192 B on disk at ANY height. A full table signs no further lock.
/// O1-FOOTPRINT-REVIEWED: by construction — `reserve` refuses past `max_rows`, a constant; never a term in height.
pub struct LockGuard {
    path: PathBuf,
    /// tag → (statement, expiry).
    by_tag: BTreeMap<[u8; 32], ([u8; 32], u64)>,
    locked: bool,
    /// Rows on disk that `by_tag` no longer holds (expired): the record is rewritten once they outnumber the live rows.
    dead_rows: usize,
    max_rows: usize,
}

impl LockGuard {
    /// The table beside this node's vote key.
    #[must_use]
    pub fn for_node_vote_key() -> LockGuard {
        LockGuard::open(crate::validator::node_vote_key_path().with_extension("lock-guard"))
    }

    /// Open the table at `path`. A missing record is a key that never locked. A record that cannot be read, has a wrong
    /// header, a torn last row, or two statements for one tag locks the guard.
    #[must_use]
    pub fn open(path: PathBuf) -> LockGuard {
        Self::open_with_max(path, LOCK_TABLE_MAX_ROWS)
    }

    fn open_with_max(path: PathBuf, max_rows: usize) -> LockGuard {
        let mut g = LockGuard { path, by_tag: BTreeMap::new(), locked: false, dead_rows: 0, max_rows };
        match std::fs::read(&g.path) {
            Ok(b) => match Self::parse(&b) {
                Some(rows) => g.by_tag = rows,
                None => {
                    eprintln!(
                        "[lock-guard] ⛔ the payment-lock record exists and does not parse — this node SIGNS NO LOCK (a second \
                         lock on one tag would burn its bond). Inspect the record beside the vote key."
                    );
                    g.locked = true;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("[lock-guard] ⛔ the payment-lock record cannot be read ({e}) — this node SIGNS NO LOCK.");
                g.locked = true;
            }
        }
        g
    }

    fn parse(b: &[u8]) -> Option<BTreeMap<[u8; 32], ([u8; 32], u64)>> {
        if b.is_empty() {
            return Some(BTreeMap::new());
        }
        let body = b.strip_prefix(MAGIC.as_slice())?;
        if body.len() % ROW_BYTES != 0 {
            return None; // a torn row: what was signed for it is unknown
        }
        let mut rows = BTreeMap::new();
        for r in body.chunks_exact(ROW_BYTES) {
            let tag: [u8; 32] = r[..32].try_into().ok()?;
            let st: [u8; 32] = r[32..64].try_into().ok()?;
            let exp = u64::from_le_bytes(r[64..72].try_into().ok()?);
            match rows.get(&tag) {
                Some((prev, _)) if *prev != st => return None, // two statements for one tag: never written by this code
                _ => {
                    rows.insert(tag, (st, exp));
                }
            }
        }
        Some(rows)
    }

    /// Has the guard refused to work (an unreadable record)?
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// The statement `tag` is locked to, if any.
    #[must_use]
    pub fn statement_for(&self, tag: &[u8; 32]) -> Option<[u8; 32]> {
        self.by_tag.get(tag).map(|(s, _)| *s)
    }

    /// Is every one of `tags` already locked to `statement` (this key signed it before)?
    #[must_use]
    pub fn holds(&self, tags: &[[u8; 32]], statement: &[u8; 32]) -> bool {
        !tags.is_empty() && tags.iter().all(|t| self.by_tag.get(t).is_some_and(|(s, _)| s == statement))
    }

    /// The ONE expiry this key recorded when it locked every one of `tags` to `statement`; `None` when it has not locked
    /// them all to it, or the rows disagree. A lock is signed again (after a restart emptied the node's book) only
    /// under this exact expiry, so one key never states two lifetimes for one statement.
    #[must_use]
    pub fn held_expiry(&self, tags: &[[u8; 32]], statement: &[u8; 32]) -> Option<u64> {
        let (first, rest) = tags.split_first()?;
        let (s, exp) = self.by_tag.get(first)?;
        (s == statement && rest.iter().all(|t| self.by_tag.get(t) == Some(&(*statement, *exp)))).then_some(*exp)
    }

    /// May this key sign a lock for `statement` over `tags`: no tag is locked to a DIFFERENT statement.
    #[must_use]
    pub fn admits(&self, tags: &[[u8; 32]], statement: &[u8; 32]) -> bool {
        !self.locked
            && !tags.is_empty()
            && tags.len() <= MAX_TAGS
            && tags.iter().all(|t| self.by_tag.get(t).is_none_or(|(s, _)| s == statement))
    }

    /// ⛔ WRITE-AHEAD: bind every tag to `statement` on disk BEFORE a signature exists. `true` only when the guard admits
    /// the lock, the table has room, AND the rows reached the disk. On `false` the caller must not sign.
    pub fn reserve(&mut self, tags: &[[u8; 32]], statement: &[u8; 32], expiry: u64) -> bool {
        if !self.admits(tags, statement) {
            return false;
        }
        let mut rows = Vec::with_capacity(tags.len() * ROW_BYTES);
        let mut fresh = 0usize;
        for (i, t) in tags.iter().enumerate() {
            if self.by_tag.contains_key(t) || tags[..i].contains(t) {
                continue; // already bound to this statement (admits checked it is the same one), or named twice
            }
            fresh += 1;
            rows.extend_from_slice(t);
            rows.extend_from_slice(statement);
            rows.extend_from_slice(&expiry.to_le_bytes());
        }
        if self.by_tag.len() + fresh > self.max_rows {
            return false; // the table is full: this payment is not locked by this key (it settles through its block)
        }
        if !rows.is_empty() {
            if let Err(e) = Self::append_durably(&self.path, &rows) {
                eprintln!("[lock-guard] ⛔ the payment-lock record could not be written ({e}) — not signing.");
                return false;
            }
        }
        for t in tags {
            self.by_tag.entry(*t).or_insert((*statement, expiry));
        }
        true
    }

    /// Append `rows` (whole rows only) and sync them; a new record starts with the header.
    /// LOCAL-STORAGE-REQUIRED: the write-ahead rows of [`LockGuard`] — see its declaration for why nothing else can hold them.
    /// bound: the record never exceeds 2 × `LOCK_TABLE_MAX_ROWS` × 72 B + 8 B (`reserve` refuses past the row limit).
    fn append_durably(path: &Path, rows: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let fresh = std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true);
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let mut buf = Vec::with_capacity(MAGIC.len() + rows.len());
        if fresh {
            buf.extend_from_slice(MAGIC);
        }
        buf.extend_from_slice(rows);
        f.write_all(&buf)?; // one write: a crash leaves the record without these rows or, at worst, torn — and a torn record locks
        f.sync_all()?;
        if fresh {
            if let Some(dir) = path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
        }
        Ok(())
    }

    /// Drop every lock whose payment can no longer settle: its anchor left the ring at fold step `expiry`, and this node's
    /// fold has reached `fold_step`. The record is rewritten (to a sibling, synced, renamed) once the dropped rows
    /// outnumber the live ones, so it never grows with height.
    pub fn expire(&mut self, fold_step: u64) {
        if self.locked {
            return;
        }
        let before = self.by_tag.len();
        self.by_tag.retain(|_, (_, exp)| *exp > fold_step);
        self.dead_rows += before - self.by_tag.len();
        if self.dead_rows > self.by_tag.len() && self.dead_rows > 0 {
            match self.rewrite_durably() {
                Ok(()) => self.dead_rows = 0,
                Err(e) => eprintln!("[lock-guard] the payment-lock record could not be compacted ({e}); it stays as it is."),
            }
        }
    }

    /// LOCAL-STORAGE-REQUIRED: the compaction of [`LockGuard`]'s own record — the same bytes, without the lapsed rows.
    /// bound: `LOCK_TABLE_MAX_ROWS` × 72 B + 8 B for the rewritten record; the sibling is renamed over the old one.
    fn rewrite_durably(&self) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("lock-guard.tmp");
        let mut buf = Vec::with_capacity(MAGIC.len() + self.by_tag.len() * ROW_BYTES);
        buf.extend_from_slice(MAGIC);
        for (tag, (st, exp)) in &self.by_tag {
            buf.extend_from_slice(tag);
            buf.extend_from_slice(st);
            buf.extend_from_slice(&exp.to_le_bytes());
        }
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Tags this key holds locked (for a readout and the pins).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// The validator's lock tick, beside its vote tick: sign a lock for each pool payment this node may lock
/// (`Node::lockable_payments`: its own pool door passed it, no tag is spent in a block it holds, the anchor has half
/// its ring left), write-ahead first, then hand the lock to the runtime, which counts it and gossips it.
/// ROOT-LAYER: the one site that signs a lock. cons: one ML-DSA-65 signature (about 3.3 KB + the 1.95 KB key on the
///   wire) per payment per validator; at most `LOCKS_PER_TICK` signatures per tick.
/// Returns how many locks were signed.
pub fn lock_tick<T: crate::transport::CellTransport>(
    rt: &std::sync::Mutex<crate::node_runtime::NodeRuntime<T>>,
    guard: &mut LockGuard,
    pk: &[u8],
    sk: &[u8],
) -> usize {
    if guard.is_locked() {
        return 0;
    }
    let me = crate::pqauth::pubkey_id(pk);
    let (genesis, fold_step, cands) = {
        let r = rt.lock().unwrap_or_else(|e| e.into_inner());
        let n = r.node();
        if !n.lock_signer_has_weight(&me) {
            return 0; // an unbonded key's lock weighs nothing: sign nothing
        }
        (n.params().genesis_parity_commit.clone(), n.lock_fold_step(), n.lock_work_for(&me, guard, LOCKS_PER_TICK))
    };
    guard.expire(fold_step);
    let mut signed = 0;
    for c in cands {
        // The tags reach the disk bound to this statement BEFORE a signature for it exists.
        if !guard.reserve(&c.tags, &c.statement, c.expiry) {
            continue;
        }
        let sig = match crate::pqauth::ml_dsa_sign(&lock_msg(&genesis, &c.statement, c.expiry), sk) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let lock = SpendLock { pubkey: pk.to_vec(), statement: c.statement, expiry: c.expiry, sig };
        let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
        if r.submit_spend_lock(lock) {
            signed += 1;
        }
    }
    signed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("musd-lock-guard-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    fn t(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn one_spend_has_one_statement_and_any_changed_part_is_another() {
        let s = statement_of(&[t(1), t(2)], &t(3), &t(4));
        assert_eq!(s, statement_of(&[t(1), t(2)], &t(3), &t(4)), "the same spend states the same thing");
        assert_ne!(s, statement_of(&[t(1), t(9)], &t(3), &t(4)), "another tag is another statement");
        assert_ne!(s, statement_of(&[t(2), t(1)], &t(3), &t(4)), "the tags' order is part of the statement");
        assert_ne!(s, statement_of(&[t(1), t(2)], &t(9), &t(4)), "another first output is another statement");
        assert_ne!(s, statement_of(&[t(1), t(2)], &t(3), &t(9)), "another second output is another statement");
        assert_ne!(s, statement_of(&[t(1)], &t(2), &t(3)), "a tag is never read as an output: the count is hashed");
    }

    #[test]
    fn the_lock_message_binds_the_network_the_statement_and_the_expiry() {
        let m = lock_msg(b"net-a", &t(7), 100);
        assert_ne!(m, lock_msg(b"net-b", &t(7), 100), "a lock for one network is not a lock for another");
        assert_ne!(m, lock_msg(b"net-a", &t(8), 100));
        assert_ne!(m, lock_msg(b"net-a", &t(7), 101));
        assert_ne!(lock_msg(b"ab", &t(7), 1), lock_msg(b"a", &t(7), 1), "the network's length is part of the message");
    }

    #[test]
    fn a_lock_survives_the_wire_and_trailing_bytes_are_refused() {
        let l = SpendLock { pubkey: vec![1, 2, 3], statement: t(5), expiry: 42, sig: vec![9; 40] };
        let w = l.to_wire();
        assert_eq!(SpendLock::from_wire(&w), Some(l));
        let mut longer = w.clone();
        longer.push(0);
        assert_eq!(SpendLock::from_wire(&longer), None, "one lock, nothing after it");
        assert_eq!(SpendLock::from_wire(&w[..w.len() - 1]), None);
    }

    /// ⛔ THE PROPERTY A CERTIFICATE RESTS ON: one validator, one statement per tag — refused by the table, before any
    /// signature, and still refused after a restart.
    #[test]
    fn a_tag_locked_to_one_statement_is_refused_to_every_other_and_a_restart_changes_nothing() {
        let p = tmp("second");
        let mut g = LockGuard::open(p.clone());
        assert!(g.reserve(&[t(1), t(2)], &t(0xA), 500), "the first lock on fresh tags is written");
        assert!(g.holds(&[t(1), t(2)], &t(0xA)));
        assert!(!g.admits(&[t(1)], &t(0xB)), "a second statement for a locked tag is not admitted");
        assert!(!g.reserve(&[t(1)], &t(0xB), 500), "and never reaches the disk");
        assert!(!g.reserve(&[t(3), t(2)], &t(0xB), 500), "one locked tag among fresh ones refuses the whole lock");
        assert_eq!(g.statement_for(&t(3)), None, "a refused lock binds none of its tags");
        assert!(g.reserve(&[t(1), t(2)], &t(0xA), 500), "the same statement again is the same lock");
        drop(g);
        let mut again = LockGuard::open(p.clone());
        assert!(!again.is_locked());
        assert_eq!(again.statement_for(&t(1)), Some(t(0xA)), "the restarted validator still holds its lock");
        assert!(!again.reserve(&[t(2)], &t(0xC), 900), "and refuses the second statement exactly as before");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_record_that_cannot_be_read_whole_signs_nothing() {
        let p = tmp("torn");
        let mut g = LockGuard::open(p.clone());
        assert!(g.reserve(&[t(1)], &t(0xA), 500));
        drop(g);
        // a torn last row
        let mut b = std::fs::read(&p).unwrap();
        b.extend_from_slice(&[7u8; 10]);
        std::fs::write(&p, &b).unwrap();
        let mut torn = LockGuard::open(p.clone());
        assert!(torn.is_locked(), "a torn record locks the guard");
        assert!(!torn.reserve(&[t(9)], &t(0xB), 500), "a locked guard signs nothing, not even on fresh tags");
        // a wrong header
        std::fs::write(&p, b"NOTALOCK").unwrap();
        assert!(LockGuard::open(p.clone()).is_locked());
        // two statements for one tag (never written by this code: a tampered record)
        let mut bad = MAGIC.to_vec();
        for st in [0xAu8, 0xB] {
            bad.extend_from_slice(&t(1));
            bad.extend_from_slice(&t(st));
            bad.extend_from_slice(&500u64.to_le_bytes());
        }
        std::fs::write(&p, &bad).unwrap();
        assert!(LockGuard::open(p.clone()).is_locked(), "a record holding two statements for one tag is refused whole");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn an_expired_lock_frees_its_tag_and_the_record_does_not_grow() {
        let p = tmp("expire");
        let mut g = LockGuard::open(p.clone());
        for i in 0..8u8 {
            assert!(g.reserve(&[t(i)], &t(0xA0 + i), 100 + u64::from(i)));
        }
        let full = std::fs::metadata(&p).unwrap().len();
        g.expire(100);
        assert_eq!(g.statement_for(&t(0)), None, "the lock whose anchor left the ring is gone");
        assert_eq!(g.statement_for(&t(1)), Some(t(0xA1)), "a lock with one step left stands");
        assert!(g.reserve(&[t(0)], &t(0xEE), 900), "the freed tag may be locked to a new payment");
        g.expire(106);
        assert_eq!(g.len(), 2, "only the two locks that outlive step 106 remain");
        let small = std::fs::metadata(&p).unwrap().len();
        assert!(small < full, "the record was rewritten without its dead rows ({small} < {full})");
        drop(g);
        let again = LockGuard::open(p.clone());
        assert!(!again.is_locked());
        assert_eq!(again.len(), 2, "and reads back as the live locks only");
        assert_eq!(again.statement_for(&t(0)), Some(t(0xEE)));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("lock-guard.tmp"));
    }

    /// ⛔ THE CERTIFICATE'S DOOR (spec §11.7): three validators of equal stake; two of them are two thirds. Accepted: the
    /// two honest locks. Refused, each for its own reason: one lock (below two thirds), the same validator twice, a lock
    /// for another statement, a lock for another expiry, a forged signature, a lock signed for another network, an
    /// expired certificate, a key with no stake standing in for the second validator, and an empty or oversized shape.
    #[test]
    fn a_certificate_is_two_thirds_of_stake_on_one_statement_and_every_forgery_is_refused() {
        let v = crate::pqauth::MlDsaVerifier;
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        let ids: Vec<[u8; 32]> = keys.iter().map(|(pk, _)| crate::pqauth::pubkey_id(pk)).collect();
        let weight = |id: &[u8; 32]| if ids.contains(id) { 2000u128 } else { 0 };
        let (tags, o0, o1, exp) = (vec![t(1), t(2)], t(3), t(4), 500u64);
        let st = statement_of(&tags, &o0, &o1);
        let lock_over = |i: usize, net: &[u8], st: &[u8; 32], exp: u64| SpendLock {
            pubkey: keys[i].0.clone(),
            statement: *st,
            expiry: exp,
            sig: crate::pqauth::ml_dsa_sign(&lock_msg(net, st, exp), &keys[i].1).expect("signs"),
        };
        let lock = |i: usize| lock_over(i, b"net", &st, exp);
        let cert = |locks: Vec<SpendLock>| LockCertificate { tags: tags.clone(), out0_cm: o0, out1_cm: o1, expiry: exp, locks };
        let check = |c: &LockCertificate| c.verify(b"net", 100, &v, &weight, 6000);

        let good = cert(vec![lock(0), lock(1)]);
        assert_eq!(check(&good), Ok(st), "two of three equal validators on one statement are a certificate");
        assert_eq!(LockCertificate::from_wire(&good.to_wire()), Some(good.clone()), "it survives the wire");
        assert_eq!(check(&cert(vec![lock(0), lock(1), lock(2)])), Ok(st), "all three are one too");

        assert_eq!(check(&cert(vec![lock(0)])), Err(CertRefusal::BelowTwoThirds), "⛔ one third passed as a certificate");
        assert_eq!(check(&cert(vec![lock(0), lock(0)])), Err(CertRefusal::DuplicateSigner), "⛔ one validator counted twice");
        let other = statement_of(&tags, &t(9), &o1);
        assert_eq!(
            check(&cert(vec![lock(0), lock_over(1, b"net", &other, exp)])),
            Err(CertRefusal::ForeignLock),
            "⛔ a lock for another statement was counted"
        );
        assert_eq!(
            check(&cert(vec![lock(0), lock_over(1, b"net", &st, exp + 1)])),
            Err(CertRefusal::ForeignLock),
            "⛔ a lock for another expiry was counted"
        );
        let mut forged = lock(1);
        forged.sig[0] ^= 1;
        assert_eq!(check(&cert(vec![lock(0), forged])), Err(CertRefusal::BadSignature), "⛔ a forged signature was counted");
        assert_eq!(
            check(&cert(vec![lock(0), lock_over(1, b"other-net", &st, exp)])),
            Err(CertRefusal::BadSignature),
            "⛔ a lock signed for another network was counted"
        );
        assert_eq!(good.verify(b"net", 500, &v, &weight, 6000), Err(CertRefusal::Expired), "⛔ an expired certificate passed");
        // a key with no stake signs a perfectly good lock: it adds nothing
        let (spk, ssk) = crate::pqauth::ml_dsa_keypair();
        let stranger = SpendLock { pubkey: spk, statement: st, expiry: exp, sig: crate::pqauth::ml_dsa_sign(&lock_msg(b"net", &st, exp), &ssk).expect("signs") };
        assert_eq!(check(&cert(vec![lock(0), stranger])), Err(CertRefusal::BelowTwoThirds), "⛔ a key with no stake made up the two thirds");
        // the same two locks under a certificate that states another spend do not verify for it
        let mut restated = good.clone();
        restated.out0_cm = t(9);
        assert_eq!(check(&restated), Err(CertRefusal::ForeignLock), "⛔ locks for one spend certified another");
        assert_eq!(check(&cert(Vec::new())), Err(CertRefusal::Shape));
        let mut no_tags = good.clone();
        no_tags.tags.clear();
        assert_eq!(check(&no_tags), Err(CertRefusal::Shape));
        let mut longer = good.to_wire();
        longer.push(0);
        assert_eq!(LockCertificate::from_wire(&longer), None, "one certificate, nothing after it");
    }

    #[test]
    fn a_lock_over_no_tags_or_too_many_is_refused_and_a_full_table_signs_nothing_more() {
        let p = tmp("width");
        let mut g = LockGuard::open_with_max(p.clone(), 3);
        assert!(!g.reserve(&[], &t(1), 10), "no tags, nothing to lock");
        let nine: Vec<[u8; 32]> = (0..9u8).map(t).collect();
        assert!(!g.reserve(&nine, &t(1), 10), "more tags than a spend carries");
        assert!(g.is_empty());
        assert!(g.reserve(&[t(1), t(2)], &t(0xA), 10));
        assert!(!g.reserve(&[t(3), t(4)], &t(0xB), 10), "two more rows do not fit a table of three");
        assert_eq!(g.statement_for(&t(3)), None, "and a lock that does not fit binds nothing");
        assert!(g.reserve(&[t(3)], &t(0xC), 10), "one more row fits");
        assert!(g.reserve(&[t(1), t(2)], &t(0xA), 10), "a lock already held needs no room");
        g.expire(10);
        assert!(g.reserve(&[t(3), t(4)], &t(0xB), 20), "lapsed rows make room again");
        let _ = std::fs::remove_file(p);
    }
}

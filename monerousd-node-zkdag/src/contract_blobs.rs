// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ D4 AVAILABILITY — EVERY BACK END'S NEWEST STATE, ONE LOOKUP AWAY (Veil spec §12, DSOL-NODE-DOOR-SPEC §10).
//!
//! The chain holds a contract's storage ROOT and never its values. Every applied call carries the contract's WHOLE
//! post-state sealed under the contract's key `k_c` (`DsolCallTx::storage`: a D4 blob proven to take the EMPTY trie to
//! the call's `storage_post`; the blob has the class's constant `W(h)` entries whether the state uses one or all of
//! them), so the newest call of a contract IS its state: a reader holding `k_c` decrypts one record and has every slot,
//! with no replay of what came before. This store keeps, per contract, the last [`KEEP`] records the fold applied, and
//! `/contract_state_blob` serves them newest first: a fold step that is rewound (its call refused or re-ordered on the
//! re-fold) leaves an orphan as the newest record, and the reader takes the newest one whose root the chain's contract
//! leaf holds (AUDIT 2026-11-13: with the newest record alone a rewound call stranded every reader until the next call).
//!
//! BORROWED: Apache Kafka's log compaction (a log that keeps the newest value per key; older values are reclaimed as the
//! writer laps them) over one ring file. A record still live when the writer reaches it is copied forward, so a back end
//! nobody has called for a long time keeps its state; only when the newest states of all contracts together exceed
//! half the file does the least recently called contract's leave (it is then read from its site's own snapshot,
//! `.veil/state/<cid>`).
//!
//! PRIVACY (DIGITAL CASH): every record is what the carried call object already shows in its block (the contract id, the
//! call's tx hash, the blob, its salt, the post-state root); the blob is ciphertext under `k_c`. Nothing is added.
//! SCALE (SAFE AT SCALE): ONE file of a CONSTANT size ([`LOG_BYTES`]); RAM: one index line a contract held. A read is one
//! lookup; a write is one record plus the live records it laps (each copied once a lap). Height, blocks, notes, calls
//! and nodes add nothing; contracts add one record each up to the bound, then the oldest-called leave.
//! What protects it (AI RESISTANT): (a) — a record is a hint, never trusted: the reader decrypts it and accepts it only
//! when its slots fold to the root the chain's contract leaf holds NOW; a lying node can withhold or serve garbage, and
//! the reader then fails closed on that node and asks another.
//! LOCAL-STORAGE-REQUIRED: the state is DA the chain's blocks carried; a reader needs it after the block window, and no
//! proof can stand in for ciphertext a person must decrypt. The node's consensus state stays the one root.
//! bound: one file of exactly LOG_BYTES (256 MiB), allocated at open; never a term in height, blocks, notes or calls.

use std::collections::{HashMap, VecDeque};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

/// The store file's size, the whole of its disk.
/// PRODUCTION-SCALE-REVIEWED: 256 MiB, the order of the site store's default; `MONEROUSD_BLOB_LOG_MB` lowers it.
pub const LOG_BYTES: u64 = 256 << 20;

/// The records kept per contract: a rewind deeper than this many calls of ONE contract leaves its readers on the site's
/// snapshot until the next call. PRODUCTION-SCALE-REVIEWED: a constant per contract, 8 × 37 KB at class 14.
pub const KEEP: usize = 8;

/// One applied call's record: the contract's state after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallBlob {
    pub seq: u64,
    pub blue: u64,
    pub cid: [u8; 32],
    pub tx_hash: [u8; 32],
    pub salt: [u8; 32],
    pub storage_post: [u8; 32],
    pub blob: Vec<u8>,
}

const MAGIC: &[u8; 8] = b"MUDSTAT1";
/// The file's header: magic, head, tail, next sequence, record count.
const HDR: u64 = 64;
/// A record's fixed part: length, sequence, blue, four words, a 16-byte check.
const FIXED: usize = 4 + 8 + 8 + 32 * 4 + 16;

impl CallBlob {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FIXED + self.blob.len());
        v.extend_from_slice(&u32::try_from(FIXED + self.blob.len()).unwrap_or(0).to_le_bytes());
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.blue.to_le_bytes());
        for w in [&self.cid, &self.tx_hash, &self.salt, &self.storage_post] {
            v.extend_from_slice(w);
        }
        v.extend_from_slice(&self.blob);
        let check = blake3::hash(&v);
        v.extend_from_slice(&check.as_bytes()[..16]);
        v
    }

    fn decode(b: &[u8]) -> Option<CallBlob> {
        if b.len() < FIXED || u32::from_le_bytes(b[..4].try_into().ok()?) as usize != b.len() {
            return None;
        }
        let (body, check) = b.split_at(b.len() - 16);
        if &blake3::hash(body).as_bytes()[..16] != check {
            return None;
        }
        let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
        let w = |i: usize| -> [u8; 32] { b[20 + 32 * i..52 + 32 * i].try_into().unwrap_or([0; 32]) };
        Some(CallBlob { seq: u(4), blue: u(12), cid: w(0), tx_hash: w(1), salt: w(2), storage_post: w(3), blob: body[FIXED - 16..].to_vec() })
    }
}

#[derive(Clone, Copy, Debug)]
struct Meta {
    off: u64,
    len: u32,
    seq: u64,
    cid: [u8; 32],
}

/// The store: one ring file of a fixed size; the records in file order, and the newest per contract.
pub struct BlobLog {
    file: std::fs::File,
    size: u64,
    head: u64,
    next: u64,
    ring: VecDeque<Meta>,
    /// per contract, its last [`KEEP`] records, oldest first
    newest: HashMap<[u8; 32], VecDeque<Meta>>,
    live_bytes: u64,
}

impl BlobLog {
    /// Open (or create) the store at `path`, of exactly `size` bytes. A file of another size or layout, or one whose
    /// records stop checking part way (a crash mid-write), opens with the records that check: the store is a cache of
    /// what blocks carried, never authority.
    pub fn open(path: &Path, size: u64) -> std::io::Result<BlobLog> {
        let size = size.max(HDR + FIXED as u64 * 8);
        let mut file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut log = BlobLog { size, head: HDR, next: 0, ring: VecDeque::new(), newest: HashMap::new(), live_bytes: 0, file: file.try_clone()? };
        let mut hdr = [0u8; HDR as usize];
        let fresh = file.metadata()?.len() != size || file.read_exact(&mut hdr).is_err() || &hdr[..8] != MAGIC;
        if fresh {
            file.set_len(0)?;
            file.set_len(size)?;
            log.write_header()?;
            return Ok(log);
        }
        let u = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap_or([0; 8]));
        let (head, tail, next, count) = (u(8), u(16), u(24), u(32));
        log.head = head.clamp(HDR, size);
        log.next = next;
        let mut off = tail.clamp(HDR, size);
        for _ in 0..count {
            if off + 4 > size {
                off = HDR;
            }
            let mut lb = [0u8; 4];
            file.seek(SeekFrom::Start(off))?;
            file.read_exact(&mut lb)?;
            if u32::from_le_bytes(lb) == 0 {
                off = HDR;
                file.seek(SeekFrom::Start(off))?;
                file.read_exact(&mut lb)?;
            }
            let len = u32::from_le_bytes(lb);
            if (len as usize) < FIXED || off + u64::from(len) > size {
                break;
            }
            let mut b = vec![0u8; len as usize];
            file.seek(SeekFrom::Start(off))?;
            file.read_exact(&mut b)?;
            let Some(r) = CallBlob::decode(&b) else { break };
            let m = Meta { off, len, seq: r.seq, cid: r.cid };
            log.ring.push_back(m);
            log.make_newest(m);
            off += u64::from(len);
        }
        Ok(log)
    }

    /// `m` is kept for its contract: a record moved forward takes its own place; a new one goes last, and the contract's
    /// oldest leaves past [`KEEP`].
    fn make_newest(&mut self, m: Meta) {
        let q = self.newest.entry(m.cid).or_default();
        if let Some(at) = q.iter_mut().find(|x| x.seq == m.seq) {
            *at = m;
            return;
        }
        q.push_back(m);
        self.live_bytes += u64::from(m.len);
        if q.len() > KEEP {
            if let Some(old) = q.pop_front() {
                self.live_bytes -= u64::from(old.len);
            }
        }
    }

    fn is_live(&self, m: &Meta) -> bool {
        self.newest.get(&m.cid).is_some_and(|q| q.iter().any(|x| x.seq == m.seq))
    }

    fn write_header(&mut self) -> std::io::Result<()> {
        let tail = self.ring.front().map_or(self.head, |m| m.off);
        let mut h = [0u8; HDR as usize];
        h[..8].copy_from_slice(MAGIC);
        for (i, v) in [self.head, tail, self.next, self.ring.len() as u64].into_iter().enumerate() {
            h[8 + 8 * i..16 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&h)
    }

    fn read(&mut self, m: &Meta) -> Option<CallBlob> {
        let mut b = vec![0u8; m.len as usize];
        self.file.seek(SeekFrom::Start(m.off)).ok()?;
        self.file.read_exact(&mut b).ok()?;
        CallBlob::decode(&b)
    }

    /// The live bound: the newest states together never exceed half the file, so a lap always frees room.
    fn live_budget(&self) -> u64 {
        (self.size - HDR) / 2
    }

    /// Place `bytes` at the head; returns where. Records the head laps over leave the ring; the live ones are returned so
    /// the caller copies them forward.
    fn place(&mut self, n: u64) -> std::io::Result<(u64, Vec<CallBlob>)> {
        let mut lapped = Vec::new();
        let mut at = self.head;
        if at + n > self.size {
            while self.ring.front().is_some_and(|m| m.off >= at) {
                let m = self.ring.pop_front().expect("front");
                if self.is_live(&m) {
                    lapped.extend(self.read(&m));
                }
            }
            if at + 4 <= self.size {
                self.file.seek(SeekFrom::Start(at))?;
                self.file.write_all(&0u32.to_le_bytes())?;
            }
            at = HDR;
        }
        while self.ring.front().is_some_and(|m| m.off >= at && m.off < at + n) {
            let m = self.ring.pop_front().expect("front");
            if self.is_live(&m) {
                lapped.extend(self.read(&m));
            }
        }
        Ok((at, lapped))
    }

    fn append(&mut self, r: &CallBlob) -> std::io::Result<Vec<CallBlob>> {
        let bytes = r.encode();
        let n = bytes.len() as u64;
        let (at, lapped) = self.place(n)?;
        self.head = at + n;
        let m = Meta { off: at, len: u32::try_from(n).unwrap_or(u32::MAX), seq: r.seq, cid: r.cid };
        self.ring.push_back(m);
        self.make_newest(m);
        // header first: a crash before the record lands leaves only that record failing its check at the next open
        self.write_header()?;
        self.file.seek(SeekFrom::Start(at))?;
        self.file.write_all(&bytes)?;
        Ok(lapped)
    }

    /// File one applied call's record: it becomes its contract's newest. Returns its sequence number. A record larger
    /// than the live bound is not kept.
    pub fn push(&mut self, mut r: CallBlob) -> std::io::Result<u64> {
        r.seq = self.next;
        self.next += 1;
        let n = (FIXED + r.blob.len()) as u64;
        if n > self.live_budget() {
            return Ok(r.seq);
        }
        // the oldest-called contracts leave until the kept records fit the live bound (this contract's own oldest last)
        while self.live_bytes + n > self.live_budget() {
            let other = self.newest.values().filter(|q| q.back().is_some_and(|m| m.cid != r.cid)).filter_map(|q| q.back()).min_by_key(|m| m.seq).map(|m| m.cid);
            match other {
                Some(cid) => {
                    let gone: u64 = self.newest.remove(&cid).map_or(0, |q| q.iter().map(|m| u64::from(m.len)).sum());
                    self.live_bytes -= gone;
                }
                None => match self.newest.get_mut(&r.cid).and_then(VecDeque::pop_front) {
                    Some(old) => self.live_bytes -= u64::from(old.len),
                    None => break,
                },
            }
        }
        let mut pending = self.append(&r)?;
        // copy forward every live record the head lapped (each keeps its sequence: it is still its contract's newest)
        while let Some(old) = pending.pop() {
            if self.newest.get(&old.cid).is_some_and(|q| q.iter().any(|m| m.seq == old.seq)) {
                let more = self.append(&old)?;
                pending.extend(more);
            }
        }
        self.file.sync_data()?;
        Ok(r.seq)
    }

    /// The records this node keeps for contract `cid`, NEWEST first (at most [`KEEP`]); empty when it holds none.
    pub fn recent(&mut self, cid: &[u8; 32]) -> Vec<CallBlob> {
        let kept: Vec<Meta> = self.newest.get(cid).map(|q| q.iter().rev().copied().collect()).unwrap_or_default();
        kept.iter().filter_map(|m| self.read(m)).collect()
    }

    /// The newest record of contract `cid`, or `None` when this node holds none.
    pub fn latest(&mut self, cid: &[u8; 32]) -> Option<CallBlob> {
        self.recent(cid).into_iter().next()
    }
}

static LOG_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
static LOG: std::sync::OnceLock<Option<std::sync::Mutex<BlobLog>>> = std::sync::OnceLock::new();

/// BOOT: where this node keeps the store (one file beside its other state). Opened at first use.
pub fn log_at(path: std::path::PathBuf) {
    let _ = LOG_PATH.set(path);
}

/// This node's store, or `None` when it was given no place for one (readers then ask another node).
pub fn log() -> Option<std::sync::MutexGuard<'static, BlobLog>> {
    let slot = LOG.get_or_init(|| {
        let path = LOG_PATH.get()?;
        let size = std::env::var("MONEROUSD_BLOB_LOG_MB").ok().and_then(|v| v.parse::<u64>().ok()).map_or(LOG_BYTES, |m| (m << 20).min(LOG_BYTES));
        BlobLog::open(path, size).ok().map(std::sync::Mutex::new)
    });
    slot.as_ref().map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The fold applied a call: its record becomes the contract's newest. Never fails the fold (availability, not consensus).
pub fn file_call(blue: u64, t: &crate::dsol_call_tx::DsolCallTx) {
    if t.storage.blob.is_empty() {
        return;
    }
    if let Some(mut l) = log() {
        let _ = l.push(CallBlob {
            seq: 0,
            blue,
            cid: t.cid,
            tx_hash: t.tx_hash(),
            salt: t.storage.salt,
            storage_post: crate::spend_frontier::leaf_to_cm_bytes(t.root.stmt.storage_post),
            blob: t.storage.blob.clone(),
        });
    }
}

// TWO-PARTY-REVIEWED: this checks one node's own store file (compaction, laps, restart, torn records). The two parties of
// the capability are a node that folds a call and ANOTHER node's reader wallet rebuilding the back end from its own
// node's record: the real-node check scratchpad/net/backend.py.
#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn tmp(tag: &str) -> Tmp {
        Tmp(std::env::temp_dir().join(format!("states-{tag}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()))))
    }
    fn rec(cid: u8, n: u8, len: usize) -> CallBlob {
        CallBlob { seq: 0, blue: u64::from(n), cid: [cid; 32], tx_hash: [n; 32], salt: [n ^ 1; 32], storage_post: [n; 32], blob: vec![n; len] }
    }

    #[test]
    fn the_store_keeps_every_contracts_newest_state_across_laps_and_restarts_inside_its_file() {
        let t = tmp("compact");
        let size = HDR + 40 * (FIXED as u64 + 1000); // live bound: 20 records
        let mut l = BlobLog::open(&t.0, size).expect("open");
        // a contract called once, then never again
        l.push(rec(1, 0, 1000)).unwrap();
        // a busy contract laps the file many times over
        for n in 1..60u8 {
            l.push(rec(2, n, 1000)).unwrap();
            assert_eq!(std::fs::metadata(&t.0).unwrap().len(), size, "the file never changes size");
        }
        assert_eq!(l.latest(&[1; 32]).map(|r| r.blob[0]), Some(0), "the quiet contract's state was copied forward, never lost");
        assert_eq!(l.latest(&[2; 32]).map(|r| r.blob[0]), Some(59), "the busy contract's newest state");
        assert_eq!(l.latest(&[3; 32]), None);
        // a rewound step's orphan is newest, and the state before it is still there for the reader: the last KEEP
        let kept = l.recent(&[2; 32]);
        assert_eq!(kept.iter().map(|r| r.blob[0]).collect::<Vec<_>>(), (52..60u8).rev().collect::<Vec<_>>(), "the busy contract's last {KEEP}, newest first");
        // a restart reads back the same newest states
        drop(l);
        let mut l = BlobLog::open(&t.0, size).expect("reopen");
        assert_eq!(l.latest(&[1; 32]).map(|r| r.blob[0]), Some(0));
        assert_eq!(l.latest(&[2; 32]).map(|r| r.blob[0]), Some(59));
        // past the live bound (half the file) the least recently called contract leaves, the rest stay
        for c in 10..23u8 {
            l.push(rec(c, c, 1000)).unwrap();
        }
        assert!(l.live_bytes <= l.live_budget());
        assert_eq!(l.latest(&[1; 32]), None, "the least recently called contract left first");
        assert_eq!(l.latest(&[22; 32]).map(|r| r.blob[0]), Some(22));
        // a torn record is never served: the reopened store stops before it
        let newest = *l.ring.back().expect("a record");
        drop(l);
        // (LOCAL-STORAGE-REQUIRED: the test's own temp copy of the store file, corrupted on purpose; bound: its size)
        let mut raw = std::fs::read(&t.0).unwrap();
        raw[usize::try_from(newest.off).unwrap() + 40] ^= 0xff;
        std::fs::write(&t.0, &raw).unwrap();
        let mut l = BlobLog::open(&t.0, size).expect("reopen torn");
        assert!(l.ring.iter().all(|m| m.seq != newest.seq), "the torn record was indexed");
        assert!(l.latest(&newest.cid).is_none_or(|r| r.seq != newest.seq));
    }
}

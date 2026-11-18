// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-10 — A RELEASE DOWNLOADS OVER TOR FROM MANY NODES, CONTENT-ADDRESSED (spec §8, the update experience).
//!
//! A release file is cut into fixed chunks; its **release root** is a Merkle root over the chunks with the chunk count
//! bound in. That root is what builders attest (`Class::ReleaseAttestation::release_hash`), so a node or wallet that holds
//! only the root can verify every chunk any peer hands it, alone, and a lying or corrupted peer is refused chunk by chunk.
//! Nodes keep ONE release — the newest one ≥ 3 builders attest — and serve its chunks to peers over the bulk lane (kind 23);
//! a node missing a chunk its wallet wants asks its peers for it. The wallet downloads through its own node, re-verifies the
//! whole file against the attested root, and only ever opens the installer when the user taps (the Bitcoin model: never
//! automatic).
//!
//! Borrowed shape: BitTorrent v2 (BEP 52) — per-piece hashes under one Merkle root that names the content, pieces pulled
//! from any peer and verified alone; and Bitcoin Core's reproducible Guix builds attested by independent signers.
//!
//! §9.6 for the kind-23 door: (1) PoW — n/a, not a chain ingress; (2) the object's proof — every chunk verifies against an
//! ATTESTED root by its Merkle path, before a byte is stored; (3) value — none moves; (4) replay — a chunk already held is
//! not stored twice (the store is keyed by index); (5) bounded work — one chunk of `CHUNK_BYTES` and a path of at most
//! `log2(MAX_CHUNKS)` hashes per answer, a store of one release; (6) parity with the band-step pull (kind 22): the asker
//! names what it wants by content id and verifies what lands; nothing is accepted on the server's word.
//! DIGITAL-CASH-PRIVACY-REVIEWED: an ask names a public release root and a chunk index — software every node runs — and no
//! account, note, amount or holder.

use std::path::{Path, PathBuf};

/// One chunk: 256 KiB (BitTorrent v2's default piece size for large files).
pub const CHUNK_BYTES: usize = 256 * 1024;
/// The most chunks a release has: 1 GiB. A root naming more is refused.
pub const MAX_CHUNKS: u32 = 4096;
/// The bulk-lane answer tag.
pub const RELEASE_CHUNK_TAG: &[u8; 8] = b"RELCHUNK";
/// The bulk-lane ask kind: `[23][root 32][index u32 LE]` (37 bytes).
pub const BULK_REQ_KIND_RELEASE_CHUNK: u8 = 23;

fn h(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut x = blake3::Hasher::new();
    x.update(domain);
    for p in parts {
        x.update(p);
    }
    *x.finalize().as_bytes()
}

/// The leaf of chunk `i`.
#[must_use]
pub fn leaf(i: u32, chunk: &[u8]) -> [u8; 32] {
    h(b"MUSD/release/leaf/v1", &[&i.to_le_bytes(), chunk])
}

fn empty_leaf() -> [u8; 32] {
    h(b"MUSD/release/empty/v1", &[])
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    h(b"MUSD/release/node/v1", &[l, r])
}

/// The leaves padded to a power of two with the fixed empty leaf (no CVE-2012-2459 duplicate-last ambiguity: the count is
/// bound into the root and the pad leaf is no chunk's leaf).
fn padded(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let width = leaves.len().max(1).next_power_of_two();
    let mut v = leaves.to_vec();
    v.resize(width, empty_leaf());
    v
}

/// The release root over `leaves` (the chunk count bound in).
#[must_use]
pub fn root_of_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = padded(leaves);
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    h(b"MUSD/release/root/v1", &[&(leaves.len() as u32).to_le_bytes(), &level[0]])
}

/// The chunks of `file`.
#[must_use]
pub fn chunks(file: &[u8]) -> Vec<&[u8]> {
    if file.is_empty() {
        return Vec::new();
    }
    file.chunks(CHUNK_BYTES).collect()
}

/// The release root of a whole file — what a builder attests. `None` for an empty file or one past `MAX_CHUNKS`.
#[must_use]
pub fn release_root(file: &[u8]) -> Option<[u8; 32]> {
    let cs = chunks(file);
    if cs.is_empty() || cs.len() > MAX_CHUNKS as usize {
        return None;
    }
    let leaves: Vec<[u8; 32]> = cs.iter().enumerate().map(|(i, c)| leaf(i as u32, c)).collect();
    Some(root_of_leaves(&leaves))
}

/// The Merkle path of chunk `i` (siblings, bottom up).
#[must_use]
pub fn proof(leaves: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
    let mut level = padded(leaves);
    let mut at = i;
    let mut out = Vec::new();
    while level.len() > 1 {
        out.push(level[at ^ 1]);
        level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        at /= 2;
    }
    out
}

/// Does `chunk` at index `i` of an `n`-chunk release verify against `root` by `path`? Every chunk but the last is exactly
/// `CHUNK_BYTES`; the last is 1..=`CHUNK_BYTES`.
#[must_use]
pub fn verify_chunk(root: &[u8; 32], n: u32, i: u32, chunk: &[u8], path: &[[u8; 32]]) -> bool {
    if n == 0 || n > MAX_CHUNKS || i >= n || chunk.is_empty() || chunk.len() > CHUNK_BYTES {
        return false;
    }
    if i + 1 < n && chunk.len() != CHUNK_BYTES {
        return false;
    }
    let depth = (n as usize).next_power_of_two().trailing_zeros() as usize;
    if path.len() != depth {
        return false;
    }
    let mut acc = leaf(i, chunk);
    let mut at = i as usize;
    for s in path {
        acc = if at % 2 == 0 { node(&acc, s) } else { node(s, &acc) };
        at /= 2;
    }
    h(b"MUSD/release/root/v1", &[&n.to_le_bytes(), &acc]) == *root
}

/// The kind-23 ask for chunk `i` of `root`.
#[must_use]
pub fn ask(root: &[u8; 32], i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(37);
    v.push(BULK_REQ_KIND_RELEASE_CHUNK);
    v.extend_from_slice(root);
    v.extend_from_slice(&i.to_le_bytes());
    v
}

/// Is `req` a kind-23 ask? `Some((root, index))`.
#[must_use]
pub fn parse_ask(req: &[u8]) -> Option<([u8; 32], u32)> {
    if req.len() != 37 || req[0] != BULK_REQ_KIND_RELEASE_CHUNK {
        return None;
    }
    let root = <[u8; 32]>::try_from(&req[1..33]).ok()?;
    let i = u32::from_le_bytes(req[33..37].try_into().ok()?);
    Some((root, i))
}

/// One answered chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkAnswer {
    pub root: [u8; 32],
    pub index: u32,
    pub n: u32,
    pub chunk: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

/// The answer page: `RELCHUNK ‖ root ‖ index ‖ n ‖ len u32 ‖ chunk ‖ npath u16 ‖ path`. `RELCHUNK ‖ root ‖ index` alone is the
/// `notfound`.
#[must_use]
pub fn encode_answer(a: Option<&ChunkAnswer>, root: &[u8; 32], index: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 32 + 4 + a.map_or(0, |a| 10 + a.chunk.len() + a.path.len() * 32));
    v.extend_from_slice(RELEASE_CHUNK_TAG);
    v.extend_from_slice(root);
    v.extend_from_slice(&index.to_le_bytes());
    if let Some(a) = a {
        v.extend_from_slice(&a.n.to_le_bytes());
        v.extend_from_slice(&(a.chunk.len() as u32).to_le_bytes());
        v.extend_from_slice(&a.chunk);
        v.extend_from_slice(&(a.path.len() as u16).to_le_bytes());
        for s in &a.path {
            v.extend_from_slice(s);
        }
    }
    v
}

/// Decode an answer page (after its tag): `Ok(None)` = the `notfound` for `(root, index)`; `Err` = malformed. Exact length.
pub fn decode_answer(body: &[u8]) -> Result<(([u8; 32], u32), Option<ChunkAnswer>), ()> {
    if body.len() < 36 {
        return Err(());
    }
    let root = <[u8; 32]>::try_from(&body[..32]).map_err(|_| ())?;
    let index = u32::from_le_bytes(body[32..36].try_into().map_err(|_| ())?);
    if body.len() == 36 {
        return Ok(((root, index), None));
    }
    let rest = &body[36..];
    if rest.len() < 8 {
        return Err(());
    }
    let n = u32::from_le_bytes(rest[..4].try_into().map_err(|_| ())?);
    let len = u32::from_le_bytes(rest[4..8].try_into().map_err(|_| ())?) as usize;
    if len == 0 || len > CHUNK_BYTES || rest.len() < 8 + len + 2 {
        return Err(());
    }
    let chunk = rest[8..8 + len].to_vec();
    let np = u16::from_le_bytes(rest[8 + len..10 + len].try_into().map_err(|_| ())?) as usize;
    let tail = &rest[10 + len..];
    if np > 32 || tail.len() != np * 32 {
        return Err(());
    }
    let path = tail.chunks_exact(32).map(|c| <[u8; 32]>::try_from(c).unwrap_or([0u8; 32])).collect();
    Ok(((root, index), Some(ChunkAnswer { root, index, n, chunk, path })))
}

/// ⭐ THE ONE RELEASE A NODE KEEPS, on disk under its state directory: the chunks of the newest attested root, each stored
/// only after it verified against that root. O1-INFINITY-REVIEWED: one release (≤ `MAX_CHUNKS` × `CHUNK_BYTES`); adopting a
/// newer root deletes the older one first.
#[derive(Debug)]
pub struct ReleaseStore {
    dir: PathBuf,
    root: Option<[u8; 32]>,
    /// The chunk count, once a verified answer has named it (every later answer must agree).
    n: Option<u32>,
    /// The chunk indexes stored (read from disk once at open). O1-FOOTPRINT-REVIEWED: ≤ `MAX_CHUNKS` entries.
    held: std::collections::BTreeSet<u32>,
    /// Every chunk's leaf, once the release is complete (a served path needs them all). O1-FOOTPRINT-REVIEWED: ≤ `MAX_CHUNKS`.
    leaves: Option<Vec<[u8; 32]>>,
}

impl ReleaseStore {
    /// The store under `dir` (created when the first chunk lands). Reads which root it holds from disk.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let mut s = Self { dir: dir.to_path_buf(), root: None, n: None, held: std::collections::BTreeSet::new(), leaves: None };
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let (Some(b), true) = (crate::rpc_http::hex_decode(&name), e.path().is_dir()) {
                    if let Ok(r) = <[u8; 32]>::try_from(b.as_slice()) {
                        s.root = Some(r);
                        s.n = std::fs::read(e.path().join("n")).ok().and_then(|b| b.try_into().ok()).map(u32::from_le_bytes);
                        if let (Ok(chunks), Some(n)) = (std::fs::read_dir(e.path()), s.n) {
                            for c in chunks.flatten() {
                                let f = c.file_name().to_string_lossy().to_string();
                                if let Some(i) = f.strip_suffix(".bin").and_then(|x| x.parse::<u32>().ok()).filter(|i| *i < n) {
                                    s.held.insert(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        s.refresh_leaves();
        s
    }

    /// Once every chunk is held, read each once and keep its leaf (the served paths need them all).
    fn refresh_leaves(&mut self) {
        if self.leaves.is_some() || !self.complete() {
            return;
        }
        let n = self.n.unwrap_or(0);
        self.leaves = (0..n).map(|k| self.chunk(k).map(|c| leaf(k, &c))).collect::<Option<Vec<_>>>();
    }

    fn root_dir(&self, root: &[u8; 32]) -> PathBuf {
        self.dir.join(crate::hash::Hash32(*root).to_hex())
    }

    /// The root this store holds chunks of.
    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        self.root
    }

    /// The chunk count of the held root, once known.
    #[must_use]
    pub fn chunk_count(&self) -> Option<u32> {
        self.n
    }

    /// Make `root` the one release held (an older root's chunks are deleted). Only call with an ATTESTED root.
    pub fn adopt(&mut self, root: [u8; 32]) {
        if self.root == Some(root) {
            return;
        }
        if let Some(old) = self.root {
            let _ = std::fs::remove_dir_all(self.root_dir(&old));
        }
        self.root = Some(root);
        self.n = None;
        self.held.clear();
        self.leaves = None;
    }

    /// Chunk `i` of the held root, if stored.
    #[must_use]
    pub fn chunk(&self, i: u32) -> Option<Vec<u8>> {
        let r = self.root?;
        std::fs::read(self.root_dir(&r).join(format!("{i}.bin"))).ok()
    }

    /// Is chunk `i` of the held root stored? (No disk read.)
    #[must_use]
    pub fn holds(&self, i: u32) -> bool {
        self.held.contains(&i)
    }

    /// How many chunks of the held root are stored.
    #[must_use]
    pub fn held_count(&self) -> u32 {
        self.held.len() as u32
    }

    /// Is the whole release held?
    #[must_use]
    pub fn complete(&self) -> bool {
        self.n.is_some_and(|n| self.held_count() == n)
    }

    /// Store a verified chunk. Refused (false) unless it is of the held root, verifies by its path, and names the same
    /// chunk count every earlier chunk named.
    pub fn accept(&mut self, a: &ChunkAnswer) -> bool {
        if self.root != Some(a.root) || self.n.is_some_and(|n| n != a.n) {
            return false;
        }
        if !verify_chunk(&a.root, a.n, a.index, &a.chunk, &a.path) {
            return false;
        }
        let d = self.root_dir(&a.root);
        if std::fs::create_dir_all(&d).is_err() {
            return false;
        }
        if self.n.is_none() {
            if std::fs::write(d.join("n"), a.n.to_le_bytes()).is_err() {
                return false;
            }
            self.n = Some(a.n);
        }
        let p = d.join(format!("{}.bin", a.index));
        if !(self.held.contains(&a.index) || std::fs::write(p, &a.chunk).is_ok()) {
            return false;
        }
        self.held.insert(a.index);
        self.refresh_leaves();
        true
    }

    /// Seed the store from a whole file (an operator who built or downloaded the release): every chunk is written under
    /// the file's own root. `None` if the file is not a release this store may hold (empty, too large).
    pub fn seed(&mut self, file: &[u8]) -> Option<[u8; 32]> {
        let root = release_root(file)?;
        self.adopt(root);
        let cs = chunks(file);
        let leaves: Vec<[u8; 32]> = cs.iter().enumerate().map(|(i, c)| leaf(i as u32, c)).collect();
        for (i, c) in cs.iter().enumerate() {
            let a = ChunkAnswer { root, index: i as u32, n: cs.len() as u32, chunk: c.to_vec(), path: proof(&leaves, i) };
            if !self.accept(&a) {
                return None;
            }
        }
        Some(root)
    }

    /// Answer a kind-23 ask: chunk `i` with its path, only when the WHOLE release is held (a path needs every leaf).
    #[must_use]
    pub fn answer(&self, root: &[u8; 32], i: u32) -> Option<ChunkAnswer> {
        if self.root != Some(*root) || !self.complete() {
            return None;
        }
        let n = self.n?;
        if i >= n {
            return None;
        }
        let leaves = self.leaves.as_ref()?;
        Some(ChunkAnswer { root: *root, index: i, n, chunk: self.chunk(i)?, path: proof(leaves, i as usize) })
    }

    /// The whole file, when complete (the wallet's download, re-verified against the root here).
    #[must_use]
    pub fn assemble(&self) -> Option<Vec<u8>> {
        let (r, n) = (self.root?, self.n?);
        let mut out = Vec::new();
        for i in 0..n {
            out.extend_from_slice(&self.chunk(i)?);
        }
        (release_root(&out) == Some(r)).then_some(out)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// Pseudo-random bytes (a blake3 XOF over the seed), so no two chunks are alike.
    fn file(len: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new().update(&[seed]).finalize_xof().fill(&mut out);
        out
    }

    /// ⭐ §BR-10 — every chunk of a release verifies alone against its root, and nothing else does: a flipped byte, a chunk
    /// moved to another index, a path from another release, a short middle chunk, a lied chunk count — each refused.
    /// CALIBRATION: one chunk, an exact multiple of the chunk size, and a ragged tail all round-trip.
    #[test]
    fn a_release_chunk_verifies_alone_against_its_root_and_nothing_else_does() {
        for len in [1usize, CHUNK_BYTES, 3 * CHUNK_BYTES, 5 * CHUNK_BYTES + 17] {
            let f = file(len, 7);
            let root = release_root(&f).expect("a root");
            let cs = chunks(&f);
            let n = cs.len() as u32;
            let leaves: Vec<[u8; 32]> = cs.iter().enumerate().map(|(i, c)| leaf(i as u32, c)).collect();
            assert_eq!(root_of_leaves(&leaves), root);
            for (i, c) in cs.iter().enumerate() {
                let p = proof(&leaves, i);
                assert!(verify_chunk(&root, n, i as u32, c, &p), "CALIBRATION: chunk {i} of {len} B verifies");
                let mut bad = c.to_vec();
                bad[0] ^= 1;
                assert!(!verify_chunk(&root, n, i as u32, &bad, &p), "⛔ a flipped byte verified");
                assert!(!verify_chunk(&root, n + 1, i as u32, c, &p), "⛔ a lied chunk count verified");
                if n > 1 {
                    let j = (i + 1) % n as usize;
                    assert!(!verify_chunk(&root, n, j as u32, c, &proof(&leaves, j)), "⛔ a chunk at another index verified");
                }
            }
            let other = release_root(&file(len, 8)).expect("a root");
            assert!(!verify_chunk(&other, n, 0, cs[0], &proof(&leaves, 0)), "⛔ a chunk verified against another release");
            if n > 2 {
                assert!(!verify_chunk(&root, n, 1, &cs[1][..CHUNK_BYTES - 1], &proof(&leaves, 1)), "⛔ a short middle chunk verified");
            }
        }
        assert!(release_root(&[]).is_none(), "an empty file is no release");
    }

    /// ⭐ §BR-10 — a store fed only verified chunks, from a peer seeding the whole file, reassembles the exact file; it serves
    /// nothing until complete, refuses a forged chunk and a chunk of another root, and adopting a newer root deletes the old.
    #[test]
    fn a_store_fed_chunk_by_chunk_from_a_seeder_reassembles_the_exact_release() {
        let base = std::env::temp_dir().join(format!("release-store-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let f = file(4 * CHUNK_BYTES + 1000, 3);
        let mut seeder = ReleaseStore::open(&base.join("seeder"));
        let root = seeder.seed(&f).expect("the seeder holds the release");
        assert!(seeder.complete());
        let mut fetcher = ReleaseStore::open(&base.join("fetcher"));
        fetcher.adopt(root);
        assert!(fetcher.answer(&root, 0).is_none(), "nothing is served before the store is complete");
        let n = seeder.chunk_count().expect("n");
        for i in (0..n).rev() {
            let page = encode_answer(seeder.answer(&root, i).as_ref(), &root, i);
            let ((r, idx), a) = decode_answer(&page[8..]).expect("one encoding");
            assert_eq!((r, idx), (root, i));
            let mut a = a.expect("the seeder holds it");
            if i == 2 {
                let mut forged = a.clone();
                forged.chunk[5] ^= 0xFF;
                assert!(!fetcher.accept(&forged), "⛔ a forged chunk was stored");
            }
            assert!(fetcher.accept(&a), "chunk {i} is stored");
            a.root = [9u8; 32];
            assert!(!fetcher.accept(&a), "⛔ a chunk of another root was stored");
        }
        assert!(fetcher.complete());
        assert_eq!(fetcher.assemble().as_deref(), Some(f.as_slice()), "the exact release");
        let reopened = ReleaseStore::open(&base.join("fetcher"));
        assert_eq!((reopened.root(), reopened.chunk_count()), (Some(root), Some(n)), "the store survives a restart");
        let newer = release_root(&file(CHUNK_BYTES, 4)).expect("a root");
        fetcher.adopt(newer);
        assert!(!base.join("fetcher").join(crate::hash::Hash32(root).to_hex()).exists(), "the older release's chunks are deleted");
        assert!(decode_answer(&encode_answer(None, &root, 3)[8..]).expect("one encoding").1.is_none(), "a notfound decodes");
        let _ = std::fs::remove_dir_all(&base);
    }
}

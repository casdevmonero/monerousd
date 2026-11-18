// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ MONEROUSD VEIL, BUILD STEP 1 (docs/VEIL-SOVEREIGN-INTERNET-SPEC-20261107.md §3, §4, §9 step 1): the three pure
//! rules the rest of the network stands on. Nothing here touches consensus state, the wire or the disk.
//!
//! 1. A NAME IS A SITE'S ADDRESS. `flame.mud` is `@flame`'s site: name → owner key ([`crate::names`]) → that owner's
//!    latest publish ([`crate::site::SiteRegistry`]). Both lookups read this node's own state, so resolving a name asks
//!    nobody anything (no which-site query leaves the machine).
//! 2. A SITE IS CHUNKS UNDER ONE ROOT. The site's bytes are cut into 256 KB chunks, each addressed by its hash; the
//!    root binds the chunk count, the total length and the Merkle root over the chunk hashes. A reader checks every
//!    chunk it is served against the root the chain anchors: a node serving a wrong, short, long or misplaced chunk is
//!    refused ([`verify_chunk`]). BORROWED: BitTorrent's piece hashes / IPFS's content addressing, under one Merkle root
//!    as Bitcoin commits its transactions.
//! 3. A CHUNK BELONGS TO A SHARD, AND A SHARD HAS HOLDERS. A chunk's shard is the top bits of its hash, one of the
//!    same 256 the record shards use, and a shard's holders are named by the ONE rendezvous rule the node already has
//!    ([`crate::nf_sparse::holders_of`]) at the same replication. So a node's whole duty is a constant-size answer to
//!    "which of 256 shards are mine", recomputed when the peer set changes, and "is this chunk mine" is one lookup.
//!
//! STEPS 2 AND 3, the parts that stand on their own (no wire, no consensus state):
//!
//! 4. HOLDING A CHUNK CAN BE SHOWN TO ANYONE. A chunk's hash is itself a tree over 1 KB pieces, so a holder answers a
//!    challenge drawn from a block hash with ONE piece and its two paths (piece → chunk → site root), and any node
//!    checks the answer against the chain's root without holding the chunk ([`storage_challenge`], [`verify_storage`]).
//!    BORROWED: Filecoin's WindowPoSt question ("show me a random part, now"), as the plain Merkle opening Bitcoin's SPV
//!    uses. It does NOT show a holder keeps its own physical copy (a holder could fetch the piece from another in time);
//!    it shows the bytes were reachable by it at that block.
//! 5. A NODE KEEPS CHUNKS UNDER A BUDGET, ON DISK ([`ChunkStore`]): nothing is dropped while the store is under budget;
//!    over it, chunks cached for a reader go first and the node's own shard's chunks last. A chunk read back is hashed
//!    again, so a rotted file is a missing chunk, never a wrong one.
//! 6. A READ THE SERVER CANNOT SEE ([`pir_query`], [`pir_answer`], [`pir_combine`]): two servers each XOR the chunks
//!    one key selects from a public bucket of 1,024; neither learns which chunk was wanted, and the reader checks the
//!    result against the root. BORROWED: two-server PIR from a distributed point function (Boyle, Gilboa, Ishai), on the
//!    node's own `pqmix::dpf`.
//! 7. THE PRICE, in dollars before the tap: bytes that are new in this version, once ([`storage_price_atomic`]).
//!
//! NOT BUILT (spec §9 steps 2 to 5): carrying a publish and its chunks between nodes, paying holders from the storage
//! endowment, the single-server sublinear read (tier 1b), the publish and browse screens, and the fees. The live node
//! runtime carries no site message today, so none of the above is reachable from a wallet yet.

use crate::hash::Hash32;
use crate::merkle;
use crate::directory::Directory;
use crate::names::canon_name;
use crate::node::Node;
use crate::site::{SitePublish, SiteRegistry};

/// The size of every chunk but a site's last. The spec's value: small enough that one chunk is one private read,
/// large enough that a typical page is a handful of chunks.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// The suffix of a site name.
pub const MUD_SUFFIX: &str = ".mud";

/// The placement domain: a node's site shards are drawn separately from its nullifier shards.
const PLACEMENT_DOMAIN: &[u8] = b"MonerousD Veil chunk shard placement v1";

// ── 1. names ────────────────────────────────────────────────────────────────────────────────────────────────────

/// The canonical name of a `.mud` host, or `None` when `host` is not exactly `<name>.mud`. A host with a path, a port,
/// a sub-name, or characters the name registry's canonical form does not keep is not a site name: nothing is guessed.
#[must_use]
pub fn mud_name(host: &str) -> Option<String> {
    let lowered = host.trim().to_ascii_lowercase();
    let label = lowered.strip_suffix(MUD_SUFFIX)?;
    let ok = !label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    (ok && canon_name(label) == label).then(|| label.to_string())
}

/// A resolved site: whose it is and what the chain says its current version is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MudSite {
    pub name: String,
    pub owner: [u8; 32],
    pub publish: SitePublish,
}

/// `flame.mud` → the site `@flame`'s owner key published under that name. `None` when the name is not registered, or
/// its owner has published no site under it. A site published under the same label by ANOTHER key is a different site
/// id and is never returned: the name's owner decides what the name shows.
#[must_use]
pub fn resolve_mud(names: &Directory, sites: &SiteRegistry, host: &str) -> Option<MudSite> {
    let name = mud_name(host)?;
    let owner = names.owner_of(&name)?;
    let publish = sites.current(&SitePublish::site_id_for(&owner, &name))?.clone();
    (publish.owner == owner).then_some(MudSite { name, owner, publish })
}

// ── 2. chunks under one root ────────────────────────────────────────────────────────────────────────────────────

/// A site version as its chunks: each one's length and hash, in order. The bytes themselves live with the chunks'
/// holders.
///
/// A CHUNK ENDS AT EVERY FILE BOUNDARY (v2, 2026-11-12). A packed site ([`pack_site`]) is cut where its header ends,
/// where every file starts, and every [`CHUNK_BYTES`] inside a file; anything else is cut every [`CHUNK_BYTES`]. So a
/// file that did not change is the same chunks in the next version, under the same hashes, and an update stores and
/// pays for the files it changed and the header alone. MEASURED why (v1, fixed 256 KB cuts over the whole run): one
/// byte added to a file moved every later byte of the site, so every chunk after it was new and was stored and paid
/// for again. BORROWED: git's trees and IPFS UnixFS, where a file is its own blocks and a directory names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedSite {
    pub total_len: u64,
    /// Each chunk's length, 1 to [`CHUNK_BYTES`]; they sum to `total_len`.
    pub lens: Vec<u32>,
    pub chunks: Vec<Hash32>,
}

/// What a server hands a reader beside a chunk: the Merkle root over the chunk hashes and the chunk's path to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkProof {
    pub chunks_root: Hash32,
    pub path: Vec<Hash32>,
}

/// What the root binds besides the chunk tree: the length, the chunk count and the digest of the chunk lengths. A
/// reader or a storage checker holding only this and a chunk's path can check one chunk without the whole index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub total_len: u64,
    pub count: u64,
    pub lens_digest: Hash32,
}

fn lens_digest(lens: &[u32]) -> Hash32 {
    let mut buf = Vec::with_capacity(32 + 4 * lens.len());
    buf.extend_from_slice(b"MonerousD Veil chunk lengths v2/");
    for l in lens {
        buf.extend_from_slice(&l.to_le_bytes());
    }
    Hash32::hash(&buf)
}

/// The root a publish anchors: the length, the count, the chunk lengths and the chunk hashes' Merkle root under one
/// domain, so a proof for a site of one shape never verifies for another, and an index that lies about where a chunk
/// starts never matches the root.
fn bind_root(shape: &Shape, chunks_root: &Hash32) -> Hash32 {
    let mut buf = Vec::with_capacity(36 + 8 + 8 + 64);
    buf.extend_from_slice(b"MonerousD Veil chunked site root v2/");
    buf.extend_from_slice(&shape.total_len.to_le_bytes());
    buf.extend_from_slice(&shape.count.to_le_bytes());
    buf.extend_from_slice(shape.lens_digest.as_bytes());
    buf.extend_from_slice(chunks_root.as_bytes());
    Hash32::hash(&buf)
}

impl ChunkedSite {
    /// Cut bytes into chunks: at every file boundary when they are a packed site, else every [`CHUNK_BYTES`]. `None`
    /// for no bytes: there is nothing to publish.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Option<Self> {
        Self::cut_at(bytes, &site_cuts(bytes).unwrap_or_default())
    }

    /// Cut `bytes` at each of `cuts` (offsets inside them, in any order) and every [`CHUNK_BYTES`] after each cut.
    #[must_use]
    pub fn cut_at(bytes: &[u8], cuts: &[u64]) -> Option<Self> {
        let pieces = cut_bounds(bytes.len() as u64, cuts)?;
        let (mut lens, mut chunks) = (Vec::with_capacity(pieces.len()), Vec::with_capacity(pieces.len()));
        for (start, len) in pieces {
            let piece = bytes.get(usize::try_from(start).ok()?..usize::try_from(start + len).ok()?)?;
            lens.push(u32::try_from(len).ok()?);
            chunks.push(chunk_hash(piece));
        }
        Some(ChunkedSite { total_len: bytes.len() as u64, lens, chunks })
    }

    /// The length, count and lengths' digest the root binds.
    #[must_use]
    pub fn shape(&self) -> Shape {
        Shape { total_len: self.total_len, count: self.chunks.len() as u64, lens_digest: lens_digest(&self.lens) }
    }

    /// The value a `SitePublish` anchors for this version.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        bind_root(&self.shape(), &merkle::root(&self.chunks))
    }

    /// The proof a holder serves beside chunk `index`.
    #[must_use]
    pub fn prove(&self, index: u64) -> Option<ChunkProof> {
        let path = merkle::inclusion_proof(&self.chunks, usize::try_from(index).ok()?)?;
        Some(ChunkProof { chunks_root: merkle::root(&self.chunks), path })
    }

    /// Chunk `index`'s length. `None` past the last chunk.
    #[must_use]
    pub fn len_of(&self, index: u64) -> Option<usize> {
        self.lens.get(usize::try_from(index).ok()?).map(|l| *l as usize)
    }

    /// Where each chunk starts in the run, and one past the end: `count + 1` offsets.
    #[must_use]
    pub fn starts(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.lens.len() + 1);
        let mut at = 0u64;
        out.push(0);
        for l in &self.lens {
            at += u64::from(*l);
            out.push(at);
        }
        out
    }

    /// Chunk `index`'s own bytes out of the whole run `bytes` this site was cut from.
    #[must_use]
    pub fn piece<'a>(&self, bytes: &'a [u8], index: u64) -> Option<&'a [u8]> {
        let i = usize::try_from(index).ok()?;
        let start: u64 = self.lens.get(..i)?.iter().map(|l| u64::from(*l)).sum();
        let len = u64::from(*self.lens.get(i)?);
        bytes.get(usize::try_from(start).ok()?..usize::try_from(start + len).ok()?)
    }

    /// Every chunk's bytes out of the whole run, in order.
    pub fn pieces<'a>(&'a self, bytes: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut at = 0usize;
        self.lens.iter().map(move |l| {
            let piece = bytes.get(at..at + *l as usize).unwrap_or(&[]);
            at += *l as usize;
            piece
        })
    }
}

/// `(start, length)` of every chunk of a `total`-byte run cut at `cuts` and every [`CHUNK_BYTES`] after each cut.
/// `None` for an empty run.
fn cut_bounds(total: u64, cuts: &[u64]) -> Option<Vec<(u64, u64)>> {
    if total == 0 {
        return None;
    }
    let mut marks: Vec<u64> = cuts.iter().copied().filter(|c| *c > 0 && *c < total).collect();
    marks.push(total);
    marks.sort_unstable();
    marks.dedup();
    let mut out = Vec::new();
    let mut at = 0u64;
    for end in marks {
        while at < end {
            let len = (end - at).min(CHUNK_BYTES as u64);
            out.push((at, len));
            at += len;
        }
    }
    Some(out)
}

/// Where a packed site's chunks must start: where its header ends and where each of its files starts. `None` when the
/// bytes are not a packed site.
#[must_use]
pub fn site_cuts(bytes: &[u8]) -> Option<Vec<u64>> {
    let header_len = site_header_len(bytes.get(..16)?)?;
    let files = site_files(bytes.get(..usize::try_from(header_len).ok()?)?, bytes.len() as u64)?;
    Some(std::iter::once(header_len).chain(files.into_iter().map(|(_, start, _)| start)).collect())
}

/// THE READER'S CHECK of a served chunk against the root the chain anchors for a site of `shape`: the chunk is at a
/// real index, and its hash (which binds its length) is in the tree the root binds. A node that serves anything else
/// (other bytes, a truncated or padded chunk, the right chunk at the wrong index, a chunk of another site) is refused
/// here, before a byte reaches a page.
#[must_use]
pub fn verify_chunk(root: &Hash32, shape: &Shape, index: u64, chunk: &[u8], proof: &ChunkProof) -> bool {
    let Ok(at) = usize::try_from(index) else {
        return false;
    };
    index < shape.count
        && !chunk.is_empty()
        && chunk.len() <= CHUNK_BYTES
        && bind_root(shape, &proof.chunks_root) == *root
        && merkle::verify(&proof.chunks_root, at, &chunk_hash(chunk), &proof.path)
}

// ── 4. a chunk's hash is a tree over its pieces: holding it can be shown to anyone ────────────────────────────

/// The size of every piece of a chunk but its last: what one storage answer carries.
pub const PIECE_BYTES: usize = 1024;

fn pieces_of(chunk: &[u8]) -> Vec<Hash32> {
    chunk.chunks(PIECE_BYTES).map(Hash32::hash).collect()
}

/// A chunk's hash from its length and the root over its pieces, under one domain: a chunk of one length never hashes
/// as a chunk of another, and a piece tree is never read as a chunk tree.
fn bind_chunk(len: usize, pieces_root: &Hash32) -> Hash32 {
    let mut buf = Vec::with_capacity(32 + 8 + 32);
    buf.extend_from_slice(b"MonerousD Veil chunk v1/");
    buf.extend_from_slice(&(len as u64).to_le_bytes());
    buf.extend_from_slice(pieces_root.as_bytes());
    Hash32::hash(&buf)
}

/// THE ADDRESS OF A CHUNK: what a site's tree holds for it, what a holder files it under, what a reader checks.
#[must_use]
pub fn chunk_hash(chunk: &[u8]) -> Hash32 {
    bind_chunk(chunk.len(), &merkle::root(&pieces_of(chunk)))
}

/// A holder's answer to one storage challenge: one piece of the challenged chunk and its way up to the site's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageAnswer {
    /// The site's shape, as its root binds it: the checker needs nothing else of the site.
    pub shape: Shape,
    pub index: u64,
    /// The challenged chunk's length (its hash binds it, so a holder cannot name another).
    pub len: u32,
    pub piece: u64,
    pub bytes: Vec<u8>,
    pub pieces_root: Hash32,
    pub piece_path: Vec<Hash32>,
    pub proof: ChunkProof,
}

fn draw(block: &Hash32, root: &Hash32, holder: &str, what: &[u8], below: u64) -> u64 {
    let mut buf = Vec::with_capacity(48 + 64 + holder.len() + what.len());
    buf.extend_from_slice(b"MonerousD Veil storage challenge v1/");
    buf.extend_from_slice(block.as_bytes());
    buf.extend_from_slice(root.as_bytes());
    buf.extend_from_slice(&(holder.len() as u64).to_le_bytes());
    buf.extend_from_slice(holder.as_bytes());
    buf.extend_from_slice(what);
    let h = Hash32::hash(&buf);
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&h.as_bytes()[..8]);
    // the bias of a 64-bit draw below a count of chunks or pieces is under 2^-40
    u64::from_le_bytes(eight) % below.max(1)
}

/// WHICH PART a holder must show for a site at one block: a chunk drawn from the block hash (the same for every
/// holder, so the chunk's holders are the ones asked) and a piece of it drawn per holder (so one holder's answer is
/// not another's). `None` for a site with no bytes.
#[must_use]
pub fn storage_challenge(block: &Hash32, root: &Hash32, site: &ChunkedSite, holder: &str) -> Option<(u64, u64)> {
    let index = challenged_chunk(block, root, site.chunks.len() as u64)?;
    Some((index, challenged_piece(block, root, holder, site.len_of(index)?)))
}

/// The chunk `block` challenges in a site of `count` chunks.
fn challenged_chunk(block: &Hash32, root: &Hash32, count: u64) -> Option<u64> {
    (count > 0).then(|| draw(block, root, "", b"chunk", count))
}

/// The piece `block` challenges `holder` for in a chunk of `len` bytes.
fn challenged_piece(block: &Hash32, root: &Hash32, holder: &str, len: usize) -> u64 {
    draw(block, root, holder, b"piece", (len as u64).div_ceil(PIECE_BYTES as u64))
}

/// HOLDER: answer the challenge for `holder` at `block` from the chunk's own bytes. `None` when `chunk` is not the
/// challenged chunk of this site.
#[must_use]
pub fn answer_storage(site: &ChunkedSite, block: &Hash32, holder: &str, chunk: &[u8]) -> Option<StorageAnswer> {
    let (index, piece) = storage_challenge(block, &site.root(), site, holder)?;
    if site.chunks.get(usize::try_from(index).ok()?) != Some(&chunk_hash(chunk)) {
        return None;
    }
    let pieces = pieces_of(chunk);
    let at = usize::try_from(piece).ok()?;
    Some(StorageAnswer {
        shape: site.shape(),
        index,
        len: u32::try_from(chunk.len()).ok()?,
        piece,
        bytes: chunk.chunks(PIECE_BYTES).nth(at)?.to_vec(),
        pieces_root: merkle::root(&pieces),
        piece_path: merkle::inclusion_proof(&pieces, at)?,
        proof: site.prove(index)?,
    })
}

/// ANY NODE: is this the answer `holder` owes for the site at `block`? It names the challenged chunk and piece, the
/// piece has exactly the length that place must have, and it opens to the chunk's hash, which opens to the root the
/// chain anchors. A holder that kept only hashes, another piece, another chunk or another site's bytes is refused.
#[must_use]
pub fn verify_storage(root: &Hash32, block: &Hash32, holder: &str, a: &StorageAnswer) -> bool {
    let len = a.len as usize;
    if len == 0 || len > CHUNK_BYTES {
        return false;
    }
    let Some(index) = challenged_chunk(block, root, a.shape.count) else {
        return false;
    };
    let piece = challenged_piece(block, root, holder, len);
    let (Ok(piece_at), Ok(chunk_at)) = (usize::try_from(piece), usize::try_from(index)) else {
        return false;
    };
    let last = len.div_ceil(PIECE_BYTES) - 1;
    let want = if piece_at < last { PIECE_BYTES } else { len - last * PIECE_BYTES };
    // the shape is the root's (so the count the chunk was drawn below is the site's), and the length named is the one
    // the tree's leaf at that index binds: a holder can choose neither
    (a.index, a.piece) == (index, piece)
        && a.bytes.len() == want
        && merkle::verify(&a.pieces_root, piece_at, &Hash32::hash(&a.bytes), &a.piece_path)
        && bind_root(&a.shape, &a.proof.chunks_root) == *root
        && merkle::verify(&a.proof.chunks_root, chunk_at, &bind_chunk(len, &a.pieces_root), &a.proof.path)
}

// ── 5. chunks on disk, in one file of constant size ─────────────────────────────────────────────────────────

/// The store holds chunk data in pages of this size: a chunk takes the pages it fills and no more, so a 3 KB file is
/// one page of the store, never a whole chunk's room. BORROWED: a filesystem's 4 KiB block.
pub const PAGE_BYTES: usize = 4096;
/// One page's entry in the store's table: the chunk's hash, its length, its flags (own shard's, a site's head, paid;
/// read from the chunk's first page) and which page of the chunk this is.
const PAGE_HEAD: usize = 40;
/// The store file starts with this, so a file written in another layout is never read as pages.
const STORE_MAGIC: &[u8; 8] = b"MUDPAGE1";
const STORE_HEAD: u64 = 4096;

const fn pages_for(len: usize) -> usize {
    len.div_ceil(PAGE_BYTES)
}

/// The budget a store needs to hold `chunks` chunks of `len` bytes each.
#[must_use]
pub const fn store_bytes_for(chunks: u64, len: usize) -> u64 {
    STORE_HEAD + chunks * pages_for(len) as u64 * (PAGE_HEAD + PAGE_BYTES) as u64
}

/// One held chunk: its length, its pages in order, and why it is kept.
#[derive(Clone, Debug)]
struct Held {
    len: u32,
    pages: Vec<u32>,
    mine: bool,
    index: bool,
    paid: bool,
    age: u64,
}

impl Held {
    fn flags(&self) -> u8 {
        u8::from(self.mine) | (u8::from(self.index) << 1) | (u8::from(self.paid) << 2)
    }

    /// The order chunks give up their pages in: a reader's cached chunk first, then this node's own that nobody paid
    /// for, then a paid chunk held for a reader, and a paid chunk of this node's own last of all; the oldest first in
    /// each.
    fn rank(&self) -> (u8, u64) {
        (u8::from(self.paid) * 2 + u8::from(self.mine || self.index), self.age)
    }
}

/// A node's site chunks: ONE file of a constant size the node's operator chose. Its head is a table of one entry per
/// page; after it come the pages. A chunk takes `ceil(len / 4 KiB)` pages wherever they are free, so the store holds
/// as many bytes of small files as of large ones. Nothing is dropped while pages are free; with too few free, whole
/// chunks give their pages up in [`Held::rank`] order. A chunk read back is hashed again, so a rotted page is a
/// missing chunk, never a wrong one; a chunk whose pages a crash left half-written is missing at the next open.
///
/// LOCAL-STORAGE-REQUIRED: a website's bytes are not chain state and no proof, frontier or DA record regenerates them:
/// the chain anchors the root, and a publisher pays holders to keep the bytes the root names. Nothing a node needs to
/// follow the chain, verify a block or serve a wallet is ever read from this file.
/// bound: one file of exactly the operator's budget rounded down to whole pages (default 512 MB), preallocated and
/// never grown: no term in height, blocks, notes or sites. No file is named after an item.
/// O1-FOOTPRINT-REVIEWED: RAM is one free-list word per free page and one entry per held chunk (at most one per page,
/// `budget / 4,136`), rebuilt from the table at open; the table is 1% of the budget and read in one pass.
pub struct ChunkStore {
    file: std::fs::File,
    pages: u32,
    free: Vec<u32>,
    held: std::collections::HashMap<Hash32, Held>,
    clock: u64,
}

impl ChunkStore {
    fn data_at(pages: u32) -> u64 {
        STORE_HEAD + u64::from(pages) * PAGE_HEAD as u64
    }

    fn page_offset(&self, page: u32) -> u64 {
        Self::data_at(self.pages) + u64::from(page) * PAGE_BYTES as u64
    }

    fn entry_offset(page: u32) -> u64 {
        STORE_HEAD + u64::from(page) * PAGE_HEAD as u64
    }

    /// Open the store file at `path` with room for `budget` bytes. Chunks already written whole are taken back as
    /// cached chunks with the flags they were written with (a node learns which are its own shard's when it next
    /// computes its shards). A file that is not a page store is emptied.
    pub fn open(path: &std::path::Path, budget: u64) -> std::io::Result<ChunkStore> {
        use std::io::{Read as _, Seek as _, Write as _};
        let pages = u32::try_from(budget.saturating_sub(STORE_HEAD) / (PAGE_HEAD + PAGE_BYTES) as u64).unwrap_or(u32::MAX);
        let mut file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut magic = [0u8; 8];
        let ours = file.read_exact(&mut magic).is_ok() && magic == *STORE_MAGIC;
        if !ours {
            // another layout (or nothing): every table entry reads empty
            file.set_len(0)?;
        }
        file.set_len(Self::data_at(pages) + u64::from(pages) * PAGE_BYTES as u64)?;
        if !ours {
            file.seek(std::io::SeekFrom::Start(0))?;
            file.write_all(STORE_MAGIC)?;
        }
        let mut table = vec![0u8; pages as usize * PAGE_HEAD];
        file.seek(std::io::SeekFrom::Start(STORE_HEAD))?;
        file.read_exact(&mut table)?;
        // gather each chunk's pages by ordinal; a chunk is held only with every page present exactly once
        let mut found: std::collections::HashMap<Hash32, (u32, u8, Vec<Option<u32>>, bool)> = std::collections::HashMap::new();
        for page in 0..pages {
            let e = &table[page as usize * PAGE_HEAD..(page as usize + 1) * PAGE_HEAD];
            let len = u32::from_le_bytes([e[32], e[33], e[34], e[35]]);
            if len == 0 || len as usize > CHUNK_BYTES {
                continue;
            }
            let ordinal = usize::from(u16::from_le_bytes([e[37], e[38]]));
            let mut h = [0u8; 32];
            h.copy_from_slice(&e[..32]);
            let need = pages_for(len as usize);
            let slot = found.entry(Hash32(h)).or_insert_with(|| (len, 0, vec![None; need], true));
            if slot.0 != len || ordinal >= need || slot.2[ordinal].is_some() {
                slot.3 = false;
                continue;
            }
            if ordinal == 0 {
                slot.1 = e[36];
            }
            slot.2[ordinal] = Some(page);
        }
        let mut s = ChunkStore { file, pages, free: Vec::new(), held: std::collections::HashMap::new(), clock: 0 };
        let mut taken = vec![false; pages as usize];
        for (hash, (len, flags, list, ok)) in found {
            let Some(list) = list.into_iter().collect::<Option<Vec<u32>>>().filter(|_| ok) else { continue };
            for p in &list {
                taken[*p as usize] = true;
            }
            s.clock += 1;
            s.held.insert(hash, Held { len, pages: list, mine: flags & 1 != 0, index: flags & 2 != 0, paid: flags & 4 != 0, age: s.clock });
        }
        // free pages are handed out lowest first, so a chunk written into an empty store is one run
        s.free = (0..pages).rev().filter(|p| !taken[*p as usize]).collect();
        Ok(s)
    }

    /// Bytes of chunks held now.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.held.values().map(|h| u64::from(h.len)).sum()
    }

    /// Bytes of the store's pages that held chunks take (whole pages): what `used` costs the budget.
    #[must_use]
    pub fn used_pages_bytes(&self) -> u64 {
        self.held.values().map(|h| h.pages.len() as u64 * PAGE_BYTES as u64).sum()
    }

    #[must_use]
    pub fn holds(&self, hash: &Hash32) -> bool {
        self.held.contains_key(hash)
    }

    fn write_entry(&mut self, page: u32, hash: &Hash32, len: u32, flags: u8, ordinal: u16) -> std::io::Result<()> {
        use std::io::{Seek as _, Write as _};
        let mut e = [0u8; PAGE_HEAD];
        e[..32].copy_from_slice(hash.as_bytes());
        e[32..36].copy_from_slice(&len.to_le_bytes());
        e[36] = flags;
        e[37..39].copy_from_slice(&ordinal.to_le_bytes());
        self.file.seek(std::io::SeekFrom::Start(Self::entry_offset(page)))?;
        self.file.write_all(&e)
    }

    /// Rewrite the flags byte of a held chunk's first page, so a reopen keeps them.
    fn write_flags(&mut self, hash: &Hash32) {
        use std::io::{Seek as _, Write as _};
        let Some((page, flags)) = self.held.get(hash).map(|h| (h.pages[0], h.flags())) else { return };
        let _ = self.file.seek(std::io::SeekFrom::Start(Self::entry_offset(page) + 36)).and_then(|_| self.file.write_all(&[flags]));
    }

    /// Give a held chunk's pages back: every one of its entries reads empty from here on, after a reopen too (so the
    /// same chunk written again elsewhere is never seen twice).
    fn release(&mut self, hash: &Hash32) {
        use std::io::{Seek as _, Write as _};
        if let Some(h) = self.held.remove(hash) {
            for page in &h.pages {
                let _ = self.file.seek(std::io::SeekFrom::Start(Self::entry_offset(*page) + 32)).and_then(|_| self.file.write_all(&[0u8; 4]));
            }
            self.free.extend(h.pages.iter().rev());
        }
    }

    /// Keep a chunk. `mine` says it is one of this node's own shard's (kept longest). Returns its hash, or an error
    /// when the store cannot make room for it at all.
    pub fn put(&mut self, chunk: &[u8], mine: bool) -> std::io::Result<Hash32> {
        self.put_kind(chunk, mine, false)
    }

    /// [`Self::put`], or with `index` a site's index: kept as this node's own and found again at open.
    pub fn put_kind(&mut self, chunk: &[u8], mine: bool, index: bool) -> std::io::Result<Hash32> {
        use std::io::{Seek as _, Write as _};
        let mine = mine || index;
        if chunk.is_empty() || chunk.len() > CHUNK_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a chunk"));
        }
        let hash = chunk_hash(chunk);
        if let Some(h) = self.held.get_mut(&hash) {
            if mine && !h.mine {
                h.mine = true;
                self.write_flags(&hash);
            }
            return Ok(hash);
        }
        let need = pages_for(chunk.len());
        if need > self.pages as usize {
            return Err(std::io::Error::new(std::io::ErrorKind::StorageFull, "this node's site store has no room"));
        }
        if self.free.len() < need {
            // whole chunks give their pages up, lowest rank first, until there is room
            let mut order: Vec<((u8, u64), Hash32)> = self.held.iter().map(|(k, h)| (h.rank(), *k)).collect();
            order.sort_unstable();
            for (_, victim) in order {
                if self.free.len() >= need {
                    break;
                }
                self.release(&victim);
            }
        }
        if self.free.len() < need {
            return Err(std::io::Error::new(std::io::ErrorKind::StorageFull, "this node's site store has no room"));
        }
        let pages: Vec<u32> = (0..need).filter_map(|_| self.free.pop()).collect();
        let held = Held { len: chunk.len() as u32, pages, mine, index, paid: false, age: 0 };
        let flags = held.flags();
        for (k, page) in held.pages.iter().enumerate() {
            let data = &chunk[k * PAGE_BYTES..((k + 1) * PAGE_BYTES).min(chunk.len())];
            let at = self.page_offset(*page);
            self.file.seek(std::io::SeekFrom::Start(at))?;
            self.file.write_all(data)?;
        }
        // the entries last: a crash before them leaves the pages unclaimed
        for (k, page) in held.pages.clone().into_iter().enumerate() {
            self.write_entry(page, &hash, held.len, flags, k as u16)?;
        }
        self.clock += 1;
        self.held.insert(hash, Held { age: self.clock, ..held });
        Ok(hash)
    }

    /// A chunk's bytes, hashed again on the way out: a chunk that no longer hashes to its name gives its pages up and
    /// reads as missing.
    pub fn get(&mut self, hash: &Hash32) -> Option<Vec<u8>> {
        use std::io::{Read as _, Seek as _};
        let (len, pages) = self.held.get(hash).map(|h| (h.len as usize, h.pages.clone()))?;
        let mut bytes = vec![0u8; len];
        let mut ok = true;
        for (k, page) in pages.iter().enumerate() {
            let at = self.page_offset(*page);
            let part = &mut bytes[k * PAGE_BYTES..((k + 1) * PAGE_BYTES).min(len)];
            if self.file.seek(std::io::SeekFrom::Start(at)).and_then(|_| self.file.read_exact(part)).is_err() {
                ok = false;
                break;
            }
        }
        if ok && chunk_hash(&bytes) == *hash {
            return Some(bytes);
        }
        self.release(hash);
        None
    }

    /// A publisher paid this node to keep this chunk: it gives its pages up last, after a reopen too.
    ///
    /// LOCAL-STORAGE-REQUIRED: the same one file as every other write of this store (see [`ChunkStore`]): one byte of
    /// one table entry is rewritten in place.
    /// bound: one byte overwritten inside the store's constant-size file; the file never grows.
    pub fn mark_paid(&mut self, hash: &Hash32) {
        if let Some(h) = self.held.get_mut(hash).filter(|h| !h.paid) {
            h.paid = true;
            self.write_flags(hash);
        }
    }

    /// Nobody pays this node to keep this chunk any longer, and it is not its own shard's (it belonged only to a
    /// version its site replaced): it is an ordinary cached chunk from here on, first to give its pages up.
    ///
    /// LOCAL-STORAGE-REQUIRED: one byte of one table entry rewritten in place (see [`ChunkStore`]).
    /// bound: one byte overwritten inside the store's constant-size file; the file never grows.
    pub fn demote(&mut self, hash: &Hash32) {
        if let Some(h) = self.held.get_mut(hash).filter(|h| h.paid || h.mine) {
            h.paid = false;
            h.mine = false;
            self.write_flags(hash);
        }
    }

    #[must_use]
    pub fn is_paid(&self, hash: &Hash32) -> bool {
        self.held.get(hash).is_some_and(|h| h.paid)
    }

    /// Give a chunk's pages up now (an older version's head). It reads as absent from here on, after a reopen too.
    ///
    /// LOCAL-STORAGE-REQUIRED: the same one file as every other write of this store (see [`ChunkStore`]): four bytes of
    /// one table entry are zeroed in place so a reopened store does not list a head its site replaced.
    /// bound: four bytes overwritten inside the store's constant-size file; the file never grows.
    pub fn forget(&mut self, hash: &Hash32) {
        self.release(hash);
    }

    /// Every site head this store holds, read back and checked.
    pub fn index_blobs(&mut self) -> Vec<Vec<u8>> {
        let hashes: Vec<Hash32> = self.held.iter().filter(|(_, h)| h.index).map(|(k, _)| *k).collect();
        hashes.iter().filter_map(|h| self.get(h)).collect()
    }

    /// Say which held chunks are this node's own shard's now (its shards change as nodes join and leave).
    pub fn mark_mine(&mut self, mine: impl Fn(&Hash32) -> bool) {
        for (k, h) in &mut self.held {
            h.mine = h.index || mine(k);
        }
    }
}

// ── 6. a read the server cannot see ─────────────────────────────────────────────────────────────────────────

/// A bucket is `2^BUCKET_DEPTH` chunk slots whose contents are public; a read hides which slot was wanted.
// PRODUCTION-SCALE-REVIEWED: the spec's bucket (1,024 chunks, 256 MB): the size one linear pass serves in about a
// tenth of a second; a larger store is more buckets, never a larger one.
pub const BUCKET_DEPTH: usize = 10;

/// READER: the two keys that ask for `slot` of a bucket, one for each of two servers that do not share them. `random`
/// is 64 fresh bytes from the OS. `None` for a slot outside the bucket.
#[must_use]
pub fn pir_query(slot: u64, random: &[u8; 2 * crate::pqmix::dpf::SEED]) -> Option<(crate::pqmix::dpf::Key, crate::pqmix::dpf::Key)> {
    crate::pqmix::dpf::gen(slot, &[1], BUCKET_DEPTH, random)
}

/// SERVER: the answer to one key over this server's copy of the bucket: the XOR of every chunk the key selects, each
/// padded to a whole chunk. EVERY slot is evaluated and read and none is skipped, so the work says nothing about the
/// slot asked for; a slot this server has no chunk for (`None`) adds nothing. `chunk_at` reads a slot's chunk.
#[must_use]
pub fn pir_answer(key: &crate::pqmix::dpf::Key, mut chunk_at: impl FnMut(u64) -> Option<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![0u8; CHUNK_BYTES];
    for slot in 0..1u64 << BUCKET_DEPTH {
        let selected = crate::pqmix::dpf::eval(key, slot).first().is_some_and(|b| b & 1 == 1);
        let chunk = chunk_at(slot);
        if let (true, Some(chunk)) = (selected, chunk) {
            for (o, c) in out.iter_mut().zip(&chunk) {
                *o ^= c;
            }
        }
    }
    out
}

/// READER: the wanted chunk from the two servers' answers, cut to the length its place in the site must have. The
/// result is checked with [`verify_chunk`] before a byte of it is used: a server that answered wrong is caught there.
#[must_use]
pub fn pir_combine(a: &[u8], b: &[u8], len: usize) -> Option<Vec<u8>> {
    (a.len() == CHUNK_BYTES && b.len() == CHUNK_BYTES && len <= CHUNK_BYTES).then(|| a.iter().zip(b).take(len).map(|(x, y)| x ^ y).collect())
}

// ── 7. the price ────────────────────────────────────────────────────────────────────────────────────────────

/// What storing one megabyte costs, once, in atomic USDm (1 USDm = 10^8): the spec's $0.50.
pub const STORAGE_ATOMIC_PER_MB: u64 = 50_000_000;

/// The bytes of `new` that no chunk of `old` already holds: an update pays for these alone.
#[must_use]
pub fn new_bytes(old: Option<&ChunkedSite>, new: &ChunkedSite) -> u64 {
    let have: std::collections::HashSet<&Hash32> = old.map(|o| o.chunks.iter().collect()).unwrap_or_default();
    new.bytes_not_in(|c| have.contains(c))
}

/// The one-time storage price of `bytes`, rounded up to the atomic unit: shown in dollars before Publish.
#[must_use]
pub fn storage_price_atomic(bytes: u64) -> u64 {
    u64::try_from((u128::from(bytes) * u128::from(STORAGE_ATOMIC_PER_MB)).div_ceil(1 << 20)).unwrap_or(u64::MAX)
}

// ── 8. a site's bytes: one packed run, its index, and a node that hosts it ───────────────────────────────────

/// A packed site starts with this, then the header's length, the file count, and one entry per file.
const SITE_MAGIC: &[u8; 8] = b"MUDSITE1";
/// The most files one site lists: a bound on the header a reader parses.
// PRODUCTION-SCALE-REVIEWED: a bound on ONE site's header (about 1 MB at most); a site with more files is two sites.
pub const MAX_SITE_FILES: usize = 4096;

/// Is this a path a site may hold: relative, plain, no step up or sideways?
#[must_use]
pub fn site_path_ok(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
}

/// PUBLISHER: a site's files as ONE run of bytes, the same bytes whoever packs them: files in path order, a header
/// that says where each one sits, then the files end to end. `None` for no files, too many, a repeated path or a
/// path [`site_path_ok`] refuses.
#[must_use]
pub fn pack_site(files: &[(String, Vec<u8>)]) -> Option<Vec<u8>> {
    let mut sorted: Vec<&(String, Vec<u8>)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.is_empty() || sorted.len() > MAX_SITE_FILES || sorted.windows(2).any(|w| w[0].0 == w[1].0) || !sorted.iter().all(|f| site_path_ok(&f.0)) {
        return None;
    }
    let mut entries = Vec::new();
    let mut offset = 0u64;
    for f in &sorted {
        entries.extend_from_slice(&(f.0.len() as u16).to_le_bytes());
        entries.extend_from_slice(f.0.as_bytes());
        entries.extend_from_slice(&offset.to_le_bytes());
        entries.extend_from_slice(&(f.1.len() as u64).to_le_bytes());
        offset += f.1.len() as u64;
    }
    let mut out = Vec::with_capacity(16 + entries.len() + offset as usize);
    out.extend_from_slice(SITE_MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    out.extend_from_slice(&entries);
    for f in &sorted {
        out.extend_from_slice(&f.1);
    }
    Some(out)
}

/// How long a packed site's header is, from its first sixteen bytes. `None` when they are not a site's.
#[must_use]
pub fn site_header_len(first: &[u8]) -> Option<u64> {
    let entries = u32::from_le_bytes(first.get(8..12)?.try_into().ok()?);
    let count = u32::from_le_bytes(first.get(12..16)?.try_into().ok()?) as usize;
    (first.get(..8)? == SITE_MAGIC && count >= 1 && count <= MAX_SITE_FILES && entries as usize <= count * (2 + 255 + 16)).then_some(16 + u64::from(entries))
}

/// READER: the files a packed site's header lists, each as `(path, where its bytes start in the run, its length)`.
/// `None` for a header that is not whole and exact, or that names a path twice, out of order or out of bounds.
#[must_use]
pub fn site_files(header: &[u8], total_len: u64) -> Option<Vec<(String, u64, u64)>> {
    let data = site_header_len(header)?;
    if header.len() as u64 != data {
        return None;
    }
    let count = u32::from_le_bytes(header[12..16].try_into().ok()?) as usize;
    let mut at = 16usize;
    let mut files: Vec<(String, u64, u64)> = Vec::with_capacity(count);
    let mut next = 0u64;
    for _ in 0..count {
        let n = u16::from_le_bytes(header.get(at..at + 2)?.try_into().ok()?) as usize;
        let path = std::str::from_utf8(header.get(at + 2..at + 2 + n)?).ok()?.to_string();
        let offset = u64::from_le_bytes(header.get(at + 2 + n..at + 10 + n)?.try_into().ok()?);
        let len = u64::from_le_bytes(header.get(at + 10 + n..at + 18 + n)?.try_into().ok()?);
        at += 18 + n;
        // files sit end to end in path order: an entry that says otherwise is not a packed site
        if !site_path_ok(&path) || offset != next || files.last().is_some_and(|(p, ..)| *p >= path) {
            return None;
        }
        next = offset.checked_add(len)?;
        files.push((path, data + offset, len));
    }
    (at == header.len() && data.checked_add(next)? == total_len).then_some(files)
}

impl ChunkedSite {
    /// A site's index: its length, its chunk count, and each chunk's length and hash. Whoever holds it finds every
    /// chunk by hash and every byte by offset.
    #[must_use]
    pub fn index_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INDEX_HEAD + INDEX_ENTRY * self.chunks.len());
        out.extend_from_slice(&self.total_len.to_le_bytes());
        out.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        for (l, c) in self.lens.iter().zip(&self.chunks) {
            out.extend_from_slice(&l.to_le_bytes());
            out.extend_from_slice(c.as_bytes());
        }
        out
    }

    /// An index read back. `None` unless it is exactly a length, a count and that many chunks, each 1 to
    /// [`CHUNK_BYTES`] long and together exactly the length, and fits one chunk.
    #[must_use]
    pub fn from_index(bytes: &[u8]) -> Option<ChunkedSite> {
        let total_len = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        let count = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
        if total_len == 0 || count == 0 || bytes.len() > CHUNK_BYTES || bytes.len() != index_len(count)? {
            return None;
        }
        let (mut lens, mut chunks, mut sum) = (Vec::with_capacity(count), Vec::with_capacity(count), 0u64);
        for e in bytes[INDEX_HEAD..].chunks_exact(INDEX_ENTRY) {
            let l = u32::from_le_bytes(e[..4].try_into().ok()?);
            if l == 0 || l as usize > CHUNK_BYTES {
                return None;
            }
            sum = sum.checked_add(u64::from(l))?;
            lens.push(l);
            chunks.push(Hash32::from_slice(&e[4..])?);
        }
        (sum == total_len).then_some(ChunkedSite { total_len, lens, chunks })
    }
}

const INDEX_HEAD: usize = 12;
const INDEX_ENTRY: usize = 36;

/// How long the index of a site of `count` chunks is. `None` past what one chunk holds.
#[must_use]
pub fn index_len(count: usize) -> Option<usize> {
    count.checked_mul(INDEX_ENTRY)?.checked_add(INDEX_HEAD).filter(|l| *l <= CHUNK_BYTES)
}

impl ChunkedSite {
    /// The bytes of the chunks whose hash `held` does not know: what a store holding those must add.
    #[must_use]
    pub fn bytes_not_in(&self, held: impl Fn(&Hash32) -> bool) -> u64 {
        let mut seen = std::collections::HashSet::new();
        self.lens.iter().zip(&self.chunks).filter(|(_, c)| !held(c) && seen.insert(**c)).map(|(l, _)| u64::from(*l)).sum()
    }
}

/// What a read of a hosted site is missing here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gap {
    /// The site's index.
    Index,
    /// These chunks.
    Chunks(Vec<u64>),
}

/// How long a frame this node passed on (or a request it answered) is remembered, so it is not passed on again.
const RECENT_SECS: u64 = 30;
/// What a node passes on per second, and how much at once: a bound on what a flood of real site bytes costs every
/// other node. BORROWED: Bitcoin Core's relay rate limits. A frame over the bound is dropped and asked for again by
/// whoever still wants it.
// PRODUCTION-SCALE-REVIEWED: a relay bound on free site bytes (about 7.5 MB a minute per node, bursts of 4 MB: a
// typical 2 MB site passes at once); it never refuses a payment, a block or a stored chunk.
const RELAY_BYTES_PER_SEC: u64 = 128 * 1024;
const RELAY_BURST: u64 = 4 * 1024 * 1024;

/// A site's HEAD is what a node keeps to know the site again after a restart: the signed publish that anchors its
/// root, and its index. One slot of the store. The publish is checked again by the node when it is read back, so the
/// file is never an authority: it is a copy of records their owners signed.
const HEAD_MAGIC: &[u8; 8] = b"MUDHEAD1";

/// The top bit of a head's publish length says a publisher paid this node to keep the site.
const HEAD_PAID: u32 = 1 << 31;

fn head_blob(publish: &[u8], index: &[u8], paid: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + publish.len() + index.len());
    out.extend_from_slice(HEAD_MAGIC);
    out.extend_from_slice(&(publish.len() as u32 | if paid { HEAD_PAID } else { 0 }).to_le_bytes());
    out.extend_from_slice(publish);
    out.extend_from_slice(index);
    out
}

/// A head's signed publish (empty for bytes kept on payment alone), its index, and whether it is paid.
fn head_parts(blob: &[u8]) -> Option<(&[u8], &[u8], bool)> {
    let word = u32::from_le_bytes(blob.get(8..12)?.try_into().ok()?);
    let n = (word & !HEAD_PAID) as usize;
    (blob.get(..8)? == HEAD_MAGIC).then_some(())?;
    Some((blob.get(12..12 + n)?, blob.get(12 + n..)?, word & HEAD_PAID != 0))
}

fn site_id_of(publish: &[u8]) -> Option<Hash32> {
    crate::site::SiteGossip::from_wire(publish).map(|g| g.publish.site_id)
}

/// A node's hosted sites: the chunk store, each site's index by its root, and what was passed on lately.
pub struct SiteHost {
    chunks: ChunkStore,
    /// root → the signed publish that anchors it, as it travelled: for the sites held, and for publishes this node
    /// adopted whose index has not arrived yet.
    publishes: std::collections::HashMap<Hash32, Vec<u8>>,
    /// root → where that site's head sits in the store.
    heads: std::collections::HashMap<Hash32, Hash32>,
    sites: std::collections::HashMap<Hash32, ChunkedSite>,
    /// The roots a publisher paid THIS node to keep ([`crate::veil_lane`], the payment).
    paid: std::collections::HashSet<Hash32>,
    /// Payments this node was told of and has not seen on the chain yet: the note commitment to look for → the root
    /// it pays for and how many bytes of it (an update pays for its new bytes alone). A short memory.
    claims: std::collections::HashMap<[u8; 32], (Hash32, u64)>,
    /// Payments the chain has shown for a root whose index is not here yet: root → the bytes paid for. Judged when
    /// the index arrives. A short memory.
    paid_ahead: std::collections::HashMap<Hash32, u64>,
    recent: std::collections::HashMap<Hash32, std::time::Instant>,
    budget: u64,
    allowance: u64,
    refilled: std::time::Instant,
}

impl SiteHost {
    /// Open the host over the store file at `path`. The sites it knows are the indexes the store holds.
    pub fn open(path: &std::path::Path, budget: u64) -> std::io::Result<SiteHost> {
        let mut chunks = ChunkStore::open(path, budget)?;
        let (mut sites, mut publishes, mut heads, mut paid) = (std::collections::HashMap::new(), std::collections::HashMap::new(), std::collections::HashMap::new(), std::collections::HashSet::new());
        for blob in chunks.index_blobs() {
            let Some((publish, index, is_paid)) = head_parts(&blob) else { continue };
            let Some(site) = ChunkedSite::from_index(index) else { continue };
            let root = site.root();
            heads.insert(root, chunk_hash(&blob));
            if !publish.is_empty() {
                publishes.insert(root, publish.to_vec());
            }
            if is_paid {
                paid.insert(root);
            }
            sites.insert(root, site);
        }
        Ok(SiteHost {
            chunks,
            publishes,
            heads,
            sites,
            paid,
            claims: std::collections::HashMap::new(),
            paid_ahead: std::collections::HashMap::new(),
            recent: std::collections::HashMap::new(),
            budget,
            allowance: RELAY_BURST,
            refilled: std::time::Instant::now(),
        })
    }

    #[must_use]
    pub fn knows(&self, root: &Hash32) -> bool {
        self.sites.contains_key(root)
    }

    /// The node adopted a signed publish for `root`: remember it as it travelled, so the site's head can be kept with
    /// it when the index arrives. A short memory: publishes whose index never comes are dropped when it fills.
    pub fn note_publish(&mut self, root: &Hash32, publish: &[u8]) {
        // PRODUCTION-SCALE-REVIEWED: how many adopted publishes wait for their index at once; a waiting one costs
        // about 5 KB of RAM and is dropped, never refused, when the memory fills.
        if self.publishes.len() >= 1024 + self.sites.len() {
            let held = &self.sites;
            self.publishes.retain(|r, _| held.contains_key(r));
        }
        self.publishes.entry(*root).or_insert_with(|| publish.to_vec());
    }

    /// The signed publishes of the sites this node holds: what it re-adopts at boot and offers to peers that missed
    /// them.
    #[must_use]
    pub fn stored_publishes(&self) -> Vec<Vec<u8>> {
        self.sites.keys().filter_map(|r| self.publishes.get(r).filter(|p| !p.is_empty()).cloned()).collect()
    }

    /// Take a site's index. True when it is the index `root` binds and it is held (now or already). The index is kept
    /// WITH the signed publish that anchors it, so only a site whose publish this node adopted is taken.
    pub fn put_index(&mut self, root: &Hash32, bytes: &[u8]) -> bool {
        self.put_index_as(root, bytes, false)
    }

    /// [`Self::put_index`] for an index this node's own wallet asked to READ (`crate::veil_lane`): checked against the
    /// root like any other, and kept as a reader's copy with or without a publish.
    pub fn put_read_index(&mut self, root: &Hash32, bytes: &[u8]) -> bool {
        self.put_index_as(root, bytes, true)
    }

    fn put_index_as(&mut self, root: &Hash32, bytes: &[u8], read: bool) -> bool {
        let Some(site) = ChunkedSite::from_index(bytes).filter(|s| s.root() == *root) else {
            return false;
        };
        if self.sites.contains_key(root) {
            return true;
        }
        // kept with the publish that anchors it; bytes a publisher paid this node for need no name and no publish
        let publish = match self.publishes.get(root) {
            Some(p) => p.clone(),
            None if read || self.accepts(root) => Vec::new(),
            None => return false,
        };
        // a payment seen before the index: it is good when it covers every byte of this version nobody paid this node
        // for already (an update pays for its new chunks alone)
        if let Some(paid_len) = self.paid_ahead.remove(root) {
            if self.unpaid_bytes(&site) <= paid_len {
                self.paid.insert(*root);
            }
        }
        let paid = self.paid.contains(root);
        let head = head_blob(&publish, bytes, paid);
        let Ok(head_hash) = self.chunks.put_kind(&head, true, true) else {
            return false;
        };
        if paid {
            self.chunks.mark_paid(&head_hash);
        }
        // an older version of the SAME site gives its head up: the name shows one version. Its chunks that the new
        // version still names stay as they are (an update stores only what changed); the ones only it named become
        // ordinary cached chunks, first to give their pages up, so an update never leaves the old bytes kept
        if let Some(id) = site_id_of(&publish) {
            let old: Vec<Hash32> = self.heads.keys().filter(|r| **r != *root && self.publishes.get(*r).and_then(|p| site_id_of(p)) == Some(id)).copied().collect();
            let mut dropped: Vec<Hash32> = Vec::new();
            for r in old {
                if let Some(h) = self.heads.remove(&r) {
                    self.chunks.forget(&h);
                }
                if let Some(s) = self.sites.remove(&r) {
                    dropped.extend(s.chunks);
                }
                self.publishes.remove(&r);
            }
            if !dropped.is_empty() {
                let named: std::collections::HashSet<Hash32> = site.chunks.iter().chain(self.sites.values().flat_map(|s| s.chunks.iter())).copied().collect();
                for c in dropped.iter().filter(|c| !named.contains(c)) {
                    self.chunks.demote(c);
                }
            }
        }
        self.heads.insert(*root, head_hash);
        if paid {
            for chunk in &site.chunks {
                self.chunks.mark_paid(chunk);
            }
        }
        self.sites.insert(*root, site);
        true
    }

    #[must_use]
    pub fn index(&self, root: &Hash32) -> Option<Vec<u8>> {
        self.sites.get(root).map(ChunkedSite::index_bytes)
    }

    /// Is `chunk` the chunk at `i` of the site `root` binds? Needs the index.
    #[must_use]
    pub fn chunk_ok(&self, root: &Hash32, i: u64, chunk: &[u8]) -> bool {
        self.sites.get(root).and_then(|s| s.chunks.get(usize::try_from(i).ok()?)).is_some_and(|h| *h == chunk_hash(chunk))
    }

    /// Take chunk `i` of a site whose index is held. True when it is that chunk and it is stored.
    pub fn put_chunk(&mut self, root: &Hash32, i: u64, chunk: &[u8], mine: bool) -> bool {
        if !self.chunk_ok(root, i, chunk) {
            return false;
        }
        match self.chunks.put(chunk, mine) {
            Ok(hash) => {
                if self.paid.contains(root) {
                    self.chunks.mark_paid(&hash);
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Does this node take bytes for `root` with no name anchoring them? Only once it has SEEN a payment for them
    /// on the chain: a payment it was merely told of buys no room.
    #[must_use]
    pub fn accepts(&self, root: &Hash32) -> bool {
        self.paid.contains(root) || self.paid_ahead.contains_key(root)
    }

    /// The bytes of `site` in chunks nobody has paid this node to keep yet: what a payment for it must cover.
    fn unpaid_bytes(&self, site: &ChunkedSite) -> u64 {
        site.bytes_not_in(|c| self.chunks.is_paid(c))
    }

    #[must_use]
    pub fn is_paid(&self, root: &Hash32) -> bool {
        self.paid.contains(root)
    }

    /// A publisher says the note with commitment `cm` pays this node for `paid_len` bytes under `root`. Remembered
    /// until the chain shows that commitment ([`Self::note_commitment`]). A short memory: when it fills, the claims
    /// are forgotten and their publishers tell this node again.
    pub fn claim(&mut self, cm: [u8; 32], root: Hash32, paid_len: u64) {
        // PRODUCTION-SCALE-REVIEWED: how many payments wait to be seen on the chain at once (72 bytes each, RAM); a
        // forgotten claim is told again by its publisher's wallet and no payment is refused.
        if self.claims.len() >= 1024 {
            self.claims.clear();
        }
        self.claims.insert(cm, (root, paid_len));
    }

    /// The commitments this node is watching the chain for.
    #[must_use]
    pub fn watching(&self) -> bool {
        !self.claims.is_empty()
    }

    /// The chain carries the note commitment `cm`. If it is a payment this node was told of, the root it pays for is
    /// PAID from here on: its head and every chunk of it held now or later give their slots up last. Returns the root.
    pub fn note_commitment(&mut self, cm: &[u8; 32]) -> Option<Hash32> {
        let (root, paid_len) = self.claims.remove(cm)?;
        match self.sites.get(&root) {
            // the index is here: the payment is judged now
            Some(site) => {
                if self.unpaid_bytes(site) <= paid_len {
                    self.mark_paid(&root);
                }
            }
            // not here yet: judged when it arrives
            None => {
                // PRODUCTION-SCALE-REVIEWED: how many seen payments wait for their index at once (40 bytes each, RAM)
                if self.paid_ahead.len() >= 1024 {
                    self.paid_ahead.clear();
                }
                let so_far = self.paid_ahead.get(&root).copied().unwrap_or(0);
                self.paid_ahead.insert(root, so_far.max(paid_len));
            }
        }
        Some(root)
    }

    /// `root` is paid for: keep it, and say so in its head so a restart knows.
    pub fn mark_paid(&mut self, root: &Hash32) {
        if !self.paid.insert(*root) {
            return;
        }
        self.paid_ahead.remove(root);
        let Some(site) = self.sites.get(root).cloned() else { return };
        for chunk in &site.chunks {
            self.chunks.mark_paid(chunk);
        }
        // the head is rewritten with its paid bit: a new slot, the old one given up
        let publish = self.publishes.get(root).cloned().unwrap_or_default();
        if let Ok(new_head) = self.chunks.put_kind(&head_blob(&publish, &site.index_bytes(), true), true, true) {
            self.chunks.mark_paid(&new_head);
            if let Some(old) = self.heads.insert(*root, new_head) {
                if old != new_head {
                    self.chunks.forget(&old);
                }
            }
        }
    }

    /// Every site this node knows, by its root.
    pub fn sites(&self) -> impl Iterator<Item = (&Hash32, &ChunkedSite)> {
        self.sites.iter()
    }

    /// A stored chunk by its own hash.
    pub fn chunk_by_hash(&mut self, hash: &Hash32) -> Option<Vec<u8>> {
        self.chunks.get(hash)
    }

    /// How many of the sites this node knows are paid for.
    #[must_use]
    pub fn paid_count(&self) -> usize {
        self.paid.len()
    }

    pub fn chunk(&mut self, root: &Hash32, i: u64) -> Option<Vec<u8>> {
        let hash = *self.sites.get(root)?.chunks.get(usize::try_from(i).ok()?)?;
        self.chunks.get(&hash)
    }

    /// The chunks of a known site this node does not hold.
    #[must_use]
    pub fn missing(&self, root: &Hash32) -> Vec<u64> {
        self.sites.get(root).map(|s| (0..s.chunks.len() as u64).filter(|i| !self.chunks.holds(&s.chunks[*i as usize])).collect()).unwrap_or_default()
    }

    /// A site's length, when its index is held.
    #[must_use]
    pub fn total_len(&self, root: &Hash32) -> Option<u64> {
        self.sites.get(root).map(|s| s.total_len)
    }

    /// The bytes `[offset, offset + len)` of a site's run, or what is missing here to read them.
    pub fn read(&mut self, root: &Hash32, offset: u64, len: u64) -> Result<Vec<u8>, Gap> {
        let Some(total) = self.total_len(root) else {
            return Err(Gap::Index);
        };
        let end = offset.checked_add(len).filter(|e| *e <= total).ok_or(Gap::Chunks(Vec::new()))?;
        if len == 0 {
            return Ok(Vec::new());
        }
        // chunks are cut at file boundaries, so where each starts comes from the index's lengths
        let starts = self.sites.get(root).map(ChunkedSite::starts).ok_or(Gap::Index)?;
        let first = starts.partition_point(|s| *s <= offset).saturating_sub(1) as u64;
        let last = starts.partition_point(|s| *s < end).saturating_sub(1) as u64;
        let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        let mut missing = Vec::new();
        for i in first..=last {
            let at = starts[i as usize];
            match self.chunk(root, i) {
                Some(chunk) => {
                    let from = if i == first { (offset - at) as usize } else { 0 };
                    let to = if i == last { (end - at) as usize } else { chunk.len() };
                    out.extend_from_slice(chunk.get(from..to).unwrap_or(&[]));
                }
                None => missing.push(i),
            }
        }
        if missing.is_empty() && out.len() as u64 == len {
            Ok(out)
        } else {
            Err(Gap::Chunks(missing))
        }
    }

    /// Where `path` sits in a site: `(start, length)`. `Ok(None)` when the site has no such file.
    pub fn locate(&mut self, root: &Hash32, path: &str) -> Result<Option<(u64, u64)>, Gap> {
        let total = self.total_len(root).ok_or(Gap::Index)?;
        let first = self.read(root, 0, total.min(16))?;
        let Some(header_len) = site_header_len(&first).filter(|l| *l <= total) else {
            return Ok(None);
        };
        let header = self.read(root, 0, header_len)?;
        Ok(site_files(&header, total).and_then(|files| files.into_iter().find(|(p, ..)| p == path)).map(|(_, start, len)| (start, len)))
    }

    /// `(bytes held, the budget, sites known)`.
    #[must_use]
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.chunks.used(), self.budget, self.sites.len())
    }

    /// Bytes of the store's pages that held chunks take (whole 4 KiB pages).
    #[must_use]
    pub fn pages_used(&self) -> u64 {
        self.chunks.used_pages_bytes()
    }

    /// May a private read be served now? One read costs a pass over the whole store, so reads are metered like relay:
    /// each spends a chunk's worth of the same allowance.
    pub(crate) fn may_serve_read(&mut self) -> bool {
        self.may_serve_bytes(CHUNK_BYTES as u64)
    }

    /// May an answer of `len` bytes be served now? Spends the relay allowance.
    pub(crate) fn may_serve_bytes(&mut self, len: u64) -> bool {
        let len = len.max(1);
        let now = std::time::Instant::now();
        let gained = now.duration_since(self.refilled).as_millis() as u64 * RELAY_BYTES_PER_SEC / 1000;
        if gained > 0 {
            self.allowance = (self.allowance + gained).min(RELAY_BURST);
            self.refilled = now;
        }
        if len > self.allowance {
            return false;
        }
        self.allowance -= len;
        true
    }

    /// May a frame of `len` bytes be passed on now, and has `key` not been passed on lately? Spends the allowance.
    fn pass(&mut self, key: Hash32, len: usize) -> bool {
        let now = std::time::Instant::now();
        // PRODUCTION-SCALE-REVIEWED: the size of a short memory of frames passed on, emptied of old entries when it fills.
        if self.recent.len() > 4096 {
            self.recent.retain(|_, at| now.duration_since(*at).as_secs() < RECENT_SECS);
        }
        if self.recent.get(&key).is_some_and(|at| now.duration_since(*at).as_secs() < RECENT_SECS) {
            return false;
        }
        let gained = now.duration_since(self.refilled).as_millis() as u64 * RELAY_BYTES_PER_SEC / 1000;
        if gained > 0 {
            self.allowance = (self.allowance + gained).min(RELAY_BURST);
            self.refilled = now;
        }
        if (len as u64) > self.allowance {
            return false;
        }
        self.allowance -= len as u64;
        self.recent.insert(key, now);
        true
    }
}

// ── 9. what nodes pass to each other ────────────────────────────────────────────────────────────────────────

/// A Veil frame rides the site message. Its first bytes are never the start of a publish record anyone made on
/// purpose (a record starts with a site id, a hash).
const WIRE_MAGIC: &[u8; 8] = b"\xffMUDveil";
const FRAME_INDEX: u8 = 1;
const FRAME_CHUNK: u8 = 2;
const FRAME_WANT: u8 = 3;
/// In a WANT, the "chunk number" that asks for the index.
pub const WANT_INDEX: u64 = u64::MAX;
const FRAME_HEAD: usize = 49;
/// How many pieces a node asks for when it learns of a site: a bound on what one index makes it send. The publisher
/// passes every piece on with the index, so these questions only fill what was missed.
// PRODUCTION-SCALE-REVIEWED: a bound on one event's questions (64 frames of 49 bytes); it limits no site's size.
const WANTS_PER_INDEX: usize = 64;

#[must_use]
pub fn is_frame(bytes: &[u8]) -> bool {
    bytes.len() >= FRAME_HEAD && &bytes[..8] == WIRE_MAGIC
}

fn frame(kind: u8, root: &Hash32, n: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEAD + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.push(kind);
    out.extend_from_slice(root.as_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// "Here is the index of the site `root` binds."
#[must_use]
pub fn frame_index(root: &Hash32, index: &[u8]) -> Vec<u8> {
    frame(FRAME_INDEX, root, 0, index)
}

/// "Here is chunk `i` of that site."
#[must_use]
pub fn frame_chunk(root: &Hash32, i: u64, chunk: &[u8]) -> Vec<u8> {
    frame(FRAME_CHUNK, root, i, chunk)
}

/// "Who has chunk `i` of that site?" ([`WANT_INDEX`] for its index.)
#[must_use]
pub fn frame_want(root: &Hash32, i: u64) -> Vec<u8> {
    frame(FRAME_WANT, root, i, &[])
}

fn key_of(tag: &[u8], root: &Hash32, n: u64) -> Hash32 {
    let mut buf = Vec::with_capacity(tag.len() + 40);
    buf.extend_from_slice(tag);
    buf.extend_from_slice(root.as_bytes());
    buf.extend_from_slice(&n.to_le_bytes());
    Hash32::hash(&buf)
}

/// ONE FRAME FROM A PEER, and the frames to pass on because of it.
///
/// §9.6, the door this is (it parallels the site message's own publish door, `Node::publish_site`): (1) proof of
/// work: none, and none on the door it parallels; a frame is not a block. (2) its own proof: a frame is taken only for
/// a root the CHAIN anchors (`anchored`: the publish its owner signed), and an index or a chunk only when it hashes to
/// what that root binds; nothing is taken on a peer's word. (3) value: none is created or moved. (4) replay: the store
/// keeps one copy by hash, and a frame passed on is remembered and not passed on again. (5) work a hostile frame can
/// cause: one hash of at most one chunk and, when it is real, one slot write; what is PASSED ON is bounded per second
/// (`RELAY_BYTES_PER_SEC`) and what is KEPT by the node's budget. A frame for a root the chain does not anchor costs
/// one lookup. (6) parity: the publish door verifies a signature; this door verifies hashes under the root that
/// signature anchored. Bytes nobody paid this node for are kept only as a reader's cache (first to give their slot
/// up); the relay bound limits what anchored, unpaid bytes cost a node that passes them on.
pub fn on_frame(host: &mut SiteHost, anchored: impl Fn(&Hash32) -> bool, mine: impl Fn(&Hash32) -> bool, bytes: &[u8]) -> Vec<Vec<u8>> {
    if !is_frame(bytes) {
        return Vec::new();
    }
    let (kind, body) = (bytes[8], &bytes[FRAME_HEAD..]);
    let Some(root) = Hash32::from_slice(&bytes[9..41]) else {
        return Vec::new();
    };
    let n = u64::from_le_bytes(bytes[41..FRAME_HEAD].try_into().unwrap_or([0; 8]));
    if !anchored(&root) && !host.accepts(&root) {
        return Vec::new();
    }
    let once = |host: &mut SiteHost, key: Hash32, out: Vec<u8>| if host.pass(key, out.len()) { vec![out] } else { Vec::new() };
    match kind {
        FRAME_INDEX => {
            let new = !host.knows(&root);
            if !host.put_index(&root, body) {
                return Vec::new();
            }
            let mut out = once(host, key_of(b"index", &root, 0), bytes.to_vec());
            if new {
                // a site this node just learned of: ask for the pieces it lacks. This is the ONLY place a node asks
                // for site bytes, and it follows a public event (a publish every node sees), never a page somebody
                // opened: what a node asks its peers for says nothing about what its owner reads.
                for i in host.missing(&root).into_iter().take(WANTS_PER_INDEX) {
                    out.extend(once(host, key_of(b"want", &root, i), frame_want(&root, i)));
                }
            }
            out
        }
        FRAME_CHUNK => {
            if !host.knows(&root) {
                // a chunk before its index: ask for the index, once
                return once(host, key_of(b"want", &root, WANT_INDEX), frame_want(&root, WANT_INDEX));
            }
            if !host.chunk_ok(&root, n, body) {
                return Vec::new();
            }
            // a site is held whole by its holders: placement is by the site's root, never chunk by chunk
            let own = mine(&root);
            let _ = host.put_chunk(&root, n, body, own);
            once(host, key_of(b"chunk", &root, n), bytes.to_vec())
        }
        FRAME_WANT => {
            let answer = if n == WANT_INDEX { host.index(&root).map(|i| frame_index(&root, &i)) } else { host.chunk(&root, n).map(|c| frame_chunk(&root, n, &c)) };
            match answer {
                Some(reply) => once(host, key_of(b"answer", &root, n), reply),
                // not here: pass the question on, once
                None => once(host, key_of(b"want", &root, n), bytes.to_vec()),
            }
        }
        _ => Vec::new(),
    }
}

/// Where this process keeps its site store, told once at boot. The store itself is opened at first use, so a node
/// that never hosts or browses a site makes no file.
static HOST_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
static HOST: std::sync::OnceLock<Option<std::sync::Mutex<SiteHost>>> = std::sync::OnceLock::new();

/// BOOT: say where this node's site store lives (one file beside its other state).
pub fn host_at(path: std::path::PathBuf) {
    let _ = HOST_PATH.set(path);
}

/// The node adopted a signed publish: the host remembers it for the site's head. Opens the store.
pub fn note_publish(g: &crate::site::SiteGossip) {
    if let Some(mut host) = host() {
        host.note_publish(&g.publish.manifest_root, &g.to_wire());
    }
}

/// The signed publishes of the sites this node holds, or none when it has no store FILE yet (a node that never
/// hosted makes no file by asking).
#[must_use]
pub fn stored_publishes() -> Vec<Vec<u8>> {
    if !HOST_PATH.get().is_some_and(|p| p.exists()) {
        return Vec::new();
    }
    host().map(|h| h.stored_publishes()).unwrap_or_default()
}

/// This node's site host, opened at first use with `MONEROUSD_SITE_BUDGET_MB` (512 when unset). `None` when the node
/// was given no place for it or the file cannot be opened: hosting is then off and nothing else is affected.
pub fn host() -> Option<std::sync::MutexGuard<'static, SiteHost>> {
    let slot = HOST.get_or_init(|| {
        let path = HOST_PATH.get()?;
        // PRODUCTION-SCALE-REVIEWED: the spec's default per-node budget for site bytes; the operator's own choice.
        let mb = std::env::var("MONEROUSD_SITE_BUDGET_MB").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(512);
        SiteHost::open(path, mb << 20).ok().map(std::sync::Mutex::new)
    });
    slot.as_ref().map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
}

// ── 3. a chunk's shard and the shard's holders ─────────────────────────────────────────────────────────────────

/// The shard a chunk belongs to: the top bits of its hash, one of the node's `2^RECORD_SHARD_BITS` shards.
#[must_use]
pub fn chunk_shard(chunk: &Hash32) -> u32 {
    u32::from(chunk.as_bytes()[0]) >> (8 - Node::RECORD_SHARD_BITS)
}

/// The nodes that hold a shard's chunks, best rank first: the node's one rendezvous rule over the public node ids, at
/// the replication the nullifier shards use. A network no larger than the replication holds everything everywhere.
#[must_use]
pub fn shard_holders(shard: u32, ids: &[String]) -> Vec<String> {
    crate::nf_sparse::holders_of(PLACEMENT_DOMAIN, shard, ids, Node::NF_SHARD_REPLICATION as usize)
}

/// The shard a SITE belongs to: all of a site's bytes are held together, by the holders of its root's shard, so a
/// publisher pays one set of holders and a reader asks one set.
#[must_use]
pub fn site_shard(root: &Hash32) -> u32 {
    chunk_shard(root)
}

/// The nodes that hold the site `root` binds, best rank first.
#[must_use]
pub fn site_holders(root: &Hash32, ids: &[String]) -> Vec<String> {
    shard_holders(site_shard(root), ids)
}

/// Does `me` hold the site `root` binds, among `ids`?
#[must_use]
pub fn holds_site(root: &Hash32, ids: &[String], me: Option<&str>) -> bool {
    holds_chunk(root, ids, me)
}

/// The chain carries these note commitments (one block's): a payment this node was told of becomes a paid site. A
/// no-op, without opening the store, unless a store file exists and a payment is being watched for.
pub fn note_block_commitments(commitments: &[u8]) {
    if !HOST_PATH.get().is_some_and(|p| p.exists()) {
        return;
    }
    let Some(mut host) = host() else { return };
    if !host.watching() {
        return;
    }
    for cm in commitments.chunks_exact(32) {
        if let Ok(cm) = <[u8; 32]>::try_from(cm) {
            let _ = host.note_commitment(&cm);
        }
    }
}

/// Does `me` hold `chunk` among `ids`? A node whose public id is not announced yet (`None`) holds everything: it
/// over-holds, never short.
#[must_use]
pub fn holds_chunk(chunk: &Hash32, ids: &[String], me: Option<&str>) -> bool {
    crate::nf_sparse::holds_shard(PLACEMENT_DOMAIN, chunk_shard(chunk), ids, Node::NF_SHARD_REPLICATION as usize, me)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut block = *blake3::hash(b"a site's bytes").as_bytes();
        while out.len() < len {
            out.extend_from_slice(&block[..block.len().min(len - out.len())]);
            block = *blake3::hash(&block).as_bytes();
        }
        out
    }

    #[test]
    fn only_a_plain_name_dot_mud_is_a_site_name() {
        assert_eq!(mud_name("flame.mud"), Some("flame".to_string()));
        assert_eq!(mud_name("  Flame.MUD "), Some("flame".to_string()));
        for bad in ["", ".mud", "flame", "flame.com", "flame.mud.com", "a.flame.mud", "flame.mud/page", "flame.mud:80", "fla me.mud", "@flame.mud", "flamé.mud", "flame.mud."] {
            assert_eq!(mud_name(bad), None, "{bad:?} was read as a site name");
        }
    }

    #[test]
    fn a_name_shows_only_what_its_own_owner_published_under_it() {
        let (alice, mallory) = ([7u8; 32], [9u8; 32]);
        let mut names = Directory::new();
        let mut sites = SiteRegistry::new();
        assert_eq!(resolve_mud(&names, &sites, "flame.mud"), None, "an unregistered name resolved");
        // the name as the chain directory holds it once a block's sign-up applied (the signature is the apply door's)
        let claim = |owner_address: &str| crate::directory::DirEntry {
            kind: crate::directory::KIND_NAME,
            key: "flame".to_string(),
            address: owner_address.to_string(),
            name: String::new(),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: None,
        };
        assert!(names.apply_entry(&claim("alice-address"), alice));
        assert!(!names.apply_entry(&claim("mallory-address"), mallory), "a second owner took a claimed name");
        assert_eq!(names.owner_of("@Flame"), Some(alice));
        assert_eq!(resolve_mud(&names, &sites, "flame.mud"), None, "a name with no site resolved");
        // someone else publishes a site under the same label: it is another site id, and the name does not show it
        sites.adopt(SitePublish::new(mallory, "flame", 5, Hash32::hash(b"mallory's site")));
        assert_eq!(resolve_mud(&names, &sites, "flame.mud"), None, "a name showed a site its owner never published");
        let v1 = SitePublish::new(alice, "flame", 1, Hash32::hash(b"alice v1"));
        sites.adopt(v1.clone());
        assert_eq!(resolve_mud(&names, &sites, "Flame.mud"), Some(MudSite { name: "flame".to_string(), owner: alice, publish: v1 }));
        let v2 = SitePublish::new(alice, "flame", 2, Hash32::hash(b"alice v2"));
        sites.adopt(v2.clone());
        assert_eq!(resolve_mud(&names, &sites, "flame.mud").map(|s| s.publish), Some(v2), "the name did not follow its owner's newer version");
        assert_eq!(resolve_mud(&names, &sites, "flames.mud"), None);
    }

    #[test]
    fn every_chunk_verifies_at_its_own_place_and_nowhere_else() {
        for len in [1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES, 3 * CHUNK_BYTES + 777] {
            let bytes = site(len);
            let s = ChunkedSite::of(&bytes).expect("a site with bytes");
            let root = s.root();
            assert_eq!(s.chunks.len() as u64, (len as u64).div_ceil(CHUNK_BYTES as u64));
            for (i, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
                let proof = s.prove(i as u64).expect("a proof for a real chunk");
                assert!(verify_chunk(&root, &s.shape(), i as u64, chunk, &proof), "an honest chunk was refused (len {len}, chunk {i})");
            }
            assert_eq!(s.prove(s.chunks.len() as u64), None);
            assert_eq!(s.len_of(s.chunks.len() as u64), None);
        }
        assert_eq!(ChunkedSite::of(&[]), None);
    }

    #[test]
    fn a_node_serving_anything_but_the_chunk_is_refused() {
        let len = 2 * CHUNK_BYTES + 1000;
        let bytes = site(len);
        let s = ChunkedSite::of(&bytes).expect("a site");
        let root = s.root();
        let chunk = |i: usize| bytes.chunks(CHUNK_BYTES).nth(i).expect("a chunk");
        let p0 = s.prove(0).expect("proof 0");
        let p2 = s.prove(2).expect("proof 2");

        let shape = s.shape();
        // other bytes
        let mut flipped = chunk(0).to_vec();
        flipped[1234] ^= 1;
        assert!(!verify_chunk(&root, &shape, 0, &flipped, &p0));
        // the right chunk at the wrong index, and another chunk under this chunk's proof
        assert!(!verify_chunk(&root, &shape, 1, chunk(0), &p0));
        assert!(!verify_chunk(&root, &shape, 0, chunk(1), &p0));
        // truncated and padded chunks, even when the claimed site shape is changed to fit them
        assert!(!verify_chunk(&root, &shape, 0, &chunk(0)[..CHUNK_BYTES - 1], &p0));
        let mut long = chunk(2).to_vec();
        long.push(0);
        assert!(!verify_chunk(&root, &shape, 2, &long, &p2));
        assert!(!verify_chunk(&root, &Shape { total_len: len as u64 + 1, ..shape }, 2, &long, &p2), "a longer site was accepted under the same root");
        assert!(!verify_chunk(&root, &Shape { total_len: len as u64 - 1, ..shape }, 2, &chunk(2)[..999], &p2), "a shorter site was accepted under the same root");
        let lied_lens = Shape { lens_digest: lens_digest(&[CHUNK_BYTES as u32, CHUNK_BYTES as u32 - 1, 1001]), ..shape };
        assert!(!verify_chunk(&root, &lied_lens, 0, chunk(0), &p0), "a shape whose chunk lengths lie was accepted under the same root");
        // an index past the site
        assert!(!verify_chunk(&root, &shape, 3, chunk(2), &p2));
        assert!(!verify_chunk(&root, &Shape { count: 4, ..shape }, 3, chunk(2), &p2));
        // a chunk of ANOTHER site, with that site's own honest proof
        let other = site(len + 5);
        let o = ChunkedSite::of(&other).expect("another site");
        let op = o.prove(0).expect("its proof");
        assert!(verify_chunk(&o.root(), &o.shape(), 0, &other[..CHUNK_BYTES], &op));
        assert!(!verify_chunk(&root, &shape, 0, &other[..CHUNK_BYTES], &op), "another site's chunk was served under this site's root");
        assert!(!verify_chunk(&root, &o.shape(), 0, &other[..CHUNK_BYTES], &op), "another site's chunk was served under this site's root with its shape");
        // a forged chunks-root in the proof
        let mut forged = p0.clone();
        forged.chunks_root = Hash32::hash(b"not the tree");
        assert!(!verify_chunk(&root, &shape, 0, chunk(0), &forged));
    }

    #[test]
    fn a_chunk_has_the_holders_the_nodes_one_rule_names_for_its_shard() {
        let ids: Vec<String> = (0..40).map(|i| format!("node-{i}")).collect();
        let r = Node::NF_SHARD_REPLICATION as usize;
        let shards = 1u32 << Node::RECORD_SHARD_BITS;
        let mut per_shard = vec![0u32; shards as usize];
        for i in 0..20_000u32 {
            let chunk = Hash32::hash(&i.to_le_bytes());
            let shard = chunk_shard(&chunk);
            assert!(shard < shards);
            per_shard[shard as usize] += 1;
            let holders = shard_holders(shard, &ids);
            assert_eq!(holders.len(), r);
            for id in &ids {
                assert_eq!(holds_chunk(&chunk, &ids, Some(id)), holders.contains(id), "holding a chunk and being named a holder disagree");
            }
        }
        // chunks spread over the shards: 20,000 over 256 is about 78 each
        assert!(per_shard.iter().all(|n| (40..=125).contains(n)), "the chunks did not spread over the shards: {per_shard:?}");
        // a node's site shards are not its nullifier shards: the placement domain is its own
        let differ = (0..shards).filter(|s| shard_holders(*s, &ids) != crate::nf_sparse::holders_of(b"another domain", *s, &ids, r)).count();
        assert!(differ > shards as usize / 2, "the site placement follows another domain's placement");
        // a small network holds everything everywhere, and a node with no announced id holds everything
        let few = &ids[..2];
        let chunk = Hash32::hash(b"one chunk");
        assert!(few.iter().all(|id| holds_chunk(&chunk, few, Some(id))));
        assert!(holds_chunk(&chunk, &ids, None));
    }

    // TWO-PARTY-REVIEWED: the tests below are the Veil's own rules on bytes (a challenge and its answer, a store, a
    // read, a packed site, frames between two `SiteHost`s in one process). They show what each rule refuses. That a
    // site published through one real node is read from ANOTHER is the real-node check `scratchpad/net/veil.py`, and
    // is not claimed here.
    // O1-INFINITY-REVIEWED: every `put` below writes pages of a store that is ONE file of a fixed number of pages (the
    // tests open it for 2, 3 or 64 chunks); a put takes free pages or overwrites pages in place, and
    // `the_store_never_grows_…` asserts the file's size never moves.
    #[test]
    fn holding_a_chunk_is_shown_by_one_piece_and_nothing_less_passes() {
        let len = 3 * CHUNK_BYTES + 5000;
        let bytes = site(len);
        let s = ChunkedSite::of(&bytes).expect("a site");
        let root = s.root();
        let chunk = |i: u64| bytes.chunks(CHUNK_BYTES).nth(i as usize).expect("a chunk");
        // over many blocks every chunk is asked for, the last short one too, and every honest answer passes
        let mut asked = std::collections::HashSet::new();
        for n in 0..64u32 {
            let block = Hash32::hash(&n.to_le_bytes());
            let (index, piece) = storage_challenge(&block, &root, &s, "node-1").expect("a challenge");
            asked.insert(index);
            let a = answer_storage(&s, &block, "node-1", chunk(index)).expect("the holder answers");
            assert_eq!((a.index, a.piece), (index, piece));
            assert!(verify_storage(&root, &block, "node-1", &a), "an honest answer was refused (block {n})");
            // a holder with another chunk has no answer
            assert!(answer_storage(&s, &block, "node-1", chunk((index + 1) % 4)).is_none());
        }
        assert_eq!(asked.len(), 4, "a chunk was never challenged");

        let block = Hash32::hash(b"one block");
        let (index, piece) = storage_challenge(&block, &root, &s, "node-1").expect("a challenge");
        let honest = answer_storage(&s, &block, "node-1", chunk(index)).expect("answers");
        let refused = |name: &str, a: &StorageAnswer| assert!(!verify_storage(&root, &block, "node-1", a), "⛔ {name} passed");
        // other bytes; a short piece; another piece of the same chunk, honestly opened
        let mut a = honest.clone();
        a.bytes[0] ^= 1;
        refused("a changed piece", &a);
        let mut a = honest.clone();
        a.bytes.pop();
        refused("a short piece", &a);
        let other_piece = (piece + 1) % (chunk(index).len() as u64).div_ceil(PIECE_BYTES as u64);
        let pieces = pieces_of(chunk(index));
        let a = StorageAnswer {
            piece: other_piece,
            bytes: chunk(index).chunks(PIECE_BYTES).nth(other_piece as usize).expect("a piece").to_vec(),
            piece_path: merkle::inclusion_proof(&pieces, other_piece as usize).expect("a path"),
            ..honest.clone()
        };
        refused("a piece that was not asked for", &a);
        // the piece's hash handed over with no bytes behind it (a holder that kept only hashes)
        let mut a = honest.clone();
        a.bytes = Hash32::hash(&honest.bytes).as_bytes().to_vec();
        refused("a hash in place of the piece", &a);
        // another block's answer, another holder's answer, another site's answer
        assert!(!verify_storage(&root, &Hash32::hash(b"another block"), "node-1", &honest) || storage_challenge(&Hash32::hash(b"another block"), &root, &s, "node-1") == Some((index, piece)));
        let theirs = storage_challenge(&block, &root, &s, "node-2").expect("a challenge");
        assert_eq!(theirs.0, index, "every holder is asked for the same chunk");
        assert!(theirs.1 == piece || !verify_storage(&root, &block, "node-2", &honest), "one holder's answer passed as another's");
        let other = site(len + 9);
        let o = ChunkedSite::of(&other).expect("another site");
        assert!(!verify_storage(&o.root(), &block, "node-1", &honest));
        // a lying prover: a well-formed answer that names another shape or another length for the chunk
        let mut a = honest.clone();
        a.shape.count += 1;
        refused("an answer naming one chunk more than the site has", &a);
        let mut a = honest.clone();
        a.shape.total_len -= 1;
        refused("an answer naming a shorter site", &a);
        let mut a = honest.clone();
        a.len -= 1;
        refused("an answer naming a shorter chunk", &a);
        let mut a = honest.clone();
        a.shape.lens_digest = Hash32::hash(b"other lengths");
        refused("an answer naming other chunk lengths", &a);
        assert_eq!(storage_challenge(&block, &root, &ChunkedSite { total_len: 0, lens: Vec::new(), chunks: Vec::new() }, "node-1"), None);
    }

    /// A store file of its own, removed when the test ends.
    struct TempStore(std::path::PathBuf);
    impl TempStore {
        fn new(name: &str) -> Self {
            TempStore(std::env::temp_dir().join(format!("monerousd-veil-test-{}-{name}.slab", std::process::id())))
        }
    }
    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn the_store_never_grows_and_gives_up_a_readers_chunk_before_its_own() {
        let tmp = TempStore::new("budget");
        let chunk = |n: u8| vec![n; 1000 + usize::from(n)];
        let three = store_bytes_for(3, PAGE_BYTES);
        let mut store = ChunkStore::open(&tmp.0, three + 17).expect("a store");
        let size = || std::fs::metadata(&tmp.0).expect("the file").len();
        assert_eq!(size(), three, "the file is the budget in whole pages");
        let mine = store.put(&chunk(1), true).expect("put");
        let read_a = store.put(&chunk(2), false).expect("put");
        let read_b = store.put(&chunk(3), false).expect("put");
        assert_eq!(store.used(), 1001 + 1002 + 1003);
        assert_eq!(store.get(&mine), Some(chunk(1)));
        // a fourth chunk: the oldest chunk held for a reader gives up its slot; this node's own stays
        let read_c = store.put(&chunk(4), false).expect("put");
        assert!(store.holds(&mine) && !store.holds(&read_a) && store.holds(&read_b) && store.holds(&read_c));
        // the same chunk again changes nothing; marking it this node's own keeps it
        assert_eq!(store.put(&chunk(3), true).expect("put"), read_b);
        let read_d = store.put(&chunk(5), false).expect("put");
        assert!(store.holds(&mine) && store.holds(&read_b) && !store.holds(&read_c) && store.holds(&read_d));
        // with only its own left to drop, the oldest of its own goes
        store.mark_mine(|_| true);
        let last = store.put(&chunk(6), true).expect("put");
        assert!(!store.holds(&mine) && store.holds(&last));
        assert_eq!(size(), three, "the file never grew");
        assert!(store.put(&[], false).is_err() && store.put(&vec![0u8; CHUNK_BYTES + 1], false).is_err());
        // reopened, what was held is still held and still reads back
        drop(store);
        let mut again = ChunkStore::open(&tmp.0, three).expect("reopened");
        assert!(again.holds(&read_b) && again.holds(&read_d) && again.holds(&last));
        assert_eq!(again.get(&last), Some(chunk(6)));
        // a store with no room for one slot holds nothing and says so
        let none = TempStore::new("none");
        assert!(ChunkStore::open(&none.0, store_bytes_for(1, PAGE_BYTES) - 1).expect("an empty store").put(&chunk(1), true).is_err());
    }

    #[test]
    fn a_rotted_slot_reads_as_missing_never_as_wrong_bytes() {
        use std::io::{Seek as _, Write as _};
        let tmp = TempStore::new("rot");
        let mut store = ChunkStore::open(&tmp.0, store_bytes_for(2, PAGE_BYTES)).expect("a store");
        let hash = store.put(&vec![7u8; 4096], true).expect("put");
        // LOCAL-STORAGE-REQUIRED: the test damages one byte of its own temporary store file to show the read refuses it.
        // bound: one byte of a two-page test file, removed when the test ends.
        let mut raw = std::fs::OpenOptions::new().write(true).open(&tmp.0).expect("the file");
        raw.seek(std::io::SeekFrom::Start(store.page_offset(store.held[&hash].pages[0]) + 100)).expect("seek");
        raw.write_all(&[8]).expect("damage");
        assert_eq!(store.get(&hash), None, "damaged bytes were served");
        assert!(!store.holds(&hash), "a damaged chunk is still listed");
    }

    #[test]
    fn a_small_chunk_takes_the_pages_it_fills_and_a_reopen_finds_each_chunk_once() {
        let tmp = TempStore::new("pages");
        // a hundred 3 KB files in a store sized for a hundred pages: all held (whole-chunk slots held one)
        let budget = store_bytes_for(100, PAGE_BYTES);
        let mut store = ChunkStore::open(&tmp.0, budget).expect("a store");
        let small = |n: u16| { let mut v = vec![(n & 0xff) as u8; 3000]; v[..2].copy_from_slice(&n.to_le_bytes()); v };
        let hashes: Vec<Hash32> = (0..100).map(|n| store.put(&small(n), true).expect("put")).collect();
        assert!(hashes.iter().all(|h| store.holds(h)), "a small chunk was pushed out of a store with room for it");
        assert_eq!(store.used(), 300_000);
        assert_eq!(store.used_pages_bytes(), 100 * PAGE_BYTES as u64);
        // a whole chunk needs 64 pages: the oldest 64 small ones give theirs up, and nothing else
        let big = site(CHUNK_BYTES);
        let big_hash = store.put(&big, true).expect("room is made");
        assert_eq!(hashes.iter().filter(|h| store.holds(h)).count(), 36);
        assert!(hashes[64..].iter().all(|h| store.holds(h)), "a newer chunk gave its pages up before an older one");
        assert_eq!(store.get(&big_hash), Some(big.clone()));
        // a chunk given up and written again; the reopened store sees it once, whole
        store.forget(&hashes[99]);
        let again_hash = store.put(&small(99), true).expect("put");
        assert_eq!(again_hash, hashes[99]);
        drop(store);
        let mut reopened = ChunkStore::open(&tmp.0, budget).expect("reopened");
        assert_eq!(reopened.get(&hashes[99]), Some(small(99)), "a chunk written twice was lost at a reopen");
        assert_eq!(reopened.get(&big_hash), Some(big), "a chunk over many pages did not come back whole");
        assert_eq!(hashes.iter().filter(|h| reopened.holds(h)).count(), 36);
        // a file of another layout is never read as pages: it opens empty
        drop(reopened);
        let other = TempStore::new("other-layout");
        std::fs::write(&other.0, vec![0xAB; 9000]).expect("a stray file");
        let fresh = ChunkStore::open(&other.0, budget).expect("opens");
        assert_eq!(fresh.used(), 0);
    }

    #[test]
    fn an_update_stores_only_the_files_it_changed_wherever_they_sit() {
        let files = |home: &[u8], style: &[u8]| {
            vec![
                ("a/first.txt".to_string(), site(40_000)),
                ("b/photo.jpg".to_string(), site(3 * CHUNK_BYTES / 2)),
                ("index.html".to_string(), home.to_vec()),
                ("style.css".to_string(), style.to_vec()),
                ("z/last.bin".to_string(), site(CHUNK_BYTES + 77)),
            ]
        };
        let v1 = pack_site(&files(b"<h1>hi</h1>", b"h1{}")).expect("packs");
        let s1 = ChunkedSite::of(&v1).expect("chunks");
        // a file in the middle grows: only it and the header are new
        let v2 = pack_site(&files(b"<h1>hi, a longer page now</h1>", b"h1{}")).expect("packs");
        let s2 = ChunkedSite::of(&v2).expect("chunks");
        let header2 = site_header_len(&v2[..16]).expect("a header");
        assert_eq!(new_bytes(Some(&s1), &s2), header2 + 30);
        // no file changes at all: the same root
        assert_eq!(ChunkedSite::of(&pack_site(&files(b"<h1>hi</h1>", b"h1{}")).expect("packs")).expect("chunks").root(), s1.root());
        // two files change: those two and the header
        let v3 = pack_site(&files(b"<h1>yo</h1>", b"h1{color:red}")).expect("packs");
        assert_eq!(new_bytes(Some(&s1), &ChunkedSite::of(&v3).expect("chunks")), site_header_len(&v3[..16]).expect("a header") + 11 + 13);
        // a file renamed keeps its bytes' chunks: only the header is new
        let mut renamed = files(b"<h1>hi</h1>", b"h1{}");
        renamed[0].0 = "a/renamed.txt".to_string();
        let v4 = pack_site(&renamed).expect("packs");
        assert_eq!(new_bytes(Some(&s1), &ChunkedSite::of(&v4).expect("chunks")), site_header_len(&v4[..16]).expect("a header"));
        // every chunk of every version still reads back to the bytes it was cut from, and verifies against its root
        for (blob, site) in [(&v1, &s1), (&v2, &s2)] {
            assert_eq!(site.pieces(blob).map(<[u8]>::len).sum::<usize>(), blob.len());
            for (i, piece) in site.pieces(blob).enumerate() {
                assert!(verify_chunk(&site.root(), &site.shape(), i as u64, piece, &site.prove(i as u64).expect("a proof")));
            }
            assert_eq!(ChunkedSite::from_index(&site.index_bytes()).as_ref(), Some(site));
        }
        // an index whose lengths do not sum to its length, or name an empty or oversize chunk, is not an index
        let mut idx = s1.index_bytes();
        idx[12..16].copy_from_slice(&(s1.lens[0] + 1).to_le_bytes());
        assert!(ChunkedSite::from_index(&idx).is_none());
        idx[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(ChunkedSite::from_index(&idx).is_none());
        let mut idx = s1.index_bytes();
        idx[8..12].copy_from_slice(&(s1.chunks.len() as u32 + 1).to_le_bytes());
        assert!(ChunkedSite::from_index(&idx).is_none());
    }

    #[test]
    fn a_private_read_returns_the_chunk_and_a_server_that_lies_is_caught() {
        let len = 5 * CHUNK_BYTES + 321;
        let bytes = site(len);
        let s = ChunkedSite::of(&bytes).expect("a site");
        let root = s.root();
        // a public bucket: this site's chunks in its first slots, the rest empty
        let bucket = |slot: u64| bytes.chunks(CHUNK_BYTES).nth(slot as usize).map(<[u8]>::to_vec);
        for want in [0u64, 3, 5] {
            let mut random = [0u8; 64];
            random.copy_from_slice(&[Hash32::hash(&want.to_le_bytes()).0, Hash32::hash(b"second seed").0].concat());
            let (ka, kb) = pir_query(want, &random).expect("a query");
            let (a, b) = (pir_answer(&ka, bucket), pir_answer(&kb, bucket));
            let want_len = s.len_of(want).expect("a real chunk");
            let got = pir_combine(&a, &b, want_len).expect("two whole answers");
            assert_eq!(got, bucket(want).expect("the chunk"), "the read returned other bytes");
            assert!(verify_chunk(&root, &s.shape(), want, &got, &s.prove(want).expect("a proof")));
            // one server alone is asked for many slots: its key does not single the wanted one out
            let picked = |k: &crate::pqmix::dpf::Key| (0..1u64 << BUCKET_DEPTH).filter(|x| crate::pqmix::dpf::eval(k, *x).first().is_some_and(|v| v & 1 == 1)).count();
            assert!(picked(&ka) > 64 && picked(&kb) > 64, "a key selects so few slots that it points at one");
            // a server that changes one byte of its answer: the reader's check refuses the result
            let mut lie = a.clone();
            lie[10] ^= 1;
            let bad = pir_combine(&lie, &b, want_len).expect("combined");
            assert!(!verify_chunk(&root, &s.shape(), want, &bad, &s.prove(want).expect("a proof")), "⛔ a wrong answer was shown");
        }
        assert!(pir_query(1 << BUCKET_DEPTH, &[0u8; 64]).is_none(), "a slot outside the bucket was asked for");
        assert!(pir_combine(&[0u8; 10], &vec![0u8; CHUNK_BYTES], 5).is_none());
    }

    fn files() -> Vec<(String, Vec<u8>)> {
        vec![
            ("index.html".to_string(), b"<h1>home</h1>".to_vec()),
            ("img/big.bin".to_string(), site(2 * CHUNK_BYTES + 4321)),
            ("about/index.html".to_string(), b"<p>about</p>".to_vec()),
        ]
    }

    #[test]
    fn a_packed_site_is_the_same_bytes_whoever_packs_it_and_reads_back_file_by_file() {
        let mut shuffled = files();
        shuffled.reverse();
        let blob = pack_site(&files()).expect("packs");
        assert_eq!(pack_site(&shuffled).expect("packs"), blob, "the order files were given in changed the site");
        let header_len = site_header_len(&blob[..16]).expect("a site header") as usize;
        let listed = site_files(&blob[..header_len], blob.len() as u64).expect("a whole header");
        assert_eq!(listed.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["about/index.html", "img/big.bin", "index.html"]);
        for (path, start, len) in &listed {
            let want = &files().into_iter().find(|f| f.0 == *path).expect("the file").1;
            assert_eq!(&blob[*start as usize..(*start + *len) as usize], &want[..], "{path} did not read back");
        }
        // what is not a site: no files, a repeated path, a path that climbs, a header cut short or lied about
        assert!(pack_site(&[]).is_none());
        assert!(pack_site(&[("a".to_string(), vec![1]), ("a".to_string(), vec![2])]).is_none());
        for bad in ["../x", "/x", "a//b", "a/./b", "", "sp ace", "q?x"] {
            assert!(!site_path_ok(bad) && pack_site(&[(bad.to_string(), vec![1])]).is_none(), "{bad:?} was packed");
        }
        assert!(site_files(&blob[..header_len - 1], blob.len() as u64).is_none());
        assert!(site_files(&blob[..header_len], blob.len() as u64 + 1).is_none(), "a longer site passed under this header");
        let mut lied = blob[..header_len].to_vec();
        lied[16 + 2 + "about/index.html".len()] ^= 1; // the first file's offset
        assert!(site_files(&lied, blob.len() as u64).is_none(), "a file that does not sit where the header says was listed");
        assert!(site_header_len(b"NOTASITE00000000").is_none());
    }

    #[test]
    fn a_host_serves_only_bytes_the_root_binds_and_says_what_it_lacks() {
        let tmp = TempStore::new("host");
        let blob = pack_site(&files()).expect("packs");
        let s = ChunkedSite::of(&blob).expect("chunks");
        let root = s.root();
        let mut host = SiteHost::open(&tmp.0, store_bytes_for(64, CHUNK_BYTES)).expect("a host");
        // nothing yet: a read says the index is missing
        assert_eq!(host.locate(&root, "index.html"), Err(Gap::Index));
        // an index with no publish behind it, for ANOTHER root, a cut index and a chunk before any index are refused
        // O1-INFINITY-REVIEWED: `put_index` writes one slot of the test's 64-slot store file; nothing here grows.
        assert!(!host.put_index(&root, &s.index_bytes()), "an index was kept with no publish that anchors it");
        let publish = crate::site::SiteGossip::new(crate::site::SitePublish::new([7; 32], "flame", 1, root), vec![1, 2, 3], vec![4, 5, 6]).to_wire();
        host.note_publish(&root, &publish);
        assert!(!host.put_index(&Hash32::hash(b"other"), &s.index_bytes()));
        assert!(!host.put_index(&root, &s.index_bytes()[..40]));
        // an index with the right hashes and lying lengths (two chunks' lengths traded): not the root's
        let mut lying = s.clone();
        lying.lens.swap(1, 2);
        assert!(lying.lens[1] != lying.lens[2] && !host.put_index(&root, &lying.index_bytes()), "⛔ an index whose lengths lie was kept");
        assert!(!host.put_chunk(&root, 0, s.piece(&blob, 0).expect("chunk 0"), true));
        assert!(host.put_index(&root, &s.index_bytes()) && host.knows(&root));
        assert_eq!(ChunkedSite::from_index(&host.index(&root).expect("held")), Some(s.clone()));
        // with the index and no chunks, a read names the chunks it lacks
        assert_eq!(host.locate(&root, "index.html"), Err(Gap::Chunks(vec![0])));
        // a chunk ends at every file boundary: the header, about/index.html, img/big.bin in three, index.html
        assert_eq!(s.chunks.len(), 6);
        // a wrong chunk, the right chunk at the wrong place: refused; the right chunks: taken
        let chunk = |i: usize| s.piece(&blob, i as u64).expect("a chunk").to_vec();
        let mut wrong = chunk(0);
        wrong[77] ^= 1;
        assert!(!host.put_chunk(&root, 0, &wrong, true), "⛔ a wrong chunk was stored");
        assert!(!host.put_chunk(&root, 1, &chunk(0), true), "⛔ a chunk was stored at another chunk's place");
        assert!(host.put_chunk(&root, 0, &chunk(0), true));
        // the header is here: every file is found, and a file whose chunk is not here says which it lacks
        let (start, len) = host.locate(&root, "about/index.html").expect("readable").expect("listed");
        assert_eq!(host.read(&root, start, len), Err(Gap::Chunks(vec![1])));
        assert!(host.put_chunk(&root, 1, &chunk(1), true));
        assert_eq!(host.read(&root, start, len), Ok(b"<p>about</p>".to_vec()));
        assert_eq!(host.locate(&root, "nope.html"), Ok(None));
        let (start, len) = host.locate(&root, "img/big.bin").expect("readable").expect("listed");
        assert_eq!(host.read(&root, start, len), Err(Gap::Chunks(vec![2, 3, 4])));
        for i in 2..s.chunks.len() {
            assert!(host.put_chunk(&root, i as u64, &chunk(i), false));
        }
        assert_eq!(host.read(&root, start, len), Ok(files()[1].1.clone()), "a file spanning chunks read back wrong");
        assert_eq!(host.read(&root, start, len + blob.len() as u64), Err(Gap::Chunks(Vec::new())), "a read past the site passed");
        // reopened from the same file, the site is still known and still reads
        drop(host);
        let mut again = SiteHost::open(&tmp.0, store_bytes_for(64, CHUNK_BYTES)).expect("reopened");
        assert!(again.knows(&root), "the index was not found again");
        assert_eq!(again.read(&root, start, len), Ok(files()[1].1.clone()));
        assert_eq!(again.stats().2, 1);
        assert_eq!(again.stored_publishes(), vec![publish.clone()], "the signed publish did not come back with the site");
        // a NEWER version of the same site: its head replaces the old one, and only the new publish is offered
        // O1-INFINITY-REVIEWED: the puts below take or overwrite slots of the test's 64-slot store file in place.
        let mut v2_files = files();
        v2_files[0].1 = b"<h1>home, again</h1>".to_vec();
        let blob2 = pack_site(&v2_files).expect("packs");
        let s2 = ChunkedSite::of(&blob2).expect("chunks");
        let publish2 = crate::site::SiteGossip::new(crate::site::SitePublish::new([7; 32], "flame", 2, s2.root()), vec![1, 2, 3], vec![9]).to_wire();
        // version 1 is paid for here: its chunks give their pages up last
        again.mark_paid(&root);
        // AN UPDATE STORES ONLY WHAT CHANGED: about/index.html and the three chunks of img/big.bin are the same chunks
        // under the same hashes in version 2; only the header and index.html are new
        let header2 = site_header_len(&blob2[..16]).expect("a header");
        assert_eq!(s2.chunks[1..5], s.chunks[1..5], "an unchanged file was cut into other chunks");
        assert_eq!(new_bytes(Some(&s), &s2), header2 + 20, "an update paid for bytes it did not change");
        again.note_publish(&s2.root(), &publish2);
        assert!(again.put_index(&s2.root(), &s2.index_bytes()));
        // the node holds every chunk version 2 shares with version 1 already: it lacks the two new ones alone
        assert_eq!(again.missing(&s2.root()), vec![0, 5], "the node asked again for chunks it already held");
        // and the chunks only version 1 named are ordinary cache now, first to give their pages up
        for gone in [s.chunks[0], s.chunks[5]] {
            assert!(again.chunks.held.get(&gone).is_some_and(|h| !h.mine && !h.paid), "a replaced version's chunk is still kept as paid or as this node's own");
        }
        for kept in &s.chunks[1..5] {
            assert!(again.chunks.is_paid(kept), "a chunk version 2 still names lost what version 1 paid for");
        }
        // MEASURED, the class this closes: grow the file that sorts FIRST. Cut at fixed 256 KB marks (v1's rule) that
        // moves every later byte, so the big file is stored again; cut at file boundaries only it and the header are new
        let mut grown = files();
        grown[2].1 = b"<p>about, and more</p>".to_vec();
        let blob3 = pack_site(&grown).expect("packs");
        let (f1, f3) = (ChunkedSite::cut_at(&blob, &[]).expect("v1 cut"), ChunkedSite::cut_at(&blob3, &[]).expect("v1 cut"));
        assert!(new_bytes(Some(&f1), &f3) > 2 * CHUNK_BYTES as u64, "the fixed cut was expected to re-store the big file");
        let s3 = ChunkedSite::of(&blob3).expect("chunks");
        assert_eq!(new_bytes(Some(&s), &s3), site_header_len(&blob3[..16]).expect("a header") + 22, "the file-boundary cut stored more than the change");
        assert!(again.knows(&s2.root()) && !again.knows(&root), "the old version is still listed beside the new one");
        assert_eq!(again.stored_publishes(), vec![publish2.clone()]);
        drop(again);
        let third = SiteHost::open(&tmp.0, store_bytes_for(64, CHUNK_BYTES)).expect("reopened again");
        assert!(third.knows(&s2.root()) && !third.knows(&root), "the forgotten head came back after a reopen");
        // another site (another name) is untouched by all of this
        assert_eq!(third.stats().2, 1);
    }

    #[test]
    fn a_frame_is_taken_only_for_an_anchored_root_and_is_passed_on_once() {
        let (ta, tb) = (TempStore::new("frames-a"), TempStore::new("frames-b"));
        let blob = pack_site(&files()).expect("packs");
        let s = ChunkedSite::of(&blob).expect("chunks");
        let root = s.root();
        let chunk = |i: usize| s.piece(&blob, i as u64).expect("a chunk").to_vec();
        let mut b = SiteHost::open(&tb.0, store_bytes_for(64, CHUNK_BYTES)).expect("b");
        b.note_publish(&root, b"the signed publish, as it travelled");
        let (yes, no, mine) = (|_: &Hash32| true, |_: &Hash32| false, |_: &Hash32| true);
        // a root no publish anchors: nothing is kept and nothing is passed on
        assert!(on_frame(&mut b, no, mine, &frame_index(&root, &s.index_bytes())).is_empty());
        assert!(!b.knows(&root), "⛔ bytes for an unanchored root were kept");
        // a chunk before its index: the node asks for the index, once
        let asked = on_frame(&mut b, yes, mine, &frame_chunk(&root, 0, &chunk(0)));
        assert_eq!(asked, vec![frame_want(&root, WANT_INDEX)]);
        assert!(on_frame(&mut b, yes, mine, &frame_chunk(&root, 0, &chunk(0))).is_empty(), "the same question was sent twice");
        // the index arrives: kept and passed on once; a second copy is not passed on again
        let index = frame_index(&root, &s.index_bytes());
        let passed = on_frame(&mut b, yes, mine, &index);
        assert_eq!(passed[0], index, "the index was not passed on");
        // a site this node just learned of: it asks for each piece it lacks, once
        let wants: Vec<Vec<u8>> = (0..s.chunks.len() as u64).map(|i| frame_want(&root, i)).collect();
        assert_eq!(&passed[1..], &wants[..]);
        assert!(on_frame(&mut b, yes, mine, &index).is_empty(), "a frame was passed on twice");
        // a forged index and a wrong chunk under the real root: dropped
        assert!(on_frame(&mut b, yes, mine, &frame_index(&root, &ChunkedSite::of(b"another site").unwrap().index_bytes())).is_empty());
        let mut wrong = chunk(1);
        wrong[5] ^= 1;
        assert!(on_frame(&mut b, yes, mine, &frame_chunk(&root, 1, &wrong)).is_empty(), "⛔ a wrong chunk was passed on");
        assert_eq!(b.read(&root, 0, 16).err(), Some(Gap::Chunks(vec![0])));
        // the real chunks: kept, passed on
        for i in 0..s.chunks.len() {
            let f = frame_chunk(&root, i as u64, &chunk(i));
            assert_eq!(on_frame(&mut b, yes, mine, &f), vec![f.clone()], "chunk {i} was not passed on");
        }
        assert_eq!(b.locate(&root, "index.html").expect("whole").map(|(_, len)| len), Some(13));
        // a node that has it answers a question; a node that does not passes the question on, once
        let mut a = SiteHost::open(&ta.0, store_bytes_for(64, CHUNK_BYTES)).expect("a");
        let want = frame_want(&root, 2);
        assert_eq!(on_frame(&mut a, yes, mine, &want), vec![want.clone()]);
        assert!(on_frame(&mut a, yes, mine, &want).is_empty());
        assert_eq!(on_frame(&mut b, yes, mine, &want), vec![frame_chunk(&root, 2, &chunk(2))]);
        assert_eq!(on_frame(&mut b, yes, mine, &frame_want(&root, WANT_INDEX)), vec![frame_index(&root, &s.index_bytes())]);
        // junk is not a frame
        assert!(!is_frame(b"short") && on_frame(&mut b, yes, mine, b"not a frame at all, just some bytes that are long enough to count").is_empty());
    }

    #[test]
    fn the_price_is_for_the_new_bytes_and_is_paid_once() {
        assert_eq!(storage_price_atomic(1 << 20), STORAGE_ATOMIC_PER_MB);
        assert_eq!(storage_price_atomic(2 << 20), 100_000_000, "a 2 MB site is one dollar");
        assert_eq!(storage_price_atomic(0), 0);
        // one byte is 50,000,000 / 1,048,576 = 47.68 atomic units: charged as 48, never 47 (a price rounds UP)
        assert_eq!(storage_price_atomic(1), 48, "a price rounds up to the atomic unit");
        assert_eq!(storage_price_atomic(21), 1002, "21 bytes are 1,001.36 atomic units: charged as 1,002");
        let v1 = site(3 * CHUNK_BYTES + 100);
        let s1 = ChunkedSite::of(&v1).expect("v1");
        assert_eq!(new_bytes(None, &s1), v1.len() as u64, "a first version pays for all of it");
        assert_eq!(new_bytes(Some(&s1), &s1), 0, "publishing the same bytes again costs no storage");
        // one chunk changed: only that chunk is paid for
        let mut v2 = v1.clone();
        v2[CHUNK_BYTES + 5] ^= 1;
        let s2 = ChunkedSite::of(&v2).expect("v2");
        assert_eq!(new_bytes(Some(&s1), &s2), CHUNK_BYTES as u64);
    }
}

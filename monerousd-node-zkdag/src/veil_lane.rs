// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE VEIL'S PRIVATE LANE (docs/VEIL-SOVEREIGN-INTERNET-SPEC-20261107.md §4, §5, §6): what one node asks another,
//! point to point, about site bytes. Every ask here is ONE request on a FRESH circuit to a holder's own hidden
//! address (the transport's `mix_request_to`: a new isolation token per ask, one request, one answer, the stream
//! drops), so the node that answers never learns which node asked.
//!
//! ```text
//! STOCK   "what is readable in each of your slots?"                          → its inventory, the same for every asker
//! READ    a slot of the holder's whole store, by a point-function key      → the XOR of the chunks the key selects
//! TERMS   "where is your operator paid for hosting?"                         → its public address keys
//! PAID    "this note pays you for these bytes" (sealed to the holder)        → taken note of
//! PUT     bytes under a root the holder has SEEN paid for                    → kept, or refused
//! PROVE   "show a piece of the site, drawn from this block hash"             → the piece and its path to the root
//! ```
//!
//! ⭐ A READ THE HOLDER CANNOT SEE. A reader that lacks a site asks TWO holders, each for one share of a distributed
//! point function over the 2^17 slots a holder's store is read through (Boyle, Gilboa and Ishai's construction;
//! `pqmix::dpf`). Each holder XORs together every item its share selects and returns one chunk-sized answer. A share
//! alone is uniformly random, so a holder learns nothing about which slot, chunk or site was wanted; the two answers
//! XOR to the wanted item, which the reader checks against the root before it uses a byte.
//!
//! TWO HOLDERS NEVER HOLD EXACTLY THE SAME BYTES, and the two answers cancel only over items both hold. So a holder
//! first states its INVENTORY: for each slot, a short id of the one item readable there. That is public and the same
//! for every asker (which sites a node stores is no secret, and asking for it says nothing about what will be read).
//! A read then names, beside its share, the set of slots where the two holders' inventories AGREE, and each holder
//! XORs only over those. The set is a function of the two inventories alone, never of the item wanted. An item's
//! slot is a public function of its site's root and its place in the site, in each of two tables, so an item that
//! loses its slot to another in one table (the smaller id stays) is read through the other.
//!
//! WHAT A READ STILL SHOWS, plainly: that some node read something from this holder now (never which node: the
//! circuit is fresh; never what: the share is random), and, if the TWO holders asked compare their shares, the slot.
//! With only one other holder known, both shares go to it on two circuits and it can pair them: such a read hides who
//! reads, not what.
//!
//! ⭐ STORAGE IS PAID FOR, ONCE, TO THE NODES THAT HOLD THE BYTES. A publisher asks each holder of a site its TERMS
//! (the public keys of the wallet its operator provisioned for rewards), pays each its share with an ordinary private
//! payment, and tells each holder alone the 32 bytes the payment's note was made from. The note's commitment is a
//! function of the amount, the holder's own address key and those bytes (BORROWED: the contract layer's publisher-fee
//! note, `asset_note_cm(fee, USDm, owner_opening(spk, seed))`, which a node checks with no key of anyone's), so the
//! holder recomputes it and keeps the bytes as PAID from the moment its own chain carries that commitment. No proof
//! is made, no chain rule changes, and nobody but the holder can tell that note from any other. The operator's wallet
//! finds the note by its ordinary scan and spends it like any payment.
//!
//! What payment buys: a paid site gives its place in a holder's store up LAST. Bytes nobody paid a node for are a
//! reader's cache there and go first. What it does not buy: a guarantee past what honest nodes keep. A publisher (or
//! anyone) can ask any holder to PROVE it still holds a paid site, from a block hash of the asker's choosing.
//!
//! §9.6, the door every ask here is (it parallels the Veil's own frame door, `veil::on_frame`): (1) proof of work:
//! none, as on that door; an ask is not a block. (2) its own proof: a READ and a PROVE change nothing; a PAID is only
//! remembered, and decides nothing until this node's own chain carries the commitment it names; a PUT is taken only
//! for a root this node has seen paid for, and only when the bytes hash to what that root binds. (3) value: none is
//! created or moved here; the payment is an ordinary spend judged by the spend doors. (4) replay: bytes are kept once
//! by hash; a claim told twice is one entry; a commitment pays for one root. (5) work a hostile ask can cause: a READ
//! is one pass over the store and an inventory one listing of it, both metered by the relay allowance
//! (`SiteHost::may_serve_bytes`); a PUT is one hash
//! of at most one chunk; a PAID is one decapsulation and one small hash; a PROVE is one chunk read. (6) parity with
//! `on_frame`: that door takes bytes for a root a signed publish anchors; this one for a root a payment anchors, and
//! in both nothing is taken on a peer's word.
//!
//! CACHE-ONLY: nothing here decides anything for the chain; a holder's "paid" mark is its own record of a payment the
//! chain carries, and governs only what this node's own store gives up first.
//! TWO-PARTY-REVIEWED: this module is the two ends' own encodings and verdicts, unit-tested end against end. That a
//! site published and paid for through one node is read privately through another, and that an unpaid site gives way
//! to a paid one, is the real-node check `scratchpad/net/veil.py`.

use crate::hash::Hash32;
use crate::pqmix::dpf;
use crate::veil::{ChunkedSite, SiteHost, StorageAnswer, CHUNK_BYTES, WANT_INDEX};

/// The bulk lane kind of every ask in this module.
pub const BULK_REQ_KIND_VEIL: u8 = 27;
const ASK_READ: u8 = 1;
const ASK_TERMS: u8 = 2;
const ASK_PAID: u8 = 3;
const ASK_PUT: u8 = 4;
const ASK_PROVE: u8 = 5;

/// The first bytes of every answer in this module (the bulk inbox routes a page by them).
pub const ANSWER_TAG: &[u8; 7] = b"VEILANS";

/// log2 of the slots a holder's store is read through: two tables of 2^16.
// PRODUCTION-SCALE-REVIEWED: the read table's address space (two tables of 65,536 slots), not a count of chunks: a
// default store holds about 2,000 chunks, so an item loses its slot in BOTH tables about once in a thousand; a larger
// store is read the same way.
pub const READ_DEPTH: usize = 17;
const TABLE_SLOTS: u64 = 1 << (READ_DEPTH - 1);
/// The bytes of a read's slot set: one bit a slot.
const SET_BYTES: usize = 1 << (READ_DEPTH - 3);
const ASK_INVENTORY: u8 = 6;

/// Is `page` an answer of this module?
#[must_use]
pub fn is_answer(page: &[u8]) -> bool {
    page.len() >= 8 && &page[..7] == ANSWER_TAG
}

/// Is `req` an ask of this module? (Never 12 bytes: that length is the bulk lane's oldest door.)
#[must_use]
pub fn is_ask(req: &[u8]) -> bool {
    req.len() >= 2 && req.len() != 12 && req[0] == BULK_REQ_KIND_VEIL
}

fn ask(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len() + 1);
    out.push(BULK_REQ_KIND_VEIL);
    out.push(kind);
    out.extend_from_slice(body);
    if out.len() == 12 {
        out.push(0); // never the bulk lane's 12-byte door
    }
    out
}

fn answer(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(ANSWER_TAG);
    out.push(kind);
    out.extend_from_slice(body);
    out
}

// ── reads ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// The slot item `n` of the site `root` binds is read through in `table` (0 or 1): [`WANT_INDEX`] for its index,
/// else chunk `n`.
#[must_use]
pub fn read_slot(root: &Hash32, n: u64, table: u8) -> u64 {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(b"MonerousD Veil read slot v2/");
    buf.push(table & 1);
    buf.extend_from_slice(root.as_bytes());
    buf.extend_from_slice(&n.to_le_bytes());
    let h = Hash32::hash(&buf);
    u64::from(table & 1) * TABLE_SLOTS + u64::from(u16::from_le_bytes([h.as_bytes()[0], h.as_bytes()[1]]))
}

/// The short id an inventory gives the item in a slot: for a chunk the start of its hash (the reader knows it from
/// the index), for an index a value the reader computes from the root alone.
#[must_use]
pub fn item_id(root: &Hash32, n: u64, chunk: Option<&Hash32>) -> [u8; 8] {
    let mut id = [0u8; 8];
    match chunk {
        Some(hash) if n != WANT_INDEX => id.copy_from_slice(&hash.as_bytes()[..8]),
        _ => {
            let mut buf = b"MonerousD Veil index item v1/".to_vec();
            buf.extend_from_slice(root.as_bytes());
            id.copy_from_slice(&Hash32::hash(&buf).as_bytes()[..8]);
        }
    }
    id
}

/// READER: the two asks for the item at `slot`, one for each of two holders, each restricted to the slots in `set`
/// (one bit a slot: where the two holders' inventories agree). `random` is 64 fresh bytes from the OS; `ticket` is 16
/// more, by which the reader knows the two answers again (each side has its own half, so the two holders cannot pair
/// the asks by it).
#[must_use]
pub fn read_asks(slot: u64, set: &[u8], random: &[u8; 2 * dpf::SEED], ticket: &[u8; 16]) -> Option<[Vec<u8>; 2]> {
    if set.len() != SET_BYTES {
        return None;
    }
    let (a, b) = dpf::gen(slot, &[1], READ_DEPTH, random)?;
    let one = |side: u8, key: &dpf::Key| {
        let mut body = side_ticket(ticket, side).to_vec();
        body.extend_from_slice(&key.to_bytes());
        body.extend_from_slice(set);
        ask(ASK_READ, &body)
    };
    Some([one(0, &a), one(1, &b)])
}

/// The ticket one side of a read carries: the reader's ticket under that side's own hash.
#[must_use]
pub fn side_ticket(ticket: &[u8; 16], side: u8) -> [u8; 16] {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(b"MonerousD Veil read side v1/");
    buf.extend_from_slice(ticket);
    buf.push(side);
    let mut out = [0u8; 16];
    out.copy_from_slice(&Hash32::hash(&buf).as_bytes()[..16]);
    out
}

/// The items a holder's store is read through: slot → the one item readable there (its id, its site and its place).
/// Every item sits in both tables; two items in one slot: the smaller id stays.
fn read_table(host: &SiteHost) -> std::collections::HashMap<u64, ([u8; 8], Hash32, u64)> {
    let mut table: std::collections::HashMap<u64, ([u8; 8], Hash32, u64)> = std::collections::HashMap::new();
    let mut place = |id: [u8; 8], root: Hash32, n: u64| {
        for t in 0..2u8 {
            let slot = read_slot(&root, n, t);
            match table.get(&slot) {
                Some((held, held_root, _)) if (held, held_root.as_bytes()) <= (&id, root.as_bytes()) => {}
                _ => {
                    table.insert(slot, (id, root, n));
                }
            }
        }
    };
    for (root, site) in host.sites() {
        place(item_id(root, WANT_INDEX, None), *root, WANT_INDEX);
        for (i, chunk) in site.chunks.iter().enumerate() {
            place(item_id(root, i as u64, Some(chunk)), *root, i as u64);
        }
    }
    table
}

/// ANYONE: "what is readable in each of your slots?" `nonce` comes back in the answer.
#[must_use]
pub fn inventory_ask(nonce: &[u8; 16]) -> Vec<u8> {
    ask(ASK_INVENTORY, nonce)
}

/// HOLDER: this node's inventory: every occupied slot and the id of the item readable there. The same for every
/// asker; it names what this node stores, which its placement already makes public.
pub fn answer_inventory(host: &mut SiteHost, req: &[u8]) -> Option<Vec<u8>> {
    let nonce = req.get(2..18).filter(|_| is_ask(req) && req[1] == ASK_INVENTORY)?;
    let table = read_table(host);
    // metered like a read: an inventory is at most a few hundred kilobytes and costs one pass to list
    if !host.may_serve_bytes(16 + 12 * table.len() as u64) {
        return None;
    }
    let mut body = Vec::with_capacity(16 + 12 * table.len());
    body.extend_from_slice(nonce);
    let mut rows: Vec<(u64, [u8; 8])> = table.into_iter().map(|(slot, (id, ..))| (slot, id)).collect();
    rows.sort_unstable();
    for (slot, id) in rows {
        body.extend_from_slice(&(slot as u32).to_le_bytes());
        body.extend_from_slice(&id);
    }
    Some(answer(ASK_INVENTORY, &body))
}

/// A holder's inventory as the asker keeps it: slot → item id.
pub type Inventory = std::collections::HashMap<u64, [u8; 8]>;

/// ASKER: the nonce and the inventory an answer carries.
#[must_use]
pub fn parse_inventory(page: &[u8]) -> Option<([u8; 16], Inventory)> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_INVENTORY)?;
    let nonce: [u8; 16] = body.get(..16)?.try_into().ok()?;
    let rows = &body[16..];
    if rows.len() % 12 != 0 || rows.len() / 12 > 1 << READ_DEPTH {
        return None;
    }
    let mut inv = Inventory::with_capacity(rows.len() / 12);
    for r in rows.chunks_exact(12) {
        let slot = u64::from(u32::from_le_bytes([r[0], r[1], r[2], r[3]]));
        if slot >> READ_DEPTH != 0 {
            return None;
        }
        inv.insert(slot, r[4..].try_into().ok()?);
    }
    Some((nonce, inv))
}

/// The slots where two inventories name the same item, one bit a slot: what a read of those two holders is taken
/// over. A function of the two inventories alone.
#[must_use]
pub fn agreed_slots(a: &Inventory, b: &Inventory) -> Vec<u8> {
    let mut set = vec![0u8; SET_BYTES];
    for (slot, id) in a {
        if b.get(slot) == Some(id) {
            set[(*slot / 8) as usize] |= 1 << (*slot % 8);
        }
    }
    set
}

/// HOLDER: the answer to one read ask: the XOR of every item the key selects among the slots the ask's set names,
/// each padded to a whole chunk. Every occupied slot is evaluated, so the work says nothing about the slot asked for.
/// `None` for an ask that is not a read, or when reads are over their allowance (the reader asks again).
pub fn answer_read(host: &mut SiteHost, req: &[u8]) -> Option<Vec<u8>> {
    let body = req.get(2..).filter(|_| is_ask(req) && req[1] == ASK_READ)?;
    let ticket: [u8; 16] = body.get(..16)?.try_into().ok()?;
    let key_len = body.len().checked_sub(16 + SET_BYTES)?;
    let key = dpf::Key::from_bytes(body.get(16..16 + key_len)?, READ_DEPTH, 1)?;
    let set = &body[16 + key_len..];
    if !host.may_serve_read() {
        return None;
    }
    let mut out = vec![0u8; CHUNK_BYTES];
    for (slot, (_, root, n)) in read_table(host) {
        let named = set[(slot / 8) as usize] >> (slot % 8) & 1 == 1;
        let selected = dpf::eval(&key, slot).first().is_some_and(|b| b & 1 == 1);
        if !(named && selected) {
            continue;
        }
        let item = if n == WANT_INDEX { host.index(&root) } else { host.chunk(&root, n) };
        if let Some(item) = item {
            for (o, c) in out.iter_mut().zip(&item) {
                *o ^= c;
            }
        }
    }
    let mut body = ticket.to_vec();
    body.extend_from_slice(&out);
    Some(answer(ASK_READ, &body))
}

/// READER: a read answer's side ticket and its chunk-sized bytes.
#[must_use]
pub fn parse_read_answer(page: &[u8]) -> Option<([u8; 16], &[u8])> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_READ)?;
    (body.len() == 16 + CHUNK_BYTES).then(|| (body[..16].try_into().unwrap_or([0; 16]), &body[16..]))
}

/// READER: the index of `root` from two holders' answers. `None` unless the two XOR to the index that root binds.
#[must_use]
pub fn combine_index(root: &Hash32, a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != CHUNK_BYTES || b.len() != CHUNK_BYTES {
        return None;
    }
    let whole: Vec<u8> = a.iter().zip(b).map(|(x, y)| x ^ y).collect();
    // an index says its own length: eight bytes of site length, four of chunk count, then a length and a hash a chunk
    let count = u32::from_le_bytes(whole.get(8..12)?.try_into().ok()?) as usize;
    let len = crate::veil::index_len(count)?;
    let index = &whole[..len];
    (ChunkedSite::from_index(index)?.root() == *root && whole[len..].iter().all(|b| *b == 0)).then(|| index.to_vec())
}

/// READER: chunk `n` of a site from two holders' answers. `None` unless the two XOR to the chunk the index names.
#[must_use]
pub fn combine_chunk(site: &ChunkedSite, n: u64, a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let len = site.len_of(n)?;
    let chunk = crate::veil::pir_combine(a, b, len)?;
    (site.chunks.get(usize::try_from(n).ok()?) == Some(&crate::veil::chunk_hash(&chunk))).then_some(chunk)
}

// ── terms and payment ─────────────────────────────────────────────────────────────────────────────────────────

/// Where a holder's operator is paid for hosting: the public keys of the wallet it provisioned for rewards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The holder's public node id.
    pub holder: String,
    /// The operator wallet's spend key, canonical 32 bytes.
    pub spk: [u8; 32],
    /// The operator wallet's ML-KEM-768 encapsulation key.
    pub scan_ek: Vec<u8>,
    /// ⛔ AUDIT F11, CLOSED HERE: the one-time locator triple `(locator, salt, hint)` of a receive address under the
    /// operator wallet's reward-only locator key, at an index this node reserved for THIS answer from the same counter
    /// its block rewards draw on (so no index is handed out twice, and two payments are never linkable by their tag).
    /// A note paid to it is tagged exactly as a block reward is, and the operator's wallet finds and spends it by the
    /// sweep it already runs for rewards. Without it a payment sealed to the bare keys was one its owner could not find.
    pub receive: Option<([u8; crate::oli::LOC_BYTES], [u8; 8], [u8; 8])>,
}

impl Terms {
    /// The receive address a publisher pays this holder at: a v4 address carrying the reserved locator triple and the
    /// operator wallet's spend key. `None` without a reserved locator (the holder is not paid then).
    #[must_use]
    pub fn address(&self) -> Option<String> {
        let (loc, salt, hint) = self.receive.as_ref()?;
        let spk = crate::spend_frontier::cm_bytes_to_root(&self.spk)?;
        // the address's id half is never read when a locator is present (a payer tags by the locator); it names the
        // spend key so two holders' addresses never share it
        let b = *Hash32::hash(&self.spk).as_bytes();
        crate::address::pq_stealth_address_v4(crate::address::PQ_ADDR_TAG_TESTNET, &b, &self.scan_ek, Some((loc, salt, hint)), &spk)
    }
}

/// Is `req` a request for this holder's terms (the one ask that reserves a receive index)?
#[must_use]
pub fn is_terms_ask(req: &[u8]) -> bool {
    is_ask(req) && req.get(1) == Some(&ASK_TERMS)
}

/// ML-KEM-768 encapsulation key width.
const EK_BYTES: usize = 1184;

/// PUBLISHER: "what are your terms?" `nonce` comes back in the answer.
#[must_use]
pub fn terms_ask(nonce: &[u8; 16]) -> Vec<u8> {
    ask(ASK_TERMS, nonce)
}

/// HOLDER: this node's terms, or that it has none (its operator provisioned no wallet). `seal_ek` is the node's own
/// letter key: what a publisher seals its payment notice to.
#[must_use]
pub fn answer_terms(req: &[u8], terms: Option<&Terms>, seal_ek: &[u8]) -> Option<Vec<u8>> {
    let nonce = req.get(2..18).filter(|_| is_ask(req) && req[1] == ASK_TERMS)?;
    let mut body = nonce.to_vec();
    if let Some(t) = terms.filter(|t| t.scan_ek.len() == EK_BYTES && seal_ek.len() == EK_BYTES && t.holder.len() <= 128) {
        body.push(t.holder.len() as u8);
        body.extend_from_slice(t.holder.as_bytes());
        body.extend_from_slice(&t.spk);
        body.extend_from_slice(&t.scan_ek);
        body.extend_from_slice(seal_ek);
        if let Some((loc, salt, hint)) = &t.receive {
            body.extend_from_slice(loc);
            body.extend_from_slice(salt);
            body.extend_from_slice(hint);
        }
    }
    Some(answer(ASK_TERMS, &body))
}

/// PUBLISHER: the nonce an answer carries, and the holder's terms and letter key when it has any.
#[must_use]
pub fn parse_terms(page: &[u8]) -> Option<([u8; 16], Option<(Terms, Vec<u8>)>)> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_TERMS)?;
    let nonce: [u8; 16] = body.get(..16)?.try_into().ok()?;
    let rest = &body[16..];
    if rest.is_empty() {
        return Some((nonce, None));
    }
    let n = usize::from(*rest.first()?);
    let holder = String::from_utf8(rest.get(1..1 + n)?.to_vec()).ok()?;
    let rest = rest.get(1 + n..)?;
    let keys = 32 + 2 * EK_BYTES;
    let receive = match rest.len() {
        n if n == keys => None,
        n if n == keys + crate::oli::LOC_BYTES + 16 => {
            let r = &rest[keys..];
            Some((r[..crate::oli::LOC_BYTES].try_into().ok()?, r[crate::oli::LOC_BYTES..crate::oli::LOC_BYTES + 8].try_into().ok()?, r[crate::oli::LOC_BYTES + 8..].try_into().ok()?))
        }
        _ => return None,
    };
    let terms = Terms { holder, spk: rest[..32].try_into().ok()?, scan_ek: rest[32..32 + EK_BYTES].to_vec(), receive };
    Some((nonce, Some((terms, rest[32 + EK_BYTES..keys].to_vec()))))
}

/// A holder's share of the storage price of `total_len` bytes held by `holders` nodes, in atomic USDm, rounded up.
#[must_use]
pub fn price_share(total_len: u64, holders: usize) -> u64 {
    crate::veil::storage_price_atomic(total_len).div_ceil(holders.max(1) as u64)
}

/// The least a holder takes as its share: the price split among as many holders as a site ever has.
#[must_use]
pub fn least_share(total_len: u64) -> u64 {
    price_share(total_len, crate::node::Node::NF_SHARD_REPLICATION as usize)
}

/// The 32 bytes a storage payment's note is made from: canonical bytes of a seed bound to the site, its length, the
/// holder paid and a secret only the publisher and that holder learn. The payer's wallet seals the note from them
/// (`seal_publisher_fee_note`'s shape) and the holder recomputes the note's commitment from them.
#[must_use]
pub fn pay_seed(root: &Hash32, total_len: u64, holder: &str, secret: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MonerousD Veil storage payment note seed v1");
    h.update(root.as_bytes());
    h.update(&total_len.to_le_bytes());
    h.update(&(holder.len() as u64).to_le_bytes());
    h.update(holder.as_bytes());
    h.update(secret);
    crate::spend_frontier::leaf_to_cm_bytes(crate::spend_frontier::note_leaf_of(h.finalize().as_bytes()))
}

/// The commitment of the note that pays `amount` to the wallet whose spend key is `spk` under `seed`
/// ([`pay_seed`]): what a holder looks for on its chain. `None` when a value is not canonical.
#[must_use]
pub fn pay_note_cm(spk: &[u8; 32], amount: u64, seed: &[u8; 32]) -> Option<[u8; 32]> {
    let (spk, seed) = (crate::spend_frontier::cm_bytes_to_root(spk)?, crate::spend_frontier::cm_bytes_to_root(seed)?);
    let opening = usdm_decider::whir_rec_block::owner_opening(&spk, &seed);
    Some(crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(amount, usdm_decider::whir_rec_block::USDM_ASSET_TAG, opening)))
}

/// What a publisher tells one holder about one payment. `total_len` is the bytes PAID FOR: a whole site, or for an
/// update the bytes of its new chunks alone (a holder counts what it was already paid to keep).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub root: Hash32,
    pub total_len: u64,
    pub amount: u64,
    pub secret: [u8; 32],
}

impl Evidence {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&self.total_len.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.secret);
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Evidence> {
        if b.len() != 80 {
            return None;
        }
        Some(Evidence {
            root: Hash32::from_slice(&b[..32])?,
            total_len: u64::from_le_bytes(b[32..40].try_into().ok()?),
            amount: u64::from_le_bytes(b[40..48].try_into().ok()?),
            secret: b[48..].try_into().ok()?,
        })
    }
}

/// PUBLISHER: the ask that tells a holder of a payment, sealed to the holder's letter key so no relay of the circuit,
/// now or later, reads the secret. `own_ek` is the asking node's own letter key (the seal names a sender key; nothing
/// is sent back to it).
#[must_use]
pub fn paid_ask(e: &Evidence, holder_seal_ek: &[u8], own_ek: &[u8]) -> Option<Vec<u8>> {
    Some(ask(ASK_PAID, &crate::letter::seal(holder_seal_ek, own_ek, &e.to_bytes())?))
}

/// HOLDER: take note of a payment. The notice is opened with this node's letter key; the payment must be at least
/// this node's least share for those bytes; the commitment it implies is remembered until the chain shows it. The
/// answer says only that the notice was read, never whether the payment is good: that is the chain's to say.
pub fn answer_paid(host: &mut SiteHost, req: &[u8], terms: Option<&Terms>, own_seal_secret: &[u8]) -> Option<Vec<u8>> {
    let sealed = req.get(2..).filter(|_| is_ask(req) && req[1] == ASK_PAID)?;
    let read = (|| {
        let opened = crate::letter::open(sealed, own_seal_secret)?;
        let e = Evidence::from_bytes(&opened.msg)?;
        let t = terms?;
        if e.total_len == 0 || e.amount < least_share(e.total_len) {
            return None;
        }
        let cm = pay_note_cm(&t.spk, e.amount, &pay_seed(&e.root, e.total_len, &t.holder, &e.secret))?;
        host.claim(cm, e.root, e.total_len);
        Some(())
    })()
    .is_some();
    Some(answer(ASK_PAID, &[u8::from(read)]))
}

/// PUBLISHER: was the notice read?
#[must_use]
pub fn parse_paid(page: &[u8]) -> Option<bool> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_PAID)?;
    (body.len() == 1).then(|| body[0] == 1)
}

// ── puts ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// PUBLISHER: hand a holder item `n` of `root` ([`WANT_INDEX`] for the index).
#[must_use]
pub fn put_ask(root: &Hash32, n: u64, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(40 + bytes.len());
    body.extend_from_slice(root.as_bytes());
    body.extend_from_slice(&n.to_le_bytes());
    body.extend_from_slice(bytes);
    ask(ASK_PUT, &body)
}

/// HOLDER: keep the item, when this node has seen `root` paid for and the bytes are what the root binds. The answer
/// names the item and says: kept (1), not paid for here yet (2), or not that item (0).
pub fn answer_put(host: &mut SiteHost, req: &[u8]) -> Option<Vec<u8>> {
    let body = req.get(2..).filter(|_| is_ask(req) && req[1] == ASK_PUT)?;
    let root = Hash32::from_slice(body.get(..32)?)?;
    let n = u64::from_le_bytes(body.get(32..40)?.try_into().ok()?);
    let bytes = body.get(40..)?;
    let verdict = if !host.accepts(&root) {
        2u8
    } else if n == WANT_INDEX {
        u8::from(host.put_index(&root, bytes))
    } else {
        u8::from(host.put_chunk(&root, n, bytes, true))
    };
    let mut out = body[..40].to_vec();
    out.push(verdict);
    Some(answer(ASK_PUT, &out))
}

/// PUBLISHER: `(root, n, verdict)` of a put answer: 1 kept, 2 not paid for there yet, 0 refused.
#[must_use]
pub fn parse_put(page: &[u8]) -> Option<(Hash32, u64, u8)> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_PUT)?;
    (body.len() == 41).then_some(())?;
    Some((Hash32::from_slice(&body[..32])?, u64::from_le_bytes(body[32..40].try_into().ok()?), body[40]))
}

// ── proof of storage ──────────────────────────────────────────────────────────────────────────────────────────

/// ANYONE: "show the piece of `root` that `block` draws for you." `block` is a hash of the asker's choosing (a recent
/// block's, so nobody could have prepared the answer).
#[must_use]
pub fn prove_ask(root: &Hash32, block: &Hash32) -> Vec<u8> {
    let mut body = root.as_bytes().to_vec();
    body.extend_from_slice(block.as_bytes());
    ask(ASK_PROVE, &body)
}

fn hashes(out: &mut Vec<u8>, list: &[Hash32]) {
    out.extend_from_slice(&(list.len() as u16).to_le_bytes());
    for h in list {
        out.extend_from_slice(h.as_bytes());
    }
}

fn take_hashes(b: &mut &[u8]) -> Option<Vec<Hash32>> {
    let n = usize::from(u16::from_le_bytes(b.get(..2)?.try_into().ok()?));
    let bytes = b.get(2..2 + 32 * n)?;
    *b = &b[2 + 32 * n..];
    bytes.chunks_exact(32).map(Hash32::from_slice).collect()
}

/// HOLDER: the piece `block` draws for this node (`holder` is its public id), with its path to the root; an answer
/// with no piece when the site or the drawn chunk is not held here.
pub fn answer_prove(host: &mut SiteHost, req: &[u8], holder: &str) -> Option<Vec<u8>> {
    let body = req.get(2..).filter(|_| is_ask(req) && req[1] == ASK_PROVE && req.len() == 66)?;
    let (root, block) = (Hash32::from_slice(&body[..32])?, Hash32::from_slice(&body[32..])?);
    let mut out = body.to_vec();
    out.push(holder.len().min(128) as u8);
    out.extend_from_slice(&holder.as_bytes()[..holder.len().min(128)]);
    let shown = (|| {
        let site = host.sites().find(|(r, _)| **r == root).map(|(_, s)| s.clone())?;
        let (index, _) = crate::veil::storage_challenge(&block, &root, &site, holder)?;
        let chunk = host.chunk(&root, index)?;
        crate::veil::answer_storage(&site, &block, holder, &chunk)
    })();
    if let Some(a) = shown {
        out.extend_from_slice(&a.shape.total_len.to_le_bytes());
        out.extend_from_slice(&a.shape.count.to_le_bytes());
        out.extend_from_slice(a.shape.lens_digest.as_bytes());
        out.extend_from_slice(&a.index.to_le_bytes());
        out.extend_from_slice(&a.len.to_le_bytes());
        out.extend_from_slice(&a.piece.to_le_bytes());
        out.extend_from_slice(&(a.bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&a.bytes);
        out.extend_from_slice(a.pieces_root.as_bytes());
        hashes(&mut out, &a.piece_path);
        out.extend_from_slice(a.proof.chunks_root.as_bytes());
        hashes(&mut out, &a.proof.path);
    }
    Some(answer(ASK_PROVE, &out))
}

/// ASKER: `(root, block, holder, shown)`: whether the answer shows the piece that block draws for that holder, under
/// that root. A holder that kept only hashes, another piece or another site's bytes reads `false`.
#[must_use]
pub fn parse_prove(page: &[u8]) -> Option<(Hash32, Hash32, String, bool)> {
    let body = page.get(8..).filter(|_| is_answer(page) && page[7] == ASK_PROVE)?;
    let (root, block) = (Hash32::from_slice(body.get(..32)?)?, Hash32::from_slice(body.get(32..64)?)?);
    let n = usize::from(*body.get(64)?);
    let holder = String::from_utf8(body.get(65..65 + n)?.to_vec()).ok()?;
    let mut rest = body.get(65 + n..)?;
    let shown = (|| {
        let word = |b: &mut &[u8]| -> Option<u64> {
            let v = u64::from_le_bytes(b.get(..8)?.try_into().ok()?);
            *b = &b[8..];
            Some(v)
        };
        let hash = |b: &mut &[u8]| -> Option<Hash32> {
            let h = Hash32::from_slice(b.get(..32)?)?;
            *b = &b[32..];
            Some(h)
        };
        let (total_len, count) = (word(&mut rest)?, word(&mut rest)?);
        let lens_digest = hash(&mut rest)?;
        let index = word(&mut rest)?;
        let chunk_len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
        rest = &rest[4..];
        let piece = word(&mut rest)?;
        let len = usize::from(u16::from_le_bytes(rest.get(..2)?.try_into().ok()?));
        let bytes = rest.get(2..2 + len)?.to_vec();
        rest = &rest[2 + len..];
        let pieces_root = hash(&mut rest)?;
        let piece_path = take_hashes(&mut rest)?;
        let chunks_root = hash(&mut rest)?;
        let path = take_hashes(&mut rest)?;
        let shape = crate::veil::Shape { total_len, count, lens_digest };
        let a = StorageAnswer { shape, index, len: chunk_len, piece, bytes, pieces_root, piece_path, proof: crate::veil::ChunkProof { chunks_root, path } };
        (rest.is_empty() && crate::veil::verify_storage(&root, &block, &holder, &a)).then_some(())
    })()
    .is_some();
    Some((root, block, holder, shown))
}

// ── the asking side's memory ──────────────────────────────────────────────────────────────────────────────────

/// What this node is in the middle of asking, kept in RAM: reads waiting for their second answer, the terms holders
/// gave, and the outcome of puts, notices and proofs its own wallet asked for.
///
/// O1-FOOTPRINT-REVIEWED: every map here is bounded by a constant below and holds only what this node's own wallet
/// asked for this session; a read waiting for its pair holds one chunk.
#[derive(Default)]
pub struct Client {
    /// side ticket → (the read's own ticket, which side).
    sides: std::collections::HashMap<[u8; 16], ([u8; 16], u8)>,
    /// ticket → the read and the answers so far.
    reads: std::collections::HashMap<[u8; 16], Read>,
    /// The sites this node's own wallet asked to read and lacks: root → when it was last asked for, in ms.
    wants: std::collections::HashMap<Hash32, u64>,
    /// terms nonce → the holder asked.
    asked_terms: std::collections::HashMap<[u8; 16], String>,
    /// inventory nonce → the holder asked.
    asked_inventory: std::collections::HashMap<[u8; 16], String>,
    /// holder id → its inventory, and when it was asked for and when it arrived (ms; 0: never).
    inventories: std::collections::HashMap<String, (Inventory, u64, u64)>,
    /// holder id → its terms and letter key (`None`: it has none).
    terms: std::collections::HashMap<String, Option<(Terms, Vec<u8>)>>,
    /// (root, item) → how many holders said they kept it, and how many said it is not paid for there yet.
    puts: std::collections::HashMap<(Hash32, u64), (u32, u32)>,
    /// How many payment notices were read by their holder.
    pub notices_read: u64,
    /// How many items (an index or a piece) this node took from two holders' answers and kept, since it started. A
    /// count of this node's own reads, shown to its own operator; it names no site.
    pub items_read: u64,
    /// (root, holder) → whether it showed its piece.
    proofs: std::collections::HashMap<(Hash32, String), bool>,
}

struct Read {
    root: Hash32,
    n: u64,
    /// The two holders asked: a pair whose answer does not check out has its inventories asked for again.
    holders: [String; 2],
    answers: [Option<Vec<u8>>; 2],
    asked_ms: u64,
}

/// How long an inventory is read from before it is asked for again, and how long an ask for one waits.
const INVENTORY_FRESH_MS: u64 = 120_000;
const INVENTORY_WAIT_MS: u64 = 20_000;

/// How many reads wait for answers at once, and how long one waits before its place is free again.
// PRODUCTION-SCALE-REVIEWED: a bound on this node's OWN reads in flight (each holds at most one chunk in RAM while it
// waits); more wanted items wait their turn, none is refused.
const READS_IN_FLIGHT: usize = 4;
const READ_WAIT_MS: u64 = 45_000;
/// The most entries any of the wallet-facing maps holds.
// PRODUCTION-SCALE-REVIEWED: bounds on what one wallet session can make its own node remember; old entries make room.
const HELD: usize = 1024;

/// What a tick asks to have sent: `(holder index, the ask)`.
pub type Send = (usize, Vec<u8>);

impl Client {
    /// The wallet wants to read the site `root` binds.
    pub fn want(&mut self, root: Hash32) {
        if self.wants.len() >= HELD {
            self.wants.clear();
        }
        self.wants.entry(root).or_insert(0);
    }

    #[must_use]
    pub fn wanted(&self) -> Vec<Hash32> {
        self.wants.keys().copied().collect()
    }

    /// THE NEXT ASKS to send for one wanted site, as `(index into holders, the ask)`. First each holder's inventory
    /// (when it is not known or has gone stale); then, for the site's index when the host lacks it, else for its
    /// missing chunks, as many reads as fit in flight. Each read is two asks to two holders whose inventories both
    /// show the wanted item in one of its slots, restricted to the slots where those two inventories agree; with one
    /// holder known, both go to it. `fresh` gives OS randomness. A site that is whole leaves the wanted list.
    pub fn next_reads(&mut self, host: &SiteHost, root: &Hash32, holders: &[String], now_ms: u64, fresh: &mut dyn FnMut(&mut [u8]) -> bool) -> Vec<Send> {
        self.reads.retain(|_, r| now_ms.saturating_sub(r.asked_ms) < READ_WAIT_MS);
        let live: std::collections::HashSet<[u8; 16]> = self.reads.keys().copied().collect();
        self.sides.retain(|_, (t, _)| live.contains(t));
        if holders.is_empty() {
            return Vec::new();
        }
        let items: Vec<(u64, [u8; 8])> = match host.sites().find(|(r, _)| *r == root) {
            Some((_, site)) => host.missing(root).into_iter().filter_map(|n| Some((n, item_id(root, n, Some(site.chunks.get(usize::try_from(n).ok()?)?))))).collect(),
            None => vec![(WANT_INDEX, item_id(root, WANT_INDEX, None))],
        };
        if items.is_empty() {
            self.wants.remove(root);
            return Vec::new();
        }
        let mut out = Vec::new();
        // inventories first: a holder whose inventory is unknown or stale is asked for it (once per wait)
        if self.inventories.len() > HELD {
            self.inventories.clear();
        }
        for (i, holder) in holders.iter().enumerate() {
            let (asked, got) = self.inventories.get(holder).map_or((0, 0), |(_, asked, got)| (*asked, *got));
            let stale = got == 0 || now_ms.saturating_sub(got) >= INVENTORY_FRESH_MS;
            if stale && (asked == 0 || now_ms.saturating_sub(asked) >= INVENTORY_WAIT_MS) {
                let mut nonce = [0u8; 16];
                if !fresh(&mut nonce) {
                    break;
                }
                if self.asked_inventory.len() >= HELD {
                    self.asked_inventory.clear();
                }
                self.asked_inventory.insert(nonce, holder.clone());
                self.inventories.entry(holder.clone()).or_insert_with(|| (Inventory::new(), 0, 0)).1 = now_ms.max(1);
                out.push((i, inventory_ask(&nonce)));
            }
        }
        let known: Vec<usize> = (0..holders.len()).filter(|i| self.inventories.get(&holders[*i]).is_some_and(|(_, _, got)| *got != 0)).collect();
        for (n, id) in items {
            if self.reads.len() >= READS_IN_FLIGHT {
                break;
            }
            if self.reads.values().any(|r| r.root == *root && r.n == n) {
                continue;
            }
            // every (pair of holders, table) whose two inventories both show this item in its slot
            let shows = |i: usize, slot: u64| self.inventories.get(&holders[i]).is_some_and(|(inv, ..)| inv.get(&slot) == Some(&id));
            let mut choices: Vec<(usize, usize, u64)> = Vec::new();
            for t in 0..2u8 {
                let slot = read_slot(root, n, t);
                let have: Vec<usize> = known.iter().copied().filter(|i| shows(*i, slot)).collect();
                if holders.len() == 1 {
                    choices.extend(have.iter().map(|i| (*i, *i, slot)));
                }
                for (x, i) in have.iter().enumerate() {
                    choices.extend(have[x + 1..].iter().map(|j| (*i, *j, slot)));
                }
            }
            if choices.is_empty() {
                continue;
            }
            let (mut random, mut ticket, mut pick) = ([0u8; 2 * dpf::SEED], [0u8; 16], [0u8; 2]);
            if !fresh(&mut random) || !fresh(&mut ticket) || !fresh(&mut pick) {
                break;
            }
            let (i, j, slot) = choices[usize::from(u16::from_le_bytes(pick)) % choices.len()];
            let set = match (self.inventories.get(&holders[i]), self.inventories.get(&holders[j])) {
                (Some((a, ..)), Some((b, ..))) => agreed_slots(a, b),
                _ => continue,
            };
            let Some(asks) = read_asks(slot, &set, &random, &ticket) else { continue };
            // which of the pair gets which share is drawn too
            let order = if pick[0] & 0x80 == 0 { [i, j] } else { [j, i] };
            for (side, (holder, ask)) in order.into_iter().zip(asks).enumerate() {
                self.sides.insert(side_ticket(&ticket, side as u8), (ticket, side as u8));
                out.push((holder, ask));
            }
            self.reads.insert(ticket, Read { root: *root, n, holders: [holders[order[0]].clone(), holders[order[1]].clone()], answers: [None, None], asked_ms: now_ms });
        }
        if let Some(at) = self.wants.get_mut(root) {
            *at = now_ms;
        }
        out
    }

    /// An answer page arrived. A read whose second answer this is, and which checks out against its root, is stored
    /// in `host` (as a reader's copy). Everything else is remembered for the wallet to read.
    pub fn on_answer(&mut self, host: &mut SiteHost, page: &[u8]) {
        if let Some((side_ticket, bytes)) = parse_read_answer(page) {
            let Some((ticket, side)) = self.sides.remove(&side_ticket) else { return };
            let Some(read) = self.reads.get_mut(&ticket) else { return };
            read.answers[usize::from(side & 1)] = Some(bytes.to_vec());
            let [Some(a), Some(b)] = &read.answers else { return };
            let (root, n) = (read.root, read.n);
            let kept = if n == WANT_INDEX {
                combine_index(&root, a, b).is_some_and(|index| host.put_read_index(&root, &index))
            } else {
                let chunk = host.sites().find(|(r, _)| **r == root).and_then(|(_, site)| combine_chunk(site, n, a, b));
                chunk.is_some_and(|chunk| host.put_chunk(&root, n, &chunk, false))
            };
            self.items_read += u64::from(kept);
            // answered, right or wrong. A pair whose answer does not check out lied or changed what it holds since
            // it stated its inventory: both inventories are asked for again before either is read from.
            if let Some(read) = self.reads.remove(&ticket) {
                if !kept {
                    for holder in &read.holders {
                        if let Some(entry) = self.inventories.get_mut(holder) {
                            (entry.1, entry.2) = (0, 0);
                        }
                    }
                }
            }
        } else if let Some((nonce, inventory)) = parse_inventory(page) {
            if let Some(holder) = self.asked_inventory.remove(&nonce) {
                let asked = self.inventories.get(&holder).map_or(1, |(_, asked, _)| *asked);
                // it arrived now, as far as the next tick's clock can tell: stamped with the time it was asked for
                self.inventories.insert(holder, (inventory, asked, asked.max(1)));
            }
        } else if let Some((nonce, terms)) = parse_terms(page) {
            if let Some(holder) = self.asked_terms.remove(&nonce) {
                // a holder's terms name the holder that was asked, or they are not its terms
                let terms = terms.filter(|(t, _)| t.holder == holder);
                if self.terms.len() >= HELD {
                    self.terms.clear();
                }
                self.terms.insert(holder, terms);
            }
        } else if let Some(read) = parse_paid(page) {
            self.notices_read += u64::from(read);
        } else if let Some((root, n, verdict)) = parse_put(page) {
            if self.puts.len() >= HELD {
                self.puts.clear();
            }
            let e = self.puts.entry((root, n)).or_insert((0, 0));
            match verdict {
                1 => e.0 += 1,
                2 => e.1 += 1,
                _ => {}
            }
        } else if let Some((root, _, holder, shown)) = parse_prove(page) {
            if self.proofs.len() >= HELD {
                self.proofs.clear();
            }
            self.proofs.insert((root, holder), shown);
        }
    }

    /// PUBLISHER: remember that `holder` was asked its terms under `nonce`.
    pub fn asked(&mut self, nonce: [u8; 16], holder: &str) {
        if self.asked_terms.len() >= HELD {
            self.asked_terms.clear();
        }
        self.asked_terms.insert(nonce, holder.to_string());
    }

    /// What `holder` answered: `None` not answered yet, `Some(None)` it has no terms.
    #[must_use]
    pub fn terms_of(&self, holder: &str) -> Option<Option<(Terms, Vec<u8>)>> {
        self.terms.get(holder).cloned()
    }

    /// `holder`'s terms were used for a payment: forget them, so the next payment asks again and is handed a FRESH
    /// receive locator (one locator, one payment: two payments to one holder are never linkable by their tag).
    pub fn spent_terms(&mut self, holder: &str) {
        self.terms.remove(holder);
    }

    /// `(kept, not paid for yet)` holders for an item this node put.
    #[must_use]
    pub fn put_verdicts(&self, root: &Hash32, n: u64) -> (u32, u32) {
        self.puts.get(&(*root, n)).copied().unwrap_or((0, 0))
    }

    /// The holders that answered a proof ask for `root`, each with whether it showed its piece.
    #[must_use]
    pub fn proofs_of(&self, root: &Hash32) -> Vec<(String, bool)> {
        self.proofs.iter().filter(|((r, _), _)| r == root).map(|((_, h), shown)| (h.clone(), *shown)).collect()
    }
}

/// Fresh bytes from the OS, as the node's keystore reads them. False when the OS gives none: the caller then sends
/// nothing (a read asked with predictable shares would hide nothing).
pub fn os_random(buf: &mut [u8]) -> bool {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
}

static CLIENT: std::sync::LazyLock<std::sync::Mutex<Client>> = std::sync::LazyLock::new(|| std::sync::Mutex::new(Client::default()));

/// This process's asking side.
pub fn client() -> std::sync::MutexGuard<'static, Client> {
    CLIENT.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(len: usize, salt: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut block = *blake3::hash(&[salt]).as_bytes();
        while out.len() < len {
            out.extend_from_slice(&block[..block.len().min(len - out.len())]);
            block = *blake3::hash(&block).as_bytes();
        }
        out
    }

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn host(name: &str, mb: u64) -> (SiteHost, Tmp) {
        let path = std::env::temp_dir().join(format!("veil-lane-{}-{name}.slab", std::process::id()));
        let _ = std::fs::remove_file(&path);
        (SiteHost::open(&path, mb << 20).expect("a store"), Tmp(path))
    }

    /// A holder that holds `blob` as a paid site (seen paid, then put).
    fn holding(host: &mut SiteHost, blob: &[u8]) -> (Hash32, ChunkedSite) {
        let site = ChunkedSite::of(blob).expect("a site");
        let root = site.root();
        host.mark_paid(&root);
        assert!(host.put_index(&root, &site.index_bytes()));
        for (i, chunk) in site.pieces(blob).enumerate() {
            assert!(host.put_chunk(&root, i as u64, chunk, true));
        }
        (root, site)
    }

    fn os(buf: &mut [u8]) -> bool {
        os_random(buf)
    }

    /// One asking round: every ask the client wants sent is answered by its holder, and the answer handed back.
    fn round(client: &mut Client, reader: &mut SiteHost, root: &Hash32, stores: &mut [&mut SiteHost], now: u64, bend: &dyn Fn(usize, &mut Vec<u8>)) -> usize {
        let ids: Vec<String> = (0..stores.len()).map(|i| format!("holder-{i}")).collect();
        let sends = client.next_reads(reader, root, &ids, now, &mut os);
        let sent = sends.len();
        for (k, (holder, ask)) in sends.into_iter().enumerate() {
            assert!(is_ask(&ask) && ask.len() != 12);
            assert!(!ask.windows(32).any(|w| w == root.as_bytes()), "an ask carries the root in the clear");
            let mut page = answer_inventory(stores[holder], &ask).or_else(|| answer_read(stores[holder], &ask)).expect("a holder answers");
            bend(k, &mut page);
            client.on_answer(reader, &page);
        }
        sent
    }

    /// TWO-PARTY-REVIEWED: two holders and a reader, each its own store, joined by the asks and answers alone.
    #[test]
    fn a_site_is_read_through_two_holders_whose_stores_differ_and_neither_ask_names_it() {
        let (mut a, _ta) = host("read-a", 8);
        let (mut b, _tb) = host("read-b", 8);
        let (mut reader, _tr) = host("read-r", 8);
        let blob = bytes(2 * CHUNK_BYTES + 777, 1);
        let (root, site) = holding(&mut a, &blob);
        holding(&mut b, &blob);
        // each holder also holds bytes the other does not: the read is taken over the slots where the two agree
        holding(&mut a, &bytes(CHUNK_BYTES / 2, 2));
        holding(&mut a, &bytes(3 * CHUNK_BYTES, 8));
        holding(&mut b, &bytes(100, 3));

        let mut client = Client::default();
        client.want(root);
        let mut rounds = 0;
        while !client.wanted().is_empty() {
            rounds += 1;
            assert!(rounds < 12, "the read did not finish");
            round(&mut client, &mut reader, &root, &mut [&mut a, &mut b], 1_000 * rounds, &|_, _| {});
        }
        assert_eq!(reader.read(&root, 0, site.total_len).expect("the whole site is here now"), blob);
        assert!(!reader.is_paid(&root), "what a reader fetched is its own copy, never a paid site");

        // the two asks of one read select different sets, and each alone selects about half the slots
        let (random, ticket) = ([7u8; 64], [9u8; 16]);
        let slot = read_slot(&root, 1, 0);
        let set = vec![0xFFu8; SET_BYTES];
        let asks = read_asks(slot, &set, &random, &ticket).expect("asks");
        let key = |ask: &[u8]| dpf::Key::from_bytes(&ask[18..ask.len() - SET_BYTES], READ_DEPTH, 1).expect("a key");
        let picked = |k: &dpf::Key| (0..1u64 << READ_DEPTH).filter(|x| dpf::eval(k, *x).first().is_some_and(|v| v & 1 == 1)).count();
        let (ka, kb) = (key(&asks[0]), key(&asks[1]));
        assert!(picked(&ka).abs_diff(1 << (READ_DEPTH - 1)) < 1 << (READ_DEPTH - 4), "a share selects about half the table");
        let differ: Vec<u64> = (0..1u64 << READ_DEPTH).filter(|x| dpf::eval(&ka, *x).first().map(|v| v & 1) != dpf::eval(&kb, *x).first().map(|v| v & 1)).collect();
        assert_eq!(differ, vec![slot], "the two shares differ at the wanted slot alone");
        assert_ne!(asks[0][2..18], asks[1][2..18], "the two holders cannot pair the asks by their tickets");
        // the slot set a read names is a function of the two inventories, the same whatever item is wanted
        let inv = |h: &mut SiteHost| parse_inventory(&answer_inventory(h, &inventory_ask(&[5; 16])).expect("answers")).expect("parses").1;
        let (ia, ib) = (inv(&mut a), inv(&mut b));
        let agreed = agreed_slots(&ia, &ib);
        assert!(ia.len() > ib.len() && agreed.iter().map(|b| b.count_ones() as usize).sum::<usize>() < ia.len(), "the stores really differ");
        for t in 0..2u8 {
            for n in [WANT_INDEX, 0, 1, 2] {
                let s = read_slot(&root, n, t);
                assert!(agreed[(s / 8) as usize] >> (s % 8) & 1 == 1, "an item both hold is in the agreed set");
            }
        }
    }

    /// TWO-PARTY-REVIEWED: a holder and a reader, each its own store; the lie is told on the path between them.
    #[test]
    fn a_holder_that_answers_wrong_is_caught_by_the_root_and_asked_again() {
        let (mut a, _ta) = host("lie-a", 4);
        let (mut reader, _tr) = host("lie-r", 4);
        let blob = bytes(CHUNK_BYTES + 5, 4);
        let (root, site) = holding(&mut a, &blob);
        let mut client = Client::default();
        client.want(root);
        // one holder known: its inventory, then both shares of the index go to it. One answer is altered on the way.
        assert_eq!(round(&mut client, &mut reader, &root, &mut [&mut a], 1_000, &|_, _| {}), 1, "the inventory is asked for first");
        let sent = round(&mut client, &mut reader, &root, &mut [&mut a], 2_000, &|k, page| {
            if k == 1 {
                page[30] ^= 1;
            }
        });
        assert_eq!(sent, 2);
        assert!(!reader.knows(&root), "⛔ an index that does not hash to its root was kept");
        assert_eq!(client.wanted(), vec![root], "the site is still wanted, so it is asked for again");
        // asked again (its inventory first, since its answer did not check out), answered honestly, it arrives
        for r in 3..14 {
            round(&mut client, &mut reader, &root, &mut [&mut a], 1_000 * r, &|_, _| {});
        }
        assert_eq!(reader.read(&root, 0, site.total_len).expect("whole"), blob);
        // an ask that is not a read is not answered as one, and a truncated one is refused
        assert!(answer_read(&mut a, &terms_ask(&[1; 16])).is_none());
        let asks = read_asks(read_slot(&root, 0, 0), &vec![0xFF; SET_BYTES], &[1u8; 64], &[2u8; 16]).expect("asks");
        assert!(answer_read(&mut a, &asks[0][..asks[0].len() - 1]).is_none());
        assert!(read_asks(1 << READ_DEPTH, &vec![0xFF; SET_BYTES], &[1u8; 64], &[2u8; 16]).is_none(), "a slot outside the table");
        // AN INVENTORY THAT LIES about what a holder has gains nothing: the read it leads to does not check out
        let mut forged = answer_inventory(&mut a, &inventory_ask(&[4; 16])).expect("answers");
        forged.truncate(8 + 16);
        assert_eq!(parse_inventory(&forged).map(|(_, inv)| inv.len()), Some(0));
        let mut odd = forged.clone();
        odd.extend_from_slice(&[0u8; 5]);
        assert!(parse_inventory(&odd).is_none(), "a ragged inventory is refused");
    }

    /// TWO-PARTY-REVIEWED: a publisher's asks against a holder's own store and keys.
    #[test]
    fn bytes_are_kept_on_a_payment_the_chain_shows_and_on_nothing_less() {
        let (mut h, _t) = host("paid", 4);
        let blob = bytes(CHUNK_BYTES + 99, 5);
        let site = ChunkedSite::of(&blob).expect("a site");
        let root = site.root();
        let (seal_ek, seal_secret) = crate::pqkem::keypair();
        let (own_ek, _) = crate::pqkem::keypair();
        let (scan_ek, _) = crate::pqkem::keypair();
        let spk = crate::spend_frontier::leaf_to_cm_bytes(crate::spend_frontier::note_leaf_of(&[0x5B; 32]));
        let terms = Terms { holder: "holder-1".to_string(), spk, scan_ek, receive: None };

        // TERMS travel whole, and only under the nonce that asked
        let ask = terms_ask(&[3u8; 16]);
        let page = answer_terms(&ask, Some(&terms), &seal_ek).expect("answers");
        assert_eq!(parse_terms(&page), Some(([3u8; 16], Some((terms.clone(), seal_ek.clone())))));
        assert_eq!(parse_terms(&answer_terms(&ask, None, &seal_ek).expect("answers")), Some(([3u8; 16], None)), "a node with no wallet named has no terms");
        // AUDIT F11: terms carry a receive locator the holder's wallet finds, and its address is a payable one
        assert_eq!(terms.address(), None, "terms with no reserved locator name no address: the holder is not paid");
        let k = [0x42u8; 32];
        let dom = crate::satoshi::SAT_LOC_DOMAIN;
        let at = |j: u64| { let salt = crate::oli::address_salt(&k, dom, j); (crate::oli::locator_at(&k, dom, j), salt, crate::oli::address_index_hint(&k, &salt, j)) };
        let paid = Terms { receive: Some(at(7)), ..terms.clone() };
        assert_eq!(parse_terms(&answer_terms(&ask, Some(&paid), &seal_ek).expect("answers")), Some(([3u8; 16], Some((paid.clone(), seal_ek.clone())))), "the locator did not travel");
        let parsed = crate::address::parse_address_full(&paid.address().expect("an address")).expect("parses");
        assert!(parsed.locator == Some(at(7).0) && parsed.spk.is_some(), "the holder's address is not one its wallet can be paid at");
        // the tag a payment to it carries is the one the operator's wallet sweeps for under its reward-only key
        assert_eq!(crate::oli::tag_clue_bytes_v2(&at(7).0, &at(7).1, &at(7).2), crate::satoshi::reward_clue(&k, 7), "⛔ the holder's wallet would not find the payment");
        assert_ne!(Terms { receive: Some(at(8)), ..terms.clone() }.address(), paid.address(), "two reserved indexes gave one address");
        // a lying holder: a locator of the wrong length is not terms at all
        let mut cut = answer_terms(&ask, Some(&paid), &seal_ek).expect("answers");
        cut.pop();
        assert_eq!(parse_terms(&cut), None);

        // a PUT before any payment is refused, and so is one after a payment this node was only TOLD of
        let put_index = put_ask(&root, WANT_INDEX, &site.index_bytes());
        assert_eq!(parse_put(&answer_put(&mut h, &put_index).expect("answers")), Some((root, WANT_INDEX, 2)));
        let amount = least_share(site.total_len);
        let e = Evidence { root, total_len: site.total_len, amount, secret: [0x11; 32] };
        let told = answer_paid(&mut h, &paid_ask(&e, &seal_ek, &own_ek).expect("sealed"), Some(&terms), &seal_secret).expect("answers");
        assert_eq!(parse_paid(&told), Some(true));
        assert!(h.watching() && !h.is_paid(&root));
        assert_eq!(parse_put(&answer_put(&mut h, &put_index).expect("answers")), Some((root, WANT_INDEX, 2)), "⛔ a payment merely told of bought room");
        // the chain shows OTHER commitments: nothing changes
        assert!(h.note_commitment(&[9u8; 32]).is_none());
        // … then the one the notice implies: the note of that amount to this holder's key under the notice's seed
        let cm = pay_note_cm(&spk, amount, &pay_seed(&root, site.total_len, "holder-1", &e.secret)).expect("a commitment");
        assert_eq!(h.note_commitment(&cm), Some(root));
        assert!(h.accepts(&root) && !h.is_paid(&root), "seen on the chain, and judged when the index arrives");
        assert_eq!(parse_put(&answer_put(&mut h, &put_index).expect("answers")), Some((root, WANT_INDEX, 1)));
        assert!(h.is_paid(&root), "the payment covers every byte of the site");
        for (i, chunk) in blob.chunks(CHUNK_BYTES).enumerate() {
            assert_eq!(parse_put(&answer_put(&mut h, &put_ask(&root, i as u64, chunk)).expect("answers")), Some((root, i as u64, 1)));
        }
        assert_eq!(parse_put(&answer_put(&mut h, &put_ask(&root, 0, &bytes(CHUNK_BYTES, 9))).expect("answers")), Some((root, 0, 0)), "⛔ bytes the root does not bind were kept");
        assert_eq!(h.read(&root, 0, site.total_len).expect("whole"), blob);

        // THE COMMITMENT IS BOUND to the amount, the holder, the site, its length and the secret
        for other in [
            pay_note_cm(&spk, amount + 1, &pay_seed(&root, site.total_len, "holder-1", &e.secret)),
            pay_note_cm(&spk, amount, &pay_seed(&root, site.total_len, "holder-2", &e.secret)),
            pay_note_cm(&spk, amount, &pay_seed(&root, site.total_len + 1, "holder-1", &e.secret)),
            pay_note_cm(&spk, amount, &pay_seed(&Hash32::hash(b"another"), site.total_len, "holder-1", &e.secret)),
            pay_note_cm(&spk, amount, &pay_seed(&root, site.total_len, "holder-1", &[0x12; 32])),
        ] {
            assert_ne!(other, Some(cm));
        }
        // A NOTICE THAT BUYS NOTHING: too little, opened with another node's key, or read by a node with no wallet named
        let (mut h2, _t2) = host("paid-2", 4);
        let cheap = Evidence { amount: amount - 1, ..e.clone() };
        assert_eq!(parse_paid(&answer_paid(&mut h2, &paid_ask(&cheap, &seal_ek, &own_ek).expect("sealed"), Some(&terms), &seal_secret).expect("answers")), Some(false));
        let (_, wrong_secret) = crate::pqkem::keypair();
        assert_eq!(parse_paid(&answer_paid(&mut h2, &paid_ask(&e, &seal_ek, &own_ek).expect("sealed"), Some(&terms), &wrong_secret).expect("answers")), Some(false));
        assert_eq!(parse_paid(&answer_paid(&mut h2, &paid_ask(&e, &seal_ek, &own_ek).expect("sealed"), None, &seal_secret).expect("answers")), Some(false));
        assert!(!h2.watching());
        // A PAYMENT FOR FEWER BYTES THAN THE SITE HOLDS pays for nothing: the notice is good for 1,000 bytes, the chain
        // shows it, and the index that arrives names a site far larger
        let (mut h3, _t3) = host("paid-3", 4);
        let small = Evidence { total_len: 1_000, amount: least_share(1_000), ..e.clone() };
        assert_eq!(parse_paid(&answer_paid(&mut h3, &paid_ask(&small, &seal_ek, &own_ek).expect("sealed"), Some(&terms), &seal_secret).expect("answers")), Some(true));
        let small_cm = pay_note_cm(&spk, small.amount, &pay_seed(&root, 1_000, "holder-1", &small.secret)).expect("a commitment");
        assert_eq!(h3.note_commitment(&small_cm), Some(root));
        assert_eq!(parse_put(&answer_put(&mut h3, &put_index).expect("answers")), Some((root, WANT_INDEX, 1)), "the index itself is taken");
        assert!(!h3.is_paid(&root), "⛔ a payment for a thousand bytes paid for a whole site");
        assert_eq!(parse_put(&answer_put(&mut h3, &put_ask(&root, 0, &blob[..CHUNK_BYTES])).expect("answers")), Some((root, 0, 2)), "and its chunks are refused");
        // the notice on the wire names neither the root nor the secret
        let sealed = paid_ask(&e, &seal_ek, &own_ek).expect("sealed");
        assert!(!sealed.windows(32).any(|w| w == root.as_bytes() || w == e.secret), "a payment notice travels in the clear");
        // the price is split so the shares cover it, and a lone holder takes it all
        assert!(price_share(site.total_len, 4) * 4 >= crate::veil::storage_price_atomic(site.total_len));
        assert_eq!(price_share(site.total_len, 1), crate::veil::storage_price_atomic(site.total_len));
    }

    /// TWO-PARTY-REVIEWED: one holder's own store, before and after a reopen.
    #[test]
    fn a_paid_site_outlasts_unpaid_bytes_and_survives_a_reopen() {
        let path = std::env::temp_dir().join(format!("veil-lane-{}-keep.slab", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _t = Tmp(path.clone());
        // room for five whole chunks: a paid site of one chunk takes its chunk's pages and one more for its head
        let budget = crate::veil::store_bytes_for(5, CHUNK_BYTES);
        let paid_blob = bytes(CHUNK_BYTES, 6);
        let root = {
            let mut h = SiteHost::open(&path, budget).expect("a store");
            let (root, _) = holding(&mut h, &paid_blob);
            // unpaid bytes fill the rest and then some: each is another site a publisher paid nobody here for
            for salt in 20u8..30 {
                let blob = bytes(CHUNK_BYTES, salt);
                let site = ChunkedSite::of(&blob).expect("a site");
                let r = site.root();
                h.note_publish(&r, b"a publish some node adopted");
                assert!(h.put_index(&r, &site.index_bytes()));
                let _ = h.put_chunk(&r, 0, &blob, true);
            }
            assert_eq!(h.read(&root, 0, CHUNK_BYTES as u64).expect("the paid site is whole"), paid_blob, "⛔ unpaid bytes pushed a paid site out");
            assert_eq!(h.paid_count(), 1);
            root
        };
        let mut again = SiteHost::open(&path, budget).expect("reopens");
        assert!(again.is_paid(&root), "a reopened store forgot what it was paid for");
        assert_eq!(again.read(&root, 0, CHUNK_BYTES as u64).expect("whole after a reopen"), paid_blob);
    }

    /// TWO-PARTY-REVIEWED: an asker's check against a holder's own store.
    #[test]
    fn a_holder_shows_the_piece_a_block_draws_and_cannot_show_what_it_dropped() {
        let (mut h, _t) = host("prove", 4);
        let blob = bytes(2 * CHUNK_BYTES + 50, 7);
        let (root, _) = holding(&mut h, &blob);
        let block = Hash32::hash(b"a recent block");
        let page = answer_prove(&mut h, &prove_ask(&root, &block), "holder-1").expect("answers");
        assert_eq!(parse_prove(&page), Some((root, block, "holder-1".to_string(), true)));
        // the same answer is no answer for another block, and each holder shows its own piece
        let mut other = page.clone();
        other[8 + 32] ^= 1; // the block hash it claims to answer
        assert!(parse_prove(&other).is_some_and(|(.., shown)| !shown), "⛔ an answer for one block passed for another");
        let as_other = answer_prove(&mut h, &prove_ask(&root, &block), "holder-2").expect("answers");
        assert!(parse_prove(&as_other).is_some_and(|(_, _, who, shown)| who == "holder-2" && shown), "each holder shows its own piece");
        // a holder that does not hold the site answers with nothing to show
        let (mut empty, _te) = host("prove-empty", 4);
        let none = answer_prove(&mut empty, &prove_ask(&root, &block), "holder-3").expect("answers");
        assert_eq!(parse_prove(&none), Some((root, block, "holder-3".to_string(), false)));
        // an answer with a byte of its piece changed is refused
        let mut bent = page.clone();
        let at = 8 + 64 + 1 + "holder-1".len() + 24 + 2 + 3;
        bent[at] ^= 1;
        assert!(parse_prove(&bent).is_some_and(|(.., shown)| !shown), "⛔ a bent piece was shown");
    }
}

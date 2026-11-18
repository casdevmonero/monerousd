// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! PROTECTED PURCHASES IN THE WALLET (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §3, §9.1, §24).
//!
//! A protected purchase locks the price in a VAULT: a note that leaves by the buyer's handover code (the seller takes
//! it), by the seller's refund code (the buyer takes it back early), or by the chain clock (the buyer takes it back at
//! the deadline). Money moves on a code or on the clock, never on a claim, and a purchase is two ordinary-looking
//! payments on the chain.
//!
//! THE HANDSHAKE, three short messages over whatever private channel the two sides have (the merchant's checkout
//! helper, a scanned code, a letter):
//!
//! ```text
//! buyer  -> seller   REQUEST   order id, amount, deadline, buyer's address key, buyer's salt
//! seller -> buyer    ACCEPT    seller's address key, seller's salt, the refund lock
//! buyer  -> seller   FUNDED    the handover lock            (the buyer has locked the price)
//! ```
//!
//! Both sides then compute the same vault and look for its commitment on the chain. The seller hands over only once
//! its own wallet has taken the money with a code its own wallet checked.
//!
//! ⛔ NOTHING HERE IS WRITTEN TO DISK. The buyer's vault note carries its own sealed record (`pq::seal_vault_note`), so a
//! restarted or restored wallet finds its open purchases by scanning, exactly as it finds its money. The seller's side
//! is recomputed from the messages themselves: its salt, its refund code and its lock are functions of this wallet's
//! secret and the request, so the shop keeps the three messages and this wallet keeps no state. The list below is a
//! cache of both, rebuilt from those two sources.
//!
//! ⛔ THE SELLER TAKES THE MONEY, THEN HANDS OVER. A handover code is checked against the vault this wallet computed
//! itself, and the take is refused by the node if the vault was already spent, so "paid" on the seller's screen is the
//! chain's answer and never the buyer's word.
//!
//! O1-FOOTPRINT-REVIEWED: by construction: the cache holds this wallet's OPEN purchases only and lives in RAM.
//!
//! TWO-PARTY-REVIEWED: this module is one wallet's half. The two-wallet check (a buyer and a seller on two real nodes:
//! lock, handover, a second take refused by the set, a refund, a deadline, a restart in between) is the real-node row
//! `vault-purchase`.

use super::*;
use serde::{Deserialize, Serialize};
use usdm_decider::whir_rec_block::{delivery_locks, vault_lock, ListingSalt, VaultBranch, VaultLock, VaultNote, VaultSecret, CHAIN_HOUR_MS, LOCK_LANES, NO_LOCK};

/// One side's view of one protected purchase.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultOrder {
    /// 16 bytes, hex: the name both sides use for this purchase.
    pub id: String,
    /// "buyer" or "seller".
    pub role: String,
    /// What the buyer's sheet showed (the shop and the item). Never leaves this device; empty after a restore.
    pub title: String,
    /// Atomic units the vault holds.
    pub amount: u64,
    /// The chain hour from which the buyer takes the money back alone.
    pub t_h: u64,
    pub buyer_spk: String,
    pub seller_spk: String,
    pub buyer_salt: String,
    pub seller_salt: String,
    /// The handover lock (the seller opens it with the buyer's code). Empty until the buyer has sent FUNDED.
    pub lock1: String,
    /// The refund lock (the buyer opens it with the seller's code).
    pub lock2: String,
    /// "requested", "accepted", "locked".
    pub state: String,
    /// The buyer's order index (it names the id and rides the vault note's record). 0 on the seller's side.
    pub index: u32,
    /// "" for a purchase. "sub" for ONE PERIOD OF A SUBSCRIPTION: the vault is the MERCHANT's from `t_h` (the period's
    /// start: the merchant collects it alone, by the clock), and until then the subscriber takes it back alone with its
    /// own lock. Nobody else's code is involved: `lock1` is empty and `lock2` is the subscriber's.
    ///
    /// "bond" for A BOND: money its POSTER locks for a BENEFICIARY, returned to the poster by a KEYHOLDER's code and
    /// the beneficiary's by the clock if that code never comes. Here `buyer_spk` is the beneficiary, `seller_spk` the
    /// poster (the only party that funds it and the only one `lock1` names), and the keyholder is whoever made the
    /// request (`role` "buyer"; `role` "beneficiary" is a wallet that only waits for the clock). A seller's delivery
    /// bond has the buyer as keyholder and beneficiary; a relay's custody bond has the buyer as keyholder and the
    /// seller as beneficiary. `lock2` is empty: nothing but the keyholder's code gives a bond back early.
    ///
    /// "key" for A DOWNLOAD (spec §3.3): the buyer's vault under the listing's DELIVERY lock, which fills both lock
    /// slots (`lock1 ‖ lock2` is the eight-lane lock the offer states). The seller takes it with its content key, and
    /// that spend publishes the key to the buyer. There is no refund code: an undelivered download comes back to the
    /// buyer at the deadline.
    #[serde(default)]
    pub kind: String,
}

/// The top bit of a buyer's order index says which kind of order its vault note restores as.
const SUB_INDEX_BIT: u32 = 1 << 31;

static ORDERS: Mutex<Vec<VaultOrder>> = Mutex::new(Vec::new());

fn hex32(d: &Digest4) -> String {
    hex::encode(usdmd_node::spend_frontier::leaf_to_cm_bytes(*d))
}

fn digest_of_hex(h: &str) -> Result<Digest4, String> {
    let b: [u8; 32] = hex::decode(h).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| "not a 32-byte value".to_string())?;
    usdmd_node::spend_frontier::cm_bytes_to_root(&b).ok_or_else(|| "not a canonical value".to_string())
}

/// A lock or a code: four field lanes, as 16 bytes.
fn lanes_bytes(l: &[u64; LOCK_LANES]) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, lane) in l.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&(*lane as u32).to_le_bytes());
    }
    b
}

fn lanes_of_bytes(b: &[u8]) -> Result<[u64; LOCK_LANES], String> {
    if b.len() != 4 * LOCK_LANES {
        return Err("that is not a code".to_string());
    }
    let mut out = [0u64; LOCK_LANES];
    for (i, c) in b.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        if v >= (1 << 31) - (1 << 24) {
            return Err("that is not a code".to_string()); // every lane is a field value
        }
        out[i] = u64::from(v);
    }
    Ok(out)
}

pub(crate) fn lanes_hex(l: &[u64; LOCK_LANES]) -> String {
    hex::encode(lanes_bytes(l))
}

pub(crate) fn lanes_of_hex(h: &str) -> Result<[u64; LOCK_LANES], String> {
    lanes_of_bytes(&hex::decode(h.trim()).map_err(|_| "that is not a code".to_string())?)
}

/// A listing's eight-lane delivery lock as 32 bytes of hex: lock 1, then lock 2.
pub(crate) fn delivery_lock_hex(locks: &[VaultLock; 2]) -> String {
    format!("{}{}", lanes_hex(&locks[0]), lanes_hex(&locks[1]))
}

fn delivery_lock_of_hex(h: &str) -> Result<(String, String), String> {
    let h = hex_of_len(h, 8 * LOCK_LANES)?;
    let (a, b) = h.split_at(8 * LOCK_LANES);
    Ok((lanes_hex(&lanes_of_hex(a)?), lanes_hex(&lanes_of_hex(b)?)))
}

/// Four secret lanes this wallet alone derives for `(purpose, about)`: a listing's content key, or its salt.
pub(crate) fn derived_lanes(purpose: &str, about: &str) -> Result<[u64; LOCK_LANES], String> {
    own_secret(about, purpose)
}

fn own_out_sk() -> Result<[u8; 32], String> {
    WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).ok_or_else(|| "no wallet open".to_string())
}

/// 32 bytes this wallet alone derives for `(purpose, about)`: codes, salts and ids are never stored.
fn derived(purpose: &str, about: &[u8]) -> Result<[u8; 32], String> {
    let key = blake3::derive_key("monerousd/wallet/purchase/v1", &own_out_sk()?);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(purpose.as_bytes());
    h.update(b"/");
    h.update(about);
    Ok(*h.finalize().as_bytes())
}

/// The secret this wallet draws for one order: four 30-bit lanes (120 bits).
fn own_secret(order_id: &str, purpose: &str) -> Result<VaultSecret, String> {
    let d = derived(purpose, order_id.as_bytes())?;
    Ok(core::array::from_fn(|i| u64::from(u32::from_le_bytes([d[4 * i], d[4 * i + 1], d[4 * i + 2], d[4 * i + 3]]) & 0x3FFF_FFFF)))
}

fn buyer_id_and_salt(index: u32) -> Result<(String, String), String> {
    let id = hex::encode(&derived("order-id", &index.to_le_bytes())?[..16]);
    let salt = hex::encode(&derived("buyer-salt", id.as_bytes())?[..16]);
    Ok((id, salt))
}

/// The seller's salt for one request: a function of this wallet's secret and everything the request says, so a
/// repeated accept answers the same and a different request never shares a vault.
fn seller_salt_for(o: &VaultOrder) -> Result<String, String> {
    let about = format!("{}/{}/{}/{}/{}", o.id, o.amount, o.t_h, o.buyer_spk, o.buyer_salt);
    Ok(hex::encode(&derived("seller-salt", about.as_bytes())?[..16]))
}

/// The vault both sides compute from the order.
pub fn vault_of(o: &VaultOrder) -> Result<VaultNote, String> {
    // a purchase's default party is the BUYER (undelivered, it comes back); a subscription period's is the MERCHANT
    // (uncancelled, it is the merchant's from the period's start)
    let owner_spk = digest_of_hex(if o.kind == "sub" { &o.seller_spk } else { &o.buyer_spk })?;
    let seed = {
        let mut h = blake3::Hasher::new_derive_key("monerousd/vault/seed/v1");
        h.update(o.id.as_bytes());
        h.update(b"/");
        h.update(o.buyer_salt.as_bytes());
        h.update(b"/");
        h.update(o.seller_salt.as_bytes());
        usdmd_node::spend_frontier::note_leaf_of(h.finalize().as_bytes())
    };
    let lock = |h: &str| -> Result<VaultLock, String> {
        if h.is_empty() {
            Ok(NO_LOCK)
        } else {
            lanes_of_hex(h)
        }
    };
    let v = VaultNote { owner_spk, seed, t_h: o.t_h, lock1: if o.kind == "sub" { NO_LOCK } else { lock(&o.lock1)? }, lock2: lock(&o.lock2)? };
    if !v.is_well_formed() {
        return Err("this purchase's deadline is out of range".to_string());
    }
    Ok(v)
}

/// THE PARTS A PRICE IS HELD IN. A vault is funded by ONE note (a spend has one input and never joins notes), so a
/// price no single note covers is held as several vaults, one per note, that add up to it; one code releases them
/// all. One part whenever a single note covers the price and its fee. Read from the notes this wallet holds now.
pub fn parts_for(price: u64) -> Result<Vec<u64>, String> {
    let mut notes: Vec<u64> =
        owned_note_ids().into_iter().filter(|(a, asset, _)| *asset == pq::USDM_ASSET_TAG && *a > 4 * P2P_FEE_ATOMIC).map(|(a, _, _)| a).collect();
    notes.sort_unstable_by(|a, b| b.cmp(a));
    if notes.iter().any(|a| *a >= price.saturating_add(P2P_FEE_ATOMIC)) {
        return Ok(vec![price]);
    }
    let (mut parts, mut left) = (Vec::new(), price);
    for a in notes {
        if left == 0 {
            break;
        }
        let mut part = (a - P2P_FEE_ATOMIC).min(left);
        // never leave a remainder too small to be a part of its own
        if left > part && left - part <= P2P_FEE_ATOMIC {
            part -= 2 * P2P_FEE_ATOMIC;
        }
        parts.push(part);
        left -= part;
    }
    if left > 0 {
        return Err("you do not hold enough for this purchase. Nothing was sent.".to_string());
    }
    Ok(parts)
}

/// Has the buyer's side said the money is in? A purchase's handover lock, or a subscription period's cancel lock, is set.
fn is_funded(o: &VaultOrder) -> bool {
    if o.kind == "sub" {
        !o.lock2.is_empty()
    } else {
        !o.lock1.is_empty()
    }
}

fn vault_cm_bytes(o: &VaultOrder) -> Result<[u8; 32], String> {
    Ok(usdmd_node::spend_frontier::leaf_to_cm_bytes(vault_of(o)?.note_cm(o.amount)))
}

// ── the open orders: a cache of what the chain and the messages say ─────────────────────────────────────────────

pub fn open_orders() -> Vec<VaultOrder> {
    ORDERS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn put_order(o: &VaultOrder) {
    let mut all = ORDERS.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|x| x.id != o.id);
    all.push(o.clone());
}

fn drop_order(id: &str) {
    ORDERS.lock().unwrap_or_else(|e| e.into_inner()).retain(|x| x.id != id);
}

fn get_order(id: &str) -> Result<VaultOrder, String> {
    open_orders().into_iter().find(|o| o.id == id).ok_or_else(|| "this wallet has no such purchase open".to_string())
}

/// The commitments of the vaults this wallet's open orders are waiting on: the membership book wants them and keeps
/// them (a seller's vault is found by its commitment, never by scanning).
pub fn watched_vaults() -> Vec<[u8; 32]> {
    open_orders().iter().filter(|o| is_funded(o)).filter_map(|o| vault_cm_bytes(o).ok()).collect()
}

/// The buyer's record in its own vault note: the locks in the KEM message; the deadline, the seller's salt and the
/// order index in the 24 bytes after the amount.
fn record_of(o: &VaultOrder) -> Result<([u8; 32], [u8; 24]), String> {
    if o.kind == "bond" {
        // a bond is restored from the letters that made it, never from its note: the record only fills the payload
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&lanes_bytes(&lanes_of_hex(&o.lock1)?));
        let mut tail = [0u8; 24];
        tail[..4].copy_from_slice(&u32::try_from(o.t_h).map_err(|_| "deadline out of range".to_string())?.to_le_bytes());
        tail[20..].copy_from_slice(&u32::MAX.to_le_bytes());
        return Ok((m, tail));
    }
    if o.kind == "sub" {
        // a subscription period: the merchant's key (its two halves), the cancel lock, the period's start, the index
        let merchant = usdmd_node::spend_frontier::leaf_to_cm_bytes(digest_of_hex(&o.seller_spk)?);
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&merchant[..16]);
        m[16..].copy_from_slice(&lanes_bytes(&lanes_of_hex(&o.lock2)?));
        let mut tail = [0u8; 24];
        tail[..4].copy_from_slice(&u32::try_from(o.t_h).map_err(|_| "deadline out of range".to_string())?.to_le_bytes());
        tail[4..20].copy_from_slice(&merchant[16..]);
        tail[20..].copy_from_slice(&o.index.to_le_bytes());
        return Ok((m, tail));
    }
    let mut m = [0u8; 32];
    m[..16].copy_from_slice(&lanes_bytes(&lanes_of_hex(&o.lock1)?));
    m[16..].copy_from_slice(&lanes_bytes(&lanes_of_hex(&o.lock2)?));
    let salt: [u8; 16] = hex::decode(&o.seller_salt).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| "bad seller salt".to_string())?;
    let mut tail = [0u8; 24];
    tail[..4].copy_from_slice(&u32::try_from(o.t_h).map_err(|_| "deadline out of range".to_string())?.to_le_bytes());
    tail[4..20].copy_from_slice(&salt);
    tail[20..].copy_from_slice(&o.index.to_le_bytes());
    Ok((m, tail))
}

/// Seal the vault note of the purchase `vault` belongs to, with its record. The order is the one this wallet holds
/// open for that vault.
pub(crate) fn seal_open_vault(my_ek: &[u8], vault: &VaultNote, amount: u64) -> Result<([u8; pq::PQ_NOTE_BYTES], Digest4), String> {
    // the wallet that FUNDS a vault seals it: the buyer of a purchase or a subscription, the poster of a bond
    let o = open_orders()
        .into_iter()
        .find(|o| ((o.role == "buyer") != (o.kind == "bond")) && o.role != "beneficiary" && vault_of(o).is_ok_and(|v| v == *vault) && o.amount == amount)
        .ok_or_else(|| "this wallet holds no purchase for that vault — nothing was sent".to_string())?;
    let (m, tail) = record_of(&o)?;
    pq::seal_vault_note(my_ek, vault, amount, &own_out_sk()?, &m, &tail)
        .ok_or_else(|| "this purchase's terms cannot be locked — nothing was sent".to_string())
}

/// SCAN: is this note a vault THIS wallet opened? Reads the sealed record its payload carries, recomputes the vault
/// and compares the commitment; a match puts the purchase back in the open list. Returns the commitment.
/// DIGITAL-CASH-PRIVACY-REVIEWED: local only: a decapsulation with this wallet's own key over a note it already holds.
pub fn recognise(note: &[u8]) -> Option<[u8; 32]> {
    let (dk, out_sk) = (own_scan_dk().ok()?, own_out_sk().ok()?);
    let (amount, m, tail) = pq::open_vault_note(note, &dk, &out_sk)?;
    let index = u32::from_le_bytes(tail[20..].try_into().ok()?);
    if index == u32::MAX {
        return None; // a bond this wallet posted: its order comes back from the letters, not from the note
    }
    let (id, buyer_salt) = buyer_id_and_salt(index).ok()?;
    let sub = index & SUB_INDEX_BIT != 0;
    let merchant: [u8; 32] = core::array::from_fn(|i| if i < 16 { m[i] } else { tail[4 + i - 16] });
    let o = if sub {
        VaultOrder {
            id,
            role: "buyer".to_string(),
            title: String::new(),
            amount,
            t_h: u64::from(u32::from_le_bytes(tail[..4].try_into().ok()?)),
            buyer_spk: hex32(&own_note_keys().ok()?.spk),
            seller_spk: hex::encode(merchant),
            buyer_salt,
            seller_salt: String::new(),
            lock1: String::new(),
            lock2: lanes_hex(&lanes_of_bytes(&m[16..]).ok()?),
            state: "locked".to_string(),
            index,
            kind: "sub".to_string(),
        }
    } else {
        VaultOrder {
        id,
        role: "buyer".to_string(),
        title: String::new(),
        amount,
        t_h: u64::from(u32::from_le_bytes(tail[..4].try_into().ok()?)),
        buyer_spk: hex32(&own_note_keys().ok()?.spk),
        seller_spk: String::new(),
        buyer_salt,
        seller_salt: hex::encode(&tail[4..20]),
        lock1: lanes_hex(&lanes_of_bytes(&m[..16]).ok()?),
        lock2: lanes_hex(&lanes_of_bytes(&m[16..]).ok()?),
        state: "locked".to_string(),
        index,
        kind: String::new(),
        }
    };
    let cm = vault_cm_bytes(&o).ok()?;
    if cm[..] != note[..32] {
        return None;
    }
    if get_order(&o.id).is_err() {
        put_order(&o);
    }
    Some(cm)
}

fn own_spk() -> Result<Digest4, String> {
    Ok(own_note_keys()?.spk)
}

fn book_key() -> Result<[u8; 32], String> {
    let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
    let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
    Ok(scan_scope_id(&w.scan_ek))
}

/// Does this wallet hold the vault's membership path, ready to spend from? That is what "the money is locked" means
/// to either side: its OWN wallet saw the vault land and fold.
pub fn vault_is_locked(o: &VaultOrder) -> Result<bool, String> {
    let cm = vault_cm_bytes(o)?;
    let key = book_key()?;
    with_member_book(&key, |b| b.want_all([cm]));
    Ok(with_member_book(&key, |b| b.holds(&cm) && b.leg_ready(&cm).is_ok()))
}

// ── the handshake ────────────────────────────────────────────────────────────────────────────────────────────────

/// BUYER, step 1: ask to buy. `deadline_ms` is when the money comes back if nothing is handed over; it is rounded UP
/// to the hour. Returns the REQUEST to send to the seller.
pub fn order_request(title: &str, amount: u64, deadline_ms: u64) -> Result<serde_json::Value, String> {
    order_request_kind(title, amount, deadline_ms, "")
}

/// [`order_request`] for a purchase (`kind` empty) or for one period of a subscription (`kind` "sub"), whose
/// `deadline_ms` is the period's START: the merchant collects from then, the subscriber cancels until then.
pub fn order_request_kind(title: &str, amount: u64, deadline_ms: u64, kind: &str) -> Result<serde_json::Value, String> {
    use rand::RngCore as _;
    if amount <= P2P_FEE_ATOMIC {
        return Err("the amount is too small to protect".to_string());
    }
    let t_h = usdm_decider::whir_rec_block::chain_hours(deadline_ms.div_ceil(CHAIN_HOUR_MS) * CHAIN_HOUR_MS)
        .ok_or_else(|| "the deadline is out of range".to_string())?;
    // a purchase's index never reads as a bond's marker (all ones) or as a subscription's (the top bit)
    let index = if kind == "sub" { (rand::rngs::OsRng.next_u32() | SUB_INDEX_BIT) & !1 } else { rand::rngs::OsRng.next_u32() & !SUB_INDEX_BIT };
    let (id, buyer_salt) = buyer_id_and_salt(index)?;
    let o = VaultOrder {
        id,
        role: "buyer".to_string(),
        title: title.chars().take(128).collect(),
        amount,
        t_h,
        buyer_spk: hex32(&own_spk()?),
        seller_spk: String::new(),
        buyer_salt,
        seller_salt: String::new(),
        lock1: String::new(),
        lock2: String::new(),
        state: "requested".to_string(),
        index,
        kind: kind.to_string(),
    };
    put_order(&o);
    Ok(serde_json::json!({ "kind": "request", "id": o.id, "amount": o.amount, "t_h": o.t_h, "buyer_spk": o.buyer_spk, "buyer_salt": o.buyer_salt, "of": o.kind }))
}

fn field<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("the message has no `{k}`"))
}

fn hex_of_len(s: &str, bytes: usize) -> Result<String, String> {
    (s.len() == 2 * bytes && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| s.to_ascii_lowercase())
        .ok_or_else(|| "a field of the message is malformed".to_string())
}

/// The seller's order for a REQUEST: its salt and its refund lock are functions of this wallet's secret and the
/// request, so this is the same order every time it is asked (the seller keeps no state).
fn seller_order(request: &serde_json::Value, title: &str) -> Result<VaultOrder, String> {
    if field(request, "kind")? != "request" {
        return Err("that is not a purchase request".to_string());
    }
    let mut o = VaultOrder {
        id: hex_of_len(field(request, "id")?, 16)?,
        role: "seller".to_string(),
        title: title.chars().take(128).collect(),
        amount: request.get("amount").and_then(serde_json::Value::as_u64).ok_or_else(|| "the request names no amount".to_string())?,
        t_h: request.get("t_h").and_then(serde_json::Value::as_u64).ok_or_else(|| "the request names no deadline".to_string())?,
        buyer_spk: hex_of_len(field(request, "buyer_spk")?, 32)?,
        seller_spk: hex32(&own_spk()?),
        buyer_salt: hex_of_len(field(request, "buyer_salt")?, 16)?,
        seller_salt: String::new(),
        lock1: String::new(),
        lock2: String::new(),
        state: "accepted".to_string(),
        index: 0,
        kind: match request.get("of").and_then(|k| k.as_str()) {
            Some("sub") => "sub".to_string(),
            Some("bond") => "bond".to_string(),
            Some("key") => "key".to_string(),
            _ => String::new(),
        },
    };
    if o.kind == "key" {
        // a download: the buyer names the listing's delivery lock; the caller checks it is this seller's own
        (o.lock1, o.lock2) = delivery_lock_of_hex(field(request, "lock")?)?;
    }
    o.seller_salt = seller_salt_for(&o)?;
    if o.kind.is_empty() {
        // the refund lock: the BUYER opens it with this seller's refund code
        let opening = vault_of(&o)?.opening();
        o.lock2 = lanes_hex(&vault_lock(&digest_of_hex(&o.buyer_spk)?, &own_secret(&o.id, "refund")?, &opening));
    }
    Ok(o)
}

/// SELLER, step 2: accept a REQUEST for `expect_amount` (what the seller's own offer says the price is). Returns the
/// ACCEPT to send back.
pub fn order_accept(request: &serde_json::Value, expect_amount: u64, title: &str) -> Result<serde_json::Value, String> {
    let o = seller_order(request, title)?;
    if o.amount != expect_amount {
        return Err("the request's amount is not this sale's price — not accepted".to_string());
    }
    let now_h = usdm_decider::whir_rec_block::chain_hours(node_chain_time_ms()).filter(|h| *h > 0).ok_or_else(|| "the node did not report the chain clock".to_string())?;
    if o.t_h <= now_h {
        return Err("the request's deadline has already passed — not accepted".to_string());
    }
    put_order(&o);
    Ok(serde_json::json!({ "kind": "accept", "id": o.id, "seller_spk": o.seller_spk, "seller_salt": o.seller_salt, "lock2": o.lock2 }))
}

/// What the buyer is asked before the price is locked (the app's command asks; a headless caller has its own consent).
pub fn fund_prompt(accept: &serde_json::Value) -> Result<String, String> {
    let o = get_order(field(accept, "id")?)?;
    Ok(format!(
        "Pay ${:.2} for {} — held in escrow until you confirm receipt, refunded after the deadline",
        o.amount as f64 / 1e8,
        approval_short(&o.title, 40)
    ))
}

/// BUYER, step 3: lock the price. Checks the ACCEPT, computes the vault, pays into it, and returns the FUNDED message
/// to send to the seller.
pub fn order_fund(accept: &serde_json::Value) -> Result<serde_json::Value, String> {
    if field(accept, "kind")? != "accept" {
        return Err("that is not a seller's acceptance".to_string());
    }
    let mut o = get_order(field(accept, "id")?)?;
    if o.role != "buyer" || o.state != "requested" {
        return Err("this purchase is not waiting for a seller's acceptance".to_string());
    }
    o.seller_spk = hex_of_len(field(accept, "seller_spk")?, 32)?;
    o.seller_salt = hex_of_len(field(accept, "seller_salt")?, 16)?;
    if o.kind == "bond" {
        // KEYHOLDER of a bond: name the poster's lock (this wallet's own code opens it) and pay NOTHING. The poster
        // funds the bond; this wallet watches for it.
        let opening = vault_of(&o)?.opening();
        o.lock1 = lanes_hex(&vault_lock(&digest_of_hex(&o.seller_spk)?, &own_secret(&o.id, "handover")?, &opening));
        o.state = "locked".to_string();
        let cm = vault_cm_bytes(&o)?;
        put_order(&o);
        with_member_book(&book_key()?, |b| b.want_all([cm]));
        return Ok(serde_json::json!({ "kind": "funded", "id": o.id, "lock1": o.lock1, "lock2": "" }));
    }
    if o.kind == "key" {
        // a download: both lock slots are the listing's delivery lock, set when the request was made
        if o.lock1.is_empty() || o.lock2.is_empty() {
            return Err("this download has no delivery lock — nothing was sent".to_string());
        }
    } else if o.kind == "sub" {
        // the cancel lock: THIS subscriber opens it with its own secret, until the period starts
        let opening = vault_of(&o)?.opening();
        o.lock2 = lanes_hex(&vault_lock(&own_spk()?, &own_secret(&o.id, "cancel")?, &opening));
    } else {
        o.lock2 = lanes_hex(&lanes_of_hex(field(accept, "lock2")?)?);
        // the handover lock: the SELLER opens it with this buyer's code
        let opening = vault_of(&o)?.opening();
        o.lock1 = lanes_hex(&vault_lock(&digest_of_hex(&o.seller_spk)?, &own_secret(&o.id, "handover")?, &opening));
    }
    let vault = vault_of(&o)?;
    // the book wants the vault BEFORE it is broadcast, so its arrival is captured
    put_order(&o);
    let cm = vault_cm_bytes(&o)?;
    with_member_book(&book_key()?, |b| b.want_all([cm]));
    let own_address =
        wallet_address()?.get("address").and_then(|a| a.as_str()).map(String::from).ok_or_else(|| "no wallet address".to_string())?;
    let sent = match do_transfer_atomic_mode(own_address, o.amount, SlotSend::None, VaultSend::Open(vault)) {
        Ok(v) => v,
        Err(e) => {
            // nothing was locked: the purchase goes back to waiting, and its lock is forgotten (a download's lock is
            // the listing's own and stays)
            if o.kind != "key" {
                o.lock1 = String::new();
            }
            if o.kind == "sub" {
                o.lock2 = String::new();
            }
            put_order(&o);
            return Err(e);
        }
    };
    o.state = "locked".to_string();
    put_order(&o);
    Ok(serde_json::json!({ "kind": "funded", "id": o.id, "lock1": o.lock1, "lock2": o.lock2, "tx_hash": sent.get("tx_hash").cloned().unwrap_or_default() }))
}

/// SELLER, step 4: take the buyer's FUNDED for the REQUEST it answers. Stateless: the shop passes both messages, and
/// the order is recomputed. From here [`order_status`] says when the money is really locked.
pub fn order_funded(request: &serde_json::Value, funded: &serde_json::Value, title: &str) -> Result<serde_json::Value, String> {
    if field(funded, "kind")? != "funded" {
        return Err("that is not a buyer's payment notice".to_string());
    }
    let mut o = seller_order(request, title)?;
    if field(funded, "id")? != o.id {
        return Err("the payment notice is for another purchase".to_string());
    }
    if o.kind == "key" {
        // a download's lock came with the request and is this seller's own listing's; the notice adds nothing to it
    } else if o.kind == "sub" {
        o.lock2 = lanes_hex(&lanes_of_hex(field(funded, "lock2")?)?);
    } else {
        o.lock1 = lanes_hex(&lanes_of_hex(field(funded, "lock1")?)?);
    }
    o.state = "locked".to_string();
    put_order(&o);
    order_status(&o.id)
}

/// BUYER, step 1 of a DOWNLOAD: ask to buy under the listing's delivery lock `lock_hex` (32 bytes: what the offer
/// states and this wallet checked the content proof against). Returns the REQUEST to send.
pub fn key_request(title: &str, amount: u64, deadline_ms: u64, lock_hex: &str) -> Result<serde_json::Value, String> {
    let (lock1, lock2) = delivery_lock_of_hex(lock_hex)?;
    let mut request = order_request_kind(title, amount, deadline_ms, "key")?;
    let mut o = get_order(field(&request, "id")?)?;
    (o.lock1, o.lock2) = (lock1, lock2);
    put_order(&o);
    request["lock"] = serde_json::Value::String(lock_hex.to_ascii_lowercase());
    Ok(request)
}

/// SELLER of a DOWNLOAD: take the buyer's payment with the content key. The spend publishes the key to the buyer, so
/// being paid IS handing it over. Refused unless `key` and `salt` are this vault's own delivery lock's, and refused
/// in the last hour before the deadline: a claim that lands after the buyer may take the money back would publish
/// the key and be paid nothing.
pub fn order_deliver(id: &str, key: VaultSecret, salt: ListingSalt) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind != "key" || o.role != "seller" || o.state != "locked" {
        return Err("this is not a download this wallet is waiting to deliver".to_string());
    }
    let note = vault_of(&o)?;
    if delivery_locks(&own_spk()?, &key, &salt) != [note.lock1, note.lock2] {
        return Err("that key is not this download's — nothing was taken".to_string());
    }
    let now_h = usdm_decider::whir_rec_block::chain_hours(node_chain_time_ms()).filter(|h| *h > 0).ok_or_else(|| "the node did not report the chain clock".to_string())?;
    if now_h + 1 >= o.t_h {
        return Err("too close to this download's deadline to deliver safely — the buyer's payment returns to them".to_string());
    }
    take_with(&o, VaultBranch::Lock1, key, Some(salt))
}

/// BUYER of a DOWNLOAD: the vault this wallet funded and the spent tag the seller's delivery lays, for the claim
/// watch: `(vault, its spent tag as the node names it)`.
pub fn key_vault(id: &str) -> Result<(VaultNote, [u8; 32]), String> {
    let o = get_order(id)?;
    if o.kind != "key" || o.role != "buyer" {
        return Err("that is not a download this wallet bought".to_string());
    }
    let note = vault_of(&o)?;
    Ok((note, usdmd_node::spend_frontier::leaf_to_cm_bytes(note.spent_tag(o.amount))))
}

/// BUYER of a DOWNLOAD: the key arrived; the order is over.
pub fn key_done(id: &str) {
    drop_order(id);
}

/// BUYER of a DOWNLOAD: is `lock_hex` the delivery lock THIS wallet locked purchase `id` under, by its own record of
/// the purchase (the vault it made)? A key letter's offer is the seller's word; this is what it is checked against.
pub fn key_lock_is(id: &str, lock_hex: &str) -> bool {
    get_order(id).is_ok_and(|o| order_is_under_lock(&o, lock_hex))
}

/// Is `o` a purchase this wallet funded under the eight-lane delivery lock `lock_hex`? Judged by the two lock slots
/// alone. NOT by `kind`: an order read back from its vault note after a restart ([`recognise`]) carries no kind (the
/// note's record holds the locks, the hour, the salt and the index, nothing else), and requiring "key" here refused
/// every honest seller's key letter on a reopened wallet. The slots are enough: a purchase that is not a download has
/// the buyer's OWN handover lock in the first slot, a hash a seller cannot choose, so no offer's lock can equal it.
fn order_is_under_lock(o: &VaultOrder, lock_hex: &str) -> bool {
    let Ok((lock1, lock2)) = delivery_lock_of_hex(lock_hex) else { return false };
    o.role == "buyer" && !lock1.is_empty() && o.lock1 == lock1 && o.lock2 == lock2
}

/// Where a purchase stands, read from THIS wallet's own node: `locked` is true once the vault's path is held here.
pub fn order_status(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    let locked = is_funded(&o) && vault_is_locked(&o)?;
    let now_h = usdm_decider::whir_rec_block::chain_hours(node_chain_time_ms()).unwrap_or(0);
    Ok(serde_json::json!({
        "id": o.id, "role": o.role, "title": o.title, "amount": o.amount, "state": o.state, "kind": o.kind,
        "locked": locked,
        "deadline_ms": o.t_h * CHAIN_HOUR_MS,
        "deadline_passed": now_h >= o.t_h,
    }))
}

/// BUYER: the handover code to show the seller once the goods are in hand. Derived, never stored.
pub fn order_code(id: &str) -> Result<String, String> {
    let o = get_order(id)?;
    if o.role != "buyer" || o.state != "locked" || o.kind == "key" {
        return Err("this purchase has no code to show".to_string());
    }
    Ok(format!("{}:{}", o.id, lanes_hex(&own_secret(&o.id, "handover")?)))
}

/// SELLER: the refund code to send the buyer when the sale is called off. Derived, never stored.
pub fn order_refund_code(id: &str) -> Result<String, String> {
    let o = get_order(id)?;
    if o.role != "seller" {
        return Err("only the seller of a purchase has a refund code".to_string());
    }
    Ok(format!("{}:{}", o.id, lanes_hex(&own_secret(&o.id, "refund")?)))
}

fn split_code(code: &str) -> Result<(String, VaultSecret), String> {
    let (id, lanes) = code.trim().split_once(':').ok_or_else(|| "that is not a code".to_string())?;
    Ok((hex_of_len(id, 16)?, lanes_of_hex(lanes)?))
}

fn take(o: &VaultOrder, branch: VaultBranch, secret: VaultSecret) -> Result<serde_json::Value, String> {
    take_with(o, branch, secret, None)
}

fn take_with(o: &VaultOrder, branch: VaultBranch, secret: VaultSecret, deliver: Option<ListingSalt>) -> Result<serde_json::Value, String> {
    let note = vault_of(o)?;
    if !vault_is_locked(o)? {
        return Err("this wallet's node has not confirmed the payment yet — nothing was taken. Try again in a moment.".to_string());
    }
    let (my_ek, b, key_id): (Vec<u8>, [u8; 32], [u8; 32]) = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.scan_ek.clone(), w.b, *blake3::hash(&w.scan_ek).as_bytes())
    };
    let my_spk = own_spk()?;
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let out = spend_one_note_to(
        &agent,
        "protected purchase",
        &b,
        None,
        None,
        &my_ek,
        &my_spk,
        &my_ek,
        o.amount,
        note.seed,
        Vec::new(),
        o.amount - P2P_FEE_ATOMIC,
        P2P_FEE_ATOMIC,
        key_id,
        &Instant::now(),
        SlotSend::None,
        VaultSend::Take { note, branch, secret, deliver },
    )?;
    drop_order(&o.id);
    Ok(out)
}

/// SELLER: is this the purchase's code? Offline: it needs no node. A seller's first check at the door.
pub fn order_code_is_good(code: &str) -> Result<bool, String> {
    let (id, secret) = split_code(code)?;
    let o = get_order(&id)?;
    let note = vault_of(&o)?;
    Ok(o.role == "seller" && note.lock1 != NO_LOCK && vault_lock(&own_spk()?, &secret, &note.opening()) == note.lock1)
}

/// SELLER: take the money with the buyer's handover code. The code is checked against the vault THIS wallet computed
/// before anything is sent; a wrong code changes nothing. Hand over once this returns: the node refuses a vault that
/// was already spent.
pub fn order_release(code: &str) -> Result<serde_json::Value, String> {
    if !order_code_is_good(code)? {
        return Err("that is not this purchase's code — nothing was taken, and nothing should be handed over".to_string());
    }
    let (id, secret) = split_code(code)?;
    let o = get_order(&id)?;
    if o.state != "locked" {
        return Err("this sale is not waiting for a handover code".to_string());
    }
    take(&o, VaultBranch::Lock1, secret)
}

/// BUYER: take the money back with the seller's refund code (the seller called the sale off).
pub fn order_refund(code: &str) -> Result<serde_json::Value, String> {
    let (id, secret) = split_code(code)?;
    let o = get_order(&id)?;
    if o.role != "buyer" || o.state != "locked" {
        return Err("this purchase is not waiting for a refund code".to_string());
    }
    let note = vault_of(&o)?;
    if note.lock2 == NO_LOCK || vault_lock(&own_spk()?, &secret, &note.opening()) != note.lock2 {
        return Err("that is not this purchase's refund code — nothing was taken".to_string());
    }
    take(&o, VaultBranch::Lock2, secret)
}

/// KEYHOLDER, step 1 of a BOND: ask `poster` (who answers with an ordinary ACCEPT) to lock `amount` until
/// `deadline_ms`. The bond is `beneficiary_spk`'s by the clock (this wallet's own when `None`) and returns to the
/// poster on this wallet's code. Returns the REQUEST to send.
pub fn bond_request(title: &str, amount: u64, deadline_ms: u64, beneficiary_spk: Option<&str>) -> Result<serde_json::Value, String> {
    let mut request = order_request_kind(title, amount, deadline_ms, "bond")?;
    if let Some(spk) = beneficiary_spk {
        let spk = hex32(&digest_of_hex(&hex_of_len(spk, 32)?)?);
        let mut o = get_order(field(&request, "id")?)?;
        o.buyer_spk = spk.clone();
        put_order(&o);
        request["buyer_spk"] = serde_json::Value::String(spk);
    }
    Ok(request)
}

/// POSTER: lock the bond. Only once this wallet's own node does not already hold it (a bond is funded once: a second
/// note of the same vault could never be spent). The caller writes its "posting" note-to-self BEFORE calling this, so
/// a wallet restarted mid-way never posts twice.
pub fn bond_post(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind != "bond" || o.role != "seller" || o.state != "locked" {
        return Err("this is not a bond this wallet can post".to_string());
    }
    if vault_is_locked(&o)? {
        return Ok(serde_json::json!({ "posted": true, "already": true }));
    }
    let own_address =
        wallet_address()?.get("address").and_then(|a| a.as_str()).map(String::from).ok_or_else(|| "no wallet address".to_string())?;
    let sent = do_transfer_atomic_mode(own_address, o.amount, SlotSend::None, VaultSend::Open(vault_of(&o)?))?;
    Ok(serde_json::json!({ "posted": true, "tx_hash": sent.get("tx_hash").cloned().unwrap_or_default() }))
}

/// KEYHOLDER: everything a third wallet needs to wait for a bond as its beneficiary.
pub fn bond_fields(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind != "bond" || o.lock1.is_empty() {
        return Err("this is not a bond with its lock set".to_string());
    }
    Ok(serde_json::to_value(&VaultOrder { role: "beneficiary".to_string(), index: 0, title: String::new(), ..o }).map_err(|e| e.to_string())?)
}

/// BENEFICIARY: watch a bond somebody posted for this wallet. Accepted only when it names THIS wallet's key as the
/// one the clock pays; from then [`order_status`] says when it is locked and [`order_reclaim`] takes it at the deadline.
pub fn bond_watch(fields: &serde_json::Value, title: &str) -> Result<serde_json::Value, String> {
    let mut o: VaultOrder = serde_json::from_value(fields.clone()).map_err(|_| "that is not a bond".to_string())?;
    if o.kind != "bond" || digest_of_hex(&o.buyer_spk)? != own_spk()? || o.lock1.is_empty() || !o.lock2.is_empty() {
        return Err("that bond is not for this wallet".to_string());
    }
    o.id = hex_of_len(&o.id, 16)?;
    o.role = "beneficiary".to_string();
    o.state = "locked".to_string();
    o.title = title.chars().take(128).collect();
    vault_of(&o)?;
    put_order(&o);
    order_status(&o.id)
}

/// SUBSCRIBER: cancel a period that has not started. The money comes back with this wallet's own secret; nobody is asked.
pub fn order_cancel(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind != "sub" || o.role != "buyer" || o.state != "locked" {
        return Err("this is not a subscription payment this wallet can cancel".to_string());
    }
    take(&o, VaultBranch::Lock2, own_secret(&o.id, "cancel")?)
}

/// MERCHANT: collect a subscription period that has started. The clock is the only key.
pub fn order_collect(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind != "sub" || o.role != "seller" || o.state != "locked" {
        return Err("this is not a subscription payment this wallet can collect".to_string());
    }
    take(&o, VaultBranch::Clock, NO_LOCK)
}

/// BUYER: take the money back after the deadline, with nobody's help.
pub fn order_reclaim(id: &str) -> Result<serde_json::Value, String> {
    let o = get_order(id)?;
    if o.kind == "sub" {
        return Err("a subscription payment is cancelled before it starts, never taken back after".to_string());
    }
    // the clock pays the vault's default party: the buyer of a purchase, the beneficiary of a bond
    let mine = digest_of_hex(&o.buyer_spk)? == own_spk()?;
    if !mine || !matches!(o.role.as_str(), "buyer" | "beneficiary") || o.state != "locked" {
        return Err("this purchase is not one this wallet can take back".to_string());
    }
    take(&o, VaultBranch::Clock, NO_LOCK)
}

// ── the commands the app and the checkout helper call ───────────────────────────────────────────────────────────

fn atomic(amount_usdm: f64) -> u64 {
    (amount_usdm * 1e8).round() as u64
}

#[tauri::command]
pub async fn purchase_request(title: String, amount_usdm: f64, deadline_ms: u64) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_request(&title, atomic(amount_usdm), deadline_ms))
        .await
        .map_err(|e| format!("purchase_request task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_accept(request: serde_json::Value, amount_usdm: f64, title: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_accept(&request, atomic(amount_usdm), &title))
        .await
        .map_err(|e| format!("purchase_accept task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_fund(accept: serde_json::Value) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval(fund_prompt(&accept)?)?;
        order_fund(&accept)
    })
    .await
    .map_err(|e| format!("purchase_fund task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_funded(request: serde_json::Value, funded: serde_json::Value, title: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_funded(&request, &funded, &title))
        .await
        .map_err(|e| format!("purchase_funded task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_status(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_status(&id)).await.map_err(|e| format!("purchase_status task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_list() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let all: Vec<serde_json::Value> = open_orders().iter().filter_map(|o| order_status(&o.id).ok()).collect();
        Ok(serde_json::json!({ "purchases": all }))
    })
    .await
    .map_err(|e| format!("purchase_list task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_code(id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Show your release code — only after you have received your order".to_string())?;
        order_code(&id)
    })
    .await
    .map_err(|e| format!("purchase_code task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_check_code(code: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || order_code_is_good(&code)).await.map_err(|e| format!("purchase_check_code task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_release(code: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_release(&code)).await.map_err(|e| format!("purchase_release task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_refund_code(id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Cancel this sale and refund the buyer".to_string())?;
        order_refund_code(&id)
    })
    .await
    .map_err(|e| format!("purchase_refund_code task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_refund(code: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_refund(&code)).await.map_err(|e| format!("purchase_refund task failed: {e}"))?
}

#[tauri::command]
pub async fn purchase_reclaim(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || order_reclaim(&id)).await.map_err(|e| format!("purchase_reclaim task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_round_trips_and_a_malformed_one_is_refused() {
        let l: [u64; LOCK_LANES] = [1, 0x3FFF_FFFF, 7, 0];
        assert_eq!(lanes_of_hex(&lanes_hex(&l)).unwrap(), l);
        assert!(lanes_of_hex("zz").is_err());
        assert!(lanes_of_hex(&"ff".repeat(16)).is_err(), "a lane above the field is no code");
        assert!(lanes_of_hex(&"00".repeat(15)).is_err());
        let id = "ab".repeat(16);
        let code = format!("{id}:{}", lanes_hex(&l));
        assert_eq!(split_code(&code).unwrap(), (id, l));
        assert!(split_code("nocolon").is_err());
    }

    /// A download's order as a REOPENED wallet holds it: read back from its vault note (`recognise`), so its kind is
    /// empty and its two lock slots are the delivery lock's halves. The seller's key letter for that listing must be
    /// taken; a letter naming another listing's lock, or a seller's own order, must not. (Before this pin the check
    /// asked for kind "key" and refused the first case: a buyer who closed the wallet could never take the key.)
    // TWO-PARTY-REVIEWED: this is the buyer's own predicate over the buyer's own record; no second wallet enters it.
    // The crossing (a buyer closed across the seller's delivery, on real nodes) is not covered by any check yet and
    // is listed open in the audit (F10).
    #[test]
    fn a_reopened_wallets_download_is_matched_by_its_locks_alone() {
        let (a, b): ([u64; LOCK_LANES], [u64; LOCK_LANES]) = ([11, 12, 13, 14], [21, 22, 23, 24]);
        let lock_hex = format!("{}{}", lanes_hex(&a), lanes_hex(&b));
        let other_hex = format!("{}{}", lanes_hex(&b), lanes_hex(&a));
        assert_eq!(lock_hex.len(), 16 * LOCK_LANES, "an offer states the lock as eight lanes, four bytes each, in hex");
        let restored = VaultOrder {
            id: "44".repeat(16),
            role: "buyer".to_string(),
            title: String::new(),
            amount: 500_000_000,
            t_h: 500_000,
            buyer_spk: "00".repeat(32),
            seller_spk: String::new(),
            buyer_salt: "22".repeat(16),
            seller_salt: "33".repeat(16),
            lock1: lanes_hex(&a),
            lock2: lanes_hex(&b),
            state: "locked".to_string(),
            index: 8,
            kind: String::new(),
        };
        assert!(order_is_under_lock(&restored, &lock_hex), "a reopened wallet refused the key letter of the download it paid for");
        assert!(!order_is_under_lock(&restored, &other_hex), "a key letter for another lock was accepted");
        assert!(!order_is_under_lock(&VaultOrder { role: "seller".to_string(), ..restored.clone() }, &lock_hex), "a seller's own order passed as a purchase");
        assert!(!order_is_under_lock(&VaultOrder { lock1: String::new(), ..restored.clone() }, &lock_hex), "an unfunded order passed");
        assert!(!order_is_under_lock(&restored, "zz"), "a malformed lock passed");
    }

    #[test]
    fn both_sides_compute_one_vault_and_each_code_opens_only_its_own_lock() {
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::{poseidon_pair, NoteOwner};
        // two fixed owners (a fixture, on purpose): the nullifier key and seed are functions of the spend key
        let owner = |k: Digest4| NoteOwner { ask: k, nk: poseidon_pair(k, lanes_of(&[1])), seed: poseidon_pair(k, lanes_of(&[2])) };
        let buyer = owner(lanes_of(&[0xA11CE, 1, 2, 3]));
        let seller = owner(lanes_of(&[0xB0B, 4, 5, 6]));
        let mut o = VaultOrder {
            id: "11".repeat(16),
            role: "buyer".to_string(),
            title: "a bicycle".to_string(),
            amount: 12_720_000_000,
            t_h: 500_000,
            buyer_spk: hex32(&buyer.spk()),
            seller_spk: hex32(&seller.spk()),
            buyer_salt: "22".repeat(16),
            seller_salt: "33".repeat(16),
            lock1: String::new(),
            lock2: String::new(),
            state: "requested".to_string(),
            index: 7,
            kind: String::new(),
        };
        let opening = vault_of(&o).unwrap().opening();
        let (code, refund): (VaultSecret, VaultSecret) = ([9, 8, 7, 6], [1, 2, 3, 4]);
        o.lock1 = lanes_hex(&vault_lock(&seller.spk(), &code, &opening));
        o.lock2 = lanes_hex(&vault_lock(&buyer.spk(), &refund, &opening));
        let v = vault_of(&o).unwrap();
        // the seller's copy of the order is the same vault
        let seller_view = VaultOrder { role: "seller".to_string(), state: "locked".to_string(), index: 0, ..o.clone() };
        assert_eq!(vault_of(&seller_view).unwrap(), v);
        assert_eq!(v.owner_spk, buyer.spk(), "the buyer is the default party");
        // the handover code opens lock 1 for the seller and for nobody else; the refund code opens lock 2 for the buyer
        assert_eq!(vault_lock(&seller.spk(), &code, &v.opening()), v.lock1);
        assert_ne!(vault_lock(&buyer.spk(), &code, &v.opening()), v.lock1, "the buyer, who knows the code, does not open the seller's lock");
        assert_ne!(vault_lock(&seller.spk(), &refund, &v.opening()), v.lock1);
        assert_eq!(vault_lock(&buyer.spk(), &refund, &v.opening()), v.lock2);
        // another seller salt is another vault: the seller's salt enters every vault it accepts
        let other = VaultOrder { seller_salt: "44".repeat(16), ..o.clone() };
        assert_ne!(vault_of(&other).unwrap().opening(), v.opening());
        // the record a vault note carries is enough to rebuild the locks, the deadline, the seller's salt and the index
        let (m, tail) = record_of(&o).unwrap();
        assert_eq!(lanes_hex(&lanes_of_bytes(&m[..16]).unwrap()), o.lock1);
        assert_eq!(lanes_hex(&lanes_of_bytes(&m[16..]).unwrap()), o.lock2);
        assert_eq!(u32::from_le_bytes(tail[..4].try_into().unwrap()) as u64, o.t_h);
        assert_eq!(hex::encode(&tail[4..20]), o.seller_salt);
        assert_eq!(u32::from_le_bytes(tail[20..].try_into().unwrap()), o.index);
    }
}
